const { sql, getConfig, getPool, getPoolByName } = require('../db')
const { writeAudit, verify } = require('../auth')

module.exports = function registerTables(app) {
  function getPayload(req) {
    try {
      const authHeader = req.headers['authorization'] || ''
      const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : ''
      const { verify } = require('../auth')
      return verify(token)
    } catch (e) {
      return null
    }
  }
  const { getPermissions } = require('../auth')
  async function requireAdmin(req, res) {
    const payload = getPayload(req)
    const roleLower = String(payload?.role || '').toLowerCase()
    if (!payload || roleLower !== 'admin') {
      res.status(403).json({ error: 'Forbidden' })
      return null
    }
    return { ...payload, role: roleLower }
  }
  async function requireCanInsert(req, res) {
    const payload = getPayload(req)
    if (!payload) { res.status(403).json({ error: 'Forbidden' }); return null }
    const perms = await getPermissions(payload.id, String(payload.role || '').toLowerCase())
    if (!perms.can_insert) { res.status(403).json({ error: 'Forbidden' }); return null }
    return payload
  }
  async function requireCanUpdate(req, res) {
    const payload = getPayload(req)
    if (!payload) { res.status(403).json({ error: 'Forbidden' }); return null }
    const perms = await getPermissions(payload.id, String(payload.role || '').toLowerCase())
    if (!perms.can_update) { res.status(403).json({ error: 'Forbidden' }); return null }
    return payload
  }
  async function requireCanDelete(req, res) {
    const payload = getPayload(req)
    if (!payload) { res.status(403).json({ error: 'Forbidden' }); return null }
    const perms = await getPermissions(payload.id, String(payload.role || '').toLowerCase())
    if (!perms.can_delete) { res.status(403).json({ error: 'Forbidden' }); return null }
    return payload
  }
  async function requireServerAllowed(req, res, sv) {
    if (!sv) {
      const payload = getPayload(req)
      if (!payload) { res.status(401).json({ error: 'Unauthorized' }); return false }
      const roleLower = String(payload.role || '').toLowerCase()
      if (roleLower === 'admin') return true
      res.status(403).json({ error: 'Forbidden server: missing selection' })
      return false
    }
    const payload = getPayload(req)
    if (!payload) { res.status(401).json({ error: 'Unauthorized' }); return false }
    const roleLower = String(payload.role || '').toLowerCase()
    if (roleLower === 'admin') return true
    const poolReg = await getPool('SQL_WebService')
    const rAcc1 = await poolReg.request().input('id', payload.id).input('sv', sv).query(`SELECT allowed FROM Tbl.ServerAccess WHERE LOWER(user_id)=LOWER(@id) AND LOWER(server_name)=LOWER(@sv)`)
    const rAcc2 = await poolReg.request().input('id', payload.id).input('sv', sv).query(`SELECT allowed FROM Tbl.ConnectionAccess WHERE LOWER(user_id)=LOWER(@id) AND LOWER(name)=LOWER(@sv)`)
    const allowed = (rAcc1.recordset[0]?.allowed ? true : false) || (rAcc2.recordset[0]?.allowed ? true : false)
    if (!allowed) { res.status(403).json({ error: 'Forbidden server' }); return false }
    return true
  }
  app.get('/api/:db/:table', async (req, res) => {
    const { db, table } = req.params
    const topRaw = String(req.query.top || '100').toLowerCase()
    const sv = req.query.sv
    try {
      if (!(await requireServerAllowed(req, res, sv))) return
      if (sv) {
        const payload = getPayload(req)
        const roleLower = String(payload?.role || '').toLowerCase()
        if (payload && roleLower !== 'admin') {
          const poolReg = await getPool('SQL_WebService')
          const rDb = await poolReg.request().input('id', payload.id).input('sv', sv).input('db', db)
            .query(`SELECT allowed FROM Tbl.DatabaseAccess WHERE LOWER(user_id)=LOWER(@id) AND LOWER(server_name)=LOWER(@sv) AND LOWER(db_name)=LOWER(@db)`)
          if (!(rDb.recordset[0]?.allowed)) return res.status(403).json({ error: 'Forbidden database' })
        }
      }
      const pool = sv ? await getPoolByName(sv, db) : await getPool(db)
      let topClause = 'TOP 100'
      if (topRaw === 'all') {
        topClause = ''
      } else if (!isNaN(parseInt(topRaw)) && parseInt(topRaw) > 0) {
        topClause = `TOP ${parseInt(topRaw)}`
      }
      const q = `SELECT ${topClause ? topClause + ' ' : ''}* FROM [${table.split('.').join('].[')}]`
      const r = await pool.request().query(q)
      res.json(r.recordset)
    } catch (err) {
      res.status(500).json({ error: err.message })
    }
  })

  app.get('/api/:db/:table/columns', async (req, res) => {
    const { db, table } = req.params
    const sv = req.query.sv
    try {
      if (!(await requireServerAllowed(req, res, sv))) return
      if (sv) {
        const payload = getPayload(req)
        const roleLower = String(payload?.role || '').toLowerCase()
        if (payload && roleLower !== 'admin') {
          const poolReg = await getPool('SQL_WebService')
          const rDb = await poolReg.request().input('id', payload.id).input('sv', sv).input('db', db)
            .query(`SELECT allowed FROM Tbl.DatabaseAccess WHERE LOWER(user_id)=LOWER(@id) AND LOWER(server_name)=LOWER(@sv) AND LOWER(db_name)=LOWER(@db)`)
          if (!(rDb.recordset[0]?.allowed)) return res.status(403).json({ error: 'Forbidden database' })
        }
      }
      const pool = sv ? await getPoolByName(sv, db) : await getPool(db)
      let schema = 'dbo'
      let tableName = table
      if (table.includes('.')) {
        const parts = table.split('.')
        schema = parts.shift()
        tableName = parts.join('.')
      }
      const sysQuery = `
        SELECT 
          c.name AS COLUMN_NAME,
          tp.name AS DATA_TYPE,
          c.is_nullable AS IS_NULLABLE,
          COLUMNPROPERTY(c.object_id, c.name, 'IsIdentity') AS IS_IDENTITY,
          CAST(CASE WHEN pk.column_id IS NOT NULL THEN 1 ELSE 0 END AS BIT) AS IS_PRIMARY_KEY
        FROM sys.columns c
        JOIN sys.types tp ON c.user_type_id = tp.user_type_id
        JOIN sys.objects o ON c.object_id = o.object_id
        JOIN sys.schemas s ON o.schema_id = s.schema_id
        LEFT JOIN (
          SELECT ic.object_id, ic.column_id
          FROM sys.index_columns ic
          JOIN sys.indexes i ON ic.object_id = i.object_id AND ic.index_id = i.index_id
          WHERE i.is_primary_key = 1
        ) pk ON c.object_id = pk.object_id AND c.column_id = pk.column_id
        WHERE o.name = @tableName AND s.name = @schemaName AND o.type IN ('U','V')
        ORDER BY c.column_id
      `
      const resultSys = await pool.request()
        .input('tableName', sql.NVarChar, tableName)
        .input('schemaName', sql.NVarChar, schema)
        .query(sysQuery)
      if (resultSys.recordset.length > 0) return res.json(resultSys.recordset)

      const infoQuery = `
        SELECT 
          COLUMN_NAME, 
          DATA_TYPE, 
          CASE WHEN IS_NULLABLE = 'YES' THEN 1 ELSE 0 END AS IS_NULLABLE,
          CAST(0 AS BIT) AS IS_IDENTITY,
          CAST(0 AS BIT) AS IS_PRIMARY_KEY
        FROM INFORMATION_SCHEMA.COLUMNS
        WHERE TABLE_NAME = @tableName AND TABLE_SCHEMA = @schemaName
        ORDER BY ORDINAL_POSITION
      `
      const resultInfo = await pool.request()
        .input('tableName', sql.NVarChar, tableName)
        .input('schemaName', sql.NVarChar, schema)
        .query(infoQuery)
      if (resultInfo.recordset.length > 0) return res.json(resultInfo.recordset)

      try {
        const q = `SELECT TOP 0 * FROM [${table.split('.').join('].[')}]`
        const r = await pool.request().query(q)
        if (r && r.recordset && r.recordset.columns) {
          const colsObj = r.recordset.columns
          const cols = Object.keys(colsObj).map(name => ({
            COLUMN_NAME: name,
            DATA_TYPE: colsObj[name].type?.name || 'sql_variant',
            IS_NULLABLE: colsObj[name].nullable ? 1 : 0,
            IS_IDENTITY: 0,
            IS_PRIMARY_KEY: 0
          }))
          return res.json(cols)
        }
      } catch (e) {}
      res.status(500).json({ error: 'Failed to read columns' })
    } catch (err) {
      res.status(500).json({ error: err.message })
    }
  })

  app.post('/api/:db/:table', async (req, res) => {
    const { db, table } = req.params
    const data = req.body
    const sv = req.query.sv
    try {
      if (!await requireCanInsert(req, res)) return
      if (!(await requireServerAllowed(req, res, sv))) return
      if (sv) {
        const payload = getPayload(req)
        const roleLower = String(payload?.role || '').toLowerCase()
        if (payload && roleLower !== 'admin') {
          const poolReg = await getPool('SQL_WebService')
          const rDb = await poolReg.request().input('id', payload.id).input('sv', sv).input('db', db)
            .query(`SELECT allowed FROM Tbl.DatabaseAccess WHERE LOWER(user_id)=LOWER(@id) AND LOWER(server_name)=LOWER(@sv) AND LOWER(db_name)=LOWER(@db)`)
          if (!(rDb.recordset[0]?.allowed)) return res.status(403).json({ error: 'Forbidden database' })
        }
      }
      const pool = sv ? await getPoolByName(sv, db) : await getPool(db)
      const columns = Object.keys(data).map(col => `[${col}]`).join(', ')
      const values = Object.keys(data).map(col => `@${col}`).join(', ')
      const request = pool.request()
      Object.entries(data).forEach(([k, v]) => request.input(k, v))
      await request.query(`INSERT INTO [${table.split('.').join('].[')}] (${columns}) VALUES (${values})`)
      const payload = getPayload(req) || { id: '', role: '' }
      await writeAudit({ user_id: payload.id, role: payload.role, action: 'insert', db, object: table, payload: data })
      res.status(201).json({ message: 'Added' })
    } catch (err) {
      res.status(500).json({ error: err.message })
    }
  })

  app.put('/api/:db/:table/:idCol/:idValue', async (req, res) => {
    const { db, table, idCol, idValue } = req.params
    const data = req.body
    const sv = req.query.sv
    try {
      if (!await requireCanUpdate(req, res)) return
      if (!(await requireServerAllowed(req, res, sv))) return
      if (sv) {
        const payload = getPayload(req)
        if (payload && payload.role !== 'admin') {
          const poolReg = await getPool('SQL_WebService')
          const rDb = await poolReg.request().input('id', payload.id).input('sv', sv).input('db', db)
            .query(`SELECT allowed FROM Tbl.DatabaseAccess WHERE user_id=@id AND server_name=@sv AND db_name=@db`)
          if (!(rDb.recordset[0]?.allowed)) return res.status(403).json({ error: 'Forbidden database' })
        }
      }
      const pool = sv ? await getPoolByName(sv, db) : await getPool(db)
      const sets = Object.keys(data).map(col => `[${col}]=@${col}`).join(', ')
      const request = pool.request()
      Object.entries(data).forEach(([k, v]) => request.input(k, v))
      request.input('idValue', idValue)
      await request.query(`UPDATE TOP (1) [${table.split('.').join('].[')}] SET ${sets} WHERE [${idCol}] = @idValue`)
      const payload = getPayload(req) || { id: '', role: '' }
      await writeAudit({ user_id: payload.id, role: payload.role, action: 'update', db, object: table, id_col: idCol, id_value: idValue, payload: data })
      res.json({ message: 'Updated' })
    } catch (err) {
      res.status(500).json({ error: err.message })
    }
  })

  app.delete('/api/:db/:table/:idCol/:idValue', async (req, res) => {
    const { db, table, idCol, idValue } = req.params
    const sv = req.query.sv
    try {
      if (!await requireCanDelete(req, res)) return
      if (!(await requireServerAllowed(req, res, sv))) return
      if (sv) {
        const payload = getPayload(req)
        if (payload && payload.role !== 'admin') {
          const poolReg = await getPool('SQL_WebService')
          const rDb = await poolReg.request().input('id', payload.id).input('sv', sv).input('db', db)
            .query(`SELECT allowed FROM Tbl.DatabaseAccess WHERE user_id=@id AND server_name=@sv AND db_name=@db`)
          if (!(rDb.recordset[0]?.allowed)) return res.status(403).json({ error: 'Forbidden database' })
        }
      }
      const needCode = String(process.env.DELETE_CONFIRM_CODE || '28914')
      const gotCode = String(req.headers['x-delete-code'] || '')
      if (gotCode !== needCode) return res.status(403).json({ error: 'Delete requires confirmation code' })
      const pool = sv ? await getPoolByName(sv, db) : await getPool(db)
      await pool.request().input('idValue', idValue).query(`DELETE TOP (1) FROM [${table.split('.').join('].[')}] WHERE [${idCol}] = @idValue`)
      const payload = getPayload(req) || { id: '', role: '' }
      await writeAudit({ user_id: payload.id, role: payload.role, action: 'delete', db, object: table, id_col: idCol, id_value: idValue })
      res.json({ message: 'Deleted' })
    } catch (err) {
      res.status(500).json({ error: err.message })
    }
  })
}
