const { sql, getConfig, getPool, getPoolByName } = require('../db')
const { verify } = require('../auth')

module.exports = function registerMetadata(app) {
  app.get('/api/databases', async (req, res) => {
    const includeSystem = ['1','true','yes','on',''].includes(String(req.query.system ?? '1').toLowerCase())
    const sv = req.query.sv
    try {
      const header = req.headers['authorization'] || ''
      const token = header.startsWith('Bearer ') ? header.slice(7) : ''
      const payload = verify(token)
      const roleLower = String(payload?.role || '').toLowerCase()
      if (!sv) {
        if (!payload) return res.status(401).json({ error: 'Unauthorized' })
        if (roleLower !== 'admin') return res.status(403).json({ error: 'Forbidden server: missing selection' })
      } else {
        if (!payload) return res.status(401).json({ error: 'Unauthorized' })
        if (roleLower !== 'admin') {
          const poolReg = await getPool('SQL_WebService')
          const rAcc1 = await poolReg.request().input('id', payload.id).input('sv', sv)
            .query(`SELECT allowed FROM Tbl.ServerAccess WHERE LOWER(user_id)=LOWER(@id) AND LOWER(server_name)=LOWER(@sv)`)
          const rAcc2 = await poolReg.request().input('id', payload.id).input('sv', sv)
            .query(`SELECT allowed FROM Tbl.ConnectionAccess WHERE LOWER(user_id)=LOWER(@id) AND LOWER(name)=LOWER(@sv)`)
          const allowed = (rAcc1.recordset[0]?.allowed ? true : false) || (rAcc2.recordset[0]?.allowed ? true : false)
          if (!allowed) return res.status(403).json({ error: 'Forbidden server' })
        }
      }
      const pool = sv ? await getPoolByName(sv, 'master') : await getPool('master')
      const q = includeSystem
        ? "SELECT name FROM sys.databases WHERE state = 0 AND name <> 'SQL_WebService' ORDER BY name"
        : "SELECT name FROM sys.databases WHERE name NOT IN ('master','tempdb','model','msdb','SQL_WebService') AND state = 0 ORDER BY name"
      const result = await pool.request().query(q)
      let names = result.recordset.map(r => r.name)
      if (payload && String(payload.role || '').toLowerCase() !== 'admin' && sv) {
        const poolReg = await getPool('SQL_WebService')
        const rDbAllowed = await poolReg.request().input('id', payload.id).input('sv', sv)
          .query(`SELECT db_name FROM Tbl.DatabaseAccess WHERE LOWER(user_id)=LOWER(@id) AND LOWER(server_name)=LOWER(@sv) AND allowed=1`)
        const allowDbSet = new Set(rDbAllowed.recordset.map(x => x.db_name))
        names = names.filter(n => allowDbSet.has(n))
      }
      res.json(names)
    } catch (err) {
      res.status(500).json({ error: err.message })
    }
  })

  app.get('/api/:db/schemas', async (req, res) => {
    const { db } = req.params
    const sv = req.query.sv
    try {
      const header = req.headers['authorization'] || ''
      const token = header.startsWith('Bearer ') ? header.slice(7) : ''
      const payload = verify(token)
      const roleLower = String(payload?.role || '').toLowerCase()
      if (!sv) {
        if (!payload) return res.status(401).json({ error: 'Unauthorized' })
        if (roleLower !== 'admin') return res.status(403).json({ error: 'Forbidden server: missing selection' })
      } else {
        if (!payload) return res.status(401).json({ error: 'Unauthorized' })
        if (roleLower !== 'admin') {
          const poolReg = await getPool('SQL_WebService')
          const rAcc = await poolReg.request().input('id', payload.id).input('sv', sv).query(`SELECT allowed FROM Tbl.ServerAccess WHERE LOWER(user_id)=LOWER(@id) AND LOWER(server_name)=LOWER(@sv)`)
          const allowed = rAcc.recordset[0]?.allowed ? true : false
          if (!allowed) return res.status(403).json({ error: 'Forbidden server' })
        }
      }
      const pool = sv ? await getPoolByName(sv, db) : await getPool(db)
      const q = `
        SELECT s.name
        FROM sys.schemas s
        JOIN sys.objects o ON o.schema_id = s.schema_id
        WHERE o.type = 'U'
        GROUP BY s.name
        ORDER BY s.name
      `
      const r = await pool.request().query(q)
      const list = r.recordset.map(x => x.name)
      if (list.length === 0) {
        const q2 = `SELECT name FROM sys.schemas ORDER BY name`
        const r2 = await pool.request().query(q2)
        return res.json(r2.recordset.map(x => x.name))
      }
      res.json(list)
    } catch (err) {
      res.status(500).json({ error: err.message })
    }
  })

  app.get('/api/tables/all', async (req, res) => {
    const includeViews = ['1','true','yes','on'].includes(String(req.query.includeViews || '0').toLowerCase())
    const includeSystem = ['1','true','yes','on',''].includes(String(req.query.system ?? '1').toLowerCase())
    const sv = req.query.sv
    try {
      const header = req.headers['authorization'] || ''
      const token = header.startsWith('Bearer ') ? header.slice(7) : ''
      const payload = verify(token)
      const roleLower = String(payload?.role || '').toLowerCase()
      if (!sv) {
        if (!payload) return res.status(401).json({ error: 'Unauthorized' })
        if (roleLower !== 'admin') return res.status(403).json({ error: 'Forbidden server: missing selection' })
      } else {
        if (!payload) return res.status(401).json({ error: 'Unauthorized' })
        if (roleLower !== 'admin') {
          const poolReg = await getPool('SQL_WebService')
          const rAcc = await poolReg.request().input('id', payload.id).input('sv', sv).query(`SELECT allowed FROM Tbl.ServerAccess WHERE LOWER(user_id)=LOWER(@id) AND LOWER(server_name)=LOWER(@sv)`)
          const allowed = rAcc.recordset[0]?.allowed ? true : false
          if (!allowed) return res.status(403).json({ error: 'Forbidden server' })
        }
      }
      const pool = sv ? await getPoolByName(sv, 'master') : await getPool('master')
      const dbFilter = includeSystem
        ? "SELECT name FROM sys.databases WHERE state = 0 AND name <> 'SQL_WebService' ORDER BY name"
        : "SELECT name FROM sys.databases WHERE state = 0 AND name NOT IN ('master','tempdb','model','msdb','SQL_WebService') ORDER BY name"
      const dbs = await pool.request().query(dbFilter)
      const out = []
      for (const row of dbs.recordset) {
        const dbName = row.name
        const poolDb = sv ? await getPoolByName(sv, dbName) : await getPool(dbName)
        const qTables = `
          SELECT '${dbName}' AS db, s.name + '.' + t.name AS name
          FROM sys.tables t
          JOIN sys.schemas s ON s.schema_id = t.schema_id
          ${includeSystem ? '' : 'WHERE t.is_ms_shipped = 0'}
          ORDER BY s.name, t.name
        `
        const rTables = await poolDb.request().query(qTables)
        for (const t of rTables.recordset) out.push({ db: t.db, name: t.name })
        if (includeViews) {
          const qViews = `
            SELECT '${dbName}' AS db, s.name + '.' + v.name AS name
            FROM sys.views v
            JOIN sys.schemas s ON s.schema_id = v.schema_id
            ${includeSystem ? '' : 'WHERE v.is_ms_shipped = 0'}
            ORDER BY s.name, v.name
          `
          const rViews = await poolDb.request().query(qViews)
          for (const v of rViews.recordset) out.push({ db: v.db, name: v.name })
        }
      }
      res.json(out)
    } catch (err) {
      res.status(500).json({ error: err.message })
    }
  })

  app.get('/api/:db/tables', async (req, res) => {
    const { db } = req.params
    const includeViews = ['1','true','yes','on'].includes(String(req.query.includeViews || '0').toLowerCase())
    const includeSystem = ['1','true','yes','on',''].includes(String(req.query.system ?? '1').toLowerCase())
    const schemaFilter = String(req.query.schema || '').trim()
    const sv = req.query.sv
    try {
      if (sv) {
        const header = req.headers['authorization'] || ''
        const token = header.startsWith('Bearer ') ? header.slice(7) : ''
        const payload = verify(token)
        if (!payload) return res.status(401).json({ error: 'Unauthorized' })
        if (payload.role !== 'admin') {
          const poolReg = await getPool('SQL_WebService')
          const rAcc1 = await poolReg.request().input('id', payload.id).input('sv', sv)
            .query(`SELECT allowed FROM Tbl.ServerAccess WHERE LOWER(user_id)=LOWER(@id) AND LOWER(server_name)=LOWER(@sv)`)
          const rAcc2 = await poolReg.request().input('id', payload.id).input('sv', sv)
            .query(`SELECT allowed FROM Tbl.ConnectionAccess WHERE LOWER(user_id)=LOWER(@id) AND LOWER(name)=LOWER(@sv)`)
          const allowed = (rAcc1.recordset[0]?.allowed ? true : false) || (rAcc2.recordset[0]?.allowed ? true : false)
          if (!allowed) return res.status(403).json({ error: 'Forbidden server' })
          const rDb = await poolReg.request()
            .input('id', payload.id)
            .input('sv', sv)
            .input('db', db)
            .query(`SELECT allowed FROM Tbl.DatabaseAccess WHERE LOWER(user_id)=LOWER(@id) AND LOWER(server_name)=LOWER(@sv) AND LOWER(db_name)=LOWER(@db)`)
          const allowedDb = rDb.recordset[0]?.allowed ? true : false
          if (!allowedDb) return res.status(403).json({ error: 'Forbidden database' })
        }
      }
      const pool = sv ? await getPoolByName(sv, db) : await getPool(db)
      const tableConds = []
      if (!includeSystem) tableConds.push('t.is_ms_shipped = 0')
      if (schemaFilter) tableConds.push('s.name = @schema')
      const tableWhere = tableConds.length ? `WHERE ${tableConds.join(' AND ')}` : ''
      const qTables = `
        SELECT s.name + '.' + t.name AS name
        FROM sys.tables t
        JOIN sys.schemas s ON s.schema_id = t.schema_id
        ${tableWhere}
        ORDER BY s.name, t.name
      `
      const reqTables = pool.request()
      if (schemaFilter) reqTables.input('schema', sql.NVarChar, schemaFilter)
      const rTables = await reqTables.query(qTables)
      let names = rTables.recordset.map(r => r.name)
      if (includeViews) {
        const viewConds = []
        if (!includeSystem) viewConds.push('v.is_ms_shipped = 0')
        if (schemaFilter) viewConds.push('s.name = @schema')
        const viewWhere = viewConds.length ? `WHERE ${viewConds.join(' AND ')}` : ''
        const qViews = `
          SELECT s.name + '.' + v.name AS name
          FROM sys.views v
          JOIN sys.schemas s ON s.schema_id = v.schema_id
          ${viewWhere}
          ORDER BY s.name, v.name
        `
        const reqViews = pool.request()
        if (schemaFilter) reqViews.input('schema', sql.NVarChar, schemaFilter)
        const rViews = await reqViews.query(qViews)
        names = [...names, ...rViews.recordset.map(r => r.name)]
      }
      if (names.length === 0) {
        const infoConds = []
        if (schemaFilter) infoConds.push('TABLE_SCHEMA = @schema')
        const infoWhere = infoConds.length ? `WHERE ${infoConds.join(' AND ')}` : ''
        const qInfo = `
          SELECT TABLE_SCHEMA + '.' + TABLE_NAME as name
          FROM INFORMATION_SCHEMA.TABLES
          ${infoWhere}
          ORDER BY TABLE_SCHEMA, TABLE_NAME
        `
        const reqInfo = pool.request()
        if (schemaFilter) reqInfo.input('schema', sql.NVarChar, schemaFilter)
        const result = await reqInfo.query(qInfo)
        names = result.recordset.map(r => r.name)
      }
      res.json(names)
    } catch (err) {
      res.status(500).json({ error: err.message })
    }
  })

  app.get('/api/:db/procedures', async (req, res) => {
    const { db } = req.params
    const full = String(req.query.full || '').toLowerCase()
    const includeSystem = ['1','true','yes','on',''].includes(String(req.query.system ?? '1').toLowerCase())
    const sv = req.query.sv
    try {
      if (sv) {
        const header = req.headers['authorization'] || ''
        const token = header.startsWith('Bearer ') ? header.slice(7) : ''
        const payload = verify(token)
        if (!payload) return res.status(401).json({ error: 'Unauthorized' })
        const roleLower = String(payload.role || '').toLowerCase()
        if (roleLower !== 'admin') {
          const poolReg = await getPool('SQL_WebService')
          const rAcc = await poolReg.request().input('id', payload.id).input('sv', sv).query(`SELECT allowed FROM Tbl.ServerAccess WHERE user_id=@id AND server_name=@sv`)
          const allowed = rAcc.recordset[0]?.allowed ? true : false
          if (!allowed) return res.status(403).json({ error: 'Forbidden server' })
        }
      }
      const pool = sv ? await getPoolByName(sv, db) : await getPool(db)
      if (full === '1' || full === 'true') {
        const qUser = `
          SELECT s.name AS [schema], o.name AS [name], o.type, o.create_date, o.modify_date, o.is_ms_shipped,
                 CASE WHEN sm.object_id IS NULL THEN 0 ELSE 1 END AS has_definition
          FROM sys.objects o
          JOIN sys.schemas s ON o.schema_id = s.schema_id
          LEFT JOIN sys.sql_modules sm ON sm.object_id = o.object_id
          WHERE o.type IN ('P','PC','X')
          ORDER BY s.name, o.name
        `
        const rUser = await pool.request().query(qUser)
        const rows = rUser.recordset.map(x => ({
          schema: x.schema,
          name: `${x.schema}.${x.name}`,
          type: x.type,
          create_date: x.create_date,
          modify_date: x.modify_date,
          is_ms_shipped: x.is_ms_shipped,
          has_definition: x.has_definition
        }))
        if (includeSystem) {
          for (const sysdb of ['master','msdb']) {
            const sysPool = sv ? await getPoolByName(sv, sysdb) : await getPool(sysdb)
            const qSys = `
              SELECT '${sysdb}' AS db, s.name AS [schema], o.name AS [name], o.type, o.create_date, o.modify_date, o.is_ms_shipped,
                     CASE WHEN sm.object_id IS NULL THEN 0 ELSE 1 END AS has_definition
              FROM sys.objects o
              JOIN sys.schemas s ON o.schema_id = s.schema_id
              LEFT JOIN sys.sql_modules sm ON sm.object_id = o.object_id
              WHERE o.type IN ('P','PC','X') AND o.is_ms_shipped = 1
              ORDER BY s.name, o.name
            `
            const rSys = await sysPool.request().query(qSys)
            for (const x of rSys.recordset) {
              rows.push({
                db: x.db,
                schema: x.schema,
                name: `${x.schema}.${x.name}`,
                type: x.type,
                create_date: x.create_date,
                modify_date: x.modify_date,
                is_ms_shipped: x.is_ms_shipped,
                has_definition: x.has_definition
              })
            }
          }
        }
        return res.json(rows)
      } else {
        const q = `
          SELECT s.name + '.' + o.name AS name
          FROM sys.objects o
          JOIN sys.schemas s ON o.schema_id = s.schema_id
          WHERE o.type IN ('P','PC','X')
          ORDER BY s.name, o.name
        `
        const r = await pool.request().query(q)
        const list = r.recordset.map(x => x.name)
        if (includeSystem) {
          for (const sysdb of ['master','msdb']) {
            const sysPool = sv ? await getPoolByName(sv, sysdb) : await getPool(sysdb)
            const qSys = `
              SELECT s.name + '.' + o.name AS name
              FROM sys.objects o
              JOIN sys.schemas s ON o.schema_id = s.schema_id
              WHERE o.type IN ('P','PC','X') AND o.is_ms_shipped = 1
              ORDER BY s.name, o.name
            `
            const rSys = await sysPool.request().query(qSys)
            for (const x of rSys.recordset) list.push(x.name)
          }
        }
        return res.json(list)
      }
    } catch (err) {
      res.status(500).json({ error: err.message })
    }
  })

  app.get('/api/procedures/all', async (req, res) => {
    const full = String(req.query.full || '').toLowerCase()
    const includeSystem = ['1','true','yes','on'].includes(String(req.query.system || '0').toLowerCase())
    const sv = req.query.sv
    try {
      const pool = sv ? await getPoolByName(sv, 'master') : await getPool('master')
      const dbs = await pool.request().query("SELECT name FROM sys.databases WHERE state = 0 AND name NOT IN ('master','tempdb','model','msdb','SQL_WebService') ORDER BY name")
      const out = []
      for (const row of dbs.recordset) {
        const dbName = row.name
        const poolDb = sv ? await getPoolByName(sv, dbName) : await getPool(dbName)
        if (full === '1' || full === 'true') {
          const q = `
            SELECT '${dbName}' AS db, s.name AS [schema], o.name AS [name], o.type, o.create_date, o.modify_date, o.is_ms_shipped,
                   CASE WHEN sm.object_id IS NULL THEN 0 ELSE 1 END AS has_definition
            FROM sys.objects o
            JOIN sys.schemas s ON o.schema_id = s.schema_id
            LEFT JOIN sys.sql_modules sm ON sm.object_id = o.object_id
            WHERE o.type IN ('P','PC','X')
            ORDER BY s.name, o.name
          `
          const r = await poolDb.request().query(q)
          for (const x of r.recordset) {
            out.push({
              db: x.db,
              schema: x.schema,
              name: `${x.schema}.${x.name}`,
              type: x.type,
              create_date: x.create_date,
              modify_date: x.modify_date,
              is_ms_shipped: x.is_ms_shipped,
              has_definition: x.has_definition
            })
          }
        } else {
          const q = `
            SELECT '${dbName}' AS db, s.name + '.' + o.name AS name
            FROM sys.objects o
            JOIN sys.schemas s ON o.schema_id = s.schema_id
            WHERE o.type IN ('P','PC','X')
            ORDER BY s.name, o.name
          `
          const r = await poolDb.request().query(q)
          for (const x of r.recordset) out.push({ db: x.db, name: x.name })
        }
      }
      if (includeSystem) {
        for (const sysdb of ['master','msdb']) {
          const sysPool = sv ? await getPoolByName(sv, sysdb) : await getPool(sysdb)
          if (full === '1' || full === 'true') {
            const qSys = `
              SELECT '${sysdb}' AS db, s.name AS [schema], o.name AS [name], o.type, o.create_date, o.modify_date, o.is_ms_shipped,
                     CASE WHEN sm.object_id IS NULL THEN 0 ELSE 1 END AS has_definition
              FROM sys.objects o
              JOIN sys.schemas s ON o.schema_id = s.schema_id
              LEFT JOIN sys.sql_modules sm ON sm.object_id = o.object_id
              WHERE o.type IN ('P','PC','X') AND o.is_ms_shipped = 1
              ORDER BY s.name, o.name
            `
            const rSys = await sysPool.request().query(qSys)
            for (const x of rSys.recordset) {
              out.push({
                db: x.db,
                schema: x.schema,
                name: `${x.schema}.${x.name}`,
                type: x.type,
                create_date: x.create_date,
                modify_date: x.modify_date,
                is_ms_shipped: x.is_ms_shipped,
                has_definition: x.has_definition
              })
            }
          } else {
            const qSys = `
              SELECT '${sysdb}' AS db, s.name + '.' + o.name AS name
              FROM sys.objects o
              JOIN sys.schemas s ON o.schema_id = s.schema_id
              WHERE o.type IN ('P','PC','X') AND o.is_ms_shipped = 1
              ORDER BY s.name, o.name
            `
            const rSys = await sysPool.request().query(qSys)
            for (const x of rSys.recordset) out.push({ db: x.db, name: x.name })
          }
        }
      }
      res.json(out)
    } catch (err) {
      res.status(500).json({ error: err.message })
    }
  })
}
