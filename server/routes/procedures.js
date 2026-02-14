const { sql, getConfig, getPool } = require('../db')

async function execBatches(pool, sqlText) {
  const batches = sqlText.split(/\r?\n\s*GO\s*\r?\n/gi).map(b => b.trim()).filter(Boolean)
  for (const b of batches) await pool.request().batch(b)
}

module.exports = function registerProcedures(app, opts = {}) {
  const allowCreate = opts.allowSpCreate === true

  app.get('/api/:db/procedures/:name/params', async (req, res) => {
    const { db, name } = req.params
    try {
      const pool = await getPool(db)
      const parts = name.includes('.') ? name.split('.') : ['dbo', name]
      const schema = parts[0]
      const procName = parts.slice(1).join('.') || parts[0]
      const r = await pool.request()
        .input('procName', sql.NVarChar, procName)
        .input('schemaName', sql.NVarChar, schema)
        .query(`
          SELECT p.name AS ParameterName, TYPE_NAME(p.user_type_id) AS DataType, p.max_length, p.is_output
          FROM sys.parameters p
          JOIN sys.procedures pr ON p.object_id = pr.object_id
          WHERE pr.name = @procName AND SCHEMA_NAME(pr.schema_id) = @schemaName
          ORDER BY p.parameter_id
        `)
      res.json(r.recordset)
    } catch (err) {
      res.status(500).json({ error: err.message })
    }
  })

  app.post('/api/:db/procedures/:name/execute', async (req, res) => {
    const { db, name } = req.params
    const params = req.body || {}
    try {
      const pool = await getPool(db)
      const request = pool.request()
      for (const [k, v] of Object.entries(params)) {
        const clean = k.startsWith('@') ? k.substring(1) : k
        request.input(clean, v)
      }
      const r = await request.execute(name)
      res.json({ recordsets: r.recordsets, returnValue: r.returnValue, output: r.output })
    } catch (err) {
      res.status(500).json({ error: err.message })
    }
  })

  app.get('/api/:db/procedures/:name/definition', async (req, res) => {
    const { db, name } = req.params
    try {
      const pool = await getPool(db)
      let schema = 'dbo'
      let procName = name
      if (name.includes('.')) {
        const parts = name.split('.')
        schema = parts.shift()
        procName = parts.join('.')
      }
      const result = await pool.request()
        .input('procName', sql.NVarChar, procName)
        .input('schemaName', sql.NVarChar, schema)
        .query(`
          SELECT sm.definition
          FROM sys.sql_modules sm
          JOIN sys.objects o ON sm.object_id = o.object_id
          JOIN sys.schemas s ON o.schema_id = s.schema_id
          WHERE o.type IN ('P') AND o.name = @procName AND s.name = @schemaName
        `)
      if (result.recordset.length === 0) {
        const exists = await pool.request()
          .input('procName', sql.NVarChar, procName)
          .input('schemaName', sql.NVarChar, schema)
          .query(`
            SELECT TOP 1 o.type
            FROM sys.objects o
            JOIN sys.schemas s ON o.schema_id = s.schema_id
            WHERE o.type IN ('P','PC','X') AND o.name = @procName AND s.name = @schemaName
          `)
        if (exists.recordset.length > 0) return res.json({ name: procName, schema, definition: null, note: 'No T-SQL definition available.' })
        return res.status(404).json({ error: 'Procedure not found' })
      }
      res.json({ name: procName, schema, definition: result.recordset[0].definition })
    } catch (err) {
      res.status(500).json({ error: err.message })
    }
  })

  app.put('/api/:db/procedures/:name/alter', async (req, res) => {
    const { db } = req.params
    const { sql: sqlText } = req.body || {}
    if (!sqlText || typeof sqlText !== 'string') return res.status(400).json({ error: 'Missing SQL text in body' })
    try {
      const pool = await getPool(db)
      await execBatches(pool, sqlText)
      res.json({ message: 'Procedure altered successfully' })
    } catch (err) {
      res.status(500).json({ error: err.message })
    }
  })

  app.post('/api/:db/procedures/create', async (req, res) => {
    const { db } = req.params
    const { sql: sqlText } = req.body || {}
    if (!allowCreate) return res.status(403).json({ error: 'Creating stored procedures is disabled on this server' })
    if (!sqlText || typeof sqlText !== 'string') return res.status(400).json({ error: 'Missing SQL text in body' })
    try {
      const pool = await getPool(db)
      await execBatches(pool, sqlText)
      res.status(201).json({ message: 'Procedure created successfully' })
    } catch (err) {
      res.status(500).json({ error: err.message })
    }
  })
}
