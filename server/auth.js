const crypto = require('crypto')
const { getPool, getPoolByName } = require('./db')

const AUTH_DB = 'SQL_WebService'
const AUTH_TABLE = 'dbo.AppUsers'
const AUTH_SECRET = process.env.AUTH_SECRET || 'change-me'
const PERM_TABLE = 'dbo.UserPermissions'
const SERVERS_TABLE = 'Tbl.Server'
const SERVER_ACCESS_TABLE = 'Tbl.ServerAccess'

function sha256(text) {
  return crypto.createHash('sha256').update(text, 'utf8').digest('hex')
}

function sign(payload) {
  const data = Buffer.from(JSON.stringify(payload)).toString('base64url')
  const sig = crypto.createHmac('sha256', AUTH_SECRET).update(data).digest('base64url')
  return `${data}.${sig}`
}

function verify(token) {
  if (!token || !token.includes('.')) return null
  const [data, sig] = token.split('.')
  const expected = crypto.createHmac('sha256', AUTH_SECRET).update(data).digest('base64url')
  if (sig !== expected) return null
  try {
    const json = JSON.parse(Buffer.from(data, 'base64url').toString('utf8'))
    return json
  } catch (e) {
    return null
  }
}

async function ensureAuthDatabase() {
  const master = await getPool('master')
  const dbExists = await master.request().query(`SELECT name FROM sys.databases WHERE name = '${AUTH_DB}'`)
  if (dbExists.recordset.length === 0) {
    await master.request().query(`CREATE DATABASE [${AUTH_DB}]`)
  }
  const pool = await getPool(AUTH_DB)
  await pool.request().query(`IF NOT EXISTS(SELECT * FROM sys.schemas WHERE name = 'Tbl') BEGIN EXEC('CREATE SCHEMA Tbl'); END`)
  await pool.request().query(`
    IF NOT EXISTS (SELECT * FROM sys.objects WHERE object_id = OBJECT_ID(N'${AUTH_TABLE}') AND type IN (N'U'))
    BEGIN
      CREATE TABLE ${AUTH_TABLE} (
        user_id NVARCHAR(50) NOT NULL PRIMARY KEY,
        password_hash NVARCHAR(128) NOT NULL,
        role NVARCHAR(20) NOT NULL
      )
    END
  `)
  await pool.request().query(`
    IF NOT EXISTS (SELECT * FROM sys.objects WHERE object_id = OBJECT_ID(N'${PERM_TABLE}') AND type IN (N'U'))
    BEGIN
      CREATE TABLE ${PERM_TABLE} (
        user_id NVARCHAR(50) NOT NULL PRIMARY KEY,
        can_insert BIT NOT NULL DEFAULT 0,
        can_update BIT NOT NULL DEFAULT 1,
        can_delete BIT NOT NULL DEFAULT 0,
        can_design BIT NOT NULL DEFAULT 0,
        swagger BIT NOT NULL DEFAULT 0
      )
    END
  `)
  await pool.request().query(`
    IF NOT EXISTS (SELECT * FROM sys.objects WHERE object_id = OBJECT_ID(N'${SERVERS_TABLE}') AND type IN (N'U'))
    BEGIN
      CREATE TABLE ${SERVERS_TABLE} (
        server_name NVARCHAR(100) NOT NULL PRIMARY KEY,
        host NVARCHAR(200) NOT NULL,
        port INT NOT NULL,
        [user] NVARCHAR(100) NOT NULL,
        [password] NVARCHAR(200) NOT NULL,
        encrypt BIT NOT NULL DEFAULT 1,
        trust BIT NOT NULL DEFAULT 1
      )
    END
  `)
  await pool.request().query(`
    IF NOT EXISTS (SELECT * FROM sys.objects WHERE object_id = OBJECT_ID(N'Tbl.Connection') AND type IN (N'U'))
    BEGIN
      CREATE TABLE Tbl.Connection (
        conn_id INT IDENTITY(1,1) PRIMARY KEY,
        name NVARCHAR(100) NOT NULL,
        host NVARCHAR(200) NOT NULL,
        port INT NOT NULL,
        [user] NVARCHAR(100) NOT NULL,
        [password] NVARCHAR(200) NOT NULL,
        encrypt BIT NOT NULL DEFAULT 1,
        trust BIT NOT NULL DEFAULT 1,
        UNIQUE(host, port, [user])
      )
    END
  `)
  await pool.request().query(`
    IF NOT EXISTS (
      SELECT 1 FROM sys.indexes 
      WHERE name = N'UX_Tbl_Connection_Name' AND object_id = OBJECT_ID(N'Tbl.Connection')
    )
    BEGIN
      IF NOT EXISTS (SELECT 1 FROM (SELECT name FROM Tbl.Connection GROUP BY name HAVING COUNT(*) > 1) d)
      BEGIN
        CREATE UNIQUE INDEX UX_Tbl_Connection_Name ON Tbl.Connection(name);
      END
    END
  `)
  await pool.request().query(`
    IF NOT EXISTS (SELECT * FROM sys.objects WHERE object_id = OBJECT_ID(N'Tbl.ConnectionAccess') AND type IN (N'U'))
    BEGIN
      CREATE TABLE Tbl.ConnectionAccess (
        user_id NVARCHAR(50) NOT NULL,
        name NVARCHAR(100) NOT NULL,
        allowed BIT NOT NULL DEFAULT 0,
        PRIMARY KEY (user_id, name)
      )
    END
  `)
  await pool.request().query(`
    IF NOT EXISTS (SELECT 1 FROM Tbl.Connection)
    BEGIN
      INSERT INTO Tbl.Connection (name, host, port, [user], [password], encrypt, trust)
      SELECT TOP 1 server_name, host, port, [user], [password], encrypt, trust FROM ${SERVERS_TABLE}
    END
  `)
  await pool.request().query(`
    IF NOT EXISTS (SELECT * FROM sys.objects WHERE object_id = OBJECT_ID(N'${SERVER_ACCESS_TABLE}') AND type IN (N'U'))
    BEGIN
      CREATE TABLE ${SERVER_ACCESS_TABLE} (
        user_id NVARCHAR(50) NOT NULL,
        server_name NVARCHAR(100) NOT NULL,
        allowed BIT NOT NULL DEFAULT 0,
        PRIMARY KEY (user_id, server_name),
        CONSTRAINT FK_ServerAccess_User FOREIGN KEY (user_id) REFERENCES ${AUTH_TABLE}(user_id) ON DELETE CASCADE,
        CONSTRAINT FK_ServerAccess_Server FOREIGN KEY (server_name) REFERENCES ${SERVERS_TABLE}(server_name) ON DELETE CASCADE
      )
    END
  `)
  await pool.request().query(`
    IF NOT EXISTS (SELECT * FROM sys.objects WHERE object_id = OBJECT_ID(N'Tbl.DatabaseAccess') AND type IN (N'U'))
    BEGIN
      CREATE TABLE Tbl.DatabaseAccess (
        user_id NVARCHAR(50) NOT NULL,
        server_name NVARCHAR(100) NOT NULL,
        db_name NVARCHAR(128) NOT NULL,
        allowed BIT NOT NULL DEFAULT 0,
        PRIMARY KEY (user_id, server_name, db_name)
      )
    END
  `)
  await pool.request().query(`
    DECLARE @fk NVARCHAR(128);
    SELECT @fk = fk.name
    FROM sys.foreign_keys fk
    WHERE fk.parent_object_id = OBJECT_ID(N'Tbl.DatabaseAccess')
      AND fk.referenced_object_id = OBJECT_ID(N'${SERVERS_TABLE}');
    IF @fk IS NOT NULL
    BEGIN
      DECLARE @sql NVARCHAR(MAX) = N'ALTER TABLE Tbl.DatabaseAccess DROP CONSTRAINT ' + QUOTENAME(@fk) + ';';
      EXEC sp_executesql @sql;
    END
  `)
  await pool.request().query(`
    IF NOT EXISTS (SELECT * FROM sys.objects WHERE object_id = OBJECT_ID(N'dbo.AuditLog') AND type IN (N'U'))
    BEGIN
      CREATE TABLE dbo.AuditLog (
        id INT IDENTITY(1,1) PRIMARY KEY,
        user_id NVARCHAR(50) NOT NULL,
        role NVARCHAR(20) NOT NULL,
        action NVARCHAR(10) NOT NULL,
        db NVARCHAR(128) NOT NULL,
        object NVARCHAR(256) NOT NULL,
        id_col NVARCHAR(128) NULL,
        id_value NVARCHAR(4000) NULL,
        payload NVARCHAR(MAX) NULL,
        ts DATETIME2 NOT NULL DEFAULT SYSUTCDATETIME()
      )
    END
  `)
  const adminCheck = await pool.request().input('uid', 'admin').query(`SELECT * FROM ${AUTH_TABLE} WHERE user_id = @uid`)
  if (adminCheck.recordset.length === 0) {
    await pool.request()
      .input('user_id', 'admin')
      .input('password_hash', sha256('1234'))
      .input('role', 'admin')
      .query(`INSERT INTO ${AUTH_TABLE} (user_id, password_hash, role) VALUES (@user_id, @password_hash, @role)`)
    await pool.request().query(`MERGE ${PERM_TABLE} AS t USING (SELECT 'admin' AS user_id) s ON t.user_id=s.user_id WHEN NOT MATCHED THEN INSERT (user_id, can_insert, can_update, can_delete, can_design, swagger) VALUES (s.user_id, 1, 1, 1, 1, 1);`)
  } else {
    const currentRole = String(adminCheck.recordset[0]?.role || '').toLowerCase()
    if (currentRole !== 'admin') {
      await pool.request().input('uid', 'admin').query(`UPDATE ${AUTH_TABLE} SET role = 'admin' WHERE user_id = @uid`)
    }
    await pool.request().query(`MERGE ${PERM_TABLE} AS t USING (SELECT 'admin' AS user_id) s ON t.user_id=s.user_id WHEN NOT MATCHED THEN INSERT (user_id, can_insert, can_update, can_delete, can_design, swagger) VALUES (s.user_id, 1, 1, 1, 1, 1) WHEN MATCHED THEN UPDATE SET can_insert=1, can_update=1, can_delete=1, can_design=1, swagger=1;`)
  }
}

async function getPermissions(user_id, role) {
  await ensureAuthDatabase()
  const pool = await getPool(AUTH_DB)
  const r = await pool.request().input('id', user_id).query(`SELECT can_insert, can_update, can_delete, can_design, swagger FROM ${PERM_TABLE} WHERE user_id = @id`)
  if (r.recordset.length) {
    const p = r.recordset[0]
    return { can_insert: !!p.can_insert, can_update: !!p.can_update, can_delete: !!p.can_delete, can_design: !!p.can_design, swagger: !!p.swagger }
  }
  if (role === 'admin') return { can_insert: true, can_update: true, can_delete: true, can_design: true, swagger: true }
  return { can_insert: false, can_update: true, can_delete: false, can_design: false, swagger: false }
}

async function writeAudit(entry) {
  await ensureAuthDatabase()
  const pool = await getPool(AUTH_DB)
  const r = pool.request()
    .input('user_id', entry.user_id || '')
    .input('role', entry.role || '')
    .input('action', entry.action || '')
    .input('db', entry.db || '')
    .input('object', entry.object || '')
    .input('id_col', entry.id_col || null)
    .input('id_value', entry.id_value != null ? String(entry.id_value) : null)
    .input('payload', entry.payload ? JSON.stringify(entry.payload) : null)
  await r.query(`INSERT INTO dbo.AuditLog (user_id, role, action, db, object, id_col, id_value, payload) VALUES (@user_id, @role, @action, @db, @object, @id_col, @id_value, @payload)`)
}

function registerAuth(app) {
  app.post('/auth/login', async (req, res) => {
    const { id, password } = req.body || {}
    if (!id || !password) return res.status(400).json({ error: 'Missing credentials' })
    try {
      await ensureAuthDatabase()
      const pool = await getPool(AUTH_DB)
      const r = await pool.request()
        .input('id', id)
        .input('ph', sha256(password))
        .query(`SELECT user_id, role FROM ${AUTH_TABLE} WHERE user_id = @id AND password_hash = @ph`)
      if (r.recordset.length === 0) return res.status(401).json({ error: 'Invalid credentials' })
      const user = r.recordset[0]
      const roleLower = String(user.role || '').toLowerCase()
      const token = sign({ id: user.user_id, role: roleLower, iat: Date.now() })
      const perms = await getPermissions(user.user_id, roleLower)
      res.json({ token, user: { id: user.user_id, role: roleLower, permissions: perms } })
    } catch (err) {
      res.status(500).json({ error: err.message })
    }
  })

  function requireAdmin(req, res) {
    const header = req.headers['authorization'] || ''
    const token = header.startsWith('Bearer ') ? header.slice(7) : ''
    const payload = verify(token)
    const roleLower = String(payload?.role || '').toLowerCase()
    if (!payload || roleLower !== 'admin') {
      res.status(403).json({ error: 'Forbidden' })
      return null
    }
    return { ...payload, role: roleLower }
  }

  app.get('/auth/users', async (req, res) => {
    try {
      if (!requireAdmin(req, res)) return
      await ensureAuthDatabase()
      const pool = await getPool(AUTH_DB)
      const r = await pool.request().query(`SELECT user_id, role FROM ${AUTH_TABLE} ORDER BY user_id`)
      res.json(r.recordset.map(x => ({ id: x.user_id, role: x.role })))
    } catch (err) {
      res.status(500).json({ error: err.message })
    }
  })

  app.post('/auth/users', async (req, res) => {
    const { id, password, role } = req.body || {}
    if (!id || !password || !role) return res.status(400).json({ error: 'Missing id/password/role' })
    try {
      if (!requireAdmin(req, res)) return
      await ensureAuthDatabase()
      const pool = await getPool(AUTH_DB)
      const exists = await pool.request().input('id', id).query(`SELECT 1 FROM ${AUTH_TABLE} WHERE user_id = @id`)
      if (exists.recordset.length) {
        await pool.request()
          .input('id', id).input('ph', sha256(password)).input('role', role)
          .query(`UPDATE ${AUTH_TABLE} SET password_hash = @ph, role = @role WHERE user_id = @id`)
        return res.json({ message: 'Updated user' })
      } else {
        await pool.request()
          .input('id', id).input('ph', sha256(password)).input('role', role)
          .query(`INSERT INTO ${AUTH_TABLE} (user_id, password_hash, role) VALUES (@id, @ph, @role)`)
        await pool.request().query(`MERGE ${PERM_TABLE} AS t USING (SELECT '${id}' AS user_id) s ON t.user_id=s.user_id WHEN NOT MATCHED THEN INSERT (user_id, can_insert, can_update, can_delete, can_design, swagger) VALUES (s.user_id, 0, 1, 0, 0, 0);`)
        return res.status(201).json({ message: 'Created user' })
      }
    } catch (err) {
      res.status(500).json({ error: err.message })
    }
  })

  app.get('/auth/permissions', async (req, res) => {
    try {
      if (!requireAdmin(req, res)) return
      const id = String(req.query.id || '')
      await ensureAuthDatabase()
      if (!id) return res.status(400).json({ error: 'Missing id' })
      const pool = await getPool(AUTH_DB)
      const rUser = await pool.request().input('id', id).query(`SELECT role FROM ${AUTH_TABLE} WHERE user_id=@id`)
      const role = rUser.recordset[0]?.role || 'user'
      const perms = await getPermissions(id, role)
      res.json({ id, role, permissions: perms })
    } catch (err) {
      res.status(500).json({ error: err.message })
    }
  })

  app.delete('/auth/users/:id', async (req, res) => {
    const { id } = req.params
    try {
      if (!requireAdmin(req, res)) return
      await ensureAuthDatabase()
      const pool = await getPool(AUTH_DB)
      await pool.request().input('id', id).query(`DELETE FROM ${AUTH_TABLE} WHERE user_id = @id`)
      res.json({ message: 'Deleted user' })
    } catch (err) {
      res.status(500).json({ error: err.message })
    }
  })

  app.get('/auth/audit', async (req, res) => {
    try {
      if (!requireAdmin(req, res)) return
      await ensureAuthDatabase()
      const pool = await getPool(AUTH_DB)
      const limit = Math.max(1, Math.min(500, parseInt(req.query.limit || '100')))
      const filters = []
      const reqst = pool.request()
      if (req.query.db) { filters.push('db = @fdb'); reqst.input('fdb', req.query.db) }
      if (req.query.action) { filters.push('action = @fact'); reqst.input('fact', req.query.action) }
      if (req.query.user_id) { filters.push('user_id = @fuid'); reqst.input('fuid', req.query.user_id) }
      const where = filters.length ? ('WHERE ' + filters.join(' AND ')) : ''
      const q = `SELECT TOP (${limit}) id, user_id, role, action, db, object, id_col, id_value, ts FROM dbo.AuditLog ${where} ORDER BY ts DESC`
      const r = await reqst.query(q)
      res.json(r.recordset)
    } catch (err) {
      res.status(500).json({ error: err.message })
    }
  })

  app.get('/auth/me', async (req, res) => {
    try {
      const header = req.headers['authorization'] || ''
      const token = header.startsWith('Bearer ') ? header.slice(7) : ''
      const payload = verify(token)
      if (!payload) return res.status(401).json({ error: 'Unauthorized' })
      const roleLower = String(payload.role || '').toLowerCase()
      const perms = await getPermissions(payload.id, roleLower)
      res.json({ id: payload.id, role: roleLower, permissions: perms })
    } catch (err) {
      res.status(500).json({ error: err.message })
    }
  })

  app.get('/auth/servers', async (req, res) => {
    try {
      if (!requireAdmin(req, res)) return
      await ensureAuthDatabase()
      const pool = await getPool(AUTH_DB)
      const r = await pool.request().query(`SELECT server_name, host, port, [user], encrypt, trust FROM ${SERVERS_TABLE} ORDER BY server_name`)
      res.json(r.recordset)
    } catch (err) {
      res.status(500).json({ error: err.message })
    }
  })

  app.post('/auth/servers', async (req, res) => {
    const { server_name, host, port, user, password, encrypt = 1, trust = 1 } = req.body || {}
    if (!server_name || !host || !port || !user || !password) return res.status(400).json({ error: 'Missing required fields' })
    try {
      if (!requireAdmin(req, res)) return
      await ensureAuthDatabase()
      const pool = await getPool(AUTH_DB)
      const r = await pool.request().input('name', server_name).query(`SELECT 1 FROM ${SERVERS_TABLE} WHERE server_name = @name`)
      const reqst = pool.request()
        .input('name', server_name).input('host', host).input('port', port)
        .input('user', user).input('password', password)
        .input('encrypt', encrypt ? 1 : 0).input('trust', trust ? 1 : 0)
      if (r.recordset.length) {
        await reqst.query(`UPDATE ${SERVERS_TABLE} SET host=@host, port=@port, [user]=@user, [password]=@password, encrypt=@encrypt, trust=@trust WHERE server_name=@name`)
        res.json({ message: 'Updated server' })
      } else {
        await reqst.query(`INSERT INTO ${SERVERS_TABLE} (server_name, host, port, [user], [password], encrypt, trust) VALUES (@name, @host, @port, @user, @password, @encrypt, @trust)`)
        res.status(201).json({ message: 'Created server' })
      }
    } catch (err) {
      res.status(500).json({ error: err.message })
    }
  })

  app.delete('/auth/servers/:name', async (req, res) => {
    const { name } = req.params
    try {
      if (!requireAdmin(req, res)) return
      await ensureAuthDatabase()
      const pool = await getPool(AUTH_DB)
      await pool.request().input('name', name).query(`DELETE FROM ${SERVERS_TABLE} WHERE server_name=@name`)
      res.json({ message: 'Deleted server' })
    } catch (err) {
      res.status(500).json({ error: err.message })
    }
  })

  // Connections CRUD (Tbl.Connection)
  app.get('/auth/connections', async (req, res) => {
    try {
      if (!requireAdmin(req, res)) return
      await ensureAuthDatabase()
      const pool = await getPool(AUTH_DB)
      const r = await pool.request().query(`SELECT conn_id, name, host, port, [user], encrypt, trust FROM Tbl.Connection ORDER BY name`)
      res.json(r.recordset)
    } catch (err) {
      res.status(500).json({ error: err.message })
    }
  })
  app.post('/auth/connections', async (req, res) => {
    const { name, host, port, user, password, encrypt = 1, trust = 1 } = req.body || {}
    if (!name || !host || !port || !user || !password) return res.status(400).json({ error: 'Missing required fields' })
    try {
      if (!requireAdmin(req, res)) return
      await ensureAuthDatabase()
      const pool = await getPool(AUTH_DB)
      const r = await pool.request().input('name', name).query(`SELECT 1 FROM Tbl.Connection WHERE name = @name`)
      const reqst = pool.request()
        .input('name', name).input('host', host).input('port', port)
        .input('user', user).input('password', password)
        .input('encrypt', encrypt ? 1 : 0).input('trust', trust ? 1 : 0)
      if (r.recordset.length) {
        await reqst.query(`UPDATE Tbl.Connection SET host=@host, port=@port, [user]=@user, [password]=@password, encrypt=@encrypt, trust=@trust WHERE name=@name`)
        res.json({ message: 'Updated connection' })
      } else {
        await reqst.query(`INSERT INTO Tbl.Connection (name, host, port, [user], [password], encrypt, trust) VALUES (@name, @host, @port, @user, @password, @encrypt, @trust)`)
        res.status(201).json({ message: 'Created connection' })
      }
    } catch (err) {
      res.status(500).json({ error: err.message })
    }
  })
  app.delete('/auth/connections/:name', async (req, res) => {
    const { name } = req.params
    try {
      if (!requireAdmin(req, res)) return
      await ensureAuthDatabase()
      const pool = await getPool(AUTH_DB)
      await pool.request().input('name', name).query(`DELETE FROM Tbl.Connection WHERE name=@name`)
      res.json({ message: 'Deleted connection' })
    } catch (err) {
      res.status(500).json({ error: err.message })
    }
  })
  app.post('/auth/servers/sync', async (req, res) => {
    try {
      if (!requireAdmin(req, res)) return
      await ensureAuthDatabase()
      // Read all databases from base host (env DB_SERVER)
      const poolDb = await getPool('master')
      const dbs = await poolDb.request().query(`SELECT name FROM sys.databases WHERE state = 0 ORDER BY name`)
      const pool = await getPool(AUTH_DB)
      const host = process.env.DB_SERVER || 'localhost'
      const port = parseInt(process.env.DB_PORT || '1433', 10)
      const user = process.env.DB_USER || ''
      const password = process.env.DB_PASSWORD || ''
      const encrypt = 1
      const trust = 1
      for (const row of dbs.recordset) {
        const name = String(row.name)
        await pool.request()
          .input('name', name)
          .input('host', host)
          .input('port', port)
          .input('user', user)
          .input('password', password)
          .input('encrypt', encrypt)
          .input('trust', trust)
          .query(`
            MERGE ${SERVERS_TABLE} AS t
            USING (SELECT @name AS server_name) s ON t.server_name = s.server_name
            WHEN MATCHED THEN UPDATE SET host=@host, port=@port, [user]=@user, [password]=@password, encrypt=@encrypt, trust=@trust
            WHEN NOT MATCHED THEN INSERT (server_name, host, port, [user], [password], encrypt, trust)
              VALUES (@name, @host, @port, @user, @password, @encrypt, @trust);
          `)
      }
      res.json({ message: 'Synced servers from host', count: dbs.recordset.length })
    } catch (err) {
      res.status(500).json({ error: err.message })
    }
  })

  app.get('/auth/server-access', async (req, res) => {
    try {
      if (!requireAdmin(req, res)) return
      const userId = String(req.query.user_id || '')
      await ensureAuthDatabase()
      const pool = await getPool(AUTH_DB)
      const rServers = await pool.request().query(`SELECT server_name FROM ${SERVERS_TABLE}`)
      const rAccess = userId ? await pool.request().input('id', userId).query(`SELECT server_name, allowed FROM ${SERVER_ACCESS_TABLE} WHERE user_id=@id`) : { recordset: [] }
      const map = new Map(rAccess.recordset.map(x => [x.server_name, !!x.allowed]))
      const rows = rServers.recordset.map(s => ({ server_name: s.server_name, allowed: map.get(s.server_name) || false }))
      res.json(rows)
    } catch (err) {
      res.status(500).json({ error: err.message })
    }
  })

  app.post('/auth/server-access', async (req, res) => {
    const { user_id, server_name, allowed } = req.body || {}
    if (!user_id || !server_name) return res.status(400).json({ error: 'Missing user_id/server_name' })
    try {
      if (!requireAdmin(req, res)) return
      await ensureAuthDatabase()
      const pool = await getPool(AUTH_DB)
      await pool.request()
        .input('id', user_id)
        .input('name', server_name)
        .input('allowed', allowed ? 1 : 0)
        .query(`
          MERGE ${SERVER_ACCESS_TABLE} AS t
          USING (SELECT @id AS user_id, @name AS server_name) s ON t.user_id = s.user_id AND t.server_name = s.server_name
          WHEN MATCHED THEN UPDATE SET allowed=@allowed
          WHEN NOT MATCHED THEN INSERT (user_id, server_name, allowed) VALUES (@id, @name, @allowed);
        `)
      res.json({ message: 'Saved access' })
    } catch (err) {
      res.status(500).json({ error: err.message })
    }
  })

  // Connection access APIs
  app.get('/auth/connection-access', async (req, res) => {
    try {
      if (!requireAdmin(req, res)) return
      const userId = String(req.query.user_id || '')
      await ensureAuthDatabase()
      const pool = await getPool(AUTH_DB)
      const rConn = await pool.request().query(`SELECT name FROM Tbl.Connection ORDER BY name`)
      const rAccess = userId ? await pool.request().input('id', userId).query(`SELECT name, allowed FROM Tbl.ConnectionAccess WHERE user_id=@id`) : { recordset: [] }
      const map = new Map(rAccess.recordset.map(x => [x.name, !!x.allowed]))
      const rows = rConn.recordset.map(s => ({ name: s.name, allowed: map.get(s.name) || false }))
      res.json(rows)
    } catch (err) {
      res.status(500).json({ error: err.message })
    }
  })
  app.post('/auth/connection-access', async (req, res) => {
    const { user_id, name, allowed } = req.body || {}
    if (!user_id || !name) return res.status(400).json({ error: 'Missing user_id/name' })
    try {
      if (!requireAdmin(req, res)) return
      await ensureAuthDatabase()
      const pool = await getPool(AUTH_DB)
      await pool.request()
        .input('id', user_id)
        .input('name', name)
        .input('allowed', allowed ? 1 : 0)
        .query(`
          MERGE Tbl.ConnectionAccess AS t
          USING (SELECT @id AS user_id, @name AS name) s ON t.user_id = s.user_id AND t.name = s.name
          WHEN MATCHED THEN UPDATE SET allowed=@allowed
          WHEN NOT MATCHED THEN INSERT (user_id, name, allowed) VALUES (@id, @name, @allowed);
        `)
      res.json({ message: 'Saved connection access' })
    } catch (err) {
      res.status(500).json({ error: err.message })
    }
  })

  app.get('/auth/database-access', async (req, res) => {
    const { user_id, server_name } = req.query
    if (!user_id || !server_name) return res.status(400).json({ error: 'Missing user_id/server_name' })
    try {
      if (!requireAdmin(req, res)) return
      await ensureAuthDatabase()
      // Load all databases from target server
      const poolSv = await getPoolByName(server_name, 'master')
      const dbs = await poolSv.request().query(`SELECT name FROM sys.databases WHERE state = 0 AND name <> 'SQL_WebService' ORDER BY name`)
      // Load existing access map
      const pool = await getPool(AUTH_DB)
      const rAcc = await pool.request().input('id', user_id).input('sv', server_name)
        .query(`SELECT db_name, allowed FROM Tbl.DatabaseAccess WHERE user_id=@id AND server_name=@sv`)
      const map = new Map(rAcc.recordset.map(x => [String(x.db_name), !!x.allowed]))
      const rows = dbs.recordset.map(d => ({ db_name: d.name, allowed: map.get(String(d.name)) || false }))
      res.json(rows)
    } catch (err) {
      res.status(500).json({ error: err.message })
    }
  })

  app.post('/auth/database-access', async (req, res) => {
    const { user_id, server_name, db_name, allowed } = req.body || {}
    if (!user_id || !server_name || !db_name) return res.status(400).json({ error: 'Missing user_id/server_name/db_name' })
    try {
      if (!requireAdmin(req, res)) return
      await ensureAuthDatabase()
      const pool = await getPool(AUTH_DB)
      await pool.request()
        .input('id', user_id)
        .input('sv', server_name)
        .input('db', db_name)
        .input('allowed', allowed ? 1 : 0)
        .query(`
          MERGE Tbl.DatabaseAccess AS t
          USING (SELECT @id AS user_id, @sv AS server_name, @db AS db_name) s 
            ON t.user_id = s.user_id AND t.server_name = s.server_name AND t.db_name = s.db_name
          WHEN MATCHED THEN UPDATE SET allowed=@allowed
          WHEN NOT MATCHED THEN INSERT (user_id, server_name, db_name, allowed) VALUES (@id, @sv, @db, @allowed);
        `)
      res.json({ message: 'Saved database access' })
    } catch (err) {
      res.status(500).json({ error: err.message })
    }
  })
  app.post('/auth/permissions', async (req, res) => {
    const header = req.headers['authorization'] || ''
    const token = header.startsWith('Bearer ') ? header.slice(7) : ''
    const payload = verify(token)
    if (!payload || payload.role !== 'admin') return res.status(403).json({ error: 'Forbidden' })
    const { id, permissions } = req.body || {}
    if (!id || !permissions) return res.status(400).json({ error: 'Missing id/permissions' })
    try {
      await ensureAuthDatabase()
      const pool = await getPool(AUTH_DB)
      const reqst = pool.request()
        .input('id', id)
        .input('can_insert', permissions.can_insert ? 1 : 0)
        .input('can_update', permissions.can_update ? 1 : 0)
        .input('can_delete', permissions.can_delete ? 1 : 0)
        .input('can_design', permissions.can_design ? 1 : 0)
        .input('swagger', permissions.swagger ? 1 : 0)
      await reqst.query(`
        MERGE ${PERM_TABLE} AS t
        USING (SELECT @id AS user_id) s ON t.user_id = s.user_id
        WHEN MATCHED THEN
          UPDATE SET can_insert=@can_insert, can_update=@can_update, can_delete=@can_delete, can_design=@can_design, swagger=@swagger
        WHEN NOT MATCHED THEN
          INSERT (user_id, can_insert, can_update, can_delete, can_design, swagger)
          VALUES (@id, @can_insert, @can_update, @can_delete, @can_design, @swagger);
      `)
      res.json({ message: 'Saved permissions' })
    } catch (err) {
      res.status(500).json({ error: err.message })
    }
  })
}

module.exports = { registerAuth, verify, ensureAuthDatabase, writeAudit, getPermissions }
