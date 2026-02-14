const sql = require('mssql')
const dotenv = require('dotenv')
dotenv.config()

const baseConfig = {
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  server: process.env.DB_SERVER,
  port: parseInt(process.env.DB_PORT || '1433', 10),
  options: { encrypt: true, trustServerCertificate: true },
  pool: { max: 10, min: 0, idleTimeoutMillis: 30000 }
}

function getConfig(database) {
  return { ...baseConfig, database: database || process.env.DB_DATABASE || 'master' }
}

const pools = new Map()
async function getPool(database) {
  const dbName = database || process.env.DB_DATABASE || 'master'
  const key = `default:${dbName}`
  let pool = pools.get(key)
  if (!pool || !pool.connected) {
    pool = await new sql.ConnectionPool(getConfig(dbName)).connect()
    pools.set(key, pool)
  }
  return pool
}

async function getServerConfigByName(serverName) {
  // Read from SQL_WebService registry
  const registryDb = process.env.DB_DATABASE || 'SQL_WebService'
  const pool = await getPool(registryDb)
  // Prefer Tbl.Connection (new registry), fallback to Tbl.Server
  const rConn = await pool.request().input('name', sql.NVarChar, serverName)
    .query(`SELECT name AS server_name, host, port, [user], [password], encrypt, trust FROM Tbl.Connection WHERE name = @name`)
  let s = rConn.recordset[0]
  if (!s) {
    const r = await pool.request().input('name', sql.NVarChar, serverName)
      .query(`SELECT server_name, host, port, [user], [password], encrypt, trust FROM Tbl.Server WHERE server_name = @name`)
    if (r.recordset.length === 0) throw new Error(`Unknown server: ${serverName}`)
    s = r.recordset[0]
  }
  return {
    user: s.user,
    password: s.password,
    server: s.host,
    port: s.port,
    options: { encrypt: !!s.encrypt, trustServerCertificate: !!s.trust },
    pool: { max: 10, min: 0, idleTimeoutMillis: 30000 }
  }
}

async function getPoolByName(serverName, database) {
  const dbName = database || 'master'
  const key = `${serverName}:${dbName}`
  let pool = pools.get(key)
  if (pool && pool.connected) return pool
  const cfg = await getServerConfigByName(serverName)
  const config = { ...cfg, database: dbName }
  pool = await new sql.ConnectionPool(config).connect()
  pools.set(key, pool)
  return pool
}

module.exports = { sql, baseConfig, getConfig, getPool, getPoolByName, getServerConfigByName }
