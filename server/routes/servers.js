const { getPool, getPoolByName } = require('../db')
const { verify, getPermissions, ensureAuthDatabase } = require('../auth')

module.exports = function registerServers(app) {
  app.get('/api/servers', async (req, res) => {
    try {
      try { await ensureAuthDatabase() } catch (e) { /* ignore migration issues */ }
      const header = req.headers['authorization'] || ''
      const token = header.startsWith('Bearer ') ? header.slice(7) : ''
      const payload = verify(token)
      if (!payload) return res.status(401).json({ error: 'Unauthorized' })
      const roleLower = String(payload.role || '').toLowerCase()
      const pool = await getPool('SQL_WebService')
      const rConn = await pool.request().query(`SELECT conn_id, name, host, port, [user] FROM Tbl.Connection`)
      if (rConn.recordset.length > 0) {
        const rows = rConn.recordset.map(c => ({
          conn_id: c.conn_id,
          server_name: c.name, // use name as identifier
          host: c.host,
          port: c.port,
          display: `${c.host},${c.port} (${c.user})`
        }))
        // admins see all, users see those mapped by ConnectionAccess (by name)
        const rAccess = await pool.request().input('id', payload.id).query(`SELECT name, allowed FROM Tbl.ConnectionAccess WHERE user_id=@id`)
        const map = new Map(rAccess.recordset.map(x => [x.name, !!x.allowed]))
        const filtered = rows.filter(s => roleLower === 'admin' || map.get(s.server_name))
        return res.json(filtered.sort((a,b)=>String(a.display).localeCompare(String(b.display))))
      }
      const rServers = await pool.request().query(`SELECT server_name, host, port, [user] FROM Tbl.Server`)
      const rAccess = await pool.request().input('id', payload.id).query(`SELECT server_name, allowed FROM Tbl.ServerAccess WHERE user_id=@id`)
      const map = new Map(rAccess.recordset.map(x => [x.server_name, !!x.allowed]))
      // group by connection string (host+port+user)
      const groups = new Map()
      for (const s of rServers.recordset) {
        const key = `${s.host}:${s.port}:${s.user}`
        if (!groups.has(key)) groups.set(key, [])
        groups.get(key).push(s)
      }
      const uniq = []
      for (const [key, list] of groups.entries()) {
        // pick first server_name as representative, but display connection string
        const rep = list[0]
        uniq.push({
          server_name: rep.server_name,
          host: rep.host,
          port: rep.port,
          display: `${rep.host},${rep.port} (${rep.user})`
        })
      }
      const rows = uniq.filter(s => roleLower === 'admin' || map.get(s.server_name))
      res.json(rows.sort((a,b)=>String(a.display).localeCompare(String(b.display))))
    } catch (err) {
      res.status(500).json({ error: err.message })
    }
  })
}
