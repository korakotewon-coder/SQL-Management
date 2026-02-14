const express = require('express');
const dotenv = require('dotenv');
const cors = require('cors');
const bodyParser = require('body-parser');
const { baseConfig } = require('./server/db');
const { verify, getPermissions } = require('./server/auth');
const registerMetadata = require('./server/routes/metadata');
const registerTables = require('./server/routes/tables');
const registerProcedures = require('./server/routes/procedures');
const registerServers = require('./server/routes/servers');
const { registerAuth, ensureAuthDatabase } = require('./server/auth');

dotenv.config();

const app = express();
const port = process.env.APP_PORT || 3000;
const allowSpCreate = String(process.env.ALLOW_SP_CREATE || 'false').toLowerCase() === 'true';

app.use(cors());
app.use(bodyParser.json());
app.use(express.static('public'));

registerMetadata(app);
registerTables(app);
registerProcedures(app, { allowSpCreate });
registerServers(app);
registerAuth(app);

// 2.7 OPENAPI SPEC (Swagger) - no extra deps, serve JSON directly
app.get('/openapi.json', async (req, res) => {
    const auth = req.headers['authorization'] || '';
    const token = auth.startsWith('Bearer ') ? auth.slice(7) : '';
    const payload = verify(token);
    if (!payload) return res.status(403).json({ error: 'Forbidden' });
    const roleLower = String(payload.role || '').toLowerCase();
    const perms = await getPermissions(payload.id, roleLower);
    if (!(roleLower === 'admin' || perms.swagger)) return res.status(403).json({ error: 'Forbidden' });
    const serverUrl = `http://localhost:${port}`;
    const spec = {
        openapi: '3.0.3',
        info: {
            title: 'Mobile SSMS API',
            version: '1.0.0',
            description: 'Admin API for browsing databases, tables, and stored procedures'
        },
        servers: [{ url: serverUrl }],
        paths: {
            '/api/databases': {
                get: {
                    summary: 'List databases (optionally include system DBs)',
                    parameters: [
                        { name: 'system', in: 'query', required: false, schema: { type: 'boolean' } }
                    ],
                    responses: { 200: { description: 'OK' } }
                }
            },
            '/api/{db}/tables': {
                get: {
                    summary: 'List tables in database (filter by schema; include system/views)',
                    parameters: [
                        { name: 'db', in: 'path', required: true, schema: { type: 'string' } },
                        { name: 'includeViews', in: 'query', required: false, schema: { type: 'boolean' } },
                        { name: 'system', in: 'query', required: false, schema: { type: 'boolean' } },
                        { name: 'schema', in: 'query', required: false, schema: { type: 'string' } }
                    ],
                    responses: { 200: { description: 'OK' } }
                }
            },
            '/api/{db}/schemas': {
                get: {
                    summary: 'List schemas in database (those owning user tables)',
                    parameters: [
                        { name: 'db', in: 'path', required: true, schema: { type: 'string' } }
                    ],
                    responses: { 200: { description: 'OK' } }
                }
            },
            '/api/tables/all': {
                get: {
                    summary: 'List tables across all databases',
                    parameters: [
                        { name: 'includeViews', in: 'query', required: false, schema: { type: 'boolean' } },
                        { name: 'system', in: 'query', required: false, schema: { type: 'boolean' } }
                    ],
                    responses: { 200: { description: 'OK' } }
                }
            },
            '/api/{db}/procedures': {
                get: {
                    summary: 'List stored procedures (optionally include system from master/msdb)',
                    parameters: [
                        { name: 'db', in: 'path', required: true, schema: { type: 'string' } },
                        { name: 'full', in: 'query', required: false, schema: { type: 'boolean' } },
                        { name: 'system', in: 'query', required: false, schema: { type: 'boolean' } }
                    ],
                    responses: { 200: { description: 'OK' } }
                }
            },
            '/api/procedures/all': {
                get: {
                    summary: 'List stored procedures across all databases (optionally include system from master/msdb)',
                    parameters: [
                        { name: 'full', in: 'query', required: false, schema: { type: 'boolean' } },
                        { name: 'system', in: 'query', required: false, schema: { type: 'boolean' } }
                    ],
                    responses: { 200: { description: 'OK' } }
                }
            },
            '/api/{db}/procedures/{name}/params': {
                get: {
                    summary: 'Get stored procedure parameters',
                    parameters: [
                        { name: 'db', in: 'path', required: true, schema: { type: 'string' } },
                        { name: 'name', in: 'path', required: true, schema: { type: 'string' } }
                    ],
                    responses: { 200: { description: 'OK' } }
                }
            },
            '/api/{db}/procedures/{name}/execute': {
                post: {
                    summary: 'Execute stored procedure',
                    parameters: [
                        { name: 'db', in: 'path', required: true, schema: { type: 'string' } },
                        { name: 'name', in: 'path', required: true, schema: { type: 'string' } }
                    ],
                    requestBody: { required: false, content: { 'application/json': { schema: { type: 'object', additionalProperties: true } } } },
                    responses: { 200: { description: 'OK' } }
                }
            },
            '/api/{db}/procedures/{name}/definition': {
                get: {
                    summary: 'Get stored procedure definition',
                    parameters: [
                        { name: 'db', in: 'path', required: true, schema: { type: 'string' } },
                        { name: 'name', in: 'path', required: true, schema: { type: 'string' } }
                    ],
                    responses: { 200: { description: 'OK' }, 404: { description: 'Not Found' } }
                }
            },
            '/api/{db}/procedures/{name}/alter': {
                put: {
                    summary: 'Alter stored procedure',
                    parameters: [
                        { name: 'db', in: 'path', required: true, schema: { type: 'string' } },
                        { name: 'name', in: 'path', required: true, schema: { type: 'string' } }
                    ],
                    requestBody: { required: true, content: { 'application/json': { schema: { type: 'object', properties: { sql: { type: 'string' } }, required: ['sql'] } } } },
                    responses: { 200: { description: 'OK' } }
                }
            },
            '/api/{db}/procedures/create': {
                post: {
                    summary: 'Create stored procedure (may be disabled)',
                    parameters: [{ name: 'db', in: 'path', required: true, schema: { type: 'string' } }],
                    requestBody: { required: true, content: { 'application/json': { schema: { type: 'object', properties: { sql: { type: 'string' } }, required: ['sql'] } } } },
                    responses: { 201: { description: 'Created' }, 403: { description: 'Disabled by server policy' } }
                }
            },
            '/api/procedures/all': {
                get: {
                    summary: 'List stored procedures across all databases',
                    parameters: [
                        { name: 'full', in: 'query', required: false, schema: { type: 'boolean' } }
                    ],
                    responses: { 200: { description: 'OK' } }
                }
            },
            '/api/{db}/{table}': {
                get: {
                    summary: 'Read rows from table (top=N or top=all)',
                    parameters: [
                        { name: 'db', in: 'path', required: true, schema: { type: 'string' } },
                        { name: 'table', in: 'path', required: true, schema: { type: 'string' } },
                        { name: 'top', in: 'query', required: false, schema: { type: 'string', example: '100 or all' } }
                    ],
                    responses: { 200: { description: 'OK' } }
                },
                post: {
                    summary: 'Insert into table',
                    parameters: [
                        { name: 'db', in: 'path', required: true, schema: { type: 'string' } },
                        { name: 'table', in: 'path', required: true, schema: { type: 'string' } }
                    ],
                    requestBody: { required: true, content: { 'application/json': { schema: { type: 'object', additionalProperties: true } } } },
                    responses: { 201: { description: 'Created' } }
                }
            },
            '/api/{db}/{table}/columns': {
                get: {
                    summary: 'Get columns metadata',
                    parameters: [
                        { name: 'db', in: 'path', required: true, schema: { type: 'string' } },
                        { name: 'table', in: 'path', required: true, schema: { type: 'string' } }
                    ],
                    responses: { 200: { description: 'OK' } }
                }
            },
            '/api/{db}/{table}/{idCol}/{idValue}': {
                put: {
                    summary: 'Update table row by id',
                    parameters: [
                        { name: 'db', in: 'path', required: true, schema: { type: 'string' } },
                        { name: 'table', in: 'path', required: true, schema: { type: 'string' } },
                        { name: 'idCol', in: 'path', required: true, schema: { type: 'string' } },
                        { name: 'idValue', in: 'path', required: true, schema: { type: 'string' } }
                    ],
                    requestBody: { required: true, content: { 'application/json': { schema: { type: 'object', additionalProperties: true } } } },
                    responses: { 200: { description: 'OK' } }
                },
                delete: {
                    summary: 'Delete table row by id',
                    parameters: [
                        { name: 'db', in: 'path', required: true, schema: { type: 'string' } },
                        { name: 'table', in: 'path', required: true, schema: { type: 'string' } },
                        { name: 'idCol', in: 'path', required: true, schema: { type: 'string' } },
                        { name: 'idValue', in: 'path', required: true, schema: { type: 'string' } }
                    ],
                    responses: { 200: { description: 'OK' } }
                }
            }
        }
    };
    res.json(spec);
});

// 2.8 API DOCS UI
app.get('/api-docs', (req, res) => {
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.end(`
<!doctype html>
<html>
  <head>
    <meta charset="utf-8"/>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>API Docs</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui.css" />
    <style>body { margin:0; } #swagger-ui { max-width: 100%; }</style>
  </head>
  <body>
    <div id="swagger-ui"></div>
    <script src="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
    <script>
      const token = localStorage.getItem('auth_token');
      if (!token) {
        document.body.innerHTML = '<div style="padding:20px;font-family:sans-serif;color:#b00">Forbidden: login as admin to view API docs.</div>';
      } else {
        window.ui = SwaggerUIBundle({ 
          url: '/openapi.json', 
          dom_id: '#swagger-ui',
          requestInterceptor: (req) => { 
            req.headers = req.headers || {}; 
            req.headers['Authorization'] = 'Bearer ' + token; 
            return req; 
          }
        });
      }
    </script>
  </body>
</html>
    `);
});

// Health check for K8s
app.get('/healthz', (req, res) => {
    res.json({ status: 'ok' });
});
app.listen(port, () => {
    console.log(`🚀 Mobile SSMS Server running at http://localhost:${port}`);
    console.log(`Connecting to ${baseConfig.server}:${baseConfig.port}...`);
    ensureAuthDatabase().catch(()=>{})
});
