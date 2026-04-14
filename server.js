require('dotenv').config();
const express = require('express');
const { Pool } = require('pg');
const path = require('path');
const fs = require('fs');
const { BedrockRuntimeClient, ConverseCommand } = require('@aws-sdk/client-bedrock-runtime');
const { GoogleAuth } = require('google-auth-library');
const { EC2Client, DescribeInstancesCommand } = require('@aws-sdk/client-ec2');
const { CloudWatchClient, GetMetricDataCommand, DescribeAlarmsCommand } = require('@aws-sdk/client-cloudwatch');
const { CloudWatchLogsClient, FilterLogEventsCommand, DescribeLogGroupsCommand } = require('@aws-sdk/client-cloudwatch-logs');
const { RDSClient, DescribeDBInstancesCommand } = require('@aws-sdk/client-rds');
const { ElasticLoadBalancingV2Client, DescribeLoadBalancersCommand } = require('@aws-sdk/client-elastic-load-balancing-v2');
const { ElastiCacheClient, DescribeCacheClustersCommand } = require('@aws-sdk/client-elasticache');
const { S3Client, ListBucketsCommand } = require('@aws-sdk/client-s3');
const { CloudFrontClient, ListDistributionsCommand } = require('@aws-sdk/client-cloudfront');

const app = express();
app.use(express.json());

// ─── Pool management ──────────────────────────────────────────────────────────
const pools = {};

function getPool(req) {
  const host = req.headers['x-db-host'] || 'localhost';
  const port = parseInt(req.headers['x-db-port'] || '8090');
  const database = req.headers['x-db-name'] || 'lillian_care_core';
  const user = req.headers['x-db-user'] || 'postgres';
  const password = req.headers['x-db-password'] || '';

  const key = `${host}:${port}/${database}:${user}:${password}`;
  if (!pools[key]) {
    pools[key] = new Pool({
      host, port, database, user, password,
      max: 5,
      idleTimeoutMillis: 60000,
      connectionTimeoutMillis: 5000,
      ssl: host !== 'localhost' ? { rejectUnauthorized: false } : false,
    });
  }
  return pools[key];
}

async function query(req, sql, params = []) {
  const pool = getPool(req);
  const result = await pool.query(sql, params);
  return result.rows;
}

// ─── Pagination helper ────────────────────────────────────────────────────────
async function paginate(req, baseSql, countSql, params, page, pageSize) {
  const offset = (page - 1) * pageSize;
  const [rows, countRows] = await Promise.all([
    query(req, `${baseSql} LIMIT $${params.length + 1} OFFSET $${params.length + 2}`, [...params, pageSize, offset]),
    query(req, countSql, params),
  ]);
  return { rows, total: parseInt(countRows[0].count), page, pageSize };
}

// ─── WHERE builder helper ─────────────────────────────────────────────────────
function buildWhere(filters) {
  const clauses = [];
  const params = [];
  for (const [col, op, val] of filters) {
    if (val === null || val === undefined || val === '') continue;
    params.push(val);
    clauses.push(`${col} ${op} $${params.length}`);
  }
  return { where: clauses.length ? 'WHERE ' + clauses.join(' AND ') : '', params };
}

// ─── Routes: env config (serves .env values to frontend, never the raw file) ──
app.get('/api/env-config', (req, res) => {
  res.json({
    passwords: {
      dev:        process.env.DB_DEV_PASSWORD        || '',
      staging:    process.env.DB_STAGING_PASSWORD    || '',
      production: process.env.DB_PROD_PASSWORD       || '',
    },
    decryptKeys: {
      dev:        process.env.DECRYPT_KEY_DEV        || '',
      staging:    process.env.DECRYPT_KEY_STAGING    || '',
      production: process.env.DECRYPT_KEY_PROD       || '',
    },
  });
});

// ─── Routes: connection test ──────────────────────────────────────────────────
app.get('/api/connection-test', async (req, res) => {
  try {
    await query(req, 'SELECT 1');
    res.json({ ok: true });
  } catch (e) {
    res.status(400).json({ ok: false, error: e.message });
  }
});

// ─── Routes: session logs ─────────────────────────────────────────────────────
app.get('/api/session-logs/endpoints', async (req, res) => {
  try {
    const rows = await query(req, `SELECT DISTINCT endpoint FROM serverpod_session_log WHERE endpoint IS NOT NULL ORDER BY endpoint`);
    res.json(rows.map(r => r.endpoint));
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/session-logs', async (req, res) => {
  try {
    const { endpoint, method, dateFrom, dateTo, errorsOnly, page = 1, pageSize = 50 } = req.query;
    const filters = [
      ['endpoint', 'ILIKE', endpoint ? `%${endpoint}%` : null],
      ['method', 'ILIKE', method ? `%${method}%` : null],
      ['"time"', '>=', dateFrom || null],
      ['"time"', '<=', dateTo || null],
    ];
    if (errorsOnly === 'true') filters.push(['error', 'IS NOT', 'NULL_PLACEHOLDER']);

    const clauses = [];
    const params = [];
    for (const [col, op, val] of filters) {
      if (val === null || val === undefined || val === '') continue;
      if (op === 'IS NOT') { clauses.push(`${col} IS NOT NULL`); continue; }
      params.push(val);
      clauses.push(`${col} ${op} $${params.length}`);
    }
    const where = clauses.length ? 'WHERE ' + clauses.join(' AND ') : '';

    const baseSql = `SELECT id, "serverId", "time", module, endpoint, method, duration, "numQueries", slow, error, "authenticatedUserId", "isOpen" FROM serverpod_session_log ${where} ORDER BY "time" DESC`;
    const countSql = `SELECT COUNT(*) FROM serverpod_session_log ${where}`;

    const result = await paginate(req, baseSql, countSql, params, parseInt(page), parseInt(pageSize));
    res.json(result);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/session-logs/:id/details', async (req, res) => {
  try {
    const id = parseInt(req.params.id);
    const [logs, queries, sessionRows] = await Promise.all([
      query(req, `SELECT id, "time", "logLevel", message, error, "stackTrace", "order" FROM serverpod_log WHERE "sessionLogId" = $1 ORDER BY "order" ASC`, [id]),
      query(req, `SELECT id, query, duration, "numRows", error, "stackTrace", slow, "order" FROM serverpod_query_log WHERE "sessionLogId" = $1 ORDER BY "order" ASC`, [id]),
      query(req, `SELECT error, "stackTrace" FROM serverpod_session_log WHERE id = $1`, [id]),
    ]);
    res.json({ session: sessionRows[0] || null, logs, queries });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ─── Routes: admin audit log ──────────────────────────────────────────────────
app.get('/api/admin-audit', async (req, res) => {
  try {
    const { action, userName, praxisId, dateFrom, dateTo, page = 1, pageSize = 50 } = req.query;
    const filters = [
      ['action', 'ILIKE', action ? `%${action}%` : null],
      ['"userName"', 'ILIKE', userName ? `%${userName}%` : null],
      ['"praxisId"', '=', praxisId || null],
      ['"createdAt"', '>=', dateFrom || null],
      ['"createdAt"', '<=', dateTo || null],
    ];
    const { where, params } = buildWhere(filters);
    const baseSql = `SELECT id, "userId", "userName", "userEmail", action, changes, "praxisId", "createdAt" FROM admin_audit_log ${where} ORDER BY "createdAt" DESC`;
    const countSql = `SELECT COUNT(*) FROM admin_audit_log ${where}`;
    const result = await paginate(req, baseSql, countSql, params, parseInt(page), parseInt(pageSize));
    res.json(result);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ─── Routes: notifications ────────────────────────────────────────────────────
app.get('/api/notifications', async (req, res) => {
  try {
    const { type, userId, dateFrom, dateTo, page = 1, pageSize = 50 } = req.query;
    const filters = [
      ['nl.type', '=', type !== undefined && type !== '' ? parseInt(type) : null],
      ['nl."userId"', '=', userId ? parseInt(userId) : null],
      ['nl."createdAt"', '>=', dateFrom || null],
      ['nl."createdAt"', '<=', dateTo || null],
    ];
    const { where, params } = buildWhere(filters);
    const baseSql = `SELECT nl.id, nl."userId", nl.title, nl.type, nl."activityId", nl.body, nl."isNew", nl."createdAt", aui.email as "userEmail", aui."firstName", aui."lastName" FROM notification_log nl LEFT JOIN app_user_info aui ON aui.id = nl."userId" ${where} ORDER BY nl."createdAt" DESC`;
    const countSql = `SELECT COUNT(*) FROM notification_log nl ${where}`;
    const result = await paginate(req, baseSql, countSql, params, parseInt(page), parseInt(pageSize));
    res.json(result);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ─── Routes: users ────────────────────────────────────────────────────────────
app.get('/api/users', async (req, res) => {
  try {
    const { q, praxisId, page = 1, pageSize = 50 } = req.query;
    const params = [];
    const clauses = [];

    if (q && q.trim()) {
      params.push(`%${q.trim()}%`);
      const n = params.length;
      clauses.push(`("firstName" ILIKE $${n} OR "lastName" ILIKE $${n} OR email ILIKE $${n} OR "phoneNumber" ILIKE $${n} OR "lcAccountId" ILIKE $${n} OR "pmsPatientId" ILIKE $${n})`);
    }
    if (praxisId && praxisId.trim()) {
      params.push(praxisId.trim());
      clauses.push(`"praxisId" = $${params.length}`);
    }

    const where = clauses.length ? 'WHERE ' + clauses.join(' AND ') : '';
    const baseSql = `SELECT id, "firstName", "lastName", email, "phoneNumber", "praxisId", "isVerified", "pmsPatientId", "lcAccountId", "createdAt", "modifiedAt" FROM app_user_info ${where} ORDER BY "createdAt" DESC`;
    const countSql = `SELECT COUNT(*) FROM app_user_info ${where}`;
    const result = await paginate(req, baseSql, countSql, params, parseInt(page), parseInt(pageSize));
    res.json(result);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/users/:id', async (req, res) => {
  try {
    const id = parseInt(req.params.id);
    const [userRows, insuranceRows, familyRows, appointmentRows] = await Promise.all([
      query(req, `SELECT * FROM app_user_info WHERE id = $1`, [id]),
      query(req, `SELECT * FROM app_user_insurance_info WHERE "userInfoId" = $1`, [id]),
      query(req, `SELECT * FROM app_user_family_member_info WHERE "userId" = $1 ORDER BY "createdAt" DESC`, [id]),
      query(req, `SELECT id, category, reason, "appointmentId", "pmsAppointmentId", status, "praxisId", "startTime", resource, "createdAt", "modifiedAt" FROM app_user_appointment WHERE "userId" = $1 ORDER BY "createdAt" DESC LIMIT 30`, [id]),
    ]);
    if (!userRows.length) return res.status(404).json({ error: 'User not found' });
    res.json({ user: userRows[0], insurance: insuranceRows[0] || null, family: familyRows, appointments: appointmentRows });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

const ALLOWED_USER_FIELDS = ['firstName', 'lastName', 'email', 'phoneNumber', 'street', 'city', 'postalCode', 'newEmail', 'newPhone'];

app.patch('/api/users/:id', async (req, res) => {
  try {
    const id = parseInt(req.params.id);
    const updates = {};
    for (const [key, val] of Object.entries(req.body)) {
      if (ALLOWED_USER_FIELDS.includes(key)) updates[key] = val;
    }
    if (!Object.keys(updates).length) return res.status(400).json({ error: 'No valid fields to update' });

    const sets = Object.keys(updates).map((k, i) => `"${k}" = $${i + 1}`);
    sets.push(`"modifiedAt" = NOW()`);
    const vals = [...Object.values(updates), id];
    const sql = `UPDATE app_user_info SET ${sets.join(', ')} WHERE id = $${vals.length} RETURNING *`;
    const rows = await query(req, sql, vals);
    res.json(rows[0]);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ─── Routes: bookings ─────────────────────────────────────────────────────────
app.get('/api/bookings', async (req, res) => {
  try {
    const { dateFrom, dateTo, praxisId, status, category, page = 1, pageSize = 50 } = req.query;
    const filters = [
      ['a."praxisId"', '=', praxisId || null],
      ['a.status', '=', status !== undefined && status !== '' ? parseInt(status) : null],
      ['a.category', 'ILIKE', category ? `%${category}%` : null],
      ['a."createdAt"', '>=', dateFrom || null],
      ['a."createdAt"', '<=', dateTo || null],
    ];
    const { where, params } = buildWhere(filters);
    const baseSql = `SELECT a.id, a."appointmentId", a."pmsAppointmentId", a.category, a.reason, a.status, a."praxisId", a."startTime", a.resource, a."createdAt", a."modifiedAt", u."firstName", u."lastName", u.email, u."phoneNumber" FROM app_user_appointment a LEFT JOIN app_user_info u ON u.id = a."userId" ${where} ORDER BY a."createdAt" DESC`;
    const countSql = `SELECT COUNT(*) FROM app_user_appointment a ${where}`;
    const result = await paginate(req, baseSql, countSql, params, parseInt(page), parseInt(pageSize));
    res.json(result);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/guest-bookings', async (req, res) => {
  try {
    const { dateFrom, dateTo, praxisId, status, category, page = 1, pageSize = 50 } = req.query;
    const filters = [
      ['"praxisId"', '=', praxisId || null],
      ['status', '=', status !== undefined && status !== '' ? parseInt(status) : null],
      ['category', 'ILIKE', category ? `%${category}%` : null],
      ['"createdAt"', '>=', dateFrom || null],
      ['"createdAt"', '<=', dateTo || null],
    ];
    const { where, params } = buildWhere(filters);
    const baseSql = `SELECT id, "bookingId", "patientId", category, reason, status, "praxisId", email, "startTime", "isBookedFromPraxis", "hasEmail", "encryptedUserInfo", "createdAt" FROM guest_appointment ${where} ORDER BY "createdAt" DESC`;
    const countSql = `SELECT COUNT(*) FROM guest_appointment ${where}`;
    const result = await paginate(req, baseSql, countSql, params, parseInt(page), parseInt(pageSize));
    res.json(result);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ─── Routes: query runner ─────────────────────────────────────────────────────
const MUTATION_PATTERN = /^\s*(INSERT|UPDATE|DELETE|DROP|TRUNCATE|CREATE|ALTER|GRANT|REVOKE)\b/i;

app.post('/api/query', async (req, res) => {
  try {
    const { sql, allowMutations } = req.body;
    if (!sql || !sql.trim()) return res.status(400).json({ error: 'No SQL provided' });
    if (!allowMutations && MUTATION_PATTERN.test(sql)) {
      return res.status(403).json({ error: 'Mutations blocked. Enable write mode to run INSERT/UPDATE/DELETE.' });
    }
    const rows = await query(req, sql);
    res.json({ rows, count: rows.length });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

// ─── Routes: AI query builder ─────────────────────────────────────────────────
const DB_SCHEMA_CONTEXT = `
You are a PostgreSQL expert for the LillianCare healthcare platform.
Generate correct PostgreSQL queries based on user requests.

RULES:
- Only generate SELECT queries unless user explicitly asks for UPDATE/INSERT/DELETE
- Always use double quotes for camelCase column names: "firstName", "createdAt", etc.
- Timestamps are in UTC in the DB. Use AT TIME ZONE 'Europe/Berlin' for display.
- Return ONLY the SQL query (no explanation, no markdown fences, no trailing semicolon)
- For relative dates like "today" or "this week" use NOW() AT TIME ZONE 'Europe/Berlin'

KEY TABLES AND COLUMNS:

app_user_info (id, email, "firstName", "lastName", "phoneNumber", gender, dob, consent, "praxisId", "mfaActivated", street, city, "postalCode", "isVerified", "lcAccountId", "pmsPatientId", "verifiedBy", "verifiedOn", "createdAt", "modifiedAt")

app_user_appointment (id, "userId" FK→app_user_info.id, "familyMemberId", category, reason, "appointmentId", "pmsAppointmentId", status [int 0-10], "praxisId", "startTime" [text ISO], resource, "createdAt", "modifiedAt")
  status enum: 0=proposed 1=pending 2=booked 3=arrived 4=fulfilled 5=cancelled 6=noshow 7=enteredInError 8=checkedIn 9=waitlist 10=rescheduled

guest_appointment (id, "bookingId", "patientId", category, reason, status [same enum], "praxisId", email, "encryptedUserInfo", "startTime" [text ISO], "isBookedFromPraxis", "hasEmail", "createdAt", "modifiedAt")

admin_audit_log (id, "userId", "userName", "userEmail", action, changes, "praxisId", "createdAt")

notification_log (id, "userId" FK→app_user_info.id, title, type [int], "activityId", body, "isNew", "createdAt")
  type enum: 0=accountVerified 1=appointmentRescheduledByPraxis 2=appointmentCancelledByPraxis 3=appointmentBookedByPraxis 4=appointmentReminder 5=newDocument 6=unknown

serverpod_session_log (id, "serverId", "time", module, endpoint, method, duration [float ms], "numQueries", slow [bool], error, "stackTrace", "authenticatedUserId", "isOpen")

serverpod_log (id, "sessionLogId" FK→serverpod_session_log.id, "logLevel" [0=debug 1=info 2=warning 3=error 4=fatal], message, error, "stackTrace", "time", "order")

serverpod_query_log (id, "sessionLogId", query, duration, "numRows", error, slow, "order")

app_user_insurance_info (id, "userInfoId" FK→app_user_info.id, "insuranceNumber", "insuranceType", status, provider, validity, "ikNumber", "createdAt")

app_user_family_member_info (id, "userId" FK→app_user_info.id, "familyMemberId", "firstName", "lastName", dob, gender, "insuranceType", "insuranceNumber", "pmsPatientId", "createdAt")

COMMON JOINS:
- appointments + user: JOIN app_user_info u ON u.id = a."userId"
- notifications + user: LEFT JOIN app_user_info u ON u.id = nl."userId"
`;

const bedrockClient = new BedrockRuntimeClient({ region: 'eu-central-1' });

// ─── AWS Monitoring Clients ───────────────────────────────────────────────────
const AWS_REGION = 'eu-central-1';
const ec2Client = new EC2Client({ region: AWS_REGION });
const cloudwatchClient = new CloudWatchClient({ region: AWS_REGION });
const cwLogsClient = new CloudWatchLogsClient({ region: AWS_REGION });
const rdsClient = new RDSClient({ region: AWS_REGION });
const elbv2Client = new ElasticLoadBalancingV2Client({ region: AWS_REGION });
const elasticacheClient = new ElastiCacheClient({ region: AWS_REGION });
const s3Client = new S3Client({ region: AWS_REGION });
const cloudfrontClient = new CloudFrontClient({ region: AWS_REGION });
let infraCache = null;

app.post('/api/ai/query', async (req, res) => {
  try {
    const { messages, modelId = 'eu.anthropic.claude-sonnet-4-5-20250929-v1:0' } = req.body;
    if (!messages || !messages.length) return res.status(400).json({ error: 'No messages provided' });

    const command = new ConverseCommand({
      modelId,
      system: [{ text: DB_SCHEMA_CONTEXT }],
      messages: messages.map(m => ({
        role: m.role,
        content: [{ text: m.content }],
      })),
      inferenceConfig: { maxTokens: 2000, temperature: 0.1 },
    });

    const response = await bedrockClient.send(command);
    const raw = response.output.message.content[0].text.trim();
    const sql = raw.replace(/^```(?:sql)?\s*\n?/i, '').replace(/\n?```\s*$/, '');
    res.json({ sql });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ─── Routes: future calls ─────────────────────────────────────────────────────
app.get('/api/future-calls', async (req, res) => {
  try {
    const { name, page = 1, pageSize = 50 } = req.query;
    const filters = [['name', 'ILIKE', name ? `%${name}%` : null]];
    const { where, params } = buildWhere(filters);
    const baseSql = `SELECT id, name, "time", "serverId", identifier FROM serverpod_future_call ${where} ORDER BY "time" ASC`;
    const countSql = `SELECT COUNT(*) FROM serverpod_future_call ${where}`;
    const result = await paginate(req, baseSql, countSql, params, parseInt(page), parseInt(pageSize));
    res.json(result);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.delete('/api/future-calls/:id', async (req, res) => {
  try {
    await query(req, `DELETE FROM serverpod_future_call WHERE id = $1`, [parseInt(req.params.id)]);
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ─── Routes: server health ────────────────────────────────────────────────────
app.get('/api/health', async (req, res) => {
  try {
    const [metrics, connections] = await Promise.all([
      query(req, `SELECT name, "serverId", "timestamp", "isHealthy", value FROM serverpod_health_metric ORDER BY "timestamp" DESC LIMIT 100`),
      query(req, `SELECT "serverId", "timestamp", active, closing, idle FROM serverpod_health_connection_info ORDER BY "timestamp" DESC LIMIT 20`),
    ]);
    res.json({ metrics, connections });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ─── Routes: API keys ─────────────────────────────────────────────────────────
app.get('/api/api-keys', async (req, res) => {
  try {
    const rows = await query(req, `SELECT id, "customerName", "customerUUID", "usageCount", "createdAt", "expiresAt", status, "lastUsedAt", permissions FROM api_keys ORDER BY "createdAt" DESC`);
    res.json(rows);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.patch('/api/api-keys/:id/status', async (req, res) => {
  try {
    const { status } = req.body;
    const rows = await query(req, `UPDATE api_keys SET status = $1 WHERE id = $2 RETURNING *`, [parseInt(status), parseInt(req.params.id)]);
    res.json(rows[0]);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ─── Routes: verify user ──────────────────────────────────────────────────────
app.post('/api/users/:id/verify', async (req, res) => {
  try {
    const id = parseInt(req.params.id);
    const { verifiedBy = 'Debugger', verifiedByDocument = 'manual', verifiedByDocumentNumber = 'manual', verifiedByPraxisId = null } = req.body;
    const rows = await query(req, `UPDATE app_user_info SET "isVerified" = true, "verifiedBy" = $1, "verifiedOn" = NOW(), "verifiedByDocument" = $2, "verifiedByDocumentNumber" = $3, "verifiedByPraxisId" = $4, "modifiedAt" = NOW() WHERE id = $5 RETURNING *`,
      [verifiedBy, verifiedByDocument, verifiedByDocumentNumber, verifiedByPraxisId, id]);
    if (!rows.length) return res.status(404).json({ error: 'User not found' });
    res.json({ ok: true, user: rows[0] });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ─── Routes: notifications via FCM ───────────────────────────────────────────
const FCM_CONFIG_PATH = path.join(__dirname, '.fcm_service_account.json');

app.post('/api/fcm/config', (req, res) => {
  try {
    const { serviceAccount } = req.body;
    const parsed = typeof serviceAccount === 'string' ? JSON.parse(serviceAccount) : serviceAccount;
    if (!parsed.project_id || !parsed.private_key || !parsed.client_email) {
      return res.status(400).json({ error: 'Invalid service account JSON — missing project_id, private_key, or client_email' });
    }
    fs.writeFileSync(FCM_CONFIG_PATH, JSON.stringify(parsed, null, 2));
    res.json({ ok: true, projectId: parsed.project_id });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

app.get('/api/fcm/config', (req, res) => {
  try {
    if (!fs.existsSync(FCM_CONFIG_PATH)) return res.json({ configured: false });
    const sa = JSON.parse(fs.readFileSync(FCM_CONFIG_PATH, 'utf8'));
    res.json({ configured: true, projectId: sa.project_id, clientEmail: sa.client_email });
  } catch (e) {
    res.json({ configured: false });
  }
});

app.get('/api/users/:id/tokens', async (req, res) => {
  try {
    const rows = await query(req, `SELECT id, token, "deviceId", platform, "createdAt", "lastUsedAt" FROM app_user_notification_token WHERE "userId" = $1 ORDER BY "createdAt" DESC`, [parseInt(req.params.id)]);
    res.json(rows);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/fcm/send', async (req, res) => {
  try {
    if (!fs.existsSync(FCM_CONFIG_PATH)) return res.status(400).json({ error: 'Firebase not configured. Add service account first.' });
    const sa = JSON.parse(fs.readFileSync(FCM_CONFIG_PATH, 'utf8'));
    const { tokens, title, body, data = {} } = req.body;
    if (!tokens || !tokens.length) return res.status(400).json({ error: 'No tokens provided' });
    if (!title || !body) return res.status(400).json({ error: 'title and body are required' });

    const auth = new GoogleAuth({ credentials: sa, scopes: ['https://www.googleapis.com/auth/firebase.messaging'] });
    const accessToken = await auth.getAccessToken();

    const results = [];
    for (const token of tokens) {
      const payload = {
        message: {
          token,
          notification: { title, body },
          data: Object.fromEntries(Object.entries(data).map(([k, v]) => [k, String(v)])),
        },
      };
      const fcmRes = await fetch(`https://fcm.googleapis.com/v1/projects/${sa.project_id}/messages:send`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${accessToken}`, 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });
      const result = await fcmRes.json();
      results.push({ token: token.slice(-10), ok: !result.error, error: result.error?.message });
    }
    res.json({ results, sent: results.filter(r => r.ok).length, failed: results.filter(r => !r.ok).length });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ─── Routes: monitoring – infra overview ─────────────────────────────────────
app.get('/api/monitor/infra/overview', async (req, res) => {
  try {
    const now = Date.now();
    if (infraCache && now - infraCache.ts < 30000) return res.json(infraCache.data);

    const [ec2Res, rdsRes, redisRes, albRes, cfRes, s3Res] = await Promise.all([
      ec2Client.send(new DescribeInstancesCommand({ Filters: [{ Name: 'instance-state-name', Values: ['running', 'stopped', 'pending'] }] })),
      rdsClient.send(new DescribeDBInstancesCommand({})),
      elasticacheClient.send(new DescribeCacheClustersCommand({ ShowCacheNodeInfo: true })),
      elbv2Client.send(new DescribeLoadBalancersCommand({})),
      cloudfrontClient.send(new ListDistributionsCommand({})),
      s3Client.send(new ListBucketsCommand({})),
    ]);

    const data = {
      ec2: ec2Res.Reservations.flatMap(r => r.Instances).map(i => ({
        id: i.InstanceId,
        name: i.Tags?.find(t => t.Key === 'Name')?.Value || i.InstanceId,
        state: i.State.Name,
        type: i.InstanceType,
        launchTime: i.LaunchTime,
        publicIp: i.PublicIpAddress || null,
        privateIp: i.PrivateIpAddress || null,
        az: i.Placement?.AvailabilityZone,
      })),
      rds: rdsRes.DBInstances.map(db => ({
        id: db.DBInstanceIdentifier,
        status: db.DBInstanceStatus,
        engine: db.Engine,
        engineVersion: db.EngineVersion,
        class: db.DBInstanceClass,
        endpoint: db.Endpoint?.Address || null,
        port: db.Endpoint?.Port || null,
        storage: db.AllocatedStorage,
        multiAz: db.MultiAZ,
      })),
      redis: redisRes.CacheClusters.map(c => ({
        id: c.CacheClusterId,
        status: c.CacheClusterStatus,
        engine: c.Engine,
        engineVersion: c.EngineVersion,
        nodeType: c.CacheNodeType,
        nodes: (c.CacheNodes || []).map(n => ({ id: n.CacheNodeId, status: n.CacheNodeStatus, endpoint: n.Endpoint?.Address || null })),
      })),
      alb: albRes.LoadBalancers.map(lb => ({
        name: lb.LoadBalancerName,
        arn: lb.LoadBalancerArn,
        arnSuffix: lb.LoadBalancerArn.split(':loadbalancer/')[1] || lb.LoadBalancerName,
        state: lb.State.Code,
        dns: lb.DNSName,
        type: lb.Type,
        scheme: lb.Scheme,
      })),
      cloudfront: ((cfRes.DistributionList && cfRes.DistributionList.Items) || []).map(d => ({
        id: d.Id,
        domain: d.DomainName,
        status: d.Status,
        origin: (d.Origins && d.Origins.Items && d.Origins.Items[0]) ? d.Origins.Items[0].DomainName : null,
        aliases: (d.Aliases && d.Aliases.Items) || [],
        enabled: d.Enabled,
      })),
      s3: (s3Res.Buckets || []).map(b => ({ name: b.Name, created: b.CreationDate })),
    };

    infraCache = { ts: now, data };
    res.json(data);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ─── Routes: monitoring – cloudwatch alarms ───────────────────────────────────
app.get('/api/monitor/cloudwatch/alarms', async (req, res) => {
  try {
    const result = await cloudwatchClient.send(new DescribeAlarmsCommand({ MaxRecords: 100 }));
    const alarms = (result.MetricAlarms || []).map(a => ({
      name: a.AlarmName,
      state: a.StateValue,
      reason: a.StateReason,
      updatedAt: a.StateUpdatedTimestamp,
      metric: a.MetricName,
      namespace: a.Namespace,
      threshold: a.Threshold,
      comparisonOp: a.ComparisonOperator,
      period: a.Period,
      dimensions: a.Dimensions,
      description: a.AlarmDescription || null,
    }));
    res.json(alarms);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ─── Routes: monitoring – cloudwatch metrics ──────────────────────────────────
app.post('/api/monitor/cloudwatch/metrics', async (req, res) => {
  try {
    const { queries, startTime, endTime } = req.body;
    if (!queries || !queries.length) return res.status(400).json({ error: 'queries required' });
    const result = await cloudwatchClient.send(new GetMetricDataCommand({
      MetricDataQueries: queries.map((q, i) => ({
        Id: q.id || `m${i}`,
        MetricStat: {
          Metric: {
            Namespace: q.namespace,
            MetricName: q.metricName,
            Dimensions: (q.dimensions || []).map(d => ({ Name: d.name, Value: d.value })),
          },
          Period: q.period || 300,
          Stat: q.stat || 'Average',
        },
        Label: q.label || q.metricName,
      })),
      StartTime: new Date(startTime),
      EndTime: new Date(endTime),
    }));
    res.json(result.MetricDataResults || []);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ─── Routes: monitoring – cloudwatch log groups ───────────────────────────────
app.get('/api/monitor/logs/cloudwatch/groups', async (req, res) => {
  try {
    const result = await cwLogsClient.send(new DescribeLogGroupsCommand({}));
    res.json((result.logGroups || []).map(g => ({ name: g.logGroupName, bytes: g.storedBytes, retention: g.retentionInDays })));
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/monitor/logs/cloudwatch/events', async (req, res) => {
  try {
    const { logGroup, filterPattern = '', limit = 50, startTime, endTime, nextToken } = req.query;
    if (!logGroup) return res.status(400).json({ error: 'logGroup required' });
    const params = { logGroupName: logGroup, limit: parseInt(limit) };
    if (filterPattern) params.filterPattern = filterPattern;
    if (startTime) params.startTime = parseInt(startTime);
    if (endTime) params.endTime = parseInt(endTime);
    if (nextToken) params.nextToken = nextToken;
    const result = await cwLogsClient.send(new FilterLogEventsCommand(params));
    res.json({ events: result.events || [], nextToken: result.nextToken });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ─── Routes: monitoring – error summary ──────────────────────────────────────
app.get('/api/monitor/errors/summary', async (req, res) => {
  try {
    const [hourly, topEndpoints, totalRow, recentRows] = await Promise.all([
      query(req, `
        SELECT date_trunc('hour', "time") AS hour, COUNT(*)::int AS count
        FROM serverpod_session_log
        WHERE "time" > NOW() - INTERVAL '24 hours' AND error IS NOT NULL
        GROUP BY 1 ORDER BY 1 ASC
      `),
      query(req, `
        SELECT COALESCE(endpoint, 'unknown') AS endpoint, COUNT(*)::int AS count
        FROM serverpod_session_log
        WHERE error IS NOT NULL AND "time" > NOW() - INTERVAL '24 hours'
        GROUP BY endpoint ORDER BY count DESC LIMIT 10
      `),
      query(req, `SELECT COUNT(*)::int AS count FROM serverpod_session_log WHERE error IS NOT NULL AND "time" > NOW() - INTERVAL '24 hours'`),
      query(req, `
        SELECT id, "time", endpoint, method, duration, error, "stackTrace"
        FROM serverpod_session_log
        WHERE error IS NOT NULL
        ORDER BY "time" DESC LIMIT 30
      `),
    ]);
    res.json({ hourly, topEndpoints, total: totalRow[0]?.count || 0, recent: recentRows });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/monitor/errors/pms-downtime', async (req, res) => {
  try {
    const rows = await query(req, `
      SELECT id, "totalDownTimeInSeconds", "createdAt"
      FROM analytics_pms_downtime
      ORDER BY "createdAt" DESC LIMIT 50
    `);
    res.json(rows);
  } catch (e) {
    // Table might not exist in all environments
    res.json([]);
  }
});

// ─── Routes: monitoring – live log SSE stream ────────────────────────────────
// EventSource doesn't support custom headers, so DB config comes via query params.
app.get('/api/monitor/logs/stream', (req, res) => {
  res.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache',
    'Connection': 'keep-alive',
    'X-Accel-Buffering': 'no',
  });
  res.write(': connected\n\n');

  const heartbeat = setInterval(() => res.write(': heartbeat\n\n'), 15000);

  // Build pool from query params
  const host = req.query.dbHost || 'localhost';
  const port = parseInt(req.query.dbPort || '8090');
  const database = req.query.dbName || 'lillian_care_core';
  const user = req.query.dbUser || 'postgres';
  const password = req.query.dbPass || '';

  const key = `${host}:${port}/${database}:${user}:${password}`;
  if (!pools[key]) {
    pools[key] = new Pool({
      host, port, database, user, password,
      max: 2,
      idleTimeoutMillis: 60000,
      connectionTimeoutMillis: 5000,
      ssl: host !== 'localhost' ? { rejectUnauthorized: false } : false,
    });
  }
  const pool = pools[key];

  // Send recent logs immediately on connect (last 5 minutes of history)
  (async () => {
    try {
      const since = new Date(Date.now() - 5 * 60 * 1000).toISOString();
      const [sessionErrors, appLogs] = await Promise.all([
        pool.query(
          `SELECT id, "time", endpoint, method, duration, error, "stackTrace", "authenticatedUserId"
           FROM serverpod_session_log
           WHERE "time" > $1 AND error IS NOT NULL
           ORDER BY "time" DESC LIMIT 30`,
          [since]
        ),
        pool.query(
          `SELECT sl.id, sl."time", sl."logLevel", sl.message, sl.error, sl."stackTrace",
                  ss.endpoint, ss.method
           FROM serverpod_log sl
           JOIN serverpod_session_log ss ON ss.id = sl."sessionLogId"
           WHERE sl."time" > $1
           ORDER BY sl."time" DESC LIMIT 50`,
          [since]
        ),
      ]);
      res.write(`data: ${JSON.stringify({ type: 'history', sessionErrors: sessionErrors.rows.reverse(), appLogs: appLogs.rows.reverse() })}\n\n`);
    } catch (e) {
      res.write(`data: ${JSON.stringify({ type: 'error', message: e.message || e.code || String(e) })}\n\n`);
    }
  })();

  let lastTime = new Date().toISOString();

  const pollInterval = setInterval(async () => {
    try {
      const [sessionErrors, appLogs] = await Promise.all([
        pool.query(
          `SELECT id, "time", endpoint, method, duration, error, "stackTrace", "authenticatedUserId"
           FROM serverpod_session_log
           WHERE "time" > $1 AND error IS NOT NULL
           ORDER BY "time" ASC LIMIT 20`,
          [lastTime]
        ),
        pool.query(
          `SELECT sl.id, sl."time", sl."logLevel", sl.message, sl.error, sl."stackTrace",
                  ss.endpoint, ss.method
           FROM serverpod_log sl
           JOIN serverpod_session_log ss ON ss.id = sl."sessionLogId"
           WHERE sl."time" > $1
           ORDER BY sl."time" ASC LIMIT 50`,
          [lastTime]
        ),
      ]);

      const newTs = new Date().toISOString();
      if (sessionErrors.rows.length > 0 || appLogs.rows.length > 0) {
        lastTime = newTs;
        res.write(`data: ${JSON.stringify({ type: 'logs', sessionErrors: sessionErrors.rows, appLogs: appLogs.rows, ts: newTs })}\n\n`);
      } else {
        lastTime = newTs;
      }
    } catch (e) {
      res.write(`data: ${JSON.stringify({ type: 'error', message: e.message || e.code || String(e) })}\n\n`);
    }
  }, 5000);

  req.on('close', () => {
    clearInterval(heartbeat);
    clearInterval(pollInterval);
  });
});

// ─── Static files ─────────────────────────────────────────────────────────────
app.use(express.static(path.join(__dirname, 'public')));

app.listen(3333, () => {
  console.log('LillianCare Debugger running at http://localhost:3333');
});
