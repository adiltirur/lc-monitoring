require('dotenv').config();
const express = require('express');
const { Pool, Client } = require('pg');
const path = require('path');
const fs = require('fs');
const { BedrockRuntimeClient, ConverseCommand } = require('@aws-sdk/client-bedrock-runtime');
const { GoogleAuth } = require('google-auth-library');
const { EC2Client, DescribeInstancesCommand } = require('@aws-sdk/client-ec2');
const { CloudWatchClient, GetMetricDataCommand, DescribeAlarmsCommand, SetAlarmStateCommand } = require('@aws-sdk/client-cloudwatch');
const { CloudWatchLogsClient, FilterLogEventsCommand, DescribeLogGroupsCommand } = require('@aws-sdk/client-cloudwatch-logs');
const {
  RDSClient,
  DescribeDBInstancesCommand,
  DescribeDBClustersCommand,
  DescribeDBClusterSnapshotsCommand,
  RestoreDBClusterFromSnapshotCommand,
  RestoreDBClusterToPointInTimeCommand,
  RestoreDBInstanceFromDBSnapshotCommand,
  RestoreDBInstanceToPointInTimeCommand,
  CreateDBInstanceCommand,
  DeleteDBInstanceCommand,
  DeleteDBClusterCommand,
} = require('@aws-sdk/client-rds');
const { ElasticLoadBalancingV2Client, DescribeLoadBalancersCommand } = require('@aws-sdk/client-elastic-load-balancing-v2');
const { ElastiCacheClient, DescribeCacheClustersCommand } = require('@aws-sdk/client-elasticache');
const { S3Client, ListBucketsCommand } = require('@aws-sdk/client-s3');
const { CloudFrontClient, ListDistributionsCommand } = require('@aws-sdk/client-cloudfront');

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

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
async function paginate(req, baseSql, countSql, params, page, pageSize, opts = {}) {
  const offset = (page - 1) * pageSize;
  const { estimateTable } = opts;
  // If no filters are applied AND an estimateTable hint is provided, skip the
  // expensive COUNT(*) and use Postgres's row estimate from pg_class instead.
  // This avoids a full sequential scan on huge log tables.
  const useEstimate = estimateTable && params.length === 0;
  const countPromise = useEstimate
    ? query(req, `SELECT reltuples::bigint AS count FROM pg_class WHERE oid = $1::regclass`, [estimateTable])
    : query(req, countSql, params);
  const [rows, countRows] = await Promise.all([
    query(req, `${baseSql} LIMIT $${params.length + 1} OFFSET $${params.length + 2}`, [...params, pageSize, offset]),
    countPromise,
  ]);
  return { rows, total: parseInt(countRows[0].count), page, pageSize, estimated: useEstimate };
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
      test:       process.env.DB_TEST_PASSWORD       || '',
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

// ─── PMS (principa FHIR) proxy ────────────────────────────────────────────────
// Mirrors the backend's `FHIRApiCaller` + `JwtProvider` (Dart) so the helper
// can list a user's medications and documents from PMS. All calls are made
// server-side; the browser never sees the secret.
const crypto = require('crypto');

// Both lcTestIdentifier and lcProdIdentifier are 'app.lillian-care.de' in
// LillianCare-Core/.../const/fhir_string.dart:9-10 — test + prod share the
// same identifier system, so one constant is enough.
const PMS_IDENTIFIER = 'app.lillian-care.de';

const PMS_CONFIG = {
  dev:        { baseUrl: process.env.PMS_BASE_URL_DEV,     secret: process.env.PMS_SECRET_TEST },
  staging:    { baseUrl: process.env.PMS_BASE_URL_STAGING, secret: process.env.PMS_SECRET_TEST },
  production: { baseUrl: process.env.PMS_BASE_URL_PROD,    secret: process.env.PMS_SECRET_PROD },
};

// HS256 JWT cache keyed by secret. Matches JwtProvider: 10-min TTL, refresh
// 60 s before expiry, drop on 401.
const jwtCache = new Map();
function pmsJwt(secret) {
  const now = Math.floor(Date.now() / 1000);
  const cached = jwtCache.get(secret);
  if (cached && now < cached.expiresAt - 60) return cached.token;
  const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
  const body   = Buffer.from(JSON.stringify({ iat: now, exp: now + 600 })).toString('base64url');
  const sig    = crypto.createHmac('sha256', secret).update(`${header}.${body}`).digest('base64url');
  const token  = `${header}.${body}.${sig}`;
  jwtCache.set(secret, { token, expiresAt: now + 600 });
  return token;
}

function pmsConfigFromReq(req) {
  const env = req.headers['x-env'] || 'dev';
  const cfg = PMS_CONFIG[env];
  if (!cfg || !cfg.baseUrl || !cfg.secret) {
    const err = new Error(`PMS not configured for env "${env}" — set PMS_BASE_URL_* and PMS_SECRET_* in .env`);
    err.status = 503;
    throw err;
  }
  return cfg;
}

async function pmsFetch(req, path) {
  const cfg = pmsConfigFromReq(req);
  const url = cfg.baseUrl.replace(/\/$/, '') + '/' + path.replace(/^\//, '');
  const hit = async () => fetch(url, {
    headers: { 'Accept': 'application/fhir+json', 'Authorization': `Bearer ${pmsJwt(cfg.secret)}` },
  });
  let res = await hit();
  if (res.status === 401) { jwtCache.delete(cfg.secret); res = await hit(); }
  if (!res.ok) {
    const text = await res.text().catch(() => '');
    const hdrs = {};
    res.headers.forEach((v, k) => { hdrs[k] = v; });
    console.error(`[pms] ${res.status} ${url}\n  headers: ${JSON.stringify(hdrs)}\n  body: ${text || '(empty)'}`);
    // FHIR servers return OperationOutcome on errors; pull the issue.diagnostics
    // if present for a more useful message.
    let msg = text;
    try {
      const j = JSON.parse(text);
      if (j.resourceType === 'OperationOutcome' && Array.isArray(j.issue) && j.issue[0]) {
        const iss = j.issue[0];
        msg = iss.diagnostics || iss.details?.text || iss.code || text;
      }
    } catch { /* not JSON */ }
    throw Object.assign(new Error(`PMS ${res.status}: ${(msg || '(empty body)').toString().slice(0, 400)}`), { status: res.status });
  }
  return res.json();
}

// Bundle parsers. We pull just the fields the UI surfaces — light-touch,
// mirrors the Dart mappers (ApiUserDocument, ApiMedicationRes) for debug use.
function parseDocumentBundle(bundle) {
  const entries = (bundle && bundle.entry) || [];
  return entries
    .map(e => e.resource)
    .filter(r => r && r.resourceType === 'DocumentReference')
    .map(doc => {
      const content = (doc.content || [])[0] || {};
      const attachment = content.attachment || {};
      const binaryRef = attachment.url || '';
      // binary ref is typically "Binary/<id>" — strip the prefix for our /api/pms/binary/:id route.
      const binaryID = binaryRef.replace(/^Binary\//, '');
      const typeCoding = (doc.type && doc.type.coding && doc.type.coding[0]) || {};
      return {
        id: doc.id || '',
        binaryID,
        title: attachment.title || doc.description || '(untitled)',
        description: doc.description || '',
        contentType: attachment.contentType || '',
        createdAt: attachment.creation || doc.date || '',
        documentType: typeCoding.display || typeCoding.code || '',
      };
    })
    .sort((a, b) => String(b.createdAt).localeCompare(String(a.createdAt)));
}

function parseMedicationBundle(bundle) {
  const entries = (bundle && bundle.entry) || [];
  const resources = entries.map(e => e.resource).filter(Boolean);
  const medById = {};
  for (const r of resources) {
    if (r.resourceType === 'Medication' && r.id) medById[`Medication/${r.id}`] = r;
  }
  const requests = resources.filter(r => r.resourceType === 'MedicationRequest');
  return requests
    .map(req => {
      const medRef = (req.medicationReference && req.medicationReference.reference) || '';
      const med = medById[medRef];
      const medCoding = (med && med.code && med.code.coding && med.code.coding[0]) || {};
      const medName =
        (med && med.code && med.code.text) ||
        medCoding.display ||
        (req.medicationCodeableConcept && req.medicationCodeableConcept.text) ||
        '(unnamed medication)';
      // PZN is typically in Medication.code.coding with system containing "pzn".
      const pzn = ((med && med.code && med.code.coding) || [])
        .find(c => c.system && /pzn/i.test(c.system));
      const dosage = (req.dosageInstruction || []).map(d => ({
        text: d.text || d.patientInstruction || '',
        asNeeded: d.asNeededBoolean === true,
        doseQuantity: (d.doseAndRate && d.doseAndRate[0] && d.doseAndRate[0].doseQuantity) || null,
      }));
      const reason =
        (req.reasonCode || [])
          .map(r => (r.text || (r.coding && r.coding[0] && r.coding[0].display) || ''))
          .filter(Boolean)
          .join(', ');
      const form = (med && med.form && med.form.coding && med.form.coding[0] && med.form.coding[0].display) || '';
      return {
        id: req.id || '',
        medicationName: medName,
        status: req.status || '',
        intent: req.intent || '',
        authoredOn: req.authoredOn || '',
        pzn: pzn ? pzn.code : null,
        form,
        reason,
        dosage,
        manufacturer: (med && med.manufacturer && med.manufacturer.display) || null,
        note: (req.note || []).map(n => n.text).filter(Boolean).join('\n'),
        validityEnd: req.dispenseRequest && req.dispenseRequest.validityPeriod && req.dispenseRequest.validityPeriod.end || null,
      };
    })
    .sort((a, b) => String(b.authoredOn).localeCompare(String(a.authoredOn)));
}

// URLs below match the exact wire format the Dart backend sends via
// Uri.parse(): `|` encoded to %7C; `:` / `/` inside _profile stay RAW.
// HAPI FHIR's _profile matching rejects the fully-encoded form.
app.get('/api/pms/users/:lcAccountId/documents', async (req, res) => {
  try {
    const id = encodeURIComponent(req.params.lcAccountId);
    const path =
      `DocumentReference?subject.identifier=${PMS_IDENTIFIER}%7C${id}` +
      `&_profile=https://app.lillian-care.de/DocumentReference`;
    const bundle = await pmsFetch(req, path);
    res.json({ documents: parseDocumentBundle(bundle) });
  } catch (e) {
    res.status(e.status || 500).json({ error: e.message });
  }
});

app.get('/api/pms/users/:lcAccountId/medications', async (req, res) => {
  try {
    const id = encodeURIComponent(req.params.lcAccountId);
    const path =
      `MedicationRequest?subject:Patient.identifier=${PMS_IDENTIFIER}%7C${id}` +
      `&_include=Medication&_profile=http://medicationrequest.lilliancare.de`;
    const bundle = await pmsFetch(req, path);
    res.json({ medications: parseMedicationBundle(bundle) });
  } catch (e) {
    res.status(e.status || 500).json({ error: e.message });
  }
});

// Debug: hits PMS `metadata` (CapabilityStatement) — no query params, just
// tests baseUrl + JWT auth. If this returns a Bundle/CapabilityStatement,
// the 400 on searches is a URL-encoding issue, not auth.
app.get('/api/pms/debug/metadata', async (req, res) => {
  try {
    const bundle = await pmsFetch(req, 'metadata');
    res.json({ ok: true, resourceType: bundle.resourceType, fhirVersion: bundle.fhirVersion, software: bundle.software });
  } catch (e) {
    res.status(e.status || 500).json({ error: e.message });
  }
});

app.get('/api/pms/binary/:id', async (req, res) => {
  try {
    const bin = await pmsFetch(req, `Binary/${encodeURIComponent(req.params.id)}`);
    res.json({ contentType: bin.contentType || '', base64: bin.data || '' });
  } catch (e) {
    res.status(e.status || 500).json({ error: e.message });
  }
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

// ─── Routes: protocol introspection ───────────────────────────────────────────
// Parses Serverpod's protocol.yaml to expose the endpoint groups and method
// names without hitting the DB. Matches what session-logs records as
// (endpoint, method) so the UI can show dropdowns instead of free-text inputs.
const PROTOCOL_YAML = '/Users/adil/Work/LillianCare/LillianCare-Core/lillian_care_core_server/lib/src/generated/protocol.yaml';

function parseProtocolYaml(src) {
  // Trivial format: top-level "groupName:" followed by indented "  - methodName:"
  const groups = {};
  let current = null;
  for (const raw of src.split('\n')) {
    if (!raw.trim() || raw.trim().startsWith('#')) continue;
    const groupMatch = raw.match(/^([A-Za-z0-9_]+):\s*$/);
    if (groupMatch) { current = groupMatch[1]; groups[current] = []; continue; }
    const methodMatch = raw.match(/^\s*-\s*([A-Za-z0-9_]+):\s*$/);
    if (methodMatch && current) groups[current].push(methodMatch[1]);
  }
  return groups;
}

let _protocolCache = null;
let _protocolMtime = 0;
app.get('/api/protocol', (_req, res) => {
  try {
    const stat = fs.statSync(PROTOCOL_YAML);
    if (!_protocolCache || stat.mtimeMs !== _protocolMtime) {
      _protocolCache = parseProtocolYaml(fs.readFileSync(PROTOCOL_YAML, 'utf8'));
      _protocolMtime = stat.mtimeMs;
    }
    res.json({ groups: _protocolCache });
  } catch (e) {
    res.status(500).json({ error: e.message });
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

    const result = await paginate(req, baseSql, countSql, params, parseInt(page), parseInt(pageSize), { estimateTable: 'serverpod_session_log' });
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

app.get('/api/future-calls/:id', async (req, res) => {
  try {
    const rows = await query(req, `SELECT id, name, "time", "serverId", identifier, "serializedObject" FROM serverpod_future_call WHERE id = $1`, [parseInt(req.params.id)]);
    if (!rows.length) return res.status(404).json({ error: 'Not found' });
    res.json(rows[0]);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ─── Routes: Analytics (per-praxis monthly metrics) ──────────────────────────
// Port of LillianCare-Core/.../endpoints/admin/analytics/admin_analytics.dart.
// All counts + lists come from the same Postgres DB we already connect to —
// no Serverpod call, no external service.

// Overview across ALL praxes for a date range.
//
// Scaling: one aggregate query per table using GROUP BY "praxisId" — each is a
// single indexed scan regardless of praxis count. We do NOT return row lists
// (no `allAppAppointments` etc.) and no daily time series, so the payload is
// ~10 fields × praxes count, typically under 10 KB even for 100 praxes.
// Total wall time ≈ the slowest single GROUP BY, since everything runs in
// Promise.all. Safe to hit on prod without hanging the DB.
app.get('/api/analytics/overview', async (req, res) => {
  try {
    const now = new Date();
    const parseDate = (s, fb) => { if (!s) return fb; const d = new Date(s); return isNaN(d) ? fb : d; };
    const defaultEnd   = new Date(now.getFullYear(), now.getMonth(), now.getDate() + 1);
    const defaultStart = new Date(defaultEnd.getTime() - 30 * 86400000);
    const start = parseDate(req.query.startDate, defaultStart);
    const end   = parseDate(req.query.endDate,   defaultEnd);
    if (end <= start) return res.status(400).json({ error: 'endDate must be after startDate' });

    const pad = n => String(n).padStart(2, '0');
    const isoNaive = d => `${d.getFullYear()}-${pad(d.getMonth()+1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
    const rangeStart = isoNaive(start);
    const rangeEnd   = isoNaive(end);
    const rangeStartIso = start.toISOString();
    const rangeEndIso   = end.toISOString();

    // Each of these returns [{ praxisId, ...counts }, ...] or a global count.
    const [
      appApptByPraxis,
      guestApptByPraxis,
      appTookPlaceByPraxis,
      guestTookPlaceByPraxis,
      npsSentByPraxis,
      fhirNpsByPraxis,
      docRequestByPraxis,
      openConsultByPraxis,
      newRegByPraxis,
      patientsByPraxis,
      totalCancellations,
      totalQuestionnaires,
      totalDeletions,
      pmsDowntimeSum,
    ] = await Promise.all([
      query(req, `SELECT "praxisId", COUNT(*)::int AS c FROM app_user_appointment
                  WHERE "praxisId" IS NOT NULL AND "createdAt">=$1 AND "createdAt"<$2 GROUP BY "praxisId"`, [rangeStart, rangeEnd]),
      query(req, `SELECT "praxisId",
                    COUNT(*)::int AS total,
                    COUNT(*) FILTER (WHERE "isBookedFromPraxis"=true)::int AS praxis,
                    COUNT(*) FILTER (WHERE "isBookedFromPraxis" IS NOT TRUE)::int AS web,
                    COUNT(*) FILTER (WHERE "isBookedFromPraxis"=true AND "hasEmail"=false)::int AS praxis_no_email
                  FROM guest_appointment
                  WHERE "praxisId" IS NOT NULL AND "createdAt">=$1 AND "createdAt"<$2 GROUP BY "praxisId"`, [rangeStart, rangeEnd]),
      query(req, `SELECT "praxisId", COUNT(*)::int AS c FROM app_user_appointment
                  WHERE "praxisId" IS NOT NULL AND "startTime" IS NOT NULL
                    AND "startTime">=$1 AND "startTime"<$2 ${TOOK_PLACE_STATUS_FILTER}
                  GROUP BY "praxisId"`, [rangeStartIso, rangeEndIso]),
      query(req, `SELECT "praxisId",
                    COUNT(*)::int AS total,
                    COUNT(*) FILTER (WHERE "isBookedFromPraxis"=true)::int AS praxis,
                    COUNT(*) FILTER (WHERE "isBookedFromPraxis" IS NOT TRUE)::int AS web
                  FROM guest_appointment
                  WHERE "praxisId" IS NOT NULL AND "startTime" IS NOT NULL
                    AND "startTime">=$1 AND "startTime"<$2 ${TOOK_PLACE_STATUS_FILTER}
                  GROUP BY "praxisId"`, [rangeStartIso, rangeEndIso]),
      query(req, `SELECT "praxisId", COUNT(*)::int AS c FROM app_user_nps_sent
                  WHERE "createdAt">=$1 AND "createdAt"<$2 GROUP BY "praxisId"`, [rangeStart, rangeEnd]),
      query(req, `SELECT "praxisId",
                    COUNT(*)::int AS total,
                    COUNT(*) FILTER (WHERE "hasEmail"=false)::int AS no_email
                  FROM fhir_nps WHERE "createdAt">=$1 AND "createdAt"<$2 GROUP BY "praxisId"`, [rangeStart, rangeEnd]),
      query(req, `SELECT "praxisId",
                    COUNT(*)::int AS total,
                    COUNT(*) FILTER (WHERE "isFromWeb"=false)::int AS from_app,
                    COUNT(*) FILTER (WHERE "isFromWeb"=true)::int  AS from_web
                  FROM app_user_document_request
                  WHERE "createdAt">=$1 AND "createdAt"<$2 GROUP BY "praxisId"`, [rangeStart, rangeEnd]),
      query(req, `SELECT "praxisId", COUNT(*)::int AS c FROM app_user_open_consultation
                  WHERE "createdAt">=$1 AND "createdAt"<$2 GROUP BY "praxisId"`, [rangeStart, rangeEnd]),
      query(req, `SELECT "praxisId",
                    COUNT(*)::int AS total,
                    COUNT(*) FILTER (WHERE "isVerified"=true)::int AS verified
                  FROM app_user_info
                  WHERE "praxisId" IS NOT NULL AND "createdAt">=$1 AND "createdAt"<$2 GROUP BY "praxisId"`, [rangeStart, rangeEnd]),
      query(req, `SELECT "praxisId",
                    COUNT(*)::int AS total,
                    COUNT(*) FILTER (WHERE "isVerified"=true)::int AS verified
                  FROM app_user_info WHERE "praxisId" IS NOT NULL GROUP BY "praxisId"`, []),
      query(req, `SELECT COUNT(*)::int AS c FROM app_user_appointment_cancellation_reason WHERE "createdAt">=$1 AND "createdAt"<$2`, [rangeStart, rangeEnd]),
      query(req, `SELECT COUNT(*)::int AS c FROM app_user_questionnaire WHERE "answeredAt">=$1 AND "answeredAt"<$2`, [rangeStart, rangeEnd]),
      query(req, `SELECT COUNT(*)::int AS c FROM app_user_deletion_feedback WHERE "createdAt">=$1 AND "createdAt"<$2`, [rangeStart, rangeEnd]),
      query(req, `SELECT COALESCE(SUM("totalDownTimeInSeconds"), 0)::bigint AS s FROM analytics_pms_downtime WHERE "createdAt">=$1 AND "createdAt"<$2`, [rangeStart, rangeEnd]),
    ]);

    // Merge into one row per praxisId.
    const byPraxis = {};
    const touch = id => (byPraxis[id] ||= {
      praxisId: id,
      appAppointments: 0, guestAppointments: 0,
      guestBookedFromWeb: 0, guestBookedFromPraxis: 0, guestBookedFromPraxisNoEmail: 0,
      appointmentsTotal: 0,
      appTookPlace: 0, guestTookPlaceWeb: 0, guestTookPlacePraxis: 0,
      tookPlaceTotal: 0,
      npsEmailsSent: 0,
      guestNPS: 0, guestNPSNoEmail: 0,            // corrected (real :422 attempts)
      guestNPSRaw: 0, guestNPSRawNoEmail: 0,      // raw fhir_nps counts (incl. :329 spurious)
      totalNPS: 0,
      docRequests: 0, docRequestsFromApp: 0, docRequestsFromWeb: 0,
      openConsultations: 0,
      newRegistrations: 0, newVerifiedRegistrations: 0,
      totalPatients: 0, totalVerifiedPatients: 0,
    });

    for (const r of appApptByPraxis)   touch(r.praxisId).appAppointments = r.c;
    for (const r of guestApptByPraxis) {
      const p = touch(r.praxisId);
      p.guestAppointments           = r.total;
      p.guestBookedFromPraxis       = r.praxis;
      p.guestBookedFromWeb          = r.web;
      p.guestBookedFromPraxisNoEmail= r.praxis_no_email;
    }
    for (const r of appTookPlaceByPraxis)   touch(r.praxisId).appTookPlace = r.c;
    for (const r of guestTookPlaceByPraxis) {
      const p = touch(r.praxisId);
      p.guestTookPlaceWeb    = r.web;
      p.guestTookPlacePraxis = r.praxis;
    }
    for (const r of npsSentByPraxis) touch(r.praxisId).npsEmailsSent = r.c;
    for (const r of fhirNpsByPraxis) {
      const p = touch(r.praxisId);
      p.guestNPSRaw        = r.total;
      p.guestNPSRawNoEmail = r.no_email;
    }
    for (const r of docRequestByPraxis) {
      const p = touch(r.praxisId);
      p.docRequests        = r.total;
      p.docRequestsFromApp = r.from_app;
      p.docRequestsFromWeb = r.from_web;
    }
    for (const r of openConsultByPraxis) touch(r.praxisId).openConsultations = r.c;
    for (const r of newRegByPraxis) {
      const p = touch(r.praxisId);
      p.newRegistrations         = r.total;
      p.newVerifiedRegistrations = r.verified;
    }
    for (const r of patientsByPraxis) {
      const p = touch(r.praxisId);
      p.totalPatients         = r.total;
      p.totalVerifiedPatients = r.verified;
    }

    // Derive totals per praxis + rates.
    const praxes = Object.values(byPraxis).map(p => {
      // praxisNoEmail is a subset of guestBookedFromPraxis — do not add it again.
      p.appointmentsTotal = p.appAppointments + p.guestBookedFromWeb + p.guestBookedFromPraxis;
      p.tookPlaceTotal = p.appTookPlace + p.guestTookPlaceWeb + p.guestTookPlacePraxis;
      // guestNPS recovery: subtract :329 spurious writes (= praxis-booked
      // guest_appointments) from raw fhir_nps. See _emptyMonthlyKpi() above
      // for the full explanation of why these are spurious.
      p.guestNPS        = Math.max(0, (p.guestNPSRaw        || 0) - (p.guestBookedFromPraxis         || 0));
      p.guestNPSNoEmail = Math.max(0, (p.guestNPSRawNoEmail || 0) - (p.guestBookedFromPraxisNoEmail || 0));
      p.totalNPS = p.npsEmailsSent + p.guestNPS;
      // NPS-eligible events = appointments + doc requests + open consultations
      // (backend triggers an NPS after each of these). 30-day per-user dedup.
      p.npsEligibleEvents     = p.appointmentsTotal + (p.docRequests || 0) + (p.openConsultations || 0);
      p.npsCoveragePercentage = p.npsEligibleEvents > 0 ? (p.totalNPS / p.npsEligibleEvents) * 100 : 0;
      p.verificationRate      = p.newRegistrations > 0 ? (p.newVerifiedRegistrations / p.newRegistrations) * 100 : 0;
      return p;
    }).sort((a, b) => b.appointmentsTotal - a.appointmentsTotal);

    // Grand totals across all praxes.
    const sumAll = key => praxes.reduce((s, p) => s + (p[key] || 0), 0);
    const summary = {
      praxesCount:             praxes.length,
      appointmentsTotal:       sumAll('appointmentsTotal'),
      tookPlaceTotal:          sumAll('tookPlaceTotal'),
      newRegistrations:        sumAll('newRegistrations'),
      newVerifiedRegistrations:sumAll('newVerifiedRegistrations'),
      totalPatients:           sumAll('totalPatients'),
      totalVerifiedPatients:   sumAll('totalVerifiedPatients'),
      docRequests:             sumAll('docRequests'),
      openConsultations:       sumAll('openConsultations'),
      npsEmailsSent:           sumAll('npsEmailsSent'),
      guestNPS:                sumAll('guestNPS'),
      guestNPSNoEmail:         sumAll('guestNPSNoEmail'),
      guestNPSRaw:             sumAll('guestNPSRaw'),
      guestNPSRawNoEmail:      sumAll('guestNPSRawNoEmail'),
      totalNPS:                sumAll('totalNPS'),
      // Global (not per-praxis in the schema)
      totalCancellations:      totalCancellations[0].c,
      totalQuestionnaires:     totalQuestionnaires[0].c,
      totalDeletions:          totalDeletions[0].c,
      pmsDownTimeInSeconds:    parseInt(pmsDowntimeSum[0].s, 10) || 0,
      pmsDownTimeInMinutes:    (parseInt(pmsDowntimeSum[0].s, 10) || 0) / 60,
    };

    res.json({
      rangeStart: start.toISOString(),
      rangeEnd:   end.toISOString(),
      summary,
      praxes,
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Praxis names — {lcId: "Name"} map. Queried once per DB connection and
// cached for 5 minutes. Tiny table (~100 rows), minimal pressure on the DB.
const praxisNameCache = new Map(); // cacheKey -> { map, expiresAt }
app.get('/api/praxis-names', async (req, res) => {
  try {
    const ck = (req.headers['x-db-host'] || '') + '|' + (req.headers['x-db-name'] || '');
    const now = Date.now();
    const hit = praxisNameCache.get(ck);
    if (hit && hit.expiresAt > now && req.query.refresh !== '1') {
      return res.json({ cached: true, names: hit.map });
    }
    const rows = await query(req, `SELECT "lcId", name, "shortName" FROM praxis_config ORDER BY "lcId"`);
    const map = {};
    for (const r of rows) map[r.lcId] = r.name || r.shortName || r.lcId;
    praxisNameCache.set(ck, { map, expiresAt: now + 5 * 60 * 1000 });
    res.json({ cached: false, names: map });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/analytics/praxes', async (req, res) => {
  try {
    const rows = await query(
      req,
      `SELECT DISTINCT "praxisId" FROM app_user_info
       WHERE "praxisId" IS NOT NULL AND "praxisId" <> ''
       ORDER BY "praxisId"`
    );
    res.json({ praxes: rows.map(r => r.praxisId) });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Port of GetEnhancedAdminAnalytics + EnhancedPraxisAnalyticsCalculator.
// Returns counters, derived rates, daily time series, and top-10 category
// breakdowns — everything the praxis app's analytics_screen.dart renders.
app.get('/api/analytics', async (req, res) => {
  try {
    const praxisId = (req.query.praxisId || '').toString().trim();
    if (!praxisId) return res.status(400).json({ error: 'praxisId is required' });

    const now = new Date();
    const parseDate = (s, fallback) => {
      if (!s) return fallback;
      const d = new Date(s);
      return isNaN(d.getTime()) ? fallback : d;
    };
    // Default = last 30 days ending tomorrow 00:00 (exclusive upper).
    const defaultEnd   = new Date(now.getFullYear(), now.getMonth(), now.getDate() + 1);
    const defaultStart = new Date(defaultEnd.getTime() - 30 * 86400000);
    const start = parseDate(req.query.startDate, defaultStart);
    const end   = parseDate(req.query.endDate,   defaultEnd);
    if (end <= start) return res.status(400).json({ error: 'endDate must be after startDate' });

    const isoNaive = d => {
      const pad = n => String(n).padStart(2, '0');
      return `${d.getFullYear()}-${pad(d.getMonth()+1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
    };
    const rangeStart = isoNaive(start);
    const rangeEnd   = isoNaive(end);
    // startTime on appointments is stored as ISO text ('2026-04-05T10:00:00'),
    // so compare against the ISO form (no space).
    const rangeStartIso = start.toISOString();
    const rangeEndIso   = end.toISOString();

    const countOne = (sql, params) => query(req, sql, params).then(r => parseInt(r[0].count));

    const [
      npsEmailsSent,
      guestNPSSent,
      guestNPSRequestWithoutEmail,
      totalPatients,
      totalVerifiedPatients,
      appointmentsTookPlaceFromApp,
      appointmentsTookPlaceFromWeb,
      appointmentsTookPlaceFromPraxis,
      appointmentsTookPlaceFromPraxisWithoutEmail,
      appAppointmentsInRange,
      webAppointmentsInRange,
      pmsDowntimes,
      openConsultations,
      cancellationReasons,
      newRegistrations,
      documentRequestsInRange,
      questionnairesAnswered,
      deletionFeedback,
    ] = await Promise.all([
      countOne(`SELECT COUNT(*) FROM app_user_nps_sent WHERE "praxisId"=$1 AND "createdAt">=$2 AND "createdAt"<$3`, [praxisId, rangeStart, rangeEnd]),
      countOne(`SELECT COUNT(*) FROM fhir_nps          WHERE "praxisId"=$1 AND "createdAt">=$2 AND "createdAt"<$3`, [praxisId, rangeStart, rangeEnd]),
      countOne(`SELECT COUNT(*) FROM fhir_nps          WHERE "praxisId"=$1 AND "createdAt">=$2 AND "createdAt"<$3 AND "hasEmail"=false`, [praxisId, rangeStart, rangeEnd]),
      countOne(`SELECT COUNT(*) FROM app_user_info     WHERE "praxisId"=$1`, [praxisId]),
      countOne(`SELECT COUNT(*) FROM app_user_info     WHERE "praxisId"=$1 AND "isVerified"=true`, [praxisId]),
      countOne(`SELECT COUNT(*) FROM app_user_appointment WHERE "praxisId"=$1 AND "startTime" IS NOT NULL AND "startTime">=$2 AND "startTime"<$3 ${TOOK_PLACE_STATUS_FILTER}`, [praxisId, rangeStartIso, rangeEndIso]),
      countOne(`SELECT COUNT(*) FROM guest_appointment    WHERE "praxisId"=$1 AND "startTime" IS NOT NULL AND "startTime">=$2 AND "startTime"<$3 AND ("isBookedFromPraxis" IS NOT TRUE) ${TOOK_PLACE_STATUS_FILTER}`, [praxisId, rangeStartIso, rangeEndIso]),
      countOne(`SELECT COUNT(*) FROM guest_appointment    WHERE "praxisId"=$1 AND "startTime" IS NOT NULL AND "startTime">=$2 AND "startTime"<$3 AND "isBookedFromPraxis"=true ${TOOK_PLACE_STATUS_FILTER}`, [praxisId, rangeStartIso, rangeEndIso]),
      countOne(`SELECT COUNT(*) FROM guest_appointment    WHERE "praxisId"=$1 AND "startTime" IS NOT NULL AND "startTime">=$2 AND "startTime"<$3 AND "isBookedFromPraxis"=true AND "hasEmail"=false ${TOOK_PLACE_STATUS_FILTER}`, [praxisId, rangeStartIso, rangeEndIso]),
      query(req, `SELECT id, "userId", "familyMemberId", category, reason, "appointmentId", "pmsAppointmentId", status, "praxisId", "startTime", "createdAt" FROM app_user_appointment WHERE "praxisId"=$1 AND "createdAt">=$2 AND "createdAt"<$3`, [praxisId, rangeStart, rangeEnd]),
      query(req, `SELECT id, "bookingId", "patientId", "praxisId", category, "hasEmail", "isBookedFromPraxis", "createdAt" FROM guest_appointment WHERE "praxisId"=$1 AND "createdAt">=$2 AND "createdAt"<$3`, [praxisId, rangeStart, rangeEnd]),
      query(req, `SELECT id, "totalDownTimeInSeconds", "createdAt" FROM analytics_pms_downtime WHERE "createdAt">=$1 AND "createdAt"<$2`, [rangeStart, rangeEnd]),
      query(req, `SELECT id, "userId", category, reason, "praxisId", status, "createdAt" FROM app_user_open_consultation WHERE "praxisId"=$1 AND "createdAt">=$2 AND "createdAt"<$3`, [praxisId, rangeStart, rangeEnd]),
      query(req, `SELECT c.id, c."userId", c.reason, c."createdAt"
                    FROM app_user_appointment_cancellation_reason c
                    JOIN app_user_info ui ON ui.id = c."userId"
                    WHERE ui."praxisId"=$1 AND c."createdAt">=$2 AND c."createdAt"<$3
                      AND EXISTS (
                        SELECT 1 FROM app_user_appointment a
                        WHERE a."userId" = c."userId" AND a."praxisId" = $1
                      )`, [praxisId, rangeStart, rangeEnd]),
      query(req, `SELECT id, "firstName", "lastName", email, "praxisId", "isVerified", "createdAt" FROM app_user_info WHERE "praxisId"=$1 AND "createdAt">=$2 AND "createdAt"<$3`, [praxisId, rangeStart, rangeEnd]),
      query(req, `SELECT id, "userId", category, "praxisId", "isFromWeb", "createdAt" FROM app_user_document_request WHERE "praxisId"=$1 AND "createdAt">=$2 AND "createdAt"<$3`, [praxisId, rangeStart, rangeEnd]),
      query(req, `SELECT q.id, q."userInfoId", q."questionnaireId", q."answeredAt", q."createdAt"
                    FROM app_user_questionnaire q
                    JOIN app_user_info ui ON ui.id = q."userInfoId"
                    WHERE ui."praxisId"=$1 AND q."answeredAt">=$2 AND q."answeredAt"<$3`, [praxisId, rangeStart, rangeEnd]),
      query(req, `SELECT id, reason, "createdAt" FROM app_user_deletion_feedback WHERE "createdAt">=$1 AND "createdAt"<$2`, [rangeStart, rangeEnd]),
    ]);

    // Derived counts from the in-range appointment lists (matches the Dart
    // calculator's getters so numbers always agree with the lists we return).
    const appointmentsBookedFromApp    = appAppointmentsInRange.length;
    const appointmentsBookedFromWeb    = webAppointmentsInRange.filter(a => a.isBookedFromPraxis !== true).length;
    const appointmentsBookedFromPraxis = webAppointmentsInRange.filter(a => a.isBookedFromPraxis === true).length;
    const appointmentsBookedFromPraxisWithoutEmail = webAppointmentsInRange.filter(a => a.isBookedFromPraxis === true && a.hasEmail !== true).length;
    // praxisWithoutEmail is a SUBSET of praxis (same rows, narrower filter) —
    // do not add it to the total or it double-counts.
    const totalAppointments = appointmentsBookedFromApp + appointmentsBookedFromWeb + appointmentsBookedFromPraxis;

    const newVerifiedRegistrations = newRegistrations.filter(u => u.isVerified === true).length;
    const familyMemberAppointments = appAppointmentsInRange.filter(a => a.familyMemberId != null).length;

    const documentRequestFromApp = documentRequestsInRange.filter(d => d.isFromWeb === false).length;
    const documentRequestFromWeb = documentRequestsInRange.filter(d => d.isFromWeb === true).length;
    const documentRequestUnknown = documentRequestsInRange.filter(d => d.isFromWeb === null).length;
    const totalDocumentRequests  = documentRequestFromApp + documentRequestFromWeb + documentRequestUnknown;

    const totalCancellations = cancellationReasons.length;
    const cancellationRate = totalAppointments > 0 ? (totalCancellations / totalAppointments) * 100 : 0;
    const verificationRate = newRegistrations.length > 0 ? (newVerifiedRegistrations / newRegistrations.length) * 100 : 0;
    const familyMemberBookingRate = totalAppointments > 0 ? (familyMemberAppointments / totalAppointments) * 100 : 0;
    // guestNPS recovery: raw fhir_nps − :329 spurious writes (one per
    // praxis-booked guest_appointment). See `_emptyMonthlyKpi()` for the full
    // backend trace.
    const guestNPSRaw                          = guestNPSSent;
    const guestNPSRawWithoutEmail              = guestNPSRequestWithoutEmail;
    const guestNPSCorrected                    = Math.max(0, guestNPSRaw - appointmentsBookedFromPraxis);
    const guestNPSRequestWithoutEmailCorrected = Math.max(0, guestNPSRawWithoutEmail - appointmentsBookedFromPraxisWithoutEmail);
    const totalNPSSent = npsEmailsSent + guestNPSCorrected;
    // NPS fires after appointments + document requests + open consultations
    // (see backend handlers). 30-day per-user dedup means <100% is expected.
    const totalNpsEligibleEvents = totalAppointments + totalDocumentRequests + openConsultations.length;
    const npsCoveragePercentage = totalNpsEligibleEvents > 0 ? (totalNPSSent / totalNpsEligibleEvents) * 100 : 0;
    // pg returns bigint columns as strings to preserve precision — coerce
    // before summing or you get string concatenation ("262" + "188" = "262188").
    const pmsDowntimeSeconds = pmsDowntimes.reduce((s, d) => s + Number(d.totalDownTimeInSeconds || 0), 0);
    const pmsDowntimeMinutes = pmsDowntimeSeconds / 60;
    // praxisWithoutEmail is a SUBSET of praxis — do not add to total.
    const totalAppointmentsTookPlace = appointmentsTookPlaceFromApp + appointmentsTookPlaceFromWeb + appointmentsTookPlaceFromPraxis;

    // Daily time-series — one bucket per calendar day in [start, end).
    const dateKey = d => {
      const x = new Date(d);
      const pad = n => String(n).padStart(2, '0');
      return `${x.getFullYear()}-${pad(x.getMonth()+1)}-${pad(x.getDate())}`;
    };
    const dailyBuckets = [];
    for (let cursor = new Date(start.getFullYear(), start.getMonth(), start.getDate());
         cursor < end;
         cursor.setDate(cursor.getDate() + 1)) {
      dailyBuckets.push(dateKey(cursor));
    }
    const initCounts = () => Object.fromEntries(dailyBuckets.map(k => [k, 0]));
    const c = {
      app: initCounts(), web: initCounts(), praxis: initCounts(),
      reg: initCounts(), ver: initCounts(),
      docApp: initCounts(), docWeb: initCounts(),
      oc: initCounts(), cancel: initCounts(), q: initCounts(),
    };
    for (const a of appAppointmentsInRange) c.app[dateKey(a.createdAt)]++;
    for (const a of webAppointmentsInRange) {
      const k = dateKey(a.createdAt);
      if (a.isBookedFromPraxis === true) c.praxis[k]++; else c.web[k]++;
    }
    for (const u of newRegistrations) {
      const k = dateKey(u.createdAt);
      c.reg[k]++;
      if (u.isVerified === true) c.ver[k]++;
    }
    for (const d of documentRequestsInRange) {
      const k = dateKey(d.createdAt);
      if (d.isFromWeb === true) c.docWeb[k]++;
      else if (d.isFromWeb === false) c.docApp[k]++;
    }
    for (const oc of openConsultations) c.oc[dateKey(oc.createdAt)]++;
    for (const x of cancellationReasons) c.cancel[dateKey(x.createdAt)]++;
    for (const q of questionnairesAnswered) c.q[dateKey(q.answeredAt)]++;

    const dailyTimeSeries = dailyBuckets.map(k => ({
      date: k,
      appointmentsApp:         c.app[k],
      appointmentsWeb:         c.web[k],
      appointmentsPraxis:      c.praxis[k],
      newRegistrations:        c.reg[k],
      verifiedRegistrations:   c.ver[k],
      documentRequestsApp:     c.docApp[k],
      documentRequestsWeb:     c.docWeb[k],
      openConsultations:       c.oc[k],
      cancellations:           c.cancel[k],
      questionnairesCompleted: c.q[k],
    }));

    // Top-10 category breakdowns.
    const topCategories = (counts) =>
      Object.entries(counts).sort((a,b) => b[1] - a[1]).slice(0, 10)
        .map(([category, count]) => ({ category, count }));

    const apptCatCounts = {};
    for (const a of appAppointmentsInRange) apptCatCounts[a.category||'—'] = (apptCatCounts[a.category||'—'] || 0) + 1;
    for (const a of webAppointmentsInRange) apptCatCounts[a.category||'—'] = (apptCatCounts[a.category||'—'] || 0) + 1;
    const appointmentCategories = topCategories(apptCatCounts);

    // cancellationReasons.reason is a JSON array in Postgres (json type), pg
    // driver returns it as an actual array.
    const cancelReasonCounts = {};
    for (const row of cancellationReasons) {
      const list = Array.isArray(row.reason) ? row.reason : [];
      for (const r of list) cancelReasonCounts[String(r)] = (cancelReasonCounts[String(r)] || 0) + 1;
    }
    const cancellationReasonsTop = topCategories(cancelReasonCounts);

    const deletionReasonCounts = {};
    for (const row of deletionFeedback) {
      const list = Array.isArray(row.reason) ? row.reason : [];
      for (const r of list) deletionReasonCounts[String(r)] = (deletionReasonCounts[String(r)] || 0) + 1;
    }
    const deletionReasons = topCategories(deletionReasonCounts);

    res.json({
      praxisId,
      rangeStart: start.toISOString(),
      rangeEnd:   end.toISOString(),
      // Counters
      npsEmailsSent,
      guestNPS:                    guestNPSCorrected,
      guestNPSRequestWithoutEmail: guestNPSRequestWithoutEmailCorrected,
      guestNPSRaw, guestNPSRawWithoutEmail,
      totalNPSSent,
      totalPatients, totalVerifiedPatients,
      appointmentsBookedFromApp, appointmentsBookedFromWeb,
      appointmentsBookedFromPraxis, appointmentsBookedFromPraxisWithoutEmail,
      totalAppointments,
      appointmentsTookPlaceFromApp, appointmentsTookPlaceFromWeb,
      appointmentsTookPlaceFromPraxis, appointmentsTookPlaceFromPraxisWithoutEmail,
      totalAppointmentsTookPlace,
      totalNewRegistrations: newRegistrations.length,
      totalNewVerifiedRegistrations: newVerifiedRegistrations,
      verificationRate,
      totalDocumentRequests, documentRequestFromApp, documentRequestFromWeb, documentRequestUnknown,
      totalOpenConsultations: openConsultations.length,
      totalCancellations, cancellationRate,
      totalQuestionnairesCompleted: questionnairesAnswered.length,
      familyMemberAppointments, familyMemberBookingRate,
      npsCoveragePercentage,
      pmsDownTimeInSeconds: pmsDowntimeSeconds, pmsDownTimeInMinutes: pmsDowntimeMinutes,
      // Charts
      dailyTimeSeries,
      appointmentCategories,
      cancellationReasons: cancellationReasonsTop,
      deletionReasons,
      // Raw lists for debug-style tables
      pmsDowntimes,
      appAppointmentsInRange,
      webAppointmentsInRange,
      openConsultations,
      newRegistrations,
      documentRequestsInRange,
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Status enum values that mean "did NOT take place" — used to filter
// "Took Place" queries so cancellations / no-shows / fake admin rows don't
// inflate the count. Indices match CoreAppUserAppointmentStatus from the
// Serverpod yaml (mirrored in public/index.html APT_STATUS):
//   5 = cancelled, 6 = noshow, 7 = enteredInError.
// Other statuses (booked / arrived / fulfilled / rescheduled / checkedIn /
// waitlist / proposed / pending) are kept — for past startTimes they mean
// "happened or was intended to happen at this time".
const DID_NOT_TAKE_PLACE_STATUSES = '(5, 6, 7)';
const TOOK_PLACE_STATUS_FILTER    = `AND status NOT IN ${DID_NOT_TAKE_PLACE_STATUSES}`;

// ─── Routes: Historical Analytics Export ─────────────────────────────────────
// One-time bulk export of aggregated analytics from the earliest data in the
// DB through a chosen end date. Writes XLSX + JSON + a self-contained HTML
// report. Walks praxes one-at-a-time to keep DB load identical to a single
// normal user request at any moment.
//
//   GET /api/analytics/export-historical?endDate=YYYY-MM-DD
//
// Returns { ok, outDir, files, praxesProcessed, monthsCovered, dataStart, dataEnd }.

function _padMonth(d) {
  return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}`;
}

function _enumerateMonths(start, end) {
  const out = [];
  const cur = new Date(start.getFullYear(), start.getMonth(), 1);
  while (cur <= end) {
    out.push(_padMonth(cur));
    cur.setMonth(cur.getMonth() + 1);
  }
  return out;
}

// Per-praxis monthly KPI shape. Excludes truly-global metrics (PMS downtime,
// deletion feedback) — those have no praxisId path and live in their own
// global section in the report.
//
// guestNPS recovery: fhir_nps has TWO write sites in the backend
// (lib/src/endpoints/fhir/helper/fhir_appointment_handler.dart):
//   1. handleNewAppointment :329 — fires on the unregistered-patient booking
//      branch (booked / rescheduled / cancelled). NO NPS email is sent here;
//      the row is "spurious" w.r.t. actual NPS delivery. Always paired with
//      a guest_appointment insert :320 carrying isBookedFromPraxis=true.
//   2. handleUnknownBooking :422 — fires only when status=fulfilled, paired
//      with scheduleGuestNPS(...) which actually triggers the Brevo send.
//      Writes NO guest_appointment row.
// So "real" guest NPS attempts ≈ fhir_nps − guest_appointment(isBookedFromPraxis=true).
// Both raw and corrected counts are kept here so the report can show the gap.
function _emptyMonthlyKpi() {
  return {
    appointmentsBookedFromApp: 0,
    appointmentsBookedFromWeb: 0,
    appointmentsBookedFromPraxis: 0,
    appointmentsBookedFromPraxisWithoutEmail: 0,
    totalAppointments: 0,
    appointmentsTookPlaceFromApp: 0,
    appointmentsTookPlaceFromWeb: 0,
    appointmentsTookPlaceFromPraxis: 0,
    appointmentsTookPlaceFromPraxisWithoutEmail: 0,
    totalAppointmentsTookPlace: 0,
    npsEmailsSent: 0,
    guestNPS: 0,                          // corrected: real :422 attempts
    guestNPSRequestWithoutEmail: 0,       // corrected: real :422 attempts w/o email
    guestNPSRaw: 0,                       // raw fhir_nps count (incl. :329 spurious)
    guestNPSRawWithoutEmail: 0,           // raw fhir_nps where hasEmail=false
    guestNPSSpurious: 0,                  // :329 writes (= praxis-booked guest_appointments)
    totalNPSSent: 0,
    documentRequestFromApp: 0,
    documentRequestFromWeb: 0,
    documentRequestUnknown: 0,
    totalDocumentRequests: 0,
    openConsultations: 0,
    newRegistrations: 0,
    newVerifiedRegistrations: 0,
    cancellations: 0,
    questionnairesCompleted: 0,
  };
}

async function _fetchPraxisAggregates(req, praxisId, rangeStart, rangeEnd) {
  // One pass per praxis: pull only the columns we need for aggregation. No
  // patient PII (firstName/lastName/email/userId) is read — we only need
  // category/flags/timestamps to compute counts.
  const [
    npsSent,
    fhirNps,
    appAppts,
    webAppts,
    docReqs,
    openCons,
    cancellations,
    registrations,
    appAppointmentsTookPlace,
    guestAppointmentsTookPlace,
    questionnaires,
    totalsRow,
  ] = await Promise.all([
    query(req, `SELECT "createdAt"                             FROM app_user_nps_sent              WHERE "praxisId"=$1 AND "createdAt" BETWEEN $2 AND $3`, [praxisId, rangeStart, rangeEnd]),
    query(req, `SELECT "createdAt", "hasEmail"                 FROM fhir_nps                       WHERE "praxisId"=$1 AND "createdAt" BETWEEN $2 AND $3`, [praxisId, rangeStart, rangeEnd]),
    query(req, `SELECT "createdAt", "startTime", category, "familyMemberId"
                                                                FROM app_user_appointment           WHERE "praxisId"=$1 AND "createdAt" BETWEEN $2 AND $3`, [praxisId, rangeStart, rangeEnd]),
    query(req, `SELECT "createdAt", "startTime", category, "isBookedFromPraxis", "hasEmail"
                                                                FROM guest_appointment              WHERE "praxisId"=$1 AND "createdAt" BETWEEN $2 AND $3`, [praxisId, rangeStart, rangeEnd]),
    query(req, `SELECT "createdAt", "isFromWeb", category       FROM app_user_document_request      WHERE "praxisId"=$1 AND "createdAt" BETWEEN $2 AND $3`, [praxisId, rangeStart, rangeEnd]),
    query(req, `SELECT "createdAt", category                    FROM app_user_open_consultation     WHERE "praxisId"=$1 AND "createdAt" BETWEEN $2 AND $3`, [praxisId, rangeStart, rangeEnd]),
    // Cancellation attribution: only count when the cancelling user actually
    // has at least one appointment at THIS praxis. cancellation_reason has no
    // praxisId/appointmentId in schema, so pure user→praxis JOIN over-attributes
    // (users registered at A who book+cancel at B end up showing under A).
    // The EXISTS filter excludes those phantom cancellations; they're counted
    // globally as "Unattributed Cancellations".
    query(req, `SELECT c."createdAt", c.reason
                  FROM app_user_appointment_cancellation_reason c
                  JOIN app_user_info ui ON ui.id = c."userId"
                  WHERE ui."praxisId"=$1 AND c."createdAt" BETWEEN $2 AND $3
                    AND EXISTS (
                      SELECT 1 FROM app_user_appointment a
                      WHERE a."userId" = c."userId" AND a."praxisId" = $1
                    )`, [praxisId, rangeStart, rangeEnd]),
    query(req, `SELECT "createdAt", "isVerified"                FROM app_user_info                  WHERE "praxisId"=$1 AND "createdAt" BETWEEN $2 AND $3`, [praxisId, rangeStart, rangeEnd]),
    query(req, `SELECT "startTime"                              FROM app_user_appointment           WHERE "praxisId"=$1 AND "startTime" IS NOT NULL AND "startTime" BETWEEN $2 AND $3 ${TOOK_PLACE_STATUS_FILTER}`, [praxisId, rangeStart.toISOString(), rangeEnd.toISOString()]),
    query(req, `SELECT "startTime", "isBookedFromPraxis", "hasEmail"
                                                                FROM guest_appointment              WHERE "praxisId"=$1 AND "startTime" IS NOT NULL AND "startTime" BETWEEN $2 AND $3 ${TOOK_PLACE_STATUS_FILTER}`, [praxisId, rangeStart.toISOString(), rangeEnd.toISOString()]),
    query(req, `SELECT q."answeredAt"
                  FROM app_user_questionnaire q
                  JOIN app_user_info ui ON ui.id = q."userInfoId"
                  WHERE ui."praxisId"=$1 AND q."answeredAt" BETWEEN $2 AND $3`, [praxisId, rangeStart, rangeEnd]),
    query(req, `SELECT
                  (SELECT COUNT(*)::int FROM app_user_info WHERE "praxisId"=$1)                          AS total_patients,
                  (SELECT COUNT(*)::int FROM app_user_info WHERE "praxisId"=$1 AND "isVerified"=true)    AS total_verified`, [praxisId]),
  ]);

  const monthly = {};
  const ensureMonth = (key) => (monthly[key] ||= _emptyMonthlyKpi());
  const monthKey = (d) => _padMonth(new Date(d));

  // totalNPSSent is recomputed at the end of this function from
  // (npsEmailsSent + corrected guestNPS), so no in-loop increment here.
  for (const r of npsSent) {
    const m = ensureMonth(monthKey(r.createdAt));
    m.npsEmailsSent++;
  }
  // Raw fhir_nps counts (both write sites combined). Corrected to actual NPS
  // attempts further down by subtracting the :329 spurious writes (= count of
  // guest_appointment rows with isBookedFromPraxis=true in the same month).
  for (const r of fhirNps) {
    const m = ensureMonth(monthKey(r.createdAt));
    m.guestNPSRaw++;
    if (r.hasEmail === false) m.guestNPSRawWithoutEmail++;
  }
  const apptCategories = {};
  for (const r of appAppts) {
    const m = ensureMonth(monthKey(r.createdAt));
    m.appointmentsBookedFromApp++;
    m.totalAppointments++;
    apptCategories[r.category || '—'] = (apptCategories[r.category || '—'] || 0) + 1;
  }
  // Praxis-booked guest_appointments are exactly the rows that triggered the
  // :329 spurious fhir_nps write — track separately for the guestNPS recovery.
  const praxisBookedNoEmailByMonth = {};
  for (const r of webAppts) {
    const mk = monthKey(r.createdAt);
    const m = ensureMonth(mk);
    if (r.isBookedFromPraxis === true) {
      m.appointmentsBookedFromPraxis++;
      m.guestNPSSpurious++;
      if (r.hasEmail !== true) {
        m.appointmentsBookedFromPraxisWithoutEmail++;
        praxisBookedNoEmailByMonth[mk] = (praxisBookedNoEmailByMonth[mk] || 0) + 1;
      }
    } else {
      m.appointmentsBookedFromWeb++;
    }
    m.totalAppointments++;
    apptCategories[r.category || '—'] = (apptCategories[r.category || '—'] || 0) + 1;
  }
  // Apply the recovery formula: corrected guestNPS = raw − spurious.
  // The :329 site sets fhir_nps.hasEmail to the same value as the paired
  // guest_appointment.hasEmail (both come from userInfo.email.isNotEmpty in
  // handleNewAppointment), so we subtract the matching no-email subset too.
  // Clamp at 0 in case of any cross-month boundary mismatch.
  for (const [mk, m] of Object.entries(monthly)) {
    m.guestNPS                   = Math.max(0, m.guestNPSRaw - m.guestNPSSpurious);
    m.guestNPSRequestWithoutEmail = Math.max(0, m.guestNPSRawWithoutEmail - (praxisBookedNoEmailByMonth[mk] || 0));
    m.totalNPSSent               = m.npsEmailsSent + m.guestNPS;
  }
  for (const r of appAppointmentsTookPlace) {
    const m = ensureMonth(monthKey(r.startTime));
    m.appointmentsTookPlaceFromApp++;
    m.totalAppointmentsTookPlace++;
  }
  for (const r of guestAppointmentsTookPlace) {
    const m = ensureMonth(monthKey(r.startTime));
    if (r.isBookedFromPraxis === true) {
      m.appointmentsTookPlaceFromPraxis++;
      if (r.hasEmail !== true) m.appointmentsTookPlaceFromPraxisWithoutEmail++;
    } else {
      m.appointmentsTookPlaceFromWeb++;
    }
    m.totalAppointmentsTookPlace++;
  }
  for (const r of docReqs) {
    const m = ensureMonth(monthKey(r.createdAt));
    if (r.isFromWeb === true) m.documentRequestFromWeb++;
    else if (r.isFromWeb === false) m.documentRequestFromApp++;
    else m.documentRequestUnknown++;
    m.totalDocumentRequests++;
  }
  for (const r of openCons) {
    const m = ensureMonth(monthKey(r.createdAt));
    m.openConsultations++;
  }
  // app_user_appointment_cancellation_reason.reason is a JSON array — pg
  // returns it as a real JS array. Iterate and count each entry.
  const cancellationReasons = {};
  for (const r of cancellations) {
    const m = ensureMonth(monthKey(r.createdAt));
    m.cancellations++;
    const list = Array.isArray(r.reason) ? r.reason : (r.reason != null ? [r.reason] : ['—']);
    for (const reason of list) {
      const k = String(reason).slice(0, 120);
      cancellationReasons[k] = (cancellationReasons[k] || 0) + 1;
    }
  }
  for (const r of registrations) {
    const m = ensureMonth(monthKey(r.createdAt));
    m.newRegistrations++;
    if (r.isVerified === true) m.newVerifiedRegistrations++;
  }
  for (const r of questionnaires) {
    const m = ensureMonth(monthKey(r.answeredAt));
    m.questionnairesCompleted++;
  }
  // Deletion feedback has no praxisId path in schema — handled in the
  // global section of the report, not bucketed per-praxis.

  const totals = _emptyMonthlyKpi();
  for (const m of Object.values(monthly)) {
    for (const k of Object.keys(totals)) totals[k] += (m[k] || 0);
  }
  totals.cancellationRate            = totals.totalAppointments > 0 ? (totals.cancellations / totals.totalAppointments) * 100 : 0;
  totals.verificationRate            = totals.newRegistrations > 0 ? (totals.newVerifiedRegistrations / totals.newRegistrations) * 100 : 0;
  // NPS is triggered after appointments, document requests, and open
  // consultations (see backend booking + document_request + open_consultation
  // handlers). Coverage denominator must reflect all three. Note: backend
  // dedupes NPS to once per 30 days per user, so <100% is normal even if
  // every event would otherwise trigger a send.
  totals.totalNpsEligibleEvents      = totals.totalAppointments + totals.totalDocumentRequests + totals.openConsultations;
  totals.npsCoveragePercentage       = totals.totalNpsEligibleEvents > 0 ? (totals.totalNPSSent / totals.totalNpsEligibleEvents) * 100 : 0;
  totals.totalPatients               = totalsRow[0] ? parseInt(totalsRow[0].total_patients, 10) || 0 : 0;
  totals.totalVerifiedPatients       = totalsRow[0] ? parseInt(totalsRow[0].total_verified, 10) || 0 : 0;

  // Diagnostic: raw row counts from each query + arithmetic invariant check.
  // Lets us confirm the export numbers match direct DB reality and surfaces
  // any code-side bug (e.g. accidental double-increment) loudly.
  const sanity = {
    rowCounts: {
      npsSent: npsSent.length,
      fhirNps: fhirNps.length,
      appAppts: appAppts.length,
      webAppts: webAppts.length,
      docReqs: docReqs.length,
      openCons: openCons.length,
      cancellations: cancellations.length,
      registrations: registrations.length,
      appAppointmentsTookPlace: appAppointmentsTookPlace.length,
      guestAppointmentsTookPlace: guestAppointmentsTookPlace.length,
      questionnaires: questionnaires.length,
    },
    invariants: {
      totalAppointmentsMatchesSum: totals.totalAppointments === (totals.appointmentsBookedFromApp + totals.appointmentsBookedFromWeb + totals.appointmentsBookedFromPraxis),
      totalAppointmentsTookPlaceMatchesSum: totals.totalAppointmentsTookPlace === (totals.appointmentsTookPlaceFromApp + totals.appointmentsTookPlaceFromWeb + totals.appointmentsTookPlaceFromPraxis),
      praxisNoEmailLessOrEqualPraxis: totals.appointmentsBookedFromPraxisWithoutEmail <= totals.appointmentsBookedFromPraxis,
      // guestNPS correction: spurious writes shouldn't exceed raw fhir_nps
      // count or the count of praxis-booked guest_appointments (both sides
      // of the recovery identity must hold).
      guestNPSSpuriousMatchesPraxisBooked: totals.guestNPSSpurious === totals.appointmentsBookedFromPraxis,
      guestNPSRawCoversCorrection: totals.guestNPSRaw >= totals.guestNPSSpurious,
    },
    // Headline counts for the recovery formula. Show both raw and corrected
    // so we can quantify the gap when explaining to stakeholders.
    guestNPSRecovery: {
      rawFhirNps:               totals.guestNPSRaw,
      spuriousFromPraxisBooked: totals.guestNPSSpurious,
      correctedAttempts:        totals.guestNPS,
      rawNoEmail:               totals.guestNPSRawWithoutEmail,
      correctedNoEmail:         totals.guestNPSRequestWithoutEmail,
    },
  };
  if (!sanity.invariants.totalAppointmentsMatchesSum || !sanity.invariants.totalAppointmentsTookPlaceMatchesSum) {
    console.warn(`[export] sanity FAIL for ${praxisId}:`, JSON.stringify({ rowCounts: sanity.rowCounts, totals: { app: totals.appointmentsBookedFromApp, web: totals.appointmentsBookedFromWeb, praxis: totals.appointmentsBookedFromPraxis, noEmail: totals.appointmentsBookedFromPraxisWithoutEmail, total: totals.totalAppointments } }));
  } else {
    console.log(`[export] ${praxisId}: app=${totals.appointmentsBookedFromApp} web=${totals.appointmentsBookedFromWeb} praxis=${totals.appointmentsBookedFromPraxis} (noEmail=${totals.appointmentsBookedFromPraxisWithoutEmail}) total=${totals.totalAppointments}`);
  }

  const top10 = (counts) => Object.entries(counts).sort((a, b) => b[1] - a[1]).slice(0, 10).map(([k, v]) => ({ category: k, count: v }));

  return {
    monthly,
    totals,
    appointmentCategories: top10(apptCategories),
    cancellationReasons:   top10(cancellationReasons),
    _debug: sanity,
  };
}

async function _gatherCockpitOverview(req) {
  const { year: cy, week: cw } = currentIsoYearWeek();
  const cwKey = cy * 53 + cw;
  const [praxes, consHours, workHours, overrides, versions, pdes, matrix] = await Promise.all([
    query(req, `SELECT id, "lcId", "bundeslandCode" FROM praxis_config`),
    query(req, `SELECT "praxisId", COUNT(*)::int AS rows, COALESCE(SUM(EXTRACT(EPOCH FROM ("end"::time - "start"::time)) / 60), 0)::int AS minutes FROM cockpit_consultation_hours GROUP BY "praxisId"`),
    query(req, `SELECT "praxisId", COUNT(*)::int AS rows, COALESCE(SUM(EXTRACT(EPOCH FROM ("end"::time - "start"::time)) / 60), 0)::int AS minutes, COALESCE(SUM("breakMin"), 0)::int AS break_minutes FROM cockpit_work_hours GROUP BY "praxisId"`),
    query(req, `SELECT "praxisId", COUNT(*)::int AS c FROM cockpit_week_override GROUP BY "praxisId"`),
    query(req, `SELECT "praxisId", COUNT(*)::int AS c FROM cockpit_standard_week_version GROUP BY "praxisId"`),
    query(req, `SELECT "praxisId", COUNT(*)::int AS c FROM cockpit_person_duration_exception WHERE ("validFromIsoYear" * 53 + "validFromIsoWeek") <= $1 AND ("validUntilIsoYear" IS NULL OR ("validUntilIsoYear" * 53 + "validUntilIsoWeek") >= $1) GROUP BY "praxisId"`, [cwKey]),
    query(req, `SELECT "praxisId", COUNT(*)::int AS c FROM cockpit_appointment_type_matrix GROUP BY "praxisId"`),
  ]);
  const byId = (rows) => Object.fromEntries(rows.map(r => [r.praxisId, r]));
  const c = byId(consHours), w = byId(workHours), o = byId(overrides), v = byId(versions), p = byId(pdes), m = byId(matrix);
  return praxes.map(pr => ({
    lcId: pr.lcId,
    bundesland: pr.bundeslandCode != null ? (BUNDESLAND_CODES[pr.bundeslandCode] || null) : null,
    consultationRows:    c[pr.id]?.rows    || 0,
    consultationMinutes: c[pr.id]?.minutes || 0,
    workRows:            w[pr.id]?.rows    || 0,
    workMinutes:         w[pr.id]?.minutes || 0,
    workBreakMinutes:    w[pr.id]?.break_minutes || 0,
    overrideCount:       o[pr.id]?.c || 0,
    versionCount:        v[pr.id]?.c || 0,
    activePdeCount:      p[pr.id]?.c || 0,
    matrixEntries:       m[pr.id]?.c || 0,
    hasBaseline:         (c[pr.id]?.rows || 0) > 0 || (w[pr.id]?.rows || 0) > 0,
  }));
}

function _xlsxFromPayload(payload) {
  const xlsx = require('xlsx');
  const wb = xlsx.utils.book_new();

  const indexRows = payload.praxes.map(p => ({
    lcId: p.lcId, name: p.name, shortName: p.shortName, bundesland: p.bundesland,
  }));
  xlsx.utils.book_append_sheet(wb, xlsx.utils.json_to_sheet(indexRows), 'Praxes');

  const totalRows = payload.praxes.map(p => ({
    lcId: p.lcId, name: p.name, ...p.totals,
  }));
  xlsx.utils.book_append_sheet(wb, xlsx.utils.json_to_sheet(totalRows), 'Totals');

  const monthlyRows = [];
  for (const p of payload.praxes) {
    for (const month of payload.monthsCovered) {
      const m = p.monthly[month] || _emptyMonthlyKpi();
      monthlyRows.push({ lcId: p.lcId, name: p.name, month, ...m });
    }
  }
  xlsx.utils.book_append_sheet(wb, xlsx.utils.json_to_sheet(monthlyRows), 'Monthly');

  const catRows = [];
  for (const p of payload.praxes) {
    for (const c of p.appointmentCategories) catRows.push({ lcId: p.lcId, name: p.name, category: c.category, count: c.count });
  }
  xlsx.utils.book_append_sheet(wb, xlsx.utils.json_to_sheet(catRows.length ? catRows : [{ lcId: '', name: '', category: '', count: 0 }]), 'AppointmentCategories');

  const cancelRows = [];
  for (const p of payload.praxes) {
    for (const c of p.cancellationReasons) cancelRows.push({ lcId: p.lcId, name: p.name, reason: c.category, count: c.count });
  }
  xlsx.utils.book_append_sheet(wb, xlsx.utils.json_to_sheet(cancelRows.length ? cancelRows : [{ lcId: '', name: '', reason: '', count: 0 }]), 'CancellationReasons');

  xlsx.utils.book_append_sheet(wb, xlsx.utils.json_to_sheet(payload.pmsDowntimes.length ? payload.pmsDowntimes : [{ id: '', totalDownTimeInSeconds: 0, createdAt: '' }]), 'PMSDowntimes');

  xlsx.utils.book_append_sheet(wb, xlsx.utils.json_to_sheet(payload.cockpit.length ? payload.cockpit : [{ lcId: '' }]), 'CockpitSummary');

  xlsx.utils.book_append_sheet(wb, xlsx.utils.json_to_sheet(payload.deletionReasons.length ? payload.deletionReasons : [{ reason: '', count: 0 }]), 'DeletionReasons');

  const unattrRows = (payload.unattributedCancellations?.byUserRegisteredPraxis?.length
    ? payload.unattributedCancellations.byUserRegisteredPraxis
    : [{ lcId: '', count: 0 }]);
  xlsx.utils.book_append_sheet(wb, xlsx.utils.json_to_sheet(unattrRows), 'UnattributedCancellations');

  return xlsx.write(wb, { type: 'buffer', bookType: 'xlsx' });
}

// Compute [start, end] ISO timestamps for a "YYYY-MM" bucket key. The export
// buckets rows in JS using local-time getFullYear/getMonth — we use UTC here
// for the SQL filter; for end-of-month boundaries the difference is rare and
// the validator output will be within 1 row of the report.
function _monthRange(monthStr) {
  const [year, month] = monthStr.split('-').map(Number);
  const start = `${year}-${String(month).padStart(2, '0')}-01T00:00:00.000Z`;
  const nextY = month === 12 ? year + 1 : year;
  const nextM = month === 12 ? 1 : month + 1;
  const nextStart = new Date(Date.UTC(nextY, nextM - 1, 1));
  const endInclusive = new Date(nextStart.getTime() - 1).toISOString();
  return { start, end: endInclusive };
}

// SQL for a single monthly-table cell. Each column maps to one COUNT query.
// (The existing _validationSqlFor builders return multi-column breakdowns;
// for cells, single-COUNT is cleaner.)
function _monthCellSql(column, lcId, start, end) {
  const r = (s) => s.trim();
  const px = `"praxisId" = '${lcId}'`;
  const win = `BETWEEN '${start}' AND '${end}'`;
  switch (column) {
    case 'app':
      return r(`SELECT COUNT(*) FROM app_user_appointment WHERE ${px} AND "createdAt" ${win};`);
    case 'web':
      return r(`SELECT COUNT(*) FROM guest_appointment WHERE ${px} AND "createdAt" ${win} AND ("isBookedFromPraxis" IS NOT TRUE);`);
    case 'praxis':
      return r(`SELECT COUNT(*) FROM guest_appointment WHERE ${px} AND "createdAt" ${win} AND "isBookedFromPraxis" = true;`);
    case 'praxisNoEmail':
      return r(`SELECT COUNT(*) FROM guest_appointment WHERE ${px} AND "createdAt" ${win} AND "isBookedFromPraxis" = true AND "hasEmail" = false;`);
    case 'totalBooked':
      return r(`-- app + web + praxis (praxisNoEmail is a subset of praxis):
WITH counts AS (
  SELECT
    (SELECT COUNT(*)::int FROM app_user_appointment WHERE ${px} AND "createdAt" ${win}) AS app,
    (SELECT COUNT(*)::int FROM guest_appointment WHERE ${px} AND "createdAt" ${win} AND ("isBookedFromPraxis" IS NOT TRUE)) AS web,
    (SELECT COUNT(*)::int FROM guest_appointment WHERE ${px} AND "createdAt" ${win} AND "isBookedFromPraxis" = true) AS praxis
)
SELECT app, web, praxis, (app + web + praxis) AS total FROM counts;`);
    case 'tookPlaceApp':
      return r(`-- status NOT IN (5,6,7) excludes cancelled / noshow / enteredInError.
SELECT COUNT(*) FROM app_user_appointment WHERE ${px} AND "startTime" IS NOT NULL AND "startTime" ${win} AND status NOT IN (5, 6, 7);`);
    case 'tookPlaceWeb':
      return r(`-- status NOT IN (5,6,7) excludes cancelled / noshow / enteredInError.
SELECT COUNT(*) FROM guest_appointment WHERE ${px} AND "startTime" IS NOT NULL AND "startTime" ${win} AND ("isBookedFromPraxis" IS NOT TRUE) AND status NOT IN (5, 6, 7);`);
    case 'tookPlacePraxis':
      return r(`-- status NOT IN (5,6,7) excludes cancelled / noshow / enteredInError.
SELECT COUNT(*) FROM guest_appointment WHERE ${px} AND "startTime" IS NOT NULL AND "startTime" ${win} AND "isBookedFromPraxis" = true AND status NOT IN (5, 6, 7);`);
    case 'tookPlace':
      return r(`-- startTime within month, status NOT IN (5,6,7) excludes
-- cancelled / noshow / enteredInError. Combines app + web + praxis:
WITH counts AS (
  SELECT
    (SELECT COUNT(*)::int FROM app_user_appointment WHERE ${px} AND "startTime" IS NOT NULL AND "startTime" ${win} AND status NOT IN (5, 6, 7)) AS app,
    (SELECT COUNT(*)::int FROM guest_appointment WHERE ${px} AND "startTime" IS NOT NULL AND "startTime" ${win} AND ("isBookedFromPraxis" IS NOT TRUE) AND status NOT IN (5, 6, 7)) AS web,
    (SELECT COUNT(*)::int FROM guest_appointment WHERE ${px} AND "startTime" IS NOT NULL AND "startTime" ${win} AND "isBookedFromPraxis" = true AND status NOT IN (5, 6, 7)) AS praxis
)
SELECT app, web, praxis, (app + web + praxis) AS total FROM counts;`);
    case 'docReqApp':
      return r(`SELECT COUNT(*) FROM app_user_document_request WHERE ${px} AND "createdAt" ${win} AND "isFromWeb" = false;`);
    case 'docReqWeb':
      return r(`SELECT COUNT(*) FROM app_user_document_request WHERE ${px} AND "createdAt" ${win} AND "isFromWeb" = true;`);
    case 'npsSent':
      return r(`SELECT COUNT(*) FROM app_user_nps_sent WHERE ${px} AND "createdAt" ${win};`);
    case 'guestNps':
      // Recovery: raw fhir_nps minus :329 spurious writes (one per
      // praxis-booked guest_appointment in the same window).
      return r(`SELECT
  (SELECT COUNT(*)::int FROM fhir_nps WHERE ${px} AND "createdAt" ${win})
  - (SELECT COUNT(*)::int FROM guest_appointment WHERE ${px} AND "createdAt" ${win} AND "isBookedFromPraxis" = true)
  AS guest_nps_corrected;`);
    case 'newReg':
      return r(`SELECT COUNT(*) FROM app_user_info WHERE ${px} AND "createdAt" ${win};`);
    case 'verifiedReg':
      return r(`-- isVerified is the user's CURRENT state, not historical state at registration time.
SELECT COUNT(*) FROM app_user_info WHERE ${px} AND "createdAt" ${win} AND "isVerified" = true;`);
    case 'cancellations':
      return r(`-- EXISTS filter: only count cancellations from users who actually booked at this praxis.
SELECT COUNT(*)
FROM app_user_appointment_cancellation_reason c
JOIN app_user_info ui ON ui.id = c."userId"
WHERE ui."praxisId" = '${lcId}' AND c."createdAt" ${win}
  AND EXISTS (
    SELECT 1 FROM app_user_appointment a
    WHERE a."userId" = c."userId" AND a."praxisId" = '${lcId}'
  );`);
    case 'openCons':
      return r(`SELECT COUNT(*) FROM app_user_open_consultation WHERE ${px} AND "createdAt" ${win};`);
    case 'questionnaires':
      return r(`SELECT COUNT(*)
FROM app_user_questionnaire q
JOIN app_user_info ui ON ui.id = q."userInfoId"
WHERE ui."praxisId" = '${lcId}' AND q."answeredAt" ${win};`);
    default:
      return null;
  }
}

// Validation SQL builders. Each takes (lcId, startISO, endISO) and returns a
// standalone SQL statement matching the helper export's data-fetching logic.
// Used by the validator HTML's per-card copy buttons.
//
// When lcId is empty/null, builds the "all praxes" variant — same logic but
// scoped to "praxisId IS NOT NULL AND <> ''" (matches the export's praxes
// discovery filter, so totals should equal the report's top-summary cards).
function _validationSqlFor(metric, lcId, start, end) {
  const r = (s) => s.trim();
  const isAll = !lcId;
  // Direct praxisId-column tables: WHERE clause for praxis filter.
  // For all-praxes mode, scope to lcIds present in praxis_config — this matches
  // the report's targetPraxes set (the report excludes orphans whose praxisId
  // doesn't resolve to a known praxis_config row, so the SQL must too).
  const px      = isAll ? `"praxisId" IN (SELECT "lcId" FROM praxis_config WHERE "lcId" IS NOT NULL)`     : `"praxisId" = '${lcId}'`;
  const uiPx    = isAll ? `ui."praxisId" IN (SELECT "lcId" FROM praxis_config WHERE "lcId" IS NOT NULL)` : `ui."praxisId" = '${lcId}'`;
  const head    = isAll ? `-- Across ALL praxes — should match the report's top-summary card.\n-- Filter "praxisId IN (SELECT lcId FROM praxis_config)" excludes orphan rows\n-- whose praxisId doesn't match any known praxis (the report does the same).\n` : '';
  switch (metric) {
    case 'Total Patients':
      return r(`${head}SELECT COUNT(*) FROM app_user_info WHERE ${px};${isAll ? `\n\n-- Diagnostic: orphan users whose praxisId doesn't map to any praxis_config row.\n-- These are excluded from the report's totals. Expect a small/zero count.\n-- SELECT ui."praxisId", COUNT(*) AS user_count\n-- FROM app_user_info ui\n-- WHERE ui."praxisId" IS NOT NULL AND ui."praxisId" <> ''\n--   AND NOT EXISTS (SELECT 1 FROM praxis_config pc WHERE pc."lcId" = ui."praxisId")\n-- GROUP BY ui."praxisId"\n-- ORDER BY user_count DESC;` : ''}`);
    case 'Verified Patients':
      return r(`${head}SELECT COUNT(*) FROM app_user_info WHERE ${px} AND "isVerified" = true;`);
    case 'New Registrations':
      return r(`${head}SELECT COUNT(*) FROM app_user_info
WHERE ${px}
  AND "createdAt" BETWEEN '${start}' AND '${end}';`);
    case 'Verification Rate':
      return r(`${head}-- verification_rate_pct matches the report's KPI value.
SELECT
  COUNT(*) FILTER (WHERE "isVerified" = true) AS verified,
  COUNT(*) AS new_registrations,
  ROUND(100.0 * COUNT(*) FILTER (WHERE "isVerified" = true) / NULLIF(COUNT(*), 0), 1) AS verification_rate_pct
FROM app_user_info
WHERE ${px}
  AND "createdAt" BETWEEN '${start}' AND '${end}';`);
    case 'Total Appointments':
      return r(`${head}-- READ THIS BEFORE SUMMING:
--   app + web + praxis = total  (this is the KPI value)
--   "of_which_praxis_no_email" is a SUBSET of "praxis" — same rows, narrower
--   filter (praxis bookings where the patient had no email). Don't add it!
WITH counts AS (
  SELECT
    (SELECT COUNT(*)::int FROM app_user_appointment
       WHERE ${px} AND "createdAt" BETWEEN '${start}' AND '${end}') AS app,
    (SELECT COUNT(*)::int FROM guest_appointment
       WHERE ${px} AND "createdAt" BETWEEN '${start}' AND '${end}'
         AND ("isBookedFromPraxis" IS NOT TRUE)) AS web,
    (SELECT COUNT(*)::int FROM guest_appointment
       WHERE ${px} AND "createdAt" BETWEEN '${start}' AND '${end}'
         AND "isBookedFromPraxis" = true) AS praxis,
    (SELECT COUNT(*)::int FROM guest_appointment
       WHERE ${px} AND "createdAt" BETWEEN '${start}' AND '${end}'
         AND "isBookedFromPraxis" = true AND "hasEmail" = false) AS praxis_no_email
)
SELECT
  app,
  web,
  praxis,
  (app + web + praxis)                AS total,
  praxis_no_email                      AS of_which_praxis_no_email
FROM counts;`);
    case 'Took Place':
      return r(`${head}-- Total = app + web + praxis. startTime within window (column is text ISO).
-- status NOT IN (5, 6, 7) excludes cancelled / noshow / enteredInError
-- so cancelled rows in the past don't inflate this count. Other statuses
-- (booked / arrived / fulfilled / rescheduled / etc.) are kept.
WITH counts AS (
  SELECT
    (SELECT COUNT(*)::int FROM app_user_appointment
       WHERE ${px} AND "startTime" IS NOT NULL
         AND "startTime" BETWEEN '${start}' AND '${end}'
         AND status NOT IN (5, 6, 7)) AS app,
    (SELECT COUNT(*)::int FROM guest_appointment
       WHERE ${px} AND "startTime" IS NOT NULL
         AND "startTime" BETWEEN '${start}' AND '${end}'
         AND ("isBookedFromPraxis" IS NOT TRUE)
         AND status NOT IN (5, 6, 7)) AS web,
    (SELECT COUNT(*)::int FROM guest_appointment
       WHERE ${px} AND "startTime" IS NOT NULL
         AND "startTime" BETWEEN '${start}' AND '${end}'
         AND "isBookedFromPraxis" = true
         AND status NOT IN (5, 6, 7)) AS praxis
)
SELECT app, web, praxis, (app + web + praxis) AS total FROM counts;`);
    case 'NPS Sent':
      return r(`${head}-- Total = app NPS + corrected guest NPS.
-- guest_nps corrected = raw fhir_nps minus the spurious writes from
-- handleNewAppointment :329 (one per praxis-booked guest_appointment in
-- the same window). The :329 site does NOT actually trigger an NPS email;
-- only the :422 site in handleUnknownBooking does.
WITH counts AS (
  SELECT
    (SELECT COUNT(*)::int FROM app_user_nps_sent
       WHERE ${px} AND "createdAt" BETWEEN '${start}' AND '${end}') AS app_nps,
    (SELECT COUNT(*)::int FROM fhir_nps
       WHERE ${px} AND "createdAt" BETWEEN '${start}' AND '${end}') AS guest_nps_raw,
    (SELECT COUNT(*)::int FROM guest_appointment
       WHERE ${px} AND "createdAt" BETWEEN '${start}' AND '${end}'
         AND "isBookedFromPraxis" = true) AS guest_nps_spurious
)
SELECT
  app_nps,
  guest_nps_raw,
  guest_nps_spurious,
  GREATEST(0, guest_nps_raw - guest_nps_spurious) AS guest_nps_corrected,
  (app_nps + GREATEST(0, guest_nps_raw - guest_nps_spurious)) AS total
FROM counts;`);
    case 'Guest NPS':
      return r(`${head}-- Corrected guest NPS = raw fhir_nps minus :329 spurious writes
-- (one per praxis-booked guest_appointment in the same window).
-- :329 writes a fhir_nps row but never triggers an NPS email — only the
-- :422 site in handleUnknownBooking actually sends one.
WITH counts AS (
  SELECT
    (SELECT COUNT(*)::int FROM fhir_nps
       WHERE ${px} AND "createdAt" BETWEEN '${start}' AND '${end}') AS raw_fhir_nps,
    (SELECT COUNT(*)::int FROM guest_appointment
       WHERE ${px} AND "createdAt" BETWEEN '${start}' AND '${end}'
         AND "isBookedFromPraxis" = true) AS spurious_writes
)
SELECT
  raw_fhir_nps,
  spurious_writes,
  GREATEST(0, raw_fhir_nps - spurious_writes) AS guest_nps_corrected
FROM counts;`);
    case 'Guest NPS · no email':
      return r(`${head}-- Corrected guest NPS where the recipient had no email.
-- Both sides of the subtraction are filtered to hasEmail = false because
-- the :329 site copies userInfo.email.isNotEmpty into BOTH the fhir_nps
-- row and the paired guest_appointment row.
WITH counts AS (
  SELECT
    (SELECT COUNT(*)::int FROM fhir_nps
       WHERE ${px} AND "createdAt" BETWEEN '${start}' AND '${end}'
         AND "hasEmail" = false) AS raw_no_email,
    (SELECT COUNT(*)::int FROM guest_appointment
       WHERE ${px} AND "createdAt" BETWEEN '${start}' AND '${end}'
         AND "isBookedFromPraxis" = true AND "hasEmail" = false) AS spurious_no_email
)
SELECT
  raw_no_email,
  spurious_no_email,
  GREATEST(0, raw_no_email - spurious_no_email) AS guest_nps_no_email_corrected
FROM counts;`);
    case 'NPS Coverage':
      return r(`${head}-- coverage_pct = (app_nps + corrected_guest_nps) / (appointments + doc_requests + open_consultations) * 100
-- 30-day per-user dedup at the backend means <100% is normal even if every event would otherwise trigger a send.
-- Guest NPS here is the corrected count (raw fhir_nps minus :329 spurious writes).
WITH counts AS (
  SELECT
    ((SELECT COUNT(*)::int FROM app_user_nps_sent WHERE ${px} AND "createdAt" BETWEEN '${start}' AND '${end}')
     + GREATEST(0,
         (SELECT COUNT(*)::int FROM fhir_nps WHERE ${px} AND "createdAt" BETWEEN '${start}' AND '${end}')
         - (SELECT COUNT(*)::int FROM guest_appointment WHERE ${px} AND "createdAt" BETWEEN '${start}' AND '${end}' AND "isBookedFromPraxis" = true)
       )) AS nps_sent,
    ((SELECT COUNT(*)::int FROM app_user_appointment WHERE ${px} AND "createdAt" BETWEEN '${start}' AND '${end}')
     + (SELECT COUNT(*)::int FROM guest_appointment WHERE ${px} AND "createdAt" BETWEEN '${start}' AND '${end}')
     + (SELECT COUNT(*)::int FROM app_user_document_request WHERE ${px} AND "createdAt" BETWEEN '${start}' AND '${end}')
     + (SELECT COUNT(*)::int FROM app_user_open_consultation WHERE ${px} AND "createdAt" BETWEEN '${start}' AND '${end}')) AS eligible_events
)
SELECT
  nps_sent,
  eligible_events,
  ROUND(100.0 * nps_sent / NULLIF(eligible_events, 0), 1) AS coverage_pct
FROM counts;`);
    case 'Doc Requests':
      return r(`${head}-- "total" matches the report's KPI value.
SELECT
  COUNT(*) FILTER (WHERE "isFromWeb" = false) AS from_app,
  COUNT(*) FILTER (WHERE "isFromWeb" = true)  AS from_web,
  COUNT(*) FILTER (WHERE "isFromWeb" IS NULL) AS unknown,
  COUNT(*) AS total
FROM app_user_document_request
WHERE ${px} AND "createdAt" BETWEEN '${start}' AND '${end}';`);
    case 'Open Consultations':
      return r(`${head}SELECT COUNT(*) FROM app_user_open_consultation
WHERE ${px} AND "createdAt" BETWEEN '${start}' AND '${end}';`);
    case 'Cancellations':
      return r(`${head}-- cancellation_reason has NO praxisId/appointmentId. Attributed via user
-- registration AND filtered to users who actually booked here (EXISTS clause)
-- to avoid attributing cancellations from users who booked at other praxes.
-- Cancellations excluded by this filter are counted globally as "Unattributed
-- Cancellations" in the report.
SELECT COUNT(*)
FROM app_user_appointment_cancellation_reason c
JOIN app_user_info ui ON ui.id = c."userId"
WHERE ${uiPx}
  AND c."createdAt" BETWEEN '${start}' AND '${end}'
  AND EXISTS (
    SELECT 1 FROM app_user_appointment a
    WHERE a."userId" = c."userId"
      ${isAll ? `AND a."praxisId" = ui."praxisId"` : `AND a."praxisId" = '${lcId}'`}
  );`);
    case 'Unattributed Cancellations':
      return r(`-- Cancellations whose user is registered at some praxis but has NO appointment
-- at that praxis. The cancelled appointment was at another praxis (which we
-- can't determine from the schema — cancellation_reason has no appointmentId).
SELECT COUNT(*)
FROM app_user_appointment_cancellation_reason c
JOIN app_user_info ui ON ui.id = c."userId"
WHERE c."createdAt" BETWEEN '${start}' AND '${end}'
  AND ui."praxisId" IS NOT NULL AND ui."praxisId" <> ''
  AND NOT EXISTS (
    SELECT 1 FROM app_user_appointment a
    WHERE a."userId" = c."userId" AND a."praxisId" = ui."praxisId"
  );

-- Breakdown: how many unattributed cancellations per registered praxis.
SELECT ui."praxisId" AS user_registered_praxis, COUNT(*) AS unattributed_cancellations
FROM app_user_appointment_cancellation_reason c
JOIN app_user_info ui ON ui.id = c."userId"
WHERE c."createdAt" BETWEEN '${start}' AND '${end}'
  AND ui."praxisId" IS NOT NULL AND ui."praxisId" <> ''
  AND NOT EXISTS (
    SELECT 1 FROM app_user_appointment a
    WHERE a."userId" = c."userId" AND a."praxisId" = ui."praxisId"
  )
GROUP BY ui."praxisId"
ORDER BY unattributed_cancellations DESC;`);
    case 'Cancellation Rate':
      return r(`${head}-- cancellation_rate_pct = cancellations / total_appointments × 100.
-- Numerator uses the same EXISTS filter as the Cancellations metric — only
-- cancellations from users who actually booked at this praxis are counted.
WITH counts AS (
  SELECT
    (SELECT COUNT(*)::int FROM app_user_appointment_cancellation_reason c
     JOIN app_user_info ui ON ui.id = c."userId"
     WHERE ${uiPx} AND c."createdAt" BETWEEN '${start}' AND '${end}'
       AND EXISTS (
         SELECT 1 FROM app_user_appointment a
         WHERE a."userId" = c."userId"
           ${isAll ? `AND a."praxisId" = ui."praxisId"` : `AND a."praxisId" = '${lcId}'`}
       )) AS cancellations,
    ((SELECT COUNT(*)::int FROM app_user_appointment WHERE ${px} AND "createdAt" BETWEEN '${start}' AND '${end}')
     + (SELECT COUNT(*)::int FROM guest_appointment WHERE ${px} AND "createdAt" BETWEEN '${start}' AND '${end}')) AS total_appointments
)
SELECT
  cancellations,
  total_appointments,
  ROUND(100.0 * cancellations / NULLIF(total_appointments, 0), 1) AS cancellation_rate_pct
FROM counts;`);
    case 'Questionnaires':
      return r(`${head}-- questionnaire has no praxisId; JOIN through userInfoId → app_user_info.praxisId:
SELECT COUNT(*)
FROM app_user_questionnaire q
JOIN app_user_info ui ON ui.id = q."userInfoId"
WHERE ${uiPx}
  AND q."answeredAt" BETWEEN '${start}' AND '${end}';`);
    case 'PMS Downtime Events':
      return r(`-- analytics_pms_downtime is platform-wide (no praxisId column):
SELECT COUNT(*) FROM analytics_pms_downtime
WHERE "createdAt" BETWEEN '${start}' AND '${end}';`);
    case 'PMS Downtime (sec)':
      return r(`-- Cast totalDownTimeInSeconds explicitly: it's bigint, not int:
SELECT COALESCE(SUM("totalDownTimeInSeconds"), 0)::bigint AS total_seconds
FROM analytics_pms_downtime
WHERE "createdAt" BETWEEN '${start}' AND '${end}';`);
    case 'PMS Downtime (min)':
      return r(`-- Match the HTML's Math.round behaviour (round half-up, not truncate).
-- Plain integer division ("...::bigint / 60") would truncate 480.5 → 480 and
-- disagree with the report's rounded minute count by 1.
SELECT ROUND(COALESCE(SUM("totalDownTimeInSeconds"), 0) / 60.0)::int AS total_minutes,
       COALESCE(SUM("totalDownTimeInSeconds"), 0)::bigint AS total_seconds
FROM analytics_pms_downtime
WHERE "createdAt" BETWEEN '${start}' AND '${end}';`);
    case 'Account Deletions (total)':
      return r(`-- Schema has no praxisId — global count of unique deletion records:
SELECT COUNT(*) FROM app_user_deletion_feedback
WHERE "createdAt" BETWEEN '${start}' AND '${end}';`);
    case 'Reasons Selected (total)':
      return r(`-- reason is a List<String>; this counts the total reason
-- occurrences (one row may contribute multiple). Will be >= Account Deletions:
SELECT COALESCE(SUM(jsonb_array_length(reason::jsonb)), 0) AS reasons_selected
FROM app_user_deletion_feedback
WHERE "createdAt" BETWEEN '${start}' AND '${end}';`);
    default:
      return null;
  }
}

function _htmlFromPayload(payload, opts = {}) {
  const withCopySql = !!opts.withCopySql;
  const fmt = (n) => Number.isFinite(n) ? n.toLocaleString('en-US') : '0';
  const fmtPct = (n) => Number.isFinite(n) ? `${n.toFixed(1)}%` : '0%';
  // For ratios where denominator may legitimately be 0 (e.g. cancellation
  // rate when there are no appointments), show "—" instead of "0.0%" which
  // would imply "the rate is zero" rather than "the rate is undefined".
  const fmtPctOrDash = (n, denom) => (denom > 0 && Number.isFinite(n)) ? `${n.toFixed(1)}%` : '—';
  const esc = (s) => String(s ?? '').replace(/[&<>"']/g, c => ({ '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;' }[c]));

  // Metric explanations — shown both as hover tooltips on each KPI card and
  // in a glossary section at the top. Keep concise; include any non-obvious
  // gotchas (lifetime vs window, dedup behaviour, etc).
  const HELP = {
    'Total Patients':            'All-time count of patients registered with this praxis. NOT filtered by the report date range.',
    'Verified Patients':         'All-time count of patients with verified identity status (current state, not historical).',
    'Total Appointments':        'Appointments booked in the report window. Sum of: app + web + praxis. (praxisWithoutEmail is a subset of praxis, not added separately.)',
    'Took Place':                'Appointments whose startTime fell within the report window AND were not cancelled/noshow/enteredInError. Independent of when they were booked.',
    'NPS Sent':                  'Total NPS surveys sent: app users (app_user_nps_sent) + corrected guest NPS (see Guest NPS for the correction).',
    'NPS Coverage':              'Sent / NPS-eligible events × 100. Eligible = appointments + document requests + open consultations (backend triggers NPS after each). Uses the corrected Guest NPS numerator. Capped by 30-day per-user dedup, so <100% is normal.',
    'Doc Requests':              'Document requests created in the window. Split by source: from app vs web (vs unknown source).',
    'Open Consultations':        'Open-consultation requests created in the window.',
    'New Registrations':         'Patients whose app_user_info row was created within the window. Subset of Total Patients.',
    'Verification Rate':         'New verified / new registrations × 100. Note: isVerified is the current state — a registration counted as "verified" may have verified later.',
    'Cancellations':             'cancellation_reason has no praxisId/appointmentId. Filtered to cancellations where the same user has at least one appointment at THIS praxis (EXISTS clause). Cancellations excluded by this filter — user registered here but cancelled an appointment at another praxis — are counted globally as "Unattributed Cancellations".',
    'Cancellation Rate':         'Cancellations / Total Appointments × 100. Shown as "—" when there are no appointments (rate is undefined).',
    'Unattributed Cancellations': 'Global metric. Cancellations whose user is registered at some praxis but has NO appointment at that praxis — meaning the cancelled appointment was at a different praxis (schema doesn\'t expose which one). Sum of these + sum of per-praxis Cancellations = total cancellations in the window.',
    'Questionnaires':            'Questionnaires answered within the window, scoped to this praxis (via JOIN through user → praxisId).',
    'PMS Downtime Events':       'Number of PMS downtime incident records logged platform-wide in the window. Not per-praxis (PMS is the shared connector).',
    'PMS Downtime (sec)':        'Sum of totalDownTimeInSeconds across all incidents in the window. Platform-wide.',
    'PMS Downtime (min)':        'PMS Downtime seconds / 60. Platform-wide.',
    'Account Deletions (total)': 'Number of unique account deletions in the window (= row count of app_user_deletion_feedback). Schema has no praxisId — counted globally only.',
    'Reasons Selected (total)':  'Sum of reason occurrences across all deletions. Each user can pick multiple reasons (reason is List<String>), so this is ≥ Account Deletions (total).',
    'Guest NPS':                 'Real NPS attempts to guest/non-app users — recovered as: (raw fhir_nps rows) − (guest_appointment rows with isBookedFromPraxis=true in the same window). The backend writes an fhir_nps row at handleNewAppointment :329 every time a praxis-booked appointment is registered (booked/rescheduled/cancelled), but that path does NOT send an NPS email. Only handleUnknownBooking :422 (status=fulfilled) calls scheduleGuestNPS and triggers Brevo. Subtracting :329 writes — uniquely identified by their paired isBookedFromPraxis=true guest_appointment row — gives the count of actual :422 attempts.',
    'Guest NPS · no email':      'Subset of corrected Guest NPS where the guest had no email captured. Same recovery formula but restricted to hasEmail=false on both sides.',
  };
  const tip = (label) => HELP[label] ? `title="${esc(HELP[label])}"` : '';
  // Metrics whose validation SQL has no praxisId concept at all (platform-wide
  // tables). For everything else, a missing lcId means "all praxes" — the SQL
  // builder generates the cross-praxis variant.
  const GLOBAL_METRICS = new Set([
    'PMS Downtime Events', 'PMS Downtime (sec)', 'PMS Downtime (min)',
    'Account Deletions (total)', 'Reasons Selected (total)',
    'Unattributed Cancellations',
  ]);
  const copyBtn = (label, lcId, allPraxes) => {
    if (!withCopySql) return '';
    if (!lcId && !allPraxes && !GLOBAL_METRICS.has(label)) return '';
    const sql = _validationSqlFor(label, lcId || '', payload.dataStart, payload.dataEnd);
    if (!sql) return '';
    const title = allPraxes
      ? 'Copy SQL — across all praxes (matches this top-summary value)'
      : 'Copy validation SQL to clipboard';
    return `<button class="copy-btn" data-sql="${esc(sql)}" onclick="copySQL(this)" title="${esc(title)}">📋</button>`;
  };
  const kpi = (label, val, opts = {}) => {
    const { lcId, allPraxes = false, suffix = '' } = opts;
    return `<div class="kpi" ${tip(label)}>${copyBtn(label, lcId, allPraxes)}<div class="kpi-label">${esc(label)}</div><div class="kpi-val">${esc(fmt(val))}${suffix}</div></div>`;
  };
  const kpiPct = (label, val, opts = {}) => {
    const { lcId, allPraxes = false, denom } = opts;
    const display = (denom !== undefined) ? fmtPctOrDash(val, denom) : fmtPct(val);
    return `<div class="kpi" ${tip(label)}>${copyBtn(label, lcId, allPraxes)}<div class="kpi-label">${esc(label)}</div><div class="kpi-val">${esc(display)}</div></div>`;
  };

  const monthlyTableHeader = `
    <tr>
      <th>Month</th>
      <th>Booked App</th><th>Booked Web</th><th>Booked Praxis</th><th>Booked Praxis (no email)</th><th>Total Booked</th>
      <th>Took Place</th><th>Took Place App</th><th>Took Place Web</th><th>Took Place Praxis</th>
      <th>Doc Req App</th><th>Doc Req Web</th>
      <th>NPS Sent</th><th>Guest NPS</th>
      <th>New Reg</th><th>Verified Reg</th>
      <th>Cancellations</th><th>Open Cons</th><th>Questionnaires</th>
    </tr>`;

  const renderPraxis = (p) => {
    const t = p.totals;
    // Cell renderer: when validator mode is on, each numeric cell becomes
    // clickable and copies a single-COUNT SQL scoped to (this praxis, this
    // month, this column).
    const mc = (column, value, monthStr, bold = false) => {
      const inner = bold ? `<strong>${fmt(value)}</strong>` : fmt(value);
      if (!withCopySql) return `<td>${inner}</td>`;
      const { start, end } = _monthRange(monthStr);
      const sql = _monthCellSql(column, p.lcId, start, end);
      if (!sql) return `<td>${inner}</td>`;
      return `<td class="clickable-cell" data-sql="${esc(sql)}" onclick="copySQL(this)" title="Click to copy SQL — ${esc(p.lcId)} · ${esc(monthStr)} · ${esc(column)}">${inner}</td>`;
    };
    const monthlyRows = payload.monthsCovered.map(month => {
      const m = p.monthly[month] || _emptyMonthlyKpi();
      return `<tr>
        <td class="mono">${esc(month)}</td>
        ${mc('app', m.appointmentsBookedFromApp, month)}
        ${mc('web', m.appointmentsBookedFromWeb, month)}
        ${mc('praxis', m.appointmentsBookedFromPraxis, month)}
        ${mc('praxisNoEmail', m.appointmentsBookedFromPraxisWithoutEmail, month)}
        ${mc('totalBooked', m.totalAppointments, month, true)}
        ${mc('tookPlace', m.totalAppointmentsTookPlace, month)}
        ${mc('tookPlaceApp', m.appointmentsTookPlaceFromApp, month)}
        ${mc('tookPlaceWeb', m.appointmentsTookPlaceFromWeb, month)}
        ${mc('tookPlacePraxis', m.appointmentsTookPlaceFromPraxis, month)}
        ${mc('docReqApp', m.documentRequestFromApp, month)}
        ${mc('docReqWeb', m.documentRequestFromWeb, month)}
        ${mc('npsSent', m.npsEmailsSent, month)}
        ${mc('guestNps', m.guestNPS, month)}
        ${mc('newReg', m.newRegistrations, month)}
        ${mc('verifiedReg', m.newVerifiedRegistrations, month)}
        ${mc('cancellations', m.cancellations, month)}
        ${mc('openCons', m.openConsultations, month)}
        ${mc('questionnaires', m.questionnairesCompleted, month)}
      </tr>`;
    }).join('');

    const catRows = (p.appointmentCategories.length ? p.appointmentCategories : [{ category: '—', count: 0 }])
      .map(c => `<tr><td>${esc(c.category)}</td><td>${fmt(c.count)}</td></tr>`).join('');
    const cancelRows = (p.cancellationReasons.length ? p.cancellationReasons : [{ category: '—', count: 0 }])
      .map(c => `<tr><td>${esc(c.category)}</td><td>${fmt(c.count)}</td></tr>`).join('');

    const dbg = p._debug;
    const sanityFail = dbg && (!dbg.invariants.totalAppointmentsMatchesSum || !dbg.invariants.totalAppointmentsTookPlaceMatchesSum || !dbg.invariants.praxisNoEmailLessOrEqualPraxis);
    const dbgBadge = sanityFail
      ? `<div style="background:#fee2e2;border:1px solid #ef4444;color:#7f1d1d;padding:8px 12px;border-radius:6px;margin:8px 0;font-size:12px"><strong>Sanity check FAILED</strong> — see _debug in JSON. Raw row counts: ${esc(JSON.stringify(dbg.rowCounts))}</div>`
      : (dbg ? `<div class="muted" style="font-size:11px;margin:6px 0">DB rows fetched: appAppts=${dbg.rowCounts.appAppts} webAppts=${dbg.rowCounts.webAppts} appTook=${dbg.rowCounts.appAppointmentsTookPlace} guestTook=${dbg.rowCounts.guestAppointmentsTookPlace} cancellations=${dbg.rowCounts.cancellations} questionnaires=${dbg.rowCounts.questionnaires}</div>` : '');
    return `
      <section class="praxis" id="${esc(p.lcId)}">
        <h2>${esc(p.name || p.lcId)} <span class="muted">(${esc(p.lcId)}${p.bundesland ? ` · ${esc(p.bundesland.toUpperCase())}` : ''})</span></h2>
        ${dbgBadge}
        <h3>Totals (${esc(payload.dataStart.slice(0,10))} → ${esc(payload.dataEnd.slice(0,10))})</h3>
        <div class="kpi-grid">
          ${kpi('Total Patients', t.totalPatients, { lcId: p.lcId })}
          ${kpi('Verified Patients', t.totalVerifiedPatients, { lcId: p.lcId })}
          ${kpi('Total Appointments', t.totalAppointments, { lcId: p.lcId })}
          ${kpi('Took Place', t.totalAppointmentsTookPlace, { lcId: p.lcId })}
          ${kpi('NPS Sent', t.totalNPSSent, { lcId: p.lcId })}
          ${kpiPct('NPS Coverage', t.npsCoveragePercentage, { lcId: p.lcId, denom: t.totalNpsEligibleEvents })}
          ${kpi('Doc Requests', t.totalDocumentRequests, { lcId: p.lcId })}
          ${kpi('Open Consultations', t.openConsultations, { lcId: p.lcId })}
          ${kpi('New Registrations', t.newRegistrations, { lcId: p.lcId })}
          ${kpiPct('Verification Rate', t.verificationRate, { lcId: p.lcId, denom: t.newRegistrations })}
          ${kpi('Cancellations', t.cancellations, { lcId: p.lcId })}
          ${kpiPct('Cancellation Rate', t.cancellationRate, { lcId: p.lcId, denom: t.totalAppointments })}
          ${kpi('Questionnaires', t.questionnairesCompleted, { lcId: p.lcId })}
        </div>

        <h3>Monthly Breakdown</h3>
        <div class="scroll"><table class="data">${monthlyTableHeader}${monthlyRows}</table></div>

        <div class="two-col">
          <div>
            <h3>Top Appointment Categories</h3>
            <table class="data narrow"><tr><th>Category</th><th>Count</th></tr>${catRows}</table>
          </div>
          <div>
            <h3>Top Cancellation Reasons</h3>
            <table class="data narrow"><tr><th>Reason</th><th>Count</th></tr>${cancelRows}</table>
          </div>
        </div>
      </section>`;
  };

  const summary = payload.praxes.reduce((acc, p) => {
    acc.totalAppointments += p.totals.totalAppointments;
    acc.totalAppointmentsTookPlace += p.totals.totalAppointmentsTookPlace;
    acc.totalNPSSent += p.totals.totalNPSSent;
    acc.totalDocumentRequests += p.totals.totalDocumentRequests;
    acc.totalCancellations += p.totals.cancellations;
    acc.openConsultations += p.totals.openConsultations;
    acc.newRegistrations += p.totals.newRegistrations;
    acc.totalPatients += p.totals.totalPatients;
    acc.totalVerifiedPatients += p.totals.totalVerifiedPatients;
    return acc;
  }, { totalAppointments: 0, totalAppointmentsTookPlace: 0, totalNPSSent: 0, totalDocumentRequests: 0, totalCancellations: 0, openConsultations: 0, newRegistrations: 0, totalPatients: 0, totalVerifiedPatients: 0 });

  const tocRows = payload.praxes.map(p =>
    `<li><a href="#${esc(p.lcId)}">${esc(p.name || p.lcId)} <span class="muted">(${esc(p.lcId)})</span></a> — ${fmt(p.totals.totalAppointments)} bookings</li>`
  ).join('');

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>LillianCare — Historical Analytics (${esc(payload.dataStart.slice(0,10))} → ${esc(payload.dataEnd.slice(0,10))})</title>
<style>
  :root { color-scheme: light dark; }
  * { box-sizing: border-box; }
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; margin: 0; padding: 24px; background: #fafaf9; color: #1a1a1a; }
  h1 { margin: 0 0 4px; font-size: 28px; }
  h2 { margin: 32px 0 12px; padding-bottom: 8px; border-bottom: 2px solid #e5e7eb; font-size: 22px; }
  h3 { margin: 20px 0 10px; font-size: 14px; text-transform: uppercase; letter-spacing: 0.05em; color: #555; }
  .muted { color: #888; font-weight: normal; font-size: 0.85em; }
  .header { background: white; padding: 20px 24px; border-radius: 12px; box-shadow: 0 1px 3px rgba(0,0,0,0.08); margin-bottom: 20px; }
  .global-kpis { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 12px; margin-top: 16px; }
  .kpi-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 10px; }
  .kpi { background: white; padding: 10px 12px; border-radius: 8px; border: 1px solid #e5e7eb; position: relative; }
  .kpi-label { font-size: 11px; text-transform: uppercase; letter-spacing: 0.04em; color: #666; }
  .kpi-val { font-size: 20px; font-weight: 600; margin-top: 2px; }
  .copy-btn { position: absolute; top: 6px; right: 6px; background: #f3f4f6; border: 1px solid #e5e7eb; border-radius: 4px; padding: 2px 6px; cursor: pointer; font-size: 12px; line-height: 1; transition: background 0.15s; }
  .copy-btn:hover { background: #e0e7ff; border-color: #6366f1; }
  .copy-btn.copied { background: #16a34a; color: white; border-color: #16a34a; }
  .clickable-cell { cursor: copy; transition: background 0.15s, color 0.15s; }
  .clickable-cell:hover { background: #e0e7ff !important; color: #1e40af; }
  .clickable-cell.cell-copied { background: #16a34a !important; color: white !important; transition: none; }
  #copy-toast { position: fixed; bottom: 24px; right: 24px; background: #16a34a; color: white; padding: 10px 16px; border-radius: 8px; font-size: 14px; opacity: 0; transition: opacity 0.2s; pointer-events: none; z-index: 1000; box-shadow: 0 4px 12px rgba(0,0,0,0.15); }
  #copy-toast.show { opacity: 1; }
  .validator-banner { background: #fef3c7; border: 1px solid #f59e0b; color: #78350f; padding: 12px 16px; border-radius: 8px; margin-bottom: 16px; font-size: 14px; }
  .praxis { background: white; padding: 20px 24px; border-radius: 12px; margin-bottom: 16px; box-shadow: 0 1px 2px rgba(0,0,0,0.04); }
  table.data { border-collapse: collapse; width: 100%; font-size: 12px; }
  table.data th, table.data td { padding: 6px 8px; border-bottom: 1px solid #eee; text-align: right; white-space: nowrap; }
  table.data th { background: #f3f4f6; font-weight: 600; text-align: right; position: sticky; top: 0; }
  table.data td:first-child, table.data th:first-child { text-align: left; }
  table.data.narrow th, table.data.narrow td { text-align: left; }
  table.data.narrow td:last-child, table.data.narrow th:last-child { text-align: right; }
  .scroll { overflow-x: auto; max-height: 420px; overflow-y: auto; border: 1px solid #e5e7eb; border-radius: 6px; }
  .two-col { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-top: 16px; }
  @media (max-width: 700px) { .two-col { grid-template-columns: 1fr; } }
  .mono { font-family: "SF Mono", Menlo, Consolas, monospace; }
  ul.toc { columns: 2; margin: 0; padding-left: 20px; font-size: 13px; }
  ul.toc li { break-inside: avoid; margin: 2px 0; }
  ul.toc a { color: #1d4ed8; text-decoration: none; }
  ul.toc a:hover { text-decoration: underline; }
  @media print { body { background: white; } .praxis { break-inside: avoid; box-shadow: none; border: 1px solid #ddd; } }
</style>
</head>
<body>
  ${withCopySql ? `<div class="validator-banner"><strong>Validator mode:</strong> click the 📋 button on any KPI card, or click any numeric cell in a monthly breakdown table, to copy a standalone SQL query that produces that number.</div>` : ''}
  <div class="header">
    <h1>LillianCare — Historical Analytics${withCopySql ? ' <span style="font-size:14px;color:#f59e0b;font-weight:normal">(validator)</span>' : ''}</h1>
    <div class="muted">${esc(payload.dataStart.slice(0,10))} → ${esc(payload.dataEnd.slice(0,10))} · ${payload.praxes.length} praxes · ${payload.monthsCovered.length} months · generated ${esc(payload.generatedAt)}</div>
    <div class="global-kpis">
      ${kpi('Total Appointments', summary.totalAppointments, { allPraxes: true })}
      ${kpi('Took Place', summary.totalAppointmentsTookPlace, { allPraxes: true })}
      ${kpi('NPS Sent', summary.totalNPSSent, { allPraxes: true })}
      ${kpi('Doc Requests', summary.totalDocumentRequests, { allPraxes: true })}
      ${kpi('Cancellations', summary.totalCancellations, { allPraxes: true })}
      ${kpi('Open Consultations', summary.openConsultations, { allPraxes: true })}
      ${kpi('Total Patients', summary.totalPatients, { allPraxes: true })}
      ${kpi('Verified Patients', summary.totalVerifiedPatients, { allPraxes: true })}
    </div>
    <h3>Praxes</h3>
    <ul class="toc">${tocRows}</ul>
  </div>

  <details class="praxis" id="__glossary__" style="border-left: 4px solid #f59e0b;">
    <summary style="cursor: pointer; list-style: none; font-size: 18px; font-weight: 600;">📖 Glossary — what each metric means <span class="muted" style="font-weight: normal; font-size: 14px;">(click to expand)</span></summary>
    <div style="margin-top: 16px;">
      <table class="data narrow" style="font-size: 13px;">
        <tr><th style="width: 220px;">Metric</th><th>Meaning</th></tr>
        ${Object.entries(HELP).map(([label, desc]) => `<tr><td><strong>${esc(label)}</strong></td><td style="white-space: normal;">${esc(desc)}</td></tr>`).join('')}
      </table>
      <div class="muted" style="margin-top: 12px; font-size: 12px;">
        Hover any KPI card below to see its definition as a tooltip.
        <br>NPS triggers: backend sends an NPS email after appointments, document requests, and open consultations — gated to once per 30 days per user (configurable via <code>CorePraxisInfoMarketingConfig.npsFrequencyDays</code>).
      </div>
    </div>
  </details>

  <section class="praxis" id="__global__" style="border-left: 4px solid #6366f1;">
    <h2>Global / Platform-wide <span class="muted">(no praxisId in schema — applies to all)</span></h2>
    <h3>System metrics</h3>
    <div class="kpi-grid">
      ${(() => {
        const totalSec = payload.pmsDowntimes.reduce((s, d) => s + Number(d.totalDownTimeInSeconds || 0), 0);
        return kpi('PMS Downtime Events', payload.pmsDowntimes.length) +
               kpi('PMS Downtime (sec)', totalSec) +
               kpi('PMS Downtime (min)', Math.round(totalSec / 60));
      })()}
      ${kpi('Account Deletions (total)', payload.totalDeletions || 0)}
      ${kpi('Reasons Selected (total)', payload.deletionReasons.reduce((s, r) => s + Number(r.count || 0), 0))}
      ${kpi('Unattributed Cancellations', payload.unattributedCancellations?.total || 0)}
    </div>

    <div class="two-col">
      <div>
        <h3>PMS Downtime Events</h3>
        ${payload.pmsDowntimes.length === 0
          ? `<div class="muted" style="font-size:13px">No PMS downtime in this range.</div>`
          : `<div class="scroll" style="max-height:280px"><table class="data narrow">
              <tr><th>When</th><th>Duration (sec)</th></tr>
              ${payload.pmsDowntimes.map(d => `<tr><td class="mono">${esc(String(d.createdAt).slice(0,19))}</td><td>${fmt(Number(d.totalDownTimeInSeconds || 0))}</td></tr>`).join('')}
            </table></div>`}
      </div>
      <div>
        <h3>Top Deletion Reasons</h3>
        ${payload.deletionReasons.length === 0
          ? `<div class="muted" style="font-size:13px">No account deletions in this range.</div>`
          : `<table class="data narrow"><tr><th>Reason</th><th>Count</th></tr>${payload.deletionReasons.map(r => `<tr><td>${esc(r.reason)}</td><td>${fmt(r.count)}</td></tr>`).join('')}</table>`}
      </div>
    </div>

    ${(payload.unattributedCancellations?.total || 0) > 0 ? `
    <h3 style="margin-top: 24px;">Unattributed Cancellations — by user-registered praxis</h3>
    <div class="muted" style="font-size: 12px; margin-bottom: 8px;">
      These cancellations come from users registered at the listed praxis, but the user has NO appointment at that praxis — so the cancelled appointment was at a different praxis.
      Schema doesn't expose which one.
    </div>
    <table class="data narrow">
      <tr><th>User registered at</th><th>Cancellations</th></tr>
      ${payload.unattributedCancellations.byUserRegisteredPraxis.map(r => `<tr><td class="mono">${esc(r.lcId)}</td><td>${fmt(r.count)}</td></tr>`).join('')}
    </table>
    ` : ''}
  </section>

  ${payload.praxes.map(renderPraxis).join('\n')}
  <div id="copy-toast"></div>
  <script>
    window.__DATA__ = ${JSON.stringify(payload).replace(/</g, '\\u003c')};
    function copySQL(el) {
      const sql = el.getAttribute('data-sql');
      if (!sql) return;
      const isCell = el.tagName === 'TD';
      const done = () => {
        if (isCell) {
          el.classList.add('cell-copied');
          setTimeout(() => el.classList.remove('cell-copied'), 900);
        } else {
          el.classList.add('copied');
          const orig = el.textContent;
          el.textContent = '✓';
          setTimeout(() => { el.classList.remove('copied'); el.textContent = orig; }, 1500);
        }
        const toast = document.getElementById('copy-toast');
        toast.textContent = isCell ? 'Cell SQL copied' : 'SQL copied — paste into your DB client to verify';
        toast.classList.add('show');
        setTimeout(() => { toast.classList.remove('show'); }, 2000);
      };
      const fallback = () => {
        const ta = document.createElement('textarea');
        ta.value = sql; ta.style.position = 'fixed'; ta.style.opacity = '0';
        document.body.appendChild(ta); ta.select();
        try { document.execCommand('copy'); done(); } catch (e) { alert('Copy failed: ' + e.message); }
        document.body.removeChild(ta);
      };
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(sql).then(done).catch(fallback);
      } else {
        fallback();
      }
    }
  </script>
</body>
</html>`;
}

app.get('/api/analytics/export-historical', async (req, res) => {
  try {
    const fs = require('fs');
    const path = require('path');

    const endDateStr = (req.query.endDate || '2026-04-30').toString();
    const endDate = new Date(`${endDateStr}T23:59:59.999Z`);
    if (isNaN(endDate.getTime())) return res.status(400).json({ error: 'invalid endDate (YYYY-MM-DD)' });

    // 1. Detect data start = MIN(createdAt) across the analytics tables.
    const startProbe = await query(req, `
      SELECT MIN("createdAt") AS m FROM (
        SELECT MIN("createdAt") AS "createdAt" FROM app_user_appointment
        UNION ALL SELECT MIN("createdAt") FROM guest_appointment
        UNION ALL SELECT MIN("createdAt") FROM app_user_info
        UNION ALL SELECT MIN("createdAt") FROM app_user_nps_sent
        UNION ALL SELECT MIN("createdAt") FROM app_user_document_request
      ) t`);
    const dataStart = startProbe[0]?.m ? new Date(startProbe[0].m) : new Date('2024-01-01');
    const rangeStart = dataStart;
    const rangeEnd   = endDate;

    // 2. Praxis directory. `bundeslandCode` is cockpit-only and may not exist
    //    in prod — try with it, fall back without.
    let praxisDirRows;
    try {
      praxisDirRows = await query(req, `SELECT "lcId", name, "shortName", "bundeslandCode" FROM praxis_config WHERE "lcId" IS NOT NULL ORDER BY "lcId"`);
    } catch (_) {
      praxisDirRows = await query(req, `SELECT "lcId", name, "shortName" FROM praxis_config WHERE "lcId" IS NOT NULL ORDER BY "lcId"`);
    }
    const praxisDir = praxisDirRows.map(r => ({
      lcId: r.lcId,
      name: r.name || r.shortName || r.lcId,
      shortName: r.shortName || null,
      bundesland: r.bundeslandCode != null ? (BUNDESLAND_CODES[r.bundeslandCode] || null) : null,
    }));

    // 3. Discover lcIds that actually have data (some praxis_config rows may
    //    be empty placeholders).
    const usedRows = await query(req, `SELECT DISTINCT "praxisId" FROM app_user_info WHERE "praxisId" IS NOT NULL AND "praxisId" <> ''`);
    const used = new Set(usedRows.map(r => r.praxisId));
    const targetPraxes = praxisDir.filter(p => used.has(p.lcId));
    if (targetPraxes.length === 0) return res.status(400).json({ error: 'no praxes with data found' });

    // 4. Walk praxes one-at-a-time. Each iteration runs ~13 indexed queries
    //    in parallel — same load profile as a normal /api/analytics request.
    const results = [];
    for (const p of targetPraxes) {
      const agg = await _fetchPraxisAggregates(req, p.lcId, rangeStart, rangeEnd);
      results.push({ ...p, ...agg });
    }

    // 5. Global PMS downtime list + deletion reasons (not praxis-scoped).
    //    Cockpit tables don't exist in prod — query is best-effort.
    //    deletion_feedback.reason is a JSON array; aggregate in JS, not SQL.
    //    Unattributed cancellations: rows where the user has no appointment at
    //    their registered praxis — the actual cancelled appointment was
    //    elsewhere (typically another praxis the user also booked at).
    const [pmsDowntimes, deletionRaw, unattributedCancellations, cockpit] = await Promise.all([
      query(req, `SELECT id, "totalDownTimeInSeconds", "createdAt" FROM analytics_pms_downtime WHERE "createdAt" BETWEEN $1 AND $2 ORDER BY "createdAt"`, [rangeStart, rangeEnd]),
      query(req, `SELECT reason FROM app_user_deletion_feedback WHERE "createdAt" BETWEEN $1 AND $2`, [rangeStart, rangeEnd]),
      query(req, `SELECT c."createdAt", c.reason, ui."praxisId" AS user_registered_praxis
                    FROM app_user_appointment_cancellation_reason c
                    JOIN app_user_info ui ON ui.id = c."userId"
                    WHERE c."createdAt" BETWEEN $1 AND $2
                      AND ui."praxisId" IS NOT NULL AND ui."praxisId" <> ''
                      AND NOT EXISTS (
                        SELECT 1 FROM app_user_appointment a
                        WHERE a."userId" = c."userId" AND a."praxisId" = ui."praxisId"
                      )`, [rangeStart, rangeEnd]),
      _gatherCockpitOverview(req).catch((e) => { console.warn('cockpit gather skipped:', e.message); return []; }),
    ]);

    // Aggregate unattributed cancellations: count + reasons + by-user-praxis breakdown.
    const unattributedTotal = unattributedCancellations.length;
    const unattributedReasonCounts = {};
    const unattributedByPraxis = {};
    for (const row of unattributedCancellations) {
      const list = Array.isArray(row.reason) ? row.reason : (row.reason != null ? [row.reason] : ['—']);
      for (const r of list) {
        const k = String(r).slice(0, 120);
        unattributedReasonCounts[k] = (unattributedReasonCounts[k] || 0) + 1;
      }
      const px = row.user_registered_praxis;
      unattributedByPraxis[px] = (unattributedByPraxis[px] || 0) + 1;
    }
    const unattributedReasons = Object.entries(unattributedReasonCounts)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 20)
      .map(([reason, count]) => ({ reason, count }));
    const unattributedByPraxisArr = Object.entries(unattributedByPraxis)
      .sort((a, b) => b[1] - a[1])
      .map(([lcId, count]) => ({ lcId, count }));

    // deletionRaw row count = unique account deletions (each user appears once
    // per deletion event). The reason column is a List<String> — same user can
    // select multiple reasons, so the reason-breakdown counts will sum to MORE
    // than totalDeletions. Track them separately.
    const totalDeletions = deletionRaw.length;
    const deletionCounts = {};
    for (const row of deletionRaw) {
      const list = Array.isArray(row.reason) ? row.reason : (row.reason != null ? [row.reason] : ['—']);
      for (const r of list) {
        const k = String(r).slice(0, 120);
        deletionCounts[k] = (deletionCounts[k] || 0) + 1;
      }
    }
    const deletionRows = Object.entries(deletionCounts)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 50)
      .map(([reason, count]) => ({ reason, count }));

    const monthsCovered = _enumerateMonths(rangeStart, rangeEnd);

    const payload = {
      generatedAt: new Date().toISOString(),
      dataStart:   rangeStart.toISOString(),
      dataEnd:     rangeEnd.toISOString(),
      monthsCovered,
      praxes: results,
      pmsDowntimes,
      totalDeletions,
      deletionReasons: deletionRows,
      unattributedCancellations: {
        total: unattributedTotal,
        reasons: unattributedReasons,
        byUserRegisteredPraxis: unattributedByPraxisArr,
      },
      cockpit,
    };

    // 6. Write outputs.
    const stamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
    const outDir = path.join(__dirname, 'exports', `historical-${endDate.toISOString().slice(0,10)}-${stamp}`);
    fs.mkdirSync(outDir, { recursive: true });

    const withCopySql = req.query.validator === '1' || req.query.validator === 'true';
    const jsonPath = path.join(outDir, 'analytics.json');
    const xlsxPath = path.join(outDir, 'analytics.xlsx');
    const htmlPath = path.join(outDir, withCopySql ? 'analytics-validator.html' : 'analytics.html');

    fs.writeFileSync(jsonPath, JSON.stringify(payload, null, 2));
    fs.writeFileSync(xlsxPath, _xlsxFromPayload(payload));
    fs.writeFileSync(htmlPath, _htmlFromPayload(payload, { withCopySql }));

    res.json({
      ok: true,
      outDir,
      validator: withCopySql,
      files: { json: jsonPath, xlsx: xlsxPath, html: htmlPath },
      praxesProcessed: results.length,
      monthsCovered: monthsCovered.length,
      dataStart: payload.dataStart,
      dataEnd:   payload.dataEnd,
    });
  } catch (e) {
    console.error('export-historical failed:', e);
    res.status(500).json({ error: e.message });
  }
});

// ─── Routes: Analytics / Cockpit (per-praxis schedule config) ────────────────
// Cockpit is the schedule editor in the praxis app. It writes to:
//   • cockpit_consultation_hours / cockpit_work_hours      (baseline per weekday)
//   • cockpit_week_override                                 (one-off per ISO week)
//   • cockpit_standard_week_version                         (versioned standard weeks)
//   • cockpit_person_duration_exception                     (per-employee overlay)
//   • cockpit_appointment_type_matrix                       (provider routing)
//   • praxis_config.bundeslandCode                          (holiday region)
//
// All `praxisId` columns on cockpit tables are int FKs to praxis_config.id, while
// the analytics overview uses praxis_config.lcId (string). We keep this layer
// keyed by lcId to match the rest of the analytics surface.
const BUNDESLAND_CODES = ['bw','by','be','bb','hb','hh','he','mv','ni','nw','rp','sl','sn','st','sh','th'];
const COCKPIT_KIND_NAMES = ['vorOrt','homeoffice','akut','heimversorgung','urlaub','nichtBuchbar','buffer'];
const COCKPIT_DAY_NAMES = ['monday','tuesday','wednesday','thursday','friday','saturday','sunday'];

function currentIsoYearWeek(d = new Date()) {
  const t = new Date(Date.UTC(d.getFullYear(), d.getMonth(), d.getDate()));
  t.setUTCDate(t.getUTCDate() + 4 - (t.getUTCDay() || 7));
  const yearStart = new Date(Date.UTC(t.getUTCFullYear(), 0, 1));
  const week = Math.ceil(((t - yearStart) / 86400000 + 1) / 7);
  return { year: t.getUTCFullYear(), week };
}

// Cockpit metrics keyed by praxis_config.lcId — rendered in the Analytics
// Overview table next to the booking/registration columns.
app.get('/api/analytics/cockpit-overview', async (req, res) => {
  try {
    const { year: cy, week: cw } = currentIsoYearWeek();
    const cwKey = cy * 53 + cw;

    const [praxes, consHours, workHours, overrides, versions, pdes, matrix] = await Promise.all([
      query(req, `SELECT id, "lcId", "bundeslandCode" FROM praxis_config`),
      query(req, `SELECT "praxisId",
                    COUNT(*)::int AS rows,
                    COALESCE(SUM(EXTRACT(EPOCH FROM ("end"::time - "start"::time)) / 60), 0)::int AS minutes
                  FROM cockpit_consultation_hours GROUP BY "praxisId"`),
      query(req, `SELECT "praxisId",
                    COUNT(*)::int AS rows,
                    COALESCE(SUM(EXTRACT(EPOCH FROM ("end"::time - "start"::time)) / 60), 0)::int AS minutes,
                    COALESCE(SUM("breakMin"), 0)::int AS break_minutes
                  FROM cockpit_work_hours GROUP BY "praxisId"`),
      query(req, `SELECT "praxisId", COUNT(*)::int AS c FROM cockpit_week_override GROUP BY "praxisId"`),
      query(req, `SELECT "praxisId", COUNT(*)::int AS c FROM cockpit_standard_week_version GROUP BY "praxisId"`),
      query(req, `SELECT "praxisId", COUNT(*)::int AS c FROM cockpit_person_duration_exception
                  WHERE ("validFromIsoYear" * 53 + "validFromIsoWeek") <= $1
                    AND ("validUntilIsoYear" IS NULL
                         OR ("validUntilIsoYear" * 53 + "validUntilIsoWeek") >= $1)
                  GROUP BY "praxisId"`, [cwKey]),
      query(req, `SELECT "praxisId", COUNT(*)::int AS c FROM cockpit_appointment_type_matrix GROUP BY "praxisId"`),
    ]);

    const byPid = {};
    for (const r of consHours)  (byPid[r.praxisId] ||= {}).consultation = { rows: r.rows, minutes: r.minutes };
    for (const r of workHours)  (byPid[r.praxisId] ||= {}).work         = { rows: r.rows, minutes: r.minutes, breakMinutes: r.break_minutes };
    for (const r of overrides)  (byPid[r.praxisId] ||= {}).overrides    = r.c;
    for (const r of versions)   (byPid[r.praxisId] ||= {}).versions     = r.c;
    for (const r of pdes)       (byPid[r.praxisId] ||= {}).activePdes   = r.c;
    for (const r of matrix)     (byPid[r.praxisId] ||= {}).matrixEntries = r.c;

    const result = praxes.map(p => {
      const m = byPid[p.id] || {};
      const cons = m.consultation || { rows: 0, minutes: 0 };
      const work = m.work || { rows: 0, minutes: 0, breakMinutes: 0 };
      const blIdx = p.bundeslandCode === null || p.bundeslandCode === undefined ? null : Number(p.bundeslandCode);
      return {
        lcId: p.lcId,
        bundesland: blIdx === null ? null : (BUNDESLAND_CODES[blIdx] || null),
        hasBaseline: cons.rows > 0 || work.rows > 0,
        consultationRows: cons.rows,
        consultationMinutes: cons.minutes,
        workRows: work.rows,
        workMinutes: work.minutes,
        workBreakMinutes: work.breakMinutes,
        overrideCount: m.overrides || 0,
        versionCount: m.versions || 0,
        activePdeCount: m.activePdes || 0,
        matrixEntries: m.matrixEntries || 0,
      };
    });

    res.json({
      currentIsoYear: cy,
      currentIsoWeek: cw,
      praxes: result,
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Cockpit detail for a single praxis (lcId) — consumed by the per-praxis
// analytics view to render a dedicated Cockpit tab.
app.get('/api/analytics/cockpit', async (req, res) => {
  try {
    const lcId = (req.query.praxisId || '').toString().trim();
    if (!lcId) return res.status(400).json({ error: 'praxisId is required' });
    const { year: cy, week: cw } = currentIsoYearWeek();
    const cwKey = cy * 53 + cw;

    const praxisRows = await query(req, `SELECT id, "lcId", name, "bundeslandCode" FROM praxis_config WHERE "lcId" = $1`, [lcId]);
    if (!praxisRows.length) return res.status(404).json({ error: 'praxis not found' });
    const p = praxisRows[0];

    const [cons, work, matrix, overrides, versions, pdes] = await Promise.all([
      query(req, `SELECT "employeeId", day, kind, "start", "end", "onlineBookable",
                    EXTRACT(EPOCH FROM ("end"::time - "start"::time)) / 60 AS minutes
                  FROM cockpit_consultation_hours WHERE "praxisId" = $1
                  ORDER BY "employeeId", day, "start"`, [p.id]),
      query(req, `SELECT "employeeId", day, "start", "end", "breakMin",
                    EXTRACT(EPOCH FROM ("end"::time - "start"::time)) / 60 AS minutes
                  FROM cockpit_work_hours WHERE "praxisId" = $1
                  ORDER BY "employeeId", day, "start"`, [p.id]),
      query(req, `SELECT "appointmentTypeKey", providers, "modifiedAt"
                  FROM cockpit_appointment_type_matrix WHERE "praxisId" = $1
                  ORDER BY "appointmentTypeKey"`, [p.id]),
      query(req, `SELECT "isoYear", "isoWeek",
                    "openingHoursJson" IS NOT NULL AS has_opening,
                    "consultationHoursJson" IS NOT NULL AS has_consultation,
                    "workHoursJson" IS NOT NULL AS has_work,
                    "mfaGenericHoursJson" IS NOT NULL AS has_mfa_generic,
                    "modifiedAt"
                  FROM cockpit_week_override WHERE "praxisId" = $1
                  ORDER BY "isoYear" DESC, "isoWeek" DESC LIMIT 25`, [p.id]),
      query(req, `SELECT "validFromIsoYear", "validFromIsoWeek",
                    "openingHoursJson" IS NOT NULL AS has_opening,
                    "consultationHoursJson" IS NOT NULL AS has_consultation,
                    "workHoursJson" IS NOT NULL AS has_work,
                    "mfaGenericHoursJson" IS NOT NULL AS has_mfa_generic,
                    "createdBy", "createdAt"
                  FROM cockpit_standard_week_version WHERE "praxisId" = $1
                  ORDER BY "validFromIsoYear" DESC, "validFromIsoWeek" DESC LIMIT 25`, [p.id]),
      query(req, `SELECT id, "employeeId", kind, day, "start", "end",
                    "validFromIsoYear", "validFromIsoWeek",
                    "validUntilIsoYear", "validUntilIsoWeek", note,
                    (("validFromIsoYear" * 53 + "validFromIsoWeek") <= $2
                     AND ("validUntilIsoYear" IS NULL
                          OR ("validUntilIsoYear" * 53 + "validUntilIsoWeek") >= $2)) AS is_active
                  FROM cockpit_person_duration_exception WHERE "praxisId" = $1
                  ORDER BY "validFromIsoYear" DESC, "validFromIsoWeek" DESC, id DESC`, [p.id, cwKey]),
    ]);

    const consByEmp = {};
    let consTotalMinutes = 0, consBookableMinutes = 0;
    const consKindMinutes = {};
    for (const r of cons) {
      const mins = parseFloat(r.minutes) || 0;
      consTotalMinutes += mins;
      if (r.onlineBookable) consBookableMinutes += mins;
      const kindName = COCKPIT_KIND_NAMES[Number(r.kind)] || `kind_${r.kind}`;
      consKindMinutes[kindName] = (consKindMinutes[kindName] || 0) + mins;
      const e = (consByEmp[r.employeeId] ||= { employeeId: r.employeeId, minutes: 0, slots: 0 });
      e.minutes += mins;
      e.slots += 1;
    }

    const workByEmp = {};
    let workTotalMinutes = 0, workBreakMinutes = 0;
    for (const r of work) {
      const mins = parseFloat(r.minutes) || 0;
      workTotalMinutes += mins;
      workBreakMinutes += r.breakMin || 0;
      const e = (workByEmp[r.employeeId] ||= { employeeId: r.employeeId, minutes: 0, breakMinutes: 0, slots: 0 });
      e.minutes += mins;
      e.breakMinutes += r.breakMin || 0;
      e.slots += 1;
    }

    const employees = {};
    for (const id of Object.keys(consByEmp)) (employees[id] ||= { employeeId: parseInt(id, 10), consultationMinutes: 0, workMinutes: 0, workBreakMinutes: 0 }).consultationMinutes = consByEmp[id].minutes;
    for (const id of Object.keys(workByEmp)) {
      const e = (employees[id] ||= { employeeId: parseInt(id, 10), consultationMinutes: 0, workMinutes: 0, workBreakMinutes: 0 });
      e.workMinutes = workByEmp[id].minutes;
      e.workBreakMinutes = workByEmp[id].breakMinutes;
    }
    const employeeRows = Object.values(employees).sort((a, b) => b.workMinutes - a.workMinutes);

    const activePdes = pdes.filter(p => p.is_active).length;

    const blIdx = p.bundeslandCode === null || p.bundeslandCode === undefined ? null : Number(p.bundeslandCode);
    res.json({
      praxisId: lcId,
      praxisName: p.name,
      bundesland: blIdx === null ? null : (BUNDESLAND_CODES[blIdx] || null),
      currentIsoYear: cy,
      currentIsoWeek: cw,
      summary: {
        consultationMinutes: Math.round(consTotalMinutes),
        consultationBookableMinutes: Math.round(consBookableMinutes),
        consultationKindMinutes: Object.fromEntries(Object.entries(consKindMinutes).map(([k, v]) => [k, Math.round(v)])),
        workMinutes: Math.round(workTotalMinutes),
        workBreakMinutes: Math.round(workBreakMinutes),
        employeeCount: employeeRows.length,
        overrideCount: overrides.length,
        versionCount: versions.length,
        matrixEntries: matrix.length,
        activePdeCount: activePdes,
        totalPdeCount: pdes.length,
      },
      employees: employeeRows,
      overrides: overrides.map(r => ({
        isoYear: r.isoYear,
        isoWeek: r.isoWeek,
        hasOpening: r.has_opening,
        hasConsultation: r.has_consultation,
        hasWork: r.has_work,
        hasMfaGeneric: r.has_mfa_generic,
        modifiedAt: r.modifiedAt,
      })),
      versions: versions.map(r => ({
        validFromIsoYear: r.validFromIsoYear,
        validFromIsoWeek: r.validFromIsoWeek,
        hasOpening: r.has_opening,
        hasConsultation: r.has_consultation,
        hasWork: r.has_work,
        hasMfaGeneric: r.has_mfa_generic,
        createdBy: r.createdBy,
        createdAt: r.createdAt,
      })),
      pdes: pdes.map(r => ({
        id: r.id,
        employeeId: r.employeeId,
        kind: COCKPIT_KIND_NAMES[Number(r.kind)] || `kind_${r.kind}`,
        day: COCKPIT_DAY_NAMES[Number(r.day)] || `day_${r.day}`,
        start: r.start,
        end: r.end,
        validFromIsoYear: r.validFromIsoYear,
        validFromIsoWeek: r.validFromIsoWeek,
        validUntilIsoYear: r.validUntilIsoYear,
        validUntilIsoWeek: r.validUntilIsoWeek,
        note: r.note,
        isActive: r.is_active,
      })),
      matrix: matrix.map(r => ({
        appointmentTypeKey: r.appointmentTypeKey,
        providers: r.providers || [],
        modifiedAt: r.modifiedAt,
      })),
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ─── Routes: Message Outbox (Brevo email/SMS durable queue) ───────────────────
const OUTBOX_CHANNELS = ['email', 'sms'];
const OUTBOX_STATUSES = ['pending', 'sending', 'sent', 'failed', 'dead'];
const OUTBOX_ERROR_CLASSES = ['permanent', 'transient'];

app.get('/api/message-outbox', async (req, res) => {
  try {
    const { status, channel, dateFrom, dateTo, correlationId, recipient, lastHttpStatus, lastErrorClass, page = 1, pageSize = 50 } = req.query;
    const filters = [];
    if (status) {
      const list = String(status).split(',').map(s => s.trim()).filter(Boolean);
      const idxs = list.map(s => OUTBOX_STATUSES.indexOf(s)).filter(i => i >= 0);
      if (idxs.length) filters.push(['status', '= ANY', idxs]);
    }
    if (channel) {
      const idx = OUTBOX_CHANNELS.indexOf(String(channel));
      if (idx >= 0) filters.push(['channel', '=', idx]);
    }
    if (lastErrorClass) {
      const idx = OUTBOX_ERROR_CLASSES.indexOf(String(lastErrorClass));
      if (idx >= 0) filters.push(['"lastErrorClass"', '=', idx]);
    }
    if (dateFrom) filters.push(['"createdAt"', '>=', dateFrom]);
    if (dateTo) filters.push(['"createdAt"', '<=', dateTo]);
    if (correlationId) filters.push(['"correlationId"', 'ILIKE', `%${correlationId}%`]);
    if (recipient) filters.push(['payload', 'ILIKE', `%${recipient}%`]);
    if (lastHttpStatus) filters.push(['"lastHttpStatus"', '=', parseInt(lastHttpStatus)]);

    const clauses = [];
    const params = [];
    for (const [col, op, val] of filters) {
      if (val === null || val === undefined || val === '') continue;
      if (Array.isArray(val) && val.length === 0) continue;
      params.push(val);
      if (op === '= ANY') {
        clauses.push(`${col} = ANY($${params.length}::int[])`);
      } else {
        clauses.push(`${col} ${op} $${params.length}`);
      }
    }
    const where = clauses.length ? 'WHERE ' + clauses.join(' AND ') : '';
    const baseSql = `SELECT id, channel, status, "attemptCount", "maxAttempts", "lastHttpStatus", "lastErrorClass", "nextAttemptAt", "firstTeamsNotifiedAt", "correlationId", "createdAt", "updatedAt", "sentAt", "deadAt" FROM core_message_outbox ${where} ORDER BY "createdAt" DESC`;
    const countSql = `SELECT COUNT(*) FROM core_message_outbox ${where}`;
    const result = await paginate(req, baseSql, countSql, params, parseInt(page), parseInt(pageSize));

    result.rows = result.rows.map(r => ({
      ...r,
      channel: OUTBOX_CHANNELS[r.channel] ?? r.channel,
      status: OUTBOX_STATUSES[r.status] ?? r.status,
      lastErrorClass: r.lastErrorClass === null ? null : (OUTBOX_ERROR_CLASSES[r.lastErrorClass] ?? r.lastErrorClass),
    }));

    res.json(result);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/message-outbox/stats', async (req, res) => {
  try {
    const rows = await query(
      req,
      `SELECT channel, status, COUNT(*)::int AS count
       FROM core_message_outbox
       WHERE "createdAt" > NOW() - INTERVAL '30 days'
       GROUP BY channel, status`
    );
    const sentLast24hRows = await query(
      req,
      `SELECT channel, COUNT(*)::int AS count
       FROM core_message_outbox
       WHERE status = 2 AND "sentAt" > NOW() - INTERVAL '24 hours'
       GROUP BY channel`
    );

    const stats = {};
    for (const ch of OUTBOX_CHANNELS) {
      stats[ch] = { pending: 0, sending: 0, sent: 0, failed: 0, dead: 0, sentLast24h: 0 };
    }
    for (const r of rows) {
      const ch = OUTBOX_CHANNELS[r.channel];
      const st = OUTBOX_STATUSES[r.status];
      if (ch && st && stats[ch]) stats[ch][st] = r.count;
    }
    for (const r of sentLast24hRows) {
      const ch = OUTBOX_CHANNELS[r.channel];
      if (ch && stats[ch]) stats[ch].sentLast24h = r.count;
    }
    res.json(stats);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/message-outbox/:id', async (req, res) => {
  try {
    const rows = await query(
      req,
      `SELECT * FROM core_message_outbox WHERE id = $1`,
      [req.params.id]
    );
    if (!rows.length) return res.status(404).json({ error: 'Not found' });
    const r = rows[0];
    let decodedPayload = null;
    try { decodedPayload = JSON.parse(r.payload); } catch { decodedPayload = r.payload; }
    res.json({
      ...r,
      channel: OUTBOX_CHANNELS[r.channel] ?? r.channel,
      status: OUTBOX_STATUSES[r.status] ?? r.status,
      lastErrorClass: r.lastErrorClass === null ? null : (OUTBOX_ERROR_CLASSES[r.lastErrorClass] ?? r.lastErrorClass),
      decodedPayload,
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/message-outbox/:id/retry', async (req, res) => {
  try {
    const id = req.params.id;
    const existing = await query(req, `SELECT id FROM core_message_outbox WHERE id = $1`, [id]);
    if (!existing.length) return res.status(404).json({ error: 'Not found' });

    await query(
      req,
      `UPDATE core_message_outbox
       SET status = 0, "nextAttemptAt" = NOW(), "attemptCount" = 0, "firstTeamsNotifiedAt" = NULL, "updatedAt" = NOW()
       WHERE id = $1`,
      [id]
    );

    const identifier = `messageOutbox_${id}_manual_${Date.now()}`;
    const payload = JSON.stringify({ outboxId: id });
    await query(
      req,
      `INSERT INTO serverpod_future_call (name, "time", "serializedObject", "serverId", identifier)
       VALUES ($1, NOW(), $2, 'helper', $3)`,
      ['messageOutboxDispatchFutureCall', payload, identifier]
    );

    const updated = await query(req, `SELECT * FROM core_message_outbox WHERE id = $1`, [id]);
    const r = updated[0];
    res.json({
      ok: true,
      row: {
        ...r,
        channel: OUTBOX_CHANNELS[r.channel] ?? r.channel,
        status: OUTBOX_STATUSES[r.status] ?? r.status,
      },
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/message-outbox/:id/kill', async (req, res) => {
  try {
    const id = req.params.id;
    const existing = await query(req, `SELECT id FROM core_message_outbox WHERE id = $1`, [id]);
    if (!existing.length) return res.status(404).json({ error: 'Not found' });

    const killMsg = `killed by operator at ${new Date().toISOString()}`;
    await query(
      req,
      `UPDATE core_message_outbox
       SET status = 4, "deadAt" = NOW(), "lastErrorClass" = 0, "lastErrorBody" = $1, "updatedAt" = NOW()
       WHERE id = $2`,
      [killMsg, id]
    );
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ─── Routes: Brevo email resend (manual replay from session-log payloads) ────
app.post('/api/email/resend', async (req, res) => {
  const key = process.env.BREVO_API_KEY;
  if (!key) {
    return res.status(500).json({ error: 'BREVO_API_KEY is not set in helper/.env' });
  }
  const payload = req.body;
  if (!payload || typeof payload !== 'object') {
    return res.status(400).json({ error: 'Body must be the parsed Brevo payload (JSON object).' });
  }
  try {
    const r = await fetch('https://api.brevo.com/v3/smtp/email', {
      method: 'POST',
      headers: {
        'api-key': key,
        'content-type': 'application/json',
        accept: 'application/json',
      },
      body: JSON.stringify(payload),
    });
    const text = await r.text();
    let parsed;
    try { parsed = JSON.parse(text); } catch (_) { parsed = { raw: text }; }
    if (!r.ok) {
      return res.status(r.status).json({ error: `Brevo ${r.status}`, brevo: parsed });
    }
    res.json({ ok: true, status: r.status, brevo: parsed });
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

// ─── Routes: monitoring – alarm reset ────────────────────────────────────────
app.post('/api/monitor/alarms/:name/reset', async (req, res) => {
  try {
    await cloudwatchClient.send(new SetAlarmStateCommand({
      AlarmName: req.params.name,
      StateValue: 'OK',
      StateReason: 'Manually reset from LC Monitor',
    }));
    res.json({ ok: true });
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

// ─── Routes: monitoring – slow endpoints ─────────────────────────────────────
app.get('/api/monitor/errors/slow', async (req, res) => {
  try {
    const [totalRow, topSlow, slowest] = await Promise.all([
      query(req, `SELECT COUNT(*)::int AS count FROM serverpod_session_log WHERE slow = true AND "time" > NOW() - INTERVAL '24 hours'`),
      query(req, `
        SELECT COALESCE(endpoint, 'unknown') AS endpoint,
               COUNT(*)::int AS count,
               ROUND((AVG(duration) * 1000)::numeric, 0) AS "avgMs",
               ROUND((MAX(duration) * 1000)::numeric, 0) AS "maxMs"
        FROM serverpod_session_log
        WHERE slow = true AND "time" > NOW() - INTERVAL '24 hours'
        GROUP BY endpoint ORDER BY "avgMs" DESC LIMIT 10
      `),
      query(req, `
        SELECT id, "time", endpoint, method, duration, "numQueries"
        FROM serverpod_session_log
        WHERE slow = true AND "time" > NOW() - INTERVAL '24 hours'
        ORDER BY duration DESC LIMIT 20
      `),
    ]);
    res.json({ total: totalRow[0]?.count || 0, topSlow, slowest });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ─── Routes: monitoring – long-lived sessions ────────────────────────────────
app.get('/api/monitor/errors/longlived', async (req, res) => {
  try {
    const [topEndpoints, openConnections] = await Promise.all([
      query(req, `
        SELECT endpoint, COALESCE(method, '') AS method,
               COUNT(*)::int AS count,
               ROUND((AVG(duration) * 1000)::numeric, 0) AS "avgMs",
               ROUND((MAX(duration) * 1000)::numeric, 0) AS "maxMs"
        FROM serverpod_session_log
        WHERE "time" > NOW() - INTERVAL '24 hours'
          AND duration IS NOT NULL AND "isOpen" = false
        GROUP BY endpoint, method
        ORDER BY "avgMs" DESC LIMIT 15
      `),
      query(req, `
        SELECT id, "time", endpoint, method,
               ROUND(EXTRACT(EPOCH FROM (NOW() - "time"))::numeric, 0) AS "openSeconds",
               "authenticatedUserId"
        FROM serverpod_session_log
        WHERE "isOpen" = true
        ORDER BY "time" ASC LIMIT 100
      `),
    ]);
    res.json({ topEndpoints, openConnections });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ─── Routes: report – error report generator ─────────────────────────────────
app.post('/api/report/errors', async (req, res) => {
  try {
    const { range = 'day', date, dbHost, dbPort, dbName, dbUser, dbPassword } = req.body;
    if (!date) return res.status(400).json({ error: 'date is required (YYYY-MM-DD)' });

    // Allow credentials from body (used by form POST) as fallback to headers
    if (dbHost) req.headers['x-db-host'] = dbHost;
    if (dbPort) req.headers['x-db-port'] = String(dbPort);
    if (dbName) req.headers['x-db-name'] = dbName;
    if (dbUser) req.headers['x-db-user'] = dbUser;
    if (dbPassword) req.headers['x-db-password'] = dbPassword;

    // Compute Berlin-timezone date boundaries — `date` is always the END date
    const berlinOffset = '+02:00'; // close enough; actual DST handled by AT TIME ZONE in SQL
    const endDate = new Date(`${date}T23:59:59.999${berlinOffset}`);
    let startDate;
    if (range === 'day')         startDate = new Date(`${date}T00:00:00${berlinOffset}`);
    else if (range === 'week')   { startDate = new Date(endDate); startDate.setDate(startDate.getDate() - 6); startDate.setHours(0, 0, 0, 0); }
    else if (range === '2weeks') { startDate = new Date(endDate); startDate.setDate(startDate.getDate() - 13); startDate.setHours(0, 0, 0, 0); }
    else return res.status(400).json({ error: 'range must be day, week, or 2weeks' });

    const isMultiDay = range !== 'day';
    const timeBucket = isMultiDay
      ? `date_trunc('day', "time" AT TIME ZONE 'Europe/Berlin')`
      : `date_trunc('hour', "time")`;

    const [timeSeries, topEndpoints, totalRow, sampleErrors, topSlow, slowTotalRow, longLived] = await Promise.all([
      query(req, `
        SELECT ${timeBucket} AS bucket, COUNT(*)::int AS count
        FROM serverpod_session_log
        WHERE "time" >= $1 AND "time" < $2 AND error IS NOT NULL
        GROUP BY 1 ORDER BY 1 ASC
      `, [startDate, endDate]),
      query(req, `
        SELECT COALESCE(endpoint, 'unknown') AS endpoint, COUNT(*)::int AS count
        FROM serverpod_session_log
        WHERE error IS NOT NULL AND "time" >= $1 AND "time" < $2
        GROUP BY endpoint ORDER BY count DESC LIMIT 15
      `, [startDate, endDate]),
      query(req, `SELECT COUNT(*)::int AS count FROM serverpod_session_log WHERE error IS NOT NULL AND "time" >= $1 AND "time" < $2`, [startDate, endDate]),
      isMultiDay
        ? query(req, `
            SELECT DISTINCT ON (LEFT(error, 100)) id, "time", endpoint, method, duration, error, "stackTrace"
            FROM serverpod_session_log
            WHERE error IS NOT NULL AND "time" >= $1 AND "time" < $2
            ORDER BY LEFT(error, 100), "time" DESC
            LIMIT 30
          `, [startDate, endDate])
        : query(req, `
            SELECT id, "time", endpoint, method, duration, error, "stackTrace"
            FROM serverpod_session_log
            WHERE error IS NOT NULL AND "time" >= $1 AND "time" < $2
            ORDER BY "time" DESC LIMIT 50
          `, [startDate, endDate]),
      query(req, `
        SELECT COALESCE(endpoint, 'unknown') AS endpoint,
               COUNT(*)::int AS count,
               ROUND((AVG(duration) * 1000)::numeric, 0) AS "avgMs",
               ROUND((MAX(duration) * 1000)::numeric, 0) AS "maxMs"
        FROM serverpod_session_log
        WHERE slow = true AND "time" >= $1 AND "time" < $2
        GROUP BY endpoint ORDER BY "avgMs" DESC LIMIT 15
      `, [startDate, endDate]),
      query(req, `SELECT COUNT(*)::int AS count FROM serverpod_session_log WHERE slow = true AND "time" >= $1 AND "time" < $2`, [startDate, endDate]),
      query(req, `
        SELECT endpoint, COALESCE(method, '') AS method,
               COUNT(*)::int AS count,
               ROUND((AVG(duration) * 1000)::numeric, 0) AS "avgMs",
               ROUND((MAX(duration) * 1000)::numeric, 0) AS "maxMs"
        FROM serverpod_session_log
        WHERE "time" >= $1 AND "time" < $2
          AND duration IS NOT NULL AND "isOpen" = false
        GROUP BY endpoint, method
        ORDER BY "avgMs" DESC LIMIT 15
      `, [startDate, endDate]),
    ]);

    const totalErrors = totalRow[0]?.count || 0;
    const totalSlow = slowTotalRow[0]?.count || 0;
    const peakBucket = timeSeries.reduce((a, b) => (b.count > (a?.count || 0) ? b : a), null);
    const peakLabel = peakBucket ? (isMultiDay
      ? new Date(peakBucket.bucket).toLocaleDateString('de-DE', { day: '2-digit', month: '2-digit', timeZone: 'Europe/Berlin' })
      : `${String(new Date(peakBucket.bucket).getHours()).padStart(2, '0')}:00`) : '—';

    const startDateStr = startDate.toISOString().slice(0, 10);
    const rangeLabel = range === 'day' ? date : `${startDateStr} → ${date} (${range === 'week' ? '7' : '14'} days)`;

    // Build Bedrock prompt (only aggregates + sample messages — no full stack traces)
    const errorSummaryForAI = [
      `Period: ${rangeLabel}`,
      `Total errors: ${totalErrors}`,
      `Total slow sessions: ${totalSlow}`,
      `Peak: ${peakLabel} with ${peakBucket?.count || 0} errors`,
      `Top error endpoints: ${topEndpoints.slice(0, 8).map(e => `${e.endpoint}(${e.count})`).join(', ')}`,
      `Slow endpoint summaries: ${topSlow.slice(0, 5).map(e => `${e.endpoint} avg=${e.avgMs}ms max=${e.maxMs}ms`).join(', ')}`,
      `Sample error messages (first line only):`,
      ...sampleErrors.slice(0, 10).map(e => {
        const msg = (e.error || '').split('\n')[0].substring(0, 120)
          .replace(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g, '[email]')  // emails
          .replace(/\b\d{5,}\b/g, '[id]')   // numeric IDs (5+ digits)
          .replace(/\+?\d[\d\s\-().]{7,}\d/g, '[phone]');  // phone numbers
        return `  [${e.endpoint || 'unknown'}] ${msg}`;
      }),
    ].join('\n');

    let aiSummary = '(AI analysis unavailable)';
    try {
      const aiRes = await bedrockClient.send(new ConverseCommand({
        modelId: 'eu.anthropic.claude-sonnet-4-5-20250929-v1:0',
        system: [{ text: 'You are a DevOps engineer analyzing server errors and performance issues for the LillianCare healthcare platform. Summarize the errors, identify patterns and root causes, analyze slow endpoints, and give concise actionable recommendations. Use markdown-style sections: **Summary**, **Error Patterns**, **Performance Issues**, **Recommendations**. Be specific and brief.' }],
        messages: [{ role: 'user', content: [{ text: errorSummaryForAI }] }],
        inferenceConfig: { maxTokens: 1500, temperature: 0.2 },
      }));
      aiSummary = aiRes.output.message.content[0].text.trim();
    } catch (bedrockErr) {
      aiSummary = `(AI analysis failed: ${bedrockErr.message})`;
    }

    // Convert markdown to HTML
    const mdToHtml = md => {
      const esc2 = s => s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
      const inline = s => s
        .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
        .replace(/\*(.+?)\*/g, '<em>$1</em>')
        .replace(/`([^`]+)`/g, '<code style="background:var(--primary-fixed);padding:1px 4px;border-radius:3px;font-size:12px">$1</code>');

      const lines = md.split('\n');
      let html = '', inList = false, inOl = false, inTable = false;

      for (let i = 0; i < lines.length; i++) {
        const l = lines[i];
        const trimmed = l.trim();

        // Table
        if (trimmed.startsWith('|')) {
          if (!inTable) { html += '<table style="width:100%;border-collapse:collapse;font-size:12px;margin:8px 0">'; inTable = true; }
          if (trimmed.replace(/[|\s-]/g, '') === '') continue; // separator row
          const cells = trimmed.split('|').filter((_,i,a) => i > 0 && i < a.length-1);
          const isHeader = lines[i-1]?.trim().startsWith('|') === false || i === 0;
          const tag = (i < lines.length-1 && lines[i+1]?.trim().replace(/[|\s-]/g,'') === '') ? 'th' : 'td';
          html += `<tr>${cells.map(c => `<${tag} style="padding:5px 8px;border:1px solid var(--outline-variant);text-align:left">${inline(c.trim())}</${tag}>`).join('')}</tr>`;
          continue;
        } else if (inTable) { html += '</table>'; inTable = false; }

        // Close lists
        if (inList && !trimmed.match(/^[-•*]\s/)) { html += '</ul>'; inList = false; }
        if (inOl && !trimmed.match(/^\d+\.\s/)) { html += '</ol>'; inOl = false; }

        if (!trimmed) continue;

        if (trimmed.match(/^#{1,3}\s/)) {
          const level = trimmed.match(/^#+/)[0].length;
          const text = trimmed.replace(/^#+\s*/, '');
          const sizes = ['15px','13px','12px'];
          html += `<div style="font-size:${sizes[level-1]||'12px'};font-weight:700;color:var(--primary);margin:${level===1?'12px':'8px'} 0 4px">${inline(esc2(text))}</div>`;
        } else if (trimmed.match(/^[-•*]\s/)) {
          if (!inList) { html += '<ul style="margin:4px 0;padding-left:18px">'; inList = true; }
          html += `<li style="margin:2px 0;color:var(--on-surface)">${inline(esc2(trimmed.replace(/^[-•*]\s*/,'')))}</li>`;
        } else if (trimmed.match(/^\d+\.\s/)) {
          if (!inOl) { html += '<ol style="margin:4px 0;padding-left:18px">'; inOl = true; }
          html += `<li style="margin:2px 0;color:var(--on-surface)">${inline(esc2(trimmed.replace(/^\d+\.\s*/,'')))}</li>`;
        } else {
          html += `<p style="margin:4px 0;color:var(--on-surface)">${inline(esc2(trimmed))}</p>`;
        }
      }
      if (inList) html += '</ul>';
      if (inOl) html += '</ol>';
      if (inTable) html += '</table>';
      return html;
    };
    const aiHtml = mdToHtml(aiSummary);

    // Chart data — single day: fill all 24 hours; multi-day: one point per day
    let chartLabels, chartValues;
    if (isMultiDay) {
      chartLabels = timeSeries.map(r => new Date(r.bucket).toLocaleDateString('de-DE', { day: '2-digit', month: '2-digit', timeZone: 'Europe/Berlin' }));
      chartValues = timeSeries.map(r => r.count);
    } else {
      const countByHour = {};
      for (const r of timeSeries) countByHour[new Date(r.bucket).getUTCHours()] = r.count;
      chartLabels = Array.from({ length: 24 }, (_, h) => String(h).padStart(2, '0') + ':00');
      chartValues = Array.from({ length: 24 }, (_, h) => countByHour[h] || 0);
    }

    const envLabel = (req.headers['x-db-host'] || 'unknown').split('.')[0];

    const escH = s => String(s || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
    const dur = secs => { if (secs == null) return '—'; const ms = secs * 1000; return fmtMs(ms); };
    const fmtMs = ms => { if (ms == null) return '—'; if (ms >= 3600000) return `${(ms/3600000).toFixed(1)}h`; if (ms >= 60000) return `${(ms/60000).toFixed(1)}m`; if (ms >= 1000) return `${(ms/1000).toFixed(1)}s`; return `${Math.round(ms)}ms`; };

    const html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>LillianCare Error Report — ${escH(rangeLabel)}</title>
<style>
  :root {
    --primary: #3525cd;
    --primary-container: #4f46e5;
    --primary-fixed: #e2dfff;
    --on-primary: #ffffff;
    --surface: #f9f9f9;
    --surface-container-lowest: #ffffff;
    --surface-container-low: #f3f3f3;
    --surface-container: #eeeeee;
    --on-surface: #1a1c1c;
    --on-surface-variant: #464555;
    --outline: #777587;
    --outline-variant: #c7c4d8;
    --error: #ba1a1a;
    --error-container: #ffdad6;
    --on-error-container: #93000a;
    --success: #16a34a;
    --warning: #d97706;
    --badge-amber-bg: rgba(215,119,6,0.12);
    --badge-amber-text: #92400e;
    --sidebar-bg: #0f1a2e;
    --font-ui: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    --font-mono: 'JetBrains Mono', 'SF Mono', monospace;
    --shadow-card: 0 2px 8px rgba(26,28,28,0.05);
    --radius-default: 0.5rem;
    --radius-md: 0.75rem;
  }
  *, *::before, *::after { box-sizing: border-box; }
  body { font-family: var(--font-ui); background: var(--surface); color: var(--on-surface); margin: 0; padding: 24px; font-size: 14px; line-height: 1.5; }
  .wrapper { max-width: 860px; margin: 0 auto; }
  .hdr { background: linear-gradient(135deg, var(--sidebar-bg) 0%, #1a2d4a 100%); color: #e8f0fe; padding: 28px 32px; border-radius: var(--radius-md) var(--radius-md) 0 0; }
  .hdr h1 { margin: 0 0 4px; font-size: 22px; font-weight: 700; letter-spacing: -0.3px; }
  .hdr .sub { font-size: 12px; color: rgba(232,240,254,0.55); margin: 0; }
  .hdr .env-badge { display: inline-block; background: rgba(79,70,229,0.2); color: var(--primary-fixed); border: 1px solid rgba(79,70,229,0.4); border-radius: var(--radius-default); padding: 2px 8px; font-size: 11px; font-weight: 600; margin-left: 10px; vertical-align: middle; text-transform: uppercase; letter-spacing: 1px; }
  .body { background: var(--surface-container-lowest); border-radius: 0 0 var(--radius-md) var(--radius-md); padding: 28px 32px; }
  .stats-row { display: flex; gap: 14px; margin-bottom: 28px; flex-wrap: wrap; }
  .stat { flex: 1; min-width: 120px; background: var(--surface-container-low); border: 1px solid var(--outline-variant); border-radius: var(--radius-default); padding: 14px 16px; text-align: center; }
  .stat .val { font-size: 28px; font-weight: 700; line-height: 1; margin-bottom: 4px; font-family: var(--font-mono); }
  .stat .lbl { font-size: 11px; color: var(--on-surface-variant); text-transform: uppercase; letter-spacing: 0.5px; }
  .val-red { color: var(--error); }
  .val-amber { color: var(--warning); }
  .val-blue { color: var(--primary-container); }
  .val-green { color: var(--success); }
  section { margin-bottom: 28px; }
  h2 { font-size: 13px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.8px; color: var(--on-surface-variant); margin: 0 0 12px; padding-bottom: 6px; border-bottom: 1px solid var(--outline-variant); }
  .ai-box { background: linear-gradient(135deg, var(--primary-fixed) 0%, #fafcff 100%); border: 1px solid rgba(79,70,229,0.2); border-radius: var(--radius-default); padding: 18px 20px; color: var(--on-surface); }
  .ai-box strong { color: var(--primary); }
  .ai-box li { color: var(--on-surface); }
  table { width: 100%; border-collapse: collapse; font-size: 13px; }
  th { text-align: left; padding: 8px 12px; background: var(--surface-container-low); color: var(--on-surface-variant); font-weight: 600; font-size: 11px; text-transform: uppercase; letter-spacing: 0.5px; border-bottom: 1px solid var(--outline-variant); }
  td { padding: 8px 12px; border-bottom: 1px solid var(--surface-container-low); vertical-align: top; }
  tr:last-child td { border-bottom: none; }
  tr:hover td { background: var(--surface-container-low); }
  .badge { display: inline-block; padding: 2px 7px; border-radius: 9999px; font-size: 11px; font-weight: 600; }
  .badge-red { background: var(--error-container); color: var(--on-error-container); }
  .badge-amber { background: var(--badge-amber-bg); color: var(--badge-amber-text); }
  .err-row { margin-bottom: 10px; background: var(--surface-container-lowest); border: 1px solid var(--outline-variant); border-radius: var(--radius-default); overflow: hidden; }
  .err-row-hdr { display: flex; gap: 12px; align-items: baseline; padding: 8px 12px; background: var(--surface-container-low); flex-wrap: wrap; }
  .err-time { font-size: 11px; color: var(--outline); font-family: var(--font-mono); }
  .err-ep { font-weight: 600; color: var(--primary-container); font-size: 12px; }
  .err-dur { font-size: 11px; color: var(--on-surface-variant); }
  .err-msg { padding: 6px 12px; font-family: var(--font-mono); font-size: 12px; color: var(--error); background: var(--surface-container-lowest); white-space: pre-wrap; word-break: break-all; }
  .err-stack { padding: 6px 12px 10px; font-family: var(--font-mono); font-size: 11px; color: var(--outline); background: var(--surface-container-lowest); white-space: pre-wrap; word-break: break-all; display: none; border-top: 1px solid var(--surface-container-low); }
  .toggle-stack { font-size: 11px; color: var(--primary-container); cursor: pointer; padding: 2px 12px 6px; display: block; background: var(--surface-container-lowest); border: none; text-align: left; }
  canvas { max-width: 100%; border-radius: var(--radius-default); }
  .chart-wrap { background: var(--surface-container-low); border: 1px solid var(--outline-variant); border-radius: var(--radius-default); padding: 16px; }
  .footer { margin-top: 24px; text-align: center; font-size: 11px; color: var(--outline); }
  @media (max-width: 600px) { body { padding: 12px; } .hdr, .body { padding: 18px; } .stats-row { gap: 10px; } }
</style>
</head>
<body>
<div class="wrapper">
  <div class="hdr">
    <h1>LillianCare Error Report <span class="env-badge">${escH(envLabel)}</span></h1>
    <p class="sub">Period: ${escH(rangeLabel)} &nbsp;·&nbsp; Generated: ${new Date().toLocaleString('de-DE', { timeZone: 'Europe/Berlin' })}</p>
  </div>
  <div class="body">
    <div class="stats-row">
      <div class="stat"><div class="val val-red">${totalErrors}</div><div class="lbl">Total Errors</div></div>
      <div class="stat"><div class="val val-amber">${topEndpoints.length}</div><div class="lbl">Error Endpoints</div></div>
      <div class="stat"><div class="val val-blue">${peakBucket?.count || 0}</div><div class="lbl">Peak ${isMultiDay ? 'Day' : 'Hour'} (${escH(peakLabel)})</div></div>
      <div class="stat"><div class="val val-amber">${totalSlow}</div><div class="lbl">Slow Sessions</div></div>
      <div class="stat"><div class="val val-blue">${longLived.length}</div><div class="lbl">Long-lived Endpoints</div></div>
    </div>

    <section>
      <h2>Error Trend — ${isMultiDay ? 'Daily' : 'Hourly'}</h2>
      <div class="chart-wrap"><canvas id="trendChart" height="120"></canvas></div>
      <table style="margin-top:12px">
        <thead><tr><th>${isMultiDay ? 'Date' : 'Hour'}</th><th>Errors</th></tr></thead>
        <tbody>${timeSeries.map((r, i) => `<tr><td>${escH(chartLabels[i])}</td><td>${r.count}</td></tr>`).join('')}</tbody>
      </table>
    </section>

    <section>
      <h2>AI Analysis</h2>
      <div class="ai-box">${aiHtml}</div>
      <details style="margin-top:10px">
        <summary style="cursor:pointer;font-size:11px;color:var(--outline);user-select:none;padding:4px 0">▶ View exact data sent to AI (for PII review)</summary>
        <pre style="margin-top:8px;background:var(--surface-container-low);border:1px solid var(--outline-variant);border-radius:var(--radius-default);padding:14px;font-size:11px;color:var(--on-surface-variant);white-space:pre-wrap;word-break:break-all;line-height:1.6">${escH(errorSummaryForAI)}</pre>
      </details>
    </section>

    <section>
      <h2>Top Error Endpoints</h2>
      <table>
        <thead><tr><th>Endpoint</th><th style="text-align:right">Errors</th></tr></thead>
        <tbody>${topEndpoints.map(e => `<tr><td>${escH(e.endpoint)}</td><td style="text-align:right"><span class="badge badge-red">${e.count}</span></td></tr>`).join('')}</tbody>
      </table>
    </section>

    ${topSlow.length ? `
    <section>
      <h2>Slow Sessions by Endpoint</h2>
      <div class="chart-wrap" style="margin-bottom:12px"><canvas id="slowChart" height="${Math.max(60, topSlow.length * 28)}"></canvas></div>
      <table>
        <thead><tr><th>Endpoint</th><th style="text-align:right">Count</th><th style="text-align:right">Avg</th><th style="text-align:right">Max</th></tr></thead>
        <tbody>${topSlow.map(e => `<tr><td>${escH(e.endpoint)}</td><td style="text-align:right">${e.count}</td><td style="text-align:right">${escH(fmtMs(e.avgMs))}</td><td style="text-align:right"><span class="badge badge-amber">${escH(fmtMs(e.maxMs))}</span></td></tr>`).join('')}</tbody>
      </table>
    </section>` : ''}

    ${longLived.length ? `
    <section>
      <h2>Long-lived Sessions by Endpoint</h2>
      <p style="font-size:12px;color:var(--on-surface-variant);margin:-4px 0 12px">Completed sessions sorted by average duration. WebSocket/streaming endpoints like <code>listenForQuestionnaires</code> will appear here — high duration is expected for these.</p>
      <table>
        <thead><tr><th>Endpoint</th><th>Method</th><th style="text-align:right">Count</th><th style="text-align:right">Avg Duration</th><th style="text-align:right">Max Duration</th></tr></thead>
        <tbody>${longLived.map(e => `<tr>
          <td>${escH(e.endpoint || 'unknown')}</td>
          <td style="color:var(--on-surface-variant);font-size:12px">${escH(e.method)}</td>
          <td style="text-align:right">${e.count}</td>
          <td style="text-align:right"><span class="badge badge-amber">${escH(fmtMs(e.avgMs))}</span></td>
          <td style="text-align:right">${escH(fmtMs(e.maxMs))}</td>
        </tr>`).join('')}</tbody>
      </table>
    </section>` : ''}

    <section>
      <h2>Error Details (${sampleErrors.length} sample${isMultiDay ? 's — distinct error types' : 's'})</h2>
      ${sampleErrors.map(e => `
      <div class="err-row">
        <div class="err-row-hdr">
          <span class="err-time">${escH(e.time ? new Date(e.time).toLocaleString('de-DE', { timeZone: 'Europe/Berlin' }) : '')}</span>
          <span class="err-ep">${escH(e.endpoint || 'unknown')}${e.method ? '#' + escH(e.method) : ''}</span>
          <span class="err-dur">${dur(e.duration)}</span>
        </div>
        <div class="err-msg">${escH((e.error || '').split('\n')[0].substring(0, 200))}</div>
        ${e.stackTrace ? `<button class="toggle-stack" onclick="this.nextElementSibling.style.display=this.nextElementSibling.style.display==='block'?'none':'block';this.textContent=this.textContent==='▶ Show stack trace'?'▼ Hide stack trace':'▶ Show stack trace'">▶ Show stack trace</button><div class="err-stack">${escH((e.stackTrace || '').substring(0, 800))}</div>` : ''}
      </div>`).join('')}
    </section>

    <div class="footer">Generated by LC Monitor · ${new Date().toISOString()}</div>
  </div>
</div>

<script>
// Design token colors for canvas API (CSS vars don't work in canvas)
const C = {
  primary:     '#4f46e5',
  primaryFill: 'rgba(79,70,229,0.2)',
  outline:     '#777587',
  onSurface:   '#464555',
  onSurface2:  '#475569',
  barStart:    '#f97316',
  barEnd:      '#ef4444',
  white:       '#ffffff',
};

function drawCharts() {
  const labels = ${JSON.stringify(chartLabels)};
  const values = ${JSON.stringify(chartValues)};

  // Trend line chart
  const trendCanvas = document.getElementById('trendChart');
  if (trendCanvas && labels.length) {
    trendCanvas.width = (trendCanvas.parentElement.offsetWidth || 796) - 32;
    const ctx = trendCanvas.getContext('2d');
    const W = trendCanvas.width, H = trendCanvas.height;
    const maxV = Math.max(...values, 1);
    const padL = 40, padR = 16, padT = 16, padB = 28;
    const chartW = W - padL - padR, chartH = H - padT - padB;
    const step = chartW / Math.max(labels.length - 1, 1);

    ctx.clearRect(0, 0, W, H);

    // Grid lines
    ctx.strokeStyle = 'rgba(119,117,135,0.12)'; ctx.lineWidth = 1;
    for (let i = 0; i <= 4; i++) {
      const y = padT + chartH - (i / 4) * chartH;
      ctx.beginPath(); ctx.moveTo(padL, y); ctx.lineTo(W - padR, y); ctx.stroke();
      ctx.fillStyle = C.outline; ctx.font = '10px sans-serif'; ctx.textAlign = 'right';
      ctx.fillText(Math.round((i / 4) * maxV), padL - 4, y + 3);
    }

    // Filled area
    const grad = ctx.createLinearGradient(0, padT, 0, padT + chartH);
    grad.addColorStop(0, C.primaryFill);
    grad.addColorStop(1, 'rgba(79,70,229,0)');
    ctx.beginPath();
    values.forEach((v, i) => {
      const x = padL + i * step, y = padT + chartH - (v / maxV) * chartH;
      i === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y);
    });
    ctx.lineTo(padL + (values.length - 1) * step, padT + chartH);
    ctx.lineTo(padL, padT + chartH);
    ctx.closePath();
    ctx.fillStyle = grad; ctx.fill();

    // Line
    ctx.beginPath(); ctx.strokeStyle = C.primary; ctx.lineWidth = 2;
    values.forEach((v, i) => {
      const x = padL + i * step, y = padT + chartH - (v / maxV) * chartH;
      i === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y);
    });
    ctx.stroke();

    // Dots
    values.forEach((v, i) => {
      const x = padL + i * step, y = padT + chartH - (v / maxV) * chartH;
      ctx.beginPath(); ctx.arc(x, y, 3, 0, Math.PI * 2);
      ctx.fillStyle = C.primary; ctx.fill();
      ctx.fillStyle = C.white; ctx.beginPath(); ctx.arc(x, y, 1.5, 0, Math.PI * 2); ctx.fill();
    });

    // X labels (show max 12)
    ctx.fillStyle = C.outline; ctx.font = '10px sans-serif'; ctx.textAlign = 'center';
    const skip = Math.ceil(labels.length / 12);
    labels.forEach((l, i) => {
      if (i % skip === 0) ctx.fillText(l, padL + i * step, H - 4);
    });
  }

  // Slow endpoint horizontal bar chart
  const slowCanvas = document.getElementById('slowChart');
  const slowData = ${JSON.stringify(topSlow.slice(0, 10))};
  if (slowCanvas && slowData.length) {
    slowCanvas.width = (slowCanvas.parentElement.offsetWidth || 796) - 32;
    const ctx2 = slowCanvas.getContext('2d');
    const W = slowCanvas.width, H = slowCanvas.height;
    const maxAvg = Math.max(...slowData.map(d => d.avgMs), 1);
    const barH = Math.max(18, Math.floor((H - 8) / slowData.length) - 4);
    const padL = 140, padR = 60;

    ctx2.clearRect(0, 0, W, H);
    slowData.forEach((d, i) => {
      const y = 4 + i * (barH + 4);
      const barW = Math.max(2, ((d.avgMs / maxAvg) * (W - padL - padR)));

      // Label
      ctx2.fillStyle = C.onSurface; ctx2.font = '11px sans-serif'; ctx2.textAlign = 'right';
      const label = d.endpoint.length > 20 ? '...' + d.endpoint.slice(-18) : d.endpoint;
      ctx2.fillText(label, padL - 6, y + barH / 2 + 4);

      // Bar (avg)
      const grad2 = ctx2.createLinearGradient(padL, 0, padL + barW, 0);
      grad2.addColorStop(0, C.barStart);
      grad2.addColorStop(1, C.barEnd);
      ctx2.fillStyle = grad2;
      ctx2.beginPath();
      ctx2.roundRect ? ctx2.roundRect(padL, y, barW, barH, 3) : ctx2.rect(padL, y, barW, barH);
      ctx2.fill();

      // Value
      ctx2.fillStyle = C.onSurface2; ctx2.font = '11px sans-serif'; ctx2.textAlign = 'left';
      ctx2.fillText(d.avgMs + 'ms avg', padL + barW + 6, y + barH / 2 + 4);
    });
  }
}
// Run on load, then retry after 200ms in case offsetWidth was 0 (file:// URLs)
window.addEventListener('load', function() { drawCharts(); setTimeout(drawCharts, 200); });
</script>
</body>
</html>`;

    const filename = `lc-error-report-${rangeLabel.replace(/[^a-zA-Z0-9-]/g, '_')}.html`;
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    res.send(html);
  } catch (e) {
    res.status(500).json({ error: e.message });
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

  const heartbeat = setInterval(() => res.write(`data: ${JSON.stringify({ type: 'ping', ts: new Date().toISOString() })}\n\n`), 10000);

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

// ─── Routes: monitoring – endpoint health checks ─────────────────────────────
const HEALTH_ENDPOINTS = [
  { name: 'API',      env: 'production', url: 'https://api.lillian.care/' },
  { name: 'Insights', env: 'production', url: 'https://insights.lillian.care/' },
  { name: 'API',      env: 'staging',    url: 'https://api-staging.lillian.care/' },
  { name: 'Insights', env: 'staging',    url: 'https://insights-staging.lillian.care/' },
  { name: 'API',      env: 'test',       url: 'https://api-test.lillian.care/' },
  { name: 'Insights', env: 'test',       url: 'https://insights-test.lillian.care/' },
];
let endpointCache = null;

app.get('/api/monitor/endpoints/health', async (req, res) => {
  try {
    const now = Date.now();
    if (endpointCache && now - endpointCache.ts < 30000) return res.json(endpointCache.data);

    const results = await Promise.all(HEALTH_ENDPOINTS.map(async ep => {
      const start = Date.now();
      try {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), 5000);
        const r = await fetch(ep.url, { method: 'HEAD', signal: controller.signal, redirect: 'follow' });
        clearTimeout(timer);
        return { ...ep, ok: r.status < 500, status: r.status, latencyMs: Date.now() - start };
      } catch (e) {
        return { ...ep, ok: false, status: null, latencyMs: Date.now() - start, error: e.name === 'AbortError' ? 'timeout' : 'unreachable' };
      }
    }));

    endpointCache = { ts: now, data: { endpoints: results, checkedAt: new Date().toISOString() } };
    res.json(endpointCache.data);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ─── Google Business Profile (GBP) ────────────────────────────────────────────
// Manages OAuth2 with Google's Business Profile APIs and exposes a small REST
// surface the UI (and later the Dart backend) can call to list accounts/
// locations and edit regularHours. The flow is standard Authorization Code
// with offline access — tokens persist in a gitignored JSON file.
//
// APIs used:
//   - mybusinessaccountmanagement.googleapis.com/v1 → list accounts
//   - mybusinessbusinessinformation.googleapis.com/v1 → list locations, PATCH hours
//
// Setup: see .env.example for the GCP steps. Credentials must come from env:
//   GBP_CLIENT_ID, GBP_CLIENT_SECRET
const { OAuth2Client } = require('google-auth-library');

const GBP_TOKEN_PATH = path.join(__dirname, '.gbp_token.json');
const GBP_REDIRECT_URI = 'http://localhost:3333/api/gbp/oauth/callback';
const GBP_SCOPE = 'https://www.googleapis.com/auth/business.manage';
const GBP_DAYS = ['MONDAY','TUESDAY','WEDNESDAY','THURSDAY','FRIDAY','SATURDAY','SUNDAY'];

function gbpLoadToken() {
  try {
    if (!fs.existsSync(GBP_TOKEN_PATH)) return null;
    return JSON.parse(fs.readFileSync(GBP_TOKEN_PATH, 'utf8'));
  } catch { return null; }
}
function gbpSaveToken(tokens) {
  const existing = gbpLoadToken() || {};
  const merged = { ...existing, ...tokens };
  fs.writeFileSync(GBP_TOKEN_PATH, JSON.stringify(merged, null, 2), { mode: 0o600 });
}
function gbpClearToken() {
  if (fs.existsSync(GBP_TOKEN_PATH)) fs.unlinkSync(GBP_TOKEN_PATH);
}

function gbpClientConfigured() {
  return !!(process.env.GBP_CLIENT_ID && process.env.GBP_CLIENT_SECRET);
}

// Returns an OAuth2Client pre-loaded with any saved token. When the library
// auto-refreshes an access_token it emits a `tokens` event — we persist the
// new values so subsequent boots don't need re-auth.
function gbpOAuthClient() {
  if (!gbpClientConfigured()) return null;
  const client = new OAuth2Client(process.env.GBP_CLIENT_ID, process.env.GBP_CLIENT_SECRET, GBP_REDIRECT_URI);
  const saved = gbpLoadToken();
  if (saved) client.setCredentials(saved);
  client.on('tokens', (tokens) => gbpSaveToken(tokens));
  return client;
}

// Wraps fetch with a Bearer token from the OAuth client, refreshing access if
// needed. Throws with the Google error body on non-2xx.
async function gbpFetch(urlPath, init = {}) {
  const client = gbpOAuthClient();
  if (!client) throw new Error('Google Business Profile credentials not configured.');
  if (!gbpLoadToken()) throw new Error('Not connected to Google. Click Connect first.');
  const { token } = await client.getAccessToken();
  if (!token) throw new Error('Failed to obtain access token — re-auth required.');
  const res = await fetch(urlPath, {
    ...init,
    headers: {
      Authorization: `Bearer ${token}`,
      'Content-Type': 'application/json',
      ...(init.headers || {}),
    },
  });
  const body = await res.text();
  let json = null;
  try { json = body ? JSON.parse(body) : null; } catch { /* keep raw */ }
  if (!res.ok) {
    const msg = json?.error?.message || body || `HTTP ${res.status}`;
    throw new Error(`Google API ${res.status}: ${msg}`);
  }
  return json;
}

// Simple { MONDAY: ['09:00','18:00'] } ⇄ Google periods[] conversion.
// Google periods use 24h "HH:MM" → { hours, minutes }, openDay/closeDay in
// enum form ("MONDAY"). Days omitted from `dict` are treated as closed.
function gbpPeriodsFromSimple(dict) {
  const periods = [];
  for (const day of GBP_DAYS) {
    const pair = dict?.[day];
    if (!pair || pair === 'closed' || !pair[0] || !pair[1]) continue;
    const [oh, om] = String(pair[0]).split(':').map(n => parseInt(n, 10));
    const [ch, cm] = String(pair[1]).split(':').map(n => parseInt(n, 10));
    periods.push({
      openDay: day,
      openTime: { hours: oh || 0, minutes: om || 0 },
      closeDay: day,
      closeTime: { hours: ch || 0, minutes: cm || 0 },
    });
  }
  return { periods };
}
function gbpSimpleFromPeriods(regularHours) {
  const out = {};
  const periods = regularHours?.periods || [];
  for (const p of periods) {
    const pad = (n) => String(n || 0).padStart(2, '0');
    const open = `${pad(p.openTime?.hours)}:${pad(p.openTime?.minutes)}`;
    const close = `${pad(p.closeTime?.hours)}:${pad(p.closeTime?.minutes)}`;
    // Most GBP entries use same day for open/close. Cross-midnight spans are
    // rare for praxis locations; if encountered, we surface the open day only.
    out[p.openDay] = [open, close];
  }
  return out;
}

// GET /api/gbp/status — drives the UI state (setup required / connect / ready)
app.get('/api/gbp/status', (req, res) => {
  const clientConfigured = gbpClientConfigured();
  const token = gbpLoadToken();
  res.json({
    clientConfigured,
    connected: !!(clientConfigured && token && (token.refresh_token || token.access_token)),
    scope: token?.scope || null,
    expiresAt: token?.expiry_date || null,
    redirectUri: GBP_REDIRECT_URI,
  });
});

// GET /api/gbp/oauth/start — redirect the user to Google's consent screen.
// `prompt:'consent'` forces a refresh_token on every authorization (Google
// only returns one the first time unless explicitly re-prompted).
app.get('/api/gbp/oauth/start', (req, res) => {
  const client = gbpOAuthClient();
  if (!client) return res.status(400).send('GBP credentials not configured. See .env.example.');
  const url = client.generateAuthUrl({
    access_type: 'offline',
    prompt: 'consent',
    scope: [GBP_SCOPE],
  });
  res.redirect(url);
});

// GET /api/gbp/oauth/callback — Google redirects here with ?code. We exchange
// it for tokens, save them, and close the popup (signaling the opener).
app.get('/api/gbp/oauth/callback', async (req, res) => {
  try {
    const code = req.query.code;
    const err = req.query.error;
    if (err) throw new Error(String(err));
    if (!code) throw new Error('Missing ?code in callback');
    const client = gbpOAuthClient();
    if (!client) throw new Error('GBP credentials not configured.');
    const { tokens } = await client.getToken(String(code));
    gbpSaveToken(tokens);
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.send(`<!doctype html><meta charset="utf-8"><title>Connected</title>
<style>body{font:14px/1.5 system-ui;background:#0a0a0b;color:#e7e7ea;display:grid;place-items:center;height:100vh;margin:0}
.card{border:1px solid #222;border-radius:12px;padding:24px 28px;text-align:center;max-width:380px}
.ok{color:#62d08c;font-weight:600;letter-spacing:.08em;text-transform:uppercase;font-size:11px}
h1{font-size:18px;margin:.4em 0}</style>
<div class="card"><div class="ok">✓ Connected</div><h1>Google Business Profile linked</h1>
<p>You can close this tab.</p></div>
<script>
  try { window.opener && window.opener.postMessage({ type:'gbp-connected' }, '*'); } catch(e){}
  setTimeout(() => { try { window.close(); } catch(e){} }, 400);
</script>`);
  } catch (e) {
    res.status(500).send(`OAuth callback failed: ${e.message}`);
  }
});

// POST /api/gbp/disconnect — remove the saved token file.
app.post('/api/gbp/disconnect', (req, res) => {
  try {
    gbpClearToken();
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// GET /api/gbp/accounts — list GBP accounts visible to the authorized user.
app.get('/api/gbp/accounts', async (req, res) => {
  try {
    const data = await gbpFetch('https://mybusinessaccountmanagement.googleapis.com/v1/accounts');
    res.json({ accounts: data?.accounts || [] });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// GET /api/gbp/locations?account=accounts/123 — list locations under the account
// with the fields we render (title, address summary, regularHours).
app.get('/api/gbp/locations', async (req, res) => {
  try {
    const account = String(req.query.account || '').trim();
    if (!account) return res.status(400).json({ error: 'account query param required (e.g. accounts/123)' });
    const readMask = encodeURIComponent('name,title,storefrontAddress,regularHours');
    const url = `https://mybusinessbusinessinformation.googleapis.com/v1/${encodeURIComponent(account)}/locations?readMask=${readMask}&pageSize=100`;
    const data = await gbpFetch(url);
    const locations = (data?.locations || []).map(loc => ({
      name: loc.name,
      title: loc.title,
      address: loc.storefrontAddress
        ? [
            (loc.storefrontAddress.addressLines || []).join(', '),
            [loc.storefrontAddress.postalCode, loc.storefrontAddress.locality].filter(Boolean).join(' '),
            loc.storefrontAddress.regionCode,
          ].filter(Boolean).join(' · ')
        : '',
      regularHours: loc.regularHours || { periods: [] },
      hoursSimple: gbpSimpleFromPeriods(loc.regularHours),
    }));
    res.json({ locations });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// PATCH /api/gbp/locations — body: { name:'locations/123', hours:{MONDAY:[...]} }
// or { name, regularHours:{periods:[...]} }. Uses updateMask=regularHours so we
// don't accidentally clobber other location fields.
app.patch('/api/gbp/locations', async (req, res) => {
  try {
    const { name, hours, regularHours } = req.body || {};
    if (!name || !/^locations\//.test(name)) return res.status(400).json({ error: 'name (locations/...) required' });
    const payload = regularHours
      ? { regularHours }
      : { regularHours: gbpPeriodsFromSimple(hours || {}) };
    const url = `https://mybusinessbusinessinformation.googleapis.com/v1/${encodeURIComponent(name)}?updateMask=regularHours`;
    const data = await gbpFetch(url, { method: 'PATCH', body: JSON.stringify(payload) });
    res.json({
      ok: true,
      location: {
        name: data?.name || name,
        title: data?.title,
        regularHours: data?.regularHours || payload.regularHours,
        hoursSimple: gbpSimpleFromPeriods(data?.regularHours || payload.regularHours),
      },
    });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ─── Routes: praxis refresh (backup, wipe, import prod→staging, scrub, set-default)
//
// Single-env endpoints take the standard `x-db-*` headers. The cross-env import
// endpoint takes TWO header sets — `x-src-db-*` and `x-tgt-db-*` — so prod and
// staging pools are accessed in the same request.
//
// Hardcoded enumeration of praxis-config tables. These are the rows that get
// backed up, wiped, and imported as a unit. Each row has a numeric `"praxisId"`
// FK to `praxis_config.id`, except `praxis_config` itself, which is the root
// (with `"lcId"` as the natural key).
//
// FK INSERT order — child after parent. Use `[...].reverse()` for delete order.
// When backend adds a new praxis_*_config table, add it here AND the schema
// drift check (GET /api/praxis/schema-drift-check) will already surface it.
const PRAXIS_CONFIG_TABLES = [
  'praxis_config',
  'praxis_acute_consultation_config',
  'praxis_hours_config',
  'praxis_marketing_config',
  'praxis_open_consultation_config',
  'praxis_open_consultation_disabled_categories_config',
  'praxis_open_consultation_hours_config',
  'praxis_preanmnesis_config',
  'praxis_preanmnesis_disabled_config',
  'praxis_preanmnesis_popup_config',
  'praxis_preanmnesis_treatment_category_config',
  'praxis_preanmnesis_vitas_ai_treatment_category_config',
  'praxis_short_notice_config',
  'praxis_special_holiday_config',
  'praxis_special_hours_config',
  'praxis_support_email_config',
  'praxis_technical_config',
  'praxis_device_config',
  'praxis_holiday_config',
  'praxis_new_patient_config',
  'praxis_new_patient_config_question',
  'praxis_holiday_notice_config',
  'cockpit_standard_week_version',
  'cockpit_appointment_type_matrix',
  'cockpit_week_override',
];

// Tables in the config family that we WIPE and BACKUP normally but SKIP on
// import because they have a NOT NULL foreign key to a non-praxis table that
// won't survive the cross-env hop. praxis_device_config has a second FK
// (`userInfoId` → app_user_info.id) — prod's user ids don't exist on staging,
// so any insert violates the FK. Staging operators can re-register devices on
// staging if they need test devices.
const PRAXIS_CONFIG_TABLES_SKIP_IMPORT = new Set([
  'praxis_device_config',
]);

// Tables whose `praxisId` column holds an lcId STRING (not a numeric FK). We
// list them so the schema-drift check can classify them as "intentionally not
// wiped" rather than flagging them as drift. Step 5 (set-default) explicitly
// fixes user-facing references on `app_user_info` + `admin_user_info`; the
// rest stay orphaned.
const PRAXIS_HISTORICAL_LCID_TABLES = [
  'app_user_appointment',
  'app_user_open_consultation',
  'app_user_document_request',
  'app_user_reserved_appointment',
  'app_user_nps_sent',
  'guest_appointment',
  'questionnaire_reservation',
  'fhir_nps',
  'app_user_info',
  'app_user_pms_invitation',
  'admin_audit_log',
  // numeric praxis_id but historical (NOT config) — explicitly excluded from wipe
  'app_user_appointment_reminder',
  'cockpit_person_duration_exception',
  'praxis_hours_sync_target',
];

// Resolve a connection spec from an arbitrary header prefix (e.g. 'x-src-db-'
// or the default 'x-db-'). Mirrors `getPool` but caller-controlled.
function poolFromHeaders(req, prefix = 'x-db-') {
  const host = req.headers[`${prefix}host`] || 'localhost';
  const port = parseInt(req.headers[`${prefix}port`] || '8090');
  const database = req.headers[`${prefix}name`] || 'lillian_care_core';
  const user = req.headers[`${prefix}user`] || 'postgres';
  const password = req.headers[`${prefix}password`] || '';
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
  return { pool: pools[key], host, port, database, user };
}

async function poolQuery(pool, sql, params = []) {
  const result = await pool.query(sql, params);
  return result.rows;
}

// Look up column metadata (name + data_type + udt_name) for a table. We re-read
// schema each call; these are admin operations run rarely and the round-trip is
// negligible. Returns rows shaped { column_name, data_type, udt_name }.
async function tableColumns(pool, tableName) {
  return await poolQuery(
    pool,
    `SELECT column_name, data_type, udt_name FROM information_schema.columns
     WHERE table_schema = 'public' AND table_name = $1
     ORDER BY ordinal_position`,
    [tableName],
  );
}

function quoteIdent(ident) {
  return `"${ident.replace(/"/g, '""')}"`;
}

// Coerce a value read from one DB into a form pg-node will bind correctly when
// inserting into another DB's column. JSON/JSONB columns are the main case: pg
// parses them into JS objects/arrays on read, but on write a JS object would
// be coerced to "[object Object]" and Postgres rejects it.
function bindValue(col, raw) {
  if (raw === null || raw === undefined) return null;
  if (col.data_type === 'json' || col.data_type === 'jsonb') {
    return typeof raw === 'string' ? raw : JSON.stringify(raw);
  }
  return raw;
}

// ── GET /api/praxis/list ──────────────────────────────────────────────────────
// Lists all praxes for the env addressed by `x-db-*` headers. Used by both the
// frontend's source/target preview and the post-import default-praxis picker.
app.get('/api/praxis/list', async (req, res) => {
  try {
    const rows = await query(
      req,
      `SELECT id, "lcId", name, "shortName", city, "isDraft"
         FROM praxis_config
        ORDER BY name`,
    );
    res.json({ rows, total: rows.length });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ── GET /api/praxis/schema-drift-check ────────────────────────────────────────
// Compares the live target-env schema against the hardcoded config-table list
// above. Returns:
//   covered:    config tables we'll backup/wipe/import (intersection)
//   historical: praxis-scoped tables we INTENTIONALLY don't wipe
//   drift:      tables with a praxisId-shaped column that aren't in either list
// The frontend gates destructive steps on `drift.length === 0` (or operator
// override).
app.get('/api/praxis/schema-drift-check', async (req, res) => {
  try {
    // Tables with any column named "praxisId" (Serverpod camelCase) — covers
    // both numeric-FK (config) and string-lcId (historical) tables.
    const found = await query(
      req,
      `SELECT table_name, data_type
         FROM information_schema.columns
        WHERE table_schema = 'public'
          AND column_name = 'praxisId'
        ORDER BY table_name`,
    );
    const known = new Set([...PRAXIS_CONFIG_TABLES, ...PRAXIS_HISTORICAL_LCID_TABLES]);
    const covered = [];
    const historical = [];
    const drift = [];
    for (const row of found) {
      if (PRAXIS_CONFIG_TABLES.includes(row.table_name)) covered.push(row);
      else if (PRAXIS_HISTORICAL_LCID_TABLES.includes(row.table_name)) historical.push(row);
      else drift.push(row);
    }
    // Also flag any hardcoded config table that doesn't exist on this env.
    const presentNames = new Set(found.map(r => r.table_name));
    const missing = PRAXIS_CONFIG_TABLES.filter(t => t !== 'praxis_config' && !presentNames.has(t));
    res.json({ covered, historical, drift, missing });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ── POST /api/praxis/backup ───────────────────────────────────────────────────
// Body: { lcIds?: string[] }  — if omitted, backs up every praxis on the env.
// Dumps each praxis (root + all 24 child tables) to
//   helper/backups/<envLabel>/<ISO-timestamp>/<lcId>.json
// Returns the absolute paths so the frontend can show them.
app.post('/api/praxis/backup', async (req, res) => {
  try {
    const envLabel = (req.headers['x-env-label'] || req.headers['x-env'] || 'unknown').toString().replace(/[^a-zA-Z0-9_-]/g, '_');
    const { lcIds } = req.body || {};
    const { pool } = poolFromHeaders(req);

    const praxes = lcIds && lcIds.length
      ? await poolQuery(pool, `SELECT * FROM praxis_config WHERE "lcId" = ANY($1::text[]) ORDER BY "lcId"`, [lcIds])
      : await poolQuery(pool, `SELECT * FROM praxis_config ORDER BY "lcId"`);

    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const backupDir = path.join(__dirname, 'backups', envLabel, timestamp);
    fs.mkdirSync(backupDir, { recursive: true });

    const written = [];
    for (const praxis of praxes) {
      const bundle = { praxis_config: praxis, related: {} };
      for (let i = 1; i < PRAXIS_CONFIG_TABLES.length; i++) {
        const t = PRAXIS_CONFIG_TABLES[i];
        try {
          const rows = await poolQuery(pool, `SELECT * FROM ${quoteIdent(t)} WHERE "praxisId" = $1`, [praxis.id]);
          bundle.related[t] = rows;
        } catch (e) {
          // Treat a missing table as empty so a partially-migrated env can still backup.
          bundle.related[t] = { __error: e.message };
        }
      }
      const filename = `${praxis.lcId}.json`;
      const filepath = path.join(backupDir, filename);
      fs.writeFileSync(filepath, JSON.stringify(bundle, null, 2));
      written.push({ lcId: praxis.lcId, name: praxis.name, path: filepath });
    }
    res.json({ ok: true, env: envLabel, dir: backupDir, files: written, count: written.length });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ── POST /api/praxis/wipe-staging ─────────────────────────────────────────────
// Refuses unless: env-label === 'staging', `x-allow-destructive: yes`, and body
// `confirmation` exactly equals 'WIPE STAGING'. Deletes from the 25 config
// tables in reverse FK order. Historical praxis-scoped tables (appointments,
// audit, NPS, etc.) are intentionally NOT touched — see CLAUDE.md.
app.post('/api/praxis/wipe-staging', async (req, res) => {
  try {
    const envLabel = (req.headers['x-env-label'] || req.headers['x-env'] || '').toString().toLowerCase();
    if (envLabel !== 'staging') {
      return res.status(400).json({ error: `Refusing to wipe: x-env-label must be 'staging' (got '${envLabel}'). This guard exists to prevent accidental prod wipes.` });
    }
    if (req.headers['x-allow-destructive'] !== 'yes') {
      return res.status(400).json({ error: `Refusing to wipe: x-allow-destructive header must be 'yes'.` });
    }
    if ((req.body && req.body.confirmation) !== 'WIPE STAGING') {
      return res.status(400).json({ error: `Refusing to wipe: body.confirmation must be the literal string 'WIPE STAGING'.` });
    }

    const { pool } = poolFromHeaders(req);
    const client = await pool.connect();
    const counts = {};
    try {
      await client.query('BEGIN');
      // Delete child tables first, then the root.
      for (const t of [...PRAXIS_CONFIG_TABLES].reverse()) {
        const r = await client.query(`DELETE FROM ${quoteIdent(t)}`);
        counts[t] = r.rowCount;
      }
      await client.query('COMMIT');
    } catch (e) {
      await client.query('ROLLBACK');
      throw e;
    } finally {
      client.release();
    }
    res.json({ ok: true, deletedRowsByTable: counts });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ── POST /api/praxis/import ───────────────────────────────────────────────────
// Headers: `x-src-db-*` (read-only, e.g. prod) AND `x-tgt-db-*` (writable, e.g.
// staging). Body: { lcIds?: string[] } — defaults to all praxes on source.
// Inserts each source praxis into the target with `"lcId"` preserved, generating
// a NEW numeric `id` (Postgres default), then copies each child config table
// remapping `"praxisId"` to the new target id. Sets `"isDraft" = false`.
// Errors out cleanly if any lcId already exists on target.
app.post('/api/praxis/import', async (req, res) => {
  try {
    const { lcIds } = req.body || {};
    const src = poolFromHeaders(req, 'x-src-db-');
    const tgt = poolFromHeaders(req, 'x-tgt-db-');
    if (`${src.host}:${src.port}/${src.database}` === `${tgt.host}:${tgt.port}/${tgt.database}`) {
      return res.status(400).json({ error: 'Source and target databases must be different.' });
    }

    const srcPraxes = lcIds && lcIds.length
      ? await poolQuery(src.pool, `SELECT * FROM praxis_config WHERE "lcId" = ANY($1::text[]) ORDER BY "lcId"`, [lcIds])
      : await poolQuery(src.pool, `SELECT * FROM praxis_config ORDER BY "lcId"`);

    if (!srcPraxes.length) return res.json({ ok: true, imported: [], skipped: [], message: 'No source praxes found.' });

    // Pre-check for collisions on target so we fail before any writes.
    const tgtExisting = await poolQuery(
      tgt.pool,
      `SELECT "lcId" FROM praxis_config WHERE "lcId" = ANY($1::text[])`,
      [srcPraxes.map(p => p.lcId)],
    );
    if (tgtExisting.length) {
      return res.status(409).json({
        error: `Target already has ${tgtExisting.length} of the requested lcId(s). Wipe first or pass a smaller lcIds list.`,
        collisions: tgtExisting.map(r => r.lcId),
      });
    }

    // Cache target table column lists once.
    const childTables = PRAXIS_CONFIG_TABLES.slice(1);
    const colsByTable = {};
    for (const t of [...childTables, 'praxis_config']) {
      colsByTable[t] = await tableColumns(tgt.pool, t);
    }

    const tgtClient = await tgt.pool.connect();
    const imported = [];
    const errors = [];
    try {
      await tgtClient.query('BEGIN');
      for (const srcPraxis of srcPraxes) {
        // Insert root, omit `id` so target assigns a fresh one. Preserve lcId
        // and force isDraft=false so imported praxes are immediately live.
        const rootCols = colsByTable['praxis_config'].filter(c => c.column_name !== 'id');
        const rootValues = rootCols.map(c =>
          c.column_name === 'isDraft' ? false : bindValue(c, srcPraxis[c.column_name])
        );
        const placeholders = rootCols.map((_, i) => `$${i + 1}`).join(',');
        const colList = rootCols.map(c => quoteIdent(c.column_name)).join(',');
        const inserted = await tgtClient.query(
          `INSERT INTO praxis_config (${colList}) VALUES (${placeholders}) RETURNING id`,
          rootValues,
        );
        const newPraxisId = inserted.rows[0].id;

        // Copy each child config table, remapping the FK.
        const perTable = {};
        for (const t of childTables) {
          if (PRAXIS_CONFIG_TABLES_SKIP_IMPORT.has(t)) {
            perTable[t] = { skipped: 'cross-table FK to non-praxis table — see PRAXIS_CONFIG_TABLES_SKIP_IMPORT' };
            continue;
          }
          let childRows;
          try {
            childRows = await poolQuery(src.pool, `SELECT * FROM ${quoteIdent(t)} WHERE "praxisId" = $1`, [srcPraxis.id]);
          } catch (e) {
            // Table may not exist on source (rare during migration). Skip silently.
            perTable[t] = { skipped: e.message };
            continue;
          }
          if (!childRows.length) { perTable[t] = 0; continue; }
          const childCols = colsByTable[t].filter(c => c.column_name !== 'id');
          const childColList = childCols.map(c => quoteIdent(c.column_name)).join(',');
          const childPlaceholders = childCols.map((_, i) => `$${i + 1}`).join(',');
          for (const row of childRows) {
            const values = childCols.map(c =>
              c.column_name === 'praxisId' ? newPraxisId : bindValue(c, row[c.column_name])
            );
            await tgtClient.query(
              `INSERT INTO ${quoteIdent(t)} (${childColList}) VALUES (${childPlaceholders})`,
              values,
            );
          }
          perTable[t] = childRows.length;
        }
        imported.push({ lcId: srcPraxis.lcId, name: srcPraxis.name, newPraxisId, perTable });
      }
      await tgtClient.query('COMMIT');
    } catch (e) {
      await tgtClient.query('ROLLBACK');
      errors.push(e.message);
      throw new Error(`Import rolled back: ${e.message}`);
    } finally {
      tgtClient.release();
    }
    res.json({ ok: true, importedCount: imported.length, imported, errors });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ── POST /api/praxis/scrub-contacts ───────────────────────────────────────────
// Body: { email: string, phone: string, vitasAIPraxisId?: string }. Bulk-updates
// email + phone on every praxis_config row. If vitasAIPraxisId is provided
// (non-empty), also overwrites that column. Refuses on production.
app.post('/api/praxis/scrub-contacts', async (req, res) => {
  try {
    const envLabel = (req.headers['x-env-label'] || req.headers['x-env'] || '').toString().toLowerCase();
    if (envLabel === 'production' || envLabel === 'prod') {
      return res.status(400).json({ error: 'Refusing to scrub on production.' });
    }
    const { email, phone, vitasAIPraxisId } = req.body || {};
    if (!email || !phone) return res.status(400).json({ error: 'email and phone are required.' });
    const setClauses = [`email = $1`, `phone = $2`];
    const params = [email, phone];
    if (typeof vitasAIPraxisId === 'string' && vitasAIPraxisId.length) {
      params.push(vitasAIPraxisId);
      setClauses.push(`"vitasAIPraxisId" = $${params.length}`);
    }
    const r = await query(req, `UPDATE praxis_config SET ${setClauses.join(', ')}`, params);
    res.json({ ok: true, scrubbedRows: r.length, columnsUpdated: setClauses.length });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ── POST /api/praxis/set-default ──────────────────────────────────────────────
// Body: { lcId: string }. Sets `praxisId` on every app_user_info row and
// replaces `associatedPraxisIds` on every admin_user_info row with [lcId].
// Refuses on production. Verifies the lcId exists in praxis_config first.
app.post('/api/praxis/set-default', async (req, res) => {
  try {
    const envLabel = (req.headers['x-env-label'] || req.headers['x-env'] || '').toString().toLowerCase();
    if (envLabel === 'production' || envLabel === 'prod') {
      return res.status(400).json({ error: 'Refusing to bulk-set default praxis on production.' });
    }
    const { lcId } = req.body || {};
    if (!lcId) return res.status(400).json({ error: 'lcId is required.' });

    const exists = await query(req, `SELECT id FROM praxis_config WHERE "lcId" = $1 LIMIT 1`, [lcId]);
    if (!exists.length) return res.status(404).json({ error: `lcId '${lcId}' not found in praxis_config on this env.` });

    const { pool } = poolFromHeaders(req);
    const client = await pool.connect();
    let appUsers = 0, adminUsers = 0;
    try {
      await client.query('BEGIN');
      const a = await client.query(`UPDATE app_user_info SET "praxisId" = $1`, [lcId]);
      appUsers = a.rowCount;
      // associatedPraxisIds is stored as JSON (array of strings), not Postgres text[].
      const b = await client.query(`UPDATE admin_user_info SET "associatedPraxisIds" = $1::json`, [JSON.stringify([lcId])]);
      adminUsers = b.rowCount;
      await client.query('COMMIT');
    } catch (e) {
      await client.query('ROLLBACK');
      throw e;
    } finally {
      client.release();
    }
    res.json({ ok: true, lcId, appUsersUpdated: appUsers, adminUsersUpdated: adminUsers });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ─── Routes: cockpit fill (bulk-fill cockpit + opening hours from an Excel) ───
//
// The Excel ("Master Öffnungszeiten Sprechzeiten") has one sheet per praxis.
// Each sheet has three blocks identified by header text in column A:
//   1. "Öffnungszeiten"     → praxis-wide opening hours       → praxis_hours_config rows
//   2. "Sprechstundenzeiten" → per-doctor consultation slots   → cockpit consultationHoursJson
//   3. "Arbeitszeiten"      → per-role staff working hours    → cockpit workHoursJson
//
// Each row in the time blocks has 5 days × {AM start, AM end, PM start, PM end} in
// columns 3–22, plus person/resource labels in cols 1–2 and weekly hours in col 23.
//
// Block positions are NOT fixed across sheets, so the parser scans by header text.
// Times can arrive as strings ("8:00:00"), Excel serials (0.333…), or Date objects;
// we normalize to "HH:MM" strings.

const XLSX = require('xlsx');

const COCKPIT_WEEKDAYS = ['monday', 'tuesday', 'wednesday', 'thursday', 'friday'];
const COCKPIT_DAY_ENUM_INDEX = { monday: 0, tuesday: 1, wednesday: 2, thursday: 3, friday: 4, saturday: 5, sunday: 6 };

// Resource labels in column B (Sprechstundenzeiten block) → ConsultationKind.
// Pattern matching is loose because the Excel has minor variations
// ("Nicht buchbare Zeit" vs "Nicht buchbare Zeiten", trailing whitespace, etc.).
function consultationKindFromLabel(label) {
  if (!label) return null;
  const s = String(label).toLowerCase().trim();
  if (s.includes('homeoffice')) return 'homeoffice';
  if (s.includes('vor ort')) return 'vorOrt';
  if (s.includes('akut')) return 'akut';
  if (s.includes('heimversorgung')) return 'heimversorgung';
  if (s.includes('urlaub')) return 'urlaub';
  if (s.includes('nicht buchbar')) return 'nichtBuchbar';
  if (s.includes('buffer')) return 'buffer';
  return null;
}

// Convert an Excel cell value to "HH:MM" or null. Handles string forms
// ("8:00:00", "08:15", "9.00"), JS Date objects, and Excel time serials
// (numbers in [0, 1) representing fraction of a day).
//
// Timezone note: SheetJS with cellDates: true encodes Excel time-of-day into
// the LOCAL components of the Date — e.g. for the cell "08:15" it returns a
// Date d such that d.getHours()===8 and d.getMinutes()===15, regardless of
// the host's timezone. The absolute UTC instant is offset by the host's TZ
// at the Excel epoch (1899-12-30), so getUTCHours() would give the wrong
// hour on any non-UTC host. Always read getHours()/getMinutes() here.
// Downstream the value flows as a wall-clock "HH:MM" string end-to-end
// (DB stores text; backend + praxis app pass the string through without
// constructing any DateTime), so a German user sees the Excel value as-is.
function cellToHHMM(v) {
  if (v === null || v === undefined || v === '') return null;
  if (typeof v === 'string') {
    const s = v.trim();
    if (!s || s.startsWith('#') || s === '0:00:00') return null;
    // Try "H:MM:SS" or "HH:MM:SS" or "HH:MM"
    const m = s.match(/^(\d{1,2})[:.](\d{2})(?:[:.](\d{2}))?$/);
    if (m) return `${m[1].padStart(2, '0')}:${m[2]}`;
    return null;
  }
  if (v instanceof Date) {
    const h = String(v.getHours()).padStart(2, '0');
    const m = String(v.getMinutes()).padStart(2, '0');
    return `${h}:${m}`;
  }
  if (typeof v === 'number') {
    // Excel time serial: fraction of a day. 0.5 = 12:00. Tolerate values >1
    // (datetimes whose date part we ignore).
    const frac = v - Math.floor(v);
    const totalMin = Math.round(frac * 24 * 60);
    const h = String(Math.floor(totalMin / 60)).padStart(2, '0');
    const m = String(totalMin % 60).padStart(2, '0');
    return `${h}:${m}`;
  }
  return null;
}

// Read row N as { A, B, slots: [{weekday, start, end} ...] }. Each weekday has
// up to 2 slots (AM and PM) — emitted as separate flat entries.
function readSlotRow(sheet, rowIdx) {
  const row = { a: null, b: null, slots: [] };
  // xlsx sheet uses A1 cell refs. Build them.
  const cellAt = (col, r) => {
    const ref = XLSX.utils.encode_cell({ c: col - 1, r: r - 1 });
    const c = sheet[ref];
    return c ? c.v : undefined;
  };
  row.a = cellAt(1, rowIdx);
  row.b = cellAt(2, rowIdx);
  // 5 days × 4 cols, starting at col 3
  for (let d = 0; d < 5; d++) {
    const baseCol = 3 + d * 4;
    const amStart = cellToHHMM(cellAt(baseCol, rowIdx));
    const amEnd   = cellToHHMM(cellAt(baseCol + 1, rowIdx));
    const pmStart = cellToHHMM(cellAt(baseCol + 2, rowIdx));
    const pmEnd   = cellToHHMM(cellAt(baseCol + 3, rowIdx));
    if (amStart && amEnd) row.slots.push({ weekday: COCKPIT_WEEKDAYS[d], start: amStart, end: amEnd, half: 'AM' });
    if (pmStart && pmEnd) row.slots.push({ weekday: COCKPIT_WEEKDAYS[d], start: pmStart, end: pmEnd, half: 'PM' });
  }
  return row;
}

function parseSheet(sheet, sheetName) {
  const range = XLSX.utils.decode_range(sheet['!ref'] || 'A1:A1');
  const maxRow = range.e.r + 1;
  const blocks = { opening: [], consultation: [], working: [], persons: [] };

  let currentBlock = null;
  let currentPerson = null;
  for (let r = 1; r <= maxRow; r++) {
    const a = sheet[XLSX.utils.encode_cell({ c: 0, r: r - 1 })]?.v;
    const aStr = a ? String(a).trim() : '';

    if (aStr.includes('Öffnungszeiten')) { currentBlock = 'opening'; currentPerson = null; continue; }
    if (aStr.includes('Sprechstundenzeiten')) { currentBlock = 'consultation'; currentPerson = null; continue; }
    if (aStr.includes('Arbeitszeiten')) { currentBlock = 'working'; currentPerson = null; continue; }
    if (aStr.startsWith('Gemeldete')) { currentBlock = null; currentPerson = null; continue; }
    if (currentBlock === null) continue;

    // Skip header sub-row (col C says 'Montag Vormittag').
    const c3 = sheet[XLSX.utils.encode_cell({ c: 2, r: r - 1 })]?.v;
    if (c3 === 'Montag Vormittag') continue;

    const row = readSlotRow(sheet, r);

    if (currentBlock === 'opening') {
      if (row.slots.length) blocks.opening.push(...row.slots.map(s => ({ weekday: s.weekday, start: s.start, end: s.end })));
    } else if (currentBlock === 'consultation') {
      // Carry person name down the rows; col B is the resource label.
      if (row.a && String(row.a).trim()) currentPerson = String(row.a).trim();
      const personName = currentPerson;
      const resourceLabel = row.b ? String(row.b).trim() : null;
      const kind = consultationKindFromLabel(resourceLabel);
      if (personName && kind && row.slots.length) {
        if (!blocks.persons.includes(personName)) blocks.persons.push(personName);
        for (const s of row.slots) {
          blocks.consultation.push({
            weekday: s.weekday,
            personName,
            kind,
            start: s.start,
            end: s.end,
            onlineBookable: kind !== 'nichtBuchbar',
            sourceLabel: resourceLabel,
          });
        }
      }
    } else if (currentBlock === 'working') {
      // Carry person name down (same as consultation block). Doctor rows in
      // Block 3 have col A = name, col B = blank; MFA rows have col A = name,
      // col B = "MFA" / "MFA Homeoffice". Continuation rows have col A blank.
      if (row.a && String(row.a).trim()) currentPerson = String(row.a).trim();
      const personName = currentPerson;
      const role = row.b ? String(row.b).trim() : null;
      if (personName && row.slots.length) {
        if (!blocks.persons.includes(personName)) blocks.persons.push(personName);
        for (const s of row.slots) {
          blocks.working.push({
            weekday: s.weekday,
            personName,
            role,
            start: s.start,
            end: s.end,
            breakMin: 0,
          });
        }
      }
    }
  }
  return { sheetName, ...blocks };
}

// ── POST /api/cockpit/parse-excel ─────────────────────────────────────────────
// Body: { path: string }  — absolute path to the .xlsx on disk. Reads, parses,
// returns per-sheet structured data plus a list of all sheet names found.
app.post('/api/cockpit/parse-excel', async (req, res) => {
  try {
    const { path: filepath } = req.body || {};
    if (!filepath) return res.status(400).json({ error: 'path is required' });
    if (!fs.existsSync(filepath)) return res.status(404).json({ error: `File not found: ${filepath}` });

    const wb = XLSX.readFile(filepath, { cellDates: true, cellNF: false, cellText: false });
    // Skip templates and reference sheets — only real praxis sheets get parsed.
    const skipRe = /^(Vorlage|Erklärung|Telefonistinnen)/i;
    const sheets = wb.SheetNames.filter(n => /_Neu\s*$/i.test(n) && !skipRe.test(n));
    const parsed = sheets.map(name => parseSheet(wb.Sheets[name], name.trim()));

    // Aggregate distinct person names across all sheets so the UI can build a
    // single mapping list.
    const allPersons = Array.from(new Set(parsed.flatMap(p => p.persons))).sort();

    res.json({
      ok: true,
      file: filepath,
      sheets: parsed.map(p => ({
        sheetName: p.sheetName,
        opening: p.opening,
        consultation: p.consultation,
        working: p.working,
        persons: p.persons,
        counts: {
          openingSlots: p.opening.length,
          consultationSlots: p.consultation.length,
          workingSlots: p.working.length,
          persons: p.persons.length,
        },
      })),
      allPersons,
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ── Personio client (server-side, for name → employeeId resolution) ───────────
let _personioToken = null;
async function getPersonioToken() {
  const id = process.env.PERSONIO_CLIENT_ID;
  const secret = process.env.PERSONIO_CLIENT_SECRET;
  if (!id || !secret) throw new Error('PERSONIO_CLIENT_ID/SECRET not set in .env — manual employeeId mapping required.');
  const now = Date.now();
  if (_personioToken && _personioToken.expiresAt - 60_000 > now) return _personioToken.token;
  const r = await fetch('https://api.personio.de/v1/auth', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
    body: JSON.stringify({ client_id: id, client_secret: secret }),
  });
  if (!r.ok) throw new Error(`Personio auth failed: HTTP ${r.status}`);
  const j = await r.json();
  if (!j?.success || !j?.data?.token) throw new Error('Personio auth response missing token');
  // Default to 25 minutes (Personio docs say 24h tokens, but cache short to be safe).
  _personioToken = { token: j.data.token, expiresAt: now + 25 * 60_000 };
  return _personioToken.token;
}

// Personio employee fields we care about: id, first_name, last_name, email, office.
// The /v1/company/employees endpoint paginates with offset+limit (default 200).
async function fetchPersonioEmployees() {
  const all = [];
  const limit = 200;
  for (let offset = 0; offset < 10000; offset += limit) {
    const token = await getPersonioToken();
    const r = await fetch(`https://api.personio.de/v1/company/employees?limit=${limit}&offset=${offset}`, {
      headers: { 'Accept': 'application/json', 'Authorization': `Bearer ${token}` },
    });
    if (r.status === 401) { _personioToken = null; continue; }
    if (!r.ok) throw new Error(`Personio employees HTTP ${r.status}`);
    const j = await r.json();
    const data = j?.data || [];
    if (!data.length) break;
    for (const emp of data) {
      const attrs = emp.attributes || {};
      const office = attrs.office?.value?.attributes?.name || null;
      let weitereStandorte = [];
      for (const [key, val] of Object.entries(attrs)) {
        if (!key.startsWith('dynamic_')) continue;
        if (!val || typeof val !== 'object') continue;
        if (val.label !== 'Weitere Standorte') continue;
        const v = val.value;
        if (typeof v === 'string' && v.length > 0) {
          weitereStandorte = v.split(',').map(s => s.trim()).filter(Boolean);
        }
        break;
      }
      all.push({
        id: attrs.id?.value ?? emp.id ?? null,
        firstName: attrs.first_name?.value || '',
        lastName: attrs.last_name?.value || '',
        email: attrs.email?.value || '',
        position: attrs.position?.value || '',
        status: attrs.status?.value || null,
        office,
        weitereStandorte,
      });
    }
    if (data.length < limit) break;
  }
  return all;
}

// ── GET /api/cockpit/personio-employees ───────────────────────────────────────
// Returns the live Personio employee list. Used by the UI to populate the
// "Excel name → Personio employee" matcher.
app.get('/api/cockpit/personio-employees', async (req, res) => {
  try {
    const employees = await fetchPersonioEmployees();
    res.json({ ok: true, count: employees.length, employees });
  } catch (e) {
    res.status(500).json({ error: e.message, configured: !!(process.env.PERSONIO_CLIENT_ID && process.env.PERSONIO_CLIENT_SECRET) });
  }
});

// ── GET /api/personio/audit ───────────────────────────────────────────────────
//
// Read-only audit. Cross-checks the Personio employee roster (with the
// `Weitere Standorte` custom field) against every (praxisId, employeeId) pair
// stored in the cockpit tables. Surfaces three classes of mismatch:
//
//   • orphan       — stored employeeId not found in the live Personio roster
//   • inactive-ref — stored record is in Personio but `status != active`
//                    (suggests a live sibling record by name)
//   • wrong-praxis — stored record is active but neither its primary office nor
//                    its Weitere Standorte resolve to this praxis
//
// We mirror the backend matcher (LillianCare-Core/personio_service.dart):
// primary office matches by substring against `<praxis.city>` and the city
// extracted from `<praxis.name>` ("Praxis <City>"); Weitere Standorte entries
// are exact-match (case-insensitive) against the same city set.
//
// Three sources are inspected:
//   • cockpit_person_duration_exception (column employeeId)
//   • cockpit_standard_week_version     (employeeIds inside JSON blobs)
//   • cockpit_week_override             (employeeIds inside JSON blobs)
function _normCity(s) {
  return (s || '').toString().trim().toLowerCase();
}
function _extractCityFromPraxisName(name) {
  const m = /Praxis\s+(.+)$/i.exec(name || '');
  return m ? m[1].trim() : null;
}
function _praxisCitySet(p) {
  const set = new Set();
  if (p.city) set.add(_normCity(p.city));
  const fromName = _extractCityFromPraxisName(p.name);
  if (fromName) set.add(_normCity(fromName));
  return set;
}
function _expectedPraxisIdsForEmployee(emp, praxes) {
  const office = _normCity(emp.office || '');
  const ws = (emp.weitereStandorte || []).map(_normCity).filter(Boolean);
  const matched = [];
  for (const p of praxes) {
    const cities = _praxisCitySet(p);
    let isMatch = false;
    if (office) {
      for (const c of cities) {
        if (c && office.includes(c)) { isMatch = true; break; }
      }
    }
    if (!isMatch && ws.length) {
      for (const c of cities) {
        if (c && ws.includes(c)) { isMatch = true; break; }
      }
    }
    if (isMatch) matched.push(p);
  }
  return matched;
}

app.get('/api/personio/audit', async (req, res) => {
  try {
    const employees = await fetchPersonioEmployees();
    const byId = new Map();
    const byName = new Map();
    for (const e of employees) {
      const id = Number(e.id);
      if (!Number.isFinite(id)) continue;
      byId.set(id, e);
      const key = `${(e.firstName || '').toLowerCase()}|${(e.lastName || '').toLowerCase()}`;
      const arr = byName.get(key) || [];
      arr.push(e);
      byName.set(key, arr);
    }

    const praxes = await query(
      req,
      `SELECT id, "lcId", name, city FROM praxis_config ORDER BY "lcId"`,
    );
    const praxisById = new Map(praxes.map(p => [Number(p.id), p]));

    const expectedByEmpId = new Map();
    for (const emp of employees) {
      const id = Number(emp.id);
      if (!Number.isFinite(id)) continue;
      const matched = _expectedPraxisIdsForEmployee(emp, praxes);
      expectedByEmpId.set(id, new Set(matched.map(p => Number(p.id))));
    }

    const stored = new Map();
    function pushStored(praxisId, employeeId, source) {
      const pid = Number(praxisId);
      const eid = Number(employeeId);
      if (!Number.isFinite(pid) || !Number.isFinite(eid)) return;
      const key = `${pid}|${eid}`;
      const cur = stored.get(key);
      if (cur) {
        if (!cur.sources.includes(source)) cur.sources.push(source);
      } else {
        stored.set(key, { praxisId: pid, employeeId: eid, sources: [source] });
      }
    }

    const [pdePairs, swvRows, woRows] = await Promise.all([
      query(req, `SELECT DISTINCT "praxisId", "employeeId" FROM cockpit_person_duration_exception`),
      query(req, `SELECT "praxisId", "consultationHoursJson", "workHoursJson" FROM cockpit_standard_week_version`),
      query(req, `SELECT "praxisId", "consultationHoursJson", "workHoursJson" FROM cockpit_week_override`),
    ]);
    for (const r of pdePairs) pushStored(r.praxisId, r.employeeId, 'cockpit_person_duration_exception');

    function harvestJsonBlob(praxisId, raw, source) {
      if (!raw) return;
      let parsed;
      try { parsed = typeof raw === 'string' ? JSON.parse(raw) : raw; }
      catch { return; }
      if (!Array.isArray(parsed)) return;
      for (const slot of parsed) {
        if (slot && typeof slot === 'object' && Number.isFinite(Number(slot.employeeId))) {
          pushStored(praxisId, slot.employeeId, source);
        }
      }
    }
    for (const r of swvRows) {
      harvestJsonBlob(r.praxisId, r.consultationHoursJson, 'cockpit_standard_week_version.consultationHoursJson');
      harvestJsonBlob(r.praxisId, r.workHoursJson, 'cockpit_standard_week_version.workHoursJson');
    }
    for (const r of woRows) {
      harvestJsonBlob(r.praxisId, r.consultationHoursJson, 'cockpit_week_override.consultationHoursJson');
      harvestJsonBlob(r.praxisId, r.workHoursJson, 'cockpit_week_override.workHoursJson');
    }

    const issues = [];
    let okCount = 0;
    for (const { praxisId, employeeId, sources } of stored.values()) {
      const praxis = praxisById.get(praxisId);
      const praxisLcId = praxis?.lcId || null;
      const praxisName = praxis?.name || null;
      const personio = byId.get(employeeId) || null;

      if (!personio) {
        issues.push({
          kind: 'orphan',
          praxisId, praxisLcId, praxisName,
          employeeId,
          personio: null,
          suggested: null,
          sources,
        });
        continue;
      }

      const fullName = `${personio.firstName || ''} ${personio.lastName || ''}`.trim();
      const empMeta = {
        id: employeeId,
        firstName: personio.firstName,
        lastName: personio.lastName,
        fullName,
        status: personio.status || null,
        office: personio.office || null,
        weitereStandorte: personio.weitereStandorte || [],
      };

      if ((personio.status || '').toLowerCase() !== 'active') {
        const key = `${(personio.firstName || '').toLowerCase()}|${(personio.lastName || '').toLowerCase()}`;
        const siblings = (byName.get(key) || []).filter(s => Number(s.id) !== employeeId && (s.status || '').toLowerCase() === 'active');
        let suggestion = null;
        for (const s of siblings) {
          const exp = expectedByEmpId.get(Number(s.id)) || new Set();
          if (exp.has(praxisId)) { suggestion = s; break; }
        }
        if (!suggestion && siblings.length) suggestion = siblings[0];
        issues.push({
          kind: 'inactive-ref',
          praxisId, praxisLcId, praxisName,
          employeeId,
          personio: empMeta,
          suggested: suggestion ? {
            id: Number(suggestion.id),
            firstName: suggestion.firstName,
            lastName: suggestion.lastName,
            status: suggestion.status,
            office: suggestion.office,
            weitereStandorte: suggestion.weitereStandorte,
          } : null,
          sources,
        });
        continue;
      }

      const expected = expectedByEmpId.get(employeeId) || new Set();
      if (!expected.has(praxisId)) {
        issues.push({
          kind: 'wrong-praxis',
          praxisId, praxisLcId, praxisName,
          employeeId,
          personio: empMeta,
          suggested: null,
          sources,
        });
        continue;
      }

      okCount++;
    }

    issues.sort((a, b) => {
      const order = { 'orphan': 0, 'inactive-ref': 1, 'wrong-praxis': 2 };
      const k = (order[a.kind] ?? 99) - (order[b.kind] ?? 99);
      if (k !== 0) return k;
      return (a.praxisLcId || '').localeCompare(b.praxisLcId || '');
    });

    const counts = {
      storedPairs: stored.size,
      ok: okCount,
      orphan: issues.filter(i => i.kind === 'orphan').length,
      inactiveRef: issues.filter(i => i.kind === 'inactive-ref').length,
      wrongPraxis: issues.filter(i => i.kind === 'wrong-praxis').length,
      personioActive: employees.filter(e => (e.status || '').toLowerCase() === 'active').length,
      personioTotal: employees.length,
      praxes: praxes.length,
    };

    res.json({ ok: true, fetchedAt: new Date().toISOString(), counts, issues });
  } catch (e) {
    res.status(500).json({ error: e.message, configured: !!(process.env.PERSONIO_CLIENT_ID && process.env.PERSONIO_CLIENT_SECRET) });
  }
});

// ── POST /api/personio/audit/fix ──────────────────────────────────────────────
// Apply remove/remap actions to the (praxisId, employeeId) pairs surfaced by
// the personio audit. All actions run in a single transaction. Affects:
//   • cockpit_person_duration_exception           (DELETE on remove, UPDATE employeeId on remap)
//   • cockpit_standard_week_version JSON blobs    (consultationHoursJson, workHoursJson)
//   • cockpit_week_override JSON blobs            (consultationHoursJson, workHoursJson)
// Body: { actions: [{ praxisId, employeeId, mode: 'remove'|'remap', newEmployeeId? }] }
// Refuses on production env-label.
function _personioFixTransformBlob(raw, employeeId, mode, newEmployeeId) {
  if (raw == null) return { json: raw, changed: false, touched: 0 };
  let parsed;
  try { parsed = typeof raw === 'string' ? JSON.parse(raw) : raw; }
  catch { return { json: raw, changed: false, touched: 0 }; }
  if (!Array.isArray(parsed)) return { json: raw, changed: false, touched: 0 };
  let touched = 0;
  let next;
  if (mode === 'remove') {
    next = parsed.filter(slot => {
      if (slot && typeof slot === 'object' && Number(slot.employeeId) === employeeId) { touched++; return false; }
      return true;
    });
  } else {
    next = parsed.map(slot => {
      if (slot && typeof slot === 'object' && Number(slot.employeeId) === employeeId) {
        touched++;
        return { ...slot, employeeId: newEmployeeId };
      }
      return slot;
    });
  }
  if (touched === 0) return { json: raw, changed: false, touched: 0 };
  return { json: JSON.stringify(next), changed: true, touched };
}

// cockpit_standard_week_version is append-only versioned (createdAt/createdBy only,
// no modifiedAt). cockpit_week_override has both createdAt + modifiedAt. The
// `touchModifiedAt` flag picks the right SET clause per table.
async function _personioFixApplyJsonBlob(client, table, praxisId, employeeId, mode, newEmployeeId, touchModifiedAt) {
  const rows = await client.query(
    `SELECT id, "consultationHoursJson", "workHoursJson" FROM "${table}" WHERE "praxisId" = $1`,
    [praxisId],
  );
  const stats = { rowsRead: rows.rowCount, rowsModified: 0, slotsConsultation: 0, slotsWork: 0 };
  const setClause = touchModifiedAt
    ? `"consultationHoursJson" = $1, "workHoursJson" = $2, "modifiedAt" = NOW()`
    : `"consultationHoursJson" = $1, "workHoursJson" = $2`;
  for (const row of rows.rows) {
    const cons = _personioFixTransformBlob(row.consultationHoursJson, employeeId, mode, newEmployeeId);
    const work = _personioFixTransformBlob(row.workHoursJson, employeeId, mode, newEmployeeId);
    if (!cons.changed && !work.changed) continue;
    await client.query(
      `UPDATE "${table}" SET ${setClause} WHERE id = $3`,
      [cons.json, work.json, row.id],
    );
    stats.rowsModified++;
    stats.slotsConsultation += cons.touched;
    stats.slotsWork += work.touched;
  }
  return stats;
}

app.post('/api/personio/audit/fix', async (req, res) => {
  try {
    const envLabel = (req.headers['x-env-label'] || req.headers['x-env'] || '').toString().toLowerCase();
    if (envLabel === 'production' || envLabel === 'prod') {
      return res.status(400).json({ error: 'Refusing to write cockpit data on production.' });
    }
    const { actions } = req.body || {};
    if (!Array.isArray(actions) || !actions.length) {
      return res.status(400).json({ error: 'actions array required' });
    }

    const { pool } = poolFromHeaders(req);
    const client = await pool.connect();
    const results = [];
    try {
      await client.query('BEGIN');
      for (const action of actions) {
        const praxisId = Number(action.praxisId);
        const employeeId = Number(action.employeeId);
        const mode = action.mode;
        const newEmployeeId = action.newEmployeeId == null ? null : Number(action.newEmployeeId);
        if (!Number.isFinite(praxisId) || !Number.isFinite(employeeId) || (mode !== 'remove' && mode !== 'remap')) {
          results.push({ ...action, status: 'error', reason: 'invalid action shape' });
          continue;
        }
        if (mode === 'remap' && !Number.isFinite(newEmployeeId)) {
          results.push({ ...action, status: 'error', reason: 'newEmployeeId required for remap' });
          continue;
        }
        if (mode === 'remap' && employeeId === newEmployeeId) {
          results.push({ ...action, status: 'error', reason: 'newEmployeeId equals employeeId' });
          continue;
        }

        let pdeRows = 0;
        if (mode === 'remove') {
          const r = await client.query(
            `DELETE FROM cockpit_person_duration_exception WHERE "praxisId" = $1 AND "employeeId" = $2`,
            [praxisId, employeeId],
          );
          pdeRows = r.rowCount;
        } else {
          const r = await client.query(
            `UPDATE cockpit_person_duration_exception SET "employeeId" = $3, "modifiedAt" = NOW()
              WHERE "praxisId" = $1 AND "employeeId" = $2`,
            [praxisId, employeeId, newEmployeeId],
          );
          pdeRows = r.rowCount;
        }

        const swvStats = await _personioFixApplyJsonBlob(client, 'cockpit_standard_week_version', praxisId, employeeId, mode, newEmployeeId, false);
        const woStats  = await _personioFixApplyJsonBlob(client, 'cockpit_week_override',         praxisId, employeeId, mode, newEmployeeId, true);

        results.push({
          praxisId,
          employeeId,
          mode,
          newEmployeeId,
          status: 'ok',
          pde: pdeRows,
          standardWeekVersion: swvStats,
          weekOverride: woStats,
        });
      }
      await client.query('COMMIT');
    } catch (e) {
      try { await client.query('ROLLBACK'); } catch {}
      return res.status(500).json({ error: e.message, results });
    } finally {
      client.release();
    }

    res.json({ ok: true, results });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ── POST /api/cockpit/import ──────────────────────────────────────────────────
// Body: {
//   parsedSheets: [...],                   // result from /parse-excel
//   sheetToLcId: { 'Trier_Neu': 'lc_05' }, // operator-confirmed mapping
//   nameToEmployeeId: { 'Claudia W': 12 }, // operator-confirmed mapping (ints)
//   validFromIsoYear?: int, validFromIsoWeek?: int, // defaults to next Monday
//   replace?: boolean,                     // default true
// }
// For each (sheet → lcId) pair: deletes prior cockpit_standard_week_version +
// praxis_hours_config rows for that praxis (if replace), then inserts:
//   - praxis_hours_config: one row per opening slot
//   - cockpit_standard_week_version: one row with three JSON blobs.
// Refuses on production env-label unless triple-gated: x-allow-destructive: yes
// AND body.confirmation === 'IMPORT COCKPIT TO PRODUCTION'.
app.post('/api/cockpit/import', async (req, res) => {
  try {
    const envLabel = (req.headers['x-env-label'] || req.headers['x-env'] || '').toString().toLowerCase();
    if (envLabel === 'production' || envLabel === 'prod') {
      if (req.headers['x-allow-destructive'] !== 'yes') {
        return res.status(400).json({ error: `Refusing cockpit import on production: x-allow-destructive header must be 'yes'.` });
      }
      if ((req.body && req.body.confirmation) !== 'IMPORT COCKPIT TO PRODUCTION') {
        return res.status(400).json({ error: `Refusing cockpit import on production: body.confirmation must be the literal string 'IMPORT COCKPIT TO PRODUCTION'.` });
      }
    }
    const {
      parsedSheets,
      sheetToLcId = {},
      nameToEmployeeId = {},
      validFromIsoYear,
      validFromIsoWeek,
      replace = true,
      createdBy = 'helper-cockpit-fill',
    } = req.body || {};
    if (!Array.isArray(parsedSheets) || !parsedSheets.length) {
      return res.status(400).json({ error: 'parsedSheets array required' });
    }

    // Default validFrom to the upcoming Monday's ISO year/week.
    function isoYearWeek(d) {
      const dt = new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate()));
      const dayNum = (dt.getUTCDay() + 6) % 7; // Mon=0
      dt.setUTCDate(dt.getUTCDate() - dayNum + 3);
      const firstThursday = dt.getTime();
      const yearStart = new Date(Date.UTC(dt.getUTCFullYear(), 0, 4));
      const weekNum = 1 + Math.round((firstThursday - yearStart.getTime()) / (7 * 86400000));
      return { year: dt.getUTCFullYear(), week: weekNum };
    }
    const fallback = isoYearWeek(new Date());
    const isoYear = Number.isFinite(validFromIsoYear) ? validFromIsoYear : fallback.year;
    const isoWeek = Number.isFinite(validFromIsoWeek) ? validFromIsoWeek : fallback.week;

    const { pool } = poolFromHeaders(req);
    const client = await pool.connect();
    const results = [];
    try {
      await client.query('BEGIN');
      for (const sheet of parsedSheets) {
        const lcId = sheetToLcId[sheet.sheetName];
        if (!lcId) { results.push({ sheet: sheet.sheetName, status: 'skipped', reason: 'no praxis mapping' }); continue; }
        const found = await client.query(`SELECT id FROM praxis_config WHERE "lcId" = $1`, [lcId]);
        if (!found.rows.length) { results.push({ sheet: sheet.sheetName, lcId, status: 'error', reason: 'lcId not in praxis_config' }); continue; }
        const praxisDbId = found.rows[0].id;

        if (replace) {
          await client.query(`DELETE FROM praxis_hours_config WHERE "praxisId" = $1`, [praxisDbId]);
          await client.query(`DELETE FROM cockpit_standard_week_version WHERE "praxisId" = $1`, [praxisDbId]);
          await client.query(`DELETE FROM cockpit_week_override WHERE "praxisId" = $1`, [praxisDbId]);
        }

        // ── praxis_hours_config: one row per opening slot. Day stored as int enum.
        let openingInserted = 0;
        for (const slot of sheet.opening || []) {
          await client.query(
            `INSERT INTO praxis_hours_config ("praxisId", day, start, "end", "createdAt", "modifiedAt")
             VALUES ($1, $2, $3, $4, NOW(), NOW())`,
            [praxisDbId, COCKPIT_DAY_ENUM_INDEX[slot.weekday], slot.start, slot.end],
          );
          openingInserted++;
        }

        // ── cockpit_standard_week_version: build the three JSON blobs.
        const openingHoursJson = JSON.stringify(
          (sheet.opening || []).map(s => ({ weekday: s.weekday, start: s.start, end: s.end })),
        );
        const consultationSlots = [];
        let unmatchedNames = [];
        for (const c of sheet.consultation || []) {
          const empId = nameToEmployeeId[c.personName];
          if (!Number.isFinite(empId)) {
            if (!unmatchedNames.includes(c.personName)) unmatchedNames.push(c.personName);
            continue;
          }
          consultationSlots.push({
            weekday: c.weekday,
            employeeId: empId,
            kind: c.kind,
            start: c.start,
            end: c.end,
            onlineBookable: !!c.onlineBookable,
          });
        }
        const consultationHoursJson = JSON.stringify(consultationSlots);

        // workHoursJson: prefer Block 3 (Arbeitszeiten) entries — explicit
        // per-person AM/PM working slots, including MFAs that don't have any
        // consultation rows. For people whose name is in Block 2 only (no
        // Block 3 row), fall back to deriving a single span from the earliest
        // consultation start to the latest end on each day.
        const workSlots = [];
        const personsWithExplicitWork = new Set();
        for (const w of sheet.working || []) {
          const empId = nameToEmployeeId[w.personName];
          if (!Number.isFinite(empId)) {
            if (!unmatchedNames.includes(w.personName)) unmatchedNames.push(w.personName);
            continue;
          }
          personsWithExplicitWork.add(empId);
          workSlots.push({
            weekday: w.weekday,
            employeeId: empId,
            start: w.start,
            end: w.end,
            breakMin: w.breakMin || 0,
          });
        }
        const derivedByPersonDay = {};
        for (const c of sheet.consultation || []) {
          const empId = nameToEmployeeId[c.personName];
          if (!Number.isFinite(empId) || personsWithExplicitWork.has(empId)) continue;
          const key = `${empId}|${c.weekday}`;
          const ws = derivedByPersonDay[key] || { weekday: c.weekday, employeeId: empId, start: c.start, end: c.end, breakMin: 0 };
          if (c.start < ws.start) ws.start = c.start;
          if (c.end > ws.end) ws.end = c.end;
          derivedByPersonDay[key] = ws;
        }
        for (const ws of Object.values(derivedByPersonDay)) workSlots.push(ws);
        const workHoursJson = JSON.stringify(workSlots);

        await client.query(
          `INSERT INTO cockpit_standard_week_version
             ("praxisId", "validFromIsoYear", "validFromIsoWeek",
              "openingHoursJson", "consultationHoursJson", "workHoursJson",
              "createdAt", "createdBy")
           VALUES ($1, $2, $3, $4, $5, $6, NOW(), $7)`,
          [praxisDbId, isoYear, isoWeek, openingHoursJson, consultationHoursJson, workHoursJson, createdBy],
        );

        results.push({
          sheet: sheet.sheetName,
          lcId,
          praxisDbId,
          openingInserted,
          consultationSlots: consultationSlots.length,
          workSlotsAggregated: workSlots.length,
          unmatchedNames,
          status: 'ok',
        });
      }
      await client.query('COMMIT');
    } catch (e) {
      await client.query('ROLLBACK');
      throw new Error(`Import rolled back: ${e.message}`);
    } finally {
      client.release();
    }
    res.json({ ok: true, isoYear, isoWeek, results });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ─── Routes: single-praxis cleanup (deep delete + reference scrub) ──────────
//
// Removes every row that references a given lcId so the praxis can be safely
// re-created. Goes further than the praxis-refresh wipe: that one only clears
// the 25 praxis-config tables; this one also cleans the historical/user tables
// that hold the lcId as a string FK. User accounts are preserved (praxisId
// nulled), admin accounts are preserved (lcId removed from associatedPraxisIds).
// Audit log is kept. Refuses on production.
//
// Per-table action map — extend when new praxis-scoped tables are added.
const CLEANUP_NON_CONFIG_TABLES = {
  // numeric praxisId (FK to praxis_config.id) — DELETE rows for this praxis
  'app_user_appointment_reminder':       { mode: 'delete-by-numid' },
  'cockpit_person_duration_exception':   { mode: 'delete-by-numid' },
  'praxis_hours_sync_target':            { mode: 'delete-by-numid' },
  // string lcId — DELETE rows for this praxis
  'app_user_appointment':                { mode: 'delete-by-lcid' },
  'app_user_open_consultation':          { mode: 'delete-by-lcid' },
  'app_user_document_request':           { mode: 'delete-by-lcid' },
  'app_user_reserved_appointment':       { mode: 'delete-by-lcid' },
  'app_user_nps_sent':                   { mode: 'delete-by-lcid' },
  'guest_appointment':                   { mode: 'delete-by-lcid' },
  'questionnaire_reservation':           { mode: 'delete-by-lcid' },
  'fhir_nps':                            { mode: 'delete-by-lcid' },
  'app_user_pms_invitation':             { mode: 'delete-by-lcid' },
  // preserve account, drop the praxis link
  'app_user_info':                       { mode: 'null-by-lcid' },
  // preserve account, drop the lcId from the JSON array (handled in code)
  'admin_user_info':                     { mode: 'remove-from-json-array' },
  // historical record — keep as-is
  'admin_audit_log':                     { mode: 'keep' },
};

// Returns a Set of table names that exist on the env addressed by `req`.
// Used by cleanup endpoints so a missing table (envs at different migration
// levels) doesn't abort the whole transaction with "relation does not exist".
async function existingPublicTables(req) {
  const rows = await query(req, `SELECT table_name FROM information_schema.tables WHERE table_schema = 'public'`);
  return new Set(rows.map(r => r.table_name));
}

// ── POST /api/praxis/cleanup-preview ─────────────────────────────────────────
// Body: { lcId: string }. Read-only. Returns per-table row counts that would
// be DELETEd, NULLed, or filtered for this lcId. Missing tables are flagged
// as `{ missing: true }` rather than blowing up.
app.post('/api/praxis/cleanup-preview', async (req, res) => {
  try {
    const { lcId } = req.body || {};
    if (!lcId) return res.status(400).json({ error: 'lcId is required' });
    const found = await query(req, `SELECT id, name FROM praxis_config WHERE "lcId" = $1`, [lcId]);
    if (!found.length) return res.status(404).json({ error: `lcId '${lcId}' not found` });
    const numId = found[0].id;
    const present = await existingPublicTables(req);
    const counts = { lcId, name: found[0].name, praxisDbId: numId, configTables: {}, nonConfigTables: {} };
    // Root praxis_config row always counts as 1 here (we already located it).
    counts.configTables['praxis_config'] = 1;
    for (const t of PRAXIS_CONFIG_TABLES.slice(1)) {
      if (!present.has(t)) { counts.configTables[t] = { missing: true }; continue; }
      try {
        const r = await query(req, `SELECT count(*)::int AS n FROM ${quoteIdent(t)} WHERE "praxisId" = $1`, [numId]);
        counts.configTables[t] = r[0].n;
      } catch (e) { counts.configTables[t] = { error: e.message }; }
    }

    for (const [t, spec] of Object.entries(CLEANUP_NON_CONFIG_TABLES)) {
      if (!present.has(t)) { counts.nonConfigTables[t] = { mode: spec.mode, missing: true }; continue; }
      try {
        if (spec.mode === 'delete-by-numid') {
          const r = await query(req, `SELECT count(*)::int AS n FROM ${quoteIdent(t)} WHERE "praxisId" = $1`, [numId]);
          counts.nonConfigTables[t] = { mode: spec.mode, rows: r[0].n };
        } else if (spec.mode === 'delete-by-lcid' || spec.mode === 'null-by-lcid') {
          const r = await query(req, `SELECT count(*)::int AS n FROM ${quoteIdent(t)} WHERE "praxisId" = $1`, [lcId]);
          counts.nonConfigTables[t] = { mode: spec.mode, rows: r[0].n };
        } else if (spec.mode === 'remove-from-json-array') {
          const r = await query(req, `SELECT count(*)::int AS n FROM ${quoteIdent(t)} WHERE "associatedPraxisIds"::text LIKE $1`, [`%${lcId}%`]);
          counts.nonConfigTables[t] = { mode: spec.mode, rows: r[0].n };
        } else {
          counts.nonConfigTables[t] = { mode: spec.mode, rows: 0 };
        }
      } catch (e) { counts.nonConfigTables[t] = { mode: spec.mode, error: e.message }; }
    }
    res.json({ ok: true, ...counts });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ── POST /api/praxis/cleanup ─────────────────────────────────────────────────
// Body: { lcId: string, confirmation: string }. confirmation must equal lcId.
// Headers: standard x-db-* + `x-allow-destructive: yes`. Refuses on production.
// Performs the full cleanup in a single transaction. Returns per-table action
// counts; rolls back the whole batch on any error.
app.post('/api/praxis/cleanup', async (req, res) => {
  try {
    const envLabel = (req.headers['x-env-label'] || req.headers['x-env'] || '').toString().toLowerCase();
    if (envLabel === 'production' || envLabel === 'prod') {
      return res.status(400).json({ error: 'Refusing to delete praxis on production.' });
    }
    if (req.headers['x-allow-destructive'] !== 'yes') {
      return res.status(400).json({ error: `x-allow-destructive: yes required.` });
    }
    const { lcId, confirmation } = req.body || {};
    if (!lcId) return res.status(400).json({ error: 'lcId is required' });
    if (confirmation !== lcId) return res.status(400).json({ error: `body.confirmation must equal the lcId ('${lcId}').` });

    const found = await query(req, `SELECT id, name FROM praxis_config WHERE "lcId" = $1`, [lcId]);
    if (!found.length) return res.status(404).json({ error: `lcId '${lcId}' not found` });
    const numId = found[0].id;
    const present = await existingPublicTables(req);

    const { pool } = poolFromHeaders(req);
    const client = await pool.connect();
    const result = {
      lcId,
      name: found[0].name,
      praxisDbId: numId,
      configDeletedRows: {},
      nonConfigActions: {},
      skippedMissing: [],
    };
    try {
      await client.query('BEGIN');

      // 1) Child praxis-config tables in reverse FK order. praxis_config (root)
      //    is at index 0 and gets deleted last, by `id` not `praxisId`.
      const childTablesReverse = PRAXIS_CONFIG_TABLES.slice(1).reverse();
      for (const t of childTablesReverse) {
        if (!present.has(t)) { result.configDeletedRows[t] = { missing: true }; result.skippedMissing.push(t); continue; }
        const r = await client.query(`DELETE FROM ${quoteIdent(t)} WHERE "praxisId" = $1`, [numId]);
        result.configDeletedRows[t] = r.rowCount;
      }

      // 2) Non-config tables — DELETE / NULL / filter as configured.
      for (const [t, spec] of Object.entries(CLEANUP_NON_CONFIG_TABLES)) {
        if (spec.mode === 'keep') {
          result.nonConfigActions[t] = { mode: spec.mode, rows: 0 };
          continue;
        }
        if (!present.has(t)) {
          result.nonConfigActions[t] = { mode: spec.mode, missing: true };
          result.skippedMissing.push(t);
          continue;
        }
        if (spec.mode === 'delete-by-numid') {
          const r = await client.query(`DELETE FROM ${quoteIdent(t)} WHERE "praxisId" = $1`, [numId]);
          result.nonConfigActions[t] = { mode: spec.mode, rows: r.rowCount };
        } else if (spec.mode === 'delete-by-lcid') {
          const r = await client.query(`DELETE FROM ${quoteIdent(t)} WHERE "praxisId" = $1`, [lcId]);
          result.nonConfigActions[t] = { mode: spec.mode, rows: r.rowCount };
        } else if (spec.mode === 'null-by-lcid') {
          const r = await client.query(`UPDATE ${quoteIdent(t)} SET "praxisId" = NULL WHERE "praxisId" = $1`, [lcId]);
          result.nonConfigActions[t] = { mode: spec.mode, rows: r.rowCount };
        } else if (spec.mode === 'remove-from-json-array') {
          // admin_user_info.associatedPraxisIds is JSON of array<string>. Pull
          // affected rows, filter the array in JS, write back.
          const rows = await client.query(
            `SELECT id, "associatedPraxisIds" FROM ${quoteIdent(t)} WHERE "associatedPraxisIds"::text LIKE $1`,
            [`%${lcId}%`],
          );
          let updated = 0;
          for (const row of rows.rows) {
            const arr = Array.isArray(row.associatedPraxisIds)
              ? row.associatedPraxisIds
              : (typeof row.associatedPraxisIds === 'string' ? JSON.parse(row.associatedPraxisIds) : []);
            const filtered = arr.filter(x => x !== lcId);
            if (filtered.length !== arr.length) {
              await client.query(`UPDATE ${quoteIdent(t)} SET "associatedPraxisIds" = $1::json WHERE id = $2`, [JSON.stringify(filtered), row.id]);
              updated++;
            }
          }
          result.nonConfigActions[t] = { mode: spec.mode, rows: updated };
        }
      }

      // 3) Finally, delete the praxis_config root by id.
      const rootDel = await client.query(`DELETE FROM praxis_config WHERE id = $1`, [numId]);
      result.configDeletedRows['praxis_config'] = rootDel.rowCount;

      await client.query('COMMIT');
    } catch (e) {
      try { await client.query('ROLLBACK'); } catch {}
      throw new Error(`Cleanup rolled back: ${e.message}`);
    } finally {
      client.release();
    }
    res.json({ ok: true, ...result });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ─── Routes: cockpit cross-env sync (export from one env, import to another) ──
//
// Copies the 5 cockpit-relevant tables for selected praxes between two envs.
// Praxes are matched by `lcId` (numeric `id` differs across envs); the numeric
// `praxisId` FK is remapped on insert. Personio `employeeId`s inside the JSON
// blobs are global IDs and cross envs unchanged. Refuses on production target.

const COCKPIT_SYNC_TABLES = [
  'praxis_hours_config',
  'cockpit_standard_week_version',
  'cockpit_appointment_type_matrix',
  'cockpit_week_override',
  'cockpit_person_duration_exception',
];

// ── POST /api/cockpit/source-summary ──────────────────────────────────────────
// Headers: x-src-db-* (single env). Body: { lcIds?: string[] }
// Returns per-praxis row counts across the 5 cockpit tables, so the UI can
// preview what would be copied before committing.
app.post('/api/cockpit/source-summary', async (req, res) => {
  try {
    const { lcIds } = req.body || {};
    const src = poolFromHeaders(req, 'x-src-db-');
    const praxRows = lcIds && lcIds.length
      ? await poolQuery(src.pool, `SELECT id, "lcId", name FROM praxis_config WHERE "lcId" = ANY($1::text[]) ORDER BY "lcId"`, [lcIds])
      : await poolQuery(src.pool, `SELECT id, "lcId", name FROM praxis_config ORDER BY "lcId"`);
    const out = [];
    for (const p of praxRows) {
      const counts = {};
      for (const t of COCKPIT_SYNC_TABLES) {
        try {
          const r = await poolQuery(src.pool, `SELECT count(*)::int AS n FROM ${quoteIdent(t)} WHERE "praxisId" = $1`, [p.id]);
          counts[t] = r[0].n;
        } catch (e) {
          counts[t] = { error: e.message };
        }
      }
      out.push({ lcId: p.lcId, name: p.name, counts });
    }
    res.json({ ok: true, rows: out });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ── POST /api/cockpit/cross-env-copy ──────────────────────────────────────────
// Headers: x-src-db-* AND x-tgt-db-*. Body: { lcIds?: string[], replace?: bool }
// Defaults to all praxes on source, replace=true.
// For each src praxis, looks up tgt praxis by lcId. If src has no match on tgt,
// the praxis is skipped (logged). For each cockpit table:
//   - replace mode: DELETE rows on tgt where praxisId = tgt's mapped id
//   - then INSERT every src row with praxisId remapped to tgt
// Refuses if target env-label is production.
app.post('/api/cockpit/cross-env-copy', async (req, res) => {
  try {
    const tgtEnvLabel = (req.headers['x-tgt-env-label'] || '').toString().toLowerCase();
    if (tgtEnvLabel === 'production' || tgtEnvLabel === 'prod') {
      return res.status(400).json({ error: 'Refusing to write cockpit data on production target.' });
    }

    const { lcIds, replace = true } = req.body || {};
    const src = poolFromHeaders(req, 'x-src-db-');
    const tgt = poolFromHeaders(req, 'x-tgt-db-');
    if (`${src.host}:${src.port}/${src.database}` === `${tgt.host}:${tgt.port}/${tgt.database}`) {
      return res.status(400).json({ error: 'Source and target databases must be different.' });
    }

    const srcPraxes = lcIds && lcIds.length
      ? await poolQuery(src.pool, `SELECT id, "lcId", name FROM praxis_config WHERE "lcId" = ANY($1::text[]) ORDER BY "lcId"`, [lcIds])
      : await poolQuery(src.pool, `SELECT id, "lcId", name FROM praxis_config ORDER BY "lcId"`);
    if (!srcPraxes.length) return res.json({ ok: true, results: [], message: 'No source praxes.' });

    // Look up target praxis ids by lcId in one query.
    const tgtMap = {};
    {
      const rows = await poolQuery(tgt.pool, `SELECT id, "lcId" FROM praxis_config WHERE "lcId" = ANY($1::text[])`, [srcPraxes.map(p => p.lcId)]);
      for (const r of rows) tgtMap[r.lcId] = r.id;
    }

    // Cache target column metadata (json/jsonb columns need bindValue serialization).
    const colsByTable = {};
    for (const t of COCKPIT_SYNC_TABLES) {
      colsByTable[t] = await tableColumns(tgt.pool, t);
    }

    const tgtClient = await tgt.pool.connect();
    const results = [];
    try {
      await tgtClient.query('BEGIN');
      for (const srcPraxis of srcPraxes) {
        const tgtPraxisId = tgtMap[srcPraxis.lcId];
        if (!tgtPraxisId) {
          results.push({ lcId: srcPraxis.lcId, status: 'skipped', reason: 'praxis not on target' });
          continue;
        }

        const perTable = {};
        for (const t of COCKPIT_SYNC_TABLES) {
          if (replace) {
            await tgtClient.query(`DELETE FROM ${quoteIdent(t)} WHERE "praxisId" = $1`, [tgtPraxisId]);
          }
          let srcRows;
          try {
            srcRows = await poolQuery(src.pool, `SELECT * FROM ${quoteIdent(t)} WHERE "praxisId" = $1`, [srcPraxis.id]);
          } catch (e) {
            // Source may not have the table (cross-version envs).
            perTable[t] = { skipped: e.message };
            continue;
          }
          if (!srcRows.length) { perTable[t] = 0; continue; }
          const cols = colsByTable[t].filter(c => c.column_name !== 'id');
          const colList = cols.map(c => quoteIdent(c.column_name)).join(',');
          const placeholders = cols.map((_, i) => `$${i + 1}`).join(',');
          for (const row of srcRows) {
            const values = cols.map(c =>
              c.column_name === 'praxisId' ? tgtPraxisId : bindValue(c, row[c.column_name])
            );
            await tgtClient.query(`INSERT INTO ${quoteIdent(t)} (${colList}) VALUES (${placeholders})`, values);
          }
          perTable[t] = srcRows.length;
        }
        results.push({ lcId: srcPraxis.lcId, name: srcPraxis.name, tgtPraxisId, status: 'ok', perTable });
      }
      await tgtClient.query('COMMIT');
    } catch (e) {
      await tgtClient.query('ROLLBACK');
      throw new Error(`Cockpit sync rolled back: ${e.message}`);
    } finally {
      tgtClient.release();
    }
    res.json({ ok: true, replace, results });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ═════════════════════════════════════════════════════════════════════════════
// RDS RESTORE wizard (`/api/rds-restore/*`, view `#rds-restore`)
// Single-table restore from a snapshot or PITR. Each endpoint maps to one card
// in the UI. Destructive endpoints require an explicit body confirmation.
// ═════════════════════════════════════════════════════════════════════════════

function rdsClientFor(region) {
  return region && region !== AWS_REGION ? new RDSClient({ region }) : rdsClient;
}

// ── POST /api/rds-restore/aws/describe-cluster ────────────────────────────────
// Body: { region, clusterId }. Returns cluster + first-instance config so the
// UI can auto-fill engine, subnet, security group, instance class.
app.post('/api/rds-restore/aws/describe-cluster', async (req, res) => {
  try {
    const { region, clusterId } = req.body || {};
    if (!clusterId) return res.status(400).json({ error: 'clusterId required' });
    const client = rdsClientFor(region);

    // Try Aurora cluster first.
    let clusterFound = null;
    try {
      const clusters = await client.send(new DescribeDBClustersCommand({ DBClusterIdentifier: clusterId }));
      clusterFound = clusters.DBClusters && clusters.DBClusters[0];
    } catch (e) {
      if (!/not found/i.test(e.message) && e.name !== 'DBClusterNotFoundFault') throw e;
    }

    if (clusterFound) {
      const c = clusterFound;
      const instances = await client.send(new DescribeDBInstancesCommand({
        Filters: [{ Name: 'db-cluster-id', Values: [clusterId] }],
      }));
      const i = instances.DBInstances && instances.DBInstances[0];
      return res.json({
        kind: 'cluster',
        cluster: {
          engine: c.Engine,
          engineVersion: c.EngineVersion,
          endpoint: c.Endpoint,
          port: c.Port,
          masterUser: c.MasterUsername,
          subnetGroup: c.DBSubnetGroup,
          securityGroups: (c.VpcSecurityGroups || []).map(s => s.VpcSecurityGroupId),
          earliestRestorableTime: c.EarliestRestorableTime,
          latestRestorableTime: c.LatestRestorableTime,
          status: c.Status,
        },
        instance: i ? {
          instanceClass: i.DBInstanceClass,
          publiclyAccessible: i.PubliclyAccessible,
          availabilityZone: i.AvailabilityZone,
        } : null,
      });
    }

    // Fall back to regular RDS instance.
    const instOut = await client.send(new DescribeDBInstancesCommand({ DBInstanceIdentifier: clusterId }));
    const i = instOut.DBInstances && instOut.DBInstances[0];
    if (!i) return res.status(404).json({ error: `Neither cluster nor instance found for "${clusterId}"` });
    return res.json({
      kind: 'instance',
      cluster: {
        engine: i.Engine,
        engineVersion: i.EngineVersion,
        endpoint: i.Endpoint?.Address || null,
        port: i.Endpoint?.Port || null,
        masterUser: i.MasterUsername,
        subnetGroup: i.DBSubnetGroup?.DBSubnetGroupName,
        securityGroups: (i.VpcSecurityGroups || []).map(s => s.VpcSecurityGroupId),
        earliestRestorableTime: i.EarliestRestorableTime,
        latestRestorableTime: i.LatestRestorableTime,
        status: i.DBInstanceStatus,
      },
      instance: {
        instanceClass: i.DBInstanceClass,
        publiclyAccessible: i.PubliclyAccessible,
        availabilityZone: i.AvailabilityZone,
      },
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ── POST /api/rds-restore/aws/restore-cluster ─────────────────────────────────
// Body: {
//   region, mode: 'snapshot' | 'pitr',
//   tempClusterId, engine, engineVersion, subnetGroup, securityGroups: [],
//   // mode=snapshot:
//   snapshotId,
//   // mode=pitr:
//   srcClusterId, pitrTime (ISO),
//   confirm: 'YES'
// }
app.post('/api/rds-restore/aws/restore-cluster', async (req, res) => {
  try {
    const b = req.body || {};
    if (b.confirm !== 'YES') return res.status(400).json({ error: 'Body confirm must be "YES" (creates a new billable resource)' });
    if (!b.subnetGroup) return res.status(400).json({ error: 'subnetGroup required' });
    if (!b.securityGroups || !b.securityGroups.length) return res.status(400).json({ error: 'securityGroups required' });
    const client = rdsClientFor(b.region);
    const kind = b.kind === 'instance' ? 'instance' : 'cluster';

    if (kind === 'cluster') {
      if (!b.tempClusterId) return res.status(400).json({ error: 'tempClusterId required' });
      if (b.mode === 'pitr') {
        if (!b.srcClusterId) return res.status(400).json({ error: 'srcClusterId required for PITR' });
        if (!b.pitrTime) return res.status(400).json({ error: 'pitrTime required for PITR' });
        const out = await client.send(new RestoreDBClusterToPointInTimeCommand({
          DBClusterIdentifier: b.tempClusterId,
          SourceDBClusterIdentifier: b.srcClusterId,
          RestoreToTime: new Date(b.pitrTime),
          DBSubnetGroupName: b.subnetGroup,
          VpcSecurityGroupIds: b.securityGroups,
        }));
        return res.json({ kind, identifier: b.tempClusterId, arn: out.DBCluster?.DBClusterArn, status: out.DBCluster?.Status });
      }
      if (!b.snapshotId) return res.status(400).json({ error: 'snapshotId required for snapshot mode' });
      const out = await client.send(new RestoreDBClusterFromSnapshotCommand({
        DBClusterIdentifier: b.tempClusterId,
        SnapshotIdentifier: b.snapshotId,
        Engine: b.engine || 'aurora-postgresql',
        EngineVersion: b.engineVersion || undefined,
        DBSubnetGroupName: b.subnetGroup,
        VpcSecurityGroupIds: b.securityGroups,
      }));
      return res.json({ kind, identifier: b.tempClusterId, arn: out.DBCluster?.DBClusterArn, status: out.DBCluster?.Status });
    }

    // kind === 'instance' — regular RDS. The restore call creates the new
    // instance directly; there is no separate cluster + create-instance step.
    if (!b.tempInstanceId) return res.status(400).json({ error: 'tempInstanceId required for instance mode' });
    if (b.mode === 'pitr') {
      if (!b.srcClusterId) return res.status(400).json({ error: 'srcClusterId required for PITR (source instance id)' });
      if (!b.pitrTime) return res.status(400).json({ error: 'pitrTime required for PITR' });
      const out = await client.send(new RestoreDBInstanceToPointInTimeCommand({
        SourceDBInstanceIdentifier: b.srcClusterId,
        TargetDBInstanceIdentifier: b.tempInstanceId,
        RestoreTime: new Date(b.pitrTime),
        DBSubnetGroupName: b.subnetGroup,
        VpcSecurityGroupIds: b.securityGroups,
        DBInstanceClass: b.instanceClass || undefined,
        PubliclyAccessible: !!b.publiclyAccessible,
      }));
      return res.json({ kind, identifier: b.tempInstanceId, arn: out.DBInstance?.DBInstanceArn, status: out.DBInstance?.DBInstanceStatus });
    }
    if (!b.snapshotId) return res.status(400).json({ error: 'snapshotId required for snapshot mode' });
    const out = await client.send(new RestoreDBInstanceFromDBSnapshotCommand({
      DBInstanceIdentifier: b.tempInstanceId,
      DBSnapshotIdentifier: b.snapshotId,
      DBSubnetGroupName: b.subnetGroup,
      VpcSecurityGroupIds: b.securityGroups,
      DBInstanceClass: b.instanceClass || undefined,
      Engine: b.engine || 'postgres',
      PubliclyAccessible: !!b.publiclyAccessible,
    }));
    return res.json({ kind, identifier: b.tempInstanceId, arn: out.DBInstance?.DBInstanceArn, status: out.DBInstance?.DBInstanceStatus });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ── POST /api/rds-restore/aws/create-instance ─────────────────────────────────
// Body: { region, tempClusterId, tempInstanceId, instanceClass, engine, publiclyAccessible, confirm: 'YES' }
app.post('/api/rds-restore/aws/create-instance', async (req, res) => {
  try {
    const b = req.body || {};
    if (b.confirm !== 'YES') return res.status(400).json({ error: 'Body confirm must be "YES" (creates a billable instance)' });
    if (!b.tempClusterId || !b.tempInstanceId) return res.status(400).json({ error: 'tempClusterId and tempInstanceId required' });
    const client = rdsClientFor(b.region);
    const out = await client.send(new CreateDBInstanceCommand({
      DBInstanceIdentifier: b.tempInstanceId,
      DBClusterIdentifier: b.tempClusterId,
      DBInstanceClass: b.instanceClass || 'db.t3.medium',
      Engine: b.engine || 'aurora-postgresql',
      PubliclyAccessible: !!b.publiclyAccessible,
    }));
    res.json({ instanceArn: out.DBInstance?.DBInstanceArn, status: out.DBInstance?.DBInstanceStatus });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ── POST /api/rds-restore/aws/instance-status ─────────────────────────────────
// Body: { region, tempInstanceId }. Returns { status, endpoint }. Frontend
// polls this in a loop until status === 'available'.
app.post('/api/rds-restore/aws/instance-status', async (req, res) => {
  try {
    const { region, tempInstanceId, tempClusterId } = req.body || {};
    if (!tempInstanceId) return res.status(400).json({ error: 'tempInstanceId required' });
    const client = rdsClientFor(region);
    const inst = await client.send(new DescribeDBInstancesCommand({ DBInstanceIdentifier: tempInstanceId }));
    const i = inst.DBInstances && inst.DBInstances[0];
    let endpoint = null;
    if (tempClusterId) {
      try {
        const cl = await client.send(new DescribeDBClustersCommand({ DBClusterIdentifier: tempClusterId }));
        endpoint = cl.DBClusters?.[0]?.Endpoint || null;
      } catch (_) { /* cluster might not exist (instance mode) */ }
    }
    if (!endpoint) endpoint = i?.Endpoint?.Address || null;
    res.json({
      status: i?.DBInstanceStatus || 'unknown',
      endpoint,
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ── POST /api/rds-restore/aws/delete-instance ─────────────────────────────────
app.post('/api/rds-restore/aws/delete-instance', async (req, res) => {
  try {
    const b = req.body || {};
    if (b.confirm !== 'YES') return res.status(400).json({ error: 'Body confirm must be "YES" (destroys the temp instance)' });
    if (!b.tempInstanceId) return res.status(400).json({ error: 'tempInstanceId required' });
    const client = rdsClientFor(b.region);
    const out = await client.send(new DeleteDBInstanceCommand({
      DBInstanceIdentifier: b.tempInstanceId,
      SkipFinalSnapshot: true,
      DeleteAutomatedBackups: true,
    }));
    res.json({ status: out.DBInstance?.DBInstanceStatus });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ── POST /api/rds-restore/aws/delete-cluster ──────────────────────────────────
app.post('/api/rds-restore/aws/delete-cluster', async (req, res) => {
  try {
    const b = req.body || {};
    if (b.confirm !== 'YES') return res.status(400).json({ error: 'Body confirm must be "YES" (destroys the temp cluster)' });
    if (!b.tempClusterId) return res.status(400).json({ error: 'tempClusterId required' });
    const client = rdsClientFor(b.region);
    const out = await client.send(new DeleteDBClusterCommand({
      DBClusterIdentifier: b.tempClusterId,
      SkipFinalSnapshot: true,
    }));
    res.json({ status: out.DBCluster?.Status });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ── POST /api/rds-restore/pg/connect-test ─────────────────────────────────────
// Uses `x-rdsr-<side>-db-*` headers (side: 'temp' or 'prod'). Just runs a
// SELECT 1 against the targeted connection so the UI can show green/red.
app.post('/api/rds-restore/pg/connect-test', async (req, res) => {
  try {
    const side = (req.body?.side === 'prod') ? 'prod' : 'temp';
    const { pool, host, database, user } = poolFromHeaders(req, `x-rdsr-${side}-db-`);
    const rows = await poolQuery(pool, 'SELECT current_database() AS db, current_user AS u, version()');
    res.json({ ok: true, host, database, user, info: rows[0] });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ── POST /api/rds-restore/pg/preview ──────────────────────────────────────────
// Body: { table }, headers: x-rdsr-temp-db-*. Read-only summary of the table.
app.post('/api/rds-restore/pg/preview', async (req, res) => {
  try {
    const { table } = req.body || {};
    if (!table || !/^[A-Za-z_][A-Za-z0-9_]*$/.test(table)) return res.status(400).json({ error: 'Invalid table name' });
    const { pool } = poolFromHeaders(req, 'x-rdsr-temp-db-');
    const cols = await tableColumns(pool, table);
    if (!cols.length) return res.status(404).json({ error: `Table ${table} not found on temp` });
    const colList = cols.map(c => quoteIdent(c.column_name)).join(', ');
    const [{ count }] = await poolQuery(pool, `SELECT COUNT(*)::bigint AS count FROM ${quoteIdent(table)}`);
    const sample = await poolQuery(pool, `SELECT ${colList} FROM ${quoteIdent(table)} ORDER BY ${cols.some(c => c.column_name === 'id') ? '"id" DESC' : '1'} LIMIT 5`);
    res.json({ count: Number(count), columns: cols, sample });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ── POST /api/rds-restore/pg/schema-diff ──────────────────────────────────────
// Body: { table }. Headers: BOTH x-rdsr-temp-db-* and x-rdsr-prod-db-*.
app.post('/api/rds-restore/pg/schema-diff', async (req, res) => {
  try {
    const { table } = req.body || {};
    if (!table || !/^[A-Za-z_][A-Za-z0-9_]*$/.test(table)) return res.status(400).json({ error: 'Invalid table name' });
    const { pool: tempPool } = poolFromHeaders(req, 'x-rdsr-temp-db-');
    const { pool: prodPool } = poolFromHeaders(req, 'x-rdsr-prod-db-');
    const [tempCols, prodCols] = await Promise.all([
      tableColumns(tempPool, table),
      tableColumns(prodPool, table),
    ]);
    if (!tempCols.length) return res.status(404).json({ error: `Table ${table} not found on temp` });
    if (!prodCols.length) return res.status(404).json({ error: `Table ${table} not found on prod` });

    const tempByName = Object.fromEntries(tempCols.map(c => [c.column_name, c]));
    const prodByName = Object.fromEntries(prodCols.map(c => [c.column_name, c]));
    const matched = [];
    const typeMismatch = [];
    const tempOnly = [];
    const prodOnly = [];
    for (const t of tempCols) {
      const p = prodByName[t.column_name];
      if (!p) { tempOnly.push(t); continue; }
      if (t.data_type !== p.data_type || t.udt_name !== p.udt_name) {
        typeMismatch.push({ name: t.column_name, temp: t, prod: p });
      } else {
        matched.push({ name: t.column_name, temp: t, prod: p });
      }
    }
    for (const p of prodCols) {
      if (!tempByName[p.column_name]) prodOnly.push(p);
    }
    res.json({ tempCols, prodCols, matched, typeMismatch, tempOnly, prodOnly });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ── POST /api/rds-restore/pg/restore-table ────────────────────────────────────
// Body: { table, mapping: { prodCol: tempCol }, confirmTable: '<table>' }.
// Headers: BOTH x-rdsr-temp-db-* and x-rdsr-prod-db-*.
// Refuses if prod table has any rows. Wraps entire copy in a transaction.
app.post('/api/rds-restore/pg/restore-table', async (req, res) => {
  try {
    const { table, mapping, confirmTable } = req.body || {};
    if (!table || !/^[A-Za-z_][A-Za-z0-9_]*$/.test(table)) return res.status(400).json({ error: 'Invalid table name' });
    if (confirmTable !== table) return res.status(400).json({ error: 'confirmTable must exactly equal the table name' });
    if (!mapping || typeof mapping !== 'object' || !Object.keys(mapping).length) return res.status(400).json({ error: 'mapping required' });
    const { pool: tempPool } = poolFromHeaders(req, 'x-rdsr-temp-db-');
    const { pool: prodPool } = poolFromHeaders(req, 'x-rdsr-prod-db-');

    // 1. Validate both tables exist.
    const [tempCols, prodCols] = await Promise.all([
      tableColumns(tempPool, table),
      tableColumns(prodPool, table),
    ]);
    if (!tempCols.length) return res.status(404).json({ error: `Table ${table} not found on temp` });
    if (!prodCols.length) return res.status(404).json({ error: `Table ${table} not found on prod` });
    const tempByName = Object.fromEntries(tempCols.map(c => [c.column_name, c]));
    const prodByName = Object.fromEntries(prodCols.map(c => [c.column_name, c]));
    const prodColNames = Object.keys(mapping);
    const tempColNames = prodColNames.map(p => mapping[p]);
    for (const p of prodColNames) {
      if (!prodByName[p]) return res.status(400).json({ error: `mapping target column "${p}" not on prod` });
    }
    for (const t of tempColNames) {
      if (!tempByName[t]) return res.status(400).json({ error: `mapping source column "${t}" not on temp` });
    }

    // 2. Refuse if prod table is non-empty.
    const [{ count: prodCount }] = await poolQuery(prodPool, `SELECT COUNT(*)::bigint AS count FROM ${quoteIdent(table)}`);
    if (BigInt(prodCount) > 0n) return res.status(409).json({ error: `Refusing: prod table has ${prodCount} rows`, prodCount: Number(prodCount) });

    // 3. Stream rows from temp via cursor, insert in batches into prod inside a transaction.
    const BATCH = 500;
    const selectSql = `SELECT ${tempColNames.map(quoteIdent).join(', ')} FROM ${quoteIdent(table)}` +
      (tempByName['id'] ? ` ORDER BY "id"` : '');
    const insertSql = `INSERT INTO ${quoteIdent(table)} (${prodColNames.map(quoteIdent).join(', ')}) VALUES (${prodColNames.map((_, i) => '$' + (i + 1)).join(', ')})`;

    const tempClient = await tempPool.connect();
    const prodClient = await prodPool.connect();
    let copied = 0;
    const start = Date.now();
    try {
      await tempClient.query('BEGIN');
      await tempClient.query(`DECLARE rdsr_cur NO SCROLL CURSOR FOR ${selectSql}`);
      await prodClient.query('BEGIN');
      while (true) {
        const batch = await tempClient.query(`FETCH ${BATCH} FROM rdsr_cur`);
        if (!batch.rows.length) break;
        for (const row of batch.rows) {
          const values = prodColNames.map(p => bindValue(prodByName[p], row[mapping[p]]));
          await prodClient.query(insertSql, values);
        }
        copied += batch.rows.length;
      }
      await tempClient.query('COMMIT');
      await prodClient.query('COMMIT');
    } catch (e) {
      await prodClient.query('ROLLBACK').catch(() => {});
      await tempClient.query('ROLLBACK').catch(() => {});
      throw e;
    } finally {
      tempClient.release();
      prodClient.release();
    }

    res.json({ copied, durationMs: Date.now() - start });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ── POST /api/rds-restore/pg/setval ───────────────────────────────────────────
// Body: { table, idColumn = 'id' }. Headers: x-rdsr-prod-db-*.
app.post('/api/rds-restore/pg/setval', async (req, res) => {
  try {
    const { table, idColumn } = req.body || {};
    const col = idColumn || 'id';
    if (!table || !/^[A-Za-z_][A-Za-z0-9_]*$/.test(table)) return res.status(400).json({ error: 'Invalid table name' });
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(col)) return res.status(400).json({ error: 'Invalid id column' });
    const { pool } = poolFromHeaders(req, 'x-rdsr-prod-db-');
    const rows = await poolQuery(pool,
      `SELECT setval(
         pg_get_serial_sequence($1, $2),
         GREATEST(COALESCE((SELECT MAX(${quoteIdent(col)}) FROM ${quoteIdent(table)}), 0), 1),
         TRUE
       ) AS newval`, [table, col]);
    res.json({ newval: rows[0]?.newval });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ═══ DB Refresh ════════════════════════════════════════════════════════════════
// Wipe a target env's database and copy the full public schema from any other
// env. Sources: dev/test/staging/production. Targets: dev/test/staging only —
// production can NEVER be a target (its hosts are hard-refused regardless of
// labels). The target label must match the env its host belongs to, so a label
// cannot be spoofed onto another host; the source session is physically
// read-only; the copy is one transaction on the target.

// Tables truncated on the target but NOT refilled from source (log/telemetry
// noise — huge on prod and useless elsewhere).
const DB_REFRESH_SKIP_TABLES = [
  'serverpod_log',
  'serverpod_session_log',
  'serverpod_query_log',
  'serverpod_message_log',
  'serverpod_health_connection_info',
  'serverpod_health_metric',
  'serverpod_readwrite_test',
];

// Env → the only hosts that env may resolve to (friendly CNAME + raw RDS endpoint).
const DB_REFRESH_ENV_HOSTS = {
  dev:        ['localhost', '127.0.0.1'],
  test:       ['database-test.lillian.care', 'lc-core-test.clyg4y6ua706.eu-central-1.rds.amazonaws.com'],
  staging:    ['database-staging.lillian.care', 'lc-core-staging.clyg4y6ua706.eu-central-1.rds.amazonaws.com'],
  production: ['database.lillian.care', 'lc-core.clyg4y6ua706.eu-central-1.rds.amazonaws.com'],
};

// Envs that may be overwritten. Production is deliberately absent.
const DB_REFRESH_TARGET_ENVS = ['dev', 'test', 'staging'];

// Hosts that must NEVER be a target, regardless of labels.
const DB_REFRESH_PROTECTED_HOSTS = DB_REFRESH_ENV_HOSTS.production;

function drEnvForHost(host) {
  const h = (host || '').toLowerCase();
  return Object.keys(DB_REFRESH_ENV_HOSTS).find((env) => DB_REFRESH_ENV_HOSTS[env].includes(h)) || null;
}

// Typed confirmation the run endpoint expects for a target env.
function drConfirmationFor(env) {
  return `REFRESH ${env.toUpperCase()}`;
}

// Connection spec from prefixed headers — like poolFromHeaders, but returns the
// raw spec (incl. password) so we can build dedicated Clients instead of shared
// pools. This feature sets session GUCs (default_transaction_read_only,
// session_replication_role) that must never leak into pooled connections.
function trSpecFromHeaders(req, prefix) {
  return {
    host: (req.headers[`${prefix}host`] || 'localhost').toString().trim(),
    port: parseInt(req.headers[`${prefix}port`] || '8090'),
    database: req.headers[`${prefix}name`] || 'lillian_care_core',
    user: req.headers[`${prefix}user`] || 'postgres',
    password: req.headers[`${prefix}password`] || '',
  };
}

function trClientFor(spec) {
  return new Client({
    ...spec,
    connectionTimeoutMillis: 5000,
    ssl: spec.host !== 'localhost' && spec.host !== '127.0.0.1' ? { rejectUnauthorized: false } : false,
  });
}

// Single source of truth for target safety. Returns an error string or null.
function drAssertSafeTarget(req, srcSpec, tgtSpec, { destructive }) {
  const label = (req.headers['x-tgt-env-label'] || '').toString().toLowerCase();
  if (!DB_REFRESH_TARGET_ENVS.includes(label))
    return `x-tgt-env-label must be one of ${DB_REFRESH_TARGET_ENVS.join('/')} (got '${label || 'missing'}')`;
  const host = (tgtSpec.host || '').toLowerCase();
  if (DB_REFRESH_PROTECTED_HOSTS.includes(host)) return `target host '${host}' is production — refusing`;
  if (drEnvForHost(host) !== label) return `target host '${host}' is not a known '${label}' host — refusing`;
  const srcEnv = drEnvForHost(srcSpec.host);
  if (!srcEnv) return `source host '${srcSpec.host}' is not a known environment`;
  if (srcEnv === label) return 'source and target must be different environments';
  if (destructive) {
    if (req.headers['x-allow-destructive'] !== 'yes') return `x-allow-destructive header must be 'yes'`;
    const expected = drConfirmationFor(label);
    if (((req.body || {}).confirmation) !== expected) return `body.confirmation must be the literal string '${expected}'`;
  }
  return null;
}

// All public BASE TABLEs, alphabetical.
async function trListBaseTables(client) {
  const r = await client.query(
    `SELECT table_name FROM information_schema.tables
     WHERE table_schema = 'public' AND table_type = 'BASE TABLE'
     ORDER BY table_name`);
  return r.rows.map((x) => x.table_name);
}

// One round-trip: all columns of the public schema grouped by table.
async function trColumnsByTable(client) {
  const r = await client.query(
    `SELECT table_name, column_name, data_type, udt_name
     FROM information_schema.columns
     WHERE table_schema = 'public'
     ORDER BY table_name, ordinal_position`);
  const byTable = {};
  for (const row of r.rows) {
    (byTable[row.table_name] = byTable[row.table_name] || []).push(row);
  }
  return byTable;
}

// Row-count estimates for every public table in one query (never COUNT(*) —
// prod log tables are huge). reltuples can be stale; UI labels it an estimate.
async function trRowEstimates(client) {
  const r = await client.query(
    `SELECT c.relname AS table_name, GREATEST(c.reltuples, 0)::bigint AS rows
     FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
     WHERE n.nspname = 'public' AND c.relkind = 'r'`);
  const map = {};
  for (const row of r.rows) map[row.table_name] = parseInt(row.rows);
  return map;
}

// Source → target type changes that can never lose data. Older envs (staging,
// prod) were created by a Serverpod version with int4 ids; freshly-created DBs
// (dev) use int8 — migrations never change id types, so this drift is normal.
const DB_REFRESH_SAFE_WIDENINGS = new Set([
  'int2>int4', 'int2>int8', 'int4>int8',
  'float4>float8',
  'varchar>text', 'bpchar>text',
  'json>jsonb',
]);

// Schema comparison. Column drift on shared tables is a hard fail. Tables that
// exist on only one side are reported but not blocking: source-only tables are
// not copied (the target's code doesn't know them — e.g. a hand-made table on
// staging), target-only tables are emptied by the TRUNCATE and left empty.
// Skip tables are excluded — they aren't copied, so drift there is irrelevant.
function trSchemaDiff(srcTables, tgtTables, srcCols, tgtCols) {
  const skip = new Set(DB_REFRESH_SKIP_TABLES);
  const src = srcTables.filter((t) => !skip.has(t));
  const tgt = tgtTables.filter((t) => !skip.has(t));
  const srcSet = new Set(src), tgtSet = new Set(tgt);
  const srcOnlyTables = src.filter((t) => !tgtSet.has(t));
  const tgtOnlyTables = tgt.filter((t) => !srcSet.has(t));
  const columnDiffs = [];
  const widenings = []; // safe type changes — reported, not blocking
  for (const t of src.filter((x) => tgtSet.has(x))) {
    const sCols = srcCols[t] || [], tCols = tgtCols[t] || [];
    const sByName = new Map(sCols.map((c) => [c.column_name, c]));
    const tByName = new Map(tCols.map((c) => [c.column_name, c]));
    const srcOnly = sCols.filter((c) => !tByName.has(c.column_name)).map((c) => c.column_name);
    const tgtOnly = tCols.filter((c) => !sByName.has(c.column_name)).map((c) => c.column_name);
    const typeChanges = sCols
      .filter((c) => tByName.has(c.column_name) && tByName.get(c.column_name).udt_name !== c.udt_name)
      .map((c) => ({ column: c.column_name, src: c.udt_name, tgt: tByName.get(c.column_name).udt_name }));
    const typeMismatch = typeChanges.filter((m) => !DB_REFRESH_SAFE_WIDENINGS.has(`${m.src}>${m.tgt}`));
    const widened = typeChanges.filter((m) => DB_REFRESH_SAFE_WIDENINGS.has(`${m.src}>${m.tgt}`));
    if (srcOnly.length || tgtOnly.length || typeMismatch.length) {
      columnDiffs.push({ table: t, srcOnly, tgtOnly, typeMismatch });
    }
    if (widened.length) widenings.push({ table: t, columns: widened });
  }
  return {
    ok: !columnDiffs.length,
    srcOnlyTables, tgtOnlyTables, columnDiffs, widenings,
  };
}

// ── POST /api/db-refresh/preflight ───────────────────────────────────────────
// Headers: x-src-db-*, x-tgt-db-*, x-tgt-env-label: dev|test|staging. Read-only.
// Returns schema diff, row estimates and the replica-role capability probe.
app.post('/api/db-refresh/preflight', async (req, res) => {
  const srcSpec = trSpecFromHeaders(req, 'x-src-db-');
  const tgtSpec = trSpecFromHeaders(req, 'x-tgt-db-');
  const guardErr = drAssertSafeTarget(req, srcSpec, tgtSpec, { destructive: false });
  if (guardErr) return res.status(400).json({ error: guardErr });

  const srcClient = trClientFor(srcSpec);
  const tgtClient = trClientFor(tgtSpec);
  try {
    await srcClient.connect();
    await srcClient.query('SET default_transaction_read_only = on');
    await tgtClient.connect();

    const [srcTables, tgtTables, srcCols, tgtCols, srcRows, tgtRows] = await Promise.all([
      trListBaseTables(srcClient), trListBaseTables(tgtClient),
      trColumnsByTable(srcClient), trColumnsByTable(tgtClient),
      trRowEstimates(srcClient), trRowEstimates(tgtClient),
    ]);
    const diff = trSchemaDiff(srcTables, tgtTables, srcCols, tgtCols);

    // Capability probe: can the target session enter replica mode (needed to
    // bypass FK triggers during the copy)? Touches no data.
    let replicaRoleOk = false, replicaRoleError = null;
    try {
      await tgtClient.query('BEGIN');
      await tgtClient.query('SET LOCAL session_replication_role = replica');
      const show = await tgtClient.query('SHOW session_replication_role');
      replicaRoleOk = show.rows[0]?.session_replication_role === 'replica';
      if (!replicaRoleOk) replicaRoleError = `SHOW returned '${show.rows[0]?.session_replication_role}'`;
    } catch (e) {
      replicaRoleError = e.message;
    } finally {
      await tgtClient.query('ROLLBACK').catch(() => {});
    }

    const skipSet = new Set(DB_REFRESH_SKIP_TABLES);
    const srcSet = new Set(srcTables), tgtSet = new Set(tgtTables);
    const allTables = [...new Set([...srcTables, ...tgtTables])].sort();
    res.json({
      ok: true,
      schemaOk: diff.ok,
      replicaRoleOk,
      replicaRoleError,
      diff,
      tables: allTables.map((t) => ({
        table: t,
        srcRows: srcRows[t] ?? null,
        tgtRows: tgtRows[t] ?? null,
        skipped: skipSet.has(t),
        srcOnly: !tgtSet.has(t),
        tgtOnly: !srcSet.has(t),
      })),
      skipTables: DB_REFRESH_SKIP_TABLES,
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  } finally {
    await srcClient.end().catch(() => {});
    await tgtClient.end().catch(() => {});
  }
});

// ── POST /api/db-refresh/run ──────────────────────────────────────────────────
// Wipe target + full copy. Headers: x-src-db-*, x-tgt-db-*,
// x-tgt-env-label: dev|test|staging, x-allow-destructive: yes.
// Body: { confirmation: 'REFRESH <TARGET ENV>' }.
// Streams NDJSON progress events: start / table / done / error. The client must
// treat a stream that ends without a 'done' event as a failure (HTTP 200 is
// already committed when errors surface mid-copy; the tx still rolls back).
app.post('/api/db-refresh/run', async (req, res) => {
  const srcSpec = trSpecFromHeaders(req, 'x-src-db-');
  const tgtSpec = trSpecFromHeaders(req, 'x-tgt-db-');
  const guardErr = drAssertSafeTarget(req, srcSpec, tgtSpec, { destructive: true });
  if (guardErr) return res.status(400).json({ error: guardErr });

  res.setHeader('Content-Type', 'application/x-ndjson');
  res.setHeader('X-Accel-Buffering', 'no');
  const emit = (evt) => res.write(JSON.stringify(evt) + '\n');

  const srcClient = trClientFor(srcSpec);
  const tgtClient = trClientFor(tgtSpec);
  let aborted = false;
  // res 'close' with writableEnded=false means the client went away mid-stream
  // (req 'close' fires on normal body completion in modern Node — wrong signal).
  res.on('close', () => { if (!res.writableEnded) aborted = true; });
  const startedAt = Date.now();

  try {
    await srcClient.connect();
    // Source is physically read-only for the whole session: even a code bug
    // cannot write to the source env. REPEATABLE READ gives one consistent
    // snapshot across all tables for the duration of the copy.
    await srcClient.query('SET default_transaction_read_only = on');
    await srcClient.query('BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY');
    await tgtClient.connect();

    // Server-side re-verification — never trust the client's preflight.
    const [srcTables, tgtTables, srcCols, tgtCols] = await Promise.all([
      trListBaseTables(srcClient), trListBaseTables(tgtClient),
      trColumnsByTable(srcClient), trColumnsByTable(tgtClient),
    ]);
    const diff = trSchemaDiff(srcTables, tgtTables, srcCols, tgtCols);
    if (!diff.ok) {
      emit({ type: 'error', message: 'Column drift between source and target — refusing to copy. Migrate the target first.', diff });
      return;
    }

    await tgtClient.query('BEGIN');
    // SET LOCAL dies with the transaction — cannot leak into later sessions.
    await tgtClient.query('SET LOCAL session_replication_role = replica');
    const show = await tgtClient.query('SHOW session_replication_role');
    if (show.rows[0]?.session_replication_role !== 'replica') {
      emit({ type: 'error', message: `Target user cannot enter replica mode (needed to bypass FK order). Nothing was changed.` });
      await tgtClient.query('ROLLBACK');
      return;
    }

    const skipSet = new Set(DB_REFRESH_SKIP_TABLES);
    // Only tables present on both sides; one-sided tables are reported by preflight.
    const tgtSet = new Set(tgtTables);
    const copyTables = srcTables.filter((t) => !skipSet.has(t) && tgtSet.has(t));
    emit({ type: 'start', tables: copyTables, truncating: tgtTables.length });

    // Wipe: every target table in ONE statement — transactional, FK-order
    // irrelevant. Skip tables are truncated too, just not refilled.
    await tgtClient.query(
      `TRUNCATE ${tgtTables.map(quoteIdent).join(', ')} RESTART IDENTITY CASCADE`);

    let totalRows = 0;
    for (let i = 0; i < copyTables.length; i++) {
      const t = copyTables[i];
      if (aborted) throw new Error('Client disconnected — rolling back');
      const t0 = Date.now();
      const cols = srcCols[t];
      const colList = cols.map((c) => quoteIdent(c.column_name)).join(', ');
      // Chunk inserts to stay under pg's 65535 bind-param limit.
      const rowsPerInsert = Math.max(1, Math.floor(30000 / cols.length));

      await srcClient.query(`DECLARE tr_cur NO SCROLL CURSOR FOR SELECT ${colList} FROM ${quoteIdent(t)}`);
      let copied = 0;
      try {
        for (;;) {
          if (aborted) throw new Error('Client disconnected — rolling back');
          const batch = await srcClient.query(`FETCH 1000 FROM tr_cur`);
          if (!batch.rows.length) break;
          for (let off = 0; off < batch.rows.length; off += rowsPerInsert) {
            const chunk = batch.rows.slice(off, off + rowsPerInsert);
            const params = [];
            const valueTuples = chunk.map((row) => {
              const ph = cols.map((c) => {
                params.push(bindValue(c, row[c.column_name]));
                return `$${params.length}`;
              });
              return `(${ph.join(',')})`;
            });
            await tgtClient.query(
              `INSERT INTO ${quoteIdent(t)} (${colList}) VALUES ${valueTuples.join(',')}`, params);
            copied += chunk.length;
          }
        }
      } finally {
        await srcClient.query('CLOSE tr_cur').catch(() => {});
      }
      totalRows += copied;
      emit({ type: 'table', table: t, rows: copied, ms: Date.now() - t0, i: i + 1, n: copyTables.length });
    }

    // Advance sequences past the preserved ids, inside the same transaction.
    for (const t of copyTables) {
      if (!srcCols[t].some((c) => c.column_name === 'id')) continue;
      const seq = await tgtClient.query(`SELECT pg_get_serial_sequence($1, 'id') AS seq`, [t]);
      if (!seq.rows[0]?.seq) continue;
      await tgtClient.query(
        `SELECT setval($1, GREATEST(COALESCE((SELECT MAX("id") FROM ${quoteIdent(t)}), 0), 1), TRUE)`,
        [seq.rows[0].seq]);
    }

    await tgtClient.query('COMMIT');
    await srcClient.query('COMMIT').catch(() => {});
    emit({
      type: 'done',
      summary: {
        tablesCopied: copyTables.length,
        totalRows,
        skipped: DB_REFRESH_SKIP_TABLES,
        durationMs: Date.now() - startedAt,
      },
    });
  } catch (e) {
    await tgtClient.query('ROLLBACK').catch(() => {});
    if (!aborted) emit({ type: 'error', message: e.message });
  } finally {
    await srcClient.end().catch(() => {});
    await tgtClient.end().catch(() => {});
    res.end();
  }
});

// ─── Routes: SSH tunnels via SSM port-forwarding ─────────────────────────────
// One-click `aws ssm start-session --document AWS-StartPortForwardingSession`
// per environment, so a private (no public IP) app instance can be reached over
// a local port — Termius/ssh point at 127.0.0.1:<localPort>. The instance id is
// resolved automatically from the ASG Name tag; no manual lookup needed.
const { spawn } = require('child_process');

// A GUI-launched node often lacks Homebrew's bin dir on PATH, which is where
// session-manager-plugin lives. Prepend the common install locations.
const SSM_PATH = ['/opt/homebrew/bin', '/usr/local/bin', process.env.PATH || ''].join(':');

const SSM_ENVS = {
  test:       { tag: 'lc-core-serverpod-test',    localPort: 2201 },
  staging:    { tag: 'lc-core-serverpod-staging', localPort: 2202 },
  production: { tag: 'lc-core-serverpod',         localPort: 2203 },
};
const SSM_REMOTE_PORT = 22;

// env → live session record. status: 'starting' | 'connected' | 'error' | 'stopped'
const ssmSessions = new Map();

function ssmPublicState(env) {
  const s = ssmSessions.get(env);
  const cfg = SSM_ENVS[env];
  return {
    env,
    localPort: cfg.localPort,
    remotePort: SSM_REMOTE_PORT,
    tag: cfg.tag,
    status: s ? s.status : 'stopped',
    instanceId: s ? s.instanceId : null,
    sessionId: s ? s.sessionId : null,
    startedAt: s ? s.startedAt : null,
    error: s ? s.lastError : null,
  };
}

async function ssmResolveInstanceId(tag) {
  const out = await ec2Client.send(new DescribeInstancesCommand({
    Filters: [
      { Name: 'tag:Name', Values: [tag] },
      { Name: 'instance-state-name', Values: ['running'] },
    ],
  }));
  const instances = (out.Reservations || []).flatMap(r => r.Instances || []);
  if (!instances.length) throw new Error(`No running instance tagged Name=${tag}`);
  instances.sort((a, b) => new Date(b.LaunchTime) - new Date(a.LaunchTime));
  return instances[0].InstanceId;
}

app.get('/api/ssm/status', (req, res) => {
  res.json({ envs: Object.keys(SSM_ENVS).map(ssmPublicState) });
});

app.post('/api/ssm/connect', async (req, res) => {
  const env = (req.body && req.body.env) || '';
  const cfg = SSM_ENVS[env];
  if (!cfg) return res.status(400).json({ error: `Unknown env "${env}"` });

  const existing = ssmSessions.get(env);
  if (existing && (existing.status === 'connected' || existing.status === 'starting')) {
    return res.json(ssmPublicState(env));
  }

  try {
    const instanceId = await ssmResolveInstanceId(cfg.tag);
    const params = JSON.stringify({
      portNumber: [String(SSM_REMOTE_PORT)],
      localPortNumber: [String(cfg.localPort)],
    });
    const child = spawn('aws', [
      'ssm', 'start-session',
      '--target', instanceId,
      '--document-name', 'AWS-StartPortForwardingSession',
      '--parameters', params,
      '--region', AWS_REGION,
    ], { env: { ...process.env, PATH: SSM_PATH } });

    const record = { child, instanceId, status: 'starting', startedAt: Date.now(), lastError: null, sessionId: null };
    ssmSessions.set(env, record);

    let settled = false;
    const finish = (state) => {
      if (settled) return;
      settled = true;
      res.json({ ...ssmPublicState(env), status: state });
    };

    child.stdout.on('data', (buf) => {
      const text = buf.toString();
      const sid = /SessionId:\s*(\S+)/.exec(text);
      if (sid) record.sessionId = sid[1];
      if (/Waiting for connections/i.test(text)) {
        record.status = 'connected';
        finish('connected');
      }
    });
    child.stderr.on('data', (buf) => {
      record.lastError = buf.toString().trim().slice(0, 500);
    });
    child.on('error', (err) => {
      record.status = 'error';
      record.lastError = err.message;
      finish('error');
    });
    child.on('exit', (code) => {
      if (record.status !== 'connected' && !record.lastError) {
        record.lastError = `aws ssm exited (code ${code})`;
      }
      record.status = 'stopped';
      if (ssmSessions.get(env) === record) ssmSessions.delete(env);
      finish(code === 0 ? 'stopped' : 'error');
    });

    setTimeout(() => finish(record.status), 6000);
  } catch (e) {
    ssmSessions.delete(env);
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/ssm/disconnect', (req, res) => {
  const env = (req.body && req.body.env) || '';
  if (!SSM_ENVS[env]) return res.status(400).json({ error: `Unknown env "${env}"` });
  const s = ssmSessions.get(env);
  if (s && s.child) {
    try { s.child.kill('SIGTERM'); } catch (_) {}
  }
  ssmSessions.delete(env);
  res.json(ssmPublicState(env));
});

// Best-effort cleanup so we don't leak SSM sessions when the debugger stops.
function ssmKillAll() {
  for (const s of ssmSessions.values()) {
    if (s && s.child) { try { s.child.kill('SIGTERM'); } catch (_) {} }
  }
}
process.on('SIGINT', () => { ssmKillAll(); process.exit(0); });
process.on('SIGTERM', () => { ssmKillAll(); process.exit(0); });

// ─── Local stack (Serverpod dev server + Docker Postgres/Redis) ─────────────
// Keeps the local backend (LillianCare-Core) running so the `dev` preset works.
// Serverpod is spawned detached in its own process group and tracked via a PID
// file, so restarting the helper (launchd kickstart) does not kill it. Docker
// Desktop's CLI is not on PATH for GUI/launchd processes, so we point at it.
const net = require('net');
const { execFile } = require('child_process');

const LS_DIR = path.join(__dirname, '.local-stack');
const LS_PID_FILE = path.join(LS_DIR, 'serverpod.pid');
const LS_LOG_FILE = path.join(LS_DIR, 'serverpod.log');
const LS_CONFIG_FILE = path.join(LS_DIR, 'config.json');
const LS_HELPER_LOG = path.join(process.env.HOME || '', 'Library', 'Logs', 'LCHelper', 'server.log');
const LS_SERVERPOD_DIR = process.env.LC_SERVERPOD_DIR
  || path.resolve(__dirname, '..', 'LillianCare-Core', 'lillian_care_core_server');
const LS_API_PORT = 8080;
const LS_PATH = [
  '/Applications/Docker.app/Contents/Resources/bin',
  path.join(process.env.HOME || '', 'Dev', 'flutter', 'bin'),
  '/opt/homebrew/bin', '/usr/local/bin', process.env.PATH || '',
].join(':');
const LS_ENV = { ...process.env, PATH: LS_PATH };
const LS_DEFAULT_CONFIG = { autostart: true, applyMigrations: false };

fs.mkdirSync(LS_DIR, { recursive: true });

// Transient state only this process knows about (in-flight actions, exit codes
// of children we spawned ourselves).
const lsState = { action: null, actionError: null, lastExit: null, child: null, stopRequested: false };

function lsReadConfig() {
  try { return { ...LS_DEFAULT_CONFIG, ...JSON.parse(fs.readFileSync(LS_CONFIG_FILE, 'utf8')) }; }
  catch (_) { return { ...LS_DEFAULT_CONFIG }; }
}

function lsWriteConfig(cfg) {
  fs.writeFileSync(LS_CONFIG_FILE, JSON.stringify(cfg, null, 2));
}

function lsExec(cmd, args, opts = {}) {
  return new Promise((resolve) => {
    execFile(cmd, args, { env: LS_ENV, timeout: opts.timeout || 20000, cwd: opts.cwd, maxBuffer: 4 * 1024 * 1024 },
      (err, stdout, stderr) => resolve({ ok: !err, stdout: String(stdout || ''), stderr: String(stderr || ''), err }));
  });
}

function lsPortOpen(port, host = '127.0.0.1') {
  return new Promise((resolve) => {
    const sock = net.connect({ port, host });
    const done = (v) => { sock.destroy(); resolve(v); };
    sock.setTimeout(600, () => done(false));
    sock.once('connect', () => done(true));
    sock.once('error', () => done(false));
  });
}

function lsPidAlive(pid) {
  if (!pid) return false;
  try { process.kill(pid, 0); return true; } catch (e) { return e.code === 'EPERM'; }
}

function lsReadPid() {
  try {
    const rec = JSON.parse(fs.readFileSync(LS_PID_FILE, 'utf8'));
    return lsPidAlive(rec.pid) ? rec : null;
  } catch (_) { return null; }
}

async function lsDockerStatus() {
  const info = await lsExec('docker', ['info', '--format', '{{.ServerVersion}}'], { timeout: 8000 });
  // While Docker Desktop boots, `docker info` can succeed with an empty engine version.
  if (!info.ok || !info.stdout.trim()) {
    const cli = fs.existsSync('/Applications/Docker.app');
    return { state: cli ? 'stopped' : 'unavailable', detail: cli ? 'Docker Desktop is not running' : 'Docker Desktop not installed', containers: [] };
  }
  const ps = await lsExec('docker', ['compose', 'ps', '--all', '--format', 'json'], { cwd: LS_SERVERPOD_DIR, timeout: 10000 });
  let containers = [];
  if (ps.ok) {
    // `docker compose ps --format json` prints either a JSON array or NDJSON depending on version.
    const text = ps.stdout.trim();
    const rows = text.startsWith('[') ? JSON.parse(text) : text.split('\n').filter(Boolean).map((l) => JSON.parse(l));
    containers = rows.map((r) => ({ service: r.Service, state: r.State, status: r.Status, ports: r.Publishers
      ? r.Publishers.filter((p) => p.PublishedPort).map((p) => p.PublishedPort) : [] }));
  }
  return { state: 'running', detail: `Engine ${info.stdout.trim()}`, containers };
}

async function lsServerpodStatus() {
  const rec = lsReadPid();
  const listening = await lsPortOpen(LS_API_PORT);
  if (lsState.action === 'stopping') return { state: 'stopping', pid: rec && rec.pid };
  if (rec) {
    return {
      state: listening ? 'running' : 'starting',
      pid: rec.pid, since: rec.startedAt, applyMigrations: !!rec.applyMigrations,
      detail: listening ? `API on :${LS_API_PORT}` : 'Compiling / booting…',
    };
  }
  if (listening) return { state: 'running', external: true, detail: `Something is listening on :${LS_API_PORT} (started outside LC Helper)` };
  if (lsState.action === 'starting') return { state: 'starting', detail: 'Waiting for Docker…' };
  if (lsState.lastExit && !lsState.stopRequested) {
    return { state: 'crashed', detail: `Exited with code ${lsState.lastExit.code}`, exitCode: lsState.lastExit.code, exitedAt: lsState.lastExit.at };
  }
  return { state: 'stopped' };
}

async function lsStatus() {
  const [docker, serverpod] = await Promise.all([lsDockerStatus(), lsServerpodStatus()]);
  return {
    docker, serverpod,
    config: lsReadConfig(),
    action: lsState.action, actionError: lsState.actionError,
    serverpodDir: LS_SERVERPOD_DIR, serverpodDirExists: fs.existsSync(LS_SERVERPOD_DIR),
  };
}

async function lsEnsureDocker() {
  let st = await lsDockerStatus();
  if (st.state === 'unavailable') throw new Error(st.detail);
  if (st.state !== 'running') {
    await lsExec('open', ['-g', '-a', 'Docker']);
    const deadline = Date.now() + 120000;
    while (Date.now() < deadline) {
      await new Promise((r) => setTimeout(r, 2000));
      st = await lsDockerStatus();
      if (st.state === 'running') break;
    }
    if (st.state !== 'running') throw new Error('Docker Desktop did not become ready within 2 minutes');
  }
  let up = await lsExec('docker', ['compose', 'up', '--detach'], { cwd: LS_SERVERPOD_DIR, timeout: 180000 });
  for (let i = 0; !up.ok && i < 3; i++) { // the engine may still be settling right after launch
    await new Promise((r) => setTimeout(r, 5000));
    up = await lsExec('docker', ['compose', 'up', '--detach'], { cwd: LS_SERVERPOD_DIR, timeout: 180000 });
  }
  if (!up.ok) throw new Error(`docker compose up failed: ${(up.stderr || up.stdout).trim().slice(-600)}`);
}

async function lsStartServerpod() {
  if (lsReadPid() || await lsPortOpen(LS_API_PORT)) return; // already running (ours or external)
  if (!fs.existsSync(LS_SERVERPOD_DIR)) throw new Error(`Serverpod directory not found: ${LS_SERVERPOD_DIR}`);
  await lsEnsureDocker();

  // Keep the log bounded: rotate once it passes 10 MB.
  try { if (fs.statSync(LS_LOG_FILE).size > 10 * 1024 * 1024) fs.renameSync(LS_LOG_FILE, LS_LOG_FILE + '.1'); } catch (_) {}
  const cfg = lsReadConfig();
  const args = ['run', 'bin/main.dart', '--mode', 'development'];
  if (cfg.applyMigrations) args.push('--apply-migrations');
  const fd = fs.openSync(LS_LOG_FILE, 'a');
  fs.writeSync(fd, `\n──── ${new Date().toISOString()} · LC Helper starting: dart ${args.join(' ')} ────\n`);
  const child = spawn('dart', args, { cwd: LS_SERVERPOD_DIR, env: LS_ENV, detached: true, stdio: ['ignore', fd, fd] });
  fs.closeSync(fd);
  await new Promise((resolve, reject) => {
    child.once('spawn', resolve);
    child.once('error', (e) => reject(new Error(`Could not start dart: ${e.message}`)));
  });
  fs.writeFileSync(LS_PID_FILE, JSON.stringify({ pid: child.pid, startedAt: Date.now(), applyMigrations: cfg.applyMigrations }));
  lsState.child = child;
  lsState.stopRequested = false;
  lsState.lastExit = null;
  child.on('exit', (code, signal) => {
    lsState.child = null;
    lsState.lastExit = { code: code == null ? signal : code, at: Date.now() };
    try { fs.unlinkSync(LS_PID_FILE); } catch (_) {}
  });
  child.unref();
}

async function lsStopServerpod() {
  lsState.stopRequested = true;
  const rec = lsReadPid();
  if (!rec) return;
  // `dart run` forks the VM, so signal the whole process group.
  const kill = (sig) => { try { process.kill(-rec.pid, sig); } catch (_) { try { process.kill(rec.pid, sig); } catch (_) {} } };
  kill('SIGTERM');
  const deadline = Date.now() + 10000;
  while (Date.now() < deadline && lsPidAlive(rec.pid)) await new Promise((r) => setTimeout(r, 300));
  if (lsPidAlive(rec.pid)) kill('SIGKILL');
  try { fs.unlinkSync(LS_PID_FILE); } catch (_) {}
}

// Runs one lifecycle action at a time; the HTTP call returns immediately and the
// UI polls /status to follow progress.
function lsRun(action, fn) {
  if (lsState.action) return false;
  lsState.action = action;
  lsState.actionError = null;
  fn().catch((e) => { lsState.actionError = e.message; console.error(`[local-stack] ${action} failed:`, e.message); })
    .finally(() => { lsState.action = null; });
  return true;
}

function lsTail(file, maxLines) {
  try {
    const size = fs.statSync(file).size;
    const len = Math.min(size, 512 * 1024);
    const buf = Buffer.alloc(len);
    const fd = fs.openSync(file, 'r');
    fs.readSync(fd, buf, 0, len, size - len);
    fs.closeSync(fd);
    const lines = buf.toString('utf8').split('\n');
    if (len < size) lines.shift(); // first line is probably partial
    return lines.slice(-maxLines);
  } catch (_) { return []; }
}

app.get('/api/local-stack/status', async (req, res) => {
  try { res.json(await lsStatus()); } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/local-stack/start', async (req, res) => {
  lsRun('starting', lsStartServerpod);
  res.json(await lsStatus());
});

app.post('/api/local-stack/stop', async (req, res) => {
  const includeDocker = !!(req.body && req.body.includeDocker);
  lsRun('stopping', async () => {
    await lsStopServerpod();
    if (includeDocker) await lsExec('docker', ['compose', 'stop'], { cwd: LS_SERVERPOD_DIR, timeout: 60000 });
  });
  res.json(await lsStatus());
});

app.post('/api/local-stack/restart', async (req, res) => {
  lsRun('restarting', async () => { await lsStopServerpod(); await lsStartServerpod(); });
  res.json(await lsStatus());
});

app.post('/api/local-stack/config', (req, res) => {
  const cfg = lsReadConfig();
  const body = req.body || {};
  if (typeof body.autostart === 'boolean') cfg.autostart = body.autostart;
  if (typeof body.applyMigrations === 'boolean') cfg.applyMigrations = body.applyMigrations;
  lsWriteConfig(cfg);
  res.json({ config: cfg });
});

app.get('/api/local-stack/logs', (req, res) => {
  const tail = Math.min(parseInt(req.query.tail || '500', 10) || 500, 5000);
  const file = req.query.service === 'helper' ? LS_HELPER_LOG : LS_LOG_FILE;
  res.json({ file, lines: lsTail(file, tail) });
});

// ─── Routes: Build & Release (Flutter apps) ──────────────────────────────────
// Builds the two Flutter apps (web / Android / iOS, test or prod) and deploys
// web builds to S3 + CloudFront. One job at a time: every build starts with
// `flutter clean`, and both apps share one pub workspace, so parallel jobs
// would trample each other. Mobile artifacts are revealed in Finder.
const RL_APPS_DIR = process.env.LC_APPS_DIR
  || path.resolve(__dirname, '..', 'apps-frontend', 'apps');
const RL_APPS = {
  praxis: {
    label: 'Praxis app', dir: 'lillian_care_praxis_app',
    web: {
      test: { bucket: 'lillian-care-praxis-test', distribution: 'E212FAFCAG5Y7B', url: 'https://praxis-test.lillian-care.de' },
      prod: { bucket: 'lillian-care-praxis-prod', distribution: 'E2HT4R4XMWOKKS', url: 'https://praxis-app.lillian-care.de' },
    },
  },
  app: {
    label: 'LillianCare app', dir: 'lillian_care_app',
    web: {
      test: { bucket: 'lillian-care-app-test', distribution: 'E1CDAZB8YO8U4C', url: 'https://app-test.lillian-care.de' },
      prod: { bucket: 'lillian-care-app-prod', distribution: 'EOIX3XODFOSC1', url: 'https://app.lillian-care.de' },
    },
  },
};
const RL_ENVS = {
  test: { flavor: 'atest', target: 'lib/main_atest.dart' },
  prod: { flavor: 'prod', target: 'lib/main_prod.dart' },
};
const RL_ANDROID_FORMATS = ['apk', 'aab'];
// Both apps are members of ONE pub workspace (apps-frontend/pubspec.yaml), so
// every build uses the workspace root's fvm pin — not an app folder's own
// .fvmrc (praxis pins an older SDK that can't resolve the shared workspace).
const RL_WORKSPACE_DIR = path.resolve(RL_APPS_DIR, '..');
const RL_FVM_VERSIONS_DIR = path.join(process.env.FVM_CACHE_PATH || path.join(process.env.HOME || '', 'fvm'), 'versions');

// Returns { version, bin } for the workspace's pinned SDK, or { error }.
function rlSdk() {
  let version;
  try { version = JSON.parse(fs.readFileSync(path.join(RL_WORKSPACE_DIR, '.fvmrc'), 'utf8')).flutter; }
  catch (e) { return { error: `cannot read ${path.join(RL_WORKSPACE_DIR, '.fvmrc')}: ${e.message}` }; }
  const bin = path.join(RL_FVM_VERSIONS_DIR, version, 'bin');
  if (!fs.existsSync(path.join(bin, 'flutter'))) return { version, error: `Flutter ${version} is not installed in fvm — run: fvm install ${version}` };
  return { version, bin };
}
const RL_DIR = path.join(__dirname, '.release');
const RL_STATE_FILE = path.join(RL_DIR, 'state.json');
// CocoaPods refuses to run without a UTF-8 locale, which launchd doesn't set.
const RL_ENV = { ...process.env, PATH: LS_PATH, LANG: process.env.LANG || 'en_US.UTF-8' };
const RL_LOG_MAX = 20000;

fs.mkdirSync(RL_DIR, { recursive: true });

// Persisted: last successful build per app/platform. The web entry records
// which env build/web was built for, so a test build can't be deployed to prod.
function rlReadState() {
  try { return { lastBuilds: {}, ...JSON.parse(fs.readFileSync(RL_STATE_FILE, 'utf8')) }; }
  catch (_) { return { lastBuilds: {} }; }
}
function rlWriteState(st) { fs.writeFileSync(RL_STATE_FILE, JSON.stringify(st, null, 2)); }

let rlJob = null;      // current or last job (in memory only)
let rlChild = null;    // running child process

function rlAppDir(appKey) { return path.join(RL_APPS_DIR, RL_APPS[appKey].dir); }

// Steps are [label, cmd, args]; args are passed without a shell.
function rlBuildSteps(appKey, env, platform, androidFormat, sdk) {
  const { flavor, target } = RL_ENVS[env];
  const flutter = path.join(sdk.bin, 'flutter');
  const build = platform === 'web'
    ? ['build', 'web', '--release', '-t', target]
    : platform === 'android'
      ? ['build', androidFormat === 'aab' ? 'appbundle' : 'apk', '--release', '--flavor', flavor, '-t', target]
      : ['build', 'ipa', '--flavor', flavor, '-t', target];
  return [
    ['Clean', flutter, ['clean']],
    ['Pub get', flutter, ['pub', 'get']],
    [`Build ${platform === 'android' ? androidFormat.toUpperCase() : platform === 'ios' ? 'IPA' : 'web'}`, flutter, build],
  ];
}

function rlDeploySteps(appKey, env) {
  const { bucket, distribution } = RL_APPS[appKey].web[env];
  return [
    ['S3 sync', 'aws', ['s3', 'sync', 'build/web/', `s3://${bucket}`, '--delete', '--exclude', 'index.html']],
    ['CloudFront invalidation', 'aws', ['cloudfront', 'create-invalidation', '--distribution-id', distribution, '--paths', '/*']],
  ];
}

function rlDeployConfirmation(appKey) { return `DEPLOY ${appKey.toUpperCase()} PROD`; }

// Newest file with `ext` under `dir` (recursive), optionally containing `hint`.
function rlFindArtifact(dir, ext, hint) {
  let best = null;
  const walk = (d) => {
    let entries; try { entries = fs.readdirSync(d, { withFileTypes: true }); } catch (_) { return; }
    for (const e of entries) {
      const p = path.join(d, e.name);
      if (e.isDirectory()) walk(p);
      else if (e.name.endsWith(ext) && (!hint || e.name.includes(hint))) {
        const m = fs.statSync(p).mtimeMs;
        if (!best || m > best.m) best = { p, m };
      }
    }
  };
  walk(dir);
  return best && best.p;
}

function rlArtifactFor(job) {
  const dir = rlAppDir(job.app);
  const { flavor } = RL_ENVS[job.env];
  if (job.platform === 'web') return path.join(dir, 'build', 'web');
  if (job.platform === 'ios') return rlFindArtifact(path.join(dir, 'build', 'ios', 'ipa'), '.ipa');
  return job.androidFormat === 'aab'
    ? rlFindArtifact(path.join(dir, 'build', 'app', 'outputs', 'bundle'), '.aab', flavor)
    : rlFindArtifact(path.join(dir, 'build', 'app', 'outputs', 'flutter-apk'), '.apk', flavor);
}

function rlLog(line) {
  rlJob.log.push(line);
  if (rlJob.log.length > RL_LOG_MAX) {
    const drop = rlJob.log.length - RL_LOG_MAX;
    rlJob.log.splice(0, drop);
    rlJob.logBase += drop;
  }
}

function rlRunStep(step, cwd) {
  return new Promise((resolve) => {
    const [, cmd, args] = step;
    rlLog(`──── $ ${cmd} ${args.map((a) => (/[\s*"]/.test(a) ? JSON.stringify(a) : a)).join(' ')}`);
    // detached → own process group, so Cancel can kill flutter's children too.
    const child = spawn(cmd, args, { cwd, env: RL_ENV, detached: true });
    rlChild = child;
    const pipe = (stream) => {
      let buf = '';
      stream.on('data', (d) => {
        buf += d.toString();
        const lines = buf.split(/\r?\n/);
        buf = lines.pop();
        lines.forEach(rlLog);
      });
      stream.on('end', () => { if (buf) rlLog(buf); });
    };
    pipe(child.stdout); pipe(child.stderr);
    child.on('error', (e) => { rlLog(`${cmd}: ${e.message}`); });
    child.on('close', (code, signal) => { rlChild = null; resolve(signal ? -1 : code); });
  });
}

async function rlRunJob(job, steps) {
  const cwd = rlAppDir(job.app);
  for (let i = 0; i < steps.length; i++) {
    if (job.cancelRequested) break;
    job.step = i;
    job.steps[i].status = 'running';
    job.steps[i].startedAt = Date.now();
    const code = await rlRunStep(steps[i], cwd);
    job.steps[i].endedAt = Date.now();
    job.steps[i].code = code;
    if (job.cancelRequested) { job.steps[i].status = 'cancelled'; break; }
    if (code !== 0) {
      job.steps[i].status = 'failed';
      job.status = 'failed';
      job.error = `${steps[i][0]} exited with code ${code}`;
      break;
    }
    job.steps[i].status = 'done';
  }
  if (job.cancelRequested) { job.status = 'cancelled'; job.error = 'Cancelled'; }
  if (job.status === 'running') job.status = 'success';

  if (job.kind === 'build' && job.status === 'success') {
    const artifact = rlArtifactFor(job);
    const st = rlReadState();
    st.lastBuilds[job.app] = st.lastBuilds[job.app] || {};
    st.lastBuilds[job.app][job.platform] = {
      env: job.env, at: Date.now(), artifact: artifact || null,
      androidFormat: job.platform === 'android' ? job.androidFormat : undefined,
    };
    rlWriteState(st);
    job.artifact = artifact || null;
    if (job.platform !== 'web') {
      if (artifact) { execFile('open', ['-R', artifact]); rlLog(`──── Revealed ${artifact} in Finder`); }
      else { job.status = 'failed'; job.error = 'Build succeeded but the output file was not found'; }
    }
  }
  if (job.kind === 'deploy' && job.status === 'success') {
    const st = rlReadState();
    const wb = st.lastBuilds[job.app] && st.lastBuilds[job.app].web;
    if (wb) { wb.deployedAt = Date.now(); rlWriteState(st); }
  }
  job.endedAt = Date.now();
  rlLog(`──── ${job.status.toUpperCase()}${job.error ? ' — ' + job.error : ''}`);
}

function rlStartJob(fields, steps) {
  rlJob = {
    id: Date.now().toString(36), status: 'running', startedAt: Date.now(), endedAt: null,
    step: 0, steps: steps.map(([label]) => ({ label, status: 'pending' })),
    log: [], logBase: 0, error: null, artifact: null, cancelRequested: false, ...fields,
  };
  rlRunJob(rlJob, steps).catch((e) => {
    rlJob.status = 'failed'; rlJob.error = e.message; rlJob.endedAt = Date.now();
  });
  return rlJob;
}

function rlJobSummary(job, since) {
  if (!job) return null;
  const { log, logBase, cancelRequested, ...rest } = job;
  const from = Math.max(0, (since || 0) - logBase);
  return { ...rest, logEnd: logBase + log.length, lines: log.slice(from), logTruncated: (since || 0) < logBase };
}

function rlValidate(body, { needPlatform }) {
  const { app: appKey, env, platform, androidFormat } = body || {};
  if (!RL_APPS[appKey]) return `unknown app '${appKey}'`;
  if (!RL_ENVS[env]) return `unknown env '${env}'`;
  if (needPlatform) {
    if (!['web', 'android', 'ios'].includes(platform)) return `unknown platform '${platform}'`;
    if (platform === 'android' && !RL_ANDROID_FORMATS.includes(androidFormat)) return `androidFormat must be apk or aab`;
  }
  if (!fs.existsSync(rlAppDir(appKey))) return `app folder not found: ${rlAppDir(appKey)}`;
  if (rlJob && rlJob.status === 'running') return 'another build/deploy is still running';
  return null;
}

app.get('/api/release/config', (req, res) => {
  res.json({
    appsDir: RL_APPS_DIR,
    sdk: rlSdk(),
    apps: Object.fromEntries(Object.entries(RL_APPS).map(([k, a]) => [k, { ...a, path: rlAppDir(k), exists: fs.existsSync(rlAppDir(k)) }])),
    envs: RL_ENVS,
    confirmations: Object.fromEntries(Object.keys(RL_APPS).map((k) => [k, rlDeployConfirmation(k)])),
    lastBuilds: rlReadState().lastBuilds,
  });
});

app.get('/api/release/status', (req, res) => {
  res.json({ job: rlJobSummary(rlJob, parseInt(req.query.since || '0')), lastBuilds: rlReadState().lastBuilds });
});

// Body: { app, env, platform: web|android|ios, androidFormat?: apk|aab }
app.post('/api/release/build', (req, res) => {
  const err = rlValidate(req.body, { needPlatform: true });
  if (err) return res.status(400).json({ error: err });
  const { app: appKey, env, platform } = req.body;
  const androidFormat = platform === 'android' ? req.body.androidFormat : undefined;
  const sdk = rlSdk();
  if (sdk.error) return res.status(400).json({ error: sdk.error });
  // `flutter clean` wipes build/, so every earlier artifact of this app is gone.
  const st = rlReadState();
  delete st.lastBuilds[appKey];
  rlWriteState(st);
  const job = rlStartJob({ kind: 'build', app: appKey, env, platform, androidFormat, flutterVersion: sdk.version },
    rlBuildSteps(appKey, env, platform, androidFormat, sdk));
  res.json({ job: rlJobSummary(job, 0) });
});

// Body: { app, env, confirmation? } — prod requires confirmation 'DEPLOY <APP> PROD'.
// Only deploys a build/web that this helper built for the same env.
app.post('/api/release/deploy', (req, res) => {
  const err = rlValidate(req.body, { needPlatform: false });
  if (err) return res.status(400).json({ error: err });
  const { app: appKey, env } = req.body;
  if (env === 'prod' && req.body.confirmation !== rlDeployConfirmation(appKey))
    return res.status(400).json({ error: `body.confirmation must be the literal string '${rlDeployConfirmation(appKey)}'` });
  const wb = (rlReadState().lastBuilds[appKey] || {}).web;
  if (!wb) return res.status(400).json({ error: 'no successful web build of this app yet — build web first' });
  if (wb.env !== env) return res.status(400).json({ error: `the current web build is for '${wb.env}', not '${env}' — rebuild for ${env} first` });
  if (!fs.existsSync(path.join(rlAppDir(appKey), 'build', 'web', 'main.dart.js')))
    return res.status(400).json({ error: 'build/web is missing — rebuild first' });
  const job = rlStartJob({ kind: 'deploy', app: appKey, env, platform: 'web', target: RL_APPS[appKey].web[env] },
    rlDeploySteps(appKey, env));
  res.json({ job: rlJobSummary(job, 0) });
});

app.post('/api/release/cancel', (req, res) => {
  if (!rlJob || rlJob.status !== 'running') return res.status(400).json({ error: 'nothing is running' });
  rlJob.cancelRequested = true;
  if (rlChild) { try { process.kill(-rlChild.pid, 'SIGTERM'); } catch (_) { try { rlChild.kill('SIGTERM'); } catch (_) {} } }
  res.json({ ok: true });
});

// Body: { app, platform } — reveals only artifacts recorded by a build here.
app.post('/api/release/reveal', (req, res) => {
  const { app: appKey, platform } = req.body || {};
  const b = ((rlReadState().lastBuilds[appKey] || {})[platform]) || null;
  if (!b || !b.artifact || !fs.existsSync(b.artifact)) return res.status(404).json({ error: 'artifact not found — rebuild' });
  execFile('open', ['-R', b.artifact]);
  res.json({ ok: true });
});

// ─── Routes: Investigations (/api/investigations/*, view #investigations) ────
// Investigation notes live as markdown in the shared folder next to this repo
// (also read by Claude Code sessions). Everything the AI sees — notes, pasted
// logs, query results — is scrubbed first; the placeholder→original mapping and
// the scrubbed AI conversation stay in INV_STATE_DIR (gitignored, local only).
// The AI only proposes SQL; a query runs when the user clicks Run, inside a
// READ ONLY transaction with a statement timeout and a row cap.
const INV_DIR = process.env.LC_INVESTIGATIONS_DIR || path.join(__dirname, '..', 'investigations');
const INV_PLAYBOOK_DIR = path.join(INV_DIR, 'playbooks');
const INV_SCRUBBER_FILE = path.join(INV_DIR, 'tools', 'principa-log-scrubber.html');
const INV_STATE_DIR = path.join(__dirname, '.investigations-state');
const INV_FILE_RE = /^\d{4}-\d{2}-\d{2}-[a-z0-9-]+\.md$/;
const INV_PLAYBOOK_RE = /^[a-z0-9-]+\.md$/;
const INV_MODEL = process.env.LC_INVESTIGATION_MODEL || 'eu.anthropic.claude-sonnet-4-5-20250929-v1:0';
const INV_MAX_ROWS = 200;
const INV_TIMEOUT_MS = 20000;
const INV_AI_RESULT_CHARS = 30000;

// The scrubber's single source is the standalone offline tool; its core sits
// between CORE-START/CORE-END markers. Reloaded when the file changes.
let invScrubberCache = { mtimeMs: 0, factory: null };
function invCreateScrubber(options) {
  const stat = fs.statSync(INV_SCRUBBER_FILE);
  if (!invScrubberCache.factory || invScrubberCache.mtimeMs !== stat.mtimeMs) {
    const html = fs.readFileSync(INV_SCRUBBER_FILE, 'utf8');
    const start = html.indexOf('// CORE-START');
    const end = html.indexOf('// CORE-END');
    if (start < 0 || end < 0) throw new Error(`Scrubber core markers missing in ${INV_SCRUBBER_FILE}`);
    const core = html.slice(start, end);
    invScrubberCache = { mtimeMs: stat.mtimeMs, factory: new Function(`${core}; return createScrubber;`)() };
  }
  return invScrubberCache.factory(options);
}

function invPath(file) {
  if (!INV_FILE_RE.test(file || '')) throw Object.assign(new Error('Invalid investigation file name'), { status: 400 });
  return path.join(INV_DIR, file);
}

function invParse(md) {
  const title = (md.match(/^#\s+(.+)$/m) || [])[1] || '';
  const status = ((md.match(/^\*\*Status:\*\*\s*(.+)$/m) || [])[1] || '').trim();
  return { title, status };
}

function invStatePath(file) { return path.join(INV_STATE_DIR, `${file}.json`); }

function invReadState(file) {
  try { return JSON.parse(fs.readFileSync(invStatePath(file), 'utf8')); }
  catch { return { mapping: [], terms: [], chat: [] }; }
}

function invWriteState(file, state) {
  fs.mkdirSync(INV_STATE_DIR, { recursive: true, mode: 0o700 });
  fs.writeFileSync(invStatePath(file), JSON.stringify(state, null, 2), { mode: 0o600 });
}

// One scrubber per call, seeded with the investigation's saved mapping so
// placeholders stay stable across queries and pasted logs.
function invScrub(state, fn) {
  const scrubber = invCreateScrubber({ state: { mapping: state.mapping }, terms: state.terms || [] });
  const result = fn(scrubber);
  state.mapping = scrubber.exportState().mapping;
  return result;
}

function invSlug(title) {
  return title.toLowerCase()
    .replace(/ä/g, 'ae').replace(/ö/g, 'oe').replace(/ü/g, 'ue').replace(/ß/g, 'ss')
    .replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 60) || 'investigation';
}

function invToday() {
  return new Intl.DateTimeFormat('en-CA', { timeZone: 'Europe/Berlin' }).format(new Date());
}

function invAppendLog(md, entry) {
  const line = `- ${invToday()}: ${entry.replace(/\s*\n\s*/g, ' ').trim()}`;
  const m = md.match(/^## Log\s*$/m);
  if (!m) return `${md.replace(/\s*$/, '')}\n\n## Log\n\n${line}\n`;
  const after = md.slice(m.index + m[0].length);
  const next = after.search(/^## /m);
  const sectionEnd = next < 0 ? md.length : m.index + m[0].length + next;
  const head = md.slice(0, sectionEnd).replace(/\s*$/, '');
  const tail = md.slice(sectionEnd);
  return `${head}\n${line}\n${tail ? `\n${tail}` : ''}`;
}

// Read-only by construction: wrapped in SELECT * FROM (...) (single statement,
// no COMMIT escape), extended protocol (Postgres rejects multiple commands),
// READ ONLY transaction (rejects writes incl. data-modifying CTEs), timeout.
async function invReadOnlyQuery(req, sql) {
  const text = String(sql || '').trim().replace(/;\s*$/, '');
  if (!text) throw Object.assign(new Error('No SQL provided'), { status: 400 });
  const client = await getPool(req).connect();
  try {
    await client.query('BEGIN TRANSACTION READ ONLY');
    await client.query(`SET LOCAL statement_timeout = ${INV_TIMEOUT_MS}`);
    const result = await client.query({
      text: `SELECT * FROM (\n${text}\n) AS inv_q LIMIT ${INV_MAX_ROWS + 1}`,
      values: [],
      queryMode: 'extended',
    });
    const truncated = result.rows.length > INV_MAX_ROWS;
    return { rows: truncated ? result.rows.slice(0, INV_MAX_ROWS) : result.rows, truncated };
  } finally {
    await client.query('ROLLBACK').catch(() => {});
    client.release();
  }
}

// The AI writes SQL with placeholders (e.g. ILIKE '%[EMAIL_1]%'); swap in the
// real values locally just before running. Quotes are doubled because the
// placeholders sit inside string literals.
function invUnscrubSql(state, sql) {
  let filled = 0;
  let out = sql;
  for (const [t, original] of [...state.mapping].sort((a, b) => b[0].length - a[0].length)) {
    if (!out.includes(t)) continue;
    out = out.split(t).join(String(original).replace(/'/g, "''"));
    filled++;
  }
  return { sql: out, filled };
}

function invClip(value, max) {
  return value.length > max ? `${value.slice(0, max)}… [truncated ${value.length - max} chars]` : value;
}

const INV_EXTRA_SCHEMA = `
MORE TABLES USED IN INVESTIGATIONS:

core_message_outbox (id uuid, channel [0=email 1=sms], payload [text JSON: to, templateId, params], status [0=pending 1=sending 2=sent 3=failed 4=dead], "attemptCount", "lastHttpStatus", "lastErrorBody", "createdAt", "sentAt", "correlationId", "idempotencyKey")

core_fhir_message_inbox (id uuid, payload [text JSON FHIR Bundle from Principa: entry[0]=MessageHeader (id = "<principaApptId>_<version>", eventCoding.code = appointment-create|update|cancel), entry[1]=Appointment (id = "<principaPatientId>_<principaApptId>", identifier[0].value = apkNr, status, start, participant)], status [0=pending 1=processing 2=processed 3=failed], "correlationId", "lastError", "createdAt", "processedAt", "failedAt")
  Extract with payload::jsonb #>> '{entry,1,resource,status}' etc.

ID CONVENTION: app_user_appointment."appointmentId" / guest_appointment."appointmentId" = Principa apkNr (e.g. BB126000026); "pmsAppointmentId" = "<principaPatientId>_<principaApptId>" (e.g. 210922_8783033) = FHIR Appointment.id. notification_log."activityId" = apkNr.

app_user_reserved_appointment ("reservationId", "slotId", category, "praxisId", "startTime", "createdAt", "validTill")
app_user_appointment_request ("appointmentId", ...) — exists when the app modified an appointment; FHIR handler then skips it
app_user_appointment_cancellation_reason (id, "userId", reason [json array], "createdAt")
`;

const INV_REPLY_TOOL = {
  toolSpec: {
    name: 'reply',
    description: 'Reply to the engineer investigating a production issue.',
    inputSchema: {
      json: {
        type: 'object',
        properties: {
          message: { type: 'string', description: 'Your analysis in concise markdown: what the evidence shows, what is still unknown, what to check next.' },
          proposed_sql: { type: 'string', description: 'ONE read-only PostgreSQL SELECT to run next, or omit when no query is needed. It runs inside SELECT * FROM (...) LIMIT 200, so no trailing semicolon.' },
          purpose: { type: 'string', description: 'One sentence: what the proposed query will confirm or rule out.' },
          log_entry: { type: 'string', description: 'Optional one-line finding worth recording in the investigation log. Only when something was established.' },
        },
        required: ['message'],
      },
    },
  },
};

function invSystemPrompt(env, scrubbedNotes, playbooks) {
  return `You are helping an engineer investigate a production issue in the LillianCare healthcare platform (Serverpod backend, Postgres, Principa PMS via FHIR).

HOW THIS WORKS
- You cannot run anything. Propose at most ONE read-only SELECT at a time via proposed_sql; the engineer reviews, may edit, and runs it. You then receive the result.
- All data you see has been scrubbed. Placeholders like [PERSON_1], [EMAIL_2], [DOB], [FREE_TEXT 20 chars] stand for redacted values; the same placeholder always means the same value. Never ask for the real values — reason with the placeholders and IDs.
- Numbered placeholders ([EMAIL_1], [PERSON_2], [TERM_1], …) can be used inside SQL string literals, e.g. WHERE lower(email) = lower('[EMAIL_1]'); they are replaced with the real values locally before the query runs. Prefer internal IDs when you have them.
- Connected environment: ${env}. DB timestamps are UTC; Principa payload times are Europe/Berlin local time.
- Be precise and evidence-driven: cite IDs and timestamps from results. Say clearly when something is a hypothesis.
- Keep queries narrow (filter by IDs and time windows, select only needed columns). Avoid full scans on huge log tables.
- When the evidence establishes something, put a one-line finding in log_entry.
- The notes may contain a "## Code analysis" section (a code-level briefing produced by reading the backend source) and a "## Correspondence" section (replies from Principa/Siegele or the practice). Treat them as evidence; cite code paths from the briefing when explaining behaviour.

${DB_SCHEMA_CONTEXT}
${INV_EXTRA_SCHEMA}

PLAYBOOKS (known flows and proven queries):
${playbooks || '(none)'}

CURRENT INVESTIGATION NOTES (scrubbed):
${scrubbedNotes}`;
}

// Bedrock Converse needs alternating roles starting with 'user'.
function invToConverseMessages(chat) {
  const out = [];
  for (const turn of chat) {
    let text = turn.text || '';
    if (turn.role === 'assistant' && turn.proposedSql) {
      text += `\n\nProposed query (${turn.purpose || 'no purpose given'}):\n${turn.proposedSql}`;
    }
    const last = out[out.length - 1];
    if (last && last.role === turn.role) last.content[0].text += `\n\n${text}`;
    else out.push({ role: turn.role, content: [{ text }] });
  }
  while (out.length && out[0].role !== 'user') out.shift();
  return out;
}

function invReadPlaybooks() {
  try {
    return fs.readdirSync(INV_PLAYBOOK_DIR).filter(f => INV_PLAYBOOK_RE.test(f)).sort()
      .map(f => ({ file: f, content: fs.readFileSync(path.join(INV_PLAYBOOK_DIR, f), 'utf8') }));
  } catch { return []; }
}

function invSend(res, e) {
  res.status(e.status || 500).json({ error: e.message });
}

app.get('/api/investigations', (req, res) => {
  try {
    fs.mkdirSync(INV_DIR, { recursive: true });
    const items = fs.readdirSync(INV_DIR).filter(f => INV_FILE_RE.test(f)).map(file => {
      const md = fs.readFileSync(path.join(INV_DIR, file), 'utf8');
      return { file, date: file.slice(0, 10), ...invParse(md), modifiedAt: fs.statSync(path.join(INV_DIR, file)).mtime };
    }).sort((a, b) => b.file.localeCompare(a.file));
    const playbooks = invReadPlaybooks().map(p => ({ file: p.file, title: invParse(p.content).title || p.file }));
    res.json({ dir: INV_DIR, items, playbooks, model: INV_MODEL });
  } catch (e) { invSend(res, e); }
});

app.post('/api/investigations', (req, res) => {
  try {
    const title = String((req.body || {}).title || '').trim();
    if (!title) return res.status(400).json({ error: 'Title required' });
    const today = invToday();
    let file = `${today}-${invSlug(title)}.md`;
    for (let i = 2; fs.existsSync(path.join(INV_DIR, file)); i++) file = `${today}-${invSlug(title)}-${i}.md`;
    const md = `# ${title}\n\n**Status:** OPEN\n\n## Summary\n\n_TBD_\n\n## Open questions\n\n## Follow-ups\n\n## Log\n\n- ${today}: Investigation opened.\n`;
    fs.mkdirSync(INV_DIR, { recursive: true });
    fs.writeFileSync(invPath(file), md);
    res.json({ file });
  } catch (e) { invSend(res, e); }
});

app.get('/api/investigations/playbooks/:file', (req, res) => {
  try {
    if (!INV_PLAYBOOK_RE.test(req.params.file)) return res.status(400).json({ error: 'Invalid playbook name' });
    res.json({ file: req.params.file, content: fs.readFileSync(path.join(INV_PLAYBOOK_DIR, req.params.file), 'utf8') });
  } catch (e) { invSend(res, e); }
});

app.get('/api/investigations/:file', (req, res) => {
  try {
    const content = fs.readFileSync(invPath(req.params.file), 'utf8');
    const state = invReadState(req.params.file);
    res.json({ file: req.params.file, content, ...invParse(content), chat: state.chat, terms: state.terms || [], mappingCount: state.mapping.length });
  } catch (e) { invSend(res, e); }
});

app.put('/api/investigations/:file', (req, res) => {
  try {
    const content = String((req.body || {}).content || '');
    if (!content.trim()) return res.status(400).json({ error: 'Refusing to save empty notes' });
    fs.writeFileSync(invPath(req.params.file), content);
    res.json({ ok: true, ...invParse(content) });
  } catch (e) { invSend(res, e); }
});

app.post('/api/investigations/:file/log', (req, res) => {
  try {
    const entry = String((req.body || {}).entry || '').trim();
    if (!entry) return res.status(400).json({ error: 'Empty log entry' });
    const p = invPath(req.params.file);
    const content = invAppendLog(fs.readFileSync(p, 'utf8'), entry);
    fs.writeFileSync(p, content);
    res.json({ ok: true, content });
  } catch (e) { invSend(res, e); }
});

// Extra redaction terms (names etc.) — PII, so kept in the local state only.
app.put('/api/investigations/:file/terms', (req, res) => {
  try {
    invPath(req.params.file);
    const state = invReadState(req.params.file);
    state.terms = (Array.isArray(req.body.terms) ? req.body.terms : []).map(t => String(t).trim()).filter(t => t.length >= 2);
    invWriteState(req.params.file, state);
    res.json({ ok: true, terms: state.terms });
  } catch (e) { invSend(res, e); }
});

app.get('/api/investigations/:file/mapping', (req, res) => {
  try {
    invPath(req.params.file);
    res.json({ mapping: invReadState(req.params.file).mapping });
  } catch (e) { invSend(res, e); }
});

app.delete('/api/investigations/:file/chat', (req, res) => {
  try {
    invPath(req.params.file);
    const state = invReadState(req.params.file);
    state.chat = [];
    invWriteState(req.params.file, state);
    res.json({ ok: true });
  } catch (e) { invSend(res, e); }
});

// Runs an (AI-proposed or hand-written) query read-only. Raw rows go back to
// this local UI only; the scrubbed rows are what gets added to the AI chat.
app.post('/api/investigations/:file/query', async (req, res) => {
  try {
    invPath(req.params.file);
    const sql = String((req.body || {}).sql || '');
    const env = String(req.headers['x-env'] || 'unknown');
    const state = invReadState(req.params.file);
    let turnText;
    let payload;
    try {
      const unscrubbed = invUnscrubSql(state, sql);
      const { rows, truncated } = await invReadOnlyQuery(req, unscrubbed.sql);
      const scrubbed = invScrub(state, s => s.scrubData(rows));
      const json = JSON.stringify(scrubbed.data, (k, v) => (typeof v === 'string' ? invClip(v, 4000) : v), 1);
      turnText = `I ran this query on ${env}:\n${sql.trim()}\n\nResult: ${rows.length} row(s)${truncated ? ` (capped at ${INV_MAX_ROWS})` : ''}, scrubbed:\n${invClip(json, INV_AI_RESULT_CHARS)}`;
      payload = { rows, scrubbedRows: scrubbed.data, counts: scrubbed.counts, count: rows.length, truncated, filledPlaceholders: unscrubbed.filled };
    } catch (e) {
      turnText = `I ran this query on ${env}:\n${sql.trim()}\n\nIt failed: ${e.message}`;
      payload = { error: e.message };
    }
    state.chat.push({ role: 'user', kind: 'query', text: turnText, sql: sql.trim(), env, at: new Date().toISOString() });
    invWriteState(req.params.file, state);
    res.json(payload);
  } catch (e) { invSend(res, e); }
});

// Adds the user's (scrubbed) message, if any, and asks the model for the next step.
app.post('/api/investigations/:file/ai', async (req, res) => {
  try {
    const p = invPath(req.params.file);
    const env = String(req.headers['x-env'] || 'unknown');
    const state = invReadState(req.params.file);
    const text = String((req.body || {}).text || '').trim();
    let counts = {};
    if (text) {
      const scrubbed = invScrub(state, s => s.run(text));
      counts = scrubbed.counts;
      state.chat.push({ role: 'user', kind: 'message', text: scrubbed.output, at: new Date().toISOString() });
    }
    const messages = invToConverseMessages(state.chat);
    if (!messages.length) return res.status(400).json({ error: 'Nothing to send yet — write a message first.' });

    const notes = invScrub(state, s => s.run(fs.readFileSync(p, 'utf8'))).output;
    const playbooks = invReadPlaybooks().map(pb => `### ${pb.file}\n${pb.content}`).join('\n\n');
    const response = await bedrockClient.send(new ConverseCommand({
      modelId: INV_MODEL,
      system: [{ text: invSystemPrompt(env, notes, playbooks) }],
      messages,
      toolConfig: { tools: [INV_REPLY_TOOL], toolChoice: { tool: { name: 'reply' } } },
      inferenceConfig: { maxTokens: 4000, temperature: 0.2 },
    }));
    const content = response.output.message.content || [];
    const toolUse = (content.find(c => c.toolUse) || {}).toolUse;
    const reply = toolUse ? toolUse.input : { message: (content.find(c => c.text) || {}).text || '(empty reply)' };
    const turn = {
      role: 'assistant',
      text: reply.message || '',
      proposedSql: reply.proposed_sql ? reply.proposed_sql.trim().replace(/;\s*$/, '') : null,
      purpose: reply.purpose || null,
      logEntry: reply.log_entry || null,
      at: new Date().toISOString(),
    };
    state.chat.push(turn);
    invWriteState(req.params.file, state);
    res.json({ turn, counts, userText: text ? state.chat[state.chat.length - 2].text : null });
  } catch (e) { invSend(res, e); }
});

// ─── Investigations: code analysis + correspondence ─────────────────────────
// Code analysis runs a headless Claude Code session on LillianCare-Core with
// read-only file tools only (--restricted, --tools Read,Grep,Glob) and a deny
// list for secrets. Its prompt contains the scrubbed notes + scrubbed question;
// the briefing is appended to the note's "## Code analysis" section, where the
// Bedrock chat picks it up as context. One job per investigation, in memory.
const INV_CORE_DIR = process.env.LC_CORE_DIR || path.join(__dirname, '..', 'LillianCare-Core');
const INV_SHARED_MODELS_DIR = path.join(__dirname, '..', 'LillianCare-Shared-Models');
const INV_CLAUDE_BIN = process.env.LC_CLAUDE_BIN || path.join(process.env.HOME || '', '.local', 'bin', 'claude');
const INV_CODE_TIMEOUT_MS = 10 * 60 * 1000;
const INV_CODE_SETTINGS = JSON.stringify({
  permissions: { deny: ['Read(**/passwords.yaml)', 'Read(**/.env)', 'Read(**/.env.*)', 'Read(**/.fcm_service_account.json)', 'Read(**/*.pem)', 'Read(**/*.p8)'] },
});
const invCodeJobs = {};

// Inserts `block` at the end of `heading`'s section, creating the section right
// before "## Log" (which stays last) when it does not exist yet.
function invAppendToSection(md, heading, block) {
  const m = md.match(new RegExp(`^${heading.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\s*$`, 'm'));
  if (m) {
    const after = md.slice(m.index + m[0].length);
    const next = after.search(/^## /m);
    const end = next < 0 ? md.length : m.index + m[0].length + next;
    return `${md.slice(0, end).replace(/\s*$/, '')}\n\n${block.trim()}\n${end < md.length ? `\n${md.slice(end)}` : ''}`;
  }
  const log = md.search(/^## Log\s*$/m);
  const section = `${heading}\n\n${block.trim()}\n`;
  if (log < 0) return `${md.replace(/\s*$/, '')}\n\n${section}`;
  return `${md.slice(0, log)}${section}\n${md.slice(log)}`;
}

function invCodePrompt(notes, question) {
  return `You are analysing the LillianCare backend codebase (this directory) to support a production investigation. You can only read code. Never open config/passwords.yaml, .env files or other secrets.

INVESTIGATION NOTES (scrubbed — placeholders like [PERSON_1] are redacted values):
${notes}

QUESTION:
${question}

Trace the relevant flows in the code the way a senior engineer would: find the entry points, follow the calls, and note guards, deduplication, status mappings and the exact conditions under which side effects (emails, pushes, DB writes, PMS calls) happen.

Reply with a concise markdown briefing (max ~700 words), using exactly these sections:
#### Relevant code paths
file:line references and what each does for this problem.
#### How the symptom can arise
Ranked hypotheses; for each, the evidence in the data that would confirm or rule it out.
#### Tables and fields to check
Table names, columns, enum values (with their integer values).
#### Suggested first queries
One to three narrow PostgreSQL SELECTs ("camelCase" columns quoted, timestamps are UTC). Placeholders like [EMAIL_1] may be used in string literals.
#### Open questions
What the code alone cannot answer.

Do not include patient data.`;
}

function invCodeProgress(event) {
  if (event.type !== 'assistant') return [];
  return (event.message.content || []).filter(c => c.type === 'tool_use').map(c => {
    const i = c.input || {};
    const target = i.file_path || i.pattern || i.path || '';
    return `${c.name} ${String(target).replace(INV_CORE_DIR + '/', '')}`.trim();
  });
}

app.post('/api/investigations/:file/code', (req, res) => {
  try {
    const p = invPath(req.params.file);
    const running = invCodeJobs[req.params.file];
    if (running && running.status === 'running') return res.status(409).json({ error: 'A code analysis is already running for this investigation' });
    if (!fs.existsSync(INV_CLAUDE_BIN)) return res.status(500).json({ error: `Claude Code not found at ${INV_CLAUDE_BIN} (set LC_CLAUDE_BIN)` });
    if (!fs.existsSync(INV_CORE_DIR)) return res.status(500).json({ error: `LillianCare-Core not found at ${INV_CORE_DIR} (set LC_CORE_DIR)` });

    const state = invReadState(req.params.file);
    const rawQuestion = String((req.body || {}).question || '').trim()
      || 'Which code paths could produce the problem described in the notes, and how should it be investigated?';
    const question = invScrub(state, s => s.run(rawQuestion)).output;
    const notes = invScrub(state, s => s.run(fs.readFileSync(p, 'utf8'))).output;
    invWriteState(req.params.file, state);

    const args = ['-p', invCodePrompt(notes, question), '--output-format', 'stream-json', '--verbose',
      '--tools', 'Read,Grep,Glob', '--restricted', '--strict-mcp-config', '--permission-mode', 'dontAsk',
      '--no-session-persistence', '--settings', INV_CODE_SETTINGS];
    if (fs.existsSync(INV_SHARED_MODELS_DIR)) args.push('--add-dir', INV_SHARED_MODELS_DIR);

    const job = { status: 'running', question, log: [], startedAt: new Date().toISOString(), finishedAt: null, error: null, costUsd: null };
    const child = spawn(INV_CLAUDE_BIN, args, {
      cwd: INV_CORE_DIR, detached: true, stdio: ['ignore', 'pipe', 'pipe'],
      env: { ...process.env, PATH: `${path.dirname(INV_CLAUDE_BIN)}:${process.env.PATH || ''}` },
    });
    job.child = child;
    invCodeJobs[req.params.file] = job;

    let buf = '';
    let stderr = '';
    let result = null;
    child.stdout.on('data', chunk => {
      buf += chunk.toString();
      let nl;
      while ((nl = buf.indexOf('\n')) >= 0) {
        const line = buf.slice(0, nl);
        buf = buf.slice(nl + 1);
        let event;
        try { event = JSON.parse(line); } catch { continue; }
        job.log.push(...invCodeProgress(event));
        if (job.log.length > 200) job.log.splice(0, job.log.length - 200);
        if (event.type === 'result') result = event;
      }
    });
    child.stderr.on('data', chunk => { stderr = (stderr + chunk.toString()).slice(-4000); });
    const timer = setTimeout(() => { try { process.kill(-child.pid, 'SIGTERM'); } catch {} }, INV_CODE_TIMEOUT_MS);

    child.on('close', code => {
      clearTimeout(timer);
      delete job.child;
      job.finishedAt = new Date().toISOString();
      if (job.status === 'cancelled') return;
      if (result && result.subtype === 'success' && !result.is_error && result.result) {
        job.costUsd = result.total_cost_usd ?? null;
        try {
          const md = fs.readFileSync(p, 'utf8');
          const shortQ = question.replace(/\s+/g, ' ').slice(0, 120);
          const block = `### ${invToday()}: ${shortQ}${question.length > 120 ? '…' : ''}\n\n${result.result.trim()}`;
          fs.writeFileSync(p, invAppendToSection(md, '## Code analysis', block));
          job.status = 'done';
        } catch (e) { job.status = 'failed'; job.error = e.message; }
      } else {
        job.status = 'failed';
        job.error = (result && (result.result || result.subtype)) || `Claude Code exited with code ${code}. ${stderr.trim().slice(-600)}`;
      }
    });
    child.on('error', e => { job.status = 'failed'; job.error = e.message; job.finishedAt = new Date().toISOString(); });

    res.json({ ok: true, question });
  } catch (e) { invSend(res, e); }
});

app.get('/api/investigations/:file/code', (req, res) => {
  try {
    invPath(req.params.file);
    const job = invCodeJobs[req.params.file];
    if (!job) return res.json({ job: null });
    const { child, ...rest } = job;
    res.json({ job: rest });
  } catch (e) { invSend(res, e); }
});

app.delete('/api/investigations/:file/code', (req, res) => {
  try {
    invPath(req.params.file);
    const job = invCodeJobs[req.params.file];
    if (!job || job.status !== 'running' || !job.child) return res.json({ ok: true });
    job.status = 'cancelled';
    try { process.kill(-job.child.pid, 'SIGTERM'); } catch {}
    res.json({ ok: true });
  } catch (e) { invSend(res, e); }
});

// Shows exactly what would be sent, without saving the mapping — free-text
// names the scrubber does not know can be spotted and added as terms first.
app.post('/api/investigations/:file/scrub-preview', (req, res) => {
  try {
    invPath(req.params.file);
    const state = invReadState(req.params.file);
    const scrubbed = invScrub(state, s => s.run(String((req.body || {}).text || '')));
    res.json({ output: scrubbed.output, counts: scrubbed.counts });
  } catch (e) { invSend(res, e); }
});

// Replies from Principa/Siegele (or what we sent them): scrubbed, filed under
// "## Correspondence" in the note, and added to the AI chat as evidence.
app.post('/api/investigations/:file/correspondence', (req, res) => {
  try {
    const p = invPath(req.params.file);
    const { direction, party, text } = req.body || {};
    if (!String(text || '').trim()) return res.status(400).json({ error: 'Empty correspondence' });
    const who = String(party || 'vendor').trim().slice(0, 60);
    const label = direction === 'sent' ? `Sent to ${who}` : `Received from ${who}`;
    const state = invReadState(req.params.file);
    const scrubbed = invScrub(state, s => s.run(String(text)));
    const quoted = scrubbed.output.trim().split('\n').map(l => `> ${l}`).join('\n');
    fs.writeFileSync(p, invAppendToSection(fs.readFileSync(p, 'utf8'), '## Correspondence', `### ${invToday()}: ${label}\n\n${quoted}`));
    state.chat.push({ role: 'user', kind: 'correspondence', text: `${label} (scrubbed):\n\n${scrubbed.output.trim()}`, at: new Date().toISOString() });
    invWriteState(req.params.file, state);
    res.json({ ok: true, counts: scrubbed.counts });
  } catch (e) { invSend(res, e); }
});

// ─── Static files ─────────────────────────────────────────────────────────────
app.use(express.static(path.join(__dirname, 'public'), { etag: false, maxAge: 0, setHeaders: (res) => { res.setHeader('Cache-Control', 'no-store'); } }));

app.listen(3333, () => {
  console.log('LillianCare Debugger running at http://localhost:3333');
  if (lsReadConfig().autostart) {
    setTimeout(() => lsRun('starting', lsStartServerpod), 2000);
  }
});
