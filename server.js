require('dotenv').config();
const express = require('express');
const { Pool } = require('pg');
const path = require('path');
const fs = require('fs');
const { BedrockRuntimeClient, ConverseCommand } = require('@aws-sdk/client-bedrock-runtime');
const { GoogleAuth } = require('google-auth-library');
const { EC2Client, DescribeInstancesCommand } = require('@aws-sdk/client-ec2');
const { CloudWatchClient, GetMetricDataCommand, DescribeAlarmsCommand, SetAlarmStateCommand } = require('@aws-sdk/client-cloudwatch');
const { CloudWatchLogsClient, FilterLogEventsCommand, DescribeLogGroupsCommand } = require('@aws-sdk/client-cloudwatch-logs');
const { RDSClient, DescribeDBInstancesCommand } = require('@aws-sdk/client-rds');
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
                    AND "startTime">=$1 AND "startTime"<$2 GROUP BY "praxisId"`, [rangeStartIso, rangeEndIso]),
      query(req, `SELECT "praxisId",
                    COUNT(*)::int AS total,
                    COUNT(*) FILTER (WHERE "isBookedFromPraxis"=true)::int AS praxis,
                    COUNT(*) FILTER (WHERE "isBookedFromPraxis" IS NOT TRUE)::int AS web
                  FROM guest_appointment
                  WHERE "praxisId" IS NOT NULL AND "startTime" IS NOT NULL
                    AND "startTime">=$1 AND "startTime"<$2 GROUP BY "praxisId"`, [rangeStartIso, rangeEndIso]),
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
      npsEmailsSent: 0, guestNPS: 0, guestNPSNoEmail: 0, totalNPS: 0,
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
      p.guestNPS        = r.total;
      p.guestNPSNoEmail = r.no_email;
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
      p.appointmentsTotal = p.appAppointments + p.guestBookedFromWeb + p.guestBookedFromPraxis + p.guestBookedFromPraxisNoEmail;
      p.tookPlaceTotal = p.appTookPlace + p.guestTookPlaceWeb + p.guestTookPlacePraxis;
      p.totalNPS = p.npsEmailsSent + p.guestNPS;
      p.npsCoveragePercentage = p.appointmentsTotal > 0 ? (p.totalNPS / p.appointmentsTotal) * 100 : 0;
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
      totalNPS:                sumAll('totalNPS'),
      // Global (not per-praxis in the schema)
      totalCancellations:      totalCancellations[0].c,
      totalQuestionnaires:     totalQuestionnaires[0].c,
      totalDeletions:          totalDeletions[0].c,
      pmsDowntimeSeconds:      parseInt(pmsDowntimeSum[0].s, 10) || 0,
      pmsDowntimeMinutes:      (parseInt(pmsDowntimeSum[0].s, 10) || 0) / 60,
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
      countOne(`SELECT COUNT(*) FROM app_user_appointment WHERE "praxisId"=$1 AND "startTime" IS NOT NULL AND "startTime">=$2 AND "startTime"<$3`, [praxisId, rangeStartIso, rangeEndIso]),
      countOne(`SELECT COUNT(*) FROM guest_appointment    WHERE "praxisId"=$1 AND "startTime" IS NOT NULL AND "startTime">=$2 AND "startTime"<$3 AND ("isBookedFromPraxis" IS NOT TRUE)`, [praxisId, rangeStartIso, rangeEndIso]),
      countOne(`SELECT COUNT(*) FROM guest_appointment    WHERE "praxisId"=$1 AND "startTime" IS NOT NULL AND "startTime">=$2 AND "startTime"<$3 AND "isBookedFromPraxis"=true`, [praxisId, rangeStartIso, rangeEndIso]),
      countOne(`SELECT COUNT(*) FROM guest_appointment    WHERE "praxisId"=$1 AND "startTime" IS NOT NULL AND "startTime">=$2 AND "startTime"<$3 AND "isBookedFromPraxis"=true AND "hasEmail"=false`, [praxisId, rangeStartIso, rangeEndIso]),
      query(req, `SELECT id, "userId", "familyMemberId", category, reason, "appointmentId", "pmsAppointmentId", status, "praxisId", "startTime", "createdAt" FROM app_user_appointment WHERE "praxisId"=$1 AND "createdAt">=$2 AND "createdAt"<$3`, [praxisId, rangeStart, rangeEnd]),
      query(req, `SELECT id, "bookingId", "patientId", "praxisId", category, "hasEmail", "isBookedFromPraxis", "createdAt" FROM guest_appointment WHERE "praxisId"=$1 AND "createdAt">=$2 AND "createdAt"<$3`, [praxisId, rangeStart, rangeEnd]),
      query(req, `SELECT id, "totalDownTimeInSeconds", "createdAt" FROM analytics_pms_downtime WHERE "createdAt">=$1 AND "createdAt"<$2`, [rangeStart, rangeEnd]),
      query(req, `SELECT id, "userId", category, reason, "praxisId", status, "createdAt" FROM app_user_open_consultation WHERE "praxisId"=$1 AND "createdAt">=$2 AND "createdAt"<$3`, [praxisId, rangeStart, rangeEnd]),
      query(req, `SELECT id, "userId", reason, "createdAt" FROM app_user_appointment_cancellation_reason WHERE "createdAt">=$1 AND "createdAt"<$2`, [rangeStart, rangeEnd]),
      query(req, `SELECT id, "firstName", "lastName", email, "praxisId", "isVerified", "createdAt" FROM app_user_info WHERE "praxisId"=$1 AND "createdAt">=$2 AND "createdAt"<$3`, [praxisId, rangeStart, rangeEnd]),
      query(req, `SELECT id, "userId", category, "praxisId", "isFromWeb", "createdAt" FROM app_user_document_request WHERE "praxisId"=$1 AND "createdAt">=$2 AND "createdAt"<$3`, [praxisId, rangeStart, rangeEnd]),
      query(req, `SELECT id, "userInfoId", "questionnaireId", "answeredAt", "createdAt" FROM app_user_questionnaire WHERE "answeredAt">=$1 AND "answeredAt"<$2`, [rangeStart, rangeEnd]),
      query(req, `SELECT id, reason, "createdAt" FROM app_user_deletion_feedback WHERE "createdAt">=$1 AND "createdAt"<$2`, [rangeStart, rangeEnd]),
    ]);

    // Derived counts from the in-range appointment lists (matches the Dart
    // calculator's getters so numbers always agree with the lists we return).
    const appointmentsBookedFromApp    = appAppointmentsInRange.length;
    const appointmentsBookedFromWeb    = webAppointmentsInRange.filter(a => a.isBookedFromPraxis !== true).length;
    const appointmentsBookedFromPraxis = webAppointmentsInRange.filter(a => a.isBookedFromPraxis === true).length;
    const appointmentsBookedFromPraxisWithoutEmail = webAppointmentsInRange.filter(a => a.isBookedFromPraxis === true && a.hasEmail !== true).length;
    const totalAppointments = appointmentsBookedFromApp + appointmentsBookedFromWeb + appointmentsBookedFromPraxis + appointmentsBookedFromPraxisWithoutEmail;

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
    const totalNPSSent = npsEmailsSent + guestNPSSent;
    const npsCoveragePercentage = totalAppointments > 0 ? (totalNPSSent / totalAppointments) * 100 : 0;
    const pmsDowntimeSeconds = pmsDowntimes.reduce((s, d) => s + (d.totalDownTimeInSeconds || 0), 0);
    const pmsDowntimeMinutes = pmsDowntimeSeconds / 60;
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
      npsEmailsSent, guestNPSSent, guestNPSRequestWithoutEmail, totalNPSSent,
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
      pmsDowntimeSeconds, pmsDowntimeMinutes,
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

// ─── Static files ─────────────────────────────────────────────────────────────
app.use(express.static(path.join(__dirname, 'public'), { etag: false, maxAge: 0, setHeaders: (res) => { res.setHeader('Cache-Control', 'no-store'); } }));

app.listen(3333, () => {
  console.log('LillianCare Debugger running at http://localhost:3333');
});
