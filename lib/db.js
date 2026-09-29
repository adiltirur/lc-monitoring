const { Pool } = require('pg');

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

module.exports = { bindValue, buildWhere, getPool, paginate, poolFromHeaders, poolQuery, pools, query, quoteIdent, tableColumns };
