const router = require('express').Router();
const { Client } = require('pg');
const { bindValue, quoteIdent } = require('../lib/db');

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
router.post('/api/db-refresh/preflight', async (req, res) => {
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
router.post('/api/db-refresh/run', async (req, res) => {
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

module.exports = router;
