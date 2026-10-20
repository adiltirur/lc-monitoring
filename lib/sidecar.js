// Principa "SideCar" reporting DB (production, run by Planorg, hosted by NT AG) — READ-ONLY.
//
// Network: 172.16.2.18:5432 is reachable only through the site-to-site VPN, and NT AG allows
// a single source IP: 10.0.13.173 (lc-core-serverpod-staging). The helper therefore never
// connects directly: it opens an SSM port-forward *through that instance*
// (AWS-StartPortForwardingSessionToRemoteHost), so the connection originates there, and it
// refuses to open the tunnel if the tagged instance doesn't have the whitelisted IP.
//
// Credentials only from env (SIDECAR_DB_USER / SIDECAR_DB_PASSWORD) — never logged or returned.
// Read-only twice over: the session starts with default_transaction_read_only=on, and every
// query runs inside BEGIN READ ONLY … ROLLBACK with a statement timeout and a row cap.
// Used by routes/sidecar.js (view #sidecar) and scripts/sidecar_smoke_test.js.
const net = require('net');
const { spawn } = require('child_process');
const { Client } = require('pg');
const { DescribeInstancesCommand } = require('@aws-sdk/client-ec2');
const { ec2Client, AWS_REGION } = require('./aws');

const env = (k, d = '') => (process.env[k] || d).trim();
const cfg = () => ({
  host: env('SIDECAR_DB_HOST', '172.16.2.18'),
  port: Number(env('SIDECAR_DB_PORT', '5432')),
  database: env('SIDECAR_DB_NAME', 'scliliancareprod'),
  sslmode: env('SIDECAR_DB_SSLMODE', 'prefer'),
  user: env('SIDECAR_DB_USER'),
  password: env('SIDECAR_DB_PASSWORD'),
  sourceIp: env('SIDECAR_SOURCE_IP', '10.0.13.173'),
  instanceTag: env('SIDECAR_SSM_INSTANCE_TAG', 'lc-core-serverpod-staging'),
  localPort: Number(env('SIDECAR_LOCAL_PORT', '25432')),
});

const CONNECT_TIMEOUT_MS = 10000;
const STATEMENT_TIMEOUT_MS = 30000;
const MAX_ROWS = 200;
const SSM_PATH = ['/opt/homebrew/bin', '/usr/local/bin', process.env.PATH || ''].join(':');

function fail(code, message, cause) {
  return Object.assign(new Error(message), { code, cause_hint: cause, status: code === 'NO_CREDS' ? 412 : 502 });
}

// ── tunnel ──
let tunnel = null; // { child, instanceId, status, lastError, startedAt }

function tunnelState() {
  if (!tunnel) return { status: 'stopped' };
  const { child, ...pub } = tunnel;
  return pub;
}

function portOpen(port) {
  return new Promise((resolve) => {
    const s = net.connect({ host: '127.0.0.1', port }, () => { s.destroy(); resolve(true); });
    s.on('error', () => resolve(false));
    s.setTimeout(1000, () => { s.destroy(); resolve(false); });
  });
}

async function resolveWhitelistedInstance() {
  const c = cfg();
  const out = await ec2Client.send(new DescribeInstancesCommand({
    Filters: [{ Name: 'tag:Name', Values: [c.instanceTag] }, { Name: 'instance-state-name', Values: ['running'] }],
  }));
  const instances = (out.Reservations || []).flatMap(r => r.Instances || []);
  const match = instances.find(i => i.PrivateIpAddress === c.sourceIp);
  if (!match) {
    const seen = instances.map(i => `${i.InstanceId}=${i.PrivateIpAddress}`).join(', ') || 'none running';
    throw fail('WRONG_SOURCE', `Refusing to open the tunnel: no running ${c.instanceTag} instance has the whitelisted IP ${c.sourceIp} (found: ${seen}).`,
      'NT AG only allows 10.0.13.173. If the instance was replaced, its IP changed — the whitelist must be updated first.');
  }
  return match.InstanceId;
}

async function openTunnel() {
  const c = cfg();
  if (tunnel && tunnel.status === 'connected' && await portOpen(c.localPort)) return tunnelState();
  if (await portOpen(c.localPort)) throw fail('PORT_BUSY', `Local port ${c.localPort} is already in use (set SIDECAR_LOCAL_PORT).`);
  const instanceId = await resolveWhitelistedInstance();
  const params = JSON.stringify({ host: [c.host], portNumber: [String(c.port)], localPortNumber: [String(c.localPort)] });
  const child = spawn('aws', ['ssm', 'start-session', '--target', instanceId, '--document-name', 'AWS-StartPortForwardingSessionToRemoteHost',
    '--parameters', params, '--region', AWS_REGION], { env: { ...process.env, PATH: SSM_PATH }, detached: true });
  tunnel = { child, instanceId, status: 'starting', lastError: null, startedAt: new Date().toISOString(), localPort: c.localPort };
  const t = tunnel;
  await new Promise((resolve) => {
    const done = () => { clearTimeout(timer); resolve(); };
    const timer = setTimeout(done, 15000);
    child.stdout.on('data', (b) => { if (/Waiting for connections/i.test(b.toString())) { t.status = 'connected'; done(); } });
    child.stderr.on('data', (b) => { t.lastError = b.toString().trim().slice(0, 500); });
    child.on('error', (e) => { t.status = 'error'; t.lastError = e.message; done(); });
    child.on('exit', (code) => { if (t.status !== 'connected' && !t.lastError) t.lastError = `aws ssm exited (code ${code})`; t.status = 'stopped'; done(); });
  });
  if (t.status !== 'connected') {
    closeTunnel();
    throw fail('TUNNEL', `SSM tunnel via ${instanceId} did not start: ${t.lastError || 'no answer within 15 s'}`,
      'Needs the AWS CLI + session-manager-plugin and SSM access to the staging instance.');
  }
  return tunnelState();
}

function closeTunnel() {
  if (tunnel && tunnel.child) { try { process.kill(-tunnel.child.pid, 'SIGTERM'); } catch { try { tunnel.child.kill('SIGTERM'); } catch { /* gone */ } } }
  tunnel = null;
  return tunnelState();
}

// ── connection ──
function missingCreds() {
  const c = cfg();
  return ['SIDECAR_DB_USER', 'SIDECAR_DB_PASSWORD'].filter(k => !env(k));
}

// Maps driver errors to the likely cause, per the agreed setup.
function classify(e) {
  const msg = String(e.message || e);
  if (e.code === '28P01' || e.code === '28000' || /password authentication failed|no pg_hba.conf entry|role .* does not exist/i.test(msg)) {
    return fail('AUTH', `Authentication failed: ${msg}`, 'The read-only user is missing or the credentials are wrong — waiting on Planorg to create it / check SIDECAR_DB_USER/PASSWORD.');
  }
  if (e.code === '3D000') return fail('NO_DB', msg, `Database ${cfg().database} not found — check SIDECAR_DB_NAME with Planorg.`);
  if (/timeout|ETIMEDOUT|Connection terminated unexpectedly|ECONNRESET/i.test(msg)) {
    return fail('TIMEOUT', `Connection timed out after ${CONNECT_TIMEOUT_MS / 1000} s: ${msg}`,
      'Network path: the tunnel/whitelist. Traffic from 10.0.13.173 to 172.16.2.16/28 currently leaves via the NAT gateway (source 10.0.4.131), which NT AG has not whitelisted.');
  }
  if (/ECONNREFUSED/.test(msg)) return fail('TUNNEL', `Connection refused: ${msg}`, 'The SSM tunnel is not running (open it first).');
  return fail('ERROR', msg);
}

async function connect() {
  const c = cfg();
  const missing = missingCreds();
  if (missing.length) throw fail('NO_CREDS', `Missing ${missing.join(' and ')} in helper/.env`, 'Waiting on read-only credentials from Planorg.');
  const base = {
    host: '127.0.0.1', port: c.localPort, database: c.database, user: c.user, password: c.password,
    connectionTimeoutMillis: CONNECT_TIMEOUT_MS,
    options: `-c default_transaction_read_only=on -c statement_timeout=${STATEMENT_TIMEOUT_MS}`,
    application_name: 'lc-helper-sidecar-readonly',
  };
  // libpq's sslmode=prefer: try TLS, fall back to plain if the server doesn't offer it.
  const attempts = c.sslmode === 'disable' ? [false] : c.sslmode === 'prefer' ? [{ rejectUnauthorized: false }, false] : [{ rejectUnauthorized: false }];
  let last;
  for (const ssl of attempts) {
    const client = new Client({ ...base, ssl });
    try {
      await client.connect();
      const ro = (await client.query('SHOW default_transaction_read_only')).rows[0].default_transaction_read_only;
      if (ro !== 'on') { await client.end(); throw fail('NOT_READONLY', 'Session is not read-only — refusing to continue.'); }
      client.sslUsed = !!ssl;
      return client;
    } catch (e) {
      last = e;
      await client.end().catch(() => {});
      if (!(ssl && /does not support SSL|SSL is not enabled/i.test(String(e.message)))) break;
    }
  }
  throw last.code && ['NOT_READONLY'].includes(last.code) ? last : classify(last);
}

// One statement, wrapped as a subquery (extended protocol rejects multiple commands),
// inside a READ ONLY transaction that is always rolled back.
async function readOnlyQuery(client, sql, maxRows = MAX_ROWS) {
  const text = String(sql || '').trim().replace(/;\s*$/, '');
  if (!text) throw Object.assign(new Error('No SQL provided'), { status: 400 });
  try {
    await client.query('BEGIN TRANSACTION READ ONLY');
    const r = await client.query({ text: `SELECT * FROM (\n${text}\n) AS sidecar_q LIMIT ${maxRows + 1}`, values: [], queryMode: 'extended' });
    const truncated = r.rows.length > maxRows;
    return { fields: r.fields.map(f => f.name), rows: truncated ? r.rows.slice(0, maxRows) : r.rows, truncated };
  } finally {
    await client.query('ROLLBACK').catch(() => {});
  }
}

const TABLES_SQL = `SELECT t.table_schema AS schema, t.table_name AS "table", t.table_type AS type,
         CASE WHEN c.reltuples < 0 THEN NULL ELSE c.reltuples::bigint END AS approx_rows
    FROM information_schema.tables t
    LEFT JOIN pg_namespace n ON n.nspname = t.table_schema
    LEFT JOIN pg_class c ON c.relnamespace = n.oid AND c.relname = t.table_name
   WHERE t.table_schema NOT IN ('pg_catalog', 'information_schema')
   ORDER BY 1, 2`;

async function smokeTest(client) {
  const info = (await readOnlyQuery(client, 'SELECT version() AS version, current_database() AS database, current_user AS "user"')).rows[0];
  const tables = await readOnlyQuery(client, TABLES_SQL, 5000);
  return { ...info, ssl: client.sslUsed, readOnly: true, tables: tables.rows, truncated: tables.truncated };
}

function psqlOneLiners() {
  const c = cfg();
  return {
    onHost: `psql "host=${c.host} port=${c.port} dbname=${c.database} user=$SIDECAR_DB_USER sslmode=${c.sslmode} options='-c default_transaction_read_only=on'"`,
    viaTunnel: `psql "host=127.0.0.1 port=${c.localPort} dbname=${c.database} user=$SIDECAR_DB_USER sslmode=${c.sslmode} options='-c default_transaction_read_only=on'"`,
  };
}

function status() {
  const c = cfg();
  return {
    host: c.host, port: c.port, database: c.database, sslmode: c.sslmode, sourceIp: c.sourceIp, instanceTag: c.instanceTag,
    localPort: c.localPort, credentials: { user: !!c.user, password: !!c.password }, tunnel: tunnelState(), psql: psqlOneLiners(),
  };
}

module.exports = { status, openTunnel, closeTunnel, connect, readOnlyQuery, smokeTest, psqlOneLiners, missingCreds, cfg };
