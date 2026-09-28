#!/usr/bin/env node
// Lilli ops: logs, calls, read-only SQL, status and deploys for the Lilli staging box.
// Used two ways: as a CLI (`node scripts/lilli.js help`, built for local Claude Code sessions)
// and as a module by server.js (/api/lilli/*, view #lilli). Everything that can carry patient
// data (survey answers, caller speech, phone numbers, booking payloads) is scrubbed before it
// leaves this file.
//
// Secrets come from helper/.env (LILLI_DB_STAGING_PASSWORD) and are never printed.

const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawn, spawnSync } = require('child_process');

require('dotenv').config({ path: path.join(__dirname, '..', '.env'), quiet: true });

const HELPER_DIR = path.join(__dirname, '..');
const cfg = {
  ssh: process.env.LILLI_SSH || 'ubuntu@3.70.67.24',
  sshKey: process.env.LILLI_SSH_KEY || path.join(os.homedir(), '.ssh', 'lc_helper_ed25519'),
  repo: process.env.LILLI_REPO || path.join(HELPER_DIR, '..', 'Lilli'),
  db: {
    host: process.env.LILLI_DB_STAGING_HOST || 'lilli-staging.clyg4y6ua706.eu-central-1.rds.amazonaws.com',
    port: 5432,
    database: process.env.LILLI_DB_STAGING_NAME || 'lilli',
    user: process.env.LILLI_DB_STAGING_USER || 'postgres',
    password: process.env.LILLI_DB_STAGING_PASSWORD,
    ssl: { rejectUnauthorized: false },
  },
  scrubberFile: path.join(HELPER_DIR, '..', 'investigations', 'tools', 'principa-log-scrubber.html'),
  stateFile: path.join(HELPER_DIR, '.lilli-state', 'scrub-mapping.json'),
  deployScript: path.join(__dirname, 'lilli-deploy-remote.sh'),
};
const MAX_ROWS = 200;
const SQL_TIMEOUT_MS = 20000;
const PM2_NAMES = { web: 'lilli-staging', ws: 'lilli-ws' };

// ─── Scrubbing ───────────────────────────────────────────────────────────────
// Shared scrubber core (same source as the helper's Investigations view), with the
// placeholder mapping persisted locally so [PHONE_1] etc. stay stable across commands.

let scrubber;
function getScrubber() {
  if (scrubber) return scrubber;
  const html = fs.readFileSync(cfg.scrubberFile, 'utf8');
  const start = html.indexOf('// CORE-START');
  const end = html.indexOf('// CORE-END');
  if (start < 0 || end < 0) throw new Error(`Scrubber core markers missing in ${cfg.scrubberFile}`);
  const createScrubber = new Function(`${html.slice(start, end)}; return createScrubber;`)();
  let state = { mapping: [] };
  try { state = JSON.parse(fs.readFileSync(cfg.stateFile, 'utf8')); } catch { /* first run */ }
  scrubber = createScrubber({ state });
  return scrubber;
}

function saveScrubState() {
  if (!scrubber) return;
  fs.mkdirSync(path.dirname(cfg.stateFile), { recursive: true, mode: 0o700 });
  fs.writeFileSync(cfg.stateFile, JSON.stringify(scrubber.exportState()), { mode: 0o600 });
}

// Bracketed like the scrubber's own placeholders, so the scrubber leaves it alone.
const REDACTED = '[REDACTED]';
const scrubText = (s) => (s == null || s === '' ? s : getScrubber().run(String(s)).output);
const scrubData = (d) => getScrubber().scrubData(d).data;

function scrubJsonTail(prefix, json) {
  try { return `${prefix}${JSON.stringify(scrubData(JSON.parse(json)))}`; }
  catch { return `${prefix}${REDACTED}`; }
}

// Lilli log lines that carry answers or speech (see console.* calls in Lilli's server/ws-server.ts
// and lib/*). Question ids and choice codes stay; values and utterances go.
const LINE_RULES = [
  // Lilli user/assistant ids are internal cuids; label them so the scrubber's "user: <login>" rule skips them
  [/\buser: (c[a-z0-9]{20,})\b/g, 'userId $1'],
  [/(answers array: ).*$/, `$1${REDACTED}`],
  [/(\b(?:args|response): )(\{.*|\[.*)$/, (_, p, json) => scrubJsonTail(p, json)],
  [/(from: )".*"?$/, `$1"${REDACTED}"`],
  [/(\[TWF TRANSCRIPT\] )(\w+): .*$/, (_, p, role) => `${p}${role}-turn ${REDACTED}`],
  [/(CORRECTED: )".*" → ".*"/, `$1"${REDACTED}" → "${REDACTED}"`],
  [/(AUTO-CORRECTED choice )'.*?'( → )/, `$1'${REDACTED}'$2`],
  [/(INVALID value )'.*?'( for )/, `$1'${REDACTED}'$2`],
  [/(Dropped [\w.-]+=)[^—]*(—)/, `$1${REDACTED} $2`],
  [/(\b[\w.-]+ = ).*?( \((?:page not yet visible|high confidence)\))?$/, (_, p, suffix) => `${p}${REDACTED}${suffix || ''}`],
  [/(\[ARIA-LISTENER\] (?:Recorded|Buffered): [\w.-]+ = ).*$/, `$1${REDACTED}`],
];

function scrubLogLine(line) {
  let out = line;
  for (const [re, rep] of LINE_RULES) out = out.replace(re, rep);
  return scrubText(out);
}

// Columns whose content is free text from callers or the AI; always dropped from SQL output.
const FREE_TEXT_COLUMNS = new Set(['transcript', 'structuredSummary', 'userMessage', 'assistantSnapshot']);
function scrubRow(row) {
  const out = {};
  for (const [k, v] of Object.entries(row)) {
    if (v == null) out[k] = v;
    else if (v instanceof Date) out[k] = v.toISOString();
    else if (FREE_TEXT_COLUMNS.has(k)) out[k] = `${REDACTED} (${String(v).length} chars)`;
    else if (k === 'answers') out[k] = answerKeys(v);
    else if (k === 'events') out[k] = `(${parseJson(v, []).length} events)`;
    else out[k] = v;
  }
  return scrubData(out);
}

function parseJson(v, fallback) {
  if (v == null) return fallback;
  if (typeof v === 'object') return v;
  try { return JSON.parse(v); } catch { return fallback; }
}

function answerKeys(v) {
  const answers = parseJson(v, null);
  if (!answers || typeof answers !== 'object') return REDACTED;
  return Object.keys(answers).map((k) => `${k}=${REDACTED}`).join(', ');
}

// Event payload keys that hold what the caller or the AI said.
const SPEECH_KEYS = new Set(['text', 'utterance', 'transcript', 'value', 'values', 'answer', 'answers', 'displayValue', 'raw', 'input', 'content']);
function dropSpeech(obj) {
  if (Array.isArray(obj)) return obj.map(dropSpeech);
  if (!obj || typeof obj !== 'object') return obj;
  return Object.fromEntries(Object.entries(obj).map(([k, v]) => [k, SPEECH_KEYS.has(k) ? REDACTED : dropSpeech(v)]));
}

// ─── Remote + DB helpers ─────────────────────────────────────────────────────

function sshArgs(extra = []) {
  return ['-i', cfg.sshKey, '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=10', ...extra, cfg.ssh];
}

// Async so the helper server's event loop keeps running while the box answers.
function sshRun(command) {
  return new Promise((resolve, reject) => {
    const child = spawn('ssh', [...sshArgs(), command], { stdio: ['ignore', 'pipe', 'pipe'] });
    let out = '';
    let err = '';
    child.stdout.on('data', (d) => { out += d; });
    child.stderr.on('data', (d) => { err += d; });
    child.on('error', reject);
    child.on('close', (code) => (code === 0 ? resolve(out) : reject(new Error(`ssh failed (${code}): ${err.trim()}`))));
  });
}

// The Lilli RDS sits in private subnets, so queries go through an SSH tunnel via the Lilli box.
// The tunnel and pool are reused across calls; if the tunnel dies, the next call opens a new one.
let pool;
let tunnel;
let dbReady;
function db() {
  if (!cfg.db.password) return Promise.reject(new Error('LILLI_DB_STAGING_PASSWORD is not set in helper/.env'));
  if (!dbReady) {
    dbReady = openDb().catch((err) => { closeDb(); throw err; });
  }
  return dbReady;
}

async function openDb() {
  const port = await freePort();
  const t = spawn('ssh', [...sshArgs(['-N', '-o', 'ExitOnForwardFailure=yes', '-o', 'ServerAliveInterval=30',
    '-L', `127.0.0.1:${port}:${cfg.db.host}:${cfg.db.port}`])], { stdio: 'ignore' });
  tunnel = t;
  t.on('exit', () => { if (tunnel === t) closeDb(); });
  await waitForPort(t, port, 15000);
  const { Pool } = require('pg');
  pool = new Pool({ ...cfg.db, host: '127.0.0.1', port, max: 2, idleTimeoutMillis: 60000 });
  pool.on('error', () => {});
  return pool;
}

function closeDb() {
  const p = pool;
  const t = tunnel;
  pool = null; tunnel = null; dbReady = null;
  if (p) p.end().catch(() => {});
  if (t && t.exitCode == null) t.kill();
}
process.on('exit', () => { if (tunnel) tunnel.kill(); });

function freePort() {
  return new Promise((resolve, reject) => {
    const srv = require('net').createServer().listen(0, '127.0.0.1', () => {
      const { port } = srv.address();
      srv.close(() => resolve(port));
    }).on('error', reject);
  });
}

async function waitForPort(t, port, timeoutMs) {
  const net = require('net');
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (t.exitCode != null) throw new Error('SSH tunnel to the Lilli box failed');
    const ok = await new Promise((r) => {
      const s = net.connect(port, '127.0.0.1', () => { s.destroy(); r(true); }).on('error', () => r(false));
    });
    if (ok) return;
    await new Promise((r) => setTimeout(r, 200));
  }
  throw new Error('SSH tunnel to the Lilli box did not come up');
}

// Every query runs in a READ ONLY transaction with a timeout and a row cap, via the extended
// protocol so Postgres rejects multiple statements (a `; COMMIT; DELETE …` can't escape the
// transaction). Same guard as invReadOnlyQuery in server.js.
async function readOnly(sql, params = []) {
  const client = await (await db()).connect();
  try {
    await client.query('BEGIN TRANSACTION READ ONLY');
    await client.query(`SET LOCAL statement_timeout = ${SQL_TIMEOUT_MS}`);
    const text = `SELECT * FROM (${sql.trim().replace(/;+\s*$/, '')}) q LIMIT ${MAX_ROWS + 1}`;
    const r = await client.query({ text, values: params, queryMode: 'extended' });
    return { rows: r.rows.slice(0, MAX_ROWS), truncated: r.rows.length > MAX_ROWS };
  } finally {
    await client.query('ROLLBACK').catch(() => {});
    client.release();
  }
}

function parseSince(s) {
  const m = /^(\d+)([mhd])$/.exec(s || '');
  if (!m) throw new Error(`since expects e.g. 30m, 6h, 2d (got "${s}")`);
  return new Date(Date.now() - Number(m[1]) * { m: 60e3, h: 3600e3, d: 86400e3 }[m[2]]);
}

function git(...args) {
  const r = spawnSync('git', ['-C', cfg.repo, ...args], { encoding: 'utf8' });
  if (r.status !== 0) throw new Error(`git ${args.join(' ')}: ${r.stderr.trim()}`);
  return r.stdout.trim();
}

// ─── Data (shared by the CLI and server.js) ──────────────────────────────────

// PM2's process list carries each process's environment (secrets), so it is reduced to safe
// fields on the box and only those come back.
async function statusData() {
  const out = await sshRun(`
    echo "release=$(readlink /opt/lilli-current 2>/dev/null)"
    echo "checkout=$(git -C /opt/lilli rev-parse --short HEAD 2>/dev/null)"
    base=$(grep -hE "^LILLI_BASE_PATH=" /opt/lilli-current/.env /opt/lilli/app/.env 2>/dev/null | head -1 | cut -d= -f2-)
    echo "web=$(curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:3001\${base}/login")"
    echo "ws=$(ss -ltn | grep -q ":3002 " && echo up || echo down)"
    echo "disk=$(df -h / | awk 'NR==2 {print $4 " free of " $2}')"
    tail -n 10 /opt/lilli-shared/deploys.log 2>/dev/null | sed 's/^/deploy=/'
    pm2 jlist | node -e '
      const ps = JSON.parse(require("fs").readFileSync(0, "utf8"));
      for (const p of ps) {
        const e = p.pm2_env;
        console.log("proc=" + JSON.stringify({ name: p.name, status: e.status, uptimeMs: e.pm_uptime ? Date.now() - e.pm_uptime : null,
          restarts: e.restart_time, memoryMb: Math.round((p.monit?.memory || 0) / 1048576), cpu: p.monit?.cpu, cwd: e.pm_cwd }));
      }'
  `);
  const s = { procs: [], deploys: [] };
  for (const line of out.split('\n')) {
    const i = line.indexOf('=');
    if (i < 0) continue;
    const [k, v] = [line.slice(0, i), line.slice(i + 1)];
    if (k === 'proc') s.procs.push(JSON.parse(v));
    else if (k === 'deploy') s.deploys.push(v);
    else s[k] = v;
  }
  s.liveRelease = s.release ? path.basename(path.dirname(s.release)) : null;
  return s;
}

async function logsData(opts = {}) {
  const lines = Math.min(Number(opts.lines || 200), 5000);
  const names = opts.proc === 'web' ? [PM2_NAMES.web] : opts.proc === 'ws' ? [PM2_NAMES.ws] : [PM2_NAMES.web, PM2_NAMES.ws];
  const grep = opts.grep ? new RegExp(opts.grep, 'i') : null;
  const out = [];
  for (const name of names) {
    const raw = await sshRun(`pm2 logs ${name} --nostream --lines ${lines} ${opts.errors ? '--err' : ''} 2>/dev/null`);
    for (const l of raw.split('\n')) {
      if (!l.trim() || /^\[TAILING\]|last \d+ lines:$/.test(l.trim())) continue;
      const text = l.replace(/^\d+\|[\w-]+\s*\|\s?/, '');
      if (grep && !grep.test(text)) continue;
      out.push({ proc: name === PM2_NAMES.ws ? 'ws' : 'web', line: scrubLogLine(text) });
    }
  }
  saveScrubState();
  return out;
}

async function callsData(opts = {}) {
  const where = [];
  const params = [];
  if (opts.since) { params.push(parseSince(opts.since)); where.push(`c."startedAt" >= $${params.length}`); }
  if (opts.status) { params.push(opts.status); where.push(`c.status = $${params.length}`); }
  if (opts.outcome) { params.push(opts.outcome); where.push(`c.outcome = $${params.length}`); }
  if (opts.errors) where.push(`c."errorMessage" IS NOT NULL`);
  params.push(Math.min(Number(opts.limit || 30), MAX_ROWS));
  const { rows } = await readOnly(`
    SELECT c.id, c."startedAt", c.status, c.outcome, c.source, c."durationSeconds" AS secs,
           c."questionsAnswered" || '/' || c."questionsTotal" AS answered,
           round(c."totalCostUsd"::numeric, 3) AS usd, a.name AS assistant, c."workflowRunId" AS run,
           left(c."errorMessage", 120) AS error
    FROM "Call" c LEFT JOIN "Assistant" a ON a.id = c."assistantId"
    ${where.length ? `WHERE ${where.join(' AND ')}` : ''}
    ORDER BY c."startedAt" DESC LIMIT $${params.length}`, params);
  const out = rows.map(scrubRow);
  saveScrubState();
  return out;
}

async function callData(id) {
  if (!id) throw new Error('call id required (id, externalId or callSid)');
  const { rows: [call] } = await readOnly(`
    SELECT c.*, a.name AS "assistantName"
    FROM "Call" c LEFT JOIN "Assistant" a ON a.id = c."assistantId"
    WHERE c.id = $1 OR c."externalId" = $1 OR c."callSid" = $1 LIMIT 1`, [id]);
  if (!call) throw Object.assign(new Error(`No call with id/externalId/callSid ${id}`), { status: 404 });

  const secs = call.durationSeconds ?? (call.endedAt ? Math.round((new Date(call.endedAt) - new Date(call.startedAt)) / 1000) : null);
  const facts = scrubData({
    id: call.id, externalId: call.externalId, callSid: call.callSid,
    assistant: `${call.assistantName} (${call.assistantId})`, owner: call.userId,
    source: call.source, status: call.status, outcome: call.outcome,
    started: call.startedAt && new Date(call.startedAt).toISOString(),
    ended: call.endedAt && new Date(call.endedAt).toISOString(),
    duration: secs == null ? null : `${secs}s`,
    questions: `${call.questionsAnswered}/${call.questionsTotal} answered`,
    cost: `$${Number(call.totalCostUsd).toFixed(4)} (${call.inputTokens} in / ${call.outputTokens} out tokens)`,
    workflow: call.workflowId ? `${call.workflowId} node ${call.workflowNodeId} run ${call.workflowRunId}` : null,
    escalation: call.escalationAttempts ? `${call.escalationAttempts} attempts` : null,
    recording: call.recordingUrl ? 'yes' : 'no',
    caller: call.callerNumber,
    error: call.errorMessage,
    answers: answerKeys(call.answers),
    transcript: call.transcript ? `${REDACTED} (${call.transcript.length} chars)` : null,
    summary: call.structuredSummary ? `${REDACTED} (${call.structuredSummary.length} chars)` : null,
  });
  const booking = call.bookingMetadata ? scrubData(call.bookingMetadata) : null;
  const t0 = new Date(call.startedAt).getTime();
  const events = parseJson(call.events, []).map((e) => {
    const at = e.timestamp || e.time || e.ts;
    const { type, timestamp, time, ts, ...rest } = e;
    return {
      offsetS: at ? Number(((new Date(at).getTime() - t0) / 1000).toFixed(1)) : null,
      type: String(type || '?'),
      detail: Object.keys(rest).length ? scrubData(dropSpeech(rest)) : null,
    };
  });
  saveScrubState();
  return { facts, booking, events, logIds: [call.id, call.externalId, call.callSid].filter(Boolean) };
}

async function sqlData(sql) {
  if (!sql) throw new Error('SQL required');
  const { rows, truncated } = await readOnly(sql);
  const out = rows.map(scrubRow);
  saveScrubState();
  return { rows: out, truncated };
}

async function releasesData() {
  const out = await sshRun(`
    cur=$(readlink /opt/lilli-current 2>/dev/null)
    for d in $(ls -1dt /opt/lilli-releases/*/ 2>/dev/null); do
      d=\${d%/}; live=0; [ "$d/app" = "$cur" ] && live=1
      echo "$(basename "$d")|$(date -r "$d" -Is)|$(cat "$d/REVISION" 2>/dev/null)|$live"
    done
  `);
  return out.split('\n').filter(Boolean).map((l) => {
    const [name, builtAt, sha, live] = l.split('|');
    let subject = null;
    try { subject = git('log', '-1', '--format=%s', sha); } catch { /* commit not in local repo */ }
    return { name, builtAt, sha, subject, live: live === '1' };
  });
}

async function liveRevision() {
  return (await sshRun(`cat "$(readlink /opt/lilli-current 2>/dev/null)/../REVISION" 2>/dev/null || git -C /opt/lilli rev-parse HEAD`)).trim();
}

const oneline = (range) => {
  const out = git('log', '--format=%h%x09%s', range);
  return out ? out.split('\n').map((l) => { const [sha, subject] = l.split('\t'); return { sha, subject }; }) : [];
};

// What a deploy of <ref> would do. Refuses refs that are not on GitHub (the box fetches from origin).
async function deployPlan(ref) {
  git('fetch', '-q', 'origin');
  const target = git('rev-parse', '--verify', `${ref || 'origin/main'}^{commit}`);
  const onOrigin = git('branch', '-r', '--contains', target) !== '';
  const live = await liveRevision();
  const same = live === target;
  let liveKnown = true;
  try { git('cat-file', '-e', `${live}^{commit}`); } catch { liveKnown = false; }
  return {
    ref: ref || 'origin/main',
    target, targetSubject: git('log', '-1', '--format=%s', target),
    live, liveSubject: liveKnown ? git('log', '-1', '--format=%s', live) : null,
    onOrigin,
    goingOut: same || !liveKnown ? [] : oneline(`${live}..${target}`),
    removed: same || !liveKnown ? [] : oneline(`${target}..${live}`),
    schemaChanged: !same && liveKnown && git('diff', '--name-only', live, target, '--', 'app/prisma/schema.prisma') !== '',
  };
}

// Runs lilli-deploy-remote.sh on the box, streaming its output lines to onLine.
// Returns { promise, cancel }.
function runRemote(args, onLine) {
  const child = spawn('ssh', [...sshArgs(), `bash -s -- ${args.map((a) => `'${String(a).replace(/'/g, '')}'`).join(' ')}`],
    { stdio: ['pipe', 'pipe', 'pipe'] });
  child.stdin.end(fs.readFileSync(cfg.deployScript));
  const pump = (stream) => {
    let buf = '';
    stream.on('data', (d) => {
      buf += d;
      const parts = buf.split(/\r?\n/);
      buf = parts.pop();
      parts.forEach(onLine);
    });
    stream.on('end', () => { if (buf) onLine(buf); });
  };
  pump(child.stdout);
  pump(child.stderr);
  const promise = new Promise((resolve, reject) => {
    child.on('error', reject);
    child.on('close', (code) => (code === 0 ? resolve() : reject(new Error(`remote step failed (exit ${code})`))));
  });
  return { promise, cancel: () => child.kill('SIGTERM') };
}

// ─── CLI ─────────────────────────────────────────────────────────────────────

const berlin = new Intl.DateTimeFormat('de-DE', { timeZone: 'Europe/Berlin', dateStyle: 'short', timeStyle: 'medium' });
const fmtTime = (d) => (d ? berlin.format(new Date(d)) : '—');
const ISO_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$/;

function printTable(rows) {
  if (!rows.length) return console.log('(no rows)');
  const cols = Object.keys(rows[0]);
  const cell = (v) => (v == null ? '' : typeof v === 'string' && ISO_RE.test(v) ? fmtTime(v) : typeof v === 'object' ? JSON.stringify(v) : String(v));
  const widths = cols.map((c) => Math.min(60, Math.max(c.length, ...rows.map((r) => cell(r[c]).length))));
  const line = (vals) => vals.map((v, i) => v.slice(0, widths[i]).padEnd(widths[i])).join('  ');
  console.log(line(cols));
  console.log(widths.map((w) => '─'.repeat(w)).join('  '));
  for (const r of rows) console.log(line(cols.map((c) => cell(r[c]))));
}

async function cliStatus() {
  const s = await statusData();
  console.log(`release: ${s.liveRelease || `(not using releases yet) ${s.checkout}`}`);
  if (s.deploys.length) { console.log('last deploys:'); s.deploys.slice(-5).forEach((d) => console.log(`  ${d}`)); }
  for (const p of s.procs) {
    const up = p.uptimeMs == null ? '-' : `${Math.round(p.uptimeMs / 60000)}m`;
    console.log(`${p.name.padEnd(16)} ${p.status.padEnd(8)} up ${up.padEnd(8)} restarts ${String(p.restarts).padEnd(5)} mem ${p.memoryMb}MB  cwd ${p.cwd}`);
  }
  console.log(`health: web ${s.web}  ws ${s.ws === 'up' ? 'listening' : 'DOWN'}`);
  console.log(`disk: ${s.disk}`);
}

async function cliLogs(opts) {
  const proc = opts.web ? 'web' : opts.ws ? 'ws' : undefined;
  for (const { proc: p, line } of await logsData({ ...opts, proc })) console.log(`${p.padEnd(3)} | ${line}`);
}

async function cliCall(id, opts) {
  const { facts, booking, events, logIds } = await callData(id);
  for (const [k, v] of Object.entries(facts)) {
    const shown = v == null ? '—' : ISO_RE.test(v) ? fmtTime(v) : v;
    console.log(`${k.padEnd(12)} ${shown}`);
  }
  if (booking) console.log(`${'booking'.padEnd(12)} ${JSON.stringify(booking)}`);
  console.log(`\nevents (${events.length})`);
  for (const e of events) {
    const offset = e.offsetS == null ? '        ' : `+${e.offsetS.toFixed(1)}s`.padStart(8);
    console.log(`${offset}  ${e.type.padEnd(28)} ${e.detail ? JSON.stringify(e.detail) : ''}`);
  }
  if (opts.logs) {
    const lines = opts.lines || 3000;
    console.log(`\nlog lines mentioning this call (last ${lines} lines per process)`);
    await cliLogs({ lines, grep: logIds.map((s) => s.replace(/[^\w-]/g, '')).join('|') });
  }
}

async function cliDeploy(ref, opts) {
  const plan = await deployPlan(ref);
  if (!plan.onOrigin) throw new Error(`${plan.target.slice(0, 7)} is not on any origin branch; push it first (the box fetches from GitHub)`);
  console.log(`live   ${plan.live.slice(0, 7)}  ${plan.liveSubject || '(not in local repo)'}`);
  console.log(`deploy ${plan.target.slice(0, 7)}  ${plan.targetSubject}`);
  if (plan.live === plan.target) console.log('(already live — will restart)');
  if (plan.goingOut.length) console.log(`\ncommits going out:\n${plan.goingOut.map((c) => `  ${c.sha} ${c.subject}`).join('\n')}`);
  if (plan.removed.length) console.log(`\n⚠ commits live now that this deploy REMOVES:\n${plan.removed.map((c) => `  ${c.sha} ${c.subject}`).join('\n')}`);
  if (plan.schemaChanged && !opts['schema-ok']) {
    throw new Error('app/prisma/schema.prisma changed. Apply the DB change first (it is shared by all releases), then re-run with --schema-ok');
  }
  if (opts['dry-run']) return console.log('\n(dry run — nothing deployed)');
  if (!opts.yes) {
    if (!process.stdin.isTTY) throw new Error('Re-run with --yes to confirm (non-interactive)');
    const answer = await new Promise((r) => {
      process.stdout.write(`\nDeploy ${plan.target.slice(0, 7)} to ${cfg.ssh}? [y/N] `);
      process.stdin.once('data', (d) => r(String(d).trim().toLowerCase()));
    });
    process.stdin.pause();
    if (answer !== 'y') return console.log('aborted');
  }
  await runRemote(['deploy', plan.target], (l) => console.log(l)).promise;
  console.log('\nlast log lines after restart:');
  await cliLogs({ lines: 15 });
}

async function cliRollback(opts) {
  if (!opts.yes) throw new Error('Re-run with --yes to confirm the rollback');
  await runRemote(['rollback'], (l) => console.log(l)).promise;
}

async function cliReleases() {
  const rs = await releasesData();
  if (!rs.length) return console.log('(no releases yet — first `deploy` creates them)');
  for (const r of rs) console.log(`${r.live ? '*' : ' '} ${r.name}  ${fmtTime(r.builtAt)}  ${r.subject || ''}`);
}

const HELP = `Lilli staging ops (box ${cfg.ssh}, DB ${cfg.db.host})

  status                         PM2 processes, live release, health, disk
  logs [--lines N] [--web|--ws] [--errors] [--grep RE]
                                 recent PM2 logs, scrubbed
  calls [--since 6h] [--status S] [--outcome O] [--errors] [--limit N]
                                 recent calls, no transcript/answers
  call <id|externalId|callSid> [--logs]
                                 one call: facts, answer keys, event timeline (+ matching log lines)
  sql "<SELECT …>"               read-only, ${SQL_TIMEOUT_MS / 1000}s timeout, ${MAX_ROWS} rows, scrubbed
  deploy [ref] [--dry-run] [--yes] [--schema-ok]
                                 build ref (default origin/main) as a new release, switch, health-check,
                                 auto-rollback on failure
  rollback --yes                 switch back to the previous release
  releases                       list releases on the box

Scrubbed output: answers/speech become [REDACTED], phones/emails/names become stable
placeholders like [PHONE_1] (mapping kept locally in helper/.lilli-state/).
The same functions back the helper's Lilli view (#lilli).`;

function parseArgs(argv) {
  const opts = {};
  const pos = [];
  const flags = ['web', 'ws', 'errors', 'logs', 'yes', 'dry-run', 'schema-ok'];
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (!a.startsWith('--')) { pos.push(a); continue; }
    const key = a.slice(2);
    const next = argv[i + 1];
    if (next != null && !next.startsWith('--') && !flags.includes(key)) { opts[key] = next; i++; } else opts[key] = true;
  }
  return { pos, opts };
}

async function cli() {
  const { pos, opts } = parseArgs(process.argv.slice(2));
  const [cmd, ...rest] = pos;
  switch (cmd) {
    case 'status': return cliStatus();
    case 'logs': return cliLogs(opts);
    case 'calls': return printTable(await callsData(opts));
    case 'call': return cliCall(rest[0], opts);
    case 'sql': {
      const { rows, truncated } = await sqlData(rest.join(' '));
      printTable(rows);
      if (truncated) console.error(`(showing first ${MAX_ROWS} rows)`);
      return undefined;
    }
    case 'deploy': return cliDeploy(rest[0], opts);
    case 'rollback': return cliRollback(opts);
    case 'releases': return cliReleases();
    default: return console.log(HELP);
  }
}

if (require.main === module) {
  cli()
    .catch((err) => { console.error(`error: ${err.message}`); process.exitCode = 1; })
    .finally(closeDb);
}

module.exports = {
  cfg, statusData, logsData, callsData, callData, sqlData, releasesData, deployPlan, runRemote,
  scrubLogLine, scrubRow,
};
