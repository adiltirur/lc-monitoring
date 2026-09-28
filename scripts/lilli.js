#!/usr/bin/env node
// Lilli ops CLI: logs, calls, read-only SQL, status and deploys for the Lilli staging box.
// Built for local Claude Code sessions as much as for people: everything that can carry
// patient data (survey answers, caller speech, phone numbers, booking payloads) is scrubbed
// before it is printed. Run `node scripts/lilli.js help`.
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
  process.on('exit', () => {
    fs.mkdirSync(path.dirname(cfg.stateFile), { recursive: true, mode: 0o700 });
    fs.writeFileSync(cfg.stateFile, JSON.stringify(scrubber.exportState()), { mode: 0o600 });
  });
  return scrubber;
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
    else if (v instanceof Date) out[k] = fmtTime(v);
    else if (FREE_TEXT_COLUMNS.has(k)) out[k] = `${REDACTED} (${String(v).length} chars)`;
    else if (k === 'answers') out[k] = answerKeys(v);
    else if (k === 'events') out[k] = `(${parseJson(v, []).length} events — use \`call <id>\`)`;
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

// ─── Remote + DB helpers ─────────────────────────────────────────────────────

function sshArgs(extra = []) {
  return ['-i', cfg.sshKey, '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=10', ...extra, cfg.ssh];
}

function sshRun(command) {
  const r = spawnSync('ssh', [...sshArgs(), command], { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 });
  if (r.status !== 0) throw new Error(`ssh failed (${r.status}): ${(r.stderr || '').trim()}`);
  return r.stdout;
}

// The Lilli RDS sits in private subnets, so queries go through an SSH tunnel via the Lilli box.
let pool;
let tunnel;
async function db() {
  if (!cfg.db.password) throw new Error('LILLI_DB_STAGING_PASSWORD is not set in helper/.env');
  if (pool) return pool;
  const port = await freePort();
  tunnel = spawn('ssh', [...sshArgs(['-N', '-o', 'ExitOnForwardFailure=yes', '-L', `127.0.0.1:${port}:${cfg.db.host}:${cfg.db.port}`])], { stdio: 'ignore' });
  process.on('exit', () => tunnel.kill());
  await waitForPort(port, 15000);
  const { Pool } = require('pg');
  pool = new Pool({ ...cfg.db, host: '127.0.0.1', port, max: 1 });
  return pool;
}

function freePort() {
  return new Promise((resolve, reject) => {
    const srv = require('net').createServer().listen(0, '127.0.0.1', () => {
      const { port } = srv.address();
      srv.close(() => resolve(port));
    }).on('error', reject);
  });
}

async function waitForPort(port, timeoutMs) {
  const net = require('net');
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (tunnel.exitCode != null) throw new Error('SSH tunnel to the Lilli box failed');
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
    if (r.rows.length > MAX_ROWS) console.error(`(showing first ${MAX_ROWS} rows)`);
    return r.rows.slice(0, MAX_ROWS);
  } finally {
    await client.query('ROLLBACK').catch(() => {});
    client.release();
  }
}

const berlin = new Intl.DateTimeFormat('de-DE', {
  timeZone: 'Europe/Berlin', dateStyle: 'short', timeStyle: 'medium',
});
const fmtTime = (d) => (d ? berlin.format(new Date(d)) : '—');

function parseSince(s) {
  const m = /^(\d+)([mhd])$/.exec(s || '');
  if (!m) throw new Error(`--since expects e.g. 30m, 6h, 2d (got "${s}")`);
  return new Date(Date.now() - Number(m[1]) * { m: 60e3, h: 3600e3, d: 86400e3 }[m[2]]);
}

function printTable(rows) {
  if (!rows.length) return console.log('(no rows)');
  const cols = Object.keys(rows[0]);
  const cell = (v) => (v == null ? '' : v instanceof Date ? fmtTime(v) : typeof v === 'object' ? JSON.stringify(v) : String(v));
  const widths = cols.map((c) => Math.min(60, Math.max(c.length, ...rows.map((r) => cell(r[c]).length))));
  const line = (vals) => vals.map((v, i) => v.slice(0, widths[i]).padEnd(widths[i])).join('  ');
  console.log(line(cols));
  console.log(widths.map((w) => '─'.repeat(w)).join('  '));
  for (const r of rows) console.log(line(cols.map((c) => cell(r[c]))));
}

// ─── Commands ────────────────────────────────────────────────────────────────

const PM2_NAMES = { web: 'lilli-staging', ws: 'lilli-ws' };

async function cmdLogs(opts) {
  const lines = Number(opts.lines || 200);
  const names = opts.web ? [PM2_NAMES.web] : opts.ws ? [PM2_NAMES.ws] : [PM2_NAMES.web, PM2_NAMES.ws];
  const grep = opts.grep ? new RegExp(opts.grep, 'i') : null;
  for (const name of names) {
    const flag = opts.errors ? '--err' : '';
    const raw = sshRun(`pm2 logs ${name} --nostream --lines ${lines} ${flag} 2>/dev/null`);
    for (const l of raw.split('\n')) {
      if (!l.trim() || /^\[TAILING\]|last \d+ lines:$/.test(l.trim())) continue;
      const line = l.replace(/^\d+\|[\w-]+\s*\|\s?/, `${name === PM2_NAMES.ws ? 'ws ' : 'web'} | `);
      if (grep && !grep.test(line)) continue;
      console.log(scrubLogLine(line));
    }
  }
}

async function cmdCalls(opts) {
  const where = [];
  const params = [];
  if (opts.since) { params.push(parseSince(opts.since)); where.push(`c."startedAt" >= $${params.length}`); }
  if (opts.status) { params.push(opts.status); where.push(`c.status = $${params.length}`); }
  if (opts.outcome) { params.push(opts.outcome); where.push(`c.outcome = $${params.length}`); }
  if (opts.errors) where.push(`c."errorMessage" IS NOT NULL`);
  params.push(Math.min(Number(opts.limit || 30), MAX_ROWS));
  const rows = await readOnly(`
    SELECT c.id, c."startedAt", c.status, c.outcome, c.source, c."durationSeconds" AS secs,
           c."questionsAnswered" || '/' || c."questionsTotal" AS answered,
           round(c."totalCostUsd"::numeric, 3) AS usd, a.name AS assistant, c."workflowRunId" AS run,
           left(c."errorMessage", 80) AS error
    FROM "Call" c LEFT JOIN "Assistant" a ON a.id = c."assistantId"
    ${where.length ? `WHERE ${where.join(' AND ')}` : ''}
    ORDER BY c."startedAt" DESC LIMIT $${params.length}`, params);
  printTable(rows.map(scrubRow));
}

async function cmdCall(id, opts) {
  if (!id) throw new Error('usage: call <id | externalId | callSid>');
  const [call] = await readOnly(`
    SELECT c.*, a.name AS "assistantName"
    FROM "Call" c LEFT JOIN "Assistant" a ON a.id = c."assistantId"
    WHERE c.id = $1 OR c."externalId" = $1 OR c."callSid" = $1 LIMIT 1`, [id]);
  if (!call) throw new Error(`No call with id/externalId/callSid ${id}`);

  const secs = call.durationSeconds ?? (call.endedAt ? Math.round((new Date(call.endedAt) - new Date(call.startedAt)) / 1000) : null);
  const facts = {
    id: call.id, externalId: call.externalId, callSid: call.callSid,
    assistant: `${call.assistantName} (${call.assistantId})`, owner: call.userId,
    source: call.source, status: call.status, outcome: call.outcome,
    started: fmtTime(call.startedAt), ended: fmtTime(call.endedAt), duration: secs == null ? '—' : `${secs}s`,
    questions: `${call.questionsAnswered}/${call.questionsTotal} answered`,
    cost: `$${Number(call.totalCostUsd).toFixed(4)} (${call.inputTokens} in / ${call.outputTokens} out tokens)`,
    workflow: call.workflowId ? `${call.workflowId} node ${call.workflowNodeId} run ${call.workflowRunId}` : '—',
    escalation: call.escalationAttempts ? `${call.escalationAttempts} attempts` : '—',
    recording: call.recordingUrl ? 'yes' : 'no',
    caller: call.callerNumber,
    error: call.errorMessage,
    answers: answerKeys(call.answers),
    transcript: call.transcript ? `${REDACTED} (${call.transcript.length} chars)` : '—',
    summary: call.structuredSummary ? `${REDACTED} (${call.structuredSummary.length} chars)` : '—',
  };
  const clean = scrubData(facts);
  for (const [k, v] of Object.entries(clean)) console.log(`${k.padEnd(12)} ${v ?? '—'}`);

  if (call.bookingMetadata) console.log(`${'booking'.padEnd(12)} ${JSON.stringify(scrubData(call.bookingMetadata))}`);

  const events = parseJson(call.events, []);
  console.log(`\nevents (${events.length})`);
  const t0 = new Date(call.startedAt).getTime();
  for (const e of events) {
    const at = e.timestamp || e.time || e.ts;
    const offset = at ? `+${((new Date(at).getTime() - t0) / 1000).toFixed(1)}s`.padStart(8) : '        ';
    const { type, timestamp, time, ts, ...rest } = e;
    const detail = Object.keys(rest).length ? JSON.stringify(scrubData(dropSpeech(rest))) : '';
    console.log(`${offset}  ${String(type || '?').padEnd(28)} ${detail}`);
  }

  if (opts.logs) {
    console.log(`\nlog lines mentioning this call (last ${opts.lines || 3000} lines per process)`);
    const ids = [call.id, call.externalId, call.callSid].filter(Boolean).map((s) => s.replace(/[^\w-]/g, ''));
    await cmdLogs({ lines: opts.lines || 3000, grep: ids.join('|') });
  }
}

// Event payload keys that hold what the caller or the AI said.
const SPEECH_KEYS = new Set(['text', 'utterance', 'transcript', 'value', 'values', 'answer', 'answers', 'displayValue', 'raw', 'input', 'content']);
function dropSpeech(obj) {
  if (Array.isArray(obj)) return obj.map(dropSpeech);
  if (!obj || typeof obj !== 'object') return obj;
  return Object.fromEntries(Object.entries(obj).map(([k, v]) => [k, SPEECH_KEYS.has(k) ? REDACTED : dropSpeech(v)]));
}

async function cmdSql(sql) {
  if (!sql) throw new Error('usage: sql "<SELECT …>"');
  printTable((await readOnly(sql)).map(scrubRow));
}

async function cmdStatus() {
  console.log(sshRun(`
    echo "release: $(readlink /opt/lilli-current 2>/dev/null || echo "(not using releases yet) $(git -C /opt/lilli rev-parse --short HEAD)")"
    [ -f /opt/lilli-shared/deploys.log ] && { echo "last deploys:"; tail -n 5 /opt/lilli-shared/deploys.log | sed 's/^/  /'; }
    pm2 jlist | node -e '
      const ps = JSON.parse(require("fs").readFileSync(0, "utf8"));
      for (const p of ps) {
        const e = p.pm2_env;
        const up = e.pm_uptime ? Math.round((Date.now() - e.pm_uptime) / 60000) + "m" : "-";
        console.log(\`\${p.name.padEnd(16)} \${e.status.padEnd(8)} up \${up.padEnd(8)} restarts \${String(e.restart_time).padEnd(5)} mem \${Math.round((p.monit?.memory || 0) / 1048576)}MB  cwd \${e.pm_cwd}\`);
      }'
    base=$(grep -E "^LILLI_BASE_PATH=" /opt/lilli-current/.env /opt/lilli/app/.env 2>/dev/null | head -1 | cut -d= -f2-)
    echo "health: web $(curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:3001\${base}/login")  ws $(ss -ltn | grep -q ":3002 " && echo listening || echo DOWN)"
    df -h / | tail -1 | awk '{print "disk: " $4 " free of " $2}'
  `).trimEnd());
}

function git(...args) {
  const r = spawnSync('git', ['-C', cfg.repo, ...args], { encoding: 'utf8' });
  if (r.status !== 0) throw new Error(`git ${args.join(' ')}: ${r.stderr.trim()}`);
  return r.stdout.trim();
}

function remoteScript(args) {
  return new Promise((resolve, reject) => {
    const child = spawn('ssh', [...sshArgs(), `bash -s -- ${args.map((a) => `'${a}'`).join(' ')}`], {
      stdio: ['pipe', 'inherit', 'inherit'],
    });
    child.stdin.end(fs.readFileSync(cfg.deployScript));
    child.on('close', (code) => (code === 0 ? resolve() : reject(new Error(`remote step failed (exit ${code})`))));
  });
}

async function cmdDeploy(ref, opts) {
  git('fetch', '-q', 'origin');
  const target = git('rev-parse', '--verify', `${ref || 'origin/main'}^{commit}`);
  if (!git('branch', '-r', '--contains', target)) {
    throw new Error(`${target.slice(0, 7)} is not on any origin branch; push it first (the box fetches from GitHub)`);
  }
  const live = sshRun(`cat "$(readlink /opt/lilli-current 2>/dev/null)/../REVISION" 2>/dev/null || git -C /opt/lilli rev-parse HEAD`).trim();
  console.log(`live   ${live.slice(0, 7)}  ${git('log', '-1', '--format=%s', live)}`);
  console.log(`deploy ${target.slice(0, 7)}  ${git('log', '-1', '--format=%s', target)}`);
  if (live === target) console.log('(already live — will rebuild and restart)');
  const log = live !== target ? git('log', '--oneline', `${live}..${target}`) : '';
  if (log) console.log(`\ncommits going out:\n${log.replace(/^/gm, '  ')}`);
  const back = live !== target ? git('log', '--oneline', `${target}..${live}`) : '';
  if (back) console.log(`\n⚠ commits live now that this deploy REMOVES:\n${back.replace(/^/gm, '  ')}`);
  const schemaChanged = live !== target && git('diff', '--name-only', live, target, '--', 'app/prisma/schema.prisma') !== '';
  if (schemaChanged && !opts['schema-ok']) {
    throw new Error('app/prisma/schema.prisma changed. Apply the DB change first (it is shared by all releases), then re-run with --schema-ok');
  }
  if (opts['dry-run']) return console.log('\n(dry run — nothing deployed)');
  if (!opts.yes) {
    if (!process.stdin.isTTY) throw new Error('Re-run with --yes to confirm (non-interactive)');
    const answer = await new Promise((r) => {
      process.stdout.write(`\nDeploy ${target.slice(0, 7)} to ${cfg.ssh}? [y/N] `);
      process.stdin.once('data', (d) => r(String(d).trim().toLowerCase()));
    });
    process.stdin.pause();
    if (answer !== 'y') return console.log('aborted');
  }
  await remoteScript(['deploy', target]);
  console.log('\nlast log lines after restart:');
  await cmdLogs({ lines: 15 });
}

async function cmdRollback(opts) {
  if (!opts.yes) throw new Error('Re-run with --yes to confirm the rollback');
  await remoteScript(['rollback']);
}

async function cmdReleases() {
  console.log(sshRun(`
    cur=$(readlink /opt/lilli-current 2>/dev/null)
    for d in $(ls -1dt /opt/lilli-releases/*/ 2>/dev/null); do
      d=\${d%/}; mark=" "; [ "$d/app" = "$cur" ] && mark="*"
      echo "$mark $(basename "$d")  $(date -r "$d" '+%Y-%m-%d %H:%M')  $(cat "$d/REVISION" 2>/dev/null | cut -c1-12)"
    done
  `).trimEnd() || '(no releases yet — first `deploy` creates them)');
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
  rollback [--yes]               switch back to the previous release
  releases                       list releases on the box

Scrubbed output: answers/speech become [REDACTED], phones/emails/names become stable
placeholders like [PHONE_1] (mapping kept locally in helper/.lilli-state/).`;

function parseArgs(argv) {
  const opts = {};
  const pos = [];
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (!a.startsWith('--')) { pos.push(a); continue; }
    const key = a.slice(2);
    const next = argv[i + 1];
    if (next != null && !next.startsWith('--') && !['web', 'ws', 'errors', 'logs', 'yes', 'dry-run', 'schema-ok'].includes(key)) {
      opts[key] = next; i++;
    } else opts[key] = true;
  }
  return { pos, opts };
}

async function main() {
  const { pos, opts } = parseArgs(process.argv.slice(2));
  const [cmd, ...rest] = pos;
  switch (cmd) {
    case 'status': return cmdStatus();
    case 'logs': return cmdLogs(opts);
    case 'calls': return cmdCalls(opts);
    case 'call': return cmdCall(rest[0], opts);
    case 'sql': return cmdSql(rest.join(' '));
    case 'deploy': return cmdDeploy(rest[0], opts);
    case 'rollback': return cmdRollback(opts);
    case 'releases': return cmdReleases();
    default: console.log(HELP);
  }
}

main()
  .catch((err) => { console.error(`error: ${err.message}`); process.exitCode = 1; })
  .finally(async () => { if (pool) await pool.end(); if (tunnel) tunnel.kill(); });
