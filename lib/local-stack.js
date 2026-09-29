const fs = require('fs');
const net = require('net');
const path = require('path');
const { execFile, spawn } = require('child_process');

const ROOT = path.join(__dirname, '..'); // helper/

// Local stack control: Docker Desktop + the Serverpod dev server (routes/local-stack.js).
const LS_DIR = path.join(ROOT, '.local-stack');
const LS_PID_FILE = path.join(LS_DIR, 'serverpod.pid');
const LS_LOG_FILE = path.join(LS_DIR, 'serverpod.log');
const LS_CONFIG_FILE = path.join(LS_DIR, 'config.json');
const LS_HELPER_LOG = path.join(process.env.HOME || '', 'Library', 'Logs', 'LCHelper', 'server.log');
const LS_SERVERPOD_DIR = process.env.LC_SERVERPOD_DIR
  || path.resolve(ROOT, '..', 'LillianCare-Core', 'lillian_care_core_server');
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

module.exports = { LS_HELPER_LOG, LS_LOG_FILE, LS_PATH, LS_SERVERPOD_DIR, lsExec, lsReadConfig, lsRun, lsStartServerpod, lsStatus, lsStopServerpod, lsTail, lsWriteConfig };
