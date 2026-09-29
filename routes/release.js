const router = require('express').Router();
const fs = require('fs');
const path = require('path');
const { execFile, spawn } = require('child_process');
const { LS_PATH } = require('../lib/local-stack');

const ROOT = path.join(__dirname, '..'); // helper/

// ─── Routes: Build & Release (Flutter apps) ──────────────────────────────────
// Builds the two Flutter apps (web / Android / iOS, test or prod) and deploys
// web builds to S3 + CloudFront. One job at a time: every build starts with
// `flutter clean`, and both apps share one pub workspace, so parallel jobs
// would trample each other. Mobile artifacts are revealed in Finder.
const RL_APPS_DIR = process.env.LC_APPS_DIR
  || path.resolve(ROOT, '..', 'apps-frontend', 'apps');
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
const RL_DIR = path.join(ROOT, '.release');
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

router.get('/api/release/config', (req, res) => {
  res.json({
    appsDir: RL_APPS_DIR,
    sdk: rlSdk(),
    apps: Object.fromEntries(Object.entries(RL_APPS).map(([k, a]) => [k, { ...a, path: rlAppDir(k), exists: fs.existsSync(rlAppDir(k)) }])),
    envs: RL_ENVS,
    confirmations: Object.fromEntries(Object.keys(RL_APPS).map((k) => [k, rlDeployConfirmation(k)])),
    lastBuilds: rlReadState().lastBuilds,
  });
});

router.get('/api/release/status', (req, res) => {
  res.json({ job: rlJobSummary(rlJob, parseInt(req.query.since || '0')), lastBuilds: rlReadState().lastBuilds });
});

// Body: { app, env, platform: web|android|ios, androidFormat?: apk|aab }
router.post('/api/release/build', (req, res) => {
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
router.post('/api/release/deploy', (req, res) => {
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

router.post('/api/release/cancel', (req, res) => {
  if (!rlJob || rlJob.status !== 'running') return res.status(400).json({ error: 'nothing is running' });
  rlJob.cancelRequested = true;
  if (rlChild) { try { process.kill(-rlChild.pid, 'SIGTERM'); } catch (_) { try { rlChild.kill('SIGTERM'); } catch (_) {} } }
  res.json({ ok: true });
});

// Body: { app, platform } — reveals only artifacts recorded by a build here.
router.post('/api/release/reveal', (req, res) => {
  const { app: appKey, platform } = req.body || {};
  const b = ((rlReadState().lastBuilds[appKey] || {})[platform]) || null;
  if (!b || !b.artifact || !fs.existsSync(b.artifact)) return res.status(404).json({ error: 'artifact not found — rebuild' });
  execFile('open', ['-R', b.artifact]);
  res.json({ ok: true });
});

module.exports = router;
