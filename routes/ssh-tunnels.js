const router = require('express').Router();
const { DescribeInstancesCommand } = require('@aws-sdk/client-ec2');
const { spawn } = require('child_process');
const { AWS_REGION, ec2Client } = require('../lib/aws');

// ─── Routes: SSH tunnels via SSM port-forwarding ─────────────────────────────
// One-click `aws ssm start-session --document AWS-StartPortForwardingSession`
// per environment, so a private (no public IP) app instance can be reached over
// a local port — Termius/ssh point at 127.0.0.1:<localPort>. The instance id is
// resolved automatically from the ASG Name tag; no manual lookup needed.

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

router.get('/api/ssm/status', (req, res) => {
  res.json({ envs: Object.keys(SSM_ENVS).map(ssmPublicState) });
});

router.post('/api/ssm/connect', async (req, res) => {
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

router.post('/api/ssm/disconnect', (req, res) => {
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

module.exports = router;
