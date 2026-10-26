const router = require('express').Router();
const { execFile } = require('child_process');
const {
  BatchGetDeploymentsCommand, BatchGetDeploymentTargetsCommand,
  ListDeploymentsCommand, ListDeploymentTargetsCommand,
} = require('@aws-sdk/client-codedeploy');
const { DescribeInstancesCommand } = require('@aws-sdk/client-ec2');
const { GetCommandInvocationCommand, SendCommandCommand } = require('@aws-sdk/client-ssm');
const { codedeployClient, ec2Client, ssmClient } = require('../lib/aws');

// ─── Routes: backend deployments ──────────────────────────────────────────────
// The "Deploy to AWS" GitHub Action only queues a CodeDeploy deployment, so a
// green run does not mean the server was updated (a failing migration in the
// start_server hook leaves the old server running). This view puts the three
// sources side by side per env: Action runs (via the `gh` CLI), CodeDeploy
// deployments with the failed hook's log, and the live server (API HEAD check,
// plus an on-demand read-only `systemctl` + log tail over SSM).

const DP_REPO = 'Lillian-Care-GmbH/LillianCare-Core';
const DP_WORKFLOW = 'deployment-aws.yml';
const DP_APP = 'lc-core-app';
const DP_ENVS = {
  test:       { group: 'lc-core-test-group',       branch: 'deployment-aws-test',       tag: 'lc-core-serverpod-test',    api: 'https://api-test.lillian.care/' },
  staging:    { group: 'lc-core-staging-group',    branch: 'deployment-aws-staging',    tag: 'lc-core-serverpod-staging', api: 'https://api-staging.lillian.care/' },
  production: { group: 'lc-core-production-group', branch: 'deployment-aws-production', tag: 'lc-core-serverpod',         api: 'https://api.lillian.care/' },
};
const DP_PER_ENV = 25; // BatchGetDeployments takes at most 25 ids
// gh lives in Homebrew's bin, which a launchd-started node does not have on PATH.
const DP_PATH = ['/opt/homebrew/bin', '/usr/local/bin', process.env.PATH || ''].join(':');

let dpCache = null;

function dpGh(path) {
  return new Promise((resolve, reject) => {
    execFile('gh', ['api', path], { env: { ...process.env, PATH: DP_PATH }, timeout: 20000, maxBuffer: 8 * 1024 * 1024 }, (err, stdout, stderr) => {
      if (err) return reject(new Error((stderr || err.message).trim()));
      try { resolve(JSON.parse(stdout)); } catch (e) { reject(e); }
    });
  });
}

// Deployments created by the workflow carry "commit <sha> run <id>".
function dpParseDescription(desc) {
  const m = /commit ([0-9a-f]{7,40}) run (\d+)/.exec(desc || '');
  return m ? { commit: m[1], runId: Number(m[2]) } : { commit: null, runId: null };
}

async function dpEnvDeployments(env) {
  const cfg = DP_ENVS[env];
  const list = await codedeployClient.send(new ListDeploymentsCommand({ applicationName: DP_APP, deploymentGroupName: cfg.group }));
  const ids = (list.deployments || []).slice(0, DP_PER_ENV);
  if (!ids.length) return [];
  const batch = await codedeployClient.send(new BatchGetDeploymentsCommand({ deploymentIds: ids }));
  const infos = batch.deploymentsInfo || [];
  const deployments = await Promise.all(infos.map(async d => {
    const out = {
      id: d.deploymentId,
      env,
      status: d.status,
      createTime: d.createTime,
      completeTime: d.completeTime || null,
      creator: d.creator,
      error: d.errorInformation ? d.errorInformation.message : null,
      ...dpParseDescription(d.description),
      failed: [],
    };
    if (d.status === 'Failed' || d.status === 'Stopped') out.failed = await dpFailedEvents(d.deploymentId);
    return out;
  }));
  return deployments.sort((a, b) => new Date(b.createTime) - new Date(a.createTime));
}

async function dpFailedEvents(deploymentId) {
  const t = await codedeployClient.send(new ListDeploymentTargetsCommand({ deploymentId }));
  if (!(t.targetIds || []).length) return [];
  const targets = await codedeployClient.send(new BatchGetDeploymentTargetsCommand({ deploymentId, targetIds: t.targetIds }));
  return (targets.deploymentTargets || []).flatMap(tg => {
    const it = tg.instanceTarget || {};
    return (it.lifecycleEvents || []).filter(e => e.status === 'Failed').map(e => ({
      target: it.targetId,
      event: e.lifecycleEventName,
      message: e.diagnostics ? e.diagnostics.message : null,
      logTail: e.diagnostics ? e.diagnostics.logTail : null,
    }));
  });
}

async function dpApiHealth(url) {
  const start = Date.now();
  try {
    const r = await fetch(url, { method: 'HEAD', signal: AbortSignal.timeout(5000), redirect: 'follow' });
    return { ok: r.status < 500, status: r.status, latencyMs: Date.now() - start };
  } catch (e) {
    return { ok: false, status: null, latencyMs: Date.now() - start, error: e.name === 'TimeoutError' ? 'timeout' : 'unreachable' };
  }
}

// Older deployments have no description, so fall back to timing: the
// workflow creates the deployment in its last step, while the run is going.
function dpMatchDeployment(run, deployments) {
  const byId = deployments.find(d => d.runId === run.id);
  if (byId) return byId;
  const start = new Date(run.run_started_at || run.created_at).getTime();
  const end = new Date(run.updated_at).getTime() + 60000;
  return deployments.find(d => d.runId == null && new Date(d.createTime).getTime() >= start && new Date(d.createTime).getTime() <= end) || null;
}

router.get('/api/deployments/overview', async (req, res) => {
  try {
    if (dpCache && Date.now() - dpCache.ts < 15000 && req.query.fresh !== '1') return res.json(dpCache.data);

    const envNames = Object.keys(DP_ENVS);
    const [perEnv, health, runsRes] = await Promise.all([
      Promise.all(envNames.map(dpEnvDeployments)),
      Promise.all(envNames.map(e => dpApiHealth(DP_ENVS[e].api))),
      dpGh(`repos/${DP_REPO}/actions/workflows/${DP_WORKFLOW}/runs?per_page=25`).then(r => ({ runs: r.workflow_runs || [] }), e => ({ runs: [], error: e.message })),
    ]);
    const allDeployments = perEnv.flat();

    const runs = runsRes.runs.map(r => {
      const dep = dpMatchDeployment(r, allDeployments);
      const branchEnv = Object.keys(DP_ENVS).find(e => DP_ENVS[e].branch === r.head_branch) || null;
      return {
        id: r.id,
        url: r.html_url,
        title: r.display_title,
        event: r.event,
        branch: r.head_branch,
        sha: r.head_sha,
        actor: r.actor ? r.actor.login : null,
        status: r.status,
        conclusion: r.conclusion,
        createdAt: r.run_started_at || r.created_at,
        updatedAt: r.updated_at,
        env: dep ? dep.env : branchEnv,
        deployment: dep ? { id: dep.id, status: dep.status } : null,
      };
    });

    const envs = envNames.map((env, i) => {
      const deployments = perEnv[i];
      const latest = deployments[0] || null;
      const lastSuccess = deployments.find(d => d.status === 'Succeeded') || null;
      // Newest finished push/dispatch for this env: is its commit what the server runs?
      const latestRun = runs.find(r => r.env === env && r.status === 'completed') || null;
      const liveCommit = lastSuccess ? (lastSuccess.commit || (runs.find(r => r.deployment && r.deployment.id === lastSuccess.id) || {}).sha || null) : null;
      const behind = !!(latestRun && liveCommit && latestRun.sha !== liveCommit);
      return { env, api: health[i], latest, lastSuccess, liveCommit, latestRun, behind, deployments };
    });

    const data = { envs, runs, runsError: runsRes.error || null, checkedAt: new Date().toISOString() };
    dpCache = { ts: Date.now(), data };
    res.json(data);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

async function dpResolveInstanceId(tag) {
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

// Read-only: service state plus the tails of the server and migration logs.
const DP_SERVER_SCRIPT = [
  'systemctl show serverpod -p ActiveState -p SubState -p ActiveEnterTimestamp -p NRestarts',
  'echo "@@ERR"; tail -n 30 /home/ec2-user/serverpod.err 2>/dev/null',
  'echo "@@LOG"; tail -n 30 /home/ec2-user/serverpod.log 2>/dev/null',
  'echo "@@MIG"; date -u -r /home/ec2-user/serverpod-migrations.log +%Y-%m-%dT%H:%M:%SZ 2>/dev/null; tail -n 30 /home/ec2-user/serverpod-migrations.log 2>/dev/null',
];

function dpParseServerOutput(text) {
  const [head, rest = ''] = text.split('@@ERR\n');
  const [err, rest2 = ''] = rest.split('@@LOG\n');
  const [log, mig = ''] = rest2.split('@@MIG\n');
  const props = Object.fromEntries(head.trim().split('\n').filter(Boolean).map(l => {
    const i = l.indexOf('=');
    return [l.slice(0, i), l.slice(i + 1)];
  }));
  const migLines = mig.split('\n');
  const migAt = /^\d{4}-\d\d-\d\dT/.test(migLines[0]) ? migLines.shift() : null;
  return {
    activeState: props.ActiveState || null,
    subState: props.SubState || null,
    activeSince: props.ActiveEnterTimestamp || null,
    restarts: props.NRestarts != null ? Number(props.NRestarts) : null,
    errTail: err.trimEnd(),
    logTail: log.trimEnd(),
    migrationsAt: migAt,
    migrationsTail: migLines.join('\n').trimEnd(),
  };
}

router.post('/api/deployments/server-check', async (req, res) => {
  const env = (req.body && req.body.env) || '';
  const cfg = DP_ENVS[env];
  if (!cfg) return res.status(400).json({ error: `Unknown env "${env}"` });
  try {
    const instanceId = await dpResolveInstanceId(cfg.tag);
    const sent = await ssmClient.send(new SendCommandCommand({
      InstanceIds: [instanceId],
      DocumentName: 'AWS-RunShellScript',
      Comment: 'LC Helper deployments: read-only server check',
      Parameters: { commands: DP_SERVER_SCRIPT },
      TimeoutSeconds: 30,
    }));
    const commandId = sent.Command.CommandId;
    const deadline = Date.now() + 25000;
    let inv = null;
    while (Date.now() < deadline) {
      await new Promise(r => setTimeout(r, 1000));
      try {
        inv = await ssmClient.send(new GetCommandInvocationCommand({ CommandId: commandId, InstanceId: instanceId }));
      } catch (e) {
        if (e.name === 'InvocationDoesNotExist') continue;
        throw e;
      }
      if (!['Pending', 'InProgress', 'Delayed'].includes(inv.Status)) break;
    }
    if (!inv || inv.Status !== 'Success') {
      return res.status(502).json({ error: `SSM command ${commandId} ended as ${inv ? inv.Status : 'no answer'}${inv && inv.StandardErrorContent ? ': ' + inv.StandardErrorContent : ''}` });
    }
    res.json({ env, instanceId, checkedAt: new Date().toISOString(), ...dpParseServerOutput(inv.StandardOutputContent || '') });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

module.exports = router;
