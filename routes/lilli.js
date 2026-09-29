const router = require('express').Router();
const lilli = require('../scripts/lilli');
const { lilliSend } = require('../lib/lilli');

// ─── Routes: Lilli staging (/api/lilli/*, view #lilli) ───────────────────────
// Thin wrapper over scripts/lilli.js (also the CLI Claude Code sessions use), so scrubbing
// and the read-only DB guard live in one place. Deploy/rollback run as one in-memory job at a
// time (lost on restart), polled like the Release view.
const LILLI_JOB_MAX_LINES = 5000;
let lilliJob = null;

router.get('/api/lilli/status', async (req, res) => {
  try { res.json(await lilli.statusData()); } catch (e) { lilliSend(res, e); }
});

router.get('/api/lilli/calls', async (req, res) => {
  try {
    const { since, status, outcome, errors, limit } = req.query;
    res.json({ rows: await lilli.callsData({ since: since || undefined, status: status || undefined, outcome: outcome || undefined, errors: errors === '1', limit }) });
  } catch (e) { lilliSend(res, e); }
});

router.get('/api/lilli/calls/:id', async (req, res) => {
  try { res.json(await lilli.callData(req.params.id)); } catch (e) { lilliSend(res, e); }
});

router.get('/api/lilli/logs', async (req, res) => {
  try {
    const { proc, errors, lines, grep } = req.query;
    res.json({ lines: await lilli.logsData({ proc, errors: errors === '1', lines, grep: grep || undefined }) });
  } catch (e) { lilliSend(res, e); }
});

router.get('/api/lilli/releases', async (req, res) => {
  try { res.json({ releases: await lilli.releasesData() }); } catch (e) { lilliSend(res, e); }
});

router.get('/api/lilli/deploy/plan', async (req, res) => {
  try { res.json(await lilli.deployPlan(req.query.ref || undefined)); } catch (e) { lilliSend(res, e); }
});

function lilliStartJob(kind, args, meta) {
  const job = { id: Date.now(), kind, status: 'running', startedAt: Date.now(), endedAt: null, lines: [], dropped: 0, error: null, ...meta };
  const run = lilli.runRemote(args, (line) => {
    job.lines.push(line);
    if (job.lines.length > LILLI_JOB_MAX_LINES) { job.lines.shift(); job.dropped++; }
  });
  job.cancel = run.cancel;
  run.promise
    .then(() => { job.status = 'success'; })
    .catch((e) => { job.status = job.status === 'cancelled' ? 'cancelled' : 'failed'; job.error = e.message; })
    .finally(() => { job.endedAt = Date.now(); job.cancel = null; });
  lilliJob = job;
  return job;
}

// Deploys take the full sha from the plan the user just reviewed, so what ships is what was shown.
router.post('/api/lilli/deploy', async (req, res) => {
  try {
    if (lilliJob && lilliJob.status === 'running') return res.status(409).json({ error: 'A deploy or rollback is already running' });
    const { sha, schemaOk } = req.body || {};
    if (!/^[0-9a-f]{40}$/.test(sha || '')) return res.status(400).json({ error: 'Full commit sha required (from the plan)' });
    const plan = await lilli.deployPlan(sha);
    if (!plan.onOrigin) return res.status(400).json({ error: 'Commit is not on GitHub; push it first' });
    if (plan.schemaChanged && !schemaOk) return res.status(400).json({ error: 'prisma/schema.prisma changed; apply the DB change first, then confirm the schema checkbox' });
    const job = lilliStartJob('deploy', ['deploy', sha], { sha, subject: plan.targetSubject });
    res.json({ ok: true, id: job.id });
  } catch (e) { lilliSend(res, e); }
});

router.post('/api/lilli/rollback', (req, res) => {
  if (lilliJob && lilliJob.status === 'running') return res.status(409).json({ error: 'A deploy or rollback is already running' });
  const job = lilliStartJob('rollback', ['rollback'], {});
  res.json({ ok: true, id: job.id });
});

router.post('/api/lilli/job/cancel', (req, res) => {
  if (!lilliJob || !lilliJob.cancel) return res.status(400).json({ error: 'Nothing running' });
  lilliJob.status = 'cancelled';
  lilliJob.cancel();
  res.json({ ok: true });
});

router.get('/api/lilli/job', (req, res) => {
  if (!lilliJob) return res.json({ job: null });
  const since = Math.max(0, Number(req.query.since || 0) - lilliJob.dropped);
  const { cancel, lines, ...rest } = lilliJob;
  res.json({ job: { ...rest, lines: lines.slice(since), logEnd: lilliJob.dropped + lines.length } });
});

module.exports = router;
