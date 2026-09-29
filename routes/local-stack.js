const router = require('express').Router();
const { LS_HELPER_LOG, LS_LOG_FILE, LS_SERVERPOD_DIR, lsExec, lsReadConfig, lsRun, lsStartServerpod, lsStatus, lsStopServerpod, lsTail, lsWriteConfig } = require('../lib/local-stack');

// ─── Local stack (Serverpod dev server + Docker Postgres/Redis) ─────────────
// Keeps the local backend (LillianCare-Core) running so the `dev` preset works.
// Serverpod is spawned detached in its own process group and tracked via a PID
// file, so restarting the helper (launchd kickstart) does not kill it. Docker
// Desktop's CLI is not on PATH for GUI/launchd processes, so we point at it.

router.get('/api/local-stack/status', async (req, res) => {
  try { res.json(await lsStatus()); } catch (e) { res.status(500).json({ error: e.message }); }
});

router.post('/api/local-stack/start', async (req, res) => {
  lsRun('starting', lsStartServerpod);
  res.json(await lsStatus());
});

router.post('/api/local-stack/stop', async (req, res) => {
  const includeDocker = !!(req.body && req.body.includeDocker);
  lsRun('stopping', async () => {
    await lsStopServerpod();
    if (includeDocker) await lsExec('docker', ['compose', 'stop'], { cwd: LS_SERVERPOD_DIR, timeout: 60000 });
  });
  res.json(await lsStatus());
});

router.post('/api/local-stack/restart', async (req, res) => {
  lsRun('restarting', async () => { await lsStopServerpod(); await lsStartServerpod(); });
  res.json(await lsStatus());
});

router.post('/api/local-stack/config', (req, res) => {
  const cfg = lsReadConfig();
  const body = req.body || {};
  if (typeof body.autostart === 'boolean') cfg.autostart = body.autostart;
  if (typeof body.applyMigrations === 'boolean') cfg.applyMigrations = body.applyMigrations;
  lsWriteConfig(cfg);
  res.json({ config: cfg });
});

router.get('/api/local-stack/logs', (req, res) => {
  const tail = Math.min(parseInt(req.query.tail || '500', 10) || 500, 5000);
  const file = req.query.service === 'helper' ? LS_HELPER_LOG : LS_LOG_FILE;
  res.json({ file, lines: lsTail(file, tail) });
});

module.exports = router;
