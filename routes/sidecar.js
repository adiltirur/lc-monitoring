// ─── Routes: Principa SideCar reporting DB (/api/sidecar/*, view #sidecar) ──
// READ-ONLY access to Planorg's production reporting DB through an SSM tunnel via the
// whitelisted staging instance (lib/sidecar.js). Result rows can hold patient data: they
// are returned to the page only — never logged or written to disk.
const router = require('express').Router();
const sidecar = require('../lib/sidecar');

function send(res, e) {
  res.status(e.status || 500).json({ error: e.message, code: e.code || null, cause: e.cause_hint || null });
}

router.get('/api/sidecar/status', (req, res) => res.json(sidecar.status()));

router.post('/api/sidecar/tunnel', async (req, res) => {
  try { res.json(await sidecar.openTunnel()); } catch (e) { send(res, e); }
});

router.delete('/api/sidecar/tunnel', (req, res) => res.json(sidecar.closeTunnel()));

async function withClient(fn) {
  if (sidecar.missingCreds().length) return fn(null);
  await sidecar.openTunnel();
  const client = await sidecar.connect();
  try { return await fn(client); } finally { await client.end().catch(() => {}); }
}

router.post('/api/sidecar/smoke', async (req, res) => {
  try {
    if (sidecar.missingCreds().length) await sidecar.connect(); // throws NO_CREDS with the blocker message
    res.json(await withClient(c => sidecar.smokeTest(c)));
  } catch (e) { send(res, e); }
});

router.post('/api/sidecar/query', async (req, res) => {
  try {
    if (sidecar.missingCreds().length) await sidecar.connect();
    const t0 = Date.now();
    const r = await withClient(c => sidecar.readOnlyQuery(c, (req.body || {}).sql));
    res.json({ ...r, ms: Date.now() - t0 });
  } catch (e) { send(res, e); }
});

module.exports = router;
