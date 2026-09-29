const router = require('express').Router();
const { query } = require('../lib/db');

// ─── Routes: server health ────────────────────────────────────────────────────
router.get('/api/health', async (req, res) => {
  try {
    const [metrics, connections] = await Promise.all([
      query(req, `SELECT name, "serverId", "timestamp", "isHealthy", value FROM serverpod_health_metric ORDER BY "timestamp" DESC LIMIT 100`),
      query(req, `SELECT "serverId", "timestamp", active, closing, idle FROM serverpod_health_connection_info ORDER BY "timestamp" DESC LIMIT 20`),
    ]);
    res.json({ metrics, connections });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

module.exports = router;
