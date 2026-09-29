const router = require('express').Router();
const { query } = require('../lib/db');

// ─── Routes: API keys ─────────────────────────────────────────────────────────
router.get('/api/api-keys', async (req, res) => {
  try {
    const rows = await query(req, `SELECT id, "customerName", "customerUUID", "usageCount", "createdAt", "expiresAt", status, "lastUsedAt", permissions FROM api_keys ORDER BY "createdAt" DESC`);
    res.json(rows);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

router.patch('/api/api-keys/:id/status', async (req, res) => {
  try {
    const { status } = req.body;
    const rows = await query(req, `UPDATE api_keys SET status = $1 WHERE id = $2 RETURNING *`, [parseInt(status), parseInt(req.params.id)]);
    res.json(rows[0]);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

module.exports = router;
