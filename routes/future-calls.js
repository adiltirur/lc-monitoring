const router = require('express').Router();
const { buildWhere, paginate, query } = require('../lib/db');

// ─── Routes: future calls ─────────────────────────────────────────────────────
router.get('/api/future-calls', async (req, res) => {
  try {
    const { name, page = 1, pageSize = 50 } = req.query;
    const filters = [['name', 'ILIKE', name ? `%${name}%` : null]];
    const { where, params } = buildWhere(filters);
    const baseSql = `SELECT id, name, "time", "serverId", identifier FROM serverpod_future_call ${where} ORDER BY "time" ASC`;
    const countSql = `SELECT COUNT(*) FROM serverpod_future_call ${where}`;
    const result = await paginate(req, baseSql, countSql, params, parseInt(page), parseInt(pageSize));
    res.json(result);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

router.delete('/api/future-calls/:id', async (req, res) => {
  try {
    await query(req, `DELETE FROM serverpod_future_call WHERE id = $1`, [parseInt(req.params.id)]);
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

router.get('/api/future-calls/:id', async (req, res) => {
  try {
    const rows = await query(req, `SELECT id, name, "time", "serverId", identifier, "serializedObject" FROM serverpod_future_call WHERE id = $1`, [parseInt(req.params.id)]);
    if (!rows.length) return res.status(404).json({ error: 'Not found' });
    res.json(rows[0]);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

module.exports = router;
