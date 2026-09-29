const router = require('express').Router();
const { buildWhere, paginate, query } = require('../lib/db');

// ─── Routes: session logs ─────────────────────────────────────────────────────
router.get('/api/session-logs/endpoints', async (req, res) => {
  try {
    const rows = await query(req, `SELECT DISTINCT endpoint FROM serverpod_session_log WHERE endpoint IS NOT NULL ORDER BY endpoint`);
    res.json(rows.map(r => r.endpoint));
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

router.get('/api/session-logs', async (req, res) => {
  try {
    const { endpoint, method, dateFrom, dateTo, errorsOnly, page = 1, pageSize = 50 } = req.query;
    const filters = [
      ['endpoint', 'ILIKE', endpoint ? `%${endpoint}%` : null],
      ['method', 'ILIKE', method ? `%${method}%` : null],
      ['"time"', '>=', dateFrom || null],
      ['"time"', '<=', dateTo || null],
    ];
    if (errorsOnly === 'true') filters.push(['error', 'IS NOT', 'NULL_PLACEHOLDER']);

    const clauses = [];
    const params = [];
    for (const [col, op, val] of filters) {
      if (val === null || val === undefined || val === '') continue;
      if (op === 'IS NOT') { clauses.push(`${col} IS NOT NULL`); continue; }
      params.push(val);
      clauses.push(`${col} ${op} $${params.length}`);
    }
    const where = clauses.length ? 'WHERE ' + clauses.join(' AND ') : '';

    const baseSql = `SELECT id, "serverId", "time", module, endpoint, method, duration, "numQueries", slow, error, "authenticatedUserId", "isOpen" FROM serverpod_session_log ${where} ORDER BY "time" DESC`;
    const countSql = `SELECT COUNT(*) FROM serverpod_session_log ${where}`;

    const result = await paginate(req, baseSql, countSql, params, parseInt(page), parseInt(pageSize), { estimateTable: 'serverpod_session_log' });
    res.json(result);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

router.get('/api/session-logs/:id/details', async (req, res) => {
  try {
    const id = parseInt(req.params.id);
    const [logs, queries, sessionRows] = await Promise.all([
      query(req, `SELECT id, "time", "logLevel", message, error, "stackTrace", "order" FROM serverpod_log WHERE "sessionLogId" = $1 ORDER BY "order" ASC`, [id]),
      query(req, `SELECT id, query, duration, "numRows", error, "stackTrace", slow, "order" FROM serverpod_query_log WHERE "sessionLogId" = $1 ORDER BY "order" ASC`, [id]),
      query(req, `SELECT error, "stackTrace" FROM serverpod_session_log WHERE id = $1`, [id]),
    ]);
    res.json({ session: sessionRows[0] || null, logs, queries });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ─── Routes: admin audit log ──────────────────────────────────────────────────
router.get('/api/admin-audit', async (req, res) => {
  try {
    const { action, userName, praxisId, dateFrom, dateTo, page = 1, pageSize = 50 } = req.query;
    const filters = [
      ['action', 'ILIKE', action ? `%${action}%` : null],
      ['"userName"', 'ILIKE', userName ? `%${userName}%` : null],
      ['"praxisId"', '=', praxisId || null],
      ['"createdAt"', '>=', dateFrom || null],
      ['"createdAt"', '<=', dateTo || null],
    ];
    const { where, params } = buildWhere(filters);
    const baseSql = `SELECT id, "userId", "userName", "userEmail", action, changes, "praxisId", "createdAt" FROM admin_audit_log ${where} ORDER BY "createdAt" DESC`;
    const countSql = `SELECT COUNT(*) FROM admin_audit_log ${where}`;
    const result = await paginate(req, baseSql, countSql, params, parseInt(page), parseInt(pageSize));
    res.json(result);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ─── Routes: notifications ────────────────────────────────────────────────────
router.get('/api/notifications', async (req, res) => {
  try {
    const { type, userId, dateFrom, dateTo, page = 1, pageSize = 50 } = req.query;
    const filters = [
      ['nl.type', '=', type !== undefined && type !== '' ? parseInt(type) : null],
      ['nl."userId"', '=', userId ? parseInt(userId) : null],
      ['nl."createdAt"', '>=', dateFrom || null],
      ['nl."createdAt"', '<=', dateTo || null],
    ];
    const { where, params } = buildWhere(filters);
    const baseSql = `SELECT nl.id, nl."userId", nl.title, nl.type, nl."activityId", nl.body, nl."isNew", nl."createdAt", aui.email as "userEmail", aui."firstName", aui."lastName" FROM notification_log nl LEFT JOIN app_user_info aui ON aui.id = nl."userId" ${where} ORDER BY nl."createdAt" DESC`;
    const countSql = `SELECT COUNT(*) FROM notification_log nl ${where}`;
    const result = await paginate(req, baseSql, countSql, params, parseInt(page), parseInt(pageSize));
    res.json(result);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

module.exports = router;
