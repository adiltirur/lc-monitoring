const router = require('express').Router();
const { buildWhere, paginate } = require('../lib/db');

// ─── Routes: bookings ─────────────────────────────────────────────────────────
router.get('/api/bookings', async (req, res) => {
  try {
    const { dateFrom, dateTo, praxisId, status, category, page = 1, pageSize = 50 } = req.query;
    const filters = [
      ['a."praxisId"', '=', praxisId || null],
      ['a.status', '=', status !== undefined && status !== '' ? parseInt(status) : null],
      ['a.category', 'ILIKE', category ? `%${category}%` : null],
      ['a."createdAt"', '>=', dateFrom || null],
      ['a."createdAt"', '<=', dateTo || null],
    ];
    const { where, params } = buildWhere(filters);
    const baseSql = `SELECT a.id, a."appointmentId", a."pmsAppointmentId", a.category, a.reason, a.status, a."praxisId", a."startTime", a.resource, a."createdAt", a."modifiedAt", u."firstName", u."lastName", u.email, u."phoneNumber" FROM app_user_appointment a LEFT JOIN app_user_info u ON u.id = a."userId" ${where} ORDER BY a."createdAt" DESC`;
    const countSql = `SELECT COUNT(*) FROM app_user_appointment a ${where}`;
    const result = await paginate(req, baseSql, countSql, params, parseInt(page), parseInt(pageSize));
    res.json(result);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

router.get('/api/guest-bookings', async (req, res) => {
  try {
    const { dateFrom, dateTo, praxisId, status, category, page = 1, pageSize = 50 } = req.query;
    const filters = [
      ['"praxisId"', '=', praxisId || null],
      ['status', '=', status !== undefined && status !== '' ? parseInt(status) : null],
      ['category', 'ILIKE', category ? `%${category}%` : null],
      ['"createdAt"', '>=', dateFrom || null],
      ['"createdAt"', '<=', dateTo || null],
    ];
    const { where, params } = buildWhere(filters);
    const baseSql = `SELECT id, "bookingId", "patientId", category, reason, status, "praxisId", email, "startTime", "isBookedFromPraxis", "hasEmail", "encryptedUserInfo", "createdAt" FROM guest_appointment ${where} ORDER BY "createdAt" DESC`;
    const countSql = `SELECT COUNT(*) FROM guest_appointment ${where}`;
    const result = await paginate(req, baseSql, countSql, params, parseInt(page), parseInt(pageSize));
    res.json(result);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

module.exports = router;
