const router = require('express').Router();
const { paginate, query } = require('../lib/db');

// ─── Routes: users ────────────────────────────────────────────────────────────
router.get('/api/users', async (req, res) => {
  try {
    const { q, praxisId, page = 1, pageSize = 50 } = req.query;
    const params = [];
    const clauses = [];

    if (q && q.trim()) {
      params.push(`%${q.trim()}%`);
      const n = params.length;
      clauses.push(`("firstName" ILIKE $${n} OR "lastName" ILIKE $${n} OR email ILIKE $${n} OR "phoneNumber" ILIKE $${n} OR "lcAccountId" ILIKE $${n} OR "pmsPatientId" ILIKE $${n})`);
    }
    if (praxisId && praxisId.trim()) {
      params.push(praxisId.trim());
      clauses.push(`"praxisId" = $${params.length}`);
    }

    const where = clauses.length ? 'WHERE ' + clauses.join(' AND ') : '';
    const baseSql = `SELECT id, "firstName", "lastName", email, "phoneNumber", "praxisId", "isVerified", "pmsPatientId", "lcAccountId", "createdAt", "modifiedAt" FROM app_user_info ${where} ORDER BY "createdAt" DESC`;
    const countSql = `SELECT COUNT(*) FROM app_user_info ${where}`;
    const result = await paginate(req, baseSql, countSql, params, parseInt(page), parseInt(pageSize));
    res.json(result);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

router.get('/api/users/:id', async (req, res) => {
  try {
    const id = parseInt(req.params.id);
    const [userRows, insuranceRows, familyRows, appointmentRows] = await Promise.all([
      query(req, `SELECT * FROM app_user_info WHERE id = $1`, [id]),
      query(req, `SELECT * FROM app_user_insurance_info WHERE "userInfoId" = $1`, [id]),
      query(req, `SELECT * FROM app_user_family_member_info WHERE "userId" = $1 ORDER BY "createdAt" DESC`, [id]),
      query(req, `SELECT id, category, reason, "appointmentId", "pmsAppointmentId", status, "praxisId", "startTime", resource, "createdAt", "modifiedAt" FROM app_user_appointment WHERE "userId" = $1 ORDER BY "createdAt" DESC LIMIT 30`, [id]),
    ]);
    if (!userRows.length) return res.status(404).json({ error: 'User not found' });
    res.json({ user: userRows[0], insurance: insuranceRows[0] || null, family: familyRows, appointments: appointmentRows });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

const ALLOWED_USER_FIELDS = ['firstName', 'lastName', 'email', 'phoneNumber', 'street', 'city', 'postalCode', 'newEmail', 'newPhone'];

router.patch('/api/users/:id', async (req, res) => {
  try {
    const id = parseInt(req.params.id);
    const updates = {};
    for (const [key, val] of Object.entries(req.body)) {
      if (ALLOWED_USER_FIELDS.includes(key)) updates[key] = val;
    }
    if (!Object.keys(updates).length) return res.status(400).json({ error: 'No valid fields to update' });

    const sets = Object.keys(updates).map((k, i) => `"${k}" = $${i + 1}`);
    sets.push(`"modifiedAt" = NOW()`);
    const vals = [...Object.values(updates), id];
    const sql = `UPDATE app_user_info SET ${sets.join(', ')} WHERE id = $${vals.length} RETURNING *`;
    const rows = await query(req, sql, vals);
    res.json(rows[0]);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ─── Routes: verify user ──────────────────────────────────────────────────────
router.post('/api/users/:id/verify', async (req, res) => {
  try {
    const id = parseInt(req.params.id);
    const { verifiedBy = 'Debugger', verifiedByDocument = 'manual', verifiedByDocumentNumber = 'manual', verifiedByPraxisId = null } = req.body;
    const rows = await query(req, `UPDATE app_user_info SET "isVerified" = true, "verifiedBy" = $1, "verifiedOn" = NOW(), "verifiedByDocument" = $2, "verifiedByDocumentNumber" = $3, "verifiedByPraxisId" = $4, "modifiedAt" = NOW() WHERE id = $5 RETURNING *`,
      [verifiedBy, verifiedByDocument, verifiedByDocumentNumber, verifiedByPraxisId, id]);
    if (!rows.length) return res.status(404).json({ error: 'User not found' });
    res.json({ ok: true, user: rows[0] });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

module.exports = router;
