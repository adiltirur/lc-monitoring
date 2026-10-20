const router = require('express').Router();
const { paginate, query } = require('../lib/db');

// ─── Routes: PMS Invitations (read-only) ──────────────────────────────────────
// Core creates app_user_pms_invitation rows when Principa sends a FHIR Patient
// that has no matching app user (or whose DOB does not match the app user with
// the same email), and logs every auto-link attempt in app_user_pms_auto_link_log
// (lib/src/endpoints/fhir/helper/fhir_patient_invitation_handler.dart).
// Both enums are serialized byIndex. 'expired' (2) was removed from Core
// ("Remove pms invite expiry"), but older rows on some envs still carry it.
const PI_STATUSES = ['pending', 'linked', 'expired'];
const PI_GENDERS = ['male', 'female', 'other'];
const PI_OUTCOMES = [
  'linked', 'dobMismatch', 'dobMissing', 'userAlreadyLinkedToOtherPatient', 'patientAlreadyLinked',
  'invitationCreated', 'invitationRenewed', 'pendingInvitationExists', 'noPmsPatientId', 'linkFailed',
  'linkedSeedFailed',
];

async function piTablesExist(req) {
  const rows = await query(req, `SELECT to_regclass('public.app_user_pms_invitation') IS NOT NULL AS inv,
    to_regclass('public.app_user_pms_auto_link_log') IS NOT NULL AS log`);
  return rows[0];
}

function piWhere(conds) {
  const params = [];
  const clauses = [];
  for (const [sql, val] of conds) {
    if (val === undefined || val === null || val === '') continue;
    params.push(val);
    clauses.push(sql.replace(/\$\?/g, `$${params.length}`));
  }
  return { where: clauses.length ? 'WHERE ' + clauses.join(' AND ') : '', params };
}

router.get('/api/pms-invitations/stats', async (req, res) => {
  try {
    const exists = await piTablesExist(req);
    const out = { tables: exists, invitations: {}, outcomes: {} };
    if (exists.inv) {
      const rows = await query(req, `SELECT status, COUNT(*)::int AS count FROM app_user_pms_invitation GROUP BY status`);
      for (const r of rows) out.invitations[PI_STATUSES[r.status] ?? r.status] = r.count;
    }
    if (exists.log) {
      const rows = await query(req, `SELECT outcome, COUNT(*)::int AS count FROM app_user_pms_auto_link_log
        WHERE "createdAt" > NOW() - INTERVAL '30 days' GROUP BY outcome ORDER BY count DESC`);
      for (const r of rows) out.outcomes[PI_OUTCOMES[r.outcome] ?? r.outcome] = r.count;
    }
    res.json(out);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

router.get('/api/pms-invitations', async (req, res) => {
  try {
    const { status, q, pmsPatientId, dateFrom, dateTo, page = 1, pageSize = 50 } = req.query;
    const statusIdx = PI_STATUSES.indexOf(String(status || ''));
    const { where, params } = piWhere([
      ['i.status = $?', statusIdx >= 0 ? statusIdx : null],
      ['i."pmsPatientId" = $?', pmsPatientId],
      [`(i.email ILIKE $? OR i."firstName" ILIKE $? OR i."lastName" ILIKE $? OR i."pmsPatientId" ILIKE $?
         OR i."invitationCode" ILIKE $? OR (i."firstName" || ' ' || i."lastName") ILIKE $?)`, q ? `%${q}%` : null],
      ['i."createdAt" >= $?', dateFrom],
      ['i."createdAt" <= $?', dateTo],
    ]);
    const baseSql = `SELECT i.id, i."pmsPatientId", i.email, i."firstName", i."lastName", i."phoneNumber", i.gender,
        to_char(i.dob, 'YYYY-MM-DD') AS dob, i."praxisId", i."invitationCode", i.status, i."linkedUserId",
        i."createdAt", i."modifiedAt",
        u.email AS "linkedEmail", u."firstName" AS "linkedFirstName", u."lastName" AS "linkedLastName",
        (SELECT COUNT(*)::int FROM app_user_pms_auto_link_log l WHERE l."pmsPatientId" = i."pmsPatientId") AS "logCount"
      FROM app_user_pms_invitation i
      LEFT JOIN app_user_info u ON u.id = i."linkedUserId"
      ${where} ORDER BY i."createdAt" DESC, i.id DESC`;
    const countSql = `SELECT COUNT(*) FROM app_user_pms_invitation i ${where}`;
    const result = await paginate(req, baseSql, countSql, params, parseInt(page), parseInt(pageSize));
    result.rows = result.rows.map(r => ({
      ...r,
      status: PI_STATUSES[r.status] ?? r.status,
      gender: r.gender === null ? null : (PI_GENDERS[r.gender] ?? r.gender),
    }));
    res.json(result);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

router.get('/api/pms-invitations/log', async (req, res) => {
  try {
    const { outcome, q, pmsPatientId, dateFrom, dateTo, page = 1, pageSize = 50 } = req.query;
    const outcomeIdx = PI_OUTCOMES.indexOf(String(outcome || ''));
    const { where, params } = piWhere([
      ['l.outcome = $?', outcomeIdx >= 0 ? outcomeIdx : null],
      ['l."pmsPatientId" = $?', pmsPatientId],
      ['(l.email ILIKE $? OR l."pmsPatientId" ILIKE $? OR l.details ILIKE $?)', q ? `%${q}%` : null],
      ['l."createdAt" >= $?', dateFrom],
      ['l."createdAt" <= $?', dateTo],
    ]);
    const baseSql = `SELECT l.id, l."pmsPatientId", l.email, to_char(l.dob, 'YYYY-MM-DD') AS dob, l."matchedUserId",
        l.outcome, l.details, l."createdAt",
        u.email AS "matchedEmail", u."firstName" AS "matchedFirstName", u."lastName" AS "matchedLastName"
      FROM app_user_pms_auto_link_log l
      LEFT JOIN app_user_info u ON u.id = l."matchedUserId"
      ${where} ORDER BY l."createdAt" DESC, l.id DESC`;
    const countSql = `SELECT COUNT(*) FROM app_user_pms_auto_link_log l ${where}`;
    const result = await paginate(req, baseSql, countSql, params, parseInt(page), parseInt(pageSize));
    result.rows = result.rows.map(r => ({ ...r, outcome: PI_OUTCOMES[r.outcome] ?? r.outcome }));
    res.json(result);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

module.exports = router;
