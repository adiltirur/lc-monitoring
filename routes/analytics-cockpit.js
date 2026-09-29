const router = require('express').Router();
const { BUNDESLAND_CODES, COCKPIT_DAY_NAMES, COCKPIT_KIND_NAMES, currentIsoYearWeek } = require('../lib/analytics');
const { query } = require('../lib/db');

// ─── Routes: Analytics / Cockpit (per-praxis schedule config) ────────────────
// Cockpit is the schedule editor in the praxis app. It writes to:
//   • cockpit_consultation_hours / cockpit_work_hours      (baseline per weekday)
//   • cockpit_week_override                                 (one-off per ISO week)
//   • cockpit_standard_week_version                         (versioned standard weeks)
//   • cockpit_person_duration_exception                     (per-employee overlay)
//   • cockpit_appointment_type_matrix                       (provider routing)
//   • praxis_config.bundeslandCode                          (holiday region)
//
// All `praxisId` columns on cockpit tables are int FKs to praxis_config.id, while
// the analytics overview uses praxis_config.lcId (string). We keep this layer
// keyed by lcId to match the rest of the analytics surface.

// Cockpit metrics keyed by praxis_config.lcId — rendered in the Analytics
// Overview table next to the booking/registration columns.
router.get('/api/analytics/cockpit-overview', async (req, res) => {
  try {
    const { year: cy, week: cw } = currentIsoYearWeek();
    const cwKey = cy * 53 + cw;

    const [praxes, consHours, workHours, overrides, versions, pdes, matrix] = await Promise.all([
      query(req, `SELECT id, "lcId", "bundeslandCode" FROM praxis_config`),
      query(req, `SELECT "praxisId",
                    COUNT(*)::int AS rows,
                    COALESCE(SUM(EXTRACT(EPOCH FROM ("end"::time - "start"::time)) / 60), 0)::int AS minutes
                  FROM cockpit_consultation_hours GROUP BY "praxisId"`),
      query(req, `SELECT "praxisId",
                    COUNT(*)::int AS rows,
                    COALESCE(SUM(EXTRACT(EPOCH FROM ("end"::time - "start"::time)) / 60), 0)::int AS minutes,
                    COALESCE(SUM("breakMin"), 0)::int AS break_minutes
                  FROM cockpit_work_hours GROUP BY "praxisId"`),
      query(req, `SELECT "praxisId", COUNT(*)::int AS c FROM cockpit_week_override GROUP BY "praxisId"`),
      query(req, `SELECT "praxisId", COUNT(*)::int AS c FROM cockpit_standard_week_version GROUP BY "praxisId"`),
      query(req, `SELECT "praxisId", COUNT(*)::int AS c FROM cockpit_person_duration_exception
                  WHERE ("validFromIsoYear" * 53 + "validFromIsoWeek") <= $1
                    AND ("validUntilIsoYear" IS NULL
                         OR ("validUntilIsoYear" * 53 + "validUntilIsoWeek") >= $1)
                  GROUP BY "praxisId"`, [cwKey]),
      query(req, `SELECT "praxisId", COUNT(*)::int AS c FROM cockpit_appointment_type_matrix GROUP BY "praxisId"`),
    ]);

    const byPid = {};
    for (const r of consHours)  (byPid[r.praxisId] ||= {}).consultation = { rows: r.rows, minutes: r.minutes };
    for (const r of workHours)  (byPid[r.praxisId] ||= {}).work         = { rows: r.rows, minutes: r.minutes, breakMinutes: r.break_minutes };
    for (const r of overrides)  (byPid[r.praxisId] ||= {}).overrides    = r.c;
    for (const r of versions)   (byPid[r.praxisId] ||= {}).versions     = r.c;
    for (const r of pdes)       (byPid[r.praxisId] ||= {}).activePdes   = r.c;
    for (const r of matrix)     (byPid[r.praxisId] ||= {}).matrixEntries = r.c;

    const result = praxes.map(p => {
      const m = byPid[p.id] || {};
      const cons = m.consultation || { rows: 0, minutes: 0 };
      const work = m.work || { rows: 0, minutes: 0, breakMinutes: 0 };
      const blIdx = p.bundeslandCode === null || p.bundeslandCode === undefined ? null : Number(p.bundeslandCode);
      return {
        lcId: p.lcId,
        bundesland: blIdx === null ? null : (BUNDESLAND_CODES[blIdx] || null),
        hasBaseline: cons.rows > 0 || work.rows > 0,
        consultationRows: cons.rows,
        consultationMinutes: cons.minutes,
        workRows: work.rows,
        workMinutes: work.minutes,
        workBreakMinutes: work.breakMinutes,
        overrideCount: m.overrides || 0,
        versionCount: m.versions || 0,
        activePdeCount: m.activePdes || 0,
        matrixEntries: m.matrixEntries || 0,
      };
    });

    res.json({
      currentIsoYear: cy,
      currentIsoWeek: cw,
      praxes: result,
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Cockpit detail for a single praxis (lcId) — consumed by the per-praxis
// analytics view to render a dedicated Cockpit tab.
router.get('/api/analytics/cockpit', async (req, res) => {
  try {
    const lcId = (req.query.praxisId || '').toString().trim();
    if (!lcId) return res.status(400).json({ error: 'praxisId is required' });
    const { year: cy, week: cw } = currentIsoYearWeek();
    const cwKey = cy * 53 + cw;

    const praxisRows = await query(req, `SELECT id, "lcId", name, "bundeslandCode" FROM praxis_config WHERE "lcId" = $1`, [lcId]);
    if (!praxisRows.length) return res.status(404).json({ error: 'praxis not found' });
    const p = praxisRows[0];

    const [cons, work, matrix, overrides, versions, pdes] = await Promise.all([
      query(req, `SELECT "employeeId", day, kind, "start", "end", "onlineBookable",
                    EXTRACT(EPOCH FROM ("end"::time - "start"::time)) / 60 AS minutes
                  FROM cockpit_consultation_hours WHERE "praxisId" = $1
                  ORDER BY "employeeId", day, "start"`, [p.id]),
      query(req, `SELECT "employeeId", day, "start", "end", "breakMin",
                    EXTRACT(EPOCH FROM ("end"::time - "start"::time)) / 60 AS minutes
                  FROM cockpit_work_hours WHERE "praxisId" = $1
                  ORDER BY "employeeId", day, "start"`, [p.id]),
      query(req, `SELECT "appointmentTypeKey", providers, "modifiedAt"
                  FROM cockpit_appointment_type_matrix WHERE "praxisId" = $1
                  ORDER BY "appointmentTypeKey"`, [p.id]),
      query(req, `SELECT "isoYear", "isoWeek",
                    "openingHoursJson" IS NOT NULL AS has_opening,
                    "consultationHoursJson" IS NOT NULL AS has_consultation,
                    "workHoursJson" IS NOT NULL AS has_work,
                    "mfaGenericHoursJson" IS NOT NULL AS has_mfa_generic,
                    "modifiedAt"
                  FROM cockpit_week_override WHERE "praxisId" = $1
                  ORDER BY "isoYear" DESC, "isoWeek" DESC LIMIT 25`, [p.id]),
      query(req, `SELECT "validFromIsoYear", "validFromIsoWeek",
                    "openingHoursJson" IS NOT NULL AS has_opening,
                    "consultationHoursJson" IS NOT NULL AS has_consultation,
                    "workHoursJson" IS NOT NULL AS has_work,
                    "mfaGenericHoursJson" IS NOT NULL AS has_mfa_generic,
                    "createdBy", "createdAt"
                  FROM cockpit_standard_week_version WHERE "praxisId" = $1
                  ORDER BY "validFromIsoYear" DESC, "validFromIsoWeek" DESC LIMIT 25`, [p.id]),
      query(req, `SELECT id, "employeeId", kind, day, "start", "end",
                    "validFromIsoYear", "validFromIsoWeek",
                    "validUntilIsoYear", "validUntilIsoWeek", note,
                    (("validFromIsoYear" * 53 + "validFromIsoWeek") <= $2
                     AND ("validUntilIsoYear" IS NULL
                          OR ("validUntilIsoYear" * 53 + "validUntilIsoWeek") >= $2)) AS is_active
                  FROM cockpit_person_duration_exception WHERE "praxisId" = $1
                  ORDER BY "validFromIsoYear" DESC, "validFromIsoWeek" DESC, id DESC`, [p.id, cwKey]),
    ]);

    const consByEmp = {};
    let consTotalMinutes = 0, consBookableMinutes = 0;
    const consKindMinutes = {};
    for (const r of cons) {
      const mins = parseFloat(r.minutes) || 0;
      consTotalMinutes += mins;
      if (r.onlineBookable) consBookableMinutes += mins;
      const kindName = COCKPIT_KIND_NAMES[Number(r.kind)] || `kind_${r.kind}`;
      consKindMinutes[kindName] = (consKindMinutes[kindName] || 0) + mins;
      const e = (consByEmp[r.employeeId] ||= { employeeId: r.employeeId, minutes: 0, slots: 0 });
      e.minutes += mins;
      e.slots += 1;
    }

    const workByEmp = {};
    let workTotalMinutes = 0, workBreakMinutes = 0;
    for (const r of work) {
      const mins = parseFloat(r.minutes) || 0;
      workTotalMinutes += mins;
      workBreakMinutes += r.breakMin || 0;
      const e = (workByEmp[r.employeeId] ||= { employeeId: r.employeeId, minutes: 0, breakMinutes: 0, slots: 0 });
      e.minutes += mins;
      e.breakMinutes += r.breakMin || 0;
      e.slots += 1;
    }

    const employees = {};
    for (const id of Object.keys(consByEmp)) (employees[id] ||= { employeeId: parseInt(id, 10), consultationMinutes: 0, workMinutes: 0, workBreakMinutes: 0 }).consultationMinutes = consByEmp[id].minutes;
    for (const id of Object.keys(workByEmp)) {
      const e = (employees[id] ||= { employeeId: parseInt(id, 10), consultationMinutes: 0, workMinutes: 0, workBreakMinutes: 0 });
      e.workMinutes = workByEmp[id].minutes;
      e.workBreakMinutes = workByEmp[id].breakMinutes;
    }
    const employeeRows = Object.values(employees).sort((a, b) => b.workMinutes - a.workMinutes);

    const activePdes = pdes.filter(p => p.is_active).length;

    const blIdx = p.bundeslandCode === null || p.bundeslandCode === undefined ? null : Number(p.bundeslandCode);
    res.json({
      praxisId: lcId,
      praxisName: p.name,
      bundesland: blIdx === null ? null : (BUNDESLAND_CODES[blIdx] || null),
      currentIsoYear: cy,
      currentIsoWeek: cw,
      summary: {
        consultationMinutes: Math.round(consTotalMinutes),
        consultationBookableMinutes: Math.round(consBookableMinutes),
        consultationKindMinutes: Object.fromEntries(Object.entries(consKindMinutes).map(([k, v]) => [k, Math.round(v)])),
        workMinutes: Math.round(workTotalMinutes),
        workBreakMinutes: Math.round(workBreakMinutes),
        employeeCount: employeeRows.length,
        overrideCount: overrides.length,
        versionCount: versions.length,
        matrixEntries: matrix.length,
        activePdeCount: activePdes,
        totalPdeCount: pdes.length,
      },
      employees: employeeRows,
      overrides: overrides.map(r => ({
        isoYear: r.isoYear,
        isoWeek: r.isoWeek,
        hasOpening: r.has_opening,
        hasConsultation: r.has_consultation,
        hasWork: r.has_work,
        hasMfaGeneric: r.has_mfa_generic,
        modifiedAt: r.modifiedAt,
      })),
      versions: versions.map(r => ({
        validFromIsoYear: r.validFromIsoYear,
        validFromIsoWeek: r.validFromIsoWeek,
        hasOpening: r.has_opening,
        hasConsultation: r.has_consultation,
        hasWork: r.has_work,
        hasMfaGeneric: r.has_mfa_generic,
        createdBy: r.createdBy,
        createdAt: r.createdAt,
      })),
      pdes: pdes.map(r => ({
        id: r.id,
        employeeId: r.employeeId,
        kind: COCKPIT_KIND_NAMES[Number(r.kind)] || `kind_${r.kind}`,
        day: COCKPIT_DAY_NAMES[Number(r.day)] || `day_${r.day}`,
        start: r.start,
        end: r.end,
        validFromIsoYear: r.validFromIsoYear,
        validFromIsoWeek: r.validFromIsoWeek,
        validUntilIsoYear: r.validUntilIsoYear,
        validUntilIsoWeek: r.validUntilIsoWeek,
        note: r.note,
        isActive: r.is_active,
      })),
      matrix: matrix.map(r => ({
        appointmentTypeKey: r.appointmentTypeKey,
        providers: r.providers || [],
        modifiedAt: r.modifiedAt,
      })),
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

module.exports = router;
