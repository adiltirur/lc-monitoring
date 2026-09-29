const path = require('path');
const router = require('express').Router();
const { query } = require('../lib/db');
const { BUNDESLAND_CODES, TOOK_PLACE_STATUS_FILTER, currentIsoYearWeek } = require('../lib/analytics');

const ROOT = path.join(__dirname, '..'); // helper/

// ─── Routes: Historical Analytics Export ─────────────────────────────────────
// One-time bulk export of aggregated analytics from the earliest data in the
// DB through a chosen end date. Writes XLSX + JSON + a self-contained HTML
// report. Walks praxes one-at-a-time to keep DB load identical to a single
// normal user request at any moment.
//
//   GET /api/analytics/export-historical?endDate=YYYY-MM-DD
//
// Returns { ok, outDir, files, praxesProcessed, monthsCovered, dataStart, dataEnd }.

function _padMonth(d) {
  return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}`;
}

function _enumerateMonths(start, end) {
  const out = [];
  const cur = new Date(start.getFullYear(), start.getMonth(), 1);
  while (cur <= end) {
    out.push(_padMonth(cur));
    cur.setMonth(cur.getMonth() + 1);
  }
  return out;
}

// Per-praxis monthly KPI shape. Excludes truly-global metrics (PMS downtime,
// deletion feedback) — those have no praxisId path and live in their own
// global section in the report.
//
// guestNPS recovery: fhir_nps has TWO write sites in the backend
// (lib/src/endpoints/fhir/helper/fhir_appointment_handler.dart):
//   1. handleNewAppointment :329 — fires on the unregistered-patient booking
//      branch (booked / rescheduled / cancelled). NO NPS email is sent here;
//      the row is "spurious" w.r.t. actual NPS delivery. Always paired with
//      a guest_appointment insert :320 carrying isBookedFromPraxis=true.
//   2. handleUnknownBooking :422 — fires only when status=fulfilled, paired
//      with scheduleGuestNPS(...) which actually triggers the Brevo send.
//      Writes NO guest_appointment row.
// So "real" guest NPS attempts ≈ fhir_nps − guest_appointment(isBookedFromPraxis=true).
// Both raw and corrected counts are kept here so the report can show the gap.
function _emptyMonthlyKpi() {
  return {
    appointmentsBookedFromApp: 0,
    appointmentsBookedFromWeb: 0,
    appointmentsBookedFromPraxis: 0,
    appointmentsBookedFromPraxisWithoutEmail: 0,
    totalAppointments: 0,
    appointmentsTookPlaceFromApp: 0,
    appointmentsTookPlaceFromWeb: 0,
    appointmentsTookPlaceFromPraxis: 0,
    appointmentsTookPlaceFromPraxisWithoutEmail: 0,
    totalAppointmentsTookPlace: 0,
    npsEmailsSent: 0,
    guestNPS: 0,                          // corrected: real :422 attempts
    guestNPSRequestWithoutEmail: 0,       // corrected: real :422 attempts w/o email
    guestNPSRaw: 0,                       // raw fhir_nps count (incl. :329 spurious)
    guestNPSRawWithoutEmail: 0,           // raw fhir_nps where hasEmail=false
    guestNPSSpurious: 0,                  // :329 writes (= praxis-booked guest_appointments)
    totalNPSSent: 0,
    documentRequestFromApp: 0,
    documentRequestFromWeb: 0,
    documentRequestUnknown: 0,
    totalDocumentRequests: 0,
    openConsultations: 0,
    newRegistrations: 0,
    newVerifiedRegistrations: 0,
    cancellations: 0,
    questionnairesCompleted: 0,
  };
}

async function _fetchPraxisAggregates(req, praxisId, rangeStart, rangeEnd) {
  // One pass per praxis: pull only the columns we need for aggregation. No
  // patient PII (firstName/lastName/email/userId) is read — we only need
  // category/flags/timestamps to compute counts.
  const [
    npsSent,
    fhirNps,
    appAppts,
    webAppts,
    docReqs,
    openCons,
    cancellations,
    registrations,
    appAppointmentsTookPlace,
    guestAppointmentsTookPlace,
    questionnaires,
    totalsRow,
  ] = await Promise.all([
    query(req, `SELECT "createdAt"                             FROM app_user_nps_sent              WHERE "praxisId"=$1 AND "createdAt" BETWEEN $2 AND $3`, [praxisId, rangeStart, rangeEnd]),
    query(req, `SELECT "createdAt", "hasEmail"                 FROM fhir_nps                       WHERE "praxisId"=$1 AND "createdAt" BETWEEN $2 AND $3`, [praxisId, rangeStart, rangeEnd]),
    query(req, `SELECT "createdAt", "startTime", category, "familyMemberId"
                                                                FROM app_user_appointment           WHERE "praxisId"=$1 AND "createdAt" BETWEEN $2 AND $3`, [praxisId, rangeStart, rangeEnd]),
    query(req, `SELECT "createdAt", "startTime", category, "isBookedFromPraxis", "hasEmail"
                                                                FROM guest_appointment              WHERE "praxisId"=$1 AND "createdAt" BETWEEN $2 AND $3`, [praxisId, rangeStart, rangeEnd]),
    query(req, `SELECT "createdAt", "isFromWeb", category       FROM app_user_document_request      WHERE "praxisId"=$1 AND "createdAt" BETWEEN $2 AND $3`, [praxisId, rangeStart, rangeEnd]),
    query(req, `SELECT "createdAt", category                    FROM app_user_open_consultation     WHERE "praxisId"=$1 AND "createdAt" BETWEEN $2 AND $3`, [praxisId, rangeStart, rangeEnd]),
    // Cancellation attribution: only count when the cancelling user actually
    // has at least one appointment at THIS praxis. cancellation_reason has no
    // praxisId/appointmentId in schema, so pure user→praxis JOIN over-attributes
    // (users registered at A who book+cancel at B end up showing under A).
    // The EXISTS filter excludes those phantom cancellations; they're counted
    // globally as "Unattributed Cancellations".
    query(req, `SELECT c."createdAt", c.reason
                  FROM app_user_appointment_cancellation_reason c
                  JOIN app_user_info ui ON ui.id = c."userId"
                  WHERE ui."praxisId"=$1 AND c."createdAt" BETWEEN $2 AND $3
                    AND EXISTS (
                      SELECT 1 FROM app_user_appointment a
                      WHERE a."userId" = c."userId" AND a."praxisId" = $1
                    )`, [praxisId, rangeStart, rangeEnd]),
    query(req, `SELECT "createdAt", "isVerified"                FROM app_user_info                  WHERE "praxisId"=$1 AND "createdAt" BETWEEN $2 AND $3`, [praxisId, rangeStart, rangeEnd]),
    query(req, `SELECT "startTime"                              FROM app_user_appointment           WHERE "praxisId"=$1 AND "startTime" IS NOT NULL AND "startTime" BETWEEN $2 AND $3 ${TOOK_PLACE_STATUS_FILTER}`, [praxisId, rangeStart.toISOString(), rangeEnd.toISOString()]),
    query(req, `SELECT "startTime", "isBookedFromPraxis", "hasEmail"
                                                                FROM guest_appointment              WHERE "praxisId"=$1 AND "startTime" IS NOT NULL AND "startTime" BETWEEN $2 AND $3 ${TOOK_PLACE_STATUS_FILTER}`, [praxisId, rangeStart.toISOString(), rangeEnd.toISOString()]),
    query(req, `SELECT q."answeredAt"
                  FROM app_user_questionnaire q
                  JOIN app_user_info ui ON ui.id = q."userInfoId"
                  WHERE ui."praxisId"=$1 AND q."answeredAt" BETWEEN $2 AND $3`, [praxisId, rangeStart, rangeEnd]),
    query(req, `SELECT
                  (SELECT COUNT(*)::int FROM app_user_info WHERE "praxisId"=$1)                          AS total_patients,
                  (SELECT COUNT(*)::int FROM app_user_info WHERE "praxisId"=$1 AND "isVerified"=true)    AS total_verified`, [praxisId]),
  ]);

  const monthly = {};
  const ensureMonth = (key) => (monthly[key] ||= _emptyMonthlyKpi());
  const monthKey = (d) => _padMonth(new Date(d));

  // totalNPSSent is recomputed at the end of this function from
  // (npsEmailsSent + corrected guestNPS), so no in-loop increment here.
  for (const r of npsSent) {
    const m = ensureMonth(monthKey(r.createdAt));
    m.npsEmailsSent++;
  }
  // Raw fhir_nps counts (both write sites combined). Corrected to actual NPS
  // attempts further down by subtracting the :329 spurious writes (= count of
  // guest_appointment rows with isBookedFromPraxis=true in the same month).
  for (const r of fhirNps) {
    const m = ensureMonth(monthKey(r.createdAt));
    m.guestNPSRaw++;
    if (r.hasEmail === false) m.guestNPSRawWithoutEmail++;
  }
  const apptCategories = {};
  for (const r of appAppts) {
    const m = ensureMonth(monthKey(r.createdAt));
    m.appointmentsBookedFromApp++;
    m.totalAppointments++;
    apptCategories[r.category || '—'] = (apptCategories[r.category || '—'] || 0) + 1;
  }
  // Praxis-booked guest_appointments are exactly the rows that triggered the
  // :329 spurious fhir_nps write — track separately for the guestNPS recovery.
  const praxisBookedNoEmailByMonth = {};
  for (const r of webAppts) {
    const mk = monthKey(r.createdAt);
    const m = ensureMonth(mk);
    if (r.isBookedFromPraxis === true) {
      m.appointmentsBookedFromPraxis++;
      m.guestNPSSpurious++;
      if (r.hasEmail !== true) {
        m.appointmentsBookedFromPraxisWithoutEmail++;
        praxisBookedNoEmailByMonth[mk] = (praxisBookedNoEmailByMonth[mk] || 0) + 1;
      }
    } else {
      m.appointmentsBookedFromWeb++;
    }
    m.totalAppointments++;
    apptCategories[r.category || '—'] = (apptCategories[r.category || '—'] || 0) + 1;
  }
  // Apply the recovery formula: corrected guestNPS = raw − spurious.
  // The :329 site sets fhir_nps.hasEmail to the same value as the paired
  // guest_appointment.hasEmail (both come from userInfo.email.isNotEmpty in
  // handleNewAppointment), so we subtract the matching no-email subset too.
  // Clamp at 0 in case of any cross-month boundary mismatch.
  for (const [mk, m] of Object.entries(monthly)) {
    m.guestNPS                   = Math.max(0, m.guestNPSRaw - m.guestNPSSpurious);
    m.guestNPSRequestWithoutEmail = Math.max(0, m.guestNPSRawWithoutEmail - (praxisBookedNoEmailByMonth[mk] || 0));
    m.totalNPSSent               = m.npsEmailsSent + m.guestNPS;
  }
  for (const r of appAppointmentsTookPlace) {
    const m = ensureMonth(monthKey(r.startTime));
    m.appointmentsTookPlaceFromApp++;
    m.totalAppointmentsTookPlace++;
  }
  for (const r of guestAppointmentsTookPlace) {
    const m = ensureMonth(monthKey(r.startTime));
    if (r.isBookedFromPraxis === true) {
      m.appointmentsTookPlaceFromPraxis++;
      if (r.hasEmail !== true) m.appointmentsTookPlaceFromPraxisWithoutEmail++;
    } else {
      m.appointmentsTookPlaceFromWeb++;
    }
    m.totalAppointmentsTookPlace++;
  }
  for (const r of docReqs) {
    const m = ensureMonth(monthKey(r.createdAt));
    if (r.isFromWeb === true) m.documentRequestFromWeb++;
    else if (r.isFromWeb === false) m.documentRequestFromApp++;
    else m.documentRequestUnknown++;
    m.totalDocumentRequests++;
  }
  for (const r of openCons) {
    const m = ensureMonth(monthKey(r.createdAt));
    m.openConsultations++;
  }
  // app_user_appointment_cancellation_reason.reason is a JSON array — pg
  // returns it as a real JS array. Iterate and count each entry.
  const cancellationReasons = {};
  for (const r of cancellations) {
    const m = ensureMonth(monthKey(r.createdAt));
    m.cancellations++;
    const list = Array.isArray(r.reason) ? r.reason : (r.reason != null ? [r.reason] : ['—']);
    for (const reason of list) {
      const k = String(reason).slice(0, 120);
      cancellationReasons[k] = (cancellationReasons[k] || 0) + 1;
    }
  }
  for (const r of registrations) {
    const m = ensureMonth(monthKey(r.createdAt));
    m.newRegistrations++;
    if (r.isVerified === true) m.newVerifiedRegistrations++;
  }
  for (const r of questionnaires) {
    const m = ensureMonth(monthKey(r.answeredAt));
    m.questionnairesCompleted++;
  }
  // Deletion feedback has no praxisId path in schema — handled in the
  // global section of the report, not bucketed per-praxis.

  const totals = _emptyMonthlyKpi();
  for (const m of Object.values(monthly)) {
    for (const k of Object.keys(totals)) totals[k] += (m[k] || 0);
  }
  totals.cancellationRate            = totals.totalAppointments > 0 ? (totals.cancellations / totals.totalAppointments) * 100 : 0;
  totals.verificationRate            = totals.newRegistrations > 0 ? (totals.newVerifiedRegistrations / totals.newRegistrations) * 100 : 0;
  // NPS is triggered after appointments, document requests, and open
  // consultations (see backend booking + document_request + open_consultation
  // handlers). Coverage denominator must reflect all three. Note: backend
  // dedupes NPS to once per 30 days per user, so <100% is normal even if
  // every event would otherwise trigger a send.
  totals.totalNpsEligibleEvents      = totals.totalAppointments + totals.totalDocumentRequests + totals.openConsultations;
  totals.npsCoveragePercentage       = totals.totalNpsEligibleEvents > 0 ? (totals.totalNPSSent / totals.totalNpsEligibleEvents) * 100 : 0;
  totals.totalPatients               = totalsRow[0] ? parseInt(totalsRow[0].total_patients, 10) || 0 : 0;
  totals.totalVerifiedPatients       = totalsRow[0] ? parseInt(totalsRow[0].total_verified, 10) || 0 : 0;

  // Diagnostic: raw row counts from each query + arithmetic invariant check.
  // Lets us confirm the export numbers match direct DB reality and surfaces
  // any code-side bug (e.g. accidental double-increment) loudly.
  const sanity = {
    rowCounts: {
      npsSent: npsSent.length,
      fhirNps: fhirNps.length,
      appAppts: appAppts.length,
      webAppts: webAppts.length,
      docReqs: docReqs.length,
      openCons: openCons.length,
      cancellations: cancellations.length,
      registrations: registrations.length,
      appAppointmentsTookPlace: appAppointmentsTookPlace.length,
      guestAppointmentsTookPlace: guestAppointmentsTookPlace.length,
      questionnaires: questionnaires.length,
    },
    invariants: {
      totalAppointmentsMatchesSum: totals.totalAppointments === (totals.appointmentsBookedFromApp + totals.appointmentsBookedFromWeb + totals.appointmentsBookedFromPraxis),
      totalAppointmentsTookPlaceMatchesSum: totals.totalAppointmentsTookPlace === (totals.appointmentsTookPlaceFromApp + totals.appointmentsTookPlaceFromWeb + totals.appointmentsTookPlaceFromPraxis),
      praxisNoEmailLessOrEqualPraxis: totals.appointmentsBookedFromPraxisWithoutEmail <= totals.appointmentsBookedFromPraxis,
      // guestNPS correction: spurious writes shouldn't exceed raw fhir_nps
      // count or the count of praxis-booked guest_appointments (both sides
      // of the recovery identity must hold).
      guestNPSSpuriousMatchesPraxisBooked: totals.guestNPSSpurious === totals.appointmentsBookedFromPraxis,
      guestNPSRawCoversCorrection: totals.guestNPSRaw >= totals.guestNPSSpurious,
    },
    // Headline counts for the recovery formula. Show both raw and corrected
    // so we can quantify the gap when explaining to stakeholders.
    guestNPSRecovery: {
      rawFhirNps:               totals.guestNPSRaw,
      spuriousFromPraxisBooked: totals.guestNPSSpurious,
      correctedAttempts:        totals.guestNPS,
      rawNoEmail:               totals.guestNPSRawWithoutEmail,
      correctedNoEmail:         totals.guestNPSRequestWithoutEmail,
    },
  };
  if (!sanity.invariants.totalAppointmentsMatchesSum || !sanity.invariants.totalAppointmentsTookPlaceMatchesSum) {
    console.warn(`[export] sanity FAIL for ${praxisId}:`, JSON.stringify({ rowCounts: sanity.rowCounts, totals: { app: totals.appointmentsBookedFromApp, web: totals.appointmentsBookedFromWeb, praxis: totals.appointmentsBookedFromPraxis, noEmail: totals.appointmentsBookedFromPraxisWithoutEmail, total: totals.totalAppointments } }));
  } else {
    console.log(`[export] ${praxisId}: app=${totals.appointmentsBookedFromApp} web=${totals.appointmentsBookedFromWeb} praxis=${totals.appointmentsBookedFromPraxis} (noEmail=${totals.appointmentsBookedFromPraxisWithoutEmail}) total=${totals.totalAppointments}`);
  }

  const top10 = (counts) => Object.entries(counts).sort((a, b) => b[1] - a[1]).slice(0, 10).map(([k, v]) => ({ category: k, count: v }));

  return {
    monthly,
    totals,
    appointmentCategories: top10(apptCategories),
    cancellationReasons:   top10(cancellationReasons),
    _debug: sanity,
  };
}

async function _gatherCockpitOverview(req) {
  const { year: cy, week: cw } = currentIsoYearWeek();
  const cwKey = cy * 53 + cw;
  const [praxes, consHours, workHours, overrides, versions, pdes, matrix] = await Promise.all([
    query(req, `SELECT id, "lcId", "bundeslandCode" FROM praxis_config`),
    query(req, `SELECT "praxisId", COUNT(*)::int AS rows, COALESCE(SUM(EXTRACT(EPOCH FROM ("end"::time - "start"::time)) / 60), 0)::int AS minutes FROM cockpit_consultation_hours GROUP BY "praxisId"`),
    query(req, `SELECT "praxisId", COUNT(*)::int AS rows, COALESCE(SUM(EXTRACT(EPOCH FROM ("end"::time - "start"::time)) / 60), 0)::int AS minutes, COALESCE(SUM("breakMin"), 0)::int AS break_minutes FROM cockpit_work_hours GROUP BY "praxisId"`),
    query(req, `SELECT "praxisId", COUNT(*)::int AS c FROM cockpit_week_override GROUP BY "praxisId"`),
    query(req, `SELECT "praxisId", COUNT(*)::int AS c FROM cockpit_standard_week_version GROUP BY "praxisId"`),
    query(req, `SELECT "praxisId", COUNT(*)::int AS c FROM cockpit_person_duration_exception WHERE ("validFromIsoYear" * 53 + "validFromIsoWeek") <= $1 AND ("validUntilIsoYear" IS NULL OR ("validUntilIsoYear" * 53 + "validUntilIsoWeek") >= $1) GROUP BY "praxisId"`, [cwKey]),
    query(req, `SELECT "praxisId", COUNT(*)::int AS c FROM cockpit_appointment_type_matrix GROUP BY "praxisId"`),
  ]);
  const byId = (rows) => Object.fromEntries(rows.map(r => [r.praxisId, r]));
  const c = byId(consHours), w = byId(workHours), o = byId(overrides), v = byId(versions), p = byId(pdes), m = byId(matrix);
  return praxes.map(pr => ({
    lcId: pr.lcId,
    bundesland: pr.bundeslandCode != null ? (BUNDESLAND_CODES[pr.bundeslandCode] || null) : null,
    consultationRows:    c[pr.id]?.rows    || 0,
    consultationMinutes: c[pr.id]?.minutes || 0,
    workRows:            w[pr.id]?.rows    || 0,
    workMinutes:         w[pr.id]?.minutes || 0,
    workBreakMinutes:    w[pr.id]?.break_minutes || 0,
    overrideCount:       o[pr.id]?.c || 0,
    versionCount:        v[pr.id]?.c || 0,
    activePdeCount:      p[pr.id]?.c || 0,
    matrixEntries:       m[pr.id]?.c || 0,
    hasBaseline:         (c[pr.id]?.rows || 0) > 0 || (w[pr.id]?.rows || 0) > 0,
  }));
}

function _xlsxFromPayload(payload) {
  const xlsx = require('xlsx');
  const wb = xlsx.utils.book_new();

  const indexRows = payload.praxes.map(p => ({
    lcId: p.lcId, name: p.name, shortName: p.shortName, bundesland: p.bundesland,
  }));
  xlsx.utils.book_append_sheet(wb, xlsx.utils.json_to_sheet(indexRows), 'Praxes');

  const totalRows = payload.praxes.map(p => ({
    lcId: p.lcId, name: p.name, ...p.totals,
  }));
  xlsx.utils.book_append_sheet(wb, xlsx.utils.json_to_sheet(totalRows), 'Totals');

  const monthlyRows = [];
  for (const p of payload.praxes) {
    for (const month of payload.monthsCovered) {
      const m = p.monthly[month] || _emptyMonthlyKpi();
      monthlyRows.push({ lcId: p.lcId, name: p.name, month, ...m });
    }
  }
  xlsx.utils.book_append_sheet(wb, xlsx.utils.json_to_sheet(monthlyRows), 'Monthly');

  const catRows = [];
  for (const p of payload.praxes) {
    for (const c of p.appointmentCategories) catRows.push({ lcId: p.lcId, name: p.name, category: c.category, count: c.count });
  }
  xlsx.utils.book_append_sheet(wb, xlsx.utils.json_to_sheet(catRows.length ? catRows : [{ lcId: '', name: '', category: '', count: 0 }]), 'AppointmentCategories');

  const cancelRows = [];
  for (const p of payload.praxes) {
    for (const c of p.cancellationReasons) cancelRows.push({ lcId: p.lcId, name: p.name, reason: c.category, count: c.count });
  }
  xlsx.utils.book_append_sheet(wb, xlsx.utils.json_to_sheet(cancelRows.length ? cancelRows : [{ lcId: '', name: '', reason: '', count: 0 }]), 'CancellationReasons');

  xlsx.utils.book_append_sheet(wb, xlsx.utils.json_to_sheet(payload.pmsDowntimes.length ? payload.pmsDowntimes : [{ id: '', totalDownTimeInSeconds: 0, createdAt: '' }]), 'PMSDowntimes');

  xlsx.utils.book_append_sheet(wb, xlsx.utils.json_to_sheet(payload.cockpit.length ? payload.cockpit : [{ lcId: '' }]), 'CockpitSummary');

  xlsx.utils.book_append_sheet(wb, xlsx.utils.json_to_sheet(payload.deletionReasons.length ? payload.deletionReasons : [{ reason: '', count: 0 }]), 'DeletionReasons');

  const unattrRows = (payload.unattributedCancellations?.byUserRegisteredPraxis?.length
    ? payload.unattributedCancellations.byUserRegisteredPraxis
    : [{ lcId: '', count: 0 }]);
  xlsx.utils.book_append_sheet(wb, xlsx.utils.json_to_sheet(unattrRows), 'UnattributedCancellations');

  return xlsx.write(wb, { type: 'buffer', bookType: 'xlsx' });
}

// Compute [start, end] ISO timestamps for a "YYYY-MM" bucket key. The export
// buckets rows in JS using local-time getFullYear/getMonth — we use UTC here
// for the SQL filter; for end-of-month boundaries the difference is rare and
// the validator output will be within 1 row of the report.
function _monthRange(monthStr) {
  const [year, month] = monthStr.split('-').map(Number);
  const start = `${year}-${String(month).padStart(2, '0')}-01T00:00:00.000Z`;
  const nextY = month === 12 ? year + 1 : year;
  const nextM = month === 12 ? 1 : month + 1;
  const nextStart = new Date(Date.UTC(nextY, nextM - 1, 1));
  const endInclusive = new Date(nextStart.getTime() - 1).toISOString();
  return { start, end: endInclusive };
}

// SQL for a single monthly-table cell. Each column maps to one COUNT query.
// (The existing _validationSqlFor builders return multi-column breakdowns;
// for cells, single-COUNT is cleaner.)
function _monthCellSql(column, lcId, start, end) {
  const r = (s) => s.trim();
  const px = `"praxisId" = '${lcId}'`;
  const win = `BETWEEN '${start}' AND '${end}'`;
  switch (column) {
    case 'app':
      return r(`SELECT COUNT(*) FROM app_user_appointment WHERE ${px} AND "createdAt" ${win};`);
    case 'web':
      return r(`SELECT COUNT(*) FROM guest_appointment WHERE ${px} AND "createdAt" ${win} AND ("isBookedFromPraxis" IS NOT TRUE);`);
    case 'praxis':
      return r(`SELECT COUNT(*) FROM guest_appointment WHERE ${px} AND "createdAt" ${win} AND "isBookedFromPraxis" = true;`);
    case 'praxisNoEmail':
      return r(`SELECT COUNT(*) FROM guest_appointment WHERE ${px} AND "createdAt" ${win} AND "isBookedFromPraxis" = true AND "hasEmail" = false;`);
    case 'totalBooked':
      return r(`-- app + web + praxis (praxisNoEmail is a subset of praxis):
WITH counts AS (
  SELECT
    (SELECT COUNT(*)::int FROM app_user_appointment WHERE ${px} AND "createdAt" ${win}) AS app,
    (SELECT COUNT(*)::int FROM guest_appointment WHERE ${px} AND "createdAt" ${win} AND ("isBookedFromPraxis" IS NOT TRUE)) AS web,
    (SELECT COUNT(*)::int FROM guest_appointment WHERE ${px} AND "createdAt" ${win} AND "isBookedFromPraxis" = true) AS praxis
)
SELECT app, web, praxis, (app + web + praxis) AS total FROM counts;`);
    case 'tookPlaceApp':
      return r(`-- status NOT IN (5,6,7) excludes cancelled / noshow / enteredInError.
SELECT COUNT(*) FROM app_user_appointment WHERE ${px} AND "startTime" IS NOT NULL AND "startTime" ${win} AND status NOT IN (5, 6, 7);`);
    case 'tookPlaceWeb':
      return r(`-- status NOT IN (5,6,7) excludes cancelled / noshow / enteredInError.
SELECT COUNT(*) FROM guest_appointment WHERE ${px} AND "startTime" IS NOT NULL AND "startTime" ${win} AND ("isBookedFromPraxis" IS NOT TRUE) AND status NOT IN (5, 6, 7);`);
    case 'tookPlacePraxis':
      return r(`-- status NOT IN (5,6,7) excludes cancelled / noshow / enteredInError.
SELECT COUNT(*) FROM guest_appointment WHERE ${px} AND "startTime" IS NOT NULL AND "startTime" ${win} AND "isBookedFromPraxis" = true AND status NOT IN (5, 6, 7);`);
    case 'tookPlace':
      return r(`-- startTime within month, status NOT IN (5,6,7) excludes
-- cancelled / noshow / enteredInError. Combines app + web + praxis:
WITH counts AS (
  SELECT
    (SELECT COUNT(*)::int FROM app_user_appointment WHERE ${px} AND "startTime" IS NOT NULL AND "startTime" ${win} AND status NOT IN (5, 6, 7)) AS app,
    (SELECT COUNT(*)::int FROM guest_appointment WHERE ${px} AND "startTime" IS NOT NULL AND "startTime" ${win} AND ("isBookedFromPraxis" IS NOT TRUE) AND status NOT IN (5, 6, 7)) AS web,
    (SELECT COUNT(*)::int FROM guest_appointment WHERE ${px} AND "startTime" IS NOT NULL AND "startTime" ${win} AND "isBookedFromPraxis" = true AND status NOT IN (5, 6, 7)) AS praxis
)
SELECT app, web, praxis, (app + web + praxis) AS total FROM counts;`);
    case 'docReqApp':
      return r(`SELECT COUNT(*) FROM app_user_document_request WHERE ${px} AND "createdAt" ${win} AND "isFromWeb" = false;`);
    case 'docReqWeb':
      return r(`SELECT COUNT(*) FROM app_user_document_request WHERE ${px} AND "createdAt" ${win} AND "isFromWeb" = true;`);
    case 'npsSent':
      return r(`SELECT COUNT(*) FROM app_user_nps_sent WHERE ${px} AND "createdAt" ${win};`);
    case 'guestNps':
      // Recovery: raw fhir_nps minus :329 spurious writes (one per
      // praxis-booked guest_appointment in the same window).
      return r(`SELECT
  (SELECT COUNT(*)::int FROM fhir_nps WHERE ${px} AND "createdAt" ${win})
  - (SELECT COUNT(*)::int FROM guest_appointment WHERE ${px} AND "createdAt" ${win} AND "isBookedFromPraxis" = true)
  AS guest_nps_corrected;`);
    case 'newReg':
      return r(`SELECT COUNT(*) FROM app_user_info WHERE ${px} AND "createdAt" ${win};`);
    case 'verifiedReg':
      return r(`-- isVerified is the user's CURRENT state, not historical state at registration time.
SELECT COUNT(*) FROM app_user_info WHERE ${px} AND "createdAt" ${win} AND "isVerified" = true;`);
    case 'cancellations':
      return r(`-- EXISTS filter: only count cancellations from users who actually booked at this praxis.
SELECT COUNT(*)
FROM app_user_appointment_cancellation_reason c
JOIN app_user_info ui ON ui.id = c."userId"
WHERE ui."praxisId" = '${lcId}' AND c."createdAt" ${win}
  AND EXISTS (
    SELECT 1 FROM app_user_appointment a
    WHERE a."userId" = c."userId" AND a."praxisId" = '${lcId}'
  );`);
    case 'openCons':
      return r(`SELECT COUNT(*) FROM app_user_open_consultation WHERE ${px} AND "createdAt" ${win};`);
    case 'questionnaires':
      return r(`SELECT COUNT(*)
FROM app_user_questionnaire q
JOIN app_user_info ui ON ui.id = q."userInfoId"
WHERE ui."praxisId" = '${lcId}' AND q."answeredAt" ${win};`);
    default:
      return null;
  }
}

// Validation SQL builders. Each takes (lcId, startISO, endISO) and returns a
// standalone SQL statement matching the helper export's data-fetching logic.
// Used by the validator HTML's per-card copy buttons.
//
// When lcId is empty/null, builds the "all praxes" variant — same logic but
// scoped to "praxisId IS NOT NULL AND <> ''" (matches the export's praxes
// discovery filter, so totals should equal the report's top-summary cards).
function _validationSqlFor(metric, lcId, start, end) {
  const r = (s) => s.trim();
  const isAll = !lcId;
  // Direct praxisId-column tables: WHERE clause for praxis filter.
  // For all-praxes mode, scope to lcIds present in praxis_config — this matches
  // the report's targetPraxes set (the report excludes orphans whose praxisId
  // doesn't resolve to a known praxis_config row, so the SQL must too).
  const px      = isAll ? `"praxisId" IN (SELECT "lcId" FROM praxis_config WHERE "lcId" IS NOT NULL)`     : `"praxisId" = '${lcId}'`;
  const uiPx    = isAll ? `ui."praxisId" IN (SELECT "lcId" FROM praxis_config WHERE "lcId" IS NOT NULL)` : `ui."praxisId" = '${lcId}'`;
  const head    = isAll ? `-- Across ALL praxes — should match the report's top-summary card.\n-- Filter "praxisId IN (SELECT lcId FROM praxis_config)" excludes orphan rows\n-- whose praxisId doesn't match any known praxis (the report does the same).\n` : '';
  switch (metric) {
    case 'Total Patients':
      return r(`${head}SELECT COUNT(*) FROM app_user_info WHERE ${px};${isAll ? `\n\n-- Diagnostic: orphan users whose praxisId doesn't map to any praxis_config row.\n-- These are excluded from the report's totals. Expect a small/zero count.\n-- SELECT ui."praxisId", COUNT(*) AS user_count\n-- FROM app_user_info ui\n-- WHERE ui."praxisId" IS NOT NULL AND ui."praxisId" <> ''\n--   AND NOT EXISTS (SELECT 1 FROM praxis_config pc WHERE pc."lcId" = ui."praxisId")\n-- GROUP BY ui."praxisId"\n-- ORDER BY user_count DESC;` : ''}`);
    case 'Verified Patients':
      return r(`${head}SELECT COUNT(*) FROM app_user_info WHERE ${px} AND "isVerified" = true;`);
    case 'New Registrations':
      return r(`${head}SELECT COUNT(*) FROM app_user_info
WHERE ${px}
  AND "createdAt" BETWEEN '${start}' AND '${end}';`);
    case 'Verification Rate':
      return r(`${head}-- verification_rate_pct matches the report's KPI value.
SELECT
  COUNT(*) FILTER (WHERE "isVerified" = true) AS verified,
  COUNT(*) AS new_registrations,
  ROUND(100.0 * COUNT(*) FILTER (WHERE "isVerified" = true) / NULLIF(COUNT(*), 0), 1) AS verification_rate_pct
FROM app_user_info
WHERE ${px}
  AND "createdAt" BETWEEN '${start}' AND '${end}';`);
    case 'Total Appointments':
      return r(`${head}-- READ THIS BEFORE SUMMING:
--   app + web + praxis = total  (this is the KPI value)
--   "of_which_praxis_no_email" is a SUBSET of "praxis" — same rows, narrower
--   filter (praxis bookings where the patient had no email). Don't add it!
WITH counts AS (
  SELECT
    (SELECT COUNT(*)::int FROM app_user_appointment
       WHERE ${px} AND "createdAt" BETWEEN '${start}' AND '${end}') AS app,
    (SELECT COUNT(*)::int FROM guest_appointment
       WHERE ${px} AND "createdAt" BETWEEN '${start}' AND '${end}'
         AND ("isBookedFromPraxis" IS NOT TRUE)) AS web,
    (SELECT COUNT(*)::int FROM guest_appointment
       WHERE ${px} AND "createdAt" BETWEEN '${start}' AND '${end}'
         AND "isBookedFromPraxis" = true) AS praxis,
    (SELECT COUNT(*)::int FROM guest_appointment
       WHERE ${px} AND "createdAt" BETWEEN '${start}' AND '${end}'
         AND "isBookedFromPraxis" = true AND "hasEmail" = false) AS praxis_no_email
)
SELECT
  app,
  web,
  praxis,
  (app + web + praxis)                AS total,
  praxis_no_email                      AS of_which_praxis_no_email
FROM counts;`);
    case 'Took Place':
      return r(`${head}-- Total = app + web + praxis. startTime within window (column is text ISO).
-- status NOT IN (5, 6, 7) excludes cancelled / noshow / enteredInError
-- so cancelled rows in the past don't inflate this count. Other statuses
-- (booked / arrived / fulfilled / rescheduled / etc.) are kept.
WITH counts AS (
  SELECT
    (SELECT COUNT(*)::int FROM app_user_appointment
       WHERE ${px} AND "startTime" IS NOT NULL
         AND "startTime" BETWEEN '${start}' AND '${end}'
         AND status NOT IN (5, 6, 7)) AS app,
    (SELECT COUNT(*)::int FROM guest_appointment
       WHERE ${px} AND "startTime" IS NOT NULL
         AND "startTime" BETWEEN '${start}' AND '${end}'
         AND ("isBookedFromPraxis" IS NOT TRUE)
         AND status NOT IN (5, 6, 7)) AS web,
    (SELECT COUNT(*)::int FROM guest_appointment
       WHERE ${px} AND "startTime" IS NOT NULL
         AND "startTime" BETWEEN '${start}' AND '${end}'
         AND "isBookedFromPraxis" = true
         AND status NOT IN (5, 6, 7)) AS praxis
)
SELECT app, web, praxis, (app + web + praxis) AS total FROM counts;`);
    case 'NPS Sent':
      return r(`${head}-- Total = app NPS + corrected guest NPS.
-- guest_nps corrected = raw fhir_nps minus the spurious writes from
-- handleNewAppointment :329 (one per praxis-booked guest_appointment in
-- the same window). The :329 site does NOT actually trigger an NPS email;
-- only the :422 site in handleUnknownBooking does.
WITH counts AS (
  SELECT
    (SELECT COUNT(*)::int FROM app_user_nps_sent
       WHERE ${px} AND "createdAt" BETWEEN '${start}' AND '${end}') AS app_nps,
    (SELECT COUNT(*)::int FROM fhir_nps
       WHERE ${px} AND "createdAt" BETWEEN '${start}' AND '${end}') AS guest_nps_raw,
    (SELECT COUNT(*)::int FROM guest_appointment
       WHERE ${px} AND "createdAt" BETWEEN '${start}' AND '${end}'
         AND "isBookedFromPraxis" = true) AS guest_nps_spurious
)
SELECT
  app_nps,
  guest_nps_raw,
  guest_nps_spurious,
  GREATEST(0, guest_nps_raw - guest_nps_spurious) AS guest_nps_corrected,
  (app_nps + GREATEST(0, guest_nps_raw - guest_nps_spurious)) AS total
FROM counts;`);
    case 'Guest NPS':
      return r(`${head}-- Corrected guest NPS = raw fhir_nps minus :329 spurious writes
-- (one per praxis-booked guest_appointment in the same window).
-- :329 writes a fhir_nps row but never triggers an NPS email — only the
-- :422 site in handleUnknownBooking actually sends one.
WITH counts AS (
  SELECT
    (SELECT COUNT(*)::int FROM fhir_nps
       WHERE ${px} AND "createdAt" BETWEEN '${start}' AND '${end}') AS raw_fhir_nps,
    (SELECT COUNT(*)::int FROM guest_appointment
       WHERE ${px} AND "createdAt" BETWEEN '${start}' AND '${end}'
         AND "isBookedFromPraxis" = true) AS spurious_writes
)
SELECT
  raw_fhir_nps,
  spurious_writes,
  GREATEST(0, raw_fhir_nps - spurious_writes) AS guest_nps_corrected
FROM counts;`);
    case 'Guest NPS · no email':
      return r(`${head}-- Corrected guest NPS where the recipient had no email.
-- Both sides of the subtraction are filtered to hasEmail = false because
-- the :329 site copies userInfo.email.isNotEmpty into BOTH the fhir_nps
-- row and the paired guest_appointment row.
WITH counts AS (
  SELECT
    (SELECT COUNT(*)::int FROM fhir_nps
       WHERE ${px} AND "createdAt" BETWEEN '${start}' AND '${end}'
         AND "hasEmail" = false) AS raw_no_email,
    (SELECT COUNT(*)::int FROM guest_appointment
       WHERE ${px} AND "createdAt" BETWEEN '${start}' AND '${end}'
         AND "isBookedFromPraxis" = true AND "hasEmail" = false) AS spurious_no_email
)
SELECT
  raw_no_email,
  spurious_no_email,
  GREATEST(0, raw_no_email - spurious_no_email) AS guest_nps_no_email_corrected
FROM counts;`);
    case 'NPS Coverage':
      return r(`${head}-- coverage_pct = (app_nps + corrected_guest_nps) / (appointments + doc_requests + open_consultations) * 100
-- 30-day per-user dedup at the backend means <100% is normal even if every event would otherwise trigger a send.
-- Guest NPS here is the corrected count (raw fhir_nps minus :329 spurious writes).
WITH counts AS (
  SELECT
    ((SELECT COUNT(*)::int FROM app_user_nps_sent WHERE ${px} AND "createdAt" BETWEEN '${start}' AND '${end}')
     + GREATEST(0,
         (SELECT COUNT(*)::int FROM fhir_nps WHERE ${px} AND "createdAt" BETWEEN '${start}' AND '${end}')
         - (SELECT COUNT(*)::int FROM guest_appointment WHERE ${px} AND "createdAt" BETWEEN '${start}' AND '${end}' AND "isBookedFromPraxis" = true)
       )) AS nps_sent,
    ((SELECT COUNT(*)::int FROM app_user_appointment WHERE ${px} AND "createdAt" BETWEEN '${start}' AND '${end}')
     + (SELECT COUNT(*)::int FROM guest_appointment WHERE ${px} AND "createdAt" BETWEEN '${start}' AND '${end}')
     + (SELECT COUNT(*)::int FROM app_user_document_request WHERE ${px} AND "createdAt" BETWEEN '${start}' AND '${end}')
     + (SELECT COUNT(*)::int FROM app_user_open_consultation WHERE ${px} AND "createdAt" BETWEEN '${start}' AND '${end}')) AS eligible_events
)
SELECT
  nps_sent,
  eligible_events,
  ROUND(100.0 * nps_sent / NULLIF(eligible_events, 0), 1) AS coverage_pct
FROM counts;`);
    case 'Doc Requests':
      return r(`${head}-- "total" matches the report's KPI value.
SELECT
  COUNT(*) FILTER (WHERE "isFromWeb" = false) AS from_app,
  COUNT(*) FILTER (WHERE "isFromWeb" = true)  AS from_web,
  COUNT(*) FILTER (WHERE "isFromWeb" IS NULL) AS unknown,
  COUNT(*) AS total
FROM app_user_document_request
WHERE ${px} AND "createdAt" BETWEEN '${start}' AND '${end}';`);
    case 'Open Consultations':
      return r(`${head}SELECT COUNT(*) FROM app_user_open_consultation
WHERE ${px} AND "createdAt" BETWEEN '${start}' AND '${end}';`);
    case 'Cancellations':
      return r(`${head}-- cancellation_reason has NO praxisId/appointmentId. Attributed via user
-- registration AND filtered to users who actually booked here (EXISTS clause)
-- to avoid attributing cancellations from users who booked at other praxes.
-- Cancellations excluded by this filter are counted globally as "Unattributed
-- Cancellations" in the report.
SELECT COUNT(*)
FROM app_user_appointment_cancellation_reason c
JOIN app_user_info ui ON ui.id = c."userId"
WHERE ${uiPx}
  AND c."createdAt" BETWEEN '${start}' AND '${end}'
  AND EXISTS (
    SELECT 1 FROM app_user_appointment a
    WHERE a."userId" = c."userId"
      ${isAll ? `AND a."praxisId" = ui."praxisId"` : `AND a."praxisId" = '${lcId}'`}
  );`);
    case 'Unattributed Cancellations':
      return r(`-- Cancellations whose user is registered at some praxis but has NO appointment
-- at that praxis. The cancelled appointment was at another praxis (which we
-- can't determine from the schema — cancellation_reason has no appointmentId).
SELECT COUNT(*)
FROM app_user_appointment_cancellation_reason c
JOIN app_user_info ui ON ui.id = c."userId"
WHERE c."createdAt" BETWEEN '${start}' AND '${end}'
  AND ui."praxisId" IS NOT NULL AND ui."praxisId" <> ''
  AND NOT EXISTS (
    SELECT 1 FROM app_user_appointment a
    WHERE a."userId" = c."userId" AND a."praxisId" = ui."praxisId"
  );

-- Breakdown: how many unattributed cancellations per registered praxis.
SELECT ui."praxisId" AS user_registered_praxis, COUNT(*) AS unattributed_cancellations
FROM app_user_appointment_cancellation_reason c
JOIN app_user_info ui ON ui.id = c."userId"
WHERE c."createdAt" BETWEEN '${start}' AND '${end}'
  AND ui."praxisId" IS NOT NULL AND ui."praxisId" <> ''
  AND NOT EXISTS (
    SELECT 1 FROM app_user_appointment a
    WHERE a."userId" = c."userId" AND a."praxisId" = ui."praxisId"
  )
GROUP BY ui."praxisId"
ORDER BY unattributed_cancellations DESC;`);
    case 'Cancellation Rate':
      return r(`${head}-- cancellation_rate_pct = cancellations / total_appointments × 100.
-- Numerator uses the same EXISTS filter as the Cancellations metric — only
-- cancellations from users who actually booked at this praxis are counted.
WITH counts AS (
  SELECT
    (SELECT COUNT(*)::int FROM app_user_appointment_cancellation_reason c
     JOIN app_user_info ui ON ui.id = c."userId"
     WHERE ${uiPx} AND c."createdAt" BETWEEN '${start}' AND '${end}'
       AND EXISTS (
         SELECT 1 FROM app_user_appointment a
         WHERE a."userId" = c."userId"
           ${isAll ? `AND a."praxisId" = ui."praxisId"` : `AND a."praxisId" = '${lcId}'`}
       )) AS cancellations,
    ((SELECT COUNT(*)::int FROM app_user_appointment WHERE ${px} AND "createdAt" BETWEEN '${start}' AND '${end}')
     + (SELECT COUNT(*)::int FROM guest_appointment WHERE ${px} AND "createdAt" BETWEEN '${start}' AND '${end}')) AS total_appointments
)
SELECT
  cancellations,
  total_appointments,
  ROUND(100.0 * cancellations / NULLIF(total_appointments, 0), 1) AS cancellation_rate_pct
FROM counts;`);
    case 'Questionnaires':
      return r(`${head}-- questionnaire has no praxisId; JOIN through userInfoId → app_user_info.praxisId:
SELECT COUNT(*)
FROM app_user_questionnaire q
JOIN app_user_info ui ON ui.id = q."userInfoId"
WHERE ${uiPx}
  AND q."answeredAt" BETWEEN '${start}' AND '${end}';`);
    case 'PMS Downtime Events':
      return r(`-- analytics_pms_downtime is platform-wide (no praxisId column):
SELECT COUNT(*) FROM analytics_pms_downtime
WHERE "createdAt" BETWEEN '${start}' AND '${end}';`);
    case 'PMS Downtime (sec)':
      return r(`-- Cast totalDownTimeInSeconds explicitly: it's bigint, not int:
SELECT COALESCE(SUM("totalDownTimeInSeconds"), 0)::bigint AS total_seconds
FROM analytics_pms_downtime
WHERE "createdAt" BETWEEN '${start}' AND '${end}';`);
    case 'PMS Downtime (min)':
      return r(`-- Match the HTML's Math.round behaviour (round half-up, not truncate).
-- Plain integer division ("...::bigint / 60") would truncate 480.5 → 480 and
-- disagree with the report's rounded minute count by 1.
SELECT ROUND(COALESCE(SUM("totalDownTimeInSeconds"), 0) / 60.0)::int AS total_minutes,
       COALESCE(SUM("totalDownTimeInSeconds"), 0)::bigint AS total_seconds
FROM analytics_pms_downtime
WHERE "createdAt" BETWEEN '${start}' AND '${end}';`);
    case 'Account Deletions (total)':
      return r(`-- Schema has no praxisId — global count of unique deletion records:
SELECT COUNT(*) FROM app_user_deletion_feedback
WHERE "createdAt" BETWEEN '${start}' AND '${end}';`);
    case 'Reasons Selected (total)':
      return r(`-- reason is a List<String>; this counts the total reason
-- occurrences (one row may contribute multiple). Will be >= Account Deletions:
SELECT COALESCE(SUM(jsonb_array_length(reason::jsonb)), 0) AS reasons_selected
FROM app_user_deletion_feedback
WHERE "createdAt" BETWEEN '${start}' AND '${end}';`);
    default:
      return null;
  }
}

function _htmlFromPayload(payload, opts = {}) {
  const withCopySql = !!opts.withCopySql;
  const fmt = (n) => Number.isFinite(n) ? n.toLocaleString('en-US') : '0';
  const fmtPct = (n) => Number.isFinite(n) ? `${n.toFixed(1)}%` : '0%';
  // For ratios where denominator may legitimately be 0 (e.g. cancellation
  // rate when there are no appointments), show "—" instead of "0.0%" which
  // would imply "the rate is zero" rather than "the rate is undefined".
  const fmtPctOrDash = (n, denom) => (denom > 0 && Number.isFinite(n)) ? `${n.toFixed(1)}%` : '—';
  const esc = (s) => String(s ?? '').replace(/[&<>"']/g, c => ({ '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;' }[c]));

  // Metric explanations — shown both as hover tooltips on each KPI card and
  // in a glossary section at the top. Keep concise; include any non-obvious
  // gotchas (lifetime vs window, dedup behaviour, etc).
  const HELP = {
    'Total Patients':            'All-time count of patients registered with this praxis. NOT filtered by the report date range.',
    'Verified Patients':         'All-time count of patients with verified identity status (current state, not historical).',
    'Total Appointments':        'Appointments booked in the report window. Sum of: app + web + praxis. (praxisWithoutEmail is a subset of praxis, not added separately.)',
    'Took Place':                'Appointments whose startTime fell within the report window AND were not cancelled/noshow/enteredInError. Independent of when they were booked.',
    'NPS Sent':                  'Total NPS surveys sent: app users (app_user_nps_sent) + corrected guest NPS (see Guest NPS for the correction).',
    'NPS Coverage':              'Sent / NPS-eligible events × 100. Eligible = appointments + document requests + open consultations (backend triggers NPS after each). Uses the corrected Guest NPS numerator. Capped by 30-day per-user dedup, so <100% is normal.',
    'Doc Requests':              'Document requests created in the window. Split by source: from app vs web (vs unknown source).',
    'Open Consultations':        'Open-consultation requests created in the window.',
    'New Registrations':         'Patients whose app_user_info row was created within the window. Subset of Total Patients.',
    'Verification Rate':         'New verified / new registrations × 100. Note: isVerified is the current state — a registration counted as "verified" may have verified later.',
    'Cancellations':             'cancellation_reason has no praxisId/appointmentId. Filtered to cancellations where the same user has at least one appointment at THIS praxis (EXISTS clause). Cancellations excluded by this filter — user registered here but cancelled an appointment at another praxis — are counted globally as "Unattributed Cancellations".',
    'Cancellation Rate':         'Cancellations / Total Appointments × 100. Shown as "—" when there are no appointments (rate is undefined).',
    'Unattributed Cancellations': 'Global metric. Cancellations whose user is registered at some praxis but has NO appointment at that praxis — meaning the cancelled appointment was at a different praxis (schema doesn\'t expose which one). Sum of these + sum of per-praxis Cancellations = total cancellations in the window.',
    'Questionnaires':            'Questionnaires answered within the window, scoped to this praxis (via JOIN through user → praxisId).',
    'PMS Downtime Events':       'Number of PMS downtime incident records logged platform-wide in the window. Not per-praxis (PMS is the shared connector).',
    'PMS Downtime (sec)':        'Sum of totalDownTimeInSeconds across all incidents in the window. Platform-wide.',
    'PMS Downtime (min)':        'PMS Downtime seconds / 60. Platform-wide.',
    'Account Deletions (total)': 'Number of unique account deletions in the window (= row count of app_user_deletion_feedback). Schema has no praxisId — counted globally only.',
    'Reasons Selected (total)':  'Sum of reason occurrences across all deletions. Each user can pick multiple reasons (reason is List<String>), so this is ≥ Account Deletions (total).',
    'Guest NPS':                 'Real NPS attempts to guest/non-app users — recovered as: (raw fhir_nps rows) − (guest_appointment rows with isBookedFromPraxis=true in the same window). The backend writes an fhir_nps row at handleNewAppointment :329 every time a praxis-booked appointment is registered (booked/rescheduled/cancelled), but that path does NOT send an NPS email. Only handleUnknownBooking :422 (status=fulfilled) calls scheduleGuestNPS and triggers Brevo. Subtracting :329 writes — uniquely identified by their paired isBookedFromPraxis=true guest_appointment row — gives the count of actual :422 attempts.',
    'Guest NPS · no email':      'Subset of corrected Guest NPS where the guest had no email captured. Same recovery formula but restricted to hasEmail=false on both sides.',
  };
  const tip = (label) => HELP[label] ? `title="${esc(HELP[label])}"` : '';
  // Metrics whose validation SQL has no praxisId concept at all (platform-wide
  // tables). For everything else, a missing lcId means "all praxes" — the SQL
  // builder generates the cross-praxis variant.
  const GLOBAL_METRICS = new Set([
    'PMS Downtime Events', 'PMS Downtime (sec)', 'PMS Downtime (min)',
    'Account Deletions (total)', 'Reasons Selected (total)',
    'Unattributed Cancellations',
  ]);
  const copyBtn = (label, lcId, allPraxes) => {
    if (!withCopySql) return '';
    if (!lcId && !allPraxes && !GLOBAL_METRICS.has(label)) return '';
    const sql = _validationSqlFor(label, lcId || '', payload.dataStart, payload.dataEnd);
    if (!sql) return '';
    const title = allPraxes
      ? 'Copy SQL — across all praxes (matches this top-summary value)'
      : 'Copy validation SQL to clipboard';
    return `<button class="copy-btn" data-sql="${esc(sql)}" onclick="copySQL(this)" title="${esc(title)}">📋</button>`;
  };
  const kpi = (label, val, opts = {}) => {
    const { lcId, allPraxes = false, suffix = '' } = opts;
    return `<div class="kpi" ${tip(label)}>${copyBtn(label, lcId, allPraxes)}<div class="kpi-label">${esc(label)}</div><div class="kpi-val">${esc(fmt(val))}${suffix}</div></div>`;
  };
  const kpiPct = (label, val, opts = {}) => {
    const { lcId, allPraxes = false, denom } = opts;
    const display = (denom !== undefined) ? fmtPctOrDash(val, denom) : fmtPct(val);
    return `<div class="kpi" ${tip(label)}>${copyBtn(label, lcId, allPraxes)}<div class="kpi-label">${esc(label)}</div><div class="kpi-val">${esc(display)}</div></div>`;
  };

  const monthlyTableHeader = `
    <tr>
      <th>Month</th>
      <th>Booked App</th><th>Booked Web</th><th>Booked Praxis</th><th>Booked Praxis (no email)</th><th>Total Booked</th>
      <th>Took Place</th><th>Took Place App</th><th>Took Place Web</th><th>Took Place Praxis</th>
      <th>Doc Req App</th><th>Doc Req Web</th>
      <th>NPS Sent</th><th>Guest NPS</th>
      <th>New Reg</th><th>Verified Reg</th>
      <th>Cancellations</th><th>Open Cons</th><th>Questionnaires</th>
    </tr>`;

  const renderPraxis = (p) => {
    const t = p.totals;
    // Cell renderer: when validator mode is on, each numeric cell becomes
    // clickable and copies a single-COUNT SQL scoped to (this praxis, this
    // month, this column).
    const mc = (column, value, monthStr, bold = false) => {
      const inner = bold ? `<strong>${fmt(value)}</strong>` : fmt(value);
      if (!withCopySql) return `<td>${inner}</td>`;
      const { start, end } = _monthRange(monthStr);
      const sql = _monthCellSql(column, p.lcId, start, end);
      if (!sql) return `<td>${inner}</td>`;
      return `<td class="clickable-cell" data-sql="${esc(sql)}" onclick="copySQL(this)" title="Click to copy SQL — ${esc(p.lcId)} · ${esc(monthStr)} · ${esc(column)}">${inner}</td>`;
    };
    const monthlyRows = payload.monthsCovered.map(month => {
      const m = p.monthly[month] || _emptyMonthlyKpi();
      return `<tr>
        <td class="mono">${esc(month)}</td>
        ${mc('app', m.appointmentsBookedFromApp, month)}
        ${mc('web', m.appointmentsBookedFromWeb, month)}
        ${mc('praxis', m.appointmentsBookedFromPraxis, month)}
        ${mc('praxisNoEmail', m.appointmentsBookedFromPraxisWithoutEmail, month)}
        ${mc('totalBooked', m.totalAppointments, month, true)}
        ${mc('tookPlace', m.totalAppointmentsTookPlace, month)}
        ${mc('tookPlaceApp', m.appointmentsTookPlaceFromApp, month)}
        ${mc('tookPlaceWeb', m.appointmentsTookPlaceFromWeb, month)}
        ${mc('tookPlacePraxis', m.appointmentsTookPlaceFromPraxis, month)}
        ${mc('docReqApp', m.documentRequestFromApp, month)}
        ${mc('docReqWeb', m.documentRequestFromWeb, month)}
        ${mc('npsSent', m.npsEmailsSent, month)}
        ${mc('guestNps', m.guestNPS, month)}
        ${mc('newReg', m.newRegistrations, month)}
        ${mc('verifiedReg', m.newVerifiedRegistrations, month)}
        ${mc('cancellations', m.cancellations, month)}
        ${mc('openCons', m.openConsultations, month)}
        ${mc('questionnaires', m.questionnairesCompleted, month)}
      </tr>`;
    }).join('');

    const catRows = (p.appointmentCategories.length ? p.appointmentCategories : [{ category: '—', count: 0 }])
      .map(c => `<tr><td>${esc(c.category)}</td><td>${fmt(c.count)}</td></tr>`).join('');
    const cancelRows = (p.cancellationReasons.length ? p.cancellationReasons : [{ category: '—', count: 0 }])
      .map(c => `<tr><td>${esc(c.category)}</td><td>${fmt(c.count)}</td></tr>`).join('');

    const dbg = p._debug;
    const sanityFail = dbg && (!dbg.invariants.totalAppointmentsMatchesSum || !dbg.invariants.totalAppointmentsTookPlaceMatchesSum || !dbg.invariants.praxisNoEmailLessOrEqualPraxis);
    const dbgBadge = sanityFail
      ? `<div style="background:#fee2e2;border:1px solid #ef4444;color:#7f1d1d;padding:8px 12px;border-radius:6px;margin:8px 0;font-size:12px"><strong>Sanity check FAILED</strong> — see _debug in JSON. Raw row counts: ${esc(JSON.stringify(dbg.rowCounts))}</div>`
      : (dbg ? `<div class="muted" style="font-size:11px;margin:6px 0">DB rows fetched: appAppts=${dbg.rowCounts.appAppts} webAppts=${dbg.rowCounts.webAppts} appTook=${dbg.rowCounts.appAppointmentsTookPlace} guestTook=${dbg.rowCounts.guestAppointmentsTookPlace} cancellations=${dbg.rowCounts.cancellations} questionnaires=${dbg.rowCounts.questionnaires}</div>` : '');
    return `
      <section class="praxis" id="${esc(p.lcId)}">
        <h2>${esc(p.name || p.lcId)} <span class="muted">(${esc(p.lcId)}${p.bundesland ? ` · ${esc(p.bundesland.toUpperCase())}` : ''})</span></h2>
        ${dbgBadge}
        <h3>Totals (${esc(payload.dataStart.slice(0,10))} → ${esc(payload.dataEnd.slice(0,10))})</h3>
        <div class="kpi-grid">
          ${kpi('Total Patients', t.totalPatients, { lcId: p.lcId })}
          ${kpi('Verified Patients', t.totalVerifiedPatients, { lcId: p.lcId })}
          ${kpi('Total Appointments', t.totalAppointments, { lcId: p.lcId })}
          ${kpi('Took Place', t.totalAppointmentsTookPlace, { lcId: p.lcId })}
          ${kpi('NPS Sent', t.totalNPSSent, { lcId: p.lcId })}
          ${kpiPct('NPS Coverage', t.npsCoveragePercentage, { lcId: p.lcId, denom: t.totalNpsEligibleEvents })}
          ${kpi('Doc Requests', t.totalDocumentRequests, { lcId: p.lcId })}
          ${kpi('Open Consultations', t.openConsultations, { lcId: p.lcId })}
          ${kpi('New Registrations', t.newRegistrations, { lcId: p.lcId })}
          ${kpiPct('Verification Rate', t.verificationRate, { lcId: p.lcId, denom: t.newRegistrations })}
          ${kpi('Cancellations', t.cancellations, { lcId: p.lcId })}
          ${kpiPct('Cancellation Rate', t.cancellationRate, { lcId: p.lcId, denom: t.totalAppointments })}
          ${kpi('Questionnaires', t.questionnairesCompleted, { lcId: p.lcId })}
        </div>

        <h3>Monthly Breakdown</h3>
        <div class="scroll"><table class="data">${monthlyTableHeader}${monthlyRows}</table></div>

        <div class="two-col">
          <div>
            <h3>Top Appointment Categories</h3>
            <table class="data narrow"><tr><th>Category</th><th>Count</th></tr>${catRows}</table>
          </div>
          <div>
            <h3>Top Cancellation Reasons</h3>
            <table class="data narrow"><tr><th>Reason</th><th>Count</th></tr>${cancelRows}</table>
          </div>
        </div>
      </section>`;
  };

  const summary = payload.praxes.reduce((acc, p) => {
    acc.totalAppointments += p.totals.totalAppointments;
    acc.totalAppointmentsTookPlace += p.totals.totalAppointmentsTookPlace;
    acc.totalNPSSent += p.totals.totalNPSSent;
    acc.totalDocumentRequests += p.totals.totalDocumentRequests;
    acc.totalCancellations += p.totals.cancellations;
    acc.openConsultations += p.totals.openConsultations;
    acc.newRegistrations += p.totals.newRegistrations;
    acc.totalPatients += p.totals.totalPatients;
    acc.totalVerifiedPatients += p.totals.totalVerifiedPatients;
    return acc;
  }, { totalAppointments: 0, totalAppointmentsTookPlace: 0, totalNPSSent: 0, totalDocumentRequests: 0, totalCancellations: 0, openConsultations: 0, newRegistrations: 0, totalPatients: 0, totalVerifiedPatients: 0 });

  const tocRows = payload.praxes.map(p =>
    `<li><a href="#${esc(p.lcId)}">${esc(p.name || p.lcId)} <span class="muted">(${esc(p.lcId)})</span></a> — ${fmt(p.totals.totalAppointments)} bookings</li>`
  ).join('');

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>LillianCare — Historical Analytics (${esc(payload.dataStart.slice(0,10))} → ${esc(payload.dataEnd.slice(0,10))})</title>
<style>
  :root { color-scheme: light dark; }
  * { box-sizing: border-box; }
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; margin: 0; padding: 24px; background: #fafaf9; color: #1a1a1a; }
  h1 { margin: 0 0 4px; font-size: 28px; }
  h2 { margin: 32px 0 12px; padding-bottom: 8px; border-bottom: 2px solid #e5e7eb; font-size: 22px; }
  h3 { margin: 20px 0 10px; font-size: 14px; text-transform: uppercase; letter-spacing: 0.05em; color: #555; }
  .muted { color: #888; font-weight: normal; font-size: 0.85em; }
  .header { background: white; padding: 20px 24px; border-radius: 12px; box-shadow: 0 1px 3px rgba(0,0,0,0.08); margin-bottom: 20px; }
  .global-kpis { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 12px; margin-top: 16px; }
  .kpi-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 10px; }
  .kpi { background: white; padding: 10px 12px; border-radius: 8px; border: 1px solid #e5e7eb; position: relative; }
  .kpi-label { font-size: 11px; text-transform: uppercase; letter-spacing: 0.04em; color: #666; }
  .kpi-val { font-size: 20px; font-weight: 600; margin-top: 2px; }
  .copy-btn { position: absolute; top: 6px; right: 6px; background: #f3f4f6; border: 1px solid #e5e7eb; border-radius: 4px; padding: 2px 6px; cursor: pointer; font-size: 12px; line-height: 1; transition: background 0.15s; }
  .copy-btn:hover { background: #e0e7ff; border-color: #6366f1; }
  .copy-btn.copied { background: #16a34a; color: white; border-color: #16a34a; }
  .clickable-cell { cursor: copy; transition: background 0.15s, color 0.15s; }
  .clickable-cell:hover { background: #e0e7ff !important; color: #1e40af; }
  .clickable-cell.cell-copied { background: #16a34a !important; color: white !important; transition: none; }
  #copy-toast { position: fixed; bottom: 24px; right: 24px; background: #16a34a; color: white; padding: 10px 16px; border-radius: 8px; font-size: 14px; opacity: 0; transition: opacity 0.2s; pointer-events: none; z-index: 1000; box-shadow: 0 4px 12px rgba(0,0,0,0.15); }
  #copy-toast.show { opacity: 1; }
  .validator-banner { background: #fef3c7; border: 1px solid #f59e0b; color: #78350f; padding: 12px 16px; border-radius: 8px; margin-bottom: 16px; font-size: 14px; }
  .praxis { background: white; padding: 20px 24px; border-radius: 12px; margin-bottom: 16px; box-shadow: 0 1px 2px rgba(0,0,0,0.04); }
  table.data { border-collapse: collapse; width: 100%; font-size: 12px; }
  table.data th, table.data td { padding: 6px 8px; border-bottom: 1px solid #eee; text-align: right; white-space: nowrap; }
  table.data th { background: #f3f4f6; font-weight: 600; text-align: right; position: sticky; top: 0; }
  table.data td:first-child, table.data th:first-child { text-align: left; }
  table.data.narrow th, table.data.narrow td { text-align: left; }
  table.data.narrow td:last-child, table.data.narrow th:last-child { text-align: right; }
  .scroll { overflow-x: auto; max-height: 420px; overflow-y: auto; border: 1px solid #e5e7eb; border-radius: 6px; }
  .two-col { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-top: 16px; }
  @media (max-width: 700px) { .two-col { grid-template-columns: 1fr; } }
  .mono { font-family: "SF Mono", Menlo, Consolas, monospace; }
  ul.toc { columns: 2; margin: 0; padding-left: 20px; font-size: 13px; }
  ul.toc li { break-inside: avoid; margin: 2px 0; }
  ul.toc a { color: #1d4ed8; text-decoration: none; }
  ul.toc a:hover { text-decoration: underline; }
  @media print { body { background: white; } .praxis { break-inside: avoid; box-shadow: none; border: 1px solid #ddd; } }
</style>
</head>
<body>
  ${withCopySql ? `<div class="validator-banner"><strong>Validator mode:</strong> click the 📋 button on any KPI card, or click any numeric cell in a monthly breakdown table, to copy a standalone SQL query that produces that number.</div>` : ''}
  <div class="header">
    <h1>LillianCare — Historical Analytics${withCopySql ? ' <span style="font-size:14px;color:#f59e0b;font-weight:normal">(validator)</span>' : ''}</h1>
    <div class="muted">${esc(payload.dataStart.slice(0,10))} → ${esc(payload.dataEnd.slice(0,10))} · ${payload.praxes.length} praxes · ${payload.monthsCovered.length} months · generated ${esc(payload.generatedAt)}</div>
    <div class="global-kpis">
      ${kpi('Total Appointments', summary.totalAppointments, { allPraxes: true })}
      ${kpi('Took Place', summary.totalAppointmentsTookPlace, { allPraxes: true })}
      ${kpi('NPS Sent', summary.totalNPSSent, { allPraxes: true })}
      ${kpi('Doc Requests', summary.totalDocumentRequests, { allPraxes: true })}
      ${kpi('Cancellations', summary.totalCancellations, { allPraxes: true })}
      ${kpi('Open Consultations', summary.openConsultations, { allPraxes: true })}
      ${kpi('Total Patients', summary.totalPatients, { allPraxes: true })}
      ${kpi('Verified Patients', summary.totalVerifiedPatients, { allPraxes: true })}
    </div>
    <h3>Praxes</h3>
    <ul class="toc">${tocRows}</ul>
  </div>

  <details class="praxis" id="__glossary__" style="border-left: 4px solid #f59e0b;">
    <summary style="cursor: pointer; list-style: none; font-size: 18px; font-weight: 600;">📖 Glossary — what each metric means <span class="muted" style="font-weight: normal; font-size: 14px;">(click to expand)</span></summary>
    <div style="margin-top: 16px;">
      <table class="data narrow" style="font-size: 13px;">
        <tr><th style="width: 220px;">Metric</th><th>Meaning</th></tr>
        ${Object.entries(HELP).map(([label, desc]) => `<tr><td><strong>${esc(label)}</strong></td><td style="white-space: normal;">${esc(desc)}</td></tr>`).join('')}
      </table>
      <div class="muted" style="margin-top: 12px; font-size: 12px;">
        Hover any KPI card below to see its definition as a tooltip.
        <br>NPS triggers: backend sends an NPS email after appointments, document requests, and open consultations — gated to once per 30 days per user (configurable via <code>CorePraxisInfoMarketingConfig.npsFrequencyDays</code>).
      </div>
    </div>
  </details>

  <section class="praxis" id="__global__" style="border-left: 4px solid #6366f1;">
    <h2>Global / Platform-wide <span class="muted">(no praxisId in schema — applies to all)</span></h2>
    <h3>System metrics</h3>
    <div class="kpi-grid">
      ${(() => {
        const totalSec = payload.pmsDowntimes.reduce((s, d) => s + Number(d.totalDownTimeInSeconds || 0), 0);
        return kpi('PMS Downtime Events', payload.pmsDowntimes.length) +
               kpi('PMS Downtime (sec)', totalSec) +
               kpi('PMS Downtime (min)', Math.round(totalSec / 60));
      })()}
      ${kpi('Account Deletions (total)', payload.totalDeletions || 0)}
      ${kpi('Reasons Selected (total)', payload.deletionReasons.reduce((s, r) => s + Number(r.count || 0), 0))}
      ${kpi('Unattributed Cancellations', payload.unattributedCancellations?.total || 0)}
    </div>

    <div class="two-col">
      <div>
        <h3>PMS Downtime Events</h3>
        ${payload.pmsDowntimes.length === 0
          ? `<div class="muted" style="font-size:13px">No PMS downtime in this range.</div>`
          : `<div class="scroll" style="max-height:280px"><table class="data narrow">
              <tr><th>When</th><th>Duration (sec)</th></tr>
              ${payload.pmsDowntimes.map(d => `<tr><td class="mono">${esc(String(d.createdAt).slice(0,19))}</td><td>${fmt(Number(d.totalDownTimeInSeconds || 0))}</td></tr>`).join('')}
            </table></div>`}
      </div>
      <div>
        <h3>Top Deletion Reasons</h3>
        ${payload.deletionReasons.length === 0
          ? `<div class="muted" style="font-size:13px">No account deletions in this range.</div>`
          : `<table class="data narrow"><tr><th>Reason</th><th>Count</th></tr>${payload.deletionReasons.map(r => `<tr><td>${esc(r.reason)}</td><td>${fmt(r.count)}</td></tr>`).join('')}</table>`}
      </div>
    </div>

    ${(payload.unattributedCancellations?.total || 0) > 0 ? `
    <h3 style="margin-top: 24px;">Unattributed Cancellations — by user-registered praxis</h3>
    <div class="muted" style="font-size: 12px; margin-bottom: 8px;">
      These cancellations come from users registered at the listed praxis, but the user has NO appointment at that praxis — so the cancelled appointment was at a different praxis.
      Schema doesn't expose which one.
    </div>
    <table class="data narrow">
      <tr><th>User registered at</th><th>Cancellations</th></tr>
      ${payload.unattributedCancellations.byUserRegisteredPraxis.map(r => `<tr><td class="mono">${esc(r.lcId)}</td><td>${fmt(r.count)}</td></tr>`).join('')}
    </table>
    ` : ''}
  </section>

  ${payload.praxes.map(renderPraxis).join('\n')}
  <div id="copy-toast"></div>
  <script>
    window.__DATA__ = ${JSON.stringify(payload).replace(/</g, '\\u003c')};
    function copySQL(el) {
      const sql = el.getAttribute('data-sql');
      if (!sql) return;
      const isCell = el.tagName === 'TD';
      const done = () => {
        if (isCell) {
          el.classList.add('cell-copied');
          setTimeout(() => el.classList.remove('cell-copied'), 900);
        } else {
          el.classList.add('copied');
          const orig = el.textContent;
          el.textContent = '✓';
          setTimeout(() => { el.classList.remove('copied'); el.textContent = orig; }, 1500);
        }
        const toast = document.getElementById('copy-toast');
        toast.textContent = isCell ? 'Cell SQL copied' : 'SQL copied — paste into your DB client to verify';
        toast.classList.add('show');
        setTimeout(() => { toast.classList.remove('show'); }, 2000);
      };
      const fallback = () => {
        const ta = document.createElement('textarea');
        ta.value = sql; ta.style.position = 'fixed'; ta.style.opacity = '0';
        document.body.appendChild(ta); ta.select();
        try { document.execCommand('copy'); done(); } catch (e) { alert('Copy failed: ' + e.message); }
        document.body.removeChild(ta);
      };
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(sql).then(done).catch(fallback);
      } else {
        fallback();
      }
    }
  </script>
</body>
</html>`;
}

router.get('/api/analytics/export-historical', async (req, res) => {
  try {
    const fs = require('fs');
    const path = require('path');

    const endDateStr = (req.query.endDate || '2026-04-30').toString();
    const endDate = new Date(`${endDateStr}T23:59:59.999Z`);
    if (isNaN(endDate.getTime())) return res.status(400).json({ error: 'invalid endDate (YYYY-MM-DD)' });

    // 1. Detect data start = MIN(createdAt) across the analytics tables.
    const startProbe = await query(req, `
      SELECT MIN("createdAt") AS m FROM (
        SELECT MIN("createdAt") AS "createdAt" FROM app_user_appointment
        UNION ALL SELECT MIN("createdAt") FROM guest_appointment
        UNION ALL SELECT MIN("createdAt") FROM app_user_info
        UNION ALL SELECT MIN("createdAt") FROM app_user_nps_sent
        UNION ALL SELECT MIN("createdAt") FROM app_user_document_request
      ) t`);
    const dataStart = startProbe[0]?.m ? new Date(startProbe[0].m) : new Date('2024-01-01');
    const rangeStart = dataStart;
    const rangeEnd   = endDate;

    // 2. Praxis directory. `bundeslandCode` is cockpit-only and may not exist
    //    in prod — try with it, fall back without.
    let praxisDirRows;
    try {
      praxisDirRows = await query(req, `SELECT "lcId", name, "shortName", "bundeslandCode" FROM praxis_config WHERE "lcId" IS NOT NULL ORDER BY "lcId"`);
    } catch (_) {
      praxisDirRows = await query(req, `SELECT "lcId", name, "shortName" FROM praxis_config WHERE "lcId" IS NOT NULL ORDER BY "lcId"`);
    }
    const praxisDir = praxisDirRows.map(r => ({
      lcId: r.lcId,
      name: r.name || r.shortName || r.lcId,
      shortName: r.shortName || null,
      bundesland: r.bundeslandCode != null ? (BUNDESLAND_CODES[r.bundeslandCode] || null) : null,
    }));

    // 3. Discover lcIds that actually have data (some praxis_config rows may
    //    be empty placeholders).
    const usedRows = await query(req, `SELECT DISTINCT "praxisId" FROM app_user_info WHERE "praxisId" IS NOT NULL AND "praxisId" <> ''`);
    const used = new Set(usedRows.map(r => r.praxisId));
    const targetPraxes = praxisDir.filter(p => used.has(p.lcId));
    if (targetPraxes.length === 0) return res.status(400).json({ error: 'no praxes with data found' });

    // 4. Walk praxes one-at-a-time. Each iteration runs ~13 indexed queries
    //    in parallel — same load profile as a normal /api/analytics request.
    const results = [];
    for (const p of targetPraxes) {
      const agg = await _fetchPraxisAggregates(req, p.lcId, rangeStart, rangeEnd);
      results.push({ ...p, ...agg });
    }

    // 5. Global PMS downtime list + deletion reasons (not praxis-scoped).
    //    Cockpit tables don't exist in prod — query is best-effort.
    //    deletion_feedback.reason is a JSON array; aggregate in JS, not SQL.
    //    Unattributed cancellations: rows where the user has no appointment at
    //    their registered praxis — the actual cancelled appointment was
    //    elsewhere (typically another praxis the user also booked at).
    const [pmsDowntimes, deletionRaw, unattributedCancellations, cockpit] = await Promise.all([
      query(req, `SELECT id, "totalDownTimeInSeconds", "createdAt" FROM analytics_pms_downtime WHERE "createdAt" BETWEEN $1 AND $2 ORDER BY "createdAt"`, [rangeStart, rangeEnd]),
      query(req, `SELECT reason FROM app_user_deletion_feedback WHERE "createdAt" BETWEEN $1 AND $2`, [rangeStart, rangeEnd]),
      query(req, `SELECT c."createdAt", c.reason, ui."praxisId" AS user_registered_praxis
                    FROM app_user_appointment_cancellation_reason c
                    JOIN app_user_info ui ON ui.id = c."userId"
                    WHERE c."createdAt" BETWEEN $1 AND $2
                      AND ui."praxisId" IS NOT NULL AND ui."praxisId" <> ''
                      AND NOT EXISTS (
                        SELECT 1 FROM app_user_appointment a
                        WHERE a."userId" = c."userId" AND a."praxisId" = ui."praxisId"
                      )`, [rangeStart, rangeEnd]),
      _gatherCockpitOverview(req).catch((e) => { console.warn('cockpit gather skipped:', e.message); return []; }),
    ]);

    // Aggregate unattributed cancellations: count + reasons + by-user-praxis breakdown.
    const unattributedTotal = unattributedCancellations.length;
    const unattributedReasonCounts = {};
    const unattributedByPraxis = {};
    for (const row of unattributedCancellations) {
      const list = Array.isArray(row.reason) ? row.reason : (row.reason != null ? [row.reason] : ['—']);
      for (const r of list) {
        const k = String(r).slice(0, 120);
        unattributedReasonCounts[k] = (unattributedReasonCounts[k] || 0) + 1;
      }
      const px = row.user_registered_praxis;
      unattributedByPraxis[px] = (unattributedByPraxis[px] || 0) + 1;
    }
    const unattributedReasons = Object.entries(unattributedReasonCounts)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 20)
      .map(([reason, count]) => ({ reason, count }));
    const unattributedByPraxisArr = Object.entries(unattributedByPraxis)
      .sort((a, b) => b[1] - a[1])
      .map(([lcId, count]) => ({ lcId, count }));

    // deletionRaw row count = unique account deletions (each user appears once
    // per deletion event). The reason column is a List<String> — same user can
    // select multiple reasons, so the reason-breakdown counts will sum to MORE
    // than totalDeletions. Track them separately.
    const totalDeletions = deletionRaw.length;
    const deletionCounts = {};
    for (const row of deletionRaw) {
      const list = Array.isArray(row.reason) ? row.reason : (row.reason != null ? [row.reason] : ['—']);
      for (const r of list) {
        const k = String(r).slice(0, 120);
        deletionCounts[k] = (deletionCounts[k] || 0) + 1;
      }
    }
    const deletionRows = Object.entries(deletionCounts)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 50)
      .map(([reason, count]) => ({ reason, count }));

    const monthsCovered = _enumerateMonths(rangeStart, rangeEnd);

    const payload = {
      generatedAt: new Date().toISOString(),
      dataStart:   rangeStart.toISOString(),
      dataEnd:     rangeEnd.toISOString(),
      monthsCovered,
      praxes: results,
      pmsDowntimes,
      totalDeletions,
      deletionReasons: deletionRows,
      unattributedCancellations: {
        total: unattributedTotal,
        reasons: unattributedReasons,
        byUserRegisteredPraxis: unattributedByPraxisArr,
      },
      cockpit,
    };

    // 6. Write outputs.
    const stamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
    const outDir = path.join(ROOT, 'exports', `historical-${endDate.toISOString().slice(0,10)}-${stamp}`);
    fs.mkdirSync(outDir, { recursive: true });

    const withCopySql = req.query.validator === '1' || req.query.validator === 'true';
    const jsonPath = path.join(outDir, 'analytics.json');
    const xlsxPath = path.join(outDir, 'analytics.xlsx');
    const htmlPath = path.join(outDir, withCopySql ? 'analytics-validator.html' : 'analytics.html');

    fs.writeFileSync(jsonPath, JSON.stringify(payload, null, 2));
    fs.writeFileSync(xlsxPath, _xlsxFromPayload(payload));
    fs.writeFileSync(htmlPath, _htmlFromPayload(payload, { withCopySql }));

    res.json({
      ok: true,
      outDir,
      validator: withCopySql,
      files: { json: jsonPath, xlsx: xlsxPath, html: htmlPath },
      praxesProcessed: results.length,
      monthsCovered: monthsCovered.length,
      dataStart: payload.dataStart,
      dataEnd:   payload.dataEnd,
    });
  } catch (e) {
    console.error('export-historical failed:', e);
    res.status(500).json({ error: e.message });
  }
});

module.exports = router;
