const router = require('express').Router();
const { query } = require('../lib/db');
const { TOOK_PLACE_STATUS_FILTER } = require('../lib/analytics');

// ─── Routes: Analytics (per-praxis monthly metrics) ──────────────────────────
// Port of LillianCare-Core/.../endpoints/admin/analytics/admin_analytics.dart.
// All counts + lists come from the same Postgres DB we already connect to —
// no Serverpod call, no external service.

// Overview across ALL praxes for a date range.
//
// Scaling: one aggregate query per table using GROUP BY "praxisId" — each is a
// single indexed scan regardless of praxis count. We do NOT return row lists
// (no `allAppAppointments` etc.) and no daily time series, so the payload is
// ~10 fields × praxes count, typically under 10 KB even for 100 praxes.
// Total wall time ≈ the slowest single GROUP BY, since everything runs in
// Promise.all. Safe to hit on prod without hanging the DB.
router.get('/api/analytics/overview', async (req, res) => {
  try {
    const now = new Date();
    const parseDate = (s, fb) => { if (!s) return fb; const d = new Date(s); return isNaN(d) ? fb : d; };
    const defaultEnd   = new Date(now.getFullYear(), now.getMonth(), now.getDate() + 1);
    const defaultStart = new Date(defaultEnd.getTime() - 30 * 86400000);
    const start = parseDate(req.query.startDate, defaultStart);
    const end   = parseDate(req.query.endDate,   defaultEnd);
    if (end <= start) return res.status(400).json({ error: 'endDate must be after startDate' });

    const pad = n => String(n).padStart(2, '0');
    const isoNaive = d => `${d.getFullYear()}-${pad(d.getMonth()+1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
    const rangeStart = isoNaive(start);
    const rangeEnd   = isoNaive(end);
    const rangeStartIso = start.toISOString();
    const rangeEndIso   = end.toISOString();

    // Each of these returns [{ praxisId, ...counts }, ...] or a global count.
    const [
      appApptByPraxis,
      guestApptByPraxis,
      appTookPlaceByPraxis,
      guestTookPlaceByPraxis,
      npsSentByPraxis,
      fhirNpsByPraxis,
      docRequestByPraxis,
      openConsultByPraxis,
      newRegByPraxis,
      patientsByPraxis,
      totalCancellations,
      totalQuestionnaires,
      totalDeletions,
      pmsDowntimeSum,
    ] = await Promise.all([
      query(req, `SELECT "praxisId", COUNT(*)::int AS c FROM app_user_appointment
                  WHERE "praxisId" IS NOT NULL AND "createdAt">=$1 AND "createdAt"<$2 GROUP BY "praxisId"`, [rangeStart, rangeEnd]),
      query(req, `SELECT "praxisId",
                    COUNT(*)::int AS total,
                    COUNT(*) FILTER (WHERE "isBookedFromPraxis"=true)::int AS praxis,
                    COUNT(*) FILTER (WHERE "isBookedFromPraxis" IS NOT TRUE)::int AS web,
                    COUNT(*) FILTER (WHERE "isBookedFromPraxis"=true AND "hasEmail"=false)::int AS praxis_no_email
                  FROM guest_appointment
                  WHERE "praxisId" IS NOT NULL AND "createdAt">=$1 AND "createdAt"<$2 GROUP BY "praxisId"`, [rangeStart, rangeEnd]),
      query(req, `SELECT "praxisId", COUNT(*)::int AS c FROM app_user_appointment
                  WHERE "praxisId" IS NOT NULL AND "startTime" IS NOT NULL
                    AND "startTime">=$1 AND "startTime"<$2 ${TOOK_PLACE_STATUS_FILTER}
                  GROUP BY "praxisId"`, [rangeStartIso, rangeEndIso]),
      query(req, `SELECT "praxisId",
                    COUNT(*)::int AS total,
                    COUNT(*) FILTER (WHERE "isBookedFromPraxis"=true)::int AS praxis,
                    COUNT(*) FILTER (WHERE "isBookedFromPraxis" IS NOT TRUE)::int AS web
                  FROM guest_appointment
                  WHERE "praxisId" IS NOT NULL AND "startTime" IS NOT NULL
                    AND "startTime">=$1 AND "startTime"<$2 ${TOOK_PLACE_STATUS_FILTER}
                  GROUP BY "praxisId"`, [rangeStartIso, rangeEndIso]),
      query(req, `SELECT "praxisId", COUNT(*)::int AS c FROM app_user_nps_sent
                  WHERE "createdAt">=$1 AND "createdAt"<$2 GROUP BY "praxisId"`, [rangeStart, rangeEnd]),
      query(req, `SELECT "praxisId",
                    COUNT(*)::int AS total,
                    COUNT(*) FILTER (WHERE "hasEmail"=false)::int AS no_email
                  FROM fhir_nps WHERE "createdAt">=$1 AND "createdAt"<$2 GROUP BY "praxisId"`, [rangeStart, rangeEnd]),
      query(req, `SELECT "praxisId",
                    COUNT(*)::int AS total,
                    COUNT(*) FILTER (WHERE "isFromWeb"=false)::int AS from_app,
                    COUNT(*) FILTER (WHERE "isFromWeb"=true)::int  AS from_web
                  FROM app_user_document_request
                  WHERE "createdAt">=$1 AND "createdAt"<$2 GROUP BY "praxisId"`, [rangeStart, rangeEnd]),
      query(req, `SELECT "praxisId", COUNT(*)::int AS c FROM app_user_open_consultation
                  WHERE "createdAt">=$1 AND "createdAt"<$2 GROUP BY "praxisId"`, [rangeStart, rangeEnd]),
      query(req, `SELECT "praxisId",
                    COUNT(*)::int AS total,
                    COUNT(*) FILTER (WHERE "isVerified"=true)::int AS verified
                  FROM app_user_info
                  WHERE "praxisId" IS NOT NULL AND "createdAt">=$1 AND "createdAt"<$2 GROUP BY "praxisId"`, [rangeStart, rangeEnd]),
      query(req, `SELECT "praxisId",
                    COUNT(*)::int AS total,
                    COUNT(*) FILTER (WHERE "isVerified"=true)::int AS verified
                  FROM app_user_info WHERE "praxisId" IS NOT NULL GROUP BY "praxisId"`, []),
      query(req, `SELECT COUNT(*)::int AS c FROM app_user_appointment_cancellation_reason WHERE "createdAt">=$1 AND "createdAt"<$2`, [rangeStart, rangeEnd]),
      query(req, `SELECT COUNT(*)::int AS c FROM app_user_questionnaire WHERE "answeredAt">=$1 AND "answeredAt"<$2`, [rangeStart, rangeEnd]),
      query(req, `SELECT COUNT(*)::int AS c FROM app_user_deletion_feedback WHERE "createdAt">=$1 AND "createdAt"<$2`, [rangeStart, rangeEnd]),
      query(req, `SELECT COALESCE(SUM("totalDownTimeInSeconds"), 0)::bigint AS s FROM analytics_pms_downtime WHERE "createdAt">=$1 AND "createdAt"<$2`, [rangeStart, rangeEnd]),
    ]);

    // Merge into one row per praxisId.
    const byPraxis = {};
    const touch = id => (byPraxis[id] ||= {
      praxisId: id,
      appAppointments: 0, guestAppointments: 0,
      guestBookedFromWeb: 0, guestBookedFromPraxis: 0, guestBookedFromPraxisNoEmail: 0,
      appointmentsTotal: 0,
      appTookPlace: 0, guestTookPlaceWeb: 0, guestTookPlacePraxis: 0,
      tookPlaceTotal: 0,
      npsEmailsSent: 0,
      guestNPS: 0, guestNPSNoEmail: 0,            // corrected (real :422 attempts)
      guestNPSRaw: 0, guestNPSRawNoEmail: 0,      // raw fhir_nps counts (incl. :329 spurious)
      totalNPS: 0,
      docRequests: 0, docRequestsFromApp: 0, docRequestsFromWeb: 0,
      openConsultations: 0,
      newRegistrations: 0, newVerifiedRegistrations: 0,
      totalPatients: 0, totalVerifiedPatients: 0,
    });

    for (const r of appApptByPraxis)   touch(r.praxisId).appAppointments = r.c;
    for (const r of guestApptByPraxis) {
      const p = touch(r.praxisId);
      p.guestAppointments           = r.total;
      p.guestBookedFromPraxis       = r.praxis;
      p.guestBookedFromWeb          = r.web;
      p.guestBookedFromPraxisNoEmail= r.praxis_no_email;
    }
    for (const r of appTookPlaceByPraxis)   touch(r.praxisId).appTookPlace = r.c;
    for (const r of guestTookPlaceByPraxis) {
      const p = touch(r.praxisId);
      p.guestTookPlaceWeb    = r.web;
      p.guestTookPlacePraxis = r.praxis;
    }
    for (const r of npsSentByPraxis) touch(r.praxisId).npsEmailsSent = r.c;
    for (const r of fhirNpsByPraxis) {
      const p = touch(r.praxisId);
      p.guestNPSRaw        = r.total;
      p.guestNPSRawNoEmail = r.no_email;
    }
    for (const r of docRequestByPraxis) {
      const p = touch(r.praxisId);
      p.docRequests        = r.total;
      p.docRequestsFromApp = r.from_app;
      p.docRequestsFromWeb = r.from_web;
    }
    for (const r of openConsultByPraxis) touch(r.praxisId).openConsultations = r.c;
    for (const r of newRegByPraxis) {
      const p = touch(r.praxisId);
      p.newRegistrations         = r.total;
      p.newVerifiedRegistrations = r.verified;
    }
    for (const r of patientsByPraxis) {
      const p = touch(r.praxisId);
      p.totalPatients         = r.total;
      p.totalVerifiedPatients = r.verified;
    }

    // Derive totals per praxis + rates.
    const praxes = Object.values(byPraxis).map(p => {
      // praxisNoEmail is a subset of guestBookedFromPraxis — do not add it again.
      p.appointmentsTotal = p.appAppointments + p.guestBookedFromWeb + p.guestBookedFromPraxis;
      p.tookPlaceTotal = p.appTookPlace + p.guestTookPlaceWeb + p.guestTookPlacePraxis;
      // guestNPS recovery: subtract :329 spurious writes (= praxis-booked
      // guest_appointments) from raw fhir_nps. See _emptyMonthlyKpi() above
      // for the full explanation of why these are spurious.
      p.guestNPS        = Math.max(0, (p.guestNPSRaw        || 0) - (p.guestBookedFromPraxis         || 0));
      p.guestNPSNoEmail = Math.max(0, (p.guestNPSRawNoEmail || 0) - (p.guestBookedFromPraxisNoEmail || 0));
      p.totalNPS = p.npsEmailsSent + p.guestNPS;
      // NPS-eligible events = appointments + doc requests + open consultations
      // (backend triggers an NPS after each of these). 30-day per-user dedup.
      p.npsEligibleEvents     = p.appointmentsTotal + (p.docRequests || 0) + (p.openConsultations || 0);
      p.npsCoveragePercentage = p.npsEligibleEvents > 0 ? (p.totalNPS / p.npsEligibleEvents) * 100 : 0;
      p.verificationRate      = p.newRegistrations > 0 ? (p.newVerifiedRegistrations / p.newRegistrations) * 100 : 0;
      return p;
    }).sort((a, b) => b.appointmentsTotal - a.appointmentsTotal);

    // Grand totals across all praxes.
    const sumAll = key => praxes.reduce((s, p) => s + (p[key] || 0), 0);
    const summary = {
      praxesCount:             praxes.length,
      appointmentsTotal:       sumAll('appointmentsTotal'),
      tookPlaceTotal:          sumAll('tookPlaceTotal'),
      newRegistrations:        sumAll('newRegistrations'),
      newVerifiedRegistrations:sumAll('newVerifiedRegistrations'),
      totalPatients:           sumAll('totalPatients'),
      totalVerifiedPatients:   sumAll('totalVerifiedPatients'),
      docRequests:             sumAll('docRequests'),
      openConsultations:       sumAll('openConsultations'),
      npsEmailsSent:           sumAll('npsEmailsSent'),
      guestNPS:                sumAll('guestNPS'),
      guestNPSNoEmail:         sumAll('guestNPSNoEmail'),
      guestNPSRaw:             sumAll('guestNPSRaw'),
      guestNPSRawNoEmail:      sumAll('guestNPSRawNoEmail'),
      totalNPS:                sumAll('totalNPS'),
      // Global (not per-praxis in the schema)
      totalCancellations:      totalCancellations[0].c,
      totalQuestionnaires:     totalQuestionnaires[0].c,
      totalDeletions:          totalDeletions[0].c,
      pmsDownTimeInSeconds:    parseInt(pmsDowntimeSum[0].s, 10) || 0,
      pmsDownTimeInMinutes:    (parseInt(pmsDowntimeSum[0].s, 10) || 0) / 60,
    };

    res.json({
      rangeStart: start.toISOString(),
      rangeEnd:   end.toISOString(),
      summary,
      praxes,
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Praxis names — {lcId: "Name"} map. Queried once per DB connection and
// cached for 5 minutes. Tiny table (~100 rows), minimal pressure on the DB.
const praxisNameCache = new Map(); // cacheKey -> { map, expiresAt }
router.get('/api/praxis-names', async (req, res) => {
  try {
    const ck = (req.headers['x-db-host'] || '') + '|' + (req.headers['x-db-name'] || '');
    const now = Date.now();
    const hit = praxisNameCache.get(ck);
    if (hit && hit.expiresAt > now && req.query.refresh !== '1') {
      return res.json({ cached: true, names: hit.map });
    }
    const rows = await query(req, `SELECT "lcId", name, "shortName" FROM praxis_config ORDER BY "lcId"`);
    const map = {};
    for (const r of rows) map[r.lcId] = r.name || r.shortName || r.lcId;
    praxisNameCache.set(ck, { map, expiresAt: now + 5 * 60 * 1000 });
    res.json({ cached: false, names: map });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

router.get('/api/analytics/praxes', async (req, res) => {
  try {
    const rows = await query(
      req,
      `SELECT DISTINCT "praxisId" FROM app_user_info
       WHERE "praxisId" IS NOT NULL AND "praxisId" <> ''
       ORDER BY "praxisId"`
    );
    res.json({ praxes: rows.map(r => r.praxisId) });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Port of GetEnhancedAdminAnalytics + EnhancedPraxisAnalyticsCalculator.
// Returns counters, derived rates, daily time series, and top-10 category
// breakdowns — everything the praxis app's analytics_screen.dart renders.
router.get('/api/analytics', async (req, res) => {
  try {
    const praxisId = (req.query.praxisId || '').toString().trim();
    if (!praxisId) return res.status(400).json({ error: 'praxisId is required' });

    const now = new Date();
    const parseDate = (s, fallback) => {
      if (!s) return fallback;
      const d = new Date(s);
      return isNaN(d.getTime()) ? fallback : d;
    };
    // Default = last 30 days ending tomorrow 00:00 (exclusive upper).
    const defaultEnd   = new Date(now.getFullYear(), now.getMonth(), now.getDate() + 1);
    const defaultStart = new Date(defaultEnd.getTime() - 30 * 86400000);
    const start = parseDate(req.query.startDate, defaultStart);
    const end   = parseDate(req.query.endDate,   defaultEnd);
    if (end <= start) return res.status(400).json({ error: 'endDate must be after startDate' });

    const isoNaive = d => {
      const pad = n => String(n).padStart(2, '0');
      return `${d.getFullYear()}-${pad(d.getMonth()+1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
    };
    const rangeStart = isoNaive(start);
    const rangeEnd   = isoNaive(end);
    // startTime on appointments is stored as ISO text ('2026-04-05T10:00:00'),
    // so compare against the ISO form (no space).
    const rangeStartIso = start.toISOString();
    const rangeEndIso   = end.toISOString();

    const countOne = (sql, params) => query(req, sql, params).then(r => parseInt(r[0].count));

    const [
      npsEmailsSent,
      guestNPSSent,
      guestNPSRequestWithoutEmail,
      totalPatients,
      totalVerifiedPatients,
      appointmentsTookPlaceFromApp,
      appointmentsTookPlaceFromWeb,
      appointmentsTookPlaceFromPraxis,
      appointmentsTookPlaceFromPraxisWithoutEmail,
      appAppointmentsInRange,
      webAppointmentsInRange,
      pmsDowntimes,
      openConsultations,
      cancellationReasons,
      newRegistrations,
      documentRequestsInRange,
      questionnairesAnswered,
      deletionFeedback,
    ] = await Promise.all([
      countOne(`SELECT COUNT(*) FROM app_user_nps_sent WHERE "praxisId"=$1 AND "createdAt">=$2 AND "createdAt"<$3`, [praxisId, rangeStart, rangeEnd]),
      countOne(`SELECT COUNT(*) FROM fhir_nps          WHERE "praxisId"=$1 AND "createdAt">=$2 AND "createdAt"<$3`, [praxisId, rangeStart, rangeEnd]),
      countOne(`SELECT COUNT(*) FROM fhir_nps          WHERE "praxisId"=$1 AND "createdAt">=$2 AND "createdAt"<$3 AND "hasEmail"=false`, [praxisId, rangeStart, rangeEnd]),
      countOne(`SELECT COUNT(*) FROM app_user_info     WHERE "praxisId"=$1`, [praxisId]),
      countOne(`SELECT COUNT(*) FROM app_user_info     WHERE "praxisId"=$1 AND "isVerified"=true`, [praxisId]),
      countOne(`SELECT COUNT(*) FROM app_user_appointment WHERE "praxisId"=$1 AND "startTime" IS NOT NULL AND "startTime">=$2 AND "startTime"<$3 ${TOOK_PLACE_STATUS_FILTER}`, [praxisId, rangeStartIso, rangeEndIso]),
      countOne(`SELECT COUNT(*) FROM guest_appointment    WHERE "praxisId"=$1 AND "startTime" IS NOT NULL AND "startTime">=$2 AND "startTime"<$3 AND ("isBookedFromPraxis" IS NOT TRUE) ${TOOK_PLACE_STATUS_FILTER}`, [praxisId, rangeStartIso, rangeEndIso]),
      countOne(`SELECT COUNT(*) FROM guest_appointment    WHERE "praxisId"=$1 AND "startTime" IS NOT NULL AND "startTime">=$2 AND "startTime"<$3 AND "isBookedFromPraxis"=true ${TOOK_PLACE_STATUS_FILTER}`, [praxisId, rangeStartIso, rangeEndIso]),
      countOne(`SELECT COUNT(*) FROM guest_appointment    WHERE "praxisId"=$1 AND "startTime" IS NOT NULL AND "startTime">=$2 AND "startTime"<$3 AND "isBookedFromPraxis"=true AND "hasEmail"=false ${TOOK_PLACE_STATUS_FILTER}`, [praxisId, rangeStartIso, rangeEndIso]),
      query(req, `SELECT id, "userId", "familyMemberId", category, reason, "appointmentId", "pmsAppointmentId", status, "praxisId", "startTime", "createdAt" FROM app_user_appointment WHERE "praxisId"=$1 AND "createdAt">=$2 AND "createdAt"<$3`, [praxisId, rangeStart, rangeEnd]),
      query(req, `SELECT id, "bookingId", "patientId", "praxisId", category, "hasEmail", "isBookedFromPraxis", "createdAt" FROM guest_appointment WHERE "praxisId"=$1 AND "createdAt">=$2 AND "createdAt"<$3`, [praxisId, rangeStart, rangeEnd]),
      query(req, `SELECT id, "totalDownTimeInSeconds", "createdAt" FROM analytics_pms_downtime WHERE "createdAt">=$1 AND "createdAt"<$2`, [rangeStart, rangeEnd]),
      query(req, `SELECT id, "userId", category, reason, "praxisId", status, "createdAt" FROM app_user_open_consultation WHERE "praxisId"=$1 AND "createdAt">=$2 AND "createdAt"<$3`, [praxisId, rangeStart, rangeEnd]),
      query(req, `SELECT c.id, c."userId", c.reason, c."createdAt"
                    FROM app_user_appointment_cancellation_reason c
                    JOIN app_user_info ui ON ui.id = c."userId"
                    WHERE ui."praxisId"=$1 AND c."createdAt">=$2 AND c."createdAt"<$3
                      AND EXISTS (
                        SELECT 1 FROM app_user_appointment a
                        WHERE a."userId" = c."userId" AND a."praxisId" = $1
                      )`, [praxisId, rangeStart, rangeEnd]),
      query(req, `SELECT id, "firstName", "lastName", email, "praxisId", "isVerified", "createdAt" FROM app_user_info WHERE "praxisId"=$1 AND "createdAt">=$2 AND "createdAt"<$3`, [praxisId, rangeStart, rangeEnd]),
      query(req, `SELECT id, "userId", category, "praxisId", "isFromWeb", "createdAt" FROM app_user_document_request WHERE "praxisId"=$1 AND "createdAt">=$2 AND "createdAt"<$3`, [praxisId, rangeStart, rangeEnd]),
      query(req, `SELECT q.id, q."userInfoId", q."questionnaireId", q."answeredAt", q."createdAt"
                    FROM app_user_questionnaire q
                    JOIN app_user_info ui ON ui.id = q."userInfoId"
                    WHERE ui."praxisId"=$1 AND q."answeredAt">=$2 AND q."answeredAt"<$3`, [praxisId, rangeStart, rangeEnd]),
      query(req, `SELECT id, reason, "createdAt" FROM app_user_deletion_feedback WHERE "createdAt">=$1 AND "createdAt"<$2`, [rangeStart, rangeEnd]),
    ]);

    // Derived counts from the in-range appointment lists (matches the Dart
    // calculator's getters so numbers always agree with the lists we return).
    const appointmentsBookedFromApp    = appAppointmentsInRange.length;
    const appointmentsBookedFromWeb    = webAppointmentsInRange.filter(a => a.isBookedFromPraxis !== true).length;
    const appointmentsBookedFromPraxis = webAppointmentsInRange.filter(a => a.isBookedFromPraxis === true).length;
    const appointmentsBookedFromPraxisWithoutEmail = webAppointmentsInRange.filter(a => a.isBookedFromPraxis === true && a.hasEmail !== true).length;
    // praxisWithoutEmail is a SUBSET of praxis (same rows, narrower filter) —
    // do not add it to the total or it double-counts.
    const totalAppointments = appointmentsBookedFromApp + appointmentsBookedFromWeb + appointmentsBookedFromPraxis;

    const newVerifiedRegistrations = newRegistrations.filter(u => u.isVerified === true).length;
    const familyMemberAppointments = appAppointmentsInRange.filter(a => a.familyMemberId != null).length;

    const documentRequestFromApp = documentRequestsInRange.filter(d => d.isFromWeb === false).length;
    const documentRequestFromWeb = documentRequestsInRange.filter(d => d.isFromWeb === true).length;
    const documentRequestUnknown = documentRequestsInRange.filter(d => d.isFromWeb === null).length;
    const totalDocumentRequests  = documentRequestFromApp + documentRequestFromWeb + documentRequestUnknown;

    const totalCancellations = cancellationReasons.length;
    const cancellationRate = totalAppointments > 0 ? (totalCancellations / totalAppointments) * 100 : 0;
    const verificationRate = newRegistrations.length > 0 ? (newVerifiedRegistrations / newRegistrations.length) * 100 : 0;
    const familyMemberBookingRate = totalAppointments > 0 ? (familyMemberAppointments / totalAppointments) * 100 : 0;
    // guestNPS recovery: raw fhir_nps − :329 spurious writes (one per
    // praxis-booked guest_appointment). See `_emptyMonthlyKpi()` for the full
    // backend trace.
    const guestNPSRaw                          = guestNPSSent;
    const guestNPSRawWithoutEmail              = guestNPSRequestWithoutEmail;
    const guestNPSCorrected                    = Math.max(0, guestNPSRaw - appointmentsBookedFromPraxis);
    const guestNPSRequestWithoutEmailCorrected = Math.max(0, guestNPSRawWithoutEmail - appointmentsBookedFromPraxisWithoutEmail);
    const totalNPSSent = npsEmailsSent + guestNPSCorrected;
    // NPS fires after appointments + document requests + open consultations
    // (see backend handlers). 30-day per-user dedup means <100% is expected.
    const totalNpsEligibleEvents = totalAppointments + totalDocumentRequests + openConsultations.length;
    const npsCoveragePercentage = totalNpsEligibleEvents > 0 ? (totalNPSSent / totalNpsEligibleEvents) * 100 : 0;
    // pg returns bigint columns as strings to preserve precision — coerce
    // before summing or you get string concatenation ("262" + "188" = "262188").
    const pmsDowntimeSeconds = pmsDowntimes.reduce((s, d) => s + Number(d.totalDownTimeInSeconds || 0), 0);
    const pmsDowntimeMinutes = pmsDowntimeSeconds / 60;
    // praxisWithoutEmail is a SUBSET of praxis — do not add to total.
    const totalAppointmentsTookPlace = appointmentsTookPlaceFromApp + appointmentsTookPlaceFromWeb + appointmentsTookPlaceFromPraxis;

    // Daily time-series — one bucket per calendar day in [start, end).
    const dateKey = d => {
      const x = new Date(d);
      const pad = n => String(n).padStart(2, '0');
      return `${x.getFullYear()}-${pad(x.getMonth()+1)}-${pad(x.getDate())}`;
    };
    const dailyBuckets = [];
    for (let cursor = new Date(start.getFullYear(), start.getMonth(), start.getDate());
         cursor < end;
         cursor.setDate(cursor.getDate() + 1)) {
      dailyBuckets.push(dateKey(cursor));
    }
    const initCounts = () => Object.fromEntries(dailyBuckets.map(k => [k, 0]));
    const c = {
      app: initCounts(), web: initCounts(), praxis: initCounts(),
      reg: initCounts(), ver: initCounts(),
      docApp: initCounts(), docWeb: initCounts(),
      oc: initCounts(), cancel: initCounts(), q: initCounts(),
    };
    for (const a of appAppointmentsInRange) c.app[dateKey(a.createdAt)]++;
    for (const a of webAppointmentsInRange) {
      const k = dateKey(a.createdAt);
      if (a.isBookedFromPraxis === true) c.praxis[k]++; else c.web[k]++;
    }
    for (const u of newRegistrations) {
      const k = dateKey(u.createdAt);
      c.reg[k]++;
      if (u.isVerified === true) c.ver[k]++;
    }
    for (const d of documentRequestsInRange) {
      const k = dateKey(d.createdAt);
      if (d.isFromWeb === true) c.docWeb[k]++;
      else if (d.isFromWeb === false) c.docApp[k]++;
    }
    for (const oc of openConsultations) c.oc[dateKey(oc.createdAt)]++;
    for (const x of cancellationReasons) c.cancel[dateKey(x.createdAt)]++;
    for (const q of questionnairesAnswered) c.q[dateKey(q.answeredAt)]++;

    const dailyTimeSeries = dailyBuckets.map(k => ({
      date: k,
      appointmentsApp:         c.app[k],
      appointmentsWeb:         c.web[k],
      appointmentsPraxis:      c.praxis[k],
      newRegistrations:        c.reg[k],
      verifiedRegistrations:   c.ver[k],
      documentRequestsApp:     c.docApp[k],
      documentRequestsWeb:     c.docWeb[k],
      openConsultations:       c.oc[k],
      cancellations:           c.cancel[k],
      questionnairesCompleted: c.q[k],
    }));

    // Top-10 category breakdowns.
    const topCategories = (counts) =>
      Object.entries(counts).sort((a,b) => b[1] - a[1]).slice(0, 10)
        .map(([category, count]) => ({ category, count }));

    const apptCatCounts = {};
    for (const a of appAppointmentsInRange) apptCatCounts[a.category||'—'] = (apptCatCounts[a.category||'—'] || 0) + 1;
    for (const a of webAppointmentsInRange) apptCatCounts[a.category||'—'] = (apptCatCounts[a.category||'—'] || 0) + 1;
    const appointmentCategories = topCategories(apptCatCounts);

    // cancellationReasons.reason is a JSON array in Postgres (json type), pg
    // driver returns it as an actual array.
    const cancelReasonCounts = {};
    for (const row of cancellationReasons) {
      const list = Array.isArray(row.reason) ? row.reason : [];
      for (const r of list) cancelReasonCounts[String(r)] = (cancelReasonCounts[String(r)] || 0) + 1;
    }
    const cancellationReasonsTop = topCategories(cancelReasonCounts);

    const deletionReasonCounts = {};
    for (const row of deletionFeedback) {
      const list = Array.isArray(row.reason) ? row.reason : [];
      for (const r of list) deletionReasonCounts[String(r)] = (deletionReasonCounts[String(r)] || 0) + 1;
    }
    const deletionReasons = topCategories(deletionReasonCounts);

    res.json({
      praxisId,
      rangeStart: start.toISOString(),
      rangeEnd:   end.toISOString(),
      // Counters
      npsEmailsSent,
      guestNPS:                    guestNPSCorrected,
      guestNPSRequestWithoutEmail: guestNPSRequestWithoutEmailCorrected,
      guestNPSRaw, guestNPSRawWithoutEmail,
      totalNPSSent,
      totalPatients, totalVerifiedPatients,
      appointmentsBookedFromApp, appointmentsBookedFromWeb,
      appointmentsBookedFromPraxis, appointmentsBookedFromPraxisWithoutEmail,
      totalAppointments,
      appointmentsTookPlaceFromApp, appointmentsTookPlaceFromWeb,
      appointmentsTookPlaceFromPraxis, appointmentsTookPlaceFromPraxisWithoutEmail,
      totalAppointmentsTookPlace,
      totalNewRegistrations: newRegistrations.length,
      totalNewVerifiedRegistrations: newVerifiedRegistrations,
      verificationRate,
      totalDocumentRequests, documentRequestFromApp, documentRequestFromWeb, documentRequestUnknown,
      totalOpenConsultations: openConsultations.length,
      totalCancellations, cancellationRate,
      totalQuestionnairesCompleted: questionnairesAnswered.length,
      familyMemberAppointments, familyMemberBookingRate,
      npsCoveragePercentage,
      pmsDownTimeInSeconds: pmsDowntimeSeconds, pmsDownTimeInMinutes: pmsDowntimeMinutes,
      // Charts
      dailyTimeSeries,
      appointmentCategories,
      cancellationReasons: cancellationReasonsTop,
      deletionReasons,
      // Raw lists for debug-style tables
      pmsDowntimes,
      appAppointmentsInRange,
      webAppointmentsInRange,
      openConsultations,
      newRegistrations,
      documentRequestsInRange,
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

module.exports = router;
