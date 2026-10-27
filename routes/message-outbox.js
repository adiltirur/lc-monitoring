const router = require('express').Router();
const { getPool, paginate, query } = require('../lib/db');

// ─── Routes: Message Outbox (Brevo email/SMS durable queue) ───────────────────
const OUTBOX_CHANNELS = ['email', 'sms'];
const OUTBOX_STATUSES = ['pending', 'sending', 'sent', 'failed', 'dead'];
const OUTBOX_ERROR_CLASSES = ['permanent', 'transient'];

// ─── Helpers: Brevo delivery status ───────────────────────────────────────────
// Core stores every Brevo webhook event in brevo_webhook_event, keyed by the
// messageId Brevo returned when the message was accepted, which is saved on
// core_message_outbox."providerMessageId". Environments that have not run that
// migration yet simply show no Brevo status, so the check is cached per pool.
const BREVO_SUPPORT_TTL_MS = 60_000;
const brevoSupportCache = new WeakMap();

async function brevoSupported(req) {
  const pool = getPool(req);
  const cached = brevoSupportCache.get(pool);
  if (cached && cached.at > Date.now() - BREVO_SUPPORT_TTL_MS) return cached.ok;
  const rows = await query(
    req,
    `SELECT
       EXISTS (SELECT 1 FROM information_schema.columns
               WHERE table_schema = 'public' AND table_name = 'core_message_outbox'
                 AND column_name = 'providerMessageId') AS outbox,
       EXISTS (SELECT 1 FROM information_schema.columns
               WHERE table_schema = 'public' AND table_name = 'brevo_webhook_event'
                 AND column_name = 'reason') AS events`
  );
  const ok = Boolean(rows[0].outbox && rows[0].events);
  brevoSupportCache.set(pool, { ok, at: Date.now() });
  return ok;
}

// Latest Brevo event per outbox row, by the time Brevo reported it.
const BREVO_LATEST_JOIN = `LEFT JOIN LATERAL (
    SELECT e.event, COALESCE(e."eventAt", e."receivedAt") AS at
    FROM brevo_webhook_event e
    WHERE e."messageId" = o."providerMessageId"
    ORDER BY COALESCE(e."eventAt", e."receivedAt") DESC, e.id DESC
    LIMIT 1
  ) brevo ON true`;

// ─── Helpers: email template ──────────────────────────────────────────────────
// Email payloads are the Brevo request body, so they carry the Brevo
// "templateId". Core maps it in email_template_id to a CoreEmailType (byIndex —
// this list must follow the order in Core's email_template_type.spy.yaml) and a
// name. One Brevo template can back several types. Extracted with a regex so a
// payload that is not valid JSON does not break the query.
const CORE_EMAIL_TYPES = [
  'openConsultationPatient', 'openConsultationPraxis', 'nps', 'documentRequestPatient',
  'documentRequestPraxis', 'otp', 'emailVerification', 'emailVerificationLC',
  'emailVerificationReminder', 'praxisAppCredentials', 'contactUsPatient', 'contactUsPraxis',
  'registration', 'passwordReset', 'confirmNewEmail', 'confirmCurrentEmail',
  'appointmentConfirmationPatient', 'appointmentCancellationPatient', 'appointmentReschedulePatient',
  'praxisConfigExport', 'appointmentReservationPatient', 'appointmentReminderPatient',
  'appointmentBookingFromPrincipa', 'documentForVerifiedUser', 'documentForUnverifiedUser',
  'pmsPatientInvitation', 'pmsAutoLinkDobMismatch', 'pmsAutoLinkDobMismatchInvitation',
  'appointmentRescheduleFromPrincipa', 'appointmentCancellationByPatient',
  'waitingListConfirmationPatient', 'influenzaAppointmentConfirmationPatient',
  'medicationPrescriptionReadyVerifiedUser', 'waitingListBookingInvitation',
];

const TEMPLATE_JOIN = `LEFT JOIN LATERAL (
    SELECT substring(o.payload from '"templateId"\\s*:\\s*(\\d{1,9})')::int AS id
  ) tpl ON true
  LEFT JOIN LATERAL (
    SELECT min(t."templateName") AS name, array_agg(DISTINCT t."templateType") AS types
    FROM email_template_id t
    WHERE t."templateId" = tpl.id
  ) tplinfo ON true`;
const TEMPLATE_COLS = 'tpl.id AS "templateId", tplinfo.name AS "templateName", tplinfo.types AS "templateTypes"';

function templateTypeNames(types) {
  return (types || []).filter(t => t !== null).map(t => CORE_EMAIL_TYPES[t] ?? String(t));
}

router.get('/api/message-outbox', async (req, res) => {
  try {
    const { status, channel, dateFrom, dateTo, correlationId, recipient, lastHttpStatus, lastErrorClass, brevoStatus, templateId, page = 1, pageSize = 50 } = req.query;
    const withBrevo = await brevoSupported(req);
    const filters = [];
    if (status) {
      const list = String(status).split(',').map(s => s.trim()).filter(Boolean);
      const idxs = list.map(s => OUTBOX_STATUSES.indexOf(s)).filter(i => i >= 0);
      if (idxs.length) filters.push(['status', '= ANY', idxs]);
    }
    if (channel) {
      const idx = OUTBOX_CHANNELS.indexOf(String(channel));
      if (idx >= 0) filters.push(['channel', '=', idx]);
    }
    if (lastErrorClass) {
      const idx = OUTBOX_ERROR_CLASSES.indexOf(String(lastErrorClass));
      if (idx >= 0) filters.push(['"lastErrorClass"', '=', idx]);
    }
    if (dateFrom) filters.push(['"createdAt"', '>=', dateFrom]);
    if (dateTo) filters.push(['"createdAt"', '<=', dateTo]);
    if (correlationId) filters.push(['"correlationId"', 'ILIKE', `%${correlationId}%`]);
    if (recipient) filters.push(['payload', 'ILIKE', `%${recipient}%`]);
    if (lastHttpStatus) filters.push(['"lastHttpStatus"', '=', parseInt(lastHttpStatus)]);
    if (templateId && Number.isInteger(parseInt(templateId))) filters.push(['tpl.id', '=', parseInt(templateId)]);

    const clauses = [];
    const params = [];
    for (const [col, op, val] of filters) {
      if (val === null || val === undefined || val === '') continue;
      if (Array.isArray(val) && val.length === 0) continue;
      params.push(val);
      if (op === '= ANY') {
        clauses.push(`${col} = ANY($${params.length}::int[])`);
      } else {
        clauses.push(`${col} ${op} $${params.length}`);
      }
    }
    if (withBrevo && brevoStatus === 'none') {
      clauses.push('brevo.event IS NULL');
    } else if (withBrevo && brevoStatus) {
      params.push(String(brevoStatus));
      clauses.push(`brevo.event = $${params.length}`);
    }
    const where = clauses.length ? 'WHERE ' + clauses.join(' AND ') : '';
    const from = `core_message_outbox o ${TEMPLATE_JOIN}${withBrevo ? ` ${BREVO_LATEST_JOIN}` : ''}`;
    const brevoCols = withBrevo ? ', o."providerMessageId", brevo.event AS "brevoStatus", brevo.at AS "brevoStatusAt"' : '';
    const baseSql = `SELECT o.id, o.channel, o.status, o."attemptCount", o."maxAttempts", o."lastHttpStatus", o."lastErrorClass", o."nextAttemptAt", o."firstTeamsNotifiedAt", o."correlationId", o."createdAt", o."updatedAt", o."sentAt", o."deadAt", ${TEMPLATE_COLS}${brevoCols} FROM ${from} ${where} ORDER BY o."createdAt" DESC`;
    const countSql = `SELECT COUNT(*) FROM ${from} ${where}`;
    const result = await paginate(req, baseSql, countSql, params, parseInt(page), parseInt(pageSize));

    result.rows = result.rows.map(r => ({
      ...r,
      channel: OUTBOX_CHANNELS[r.channel] ?? r.channel,
      status: OUTBOX_STATUSES[r.status] ?? r.status,
      lastErrorClass: r.lastErrorClass === null ? null : (OUTBOX_ERROR_CLASSES[r.lastErrorClass] ?? r.lastErrorClass),
      templateTypes: templateTypeNames(r.templateTypes),
    }));

    result.brevoSupported = withBrevo;
    res.json(result);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

router.get('/api/message-outbox/stats', async (req, res) => {
  try {
    const rows = await query(
      req,
      `SELECT channel, status, COUNT(*)::int AS count
       FROM core_message_outbox
       WHERE "createdAt" > NOW() - INTERVAL '30 days'
       GROUP BY channel, status`
    );
    const sentLast24hRows = await query(
      req,
      `SELECT channel, COUNT(*)::int AS count
       FROM core_message_outbox
       WHERE status = 2 AND "sentAt" > NOW() - INTERVAL '24 hours'
       GROUP BY channel`
    );

    const stats = {};
    for (const ch of OUTBOX_CHANNELS) {
      stats[ch] = { pending: 0, sending: 0, sent: 0, failed: 0, dead: 0, sentLast24h: 0 };
    }
    for (const r of rows) {
      const ch = OUTBOX_CHANNELS[r.channel];
      const st = OUTBOX_STATUSES[r.status];
      if (ch && st && stats[ch]) stats[ch][st] = r.count;
    }
    for (const r of sentLast24hRows) {
      const ch = OUTBOX_CHANNELS[r.channel];
      if (ch && stats[ch]) stats[ch].sentLast24h = r.count;
    }
    if (await brevoSupported(req)) {
      const brevoRows = await query(
        req,
        `SELECT event, COUNT(*)::int AS count
         FROM brevo_webhook_event
         WHERE "receivedAt" > NOW() - INTERVAL '30 days'
         GROUP BY event ORDER BY count DESC`
      );
      stats.brevo = Object.fromEntries(brevoRows.map(r => [r.event, r.count]));
    }
    res.json(stats);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Templates known to Core, plus Brevo ids seen in outbox payloads (last 90 days)
// that have no email_template_id row, so they can still be filtered on.
router.get('/api/message-outbox/templates', async (req, res) => {
  try {
    const rows = await query(
      req,
      `SELECT t."templateId"::int AS "templateId", t."templateName", t."templateType", COALESCE(u.count, 0)::int AS count
       FROM email_template_id t
       LEFT JOIN (
         SELECT tpl.id, COUNT(*) AS count
         FROM core_message_outbox o ${TEMPLATE_JOIN}
         WHERE o."createdAt" > NOW() - INTERVAL '90 days' AND tpl.id IS NOT NULL
         GROUP BY tpl.id
       ) u ON u.id = t."templateId"
       UNION ALL
       SELECT tpl.id, NULL, NULL, COUNT(*)::int
       FROM core_message_outbox o ${TEMPLATE_JOIN}
       WHERE o."createdAt" > NOW() - INTERVAL '90 days' AND tpl.id IS NOT NULL
         AND NOT EXISTS (SELECT 1 FROM email_template_id t WHERE t."templateId" = tpl.id)
       GROUP BY tpl.id`
    );
    const byId = new Map();
    for (const r of rows) {
      const t = byId.get(r.templateId) || { templateId: r.templateId, templateName: r.templateName, types: [], count: r.count };
      if (r.templateType !== null) t.types.push(CORE_EMAIL_TYPES[r.templateType] ?? String(r.templateType));
      byId.set(r.templateId, t);
    }
    const templates = [...byId.values()].sort((a, b) =>
      (!a.templateName - !b.templateName) || (a.templateName || '').localeCompare(b.templateName || '') || a.templateId - b.templateId);
    res.json({ templates });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ─── Helpers: template test ───────────────────────────────────────────────────
// A test send reuses the Brevo payload of an email Core already sent with that
// template, so the params have the real shape. Only these keys are carried over;
// anything that could reach another person (cc, bcc, messageVersions) or carries
// Core-specific headers is dropped. The recipient must be typed in and may not
// be any of the original recipients.
const TEST_KEEP_KEYS = ['sender', 'subject', 'replyTo', 'templateId', 'params'];
const TEST_EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

function payloadRecipients(payload) {
  return ['to', 'cc', 'bcc']
    .flatMap(k => (Array.isArray(payload?.[k]) ? payload[k] : []))
    .concat((payload?.messageVersions || []).flatMap(v => [...(v.to || []), ...(v.cc || []), ...(v.bcc || [])]))
    .map(r => String(r?.email || '').trim().toLowerCase())
    .filter(Boolean);
}

async function loadSentSample(req, templateId, { offset = 0, id = null } = {}) {
  const params = [templateId];
  let where = 'o.channel = 0 AND o.status = 2 AND tpl.id = $1';
  if (id) { params.push(id); where += ` AND o.id = $${params.length}`; }
  const rows = await query(
    req,
    `SELECT o.id, o.payload, o."sentAt", o."createdAt", count(*) OVER ()::int AS total
     FROM core_message_outbox o ${TEMPLATE_JOIN}
     WHERE ${where}
     ORDER BY o."sentAt" DESC NULLS LAST, o."createdAt" DESC
     OFFSET ${Math.max(0, parseInt(offset) || 0)} LIMIT 1`,
    params
  );
  if (!rows.length) return null;
  let payload;
  try { payload = JSON.parse(rows[0].payload); } catch { payload = null; }
  return { ...rows[0], payload };
}

// Latest sent email for a template (offset steps back through older ones).
router.get('/api/message-outbox/template-test/sample', async (req, res) => {
  try {
    const templateId = parseInt(req.query.templateId);
    if (!Number.isInteger(templateId)) return res.status(400).json({ error: 'templateId required' });
    const offset = Math.max(0, parseInt(req.query.offset) || 0);
    const s = await loadSentSample(req, templateId, { offset });
    if (!s) return res.json({ sample: null, total: 0, offset });
    if (!s.payload || typeof s.payload !== 'object') return res.status(422).json({ error: `Outbox row ${s.id} has a payload that is not JSON` });
    const p = s.payload;
    res.json({
      total: s.total,
      offset,
      sample: {
        id: s.id,
        sentAt: s.sentAt,
        createdAt: s.createdAt,
        to: p.to || [],
        sender: p.sender || null,
        subject: p.subject || null,
        replyTo: p.replyTo || null,
        params: p.params && typeof p.params === 'object' ? p.params : {},
        attachments: (p.attachment || []).map(a => a.name || a.url || 'attachment'),
        droppedKeys: Object.keys(p).filter(k => !TEST_KEEP_KEYS.includes(k) && k !== 'to' && k !== 'attachment'),
      },
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Sends one test email straight through Brevo (not via the outbox).
router.post('/api/message-outbox/template-test/send', async (req, res) => {
  const key = process.env.BREVO_API_KEY;
  if (!key) return res.status(500).json({ error: 'BREVO_API_KEY is not set in helper/.env' });
  try {
    const { sourceId = null, to = {}, params = {}, includeAttachments = false } = req.body || {};
    const templateId = parseInt(req.body?.templateId);
    if (!Number.isInteger(templateId)) return res.status(400).json({ error: 'templateId required' });
    const email = String(to.email || '').trim();
    if (!TEST_EMAIL_RE.test(email)) return res.status(400).json({ error: 'Enter a valid recipient email' });
    if (params === null || typeof params !== 'object' || Array.isArray(params)) return res.status(400).json({ error: 'params must be an object' });

    let source = null;
    if (sourceId) {
      source = await loadSentSample(req, templateId, { id: sourceId });
      if (!source || !source.payload) return res.status(404).json({ error: `Sent outbox row ${sourceId} for template ${templateId} not found` });
      if (payloadRecipients(source.payload).includes(email.toLowerCase())) {
        return res.status(400).json({ error: 'The recipient must be changed — this address received the original email' });
      }
    }

    const payload = {};
    for (const k of TEST_KEEP_KEYS) if (source?.payload?.[k] !== undefined) payload[k] = source.payload[k];
    payload.templateId = templateId;
    payload.to = [{ email, ...(to.name ? { name: String(to.name) } : {}) }];
    if (Object.keys(params).length) payload.params = params; else delete payload.params;
    if (includeAttachments && Array.isArray(source?.payload?.attachment) && source.payload.attachment.length) {
      payload.attachment = source.payload.attachment;
    }
    payload.tags = ['lc-helper-template-test'];

    const r = await fetch('https://api.brevo.com/v3/smtp/email', {
      method: 'POST',
      headers: { 'api-key': key, 'content-type': 'application/json', accept: 'application/json' },
      body: JSON.stringify(payload),
    });
    const text = await r.text();
    let parsed;
    try { parsed = JSON.parse(text); } catch (_) { parsed = { raw: text }; }
    if (!r.ok) return res.status(r.status).json({ error: `Brevo ${r.status}: ${parsed.message || text}`, brevo: parsed });
    res.json({ ok: true, messageId: parsed.messageId || null });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

router.get('/api/message-outbox/:id', async (req, res) => {
  try {
    const rows = await query(
      req,
      `SELECT o.*, ${TEMPLATE_COLS} FROM core_message_outbox o ${TEMPLATE_JOIN} WHERE o.id = $1`,
      [req.params.id]
    );
    if (!rows.length) return res.status(404).json({ error: 'Not found' });
    const r = rows[0];
    let decodedPayload = null;
    try { decodedPayload = JSON.parse(r.payload); } catch { decodedPayload = r.payload; }
    const brevoEvents = r.providerMessageId && await brevoSupported(req)
      ? await query(
          req,
          `SELECT *
           FROM brevo_webhook_event
           WHERE "messageId" = $1
           ORDER BY COALESCE("eventAt", "receivedAt"), id`,
          [r.providerMessageId]
        )
      : [];
    res.json({
      ...r,
      brevoEvents,
      channel: OUTBOX_CHANNELS[r.channel] ?? r.channel,
      status: OUTBOX_STATUSES[r.status] ?? r.status,
      lastErrorClass: r.lastErrorClass === null ? null : (OUTBOX_ERROR_CLASSES[r.lastErrorClass] ?? r.lastErrorClass),
      templateTypes: templateTypeNames(r.templateTypes),
      decodedPayload,
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

router.post('/api/message-outbox/:id/retry', async (req, res) => {
  try {
    const id = req.params.id;
    const existing = await query(req, `SELECT id FROM core_message_outbox WHERE id = $1`, [id]);
    if (!existing.length) return res.status(404).json({ error: 'Not found' });

    await query(
      req,
      `UPDATE core_message_outbox
       SET status = 0, "nextAttemptAt" = NOW(), "attemptCount" = 0, "firstTeamsNotifiedAt" = NULL, "updatedAt" = NOW()
       WHERE id = $1`,
      [id]
    );

    const identifier = `messageOutbox_${id}_manual_${Date.now()}`;
    const payload = JSON.stringify({ outboxId: id });
    await query(
      req,
      `INSERT INTO serverpod_future_call (name, "time", "serializedObject", "serverId", identifier)
       VALUES ($1, NOW(), $2, 'helper', $3)`,
      ['messageOutboxDispatchFutureCall', payload, identifier]
    );

    const updated = await query(req, `SELECT * FROM core_message_outbox WHERE id = $1`, [id]);
    const r = updated[0];
    res.json({
      ok: true,
      row: {
        ...r,
        channel: OUTBOX_CHANNELS[r.channel] ?? r.channel,
        status: OUTBOX_STATUSES[r.status] ?? r.status,
      },
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ─── Helpers: send a pending message now ──────────────────────────────────────
// Core's dispatcher claims a row with a plain read-then-update (no status check
// in the UPDATE), so two dispatches running at once can send the same message
// twice. Sending now therefore never adds a second dispatch: it moves the
// scheduled one (identifier messageOutbox_<id>, or an earlier helper
// messageOutbox_<id>_manual_…) to NOW() (+ delaySeconds) and drops duplicates,
// and only inserts a new one when none exists. Rows touched in the last 30 s
// are refused because the server may be picking them up right now.
async function sendPendingNow(client, id, delaySeconds = 0) {
  try {
    await client.query('BEGIN');
    const { rows } = await client.query(
      `SELECT status, "updatedAt" > NOW() - interval '30 seconds' AS recently_touched
       FROM core_message_outbox WHERE id = $1 FOR UPDATE`,
      [id]
    );
    if (!rows.length) { await client.query('ROLLBACK'); return { ok: false, code: 404, error: 'Not found' }; }
    const status = OUTBOX_STATUSES[rows[0].status] ?? rows[0].status;
    if (status !== 'pending') {
      await client.query('ROLLBACK');
      return { ok: false, code: 409, error: `Only pending messages can be sent now (this one is ${status}). Use Retry for failed/dead.` };
    }
    if (rows[0].recently_touched) {
      await client.query('ROLLBACK');
      return { ok: false, code: 409, error: 'Changed in the last 30 seconds — the server may be sending it right now. Refresh and try again shortly.' };
    }

    const identifier = `messageOutbox_${id}`;
    const manualPrefix = `messageOutbox_${id}_manual_`;
    const { rows: calls } = await client.query(
      `SELECT id FROM serverpod_future_call
       WHERE name = 'messageOutboxDispatchFutureCall'
         AND (identifier = $1 OR left(identifier, length($2)) = $2)
       ORDER BY "time", id`,
      [identifier, manualPrefix]
    );

    let action, created = false;
    if (calls.length) {
      await client.query(
        `UPDATE serverpod_future_call SET "time" = NOW() + make_interval(secs => $2) WHERE id = $1`,
        [calls[0].id, delaySeconds]
      );
      if (calls.length > 1) {
        await client.query(`DELETE FROM serverpod_future_call WHERE id = ANY($1::bigint[])`, [calls.slice(1).map(c => c.id)]);
      }
      action = calls.length > 1 ? `moved scheduled dispatch to now, removed ${calls.length - 1} duplicate(s)` : 'moved scheduled dispatch to now';
    } else {
      await client.query(
        `INSERT INTO serverpod_future_call (name, "time", "serializedObject", "serverId", identifier)
         VALUES ('messageOutboxDispatchFutureCall', NOW() + make_interval(secs => $3), $1, 'helper', $2)`,
        [JSON.stringify({ outboxId: id }), identifier, delaySeconds]
      );
      action = 'no dispatch was scheduled — created one';
      created = true;
    }

    await client.query(
      `UPDATE core_message_outbox SET "nextAttemptAt" = NOW() + make_interval(secs => $2), "updatedAt" = NOW() WHERE id = $1`,
      [id, delaySeconds]
    );
    await client.query('COMMIT');
    return { ok: true, action, created };
  } catch (e) {
    await client.query('ROLLBACK').catch(() => {});
    return { ok: false, code: 500, error: e.message };
  }
}

// ─── Routes: send one pending message now ─────────────────────────────────────
router.post('/api/message-outbox/:id/send-now', async (req, res) => {
  const client = await getPool(req).connect();
  try {
    const r = await sendPendingNow(client, req.params.id);
    if (!r.ok) return res.status(r.code).json({ error: r.error });
    res.json({ ok: true, action: r.action });
  } finally {
    client.release();
  }
});

// ─── Routes: send all pending messages (oldest first, spaced out) ─────────────
// { dryRun: true } only counts. Otherwise sends up to `limit` (max 200) oldest
// pending messages, one transaction each, spacing their dispatch SEND_ALL_GAP_S
// seconds apart so Brevo and the database are not hit all at once.
const SEND_ALL_MAX = 200;
const SEND_ALL_GAP_S = 2;

router.post('/api/message-outbox/send-all-pending', async (req, res) => {
  const { dryRun = false, confirm = false, channel = '' } = req.body || {};
  const limit = Math.min(Math.max(parseInt(req.body?.limit) || SEND_ALL_MAX, 1), SEND_ALL_MAX);
  const channelIdx = channel ? OUTBOX_CHANNELS.indexOf(channel) : -1;
  if (channel && channelIdx < 0) return res.status(400).json({ error: `Unknown channel ${channel}` });
  const client = await getPool(req).connect();
  try {
    const params = channelIdx >= 0 ? [channelIdx] : [];
    const channelSql = channelIdx >= 0 ? 'AND channel = $1' : '';
    const { rows: [summary] } = await client.query(
      `SELECT count(*)::int AS total, min("createdAt") AS oldest
       FROM core_message_outbox
       WHERE status = 0 AND "updatedAt" <= NOW() - interval '30 seconds' ${channelSql}`,
      params
    );
    if (dryRun) return res.json({ total: summary.total, oldest: summary.oldest, willSend: Math.min(summary.total, limit), max: SEND_ALL_MAX, gapSeconds: SEND_ALL_GAP_S });
    if (confirm !== true) return res.status(400).json({ error: 'confirm required' });

    const { rows: ids } = await client.query(
      `SELECT id FROM core_message_outbox
       WHERE status = 0 AND "updatedAt" <= NOW() - interval '30 seconds' ${channelSql}
       ORDER BY "createdAt", id LIMIT ${limit}`,
      params
    );
    const result = { scheduled: 0, created: 0, skipped: 0, errors: [] };
    for (let i = 0; i < ids.length; i++) {
      const r = await sendPendingNow(client, ids[i].id, result.scheduled * SEND_ALL_GAP_S);
      if (r.ok) {
        result.scheduled++;
        if (r.created) result.created++;
      } else if (r.code === 409 || r.code === 404) {
        result.skipped++;
      } else {
        result.errors.push({ id: ids[i].id, error: r.error });
        if (result.errors.length >= 5) break;
      }
    }
    res.json({ ...result, remaining: Math.max(0, summary.total - result.scheduled - result.skipped), finishesInSeconds: Math.max(0, (result.scheduled - 1) * SEND_ALL_GAP_S) });
  } catch (e) {
    res.status(500).json({ error: e.message });
  } finally {
    client.release();
  }
});

router.post('/api/message-outbox/:id/kill', async (req, res) => {
  try {
    const id = req.params.id;
    const existing = await query(req, `SELECT id FROM core_message_outbox WHERE id = $1`, [id]);
    if (!existing.length) return res.status(404).json({ error: 'Not found' });

    const killMsg = `killed by operator at ${new Date().toISOString()}`;
    await query(
      req,
      `UPDATE core_message_outbox
       SET status = 4, "deadAt" = NOW(), "lastErrorClass" = 0, "lastErrorBody" = $1, "updatedAt" = NOW()
       WHERE id = $2`,
      [killMsg, id]
    );
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ─── Routes: Brevo email resend (manual replay from session-log payloads) ────
router.post('/api/email/resend', async (req, res) => {
  const key = process.env.BREVO_API_KEY;
  if (!key) {
    return res.status(500).json({ error: 'BREVO_API_KEY is not set in helper/.env' });
  }
  const payload = req.body;
  if (!payload || typeof payload !== 'object') {
    return res.status(400).json({ error: 'Body must be the parsed Brevo payload (JSON object).' });
  }
  try {
    const r = await fetch('https://api.brevo.com/v3/smtp/email', {
      method: 'POST',
      headers: {
        'api-key': key,
        'content-type': 'application/json',
        accept: 'application/json',
      },
      body: JSON.stringify(payload),
    });
    const text = await r.text();
    let parsed;
    try { parsed = JSON.parse(text); } catch (_) { parsed = { raw: text }; }
    if (!r.ok) {
      return res.status(r.status).json({ error: `Brevo ${r.status}`, brevo: parsed });
    }
    res.json({ ok: true, status: r.status, brevo: parsed });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

module.exports = router;
