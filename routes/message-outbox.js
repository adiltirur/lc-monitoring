const router = require('express').Router();
const { getPool, paginate, query } = require('../lib/db');

// ─── Routes: Message Outbox (Brevo email/SMS durable queue) ───────────────────
const OUTBOX_CHANNELS = ['email', 'sms'];
const OUTBOX_STATUSES = ['pending', 'sending', 'sent', 'failed', 'dead'];
const OUTBOX_ERROR_CLASSES = ['permanent', 'transient'];

router.get('/api/message-outbox', async (req, res) => {
  try {
    const { status, channel, dateFrom, dateTo, correlationId, recipient, lastHttpStatus, lastErrorClass, page = 1, pageSize = 50 } = req.query;
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
    const where = clauses.length ? 'WHERE ' + clauses.join(' AND ') : '';
    const baseSql = `SELECT id, channel, status, "attemptCount", "maxAttempts", "lastHttpStatus", "lastErrorClass", "nextAttemptAt", "firstTeamsNotifiedAt", "correlationId", "createdAt", "updatedAt", "sentAt", "deadAt" FROM core_message_outbox ${where} ORDER BY "createdAt" DESC`;
    const countSql = `SELECT COUNT(*) FROM core_message_outbox ${where}`;
    const result = await paginate(req, baseSql, countSql, params, parseInt(page), parseInt(pageSize));

    result.rows = result.rows.map(r => ({
      ...r,
      channel: OUTBOX_CHANNELS[r.channel] ?? r.channel,
      status: OUTBOX_STATUSES[r.status] ?? r.status,
      lastErrorClass: r.lastErrorClass === null ? null : (OUTBOX_ERROR_CLASSES[r.lastErrorClass] ?? r.lastErrorClass),
    }));

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
    res.json(stats);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

router.get('/api/message-outbox/:id', async (req, res) => {
  try {
    const rows = await query(
      req,
      `SELECT * FROM core_message_outbox WHERE id = $1`,
      [req.params.id]
    );
    if (!rows.length) return res.status(404).json({ error: 'Not found' });
    const r = rows[0];
    let decodedPayload = null;
    try { decodedPayload = JSON.parse(r.payload); } catch { decodedPayload = r.payload; }
    res.json({
      ...r,
      channel: OUTBOX_CHANNELS[r.channel] ?? r.channel,
      status: OUTBOX_STATUSES[r.status] ?? r.status,
      lastErrorClass: r.lastErrorClass === null ? null : (OUTBOX_ERROR_CLASSES[r.lastErrorClass] ?? r.lastErrorClass),
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

// ─── Routes: send a pending message now ───────────────────────────────────────
// Core's dispatcher claims a row with a plain read-then-update (no status check
// in the UPDATE), so two dispatches running at once can send the same message
// twice. "Send now" therefore never adds a second dispatch: it moves the
// scheduled one (identifier messageOutbox_<id>, or an earlier helper
// messageOutbox_<id>_manual_…) to NOW() and drops duplicates, and only inserts
// a new one when none exists. Rows touched in the last 30 s are refused because
// the server may be picking them up right now.
router.post('/api/message-outbox/:id/send-now', async (req, res) => {
  const id = req.params.id;
  const client = await getPool(req).connect();
  try {
    await client.query('BEGIN');
    const { rows } = await client.query(
      `SELECT status, "updatedAt" > NOW() - interval '30 seconds' AS recently_touched
       FROM core_message_outbox WHERE id = $1 FOR UPDATE`,
      [id]
    );
    if (!rows.length) { await client.query('ROLLBACK'); return res.status(404).json({ error: 'Not found' }); }
    const status = OUTBOX_STATUSES[rows[0].status] ?? rows[0].status;
    if (status !== 'pending') {
      await client.query('ROLLBACK');
      return res.status(409).json({ error: `Only pending messages can be sent now (this one is ${status}). Use Retry for failed/dead.` });
    }
    if (rows[0].recently_touched) {
      await client.query('ROLLBACK');
      return res.status(409).json({ error: 'Changed in the last 30 seconds — the server may be sending it right now. Refresh and try again shortly.' });
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

    let action;
    if (calls.length) {
      await client.query(`UPDATE serverpod_future_call SET "time" = NOW() WHERE id = $1`, [calls[0].id]);
      if (calls.length > 1) {
        await client.query(`DELETE FROM serverpod_future_call WHERE id = ANY($1::bigint[])`, [calls.slice(1).map(c => c.id)]);
      }
      action = calls.length > 1 ? `moved scheduled dispatch to now, removed ${calls.length - 1} duplicate(s)` : 'moved scheduled dispatch to now';
    } else {
      await client.query(
        `INSERT INTO serverpod_future_call (name, "time", "serializedObject", "serverId", identifier)
         VALUES ('messageOutboxDispatchFutureCall', NOW(), $1, 'helper', $2)`,
        [JSON.stringify({ outboxId: id }), identifier]
      );
      action = 'no dispatch was scheduled — created one';
    }

    await client.query(
      `UPDATE core_message_outbox SET "nextAttemptAt" = NOW(), "updatedAt" = NOW() WHERE id = $1`,
      [id]
    );
    await client.query('COMMIT');
    res.json({ ok: true, action });
  } catch (e) {
    await client.query('ROLLBACK').catch(() => {});
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
