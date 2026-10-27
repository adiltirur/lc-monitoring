// ═════════════════════════════════════════════════════════════════════════
// MESSAGE OUTBOX
// ═════════════════════════════════════════════════════════════════════════
let moFilters = {};
const MO_STATUSES = ['pending','sending','sent','failed','dead'];
const MO_CHANNELS = ['email','sms'];
const MO_STATUS_PILL = { pending: '', sending: 'info', sent: 'ok', failed: 'warn', dead: 'err' };

// Brevo delivery events (from Core's brevo_webhook_event, via the webhook).
const MO_BREVO_EVENTS = ['request','delivered','unique_opened','opened','click','proxy_open','deferred','soft_bounce','hard_bounce','invalid_email','blocked','spam','unsubscribed','error'];
const MO_BREVO_GOOD = new Set(['delivered','unique_opened','opened','click','proxy_open']);
const MO_BREVO_WARN = new Set(['deferred','soft_bounce']);
const MO_BREVO_BAD = new Set(['hard_bounce','invalid_email','blocked','spam','unsubscribed','error']);

function moBrevoPill(event, title = '') {
  if (!event) return '<span class="faint">—</span>';
  const cls = MO_BREVO_GOOD.has(event) ? 'ok' : MO_BREVO_WARN.has(event) ? 'warn' : MO_BREVO_BAD.has(event) ? 'err' : '';
  return `<span class="pill ${cls}" title="${escHtml(title)}">${escHtml(event.replace(/_/g, ' '))}</span>`;
}

function moBrevoTimeline(detail) {
  if (!detail.providerMessageId) {
    return '<div class="faint" style="font-size:12px">No Brevo messageId on this row — it was sent before Core stored message ids, or it was never accepted by Brevo.</div>';
  }
  const events = detail.brevoEvents || [];
  const rows = events.map(ev => `<div class="list-row" style="justify-content:flex-start;padding:6px 0">
      <span class="list-meta" style="margin:0;width:150px;flex-shrink:0">${escHtml(deTime(ev.eventAt || ev.receivedAt))}</span>
      <span class="row-sm" style="white-space:nowrap">${moBrevoPill(ev.event)}${ev.occurrences > 1 ? `<b style="font-size:12px">×${ev.occurrences}</b><span class="faint" style="font-size:11.5px">latest</span>` : ''}</span>
      <span style="font-size:12px;word-break:break-all">${escHtml(ev.reason || '')}</span>
    </div>`).join('');
  return `<div class="list-meta" style="margin:0 0 6px;word-break:break-all">messageId: ${escHtml(detail.providerMessageId)}</div>
    ${rows || '<div class="faint" style="font-size:12px">No events from Brevo yet.</div>'}`;
}

function moBrevoStats(brevo) {
  if (!brevo) return '';
  const entries = Object.entries(brevo);
  if (!entries.length) return '';
  return `<div class="mo-stat-line"><span class="mo-stat-label">Brevo · 30 days</span>${entries.map(([ev, n]) => `<span class="row-sm">${moBrevoPill(ev)}<b class="mono">${n}</b></span>`).join('')}</div>`;
}

// "Name · type" for a row's Brevo template; the id alone when Core has no mapping for it.
function moTemplateLabel(row) {
  if (row.templateId === null || row.templateId === undefined) return '';
  const name = row.templateName || (row.templateTypes || []).join(', ');
  return name || `#${row.templateId}`;
}

function moTemplateTitle(row) {
  if (row.templateId === null || row.templateId === undefined) return '';
  return [`Brevo template ${row.templateId}`, row.templateName, (row.templateTypes || []).join(', ')].filter(Boolean).join(' · ');
}

function moExtractRecipient(row) {
  return row.recipient || '—';
}

function moStatsBanner(stats) {
  if (!stats) return '';
  const chan = (ch) => {
    const s = stats[ch] || {};
    const n = (label, v, cls) => `<span class="pill ${cls}">${label}<b class="mono">${v || 0}</b></span>`;
    return `<div class="mo-stat-line"><span class="mo-stat-label">${ch === 'sms' ? 'SMS' : 'Email'}</span>
      ${n('sent 24h', s.sentLast24h, 'ok')}${n('pending', s.pending, '')}${n('sending', s.sending, 'info')}${n('failed', s.failed, s.failed ? 'warn' : '')}${n('dead', s.dead, s.dead ? 'err' : '')}
    </div>`;
  };
  return `<div class="mo-stats">${MO_CHANNELS.map(chan).join('')}</div>`;
}

async function retryMessageOutbox(id) {
  if (!confirm('Retry this message now? Status will reset to pending and a dispatch will be scheduled.')) return;
  try {
    const res = await apiFetch(`/api/message-outbox/${id}/retry`, { method: 'POST' });
    if (res && res.error) throw new Error(res.error);
    showToast('✓ Retry scheduled');
    renderMessageOutbox(document.getElementById('content'));
  } catch (e) {
    alert('Retry failed: ' + e.message);
  }
}

async function sendNowMessageOutbox(id) {
  const env = document.getElementById('envBtn')?.dataset.env || 'dev';
  if (!confirm(`Send this pending message now on ${env.toUpperCase()}?\n\nThe server's scheduled dispatch is moved to now (a new one is only created if none exists), so it is sent once, within a few seconds.`)) return;
  try {
    const res = await apiFetch(`/api/message-outbox/${id}/send-now`, { method: 'POST' });
    if (res && res.error) throw new Error(res.error);
    showToast(`✓ Sending — ${res.action}`);
    renderMessageOutbox(document.getElementById('content'));
  } catch (e) {
    alert('Send now failed: ' + e.message);
  }
}

function moPendingTotal(stats) {
  if (!stats) return 0;
  return MO_CHANNELS.reduce((n, ch) => n + ((stats[ch] && stats[ch].pending) || 0), 0);
}

async function sendAllPendingMessageOutbox() {
  const env = document.getElementById('envBtn')?.dataset.env || 'dev';
  const channel = moFilters.channel || '';
  try {
    const preview = await apiPost('/api/message-outbox/send-all-pending', { dryRun: true, channel });
    if (!preview.total) { showToast('No pending messages to send (messages changed in the last 30 s are left alone)'); return; }
    const capped = preview.total > preview.max ? `\nOnly the oldest ${preview.max} are sent per click.` : '';
    const msg = `Send ${preview.willSend} pending ${channel || 'email/SMS'} message(s) on ${env.toUpperCase()}?\n\n` +
      `Oldest waiting since ${deTime(preview.oldest)}.\n` +
      `They are dispatched ${preview.gapSeconds} s apart (about ${Math.ceil(Math.max(0, preview.willSend - 1) * preview.gapSeconds / 60)} min in total), each exactly once.${capped}`;
    if (!confirm(msg)) return;
    const r = await apiPost('/api/message-outbox/send-all-pending', { confirm: true, channel });
    const parts = [`${r.scheduled} scheduled`];
    if (r.created) parts.push(`${r.created} had no dispatch (created)`);
    if (r.skipped) parts.push(`${r.skipped} skipped (changed meanwhile)`);
    if (r.remaining) parts.push(`${r.remaining} still pending — click again`);
    showToast(`✓ ${parts.join(' · ')}`);
    if (r.errors && r.errors.length) alert(`Some messages failed:\n${r.errors.map(e => `${e.id}: ${e.error}`).join('\n')}`);
    renderMessageOutbox(document.getElementById('content'));
  } catch (e) {
    alert('Send all failed: ' + e.message);
  }
}

async function killMessageOutbox(id) {
  if (!confirm('Mark this message DEAD? This stops all further retries.')) return;
  try {
    const res = await apiFetch(`/api/message-outbox/${id}/kill`, { method: 'POST' });
    if (res && res.error) throw new Error(res.error);
    showToast('✓ Message marked dead');
    renderMessageOutbox(document.getElementById('content'));
  } catch (e) {
    alert('Kill failed: ' + e.message);
  }
}

async function toggleMessageOutboxDetail(tr, id) {
  const existing = tr.nextElementSibling;
  if (existing && existing.classList.contains('expand-row')) {
    existing.remove();
    tr.classList.remove('active');
    return;
  }
  tr.classList.add('active');
  const expandTr = document.createElement('tr');
  expandTr.className = 'expand-row mo-detail';
  expandTr.innerHTML = `<td colspan="12"><div class="mo-detail-body faint">Loading…</div></td>`;
  tr.after(expandTr);

  try {
    const detail = await apiFetch(`/api/message-outbox/${id}`);
    const payloadStr = typeof detail.decodedPayload === 'object'
      ? JSON.stringify(detail.decodedPayload, null, 2)
      : String(detail.decodedPayload ?? '');
    const kv = (label, value) => `<div class="kv-row"><span class="kv-label">${label}</span><span class="kv-value mono">${value}</span></div>`;
    expandTr.innerHTML = `<td colspan="12"><div class="mo-detail-body">
      <div>
        <h4 class="section-label">Payload (decoded)</h4>
        <pre class="code mo-pre">${escHtml(payloadStr)}</pre>
      </div>
      <div>
        <h4 class="section-label">Last error body</h4>
        <pre class="code mo-pre"${detail.lastErrorBody ? ' style="color:var(--red)"' : ''}>${escHtml(detail.lastErrorBody || '(no error)')}</pre>
        <div class="mo-kv">
          ${kv('HTTP status', detail.lastHttpStatus ?? '—')}
          ${kv('Error class', escHtml(detail.lastErrorClass ?? '—'))}
          ${kv('Attempt', `${detail.attemptCount}/${detail.maxAttempts}`)}
          ${kv('Next attempt', escHtml(deTime(detail.nextAttemptAt)) || '—')}
          ${kv('First Teams ping', escHtml(deTime(detail.firstTeamsNotifiedAt)) || '—')}
          ${kv('Sent at', escHtml(deTime(detail.sentAt)) || '—')}
          ${kv('Dead at', escHtml(deTime(detail.deadAt)) || '—')}
          ${kv('Template', escHtml(moTemplateTitle(detail)) || '—')}
          ${kv('Correlation', escHtml(detail.correlationId) || '—')}
        </div>
      </div>
      <div style="grid-column:1 / -1">
        <h4 class="section-label">Brevo delivery</h4>
        ${moBrevoTimeline(detail)}
      </div>
    </div></td>`;
  } catch (e) {
    expandTr.innerHTML = `<td colspan="12"><div class="mo-detail-body" style="color:var(--red)">Failed to load: ${escHtml(e.message)}</div></td>`;
  }
}

async function renderMessageOutbox(el, page = 1) {
  el.innerHTML = pageWrap(pageHero('Message Outbox', { sub: 'Brevo email/SMS durable queue', live: true }) + loadingState());
  try {
    const p = new URLSearchParams({ ...moFilters, page, pageSize: 50 });
    const [data, stats, templates] = await Promise.all([
      apiFetch(`/api/message-outbox?${p}`),
      apiFetch(`/api/message-outbox/stats`).catch(() => null),
      apiFetch(`/api/message-outbox/templates`).then(r => r.templates || []).catch(() => []),
    ]);
    setConnStatus('connected');
    window._moTemplates = templates;

    const statusOpts = [{value:'',label:'All Statuses'}, ...MO_STATUSES.map(s => ({value:s, label:s}))];
    const channelOpts = [{value:'',label:'All Channels'}, ...MO_CHANNELS.map(c => ({value:c, label:c}))];
    const errorClassOpts = [{value:'',label:'Any'}, {value:'permanent',label:'permanent'}, {value:'transient',label:'transient'}];
    const templateOpts = [{value:'',label:'All Templates'}, ...templates.map(t => ({
      value: t.templateId,
      label: `${t.templateName || t.types.join(', ') || 'not in email_template_id'} (#${t.templateId})${t.count ? ` · ${t.count}` : ''}`,
    }))];
    if (moFilters.templateId && !templates.some(t => String(t.templateId) === String(moFilters.templateId))) {
      templateOpts.push({ value: moFilters.templateId, label: `#${moFilters.templateId}` });
    }
    const brevoOpts = [{value:'',label:'Any'}, {value:'none',label:'no event yet'}, ...MO_BREVO_EVENTS.map(e => ({value:e, label:e.replace(/_/g,' ')}))];

    const filterHtml =
      fSelect('Status', statusOpts, `oninput="moFilters.status=this.value"`, moFilters.status || '') +
      fSelect('Channel', channelOpts, `oninput="moFilters.channel=this.value"`, moFilters.channel || '') +
      fSelect('Template', templateOpts, `oninput="moFilters.templateId=this.value"`, moFilters.templateId || '') +
      fSelect('Error class', errorClassOpts, `oninput="moFilters.lastErrorClass=this.value"`, moFilters.lastErrorClass || '') +
      (data.brevoSupported ? fSelect('Brevo', brevoOpts, `oninput="moFilters.brevoStatus=this.value"`, moFilters.brevoStatus || '') : '') +
      fInput('From', `type="datetime-local" value="${moFilters.dateFrom||''}" oninput="moFilters.dateFrom=this.value"`) +
      fInput('To', `type="datetime-local" value="${moFilters.dateTo||''}" oninput="moFilters.dateTo=this.value"`) +
      fInput('Correlation', `placeholder="e.g. appointmentId" value="${escHtml(moFilters.correlationId||'')}" oninput="moFilters.correlationId=this.value"`) +
      fInput('Recipient', `placeholder="email or phone substring" value="${escHtml(moFilters.recipient||'')}" oninput="moFilters.recipient=this.value"`) +
      fInput('HTTP Status', `placeholder="e.g. 500" value="${escHtml(moFilters.lastHttpStatus||'')}" oninput="moFilters.lastHttpStatus=this.value"`) +
      `<div class="row-sm">${btnPrimary('Search', `renderMessageOutbox(document.getElementById('content'))`, { full: true })}${btnGhost('Clear', `moFilters={};renderMessageOutbox(document.getElementById('content'))`)}</div>`;

    const rowsHtml = data.rows.map(row => {
      const canRetry = row.status === 'failed' || row.status === 'dead';
      const canKill = row.status === 'pending' || row.status === 'sending' || row.status === 'failed';
      const actions = [
        row.status === 'pending' ? `<button class="btn btn-sm" onclick="event.stopPropagation();sendNowMessageOutbox('${escHtml(row.id)}')">Send now</button>` : '',
        canRetry ? `<button class="btn btn-sm" onclick="event.stopPropagation();retryMessageOutbox('${escHtml(row.id)}')">Retry</button>` : '',
        canKill ? `<button class="btn btn-sm btn-danger" onclick="event.stopPropagation();killMessageOutbox('${escHtml(row.id)}')">Kill</button>` : '',
      ].filter(Boolean).join('');

      const http = row.lastHttpStatus;
      return `<tr class="mo-row" data-id="${escHtml(row.id)}">
        <td class="mono" style="white-space:nowrap">${escHtml(deTime(row.createdAt))}</td>
        <td>${escHtml(row.channel)}</td>
        <td><span class="pill ${MO_STATUS_PILL[row.status] ?? ''}">${escHtml(row.status)}</span></td>
        <td class="mono">${row.attemptCount}/${row.maxAttempts}</td>
        <td class="mono" style="white-space:nowrap">${escHtml(deTime(row.nextAttemptAt)) || '—'}</td>
        <td class="mono${http >= 500 ? ' err' : ''}"${http >= 400 && http < 500 ? ' style="color:rgb(var(--tw-amber-700))"' : ''}>${http ?? '—'}</td>
        <td>${escHtml(row.lastErrorClass) || '—'}</td>
        <td style="max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${escHtml(moTemplateTitle(row))}">${escHtml(moTemplateLabel(row)) || '—'}</td>
        <td>${moBrevoPill(row.brevoStatus, row.brevoStatusAt ? deTime(row.brevoStatusAt) : '')}</td>
        <td style="max-width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${escHtml(row.correlationId||'')}">${escHtml(row.correlationId) || '—'}</td>
        <td class="mono muted" title="${escHtml(String(row.id))}">${escHtml(String(row.id).slice(0,8))}…</td>
        <td><div class="row-sm">${actions || '—'}</div></td>
      </tr>`;
    }).join('');

    el.innerHTML = pageWrap(
      pageHero('Message Outbox', {
        sub: 'Brevo email/SMS durable queue — monitor, retry, kill',
        live: true,
        actions: btnGhost('Test template', 'motToggle()', { icon: 'science' }) +
          (moPendingTotal(stats) ? btnGhost(`Send all pending (${moPendingTotal(stats)})`, 'sendAllPendingMessageOutbox()', { icon: 'send' }) : '') +
          `<button class="btn btn-ghost" onclick="renderMessageOutbox(document.getElementById('content'))" title="Refresh"><span class="material-symbols-outlined">refresh</span></button>`,
      }) +
      '<div id="motPanel"></div>' +
      moStatsBanner(stats) +
      moBrevoStats(stats && stats.brevo) +
      filterCard(filterHtml, 6) +
      tableShell(['Created','Channel','Status','Attempt','Next','HTTP','Err cls','Template','Brevo','Correlation','ID','Actions'], rowsHtml, 'moPaging')
    );

    document.querySelectorAll('.mo-row').forEach(tr => {
      tr.addEventListener('click', () => toggleMessageOutboxDetail(tr, tr.dataset.id));
    });

    motRender();
    renderPagination(document.getElementById('moPaging'), data, (p) => renderMessageOutbox(document.getElementById('content'), p));
  } catch (e) {
    setConnStatus('error');
    el.innerHTML = pageWrap(pageHero('Message Outbox') + errorState(e.message));
  }
}
