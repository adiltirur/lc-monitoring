// ═════════════════════════════════════════════════════════════════════════
// MESSAGE OUTBOX
// ═════════════════════════════════════════════════════════════════════════
let moFilters = {};
const MO_STATUSES = ['pending','sending','sent','failed','dead'];
const MO_CHANNELS = ['email','sms'];
const MO_STATUS_PILL = {
  pending:  ['bg-slate-100','text-slate-700'],
  sending:  ['bg-blue-100','text-blue-700'],
  sent:     ['bg-emerald-100','text-emerald-700'],
  failed:   ['bg-amber-100','text-amber-800'],
  dead:     ['bg-red-100','text-red-700'],
};

// Brevo delivery events (from Core's brevo_webhook_event, via the webhook).
const MO_BREVO_EVENTS = ['request','delivered','unique_opened','opened','click','proxy_open','deferred','soft_bounce','hard_bounce','invalid_email','blocked','spam','unsubscribed','error'];
const MO_BREVO_GOOD = new Set(['delivered','unique_opened','opened','click','proxy_open']);
const MO_BREVO_WARN = new Set(['deferred','soft_bounce']);
const MO_BREVO_BAD = new Set(['hard_bounce','invalid_email','blocked','spam','unsubscribed','error']);

function moBrevoPill(event, title = '') {
  if (!event) return '<span class="text-xs opacity-50">—</span>';
  const cls = MO_BREVO_GOOD.has(event) ? 'bg-emerald-100 text-emerald-700'
    : MO_BREVO_WARN.has(event) ? 'bg-amber-100 text-amber-800'
    : MO_BREVO_BAD.has(event) ? 'bg-red-100 text-red-700'
    : 'bg-slate-100 text-slate-700';
  return `<span class="px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider ${cls}" title="${escHtml(title)}">${escHtml(event.replace(/_/g, ' '))}</span>`;
}

function moBrevoTimeline(detail) {
  if (!detail.providerMessageId) {
    return '<div class="text-xs opacity-60">No Brevo messageId on this row — it was sent before Core stored message ids, or it was never accepted by Brevo.</div>';
  }
  const events = detail.brevoEvents || [];
  const rows = events.map(ev => `<div class="flex items-start gap-3 py-1.5 border-b border-outline-variant/20 last:border-0">
      <div class="mono-text text-[11px] opacity-70 whitespace-nowrap w-40">${escHtml(deTime(ev.eventAt || ev.receivedAt))}</div>
      <div class="whitespace-nowrap">${moBrevoPill(ev.event)}${ev.occurrences > 1 ? ` <span class="text-xs font-bold">×${ev.occurrences}</span> <span class="text-[10px] opacity-60">latest</span>` : ''}</div>
      <div class="text-xs break-all">${escHtml(ev.reason || '')}</div>
    </div>`).join('');
  return `<div class="text-[11px] mono-text opacity-70 mb-2 break-all">messageId: ${escHtml(detail.providerMessageId)}</div>
    ${rows || '<div class="text-xs opacity-60">No events from Brevo yet.</div>'}`;
}

function moBrevoStats(brevo) {
  if (!brevo) return '';
  const entries = Object.entries(brevo);
  if (!entries.length) return '';
  return `<div class="bg-surface-container-lowest rounded-lg p-3 border border-outline-variant/20 mb-4">
    <div class="text-xs font-bold uppercase tracking-wider text-on-surface-variant mb-2">Brevo events · last 30 days</div>
    <div class="flex flex-wrap gap-2 text-xs">${entries.map(([ev, n]) => `<span class="inline-flex items-center gap-1">${moBrevoPill(ev)}<b>${n}</b></span>`).join('')}</div>
  </div>`;
}

function moExtractRecipient(row) {
  return row.recipient || '—';
}

function moStatsBanner(stats) {
  if (!stats) return '';
  const chan = (ch) => {
    const s = stats[ch] || {};
    return `<div class="bg-surface-container-lowest rounded-lg p-3 border border-outline-variant/20">
      <div class="text-xs font-bold uppercase tracking-wider text-on-surface-variant mb-2">${ch}</div>
      <div class="flex flex-wrap gap-2 text-xs">
        <span class="px-2 py-0.5 rounded bg-emerald-100 text-emerald-700">🟢 sent 24h: <b>${s.sentLast24h||0}</b></span>
        <span class="px-2 py-0.5 rounded bg-slate-100 text-slate-700">⚪ pending: <b>${s.pending||0}</b></span>
        <span class="px-2 py-0.5 rounded bg-blue-100 text-blue-700">🔵 sending: <b>${s.sending||0}</b></span>
        <span class="px-2 py-0.5 rounded bg-amber-100 text-amber-800">🟠 failed: <b>${s.failed||0}</b></span>
        <span class="px-2 py-0.5 rounded bg-red-100 text-red-700">🔴 dead: <b>${s.dead||0}</b></span>
      </div>
    </div>`;
  };
  return `<div class="grid grid-cols-1 md:grid-cols-2 gap-3 mb-4">${MO_CHANNELS.map(chan).join('')}</div>`;
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
    tr.classList.remove('bg-surface-container-low','border-l-4','border-primary');
    return;
  }
  tr.classList.add('bg-surface-container-low','border-l-4','border-primary');
  const expandTr = document.createElement('tr');
  expandTr.className = 'expand-row bg-surface-container-low/50';
  expandTr.innerHTML = `<td class="p-6" colspan="11"><div class="text-on-surface-variant text-sm">Loading…</div></td>`;
  tr.after(expandTr);

  try {
    const detail = await apiFetch(`/api/message-outbox/${id}`);
    const payloadStr = typeof detail.decodedPayload === 'object'
      ? JSON.stringify(detail.decodedPayload, null, 2)
      : String(detail.decodedPayload ?? '');
    expandTr.innerHTML = `<td colspan="11" class="p-0">
      <div class="p-6 border-l-4 border-primary bg-surface-container-low/40">
        <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <div>
            <h4 class="text-xs font-black uppercase tracking-widest text-on-surface-variant mb-3">Payload (decoded)</h4>
            <pre class="code-bg text-xs mono-text p-4 rounded-lg whitespace-pre-wrap break-all max-h-96 overflow-y-auto">${escHtml(payloadStr)}</pre>
          </div>
          <div class="lg:col-span-2">
            <h4 class="text-xs font-black uppercase tracking-widest text-on-surface-variant mb-3">Brevo delivery</h4>
            <div class="bg-surface-container-lowest rounded-lg p-4 border border-outline-variant/20">${moBrevoTimeline(detail)}</div>
          </div>
          <div>
            <h4 class="text-xs font-black uppercase tracking-widest text-on-surface-variant mb-3">Last Error Body</h4>
            <pre class="code-bg text-xs mono-text p-4 rounded-lg whitespace-pre-wrap break-all max-h-96 overflow-y-auto ${detail.lastErrorBody ? 'text-red-300' : ''}">${escHtml(detail.lastErrorBody || '(no error)')}</pre>
            <div class="mt-4 grid grid-cols-2 gap-2 text-xs">
              <div><b>HTTP Status:</b> ${detail.lastHttpStatus ?? '—'}</div>
              <div><b>Error Class:</b> ${detail.lastErrorClass ?? '—'}</div>
              <div><b>Attempt:</b> ${detail.attemptCount}/${detail.maxAttempts}</div>
              <div><b>Next attempt:</b> ${escHtml(deTime(detail.nextAttemptAt)) || '—'}</div>
              <div><b>First Teams ping:</b> ${escHtml(deTime(detail.firstTeamsNotifiedAt)) || '—'}</div>
              <div><b>Sent at:</b> ${escHtml(deTime(detail.sentAt)) || '—'}</div>
              <div><b>Dead at:</b> ${escHtml(deTime(detail.deadAt)) || '—'}</div>
              <div><b>Correlation:</b> ${escHtml(detail.correlationId) || '—'}</div>
            </div>
          </div>
        </div>
      </div>
    </td>`;
  } catch (e) {
    expandTr.innerHTML = `<td class="p-6" colspan="11"><div class="text-error text-sm">Failed to load: ${escHtml(e.message)}</div></td>`;
  }
}

async function renderMessageOutbox(el, page = 1) {
  el.innerHTML = pageWrap(pageHero('Message Outbox', { sub: 'Brevo email/SMS durable queue', live: true }) + loadingState());
  try {
    const p = new URLSearchParams({ ...moFilters, page, pageSize: 50 });
    const [data, stats] = await Promise.all([
      apiFetch(`/api/message-outbox?${p}`),
      apiFetch(`/api/message-outbox/stats`).catch(() => null),
    ]);
    setConnStatus('connected');

    const statusOpts = [{value:'',label:'All Statuses'}, ...MO_STATUSES.map(s => ({value:s, label:s}))];
    const channelOpts = [{value:'',label:'All Channels'}, ...MO_CHANNELS.map(c => ({value:c, label:c}))];
    const errorClassOpts = [{value:'',label:'Any'}, {value:'permanent',label:'permanent'}, {value:'transient',label:'transient'}];
    const brevoOpts = [{value:'',label:'Any'}, {value:'none',label:'no event yet'}, ...MO_BREVO_EVENTS.map(e => ({value:e, label:e.replace(/_/g,' ')}))];

    const filterHtml =
      fSelect('Status', statusOpts, `oninput="moFilters.status=this.value"`, moFilters.status || '') +
      fSelect('Channel', channelOpts, `oninput="moFilters.channel=this.value"`, moFilters.channel || '') +
      fSelect('Error class', errorClassOpts, `oninput="moFilters.lastErrorClass=this.value"`, moFilters.lastErrorClass || '') +
      (data.brevoSupported ? fSelect('Brevo', brevoOpts, `oninput="moFilters.brevoStatus=this.value"`, moFilters.brevoStatus || '') : '') +
      fInput('From', `type="datetime-local" value="${moFilters.dateFrom||''}" oninput="moFilters.dateFrom=this.value"`) +
      fInput('To', `type="datetime-local" value="${moFilters.dateTo||''}" oninput="moFilters.dateTo=this.value"`) +
      fInput('Correlation', `placeholder="e.g. appointmentId" value="${escHtml(moFilters.correlationId||'')}" oninput="moFilters.correlationId=this.value"`) +
      fInput('Recipient', `placeholder="email or phone substring" value="${escHtml(moFilters.recipient||'')}" oninput="moFilters.recipient=this.value"`) +
      fInput('HTTP Status', `placeholder="e.g. 500" value="${escHtml(moFilters.lastHttpStatus||'')}" oninput="moFilters.lastHttpStatus=this.value"`) +
      `<div class="flex gap-2">${btnPrimary('Search', `renderMessageOutbox(document.getElementById('content'))`, { full: true })}${btnGhost('Clear', `moFilters={};renderMessageOutbox(document.getElementById('content'))`)}</div>`;

    const rowsHtml = data.rows.map(row => {
      const [bg, fg] = MO_STATUS_PILL[row.status] || ['bg-slate-100','text-slate-700'];
      const canRetry = row.status === 'failed' || row.status === 'dead';
      const canKill = row.status === 'pending' || row.status === 'sending' || row.status === 'failed';
      const actions = [
        row.status === 'pending' ? `<button class="px-2 py-1 rounded bg-primary/10 text-primary hover:bg-primary/20 text-xs font-bold" onclick="event.stopPropagation();sendNowMessageOutbox('${escHtml(row.id)}')">Send now</button>` : '',
        canRetry ? `<button class="px-2 py-1 rounded bg-primary/10 text-primary hover:bg-primary/20 text-xs font-bold" onclick="event.stopPropagation();retryMessageOutbox('${escHtml(row.id)}')">Retry</button>` : '',
        canKill ? `<button class="px-2 py-1 rounded bg-red-100 text-red-700 hover:bg-red-200 text-xs font-bold" onclick="event.stopPropagation();killMessageOutbox('${escHtml(row.id)}')">Kill</button>` : '',
      ].filter(Boolean).join(' ');

      return `<tr class="zebra-row hover:bg-surface-container transition-colors cursor-pointer mo-row" data-id="${escHtml(row.id)}">
        <td class="px-4 py-2 mono-text text-xs opacity-70 whitespace-nowrap">${escHtml(deTime(row.createdAt))}</td>
        <td class="px-4 py-2"><span class="px-2 py-0.5 bg-surface-container-high rounded text-[10px] font-bold mono-text">${escHtml(row.channel)}</span></td>
        <td class="px-4 py-2"><span class="px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider ${bg} ${fg}">${escHtml(row.status)}</span></td>
        <td class="px-4 py-2 mono-text text-xs">${row.attemptCount}/${row.maxAttempts}</td>
        <td class="px-4 py-2 mono-text text-xs opacity-70 whitespace-nowrap">${escHtml(deTime(row.nextAttemptAt)) || '—'}</td>
        <td class="px-4 py-2 mono-text text-xs ${row.lastHttpStatus >= 500 ? 'text-red-600 font-bold' : row.lastHttpStatus >= 400 ? 'text-amber-600' : ''}">${row.lastHttpStatus ?? '—'}</td>
        <td class="px-4 py-2 text-xs">${escHtml(row.lastErrorClass) || '—'}</td>
        <td class="px-4 py-2">${moBrevoPill(row.brevoStatus, row.brevoStatusAt ? deTime(row.brevoStatusAt) : '')}</td>
        <td class="px-4 py-2 text-xs truncate max-w-[180px]" title="${escHtml(row.correlationId||'')}">${escHtml(row.correlationId) || '—'}</td>
        <td class="px-4 py-2 mono-text text-[10px] opacity-60">${escHtml(String(row.id).slice(0,8))}…</td>
        <td class="px-4 py-2">${actions || '—'}</td>
      </tr>`;
    }).join('');

    el.innerHTML = pageWrap(
      pageHero('Message Outbox', {
        sub: 'Brevo email/SMS durable queue — monitor, retry, kill',
        live: true,
        actions: (moPendingTotal(stats) ? btnGhost(`Send all pending (${moPendingTotal(stats)})`, 'sendAllPendingMessageOutbox()', { icon: 'send' }) : '') +
          `<button class="p-2 bg-surface-container rounded-lg text-on-surface-variant hover:bg-surface-container-high transition-colors" onclick="renderMessageOutbox(document.getElementById('content'))" title="Refresh"><span class="material-symbols-outlined">refresh</span></button>`,
      }) +
      moStatsBanner(stats) +
      moBrevoStats(stats && stats.brevo) +
      filterCard(filterHtml, 6) +
      tableShell(['Created','Channel','Status','Attempt','Next','HTTP','Err cls','Brevo','Correlation','ID','Actions'], rowsHtml, 'moPaging')
    );

    document.querySelectorAll('.mo-row').forEach(tr => {
      tr.addEventListener('click', () => toggleMessageOutboxDetail(tr, tr.dataset.id));
    });

    renderPagination(document.getElementById('moPaging'), data, (p) => renderMessageOutbox(document.getElementById('content'), p));
  } catch (e) {
    setConnStatus('error');
    el.innerHTML = pageWrap(pageHero('Message Outbox') + errorState(e.message));
  }
}
