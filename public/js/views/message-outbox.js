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
  expandTr.innerHTML = `<td class="p-6" colspan="10"><div class="text-on-surface-variant text-sm">Loading…</div></td>`;
  tr.after(expandTr);

  try {
    const detail = await apiFetch(`/api/message-outbox/${id}`);
    const payloadStr = typeof detail.decodedPayload === 'object'
      ? JSON.stringify(detail.decodedPayload, null, 2)
      : String(detail.decodedPayload ?? '');
    expandTr.innerHTML = `<td colspan="10" class="p-0">
      <div class="p-6 border-l-4 border-primary bg-surface-container-low/40">
        <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <div>
            <h4 class="text-xs font-black uppercase tracking-widest text-on-surface-variant mb-3">Payload (decoded)</h4>
            <pre class="code-bg text-xs mono-text p-4 rounded-lg whitespace-pre-wrap break-all max-h-96 overflow-y-auto">${escHtml(payloadStr)}</pre>
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
    expandTr.innerHTML = `<td class="p-6" colspan="10"><div class="text-error text-sm">Failed to load: ${escHtml(e.message)}</div></td>`;
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

    const filterHtml =
      fSelect('Status', statusOpts, `oninput="moFilters.status=this.value"`, moFilters.status || '') +
      fSelect('Channel', channelOpts, `oninput="moFilters.channel=this.value"`, moFilters.channel || '') +
      fSelect('Error class', errorClassOpts, `oninput="moFilters.lastErrorClass=this.value"`, moFilters.lastErrorClass || '') +
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
        <td class="px-4 py-2 text-xs truncate max-w-[180px]" title="${escHtml(row.correlationId||'')}">${escHtml(row.correlationId) || '—'}</td>
        <td class="px-4 py-2 mono-text text-[10px] opacity-60">${escHtml(String(row.id).slice(0,8))}…</td>
        <td class="px-4 py-2">${actions || '—'}</td>
      </tr>`;
    }).join('');

    el.innerHTML = pageWrap(
      pageHero('Message Outbox', {
        sub: 'Brevo email/SMS durable queue — monitor, retry, kill',
        live: true,
        actions: `<button class="p-2 bg-surface-container rounded-lg text-on-surface-variant hover:bg-surface-container-high transition-colors" onclick="renderMessageOutbox(document.getElementById('content'))" title="Refresh"><span class="material-symbols-outlined">refresh</span></button>`,
      }) +
      moStatsBanner(stats) +
      filterCard(filterHtml, 6) +
      tableShell(['Created','Channel','Status','Attempt','Next','HTTP','Err cls','Correlation','ID','Actions'], rowsHtml, 'moPaging')
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
