// ═════════════════════════════════════════════════════════════════════════
// SESSION LOGS
// ═════════════════════════════════════════════════════════════════════════
let slFilters = {};
const slCache = {};

// Endpoint groups + method names sourced from Serverpod's protocol.yaml
// via /api/protocol. Cached on first load (no DB query needed).
let slProtocol = null;
let slProtocolPromise = null;
function loadProtocol() {
  if (slProtocol) return Promise.resolve(slProtocol);
  if (slProtocolPromise) return slProtocolPromise;
  slProtocolPromise = fetch('/api/protocol').then(r => r.json()).then(d => {
    slProtocol = d.groups || {};
    return slProtocol;
  }).catch(e => {
    showToast('Failed to load protocol: ' + e.message);
    slProtocol = {};
    return slProtocol;
  });
  return slProtocolPromise;
}

// Rebuild the Method <select> when the chosen endpoint changes.
function refreshSlMethodOptions() {
  const sel = document.getElementById('slMethod');
  if (!sel || !slProtocol) return;
  const ep = slFilters.endpoint || '';
  const methods = ep && slProtocol[ep]
    ? slProtocol[ep]
    : Array.from(new Set(Object.values(slProtocol).flat())).sort();
  const cur = slFilters.method || '';
  sel.innerHTML = ['<option value="">All Methods</option>',
    ...methods.map(m => `<option value="${escHtml(m)}" ${cur === m ? 'selected' : ''}>${escHtml(m)}</option>`)
  ].join('');
}

function onSlEndpointChange(val) {
  slFilters.endpoint = val;
  // If current method isn't valid for the new endpoint, clear it.
  if (val && slProtocol && slProtocol[val] && slFilters.method && !slProtocol[val].includes(slFilters.method)) {
    slFilters.method = '';
  }
  refreshSlMethodOptions();
}

async function renderSessionLogs(el, page = 1) {
  el.innerHTML = pageWrap(pageHero('Session Logs', { sub: 'Per-request server-side logs and queries', live: true }) + loadingState());
  try {
    // Kick off protocol load in parallel with the rows fetch.
    const [data] = await Promise.all([
      apiFetch(`/api/session-logs?${new URLSearchParams({ ...slFilters, page, pageSize: 50 })}`),
      loadProtocol(),
    ]);
    setConnStatus('connected');

    const groupNames = Object.keys(slProtocol || {}).sort();
    const allMethods = slFilters.endpoint && slProtocol?.[slFilters.endpoint]
      ? slProtocol[slFilters.endpoint]
      : Array.from(new Set(Object.values(slProtocol || {}).flat())).sort();
    const endpointOpts = [{value:'',label:'All Endpoints'}, ...groupNames.map(e => ({value:e,label:e}))];
    const methodOpts   = [{value:'',label:'All Methods'},   ...allMethods.map(m => ({value:m,label:m}))];

    const filterHtml =
      fSelect('Endpoint', endpointOpts, `id="slEndpoint" onchange="onSlEndpointChange(this.value)"`, slFilters.endpoint || '') +
      fSelect('Method',   methodOpts,   `id="slMethod"   onchange="slFilters.method=this.value"`,   slFilters.method   || '') +
      fInput('From', `type="datetime-local" id="slFrom" value="${slFilters.dateFrom||''}" oninput="slFilters.dateFrom=this.value"`) +
      fInput('To',   `type="datetime-local" id="slTo"   value="${slFilters.dateTo||''}"   oninput="slFilters.dateTo=this.value"`) +
      `<div class="flex items-center gap-3 pb-2.5">
        <input type="checkbox" id="slErrors" ${slFilters.errorsOnly?'checked':''} onchange="slFilters.errorsOnly=this.checked" class="w-5 h-5 text-primary rounded border-outline-variant focus:ring-primary">
        <label for="slErrors" class="text-sm font-medium text-on-surface">Errors only</label>
      </div>` +
      `<div class="flex gap-2">${btnPrimary('Search', `renderSessionLogs(document.getElementById('content'))`, { full: true })}${btnGhost('Clear', `slFilters={};renderSessionLogs(document.getElementById('content'))`)}</div>`;

    const rowsHtml = data.rows.map(row => {
      const hasError = !!row.error;
      const isSlow = row.slow;
      const dotClass = hasError ? 'bg-error' : isSlow ? 'bg-amber-500' : 'bg-tertiary';
      const statusPill = hasError ? statusBadge('Error','error') : isSlow ? statusBadge('Slow','amber') : statusBadge('OK','tertiary');
      return `<tr class="zebra-row hover:bg-surface-container transition-colors cursor-pointer group sl-row" data-id="${row.id}">
        <td class="px-4 py-2"><div class="w-2 h-2 rounded-full ${dotClass}"></div></td>
        <td class="px-4 py-2 mono-text text-xs opacity-70 whitespace-nowrap">${escHtml(deTime(row.time))}</td>
        <td class="px-4 py-2 font-medium" title="${escHtml(row.endpoint)}">${escHtml(row.endpoint) || '—'}</td>
        <td class="px-4 py-2"><span class="px-2 py-0.5 bg-surface-container-high rounded text-[0.65rem] font-bold mono-text">${escHtml(row.method) || '—'}</span></td>
        <td class="px-4 py-2 mono-text ${hasError ? 'text-error font-bold' : isSlow ? 'text-amber-600' : ''}">${dur(row.duration)}</td>
        <td class="px-4 py-2 mono-text">${row.numQueries ?? '—'}</td>
        <td class="px-4 py-2 mono-text text-xs">${escHtml(row.authenticatedUserId) || '—'}</td>
        <td class="px-4 py-2">${statusPill}</td>
      </tr>`;
    }).join('');

    el.innerHTML = pageWrap(
      pageHero('Session Logs', { sub: `SID: ${getCfg().db}`, live: true,
        actions: `<button class="p-2 bg-surface-container rounded-lg text-on-surface-variant hover:bg-surface-container-high transition-colors" onclick="renderSessionLogs(document.getElementById('content'))" title="Refresh"><span class="material-symbols-outlined">refresh</span></button>` }) +
      filterCard(filterHtml, 6) +
      tableShell(['St','Time','Endpoint','Method','Duration','Queries','User ID','Status'], rowsHtml, 'slPaging')
    );

    // Wire row clicks
    document.querySelectorAll('.sl-row').forEach(tr => {
      tr.addEventListener('click', () => toggleSessionDetail(tr, tr.dataset.id));
    });

    renderPagination(document.getElementById('slPaging'), data, (p) => renderSessionLogs(document.getElementById('content'), p));
  } catch(e) {
    setConnStatus('error');
    el.innerHTML = pageWrap(pageHero('Session Logs') + errorState(e.message));
  }
}

async function toggleSessionDetail(tr, id) {
  const existing = tr.nextElementSibling;
  if (existing && existing.classList.contains('expand-row')) {
    existing.remove();
    tr.classList.remove('bg-surface-container-low','border-l-4','border-primary');
    return;
  }
  tr.classList.add('bg-surface-container-low','border-l-4','border-primary');
  const expandTr = document.createElement('tr');
  expandTr.className = 'expand-row bg-surface-container-low/50';
  expandTr.innerHTML = `<td class="p-6" colspan="8"><div class="text-on-surface-variant text-sm">Loading…</div></td>`;
  tr.after(expandTr);

  const details = slCache[id] || await apiFetch(`/api/session-logs/${id}/details`);
  slCache[id] = details;

  const { session, logs, queries } = details;
  const crashSection = session?.error ? `
    <div class="mb-6">
      <h4 class="text-xs font-black uppercase tracking-widest text-error mb-2 flex items-center gap-2">
        <span class="material-symbols-outlined text-sm">crisis_alert</span> Crash Reason
      </h4>
      <pre class="code-bg text-xs mono-text text-red-300 p-4 rounded-lg whitespace-pre-wrap break-all max-h-60 overflow-y-auto">${escHtml(session.error)}${session.stackTrace ? '\n\n' + escHtml(session.stackTrace) : ''}</pre>
    </div>` : '';

  const logsHtml = logs.length ? logs.map(l => {
    let resendBtn = '';
    if (isEmailSendLog(l.message)) {
      const cacheKey = `${id}:${l.id}`;
      _emailResendCache[cacheKey] = l.message;
      resendBtn = ` <button class="ml-2 px-2 py-0.5 rounded bg-tertiary-container text-on-tertiary-container text-[10px] font-bold uppercase tracking-wider hover:bg-tertiary hover:text-on-tertiary transition-colors" onclick="openEmailResendModal('${cacheKey}')" title="Resend this email via Brevo"><span class="material-symbols-outlined text-[12px] align-middle mr-0.5">send</span>Resend</button>`;
    }
    return `<div class="${LOG_CLASSES[l.logLevel] || ''} mono-text text-[11px] mb-1.5 leading-relaxed">
      <strong>[${LOG_LEVELS[l.logLevel]||l.logLevel}]</strong> ${escHtml(deTime(l.time))} — ${escHtml(l.message)}${resendBtn}
      ${l.error ? `<pre class="mt-1 code-bg text-red-300 p-2 rounded mono-text text-[10px] whitespace-pre-wrap break-all max-h-32 overflow-y-auto">${escHtml(l.error)}${l.stackTrace ? '\n\n'+escHtml(l.stackTrace) : ''}</pre>` : ''}
    </div>`;
  }).join('') : '<div class="text-outline text-sm italic">No log entries</div>';

  const queryHtml = queries.length ? `
    <div class="bg-surface-container-lowest rounded-lg overflow-hidden border border-outline-variant/20">
      <table class="w-full text-[11px] mono-text">
        <thead class="bg-surface-container-high"><tr>
          <th class="px-3 py-2 text-left font-bold">SQL</th>
          <th class="px-3 py-2 text-right font-bold">Dur</th>
          <th class="px-3 py-2 text-right font-bold">Rows</th>
          <th class="px-3 py-2 text-right font-bold w-10"></th>
        </tr></thead>
        <tbody>${queries.map(q => `<tr class="border-b border-surface-container">
          <td class="px-3 py-2 truncate max-w-[260px]" title="${escHtml(q.query)}">${escHtml(q.query)}</td>
          <td class="px-3 py-2 text-right ${q.slow ? 'text-amber-600 font-bold' : ''}">${dur(q.duration)}${q.slow ? ' <span class="bg-amber-100 text-[9px] px-1 rounded ml-1 font-bold">SLOW</span>':''}</td>
          <td class="px-3 py-2 text-right">${q.numRows ?? '—'}</td>
          <td class="px-3 py-2 text-right">
            <button class="text-on-surface-variant hover:text-primary p-1 rounded hover:bg-primary/5 transition-colors" title="Copy SQL" onclick="copyText(decodeEntities('${escHtml(q.query)}'), 'Copied SQL')">
              <span class="material-symbols-outlined text-sm">content_copy</span>
            </button>
          </td>
        </tr>`).join('')}</tbody>
      </table>
    </div>` : '<div class="text-outline text-sm italic">No queries</div>';

  expandTr.innerHTML = `<td colspan="8" class="p-0">
    <div class="p-6 border-l-4 border-primary bg-surface-container-low/40">
      ${crashSection}
      <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div>
          <h4 class="text-xs font-black uppercase tracking-widest text-on-surface-variant mb-3 flex items-center gap-2">
            <span class="material-symbols-outlined text-sm">subject</span> Log Entries (${logs.length})
          </h4>
          <div class="bg-surface-container-lowest p-4 rounded-lg shadow-inner max-h-72 overflow-y-auto">${logsHtml}</div>
        </div>
        <div>
          <h4 class="text-xs font-black uppercase tracking-widest text-on-surface-variant mb-3 flex items-center gap-2">
            <span class="material-symbols-outlined text-sm">database</span> Query Log (${queries.length})
          </h4>
          ${queryHtml}
        </div>
      </div>
    </div>
  </td>`;
}

// ═════════════════════════════════════════════════════════════════════════
// EMAIL RESEND (Brevo) — manual replay from "Sending email with data :" logs
// ═════════════════════════════════════════════════════════════════════════
const EMAIL_LOG_RE = /^Sending email with data\s*:\s*(\{[\s\S]*\})\s*$/;

function isEmailSendLog(message) {
  return typeof message === 'string' && EMAIL_LOG_RE.test(message);
}

// Parse Dart Map.toString() output into a plain JS object.
// Handles: Name(...) class wrappers, [..] lists, {..} maps, null/true/false/numbers/strings.
// Lookahead-aware scalar reader so values can contain ':' and ',' that aren't field separators.
function parseDartMapString(input) {
  const s = input;
  let i = 0;
  function skipWs() { while (i < s.length && /\s/.test(s[i])) i++; }
  function peekIsKey(j) {
    while (j < s.length && /\s/.test(s[j])) j++;
    return j < s.length && /^[A-Za-z_]\w*\s*:/.test(s.slice(j));
  }
  function peekIsValueStart(j) {
    while (j < s.length && /\s/.test(s[j])) j++;
    if (j >= s.length) return false;
    const c = s[j];
    if (c === '[' || c === '{') return true;
    if (c === '"' || c === "'") return true;
    return /^[A-Za-z_]\w*\(/.test(s.slice(j));
  }
  function readValue() {
    skipWs();
    if (s[i] === '{') { i++; return readEntries('}'); }
    if (s[i] === '[') { i++; return readList(); }
    const cls = s.slice(i).match(/^([A-Za-z_]\w*)\(/);
    if (cls) { i += cls[0].length; return readEntries(')'); }
    return readScalar();
  }
  function readList() {
    const out = [];
    while (i < s.length) {
      skipWs();
      if (s[i] === ']') { i++; return out; }
      out.push(readValue());
      skipWs();
      if (s[i] === ',') i++;
    }
    throw new Error('unterminated list');
  }
  function readEntries(closer) {
    const out = {};
    while (i < s.length) {
      skipWs();
      if (s[i] === closer) { i++; return out; }
      const km = s.slice(i).match(/^([A-Za-z_]\w*)/);
      if (!km) throw new Error(`expected key at ${i}: '${s.slice(i, i + 30)}'`);
      const key = km[1];
      i += key.length;
      skipWs();
      if (s[i] !== ':') throw new Error(`expected ':' after key '${key}'`);
      i++;
      out[key] = readValue();
      skipWs();
      if (s[i] === ',') i++;
    }
    throw new Error(`unterminated, expected ${closer}`);
  }
  function readScalar() {
    const start = i;
    let depth = 0;
    while (i < s.length) {
      const c = s[i];
      if (depth === 0) {
        if (c === ')' || c === ']' || c === '}') break;
        if (c === ',') {
          // Comma is a field separator only if followed by another key, a list-item starter, or a struct end.
          if (peekIsKey(i + 1) || peekIsValueStart(i + 1)) break;
          let j = i + 1;
          while (j < s.length && /\s/.test(s[j])) j++;
          if (j < s.length && (s[j] === ')' || s[j] === ']' || s[j] === '}')) break;
        }
      }
      if (c === '(' || c === '[' || c === '{') depth++;
      if (c === ')' || c === ']' || c === '}') depth--;
      i++;
    }
    const raw = s.slice(start, i).trim();
    if (raw === 'null') return null;
    if (raw === 'true') return true;
    if (raw === 'false') return false;
    if (/^-?\d+$/.test(raw)) return parseInt(raw, 10);
    if (/^-?\d+\.\d+$/.test(raw)) return parseFloat(raw);
    return raw;
  }
  i = 0;
  skipWs();
  return readValue();
}

function extractEmailPayload(message) {
  const m = message.match(EMAIL_LOG_RE);
  if (!m) throw new Error('Log line is not a "Sending email with data" entry');
  return parseDartMapString(m[1]);
}

let _emailResendCache = {};

function openEmailResendModal(cacheKey) {
  const message = _emailResendCache[cacheKey];
  if (!message) { showToast('❌ Log message not found in cache'); return; }
  let parsed = null, parseError = null, jsonText = '';
  try {
    parsed = extractEmailPayload(message);
    jsonText = JSON.stringify(parsed, null, 2);
  } catch (e) {
    parseError = e.message;
    const m = message.match(EMAIL_LOG_RE);
    jsonText = m ? m[1] : message;
  }

  const overlay = document.createElement('div');
  overlay.id = 'emailResendModal';
  overlay.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,0.55);z-index:9999;display:flex;align-items:center;justify-content:center;padding:24px;';
  overlay.innerHTML = `
    <div class="bg-surface rounded-lg shadow-2xl w-full max-w-3xl flex flex-col" style="max-height:90vh">
      <div class="flex items-center justify-between p-4 border-b border-outline-variant/30">
        <div>
          <h3 class="text-lg font-bold text-on-surface">Resend Email via Brevo</h3>
          <p class="text-xs text-on-surface-variant mt-0.5">POSTs the JSON below to <code class="mono-text">/v3/smtp/email</code>. Review and edit before sending.</p>
        </div>
        <button onclick="closeEmailResendModal()" class="lc-icon-btn" title="Close"><span class="material-symbols-outlined">close</span></button>
      </div>
      ${parseError ? `<div class="mx-4 mt-4 p-3 rounded bg-error-container text-on-error-container text-xs"><strong>Parse failed:</strong> ${escHtml(parseError)} — paste valid JSON below before sending.</div>`
                   : `<div class="mx-4 mt-4 p-3 rounded bg-tertiary-container text-on-tertiary-container text-xs">Parsed OK. Edit if any field looks wrong (e.g. names containing commas), then Send.</div>`}
      <div class="p-4 flex-1 overflow-hidden flex flex-col">
        <label class="text-xs font-bold uppercase tracking-widest text-on-surface-variant mb-2">Brevo payload (JSON)</label>
        <textarea id="emailResendJson" class="w-full flex-1 p-3 rounded code-bg mono-text text-[11px] text-on-surface border border-outline-variant/30 focus:outline-none focus:border-primary" style="min-height:280px;resize:vertical">${escHtml(jsonText)}</textarea>
      </div>
      <div class="flex items-center justify-end gap-2 p-4 border-t border-outline-variant/30">
        ${btnGhost('Cancel', 'closeEmailResendModal()')}
        ${btnPrimary('Send via Brevo', 'submitEmailResend()')}
      </div>
    </div>`;
  document.body.appendChild(overlay);
  overlay.addEventListener('click', (e) => { if (e.target === overlay) closeEmailResendModal(); });
}

function closeEmailResendModal() {
  const m = document.getElementById('emailResendModal');
  if (m) m.remove();
}

async function submitEmailResend() {
  const ta = document.getElementById('emailResendJson');
  if (!ta) return;
  let payload;
  try {
    payload = JSON.parse(ta.value);
  } catch (e) {
    showToast('❌ Invalid JSON: ' + e.message);
    return;
  }
  try {
    const r = await fetch('/api/email/resend', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(payload),
    });
    const body = await r.json().catch(() => ({}));
    if (!r.ok) {
      showToast('❌ Brevo: ' + (body.error || `HTTP ${r.status}`));
      return;
    }
    const id = body.brevo && body.brevo.messageId ? body.brevo.messageId : 'sent';
    showToast('✅ Sent · ' + id);
    closeEmailResendModal();
  } catch (e) {
    showToast('❌ ' + e.message);
  }
}
