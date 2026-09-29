// ═════════════════════════════════════════════════════════════════════════
// LILLI STAGING (#lilli) — UI over /api/lilli/* (scripts/lilli.js). Everything the
// server returns is already scrubbed; this view never sees answers, speech or contacts.
// ═════════════════════════════════════════════════════════════════════════
let liTab = 'investigate', liTimer = null, liJobState = null, liLines = [], liLogEnd = 0, liNotifiedJob = null;
let liCallFilter = { since: '30d', status: '', errors: false };
let liLogOpts = { proc: '', errors: false, lines: '300', grep: '' };
let liRef = 'origin/main';

function renderLilli(el) {
  el.innerHTML = pageWrap(`
    ${pageHero('Lilli staging', {
      sub: `Voice platform on the Ubuntu box (PM2 <span class="mono">lilli-staging</span> + <span class="mono">lilli-ws</span>), served at
        <a href="https://voice-staging.lillian.care/lilli-staging/" target="_blank">voice-staging</a> and
        <a href="https://tools.lillian.care/lilli-staging/" target="_blank">tools.lillian.care/lilli-staging</a>.
        Answers, speech and contact data are scrubbed before they reach this page. Same data as <span class="mono">node scripts/lilli.js</span>.`,
      actions: `<button class="btn" onclick="liLoadStatus()"><span class="material-symbols-outlined">refresh</span>Refresh</button>`,
    })}
    <div id="liStatus" style="margin-bottom:var(--s-4)">${loadingState('Checking the box…')}</div>
    <div class="lc-tabs" style="margin-bottom:var(--s-4)">
      ${[['investigate', 'Investigate'], ['calls', 'Calls'], ['logs', 'Logs'], ['deploy', 'Deploy']].map(([k, l]) =>
        `<button class="lc-tab" data-li-tab="${k}" onclick="liSwitch('${k}')">${l}</button>`).join('')}
    </div>
    <div id="liBody"></div>`);
  liLoadStatus();
  liSwitch(liTab);
}

function liDur(ms) {
  if (ms == null) return '—';
  const m = Math.round(ms / 60000);
  return m < 60 ? `${m}m` : m < 1440 ? `${Math.round(m / 60)}h` : `${Math.round(m / 1440)}d`;
}

function liPill(ok, label) { return `<span class="pill ${ok ? 'ok' : 'err'}">${escHtml(label)}</span>`; }

async function liLoadStatus() {
  const box = document.getElementById('liStatus');
  if (!box) return;
  try {
    const s = await gbpApi('/api/lilli/status');
    const tile = (label, value, extra = '') => `<div class="panel" style="padding:12px 14px">
      <div class="label" style="margin-bottom:6px">${escHtml(label)}</div><div>${value}</div>
      ${extra ? `<div class="muted mono" style="font-size:11px;margin-top:6px">${escHtml(extra)}</div>` : ''}</div>`;
    box.innerHTML = `<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:var(--s-3)">
      ${tile('Live', `<span class="mono" style="font-weight:600">${escHtml(s.liveRelease || s.checkout || '?')}</span>`,
        s.liveRelease ? 'release' : 'in-place checkout, before the first release deploy')}
      ${tile('Health', `${liPill(s.web === '200', 'web ' + s.web)} ${liPill(s.ws === 'up', 'ws ' + s.ws)}`)}
      ${s.procs.map(p => tile(p.name, `${liPill(p.status === 'online', p.status)} <span class="muted" style="font-size:12px">up ${liDur(p.uptimeMs)}</span>`,
        `${p.restarts} restarts · ${p.memoryMb} MB`)).join('')}
      ${tile('Disk', escHtml(s.disk || '?'))}
    </div>`;
  } catch (e) { box.innerHTML = errorState(e.message); }
}

function liSwitch(tab) {
  liTab = tab;
  document.querySelectorAll('.lc-tab[data-li-tab]').forEach(t => t.classList.toggle('active', t.dataset.liTab === tab));
  clearInterval(liTimer);
  if (tab === 'investigate') liRenderInvestigate();
  else if (tab === 'calls') liRenderCalls();
  else if (tab === 'logs') liRenderLogs();
  else liRenderDeploy();
}

// ── Investigate ── ask a question; a sandboxed Claude Code session reads logs/calls/code and
// answers with a fix brief. Notes live in ../investigations/ (YYYY-MM-DD-lilli-*.md).
let liInvFile = null, liInvTimer = null;

function liRenderInvestigate() {
  document.getElementById('liBody').innerHTML = `
    <div style="display:grid;grid-template-columns:280px minmax(0,1fr);gap:var(--s-4);align-items:start">
      <div>
        <button class="btn btn-primary" style="width:100%;margin-bottom:var(--s-3)" onclick="liInvSelect(null)">
          <span class="material-symbols-outlined">add</span>New investigation</button>
        <div id="liInvList">${loadingState()}</div>
      </div>
      <div id="liInvMain"></div>
    </div>`;
  liInvLoadList();
  liInvSelect(liInvFile);
}

async function liInvLoadList() {
  const box = document.getElementById('liInvList');
  if (!box) return;
  try {
    const { items } = await gbpApi('/api/lilli/inv');
    box.innerHTML = items.length ? items.map(i => `
      <div class="panel" onclick="liInvSelect('${escHtml(i.file)}')" style="padding:10px 12px;margin-bottom:6px;cursor:pointer;${i.file === liInvFile ? 'border-color:var(--action)' : ''}">
        <div style="font-size:12.5px;font-weight:600;color:var(--ink);line-height:1.35">${escHtml(i.title.replace(/^Lilli:\s*/, ''))}</div>
        <div style="display:flex;gap:6px;align-items:center;margin-top:6px">
          ${i.running ? '<span class="pill warn"><span class="dot warn live"></span>Running</span>' : `<span class="pill ${/CLOSED/.test(i.status) ? '' : 'info'}">${escHtml(i.status || 'OPEN')}</span>`}
          <span class="muted mono" style="font-size:10.5px">${escHtml(i.file.slice(0, 10))}</span>
        </div>
      </div>`).join('') : '<div class="muted" style="font-size:12px">No Lilli investigations yet.</div>';
  } catch (e) { box.innerHTML = errorState(e.message); }
}

function liInvSelect(file) {
  liInvFile = file;
  clearInterval(liInvTimer);
  document.querySelectorAll('#liInvList .panel').forEach(p => { p.style.borderColor = ''; });
  if (!file) { liInvRenderNew(); return; }
  liInvLoad(true);
}

function liInvRenderNew() {
  const main = document.getElementById('liInvMain');
  if (!main) return;
  main.innerHTML = `<div class="panel"><div class="panel-body">
    <div style="font-weight:600;margin-bottom:6px">What's going wrong on Lilli staging?</div>
    <div class="muted" style="font-size:12px;line-height:1.6;margin-bottom:var(--s-3)">
      Describe the symptom, with call ids or times if you have them. A Claude Code session reads the logs, calls and
      database (read-only, scrubbed) and the Lilli code, then answers with the root cause and a <b>fix brief</b> you can hand to a
      Claude Code session. It cannot change or deploy anything.</div>
    <textarea class="lc-textarea" id="liInvQ" rows="5" style="width:100%" placeholder="e.g. Test calls with the booking agent end without offering slots since this morning. Call cmu2zqyt… is one of them."
      onkeydown="if ((event.metaKey || event.ctrlKey) && event.key === 'Enter') liInvAsk()"></textarea>
    <div style="display:flex;justify-content:space-between;align-items:center;margin-top:var(--s-3)">
      <span class="muted" style="font-size:11.5px">⌘↩ to start · usually 2–6 minutes · names and numbers in your question are scrubbed first</span>
      <button class="btn btn-primary" onclick="liInvAsk()"><span class="material-symbols-outlined">troubleshoot</span>Investigate</button>
    </div>
  </div></div>`;
}

async function liInvAsk(followUp) {
  const input = document.getElementById(followUp ? 'liInvFollow' : 'liInvQ');
  const question = input.value.trim();
  if (!question) { showToast('Ask a question first', 'err'); return; }
  input.disabled = true;
  try {
    const { file } = await gbpApi('/api/lilli/inv', { method: 'POST', body: JSON.stringify({ question, file: followUp ? liInvFile : undefined }) });
    liInvFile = file;
    await liInvLoadList();
    liInvLoad(true);
  } catch (e) { showToast(e.message, 'err'); input.disabled = false; }
}

// Latest "#### Fix brief" section of the note, for handing to a Claude Code session.
function liInvFixBrief(md, file) {
  const parts = md.split(/^#### Fix brief\s*$/m);
  if (parts.length < 2) return null;
  const brief = parts[parts.length - 1].split(/^#{2,4} /m)[0].trim();
  return `Fix for a Lilli staging issue. Investigation notes: investigations/${file} (read them for evidence and root cause).\n\n${brief}`;
}

async function liInvLoad(scrollTop) {
  const main = document.getElementById('liInvMain');
  if (!main || !liInvFile) return;
  let d;
  try { d = await gbpApi('/api/lilli/inv/' + encodeURIComponent(liInvFile)); }
  catch (e) { main.innerHTML = errorState(e.message); return; }
  const j = d.job;
  const running = j && j.status === 'running';
  const brief = liInvFixBrief(d.md, d.file);
  const body = d.md.replace(/^# .*\n/, '').replace(/^\*\*(Status|System):\*\*.*\n/gm, '').trim();
  const secs = j ? Math.round(((j.finishedAt ? Date.parse(j.finishedAt) : Date.now()) - Date.parse(j.startedAt)) / 1000) : 0;
  main.innerHTML = `
    <div class="panel" style="margin-bottom:var(--s-3)"><div class="panel-body" style="display:flex;gap:var(--s-3);align-items:center;flex-wrap:wrap">
      <div style="flex:1;min-width:240px">
        <div style="font-weight:700">${escHtml(d.title.replace(/^Lilli:\s*/, ''))}</div>
        <div class="muted mono" style="font-size:11px;margin-top:2px">investigations/${escHtml(d.file)}</div>
      </div>
      <button class="btn btn-primary btn-sm" ${brief ? '' : 'disabled'} onclick="copyText(liInvFixBrief(window.__liInvMd, '${escHtml(d.file)}'), 'Fix brief copied — paste it into a Claude Code session')">
        <span class="material-symbols-outlined">content_copy</span>Copy fix brief</button>
      <button class="btn btn-sm" onclick="copyText('Continue the investigation in investigations/${escHtml(d.file)}', 'Copied')">
        <span class="material-symbols-outlined">link</span>Copy note path</button>
      <button class="btn btn-sm btn-ghost" onclick="liInvSetStatus('${/CLOSED/.test(d.status) ? 'OPEN' : 'CLOSED'}')">${/CLOSED/.test(d.status) ? 'Reopen' : 'Mark closed'}</button>
    </div></div>
    ${j && (running || j.status === 'failed' || j.status === 'cancelled') ? `<div class="panel" style="margin-bottom:var(--s-3);overflow:hidden">
      <div class="panel-header">
        <div style="display:flex;gap:var(--s-3);align-items:center">
          ${running ? '<span class="pill warn"><span class="dot warn live"></span>Investigating</span>' : `<span class="pill err">${escHtml(j.status)}</span>`}
          <span style="font-size:12.5px">${escHtml(j.question.slice(0, 140))}</span>
          <span class="muted mono" style="font-size:11px">${Math.floor(secs / 60)}:${String(secs % 60).padStart(2, '0')}</span>
        </div>
        <div class="panel-actions">${running ? `<button class="btn btn-sm" onclick="liInvCancel()"><span class="material-symbols-outlined">stop</span>Stop</button>` : ''}</div>
      </div>
      ${j.error ? `<div class="panel-body mono" style="color:var(--err);font-size:11.5px">${escHtml(j.error)}</div>` : ''}
      <pre class="ls-log" style="height:auto;max-height:260px">${j.log.length ? j.log.map(l => escHtml('› ' + l)).join('\n') : '<span class="muted">Starting Claude Code…</span>'}</pre>
    </div>` : ''}
    <div class="panel" style="margin-bottom:var(--s-3)"><div class="panel-body" style="font-size:13px;line-height:1.6">${invMd(body)}</div></div>
    ${!running && d.canFollowUp ? `<div class="panel"><div class="panel-body">
      <textarea class="lc-textarea" id="liInvFollow" rows="3" style="width:100%" placeholder="Follow-up: dig deeper, check another call, challenge the root cause…"
        onkeydown="if ((event.metaKey || event.ctrlKey) && event.key === 'Enter') liInvAsk(true)"></textarea>
      <div style="display:flex;justify-content:flex-end;margin-top:var(--s-2)">
        <button class="btn btn-primary btn-sm" onclick="liInvAsk(true)"><span class="material-symbols-outlined">send</span>Ask follow-up</button></div>
    </div></div>` : ''}`;
  window.__liInvMd = d.md;
  if (scrollTop) main.scrollIntoView({ block: 'nearest' });
  clearInterval(liInvTimer);
  if (running) {
    liInvTimer = setInterval(() => {
      if (window.__currentView !== 'lilli' || liTab !== 'investigate' || !document.getElementById('liInvMain')) { clearInterval(liInvTimer); return; }
      liInvLoad(false);
    }, 2500);
  } else if (j && j.status === 'done' && window.__liInvNotified !== j.startedAt) {
    window.__liInvNotified = j.startedAt;
    liInvLoadList();
    try { window.lcNative && window.lcNative.post('notify', { title: 'Lilli investigation finished', body: d.title }); } catch {}
  }
}

async function liInvCancel() {
  try { await gbpApi('/api/lilli/inv/' + encodeURIComponent(liInvFile) + '/job', { method: 'DELETE' }); liInvLoad(false); }
  catch (e) { showToast(e.message, 'err'); }
}

async function liInvSetStatus(status) {
  try {
    await gbpApi('/api/lilli/inv/' + encodeURIComponent(liInvFile) + '/status', { method: 'POST', body: JSON.stringify({ status }) });
    liInvLoadList(); liInvLoad(false);
  } catch (e) { showToast(e.message, 'err'); }
}

// ── Calls ──
function liRenderCalls() {
  const f = liCallFilter;
  document.getElementById('liBody').innerHTML = `
    <div class="panel" style="margin-bottom:var(--s-4)"><div class="panel-body" style="display:flex;gap:var(--s-4);flex-wrap:wrap;align-items:flex-end">
      <div class="field">${fLabel('Since')}<select class="lc-select" id="liSince">${[['1h', '1 hour'], ['6h', '6 hours'], ['24h', '24 hours'], ['7d', '7 days'], ['30d', '30 days'], ['', 'All time']]
        .map(([v, l]) => `<option value="${v}" ${f.since === v ? 'selected' : ''}>${l}</option>`).join('')}</select></div>
      <div class="field">${fLabel('Status')}<select class="lc-select" id="liStatusSel">${['', 'in_progress', 'complete', 'abandoned']
        .map(v => `<option value="${v}" ${f.status === v ? 'selected' : ''}>${v || 'Any'}</option>`).join('')}</select></div>
      <label class="switch" style="margin-bottom:6px"><input type="checkbox" id="liErrors" ${f.errors ? 'checked' : ''}><span>With errors only</span></label>
      <button class="btn btn-primary" onclick="liLoadCalls()"><span class="material-symbols-outlined">search</span>Load</button>
      <form onsubmit="liOpenCall(document.getElementById('liCallId').value.trim());return false" style="margin-left:auto;display:flex;gap:var(--s-2)">
        <input class="lc-input mono" id="liCallId" placeholder="id / externalId / callSid" style="width:260px">
        <button class="btn" type="submit"><span class="material-symbols-outlined">open_in_new</span>Open</button>
      </form>
    </div></div>
    <div id="liCall"></div>
    <div id="liCalls">${loadingState()}</div>`;
  liLoadCalls();
}

async function liLoadCalls() {
  const box = document.getElementById('liCalls');
  if (!box) return;
  liCallFilter = {
    since: document.getElementById('liSince').value,
    status: document.getElementById('liStatusSel').value,
    errors: document.getElementById('liErrors').checked,
  };
  box.innerHTML = loadingState('Querying through the SSH tunnel…');
  try {
    const q = new URLSearchParams({ since: liCallFilter.since, status: liCallFilter.status, errors: liCallFilter.errors ? '1' : '', limit: '100' });
    const { rows } = await gbpApi('/api/lilli/calls?' + q);
    if (!rows.length) { box.innerHTML = emptyState('No calls match these filters', 'call'); return; }
    box.innerHTML = tableShell(['Started', 'Assistant', 'Status', 'Outcome', 'Source', 'Duration', 'Answered', 'Cost', 'Error'], rows.map(r => `
      <tr onclick="liOpenCall('${escHtml(r.id)}')" style="cursor:pointer">
        <td class="mono" style="white-space:nowrap">${escHtml(deTime(r.startedAt))}</td>
        <td style="color:var(--ink)">${escHtml(r.assistant || '—')}</td>
        <td><span class="pill ${r.status === 'complete' ? 'ok' : r.status === 'in_progress' ? 'warn' : 'err'}">${escHtml(r.status)}</span></td>
        <td>${escHtml(r.outcome || '—')}</td>
        <td class="muted">${escHtml(r.source)}</td>
        <td class="mono">${r.secs == null ? '—' : escHtml(r.secs + 's')}</td>
        <td class="mono">${escHtml(r.answered)}</td>
        <td class="mono">$${escHtml(r.usd)}</td>
        <td class="mono" style="color:var(--err);font-size:11px;max-width:320px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${escHtml(r.error || '')}">${escHtml(r.error || '')}</td>
      </tr>`).join(''));
  } catch (e) { box.innerHTML = errorState(e.message); }
}

async function liOpenCall(id) {
  const box = document.getElementById('liCall');
  if (!box || !id) return;
  box.innerHTML = loadingState('Loading call…');
  box.scrollIntoView({ behavior: 'smooth', block: 'start' });
  try {
    const c = await gbpApi('/api/lilli/calls/' + encodeURIComponent(id));
    const f = c.facts;
    const shown = (k, v) => v == null ? '—' : (k === 'started' || k === 'ended') ? deTime(v) : v;
    box.innerHTML = `<div class="panel" style="margin-bottom:var(--s-4);overflow:hidden">
      <div class="panel-header"><div style="font-weight:600">Call <span class="mono">${escHtml(f.id)}</span></div>
        <div class="panel-actions">
          <button class="btn btn-sm" onclick="liCallLogs(${escHtml(JSON.stringify(c.logIds))})"><span class="material-symbols-outlined">receipt_long</span>Matching log lines</button>
          <button class="btn btn-sm btn-ghost" onclick="document.getElementById('liCall').innerHTML=''"><span class="material-symbols-outlined">close</span></button>
        </div></div>
      <div class="panel-body" style="display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:6px 24px;font-size:12.5px">
        ${Object.entries(f).map(([k, v]) => `<div style="display:flex;gap:10px"><span class="label" style="min-width:84px">${escHtml(k)}</span>
          <span class="mono" style="word-break:break-all;${k === 'error' && v ? 'color:var(--err)' : ''}">${escHtml(shown(k, v))}</span></div>`).join('')}
        ${c.booking ? `<div style="grid-column:1/-1;display:flex;gap:10px"><span class="label" style="min-width:84px">booking</span><span class="mono" style="word-break:break-all">${escHtml(JSON.stringify(c.booking))}</span></div>` : ''}
      </div>
      ${c.events.length ? `<div style="overflow-x:auto;border-top:1px solid var(--rule)"><table class="lc-table"><thead><tr><th>Offset</th><th>Event</th><th>Detail</th></tr></thead><tbody>
        ${c.events.map(e => `<tr style="cursor:default"><td class="mono">${e.offsetS == null ? '' : '+' + e.offsetS.toFixed(1) + 's'}</td>
          <td style="color:var(--ink)">${escHtml(e.type)}</td>
          <td class="mono muted" style="font-size:11px;word-break:break-all">${e.detail ? escHtml(JSON.stringify(e.detail)) : ''}</td></tr>`).join('')}
      </tbody></table></div>` : `<div class="panel-body muted" style="border-top:1px solid var(--rule)">No events recorded for this call.</div>`}
      <pre class="ls-log" id="liCallLog" style="display:none;height:320px"></pre>
    </div>`;
  } catch (e) { box.innerHTML = errorState(e.message); }
}

async function liCallLogs(ids) {
  const pre = document.getElementById('liCallLog');
  if (!pre) return;
  pre.style.display = '';
  pre.textContent = 'Searching the last 3000 lines of each process…';
  try {
    const grep = ids.map(s => s.replace(/[^\w-]/g, '')).join('|');
    const { lines } = await gbpApi('/api/lilli/logs?' + new URLSearchParams({ lines: '3000', grep }));
    pre.innerHTML = lines.length ? liLogHtml(lines) : '<span class="muted">No log lines mention this call. Older lines may have rotated out.</span>';
  } catch (e) { pre.textContent = e.message; }
}

function liLogHtml(lines) {
  return lines.map(({ proc, line }) => {
    const cls = /\b(error|Error|ERROR|Exception|failed|HTTP 5\d\d)\b|^\s+at /.test(line) ? 'l-err' : /\b(warn|Warn|WARN|timed out)\b/.test(line) ? 'l-warn' : '';
    const text = `${proc.padEnd(3)} | ${line}`;
    return cls ? `<span class="${cls}">${escHtml(text)}</span>` : escHtml(text);
  }).join('\n');
}

// ── Logs ──
function liRenderLogs() {
  const o = liLogOpts;
  document.getElementById('liBody').innerHTML = `
    <div class="panel" style="overflow:hidden">
      <div class="panel-header" style="flex-wrap:wrap;gap:var(--s-3)">
        <div style="display:flex;gap:var(--s-3);align-items:center;flex-wrap:wrap">
          <div class="tweak-seg">${[['', 'Both'], ['web', 'Web'], ['ws', 'WS']].map(([v, l]) =>
            `<button class="${o.proc === v ? 'on' : ''}" onclick="liLogOpts.proc='${v}';liRenderLogs()">${l}</button>`).join('')}</div>
          <select class="lc-select" id="liLines" onchange="liLoadLogs()">${['100', '300', '1000', '3000'].map(v =>
            `<option value="${v}" ${o.lines === v ? 'selected' : ''}>last ${v} lines</option>`).join('')}</select>
          <label class="switch"><input type="checkbox" id="liLogErr" ${o.errors ? 'checked' : ''} onchange="liLoadLogs()"><span>stderr only</span></label>
          <input class="lc-input mono" id="liGrep" placeholder="Filter (regex), e.g. ARIA|Booking" value="${escHtml(o.grep)}"
            onkeydown="if (event.key === 'Enter') liLoadLogs()" style="width:260px">
        </div>
        <div class="panel-actions">
          <button class="btn btn-primary btn-sm" onclick="liLoadLogs()"><span class="material-symbols-outlined">refresh</span>Refresh</button>
          <button class="btn btn-sm" onclick="copyText(document.getElementById('liLog').innerText, 'Copied log')"><span class="material-symbols-outlined">content_copy</span>Copy</button>
        </div>
      </div>
      <pre class="ls-log" id="liLog" style="height:560px"></pre>
    </div>
    <div class="muted" style="font-size:11.5px;margin-top:var(--s-2)">PM2 log files on the box, oldest first. Lines carry timestamps once a release deploy has restarted PM2 with --time.</div>`;
  liLoadLogs();
}

async function liLoadLogs() {
  const pre = document.getElementById('liLog');
  if (!pre) return;
  liLogOpts = { ...liLogOpts, lines: document.getElementById('liLines').value, errors: document.getElementById('liLogErr').checked, grep: document.getElementById('liGrep').value.trim() };
  pre.textContent = 'Loading…';
  try {
    const q = new URLSearchParams({ proc: liLogOpts.proc, lines: liLogOpts.lines, errors: liLogOpts.errors ? '1' : '', grep: liLogOpts.grep });
    const { lines } = await gbpApi('/api/lilli/logs?' + q);
    pre.innerHTML = lines.length ? liLogHtml(lines) : '<span class="muted">No lines.</span>';
    pre.scrollTop = pre.scrollHeight;
  } catch (e) { pre.textContent = e.message; }
}

// ── Deploy ──
function liRenderDeploy() {
  document.getElementById('liBody').innerHTML = `
    <div class="panel" style="margin-bottom:var(--s-4)"><div class="panel-body">
      <div style="display:flex;gap:var(--s-3);align-items:flex-end;flex-wrap:wrap">
        <div class="field">${fLabel('Commit or branch (must be on GitHub)')}
          <input class="lc-input mono" id="liRef" value="${escHtml(liRef)}" style="width:260px" onkeydown="if (event.key === 'Enter') liPlanDeploy()"></div>
        <button class="btn btn-primary" onclick="liPlanDeploy()"><span class="material-symbols-outlined">fact_check</span>Plan deploy</button>
        <div style="margin-left:auto"><button class="btn" id="liRollbackBtn" onclick="liRollback()"><span class="material-symbols-outlined">undo</span>Roll back to previous release</button></div>
      </div>
      <div class="muted" style="font-size:11.5px;margin-top:var(--s-3);line-height:1.6">
        Builds the commit in its own release folder next to the live one, switches over only if the build succeeds,
        health-checks, and switches back on its own if the check fails.</div>
      <div id="liPlan"></div>
    </div></div>
    <div class="panel" style="margin-bottom:var(--s-4);overflow:hidden">
      <div class="panel-header">
        <div id="liJobHead" style="display:flex;align-items:center;gap:var(--s-3);flex-wrap:wrap"></div>
        <div class="panel-actions" id="liJobActions"></div>
      </div>
      <pre class="ls-log" id="liJobLog"></pre>
    </div>
    <div id="liReleases"></div>`;
  liLines = []; liLogEnd = 0; liJobState = null;
  liPollJob();
  liLoadReleases();
  liTimer = setInterval(() => {
    if (window.__currentView !== 'lilli' || liTab !== 'deploy') { clearInterval(liTimer); return; }
    liPollJob();
  }, 1500);
}

function liBusy() { return !!(liJobState && liJobState.status === 'running'); }

async function liPlanDeploy() {
  const box = document.getElementById('liPlan');
  liRef = document.getElementById('liRef').value.trim() || 'origin/main';
  box.innerHTML = `<div style="margin-top:var(--s-4)">${loadingState('Fetching and comparing with what is live…')}</div>`;
  try {
    const p = await gbpApi('/api/lilli/deploy/plan?' + new URLSearchParams({ ref: liRef }));
    const list = (cs) => cs.map(c => `<div class="mono" style="font-size:12px"><span class="muted">${escHtml(c.sha)}</span> ${escHtml(c.subject)}</div>`).join('');
    const same = p.live === p.target;
    box.innerHTML = `<div style="margin-top:var(--s-4);border-top:1px solid var(--rule);padding-top:var(--s-4);display:grid;gap:var(--s-3)">
      <div class="mono" style="font-size:12px;line-height:1.8">
        <span class="label" style="display:inline-block;width:60px">live</span>${escHtml(p.live.slice(0, 7))} ${escHtml(p.liveSubject || '(not in the local repo)')}<br>
        <span class="label" style="display:inline-block;width:60px">deploy</span>${escHtml(p.target.slice(0, 7))} ${escHtml(p.targetSubject)}</div>
      ${same ? `<div class="muted" style="font-size:12px">Already live; deploying restarts the same release.</div>` : ''}
      ${p.goingOut.length ? `<div><div class="label" style="margin-bottom:4px">Going out (${p.goingOut.length})</div>${list(p.goingOut)}</div>` : ''}
      ${p.removed.length ? `<div style="color:var(--err)"><div class="label" style="margin-bottom:4px;color:var(--err)">Live now but removed by this deploy (${p.removed.length})</div>${list(p.removed)}</div>` : ''}
      ${!p.onOrigin ? `<div style="color:var(--err);font-size:12px">This commit is not on GitHub. Push it first; the box fetches from origin.</div>` : ''}
      ${p.schemaChanged ? `<label class="switch" style="color:var(--err)"><input type="checkbox" id="liSchemaOk">
        <span>prisma/schema.prisma changed. I applied the DB change already<small>All releases share one database, so apply schema changes before deploying code that needs them.</small></span></label>` : ''}
      <div><button class="btn btn-primary" id="liDeployBtn" ${!p.onOrigin || liBusy() ? 'disabled' : ''}
        onclick="liDeploy('${escHtml(p.target)}')"><span class="material-symbols-outlined">rocket_launch</span>Deploy ${escHtml(p.target.slice(0, 7))} to Lilli staging</button></div>
    </div>`;
  } catch (e) { box.innerHTML = `<div style="margin-top:var(--s-4)">${errorState(e.message)}</div>`; }
}

async function liDeploy(sha) {
  const schemaBox = document.getElementById('liSchemaOk');
  if (schemaBox && !schemaBox.checked) { showToast('Confirm the schema checkbox first', 'err'); return; }
  if (!confirm(`Deploy ${sha.slice(0, 7)} to Lilli staging?`)) return;
  try {
    await gbpApi('/api/lilli/deploy', { method: 'POST', body: JSON.stringify({ sha, schemaOk: !!(schemaBox && schemaBox.checked) }) });
    liLines = []; liLogEnd = 0;
    document.getElementById('liPlan').innerHTML = '';
    liPollJob();
  } catch (e) { showToast(e.message, 'err'); }
}

async function liRollback() {
  if (!confirm('Switch Lilli staging back to the previous release?')) return;
  try {
    await gbpApi('/api/lilli/rollback', { method: 'POST' });
    liLines = []; liLogEnd = 0;
    liPollJob();
  } catch (e) { showToast(e.message, 'err'); }
}

async function liCancel() {
  if (!confirm('Stop the running job? A half-finished deploy switches back on its own only if it reached the health check.')) return;
  try { await gbpApi('/api/lilli/job/cancel', { method: 'POST' }); } catch (e) { showToast(e.message, 'err'); }
}

async function liPollJob() {
  let d;
  try { d = await gbpApi(`/api/lilli/job?since=${liLogEnd}`); } catch { return; }
  let j = d.job;
  if (j && liJobState && j.id !== liJobState.id) {
    liLines = []; liLogEnd = 0;
    try { d = await gbpApi('/api/lilli/job?since=0'); j = d.job; } catch { return; }
  }
  const wasRunning = liBusy();
  if (j) { liLines.push(...j.lines); liLogEnd = j.logEnd; }
  liJobState = j;
  liRenderJob();
  const rb = document.getElementById('liRollbackBtn');
  if (rb) rb.disabled = liBusy();
  if (j && wasRunning && j.status !== 'running' && liNotifiedJob !== j.id) {
    liNotifiedJob = j.id;
    const title = `Lilli ${j.kind} ${j.status === 'success' ? 'finished' : j.status}`;
    showToast(title, j.status === 'success' ? 'ok' : 'err');
    try { window.lcNative && window.lcNative.post('notify', { title, body: j.error || (j.sha ? j.sha.slice(0, 7) : '') }); } catch {}
    liLoadStatus();
    liLoadReleases();
  }
}

function liRenderJob() {
  const head = document.getElementById('liJobHead');
  if (!head) return;
  const j = liJobState;
  const actions = document.getElementById('liJobActions');
  const pre = document.getElementById('liJobLog');
  if (!j) {
    head.innerHTML = `<span class="label">Job</span><span class="muted" style="font-size:12px">No deploy or rollback since the helper started.</span>`;
    actions.innerHTML = '';
    pre.innerHTML = '<span class="muted">Output appears here.</span>';
    return;
  }
  const pill = { running: ['Running', 'warn'], success: ['Succeeded', 'ok'], failed: ['Failed', 'err'], cancelled: ['Cancelled', 'err'] }[j.status] || [j.status, ''];
  const what = j.kind === 'deploy' ? `Deploy ${j.sha.slice(0, 7)} · ${j.subject || ''}` : 'Rollback to previous release';
  const secs = Math.round(((j.endedAt || Date.now()) - j.startedAt) / 1000);
  head.innerHTML = `<span class="pill ${pill[1]}">${pill[1] === 'warn' ? '<span class="dot warn live"></span>' : ''}${pill[0]}</span>
    <span style="font-weight:600">${escHtml(what)}</span>
    <span class="muted mono" style="font-size:11px">${Math.floor(secs / 60)}:${String(secs % 60).padStart(2, '0')}</span>
    ${j.error && j.status !== 'cancelled' ? `<span class="mono" style="color:var(--err);font-size:11px">${escHtml(j.error)}</span>` : ''}`;
  actions.innerHTML = (j.status === 'running' ? `<button class="btn btn-sm" onclick="liCancel()"><span class="material-symbols-outlined">stop</span>Stop</button>` : '')
    + `<button class="btn btn-sm" onclick="copyText(document.getElementById('liJobLog').innerText, 'Copied log')"><span class="material-symbols-outlined">content_copy</span>Copy</button>`;
  const atBottom = pre.scrollTop + pre.clientHeight >= pre.scrollHeight - 24;
  pre.innerHTML = liLines.length ? liLines.map(l => {
    const cls = /^\[lilli\]/.test(l) ? 'l-mark' : /\b(error|Error|ERR!|failed|FAILED|unhealthy)\b/.test(l) ? 'l-err' : /\b(warn|WARN|WARNING)\b/.test(l) ? 'l-warn' : '';
    return cls ? `<span class="${cls}">${escHtml(l)}</span>` : escHtml(l);
  }).join('\n') : '<span class="muted">Waiting for output…</span>';
  if (atBottom) pre.scrollTop = pre.scrollHeight;
}

async function liLoadReleases() {
  const box = document.getElementById('liReleases');
  if (!box) return;
  try {
    const { releases } = await gbpApi('/api/lilli/releases');
    box.innerHTML = releases.length
      ? `<div class="label" style="margin:var(--s-2) 0">Releases on the box</div>` + tableShell(['Release', 'Built', 'Commit', ''], releases.map(r => `
          <tr style="cursor:default"><td class="mono" style="color:var(--ink)">${escHtml(r.name)}</td>
          <td class="muted">${escHtml(deTime(r.builtAt))}</td><td>${escHtml(r.subject || '')}</td>
          <td style="text-align:right">${r.live ? '<span class="pill ok">live</span>' : ''}</td></tr>`).join(''))
      : `<div class="muted" style="font-size:12px">No releases yet. The first deploy moves the box from its in-place checkout onto releases.</div>`;
  } catch (e) { box.innerHTML = errorState(e.message); }
}
