// ═════════════════════════════════════════════════════════════════════════
// LOCAL STACK (Serverpod dev server + Docker Postgres/Redis)
// ═════════════════════════════════════════════════════════════════════════
// Backed by /api/local-stack/*; the helper's launchd agent keeps it running.
const LS_STATE_LABEL = {
  running: ['Running', 'ok'], starting: ['Starting', 'warn'], stopping: ['Stopping', 'warn'],
  stopped: ['Stopped', 'err'], crashed: ['Crashed', 'plate-err'], unavailable: ['Not installed', 'err'],
};
let lsLast = null;
let lsLogSource = 'serverpod';
let lsTimer = null;

async function lsFetchStatus() {
  const r = await fetch('/api/local-stack/status');
  if (!r.ok) throw new Error(`status ${r.status}`);
  lsLast = await r.json();
  lsUpdateTicker();
  return lsLast;
}

function lsUpdateTicker() {
  const st = lsLast;
  if (!st) return;
  const sp = st.serverpod.state, dk = st.docker.state;
  const cls = (s) => s === 'running' ? 'ok' : (s === 'starting' || s === 'stopping') ? 'warn' : 'err';
  const set = (id, led, s) => {
    const el = document.getElementById(id); if (el) el.textContent = (LS_STATE_LABEL[s] || [s])[0].toLowerCase();
    const l = document.getElementById(led); if (l) l.className = 'led ' + cls(s);
  };
  set('tkSp', 'tkSpLed', sp);
  set('tkDk', 'tkDkLed', dk);
}

async function lsAction(action, body = {}) {
  try {
    const r = await fetch(`/api/local-stack/${action}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
    if (!r.ok) throw new Error((await r.json().catch(() => ({}))).error || `HTTP ${r.status}`);
    lsLast = await r.json();
    showToast(action === 'start' ? 'Starting Serverpod' : action === 'stop' ? 'Stopping' : action === 'restart' ? 'Restarting Serverpod' : 'Saved', 'ok');
  } catch (e) { showToast('Local stack: ' + e.message, 'err'); }
  if (window.__currentView === 'local-stack') lsRenderBoard(); else lsUpdateTicker();
}

async function lsSetConfig(key, value) {
  try {
    await fetch('/api/local-stack/config', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ [key]: value }) });
    showToast(key === 'autostart' ? (value ? 'Serverpod will start with LC Helper' : 'Serverpod will not start automatically') : (value ? 'Migrations will be applied on next start' : 'Migrations will not be applied'), 'ok');
  } catch (e) { showToast('Could not save: ' + e.message, 'err'); }
}

function lsRelTime(ts) {
  if (!ts) return '—';
  if (Date.now() - ts > 6 * 3600 * 1000) return new Intl.DateTimeFormat('de-DE', { timeZone: DE_TZ, day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit' }).format(new Date(ts));
  const s = Math.round((Date.now() - ts) / 1000);
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)} min ago`;
  return `${Math.floor(s / 3600)} h ${Math.floor((s % 3600) / 60)} min ago`;
}

function lsPlate(state) {
  const [label, cls] = LS_STATE_LABEL[state] || [state, ''];
  return `<span class="pill ${cls}">${cls === 'ok' || cls === 'warn' ? `<span class="dot ${cls}${state !== 'running' ? ' live' : ''}"></span>` : ''}${escHtml(label)}</span>`;
}

function renderLocalStack(el) {
  el.innerHTML = pageWrap(`
    ${pageHero('Local Stack', {
      sub: 'Serverpod development server and its Docker Postgres + Redis, kept running by LC Helper so the Dev environment always answers.',
      actions: `
        <button class="btn btn-primary" id="lsStartBtn" onclick="lsAction('start')"><span class="material-symbols-outlined">play_arrow</span>Start</button>
        <button class="btn" onclick="lsAction('restart')"><span class="material-symbols-outlined">restart_alt</span>Restart</button>
        <button class="btn" onclick="lsAction('stop')"><span class="material-symbols-outlined">stop</span>Stop Serverpod</button>
        <button class="btn btn-ghost" onclick="if (confirm('Stop Serverpod and the Postgres/Redis containers?')) lsAction('stop', { includeDocker: true })">Stop all</button>`,
    })}
    <div id="lsError"></div>
    <div class="panel" style="margin-bottom:var(--s-5);overflow:hidden">
      <table class="lc-table ls-board">
        <thead><tr><th>Since</th><th>Service</th><th>Status</th><th>Detail</th><th style="text-align:right">Port</th></tr></thead>
        <tbody id="lsBoard"><tr><td colspan="5" class="muted">Loading…</td></tr></tbody>
      </table>
    </div>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:var(--s-4);margin-bottom:var(--s-5)">
      <label class="switch panel" style="padding:12px 14px"><input type="checkbox" id="lsAutostart" onchange="lsSetConfig('autostart', this.checked)">
        <span>Start Serverpod with LC Helper<small>Runs at login, together with the helper server.</small></span></label>
      <label class="switch panel" style="padding:12px 14px"><input type="checkbox" id="lsMigrations" onchange="lsSetConfig('applyMigrations', this.checked)">
        <span>Apply migrations on start<small>Passes --apply-migrations to the local dev database only.</small></span></label>
    </div>
    <div class="panel" style="overflow:hidden">
      <div class="panel-header">
        <div class="lc-tabs" style="border:0">
          <button class="lc-tab" data-src="serverpod" onclick="lsSwitchLog('serverpod')">Serverpod log</button>
          <button class="lc-tab" data-src="helper" onclick="lsSwitchLog('helper')">Helper server log</button>
        </div>
        <div class="panel-actions">
          <span class="muted mono" id="lsLogFile" style="font-size:11px"></span>
          <button class="btn btn-sm" onclick="copyText(document.getElementById('lsLog').innerText, 'Copied log')"><span class="material-symbols-outlined">content_copy</span>Copy</button>
        </div>
      </div>
      <pre class="ls-log" id="lsLog"></pre>
    </div>`);
  lsSwitchLog(lsLogSource);
  lsRenderBoard();
  clearInterval(lsTimer);
  lsTimer = setInterval(() => {
    if (window.__currentView !== 'local-stack') { clearInterval(lsTimer); return; }
    lsRenderBoard(); lsLoadLog();
  }, 2500);
}

async function lsRenderBoard() {
  const board = document.getElementById('lsBoard');
  if (!board) return;
  let st;
  try { st = await lsFetchStatus(); }
  catch (e) { document.getElementById('lsError').innerHTML = errorState('Could not reach /api/local-stack: ' + e.message); return; }
  document.getElementById('lsError').innerHTML = st.actionError ? errorState(st.actionError)
    : !st.serverpodDirExists ? errorState('Serverpod project not found at ' + st.serverpodDir) : '';
  const byService = Object.fromEntries((st.docker.containers || []).map(c => [c.service, c]));
  const cstate = (c) => !c ? (st.docker.state === 'running' ? 'stopped' : st.docker.state) : c.state === 'running' ? 'running' : c.state === 'restarting' ? 'starting' : 'stopped';
  const sp = st.serverpod;
  const rows = [
    { state: sp.state, name: 'Serverpod API', port: '8080', detail: [sp.state === 'crashed' ? `Exited with code ${sp.exitCode}` : sp.detail, sp.pid ? `pid ${sp.pid}` : '', sp.applyMigrations ? 'with migrations' : ''].filter(Boolean).join(' · '), since: sp.since || sp.exitedAt },
    { state: cstate(byService.postgres), name: 'Postgres', port: '8090', detail: byService.postgres ? byService.postgres.status : 'docker compose service', since: null },
    { state: cstate(byService.redis), name: 'Redis', port: '8091', detail: byService.redis ? byService.redis.status : 'docker compose service', since: null },
    { state: st.docker.state, name: 'Docker Desktop', port: '—', detail: st.docker.detail || '', since: null },
  ];
  board.innerHTML = rows.map(r => `<tr style="cursor:default">
    <td class="ls-since">${escHtml(lsRelTime(r.since))}</td>
    <td style="color:var(--ink)">${escHtml(r.name)}</td>
    <td class="state">${lsPlate(r.state)}</td>
    <td class="muted">${escHtml(r.detail)}</td>
    <td style="text-align:right">${r.port === '—' ? '' : `<span class="gleis">${escHtml(r.port)}</span>`}</td></tr>`).join('');
  const a = document.getElementById('lsAutostart'); if (a && document.activeElement !== a) a.checked = !!st.config.autostart;
  const m = document.getElementById('lsMigrations'); if (m && document.activeElement !== m) m.checked = !!st.config.applyMigrations;
  const startBtn = document.getElementById('lsStartBtn');
  if (startBtn) startBtn.disabled = !!st.action || sp.state === 'running' || sp.state === 'starting';
}

function lsSwitchLog(src) {
  lsLogSource = src;
  document.querySelectorAll('.lc-tab[data-src]').forEach(t => t.classList.toggle('active', t.dataset.src === src));
  const pre = document.getElementById('lsLog'); if (pre) { pre.dataset.stick = '1'; pre.textContent = ''; }
  lsLoadLog();
}

async function lsLoadLog() {
  const pre = document.getElementById('lsLog');
  if (!pre) return;
  try {
    const r = await fetch(`/api/local-stack/logs?tail=800&service=${lsLogSource}`);
    const { file, lines } = await r.json();
    document.getElementById('lsLogFile').textContent = file || '';
    const atBottom = pre.scrollTop + pre.clientHeight >= pre.scrollHeight - 24;
    pre.innerHTML = lines.length ? lines.map(l => {
      const cls = /────/.test(l) ? 'l-mark' : /\b(ERROR|FATAL|Exception|Unhandled)\b/.test(l) ? 'l-err' : /\bWARN(ING)?\b/.test(l) ? 'l-warn' : '';
      return cls ? `<span class="${cls}">${escHtml(l)}</span>` : escHtml(l);
    }).join('\n') : '<span class="muted">No output yet.</span>';
    if (atBottom || pre.dataset.stick === '1') { pre.scrollTop = pre.scrollHeight; pre.dataset.stick = ''; }
  } catch (e) { pre.textContent = 'Could not load log: ' + e.message; }
}

// Header ticker: refresh local stack state every 10 s.
lsFetchStatus().catch(() => {});
setInterval(() => { if (window.__currentView !== 'local-stack') lsFetchStatus().catch(() => {}); }, 10000);
