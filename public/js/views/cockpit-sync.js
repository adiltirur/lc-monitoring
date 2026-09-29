// ═════════════════════════════════════════════════════════════════════════
// COCKPIT SYNC — copy cockpit + opening-hours data between two envs
// ═════════════════════════════════════════════════════════════════════════
//
// Same shape as Praxis Refresh (two env header sets), but scoped to the 5
// cockpit-relevant tables and matched by lcId. Praxes that don't exist on
// the target are skipped. Replace mode wipes the praxis's existing rows on
// target before inserting from source.

const CS_STATE_KEY = 'lc_cockpit_sync_state';
const CS_DEFAULT_STATE = {
  src: 'production',
  tgt: 'staging',
  summary: null,        // { rows: [{lcId, name, counts: {...}}] }
  selectedLcIds: null,  // null = all
  replace: true,
  result: null,
  log: [],
};

let csState = (() => {
  try {
    const saved = JSON.parse(localStorage.getItem(CS_STATE_KEY) || 'null');
    return { ...CS_DEFAULT_STATE, ...(saved || {}) };
  } catch { return { ...CS_DEFAULT_STATE }; }
})();

function csSaveState() { try { localStorage.setItem(CS_STATE_KEY, JSON.stringify(csState)); } catch {} }
function csResetState() {
  if (!confirm('Reset Cockpit Sync wizard? Local progress markers will be cleared. DB data already written stays.')) return;
  csState = { ...CS_DEFAULT_STATE, log: [] };
  localStorage.removeItem(CS_STATE_KEY);
  csRender();
  csLog('Wizard reset.');
}
function csLog(msg, type = 'info') {
  csState.log.push({ ts: new Date().toISOString().slice(11, 19), msg, type });
  csRefreshLog();
}
function csRefreshLog() {
  const el = document.getElementById('csLog');
  if (!el) return;
  el.innerHTML = csState.log.map(e => {
    const cls = e.type === 'error' ? 'text-red-500' : e.type === 'ok' ? 'text-emerald-500' : e.type === 'warn' ? 'text-amber-500' : 'text-on-surface-variant';
    return `<div class="text-xs mono-text ${cls}">[${e.ts}] ${escHtml(e.msg)}</div>`;
  }).join('');
  el.scrollTop = el.scrollHeight;
}

async function renderCockpitSync(el) {
  el.innerHTML = pageWrap(pageHero('Cockpit Sync') + loadingState());
  try { await ensureEnvPasswords(); }
  catch (e) {
    el.innerHTML = pageWrap(pageHero('Cockpit Sync') + errorState('Failed to load env passwords: ' + e.message));
    return;
  }
  csRender();
}

function csRender() {
  const el = document.getElementById('content');
  if (!el) return;
  csSaveState();

  const envOpt = (cur) => Object.keys(PRESETS).map(k =>
    `<option value="${k}" ${k === cur ? 'selected' : ''}>${escHtml(k)}</option>`).join('');

  const sameEnv = csState.src === csState.tgt;
  const tgtIsProd = csState.tgt === 'production';

  // ── Step 1: source/target picker ────────────────────────────────────────
  const step1 = `<section class="bg-surface-container-lowest rounded-xl shadow-whisper p-6 mb-4">
    <h3 class="text-base font-bold flex items-center gap-2 mb-3"><span class="material-symbols-outlined">database</span>Step 1 · Source &amp; Target</h3>
    <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
      <div>
        <label class="block text-[10px] uppercase tracking-wider font-bold text-on-surface-variant mb-1.5">Source (read)</label>
        <select class="w-full bg-surface-container border-none rounded-lg text-sm px-3 py-2.5 mono-text" onchange="csState.src=this.value;csState.summary=null;csRender()">${envOpt(csState.src)}</select>
        <div class="text-[10px] mono-text text-outline mt-1">${escHtml(PRESETS[csState.src]?.host)}:${escHtml(PRESETS[csState.src]?.port)}/${escHtml(PRESETS[csState.src]?.db)}</div>
      </div>
      <div>
        <label class="block text-[10px] uppercase tracking-wider font-bold text-on-surface-variant mb-1.5">Target (write)</label>
        <select class="w-full bg-surface-container border-none rounded-lg text-sm px-3 py-2.5 mono-text" onchange="csState.tgt=this.value;csRender()">${envOpt(csState.tgt)}</select>
        <div class="text-[10px] mono-text text-outline mt-1">${escHtml(PRESETS[csState.tgt]?.host)}:${escHtml(PRESETS[csState.tgt]?.port)}/${escHtml(PRESETS[csState.tgt]?.db)}</div>
      </div>
    </div>
    ${sameEnv ? `<div class="mt-3 text-xs text-amber-600 font-bold">⚠ Source and target must differ.</div>`
              : tgtIsProd ? `<div class="mt-3 text-xs text-red-600 font-bold">⛔ Target = production. Server will refuse the copy.</div>` : ''}
    <div class="mt-4 flex items-center gap-3">
      <label class="flex items-center gap-2 text-xs"><input type="checkbox" ${csState.replace ? 'checked' : ''} onchange="csState.replace=this.checked;csSaveState()"/> Replace target rows for each praxis (delete then insert)</label>
    </div>
  </section>`;

  // ── Step 2: source preview / praxis selector ────────────────────────────
  const summary = csState.summary;
  let praxisGrid = '';
  if (summary && summary.rows) {
    const rows = summary.rows;
    const allSelected = csState.selectedLcIds === null;
    const selSet = allSelected ? null : new Set(csState.selectedLcIds || []);
    const isSel = (lcId) => allSelected || selSet.has(lcId);
    const checkboxes = rows.map(r => {
      const total = Object.values(r.counts).reduce((a, c) => a + (typeof c === 'number' ? c : 0), 0);
      return `<tr class="border-b border-outline-variant">
        <td class="px-2 py-1.5"><input type="checkbox" ${isSel(r.lcId) ? 'checked' : ''} onchange="csTogglePraxis('${escHtml(r.lcId)}', this.checked)"/></td>
        <td class="px-2 py-1.5 mono-text text-xs font-bold">${escHtml(r.lcId)}</td>
        <td class="px-2 py-1.5 text-xs">${escHtml(r.name || '')}</td>
        <td class="px-2 py-1.5 text-[10px] mono-text text-on-surface-variant">${total === 0 ? '<span class="text-outline italic">empty</span>' : Object.entries(r.counts).map(([t, n]) => `${t.replace(/^cockpit_|^praxis_/, '')}=${n}`).join(' · ')}</td>
      </tr>`;
    }).join('');
    praxisGrid = `<div class="overflow-auto max-h-72 border border-outline-variant rounded mt-3">
      <table class="w-full text-xs"><thead class="bg-surface-container sticky top-0"><tr>
        <th class="px-2 py-1.5 text-left"><input type="checkbox" ${allSelected ? 'checked' : ''} onchange="csToggleAll(this.checked)"/></th>
        <th class="px-2 py-1.5 text-left">lcId</th><th class="px-2 py-1.5 text-left">name</th><th class="px-2 py-1.5 text-left">source counts</th>
      </tr></thead><tbody>${checkboxes}</tbody></table>
    </div>`;
  }

  const step2 = `<section class="bg-surface-container-lowest rounded-xl shadow-whisper p-6 mb-4 ${sameEnv ? 'opacity-40 pointer-events-none' : ''}">
    <div class="flex items-center justify-between">
      <h3 class="text-base font-bold flex items-center gap-2"><span class="material-symbols-outlined">visibility</span>Step 2 · Preview source ${escHtml(csState.src)}</h3>
      <button class="px-3 py-1.5 bg-surface-container rounded text-xs font-bold hover:bg-surface-container-high" onclick="csLoadSummary()">${summary ? 'Reload' : 'Load source praxes'}</button>
    </div>
    <div class="text-xs text-on-surface-variant mt-1">Per-praxis row counts across the 5 cockpit tables (praxis_hours_config + the four cockpit_*).</div>
    ${praxisGrid}
  </section>`;

  // ── Step 3: run sync ────────────────────────────────────────────────────
  const im = csState.result;
  const selCount = csState.selectedLcIds === null ? (summary?.rows.length || 0) : (csState.selectedLcIds.length);
  const canRun = !!summary && !sameEnv && !tgtIsProd && selCount > 0;

  const resultBody = im ? `<div class="bg-surface-container rounded p-3 mt-3 text-[10px] mono-text max-h-64 overflow-auto">
    ${im.error ? `<div class="text-red-600">${escHtml(im.error)}</div>` :
      (im.results || []).map(r => {
        const cls = r.status === 'ok' ? 'text-emerald-600' : r.status === 'skipped' ? 'text-amber-600' : 'text-red-600';
        const tail = r.perTable ? Object.entries(r.perTable).map(([t, v]) => `${t.replace(/^cockpit_|^praxis_/, '')}=${typeof v === 'number' ? v : (v.skipped ? 'skip' : 'err')}`).join(' · ') : (r.reason || '');
        return `<div class="${cls}">${escHtml(r.lcId)}: ${escHtml(r.status)} · ${escHtml(tail)}</div>`;
      }).join('')}
  </div>` : '';

  const step3 = `<section class="bg-surface-container-lowest rounded-xl shadow-whisper p-6 mb-4">
    <h3 class="text-base font-bold flex items-center gap-2 mb-3"><span class="material-symbols-outlined">south_west</span>Step 3 · Copy ${escHtml(csState.src)} → ${escHtml(csState.tgt)}</h3>
    <div class="text-xs text-on-surface-variant">${selCount} praxis(es) will be copied. ${csState.replace ? '<span class="text-amber-600 font-bold">Replace mode</span> — target rows for those praxes are wiped first.' : 'Append mode — UNIQUE constraints may collide.'}</div>
    ${resultBody}
    <div class="mt-4">
      <button class="px-4 py-2 bg-primary text-on-primary rounded-lg text-xs font-bold hover:opacity-90 disabled:opacity-30 disabled:cursor-not-allowed" onclick="csRunCopy()" ${!canRun ? 'disabled' : ''}>${im ? 'Re-run sync' : 'Run sync'}</button>
    </div>
  </section>`;

  const logCard = `<section class="bg-surface-container-lowest rounded-xl shadow-whisper p-4">
    <div class="flex items-center justify-between mb-2"><h3 class="text-sm font-bold">Log</h3>
      <button class="text-[10px] uppercase tracking-wider text-on-surface-variant hover:text-primary" onclick="csState.log=[];csRefreshLog()">Clear</button>
    </div>
    <div id="csLog" class="bg-surface-container rounded p-3 max-h-56 overflow-auto"></div>
  </section>`;

  el.innerHTML = pageWrap(
    pageHero('Cockpit Sync', {
      sub: 'Copy cockpit + opening-hours data between two envs. Matches praxes by lcId, remaps numeric FK on insert.',
      actions: `<button class="px-3 py-2 bg-surface-container rounded-lg text-xs font-bold flex items-center gap-1.5" onclick="csResetState()"><span class="material-symbols-outlined text-sm">restart_alt</span>Reset</button>`,
    }) + step1 + step2 + step3 + logCard
  );
  csRefreshLog();
}

function csTogglePraxis(lcId, on) {
  if (csState.selectedLcIds === null) {
    // First explicit deselection — switch from "all" to a copy of all lcIds.
    const allIds = (csState.summary?.rows || []).map(r => r.lcId);
    csState.selectedLcIds = allIds.slice();
  }
  const set = new Set(csState.selectedLcIds);
  if (on) set.add(lcId); else set.delete(lcId);
  csState.selectedLcIds = Array.from(set);
  csRender();
}

function csToggleAll(on) {
  if (on) csState.selectedLcIds = null; // null = all
  else csState.selectedLcIds = [];
  csRender();
}

async function csLoadSummary() {
  csLog(`Loading source summary from ${csState.src}…`);
  try {
    const r = await fetch('/api/cockpit/source-summary', {
      method: 'POST',
      headers: { ...envHeadersFor(csState.src, 'x-src-db-'), 'Content-Type': 'application/json' },
      body: JSON.stringify({}),
    });
    const d = await r.json();
    if (!r.ok) throw new Error(d.error || `HTTP ${r.status}`);
    csState.summary = d;
    csState.selectedLcIds = null; // default: all
    csLog(`Loaded ${d.rows.length} praxes from ${csState.src}.`, 'ok');
  } catch (e) { csLog('Source summary failed: ' + e.message, 'error'); }
  finally { csRender(); }
}

async function csRunCopy() {
  if (csState.tgt === 'production') { showToast('Refusing to copy to production.'); return; }
  if (csState.src === csState.tgt) { showToast('Source and target must differ.'); return; }
  const lcIds = csState.selectedLcIds === null ? (csState.summary?.rows || []).map(r => r.lcId) : csState.selectedLcIds;
  if (!lcIds.length) { showToast('Select at least one praxis.'); return; }
  if (!confirm(`Copy ${lcIds.length} praxis(es) of cockpit data ${csState.src} → ${csState.tgt}?${csState.replace ? '\n\nReplace mode: existing target rows for those praxes will be DELETED first.' : ''}`)) return;
  csLog(`Copying ${lcIds.length} praxis(es) from ${csState.src} → ${csState.tgt}…`);
  try {
    const r = await fetch('/api/cockpit/cross-env-copy', {
      method: 'POST',
      headers: {
        ...envHeadersFor(csState.src, 'x-src-db-'),
        ...envHeadersFor(csState.tgt, 'x-tgt-db-'),
        'x-tgt-env-label': csState.tgt,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ lcIds, replace: csState.replace }),
    });
    const d = await r.json();
    if (!r.ok) throw new Error(d.error || `HTTP ${r.status}`);
    csState.result = d;
    const okCount = (d.results || []).filter(x => x.status === 'ok').length;
    const skipCount = (d.results || []).filter(x => x.status === 'skipped').length;
    csLog(`Sync done — ${okCount} ok, ${skipCount} skipped.`, 'ok');
  } catch (e) {
    csState.result = { error: e.message };
    csLog('Sync failed: ' + e.message, 'error');
  } finally { csRender(); }
}
