// ═════════════════════════════════════════════════════════════════════════
// PRAXIS CLEANUP — single-praxis deep delete + reference scrub
// ═════════════════════════════════════════════════════════════════════════
//
// Pick a praxis, preview what would be touched, type the lcId to confirm,
// then run the deep cleanup (DELETE config + DELETE history + NULL/filter
// user references). Refused on production server-side.

let pcState = {
  env: 'staging',
  lcId: '',
  praxes: [],
  preview: null,
  result: null,
  confirm: '',
  log: [],
};
function pcLog(msg, type = 'info') {
  pcState.log.push({ ts: new Date().toISOString().slice(11, 19), msg, type });
  const el = document.getElementById('pcLog');
  if (!el) return;
  el.innerHTML = pcState.log.map(e => {
    const cls = e.type === 'error' ? 'text-red-500' : e.type === 'ok' ? 'text-emerald-500' : e.type === 'warn' ? 'text-amber-500' : 'text-on-surface-variant';
    return `<div class="text-xs mono-text ${cls}">[${e.ts}] ${escHtml(e.msg)}</div>`;
  }).join('');
  el.scrollTop = el.scrollHeight;
}

async function renderPraxisCleanup(el) {
  el.innerHTML = pageWrap(pageHero('Praxis Cleanup') + loadingState());
  try { await ensureEnvPasswords(); }
  catch (e) {
    el.innerHTML = pageWrap(pageHero('Praxis Cleanup') + errorState('Failed to load env passwords: ' + e.message));
    return;
  }
  pcRender();
}

function pcRender() {
  const el = document.getElementById('content');
  if (!el) return;

  const envOpt = (cur) => Object.keys(PRESETS).map(k =>
    `<option value="${k}" ${k === cur ? 'selected' : ''}>${escHtml(k)}</option>`).join('');
  const tgtIsProd = pcState.env === 'production';

  // ── Step 1: env + praxis picker ──────────────────────────────────────────
  const praxOpts = `<option value="">— pick praxis —</option>` + pcState.praxes.map(p =>
    `<option value="${escHtml(p.lcId)}" ${p.lcId === pcState.lcId ? 'selected' : ''}>${escHtml(p.lcId)} · ${escHtml(p.name || '')}</option>`).join('');
  const step1 = `<section class="bg-surface-container-lowest rounded-xl shadow-whisper p-6 mb-4">
    <h3 class="text-base font-bold flex items-center gap-2 mb-3"><span class="material-symbols-outlined">database</span>Step 1 · Pick env + praxis</h3>
    <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
      <div>
        <label class="block text-[10px] uppercase tracking-wider font-bold text-on-surface-variant mb-1.5">Env</label>
        <select class="w-full bg-surface-container border-none rounded-lg text-sm px-3 py-2.5 mono-text" onchange="pcState.env=this.value;pcState.praxes=[];pcState.preview=null;pcRender()">${envOpt(pcState.env)}</select>
        <div class="text-[10px] mono-text text-outline mt-1">${escHtml(PRESETS[pcState.env]?.host)}:${escHtml(PRESETS[pcState.env]?.port)}/${escHtml(PRESETS[pcState.env]?.db)}</div>
      </div>
      <div>
        <label class="block text-[10px] uppercase tracking-wider font-bold text-on-surface-variant mb-1.5">Praxis</label>
        <div class="flex gap-2">
          <select class="flex-1 bg-surface-container border-none rounded-lg text-sm px-3 py-2.5 mono-text" onchange="pcState.lcId=this.value;pcState.preview=null;pcState.confirm='';pcRender()">${praxOpts}</select>
          <button class="px-3 py-2 bg-surface-container rounded text-xs font-bold hover:bg-surface-container-high" onclick="pcLoadPraxes()">${pcState.praxes.length ? `Reload (${pcState.praxes.length})` : 'Load praxes'}</button>
        </div>
      </div>
    </div>
    ${tgtIsProd ? `<div class="mt-3 text-xs text-red-600 font-bold">⛔ Env = production. Server will refuse the cleanup.</div>` : ''}
  </section>`;

  // ── Step 2: preview ──────────────────────────────────────────────────────
  const pv = pcState.preview;
  let previewBody = '';
  if (pv) {
    const cfgRows = Object.entries(pv.configTables || {}).map(([t, n]) =>
      `<tr><td class="px-2 py-1 mono-text">${escHtml(t)}</td><td class="px-2 py-1 text-right mono-text">${typeof n === 'number' ? n : 'err'}</td><td class="px-2 py-1 text-[10px] uppercase tracking-wider text-on-surface-variant">DELETE</td></tr>`
    ).join('');
    const ncRows = Object.entries(pv.nonConfigTables || {}).map(([t, info]) => {
      const action = info.mode === 'keep' ? 'KEEP' :
                     info.mode === 'null-by-lcid' ? 'NULL' :
                     info.mode === 'remove-from-json-array' ? 'FILTER' : 'DELETE';
      return `<tr><td class="px-2 py-1 mono-text">${escHtml(t)}</td><td class="px-2 py-1 text-right mono-text">${typeof info.rows === 'number' ? info.rows : 'err'}</td><td class="px-2 py-1 text-[10px] uppercase tracking-wider text-on-surface-variant">${action}</td></tr>`;
    }).join('');
    previewBody = `<div class="mt-3 grid grid-cols-1 lg:grid-cols-2 gap-3">
      <div class="bg-surface-container rounded p-2">
        <div class="text-[10px] uppercase tracking-wider font-bold text-on-surface-variant px-2 py-1">Praxis-config tables (DELETE) — ${Object.keys(pv.configTables || {}).length}</div>
        <table class="w-full text-xs"><tbody>${cfgRows}</tbody></table>
      </div>
      <div class="bg-surface-container rounded p-2">
        <div class="text-[10px] uppercase tracking-wider font-bold text-on-surface-variant px-2 py-1">Historical / user tables — ${Object.keys(pv.nonConfigTables || {}).length}</div>
        <table class="w-full text-xs"><tbody>${ncRows}</tbody></table>
      </div>
    </div>`;
  }
  const step2 = `<section class="bg-surface-container-lowest rounded-xl shadow-whisper p-6 mb-4 ${pcState.lcId ? '' : 'opacity-40 pointer-events-none'}">
    <div class="flex items-center justify-between">
      <h3 class="text-base font-bold flex items-center gap-2"><span class="material-symbols-outlined">visibility</span>Step 2 · Preview${pcState.lcId ? ' ' + escHtml(pcState.lcId) : ''}</h3>
      <button class="px-3 py-1.5 bg-surface-container rounded text-xs font-bold hover:bg-surface-container-high" onclick="pcRunPreview()" ${pcState.lcId ? '' : 'disabled'}>${pv ? 'Reload preview' : 'Run preview'}</button>
    </div>
    ${previewBody}
  </section>`;

  // ── Step 3: confirm + run ────────────────────────────────────────────────
  const im = pcState.result;
  let resultBody = '';
  if (im) {
    if (im.error) {
      resultBody = `<div class="bg-red-50 rounded p-3 text-xs mono-text text-red-700 mt-3">${escHtml(im.error)}</div>`;
    } else {
      const cfgDel = Object.entries(im.configDeletedRows || {}).map(([t, n]) => `<div>${escHtml(t)}: ${n}</div>`).join('');
      const ncAct = Object.entries(im.nonConfigActions || {}).map(([t, info]) => `<div>${escHtml(t)}: ${info.mode} · ${info.rows ?? 0}</div>`).join('');
      resultBody = `<div class="grid grid-cols-1 lg:grid-cols-2 gap-3 mt-3">
        <div class="bg-emerald-50 rounded p-2 text-[10px] mono-text text-emerald-700 max-h-40 overflow-auto"><div class="font-bold mb-1">Config DELETEs</div>${cfgDel}</div>
        <div class="bg-emerald-50 rounded p-2 text-[10px] mono-text text-emerald-700 max-h-40 overflow-auto"><div class="font-bold mb-1">Non-config actions</div>${ncAct}</div>
      </div>`;
    }
  }
  const canRun = !!pv && !tgtIsProd && pcState.confirm === pcState.lcId;
  const step3 = `<section data-band="Destructive — changes data in the target database" class="lc-destructive bg-surface-container-lowest rounded-xl shadow-whisper p-6 mb-4 ${pv ? '' : 'opacity-40 pointer-events-none'}">
    <h3 class="text-base font-bold flex items-center gap-2 mb-3"><span class="material-symbols-outlined text-red-500">delete_forever</span>Step 3 · Confirm &amp; delete</h3>
    <div class="text-xs text-on-surface-variant">Type the lcId (<span class="mono-text font-bold">${escHtml(pcState.lcId || '—')}</span>) to enable the delete button. The whole operation runs in one transaction; any error rolls everything back.</div>
    <div class="mt-3 flex items-center gap-3">
      <input placeholder="type lcId to confirm" value="${escHtml(pcState.confirm)}" class="bg-surface-container border-none rounded-lg text-xs px-3 py-2 mono-text" oninput="pcState.confirm=this.value;pcRender()"/>
      <button class="px-4 py-2 bg-red-500 text-white rounded-lg text-xs font-bold hover:bg-red-600 disabled:opacity-30 disabled:cursor-not-allowed" onclick="pcRunDelete()" ${!canRun ? 'disabled' : ''}>Delete praxis &amp; all references</button>
    </div>
    ${resultBody}
  </section>`;

  const logCard = `<section class="bg-surface-container-lowest rounded-xl shadow-whisper p-4">
    <div class="flex items-center justify-between mb-2"><h3 class="text-sm font-bold">Log</h3>
      <button class="text-[10px] uppercase tracking-wider text-on-surface-variant hover:text-primary" onclick="pcState.log=[];pcLog('Log cleared')">Clear</button>
    </div>
    <div id="pcLog" class="bg-surface-container rounded p-3 max-h-48 overflow-auto"></div>
  </section>`;

  el.innerHTML = pageWrap(
    pageHero('Praxis Cleanup', { sub: 'Single-praxis deep delete: removes all config + historical + user-reference rows for one lcId.' }) +
    step1 + step2 + step3 + logCard
  );
  // Repaint the log into the freshly rendered element.
  const lg = document.getElementById('pcLog');
  if (lg) lg.innerHTML = pcState.log.map(e => {
    const cls = e.type === 'error' ? 'text-red-500' : e.type === 'ok' ? 'text-emerald-500' : e.type === 'warn' ? 'text-amber-500' : 'text-on-surface-variant';
    return `<div class="text-xs mono-text ${cls}">[${e.ts}] ${escHtml(e.msg)}</div>`;
  }).join('');
}

async function pcLoadPraxes() {
  pcLog(`Loading praxes from ${pcState.env}…`);
  try {
    const r = await fetch('/api/praxis/list', { headers: { ...envHeadersFor(pcState.env), 'x-env-label': pcState.env } });
    const d = await r.json();
    if (!r.ok) throw new Error(d.error || `HTTP ${r.status}`);
    pcState.praxes = d.rows || [];
    pcLog(`Loaded ${pcState.praxes.length} praxes.`, 'ok');
  } catch (e) { pcLog('Praxes load failed: ' + e.message, 'error'); }
  finally { pcRender(); }
}

async function pcRunPreview() {
  if (!pcState.lcId) return;
  pcLog(`Previewing cleanup for ${pcState.lcId}…`);
  try {
    const r = await fetch('/api/praxis/cleanup-preview', {
      method: 'POST',
      headers: { ...envHeadersFor(pcState.env), 'x-env-label': pcState.env, 'Content-Type': 'application/json' },
      body: JSON.stringify({ lcId: pcState.lcId }),
    });
    const d = await r.json();
    if (!r.ok) throw new Error(d.error || `HTTP ${r.status}`);
    pcState.preview = d;
    const cfgTotal = Object.values(d.configTables || {}).reduce((a, n) => a + (typeof n === 'number' ? n : 0), 0);
    const ncTotal = Object.values(d.nonConfigTables || {}).reduce((a, info) => a + (typeof info?.rows === 'number' ? info.rows : 0), 0);
    pcLog(`Preview: ${cfgTotal} config rows + ${ncTotal} historical/user rows would be touched.`, 'ok');
  } catch (e) {
    pcState.preview = null;
    pcLog('Preview failed: ' + e.message, 'error');
  } finally { pcRender(); }
}

async function pcRunDelete() {
  if (pcState.env === 'production') { showToast('Refusing on production.'); return; }
  if (pcState.confirm !== pcState.lcId) { showToast('Confirmation must equal the lcId.'); return; }
  if (!confirm(`Permanently delete ${pcState.lcId} and all referencing rows on ${pcState.env}? This cannot be undone.`)) return;
  pcLog(`Cleaning up ${pcState.lcId} on ${pcState.env}…`, 'warn');
  try {
    const r = await fetch('/api/praxis/cleanup', {
      method: 'POST',
      headers: { ...envHeadersFor(pcState.env), 'x-env-label': pcState.env, 'x-allow-destructive': 'yes', 'Content-Type': 'application/json' },
      body: JSON.stringify({ lcId: pcState.lcId, confirmation: pcState.confirm }),
    });
    const d = await r.json();
    if (!r.ok) throw new Error(d.error || `HTTP ${r.status}`);
    pcState.result = d;
    const cfgTotal = Object.values(d.configDeletedRows || {}).reduce((a, n) => a + (typeof n === 'number' ? n : 0), 0);
    const ncTotal = Object.values(d.nonConfigActions || {}).reduce((a, info) => a + (typeof info?.rows === 'number' ? info.rows : 0), 0);
    pcLog(`Cleanup done — config rows deleted: ${cfgTotal}, non-config actions: ${ncTotal}.`, 'ok');
    // Refresh praxis list since one is gone.
    pcState.praxes = pcState.praxes.filter(p => p.lcId !== pcState.lcId);
    pcState.preview = null;
    pcState.confirm = '';
    pcState.lcId = '';
  } catch (e) {
    pcState.result = { error: e.message };
    pcLog('Cleanup failed: ' + e.message, 'error');
  } finally { pcRender(); }
}
