// ═════════════════════════════════════════════════════════════════════════
// PRAXIS REFRESH (backup → wipe → import prod → scrub → set default)
// ═════════════════════════════════════════════════════════════════════════
//
// Self-contained admin wizard for refreshing staging from prod. Operates on
// two envs simultaneously, so it bypasses the global env selector and uses
// PRESETS + cached env-config passwords directly. All destructive ops are
// gated server-side (env label, confirmation phrase, x-allow-destructive),
// but the UI also blocks each step on the previous one's success.

const PR_STATE_KEY = 'lc_praxis_refresh_state';
const PR_DEFAULT_STATE = {
  src: 'production',
  tgt: 'staging',
  driftResult: null,
  driftAck: false,
  backupResult: null,
  wipeResult: null,
  importResult: null,
  scrubResult: null,
  setDefaultResult: null,
  scrubEmail: 'developer@lillian-care.de',
  scrubPhone: '+4917630598897',
  scrubVitasAIPraxisId: '',
  selectedDefaultLcId: '',
  imported: [],
  log: [],
};

let prState = (() => {
  try {
    const saved = JSON.parse(localStorage.getItem(PR_STATE_KEY) || 'null');
    return { ...PR_DEFAULT_STATE, ...(saved || {}), busy: '' };
  } catch {
    return { ...PR_DEFAULT_STATE, busy: '' };
  }
})();

function prSaveState() {
  try {
    // Skip the transient `busy` flag.
    const { busy, ...rest } = prState;
    localStorage.setItem(PR_STATE_KEY, JSON.stringify(rest));
  } catch { /* quota or disabled */ }
}

function prResetState() {
  if (!confirm('Reset the Praxis Refresh wizard? This clears local progress markers but does NOT undo any DB changes already made on staging.')) return;
  prState = { ...PR_DEFAULT_STATE, busy: '', log: [] };
  localStorage.removeItem(PR_STATE_KEY);
  prRender();
  prLog('Wizard reset.');
}

// Use when you've already done backup + wipe in a previous session and want
// to resume at step 3 (import) without re-running the no-op wipe and the
// redundant second backup. Marks steps 0-2 as skipped so the gates open.
function prMarkPreImportDone() {
  if (!confirm('Mark steps 0-2 (drift check, backup, wipe) as already complete? Use this only if staging is already wiped and you have backups elsewhere.')) return;
  prState.driftResult = prState.driftResult || { skipped: true, covered: [], historical: [], drift: [], missing: [] };
  prState.driftAck = true;
  prState.backupResult = prState.backupResult || { skipped: true };
  prState.wipeResult = prState.wipeResult || { skipped: true };
  prRender();
  prLog('Marked steps 0-2 as already complete (skipped).', 'warn');
}

function prLog(msg, type = 'info') {
  prState.log.push({ ts: new Date().toISOString().slice(11, 19), msg, type });
  const el = document.getElementById('prLog');
  if (el) {
    el.innerHTML = prState.log.map(e => {
      const cls = e.type === 'error' ? 'text-red-500' : e.type === 'ok' ? 'text-emerald-500' : e.type === 'warn' ? 'text-amber-500' : 'text-on-surface-variant';
      return `<div class="text-xs mono-text ${cls}">[${e.ts}] ${escHtml(e.msg)}</div>`;
    }).join('');
    el.scrollTop = el.scrollHeight;
  }
}

function prStepStatus(result) {
  if (!result) return `<span class="px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider bg-slate-100 text-slate-600">Pending</span>`;
  if (result.error) return `<span class="px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider bg-red-100 text-red-700">Error</span>`;
  if (result.skipped) return `<span class="px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider bg-amber-100 text-amber-700">Skipped</span>`;
  return `<span class="px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider bg-emerald-100 text-emerald-700">Done</span>`;
}

async function renderPraxisRefresh(el) {
  el.innerHTML = pageWrap(pageHero('Praxis Refresh') + loadingState());
  try {
    await ensureEnvPasswords();
  } catch (e) {
    el.innerHTML = pageWrap(pageHero('Praxis Refresh') + errorState('Failed to load env passwords: ' + e.message));
    return;
  }
  prRender();
}

function prRender() {
  const el = document.getElementById('content');
  if (!el) return;
  prSaveState();

  const envOpt = (cur) => Object.keys(PRESETS).map(k =>
    `<option value="${k}" ${k === cur ? 'selected' : ''}>${escHtml(k)}</option>`
  ).join('');

  // ── Source / Target picker ──────────────────────────────────────────────
  const envCard = `<section class="bg-surface-container-lowest rounded-xl shadow-whisper p-6 mb-6">
    <h2 class="text-lg font-bold tracking-tight mb-4 flex items-center gap-2">
      <span class="material-symbols-outlined">database</span>Source &amp; Target
    </h2>
    <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
      <div>
        <label class="block text-[10px] uppercase tracking-wider font-bold text-on-surface-variant mb-1.5">Source (read)</label>
        <select id="prSrc" class="w-full bg-surface-container border-none rounded-lg text-sm px-3 py-2.5 mono-text focus:ring-2 focus:ring-primary-fixed" onchange="prState.src=this.value;prRender()">${envOpt(prState.src)}</select>
        <div class="text-[10px] mono-text text-outline mt-1">${escHtml(PRESETS[prState.src]?.host)}:${escHtml(PRESETS[prState.src]?.port)}/${escHtml(PRESETS[prState.src]?.db)}</div>
      </div>
      <div>
        <label class="block text-[10px] uppercase tracking-wider font-bold text-on-surface-variant mb-1.5">Target (write)</label>
        <select id="prTgt" class="w-full bg-surface-container border-none rounded-lg text-sm px-3 py-2.5 mono-text focus:ring-2 focus:ring-primary-fixed" onchange="prState.tgt=this.value;prRender()">${envOpt(prState.tgt)}</select>
        <div class="text-[10px] mono-text text-outline mt-1">${escHtml(PRESETS[prState.tgt]?.host)}:${escHtml(PRESETS[prState.tgt]?.port)}/${escHtml(PRESETS[prState.tgt]?.db)}</div>
      </div>
    </div>
    ${prState.src === prState.tgt
      ? `<div class="mt-3 text-xs text-amber-600 font-bold">⚠ Source and Target are the same — pick different envs.</div>`
      : prState.tgt === 'production'
        ? `<div class="mt-3 text-xs text-red-600 font-bold">⛔ Target = production. Backend will refuse destructive steps.</div>`
        : ''}
  </section>`;

  const sameEnv = prState.src === prState.tgt;

  // ── Step 0: schema drift ────────────────────────────────────────────────
  const drift = prState.driftResult;
  const driftBody = drift
    ? `<div class="grid grid-cols-3 gap-3 mt-3">
        <div class="bg-emerald-50 rounded-lg p-3">
          <div class="text-[10px] uppercase font-bold text-emerald-700 tracking-wider">Covered (${drift.covered.length})</div>
          <div class="text-[10px] mono-text text-emerald-700 mt-1 max-h-24 overflow-auto">${drift.covered.map(r => escHtml(r.table_name)).join('<br>') || '—'}</div>
        </div>
        <div class="bg-amber-50 rounded-lg p-3">
          <div class="text-[10px] uppercase font-bold text-amber-700 tracking-wider">Historical (not wiped, ${drift.historical.length})</div>
          <div class="text-[10px] mono-text text-amber-700 mt-1 max-h-24 overflow-auto">${drift.historical.map(r => escHtml(r.table_name)).join('<br>') || '—'}</div>
        </div>
        <div class="${drift.drift.length ? 'bg-red-50' : 'bg-slate-50'} rounded-lg p-3">
          <div class="text-[10px] uppercase font-bold ${drift.drift.length ? 'text-red-700' : 'text-slate-600'} tracking-wider">Drift (${drift.drift.length})</div>
          <div class="text-[10px] mono-text ${drift.drift.length ? 'text-red-700' : 'text-slate-600'} mt-1 max-h-24 overflow-auto">${drift.drift.map(r => escHtml(r.table_name)).join('<br>') || '—'}</div>
        </div>
      </div>
      ${drift.missing && drift.missing.length ? `<div class="mt-3 text-xs text-red-600 mono-text">Missing on target: ${drift.missing.map(escHtml).join(', ')}</div>` : ''}
      ${drift.drift.length ? `<label class="mt-3 flex items-center gap-2 text-xs text-on-surface-variant">
        <input type="checkbox" ${prState.driftAck ? 'checked' : ''} onchange="prState.driftAck=this.checked;prRender()"/>
        I have reviewed the drift tables and understand they will NOT be backed up or imported.
      </label>` : ''}`
    : `<div class="text-xs text-outline italic mt-2">Run the check before continuing.</div>`;

  const step0 = `<section class="bg-surface-container-lowest rounded-xl shadow-whisper p-6 mb-4">
    <div class="flex items-center justify-between">
      <h3 class="text-base font-bold flex items-center gap-2"><span class="material-symbols-outlined text-primary">policy</span>Step 0 · Schema drift check on ${escHtml(prState.tgt)}</h3>
      ${prStepStatus(drift)}
    </div>
    <div class="text-xs text-on-surface-variant mt-1">Confirms the helper's hardcoded table list still matches the target schema.</div>
    ${driftBody}
    <div class="mt-4">
      <button class="px-4 py-2 bg-primary text-on-primary rounded-lg text-xs font-bold hover:opacity-90 disabled:opacity-30 disabled:cursor-not-allowed" onclick="prRunDriftCheck()" ${prState.busy || sameEnv ? 'disabled' : ''}>${prState.busy === 'drift' ? 'Checking…' : 'Run schema check'}</button>
    </div>
  </section>`;

  // Steps 1+ are gated on Step 0 succeeding (and ack if drift > 0).
  const driftPasses = drift && drift.drift.length === 0;
  const driftCleared = drift && (drift.drift.length === 0 || prState.driftAck);
  const canProceed = !!driftCleared && !sameEnv;

  // ── Step 1: backup ──────────────────────────────────────────────────────
  const bk = prState.backupResult;
  const step1 = `<section class="bg-surface-container-lowest rounded-xl shadow-whisper p-6 mb-4 ${canProceed ? '' : 'opacity-40 pointer-events-none'}">
    <div class="flex items-center justify-between">
      <h3 class="text-base font-bold flex items-center gap-2"><span class="material-symbols-outlined text-primary">save</span>Step 1 · Backup ${escHtml(prState.src)} + ${escHtml(prState.tgt)}</h3>
      ${prStepStatus(bk)}
    </div>
    <div class="text-xs text-on-surface-variant mt-1">Writes one JSON file per praxis to <span class="mono-text">helper/backups/&lt;env&gt;/&lt;timestamp&gt;/&lt;lcId&gt;.json</span>.</div>
    ${bk ? `<div class="mt-3 text-xs mono-text text-on-surface-variant">
      <div>Source (${escHtml(prState.src)}): ${bk.src ? `${bk.src.count} files → ${escHtml(bk.src.dir)}` : '—'}</div>
      <div>Target (${escHtml(prState.tgt)}): ${bk.tgt ? `${bk.tgt.count} files → ${escHtml(bk.tgt.dir)}` : '—'}</div>
    </div>` : ''}
    <div class="mt-4">
      <button class="px-4 py-2 bg-primary text-on-primary rounded-lg text-xs font-bold hover:opacity-90 disabled:opacity-30 disabled:cursor-not-allowed" onclick="prRunBackup()" ${prState.busy ? 'disabled' : ''}>${prState.busy === 'backup' ? 'Backing up…' : 'Run backup'}</button>
    </div>
  </section>`;

  const canWipe = canProceed && !!bk && !bk.error;

  // ── Step 2: wipe staging ────────────────────────────────────────────────
  const wp = prState.wipeResult;
  const step2 = `<section data-band="Destructive — changes data in the target database" class="lc-destructive bg-surface-container-lowest rounded-xl shadow-whisper p-6 mb-4 ${canWipe ? '' : 'opacity-40 pointer-events-none'}">
    <div class="flex items-center justify-between">
      <h3 class="text-base font-bold flex items-center gap-2"><span class="material-symbols-outlined text-red-500">delete_forever</span>Step 2 · Wipe praxis config on ${escHtml(prState.tgt)}</h3>
      ${prStepStatus(wp)}
    </div>
    <div class="text-xs text-on-surface-variant mt-1">DELETEs every row from the 25 praxis-config tables. Historical tables (appointments, audit, NPS) untouched.</div>
    ${wp ? `<div class="mt-3 text-[10px] mono-text text-on-surface-variant max-h-32 overflow-auto bg-surface-container rounded p-2">${Object.entries(wp.deletedRowsByTable || {}).map(([t,n]) => `${escHtml(t)}: ${n}`).join('<br>')}</div>` : ''}
    <div class="mt-4 flex items-center gap-3">
      <input id="prWipeConfirm" placeholder='Type WIPE STAGING to enable' class="bg-surface-container border-none rounded-lg text-xs px-3 py-2 mono-text" oninput="document.getElementById('prWipeBtn').disabled = this.value !== 'WIPE STAGING' || !!window.__prBusy"/>
      <button id="prWipeBtn" class="px-4 py-2 bg-red-500 text-white rounded-lg text-xs font-bold hover:bg-red-600 disabled:opacity-30 disabled:cursor-not-allowed" onclick="prRunWipe()" disabled>${prState.busy === 'wipe' ? 'Wiping…' : 'Wipe staging'}</button>
    </div>
  </section>`;

  const canImport = canWipe && !!wp && !wp.error;

  // ── Step 3: import ──────────────────────────────────────────────────────
  const im = prState.importResult;
  const step3 = `<section class="bg-surface-container-lowest rounded-xl shadow-whisper p-6 mb-4 ${canImport ? '' : 'opacity-40 pointer-events-none'}">
    <div class="flex items-center justify-between">
      <h3 class="text-base font-bold flex items-center gap-2"><span class="material-symbols-outlined text-primary">south_west</span>Step 3 · Import ${escHtml(prState.src)} → ${escHtml(prState.tgt)}</h3>
      ${prStepStatus(im)}
    </div>
    <div class="text-xs text-on-surface-variant mt-1">Mirrors all praxes from source. Preserves <span class="mono-text">lcId</span>, sets <span class="mono-text">isDraft=false</span>.</div>
    ${im && im.imported ? `<div class="mt-3 text-xs mono-text text-on-surface-variant max-h-32 overflow-auto bg-surface-container rounded p-2">${im.imported.map(r => `${escHtml(r.lcId)} · ${escHtml(r.name)}`).join('<br>')}</div>` : ''}
    <div class="mt-4">
      <button class="px-4 py-2 bg-primary text-on-primary rounded-lg text-xs font-bold hover:opacity-90 disabled:opacity-30 disabled:cursor-not-allowed" onclick="prRunImport()" ${prState.busy ? 'disabled' : ''}>${prState.busy === 'import' ? 'Importing…' : 'Run import'}</button>
    </div>
  </section>`;

  const canScrub = canImport && !!im && !im.error;

  // ── Step 4: scrub contacts ──────────────────────────────────────────────
  const sc = prState.scrubResult;
  const step4 = `<section class="bg-surface-container-lowest rounded-xl shadow-whisper p-6 mb-4 ${canScrub ? '' : 'opacity-40 pointer-events-none'}">
    <div class="flex items-center justify-between">
      <h3 class="text-base font-bold flex items-center gap-2"><span class="material-symbols-outlined text-primary">soap</span>Step 4 · Scrub contact info on ${escHtml(prState.tgt)}</h3>
      ${prStepStatus(sc)}
    </div>
    <div class="text-xs text-on-surface-variant mt-1">UPDATE praxis_config SET email, phone — applied to ALL praxes. vitasAIPraxisId only updated if non-empty.</div>
    <div class="grid grid-cols-3 gap-3 mt-3">
      <div>
        <label class="block text-[10px] uppercase tracking-wider font-bold text-on-surface-variant mb-1">email</label>
        <input id="prScrubEmail" value="${escHtml(prState.scrubEmail)}" class="w-full bg-surface-container border-none rounded-lg text-xs px-3 py-2 mono-text" oninput="prState.scrubEmail=this.value"/>
      </div>
      <div>
        <label class="block text-[10px] uppercase tracking-wider font-bold text-on-surface-variant mb-1">phone</label>
        <input id="prScrubPhone" value="${escHtml(prState.scrubPhone)}" class="w-full bg-surface-container border-none rounded-lg text-xs px-3 py-2 mono-text" oninput="prState.scrubPhone=this.value"/>
      </div>
      <div>
        <label class="block text-[10px] uppercase tracking-wider font-bold text-on-surface-variant mb-1">vitasAIPraxisId (optional)</label>
        <input id="prScrubVitasId" value="${escHtml(prState.scrubVitasAIPraxisId)}" placeholder="leave empty to keep current" class="w-full bg-surface-container border-none rounded-lg text-xs px-3 py-2 mono-text" oninput="prState.scrubVitasAIPraxisId=this.value"/>
      </div>
    </div>
    <div class="mt-4">
      <button class="px-4 py-2 bg-primary text-on-primary rounded-lg text-xs font-bold hover:opacity-90 disabled:opacity-30 disabled:cursor-not-allowed" onclick="prRunScrub()" ${prState.busy ? 'disabled' : ''}>${prState.busy === 'scrub' ? 'Scrubbing…' : 'Scrub contacts'}</button>
    </div>
  </section>`;

  const canSetDefault = canScrub && !!sc && !sc.error;

  // ── Step 5: set default praxis ──────────────────────────────────────────
  const sd = prState.setDefaultResult;
  const radioList = (im && im.imported && im.imported.length)
    ? im.imported.map(r => `<label class="flex items-center gap-2 p-2 hover:bg-surface-container rounded text-xs cursor-pointer">
        <input type="radio" name="prDefault" value="${escHtml(r.lcId)}" ${prState.selectedDefaultLcId === r.lcId ? 'checked' : ''} onchange="prState.selectedDefaultLcId=this.value;prRender()"/>
        <span class="mono-text font-bold">${escHtml(r.lcId)}</span>
        <span class="text-on-surface-variant">· ${escHtml(r.name)}</span>
      </label>`).join('')
    : `<div class="text-xs text-outline italic">No praxes imported yet.</div>`;

  const step5 = `<section class="bg-surface-container-lowest rounded-xl shadow-whisper p-6 mb-4 ${canSetDefault ? '' : 'opacity-40 pointer-events-none'}">
    <div class="flex items-center justify-between">
      <h3 class="text-base font-bold flex items-center gap-2"><span class="material-symbols-outlined text-primary">person_pin</span>Step 5 · Set default praxis on ${escHtml(prState.tgt)}</h3>
      ${prStepStatus(sd)}
    </div>
    <div class="text-xs text-on-surface-variant mt-1">Updates app_user_info.praxisId AND admin_user_info.associatedPraxisIds for ALL users to the chosen lcId.</div>
    <div class="mt-3 max-h-48 overflow-auto bg-surface-container rounded p-2">${radioList}</div>
    ${sd ? `<div class="mt-3 text-xs mono-text text-emerald-600">App users updated: ${sd.appUsersUpdated || 0} · Admin users updated: ${sd.adminUsersUpdated || 0}</div>` : ''}
    <div class="mt-4">
      <button class="px-4 py-2 bg-primary text-on-primary rounded-lg text-xs font-bold hover:opacity-90 disabled:opacity-30 disabled:cursor-not-allowed" onclick="prRunSetDefault()" ${prState.busy || !prState.selectedDefaultLcId ? 'disabled' : ''}>${prState.busy === 'setDefault' ? 'Updating…' : 'Set as default for all users'}</button>
    </div>
  </section>`;

  const logCard = `<section class="bg-surface-container-lowest rounded-xl shadow-whisper p-4">
    <div class="flex items-center justify-between mb-2">
      <h3 class="text-sm font-bold">Live log</h3>
      <button class="text-[10px] uppercase tracking-wider text-on-surface-variant hover:text-primary" onclick="prState.log=[];prLog('Log cleared')">Clear</button>
    </div>
    <div id="prLog" class="bg-surface-container rounded p-3 max-h-64 overflow-auto"></div>
  </section>`;

  el.innerHTML = pageWrap(
    pageHero('Praxis Refresh', {
      sub: 'Backup → wipe → import prod → scrub → set default. Local-only, destructive — used to refresh staging from prod.',
      actions: `<div class="flex gap-2">
        <button class="px-3 py-2 bg-surface-container rounded-lg text-on-surface-variant hover:bg-surface-container-high transition-colors text-xs font-bold flex items-center gap-1.5" onclick="prMarkPreImportDone()" title="Mark drift/backup/wipe as already complete"><span class="material-symbols-outlined text-sm">fast_forward</span>Skip to import</button>
        <button class="px-3 py-2 bg-surface-container rounded-lg text-on-surface-variant hover:bg-surface-container-high transition-colors text-xs font-bold flex items-center gap-1.5" onclick="prResetState()" title="Clear local wizard progress"><span class="material-symbols-outlined text-sm">restart_alt</span>Reset wizard</button>
      </div>`,
    }) +
    envCard + step0 + step1 + step2 + step3 + step4 + step5 + logCard
  );

  // Repopulate the log into the freshly-rendered #prLog element.
  const logEl = document.getElementById('prLog');
  if (logEl) {
    logEl.innerHTML = prState.log.map(e => {
      const cls = e.type === 'error' ? 'text-red-500' : e.type === 'ok' ? 'text-emerald-500' : e.type === 'warn' ? 'text-amber-500' : 'text-on-surface-variant';
      return `<div class="text-xs mono-text ${cls}">[${e.ts}] ${escHtml(e.msg)}</div>`;
    }).join('');
    logEl.scrollTop = logEl.scrollHeight;
  }
}

async function prCall(path, opts) {
  const res = await fetch(path, opts);
  const data = await res.json().catch(() => ({ error: `HTTP ${res.status}` }));
  if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
  return data;
}

async function prRunDriftCheck() {
  prState.busy = 'drift';
  prState.driftResult = null;
  prRender();
  prLog(`Drift check against ${prState.tgt}…`);
  try {
    const data = await prCall('/api/praxis/schema-drift-check', {
      headers: { ...envHeadersFor(prState.tgt), 'x-env-label': prState.tgt },
    });
    prState.driftResult = data;
    prState.driftAck = data.drift.length === 0; // auto-ack if no drift
    prLog(`covered=${data.covered.length} historical=${data.historical.length} drift=${data.drift.length} missing=${(data.missing||[]).length}`, data.drift.length === 0 ? 'ok' : 'warn');
  } catch (e) {
    prState.driftResult = { error: e.message, covered: [], historical: [], drift: [], missing: [] };
    prLog('Drift check failed: ' + e.message, 'error');
  } finally {
    prState.busy = '';
    prRender();
  }
}

async function prRunBackup() {
  prState.busy = 'backup';
  prRender();
  const result = { src: null, tgt: null };
  try {
    prLog(`Backing up source ${prState.src}…`);
    result.src = await prCall('/api/praxis/backup', {
      method: 'POST',
      headers: { ...envHeadersFor(prState.src), 'x-env-label': prState.src },
      body: JSON.stringify({}),
    });
    prLog(`  → ${result.src.count} files in ${result.src.dir}`, 'ok');

    prLog(`Backing up target ${prState.tgt}…`);
    result.tgt = await prCall('/api/praxis/backup', {
      method: 'POST',
      headers: { ...envHeadersFor(prState.tgt), 'x-env-label': prState.tgt },
      body: JSON.stringify({}),
    });
    prLog(`  → ${result.tgt.count} files in ${result.tgt.dir}`, 'ok');
    prState.backupResult = result;
  } catch (e) {
    prState.backupResult = { ...result, error: e.message };
    prLog('Backup failed: ' + e.message, 'error');
  } finally {
    prState.busy = '';
    prRender();
  }
}

async function prRunWipe() {
  if (prState.tgt !== 'staging') { showToast('Target must be staging to wipe.'); return; }
  if (!confirm(`Really DELETE all praxis_config rows on ${prState.tgt}? This cannot be undone (you have backups, right?).`)) return;
  prState.busy = 'wipe';
  prRender();
  prLog(`Wiping praxis config on ${prState.tgt}…`, 'warn');
  try {
    const data = await prCall('/api/praxis/wipe-staging', {
      method: 'POST',
      headers: { ...envHeadersFor(prState.tgt), 'x-env-label': prState.tgt, 'x-allow-destructive': 'yes' },
      body: JSON.stringify({ confirmation: 'WIPE STAGING' }),
    });
    prState.wipeResult = data;
    const total = Object.values(data.deletedRowsByTable || {}).reduce((a,b) => a + b, 0);
    prLog(`Wipe done — ${total} rows deleted across ${Object.keys(data.deletedRowsByTable || {}).length} tables`, 'ok');
  } catch (e) {
    prState.wipeResult = { error: e.message };
    prLog('Wipe failed: ' + e.message, 'error');
  } finally {
    prState.busy = '';
    prRender();
  }
}

async function prRunImport() {
  prState.busy = 'import';
  prRender();
  prLog(`Importing ${prState.src} → ${prState.tgt}…`);
  try {
    const headers = {
      ...envHeadersFor(prState.src, 'x-src-db-'),
      ...envHeadersFor(prState.tgt, 'x-tgt-db-'),
      'Content-Type': 'application/json',
    };
    const data = await prCall('/api/praxis/import', {
      method: 'POST',
      headers,
      body: JSON.stringify({}),
    });
    prState.importResult = data;
    prLog(`Imported ${data.importedCount} praxes`, 'ok');
    if (data.imported && data.imported.length) {
      prState.selectedDefaultLcId = data.imported[0].lcId;
    }
  } catch (e) {
    prState.importResult = { error: e.message };
    prLog('Import failed: ' + e.message, 'error');
  } finally {
    prState.busy = '';
    prRender();
  }
}

async function prRunScrub() {
  if (!prState.scrubEmail || !prState.scrubPhone) { showToast('Email and phone required.'); return; }
  prState.busy = 'scrub';
  prRender();
  const vitasNote = prState.scrubVitasAIPraxisId ? `, vitasAIPraxisId → ${prState.scrubVitasAIPraxisId}` : '';
  prLog(`Scrubbing contacts on ${prState.tgt} → ${prState.scrubEmail} / ${prState.scrubPhone}${vitasNote}…`);
  try {
    const data = await prCall('/api/praxis/scrub-contacts', {
      method: 'POST',
      headers: { ...envHeadersFor(prState.tgt), 'x-env-label': prState.tgt },
      body: JSON.stringify({
        email: prState.scrubEmail,
        phone: prState.scrubPhone,
        vitasAIPraxisId: prState.scrubVitasAIPraxisId || undefined,
      }),
    });
    prState.scrubResult = data;
    prLog(`Scrub done`, 'ok');
  } catch (e) {
    prState.scrubResult = { error: e.message };
    prLog('Scrub failed: ' + e.message, 'error');
  } finally {
    prState.busy = '';
    prRender();
  }
}

async function prRunSetDefault() {
  if (!prState.selectedDefaultLcId) { showToast('Pick a praxis first.'); return; }
  if (!confirm(`Set ${prState.selectedDefaultLcId} as the default praxis for ALL users on ${prState.tgt}?`)) return;
  prState.busy = 'setDefault';
  prRender();
  prLog(`Setting default praxis ${prState.selectedDefaultLcId} on ${prState.tgt}…`);
  try {
    const data = await prCall('/api/praxis/set-default', {
      method: 'POST',
      headers: { ...envHeadersFor(prState.tgt), 'x-env-label': prState.tgt },
      body: JSON.stringify({ lcId: prState.selectedDefaultLcId }),
    });
    prState.setDefaultResult = data;
    prLog(`Default set — app users: ${data.appUsersUpdated}, admin users: ${data.adminUsersUpdated}`, 'ok');
  } catch (e) {
    prState.setDefaultResult = { error: e.message };
    prLog('Set-default failed: ' + e.message, 'error');
  } finally {
    prState.busy = '';
    prRender();
  }
}
