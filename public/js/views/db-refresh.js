// ═════════════════════════════════════════════════════════════════════════
// DB REFRESH — wipe a target DB + full copy from any other env
// ═════════════════════════════════════════════════════════════════════════
//
// Source: any preset. Target: dev/test/staging — production is never offered
// and the backend hard-refuses prod hosts and checks each target host belongs
// to its labelled env. The source connection is opened read-only server-side.

const TR_STATE_KEY = 'lc_db_refresh_state';
const TR_SRC_ENVS = ['dev', 'test', 'staging', 'production'];
const TR_TGT_ENVS = ['dev', 'test', 'staging'];
const TR_DEFAULT_STATE = {
  src: 'staging',
  tgt: 'test',
  preflight: null,
  runResult: null,   // { summary } on success, { error } on failure
  perTable: [],      // [{ table, rows, ms }]
  log: [],
};

let trState = (() => {
  try {
    const saved = JSON.parse(localStorage.getItem(TR_STATE_KEY) || 'null');
    return { ...TR_DEFAULT_STATE, ...(saved || {}), busy: '' };
  } catch { return { ...TR_DEFAULT_STATE, busy: '' }; }
})();

function trSaveState() {
  try {
    const { busy, ...rest } = trState;
    localStorage.setItem(TR_STATE_KEY, JSON.stringify(rest));
  } catch { /* quota or disabled */ }
}

function trLog(msg, type = 'info') {
  trState.log.push({ ts: new Date().toISOString().slice(11, 19), msg, type });
  const el = document.getElementById('trLog');
  if (el) {
    el.innerHTML = trState.log.map(e => {
      const cls = e.type === 'error' ? 'text-red-500' : e.type === 'ok' ? 'text-emerald-500' : e.type === 'warn' ? 'text-amber-500' : 'text-on-surface-variant';
      return `<div class="text-xs mono-text ${cls}">[${e.ts}] ${escHtml(e.msg)}</div>`;
    }).join('');
    el.scrollTop = el.scrollHeight;
  }
}

function trResetState() {
  if (!confirm('Reset the DB Refresh wizard? This clears local progress markers only.')) return;
  trState = { ...TR_DEFAULT_STATE, busy: '', log: [] };
  localStorage.removeItem(TR_STATE_KEY);
  trRender();
  trLog('Wizard reset.');
}

function trConfirmPhrase() { return `REFRESH ${trState.tgt.toUpperCase()}`; }

// Changing either env invalidates the pre-flight; keep src ≠ tgt.
function trSetEnv(which, value) {
  trState[which] = value;
  if (trState.src === trState.tgt) {
    if (which === 'tgt') trState.src = TR_SRC_ENVS.find(e => e !== value);
    else trState.tgt = TR_TGT_ENVS.find(e => e !== value);
  }
  trState.preflight = null;
  trState.runResult = null;
  trState.perTable = [];
  trRender();
}

async function renderDbRefresh(el) {
  if (!TR_TGT_ENVS.includes(trState.tgt)) trState.tgt = 'test';
  if (!TR_SRC_ENVS.includes(trState.src) || trState.src === trState.tgt) trState.src = TR_SRC_ENVS.find(e => e !== trState.tgt);
  el.innerHTML = pageWrap(pageHero('DB Refresh') + loadingState());
  try { await ensureEnvPasswords(); }
  catch (e) {
    el.innerHTML = pageWrap(pageHero('DB Refresh') + errorState('Failed to load env passwords: ' + e.message));
    return;
  }
  trRender();
}

function trRender() {
  const el = document.getElementById('content');
  if (!el || window.__currentView !== 'db-refresh') return;
  trSaveState();

  const srcOpt = TR_SRC_ENVS.map(k =>
    `<option value="${k}" ${k === trState.src ? 'selected' : ''} ${k === trState.tgt ? 'disabled' : ''}>${escHtml(k)}</option>`).join('');
  const tgtOpt = TR_TGT_ENVS.map(k =>
    `<option value="${k}" ${k === trState.tgt ? 'selected' : ''} ${k === trState.src ? 'disabled' : ''}>${escHtml(k)}</option>`).join('');
  const tgt = PRESETS[trState.tgt];
  const phrase = trConfirmPhrase();

  const envCard = `<section class="bg-surface-container-lowest rounded-xl shadow-whisper p-6 mb-6">
    <h2 class="text-lg font-bold tracking-tight mb-4 flex items-center gap-2">
      <span class="material-symbols-outlined">database</span>Source &amp; Target
    </h2>
    <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
      <div>
        <label class="block text-[10px] uppercase tracking-wider font-bold text-on-surface-variant mb-1.5">Source (read-only)</label>
        <select class="w-full bg-surface-container border-none rounded-lg text-sm px-3 py-2.5 mono-text focus:ring-2 focus:ring-primary-fixed" onchange="trSetEnv('src', this.value)">${srcOpt}</select>
        <div class="text-[10px] mono-text text-outline mt-1">${escHtml(PRESETS[trState.src]?.host)}:${escHtml(PRESETS[trState.src]?.port)}/${escHtml(PRESETS[trState.src]?.db)}</div>
      </div>
      <div>
        <label class="block text-[10px] uppercase tracking-wider font-bold text-on-surface-variant mb-1.5">Target (wiped &amp; refilled)</label>
        <select class="w-full bg-surface-container border-none rounded-lg text-sm px-3 py-2.5 mono-text focus:ring-2 focus:ring-primary-fixed" onchange="trSetEnv('tgt', this.value)">${tgtOpt}</select>
        <div class="text-[10px] mono-text text-outline mt-1">${escHtml(tgt.host)}:${escHtml(tgt.port)}/${escHtml(tgt.db)}</div>
      </div>
    </div>
    <div class="mt-3 text-xs text-on-surface-variant">Production can never be a target — the backend refuses its hosts outright and checks the target host belongs to the chosen env. The source session is opened read-only.</div>
  </section>`;

  // ── Step 1: pre-flight ─────────────────────────────────────────────────
  const pf = trState.preflight;
  let pfBody = `<div class="text-xs text-outline italic mt-2">Run the pre-flight check before the copy unlocks.</div>`;
  if (pf && pf.error) {
    pfBody = `<div class="mt-3 text-xs text-red-600 mono-text">${escHtml(pf.error)}</div>`;
  } else if (pf) {
    const banner = (ok, okMsg, errMsg) => ok
      ? `<div class="bg-emerald-50 text-emerald-700 rounded-lg p-3 text-xs font-bold">✓ ${okMsg}</div>`
      : `<div class="bg-red-50 text-red-700 rounded-lg p-3 text-xs font-bold">⛔ ${errMsg}</div>`;
    const oneSided = (pf.diff.srcOnlyTables.length || pf.diff.tgtOnlyTables.length) ? `<div class="mt-2 text-[10px] mono-text text-amber-700 bg-amber-50 rounded p-2">
        ${pf.diff.srcOnlyTables.length ? `Only on source — not copied: ${pf.diff.srcOnlyTables.map(escHtml).join(', ')}<br>` : ''}
        ${pf.diff.tgtOnlyTables.length ? `Only on ${escHtml(trState.tgt)} — emptied, not refilled: ${pf.diff.tgtOnlyTables.map(escHtml).join(', ')}` : ''}
      </div>` : '';
    const diffDetail = !pf.schemaOk ? `<div class="mt-2 text-[10px] mono-text text-red-700 max-h-40 overflow-auto bg-red-50 rounded p-2">
        ${pf.diff.columnDiffs.map(d => `${escHtml(d.table)}: ${[
          d.srcOnly.length ? 'src-only cols ' + d.srcOnly.map(escHtml).join(',') : '',
          d.tgtOnly.length ? 'tgt-only cols ' + d.tgtOnly.map(escHtml).join(',') : '',
          d.typeMismatch.length ? 'type mismatch ' + d.typeMismatch.map(m => `${escHtml(m.column)} (${escHtml(m.src)}≠${escHtml(m.tgt)})`).join(',') : '',
        ].filter(Boolean).join(' · ')}`).join('<br>')}
      </div>` : '';
    const widenings = (pf.diff && pf.diff.widenings) || [];
    const wideningNote = widenings.length ? `<details class="mt-2 text-[10px] mono-text text-on-surface-variant bg-surface-container rounded p-2">
        <summary class="cursor-pointer">ℹ ${widenings.reduce((n, w) => n + w.columns.length, 0)} column(s) in ${widenings.length} table(s) widen on copy (e.g. int4 → int8) — lossless, not blocking</summary>
        <div class="mt-1 max-h-32 overflow-auto">${widenings.map(w => `${escHtml(w.table)}: ${w.columns.map(m => `${escHtml(m.column)} (${escHtml(m.src)}→${escHtml(m.tgt)})`).join(', ')}`).join('<br>')}</div>
      </details>` : '';
    const rows = (pf.tables || []).map(t => `<tr class="${t.skipped ? 'opacity-50' : ''}">
        <td class="px-2 py-1 mono-text">${escHtml(t.table)}</td>
        <td class="px-2 py-1 mono-text text-right">${t.srcRows === null ? '—' : '~' + t.srcRows.toLocaleString()}</td>
        <td class="px-2 py-1 mono-text text-right">${t.tgtRows === null ? '—' : '~' + t.tgtRows.toLocaleString()}</td>
        <td class="px-2 py-1">${t.skipped ? '<span class="px-1.5 py-0.5 rounded text-[9px] font-bold uppercase bg-amber-100 text-amber-700">skipped (log)</span>'
          : t.srcOnly ? '<span class="px-1.5 py-0.5 rounded text-[9px] font-bold uppercase bg-amber-100 text-amber-700">source only</span>'
          : t.tgtOnly ? '<span class="px-1.5 py-0.5 rounded text-[9px] font-bold uppercase bg-amber-100 text-amber-700">target only</span>' : ''}</td>
      </tr>`).join('');
    pfBody = `<div class="grid grid-cols-2 gap-3 mt-3">
        ${banner(pf.schemaOk, 'Schemas match', 'Column drift — migrate ' + escHtml(trState.tgt) + ' first, copy refused')}
        ${banner(pf.replicaRoleOk, 'Target can enter replica mode', 'Target user cannot enter replica mode: ' + escHtml(pf.replicaRoleError || ''))}
      </div>
      ${diffDetail}
      ${oneSided}
      ${wideningNote}
      <div class="mt-3 max-h-64 overflow-auto bg-surface-container rounded">
        <table class="w-full text-xs">
          <thead class="sticky top-0 bg-surface-container-high"><tr>
            <th class="px-2 py-1.5 text-left text-[10px] uppercase tracking-wider">Table</th>
            <th class="px-2 py-1.5 text-right text-[10px] uppercase tracking-wider">Source rows (est.)</th>
            <th class="px-2 py-1.5 text-right text-[10px] uppercase tracking-wider">${escHtml(trState.tgt)} rows (est.)</th>
            <th class="px-2 py-1.5"></th>
          </tr></thead>
          <tbody>${rows}</tbody>
        </table>
      </div>`;
  }
  const step1 = `<section class="bg-surface-container-lowest rounded-xl shadow-whisper p-6 mb-4">
    <div class="flex items-center justify-between">
      <h3 class="text-base font-bold flex items-center gap-2"><span class="material-symbols-outlined text-primary">policy</span>Step 1 · Pre-flight check</h3>
      ${prStepStatus(pf)}
    </div>
    <div class="text-xs text-on-surface-variant mt-1">Compares schemas (hard gate), estimates row counts, probes replica-mode capability. Read-only.</div>
    ${pfBody}
    <div class="mt-4">
      <button class="px-4 py-2 bg-primary text-on-primary rounded-lg text-xs font-bold hover:opacity-90 disabled:opacity-30 disabled:cursor-not-allowed" onclick="trRunPreflight()" ${trState.busy ? 'disabled' : ''}>${trState.busy === 'preflight' ? 'Checking…' : 'Run pre-flight'}</button>
    </div>
  </section>`;

  // ── Step 2: wipe + copy ────────────────────────────────────────────────
  const canRun = !!pf && !pf.error && pf.schemaOk && pf.replicaRoleOk;
  const rr = trState.runResult;
  const resultRows = (trState.perTable || []).map(t =>
    `<tr><td class="px-2 py-1 mono-text">${escHtml(t.table)}</td>
      <td class="px-2 py-1 mono-text text-right">${t.rows.toLocaleString()}</td>
      <td class="px-2 py-1 mono-text text-right">${t.ms.toLocaleString()} ms</td></tr>`).join('');
  const step2 = `<section data-band="Destructive — changes data in the target database" class="lc-destructive bg-surface-container-lowest rounded-xl shadow-whisper p-6 mb-4 ${canRun ? '' : 'opacity-40 pointer-events-none'}">
    <div class="flex items-center justify-between">
      <h3 class="text-base font-bold flex items-center gap-2"><span class="material-symbols-outlined text-red-500">delete_forever</span>Step 2 · Wipe ${escHtml(trState.tgt)} &amp; copy from ${escHtml(trState.src)}</h3>
      ${prStepStatus(rr)}
    </div>
    <div class="text-xs text-on-surface-variant mt-1">TRUNCATEs every table on ${escHtml(trState.tgt)}, then copies all rows (ids preserved) in one transaction — any failure rolls back to the old ${escHtml(trState.tgt)} data. Log tables are emptied but not refilled.</div>
    ${trState.perTable.length ? `<div class="mt-3 max-h-48 overflow-auto bg-surface-container rounded">
      <table class="w-full text-xs">
        <thead class="sticky top-0 bg-surface-container-high"><tr>
          <th class="px-2 py-1.5 text-left text-[10px] uppercase tracking-wider">Table</th>
          <th class="px-2 py-1.5 text-right text-[10px] uppercase tracking-wider">Rows</th>
          <th class="px-2 py-1.5 text-right text-[10px] uppercase tracking-wider">Time</th>
        </tr></thead><tbody>${resultRows}</tbody>
      </table>
    </div>` : ''}
    ${rr && rr.summary ? `<div class="mt-3 text-xs mono-text text-emerald-600">Done — ${rr.summary.tablesCopied} tables, ${rr.summary.totalRows.toLocaleString()} rows in ${(rr.summary.durationMs / 1000).toFixed(1)}s.</div>` : ''}
    ${rr && rr.error ? `<div class="mt-3 text-xs mono-text text-red-600">${escHtml(rr.error)} — ${escHtml(trState.tgt)} DB rolled back to its previous state.</div>` : ''}
    <div class="mt-4 flex items-center gap-3">
      <input id="trRunConfirm" placeholder='Type ${phrase} to enable' class="bg-surface-container border-none rounded-lg text-xs px-3 py-2 mono-text" oninput="document.getElementById('trRunBtn').disabled = this.value !== trConfirmPhrase() || !!trState.busy"/>
      <button id="trRunBtn" class="px-4 py-2 bg-red-500 text-white rounded-lg text-xs font-bold hover:bg-red-600 disabled:opacity-30 disabled:cursor-not-allowed" onclick="trRunCopy()" disabled>${trState.busy === 'run' ? 'Refreshing…' : 'Wipe ' + escHtml(trState.tgt) + ' &amp; copy'}</button>
    </div>
  </section>`;

  const logCard = `<section class="bg-surface-container-lowest rounded-xl shadow-whisper p-4">
    <div class="flex items-center justify-between mb-2">
      <h3 class="text-sm font-bold">Live log</h3>
      <button class="text-[10px] uppercase tracking-wider text-on-surface-variant hover:text-primary" onclick="trState.log=[];trLog('Log cleared')">Clear</button>
    </div>
    <div id="trLog" class="bg-surface-container rounded p-3 max-h-64 overflow-auto"></div>
  </section>`;

  el.innerHTML = pageWrap(
    pageHero('DB Refresh', {
      sub: 'Wipe a target DB and mirror everything from another env. Targets: dev, test, staging — production can never be overwritten.',
      actions: `<button class="px-3 py-2 bg-surface-container rounded-lg text-on-surface-variant hover:bg-surface-container-high transition-colors text-xs font-bold flex items-center gap-1.5" onclick="trResetState()" title="Clear local wizard progress"><span class="material-symbols-outlined text-sm">restart_alt</span>Reset wizard</button>`,
    }) +
    envCard + step1 + step2 + logCard
  );

  // Repopulate the log into the freshly-rendered #trLog element.
  const logEl = document.getElementById('trLog');
  if (logEl) {
    logEl.innerHTML = trState.log.map(e => {
      const cls = e.type === 'error' ? 'text-red-500' : e.type === 'ok' ? 'text-emerald-500' : e.type === 'warn' ? 'text-amber-500' : 'text-on-surface-variant';
      return `<div class="text-xs mono-text ${cls}">[${e.ts}] ${escHtml(e.msg)}</div>`;
    }).join('');
    logEl.scrollTop = logEl.scrollHeight;
  }
}

function trHeaders() {
  return {
    ...envHeadersFor(trState.src, 'x-src-db-'),
    ...envHeadersFor(trState.tgt, 'x-tgt-db-'),
    'x-tgt-env-label': trState.tgt,
    'Content-Type': 'application/json',
  };
}

async function trRunPreflight() {
  trState.busy = 'preflight';
  trState.preflight = null;
  trState.runResult = null;
  trState.perTable = [];
  trRender();
  trLog(`Pre-flight ${trState.src} → ${trState.tgt}…`);
  try {
    const r = await fetch('/api/db-refresh/preflight', { method: 'POST', headers: trHeaders() });
    const d = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(d.error || `HTTP ${r.status}`);
    trState.preflight = d;
    trLog(`Schemas ${d.schemaOk ? 'match' : 'DIFFER — copy refused'}.`, d.schemaOk ? 'ok' : 'error');
    trLog(`Replica mode on target: ${d.replicaRoleOk ? 'available' : 'NOT available — ' + (d.replicaRoleError || '')}.`, d.replicaRoleOk ? 'ok' : 'error');
  } catch (e) {
    trState.preflight = { error: e.message };
    trLog('Pre-flight failed: ' + e.message, 'error');
  } finally {
    trState.busy = '';
    trRender();
  }
}

async function trRunCopy() {
  const src = trState.src, tgt = trState.tgt;
  if (!TR_TGT_ENVS.includes(tgt) || src === tgt) return;
  if (!confirm(`Wipe the ENTIRE ${tgt} DB and copy everything from ${src}?\n\nThis truncates every table on ${PRESETS[tgt].host} and refills it from ${PRESETS[src].host}.`)) return;
  trState.busy = 'run';
  trState.runResult = null;
  trState.perTable = [];
  trRender();
  trLog(`Refreshing ${tgt} from ${src}…`);
  try {
    const r = await fetch('/api/db-refresh/run', {
      method: 'POST',
      headers: { ...trHeaders(), 'x-allow-destructive': 'yes' },
      body: JSON.stringify({ confirmation: trConfirmPhrase() }),
    });
    if (!r.ok) {
      const d = await r.json().catch(() => ({}));
      throw new Error(d.error || `HTTP ${r.status}`);
    }
    // NDJSON stream: parse line-by-line; a stream that ends without a
    // 'done' event is a failure (HTTP 200 is committed before the copy runs).
    const reader = r.body.getReader();
    const decoder = new TextDecoder();
    let buf = '';
    let done = false;
    for (;;) {
      const chunk = await reader.read();
      if (chunk.done) break;
      buf += decoder.decode(chunk.value, { stream: true });
      const lines = buf.split('\n');
      buf = lines.pop();
      for (const line of lines) {
        if (!line.trim()) continue;
        let evt;
        try { evt = JSON.parse(line); } catch { continue; }
        if (evt.type === 'start') {
          trLog(`Truncating ${evt.truncating} tables, copying ${evt.tables.length}…`);
        } else if (evt.type === 'table') {
          trState.perTable.push(evt);
          trLog(`[${evt.i}/${evt.n}] ${evt.table} — ${evt.rows.toLocaleString()} rows in ${evt.ms} ms`);
        } else if (evt.type === 'done') {
          done = true;
          trState.runResult = { summary: evt.summary };
          trLog(`Refresh complete — ${evt.summary.totalRows.toLocaleString()} rows across ${evt.summary.tablesCopied} tables in ${(evt.summary.durationMs / 1000).toFixed(1)}s. Committed.`, 'ok');
        } else if (evt.type === 'error') {
          throw new Error(evt.message);
        }
      }
    }
    if (!done) throw new Error('Stream ended without completion — treat as failed');
  } catch (e) {
    trState.runResult = { error: e.message };
    trLog('Refresh failed: ' + e.message + ` (${tgt} DB rolled back)`, 'error');
  } finally {
    trState.busy = '';
    trRender();
  }
}
