// ═════════════════════════════════════════════════════════════════════════
// COCKPIT FILL — bulk-fill praxis hours + cockpit standard week from xlsx
// ═════════════════════════════════════════════════════════════════════════
//
// Wizard:
//   1. Type Excel path (file lives on local disk — helper is local-only)
//   2. Parse + show per-sheet preview
//   3. Map each Excel sheet → DB praxis (loaded from /api/praxis/list, with
//      auto-suggestion by city substring)
//   4. Map each Excel person name → Personio employee (live fetch, with
//      auto-suggestion by name similarity). Manual numeric fallback if
//      Personio creds aren't in .env.
//   5. Pick target env (defaults to staging) + isoYear/isoWeek
//   6. Import — replaces existing cockpit + praxis_hours_config rows for
//      each mapped praxis. One transaction across all praxes.

const CF_STATE_KEY = 'lc_cockpit_fill_state';
const CF_DEFAULT_STATE = {
  filepath: '/Users/adil/Downloads/20260202_Master_Öffnungszeiten_Sprechzeiten.xlsx',
  parsed: null,            // result of /api/cockpit/parse-excel
  sheetToLcId: {},         // sheetName → lcId
  nameToEmployeeId: {},    // personName → employeeId (number)
  praxes: [],              // from /api/praxis/list on the chosen env
  personioEmployees: null, // from /api/cockpit/personio-employees
  personioError: null,
  tgt: 'staging',
  isoYear: null,
  isoWeek: null,
  importResult: null,
  allowDestructive: false,  // production triple-gate: checkbox
  confirmation: '',         // production triple-gate: typed phrase
  log: [],
};

let cfState = (() => {
  try {
    const saved = JSON.parse(localStorage.getItem(CF_STATE_KEY) || 'null');
    return { ...CF_DEFAULT_STATE, ...(saved || {}) };
  } catch {
    return { ...CF_DEFAULT_STATE };
  }
})();

function cfSaveState() {
  try { localStorage.setItem(CF_STATE_KEY, JSON.stringify(cfState)); } catch {}
}
function cfResetState() {
  if (!confirm('Reset Cockpit Fill wizard? Local progress will be cleared. DB data already written stays.')) return;
  cfState = { ...CF_DEFAULT_STATE };
  localStorage.removeItem(CF_STATE_KEY);
  cfRender();
  cfLog('Wizard reset.');
}
function cfLog(msg, type = 'info') {
  cfState.log.push({ ts: new Date().toISOString().slice(11, 19), msg, type });
  const el = document.getElementById('cfLog');
  if (el) {
    const cls = (e) => e.type === 'error' ? 'text-red-500' : e.type === 'ok' ? 'text-emerald-500' : e.type === 'warn' ? 'text-amber-500' : 'text-on-surface-variant';
    el.innerHTML = cfState.log.map(e => `<div class="text-xs mono-text ${cls(e)}">[${e.ts}] ${escHtml(e.msg)}</div>`).join('');
    el.scrollTop = el.scrollHeight;
  }
}

// Simple Levenshtein-based similarity (0..1). Used for auto-suggestion.
function cfNameSimilarity(a, b) {
  if (!a || !b) return 0;
  const x = a.toLowerCase().replace(/\s+/g, ' ').trim();
  const y = b.toLowerCase().replace(/\s+/g, ' ').trim();
  if (x === y) return 1;
  // Quick substring boost
  if (x.includes(y) || y.includes(x)) return 0.8;
  const lev = (function() {
    const dp = Array.from({ length: x.length + 1 }, () => new Array(y.length + 1).fill(0));
    for (let i = 0; i <= x.length; i++) dp[i][0] = i;
    for (let j = 0; j <= y.length; j++) dp[0][j] = j;
    for (let i = 1; i <= x.length; i++) {
      for (let j = 1; j <= y.length; j++) {
        dp[i][j] = Math.min(
          dp[i - 1][j] + 1,
          dp[i][j - 1] + 1,
          dp[i - 1][j - 1] + (x[i - 1] === y[j - 1] ? 0 : 1),
        );
      }
    }
    return dp[x.length][y.length];
  })();
  return 1 - lev / Math.max(x.length, y.length);
}

async function renderCockpitFill(el) {
  el.innerHTML = pageWrap(pageHero('Cockpit Fill') + loadingState());
  try {
    await ensureEnvPasswords();
  } catch (e) {
    el.innerHTML = pageWrap(pageHero('Cockpit Fill') + errorState('Failed to load env passwords: ' + e.message));
    return;
  }
  cfRender();
}

function cfRender() {
  const el = document.getElementById('content');
  if (!el) return;
  cfSaveState();

  const envOpt = (cur) => Object.keys(PRESETS).map(k =>
    `<option value="${k}" ${k === cur ? 'selected' : ''}>${escHtml(k)}</option>`
  ).join('');

  // ── Step 0: file + env picker ────────────────────────────────────────────
  const step0 = `<section class="bg-surface-container-lowest rounded-xl shadow-whisper p-6 mb-4">
    <h3 class="text-base font-bold flex items-center gap-2 mb-3"><span class="material-symbols-outlined text-primary">upload_file</span>Step 1 · Excel + target env</h3>
    <div class="grid grid-cols-1 md:grid-cols-3 gap-3">
      <div class="md:col-span-2">
        <label class="block text-[10px] uppercase tracking-wider font-bold text-on-surface-variant mb-1">Excel file path</label>
        <input id="cfPath" value="${escHtml(cfState.filepath)}" class="w-full bg-surface-container border-none rounded-lg text-xs px-3 py-2 mono-text" oninput="cfState.filepath=this.value"/>
      </div>
      <div>
        <label class="block text-[10px] uppercase tracking-wider font-bold text-on-surface-variant mb-1">Target env</label>
        <select id="cfTgt" class="w-full bg-surface-container border-none rounded-lg text-sm px-3 py-2 mono-text" onchange="cfState.tgt=this.value;cfState.praxes=[];cfRender()">${envOpt(cfState.tgt)}</select>
      </div>
    </div>
    <div class="mt-3 flex gap-2">
      <button class="px-4 py-2 bg-primary text-on-primary rounded-lg text-xs font-bold hover:opacity-90" onclick="cfRunParse()">Parse Excel</button>
      <button class="px-4 py-2 bg-surface-container rounded-lg text-xs font-bold hover:bg-surface-container-high" onclick="cfLoadPraxes()">${cfState.praxes.length ? `Reload praxes (${cfState.praxes.length})` : 'Load praxes from target'}</button>
      <button class="px-4 py-2 bg-surface-container rounded-lg text-xs font-bold hover:bg-surface-container-high" onclick="cfFetchPersonio()">${cfState.personioEmployees ? `Reload Personio (${cfState.personioEmployees.length})` : 'Fetch Personio employees'}</button>
    </div>
    ${cfState.personioError ? `<div class="mt-2 text-xs text-amber-600">⚠ ${escHtml(cfState.personioError)} — you can still type employeeIds manually below.</div>` : ''}
  </section>`;

  if (!cfState.parsed) {
    el.innerHTML = pageWrap(
      pageHero('Cockpit Fill', {
        sub: 'Bulk-fill praxis_hours_config + cockpit_standard_week_version from a Master Excel.',
        actions: `<button class="px-3 py-2 bg-surface-container rounded-lg text-xs font-bold flex items-center gap-1.5" onclick="cfResetState()"><span class="material-symbols-outlined text-sm">restart_alt</span>Reset</button>`,
      }) + step0 + cfLogCard()
    );
    cfRefreshLog();
    return;
  }

  // ── Step 2: sheet → praxis mapping ───────────────────────────────────────
  const praxesOpts = (cur) => `<option value="">— pick praxis —</option>` + cfState.praxes.map(p =>
    `<option value="${escHtml(p.lcId)}" ${p.lcId === cur ? 'selected' : ''}>${escHtml(p.lcId)} · ${escHtml(p.name || '')} ${escHtml(p.city ? '· ' + p.city : '')}</option>`
  ).join('');

  const sheetRows = cfState.parsed.sheets.map(s => {
    const cur = cfState.sheetToLcId[s.sheetName] || cfAutoSheetMatch(s.sheetName);
    if (cur && !cfState.sheetToLcId[s.sheetName]) cfState.sheetToLcId[s.sheetName] = cur; // persist auto-suggestion
    const c = s.counts;
    return `<tr class="border-b border-outline-variant">
      <td class="px-3 py-2 mono-text text-xs font-bold">${escHtml(s.sheetName)}</td>
      <td class="px-3 py-2 text-[10px] mono-text text-on-surface-variant">open: ${c.openingSlots} · consult: ${c.consultationSlots} · work: ${c.workingSlots} · persons: ${c.persons}</td>
      <td class="px-3 py-2"><select class="w-full bg-surface-container border-none rounded text-xs px-2 py-1 mono-text" onchange="cfState.sheetToLcId['${escHtml(s.sheetName)}']=this.value;cfSaveState()">${praxesOpts(cur)}</select></td>
    </tr>`;
  }).join('');

  const step1 = `<section class="bg-surface-container-lowest rounded-xl shadow-whisper p-6 mb-4">
    <h3 class="text-base font-bold flex items-center gap-2 mb-3"><span class="material-symbols-outlined text-primary">grid_view</span>Step 2 · Sheet → Praxis (${cfState.parsed.sheets.length} sheets)</h3>
    ${!cfState.praxes.length ? `<div class="text-xs text-amber-600 mb-2">⚠ No praxes loaded yet. Click "Load praxes from target" above.</div>` : ''}
    <div class="overflow-auto max-h-72 border border-outline-variant rounded">
      <table class="w-full text-xs"><thead class="bg-surface-container sticky top-0"><tr>
        <th class="px-3 py-2 text-left">Sheet</th><th class="px-3 py-2 text-left">Counts</th><th class="px-3 py-2 text-left">Praxis</th>
      </tr></thead><tbody>${sheetRows}</tbody></table>
    </div>
  </section>`;

  // ── Step 3: person → employeeId mapping ──────────────────────────────────
  const personRows = cfState.parsed.allPersons.map(name => {
    const empId = cfState.nameToEmployeeId[name];
    let suggestion = '';
    if (cfState.personioEmployees && cfState.personioEmployees.length) {
      let best = null, bestScore = 0;
      for (const e of cfState.personioEmployees) {
        const fullName = `${e.firstName} ${e.lastName}`.trim();
        const score = cfNameSimilarity(name.replace(/\s*\(.*\).*/, '').trim(), fullName);
        if (score > bestScore) { bestScore = score; best = e; }
      }
      if (best && bestScore >= 0.6) {
        suggestion = `${best.firstName} ${best.lastName} (id ${best.id}, ${(bestScore * 100).toFixed(0)}%)`;
        if (!empId) cfState.nameToEmployeeId[name] = best.id;
      }
    }
    const opts = cfState.personioEmployees ? cfState.personioEmployees.map(e =>
      `<option value="${e.id}" ${cfState.nameToEmployeeId[name] === e.id ? 'selected' : ''}>${escHtml(`${e.firstName} ${e.lastName}`)} · ${escHtml(e.position || '')} · ${escHtml(e.office || '')}</option>`
    ).join('') : '';
    return `<tr class="border-b border-outline-variant">
      <td class="px-3 py-2 mono-text text-xs">${escHtml(name)}</td>
      <td class="px-3 py-2 text-[10px] text-on-surface-variant">${escHtml(suggestion || '—')}</td>
      <td class="px-3 py-2">
        ${cfState.personioEmployees ?
          `<select class="w-full bg-surface-container border-none rounded text-xs px-2 py-1 mono-text" onchange="cfState.nameToEmployeeId['${escHtml(name).replace(/'/g, '&#39;')}']=parseInt(this.value)||null;cfSaveState()">
            <option value="">— skip —</option>${opts}
          </select>` :
          `<input type="number" placeholder="employeeId" value="${cfState.nameToEmployeeId[name] || ''}" class="w-32 bg-surface-container border-none rounded text-xs px-2 py-1 mono-text" oninput="cfState.nameToEmployeeId['${escHtml(name).replace(/'/g, '&#39;')}']=parseInt(this.value)||null;cfSaveState()"/>`
        }
      </td>
    </tr>`;
  }).join('');

  const step2 = `<section class="bg-surface-container-lowest rounded-xl shadow-whisper p-6 mb-4">
    <h3 class="text-base font-bold flex items-center gap-2 mb-3"><span class="material-symbols-outlined text-primary">badge</span>Step 3 · Person → Personio employee (${cfState.parsed.allPersons.length} names)</h3>
    ${!cfState.personioEmployees ? `<div class="text-xs text-amber-600 mb-2">⚠ Personio employees not loaded — auto-suggestion disabled. Click "Fetch Personio employees" above, or type IDs manually.</div>` : ''}
    <div class="overflow-auto max-h-80 border border-outline-variant rounded">
      <table class="w-full text-xs"><thead class="bg-surface-container sticky top-0"><tr>
        <th class="px-3 py-2 text-left">Excel name</th><th class="px-3 py-2 text-left">Auto-match</th><th class="px-3 py-2 text-left">EmployeeId</th>
      </tr></thead><tbody>${personRows}</tbody></table>
    </div>
  </section>`;

  // ── Step 4: import ───────────────────────────────────────────────────────
  const mappedSheets = Object.entries(cfState.sheetToLcId).filter(([_, v]) => !!v).length;
  const mappedPersons = Object.entries(cfState.nameToEmployeeId).filter(([_, v]) => Number.isFinite(v) && v > 0).length;
  const im = cfState.importResult;
  const step3 = `<section class="bg-surface-container-lowest rounded-xl shadow-whisper p-6 mb-4">
    <h3 class="text-base font-bold flex items-center gap-2 mb-3"><span class="material-symbols-outlined text-primary">south_west</span>Step 4 · Import to ${escHtml(cfState.tgt)}</h3>
    <div class="grid grid-cols-3 gap-3 text-xs mb-3">
      <div class="bg-surface-container rounded p-2"><div class="text-[10px] uppercase tracking-wider text-on-surface-variant">Sheets mapped</div><div class="text-lg font-bold">${mappedSheets} / ${cfState.parsed.sheets.length}</div></div>
      <div class="bg-surface-container rounded p-2"><div class="text-[10px] uppercase tracking-wider text-on-surface-variant">Persons mapped</div><div class="text-lg font-bold">${mappedPersons} / ${cfState.parsed.allPersons.length}</div></div>
      <div class="bg-surface-container rounded p-2"><div class="text-[10px] uppercase tracking-wider text-on-surface-variant">ISO year/week</div>
        <div class="flex items-center gap-1 mt-1">
          <input type="number" value="${cfState.isoYear || ''}" placeholder="auto" class="w-16 bg-surface-container-low border-none rounded text-xs px-1 py-0.5 mono-text" oninput="cfState.isoYear=parseInt(this.value)||null;cfSaveState()"/>/
          <input type="number" value="${cfState.isoWeek || ''}" placeholder="auto" class="w-12 bg-surface-container-low border-none rounded text-xs px-1 py-0.5 mono-text" oninput="cfState.isoWeek=parseInt(this.value)||null;cfSaveState()"/>
        </div>
      </div>
    </div>
    ${im ? `<div class="bg-surface-container rounded p-3 mb-3 text-[10px] mono-text max-h-48 overflow-auto">${im.results ? im.results.map(r => `<div class="${r.status === 'ok' ? 'text-emerald-600' : r.status === 'skipped' ? 'text-amber-600' : 'text-red-600'}">${escHtml(r.sheet)} → ${escHtml(r.lcId || '?')}: ${escHtml(r.status)}${r.openingInserted !== undefined ? ` · open=${r.openingInserted} consult=${r.consultationSlots} work=${r.workSlotsAggregated}` : ''}${r.unmatchedNames && r.unmatchedNames.length ? ` · unmatched=${escHtml(r.unmatchedNames.join(', '))}` : ''}${r.reason ? ` · ${escHtml(r.reason)}` : ''}</div>`).join('') : escHtml(JSON.stringify(im))}</div>` : ''}
    ${(() => {
      const prodOk = cfState.tgt !== 'production' || (cfState.allowDestructive && cfState.confirmation === 'IMPORT COCKPIT TO PRODUCTION');
      const disabled = !mappedSheets || !prodOk;
      return `<button class="px-4 py-2 bg-primary text-on-primary rounded-lg text-xs font-bold hover:opacity-90 disabled:opacity-30 disabled:cursor-not-allowed" onclick="cfRunImport()" ${disabled ? 'disabled' : ''}>${im ? 'Re-run import' : `Import ${mappedSheets} sheet(s)`}</button>`;
    })()}
    ${cfState.tgt === 'production' ? `
      <div class="mt-3 border border-red-600 rounded-lg p-3 bg-red-50">
        <div class="text-xs text-red-700 font-bold mb-2">⚠ Production target — destructive bulk import</div>
        <div class="text-[11px] text-red-700 mb-2">This REPLACES existing praxis_hours_config + cockpit_standard_week_version rows for every mapped praxis. Type the phrase below exactly to confirm.</div>
        <label class="flex items-center gap-2 text-xs text-red-700 mb-2">
          <input type="checkbox" ${cfState.allowDestructive ? 'checked' : ''} onchange="cfState.allowDestructive=this.checked;cfSaveState();cfRender()"/>
          I understand this will overwrite production cockpit data.
        </label>
        <input
          type="text"
          placeholder="IMPORT COCKPIT TO PRODUCTION"
          value="${escHtml(cfState.confirmation || '')}"
          class="w-full bg-surface-container-low border border-red-300 rounded text-xs px-2 py-1 mono-text"
          oninput="cfState.confirmation=this.value;cfSaveState();cfRender()"
        />
      </div>` : ''}
  </section>`;

  el.innerHTML = pageWrap(
    pageHero('Cockpit Fill', {
      sub: 'Bulk-fill praxis_hours_config + cockpit_standard_week_version from a Master Excel.',
      actions: `<button class="px-3 py-2 bg-surface-container rounded-lg text-xs font-bold flex items-center gap-1.5" onclick="cfResetState()"><span class="material-symbols-outlined text-sm">restart_alt</span>Reset</button>`,
    }) + step0 + step1 + step2 + step3 + cfLogCard()
  );
  cfRefreshLog();
}

function cfLogCard() {
  return `<section class="bg-surface-container-lowest rounded-xl shadow-whisper p-4 mb-4">
    <div class="flex items-center justify-between mb-2"><h3 class="text-sm font-bold">Log</h3>
      <button class="text-[10px] uppercase tracking-wider text-on-surface-variant hover:text-primary" onclick="cfState.log=[];cfLog('Log cleared')">Clear</button>
    </div>
    <div id="cfLog" class="bg-surface-container rounded p-3 max-h-56 overflow-auto"></div>
  </section>`;
}
function cfRefreshLog() {
  const el = document.getElementById('cfLog');
  if (el) el.innerHTML = cfState.log.map(e => {
    const cls = e.type === 'error' ? 'text-red-500' : e.type === 'ok' ? 'text-emerald-500' : e.type === 'warn' ? 'text-amber-500' : 'text-on-surface-variant';
    return `<div class="text-xs mono-text ${cls}">[${e.ts}] ${escHtml(e.msg)}</div>`;
  }).join('');
}

// Auto-suggest praxis lcId for a sheet name based on city substring.
function cfAutoSheetMatch(sheetName) {
  if (!cfState.praxes.length) return '';
  const stripped = sheetName.replace(/_Neu\s*$/i, '').toLowerCase().trim();
  for (const p of cfState.praxes) {
    const city = (p.city || '').toLowerCase();
    const name = (p.name || '').toLowerCase();
    if (city && (city.includes(stripped) || stripped.includes(city))) return p.lcId;
    if (name && (name.includes(stripped) || stripped.includes(name))) return p.lcId;
  }
  return '';
}

async function cfRunParse() {
  cfLog(`Parsing ${cfState.filepath}…`);
  try {
    const r = await fetch('/api/cockpit/parse-excel', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ path: cfState.filepath }),
    });
    const d = await r.json();
    if (!r.ok) throw new Error(d.error || `HTTP ${r.status}`);
    cfState.parsed = d;
    cfLog(`Parsed ${d.sheets.length} sheets, ${d.allPersons.length} unique persons.`, 'ok');
  } catch (e) {
    cfLog('Parse failed: ' + e.message, 'error');
  } finally { cfRender(); }
}

async function cfLoadPraxes() {
  cfLog(`Loading praxes from ${cfState.tgt}…`);
  try {
    const r = await fetch('/api/praxis/list', { headers: { ...envHeadersFor(cfState.tgt), 'x-env-label': cfState.tgt } });
    const d = await r.json();
    if (!r.ok) throw new Error(d.error || `HTTP ${r.status}`);
    cfState.praxes = d.rows || [];
    cfLog(`Loaded ${cfState.praxes.length} praxes.`, 'ok');
  } catch (e) { cfLog('Praxes load failed: ' + e.message, 'error'); }
  finally { cfRender(); }
}

async function cfFetchPersonio() {
  cfLog('Fetching Personio employees…');
  try {
    const r = await fetch('/api/cockpit/personio-employees');
    const d = await r.json();
    if (!r.ok) {
      cfState.personioError = d.error || `HTTP ${r.status}`;
      throw new Error(cfState.personioError);
    }
    cfState.personioEmployees = d.employees;
    cfState.personioError = null;
    cfLog(`Loaded ${d.employees.length} Personio employees.`, 'ok');
  } catch (e) { cfLog('Personio fetch failed: ' + e.message, 'error'); }
  finally { cfRender(); }
}

async function cfRunImport() {
  const mappedSheets = Object.entries(cfState.sheetToLcId).filter(([_, v]) => !!v);
  if (!mappedSheets.length) { showToast('Map at least one sheet to a praxis first.'); return; }
  if (cfState.tgt === 'production' && (!cfState.allowDestructive || cfState.confirmation !== 'IMPORT COCKPIT TO PRODUCTION')) {
    showToast('Tick the checkbox AND type the confirmation phrase to import on production.');
    return;
  }
  const proceed = confirm(
    cfState.tgt === 'production'
      ? `PRODUCTION — Import ${mappedSheets.length} sheet(s) and REPLACE existing cockpit rows? This is destructive.`
      : `Import ${mappedSheets.length} sheet(s) to ${cfState.tgt}? This REPLACES existing praxis_hours_config + cockpit_standard_week_version rows for those praxes.`,
  );
  if (!proceed) return;
  cfLog(`Importing ${mappedSheets.length} sheet(s) → ${cfState.tgt}…`);
  try {
    const body = {
      parsedSheets: cfState.parsed.sheets,
      sheetToLcId: cfState.sheetToLcId,
      nameToEmployeeId: cfState.nameToEmployeeId,
      validFromIsoYear: cfState.isoYear || undefined,
      validFromIsoWeek: cfState.isoWeek || undefined,
      replace: true,
    };
    const headers = { ...envHeadersFor(cfState.tgt), 'x-env-label': cfState.tgt };
    if (cfState.tgt === 'production') {
      headers['x-allow-destructive'] = 'yes';
      body.confirmation = 'IMPORT COCKPIT TO PRODUCTION';
    }
    const r = await fetch('/api/cockpit/import', {
      method: 'POST',
      headers,
      body: JSON.stringify(body),
    });
    const d = await r.json();
    if (!r.ok) throw new Error(d.error || `HTTP ${r.status}`);
    cfState.importResult = d;
    const oks = (d.results || []).filter(x => x.status === 'ok').length;
    cfLog(`Import done — ${oks} ok, year/week ${d.isoYear}/${d.isoWeek}.`, 'ok');
  } catch (e) {
    cfState.importResult = { error: e.message };
    cfLog('Import failed: ' + e.message, 'error');
  } finally { cfRender(); }
}
