// ═════════════════════════════════════════════════════════════════════════
// PERSONIO AUDIT — read-only cross-check of stored employeeIds vs Personio
// ═════════════════════════════════════════════════════════════════════════
//
// Pulls active Personio employees + Weitere Standorte via the helper's
// /api/personio/audit endpoint, joins them against every (praxisId,
// employeeId) pair stored in the cockpit tables, and surfaces three issue
// classes (orphan, inactive-ref, wrong-praxis). No DB writes.

const PA_STATE_KEY = 'lc_personio_audit_state';
const PA_DEFAULT_STATE = {
  env: 'staging',
  result: null,
  filter: 'all',  // all | orphan | inactive-ref | wrong-praxis
  praxisFilter: '',
};

let paState = (() => {
  try {
    const saved = JSON.parse(localStorage.getItem(PA_STATE_KEY) || 'null');
    return { ...PA_DEFAULT_STATE, ...(saved || {}) };
  } catch { return { ...PA_DEFAULT_STATE }; }
})();

function paSaveState() { try { localStorage.setItem(PA_STATE_KEY, JSON.stringify(paState)); } catch {} }

async function renderPersonioAudit(el) {
  el.innerHTML = pageWrap(pageHero('Personio Audit') + loadingState());
  try { await ensureEnvPasswords(); }
  catch (e) {
    el.innerHTML = pageWrap(pageHero('Personio Audit') + errorState('Failed to load env passwords: ' + e.message));
    return;
  }
  paRender();
}

function paRender() {
  const el = document.getElementById('content');
  if (!el) return;
  paSaveState();

  const envOpt = (cur) => Object.keys(PRESETS).map(k =>
    `<option value="${k}" ${k === cur ? 'selected' : ''}>${escHtml(k)}</option>`).join('');

  const step1 = `<section class="bg-surface-container-lowest rounded-xl shadow-whisper p-6 mb-4">
    <h3 class="text-base font-bold flex items-center gap-2 mb-3"><span class="material-symbols-outlined">database</span>Step 1 · Environment</h3>
    <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
      <div>
        <label class="block text-[10px] uppercase tracking-wider font-bold text-on-surface-variant mb-1.5">Database to inspect (read-only)</label>
        <select class="w-full bg-surface-container border-none rounded-lg text-sm px-3 py-2.5 mono-text" onchange="paState.env=this.value;paState.result=null;paRender()">${envOpt(paState.env)}</select>
        <div class="text-[10px] mono-text text-outline mt-1">${escHtml(PRESETS[paState.env]?.host)}:${escHtml(PRESETS[paState.env]?.port)}/${escHtml(PRESETS[paState.env]?.db)}</div>
      </div>
      <div class="text-xs text-on-surface-variant flex items-end">
        Personio API is read once via <code class="mono-text">PERSONIO_CLIENT_ID/SECRET</code> from <code>.env</code>. Active records only — primary office plus <em>Weitere Standorte</em> resolve to praxes by city match.
      </div>
    </div>
    <div class="mt-4">
      <button class="px-4 py-2 bg-primary text-on-primary rounded-lg text-xs font-bold hover:opacity-90" onclick="paRunAudit()">${paState.result ? 'Re-run audit' : 'Run audit'}</button>
    </div>
  </section>`;

  let resultBlock = '';
  const r = paState.result;
  if (r && r.error) {
    resultBlock = errorState(r.error);
  } else if (r && r.counts) {
    const c = r.counts;
    const counter = (label, n, color) => `<div class="bg-surface-container rounded-lg p-3">
      <div class="text-[10px] uppercase tracking-wider text-on-surface-variant font-bold">${escHtml(label)}</div>
      <div class="text-xl font-bold mono-text ${color || ''}">${n.toLocaleString()}</div>
    </div>`;
    const totalIssues = c.orphan + c.inactiveRef + c.wrongPraxis;
    const summary = `<div class="grid grid-cols-2 md:grid-cols-4 gap-3 mb-4">
      ${counter('Stored pairs', c.storedPairs)}
      ${counter('OK', c.ok, 'text-emerald-500')}
      ${counter('Issues', totalIssues, totalIssues ? 'text-amber-500' : '')}
      ${counter('Personio (active / total)', c.personioActive, '')}
    </div>
    <div class="grid grid-cols-3 gap-3 mb-4">
      ${counter('Orphan', c.orphan, c.orphan ? 'text-red-500' : '')}
      ${counter('Inactive-ref', c.inactiveRef, c.inactiveRef ? 'text-amber-500' : '')}
      ${counter('Wrong-praxis', c.wrongPraxis, c.wrongPraxis ? 'text-amber-500' : '')}
    </div>`;

    const filterChip = (k, label) => {
      const active = paState.filter === k;
      return `<button class="px-3 py-1.5 rounded-full text-[11px] font-bold uppercase tracking-wider mr-2 ${active ? 'bg-primary text-on-primary' : 'bg-surface-container text-on-surface-variant hover:bg-surface-container-high'}" onclick="paState.filter='${k}';paRender()">${escHtml(label)}</button>`;
    };
    const filterRow = `<div class="mb-3">
      ${filterChip('all', 'All')}
      ${filterChip('orphan', `Orphan (${c.orphan})`)}
      ${filterChip('inactive-ref', `Inactive-ref (${c.inactiveRef})`)}
      ${filterChip('wrong-praxis', `Wrong-praxis (${c.wrongPraxis})`)}
      <input class="ml-3 px-3 py-1.5 bg-surface-container rounded text-xs mono-text" placeholder="filter by lcId or name" value="${escHtml(paState.praxisFilter)}" oninput="paState.praxisFilter=this.value;paRender()" style="width:240px"/>
    </div>`;

    const filtered = (r.issues || []).filter(i => {
      if (paState.filter !== 'all' && i.kind !== paState.filter) return false;
      if (paState.praxisFilter) {
        const f = paState.praxisFilter.toLowerCase();
        const hay = `${i.praxisLcId || ''} ${i.praxisName || ''} ${i.personio?.fullName || ''}`.toLowerCase();
        if (!hay.includes(f)) return false;
      }
      return true;
    });

    const kindBadge = (k) => {
      const map = {
        'orphan': ['bg-red-500/20 text-red-400', 'orphan'],
        'inactive-ref': ['bg-amber-500/20 text-amber-400', 'inactive-ref'],
        'wrong-praxis': ['bg-amber-500/20 text-amber-400', 'wrong-praxis'],
      };
      const [cls, label] = map[k] || ['bg-surface-container text-on-surface-variant', k];
      return `<span class="px-1.5 py-0.5 rounded text-[10px] font-bold uppercase ${cls}">${escHtml(label)}</span>`;
    };

    const rows = filtered.map(i => {
      const p = i.personio;
      const name = p ? `${p.firstName || ''} ${p.lastName || ''}`.trim() : '—';
      const status = p?.status || '—';
      const office = p?.office || '—';
      const ws = (p?.weitereStandorte || []).join(', ') || '—';
      const sources = (i.sources || []).map(s => s.replace(/^cockpit_|^cockpit_/, '')).join(' · ');
      let suggestion = '—';
      if (i.suggested) {
        const s = i.suggested;
        suggestion = `<span class="mono-text text-emerald-400">#${s.id}</span> ${escHtml(s.firstName || '')} ${escHtml(s.lastName || '')} <span class="text-[10px] text-on-surface-variant">(${escHtml(s.status || '')})</span>`;
      }
      const remapPreset = i.suggested ? Number(i.suggested.id) : '';
      const removeBtn = `<button class="px-2 py-1 rounded text-[10px] font-bold uppercase bg-red-500/20 text-red-400 hover:bg-red-500/30" onclick="paApplyAction(${i.praxisId}, ${i.employeeId}, 'remove')">Remove</button>`;
      const remapSuggestedBtn = i.suggested
        ? `<button class="px-2 py-1 rounded text-[10px] font-bold uppercase bg-emerald-500/20 text-emerald-400 hover:bg-emerald-500/30" onclick="paApplyAction(${i.praxisId}, ${i.employeeId}, 'remap', ${remapPreset})">Remap → #${remapPreset}</button>`
        : '';
      const remapPromptBtn = `<button class="px-2 py-1 rounded text-[10px] font-bold uppercase bg-surface-container text-on-surface-variant hover:bg-surface-container-high" onclick="paRemapPrompt(${i.praxisId}, ${i.employeeId}, ${remapPreset || 'null'})">Remap…</button>`;
      const actions = `<div class="flex flex-wrap gap-1">${removeBtn}${remapSuggestedBtn}${remapPromptBtn}</div>`;
      return `<tr class="border-b border-outline-variant align-top">
        <td class="px-2 py-1.5">${kindBadge(i.kind)}</td>
        <td class="px-2 py-1.5 mono-text text-xs font-bold">${escHtml(i.praxisLcId || '—')}</td>
        <td class="px-2 py-1.5 text-xs">${escHtml(i.praxisName || '—')}</td>
        <td class="px-2 py-1.5 mono-text text-xs">#${i.employeeId}</td>
        <td class="px-2 py-1.5 text-xs">${escHtml(name)}</td>
        <td class="px-2 py-1.5 text-[11px] mono-text">${escHtml(status)}</td>
        <td class="px-2 py-1.5 text-[11px]">${escHtml(office)}</td>
        <td class="px-2 py-1.5 text-[11px] text-on-surface-variant">${escHtml(ws)}</td>
        <td class="px-2 py-1.5 text-[11px]">${suggestion}</td>
        <td class="px-2 py-1.5 text-[10px] mono-text text-on-surface-variant">${escHtml(sources)}</td>
        <td class="px-2 py-1.5">${actions}</td>
      </tr>`;
    }).join('');

    const table = filtered.length ? `<div class="overflow-auto border border-outline-variant rounded">
      <table class="w-full text-xs">
        <thead class="bg-surface-container sticky top-0">
          <tr>
            <th class="px-2 py-1.5 text-left">kind</th>
            <th class="px-2 py-1.5 text-left">lcId</th>
            <th class="px-2 py-1.5 text-left">praxis</th>
            <th class="px-2 py-1.5 text-left">empId</th>
            <th class="px-2 py-1.5 text-left">name</th>
            <th class="px-2 py-1.5 text-left">status</th>
            <th class="px-2 py-1.5 text-left">primary office</th>
            <th class="px-2 py-1.5 text-left">Weitere Standorte</th>
            <th class="px-2 py-1.5 text-left">suggested swap</th>
            <th class="px-2 py-1.5 text-left">stored in</th>
            <th class="px-2 py-1.5 text-left">actions</th>
          </tr>
        </thead>
        <tbody>${rows}</tbody>
      </table>
    </div>` : `<div class="text-xs text-on-surface-variant italic p-4 text-center">No issues match the current filter.</div>`;

    const fetchedAtLine = `<div class="text-[10px] mono-text text-on-surface-variant mb-3">Fetched at ${escHtml(deTime(r.fetchedAt))} · ${c.praxes} praxes</div>`;

    resultBlock = `<section class="bg-surface-container-lowest rounded-xl shadow-whisper p-6 mb-4">
      <h3 class="text-base font-bold flex items-center gap-2 mb-3"><span class="material-symbols-outlined">analytics</span>Step 2 · Result</h3>
      ${fetchedAtLine}
      ${summary}
      ${filterRow}
      ${table}
    </section>`;
  }

  el.innerHTML = pageWrap(
    pageHero('Personio Audit', {
      sub: 'Read-only cross-check of every (praxis, employeeId) pair stored in cockpit tables against the live Personio roster. Surfaces orphans, inactive references, and wrong-praxis bindings.',
      actions: `<button class="px-3 py-2 bg-surface-container rounded-lg text-xs font-bold flex items-center gap-1.5" onclick="paResetState()"><span class="material-symbols-outlined text-sm">restart_alt</span>Reset</button>`,
    }) + step1 + resultBlock
  );
}

function paResetState() {
  if (!confirm('Reset Personio Audit view? Cached results will be cleared.')) return;
  paState = { ...PA_DEFAULT_STATE };
  localStorage.removeItem(PA_STATE_KEY);
  paRender();
}

async function paRunAudit() {
  paState.result = null;
  paRender();
  const el = document.getElementById('content');
  if (el) {
    const tmp = document.createElement('div');
    tmp.className = 'text-xs text-on-surface-variant italic mt-2';
    tmp.textContent = 'Running audit (Personio API + DB queries)…';
    el.querySelector('section')?.appendChild(tmp);
  }
  try {
    const r = await fetch('/api/personio/audit', {
      method: 'GET',
      headers: { ...envHeadersFor(paState.env) },
    });
    const d = await r.json();
    if (!r.ok) throw new Error(d.error || `HTTP ${r.status}`);
    paState.result = d;
  } catch (e) {
    paState.result = { error: e.message };
  } finally {
    paRender();
  }
}

async function paApplyAction(praxisId, employeeId, mode, newEmployeeId) {
  if (paState.env === 'production') { alert('Refusing to write on production.'); return; }
  const label = mode === 'remove'
    ? `Remove cockpit references for praxis ${praxisId}, employee #${employeeId}?`
    : `Remap praxis ${praxisId}: employee #${employeeId} → #${newEmployeeId}?`;
  if (!confirm(label + `\n\nEnvironment: ${paState.env}`)) return;
  try {
    const body = { actions: [{ praxisId, employeeId, mode }] };
    if (mode === 'remap') body.actions[0].newEmployeeId = newEmployeeId;
    const r = await fetch('/api/personio/audit/fix', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...envHeadersFor(paState.env) },
      body: JSON.stringify(body),
    });
    const d = await r.json();
    if (!r.ok) throw new Error(d.error || `HTTP ${r.status}`);
    const s = (d.results || [])[0] || {};
    const swv = s.standardWeekVersion || {};
    const wo = s.weekOverride || {};
    alert(
      `Applied (${mode}).\n` +
      `PDE rows: ${s.pde || 0}\n` +
      `Standard week version — rows changed: ${swv.rowsModified || 0} (consultation slots: ${swv.slotsConsultation || 0}, work slots: ${swv.slotsWork || 0})\n` +
      `Week overrides — rows changed: ${wo.rowsModified || 0} (consultation: ${wo.slotsConsultation || 0}, work: ${wo.slotsWork || 0})`,
    );
    paRunAudit();
  } catch (e) {
    alert('Failed: ' + e.message);
  }
}

function paRemapPrompt(praxisId, employeeId, presetNewId) {
  const v = window.prompt('Remap to Personio employee ID:', presetNewId == null ? '' : String(presetNewId));
  if (v == null) return;
  const trimmed = String(v).trim();
  if (!trimmed) return;
  const newId = Number(trimmed);
  if (!Number.isFinite(newId) || newId <= 0) { alert('Invalid Personio employee ID.'); return; }
  if (newId === Number(employeeId)) { alert('New ID is the same as the current ID.'); return; }
  paApplyAction(praxisId, employeeId, 'remap', newId);
}
