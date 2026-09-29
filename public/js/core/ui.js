// ═════════════════════════════════════════════════════════════════════════
// REUSABLE UI BUILDERS — bridge theme
// ═════════════════════════════════════════════════════════════════════════
function pageHero(title, opts = {}) {
  const { sub = '', actions = '', live = false } = opts;
  const liveBadge = live ? `<span class="pill ok"><span class="dot ok live"></span>Live</span>` : '';
  const subRow = sub ? `<div class="view-subtitle">${sub}</div>` : '';
  return `<div class="view-header">
    <div>
      <h1 class="view-title">${escHtml(title)}${liveBadge}</h1>
      ${subRow}
    </div>
    ${actions ? `<div class="view-actions">${actions}</div>` : ''}
  </div>`;
}

function filterCard(html, cols = 6) {
  return `<div class="panel" style="margin-bottom:var(--s-4)">
    <div class="panel-body" style="display:grid;grid-template-columns:repeat(${cols},1fr);gap:var(--s-3);align-items:end">${html}</div>
  </div>`;
}

function fLabel(text) {
  return `<label class="field-label">${escHtml(text)}</label>`;
}

function fInput(label, attrs) {
  return `<div class="field">${fLabel(label)}<input ${attrs} class="lc-input mono"></div>`;
}

function fSelect(label, options, attrs = '', selected = '') {
  return `<div class="field">${fLabel(label)}<select ${attrs} class="lc-select">${options.map(o => {
    const v = typeof o === 'object' ? o.value : o;
    const lbl = typeof o === 'object' ? o.label : o;
    return `<option value="${escHtml(v)}" ${String(selected) === String(v) ? 'selected' : ''}>${escHtml(lbl)}</option>`;
  }).join('')}</select></div>`;
}

function btnPrimary(label, onclick, opts = {}) {
  const icon = opts.icon ? `<span class="material-symbols-outlined">${opts.icon}</span>` : '';
  const w = opts.full ? 'style="width:100%;justify-content:center"' : '';
  return `<button class="btn btn-primary" ${w} onclick="${onclick}">${icon}${escHtml(label)}</button>`;
}

function btnGhost(label, onclick, opts = {}) {
  const icon = opts.icon ? `<span class="material-symbols-outlined">${opts.icon}</span>` : '';
  const w = opts.full ? 'style="width:100%;justify-content:center"' : '';
  return `<button class="btn" ${w} onclick="${onclick}">${icon}${escHtml(label)}</button>`;
}

function statusBadge(label, color = 'tertiary') {
  // Map legacy color names to new pill variants.
  const map = { tertiary: 'ok', primary: 'ok', emerald: 'ok', amber: 'warn', orange: 'warn',
                error: 'err', red: 'err', blue: 'info', indigo: 'info', slate: '', purple: 'info' };
  return `<span class="pill ${map[color] ?? ''}">${escHtml(label)}</span>`;
}

function statusDotText(label, color) {
  const map = { tertiary: 'ok', emerald: 'ok', error: 'err', red: 'err', amber: 'warn', orange: 'warn', blue: 'info', slate: '' };
  const dot = map[color] || '';
  return `<span class="row-sm" style="font-size:12px;font-weight:500"><span class="dot ${dot} live"></span>${escHtml(label)}</span>`;
}

function tableShell(headers, rowsHtml, paginationId = '') {
  const headHtml = headers.map(h => `<th>${h}</th>`).join('');
  return `<div class="panel" style="margin-bottom:var(--s-4);overflow:hidden">
    <div style="overflow-x:auto"><table class="lc-table"><thead><tr>${headHtml}</tr></thead><tbody>${rowsHtml}</tbody></table></div>
    ${paginationId ? `<div id="${paginationId}"></div>` : ''}
  </div>`;
}

function emptyState(label, icon = 'inbox') {
  return `<div class="panel" style="margin-bottom:var(--s-4)"><div class="empty">
    <div class="empty-icon"><span class="material-symbols-outlined">${icon}</span></div>
    <div class="empty-title">${escHtml(label)}</div>
  </div></div>`;
}

function loadingState(label = 'Loading…') {
  return `<div class="panel" style="margin-bottom:var(--s-4)"><div class="empty">
    <div class="empty-icon"><span class="material-symbols-outlined spin">progress_activity</span></div>
    <div class="empty-sub">${escHtml(label)}</div>
  </div></div>`;
}

function errorState(msg) {
  return `<div class="panel" style="border-color:var(--band);margin-bottom:var(--s-4);overflow:hidden">
    <div class="band"><span class="material-symbols-outlined">error</span>Something went wrong</div>
    <div class="panel-body"><div class="mono" style="font-size:12px;color:var(--ink);word-break:break-all">${escHtml(msg)}</div>
      <div style="font-size:12px;color:var(--ink-3);margin-top:6px">Check the environment connection (the numbered plate, top left). For Dev, make sure the Local Stack is running.</div></div>
  </div>`;
}

function pageWrap(inner) {
  return `<div class="lc-view">${inner}</div>`;
}

// ═════════════════════════════════════════════════════════════════════════
// PAGINATION HELPER
// ═════════════════════════════════════════════════════════════════════════
function renderPagination(el, data, onPage) {
  const { total, page, pageSize, estimated } = data;
  const totalPages = Math.ceil(total / pageSize);
  const start = (page - 1) * pageSize + 1;
  const end = Math.min(page * pageSize, total);
  const totalLabel = estimated ? `~${total.toLocaleString()}` : total.toLocaleString();
  el.innerHTML = `
    <div style="padding:10px var(--panel-pad);border-top:1px solid var(--border-subtle);background:var(--surface-2);display:flex;justify-content:space-between;align-items:center">
      <span class="label">${start}–${end} of ${totalLabel}${estimated ? ' (est.)' : ''}</span>
      <div class="row-sm" style="gap:2px">
        <button class="btn btn-ghost btn-sm" ${page <= 1 ? 'disabled style="opacity:.3;pointer-events:none"' : ''} onclick="(${onPage.toString()})(${page - 1})">
          <span class="material-symbols-outlined">chevron_left</span>
        </button>
        ${[...Array(Math.min(totalPages, 5))].map((_, i) => {
          const p = page <= 3 ? i+1 : page - 2 + i;
          if (p < 1 || p > totalPages) return '';
          const cls = p === page ? 'btn-primary' : 'btn-ghost';
          return `<button class="btn btn-sm ${cls}" style="min-width:26px;justify-content:center" onclick="(${onPage.toString()})(${p})">${p}</button>`;
        }).join('')}
        <button class="btn btn-ghost btn-sm" ${page >= totalPages ? 'disabled style="opacity:.3;pointer-events:none"' : ''} onclick="(${onPage.toString()})(${page + 1})">
          <span class="material-symbols-outlined">chevron_right</span>
        </button>
      </div>
    </div>`;
}
