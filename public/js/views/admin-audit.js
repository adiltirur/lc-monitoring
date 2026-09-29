// ═════════════════════════════════════════════════════════════════════════
// ADMIN AUDIT
// ═════════════════════════════════════════════════════════════════════════
let aaFilters = {};

async function renderAdminAudit(el, page = 1) {
  el.innerHTML = pageWrap(pageHero('Admin Audit') + loadingState());
  try {
    const p = new URLSearchParams({ ...aaFilters, page, pageSize: 50 });
    const data = await apiFetch(`/api/admin-audit?${p}`);
    setConnStatus('connected');

    const filterHtml =
      fInput('Action', `placeholder="action" value="${escHtml(aaFilters.action||'')}" oninput="aaFilters.action=this.value"`) +
      fInput('User',   `placeholder="name"   value="${escHtml(aaFilters.userName||'')}" oninput="aaFilters.userName=this.value"`) +
      fInput('Praxis', `placeholder="praxisId" value="${escHtml(aaFilters.praxisId||'')}" oninput="aaFilters.praxisId=this.value"`) +
      fInput('From', `type="datetime-local" value="${aaFilters.dateFrom||''}" oninput="aaFilters.dateFrom=this.value"`) +
      fInput('To',   `type="datetime-local" value="${aaFilters.dateTo||''}"   oninput="aaFilters.dateTo=this.value"`) +
      `<div class="flex gap-2">${btnPrimary('Search', `renderAdminAudit(document.getElementById('content'))`, { full: true })}${btnGhost('Clear', `aaFilters={};renderAdminAudit(document.getElementById('content'))`)}</div>`;

    const rowsHtml = data.rows.map(r => `<tr class="zebra-row hover:bg-surface-container transition-colors">
      <td class="px-4 py-2 mono-text text-xs opacity-70 whitespace-nowrap">${escHtml(deTime(r.createdAt))}</td>
      <td class="px-4 py-2 font-semibold">${escHtml(r.userName)}</td>
      <td class="px-4 py-2 text-xs text-on-surface-variant">${escHtml(r.userEmail)}</td>
      <td class="px-4 py-2">${statusBadge(r.action,'blue')}</td>
      <td class="px-4 py-2 text-xs" title="${escHtml(r.praxisId)||''}">${r.praxisId ? escHtml(praxisName(r.praxisId) || r.praxisId) : '—'}</td>
      <td class="px-4 py-2 text-xs text-on-surface-variant truncate max-w-[300px]" title="${escHtml(r.changes)}">${escHtml(r.changes)||'—'}</td>
    </tr>`).join('');

    el.innerHTML = pageWrap(
      pageHero('Admin Audit', { sub: 'Compliance trail of admin actions' }) +
      filterCard(filterHtml, 6) +
      tableShell(['Time','User','Email','Action','Praxis','Changes'], rowsHtml, 'aaPaging')
    );
    renderPagination(document.getElementById('aaPaging'), data, (p) => renderAdminAudit(document.getElementById('content'), p));
  } catch(e) {
    setConnStatus('error');
    el.innerHTML = pageWrap(pageHero('Admin Audit') + errorState(e.message));
  }
}
