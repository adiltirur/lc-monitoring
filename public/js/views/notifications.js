// ═════════════════════════════════════════════════════════════════════════
// NOTIFICATIONS
// ═════════════════════════════════════════════════════════════════════════
let nfFilters = {};

async function renderNotifications(el, page = 1) {
  el.innerHTML = pageWrap(pageHero('Notifications') + loadingState());
  try {
    const p = new URLSearchParams({ ...nfFilters, page, pageSize: 50 });
    const data = await apiFetch(`/api/notifications?${p}`);
    setConnStatus('connected');

    const filterHtml =
      fSelect('Type', [{value:'',label:'All'}, ...NOTIF_TYPES.map((t,i) => ({value:i,label:t}))], `oninput="nfFilters.type=this.value"`, nfFilters.type ?? '') +
      fInput('User ID', `placeholder="userId" value="${escHtml(nfFilters.userId||'')}" oninput="nfFilters.userId=this.value"`) +
      fInput('From', `type="datetime-local" value="${nfFilters.dateFrom||''}" oninput="nfFilters.dateFrom=this.value"`) +
      fInput('To',   `type="datetime-local" value="${nfFilters.dateTo||''}"   oninput="nfFilters.dateTo=this.value"`) +
      `<div></div>` +
      `<div class="flex gap-2">${btnPrimary('Search', `renderNotifications(document.getElementById('content'))`, { full: true })}${btnGhost('Clear', `nfFilters={};renderNotifications(document.getElementById('content'))`)}</div>`;

    const rowsHtml = data.rows.map(r => {
      const [bg, fg] = NOTIF_PILL[r.type] || NOTIF_PILL[6];
      return `<tr class="zebra-row hover:bg-surface-container transition-colors">
        <td class="px-4 py-2 mono-text text-xs opacity-70 whitespace-nowrap">${escHtml(deTime(r.createdAt))}</td>
        <td class="px-4 py-2">
          ${r.firstName ? `<div class="font-semibold text-sm">${escHtml(r.firstName)} ${escHtml(r.lastName)}</div>` : ''}
          <div class="text-xs text-on-surface-variant">${escHtml(r.userEmail||r.userId||'')}</div>
        </td>
        <td class="px-4 py-2"><span class="px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider ${bg} ${fg}">${escHtml(NOTIF_TYPES[r.type]||r.type)}</span></td>
        <td class="px-4 py-2 text-sm font-medium" title="${escHtml(r.title)}">${escHtml(r.title)}</td>
        <td class="px-4 py-2 text-xs text-on-surface-variant truncate max-w-[260px]" title="${escHtml(r.body)}">${escHtml(r.body)}</td>
        <td class="px-4 py-2">${r.isNew ? '<span class="w-2 h-2 rounded-full bg-blue-500 inline-block"></span>' : ''}</td>
      </tr>`;
    }).join('');

    el.innerHTML = pageWrap(
      pageHero('Notifications', { sub: 'Sent push notifications log' }) +
      filterCard(filterHtml, 6) +
      tableShell(['Time','User','Type','Title','Body','New'], rowsHtml, 'nfPaging')
    );
    renderPagination(document.getElementById('nfPaging'), data, (p) => renderNotifications(document.getElementById('content'), p));
  } catch(e) {
    setConnStatus('error');
    el.innerHTML = pageWrap(pageHero('Notifications') + errorState(e.message));
  }
}
