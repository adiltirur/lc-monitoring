// ═════════════════════════════════════════════════════════════════════════
// API KEYS
// ═════════════════════════════════════════════════════════════════════════
const API_KEY_STATUS = { 0: ['Active','tertiary','bg-tertiary'], 1: ['Inactive','slate','bg-slate-300'], 2: ['Expired','error','bg-error'] };

async function renderApiKeys(el) {
  el.innerHTML = pageWrap(pageHero('API Keys') + loadingState());
  try {
    const rows = await apiFetch('/api/api-keys');
    setConnStatus('connected');

    const rowsHtml = rows.map(r => {
      const [label, color, dot] = API_KEY_STATUS[r.status] || ['Unknown','slate','bg-slate-400'];
      const perms = typeof r.permissions === 'object' ? Object.entries(r.permissions).filter(([,v])=>v).map(([k])=>k).join(', ') : String(r.permissions);
      const expired = new Date(r.expiresAt) < new Date();
      return `<tr class="row-compact hover:bg-surface-container-low transition-colors group border-t border-surface-container/40">
        <td class="px-4 py-2">
          <div class="font-bold text-sm">${escHtml(r.customerName)}</div>
          <div class="text-[10px] mono-text text-on-surface-variant truncate max-w-[180px]">${escHtml(r.customerUUID)}</div>
        </td>
        <td class="px-4 py-2">
          <div class="flex items-center gap-1.5 text-${color}">
            <span class="w-1.5 h-1.5 rounded-full ${dot}"></span>
            <span class="text-xs font-medium">${escHtml(label)}</span>
          </div>
        </td>
        <td class="px-4 py-2 mono-text text-sm font-bold">${r.usageCount.toLocaleString()}</td>
        <td class="px-4 py-2 mono-text text-xs opacity-60 whitespace-nowrap">${escHtml(deTime(r.lastUsedAt))}</td>
        <td class="px-4 py-2 mono-text text-xs ${expired ? 'text-error' : ''} whitespace-nowrap">${escHtml(deTime(r.expiresAt))}</td>
        <td class="px-4 py-2 text-xs text-on-surface-variant truncate max-w-[200px]" title="${escHtml(perms)}">${escHtml(perms)||'—'}</td>
        <td class="px-4 py-2 text-right">
          ${r.status === 0
            ? `<button class="text-error opacity-0 group-hover:opacity-100 font-black uppercase tracking-tighter text-[10px] transition-opacity" onclick="setApiKeyStatus(${r.id}, 1, this)">Disable</button>`
            : `<button class="text-primary opacity-0 group-hover:opacity-100 font-black uppercase tracking-tighter text-[10px] transition-opacity" onclick="setApiKeyStatus(${r.id}, 0, this)">Enable</button>`}
        </td>
      </tr>`;
    }).join('');

    el.innerHTML = pageWrap(
      pageHero('API Keys', { sub: 'Customer access tokens',
        actions: `<button class="bg-surface-container-high text-on-surface-variant px-4 py-2 rounded-lg text-[11px] font-black uppercase tracking-widest hover:bg-surface-variant transition-colors" onclick="showToast('Local-only tool — Issue New Key disabled')">Issue New Key</button>` }) +
      tableShell(['Customer','Status','Usage','Last Used','Expires','Permissions','Actions'], rowsHtml)
    );
  } catch(e) {
    setConnStatus('error');
    el.innerHTML = pageWrap(pageHero('API Keys') + errorState(e.message));
  }
}

async function setApiKeyStatus(id, status, btn) {
  const action = status === 0 ? 'enable' : 'disable';
  if (!confirm(`Are you sure you want to ${action} this API key?`)) return;
  btn.disabled = true;
  try {
    const res = await fetch(`/api/api-keys/${id}/status`, { method: 'PATCH', headers: dbHeaders(), body: JSON.stringify({ status }) });
    const data = await res.json();
    if (data.error) { showToast('Error: ' + data.error); btn.disabled = false; return; }
    renderApiKeys(document.getElementById('content'));
  } catch(e) { showToast(e.message); btn.disabled = false; }
}
