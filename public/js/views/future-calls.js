// ═════════════════════════════════════════════════════════════════════════
// FUTURE CALLS
// ═════════════════════════════════════════════════════════════════════════
async function renderFutureCalls(el, page = 1) {
  el.innerHTML = pageWrap(pageHero('Future Calls') + loadingState());
  try {
    const data = await apiFetch(`/api/future-calls?page=${page}&pageSize=100`);
    setConnStatus('connected');

    const now = new Date();
    const overdue = data.rows.filter(r => new Date(r.time) < now).length;
    const upcoming = data.rows.length - overdue;

    const statTile = (label, value, color) => {
      const map = {
        indigo: ['bg-indigo-50','border-indigo-500','text-indigo-600','text-indigo-900'],
        red: ['bg-error-container/30','border-error','text-error','text-error'],
        emerald: ['bg-tertiary-container/15','border-tertiary-container','text-tertiary-container','text-tertiary'],
      };
      const [bg, bd, lbl, val] = map[color];
      return `<div class="${bg} border-t-[3px] ${bd} px-5 py-3 rounded-lg flex flex-col min-w-[100px]">
        <span class="text-[10px] uppercase tracking-tighter ${lbl} font-bold">${escHtml(label)}</span>
        <span class="text-2xl font-black mono-text ${val} leading-tight">${escHtml(value)}</span>
      </div>`;
    };

    const rowsHtml = data.rows.map(r => {
      const isOverdue = new Date(r.time) < now;
      const trClass = isOverdue ? 'bg-error-container/10 border-l-2 border-error' : 'hover:bg-surface-container-low transition-colors border-b border-surface-container/40';
      return `<tr class="row-compact ${trClass} cursor-pointer fc-row" data-id="${r.id}">
        <td class="px-3 py-1 mono-text text-sm whitespace-nowrap ${isOverdue ? 'text-error font-bold' : ''}">${escHtml(deTime(r.time))}</td>
        <td class="px-3 py-1 font-medium text-sm">${escHtml(r.name)}</td>
        <td class="px-3 py-1 mono-text text-xs opacity-60">${escHtml(r.identifier||'—')}</td>
        <td class="px-3 py-1 mono-text text-xs opacity-60">${escHtml(r.serverId)}</td>
        <td class="px-3 py-1">${isOverdue ? `<span class="bg-error text-white text-[9px] font-black px-1.5 py-0.5 rounded uppercase">Overdue</span>` : `<span class="bg-tertiary-container/10 text-tertiary-container text-[9px] font-bold px-1.5 py-0.5 rounded uppercase border border-tertiary-container/20">Scheduled</span>`}</td>
        <td class="px-3 py-1 text-right">
          <button class="text-error border border-error/30 hover:bg-error hover:text-white px-2 py-0.5 rounded transition-colors text-[10px] font-bold" onclick="event.stopPropagation();cancelFutureCall(${r.id}, this)">Cancel</button>
        </td>
      </tr>`;
    }).join('');

    el.innerHTML = pageWrap(
      pageHero('Future Calls', { sub: 'Scheduled server jobs',
        actions: `<div class="flex gap-3">${statTile('Total', data.total, 'indigo')}${statTile('Overdue', overdue, 'red')}${statTile('Upcoming', upcoming, 'emerald')}</div>` }) +
      tableShell(['Scheduled Time','Name','Identifier','Server','Status','Cancel'], rowsHtml, 'fcPaging')
    );

    // Wire row clicks → expand serializedObject as formatted JSON
    document.querySelectorAll('.fc-row').forEach(tr => {
      tr.addEventListener('click', () => toggleFutureCallDetail(tr, tr.dataset.id));
    });

    renderPagination(document.getElementById('fcPaging'), data, (p) => renderFutureCalls(document.getElementById('content'), p));
  } catch(e) {
    setConnStatus('error');
    el.innerHTML = pageWrap(pageHero('Future Calls') + errorState(e.message));
  }
}

// Lazily fetch and render a future-call's serializedObject as pretty JSON
// in an expandable row beneath, mirroring the Session Logs pattern.
const fcCache = {};
async function toggleFutureCallDetail(tr, id) {
  const existing = tr.nextElementSibling;
  if (existing && existing.classList.contains('fc-expand-row')) {
    existing.remove();
    tr.classList.remove('bg-surface-container-low','border-l-4','border-primary');
    return;
  }
  tr.classList.add('bg-surface-container-low','border-l-4','border-primary');
  const expandTr = document.createElement('tr');
  expandTr.className = 'fc-expand-row bg-surface-container-low/50';
  expandTr.innerHTML = `<td class="p-6" colspan="6"><div class="text-on-surface-variant text-sm">Loading…</div></td>`;
  tr.after(expandTr);

  try {
    const detail = fcCache[id] || await apiFetch(`/api/future-calls/${id}`);
    fcCache[id] = detail;

    let pretty = '', parseError = '';
    const raw = detail.serializedObject;
    if (raw === null || raw === undefined || raw === '') {
      pretty = '(no serializedObject)';
    } else {
      try { pretty = JSON.stringify(JSON.parse(raw), null, 2); }
      catch (e) { pretty = String(raw); parseError = 'Not valid JSON — showing raw value.'; }
    }

    expandTr.innerHTML = `<td colspan="6" class="p-0">
      <div class="p-6 border-l-4 border-primary bg-surface-container-low/40">
        <div class="flex items-center justify-between mb-3">
          <h4 class="text-xs font-black uppercase tracking-widest text-on-surface-variant flex items-center gap-2">
            <span class="material-symbols-outlined text-sm">data_object</span> serializedObject
          </h4>
          <button class="text-on-surface-variant hover:text-primary p-1 rounded hover:bg-primary/5 transition-colors flex items-center gap-1 text-[11px] font-bold" title="Copy JSON" onclick="event.stopPropagation();copyText(decodeEntities('${escHtml(pretty)}'), 'Copied JSON')">
            <span class="material-symbols-outlined text-sm">content_copy</span>Copy
          </button>
        </div>
        ${parseError ? `<div class="text-[11px] text-amber-700 mb-2">${escHtml(parseError)}</div>` : ''}
        <pre class="code-bg text-xs mono-text text-indigo-300 p-4 rounded-lg whitespace-pre-wrap break-all max-h-96 overflow-y-auto leading-relaxed">${escHtml(pretty)}</pre>
      </div>
    </td>`;
  } catch (e) {
    expandTr.innerHTML = `<td colspan="6" class="p-6"><div class="bg-error-container text-on-error-container text-sm rounded-lg p-3">Error: ${escHtml(e.message)}</div></td>`;
  }
}

async function cancelFutureCall(id, btn) {
  if (!confirm('Cancel this scheduled task?')) return;
  btn.disabled = true;
  try {
    const res = await fetch(`/api/future-calls/${id}`, { method: 'DELETE', headers: dbHeaders() });
    const data = await res.json();
    if (data.error) { showToast('Error: ' + data.error); btn.disabled = false; return; }
    btn.closest('tr').style.opacity = '0.4';
    btn.textContent = 'Cancelled';
  } catch(e) { showToast(e.message); btn.disabled = false; }
}
