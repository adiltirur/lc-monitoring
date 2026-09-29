// ═════════════════════════════════════════════════════════════════════════
// SERVER HEALTH
// ═════════════════════════════════════════════════════════════════════════
async function renderHealth(el) {
  el.innerHTML = pageWrap(pageHero('Server Health') + loadingState());
  try {
    const data = await apiFetch('/api/health');
    setConnStatus('connected');

    const latest = {};
    for (const m of data.metrics) {
      if (!latest[m.name] || new Date(m.timestamp) > new Date(latest[m.name].timestamp)) latest[m.name] = m;
    }
    const conn = data.connections[0];

    const metricsHtml = Object.values(latest).length ? Object.values(latest).map(m => `
      <div class="flex items-center justify-between border-b border-slate-50 pb-2.5">
        <span class="text-xs mono-text text-on-surface-variant">${escHtml(m.name)}</span>
        <div class="flex items-center gap-2">
          <span class="mono-text font-bold text-sm">${m.value.toFixed(2)}</span>
          <span class="w-1.5 h-1.5 rounded-full ${m.isHealthy ? 'bg-tertiary' : 'bg-error'}"></span>
        </div>
      </div>`).join('') : '<div class="text-outline text-sm italic">No metrics</div>';

    const poolHtml = conn ? `<div class="space-y-6">
      <div class="flex items-end gap-3">
        <span class="text-3xl font-black mono-text text-tertiary leading-none">${conn.active}</span>
        <span class="text-[10px] font-bold uppercase tracking-widest mb-1">Active</span>
      </div>
      <div class="flex items-end gap-3">
        <span class="text-3xl font-black mono-text text-slate-400 leading-none">${conn.idle}</span>
        <span class="text-[10px] font-bold uppercase tracking-widest mb-1">Idle</span>
      </div>
      <div class="flex items-end gap-3">
        <span class="text-3xl font-black mono-text text-amber-500 leading-none">${conn.closing}</span>
        <span class="text-[10px] font-bold uppercase tracking-widest mb-1">Closing</span>
      </div>
      <p class="text-[10px] text-slate-400 italic mt-4">Updated ${escHtml(deTime(conn.timestamp))}</p>
    </div>` : '<div class="text-outline text-sm italic">No connection data</div>';

    const historyRowsHtml = data.metrics.slice(0, 50).map(m => `<tr class="zebra-row hover:bg-surface-container">
      <td class="px-4 py-2 mono-text text-xs whitespace-nowrap">${escHtml(deTime(m.timestamp))}</td>
      <td class="px-4 py-2 text-sm">${escHtml(m.name)}</td>
      <td class="px-4 py-2 mono-text text-xs text-on-surface-variant">${escHtml(m.serverId)}</td>
      <td class="px-4 py-2">${m.isHealthy ? '<span class="w-2 h-2 inline-block rounded-full bg-tertiary"></span>' : '<span class="w-2 h-2 inline-block rounded-full bg-error"></span>'}</td>
      <td class="px-4 py-2 mono-text font-bold">${m.value.toFixed(3)}</td>
    </tr>`).join('');

    el.innerHTML = pageWrap(
      pageHero('Server Health', { sub: `Host: ${escHtml(conn?.serverId||'—')}`,
        actions: `<button class="text-on-surface-variant hover:text-primary flex items-center gap-1.5 text-[10px] font-bold uppercase tracking-wider" onclick="renderHealth(document.getElementById('content'))"><span class="material-symbols-outlined text-sm">refresh</span>Refresh</button>` }) +
      `<div class="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
        <section class="bg-surface-container-lowest rounded-xl shadow-whisper p-6">
          <h2 class="text-lg font-bold tracking-tight mb-6">Health Metrics</h2>
          <div class="space-y-3">${metricsHtml}</div>
        </section>
        <section class="bg-surface-container-lowest rounded-xl shadow-whisper p-6">
          <h2 class="text-lg font-bold tracking-tight mb-6">DB Connection Pool</h2>
          ${poolHtml}
        </section>
      </div>` +
      `<section class="bg-surface-container-lowest rounded-xl shadow-whisper overflow-hidden">
        <div class="px-6 py-4 flex justify-between items-center bg-white border-b border-surface-container-low">
          <h3 class="text-lg font-bold tracking-tight">Metric History</h3>
          <span class="text-xs mono-text text-on-surface-variant">${data.metrics.length} samples</span>
        </div>
        <div class="overflow-x-auto">
          <table class="w-full text-left border-collapse">
            <thead class="bg-surface-container-low text-on-surface-variant"><tr>
              <th class="px-4 py-3 text-[0.7rem] font-bold uppercase tracking-widest">Time</th>
              <th class="px-4 py-3 text-[0.7rem] font-bold uppercase tracking-widest">Name</th>
              <th class="px-4 py-3 text-[0.7rem] font-bold uppercase tracking-widest">Server</th>
              <th class="px-4 py-3 text-[0.7rem] font-bold uppercase tracking-widest">Healthy</th>
              <th class="px-4 py-3 text-[0.7rem] font-bold uppercase tracking-widest">Value</th>
            </tr></thead>
            <tbody>${historyRowsHtml}</tbody>
          </table>
        </div>
      </section>`
    );
  } catch(e) {
    setConnStatus('error');
    el.innerHTML = pageWrap(pageHero('Server Health') + errorState(e.message));
  }
}
