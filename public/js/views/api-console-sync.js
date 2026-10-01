// API console — "Find missing": a headless Claude Code session reads LillianCare-Core
// (read-only) and the server adds templates for backend calls the console doesn't have
// yet (lib/api-console/sync.js → externals-generated.json). This file is the modal
// that starts it, shows progress, and reloads the catalog when it's done.

let acSyncTimer = null;

async function acStartSync() {
  try {
    const s = await acApi('/api/console/sync');
    if (s.status !== 'running') await acApi('/api/console/sync', { method: 'POST' });
  } catch (e) { showToast(`❌ ${e.message}`); return; }
  acOpenSyncModal();
}

function acOpenSyncModal() {
  acModal(`${acModalHead('Find missing requests — Claude Code')}
    <div class="ac-modal-body" id="acSyncBody">${loadingState('Starting…')}</div>
    <div class="ac-modal-foot" id="acSyncFoot"></div>`, { wide: true });
  acPollSync();
}

async function acPollSync() {
  clearTimeout(acSyncTimer);
  let s;
  try { s = await acApi('/api/console/sync'); } catch (e) { s = { status: 'failed', error: e.message }; }
  const body = document.getElementById('acSyncBody');
  const foot = document.getElementById('acSyncFoot');
  if (!body) return; // modal closed; the scan keeps running on the server
  const elapsed = s.startedAt ? Math.round(((s.finishedAt ? new Date(s.finishedAt) : new Date()) - new Date(s.startedAt)) / 1000) : 0;
  const log = (s.log || []).slice(-14).map(l => `<div>${escHtml(l)}</div>`).join('');

  if (s.status === 'running') {
    body.innerHTML = `<div class="ac-row"><span class="material-symbols-outlined spin">progress_activity</span>
        <b>Reading LillianCare-Core…</b><span class="ac-hint">${elapsed} s · usually 2–6 minutes</span></div>
      <div class="ac-hint">Read-only session (Read/Grep/Glob, no secrets) comparing the backend's outbound calls and webhook routes
        with the console's templates. You can close this window; the scan keeps running.</div>
      <div class="code ac-sync-log">${log || '<span class="ac-hint">waiting for the first step…</span>'}</div>`;
    foot.innerHTML = `${btnGhost('Close', 'acCloseModal()')}<button class="btn btn-danger" onclick="acCancelSync()">Cancel scan</button>`;
    acSyncTimer = setTimeout(acPollSync, 1500);
    return;
  }
  foot.innerHTML = btnPrimary('Done', 'acCloseModal()');
  if (s.status === 'failed' || s.status === 'cancelled') {
    body.innerHTML = `<div class="ac-neterr"><div class="band"><span class="material-symbols-outlined">error</span>${s.status === 'cancelled' ? 'Cancelled' : 'Scan failed'}</div>
      <div class="panel-body mono">${escHtml(s.error || 'Cancelled')}</div></div>
      ${log ? `<div class="code ac-sync-log">${log}</div>` : ''}`;
    return;
  }
  if (s.status !== 'done' || !s.summary) { body.innerHTML = `<div class="ac-hint">No scan has run yet.</div>`; foot.innerHTML = `${btnGhost('Close', 'acCloseModal()')}${btnPrimary('Start scan', 'acStartSync()')}`; return; }

  const sum = s.summary;
  // Pull the new templates into the tree and open their groups.
  try { acState.catalog = await acApi('/api/console/catalog'); } catch { /* keep old */ }
  sum.added.forEach(a => acState.open.add(`ext:${a.group}`));
  acState.sideTab = 'catalog';
  acRenderSide();
  body.innerHTML = `
    <div class="ac-row"><span class="pill ${sum.added.length ? 'ok' : ''}">${sum.added.length} added</span>
      ${sum.skipped.length ? `<span class="pill warn">${sum.skipped.length} rejected</span>` : ''}
      ${sum.stale.length ? `<span class="pill">${sum.stale.length} possibly stale</span>` : ''}
      <span class="ac-hint">${elapsed} s${s.costUsd != null ? ` · $${s.costUsd.toFixed(2)}` : ''}</span></div>
    ${sum.notes ? `<div class="ac-hint" style="white-space:pre-line">${escHtml(sum.notes)}</div>` : ''}
    ${sum.added.length ? `<div><div class="field-label" style="margin-bottom:4px">Added — saved in lib/api-console/externals-generated.json (review with git diff)</div>
      ${sum.added.map(a => `<button class="ac-node" onclick="acCloseModal();acOpenExternal('${a.id}')"><span class="ac-m ${a.method}">${a.method}</span>
        <span class="grow">${escHtml(a.group)}: ${escHtml(a.name)}<br><span class="meta">${escHtml(a.url)}</span></span></button>`).join('')}</div>`
      : '<div class="ac-hint">Nothing missing — every backend call has a template.</div>'}
    ${sum.skipped.length ? `<div><div class="field-label" style="margin-bottom:4px">Rejected by the checks</div>
      ${sum.skipped.map(k => `<div class="ac-hint">• ${escHtml(k.name || '')} <code>${escHtml(k.url || '')}</code> — ${escHtml(k.reason)}</div>`).join('')}</div>` : ''}
    ${sum.stale.length ? `<div><div class="field-label" style="margin-bottom:4px">Templates whose call may no longer exist</div>
      ${sum.stale.map(k => `<div class="ac-hint">• <code>${escHtml(k.url)}</code> — ${escHtml(k.reason)}</div>`).join('')}</div>` : ''}`;
}

async function acCancelSync() {
  try { await acApi('/api/console/sync', { method: 'DELETE' }); } catch (e) { showToast(`❌ ${e.message}`); }
  acPollSync();
}

async function acRemoveGenerated(id) {
  if (!confirm('Remove this template (added by a scan)?')) return;
  try {
    await acApi(`/api/console/externals/${id}`, { method: 'DELETE' });
    acState.catalog = await acApi('/api/console/catalog');
    acNewRequest();
    acRenderSide();
    showToast('✅ Template removed');
  } catch (e) { showToast(`❌ ${e.message}`); }
}
