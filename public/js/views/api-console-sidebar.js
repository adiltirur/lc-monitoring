// API console — left column: catalog (Serverpod + external), collections, history.

function acRenderSide() {
  const el = document.getElementById('acSide');
  if (!el || !acState.catalog) return;
  const c = acState.catalog;
  const tabs = [['catalog', 'Catalog'], ['collections', `Collections`], ['history', 'History']];
  el.innerHTML = `
    <div class="lc-tabs">${tabs.map(([k, l]) => `<button class="lc-tab ${acState.sideTab === k ? 'active' : ''}" onclick="acSideTab('${k}')">${l}</button>`).join('')}</div>
    <div class="ac-side-search"><input class="lc-input" id="acSearch" placeholder="${acState.sideTab === 'catalog' ? `Search ${c.serverpod.counts.methods + c.externals.length} requests…` : 'Filter…'}"
      value="${escHtml(acState.search)}" oninput="acSearchInput(this.value)"></div>
    ${acState.sideTab === 'catalog' ? `<div class="ac-catalog-info">
      <span class="grow" title="Read from ${escHtml(c.serverpod.coreDir)}${c.serverpod.git ? ` — branch ${escHtml(c.serverpod.git.branch || 'detached')} @ ${escHtml(c.serverpod.git.commit || '?')}` : ''}">${c.serverpod.counts.methods} methods · built ${escHtml(deTime(c.serverpod.builtAt).slice(-8))}${c.serverpod.git ? ` · <span class="mono">${escHtml(c.serverpod.git.branch || 'detached')}${c.serverpod.git.commit ? '@' + escHtml(c.serverpod.git.commit) : ''}</span>` : ''}</span>
      <button class="btn btn-sm" onclick="acStartSync()" title="Claude Code reads LillianCare-Core and adds templates for backend calls (Principa, Personio, webhooks, …) the console doesn't have yet"><span class="material-symbols-outlined">auto_awesome</span>Find missing</button>
      <button class="lc-icon-btn" onclick="acReloadCatalog()" title="Reload the catalog from LillianCare-Core"><span class="material-symbols-outlined" id="acReloadIcon">refresh</span></button>
    </div>` : ''}
    <div class="ac-side-list" id="acSideList"></div>`;
  acRenderSideList();
}

// Forces a rebuild (normally automatic when Core's generated code, models or
// endpoint sources change) and reports what changed.
async function acReloadCatalog() {
  const icon = document.getElementById('acReloadIcon');
  if (icon) icon.classList.add('spin');
  const key = (c) => new Set(c.serverpod.endpoints.flatMap(e => e.methods.map(m => `${e.name}.${m.name}`)));
  const before = key(acState.catalog);
  try {
    acState.catalog = await acApi('/api/console/catalog?reload=1');
    const after = key(acState.catalog);
    const added = [...after].filter(k => !before.has(k));
    const removed = [...before].filter(k => !after.has(k));
    acRenderSide();
    showToast(added.length || removed.length
      ? `✅ Catalog reloaded: ${added.length ? `+${added.length} (${added.slice(0, 3).join(', ')}${added.length > 3 ? '…' : ''})` : ''}${added.length && removed.length ? ', ' : ''}${removed.length ? `−${removed.length}` : ''}`
      : '✅ Catalog reloaded — no endpoint changes');
  } catch (e) {
    showToast(`❌ ${e.message}`);
    if (icon) icon.classList.remove('spin');
  }
}

function acSideTab(tab) {
  acState.sideTab = tab;
  acRenderSide();
}

function acSearchInput(v) {
  acState.search = v;
  acRenderSideList();
}

function acRenderSideList() {
  const el = document.getElementById('acSideList');
  if (!el) return;
  if (acState.sideTab === 'collections') el.innerHTML = acCollectionsHtml();
  else if (acState.sideTab === 'history') el.innerHTML = acHistoryHtml();
  else el.innerHTML = acCatalogHtml();
}

function acToggleNode(id) {
  if (acState.open.has(id)) acState.open.delete(id); else acState.open.add(id);
  acRenderSideList();
}

const acMatch = (q, ...parts) => !q || parts.some(p => String(p || '').toLowerCase().includes(q));

function acCatalogHtml() {
  const q = acState.search.trim().toLowerCase();
  const { serverpod, externals } = acState.catalog;
  const cur = acState.req.ref || {};
  let html = '';

  // Serverpod endpoints
  const eps = serverpod.endpoints.map(ep => ({ ep, methods: ep.methods.filter(m => acMatch(q, ep.name, m.name, `${ep.name}.${m.name}`, `${ep.name}/${m.name}`)) }))
    .filter(x => x.methods.length);
  html += `<div class="ac-group"><span class="material-symbols-outlined" style="font-size:15px">dns</span>Serverpod<span class="count">${serverpod.counts.methods}</span></div>`;
  for (const { ep, methods } of eps) {
    const id = `sp:${ep.name}`;
    const open = q || acState.open.has(id);
    html += `<button class="ac-node ${open ? 'open' : ''}" onclick="acToggleNode('${id}')" title="${escHtml(ep.source || ep.module || '')}">
      <span class="material-symbols-outlined caret">chevron_right</span>
      <span class="grow">${escHtml(ep.name)}</span>
      ${ep.requireLogin ? '<span class="material-symbols-outlined flag" title="requireLogin">lock</span>' : ''}
      <span class="meta">${methods.length}</span></button>`;
    if (!open) continue;
    for (const m of methods) {
      const active = cur.endpoint === ep.name && cur.method === m.name;
      html += m.streaming
        ? `<button class="ac-node child" disabled title="Streaming method (WebSocket) — not supported in the console"><span class="ac-m RPC">WS</span><span class="grow">${escHtml(m.name)}</span></button>`
        : `<button class="ac-node child ${active ? 'active' : ''}" onclick="acOpenServerpod('${ep.name}','${m.name}')"><span class="ac-m RPC">RPC</span><span class="grow">${escHtml(m.name)}</span></button>`;
    }
  }
  if (!eps.length) html += `<div class="ac-empty">No Serverpod method matches.</div>`;

  // External groups
  const groups = {};
  externals.forEach(t => { if (acMatch(q, t.group, t.name, t.url, t.method)) (groups[t.group] ||= []).push(t); });
  for (const [g, items] of Object.entries(groups)) {
    const id = `ext:${g}`;
    const open = q || acState.open.has(id);
    html += `<button class="ac-group" style="width:100%;border:0;background:transparent;cursor:pointer" onclick="acToggleNode('${escHtml(id)}')">
      <span class="material-symbols-outlined" style="font-size:15px;transition:transform .12s;${open ? 'transform:rotate(90deg)' : ''}">chevron_right</span>${escHtml(g)}<span class="count">${items.length}</span></button>`;
    if (!open) continue;
    for (const t of items) {
      const flag = t.effect === 'sends' ? '<span class="material-symbols-outlined flag sends" title="Sends to a real person">outgoing_mail</span>'
        : t.effect === 'write' ? '<span class="material-symbols-outlined flag write" title="Changes data">edit_note</span>' : '';
      const gen = t.generated ? '<span class="material-symbols-outlined flag" title="Added by a Find missing scan">auto_awesome</span>' : '';
      html += `<button class="ac-node ${cur.extId === t.id ? 'active' : ''}" onclick="acOpenExternal('${t.id}')" title="${escHtml(t.url)}">
        <span class="ac-m ${t.method}">${t.method}</span><span class="grow">${escHtml(t.name)}</span>${gen}${flag}</button>`;
    }
  }
  return html;
}

function acCollectionsHtml() {
  const q = acState.search.trim().toLowerCase();
  const cols = acState.collections;
  let html = `<div class="ac-row" style="padding:8px 12px">
    <button class="btn btn-sm" onclick="acNewCollection()"><span class="material-symbols-outlined">create_new_folder</span>New</button>
    <button class="btn btn-sm" onclick="acImportPick()"><span class="material-symbols-outlined">upload</span>Import Postman</button></div>`;
  if (!cols.length) return html + `<div class="ac-empty">No collections yet. Save a request (bookmark icon) or import a Postman collection.</div>`;
  cols.forEach((col, ci) => {
    const items = col.items.filter(it => acMatch(q, col.name, it.name, it.request.url));
    if (q && !items.length) return;
    const id = `col:${col.id}`;
    const open = q || acState.open.has(id);
    html += `<div class="ac-line">
      <button class="ac-node ${open ? 'open' : ''}" onclick="acToggleNode('${id}')">
        <span class="material-symbols-outlined caret">chevron_right</span><span class="grow">${escHtml(col.name)}</span><span class="meta">${col.items.length}</span></button>
      <button class="lc-icon-btn" title="Export as Postman collection" onclick="acExportCollection(${ci})"><span class="material-symbols-outlined">download</span></button>
      <button class="lc-icon-btn" title="Rename" onclick="acRenameCollection(${ci})"><span class="material-symbols-outlined">edit</span></button>
      <button class="lc-icon-btn" title="Delete collection" onclick="acDeleteCollection(${ci})"><span class="material-symbols-outlined">delete</span></button>
    </div>`;
    if (!open) return;
    col.items.forEach((it, ii) => {
      if (q && !acMatch(q, col.name, it.name, it.request.url)) return;
      const m = it.request.kind === 'serverpod' ? 'RPC' : it.request.method;
      html += `<div class="ac-line">
        <button class="ac-node child" onclick="acOpenSaved(${ci},${ii})" title="${escHtml(it.request.url)}"><span class="ac-m ${m}">${m}</span><span class="grow">${escHtml(it.name)}</span></button>
        <button class="lc-icon-btn" title="Remove" onclick="acDeleteSaved(${ci},${ii})"><span class="material-symbols-outlined">close</span></button></div>`;
    });
  });
  return html;
}

function acHistoryHtml() {
  const q = acState.search.trim().toLowerCase();
  const list = acState.history.filter(h => acMatch(q, h.name, h.request?.url, h.env, h.status));
  let html = `<div class="ac-row space" style="padding:8px 12px"><span class="ac-hint">Requests only — responses are never saved.</span>
    ${acState.history.length ? `<button class="btn btn-sm" onclick="acClearHistory()">Clear</button>` : ''}</div>`;
  if (!list.length) return html + `<div class="ac-empty">Nothing sent yet.</div>`;
  list.forEach((h) => {
    const i = acState.history.indexOf(h);
    const m = h.request?.kind === 'serverpod' ? 'RPC' : h.request?.method;
    const st = h.status === 'ERR' ? '<span class="pill err">ERR</span>' : `<span class="pill ${h.status >= 400 ? 'err' : h.status >= 300 ? 'warn' : 'ok'}">${h.status}</span>`;
    html += `<button class="ac-node" onclick="acOpenHistory(${i})" title="${escHtml(h.request?.url || '')}">
      <span class="ac-m ${m}">${m}</span>
      <span class="grow">${escHtml(h.name || h.request?.url || '')}<br><span class="meta">${escHtml(h.env)} · ${deTime(h.at)} · ${h.ms ?? '—'} ms</span></span>${st}</button>`;
  });
  return html;
}

// ── opening requests ──
function acOpenServerpod(epName, methodName) {
  const ep = acState.catalog.serverpod.endpoints.find(e => e.name === epName);
  const m = ep && ep.methods.find(x => x.name === methodName);
  if (!m) return;
  const acc = acState.accounts.find(a => a.env === acState.env);
  const needsLogin = ep.requireLogin === true;
  acState.req = {
    name: `${ep.name}.${m.name}`, kind: 'serverpod', ref: { endpoint: ep.name, method: m.name },
    method: 'POST', url: `{{coreApi}}/${ep.name}/${m.name}`,
    headers: [{ key: 'Accept', value: 'application/json', enabled: true }],
    bodyMode: 'json', body: JSON.stringify(m.body, null, 2),
    auth: needsLogin ? { type: 'core', accountId: acc ? acc.id : null } : { type: 'none' },
    effect: null, example: JSON.stringify(m.body, null, 2),
  };
  acState.reqTab = m.params.length ? 'body' : 'docs';
  acAfterOpen();
}

function acOpenExternal(id) {
  const t = acState.catalog.externals.find(x => x.id === id);
  if (!t) return;
  const body = t.body === undefined ? '' : JSON.stringify(t.body, null, 2);
  acState.req = {
    name: `${t.group}: ${t.name}`, kind: 'external', ref: { extId: t.id },
    method: t.method, url: t.url,
    headers: Object.entries(t.headers || {}).map(([key, value]) => ({ key, value, enabled: true })),
    bodyMode: t.body === undefined ? 'none' : 'json', body,
    auth: { type: t.auth || 'none' }, effect: t.effect, example: body || null,
  };
  acState.reqTab = t.body !== undefined ? 'body' : 'params';
  acAfterOpen();
}

function acOpenRequest(r) {
  acState.req = { ...acBlankRequest(), ...JSON.parse(JSON.stringify(r)) };
  acState.reqTab = acState.req.bodyMode !== 'none' ? 'body' : 'params';
  acAfterOpen();
}

function acOpenSaved(ci, ii) { acOpenRequest(acState.collections[ci].items[ii].request); }

function acOpenHistory(i) {
  const h = acState.history[i];
  if (!h) return;
  if (AC_ENVS.includes(h.env) && h.env !== acState.env) acSetEnv(h.env);
  acOpenRequest(h.request);
}

function acAfterOpen() {
  acState.resp = null;
  acSaveDraft();
  acRenderRequest();
  acRenderResponse();
  acRenderSideList();
}

async function acClearHistory() {
  if (!confirm('Clear the request history?')) return;
  await acApi('/api/console/history', { method: 'DELETE' });
  acState.history = [];
  acRenderSideList();
}
