// API console — modals: accounts, variables, save to collection, production confirmation.

function acModal(html, { wide = false, prod = false } = {}) {
  acCloseModal();
  const bg = document.createElement('div');
  bg.className = 'ac-modal-bg';
  bg.id = 'acModal';
  bg.innerHTML = `<div class="ac-modal ${wide ? 'wide' : ''} ${prod ? 'prod' : ''}">${html}</div>`;
  bg.addEventListener('mousedown', (e) => { if (e.target === bg) acCloseModal(); });
  document.body.appendChild(bg);
  const first = bg.querySelector('[autofocus]');
  if (first) first.focus();
  return bg;
}

function acCloseModal() {
  const m = document.getElementById('acModal');
  if (m) m.remove();
}

document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape' && document.getElementById('acModal')) acCloseModal();
});

const acModalHead = (title) => `<div class="ac-modal-head"><h3>${title}</h3>
  <button class="lc-icon-btn" onclick="acCloseModal()" title="Close"><span class="material-symbols-outlined">close</span></button></div>`;

// ── production confirmation ──
function acConfirmProduction() {
  const r = acState.req;
  acModal(`${acModalHead('Send to PRODUCTION?')}
    <div class="ac-modal-body">
      <div><span class="mono" style="font-weight:700">${escHtml(r.kind === 'serverpod' ? 'RPC' : r.method)}</span> <span class="mono">${escHtml(r.url)}</span></div>
      <div class="ac-hint">${r.kind === 'serverpod' ? 'Serverpod calls run with the selected login and can change production data.' : 'This request is not a GET and runs against production.'}
        ${r.effect === 'sends' ? '<b>It reaches real patients.</b>' : ''} Type <code>production</code> to send it once.</div>
      <input class="lc-input mono" id="acProdConfirm" autofocus autocomplete="off" placeholder="production"
        oninput="document.getElementById('acProdGo').disabled=this.value!=='production'"
        onkeydown="if(event.key==='Enter'&&this.value==='production'){acCloseModal();acSend('production')}">
    </div>
    <div class="ac-modal-foot">${btnGhost('Cancel', 'acCloseModal()')}
      <button class="btn btn-danger" id="acProdGo" disabled onclick="acCloseModal();acSend('production')"><span class="material-symbols-outlined">send</span>Send to production</button></div>`, { prod: true });
}

// ── accounts ──
async function acOpenAccounts() {
  try { acState.accounts = await acApi('/api/console/accounts'); } catch (e) { showToast(`❌ ${e.message}`); }
  const byEnv = AC_ENVS.map(env => [env, acState.accounts.filter(a => a.env === env)]);
  acModal(`${acModalHead('LillianCare accounts')}
    <div class="ac-modal-body">
      <div class="ac-hint">Used by the “LillianCare login” auth type: the helper calls <code>POST {{coreApi}}/emailIdp/login</code> and sends the session token as <code>Authorization: Bearer …</code>.
        Saved in <code>helper/.api-console/accounts.json</code> (only readable by you). Passwords never come back to this page.</div>
      ${byEnv.map(([env, list]) => `<div>
        <div class="field-label" style="margin-bottom:4px">${escHtml(env)}</div>
        ${list.length ? list.map(a => `<div class="ac-acc">
          <div class="grow"><div class="who">${escHtml(a.label)}</div>
            <div class="sub">${escHtml(a.email)}${a.session ? ` · logged in, scopes: ${escHtml((a.session.scopeNames || []).join(', ') || '—')}` : ''}${a.hasPassword ? '' : ' · <b>no password</b>'}</div></div>
          <button class="btn btn-sm" onclick="acLoginAccount('${a.id}', true)">Test login</button>
          <button class="btn btn-sm" onclick="acEditAccount('${a.id}')">Edit</button>
          <button class="lc-icon-btn" onclick="acDeleteAccount('${a.id}')" title="Delete"><span class="material-symbols-outlined">delete</span></button>
        </div>`).join('') : `<div class="ac-hint">None.</div>`}</div>`).join('')}
      <div class="panel" style="padding:var(--s-3)">
        <div class="field-label" id="acAccFormTitle" style="margin-bottom:8px">Add account</div>
        <input type="hidden" id="acAccId">
        <div class="ac-form">
          <div class="field">${fLabel('Env')}<select class="lc-select" id="acAccEnv">${AC_ENVS.map(e => `<option ${e === acState.env ? 'selected' : ''}>${e}</option>`).join('')}</select></div>
          <div class="field">${fLabel('Label')}<input class="lc-input" id="acAccLabel" placeholder="e.g. superAdmin"></div>
          <div class="field">${fLabel('Email')}<input class="lc-input" id="acAccEmail" autocomplete="off"></div>
          <div class="field full">${fLabel('Password')}<input class="lc-input" id="acAccPassword" type="password" autocomplete="new-password" placeholder="leave empty to keep the saved one"></div>
        </div>
        <div class="ac-row" style="margin-top:10px;justify-content:flex-end">${btnPrimary('Save account', 'acSaveAccount()')}</div>
      </div>
    </div>`, { wide: true });
}

function acEditAccount(id) {
  const a = acState.accounts.find(x => x.id === id);
  if (!a) return;
  document.getElementById('acAccId').value = a.id;
  document.getElementById('acAccEnv').value = a.env;
  document.getElementById('acAccLabel').value = a.label;
  document.getElementById('acAccEmail').value = a.email;
  document.getElementById('acAccPassword').value = '';
  document.getElementById('acAccFormTitle').textContent = `Edit ${a.email}`;
}

async function acSaveAccount() {
  const v = (id) => document.getElementById(id).value;
  try {
    await acApi('/api/console/accounts', { method: 'POST', body: { id: v('acAccId') || undefined, env: v('acAccEnv'), label: v('acAccLabel'), email: v('acAccEmail'), password: v('acAccPassword') } });
    showToast('✅ Account saved');
    await acOpenAccounts();
    await acLoadEnv();
  } catch (e) { showToast(`❌ ${e.message}`); }
}

async function acDeleteAccount(id) {
  if (!confirm('Delete this account?')) return;
  await acApi(`/api/console/accounts/${id}`, { method: 'DELETE' });
  await acOpenAccounts();
  await acLoadEnv();
}

async function acLoginAccount(id, inModal = false) {
  try {
    const r = await acApi(`/api/console/accounts/${id}/login`, { method: 'POST' });
    showToast(`✅ Logged in — scopes: ${(r.session.scopeNames || []).join(', ') || '—'}`);
  } catch (e) { showToast(`❌ ${e.message}`); }
  acState.accounts = await acApi('/api/console/accounts').catch(() => acState.accounts);
  if (inModal) acOpenAccounts(); else acRenderReqPane();
}

// ── variables ──
async function acOpenVars() {
  try { acState.vars = await acApi('/api/console/vars'); } catch (e) { showToast(`❌ ${e.message}`); return; }
  const env = acState.env;
  const used = acState.req ? acVarsIn(acState.req) : [];
  const base = acState.meta?.baseVars || {};
  const rows = (scope) => {
    const obj = { ...acState.vars[scope] };
    if (scope === env) for (const u of used) if (!u.startsWith('$') && !(u in base) && !(u in acState.vars.global) && !(u in obj)) obj[u] = '';
    return Object.entries(obj).map(([k, v]) => ({ k, v }));
  };
  const table = (scope) => `<table class="ac-kv" data-scope="${scope}">${rows(scope).map(({ k, v }) => `<tr>
      <td></td><td><input class="lc-input" value="${escHtml(k)}" placeholder="name"></td>
      <td><input class="lc-input" value="${escHtml(v)}" placeholder="value"></td>
      <td><button class="lc-icon-btn" onclick="this.closest('tr').remove()"><span class="material-symbols-outlined">close</span></button></td></tr>`).join('')}</table>
    <button class="btn btn-sm" style="margin-top:6px" onclick="acAddVarRow('${scope}')"><span class="material-symbols-outlined">add</span>Add</button>`;
  acModal(`${acModalHead('Variables')}
    <div class="ac-modal-body">
      <div class="ac-hint">Use <code>{{name}}</code> in the URL, headers and body. ${env} values override global ones; both override the built-in base URLs. Empty rows below are variables the current request uses but nothing defines yet.</div>
      <div><div class="field-label" style="margin-bottom:6px">${escHtml(env)} only</div>${table(env)}</div>
      <div><div class="field-label" style="margin-bottom:6px">Global</div>${table('global')}</div>
      <div><div class="field-label" style="margin-bottom:6px">Built-in for ${escHtml(env)} (read-only)</div>
        <table class="ac-headers">${Object.entries(base).map(([k, v]) => `<tr><td>{{${escHtml(k)}}}</td><td>${escHtml(v)}</td></tr>`).join('')}
        ${['$isoTimestamp', '$timestamp', '$guid', '$randomInt', '$date', '$datePlus7', '$datePlus30', '$year'].map(k => `<tr><td>{{${k}}}</td><td class="ac-hint">generated per request</td></tr>`).join('')}</table></div>
    </div>
    <div class="ac-modal-foot">${btnGhost('Cancel', 'acCloseModal()')}${btnPrimary('Save variables', 'acSaveVars()')}</div>`, { wide: true });
}

function acAddVarRow(scope) {
  const t = document.querySelector(`.ac-kv[data-scope="${scope}"]`);
  const tr = document.createElement('tr');
  tr.innerHTML = `<td></td><td><input class="lc-input" placeholder="name"></td><td><input class="lc-input" placeholder="value"></td>
    <td><button class="lc-icon-btn" onclick="this.closest('tr').remove()"><span class="material-symbols-outlined">close</span></button></td>`;
  t.appendChild(tr);
  tr.querySelector('input').focus();
}

async function acSaveVars() {
  const next = JSON.parse(JSON.stringify(acState.vars));
  document.querySelectorAll('#acModal .ac-kv[data-scope]').forEach(t => {
    const scope = t.dataset.scope;
    next[scope] = {};
    t.querySelectorAll('tr').forEach(tr => {
      const [k, v] = [...tr.querySelectorAll('input')].map(i => i.value.trim());
      if (k && v !== '') next[scope][k] = v;
    });
  });
  try {
    acState.vars = await acApi('/api/console/vars', { method: 'PUT', body: next });
    acCloseModal();
    showToast('✅ Variables saved');
  } catch (e) { showToast(`❌ ${e.message}`); }
}

// ── collections ──
async function acPersistCollections() {
  await acApi('/api/console/collections', { method: 'PUT', body: acState.collections });
  acRenderSideList();
}

const acId = () => Math.random().toString(36).slice(2, 10);

function acOpenSave() {
  const cols = acState.collections;
  acModal(`${acModalHead('Save request')}
    <div class="ac-modal-body">
      <div class="field">${fLabel('Name')}<input class="lc-input" id="acSaveName" value="${escHtml(acState.req.name)}" autofocus></div>
      <div class="field">${fLabel('Collection')}<select class="lc-select" id="acSaveCol">
        ${cols.map((c, i) => `<option value="${i}">${escHtml(c.name)}</option>`).join('')}<option value="new">+ New collection…</option></select></div>
      <div class="field">${fLabel('New collection name')}<input class="lc-input" id="acSaveNewCol" placeholder="only if “New collection” is picked"></div>
      <div class="ac-hint">Saved with its auth type and any typed tokens; credentials the server adds are never stored.</div>
    </div>
    <div class="ac-modal-foot">${btnGhost('Cancel', 'acCloseModal()')}${btnPrimary('Save', 'acDoSave()')}</div>`);
  if (!cols.length) document.getElementById('acSaveCol').value = 'new';
}

async function acDoSave() {
  const name = document.getElementById('acSaveName').value.trim() || acState.req.name;
  let ci = document.getElementById('acSaveCol').value;
  if (ci === 'new') {
    const colName = document.getElementById('acSaveNewCol').value.trim() || 'My requests';
    acState.collections.push({ id: acId(), name: colName, items: [] });
    ci = acState.collections.length - 1;
  }
  acState.req.name = name;
  acState.collections[ci].items.push({ id: acId(), name, request: acRequestPayload() });
  try {
    await acPersistCollections();
    acCloseModal();
    acState.open.add(`col:${acState.collections[ci].id}`);
    acRenderRequest();
    showToast(`✅ Saved to ${acState.collections[ci].name}`);
  } catch (e) { showToast(`❌ ${e.message}`); }
}

async function acNewCollection() {
  const name = prompt('Collection name');
  if (!name) return;
  acState.collections.push({ id: acId(), name, items: [] });
  await acPersistCollections();
}

async function acRenameCollection(ci) {
  const name = prompt('Rename collection', acState.collections[ci].name);
  if (!name) return;
  acState.collections[ci].name = name;
  await acPersistCollections();
}

async function acDeleteCollection(ci) {
  if (!confirm(`Delete collection “${acState.collections[ci].name}” and its ${acState.collections[ci].items.length} requests?`)) return;
  acState.collections.splice(ci, 1);
  await acPersistCollections();
}

async function acDeleteSaved(ci, ii) {
  acState.collections[ci].items.splice(ii, 1);
  await acPersistCollections();
}

// ── find a patient's lcAccountId by email ──
// Searches app_user_info on the console's env (same query as the Users view) and
// writes the id into the open request in place of {{lcAccountId}}. The inserted
// value is remembered, so picking another user replaces it again.
function acUsesLcAccountId(r = acState.req) {
  const text = [r.url, r.body, ...r.headers.map(h => h.value)].join(' ');
  return /\{\{\s*lcAccountId\s*\}\}/.test(text) || (r.lcFilled && text.includes(r.lcFilled));
}

function acOpenLcLookup() {
  acModal(`${acModalHead(`Find lcAccountId — ${escHtml(acState.env)}`)}
    <div class="ac-modal-body">
      <div class="ac-row" style="flex-wrap:nowrap">
        <input class="lc-input" id="acLcQuery" autofocus placeholder="Email (or part of a name)" autocomplete="off"
          onkeydown="if(event.key==='Enter')acLcSearch()">
        ${btnPrimary('Search', 'acLcSearch()', { icon: 'search' })}
      </div>
      <div class="ac-hint">Searches <code>app_user_info</code> on ${escHtml(acState.env)}; the id replaces <code>{{lcAccountId}}</code> in the URL, headers and body.</div>
      <div id="acLcResults"></div>
    </div>`, { wide: true });
}

async function acLcSearch() {
  const q = document.getElementById('acLcQuery').value.trim();
  const box = document.getElementById('acLcResults');
  if (!q) return;
  box.innerHTML = loadingState('Searching…');
  try {
    await ensureEnvPasswords();
    const res = await fetch(`/api/users?q=${encodeURIComponent(q)}&page=1&pageSize=10`, { headers: envHeadersFor(acState.env) });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
    const rows = data.rows || data.data || [];
    if (!rows.length) { box.innerHTML = `<div class="ac-hint">No user matches “${escHtml(q)}” on ${escHtml(acState.env)}.</div>`; return; }
    box.innerHTML = rows.map(u => `<div class="ac-acc">
        <div class="grow"><div class="who">${escHtml(`${u.firstName || ''} ${u.lastName || ''}`.trim() || '—')} · ${escHtml(u.email || '')}</div>
          <div class="sub mono">lcAccountId ${escHtml(u.lcAccountId || '—')}${u.praxisId ? ` · ${escHtml(praxisLabel(u.praxisId))}` : ''}${u.pmsPatientId ? ` · pmsPatientId ${escHtml(u.pmsPatientId)}` : ''}</div></div>
        ${u.lcAccountId ? `<button class="btn btn-sm btn-primary" onclick="acUseLcAccountId('${escHtml(u.lcAccountId)}')">Use</button>` : '<span class="pill">no lcAccountId</span>'}
      </div>`).join('') + (data.total > rows.length ? `<div class="ac-hint">${data.total - rows.length} more — refine the search.</div>` : '');
  } catch (e) {
    box.innerHTML = `<div class="ac-hint" style="color:var(--red)">${escHtml(e.message)}</div>`;
  }
}

function acUseLcAccountId(id) {
  const r = acState.req;
  const replace = (s) => {
    let out = String(s || '').replace(/\{\{\s*lcAccountId\s*\}\}/g, id);
    if (r.lcFilled && r.lcFilled !== id) out = out.split(r.lcFilled).join(id);
    return out;
  };
  const before = JSON.stringify([r.url, r.body, r.headers]);
  r.url = replace(r.url);
  r.body = replace(r.body);
  r.headers = r.headers.map(h => ({ ...h, value: replace(h.value) }));
  const changed = JSON.stringify([r.url, r.body, r.headers]) !== before;
  acCloseModal();
  if (changed) {
    r.lcFilled = id;
    acSaveDraft();
    acRenderRequest();
    showToast(`✅ lcAccountId ${id} inserted`);
  } else {
    copyText(id);
  }
}
