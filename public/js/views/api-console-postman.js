// API console — Postman v2.1 import/export and "Copy as curl".
// Postman and the console share the {{variable}} syntax, so URLs and bodies
// round-trip unchanged. Auth types Postman has (bearer, basic, apikey) map
// 1:1; the helper's own types (LillianCare login, Principa JWT, …) are kept
// in an `lcHelper` field Postman ignores and noted in the description.

const AC_POSTMAN_SCHEMA = 'https://schema.getpostman.com/json/collection/v2.1.0/collection.json';

// ── export ──
function acToPostmanAuth(a) {
  switch (a.type) {
    case 'none': return { type: 'noauth' };
    case 'bearer': return { type: 'bearer', bearer: [{ key: 'token', value: a.token || '', type: 'string' }] };
    case 'basic': return { type: 'basic', basic: [{ key: 'username', value: a.username || '', type: 'string' }, { key: 'password', value: a.password || '', type: 'string' }] };
    case 'header': return { type: 'apikey', apikey: [{ key: 'key', value: a.name || '', type: 'string' }, { key: 'value', value: a.value || '', type: 'string' }, { key: 'in', value: 'header', type: 'string' }] };
    default: return { type: 'noauth' };
  }
}

function acToPostmanItem(name, r) {
  const custom = !['none', 'bearer', 'basic', 'header'].includes(r.auth.type);
  const item = {
    name,
    request: {
      method: r.method,
      header: r.headers.filter(h => h.key).map(h => ({ key: h.key, value: h.value, ...(h.enabled === false ? { disabled: true } : {}) })),
      url: { raw: r.url },
      auth: acToPostmanAuth(r.auth),
      ...(custom ? { description: `LC Helper auth: ${acAuthLabel(r.auth.type)} — added by the helper server; set it up manually outside the helper.` } : {}),
    },
    lcHelper: { kind: r.kind, ref: r.ref, auth: r.auth, effect: r.effect || null },
  };
  if (r.bodyMode !== 'none') item.request.body = { mode: 'raw', raw: r.body, options: { raw: { language: r.bodyMode === 'json' ? 'json' : 'text' } } };
  return item;
}

async function acExportCollection(ci) {
  const col = acState.collections[ci];
  const base = acState.meta?.baseVars || {};
  const doc = {
    info: { name: col.name, schema: AC_POSTMAN_SCHEMA, description: `Exported from LC Helper API Console (${acState.env}).` },
    item: col.items.map(it => acToPostmanItem(it.name, it.request)),
    variable: [
      ...Object.entries(base).map(([key, value]) => ({ key, value })),
      ...Object.entries({ ...acState.vars?.global, ...acState.vars?.[acState.env] }).map(([key, value]) => ({ key, value })),
    ],
  };
  const safe = col.name.replace(/[^\w.-]+/g, '_');
  try {
    const { id } = await acApi('/api/console/export', { method: 'POST', body: { name: `${safe}.postman_collection.json`, content: JSON.stringify(doc, null, 2) } });
    window.location.href = `/api/console/download/${id}`;
  } catch (e) { showToast(`❌ ${e.message}`); }
}

// ── import ──
function acImportPick() {
  document.getElementById('acImportFile')?.click();
}

function acImportFile(input) {
  const f = input.files && input.files[0];
  input.value = '';
  if (!f) return;
  const reader = new FileReader();
  reader.onload = async () => {
    let doc;
    try { doc = JSON.parse(reader.result); } catch { showToast('❌ Not a JSON file'); return; }
    try {
      if (Array.isArray(doc.values)) await acImportEnvironment(doc);
      else if (doc.info && Array.isArray(doc.item)) await acImportCollection(doc);
      else showToast('❌ Not a Postman collection (v2/v2.1) or environment');
    } catch (e) { showToast(`❌ Import failed: ${e.message}`); }
  };
  reader.readAsText(f);
}

function acFromPostmanAuth(pa) {
  if (!pa || pa.type === 'noauth') return { type: 'none' };
  const get = (list, key) => ((pa[pa.type] || []).find(x => x.key === key) || {}).value || '';
  if (pa.type === 'bearer') return { type: 'bearer', token: get('bearer', 'token') };
  if (pa.type === 'basic') return { type: 'basic', username: get('basic', 'username'), password: get('basic', 'password') };
  if (pa.type === 'apikey' && (get('apikey', 'in') || 'header') === 'header') return { type: 'header', name: get('apikey', 'key'), value: get('apikey', 'value') };
  return null; // unsupported (oauth2, digest, …)
}

function acFromPostmanRequest(req, inheritedAuth, lc, notes) {
  const url = typeof req.url === 'string' ? req.url : req.url?.raw
    || `${(req.url?.protocol ? req.url.protocol + '://' : '')}${[].concat(req.url?.host || []).join('.')}/${[].concat(req.url?.path || []).join('/')}`;
  const headers = (req.header || []).map(h => ({ key: h.key, value: h.value ?? '', enabled: !h.disabled }));
  let bodyMode = 'none', body = '';
  const b = req.body;
  if (b && b.mode === 'raw') {
    body = b.raw || '';
    bodyMode = b.options?.raw?.language === 'json' || /^\s*[[{]/.test(body) ? 'json' : 'text';
  } else if (b && b.mode === 'urlencoded') {
    body = (b.urlencoded || []).filter(x => !x.disabled).map(x => `${encodeURIComponent(x.key)}=${encodeURIComponent(x.value ?? '')}`).join('&');
    bodyMode = 'text';
    if (!headers.some(h => h.key.toLowerCase() === 'content-type')) headers.push({ key: 'Content-Type', value: 'application/x-www-form-urlencoded', enabled: true });
  } else if (b && b.mode && b.mode !== 'none') {
    notes.add(`${b.mode} bodies are not supported`);
  }
  let auth = lc?.auth || acFromPostmanAuth(req.auth || inheritedAuth);
  if (!auth) { notes.add(`auth type ${(req.auth || inheritedAuth).type} is not supported`); auth = { type: 'none' }; }
  return { ...acBlankRequest(), kind: lc?.kind || 'custom', ref: lc?.ref || null, effect: lc?.effect || null,
    method: (req.method || 'GET').toUpperCase(), url, headers, bodyMode, body, auth };
}

async function acImportCollection(doc) {
  const items = [];
  const notes = new Set();
  const walk = (list, prefix, auth) => {
    for (const it of list) {
      if (Array.isArray(it.item)) walk(it.item, prefix ? `${prefix} / ${it.name}` : it.name, it.auth || auth);
      else if (it.request) {
        const name = prefix ? `${prefix} / ${it.name}` : it.name;
        const r = acFromPostmanRequest(typeof it.request === 'string' ? { url: it.request } : it.request, auth, it.lcHelper, notes);
        items.push({ id: acId(), name, request: { ...r, name } });
      }
    }
  };
  walk(doc.item, '', doc.auth);
  acState.collections.push({ id: acId(), name: doc.info.name || 'Imported', items });
  await acPersistCollections();

  // Collection variables: add the ones not defined yet (never overwrite yours or the built-ins).
  const base = acState.meta?.baseVars || {};
  const vars = await acApi('/api/console/vars');
  let added = 0;
  for (const v of doc.variable || []) {
    if (!v.key || v.key in base || v.key in vars.global || v.key in vars[acState.env]) continue;
    vars.global[v.key] = String(v.value ?? '');
    added++;
  }
  if (added) acState.vars = await acApi('/api/console/vars', { method: 'PUT', body: vars });

  acState.sideTab = 'collections';
  acState.open.add(`col:${acState.collections[acState.collections.length - 1].id}`);
  acRenderSide();
  showToast(`✅ Imported ${items.length} requests${added ? `, ${added} variables (global)` : ''}${notes.size ? ` — note: ${[...notes].join('; ')}` : ''}`);
}

async function acImportEnvironment(doc) {
  const env = acState.env;
  const vars = await acApi('/api/console/vars');
  let n = 0;
  for (const v of doc.values) {
    if (!v.key || v.enabled === false) continue;
    vars[env][v.key] = String(v.value ?? '');
    n++;
  }
  acState.vars = await acApi('/api/console/vars', { method: 'PUT', body: vars });
  showToast(`✅ Imported ${n} variables from “${doc.name || 'environment'}” into ${env}`);
}

// ── curl ──
async function acCopyCurl() {
  try {
    const { curl } = await acApi('/api/console/curl', { method: 'POST', body: { env: acState.env, request: acRequestPayload() } });
    acModal(`${acModalHead('Copy as curl')}
      <div class="ac-modal-body">
        <div class="ac-hint">Variables are filled in for ${escHtml(acState.env)}; credentials are <code>$PLACEHOLDERS</code> — export them in your shell first.</div>
        <pre class="code" style="white-space:pre-wrap;word-break:break-all;margin:0" id="acCurlText">${escHtml(curl)}</pre>
      </div>
      <div class="ac-modal-foot">${btnGhost('Close', 'acCloseModal()')}${btnPrimary('Copy', "copyText(document.getElementById('acCurlText').textContent)")}</div>`, { wide: true });
  } catch (e) { showToast(`❌ ${e.message}`); }
}
