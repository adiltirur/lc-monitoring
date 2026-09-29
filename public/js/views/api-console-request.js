// API console — request editor: URL bar, Params / Headers / Body / Auth / Docs.
// Inputs write straight into acState.req (no re-render while typing, so focus stays).

const AC_METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'];

function acRenderRequest() {
  const el = document.getElementById('acReq');
  if (!el || !acState.req) return;
  const r = acState.req;
  const tabs = [
    ['params', `Params${acQueryPairs(r.url).length ? ` <span class="pill">${acQueryPairs(r.url).length}</span>` : ''}`],
    ['headers', `Headers <span class="pill">${r.headers.filter(h => h.enabled !== false && h.key).length}</span>`],
    ['body', `Body${r.bodyMode !== 'none' ? ' <span class="dot ok"></span>' : ''}`],
    ['auth', `Auth <span class="pill">${escHtml(acAuthLabel(r.auth.type))}</span>`],
    ['docs', 'Docs'],
  ];
  el.innerHTML = `
    <div class="ac-req-head">
      ${r.kind === 'serverpod' ? '<span class="pill info">Serverpod</span>' : r.kind === 'external' ? '<span class="pill">External</span>' : '<span class="pill ghost">Custom</span>'}
      <input class="ac-name" value="${escHtml(r.name)}" oninput="acState.req.name=this.value;acSaveDraft()" spellcheck="false">
      <button class="btn btn-sm" onclick="acCopyCurl()" title="Copy as curl (secrets as $VARIABLES)"><span class="material-symbols-outlined">terminal</span>curl</button>
      <button class="btn btn-sm" onclick="acOpenSave()" title="Save to a collection"><span class="material-symbols-outlined">bookmark_add</span>Save</button>
      <button class="btn btn-sm" onclick="acNewRequest()" title="New blank request"><span class="material-symbols-outlined">add</span>New</button>
    </div>
    <div class="ac-urlbar">
      <select class="lc-select" onchange="acSetMethod(this.value)">${AC_METHODS.map(m => `<option ${m === r.method ? 'selected' : ''}>${m}</option>`).join('')}</select>
      <input class="lc-input" id="acUrl" value="${escHtml(r.url)}" spellcheck="false" oninput="acSetUrl(this.value)"
        onkeydown="if(event.key==='Enter'&&!event.metaKey&&!event.ctrlKey)acSend()" placeholder="{{coreApi}}/endpoint/method">
      <button class="btn btn-primary" onclick="acSend()" ${acState.sending ? 'disabled' : ''}>
        <span class="material-symbols-outlined ${acState.sending ? 'spin' : ''}">${acState.sending ? 'progress_activity' : 'send'}</span>Send <span class="kbd">⌘↵</span></button>
    </div>
    ${acWarningHtml()}
    <div class="lc-tabs">${tabs.map(([k, l]) => `<button class="lc-tab ${acState.reqTab === k ? 'active' : ''}" onclick="acReqTab('${k}')">${l}</button>`).join('')}</div>
    <div class="ac-pane" id="acReqPane"></div>`;
  acRenderReqPane();
}

function acWarningHtml() {
  const r = acState.req;
  if (acState.env === 'production') {
    const guarded = r.kind === 'serverpod' || !['GET', 'HEAD'].includes(r.method);
    return `<div class="ac-warn prod"><span class="material-symbols-outlined">warning</span>PRODUCTION${guarded ? ' — you will be asked to type "production" before this is sent.' : ' — read-only request.'}${r.effect === 'sends' ? ' This reaches real patients.' : ''}</div>`;
  }
  if (r.effect === 'sends') return `<div class="ac-warn"><span class="material-symbols-outlined">outgoing_mail</span>Sends a real email / SMS / push to whoever the body names.</div>`;
  if (r.effect === 'write') return `<div class="ac-warn"><span class="material-symbols-outlined">edit_note</span>Changes data on ${escHtml(acState.env)}${r.url.includes('{{principa') ? ' (Principa is shared by dev, test and staging)' : ''}.</div>`;
  return '';
}

function acReqTab(tab) {
  acState.reqTab = tab;
  acRenderRequest();
}

function acNewRequest() {
  acState.req = acBlankRequest();
  acState.reqTab = 'params';
  acAfterOpen();
}

function acSetMethod(m) {
  acState.req.method = m;
  if (['GET', 'HEAD'].includes(m) && acState.req.bodyMode !== 'none') showToast('GET/HEAD requests are sent without a body');
  acSaveDraft();
  acRenderRequest();
}

function acSetUrl(v) {
  acState.req.url = v;
  acSaveDraft();
  if (acState.reqTab === 'params') acRenderReqPane();
}

function acAuthLabel(type) {
  return ((acState.meta?.authTypes || []).find(t => t.id === type) || { label: type }).label;
}

function acRenderReqPane() {
  const el = document.getElementById('acReqPane');
  if (!el) return;
  const t = acState.reqTab;
  el.innerHTML = t === 'params' ? acParamsHtml() : t === 'headers' ? acHeadersHtml() : t === 'body' ? acBodyHtml() : t === 'auth' ? acAuthHtml() : acDocsHtml();
}

// ── params (the URL's query string) ──
function acQueryPairs(url) {
  const i = url.indexOf('?');
  if (i < 0) return [];
  return url.slice(i + 1).split('&').filter(Boolean).map(p => {
    const j = p.indexOf('=');
    return j < 0 ? [p, ''] : [p.slice(0, j), p.slice(j + 1)];
  });
}

function acParamsHtml() {
  const pairs = acQueryPairs(acState.req.url);
  return `<table class="ac-kv">${pairs.map(([k, v], i) => `<tr><td></td>
      <td><input class="lc-input" value="${escHtml(k)}" oninput="acSetParam(${i},0,this.value)" placeholder="key"></td>
      <td><input class="lc-input" value="${escHtml(v)}" oninput="acSetParam(${i},1,this.value)" placeholder="value"></td>
      <td><button class="lc-icon-btn" onclick="acDelParam(${i})" title="Remove"><span class="material-symbols-outlined">close</span></button></td></tr>`).join('')}
    </table>
    <div class="ac-row" style="margin-top:8px"><button class="btn btn-sm" onclick="acAddParam()"><span class="material-symbols-outlined">add</span>Add param</button>
    <span class="ac-hint">Values are sent as typed — encode special characters yourself (e.g. <code>%7C</code> for |). <code>{{variables}}</code> work everywhere.</span></div>`;
}

function acWriteParams(pairs) {
  const base = acState.req.url.split('?')[0];
  acState.req.url = pairs.length ? `${base}?${pairs.map(([k, v]) => (v === '' && !k ? '' : `${k}=${v}`)).join('&')}` : base;
  const u = document.getElementById('acUrl');
  if (u) u.value = acState.req.url;
  acSaveDraft();
}
function acSetParam(i, part, value) { const p = acQueryPairs(acState.req.url); p[i][part] = value; acWriteParams(p); }
function acDelParam(i) { const p = acQueryPairs(acState.req.url); p.splice(i, 1); acWriteParams(p); acRenderRequest(); }
function acAddParam() { const p = acQueryPairs(acState.req.url); p.push(['', '']); acWriteParams(p); acRenderReqPane(); }

// ── headers ──
function acHeadersHtml() {
  const h = acState.req.headers;
  return `<table class="ac-kv">${h.map((x, i) => `<tr class="${x.enabled === false ? 'off' : ''}">
      <td><input type="checkbox" ${x.enabled !== false ? 'checked' : ''} onchange="acState.req.headers[${i}].enabled=this.checked;acSaveDraft();this.closest('tr').classList.toggle('off',!this.checked)"></td>
      <td><input class="lc-input" value="${escHtml(x.key)}" oninput="acState.req.headers[${i}].key=this.value;acSaveDraft()" placeholder="Header"></td>
      <td><input class="lc-input" value="${escHtml(x.value)}" oninput="acState.req.headers[${i}].value=this.value;acSaveDraft()" placeholder="value"></td>
      <td><button class="lc-icon-btn" onclick="acState.req.headers.splice(${i},1);acSaveDraft();acRenderRequest()" title="Remove"><span class="material-symbols-outlined">close</span></button></td></tr>`).join('')}
    </table>
    <div class="ac-row" style="margin-top:8px"><button class="btn btn-sm" onclick="acState.req.headers.push({key:'',value:'',enabled:true});acRenderReqPane()"><span class="material-symbols-outlined">add</span>Add header</button>
    <span class="ac-hint">Auth headers are added by the server (Auth tab). <code>User-Agent</code>, <code>Accept</code> and <code>Content-Length</code> are filled in when missing; the Request tab of the response shows exactly what went out.</span></div>`;
}

// ── body ──
function acBodyHtml() {
  const r = acState.req;
  const modes = [['none', 'None'], ['json', 'JSON'], ['text', 'Text']];
  const noBody = ['GET', 'HEAD'].includes(r.method);
  return `<div class="ac-row space" style="margin-bottom:8px">
      <div class="ac-seg">${modes.map(([k, l]) => `<button class="${r.bodyMode === k ? 'active' : ''}" onclick="acSetBodyMode('${k}')">${l}</button>`).join('')}</div>
      <div class="ac-row">
        ${r.bodyMode === 'json' ? `<button class="btn btn-sm" onclick="acFormatBody()"><span class="material-symbols-outlined">format_align_left</span>Format</button>` : ''}
        ${r.example ? `<button class="btn btn-sm" onclick="acResetBody()" title="Back to the generated example"><span class="material-symbols-outlined">restart_alt</span>Example</button>` : ''}
      </div>
    </div>
    ${noBody && r.bodyMode !== 'none' ? `<div class="ac-hint" style="margin-bottom:6px">${r.method} requests are sent without a body.</div>` : ''}
    ${r.bodyMode === 'none' ? `<div class="ac-hint">No body.</div>` : `<textarea class="lc-textarea" id="acBody" spellcheck="false"
      oninput="acState.req.body=this.value;acSaveDraft()" onkeydown="acBodyKey(event)">${escHtml(r.body)}</textarea>`}
    ${r.kind === 'serverpod' ? `<div class="ac-hint" style="margin-top:6px">Serverpod: one JSON object keyed by parameter name. DateTime = ISO string (UTC), Duration = ms, enums as index or name (see Docs). Missing non-nullable params → HTTP 400.</div>` : ''}`;
}

function acSetBodyMode(mode) {
  acState.req.bodyMode = mode;
  const has = (n) => acState.req.headers.some(h => h.key.toLowerCase() === n);
  if (mode === 'json' && !has('content-type') && acState.req.kind !== 'serverpod') acState.req.headers.push({ key: 'Content-Type', value: 'application/json', enabled: true });
  acSaveDraft();
  acRenderRequest();
}

function acFormatBody() {
  try {
    acState.req.body = JSON.stringify(JSON.parse(acState.req.body), null, 2);
    acSaveDraft();
    acRenderReqPane();
  } catch (e) { showToast(`❌ Not valid JSON: ${e.message}`); }
}

function acResetBody() {
  acState.req.body = acState.req.example || '';
  acSaveDraft();
  acRenderReqPane();
}

// Tab inserts two spaces in the body editor.
function acBodyKey(e) {
  if (e.key !== 'Tab') return;
  e.preventDefault();
  const t = e.target, s = t.selectionStart;
  t.value = t.value.slice(0, s) + '  ' + t.value.slice(t.selectionEnd);
  t.selectionStart = t.selectionEnd = s + 2;
  acState.req.body = t.value;
  acSaveDraft();
}

// ── auth ──
function acAuthHtml() {
  const a = acState.req.auth;
  const types = acState.meta?.authTypes || [];
  const def = types.find(t => t.id === a.type) || {};
  const secrets = acState.meta?.secrets || {};
  let fields = '';
  if (a.type === 'core') {
    const list = acState.accounts.filter(x => x.env === acState.env);
    const acc = list.find(x => x.id === a.accountId);
    fields = list.length ? `<div class="ac-row" style="align-items:end">
        <div class="field" style="min-width:280px">${fLabel(`Account (${acState.env})`)}
          <select class="lc-select" onchange="acState.req.auth.accountId=this.value;acSaveDraft();acRenderReqPane()">
            ${list.map(x => `<option value="${x.id}" ${x.id === a.accountId ? 'selected' : ''}>${escHtml(x.label)} — ${escHtml(x.email)}</option>`).join('')}
          </select></div>
        ${acc ? `<button class="btn" onclick="acLoginAccount('${acc.id}')"><span class="material-symbols-outlined">login</span>Log in now</button>` : ''}
        <button class="btn" onclick="acOpenAccounts()"><span class="material-symbols-outlined">badge</span>Manage</button>
      </div>
      ${acc && acc.session ? `<div class="ac-hint" style="margin-top:8px">Session cached: authUserId <code>${escHtml(acc.session.authUserId || '')}</code>, scopes <code>${escHtml((acc.session.scopeNames || []).join(', ') || '—')}</code>. A 401 logs in again automatically.</div>`
        : `<div class="ac-hint" style="margin-top:8px">Logs in on the first request and reuses the session token.</div>`}`
      : `<div class="ac-row"><span class="ac-hint">No LillianCare account for ${escHtml(acState.env)} yet.</span>
         <button class="btn btn-primary" onclick="acOpenAccounts()"><span class="material-symbols-outlined">person_add</span>Add account</button></div>`;
  } else if (def.fields) {
    fields = `<div class="ac-row">${def.fields.map(f => `<div class="field" style="flex:1;min-width:200px">${fLabel(f)}
      <input class="lc-input mono" ${f === 'password' ? 'type="password"' : ''} value="${escHtml(a[f] || '')}" oninput="acState.req.auth['${f}']=this.value;acSaveDraft()"></div>`).join('')}</div>
      <div class="ac-hint" style="margin-top:6px">Typed values are kept with the request (history, collections) in <code>.api-console/</code> on this Mac.</div>`;
  } else if (a.type !== 'none') {
    const ok = secrets[a.type];
    fields = `<div class="ac-hint">${ok ? '<span class="pill ok">configured</span>' : '<span class="pill err">missing</span>'} &nbsp;${escHtml(def.detail || '')}</div>
      ${ok ? '' : `<div class="ac-hint" style="margin-top:6px">Add the key to <code>helper/.env</code> (see <code>.env.example</code>) and restart the helper server.</div>`}`;
  }
  return `<div class="field" style="max-width:360px;margin-bottom:12px">${fLabel('Type')}
      <select class="lc-select" onchange="acSetAuthType(this.value)">${types.map(t => `<option value="${t.id}" ${t.id === a.type ? 'selected' : ''}>${escHtml(t.label)}${secrets[t.id] === false && !t.fields && t.id !== 'none' ? ' (not configured)' : ''}</option>`).join('')}</select></div>
    ${def.detail && a.type === 'core' ? `<div class="ac-hint" style="margin-bottom:10px">${escHtml(def.detail)}</div>` : ''}
    ${fields}`;
}

function acSetAuthType(type) {
  acState.req.auth = { type };
  if (type === 'core') acState.req.auth.accountId = (acState.accounts.find(a => a.env === acState.env) || {}).id || null;
  acSaveDraft();
  acRenderRequest();
}

// ── docs ──
function acDocsHtml() {
  const r = acState.req;
  if (r.kind === 'serverpod' && r.ref) {
    const ep = acState.catalog?.serverpod.endpoints.find(e => e.name === r.ref.endpoint);
    const m = ep && ep.methods.find(x => x.name === r.ref.method);
    if (!m) return `<div class="ac-hint">Method not in the current catalog.</div>`;
    const models = acState.catalog.serverpod.models;
    return `<div class="ac-docs">
      <h4>Method</h4>
      <div><span class="mono">POST {{coreApi}}/${escHtml(ep.name)}/${escHtml(m.name)}</span> → <span class="mono">${escHtml(m.returns || '?')}</span></div>
      <div style="margin-top:4px">${ep.requireLogin ? '<span class="pill warn">requireLogin</span>' : ep.module ? `<span class="pill">module ${escHtml(ep.module)}</span>` : '<span class="pill">no login required</span>'}
        ${ep.source ? `<span class="ac-hint">&nbsp; ${escHtml(ep.source)}</span>` : ''}</div>
      ${m.doc ? `<pre class="ac-hint" style="margin-top:8px">${escHtml(m.doc)}</pre>` : ''}
      <h4>Parameters</h4>
      ${m.params.length ? `<table><tr><th>Name</th><th>Type</th><th></th></tr>${m.params.map(p => `<tr><td class="mono">${escHtml(p.name)}</td><td class="mono">${escHtml(p.type)}</td><td>${p.nullable ? 'optional' : '<b>required</b>'}</td></tr>`).join('')}</table>` : '<div class="ac-hint">None — send <code>{}</code>.</div>'}
      ${acModelDocs([...m.types, ...(m.returns ? (m.returns.match(/\b[A-Z]\w+/g) || []) : [])], models)}
      <h4>Permissions</h4>
      <div class="ac-hint">Most admin methods check permissions inside the method (<code>session.checkPermission</code>); a failure is HTTP 400 with <code>errorCode 7</code>, not 403.</div>
    </div>`;
  }
  if (r.kind === 'external' && r.ref) {
    const t = acState.catalog?.externals.find(x => x.id === r.ref.extId);
    if (!t) return `<div class="ac-hint">Template not in the current catalog.</div>`;
    return `<div class="ac-docs">
      <h4>${escHtml(t.group)}</h4>
      <div><span class="mono">${escHtml(t.method)} ${escHtml(t.url)}</span></div>
      <div style="margin-top:6px">${t.effect === 'sends' ? '<span class="pill err">sends</span>' : t.effect === 'write' ? '<span class="pill warn">writes</span>' : '<span class="pill ok">read</span>'}
        ${t.usedByBackend ? '<span class="pill info">used by the backend</span>' : '<span class="pill">debug extra</span>'}
        <span class="pill">auth: ${escHtml(acAuthLabel(t.auth))}</span></div>
      ${t.doc ? `<p style="margin-top:10px">${escHtml(t.doc)}</p>` : ''}
      ${t.source ? `<h4>Call site</h4><div class="mono">${escHtml(t.source)}</div>` : ''}
      <h4>Variables</h4><div class="ac-hint">${acVarsIn(r).map(v => `<code>{{${escHtml(v)}}}</code>`).join(' ') || 'none'}</div>
    </div>`;
  }
  return `<div class="ac-docs"><div class="ac-hint">Custom request. Variables in use: ${acVarsIn(r).map(v => `<code>{{${escHtml(v)}}}</code>`).join(' ') || 'none'}.</div></div>`;
}

function acVarsIn(r) {
  const text = [r.url, r.body, ...r.headers.map(h => `${h.key} ${h.value}`)].join(' ');
  return [...new Set([...text.matchAll(/\{\{\s*([$\w.-]+)\s*\}\}/g)].map(m => m[1]))];
}

function acModelDocs(names, models, seen = new Set()) {
  let html = '';
  for (const n of names) {
    if (seen.has(n) || !models[n]) continue;
    seen.add(n);
    const m = models[n];
    if (m.kind === 'enum') {
      html += `<h4>enum ${escHtml(n)} <span class="pill">${m.serialized === 'byIndex' ? 'sent as index' : 'sent as name'}</span></h4>
        <div class="mono" style="font-size:12px">${m.values.map((v, i) => `${m.serialized === 'byIndex' ? `${i}=` : ''}${escHtml(v)}`).join(' · ')}</div>`;
    } else {
      html += `<h4>${escHtml(n)}</h4><table>${(m.fields || []).map(f => `<tr><td class="mono">${escHtml(f.name)}</td><td class="mono">${escHtml(f.type)}</td></tr>`).join('')}</table>`;
      const nested = (m.fields || []).flatMap(f => f.type.match(/\b[A-Z]\w+/g) || []);
      html += acModelDocs(nested, models, seen);
    }
  }
  return html;
}
