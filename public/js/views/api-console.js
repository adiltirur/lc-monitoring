// ═════════════════════════════════════════════════════════════════════════
// API CONSOLE (#api-console) — Postman-like console for every Serverpod
// endpoint and every external call the backend makes. Backed by
// /api/console/* (routes/api-console.js): requests are sent by the helper
// server, which adds credentials and masks them in everything shown here.
//
// Files: api-console.js (state, layout, send) · -sidebar.js (catalog,
// collections, history) · -request.js (editor) · -response.js ·
// -panels.js (accounts, variables, save, prod confirm) · -postman.js (import/export, curl)
// ═════════════════════════════════════════════════════════════════════════

const AC_ENVS = ['dev', 'test', 'staging', 'production'];
const AC_DRAFT_KEY = 'lc_api_console_draft';

let acState = {
  env: 'dev',
  catalog: null,        // { serverpod: {endpoints, models, urls, counts}, externals: [] }
  meta: null,           // { authTypes, secrets, baseVars }
  accounts: [],
  collections: [],
  history: [],
  vars: null,
  sideTab: 'catalog',
  search: '',
  open: new Set(),      // expanded tree nodes
  req: null,            // the request in the editor (see acBlankRequest)
  reqTab: 'body',
  resp: null,
  respTab: 'body',
  pretty: true,
  sending: false,
};

function acBlankRequest() {
  return {
    name: 'Untitled request', kind: 'custom', ref: null,
    method: 'GET', url: '{{coreApi}}/', headers: [{ key: 'Accept', value: 'application/json', enabled: true }],
    bodyMode: 'none', body: '', auth: { type: 'none' }, effect: null, example: null,
  };
}

// Only the fields that describe a request (what history/collections store).
function acRequestPayload(r = acState.req) {
  return { name: r.name, kind: r.kind, ref: r.ref, method: r.method, url: r.url, headers: r.headers,
    bodyMode: r.bodyMode, body: r.body, auth: r.auth, effect: r.effect || null };
}

function acSaveDraft() {
  try { localStorage.setItem(AC_DRAFT_KEY, JSON.stringify({ env: acState.env, req: acRequestPayload() })); } catch { /* storage off */ }
}

function acLoadDraft() {
  try { return JSON.parse(localStorage.getItem(AC_DRAFT_KEY) || 'null'); } catch { return null; }
}

async function acApi(path, opts = {}) {
  const res = await fetch(path, {
    method: opts.method || 'GET',
    headers: opts.body !== undefined ? { 'Content-Type': 'application/json' } : {},
    body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok && !opts.raw) throw Object.assign(new Error(data.error || `HTTP ${res.status}`), { status: res.status, data });
  return opts.raw ? { status: res.status, data } : data;
}

async function renderApiConsole(el) {
  const globalEnv = document.documentElement.dataset.env;
  const draft = acLoadDraft();
  acState.env = AC_ENVS.includes(draft?.env) ? draft.env : AC_ENVS.includes(globalEnv) ? globalEnv : 'dev';
  if (!acState.req) acState.req = draft?.req ? { ...acBlankRequest(), ...draft.req } : acBlankRequest();

  el.innerHTML = `<div class="lc-view ac-view">
    ${pageHero('API Console', {
      sub: 'Every Serverpod endpoint, Principa, Personio, Brevo, FCM, Maps and the inbound webhooks. Sent by the helper server; credentials are added there and masked here.',
      actions: `<div class="ac-envs" id="acEnvs"></div>
        <button class="btn" onclick="acOpenVars()"><span class="material-symbols-outlined">data_object</span>Variables</button>
        <button class="btn" onclick="acOpenAccounts()"><span class="material-symbols-outlined">badge</span>Accounts</button>
        <button class="btn" onclick="acImportPick()"><span class="material-symbols-outlined">upload</span>Import</button>`,
    })}
    <div class="ac-grid">
      <div class="ac-col"><div class="panel ac-side" id="acSide">${loadingState('Reading LillianCare-Core…')}</div></div>
      <div class="ac-col" style="overflow:auto">
        <div class="panel ac-req" id="acReq"></div>
        <div class="panel ac-resp" id="acResp"></div>
      </div>
    </div>
    <input type="file" id="acImportFile" accept=".json,application/json" style="display:none" onchange="acImportFile(this)">
  </div>`;
  acRenderEnvs();
  acRenderRequest();
  acRenderResponse();
  try {
    const [catalog, collections, history, vars] = await Promise.all([
      acApi('/api/console/catalog'), acApi('/api/console/collections'), acApi('/api/console/history'), acApi('/api/console/vars'),
    ]);
    Object.assign(acState, { catalog, collections, history, vars });
    await acLoadEnv();
    acRenderSide();
  } catch (e) {
    document.getElementById('acSide').innerHTML = `<div class="panel-body">${errorState(e.message)}</div>`;
  }
}

// Meta (secret status, base URLs) and accounts depend on the env.
async function acLoadEnv() {
  const [meta, accounts] = await Promise.all([acApi(`/api/console/meta?env=${acState.env}`), acApi('/api/console/accounts')]);
  acState.meta = meta;
  acState.accounts = accounts;
  // A LillianCare account belongs to one env; follow the env switch.
  const a = acState.req.auth;
  if (a.type === 'core' && !accounts.some(x => x.id === a.accountId && x.env === acState.env)) {
    a.accountId = (accounts.find(x => x.env === acState.env) || {}).id || null;
  }
  acRenderRequest();
}

function acRenderEnvs() {
  const box = document.getElementById('acEnvs');
  if (!box) return;
  box.innerHTML = AC_ENVS.map((e, i) =>
    `<button data-env="${e}" class="${e === acState.env ? 'active' : ''}" onclick="acSetEnv('${e}')"><span class="num">${i + 1}</span>${e}</button>`).join('');
}

async function acSetEnv(env) {
  if (env === acState.env) return;
  acState.env = env;
  acSaveDraft();
  acRenderEnvs();
  try { await acLoadEnv(); } catch (e) { showToast(`❌ ${e.message}`); }
}

// ── send ──
async function acSend(confirm = null) {
  if (acState.sending) return;
  const r = acState.req;
  acState.sending = true;
  acState.resp = { pending: true };
  acRenderRequest();
  acRenderResponse();
  try {
    const { status, data } = await acApi('/api/console/send', {
      method: 'POST', raw: true,
      body: { env: acState.env, request: acRequestPayload(r), confirm },
    });
    if (status === 428 && data.needsConfirm) {
      acState.sending = false;
      acState.resp = null;
      acRenderRequest();
      acRenderResponse();
      acConfirmProduction();
      return;
    }
    acState.resp = status >= 400 && !data.status ? { failed: true, ...data } : data;
    if (data.missing && data.missing.length) acState.respTab = 'console';
    else if (data.networkError) acState.respTab = 'console';
    else if (acState.respTab === 'request') acState.respTab = 'body';
  } catch (e) {
    acState.resp = { failed: true, error: e.message, trace: [] };
  }
  acState.sending = false;
  acRenderRequest();
  acRenderResponse();
  acRefreshHistory();
}

async function acRefreshHistory() {
  try {
    acState.history = await acApi('/api/console/history');
    if (acState.sideTab === 'history') acRenderSide();
  } catch { /* not critical */ }
}

// ⌘/Ctrl+Enter sends while the console is open.
document.addEventListener('keydown', (e) => {
  if (window.__currentView !== 'api-console') return;
  if ((e.metaKey || e.ctrlKey) && e.key === 'Enter') { e.preventDefault(); acSend(); }
});
