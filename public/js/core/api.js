// ═════════════════════════════════════════════════════════════════════════
// ENV CONFIG (passwords + decrypt key from server .env)
// ═════════════════════════════════════════════════════════════════════════
let envConfig = null;
// Kept as a promise so INIT can wait for it before the first view renders —
// otherwise the first API calls go out with a stale/empty saved password.
const envConfigPromise = fetch('/api/env-config').then(r => r.json()).then(c => {
  envConfig = c;
  // Auto-fill password if a preset is selected and no password is set
  const cfg = getCfg();
  if (!cfg.pass) {
    const preset = document.getElementById('cfPreset')?.value;
    if (preset && envConfig?.passwords?.[preset]) {
      document.getElementById('cfPass').value = envConfig.passwords[preset];
    }
  }
}).catch(() => {});

// ── Praxis names cache (lcId → display name) ─────────────────────────────────
// Loaded once per env from praxis_config; ~100 rows, server caches for 5 min.
// Other views look up synchronously via praxisLabel(id).
window._praxisNames = {};
window._praxisNamesPromise = null;
function loadPraxisNames(force) {
  if (!force && window._praxisNamesPromise) return window._praxisNamesPromise;
  window._praxisNamesPromise = apiFetch('/api/praxis-names').then(r => {
    window._praxisNames = r.names || {};
    return window._praxisNames;
  }).catch(() => ({}));
  return window._praxisNamesPromise;
}
function praxisName(id)  { return (id && window._praxisNames[id]) || ''; }
function praxisLabel(id) { const n = praxisName(id); return n ? `${n} (${id})` : (id || '—'); }
// Kick off initial load — don't await; views render with raw IDs until names
// arrive. Waits for env-config first: the result promise is cached, so firing
// it with a not-yet-healed password would pin an empty name map.
envConfigPromise.then(() => loadPraxisNames());

// ═════════════════════════════════════════════════════════════════════════
// DB CONFIG
// ═════════════════════════════════════════════════════════════════════════
function getCfg() {
  const c = JSON.parse(localStorage.getItem('lc_db') || '{"host":"localhost","port":"8090","db":"lillian_care_core","user":"postgres","pass":""}');
  // Self-heal: a connection saved with an empty password (e.g. saved while
  // .env had no value for that env yet) picks up the password from
  // /api/env-config once loaded — matched to a preset by host+db. Without
  // this, every view keeps sending the stale empty password until the user
  // manually re-selects the preset and hits Connect.
  if (!c.pass && envConfig && envConfig.passwords) {
    const preset = Object.keys(PRESETS).find(k => PRESETS[k].host === c.host && PRESETS[k].db === c.db);
    if (preset && envConfig.passwords[preset]) {
      c.pass = envConfig.passwords[preset];
      try { localStorage.setItem('lc_db', JSON.stringify(c)); } catch {}
    }
  }
  return c;
}

function dbHeaders(extra = {}) {
  const c = getCfg();
  const env = document.getElementById('envBtn')?.dataset.env || 'dev';
  return { 'Content-Type': 'application/json', 'x-db-host': c.host, 'x-db-port': c.port, 'x-db-name': c.db, 'x-db-user': c.user, 'x-db-password': c.pass, 'x-env': env, ...extra };
}

async function apiFetch(path, opts = {}) {
  const res = await fetch(path, { headers: dbHeaders(), ...opts });
  return handleJsonResponse(res, path);
}

async function apiPost(path, body) {
  const res = await fetch(path, { method: 'POST', headers: dbHeaders(), body: JSON.stringify(body) });
  return handleJsonResponse(res, path);
}

async function apiPatch(path, body) {
  const res = await fetch(path, { method: 'PATCH', headers: dbHeaders(), body: JSON.stringify(body) });
  return handleJsonResponse(res, path);
}

async function handleJsonResponse(res, path) {
  const ct = res.headers.get('content-type') || '';
  const isJson = ct.includes('application/json');
  const body = isJson ? await res.json().catch(() => null) : await res.text().catch(() => '');
  if (!res.ok) {
    const msg = (isJson && body && body.error) ? body.error
              : (!isJson && typeof body === 'string' && body) ? body.slice(0, 200)
              : `HTTP ${res.status} ${res.statusText || ''}`.trim();
    throw new Error(`${msg}  [${path}]`);
  }
  return body;
}

let _envPasswords = null;
async function ensureEnvPasswords() {
  if (_envPasswords) return _envPasswords;
  const r = await fetch('/api/env-config');
  const d = await r.json();
  _envPasswords = d.passwords || {};
  return _envPasswords;
}

function envHeadersFor(envName, prefix = 'x-db-') {
  const preset = PRESETS[envName];
  if (!preset) throw new Error(`Unknown env: ${envName}`);
  const password = (_envPasswords && _envPasswords[envName]) || '';
  return {
    'Content-Type': 'application/json',
    [`${prefix}host`]: preset.host,
    [`${prefix}port`]: preset.port,
    [`${prefix}name`]: preset.db,
    [`${prefix}user`]: preset.user,
    [`${prefix}password`]: password,
  };
}
