// API console: environments, variables and auth. Everything secret is resolved
// here, server-side; the browser only ever names an auth type (and an account id).
//
// Secrets (helper .env):
//   principa   PMS_SECRET_TEST (dev/test/staging), PMS_SECRET_PROD
//              base URL: PMS_BASE_URL_DEV|TEST|STAGING|PROD, else the backend's hard-coded hosts
//   personio   PERSONIO_CLIENT_ID + PERSONIO_CLIENT_SECRET
//   fcm        .fcm_service_account.json (the Send Notification view manages it)
//   brevo      BREVO_API_KEY
//   maps       GOOGLE_MAPS_API_KEY
//   lilli      LILLI_SSO_SECRET_DEV|TEST|STAGING|PROD   (the backend's ssoSecret)
//   coreApiKey LC_API_KEY_DEV|TEST|STAGING|PROD         (a row of core_api_keys)
//   core       email/password accounts in .api-console/accounts.json
const path = require('path');
const crypto = require('crypto');
const { GoogleAuth } = require('google-auth-library');
const { pmsJwt, pmsJwtInvalidate } = require('../pms');
const { getPersonioToken, setPersonioToken, clearPersonioToken } = require('../personio');
const { serverUrls } = require('./catalog');
const store = require('./store');

const ROOT = path.join(__dirname, '..', '..'); // helper/
const FCM_KEY_FILE = path.join(ROOT, '.fcm_service_account.json');
const ENV_SUFFIX = { dev: 'DEV', test: 'TEST', staging: 'STAGING', production: 'PROD' };

// Hosts from LillianCare-Core fhir_api_caller.dart / rest_api_caller.dart.
const PRINCIPA_DEFAULT = { nonProd: 'http://172.16.2.20:8080/fhir4/', prod: 'https://principa.aws.lillian-care.de/fhir4/' };

const envVar = (name) => (process.env[name] || '').trim();

function principaFhirBase(env) {
  const s = ENV_SUFFIX[env];
  const v = envVar(`PMS_BASE_URL_${s}`) || (env === 'test' ? envVar('PMS_BASE_URL_STAGING') : '')
    || (env === 'production' ? PRINCIPA_DEFAULT.prod : PRINCIPA_DEFAULT.nonProd);
  return v.endsWith('/') ? v : v + '/';
}

function principaSecretName(env) { return env === 'production' ? 'PMS_SECRET_PROD' : 'PMS_SECRET_TEST'; }

// ── variables ──
let fcmAuth = null;
let fcmProject = null;
function fcmClient() {
  if (!fcmAuth) fcmAuth = new GoogleAuth({ keyFile: FCM_KEY_FILE, scopes: ['https://www.googleapis.com/auth/firebase.messaging'] });
  return fcmAuth;
}
async function fcmProjectId() {
  if (fcmProject) return fcmProject;
  try { fcmProject = await fcmClient().getProjectId(); } catch { return null; }
  return fcmProject;
}

async function baseVars(env) {
  const urls = serverUrls()[env] || {};
  const fhir = principaFhirBase(env);
  const project = await fcmProjectId();
  return {
    coreApi: urls.coreApi || '',
    coreWeb: urls.coreWeb || '',
    principaFhir: fhir,
    principaRest: fhir.replace(/fhir4\/$/, 'rest/'),
    personio: 'https://api.personio.de/v1',
    brevo: 'https://api.brevo.com/v3',
    fcm: `https://fcm.googleapis.com/v1/projects/${project || '<no .fcm_service_account.json>'}`,
    maps: 'https://maps.googleapis.com/maps/api',
    holidays: 'https://feiertage-api.de/api',
  };
}

function dynamicVars() {
  const now = new Date();
  const day = (d) => new Date(now.getTime() + d * 86400000).toISOString().slice(0, 10);
  return {
    $isoTimestamp: now.toISOString(),
    $timestamp: String(Math.floor(now.getTime() / 1000)),
    $guid: crypto.randomUUID(),
    $randomInt: String(Math.floor(Math.random() * 1000)),
    $date: day(0),
    $datePlus7: day(7),
    $datePlus30: day(30),
    $year: String(now.getFullYear()),
  };
}

// Precedence: dynamic < env base URLs < global user vars < env user vars.
async function allVars(env) {
  const user = store.vars();
  return { ...dynamicVars(), ...(await baseVars(env)), ...user.global, ...user[env] };
}

// Replace {{name}}; collects names with no value.
function substitute(text, vars, missing) {
  if (typeof text !== 'string') return text;
  return text.replace(/\{\{\s*([$\w.-]+)\s*\}\}/g, (m, name) => {
    if (Object.prototype.hasOwnProperty.call(vars, name)) return vars[name];
    missing.add(name);
    return m;
  });
}

// ── auth types (metadata for the UI) ──
const AUTH_TYPES = [
  { id: 'none', label: 'No auth' },
  { id: 'core', label: 'LillianCare login', detail: 'Email/password account → POST /emailIdp/login → Authorization: Bearer <session token>' },
  { id: 'coreApiKey', label: 'Core api-key', detail: 'api-key: LC_API_KEY_<ENV> (a core_api_keys row; used by Principa for /fhir/*)' },
  { id: 'principa', label: 'Principa JWT', detail: 'Authorization: Bearer <HS256 JWT signed with PMS_SECRET_TEST / PMS_SECRET_PROD, iat+exp only, 10 min>' },
  { id: 'personio', label: 'Personio', detail: 'client_credentials → POST /v1/auth; token rotates via the authorization response header' },
  { id: 'fcm', label: 'Google service account (FCM)', detail: 'OAuth access token from .fcm_service_account.json, scope firebase.messaging' },
  { id: 'brevo', label: 'Brevo api-key', detail: 'api-key: BREVO_API_KEY' },
  { id: 'maps', label: 'Google Maps key', detail: '?key=GOOGLE_MAPS_API_KEY' },
  { id: 'lilli', label: 'Lilli secret', detail: 'X-Lilli-Secret: LILLI_SSO_SECRET_<ENV>' },
  { id: 'bearer', label: 'Bearer token', fields: ['token'] },
  { id: 'basic', label: 'Basic auth', fields: ['username', 'password'] },
  { id: 'header', label: 'Custom header', fields: ['name', 'value'] },
];

function secretStatus(env) {
  const s = ENV_SUFFIX[env];
  return {
    principa: !!envVar(principaSecretName(env)),
    personio: !!(envVar('PERSONIO_CLIENT_ID') && envVar('PERSONIO_CLIENT_SECRET')),
    fcm: require('fs').existsSync(FCM_KEY_FILE),
    brevo: !!envVar('BREVO_API_KEY'),
    maps: !!envVar('GOOGLE_MAPS_API_KEY'),
    lilli: !!envVar(`LILLI_SSO_SECRET_${s}`),
    coreApiKey: !!envVar(`LC_API_KEY_${s}`),
    core: store.accounts().some(a => a.env === env),
  };
}

function need(name) {
  const v = envVar(name);
  if (!v) throw Object.assign(new Error(`${name} is not set in helper/.env`), { status: 400 });
  return v;
}

// ── LillianCare (Serverpod) login ──
const sessions = new Map(); // `${env}:${accountId}` → { token, authUserId, scopeNames, at }

async function coreLogin(env, acc, trace, { force = false } = {}) {
  const key = `${env}:${acc.id}`;
  if (!force && sessions.has(key)) {
    const s = sessions.get(key);
    trace('auth', `Using cached session for ${acc.email} (logged in ${Math.round((Date.now() - s.at) / 60000)} min ago, scopes: ${s.scopeNames.join(', ') || '—'})`);
    return s.token;
  }
  if (!acc.password) throw Object.assign(new Error(`Account ${acc.email} has no password saved`), { status: 400 });
  const base = (await baseVars(env)).coreApi;
  const url = `${base}/emailIdp/login`;
  trace('auth', `POST ${url} as ${acc.email}`);
  const t0 = Date.now();
  let res;
  try {
    res = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
      body: JSON.stringify({ email: acc.email, password: acc.password }),
      signal: AbortSignal.timeout(20000),
    });
  } catch (e) {
    throw Object.assign(new Error(`Login request failed: ${e.cause?.code || e.message}`), { status: 502 });
  }
  const text = await res.text();
  let j = null;
  try { j = JSON.parse(text); } catch { /* not JSON */ }
  if (!res.ok || !j || !j.token) {
    const msg = j?.data?.message || j?.message || text.slice(0, 300) || res.statusText;
    trace('error', `Login failed: HTTP ${res.status} — ${msg}`);
    throw Object.assign(new Error(`Login as ${acc.email} failed: HTTP ${res.status} — ${msg}`), { status: 401 });
  }
  const s = { token: j.token, authUserId: j.authUserId, scopeNames: j.scopeNames || [], expiresAt: j.tokenExpiresAt || null, at: Date.now() };
  sessions.set(key, s);
  trace('auth', `Logged in (${Date.now() - t0} ms): authUserId ${s.authUserId}, scopes: ${s.scopeNames.join(', ') || '—'}${s.expiresAt ? `, expires ${s.expiresAt}` : ''}`);
  return s.token;
}

function sessionInfo(env, accountId) {
  const s = sessions.get(`${env}:${accountId}`);
  return s ? { authUserId: s.authUserId, scopeNames: s.scopeNames, expiresAt: s.expiresAt, loggedInAt: new Date(s.at).toISOString() } : null;
}
function dropSession(env, accountId) { sessions.delete(`${env}:${accountId}`); }

// ── apply auth to an outgoing request ──
// req: { method, url: URL, headers: {} }. `mask(value, label)` registers a secret so it
// is replaced by ‹label› everywhere it would be shown. Returns hooks:
//   refresh()        → true if new credentials were fetched (caller retries once on 401)
//   afterResponse(r) → e.g. Personio token rotation
async function applyAuth(auth, env, req, trace, mask) {
  const type = (auth && auth.type) || 'none';
  const hooks = { refresh: async () => false, afterResponse: () => {} };
  const setHeader = (name, value) => {
    for (const k of Object.keys(req.headers)) if (k.toLowerCase() === name.toLowerCase()) delete req.headers[k];
    req.headers[name] = value;
  };
  switch (type) {
    case 'none':
      return hooks;
    case 'bearer':
      if (!auth.token) throw Object.assign(new Error('Bearer token is empty'), { status: 400 });
      mask(auth.token, 'token');
      setHeader('Authorization', `Bearer ${auth.token}`);
      return hooks;
    case 'basic':
      mask(auth.password || '', 'password');
      mask(Buffer.from(`${auth.username || ''}:${auth.password || ''}`).toString('base64'), 'basic credentials');
      setHeader('Authorization', `Basic ${Buffer.from(`${auth.username || ''}:${auth.password || ''}`).toString('base64')}`);
      return hooks;
    case 'header':
      if (!auth.name) throw Object.assign(new Error('Custom auth header name is empty'), { status: 400 });
      mask(auth.value || '', auth.name);
      setHeader(auth.name, auth.value || '');
      return hooks;
    case 'core': {
      const acc = store.account(auth.accountId);
      if (!acc) throw Object.assign(new Error('Pick a LillianCare account (Auth tab)'), { status: 400 });
      if (acc.env !== env) throw Object.assign(new Error(`Account ${acc.email} belongs to ${acc.env}, not ${env}`), { status: 400 });
      const put = (token) => { mask(token, 'session token'); setHeader('Authorization', `Bearer ${token}`); };
      put(await coreLogin(env, acc, trace));
      hooks.refresh = async () => { dropSession(env, acc.id); put(await coreLogin(env, acc, trace, { force: true })); return true; };
      return hooks;
    }
    case 'principa': {
      const name = principaSecretName(env);
      const secret = need(name);
      const put = () => {
        const jwt = pmsJwt(secret);
        mask(jwt, 'principa jwt');
        const claims = JSON.parse(Buffer.from(jwt.split('.')[1], 'base64url').toString());
        trace('auth', `Principa JWT (HS256, ${name}): iat ${new Date(claims.iat * 1000).toISOString()}, exp in ${claims.exp - Math.floor(Date.now() / 1000)} s`);
        setHeader('Authorization', `Bearer ${jwt}`);
      };
      put();
      hooks.refresh = async () => { pmsJwtInvalidate(secret); trace('auth', 'Principa answered 401 — minting a fresh JWT'); put(); return true; };
      return hooks;
    }
    case 'personio': {
      const put = async () => {
        const t = await getPersonioToken();
        mask(t, 'personio token');
        setHeader('Authorization', `Bearer ${t}`);
      };
      trace('auth', 'Personio token via client_credentials (PERSONIO_CLIENT_ID), cached up to 25 min');
      await put();
      hooks.refresh = async () => { clearPersonioToken(); trace('auth', 'Personio answered 401 — requesting a new token'); await put(); return true; };
      hooks.afterResponse = (headers) => {
        const rotated = headers.authorization;
        if (rotated) {
          const t = String(rotated).replace(/^Bearer\s+/i, '');
          mask(t, 'personio token (rotated)');
          setPersonioToken(t);
          trace('auth', 'Personio rotated the token (authorization response header) — cache updated');
        }
      };
      return hooks;
    }
    case 'fcm': {
      if (!require('fs').existsSync(FCM_KEY_FILE)) throw Object.assign(new Error('No .fcm_service_account.json — upload it in Send Notification'), { status: 400 });
      const token = await fcmClient().getAccessToken();
      if (!token) throw Object.assign(new Error('Google did not return an access token'), { status: 502 });
      mask(token, 'google access token');
      trace('auth', `Google OAuth access token from service account (project ${await fcmProjectId()}, scope firebase.messaging)`);
      setHeader('Authorization', `Bearer ${token}`);
      return hooks;
    }
    case 'brevo': {
      const key = need('BREVO_API_KEY');
      mask(key, 'BREVO_API_KEY');
      setHeader('api-key', key);
      return hooks;
    }
    case 'maps': {
      const key = need('GOOGLE_MAPS_API_KEY');
      mask(key, 'GOOGLE_MAPS_API_KEY');
      req.url.searchParams.set('key', key);
      return hooks;
    }
    case 'lilli': {
      const name = `LILLI_SSO_SECRET_${ENV_SUFFIX[env]}`;
      const v = need(name);
      mask(v, name);
      setHeader('X-Lilli-Secret', v);
      return hooks;
    }
    case 'coreApiKey': {
      const name = `LC_API_KEY_${ENV_SUFFIX[env]}`;
      const v = need(name);
      mask(v, name);
      setHeader('api-key', v);
      return hooks;
    }
    default:
      throw Object.assign(new Error(`Unknown auth type ${type}`), { status: 400 });
  }
}

// Credentials the server adds may only go to the service they belong to, so a typo
// or an edited URL can't hand e.g. the Principa prod secret to another host.
// `vars` are the resolved variables, so overriding {{principaFhir}} moves the target too.
const CREDENTIAL_TARGETS = {
  principa: ['principaFhir', 'principaRest'], personio: ['personio'], fcm: ['fcm'], brevo: ['brevo'], maps: ['maps'],
  lilli: ['coreWeb', 'coreApi'], coreApiKey: ['coreApi', 'coreWeb'], core: ['coreApi', 'coreWeb'],
};
function assertCredentialTarget(auth, url, vars, env) {
  const keys = CREDENTIAL_TARGETS[(auth && auth.type) || 'none'];
  if (!keys) return;
  const origins = [...new Set(keys.map(k => { try { return new URL(vars[k]).origin; } catch { return null; } }).filter(Boolean))];
  if (!origins.includes(url.origin)) {
    const label = (AUTH_TYPES.find(t => t.id === auth.type) || {}).label || auth.type;
    throw Object.assign(new Error(`${label} credentials are only sent to ${origins.join(' or ')} on ${env} — not to ${url.origin}. Fix the URL or pick another auth type.`), { status: 400 });
  }
}

// What an auth type adds, with $PLACEHOLDERS instead of secrets (for "Copy as curl").
function curlAuth(auth, env) {
  const s = ENV_SUFFIX[env];
  switch ((auth && auth.type) || 'none') {
    case 'bearer': return { headers: { Authorization: 'Bearer $TOKEN' }, vars: ['TOKEN'] };
    case 'basic': return { user: '"$USERNAME:$PASSWORD"', vars: ['USERNAME', 'PASSWORD'] };
    case 'header': return { headers: { [auth.name || 'X-Header']: '$HEADER_VALUE' }, vars: ['HEADER_VALUE'] };
    case 'core': return { headers: { Authorization: 'Bearer $LC_SESSION_TOKEN' }, vars: ['LC_SESSION_TOKEN'] };
    case 'principa': return { headers: { Authorization: 'Bearer $PRINCIPA_JWT' }, vars: ['PRINCIPA_JWT'] };
    case 'personio': return { headers: { Authorization: 'Bearer $PERSONIO_TOKEN' }, vars: ['PERSONIO_TOKEN'] };
    case 'fcm': return { headers: { Authorization: 'Bearer $GOOGLE_ACCESS_TOKEN' }, vars: ['GOOGLE_ACCESS_TOKEN'] };
    case 'brevo': return { headers: { 'api-key': '$BREVO_API_KEY' }, vars: ['BREVO_API_KEY'] };
    case 'maps': return { query: { key: '$GOOGLE_MAPS_API_KEY' }, vars: ['GOOGLE_MAPS_API_KEY'] };
    case 'lilli': return { headers: { 'X-Lilli-Secret': `$LILLI_SSO_SECRET_${s}` }, vars: [`LILLI_SSO_SECRET_${s}`] };
    case 'coreApiKey': return { headers: { 'api-key': `$LC_API_KEY_${s}` }, vars: [`LC_API_KEY_${s}`] };
    default: return { vars: [] };
  }
}

module.exports = {
  AUTH_TYPES, baseVars, allVars, substitute, secretStatus, applyAuth, assertCredentialTarget, curlAuth,
  coreLogin, sessionInfo, dropSession,
};
