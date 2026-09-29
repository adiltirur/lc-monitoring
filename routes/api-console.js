// ─── Routes: API console (/api/console/*, view #api-console) ────────────────
// A Postman-like console for every Serverpod endpoint and every external call
// the backend makes (Principa, Personio, Brevo, FCM, Maps, holidays) plus the
// inbound webhooks. Requests are sent from here, not the browser: secrets are
// added server-side (lib/api-console/auth.js) and masked in everything returned.
//
// Production: anything but GET/HEAD — and every Serverpod call, which is always a
// POST — needs body.confirm === 'production'. The UI asks for it each time.
const crypto = require('crypto');
const router = require('express').Router();
const { getCatalog } = require('../lib/api-console/catalog');
const { EXTERNALS } = require('../lib/api-console/externals');
const auth = require('../lib/api-console/auth');
const store = require('../lib/api-console/store');
const { send, networkHint, errorMessage } = require('../lib/api-console/http');

const TEXT_MAX = 5 * 1024 * 1024;
const downloads = new Map(); // id → { buf, contentType, name } (last 20 binary responses, memory only)

function fail(res, e) {
  res.status(e.status || 500).json({ error: e.message });
}

function checkEnv(env) {
  if (!store.ENVS.includes(env)) throw Object.assign(new Error(`env must be one of ${store.ENVS.join(', ')}`), { status: 400 });
  return env;
}

// ── catalog + meta ──
router.get('/api/console/catalog', (req, res) => {
  try { res.json({ serverpod: getCatalog(), externals: EXTERNALS }); } catch (e) { fail(res, e); }
});

router.get('/api/console/meta', async (req, res) => {
  try {
    const env = checkEnv(req.query.env || 'dev');
    res.json({ env, envs: store.ENVS, authTypes: auth.AUTH_TYPES, secrets: auth.secretStatus(env), baseVars: await auth.baseVars(env) });
  } catch (e) { fail(res, e); }
});

// ── accounts (passwords never leave the server) ──
router.get('/api/console/accounts', (req, res) => {
  res.json(store.accounts().map(a => ({ ...store.publicAccount(a), session: auth.sessionInfo(a.env, a.id) })));
});

router.post('/api/console/accounts', (req, res) => {
  try {
    const saved = store.saveAccount(req.body || {});
    auth.dropSession(saved.env, saved.id);
    res.json(store.publicAccount(saved));
  } catch (e) { fail(res, e); }
});

router.delete('/api/console/accounts/:id', (req, res) => {
  const a = store.account(req.params.id);
  if (a) auth.dropSession(a.env, a.id);
  store.deleteAccount(req.params.id);
  res.json({ ok: true });
});

router.post('/api/console/accounts/:id/login', async (req, res) => {
  const lines = [];
  try {
    const a = store.account(req.params.id);
    if (!a) return res.status(404).json({ error: 'Account not found' });
    await auth.coreLogin(a.env, a, (level, msg) => lines.push(msg), { force: true });
    res.json({ ok: true, session: auth.sessionInfo(a.env, a.id), log: lines });
  } catch (e) { res.status(e.status || 500).json({ error: e.message, log: lines }); }
});

router.post('/api/console/accounts/:id/logout', (req, res) => {
  const a = store.account(req.params.id);
  if (a) auth.dropSession(a.env, a.id);
  res.json({ ok: true });
});

// ── history / collections / variables ──
router.get('/api/console/history', (req, res) => res.json(store.history()));
router.delete('/api/console/history', (req, res) => { store.clearHistory(); res.json({ ok: true }); });
router.get('/api/console/collections', (req, res) => res.json(store.collections()));
router.put('/api/console/collections', (req, res) => {
  try { store.saveCollections(req.body); res.json({ ok: true }); } catch (e) { fail(res, e); }
});
router.get('/api/console/vars', (req, res) => res.json(store.vars()));
router.put('/api/console/vars', (req, res) => {
  try { res.json(store.saveVars(req.body)); } catch (e) { fail(res, e); }
});

// ── building a request ──
// Input (from the editor): { method, url, headers: [{ key, value, enabled }], bodyMode: none|json|text,
//   body, auth: { type, … }, kind: serverpod|external|custom, name }
async function resolveRequest(env, input, { forCurl = false } = {}) {
  const vars = await auth.allVars(env);
  const missing = new Set();
  const method = String(input.method || 'GET').toUpperCase();
  if (!/^[A-Z]+$/.test(method)) throw Object.assign(new Error('Invalid method'), { status: 400 });
  const urlText = auth.substitute(String(input.url || '').trim(), vars, missing);
  const headers = {};
  for (const h of input.headers || []) {
    if (h.enabled === false || !h.key) continue;
    headers[auth.substitute(h.key, vars, missing)] = auth.substitute(h.value || '', vars, missing);
  }
  const hasBody = input.bodyMode && input.bodyMode !== 'none' && !['GET', 'HEAD'].includes(method);
  const bodyText = hasBody ? auth.substitute(String(input.body || ''), vars, missing) : null;
  if (missing.size) {
    throw Object.assign(new Error(`Unresolved variable${missing.size > 1 ? 's' : ''}: ${[...missing].map(n => `{{${n}}}`).join(', ')} — set ${missing.size > 1 ? 'them' : 'it'} in Variables`), { status: 400, missing: [...missing] });
  }
  let url;
  try { url = new URL(urlText); } catch { throw Object.assign(new Error(`Invalid URL: ${urlText || '(empty)'}`), { status: 400 }); }
  if (!/^https?:$/.test(url.protocol)) throw Object.assign(new Error('Only http and https URLs'), { status: 400 });
  const has = (name) => Object.keys(headers).some(k => k.toLowerCase() === name);
  if (hasBody && input.bodyMode === 'json' && !has('content-type')) headers['Content-Type'] = 'application/json';
  if (!forCurl) {
    if (!has('user-agent')) headers['User-Agent'] = 'LC-Helper-API-Console/1.0';
    if (!has('accept')) headers.Accept = '*/*';
  }
  return { method, url, headers, bodyText, baseVars: vars };
}

function isTextual(contentType, buf) {
  if (/json|xml|text\/|javascript|x-www-form-urlencoded|graphql|yaml/i.test(contentType || '')) return true;
  if (contentType) return false;
  return buf.length < TEXT_MAX && !buf.subarray(0, 4096).includes(0);
}

// Serverpod error bodies: { className, data: { message, errorCode, errorType } }.
function describeServerpodError(text) {
  try {
    const j = JSON.parse(text);
    if (!j || !j.className) return null;
    const d = j.data || {};
    const types = getCatalog().models.CoreExceptionType;
    const typeName = typeof d.errorType === 'number' && types ? types.values[d.errorType] : d.errorType;
    return `Serverpod exception ${j.className}: ${d.message || ''}${d.errorCode != null ? ` (errorCode ${d.errorCode}` : ''}${typeName != null ? `, errorType ${typeName})` : d.errorCode != null ? ')' : ''}`;
  } catch { return null; }
}

// ── send ──
router.post('/api/console/send', async (req, res) => {
  const t0 = Date.now();
  const trace = [];
  const secrets = new Map(); // value → label
  const mask = (value, label) => { const v = String(value || ''); if (v.length >= 4 && !secrets.has(v)) secrets.set(v, label); };
  const hide = (s) => {
    let out = String(s);
    for (const [v, label] of [...secrets].sort((a, b) => b[0].length - a[0].length)) out = out.split(v).join(`‹${label}›`);
    return out;
  };
  const log = (level, msg) => trace.push({ t: Date.now() - t0, level, msg });
  const body = req.body || {};
  const input = body.request || {};
  let env;
  try {
    env = checkEnv(body.env);
    const r = await resolveRequest(env, input);
    log('info', `${env.toUpperCase()} · ${r.method} ${r.url}`);

    // Production guard
    const prodApi = (await auth.baseVars('production')).coreApi;
    const isCore = input.kind === 'serverpod' || (prodApi && r.url.origin === new URL(prodApi).origin);
    if (env === 'production' && (!['GET', 'HEAD'].includes(r.method) || isCore) && body.confirm !== 'production') {
      return res.status(428).json({ error: 'Production request needs confirmation', needsConfirm: true });
    }
    if (env === 'production') log('warn', body.confirm === 'production' ? 'PRODUCTION — confirmed by typing "production"' : 'PRODUCTION — read-only request');
    auth.assertCredentialTarget(input.auth, r.url, r.baseVars, env);

    const outgoing = { method: r.method, url: r.url, headers: r.headers, body: r.bodyText != null ? Buffer.from(r.bodyText) : null };
    const hooks = await auth.applyAuth(input.auth, env, outgoing, log, mask);
    if (outgoing.body) outgoing.headers['Content-Length'] = String(outgoing.body.length);
    if (input.bodyMode === 'json' && r.bodyText) {
      try { JSON.parse(r.bodyText); } catch (e) { log('warn', `Body is not valid JSON (${e.message}) — sent as is`); }
    }
    log('info', `Request headers: ${Object.keys(outgoing.headers).join(', ')}${outgoing.body ? ` · body ${outgoing.body.length} bytes` : ''}`);

    const opts = { timeoutMs: Math.min(Math.max(Number(body.timeoutMs) || 60000, 1000), 300000), followRedirects: body.followRedirects !== false, log };
    let result;
    try {
      result = await send(outgoing, opts);
      if (result.status === 401 && await hooks.refresh()) {
        log('warn', '401 Unauthorized — retrying once with fresh credentials');
        result = await send(outgoing, opts);
      }
    } catch (e) {
      const hint = networkHint(e, outgoing.url);
      const message = errorMessage(e);
      log('error', `${e.code || 'Error'}: ${message}`);
      if (hint) log('hint', hint);
      store.addHistory({ env, name: input.name || '', request: input, status: 'ERR', ms: Date.now() - t0 });
      return res.json({ ok: false, networkError: true, error: message, code: e.code || null, hint, trace: trace.map(x => ({ ...x, msg: hide(x.msg) })) });
    }
    hooks.afterResponse(result.headers);

    const tm = result.timings;
    if (result.remote) log('info', `Connected to ${result.remote.address}${result.remote.port ? ':' + result.remote.port : ''}`);
    if (result.tls) log('info', `TLS ${result.tls.protocol || ''} ${result.tls.cipher || ''} · cert ${result.tls.subject || '?'} by ${result.tls.issuer || '?'}, valid to ${result.tls.validTo || '?'}${result.tls.authorized === false ? ` · NOT TRUSTED: ${result.tls.authorizationError}` : ''}`);
    log(result.status >= 400 ? 'error' : 'info', `HTTP/${result.httpVersion} ${result.status} ${result.statusText || ''} · ${Math.round(tm.total)} ms (dns ${fmt(tm.dns)}, connect ${fmt(tm.connect)}, tls ${fmt(tm.tls)}, first byte ${fmt(tm.ttfb)}, download ${fmt(tm.download)})`);

    const contentType = result.headers['content-type'] || '';
    const textual = isTextual(contentType, result.body);
    let bodyText = null, downloadId = null, truncated = false;
    if (textual) {
      bodyText = result.body.subarray(0, TEXT_MAX).toString('utf8');
      truncated = result.body.length > TEXT_MAX;
      if (result.status >= 400) { const d = describeServerpodError(bodyText); if (d) log('error', d); }
    }
    if (!textual || truncated) {
      downloadId = crypto.randomBytes(8).toString('hex');
      const ext = (contentType.split(';')[0].split('/')[1] || 'bin').replace(/[^\w.+-]/g, '');
      downloads.set(downloadId, { buf: result.body, contentType: contentType || 'application/octet-stream', name: `response-${Date.now()}.${ext}` });
      while (downloads.size > 20) downloads.delete(downloads.keys().next().value);
    }

    store.addHistory({ env, name: input.name || '', request: input, status: result.status, ms: Math.round(tm.total) });
    const pairs = [];
    for (let i = 0; i < result.rawHeaders.length; i += 2) pairs.push([result.rawHeaders[i], result.rawHeaders[i + 1]]);
    res.json({
      ok: true,
      status: result.status,
      statusText: result.statusText,
      httpVersion: result.httpVersion,
      timings: tm,
      size: result.raw.length,
      decodedSize: result.body.length,
      contentType,
      headers: pairs,
      bodyText, truncated, downloadId,
      hops: result.hops.map(h => ({ ...h, url: hide(h.url) })),
      remote: result.remote, tls: result.tls,
      request: {
        method: outgoing.method,
        url: hide(outgoing.url.toString()),
        headers: Object.entries(outgoing.headers).map(([k, v]) => [k, hide(v)]),
        bodySize: outgoing.body ? outgoing.body.length : 0,
      },
      trace: trace.map(x => ({ ...x, msg: hide(x.msg) })),
    });
  } catch (e) {
    log('error', e.message);
    res.status(e.status || 500).json({ error: hide(e.message), missing: e.missing, trace: trace.map(x => ({ ...x, msg: hide(x.msg) })) });
  }
});

function fmt(v) { return v == null ? '—' : `${Math.round(v)} ms`; }

router.get('/api/console/download/:id', (req, res) => {
  const d = downloads.get(req.params.id);
  if (!d) return res.status(404).json({ error: 'Response no longer in memory — send the request again' });
  res.setHeader('Content-Type', d.contentType);
  res.setHeader('Content-Disposition', `${req.query.inline ? 'inline' : 'attachment'}; filename="${d.name}"`);
  res.send(d.buf);
});

// Postman export: the page posts the JSON, then downloads it via /download/:id
// (the Mac shell turns Content-Disposition: attachment into a real download).
router.post('/api/console/export', (req, res) => {
  const { name, content } = req.body || {};
  if (typeof content !== 'string' || !content) return res.status(400).json({ error: 'content required' });
  const id = crypto.randomBytes(8).toString('hex');
  downloads.set(id, { buf: Buffer.from(content), contentType: 'application/json', name: String(name || 'export.json').replace(/[^\w.-]+/g, '_') });
  while (downloads.size > 20) downloads.delete(downloads.keys().next().value);
  res.json({ id });
});

// ── copy as curl (secrets as $PLACEHOLDERS) ──
// Single-quotes everything except the $PLACEHOLDERS, which stay expandable ("$X").
function shellQuote(s, placeholders) {
  const single = (p) => `'${p.replace(/'/g, `'\\''`)}'`;
  if (!placeholders.length) return single(s);
  const names = new Set(placeholders.map(p => `$${p}`));
  return s.split(new RegExp(`(\\$(?:${placeholders.join('|')}))`)).filter(p => p !== '')
    .map(p => (names.has(p) ? `"${p}"` : single(p))).join('');
}

router.post('/api/console/curl', async (req, res) => {
  try {
    const env = checkEnv((req.body || {}).env);
    const input = (req.body || {}).request || {};
    const r = await resolveRequest(env, input, { forCurl: true });
    const a = auth.curlAuth(input.auth, env);
    const url = new URL(r.url.toString());
    let urlText = url.toString();
    for (const [k, v] of Object.entries(a.query || {})) urlText += `${url.search ? '&' : '?'}${k}=${v}`;
    const lines = [`curl -X ${r.method} ${shellQuote(urlText, a.vars)}`];
    for (const [k, v] of Object.entries({ ...r.headers, ...(a.headers || {}) })) lines.push(`  -H ${shellQuote(`${k}: ${v}`, a.vars)}`);
    if (a.user) lines.push(`  -u ${a.user}`);
    if (r.bodyText) lines.push(`  --data-raw ${shellQuote(r.bodyText, [])}`);
    const notes = [];
    if (input.auth?.type === 'core') notes.push(`# LC_SESSION_TOKEN: the "token" from POST ${r.baseVars.coreApi}/emailIdp/login {"email":…,"password":…}`);
    if (input.auth?.type === 'principa') notes.push('# PRINCIPA_JWT: HS256 JWT {"iat","exp"} signed with the principa secret (see lib/pms.js)');
    if (input.auth?.type === 'personio') notes.push('# PERSONIO_TOKEN: data.token from POST https://api.personio.de/v1/auth {"client_id","client_secret"}');
    if (input.auth?.type === 'fcm') notes.push('# GOOGLE_ACCESS_TOKEN: gcloud auth print-access-token (service account with firebase.messaging)');
    res.json({ curl: [...notes, lines.join(' \\\n')].join('\n'), vars: a.vars });
  } catch (e) { fail(res, e); }
});

module.exports = router;
