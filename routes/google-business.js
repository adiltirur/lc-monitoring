const router = require('express').Router();
const fs = require('fs');
const path = require('path');
const { OAuth2Client } = require('google-auth-library');

const ROOT = path.join(__dirname, '..'); // helper/

// ─── Google Business Profile (GBP) ────────────────────────────────────────────
// Manages OAuth2 with Google's Business Profile APIs and exposes a small REST
// surface the UI (and later the Dart backend) can call to list accounts/
// locations and edit regularHours. The flow is standard Authorization Code
// with offline access — tokens persist in a gitignored JSON file.
//
// APIs used:
//   - mybusinessaccountmanagement.googleapis.com/v1 → list accounts
//   - mybusinessbusinessinformation.googleapis.com/v1 → list locations, PATCH hours
//
// Setup: see .env.example for the GCP steps. Credentials must come from env:
//   GBP_CLIENT_ID, GBP_CLIENT_SECRET

const GBP_TOKEN_PATH = path.join(ROOT, '.gbp_token.json');
const GBP_REDIRECT_URI = 'http://localhost:3333/api/gbp/oauth/callback';
const GBP_SCOPE = 'https://www.googleapis.com/auth/business.manage';
const GBP_DAYS = ['MONDAY','TUESDAY','WEDNESDAY','THURSDAY','FRIDAY','SATURDAY','SUNDAY'];

function gbpLoadToken() {
  try {
    if (!fs.existsSync(GBP_TOKEN_PATH)) return null;
    return JSON.parse(fs.readFileSync(GBP_TOKEN_PATH, 'utf8'));
  } catch { return null; }
}
function gbpSaveToken(tokens) {
  const existing = gbpLoadToken() || {};
  const merged = { ...existing, ...tokens };
  fs.writeFileSync(GBP_TOKEN_PATH, JSON.stringify(merged, null, 2), { mode: 0o600 });
}
function gbpClearToken() {
  if (fs.existsSync(GBP_TOKEN_PATH)) fs.unlinkSync(GBP_TOKEN_PATH);
}

function gbpClientConfigured() {
  return !!(process.env.GBP_CLIENT_ID && process.env.GBP_CLIENT_SECRET);
}

// Returns an OAuth2Client pre-loaded with any saved token. When the library
// auto-refreshes an access_token it emits a `tokens` event — we persist the
// new values so subsequent boots don't need re-auth.
function gbpOAuthClient() {
  if (!gbpClientConfigured()) return null;
  const client = new OAuth2Client(process.env.GBP_CLIENT_ID, process.env.GBP_CLIENT_SECRET, GBP_REDIRECT_URI);
  const saved = gbpLoadToken();
  if (saved) client.setCredentials(saved);
  client.on('tokens', (tokens) => gbpSaveToken(tokens));
  return client;
}

// Wraps fetch with a Bearer token from the OAuth client, refreshing access if
// needed. Throws with the Google error body on non-2xx.
async function gbpFetch(urlPath, init = {}) {
  const client = gbpOAuthClient();
  if (!client) throw new Error('Google Business Profile credentials not configured.');
  if (!gbpLoadToken()) throw new Error('Not connected to Google. Click Connect first.');
  const { token } = await client.getAccessToken();
  if (!token) throw new Error('Failed to obtain access token — re-auth required.');
  const res = await fetch(urlPath, {
    ...init,
    headers: {
      Authorization: `Bearer ${token}`,
      'Content-Type': 'application/json',
      ...(init.headers || {}),
    },
  });
  const body = await res.text();
  let json = null;
  try { json = body ? JSON.parse(body) : null; } catch { /* keep raw */ }
  if (!res.ok) {
    const msg = json?.error?.message || body || `HTTP ${res.status}`;
    throw new Error(`Google API ${res.status}: ${msg}`);
  }
  return json;
}

// Simple { MONDAY: ['09:00','18:00'] } ⇄ Google periods[] conversion.
// Google periods use 24h "HH:MM" → { hours, minutes }, openDay/closeDay in
// enum form ("MONDAY"). Days omitted from `dict` are treated as closed.
function gbpPeriodsFromSimple(dict) {
  const periods = [];
  for (const day of GBP_DAYS) {
    const pair = dict?.[day];
    if (!pair || pair === 'closed' || !pair[0] || !pair[1]) continue;
    const [oh, om] = String(pair[0]).split(':').map(n => parseInt(n, 10));
    const [ch, cm] = String(pair[1]).split(':').map(n => parseInt(n, 10));
    periods.push({
      openDay: day,
      openTime: { hours: oh || 0, minutes: om || 0 },
      closeDay: day,
      closeTime: { hours: ch || 0, minutes: cm || 0 },
    });
  }
  return { periods };
}
function gbpSimpleFromPeriods(regularHours) {
  const out = {};
  const periods = regularHours?.periods || [];
  for (const p of periods) {
    const pad = (n) => String(n || 0).padStart(2, '0');
    const open = `${pad(p.openTime?.hours)}:${pad(p.openTime?.minutes)}`;
    const close = `${pad(p.closeTime?.hours)}:${pad(p.closeTime?.minutes)}`;
    // Most GBP entries use same day for open/close. Cross-midnight spans are
    // rare for praxis locations; if encountered, we surface the open day only.
    out[p.openDay] = [open, close];
  }
  return out;
}

// GET /api/gbp/status — drives the UI state (setup required / connect / ready)
router.get('/api/gbp/status', (req, res) => {
  const clientConfigured = gbpClientConfigured();
  const token = gbpLoadToken();
  res.json({
    clientConfigured,
    connected: !!(clientConfigured && token && (token.refresh_token || token.access_token)),
    scope: token?.scope || null,
    expiresAt: token?.expiry_date || null,
    redirectUri: GBP_REDIRECT_URI,
  });
});

// GET /api/gbp/oauth/start — redirect the user to Google's consent screen.
// `prompt:'consent'` forces a refresh_token on every authorization (Google
// only returns one the first time unless explicitly re-prompted).
router.get('/api/gbp/oauth/start', (req, res) => {
  const client = gbpOAuthClient();
  if (!client) return res.status(400).send('GBP credentials not configured. See .env.example.');
  const url = client.generateAuthUrl({
    access_type: 'offline',
    prompt: 'consent',
    scope: [GBP_SCOPE],
  });
  res.redirect(url);
});

// GET /api/gbp/oauth/callback — Google redirects here with ?code. We exchange
// it for tokens, save them, and close the popup (signaling the opener).
router.get('/api/gbp/oauth/callback', async (req, res) => {
  try {
    const code = req.query.code;
    const err = req.query.error;
    if (err) throw new Error(String(err));
    if (!code) throw new Error('Missing ?code in callback');
    const client = gbpOAuthClient();
    if (!client) throw new Error('GBP credentials not configured.');
    const { tokens } = await client.getToken(String(code));
    gbpSaveToken(tokens);
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.send(`<!doctype html><meta charset="utf-8"><title>Connected</title>
<style>body{font:14px/1.5 system-ui;background:#0a0a0b;color:#e7e7ea;display:grid;place-items:center;height:100vh;margin:0}
.card{border:1px solid #222;border-radius:12px;padding:24px 28px;text-align:center;max-width:380px}
.ok{color:#62d08c;font-weight:600;letter-spacing:.08em;text-transform:uppercase;font-size:11px}
h1{font-size:18px;margin:.4em 0}</style>
<div class="card"><div class="ok">✓ Connected</div><h1>Google Business Profile linked</h1>
<p>You can close this tab.</p></div>
<script>
  try { window.opener && window.opener.postMessage({ type:'gbp-connected' }, '*'); } catch(e){}
  setTimeout(() => { try { window.close(); } catch(e){} }, 400);
</script>`);
  } catch (e) {
    res.status(500).send(`OAuth callback failed: ${e.message}`);
  }
});

// POST /api/gbp/disconnect — remove the saved token file.
router.post('/api/gbp/disconnect', (req, res) => {
  try {
    gbpClearToken();
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// GET /api/gbp/accounts — list GBP accounts visible to the authorized user.
router.get('/api/gbp/accounts', async (req, res) => {
  try {
    const data = await gbpFetch('https://mybusinessaccountmanagement.googleapis.com/v1/accounts');
    res.json({ accounts: data?.accounts || [] });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// GET /api/gbp/locations?account=accounts/123 — list locations under the account
// with the fields we render (title, address summary, regularHours).
router.get('/api/gbp/locations', async (req, res) => {
  try {
    const account = String(req.query.account || '').trim();
    if (!account) return res.status(400).json({ error: 'account query param required (e.g. accounts/123)' });
    const readMask = encodeURIComponent('name,title,storefrontAddress,regularHours');
    const url = `https://mybusinessbusinessinformation.googleapis.com/v1/${encodeURIComponent(account)}/locations?readMask=${readMask}&pageSize=100`;
    const data = await gbpFetch(url);
    const locations = (data?.locations || []).map(loc => ({
      name: loc.name,
      title: loc.title,
      address: loc.storefrontAddress
        ? [
            (loc.storefrontAddress.addressLines || []).join(', '),
            [loc.storefrontAddress.postalCode, loc.storefrontAddress.locality].filter(Boolean).join(' '),
            loc.storefrontAddress.regionCode,
          ].filter(Boolean).join(' · ')
        : '',
      regularHours: loc.regularHours || { periods: [] },
      hoursSimple: gbpSimpleFromPeriods(loc.regularHours),
    }));
    res.json({ locations });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// PATCH /api/gbp/locations — body: { name:'locations/123', hours:{MONDAY:[...]} }
// or { name, regularHours:{periods:[...]} }. Uses updateMask=regularHours so we
// don't accidentally clobber other location fields.
router.patch('/api/gbp/locations', async (req, res) => {
  try {
    const { name, hours, regularHours } = req.body || {};
    if (!name || !/^locations\//.test(name)) return res.status(400).json({ error: 'name (locations/...) required' });
    const payload = regularHours
      ? { regularHours }
      : { regularHours: gbpPeriodsFromSimple(hours || {}) };
    const url = `https://mybusinessbusinessinformation.googleapis.com/v1/${encodeURIComponent(name)}?updateMask=regularHours`;
    const data = await gbpFetch(url, { method: 'PATCH', body: JSON.stringify(payload) });
    res.json({
      ok: true,
      location: {
        name: data?.name || name,
        title: data?.title,
        regularHours: data?.regularHours || payload.regularHours,
        hoursSimple: gbpSimpleFromPeriods(data?.regularHours || payload.regularHours),
      },
    });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

module.exports = router;
