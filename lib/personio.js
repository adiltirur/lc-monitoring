

// ── Personio client (server-side, for name → employeeId resolution) ───────────
let _personioToken = null;
async function getPersonioToken() {
  const id = process.env.PERSONIO_CLIENT_ID;
  const secret = process.env.PERSONIO_CLIENT_SECRET;
  if (!id || !secret) throw new Error('PERSONIO_CLIENT_ID/SECRET not set in .env — manual employeeId mapping required.');
  const now = Date.now();
  if (_personioToken && _personioToken.expiresAt - 60_000 > now) return _personioToken.token;
  const r = await fetch('https://api.personio.de/v1/auth', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
    body: JSON.stringify({ client_id: id, client_secret: secret }),
  });
  if (!r.ok) throw new Error(`Personio auth failed: HTTP ${r.status}`);
  const j = await r.json();
  if (!j?.success || !j?.data?.token) throw new Error('Personio auth response missing token');
  // Default to 25 minutes (Personio docs say 24h tokens, but cache short to be safe).
  _personioToken = { token: j.data.token, expiresAt: now + 25 * 60_000 };
  return _personioToken.token;
}

// Personio employee fields we care about: id, first_name, last_name, email, office.
// The /v1/company/employees endpoint paginates with offset+limit (default 200).
async function fetchPersonioEmployees() {
  const all = [];
  const limit = 200;
  for (let offset = 0; offset < 10000; offset += limit) {
    const token = await getPersonioToken();
    const r = await fetch(`https://api.personio.de/v1/company/employees?limit=${limit}&offset=${offset}`, {
      headers: { 'Accept': 'application/json', 'Authorization': `Bearer ${token}` },
    });
    if (r.status === 401) { _personioToken = null; continue; }
    if (!r.ok) throw new Error(`Personio employees HTTP ${r.status}`);
    const j = await r.json();
    const data = j?.data || [];
    if (!data.length) break;
    for (const emp of data) {
      const attrs = emp.attributes || {};
      const office = attrs.office?.value?.attributes?.name || null;
      let weitereStandorte = [];
      for (const [key, val] of Object.entries(attrs)) {
        if (!key.startsWith('dynamic_')) continue;
        if (!val || typeof val !== 'object') continue;
        if (val.label !== 'Weitere Standorte') continue;
        const v = val.value;
        if (typeof v === 'string' && v.length > 0) {
          weitereStandorte = v.split(',').map(s => s.trim()).filter(Boolean);
        }
        break;
      }
      all.push({
        id: attrs.id?.value ?? emp.id ?? null,
        firstName: attrs.first_name?.value || '',
        lastName: attrs.last_name?.value || '',
        email: attrs.email?.value || '',
        position: attrs.position?.value || '',
        status: attrs.status?.value || null,
        office,
        weitereStandorte,
      });
    }
    if (data.length < limit) break;
  }
  return all;
}

// Personio v1 rotates the bearer token: responses may carry a fresh one in the
// `authorization` header. The API console keeps the shared cache in step.
function setPersonioToken(token) {
  if (_personioToken && token) _personioToken.token = token;
}
function clearPersonioToken() {
  _personioToken = null;
}

module.exports = { fetchPersonioEmployees, getPersonioToken, setPersonioToken, clearPersonioToken };
