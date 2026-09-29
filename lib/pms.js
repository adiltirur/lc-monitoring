// Principa (PMS) request signing, shared by routes/pms.js and the API console.
// Mirrors the backend's JwtProvider: a self-signed HS256 token with only
// iat/exp, one secret per env (principaTestSecret / principaProdSecret).
const crypto = require('crypto');

// HS256 JWT cache keyed by secret. Matches JwtProvider: 10-min TTL, refresh
// 60 s before expiry, drop on 401.
const jwtCache = new Map();
function pmsJwt(secret) {
  const now = Math.floor(Date.now() / 1000);
  const cached = jwtCache.get(secret);
  if (cached && now < cached.expiresAt - 60) return cached.token;
  const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
  const body   = Buffer.from(JSON.stringify({ iat: now, exp: now + 600 })).toString('base64url');
  const sig    = crypto.createHmac('sha256', secret).update(`${header}.${body}`).digest('base64url');
  const token  = `${header}.${body}.${sig}`;
  jwtCache.set(secret, { token, expiresAt: now + 600 });
  return token;
}

function pmsJwtInvalidate(secret) {
  jwtCache.delete(secret);
}

module.exports = { pmsJwt, pmsJwtInvalidate };
