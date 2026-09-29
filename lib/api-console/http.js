// API console: one HTTP exchange with the details a debugging console wants —
// DNS / connect / TLS / first-byte timings, remote address, TLS certificate,
// raw response headers, redirects followed one by one, and decompression.
// A fresh socket per request (agent: false) so the timings are real.
const http = require('http');
const https = require('https');
const zlib = require('zlib');

const MAX_BODY = 25 * 1024 * 1024;

function once(req, { timeoutMs }) {
  return new Promise((resolve, reject) => {
    const url = req.url;
    const lib = url.protocol === 'https:' ? https : http;
    const t = { start: process.hrtime.bigint() };
    const ms = (a, b) => (a && b ? Number(b - a) / 1e6 : null);
    const out = { remote: null, tls: null };

    const r = lib.request(url, { method: req.method, headers: req.headers, agent: false, timeout: timeoutMs }, (res) => {
      t.firstByte = process.hrtime.bigint();
      const chunks = [];
      let size = 0;
      res.on('data', (c) => {
        size += c.length;
        if (size > MAX_BODY) { r.destroy(new Error(`Response larger than ${MAX_BODY / 1048576} MB — aborted`)); return; }
        chunks.push(c);
      });
      res.on('end', () => {
        t.end = process.hrtime.bigint();
        resolve({
          status: res.statusCode,
          statusText: res.statusMessage,
          httpVersion: res.httpVersion,
          rawHeaders: res.rawHeaders,
          headers: res.headers,
          raw: Buffer.concat(chunks),
          ...out,
          timings: {
            dns: ms(t.start, t.lookup),
            connect: ms(t.lookup || t.start, t.connect),
            tls: ms(t.connect, t.secure),
            ttfb: ms(t.secure || t.connect || t.start, t.firstByte),
            download: ms(t.firstByte, t.end),
            total: ms(t.start, t.end),
          },
        });
      });
      res.on('error', reject);
    });
    r.on('socket', (s) => {
      s.on('lookup', (err, address) => { t.lookup = process.hrtime.bigint(); if (!err) out.remote = { address }; });
      s.on('connect', () => { t.connect = process.hrtime.bigint(); out.remote = { address: s.remoteAddress, port: s.remotePort }; });
      s.on('secureConnect', () => {
        t.secure = process.hrtime.bigint();
        const cert = s.getPeerCertificate && s.getPeerCertificate();
        out.tls = {
          protocol: s.getProtocol && s.getProtocol(),
          cipher: s.getCipher && s.getCipher()?.name,
          subject: cert?.subject?.CN, issuer: cert?.issuer?.O || cert?.issuer?.CN, validTo: cert?.valid_to,
          authorized: s.authorized, authorizationError: s.authorizationError || null,
        };
      });
    });
    r.on('timeout', () => r.destroy(Object.assign(new Error(`No response within ${timeoutMs / 1000} s`), { code: 'ETIMEDOUT' })));
    r.on('error', reject);
    if (req.body && req.body.length) r.write(req.body);
    r.end();
  });
}

function decode(res) {
  const enc = String(res.headers['content-encoding'] || '').toLowerCase();
  try {
    if (enc === 'gzip' || enc === 'x-gzip') return zlib.gunzipSync(res.raw);
    if (enc === 'deflate') return zlib.inflateSync(res.raw);
    if (enc === 'br') return zlib.brotliDecompressSync(res.raw);
  } catch { /* keep raw */ }
  return res.raw;
}

// Human hint for network errors, e.g. the VPN for Principa's private IP.
function networkHint(err, url) {
  const code = err.code || err.cause?.code;
  const host = url.hostname;
  if (/^(10|172\.(1[6-9]|2\d|3[01])|192\.168)\./.test(host)) {
    return `${host} is a private address (Principa non-prod). Is the VPN connected?`;
  }
  if (host === 'localhost' || host === '127.0.0.1') {
    if (code === 'ECONNREFUSED') return 'Nothing is listening locally. For dev, check that the Local Stack (Serverpod on :8080/:8082) is running.';
    if (code === 'ETIMEDOUT') return 'The local port accepts no connections — the local Serverpod may be hung. Restart it in Local Stack.';
  }
  if (code === 'ENOTFOUND') return `DNS could not resolve ${host}.`;
  if (code === 'CERT_HAS_EXPIRED' || /certificate/i.test(err.message)) return 'TLS certificate problem.';
  return null;
}

// Node reports failed happy-eyeballs attempts (IPv6 + IPv4) as an AggregateError
// with an empty message; spell out each attempt instead.
function errorMessage(err) {
  if (err.message) return err.message;
  if (Array.isArray(err.errors) && err.errors.length) return err.errors.map(e => `${e.code || e.message} ${e.address || ''}${e.port ? ':' + e.port : ''}`.trim()).join('; ');
  return err.code || 'Request failed';
}

// Sends req, following up to maxRedirects. `log(level, msg)` receives each hop.
async function send(req, { timeoutMs = 60000, followRedirects = true, maxRedirects = 5, log = () => {} } = {}) {
  const hops = [];
  let cur = { ...req };
  for (let i = 0; ; i++) {
    const res = await once(cur, { timeoutMs });
    hops.push({ method: cur.method, url: cur.url.toString(), status: res.status });
    const loc = res.headers.location;
    if (followRedirects && loc && res.status >= 300 && res.status < 400 && i < maxRedirects) {
      const next = new URL(loc, cur.url);
      const keepMethod = res.status === 307 || res.status === 308;
      log('info', `↪ ${res.status} redirect to ${next} (${keepMethod ? 'keeping' : 'switching to GET,'} ${keepMethod ? cur.method : 'dropping body'})`);
      const headers = { ...cur.headers };
      if (next.host !== cur.url.host) {
        for (const k of Object.keys(headers)) if (/^(authorization|cookie|api-key|x-lilli-secret)$/i.test(k)) delete headers[k];
        log('warn', 'Redirect to another host — credentials were not forwarded');
      }
      if (!keepMethod) { for (const k of Object.keys(headers)) if (/^content-(type|length)$/i.test(k)) delete headers[k]; }
      cur = { method: keepMethod ? cur.method : 'GET', url: next, headers, body: keepMethod ? cur.body : null };
      continue;
    }
    return { ...res, body: decode(res), hops };
  }
}

module.exports = { send, networkHint, errorMessage };
