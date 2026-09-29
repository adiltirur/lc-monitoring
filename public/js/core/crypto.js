// ═════════════════════════════════════════════════════════════════════════
// AES-256-CBC decryption
// ═════════════════════════════════════════════════════════════════════════
async function importAesKey(keyStr) {
  const bytes = new TextEncoder().encode(keyStr);
  return crypto.subtle.importKey('raw', bytes, { name: 'AES-CBC' }, false, ['decrypt']);
}

function b64urlToBytes(s) {
  let b64 = s.replace(/-/g, '+').replace(/_/g, '/');
  while (b64.length % 4) b64 += '=';
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

async function aesDecrypt(cryptoKey, encText) {
  const raw = b64urlToBytes(encText.trim());
  const iv = raw.length >= 32 ? raw.slice(0, 16) : new Uint8Array(16);
  const cipher = raw.length >= 32 ? raw.slice(16) : raw;
  const plain = await crypto.subtle.decrypt({ name: 'AES-CBC', iv }, cryptoKey, cipher);
  return new TextDecoder().decode(plain);
}
