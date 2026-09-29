// ═════════════════════════════════════════════════════════════════════════
// HELPERS
// ═════════════════════════════════════════════════════════════════════════

// Postgres returns timestamps without a TZ marker (e.g. "2026-04-17 10:30:00").
// JS would otherwise parse those as LOCAL time — but the server stores UTC.
// Force-tag tz-less strings as UTC, then we can format in any zone.
function parseDbDate(val) {
  if (val === null || val === undefined || val === '') return null;
  if (val instanceof Date) return isNaN(val) ? null : val;
  let s = String(val).trim();
  s = s.replace(' ', 'T');                          // "2026-04-17 10:30" → "2026-04-17T10:30"
  if (!/Z$|[+\-]\d{2}:?\d{2}$/.test(s)) s += 'Z';   // no tz → assume UTC
  const d = new Date(s);
  return isNaN(d) ? null : d;
}

// Format a DB timestamp in the user's local timezone (de-DE format: dd.MM.yyyy HH:mm:ss).
function deTime(val) {
  if (!val) return '—';
  const d = parseDbDate(val);
  if (!d) return String(val);
  return new Intl.DateTimeFormat('de-DE', {
    year: 'numeric', month: '2-digit', day: '2-digit',
    hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false,
  }).format(d).replace(',', '');
}

// Local timezone label (e.g. "Europe/Berlin") for the bottom status bar.
const LOCAL_TZ = (() => {
  try { return Intl.DateTimeFormat().resolvedOptions().timeZone || 'local'; }
  catch { return 'local'; }
})();

// "2026-09-01" → "01.09.2026" (date-only values, no timezone shift).
function deDate(v) {
  const m = /^(\d{4})-(\d{2})-(\d{2})/.exec(v || '');
  return m ? `${m[3]}.${m[2]}.${m[1]}` : (v || '');
}

function escHtml(s) {
  if (s === null || s === undefined) return '';
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function dur(ms) {
  if (ms === null || ms === undefined) return '—';
  if (ms < 1000) return `${Math.round(ms)}ms`;
  return `${(ms/1000).toFixed(2)}s`;
}

function showToast(msg, type = '') {
  const c = document.getElementById('toastContainer');
  const t = document.createElement('div');
  t.className = 'toast ' + (type || (msg.startsWith('❌') || msg.toLowerCase().startsWith('error') ? 'err' : 'ok'));
  t.innerHTML = `<span class="dot ${type || (t.className.includes('err') ? 'err' : 'ok')}"></span><span></span>`;
  t.querySelector('span:last-child').textContent = msg.replace(/^(✅|❌|✓|✗|⚠️?)\s*/u, '');
  c.appendChild(t);
  setTimeout(() => { t.style.opacity = '0'; t.style.transform = 'translateY(6px)'; setTimeout(() => t.remove(), 300); }, 2400);
}

// Copy arbitrary text to clipboard with a toast confirmation.
// Falls back to a hidden textarea + execCommand for non-secure contexts.
async function copyText(text, label = 'Copied') {
  try {
    if (navigator.clipboard && window.isSecureContext) {
      await navigator.clipboard.writeText(text);
    } else {
      const ta = document.createElement('textarea');
      ta.value = text;
      ta.style.position = 'fixed';
      ta.style.left = '-9999px';
      document.body.appendChild(ta);
      ta.select();
      document.execCommand('copy');
      ta.remove();
    }
    showToast('✓ ' + label);
  } catch (e) {
    showToast('Copy failed: ' + e.message);
  }
}

// Decode HTML entities back to raw text. Used by inline onclick handlers
// that need to copy SQL stored in escaped HTML attributes.
function decodeEntities(s) {
  const t = document.createElement('textarea');
  t.innerHTML = s;
  return t.value;
}
