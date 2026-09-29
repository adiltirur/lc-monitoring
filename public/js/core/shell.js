// ═════════════════════════════════════════════════════════════════════════
// DISPLAY SETTINGS (appearance / density / navigation)
// ═════════════════════════════════════════════════════════════════════════
// Stored under 'lc-helper-tweaks'; /theme.js reads the same key so iframes
// (monitoring, tools) follow the shell's appearance live.
const TWEAK_DEFAULTS = { density: 'default', nav: 'sidebar', theme: 'system' };
const TW_STATE = Object.assign({}, TWEAK_DEFAULTS);
const LS_TW = 'lc-helper-tweaks';
try { Object.assign(TW_STATE, JSON.parse(localStorage.getItem(LS_TW) || '{}')); } catch {}
// Legacy values from the pre-2026 theme: 'dark' was the only default.
if (TW_STATE.theme === 'dark') TW_STATE.theme = 'system';
if (TW_STATE.theme === 'light') TW_STATE.theme = 'day';
if (TW_STATE.nav === 'topbar') TW_STATE.nav = 'palette';

function applyTweaks() {
  const r = document.documentElement;
  r.dataset.density = TW_STATE.density;
  r.dataset.nav = TW_STATE.nav;
  if (window.lcApplyTheme) window.lcApplyTheme();
}
function saveTweaks() {
  try { localStorage.setItem(LS_TW, JSON.stringify(TW_STATE)); } catch {}
  applyTweaks();
}
function wireSeg(id, key) {
  document.querySelectorAll(`#${id} button`).forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll(`#${id} button`).forEach(b => b.classList.remove('on'));
      btn.classList.add('on');
      TW_STATE[key] = btn.dataset.v;
      saveTweaks();
    });
  });
}
wireSeg('tw-density', 'density');
wireSeg('tw-nav',     'nav');
wireSeg('tw-theme',   'theme');
function syncTweaksUI() {
  [['tw-density','density'],['tw-nav','nav'],['tw-theme','theme']].forEach(([id, key]) => {
    document.querySelectorAll(`#${id} button`).forEach(b => b.classList.toggle('on', b.dataset.v === String(TW_STATE[key])));
  });
}
document.getElementById('tweaksBtn').addEventListener('click', (e) => { e.stopPropagation(); document.getElementById('tweaks').classList.toggle('open'); });
document.getElementById('tweaksClose').addEventListener('click', () => document.getElementById('tweaks').classList.remove('open'));
document.addEventListener('click', (e) => {
  const tw = document.getElementById('tweaks');
  if (tw.classList.contains('open') && !tw.contains(e.target)) tw.classList.remove('open');
});

// ═════════════════════════════════════════════════════════════════════════
// STATION CLOCK
// ═════════════════════════════════════════════════════════════════════════
function tickClocks() {
  const d = new Date();
  const z = n => String(n).padStart(2,'0');
  const el = document.getElementById('localClock');
  if (el) el.innerHTML = `${z(d.getHours())}:${z(d.getMinutes())}<small>:${z(d.getSeconds())}</small>`;
}
setInterval(tickClocks, 1000);

// ═════════════════════════════════════════════════════════════════════════
// UPTIME TICKER (decorative)
// ═════════════════════════════════════════════════════════════════════════
const _started = Date.now();
function tickUptime() {
  if (!document.getElementById('uptimeDisplay')) return;
  const ms = Date.now() - _started;
  const h = Math.floor(ms/3600000);
  const m = Math.floor((ms%3600000)/60000);
  const s = Math.floor((ms%60000)/1000);
  document.getElementById('uptimeDisplay').textContent = `${String(h).padStart(2,'0')}H ${String(m).padStart(2,'0')}M ${String(s).padStart(2,'0')}S`;
}
setInterval(tickUptime, 1000);
tickUptime();
