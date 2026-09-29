// Generates public/theme.css and public/theme.js for LC Helper.
const fs = require('fs');
const path = require('path');
const OUT = process.argv[2];

const hex = (h) => { h = h.replace('#', ''); return [0, 2, 4].map((i) => parseInt(h.slice(i, i + 2), 16)); };
const mix = (a, b, t) => a.map((v, i) => Math.round(v * (1 - t) + b[i] * t));
const trip = (c) => c.join(' ');

// LillianCare CI (apps-frontend/packages/design_system): petrol #004E64 primary,
// logo turquoise #2BD2C9 / #B0EFEC, Manrope, white grounds, 8px radius.
const NIGHT = {
  ground: '#00212a', s1: '#002b37', s2: '#003340', s3: '#003f4f', s4: '#0b5266',
  ink: '#f2fffe', ink2: '#b8ccd2', ink3: '#8aaeb8', ink4: '#4f7c89',
  action: '#2bd2c9', actionInk: '#00212a', focus: '#2bd2c9',
  accent: '#2bd2c9', accentSoft: 'rgba(43, 210, 201, 0.16)', highlight: '#0b4a5b',
  topbar: '#002b37', topbarInk: '#f2fffe',
  yellow: '#fdb440', red: '#ff6f6f', green: '#4cc76a', blue: '#6fb1ff', orange: '#fcac3b', purple: '#b39cff', pink: '#ff8cc6',
  band: '#b53535',
};
const DAY = {
  ground: '#f7f9f9', s1: '#ffffff', s2: '#ffffff', s3: '#f0f7f9', s4: '#e6edf0',
  ink: '#00212a', ink2: '#384048', ink3: '#60666d', ink4: '#a3a7ab',
  action: '#004e64', actionInk: '#ffffff', focus: '#004e64',
  accent: '#2bd2c9', accentSoft: '#e6fffd', highlight: '#dbedf1',
  topbar: '#004e64', topbarInk: '#ffffff',
  yellow: '#f39b1f', yellowInk: '#b76800', red: '#e84444', green: '#008a05', blue: '#096fdd', orange: '#da8201', purple: '#6b3fc4', pink: '#b8266f',
  band: '#b53535',
};

// Tailwind default palettes (light mode keeps them so pastel pills read as designed).
const TW = {
  red:     ['#fef2f2','#fee2e2','#fecaca','#fca5a5','#f87171','#ef4444','#dc2626','#b91c1c','#991b1b','#7f1d1d'],
  amber:   ['#fffbeb','#fef3c7','#fde68a','#fcd34d','#fbbf24','#f59e0b','#d97706','#b45309','#92400e','#78350f'],
  yellow:  ['#fefce8','#fef9c3','#fef08a','#fde047','#facc15','#eab308','#ca8a04','#a16207','#854d0e','#713f12'],
  emerald: ['#ecfdf5','#d1fae5','#a7f3d0','#6ee7b7','#34d399','#10b981','#059669','#047857','#065f46','#064e3b'],
  green:   ['#f0fdf4','#dcfce7','#bbf7d0','#86efac','#4ade80','#22c55e','#16a34a','#15803d','#166534','#14532d'],
  blue:    ['#eff6ff','#dbeafe','#bfdbfe','#93c5fd','#60a5fa','#3b82f6','#2563eb','#1d4ed8','#1e40af','#1e3a8a'],
  sky:     ['#f0f9ff','#e0f2fe','#bae6fd','#7dd3fc','#38bdf8','#0ea5e9','#0284c7','#0369a1','#075985','#0c4a6e'],
  indigo:  ['#eef2ff','#e0e7ff','#c7d2fe','#a5b4fc','#818cf8','#6366f1','#4f46e5','#4338ca','#3730a3','#312e81'],
  orange:  ['#fff7ed','#ffedd5','#fed7aa','#fdba74','#fb923c','#f97316','#ea580c','#c2410c','#9a3412','#7c2d12'],
  purple:  ['#faf5ff','#f3e8ff','#e9d5ff','#d8b4fe','#c084fc','#a855f7','#9333ea','#7e22ce','#6b21a8','#581c87'],
  pink:    ['#fdf2f8','#fce7f3','#fbcfe8','#f9a8d4','#f472b6','#ec4899','#db2777','#be185d','#9d174d','#831843'],
  slate:   ['#f8fafc','#f1f5f9','#e2e8f0','#cbd5e1','#94a3b8','#64748b','#475569','#334155','#1e293b','#0f172a'],
  gray:    ['#f9fafb','#f3f4f6','#e5e7eb','#d1d5db','#9ca3af','#6b7280','#4b5563','#374151','#1f2937','#111827'],
};
const SHADES = [50, 100, 200, 300, 400, 500, 600, 700, 800, 900];
// Night: every hue collapses onto one of the four signal colours (greys never carry meaning).
const SIGNAL = { red: 'red', amber: 'yellowInk', yellow: 'yellowInk', emerald: 'green', green: 'green', blue: 'blue', sky: 'blue', indigo: 'blue', orange: 'orange', purple: 'purple', pink: 'pink' };

function nightRamp(sig) {
  const S = hex(NIGHT[sig === 'yellowInk' ? 'yellow' : sig]), G = hex(NIGHT.s1), W = [255, 255, 255], K = [0, 0, 0];
  return [mix(G, S, .10), mix(G, S, .17), mix(G, S, .28), mix(S, W, .45), mix(S, W, .2), S, mix(S, K, .12), mix(S, W, .12), mix(S, W, .32), mix(S, W, .5)];
}
function nightNeutral() {
  const N = NIGHT;
  return [N.s1, N.s3, N.s4, '#33476f', N.ink4, N.ink3, N.ink3, N.ink2, N.ink, N.ink].map(hex);
}

function tokens(T, rampFor) {
  const L = [];
  const v = (k, val) => L.push(`  --${k}: ${val};`);
  v('ground', T.ground); v('surface-1', T.s1); v('surface-2', T.s2); v('surface-3', T.s3); v('surface-4', T.s4);
  v('ink', T.ink); v('ink-2', T.ink2); v('ink-3', T.ink3); v('ink-4', T.ink4);
  v('action', T.action); v('action-ink', T.actionInk); v('focus', T.focus);
  for (const k of ['yellow', 'red', 'green', 'blue', 'orange', 'purple']) v(k, T[k]);
  v('band', T.band);
  v('accent', T.accent); v('accent-soft', T.accentSoft); v('highlight', T.highlight); v('topbar', T.topbar); v('topbar-ink', T.topbarInk);
  // rgb triplets for Tailwind's <alpha-value>
  const t = (k, c) => v(`rgb-${k}`, trip(hex(c)));
  t('ground', T.ground); t('s1', T.s1); t('s2', T.s2); t('s3', T.s3); t('s4', T.s4);
  t('ink', T.ink); t('ink2', T.ink2); t('ink3', T.ink3); t('ink4', T.ink4);
  t('action', T.action); t('action-ink', T.actionInk); t('accent', T.accent); t('highlight', T.highlight); t('red', T.red); t('green', T.green); t('yellow', T.yellow); t('blue', T.blue);
  for (const [hue, ramp] of Object.entries(rampFor)) ramp.forEach((c, i) => v(`tw-${hue}-${SHADES[i]}`, trip(c)));
  return L.join('\n');
}

// Day: same rule — stock hues collapse onto the day signal colours (tints for grounds, ink-strength for text).
function dayRamp(sig) {
  const S = hex(DAY[sig]), W = [255, 255, 255], K = [0, 0, 0];
  return [mix(W, S, .06), mix(W, S, .11), mix(W, S, .2), mix(W, S, .45), mix(W, S, .7), S, S, mix(S, K, .12), mix(S, K, .25), mix(S, K, .38)];
}
const dayRamps = Object.fromEntries(Object.entries(TW).map(([h, r]) => [h, SIGNAL[h] ? dayRamp(SIGNAL[h]) : r.map(hex)]));
const nightRamps = Object.fromEntries(Object.keys(TW).map((h) => [h, SIGNAL[h] ? nightRamp(SIGNAL[h]) : nightNeutral()]));

const dayBlock = tokens(DAY, dayRamps);
const nightBlock = tokens(NIGHT, nightRamps);

const css = `/* ==========================================================================
   LC HELPER — THEME TOKENS (generated; shared by index, monitoring, tools)
   LillianCare CI: petrol #004E64 primary, logo turquoise #2BD2C9 accent,
   Manrope, white grounds, 8px corners. Day is the brand; Night is a
   deep-petrol variant for late incidents. Signal colours: red (errors,
   production), amber (warning), green (healthy), blue (info).
   ========================================================================== */
@import url("vendor/fonts/fonts.css");

:root {
  color-scheme: light;
${dayBlock}
  --rule: #e6edf0;
  --rule-strong: #d5d4dc;
  --yellow-soft: #fff8e8;
  --red-soft: #fff0f0;
  --green-soft: #e6f3e6;
  --blue-soft: #e8f1fc;
  --shadow-card: 0 1px 2px rgba(0, 33, 42, 0.04), 0 1px 3px rgba(0, 33, 42, 0.06);
  --shadow-pop: 0 16px 40px -12px rgba(0, 33, 42, 0.22), 0 2px 6px rgba(0, 33, 42, 0.06);

  --font-ui: "Manrope", -apple-system, BlinkMacSystemFont, system-ui, sans-serif;
  --font-sign: "Manrope", -apple-system, BlinkMacSystemFont, system-ui, sans-serif;
  --font-mono: ui-monospace, "SF Mono", SFMono-Regular, Menlo, monospace;

  --t-board: 26px; --t-h2: 15px; --t-body: 13px; --t-data: 12.5px; --t-small: 11.5px; --t-label: 11px;
  --s-1: 4px; --s-2: 8px; --s-3: 12px; --s-4: 16px; --s-5: 20px; --s-6: 24px; --s-8: 32px; --s-10: 40px; --s-12: 48px;
  --r: 8px; --r-2: 12px; --r-sm: 6px;
  --step: cubic-bezier(0.2, 0.7, 0.2, 1); --t-step: 140ms;
}
${['@media (prefers-color-scheme: dark) {\n  :root:not([data-theme="day"]) {', ':root[data-theme="night"] {'].map((open, i) => `${open}
  color-scheme: dark;
${nightBlock}
  --rule: rgba(176, 200, 207, 0.14);
  --rule-strong: rgba(176, 200, 207, 0.26);
  --yellow-soft: rgba(253, 180, 64, 0.15);
  --red-soft: rgba(255, 111, 111, 0.15);
  --green-soft: rgba(76, 199, 106, 0.14);
  --blue-soft: rgba(111, 177, 255, 0.14);
  --shadow-card: none;
  --shadow-pop: 0 22px 60px -10px rgba(0, 0, 0, 0.55), 0 2px 8px rgba(0, 0, 0, 0.3);
}${i === 0 ? '\n}' : ''}`).join('\n')}

html, body { margin: 0; padding: 0; }
body {
  background: var(--ground); color: var(--ink);
  font-family: var(--font-ui); font-size: var(--t-body); line-height: 1.5;
  -webkit-font-smoothing: antialiased; font-feature-settings: "tnum" 1; letter-spacing: 0.01em;
}
::selection { background: #b0efec; color: #00212a; }
:focus-visible { outline: 2px solid var(--focus); outline-offset: 1px; }
input, textarea { caret-color: var(--focus); }
a { text-underline-offset: 3px; }
::-webkit-scrollbar { width: 11px; height: 11px; }
::-webkit-scrollbar-track { background: transparent; }
::-webkit-scrollbar-thumb { background: var(--surface-4); border: 3px solid transparent; background-clip: padding-box; border-radius: 10px; }
::-webkit-scrollbar-thumb:hover { background-color: var(--ink-4); }
::-webkit-scrollbar-corner { background: transparent; }
@media (prefers-reduced-motion: reduce) { *, *::before, *::after { animation: none !important; transition: none !important; } }
`;
fs.writeFileSync(path.join(OUT, 'theme.css'), css);

// Tailwind bridge: every Material-ish token and every stock hue resolves to a CSS
// variable, so views written with Tailwind utilities re-theme with Day/Night.
const c = (k) => `rgb(var(--${k}) / <alpha-value>)`;
const colors = {
  primary: c('rgb-action'), accent: c('rgb-accent'), highlight: c('rgb-highlight'), 'primary-container': c('rgb-action'), 'on-primary': c('rgb-action-ink'),
  'primary-fixed': c('rgb-action'), 'primary-fixed-dim': c('rgb-action'), 'on-primary-container': c('rgb-action-ink'),
  'on-primary-fixed': c('rgb-action-ink'), 'on-primary-fixed-variant': c('rgb-action'), 'inverse-primary': c('rgb-action'),
  secondary: c('rgb-ink2'), 'secondary-container': c('rgb-s3'), 'on-secondary': c('rgb-ink'), 'on-secondary-container': c('rgb-ink2'),
  'secondary-fixed': c('rgb-s3'), 'secondary-fixed-dim': c('rgb-s2'), 'on-secondary-fixed': c('rgb-ink'), 'on-secondary-fixed-variant': c('rgb-ink2'),
  tertiary: c('rgb-green'), 'tertiary-container': c('rgb-green'), 'tertiary-fixed': c('rgb-green'), 'tertiary-fixed-dim': c('rgb-green'),
  'on-tertiary': c('rgb-ground'), 'on-tertiary-container': c('rgb-green'), 'on-tertiary-fixed': c('rgb-ground'), 'on-tertiary-fixed-variant': c('rgb-green'),
  error: c('rgb-red'), 'error-container': c('tw-red-100'), 'on-error': 'rgb(255 255 255 / <alpha-value>)', 'on-error-container': c('rgb-red'),
  surface: c('rgb-ground'), background: c('rgb-ground'), 'surface-bright': c('rgb-s2'), 'surface-dim': c('rgb-ground'), 'surface-tint': c('rgb-action'),
  'surface-container-lowest': c('rgb-s1'), 'surface-container-low': c('rgb-s2'), 'surface-container': c('rgb-s2'),
  'surface-container-high': c('rgb-s3'), 'surface-container-highest': c('rgb-s4'), 'surface-variant': c('rgb-s3'),
  'on-surface': c('rgb-ink'), 'on-surface-variant': c('rgb-ink2'), 'on-background': c('rgb-ink'),
  outline: c('rgb-ink3'), 'outline-variant': c('rgb-ink4'),
  'inverse-surface': c('rgb-ink'), 'inverse-on-surface': c('rgb-ground'),
};
for (const hue of Object.keys(TW)) colors[hue] = Object.fromEntries(SHADES.map((s) => [s, c(`tw-${hue}-${s}`)]));

const js = `// LC Helper — shared theme bootstrap (generated). Load in <head> before the
// Tailwind runtime. Applies the Day/Night/System choice stored by the main
// app (localStorage 'lc-helper-tweaks'.theme) and follows changes live, so
// iframes (monitoring, tools) always match the shell.
(function () {
  function apply() {
    var t = 'system';
    try { t = (JSON.parse(localStorage.getItem('lc-helper-tweaks') || '{}').theme) || 'system'; } catch (e) {}
    // ?theme=day|night overrides for one page load (screenshots, debugging).
    var q = /[?&]theme=(day|night)\\b/.exec(location.search);
    if (q) t = q[1];
    if (t === 'dark') t = 'night';
    if (t === 'light') t = 'day';
    if (t === 'night' || t === 'day') document.documentElement.dataset.theme = t;
    else delete document.documentElement.dataset.theme;
  }
  apply();
  window.addEventListener('storage', function (e) { if (e.key === 'lc-helper-tweaks') apply(); });
  window.lcApplyTheme = apply;
  window.LC_TAILWIND_CONFIG = {
    darkMode: ['selector', '[data-theme="night"]'],
    theme: {
      extend: {
        colors: ${JSON.stringify(colors, null, 2).replace(/\n/g, '\n        ')},
        // LillianCare radii: 8px default (LCRadius.defaultRadius), 12px sheets.
        borderRadius: { DEFAULT: '6px', sm: '4px', md: '6px', lg: '8px', xl: '8px', '2xl': '12px', '3xl': '12px', full: '9999px' },
        backgroundImage: { 'gradient-to-r': 'none', 'gradient-to-br': 'none', 'gradient-to-b': 'none', 'gradient-to-tr': 'none' },
        fontFamily: {
          headline: ['Manrope', '-apple-system', 'system-ui', 'sans-serif'],
          body: ['Manrope', '-apple-system', 'system-ui', 'sans-serif'],
          label: ['Manrope', '-apple-system', 'system-ui', 'sans-serif'],
          mono: ['ui-monospace', 'SF Mono', 'Menlo', 'monospace'],
        },
      },
    },
  };
})();
`;
fs.writeFileSync(path.join(OUT, 'theme.js'), js);
console.log('ok');
