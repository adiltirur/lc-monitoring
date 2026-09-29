// LC Helper — shared theme bootstrap (generated). Load in <head> before the
// Tailwind runtime. Applies the Day/Night/System choice stored by the main
// app (localStorage 'lc-helper-tweaks'.theme) and follows changes live, so
// iframes (monitoring, tools) always match the shell.
(function () {
  function apply() {
    var t = 'system';
    try { t = (JSON.parse(localStorage.getItem('lc-helper-tweaks') || '{}').theme) || 'system'; } catch (e) {}
    // ?theme=day|night overrides for one page load (screenshots, debugging).
    var q = /[?&]theme=(day|night)\b/.exec(location.search);
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
        colors: {
          "primary": "rgb(var(--rgb-action) / <alpha-value>)",
          "accent": "rgb(var(--rgb-accent) / <alpha-value>)",
          "highlight": "rgb(var(--rgb-highlight) / <alpha-value>)",
          "primary-container": "rgb(var(--rgb-action) / <alpha-value>)",
          "on-primary": "rgb(var(--rgb-action-ink) / <alpha-value>)",
          "primary-fixed": "rgb(var(--rgb-action) / <alpha-value>)",
          "primary-fixed-dim": "rgb(var(--rgb-action) / <alpha-value>)",
          "on-primary-container": "rgb(var(--rgb-action-ink) / <alpha-value>)",
          "on-primary-fixed": "rgb(var(--rgb-action-ink) / <alpha-value>)",
          "on-primary-fixed-variant": "rgb(var(--rgb-action) / <alpha-value>)",
          "inverse-primary": "rgb(var(--rgb-action) / <alpha-value>)",
          "secondary": "rgb(var(--rgb-ink2) / <alpha-value>)",
          "secondary-container": "rgb(var(--rgb-s3) / <alpha-value>)",
          "on-secondary": "rgb(var(--rgb-ink) / <alpha-value>)",
          "on-secondary-container": "rgb(var(--rgb-ink2) / <alpha-value>)",
          "secondary-fixed": "rgb(var(--rgb-s3) / <alpha-value>)",
          "secondary-fixed-dim": "rgb(var(--rgb-s2) / <alpha-value>)",
          "on-secondary-fixed": "rgb(var(--rgb-ink) / <alpha-value>)",
          "on-secondary-fixed-variant": "rgb(var(--rgb-ink2) / <alpha-value>)",
          "tertiary": "rgb(var(--rgb-green) / <alpha-value>)",
          "tertiary-container": "rgb(var(--rgb-green) / <alpha-value>)",
          "tertiary-fixed": "rgb(var(--rgb-green) / <alpha-value>)",
          "tertiary-fixed-dim": "rgb(var(--rgb-green) / <alpha-value>)",
          "on-tertiary": "rgb(var(--rgb-ground) / <alpha-value>)",
          "on-tertiary-container": "rgb(var(--rgb-green) / <alpha-value>)",
          "on-tertiary-fixed": "rgb(var(--rgb-ground) / <alpha-value>)",
          "on-tertiary-fixed-variant": "rgb(var(--rgb-green) / <alpha-value>)",
          "error": "rgb(var(--rgb-red) / <alpha-value>)",
          "error-container": "rgb(var(--tw-red-100) / <alpha-value>)",
          "on-error": "rgb(255 255 255 / <alpha-value>)",
          "on-error-container": "rgb(var(--rgb-red) / <alpha-value>)",
          "surface": "rgb(var(--rgb-ground) / <alpha-value>)",
          "background": "rgb(var(--rgb-ground) / <alpha-value>)",
          "surface-bright": "rgb(var(--rgb-s2) / <alpha-value>)",
          "surface-dim": "rgb(var(--rgb-ground) / <alpha-value>)",
          "surface-tint": "rgb(var(--rgb-action) / <alpha-value>)",
          "surface-container-lowest": "rgb(var(--rgb-s1) / <alpha-value>)",
          "surface-container-low": "rgb(var(--rgb-s2) / <alpha-value>)",
          "surface-container": "rgb(var(--rgb-s2) / <alpha-value>)",
          "surface-container-high": "rgb(var(--rgb-s3) / <alpha-value>)",
          "surface-container-highest": "rgb(var(--rgb-s4) / <alpha-value>)",
          "surface-variant": "rgb(var(--rgb-s3) / <alpha-value>)",
          "on-surface": "rgb(var(--rgb-ink) / <alpha-value>)",
          "on-surface-variant": "rgb(var(--rgb-ink2) / <alpha-value>)",
          "on-background": "rgb(var(--rgb-ink) / <alpha-value>)",
          "outline": "rgb(var(--rgb-ink3) / <alpha-value>)",
          "outline-variant": "rgb(var(--rgb-ink4) / <alpha-value>)",
          "inverse-surface": "rgb(var(--rgb-ink) / <alpha-value>)",
          "inverse-on-surface": "rgb(var(--rgb-ground) / <alpha-value>)",
          "red": {
            "50": "rgb(var(--tw-red-50) / <alpha-value>)",
            "100": "rgb(var(--tw-red-100) / <alpha-value>)",
            "200": "rgb(var(--tw-red-200) / <alpha-value>)",
            "300": "rgb(var(--tw-red-300) / <alpha-value>)",
            "400": "rgb(var(--tw-red-400) / <alpha-value>)",
            "500": "rgb(var(--tw-red-500) / <alpha-value>)",
            "600": "rgb(var(--tw-red-600) / <alpha-value>)",
            "700": "rgb(var(--tw-red-700) / <alpha-value>)",
            "800": "rgb(var(--tw-red-800) / <alpha-value>)",
            "900": "rgb(var(--tw-red-900) / <alpha-value>)"
          },
          "amber": {
            "50": "rgb(var(--tw-amber-50) / <alpha-value>)",
            "100": "rgb(var(--tw-amber-100) / <alpha-value>)",
            "200": "rgb(var(--tw-amber-200) / <alpha-value>)",
            "300": "rgb(var(--tw-amber-300) / <alpha-value>)",
            "400": "rgb(var(--tw-amber-400) / <alpha-value>)",
            "500": "rgb(var(--tw-amber-500) / <alpha-value>)",
            "600": "rgb(var(--tw-amber-600) / <alpha-value>)",
            "700": "rgb(var(--tw-amber-700) / <alpha-value>)",
            "800": "rgb(var(--tw-amber-800) / <alpha-value>)",
            "900": "rgb(var(--tw-amber-900) / <alpha-value>)"
          },
          "yellow": {
            "50": "rgb(var(--tw-yellow-50) / <alpha-value>)",
            "100": "rgb(var(--tw-yellow-100) / <alpha-value>)",
            "200": "rgb(var(--tw-yellow-200) / <alpha-value>)",
            "300": "rgb(var(--tw-yellow-300) / <alpha-value>)",
            "400": "rgb(var(--tw-yellow-400) / <alpha-value>)",
            "500": "rgb(var(--tw-yellow-500) / <alpha-value>)",
            "600": "rgb(var(--tw-yellow-600) / <alpha-value>)",
            "700": "rgb(var(--tw-yellow-700) / <alpha-value>)",
            "800": "rgb(var(--tw-yellow-800) / <alpha-value>)",
            "900": "rgb(var(--tw-yellow-900) / <alpha-value>)"
          },
          "emerald": {
            "50": "rgb(var(--tw-emerald-50) / <alpha-value>)",
            "100": "rgb(var(--tw-emerald-100) / <alpha-value>)",
            "200": "rgb(var(--tw-emerald-200) / <alpha-value>)",
            "300": "rgb(var(--tw-emerald-300) / <alpha-value>)",
            "400": "rgb(var(--tw-emerald-400) / <alpha-value>)",
            "500": "rgb(var(--tw-emerald-500) / <alpha-value>)",
            "600": "rgb(var(--tw-emerald-600) / <alpha-value>)",
            "700": "rgb(var(--tw-emerald-700) / <alpha-value>)",
            "800": "rgb(var(--tw-emerald-800) / <alpha-value>)",
            "900": "rgb(var(--tw-emerald-900) / <alpha-value>)"
          },
          "green": {
            "50": "rgb(var(--tw-green-50) / <alpha-value>)",
            "100": "rgb(var(--tw-green-100) / <alpha-value>)",
            "200": "rgb(var(--tw-green-200) / <alpha-value>)",
            "300": "rgb(var(--tw-green-300) / <alpha-value>)",
            "400": "rgb(var(--tw-green-400) / <alpha-value>)",
            "500": "rgb(var(--tw-green-500) / <alpha-value>)",
            "600": "rgb(var(--tw-green-600) / <alpha-value>)",
            "700": "rgb(var(--tw-green-700) / <alpha-value>)",
            "800": "rgb(var(--tw-green-800) / <alpha-value>)",
            "900": "rgb(var(--tw-green-900) / <alpha-value>)"
          },
          "blue": {
            "50": "rgb(var(--tw-blue-50) / <alpha-value>)",
            "100": "rgb(var(--tw-blue-100) / <alpha-value>)",
            "200": "rgb(var(--tw-blue-200) / <alpha-value>)",
            "300": "rgb(var(--tw-blue-300) / <alpha-value>)",
            "400": "rgb(var(--tw-blue-400) / <alpha-value>)",
            "500": "rgb(var(--tw-blue-500) / <alpha-value>)",
            "600": "rgb(var(--tw-blue-600) / <alpha-value>)",
            "700": "rgb(var(--tw-blue-700) / <alpha-value>)",
            "800": "rgb(var(--tw-blue-800) / <alpha-value>)",
            "900": "rgb(var(--tw-blue-900) / <alpha-value>)"
          },
          "sky": {
            "50": "rgb(var(--tw-sky-50) / <alpha-value>)",
            "100": "rgb(var(--tw-sky-100) / <alpha-value>)",
            "200": "rgb(var(--tw-sky-200) / <alpha-value>)",
            "300": "rgb(var(--tw-sky-300) / <alpha-value>)",
            "400": "rgb(var(--tw-sky-400) / <alpha-value>)",
            "500": "rgb(var(--tw-sky-500) / <alpha-value>)",
            "600": "rgb(var(--tw-sky-600) / <alpha-value>)",
            "700": "rgb(var(--tw-sky-700) / <alpha-value>)",
            "800": "rgb(var(--tw-sky-800) / <alpha-value>)",
            "900": "rgb(var(--tw-sky-900) / <alpha-value>)"
          },
          "indigo": {
            "50": "rgb(var(--tw-indigo-50) / <alpha-value>)",
            "100": "rgb(var(--tw-indigo-100) / <alpha-value>)",
            "200": "rgb(var(--tw-indigo-200) / <alpha-value>)",
            "300": "rgb(var(--tw-indigo-300) / <alpha-value>)",
            "400": "rgb(var(--tw-indigo-400) / <alpha-value>)",
            "500": "rgb(var(--tw-indigo-500) / <alpha-value>)",
            "600": "rgb(var(--tw-indigo-600) / <alpha-value>)",
            "700": "rgb(var(--tw-indigo-700) / <alpha-value>)",
            "800": "rgb(var(--tw-indigo-800) / <alpha-value>)",
            "900": "rgb(var(--tw-indigo-900) / <alpha-value>)"
          },
          "orange": {
            "50": "rgb(var(--tw-orange-50) / <alpha-value>)",
            "100": "rgb(var(--tw-orange-100) / <alpha-value>)",
            "200": "rgb(var(--tw-orange-200) / <alpha-value>)",
            "300": "rgb(var(--tw-orange-300) / <alpha-value>)",
            "400": "rgb(var(--tw-orange-400) / <alpha-value>)",
            "500": "rgb(var(--tw-orange-500) / <alpha-value>)",
            "600": "rgb(var(--tw-orange-600) / <alpha-value>)",
            "700": "rgb(var(--tw-orange-700) / <alpha-value>)",
            "800": "rgb(var(--tw-orange-800) / <alpha-value>)",
            "900": "rgb(var(--tw-orange-900) / <alpha-value>)"
          },
          "purple": {
            "50": "rgb(var(--tw-purple-50) / <alpha-value>)",
            "100": "rgb(var(--tw-purple-100) / <alpha-value>)",
            "200": "rgb(var(--tw-purple-200) / <alpha-value>)",
            "300": "rgb(var(--tw-purple-300) / <alpha-value>)",
            "400": "rgb(var(--tw-purple-400) / <alpha-value>)",
            "500": "rgb(var(--tw-purple-500) / <alpha-value>)",
            "600": "rgb(var(--tw-purple-600) / <alpha-value>)",
            "700": "rgb(var(--tw-purple-700) / <alpha-value>)",
            "800": "rgb(var(--tw-purple-800) / <alpha-value>)",
            "900": "rgb(var(--tw-purple-900) / <alpha-value>)"
          },
          "pink": {
            "50": "rgb(var(--tw-pink-50) / <alpha-value>)",
            "100": "rgb(var(--tw-pink-100) / <alpha-value>)",
            "200": "rgb(var(--tw-pink-200) / <alpha-value>)",
            "300": "rgb(var(--tw-pink-300) / <alpha-value>)",
            "400": "rgb(var(--tw-pink-400) / <alpha-value>)",
            "500": "rgb(var(--tw-pink-500) / <alpha-value>)",
            "600": "rgb(var(--tw-pink-600) / <alpha-value>)",
            "700": "rgb(var(--tw-pink-700) / <alpha-value>)",
            "800": "rgb(var(--tw-pink-800) / <alpha-value>)",
            "900": "rgb(var(--tw-pink-900) / <alpha-value>)"
          },
          "slate": {
            "50": "rgb(var(--tw-slate-50) / <alpha-value>)",
            "100": "rgb(var(--tw-slate-100) / <alpha-value>)",
            "200": "rgb(var(--tw-slate-200) / <alpha-value>)",
            "300": "rgb(var(--tw-slate-300) / <alpha-value>)",
            "400": "rgb(var(--tw-slate-400) / <alpha-value>)",
            "500": "rgb(var(--tw-slate-500) / <alpha-value>)",
            "600": "rgb(var(--tw-slate-600) / <alpha-value>)",
            "700": "rgb(var(--tw-slate-700) / <alpha-value>)",
            "800": "rgb(var(--tw-slate-800) / <alpha-value>)",
            "900": "rgb(var(--tw-slate-900) / <alpha-value>)"
          },
          "gray": {
            "50": "rgb(var(--tw-gray-50) / <alpha-value>)",
            "100": "rgb(var(--tw-gray-100) / <alpha-value>)",
            "200": "rgb(var(--tw-gray-200) / <alpha-value>)",
            "300": "rgb(var(--tw-gray-300) / <alpha-value>)",
            "400": "rgb(var(--tw-gray-400) / <alpha-value>)",
            "500": "rgb(var(--tw-gray-500) / <alpha-value>)",
            "600": "rgb(var(--tw-gray-600) / <alpha-value>)",
            "700": "rgb(var(--tw-gray-700) / <alpha-value>)",
            "800": "rgb(var(--tw-gray-800) / <alpha-value>)",
            "900": "rgb(var(--tw-gray-900) / <alpha-value>)"
          }
        },
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
