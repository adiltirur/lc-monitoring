// ═════════════════════════════════════════════════════════════════════════
// INIT
// ═════════════════════════════════════════════════════════════════════════
applyTweaks();
syncTweaksUI();
loadConfigFromStorage();
tickClocks();
const tzEl = document.getElementById('tzDisplay');
if (tzEl) tzEl.textContent = LOCAL_TZ;
const initView = window.location.hash.replace('#', '') || 'monitoring';
// Wait for env-config (fast, local) so the first view's API calls already
// carry a healed password — see getCfg(). Renders regardless on failure.
envConfigPromise.then(() => navigate(initView));
// Back/forward and the Mac shell's Go menu change the hash directly.
window.addEventListener('hashchange', () => {
  if (window.__navFromCode) { window.__navFromCode = false; return; }
  const v = window.location.hash.replace('#', '');
  if (v && v !== window.__currentView) navigate(v);
});
