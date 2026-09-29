function toggleConfig() {
  const body = document.getElementById('configBody');
  body.classList.toggle('open');
}
// Close popover on outside click
document.addEventListener('click', (e) => {
  const pop = document.getElementById('configBody');
  const env = document.getElementById('envBtn');
  if (!pop || !pop.classList.contains('open')) return;
  if (env && env.contains(e.target)) return;
  if (pop.contains(e.target)) return;
  pop.classList.remove('open');
});

function applyPreset() {
  const val = document.getElementById('cfPreset').value;
  const p = PRESETS[val];
  if (!p) return;
  document.getElementById('cfHost').value = p.host;
  document.getElementById('cfPort').value = p.port;
  document.getElementById('cfDb').value = p.db;
  document.getElementById('cfUser').value = p.user;
  document.getElementById('cfPass').value = (envConfig && envConfig.passwords && envConfig.passwords[val]) || '';
  if (envConfig && envConfig.decryptKeys && envConfig.decryptKeys[val]) {
    localStorage.setItem('bk_dec_key', envConfig.decryptKeys[val]);
  }
}

async function testConnection() {
  const cfg = readConfigForm();
  try {
    const res = await fetch('/api/connection-test', { headers: { 'x-db-host': cfg.host, 'x-db-port': cfg.port, 'x-db-name': cfg.db, 'x-db-user': cfg.user, 'x-db-password': cfg.pass } });
    const data = await res.json();
    if (data.ok) showToast('✅ Connection successful');
    else showToast('❌ Connection failed: ' + data.error);
  } catch(e) { showToast('❌ ' + e.message); }
}

function readConfigForm() {
  return {
    host: document.getElementById('cfHost').value,
    port: document.getElementById('cfPort').value,
    db:   document.getElementById('cfDb').value,
    user: document.getElementById('cfUser').value,
    pass: document.getElementById('cfPass').value,
  };
}

function saveConnection() {
  const cfg = readConfigForm();
  localStorage.setItem('lc_db', JSON.stringify(cfg));
  // Invalidate cached praxis names — different env → different DB.
  window._praxisNames = {};
  window._praxisNamesPromise = null;
  loadPraxisNames();
  const preset = document.getElementById('cfPreset').value;
  setEnvDisplay(preset, cfg);
  toggleConfig();
  setConnStatus('connected');
  const view = window.location.hash.replace('#','') || 'monitoring';
  navigate(view);
}

function setConnStatus(state) {
  const dot = document.getElementById('connStatus');
  if (!dot) return;
  dot.className = 'dot live ' + (state === 'connected' ? 'ok' : state === 'error' ? 'err' : '');
}

function loadConfigFromStorage() {
  const cfg = getCfg();
  document.getElementById('cfHost').value = cfg.host || 'localhost';
  document.getElementById('cfPort').value = cfg.port || '8090';
  document.getElementById('cfDb').value   = cfg.db   || 'lillian_care_core';
  document.getElementById('cfUser').value = cfg.user || 'postgres';
  document.getElementById('cfPass').value = cfg.pass || '';
  // Pick the matching preset
  let matched = 'custom';
  for (const [k, p] of Object.entries(PRESETS)) {
    if (cfg.host === p.host && String(cfg.port) === String(p.port) && cfg.db === p.db) {
      document.getElementById('cfPreset').value = k;
      matched = k;
      break;
    }
  }
  if (matched === 'custom') document.getElementById('cfPreset').value = 'custom';
  setEnvDisplay(matched, cfg);
}

// The header plate is the platform number: 1 dev · 2 test · 3 staging · 4 prod.
// Production turns the whole platform display into a red disruption band, and
// the native Mac shell (if present) tints its window chrome to match.
const ENV_PLATE = { dev: '1', test: '2', staging: '3', production: '4', custom: 'C' };
function setEnvDisplay(preset, cfg) {
  const envBtn = document.getElementById('envBtn');
  // dbHeaders() reads envBtn.dataset.env as the x-env-label; custom stays 'dev' as before.
  if (envBtn) envBtn.dataset.env = preset === 'custom' ? 'dev' : preset;
  const prev = document.documentElement.dataset.env;
  document.documentElement.dataset.env = preset;
  const plate = document.getElementById('envPlate');
  if (plate) {
    plate.textContent = ENV_PLATE[preset] || 'C';
    if (prev && prev !== preset) { plate.classList.remove('env-flip'); void plate.offsetWidth; plate.classList.add('env-flip'); }
  }
  const envName = document.getElementById('envName');
  if (envName) envName.textContent = preset === 'production' ? 'Production' : preset;
  const label = document.getElementById('connLabel');
  if (label && cfg) label.textContent = `${cfg.host}:${cfg.port}/${cfg.db}`;
  syncPresetButtons();
  try { window.lcNative && window.lcNative.post('setEnv', { env: preset }); } catch {}
}

function syncPresetButtons() {
  const cur = document.getElementById('cfPreset')?.value;
  document.querySelectorAll('#envPresets .env-preset').forEach(b => b.classList.toggle('on', b.dataset.p === cur));
}

function pickPreset(preset) {
  if (preset === 'production' && !confirm('Connect to the PRODUCTION database?\n\nEvery write in LC Helper will change live patient data.')) return;
  document.getElementById('cfPreset').value = preset;
  applyPreset();
  saveConnection();
}
