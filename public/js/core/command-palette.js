// ═════════════════════════════════════════════════════════════════════════
// COMMAND PALETTE
// ═════════════════════════════════════════════════════════════════════════
const CMDK = [
  { sec:'Navigate', icon:'radar',          label:'Monitor',          crumb:'',        kbd:'M', run: () => navigate('monitoring') },
  { sec:'Navigate', icon:'favorite',       label:'Server Health',    crumb:'',                 run: () => navigate('health') },
  { sec:'Navigate', icon:'terminal',       label:'Session Logs',     crumb:'',       kbd:'S', run: () => navigate('session-logs') },
  { sec:'Navigate', icon:'shield',         label:'Admin Audit',      crumb:'',                  run: () => navigate('admin-audit') },
  { sec:'Navigate', icon:'notifications',  label:'Notifications',    crumb:'',          run: () => navigate('notifications') },
  { sec:'Navigate', icon:'person',         label:'Users',            crumb:'',          kbd:'U', run: () => navigate('users') },
  { sec:'Navigate', icon:'calendar_today', label:'Bookings',         crumb:'',               run: () => navigate('bookings') },
  { sec:'Navigate', icon:'database',       label:'Query Runner',     crumb:'',          kbd:'Q', run: () => navigate('query-runner') },
  { sec:'Navigate', icon:'api',            label:'API Console',      crumb:'',                   run: () => navigate('api-console') },
  { sec:'Navigate', icon:'neurology',      label:'AI Assistant',     crumb:'',                     run: () => navigate('ai-query') },
  { sec:'Navigate', icon:'campaign',       label:'Send Notification',crumb:'',                   run: () => navigate('send-notification') },
  { sec:'Navigate', icon:'schedule',       label:'Future Calls',     crumb:'',                  run: () => navigate('future-calls') },
  { sec:'Navigate', icon:'key',            label:'API Keys',         crumb:'',                   run: () => navigate('api-keys') },
  { sec:'Navigate', icon:'lock_open',      label:'CSV Decryptor',    crumb:'',                  run: () => navigate('csv-decrypt') },
  { sec:'Navigate', icon:'storefront',     label:'Google Business',  crumb:'',                    run: () => navigate('google-business') },
  { sec:'Navigate', icon:'sync_alt',       label:'Praxis Refresh',   crumb:'',                run: () => navigate('praxis-refresh') },
  { sec:'Navigate', icon:'grid_on',        label:'Cockpit Fill',     crumb:'',                run: () => navigate('cockpit-fill') },
  { sec:'Navigate', icon:'swap_horiz',     label:'Cockpit Sync',     crumb:'',           run: () => navigate('cockpit-sync') },
  { sec:'Navigate', icon:'delete_sweep',   label:'Praxis Cleanup',   crumb:'',                run: () => navigate('praxis-cleanup') },
  { sec:'Navigate', icon:'fact_check',     label:'Personio Audit',   crumb:'',         run: () => navigate('personio-audit') },
  { sec:'Navigate', icon:'settings_backup_restore', label:'RDS Restore', crumb:'',         run: () => navigate('rds-restore') },
  { sec:'Navigate', icon:'restart_alt',    label:'DB Refresh',       crumb:'',           run: () => navigate('db-refresh') },
  { sec:'Navigate', icon:'rocket_launch',  label:'Build & Release',  crumb:'',           run: () => navigate('release') },
  { sec:'Navigate', icon:'vpn_key',        label:'SSH Tunnels',      crumb:'',            run: () => navigate('ssh-tunnels') },

  { sec:'Actions',  icon:'search',     label:'Find user by email, phone, or ID', crumb:'Go → Users',   run: () => navigate('users') },
  { sec:'Actions',  icon:'play_arrow', label:'New SQL query',                    crumb:'Query Runner', run: () => navigate('query-runner') },
  { sec:'Actions',  icon:'send',       label:'Send operational push',            crumb:'Operations',   run: () => navigate('send-notification') },
  { sec:'Actions',  icon:'lock_open',  label:'Decrypt guest CSV',                crumb:'Vault',        run: () => navigate('csv-decrypt') },
  { sec:'Actions',  icon:'refresh',    label:'Reload current view',              crumb:'Refresh',      run: () => navigate(window.__currentView || 'monitoring') },

  { sec:'Switch',   icon:'cloud', label:'dev',        crumb:'ENV · local', run: () => switchEnvPreset('dev') },
  { sec:'Switch',   icon:'cloud', label:'test',       crumb:'ENV',         run: () => switchEnvPreset('test') },
  { sec:'Switch',   icon:'cloud', label:'staging',    crumb:'ENV',         run: () => switchEnvPreset('staging') },
  { sec:'Switch',   icon:'cloud', label:'production', crumb:'ENV · confirm', run: () => { if (confirm('Connect to the PRODUCTION database?\n\nEvery write in LC Helper will change live patient data.')) switchEnvPreset('production'); } },
  { sec:'Navigate', icon:'dns', label:'Local Stack', crumb:'Serverpod · Docker', kbd:'L', run: () => navigate('local-stack') },
  { sec:'Actions',  icon:'restart_alt', label:'Restart local Serverpod', crumb:'Local Stack', run: () => lsAction('restart') },
];

function switchEnvPreset(preset) {
  const el = document.getElementById('cfPreset');
  if (!el) return;
  el.value = preset;
  applyPreset();
  saveConnection();
  showToast('Switched ENV · ' + preset, 'ok');
}

const cmdkEl = document.getElementById('cmdk');
const cmdkInput = document.getElementById('cmdkInput');
const cmdkList = document.getElementById('cmdkList');
let cmdkFocus = 0;

function renderCmdk(q = '') {
  const query = q.trim().toLowerCase();
  const items = CMDK.filter(c => !query || (c.label + ' ' + c.crumb).toLowerCase().includes(query));
  const grouped = {};
  items.forEach(c => (grouped[c.sec] ||= []).push(c));
  cmdkList.innerHTML = Object.entries(grouped).map(([sec, arr]) => `
    <div class="cmdk-sec">${sec}</div>
    ${arr.map((c) => `
      <div class="cmdk-item" data-idx="${items.indexOf(c)}">
        <span class="material-symbols-outlined">${c.icon}</span>
        <span>${escHtml(c.label)}</span>
        <span class="crumb">${escHtml(c.crumb)}</span>
        ${c.kbd ? `<span class="kbd-hint"><span class="kbd">${c.kbd}</span></span>` : ''}
      </div>`).join('')}
  `).join('');
  cmdkFocus = 0;
  updateCmdkFocus();
  cmdkList.querySelectorAll('.cmdk-item').forEach(el => {
    el.addEventListener('click', () => { items[+el.dataset.idx].run(); closeCmdk(); });
    el.addEventListener('mouseenter', () => { cmdkFocus = +el.dataset.idx; updateCmdkFocus(); });
  });
  cmdkEl._items = items;
}
function updateCmdkFocus() {
  cmdkList.querySelectorAll('.cmdk-item').forEach(el => {
    el.classList.toggle('focus', +el.dataset.idx === cmdkFocus);
  });
  const f = cmdkList.querySelector('.cmdk-item.focus');
  if (f) f.scrollIntoView({ block: 'nearest' });
}
function openCmdk() { cmdkEl.classList.add('open'); cmdkInput.value = ''; renderCmdk(); setTimeout(() => cmdkInput.focus(), 50); }
function closeCmdk() { cmdkEl.classList.remove('open'); }
document.getElementById('openCmdK').addEventListener('click', openCmdk);
cmdkEl.addEventListener('click', e => { if (e.target === cmdkEl) closeCmdk(); });
cmdkInput.addEventListener('input', () => renderCmdk(cmdkInput.value));
cmdkInput.addEventListener('keydown', e => {
  const items = cmdkEl._items || [];
  if (e.key === 'Escape') closeCmdk();
  if (e.key === 'ArrowDown') { e.preventDefault(); cmdkFocus = Math.min(items.length - 1, cmdkFocus + 1); updateCmdkFocus(); }
  if (e.key === 'ArrowUp')   { e.preventDefault(); cmdkFocus = Math.max(0, cmdkFocus - 1); updateCmdkFocus(); }
  if (e.key === 'Enter')     { if (items[cmdkFocus]) { items[cmdkFocus].run(); closeCmdk(); } }
});
document.addEventListener('keydown', e => {
  if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
    e.preventDefault();
    cmdkEl.classList.contains('open') ? closeCmdk() : openCmdk();
  }
  if (e.key === 'Escape' && cmdkEl.classList.contains('open')) closeCmdk();
  // single-key jumps when palette is closed and no input is focused
  if (!cmdkEl.classList.contains('open') && !['INPUT','TEXTAREA','SELECT'].includes(document.activeElement.tagName)) {
    const map = { m:'monitoring', s:'session-logs', u:'users', q:'query-runner', l:'local-stack' };
    if (map[e.key.toLowerCase()]) navigate(map[e.key.toLowerCase()]);
  }
});
