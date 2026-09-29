// ═════════════════════════════════════════════════════════════════════════
// SEND NOTIFICATION
// ═════════════════════════════════════════════════════════════════════════
let fcmConfigured = false;
let snSelectedTokens = [];

async function renderSendNotification(el) {
  el.innerHTML = pageWrap(pageHero('Send Notification') + loadingState());
  const cfg = await apiFetch('/api/fcm/config');
  fcmConfigured = cfg.configured;

  const setupCard = !fcmConfigured ? `
    <section class="bg-surface-container-lowest rounded-xl shadow-whisper p-6 mb-6 border-l-4 border-amber-400">
      <div class="flex items-center gap-3 mb-4">
        <span class="material-symbols-outlined text-amber-600 text-2xl">settings</span>
        <h3 class="font-bold text-lg tracking-tight">Firebase Setup Required</h3>
      </div>
      <p class="text-sm text-on-surface-variant mb-4">Paste your Firebase service account JSON to enable push notifications. Get it from Firebase Console → Project Settings → Service Accounts → Generate new private key.</p>
      <textarea id="fcmJson" placeholder='{"type":"service_account","project_id":"..."}' class="w-full min-h-[140px] bg-surface-container-low border border-outline-variant rounded-lg p-3 mono-text text-xs focus:ring-2 focus:ring-primary-fixed focus:border-primary outline-none resize-y"></textarea>
      <div class="mt-4">${btnPrimary('Save Configuration', 'saveFcmConfig()')}</div>
    </section>` : `
    <section class="bg-surface-container-lowest rounded-xl shadow-whisper p-4 mb-6 border-l-4 border-tertiary flex items-center gap-3">
      <span class="w-2.5 h-2.5 rounded-full bg-tertiary pulse-dot"></span>
      <span class="text-sm">Firebase configured · project <strong>${escHtml(cfg.projectId)}</strong></span>
      <button class="ml-auto px-3 py-1 text-xs font-bold text-on-surface-variant hover:bg-surface-container rounded transition-colors" onclick="clearFcmConfig()">Change</button>
    </section>`;

  el.innerHTML = pageWrap(
    pageHero('Send Notification', { sub: 'Push notifications via Firebase Cloud Messaging' }) +
    setupCard +
    `<div class="grid grid-cols-1 lg:grid-cols-2 gap-6 ${!fcmConfigured ? 'opacity-50 pointer-events-none' : ''}">
      <section class="bg-surface-container-lowest rounded-xl shadow-whisper p-6">
        <div class="flex justify-between items-start mb-6">
          <div>
            <h2 class="text-lg font-bold tracking-tight mb-1">Compose</h2>
            <div class="flex items-center gap-2 text-xs text-on-surface-variant mono-text">
              <span class="w-2 h-2 rounded-full bg-tertiary"></span>
              <span>Firebase ready · ${escHtml(cfg.projectId||'—')}</span>
            </div>
          </div>
          <span class="material-symbols-outlined text-slate-300">send</span>
        </div>
        <div class="space-y-4">
          <div>
            <label class="block text-[10px] uppercase tracking-wider font-bold text-on-surface-variant mb-1.5">Recipient Search</label>
            <div class="flex gap-2">
              <input id="snUserSearch" placeholder="name / email / phone" class="flex-1 bg-surface-container border-none rounded-lg text-sm px-3 py-2.5 focus:ring-2 focus:ring-primary-fixed mono-text" onkeydown="if(event.key==='Enter')searchNotifUser()">
              <button class="px-4 py-2 bg-surface-container-high text-on-surface-variant rounded-lg text-xs font-bold hover:bg-surface-variant" onclick="searchNotifUser()">Search</button>
            </div>
            <div id="snUserResults" class="mt-2"></div>
          </div>
          <div id="snTokenSection" class="hidden">
            <label class="block text-[10px] uppercase tracking-wider font-bold text-on-surface-variant mb-2">Devices</label>
            <div id="snTokenList" class="space-y-2"></div>
          </div>
          <div>
            <label class="block text-[10px] uppercase tracking-wider font-bold text-on-surface-variant mb-1.5">Title</label>
            <input id="snTitle" placeholder="Notification title" class="w-full bg-surface-container border-none rounded-lg text-sm px-3 py-2.5 focus:ring-2 focus:ring-primary-fixed font-medium">
          </div>
          <div>
            <label class="block text-[10px] uppercase tracking-wider font-bold text-on-surface-variant mb-1.5">Body</label>
            <textarea id="snBody" placeholder="Notification message" rows="3" class="w-full bg-surface-container border-none rounded-lg text-sm px-3 py-2.5 focus:ring-2 focus:ring-primary-fixed resize-none"></textarea>
          </div>
          <div class="pt-2 flex items-center justify-between">
            <button id="snSendBtn" class="px-6 py-2.5 bg-gradient-to-br from-primary to-primary-container text-on-primary rounded-lg text-sm font-bold shadow-md shadow-primary/20 active:scale-95 transition-transform flex items-center gap-2 disabled:opacity-30 disabled:cursor-not-allowed" onclick="sendNotification()" disabled>
              <span class="material-symbols-outlined text-sm ms-fill">send</span>Send Notification
            </button>
            <div id="snResult"></div>
          </div>
        </div>
      </section>
      <section class="bg-surface-container-lowest rounded-xl shadow-whisper p-6">
        <h2 class="text-lg font-bold tracking-tight mb-4">Tips</h2>
        <ul class="space-y-3 text-sm text-on-surface-variant">
          <li class="flex gap-3"><span class="material-symbols-outlined text-primary text-lg">info</span>Title appears bold above the body in the system tray.</li>
          <li class="flex gap-3"><span class="material-symbols-outlined text-primary text-lg">info</span>Test on staging first — push targets real devices.</li>
          <li class="flex gap-3"><span class="material-symbols-outlined text-primary text-lg">info</span>Tokens older than 270 days may have rotated.</li>
        </ul>
      </section>
    </div>`
  );
}

async function saveFcmConfig() {
  const json = document.getElementById('fcmJson').value.trim();
  if (!json) { showToast('Paste your service account JSON first'); return; }
  try {
    const res = await fetch('/api/fcm/config', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ serviceAccount: json }) });
    const data = await res.json();
    if (data.error) { showToast('Error: ' + data.error); return; }
    renderSendNotification(document.getElementById('content'));
  } catch(e) { showToast('Error: ' + e.message); }
}

async function clearFcmConfig() {
  await fetch('/api/fcm/config', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ serviceAccount: '{}' }) });
  renderSendNotification(document.getElementById('content'));
}

async function searchNotifUser() {
  const q = document.getElementById('snUserSearch').value.trim();
  if (!q) return;
  const data = await apiFetch(`/api/users?q=${encodeURIComponent(q)}&pageSize=5`);
  const resultsEl = document.getElementById('snUserResults');
  if (!data.rows.length) { resultsEl.innerHTML = `<div class="text-sm text-outline italic">No users found</div>`; return; }
  resultsEl.innerHTML = `<div class="bg-white border border-slate-100 rounded-lg shadow-md overflow-hidden divide-y divide-slate-50">${data.rows.map(u => {
    const initials = ((u.firstName||'?').charAt(0) + (u.lastName||'').charAt(0)).toUpperCase();
    return `<div class="p-2 hover:bg-indigo-50 cursor-pointer flex items-center gap-3" onclick="selectNotifUser(${u.id}, '${escHtml(u.firstName||'')} ${escHtml(u.lastName||'')}')">
      <div class="w-7 h-7 rounded-full bg-indigo-100 text-indigo-600 flex items-center justify-center text-[10px] font-bold">${escHtml(initials)}</div>
      <div class="flex-1">
        <div class="text-xs font-semibold">${escHtml(u.firstName||'')} ${escHtml(u.lastName||'')}</div>
        <div class="text-[10px] text-on-surface-variant">${escHtml(u.email)} · ${escHtml(praxisName(u.praxisId) || u.praxisId || '')}</div>
      </div>
      <span class="text-[10px] mono-text text-outline">ID ${u.id}</span>
    </div>`;
  }).join('')}</div>`;
}

async function selectNotifUser(userId, name) {
  document.getElementById('snUserResults').innerHTML = `<div class="text-sm text-tertiary font-bold flex items-center gap-2"><span class="material-symbols-outlined text-base ms-fill">check_circle</span>${escHtml(name)}</div>`;
  const tokens = await apiFetch(`/api/users/${userId}/tokens`);
  const tokenSection = document.getElementById('snTokenSection');
  const tokenList = document.getElementById('snTokenList');
  snSelectedTokens = tokens.map(t => t.token);
  tokenSection.classList.remove('hidden');
  if (!tokens.length) {
    tokenList.innerHTML = `<div class="text-sm text-outline italic">No device tokens for this user</div>`;
    document.getElementById('snSendBtn').disabled = true;
    return;
  }
  tokenList.innerHTML = tokens.map(t => {
    const colorMap = { ios: 'blue', android: 'emerald' };
    const c = colorMap[t.platform] || 'slate';
    return `<label class="flex items-center gap-3 p-3 bg-surface-container-low rounded-lg hover:bg-surface-container cursor-pointer">
      <input type="checkbox" checked data-token="${escHtml(t.token)}" onchange="updateSnTokens()" class="w-4 h-4 rounded text-primary border-slate-300 focus:ring-primary">
      ${statusBadge(t.platform, c)}
      <span class="text-xs text-on-surface-variant flex-1 mono-text">${escHtml(t.deviceId)}</span>
      <span class="text-[10px] text-outline">last used ${escHtml(deTime(t.lastUsedAt))}</span>
    </label>`;
  }).join('');
  document.getElementById('snSendBtn').disabled = false;
}

function updateSnTokens() {
  snSelectedTokens = [...document.querySelectorAll('#snTokenList input[type=checkbox]:checked')].map(cb => cb.dataset.token);
  document.getElementById('snSendBtn').disabled = !snSelectedTokens.length;
}

async function sendNotification() {
  const title = document.getElementById('snTitle').value.trim();
  const body = document.getElementById('snBody').value.trim();
  if (!title || !body) { showToast('Title and body are required'); return; }
  if (!snSelectedTokens.length) { showToast('No tokens selected'); return; }
  if (!confirm(`Send "${title}" to ${snSelectedTokens.length} device(s)?`)) return;

  document.getElementById('snSendBtn').disabled = true;
  const resultEl = document.getElementById('snResult');
  resultEl.innerHTML = `<span class="text-xs text-on-surface-variant">Sending…</span>`;

  try {
    const data = await apiPost('/api/fcm/send', { tokens: snSelectedTokens, title, body });
    if (data.error) {
      resultEl.innerHTML = `<span class="text-xs text-error font-bold">${escHtml(data.error)}</span>`;
    } else {
      resultEl.innerHTML = `<span class="text-xs text-tertiary font-bold flex items-center gap-1"><span class="material-symbols-outlined text-sm ms-fill">check_circle</span>Sent to ${data.sent} device(s)${data.failed ? ` · ${data.failed} failed` : ''}</span>`;
    }
  } catch(e) { resultEl.innerHTML = `<span class="text-xs text-error font-bold">${escHtml(e.message)}</span>`; }
  document.getElementById('snSendBtn').disabled = false;
}
