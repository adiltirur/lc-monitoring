// ═════════════════════════════════════════════════════════════════════════
// GOOGLE BUSINESS PROFILE
// Connect → list accounts → list locations → edit regularHours.
// Doesn't use dbHeaders(): /api/gbp/* routes don't need Postgres credentials.
// ═════════════════════════════════════════════════════════════════════════
const GBP_DAY_ORDER = ['MONDAY','TUESDAY','WEDNESDAY','THURSDAY','FRIDAY','SATURDAY','SUNDAY'];
const GBP_DAY_LABEL = { MONDAY:'Mon', TUESDAY:'Tue', WEDNESDAY:'Wed', THURSDAY:'Thu', FRIDAY:'Fri', SATURDAY:'Sat', SUNDAY:'Sun' };
const GBP_WEEKDAY_TEMPLATE = { MONDAY:['09:00','18:00'], TUESDAY:['09:00','18:00'], WEDNESDAY:['09:00','18:00'], THURSDAY:['09:00','18:00'], FRIDAY:['09:00','18:00'], SATURDAY:['10:00','14:00'] };
let _gbpAccounts = [];
let _gbpLocations = [];
let _gbpEditingName = null; // locations/... currently being edited
let _gbpEditBuffer = {};    // { MONDAY:['09:00','18:00'], ... }
let _gbpMessageHandler = null;

async function gbpApi(path, opts = {}) {
  const res = await fetch(path, { ...opts, headers: { 'Content-Type': 'application/json', ...(opts.headers || {}) } });
  const body = await res.json().catch(() => null);
  if (!res.ok) throw new Error((body && body.error) || `HTTP ${res.status}`);
  return body;
}

function gbpHoursSummary(simple) {
  const entries = GBP_DAY_ORDER
    .filter(d => simple && simple[d])
    .map(d => `${GBP_DAY_LABEL[d]} ${simple[d][0]}–${simple[d][1]}`);
  if (!entries.length) return '<span class="label" style="opacity:.5">Closed / not set</span>';
  return entries.join(' · ');
}

async function renderGoogleBusiness(el) {
  el.innerHTML = pageWrap(pageHero('Google Business') + loadingState());
  if (_gbpMessageHandler) { window.removeEventListener('message', _gbpMessageHandler); _gbpMessageHandler = null; }
  try {
    const status = await gbpApi('/api/gbp/status');

    if (!status.clientConfigured) {
      el.innerHTML = pageWrap(
        pageHero('Google Business', { sub: 'OAuth credentials required' }) +
        `<div class="panel" style="margin-bottom:var(--s-4);border-color:var(--warn-faint,#6a4d19);background:rgba(255,180,60,.04)">
          <div class="panel-body" style="display:flex;gap:var(--s-3);align-items:flex-start">
            <span class="material-symbols-outlined" style="color:var(--warn,#f0a640);margin-top:2px">key_off</span>
            <div style="flex:1">
              <div class="label" style="margin-bottom:6px">GBP credentials not configured</div>
              <div style="font-size:13px;line-height:1.55;color:var(--fg-muted,#9a9aa0)">
                Set <span class="mono">GBP_CLIENT_ID</span> and <span class="mono">GBP_CLIENT_SECRET</span> in
                <span class="mono">.env</span>, then restart the helper. The full Google Cloud Console setup
                (enable APIs, OAuth consent, Web application client, redirect URI) is documented in
                <span class="mono">.env.example</span>.
                <div style="margin-top:10px">Authorized redirect URI to register in Google Cloud:</div>
                <div class="mono" style="margin-top:4px;padding:8px 10px;background:var(--surface-2);border-radius:6px;font-size:12px;word-break:break-all">${escHtml(status.redirectUri)}</div>
              </div>
            </div>
          </div>
        </div>`
      );
      return;
    }

    if (!status.connected) {
      _gbpMessageHandler = (ev) => {
        if (ev && ev.data && ev.data.type === 'gbp-connected') {
          window.removeEventListener('message', _gbpMessageHandler);
          _gbpMessageHandler = null;
          renderGoogleBusiness(document.getElementById('content'));
        }
      };
      window.addEventListener('message', _gbpMessageHandler);

      el.innerHTML = pageWrap(
        pageHero('Google Business', { sub: 'Connect a Google account to manage locations' }) +
        `<div class="panel" style="margin-bottom:var(--s-4)">
          <div class="panel-body" style="display:flex;flex-direction:column;gap:var(--s-3);align-items:flex-start">
            <div style="font-size:13px;line-height:1.55;color:var(--fg-muted,#9a9aa0);max-width:640px">
              Sign in with the Google account that owns or manages the Business Profile. A popup will open for
              consent; tokens are stored locally in <span class="mono">.gbp_token.json</span> (gitignored) and
              refreshed automatically.
            </div>
            <button class="btn btn-primary" onclick="gbpConnect()">
              <span class="material-symbols-outlined">link</span>Connect Google Business
            </button>
          </div>
        </div>`
      );
      return;
    }

    // Connected: load accounts.
    const acctResp = await gbpApi('/api/gbp/accounts');
    _gbpAccounts = acctResp.accounts || [];

    const heroActions = `
      <button class="btn" onclick="gbpDisconnect()">
        <span class="material-symbols-outlined">logout</span>Disconnect
      </button>`;

    if (!_gbpAccounts.length) {
      el.innerHTML = pageWrap(
        pageHero('Google Business', { sub: 'Connected · 0 accounts visible', actions: heroActions }) +
        emptyState('No GBP accounts visible to this Google user. Check that the signed-in account has access to a Business Profile.', 'storefront')
      );
      return;
    }

    const accountOptions = _gbpAccounts.map(a => ({
      value: a.name,
      label: `${a.accountName || a.name} · ${a.name}`,
    }));
    const firstAccount = _gbpAccounts[0].name;

    el.innerHTML = pageWrap(
      pageHero('Google Business', { sub: `Connected · ${_gbpAccounts.length} account${_gbpAccounts.length === 1 ? '' : 's'}`, actions: heroActions }) +
      filterCard(
        fSelect('Account', accountOptions, `id="gbpAccount" onchange="gbpLoadLocations()"`, firstAccount) +
        `<div class="field" style="grid-column:span 3"><label class="field-label">Hours template</label>
          <div class="row-sm" style="gap:6px">
            <button class="btn btn-sm" onclick="gbpApplyTemplate('weekday')">
              <span class="material-symbols-outlined">bolt</span>Weekday 9–18 + Sat 10–14
            </button>
            <button class="btn btn-sm" onclick="gbpApplyTemplate('clear')">
              <span class="material-symbols-outlined">clear_all</span>Clear (all closed)
            </button>
          </div>
        </div>`,
      4) +
      `<div id="gbpLocations">${loadingState('Loading locations…')}</div>`
    );
    gbpLoadLocations();
  } catch (e) {
    el.innerHTML = pageWrap(pageHero('Google Business') + errorState(e.message));
  }
}

function gbpConnect() {
  window.open('/api/gbp/oauth/start', 'gbp-auth', 'width=520,height=720');
}

async function gbpDisconnect() {
  if (!confirm('Disconnect Google Business? You will need to re-auth to manage locations again.')) return;
  try {
    await gbpApi('/api/gbp/disconnect', { method: 'POST' });
    showToast('✓ Disconnected from Google Business');
    renderGoogleBusiness(document.getElementById('content'));
  } catch (e) { showToast('❌ ' + e.message); }
}

async function gbpLoadLocations() {
  const account = document.getElementById('gbpAccount').value;
  const target = document.getElementById('gbpLocations');
  target.innerHTML = loadingState('Loading locations…');
  try {
    const data = await gbpApi(`/api/gbp/locations?account=${encodeURIComponent(account)}`);
    _gbpLocations = data.locations || [];
    gbpRenderLocationsTable();
  } catch (e) {
    target.innerHTML = errorState(e.message);
  }
}

function gbpRenderLocationsTable() {
  const target = document.getElementById('gbpLocations');
  if (!_gbpLocations.length) {
    target.innerHTML = emptyState('No locations found for this account.', 'storefront');
    return;
  }
  const rows = _gbpLocations.map(loc => {
    if (_gbpEditingName === loc.name) {
      return gbpEditorRow(loc);
    }
    return `<tr>
      <td style="padding:10px 14px">
        <div style="font-weight:600">${escHtml(loc.title || '—')}</div>
        <div class="mono" style="font-size:11px;opacity:.6">${escHtml(loc.name)}</div>
      </td>
      <td style="padding:10px 14px;font-size:12px;opacity:.75">${escHtml(loc.address || '—')}</td>
      <td style="padding:10px 14px;font-size:12px">${gbpHoursSummary(loc.hoursSimple)}</td>
      <td style="padding:10px 14px;text-align:right">
        <button class="btn btn-sm" onclick="gbpStartEdit('${escHtml(loc.name)}')">
          <span class="material-symbols-outlined">edit</span>Edit
        </button>
      </td>
    </tr>`;
  }).join('');
  target.innerHTML = tableShell(['Location', 'Address', 'Regular hours', ''], rows);
}

function gbpStartEdit(name) {
  const loc = _gbpLocations.find(l => l.name === name);
  if (!loc) return;
  _gbpEditingName = name;
  _gbpEditBuffer = { ...(loc.hoursSimple || {}) };
  gbpRenderLocationsTable();
}

function gbpCancelEdit() {
  _gbpEditingName = null;
  _gbpEditBuffer = {};
  gbpRenderLocationsTable();
}

function gbpApplyTemplate(which) {
  if (!_gbpEditingName) {
    showToast('Click Edit on a location first, then apply a template.');
    return;
  }
  _gbpEditBuffer = which === 'clear' ? {} : { ...GBP_WEEKDAY_TEMPLATE };
  gbpRenderLocationsTable();
}

function gbpEditorRow(loc) {
  const dayRows = GBP_DAY_ORDER.map(day => {
    const pair = _gbpEditBuffer[day];
    const open = pair ? pair[0] : '';
    const close = pair ? pair[1] : '';
    const closed = !pair;
    return `<tr>
      <td style="padding:6px 10px;width:80px;font-weight:600">${GBP_DAY_LABEL[day]}</td>
      <td style="padding:6px 10px">
        <label class="row-sm" style="gap:6px;font-size:12px;cursor:pointer">
          <input type="checkbox" ${closed ? 'checked' : ''} onchange="gbpToggleClosed('${day}', this.checked)">
          Closed
        </label>
      </td>
      <td style="padding:6px 10px">
        <input type="time" class="lc-input mono" style="width:120px" value="${escHtml(open)}" ${closed ? 'disabled' : ''} onchange="gbpSetHour('${day}', 'open', this.value)">
      </td>
      <td style="padding:6px 10px">
        <input type="time" class="lc-input mono" style="width:120px" value="${escHtml(close)}" ${closed ? 'disabled' : ''} onchange="gbpSetHour('${day}', 'close', this.value)">
      </td>
    </tr>`;
  }).join('');

  return `<tr><td colspan="4" style="padding:0;background:var(--surface-2)">
    <div style="padding:var(--s-4);display:grid;grid-template-columns:1fr 1fr;gap:var(--s-4)">
      <div>
        <div class="label" style="margin-bottom:8px">Editing · ${escHtml(loc.title || loc.name)}</div>
        <table style="width:100%;border-collapse:collapse;font-size:12px">
          <thead><tr style="opacity:.6;text-align:left">
            <th style="padding:6px 10px">Day</th><th style="padding:6px 10px"></th>
            <th style="padding:6px 10px">Open</th><th style="padding:6px 10px">Close</th>
          </tr></thead>
          <tbody>${dayRows}</tbody>
        </table>
      </div>
      <div>
        <div class="label" style="margin-bottom:8px">Preview payload</div>
        <pre class="mono" style="background:var(--surface-1);padding:12px;border-radius:8px;font-size:11px;overflow:auto;max-height:240px">${escHtml(JSON.stringify({ name: loc.name, hours: _gbpEditBuffer }, null, 2))}</pre>
        <div class="row-sm" style="margin-top:var(--s-3);gap:8px">
          <button class="btn btn-primary" onclick="gbpSaveEdit()">
            <span class="material-symbols-outlined">save</span>Save hours
          </button>
          <button class="btn" onclick="gbpCancelEdit()">Cancel</button>
        </div>
      </div>
    </div>
  </td></tr>`;
}

function gbpToggleClosed(day, closed) {
  if (closed) delete _gbpEditBuffer[day];
  else _gbpEditBuffer[day] = ['09:00', '18:00'];
  gbpRenderLocationsTable();
}

function gbpSetHour(day, which, value) {
  if (!_gbpEditBuffer[day]) _gbpEditBuffer[day] = ['09:00', '18:00'];
  if (which === 'open') _gbpEditBuffer[day][0] = value;
  else _gbpEditBuffer[day][1] = value;
  // Re-render preview only; keep inputs stable by not rebuilding row on each keystroke.
  const pre = document.querySelector('#gbpLocations pre.mono');
  if (pre) {
    const loc = _gbpLocations.find(l => l.name === _gbpEditingName);
    if (loc) pre.textContent = JSON.stringify({ name: loc.name, hours: _gbpEditBuffer }, null, 2);
  }
}

async function gbpSaveEdit() {
  const name = _gbpEditingName;
  if (!name) return;
  try {
    const resp = await gbpApi('/api/gbp/locations', {
      method: 'PATCH',
      body: JSON.stringify({ name, hours: _gbpEditBuffer }),
    });
    const idx = _gbpLocations.findIndex(l => l.name === name);
    if (idx >= 0 && resp.location) {
      _gbpLocations[idx] = { ..._gbpLocations[idx], ...resp.location };
    }
    _gbpEditingName = null;
    _gbpEditBuffer = {};
    gbpRenderLocationsTable();
    showToast('✓ Hours updated');
  } catch (e) {
    showToast('❌ ' + e.message);
  }
}
