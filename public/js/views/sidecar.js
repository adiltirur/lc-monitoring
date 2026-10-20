// ═════════════════════════════════════════════════════════════════════════
// PRINCIPA SIDECAR (#sidecar) — read-only view of Planorg's production reporting DB
// (for the Helu sync). Backed by /api/sidecar/* (routes/sidecar.js, lib/sidecar.js):
// SSM tunnel through the whitelisted staging instance, read-only session, row cap.
// Rows are shown here only; nothing is saved.
// ═════════════════════════════════════════════════════════════════════════

let scStatus = null;
let scTables = null;

async function renderSidecar(el) {
  el.innerHTML = pageWrap(`
    ${pageHero('Principa SideCar', {
      sub: 'Planorg’s <b>production</b> reporting DB (172.16.2.18, via the site-to-site VPN). Read-only: the session starts with <span class="mono">default_transaction_read_only=on</span> and every query runs in a rolled-back READ ONLY transaction. Reached through an SSM tunnel via the only whitelisted host, 10.0.13.173 (lc-core-serverpod-staging).',
      actions: `<button class="btn" onclick="scLoadStatus()"><span class="material-symbols-outlined">refresh</span>Refresh</button>`,
    })}
    <div id="scStatus" style="margin-bottom:var(--s-4)">${loadingState()}</div>
    <div id="scResult" style="margin-bottom:var(--s-4)"></div>
    <div class="panel" style="margin-bottom:var(--s-4)">
      <div class="panel-header"><div class="panel-title">Read-only query</div><span class="pill warn">production data</span></div>
      <div class="panel-body">
        <textarea class="lc-textarea" id="scSql" spellcheck="false" style="min-height:110px" placeholder="SELECT … (one statement; results capped at 200 rows)"></textarea>
        <div class="row-sm" style="margin-top:8px;gap:8px">${btnPrimary('Run', 'scRunQuery()', { icon: 'play_arrow' })}
          <span class="muted" style="font-size:12px">Wrapped as <span class="mono">SELECT * FROM (…) LIMIT 201</span> inside <span class="mono">BEGIN READ ONLY … ROLLBACK</span>; 30 s statement timeout.</span></div>
        <div id="scQueryOut" style="margin-top:12px"></div>
      </div>
    </div>`);
  scLoadStatus();
}

async function scLoadStatus() {
  const box = document.getElementById('scStatus');
  try {
    scStatus = await apiFetch('/api/sidecar/status');
    const s = scStatus;
    const creds = s.credentials.user && s.credentials.password;
    const tun = s.tunnel.status === 'connected';
    box.innerHTML = `<div class="panel"><div class="panel-body">
      <table class="lc-table" style="margin-bottom:12px"><tbody>
        <tr><td style="width:160px">Database</td><td class="mono">${escHtml(s.host)}:${s.port}/${escHtml(s.database)} · sslmode=${escHtml(s.sslmode)}</td></tr>
        <tr><td>Network path</td><td>SSM tunnel via <span class="mono">${escHtml(s.instanceTag)}</span> (${escHtml(s.sourceIp)}) → <span class="mono">127.0.0.1:${s.localPort}</span>
          &nbsp;${tun ? `<span class="pill ok">tunnel open · ${escHtml(s.tunnel.instanceId)}</span>` : '<span class="pill">tunnel closed</span>'}</td></tr>
        <tr><td>Credentials</td><td>${creds ? '<span class="pill ok">SIDECAR_DB_USER / PASSWORD set</span>'
          : '<span class="pill err">missing</span> <span class="muted">Add SIDECAR_DB_USER and SIDECAR_DB_PASSWORD to helper/.env once Planorg creates the read-only user, then restart the helper server.</span>'}</td></tr>
        <tr><td>psql on 10.0.13.173</td><td class="mono" style="font-size:12px">${escHtml(s.psql.onHost)}</td></tr>
      </tbody></table>
      <div class="row-sm" style="gap:8px">
        ${btnPrimary('Run smoke test', 'scSmoke()', { icon: 'health_and_safety' })}
        ${tun ? btnGhost('Close tunnel', 'scTunnel(false)', { icon: 'link_off' }) : btnGhost('Open tunnel', 'scTunnel(true)', { icon: 'link' })}
      </div>
    </div></div>`;
  } catch (e) { box.innerHTML = errorState(e.message); }
}

async function scTunnel(open) {
  try {
    const r = await fetch('/api/sidecar/tunnel', { method: open ? 'POST' : 'DELETE' });
    const d = await r.json();
    if (!r.ok) scShowError(d);
  } catch (e) { showToast(`❌ ${e.message}`); }
  scLoadStatus();
}

function scShowError(d, target = 'scResult') {
  document.getElementById(target).innerHTML = `<div class="panel" style="border-color:var(--band);overflow:hidden">
    <div class="band"><span class="material-symbols-outlined">error</span>${escHtml(d.code === 'NO_CREDS' ? 'Blocked: no credentials yet' : d.code === 'TIMEOUT' ? 'Blocked: network path' : d.code === 'AUTH' ? 'Blocked: authentication' : 'Failed')}</div>
    <div class="panel-body"><div class="mono" style="font-size:12px">${escHtml(d.error || '')}</div>
      ${d.cause ? `<div style="margin-top:6px;font-size:12.5px;color:var(--ink-2)">Likely cause: ${escHtml(d.cause)}</div>` : ''}</div></div>`;
}

async function scSmoke() {
  const out = document.getElementById('scResult');
  out.innerHTML = loadingState('Opening the tunnel and connecting (10 s timeout)…');
  try {
    const r = await fetch('/api/sidecar/smoke', { method: 'POST' });
    const d = await r.json();
    if (!r.ok) { scShowError(d); scLoadStatus(); return; }
    scTables = d.tables;
    out.innerHTML = `<div class="panel"><div class="panel-header"><div class="panel-title">Smoke test passed</div>
        <span class="pill ok">${escHtml(d.user)} @ ${escHtml(d.database)} · ${d.ssl ? 'TLS' : 'no TLS'} · read-only</span></div>
      <div class="panel-body"><div class="mono muted" style="font-size:12px;margin-bottom:10px">${escHtml(d.version)}</div>
        <input class="lc-input" placeholder="Filter ${d.tables.length} tables…" oninput="scFilterTables(this.value)" style="max-width:360px;margin-bottom:8px">
        <div id="scTables"></div></div></div>`;
    scFilterTables('');
    scLoadStatus();
  } catch (e) { out.innerHTML = errorState(e.message); }
}

function scFilterTables(q) {
  const n = q.toLowerCase();
  const rows = (scTables || []).filter(t => `${t.schema}.${t.table}`.toLowerCase().includes(n));
  document.getElementById('scTables').innerHTML = `<table class="lc-table"><thead><tr><th>Schema</th><th>Table</th><th>Type</th><th style="text-align:right">≈ rows</th><th></th></tr></thead><tbody>
    ${rows.map(t => `<tr><td class="mono">${escHtml(t.schema)}</td><td class="mono">${escHtml(t.table)}</td><td>${escHtml(t.type)}</td>
      <td class="mono" style="text-align:right">${t.approx_rows ?? '—'}</td>
      <td><button class="btn btn-sm" onclick="scPeek('${escHtml(t.schema)}','${escHtml(t.table)}')">SELECT 20</button></td></tr>`).join('')}</tbody></table>`;
}

function scPeek(schema, table) {
  const q = (s) => `"${s.replace(/"/g, '""')}"`;
  document.getElementById('scSql').value = `SELECT * FROM ${q(schema)}.${q(table)} LIMIT 20`;
  scRunQuery();
}

async function scRunQuery() {
  const out = document.getElementById('scQueryOut');
  out.innerHTML = loadingState('Running…');
  try {
    const r = await fetch('/api/sidecar/query', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ sql: document.getElementById('scSql').value }) });
    const d = await r.json();
    if (!r.ok) { scShowError(d, 'scQueryOut'); return; }
    out.innerHTML = `<div class="muted" style="font-size:12px;margin-bottom:6px">${d.rows.length}${d.truncated ? '+ (capped)' : ''} rows · ${d.ms} ms</div>
      <div style="overflow:auto;max-height:480px"><table class="lc-table"><thead><tr>${d.fields.map(f => `<th>${escHtml(f)}</th>`).join('')}</tr></thead><tbody>
      ${d.rows.map(row => `<tr>${d.fields.map(f => `<td class="mono" style="font-size:12px">${escHtml(row[f] === null ? 'NULL' : typeof row[f] === 'object' ? JSON.stringify(row[f]) : String(row[f]))}</td>`).join('')}</tr>`).join('')}</tbody></table></div>`;
  } catch (e) { out.innerHTML = errorState(e.message); }
}
