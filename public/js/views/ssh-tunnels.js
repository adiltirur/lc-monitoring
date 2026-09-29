// ─── SSH Tunnels (SSM port-forwarding) ───────────────────────────────────────
function ssmEnvColor(env) {
  return env === 'production' ? 'production' : env === 'staging' ? 'staging' : 'test';
}

function ssmCardHtml(s) {
  const connected = s.status === 'connected';
  const starting = s.status === 'starting';
  const dot = connected ? 'ok' : starting ? 'warn' : s.status === 'error' ? 'err' : '';
  const live = (connected || starting) ? 'live' : '';
  const statusLabel = connected ? 'Connected' : starting ? 'Connecting…' : s.status === 'error' ? 'Error' : 'Not connected';
  const action = (connected || starting)
    ? btnGhost('Disconnect', `ssmDisconnect('${s.env}')`, { icon: 'link_off' })
    : btnPrimary('Connect', `ssmConnect('${s.env}')`, { icon: 'bolt' });
  const inst = s.instanceId ? `<span class="mono">${escHtml(s.instanceId)}</span>` : '<span class="faint">—</span>';
  const err = (s.error && !connected)
    ? `<div class="mono" style="color:var(--err);font-size:11px;word-break:break-all">${escHtml(s.error)}</div>` : '';
  const hint = connected
    ? `<div class="mono" style="font-size:11px;color:var(--text-dim)">Termius host <strong>127.0.0.1</strong> · port <strong>${s.localPort}</strong> &nbsp;·&nbsp; <span class="faint">ssh -p ${s.localPort} ec2-user@127.0.0.1</span></div>` : '';
  const footer = (hint || err) ? `<div class="panel-body" style="padding-top:0">${hint}${err}</div>` : '';
  return `<div class="panel" style="margin-bottom:var(--s-3)">
    <div class="panel-body" style="display:flex;align-items:center;gap:var(--s-4);flex-wrap:wrap">
      <div class="lc-env" data-env="${ssmEnvColor(s.env)}" style="min-width:110px">
        <span class="env-name" style="font-size:14px;font-weight:600">${escHtml(s.env)}</span>
      </div>
      <div style="min-width:150px">
        <div class="label" style="margin-bottom:2px">STATUS</div>
        <span class="row-sm" style="font-size:12px;font-weight:500"><span class="dot ${dot} ${live}"></span>${escHtml(statusLabel)}</span>
      </div>
      <div style="min-width:180px">
        <div class="label" style="margin-bottom:2px">INSTANCE</div>${inst}
      </div>
      <div style="min-width:80px">
        <div class="label" style="margin-bottom:2px">LOCAL PORT</div><span class="mono">${s.localPort}</span>
      </div>
      <div style="margin-left:auto">${action}</div>
    </div>
    ${footer}
  </div>`;
}

async function ssmRefresh() {
  const box = document.getElementById('ssmCards');
  if (!box) return;
  try {
    const data = await gbpApi('/api/ssm/status');
    const box2 = document.getElementById('ssmCards');
    if (box2) box2.innerHTML = (data.envs || []).map(ssmCardHtml).join('');
  } catch (e) {
    const box2 = document.getElementById('ssmCards');
    if (box2) box2.innerHTML = errorState(e.message);
  }
}

async function ssmConnect(env) {
  if (env === 'production' && !confirm('Open an SSM tunnel to PRODUCTION?')) return;
  showToast('Opening SSM tunnel for ' + env + '…');
  try {
    const s = await gbpApi('/api/ssm/connect', { method: 'POST', body: JSON.stringify({ env }) });
    if (s.status === 'connected') showToast('✅ Tunnel up · 127.0.0.1:' + s.localPort + ' → ' + s.instanceId);
    else if (s.status === 'error') showToast('❌ ' + (s.error || 'Failed to open tunnel'));
    else showToast('Tunnel starting on port ' + s.localPort + '…');
  } catch (e) {
    showToast('❌ ' + e.message);
  }
  ssmRefresh();
}

async function ssmDisconnect(env) {
  try {
    await gbpApi('/api/ssm/disconnect', { method: 'POST', body: JSON.stringify({ env }) });
    showToast('Tunnel closed for ' + env);
  } catch (e) {
    showToast('❌ ' + e.message);
  }
  ssmRefresh();
}

async function renderSshTunnels(el) {
  el.innerHTML = pageWrap(
    pageHero('SSH Tunnels', {
      sub: 'One-click SSM port-forward to a private app instance. Point Termius / ssh at 127.0.0.1 on the shown local port.',
      actions: btnGhost('Refresh', 'ssmRefresh()', { icon: 'refresh' }),
    }) +
    `<div id="ssmCards">${loadingState('Checking tunnels…')}</div>` +
    `<div class="panel" style="margin-top:var(--s-4)"><div class="panel-body" style="font-size:12px;color:var(--text-dim);line-height:1.6">
      <div class="label" style="margin-bottom:6px">How it works</div>
      <strong>Connect</strong> resolves the newest running instance for that environment (by its <span class="mono">Name</span> tag) and opens
      <span class="mono">aws ssm start-session … AWS-StartPortForwardingSession</span> to its port 22.
      Then connect Termius (or a terminal) to host <span class="mono">127.0.0.1</span> on the local port shown.
      Requires the AWS CLI and <span class="mono">session-manager-plugin</span> installed on this machine.
    </div></div>`
  );
  ssmRefresh();
}
