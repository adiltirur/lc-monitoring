// ─── Deployments (backend: GitHub Action → CodeDeploy → server) ──────────────
let dpData = null;
let dpTimer = null;
let dpSeenFailed = null;   // deployment ids already failed when the view opened
const dpServer = {};       // env → { loading, data, error }

const DP_STATUS_PILL = { Succeeded: 'ok', Failed: 'err', Stopped: 'err', InProgress: 'info', Created: 'info', Queued: 'info', Ready: 'info' };

function dpShort(sha) { return sha ? sha.slice(0, 8) : '—'; }

function dpPill(label, kind) { return `<span class="pill ${kind || ''}">${escHtml(label)}</span>`; }

function dpRunPill(r) {
  if (r.status !== 'completed') return dpPill(r.status === 'in_progress' ? 'Running' : r.status, 'info');
  return dpPill(r.conclusion || '—', r.conclusion === 'success' ? 'ok' : r.conclusion === 'cancelled' ? '' : 'err');
}

function dpLogBlock(title, text) {
  if (!text) return '';
  return `<details style="margin-top:var(--s-2)"><summary class="label" style="cursor:pointer">${escHtml(title)}</summary>
    <pre class="code" style="white-space:pre-wrap;word-break:break-all;margin:6px 0 0;max-height:320px;overflow:auto;font-size:11px">${escHtml(text)}</pre></details>`;
}

function dpEnvCard(e) {
  const latest = e.latest;
  const failed = latest && (latest.status === 'Failed' || latest.status === 'Stopped');
  const live = e.lastSuccess;
  const apiDot = e.api.ok ? 'ok' : 'err';
  const apiLabel = e.api.ok ? `API up · ${e.api.latencyMs} ms` : `API ${e.api.error || e.api.status || 'down'}`;
  const liveLine = live
    ? `<span class="mono">${dpShort(e.liveCommit)}</span> <span class="faint">deployed ${escHtml(deTime(live.completeTime || live.createTime))}</span>`
    : '<span class="faint">no successful deployment in the last 25</span>';

  let warn = '';
  if (failed) {
    const f = latest.failed[0];
    warn = `<div class="panel-body" style="border-top:1px solid var(--rule);background:var(--red-soft)">
      <div style="font-weight:600;color:var(--red);margin-bottom:4px">Last deployment failed, the server still runs the previous build</div>
      <div style="font-size:12px"><span class="mono">${escHtml(latest.id)}</span> · ${escHtml(deTime(latest.createTime))}${latest.commit ? ` · commit <span class="mono">${dpShort(latest.commit)}</span>` : ''}</div>
      ${f ? `<div style="font-size:12px;margin-top:4px"><strong>${escHtml(f.event)}</strong>: ${escHtml(f.message || '')}</div>` : ''}
      ${f ? dpLogBlock('Hook log (tail)', f.logTail) : ''}
    </div>`;
  } else if (e.behind) {
    warn = `<div class="panel-body" style="border-top:1px solid var(--rule);background:var(--yellow-soft);font-size:12px">
      Newest run for this env is commit <span class="mono">${dpShort(e.latestRun.sha)}</span>, but the server runs <span class="mono">${dpShort(e.liveCommit)}</span>.
    </div>`;
  }

  const s = dpServer[e.env] || {};
  let server = '';
  if (s.loading) server = `<div class="panel-body" style="border-top:1px solid var(--rule);font-size:12px"><span class="material-symbols-outlined spin" style="font-size:14px;vertical-align:middle">progress_activity</span> Asking the instance over SSM…</div>`;
  else if (s.error) server = `<div class="panel-body mono" style="border-top:1px solid var(--rule);font-size:11px;color:var(--err);word-break:break-all">${escHtml(s.error)}</div>`;
  else if (s.data) {
    const d = s.data;
    const ok = d.activeState === 'active' && d.subState === 'running';
    server = `<div class="panel-body" style="border-top:1px solid var(--rule)">
      <div class="row-sm" style="font-size:12px;gap:var(--s-4);flex-wrap:wrap">
        <span class="row-sm"><span class="dot ${ok ? 'ok' : 'err'}"></span>serverpod.service ${escHtml(d.activeState || '?')} (${escHtml(d.subState || '?')})</span>
        <span>since <span class="mono">${escHtml(d.activeSince || '—')}</span></span>
        ${d.migrationsAt ? `<span>last migration run <span class="mono">${escHtml(deTime(d.migrationsAt))}</span></span>` : ''}
        <span class="faint mono">${escHtml(d.instanceId)} · checked ${escHtml(deTime(d.checkedAt))}</span>
      </div>
      ${dpLogBlock('serverpod.err (last 30 lines)', d.errTail)}
      ${dpLogBlock('serverpod.log (last 30 lines)', d.logTail)}
      ${dpLogBlock('serverpod-migrations.log (last 30 lines)', d.migrationsTail)}
    </div>`;
  }

  return `<div class="panel" style="margin-bottom:var(--s-3);overflow:hidden">
    <div class="panel-body" style="display:flex;align-items:center;gap:var(--s-4);flex-wrap:wrap">
      <div class="lc-env" data-env="${e.env === 'production' ? 'production' : e.env === 'staging' ? 'staging' : 'test'}" style="min-width:110px">
        <span class="env-name" style="font-size:14px;font-weight:600">${escHtml(e.env)}</span>
      </div>
      <div style="min-width:150px">
        <div class="label" style="margin-bottom:2px">API</div>
        <span class="row-sm" style="font-size:12px;font-weight:500"><span class="dot ${apiDot}"></span>${escHtml(apiLabel)}</span>
      </div>
      <div style="min-width:170px">
        <div class="label" style="margin-bottom:2px">LAST DEPLOYMENT</div>
        ${latest ? `${dpPill(latest.status, DP_STATUS_PILL[latest.status])} <span class="faint" style="font-size:12px">${escHtml(deTime(latest.createTime))}</span>` : '<span class="faint">—</span>'}
      </div>
      <div style="min-width:220px">
        <div class="label" style="margin-bottom:2px">RUNNING</div>${liveLine}
      </div>
      <div style="margin-left:auto">${btnGhost('Check server', `dpCheckServer('${e.env}')`, { icon: 'dns' })}</div>
    </div>
    ${warn}${server}
  </div>`;
}

function dpRunsTable(d) {
  if (d.runsError) return errorState('GitHub runs unavailable (is `gh` logged in?): ' + d.runsError);
  const rows = d.runs.map(r => {
    const dep = r.deployment;
    // The case this view exists for: green Action, failed deployment.
    const hidden = r.conclusion === 'success' && dep && (dep.status === 'Failed' || dep.status === 'Stopped');
    return `<tr${hidden ? ' style="background:var(--red-soft)"' : ''}>
      <td><a href="${escHtml(r.url)}" target="_blank" class="mono">#${r.id}</a></td>
      <td>${escHtml(r.env || '—')}</td>
      <td class="mono" style="font-size:12px">${escHtml(r.branch || '')}<div class="faint">${escHtml(r.event)}${r.actor ? ' · ' + escHtml(r.actor) : ''}</div></td>
      <td class="mono">${dpShort(r.sha)}<div class="faint" style="font-family:inherit;max-width:280px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${escHtml(r.title || '')}</div></td>
      <td style="white-space:nowrap">${escHtml(deTime(r.createdAt))}</td>
      <td>${dpRunPill(r)}</td>
      <td>${dep ? `${dpPill(dep.status, DP_STATUS_PILL[dep.status])} <span class="mono faint" style="font-size:11px">${escHtml(dep.id)}</span>` : '<span class="faint">—</span>'}
        ${hidden ? '<div style="font-size:11px;color:var(--red);font-weight:600">Green run, deploy failed</div>' : ''}</td>
    </tr>`;
  }).join('');
  return tableShell(['Run', 'Env', 'Branch', 'Commit', 'Started', 'Action', 'CodeDeploy'], rows);
}

function dpRender() {
  const envBox = document.getElementById('dpEnvs');
  const runBox = document.getElementById('dpRuns');
  if (!envBox || !runBox || !dpData) return;
  envBox.innerHTML = dpData.envs.map(dpEnvCard).join('');
  runBox.innerHTML = `<div class="label" style="margin:var(--s-4) 0 var(--s-2)">GITHUB ACTION RUNS · Deploy to AWS</div>` + dpRunsTable(dpData);
  const stamp = document.getElementById('dpStamp');
  if (stamp) stamp.textContent = 'Checked ' + deTime(dpData.checkedAt);
}

function dpNotifyNewFailures(data) {
  const failed = data.envs.flatMap(e => e.deployments).filter(d => d.status === 'Failed' || d.status === 'Stopped');
  if (dpSeenFailed === null) { dpSeenFailed = new Set(failed.map(d => d.id)); return; }
  for (const d of failed) {
    if (dpSeenFailed.has(d.id)) continue;
    dpSeenFailed.add(d.id);
    const title = `Backend deploy failed: ${d.env}`;
    const body = d.failed[0] ? `${d.failed[0].event}: ${d.failed[0].message || ''}` : (d.error || d.id);
    showToast(`${title} · ${body}`, 'err');
    try { window.lcNative && window.lcNative.post('notify', { title, body }); } catch {}
  }
}

async function dpRefresh(fresh) {
  if (!document.getElementById('dpEnvs')) { clearInterval(dpTimer); dpTimer = null; return; }
  try {
    const data = await apiFetch('/api/deployments/overview' + (fresh ? '?fresh=1' : ''));
    dpData = data;
    dpNotifyNewFailures(data);
    dpRender();
  } catch (e) {
    const box = document.getElementById('dpEnvs');
    if (box) box.innerHTML = errorState(e.message);
  }
}

async function dpCheckServer(env) {
  if (env === 'production' && !confirm('Run a read-only status check on the PRODUCTION instance over SSM?')) return;
  dpServer[env] = { loading: true };
  dpRender();
  try {
    dpServer[env] = { data: await apiPost('/api/deployments/server-check', { env }) };
  } catch (e) {
    dpServer[env] = { error: e.message };
  }
  dpRender();
}

function renderDeployments(el) {
  dpData = null;
  dpSeenFailed = null;
  el.innerHTML = pageWrap(
    pageHero('Deployments', {
      sub: 'Backend deploys per environment: the GitHub Action, the CodeDeploy deployment it queues, and what the server actually runs. A green Action only means the deployment was queued.',
      actions: `<span class="faint" id="dpStamp" style="font-size:12px;margin-right:8px"></span>` + btnGhost('Refresh', 'dpRefresh(true)', { icon: 'refresh' }),
      live: true,
    }) +
    `<div id="dpEnvs">${loadingState('Loading deployments…')}</div><div id="dpRuns"></div>`
  );
  clearInterval(dpTimer);
  dpTimer = setInterval(() => dpRefresh(false), 30000);
  dpRefresh(true);
}
