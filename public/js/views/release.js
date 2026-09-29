// ═════════════════════════════════════════════════════════════════════════
// BUILD & RELEASE — Flutter apps (web → S3/CloudFront, Android, iOS)
// ═════════════════════════════════════════════════════════════════════════
// Backed by /api/release/*. One job at a time; the server keeps the job and
// its log in memory, so leaving the view and coming back picks it up again.
const RL_SEL_KEY = 'lc_release_sel';
let rlSel = (() => {
  const d = { app: 'praxis', env: 'test', platform: 'web', androidFormat: 'apk' };
  try { return { ...d, ...(JSON.parse(localStorage.getItem(RL_SEL_KEY) || 'null') || {}) }; } catch { return d; }
})();
let rlCfg = null;
let rlJobState = null;     // last job summary from the server
let rlLines = [];          // accumulated log lines of rlJobState
let rlLogEnd = 0;
let rlLastBuilds = {};
let rlTimer = null;
let rlNotifiedJob = null;  // job id we already announced as finished
let rlNeedsFull = true;    // re-render every panel on the next poll

const RL_PLATFORM_LABEL = { web: 'Web', android: 'Android', ios: 'iOS' };
const RL_ENV_LABEL = { test: 'Test', prod: 'Prod' };

function rlSet(key, value) {
  rlSel[key] = value;
  try { localStorage.setItem(RL_SEL_KEY, JSON.stringify(rlSel)); } catch {}
  rlRenderControls();
  rlRenderDeploy();
}

function rlSeg(key, options) {
  return `<div class="tweak-seg">${options.map(([v, l]) =>
    `<button class="${rlSel[key] === v ? 'on' : ''}" onclick="rlSet('${key}','${v}')">${escHtml(l)}</button>`).join('')}</div>`;
}

function rlRelTime(ts) { return ts ? lsRelTime(ts) : '—'; }

function rlBusy() { return !!(rlJobState && rlJobState.status === 'running'); }

async function renderRelease(el) {
  el.innerHTML = pageWrap(pageHero('Build & Release') + loadingState());
  try { rlCfg = await gbpApi('/api/release/config'); rlLastBuilds = rlCfg.lastBuilds || {}; }
  catch (e) { el.innerHTML = pageWrap(pageHero('Build & Release') + errorState(e.message)); return; }
  el.innerHTML = pageWrap(`
    ${pageHero('Build & Release', {
      sub: `Build the Flutter apps for test or prod and ship web builds to S3 + CloudFront. Apps from <span class="mono">${escHtml(rlCfg.appsDir)}</span>, built with fvm.`,
    })}
    <div class="panel" style="margin-bottom:var(--s-4)"><div class="panel-body" id="rlControls"></div></div>
    <div id="rlDeploy"></div>
    <div class="panel" style="margin-bottom:var(--s-4);overflow:hidden">
      <div class="panel-header">
        <div id="rlJobHead" style="display:flex;align-items:center;gap:var(--s-3);flex-wrap:wrap"></div>
        <div class="panel-actions" id="rlJobActions"></div>
      </div>
      <div id="rlSteps" class="panel-body" style="padding-top:0"></div>
      <pre class="ls-log" id="rlLog"></pre>
    </div>
    <div id="rlLastBuilds"></div>`);
  rlRenderControls();
  rlRenderDeploy();
  rlLines = []; rlLogEnd = 0; rlJobState = null; rlNeedsFull = true;
  await rlPoll();
  clearInterval(rlTimer);
  rlTimer = setInterval(() => {
    if (window.__currentView !== 'release') { clearInterval(rlTimer); return; }
    rlPoll();
  }, 1500);
}

function rlRenderControls() {
  const box = document.getElementById('rlControls');
  if (!box || !rlCfg) return;
  const a = rlCfg.apps[rlSel.app];
  const { flavor, target } = rlCfg.envs[rlSel.env];
  const buildCmd = rlSel.platform === 'web' ? `flutter build web --release -t ${target}`
    : rlSel.platform === 'android' ? `flutter build ${rlSel.androidFormat === 'aab' ? 'appbundle' : 'apk'} --release --flavor ${flavor} -t ${target}`
    : `flutter build ipa --flavor ${flavor} -t ${target}`;
  const cmds = ['flutter clean', 'flutter pub get', buildCmd];
  const sdk = rlCfg.sdk || {};
  const after = rlSel.platform === 'web' ? 'Then deploy below.' : 'The output file opens in Finder when done.';
  box.innerHTML = `
    <div style="display:flex;gap:var(--s-5);flex-wrap:wrap;align-items:flex-end">
      <div class="field">${fLabel('App')}${rlSeg('app', Object.entries(rlCfg.apps).map(([k, x]) => [k, x.label]))}</div>
      <div class="field">${fLabel('Environment')}${rlSeg('env', [['test', 'Test'], ['prod', 'Prod']])}</div>
      <div class="field">${fLabel('Platform')}${rlSeg('platform', [['web', 'Web'], ['android', 'Android'], ['ios', 'iOS']])}</div>
      ${rlSel.platform === 'android' ? `<div class="field">${fLabel('Android output')}${rlSeg('androidFormat', [['apk', 'APK'], ['aab', 'App Bundle']])}</div>` : ''}
      <div style="margin-left:auto">
        <button class="btn btn-primary" id="rlBuildBtn" onclick="rlBuild()" ${rlBusy() || !a.exists ? 'disabled' : ''}>
          <span class="material-symbols-outlined">construction</span>Build ${escHtml(a.label)} · ${RL_PLATFORM_LABEL[rlSel.platform]} · ${RL_ENV_LABEL[rlSel.env]}</button>
      </div>
    </div>
    ${!a.exists ? `<div class="mono" style="color:var(--err);font-size:12px;margin-top:var(--s-3)">App folder not found: ${escHtml(a.path)}</div>` : ''}
    ${sdk.error ? `<div class="mono" style="color:var(--err);font-size:12px;margin-top:var(--s-3)">${escHtml(sdk.error)}</div>` : ''}
    <div class="mono" style="font-size:11px;color:var(--text-dim);margin-top:var(--s-3);line-height:1.7">
      in ${escHtml(a.path)} · Flutter ${escHtml(sdk.version || '?')} (workspace .fvmrc)<br>${cmds.map(c => '$ ' + escHtml(c)).join('<br>')}<br><span class="faint">${after}</span>
    </div>`;
}

function rlRenderDeploy() {
  const box = document.getElementById('rlDeploy');
  if (!box || !rlCfg) return;
  if (rlSel.platform !== 'web') { box.innerHTML = ''; return; }
  const a = rlCfg.apps[rlSel.app];
  const t = a.web[rlSel.env];
  const wb = (rlLastBuilds[rlSel.app] || {}).web;
  const prod = rlSel.env === 'prod';
  const phrase = rlCfg.confirmations[rlSel.app];
  let state, ready = false;
  if (!wb) state = `No web build of ${escHtml(a.label)} yet — build web first.`;
  else if (wb.env !== rlSel.env) state = `The current web build is for <strong>${escHtml(RL_ENV_LABEL[wb.env])}</strong> — rebuild for ${escHtml(RL_ENV_LABEL[rlSel.env])} before deploying.`;
  else { ready = true; state = `Ready: ${escHtml(RL_ENV_LABEL[wb.env])} web build from ${escHtml(rlRelTime(wb.at))}${wb.deployedAt ? ` · last deployed ${escHtml(rlRelTime(wb.deployedAt))}` : ''}.`; }
  const disabled = !ready || rlBusy();
  box.innerHTML = `<div class="panel ${prod ? 'lc-destructive' : ''}" ${prod ? 'data-band="Production — this goes live for users"' : ''} style="margin-bottom:var(--s-4)">
    <div class="panel-body">
      <div style="display:flex;gap:var(--s-5);flex-wrap:wrap;align-items:flex-start">
        <div style="flex:1;min-width:260px">
          <div class="label" style="margin-bottom:6px">Deploy web · ${escHtml(a.label)} · ${RL_ENV_LABEL[rlSel.env]}</div>
          <div class="mono" style="font-size:11px;line-height:1.7;color:var(--text-dim)">
            $ aws s3 sync build/web/ s3://${escHtml(t.bucket)} --delete --exclude "index.html"<br>
            $ aws cloudfront create-invalidation --distribution-id ${escHtml(t.distribution)} --paths "/*"<br>
            → <a href="${escHtml(t.url)}" target="_blank">${escHtml(t.url)}</a>
          </div>
          <div style="font-size:12px;margin-top:var(--s-2)">${state}</div>
        </div>
        <div style="display:flex;gap:var(--s-2);align-items:center">
          ${prod ? `<input id="rlConfirm" class="lc-input mono" style="width:220px" placeholder="Type ${escHtml(phrase)}" ${disabled ? 'disabled' : ''}
              oninput="document.getElementById('rlDeployBtn').disabled = this.value !== '${escHtml(phrase)}' || rlBusy()">` : ''}
          <button class="btn ${prod ? '' : 'btn-primary'}" id="rlDeployBtn" onclick="rlDeploy()" ${disabled || prod ? 'disabled' : ''}
            ${prod ? 'style="background:var(--red);color:#fff;border-color:var(--red)"' : ''}>
            <span class="material-symbols-outlined">cloud_upload</span>Deploy to ${escHtml(t.bucket)}</button>
        </div>
      </div>
    </div>
  </div>`;
}

function rlRenderJob() {
  const head = document.getElementById('rlJobHead');
  if (!head) return;
  const j = rlJobState;
  const actions = document.getElementById('rlJobActions');
  const steps = document.getElementById('rlSteps');
  if (!j) {
    head.innerHTML = `<span class="label">Job</span><span class="muted" style="font-size:12px">Nothing has run since the helper started.</span>`;
    actions.innerHTML = ''; steps.innerHTML = '';
  } else {
    const pill = { running: ['Running', 'warn'], success: ['Succeeded', 'ok'], failed: ['Failed', 'err'], cancelled: ['Cancelled', 'err'] }[j.status] || [j.status, ''];
    const what = j.kind === 'deploy'
      ? `Deploy ${rlCfg.apps[j.app].label} · Web · ${RL_ENV_LABEL[j.env]}`
      : `Build ${rlCfg.apps[j.app].label} · ${RL_PLATFORM_LABEL[j.platform]}${j.androidFormat ? ' (' + j.androidFormat.toUpperCase() + ')' : ''} · ${RL_ENV_LABEL[j.env]}${j.flutterVersion ? ' · Flutter ' + j.flutterVersion : ''}`;
    const dur = Math.round(((j.endedAt || Date.now()) - j.startedAt) / 1000);
    head.innerHTML = `<span class="pill ${pill[1]}">${pill[1] === 'warn' ? '<span class="dot warn live"></span>' : ''}${pill[0]}</span>
      <span style="font-weight:600">${escHtml(what)}</span>
      <span class="muted mono" style="font-size:11px">${Math.floor(dur / 60)}:${String(dur % 60).padStart(2, '0')}</span>
      ${j.error && j.status !== 'cancelled' ? `<span class="mono" style="color:var(--err);font-size:11px">${escHtml(j.error)}</span>` : ''}`;
    actions.innerHTML = (j.status === 'running' ? `<button class="btn btn-sm" onclick="rlCancel()"><span class="material-symbols-outlined">stop</span>Cancel</button>` : '')
      + (j.status === 'success' && j.kind === 'build' && j.platform !== 'web' ? `<button class="btn btn-sm" onclick="rlReveal('${j.app}','${j.platform}')"><span class="material-symbols-outlined">folder_open</span>Show in Finder</button>` : '')
      + `<button class="btn btn-sm" onclick="copyText(document.getElementById('rlLog').innerText, 'Copied log')"><span class="material-symbols-outlined">content_copy</span>Copy</button>`;
    const icon = { pending: 'radio_button_unchecked', running: 'progress_activity', done: 'check_circle', failed: 'error', cancelled: 'cancel' };
    steps.innerHTML = `<div style="display:flex;gap:var(--s-4);flex-wrap:wrap;font-size:12px">${j.steps.map(s => {
      const t = s.startedAt ? Math.round(((s.endedAt || Date.now()) - s.startedAt) / 1000) + 's' : '';
      const color = s.status === 'done' ? 'var(--ok)' : s.status === 'failed' || s.status === 'cancelled' ? 'var(--err)' : s.status === 'running' ? 'var(--ink)' : 'var(--ink-3)';
      return `<span class="row-sm" style="color:${color}"><span class="material-symbols-outlined ${s.status === 'running' ? 'spin' : ''}" style="font-size:16px">${icon[s.status]}</span>${escHtml(s.label)} <span class="faint mono">${t}</span></span>`;
    }).join('')}</div>`;
  }
  const pre = document.getElementById('rlLog');
  const atBottom = pre.scrollTop + pre.clientHeight >= pre.scrollHeight - 24;
  pre.innerHTML = rlLines.length ? rlLines.map(l => {
    const cls = /^────/.test(l) ? 'l-mark' : /\b(error|Error|ERROR|FAILURE|Exception)\b/.test(l) ? 'l-err' : /\b(warning|Warning|WARN)\b/.test(l) ? 'l-warn' : '';
    return cls ? `<span class="${cls}">${escHtml(l)}</span>` : escHtml(l);
  }).join('\n') : '<span class="muted">No output yet.</span>';
  if (atBottom) pre.scrollTop = pre.scrollHeight;
}

function rlRenderLastBuilds() {
  const box = document.getElementById('rlLastBuilds');
  if (!box || !rlCfg) return;
  const rows = [];
  for (const [k, a] of Object.entries(rlCfg.apps)) {
    for (const p of ['web', 'android', 'ios']) {
      const b = (rlLastBuilds[k] || {})[p];
      if (!b) continue;
      const file = b.artifact ? b.artifact.split('/').slice(-1)[0] : '—';
      rows.push(`<tr style="cursor:default">
        <td style="color:var(--ink)">${escHtml(a.label)}</td>
        <td>${escHtml(RL_PLATFORM_LABEL[p])}${b.androidFormat ? ' · ' + escHtml(b.androidFormat.toUpperCase()) : ''}</td>
        <td><span class="pill ${b.env === 'prod' ? 'err' : 'info'}">${escHtml(RL_ENV_LABEL[b.env])}</span></td>
        <td class="muted">${escHtml(rlRelTime(b.at))}${p === 'web' && b.deployedAt ? ' · deployed ' + escHtml(rlRelTime(b.deployedAt)) : ''}</td>
        <td class="mono muted" style="font-size:11px">${escHtml(file)}</td>
        <td style="text-align:right">${p !== 'web' && b.artifact ? `<button class="btn btn-sm" onclick="rlReveal('${k}','${p}')"><span class="material-symbols-outlined">folder_open</span>Finder</button>` : ''}</td></tr>`);
    }
  }
  box.innerHTML = rows.length ? `<div class="label" style="margin:var(--s-2) 0">Latest builds</div>`
    + tableShell(['App', 'Platform', 'Env', 'Built', 'Output', ''], rows.join('')) : '';
}

async function rlPoll() {
  let d;
  try { d = await gbpApi(`/api/release/status?since=${rlLogEnd}`); } catch { return; }
  let j = d.job;
  if (j && rlLogEnd && (!rlJobState || j.id !== rlJobState.id)) {
    // A different job than the one whose log we hold — refetch its log from 0.
    rlLogEnd = 0; rlLines = [];
    try { d = await gbpApi('/api/release/status?since=0'); j = d.job; } catch { return; }
  }
  if (j) {
    if (j.logTruncated) rlLines = [];
    rlLines.push(...j.lines);
    rlLogEnd = j.logEnd;
  }
  const wasRunning = rlBusy();
  const changed = rlNeedsFull || wasRunning !== !!(j && j.status === 'running');
  rlJobState = j;
  rlLastBuilds = d.lastBuilds || {};
  rlRenderJob();
  // Controls/deploy panels hold inputs — only re-render them when state flips.
  if (changed) { rlNeedsFull = false; rlRenderControls(); rlRenderDeploy(); rlRenderLastBuilds(); }
  if (j && j.status !== 'running' && wasRunning && rlNotifiedJob !== j.id) {
    rlNotifiedJob = j.id;
    const title = j.status === 'success' ? (j.kind === 'deploy' ? 'Deploy finished' : 'Build finished') : (j.kind === 'deploy' ? 'Deploy failed' : 'Build failed');
    const body = `${rlCfg.apps[j.app].label} · ${RL_PLATFORM_LABEL[j.platform]} · ${RL_ENV_LABEL[j.env]}`;
    showToast(`${title}: ${body}`, j.status === 'success' ? 'ok' : 'err');
    try { window.lcNative && window.lcNative.post('notify', { title, body }); } catch {}
  }
}

function rlStarted(d) {
  rlJobState = d.job; rlLines = d.job.lines || []; rlLogEnd = d.job.logEnd;
  rlNotifiedJob = null;
  rlRenderJob(); rlRenderControls(); rlRenderDeploy(); rlRenderLastBuilds();
}

async function rlBuild() {
  const a = rlCfg.apps[rlSel.app];
  if (rlSel.env === 'prod' && !confirm(`Build ${a.label} (${RL_PLATFORM_LABEL[rlSel.platform]}) for PROD?\n\nThis runs flutter clean first, so earlier build outputs of this app are removed.`)) return;
  try {
    const body = { app: rlSel.app, env: rlSel.env, platform: rlSel.platform, androidFormat: rlSel.androidFormat };
    rlStarted(await gbpApi('/api/release/build', { method: 'POST', body: JSON.stringify(body) }));
  } catch (e) { showToast('Build: ' + e.message, 'err'); }
}

async function rlDeploy() {
  const a = rlCfg.apps[rlSel.app];
  const t = a.web[rlSel.env];
  const prod = rlSel.env === 'prod';
  if (!confirm(`Deploy the ${RL_ENV_LABEL[rlSel.env]} web build of ${a.label} to s3://${t.bucket}?${prod ? '\n\nThis is PRODUCTION — users get it after the CloudFront invalidation.' : ''}`)) return;
  try {
    const body = { app: rlSel.app, env: rlSel.env, confirmation: prod ? (document.getElementById('rlConfirm') || {}).value : undefined };
    rlStarted(await gbpApi('/api/release/deploy', { method: 'POST', body: JSON.stringify(body) }));
  } catch (e) { showToast('Deploy: ' + e.message, 'err'); }
}

async function rlCancel() {
  if (!confirm('Cancel the running job?')) return;
  try { await gbpApi('/api/release/cancel', { method: 'POST' }); } catch (e) { showToast(e.message, 'err'); }
}

async function rlReveal(appKey, platform) {
  try { await gbpApi('/api/release/reveal', { method: 'POST', body: JSON.stringify({ app: appKey, platform }) }); }
  catch (e) { showToast(e.message, 'err'); }
}
