// ─── Log Cleanup (Serverpod session logs, batched) ───────────────────────────
const LGC_PROD_PHRASE = 'CLEAN PRODUCTION LOGS';
const lgcState = { data: null, form: { retentionDays: 7, batchSize: 5000, pauseMs: 300, vacuum: true }, confirm: '', job: null };
let lgcTimer = null;

function lgcEnvName() {
  return lgcState.data?.env || document.getElementById('envBtn')?.dataset.env || 'dev';
}

function lgcNum(n) { return n == null ? '—' : Number(n).toLocaleString(); }

// dur() only knows seconds; an ETA can be hours.
function lgcDuration(ms) {
  const s = Math.round(ms / 1000);
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  return m < 60 ? `${m}m ${s % 60}s` : `${Math.floor(m / 60)}h ${m % 60}m`;
}

function lgcJobActive(j) { return j && (j.status === 'running' || j.status === 'vacuuming'); }

function lgcOverviewPanel() {
  const d = lgcState.data;
  const sizes = d.sizes.map(s => `<tr><td class="mono">${escHtml(s.table)}</td><td class="mono">${escHtml(s.size)}</td><td class="mono">~${lgcNum(s.est_rows)}</td></tr>`).join('');
  return `<div class="panel" style="margin-bottom:var(--s-4)">
    <div class="panel-header"><span class="panel-title"><span class="material-symbols-outlined">inventory_2</span>Session logs on ${escHtml(d.env)}</span>
      <span class="faint mono" style="font-size:11px">${escHtml(d.host)}</span></div>
    <div class="panel-body" style="display:flex;gap:var(--s-5);flex-wrap:wrap">
      <div><div class="label">SESSIONS</div><div class="mono" style="font-size:18px">${lgcNum(d.total)}</div></div>
      <div><div class="label">OLDER THAN ${d.retentionDays} DAYS</div><div class="mono" style="font-size:18px;color:${d.expired ? 'var(--red)' : 'inherit'}">${lgcNum(d.expired)}</div></div>
      <div><div class="label">OLDEST</div><div class="mono" style="font-size:14px">${d.oldest ? escHtml(deTime(d.oldest)) : '—'}</div></div>
    </div>
    <div style="overflow-x:auto"><table class="lc-table"><thead><tr><th>Table</th><th>Size on disk</th><th>Rows (estimate)</th></tr></thead><tbody>${sizes}</tbody></table></div>
  </div>`;
}

function lgcRunPanel() {
  const f = lgcState.form;
  const prod = lgcEnvName() === 'production';
  const busy = lgcJobActive(lgcState.job);
  const canRun = !busy && (!prod || lgcState.confirm === LGC_PROD_PHRASE);
  const confirmInput = prod
    ? `<input class="lc-input mono" style="width:260px" placeholder="type ${LGC_PROD_PHRASE}" value="${escHtml(lgcState.confirm)}"
         oninput="lgcState.confirm=this.value;document.getElementById('lgcRunBtn').disabled=this.value!=='${LGC_PROD_PHRASE}'">`
    : '';
  return `<section class="panel lc-destructive" data-band="Destructive — deletes session logs${prod ? ' on PRODUCTION' : ''}" style="margin-bottom:var(--s-4)">
    <div class="panel-header"><span class="panel-title"><span class="material-symbols-outlined">delete_sweep</span>Delete expired session logs in batches</span></div>
    <div class="panel-body">
      <div class="list-meta" style="margin:0 0 var(--s-3);font-size:12px;color:var(--ink-3)">
        Deletes <span class="mono">serverpod_session_log</span> rows older than the retention (their log, query and message rows go with them by cascade),
        one autocommitted batch at a time with a pause in between. Same rule as Serverpod's <span class="mono">sessionLogs.retentionPeriod</span> (7 days).
        ${prod ? '<br><strong>Production:</strong> run off-hours and keep an eye on EBS byte balance in DB Diagnostics; raise the pause if it drops.' : ''}
      </div>
      <div style="display:grid;grid-template-columns:repeat(4,minmax(120px,180px));gap:var(--s-3);align-items:end;margin-bottom:var(--s-3)">
        ${fInput('Keep last (days)', `type="number" min="1" value="${f.retentionDays}" onchange="lgcState.form.retentionDays=+this.value;lgcLoad()"`)}
        ${fInput('Batch size (sessions)', `type="number" min="100" max="50000" step="1000" value="${f.batchSize}" onchange="lgcState.form.batchSize=+this.value"`)}
        ${fInput('Pause between (ms)', `type="number" min="0" max="60000" step="100" value="${f.pauseMs}" onchange="lgcState.form.pauseMs=+this.value"`)}
        <label class="row-sm" style="font-size:12px;padding-bottom:8px"><input type="checkbox" ${f.vacuum ? 'checked' : ''} onchange="lgcState.form.vacuum=this.checked"> VACUUM (ANALYZE) after</label>
      </div>
      <div class="row-sm">
        ${confirmInput}
        <button id="lgcRunBtn" class="btn btn-danger" onclick="lgcStart()" ${canRun ? '' : 'disabled'}><span class="material-symbols-outlined">delete_forever</span>Start cleanup</button>
      </div>
    </div>
  </section>`;
}

function lgcJobPanel() {
  const j = lgcState.job;
  if (!j) return '';
  const pct = j.expiredAtStart ? Math.min(100, Math.round((j.deleted / j.expiredAtStart) * 100)) : 100;
  const elapsed = ((j.finishedAt ? new Date(j.finishedAt) : new Date()) - new Date(j.startedAt)) / 1000;
  const rate = elapsed > 0 ? j.deleted / elapsed : 0;
  const eta = j.status === 'running' && rate > 0 ? lgcDuration(((j.expiredAtStart - j.deleted) / rate) * 1000) : '—';
  const pill = { running: 'info', vacuuming: 'info', done: 'ok', cancelled: 'warn', error: 'err' }[j.status] || '';
  return `<div class="panel" style="margin-bottom:var(--s-4)">
    <div class="panel-header"><span class="panel-title"><span class="material-symbols-outlined">${lgcJobActive(j) ? 'progress_activity' : 'task_alt'}</span>Cleanup on ${escHtml(j.env)}
      <span class="pill ${pill}">${escHtml(j.status === 'vacuuming' ? 'vacuuming tables…' : j.status)}</span></span>
      ${j.status === 'running' ? btnGhost('Cancel', 'lgcCancel()', { icon: 'stop_circle' }) : ''}</div>
    <div class="panel-body">
      <div style="height:8px;border-radius:4px;background:var(--surface-2);overflow:hidden;margin-bottom:var(--s-3)">
        <div style="height:100%;width:${pct}%;background:var(--accent, var(--green))"></div></div>
      <div class="row-sm" style="gap:var(--s-5);flex-wrap:wrap;font-size:12px">
        <span>deleted <b class="mono">${lgcNum(j.deleted)}</b> / ${lgcNum(j.expiredAtStart)} sessions (${pct}%)</span>
        <span>batches <b class="mono">${lgcNum(j.batches)}</b></span>
        <span>last batch <b class="mono">${j.lastBatchMs != null ? dur(j.lastBatchMs) : '—'}</b></span>
        <span>rate <b class="mono">${lgcNum(Math.round(rate))}</b>/s</span>
        <span>ETA <b class="mono">${eta}</b></span>
        <span class="faint">started ${escHtml(deTime(j.startedAt))}${j.finishedAt ? ' · finished ' + escHtml(deTime(j.finishedAt)) : ''}</span>
      </div>
      ${j.error ? `<div class="mono" style="margin-top:var(--s-2);font-size:11px;color:var(--red);word-break:break-all">${escHtml(j.error)}</div>` : ''}
    </div>
  </div>`;
}

function lgcRender() {
  const el = document.getElementById('lgcBody');
  if (!el || !lgcState.data) return;
  el.innerHTML = lgcJobPanel() + lgcOverviewPanel() + lgcRunPanel();
}

async function lgcLoad() {
  const el = document.getElementById('lgcBody');
  if (!el) return;
  try {
    lgcState.data = await apiFetch(`/api/log-cleanup/overview?retentionDays=${encodeURIComponent(lgcState.form.retentionDays)}`);
    lgcState.job = lgcState.data.job;
    lgcRender();
    if (lgcJobActive(lgcState.job)) lgcPoll();
  } catch (e) {
    el.innerHTML = errorState(e.message);
  }
}

function lgcPoll() {
  clearTimeout(lgcTimer);
  lgcTimer = setTimeout(async () => {
    if (!document.getElementById('lgcBody')) return;
    try {
      const { job } = await apiFetch('/api/log-cleanup/status');
      const wasActive = lgcJobActive(lgcState.job);
      lgcState.job = job;
      if (wasActive && !lgcJobActive(job)) {
        const title = job.status === 'done' ? 'Log cleanup finished' : `Log cleanup ${job.status}`;
        const body = `${job.env}: ${lgcNum(job.deleted)} sessions deleted`;
        showToast(`${title} · ${body}`, job.status === 'done' ? 'ok' : 'err');
        try { window.lcNative && window.lcNative.post('notify', { title, body }); } catch {}
        return lgcLoad();
      }
      lgcRender();
    } catch (e) {
      showToast('❌ ' + e.message);
    }
    if (lgcJobActive(lgcState.job)) lgcPoll();
  }, 2000);
}

async function lgcStart() {
  const f = lgcState.form;
  const prod = lgcEnvName() === 'production';
  if (!prod && !confirm(`Delete ${lgcNum(lgcState.data.expired)} session logs older than ${f.retentionDays} days on ${lgcEnvName()}?`)) return;
  try {
    const { job } = await apiPost('/api/log-cleanup/start', { ...f, confirmation: lgcState.confirm });
    lgcState.job = job;
    lgcState.confirm = '';
    lgcRender();
    lgcPoll();
  } catch (e) {
    showToast('❌ ' + e.message);
  }
}

async function lgcCancel() {
  try {
    const { job } = await apiPost('/api/log-cleanup/cancel', {});
    lgcState.job = job;
    showToast('Stopping after the current batch…');
    lgcRender();
  } catch (e) {
    showToast('❌ ' + e.message);
  }
}

function renderLogCleanup(el) {
  lgcState.data = null;
  lgcState.confirm = '';
  el.innerHTML = pageWrap(
    pageHero('Log Cleanup', {
      sub: 'Serverpod deletes expired session logs in one statement, which times out on a large backlog ("FAILED TO CLEAN UP LOGS"). This deletes them in small batches instead, on the connected environment.',
      actions: btnGhost('Refresh', 'lgcLoad()', { icon: 'refresh' }),
    }) + `<div id="lgcBody">${loadingState('Counting session logs…')}</div>`
  );
  lgcLoad();
}
