// ═════════════════════════════════════════════════════════════════════════
// DB DIAGNOSTICS — is something making the database slow or stuck?
// ═════════════════════════════════════════════════════════════════════════
let dgState = { overview: null, rds: null, slow: null, overviewError: '', rdsError: '' };

function dgBytes(n) {
  if (n === null || n === undefined) return '—';
  const u = ['B', 'KB', 'MB', 'GB', 'TB'];
  let v = Number(n), i = 0;
  while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
  return `${v >= 100 || i === 0 ? Math.round(v) : v.toFixed(1)} ${u[i]}`;
}

function dgNum(n) {
  return n === null || n === undefined ? '—' : Number(n).toLocaleString('de-DE');
}

function dgSecs(s) {
  s = Number(s) || 0;
  if (s < 60) return `${s}s`;
  if (s < 3600) return `${Math.floor(s / 60)}m ${s % 60}s`;
  return `${Math.floor(s / 3600)}h ${Math.floor((s % 3600) / 60)}m`;
}

function dgLatest(series, name) {
  const s = series && series[name];
  return s && s.length ? s[s.length - 1].v : null;
}

function dgSpark(points, color) {
  if (!points || points.length < 2) return '';
  const w = 160, h = 32, vals = points.map(p => p.v);
  const min = Math.min(...vals), max = Math.max(...vals), span = max - min || 1;
  const xy = vals.map((v, i) => `${(i * w / (vals.length - 1)).toFixed(1)},${(h - 2 - ((v - min) / span) * (h - 4)).toFixed(1)}`).join(' ');
  return `<svg viewBox="0 0 ${w} ${h}" preserveAspectRatio="none" style="width:100%;height:${h}px;display:block;margin-top:6px">
    <polyline fill="none" stroke="${color}" stroke-width="1.6" stroke-linejoin="round" points="${xy}"/></svg>`;
}

// ─── Findings: turn raw numbers into a short verdict list ────────────────
function dgFindings(ov, rds) {
  const out = [];
  const add = (level, title, detail) => out.push({ level, title, detail });
  const series = rds && rds.series;

  if (series) {
    const ebs = dgLatest(series, 'EBSByteBalance%');
    if (ebs !== null && ebs < 5) add('err', 'Disk bandwidth exhausted', `EBSByteBalance% is ${ebs.toFixed(1)}%. AWS is throttling the disk, so queries slow down or time out.`);
    else if (ebs !== null && ebs < 30) add('warn', 'Disk bandwidth running low', `EBSByteBalance% is ${ebs.toFixed(1)}%. At 0% the disk gets throttled.`);
    const rl = dgLatest(series, 'ReadLatency');
    if (rl !== null && rl > 0.01) add('err', 'Slow disk reads', `ReadLatency is ${(rl * 1000).toFixed(1)} ms (normal is about 1 ms).`);
    else if (rl !== null && rl > 0.005) add('warn', 'Disk reads slower than normal', `ReadLatency is ${(rl * 1000).toFixed(1)} ms.`);
    const mem = dgLatest(series, 'FreeableMemory');
    if (mem !== null && mem < 100 * 1024 * 1024) add('warn', 'Very little free memory', `${dgBytes(mem)} free on ${escHtml(rds.instanceClass || 'the instance')}: almost nothing stays cached, so most queries read from disk.`);
    const disk = dgLatest(series, 'FreeStorageSpace');
    if (disk !== null && disk < 5 * 1024 ** 3) add('err', 'Storage almost full', `${dgBytes(disk)} left. Postgres stops accepting writes when it runs out.`);
    else if (disk !== null && disk < 10 * 1024 ** 3) add('warn', 'Storage getting low', `${dgBytes(disk)} left.`);
  }

  if (ov) {
    if (ov.blocked.length) add('err', `${ov.blocked.length} blocked quer${ov.blocked.length === 1 ? 'y' : 'ies'}`, 'Another session holds a lock they need. See "Blocked" below for the culprit.');
    if (ov.longRunning.length) add('warn', `${ov.longRunning.length} quer${ov.longRunning.length === 1 ? 'y' : 'ies'} running longer than 5 s`, 'Check the wait event: IO means the disk is the bottleneck.');
    const staleTx = ov.idleInTx.filter(r => r.open_seconds > 60);
    if (staleTx.length) add('warn', `${staleTx.length} transaction${staleTx.length === 1 ? '' : 's'} left open over a minute`, 'The app opened a transaction and did not finish it; this can block other work.');
    for (const t of ov.seqScans) {
      if (dgSeqVerdict(t) === 'now' && t.bytes > 20 * 1024 * 1024) {
        add('warn', `Possible missing index on ${escHtml(t.table)}`, `${dgNum(t.delta_scans)} full-table reads of a ${dgBytes(t.bytes)} table in the last ${dgSecs(t.delta_seconds)}.`);
      }
    }
    if (ov.seqScans.length && !ov.seqScans.some(t => t.delta_scans !== undefined)) {
      add('info', 'Full-table reads: no earlier check to compare with', 'The counts below are totals since the stats were last reset. Refresh in a few minutes to see which tables are being read in full right now.');
    }
    const ls = ov.logSettings;
    if (ls && (ls.logAllQueries || ls.logAllSessions)) add('err', 'Serverpod is logging every request', `logAllQueries=${!!ls.logAllQueries}, logAllSessions=${!!ls.logAllSessions}. This filled prod with a 51 GB query log on 2026-09-30.`);
    const ql = ov.biggest.find(t => t.table === 'serverpod_query_log');
    if (ql && ql.total_bytes > 5 * 1024 ** 3) add('warn', 'serverpod_query_log is large', `${dgBytes(ql.total_bytes)}. Serverpod's cleanup times out on tables this size.`);
    if (!ov.statements.installed) add('info', 'Query statistics are off', 'Enable pg_stat_statements below to see which queries cost the most.');
  }

  if (!out.some(f => f.level === 'err' || f.level === 'warn')) add('ok', 'No problems detected', 'Nothing blocked, nothing long-running, disk and memory look fine.');
  return out;
}

function dgFindingsPanel(findings) {
  const icon = { err: 'error', warn: 'warning', ok: 'check_circle', info: 'info' };
  const rows = findings.map(f => `<div style="display:flex;gap:10px;align-items:flex-start;padding:8px 0;border-bottom:1px solid var(--rule)">
      <span class="pill ${f.level === 'info' ? 'info' : f.level}" style="flex-shrink:0"><span class="material-symbols-outlined" style="font-size:14px">${icon[f.level]}</span>${f.level === 'err' ? 'Problem' : f.level === 'warn' ? 'Watch' : f.level === 'ok' ? 'OK' : 'Note'}</span>
      <div><div style="font-weight:600">${f.title}</div><div style="font-size:12.5px;color:var(--ink-3)">${f.detail}</div></div>
    </div>`).join('');
  return `<div class="panel" style="margin-bottom:var(--s-4)">
    <div class="panel-header"><span class="panel-title"><span class="material-symbols-outlined">troubleshoot</span>Findings</span></div>
    <div class="panel-body" style="padding-top:0;padding-bottom:0">${rows}</div>
  </div>`;
}

// ─── RDS metric tiles ────────────────────────────────────────────────────
const DG_TILES = [
  { name: 'EBSByteBalance%', label: 'Disk bandwidth left', fmt: v => `${v.toFixed(1)}%`, level: v => v < 5 ? 'err' : v < 30 ? 'warn' : 'ok' },
  { name: 'ReadLatency', label: 'Read latency', fmt: v => `${(v * 1000).toFixed(1)} ms`, level: v => v > 0.01 ? 'err' : v > 0.005 ? 'warn' : 'ok' },
  { name: 'WriteLatency', label: 'Write latency', fmt: v => `${(v * 1000).toFixed(1)} ms`, level: v => v > 0.02 ? 'err' : v > 0.01 ? 'warn' : 'ok' },
  { name: 'DiskQueueDepth', label: 'Disk queue', fmt: v => v.toFixed(2), level: v => v > 2 ? 'err' : v > 0.5 ? 'warn' : 'ok' },
  { name: 'CPUUtilization', label: 'CPU', fmt: v => `${v.toFixed(0)}%`, level: v => v > 85 ? 'err' : v > 60 ? 'warn' : 'ok' },
  { name: 'FreeableMemory', label: 'Free memory', fmt: v => dgBytes(v), level: v => v < 100 * 1024 * 1024 ? 'warn' : 'ok' },
  { name: 'FreeStorageSpace', label: 'Free storage', fmt: v => dgBytes(v), level: v => v < 5 * 1024 ** 3 ? 'err' : v < 10 * 1024 ** 3 ? 'warn' : 'ok' },
  { name: 'DatabaseConnections', label: 'Connections', fmt: v => v.toFixed(0), level: () => 'ok' },
];

function dgRdsPanel(rds, err) {
  const head = `<div class="panel-header"><span class="panel-title"><span class="material-symbols-outlined">storage</span>RDS instance</span>
    <span class="count mono" style="font-size:12px;color:var(--ink-3)">${rds && rds.instanceId ? `${escHtml(rds.instanceId)} · ${escHtml(rds.instanceClass || '')} · ${escHtml(rds.status || '')} · last ${rds.hours}h, 5-min averages` : ''}</span></div>`;
  if (err) return `<div class="panel" style="margin-bottom:var(--s-4)">${head}<div class="panel-body mono" style="font-size:12px;color:var(--red)">${escHtml(err)}</div></div>`;
  if (!rds || !rds.instanceId) return `<div class="panel" style="margin-bottom:var(--s-4)">${head}<div class="panel-body" style="font-size:12.5px;color:var(--ink-3)">No RDS instance for this connection (local database), so there are no AWS disk metrics.</div></div>`;
  const colors = { ok: 'var(--green)', warn: 'var(--yellow)', err: 'var(--red)' };
  const tiles = DG_TILES.map(t => {
    const pts = rds.series[t.name] || [];
    const v = pts.length ? pts[pts.length - 1].v : null;
    const lvl = v === null ? '' : t.level(v);
    return `<div style="border:1px solid var(--rule);border-radius:8px;padding:10px 12px">
      <div style="font-size:11.5px;color:var(--ink-3);display:flex;align-items:center;gap:6px"><span class="dot ${lvl}"></span>${escHtml(t.label)}</div>
      <div class="mono" style="font-size:20px;font-weight:700;margin-top:4px">${v === null ? '—' : t.fmt(v)}</div>
      ${dgSpark(pts, colors[lvl] || 'var(--ink-3)')}
    </div>`;
  }).join('');
  const pending = rds.pending && Object.keys(rds.pending).length
    ? `<div style="font-size:12px;color:var(--ink-3);margin-top:8px">Pending change: <span class="mono">${escHtml(JSON.stringify(rds.pending))}</span></div>` : '';
  return `<div class="panel" style="margin-bottom:var(--s-4)">${head}
    <div class="panel-body"><div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(170px,1fr));gap:var(--s-3)">${tiles}</div>${pending}</div>
  </div>`;
}

// ─── Tables ──────────────────────────────────────────────────────────────
function dgSection(title, icon, count, bodyHtml, note = '') {
  return `<div class="panel" style="margin-bottom:var(--s-4);overflow:hidden">
    <div class="panel-header"><span class="panel-title"><span class="material-symbols-outlined">${icon}</span>${escHtml(title)}${count !== null ? `<span class="count">${count}</span>` : ''}</span></div>
    ${note ? `<div style="font-size:12px;color:var(--ink-3);padding:8px var(--panel-pad) 0">${note}</div>` : ''}
    ${bodyHtml}
  </div>`;
}

function dgTable(headers, rows) {
  if (!rows.length) return `<div class="panel-body" style="font-size:12.5px;color:var(--ink-3)">None</div>`;
  return `<div style="overflow-x:auto"><table class="lc-table"><thead><tr>${headers.map(h => `<th>${h}</th>`).join('')}</tr></thead><tbody>${rows.join('')}</tbody></table></div>`;
}

function dgQueryCell(q) {
  return `<td class="mono" style="font-size:11.5px;max-width:560px;white-space:normal;word-break:break-word" title="${escHtml(q || '')}">${escHtml(q || '')}</td>`;
}

function dgLivePanels(ov) {
  const conn = ov.connections.map(c => `<span class="pill ${c.state === 'active' ? 'ok' : c.state.startsWith('idle in') ? 'warn' : 'ghost'}">${escHtml(c.state)} <b class="mono">${c.count}</b></span>`).join(' ');
  const long = dgTable(['PID', 'Running', 'State', 'Waiting on', 'Query'], ov.longRunning.map(r => `<tr>
    <td class="mono">${r.pid}</td><td class="mono">${dgSecs(r.seconds)}</td><td>${escHtml(r.state || '')}</td>
    <td>${r.wait_event_type ? statusBadge(`${r.wait_event_type}: ${r.wait_event}`, r.wait_event_type === 'IO' ? 'amber' : r.wait_event_type === 'Lock' ? 'error' : 'slate') : '—'}</td>
    ${dgQueryCell(r.query)}</tr>`));
  const blocked = dgTable(['Blocked PID', 'Waiting', 'Blocked query', 'Blocker PID', 'Blocker state', 'Blocker query'], ov.blocked.map(r => `<tr>
    <td class="mono">${r.blocked_pid}</td><td class="mono">${dgSecs(r.waiting_seconds)}</td>${dgQueryCell(r.blocked_query)}
    <td class="mono">${r.blocker_pid}</td><td>${escHtml(r.blocker_state || '')}</td>${dgQueryCell(r.blocker_query)}</tr>`));
  const idle = dgTable(['PID', 'Open for', 'Last query'], ov.idleInTx.map(r => `<tr>
    <td class="mono">${r.pid}</td><td class="mono">${dgSecs(r.open_seconds)}</td>${dgQueryCell(r.last_query)}</tr>`));
  return dgSection('Connections', 'lan', null, `<div class="panel-body" style="display:flex;gap:6px;flex-wrap:wrap">${conn || 'None'}</div>`)
    + dgSection('Running longer than 5 s', 'hourglass_top', ov.longRunning.length, long, 'Wait event <b>IO</b> means the disk is the bottleneck; <b>Lock</b> means another session is in the way.')
    + dgSection('Blocked', 'block', ov.blocked.length, blocked, 'The blocker is holding a lock the blocked query needs.')
    + dgSection('Transactions left open (idle in transaction)', 'pending', ov.idleInTx.length, idle);
}

// Full-read counters are lifetime totals, so on their own they keep flagging
// problems that were fixed long ago. Compare with the previous check (kept per
// environment in localStorage) to see what is being read in full right now.
function dgSeqKey(env) {
  return `lc_dg_seq_${env}`;
}

function dgApplySeqDeltas(ov, env) {
  let prev = null;
  try { prev = JSON.parse(localStorage.getItem(dgSeqKey(env)) || 'null'); } catch {}
  const now = Date.now();
  const usable = prev && prev.statsReset === ov.statsReset && now - prev.at < 24 * 3600 * 1000;
  for (const t of ov.seqScans) {
    const p = usable && prev.tables[t.table];
    if (!p) continue;
    t.delta_scans = Math.max(0, t.seq_scans - p.seq_scans);
    t.delta_rows = Math.max(0, t.rows_read - p.rows_read);
    t.delta_seconds = Math.round((now - prev.at) / 1000);
  }
  const tables = {};
  for (const t of ov.seqScans) tables[t.table] = { seq_scans: t.seq_scans, rows_read: t.rows_read };
  try { localStorage.setItem(dgSeqKey(env), JSON.stringify({ at: now, statsReset: ov.statsReset, tables })); } catch {}
}

function dgSeqVerdict(t) {
  const heavy = (scans, rows) => scans > 0 && t.live_rows > 1000 && rows / scans > t.live_rows * 0.5;
  if (t.delta_scans !== undefined) return heavy(t.delta_scans, t.delta_rows) ? 'now' : heavy(t.seq_scans, t.rows_read) ? 'past' : '';
  return t.seq_scans > 100 && heavy(t.seq_scans, t.rows_read) ? 'unknown' : '';
}

function dgSeqScanPanel(ov) {
  const badges = {
    now: statusBadge('reads whole table now', 'amber'),
    past: '<span class="pill ghost">only in the past</span>',
    unknown: '<span class="pill ghost">in the past — refresh to compare</span>',
  };
  const rows = ov.seqScans.map(t => {
    const avg = t.seq_scans ? t.rows_read / t.seq_scans : 0;
    const recent = t.delta_scans === undefined ? '—' : `+${dgNum(t.delta_scans)} <span style="color:var(--ink-3)">in ${dgSecs(t.delta_seconds)}</span>`;
    return `<tr><td class="mono">${escHtml(t.table)}</td><td class="mono">${dgBytes(t.bytes)}</td>
      <td class="mono">${recent}</td>
      <td class="mono">${dgNum(t.seq_scans)}</td><td class="mono">${dgNum(t.index_scans)}</td>
      <td class="mono">${dgNum(Math.round(avg))} / ${dgNum(t.live_rows)}</td>
      <td>${badges[dgSeqVerdict(t)] || ''}</td></tr>`;
  });
  const since = ov.statsReset ? escHtml(deTime(ov.statsReset)) : 'the last stats reset';
  return dgSection('Full-table reads (tables over 10 MB)', 'manage_search', ov.seqScans.length,
    dgTable(['Table', 'Size', 'Since last check', 'Full reads (total)', 'Index lookups (total)', 'Rows per read / total', ''], rows),
    `Many full reads of a big table usually means a missing index. Totals count since ${since}; "Since last check" shows what happened between your last two refreshes, which is what matters now.`);
}

function dgBiggestPanel(ov) {
  const rows = ov.biggest.map(t => `<tr><td class="mono">${escHtml(t.table)}</td><td class="mono">${dgBytes(t.total_bytes)}</td>
    <td class="mono">${dgBytes(t.table_bytes)}</td><td class="mono">${dgNum(t.live_rows)}</td><td class="mono">${dgNum(t.dead_rows)}</td></tr>`);
  return dgSection('Largest tables', 'database', null, dgTable(['Table', 'Total (with indexes)', 'Table only', 'Rows', 'Dead rows'], rows),
    `Whole database: <b class="mono">${dgBytes(ov.dbBytes)}</b>.`);
}

function dgStatementsPanel(ov) {
  const st = ov.statements;
  if (!st.installed) {
    return dgSection('Most expensive queries', 'leaderboard', null,
      `<div class="panel-body" style="font-size:12.5px;color:var(--ink-3)">pg_stat_statements is not enabled on this database. Enabling it only starts collecting statistics; it does not change any data.
        <div style="margin-top:10px">${btnGhost('Enable query statistics', 'dgEnableStatements()', { icon: 'play_arrow' })}</div></div>`);
  }
  if (st.error) {
    return dgSection('Most expensive queries', 'leaderboard', null,
      `<div class="panel-body mono" style="font-size:12px;color:var(--red)">${escHtml(st.error)}</div>`,
      'If this mentions shared_preload_libraries, the RDS parameter group needs pg_stat_statements added first.');
  }
  const rows = st.rows.map(r => `<tr><td class="mono">${dgNum(r.calls)}</td><td class="mono">${dgSecs(Math.round(r.total_ms / 1000))}</td>
    <td class="mono">${r.mean_ms} ms</td><td class="mono">${dgNum(r.disk_blocks_read)}</td>${dgQueryCell(r.query)}</tr>`);
  return dgSection('Most expensive queries (pg_stat_statements)', 'leaderboard', st.rows.length,
    dgTable(['Calls', 'Total time', 'Avg', 'Disk blocks read', 'Query'], rows),
    'High "Disk blocks read" is what drains a t3.micro. Queries show placeholders ($1), not real values.');
}

function dgSlowPanel() {
  const s = dgState.slow;
  const btn = btnGhost(s ? 'Reload' : 'Load slow queries (last 24 h)', 'dgLoadSlow()', { icon: 'history' });
  let body = `<div class="panel-body" style="font-size:12.5px;color:var(--ink-3)">Queries Serverpod recorded as taking 1 s or more. Loaded on demand because the log tables can be large.<div style="margin-top:10px">${btn}</div></div>`;
  if (s && s.error) body = `<div class="panel-body mono" style="font-size:12px;color:var(--red)">${escHtml(s.error)}<div style="margin-top:10px">${btn}</div></div>`;
  else if (s && s.rows) {
    body = `<div class="panel-body" style="padding-bottom:0">${btn}</div>` + dgTable(['When', 'Seconds', '', 'Query'], s.rows.map(r => `<tr>
      <td class="mono" style="white-space:nowrap">${escHtml(deTime(r.at))}</td><td class="mono">${r.seconds}</td>
      <td>${r.failed ? statusBadge('failed', 'error') : ''}</td>${dgQueryCell(r.query)}</tr>`));
  }
  return `<div id="dgSlow">${dgSection('Slow queries recorded by Serverpod', 'timer', s && s.rows ? s.rows.length : null, body,
    'These are the real statements and can contain patient data: scrub before sharing.')}</div>`;
}

function dgLogSettingsPanel(ov) {
  const ls = ov.logSettings;
  if (!ls) return '';
  const flag = (k, bad) => `<span class="pill ${ls[k] === bad ? 'err' : 'ghost'}">${k}: <b>${String(!!ls[k])}</b></span>`;
  return dgSection('Serverpod log settings', 'tune', null,
    `<div class="panel-body" style="display:flex;gap:6px;flex-wrap:wrap">${flag('logAllQueries', true)} ${flag('logAllSessions', true)}
      <span class="pill ghost">logLevel: <b>${ls.logLevel}</b></span>
      <span class="pill ghost">slowQueryDuration: <b>${ls.slowQueryDuration}s</b></span></div>`,
    'Recommended: logAllQueries and logAllSessions off; slow and failed logging on.');
}

// ─── Actions ─────────────────────────────────────────────────────────────
async function dgEnableStatements() {
  const env = document.getElementById('envBtn')?.dataset.env || 'dev';
  if (!confirm(`Enable pg_stat_statements on ${env.toUpperCase()}?\n\nRuns: CREATE EXTENSION IF NOT EXISTS pg_stat_statements\nIt only collects query statistics; no data is changed.`)) return;
  try {
    await apiPost('/api/db-diag/enable-statements', { confirm: true });
    showToast('✓ Query statistics enabled — give it 15–30 min to collect data');
    renderDbDiagnostics(document.getElementById('content'));
  } catch (e) {
    alert('Could not enable: ' + e.message);
  }
}

async function dgLoadSlow() {
  const slot = document.getElementById('dgSlow');
  if (slot) slot.innerHTML = dgSection('Slow queries recorded by Serverpod', 'timer', null, loadingState('Reading serverpod_query_log…'));
  try {
    dgState.slow = await apiFetch('/api/db-diag/slow-queries?hours=24');
  } catch (e) {
    dgState.slow = { error: e.message };
  }
  const el = document.getElementById('dgSlow');
  if (el) el.outerHTML = dgSlowPanel();
}

// ─── Render ──────────────────────────────────────────────────────────────
async function renderDbDiagnostics(el) {
  const env = document.getElementById('envBtn')?.dataset.env || 'dev';
  const refresh = btnGhost('Refresh', "renderDbDiagnostics(document.getElementById('content'))", { icon: 'refresh' });
  el.innerHTML = pageWrap(pageHero('DB Diagnostics', { sub: `Environment: ${escHtml(env)}`, actions: refresh }) + loadingState('Checking the database…'));

  const [ov, rds] = await Promise.allSettled([apiFetch('/api/db-diag/overview'), apiFetch('/api/db-diag/rds')]);
  dgState.overview = ov.status === 'fulfilled' ? ov.value : null;
  dgState.overviewError = ov.status === 'rejected' ? ov.reason.message : '';
  dgState.rds = rds.status === 'fulfilled' ? rds.value : null;
  dgState.rdsError = rds.status === 'rejected' ? rds.reason.message : '';
  dgState.slow = null;
  setConnStatus(dgState.overview ? 'connected' : 'error');

  const o = dgState.overview;
  if (o) dgApplySeqDeltas(o, env);
  const sub = `Environment: <b>${escHtml(env)}</b>${dgState.rds && dgState.rds.instanceId ? ` · ${escHtml(dgState.rds.instanceId)} (${escHtml(dgState.rds.instanceClass || '')})` : ''} · checked ${escHtml(deTime(new Date().toISOString()))}`;
  let body = dgFindingsPanel(dgFindings(o, dgState.rds)) + dgRdsPanel(dgState.rds, dgState.rdsError);
  if (o) {
    body += dgLivePanels(o) + dgSeqScanPanel(o) + dgStatementsPanel(o) + dgSlowPanel() + dgBiggestPanel(o) + dgLogSettingsPanel(o);
  } else {
    body += errorState(`Could not query the database: ${dgState.overviewError}`);
  }
  el.innerHTML = pageWrap(pageHero('DB Diagnostics', { sub, actions: refresh }) + body);
}
