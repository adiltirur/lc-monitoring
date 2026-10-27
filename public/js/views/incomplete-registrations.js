// ═════════════════════════════════════════════════════════════════════════
// INCOMPLETE REGISTRATIONS — signups that never reached app_user_info
// ═════════════════════════════════════════════════════════════════════════
//
// The Users view only lists app_user_info. This one lists everyone who started
// a registration and stopped: a pending email verification request, an auth
// account with no profile (new or old app), or a legacy request. Items older
// than the chosen age can be deleted; each run can be dry-run first.

let irState = { data: null, age: 24, kind: '', q: '', selected: new Set(), confirm: '', busy: false, result: null };

const IR_KIND = {
  'request':        { label: 'pending verification', pill: 'info' },
  'account':        { label: 'no profile',           pill: 'warn' },
  'legacy':         { label: 'legacy user',          pill: 'warn' },
  'legacy-request': { label: 'legacy request',       pill: '' },
};

const IR_AGES = [
  { value: 1, label: 'older than 1 hour' },
  { value: 24, label: 'older than 24 hours' },
  { value: 168, label: 'older than 7 days' },
  { value: 720, label: 'older than 30 days' },
];

function irEnvName() {
  return irState.data?.env || document.getElementById('envBtn')?.dataset.env || 'dev';
}

function irConfirmPhrase(n) {
  return `DELETE ${n} REGISTRATIONS${irEnvName() === 'production' ? ' ON PRODUCTION' : ''}`;
}

function irEligible(item) {
  if (item.blockers.length) return false;
  if (item.lastActivity === null) return true;
  return new Date(item.lastActivity) < new Date(Date.now() - irState.age * 3600 * 1000);
}

function irVisible() {
  const q = irState.q.trim().toLowerCase();
  return (irState.data?.items || []).filter(i =>
    (!irState.kind || i.kind === irState.kind) &&
    (!q || [i.email, i.name, i.id].some(v => String(v ?? '').toLowerCase().includes(q))));
}

function irSelectedKeys() {
  const eligible = new Set(irVisible().filter(irEligible).map(i => i.key));
  return [...irState.selected].filter(k => eligible.has(k));
}

function irAgeText(d) {
  if (!d) return 'unknown';
  const h = (Date.now() - new Date(d).getTime()) / 3600000;
  if (h < 1) return `${Math.max(1, Math.round(h * 60))} min ago`;
  if (h < 48) return `${Math.round(h)} h ago`;
  return `${Math.round(h / 24)} days ago`;
}

function irDetails(i) {
  const d = i.details, parts = [];
  if (i.kind === 'account') {
    parts.push(d.emailAccountId ? 'email login' : 'no email login');
    if (d.oldUserId !== null) parts.push(`legacy user ${escHtml(d.oldUserId)}`);
    parts.push(`${d.sessions} session(s)`);
    if (d.blocked) parts.push('<span class="err">blocked</span>');
  }
  if (i.kind === 'request' && d.hasAccount) parts.push('email login exists');
  return parts.join(' · ');
}

function irRow(i) {
  const k = IR_KIND[i.kind] || { label: i.kind, pill: '' };
  const ok = irEligible(i);
  const notes = [...i.blockers.map(b => `<div class="ir-block">${escHtml(b)}</div>`), ...i.warnings.map(w => `<div class="ir-warn">${escHtml(w)}</div>`)].join('');
  return `<tr class="${ok ? '' : 'ir-recent'}">
    <td><input type="checkbox" ${ok ? '' : 'disabled'} ${irState.selected.has(i.key) && ok ? 'checked' : ''} onchange="irToggle('${escHtml(i.key)}', this.checked)"
      title="${ok ? '' : i.blockers.length ? 'Blocked' : 'Active within the selected age'}"></td>
    <td style="word-break:break-all"><div>${escHtml(i.email) || '<span class="faint">no email</span>'}</div>
      ${i.name ? `<div class="list-meta" style="margin:2px 0 0">${escHtml(i.name)}</div>` : ''}</td>
    <td><span class="pill ${k.pill}">${escHtml(k.label)}</span><div class="list-meta" style="margin:4px 0 0">${escHtml(i.stage)}</div></td>
    <td class="mono" style="font-size:12px;white-space:nowrap">${escHtml(deTime(i.createdAt)) || '—'}</td>
    <td style="font-size:12px;white-space:nowrap">${escHtml(irAgeText(i.lastActivity))}</td>
    <td style="font-size:12px">${irDetails(i)}${notes}<div class="mono faint" style="font-size:11px;margin-top:2px">${escHtml(i.id)}</div></td>
  </tr>`;
}

function irResultPanel() {
  const r = irState.result;
  if (!r) return '';
  if (r.error) return `<div class="panel" style="margin-bottom:var(--s-4)"><div class="panel-body ir-block">${escHtml(r.error)}</div></div>`;
  const sum = obj => Object.entries(obj || {}).map(([t, n]) => `${t} ${n}`).join(', ') || '—';
  const rows = r.results.map(x => `<tr>
      <td style="word-break:break-all">${escHtml(x.email || x.key)}</td>
      <td>${x.ok ? '<span class="pill ok">ok</span>' : '<span class="pill err">failed</span>'}</td>
      <td style="font-size:12px">${x.ok ? escHtml(sum(x.deleted)) : `<span class="ir-block">${escHtml(x.error)}</span>`}</td>
    </tr>`).join('');
  return `<div class="panel" style="margin-bottom:var(--s-4)">
    <div class="panel-header"><span class="panel-title"><span class="material-symbols-outlined">${r.dryRun ? 'science' : 'task_alt'}</span>${r.dryRun ? 'Dry run (rolled back)' : 'Cleanup report'} · ${escHtml(r.env)}</span>
      <div class="panel-actions"><button class="lc-icon-btn" title="Close" onclick="irState.result=null;irRender()"><span class="material-symbols-outlined">close</span></button></div></div>
    <div class="panel-body">
      <div class="row-sm" style="margin-bottom:var(--s-3)">
        <span class="pill">processed <b class="mono">${r.processed}</b></span>
        <span class="pill ok">${r.dryRun ? 'would be deleted' : 'deleted'} <b class="mono">${r.done}</b></span>
        <span class="pill ${r.failed ? 'err' : ''}">failed <b class="mono">${r.failed}</b></span>
        ${r.backupDir ? `<span class="list-meta" style="margin:0">backup: <span class="mono">${escHtml(r.backupDir)}</span></span>` : ''}
      </div>
      <table class="lc-table"><thead><tr><th>Email</th><th>Result</th><th>Deleted rows</th></tr></thead><tbody>${rows}</tbody></table>
    </div>
  </div>`;
}

function irCleanupPanel() {
  const keys = irSelectedKeys();
  if (!keys.length) return '';
  const phrase = irConfirmPhrase(keys.length);
  const prod = irEnvName() === 'production';
  return `<section class="panel lc-destructive" data-band="Destructive — deletes accounts${prod ? ' on PRODUCTION' : ''}" style="margin-bottom:var(--s-4)">
    <div class="panel-header"><span class="panel-title"><span class="material-symbols-outlined">delete_sweep</span>Delete ${keys.length} incomplete registration(s)</span></div>
    <div class="panel-body">
      <div class="list-meta" style="margin:0 0 var(--s-3)">Pending requests: the request, its codes and the code outbox row. Accounts: the auth user with its email login,
        sessions, tokens and auth profile, plus the legacy serverpod_user_info and legacy login when it came from the old app. Email-keyed leftovers are only
        removed when no profile uses the email. One transaction per item, re-checked under a row lock; a JSON backup is written before COMMIT. The person can register again afterwards.</div>
      <div class="row-sm">
        ${btnGhost(irState.busy ? 'Running…' : 'Dry run', 'irRun(true)', { icon: 'science' })}
        <input class="lc-input mono" style="width:360px" placeholder="type ${escHtml(phrase)}" value="${escHtml(irState.confirm)}" oninput="irState.confirm=this.value;document.getElementById('irRunBtn').disabled=this.value!=='${escHtml(phrase)}'">
        <button id="irRunBtn" class="btn btn-danger" onclick="irRun(false)" ${irState.confirm === phrase ? '' : 'disabled'}><span class="material-symbols-outlined">delete_forever</span>Delete ${keys.length}</button>
      </div>
    </div>
  </section>`;
}

function irRender() {
  const el = document.getElementById('content');
  if (!el || !irState.data) return;
  const all = irState.data.items;
  const visible = irVisible();
  const eligible = visible.filter(irEligible);
  const allChecked = eligible.length && eligible.every(i => irState.selected.has(i.key));
  const count = kind => all.filter(i => i.kind === kind).length;
  const filters =
    `<div class="field col-span-2">${fLabel('Search')}<input id="irQ" class="lc-input" placeholder="email / name / id" value="${escHtml(irState.q)}"
      oninput="irState.q=this.value" onkeydown="if(event.key==='Enter')irRender()"></div>` +
    fSelect('Kind', [{ value: '', label: 'All kinds' }, ...Object.entries(IR_KIND).map(([value, k]) => ({ value, label: k.label }))],
      `onchange="irState.kind=this.value;irRender()"`, irState.kind) +
    fSelect('Can be deleted when', IR_AGES, `onchange="irState.age=Number(this.value);irState.confirm='';irRender()"`, irState.age) +
    `<div></div><div class="flex gap-2">${btnPrimary('Search', 'irRender()', { full: true })}</div>`;
  el.innerHTML = pageWrap(
    pageHero('Incomplete Registrations', {
      sub: 'People who started registering but never got an app profile (not listed under Users).',
      actions: btnGhost('Users', "navigate('users')", { icon: 'person_search' }) +
        btnGhost('Download log CSV', 'irDownloadLog()', { icon: 'download' }) +
        `<button class="btn btn-ghost" onclick="renderIncompleteRegistrations(document.getElementById('content'))" title="Reload"><span class="material-symbols-outlined">refresh</span></button>`,
    }) +
    `<div class="mo-stat-line" style="margin-bottom:var(--s-4)"><span class="mo-stat-label">${escHtml(irState.data.env)}</span>
      <span class="pill">total <b class="mono">${all.length}</b></span>
      ${Object.entries(IR_KIND).map(([kind, k]) => `<span class="pill ${k.pill}">${escHtml(k.label)} <b class="mono">${count(kind)}</b></span>`).join('')}
      <span class="pill ok">can be deleted <b class="mono">${all.filter(irEligible).length}</b></span>
      <span class="pill ${all.some(i => i.blockers.length) ? 'err' : ''}">blocked <b class="mono">${all.filter(i => i.blockers.length).length}</b></span>
    </div>` +
    filterCard(filters, 6) +
    irResultPanel() +
    irCleanupPanel() +
    (visible.length
      ? `<div class="panel"><table class="lc-table ir-table"><thead><tr>
          <th><input type="checkbox" ${allChecked ? 'checked' : ''} ${eligible.length ? '' : 'disabled'} onchange="irToggleAll(this.checked)" title="Select all that can be deleted"></th>
          <th>Email</th><th>Stage</th><th>Created</th><th>Last activity</th><th>Details</th></tr></thead>
          <tbody>${visible.map(irRow).join('')}</tbody></table></div>`
      : emptyState(all.length ? 'Nothing matches the filter' : 'No incomplete registrations on this environment', 'how_to_reg'))
  );
}

function irToggle(key, on) {
  if (on) irState.selected.add(key); else irState.selected.delete(key);
  irState.confirm = '';
  irRender();
}

function irToggleAll(on) {
  for (const i of irVisible().filter(irEligible)) {
    if (on) irState.selected.add(i.key); else irState.selected.delete(i.key);
  }
  irState.confirm = '';
  irRender();
}

async function renderIncompleteRegistrations(el) {
  el.innerHTML = pageWrap(pageHero('Incomplete Registrations') + loadingState());
  try {
    irState.data = await apiFetch('/api/incomplete-registrations');
    irState.selected = new Set();
    irState.confirm = '';
    setConnStatus('connected');
    irRender();
  } catch (e) {
    setConnStatus('error');
    el.innerHTML = pageWrap(pageHero('Incomplete Registrations') + errorState(e.message));
  }
}

async function irRun(dryRun) {
  if (irState.busy) return;
  const keys = irSelectedKeys();
  if (!keys.length) return;
  if (!dryRun && !confirm(`Delete ${keys.length} incomplete registration(s) on ${irEnvName().toUpperCase()}?\n\nThis cannot be undone from the helper (backups are written).`)) return;
  irState.busy = true; irRender();
  try {
    const res = await fetch('/api/incomplete-registrations/cleanup', {
      method: 'POST',
      headers: dbHeaders(dryRun ? {} : { 'x-allow-destructive': 'yes' }),
      body: JSON.stringify({ keys, olderThanHours: irState.age, dryRun, confirmation: irState.confirm }),
    });
    const result = await handleJsonResponse(res, '/api/incomplete-registrations/cleanup');
    if (!dryRun) {
      showToast(`✓ ${result.done} deleted${result.failed ? `, ${result.failed} failed` : ''}`);
      await renderIncompleteRegistrations(document.getElementById('content'));
    }
    irState.result = result;
  } catch (e) {
    irState.result = { error: e.message };
  } finally {
    irState.busy = false;
    irRender();
  }
}

async function irDownloadLog() {
  try {
    const res = await fetch('/api/incomplete-registrations/log.csv', { headers: dbHeaders() });
    if (!res.ok) { await handleJsonResponse(res, '/api/incomplete-registrations/log.csv'); return; }
    const url = URL.createObjectURL(await res.blob());
    const a = Object.assign(document.createElement('a'), { href: url, download: `incomplete-registrations-${irEnvName()}.csv` });
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  } catch (e) {
    alert(e.message);
  }
}
