// ═════════════════════════════════════════════════════════════════════════
// DUPLICATE ACCOUNTS — legacy + new-system app_user_info with the same email
// ═════════════════════════════════════════════════════════════════════════
//
// Lists every duplicate pair on the connected env with what each account holds,
// and the plan from the server. The new account is always kept: the legacy
// account's rows are moved onto it and the legacy profile + legacy auth are
// deleted. Clear pairs run in one batch; "both have data" pairs are merged one
// at a time. Every run can be dry-run first (applied, then rolled back).

let daState = { data: null, result: null, confirm: '', busy: false, merge: null };

const DA_ACTION = {
  'delete-legacy':      { label: 'delete legacy',          pill: 'ok' },
  'move-delete-legacy': { label: 'move data, delete legacy', pill: 'info' },
  'manual':             { label: 'manual review',           pill: 'warn' },
  'blocked':            { label: 'blocked',                 pill: 'err' },
};

function daEnvName() {
  return daState.data?.env || document.getElementById('envBtn')?.dataset.env || 'dev';
}

function daAutoPairs() {
  return (daState.data?.pairs || []).filter(p => p.action === 'delete-legacy' || p.action === 'move-delete-legacy');
}

function daConfirmPhrase(mode, n, legacyId) {
  const where = daEnvName() === 'production' ? ' ON PRODUCTION' : '';
  return mode === 'merge' ? `MERGE ${legacyId}${where}` : `CLEAN UP ${n} ACCOUNTS${where}`;
}

function daCounts(acc) {
  const tables = daState.data?.tables || [];
  const parts = tables.filter(t => acc.counts[t.table]).map(t =>
    `<span class="${t.data ? 'da-data' : 'faint'}">${escHtml(t.label)} ${acc.counts[t.table]}</span>`);
  if (acc.pmsPatientId) parts.push('<span class="da-data">PMS linked</span>');
  if (acc.isVerified) parts.push('<span class="da-data">verified</span>');
  return parts.join(' · ') || '<span class="faint">no data</span>';
}

function daAccountCell(acc, isNew) {
  if (!acc) return '<span class="faint">—</span>';
  const login = isNew
    ? (acc.hasNewLogin ? `last session ${escHtml(deTime(acc.lastNewSession)) || '—'}` : '<span class="err">no email login</span>')
    : (acc.hasLegacyLogin ? 'legacy login' : 'no legacy login');
  return `<div class="mono" style="font-size:12px">#${escHtml(acc.id)} · userId ${escHtml(acc.userId ?? '—')}</div>
    <div class="list-meta" style="margin:2px 0">${escHtml(acc.firstName)} ${escHtml(acc.lastName)} · created ${escHtml(deTime(acc.createdAt))} · ${login}</div>
    <div class="da-counts">${daCounts(acc)}</div>`;
}

function daPairRow(p) {
  const legacy = p.accounts.find(a => a.legacy && a.id === p.legacyId) || p.accounts.find(a => a.legacy);
  const neu = p.accounts.find(a => !a.legacy && a.id === p.newId) || p.accounts.find(a => !a.legacy);
  const a = DA_ACTION[p.action] || { label: p.action, pill: '' };
  const action = p.action === 'manual'
    ? `<button class="btn btn-sm" onclick="daOpenMerge('${escHtml(p.emailKey)}')">Merge…</button>` : '';
  return `<tr>
    <td style="word-break:break-all">${escHtml(p.email)}</td>
    <td>${daAccountCell(legacy, false)}</td>
    <td>${daAccountCell(neu, true)}</td>
    <td><span class="pill ${a.pill}">${escHtml(a.label)}</span><div class="list-meta" style="margin:4px 0 0">${escHtml(p.reason)}</div>
      ${(p.warnings || []).map(w => `<div class="da-warn">${escHtml(w)}</div>`).join('')}</td>
    <td>${action}</td>
  </tr>`;
}

function daResultPanel() {
  const r = daState.result;
  if (!r) return '';
  if (r.error) return `<div class="panel" style="margin-bottom:var(--s-4)"><div class="panel-body da-err">${escHtml(r.error)}</div></div>`;
  const sum = obj => Object.entries(obj || {}).map(([t, n]) => `${t} ${n}`).join(', ') || '—';
  const rows = r.results.map(x => `<tr>
      <td style="word-break:break-all">${escHtml(x.email)}</td>
      <td>${x.ok ? '<span class="pill ok">ok</span>' : '<span class="pill err">failed</span>'}</td>
      <td class="mono" style="font-size:12px">${x.deletedProfileId ? `#${escHtml(x.deletedProfileId)} → #${escHtml(x.keptProfileId)}` : '—'}</td>
      <td style="font-size:12px">${x.ok ? `moved: ${escHtml(sum(x.moved))}<br>deleted: ${escHtml(sum(x.deleted))}${x.updated && x.updated.app_user_info ? `<br>kept account took over: ${escHtml(x.updated.app_user_info.join(', '))}` : ''}` : `<span class="da-err">${escHtml(x.error)}</span>`}</td>
    </tr>`).join('');
  return `<div class="panel" style="margin-bottom:var(--s-4)">
    <div class="panel-header"><span class="panel-title"><span class="material-symbols-outlined">${r.dryRun ? 'science' : 'task_alt'}</span>${r.dryRun ? 'Dry run (rolled back)' : 'Cleanup report'} · ${escHtml(r.env)}</span>
      <div class="panel-actions"><button class="lc-icon-btn" title="Close" onclick="daState.result=null;daRender()"><span class="material-symbols-outlined">close</span></button></div></div>
    <div class="panel-body">
      <div class="row-sm" style="margin-bottom:var(--s-3)">
        <span class="pill">processed <b class="mono">${r.processed}</b></span>
        <span class="pill ok">${r.dryRun ? 'would succeed' : 'cleaned up'} <b class="mono">${r.done}</b></span>
        <span class="pill ${r.failed ? 'err' : ''}">failed <b class="mono">${r.failed}</b></span>
        <span class="pill warn">manual review <b class="mono">${daState.data?.summary.manual ?? 0}</b></span>
        ${r.backupDir ? `<span class="list-meta" style="margin:0">backup: <span class="mono">${escHtml(r.backupDir)}</span></span>` : ''}
      </div>
      <table class="lc-table"><thead><tr><th>Email</th><th>Result</th><th>Legacy → kept</th><th>Rows</th></tr></thead><tbody>${rows}</tbody></table>
    </div>
  </div>`;
}

function daAutoPanel() {
  const auto = daAutoPairs();
  if (!auto.length) return '';
  const phrase = daConfirmPhrase('auto', auto.length);
  const prod = daEnvName() === 'production';
  return `<section class="panel lc-destructive" data-band="Destructive — deletes accounts${prod ? ' on PRODUCTION' : ''}" style="margin-bottom:var(--s-4)">
    <div class="panel-header"><span class="panel-title"><span class="material-symbols-outlined">delete_sweep</span>Clean up ${auto.length} clear pair(s)</span></div>
    <div class="panel-body">
      <div class="list-meta" style="margin:0 0 var(--s-3)">For each pair: the legacy account's rows are moved to the new account, then the legacy profile,
        its legacy login (serverpod_email_auth, auth keys, resets) and serverpod_user_info are deleted. One transaction per pair, re-checked under row
        locks; a JSON backup of every changed row is written before COMMIT. Run the dry run first.</div>
      <div class="row-sm">
        ${btnGhost(daState.busy ? 'Running…' : 'Dry run', 'daRunAuto(true)', { icon: 'science' })}
        <input class="lc-input mono" style="width:340px" placeholder="type ${escHtml(phrase)}" value="${escHtml(daState.confirm)}" oninput="daState.confirm=this.value;document.getElementById('daRunBtn').disabled=this.value!=='${escHtml(phrase)}'">
        <button id="daRunBtn" class="btn btn-danger" onclick="daRunAuto(false)" ${daState.confirm === phrase ? '' : 'disabled'}><span class="material-symbols-outlined">delete_forever</span>Clean up ${auto.length}</button>
      </div>
    </div>
  </section>`;
}

function daRender() {
  const el = document.getElementById('content');
  if (!el || !daState.data) return;
  const d = daState.data, s = d.summary;
  const order = { 'delete-legacy': 0, 'move-delete-legacy': 1, manual: 2, blocked: 3 };
  const pairs = [...d.pairs].sort((a, b) => order[a.action] - order[b.action] || a.emailKey.localeCompare(b.emailKey));
  el.innerHTML = pageWrap(
    pageHero('Duplicate Accounts', {
      sub: 'Legacy + new-system app accounts with the same email. The new account is kept; legacy data is moved onto it.',
      actions: btnGhost('Download log CSV', 'daDownloadLog()', { icon: 'download' }) +
        `<button class="btn btn-ghost" onclick="renderDuplicateAccounts(document.getElementById('content'))" title="Reload"><span class="material-symbols-outlined">refresh</span></button>`,
    }) +
    `<div class="mo-stat-line" style="margin-bottom:var(--s-4)"><span class="mo-stat-label">${escHtml(d.env)}</span>
      <span class="pill">pairs <b class="mono">${s.pairs}</b></span>
      <span class="pill ok">delete legacy <b class="mono">${s.deleteLegacy}</b></span>
      <span class="pill info">move + delete legacy <b class="mono">${s.moveDeleteLegacy}</b></span>
      <span class="pill warn">manual review <b class="mono">${s.manual}</b></span>
      <span class="pill ${s.blocked ? 'err' : ''}">blocked <b class="mono">${s.blocked}</b></span>
    </div>` +
    daResultPanel() +
    daMergePanel() +
    daAutoPanel() +
    (pairs.length
      ? `<div class="panel"><table class="lc-table da-table"><thead><tr><th>Email</th><th>Legacy account</th><th>New account (kept)</th><th>Plan</th><th></th></tr></thead>
          <tbody>${pairs.map(daPairRow).join('')}</tbody></table></div>`
      : emptyState('No duplicate accounts on this environment', 'verified_user'))
  );
}

async function renderDuplicateAccounts(el) {
  el.innerHTML = pageWrap(pageHero('Duplicate Accounts') + loadingState());
  try {
    daState.data = await apiFetch('/api/duplicate-accounts');
    daState.confirm = '';
    setConnStatus('connected');
    daRender();
  } catch (e) {
    setConnStatus('error');
    el.innerHTML = pageWrap(pageHero('Duplicate Accounts') + errorState(e.message));
  }
}

async function daPost(body) {
  const res = await fetch('/api/duplicate-accounts/run', {
    method: 'POST',
    headers: dbHeaders(body.dryRun ? {} : { 'x-allow-destructive': 'yes' }),
    body: JSON.stringify(body),
  });
  return handleJsonResponse(res, '/api/duplicate-accounts/run');
}

function daExpect(pairs) {
  return Object.fromEntries(pairs.map(p => [p.emailKey, p.action]));
}

async function daRunAuto(dryRun) {
  if (daState.busy) return;
  const auto = daAutoPairs();
  if (!dryRun && !confirm(`Delete ${auto.length} legacy account(s) on ${daEnvName().toUpperCase()}?\n\nTheir data is moved to the new accounts first. This cannot be undone from the helper (backups are written).`)) return;
  daState.busy = true; daRender();
  try {
    daState.result = await daPost({ mode: 'auto', emails: auto.map(p => p.emailKey), expect: daExpect(auto), dryRun, confirmation: daState.confirm });
    if (!dryRun) {
      showToast(`✓ ${daState.result.done} cleaned up${daState.result.failed ? `, ${daState.result.failed} failed` : ''}`);
      const keep = daState.result;
      await renderDuplicateAccounts(document.getElementById('content'));
      daState.result = keep;
    }
  } catch (e) {
    daState.result = { error: e.message };
  } finally {
    daState.busy = false;
    daRender();
  }
}

// ─── Merge one pair (review panel) ────────────────────────────────────────
function daOpenMerge(emailKey) {
  const p = daState.data.pairs.find(x => x.emailKey === emailKey);
  if (!p) return;
  daState.merge = { emailKey, keep: {}, dry: null, confirm: '', busy: false };
  daRender();
  document.getElementById('daMerge')?.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function daInsuranceCell(ins) {
  if (!ins) return '<span class="faint">none</span>';
  return `${escHtml(ins.provider || '—')} · type ${escHtml(ins.insuranceType)} · status ${escHtml(ins.status)}
    <div class="list-meta" style="margin:2px 0 0">valid ${escHtml(deTime(ins.validity)) || '—'} · changed ${escHtml(deTime(ins.modifiedAt)) || '—'}</div>`;
}

function daMergePanel() {
  const m = daState.merge;
  if (!m) return '';
  const p = daState.data.pairs.find(x => x.emailKey === m.emailKey);
  if (!p) return '';
  const legacy = p.accounts.find(a => a.id === p.legacyId), neu = p.accounts.find(a => a.id === p.newId);
  const day = d => (d ? new Date(d).toISOString().slice(0, 10) : '—');
  const row = (label, l, n, same) => `<tr><td class="faint">${label}</td><td>${l}</td><td>${n}</td><td>${same === undefined ? '' : same ? '<span class="pill ok">same</span>' : '<span class="pill warn">differs</span>'}</td></tr>`;
  const choice = (table, side) => `<label class="row-sm"><input type="radio" name="daKeep_${table}" ${m.keep[table] === side ? 'checked' : ''} onchange="daState.merge.keep['${table}']='${side}';daState.merge.dry=null;daRender()"> keep</label>`;
  const insChoice = p.choices.includes('app_user_insurance_info');
  const sameNumber = legacy.insurance && neu.insurance ? legacy.insurance.numberHash === neu.insurance.numberHash : undefined;
  const carry = Object.entries(p.carry || {}).filter(([, v]) => v).map(([k]) => ({ lcAccountId: 'lcAccountId (Principa id)', pmsPatientId: 'PMS patient id', verified: 'verified status' })[k]);
  const missing = [...p.choices, ...(p.sameIdentity ? [] : ['profile'])].filter(t => !m.keep[t]);
  const profileChoice = p.sameIdentity ? '' : row('Profile to keep',
    `name, date of birth, gender, phone, address${legacy.praxisId ? ', praxis' : ''}, praxis code` + choice('profile', 'legacy'),
    'name, date of birth, gender, phone, address, praxis code' + choice('profile', 'new'));
  const profileNote = !p.sameIdentity && m.keep.profile === 'legacy'
    ? `<div class="da-note">The kept account (new login) gets the legacy name, date of birth and contact details; its own are overwritten.</div>`
    : !p.sameIdentity && m.keep.profile === 'new' && p.carry?.verified
      ? `<div class="da-warn">The legacy verification is not carried over: it was checked for the legacy name and date of birth.</div>` : '';
  const list = obj => Object.entries(obj || {}).map(([t, n]) => `${t} ${Array.isArray(n) ? n.join(', ') : n}`).join(' · ') || '—';
  const phrase = daConfirmPhrase('merge', 1, p.legacyId);
  const dry = m.dry
    ? (m.dry.ok
        ? `<div class="da-dry"><b>Dry run OK</b> (rolled back)<br>moved: ${escHtml(list(m.dry.moved))}<br>deleted: ${escHtml(list(m.dry.deleted))}<br>updated on the kept account: ${escHtml(list(m.dry.updated))}</div>`
        : `<div class="da-err">Dry run failed: ${escHtml(m.dry.error)}</div>`)
    : '';
  return `<section id="daMerge" class="panel lc-destructive" data-band="Merge — deletes the legacy account${daEnvName() === 'production' ? ' on PRODUCTION' : ''}" style="margin-bottom:var(--s-4)">
    <div class="panel-header"><span class="panel-title"><span class="material-symbols-outlined">merge</span>Merge ${escHtml(p.email)}</span>
      <div class="panel-actions"><button class="lc-icon-btn" title="Close" onclick="daState.merge=null;daRender()"><span class="material-symbols-outlined">close</span></button></div></div>
    <div class="panel-body">
      <table class="lc-table da-table"><thead><tr><th></th><th>Legacy #${escHtml(p.legacyId)} (deleted)</th><th>New #${escHtml(p.newId)} (kept)</th><th></th></tr></thead><tbody>
        ${row('Name', `${escHtml(legacy.firstName)} ${escHtml(legacy.lastName)}`, `${escHtml(neu.firstName)} ${escHtml(neu.lastName)}`,
              `${legacy.firstName} ${legacy.lastName}`.trim().toLowerCase() === `${neu.firstName} ${neu.lastName}`.trim().toLowerCase())}
        ${row('Date of birth', day(legacy.dob), day(neu.dob), day(legacy.dob) === day(neu.dob))}
        ${row('Data', daCounts(legacy), daCounts(neu))}
        ${row('Known to PMS', legacy.pmsKnown ? 'yes' : 'no', neu.pmsKnown ? 'yes' : 'no')}
        ${legacy.insurance || neu.insurance ? row('Insurance', daInsuranceCell(legacy.insurance) + (insChoice ? choice('app_user_insurance_info', 'legacy') : ''),
              daInsuranceCell(neu.insurance) + (insChoice ? choice('app_user_insurance_info', 'new') : ''),
              sameNumber === undefined ? undefined : sameNumber) : ''}
        ${profileChoice}
      </tbody></table>
      ${profileNote}
      ${insChoice && sameNumber !== undefined ? `<div class="list-meta" style="margin:6px 0 0">Insurance numbers ${sameNumber ? 'are the same' : 'differ'} (compared on the server, not shown).</div>` : ''}
      ${carry.length ? `<div class="da-note">The kept account takes over the legacy ${escHtml(carry.join(', '))}, so Principa's messages keep finding this patient.</div>` : ''}
      ${(p.warnings || []).map(w => `<div class="da-warn">${escHtml(w)}</div>`).join('')}
      <div class="row-sm" style="margin-top:var(--s-4)">
        <button class="btn" onclick="daMergeRun(true)" ${missing.length || m.busy ? 'disabled' : ''}><span class="material-symbols-outlined">science</span>${m.busy ? 'Running…' : 'Dry run'}</button>
        <input class="lc-input mono" style="width:300px" placeholder="type ${escHtml(phrase)}" value="${escHtml(m.confirm)}" ${m.dry && m.dry.ok ? '' : 'disabled'}
          oninput="daState.merge.confirm=this.value;document.getElementById('daMergeBtn').disabled=this.value!=='${escHtml(phrase)}'">
        <button id="daMergeBtn" class="btn btn-danger" onclick="daMergeRun(false)" ${m.dry && m.dry.ok && m.confirm === phrase ? '' : 'disabled'}><span class="material-symbols-outlined">merge</span>Merge</button>
      </div>
      ${missing.length ? `<div class="list-meta" style="margin:6px 0 0">Choose which ${missing.map(t => t === 'profile' ? 'profile' : 'insurance').join(' and ')} to keep first.</div>` : ''}
      ${dry}
    </div>
  </section>`;
}

async function daMergeRun(dryRun) {
  const m = daState.merge;
  const p = daState.data.pairs.find(x => x.emailKey === m.emailKey);
  if (!p || m.busy) return;
  m.busy = true; daRender();
  const body = { mode: 'merge', emails: [p.emailKey], expect: daExpect([p]), keep: m.keep, legacyId: p.legacyId, dryRun, confirmation: m.confirm };
  try {
    const res = await daPost(body);
    if (dryRun) {
      m.dry = res.results[0];
    } else {
      daState.merge = null;
      await renderDuplicateAccounts(document.getElementById('content'));
      daState.result = res;
      showToast(res.done ? '✓ Merged' : `Merge failed: ${res.results[0].error}`);
    }
  } catch (e) {
    if (dryRun) m.dry = { ok: false, error: e.message }; else alert('Merge failed: ' + e.message);
  } finally {
    if (daState.merge) daState.merge.busy = false;
    daRender();
  }
}

async function daDownloadLog() {
  try {
    const res = await fetch('/api/duplicate-accounts/log.csv', { headers: dbHeaders() });
    if (!res.ok) { await handleJsonResponse(res, '/api/duplicate-accounts/log.csv'); return; }
    const url = URL.createObjectURL(await res.blob());
    const a = Object.assign(document.createElement('a'), { href: url, download: `duplicate-accounts-${daEnvName()}.csv` });
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  } catch (e) {
    alert(e.message);
  }
}
