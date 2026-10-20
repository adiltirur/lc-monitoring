// ═════════════════════════════════════════════════════════════════════════
// PMS INVITATIONS — app_user_pms_invitation + app_user_pms_auto_link_log
// ═════════════════════════════════════════════════════════════════════════
let piTab = 'invitations';
let piFilters = { invitations: {}, log: {} };
const PI_STATUS_PILL = { pending: 'warn', linked: 'ok', expired: '' };
const PI_OUTCOMES = ['linked', 'patientAlreadyLinked', 'invitationCreated', 'invitationRenewed', 'pendingInvitationExists',
  'dobMismatch', 'dobMissing', 'linkedSeedFailed', 'userAlreadyLinkedToOtherPatient', 'linkFailed', 'noPmsPatientId'];
const PI_OUTCOME_PILL = {
  linked: 'ok', patientAlreadyLinked: 'ok',
  invitationCreated: 'info', invitationRenewed: 'info', pendingInvitationExists: 'info',
  dobMismatch: 'warn', dobMissing: 'warn', linkedSeedFailed: 'warn',
  userAlreadyLinkedToOtherPatient: 'err', linkFailed: 'err', noPmsPatientId: 'err',
};
const PI_OUTCOME_HELP = {
  linked: 'Email + DOB matched an app user; linked and appointments seeded',
  patientAlreadyLinked: 'An app user already has this pmsPatientId; appointments re-seeded',
  invitationCreated: 'No app user with this email; invitation code emailed',
  invitationRenewed: 'Invitation renewed',
  pendingInvitationExists: 'A pending invitation already exists; no new code',
  dobMismatch: 'Email matched but DOB differs; linking code emailed instead',
  dobMissing: 'Email matched but the PMS record has no birth date',
  linkedSeedFailed: 'Linked, but seeding appointments from Principa failed',
  userAlreadyLinkedToOtherPatient: 'The app user is already linked to another PMS patient',
  linkFailed: 'Email + DOB matched but patching the PMS patient failed',
  noPmsPatientId: 'FHIR Patient had no id',
};

function piPill(map, value, title = '') {
  return `<span class="pill ${map[value] ?? ''}" title="${escHtml(title)}">${escHtml(value)}</span>`;
}

function piUserCell(id, email, first, last) {
  if (!id) return '<span class="faint">—</span>';
  const name = [first, last].filter(Boolean).join(' ');
  return `<a class="pi-link" onclick="event.stopPropagation();renderUserDetail(document.getElementById('content'), ${Number(id)})"
    title="${escHtml(email || '')}">#${Number(id)}${name ? ' · ' + escHtml(name) : ''}</a>`;
}

function piPatientCell(pmsPatientId, otherTab) {
  if (!pmsPatientId) return '<span class="faint">—</span>';
  const label = otherTab === 'log' ? 'Show auto-link history' : 'Show invitations';
  return `<a class="pi-link mono" title="${label}" onclick="event.stopPropagation();piJump('${otherTab}', '${escHtml(pmsPatientId).replace(/'/g, '&#39;')}')">${escHtml(pmsPatientId)}</a>`;
}

function piJump(tab, pmsPatientId) {
  piTab = tab;
  piFilters[tab] = { pmsPatientId };
  renderPmsInvitations(document.getElementById('content'));
}

function piSetTab(tab) {
  piTab = tab;
  renderPmsInvitations(document.getElementById('content'));
}

function piStats(stats) {
  if (!stats) return '';
  const inv = stats.invitations || {};
  const outcomes = Object.entries(stats.outcomes || {});
  return `<div class="mo-stats">
    <div class="mo-stat-line"><span class="mo-stat-label">Invitations</span>
      <span class="pill warn">pending<b class="mono">${inv.pending || 0}</b></span>
      <span class="pill ok">linked<b class="mono">${inv.linked || 0}</b></span>
      ${inv.expired ? `<span class="pill" title="Legacy status, removed from Core">expired<b class="mono">${inv.expired}</b></span>` : ''}</div>
    <div class="mo-stat-line"><span class="mo-stat-label">Auto-link · 30 days</span>
      ${outcomes.length ? outcomes.map(([o, n]) => `<span class="pill ${PI_OUTCOME_PILL[o] ?? ''}" title="${escHtml(PI_OUTCOME_HELP[o] || '')}">${escHtml(o)}<b class="mono">${n}</b></span>`).join('') : '<span class="faint">No attempts</span>'}
    </div></div>`;
}

function piSearchRow(tab, extra) {
  const f = piFilters[tab];
  const run = `renderPmsInvitations(document.getElementById('content'))`;
  return extra +
    fInput('Search', `placeholder="${tab === 'log' ? 'email / patient id / details' : 'name / email / patient id / code'}" value="${escHtml(f.q || '')}" oninput="piFilters.${tab}.q=this.value" onkeydown="if(event.key==='Enter')${run}"`) +
    fInput('PMS patient', `placeholder="exact id" value="${escHtml(f.pmsPatientId || '')}" oninput="piFilters.${tab}.pmsPatientId=this.value" onkeydown="if(event.key==='Enter')${run}"`) +
    fInput('From', `type="datetime-local" value="${escHtml(f.dateFrom || '')}" oninput="piFilters.${tab}.dateFrom=this.value"`) +
    fInput('To', `type="datetime-local" value="${escHtml(f.dateTo || '')}" oninput="piFilters.${tab}.dateTo=this.value"`) +
    `<div class="row-sm">${btnPrimary('Search', run, { full: true })}${btnGhost('Clear', `piFilters.${tab}={};${run}`)}</div>`;
}

function piInvitationRows(rows) {
  return rows.map(r => `<tr>
    <td class="mono" style="white-space:nowrap">${escHtml(deTime(r.createdAt))}</td>
    <td>${piPill(PI_STATUS_PILL, r.status)}</td>
    <td>${escHtml([r.firstName, r.lastName].filter(Boolean).join(' ')) || '—'}</td>
    <td>${escHtml(r.email) || '—'}</td>
    <td class="mono" style="white-space:nowrap">${r.dob ? escHtml(deDate(r.dob)) : '—'}</td>
    <td class="mono">${escHtml(r.phoneNumber) || '—'}</td>
    <td>${piPatientCell(r.pmsPatientId, 'log')}${r.logCount ? ` <span class="faint">(${r.logCount})</span>` : ''}</td>
    <td class="mono">${escHtml(r.invitationCode)}</td>
    <td>${piUserCell(r.linkedUserId, r.linkedEmail, r.linkedFirstName, r.linkedLastName)}</td>
    <td title="${escHtml(r.praxisId || '')}">${r.praxisId ? escHtml(praxisName(r.praxisId) || r.praxisId) : '—'}</td>
    <td class="mono" style="white-space:nowrap">${escHtml(deTime(r.modifiedAt))}</td>
  </tr>`).join('');
}

function piLogRows(rows) {
  return rows.map(r => `<tr>
    <td class="mono" style="white-space:nowrap">${escHtml(deTime(r.createdAt))}</td>
    <td>${piPill(PI_OUTCOME_PILL, r.outcome, PI_OUTCOME_HELP[r.outcome] || '')}</td>
    <td>${piPatientCell(r.pmsPatientId, 'invitations')}</td>
    <td>${escHtml(r.email) || '—'}</td>
    <td class="mono" style="white-space:nowrap">${r.dob ? escHtml(deDate(r.dob)) : '—'}</td>
    <td>${piUserCell(r.matchedUserId, r.matchedEmail, r.matchedFirstName, r.matchedLastName)}</td>
    <td class="pi-details" title="${escHtml(r.details || '')}">${escHtml(r.details) || '—'}</td>
  </tr>`).join('');
}

async function renderPmsInvitations(el, page = 1) {
  const sub = 'Principa patients invited to link their app account, and every auto-link attempt';
  el.innerHTML = pageWrap(pageHero('PMS Invitations', { sub }) + loadingState());
  try {
    const tab = piTab;
    const f = Object.fromEntries(Object.entries(piFilters[tab]).filter(([, v]) => v));
    const p = new URLSearchParams({ ...f, page, pageSize: 50 });
    const stats = await apiFetch('/api/pms-invitations/stats');
    setConnStatus('connected');

    const missing = tab === 'log' ? !stats.tables.log : !stats.tables.inv;
    const tabs = `<div class="lc-tabs pi-tabs">${[['invitations', 'Invitations'], ['log', 'Auto-link log']].map(([k, l]) =>
      `<button class="lc-tab ${tab === k ? 'active' : ''}" onclick="piSetTab('${k}')">${l}</button>`).join('')}</div>`;
    const head = pageHero('PMS Invitations', { sub,
      actions: `<button class="btn btn-ghost" onclick="renderPmsInvitations(document.getElementById('content'), ${page})" title="Refresh"><span class="material-symbols-outlined">refresh</span></button>` });

    if (missing) {
      el.innerHTML = pageWrap(head + piStats(stats) + tabs +
        emptyState(`Table ${tab === 'log' ? 'app_user_pms_auto_link_log' : 'app_user_pms_invitation'} does not exist on this environment yet`, 'database'));
      return;
    }

    let table, filterHtml;
    if (tab === 'log') {
      const data = await apiFetch(`/api/pms-invitations/log?${p}`);
      const outcomeOpts = [{ value: '', label: 'All outcomes' }, ...PI_OUTCOMES.map(o => ({ value: o, label: o }))];
      filterHtml = piSearchRow('log', fSelect('Outcome', outcomeOpts, `oninput="piFilters.log.outcome=this.value"`, piFilters.log.outcome || ''));
      table = { data, html: tableShell(['When', 'Outcome', 'PMS patient', 'Email', 'DOB (PMS)', 'Matched user', 'Details'], piLogRows(data.rows), 'piPaging') };
    } else {
      const data = await apiFetch(`/api/pms-invitations?${p}`);
      const statusOpts = [{ value: '', label: 'All statuses' }, { value: 'pending', label: 'pending' }, { value: 'linked', label: 'linked' }, { value: 'expired', label: 'expired (legacy)' }];
      filterHtml = piSearchRow('invitations', fSelect('Status', statusOpts, `oninput="piFilters.invitations.status=this.value"`, piFilters.invitations.status || ''));
      table = { data, html: tableShell(['Created', 'Status', 'Name', 'Email', 'DOB', 'Phone', 'PMS patient', 'Code', 'Linked user', 'Praxis', 'Modified'], piInvitationRows(data.rows), 'piPaging') };
    }

    el.innerHTML = pageWrap(head + piStats(stats) + tabs + filterCard(filterHtml, 6) +
      (table.data.rows.length ? table.html : emptyState('No rows match these filters', 'search_off')));
    const pg = document.getElementById('piPaging');
    if (pg) renderPagination(pg, table.data, (n) => renderPmsInvitations(document.getElementById('content'), n));
  } catch (e) {
    setConnStatus('error');
    el.innerHTML = pageWrap(pageHero('PMS Invitations') + errorState(e.message));
  }
}
