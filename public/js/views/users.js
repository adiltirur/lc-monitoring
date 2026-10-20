// ═════════════════════════════════════════════════════════════════════════
// USERS
// ═════════════════════════════════════════════════════════════════════════
let usFilters = {};

async function renderUsers(el, page = 1) {
  el.innerHTML = pageWrap(pageHero('Users') + loadingState());
  try {
    const p = new URLSearchParams({ ...usFilters, page, pageSize: 50 });
    const data = await apiFetch(`/api/users?${p}`);
    setConnStatus('connected');

    const filterHtml =
      `<div class="space-y-1.5 col-span-2">${fLabel('Search')}<input id="usQ" placeholder="name / email / phone / ID" value="${escHtml(usFilters.q||'')}" oninput="usFilters.q=this.value" onkeydown="if(event.key==='Enter')renderUsers(document.getElementById('content'))" class="w-full h-10 bg-surface-container-low text-sm rounded-lg border-none focus:ring-2 focus:ring-primary-fixed px-3"></div>` +
      fInput('Praxis', `placeholder="lc_10" value="${escHtml(usFilters.praxisId||'')}" oninput="usFilters.praxisId=this.value"`) +
      `<div></div><div></div>` +
      `<div class="flex gap-2">${btnPrimary('Search', `renderUsers(document.getElementById('content'))`, { full: true })}${btnGhost('Clear', `usFilters={};renderUsers(document.getElementById('content'))`)}</div>`;

    const rowsHtml = data.rows.map(r => `<tr class="zebra-row hover:bg-surface-container transition-colors cursor-pointer" onclick="renderUserDetail(document.getElementById('content'), ${r.id})">
      <td class="px-4 py-2 mono-text text-xs opacity-60">${r.id}</td>
      <td class="px-4 py-2 font-semibold text-primary">${escHtml(r.firstName)} ${escHtml(r.lastName)}</td>
      <td class="px-4 py-2 text-sm">${escHtml(r.email)}</td>
      <td class="px-4 py-2 mono-text text-xs">${escHtml(r.phoneNumber)||'—'}</td>
      <td class="px-4 py-2 text-xs" title="${escHtml(r.praxisId)||''}">${r.praxisId ? escHtml(praxisName(r.praxisId) || r.praxisId) : '—'}</td>
      <td class="px-4 py-2">${r.isVerified ? statusBadge('Verified','tertiary') : statusBadge('No','slate')}</td>
      <td class="px-4 py-2 mono-text text-xs whitespace-nowrap">${escHtml(deTime(r.createdAt))}</td>
      <td class="px-4 py-2 text-right"><span class="material-symbols-outlined text-on-surface-variant text-sm">chevron_right</span></td>
    </tr>`).join('');

    el.innerHTML = pageWrap(
      pageHero('Users', { sub: 'Patient and staff records' }) +
      filterCard(filterHtml, 6) +
      tableShell(['ID','Name','Email','Phone','Praxis','Verified','Created',''], rowsHtml, 'usPaging')
    );
    renderPagination(document.getElementById('usPaging'), data, (p) => renderUsers(document.getElementById('content'), p));
    document.getElementById('usQ')?.focus();
  } catch(e) {
    setConnStatus('error');
    el.innerHTML = pageWrap(pageHero('Users') + errorState(e.message));
  }
}

function udCard(icon, title, body, opts = {}) {
  const count = opts.count !== undefined ? ` <span class="count">${opts.count}</span>` : '';
  return `<div class="panel"${opts.id ? ` id="${opts.id}"` : ''}>
    <div class="panel-header"><span class="panel-title"><span class="material-symbols-outlined">${icon}</span>${escHtml(title)}${count}</span>${opts.actions || ''}</div>
    <div class="panel-body">${body}</div>
  </div>`;
}

function udEmpty(text) {
  return `<div class="faint" style="font-size:12.5px">${escHtml(text)}</div>`;
}

async function renderUserDetail(el, userId) {
  el.innerHTML = pageWrap(loadingState('Loading user…'));
  try {
    const d = await apiFetch(`/api/users/${userId}`);
    const u = d.user;
    const changed = {};

    const EDITABLE = ['firstName','lastName','email','phoneNumber','street','city','postalCode','newEmail','newPhone'];
    const READONLY = ['id','gender','dob','consent','praxisId','mfaActivated','isVerified','lcAccountId','pmsPatientId','verifiedBy','verifiedOn','verifiedByDocument','verifiedByPraxisId','createdAt','modifiedAt'];
    const MONO = ['id','lcAccountId','pmsPatientId','praxisId','verifiedByPraxisId','createdAt','modifiedAt','dob','verifiedOn'];

    function fieldDisplay(k, val) {
      if (val === null || val === undefined) return '';
      if (k === 'createdAt' || k === 'modifiedAt' || k === 'dob' || k === 'verifiedOn') return deTime(val);
      return String(val);
    }

    function editHtml(k) {
      return `<div class="field">${fLabel(k)}<input class="lc-input user-field" data-key="${k}" value="${escHtml(fieldDisplay(k, u[k]))}" oninput="markChanged('${k}', this.value)"></div>`;
    }

    function readHtml(k) {
      const display = fieldDisplay(k, u[k]);
      let value;
      if (k === 'isVerified') value = u[k] ? statusBadge('Verified', 'tertiary') : statusBadge('Pending', 'amber');
      else if (k === 'mfaActivated' || k === 'consent') value = u[k] ? statusBadge('Enabled', 'tertiary') : statusBadge('Disabled', 'slate');
      else {
        const pName = (k === 'praxisId' || k === 'verifiedByPraxisId') && display && praxisName(display);
        value = (escHtml(display) || '<span class="faint">—</span>') + (pName ? `<span class="faint">${escHtml(pName)}</span>` : '');
      }
      return `<div class="kv"><span class="kv-label">${escHtml(k)}</span><span class="kv-value${MONO.includes(k) && display ? ' mono' : ''}">${value}</span></div>`;
    }

    const insuranceCard = d.insurance ? udCard('clinical_notes', 'Insurance',
      Object.entries(d.insurance).map(([k, v]) => `<div class="kv-row"><span class="kv-label">${escHtml(k)}</span><span class="kv-value mono">${escHtml(String(v ?? '')) || '<span class="faint">—</span>'}</span></div>`).join('')) : '';

    const familyCard = udCard('family_history', 'Family members',
      d.family.length ? d.family.map(f => {
        const initials = ((f.firstName || '?').charAt(0) + (f.lastName || '').charAt(0)).toUpperCase();
        return `<div class="list-row"><div class="row" style="min-width:0">
          <span class="avatar">${escHtml(initials)}</span>
          <div style="min-width:0"><div class="list-title">${escHtml(f.firstName || '')} ${escHtml(f.lastName || '')}</div>
          <div class="list-meta">${escHtml(f.insuranceType ?? '')} · ${escHtml(deTime(f.dob))}</div></div>
        </div></div>`;
      }).join('') : udEmpty('No family members'), { count: d.family.length });

    const apptCard = udCard('calendar_month', 'Recent appointments',
      d.appointments.length ? d.appointments.map(a => `<div class="list-row">
        <div><div class="list-title">${escHtml(a.category || '—')}</div><div class="list-meta">${escHtml(deTime(a.createdAt))}</div></div>
        ${statusBadge(APT_STATUS[a.status] || String(a.status), 'slate')}
      </div>`).join('') : udEmpty('No appointments'), { count: d.appointments.length });

    const pmsPending = udEmpty(u.lcAccountId ? 'Loading…' : 'No lcAccountId — PMS data unavailable');
    const actions = (u.isVerified
        ? `<span class="pill ok"><span class="material-symbols-outlined" style="font-size:14px">verified</span>Verified</span>`
        : `<button class="btn" onclick="verifyUser(${userId})"><span class="material-symbols-outlined">verified</span>Verify user</button>`) +
      `<button id="saveBtn" class="btn btn-primary" onclick="saveUserChanges(${userId})" disabled><span class="material-symbols-outlined">save</span>Save changes</button>`;
    const name = `${u.firstName || ''} ${u.lastName || ''}`.trim() || `User ${userId}`;

    el.innerHTML = pageWrap(
      `<button class="back-link" onclick="renderUsers(document.getElementById('content'))"><span class="material-symbols-outlined">arrow_back</span>Users</button>` +
      pageHero(name, { sub: `User ${escHtml(String(userId))}${u.email ? ' · ' + escHtml(u.email) : ''}`, actions }) +
      `<div class="detail-grid">
        <div class="detail-stack">
          ${udCard('badge', 'Profile', `<h4 class="section-label">Editable</h4><div class="form-grid">${EDITABLE.map(editHtml).join('')}</div>
            <div id="dirtyFooter" class="dirty-note" style="display:none"><span class="material-symbols-outlined">warning</span>Unsaved changes: <span id="dirtyList" class="mono"></span></div>`)}
          ${udCard('tune', 'System attributes', `<div class="kv-grid">${READONLY.map(readHtml).join('')}</div>`, { actions: '<span class="faint" style="font-size:12px">Read-only</span>' })}
        </div>
        <div class="detail-stack">
          ${insuranceCard}
          ${familyCard}
          ${apptCard}
          ${udCard('medication', 'Medications', pmsPending, { id: 'medsCard' })}
          ${udCard('description', 'Documents', pmsPending, { id: 'documentsCard' })}
        </div>
      </div>`
    );

    window._userChanged = changed;
    window._userId = userId;
    window._origUser = { ...u };

    if (u.lcAccountId) {
      loadPmsMedications(u.lcAccountId);
      loadPmsDocuments(u.lcAccountId);
    }
  } catch(e) {
    el.innerHTML = pageWrap(errorState(e.message));
  }
}

// ── PMS: medications + documents (proxied through server.js) ─────────────────
const MED_STATUS_PILL = {
  active: 'ok', 'on-hold': 'warn', cancelled: 'err', completed: '', stopped: 'err', 'entered-in-error': 'err', draft: 'info',
};

function udReplaceCard(id, html) {
  const card = document.getElementById(id);
  if (card) card.outerHTML = html;
}

async function loadPmsMedications(lcAccountId) {
  if (!document.getElementById('medsCard')) return;
  try {
    const data = await apiFetch(`/api/pms/users/${encodeURIComponent(lcAccountId)}/medications`);
    const meds = data.medications || [];
    const body = meds.length ? meds.map(m => {
      const dosage = (m.dosage || []).map(d => escHtml(d.text)).filter(Boolean).join(' · ');
      return `<div class="list-row" style="align-items:flex-start">
        <div style="min-width:0">
          <div class="list-title">${escHtml(m.medicationName)}</div>
          <div class="list-meta">${escHtml(deTime(m.authoredOn)) || '—'}${m.pzn ? ' · PZN ' + escHtml(m.pzn) : ''}${m.form ? ' · ' + escHtml(m.form) : ''}${(m.copyIds || []).length > 1 ? ` · <span title="${escHtml(m.copyIds.join(', '))}">${m.copyIds.length} identical copies in Principa</span>` : ''}</div>
          ${dosage ? `<div style="font-size:12.5px;color:var(--ink-2);margin-top:4px">${dosage}</div>` : ''}
          ${m.reason ? `<div class="faint" style="font-size:12px;margin-top:2px">${escHtml(m.reason)}</div>` : ''}
        </div>
        <span class="pill ${MED_STATUS_PILL[m.status] ?? ''}">${escHtml(m.status || '—')}</span>
      </div>`;
    }).join('') : udEmpty('No medications');
    udReplaceCard('medsCard', udCard('medication', 'Medications', body, { id: 'medsCard', count: meds.length }));
  } catch (e) {
    udReplaceCard('medsCard', udCard('medication', 'Medications', `<div class="mono" style="font-size:12px;color:var(--red);word-break:break-all">${escHtml(e.message)}</div>`, { id: 'medsCard' }));
  }
}

async function loadPmsDocuments(lcAccountId) {
  if (!document.getElementById('documentsCard')) return;
  try {
    const data = await apiFetch(`/api/pms/users/${encodeURIComponent(lcAccountId)}/documents`);
    const docs = data.documents || [];
    const body = docs.length ? docs.map(d => `<div class="list-row clickable"
        onclick="openDocumentPreview('${escHtml(d.binaryID)}','${escHtml(d.title).replace(/'/g,"\\'")}','${escHtml(d.contentType)}')">
      <div style="min-width:0;flex:1">
        <div class="list-title" style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${escHtml(d.title)}</div>
        <div class="list-meta">${escHtml(deTime(d.createdAt)) || '—'}${d.documentType ? ' · ' + escHtml(d.documentType) : ''}${d.contentType ? ' · ' + escHtml(d.contentType) : ''}</div>
        ${d.description ? `<div class="faint" style="font-size:12px;margin-top:2px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${escHtml(d.description)}</div>` : ''}
      </div>
      <span class="material-symbols-outlined faint" style="font-size:17px">open_in_new</span>
    </div>`).join('') : udEmpty('No documents');
    udReplaceCard('documentsCard', udCard('description', 'Documents', body, { id: 'documentsCard', count: docs.length }));
  } catch (e) {
    udReplaceCard('documentsCard', udCard('description', 'Documents', `<div class="mono" style="font-size:12px;color:var(--red);word-break:break-all">${escHtml(e.message)}</div>`, { id: 'documentsCard' }));
  }
}

async function openDocumentPreview(binaryId, title, hintedContentType) {
  const modal = document.createElement('div');
  modal.style.cssText = 'position:fixed;inset:0;z-index:100;display:grid;place-items:center;padding:24px;background:rgba(0,33,42,.45)';
  modal.innerHTML = `<div class="panel" style="width:100%;max-width:1024px;max-height:90vh;display:flex;flex-direction:column;overflow:hidden;box-shadow:var(--shadow-pop)">
    <div class="panel-header">
      <div style="min-width:0;flex:1">
        <div class="panel-title" style="display:block;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${escHtml(title)}</div>
        <div class="list-meta" style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${escHtml(binaryId)}</div>
      </div>
      <div class="row-sm" style="flex-shrink:0">
        <a id="docDownload" class="btn btn-sm" style="display:none;text-decoration:none" download="${escHtml(title)}"><span class="material-symbols-outlined">download</span>Download</a>
        <button class="btn btn-ghost btn-sm" onclick="this.closest('.doc-modal').remove()"><span class="material-symbols-outlined">close</span></button>
      </div>
    </div>
    <div id="docBody" style="flex:1;overflow:auto;padding:16px;background:var(--surface-2)"><div class="empty-sub" style="text-align:center;padding:48px 0">Loading…</div></div>
  </div>`;
  modal.className = 'doc-modal';
  const onKey = e => { if (e.key === 'Escape') { modal.remove(); document.removeEventListener('keydown', onKey); } };
  document.addEventListener('keydown', onKey);
  modal.addEventListener('click', e => { if (e.target === modal) { modal.remove(); document.removeEventListener('keydown', onKey); } });
  document.body.appendChild(modal);

  try {
    const data = await apiFetch(`/api/pms/binary/${encodeURIComponent(binaryId)}`);
    const ct = data.contentType || hintedContentType || 'application/octet-stream';
    const dataUrl = `data:${ct};base64,${data.base64}`;
    const body = modal.querySelector('#docBody');
    const dl   = modal.querySelector('#docDownload');
    dl.href = dataUrl;
    dl.style.display = '';
    if (ct.startsWith('image/')) {
      body.innerHTML = `<img src="${dataUrl}" alt="${escHtml(title)}" style="max-width:100%;display:block;margin:0 auto;border-radius:var(--r)">`;
    } else if (ct === 'application/pdf' || ct.endsWith('/pdf')) {
      body.innerHTML = `<iframe src="${dataUrl}" style="width:100%;height:75vh;border:0;border-radius:var(--r);background:#fff" title="${escHtml(title)}"></iframe>`;
    } else {
      body.innerHTML = `<div style="font-size:12.5px;color:var(--ink-2)">Content type <span class="mono">${escHtml(ct)}</span> cannot be previewed inline — use Download above.</div>`;
    }
  } catch (e) {
    modal.querySelector('#docBody').innerHTML = `<div class="mono" style="font-size:12px;color:var(--red);word-break:break-all">${escHtml(e.message)}</div>`;
  }
}

function markChanged(key, val) {
  if (!window._userChanged) return;
  const orig = String(window._origUser[key] ?? '');
  if (val === orig) delete window._userChanged[key]; else window._userChanged[key] = val;

  document.querySelectorAll('.user-field').forEach(i => {
    const k = i.dataset.key;
    i.classList.toggle('field-changed', window._userChanged[k] !== undefined);
  });
  const keys = Object.keys(window._userChanged);
  document.getElementById('saveBtn').disabled = !keys.length;
  const footer = document.getElementById('dirtyFooter');
  if (keys.length) {
    footer.style.display = '';
    document.getElementById('dirtyList').textContent = keys.join(', ');
  } else {
    footer.style.display = 'none';
  }
}

async function saveUserChanges(userId) {
  const updates = {};
  document.querySelectorAll('.user-field[data-key]').forEach(i => {
    const orig = String(window._origUser[i.dataset.key] ?? '');
    if (i.value !== orig) updates[i.dataset.key] = i.value;
  });
  if (!Object.keys(updates).length) return;
  if (!confirm(`Update ${Object.keys(updates).join(', ')} for user ${userId}?`)) return;
  try {
    const result = await apiPatch(`/api/users/${userId}`, updates);
    if (result.error) { showToast('Error: ' + result.error); return; }
    showToast('✅ Saved');
    renderUserDetail(document.getElementById('content'), userId);
  } catch(e) { showToast('Error: ' + e.message); }
}

async function verifyUser(userId) {
  const verifiedBy = prompt('Verified by (name):', 'Debugger');
  if (verifiedBy === null) return;
  const doc = prompt('Document type:', 'manual');
  if (doc === null) return;
  const docNumber = prompt('Document number:', 'manual');
  if (docNumber === null) return;
  try {
    const res = await apiPost(`/api/users/${userId}/verify`, { verifiedBy, verifiedByDocument: doc, verifiedByDocumentNumber: docNumber });
    if (res.error) { showToast('Error: ' + res.error); return; }
    showToast('✅ User verified');
    renderUserDetail(document.getElementById('content'), userId);
  } catch(e) { showToast('Error: ' + e.message); }
}
