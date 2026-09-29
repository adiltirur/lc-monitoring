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

async function renderUserDetail(el, userId) {
  el.innerHTML = pageWrap(loadingState('Loading user…'));
  try {
    const d = await apiFetch(`/api/users/${userId}`);
    const u = d.user;
    const changed = {};

    const EDITABLE = ['firstName','lastName','email','phoneNumber','street','city','postalCode','newEmail','newPhone'];
    const FIELD_GROUPS = {
      'Editable Records': ['firstName','lastName','email','phoneNumber','street','city','postalCode','newEmail','newPhone'],
      'System Attributes (Read-Only)': ['id','gender','dob','consent','praxisId','mfaActivated','isVerified','lcAccountId','pmsPatientId','verifiedBy','verifiedOn','verifiedByDocument','verifiedByPraxisId','createdAt','modifiedAt'],
    };

    function fieldDisplay(k, val) {
      if (val === null || val === undefined) return '';
      if (k === 'createdAt' || k === 'modifiedAt' || k === 'dob' || k === 'verifiedOn') return deTime(val);
      return String(val);
    }

    function fieldHtml(k) {
      const isEdit = EDITABLE.includes(k);
      const display = fieldDisplay(k, u[k]);
      if (isEdit) {
        return `<div class="space-y-1.5">
          <label class="text-[11px] font-bold uppercase tracking-widest text-on-surface-variant">${escHtml(k)}</label>
          <input class="user-field w-full bg-surface-container-lowest border border-outline-variant rounded-lg px-3 py-2 text-sm focus:ring-2 focus:ring-primary-fixed focus:border-primary" data-key="${k}" value="${escHtml(display)}" oninput="markChanged('${k}', this.value)">
        </div>`;
      } else {
        if (k === 'isVerified') {
          return `<div class="space-y-1.5">
            <label class="text-[11px] font-bold uppercase tracking-widest text-on-surface-variant">${escHtml(k)}</label>
            <div class="bg-surface-container-low px-3 py-2 rounded-lg flex items-center">
              ${u[k] ? statusBadge('Verified','tertiary') : statusBadge('Pending','amber')}
            </div>
          </div>`;
        }
        if (k === 'mfaActivated' || k === 'consent') {
          return `<div class="space-y-1.5">
            <label class="text-[11px] font-bold uppercase tracking-widest text-on-surface-variant">${escHtml(k)}</label>
            <div class="bg-surface-container-low px-3 py-2 rounded-lg flex items-center">
              ${u[k] ? statusBadge('Enabled','primary') : statusBadge('Disabled','slate')}
            </div>
          </div>`;
        }
        const isMono = k === 'id' || k === 'lcAccountId' || k === 'pmsPatientId' || k === 'praxisId' || k === 'verifiedByPraxisId';
        const showPraxisName = (k === 'praxisId' || k === 'verifiedByPraxisId') && praxisName(display);
        return `<div class="space-y-1.5">
          <label class="text-[11px] font-bold uppercase tracking-widest text-on-surface-variant">${escHtml(k)}</label>
          <div class="bg-surface-container-low px-3 py-2 rounded-lg ${isMono ? 'mono-text text-xs' : 'text-sm'} text-on-surface-variant">${escHtml(display) || '—'}${showPraxisName ? ` <span class="text-on-surface ml-2">· ${escHtml(praxisName(display))}</span>` : ''}</div>
        </div>`;
      }
    }

    const editableFields = FIELD_GROUPS['Editable Records'].map(fieldHtml).join('');
    const readonlyFields = FIELD_GROUPS['System Attributes (Read-Only)'].map(fieldHtml).join('');

    const insuranceCard = d.insurance ? `
      <div class="bg-surface-container-lowest rounded-xl shadow-whisper p-6 border border-transparent hover:border-outline-variant transition-all">
        <div class="flex items-center gap-3 mb-6">
          <div class="w-10 h-10 rounded-lg bg-primary/5 flex items-center justify-center text-primary">
            <span class="material-symbols-outlined">clinical_notes</span>
          </div>
          <h3 class="font-bold tracking-tight">Insurance</h3>
        </div>
        <div class="space-y-3">
          ${Object.entries(d.insurance).map(([k,v]) => `<div class="flex justify-between items-center pb-2 border-b border-surface-container-low last:border-b-0">
            <span class="text-[11px] font-bold uppercase tracking-widest text-on-surface-variant">${escHtml(k)}</span>
            <span class="text-sm font-semibold mono-text">${escHtml(String(v??''))||'—'}</span>
          </div>`).join('')}
        </div>
      </div>` : '';

    const familyCard = `
      <div class="bg-surface-container-lowest rounded-xl shadow-whisper p-6 border border-transparent hover:border-outline-variant transition-all">
        <div class="flex items-center gap-3 mb-6">
          <div class="w-10 h-10 rounded-lg bg-tertiary/5 flex items-center justify-center text-tertiary">
            <span class="material-symbols-outlined">family_history</span>
          </div>
          <h3 class="font-bold tracking-tight">Family Members (${d.family.length})</h3>
        </div>
        <div class="space-y-3">
          ${d.family.length ? d.family.map(f => {
            const initials = ((f.firstName||'?').charAt(0) + (f.lastName||'').charAt(0)).toUpperCase();
            return `<div class="flex items-center justify-between p-3 rounded-lg hover:bg-surface-container-low transition-colors">
              <div class="flex items-center gap-3">
                <div class="w-8 h-8 rounded-full bg-secondary-container flex items-center justify-center text-on-secondary-container text-xs font-bold">${escHtml(initials)}</div>
                <div>
                  <p class="text-sm font-semibold">${escHtml(f.firstName||'')} ${escHtml(f.lastName||'')}</p>
                  <p class="text-[10px] text-on-surface-variant uppercase tracking-tighter">${escHtml(f.insuranceType||'')} · ${escHtml(deTime(f.dob))}</p>
                </div>
              </div>
              <div class="w-2 h-2 rounded-full bg-tertiary ring-4 ring-tertiary/10"></div>
            </div>`;
          }).join('') : '<div class="text-outline text-sm italic">No family members</div>'}
        </div>
      </div>`;

    const apptCard = `
      <div class="bg-surface-container-lowest rounded-xl shadow-whisper p-6 border border-transparent hover:border-outline-variant transition-all">
        <div class="flex items-center justify-between mb-6">
          <div class="flex items-center gap-3">
            <div class="w-10 h-10 rounded-lg bg-secondary/5 flex items-center justify-center text-secondary">
              <span class="material-symbols-outlined">calendar_month</span>
            </div>
            <h3 class="font-bold tracking-tight">Recent Appointments (${d.appointments.length})</h3>
          </div>
        </div>
        ${d.appointments.length ? `<table class="w-full text-left">
          <thead><tr class="border-b border-surface-container-low">
            <th class="pb-3 text-[10px] font-bold uppercase tracking-widest text-on-surface-variant">Date</th>
            <th class="pb-3 text-[10px] font-bold uppercase tracking-widest text-on-surface-variant">Category</th>
            <th class="pb-3 text-right text-[10px] font-bold uppercase tracking-widest text-on-surface-variant">Status</th>
          </tr></thead>
          <tbody class="divide-y divide-surface-container-low">
            ${d.appointments.map(a => {
              const [bg, fg] = APT_STATUS_PILL[a.status] || APT_STATUS_PILL[0];
              return `<tr>
                <td class="py-3 text-xs font-semibold mono-text">${escHtml(deTime(a.createdAt))}</td>
                <td class="py-3"><span class="px-2 py-0.5 ${bg} ${fg} text-[9px] font-bold rounded uppercase tracking-wider">${escHtml(a.category||'')}</span></td>
                <td class="py-3 text-right"><span class="text-[10px] font-bold uppercase ${fg}">${escHtml(APT_STATUS[a.status]||a.status)}</span></td>
              </tr>`;
            }).join('')}
          </tbody>
        </table>` : '<div class="text-outline text-sm italic">No appointments</div>'}
      </div>`;

    el.innerHTML = `<div class="p-8 max-w-[1600px] mx-auto">
      <div class="flex items-center gap-4 mb-6">
        <button class="flex items-center gap-2 text-slate-500 hover:text-primary transition-colors font-medium" onclick="renderUsers(document.getElementById('content'))">
          <span class="material-symbols-outlined">arrow_back</span>
          <span class="text-sm">Back to Users</span>
        </button>
        <div class="h-6 w-px bg-slate-200"></div>
        <div class="flex flex-col">
          <h2 class="text-sm font-bold tracking-tight text-slate-900 leading-tight">User Detail</h2>
          <span class="text-xs text-slate-500">${escHtml(u.firstName||'')} ${escHtml(u.lastName||'')}</span>
        </div>
      </div>
      <div class="grid grid-cols-10 gap-8">
        <div class="col-span-10 lg:col-span-6 space-y-6">
          <div class="bg-surface-container-lowest rounded-xl shadow-whisper overflow-hidden">
            <div class="px-8 py-6 flex items-center justify-between bg-white border-b border-surface-container-low">
              <div class="flex items-center gap-3">
                <span class="material-symbols-outlined text-primary">badge</span>
                <h3 class="font-bold text-lg tracking-tight">User Information</h3>
              </div>
              <div class="flex items-center gap-3">
                ${!u.isVerified
                  ? `<button class="px-4 py-2 bg-tertiary text-on-tertiary rounded-lg text-sm font-semibold flex items-center gap-2 hover:opacity-90 active:scale-95 transition-all" onclick="verifyUser(${userId})">
                      <span class="material-symbols-outlined text-[18px] ms-fill">verified</span>Verify User
                    </button>`
                  : `<span class="flex items-center gap-2 px-4 py-2 bg-tertiary/10 text-tertiary rounded-lg text-sm font-semibold">
                      <span class="material-symbols-outlined text-[18px] ms-fill">verified</span>Verified
                    </span>`}
                <button id="saveBtn" class="px-4 py-2 bg-primary text-on-primary rounded-lg text-sm font-semibold flex items-center gap-2 hover:opacity-90 active:scale-95 transition-all disabled:opacity-30 disabled:cursor-not-allowed" onclick="saveUserChanges(${userId})" disabled>
                  <span class="material-symbols-outlined text-[18px]">save</span>Save Changes
                </button>
              </div>
            </div>
            <div class="p-8">
              <h4 class="text-[11px] font-bold uppercase tracking-widest text-primary/70 mb-4">Editable Records</h4>
              <div class="grid grid-cols-2 gap-x-8 gap-y-4 mb-8">${editableFields}</div>
              <h4 class="text-[11px] font-bold uppercase tracking-widest text-on-surface-variant/70 mb-4">System Attributes (Read-Only)</h4>
              <div class="grid grid-cols-2 gap-x-8 gap-y-4">${readonlyFields}</div>
              <div id="dirtyFooter" class="mt-10 pt-6 border-t border-surface-container hidden items-center gap-2">
                <span class="material-symbols-outlined text-amber-600 text-lg">warning</span>
                <p class="text-sm font-semibold text-amber-700">Unsaved changes: <span id="dirtyList" class="mono-text text-xs"></span></p>
              </div>
            </div>
          </div>
        </div>
        <div class="col-span-10 lg:col-span-4 space-y-6">
          ${insuranceCard}
          ${familyCard}
          ${apptCard}
          <div id="medsCard" class="bg-surface-container-lowest rounded-xl shadow-whisper p-6 border border-transparent">
            <div class="flex items-center gap-3 mb-4">
              <div class="w-10 h-10 rounded-lg bg-primary/5 flex items-center justify-center text-primary">
                <span class="material-symbols-outlined">medication</span>
              </div>
              <h3 class="font-bold tracking-tight">Medications</h3>
            </div>
            <div class="text-outline text-sm italic">${u.lcAccountId ? 'Loading…' : 'No lcAccountId — PMS data unavailable'}</div>
          </div>
          <div id="documentsCard" class="bg-surface-container-lowest rounded-xl shadow-whisper p-6 border border-transparent">
            <div class="flex items-center gap-3 mb-4">
              <div class="w-10 h-10 rounded-lg bg-tertiary/5 flex items-center justify-center text-tertiary">
                <span class="material-symbols-outlined">description</span>
              </div>
              <h3 class="font-bold tracking-tight">Documents</h3>
            </div>
            <div class="text-outline text-sm italic">${u.lcAccountId ? 'Loading…' : 'No lcAccountId — PMS data unavailable'}</div>
          </div>
        </div>
      </div>
    </div>`;

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
  active:         ['bg-emerald-100','text-emerald-700'],
  'on-hold':      ['bg-amber-100','text-amber-700'],
  cancelled:      ['bg-red-100','text-red-700'],
  completed:      ['bg-slate-100','text-slate-700'],
  stopped:        ['bg-red-100','text-red-700'],
  'entered-in-error': ['bg-red-100','text-red-700'],
  draft:          ['bg-blue-100','text-blue-700'],
};

async function loadPmsMedications(lcAccountId) {
  const card = document.getElementById('medsCard');
  if (!card) return;
  try {
    const data = await apiFetch(`/api/pms/users/${encodeURIComponent(lcAccountId)}/medications`);
    const meds = data.medications || [];
    const body = meds.length ? meds.map(m => {
      const [bg, fg] = MED_STATUS_PILL[m.status] || ['bg-slate-100','text-slate-700'];
      const dosage = (m.dosage || []).map(d => escHtml(d.text)).filter(Boolean).join(' · ');
      return `<div class="p-3 rounded-lg hover:bg-surface-container-low transition-colors border-b border-surface-container-low last:border-b-0">
        <div class="flex items-start justify-between gap-3 mb-1">
          <div class="text-sm font-semibold leading-tight">${escHtml(m.medicationName)}</div>
          <span class="px-2 py-0.5 rounded text-[9px] font-bold uppercase tracking-wider ${bg} ${fg} whitespace-nowrap">${escHtml(m.status||'—')}</span>
        </div>
        <div class="text-[11px] text-on-surface-variant mono-text">${escHtml(deTime(m.authoredOn)) || '—'}${m.pzn ? ' · PZN ' + escHtml(m.pzn) : ''}${m.form ? ' · ' + escHtml(m.form) : ''}</div>
        ${dosage ? `<div class="text-xs text-on-surface-variant mt-1">${dosage}</div>` : ''}
        ${m.reason ? `<div class="text-[11px] text-on-surface-variant/70 mt-1 italic">${escHtml(m.reason)}</div>` : ''}
      </div>`;
    }).join('') : '<div class="text-outline text-sm italic">No medications</div>';
    card.innerHTML = `
      <div class="flex items-center gap-3 mb-4">
        <div class="w-10 h-10 rounded-lg bg-primary/5 flex items-center justify-center text-primary">
          <span class="material-symbols-outlined">medication</span>
        </div>
        <h3 class="font-bold tracking-tight">Medications (${meds.length})</h3>
      </div>
      <div class="space-y-1">${body}</div>`;
  } catch (e) {
    card.innerHTML = `<div class="flex items-center gap-3 mb-3">
      <div class="w-10 h-10 rounded-lg bg-error/10 flex items-center justify-center text-error"><span class="material-symbols-outlined">medication</span></div>
      <h3 class="font-bold tracking-tight">Medications</h3>
    </div>
    <div class="text-xs text-error mono-text break-all">${escHtml(e.message)}</div>`;
  }
}

async function loadPmsDocuments(lcAccountId) {
  const card = document.getElementById('documentsCard');
  if (!card) return;
  try {
    const data = await apiFetch(`/api/pms/users/${encodeURIComponent(lcAccountId)}/documents`);
    const docs = data.documents || [];
    const body = docs.length ? docs.map(d => `<div class="p-3 rounded-lg hover:bg-surface-container-low transition-colors border-b border-surface-container-low last:border-b-0 cursor-pointer flex items-start justify-between gap-3"
        onclick="openDocumentPreview('${escHtml(d.binaryID)}','${escHtml(d.title).replace(/'/g,"\\'")}','${escHtml(d.contentType)}')">
      <div class="min-w-0 flex-1">
        <div class="text-sm font-semibold truncate">${escHtml(d.title)}</div>
        <div class="text-[11px] text-on-surface-variant mono-text">${escHtml(deTime(d.createdAt)) || '—'}${d.documentType ? ' · ' + escHtml(d.documentType) : ''}${d.contentType ? ' · ' + escHtml(d.contentType) : ''}</div>
        ${d.description ? `<div class="text-[11px] text-on-surface-variant/70 mt-1 italic truncate">${escHtml(d.description)}</div>` : ''}
      </div>
      <span class="material-symbols-outlined text-on-surface-variant flex-shrink-0">open_in_new</span>
    </div>`).join('') : '<div class="text-outline text-sm italic">No documents</div>';
    card.innerHTML = `
      <div class="flex items-center gap-3 mb-4">
        <div class="w-10 h-10 rounded-lg bg-tertiary/5 flex items-center justify-center text-tertiary">
          <span class="material-symbols-outlined">description</span>
        </div>
        <h3 class="font-bold tracking-tight">Documents (${docs.length})</h3>
      </div>
      <div class="space-y-1">${body}</div>`;
  } catch (e) {
    card.innerHTML = `<div class="flex items-center gap-3 mb-3">
      <div class="w-10 h-10 rounded-lg bg-error/10 flex items-center justify-center text-error"><span class="material-symbols-outlined">description</span></div>
      <h3 class="font-bold tracking-tight">Documents</h3>
    </div>
    <div class="text-xs text-error mono-text break-all">${escHtml(e.message)}</div>`;
  }
}

async function openDocumentPreview(binaryId, title, hintedContentType) {
  const modal = document.createElement('div');
  modal.className = 'fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-6';
  modal.innerHTML = `<div class="bg-surface-container-lowest rounded-xl shadow-whisper w-full max-w-5xl max-h-[90vh] flex flex-col overflow-hidden border border-outline-variant/30">
    <div class="px-6 py-4 flex items-center justify-between border-b border-outline-variant/20 flex-shrink-0">
      <div class="min-w-0 flex-1">
        <h3 class="font-bold text-lg tracking-tight truncate">${escHtml(title)}</h3>
        <div class="text-[11px] text-on-surface-variant mono-text truncate">${escHtml(binaryId)}</div>
      </div>
      <div class="flex items-center gap-2 flex-shrink-0">
        <a id="docDownload" class="hidden px-3 py-1.5 bg-surface-container-high text-on-surface rounded-lg text-xs font-bold flex items-center gap-1.5 hover:bg-surface-variant transition-colors" download="${escHtml(title)}"><span class="material-symbols-outlined text-sm">download</span>Download</a>
        <button class="p-2 rounded-lg text-on-surface-variant hover:bg-surface-container-high transition-colors" onclick="this.closest('.fixed').remove()"><span class="material-symbols-outlined">close</span></button>
      </div>
    </div>
    <div id="docBody" class="flex-1 overflow-auto p-4 bg-surface-container"><div class="text-outline text-sm italic text-center py-12">Loading…</div></div>
  </div>`;
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
    dl.classList.remove('hidden');
    if (ct.startsWith('image/')) {
      body.innerHTML = `<img src="${dataUrl}" alt="${escHtml(title)}" class="max-w-full mx-auto rounded-lg shadow-lg">`;
    } else if (ct === 'application/pdf' || ct.endsWith('/pdf')) {
      body.innerHTML = `<iframe src="${dataUrl}" class="w-full h-[75vh] rounded-lg bg-white" title="${escHtml(title)}"></iframe>`;
    } else {
      body.innerHTML = `<div class="text-sm text-on-surface-variant">Content type <span class="mono-text">${escHtml(ct)}</span> cannot be previewed inline — use Download above.</div>`;
    }
  } catch (e) {
    modal.querySelector('#docBody').innerHTML = `<div class="text-sm text-error mono-text break-all">${escHtml(e.message)}</div>`;
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
    footer.classList.remove('hidden');
    footer.classList.add('flex');
    document.getElementById('dirtyList').textContent = keys.join(', ');
  } else {
    footer.classList.add('hidden');
    footer.classList.remove('flex');
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
