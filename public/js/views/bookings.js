// ═════════════════════════════════════════════════════════════════════════
// BOOKINGS
// ═════════════════════════════════════════════════════════════════════════
let bkFilters = {}, bkTab = 'registered';

async function renderBookings(el, page = 1) {
  el.innerHTML = pageWrap(pageHero('Bookings') + loadingState());
  try {
    const endpoint = bkTab === 'registered' ? '/api/bookings' : '/api/guest-bookings';
    const p = new URLSearchParams({ ...bkFilters, page, pageSize: 50 });
    const data = await apiFetch(`${endpoint}?${p}`);
    setConnStatus('connected');

    const filterHtml =
      fInput('Date From', `type="date" value="${bkFilters.dateFrom?.split('T')[0]||''}" oninput="bkFilters.dateFrom=this.value?this.value+'T00:00:00':''"`) +
      fInput('Date To',   `type="date" value="${bkFilters.dateTo?.split('T')[0]||''}"   oninput="bkFilters.dateTo=this.value?this.value+'T23:59:59':''"`) +
      fInput('Praxis', `placeholder="lc_10" value="${escHtml(bkFilters.praxisId||'')}" oninput="bkFilters.praxisId=this.value"`) +
      fSelect('Status', [{value:'',label:'All'}, ...APT_STATUS.map((s,i) => ({value:i,label:s}))], `oninput="bkFilters.status=this.value"`, bkFilters.status ?? '') +
      fInput('Category', `placeholder="category" value="${escHtml(bkFilters.category||'')}" oninput="bkFilters.category=this.value"`) +
      `<div class="flex gap-2">${btnPrimary('Search', `renderBookings(document.getElementById('content'))`, { full: true, icon: 'search' })}${btnGhost('Clear', `bkFilters={};renderBookings(document.getElementById('content'))`)}</div>`;

    const guestKeyRow = bkTab === 'guest' ? `
      <section class="bg-surface-container-lowest rounded-xl shadow-whisper p-4 mb-6 flex items-center gap-4">
        <span class="material-symbols-outlined text-primary">key</span>
        <label class="text-[10px] font-bold text-on-surface-variant uppercase tracking-wider">Decryption Key</label>
        <input id="bkDecKey" type="password" placeholder="32-char AES-256 key" value="${escHtml(localStorage.getItem('bk_dec_key')||'')}" class="flex-1 max-w-md bg-surface-container-low border-none rounded-lg text-xs px-3 py-2 mono-text focus:ring-2 focus:ring-primary-fixed">
        <span id="bkKeyLen" class="text-[10px] mono-text ${(localStorage.getItem('bk_dec_key')||'').length === 32 ? 'text-tertiary' : 'text-outline'}">${(localStorage.getItem('bk_dec_key')||'').length}/32</span>
      </section>` : '';

    const tabsHtml = `<div class="flex gap-1 border-b border-outline-variant/30 mb-6">
      <button class="px-6 py-3 text-sm ${bkTab==='registered' ? 'font-semibold text-primary border-b-2 border-primary' : 'font-medium text-on-surface-variant hover:text-on-surface'} transition-all" onclick="bkTab='registered';renderBookings(document.getElementById('content'))">Registered Patients</button>
      <button class="px-6 py-3 text-sm ${bkTab==='guest' ? 'font-semibold text-primary border-b-2 border-primary' : 'font-medium text-on-surface-variant hover:text-on-surface'} transition-all" onclick="bkTab='guest';renderBookings(document.getElementById('content'))">Guest Appointments</button>
    </div>`;

    const headers = bkTab === 'registered'
      ? ['Created','Start Time','Patient','Email','Category','Status','Praxis','PMS ID']
      : ['Created','Start Time','Email','Category','Status','Praxis','Patient Info'];

    const rowsHtml = data.rows.map((r, ri) => {
      const [bg, fg, dot] = APT_STATUS_PILL[r.status] || APT_STATUS_PILL[0];
      const statusCell = `<span class="flex items-center gap-1.5 ${fg} font-medium text-xs"><span class="w-2 h-2 rounded-full ${dot} ring-2 ring-current/10"></span>${escHtml(APT_STATUS[r.status]||r.status)}</span>`;
      if (bkTab === 'registered') {
        return `<tr class="compact-row border-b border-surface-container hover:bg-surface-container-low transition-colors">
          <td class="px-4 mono-text text-[11px] text-on-surface-variant whitespace-nowrap">${escHtml(deTime(r.createdAt))}</td>
          <td class="px-4 mono-text text-[11px] font-medium whitespace-nowrap">${escHtml(deTime(r.startTime))}</td>
          <td class="px-4 font-semibold text-primary text-sm">${escHtml(r.firstName||'')} ${escHtml(r.lastName||'')}</td>
          <td class="px-4 text-outline text-sm truncate max-w-[180px]">${escHtml(r.email)||'—'}</td>
          <td class="px-4"><span class="px-2 py-0.5 rounded-full text-[10px] font-bold ${bg} ${fg}">${escHtml((r.category||'').toUpperCase())}</span></td>
          <td class="px-4">${statusCell}</td>
          <td class="px-4 text-xs font-medium" title="${escHtml(r.praxisId)||''}">${escHtml(praxisName(r.praxisId) || r.praxisId)}</td>
          <td class="px-4 mono-text text-[10px] text-outline">${escHtml(r.pmsAppointmentId)||'—'}</td>
        </tr>`;
      } else {
        return `<tr class="compact-row border-b border-surface-container hover:bg-surface-container-low transition-colors">
          <td class="px-4 mono-text text-[11px] text-on-surface-variant whitespace-nowrap">${escHtml(deTime(r.createdAt))}</td>
          <td class="px-4 mono-text text-[11px] font-medium whitespace-nowrap">${escHtml(deTime(r.startTime))}</td>
          <td class="px-4 text-sm">${escHtml(r.email)||'—'}</td>
          <td class="px-4"><span class="px-2 py-0.5 rounded-full text-[10px] font-bold ${bg} ${fg}">${escHtml((r.category||'').toUpperCase())}</span></td>
          <td class="px-4">${statusCell}</td>
          <td class="px-4 text-xs font-medium" title="${escHtml(r.praxisId)||''}">${escHtml(praxisName(r.praxisId) || r.praxisId)}</td>
          <td class="px-4 text-xs" id="bkCell_${ri}">
            ${r.encryptedUserInfo
              ? `<button class="flex items-center gap-1 px-2 py-1 bg-primary/10 text-primary rounded text-[10px] font-bold hover:bg-primary/20 transition-colors" onclick="decryptGuestRow(${ri}, '${escHtml(r.encryptedUserInfo)}')"><span class="material-symbols-outlined text-xs">lock_open</span>Decrypt</button>`
              : '—'}
          </td>
        </tr>`;
      }
    }).join('');

    el.innerHTML = pageWrap(
      pageHero('Bookings', { sub: 'Patient and guest appointment ledger' }) +
      tabsHtml +
      filterCard(filterHtml, 6) +
      guestKeyRow +
      tableShell(headers, rowsHtml, 'bkPaging')
    );
    renderPagination(document.getElementById('bkPaging'), data, (p) => renderBookings(document.getElementById('content'), p));

    const keyInput = document.getElementById('bkDecKey');
    const keyLen = document.getElementById('bkKeyLen');
    if (keyInput && keyLen) {
      keyInput.addEventListener('input', () => {
        const l = keyInput.value.length;
        keyLen.textContent = `${l}/32`;
        keyLen.className = `text-[10px] mono-text ${l === 32 ? 'text-tertiary' : l > 32 ? 'text-error' : 'text-outline'}`;
        localStorage.setItem('bk_dec_key', keyInput.value);
      });
    }
  } catch(e) {
    setConnStatus('error');
    el.innerHTML = pageWrap(pageHero('Bookings') + errorState(e.message));
  }
}

async function decryptGuestRow(rowIndex, encryptedText) {
  const keyInput = document.getElementById('bkDecKey');
  const key = keyInput ? keyInput.value : localStorage.getItem('bk_dec_key') || '';
  const cell = document.getElementById(`bkCell_${rowIndex}`);
  if (!cell) return;

  if (key.length !== 32) {
    cell.innerHTML = `<span class="text-error text-xs font-medium">Enter a 32-char key above</span>`;
    keyInput?.focus();
    return;
  }

  cell.innerHTML = `<span class="text-outline text-xs">Decrypting…</span>`;
  try {
    const cryptoKey = await importAesKey(key);
    const json = await aesDecrypt(cryptoKey, encryptedText);
    const obj = JSON.parse(json);
    const name = [obj.firstName || obj.first_name, obj.lastName || obj.last_name].filter(Boolean).join(' ');
    const email = obj.email || '';
    const phone = obj.phoneNumber || obj.phone_number || obj.phone || '';
    const dob = obj.dob || obj.dateOfBirth || '';
    cell.innerHTML = `<div class="text-xs leading-relaxed">
      ${name ? `<div class="font-semibold text-tertiary-container">${escHtml(name)}</div>` : ''}
      ${email ? `<div class="text-primary">${escHtml(email)}</div>` : ''}
      ${phone ? `<div class="text-on-surface-variant mono-text">${escHtml(phone)}</div>` : ''}
      ${dob ? `<div class="text-on-surface-variant mono-text">DOB: ${escHtml(dob)}</div>` : ''}
    </div>`;
  } catch(e) {
    cell.innerHTML = `<span class="text-error text-xs font-medium" title="${escHtml(e.message)}">Decrypt failed</span>`;
  }
}
