// ═════════════════════════════════════════════════════════════════════════
// ANALYTICS
// ═════════════════════════════════════════════════════════════════════════
let anState = {
  praxes: null, selected: null,
  startDate: null, endDate: null,
  tab: 'overview',
  data: null,
  overviewData: null,
  overviewCockpit: null,
  cockpitData: null,
  overviewSort: { key: 'appointmentsTotal', dir: 'desc' },
};
const AN_ALL_PRAXES = '__all__';

// Palette for charts — picked from the token set so they fit the dark theme.
const AN_COLORS = {
  app:      '#00ffa0',
  web:      '#7aa5ff',
  praxis:   '#b3ff00',
  newReg:   '#ffb454',
  verified: '#00ffa0',
  error:    '#ff5374',
  muted:    '#a0a8b4',
  palette:  ['#00ffa0','#7aa5ff','#b3ff00','#ffb454','#ff5374','#6affd5','#c084fc','#f472b6','#fb923c','#38bdf8'],
};

function fmtDuration(totalSeconds) {
  const s = Math.max(0, parseInt(totalSeconds || 0, 10));
  const d = Math.floor(s / 86400);
  const h = Math.floor((s % 86400) / 3600);
  const m = Math.floor((s % 3600) / 60);
  const sec = s % 60;
  const parts = [];
  if (d) parts.push(`${d}d`);
  if (h) parts.push(`${h}h`);
  if (m) parts.push(`${m}m`);
  if (sec || !parts.length) parts.push(`${sec}s`);
  return parts.join(' ');
}

function fmtDate(d) {
  if (!d) return '';
  const x = d instanceof Date ? d : new Date(d);
  const pad = n => String(n).padStart(2, '0');
  return `${x.getFullYear()}-${pad(x.getMonth()+1)}-${pad(x.getDate())}`;
}

function statCard(label, value, opts = {}) {
  const tone = opts.tone || 'primary';
  const toneCls = { primary: 'text-primary', amber: 'text-amber-400', error: 'text-error', muted: 'text-on-surface-variant', success: 'text-tertiary' }[tone] || 'text-primary';
  const sub = opts.sub ? `<div class="text-[11px] font-semibold mt-2 ${toneCls}">${escHtml(opts.sub)}</div>` : '';
  const num = typeof value === 'number' ? value.toLocaleString(undefined, { maximumFractionDigits: 1 }) : String(value);
  const suffix = opts.suffix ? `<span class="text-lg ml-1 text-on-surface-variant">${escHtml(opts.suffix)}</span>` : '';
  return `<div class="bg-surface-container-lowest rounded-xl p-4 border border-outline-variant/20">
    <div class="text-[10px] font-bold uppercase tracking-widest text-on-surface-variant mb-2">${escHtml(label)}</div>
    <div class="text-3xl font-black mono-text ${toneCls} leading-none">${num}${suffix}</div>
    ${sub}
  </div>`;
}

// ── Tabs ──
const AN_TABS = [
  { id: 'overview',     label: 'Overview' },
  { id: 'appointments', label: 'Appointments' },
  { id: 'patients',     label: 'Patients' },
  { id: 'operations',   label: 'Operations' },
  { id: 'cockpit',      label: 'Cockpit' },
];

function fmtMinutesToHours(min) {
  const m = Number(min) || 0;
  if (m === 0) return '0h';
  const sign = m < 0 ? '-' : '';
  const abs = Math.abs(m);
  const h = Math.floor(abs / 60);
  const r = Math.round(abs % 60);
  return `${sign}${h}h${r ? ' ' + r + 'm' : ''}`;
}

function anRenderTabBar() {
  return `<div class="inline-flex gap-1 p-1 bg-surface-container rounded-xl border border-outline-variant/30 mb-6">
    ${AN_TABS.map(t => `<button
        class="px-4 py-1.5 text-xs font-bold rounded-lg transition-all ${anState.tab === t.id ? 'bg-surface-container-lowest text-primary shadow' : 'text-on-surface-variant hover:text-on-surface'}"
        onclick="anState.tab='${t.id}';anRenderBody()"
      >${escHtml(t.label)}</button>`).join('')}
  </div>`;
}

function anSortOverview(key) {
  if (anState.overviewSort.key === key) anState.overviewSort.dir = anState.overviewSort.dir === 'desc' ? 'asc' : 'desc';
  else anState.overviewSort = { key, dir: 'desc' };
  anRenderBody();
}

function anRenderOverview() {
  const el = document.getElementById('anBody');
  if (!el) return;
  const data = anState.overviewData;
  if (!data) { el.innerHTML = loadingState('Loading all praxes…'); return; }

  const sum = data.summary;
  const summaryCards = `<div class="grid grid-cols-2 md:grid-cols-4 gap-3 mb-6">` +
    statCard('Praxes',                 sum.praxesCount, { tone: 'muted' }) +
    statCard('Appointments booked',    sum.appointmentsTotal) +
    statCard('Appointments took place',sum.tookPlaceTotal, { tone: 'success' }) +
    statCard('New registrations',      sum.newRegistrations, { sub: `${sum.newVerifiedRegistrations.toLocaleString()} verified` }) +
    statCard('Total patients',         sum.totalPatients, { sub: `${sum.totalVerifiedPatients.toLocaleString()} verified`, tone: 'muted' }) +
    statCard('Doc requests',           sum.docRequests) +
    statCard('Open consultations',     sum.openConsultations) +
    statCard('NPS sent (total)',       sum.totalNPS, { sub: `app ${sum.npsEmailsSent.toLocaleString()} · guest ${sum.guestNPS.toLocaleString()}` }) +
  `</div>`;

  const globalCards = `<div class="grid grid-cols-2 md:grid-cols-4 gap-3 mb-6">
    <div class="col-span-2 md:col-span-4 text-[11px] font-bold uppercase tracking-widest text-on-surface-variant -mb-1">Global (not per-praxis in schema)</div>` +
    statCard('Cancellations',          sum.totalCancellations, { tone: 'error' }) +
    statCard('Questionnaires',         sum.totalQuestionnaires) +
    statCard('Deletion feedback',      sum.totalDeletions, { tone: 'muted' }) +
    statCard('PMS downtime',           sum.pmsDownTimeInMinutes, { suffix: ' min', sub: sum.pmsDownTimeInSeconds > 0 ? fmtDuration(sum.pmsDownTimeInSeconds) : '', tone: sum.pmsDownTimeInSeconds > 0 ? 'error' : 'primary' }) +
  `</div>`;

  let cockpitCards = '';
  if (anState.overviewCockpit && anState.overviewCockpit.praxes) {
    const cp = anState.overviewCockpit.praxes;
    const cpConfigured = cp.filter(x => x.hasBaseline).length;
    const cpBundeslandSet = cp.filter(x => x.bundesland).length;
    const cpBundeslandMissing = cpConfigured - cpBundeslandSet;
    const cpOverrideTotal = cp.reduce((s, x) => s + (x.overrideCount || 0), 0);
    const cpVersionTotal  = cp.reduce((s, x) => s + (x.versionCount || 0), 0);
    const cpActivePdes    = cp.reduce((s, x) => s + (x.activePdeCount || 0), 0);
    const cpMatrixEntries = cp.reduce((s, x) => s + (x.matrixEntries || 0), 0);
    const wk = `${anState.overviewCockpit.currentIsoYear}-W${String(anState.overviewCockpit.currentIsoWeek).padStart(2, '0')}`;
    cockpitCards = `<div class="grid grid-cols-2 md:grid-cols-4 gap-3 mb-6">
      <div class="col-span-2 md:col-span-4 text-[11px] font-bold uppercase tracking-widest text-on-surface-variant -mb-1">Cockpit (config snapshot · current ISO week ${escHtml(wk)})</div>` +
      statCard('Praxes with baseline', cpConfigured,   { sub: `${cp.length - cpConfigured} not yet configured`, tone: cpConfigured > 0 ? 'success' : 'muted' }) +
      statCard('Bundesland missing',   cpBundeslandMissing, { sub: `${cpBundeslandSet} set`, tone: cpBundeslandMissing > 0 ? 'amber' : 'muted' }) +
      statCard('Week overrides',       cpOverrideTotal, { sub: `${cpVersionTotal} std-week versions` }) +
      statCard('Active PDEs',          cpActivePdes,    { sub: `${cpMatrixEntries} matrix entries`, tone: cpActivePdes > 0 ? 'amber' : 'muted' }) +
    `</div>`;
  }

  const cols = [
    { key: 'praxisId',              label: 'Praxis' },
    { key: 'appointmentsTotal',     label: 'Booked' },
    { key: 'tookPlaceTotal',        label: 'Took place' },
    { key: 'newRegistrations',      label: 'New regs' },
    { key: 'totalPatients',         label: 'Patients' },
    { key: 'totalVerifiedPatients', label: 'Verified' },
    { key: 'docRequests',           label: 'Doc reqs' },
    { key: 'openConsultations',     label: 'Open consults' },
    { key: 'totalNPS',              label: 'NPS sent' },
    { key: 'npsCoveragePercentage', label: 'NPS cov %' },
    { key: 'cockpitWorkMinutes',    label: 'Cockpit work' },
    { key: 'cockpitOverrideCount',  label: 'Overrides' },
    { key: 'cockpitActivePdeCount', label: 'PDEs' },
  ];

  const cockpitByLcId = {};
  if (anState.overviewCockpit && anState.overviewCockpit.praxes) {
    for (const r of anState.overviewCockpit.praxes) cockpitByLcId[r.lcId] = r;
  }
  const enrichedPraxes = data.praxes.map(p => {
    const c = cockpitByLcId[p.praxisId] || {};
    return {
      ...p,
      cockpitWorkMinutes:    c.workMinutes || 0,
      cockpitOverrideCount:  c.overrideCount || 0,
      cockpitActivePdeCount: c.activePdeCount || 0,
      cockpitVersionCount:   c.versionCount || 0,
      cockpitBundesland:     c.bundesland || null,
      cockpitHasBaseline:    !!c.hasBaseline,
    };
  });

  const { key: sortKey, dir: sortDir } = anState.overviewSort;
  const praxes = enrichedPraxes.sort((a, b) => {
    const av = a[sortKey], bv = b[sortKey];
    if (typeof av === 'string') return sortDir === 'asc' ? av.localeCompare(bv) : bv.localeCompare(av);
    return sortDir === 'asc' ? (av - bv) : (bv - av);
  });

  const head = cols.map(c => {
    const isSorted = c.key === sortKey;
    const arrow = isSorted ? (sortDir === 'desc' ? ' ↓' : ' ↑') : '';
    return `<th class="px-3 py-2 text-[10px] font-bold uppercase tracking-widest text-on-surface-variant cursor-pointer hover:text-primary transition-colors ${isSorted ? 'text-primary' : ''}"
             onclick="anSortOverview('${c.key}')">${escHtml(c.label)}${arrow}</th>`;
  }).join('');

  const cockpitWorkCell = (p) => {
    if (!p.cockpitHasBaseline) return `<span class="text-on-surface-variant italic">—</span>`;
    const land = p.cockpitBundesland
      ? `<span class="ml-1 px-1.5 py-0.5 text-[9px] font-bold rounded bg-surface-container text-on-surface-variant uppercase">${escHtml(p.cockpitBundesland)}</span>`
      : `<span class="ml-1 px-1.5 py-0.5 text-[9px] font-bold rounded bg-amber-500/15 text-amber-300 uppercase" title="bundeslandCode missing — holiday calendar disabled">no land</span>`;
    return `${escHtml(fmtMinutesToHours(p.cockpitWorkMinutes))}${land}`;
  };

  const rows = praxes.map(p => `<tr class="zebra-row cursor-pointer hover:bg-surface-container transition-colors"
      onclick="anState.selected='${escHtml(p.praxisId)}';anState.data=null;anState.cockpitData=null;renderAnalytics(document.getElementById('content'))">
    <td class="px-3 py-2 text-xs">
      <div class="font-semibold">${escHtml(praxisName(p.praxisId) || p.praxisId)}</div>
      ${praxisName(p.praxisId) ? `<div class="mono-text text-[10px] text-on-surface-variant">${escHtml(p.praxisId)}</div>` : ''}
    </td>
    <td class="px-3 py-2 mono-text text-xs text-right">${p.appointmentsTotal.toLocaleString()}</td>
    <td class="px-3 py-2 mono-text text-xs text-right text-tertiary">${p.tookPlaceTotal.toLocaleString()}</td>
    <td class="px-3 py-2 mono-text text-xs text-right">${p.newRegistrations.toLocaleString()}</td>
    <td class="px-3 py-2 mono-text text-xs text-right">${p.totalPatients.toLocaleString()}</td>
    <td class="px-3 py-2 mono-text text-xs text-right text-on-surface-variant">${p.totalVerifiedPatients.toLocaleString()}</td>
    <td class="px-3 py-2 mono-text text-xs text-right">${p.docRequests.toLocaleString()}</td>
    <td class="px-3 py-2 mono-text text-xs text-right">${p.openConsultations.toLocaleString()}</td>
    <td class="px-3 py-2 mono-text text-xs text-right">${p.totalNPS.toLocaleString()}</td>
    <td class="px-3 py-2 mono-text text-xs text-right">${p.npsCoveragePercentage.toFixed(1)}%</td>
    <td class="px-3 py-2 mono-text text-xs text-right">${cockpitWorkCell(p)}</td>
    <td class="px-3 py-2 mono-text text-xs text-right ${p.cockpitOverrideCount > 0 ? 'text-primary' : 'text-on-surface-variant'}">${p.cockpitOverrideCount.toLocaleString()}</td>
    <td class="px-3 py-2 mono-text text-xs text-right ${p.cockpitActivePdeCount > 0 ? 'text-amber-300' : 'text-on-surface-variant'}">${p.cockpitActivePdeCount.toLocaleString()}</td>
  </tr>`).join('');

  el.innerHTML = summaryCards + globalCards + cockpitCards + `
    <div class="bg-surface-container-lowest rounded-xl border border-outline-variant/20 overflow-hidden">
      <div class="px-4 py-3 border-b border-outline-variant/20 flex items-center justify-between">
        <h3 class="text-sm font-bold tracking-tight">Per-praxis breakdown (${praxes.length})</h3>
        <span class="text-[11px] text-on-surface-variant italic">Click a row to drill in</span>
      </div>
      <div class="overflow-auto max-h-[70vh]">
        <table class="w-full text-left">
          <thead class="bg-surface-container-high sticky top-0"><tr>${head}</tr></thead>
          <tbody>${rows || `<tr><td colspan="${cols.length}" class="px-4 py-8 text-center text-outline italic">No data for this range</td></tr>`}</tbody>
        </table>
      </div>
    </div>`;
}

function anRenderBody() {
  if (anState.selected === AN_ALL_PRAXES) { anRenderOverview(); return; }
  const data = anState.data;
  const el = document.getElementById('anBody');
  if (!el) return;
  if (!data) { el.innerHTML = `<div class="text-outline italic text-sm py-12 text-center">Pick a praxis + date range and hit Apply.</div>`; return; }

  const labels = (data.dailyTimeSeries || []).map(d => d.date);
  const series = (key, label, color) => ({ label, color, values: (data.dailyTimeSeries || []).map(d => d[key]) });

  let body = anRenderTabBar();

  if (anState.tab === 'overview') {
    body += `<div class="grid grid-cols-2 md:grid-cols-3 gap-3 mb-6">` +
      statCard('Total Appointments', data.totalAppointments, { sub: `${data.totalAppointmentsTookPlace.toLocaleString()} took place`, tone: 'primary' }) +
      statCard('New Registrations',  data.totalNewRegistrations, { sub: `${data.verificationRate.toFixed(1)}% verified`, tone: 'success' }) +
      statCard('Cancellations',      data.totalCancellations, { sub: `${data.cancellationRate.toFixed(1)}% rate`, tone: 'error' }) +
      statCard('Document Requests',  data.totalDocumentRequests, { sub: `App ${data.documentRequestFromApp} · Web ${data.documentRequestFromWeb}`, tone: 'muted' }) +
      statCard('Open Consultations', data.totalOpenConsultations) +
      statCard('Questionnaires',     data.totalQuestionnairesCompleted) +
    `</div>`;
    if (labels.length) {
      body += chartCard('Appointments by Source (daily)', svgLineChart([
        series('appointmentsApp',    'App',    AN_COLORS.app),
        series('appointmentsWeb',    'Web',    AN_COLORS.web),
        series('appointmentsPraxis', 'Praxis', AN_COLORS.praxis),
      ], labels));
      body += chartCard('Registrations (daily)', svgLineChart([
        series('newRegistrations',      'New',      AN_COLORS.newReg),
        series('verifiedRegistrations', 'Verified', AN_COLORS.verified),
      ], labels));
    }
  } else if (anState.tab === 'appointments') {
    body += `<div class="grid grid-cols-2 md:grid-cols-4 gap-3 mb-6">` +
      statCard('Total Booked',    data.totalAppointments) +
      statCard('Took Place',      data.totalAppointmentsTookPlace, { tone: 'success' }) +
      statCard('Cancelled',       data.totalCancellations, { sub: `${data.cancellationRate.toFixed(1)}%`, tone: 'error' }) +
      statCard('Family Members',  data.familyMemberAppointments, { sub: `${data.familyMemberBookingRate.toFixed(1)}%`, tone: 'primary' }) +
    `</div>`;
    body += `<div class="grid grid-cols-1 lg:grid-cols-2 gap-4 mb-4">
      <div class="bg-surface-container-lowest rounded-xl p-5 border border-outline-variant/20">
        <h4 class="text-sm font-bold tracking-tight mb-3">Booking Source</h4>
        ${svgDonut([
          { label: 'App',                  value: data.appointmentsBookedFromApp,                    color: AN_COLORS.app },
          { label: 'Web',                  value: data.appointmentsBookedFromWeb,                    color: AN_COLORS.web },
          { label: 'Praxis (with email)',  value: data.appointmentsBookedFromPraxis,                 color: AN_COLORS.praxis },
          { label: 'Praxis (no email)',    value: data.appointmentsBookedFromPraxisWithoutEmail,     color: '#8fbd00' },
        ])}
      </div>
      <div class="bg-surface-container-lowest rounded-xl p-5 border border-outline-variant/20">
        <h4 class="text-sm font-bold tracking-tight mb-3">Took Place by Source</h4>
        ${svgDonut([
          { label: 'App',                  value: data.appointmentsTookPlaceFromApp,                    color: AN_COLORS.app },
          { label: 'Web',                  value: data.appointmentsTookPlaceFromWeb,                    color: AN_COLORS.web },
          { label: 'Praxis (with email)',  value: data.appointmentsTookPlaceFromPraxis,                 color: AN_COLORS.praxis },
          { label: 'Praxis (no email)',    value: data.appointmentsTookPlaceFromPraxisWithoutEmail,     color: '#8fbd00' },
        ])}
      </div>
    </div>`;
    if (data.appointmentCategories && data.appointmentCategories.length) {
      body += chartCard('Appointment Categories', svgHBars(data.appointmentCategories, AN_COLORS.app));
    }
    if (labels.length) {
      body += chartCard('Daily Appointments (stacked)', svgBarChart([
        series('appointmentsApp',    'App',    AN_COLORS.app),
        series('appointmentsWeb',    'Web',    AN_COLORS.web),
        series('appointmentsPraxis', 'Praxis', AN_COLORS.praxis),
      ], labels, { stacked: true }));
    }
    if (data.cancellationReasons && data.cancellationReasons.length) {
      body += chartCard('Cancellation Reasons', svgHBars(data.cancellationReasons, AN_COLORS.error));
    }
  } else if (anState.tab === 'patients') {
    body += `<div class="grid grid-cols-2 md:grid-cols-4 gap-3 mb-6">` +
      statCard('Total Patients',      data.totalPatients) +
      statCard('Verified Patients',   data.totalVerifiedPatients) +
      statCard('New Registrations',   data.totalNewRegistrations) +
      statCard('Verification Rate',   data.verificationRate, { suffix: '%', tone: 'success' }) +
    `</div>`;
    if (labels.length) {
      body += chartCard('Registration Trend', svgLineChart([
        series('newRegistrations',      'New',      AN_COLORS.newReg),
        series('verifiedRegistrations', 'Verified', AN_COLORS.verified),
      ], labels));
      body += chartCard('Document Requests (daily)', svgLineChart([
        series('documentRequestsApp', 'App', AN_COLORS.app),
        series('documentRequestsWeb', 'Web', AN_COLORS.web),
      ], labels));
      body += chartCard('Open Consultations (daily)', svgBarChart([
        series('openConsultations', 'Open consultations', AN_COLORS.app),
      ], labels, { stacked: false }));
      body += chartCard('Questionnaires Completed (daily)', svgBarChart([
        series('questionnairesCompleted', 'Completed', AN_COLORS.newReg),
      ], labels, { stacked: false }));
    }
    if (data.deletionReasons && data.deletionReasons.length) {
      body += chartCard('Deletion Reasons', svgHBars(data.deletionReasons, AN_COLORS.error));
    }
  } else if (anState.tab === 'operations') {
    const hasDowntime = data.pmsDownTimeInMinutes > 0;
    body += `<div class="grid grid-cols-2 md:grid-cols-4 gap-3 mb-6">` +
      statCard('NPS emails sent',    data.npsEmailsSent) +
      statCard('NPS coverage',       data.npsCoveragePercentage, { suffix: '%' }) +
      statCard('Guest NPS',          data.guestNPS) +
      statCard('Guest NPS · no email', data.guestNPSRequestWithoutEmail, { tone: 'amber' }) +
      statCard('PMS downtime (global)', data.pmsDownTimeInMinutes, { suffix: ' min', sub: hasDowntime ? fmtDuration(data.pmsDownTimeInSeconds) : 'platform-wide — same across all praxes', tone: hasDowntime ? 'error' : 'primary' }) +
    `</div>`;
    body += chartCard('NPS Coverage', svgGauge(data.npsCoveragePercentage));
    if (hasDowntime) {
      body += `<div class="bg-error/10 border border-error/30 rounded-xl p-4 mb-4 flex gap-3 items-start">
        <span class="material-symbols-outlined text-error text-2xl flex-shrink-0">warning</span>
        <div>
          <div class="text-sm font-bold text-error">PMS downtime detected</div>
          <div class="text-xs text-on-surface-variant mt-1">Total: ${escHtml(fmtDuration(data.pmsDownTimeInSeconds))}</div>
        </div>
      </div>`;
      body += chartCard('PMS Downtime events', `<div class="bg-surface-container rounded-lg overflow-hidden">
        <table class="w-full text-left"><thead class="bg-surface-container-high"><tr>
          <th class="px-4 py-2 text-[10px] font-bold uppercase tracking-widest text-on-surface-variant">When</th>
          <th class="px-4 py-2 text-[10px] font-bold uppercase tracking-widest text-on-surface-variant">Duration</th>
          <th class="px-4 py-2 text-[10px] font-bold uppercase tracking-widest text-on-surface-variant">Raw (s)</th>
        </tr></thead><tbody>
          ${(data.pmsDowntimes || []).map(d => `<tr class="zebra-row">
            <td class="px-4 py-2 mono-text text-xs whitespace-nowrap">${escHtml(deTime(d.createdAt))}</td>
            <td class="px-4 py-2 mono-text text-xs">${escHtml(fmtDuration(d.totalDownTimeInSeconds))}</td>
            <td class="px-4 py-2 mono-text text-xs text-on-surface-variant">${d.totalDownTimeInSeconds.toLocaleString()}</td>
          </tr>`).join('')}
        </tbody></table>
      </div>`);
    }
  } else if (anState.tab === 'cockpit') {
    body += anRenderCockpitTab();
  }

  el.innerHTML = body;
}

function anRenderCockpitTab() {
  const c = anState.cockpitData;
  if (!c) {
    return `<div class="bg-surface-container-lowest rounded-xl p-6 border border-outline-variant/20 text-sm text-on-surface-variant italic">
      Cockpit data not available for this praxis. The endpoint may not be reachable, or the praxis has no schedule configured yet.
    </div>`;
  }

  const s = c.summary;
  const wk = `${c.currentIsoYear}-W${String(c.currentIsoWeek).padStart(2, '0')}`;
  const bundeslandPill = c.bundesland
    ? `<span class="px-2 py-0.5 rounded bg-surface-container text-on-surface-variant text-[10px] font-bold uppercase">${escHtml(c.bundesland)}</span>`
    : `<span class="px-2 py-0.5 rounded bg-amber-500/15 text-amber-300 text-[10px] font-bold uppercase">bundesland missing</span>`;

  let body = `<div class="flex items-center gap-3 mb-4">
    <h3 class="text-sm font-bold tracking-tight">Schedule snapshot</h3>
    <span class="text-xs text-on-surface-variant">Current ISO week ${escHtml(wk)}</span>
    ${bundeslandPill}
  </div>`;

  body += `<div class="grid grid-cols-2 md:grid-cols-4 gap-3 mb-6">` +
    statCard('Baseline work',         fmtMinutesToHours(s.workMinutes), { sub: `${fmtMinutesToHours(s.workBreakMinutes)} break · ${s.employeeCount} employees`, tone: 'success' }) +
    statCard('Baseline consultation', fmtMinutesToHours(s.consultationMinutes), { sub: `${fmtMinutesToHours(s.consultationBookableMinutes)} bookable` }) +
    statCard('Standard week versions', s.versionCount, { sub: `${s.overrideCount} week overrides`, tone: 'muted' }) +
    statCard('Active PDEs',           s.activePdeCount, { sub: `${s.totalPdeCount} stored total`, tone: s.activePdeCount > 0 ? 'amber' : 'muted' }) +
  `</div>`;

  const kindEntries = Object.entries(s.consultationKindMinutes || {}).sort((a, b) => b[1] - a[1]);
  if (kindEntries.length) {
    body += chartCard('Consultation minutes by kind', `<div class="space-y-2">${kindEntries.map(([k, v]) => {
      const max = Math.max(1, ...kindEntries.map(x => x[1]));
      const pct = (v / max) * 100;
      return `<div>
        <div class="flex justify-between items-center text-[11px] mb-1">
          <span class="truncate pr-2">${escHtml(k)}</span>
          <span class="mono-text text-on-surface-variant">${escHtml(fmtMinutesToHours(v))}</span>
        </div>
        <div class="h-2 bg-surface-container rounded-full overflow-hidden">
          <div class="h-full rounded-full" style="width:${pct}%;background:${AN_COLORS.app};opacity:0.85"></div>
        </div>
      </div>`;
    }).join('')}</div>`);
  }

  if ((c.employees || []).length) {
    const rows = c.employees.map(e => `<tr class="zebra-row">
      <td class="px-4 py-2 mono-text text-xs">${e.employeeId}</td>
      <td class="px-4 py-2 mono-text text-xs text-right">${escHtml(fmtMinutesToHours(e.workMinutes))}</td>
      <td class="px-4 py-2 mono-text text-xs text-right text-on-surface-variant">${escHtml(fmtMinutesToHours(e.workBreakMinutes))}</td>
      <td class="px-4 py-2 mono-text text-xs text-right">${escHtml(fmtMinutesToHours(e.consultationMinutes))}</td>
    </tr>`).join('');
    body += chartCard(`Per-employee baseline (${c.employees.length})`, `<div class="bg-surface-container rounded-lg overflow-hidden">
      <table class="w-full text-left"><thead class="bg-surface-container-high"><tr>
        <th class="px-4 py-2 text-[10px] font-bold uppercase tracking-widest text-on-surface-variant">Personio ID</th>
        <th class="px-4 py-2 text-[10px] font-bold uppercase tracking-widest text-on-surface-variant text-right">Work</th>
        <th class="px-4 py-2 text-[10px] font-bold uppercase tracking-widest text-on-surface-variant text-right">Break</th>
        <th class="px-4 py-2 text-[10px] font-bold uppercase tracking-widest text-on-surface-variant text-right">Consultation</th>
      </tr></thead><tbody>${rows}</tbody></table>
    </div>`);
  }

  const aspectFlags = (r) => {
    const flag = (label, on) => `<span class="px-1.5 py-0.5 text-[9px] font-bold rounded ${on ? 'bg-primary/20 text-primary' : 'bg-surface-container text-on-surface-variant/50'}">${label}</span>`;
    return `<div class="flex gap-1">${flag('O', r.hasOpening)}${flag('C', r.hasConsultation)}${flag('W', r.hasWork)}${flag('M', r.hasMfaGeneric)}</div>`;
  };

  if ((c.overrides || []).length) {
    const rows = c.overrides.map(r => `<tr class="zebra-row">
      <td class="px-4 py-2 mono-text text-xs">${r.isoYear}-W${String(r.isoWeek).padStart(2, '0')}</td>
      <td class="px-4 py-2">${aspectFlags(r)}</td>
      <td class="px-4 py-2 mono-text text-xs text-on-surface-variant whitespace-nowrap">${escHtml(deTime(r.modifiedAt))}</td>
    </tr>`).join('');
    body += chartCard(`Recent week overrides (${c.overrides.length})`, `<div class="bg-surface-container rounded-lg overflow-hidden">
      <table class="w-full text-left"><thead class="bg-surface-container-high"><tr>
        <th class="px-4 py-2 text-[10px] font-bold uppercase tracking-widest text-on-surface-variant">Week</th>
        <th class="px-4 py-2 text-[10px] font-bold uppercase tracking-widest text-on-surface-variant">Aspects</th>
        <th class="px-4 py-2 text-[10px] font-bold uppercase tracking-widest text-on-surface-variant">Modified</th>
      </tr></thead><tbody>${rows}</tbody></table>
    </div>`);
  }

  if ((c.versions || []).length) {
    const rows = c.versions.map(r => `<tr class="zebra-row">
      <td class="px-4 py-2 mono-text text-xs">${r.validFromIsoYear}-W${String(r.validFromIsoWeek).padStart(2, '0')}</td>
      <td class="px-4 py-2">${aspectFlags(r)}</td>
      <td class="px-4 py-2 mono-text text-xs text-on-surface-variant">${escHtml(r.createdBy || '—')}</td>
      <td class="px-4 py-2 mono-text text-xs text-on-surface-variant whitespace-nowrap">${escHtml(deTime(r.createdAt))}</td>
    </tr>`).join('');
    body += chartCard(`Standard-week versions (${c.versions.length})`, `<div class="bg-surface-container rounded-lg overflow-hidden">
      <table class="w-full text-left"><thead class="bg-surface-container-high"><tr>
        <th class="px-4 py-2 text-[10px] font-bold uppercase tracking-widest text-on-surface-variant">Valid from</th>
        <th class="px-4 py-2 text-[10px] font-bold uppercase tracking-widest text-on-surface-variant">Aspects</th>
        <th class="px-4 py-2 text-[10px] font-bold uppercase tracking-widest text-on-surface-variant">Created by</th>
        <th class="px-4 py-2 text-[10px] font-bold uppercase tracking-widest text-on-surface-variant">Created</th>
      </tr></thead><tbody>${rows}</tbody></table>
    </div>`);
  }

  if ((c.pdes || []).length) {
    const rows = c.pdes.map(r => {
      const validUntil = r.validUntilIsoYear ? `${r.validUntilIsoYear}-W${String(r.validUntilIsoWeek).padStart(2, '0')}` : '∞';
      const activePill = r.isActive
        ? `<span class="px-1.5 py-0.5 text-[9px] font-bold rounded bg-tertiary/20 text-tertiary uppercase">active</span>`
        : `<span class="px-1.5 py-0.5 text-[9px] font-bold rounded bg-surface-container text-on-surface-variant uppercase">inactive</span>`;
      return `<tr class="zebra-row">
        <td class="px-4 py-2 mono-text text-xs">${r.id}</td>
        <td class="px-4 py-2 mono-text text-xs">${r.employeeId}</td>
        <td class="px-4 py-2 text-xs">${escHtml(r.day)}</td>
        <td class="px-4 py-2 text-xs">${escHtml(r.kind)}</td>
        <td class="px-4 py-2 mono-text text-xs">${escHtml(r.start)} – ${escHtml(r.end)}</td>
        <td class="px-4 py-2 mono-text text-xs">${r.validFromIsoYear}-W${String(r.validFromIsoWeek).padStart(2, '0')} → ${escHtml(validUntil)}</td>
        <td class="px-4 py-2">${activePill}</td>
        <td class="px-4 py-2 text-xs text-on-surface-variant truncate max-w-[200px]">${escHtml(r.note || '')}</td>
      </tr>`;
    }).join('');
    body += chartCard(`Person-duration exceptions (${c.pdes.length})`, `<div class="bg-surface-container rounded-lg overflow-hidden">
      <table class="w-full text-left"><thead class="bg-surface-container-high"><tr>
        <th class="px-4 py-2 text-[10px] font-bold uppercase tracking-widest text-on-surface-variant">ID</th>
        <th class="px-4 py-2 text-[10px] font-bold uppercase tracking-widest text-on-surface-variant">Employee</th>
        <th class="px-4 py-2 text-[10px] font-bold uppercase tracking-widest text-on-surface-variant">Day</th>
        <th class="px-4 py-2 text-[10px] font-bold uppercase tracking-widest text-on-surface-variant">Kind</th>
        <th class="px-4 py-2 text-[10px] font-bold uppercase tracking-widest text-on-surface-variant">Time</th>
        <th class="px-4 py-2 text-[10px] font-bold uppercase tracking-widest text-on-surface-variant">Validity</th>
        <th class="px-4 py-2 text-[10px] font-bold uppercase tracking-widest text-on-surface-variant">Status</th>
        <th class="px-4 py-2 text-[10px] font-bold uppercase tracking-widest text-on-surface-variant">Note</th>
      </tr></thead><tbody>${rows}</tbody></table>
    </div>`);
  }

  if ((c.matrix || []).length) {
    const rows = c.matrix.map(r => `<tr class="zebra-row">
      <td class="px-4 py-2 mono-text text-xs">${escHtml(r.appointmentTypeKey)}</td>
      <td class="px-4 py-2 text-xs">${(r.providers || []).map(p => `<span class="inline-block px-1.5 py-0.5 mr-1 mb-1 text-[10px] rounded bg-surface-container text-on-surface-variant">${escHtml(p)}</span>`).join('') || '<span class="text-on-surface-variant italic">—</span>'}</td>
      <td class="px-4 py-2 mono-text text-xs text-on-surface-variant whitespace-nowrap">${escHtml(deTime(r.modifiedAt))}</td>
    </tr>`).join('');
    body += chartCard(`Appointment-type matrix (${c.matrix.length})`, `<div class="bg-surface-container rounded-lg overflow-hidden">
      <table class="w-full text-left"><thead class="bg-surface-container-high"><tr>
        <th class="px-4 py-2 text-[10px] font-bold uppercase tracking-widest text-on-surface-variant">Type key</th>
        <th class="px-4 py-2 text-[10px] font-bold uppercase tracking-widest text-on-surface-variant">Providers</th>
        <th class="px-4 py-2 text-[10px] font-bold uppercase tracking-widest text-on-surface-variant">Modified</th>
      </tr></thead><tbody>${rows}</tbody></table>
    </div>`);
  }

  return body;
}

function anApplyPreset(preset) {
  const today = new Date();
  const start = new Date(today.getFullYear(), today.getMonth(), today.getDate());
  const end   = new Date(today.getFullYear(), today.getMonth(), today.getDate() + 1);
  if (preset === 'thisMonth') {
    anState.startDate = fmtDate(new Date(today.getFullYear(), today.getMonth(), 1));
    anState.endDate   = fmtDate(new Date(today.getFullYear(), today.getMonth() + 1, 1));
  } else if (preset === 'lastMonth') {
    anState.startDate = fmtDate(new Date(today.getFullYear(), today.getMonth() - 1, 1));
    anState.endDate   = fmtDate(new Date(today.getFullYear(), today.getMonth(), 1));
  } else if (preset === '7d') {
    anState.startDate = fmtDate(new Date(start.getTime() - 6 * 86400000));
    anState.endDate   = fmtDate(end);
  } else if (preset === '30d') {
    anState.startDate = fmtDate(new Date(start.getTime() - 29 * 86400000));
    anState.endDate   = fmtDate(end);
  }
  renderAnalytics(document.getElementById('content'));
}

function anExportHistoricalShowModal() {
  return new Promise(resolve => {
    const overlay = document.createElement('div');
    overlay.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,0.55);z-index:10000;display:flex;align-items:center;justify-content:center;padding:16px;';
    overlay.innerHTML = `
      <div class="bg-surface rounded-xl p-6" style="min-width:380px;max-width:520px;width:100%;box-shadow:0 8px 32px rgba(0,0,0,0.25);">
        <h3 class="text-lg font-bold mb-1">Export Historical Analytics</h3>
        <div class="text-xs text-on-surface-variant mb-4">From the earliest record in DB through the selected end date. Praxes processed one-at-a-time to keep DB load low.</div>

        <label class="block text-xs font-semibold uppercase tracking-wide text-on-surface-variant mb-1">End date</label>
        <input type="date" id="ex-end-date" value="2026-04-30" class="w-full px-3 py-2 bg-surface-container rounded-lg mb-4 text-sm">

        <label class="flex items-start gap-2 mb-4 cursor-pointer p-3 bg-surface-container rounded-lg">
          <input type="checkbox" id="ex-validator" class="mt-0.5 w-4 h-4 cursor-pointer">
          <span class="text-sm">
            <strong>Validator mode</strong>
            <div class="text-xs text-on-surface-variant mt-0.5">Adds a 📋 button next to each KPI that copies the SQL behind that number, so you can paste it into your DB client and verify.</div>
          </span>
        </label>

        <div class="flex justify-end gap-2 mt-6">
          <button id="ex-cancel" class="px-4 py-2 rounded-lg bg-surface-container hover:bg-surface-container-high transition-colors text-sm">Cancel</button>
          <button id="ex-go" class="px-4 py-2 rounded-lg bg-primary text-on-primary hover:opacity-90 transition-opacity text-sm font-semibold">Export</button>
        </div>
      </div>
    `;
    document.body.appendChild(overlay);
    const cleanup = (val) => { overlay.remove(); resolve(val); };
    document.getElementById('ex-cancel').onclick = () => cleanup(null);
    overlay.onclick = (e) => { if (e.target === overlay) cleanup(null); };
    document.getElementById('ex-go').onclick = () => {
      const endDate = document.getElementById('ex-end-date').value;
      const validator = document.getElementById('ex-validator').checked;
      if (!/^\d{4}-\d{2}-\d{2}$/.test(endDate)) { alert('Pick a valid date.'); return; }
      cleanup({ endDate, validator });
    };
    setTimeout(() => document.getElementById('ex-end-date')?.focus(), 50);
  });
}

async function anExportHistorical() {
  const choice = await anExportHistoricalShowModal();
  if (!choice) return;
  const { endDate, validator } = choice;
  const body = document.getElementById('anBody');
  if (body) body.innerHTML = `<div class="text-outline text-sm py-12 text-center">Running historical export through ${escHtml(endDate)}${validator ? ' (validator mode)' : ''}… this can take a minute or two. Don't navigate away.</div>`;
  try {
    const q = new URLSearchParams({ endDate, validator: validator ? '1' : '0' });
    const r = await apiFetch(`/api/analytics/export-historical?${q}`);
    if (!r.ok) throw new Error(r.error || 'export failed');
    if (body) body.innerHTML = `<div class="bg-surface-container rounded-xl p-6">
      <div class="text-base font-semibold mb-3">Export complete${r.validator ? ' (validator mode)' : ''}</div>
      <div class="text-sm text-on-surface-variant mb-2">Praxes: <strong>${r.praxesProcessed}</strong> · Months: <strong>${r.monthsCovered}</strong> · Range: <strong>${r.dataStart.slice(0,10)} → ${r.dataEnd.slice(0,10)}</strong></div>
      <div class="text-xs mono-text bg-surface rounded p-3 mt-3 break-all">${escHtml(r.outDir)}</div>
      <ul class="text-sm mt-3 list-disc pl-5">
        <li>${escHtml(r.files.xlsx.split('/').pop())} — multi-sheet workbook</li>
        <li>${escHtml(r.files.html.split('/').pop())} — self-contained report${r.validator ? ' with 📋 SQL copy buttons' : ''}</li>
        <li>${escHtml(r.files.json.split('/').pop())} — raw payload</li>
      </ul>
    </div>`;
  } catch (e) {
    if (body) body.innerHTML = `<div class="bg-error/10 border border-error/30 rounded-xl p-4 text-error text-sm">Export failed: ${escHtml(e.message)}</div>`;
  }
}

async function renderAnalytics(el) {
  const today = new Date();
  if (!anState.startDate) anState.startDate = fmtDate(new Date(today.getFullYear(), today.getMonth(), 1));
  if (!anState.endDate)   anState.endDate   = fmtDate(new Date(today.getFullYear(), today.getMonth() + 1, 1));

  el.innerHTML = pageWrap(pageHero('Analytics', { sub: 'Per-praxis metrics · date-range filtered' }) + loadingState('Loading praxes…'));

  try {
    if (!anState.praxes) {
      const [{ praxes }] = await Promise.all([apiFetch('/api/analytics/praxes'), loadPraxisNames()]);
      anState.praxes = praxes || [];
      if (!anState.selected && anState.praxes.length) anState.selected = anState.praxes[0];
    }

    const praxisOpts = [
      { value: '',              label: '— select praxis —' },
      { value: AN_ALL_PRAXES,   label: '— All praxes (overview) —' },
      ...anState.praxes.map(p => ({ value: p, label: praxisLabel(p) })),
    ];

    const filters =
      fSelect('Praxis', praxisOpts, `oninput="anState.selected=this.value;anState.data=null;anState.overviewData=null;anState.overviewCockpit=null;anState.cockpitData=null;renderAnalytics(document.getElementById('content'))"`, anState.selected || '') +
      fInput('Start date', `type="date" value="${anState.startDate}" onchange="anState.startDate=this.value"`) +
      fInput('End date',   `type="date" value="${anState.endDate}"   onchange="anState.endDate=this.value"`) +
      `<div class="flex gap-2">${btnPrimary('Apply', `anState.data=null;anState.overviewData=null;anState.overviewCockpit=null;anState.cockpitData=null;renderAnalytics(document.getElementById('content'))`, { full: true })}</div>`;

    const presets = `<div class="flex flex-wrap gap-2 text-[11px] font-bold">
      <button class="px-3 py-1.5 rounded-lg bg-surface-container hover:bg-surface-container-high transition-colors" onclick="anApplyPreset('thisMonth')">This month</button>
      <button class="px-3 py-1.5 rounded-lg bg-surface-container hover:bg-surface-container-high transition-colors" onclick="anApplyPreset('lastMonth')">Last month</button>
      <button class="px-3 py-1.5 rounded-lg bg-surface-container hover:bg-surface-container-high transition-colors" onclick="anApplyPreset('7d')">Last 7 days</button>
      <button class="px-3 py-1.5 rounded-lg bg-surface-container hover:bg-surface-container-high transition-colors" onclick="anApplyPreset('30d')">Last 30 days</button>
    </div>`;

    const subLabel = anState.selected === AN_ALL_PRAXES
      ? `All praxes · ${escHtml(deDate(anState.startDate))} – ${escHtml(deDate(anState.endDate))}`
      : `${escHtml(praxisLabel(anState.selected) || '—')} · ${escHtml(deDate(anState.startDate))} – ${escHtml(deDate(anState.endDate))}`;

    el.innerHTML = pageWrap(
      pageHero('Analytics', {
        sub: subLabel,
        actions: `<button class="px-3 py-2 bg-surface-container rounded-lg text-on-surface-variant hover:bg-surface-container-high transition-colors text-sm font-medium" onclick="anExportHistorical()" title="Export full history (XLSX + HTML + JSON) through end of April 2026">Export historical</button>` +
                 `<button class="p-2 bg-surface-container rounded-lg text-on-surface-variant hover:bg-surface-container-high transition-colors ml-2" onclick="anState.data=null;anState.overviewData=null;anState.overviewCockpit=null;anState.cockpitData=null;renderAnalytics(document.getElementById('content'))" title="Refresh"><span class="material-symbols-outlined">refresh</span></button>`,
      }) +
      filterCard(filters, 4) +
      `<div class="mb-4">${presets}</div>` +
      `<div id="anBody">${anState.selected ? loadingState('Running queries…') : `<div class="text-outline italic text-sm py-12 text-center">Pick a praxis (or "All praxes" for an overview) to load metrics.</div>`}</div>`
    );

    if (!anState.selected) return;

    if (anState.selected === AN_ALL_PRAXES) {
      if (!anState.overviewData) {
        const q = new URLSearchParams({ startDate: anState.startDate, endDate: anState.endDate });
        const [overview, cockpit] = await Promise.all([
          apiFetch(`/api/analytics/overview?${q}`),
          apiFetch(`/api/analytics/cockpit-overview`).catch(() => null),
        ]);
        anState.overviewData = overview;
        anState.overviewCockpit = cockpit;
        setConnStatus('connected');
      }
    } else {
      if (!anState.data) {
        const q = new URLSearchParams({
          praxisId:  anState.selected,
          startDate: anState.startDate,
          endDate:   anState.endDate,
        });
        const [perPraxis, cockpit] = await Promise.all([
          apiFetch(`/api/analytics?${q}`),
          apiFetch(`/api/analytics/cockpit?praxisId=${encodeURIComponent(anState.selected)}`).catch(() => null),
        ]);
        anState.data = perPraxis;
        anState.cockpitData = cockpit;
        setConnStatus('connected');
      }
    }
    anRenderBody();
  } catch (e) {
    setConnStatus('error');
    el.innerHTML = pageWrap(pageHero('Analytics') + errorState(e.message));
  }
}
