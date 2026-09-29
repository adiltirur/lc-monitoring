// Copy the current Query Runner editor contents.
function copyQrSql() {
  const ta = document.getElementById('qrSql');
  if (!ta) return;
  const v = ta.value.trim();
  if (!v) { showToast('Editor is empty'); return; }
  copyText(v, 'Copied SQL');
}

// ═════════════════════════════════════════════════════════════════════════
// QUERY RUNNER
// ═════════════════════════════════════════════════════════════════════════
let qrHistory = JSON.parse(localStorage.getItem('qr_history') || '[]');
let qrWriteMode = false;

const PRESET_QUERIES = [
  { label: 'Users registered today', sql: `SELECT id, "firstName", "lastName", email, "phoneNumber", "praxisId", "createdAt" AT TIME ZONE 'Europe/Berlin' as "createdAt_DE"\nFROM app_user_info\nWHERE "createdAt" >= NOW() - INTERVAL '1 day'\nORDER BY "createdAt" DESC` },
  { label: 'Appointments on a date', sql: `SELECT a.id, a.category, a.status, a."startTime", a."praxisId", u."firstName", u."lastName", u.email\nFROM app_user_appointment a\nLEFT JOIN app_user_info u ON u.id = a."userId"\nWHERE DATE(a."createdAt" AT TIME ZONE 'Europe/Berlin') = '2026-01-01'\nORDER BY a."createdAt" DESC` },
  { label: 'Failed API sessions (24h)', sql: `SELECT id, "time" AT TIME ZONE 'Europe/Berlin' as "time_DE", endpoint, method, duration, error\nFROM serverpod_session_log\nWHERE error IS NOT NULL AND "time" >= NOW() - INTERVAL '24 hours'\nORDER BY "time" DESC LIMIT 100` },
  { label: 'Users by praxis', sql: `SELECT "praxisId", COUNT(*) as user_count\nFROM app_user_info\nGROUP BY "praxisId"\nORDER BY user_count DESC` },
  { label: 'Cancelled appointments (7 days)', sql: `SELECT a."createdAt" AT TIME ZONE 'Europe/Berlin', a.category, a."praxisId", u."firstName", u."lastName", u.email\nFROM app_user_appointment a\nLEFT JOIN app_user_info u ON u.id = a."userId"\nWHERE a.status = 5 AND a."createdAt" >= NOW() - INTERVAL '7 days'\nORDER BY a."createdAt" DESC` },
  { label: 'Guest appointments this week', sql: `SELECT id, category, status, "praxisId", email, "startTime", "isBookedFromPraxis", "createdAt" AT TIME ZONE 'Europe/Berlin'\nFROM guest_appointment\nWHERE "createdAt" >= date_trunc('week', NOW() AT TIME ZONE 'Europe/Berlin') AT TIME ZONE 'Europe/Berlin'\nORDER BY "createdAt" DESC` },
  { label: 'Recent admin actions', sql: `SELECT "userName", "userEmail", action, "praxisId", "createdAt" AT TIME ZONE 'Europe/Berlin'\nFROM admin_audit_log\nORDER BY "createdAt" DESC LIMIT 50` },
  { label: 'Slow queries (>1s)', sql: `SELECT sl."time" AT TIME ZONE 'Europe/Berlin', sl.endpoint, sl.method, ql.query, ql.duration, ql."numRows"\nFROM serverpod_query_log ql\nJOIN serverpod_session_log sl ON sl.id = ql."sessionLogId"\nWHERE ql.slow = true OR ql.duration > 1000\nORDER BY ql.duration DESC LIMIT 50` },
];

function renderQueryRunner(el) {
  el.innerHTML = `<div class="p-8 max-w-[1600px] mx-auto">
    ${pageHero('Query Runner', { sub: 'Read-only by default · Ctrl+Enter to run' })}
    <section class="bg-surface-container-lowest rounded-xl shadow-whisper overflow-hidden mb-6">
      <div class="p-4 border-b border-slate-200 bg-white">
        <div class="flex justify-between items-start mb-4">
          <div>
            <h3 class="text-lg font-bold tracking-tight">SQL Editor</h3>
            <p class="text-xs text-on-surface-variant font-medium">Read-only by default</p>
          </div>
          <label class="flex items-center gap-2 cursor-pointer">
            <span class="text-[10px] font-bold text-slate-400 uppercase tracking-widest">Write Mode</span>
            <div class="relative inline-flex items-center cursor-pointer">
              <input id="writeMode" type="checkbox" class="sr-only peer" onchange="qrWriteMode=this.checked;document.getElementById('writeModeWarn').classList.toggle('hidden', !this.checked)">
              <div class="w-8 h-4 bg-slate-200 rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-3 after:w-3 after:transition-all peer-checked:bg-error"></div>
            </div>
          </label>
        </div>
        <div class="flex items-center gap-2 mb-2">
          <select id="qrPreset" class="flex-1 bg-surface-container-low border border-outline-variant rounded-lg text-xs font-medium py-2 px-3 focus:ring-2 focus:ring-primary-fixed focus:border-primary" onchange="if(this.value!==''){document.getElementById('qrSql').value=PRESET_QUERIES[this.value].sql;this.value='';}">
            <option value="">— Preset queries —</option>
            ${PRESET_QUERIES.map((q,i) => `<option value="${i}">${escHtml(q.label)}</option>`).join('')}
          </select>
          ${qrHistory.length ? `<select class="flex-1 bg-surface-container-low border border-outline-variant rounded-lg text-xs font-medium py-2 px-3 focus:ring-2 focus:ring-primary-fixed focus:border-primary" onchange="if(this.value!==''){document.getElementById('qrSql').value=qrHistory[this.value];this.value='';}">
            <option value="">— Recent queries —</option>
            ${qrHistory.map((q,i) => `<option value="${i}">${escHtml(q.substring(0,80))}…</option>`).join('')}
          </select>` : ''}
          <button class="px-3 py-2 text-xs font-medium text-slate-500 hover:text-primary hover:bg-primary/5 rounded-lg transition-colors flex items-center gap-1" onclick="document.getElementById('qrSql').value=''">
            <span class="material-symbols-outlined text-sm">layers_clear</span>Clear
          </button>
        </div>
      </div>
      <div class="code-bg relative group">
        <textarea id="qrSql" class="w-full h-72 bg-transparent border-none focus:ring-0 text-jetbrains text-sm p-4 pr-14 text-indigo-300/90 leading-relaxed resize-none outline-none" spellcheck="false" placeholder="SELECT * FROM app_user_info LIMIT 10"></textarea>
        <button class="absolute top-3 right-3 p-2 rounded-md bg-slate-800/80 hover:bg-slate-700 text-slate-300 hover:text-white opacity-60 group-hover:opacity-100 transition-all" title="Copy SQL" onclick="copyQrSql()">
          <span class="material-symbols-outlined text-sm">content_copy</span>
        </button>
      </div>
      <div class="p-3 bg-surface-container-low flex justify-between items-center border-t border-slate-200">
        <div class="flex items-center gap-4">
          <button class="bg-gradient-to-br from-primary to-primary-container text-on-primary px-5 py-2 rounded-lg text-xs font-bold flex items-center gap-2 transition-all shadow-md active:scale-95" onclick="runQuery()">
            <span class="material-symbols-outlined text-sm ms-fill">play_arrow</span>Run Query
            <span class="opacity-50 font-normal">Ctrl+Enter</span>
          </button>
          <button class="bg-surface-container-high hover:bg-surface-variant text-on-surface-variant px-3 py-2 rounded-lg text-xs font-bold flex items-center gap-1.5 transition-colors" onclick="copyQrSql()" title="Copy SQL">
            <span class="material-symbols-outlined text-sm">content_copy</span>Copy
          </button>
          <span class="text-[10px] mono-text text-slate-400">Status: Idle</span>
        </div>
        <div id="writeModeWarn" class="hidden flex items-center gap-2 text-error text-[10px] font-bold tracking-widest uppercase">
          <span class="material-symbols-outlined text-sm">warning</span>Mutations enabled
        </div>
      </div>
    </section>
    <div id="qrResult"></div>
  </div>`;

  document.getElementById('qrSql').addEventListener('keydown', e => {
    if (e.ctrlKey && e.key === 'Enter') runQuery();
  });
}

async function runQuery() {
  const sql = document.getElementById('qrSql').value.trim();
  if (!sql) return;
  const resultEl = document.getElementById('qrResult');
  resultEl.innerHTML = loadingState('Running query…');

  try {
    const data = await apiPost('/api/query', { sql, allowMutations: qrWriteMode });
    if (data.error) {
      resultEl.innerHTML = errorState(data.error); return;
    }

    qrHistory = [sql, ...qrHistory.filter(q => q !== sql)].slice(0, 20);
    localStorage.setItem('qr_history', JSON.stringify(qrHistory));

    if (!data.rows.length) { resultEl.innerHTML = emptyState('Query returned 0 rows', 'inbox'); return; }

    const cols = Object.keys(data.rows[0]);
    const rowsHtml = data.rows.map(r => `<tr class="zebra-row hover:bg-surface-container transition-colors">${cols.map(c => `<td class="px-4 py-2 mono-text text-xs truncate max-w-[260px]" title="${escHtml(String(r[c]??''))}">${escHtml(String(r[c]??''))||'<span class="text-outline italic">null</span>'}</td>`).join('')}</tr>`).join('');

    resultEl.innerHTML = `<section class="bg-surface-container-lowest rounded-xl shadow-whisper overflow-hidden">
      <div class="px-6 py-4 flex justify-between items-center bg-white border-b border-surface-container-low">
        <h3 class="text-lg font-bold tracking-tight">Results</h3>
        <span class="text-xs mono-text text-on-surface-variant">${data.count} rows</span>
      </div>
      <div class="overflow-x-auto">
        <table class="w-full text-left border-collapse">
          <thead class="bg-surface-container-low text-on-surface-variant"><tr>${cols.map(c => `<th class="px-4 py-3 text-[0.7rem] font-bold uppercase tracking-widest mono-text">${escHtml(c)}</th>`).join('')}</tr></thead>
          <tbody>${rowsHtml}</tbody>
        </table>
      </div>
    </section>`;
  } catch(e) { resultEl.innerHTML = errorState(e.message); }
}
