// ═════════════════════════════════════════════════════════════════════════
// AI ASSISTANT
// ═════════════════════════════════════════════════════════════════════════
let aiMessages = [];
const AI_MODEL = 'eu.anthropic.claude-sonnet-4-5-20250929-v1:0';

function renderAIQuery(el) {
  aiMessages = [];
  el.innerHTML = `<div class="h-full flex flex-col">
    <div class="p-4 border-b border-slate-200 bg-white/80 backdrop-blur-md flex justify-between items-center flex-shrink-0">
      <div class="flex items-center gap-3">
        <h2 class="text-lg font-bold tracking-tight text-on-surface">AI Assistant</h2>
        <span class="bg-surface-container-high px-2 py-0.5 rounded-full text-[10px] font-bold text-slate-600 uppercase border border-slate-300">Claude Sonnet 4.5</span>
      </div>
      <button class="p-2 hover:bg-slate-100 rounded-lg transition-colors" onclick="aiMessages=[];renderAIQuery(document.getElementById('content'))">
        <span class="material-symbols-outlined text-slate-500">refresh</span>
      </button>
    </div>
    <div class="flex-1 overflow-y-auto p-6 space-y-6 atelier-grid" id="chatMessages">
      <div class="flex flex-col items-start">
        <div class="max-w-[90%] bg-white p-5 rounded-xl rounded-tl-none shadow-sm border border-slate-100 text-sm leading-relaxed">
          <p class="text-on-surface mb-3 font-medium">Hi! I know your full database schema. Try asking:</p>
          <ul class="text-sm text-on-surface-variant space-y-1.5 list-disc pl-5">
            <li>"find all bookings for March 2nd"</li>
            <li>"show users who registered this week for praxis lc_10"</li>
            <li>"how many cancelled appointments per praxis last month"</li>
          </ul>
        </div>
        <span class="text-[10px] text-slate-400 mt-1 ml-1">AI</span>
      </div>
    </div>
    <div class="p-6 bg-white border-t border-slate-200 flex-shrink-0">
      <div class="relative bg-surface-container-low rounded-xl border-2 border-transparent focus-within:border-primary/20 transition-all">
        <textarea id="aiInput" placeholder="Ask about the database…" rows="2" class="w-full bg-transparent border-none focus:ring-0 p-4 text-sm text-on-surface placeholder:text-slate-400 resize-none outline-none" onkeydown="if(event.key==='Enter'&&!event.shiftKey){event.preventDefault();sendAiMessage()}"></textarea>
        <div class="flex justify-between items-center px-4 pb-3">
          <div class="flex gap-2 text-slate-400">
            <span class="material-symbols-outlined">database</span>
            <span class="text-[10px] font-medium uppercase tracking-wider">Schema-aware</span>
          </div>
          <div class="flex items-center gap-3">
            <span class="text-[10px] text-slate-400 font-medium">Enter to send · Shift+Enter for newline</span>
            <button class="bg-primary text-on-primary h-9 w-9 flex items-center justify-center rounded-lg shadow-md hover:bg-primary-container transition-all" onclick="sendAiMessage()">
              <span class="material-symbols-outlined ms-fill">send</span>
            </button>
          </div>
        </div>
      </div>
    </div>
  </div>`;
}

async function sendAiMessage() {
  const input = document.getElementById('aiInput');
  const text = input.value.trim();
  if (!text) return;
  input.value = '';

  aiMessages.push({ role: 'user', content: text });
  const chatEl = document.getElementById('chatMessages');

  const time = new Date().toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' });
  chatEl.innerHTML += `<div class="flex flex-col items-end">
    <div class="max-w-[85%] bg-primary text-on-primary p-4 rounded-xl rounded-tr-none shadow-lg text-sm leading-relaxed">${escHtml(text)}</div>
    <span class="text-[10px] text-slate-400 mt-1 mr-1">${time}</span>
  </div>`;
  chatEl.innerHTML += `<div id="aiTyping" class="flex flex-col items-start">
    <div class="bg-white p-4 rounded-xl rounded-tl-none shadow-sm border border-slate-100 text-sm text-outline">
      <span class="material-symbols-outlined animate-spin text-base mr-2">progress_activity</span>Generating SQL…
    </div>
  </div>`;
  chatEl.scrollTop = chatEl.scrollHeight;

  try {
    const data = await apiPost('/api/ai/query', { messages: aiMessages, modelId: AI_MODEL });
    document.getElementById('aiTyping')?.remove();

    if (data.error) {
      chatEl.innerHTML += `<div class="flex flex-col items-start">
        <div class="bg-error-container p-4 rounded-xl rounded-tl-none shadow-sm border border-error/20 text-sm text-on-error-container">Error: ${escHtml(data.error)}</div>
        <span class="text-[10px] text-slate-400 mt-1 ml-1">AI</span>
      </div>`;
    } else {
      const sql = data.sql;
      aiMessages.push({ role: 'assistant', content: sql });
      const msgId = 'ai_' + Date.now();
      const t = new Date().toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' });
      chatEl.innerHTML += `<div class="flex flex-col items-start">
        <div class="max-w-[90%] bg-white p-5 rounded-xl rounded-tl-none shadow-md border-l-4 border-l-emerald-500 border-r border-t border-b border-slate-100">
          <p class="text-sm text-on-surface mb-3 font-medium">Here's the query:</p>
          <div class="code-bg rounded-lg p-4 mb-3 relative group">
            <pre class="text-jetbrains text-xs text-indigo-300 overflow-x-auto whitespace-pre-wrap break-all">${escHtml(sql)}</pre>
            <button class="absolute top-2 right-2 p-1.5 opacity-0 group-hover:opacity-100 transition-opacity bg-slate-800 rounded-md text-white" onclick="navigator.clipboard.writeText(window['_ai_sql_${msgId}']);showToast('Copied SQL')">
              <span class="material-symbols-outlined text-xs">content_copy</span>
            </button>
          </div>
          <div class="flex gap-2 mb-2">
            <button class="flex items-center gap-1.5 px-3 py-1.5 bg-primary/10 text-primary text-[11px] font-bold rounded-lg hover:bg-primary/20 transition-colors" onclick="runAiSql('${msgId}')">
              <span class="material-symbols-outlined text-sm ms-fill">play_circle</span>Run
            </button>
            <button class="flex items-center gap-1.5 px-3 py-1.5 text-slate-500 hover:text-on-surface text-[11px] font-bold transition-colors" onclick="copyToQueryRunner('${msgId}')">
              <span class="material-symbols-outlined text-sm">open_in_new</span>Open in Query Runner
            </button>
          </div>
          <div id="${msgId}_result"></div>
        </div>
        <span class="text-[10px] text-slate-400 mt-1 ml-1">AI · ${t}</span>
      </div>`;
      window['_ai_sql_' + msgId] = sql;
    }
  } catch(e) {
    document.getElementById('aiTyping')?.remove();
    chatEl.innerHTML += `<div class="flex flex-col items-start"><div class="bg-error-container p-4 rounded-xl text-sm text-on-error-container">Error: ${escHtml(e.message)}</div></div>`;
  }
  chatEl.scrollTop = chatEl.scrollHeight;
}

async function runAiSql(msgId) {
  const sql = window['_ai_sql_' + msgId];
  const resultEl = document.getElementById(msgId + '_result');
  if (!resultEl || !sql) return;
  resultEl.innerHTML = `<div class="text-xs text-on-surface-variant py-2">Running…</div>`;

  try {
    const data = await apiPost('/api/query', { sql, allowMutations: false });
    if (data.error) { resultEl.innerHTML = `<div class="bg-error-container text-on-error-container p-3 rounded-lg text-xs">${escHtml(data.error)}</div>`; return; }
    if (!data.rows.length) { resultEl.innerHTML = `<div class="text-xs text-on-surface-variant py-2">0 rows returned</div>`; return; }
    const cols = Object.keys(data.rows[0]);
    resultEl.innerHTML = `<div class="border rounded-lg overflow-hidden border-slate-200 mt-2">
      <div class="px-3 py-2 text-[10px] mono-text text-on-surface-variant bg-slate-50 border-b border-slate-100">${data.count} rows</div>
      <div class="overflow-x-auto max-h-72">
        <table class="w-full text-left text-[10px]">
          <thead class="bg-slate-50 sticky top-0"><tr>${cols.map(c => `<th class="px-2 py-1.5 mono-text font-bold">${escHtml(c)}</th>`).join('')}</tr></thead>
          <tbody>${data.rows.slice(0,100).map(r => `<tr class="border-t border-slate-50">${cols.map(c => `<td class="px-2 py-1 mono-text truncate max-w-[160px]" title="${escHtml(String(r[c]??''))}">${escHtml(String(r[c]??''))||'<span class="text-outline italic">null</span>'}</td>`).join('')}</tr>`).join('')}</tbody>
        </table>
      </div>
    </div>`;
    document.getElementById('chatMessages').scrollTop = document.getElementById('chatMessages').scrollHeight;
  } catch(e) { resultEl.innerHTML = `<div class="bg-error-container text-on-error-container p-3 rounded-lg text-xs">${escHtml(e.message)}</div>`; }
}

function copyToQueryRunner(msgId) {
  const sql = window['_ai_sql_' + msgId];
  navigate('query-runner');
  setTimeout(() => { const el = document.getElementById('qrSql'); if (el) el.value = sql; }, 100);
}
