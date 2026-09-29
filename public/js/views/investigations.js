// ═════════════════════════════════════════════════════════════════════════
// INVESTIGATIONS
// ═════════════════════════════════════════════════════════════════════════
// Notes are markdown files in the shared investigations folder (Claude Code
// reads the same files). The AI chat, placeholder mapping and redaction terms
// live server-side in .investigations-state/. The AI only ever sees scrubbed
// text; raw query rows are shown here and kept in memory for this session only.
let invList = null;       // { dir, items, playbooks, model }
let invCurrent = null;    // { file, content, title, status, chat, terms, mappingCount }
let invTab = 'ai';
let invBusy = false;
let invLastRows = {};     // chat index -> raw rows (this browser session only)
let invCodeJob = null;    // latest code-analysis job for the open investigation
let invCodeTimer = null;
let invDraft = '';        // composer text, kept if a send fails
let invPreview = null;    // { text, output, counts } awaiting "Send as shown"
function invPreviewOn() { try { return localStorage.getItem('inv_preview') !== 'off'; } catch (_) { return true; } }

function invEnv() { return document.getElementById('envBtn')?.dataset.env || 'dev'; }
function invIsProd() { return /^prod/.test(invEnv()); }

function invStatusPill(status) {
  const s = (status || '').toUpperCase();
  const cls = s.startsWith('OPEN') ? 'info' : s.startsWith('WAITING') ? 'warn' : s.startsWith('CLOSED') ? 'ok' : '';
  return `<span class="pill ${cls}">${escHtml(status || 'no status')}</span>`;
}

// Minimal markdown for AI replies: fenced code, inline code, bold, headings, bullets.
function invMd(text) {
  return String(text || '').split(/```[a-z]*\n?/i).map((part, i) => {
    if (i % 2 === 1) return `<pre class="code" style="white-space:pre-wrap;margin:6px 0">${escHtml(part.replace(/\n$/, ''))}</pre>`;
    return escHtml(part)
      .replace(/`([^`\n]+)`/g, '<code class="mono" style="background:var(--surface-2);padding:0 4px;border-radius:4px;font-size:12px">$1</code>')
      .replace(/\*\*([^*\n]+)\*\*/g, '<b>$1</b>')
      .replace(/^#{1,4}\s+(.+)$/gm, '<div style="font-weight:700;margin-top:6px">$1</div>')
      .replace(/^\s*(?:[-*]|\d+\.)\s+(.+)$/gm, '<div style="padding-left:16px;text-indent:-10px">• $1</div>')
      .replace(/<\/div>\n/g, '</div>')
      .replace(/\n{2,}/g, '<div style="height:8px"></div>')
      .replace(/\n/g, '<br>');
  }).join('');
}

function invRowsTable(rows) {
  if (!rows || !rows.length) return `<div style="font-size:12px;color:var(--ink-3);padding:6px 0">0 rows</div>`;
  const cols = Object.keys(rows[0]);
  const cell = v => {
    const s = v === null || v === undefined ? '' : (typeof v === 'object' ? JSON.stringify(v) : String(v));
    return `<td class="mono" style="font-size:11.5px;max-width:320px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${escHtml(s.slice(0, 2000))}">${s === '' ? '<span style="color:var(--ink-4)">null</span>' : escHtml(s.slice(0, 200))}</td>`;
  };
  return `<div style="overflow:auto;max-height:340px;border:1px solid var(--rule);border-radius:var(--r);margin-top:6px">
    <table class="lc-table"><thead><tr>${cols.map(c => `<th>${escHtml(c)}</th>`).join('')}</tr></thead>
    <tbody>${rows.map(r => `<tr>${cols.map(c => cell(r[c])).join('')}</tr>`).join('')}</tbody></table></div>`;
}

async function renderInvestigations(el) {
  el.innerHTML = `<div class="p-8 max-w-[1600px] mx-auto">
    ${pageHero('Investigations', {
      sub: 'Shared notes folder · the AI only sees scrubbed data · queries run read-only, and only when you click Run',
      actions: btnPrimary('New investigation', 'invNew()', { icon: 'add' }),
    })}
    <div style="display:grid;grid-template-columns:290px minmax(0,1fr);gap:var(--s-4);align-items:start">
      <div id="invSide">${loadingState()}</div>
      <div id="invMain"></div>
    </div>
  </div>`;
  try {
    invList = await apiFetch('/api/investigations');
  } catch (e) {
    document.getElementById('invSide').innerHTML = errorState(e.message);
    return;
  }
  const want = (invCurrent && invList.items.some(i => i.file === invCurrent.file)) ? invCurrent.file : invList.items[0]?.file;
  if (want) await invOpen(want);
  else {
    invRenderSide();
    document.getElementById('invMain').innerHTML = emptyState('No investigations yet — start one with "New investigation"', 'troubleshoot');
  }
}

function invRenderSide() {
  const el = document.getElementById('invSide');
  if (!el || !invList) return;
  const item = it => {
    const active = invCurrent && invCurrent.file === it.file;
    return `<div onclick="invOpen('${it.file}')" style="padding:10px 12px;border-bottom:1px solid var(--rule);cursor:pointer;${active ? 'background:var(--highlight)' : ''}">
      <div style="font-weight:600;font-size:13px;color:var(--ink);line-height:1.3">${escHtml(it.title || it.file)}</div>
      <div style="display:flex;gap:6px;align-items:center;margin-top:5px">
        <span class="mono" style="font-size:11px;color:var(--ink-3)">${escHtml(it.date)}</span>${invStatusPill((it.status || '').split(/[\s(]/)[0])}
      </div>
    </div>`;
  };
  el.innerHTML = `<div class="panel" style="overflow:hidden;margin-bottom:var(--s-4)">
      <div class="panel-header"><span class="panel-title"><span class="material-symbols-outlined">troubleshoot</span>Investigations <span class="count">${invList.items.length}</span></span></div>
      ${invList.items.map(item).join('') || '<div class="panel-body" style="font-size:12px;color:var(--ink-3)">None yet</div>'}
    </div>
    <div class="panel" style="overflow:hidden">
      <div class="panel-header"><span class="panel-title"><span class="material-symbols-outlined">menu_book</span>Playbooks</span></div>
      ${invList.playbooks.map(p => `<div onclick="invOpenPlaybook('${p.file}')" style="padding:9px 12px;border-bottom:1px solid var(--rule);cursor:pointer;font-size:12.5px">${escHtml(p.title)}</div>`).join('') || '<div class="panel-body" style="font-size:12px;color:var(--ink-3)">None</div>'}
      <div style="padding:8px 12px;font-size:11px;color:var(--ink-3)" class="mono">${escHtml(invList.dir)}</div>
    </div>`;
}

async function invOpen(file) {
  try {
    invCurrent = await apiFetch(`/api/investigations/${file}`);
    invLastRows = {};
    invDraft = '';
    invCodeJob = (await apiFetch(`/api/investigations/${file}/code`)).job;
    if (invCodeJob && invCodeJob.status === 'running') invWatchCode();
    invRenderSide();
    invRenderMain();
  } catch (e) { document.getElementById('invMain').innerHTML = errorState(e.message); }
}

async function invReload() {
  const keep = invLastRows;
  invCurrent = await apiFetch(`/api/investigations/${invCurrent.file}`);
  invLastRows = keep;
}

async function invOpenPlaybook(file) {
  const main = document.getElementById('invMain');
  try {
    const pb = await apiFetch(`/api/investigations/playbooks/${file}`);
    main.innerHTML = `<div class="panel"><div class="panel-header"><span class="panel-title"><span class="material-symbols-outlined">menu_book</span>${escHtml(file)}</span>
      ${invCurrent ? btnGhost('Back to investigation', 'invRenderMain()', { icon: 'arrow_back' }) : ''}</div>
      <div class="panel-body"><pre class="code" style="white-space:pre-wrap;max-height:75vh;overflow:auto">${escHtml(pb.content)}</pre>
      <div style="font-size:12px;color:var(--ink-3);margin-top:8px">The AI reads every playbook as context. Edit the file in the investigations folder to improve it.</div></div></div>`;
  } catch (e) { main.innerHTML = errorState(e.message); }
}

async function invNew() {
  const title = (prompt('Investigation title (no patient names):') || '').trim();
  if (!title) return;
  try {
    const { file } = await apiPost('/api/investigations', { title });
    invList = await apiFetch('/api/investigations');
    invTab = 'ai';
    await invOpen(file);
  } catch (e) { showToast(e.message, 'err'); }
}

function invSetTab(tab) { invTab = tab; invRenderMain(); }

function invRenderMain() {
  const main = document.getElementById('invMain');
  if (!main || !invCurrent) return;
  const env = invEnv();
  const envPill = invIsProd()
    ? `<span class="pill plate-err">PRODUCTION · read-only</span>`
    : `<span class="pill ghost">${escHtml(env)} · read-only</span>`;
  const tab = (key, label, icon, count) => `<button class="lc-tab ${invTab === key ? 'active' : ''}" onclick="invSetTab('${key}')"><span class="material-symbols-outlined" style="font-size:16px">${icon}</span>${label}${count !== undefined ? ` <span class="count">${count}</span>` : ''}</button>`;
  main.innerHTML = `<div class="panel" style="margin-bottom:var(--s-4)">
      <div class="panel-body" style="display:flex;justify-content:space-between;gap:12px;align-items:flex-start">
        <div style="min-width:0">
          <div style="font:700 17px/1.3 var(--font-sign);color:var(--ink)">${escHtml(invCurrent.title || invCurrent.file)}</div>
          <div style="display:flex;gap:8px;align-items:center;margin-top:6px;flex-wrap:wrap">${invStatusPill(invCurrent.status)}<span class="mono" style="font-size:11px;color:var(--ink-3)">${escHtml(invCurrent.file)}</span></div>
        </div>
        <div style="display:flex;gap:6px;align-items:center;flex-shrink:0">${envPill}</div>
      </div>
      <div class="lc-tabs" style="padding:0 var(--panel-pad)">
        ${tab('ai', 'AI investigation', 'forum', (invCurrent.chat || []).length)}
        ${tab('code', 'Code analysis', 'code_blocks')}
        ${tab('notes', 'Notes', 'description')}
        ${tab('redaction', 'Redaction', 'shield_lock', invCurrent.mappingCount)}
      </div>
    </div>
    <div id="invTabBody">${invTab === 'notes' ? invRenderNotes() : invTab === 'redaction' ? invRenderRedaction() : invTab === 'code' ? invRenderCode() : invRenderChat()}</div>`;
  if (invTab === 'ai') {
    const chat = document.getElementById('invChat');
    if (chat) chat.scrollTop = chat.scrollHeight;
    document.getElementById('invInput')?.addEventListener('keydown', e => {
      if ((e.metaKey || e.ctrlKey) && e.key === 'Enter') { e.preventDefault(); invAsk(false); }
    });
  }
}

// ── AI tab ────────────────────────────────────────────────────────────────
function invRenderTurn(t, i, isLast) {
  const time = t.at ? new Date(t.at).toLocaleString('de-DE', { timeZone: 'Europe/Berlin', day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit' }) : '';
  const meta = label => `<div style="font-size:10.5px;color:var(--ink-3);margin:0 4px 3px">${label} · ${escHtml(time)}</div>`;
  if (t.role === 'user' && t.kind === 'query') {
    const raw = invLastRows[i];
    return `<div>${meta(`Query on ${escHtml(t.env || '?')}`)}
      <div class="panel panel-2" style="padding:10px 12px">
        <pre class="code" style="white-space:pre-wrap;margin:0">${escHtml(t.sql || '')}</pre>
        ${raw ? invRowsTable(raw) : ''}
        <details style="margin-top:6px"><summary style="font-size:12px;color:var(--ink-3);cursor:pointer">What the AI saw (scrubbed)</summary>
          <pre class="code" style="white-space:pre-wrap;max-height:300px;overflow:auto;margin-top:6px">${escHtml(t.text)}</pre></details>
      </div></div>`;
  }
  if (t.role === 'user' && t.kind === 'correspondence') {
    return `<div>${meta('Correspondence (scrubbed)')}
      <div class="panel" style="padding:10px 12px;border-left:3px solid var(--blue);font-size:12.5px;white-space:pre-wrap;word-break:break-word">${escHtml(t.text)}</div></div>`;
  }
  if (t.role === 'user') {
    return `<div style="align-self:flex-end;max-width:85%">${meta('You (scrubbed)')}
      <div style="background:var(--highlight);border-radius:var(--r);padding:10px 12px;font-size:13px;white-space:pre-wrap;word-break:break-word">${escHtml(t.text)}</div></div>`;
  }
  let proposal = '';
  if (t.proposedSql) {
    proposal = isLast && !invBusy
      ? `<div class="panel" style="margin-top:10px;padding:10px 12px;border-color:var(--action)">
          <div style="font-size:12px;font-weight:600;color:var(--ink-2);margin-bottom:6px">Proposed query${t.purpose ? ` — ${escHtml(t.purpose)}` : ''}</div>
          <textarea id="invSql-${i}" class="lc-textarea" rows="${Math.min(14, t.proposedSql.split('\n').length + 1)}" spellcheck="false">${escHtml(t.proposedSql)}</textarea>
          <div style="display:flex;gap:6px;margin-top:8px;align-items:center">
            <button class="btn ${invIsProd() ? 'btn-danger' : 'btn-primary'} btn-sm" onclick="invRunSql(document.getElementById('invSql-${i}').value)"><span class="material-symbols-outlined">play_arrow</span>Run read-only on ${escHtml(invEnv())}</button>
            <span style="font-size:11.5px;color:var(--ink-3)">You can edit it first. Placeholders like [EMAIL_1] are filled in locally; results are scrubbed before the AI sees them.</span>
          </div></div>`
      : `<pre class="code" style="white-space:pre-wrap;margin-top:8px">${escHtml(t.proposedSql)}</pre>`;
  }
  const log = t.logEntry
    ? `<div style="margin-top:8px;padding:8px 10px;border-left:3px solid var(--green);background:var(--green-soft);border-radius:4px;font-size:12.5px;display:flex;gap:8px;align-items:center;justify-content:space-between">
        <span><b>Finding:</b> ${escHtml(t.logEntry)}</span>
        <button class="btn btn-sm" onclick="invAddLog(${i})"><span class="material-symbols-outlined">note_add</span>Add to log</button></div>`
    : '';
  return `<div style="max-width:92%">${meta('AI')}
    <div class="panel" style="padding:10px 12px;font-size:13px;line-height:1.5">${invMd(t.text)}${proposal}${log}</div></div>`;
}

function invRenderChat() {
  const chat = invCurrent.chat || [];
  const turns = chat.map((t, i) => invRenderTurn(t, i, i === chat.length - 1)).join('');
  const intro = `<div class="empty" style="padding:28px"><div class="empty-icon"><span class="material-symbols-outlined">forum</span></div>
    <div class="empty-sub" style="max-width:520px">Describe the problem, e.g. <i>"app_user_info.id 6524 got a booking confirmation at 06:42 UTC on 25.09. for an appointment they say they never booked"</i>, or paste logs. Everything is scrubbed before the AI sees it. The AI proposes queries; nothing runs until you click Run.</div></div>`;
  return `<div class="panel" style="overflow:hidden">
    <div id="invChat" style="max-height:62vh;min-height:220px;overflow-y:auto;padding:var(--panel-pad);display:flex;flex-direction:column;gap:14px">
      ${turns || intro}
      ${invBusy ? `<div style="font-size:12.5px;color:var(--ink-3);display:flex;gap:6px;align-items:center"><span class="material-symbols-outlined spin" style="font-size:16px">progress_activity</span>${escHtml(invBusy)}</div>` : ''}
      <div id="invManual"></div>
    </div>
    <div style="border-top:1px solid var(--rule);padding:var(--panel-pad)">
      <div style="display:flex;gap:6px;align-items:center;margin-bottom:6px">
        <select id="invKind" class="lc-select" style="width:auto;height:28px;font-size:12px" onchange="document.getElementById('invParty').style.display=this.value==='message'?'none':'block'" ${invBusy ? 'disabled' : ''}>
          <option value="message">Message / logs</option>
          <option value="received">Reply received from…</option>
          <option value="sent">Email sent to…</option>
        </select>
        <input id="invParty" class="lc-input" value="Siegele" style="display:none;width:160px;height:28px;font-size:12px" placeholder="Siegele, practice, …">
      </div>
      <textarea id="invInput" class="lc-textarea" rows="4" placeholder="Question, context, pasted logs or a vendor reply… (Cmd+Enter to send)" ${invBusy ? 'disabled' : ''}>${escHtml(invDraft)}</textarea>
      ${!chat.length && !/^## Code analysis/m.test(invCurrent.content) ? `<label style="display:flex;gap:6px;align-items:center;font-size:12px;color:var(--ink-2);margin-top:6px;cursor:pointer">
        <input type="checkbox" id="invCodeFirst" checked> Analyze the codebase first (read-only Claude Code session on LillianCare-Core, ~1–3 min)</label>` : ''}
      ${invPreview ? `<div class="panel" style="margin-top:8px;padding:10px 12px;border-color:var(--yellow)">
        <div style="font-size:12px;font-weight:600;color:var(--ink-2);margin-bottom:6px">This is what will be sent and stored. Check for names the scrubber missed; add them in the Redaction tab if needed.</div>
        <pre class="code" style="white-space:pre-wrap;max-height:260px;overflow:auto;margin:0">${escHtml(invPreview.output).replace(/\[[A-Z_]+(?:_\d+)?(?: [^\]]*)?\]/g, m => `<span style="background:var(--yellow-soft);border-radius:3px;padding:0 2px">${m}</span>`)}</pre>
        <div style="display:flex;gap:6px;margin-top:8px">
          <button class="btn btn-primary btn-sm" onclick="invAsk(false, true)"><span class="material-symbols-outlined">send</span>Send as shown</button>
          <button class="btn btn-sm btn-ghost" onclick="invPreview=null;invRenderMain()">Edit</button>
        </div></div>` : ''}
      <div style="display:flex;justify-content:space-between;align-items:center;margin-top:8px;gap:8px;flex-wrap:wrap">
        <label style="font-size:11.5px;color:var(--ink-3);display:flex;gap:6px;align-items:center;cursor:pointer"><input type="checkbox" ${invPreviewOn() ? 'checked' : ''} onchange="try{localStorage.setItem('inv_preview', this.checked ? 'on' : 'off')}catch(_){}"> Preview scrubbed text before sending · ${escHtml(invList?.model || '')}</label>
        <div style="display:flex;gap:6px">
          <button class="btn btn-sm" onclick="invManualQuery()" ${invBusy ? 'disabled' : ''}><span class="material-symbols-outlined">database</span>Write a query</button>
          ${chat.length ? `<button class="btn btn-sm" onclick="invAsk(true)" ${invBusy ? 'disabled' : ''}><span class="material-symbols-outlined">redo</span>Ask AI for next step</button>` : ''}
          ${chat.length ? `<button class="btn btn-sm btn-ghost" onclick="invClearChat()" ${invBusy ? 'disabled' : ''} title="Clear the AI conversation (notes and mapping stay)"><span class="material-symbols-outlined">delete_sweep</span></button>` : ''}
          <button class="btn btn-primary btn-sm" onclick="invAsk(false)" ${invBusy ? 'disabled' : ''}><span class="material-symbols-outlined">send</span>Send</button>
        </div>
      </div>
    </div>
  </div>`;
}

function invManualQuery() {
  const el = document.getElementById('invManual');
  if (!el) return;
  el.innerHTML = `<div class="panel" style="padding:10px 12px;border-color:var(--action)">
    <div style="font-size:12px;font-weight:600;color:var(--ink-2);margin-bottom:6px">Your query (runs read-only, max 200 rows)</div>
    <textarea id="invSql-manual" class="lc-textarea" rows="6" spellcheck="false" placeholder="SELECT …"></textarea>
    <div style="display:flex;gap:6px;margin-top:8px">
      <button class="btn ${invIsProd() ? 'btn-danger' : 'btn-primary'} btn-sm" onclick="invRunSql(document.getElementById('invSql-manual').value)"><span class="material-symbols-outlined">play_arrow</span>Run read-only on ${escHtml(invEnv())}</button>
      <button class="btn btn-sm btn-ghost" onclick="document.getElementById('invManual').innerHTML=''">Cancel</button>
    </div></div>`;
  document.getElementById('invSql-manual').focus();
}

async function invWithBusy(label, fn) {
  invBusy = label;
  invRenderMain();
  try { await fn(); }
  catch (e) { showToast(e.message, 'err'); }
  finally {
    invBusy = false;
    try { await invReload(); } catch (_) {}
    invRenderMain();
  }
}

async function invRunSql(sql) {
  if (!sql || !sql.trim() || invBusy) return;
  await invWithBusy(`Running read-only on ${invEnv()}…`, async () => {
    const res = await apiPost(`/api/investigations/${invCurrent.file}/query`, { sql });
    await invReload();
    const idx = invCurrent.chat.length - 1;
    if (res.rows) invLastRows[idx] = res.rows;
    if (res.error) { showToast(`Query failed: ${res.error}`, 'err'); }
    else if (res.filledPlaceholders) { showToast(`${res.filledPlaceholders} placeholder(s) filled in locally before running`); }
    invBusy = 'AI is analysing the result…';
    invRenderMain();
    await apiPost(`/api/investigations/${invCurrent.file}/ai`, {});
  });
}

function invScrubToast(counts) {
  const parts = Object.entries(counts || {}).map(([k, v]) => `${k.toLowerCase()} ${v}`);
  if (parts.length) showToast(`Scrubbed before sending: ${parts.join(' · ')}`);
}

async function invAsk(continueOnly, confirmed) {
  if (invBusy) return;
  const text = continueOnly ? '' : (confirmed && invPreview ? invPreview.text : (document.getElementById('invInput')?.value || '').trim());
  if (!continueOnly && !text) return;
  const kind = continueOnly ? 'message' : (confirmed && invPreview ? invPreview.kind : (document.getElementById('invKind')?.value || 'message'));
  const party = (confirmed && invPreview ? invPreview.party : (document.getElementById('invParty')?.value || '').trim()) || 'vendor';
  const codeFirst = confirmed && invPreview ? invPreview.codeFirst : (kind === 'message' && !!document.getElementById('invCodeFirst')?.checked);
  invDraft = text;
  if (!continueOnly && !confirmed && invPreviewOn()) {
    try {
      const prev = await apiPost(`/api/investigations/${invCurrent.file}/scrub-preview`, { text });
      invPreview = { text, kind, party, codeFirst, output: prev.output, counts: prev.counts };
      invRenderMain();
    } catch (e) { showToast(e.message, 'err'); }
    return;
  }
  invPreview = null;
  const file = invCurrent.file;
  await invWithBusy(codeFirst ? 'Starting code analysis…' : 'AI is thinking…', async () => {
    if (codeFirst) {
      await apiPost(`/api/investigations/${file}/code`, { question: text });
      await invAwaitCode();
      if (!invCodeJob || invCodeJob.status !== 'done') showToast(`Code analysis ${invCodeJob?.status || 'failed'}; continuing without it`, 'err');
      invBusy = 'AI is thinking…';
      invRenderMain();
    }
    if (kind === 'message') {
      invScrubToast((await apiPost(`/api/investigations/${file}/ai`, { text })).counts);
    } else {
      invScrubToast((await apiPost(`/api/investigations/${file}/correspondence`, { direction: kind, party, text })).counts);
      invBusy = 'AI is reading the correspondence…';
      invRenderMain();
      await apiPost(`/api/investigations/${file}/ai`, {});
    }
    invDraft = '';
  });
}

// ── Code analysis tab ─────────────────────────────────────────────────────
function invCodeSectionMd() {
  const md = invCurrent?.content || '';
  const m = md.match(/^## Code analysis\s*$/m);
  if (!m) return '';
  const rest = md.slice(m.index + m[0].length);
  const next = rest.search(/^## /m);
  return (next < 0 ? rest : rest.slice(0, next)).trim();
}

function invCodeStatusHtml() {
  const job = invCodeJob;
  if (!job) return '';
  const tail = (job.log || []).slice(-8).map(l => escHtml(l)).join('<br>');
  if (job.status === 'running') {
    return `<div class="panel panel-2" style="padding:10px 12px;margin-bottom:var(--s-4)">
      <div style="display:flex;justify-content:space-between;align-items:center">
        <span style="font-size:12.5px;font-weight:600;display:flex;gap:6px;align-items:center"><span class="material-symbols-outlined spin" style="font-size:16px">progress_activity</span>Claude Code is reading the codebase…</span>
        <button class="btn btn-sm btn-ghost" onclick="invCancelCode()">Cancel</button></div>
      <div class="mono" style="font-size:11.5px;color:var(--ink-3);margin-top:6px">${tail || 'starting…'}</div></div>`;
  }
  if (job.status === 'failed') return `<div class="panel" style="padding:10px 12px;margin-bottom:var(--s-4);border-color:var(--red);font-size:12.5px"><b>Code analysis failed:</b> ${escHtml(job.error || '')}</div>`;
  if (job.status === 'cancelled') return `<div class="panel" style="padding:10px 12px;margin-bottom:var(--s-4);font-size:12.5px">Code analysis cancelled.</div>`;
  return `<div style="font-size:11.5px;color:var(--ink-3);margin-bottom:8px">Last analysis finished${job.costUsd != null ? ` · $${Number(job.costUsd).toFixed(2)}` : ''} · ${(job.log || []).length} file lookups</div>`;
}

function invRenderCode() {
  const running = invCodeJob && invCodeJob.status === 'running';
  const section = invCodeSectionMd();
  return `<div id="invCodeStatus">${invCodeStatusHtml()}</div>
    <div class="panel" style="margin-bottom:var(--s-4)"><div class="panel-body">
      <div class="field-label" style="margin-bottom:6px">Ask the codebase</div>
      <textarea id="invCodeQ" class="lc-textarea" rows="3" placeholder="e.g. Why would only one email go out when two appointments go from cancelled to booked within 2 seconds? (empty = general analysis of the problem in the notes)"></textarea>
      <div style="display:flex;justify-content:space-between;align-items:center;margin-top:8px;gap:8px">
        <span style="font-size:11.5px;color:var(--ink-3)">Runs a local Claude Code session on LillianCare-Core: read-only file tools, secrets blocked, only scrubbed notes in the prompt. The result is added to the notes and used by the AI chat.</span>
        <button class="btn btn-primary btn-sm" onclick="invStartCode()" ${running ? 'disabled' : ''}><span class="material-symbols-outlined">code_blocks</span>Analyze codebase</button>
      </div></div></div>
    <div class="panel"><div class="panel-header"><span class="panel-title"><span class="material-symbols-outlined">description</span>Code analysis in notes</span></div>
      <div class="panel-body" style="font-size:13px;line-height:1.55">${section ? invMd(section) : '<span style="color:var(--ink-3)">No code analysis yet.</span>'}</div></div>`;
}

async function invStartCode() {
  const question = (document.getElementById('invCodeQ')?.value || '').trim();
  try {
    await apiPost(`/api/investigations/${invCurrent.file}/code`, { question });
    invCodeJob = (await apiFetch(`/api/investigations/${invCurrent.file}/code`)).job;
    invRenderMain();
    invWatchCode();
  } catch (e) { showToast(e.message, 'err'); }
}

async function invCancelCode() {
  try { await fetch(`/api/investigations/${invCurrent.file}/code`, { method: 'DELETE', headers: dbHeaders() }); }
  catch (e) { showToast(e.message, 'err'); }
}

// Polls the code job; resolves when it is no longer running. Updates the status
// box (Code tab) or the busy line (chat) without touching the composer.
function invAwaitCode() {
  const file = invCurrent.file;
  return new Promise(resolve => {
    const tick = async () => {
      try {
        invCodeJob = (await apiFetch(`/api/investigations/${file}/code`)).job;
      } catch (_) { /* transient */ }
      if (!invCurrent || invCurrent.file !== file) return resolve();
      const running = invCodeJob && invCodeJob.status === 'running';
      if (invBusy) {
        const last = (invCodeJob?.log || []).slice(-1)[0];
        invBusy = `Analyzing the codebase… ${last ? `(${last})` : ''}`;
        invRenderMain();
      } else if (invTab === 'code') {
        const el = document.getElementById('invCodeStatus');
        if (el) el.innerHTML = invCodeStatusHtml();
      }
      if (running) { invCodeTimer = setTimeout(tick, 2000); return; }
      try { await invReload(); } catch (_) {}
      if (!invBusy) {
        invRenderMain();
        if (invCodeJob?.status === 'done') showToast('Code analysis added to the notes', 'ok');
      }
      resolve();
    };
    clearTimeout(invCodeTimer);
    invCodeTimer = setTimeout(tick, 1500);
  });
}

function invWatchCode() { invAwaitCode(); }

async function invClearChat() {
  if (!confirm('Clear the AI conversation for this investigation? Notes and redaction mapping are kept.')) return;
  try {
    await fetch(`/api/investigations/${invCurrent.file}/chat`, { method: 'DELETE', headers: dbHeaders() });
    invLastRows = {};
    await invReload();
    invRenderMain();
  } catch (e) { showToast(e.message, 'err'); }
}

async function invAddLog(i) {
  const turn = invCurrent.chat[i];
  if (!turn || !turn.logEntry) return;
  try {
    const res = await apiPost(`/api/investigations/${invCurrent.file}/log`, { entry: turn.logEntry });
    invCurrent.content = res.content;
    showToast('Added to the investigation log', 'ok');
  } catch (e) { showToast(e.message, 'err'); }
}

// ── Notes tab ─────────────────────────────────────────────────────────────
function invRenderNotes() {
  const btn = s => `<button class="btn btn-sm" onclick="invSetStatus('${s}')">${s}</button>`;
  return `<div class="panel"><div class="panel-body">
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;gap:8px;flex-wrap:wrap">
      <div style="display:flex;gap:6px;align-items:center"><span style="font-size:12px;color:var(--ink-3)">Set status:</span>${btn('OPEN')}${btn('WAITING')}${btn('CLOSED')}</div>
      ${btnPrimary('Save notes', 'invSaveNotes()', { icon: 'save' })}
    </div>
    <textarea id="invNotes" class="lc-textarea" style="min-height:60vh;font-size:12.5px;line-height:1.55" spellcheck="false">${escHtml(invCurrent.content)}</textarea>
    <div style="font-size:11.5px;color:var(--ink-3);margin-top:6px">Markdown file in the shared folder: no patient names, emails or other PII, only internal IDs.</div>
  </div></div>`;
}

async function invSaveNotes(content) {
  const text = content !== undefined ? content : document.getElementById('invNotes')?.value;
  if (!text) return;
  try {
    await apiPutJson(`/api/investigations/${invCurrent.file}`, { content: text });
    invCurrent.content = text;
    invList = await apiFetch('/api/investigations');
    await invReload();
    invRenderSide();
    invRenderMain();
    showToast('Notes saved', 'ok');
  } catch (e) { showToast(e.message, 'err'); }
}

function invSetStatus(status) {
  const el = document.getElementById('invNotes');
  let text = el ? el.value : invCurrent.content;
  const suffix = status === 'WAITING' ? ` (on ${prompt('Waiting on whom?') || '?'})` : '';
  const line = `**Status:** ${status}${suffix}`;
  text = /^\*\*Status:\*\*.*$/m.test(text) ? text.replace(/^\*\*Status:\*\*.*$/m, line) : text.replace(/^(#.*\n)/, `$1\n${line}\n`);
  invSaveNotes(text);
}

async function apiPutJson(path, body) {
  const res = await fetch(path, { method: 'PUT', headers: dbHeaders(), body: JSON.stringify(body) });
  return handleJsonResponse(res, path);
}

// ── Redaction tab ─────────────────────────────────────────────────────────
function invRenderRedaction() {
  return `<div class="panel" style="margin-bottom:var(--s-4)"><div class="panel-body">
      <div class="field-label" style="margin-bottom:6px">Extra terms to redact (one per line: patient names, staff logins, …)</div>
      <textarea id="invTerms" class="lc-textarea" rows="5" spellcheck="false">${escHtml((invCurrent.terms || []).join('\n'))}</textarea>
      <div style="display:flex;justify-content:space-between;align-items:center;margin-top:8px">
        <span style="font-size:11.5px;color:var(--ink-3)">Applied to everything sent to the AI from now on. Stored locally in helper/.investigations-state (gitignored).</span>
        ${btnPrimary('Save terms', 'invSaveTerms()', { icon: 'save' })}
      </div>
    </div></div>
    <div class="panel"><div class="panel-header"><span class="panel-title"><span class="material-symbols-outlined">key</span>Placeholder mapping <span class="count">${invCurrent.mappingCount}</span></span>
      ${btnGhost('Reveal (local only)', 'invShowMapping()', { icon: 'visibility' })}</div>
      <div id="invMapping" class="panel-body" style="font-size:12px;color:var(--ink-3)">Shows which real value each placeholder stands for. Never paste this anywhere.</div></div>`;
}

async function invSaveTerms() {
  const terms = (document.getElementById('invTerms')?.value || '').split('\n');
  try {
    const res = await apiPutJson(`/api/investigations/${invCurrent.file}/terms`, { terms });
    invCurrent.terms = res.terms;
    showToast(`${res.terms.length} term(s) saved`, 'ok');
  } catch (e) { showToast(e.message, 'err'); }
}

async function invShowMapping() {
  try {
    const { mapping } = await apiFetch(`/api/investigations/${invCurrent.file}/mapping`);
    document.getElementById('invMapping').innerHTML = mapping.length
      ? `<table class="lc-table"><thead><tr><th>Placeholder</th><th>Original</th></tr></thead><tbody>${mapping.map(([t, o]) => `<tr><td class="mono">${escHtml(t)}</td><td class="mono">${escHtml(o)}</td></tr>`).join('')}</tbody></table>`
      : 'Nothing has been redacted yet.';
  } catch (e) { showToast(e.message, 'err'); }
}
