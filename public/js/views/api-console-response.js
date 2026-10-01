// API console — response: status line, Body / Headers / Console (trace) / Request.

function acRenderResponse() {
  const el = document.getElementById('acResp');
  if (!el) return;
  const r = acState.resp;
  if (!r) {
    el.innerHTML = `<div class="empty" style="margin:auto"><div class="empty-icon"><span class="material-symbols-outlined">send</span></div>
      <div class="empty-title">Pick a request on the left, then Send</div>
      <div class="empty-sub">⌘↵ sends · Responses stay in this window only; they are never saved.</div></div>`;
    return;
  }
  if (r.pending) {
    el.innerHTML = `<div class="empty" style="margin:auto"><div class="empty-icon"><span class="material-symbols-outlined spin">progress_activity</span></div><div class="empty-sub">Waiting for the response…</div></div>`;
    return;
  }
  const hasResponse = r.status != null;
  const tabs = hasResponse
    ? [['body', 'Body'], ['headers', `Headers <span class="pill">${r.headers.length}</span>`], ['console', 'Console'], ['request', 'Request']]
    : [['console', 'Console']];
  if (!tabs.some(([k]) => k === acState.respTab)) acState.respTab = tabs[0][0];
  const cls = !hasResponse ? 'err' : r.status >= 500 ? 'err' : r.status >= 400 ? 'err' : r.status >= 300 ? 'warn' : 'ok';
  el.innerHTML = `
    <div class="ac-resp-head">
      <span class="pill ${cls}" style="height:24px;font-size:12px">${hasResponse ? `${r.status} ${escHtml(r.statusText || '')}` : r.networkError ? 'No response' : 'Not sent'}</span>
      ${hasResponse ? `<span class="stat"><b>${Math.round(r.timings.total)}</b> ms</span>
        <span class="stat"><b>${acBytes(r.size)}</b>${r.decodedSize !== r.size ? ` (${acBytes(r.decodedSize)} decoded)` : ''}</span>
        <span class="stat">${escHtml((r.contentType || '').split(';')[0] || 'no content-type')}</span>
        ${r.hops && r.hops.length > 1 ? `<span class="stat">${r.hops.length - 1} redirect${r.hops.length > 2 ? 's' : ''}</span>` : ''}` : ''}
      <span style="flex:1"></span>
      ${hasResponse && r.bodyText != null ? `<button class="btn btn-sm" onclick="acCopyBody()"><span class="material-symbols-outlined">content_copy</span>Copy</button>` : ''}
      ${r.downloadId ? `<a class="btn btn-sm" href="/api/console/download/${r.downloadId}"><span class="material-symbols-outlined">download</span>Save response</a>` : ''}
    </div>
    <div class="lc-tabs">${tabs.map(([k, l]) => `<button class="lc-tab ${acState.respTab === k ? 'active' : ''}" onclick="acRespTab('${k}')">${l}</button>`).join('')}</div>
    <div class="ac-resp-tools" id="acRespTools"></div>
    <div class="ac-resp-body" id="acRespBody"></div>`;
  acRenderRespTools();
  acRenderRespContent();
}

function acRespTab(tab) {
  acState.respTab = tab;
  acRenderResponse();
}

function acBytes(n) {
  if (n == null) return '—';
  return n < 1024 ? `${n} B` : n < 1048576 ? `${(n / 1024).toFixed(1)} KB` : `${(n / 1048576).toFixed(2)} MB`;
}

// Parsed once per response; the search re-renders often.
function acRespJson(r) {
  if (r._json === undefined) {
    r._json = null;
    const ct = (r.contentType || '').toLowerCase();
    if (r.bodyText && (/json/.test(ct) || /^\s*[[{]/.test(r.bodyText))) { try { r._json = JSON.parse(r.bodyText); } catch { /* not JSON */ } }
  }
  return r._json;
}

const acSearchable = () => ['body', 'headers'].includes(acState.respTab) && acState.resp && acState.resp.status != null
  && (acState.respTab === 'headers' || acState.resp.bodyText);

// Toolbar above the pane: Pretty/Raw (JSON bodies) and the search box (Body, Headers).
// Rendered separately from the content so typing never loses focus.
function acRenderRespTools() {
  const el = document.getElementById('acRespTools');
  if (!el) return;
  const r = acState.resp;
  const isJson = acState.respTab === 'body' && acRespJson(r) !== null;
  if (!acSearchable() && !isJson) { el.innerHTML = ''; el.style.display = 'none'; return; }
  el.style.display = '';
  el.innerHTML = `
    ${isJson ? `<div class="ac-seg">
      <button class="${acState.pretty ? 'active' : ''}" onclick="acState.pretty=true;acRenderResponse()">Pretty</button>
      <button class="${!acState.pretty ? 'active' : ''}" onclick="acState.pretty=false;acRenderResponse()">Raw</button></div>` : ''}
    ${acSearchable() ? `<div class="ac-search">
      <span class="material-symbols-outlined">search</span>
      <input id="acRespSearch" value="${escHtml(acState.respQuery)}" spellcheck="false" autocomplete="off"
        placeholder="Search ${acState.respTab === 'headers' ? 'headers' : 'body'}  ⌘F" oninput="acRespSearchInput(this.value)" onkeydown="acRespSearchKey(event)">
      <span class="ac-search-count" id="acRespCount"></span>
      <button class="lc-icon-btn" onclick="acRespHitStep(-1)" title="Previous (⇧↵)"><span class="material-symbols-outlined">keyboard_arrow_up</span></button>
      <button class="lc-icon-btn" onclick="acRespHitStep(1)" title="Next (↵)"><span class="material-symbols-outlined">keyboard_arrow_down</span></button>
    </div>` : ''}
    ${acState.respTab === 'body' && r.truncated ? '<span class="pill warn">truncated at 5 MB — Save response for all of it</span>' : ''}`;
}

function acRenderRespContent() {
  const el = document.getElementById('acRespBody');
  if (!el) return;
  el.innerHTML = acRespPaneHtml();
  acApplyRespSearch();
}

let acSearchTimer = null;
function acRespSearchInput(v) {
  acState.respQuery = v;
  acState.respHit = 0;
  clearTimeout(acSearchTimer);
  // Large bodies: wait for a pause in typing.
  acSearchTimer = setTimeout(acRenderRespContent, (acState.resp.bodyText || '').length > 200000 ? 250 : 60);
}

function acRespSearchKey(e) {
  if (e.key === 'Enter') { e.preventDefault(); acRespHitStep(e.shiftKey ? -1 : 1); }
  else if (e.key === 'Escape') { e.stopPropagation(); e.target.value = ''; acRespSearchInput(''); }
}

function acRespHitStep(d) {
  if (!acState.respHits) return;
  acState.respHit = (acState.respHit + d + acState.respHits) % acState.respHits;
  acShowCurrentHit();
}

const AC_MAX_HITS = 2000;

// Highlights every case-insensitive match of the query inside `root`, also when a
// match spans several text nodes (e.g. across JSON syntax colours). Returns the count.
function acMarkMatches(root, query) {
  const needle = query.toLowerCase();
  const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
  const nodes = [];
  let text = '';
  for (let n = walker.nextNode(); n; n = walker.nextNode()) {
    nodes.push({ n, start: text.length, len: n.nodeValue.length });
    text += n.nodeValue;
  }
  const hay = text.toLowerCase();
  const hits = [];
  for (let i = hay.indexOf(needle); i !== -1 && hits.length < AC_MAX_HITS; i = hay.indexOf(needle, i + needle.length)) hits.push(i);
  // Wrap from the last match backwards: splitting a text node only shortens it,
  // so the offsets recorded for earlier matches stay valid.
  let k = nodes.length - 1;
  for (let h = hits.length - 1; h >= 0; h--) {
    const s = hits[h], e = s + needle.length;
    while (k > 0 && nodes[k].start >= e) k--;
    for (let j = k; j >= 0 && nodes[j].start + nodes[j].len > s; j--) {
      const { n, start, len } = nodes[j];
      const a = Math.max(s - start, 0), b = Math.min(e - start, len);
      if (a >= b) continue;
      const range = document.createRange();
      range.setStart(n, a);
      range.setEnd(n, b);
      const mark = document.createElement('mark');
      mark.className = 'ac-hit';
      mark.dataset.hit = h;
      range.surroundContents(mark);
    }
  }
  return hits.length;
}

function acApplyRespSearch() {
  const count = document.getElementById('acRespCount');
  const root = document.getElementById('acRespBody');
  acState.respHits = 0;
  if (!acSearchable() || !root) return;
  const q = acState.respQuery.trim() ? acState.respQuery : '';
  if (q && acState.respTab === 'headers') {
    const needle = q.toLowerCase();
    root.querySelectorAll('tr').forEach(tr => { tr.style.display = tr.textContent.toLowerCase().includes(needle) ? '' : 'none'; });
  }
  if (q) acState.respHits = acMarkMatches(root, q);
  if (count) {
    count.textContent = !q ? '' : acState.respHits ? `${Math.min(acState.respHit, acState.respHits - 1) + 1} / ${acState.respHits}${acState.respHits >= AC_MAX_HITS ? '+' : ''}` : 'No matches';
    count.classList.toggle('none', !!q && !acState.respHits);
  }
  if (acState.respHits) acShowCurrentHit();
}

function acShowCurrentHit() {
  const root = document.getElementById('acRespBody');
  if (!root) return;
  acState.respHit = Math.min(acState.respHit, acState.respHits - 1);
  root.querySelectorAll('mark.ac-hit.cur').forEach(m => m.classList.remove('cur'));
  const cur = root.querySelectorAll(`mark.ac-hit[data-hit="${acState.respHit}"]`);
  cur.forEach(m => m.classList.add('cur'));
  if (cur[0]) cur[0].scrollIntoView({ block: 'center' });
  const count = document.getElementById('acRespCount');
  if (count) count.textContent = `${acState.respHit + 1} / ${acState.respHits}${acState.respHits >= AC_MAX_HITS ? '+' : ''}`;
}

function acRespPaneHtml() {
  const r = acState.resp;
  const t = acState.respTab;
  if (t === 'console') return acConsoleHtml(r);
  if (t === 'headers') {
    return `<table class="ac-headers">${r.headers.map(([k, v]) => `<tr><td>${escHtml(k)}</td><td>${escHtml(v)}</td></tr>`).join('')}</table>`;
  }
  if (t === 'request') {
    return `<div class="ac-hint" style="margin-bottom:8px">Exactly what the helper sent (credentials masked).</div>
      <pre class="ac-pre" style="margin-bottom:10px"><b>${escHtml(r.request.method)}</b> ${escHtml(r.request.url)}</pre>
      <table class="ac-headers">${r.request.headers.map(([k, v]) => `<tr><td>${escHtml(k)}</td><td>${escHtml(v)}</td></tr>`).join('')}</table>
      <div class="ac-hint" style="margin-top:8px">Body: ${r.request.bodySize ? acBytes(r.request.bodySize) : 'none'}${r.hops && r.hops.length > 1 ? ` · Hops: ${r.hops.map(h => `${h.status} ${escHtml(h.url)}`).join(' → ')}` : ''}</div>`;
  }
  // body
  const ct = (r.contentType || '').toLowerCase();
  if (r.bodyText == null) {
    if (/^image\//.test(ct)) return `<img class="ac-preview" src="/api/console/download/${r.downloadId}?inline=1" alt="response image">`;
    if (/pdf/.test(ct)) return `<iframe class="ac-preview pdf" src="/api/console/download/${r.downloadId}?inline=1"></iframe>`;
    return `<div class="ac-hint">Binary response (${acBytes(r.decodedSize)}). Use “Save response”.</div>`;
  }
  if (!r.bodyText) return `<div class="ac-hint">Empty body.</div>`;
  const json = acRespJson(r);
  if (json !== null && acState.pretty) {
    if (r._prettyHtml === undefined) r._prettyHtml = acHighlightJson(JSON.stringify(json, null, 2));
    return `<pre class="ac-pre">${r._prettyHtml}</pre>`;
  }
  return `<pre class="ac-pre">${escHtml(r.bodyText)}</pre>`;
}

function acHighlightJson(text) {
  return escHtml(text).replace(/(&quot;(?:\\.|[^&\\]|&(?!quot;))*?&quot;)(\s*:)?|\b(true|false|null)\b|(-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)/g,
    (m, str, colon, lit, num) => str ? (colon ? `<span class="k">${str}</span>${colon}` : `<span class="s">${str}</span>`)
      : lit ? `<span class="b">${lit}</span>` : `<span class="n">${num}</span>`);
}

function acConsoleHtml(r) {
  let html = '';
  if (r.networkError || r.failed) {
    html += `<div class="ac-neterr"><div class="band"><span class="material-symbols-outlined">error</span>${r.networkError ? 'Request failed' : 'Not sent'}</div>
      <div class="panel-body"><div class="mono">${escHtml(r.error || '')}</div>${r.hint ? `<div style="margin-top:6px;color:var(--ink-2)">${escHtml(r.hint)}</div>` : ''}
      ${r.missing && r.missing.length ? `<div class="ac-row" style="margin-top:8px">
        ${r.missing.filter(n => AC_LOOKUPS[n]).map(n => `<button class="btn btn-sm btn-primary" onclick="acOpenLookup('${n}')"><span class="material-symbols-outlined">${AC_LOOKUPS[n].icon}</span>${escHtml(AC_LOOKUPS[n].title)} by email</button>`).join('')}
        <button class="btn btn-sm" onclick="acOpenVars()">Open Variables</button></div>` : ''}</div></div>`;
  }
  if (r.timings) {
    const tm = r.timings;
    const parts = [['dns', 'DNS', 'var(--tw-sky-400)'], ['connect', 'Connect', 'var(--tw-indigo-400)'], ['tls', 'TLS', 'var(--tw-purple-400)'], ['ttfb', 'Waiting', 'var(--tw-amber-400)'], ['download', 'Download', 'var(--tw-emerald-400)']]
      .filter(([k]) => tm[k] != null && tm[k] > 0);
    const total = parts.reduce((n, [k]) => n + tm[k], 0) || 1;
    html += `<div class="ac-timing">${parts.map(([k, , c]) => `<span style="width:${(tm[k] / total) * 100}%;background:rgb(${c})" title="${k} ${Math.round(tm[k])} ms"></span>`).join('')}</div>
      <div class="ac-timing-legend" style="margin-bottom:12px">${parts.map(([k, l, c]) => `<span><i style="background:rgb(${c})"></i>${l} ${Math.round(tm[k])} ms</span>`).join('')}</div>`;
  }
  html += `<div class="ac-trace">${(r.trace || []).map(x => `<div><span class="t">+${x.t} ms</span><span class="lv ${x.level}">${x.level}</span><span class="msg">${escHtml(x.msg)}</span></div>`).join('')}</div>`;
  return html;
}

function acCopyBody() {
  const r = acState.resp;
  if (!r || r.bodyText == null) return;
  let text = r.bodyText;
  if (acState.pretty) { try { text = JSON.stringify(JSON.parse(text), null, 2); } catch { /* raw */ } }
  copyText(text);
}
