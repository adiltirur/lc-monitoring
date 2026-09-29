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
    <div class="ac-resp-body">${acRespPaneHtml()}</div>`;
}

function acRespTab(tab) {
  acState.respTab = tab;
  acRenderResponse();
}

function acBytes(n) {
  if (n == null) return '—';
  return n < 1024 ? `${n} B` : n < 1048576 ? `${(n / 1024).toFixed(1)} KB` : `${(n / 1048576).toFixed(2)} MB`;
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
  let json = null;
  if (/json/.test(ct) || /^\s*[[{]/.test(r.bodyText)) { try { json = JSON.parse(r.bodyText); } catch { /* not JSON */ } }
  const toggle = json !== null ? `<div class="ac-row space" style="margin-bottom:8px"><div class="ac-seg">
      <button class="${acState.pretty ? 'active' : ''}" onclick="acState.pretty=true;acRenderResponse()">Pretty</button>
      <button class="${!acState.pretty ? 'active' : ''}" onclick="acState.pretty=false;acRenderResponse()">Raw</button></div>
      ${r.truncated ? '<span class="pill warn">truncated at 5 MB — Save response for all of it</span>' : ''}</div>` : '';
  const body = json !== null && acState.pretty ? acHighlightJson(JSON.stringify(json, null, 2)) : escHtml(r.bodyText);
  return `${toggle}<pre class="ac-pre">${body}</pre>`;
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
      ${r.missing && r.missing.length ? `<div style="margin-top:8px"><button class="btn btn-sm" onclick="acOpenVars()">Open Variables</button></div>` : ''}</div></div>`;
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
