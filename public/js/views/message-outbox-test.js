// ═════════════════════════════════════════════════════════════════════════
// MESSAGE OUTBOX — template test
// Loads the Brevo payload of an email Core already sent with a template, lets
// the params be edited, and sends one copy to an address typed in here. The
// server refuses the original recipients and drops cc/bcc.
// ═════════════════════════════════════════════════════════════════════════
let motState = { open: false, templateId: '', offset: 0, total: 0, sample: null, params: [], loading: false, error: '' };

function motToggle() {
  motState.open = !motState.open;
  motRender();
}

function motParamRow(p, i) {
  const isJson = typeof p.value !== 'string';
  const val = isJson ? JSON.stringify(p.value, null, 2) : p.value;
  const input = isJson || val.includes('\n')
    ? `<textarea class="lc-textarea" rows="${Math.min(8, val.split('\n').length + 1)}" oninput="motParamInput(${i}, this.value)">${escHtml(val)}</textarea>`
    : `<input class="lc-input mono" value="${escHtml(val)}" oninput="motParamInput(${i}, this.value)">`;
  return `<div class="mot-param">
    <input class="lc-input mono" value="${escHtml(p.key)}" placeholder="key" oninput="motState.params[${i}].key=this.value">
    <div>${input}${isJson ? '<div class="faint mot-hint">JSON</div>' : ''}</div>
    <button class="lc-icon-btn" title="Remove" onclick="motState.params.splice(${i},1);motRender()"><span class="material-symbols-outlined">close</span></button>
  </div>`;
}

function motParamInput(i, raw) {
  const p = motState.params[i];
  if (typeof p.value === 'string') { p.value = raw; p.invalid = false; return; }
  try { p.value = JSON.parse(raw); p.invalid = false; } catch { p.raw = raw; p.invalid = true; }
}

function motRecipientList(sample) {
  return (sample.to || []).map(r => r.email).filter(Boolean).join(', ') || '—';
}

function motBody() {
  const s = motState.sample;
  const templates = (window._moTemplates || []);
  const opts = [{ value: '', label: 'Choose a template…' }, ...templates.map(t => ({
    value: t.templateId,
    label: `${t.templateName || t.types.join(', ') || 'not in email_template_id'} (#${t.templateId})${t.count ? ` · ${t.count}` : ''}`,
  }))];
  const head = `<div class="mot-pick">
      ${fSelect('Template', opts, `oninput="motState.templateId=this.value;motState.sample=null;motState.error='';motRender()"`, motState.templateId)}
      ${btnPrimary(motState.loading ? 'Loading…' : 'Load data', 'motLoad(0)', { icon: 'download' })}
    </div>`;
  if (motState.error) return head + `<div class="mot-error">${escHtml(motState.error)}</div>`;
  if (!s) {
    return head + (motState.loaded && motState.templateId
      ? `<div class="faint mot-note">No sent email with this template in the outbox on this environment. You can still add params and send.</div>${motForm()}`
      : '');
  }
  const nav = `<div class="row-sm">
      <button class="btn btn-sm" ${motState.offset + 1 >= motState.total ? 'disabled' : ''} onclick="motLoad(${motState.offset + 1})">Older</button>
      <button class="btn btn-sm" ${motState.offset === 0 ? 'disabled' : ''} onclick="motLoad(${motState.offset - 1})">Newer</button>
    </div>`;
  const dropped = s.droppedKeys.length ? ` · not copied: ${escHtml(s.droppedKeys.join(', '))}` : '';
  return head + `<div class="mot-source">
      <div class="list-meta" style="margin:0">Sent email ${motState.offset + 1} of ${motState.total} · ${escHtml(deTime(s.sentAt || s.createdAt))} · row <span class="mono">${escHtml(String(s.id).slice(0, 8))}…</span>
        · originally to <span class="mono">${escHtml(motRecipientList(s))}</span>${s.sender ? ` · from <span class="mono">${escHtml(s.sender.email || s.sender.name || '')}</span>` : ''}${s.subject ? ` · subject “${escHtml(s.subject)}”` : ''}${dropped}</div>
      ${nav}
    </div>${motForm()}`;
}

function motForm() {
  const s = motState.sample;
  const att = s && s.attachments.length
    ? `<label class="row-sm mot-check"><input type="checkbox" id="motAttach"> Include the original ${s.attachments.length} attachment(s): ${escHtml(s.attachments.join(', '))}</label>`
    : '';
  return `<div class="mot-form">
      <div class="mot-to">
        ${fInput('Send to (required)', `id="motToEmail" type="email" placeholder="your test address"`)}
        ${fInput('Name (optional)', `id="motToName" placeholder="Test Empfänger"`)}
      </div>
      <h4 class="section-label">Params</h4>
      <div class="mot-params">${motState.params.map(motParamRow).join('') || '<div class="faint mot-note">No params.</div>'}</div>
      <div class="row-sm" style="margin-top:var(--s-2)">
        ${btnGhost('Add param', `motState.params.push({key:'',value:''});motRender()`, { icon: 'add' })}
        ${s ? btnGhost('Reset to original', 'motLoad(motState.offset)', { icon: 'restart_alt' }) : ''}
      </div>
      ${att}
      <div class="mot-actions">${btnPrimary('Send test email', 'motSend()', { icon: 'send' })}</div>
    </div>`;
}

function motRender() {
  const el = document.getElementById('motPanel');
  if (!el) return;
  // Keep what was typed in the recipient fields across re-renders.
  const email = document.getElementById('motToEmail')?.value || '';
  const name = document.getElementById('motToName')?.value || '';
  el.innerHTML = motState.open ? `<div class="panel" style="margin-bottom:var(--s-4)">
      <div class="panel-header"><span class="panel-title"><span class="material-symbols-outlined">science</span>Test email template</span>
        <div class="panel-actions"><button class="lc-icon-btn" title="Close" onclick="motToggle()"><span class="material-symbols-outlined">close</span></button></div>
      </div>
      <div class="panel-body">${motBody()}</div>
    </div>` : '';
  const e = document.getElementById('motToEmail'); if (e) e.value = email;
  const n = document.getElementById('motToName'); if (n) n.value = name;
}

async function motLoad(offset) {
  if (!motState.templateId) { showToast('Choose a template first'); return; }
  motState.loading = true; motState.error = ''; motRender();
  try {
    const r = await apiFetch(`/api/message-outbox/template-test/sample?templateId=${encodeURIComponent(motState.templateId)}&offset=${offset}`);
    if (r && r.error) throw new Error(r.error);
    motState.sample = r.sample;
    motState.total = r.total;
    motState.offset = r.offset;
    motState.loaded = true;
    motState.params = r.sample ? Object.entries(r.sample.params).map(([key, value]) => ({ key, value })) : [];
  } catch (e) {
    motState.error = 'Load failed: ' + e.message;
  } finally {
    motState.loading = false;
    motRender();
  }
}

async function motSend() {
  const email = (document.getElementById('motToEmail')?.value || '').trim();
  const name = (document.getElementById('motToName')?.value || '').trim();
  if (!email) { showToast('Enter the address to send the test to'); document.getElementById('motToEmail')?.focus(); return; }
  const s = motState.sample;
  if (s && (s.to || []).some(r => String(r.email || '').toLowerCase() === email.toLowerCase())) {
    showToast('Change the recipient — that address received the original email');
    return;
  }
  const bad = motState.params.find(p => p.invalid);
  if (bad) { showToast(`Param “${bad.key}” is not valid JSON`); return; }
  const params = {};
  for (const p of motState.params) {
    const k = p.key.trim();
    if (!k) continue;
    if (k in params) { showToast(`Param “${k}” is listed twice`); return; }
    params[k] = p.value;
  }
  const includeAttachments = !!document.getElementById('motAttach')?.checked;
  if (!confirm(`Send template #${motState.templateId} to ${email} via Brevo?${includeAttachments ? '\n\nThe original attachments are included.' : ''}`)) return;
  try {
    const r = await apiPost('/api/message-outbox/template-test/send', {
      templateId: motState.templateId,
      sourceId: s ? s.id : null,
      to: { email, name },
      params,
      includeAttachments,
    });
    if (r && r.error) throw new Error(r.error);
    showToast(`✓ Test email sent${r.messageId ? ` · ${r.messageId}` : ''}`);
  } catch (e) {
    alert('Send failed: ' + e.message);
  }
}
