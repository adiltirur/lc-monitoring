// LC Helper — macOS-style date picker (shared by index, monitoring, tools).
//
// Enhances every <input type="date"> and <input type="datetime-local"> on the
// page, including ones rendered later: the original input stays in the DOM
// (hidden) and keeps its value format (YYYY-MM-DD / YYYY-MM-DDTHH:MM), so view
// code, inline oninput/onchange handlers and .value reads keep working. A text
// field shows the date as 24.09.2026 (de-DE, like the rest of the app) and
// accepts typing; clicking it opens a Calendar-style popover.
(function () {
  if (window.__lcDatePicker) return;
  window.__lcDatePicker = true;

  const MONTHS = ['January', 'February', 'March', 'April', 'May', 'June', 'July', 'August', 'September', 'October', 'November', 'December'];
  const DOW = ['Mo', 'Tu', 'We', 'Th', 'Fr', 'Sa', 'Su']; // weeks start on Monday (de)
  const pad = (n) => String(n).padStart(2, '0');
  const iso = (d) => `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
  const same = (a, b) => a && b && a.getFullYear() === b.getFullYear() && a.getMonth() === b.getMonth() && a.getDate() === b.getDate();

  // ── Styles (theme tokens with fallbacks so it works on every page) ──
  const css = `
  .lcd-field { position: relative; display: block; }
  .lcd-field input.lcd-text { width: 100%; padding-right: 34px !important; font-family: var(--font-ui, -apple-system, system-ui, sans-serif) !important;
    font-variant-numeric: tabular-nums; letter-spacing: .01em; cursor: pointer; }
  .lcd-field .lcd-icon { position: absolute; right: 9px; top: 50%; transform: translateY(-50%); width: 18px; height: 18px; pointer-events: none;
    color: var(--ink-3, #60666d); }
  .lcd-pop { position: fixed; z-index: 1000; width: 262px; padding: 12px; border-radius: 12px; background: var(--surface-1, #fff);
    color: var(--ink, #00212a); border: 1px solid var(--rule-strong, #d5d4dc); box-shadow: var(--shadow-pop, 0 16px 40px -12px rgba(0,0,0,.3));
    font: 500 12.5px/1 var(--font-ui, -apple-system, system-ui, sans-serif); user-select: none; -webkit-user-select: none;
    animation: lcd-in 140ms cubic-bezier(.2,.7,.2,1); }
  @keyframes lcd-in { from { opacity: 0; transform: translateY(-4px) scale(.98); } }
  .lcd-head { display: flex; align-items: center; gap: 4px; margin: 0 2px 10px; }
  .lcd-title { flex: 1; font-weight: 700; font-size: 13.5px; letter-spacing: .01em; }
  .lcd-title span { color: var(--action, #004e64); }
  .lcd-nav { width: 26px; height: 26px; display: grid; place-items: center; border: 0; border-radius: 6px; background: transparent;
    color: var(--ink-2, #384048); cursor: pointer; font: inherit; }
  .lcd-nav:hover { background: var(--surface-3, #f0f7f9); color: var(--ink, #00212a); }
  .lcd-today { height: 24px; padding: 0 8px; border-radius: 6px; border: 1px solid var(--rule-strong, #d5d4dc); background: transparent;
    color: var(--ink-2, #384048); font: 600 11.5px/1 var(--font-ui, system-ui); cursor: pointer; }
  .lcd-today:hover { background: var(--surface-3, #f0f7f9); }
  .lcd-grid { display: grid; grid-template-columns: repeat(7, 1fr); gap: 2px; }
  .lcd-dow { height: 22px; display: grid; place-items: center; font-size: 10.5px; font-weight: 700; color: var(--ink-3, #60666d); }
  .lcd-day { height: 32px; border: 0; border-radius: 50%; background: transparent; color: var(--ink, #00212a); cursor: pointer;
    font: 500 12.5px/1 var(--font-ui, system-ui); font-variant-numeric: tabular-nums; }
  .lcd-day:hover { background: var(--surface-3, #f0f7f9); }
  .lcd-day.out { color: var(--ink-4, #a3a7ab); }
  .lcd-day.wknd:not(.sel) { color: var(--ink-3, #60666d); }
  .lcd-day.today:not(.sel) { color: var(--red, #e84444); font-weight: 800; }
  .lcd-day.sel { background: var(--action, #004e64); color: var(--action-ink, #fff); font-weight: 700; }
  .lcd-day.focus { box-shadow: 0 0 0 2px var(--focus, #004e64); }
  .lcd-day:disabled { opacity: .3; cursor: not-allowed; background: transparent; }
  .lcd-time { display: flex; align-items: center; gap: 6px; margin-top: 10px; padding-top: 10px; border-top: 1px solid var(--rule, #e6edf0); }
  .lcd-time label { flex: 1; color: var(--ink-2, #384048); font-weight: 600; }
  .lcd-time input { width: 44px; height: 28px; text-align: center; border-radius: 6px; border: 1px solid var(--rule-strong, #d5d4dc);
    background: var(--surface-2, #fff); color: var(--ink, #00212a); font: 600 13px var(--font-ui, system-ui); font-variant-numeric: tabular-nums; padding: 0; }
  .lcd-time input:focus { outline: none; border-color: var(--focus, #004e64); box-shadow: 0 0 0 1px var(--focus, #004e64); }
  .lcd-foot { display: flex; justify-content: space-between; margin-top: 10px; }
  .lcd-foot button { height: 26px; padding: 0 12px; border-radius: 6px; border: 1px solid var(--rule-strong, #d5d4dc); background: transparent;
    color: var(--ink-2, #384048); font: 600 12px var(--font-ui, system-ui); cursor: pointer; }
  .lcd-foot button.primary { background: var(--action, #004e64); border-color: var(--action, #004e64); color: var(--action-ink, #fff); }
  /* Native time fields: same type treatment as the enhanced fields. */
  input[type="time"] { font-family: var(--font-ui, system-ui) !important; font-variant-numeric: tabular-nums; }
  input[type="time"]::-webkit-datetime-edit { padding: 0; line-height: 1; }
  `;
  const style = document.createElement('style');
  style.textContent = css;
  document.head.appendChild(style);

  const ICON = '<svg class="lcd-icon" viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.5" aria-hidden="true"><rect x="3" y="4.5" width="14" height="12.5" rx="2.5"/><path d="M3 8.5h14M7 2.8v3.2M13 2.8v3.2" stroke-linecap="round"/></svg>';

  // ── Parsing / formatting ──
  function parseIso(v, withTime) {
    const m = /^(\d{4})-(\d{2})-(\d{2})(?:T(\d{2}):(\d{2}))?/.exec(v || '');
    if (!m) return null;
    const d = new Date(+m[1], +m[2] - 1, +m[3], withTime && m[4] ? +m[4] : 0, withTime && m[5] ? +m[5] : 0);
    return isNaN(d) ? null : d;
  }
  function toIso(d, withTime) { return withTime ? `${iso(d)}T${pad(d.getHours())}:${pad(d.getMinutes())}` : iso(d); }
  function show(d, withTime) { if (!d) return ''; const s = `${pad(d.getDate())}.${pad(d.getMonth() + 1)}.${d.getFullYear()}`; return withTime ? `${s}, ${pad(d.getHours())}:${pad(d.getMinutes())}` : s; }
  // Accepts 24.9.2026, 24.09.26, 2026-09-24, "24.9.2026 14:30", "today"/"heute".
  function parseTyped(text, withTime, fallbackTime) {
    const t = text.trim().toLowerCase();
    if (!t) return null;
    if (t === 'today' || t === 'heute') { const n = new Date(); if (!withTime) n.setHours(0, 0, 0, 0); return n; }
    let m = /^(\d{1,2})[.\/-](\d{1,2})[.\/-](\d{2,4})(?:[ ,T]+(\d{1,2})[:.](\d{2}))?$/.exec(t);
    let y, mo, d, h, mi;
    if (m) { d = +m[1]; mo = +m[2]; y = +m[3]; if (y < 100) y += 2000; h = m[4]; mi = m[5]; }
    else { m = /^(\d{4})-(\d{1,2})-(\d{1,2})(?:[ T](\d{1,2}):(\d{2}))?$/.exec(t); if (!m) return undefined; y = +m[1]; mo = +m[2]; d = +m[3]; h = m[4]; mi = m[5]; }
    const out = new Date(y, mo - 1, d, h != null ? +h : fallbackTime ? fallbackTime.getHours() : 0, mi != null ? +mi : fallbackTime ? fallbackTime.getMinutes() : 0);
    if (out.getMonth() !== mo - 1) return undefined;
    return out;
  }

  // ── Enhancement ──
  function enhance(input) {
    if (input.__lcd || input.closest('.lcd-field')) return;
    input.__lcd = true;
    const withTime = input.type === 'datetime-local';
    const wrap = document.createElement('span');
    wrap.className = 'lcd-field';
    const text = document.createElement('input');
    text.type = 'text';
    text.className = (input.className || '') + ' lcd-text';
    text.setAttribute('style', input.getAttribute('style') || '');
    text.placeholder = withTime ? 'dd.mm.yyyy, hh:mm' : 'dd.mm.yyyy';
    text.autocomplete = 'off';
    text.spellcheck = false;
    if (input.disabled) text.disabled = true;
    const label = input.id && document.querySelector(`label[for="${CSS.escape(input.id)}"]`);
    if (label) text.setAttribute('aria-label', label.textContent.trim());
    input.parentNode.insertBefore(wrap, input);
    wrap.appendChild(text);
    wrap.insertAdjacentHTML('beforeend', ICON);
    wrap.appendChild(input);
    input.style.display = 'none';

    // Keep the visible text in sync when code assigns input.value directly.
    const desc = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value');
    Object.defineProperty(input, 'value', {
      configurable: true,
      get() { return desc.get.call(this); },
      set(v) { desc.set.call(this, v); text.value = show(parseIso(v, withTime), withTime); },
    });
    text.value = show(parseIso(input.value, withTime), withTime);

    const commit = (d) => {
      const v = d ? toIso(d, withTime) : '';
      if (v === desc.get.call(input)) { text.value = show(d, withTime); return; }
      input.value = v;
      input.dispatchEvent(new Event('input', { bubbles: true }));
      input.dispatchEvent(new Event('change', { bubbles: true }));
    };
    text.addEventListener('click', () => open(input, text, withTime, commit));
    text.addEventListener('keydown', (e) => {
      if (e.key === 'ArrowDown' && (e.altKey || !pop)) { e.preventDefault(); open(input, text, withTime, commit); }
      else if (e.key === 'Enter') { e.preventDefault(); applyTyped(); close(); }
      else if (e.key === 'Escape') close();
      else if (pop && ['ArrowUp', 'ArrowDown', 'ArrowLeft', 'ArrowRight', 'PageUp', 'PageDown'].includes(e.key)) { e.preventDefault(); pop.__key(e); }
    });
    const applyTyped = () => {
      const d = parseTyped(text.value, withTime, parseIso(input.value, withTime));
      if (d === undefined) { text.value = show(parseIso(input.value, withTime), withTime); return; }
      if (d && !inRange(input, d)) { text.value = show(parseIso(input.value, withTime), withTime); return; }
      commit(d);
    };
    text.addEventListener('blur', () => setTimeout(() => { if (!pop || !pop.contains(document.activeElement)) applyTyped(); }, 0));
  }

  function inRange(input, d) {
    const min = parseIso(input.min, false), max = parseIso(input.max, false);
    const day = new Date(d.getFullYear(), d.getMonth(), d.getDate());
    return !(min && day < min) && !(max && day > max);
  }

  // ── Popover ──
  let pop = null;
  function close() { if (pop) { pop.remove(); pop = null; } }
  function open(input, text, withTime, commit) {
    close();
    const current = parseIso(input.value, withTime);
    let view = current ? new Date(current) : new Date();
    let focus = current ? new Date(current) : new Date();
    let time = current ? { h: current.getHours(), m: current.getMinutes() } : { h: 0, m: 0 };
    pop = document.createElement('div');
    pop.className = 'lcd-pop';
    pop.setAttribute('role', 'dialog');
    pop.setAttribute('data-no-drag', '');
    document.body.appendChild(pop);

    const pick = (d) => {
      const out = new Date(d.getFullYear(), d.getMonth(), d.getDate(), withTime ? time.h : 0, withTime ? time.m : 0);
      commit(out);
      if (!withTime) { close(); text.focus(); } else { view = new Date(out); focus = new Date(out); render(); }
    };
    function render() {
      const y = view.getFullYear(), mo = view.getMonth();
      const first = new Date(y, mo, 1);
      const start = new Date(y, mo, 1 - ((first.getDay() + 6) % 7));
      const sel = parseIso(input.value, withTime), today = new Date();
      let cells = '';
      for (let i = 0; i < 42; i++) {
        const d = new Date(start.getFullYear(), start.getMonth(), start.getDate() + i);
        const cls = ['lcd-day', d.getMonth() !== mo && 'out', (d.getDay() === 0 || d.getDay() === 6) && 'wknd', same(d, today) && 'today', same(d, sel) && 'sel', same(d, focus) && 'focus'].filter(Boolean).join(' ');
        cells += `<button type="button" class="${cls}" data-d="${iso(d)}" ${inRange(input, d) ? '' : 'disabled'} aria-label="${d.getDate()} ${MONTHS[d.getMonth()]} ${d.getFullYear()}">${d.getDate()}</button>`;
      }
      pop.innerHTML = `
        <div class="lcd-head">
          <div class="lcd-title">${MONTHS[mo]} <span>${y}</span></div>
          <button type="button" class="lcd-nav" data-nav="-1" aria-label="Previous month">‹</button>
          <button type="button" class="lcd-today" data-nav="0">Today</button>
          <button type="button" class="lcd-nav" data-nav="1" aria-label="Next month">›</button>
        </div>
        <div class="lcd-grid">${DOW.map((d) => `<div class="lcd-dow">${d}</div>`).join('')}${cells}</div>
        ${withTime ? `<div class="lcd-time"><label>Time</label><input inputmode="numeric" maxlength="2" data-t="h" value="${pad(time.h)}" aria-label="Hours">:<input inputmode="numeric" maxlength="2" data-t="m" value="${pad(time.m)}" aria-label="Minutes"></div>
          <div class="lcd-foot"><button type="button" data-act="clear">Clear</button><button type="button" class="primary" data-act="done">Done</button></div>`
        : `<div class="lcd-foot"><button type="button" data-act="clear">Clear</button></div>`}`;
      pop.querySelectorAll('.lcd-day').forEach((b) => b.addEventListener('mousedown', (e) => { e.preventDefault(); pick(parseIso(b.dataset.d)); }));
      pop.querySelectorAll('[data-nav]').forEach((b) => b.addEventListener('mousedown', (e) => {
        e.preventDefault();
        const n = +b.dataset.nav;
        if (n === 0) { const t = new Date(); view = new Date(t); focus = new Date(t); if (!withTime) return pick(t); }
        else view = new Date(view.getFullYear(), view.getMonth() + n, 1);
        render();
      }));
      pop.querySelectorAll('[data-act]').forEach((b) => b.addEventListener('mousedown', (e) => {
        e.preventDefault();
        if (b.dataset.act === 'clear') { commit(null); close(); text.focus(); }
        else { close(); text.focus(); }
      }));
      pop.querySelectorAll('.lcd-time input').forEach((t) => {
        t.addEventListener('input', () => {
          const v = Math.max(0, Math.min(t.dataset.t === 'h' ? 23 : 59, parseInt(t.value || '0', 10) || 0));
          time[t.dataset.t] = v;
          const cur = parseIso(input.value, true);
          if (cur) { cur.setHours(time.h, time.m); commit(cur); }
        });
        t.addEventListener('blur', () => { t.value = pad(time[t.dataset.t]); });
        t.addEventListener('keydown', (e) => { if (e.key === 'Enter') { close(); text.focus(); } if (e.key === 'Escape') { close(); text.focus(); } });
      });
      position();
    }
    pop.__key = (e) => {
      const step = { ArrowLeft: -1, ArrowRight: 1, ArrowUp: -7, ArrowDown: 7 }[e.key];
      if (step) focus = new Date(focus.getFullYear(), focus.getMonth(), focus.getDate() + step);
      if (e.key === 'PageUp') focus = new Date(focus.getFullYear(), focus.getMonth() - 1, focus.getDate());
      if (e.key === 'PageDown') focus = new Date(focus.getFullYear(), focus.getMonth() + 1, focus.getDate());
      view = new Date(focus.getFullYear(), focus.getMonth(), 1);
      pop.__navigated = true;
      render();
    };
    // Enter on the text field while navigating picks the focused day.
    pop.__pickFocus = () => pick(focus);
    function position() {
      const r = text.getBoundingClientRect();
      const h = pop.offsetHeight, w = pop.offsetWidth;
      let top = r.bottom + 6;
      if (top + h > window.innerHeight - 8) top = Math.max(8, r.top - h - 6);
      pop.style.top = `${top}px`;
      pop.style.left = `${Math.max(8, Math.min(r.left, window.innerWidth - w - 8))}px`;
    }
    render();
  }

  // Enter while the popover is open selects the keyboard-focused day.
  document.addEventListener('keydown', (e) => {
    if (pop && e.key === 'Enter' && e.target.classList && e.target.classList.contains('lcd-text') && pop.__navigated && pop.__pickFocus) {
      e.stopImmediatePropagation(); e.preventDefault(); pop.__pickFocus();
    }
  }, true);
  document.addEventListener('mousedown', (e) => { if (pop && !pop.contains(e.target) && !(e.target.classList && e.target.classList.contains('lcd-text'))) close(); });
  window.addEventListener('resize', close);
  document.addEventListener('scroll', (e) => { if (pop && !pop.contains(e.target)) close(); }, true);

  // ── Wire up: existing inputs + anything rendered later ──
  const scan = (root) => root.querySelectorAll && root.querySelectorAll('input[type="date"], input[type="datetime-local"]').forEach(enhance);
  const start = () => {
    scan(document);
    new MutationObserver((muts) => { for (const m of muts) for (const n of m.addedNodes) if (n.nodeType === 1) { if (n.matches && n.matches('input[type="date"], input[type="datetime-local"]')) enhance(n); else scan(n); } })
      .observe(document.body, { childList: true, subtree: true });
  };
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', start); else start();
})();
