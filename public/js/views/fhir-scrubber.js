// ═════════════════════════════════════════════════════════════════════════
// FHIR PII SCRUBBER — runs entirely in the browser; nothing is sent anywhere
// ═════════════════════════════════════════════════════════════════════════
// Replaces person identifiers in a FHIR Bundle / resource / resource array with
// stable placeholders ([PATIENT_ID_1] …) and shifts every date by one random
// offset (±1–30 days), so time-of-day and durations survive.
let fsLast = null; // { output, replacements, fields }

// Institutional resources: their ids, identifiers, names and addresses are org data, not PII.
const FS_INSTITUTIONAL = new Set(['Organization', 'Location', 'Endpoint', 'HealthcareService']);
const FS_PERSON = new Set(['Patient', 'Practitioner', 'RelatedPerson', 'Person']);
const FS_REF_TYPES = new Set(['Patient', 'Practitioner', 'PractitionerRole', 'RelatedPerson', 'Person',
  'Appointment', 'AppointmentResponse', 'Schedule', 'Slot', 'Encounter', 'Observation', 'Condition',
  'DocumentReference', 'Binary', 'Communication', 'CommunicationRequest', 'ServiceRequest', 'Task',
  'Coverage', 'Consent', 'QuestionnaireResponse', 'Questionnaire', 'MessageHeader', 'Bundle',
  'Provenance', 'AuditEvent', 'Device', 'Group', 'EpisodeOfCare', 'Account', 'Invoice', 'Claim',
  'Organization', 'Location', 'Endpoint', 'HealthcareService']);
// Values under these keys are codes / infrastructure, not PII.
const FS_KEEP_KEYS = new Set(['resourceType', 'status', 'system', 'url', 'code', 'version', 'use', 'type',
  'mode', 'method', 'kind', 'language', 'contentType', 'unit', 'comparator', 'profile', 'versionId',
  'userSelected', 'minutesDuration', 'priority', 'required', 'participantStatus', 'eventUri', 'severity',
  'relation', 'intent', 'category', 'focus']);
const FS_ADDRESS_KEYS = new Set(['line', 'city', 'postalCode', 'district', 'state', 'country', 'text']);
const FS_NAME_KEYS = new Set(['family', 'given', 'prefix', 'suffix', 'text']);
const FS_VIDEO_RE = /video|room|meeting|jitsi|teams|zoom|webrtc/i;
const FS_DATE_RE = /^(\d{4})-(\d{2})-(\d{2})(T[\d:.]+(?:Z|[+-]\d{2}:\d{2})?)?$/;
const FS_REF_RE = /^(.*?\/)?([A-Z][A-Za-z]+)\/([A-Za-z0-9\-._]{1,64})(\/_history\/[A-Za-z0-9\-.]+)?$/;

function fsPlaceholderName(type) {
  return type.replace(/([a-z])([A-Z])/g, '$1_$2').toUpperCase() + '_ID';
}

function fsCreateScrubber() {
  const offsetDays = (Math.floor(Math.random() * 30) + 1) * (Math.random() < 0.5 ? -1 : 1);
  const maps = {};      // category → Map(original → placeholder)
  const replacements = []; // { category, placeholder, original }
  let fields = [];

  function token(category, original) {
    const m = maps[category] || (maps[category] = new Map());
    if (!m.has(original)) {
      const ph = `[${category}_${m.size + 1}]`;
      m.set(original, ph);
      replacements.push({ category, placeholder: ph, original });
    }
    return m.get(original);
  }

  function shiftDate(s) {
    const m = FS_DATE_RE.exec(s);
    const d = new Date(Date.UTC(+m[1], +m[2] - 1, +m[3] + offsetDays));
    const ymd = d.toISOString().slice(0, 10);
    return ymd + (m[4] || '');
  }

  // Reference "Patient/220775" (optionally with base URL / _history). Org-like refs stay.
  function scrubRef(s) {
    const m = FS_REF_RE.exec(s);
    if (!m || !FS_REF_TYPES.has(m[2])) return null;
    if (FS_INSTITUTIONAL.has(m[2])) return s;
    return (m[1] || '') + m[2] + '/' + token(fsPlaceholderName(m[2]), m[3]) + (m[4] ? '/_history/[VERSION]' : '');
  }

  // ctx: { key, keys (ancestor keys), parent, resType, extUrl }
  function scrubString(s, ctx) {
    const { key, keys, parent, resType, extUrl } = ctx;
    if (key === 'resourceType') return s;
    if (/^urn:uuid:/i.test(s)) return 'urn:uuid:' + token('UUID', s.slice(9).toLowerCase());
    if (FS_REF_RE.test(s)) { const r = scrubRef(s); if (r) return r; }
    if (FS_DATE_RE.test(s)) return shiftDate(s);
    if (FS_INSTITUTIONAL.has(resType)) return s;

    const videoCtx = FS_VIDEO_RE.test(key) || (extUrl && FS_VIDEO_RE.test(extUrl));
    if (videoCtx && !FS_KEEP_KEYS.has(key)) {
      if (/^https?:\/\//.test(s)) return s.replace(/[^/?#=]+$/, seg => token('VIDEO_ROOM', seg));
      return token('VIDEO_ROOM', s);
    }
    // Endpoint / infrastructure URLs stay; ids inside them are replaced by substituteKnown.
    if (/^https?:\/\/\S+$/.test(s)) return s;
    if (key === 'id' && parent && parent.resourceType) {
      return token(fsPlaceholderName(parent.resourceType), s);
    }
    if (keys.includes('identifier') && key === 'value') return token('IDENTIFIER', s);
    if (keys.includes('telecom') && key === 'value') return token(s.includes('@') ? 'EMAIL' : 'PHONE', s);
    if (keys.includes('address') && FS_ADDRESS_KEYS.has(key)) return token('ADDRESS', s);
    if (keys.includes('name') && FS_NAME_KEYS.has(key) && FS_PERSON.has(resType)) return token('NAME', s);
    if (key === 'display') {
      // Coding display ("attender") is a code label; a Reference display is a name.
      if (parent && ('code' in parent || 'system' in parent)) return s;
      return token('NAME', s);
    }
    if (key === 'text' && parent && Array.isArray(parent.coding)) return s; // CodeableConcept.text
    if (keys.includes('coding') || keys.includes('eventCoding') || keys.includes('meta')) {
      if (key !== 'source') return s;
    }
    if (FS_KEEP_KEYS.has(key)) return s;
    if (key === 'id') return token('ID', s); // element id
    return token('REDACTED', s);
  }

  function walk(node, path, keys, parent, resType, extUrl) {
    if (Array.isArray(node)) return node.map((v, i) => walk(v, `${path}[${i}]`, keys, parent, resType, extUrl));
    if (node && typeof node === 'object') {
      const rt = node.resourceType || resType;
      const eu = typeof node.url === 'string' && Object.keys(node).some(k => k.startsWith('value')) ? node.url : extUrl;
      const out = {};
      for (const [k, v] of Object.entries(node)) {
        const p = /^[A-Za-z_$][\w$]*$/.test(k) ? `${path}.${k}` : `${path}[${JSON.stringify(k)}]`;
        out[k] = walk(v, p, typeof v === 'object' && v !== null ? keys.concat(k) : keys, node, rt, eu);
      }
      return out;
    }
    const key = /\[\d+\]$/.test(path) ? keys[keys.length - 1] : path.slice(path.lastIndexOf('.') + 1);
    const ctx = { key, keys, parent, resType, extUrl };
    if (typeof node === 'string') {
      const r = scrubString(node, ctx);
      if (r !== node) fields.push(path);
      return r;
    }
    // Numeric ids / identifier values would be PII too.
    if (typeof node === 'number' && (key === 'id' || (keys.includes('identifier') && key === 'value'))
        && !FS_INSTITUTIONAL.has(resType)) {
      fields.push(path);
      return scrubString(String(node), ctx);
    }
    return node;
  }

  // Values kept verbatim (URLs, free codes) may still embed an id we replaced elsewhere.
  function substituteKnown(node) {
    const known = replacements.filter(r => r.original.length >= 4 && r.category !== 'REDACTED')
      .sort((a, b) => b.original.length - a.original.length);
    if (!known.length) return node;
    const esc = s => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const re = new RegExp(`(?<![A-Za-z0-9])(${known.map(r => esc(r.original)).join('|')})(?![A-Za-z0-9])`, 'g');
    const byOrig = new Map(known.map(r => [r.original, r.placeholder]));
    const rec = (n, path) => {
      if (Array.isArray(n)) return n.map((v, i) => rec(v, `${path}[${i}]`));
      if (n && typeof n === 'object') {
        const o = {};
        for (const [k, v] of Object.entries(n)) o[k] = k === 'resourceType' ? v : rec(v, `${path}.${k}`);
        return o;
      }
      if (typeof n !== 'string' || !re.test(n)) return n;
      re.lastIndex = 0;
      if (!fields.includes(path)) fields.push(path);
      return n.replace(re, m => byOrig.get(m));
    };
    re.lastIndex = 0;
    return rec(node, '$');
  }

  return {
    run(input) {
      walk(input, '$', [], null, null, null); // pass 1: number placeholders by first appearance
      fields = [];
      const out = substituteKnown(walk(input, '$', [], null, null, null));
      return { output: out, replacements, fields: [...new Set(fields)] };
    },
  };
}

function fsScrub(input) {
  const { output, replacements, fields } = fsCreateScrubber().run(input);
  const meta = {
    version: '1.0',
    scrubbed_at: new Date().toISOString(),
    fields_scrubbed: fields,
    method: 'synthetic_replacement',
  };
  const wrapped = Array.isArray(output) ? { _scrubber: meta, resources: output } : { _scrubber: meta, ...output };
  return { output: wrapped, replacements, fields };
}

function renderFhirScrubber(el) {
  el.innerHTML = pageWrap(
    pageHero('FHIR Scrubber', { sub: 'Removes PII from a FHIR Bundle or resource. Runs in this window only — nothing is sent to the server or an AI.' }) +
    `<div class="fs-grid">
      <div class="panel">
        <div class="panel-header"><div class="panel-title"><span class="material-symbols-outlined">input</span>Input</div>
          <div class="panel-actions">${btnGhost('Clear', 'fsClear()', { icon: 'backspace' })}</div></div>
        <div class="panel-body"><textarea id="fs-in" class="lc-textarea fs-text" spellcheck="false"
          placeholder='Paste a FHIR Bundle, resource, or array of resources (JSON)'></textarea>
          <div class="fs-actions">${btnPrimary('Scrub', 'fsRun()', { icon: 'shield_person' })}
            <span class="muted fs-note">Dates are shifted by one random offset per run (±1–30 days).</span></div>
        </div>
      </div>
      <div class="panel">
        <div class="panel-header"><div class="panel-title"><span class="material-symbols-outlined">output</span>Scrubbed</div>
          <div class="panel-actions">${btnGhost('Copy', 'fsCopy()', { icon: 'content_copy' })}</div></div>
        <div class="panel-body"><textarea id="fs-out" class="lc-textarea fs-text" spellcheck="false" readonly></textarea></div>
      </div>
    </div>
    <div id="fs-summary"></div>`
  );
  if (fsLast) fsShow();
}

function fsClear() {
  fsLast = null;
  document.getElementById('fs-in').value = '';
  document.getElementById('fs-out').value = '';
  document.getElementById('fs-summary').innerHTML = '';
}

function fsRun() {
  const raw = document.getElementById('fs-in').value.trim();
  if (!raw) return showToast('Paste some FHIR JSON first');
  let input;
  try { input = JSON.parse(raw); }
  catch (e) { return showToast('Not valid JSON: ' + e.message); }
  if (!input || typeof input !== 'object') return showToast('Expected a JSON object or array');
  const r = fsScrub(input);
  fsLast = { output: JSON.stringify(r.output, null, 2), replacements: r.replacements, fields: r.fields };
  fsShow();
}

function fsShow() {
  document.getElementById('fs-out').value = fsLast.output;
  const counts = {};
  for (const r of fsLast.replacements) counts[r.category] = (counts[r.category] || 0) + 1;
  const pills = Object.entries(counts).map(([c, n]) => `<span class="pill info">${escHtml(c)} × ${n}</span>`).join(' ');
  const rows = fsLast.replacements.map(r => `<tr>
      <td class="mono">${escHtml(r.placeholder)}</td>
      <td class="mono fs-orig">${escHtml(r.original)}</td></tr>`).join('');
  document.getElementById('fs-summary').innerHTML = `<div class="panel" style="margin-top:var(--s-4)">
    <div class="panel-header"><div class="panel-title"><span class="material-symbols-outlined">fact_check</span>
      Replacements <span class="count">${fsLast.fields.length} fields</span></div>
      <div class="panel-actions">${pills || '<span class="muted">Nothing to scrub</span>'}</div></div>
    ${rows ? `<details class="fs-details"><summary>Show originals (local only, not part of the output)</summary>
      <div style="overflow-x:auto"><table class="lc-table"><thead><tr><th>Placeholder</th><th>Original</th></tr></thead>
      <tbody>${rows}</tbody></table></div></details>` : ''}
  </div>`;
}

function fsCopy() {
  if (!fsLast) return showToast('Nothing scrubbed yet');
  copyText(fsLast.output, 'Scrubbed JSON copied');
}
