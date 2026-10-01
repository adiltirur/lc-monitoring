// API console: "Find missing" — a headless Claude Code session reads LillianCare-Core
// and lists the outbound calls (Principa, Personio, Brevo, FCM, Maps, …) and inbound
// webhooks that have no console template yet. It only reads (Read/Grep/Glob, secrets
// denied, same sandbox as Investigations) and answers with structured JSON; this
// module validates every entry and appends it to externals-generated.json (tracked in
// git, so additions can be reviewed and committed). Claude never edits files.
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { spawn } = require('child_process');
const { INV_CLAUDE_BIN, INV_CODE_SETTINGS, INV_CORE_DIR, invCodeProgress } = require('../investigations');

const GENERATED_FILE = path.join(__dirname, 'externals-generated.json');
const TIMEOUT_MS = 12 * 60 * 1000;

// Group → auth it may use + URL prefixes it may call. Enforced on Claude's output.
const GROUPS = {
  'Principa FHIR': { auth: ['principa'], prefixes: ['{{principaFhir}}'] },
  'Principa REST': { auth: ['principa'], prefixes: ['{{principaRest}}'] },
  Personio: { auth: ['personio'], prefixes: ['{{personio}}'] },
  Brevo: { auth: ['brevo'], prefixes: ['{{brevo}}'] },
  'Firebase (FCM)': { auth: ['fcm'], prefixes: ['{{fcm}}'] },
  'Google Maps': { auth: ['maps'], prefixes: ['{{maps}}'] },
  Holidays: { auth: ['none'], prefixes: ['{{holidays}}'] },
  'Inbound webhooks': { auth: ['none', 'coreApiKey', 'lilli'], prefixes: ['{{coreApi}}', '{{coreWeb}}'] },
  // A service the console doesn't know yet: no helper credentials are ever attached.
  Other: { auth: ['none'], prefixes: ['https://', 'http://'] },
};
const METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'];

const SCHEMA = {
  type: 'object',
  required: ['added', 'stale', 'notes'],
  properties: {
    added: {
      type: 'array',
      items: {
        type: 'object',
        required: ['group', 'name', 'method', 'url', 'auth', 'effect', 'headers', 'source', 'doc'],
        properties: {
          group: { type: 'string', enum: Object.keys(GROUPS) },
          name: { type: 'string' },
          method: { type: 'string', enum: METHODS },
          url: { type: 'string' },
          auth: { type: 'string', enum: ['none', 'principa', 'personio', 'brevo', 'fcm', 'maps', 'coreApiKey', 'lilli'] },
          effect: { type: 'string', enum: ['read', 'write', 'sends'] },
          headers: { type: 'object', additionalProperties: { type: 'string' } },
          body: { description: 'Example JSON body, or omit for no body' },
          source: { type: 'string', description: 'file:line of the call site, relative to lillian_care_core_server/lib/src' },
          doc: { type: 'string' },
        },
      },
    },
    stale: {
      type: 'array',
      items: { type: 'object', required: ['url', 'reason'], properties: { url: { type: 'string' }, reason: { type: 'string' } } },
    },
    notes: { type: 'string' },
  },
};

function readGenerated() {
  try { return JSON.parse(fs.readFileSync(GENERATED_FILE, 'utf8')); } catch { return []; }
}
function writeGenerated(list) {
  fs.writeFileSync(GENERATED_FILE, JSON.stringify(list, null, 2) + '\n');
}

// Same call = same method + path + query keys (values and {{variables}} ignored).
function callKey(method, url) {
  const [p, q = ''] = String(url).split('?');
  const norm = p.replace(/\{\{\s*[$\w.-]+\s*\}\}/g, '*').replace(/\$\{?\w+\}?/g, '*').replace(/\/+$/, '').toLowerCase();
  const keys = q.split('&').map(kv => kv.split('=')[0]).filter(Boolean).sort().join('&');
  return `${method} ${norm}?${keys}`;
}

function prompt(existing) {
  const list = existing.map(t => `- ${t.method} ${t.url}  [${t.group}]${t.usedByBackend === false ? ' (debug extra, not a backend call)' : ''}`).join('\n');
  return `You are auditing the LillianCare backend (a Dart Serverpod server in ./lillian_care_core_server) for an API console.
The console has request templates for every HTTP call the backend makes to external services, and for the plain HTTP
routes other systems call INTO the backend. Find the calls that have NO template yet.

Existing templates (method, URL with {{variables}}, group):
${list}

Where to look (read only):
- Principa FHIR paths: lib/src/const/patient_management_endpoint.dart (PMSEndpoint) and every call site of
  FHIRApiCaller (lib/src/services/patient_management/fhir_api_caller.dart) — the call site tells you the HTTP method and body.
- Principa REST: lib/src/services/patient_management/rest_api_caller.dart and its callers.
- Personio: lib/src/services/personio/personio_api_caller.dart (+ personio_token_provider.dart).
- Brevo / Maps / other URLs: lib/src/const/external_endpoints.dart and their callers; FCM:
  lib/src/services/push_notification/; holidays: lib/src/endpoints/holidays/.
- Any other outbound call: grep lib/src for http.get/post/put/patch/delete, http.Request, Uri.parse('http.
- Inbound plain HTTP routes: pod.webServer.addRoute(...) in lib/server.dart and their Route classes (method, headers, body fields).
  Serverpod RPC endpoints are NOT in scope (the console reads those from generated code).

Rules for each missing call (put them in "added"):
- url: start with the base variable of its service: {{principaFhir}} (FHIR base ends with /, so "{{principaFhir}}Coverage?…"),
  {{principaRest}} (also ends with /), {{personio}} (= https://api.personio.de/v1, so "{{personio}}/company/…"), {{brevo}}
  (= https://api.brevo.com/v3), {{fcm}} (= https://fcm.googleapis.com/v1/projects/<id>), {{maps}} (= https://maps.googleapis.com/maps/api),
  {{holidays}} (= https://feiertage-api.de/api), inbound routes: {{coreWeb}} (web server) or {{coreApi}}.
  A service not listed: group "Other", full https URL, auth "none".
- Replace ids and values with {{camelCaseVariables}}; reuse existing names where they fit: {{lcAccountId}}, {{scheduleId}},
  {{slotId}}, {{pmsAppointmentId}}, {{principaPatientId}}, {{employeeId}}, {{lcPraxisId}}, {{fcmToken}}, {{testEmail}}, {{$date}},
  {{$datePlus7}}, {{$isoTimestamp}}, {{$guid}}. For "|" inside FHIR identifiers write it literally (app.lillian-care.de|{{lcAccountId}}).
- auth: principa for both Principa groups, personio, brevo, fcm, maps; inbound: coreApiKey (api-key header), lilli (X-Lilli-Secret) or none.
  Never put secrets, tokens or api keys in headers/body — auth is added by the console.
- headers: the content headers the backend sends (e.g. Accept / Content-Type application/fhir+json for FHIR).
- body: a realistic example built from the call site, with placeholders instead of real data. Never real patient data. Omit for GET.
- effect: "read", "write" (changes data) or "sends" (email/SMS/push reaching a person).
- source: file:line of the call site, relative to lillian_care_core_server/lib/src. doc: one or two sentences on what it does and when the backend calls it.
- Only calls that really exist in the code. Skip anything already covered by an existing template (same method + path + query keys).
In "stale" list existing templates whose call no longer exists in the code (url + reason); ignore the ones marked "debug extra". In "notes" summarise briefly.`;
}

let job = null;

function status() {
  if (!job) return { status: 'idle' };
  const { child, ...pub } = job;
  return pub;
}

function start(existing) {
  if (job && job.status === 'running') throw Object.assign(new Error('A scan is already running'), { status: 409 });
  if (!fs.existsSync(INV_CLAUDE_BIN)) throw Object.assign(new Error(`Claude Code not found at ${INV_CLAUDE_BIN} (set LC_CLAUDE_BIN)`), { status: 500 });
  if (!fs.existsSync(INV_CORE_DIR)) throw Object.assign(new Error(`LillianCare-Core not found at ${INV_CORE_DIR} (set LC_CORE_DIR)`), { status: 500 });

  const args = ['-p', prompt(existing), '--output-format', 'stream-json', '--verbose',
    '--json-schema', JSON.stringify(SCHEMA),
    '--tools', 'Read,Grep,Glob', '--restricted', '--strict-mcp-config', '--permission-mode', 'dontAsk',
    '--no-session-persistence', '--settings', INV_CODE_SETTINGS];
  job = { status: 'running', startedAt: new Date().toISOString(), finishedAt: null, log: [], error: null, costUsd: null, summary: null };
  const child = spawn(INV_CLAUDE_BIN, args, {
    cwd: INV_CORE_DIR, detached: true, stdio: ['ignore', 'pipe', 'pipe'],
    env: { ...process.env, PATH: `${path.dirname(INV_CLAUDE_BIN)}:${process.env.PATH || ''}` },
  });
  const current = job;
  current.child = child;

  let buf = '', stderr = '', result = null;
  child.stdout.on('data', (chunk) => {
    buf += chunk.toString();
    let nl;
    while ((nl = buf.indexOf('\n')) >= 0) {
      const line = buf.slice(0, nl);
      buf = buf.slice(nl + 1);
      let event;
      try { event = JSON.parse(line); } catch { continue; }
      current.log.push(...invCodeProgress(event));
      if (current.log.length > 300) current.log.splice(0, current.log.length - 300);
      if (event.type === 'result') result = event;
    }
  });
  child.stderr.on('data', (c) => { stderr = (stderr + c.toString()).slice(-4000); });
  const timer = setTimeout(() => { try { process.kill(-child.pid, 'SIGTERM'); } catch { /* gone */ } }, TIMEOUT_MS);

  child.on('close', (code) => {
    clearTimeout(timer);
    delete current.child;
    current.finishedAt = new Date().toISOString();
    if (current.status === 'cancelled') return;
    const out = result && result.structured_output;
    if (!result || result.is_error || !out) {
      current.status = 'failed';
      current.error = (result && (result.result || result.subtype)) || `Claude Code exited with code ${code}. ${stderr.trim().slice(-600)}`;
      return;
    }
    current.costUsd = result.total_cost_usd ?? null;
    try {
      current.summary = apply(out, existing);
      current.status = 'done';
    } catch (e) { current.status = 'failed'; current.error = e.message; }
  });
  child.on('error', (e) => { current.status = 'failed'; current.error = e.message; current.finishedAt = new Date().toISOString(); });
  return status();
}

function cancel() {
  if (!job || job.status !== 'running') return status();
  job.status = 'cancelled';
  try { process.kill(-job.child.pid, 'SIGTERM'); } catch { /* gone */ }
  return status();
}

// Validate Claude's entries and append the good ones to externals-generated.json.
function apply(out, existing) {
  const known = new Set(existing.map(t => callKey(t.method, t.url)));
  const generated = readGenerated();
  const added = [], skipped = [];
  for (const t of out.added || []) {
    const g = GROUPS[t.group];
    const why = !g ? `unknown group ${t.group}`
      : !METHODS.includes(t.method) ? `bad method ${t.method}`
      : !g.auth.includes(t.auth) ? `auth ${t.auth} not allowed for ${t.group}`
      : !g.prefixes.some(p => String(t.url).startsWith(p)) ? `URL must start with ${g.prefixes.join(' or ')}`
      : /\{\{(?![$\w.-]+\}\})/.test(t.url) ? 'malformed {{variable}}'
      : known.has(callKey(t.method, t.url)) ? 'already has a template'
      : null;
    if (why) { skipped.push({ name: t.name, url: t.url, reason: why }); continue; }
    known.add(callKey(t.method, t.url));
    const headers = {};
    for (const [k, v] of Object.entries(t.headers || {})) {
      if (/^(authorization|api-key|x-lilli-secret|cookie)$/i.test(k)) continue; // credentials come from the console
      headers[k] = String(v);
    }
    const entry = {
      id: `gen-${crypto.createHash('sha1').update(callKey(t.method, t.url)).digest('hex').slice(0, 10)}`,
      group: t.group, name: String(t.name).slice(0, 120), method: t.method, url: t.url, auth: t.auth, effect: t.effect,
      headers, ...(t.body !== undefined && t.body !== null && t.method !== 'GET' ? { body: t.body } : {}),
      source: t.source, doc: t.doc, usedByBackend: true, generated: true, addedAt: new Date().toISOString(),
    };
    generated.push(entry);
    added.push({ id: entry.id, group: entry.group, name: entry.name, method: entry.method, url: entry.url });
  }
  if (added.length) writeGenerated(generated);
  return { added, skipped, stale: out.stale || [], notes: out.notes || '' };
}

function removeGenerated(id) {
  const list = readGenerated();
  const next = list.filter(t => t.id !== id);
  if (next.length === list.length) throw Object.assign(new Error('Only templates added by a scan can be removed here'), { status: 400 });
  writeGenerated(next);
}

module.exports = { readGenerated, start, status, cancel, removeGenerated };
