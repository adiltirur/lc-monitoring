const fs = require('fs');
const path = require('path');
const { getPool } = require('./db');
const { DB_SCHEMA_CONTEXT } = require('./ai');

const ROOT = path.join(__dirname, '..'); // helper/

// ─── Investigations: shared helpers (routes/investigations*.js, routes/lilli-inv.js)
// Investigation notes live as markdown in the shared folder next to this repo
// (also read by Claude Code sessions). Everything the AI sees — notes, pasted
// logs, query results — is scrubbed first; the placeholder→original mapping and
// the scrubbed AI conversation stay in INV_STATE_DIR (gitignored, local only).
// The AI only proposes SQL; a query runs when the user clicks Run, inside a
// READ ONLY transaction with a statement timeout and a row cap.
const INV_DIR = process.env.LC_INVESTIGATIONS_DIR || path.join(ROOT, '..', 'investigations');
const INV_PLAYBOOK_DIR = path.join(INV_DIR, 'playbooks');
const INV_SCRUBBER_FILE = path.join(INV_DIR, 'tools', 'principa-log-scrubber.html');
const INV_STATE_DIR = path.join(ROOT, '.investigations-state');
const INV_FILE_RE = /^\d{4}-\d{2}-\d{2}-[a-z0-9-]+\.md$/;
const INV_PLAYBOOK_RE = /^[a-z0-9-]+\.md$/;
const INV_MODEL = process.env.LC_INVESTIGATION_MODEL || 'eu.anthropic.claude-sonnet-4-5-20250929-v1:0';
const INV_MAX_ROWS = 200;
const INV_TIMEOUT_MS = 20000;
const INV_AI_RESULT_CHARS = 30000;

// The scrubber's single source is the standalone offline tool; its core sits
// between CORE-START/CORE-END markers. Reloaded when the file changes.
let invScrubberCache = { mtimeMs: 0, factory: null };
function invCreateScrubber(options) {
  const stat = fs.statSync(INV_SCRUBBER_FILE);
  if (!invScrubberCache.factory || invScrubberCache.mtimeMs !== stat.mtimeMs) {
    const html = fs.readFileSync(INV_SCRUBBER_FILE, 'utf8');
    const start = html.indexOf('// CORE-START');
    const end = html.indexOf('// CORE-END');
    if (start < 0 || end < 0) throw new Error(`Scrubber core markers missing in ${INV_SCRUBBER_FILE}`);
    const core = html.slice(start, end);
    invScrubberCache = { mtimeMs: stat.mtimeMs, factory: new Function(`${core}; return createScrubber;`)() };
  }
  return invScrubberCache.factory(options);
}

function invPath(file) {
  if (!INV_FILE_RE.test(file || '')) throw Object.assign(new Error('Invalid investigation file name'), { status: 400 });
  return path.join(INV_DIR, file);
}

function invParse(md) {
  const title = (md.match(/^#\s+(.+)$/m) || [])[1] || '';
  const status = ((md.match(/^\*\*Status:\*\*\s*(.+)$/m) || [])[1] || '').trim();
  return { title, status };
}

function invStatePath(file) { return path.join(INV_STATE_DIR, `${file}.json`); }

function invReadState(file) {
  try { return JSON.parse(fs.readFileSync(invStatePath(file), 'utf8')); }
  catch { return { mapping: [], terms: [], chat: [] }; }
}

function invWriteState(file, state) {
  fs.mkdirSync(INV_STATE_DIR, { recursive: true, mode: 0o700 });
  fs.writeFileSync(invStatePath(file), JSON.stringify(state, null, 2), { mode: 0o600 });
}

// One scrubber per call, seeded with the investigation's saved mapping so
// placeholders stay stable across queries and pasted logs.
function invScrub(state, fn) {
  const scrubber = invCreateScrubber({ state: { mapping: state.mapping }, terms: state.terms || [] });
  const result = fn(scrubber);
  state.mapping = scrubber.exportState().mapping;
  return result;
}

function invSlug(title) {
  return title.toLowerCase()
    .replace(/ä/g, 'ae').replace(/ö/g, 'oe').replace(/ü/g, 'ue').replace(/ß/g, 'ss')
    .replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 60) || 'investigation';
}

function invToday() {
  return new Intl.DateTimeFormat('en-CA', { timeZone: 'Europe/Berlin' }).format(new Date());
}

function invAppendLog(md, entry) {
  const line = `- ${invToday()}: ${entry.replace(/\s*\n\s*/g, ' ').trim()}`;
  const m = md.match(/^## Log\s*$/m);
  if (!m) return `${md.replace(/\s*$/, '')}\n\n## Log\n\n${line}\n`;
  const after = md.slice(m.index + m[0].length);
  const next = after.search(/^## /m);
  const sectionEnd = next < 0 ? md.length : m.index + m[0].length + next;
  const head = md.slice(0, sectionEnd).replace(/\s*$/, '');
  const tail = md.slice(sectionEnd);
  return `${head}\n${line}\n${tail ? `\n${tail}` : ''}`;
}

// Read-only by construction: wrapped in SELECT * FROM (...) (single statement,
// no COMMIT escape), extended protocol (Postgres rejects multiple commands),
// READ ONLY transaction (rejects writes incl. data-modifying CTEs), timeout.
async function invReadOnlyQuery(req, sql) {
  const text = String(sql || '').trim().replace(/;\s*$/, '');
  if (!text) throw Object.assign(new Error('No SQL provided'), { status: 400 });
  const client = await getPool(req).connect();
  try {
    await client.query('BEGIN TRANSACTION READ ONLY');
    await client.query(`SET LOCAL statement_timeout = ${INV_TIMEOUT_MS}`);
    const result = await client.query({
      text: `SELECT * FROM (\n${text}\n) AS inv_q LIMIT ${INV_MAX_ROWS + 1}`,
      values: [],
      queryMode: 'extended',
    });
    const truncated = result.rows.length > INV_MAX_ROWS;
    return { rows: truncated ? result.rows.slice(0, INV_MAX_ROWS) : result.rows, truncated };
  } finally {
    await client.query('ROLLBACK').catch(() => {});
    client.release();
  }
}

// The AI writes SQL with placeholders (e.g. ILIKE '%[EMAIL_1]%'); swap in the
// real values locally just before running. Quotes are doubled because the
// placeholders sit inside string literals.
function invUnscrubSql(state, sql) {
  let filled = 0;
  let out = sql;
  for (const [t, original] of [...state.mapping].sort((a, b) => b[0].length - a[0].length)) {
    if (!out.includes(t)) continue;
    out = out.split(t).join(String(original).replace(/'/g, "''"));
    filled++;
  }
  return { sql: out, filled };
}

function invClip(value, max) {
  return value.length > max ? `${value.slice(0, max)}… [truncated ${value.length - max} chars]` : value;
}

const INV_EXTRA_SCHEMA = `
MORE TABLES USED IN INVESTIGATIONS:

core_message_outbox (id uuid, channel [0=email 1=sms], payload [text JSON: to, templateId, params], status [0=pending 1=sending 2=sent 3=failed 4=dead], "attemptCount", "lastHttpStatus", "lastErrorBody", "createdAt", "sentAt", "correlationId", "idempotencyKey")

core_fhir_message_inbox (id uuid, payload [text JSON FHIR Bundle from Principa: entry[0]=MessageHeader (id = "<principaApptId>_<version>", eventCoding.code = appointment-create|update|cancel), entry[1]=Appointment (id = "<principaPatientId>_<principaApptId>", identifier[0].value = apkNr, status, start, participant)], status [0=pending 1=processing 2=processed 3=failed], "correlationId", "lastError", "createdAt", "processedAt", "failedAt")
  Extract with payload::jsonb #>> '{entry,1,resource,status}' etc.

ID CONVENTION: app_user_appointment."appointmentId" / guest_appointment."appointmentId" = Principa apkNr (e.g. BB126000026); "pmsAppointmentId" = "<principaPatientId>_<principaApptId>" (e.g. 210922_8783033) = FHIR Appointment.id. notification_log."activityId" = apkNr.

app_user_reserved_appointment ("reservationId", "slotId", category, "praxisId", "startTime", "createdAt", "validTill")
app_user_appointment_request ("appointmentId", ...) — exists when the app modified an appointment; FHIR handler then skips it
app_user_appointment_cancellation_reason (id, "userId", reason [json array], "createdAt")
`;

const INV_REPLY_TOOL = {
  toolSpec: {
    name: 'reply',
    description: 'Reply to the engineer investigating a production issue.',
    inputSchema: {
      json: {
        type: 'object',
        properties: {
          message: { type: 'string', description: 'Your analysis in concise markdown: what the evidence shows, what is still unknown, what to check next.' },
          proposed_sql: { type: 'string', description: 'ONE read-only PostgreSQL SELECT to run next, or omit when no query is needed. It runs inside SELECT * FROM (...) LIMIT 200, so no trailing semicolon.' },
          purpose: { type: 'string', description: 'One sentence: what the proposed query will confirm or rule out.' },
          log_entry: { type: 'string', description: 'Optional one-line finding worth recording in the investigation log. Only when something was established.' },
        },
        required: ['message'],
      },
    },
  },
};

function invSystemPrompt(env, scrubbedNotes, playbooks) {
  return `You are helping an engineer investigate a production issue in the LillianCare healthcare platform (Serverpod backend, Postgres, Principa PMS via FHIR).

HOW THIS WORKS
- You cannot run anything. Propose at most ONE read-only SELECT at a time via proposed_sql; the engineer reviews, may edit, and runs it. You then receive the result.
- All data you see has been scrubbed. Placeholders like [PERSON_1], [EMAIL_2], [DOB], [FREE_TEXT 20 chars] stand for redacted values; the same placeholder always means the same value. Never ask for the real values — reason with the placeholders and IDs.
- Numbered placeholders ([EMAIL_1], [PERSON_2], [TERM_1], …) can be used inside SQL string literals, e.g. WHERE lower(email) = lower('[EMAIL_1]'); they are replaced with the real values locally before the query runs. Prefer internal IDs when you have them.
- Connected environment: ${env}. DB timestamps are UTC; Principa payload times are Europe/Berlin local time.
- Be precise and evidence-driven: cite IDs and timestamps from results. Say clearly when something is a hypothesis.
- Keep queries narrow (filter by IDs and time windows, select only needed columns). Avoid full scans on huge log tables.
- When the evidence establishes something, put a one-line finding in log_entry.
- The notes may contain a "## Code analysis" section (a code-level briefing produced by reading the backend source) and a "## Correspondence" section (replies from Principa/Siegele or the practice). Treat them as evidence; cite code paths from the briefing when explaining behaviour.

${DB_SCHEMA_CONTEXT}
${INV_EXTRA_SCHEMA}

PLAYBOOKS (known flows and proven queries):
${playbooks || '(none)'}

CURRENT INVESTIGATION NOTES (scrubbed):
${scrubbedNotes}`;
}

// Bedrock Converse needs alternating roles starting with 'user'.
function invToConverseMessages(chat) {
  const out = [];
  for (const turn of chat) {
    let text = turn.text || '';
    if (turn.role === 'assistant' && turn.proposedSql) {
      text += `\n\nProposed query (${turn.purpose || 'no purpose given'}):\n${turn.proposedSql}`;
    }
    const last = out[out.length - 1];
    if (last && last.role === turn.role) last.content[0].text += `\n\n${text}`;
    else out.push({ role: turn.role, content: [{ text }] });
  }
  while (out.length && out[0].role !== 'user') out.shift();
  return out;
}

function invReadPlaybooks() {
  try {
    return fs.readdirSync(INV_PLAYBOOK_DIR).filter(f => INV_PLAYBOOK_RE.test(f)).sort()
      .map(f => ({ file: f, content: fs.readFileSync(path.join(INV_PLAYBOOK_DIR, f), 'utf8') }));
  } catch { return []; }
}

function invSend(res, e) {
  res.status(e.status || 500).json({ error: e.message });
}

// ─── Investigations: code analysis + correspondence ─────────────────────────
// Code analysis runs a headless Claude Code session on LillianCare-Core with
// read-only file tools only (--restricted, --tools Read,Grep,Glob) and a deny
// list for secrets. Its prompt contains the scrubbed notes + scrubbed question;
// the briefing is appended to the note's "## Code analysis" section, where the
// Bedrock chat picks it up as context. One job per investigation, in memory.
const INV_CORE_DIR = process.env.LC_CORE_DIR || path.join(ROOT, '..', 'LillianCare-Core');
const INV_SHARED_MODELS_DIR = path.join(ROOT, '..', 'LillianCare-Shared-Models');
const INV_CLAUDE_BIN = process.env.LC_CLAUDE_BIN || path.join(process.env.HOME || '', '.local', 'bin', 'claude');
const INV_CODE_TIMEOUT_MS = 10 * 60 * 1000;
const INV_CODE_SETTINGS = JSON.stringify({
  permissions: { deny: ['Read(**/passwords.yaml)', 'Read(**/.env)', 'Read(**/.env.*)', 'Read(**/.fcm_service_account.json)', 'Read(**/*.pem)', 'Read(**/*.p8)'] },
});
const invCodeJobs = {};

// Inserts `block` at the end of `heading`'s section, creating the section right
// before "## Log" (which stays last) when it does not exist yet.
function invAppendToSection(md, heading, block) {
  const m = md.match(new RegExp(`^${heading.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\s*$`, 'm'));
  if (m) {
    const after = md.slice(m.index + m[0].length);
    const next = after.search(/^## /m);
    const end = next < 0 ? md.length : m.index + m[0].length + next;
    return `${md.slice(0, end).replace(/\s*$/, '')}\n\n${block.trim()}\n${end < md.length ? `\n${md.slice(end)}` : ''}`;
  }
  const log = md.search(/^## Log\s*$/m);
  const section = `${heading}\n\n${block.trim()}\n`;
  if (log < 0) return `${md.replace(/\s*$/, '')}\n\n${section}`;
  return `${md.slice(0, log)}${section}\n${md.slice(log)}`;
}

function invCodePrompt(notes, question) {
  return `You are analysing the LillianCare backend codebase (this directory) to support a production investigation. You can only read code. Never open config/passwords.yaml, .env files or other secrets.

INVESTIGATION NOTES (scrubbed — placeholders like [PERSON_1] are redacted values):
${notes}

QUESTION:
${question}

Trace the relevant flows in the code the way a senior engineer would: find the entry points, follow the calls, and note guards, deduplication, status mappings and the exact conditions under which side effects (emails, pushes, DB writes, PMS calls) happen.

Reply with a concise markdown briefing (max ~700 words), using exactly these sections:
#### Relevant code paths
file:line references and what each does for this problem.
#### How the symptom can arise
Ranked hypotheses; for each, the evidence in the data that would confirm or rule it out.
#### Tables and fields to check
Table names, columns, enum values (with their integer values).
#### Suggested first queries
One to three narrow PostgreSQL SELECTs ("camelCase" columns quoted, timestamps are UTC). Placeholders like [EMAIL_1] may be used in string literals.
#### Open questions
What the code alone cannot answer.

Do not include patient data.`;
}

function invCodeProgress(event) {
  if (event.type !== 'assistant') return [];
  return (event.message.content || []).filter(c => c.type === 'tool_use').map(c => {
    const i = c.input || {};
    const target = i.file_path || i.pattern || i.path || '';
    return `${c.name} ${String(target).replace(INV_CORE_DIR + '/', '')}`.trim();
  });
}

module.exports = { INV_AI_RESULT_CHARS, INV_CLAUDE_BIN, INV_CODE_SETTINGS, INV_CODE_TIMEOUT_MS, INV_CORE_DIR, INV_DIR, INV_FILE_RE, INV_MAX_ROWS, INV_MODEL, INV_PLAYBOOK_DIR, INV_PLAYBOOK_RE, INV_REPLY_TOOL, INV_SHARED_MODELS_DIR, invAppendLog, invAppendToSection, invClip, invCodeJobs, invCodeProgress, invCodePrompt, invParse, invPath, invReadOnlyQuery, invReadPlaybooks, invReadState, invScrub, invSend, invSlug, invSystemPrompt, invToConverseMessages, invToday, invUnscrubSql, invWriteState };
