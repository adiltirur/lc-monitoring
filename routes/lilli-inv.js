const router = require('express').Router();
const fs = require('fs');
const path = require('path');
const { spawn } = require('child_process');
const { INV_CLAUDE_BIN, INV_DIR, invAppendLog, invAppendToSection, invParse, invPath, invReadState, invScrub, invSlug, invToday, invWriteState } = require('../lib/investigations');
const { lilliSend } = require('../lib/lilli');

const ROOT = path.join(__dirname, '..'); // helper/

// ─── Lilli investigations (/api/lilli/inv/*, Investigate tab in #lilli) ─────
// Ask a question about Lilli staging; a headless Claude Code session in the Lilli repo answers it.
// Its sandbox: --restricted (file tools confined to the Lilli repo, so helper/.env and the scrub
// mappings are out of reach), Bash only for the read-only lilli.js commands and read-only git
// (--permission-mode dontAsk refuses everything else, including deploy/rollback). lilli.js output
// is already scrubbed. Each investigation is a note in ../investigations/ (YYYY-MM-DD-lilli-*.md),
// so a Claude Code session can pick up the fix brief. Follow-ups resume the same session.
const LILLI_REPO_DIR = process.env.LILLI_REPO || path.join(ROOT, '..', 'Lilli');
const LILLI_CLI = path.join(ROOT, 'scripts', 'lilli.js');
const LILLI_INV_TIMEOUT_MS = 15 * 60 * 1000;
const LILLI_INV_READ_CMDS = ['status', 'logs', 'calls', 'call', 'sql', 'releases', 'help'];
const LILLI_INV_SETTINGS = JSON.stringify({
  permissions: {
    allow: [
      ...LILLI_INV_READ_CMDS.map(c => `Bash(node ${LILLI_CLI} ${c}:*)`),
      'Bash(git log:*)', 'Bash(git show:*)', 'Bash(git diff:*)', 'Bash(git blame:*)', 'Bash(git status:*)',
    ],
    deny: [
      `Bash(node ${LILLI_CLI} deploy:*)`, `Bash(node ${LILLI_CLI} rollback:*)`,
      'Read(**/.env)', 'Read(**/.env.*)', 'Read(**/*.pem)', 'Read(**/*.key)',
    ],
  },
});
const lilliInvJobs = {};

function lilliInvFile(file) {
  if (!/^\d{4}-\d{2}-\d{2}-lilli-[a-z0-9-]+\.md$/.test(file || '')) throw Object.assign(new Error('Invalid Lilli investigation file'), { status: 400 });
  return invPath(file);
}

function lilliInvPrompt(question, first) {
  const cli = `node ${LILLI_CLI}`;
  if (!first) {
    return `Follow-up question from the user:\n\n${question}\n\nInvestigate further if needed, then answer in the same format. If the root cause or the fix changed, give the complete updated fix brief.`;
  }
  return `You are debugging Lilli, a voice survey platform (Next.js app in app/, voice/WebSocket server in app/server/ws-server.ts, Prisma schema in app/prisma/schema.prisma). The current directory is the Lilli repo. Read app/CLAUDE.md first if you need orientation.

The live system is Lilli staging. You can observe it ONLY through these read-only commands (run them with Bash, exactly in this form, no pipes):
  ${cli} status                                  PM2 processes, live commit, health
  ${cli} logs --lines N [--ws|--web] [--errors] [--grep REGEX]
  ${cli} calls [--since 6h] [--status S] [--outcome O] [--errors] [--limit N]
  ${cli} call <id|externalId|callSid> [--logs]   one call: facts, event timeline, matching log lines
  ${cli} sql "SELECT …"                          read-only Postgres ("Call", "Assistant", "Survey", "Workflow", "User", … camelCase columns in double quotes)
  ${cli} releases
You may also use read-only git (git log/show/diff/blame) and Read/Grep/Glob on the repo. You cannot change anything, deploy, or run other commands.

All output from those commands is scrubbed: [REDACTED], [PHONE_1], [PERSON_1] etc. stand for removed patient data. Do not try to recover it. The live commit (from status) can differ from the checked-out code; check with git when line numbers matter. PM2 logs may lack timestamps and contain lines from older builds (stack-trace line numbers that don't match the current code are a hint).

Work like a senior engineer on call: establish what happened (calls, logs, timeline), find the failing component, trace it in the code, and confirm the root cause with evidence rather than guessing. Keep going until you can point at the code, or you have ruled out the obvious causes.

QUESTION:
${question}

Reply in markdown with exactly these sections:
#### Summary
Two or three sentences: what is wrong and why.
#### Evidence
The log lines, call ids, timestamps and query results that show it (scrubbed as received).
#### Root cause
file:line references, and your confidence (high / medium / low) with the reason.
#### Fix brief
Self-contained instructions for another Claude Code session that will make the fix: what to change and where, edge cases, how to test locally, and how to verify on staging afterwards with the ${cli} commands above. Name the evidence (call ids, log messages) to check against.
#### Open questions
What you could not determine, and what would settle it.`;
}

function lilliInvProgress(event) {
  if (event.type !== 'assistant') return [];
  return (event.message.content || []).filter(c => c.type === 'tool_use').map(c => {
    const i = c.input || {};
    if (c.name === 'Bash') return String(i.command || '').replace(`node ${LILLI_CLI}`, 'lilli');
    const target = i.file_path || i.pattern || i.path || '';
    return `${c.name} ${String(target).replace(LILLI_REPO_DIR + '/', '')}`.trim();
  });
}

function lilliInvStart(file, question) {
  const p = lilliInvFile(file);
  const state = invReadState(file);
  const first = !state.lilliSessionId;
  const args = ['-p', lilliInvPrompt(question, first), '--output-format', 'stream-json', '--verbose',
    '--tools', 'Read,Grep,Glob,Bash', '--restricted', '--strict-mcp-config', '--permission-mode', 'dontAsk',
    '--settings', LILLI_INV_SETTINGS];
  if (!first) args.push('--resume', state.lilliSessionId);

  const job = { status: 'running', question, log: [], startedAt: new Date().toISOString(), finishedAt: null, error: null, costUsd: null };
  const child = spawn(INV_CLAUDE_BIN, args, {
    cwd: LILLI_REPO_DIR, detached: true, stdio: ['ignore', 'pipe', 'pipe'],
    env: { ...process.env, PATH: `${path.dirname(INV_CLAUDE_BIN)}:${process.env.PATH || ''}` },
  });
  job.child = child;
  lilliInvJobs[file] = job;

  let buf = '';
  let stderr = '';
  let result = null;
  let sessionId = null;
  child.stdout.on('data', chunk => {
    buf += chunk.toString();
    let nl;
    while ((nl = buf.indexOf('\n')) >= 0) {
      const line = buf.slice(0, nl);
      buf = buf.slice(nl + 1);
      let event;
      try { event = JSON.parse(line); } catch { continue; }
      if (event.session_id) sessionId = event.session_id;
      job.log.push(...lilliInvProgress(event));
      if (job.log.length > 300) job.log.splice(0, job.log.length - 300);
      if (event.type === 'result') result = event;
    }
  });
  child.stderr.on('data', chunk => { stderr = (stderr + chunk.toString()).slice(-4000); });
  const timer = setTimeout(() => { try { process.kill(-child.pid, 'SIGTERM'); } catch {} }, LILLI_INV_TIMEOUT_MS);

  child.on('close', code => {
    clearTimeout(timer);
    delete job.child;
    job.finishedAt = new Date().toISOString();
    if (job.status === 'cancelled') return;
    if (result && result.subtype === 'success' && !result.is_error && result.result) {
      job.costUsd = result.total_cost_usd ?? null;
      try {
        const s = invReadState(file);
        if (sessionId) s.lilliSessionId = sessionId;
        invWriteState(file, s);
        const time = new Intl.DateTimeFormat('de-DE', { timeZone: 'Europe/Berlin', hour: '2-digit', minute: '2-digit' }).format(new Date());
        const shortQ = question.replace(/\s+/g, ' ').slice(0, 120);
        // Keep the answer from its first section heading; drop any "writing it up now" preamble.
        const answer = result.result.trim();
        const start = answer.search(/^#### /m);
        const block = `### ${invToday()} ${time}: ${shortQ}${question.length > 120 ? '…' : ''}\n\n${start > 0 ? answer.slice(start) : answer}`;
        fs.writeFileSync(p, invAppendToSection(fs.readFileSync(p, 'utf8'), '## Findings', block));
        job.status = 'done';
      } catch (e) { job.status = 'failed'; job.error = e.message; }
    } else {
      job.status = 'failed';
      job.error = (result && (result.result || result.subtype)) || `Claude Code exited with code ${code}. ${stderr.trim().slice(-600)}`;
    }
  });
  child.on('error', e => { job.status = 'failed'; job.error = e.message; job.finishedAt = new Date().toISOString(); });
  return job;
}

router.get('/api/lilli/inv', (req, res) => {
  try {
    const files = fs.existsSync(INV_DIR) ? fs.readdirSync(INV_DIR).filter(f => /^\d{4}-\d{2}-\d{2}-lilli-[a-z0-9-]+\.md$/.test(f)) : [];
    const items = files.map(f => {
      const md = fs.readFileSync(path.join(INV_DIR, f), 'utf8');
      const job = lilliInvJobs[f];
      return { file: f, ...invParse(md), mtime: fs.statSync(path.join(INV_DIR, f)).mtimeMs, running: !!(job && job.status === 'running') };
    }).sort((a, b) => b.mtime - a.mtime);
    res.json({ items });
  } catch (e) { lilliSend(res, e); }
});

// Body: { question, file? }. Without file a new investigation note is created.
router.post('/api/lilli/inv', (req, res) => {
  try {
    if (!fs.existsSync(INV_CLAUDE_BIN)) return res.status(500).json({ error: `Claude Code not found at ${INV_CLAUDE_BIN} (set LC_CLAUDE_BIN)` });
    if (!fs.existsSync(LILLI_REPO_DIR)) return res.status(500).json({ error: `Lilli repo not found at ${LILLI_REPO_DIR} (set LILLI_REPO)` });
    const raw = String((req.body || {}).question || '').trim();
    if (!raw) return res.status(400).json({ error: 'Ask a question' });
    let file = (req.body || {}).file;
    if (file) {
      lilliInvFile(file);
      const running = lilliInvJobs[file];
      if (running && running.status === 'running') return res.status(409).json({ error: 'This investigation is already running' });
    }
    // Questions can contain names or numbers: scrub before they reach the note or the model.
    const state = file ? invReadState(file) : { mapping: [], terms: [], chat: [] };
    const question = invScrub(state, s => s.run(raw)).output.trim();
    if (!file) {
      const flat = question.replace(/\s+/g, ' ');
      const title = flat.length <= 80 ? flat : `${flat.slice(0, 80).replace(/\s+\S*$/, '')}…`;
      file = `${invToday()}-lilli-${invSlug(title).slice(0, 50).replace(/-+$/, '')}.md`;
      let n = 2;
      while (fs.existsSync(path.join(INV_DIR, file))) file = `${invToday()}-lilli-${invSlug(title).slice(0, 46).replace(/-+$/, '')}-${n++}.md`;
      fs.writeFileSync(path.join(INV_DIR, file), `# Lilli: ${title}\n\n**Status:** OPEN\n**System:** Lilli staging\n\n## Question\n\n${question}\n\n## Findings\n\n## Log\n\n- ${invToday()}: Opened from LC Helper (Lilli, Investigate tab).\n`);
    }
    invWriteState(file, state);
    lilliInvStart(file, question);
    res.json({ ok: true, file });
  } catch (e) { lilliSend(res, e); }
});

router.get('/api/lilli/inv/:file', (req, res) => {
  try {
    const p = lilliInvFile(req.params.file);
    const md = fs.readFileSync(p, 'utf8');
    const job = lilliInvJobs[req.params.file];
    const { child, ...rest } = job || {};
    res.json({ file: req.params.file, md, ...invParse(md), job: job ? rest : null, canFollowUp: !!invReadState(req.params.file).lilliSessionId });
  } catch (e) { lilliSend(res, e); }
});

router.delete('/api/lilli/inv/:file/job', (req, res) => {
  try {
    lilliInvFile(req.params.file);
    const job = lilliInvJobs[req.params.file];
    if (!job || !job.child) return res.status(400).json({ error: 'Nothing running' });
    job.status = 'cancelled';
    try { process.kill(-job.child.pid, 'SIGTERM'); } catch {}
    res.json({ ok: true });
  } catch (e) { lilliSend(res, e); }
});

router.post('/api/lilli/inv/:file/status', (req, res) => {
  try {
    const p = lilliInvFile(req.params.file);
    const status = String((req.body || {}).status || '').toUpperCase();
    if (!['OPEN', 'CLOSED'].includes(status)) return res.status(400).json({ error: 'status must be OPEN or CLOSED' });
    const md = fs.readFileSync(p, 'utf8').replace(/^\*\*Status:\*\*.*$/m, `**Status:** ${status}`);
    fs.writeFileSync(p, invAppendLog(md, `Marked ${status} in LC Helper.`));
    res.json({ ok: true });
  } catch (e) { lilliSend(res, e); }
});

module.exports = router;
