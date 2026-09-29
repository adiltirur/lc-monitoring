const router = require('express').Router();
const fs = require('fs');
const path = require('path');
const { spawn } = require('child_process');
const { INV_CLAUDE_BIN, INV_CODE_SETTINGS, INV_CODE_TIMEOUT_MS, INV_CORE_DIR, INV_SHARED_MODELS_DIR, invAppendToSection, invCodeJobs, invCodeProgress, invCodePrompt, invPath, invReadState, invScrub, invSend, invToday, invWriteState } = require('../lib/investigations');

// ─── Investigations: code analysis + correspondence ─────────────────────────

router.post('/api/investigations/:file/code', (req, res) => {
  try {
    const p = invPath(req.params.file);
    const running = invCodeJobs[req.params.file];
    if (running && running.status === 'running') return res.status(409).json({ error: 'A code analysis is already running for this investigation' });
    if (!fs.existsSync(INV_CLAUDE_BIN)) return res.status(500).json({ error: `Claude Code not found at ${INV_CLAUDE_BIN} (set LC_CLAUDE_BIN)` });
    if (!fs.existsSync(INV_CORE_DIR)) return res.status(500).json({ error: `LillianCare-Core not found at ${INV_CORE_DIR} (set LC_CORE_DIR)` });

    const state = invReadState(req.params.file);
    const rawQuestion = String((req.body || {}).question || '').trim()
      || 'Which code paths could produce the problem described in the notes, and how should it be investigated?';
    const question = invScrub(state, s => s.run(rawQuestion)).output;
    const notes = invScrub(state, s => s.run(fs.readFileSync(p, 'utf8'))).output;
    invWriteState(req.params.file, state);

    const args = ['-p', invCodePrompt(notes, question), '--output-format', 'stream-json', '--verbose',
      '--tools', 'Read,Grep,Glob', '--restricted', '--strict-mcp-config', '--permission-mode', 'dontAsk',
      '--no-session-persistence', '--settings', INV_CODE_SETTINGS];
    if (fs.existsSync(INV_SHARED_MODELS_DIR)) args.push('--add-dir', INV_SHARED_MODELS_DIR);

    const job = { status: 'running', question, log: [], startedAt: new Date().toISOString(), finishedAt: null, error: null, costUsd: null };
    const child = spawn(INV_CLAUDE_BIN, args, {
      cwd: INV_CORE_DIR, detached: true, stdio: ['ignore', 'pipe', 'pipe'],
      env: { ...process.env, PATH: `${path.dirname(INV_CLAUDE_BIN)}:${process.env.PATH || ''}` },
    });
    job.child = child;
    invCodeJobs[req.params.file] = job;

    let buf = '';
    let stderr = '';
    let result = null;
    child.stdout.on('data', chunk => {
      buf += chunk.toString();
      let nl;
      while ((nl = buf.indexOf('\n')) >= 0) {
        const line = buf.slice(0, nl);
        buf = buf.slice(nl + 1);
        let event;
        try { event = JSON.parse(line); } catch { continue; }
        job.log.push(...invCodeProgress(event));
        if (job.log.length > 200) job.log.splice(0, job.log.length - 200);
        if (event.type === 'result') result = event;
      }
    });
    child.stderr.on('data', chunk => { stderr = (stderr + chunk.toString()).slice(-4000); });
    const timer = setTimeout(() => { try { process.kill(-child.pid, 'SIGTERM'); } catch {} }, INV_CODE_TIMEOUT_MS);

    child.on('close', code => {
      clearTimeout(timer);
      delete job.child;
      job.finishedAt = new Date().toISOString();
      if (job.status === 'cancelled') return;
      if (result && result.subtype === 'success' && !result.is_error && result.result) {
        job.costUsd = result.total_cost_usd ?? null;
        try {
          const md = fs.readFileSync(p, 'utf8');
          const shortQ = question.replace(/\s+/g, ' ').slice(0, 120);
          const block = `### ${invToday()}: ${shortQ}${question.length > 120 ? '…' : ''}\n\n${result.result.trim()}`;
          fs.writeFileSync(p, invAppendToSection(md, '## Code analysis', block));
          job.status = 'done';
        } catch (e) { job.status = 'failed'; job.error = e.message; }
      } else {
        job.status = 'failed';
        job.error = (result && (result.result || result.subtype)) || `Claude Code exited with code ${code}. ${stderr.trim().slice(-600)}`;
      }
    });
    child.on('error', e => { job.status = 'failed'; job.error = e.message; job.finishedAt = new Date().toISOString(); });

    res.json({ ok: true, question });
  } catch (e) { invSend(res, e); }
});

router.get('/api/investigations/:file/code', (req, res) => {
  try {
    invPath(req.params.file);
    const job = invCodeJobs[req.params.file];
    if (!job) return res.json({ job: null });
    const { child, ...rest } = job;
    res.json({ job: rest });
  } catch (e) { invSend(res, e); }
});

router.delete('/api/investigations/:file/code', (req, res) => {
  try {
    invPath(req.params.file);
    const job = invCodeJobs[req.params.file];
    if (!job || job.status !== 'running' || !job.child) return res.json({ ok: true });
    job.status = 'cancelled';
    try { process.kill(-job.child.pid, 'SIGTERM'); } catch {}
    res.json({ ok: true });
  } catch (e) { invSend(res, e); }
});

// Shows exactly what would be sent, without saving the mapping — free-text
// names the scrubber does not know can be spotted and added as terms first.
router.post('/api/investigations/:file/scrub-preview', (req, res) => {
  try {
    invPath(req.params.file);
    const state = invReadState(req.params.file);
    const scrubbed = invScrub(state, s => s.run(String((req.body || {}).text || '')));
    res.json({ output: scrubbed.output, counts: scrubbed.counts });
  } catch (e) { invSend(res, e); }
});

// Replies from Principa/Siegele (or what we sent them): scrubbed, filed under
// "## Correspondence" in the note, and added to the AI chat as evidence.
router.post('/api/investigations/:file/correspondence', (req, res) => {
  try {
    const p = invPath(req.params.file);
    const { direction, party, text } = req.body || {};
    if (!String(text || '').trim()) return res.status(400).json({ error: 'Empty correspondence' });
    const who = String(party || 'vendor').trim().slice(0, 60);
    const label = direction === 'sent' ? `Sent to ${who}` : `Received from ${who}`;
    const state = invReadState(req.params.file);
    const scrubbed = invScrub(state, s => s.run(String(text)));
    const quoted = scrubbed.output.trim().split('\n').map(l => `> ${l}`).join('\n');
    fs.writeFileSync(p, invAppendToSection(fs.readFileSync(p, 'utf8'), '## Correspondence', `### ${invToday()}: ${label}\n\n${quoted}`));
    state.chat.push({ role: 'user', kind: 'correspondence', text: `${label} (scrubbed):\n\n${scrubbed.output.trim()}`, at: new Date().toISOString() });
    invWriteState(req.params.file, state);
    res.json({ ok: true, counts: scrubbed.counts });
  } catch (e) { invSend(res, e); }
});

module.exports = router;
