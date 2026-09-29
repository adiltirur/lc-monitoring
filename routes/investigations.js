const router = require('express').Router();
const fs = require('fs');
const path = require('path');
const { ConverseCommand } = require('@aws-sdk/client-bedrock-runtime');
const { INV_AI_RESULT_CHARS, INV_DIR, INV_FILE_RE, INV_MAX_ROWS, INV_MODEL, INV_PLAYBOOK_DIR, INV_PLAYBOOK_RE, INV_REPLY_TOOL, invAppendLog, invClip, invParse, invPath, invReadOnlyQuery, invReadPlaybooks, invReadState, invScrub, invSend, invSlug, invSystemPrompt, invToConverseMessages, invToday, invUnscrubSql, invWriteState } = require('../lib/investigations');
const { bedrockClient } = require('../lib/ai');

// ─── Routes: Investigations (/api/investigations/*, view #investigations) ────
// Notes, scrubbing, state and the read-only query guard live in lib/investigations.js.

router.get('/api/investigations', (req, res) => {
  try {
    fs.mkdirSync(INV_DIR, { recursive: true });
    const items = fs.readdirSync(INV_DIR).filter(f => INV_FILE_RE.test(f)).map(file => {
      const md = fs.readFileSync(path.join(INV_DIR, file), 'utf8');
      return { file, date: file.slice(0, 10), ...invParse(md), modifiedAt: fs.statSync(path.join(INV_DIR, file)).mtime };
    }).sort((a, b) => b.file.localeCompare(a.file));
    const playbooks = invReadPlaybooks().map(p => ({ file: p.file, title: invParse(p.content).title || p.file }));
    res.json({ dir: INV_DIR, items, playbooks, model: INV_MODEL });
  } catch (e) { invSend(res, e); }
});

router.post('/api/investigations', (req, res) => {
  try {
    const title = String((req.body || {}).title || '').trim();
    if (!title) return res.status(400).json({ error: 'Title required' });
    const today = invToday();
    let file = `${today}-${invSlug(title)}.md`;
    for (let i = 2; fs.existsSync(path.join(INV_DIR, file)); i++) file = `${today}-${invSlug(title)}-${i}.md`;
    const md = `# ${title}\n\n**Status:** OPEN\n\n## Summary\n\n_TBD_\n\n## Open questions\n\n## Follow-ups\n\n## Log\n\n- ${today}: Investigation opened.\n`;
    fs.mkdirSync(INV_DIR, { recursive: true });
    fs.writeFileSync(invPath(file), md);
    res.json({ file });
  } catch (e) { invSend(res, e); }
});

router.get('/api/investigations/playbooks/:file', (req, res) => {
  try {
    if (!INV_PLAYBOOK_RE.test(req.params.file)) return res.status(400).json({ error: 'Invalid playbook name' });
    res.json({ file: req.params.file, content: fs.readFileSync(path.join(INV_PLAYBOOK_DIR, req.params.file), 'utf8') });
  } catch (e) { invSend(res, e); }
});

router.get('/api/investigations/:file', (req, res) => {
  try {
    const content = fs.readFileSync(invPath(req.params.file), 'utf8');
    const state = invReadState(req.params.file);
    res.json({ file: req.params.file, content, ...invParse(content), chat: state.chat, terms: state.terms || [], mappingCount: state.mapping.length });
  } catch (e) { invSend(res, e); }
});

router.put('/api/investigations/:file', (req, res) => {
  try {
    const content = String((req.body || {}).content || '');
    if (!content.trim()) return res.status(400).json({ error: 'Refusing to save empty notes' });
    fs.writeFileSync(invPath(req.params.file), content);
    res.json({ ok: true, ...invParse(content) });
  } catch (e) { invSend(res, e); }
});

router.post('/api/investigations/:file/log', (req, res) => {
  try {
    const entry = String((req.body || {}).entry || '').trim();
    if (!entry) return res.status(400).json({ error: 'Empty log entry' });
    const p = invPath(req.params.file);
    const content = invAppendLog(fs.readFileSync(p, 'utf8'), entry);
    fs.writeFileSync(p, content);
    res.json({ ok: true, content });
  } catch (e) { invSend(res, e); }
});

// Extra redaction terms (names etc.) — PII, so kept in the local state only.
router.put('/api/investigations/:file/terms', (req, res) => {
  try {
    invPath(req.params.file);
    const state = invReadState(req.params.file);
    state.terms = (Array.isArray(req.body.terms) ? req.body.terms : []).map(t => String(t).trim()).filter(t => t.length >= 2);
    invWriteState(req.params.file, state);
    res.json({ ok: true, terms: state.terms });
  } catch (e) { invSend(res, e); }
});

router.get('/api/investigations/:file/mapping', (req, res) => {
  try {
    invPath(req.params.file);
    res.json({ mapping: invReadState(req.params.file).mapping });
  } catch (e) { invSend(res, e); }
});

router.delete('/api/investigations/:file/chat', (req, res) => {
  try {
    invPath(req.params.file);
    const state = invReadState(req.params.file);
    state.chat = [];
    invWriteState(req.params.file, state);
    res.json({ ok: true });
  } catch (e) { invSend(res, e); }
});

// Runs an (AI-proposed or hand-written) query read-only. Raw rows go back to
// this local UI only; the scrubbed rows are what gets added to the AI chat.
router.post('/api/investigations/:file/query', async (req, res) => {
  try {
    invPath(req.params.file);
    const sql = String((req.body || {}).sql || '');
    const env = String(req.headers['x-env'] || 'unknown');
    const state = invReadState(req.params.file);
    let turnText;
    let payload;
    try {
      const unscrubbed = invUnscrubSql(state, sql);
      const { rows, truncated } = await invReadOnlyQuery(req, unscrubbed.sql);
      const scrubbed = invScrub(state, s => s.scrubData(rows));
      const json = JSON.stringify(scrubbed.data, (k, v) => (typeof v === 'string' ? invClip(v, 4000) : v), 1);
      turnText = `I ran this query on ${env}:\n${sql.trim()}\n\nResult: ${rows.length} row(s)${truncated ? ` (capped at ${INV_MAX_ROWS})` : ''}, scrubbed:\n${invClip(json, INV_AI_RESULT_CHARS)}`;
      payload = { rows, scrubbedRows: scrubbed.data, counts: scrubbed.counts, count: rows.length, truncated, filledPlaceholders: unscrubbed.filled };
    } catch (e) {
      turnText = `I ran this query on ${env}:\n${sql.trim()}\n\nIt failed: ${e.message}`;
      payload = { error: e.message };
    }
    state.chat.push({ role: 'user', kind: 'query', text: turnText, sql: sql.trim(), env, at: new Date().toISOString() });
    invWriteState(req.params.file, state);
    res.json(payload);
  } catch (e) { invSend(res, e); }
});

// Adds the user's (scrubbed) message, if any, and asks the model for the next step.
router.post('/api/investigations/:file/ai', async (req, res) => {
  try {
    const p = invPath(req.params.file);
    const env = String(req.headers['x-env'] || 'unknown');
    const state = invReadState(req.params.file);
    const text = String((req.body || {}).text || '').trim();
    let counts = {};
    if (text) {
      const scrubbed = invScrub(state, s => s.run(text));
      counts = scrubbed.counts;
      state.chat.push({ role: 'user', kind: 'message', text: scrubbed.output, at: new Date().toISOString() });
    }
    const messages = invToConverseMessages(state.chat);
    if (!messages.length) return res.status(400).json({ error: 'Nothing to send yet — write a message first.' });

    const notes = invScrub(state, s => s.run(fs.readFileSync(p, 'utf8'))).output;
    const playbooks = invReadPlaybooks().map(pb => `### ${pb.file}\n${pb.content}`).join('\n\n');
    const response = await bedrockClient.send(new ConverseCommand({
      modelId: INV_MODEL,
      system: [{ text: invSystemPrompt(env, notes, playbooks) }],
      messages,
      toolConfig: { tools: [INV_REPLY_TOOL], toolChoice: { tool: { name: 'reply' } } },
      inferenceConfig: { maxTokens: 4000, temperature: 0.2 },
    }));
    const content = response.output.message.content || [];
    const toolUse = (content.find(c => c.toolUse) || {}).toolUse;
    const reply = toolUse ? toolUse.input : { message: (content.find(c => c.text) || {}).text || '(empty reply)' };
    const turn = {
      role: 'assistant',
      text: reply.message || '',
      proposedSql: reply.proposed_sql ? reply.proposed_sql.trim().replace(/;\s*$/, '') : null,
      purpose: reply.purpose || null,
      logEntry: reply.log_entry || null,
      at: new Date().toISOString(),
    };
    state.chat.push(turn);
    invWriteState(req.params.file, state);
    res.json({ turn, counts, userText: text ? state.chat[state.chat.length - 2].text : null });
  } catch (e) { invSend(res, e); }
});

module.exports = router;
