const router = require('express').Router();
const { ConverseCommand } = require('@aws-sdk/client-bedrock-runtime');
const { query } = require('../lib/db');
const { DB_SCHEMA_CONTEXT, bedrockClient } = require('../lib/ai');

// ─── Routes: query runner ─────────────────────────────────────────────────────
const MUTATION_PATTERN = /^\s*(INSERT|UPDATE|DELETE|DROP|TRUNCATE|CREATE|ALTER|GRANT|REVOKE)\b/i;

router.post('/api/query', async (req, res) => {
  try {
    const { sql, allowMutations } = req.body;
    if (!sql || !sql.trim()) return res.status(400).json({ error: 'No SQL provided' });
    if (!allowMutations && MUTATION_PATTERN.test(sql)) {
      return res.status(403).json({ error: 'Mutations blocked. Enable write mode to run INSERT/UPDATE/DELETE.' });
    }
    const rows = await query(req, sql);
    res.json({ rows, count: rows.length });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

// ─── Routes: AI query builder ─────────────────────────────────────────────────
router.post('/api/ai/query', async (req, res) => {
  try {
    const { messages, modelId = 'eu.anthropic.claude-sonnet-4-5-20250929-v1:0' } = req.body;
    if (!messages || !messages.length) return res.status(400).json({ error: 'No messages provided' });

    const command = new ConverseCommand({
      modelId,
      system: [{ text: DB_SCHEMA_CONTEXT }],
      messages: messages.map(m => ({
        role: m.role,
        content: [{ text: m.content }],
      })),
      inferenceConfig: { maxTokens: 2000, temperature: 0.1 },
    });

    const response = await bedrockClient.send(command);
    const raw = response.output.message.content[0].text.trim();
    const sql = raw.replace(/^```(?:sql)?\s*\n?/i, '').replace(/\n?```\s*$/, '');
    res.json({ sql });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

module.exports = router;
