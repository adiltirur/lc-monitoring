const router = require('express').Router();
const fs = require('fs');
const { query } = require('../lib/db');

// ─── Routes: env config (serves .env values to frontend, never the raw file) ──
router.get('/api/env-config', (req, res) => {
  res.json({
    passwords: {
      dev:        process.env.DB_DEV_PASSWORD        || '',
      test:       process.env.DB_TEST_PASSWORD       || '',
      staging:    process.env.DB_STAGING_PASSWORD    || '',
      production: process.env.DB_PROD_PASSWORD       || '',
    },
    decryptKeys: {
      dev:        process.env.DECRYPT_KEY_DEV        || '',
      staging:    process.env.DECRYPT_KEY_STAGING    || '',
      production: process.env.DECRYPT_KEY_PROD       || '',
    },
  });
});

// ─── Routes: connection test ──────────────────────────────────────────────────
router.get('/api/connection-test', async (req, res) => {
  try {
    await query(req, 'SELECT 1');
    res.json({ ok: true });
  } catch (e) {
    res.status(400).json({ ok: false, error: e.message });
  }
});

// ─── Routes: protocol introspection ───────────────────────────────────────────
// Parses Serverpod's protocol.yaml to expose the endpoint groups and method
// names without hitting the DB. Matches what session-logs records as
// (endpoint, method) so the UI can show dropdowns instead of free-text inputs.
const PROTOCOL_YAML = '/Users/adil/Work/LillianCare/LillianCare-Core/lillian_care_core_server/lib/src/generated/protocol.yaml';

function parseProtocolYaml(src) {
  // Trivial format: top-level "groupName:" followed by indented "  - methodName:"
  const groups = {};
  let current = null;
  for (const raw of src.split('\n')) {
    if (!raw.trim() || raw.trim().startsWith('#')) continue;
    const groupMatch = raw.match(/^([A-Za-z0-9_]+):\s*$/);
    if (groupMatch) { current = groupMatch[1]; groups[current] = []; continue; }
    const methodMatch = raw.match(/^\s*-\s*([A-Za-z0-9_]+):\s*$/);
    if (methodMatch && current) groups[current].push(methodMatch[1]);
  }
  return groups;
}

let _protocolCache = null;
let _protocolMtime = 0;
router.get('/api/protocol', (_req, res) => {
  try {
    const stat = fs.statSync(PROTOCOL_YAML);
    if (!_protocolCache || stat.mtimeMs !== _protocolMtime) {
      _protocolCache = parseProtocolYaml(fs.readFileSync(PROTOCOL_YAML, 'utf8'));
      _protocolMtime = stat.mtimeMs;
    }
    res.json({ groups: _protocolCache });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

module.exports = router;
