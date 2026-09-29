const router = require('express').Router();
const { poolFromHeaders, query, quoteIdent } = require('../lib/db');
const { PRAXIS_CONFIG_TABLES } = require('../lib/praxis');

// ─── Routes: single-praxis cleanup (deep delete + reference scrub) ──────────
//
// Removes every row that references a given lcId so the praxis can be safely
// re-created. Goes further than the praxis-refresh wipe: that one only clears
// the 25 praxis-config tables; this one also cleans the historical/user tables
// that hold the lcId as a string FK. User accounts are preserved (praxisId
// nulled), admin accounts are preserved (lcId removed from associatedPraxisIds).
// Audit log is kept. Refuses on production.
//
// Per-table action map — extend when new praxis-scoped tables are added.
const CLEANUP_NON_CONFIG_TABLES = {
  // numeric praxisId (FK to praxis_config.id) — DELETE rows for this praxis
  'app_user_appointment_reminder':       { mode: 'delete-by-numid' },
  'cockpit_person_duration_exception':   { mode: 'delete-by-numid' },
  'praxis_hours_sync_target':            { mode: 'delete-by-numid' },
  // string lcId — DELETE rows for this praxis
  'app_user_appointment':                { mode: 'delete-by-lcid' },
  'app_user_open_consultation':          { mode: 'delete-by-lcid' },
  'app_user_document_request':           { mode: 'delete-by-lcid' },
  'app_user_reserved_appointment':       { mode: 'delete-by-lcid' },
  'app_user_nps_sent':                   { mode: 'delete-by-lcid' },
  'guest_appointment':                   { mode: 'delete-by-lcid' },
  'questionnaire_reservation':           { mode: 'delete-by-lcid' },
  'fhir_nps':                            { mode: 'delete-by-lcid' },
  'app_user_pms_invitation':             { mode: 'delete-by-lcid' },
  // preserve account, drop the praxis link
  'app_user_info':                       { mode: 'null-by-lcid' },
  // preserve account, drop the lcId from the JSON array (handled in code)
  'admin_user_info':                     { mode: 'remove-from-json-array' },
  // historical record — keep as-is
  'admin_audit_log':                     { mode: 'keep' },
};

// Returns a Set of table names that exist on the env addressed by `req`.
// Used by cleanup endpoints so a missing table (envs at different migration
// levels) doesn't abort the whole transaction with "relation does not exist".
async function existingPublicTables(req) {
  const rows = await query(req, `SELECT table_name FROM information_schema.tables WHERE table_schema = 'public'`);
  return new Set(rows.map(r => r.table_name));
}

// ── POST /api/praxis/cleanup-preview ─────────────────────────────────────────
// Body: { lcId: string }. Read-only. Returns per-table row counts that would
// be DELETEd, NULLed, or filtered for this lcId. Missing tables are flagged
// as `{ missing: true }` rather than blowing up.
router.post('/api/praxis/cleanup-preview', async (req, res) => {
  try {
    const { lcId } = req.body || {};
    if (!lcId) return res.status(400).json({ error: 'lcId is required' });
    const found = await query(req, `SELECT id, name FROM praxis_config WHERE "lcId" = $1`, [lcId]);
    if (!found.length) return res.status(404).json({ error: `lcId '${lcId}' not found` });
    const numId = found[0].id;
    const present = await existingPublicTables(req);
    const counts = { lcId, name: found[0].name, praxisDbId: numId, configTables: {}, nonConfigTables: {} };
    // Root praxis_config row always counts as 1 here (we already located it).
    counts.configTables['praxis_config'] = 1;
    for (const t of PRAXIS_CONFIG_TABLES.slice(1)) {
      if (!present.has(t)) { counts.configTables[t] = { missing: true }; continue; }
      try {
        const r = await query(req, `SELECT count(*)::int AS n FROM ${quoteIdent(t)} WHERE "praxisId" = $1`, [numId]);
        counts.configTables[t] = r[0].n;
      } catch (e) { counts.configTables[t] = { error: e.message }; }
    }

    for (const [t, spec] of Object.entries(CLEANUP_NON_CONFIG_TABLES)) {
      if (!present.has(t)) { counts.nonConfigTables[t] = { mode: spec.mode, missing: true }; continue; }
      try {
        if (spec.mode === 'delete-by-numid') {
          const r = await query(req, `SELECT count(*)::int AS n FROM ${quoteIdent(t)} WHERE "praxisId" = $1`, [numId]);
          counts.nonConfigTables[t] = { mode: spec.mode, rows: r[0].n };
        } else if (spec.mode === 'delete-by-lcid' || spec.mode === 'null-by-lcid') {
          const r = await query(req, `SELECT count(*)::int AS n FROM ${quoteIdent(t)} WHERE "praxisId" = $1`, [lcId]);
          counts.nonConfigTables[t] = { mode: spec.mode, rows: r[0].n };
        } else if (spec.mode === 'remove-from-json-array') {
          const r = await query(req, `SELECT count(*)::int AS n FROM ${quoteIdent(t)} WHERE "associatedPraxisIds"::text LIKE $1`, [`%${lcId}%`]);
          counts.nonConfigTables[t] = { mode: spec.mode, rows: r[0].n };
        } else {
          counts.nonConfigTables[t] = { mode: spec.mode, rows: 0 };
        }
      } catch (e) { counts.nonConfigTables[t] = { mode: spec.mode, error: e.message }; }
    }
    res.json({ ok: true, ...counts });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ── POST /api/praxis/cleanup ─────────────────────────────────────────────────
// Body: { lcId: string, confirmation: string }. confirmation must equal lcId.
// Headers: standard x-db-* + `x-allow-destructive: yes`. Refuses on production.
// Performs the full cleanup in a single transaction. Returns per-table action
// counts; rolls back the whole batch on any error.
router.post('/api/praxis/cleanup', async (req, res) => {
  try {
    const envLabel = (req.headers['x-env-label'] || req.headers['x-env'] || '').toString().toLowerCase();
    if (envLabel === 'production' || envLabel === 'prod') {
      return res.status(400).json({ error: 'Refusing to delete praxis on production.' });
    }
    if (req.headers['x-allow-destructive'] !== 'yes') {
      return res.status(400).json({ error: `x-allow-destructive: yes required.` });
    }
    const { lcId, confirmation } = req.body || {};
    if (!lcId) return res.status(400).json({ error: 'lcId is required' });
    if (confirmation !== lcId) return res.status(400).json({ error: `body.confirmation must equal the lcId ('${lcId}').` });

    const found = await query(req, `SELECT id, name FROM praxis_config WHERE "lcId" = $1`, [lcId]);
    if (!found.length) return res.status(404).json({ error: `lcId '${lcId}' not found` });
    const numId = found[0].id;
    const present = await existingPublicTables(req);

    const { pool } = poolFromHeaders(req);
    const client = await pool.connect();
    const result = {
      lcId,
      name: found[0].name,
      praxisDbId: numId,
      configDeletedRows: {},
      nonConfigActions: {},
      skippedMissing: [],
    };
    try {
      await client.query('BEGIN');

      // 1) Child praxis-config tables in reverse FK order. praxis_config (root)
      //    is at index 0 and gets deleted last, by `id` not `praxisId`.
      const childTablesReverse = PRAXIS_CONFIG_TABLES.slice(1).reverse();
      for (const t of childTablesReverse) {
        if (!present.has(t)) { result.configDeletedRows[t] = { missing: true }; result.skippedMissing.push(t); continue; }
        const r = await client.query(`DELETE FROM ${quoteIdent(t)} WHERE "praxisId" = $1`, [numId]);
        result.configDeletedRows[t] = r.rowCount;
      }

      // 2) Non-config tables — DELETE / NULL / filter as configured.
      for (const [t, spec] of Object.entries(CLEANUP_NON_CONFIG_TABLES)) {
        if (spec.mode === 'keep') {
          result.nonConfigActions[t] = { mode: spec.mode, rows: 0 };
          continue;
        }
        if (!present.has(t)) {
          result.nonConfigActions[t] = { mode: spec.mode, missing: true };
          result.skippedMissing.push(t);
          continue;
        }
        if (spec.mode === 'delete-by-numid') {
          const r = await client.query(`DELETE FROM ${quoteIdent(t)} WHERE "praxisId" = $1`, [numId]);
          result.nonConfigActions[t] = { mode: spec.mode, rows: r.rowCount };
        } else if (spec.mode === 'delete-by-lcid') {
          const r = await client.query(`DELETE FROM ${quoteIdent(t)} WHERE "praxisId" = $1`, [lcId]);
          result.nonConfigActions[t] = { mode: spec.mode, rows: r.rowCount };
        } else if (spec.mode === 'null-by-lcid') {
          const r = await client.query(`UPDATE ${quoteIdent(t)} SET "praxisId" = NULL WHERE "praxisId" = $1`, [lcId]);
          result.nonConfigActions[t] = { mode: spec.mode, rows: r.rowCount };
        } else if (spec.mode === 'remove-from-json-array') {
          // admin_user_info.associatedPraxisIds is JSON of array<string>. Pull
          // affected rows, filter the array in JS, write back.
          const rows = await client.query(
            `SELECT id, "associatedPraxisIds" FROM ${quoteIdent(t)} WHERE "associatedPraxisIds"::text LIKE $1`,
            [`%${lcId}%`],
          );
          let updated = 0;
          for (const row of rows.rows) {
            const arr = Array.isArray(row.associatedPraxisIds)
              ? row.associatedPraxisIds
              : (typeof row.associatedPraxisIds === 'string' ? JSON.parse(row.associatedPraxisIds) : []);
            const filtered = arr.filter(x => x !== lcId);
            if (filtered.length !== arr.length) {
              await client.query(`UPDATE ${quoteIdent(t)} SET "associatedPraxisIds" = $1::json WHERE id = $2`, [JSON.stringify(filtered), row.id]);
              updated++;
            }
          }
          result.nonConfigActions[t] = { mode: spec.mode, rows: updated };
        }
      }

      // 3) Finally, delete the praxis_config root by id.
      const rootDel = await client.query(`DELETE FROM praxis_config WHERE id = $1`, [numId]);
      result.configDeletedRows['praxis_config'] = rootDel.rowCount;

      await client.query('COMMIT');
    } catch (e) {
      try { await client.query('ROLLBACK'); } catch {}
      throw new Error(`Cleanup rolled back: ${e.message}`);
    } finally {
      client.release();
    }
    res.json({ ok: true, ...result });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

module.exports = router;
