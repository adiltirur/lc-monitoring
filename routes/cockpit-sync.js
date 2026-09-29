const router = require('express').Router();
const { bindValue, poolFromHeaders, poolQuery, quoteIdent, tableColumns } = require('../lib/db');

// ─── Routes: cockpit cross-env sync (export from one env, import to another) ──
//
// Copies the 5 cockpit-relevant tables for selected praxes between two envs.
// Praxes are matched by `lcId` (numeric `id` differs across envs); the numeric
// `praxisId` FK is remapped on insert. Personio `employeeId`s inside the JSON
// blobs are global IDs and cross envs unchanged. Refuses on production target.

const COCKPIT_SYNC_TABLES = [
  'praxis_hours_config',
  'cockpit_standard_week_version',
  'cockpit_appointment_type_matrix',
  'cockpit_week_override',
  'cockpit_person_duration_exception',
];

// ── POST /api/cockpit/source-summary ──────────────────────────────────────────
// Headers: x-src-db-* (single env). Body: { lcIds?: string[] }
// Returns per-praxis row counts across the 5 cockpit tables, so the UI can
// preview what would be copied before committing.
router.post('/api/cockpit/source-summary', async (req, res) => {
  try {
    const { lcIds } = req.body || {};
    const src = poolFromHeaders(req, 'x-src-db-');
    const praxRows = lcIds && lcIds.length
      ? await poolQuery(src.pool, `SELECT id, "lcId", name FROM praxis_config WHERE "lcId" = ANY($1::text[]) ORDER BY "lcId"`, [lcIds])
      : await poolQuery(src.pool, `SELECT id, "lcId", name FROM praxis_config ORDER BY "lcId"`);
    const out = [];
    for (const p of praxRows) {
      const counts = {};
      for (const t of COCKPIT_SYNC_TABLES) {
        try {
          const r = await poolQuery(src.pool, `SELECT count(*)::int AS n FROM ${quoteIdent(t)} WHERE "praxisId" = $1`, [p.id]);
          counts[t] = r[0].n;
        } catch (e) {
          counts[t] = { error: e.message };
        }
      }
      out.push({ lcId: p.lcId, name: p.name, counts });
    }
    res.json({ ok: true, rows: out });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ── POST /api/cockpit/cross-env-copy ──────────────────────────────────────────
// Headers: x-src-db-* AND x-tgt-db-*. Body: { lcIds?: string[], replace?: bool }
// Defaults to all praxes on source, replace=true.
// For each src praxis, looks up tgt praxis by lcId. If src has no match on tgt,
// the praxis is skipped (logged). For each cockpit table:
//   - replace mode: DELETE rows on tgt where praxisId = tgt's mapped id
//   - then INSERT every src row with praxisId remapped to tgt
// Refuses if target env-label is production.
router.post('/api/cockpit/cross-env-copy', async (req, res) => {
  try {
    const tgtEnvLabel = (req.headers['x-tgt-env-label'] || '').toString().toLowerCase();
    if (tgtEnvLabel === 'production' || tgtEnvLabel === 'prod') {
      return res.status(400).json({ error: 'Refusing to write cockpit data on production target.' });
    }

    const { lcIds, replace = true } = req.body || {};
    const src = poolFromHeaders(req, 'x-src-db-');
    const tgt = poolFromHeaders(req, 'x-tgt-db-');
    if (`${src.host}:${src.port}/${src.database}` === `${tgt.host}:${tgt.port}/${tgt.database}`) {
      return res.status(400).json({ error: 'Source and target databases must be different.' });
    }

    const srcPraxes = lcIds && lcIds.length
      ? await poolQuery(src.pool, `SELECT id, "lcId", name FROM praxis_config WHERE "lcId" = ANY($1::text[]) ORDER BY "lcId"`, [lcIds])
      : await poolQuery(src.pool, `SELECT id, "lcId", name FROM praxis_config ORDER BY "lcId"`);
    if (!srcPraxes.length) return res.json({ ok: true, results: [], message: 'No source praxes.' });

    // Look up target praxis ids by lcId in one query.
    const tgtMap = {};
    {
      const rows = await poolQuery(tgt.pool, `SELECT id, "lcId" FROM praxis_config WHERE "lcId" = ANY($1::text[])`, [srcPraxes.map(p => p.lcId)]);
      for (const r of rows) tgtMap[r.lcId] = r.id;
    }

    // Cache target column metadata (json/jsonb columns need bindValue serialization).
    const colsByTable = {};
    for (const t of COCKPIT_SYNC_TABLES) {
      colsByTable[t] = await tableColumns(tgt.pool, t);
    }

    const tgtClient = await tgt.pool.connect();
    const results = [];
    try {
      await tgtClient.query('BEGIN');
      for (const srcPraxis of srcPraxes) {
        const tgtPraxisId = tgtMap[srcPraxis.lcId];
        if (!tgtPraxisId) {
          results.push({ lcId: srcPraxis.lcId, status: 'skipped', reason: 'praxis not on target' });
          continue;
        }

        const perTable = {};
        for (const t of COCKPIT_SYNC_TABLES) {
          if (replace) {
            await tgtClient.query(`DELETE FROM ${quoteIdent(t)} WHERE "praxisId" = $1`, [tgtPraxisId]);
          }
          let srcRows;
          try {
            srcRows = await poolQuery(src.pool, `SELECT * FROM ${quoteIdent(t)} WHERE "praxisId" = $1`, [srcPraxis.id]);
          } catch (e) {
            // Source may not have the table (cross-version envs).
            perTable[t] = { skipped: e.message };
            continue;
          }
          if (!srcRows.length) { perTable[t] = 0; continue; }
          const cols = colsByTable[t].filter(c => c.column_name !== 'id');
          const colList = cols.map(c => quoteIdent(c.column_name)).join(',');
          const placeholders = cols.map((_, i) => `$${i + 1}`).join(',');
          for (const row of srcRows) {
            const values = cols.map(c =>
              c.column_name === 'praxisId' ? tgtPraxisId : bindValue(c, row[c.column_name])
            );
            await tgtClient.query(`INSERT INTO ${quoteIdent(t)} (${colList}) VALUES (${placeholders})`, values);
          }
          perTable[t] = srcRows.length;
        }
        results.push({ lcId: srcPraxis.lcId, name: srcPraxis.name, tgtPraxisId, status: 'ok', perTable });
      }
      await tgtClient.query('COMMIT');
    } catch (e) {
      await tgtClient.query('ROLLBACK');
      throw new Error(`Cockpit sync rolled back: ${e.message}`);
    } finally {
      tgtClient.release();
    }
    res.json({ ok: true, replace, results });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

module.exports = router;
