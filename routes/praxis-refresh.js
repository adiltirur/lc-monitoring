const router = require('express').Router();
const fs = require('fs');
const path = require('path');
const { bindValue, poolFromHeaders, poolQuery, query, quoteIdent, tableColumns } = require('../lib/db');
const { PRAXIS_CONFIG_TABLES, PRAXIS_CONFIG_TABLES_SKIP_IMPORT, PRAXIS_HISTORICAL_LCID_TABLES } = require('../lib/praxis');

const ROOT = path.join(__dirname, '..'); // helper/

// ─── Routes: praxis refresh (backup, wipe, import prod→staging, scrub, set-default)
//
// Single-env endpoints take the standard `x-db-*` headers. The cross-env import
// endpoint takes TWO header sets — `x-src-db-*` and `x-tgt-db-*` — so prod and
// staging pools are accessed in the same request.
// Table lists: lib/praxis.js. Pool helpers: lib/db.js.

// ── GET /api/praxis/list ──────────────────────────────────────────────────────
// Lists all praxes for the env addressed by `x-db-*` headers. Used by both the
// frontend's source/target preview and the post-import default-praxis picker.
router.get('/api/praxis/list', async (req, res) => {
  try {
    const rows = await query(
      req,
      `SELECT id, "lcId", name, "shortName", city, "isDraft"
         FROM praxis_config
        ORDER BY name`,
    );
    res.json({ rows, total: rows.length });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ── GET /api/praxis/schema-drift-check ────────────────────────────────────────
// Compares the live target-env schema against the hardcoded config-table list
// above. Returns:
//   covered:    config tables we'll backup/wipe/import (intersection)
//   historical: praxis-scoped tables we INTENTIONALLY don't wipe
//   drift:      tables with a praxisId-shaped column that aren't in either list
// The frontend gates destructive steps on `drift.length === 0` (or operator
// override).
router.get('/api/praxis/schema-drift-check', async (req, res) => {
  try {
    // Tables with any column named "praxisId" (Serverpod camelCase) — covers
    // both numeric-FK (config) and string-lcId (historical) tables.
    const found = await query(
      req,
      `SELECT table_name, data_type
         FROM information_schema.columns
        WHERE table_schema = 'public'
          AND column_name = 'praxisId'
        ORDER BY table_name`,
    );
    const known = new Set([...PRAXIS_CONFIG_TABLES, ...PRAXIS_HISTORICAL_LCID_TABLES]);
    const covered = [];
    const historical = [];
    const drift = [];
    for (const row of found) {
      if (PRAXIS_CONFIG_TABLES.includes(row.table_name)) covered.push(row);
      else if (PRAXIS_HISTORICAL_LCID_TABLES.includes(row.table_name)) historical.push(row);
      else drift.push(row);
    }
    // Also flag any hardcoded config table that doesn't exist on this env.
    const presentNames = new Set(found.map(r => r.table_name));
    const missing = PRAXIS_CONFIG_TABLES.filter(t => t !== 'praxis_config' && !presentNames.has(t));
    res.json({ covered, historical, drift, missing });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ── POST /api/praxis/backup ───────────────────────────────────────────────────
// Body: { lcIds?: string[] }  — if omitted, backs up every praxis on the env.
// Dumps each praxis (root + all 24 child tables) to
//   helper/backups/<envLabel>/<ISO-timestamp>/<lcId>.json
// Returns the absolute paths so the frontend can show them.
router.post('/api/praxis/backup', async (req, res) => {
  try {
    const envLabel = (req.headers['x-env-label'] || req.headers['x-env'] || 'unknown').toString().replace(/[^a-zA-Z0-9_-]/g, '_');
    const { lcIds } = req.body || {};
    const { pool } = poolFromHeaders(req);

    const praxes = lcIds && lcIds.length
      ? await poolQuery(pool, `SELECT * FROM praxis_config WHERE "lcId" = ANY($1::text[]) ORDER BY "lcId"`, [lcIds])
      : await poolQuery(pool, `SELECT * FROM praxis_config ORDER BY "lcId"`);

    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const backupDir = path.join(ROOT, 'backups', envLabel, timestamp);
    fs.mkdirSync(backupDir, { recursive: true });

    const written = [];
    for (const praxis of praxes) {
      const bundle = { praxis_config: praxis, related: {} };
      for (let i = 1; i < PRAXIS_CONFIG_TABLES.length; i++) {
        const t = PRAXIS_CONFIG_TABLES[i];
        try {
          const rows = await poolQuery(pool, `SELECT * FROM ${quoteIdent(t)} WHERE "praxisId" = $1`, [praxis.id]);
          bundle.related[t] = rows;
        } catch (e) {
          // Treat a missing table as empty so a partially-migrated env can still backup.
          bundle.related[t] = { __error: e.message };
        }
      }
      const filename = `${praxis.lcId}.json`;
      const filepath = path.join(backupDir, filename);
      fs.writeFileSync(filepath, JSON.stringify(bundle, null, 2));
      written.push({ lcId: praxis.lcId, name: praxis.name, path: filepath });
    }
    res.json({ ok: true, env: envLabel, dir: backupDir, files: written, count: written.length });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ── POST /api/praxis/wipe-staging ─────────────────────────────────────────────
// Refuses unless: env-label === 'staging', `x-allow-destructive: yes`, and body
// `confirmation` exactly equals 'WIPE STAGING'. Deletes from the 25 config
// tables in reverse FK order. Historical praxis-scoped tables (appointments,
// audit, NPS, etc.) are intentionally NOT touched — see CLAUDE.md.
router.post('/api/praxis/wipe-staging', async (req, res) => {
  try {
    const envLabel = (req.headers['x-env-label'] || req.headers['x-env'] || '').toString().toLowerCase();
    if (envLabel !== 'staging') {
      return res.status(400).json({ error: `Refusing to wipe: x-env-label must be 'staging' (got '${envLabel}'). This guard exists to prevent accidental prod wipes.` });
    }
    if (req.headers['x-allow-destructive'] !== 'yes') {
      return res.status(400).json({ error: `Refusing to wipe: x-allow-destructive header must be 'yes'.` });
    }
    if ((req.body && req.body.confirmation) !== 'WIPE STAGING') {
      return res.status(400).json({ error: `Refusing to wipe: body.confirmation must be the literal string 'WIPE STAGING'.` });
    }

    const { pool } = poolFromHeaders(req);
    const client = await pool.connect();
    const counts = {};
    try {
      await client.query('BEGIN');
      // Delete child tables first, then the root.
      for (const t of [...PRAXIS_CONFIG_TABLES].reverse()) {
        const r = await client.query(`DELETE FROM ${quoteIdent(t)}`);
        counts[t] = r.rowCount;
      }
      await client.query('COMMIT');
    } catch (e) {
      await client.query('ROLLBACK');
      throw e;
    } finally {
      client.release();
    }
    res.json({ ok: true, deletedRowsByTable: counts });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ── POST /api/praxis/import ───────────────────────────────────────────────────
// Headers: `x-src-db-*` (read-only, e.g. prod) AND `x-tgt-db-*` (writable, e.g.
// staging). Body: { lcIds?: string[] } — defaults to all praxes on source.
// Inserts each source praxis into the target with `"lcId"` preserved, generating
// a NEW numeric `id` (Postgres default), then copies each child config table
// remapping `"praxisId"` to the new target id. Sets `"isDraft" = false`.
// Errors out cleanly if any lcId already exists on target.
router.post('/api/praxis/import', async (req, res) => {
  try {
    const { lcIds } = req.body || {};
    const src = poolFromHeaders(req, 'x-src-db-');
    const tgt = poolFromHeaders(req, 'x-tgt-db-');
    if (`${src.host}:${src.port}/${src.database}` === `${tgt.host}:${tgt.port}/${tgt.database}`) {
      return res.status(400).json({ error: 'Source and target databases must be different.' });
    }

    const srcPraxes = lcIds && lcIds.length
      ? await poolQuery(src.pool, `SELECT * FROM praxis_config WHERE "lcId" = ANY($1::text[]) ORDER BY "lcId"`, [lcIds])
      : await poolQuery(src.pool, `SELECT * FROM praxis_config ORDER BY "lcId"`);

    if (!srcPraxes.length) return res.json({ ok: true, imported: [], skipped: [], message: 'No source praxes found.' });

    // Pre-check for collisions on target so we fail before any writes.
    const tgtExisting = await poolQuery(
      tgt.pool,
      `SELECT "lcId" FROM praxis_config WHERE "lcId" = ANY($1::text[])`,
      [srcPraxes.map(p => p.lcId)],
    );
    if (tgtExisting.length) {
      return res.status(409).json({
        error: `Target already has ${tgtExisting.length} of the requested lcId(s). Wipe first or pass a smaller lcIds list.`,
        collisions: tgtExisting.map(r => r.lcId),
      });
    }

    // Cache target table column lists once.
    const childTables = PRAXIS_CONFIG_TABLES.slice(1);
    const colsByTable = {};
    for (const t of [...childTables, 'praxis_config']) {
      colsByTable[t] = await tableColumns(tgt.pool, t);
    }

    const tgtClient = await tgt.pool.connect();
    const imported = [];
    const errors = [];
    try {
      await tgtClient.query('BEGIN');
      for (const srcPraxis of srcPraxes) {
        // Insert root, omit `id` so target assigns a fresh one. Preserve lcId
        // and force isDraft=false so imported praxes are immediately live.
        const rootCols = colsByTable['praxis_config'].filter(c => c.column_name !== 'id');
        const rootValues = rootCols.map(c =>
          c.column_name === 'isDraft' ? false : bindValue(c, srcPraxis[c.column_name])
        );
        const placeholders = rootCols.map((_, i) => `$${i + 1}`).join(',');
        const colList = rootCols.map(c => quoteIdent(c.column_name)).join(',');
        const inserted = await tgtClient.query(
          `INSERT INTO praxis_config (${colList}) VALUES (${placeholders}) RETURNING id`,
          rootValues,
        );
        const newPraxisId = inserted.rows[0].id;

        // Copy each child config table, remapping the FK.
        const perTable = {};
        for (const t of childTables) {
          if (PRAXIS_CONFIG_TABLES_SKIP_IMPORT.has(t)) {
            perTable[t] = { skipped: 'cross-table FK to non-praxis table — see PRAXIS_CONFIG_TABLES_SKIP_IMPORT' };
            continue;
          }
          let childRows;
          try {
            childRows = await poolQuery(src.pool, `SELECT * FROM ${quoteIdent(t)} WHERE "praxisId" = $1`, [srcPraxis.id]);
          } catch (e) {
            // Table may not exist on source (rare during migration). Skip silently.
            perTable[t] = { skipped: e.message };
            continue;
          }
          if (!childRows.length) { perTable[t] = 0; continue; }
          const childCols = colsByTable[t].filter(c => c.column_name !== 'id');
          const childColList = childCols.map(c => quoteIdent(c.column_name)).join(',');
          const childPlaceholders = childCols.map((_, i) => `$${i + 1}`).join(',');
          for (const row of childRows) {
            const values = childCols.map(c =>
              c.column_name === 'praxisId' ? newPraxisId : bindValue(c, row[c.column_name])
            );
            await tgtClient.query(
              `INSERT INTO ${quoteIdent(t)} (${childColList}) VALUES (${childPlaceholders})`,
              values,
            );
          }
          perTable[t] = childRows.length;
        }
        imported.push({ lcId: srcPraxis.lcId, name: srcPraxis.name, newPraxisId, perTable });
      }
      await tgtClient.query('COMMIT');
    } catch (e) {
      await tgtClient.query('ROLLBACK');
      errors.push(e.message);
      throw new Error(`Import rolled back: ${e.message}`);
    } finally {
      tgtClient.release();
    }
    res.json({ ok: true, importedCount: imported.length, imported, errors });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ── POST /api/praxis/scrub-contacts ───────────────────────────────────────────
// Body: { email: string, phone: string, vitasAIPraxisId?: string }. Bulk-updates
// email + phone on every praxis_config row. If vitasAIPraxisId is provided
// (non-empty), also overwrites that column. Refuses on production.
router.post('/api/praxis/scrub-contacts', async (req, res) => {
  try {
    const envLabel = (req.headers['x-env-label'] || req.headers['x-env'] || '').toString().toLowerCase();
    if (envLabel === 'production' || envLabel === 'prod') {
      return res.status(400).json({ error: 'Refusing to scrub on production.' });
    }
    const { email, phone, vitasAIPraxisId } = req.body || {};
    if (!email || !phone) return res.status(400).json({ error: 'email and phone are required.' });
    const setClauses = [`email = $1`, `phone = $2`];
    const params = [email, phone];
    if (typeof vitasAIPraxisId === 'string' && vitasAIPraxisId.length) {
      params.push(vitasAIPraxisId);
      setClauses.push(`"vitasAIPraxisId" = $${params.length}`);
    }
    const r = await query(req, `UPDATE praxis_config SET ${setClauses.join(', ')}`, params);
    res.json({ ok: true, scrubbedRows: r.length, columnsUpdated: setClauses.length });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ── POST /api/praxis/set-default ──────────────────────────────────────────────
// Body: { lcId: string }. Sets `praxisId` on every app_user_info row and
// replaces `associatedPraxisIds` on every admin_user_info row with [lcId].
// Refuses on production. Verifies the lcId exists in praxis_config first.
router.post('/api/praxis/set-default', async (req, res) => {
  try {
    const envLabel = (req.headers['x-env-label'] || req.headers['x-env'] || '').toString().toLowerCase();
    if (envLabel === 'production' || envLabel === 'prod') {
      return res.status(400).json({ error: 'Refusing to bulk-set default praxis on production.' });
    }
    const { lcId } = req.body || {};
    if (!lcId) return res.status(400).json({ error: 'lcId is required.' });

    const exists = await query(req, `SELECT id FROM praxis_config WHERE "lcId" = $1 LIMIT 1`, [lcId]);
    if (!exists.length) return res.status(404).json({ error: `lcId '${lcId}' not found in praxis_config on this env.` });

    const { pool } = poolFromHeaders(req);
    const client = await pool.connect();
    let appUsers = 0, adminUsers = 0;
    try {
      await client.query('BEGIN');
      const a = await client.query(`UPDATE app_user_info SET "praxisId" = $1`, [lcId]);
      appUsers = a.rowCount;
      // associatedPraxisIds is stored as JSON (array of strings), not Postgres text[].
      const b = await client.query(`UPDATE admin_user_info SET "associatedPraxisIds" = $1::json`, [JSON.stringify([lcId])]);
      adminUsers = b.rowCount;
      await client.query('COMMIT');
    } catch (e) {
      await client.query('ROLLBACK');
      throw e;
    } finally {
      client.release();
    }
    res.json({ ok: true, lcId, appUsersUpdated: appUsers, adminUsersUpdated: adminUsers });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

module.exports = router;
