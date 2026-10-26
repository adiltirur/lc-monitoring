const router = require('express').Router();
const { getPool } = require('../lib/db');

// ─── Routes: Serverpod session-log cleanup ────────────────────────────────────
// Serverpod's built-in retention (`sessionLogs.retentionPeriod`) deletes every
// expired session in ONE statement. With a large backlog that statement is
// cancelled after ~1.5 min ("FAILED TO CLEAN UP LOGS") and never catches up.
// This runs the same delete in small batches, each its own autocommitted
// statement, with a pause in between so a db.t3.micro keeps its EBS burst
// balance. serverpod_log / serverpod_query_log / serverpod_message_log rows go
// with their session through ON DELETE CASCADE. One job at a time, in memory.

const LC_PROD_HOSTS = ['database.lillian.care', 'lc-core.clyg4y6ua706.eu-central-1.rds.amazonaws.com'];
const LC_TABLES = ['serverpod_session_log', 'serverpod_log', 'serverpod_query_log', 'serverpod_message_log'];
const LC_PROD_CONFIRMATION = 'CLEAN PRODUCTION LOGS';

let lcJob = null;

function lcEnv(req) {
  const host = String(req.headers['x-db-host'] || '').toLowerCase();
  if (LC_PROD_HOSTS.includes(host)) return 'production';
  const label = String(req.headers['x-env'] || '').toLowerCase();
  if (label === 'production' || label === 'prod') return 'production';
  return label || 'dev';
}

function lcPublicJob() {
  if (!lcJob) return null;
  const { client, cancelRequested, ...pub } = lcJob;
  return pub;
}

async function lcOverview(pool, retentionDays) {
  const { rows: [counts] } = await pool.query(`
    SELECT count(*)::bigint AS total,
           count(*) FILTER (WHERE "time" < now() - make_interval(days => $1))::bigint AS expired,
           min("time") AS oldest
    FROM serverpod_session_log`, [retentionDays]);
  const { rows: sizes } = await pool.query(`
    SELECT c.relname AS table, pg_total_relation_size(c.oid)::bigint AS bytes,
           pg_size_pretty(pg_total_relation_size(c.oid)) AS size, c.reltuples::bigint AS est_rows
    FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'public' AND c.relname = ANY($1)
    ORDER BY bytes DESC`, [LC_TABLES]);
  return { total: Number(counts.total), expired: Number(counts.expired), oldest: counts.oldest, sizes };
}

router.get('/api/log-cleanup/overview', async (req, res) => {
  try {
    const retentionDays = Math.max(1, parseInt(req.query.retentionDays || '7', 10));
    const data = await lcOverview(getPool(req), retentionDays);
    res.json({ env: lcEnv(req), host: req.headers['x-db-host'] || 'localhost', retentionDays, ...data, job: lcPublicJob() });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

router.get('/api/log-cleanup/status', (req, res) => {
  res.json({ job: lcPublicJob() });
});

router.post('/api/log-cleanup/start', async (req, res) => {
  if (lcJob && ['running', 'vacuuming'].includes(lcJob.status)) {
    return res.status(409).json({ error: `A cleanup is already running on ${lcJob.env}` });
  }
  const env = lcEnv(req);
  const b = req.body || {};
  const retentionDays = parseInt(b.retentionDays, 10);
  const batchSize = parseInt(b.batchSize, 10);
  const pauseMs = parseInt(b.pauseMs, 10);
  if (!(retentionDays >= 1)) return res.status(400).json({ error: 'retentionDays must be at least 1' });
  if (!(batchSize >= 100 && batchSize <= 50000)) return res.status(400).json({ error: 'batchSize must be 100–50000' });
  if (!(pauseMs >= 0 && pauseMs <= 60000)) return res.status(400).json({ error: 'pauseMs must be 0–60000' });
  if (env === 'production' && b.confirmation !== LC_PROD_CONFIRMATION) {
    return res.status(400).json({ error: `Type "${LC_PROD_CONFIRMATION}" to run on production` });
  }

  let client;
  try {
    client = await getPool(req).connect();
    // Per batch, not for the whole job: one stuck batch must not run for ever.
    await client.query(`SET statement_timeout = '120s'`);
    const { rows: [c] } = await client.query(
      `SELECT count(*)::bigint AS n FROM serverpod_session_log WHERE "time" < now() - make_interval(days => $1)`, [retentionDays]);
    lcJob = {
      id: Date.now(), env, host: req.headers['x-db-host'] || 'localhost',
      retentionDays, batchSize, pauseMs, vacuum: b.vacuum !== false,
      status: 'running', expiredAtStart: Number(c.n), deleted: 0, batches: 0,
      startedAt: new Date().toISOString(), finishedAt: null, lastBatchMs: null, error: null,
      client, cancelRequested: false,
    };
  } catch (e) {
    if (client) client.release();
    return res.status(500).json({ error: e.message });
  }
  lcRun(lcJob);
  res.json({ job: lcPublicJob() });
});

router.post('/api/log-cleanup/cancel', (req, res) => {
  if (!lcJob || lcJob.status !== 'running') return res.status(409).json({ error: 'No batch delete is running' });
  lcJob.cancelRequested = true;
  res.json({ job: lcPublicJob() });
});

async function lcRun(job) {
  const { client } = job;
  try {
    while (!job.cancelRequested) {
      const t0 = Date.now();
      // The cutoff is re-evaluated per batch, the same rule Serverpod applies.
      const r = await client.query(`
        DELETE FROM serverpod_session_log
        WHERE id IN (
          SELECT id FROM serverpod_session_log
          WHERE "time" < now() - make_interval(days => $1)
          ORDER BY id
          LIMIT $2
        )`, [job.retentionDays, job.batchSize]);
      job.lastBatchMs = Date.now() - t0;
      job.batches += 1;
      job.deleted += r.rowCount;
      if (r.rowCount < job.batchSize) break;
      if (job.pauseMs) await new Promise(resolve => setTimeout(resolve, job.pauseMs));
    }
    if (job.cancelRequested) {
      job.status = 'cancelled';
    } else if (job.vacuum && job.deleted > 0) {
      // Plain VACUUM takes no exclusive lock; it makes the freed space reusable
      // and refreshes planner statistics. It does not shrink the files.
      job.status = 'vacuuming';
      await client.query(`SET statement_timeout = 0`);
      const { rows } = await client.query(`SELECT tablename FROM pg_tables WHERE schemaname = 'public' AND tablename = ANY($1)`, [LC_TABLES]);
      await client.query(`VACUUM (ANALYZE) ${rows.map(t => `"${t.tablename}"`).join(', ')}`);
      job.status = 'done';
    } else {
      job.status = 'done';
    }
  } catch (e) {
    job.status = 'error';
    job.error = e.message;
  } finally {
    job.finishedAt = new Date().toISOString();
    try { await client.query('RESET statement_timeout'); } catch {}
    client.release();
  }
}

module.exports = router;
