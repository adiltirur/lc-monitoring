const router = require('express').Router();
const dns = require('dns').promises;
const { GetMetricDataCommand } = require('@aws-sdk/client-cloudwatch');
const { DescribeDBInstancesCommand } = require('@aws-sdk/client-rds');
const { getPool } = require('../lib/db');
const { cloudwatchClient, rdsClient } = require('../lib/aws');

// ─── Helpers: read-only diagnostics session ───────────────────────────────────
// Every diagnostic query runs in a READ ONLY transaction with a short statement
// timeout, so the page can never change data or pile more load onto a database
// that is already struggling. Optional probes run behind a savepoint so one
// failure (e.g. pg_stat_statements not loaded) does not abort the rest.
async function withReadOnly(req, fn) {
  const client = await getPool(req).connect();
  try {
    await client.query('BEGIN READ ONLY');
    await client.query(`SET LOCAL statement_timeout = '15s'`);
    const run = async (sql, params = []) => (await client.query(sql, params)).rows;
    const safe = async (sql, params = []) => {
      await client.query('SAVEPOINT probe');
      try {
        const rows = await run(sql, params);
        await client.query('RELEASE SAVEPOINT probe');
        return { rows };
      } catch (e) {
        await client.query('ROLLBACK TO SAVEPOINT probe');
        return { error: e.message };
      }
    };
    return await fn(run, safe);
  } finally {
    await client.query('ROLLBACK').catch(() => {});
    client.release();
  }
}

const SQL_CONNECTIONS = `
  SELECT coalesce(state, 'background') AS state, count(*)::int AS count
  FROM pg_stat_activity WHERE datname = current_database()
  GROUP BY 1 ORDER BY 2 DESC`;

const SQL_LONG_RUNNING = `
  SELECT pid, extract(epoch FROM now() - query_start)::int AS seconds, state,
         wait_event_type, wait_event,
         left(regexp_replace(query, '\\s+', ' ', 'g'), 200) AS query
  FROM pg_stat_activity
  WHERE datname = current_database() AND pid <> pg_backend_pid()
    AND state <> 'idle' AND now() - query_start > interval '5 seconds'
  ORDER BY query_start LIMIT 25`;

const SQL_BLOCKED = `
  SELECT blocked.pid AS blocked_pid,
         extract(epoch FROM now() - blocked.query_start)::int AS waiting_seconds,
         left(regexp_replace(blocked.query, '\\s+', ' ', 'g'), 120) AS blocked_query,
         blocker.pid AS blocker_pid, blocker.state AS blocker_state,
         left(regexp_replace(blocker.query, '\\s+', ' ', 'g'), 120) AS blocker_query
  FROM pg_stat_activity blocked
  JOIN LATERAL unnest(pg_blocking_pids(blocked.pid)) AS b(pid) ON true
  JOIN pg_stat_activity blocker ON blocker.pid = b.pid
  LIMIT 25`;

const SQL_IDLE_IN_TX = `
  SELECT pid, extract(epoch FROM now() - xact_start)::int AS open_seconds,
         left(regexp_replace(query, '\\s+', ' ', 'g'), 120) AS last_query
  FROM pg_stat_activity
  WHERE datname = current_database() AND state LIKE 'idle in transaction%'
  ORDER BY xact_start LIMIT 25`;

const SQL_SEQ_SCANS = `
  SELECT relname AS table, seq_scan::float8 AS seq_scans, seq_tup_read::float8 AS rows_read,
         coalesce(idx_scan, 0)::float8 AS index_scans, n_live_tup::float8 AS live_rows,
         pg_relation_size(relid)::float8 AS bytes
  FROM pg_stat_user_tables
  WHERE seq_scan > 0 AND pg_relation_size(relid) > 10 * 1024 * 1024
  ORDER BY seq_tup_read DESC LIMIT 10`;

const SQL_BIGGEST = `
  SELECT relname AS table, pg_total_relation_size(relid)::float8 AS total_bytes,
         pg_relation_size(relid)::float8 AS table_bytes, n_live_tup::float8 AS live_rows,
         n_dead_tup::float8 AS dead_rows
  FROM pg_stat_user_tables ORDER BY pg_total_relation_size(relid) DESC LIMIT 10`;

const SQL_DB_SIZE = `
  SELECT pg_database_size(current_database())::float8 AS bytes,
         (SELECT stats_reset FROM pg_stat_database WHERE datname = current_database()) AS stats_reset`;

const SQL_STATEMENTS = `
  SELECT calls::float8 AS calls, round(total_exec_time)::float8 AS total_ms,
         round(mean_exec_time::numeric, 1)::float8 AS mean_ms, shared_blks_read::float8 AS disk_blocks_read,
         left(regexp_replace(query, '\\s+', ' ', 'g'), 200) AS query
  FROM pg_stat_statements
  WHERE dbid = (SELECT oid FROM pg_database WHERE datname = current_database())
  ORDER BY total_exec_time DESC LIMIT 10`;

const SQL_SLOW_QUERIES = `
  SELECT s.time AS at, round(q.duration::numeric, 2)::float8 AS seconds, q.error IS NOT NULL AS failed,
         left(regexp_replace(q.query, '\\s+', ' ', 'g'), 300) AS query
  FROM serverpod_query_log q
  JOIN serverpod_session_log s ON s.id = q."sessionLogId"
  WHERE s.time > now() - make_interval(hours => $1) AND q.duration >= 1
  ORDER BY q.duration DESC LIMIT 25`;

function parseLogSettings(rows) {
  const raw = rows && rows[0] && rows[0].logSettings;
  if (!raw) return null;
  if (typeof raw === 'object') return raw;
  try { return JSON.parse(raw); } catch { return null; }
}

// ─── Helpers: RDS instance + CloudWatch metrics ───────────────────────────────
// database*.lillian.care are CNAMEs onto the RDS endpoint, whose first label
// is the DB instance identifier (lc-core, lc-core-staging, …).
async function rdsInstanceIdForHost(host) {
  if (!host || host === 'localhost' || host === '127.0.0.1') return null;
  let target = host;
  if (!host.endsWith('.rds.amazonaws.com')) {
    const cnames = await dns.resolveCname(host).catch(() => []);
    target = cnames.find(c => c.endsWith('.rds.amazonaws.com')) || '';
  }
  return target ? target.split('.')[0] : null;
}

const RDS_METRICS = [
  'EBSByteBalance%', 'EBSIOBalance%', 'ReadLatency', 'WriteLatency', 'DiskQueueDepth',
  'CPUUtilization', 'FreeableMemory', 'FreeStorageSpace', 'DatabaseConnections',
];

async function rdsMetrics(instanceId, hours) {
  const end = new Date();
  const start = new Date(end.getTime() - hours * 3600 * 1000);
  const result = await cloudwatchClient.send(new GetMetricDataCommand({
    MetricDataQueries: RDS_METRICS.map((name, i) => ({
      Id: `m${i}`,
      Label: name,
      MetricStat: {
        Metric: {
          Namespace: 'AWS/RDS',
          MetricName: name,
          Dimensions: [{ Name: 'DBInstanceIdentifier', Value: instanceId }],
        },
        Period: 300,
        Stat: 'Average',
      },
    })),
    StartTime: start,
    EndTime: end,
    ScanBy: 'TimestampAscending',
  }));
  const series = {};
  for (const r of result.MetricDataResults || []) {
    series[r.Label] = (r.Timestamps || []).map((t, i) => ({ t, v: r.Values[i] }));
  }
  return series;
}

// ─── Routes: overview (live activity, tables, top queries, log settings) ──────
router.get('/api/db-diag/overview', async (req, res) => {
  try {
    const data = await withReadOnly(req, async (run, safe) => {
      const [dbInfo] = await run(SQL_DB_SIZE);
      const connections = await run(SQL_CONNECTIONS);
      const longRunning = await run(SQL_LONG_RUNNING);
      const blocked = await run(SQL_BLOCKED);
      const idleInTx = await run(SQL_IDLE_IN_TX);
      const seqScans = await run(SQL_SEQ_SCANS);
      const biggest = await run(SQL_BIGGEST);
      const ext = await run(`SELECT 1 FROM pg_extension WHERE extname = 'pg_stat_statements'`);
      const statements = ext.length
        ? { installed: true, ...(await safe(SQL_STATEMENTS)) }
        : { installed: false, rows: [] };
      const settings = await safe(`SELECT "logSettings" FROM serverpod_runtime_settings ORDER BY id LIMIT 1`);
      return {
        dbBytes: dbInfo.bytes,
        statsReset: dbInfo.stats_reset,
        connections, longRunning, blocked, idleInTx, seqScans, biggest, statements,
        logSettings: settings.error ? null : parseLogSettings(settings.rows),
      };
    });
    res.json(data);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ─── Routes: slow queries recorded by Serverpod (≥ 1 s) ───────────────────────
router.get('/api/db-diag/slow-queries', async (req, res) => {
  try {
    const hours = Math.min(Math.max(parseInt(req.query.hours) || 24, 1), 168);
    const rows = await withReadOnly(req, run => run(SQL_SLOW_QUERIES, [hours]));
    res.json({ hours, rows });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ─── Routes: RDS status + CloudWatch disk/CPU metrics ─────────────────────────
router.get('/api/db-diag/rds', async (req, res) => {
  try {
    const instanceId = await rdsInstanceIdForHost(req.headers['x-db-host']);
    if (!instanceId) return res.json({ instanceId: null });
    const hours = Math.min(Math.max(parseInt(req.query.hours) || 3, 1), 24);
    const [desc, series] = await Promise.all([
      rdsClient.send(new DescribeDBInstancesCommand({ DBInstanceIdentifier: instanceId })),
      rdsMetrics(instanceId, hours),
    ]);
    const db = (desc.DBInstances || [])[0] || {};
    res.json({
      instanceId, hours,
      status: db.DBInstanceStatus,
      instanceClass: db.DBInstanceClass,
      engineVersion: db.EngineVersion,
      multiAZ: db.MultiAZ,
      pending: db.PendingModifiedValues || {},
      series,
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ─── Routes: enable pg_stat_statements (one-time, not read-only) ──────────────
router.post('/api/db-diag/enable-statements', async (req, res) => {
  try {
    if (!req.body || req.body.confirm !== true) return res.status(400).json({ error: 'confirm required' });
    await getPool(req).query('CREATE EXTENSION IF NOT EXISTS pg_stat_statements');
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

module.exports = router;
