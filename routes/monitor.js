const router = require('express').Router();
const { DescribeAlarmsCommand, GetMetricDataCommand, SetAlarmStateCommand } = require('@aws-sdk/client-cloudwatch');
const { DescribeCacheClustersCommand } = require('@aws-sdk/client-elasticache');
const { DescribeDBInstancesCommand } = require('@aws-sdk/client-rds');
const { DescribeInstancesCommand } = require('@aws-sdk/client-ec2');
const { DescribeLoadBalancersCommand } = require('@aws-sdk/client-elastic-load-balancing-v2');
const { DescribeLogGroupsCommand, FilterLogEventsCommand } = require('@aws-sdk/client-cloudwatch-logs');
const { ListBucketsCommand } = require('@aws-sdk/client-s3');
const { ListDistributionsCommand } = require('@aws-sdk/client-cloudfront');
const { Pool } = require('pg');
const { cloudfrontClient, cloudwatchClient, cwLogsClient, ec2Client, elasticacheClient, elbv2Client, rdsClient, s3Client } = require('../lib/aws');
const { pools, query } = require('../lib/db');

// ─── Routes: monitoring – infra overview ─────────────────────────────────────
let infraCache = null;
router.get('/api/monitor/infra/overview', async (req, res) => {
  try {
    const now = Date.now();
    if (infraCache && now - infraCache.ts < 30000) return res.json(infraCache.data);

    const [ec2Res, rdsRes, redisRes, albRes, cfRes, s3Res] = await Promise.all([
      ec2Client.send(new DescribeInstancesCommand({ Filters: [{ Name: 'instance-state-name', Values: ['running', 'stopped', 'pending'] }] })),
      rdsClient.send(new DescribeDBInstancesCommand({})),
      elasticacheClient.send(new DescribeCacheClustersCommand({ ShowCacheNodeInfo: true })),
      elbv2Client.send(new DescribeLoadBalancersCommand({})),
      cloudfrontClient.send(new ListDistributionsCommand({})),
      s3Client.send(new ListBucketsCommand({})),
    ]);

    const data = {
      ec2: ec2Res.Reservations.flatMap(r => r.Instances).map(i => ({
        id: i.InstanceId,
        name: i.Tags?.find(t => t.Key === 'Name')?.Value || i.InstanceId,
        state: i.State.Name,
        type: i.InstanceType,
        launchTime: i.LaunchTime,
        publicIp: i.PublicIpAddress || null,
        privateIp: i.PrivateIpAddress || null,
        az: i.Placement?.AvailabilityZone,
      })),
      rds: rdsRes.DBInstances.map(db => ({
        id: db.DBInstanceIdentifier,
        status: db.DBInstanceStatus,
        engine: db.Engine,
        engineVersion: db.EngineVersion,
        class: db.DBInstanceClass,
        endpoint: db.Endpoint?.Address || null,
        port: db.Endpoint?.Port || null,
        storage: db.AllocatedStorage,
        multiAz: db.MultiAZ,
      })),
      redis: redisRes.CacheClusters.map(c => ({
        id: c.CacheClusterId,
        status: c.CacheClusterStatus,
        engine: c.Engine,
        engineVersion: c.EngineVersion,
        nodeType: c.CacheNodeType,
        nodes: (c.CacheNodes || []).map(n => ({ id: n.CacheNodeId, status: n.CacheNodeStatus, endpoint: n.Endpoint?.Address || null })),
      })),
      alb: albRes.LoadBalancers.map(lb => ({
        name: lb.LoadBalancerName,
        arn: lb.LoadBalancerArn,
        arnSuffix: lb.LoadBalancerArn.split(':loadbalancer/')[1] || lb.LoadBalancerName,
        state: lb.State.Code,
        dns: lb.DNSName,
        type: lb.Type,
        scheme: lb.Scheme,
      })),
      cloudfront: ((cfRes.DistributionList && cfRes.DistributionList.Items) || []).map(d => ({
        id: d.Id,
        domain: d.DomainName,
        status: d.Status,
        origin: (d.Origins && d.Origins.Items && d.Origins.Items[0]) ? d.Origins.Items[0].DomainName : null,
        aliases: (d.Aliases && d.Aliases.Items) || [],
        enabled: d.Enabled,
      })),
      s3: (s3Res.Buckets || []).map(b => ({ name: b.Name, created: b.CreationDate })),
    };

    infraCache = { ts: now, data };
    res.json(data);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ─── Routes: monitoring – cloudwatch alarms ───────────────────────────────────
router.get('/api/monitor/cloudwatch/alarms', async (req, res) => {
  try {
    const result = await cloudwatchClient.send(new DescribeAlarmsCommand({ MaxRecords: 100 }));
    const alarms = (result.MetricAlarms || []).map(a => ({
      name: a.AlarmName,
      state: a.StateValue,
      reason: a.StateReason,
      updatedAt: a.StateUpdatedTimestamp,
      metric: a.MetricName,
      namespace: a.Namespace,
      threshold: a.Threshold,
      comparisonOp: a.ComparisonOperator,
      period: a.Period,
      dimensions: a.Dimensions,
      description: a.AlarmDescription || null,
    }));
    res.json(alarms);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ─── Routes: monitoring – alarm reset ────────────────────────────────────────
router.post('/api/monitor/alarms/:name/reset', async (req, res) => {
  try {
    await cloudwatchClient.send(new SetAlarmStateCommand({
      AlarmName: req.params.name,
      StateValue: 'OK',
      StateReason: 'Manually reset from LC Monitor',
    }));
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ─── Routes: monitoring – cloudwatch metrics ──────────────────────────────────
router.post('/api/monitor/cloudwatch/metrics', async (req, res) => {
  try {
    const { queries, startTime, endTime } = req.body;
    if (!queries || !queries.length) return res.status(400).json({ error: 'queries required' });
    const result = await cloudwatchClient.send(new GetMetricDataCommand({
      MetricDataQueries: queries.map((q, i) => ({
        Id: q.id || `m${i}`,
        MetricStat: {
          Metric: {
            Namespace: q.namespace,
            MetricName: q.metricName,
            Dimensions: (q.dimensions || []).map(d => ({ Name: d.name, Value: d.value })),
          },
          Period: q.period || 300,
          Stat: q.stat || 'Average',
        },
        Label: q.label || q.metricName,
      })),
      StartTime: new Date(startTime),
      EndTime: new Date(endTime),
    }));
    res.json(result.MetricDataResults || []);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ─── Routes: monitoring – cloudwatch log groups ───────────────────────────────
router.get('/api/monitor/logs/cloudwatch/groups', async (req, res) => {
  try {
    const result = await cwLogsClient.send(new DescribeLogGroupsCommand({}));
    res.json((result.logGroups || []).map(g => ({ name: g.logGroupName, bytes: g.storedBytes, retention: g.retentionInDays })));
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

router.get('/api/monitor/logs/cloudwatch/events', async (req, res) => {
  try {
    const { logGroup, filterPattern = '', limit = 50, startTime, endTime, nextToken } = req.query;
    if (!logGroup) return res.status(400).json({ error: 'logGroup required' });
    const params = { logGroupName: logGroup, limit: parseInt(limit) };
    if (filterPattern) params.filterPattern = filterPattern;
    if (startTime) params.startTime = parseInt(startTime);
    if (endTime) params.endTime = parseInt(endTime);
    if (nextToken) params.nextToken = nextToken;
    const result = await cwLogsClient.send(new FilterLogEventsCommand(params));
    res.json({ events: result.events || [], nextToken: result.nextToken });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ─── Routes: monitoring – error summary ──────────────────────────────────────
router.get('/api/monitor/errors/summary', async (req, res) => {
  try {
    const [hourly, topEndpoints, totalRow, recentRows] = await Promise.all([
      query(req, `
        SELECT date_trunc('hour', "time") AS hour, COUNT(*)::int AS count
        FROM serverpod_session_log
        WHERE "time" > NOW() - INTERVAL '24 hours' AND error IS NOT NULL
        GROUP BY 1 ORDER BY 1 ASC
      `),
      query(req, `
        SELECT COALESCE(endpoint, 'unknown') AS endpoint, COUNT(*)::int AS count
        FROM serverpod_session_log
        WHERE error IS NOT NULL AND "time" > NOW() - INTERVAL '24 hours'
        GROUP BY endpoint ORDER BY count DESC LIMIT 10
      `),
      query(req, `SELECT COUNT(*)::int AS count FROM serverpod_session_log WHERE error IS NOT NULL AND "time" > NOW() - INTERVAL '24 hours'`),
      query(req, `
        SELECT id, "time", endpoint, method, duration, error, "stackTrace"
        FROM serverpod_session_log
        WHERE error IS NOT NULL
        ORDER BY "time" DESC LIMIT 30
      `),
    ]);
    res.json({ hourly, topEndpoints, total: totalRow[0]?.count || 0, recent: recentRows });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

router.get('/api/monitor/errors/pms-downtime', async (req, res) => {
  try {
    const rows = await query(req, `
      SELECT id, "totalDownTimeInSeconds", "createdAt"
      FROM analytics_pms_downtime
      ORDER BY "createdAt" DESC LIMIT 50
    `);
    res.json(rows);
  } catch (e) {
    // Table might not exist in all environments
    res.json([]);
  }
});

// ─── Routes: monitoring – slow endpoints ─────────────────────────────────────
router.get('/api/monitor/errors/slow', async (req, res) => {
  try {
    const [totalRow, topSlow, slowest] = await Promise.all([
      query(req, `SELECT COUNT(*)::int AS count FROM serverpod_session_log WHERE slow = true AND "time" > NOW() - INTERVAL '24 hours'`),
      query(req, `
        SELECT COALESCE(endpoint, 'unknown') AS endpoint,
               COUNT(*)::int AS count,
               ROUND((AVG(duration) * 1000)::numeric, 0) AS "avgMs",
               ROUND((MAX(duration) * 1000)::numeric, 0) AS "maxMs"
        FROM serverpod_session_log
        WHERE slow = true AND "time" > NOW() - INTERVAL '24 hours'
        GROUP BY endpoint ORDER BY "avgMs" DESC LIMIT 10
      `),
      query(req, `
        SELECT id, "time", endpoint, method, duration, "numQueries"
        FROM serverpod_session_log
        WHERE slow = true AND "time" > NOW() - INTERVAL '24 hours'
        ORDER BY duration DESC LIMIT 20
      `),
    ]);
    res.json({ total: totalRow[0]?.count || 0, topSlow, slowest });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ─── Routes: monitoring – long-lived sessions ────────────────────────────────
router.get('/api/monitor/errors/longlived', async (req, res) => {
  try {
    const [topEndpoints, openConnections] = await Promise.all([
      query(req, `
        SELECT endpoint, COALESCE(method, '') AS method,
               COUNT(*)::int AS count,
               ROUND((AVG(duration) * 1000)::numeric, 0) AS "avgMs",
               ROUND((MAX(duration) * 1000)::numeric, 0) AS "maxMs"
        FROM serverpod_session_log
        WHERE "time" > NOW() - INTERVAL '24 hours'
          AND duration IS NOT NULL AND "isOpen" = false
        GROUP BY endpoint, method
        ORDER BY "avgMs" DESC LIMIT 15
      `),
      query(req, `
        SELECT id, "time", endpoint, method,
               ROUND(EXTRACT(EPOCH FROM (NOW() - "time"))::numeric, 0) AS "openSeconds",
               "authenticatedUserId"
        FROM serverpod_session_log
        WHERE "isOpen" = true
        ORDER BY "time" ASC LIMIT 100
      `),
    ]);
    res.json({ topEndpoints, openConnections });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ─── Routes: monitoring – live log SSE stream ────────────────────────────────
// EventSource doesn't support custom headers, so DB config comes via query params.
router.get('/api/monitor/logs/stream', (req, res) => {
  res.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache',
    'Connection': 'keep-alive',
    'X-Accel-Buffering': 'no',
  });
  res.write(': connected\n\n');

  const heartbeat = setInterval(() => res.write(`data: ${JSON.stringify({ type: 'ping', ts: new Date().toISOString() })}\n\n`), 10000);

  // Build pool from query params
  const host = req.query.dbHost || 'localhost';
  const port = parseInt(req.query.dbPort || '8090');
  const database = req.query.dbName || 'lillian_care_core';
  const user = req.query.dbUser || 'postgres';
  const password = req.query.dbPass || '';

  const key = `${host}:${port}/${database}:${user}:${password}`;
  if (!pools[key]) {
    pools[key] = new Pool({
      host, port, database, user, password,
      max: 2,
      idleTimeoutMillis: 60000,
      connectionTimeoutMillis: 5000,
      ssl: host !== 'localhost' ? { rejectUnauthorized: false } : false,
    });
  }
  const pool = pools[key];

  // Send recent logs immediately on connect (last 5 minutes of history)
  (async () => {
    try {
      const since = new Date(Date.now() - 5 * 60 * 1000).toISOString();
      const [sessionErrors, appLogs] = await Promise.all([
        pool.query(
          `SELECT id, "time", endpoint, method, duration, error, "stackTrace", "authenticatedUserId"
           FROM serverpod_session_log
           WHERE "time" > $1 AND error IS NOT NULL
           ORDER BY "time" DESC LIMIT 30`,
          [since]
        ),
        pool.query(
          `SELECT sl.id, sl."time", sl."logLevel", sl.message, sl.error, sl."stackTrace",
                  ss.endpoint, ss.method
           FROM serverpod_log sl
           JOIN serverpod_session_log ss ON ss.id = sl."sessionLogId"
           WHERE sl."time" > $1
           ORDER BY sl."time" DESC LIMIT 50`,
          [since]
        ),
      ]);
      res.write(`data: ${JSON.stringify({ type: 'history', sessionErrors: sessionErrors.rows.reverse(), appLogs: appLogs.rows.reverse() })}\n\n`);
    } catch (e) {
      res.write(`data: ${JSON.stringify({ type: 'error', message: e.message || e.code || String(e) })}\n\n`);
    }
  })();

  let lastTime = new Date().toISOString();

  const pollInterval = setInterval(async () => {
    try {
      const [sessionErrors, appLogs] = await Promise.all([
        pool.query(
          `SELECT id, "time", endpoint, method, duration, error, "stackTrace", "authenticatedUserId"
           FROM serverpod_session_log
           WHERE "time" > $1 AND error IS NOT NULL
           ORDER BY "time" ASC LIMIT 20`,
          [lastTime]
        ),
        pool.query(
          `SELECT sl.id, sl."time", sl."logLevel", sl.message, sl.error, sl."stackTrace",
                  ss.endpoint, ss.method
           FROM serverpod_log sl
           JOIN serverpod_session_log ss ON ss.id = sl."sessionLogId"
           WHERE sl."time" > $1
           ORDER BY sl."time" ASC LIMIT 50`,
          [lastTime]
        ),
      ]);

      const newTs = new Date().toISOString();
      if (sessionErrors.rows.length > 0 || appLogs.rows.length > 0) {
        lastTime = newTs;
        res.write(`data: ${JSON.stringify({ type: 'logs', sessionErrors: sessionErrors.rows, appLogs: appLogs.rows, ts: newTs })}\n\n`);
      } else {
        lastTime = newTs;
      }
    } catch (e) {
      res.write(`data: ${JSON.stringify({ type: 'error', message: e.message || e.code || String(e) })}\n\n`);
    }
  }, 5000);

  req.on('close', () => {
    clearInterval(heartbeat);
    clearInterval(pollInterval);
  });
});

// ─── Routes: monitoring – endpoint health checks ─────────────────────────────
const HEALTH_ENDPOINTS = [
  { name: 'API',      env: 'production', url: 'https://api.lillian.care/' },
  { name: 'Insights', env: 'production', url: 'https://insights.lillian.care/' },
  { name: 'API',      env: 'staging',    url: 'https://api-staging.lillian.care/' },
  { name: 'Insights', env: 'staging',    url: 'https://insights-staging.lillian.care/' },
  { name: 'API',      env: 'test',       url: 'https://api-test.lillian.care/' },
  { name: 'Insights', env: 'test',       url: 'https://insights-test.lillian.care/' },
];
let endpointCache = null;

router.get('/api/monitor/endpoints/health', async (req, res) => {
  try {
    const now = Date.now();
    if (endpointCache && now - endpointCache.ts < 30000) return res.json(endpointCache.data);

    const results = await Promise.all(HEALTH_ENDPOINTS.map(async ep => {
      const start = Date.now();
      try {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), 5000);
        const r = await fetch(ep.url, { method: 'HEAD', signal: controller.signal, redirect: 'follow' });
        clearTimeout(timer);
        return { ...ep, ok: r.status < 500, status: r.status, latencyMs: Date.now() - start };
      } catch (e) {
        return { ...ep, ok: false, status: null, latencyMs: Date.now() - start, error: e.name === 'AbortError' ? 'timeout' : 'unreachable' };
      }
    }));

    endpointCache = { ts: now, data: { endpoints: results, checkedAt: new Date().toISOString() } };
    res.json(endpointCache.data);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

module.exports = router;
