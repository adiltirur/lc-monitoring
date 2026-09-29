const router = require('express').Router();
const { CreateDBInstanceCommand, DeleteDBClusterCommand, DeleteDBInstanceCommand, DescribeDBClustersCommand, DescribeDBInstancesCommand, RDSClient, RestoreDBClusterFromSnapshotCommand, RestoreDBClusterToPointInTimeCommand, RestoreDBInstanceFromDBSnapshotCommand, RestoreDBInstanceToPointInTimeCommand } = require('@aws-sdk/client-rds');
const { AWS_REGION, rdsClient } = require('../lib/aws');
const { bindValue, poolFromHeaders, poolQuery, quoteIdent, tableColumns } = require('../lib/db');

// ═════════════════════════════════════════════════════════════════════════════
// RDS RESTORE wizard (`/api/rds-restore/*`, view `#rds-restore`)
// Single-table restore from a snapshot or PITR. Each endpoint maps to one card
// in the UI. Destructive endpoints require an explicit body confirmation.
// ═════════════════════════════════════════════════════════════════════════════

function rdsClientFor(region) {
  return region && region !== AWS_REGION ? new RDSClient({ region }) : rdsClient;
}

// ── POST /api/rds-restore/aws/describe-cluster ────────────────────────────────
// Body: { region, clusterId }. Returns cluster + first-instance config so the
// UI can auto-fill engine, subnet, security group, instance class.
router.post('/api/rds-restore/aws/describe-cluster', async (req, res) => {
  try {
    const { region, clusterId } = req.body || {};
    if (!clusterId) return res.status(400).json({ error: 'clusterId required' });
    const client = rdsClientFor(region);

    // Try Aurora cluster first.
    let clusterFound = null;
    try {
      const clusters = await client.send(new DescribeDBClustersCommand({ DBClusterIdentifier: clusterId }));
      clusterFound = clusters.DBClusters && clusters.DBClusters[0];
    } catch (e) {
      if (!/not found/i.test(e.message) && e.name !== 'DBClusterNotFoundFault') throw e;
    }

    if (clusterFound) {
      const c = clusterFound;
      const instances = await client.send(new DescribeDBInstancesCommand({
        Filters: [{ Name: 'db-cluster-id', Values: [clusterId] }],
      }));
      const i = instances.DBInstances && instances.DBInstances[0];
      return res.json({
        kind: 'cluster',
        cluster: {
          engine: c.Engine,
          engineVersion: c.EngineVersion,
          endpoint: c.Endpoint,
          port: c.Port,
          masterUser: c.MasterUsername,
          subnetGroup: c.DBSubnetGroup,
          securityGroups: (c.VpcSecurityGroups || []).map(s => s.VpcSecurityGroupId),
          earliestRestorableTime: c.EarliestRestorableTime,
          latestRestorableTime: c.LatestRestorableTime,
          status: c.Status,
        },
        instance: i ? {
          instanceClass: i.DBInstanceClass,
          publiclyAccessible: i.PubliclyAccessible,
          availabilityZone: i.AvailabilityZone,
        } : null,
      });
    }

    // Fall back to regular RDS instance.
    const instOut = await client.send(new DescribeDBInstancesCommand({ DBInstanceIdentifier: clusterId }));
    const i = instOut.DBInstances && instOut.DBInstances[0];
    if (!i) return res.status(404).json({ error: `Neither cluster nor instance found for "${clusterId}"` });
    return res.json({
      kind: 'instance',
      cluster: {
        engine: i.Engine,
        engineVersion: i.EngineVersion,
        endpoint: i.Endpoint?.Address || null,
        port: i.Endpoint?.Port || null,
        masterUser: i.MasterUsername,
        subnetGroup: i.DBSubnetGroup?.DBSubnetGroupName,
        securityGroups: (i.VpcSecurityGroups || []).map(s => s.VpcSecurityGroupId),
        earliestRestorableTime: i.EarliestRestorableTime,
        latestRestorableTime: i.LatestRestorableTime,
        status: i.DBInstanceStatus,
      },
      instance: {
        instanceClass: i.DBInstanceClass,
        publiclyAccessible: i.PubliclyAccessible,
        availabilityZone: i.AvailabilityZone,
      },
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ── POST /api/rds-restore/aws/restore-cluster ─────────────────────────────────
// Body: {
//   region, mode: 'snapshot' | 'pitr',
//   tempClusterId, engine, engineVersion, subnetGroup, securityGroups: [],
//   // mode=snapshot:
//   snapshotId,
//   // mode=pitr:
//   srcClusterId, pitrTime (ISO),
//   confirm: 'YES'
// }
router.post('/api/rds-restore/aws/restore-cluster', async (req, res) => {
  try {
    const b = req.body || {};
    if (b.confirm !== 'YES') return res.status(400).json({ error: 'Body confirm must be "YES" (creates a new billable resource)' });
    if (!b.subnetGroup) return res.status(400).json({ error: 'subnetGroup required' });
    if (!b.securityGroups || !b.securityGroups.length) return res.status(400).json({ error: 'securityGroups required' });
    const client = rdsClientFor(b.region);
    const kind = b.kind === 'instance' ? 'instance' : 'cluster';

    if (kind === 'cluster') {
      if (!b.tempClusterId) return res.status(400).json({ error: 'tempClusterId required' });
      if (b.mode === 'pitr') {
        if (!b.srcClusterId) return res.status(400).json({ error: 'srcClusterId required for PITR' });
        if (!b.pitrTime) return res.status(400).json({ error: 'pitrTime required for PITR' });
        const out = await client.send(new RestoreDBClusterToPointInTimeCommand({
          DBClusterIdentifier: b.tempClusterId,
          SourceDBClusterIdentifier: b.srcClusterId,
          RestoreToTime: new Date(b.pitrTime),
          DBSubnetGroupName: b.subnetGroup,
          VpcSecurityGroupIds: b.securityGroups,
        }));
        return res.json({ kind, identifier: b.tempClusterId, arn: out.DBCluster?.DBClusterArn, status: out.DBCluster?.Status });
      }
      if (!b.snapshotId) return res.status(400).json({ error: 'snapshotId required for snapshot mode' });
      const out = await client.send(new RestoreDBClusterFromSnapshotCommand({
        DBClusterIdentifier: b.tempClusterId,
        SnapshotIdentifier: b.snapshotId,
        Engine: b.engine || 'aurora-postgresql',
        EngineVersion: b.engineVersion || undefined,
        DBSubnetGroupName: b.subnetGroup,
        VpcSecurityGroupIds: b.securityGroups,
      }));
      return res.json({ kind, identifier: b.tempClusterId, arn: out.DBCluster?.DBClusterArn, status: out.DBCluster?.Status });
    }

    // kind === 'instance' — regular RDS. The restore call creates the new
    // instance directly; there is no separate cluster + create-instance step.
    if (!b.tempInstanceId) return res.status(400).json({ error: 'tempInstanceId required for instance mode' });
    if (b.mode === 'pitr') {
      if (!b.srcClusterId) return res.status(400).json({ error: 'srcClusterId required for PITR (source instance id)' });
      if (!b.pitrTime) return res.status(400).json({ error: 'pitrTime required for PITR' });
      const out = await client.send(new RestoreDBInstanceToPointInTimeCommand({
        SourceDBInstanceIdentifier: b.srcClusterId,
        TargetDBInstanceIdentifier: b.tempInstanceId,
        RestoreTime: new Date(b.pitrTime),
        DBSubnetGroupName: b.subnetGroup,
        VpcSecurityGroupIds: b.securityGroups,
        DBInstanceClass: b.instanceClass || undefined,
        PubliclyAccessible: !!b.publiclyAccessible,
      }));
      return res.json({ kind, identifier: b.tempInstanceId, arn: out.DBInstance?.DBInstanceArn, status: out.DBInstance?.DBInstanceStatus });
    }
    if (!b.snapshotId) return res.status(400).json({ error: 'snapshotId required for snapshot mode' });
    const out = await client.send(new RestoreDBInstanceFromDBSnapshotCommand({
      DBInstanceIdentifier: b.tempInstanceId,
      DBSnapshotIdentifier: b.snapshotId,
      DBSubnetGroupName: b.subnetGroup,
      VpcSecurityGroupIds: b.securityGroups,
      DBInstanceClass: b.instanceClass || undefined,
      Engine: b.engine || 'postgres',
      PubliclyAccessible: !!b.publiclyAccessible,
    }));
    return res.json({ kind, identifier: b.tempInstanceId, arn: out.DBInstance?.DBInstanceArn, status: out.DBInstance?.DBInstanceStatus });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ── POST /api/rds-restore/aws/create-instance ─────────────────────────────────
// Body: { region, tempClusterId, tempInstanceId, instanceClass, engine, publiclyAccessible, confirm: 'YES' }
router.post('/api/rds-restore/aws/create-instance', async (req, res) => {
  try {
    const b = req.body || {};
    if (b.confirm !== 'YES') return res.status(400).json({ error: 'Body confirm must be "YES" (creates a billable instance)' });
    if (!b.tempClusterId || !b.tempInstanceId) return res.status(400).json({ error: 'tempClusterId and tempInstanceId required' });
    const client = rdsClientFor(b.region);
    const out = await client.send(new CreateDBInstanceCommand({
      DBInstanceIdentifier: b.tempInstanceId,
      DBClusterIdentifier: b.tempClusterId,
      DBInstanceClass: b.instanceClass || 'db.t3.medium',
      Engine: b.engine || 'aurora-postgresql',
      PubliclyAccessible: !!b.publiclyAccessible,
    }));
    res.json({ instanceArn: out.DBInstance?.DBInstanceArn, status: out.DBInstance?.DBInstanceStatus });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ── POST /api/rds-restore/aws/instance-status ─────────────────────────────────
// Body: { region, tempInstanceId }. Returns { status, endpoint }. Frontend
// polls this in a loop until status === 'available'.
router.post('/api/rds-restore/aws/instance-status', async (req, res) => {
  try {
    const { region, tempInstanceId, tempClusterId } = req.body || {};
    if (!tempInstanceId) return res.status(400).json({ error: 'tempInstanceId required' });
    const client = rdsClientFor(region);
    const inst = await client.send(new DescribeDBInstancesCommand({ DBInstanceIdentifier: tempInstanceId }));
    const i = inst.DBInstances && inst.DBInstances[0];
    let endpoint = null;
    if (tempClusterId) {
      try {
        const cl = await client.send(new DescribeDBClustersCommand({ DBClusterIdentifier: tempClusterId }));
        endpoint = cl.DBClusters?.[0]?.Endpoint || null;
      } catch (_) { /* cluster might not exist (instance mode) */ }
    }
    if (!endpoint) endpoint = i?.Endpoint?.Address || null;
    res.json({
      status: i?.DBInstanceStatus || 'unknown',
      endpoint,
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ── POST /api/rds-restore/aws/delete-instance ─────────────────────────────────
router.post('/api/rds-restore/aws/delete-instance', async (req, res) => {
  try {
    const b = req.body || {};
    if (b.confirm !== 'YES') return res.status(400).json({ error: 'Body confirm must be "YES" (destroys the temp instance)' });
    if (!b.tempInstanceId) return res.status(400).json({ error: 'tempInstanceId required' });
    const client = rdsClientFor(b.region);
    const out = await client.send(new DeleteDBInstanceCommand({
      DBInstanceIdentifier: b.tempInstanceId,
      SkipFinalSnapshot: true,
      DeleteAutomatedBackups: true,
    }));
    res.json({ status: out.DBInstance?.DBInstanceStatus });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ── POST /api/rds-restore/aws/delete-cluster ──────────────────────────────────
router.post('/api/rds-restore/aws/delete-cluster', async (req, res) => {
  try {
    const b = req.body || {};
    if (b.confirm !== 'YES') return res.status(400).json({ error: 'Body confirm must be "YES" (destroys the temp cluster)' });
    if (!b.tempClusterId) return res.status(400).json({ error: 'tempClusterId required' });
    const client = rdsClientFor(b.region);
    const out = await client.send(new DeleteDBClusterCommand({
      DBClusterIdentifier: b.tempClusterId,
      SkipFinalSnapshot: true,
    }));
    res.json({ status: out.DBCluster?.Status });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ── POST /api/rds-restore/pg/connect-test ─────────────────────────────────────
// Uses `x-rdsr-<side>-db-*` headers (side: 'temp' or 'prod'). Just runs a
// SELECT 1 against the targeted connection so the UI can show green/red.
router.post('/api/rds-restore/pg/connect-test', async (req, res) => {
  try {
    const side = (req.body?.side === 'prod') ? 'prod' : 'temp';
    const { pool, host, database, user } = poolFromHeaders(req, `x-rdsr-${side}-db-`);
    const rows = await poolQuery(pool, 'SELECT current_database() AS db, current_user AS u, version()');
    res.json({ ok: true, host, database, user, info: rows[0] });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ── POST /api/rds-restore/pg/preview ──────────────────────────────────────────
// Body: { table }, headers: x-rdsr-temp-db-*. Read-only summary of the table.
router.post('/api/rds-restore/pg/preview', async (req, res) => {
  try {
    const { table } = req.body || {};
    if (!table || !/^[A-Za-z_][A-Za-z0-9_]*$/.test(table)) return res.status(400).json({ error: 'Invalid table name' });
    const { pool } = poolFromHeaders(req, 'x-rdsr-temp-db-');
    const cols = await tableColumns(pool, table);
    if (!cols.length) return res.status(404).json({ error: `Table ${table} not found on temp` });
    const colList = cols.map(c => quoteIdent(c.column_name)).join(', ');
    const [{ count }] = await poolQuery(pool, `SELECT COUNT(*)::bigint AS count FROM ${quoteIdent(table)}`);
    const sample = await poolQuery(pool, `SELECT ${colList} FROM ${quoteIdent(table)} ORDER BY ${cols.some(c => c.column_name === 'id') ? '"id" DESC' : '1'} LIMIT 5`);
    res.json({ count: Number(count), columns: cols, sample });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ── POST /api/rds-restore/pg/schema-diff ──────────────────────────────────────
// Body: { table }. Headers: BOTH x-rdsr-temp-db-* and x-rdsr-prod-db-*.
router.post('/api/rds-restore/pg/schema-diff', async (req, res) => {
  try {
    const { table } = req.body || {};
    if (!table || !/^[A-Za-z_][A-Za-z0-9_]*$/.test(table)) return res.status(400).json({ error: 'Invalid table name' });
    const { pool: tempPool } = poolFromHeaders(req, 'x-rdsr-temp-db-');
    const { pool: prodPool } = poolFromHeaders(req, 'x-rdsr-prod-db-');
    const [tempCols, prodCols] = await Promise.all([
      tableColumns(tempPool, table),
      tableColumns(prodPool, table),
    ]);
    if (!tempCols.length) return res.status(404).json({ error: `Table ${table} not found on temp` });
    if (!prodCols.length) return res.status(404).json({ error: `Table ${table} not found on prod` });

    const tempByName = Object.fromEntries(tempCols.map(c => [c.column_name, c]));
    const prodByName = Object.fromEntries(prodCols.map(c => [c.column_name, c]));
    const matched = [];
    const typeMismatch = [];
    const tempOnly = [];
    const prodOnly = [];
    for (const t of tempCols) {
      const p = prodByName[t.column_name];
      if (!p) { tempOnly.push(t); continue; }
      if (t.data_type !== p.data_type || t.udt_name !== p.udt_name) {
        typeMismatch.push({ name: t.column_name, temp: t, prod: p });
      } else {
        matched.push({ name: t.column_name, temp: t, prod: p });
      }
    }
    for (const p of prodCols) {
      if (!tempByName[p.column_name]) prodOnly.push(p);
    }
    res.json({ tempCols, prodCols, matched, typeMismatch, tempOnly, prodOnly });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ── POST /api/rds-restore/pg/restore-table ────────────────────────────────────
// Body: { table, mapping: { prodCol: tempCol }, confirmTable: '<table>' }.
// Headers: BOTH x-rdsr-temp-db-* and x-rdsr-prod-db-*.
// Refuses if prod table has any rows. Wraps entire copy in a transaction.
router.post('/api/rds-restore/pg/restore-table', async (req, res) => {
  try {
    const { table, mapping, confirmTable } = req.body || {};
    if (!table || !/^[A-Za-z_][A-Za-z0-9_]*$/.test(table)) return res.status(400).json({ error: 'Invalid table name' });
    if (confirmTable !== table) return res.status(400).json({ error: 'confirmTable must exactly equal the table name' });
    if (!mapping || typeof mapping !== 'object' || !Object.keys(mapping).length) return res.status(400).json({ error: 'mapping required' });
    const { pool: tempPool } = poolFromHeaders(req, 'x-rdsr-temp-db-');
    const { pool: prodPool } = poolFromHeaders(req, 'x-rdsr-prod-db-');

    // 1. Validate both tables exist.
    const [tempCols, prodCols] = await Promise.all([
      tableColumns(tempPool, table),
      tableColumns(prodPool, table),
    ]);
    if (!tempCols.length) return res.status(404).json({ error: `Table ${table} not found on temp` });
    if (!prodCols.length) return res.status(404).json({ error: `Table ${table} not found on prod` });
    const tempByName = Object.fromEntries(tempCols.map(c => [c.column_name, c]));
    const prodByName = Object.fromEntries(prodCols.map(c => [c.column_name, c]));
    const prodColNames = Object.keys(mapping);
    const tempColNames = prodColNames.map(p => mapping[p]);
    for (const p of prodColNames) {
      if (!prodByName[p]) return res.status(400).json({ error: `mapping target column "${p}" not on prod` });
    }
    for (const t of tempColNames) {
      if (!tempByName[t]) return res.status(400).json({ error: `mapping source column "${t}" not on temp` });
    }

    // 2. Refuse if prod table is non-empty.
    const [{ count: prodCount }] = await poolQuery(prodPool, `SELECT COUNT(*)::bigint AS count FROM ${quoteIdent(table)}`);
    if (BigInt(prodCount) > 0n) return res.status(409).json({ error: `Refusing: prod table has ${prodCount} rows`, prodCount: Number(prodCount) });

    // 3. Stream rows from temp via cursor, insert in batches into prod inside a transaction.
    const BATCH = 500;
    const selectSql = `SELECT ${tempColNames.map(quoteIdent).join(', ')} FROM ${quoteIdent(table)}` +
      (tempByName['id'] ? ` ORDER BY "id"` : '');
    const insertSql = `INSERT INTO ${quoteIdent(table)} (${prodColNames.map(quoteIdent).join(', ')}) VALUES (${prodColNames.map((_, i) => '$' + (i + 1)).join(', ')})`;

    const tempClient = await tempPool.connect();
    const prodClient = await prodPool.connect();
    let copied = 0;
    const start = Date.now();
    try {
      await tempClient.query('BEGIN');
      await tempClient.query(`DECLARE rdsr_cur NO SCROLL CURSOR FOR ${selectSql}`);
      await prodClient.query('BEGIN');
      while (true) {
        const batch = await tempClient.query(`FETCH ${BATCH} FROM rdsr_cur`);
        if (!batch.rows.length) break;
        for (const row of batch.rows) {
          const values = prodColNames.map(p => bindValue(prodByName[p], row[mapping[p]]));
          await prodClient.query(insertSql, values);
        }
        copied += batch.rows.length;
      }
      await tempClient.query('COMMIT');
      await prodClient.query('COMMIT');
    } catch (e) {
      await prodClient.query('ROLLBACK').catch(() => {});
      await tempClient.query('ROLLBACK').catch(() => {});
      throw e;
    } finally {
      tempClient.release();
      prodClient.release();
    }

    res.json({ copied, durationMs: Date.now() - start });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ── POST /api/rds-restore/pg/setval ───────────────────────────────────────────
// Body: { table, idColumn = 'id' }. Headers: x-rdsr-prod-db-*.
router.post('/api/rds-restore/pg/setval', async (req, res) => {
  try {
    const { table, idColumn } = req.body || {};
    const col = idColumn || 'id';
    if (!table || !/^[A-Za-z_][A-Za-z0-9_]*$/.test(table)) return res.status(400).json({ error: 'Invalid table name' });
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(col)) return res.status(400).json({ error: 'Invalid id column' });
    const { pool } = poolFromHeaders(req, 'x-rdsr-prod-db-');
    const rows = await poolQuery(pool,
      `SELECT setval(
         pg_get_serial_sequence($1, $2),
         GREATEST(COALESCE((SELECT MAX(${quoteIdent(col)}) FROM ${quoteIdent(table)}), 0), 1),
         TRUE
       ) AS newval`, [table, col]);
    res.json({ newval: rows[0]?.newval });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

module.exports = router;
