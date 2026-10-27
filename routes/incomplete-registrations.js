const router = require('express').Router();
const fs = require('fs');
const path = require('path');
const { getPool, quoteIdent } = require('../lib/db');

// ─── Incomplete registrations (signups that never reached app_user_info) ──────
//
// Serverpod stores UTC in timestamp-without-time-zone columns; they are selected AT TIME ZONE 'UTC'
// so node-postgres does not read them as local time (the age cutoff depends on it).
//
// Registration in the new auth system runs in steps, and a user can stop after any of them:
//   1. startRegistration  → serverpod_auth_idp_email_account_request (+ secret challenge, code in
//                           auth_email_code_outbox). createAccountChallengeId is set once the code is verified.
//   2. finishRegistration → serverpod_auth_core_user + serverpod_auth_idp_email_account (+ profile, session),
//                           the request is deleted.
//   3. the app's createUser (post_user.dart) → app_user_info.
// Admins have admin_user_info instead of app_user_info. Old clients still register through the legacy
// serverpod_auth tables (serverpod_email_create_request → serverpod_user_info). Every legacy user was
// migrated to an auth user (serverpod_auth_migration_migrated_user), so a legacy signup that never got a
// profile shows up as an `account` with an oldUserId.
//
// Kinds:
//   request         new-system request that never became an account (step 1)
//   account         auth user with no app_user_info / admin_user_info (step 2 done, step 3 not)
//   legacy          legacy serverpod_user_info, not migrated, no profile
//   legacy-request  legacy serverpod_email_create_request (has no timestamp, so its age is unknown)
//
// Deleting serverpod_auth_core_user cascades to every serverpod_auth_* table that has an authUserId
// (email account, sessions, tokens, profile, migrated_user). Any other table with an authUserId column
// that points at the user blocks it, so a table Core adds later is never orphaned silently.

// Legacy serverpod_auth rows keyed by serverpod_user_info.id, deleted in this order, then serverpod_user_info.
const IR_LEGACY_AUTH_TABLES = [
  { table: 'serverpod_auth_key',                     col: 'userId' },
  { table: 'serverpod_email_reset',                  col: 'userId' },
  { table: 'serverpod_user_image',                   col: 'userId' },
  { table: 'serverpod_google_refresh_token',         col: 'userId' },
  { table: 'serverpod_auth_migration_migrated_user', col: 'oldUserId' },
  { table: 'serverpod_email_auth',                   col: 'userId' },
];

// Tables with an authUserId column that may point at an incomplete account (they cascade or are checked).
const IR_PROFILE_TABLES = ['app_user_info', 'admin_user_info'];

const IR_PROD_HOSTS = ['database.lillian.care', 'lc-core.clyg4y6ua706.eu-central-1.rds.amazonaws.com'];
const IR_BACKUP_ROOT = path.join(__dirname, '..', 'backups');
const IR_KINDS = ['request', 'account', 'legacy', 'legacy-request'];
const IR_MIN_AGE_HOURS = 1;

function irEnv(req) {
  const host = String(req.headers['x-db-host'] || '').toLowerCase();
  if (IR_PROD_HOSTS.includes(host)) return 'production';
  const label = String(req.headers['x-env'] || '').toLowerCase();
  if (label === 'production' || label === 'prod') return 'production';
  return label || 'dev';
}

function irConfirmation(env, n) {
  return `DELETE ${n} REGISTRATIONS${env === 'production' ? ' ON PRODUCTION' : ''}`;
}

async function irSchema(db) {
  const { rows: tables } = await db.query(`SELECT table_name FROM information_schema.tables WHERE table_schema = 'public'`);
  const { rows: cols } = await db.query(
    `SELECT table_name FROM information_schema.columns WHERE table_schema = 'public' AND column_name = 'authUserId'`
  );
  const authUserTables = cols.map(r => r.table_name);
  return {
    present: new Set(tables.map(r => r.table_name)),
    cascading: authUserTables.filter(t => t.startsWith('serverpod_auth_')),
    blocking: authUserTables.filter(t => !t.startsWith('serverpod_auth_') && !IR_PROFILE_TABLES.includes(t)),
  };
}

function irEmails(...values) {
  return [...new Set(values.filter(Boolean).map(v => String(v).trim().toLowerCase()))];
}

// Profiles (app or admin) that use one of these emails: the incomplete signup is then a second attempt
// by someone who has an account, and email-keyed rows (code outbox, legacy requests) are left alone.
async function irProfilesByEmail(db, emails) {
  if (!emails.length) return {};
  const { rows } = await db.query(
    `SELECT lower(trim(email)) AS email, 'app_user_info' AS "table", id FROM app_user_info WHERE lower(trim(email)) = ANY($1)
     UNION ALL
     SELECT lower(trim(email)), 'admin_user_info', id FROM admin_user_info WHERE lower(trim(email)) = ANY($1)`,
    [emails]
  );
  const by = {};
  for (const r of rows) (by[r.email] ||= []).push(`${r.table} #${r.id}`);
  return by;
}

async function irLoadRequests(db, { ids, lock }) {
  const { rows } = await db.query(
    `SELECT r.id, r.email, r."createdAt" AT TIME ZONE 'UTC' AS "createdAt", r."createAccountChallengeId" IS NOT NULL AS verified,
            EXISTS (SELECT 1 FROM serverpod_auth_idp_email_account ea WHERE lower(ea.email) = lower(r.email)) AS "hasAccount"
     FROM serverpod_auth_idp_email_account_request r
     ${ids ? 'WHERE r.id = ANY($1::uuid[])' : ''}
     ORDER BY r."createdAt" DESC
     ${lock ? 'FOR UPDATE OF r' : ''}`,
    ids ? [ids] : []
  );
  return rows.map(r => ({
    kind: 'request', id: r.id, email: r.email, name: null, createdAt: r.createdAt, lastActivity: r.createdAt,
    stage: r.verified ? 'Code verified, account never created' : 'Verification code sent, never entered',
    details: { verified: r.verified, hasAccount: r.hasAccount },
    emails: irEmails(r.email), blockers: [], warnings: r.hasAccount ? ['an email login with this address exists'] : [],
  }));
}

async function irLoadAccounts(db, schema, { ids, lock }) {
  const { rows } = await db.query(
    `SELECT u.id, u."createdAt" AT TIME ZONE 'UTC' AS "createdAt", u.blocked,
            (SELECT ea.id FROM serverpod_auth_idp_email_account ea WHERE ea."authUserId" = u.id LIMIT 1) AS "emailAccountId",
            (SELECT ea.email FROM serverpod_auth_idp_email_account ea WHERE ea."authUserId" = u.id LIMIT 1) AS "loginEmail",
            p.email AS "profileEmail", p."fullName",
            mu."oldUserId", su.email AS "legacyEmail", su."userName" AS "legacyName", su.created AT TIME ZONE 'UTC' AS "legacyCreated",
            (SELECT count(*)::int FROM serverpod_auth_core_session s WHERE s."authUserId" = u.id) AS sessions,
            GREATEST(
              (SELECT max(COALESCE(s."lastUsedAt", s."createdAt")) FROM serverpod_auth_core_session s WHERE s."authUserId" = u.id),
              (SELECT max(t."lastUpdatedAt") FROM serverpod_auth_core_jwt_refresh_token t WHERE t."authUserId" = u.id)
            ) AT TIME ZONE 'UTC' AS "lastSession"
     FROM serverpod_auth_core_user u
     LEFT JOIN serverpod_auth_core_profile p ON p."authUserId" = u.id
     LEFT JOIN serverpod_auth_migration_migrated_user mu ON mu."newAuthUserId" = u.id
     LEFT JOIN serverpod_user_info su ON su.id = mu."oldUserId"
     WHERE NOT EXISTS (SELECT 1 FROM app_user_info a WHERE a."authUserId" = u.id)
       AND NOT EXISTS (SELECT 1 FROM admin_user_info d WHERE d."authUserId" = u.id)
       ${ids ? 'AND u.id = ANY($1::uuid[])' : ''}
     ORDER BY u."createdAt" DESC
     ${lock ? 'FOR UPDATE OF u' : ''}`,
    ids ? [ids] : []
  );
  const authIds = rows.map(r => r.id);
  const refs = {};
  for (const table of schema.blocking) {
    if (!authIds.length) break;
    const { rows: hits } = await db.query(
      `SELECT "authUserId" AS id, count(*)::int AS n FROM ${quoteIdent(table)} WHERE "authUserId" = ANY($1::uuid[]) GROUP BY 1`,
      [authIds]
    );
    for (const h of hits) (refs[h.id] ||= []).push(`${table} (${h.n})`);
  }
  const oldIds = rows.map(r => r.oldUserId).filter(v => v !== null);
  const legacyUsers = {};
  if (oldIds.length) {
    const { rows: hits } = await db.query(
      `SELECT "userId" AS id, 'app_user_info' AS "table", id AS "profileId" FROM app_user_info WHERE "userId" = ANY($1::bigint[])
       UNION ALL
       SELECT "userId", 'admin_user_info', id FROM admin_user_info WHERE "userId" = ANY($1::bigint[])`,
      [oldIds]
    );
    for (const h of hits) (legacyUsers[h.id] ||= []).push(`${h.table} #${h.profileId}`);
  }
  return rows.map(r => {
    const legacy = r.oldUserId !== null;
    const blockers = [];
    if (refs[r.id]) blockers.push(`still referenced by ${refs[r.id].join(', ')}`);
    if (legacy && legacyUsers[r.oldUserId]) blockers.push(`legacy user id ${r.oldUserId} is used by ${legacyUsers[r.oldUserId].join(', ')}`);
    let stage;
    if (legacy) stage = 'Old app: account created, profile never completed';
    else if (r.emailAccountId) stage = 'Email verified + password set, profile never completed';
    else stage = 'Auth user without email login or profile';
    return {
      kind: 'account', id: r.id, email: r.loginEmail || r.profileEmail || r.legacyEmail, name: r.fullName || r.legacyName,
      createdAt: legacy && r.legacyCreated ? r.legacyCreated : r.createdAt,
      // A migrated user's auth user was created by the migration, so its createdAt is not activity.
      lastActivity: [legacy && r.legacyCreated ? r.legacyCreated : r.createdAt, r.lastSession].filter(Boolean).reduce((a, b) => (new Date(a) > new Date(b) ? a : b)),
      stage,
      details: { emailAccountId: r.emailAccountId, oldUserId: r.oldUserId, sessions: r.sessions, lastSession: r.lastSession, blocked: r.blocked },
      emails: irEmails(r.loginEmail, r.profileEmail, r.legacyEmail), blockers, warnings: [],
    };
  });
}

async function irLoadLegacy(db, { ids, lock }) {
  const { rows } = await db.query(
    `SELECT s.id, s.email, s."userName", s.created AT TIME ZONE 'UTC' AS created,
            EXISTS (SELECT 1 FROM serverpod_email_auth ea WHERE ea."userId" = s.id) AS "hasLogin"
     FROM serverpod_user_info s
     WHERE NOT EXISTS (SELECT 1 FROM serverpod_auth_migration_migrated_user mu WHERE mu."oldUserId" = s.id)
       AND NOT EXISTS (SELECT 1 FROM app_user_info a WHERE a."userId" = s.id)
       AND NOT EXISTS (SELECT 1 FROM admin_user_info d WHERE d."userId" = s.id)
       ${ids ? 'AND s.id = ANY($1::bigint[])' : ''}
     ORDER BY s.created DESC
     ${lock ? 'FOR UPDATE OF s' : ''}`,
    ids ? [ids] : []
  );
  return rows.map(r => ({
    kind: 'legacy', id: String(r.id), email: r.email, name: r.userName, createdAt: r.created, lastActivity: r.created,
    stage: r.hasLogin ? 'Old app: account created, never migrated, no profile' : 'Old app: user without login or profile',
    details: { hasLogin: r.hasLogin }, emails: irEmails(r.email), blockers: [], warnings: [],
  }));
}

async function irLoadLegacyRequests(db, { ids, lock }) {
  const { rows } = await db.query(
    `SELECT r.id, r.email, r."userName",
            EXISTS (SELECT 1 FROM serverpod_email_auth ea WHERE lower(ea.email) = lower(r.email)) AS "hasLogin"
     FROM serverpod_email_create_request r
     ${ids ? 'WHERE r.id = ANY($1::bigint[])' : ''}
     ORDER BY r.id DESC
     ${lock ? 'FOR UPDATE OF r' : ''}`,
    ids ? [ids] : []
  );
  return rows.map(r => ({
    kind: 'legacy-request', id: String(r.id), email: r.email, name: r.userName, createdAt: null, lastActivity: null,
    stage: r.hasLogin ? 'Old app: leftover request, the account exists' : 'Old app: verification code sent, never entered',
    details: { hasLogin: r.hasLogin }, emails: irEmails(r.email), blockers: [], warnings: [],
  }));
}

// Every incomplete registration, or only `keys` ("kind:id"). `db` is a pool or a client.
async function irLoad(db, schema, { keys = null, lock = false } = {}) {
  const idsOf = kind => (keys ? keys.filter(k => k.startsWith(kind + ':')).map(k => k.slice(kind.length + 1)) : null);
  const want = kind => !keys || idsOf(kind).length;
  const items = [
    ...(want('request') ? await irLoadRequests(db, { ids: idsOf('request'), lock }) : []),
    ...(want('account') ? await irLoadAccounts(db, schema, { ids: idsOf('account'), lock }) : []),
    ...(want('legacy') ? await irLoadLegacy(db, { ids: idsOf('legacy'), lock }) : []),
    ...(want('legacy-request') ? await irLoadLegacyRequests(db, { ids: idsOf('legacy-request'), lock }) : []),
  ];
  const profiles = await irProfilesByEmail(db, [...new Set(items.flatMap(i => i.emails))]);
  for (const item of items) {
    item.key = `${item.kind}:${item.id}`;
    item.profiles = item.emails.flatMap(e => profiles[e] || []);
    if (item.profiles.length) item.warnings.push(`this email already has a profile (${item.profiles.join(', ')}) — likely a second signup attempt`);
  }
  return items;
}

function irEligible(item, cutoff) {
  if (item.blockers.length) return false;
  if (item.lastActivity === null) return true;
  return new Date(item.lastActivity) < cutoff;
}

function irCutoff(hours) {
  const h = Math.max(IR_MIN_AGE_HOURS, Number(hours) || 24);
  return new Date(Date.now() - h * 3600 * 1000);
}

// ─── Delete ───────────────────────────────────────────────────────────────────
// Each delete takes a backup of every row it removes (before removing it) and returns per-table counts.
function irSnapper(client, backup) {
  return async (table, col, vals, key = table) => {
    const list = Array.isArray(vals) ? vals : [vals];
    if (!list.length) return [];
    const { rows } = await client.query(`SELECT * FROM ${quoteIdent(table)} WHERE ${quoteIdent(col)} = ANY($1)`, [list]);
    if (rows.length) backup.rows[key] = (backup.rows[key] || []).concat(rows);
    return rows;
  };
}

async function irDeleteWhere(client, deleted, table, col, vals) {
  const list = Array.isArray(vals) ? vals : [vals];
  if (!list.length) return 0;
  const n = (await client.query(`DELETE FROM ${quoteIdent(table)} WHERE ${quoteIdent(col)} = ANY($1)`, [list])).rowCount;
  if (n) deleted[table] = (deleted[table] || 0) + n;
  return n;
}

async function irDeleteChallenges(client, snap, deleted, ids) {
  const list = [...new Set(ids.filter(Boolean))];
  await snap('serverpod_auth_idp_secret_challenge', 'id', list);
  await irDeleteWhere(client, deleted, 'serverpod_auth_idp_secret_challenge', 'id', list);
}

// Email-keyed leftovers (code outbox, legacy create requests, failed sign-ins), only when no profile uses the email.
async function irDeleteEmailRows(client, snap, deleted, item, present) {
  if (item.profiles.length || !item.emails.length) return;
  const byEmail = async (table) => {
    if (!present.has(table)) return;
    const { rows } = await client.query(`SELECT * FROM ${quoteIdent(table)} WHERE lower(trim(email)) = ANY($1)`, [item.emails]);
    if (!rows.length) return;
    await snap(table, 'id', rows.map(r => r.id));
    await irDeleteWhere(client, deleted, table, 'id', rows.map(r => r.id));
  };
  await byEmail('auth_email_code_outbox');
  await byEmail('serverpod_email_create_request');
  await byEmail('serverpod_email_failed_sign_in');
}

async function irDeleteLegacyUser(client, snap, deleted, userId, present) {
  const still = await client.query(`SELECT 1 FROM app_user_info WHERE "userId" = $1 UNION ALL SELECT 1 FROM admin_user_info WHERE "userId" = $1`, [userId]);
  if (still.rows.length) throw new Error(`serverpod_user_info ${userId} is used by a profile`);
  for (const t of IR_LEGACY_AUTH_TABLES) {
    if (!present.has(t.table)) continue;
    await snap(t.table, t.col, userId);
    await irDeleteWhere(client, deleted, t.table, t.col, userId);
  }
  await snap('serverpod_user_info', 'id', userId);
  if (await irDeleteWhere(client, deleted, 'serverpod_user_info', 'id', userId) !== 1) throw new Error(`serverpod_user_info ${userId} was not deleted`);
}

async function irDeleteRequest(client, snap, deleted, item, present) {
  const [req] = await snap('serverpod_auth_idp_email_account_request', 'id', item.id);
  if (!req) throw new Error('request is gone');
  if (present.has('auth_email_code_outbox')) {
    await snap('auth_email_code_outbox', 'requestId', item.id);
    await irDeleteWhere(client, deleted, 'auth_email_code_outbox', 'requestId', item.id);
  }
  await irDeleteWhere(client, deleted, 'serverpod_auth_idp_email_account_request', 'id', item.id);
  await irDeleteChallenges(client, snap, deleted, [req.challengeId, req.createAccountChallengeId]);
}

async function irDeleteAccount(client, snap, deleted, item, schema) {
  for (const table of schema.cascading) await snap(table, 'authUserId', item.id);
  await snap('serverpod_auth_migration_migrated_user', 'newAuthUserId', item.id);
  const profiles = snap.backup.rows.serverpod_auth_core_profile || [];
  if (profiles.length && schema.present.has('serverpod_auth_core_profile_image')) await snap('serverpod_auth_core_profile_image', 'userProfileId', profiles.map(p => p.id));
  const emailAccountId = item.details.emailAccountId;
  let challenges = [];
  if (emailAccountId) {
    const resets = await snap('serverpod_auth_idp_email_account_password_reset_request', 'emailAccountId', emailAccountId);
    challenges = resets.flatMap(r => [r.challengeId, r.setPasswordChallengeId]);
    if (schema.present.has('serverpod_auth_bridge_email_password')) await snap('serverpod_auth_bridge_email_password', 'emailAccountId', emailAccountId);
  }
  await snap('serverpod_auth_core_user', 'id', item.id);
  // Cascades to the serverpod_auth_* rows snapshotted above; count them as deleted.
  for (const [table, rows] of Object.entries(snap.backup.rows)) {
    if (table !== 'serverpod_auth_core_user' && table !== 'serverpod_auth_idp_secret_challenge') deleted[table] = rows.length;
  }
  if (await irDeleteWhere(client, deleted, 'serverpod_auth_core_user', 'id', item.id) !== 1) throw new Error('auth user was not deleted');
  await irDeleteChallenges(client, snap, deleted, challenges);
  if (item.details.oldUserId !== null) await irDeleteLegacyUser(client, snap, deleted, item.details.oldUserId, schema.present);
}

async function irDelete(client, item, schema) {
  const backup = { item: { key: item.key, kind: item.kind, email: item.email, stage: item.stage }, rows: {} };
  const snap = irSnapper(client, backup);
  snap.backup = backup;
  const deleted = {};
  if (item.kind === 'request') await irDeleteRequest(client, snap, deleted, item, schema.present);
  else if (item.kind === 'account') await irDeleteAccount(client, snap, deleted, item, schema);
  else if (item.kind === 'legacy') await irDeleteLegacyUser(client, snap, deleted, item.id, schema.present);
  else if (item.kind === 'legacy-request') {
    await snap('serverpod_email_create_request', 'id', item.id);
    if (await irDeleteWhere(client, deleted, 'serverpod_email_create_request', 'id', item.id) !== 1) throw new Error('request is gone');
  }
  await irDeleteEmailRows(client, snap, deleted, item, schema.present);
  return { deleted, backup };
}

// ─── Log ──────────────────────────────────────────────────────────────────────
function irCsvCell(v) {
  const s = v === null || v === undefined ? '' : String(v);
  return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

const IR_CSV_HEADER = 'timestamp,env,kind,id,email,stage,last_activity,deleted_rows\n';

function irLogPath(env) {
  return path.join(IR_BACKUP_ROOT, env, 'incomplete-registrations', 'log.csv');
}

function irAppendLog(env, e) {
  const file = irLogPath(env);
  fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
  if (!fs.existsSync(file)) fs.writeFileSync(file, IR_CSV_HEADER, { mode: 0o600 });
  fs.appendFileSync(file, [
    e.timestamp, env, e.kind, e.id, e.email, e.stage, e.lastActivity ? new Date(e.lastActivity).toISOString() : '',
    Object.values(e.deleted).reduce((a, b) => a + b, 0),
  ].map(irCsvCell).join(',') + '\n');
}

// ─── Routes ───────────────────────────────────────────────────────────────────
router.get('/api/incomplete-registrations', async (req, res) => {
  const client = await getPool(req).connect();
  try {
    await client.query('BEGIN TRANSACTION READ ONLY');
    await client.query(`SET LOCAL statement_timeout = '15s'`);
    const schema = await irSchema(client);
    const items = await irLoad(client, schema);
    await client.query('ROLLBACK');
    res.json({ env: irEnv(req), items, minAgeHours: IR_MIN_AGE_HOURS, blockingTables: schema.blocking });
  } catch (e) {
    await client.query('ROLLBACK').catch(() => {});
    res.status(500).json({ error: e.message });
  } finally {
    client.release();
  }
});

// Body: { keys: ["kind:id"…], olderThanHours, dryRun, confirmation }
// One transaction per item. The item is reloaded under a row lock and must still be incomplete,
// unblocked and older than the cutoff. Dry run deletes and rolls back. Real runs need
// `x-allow-destructive: yes` and the typed confirmation, write a JSON backup per item before COMMIT
// and append to backups/<env>/incomplete-registrations/log.csv.
router.post('/api/incomplete-registrations/cleanup', async (req, res) => {
  const { keys, olderThanHours = 24, dryRun = false, confirmation = '' } = req.body || {};
  if (!Array.isArray(keys) || !keys.length) return res.status(400).json({ error: 'keys required' });
  if (keys.some(k => typeof k !== 'string' || !IR_KINDS.includes(k.split(':')[0]))) return res.status(400).json({ error: 'invalid key' });
  const env = irEnv(req);
  if (!dryRun) {
    if (req.headers['x-allow-destructive'] !== 'yes') return res.status(400).json({ error: 'x-allow-destructive: yes required' });
    const want = irConfirmation(env, keys.length);
    if (confirmation !== want) return res.status(400).json({ error: `Type "${want}" to confirm` });
  }
  const cutoff = irCutoff(olderThanHours);
  const runAt = new Date().toISOString();
  const backupDir = path.join(IR_BACKUP_ROOT, env, 'incomplete-registrations', runAt.replace(/[:.]/g, '-'));
  const results = [];
  const client = await getPool(req).connect();
  try {
    const schema = await irSchema(client);
    for (const key of keys) {
      const r = { key, ok: false };
      try {
        await client.query('BEGIN');
        await client.query(`SET LOCAL statement_timeout = '20s'`);
        const [item] = await irLoad(client, schema, { keys: [key], lock: true });
        if (!item) throw new Error('no longer incomplete (completed or already removed)');
        Object.assign(r, { kind: item.kind, id: item.id, email: item.email, stage: item.stage, lastActivity: item.lastActivity });
        if (item.blockers.length) throw new Error(`blocked: ${item.blockers.join('; ')}`);
        if (!irEligible(item, cutoff)) throw new Error('active within the selected age — skipped');
        const { deleted, backup } = await irDelete(client, item, schema);
        r.deleted = deleted;
        if (dryRun) {
          await client.query('ROLLBACK');
        } else {
          fs.mkdirSync(backupDir, { recursive: true, mode: 0o700 });
          fs.writeFileSync(path.join(backupDir, `${item.kind}-${item.id}.json`), JSON.stringify(backup, null, 2), { mode: 0o600 });
          await client.query('COMMIT');
          r.timestamp = new Date().toISOString();
          irAppendLog(env, r);
        }
        r.ok = true;
      } catch (e) {
        await client.query('ROLLBACK').catch(() => {});
        r.error = e.message;
      }
      results.push(r);
    }
  } finally {
    client.release();
  }
  res.json({
    env,
    dryRun,
    backupDir: dryRun ? null : path.relative(path.join(__dirname, '..'), backupDir),
    processed: results.length,
    done: results.filter(r => r.ok).length,
    failed: results.filter(r => !r.ok).length,
    results,
  });
});

router.get('/api/incomplete-registrations/log.csv', (req, res) => {
  const file = irLogPath(irEnv(req));
  if (!fs.existsSync(file)) return res.status(404).json({ error: 'No cleanup has run on this environment yet' });
  res.type('text/csv').attachment(`incomplete-registrations-${irEnv(req)}.csv`).send(fs.readFileSync(file));
});

module.exports = router;
