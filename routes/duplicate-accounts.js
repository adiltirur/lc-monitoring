const router = require('express').Router();
const fs = require('fs');
const path = require('path');
const { getPool, quoteIdent } = require('../lib/db');

// ─── Duplicate accounts (legacy + new-system app_user_info with one email) ────
//
// Core's EmailIdpEndpoint did not check the legacy serverpod_auth tables on
// registration, so some users have two app_user_info rows with one email:
//   legacy — authUserId NULL, userId = serverpod_user_info.id (serverpod_email_auth login)
//   new    — authUserId set (serverpod_auth_idp_email_account login), userId from
//            LegacyUserIdAllocator (no serverpod_user_info row)
// Login only migrates a legacy account when no modular email account exists, so
// the legacy account is unreachable. The cleanup always keeps the NEW account:
// the legacy account's rows are moved onto it, then the legacy profile and its
// legacy auth rows are deleted. Pairs where both accounts hold data are listed
// for manual review and can be merged one at a time.
//
// Don't classify by userId: new accounts' ids come from the allocator and
// overlap the legacy range on production.

// Tables that reference app_user_info.id. `data` rows count as "the account has
// data"; the others follow from them (logs, tokens). `unique` tables allow one
// row per user: 'choose' means the operator picks which account's row survives
// when both have one, true blocks the pair. `delete` rows are dropped instead of
// moved: device tokens and the OTP record (app_user_verification holds the MFA /
// verification secret, not an identity check) of the unused account.
// admin_audit_log.userId is history and is left alone.
const DA_USER_TABLES = [
  { table: 'app_user_appointment',                    col: 'userId',        label: 'Appointments',          data: true },
  { table: 'app_user_appointment_request',            col: 'userId',        label: 'Appointment requests',  data: true },
  { table: 'app_user_appointment_cancellation_reason', col: 'userId',       label: 'Cancellation reasons' },
  { table: 'app_user_document_request',               col: 'userId',        label: 'Document requests',     data: true },
  { table: 'app_user_family_member_info',             col: 'userId',        label: 'Family members',        data: true },
  { table: 'app_user_insurance_info',                 col: 'userInfoId',    label: 'Insurance',             data: true, unique: 'choose' },
  { table: 'app_user_questionnaire',                  col: 'userInfoId',    label: 'Questionnaires',        data: true },
  { table: 'app_user_verification',                   col: 'userInfoId',    label: 'OTP record',            delete: true },
  { table: 'app_user_open_consultation',              col: 'userId',        label: 'Open consultations',    data: true },
  { table: 'app_user_nps',                            col: 'userId',        label: 'NPS answers',           data: true },
  { table: 'app_user_nps_sent',                       col: 'userId',        label: 'NPS sent' },
  { table: 'notification_log',                        col: 'userId',        label: 'Notifications' },
  { table: 'praxis_device_config',                    col: 'userInfoId',    label: 'Praxis device',         data: true, unique: true },
  { table: 'app_user_pms_invitation',                 col: 'linkedUserId',  label: 'PMS invitations',       data: true },
  { table: 'app_user_pms_auto_link_log',              col: 'matchedUserId', label: 'PMS auto-link log' },
  { table: 'app_user_notification_token',             col: 'userId',        label: 'Push tokens',           delete: true },
];

// Legacy serverpod_auth rows keyed by serverpod_user_info.id (= legacy app_user_info.userId),
// deleted in this order, then serverpod_user_info itself.
const DA_LEGACY_AUTH_TABLES = [
  { table: 'serverpod_auth_key',                     col: 'userId' },
  { table: 'serverpod_email_reset',                  col: 'userId' },
  { table: 'serverpod_user_image',                   col: 'userId' },
  { table: 'serverpod_google_refresh_token',         col: 'userId' },
  { table: 'serverpod_auth_migration_migrated_user', col: 'oldUserId' },
  { table: 'serverpod_email_auth',                   col: 'userId' },
];

// Personal fields of app_user_info that move with the person. When name or date of birth
// differ, the operator picks whose profile the kept account ends up with ('profile' in `keep`);
// keeping the legacy one copies these onto the kept account. praxisVerificationCode goes along
// because the praxis may have been given the legacy code.
const DA_PROFILE_FIELDS = ['firstName', 'lastName', 'dob', 'gender', 'phoneNumber', 'street', 'city', 'postalCode', 'praxisVerificationCode'];

const DA_PROD_HOSTS = ['database.lillian.care', 'lc-core.clyg4y6ua706.eu-central-1.rds.amazonaws.com'];
const DA_BACKUP_ROOT = path.join(__dirname, '..', 'backups');

function daEnv(req) {
  const host = String(req.headers['x-db-host'] || '').toLowerCase();
  if (DA_PROD_HOSTS.includes(host)) return 'production';
  const label = String(req.headers['x-env'] || '').toLowerCase();
  if (label === 'production' || label === 'prod') return 'production';
  return label || 'dev';
}

// Typed confirmation for a run: auto pairs by count, a merge by the legacy profile id.
function daConfirmation(env, mode, n, legacyId) {
  const where = env === 'production' ? ' ON PRODUCTION' : '';
  return mode === 'merge' ? `MERGE ${legacyId}${where}` : `CLEAN UP ${n} ACCOUNTS${where}`;
}

async function daPresentTables(db) {
  const { rows } = await db.query(`SELECT table_name FROM information_schema.tables WHERE table_schema = 'public'`);
  return new Set(rows.map(r => r.table_name));
}

// Every duplicate group with both accounts, per-table counts and the plan.
// `db` is a pool or a client; `onlyEmails` limits it (run endpoint, inside its transaction).
async function daLoadPairs(db, { onlyEmails = null, lock = false } = {}) {
  const present = await daPresentTables(db);
  const emailFilter = onlyEmails ? 'AND lower(trim(email)) = ANY($1)' : '';
  const { rows: accounts } = await db.query(
    `SELECT a.id, lower(trim(a.email)) AS "emailKey", a.email, a."userId", a."authUserId", a."firstName", a."lastName",
            a."createdAt", a.dob, a."praxisId", a."pmsPatientId", a."isVerified", a."lcAccountId",
            EXISTS (SELECT 1 FROM serverpod_user_info u WHERE u.id = a."userId") AS "hasLegacyUser",
            EXISTS (SELECT 1 FROM serverpod_email_auth ea WHERE ea."userId" = a."userId") AS "hasLegacyLogin",
            EXISTS (SELECT 1 FROM serverpod_auth_idp_email_account x WHERE x."authUserId" = a."authUserId") AS "hasNewLogin",
            EXISTS (SELECT 1 FROM admin_user_info ad WHERE ad."userId" = a."userId") AS "sharedWithAdmin",
            (SELECT max(COALESCE(s."lastUsedAt", s."createdAt")) FROM serverpod_auth_core_session s WHERE s."authUserId" = a."authUserId") AS "lastNewSession"
     FROM app_user_info a
     WHERE lower(trim(a.email)) IN (
       SELECT lower(trim(email)) FROM app_user_info WHERE email IS NOT NULL AND trim(email) <> ''
       GROUP BY 1 HAVING count(*) > 1)
       ${emailFilter}
     ORDER BY lower(trim(a.email)), a.id
     ${lock ? 'FOR UPDATE OF a' : ''}`,
    onlyEmails ? [onlyEmails] : []
  );
  const ids = accounts.map(a => a.id);
  const counts = {};
  for (const t of DA_USER_TABLES) {
    if (!present.has(t.table) || !ids.length) continue;
    const { rows } = await db.query(
      `SELECT ${quoteIdent(t.col)} AS id, count(*)::int AS n FROM ${quoteIdent(t.table)} WHERE ${quoteIdent(t.col)} = ANY($1::bigint[]) GROUP BY 1`,
      [ids]
    );
    for (const r of rows) (counts[r.id] ||= {})[t.table] = r.n;
  }
  // Insurance is shown side by side when both accounts have one. The number is
  // compared server-side and never sent to the browser.
  const insurance = {};
  if (present.has('app_user_insurance_info') && ids.length) {
    const { rows } = await db.query(
      `SELECT "userInfoId" AS id, provider, "insuranceType", status, validity, "modifiedAt", md5("insuranceNumber") AS "numberHash"
       FROM app_user_insurance_info WHERE "userInfoId" = ANY($1::bigint[])`,
      [ids]
    );
    for (const r of rows) insurance[r.id] = r;
  }
  const groups = new Map();
  for (const a of accounts) {
    a.counts = counts[a.id] || {};
    a.insurance = insurance[a.id] || null;
    a.legacy = a.authUserId === null;
    a.hasData = DA_USER_TABLES.some(t => t.data && a.counts[t.table]) || !!a.pmsPatientId || !!a.isVerified;
    // Principa knows a patient by lcAccountId (bookings send it; appointments and
    // documents from Principa are matched by it).
    a.pmsKnown = !!a.pmsPatientId || !!a.counts.app_user_appointment || !!a.counts.app_user_document_request;
    if (!groups.has(a.emailKey)) groups.set(a.emailKey, []);
    groups.get(a.emailKey).push(a);
  }
  return [...groups.entries()].map(([emailKey, accs]) => daPlan(emailKey, accs));
}

// action: delete-legacy | move-delete-legacy (both automatic), manual (merge on
// request), blocked (never touched here).
function daPlan(emailKey, accs) {
  const legacies = accs.filter(a => a.legacy);
  const news = accs.filter(a => !a.legacy);
  const pair = { emailKey, email: accs[0].email, accounts: accs, blockers: [] };
  if (accs.length !== 2 || legacies.length !== 1 || news.length !== 1) {
    pair.blockers.push(`expected one legacy + one new account, found ${legacies.length} legacy + ${news.length} new`);
    return { ...pair, action: 'blocked', reason: pair.blockers[0] };
  }
  const [legacy] = legacies, [neu] = news;
  pair.legacyId = legacy.id;
  pair.newId = neu.id;
  if (!neu.hasNewLogin) pair.blockers.push('the new account has no email login (serverpod_auth_idp_email_account)');
  if (legacy.sharedWithAdmin) pair.blockers.push('an admin account uses the same legacy serverpod_user_info');
  if (legacy.pmsPatientId && neu.pmsPatientId && legacy.pmsPatientId !== neu.pmsPatientId) pair.blockers.push('the accounts are linked to different PMS patients');
  pair.choices = [];
  for (const t of DA_USER_TABLES) {
    if (!t.unique || !legacy.counts[t.table] || !neu.counts[t.table]) continue;
    if (t.unique === 'choose') pair.choices.push(t.table);
    else pair.blockers.push(`both accounts have ${t.label.toLowerCase()} (one per user)`);
  }
  if (pair.blockers.length) return { ...pair, action: 'blocked', reason: pair.blockers.join('; ') };

  // What the kept account takes over from the legacy one (see daApply).
  pair.carry = {
    // Take the legacy id when the kept account has none, or when only the legacy
    // one is known to the PMS (the new account's id was never used there).
    lcAccountId: !!legacy.lcAccountId && (!neu.lcAccountId || (legacy.pmsKnown && !neu.pmsKnown)),
    pmsPatientId: !!legacy.pmsPatientId && !neu.pmsPatientId,
    verified: !!legacy.isVerified && !neu.isVerified,
  };
  pair.warnings = [];
  if (legacy.pmsKnown && neu.pmsKnown && legacy.lcAccountId && legacy.lcAccountId !== neu.lcAccountId) {
    pair.warnings.push("Principa may know both accounts; after the merge the legacy lcAccountId no longer resolves");
  }
  const norm = v => String(v ?? '').trim().toLowerCase();
  const day = d => (d ? new Date(d).toISOString().slice(0, 10) : '');
  pair.sameIdentity = norm(legacy.firstName) === norm(neu.firstName) && norm(legacy.lastName) === norm(neu.lastName) && day(legacy.dob) === day(neu.dob);

  const carried = [pair.carry.lcAccountId && 'lcAccountId', pair.carry.pmsPatientId && 'PMS patient', pair.carry.verified && (pair.sameIdentity ? 'verified status' : 'verified status (only when its profile is kept)')].filter(Boolean);
  const carryNote = carried.length ? `; the new account takes over the legacy ${carried.join(', ')}` : '';
  const review = [];
  if (!pair.sameIdentity) review.push('name or date of birth differ — check it is the same person and choose whose profile to keep');
  if (pair.choices.length) review.push('both accounts have insurance — choose which to keep');
  if (legacy.hasData && neu.hasData) review.push('both accounts have data');
  if (review.length) return { ...pair, action: 'manual', reason: review.join('; ') + carryNote };
  if (!legacy.hasData) return { ...pair, action: 'delete-legacy', reason: (neu.hasData ? 'only the new account has data' : 'neither account has data') + carryNote };
  return { ...pair, action: 'move-delete-legacy', reason: 'only the legacy account has data — moved to the new account' + carryNote };
}

// Moves the legacy account's rows onto the new account and deletes the legacy
// profile + legacy auth. Returns per-table counts and the backup of every row
// it changed or removed (taken before the change).
// `keep` picks the surviving row for each table in pair.choices ('legacy' | 'new'), and
// keep.profile whose personal fields the kept account has when the identities differ.
async function daApply(client, pair, present, keep = {}) {
  const legacy = pair.accounts.find(a => a.id === pair.legacyId);
  const backup = { pair: { email: pair.email, legacyId: pair.legacyId, newId: pair.newId, action: pair.action, keep, carry: pair.carry }, rows: {} };
  const moved = {}, deleted = {}, updated = {};
  const snap = async (table, col, val, key = table) => {
    const { rows } = await client.query(`SELECT * FROM ${quoteIdent(table)} WHERE ${quoteIdent(col)} = $1`, [val]);
    if (rows.length) backup.rows[key] = rows;
    return rows.length;
  };

  if (!pair.sameIdentity && keep.profile !== 'legacy' && keep.profile !== 'new') throw new Error('choose whose profile (name, date of birth) to keep');
  const keepLegacyProfile = !pair.sameIdentity && keep.profile === 'legacy';

  for (const table of pair.choices) {
    const t = DA_USER_TABLES.find(x => x.table === table);
    if (keep[table] !== 'legacy' && keep[table] !== 'new') throw new Error(`choose which ${t.label.toLowerCase()} to keep`);
    // Drop the losing row; a kept legacy row is then moved by the loop below.
    const loserId = keep[table] === 'legacy' ? pair.newId : legacy.id;
    await snap(table, t.col, loserId, `${table} (${keep[table] === 'legacy' ? 'new' : 'legacy'} account, replaced)`);
    deleted[table] = (await client.query(`DELETE FROM ${quoteIdent(table)} WHERE ${quoteIdent(t.col)} = $1`, [loserId])).rowCount;
  }

  for (const t of DA_USER_TABLES) {
    if (!present.has(t.table)) continue;
    if (!(await snap(t.table, t.col, legacy.id))) continue;
    if (t.delete) {
      deleted[t.table] = (await client.query(`DELETE FROM ${quoteIdent(t.table)} WHERE ${quoteIdent(t.col)} = $1`, [legacy.id])).rowCount;
    } else {
      moved[t.table] = (await client.query(`UPDATE ${quoteIdent(t.table)} SET ${quoteIdent(t.col)} = $1 WHERE ${quoteIdent(t.col)} = $2`, [pair.newId, legacy.id])).rowCount;
    }
  }

  await snap('app_user_info', 'id', legacy.id);
  const del = await client.query(`DELETE FROM app_user_info WHERE id = $1 AND "authUserId" IS NULL`, [legacy.id]);
  if (del.rowCount !== 1) throw new Error(`legacy profile ${legacy.id} was not deleted (changed meanwhile?)`);
  deleted.app_user_info = 1;

  // After the legacy row is gone (lcAccountId is unique), the kept account takes
  // over what the PMS knows about the legacy one.
  const sets = [], vals = [];
  const set = (col, val) => { vals.push(val); sets.push(`${quoteIdent(col)} = $${vals.length}`); };
  const old = backup.rows.app_user_info[0];
  if (pair.carry.lcAccountId) set('lcAccountId', old.lcAccountId);
  if (pair.carry.pmsPatientId) set('pmsPatientId', old.pmsPatientId);
  if (keepLegacyProfile) {
    for (const col of DA_PROFILE_FIELDS) set(col, old[col]);
    if (old.praxisId) set('praxisId', old.praxisId);
  }
  // A verification checked the legacy person's ID document; it only follows when the kept
  // account ends up as that person.
  if (pair.carry.verified && (pair.sameIdentity || keepLegacyProfile)) {
    for (const col of ['isVerified', 'verifiedBy', 'verifiedOn', 'verifiedByDocumentNumber', 'verifiedByDocument', 'verifiedByPraxisId']) set(col, old[col]);
  }
  if (sets.length) {
    await snap('app_user_info', 'id', pair.newId, 'app_user_info (kept account, before)');
    vals.push(pair.newId);
    await client.query(`UPDATE app_user_info SET ${sets.join(', ')}, "modifiedAt" = NOW() WHERE id = $${vals.length}`, vals);
    updated.app_user_info = sets.map(x => x.split(' = ')[0].replace(/"/g, ''));
  }

  if (legacy.userId !== null) {
    const still = await client.query(`SELECT 1 FROM app_user_info WHERE "userId" = $1 UNION ALL SELECT 1 FROM admin_user_info WHERE "userId" = $1`, [legacy.userId]);
    if (still.rows.length) throw new Error(`serverpod_user_info ${legacy.userId} is still used by another account`);
    for (const t of DA_LEGACY_AUTH_TABLES) {
      if (!present.has(t.table) || !(await snap(t.table, t.col, legacy.userId))) continue;
      deleted[t.table] = (await client.query(`DELETE FROM ${quoteIdent(t.table)} WHERE ${quoteIdent(t.col)} = $1`, [legacy.userId])).rowCount;
    }
    if (await snap('serverpod_user_info', 'id', legacy.userId)) {
      deleted.serverpod_user_info = (await client.query(`DELETE FROM serverpod_user_info WHERE id = $1`, [legacy.userId])).rowCount;
    }
  }
  return { moved, deleted, updated, backup };
}

function daCsvCell(v) {
  const s = v === null || v === undefined ? '' : String(v);
  return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

const DA_CSV_HEADER = 'timestamp,env,email,action,deleted_profile_id,deleted_userId,kept_profile_id,moved_rows,deleted_rows,reason\n';

function daLogPath(env) {
  return path.join(DA_BACKUP_ROOT, env, 'duplicate-accounts', 'log.csv');
}

function daAppendLog(env, entries) {
  const file = daLogPath(env);
  fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
  if (!fs.existsSync(file)) fs.writeFileSync(file, DA_CSV_HEADER, { mode: 0o600 });
  fs.appendFileSync(file, entries.map(e => [
    e.timestamp, env, e.email, e.action, e.deletedProfileId, e.deletedUserId, e.keptProfileId,
    Object.values(e.moved).reduce((a, b) => a + b, 0), Object.values(e.deleted).reduce((a, b) => a + b, 0), e.reason,
  ].map(daCsvCell).join(',') + '\n').join(''));
}

function daSummary(pairs) {
  const by = a => pairs.filter(p => p.action === a).length;
  return { pairs: pairs.length, deleteLegacy: by('delete-legacy'), moveDeleteLegacy: by('move-delete-legacy'), manual: by('manual'), blocked: by('blocked') };
}

// ─── Routes ───────────────────────────────────────────────────────────────────
router.get('/api/duplicate-accounts', async (req, res) => {
  const client = await getPool(req).connect();
  try {
    await client.query('BEGIN TRANSACTION READ ONLY');
    await client.query(`SET LOCAL statement_timeout = '15s'`);
    const pairs = await daLoadPairs(client);
    await client.query('ROLLBACK');
    const env = daEnv(req);
    res.json({
      env,
      pairs,
      summary: daSummary(pairs),
      tables: DA_USER_TABLES.map(({ table, label, data }) => ({ table, label, data: !!data })),
    });
  } catch (e) {
    await client.query('ROLLBACK').catch(() => {});
    res.status(500).json({ error: e.message });
  } finally {
    client.release();
  }
});

// Body: { mode: 'auto' | 'merge', emails: [emailKey…] (merge: exactly one),
//         expect: { [emailKey]: action } (the plan the user reviewed),
//         keep: { app_user_insurance_info: 'legacy' | 'new' } (merge, when both have one), dryRun, confirmation }
// One transaction per pair; the plan is recomputed under row locks and must still
// match `expect`. Dry run applies everything and rolls back. Real runs need
// `x-allow-destructive: yes` and the typed confirmation, write a JSON backup per
// pair before COMMIT and append to backups/<env>/duplicate-accounts/log.csv.
router.post('/api/duplicate-accounts/run', async (req, res) => {
  const { mode, emails, expect = {}, keep = {}, dryRun = false, confirmation = '' } = req.body || {};
  if (mode !== 'auto' && mode !== 'merge') return res.status(400).json({ error: "mode must be 'auto' or 'merge'" });
  if (!Array.isArray(emails) || !emails.length) return res.status(400).json({ error: 'emails required' });
  if (mode === 'merge' && emails.length !== 1) return res.status(400).json({ error: 'merge takes exactly one pair' });
  const env = daEnv(req);
  if (!dryRun) {
    if (req.headers['x-allow-destructive'] !== 'yes') return res.status(400).json({ error: 'x-allow-destructive: yes required' });
    const want = daConfirmation(env, mode, emails.length, mode === 'merge' ? req.body.legacyId : null);
    if (confirmation !== want) return res.status(400).json({ error: `Type "${want}" to confirm` });
  }

  const pool = getPool(req);
  const runAt = new Date().toISOString();
  const backupDir = path.join(DA_BACKUP_ROOT, env, 'duplicate-accounts', runAt.replace(/[:.]/g, '-'));
  const results = [];
  const client = await pool.connect();
  try {
    const present = await daPresentTables(client);
    for (const emailKey of emails) {
      const r = { email: emailKey, ok: false };
      try {
        await client.query('BEGIN');
        await client.query(`SET LOCAL statement_timeout = '20s'`);
        const [pair] = await daLoadPairs(client, { onlyEmails: [emailKey], lock: true });
        if (!pair) throw new Error('no longer a duplicate');
        r.email = pair.email;
        r.action = pair.action;
        r.reason = pair.reason;
        if (expect[emailKey] && expect[emailKey] !== pair.action) throw new Error(`plan changed from ${expect[emailKey]} to ${pair.action} — reload and review`);
        const allowed = mode === 'merge' ? ['manual', 'delete-legacy', 'move-delete-legacy'] : ['delete-legacy', 'move-delete-legacy'];
        if (!allowed.includes(pair.action)) throw new Error(`${pair.action}: ${pair.reason}`);
        if (mode === 'merge' && String(pair.legacyId) !== String(req.body.legacyId)) throw new Error('legacy id does not match the pair');

        const legacy = pair.accounts.find(a => a.id === pair.legacyId);
        const { moved, deleted, updated, backup } = await daApply(client, pair, present, keep);
        Object.assign(r, { moved, deleted, updated, deletedProfileId: legacy.id, deletedUserId: legacy.userId, keptProfileId: pair.newId });
        if (dryRun) {
          await client.query('ROLLBACK');
        } else {
          fs.mkdirSync(backupDir, { recursive: true, mode: 0o700 });
          fs.writeFileSync(path.join(backupDir, `${legacy.id}.json`), JSON.stringify(backup, null, 2), { mode: 0o600 });
          await client.query('COMMIT');
          r.timestamp = new Date().toISOString();
          const kept = Object.entries(keep).filter(([t]) => pair.choices.includes(t) || (t === 'profile' && !pair.sameIdentity)).map(([t, side]) => `kept ${side} ${t}`);
          daAppendLog(env, [{ ...r, reason: [mode === 'merge' ? `merged by operator: ${pair.reason}` : pair.reason, ...kept].join('; ') }]);
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

router.get('/api/duplicate-accounts/log.csv', (req, res) => {
  const file = daLogPath(daEnv(req));
  if (!fs.existsSync(file)) return res.status(404).json({ error: 'No cleanup has run on this environment yet' });
  res.type('text/csv').attachment(`duplicate-accounts-${daEnv(req)}.csv`).send(fs.readFileSync(file));
});

module.exports = router;
