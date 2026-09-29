const router = require('express').Router();
const { fetchPersonioEmployees } = require('../lib/personio');
const { poolFromHeaders, query } = require('../lib/db');

// ── GET /api/personio/audit ───────────────────────────────────────────────────
//
// Read-only audit. Cross-checks the Personio employee roster (with the
// `Weitere Standorte` custom field) against every (praxisId, employeeId) pair
// stored in the cockpit tables. Surfaces three classes of mismatch:
//
//   • orphan       — stored employeeId not found in the live Personio roster
//   • inactive-ref — stored record is in Personio but `status != active`
//                    (suggests a live sibling record by name)
//   • wrong-praxis — stored record is active but neither its primary office nor
//                    its Weitere Standorte resolve to this praxis
//
// We mirror the backend matcher (LillianCare-Core/personio_service.dart):
// primary office matches by substring against `<praxis.city>` and the city
// extracted from `<praxis.name>` ("Praxis <City>"); Weitere Standorte entries
// are exact-match (case-insensitive) against the same city set.
//
// Three sources are inspected:
//   • cockpit_person_duration_exception (column employeeId)
//   • cockpit_standard_week_version     (employeeIds inside JSON blobs)
//   • cockpit_week_override             (employeeIds inside JSON blobs)
function _normCity(s) {
  return (s || '').toString().trim().toLowerCase();
}
function _extractCityFromPraxisName(name) {
  const m = /Praxis\s+(.+)$/i.exec(name || '');
  return m ? m[1].trim() : null;
}
function _praxisCitySet(p) {
  const set = new Set();
  if (p.city) set.add(_normCity(p.city));
  const fromName = _extractCityFromPraxisName(p.name);
  if (fromName) set.add(_normCity(fromName));
  return set;
}
function _expectedPraxisIdsForEmployee(emp, praxes) {
  const office = _normCity(emp.office || '');
  const ws = (emp.weitereStandorte || []).map(_normCity).filter(Boolean);
  const matched = [];
  for (const p of praxes) {
    const cities = _praxisCitySet(p);
    let isMatch = false;
    if (office) {
      for (const c of cities) {
        if (c && office.includes(c)) { isMatch = true; break; }
      }
    }
    if (!isMatch && ws.length) {
      for (const c of cities) {
        if (c && ws.includes(c)) { isMatch = true; break; }
      }
    }
    if (isMatch) matched.push(p);
  }
  return matched;
}

router.get('/api/personio/audit', async (req, res) => {
  try {
    const employees = await fetchPersonioEmployees();
    const byId = new Map();
    const byName = new Map();
    for (const e of employees) {
      const id = Number(e.id);
      if (!Number.isFinite(id)) continue;
      byId.set(id, e);
      const key = `${(e.firstName || '').toLowerCase()}|${(e.lastName || '').toLowerCase()}`;
      const arr = byName.get(key) || [];
      arr.push(e);
      byName.set(key, arr);
    }

    const praxes = await query(
      req,
      `SELECT id, "lcId", name, city FROM praxis_config ORDER BY "lcId"`,
    );
    const praxisById = new Map(praxes.map(p => [Number(p.id), p]));

    const expectedByEmpId = new Map();
    for (const emp of employees) {
      const id = Number(emp.id);
      if (!Number.isFinite(id)) continue;
      const matched = _expectedPraxisIdsForEmployee(emp, praxes);
      expectedByEmpId.set(id, new Set(matched.map(p => Number(p.id))));
    }

    const stored = new Map();
    function pushStored(praxisId, employeeId, source) {
      const pid = Number(praxisId);
      const eid = Number(employeeId);
      if (!Number.isFinite(pid) || !Number.isFinite(eid)) return;
      const key = `${pid}|${eid}`;
      const cur = stored.get(key);
      if (cur) {
        if (!cur.sources.includes(source)) cur.sources.push(source);
      } else {
        stored.set(key, { praxisId: pid, employeeId: eid, sources: [source] });
      }
    }

    const [pdePairs, swvRows, woRows] = await Promise.all([
      query(req, `SELECT DISTINCT "praxisId", "employeeId" FROM cockpit_person_duration_exception`),
      query(req, `SELECT "praxisId", "consultationHoursJson", "workHoursJson" FROM cockpit_standard_week_version`),
      query(req, `SELECT "praxisId", "consultationHoursJson", "workHoursJson" FROM cockpit_week_override`),
    ]);
    for (const r of pdePairs) pushStored(r.praxisId, r.employeeId, 'cockpit_person_duration_exception');

    function harvestJsonBlob(praxisId, raw, source) {
      if (!raw) return;
      let parsed;
      try { parsed = typeof raw === 'string' ? JSON.parse(raw) : raw; }
      catch { return; }
      if (!Array.isArray(parsed)) return;
      for (const slot of parsed) {
        if (slot && typeof slot === 'object' && Number.isFinite(Number(slot.employeeId))) {
          pushStored(praxisId, slot.employeeId, source);
        }
      }
    }
    for (const r of swvRows) {
      harvestJsonBlob(r.praxisId, r.consultationHoursJson, 'cockpit_standard_week_version.consultationHoursJson');
      harvestJsonBlob(r.praxisId, r.workHoursJson, 'cockpit_standard_week_version.workHoursJson');
    }
    for (const r of woRows) {
      harvestJsonBlob(r.praxisId, r.consultationHoursJson, 'cockpit_week_override.consultationHoursJson');
      harvestJsonBlob(r.praxisId, r.workHoursJson, 'cockpit_week_override.workHoursJson');
    }

    const issues = [];
    let okCount = 0;
    for (const { praxisId, employeeId, sources } of stored.values()) {
      const praxis = praxisById.get(praxisId);
      const praxisLcId = praxis?.lcId || null;
      const praxisName = praxis?.name || null;
      const personio = byId.get(employeeId) || null;

      if (!personio) {
        issues.push({
          kind: 'orphan',
          praxisId, praxisLcId, praxisName,
          employeeId,
          personio: null,
          suggested: null,
          sources,
        });
        continue;
      }

      const fullName = `${personio.firstName || ''} ${personio.lastName || ''}`.trim();
      const empMeta = {
        id: employeeId,
        firstName: personio.firstName,
        lastName: personio.lastName,
        fullName,
        status: personio.status || null,
        office: personio.office || null,
        weitereStandorte: personio.weitereStandorte || [],
      };

      if ((personio.status || '').toLowerCase() !== 'active') {
        const key = `${(personio.firstName || '').toLowerCase()}|${(personio.lastName || '').toLowerCase()}`;
        const siblings = (byName.get(key) || []).filter(s => Number(s.id) !== employeeId && (s.status || '').toLowerCase() === 'active');
        let suggestion = null;
        for (const s of siblings) {
          const exp = expectedByEmpId.get(Number(s.id)) || new Set();
          if (exp.has(praxisId)) { suggestion = s; break; }
        }
        if (!suggestion && siblings.length) suggestion = siblings[0];
        issues.push({
          kind: 'inactive-ref',
          praxisId, praxisLcId, praxisName,
          employeeId,
          personio: empMeta,
          suggested: suggestion ? {
            id: Number(suggestion.id),
            firstName: suggestion.firstName,
            lastName: suggestion.lastName,
            status: suggestion.status,
            office: suggestion.office,
            weitereStandorte: suggestion.weitereStandorte,
          } : null,
          sources,
        });
        continue;
      }

      const expected = expectedByEmpId.get(employeeId) || new Set();
      if (!expected.has(praxisId)) {
        issues.push({
          kind: 'wrong-praxis',
          praxisId, praxisLcId, praxisName,
          employeeId,
          personio: empMeta,
          suggested: null,
          sources,
        });
        continue;
      }

      okCount++;
    }

    issues.sort((a, b) => {
      const order = { 'orphan': 0, 'inactive-ref': 1, 'wrong-praxis': 2 };
      const k = (order[a.kind] ?? 99) - (order[b.kind] ?? 99);
      if (k !== 0) return k;
      return (a.praxisLcId || '').localeCompare(b.praxisLcId || '');
    });

    const counts = {
      storedPairs: stored.size,
      ok: okCount,
      orphan: issues.filter(i => i.kind === 'orphan').length,
      inactiveRef: issues.filter(i => i.kind === 'inactive-ref').length,
      wrongPraxis: issues.filter(i => i.kind === 'wrong-praxis').length,
      personioActive: employees.filter(e => (e.status || '').toLowerCase() === 'active').length,
      personioTotal: employees.length,
      praxes: praxes.length,
    };

    res.json({ ok: true, fetchedAt: new Date().toISOString(), counts, issues });
  } catch (e) {
    res.status(500).json({ error: e.message, configured: !!(process.env.PERSONIO_CLIENT_ID && process.env.PERSONIO_CLIENT_SECRET) });
  }
});

// ── POST /api/personio/audit/fix ──────────────────────────────────────────────
// Apply remove/remap actions to the (praxisId, employeeId) pairs surfaced by
// the personio audit. All actions run in a single transaction. Affects:
//   • cockpit_person_duration_exception           (DELETE on remove, UPDATE employeeId on remap)
//   • cockpit_standard_week_version JSON blobs    (consultationHoursJson, workHoursJson)
//   • cockpit_week_override JSON blobs            (consultationHoursJson, workHoursJson)
// Body: { actions: [{ praxisId, employeeId, mode: 'remove'|'remap', newEmployeeId? }] }
// Refuses on production env-label.
function _personioFixTransformBlob(raw, employeeId, mode, newEmployeeId) {
  if (raw == null) return { json: raw, changed: false, touched: 0 };
  let parsed;
  try { parsed = typeof raw === 'string' ? JSON.parse(raw) : raw; }
  catch { return { json: raw, changed: false, touched: 0 }; }
  if (!Array.isArray(parsed)) return { json: raw, changed: false, touched: 0 };
  let touched = 0;
  let next;
  if (mode === 'remove') {
    next = parsed.filter(slot => {
      if (slot && typeof slot === 'object' && Number(slot.employeeId) === employeeId) { touched++; return false; }
      return true;
    });
  } else {
    next = parsed.map(slot => {
      if (slot && typeof slot === 'object' && Number(slot.employeeId) === employeeId) {
        touched++;
        return { ...slot, employeeId: newEmployeeId };
      }
      return slot;
    });
  }
  if (touched === 0) return { json: raw, changed: false, touched: 0 };
  return { json: JSON.stringify(next), changed: true, touched };
}

// cockpit_standard_week_version is append-only versioned (createdAt/createdBy only,
// no modifiedAt). cockpit_week_override has both createdAt + modifiedAt. The
// `touchModifiedAt` flag picks the right SET clause per table.
async function _personioFixApplyJsonBlob(client, table, praxisId, employeeId, mode, newEmployeeId, touchModifiedAt) {
  const rows = await client.query(
    `SELECT id, "consultationHoursJson", "workHoursJson" FROM "${table}" WHERE "praxisId" = $1`,
    [praxisId],
  );
  const stats = { rowsRead: rows.rowCount, rowsModified: 0, slotsConsultation: 0, slotsWork: 0 };
  const setClause = touchModifiedAt
    ? `"consultationHoursJson" = $1, "workHoursJson" = $2, "modifiedAt" = NOW()`
    : `"consultationHoursJson" = $1, "workHoursJson" = $2`;
  for (const row of rows.rows) {
    const cons = _personioFixTransformBlob(row.consultationHoursJson, employeeId, mode, newEmployeeId);
    const work = _personioFixTransformBlob(row.workHoursJson, employeeId, mode, newEmployeeId);
    if (!cons.changed && !work.changed) continue;
    await client.query(
      `UPDATE "${table}" SET ${setClause} WHERE id = $3`,
      [cons.json, work.json, row.id],
    );
    stats.rowsModified++;
    stats.slotsConsultation += cons.touched;
    stats.slotsWork += work.touched;
  }
  return stats;
}

router.post('/api/personio/audit/fix', async (req, res) => {
  try {
    const envLabel = (req.headers['x-env-label'] || req.headers['x-env'] || '').toString().toLowerCase();
    if (envLabel === 'production' || envLabel === 'prod') {
      return res.status(400).json({ error: 'Refusing to write cockpit data on production.' });
    }
    const { actions } = req.body || {};
    if (!Array.isArray(actions) || !actions.length) {
      return res.status(400).json({ error: 'actions array required' });
    }

    const { pool } = poolFromHeaders(req);
    const client = await pool.connect();
    const results = [];
    try {
      await client.query('BEGIN');
      for (const action of actions) {
        const praxisId = Number(action.praxisId);
        const employeeId = Number(action.employeeId);
        const mode = action.mode;
        const newEmployeeId = action.newEmployeeId == null ? null : Number(action.newEmployeeId);
        if (!Number.isFinite(praxisId) || !Number.isFinite(employeeId) || (mode !== 'remove' && mode !== 'remap')) {
          results.push({ ...action, status: 'error', reason: 'invalid action shape' });
          continue;
        }
        if (mode === 'remap' && !Number.isFinite(newEmployeeId)) {
          results.push({ ...action, status: 'error', reason: 'newEmployeeId required for remap' });
          continue;
        }
        if (mode === 'remap' && employeeId === newEmployeeId) {
          results.push({ ...action, status: 'error', reason: 'newEmployeeId equals employeeId' });
          continue;
        }

        let pdeRows = 0;
        if (mode === 'remove') {
          const r = await client.query(
            `DELETE FROM cockpit_person_duration_exception WHERE "praxisId" = $1 AND "employeeId" = $2`,
            [praxisId, employeeId],
          );
          pdeRows = r.rowCount;
        } else {
          const r = await client.query(
            `UPDATE cockpit_person_duration_exception SET "employeeId" = $3, "modifiedAt" = NOW()
              WHERE "praxisId" = $1 AND "employeeId" = $2`,
            [praxisId, employeeId, newEmployeeId],
          );
          pdeRows = r.rowCount;
        }

        const swvStats = await _personioFixApplyJsonBlob(client, 'cockpit_standard_week_version', praxisId, employeeId, mode, newEmployeeId, false);
        const woStats  = await _personioFixApplyJsonBlob(client, 'cockpit_week_override',         praxisId, employeeId, mode, newEmployeeId, true);

        results.push({
          praxisId,
          employeeId,
          mode,
          newEmployeeId,
          status: 'ok',
          pde: pdeRows,
          standardWeekVersion: swvStats,
          weekOverride: woStats,
        });
      }
      await client.query('COMMIT');
    } catch (e) {
      try { await client.query('ROLLBACK'); } catch {}
      return res.status(500).json({ error: e.message, results });
    } finally {
      client.release();
    }

    res.json({ ok: true, results });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

module.exports = router;
