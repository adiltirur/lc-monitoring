const router = require('express').Router();
const XLSX = require('xlsx');
const fs = require('fs');
const { fetchPersonioEmployees } = require('../lib/personio');
const { poolFromHeaders } = require('../lib/db');

// ─── Routes: cockpit fill (bulk-fill cockpit + opening hours from an Excel) ───
//
// The Excel ("Master Öffnungszeiten Sprechzeiten") has one sheet per praxis.
// Each sheet has three blocks identified by header text in column A:
//   1. "Öffnungszeiten"     → praxis-wide opening hours       → praxis_hours_config rows
//   2. "Sprechstundenzeiten" → per-doctor consultation slots   → cockpit consultationHoursJson
//   3. "Arbeitszeiten"      → per-role staff working hours    → cockpit workHoursJson
//
// Each row in the time blocks has 5 days × {AM start, AM end, PM start, PM end} in
// columns 3–22, plus person/resource labels in cols 1–2 and weekly hours in col 23.
//
// Block positions are NOT fixed across sheets, so the parser scans by header text.
// Times can arrive as strings ("8:00:00"), Excel serials (0.333…), or Date objects;
// we normalize to "HH:MM" strings.


const COCKPIT_WEEKDAYS = ['monday', 'tuesday', 'wednesday', 'thursday', 'friday'];
const COCKPIT_DAY_ENUM_INDEX = { monday: 0, tuesday: 1, wednesday: 2, thursday: 3, friday: 4, saturday: 5, sunday: 6 };

// Resource labels in column B (Sprechstundenzeiten block) → ConsultationKind.
// Pattern matching is loose because the Excel has minor variations
// ("Nicht buchbare Zeit" vs "Nicht buchbare Zeiten", trailing whitespace, etc.).
function consultationKindFromLabel(label) {
  if (!label) return null;
  const s = String(label).toLowerCase().trim();
  if (s.includes('homeoffice')) return 'homeoffice';
  if (s.includes('vor ort')) return 'vorOrt';
  if (s.includes('akut')) return 'akut';
  if (s.includes('heimversorgung')) return 'heimversorgung';
  if (s.includes('urlaub')) return 'urlaub';
  if (s.includes('nicht buchbar')) return 'nichtBuchbar';
  if (s.includes('buffer')) return 'buffer';
  return null;
}

// Convert an Excel cell value to "HH:MM" or null. Handles string forms
// ("8:00:00", "08:15", "9.00"), JS Date objects, and Excel time serials
// (numbers in [0, 1) representing fraction of a day).
//
// Timezone note: SheetJS with cellDates: true encodes Excel time-of-day into
// the LOCAL components of the Date — e.g. for the cell "08:15" it returns a
// Date d such that d.getHours()===8 and d.getMinutes()===15, regardless of
// the host's timezone. The absolute UTC instant is offset by the host's TZ
// at the Excel epoch (1899-12-30), so getUTCHours() would give the wrong
// hour on any non-UTC host. Always read getHours()/getMinutes() here.
// Downstream the value flows as a wall-clock "HH:MM" string end-to-end
// (DB stores text; backend + praxis app pass the string through without
// constructing any DateTime), so a German user sees the Excel value as-is.
function cellToHHMM(v) {
  if (v === null || v === undefined || v === '') return null;
  if (typeof v === 'string') {
    const s = v.trim();
    if (!s || s.startsWith('#') || s === '0:00:00') return null;
    // Try "H:MM:SS" or "HH:MM:SS" or "HH:MM"
    const m = s.match(/^(\d{1,2})[:.](\d{2})(?:[:.](\d{2}))?$/);
    if (m) return `${m[1].padStart(2, '0')}:${m[2]}`;
    return null;
  }
  if (v instanceof Date) {
    const h = String(v.getHours()).padStart(2, '0');
    const m = String(v.getMinutes()).padStart(2, '0');
    return `${h}:${m}`;
  }
  if (typeof v === 'number') {
    // Excel time serial: fraction of a day. 0.5 = 12:00. Tolerate values >1
    // (datetimes whose date part we ignore).
    const frac = v - Math.floor(v);
    const totalMin = Math.round(frac * 24 * 60);
    const h = String(Math.floor(totalMin / 60)).padStart(2, '0');
    const m = String(totalMin % 60).padStart(2, '0');
    return `${h}:${m}`;
  }
  return null;
}

// Read row N as { A, B, slots: [{weekday, start, end} ...] }. Each weekday has
// up to 2 slots (AM and PM) — emitted as separate flat entries.
function readSlotRow(sheet, rowIdx) {
  const row = { a: null, b: null, slots: [] };
  // xlsx sheet uses A1 cell refs. Build them.
  const cellAt = (col, r) => {
    const ref = XLSX.utils.encode_cell({ c: col - 1, r: r - 1 });
    const c = sheet[ref];
    return c ? c.v : undefined;
  };
  row.a = cellAt(1, rowIdx);
  row.b = cellAt(2, rowIdx);
  // 5 days × 4 cols, starting at col 3
  for (let d = 0; d < 5; d++) {
    const baseCol = 3 + d * 4;
    const amStart = cellToHHMM(cellAt(baseCol, rowIdx));
    const amEnd   = cellToHHMM(cellAt(baseCol + 1, rowIdx));
    const pmStart = cellToHHMM(cellAt(baseCol + 2, rowIdx));
    const pmEnd   = cellToHHMM(cellAt(baseCol + 3, rowIdx));
    if (amStart && amEnd) row.slots.push({ weekday: COCKPIT_WEEKDAYS[d], start: amStart, end: amEnd, half: 'AM' });
    if (pmStart && pmEnd) row.slots.push({ weekday: COCKPIT_WEEKDAYS[d], start: pmStart, end: pmEnd, half: 'PM' });
  }
  return row;
}

function parseSheet(sheet, sheetName) {
  const range = XLSX.utils.decode_range(sheet['!ref'] || 'A1:A1');
  const maxRow = range.e.r + 1;
  const blocks = { opening: [], consultation: [], working: [], persons: [] };

  let currentBlock = null;
  let currentPerson = null;
  for (let r = 1; r <= maxRow; r++) {
    const a = sheet[XLSX.utils.encode_cell({ c: 0, r: r - 1 })]?.v;
    const aStr = a ? String(a).trim() : '';

    if (aStr.includes('Öffnungszeiten')) { currentBlock = 'opening'; currentPerson = null; continue; }
    if (aStr.includes('Sprechstundenzeiten')) { currentBlock = 'consultation'; currentPerson = null; continue; }
    if (aStr.includes('Arbeitszeiten')) { currentBlock = 'working'; currentPerson = null; continue; }
    if (aStr.startsWith('Gemeldete')) { currentBlock = null; currentPerson = null; continue; }
    if (currentBlock === null) continue;

    // Skip header sub-row (col C says 'Montag Vormittag').
    const c3 = sheet[XLSX.utils.encode_cell({ c: 2, r: r - 1 })]?.v;
    if (c3 === 'Montag Vormittag') continue;

    const row = readSlotRow(sheet, r);

    if (currentBlock === 'opening') {
      if (row.slots.length) blocks.opening.push(...row.slots.map(s => ({ weekday: s.weekday, start: s.start, end: s.end })));
    } else if (currentBlock === 'consultation') {
      // Carry person name down the rows; col B is the resource label.
      if (row.a && String(row.a).trim()) currentPerson = String(row.a).trim();
      const personName = currentPerson;
      const resourceLabel = row.b ? String(row.b).trim() : null;
      const kind = consultationKindFromLabel(resourceLabel);
      if (personName && kind && row.slots.length) {
        if (!blocks.persons.includes(personName)) blocks.persons.push(personName);
        for (const s of row.slots) {
          blocks.consultation.push({
            weekday: s.weekday,
            personName,
            kind,
            start: s.start,
            end: s.end,
            onlineBookable: kind !== 'nichtBuchbar',
            sourceLabel: resourceLabel,
          });
        }
      }
    } else if (currentBlock === 'working') {
      // Carry person name down (same as consultation block). Doctor rows in
      // Block 3 have col A = name, col B = blank; MFA rows have col A = name,
      // col B = "MFA" / "MFA Homeoffice". Continuation rows have col A blank.
      if (row.a && String(row.a).trim()) currentPerson = String(row.a).trim();
      const personName = currentPerson;
      const role = row.b ? String(row.b).trim() : null;
      if (personName && row.slots.length) {
        if (!blocks.persons.includes(personName)) blocks.persons.push(personName);
        for (const s of row.slots) {
          blocks.working.push({
            weekday: s.weekday,
            personName,
            role,
            start: s.start,
            end: s.end,
            breakMin: 0,
          });
        }
      }
    }
  }
  return { sheetName, ...blocks };
}

// ── POST /api/cockpit/parse-excel ─────────────────────────────────────────────
// Body: { path: string }  — absolute path to the .xlsx on disk. Reads, parses,
// returns per-sheet structured data plus a list of all sheet names found.
router.post('/api/cockpit/parse-excel', async (req, res) => {
  try {
    const { path: filepath } = req.body || {};
    if (!filepath) return res.status(400).json({ error: 'path is required' });
    if (!fs.existsSync(filepath)) return res.status(404).json({ error: `File not found: ${filepath}` });

    const wb = XLSX.readFile(filepath, { cellDates: true, cellNF: false, cellText: false });
    // Skip templates and reference sheets — only real praxis sheets get parsed.
    const skipRe = /^(Vorlage|Erklärung|Telefonistinnen)/i;
    const sheets = wb.SheetNames.filter(n => /_Neu\s*$/i.test(n) && !skipRe.test(n));
    const parsed = sheets.map(name => parseSheet(wb.Sheets[name], name.trim()));

    // Aggregate distinct person names across all sheets so the UI can build a
    // single mapping list.
    const allPersons = Array.from(new Set(parsed.flatMap(p => p.persons))).sort();

    res.json({
      ok: true,
      file: filepath,
      sheets: parsed.map(p => ({
        sheetName: p.sheetName,
        opening: p.opening,
        consultation: p.consultation,
        working: p.working,
        persons: p.persons,
        counts: {
          openingSlots: p.opening.length,
          consultationSlots: p.consultation.length,
          workingSlots: p.working.length,
          persons: p.persons.length,
        },
      })),
      allPersons,
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ── GET /api/cockpit/personio-employees ───────────────────────────────────────
// Returns the live Personio employee list. Used by the UI to populate the
// "Excel name → Personio employee" matcher.
router.get('/api/cockpit/personio-employees', async (req, res) => {
  try {
    const employees = await fetchPersonioEmployees();
    res.json({ ok: true, count: employees.length, employees });
  } catch (e) {
    res.status(500).json({ error: e.message, configured: !!(process.env.PERSONIO_CLIENT_ID && process.env.PERSONIO_CLIENT_SECRET) });
  }
});

// ── POST /api/cockpit/import ──────────────────────────────────────────────────
// Body: {
//   parsedSheets: [...],                   // result from /parse-excel
//   sheetToLcId: { 'Trier_Neu': 'lc_05' }, // operator-confirmed mapping
//   nameToEmployeeId: { 'Claudia W': 12 }, // operator-confirmed mapping (ints)
//   validFromIsoYear?: int, validFromIsoWeek?: int, // defaults to next Monday
//   replace?: boolean,                     // default true
// }
// For each (sheet → lcId) pair: deletes prior cockpit_standard_week_version +
// praxis_hours_config rows for that praxis (if replace), then inserts:
//   - praxis_hours_config: one row per opening slot
//   - cockpit_standard_week_version: one row with three JSON blobs.
// Refuses on production env-label unless triple-gated: x-allow-destructive: yes
// AND body.confirmation === 'IMPORT COCKPIT TO PRODUCTION'.
router.post('/api/cockpit/import', async (req, res) => {
  try {
    const envLabel = (req.headers['x-env-label'] || req.headers['x-env'] || '').toString().toLowerCase();
    if (envLabel === 'production' || envLabel === 'prod') {
      if (req.headers['x-allow-destructive'] !== 'yes') {
        return res.status(400).json({ error: `Refusing cockpit import on production: x-allow-destructive header must be 'yes'.` });
      }
      if ((req.body && req.body.confirmation) !== 'IMPORT COCKPIT TO PRODUCTION') {
        return res.status(400).json({ error: `Refusing cockpit import on production: body.confirmation must be the literal string 'IMPORT COCKPIT TO PRODUCTION'.` });
      }
    }
    const {
      parsedSheets,
      sheetToLcId = {},
      nameToEmployeeId = {},
      validFromIsoYear,
      validFromIsoWeek,
      replace = true,
      createdBy = 'helper-cockpit-fill',
    } = req.body || {};
    if (!Array.isArray(parsedSheets) || !parsedSheets.length) {
      return res.status(400).json({ error: 'parsedSheets array required' });
    }

    // Default validFrom to the upcoming Monday's ISO year/week.
    function isoYearWeek(d) {
      const dt = new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate()));
      const dayNum = (dt.getUTCDay() + 6) % 7; // Mon=0
      dt.setUTCDate(dt.getUTCDate() - dayNum + 3);
      const firstThursday = dt.getTime();
      const yearStart = new Date(Date.UTC(dt.getUTCFullYear(), 0, 4));
      const weekNum = 1 + Math.round((firstThursday - yearStart.getTime()) / (7 * 86400000));
      return { year: dt.getUTCFullYear(), week: weekNum };
    }
    const fallback = isoYearWeek(new Date());
    const isoYear = Number.isFinite(validFromIsoYear) ? validFromIsoYear : fallback.year;
    const isoWeek = Number.isFinite(validFromIsoWeek) ? validFromIsoWeek : fallback.week;

    const { pool } = poolFromHeaders(req);
    const client = await pool.connect();
    const results = [];
    try {
      await client.query('BEGIN');
      for (const sheet of parsedSheets) {
        const lcId = sheetToLcId[sheet.sheetName];
        if (!lcId) { results.push({ sheet: sheet.sheetName, status: 'skipped', reason: 'no praxis mapping' }); continue; }
        const found = await client.query(`SELECT id FROM praxis_config WHERE "lcId" = $1`, [lcId]);
        if (!found.rows.length) { results.push({ sheet: sheet.sheetName, lcId, status: 'error', reason: 'lcId not in praxis_config' }); continue; }
        const praxisDbId = found.rows[0].id;

        if (replace) {
          await client.query(`DELETE FROM praxis_hours_config WHERE "praxisId" = $1`, [praxisDbId]);
          await client.query(`DELETE FROM cockpit_standard_week_version WHERE "praxisId" = $1`, [praxisDbId]);
          await client.query(`DELETE FROM cockpit_week_override WHERE "praxisId" = $1`, [praxisDbId]);
        }

        // ── praxis_hours_config: one row per opening slot. Day stored as int enum.
        let openingInserted = 0;
        for (const slot of sheet.opening || []) {
          await client.query(
            `INSERT INTO praxis_hours_config ("praxisId", day, start, "end", "createdAt", "modifiedAt")
             VALUES ($1, $2, $3, $4, NOW(), NOW())`,
            [praxisDbId, COCKPIT_DAY_ENUM_INDEX[slot.weekday], slot.start, slot.end],
          );
          openingInserted++;
        }

        // ── cockpit_standard_week_version: build the three JSON blobs.
        const openingHoursJson = JSON.stringify(
          (sheet.opening || []).map(s => ({ weekday: s.weekday, start: s.start, end: s.end })),
        );
        const consultationSlots = [];
        let unmatchedNames = [];
        for (const c of sheet.consultation || []) {
          const empId = nameToEmployeeId[c.personName];
          if (!Number.isFinite(empId)) {
            if (!unmatchedNames.includes(c.personName)) unmatchedNames.push(c.personName);
            continue;
          }
          consultationSlots.push({
            weekday: c.weekday,
            employeeId: empId,
            kind: c.kind,
            start: c.start,
            end: c.end,
            onlineBookable: !!c.onlineBookable,
          });
        }
        const consultationHoursJson = JSON.stringify(consultationSlots);

        // workHoursJson: prefer Block 3 (Arbeitszeiten) entries — explicit
        // per-person AM/PM working slots, including MFAs that don't have any
        // consultation rows. For people whose name is in Block 2 only (no
        // Block 3 row), fall back to deriving a single span from the earliest
        // consultation start to the latest end on each day.
        const workSlots = [];
        const personsWithExplicitWork = new Set();
        for (const w of sheet.working || []) {
          const empId = nameToEmployeeId[w.personName];
          if (!Number.isFinite(empId)) {
            if (!unmatchedNames.includes(w.personName)) unmatchedNames.push(w.personName);
            continue;
          }
          personsWithExplicitWork.add(empId);
          workSlots.push({
            weekday: w.weekday,
            employeeId: empId,
            start: w.start,
            end: w.end,
            breakMin: w.breakMin || 0,
          });
        }
        const derivedByPersonDay = {};
        for (const c of sheet.consultation || []) {
          const empId = nameToEmployeeId[c.personName];
          if (!Number.isFinite(empId) || personsWithExplicitWork.has(empId)) continue;
          const key = `${empId}|${c.weekday}`;
          const ws = derivedByPersonDay[key] || { weekday: c.weekday, employeeId: empId, start: c.start, end: c.end, breakMin: 0 };
          if (c.start < ws.start) ws.start = c.start;
          if (c.end > ws.end) ws.end = c.end;
          derivedByPersonDay[key] = ws;
        }
        for (const ws of Object.values(derivedByPersonDay)) workSlots.push(ws);
        const workHoursJson = JSON.stringify(workSlots);

        await client.query(
          `INSERT INTO cockpit_standard_week_version
             ("praxisId", "validFromIsoYear", "validFromIsoWeek",
              "openingHoursJson", "consultationHoursJson", "workHoursJson",
              "createdAt", "createdBy")
           VALUES ($1, $2, $3, $4, $5, $6, NOW(), $7)`,
          [praxisDbId, isoYear, isoWeek, openingHoursJson, consultationHoursJson, workHoursJson, createdBy],
        );

        results.push({
          sheet: sheet.sheetName,
          lcId,
          praxisDbId,
          openingInserted,
          consultationSlots: consultationSlots.length,
          workSlotsAggregated: workSlots.length,
          unmatchedNames,
          status: 'ok',
        });
      }
      await client.query('COMMIT');
    } catch (e) {
      await client.query('ROLLBACK');
      throw new Error(`Import rolled back: ${e.message}`);
    } finally {
      client.release();
    }
    res.json({ ok: true, isoYear, isoWeek, results });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

module.exports = router;
