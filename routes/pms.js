const router = require('express').Router();
const { pmsJwt, pmsJwtInvalidate } = require('../lib/pms');

// ─── PMS (principa FHIR) proxy ────────────────────────────────────────────────
// Mirrors the backend's `FHIRApiCaller` + `JwtProvider` (Dart) so the helper
// can list a user's medications and documents from PMS. All calls are made
// server-side; the browser never sees the secret.

// Both lcTestIdentifier and lcProdIdentifier are 'app.lillian-care.de' in
// LillianCare-Core/.../const/fhir_string.dart:9-10 — test + prod share the
// same identifier system, so one constant is enough.
const PMS_IDENTIFIER = 'app.lillian-care.de';

const PMS_CONFIG = {
  dev:        { baseUrl: process.env.PMS_BASE_URL_DEV,     secret: process.env.PMS_SECRET_TEST },
  staging:    { baseUrl: process.env.PMS_BASE_URL_STAGING, secret: process.env.PMS_SECRET_TEST },
  production: { baseUrl: process.env.PMS_BASE_URL_PROD,    secret: process.env.PMS_SECRET_PROD },
};


function pmsConfigFromReq(req) {
  const env = req.headers['x-env'] || 'dev';
  const cfg = PMS_CONFIG[env];
  if (!cfg || !cfg.baseUrl || !cfg.secret) {
    const err = new Error(`PMS not configured for env "${env}" — set PMS_BASE_URL_* and PMS_SECRET_* in .env`);
    err.status = 503;
    throw err;
  }
  return cfg;
}

async function pmsFetch(req, path) {
  const cfg = pmsConfigFromReq(req);
  const url = cfg.baseUrl.replace(/\/$/, '') + '/' + path.replace(/^\//, '');
  const hit = async () => fetch(url, {
    headers: { 'Accept': 'application/fhir+json', 'Authorization': `Bearer ${pmsJwt(cfg.secret)}` },
  });
  let res = await hit();
  if (res.status === 401) { pmsJwtInvalidate(cfg.secret); res = await hit(); }
  if (!res.ok) {
    const text = await res.text().catch(() => '');
    const hdrs = {};
    res.headers.forEach((v, k) => { hdrs[k] = v; });
    console.error(`[pms] ${res.status} ${url}\n  headers: ${JSON.stringify(hdrs)}\n  body: ${text || '(empty)'}`);
    // FHIR servers return OperationOutcome on errors; pull the issue.diagnostics
    // if present for a more useful message.
    let msg = text;
    try {
      const j = JSON.parse(text);
      if (j.resourceType === 'OperationOutcome' && Array.isArray(j.issue) && j.issue[0]) {
        const iss = j.issue[0];
        msg = iss.diagnostics || iss.details?.text || iss.code || text;
      }
    } catch { /* not JSON */ }
    throw Object.assign(new Error(`PMS ${res.status}: ${(msg || '(empty body)').toString().slice(0, 400)}`), { status: res.status });
  }
  return res.json();
}

// Bundle parsers. We pull just the fields the UI surfaces — light-touch,
// mirrors the Dart mappers (ApiUserDocument, ApiMedicationRes) for debug use.
function parseDocumentBundle(bundle) {
  const entries = (bundle && bundle.entry) || [];
  return entries
    .map(e => e.resource)
    .filter(r => r && r.resourceType === 'DocumentReference')
    .map(doc => {
      const content = (doc.content || [])[0] || {};
      const attachment = content.attachment || {};
      const binaryRef = attachment.url || '';
      // binary ref is typically "Binary/<id>" — strip the prefix for our /api/pms/binary/:id route.
      const binaryID = binaryRef.replace(/^Binary\//, '');
      const typeCoding = (doc.type && doc.type.coding && doc.type.coding[0]) || {};
      return {
        id: doc.id || '',
        binaryID,
        title: attachment.title || doc.description || '(untitled)',
        description: doc.description || '',
        contentType: attachment.contentType || '',
        createdAt: attachment.creation || doc.date || '',
        documentType: typeCoding.display || typeCoding.code || '',
      };
    })
    .sort((a, b) => String(b.createdAt).localeCompare(String(a.createdAt)));
}

function parseMedicationBundle(bundle) {
  const entries = (bundle && bundle.entry) || [];
  const resources = entries.map(e => e.resource).filter(Boolean);
  const medById = {};
  for (const r of resources) {
    if (r.resourceType === 'Medication' && r.id) medById[`Medication/${r.id}`] = r;
  }
  const requests = resources.filter(r => r.resourceType === 'MedicationRequest');
  return requests
    .map(req => {
      const medRef = (req.medicationReference && req.medicationReference.reference) || '';
      const med = medById[medRef];
      const medCoding = (med && med.code && med.code.coding && med.code.coding[0]) || {};
      const medName =
        (med && med.code && med.code.text) ||
        medCoding.display ||
        (req.medicationCodeableConcept && req.medicationCodeableConcept.text) ||
        '(unnamed medication)';
      // PZN is typically in Medication.code.coding with system containing "pzn".
      const pzn = ((med && med.code && med.code.coding) || [])
        .find(c => c.system && /pzn/i.test(c.system));
      const dosage = (req.dosageInstruction || []).map(d => ({
        text: d.text || d.patientInstruction || '',
        asNeeded: d.asNeededBoolean === true,
        doseQuantity: (d.doseAndRate && d.doseAndRate[0] && d.doseAndRate[0].doseQuantity) || null,
      }));
      const reason =
        (req.reasonCode || [])
          .map(r => (r.text || (r.coding && r.coding[0] && r.coding[0].display) || ''))
          .filter(Boolean)
          .join(', ');
      const form = (med && med.form && med.form.coding && med.form.coding[0] && med.form.coding[0].display) || '';
      return {
        id: req.id || '',
        medicationName: medName,
        status: req.status || '',
        intent: req.intent || '',
        authoredOn: req.authoredOn || '',
        pzn: pzn ? pzn.code : null,
        form,
        reason,
        dosage,
        manufacturer: (med && med.manufacturer && med.manufacturer.display) || null,
        note: (req.note || []).map(n => n.text).filter(Boolean).join('\n'),
        validityEnd: req.dispenseRequest && req.dispenseRequest.validityPeriod && req.dispenseRequest.validityPeriod.end || null,
      };
    })
    .sort((a, b) => String(b.authoredOn).localeCompare(String(a.authoredOn)));
}

// URLs below match the exact wire format the Dart backend sends via
// Uri.parse(): `|` encoded to %7C; `:` / `/` inside _profile stay RAW.
// HAPI FHIR's _profile matching rejects the fully-encoded form.
router.get('/api/pms/users/:lcAccountId/documents', async (req, res) => {
  try {
    const id = encodeURIComponent(req.params.lcAccountId);
    const path =
      `DocumentReference?subject.identifier=${PMS_IDENTIFIER}%7C${id}` +
      `&_profile=https://app.lillian-care.de/DocumentReference`;
    const bundle = await pmsFetch(req, path);
    res.json({ documents: parseDocumentBundle(bundle) });
  } catch (e) {
    res.status(e.status || 500).json({ error: e.message });
  }
});

router.get('/api/pms/users/:lcAccountId/medications', async (req, res) => {
  try {
    const id = encodeURIComponent(req.params.lcAccountId);
    const path =
      `MedicationRequest?subject:Patient.identifier=${PMS_IDENTIFIER}%7C${id}` +
      `&_include=Medication&_profile=http://medicationrequest.lilliancare.de`;
    const bundle = await pmsFetch(req, path);
    res.json({ medications: parseMedicationBundle(bundle) });
  } catch (e) {
    res.status(e.status || 500).json({ error: e.message });
  }
});

// Debug: hits PMS `metadata` (CapabilityStatement) — no query params, just
// tests baseUrl + JWT auth. If this returns a Bundle/CapabilityStatement,
// the 400 on searches is a URL-encoding issue, not auth.
router.get('/api/pms/debug/metadata', async (req, res) => {
  try {
    const bundle = await pmsFetch(req, 'metadata');
    res.json({ ok: true, resourceType: bundle.resourceType, fhirVersion: bundle.fhirVersion, software: bundle.software });
  } catch (e) {
    res.status(e.status || 500).json({ error: e.message });
  }
});

router.get('/api/pms/binary/:id', async (req, res) => {
  try {
    const bin = await pmsFetch(req, `Binary/${encodeURIComponent(req.params.id)}`);
    res.json({ contentType: bin.contentType || '', base64: bin.data || '' });
  } catch (e) {
    res.status(e.status || 500).json({ error: e.message });
  }
});

module.exports = router;
