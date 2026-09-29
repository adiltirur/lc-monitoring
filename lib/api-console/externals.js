// API console: request templates for everything outside Serverpod RPC — the
// external services the backend calls (Principa, Personio, Brevo, FCM, Google
// Maps, feiertage-api) and the webhooks other systems call INTO the backend.
//
// Each template mirrors a call site in LillianCare-Core (see `source`). URLs use
// {{variables}}: base URLs come from the env (see auth.js baseVars), the rest
// ({{lcAccountId}}, {{scheduleId}}, …) are yours to fill in the Variables panel.
// `effect`: 'read' | 'write' (changes data) | 'sends' (email/SMS/push to a person).
// `usedByBackend: false` marks extras that are handy for debugging only.

const FHIR = { Accept: 'application/fhir+json' };
const FHIR_BODY = { Accept: 'application/fhir+json', 'Content-Type': 'application/fhir+json' };
const JSON_BODY = { Accept: 'application/json', 'Content-Type': 'application/json' };
const LC = 'app.lillian-care.de';

const principaFhir = [
  { name: 'Capability statement', method: 'GET', path: 'metadata', effect: 'read', usedByBackend: false,
    doc: 'FHIR server metadata. PMSEndpoint.metaData is defined in the backend but not called; handy to check reachability + auth.' },
  { name: 'List active schedules', method: 'GET', path: 'Schedule?active=true', effect: 'read',
    source: 'endpoints/booking/helper/slot_service.dart:303',
    doc: 'All schedules. The backend filters them client-side by extension valueReference → Organization/<principaOrganizationId> (praxis_technical_config) and the category valueString.' },
  { name: 'Get schedule', method: 'GET', path: 'Schedule/{{scheduleId}}', effect: 'read', source: 'booking_extension.dart:407' },
  { name: 'Free slots (count days)', method: 'GET',
    path: 'Slot?status=free&start={{$date}}T00:00:00Z&end={{$datePlus7}}T23:59:59Z&schedule=Schedule/{{scheduleId}}&_countDays=7&_versType={{insurance}}',
    effect: 'read', source: 'slot_service.dart:133', doc: '_versType is the insurance code (e.g. GKV / PKV).' },
  { name: 'Free slots in range', method: 'GET',
    path: 'Slot?status=free&start={{$date}}T00:00:00Z&end={{$datePlus7}}T23:59:59Z&schedule=Schedule/{{scheduleId}}&_versType={{insurance}}',
    effect: 'read', source: 'slot_service.dart:99, slot_claim_service.dart:212' },
  { name: 'Get slot', method: 'GET', path: 'Slot/{{slotId}}', effect: 'read', source: 'slot_claim_service.dart:187' },
  { name: 'Book appointment — new patient', method: 'POST', path: 'Appointment/$book', effect: 'write',
    source: 'endpoints/booking/api/helper/book_new_patient.dart:60',
    doc: 'Books a REAL appointment in Principa. Contained Patient (reference Patient/T1) + optional Coverage.',
    body: {
      resourceType: 'Parameters',
      parameter: [{
        name: 'appt-resource',
        resource: {
          resourceType: 'Appointment',
          status: 'proposed',
          start: '{{slotStart}}', end: '{{slotEnd}}',
          slot: [{ reference: 'Slot/{{slotId}}' }],
          participant: [{ status: 'accepted', actor: { reference: 'Patient/T1' } }],
          extension: [{ url: 'http://principa.com/selectedInsurance', valueString: '{{insurance}}' }],
          contained: [{
            resourceType: 'Patient', id: 'T1',
            identifier: [{ system: LC, value: '{{lcAccountId}}' }],
            name: [{ family: 'Test', given: ['Test'] }],
            gender: 'unknown', birthDate: '1990-01-01',
            telecom: [{ system: 'email', value: 'test@example.com' }],
          }],
        },
      }],
    } },
  { name: 'Book appointment — existing patient', method: 'POST', path: 'Appointment/$book', effect: 'write',
    source: 'endpoints/booking/api/helper/book_existing_patient.dart:28',
    doc: 'Books a REAL appointment for a patient Principa already knows by lcAccountId.',
    body: {
      resourceType: 'Parameters',
      parameter: [{
        name: 'appt-resource',
        resource: {
          resourceType: 'Appointment',
          status: 'proposed',
          start: '{{slotStart}}', end: '{{slotEnd}}',
          slot: [{ reference: 'Slot/{{slotId}}' }],
          participant: [{ status: 'accepted', actor: { identifier: { system: LC, value: '{{lcAccountId}}' } } }],
          extension: [{ url: 'http://principa.com/selectedInsurance', valueString: '{{insurance}}' }],
        },
      }],
    } },
  { name: 'Appointments of a patient', method: 'GET', path: `Appointment?actor.identifier=${LC}|{{lcAccountId}}`, effect: 'read',
    source: 'endpoints/booking/api/get_booking.dart:191' },
  { name: 'Get appointment', method: 'GET', path: 'Appointment/{{pmsAppointmentId}}', effect: 'read', source: 'put_booking.dart:219' },
  { name: 'Reschedule appointment', method: 'PUT', path: 'Appointment/{{pmsAppointmentId}}', effect: 'write',
    source: 'put_booking.dart:206',
    doc: 'The backend GETs the appointment, changes start/end and PUTs the whole resource back. Paste the GET result here and edit start/end.',
    body: { resourceType: 'Appointment', id: '{{pmsAppointmentId}}', start: '{{slotStart}}', end: '{{slotEnd}}' } },
  { name: 'Cancel appointment', method: 'PUT', path: 'Appointment/{{pmsAppointmentId}}', effect: 'write',
    source: 'put_booking.dart:409',
    body: { resourceType: 'Appointment', id: '{{pmsAppointmentId}}', status: 'cancelled', comment: 'Cancelled via LC Helper', participant: [] } },
  { name: 'Submit questionnaire response', method: 'POST', path: 'QuestionnaireResponse', effect: 'write',
    source: 'endpoints/booking/api/post_questionnaire.dart:94',
    body: {
      resourceType: 'QuestionnaireResponse', status: 'completed',
      subject: { identifier: { system: LC, value: '{{lcAccountId}}' } },
      encounter: { reference: 'Encounter/{{pmsAppointmentId}}' },
      authored: '{{$isoTimestamp}}',
      item: [{ linkId: 'QUESTIONNAIRE', item: [{ linkId: 'QUESTION1', answer: [{ valueBoolean: true }] }] }],
    } },
  { name: 'Add signature to questionnaire', method: 'POST', path: 'DocumentReference/$addSignature', effect: 'write',
    source: 'endpoints/questionnaire/questionnaire_endpoint.dart:214',
    body: {
      resourceType: 'Parameters',
      parameter: [
        { name: 'signature', valueAttachment: { contentType: 'image/png', data: '<base64 png>' } },
        { name: 'document', valueReference: { reference: 'QuestionnaireResponse/{{questionnaireResponseId}}' } },
      ],
    } },
  { name: 'Documents of a patient', method: 'GET',
    path: `DocumentReference?subject.identifier=${LC}|{{lcAccountId}}&_profile=https://app.lillian-care.de/DocumentReference`,
    effect: 'read', source: 'endpoints/document/document_endpoint.dart:193' },
  { name: 'Upload document', method: 'POST', path: 'DocumentReference', effect: 'write',
    source: 'document_endpoint.dart:316',
    body: {
      resourceType: 'DocumentReference', status: 'current',
      subject: { identifier: { system: LC, value: '{{lcAccountId}}' } },
      date: '{{$isoTimestamp}}', description: 'Test upload',
      extension: [{ url: 'http://www.principa.com/titleKat', valueString: '' }, { url: 'http://www.principa.com/titleKatLong', valueString: '' }],
      author: [{ display: 'Patient', identifier: { system: LC, value: '{{lcAccountId}}' } }],
      content: [{ attachment: { contentType: 'application/pdf', data: '<base64>', title: 'test.pdf' } }],
    } },
  { name: 'Download binary', method: 'GET', path: 'Binary/{{binaryId}}', effect: 'read', headers: { Accept: '*/*' },
    source: 'document_endpoint.dart:133', doc: 'Raw bytes (PDF/image). Use "Save response" to download.' },
  { name: 'Medications of a patient', method: 'GET',
    path: `MedicationRequest?subject:Patient.identifier=${LC}|{{lcAccountId}}&_include=Medication&_profile=http://medicationrequest.lilliancare.de`,
    effect: 'read', source: 'endpoints/medication/api/get_medication.dart:221' },
  { name: 'Request medication', method: 'POST', path: 'MedicationRequest/$new', effect: 'write',
    source: 'endpoints/medication/api/request_medication.dart:214',
    doc: 'Returns an OperationOutcome; error/fatal issues mean rejection.',
    body: { resourceType: 'Parameters', parameter: [{ name: 'request', resource: { resourceType: 'MedicationRequest', status: 'draft', intent: 'order', subject: { identifier: { system: LC, value: '{{lcAccountId}}' } } } }] } },
  { name: 'Get patient', method: 'GET', path: 'Patient/{{principaPatientId}}', effect: 'read', source: 'fhir_appointment_handler.dart:487' },
  { name: 'Link patient to LC account', method: 'PATCH', path: 'Patient/{{principaPatientId}}', effect: 'write',
    headers: { Accept: 'application/fhir+json', 'Content-Type': 'application/json-patch+json' },
    source: 'services/patient_management/fhir_api_caller.dart:253 (patchPatient)',
    body: [{ op: 'add', path: '/identifier/-', value: { system: LC, value: '{{lcAccountId}}' } }] },
].map(t => ({ group: 'Principa FHIR', auth: 'principa', url: `{{principaFhir}}${t.path}`,
  headers: t.headers || (t.body ? FHIR_BODY : FHIR), ...t }));

const principaRest = [
  { name: 'Ping (health check)', path: 'ping', source: 'health/principa_health.dart:36' },
  { name: 'App properties (Jitsi domain)', path: 'appProperties?context=ALL&language=de', source: 'jitsi_domain_provider.dart:22' },
  { name: 'Tablet questionnaire URL', path: 'getLCTabletURL?id={{deviceShortName}}', source: 'questionnaire_endpoint.dart:358',
    doc: 'Polled every second by the praxis tablet flow; {} means nothing queued.' },
].map(t => ({ group: 'Principa REST', auth: 'principa', method: 'GET', effect: 'read', url: `{{principaRest}}${t.path}`,
  headers: { Accept: 'application/json' }, ...t }));

const personio = [
  { name: 'Employees', method: 'GET', url: '{{personio}}/company/employees?limit=200&offset=0', effect: 'read',
    source: 'services/personio/personio_api_caller.dart:90' },
  { name: 'Time-offs', method: 'GET',
    url: '{{personio}}/company/time-offs?start_date={{$date}}&end_date={{$datePlus30}}&limit=200&offset=0&employees[]={{employeeId}}',
    effect: 'read', source: 'personio_api_caller.dart:126', doc: 'The backend sends employee ids in batches of 25 (employees[]=…).' },
].map(t => ({ group: 'Personio', auth: 'personio', headers: { Accept: 'application/json' }, ...t }));

const brevo = [
  { name: 'Account (check API key)', method: 'GET', url: '{{brevo}}/account', effect: 'read', usedByBackend: false },
  { name: 'Send template email', method: 'POST', url: '{{brevo}}/smtp/email', effect: 'sends',
    source: 'future_calls/mailer/message_outbox_dispatch_future_call.dart:59',
    doc: 'Sends a REAL email. Template ids live in the email_template_id table.',
    body: { to: [{ email: '{{testEmail}}', name: 'Test' }], templateId: 1, params: {} } },
  { name: 'Send SMS', method: 'POST', url: '{{brevo}}/transactionalSMS/sms', effect: 'sends',
    source: 'message_outbox_dispatch_future_call.dart', doc: 'Sends a REAL SMS.',
    body: { recipient: '{{testPhone}}', unicodeEnabled: true, sender: 'LillianCare', type: 'transactional', content: 'Test from LC Helper' } },
].map(t => ({ group: 'Brevo', auth: 'brevo', headers: t.body ? JSON_BODY : { Accept: 'application/json' }, ...t }));

const fcm = [
  { name: 'Send push (validate only)', method: 'POST', url: '{{fcm}}/messages:send', effect: 'read',
    source: 'services/push_notification/firebase_push_notification.dart:60',
    doc: 'validate_only: true makes FCM check the message and device token without delivering it. Remove it to send for real.',
    body: { validate_only: true, message: { token: '{{fcmToken}}', notification: { title: 'Test', body: 'From LC Helper' }, data: {} } } },
  { name: 'Send push', method: 'POST', url: '{{fcm}}/messages:send', effect: 'sends',
    source: 'firebase_push_notification.dart:60', doc: 'Delivers a REAL push notification. Device tokens: app_user_info → /api/users/:id/tokens.',
    body: { message: { token: '{{fcmToken}}', notification: { title: 'Test', body: 'From LC Helper' }, data: {} } } },
].map(t => ({ group: 'Firebase (FCM)', auth: 'fcm', headers: JSON_BODY, ...t }));

const maps = [
  { name: 'Place autocomplete', url: '{{maps}}/place/autocomplete/json?input=Hauptstra%C3%9Fe&language=de&components=country:de&type=address' },
  { name: 'Place details', url: '{{maps}}/place/details/json?place_id={{placeId}}' },
  { name: 'Distance matrix', url: '{{maps}}/distancematrix/json?units=metric&origins=52.52,13.405&destinations=place_id:{{placeId}}' },
].map(t => ({ group: 'Google Maps', auth: 'maps', method: 'GET', effect: 'read', headers: { Accept: 'application/json' },
  source: 'endpoints/maps/maps_endpoint.dart', ...t }));

const holidays = [
  { group: 'Holidays', name: 'Public holidays (feiertage-api.de)', method: 'GET', url: '{{holidays}}/?jahr={{$year}}&nur_land=BY',
    auth: 'none', effect: 'read', headers: { Accept: 'application/json' }, source: 'endpoints/holidays/holiday_endpoint.dart:51' },
];

// Calls INTO the backend from other systems.
const inbound = [
  { name: 'FHIR messaging (Principa → us)', method: 'POST', url: '{{coreApi}}/fhir/messaging', auth: 'coreApiKey', effect: 'write',
    source: 'endpoints/fhir/fhir_endpoint.dart:14', headers: JSON_BODY,
    doc: 'Principa posts appointment/patient bundles here. Authenticated by the api-key header (core_api_keys table, permission * or fhir).',
    body: { resourceType: 'Bundle', type: 'message', id: '{{$guid}}', timestamp: '{{$isoTimestamp}}', entry: [] } },
  { name: 'FHIR patient invite (Principa → us)', method: 'POST', url: '{{coreApi}}/fhir/patientInvite', auth: 'coreApiKey', effect: 'sends',
    source: 'endpoints/fhir/fhir_endpoint.dart:66', headers: JSON_BODY,
    doc: 'Parameters are listed on fhir.patientInvite in the Serverpod catalog.', body: {} },
  { name: 'Lilli: validate credentials', method: 'POST', url: '{{coreWeb}}/aivo/validate-credentials', auth: 'lilli', effect: 'read',
    source: 'endpoints/sso/lilli_credentials_route.dart', headers: JSON_BODY, body: { email: '{{testEmail}}', password: '' } },
  { name: 'Lilli: update pre-anamnesis', method: 'POST', url: '{{coreWeb}}/aivo/update-preanmnesis', auth: 'lilli', effect: 'write',
    source: 'endpoints/sso/lilli_preanmnesis_route.dart', headers: JSON_BODY, body: { survey: {}, userName: '', userEmail: '{{testEmail}}' } },
  { name: 'Lilli: slots', method: 'GET', url: '{{coreWeb}}/incoming/lilli/slots?lcPraxisId={{lcPraxisId}}&category={{category}}&callId={{callId}}',
    auth: 'lilli', effect: 'read', source: 'endpoints/sso/lilli_slots_route.dart', headers: { Accept: 'application/json', 'X-Lilli-Call-Id': '{{callId}}' } },
  { name: 'Lilli: book confirm', method: 'POST', url: '{{coreWeb}}/incoming/lilli/book-confirm', auth: 'lilli', effect: 'write',
    source: 'endpoints/sso/lilli_book_confirm_route.dart', headers: { ...JSON_BODY, 'X-Lilli-Call-Id': '{{callId}}' },
    body: { callId: '{{callId}}', slotId: '{{slotId}}', slotStart: '{{slotStart}}', slotEnd: '{{slotEnd}}' } },
  { name: 'Lilli: booking (end of call)', method: 'POST', url: '{{coreWeb}}/incoming/lilli/booking', auth: 'lilli', effect: 'write',
    source: 'endpoints/sso/lilli_booking_route.dart', headers: JSON_BODY,
    doc: 'bookingMetadata and answers are JSON strings. Falls back to praxis lc_25 when no call session/lcPraxisId is found.',
    body: { callId: '{{callId}}', callerNumber: '', completionStatus: 'completed', lcPraxisId: '{{lcPraxisId}}', bookingMetadata: '{}', answers: '{}' } },
  { name: 'Lilli: calculate', method: 'POST', url: '{{coreWeb}}/incoming/lilli/calculate', auth: 'lilli', effect: 'read',
    source: 'endpoints/sso/lilli_calculate_route.dart', headers: JSON_BODY,
    body: { lcPraxisId: '{{lcPraxisId}}', callId: '{{callId}}', callerNumber: '', answers: {}, firstName: '', lastName: '', dob: '', gender: '', email: '' } },
  { name: 'Fonio webhook', method: 'POST', url: '{{coreWeb}}/incoming/fonio', auth: 'none', effect: 'write',
    source: 'endpoints/admin/dev_helper/fonio_route.dart', headers: JSON_BODY,
    doc: 'No auth on the backend. Books appointments (hard-coded praxis lc_25).',
    body: { fromNumber: '', toNumber: '', direction: 'inbound', duration: 0, disconnectReason: '', startTimestamp: '{{$isoTimestamp}}', endTimestamp: '{{$isoTimestamp}}', audioLink: '', extractionData: { first_name: '', last_name: '', email: '', telefonnummer: '', geburtsdatum: '' } } },
  { name: 'Unify webhook', method: 'POST', url: '{{coreWeb}}/incoming/unify', auth: 'none', effect: 'read',
    source: 'endpoints/unify/unify_route.dart', headers: JSON_BODY, doc: 'No auth; only logs headers and body.', body: {} },
  { name: 'Public: join waiting list', method: 'POST', url: '{{coreWeb}}/api/public/join-waiting-list', auth: 'none', effect: 'write',
    source: 'endpoints/waiting_list/join_waiting_list_route.dart', headers: JSON_BODY,
    doc: 'Fields are checked by WaitingListValidator in the backend.', body: { lcId: '{{lcPraxisId}}' } },
  { name: 'Public: praxis lookup', method: 'GET', url: '{{coreWeb}}/api/public/praxis/{{lcPraxisId}}?lang=de', auth: 'none', effect: 'read',
    source: 'endpoints/waiting_list/praxis_lookup_route.dart', headers: { Accept: 'application/json' } },
  { name: 'Diagnostics: outbound IP', method: 'GET', url: '{{coreWeb}}/diagnostics/ip', auth: 'none', effect: 'read',
    source: 'web/routes/diagnostics_route.dart', doc: 'Returns 403 on production.' },
].map(t => ({ group: 'Inbound webhooks', ...t }));

const EXTERNALS = [...principaFhir, ...principaRest, ...personio, ...brevo, ...fcm, ...maps, ...holidays, ...inbound]
  .map((t, i) => {
    const { path: _p, ...rest } = t;
    return { id: `ext-${i}`, usedByBackend: true, headers: {}, ...rest };
  });

module.exports = { EXTERNALS };
