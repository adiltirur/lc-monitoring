// Praxis-scoped table lists shared by Praxis Refresh and Praxis Cleanup.
//
// Hardcoded enumeration of praxis-config tables. These are the rows that get
// backed up, wiped, and imported as a unit. Each row has a numeric `"praxisId"`
// FK to `praxis_config.id`, except `praxis_config` itself, which is the root
// (with `"lcId"` as the natural key).
//
// FK INSERT order — child after parent. Use `[...].reverse()` for delete order.
// When backend adds a new praxis_*_config table, add it here AND the schema
// drift check (GET /api/praxis/schema-drift-check) will already surface it.
const PRAXIS_CONFIG_TABLES = [
  'praxis_config',
  'praxis_acute_consultation_config',
  'praxis_hours_config',
  'praxis_marketing_config',
  'praxis_open_consultation_config',
  'praxis_open_consultation_disabled_categories_config',
  'praxis_open_consultation_hours_config',
  'praxis_preanmnesis_config',
  'praxis_preanmnesis_disabled_config',
  'praxis_preanmnesis_popup_config',
  'praxis_preanmnesis_treatment_category_config',
  'praxis_preanmnesis_vitas_ai_treatment_category_config',
  'praxis_short_notice_config',
  'praxis_special_holiday_config',
  'praxis_special_hours_config',
  'praxis_support_email_config',
  'praxis_technical_config',
  'praxis_device_config',
  'praxis_holiday_config',
  'praxis_new_patient_config',
  'praxis_new_patient_config_question',
  'praxis_holiday_notice_config',
  'cockpit_standard_week_version',
  'cockpit_appointment_type_matrix',
  'cockpit_week_override',
];

// Tables in the config family that we WIPE and BACKUP normally but SKIP on
// import because they have a NOT NULL foreign key to a non-praxis table that
// won't survive the cross-env hop. praxis_device_config has a second FK
// (`userInfoId` → app_user_info.id) — prod's user ids don't exist on staging,
// so any insert violates the FK. Staging operators can re-register devices on
// staging if they need test devices.
const PRAXIS_CONFIG_TABLES_SKIP_IMPORT = new Set([
  'praxis_device_config',
]);

// Tables whose `praxisId` column holds an lcId STRING (not a numeric FK). We
// list them so the schema-drift check can classify them as "intentionally not
// wiped" rather than flagging them as drift. Step 5 (set-default) explicitly
// fixes user-facing references on `app_user_info` + `admin_user_info`; the
// rest stay orphaned.
const PRAXIS_HISTORICAL_LCID_TABLES = [
  'app_user_appointment',
  'app_user_open_consultation',
  'app_user_document_request',
  'app_user_reserved_appointment',
  'app_user_nps_sent',
  'guest_appointment',
  'questionnaire_reservation',
  'fhir_nps',
  'app_user_info',
  'app_user_pms_invitation',
  'admin_audit_log',
  // numeric praxis_id but historical (NOT config) — explicitly excluded from wipe
  'app_user_appointment_reminder',
  'cockpit_person_duration_exception',
  'praxis_hours_sync_target',
];

module.exports = { PRAXIS_CONFIG_TABLES, PRAXIS_CONFIG_TABLES_SKIP_IMPORT, PRAXIS_HISTORICAL_LCID_TABLES };
