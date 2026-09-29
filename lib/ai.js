// Shared AI pieces: the Bedrock client and the DB schema prompt.

const { BedrockRuntimeClient } = require('@aws-sdk/client-bedrock-runtime');

// Prompt context describing the core DB schema (AI query builder, investigations).
const DB_SCHEMA_CONTEXT = `
You are a PostgreSQL expert for the LillianCare healthcare platform.
Generate correct PostgreSQL queries based on user requests.

RULES:
- Only generate SELECT queries unless user explicitly asks for UPDATE/INSERT/DELETE
- Always use double quotes for camelCase column names: "firstName", "createdAt", etc.
- Timestamps are in UTC in the DB. Use AT TIME ZONE 'Europe/Berlin' for display.
- Return ONLY the SQL query (no explanation, no markdown fences, no trailing semicolon)
- For relative dates like "today" or "this week" use NOW() AT TIME ZONE 'Europe/Berlin'

KEY TABLES AND COLUMNS:

app_user_info (id, email, "firstName", "lastName", "phoneNumber", gender, dob, consent, "praxisId", "mfaActivated", street, city, "postalCode", "isVerified", "lcAccountId", "pmsPatientId", "verifiedBy", "verifiedOn", "createdAt", "modifiedAt")

app_user_appointment (id, "userId" FK→app_user_info.id, "familyMemberId", category, reason, "appointmentId", "pmsAppointmentId", status [int 0-10], "praxisId", "startTime" [text ISO], resource, "createdAt", "modifiedAt")
  status enum: 0=proposed 1=pending 2=booked 3=arrived 4=fulfilled 5=cancelled 6=noshow 7=enteredInError 8=checkedIn 9=waitlist 10=rescheduled

guest_appointment (id, "bookingId", "patientId", category, reason, status [same enum], "praxisId", email, "encryptedUserInfo", "startTime" [text ISO], "isBookedFromPraxis", "hasEmail", "createdAt", "modifiedAt")

admin_audit_log (id, "userId", "userName", "userEmail", action, changes, "praxisId", "createdAt")

notification_log (id, "userId" FK→app_user_info.id, title, type [int], "activityId", body, "isNew", "createdAt")
  type enum: 0=accountVerified 1=appointmentRescheduledByPraxis 2=appointmentCancelledByPraxis 3=appointmentBookedByPraxis 4=appointmentReminder 5=newDocument 6=unknown

serverpod_session_log (id, "serverId", "time", module, endpoint, method, duration [float ms], "numQueries", slow [bool], error, "stackTrace", "authenticatedUserId", "isOpen")

serverpod_log (id, "sessionLogId" FK→serverpod_session_log.id, "logLevel" [0=debug 1=info 2=warning 3=error 4=fatal], message, error, "stackTrace", "time", "order")

serverpod_query_log (id, "sessionLogId", query, duration, "numRows", error, slow, "order")

app_user_insurance_info (id, "userInfoId" FK→app_user_info.id, "insuranceNumber", "insuranceType", status, provider, validity, "ikNumber", "createdAt")

app_user_family_member_info (id, "userId" FK→app_user_info.id, "familyMemberId", "firstName", "lastName", dob, gender, "insuranceType", "insuranceNumber", "pmsPatientId", "createdAt")

COMMON JOINS:
- appointments + user: JOIN app_user_info u ON u.id = a."userId"
- notifications + user: LEFT JOIN app_user_info u ON u.id = nl."userId"
`;

const bedrockClient = new BedrockRuntimeClient({ region: 'eu-central-1' });

module.exports = { DB_SCHEMA_CONTEXT, bedrockClient };
