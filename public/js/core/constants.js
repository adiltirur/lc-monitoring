// ═════════════════════════════════════════════════════════════════════════
// CONSTANTS
// ═════════════════════════════════════════════════════════════════════════
const DE_TZ = 'Europe/Berlin';
const PRESETS = {
  dev:        { host: 'localhost',                    port: '8090', db: 'lillian_care_core', user: 'postgres' },
  test:       { host: 'database-test.lillian.care',    port: '5432', db: 'serverpod',         user: 'postgres' },
  staging:    { host: 'database-staging.lillian.care', port: '5432', db: 'serverpod',         user: 'postgres' },
  production: { host: 'database.lillian.care',         port: '5432', db: 'serverpod',         user: 'postgres' },
};

const APT_STATUS = ['proposed','pending','booked','arrived','fulfilled','cancelled','noshow','enteredInError','checkedIn','waitlist','rescheduled'];
const APT_STATUS_PILL = {
  0: ['bg-slate-100','text-slate-700','bg-slate-500'],     // proposed
  1: ['bg-amber-100','text-amber-700','bg-amber-500'],     // pending
  2: ['bg-emerald-100','text-emerald-700','bg-emerald-500'],// booked
  3: ['bg-blue-100','text-blue-700','bg-blue-500'],         // arrived
  4: ['bg-indigo-100','text-indigo-700','bg-indigo-500'],   // fulfilled
  5: ['bg-red-100','text-red-700','bg-red-500'],            // cancelled
  6: ['bg-red-100','text-red-700','bg-red-500'],            // noshow
  7: ['bg-red-100','text-red-700','bg-red-500'],            // enteredInError
  8: ['bg-emerald-100','text-emerald-700','bg-emerald-500'],// checkedIn
  9: ['bg-orange-100','text-orange-700','bg-orange-500'],   // waitlist
  10:['bg-orange-100','text-orange-700','bg-orange-500'],   // rescheduled
};

const NOTIF_TYPES = ['accountVerified','aptRescheduledByPraxis','aptCancelledByPraxis','aptBookedByPraxis','aptReminder','newDocument','unknown'];
const NOTIF_PILL = {
  0: ['bg-indigo-100','text-indigo-700'],
  1: ['bg-orange-100','text-orange-700'],
  2: ['bg-red-100','text-red-700'],
  3: ['bg-blue-100','text-blue-700'],
  4: ['bg-blue-100','text-blue-700'],
  5: ['bg-emerald-100','text-emerald-700'],
  6: ['bg-slate-100','text-slate-700'],
};

const LOG_LEVELS = ['DEBUG','INFO','WARNING','ERROR','FATAL'];
const LOG_CLASSES = ['log-debug','log-info','log-warning','log-error','log-fatal'];

const TITLE_BY_VIEW = {
  'session-logs': 'Session Logs',
  'admin-audit': 'Admin Audit',
  'notifications': 'Notifications',
  'users': 'Users',
  'bookings': 'Bookings',
  'send-notification': 'Send Notification',
  'future-calls': 'Future Calls',
  'health': 'Server Health',
  'api-keys': 'API Keys',
  'query-runner': 'Query Runner',
  'ai-query': 'AI Assistant',
  'investigations': 'Investigations',
  'api-console': 'API Console',
  'csv-decrypt': 'CSV Decryptor',
  'monitoring': 'Monitor',
  'praxis-refresh': 'Praxis Refresh',
  'cockpit-fill': 'Cockpit Fill',
  'cockpit-sync': 'Cockpit Sync',
  'praxis-cleanup': 'Praxis Cleanup',
  'personio-audit': 'Personio Audit',
  'rds-restore': 'RDS Restore',
  'db-refresh': 'DB Refresh',
  'release': 'Build & Release',
  'ssh-tunnels': 'SSH Tunnels',
  'local-stack': 'Local Stack',
  'lilli': 'Lilli Staging',
};
