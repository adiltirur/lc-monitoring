require('dotenv').config();
const express = require('express');
const path = require('path');

const app = express();
// The API console relays request bodies (base64 documents, Postman exports) — allow up to
// Serverpod's own maxRequestSize there; everything else keeps the 100 kB default.
app.use('/api/console', express.json({ limit: '30mb' }));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
const { lsReadConfig, lsRun, lsStartServerpod } = require('./lib/local-stack');

// ─── API routes (routes/*.js, mounted in their original order) ───────────────
app.use(require('./routes/core'));
app.use(require('./routes/pms'));
app.use(require('./routes/logs'));
app.use(require('./routes/users'));
app.use(require('./routes/bookings'));
app.use(require('./routes/query'));
app.use(require('./routes/future-calls'));
app.use(require('./routes/analytics'));
app.use(require('./routes/analytics-export'));
app.use(require('./routes/analytics-cockpit'));
app.use(require('./routes/message-outbox'));
app.use(require('./routes/health'));
app.use(require('./routes/api-keys'));
app.use(require('./routes/fcm'));
app.use(require('./routes/monitor'));
app.use(require('./routes/error-report'));
app.use(require('./routes/google-business'));
app.use(require('./routes/praxis-refresh'));
app.use(require('./routes/cockpit-fill'));
app.use(require('./routes/personio-audit'));
app.use(require('./routes/praxis-cleanup'));
app.use(require('./routes/cockpit-sync'));
app.use(require('./routes/rds-restore'));
app.use(require('./routes/db-refresh'));
app.use(require('./routes/ssh-tunnels'));
app.use(require('./routes/local-stack'));
app.use(require('./routes/release'));
app.use(require('./routes/investigations'));
app.use(require('./routes/investigations-code'));
app.use(require('./routes/lilli'));
app.use(require('./routes/lilli-inv'));
app.use(require('./routes/api-console'));

// ─── Static files ─────────────────────────────────────────────────────────────
app.use(express.static(path.join(__dirname, 'public'), { etag: false, maxAge: 0, setHeaders: (res) => { res.setHeader('Cache-Control', 'no-store'); } }));

// PORT lets a second copy run next to the LaunchAgent (e.g. to test a change);
// only the main instance on 3333 autostarts the local stack.
const PORT = Number(process.env.PORT) || 3333;
app.listen(PORT, () => {
  console.log(`LillianCare Debugger running at http://localhost:${PORT}`);
  if (PORT === 3333 && lsReadConfig().autostart) {
    setTimeout(() => lsRun('starting', lsStartServerpod), 2000);
  }
});
