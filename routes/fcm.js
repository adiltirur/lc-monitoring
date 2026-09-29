const router = require('express').Router();
const fs = require('fs');
const path = require('path');
const { GoogleAuth } = require('google-auth-library');
const { query } = require('../lib/db');

const ROOT = path.join(__dirname, '..'); // helper/

// ─── Routes: notifications via FCM ───────────────────────────────────────────
const FCM_CONFIG_PATH = path.join(ROOT, '.fcm_service_account.json');

router.post('/api/fcm/config', (req, res) => {
  try {
    const { serviceAccount } = req.body;
    const parsed = typeof serviceAccount === 'string' ? JSON.parse(serviceAccount) : serviceAccount;
    if (!parsed.project_id || !parsed.private_key || !parsed.client_email) {
      return res.status(400).json({ error: 'Invalid service account JSON — missing project_id, private_key, or client_email' });
    }
    fs.writeFileSync(FCM_CONFIG_PATH, JSON.stringify(parsed, null, 2));
    res.json({ ok: true, projectId: parsed.project_id });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

router.get('/api/fcm/config', (req, res) => {
  try {
    if (!fs.existsSync(FCM_CONFIG_PATH)) return res.json({ configured: false });
    const sa = JSON.parse(fs.readFileSync(FCM_CONFIG_PATH, 'utf8'));
    res.json({ configured: true, projectId: sa.project_id, clientEmail: sa.client_email });
  } catch (e) {
    res.json({ configured: false });
  }
});

router.get('/api/users/:id/tokens', async (req, res) => {
  try {
    const rows = await query(req, `SELECT id, token, "deviceId", platform, "createdAt", "lastUsedAt" FROM app_user_notification_token WHERE "userId" = $1 ORDER BY "createdAt" DESC`, [parseInt(req.params.id)]);
    res.json(rows);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

router.post('/api/fcm/send', async (req, res) => {
  try {
    if (!fs.existsSync(FCM_CONFIG_PATH)) return res.status(400).json({ error: 'Firebase not configured. Add service account first.' });
    const sa = JSON.parse(fs.readFileSync(FCM_CONFIG_PATH, 'utf8'));
    const { tokens, title, body, data = {} } = req.body;
    if (!tokens || !tokens.length) return res.status(400).json({ error: 'No tokens provided' });
    if (!title || !body) return res.status(400).json({ error: 'title and body are required' });

    const auth = new GoogleAuth({ credentials: sa, scopes: ['https://www.googleapis.com/auth/firebase.messaging'] });
    const accessToken = await auth.getAccessToken();

    const results = [];
    for (const token of tokens) {
      const payload = {
        message: {
          token,
          notification: { title, body },
          data: Object.fromEntries(Object.entries(data).map(([k, v]) => [k, String(v)])),
        },
      };
      const fcmRes = await fetch(`https://fcm.googleapis.com/v1/projects/${sa.project_id}/messages:send`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${accessToken}`, 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });
      const result = await fcmRes.json();
      results.push({ token: token.slice(-10), ok: !result.error, error: result.error?.message });
    }
    res.json({ results, sent: results.filter(r => r.ok).length, failed: results.filter(r => !r.ok).length });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

module.exports = router;
