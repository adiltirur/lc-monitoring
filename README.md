# LillianCare Debugger

Local developer tool for debugging and monitoring the LillianCare platform. Runs on `http://localhost:3333` only — do not expose to the internet.

---

## First-Time Setup

### 1. Install dependencies

```bash
cd /Users/adil/Work/LillianCare/helper
npm install
```

### 2. Configure secrets

Copy the example env file and fill in your values:

```bash
cp .env.example .env
```

Open `.env` and fill in:

```env
DB_DEV_PASSWORD=your_local_postgres_password
DB_STAGING_PASSWORD=your_staging_db_password
DB_PROD_PASSWORD=your_production_db_password

DECRYPT_KEY_DEV=your32chardevkeyhere123456789012
DECRYPT_KEY_STAGING=your32charstagingkeyhere1234567
DECRYPT_KEY_PROD=your32charprodkeyhere12345678901
```

> Decrypt keys must be **exactly 32 characters**. These are the AES-256-CBC keys used to decrypt `encryptedUserInfo` in guest appointments.

### 3. (Optional) Configure Firebase push notifications

If you need to send FCM push notifications, paste your Firebase service account JSON via the **Send Notification** tab in the UI. It will be saved to `.fcm_service_account.json` automatically.

---

## Starting the Server

```bash
cd /Users/adil/Work/LillianCare/helper
npm start
```

Then open **http://localhost:3333** in your browser.

---

## Stopping the Server

If you started with `npm start` in a terminal, press **Ctrl+C** in that terminal.

If it's running in the background:

```bash
lsof -ti:3333 | xargs kill -9
```

---

## Connecting to a Database

1. Click the **DB Config** panel at the top of the page (click the row to expand it)
2. Select a preset: **Development**, **Staging**, or **Production**
   - The password and decrypt key are filled automatically from your `.env`
3. Click **Connect**

The status dot turns green when connected. All views (Session Logs, Users, Bookings, etc.) use the active connection.

---

## Features

| Section | What it does |
|---|---|
| **Session Logs** | Browse Serverpod request logs, filter by endpoint/method/date, view errors and stack traces |
| **Admin Audit** | View admin actions by user, praxis, and date |
| **Notifications** | Browse push notification logs |
| **Server Health** | Serverpod health metrics, DB connection pool stats |
| **Users** | Search users, view profile/insurance/appointments, edit fields, manual verification |
| **Bookings** | View registered and guest appointments, decrypt guest patient info |
| **Send Notification** | Send FCM push notifications to specific user devices |
| **Future Calls** | View and cancel Serverpod scheduled tasks |
| **API Keys** | View usage stats, enable/disable keys |
| **Query Runner** | Run raw SQL with preset queries and AI-assisted query generation |
| **AI Assistant** | Chat with Claude (via AWS Bedrock) to generate SQL queries |
| **CSV Decryptor** | Bulk-decrypt exported guest appointment CSVs |
| **AWS Monitor** | Real-time dashboard for EC2, RDS, Redis, ALB, CloudFront, CloudWatch metrics/alarms and live log stream |

---

## AWS Monitor Setup

The monitoring dashboard works out of the box — it uses your local AWS credentials (`~/.aws/credentials`).

**Basic metrics** (CPU, network, RDS connections, ALB latency) are available immediately with no AWS changes.

**Memory and disk metrics** require the CloudWatch Agent on EC2 instances. To deploy it:

```bash
cd /Users/adil/Work/LillianCare/LillianCare-Core/lillian_care_core_server/deploy/aws/terraform

# Apply only the CloudWatch Agent changes (safe, won't affect running instances)
terraform apply \
  -target=aws_ssm_parameter.cloudwatch_agent_config \
  -target=aws_iam_role_policy_attachment.cloudwatch_agent \
  -target=aws_launch_configuration.serverpod \
  -target=aws_launch_configuration.staging \
  -target=aws_launch_configuration.test \
  -target=aws_autoscaling_group.serverpod \
  -target=aws_autoscaling_group.staging \
  -target=aws_autoscaling_group.test
```

Then do a rolling instance refresh (start with test, then staging, then prod):

```bash
aws autoscaling start-instance-refresh --auto-scaling-group-name lc-core-serverpod-test
# Wait for test to finish, verify metrics appear, then:
aws autoscaling start-instance-refresh --auto-scaling-group-name lc-core-serverpod-staging
aws autoscaling start-instance-refresh --auto-scaling-group-name lc-core-serverpod
```

---

## Project Structure

```
helper/
  server.js                   — Express backend (all API routes)
  package.json                — Node.js dependencies
  .env                        — Your secrets (never commit this)
  .env.example                — Template for .env
  .gitignore                  — Excludes .env and .fcm_service_account.json
  CLAUDE.md                   — Instructions for Claude Code
  README.md                   — This file
  public/
    index.html                — Main dashboard SPA
    monitoring.html           — AWS monitoring dashboard
    tools/
      decrypt_viewer.html     — CSV bulk decryptor
```

---

## Troubleshooting

**Port 3333 already in use:**
```bash
lsof -ti:3333 | xargs kill -9
npm start
```

**Live Logs tab shows "ECONNREFUSED":**
You are connected to `localhost` but no local Serverpod server is running. Switch to Staging or Production in the DB Config panel.

**Preset password field is empty after selecting a preset:**
Your `.env` file is missing or the password for that environment is not filled in.

**Decrypt button does nothing / wrong output:**
The decrypt key for the selected environment is wrong or missing in `.env`. Keys must be exactly 32 characters.

**AWS Monitor shows no data:**
Run `aws sts get-caller-identity` to confirm your AWS credentials are active. If expired, re-authenticate with `aws sso login` or update `~/.aws/credentials`.
