# LC Helper: Project Overview

LC Helper (package name `lilliancare-debugger`) is a **local-only** developer and operations tool for the
LillianCare platform: a German, multi-tenant healthcare platform where every medical practice (a "Praxis") is a
tenant. It runs on `http://localhost:3333`, is never exposed to the internet, and comes wrapped as a small macOS
app.

It brings together everything needed to debug, monitor and operate the platform across environments
(dev, test, staging, production): database browsing, logs, AWS monitoring, data-repair wizards, release
tooling, AI-assisted investigations and an API console.

> This document contains no secrets. Credentials live only in the gitignored `.env` (see `.env.example` for the
> variable names) and in gitignored local state folders. Account IDs, internal IPs and similar infrastructure
> identifiers are left out on purpose.

---

## 1. Where it sits in the LillianCare workspace

The helper is one repo among several sibling folders:

| Folder | What it is |
|---|---|
| `LillianCare-Core/` | Serverpod 2.9 backend (Dart, Postgres, Redis), deployed to AWS |
| `apps-frontend/` | Flutter apps: patient app and Praxis app, plus shared packages |
| `LillianCare-Shared-Models/` | Shared `Api…Req` / `Api…Res` models |
| `Lilli/` | Voice and booking assistant (Next.js) |
| `investigations/` | Investigation notes and playbooks, shared with the helper |
| **`helper/`** | **This project** |

The helper reads several of these siblings directly: it parses Core's sources for the API Console, builds the
Flutter apps from `apps-frontend`, runs the local backend from `LillianCare-Core`, and reads and writes
`investigations/`.

---

## 2. Tech stack

- **Server:** Node.js and Express. `server.js` is only the bootstrap. Each feature is one Express Router in
  `routes/<feature>.js`, and helpers shared by several routes live in `lib/`.
- **Frontend:** a vanilla HTML/CSS/JS single-page app with hash routing. No framework, no build step, no
  TypeScript.
- **Database:** PostgreSQL via `pg`, connecting to the Serverpod database of the selected environment.
- **AWS SDK v3:** EC2, RDS, CloudWatch, CloudWatch Logs, ELBv2, ElastiCache, S3, CloudFront, CodeDeploy, SSM,
  Bedrock.
- **Other dependencies:** `dotenv`, `google-auth-library` (FCM, Google Business Profile), `xlsx` (Excel import).
- **AI:** Amazon Bedrock for chat and SQL help, and headless Claude Code sessions (sandboxed, read-only) for code
  analysis.
- **Mac shell:** a Swift Package (AppKit and WKWebView) in `mac/`.

### Repository layout

```
helper/
  server.js              Bootstrap: dotenv, middleware, mounts routes/*, static files, listen
  routes/                One Express Router per feature (~40 files)
  lib/                   Shared helpers: db, aws, ai, praxis, analytics, personio, pms,
                         local-stack, investigations, lilli, sidecar, api-console/*
  scripts/               lilli.js (Lilli ops CLI), gen-theme.js, sidecar_smoke_test.js,
                         lilli-deploy-remote.sh
  public/
    index.html           App shell: top bar, sidebar, popovers, script tags
    css/                 app.css, api-console.css (tokens come from theme.css)
    theme.css/.js        Generated design tokens (scripts/gen-theme.js)
    js/core/             Shared frontend code (constants, format, ui, api, router, charts, …)
    js/views/            One file per view
    monitoring.html      AWS monitoring dashboard (iframe, live logs via SSE)
    tools/               Standalone iframe tools (decrypt viewer, RDS restore)
    brand/, vendor/      Logos, Manrope font, Material Symbols (all served locally)
  mac/                   Swift wrapper app + LaunchAgent installer
  .env.example           Names of the required settings (no values)
```

### How the frontend loads

Scripts are plain classic `<script>` tags in `index.html`, loaded in order: `core/`, then `views/`, then the
command palette, shell and boot code. They share one global scope, which the inline `onclick` handlers rely on.
So top-level names must be unique across files, and every new file has to be added to `index.html`.

---

## 3. Running it

- **As a service:** `mac/install.sh` builds **LC Helper.app** into `~/Applications` and installs a LaunchAgent
  that runs `node server.js` all the time (start at login, restart on exit). Logs go to
  `~/Library/Logs/LCHelper/server.log`.
- **The Mac app** is a menu-bar item plus a window on demand. It injects `window.lcNative` for native actions
  (window drag, zoom, notifications, environment tint). On production the window turns red and shows a "PROD"
  badge. It also provides the file pickers, downloads, dialogs and `window.open` that WKWebView lacks.
- **Applying changes:** web changes need only a reload (⌘R). Server changes need "Restart Helper Server" in the
  menu bar. To test a server change first, run a second copy: `PORT=<free port> node server.js`.
- **Manually:** `npm start` (= `node server.js`).

---

## 4. Environments and connections

The connection popover offers four presets: **dev** (local Docker Postgres), **test**, **staging** and
**production**. Each preset has its own colour plate: dev is white, test blue, staging amber, and on production
the whole header becomes a red band.

- Credentials go from the browser to the server as `x-db-*` request headers. The server caches one connection
  pool per connection string.
- `GET /api/env-config` gives the frontend the per-env settings it needs from `.env`, so the right preset fills
  itself in. The raw file is never served.
- Wizards that work across two environments use two header sets (`x-src-db-*` and `x-tgt-db-*`).

### Local Stack

The Local Stack view keeps the local backend running so the dev preset works: Docker Desktop, then
`docker compose up -d` (Postgres on :8090, Redis on :8091), then `dart run bin/main.dart --mode development`
(API on :8080) in `LillianCare-Core/lillian_care_core_server`. Serverpod is started detached with a PID file, so
restarting the helper does not kill it. It starts automatically on port 3333; applying migrations is off by
default.

---

## 5. Feature map

The sidebar is grouped into sections. Each view has a matching router under `/api/...`.

### Signals

| View | What it does |
|---|---|
| **Monitor** | Dashboard for AWS: infrastructure overview, CloudWatch metrics and alarms, live log stream (SSE), error summaries, PMS downtime, slow and long-running requests, endpoint health. |
| **Server Health** | Health check of the backend servers. |
| **DB Diagnostics** | "Is the database slow or stuck?" Connections, long-running and blocked queries, idle transactions, full-table scans, largest tables, `pg_stat_statements`, plus RDS CloudWatch metrics (EBS byte balance, latencies, CPU, memory, storage). Turns the numbers into a list of findings. Read-only, except for an opt-in `CREATE EXTENSION pg_stat_statements`. |
| **Log Cleanup** | Deletes expired Serverpod session logs in small batches, for when the built-in retention cleanup can't catch up. Optional `VACUUM (ANALYZE)` afterwards. |
| **Local Stack** | Starts, stops and restarts the local backend and shows its logs (see above). |

### Logs

| View | What it does |
|---|---|
| **Session Logs** | Serverpod session logs per endpoint, with details. |
| **Admin Audit** | The admin audit log. |
| **Notifications** | Notifications sent by the platform. |
| **Message Outbox** | Core's Brevo email/SMS queue: status, delivery events, template mapping, retry, send now, stop a message. Includes a **template test** that sends one copy of a real past email to an address you type in (never to the original recipients). |
| **Analytics** | Monthly metrics per practice (a port of Core's admin analytics), a cockpit overview, and a one-off historical export (XLSX, JSON, HTML). |

### Data

| View | What it does |
|---|---|
| **Users** | Search app users, show details, edit, verify. Encrypted fields are decrypted locally (AES-256-CBC). Shows medications and documents from the PMS (Principa FHIR) through a server-side proxy. |
| **Incomplete Registrations** | People who started registering but never got a profile (open requests, auth accounts without a profile, unmigrated legacy accounts). Deletes them so they can register again. |
| **Bookings** | App and guest bookings. |
| **PMS Invitations** | Read-only view of invitation codes and auto-link attempts created from Principa patient messages. |
| **Duplicate Accounts** | Merges users who have both a legacy and a new account with the same email. The new account is always kept; data is moved, legacy auth rows are deleted. Unclear cases are merged one pair at a time from a review panel. |
| **Query Runner** | Run SQL against the connected environment. |
| **AI Assistant** | Natural language to SQL via Bedrock, with the schema as context. |
| **Investigations** | AI-assisted production investigations (see section 7). |
| **FHIR Scrubber** | Removes personal data from FHIR / Principa logs. |
| **API Console** | Postman-like console (see section 6). |
| **Principa SideCar** | Read-only queries against the practice software's reporting database, through an SSM tunnel via the one whitelisted instance. |

### Operate

| View | What it does |
|---|---|
| **Send Notification** | Send an FCM push to a user's device. |
| **Future Calls** | Inspect and delete Serverpod scheduled tasks. |
| **API Keys** | List API keys and change their status. |
| **CSV Decryptor** | Decrypt exported CSVs locally. |
| **Google Business** | OAuth to Google Business Profile; list locations and edit opening hours. |
| **Praxis Refresh** | Wizard that refreshes staging practice data from prod: schema-drift check, backup, wipe staging, import, scrub contacts, set default practice. |
| **Cockpit Fill** | Fills practices' standard-week schedules from the master Excel, mapping person names to Personio employees. |
| **Cockpit Sync** | Copies the cockpit tables for selected practices from one environment to another. Production is never a target. |
| **Praxis Cleanup** | Deletes a single practice and every reference to it, so it can be created again. |
| **Personio Audit** | Checks the Personio roster against the employees used in the cockpit tables and offers fixes. |
| **RDS Restore** | Restores a single table from a snapshot or point-in-time recovery, step by step. |
| **DB Refresh** | Wipes a whole target database (dev, test or staging) and mirrors the full schema and data from another environment in one transaction. |

### Lilli

| View | What it does |
|---|---|
| **Lilli Staging** | Status, calls, logs, releases, deploy and rollback for the Lilli voice assistant on staging, plus an Investigate tab that answers questions with a sandboxed Claude Code session. Shares one module with the `scripts/lilli.js` CLI; everything printed is scrubbed. |

### Release

| View | What it does |
|---|---|
| **Build & Release** | Builds the patient app and Praxis app (web, APK/AAB, IPA) for test or prod with the Flutter SDK pinned by the workspace, and deploys web builds to S3 and CloudFront. One job at a time. |
| **Deployments** | Shows whether a backend deploy really reached the server: GitHub Action runs, CodeDeploy deployments (with the failed lifecycle events), API health, live commit and whether it's behind. Read-only server check and a restart over SSM. |

### Infra

| View | What it does |
|---|---|
| **SSH Tunnels** | One-click SSM port-forwarding to the private app instances, so ssh clients can connect through a local port. |

A ⌘K command palette lets you jump to any view.

---

## 6. API Console

- **Catalog** parsed live from LillianCare-Core: every Serverpod endpoint method with parameter types, docs,
  login requirements, return types and generated body skeletons. It rebuilds automatically when the Core sources
  change.
- **External templates** for every outbound call the backend makes (Principa FHIR/REST, Personio, Brevo, FCM,
  Google Maps, public holidays) and the inbound webhooks. A "Find missing" button runs a sandboxed Claude Code
  session that proposes templates that are still missing.
- **Auth** handled server-side: LillianCare login sessions, Principa JWT, Personio token rotation, Google service
  account, API keys. Every secret is masked in traces and echoed requests, and a service's credentials are only
  attached when the URL really points at that service.
- **Variables** (`{{name}}`) at dynamic, built-in, global and environment level; collections and history;
  Postman v2.1 import/export; "Copy as curl" with placeholders instead of credentials.
- **Production guard:** anything other than GET/HEAD, and every Serverpod call, needs an explicit confirmation.
- Responses are never saved to disk (they can contain patient data).

---

## 7. Investigations

Notes are markdown files in the shared `../investigations/` folder, so an investigation can move between the
helper and a Claude Code session. Playbooks in that folder are given to the AI as context.

1. Describe the problem or paste logs. The text is **scrubbed** first (names, emails, phone numbers and so on
   become stable placeholders) using the shared scrubber in `investigations/tools/`.
2. Bedrock answers with a message, optionally a proposed SQL query and a log entry.
3. You review and run the SQL. It runs in a **read-only guard**: single statement, read-only transaction,
   timeout, row cap, always rolled back. Results are shown raw in the browser, but only scrubbed results go to
   the AI.
4. Findings can be added to the note's log. Vendor or practice correspondence can be filed (scrubbed) too.
5. **Code analysis** starts a headless Claude Code session in LillianCare-Core with read-only tools, and secret
   files are denied. Its briefing is added to the note.

Placeholder mappings and extra redaction terms are kept locally in a gitignored state folder (file mode 0600).
Notes themselves must not contain personal data.

---

## 8. Safety model

The helper can reach production databases, so safety rules are built into the server, not just the UI:

- **Read-only by default.** Diagnostics, investigations, SideCar and Lilli queries run in read-only transactions
  with timeouts and row caps.
- **Destructive operations are triple-gated:** a header (`x-allow-destructive: yes`), the environment label,
  and a typed confirmation phrase (for example `WIPE STAGING`, `REFRESH STAGING`, `MERGE <id>`,
  `DEPLOY PRAXIS PROD`, `RESTART PRODUCTION`).
- **Production is never a target** for DB Refresh, Cockpit Sync, Praxis Cleanup or the staging wipe. DB Refresh
  also checks that the target host really belongs to the labelled environment.
- **Transactions everywhere:** multi-table changes run in one transaction and roll back on any error or
  disconnect. Merge-type operations recompute their plan under `FOR UPDATE` and must match what you reviewed.
- **Backups before changes:** JSON backups of affected rows go to the gitignored `backups/<env>/...` folder, and
  each committed change is logged to a CSV there.
- **Personal data:** query results with patient data stay in the browser. They aren't logged, saved or sent to
  the AI unscrubbed.
- **Sandboxed AI:** headless Claude Code sessions are restricted to read-only tools inside one repo, with a deny
  list for secret files and no access to the helper's `.env` or scrub mappings.

---

## 9. Configuration and secrets

All secrets live in `.env` (gitignored, never committed, never read by AI tools). `.env.example` lists the
names only. The groups are:

- Database passwords per environment
- Decryption keys per environment (for encrypted user and booking fields)
- PMS (Principa) base URLs and secrets
- Google Business Profile OAuth client
- Personio API client
- Lilli staging database password and Lilli SSO secrets per environment
- Brevo API key, Google Maps API key
- Core API keys per environment
- Principa SideCar connection settings

Other secret or personal files, all gitignored: the Firebase service-account key, the Google Business token
file, and the local state folders (`.api-console/`, `.investigations-state/`, `.lilli-state/`, `.local-stack/`,
`.release/`, `backups/`).

---

## 10. Design

The UI follows the LillianCare corporate identity from the apps' design system: petrol `#004E64` as the primary
colour, logo turquoise `#2BD2C9` / `#B0EFEC`, the Manrope font, white backgrounds and 8 px corner radius. Design
tokens are generated by `scripts/gen-theme.js` into `public/theme.css` and `public/theme.js`. There is a Day
theme (the brand look) and a Night theme (deep petrol). All fonts, icons and logos are served locally, so the
app works offline. `PRODUCT.md` and `DESIGN.md` describe the product context and the visual system.

---

## 11. Adding a feature

1. Create `routes/<feature>.js` (one Express Router) and mount it in `server.js` before the static-files
   section. Shared helpers go in `lib/`; route files never require each other.
2. Add a sidebar item in `public/index.html`.
3. Add a title to `TITLE_BY_VIEW` (`js/core/constants.js`) and a branch in `navigate()` (`js/core/router.js`).
4. Create `public/js/views/<feature>.js` with `renderXxx(el)`, using the shared builders (`pageWrap`,
   `pageHero`, `apiFetch`, loading and error states).
5. Add its `<script>` tag to `index.html`.
6. Optionally add a ⌘K entry.

Conventions: timestamps are shown in Europe/Berlin; SQL column names are camelCase in double quotes; errors are
returned as `res.status(5xx).json({ error })`; no external frontend libraries.

`CLAUDE.md` holds the detailed notes for each feature (table lists, safety guards and edge cases).
