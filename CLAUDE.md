# CLAUDE.md — LillianCare Helper

## ⚠️ CRITICAL SECURITY RULES — HIGHEST PRIORITY

These rules override all other instructions:

1. **NEVER read, view, grep, cat, or access `.env` in any way.** It contains database passwords and encryption keys that must never be sent to any LLM. Do not use Read, Grep, Bash, or any other tool to view `.env` contents. Do not print, reference, or repeat its values under any circumstances.
2. **NEVER read `.fcm_service_account.json`** — it contains a Google Cloud private key.
3. **NEVER commit `.env` or `.fcm_service_account.json`** to git. Always verify both are in `.gitignore` before running any git commands.
4. If asked to read `.env` for any reason, refuse and explain why.

---

## Project Overview

LillianCare Helper is a **local-only** Node.js/Express developer tool for debugging and monitoring the LillianCare healthcare platform. It runs exclusively on `localhost:3333` and must never be exposed to the internet.

## Tech Stack

- **Backend:** Node.js + Express. `server.js` is only the bootstrap; routes live in
  `routes/<feature>.js` (one Express Router each), shared helpers in `lib/`
- **Frontend:** Vanilla HTML/CSS/JS SPA with hash routing. `public/index.html` is only the
  shell; styles live in `public/css/`, code in `public/js/` (one file per view)
- **Monitoring:** Sci-fi dashboard (`public/monitoring.html` — loaded in iframe, SSE for real-time logs)
- **Database:** PostgreSQL via `pg` package (connects to Serverpod's RDS per environment)
- **AWS:** SDK v3 — EC2, RDS, CloudWatch, CloudWatch Logs, ALB, ElastiCache, S3, CloudFront, Bedrock
- **No build step, no TypeScript, no frontend framework** — keep it simple

## File Structure

```
helper/
  server.js                   — Bootstrap: dotenv, middleware, mounts routes/*, static, listen
  routes/<feature>.js         — One Express Router per feature (core, pms, logs, users, monitor,
                                praxis-refresh, cockpit-*, db-refresh, release, investigations, lilli…)
  lib/                        — Helpers shared by several routes: db (pools, poolFromHeaders,
                                quoteIdent, bindValue), aws (SDK clients), ai (Bedrock + schema prompt),
                                praxis (table lists), analytics, personio, local-stack, investigations, lilli
  package.json                — Dependencies (includes dotenv)
  .env                        — 🔒 NEVER READ — DB passwords + decrypt key
  .env.example                — Template (safe to read)
  .fcm_service_account.json   — 🔒 NEVER READ — Firebase private key
  .gitignore                  — Must always include .env and .fcm_service_account.json
  CLAUDE.md                   — This file
  scripts/                    — lilli.js (Lilli ops CLI), gen-theme.js, lilli-deploy-remote.sh
  public/
    index.html                — App shell: top bar, sidebar nav, popovers, script tags
    css/app.css               — Shell + component styles (tokens come from theme.css)
    js/core/                  — Shared code, loaded before the views
      constants.js            — PRESETS, status/pill maps, TITLE_BY_VIEW
      format.js               — Dates (Europe/Berlin), escHtml, showToast, copyText
      ui.js                   — pageHero, pageWrap, btn*/f* builders, empty/loading/error states, pagination
      api.js                  — env-config, praxis names, getCfg/dbHeaders, apiFetch/apiPost/apiPatch,
                                ensureEnvPasswords/envHeadersFor (two-env wizards)
      connection.js           — Connection popover, presets, env plate + native setEnv
      router.js               — navigate(view)
      charts.js               — Inline-SVG chart primitives
      crypto.js               — AES-256-CBC decrypt (bookings, users)
      command-palette.js      — ⌘K palette (CMDK list)
      shell.js                — Display settings (tweaks), clocks, uptime ticker
      boot.js                 — Init: apply tweaks, load connection, first navigate, hashchange
    js/views/<view>.js        — One file per view (renderXxx + its helpers and state)
    monitoring.html           — AWS monitoring dashboard (iframe, sci-fi theme)
    tools/                    — decrypt_viewer.html, aws_rds_restore.html (iframes)
```

**How the frontend scripts load:** plain classic `<script src>` tags at the end of
`index.html`, in order: `core/` → `views/` → `command-palette.js`, `shell.js`, `boot.js`.
They are not ES modules: all top-level functions and `let`/`const` share one global
scope, which is what inline `onclick="fn()"` handlers rely on. Consequences:
- Top-level names must be unique across all files (prefix view state, e.g. `invList`, `prState`).
- Code that runs at load time (not inside a function) may only use things defined
  in the same file or an earlier one. Calls inside functions are fine anywhere.
- New files must be added to the script list in `index.html`.

## Mac app (`mac/`) and always-on server

- `mac/` is a Swift Package (AppKit + WKWebView) that wraps `http://localhost:3333`
  as **LC Helper.app** (`~/Applications`). `mac/install.sh` builds it and installs
  the LaunchAgent `care.lillian.helper.server` which runs `node server.js`
  (RunAtLoad + KeepAlive, logs in `~/Library/Logs/LCHelper/server.log`).
  Re-run `install.sh` after switching nvm Node versions (node path is baked in).
- The app is a menu-bar item + a window on demand. Closing the window does not
  stop anything; quitting the app does not stop the server.
- Web changes need no rebuild (⌘R in the app). server-side changes (`server.js`, `routes/`, `lib/`) need
  "Restart Helper Server" in the menu bar (`launchctl kickstart -k`).
- The shell injects `data-shell="mac"` on `<html>` and `window.lcNative.post(type, payload)`
  (`drag`, `zoom`, `notify`, `setEnv`). Elements with `data-drag-region` drag the
  window; mark popovers inside them `data-no-drag`. The page calls `setEnv` so the
  native window tints red and badges "PROD" on production.
- WKWebView has no built-in `alert/confirm/prompt`, file picker, downloads or
  `window.open` — the shell implements all of them. Non-localhost navigations open
  in the default browser (Google OAuth refuses embedded webviews).

## Local Stack (`/api/local-stack/*`, view `#local-stack`)

Keeps the local backend running so the `dev` preset works: Docker Desktop →
`docker compose up -d` (Postgres :8090, Redis :8091) in
`../LillianCare-Core/lillian_care_core_server`, then `dart run bin/main.dart --mode development`
(API :8080). Serverpod is spawned **detached** with a PID file in `.local-stack/`
(gitignored), so restarting the helper does not kill it. State/config/log live in
`.local-stack/` (`config.json`: `autostart` default true, `applyMigrations` default
false). Docker's CLI is not on launchd's PATH — `LS_PATH` in `lib/local-stack.js` adds it.
Override the Serverpod dir with `LC_SERVERPOD_DIR`.

## Visual system

`PRODUCT.md` holds product context; `DESIGN.md` the visual system. The UI follows
the **LillianCare CI** from `../apps-frontend/packages/design_system` (petrol
`#004E64` primary, logo turquoise `#2BD2C9`/`#B0EFEC`, Manrope, white grounds,
8px radius). Brand assets live in `public/brand/` (logo SVGs copied from the
praxis app) and `public/vendor/fonts/` (Manrope TTFs, Material Symbols).
Shared tokens: `public/theme.css` + `public/theme.js` are **generated** by
`scripts/gen-theme.js` — edit the generator, then `node scripts/gen-theme.js public`.
`theme.js` also exports `window.LC_TAILWIND_CONFIG`, which maps every Tailwind
colour (Material tokens and stock hues) onto theme variables, so utility classes in
views re-theme for Day/Night automatically. Day is the brand look; Night is a
deep-petrol variant. Everything is served locally, so the app works offline.
Environment plates: 1 dev (white), 2 test (blue), 3 staging (amber), 4 production
(the whole header becomes a red band). Destructive wizard steps carry
`class="lc-destructive" data-band="…"` for a red header band.

## Architecture & Key Patterns

**DB credentials flow:**
- Configured via the browser's top config panel (Dev / Staging / Prod presets)
- Passwords auto-filled from `.env` via `GET /api/env-config` on page load
- Credentials travel as HTTP request headers: `x-db-host`, `x-db-port`, `x-db-name`, `x-db-user`, `x-db-password`
- SSE endpoint (`/api/monitor/logs/stream`) uses query params instead (EventSource doesn't support custom headers)
- Pool management: `getPool(req)` in `lib/db.js` creates/caches PG connection pools keyed by connection string

**Environment presets** (`PRESETS` in `public/js/core/constants.js`):
- `dev` → `localhost:8090/lillian_care_core`
- `test` → `database-test.lillian.care:5432/serverpod`
- `staging` → `database-staging.lillian.care:5432/serverpod`
- `production` → `database.lillian.care:5432/serverpod`

**Secret loading:**
- `require('dotenv').config()` at the top of `server.js` loads `.env`
- `GET /api/env-config` serves `{ passwords: { dev, test, staging, production }, decryptKeys: { dev, staging, production } }` to the frontend
- Frontend fetches this on load and uses it to auto-fill the password field when a preset is selected

**Navigation:** Hash-based routing via `navigate(view)` (`public/js/core/router.js`). Each view has a `renderXxx(el)` function in `public/js/views/`. See "Adding New Features".

**Monitoring dashboard:** Lives in `monitoring.html` (separate file, own CSS). Tabs: Overview, Metrics, Live Logs, Errors, Alarms.

## AWS Infrastructure (eu-central-1, account 730335337275)

- 6 EC2 instances: `lc-core-serverpod` (prod/staging/test) + `lilli-prod/staging` + OpenClaw
- 5 RDS PostgreSQL: `lc-core` (prod/staging/test) + `lilli-prod/staging`
- 3 ElastiCache Redis: `lc-core` (prod/staging/test)
- 3 ALBs: `lc-core-serverpod` (prod/staging/test)
- 4 CloudFront distributions
- Terraform at: `LillianCare-Core/lillian_care_core_server/deploy/aws/terraform/`
- CloudWatch Agent configured via SSM Parameter `/lc-core/cloudwatch-agent/config`

## Coding Conventions

- Timestamps display in `Europe/Berlin` timezone via `Intl.DateTimeFormat`
- SQL column names use camelCase with double quotes: `"firstName"`, `"createdAt"`
- Error responses: `res.status(5xx).json({ error: e.message })`
- No external frontend libraries (PapaParse CDN is the only exception, in decrypt_viewer.html)
- Keep files focused and readable: one view per file in `public/js/views/`; shared
  helpers go in `public/js/core/` only when more than one view uses them. Split a
  view into several files (`views/<view>-<part>.js`) rather than letting one grow huge.

## Adding New Features

1. Add API routes in a new `routes/xxx.js` (`const router = require('express').Router();`
   … `module.exports = router;`) and mount it in `server.js` with `app.use(require('./routes/xxx'));`
   before the `// ─── Static files ───` section. Put helpers that more than one route file
   needs in `lib/`; route files never require each other. Test a server change with a
   second copy (`PORT=<free port> node server.js`; only port 3333 autostarts the local
   stack) before restarting the LaunchAgent
2. Add sidebar nav item in `public/index.html` under the relevant section
3. Add a title to `TITLE_BY_VIEW` (`js/core/constants.js`) and
   `else if (view === 'xxx') renderXxx(content);` in `navigate()` (`js/core/router.js`)
4. Create `public/js/views/xxx.js` with `function renderXxx(el) { ... }` following
   existing patterns (`pageWrap`/`pageHero`, `apiFetch`, `loadingState`/`errorState`)
5. Add `<script src="/js/views/xxx.js"></script>` to the views block in `index.html`
6. Optionally add a ⌘K entry to `CMDK` (`js/core/command-palette.js`)
7. For monitoring features: add to `monitoring.html` instead

## Praxis Refresh feature (`/api/praxis/*`, view `#praxis-refresh`)

Wizard for refreshing staging praxis data from prod:
1. Schema-drift check → 2. Backup both envs → 3. Wipe staging → 4. Import prod → staging
→ 5. Scrub contacts → 6. Set default praxis on all users.

**Hardcoded table list (`PRAXIS_CONFIG_TABLES` in `lib/praxis.js`)** — when the
backend adds a new `praxis_*_config` or `cockpit_*` table that's praxis-scoped,
add it to this constant. Step 0 (drift check) queries the live target schema
for any column named `praxisId` and flags tables not in this list, so an
out-of-date enumeration will surface on the next run.

**Two-env operations** — the import endpoint takes BOTH `x-src-db-*` and
`x-tgt-db-*` header sets. The frontend pulls passwords from `/api/env-config`
once on view init, then constructs both header sets from `PRESETS`.

**Destructive guards** — `POST /api/praxis/wipe-staging` requires:
- `x-env-label: staging`
- `x-allow-destructive: yes`
- body `confirmation` exactly `WIPE STAGING`

`scrub-contacts` and `set-default` refuse if `x-env-label` is `production` or
`prod`.

**Why historical data isn't wiped** — we delete only the 25 praxis-config
tables. The 14 historical tables (`app_user_appointment`, `admin_audit_log`,
`fhir_nps`, `guest_appointment`, etc.) keep their `praxisId` columns but those
references become orphaned after wipe. This is intentional: it preserves test
history and matches what the user asked for. `app_user_info.praxisId` and
`admin_user_info.associatedPraxisIds` get fixed by step 5; the rest stay
orphaned and harmless because Serverpod treats `praxisId` as a filter string,
not an enforced FK.

**Backups** — written to `helper/backups/<env>/<ISO-timestamp>/<lcId>.json`.
The `backups/` directory is gitignored.

**Cross-table FK skip list (`PRAXIS_CONFIG_TABLES_SKIP_IMPORT`)** — some
praxis-config tables have a NOT NULL FK to a non-praxis table (e.g.,
`praxis_device_config.userInfoId → app_user_info.id`). Importing rows from
prod would violate that FK on staging because prod's user ids don't exist
there. These tables are still backed up and wiped, but skipped on import.
If you add a new praxis-config table that references users/admins, add it
to this set in `lib/praxis.js`.

## Cockpit Fill feature (`/api/cockpit/*`, view `#cockpit-fill`)

Bulk-fills a praxis's standard-week schedule from a Master Excel.

**Excel structure** — one sheet per praxis (`*_Neu` suffix). Each sheet has 3
blocks identified by header text in column A:
- "Öffnungszeiten" — practice opening hours (1 row, no person)
- "Sprechstundenzeiten" — per-person consultation slots (many rows: col A
  carries the person name down, col B is the resource label like "Arzt 1 vor
  Ort", "Akutsprechstunde", "Nicht buchbare Zeiten")
- "Arbeitszeiten" — per-role staff working hours (col B has role labels:
  "Arzt", "PA", "MFA")

Each row has 5 days × {AM start, AM end, PM start, PM end} in cols 3-22.
Time cells can be strings ("8:00:00"), Excel time serials (numbers), or Date
objects — `cellToHHMM()` normalizes all three to "HH:MM".

**DB writes** (per mapped sheet):
- Replace mode: DELETE existing rows on `praxis_hours_config`,
  `cockpit_standard_week_version`, `cockpit_week_override` for that praxisId
- INSERT one `praxis_hours_config` row per opening slot (day stored as int
  enum: monday=0…friday=4)
- INSERT one `cockpit_standard_week_version` row per praxis with three JSON
  blobs (`openingHoursJson`, `consultationHoursJson`, `workHoursJson`) matching
  the praxis app's domain models (OpeningSlot / ConsultationSlot / WorkSlot)

**Personnel resolution** — Excel uses person NAMES, but cockpit slots need
Personio numeric `employeeId`s. The view fetches Personio's `/v1/company/employees`
(via `PERSONIO_CLIENT_ID/SECRET` in `.env`) and shows an auto-suggested match
per name (Levenshtein similarity threshold 0.6). If creds aren't set, the UI
falls back to manual numeric entry per person.

**workHoursJson derivation** — derived from consultationSlots, not from Block 3
of the Excel. Each (employeeId, weekday) pair gets one work slot spanning the
earliest start to the latest end across that person's consultation slots that
day. Block 3 in the Excel is per-role (not per-person) so it can't be mapped
1:1 to the cockpit's per-employee work-hour model.

**Triple-gated on production** — when `x-env-label` is `production`/`prod`,
the import endpoint additionally requires `x-allow-destructive: yes` AND
`body.confirmation === 'IMPORT COCKPIT TO PRODUCTION'`. The Cockpit Fill UI
surfaces a confirmation block (checkbox + typed phrase) when the target
preset is Production. Staging/dev are unaffected.

**Timezone invariant** — Times are wall-clock Europe/Berlin throughout. DB
columns (`praxis_hours_config.start`/`"end"` and the three `*HoursJson` blobs
in `cockpit_standard_week_version`) store `"HH:MM"` text only. The backend
and praxis app pass these through as strings — never construct a `DateTime`
from them. `cellToHHMM` in `routes/cockpit-fill.js` reads `getHours/getMinutes` (NOT
`getUTCHours`) because SheetJS with `cellDates: true` encodes Excel
time-of-day into the **local** components of the Date object — e.g. cell
`08:15` returns a Date `d` with `d.getHours()===8` regardless of host TZ;
the absolute UTC instant is offset by the host's TZ at the Excel epoch
(1899-12-30, no DST), so `getUTCHours()` would silently shift every time
by the host's offset (1 hour earlier when the helper runs on a CET/CEST
machine).

## Cockpit Sync feature (`/api/cockpit/source-summary`, `/api/cockpit/cross-env-copy`, view `#cockpit-sync`)

Cross-env copy of the cockpit-related tables for selected praxes. Same two
header sets as Praxis Refresh import (`x-src-db-*` + `x-tgt-db-*`), but scoped
to the cockpit subset (constant `COCKPIT_SYNC_TABLES` in `routes/cockpit-sync.js`):

```
praxis_hours_config
cockpit_standard_week_version
cockpit_appointment_type_matrix
cockpit_week_override
cockpit_person_duration_exception
```

**Praxis matching** — by `lcId`. Numeric `praxisId` FKs are looked up on
target and remapped on insert. If a source `lcId` doesn't exist on the target,
that praxis is skipped (logged in result). Personio `employeeId` values inside
the JSON blobs are global IDs and pass through unchanged.

**Replace mode** (default) — DELETE target rows for the praxis on each table
before INSERTing source rows, so the target ends up exactly mirroring source
for the selected praxes. Append mode is available but will likely violate
UNIQUE constraints on `cockpit_appointment_type_matrix(praxisId, appointmentTypeKey)`.

**Production target is refused** — `x-tgt-env-label: production|prod` errors
out. To overwrite cockpit data on prod, do it through the praxis app cockpit
UI directly (which has audit logging).

The whole copy runs in one transaction on the target connection — any error
rolls back the entire batch.

## Praxis Cleanup feature (`/api/praxis/cleanup-preview`, `/api/praxis/cleanup`, view `#praxis-cleanup`)

Single-praxis deep delete. Used when a praxis is in a broken state (e.g.
duplicate-creation collision) and you want every reference to it gone so it
can be safely recreated.

**Three triple-gated requirements** — server rejects with a clear message
unless all are satisfied:
- `x-env-label` is NOT `production` / `prod`
- `x-allow-destructive: yes` header
- body `confirmation` exactly equals the `lcId`

**Per-table action map (`CLEANUP_NON_CONFIG_TABLES` in `routes/praxis-cleanup.js`)**:

| Table | Action | Why |
|---|---|---|
| 24 praxis-config child tables | DELETE | Standard config wipe. |
| `praxis_config` (root) | DELETE | Removes the praxis row last. |
| `app_user_appointment_reminder`, `cockpit_person_duration_exception`, `praxis_hours_sync_target` | DELETE (numeric FK) | Praxis-specific data. |
| `app_user_appointment`, `app_user_open_consultation`, `app_user_document_request`, `app_user_reserved_appointment`, `app_user_nps_sent`, `guest_appointment`, `questionnaire_reservation`, `fhir_nps`, `app_user_pms_invitation` | DELETE (string lcId) | Historical data tied to this praxis only. |
| `app_user_info` | UPDATE praxisId = NULL | Preserve the user account. |
| `admin_user_info` | UPDATE associatedPraxisIds (filter the lcId out of JSON array) | Preserve the admin account. |
| `admin_audit_log` | KEEP | Historical record — should survive even if its praxis is gone. |

When a new praxis-scoped table is added in the backend, add it here with the
right action mode.

**Re-creation after cleanup** — once cleanup succeeds, you can re-create the
praxis (e.g. via Praxis Refresh import or the praxis app) without lcId
collisions. Users and admins that were previously linked have their references
nulled / filtered, so reassigning them to the new praxis row is a separate
follow-up step.

## DB Refresh feature (`/api/db-refresh/*`, view `#db-refresh`)

Wipes an ENTIRE target database and mirrors the full public schema from
another env. Source: dev/test/staging/production. Target: dev/test/staging —
**production can never be a target**. Uses dedicated `pg.Client`s (never the
shared pools) because it sets session GUCs. (Replaces the old Test DB Refresh;
`#test-refresh` redirects here.)

**Safety model:**
- `x-tgt-env-label` must be in `DB_REFRESH_TARGET_ENVS` (`dev`/`test`/`staging`)
- Target host is refused outright if it's a production host
  (`DB_REFRESH_PROTECTED_HOSTS` = CNAME + raw RDS endpoint), AND must belong to
  the labelled env in `DB_REFRESH_ENV_HOSTS` — a label can't be spoofed onto
  another env's host. Unknown hosts fail.
- Source host must be a known env, and source env ≠ target env
- `run` additionally requires `x-allow-destructive: yes` + body
  `confirmation === 'REFRESH <TARGET ENV>'` (e.g. `REFRESH STAGING`)
- The source session is opened with `default_transaction_read_only = on` and
  the whole read happens inside a `REPEATABLE READ READ ONLY` transaction —
  even a code bug cannot write to the source env.
- All guards live in `drAssertSafeTarget()` in `routes/db-refresh.js`, called by both
  endpoints.

**Skip list (`DB_REFRESH_SKIP_TABLES`)** — Serverpod log/telemetry tables
(`serverpod_log`, `serverpod_session_log`, `serverpod_query_log`,
`serverpod_message_log`, `serverpod_health_*`, `serverpod_readwrite_test`).
They ARE truncated on the target but NOT refilled (prod logs are huge and useless on
the target — `serverpod_readwrite_test` alone had 4.2M rows on dev).

**Schema drift** — preflight and run both diff table sets and per-table
columns/types (skip tables excluded). Column drift on shared tables refuses the
copy (migrate the target first), except lossless widenings in
`DB_REFRESH_SAFE_WIDENINGS` (e.g. int4→int8 — older envs have int4 ids, fresh
DBs int8). Tables on only one side don't block: source-only ones are not copied
(e.g. hand-made `channel` on staging), target-only ones are emptied. `serverpod_migrations` IS copied, so after a refresh
the target's migration registry mirrors the source.

**Copy algorithm** (`POST /api/db-refresh/run`): one transaction on target →
`SET LOCAL session_replication_role = replica` (verified via `SHOW`; aborts
pre-wipe if unavailable — preflight probes this too) → single
`TRUNCATE <all tables> RESTART IDENTITY CASCADE` → per-table cursor streaming
(`FETCH 1000`, chunked multi-row INSERTs under the 65535-param limit,
`bindValue()` for json/jsonb, `id`s preserved) → `setval` per id-table →
COMMIT. Any error or client disconnect rolls the whole thing back, so the target
reverts to its pre-run state.

**Progress protocol** — the run endpoint streams NDJSON events
(`start`/`table`/`done`/`error`) on the POST response. HTTP 200 is committed
before the copy runs, so the frontend treats a stream that ends without `done`
as failure.

**Frontend** — source and target dropdowns (target: dev/test/staging only;
the same env can't be picked on both sides). Step 1 preflight gates Step 2
(typed `REFRESH <TARGET>` confirmation). Needs the matching `DB_*_PASSWORD`s
in `.env`.
## Build & Release feature (`/api/release/*`, view `#release`)

Builds the two Flutter apps in `../apps-frontend/apps` (override with
`LC_APPS_DIR`) and ships web builds. Config lives in `RL_APPS` / `RL_ENVS` in
`routes/release.js`:

| App key | Folder | Web test bucket → CF dist | Web prod bucket → CF dist |
|---|---|---|---|
| `praxis` | `lillian_care_praxis_app` | `lillian-care-praxis-test` → `E212FAFCAG5Y7B` | `lillian-care-praxis-prod` → `E2HT4R4XMWOKKS` |
| `app` | `lillian_care_app` | `lillian-care-app-test` → `E1CDAZB8YO8U4C` | `lillian-care-app-prod` → `EOIX3XODFOSC1` |

(`lillian-care-app-test-v2` / `app-test.lillian.care` exists but is deliberately
not a deploy target.) Envs: `test` = flavor `atest` + `lib/main_atest.dart`,
`prod` = flavor `prod` + `lib/main_prod.dart`.

**Build** — every build runs in the app folder with the Flutter SDK pinned
by the **workspace root** `apps-frontend/.fvmrc`, invoked directly from
`~/fvm/versions/<ver>/bin/flutter` (both apps share one pub workspace, so an app
folder's own `.fvmrc` — praxis pins an older SDK — is ignored): `flutter clean` → `flutter pub get` → one of
`flutter build web --release -t …` / `flutter build apk|appbundle --release --flavor … -t …`
(APK or AAB picked per build) / `flutter build ipa --flavor … -t …` (default
App Store export). Mobile outputs are revealed in Finder (`open -R`).
`RL_ENV` adds `LANG` (CocoaPods needs UTF-8; launchd doesn't set it).

**Deploy (web only, separate step)** — `aws s3 sync build/web/ s3://<bucket> --delete --exclude "index.html"`
(index.html is never uploaded) → `aws cloudfront create-invalidation --paths "/*"`.
The server only deploys a `build/web` it built itself for the SAME env
(recorded in `.release/state.json`, gitignored; cleared when any build of that
app starts, since `flutter clean` wipes `build/`). Prod requires body
`confirmation === 'DEPLOY <APP KEY> PROD'` (`DEPLOY PRAXIS PROD` / `DEPLOY APP PROD`).

**Jobs** — one at a time (shared pub workspace + `flutter clean`), held in
memory with the log (lost on helper restart). Children spawn `detached` so
Cancel kills the whole process group. The view polls `/api/release/status?since=<logEnd>`
every 1.5 s and posts a native `notify` when a job finishes.

## Investigations feature (`/api/investigations/*`, view `#investigations`)

AI-assisted prod investigations. Notes are markdown files in the **shared folder**
`../investigations/` (override with `LC_INVESTIGATIONS_DIR`) — the same files
Claude Code sessions read, so an investigation can move between the helper and
a Claude Code session. Playbooks (`../investigations/playbooks/*.md`) are fed to
the AI as context.

**Flow** — the user describes the problem or pastes logs → text is scrubbed →
Bedrock (`INV_MODEL`, override with `LC_INVESTIGATION_MODEL`) replies via a forced
`reply` tool: `message`, optional `proposed_sql` + `purpose`, optional `log_entry`
→ the user reviews/edits the SQL and clicks Run → rows are shown raw in the UI,
scrubbed, appended to the chat → the AI is asked for the next step automatically.
"Add to log" appends a finding to the note's `## Log` section.

**Scrubbing** — single source is the offline tool
`../investigations/tools/principa-log-scrubber.html`; `invCreateScrubber()` loads
the code between `// CORE-START` and `// CORE-END` (reloaded on file change). Edit
the scrubber there, not here. Placeholders are stable per investigation: the
mapping is persisted and seeds every scrub, and known names/emails are also
replaced when they reappear in free text. The AI may write placeholders inside SQL
literals; `invUnscrubSql()` fills in the real values locally (quotes doubled)
right before execution.

**Read-only guard (`invReadOnlyQuery`)** — never use the Query Runner path for
AI-proposed SQL. Queries run as `SELECT * FROM (<sql>) LIMIT 201` via the extended
protocol (`queryMode: 'extended'` — Postgres rejects multiple commands) inside
`BEGIN TRANSACTION READ ONLY` with `statement_timeout` 20 s, always rolled back.
Verified to reject DELETE, data-modifying CTEs, COMMIT escapes, multi-statements,
`set_config(transaction_read_only)` and `nextval()`.

**Local state** — `.investigations-state/<file>.json` (gitignored, 0600) holds the
placeholder→original mapping (PII), extra redaction terms (PII) and the scrubbed
AI conversation. Raw query rows are never persisted (browser memory only). The
markdown notes must not contain PII — internal IDs only.

**Code analysis (`POST/GET/DELETE /api/investigations/:file/code`)** — spawns a
headless Claude Code session (`INV_CLAUDE_BIN`, default `~/.local/bin/claude`,
override `LC_CLAUDE_BIN`) in `../LillianCare-Core` (override `LC_CORE_DIR`) with
`--restricted --tools Read,Grep,Glob --strict-mcp-config --permission-mode dontAsk
--no-session-persistence` and a `--settings` deny list for `passwords.yaml`, `.env*`,
the FCM key and key files (verified: Read is refused, Grep skips the file). The
prompt holds only the scrubbed notes and the scrubbed question. The briefing is
appended under `## Code analysis` in the note (inserted before `## Log`), so the
Bedrock chat sees it as context. One in-memory job per investigation (lost on
restart), `stream-json` progress, 10 min timeout, process group killed on cancel.
The first message of a new investigation runs it first (checkbox, on by default).

**Correspondence (`POST /api/investigations/:file/correspondence`)** — vendor or
practice replies (and what we sent) are scrubbed, filed under `## Correspondence`
in the note, and added to the chat before the AI is asked for the next step.

**Scrub preview (`POST /api/investigations/:file/scrub-preview`)** — scrubs without
saving the mapping. The composer shows it before sending (toggle, stored in
`localStorage.inv_preview`, default on) so names in free text that the scrubber
could not recognise can be caught. The scrubber also redacts names after titles
and greetings (Frau/Herr/Dr./Hallo …) and logins after "user"/"Benutzer", but keeps
technical actors such as SYSTEM, which are evidence.

## Lilli ops CLI (`scripts/lilli.js`) and view (`/api/lilli/*`, view `#lilli`)

Command-line access to Lilli staging (Ubuntu box `ubuntu@3.70.67.24`, PM2 `lilli-staging` + `lilli-ws`,
served at voice-staging.lillian.care and tools.lillian.care under `/lilli-staging`). Run
`node scripts/lilli.js help`. Commands: `status`, `logs`, `calls`, `call <id>`, `sql`, `deploy`, `rollback`,
`releases`. Built for Claude Code sessions: use it instead of raw ssh/psql.

- **Everything printed is scrubbed.** Lilli-specific rules in `LINE_RULES` drop survey answers, caller
  speech and booking payload values (Lilli logs them from `server/ws-server.ts`), then the shared
  scrubber (`../investigations/tools/principa-log-scrubber.html`) tokenises phones/emails/names. When
  Lilli adds a `console.*` line that prints answers or speech, add a rule. SQL output drops
  `transcript`, `structuredSummary`, `userMessage`, `assistantSnapshot`, and shows only the keys of `answers`.
  The placeholder mapping lives in `.lilli-state/` (gitignored, 0600).
- **DB access** goes through an SSH tunnel via the box (the RDS is in private subnets) with
  `LILLI_DB_STAGING_PASSWORD` from `.env`, in the same READ ONLY / extended-protocol / timeout / row-cap
  guard as `invReadOnlyQuery`.
- **Deploys** pipe `scripts/lilli-deploy-remote.sh` over ssh: build `git archive <sha>` into
  `/opt/lilli-deploy/releases/<sha7>/` (own `node_modules` and `.next`, `.env` symlinked from
  `/opt/lilli-deploy/shared/app.env`), switch the `/opt/lilli-deploy/current` symlink, restart PM2 (with `--time`), health-check,
  and switch back on failure. The live release is never touched by a build. The deploy refuses when
  `prisma/schema.prisma` changed unless `--schema-ok` (the DB is shared by all releases, so apply schema
  changes first). The ref must be pushed to GitHub, because the box fetches from origin.
- **One module, two front ends.** `scripts/lilli.js` exports the data functions (`statusData`,
  `callsData`, `callData`, `logsData`, `releasesData`, `deployPlan`, `runRemote`), and runs as a CLI when
  executed directly. `routes/lilli.js` wraps them in `/api/lilli/*`, and the `#lilli` view (Calls, Logs,
  Deploy tabs) renders them. Add new Lilli features to the module first, so the CLI and the UI stay in step.
  SSH calls are async and the tunnel/pool is reused across requests. PM2's process list is reduced to
  safe fields on the box, because `pm2 jlist` includes each process's environment (secrets).
- **Deploy/rollback from the UI** run one in-memory job at a time (lost on helper restart), polled via
  `/api/lilli/job?since=`. `POST /api/lilli/deploy` takes the full sha from the plan the user reviewed and
  re-checks it's on GitHub and whether the schema changed.
- **Investigate tab (`/api/lilli/inv/*`).** A question starts a headless Claude Code session in `../Lilli`
  (`LILLI_REPO`) with `--restricted` (file tools confined to the Lilli repo, so `.env` and the scrub mappings
  here are out of reach), `--tools Read,Grep,Glob,Bash`, `--permission-mode dontAsk`, and `LILLI_INV_SETTINGS`,
  which allows Bash only for the read-only `lilli.js` commands and read-only git. Deploy/rollback are denied, and so
  is every other command. Don't add `grep`/`cat`/`cut` to the allow list: they could read files outside the repo. The
  question is scrubbed first. The answer (Summary / Evidence / Root cause / Fix brief / Open questions) is appended to
  `## Findings` in `../investigations/YYYY-MM-DD-lilli-*.md`. Follow-ups `--resume` the saved session id
  (`.investigations-state/<file>.json` → `lilliSessionId`). "Copy fix brief" hands the latest brief to a Claude Code session.

## API Console (`/api/console/*`, view `#api-console`)

Postman-like console for every Serverpod endpoint method, the external services the
backend calls, and the webhooks other systems call into the backend. Requests are sent by the
helper server (`routes/api-console.js`), never the browser, so credentials stay server-side.

- **Catalog** (`lib/api-console/catalog.js`) is parsed live from LillianCare-Core and is
  rebuilt when `endpoints.dart` or `client.dart` change: endpoints/methods/param types from
  `lib/src/generated/endpoints.dart` (+ the `serverpod_auth*` modules in `~/.pub-cache`),
  `requireLogin` and `///` docs from the endpoint sources, return types from the generated
  client, model fields / enum serialization from `*.spy.yaml` and the freezed `Api*` classes
  in `../LillianCare-Shared-Models`, and the public API/web URL per env from `config/<mode>.yaml`.
  Body skeletons are generated from the param types (enums: index or name as serialized).
  Wire format: `POST {{coreApi}}/<endpoint>/<method>`, JSON object keyed by param name.
  The one streaming method (`questionnaire.listenForQuestionnaires`) is listed but disabled.
- **External templates** (`lib/api-console/externals.js`) mirror each call site in Core
  (Principa FHIR + REST, Personio, Brevo, FCM, Google Maps, feiertage-api) plus the inbound
  webhooks (`/fhir/*`, `/aivo/*`, `/incoming/lilli/*`, Fonio, Unify, `/api/public/*`).
  When the backend adds or changes an outbound call, update the template here. `effect`
  (`read` / `write` / `sends`) drives the warnings in the UI.
- **Auth** (`lib/api-console/auth.js`): LillianCare login (email/password accounts →
  `/emailIdp/login` → Bearer session token, cached, re-login on 401), Principa JWT
  (`lib/pms.js`, shared with `routes/pms.js`), Personio (token rotation via the `authorization`
  response header, shared cache in `lib/personio.js`), Google service account (FCM), Brevo,
  Maps key, `X-Lilli-Secret`, core `api-key`, plus generic bearer/basic/header. Secrets come from
  `.env` (see `.env.example`: `BREVO_API_KEY`, `GOOGLE_MAPS_API_KEY`, `LILLI_SSO_SECRET_<ENV>`,
  `LC_API_KEY_<ENV>`, optional `PMS_BASE_URL_TEST`). Every secret added is masked (‹label›) in
  the trace and the echoed request. **A service's credentials are only attached when the URL
  points at that service for the selected env** (`assertCredentialTarget`).
- **Production guard**: on `production`, anything but GET/HEAD — and every Serverpod call —
  returns 428 unless `body.confirm === 'production'`; the UI asks for it each time.
- **Variables**: `{{name}}` in URL/headers/body. Precedence: dynamic (`{{$isoTimestamp}}`,
  `{{$guid}}`, `{{$date}}`, `{{$datePlus7}}`, …) < built-in base URLs (`coreApi`, `coreWeb`,
  `principaFhir`, `principaRest`, `personio`, `brevo`, `fcm`, `maps`, `holidays`) < global < env.
  Unresolved variables refuse the send.
- **State** in `.api-console/` (gitignored, 0700/0600): `accounts.json` (passwords never go back to
  the browser), `history.json` (requests only — **responses are never persisted**, they can hold
  patient data), `collections.json`, `vars.json`. Binary responses are kept in memory (last 20)
  for `/api/console/download/:id`.
- **Frontend**: `public/js/views/api-console*.js` (state/send, sidebar, request editor, response,
  modals, Postman import/export + curl) and `public/css/api-console.css`. Postman v2.1 collections
  and environments import/export; the helper's own auth types are kept in an `lcHelper` field.
  "Copy as curl" puts credentials in as `$PLACEHOLDERS`.
- `/api/console` has a 30 MB JSON body limit (Serverpod's `maxRequestSize`); other routes keep 100 kB.
