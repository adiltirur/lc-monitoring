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

- **Backend:** Node.js + Express (`server.js` — single file, all routes, ~850 lines)
- **Frontend:** Vanilla HTML/CSS/JS SPA (`public/index.html` — single file, hash-based routing, ~1500 lines)
- **Monitoring:** Sci-fi dashboard (`public/monitoring.html` — loaded in iframe, SSE for real-time logs)
- **Database:** PostgreSQL via `pg` package (connects to Serverpod's RDS per environment)
- **AWS:** SDK v3 — EC2, RDS, CloudWatch, CloudWatch Logs, ALB, ElastiCache, S3, CloudFront, Bedrock
- **No build step, no TypeScript, no frontend framework** — keep it simple

## File Structure

```
helper/
  server.js                   — Express backend, all API routes
  package.json                — Dependencies (includes dotenv)
  .env                        — 🔒 NEVER READ — DB passwords + decrypt key
  .env.example                — Template (safe to read)
  .fcm_service_account.json   — 🔒 NEVER READ — Firebase private key
  .gitignore                  — Must always include .env and .fcm_service_account.json
  CLAUDE.md                   — This file
  public/
    index.html                — Main SPA (hash routing, sidebar navigation)
    monitoring.html           — AWS monitoring dashboard (iframe, sci-fi theme)
    tools/
      decrypt_viewer.html     — CSV bulk decryptor (iframe)
```

## Architecture & Key Patterns

**DB credentials flow:**
- Configured via the browser's top config panel (Dev / Staging / Prod presets)
- Passwords auto-filled from `.env` via `GET /api/env-config` on page load
- Credentials travel as HTTP request headers: `x-db-host`, `x-db-port`, `x-db-name`, `x-db-user`, `x-db-password`
- SSE endpoint (`/api/monitor/logs/stream`) uses query params instead (EventSource doesn't support custom headers)
- Pool management: `getPool(req)` in `server.js` creates/caches PG connection pools keyed by connection string

**Environment presets** (in `index.html` `PRESETS` constant):
- `dev` → `localhost:8090/lillian_care_core`
- `staging` → `database-staging.lillian.care:5432/serverpod`
- `production` → `database.lillian.care:5432/serverpod`

**Secret loading:**
- `require('dotenv').config()` at the top of `server.js` loads `.env`
- `GET /api/env-config` serves `{ passwords: { dev, staging, production }, decryptKeys: { dev, staging, production } }` to the frontend
- Frontend fetches this on load and uses it to auto-fill the password field when a preset is selected

**Navigation:** Hash-based routing via `navigate(view)`. Each view has a `renderXxx(el)` function. Add new views by: nav item in sidebar → route in `navigate()` → `renderXxx()` function.

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
- Keep single-file architecture — do not split server.js or index.html into modules

## Adding New Features

1. Add API route to `server.js` before the `// ─── Static files ───` section
2. Add sidebar nav item in `index.html` HTML under the relevant section
3. Add `else if (view === 'xxx') renderXxx(content);` in the `navigate()` function
4. Add `function renderXxx(el) { ... }` following existing patterns
5. For monitoring features: add to `monitoring.html` instead
