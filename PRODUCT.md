# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

(Web UI rendered inside a native macOS shell — `mac/` — using WKWebView. The
web UI also keeps working in a normal browser at `http://localhost:3333`.)

## Users

One person: the LillianCare backend/infra engineer who built it. Expert user,
keyboard-first, runs it all day on their own Mac.

## Product Purpose

A local-only control room for the LillianCare healthcare platform: inspect and
debug the Serverpod backend across dev / test / staging / production, look up
production data for support questions, run guarded environment operations, and
keep the local Serverpod dev stack running.

Success: the engineer reaches the right log, row or metric in seconds, and
never runs something against the wrong environment by accident.

## Operating Context

Priority jobs (confirmed):
1. **Incident debugging** — Monitor (AWS metrics, live CloudWatch logs via SSE,
   errors, alarms), Session Logs, Server Health.
2. **Data lookup** — Users, Bookings, Query Runner, AI Assistant (Bedrock).
3. **Local dev stack** — Serverpod (`LillianCare-Core/lillian_care_core_server`)
   plus its Docker Postgres (8090) and Redis (8091).

Secondary: Praxis Refresh/Cleanup, Cockpit Fill/Sync, Test DB Refresh, RDS
Restore, Send Notification, Future Calls, API Keys, CSV Decryptor, Google
Business, Personio Audit, SSH Tunnels, Admin Audit, Notifications, Message
Outbox, Analytics.

Environment is switched from one global DB connection (Dev / Test / Staging /
Production presets).

## Capabilities and Constraints

- Local-only; never exposed to the internet. Express on `localhost:3333`.
- Plain files, no build step, no framework: `server.js`, `public/index.html`
  (shell) + `public/css/`, `public/js/core/`, `public/js/views/` (one file per view),
  `public/monitoring.html`, `public/tools/*.html`.
- Secrets in `.env` / `.fcm_service_account.json` must never be read by tools.
- Destructive endpoints have server-side typed-confirmation gates; the UI must
  keep surfacing them.
- Timestamps shown in Europe/Berlin.

## Brand Commitments

The UI must follow the LillianCare corporate identity as implemented in
`apps-frontend/packages/design_system` (colors.dart, fonts.dart, borders.dart):
petrol `#004E64` primary, logo turquoise, Manrope, white surfaces, 8px corners, and
the LillianCare logo. (User direction, 2026-09-23: the earlier rail-board look was
rejected because it did not fit the brand.)

## Product Principles

1. **Environment is never ambiguous.** Production must be unmistakable in the
   whole window, not only in a badge.
2. **Speed to signal.** Debugging and lookup views come first; dense, scannable
   data over decoration.
3. **Native where it counts.** Behaves like a Mac app: shortcuts, dialogs,
   downloads, menu bar status, always-on.
4. **Nothing lost.** Redesigns never remove a working function or guard.
