---
version: 1
slug: "public-index-html"
primary_target: "public/index.html"
related_targets: ["public/monitoring.html","public/tools/decrypt_viewer.html","public/tools/aws_rds_restore.html"]
---

# LC Helper — app shell and all views

Scope: public/index.html (shell + all views), public/monitoring.html, public/tools/*.html, and the native mac shell chrome. Mode: Operate.
Audience/job: one expert engineer; incident debugging, data lookup, local dev stack first. Must keep every function and every destructive guard.

## Direction contract

THESIS: Everything here is a timed event, so every view reads as a station departures board: time first (bold, tabular), then what happened (the "destination"), then where (a boxed "platform" column). It refuses the neon-on-black sci-fi dashboard and the grey SaaS admin.

OWN-WORLD: Night mode is the DB platform display: navy ground #0a1633, white ink, one yellow #ffd400 for change/selection/primary action, red #ff4d5e for disruption and production, green #3ddc84 for on-time/healthy. Day mode is the printed white timetable poster with navy ink; its primary action is navy (yellow-on-white fails contrast), yellow stays for selection/active plates. Blue marks the test environment and information (cited exception to the four-signal rule: it is the info colour). Signage face: Barlow Semi Condensed, self-hosted (the craft floor forbids a system display face; a DIN-like condensed grotesk is the rail-signage stand-in for DB Type). Body: system sans (SF Pro); data: SF Mono. Square-cornered plates, hairline rules, no glow, no gradients, no scanlines. Greys never carry meaning; only four signal colours do.

STORY: Glance at the header plate to know the environment (1 dev · 2 test · 3 staging · 4 PROD). Read the board to find the row. Act with the yellow control. Production turns the whole header into a red disruption band.

FIRST VIEWPORT: 48px platform-display header across the full width: environment number plate (34px square numeral, sized to the 48px band) + env name + host, a status ticker (local stack state), the big station clock HH:MM (seconds small) at right with the ⌘K field. Left: wayfinding rail (sidebar) with pictogram squares, active item = yellow plate. Main: board-style view header (large title, left-aligned, count at right) over a timetable table.

FORM: German rail passenger-information system (Abfahrt/Zugzielanzeiger), assigned candidate 6 of 7; seed key 0126fd32 (printed by `impeccable concept-seed --scope direction --mode operate`; choice recorded with --kind assigned --from 0126fd32). Raises: stepped two-frame motion, no easing (acetate manual); greys never carry meaning (datamatics); destructive zones as red disruption bands (leather studio); one ruled label grid for entities (sneaker wall). Signature interaction: env switch flips the header plate like a split-flap/LED refresh in two steps; prod turns the band red.

FINISH: unreviewed and undocumented is unfinished; this build ends with the finish review, the verdict, DESIGN.md, and every shipping raster carrying its provenance
