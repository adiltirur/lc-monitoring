---
name: LC Helper
description: Local-only debugging and operations console for the LillianCare platform, dressed in the LillianCare corporate identity.
colors:
  petrol: "#004e64"
  petrol-hover: "#00667f"
  turquoise: "#2bd2c9"
  turquoise-light: "#b0efec"
  turquoise-wash: "#e6fffd"
  highlight: "#dbedf1"
  ground: "#f7f9f9"
  surface: "#ffffff"
  surface-sunk: "#f0f7f9"
  surface-deep: "#e6edf0"
  ink: "#00212a"
  ink-2: "#384048"
  ink-3: "#60666d"
  ink-4: "#a3a7ab"
  rule: "#e6edf0"
  rule-strong: "#d5d4dc"
  band: "#b53535"
  red: "#e84444"
  red-soft: "#fff0f0"
  amber: "#f39b1f"
  amber-ink: "#da8201"
  amber-soft: "#fff8e8"
  green: "#008a05"
  green-soft: "#e6f3e6"
  blue: "#096fdd"
  blue-soft: "#e8f1fc"
  plate-test: "#6fb1ff"
  plate-staging: "#fdb440"
  night-ground: "#00212a"
  night-surface: "#002b37"
  night-surface-2: "#003340"
  night-surface-3: "#003f4f"
  night-surface-4: "#0b5266"
  night-highlight: "#0b4a5b"
  night-ink: "#f2fffe"
  night-ink-2: "#b8ccd2"
  night-ink-3: "#8aaeb8"
  night-ink-4: "#4f7c89"
  night-red: "#ff6f6f"
  night-amber: "#fdb440"
  night-green: "#4cc76a"
  night-blue: "#6fb1ff"
typography:
  board:
    fontFamily: "Manrope, -apple-system, BlinkMacSystemFont, system-ui, sans-serif"
    fontSize: "26px"
    fontWeight: 800
    lineHeight: 1.15
    letterSpacing: "-0.01em"
  title:
    fontFamily: "Manrope, -apple-system, BlinkMacSystemFont, system-ui, sans-serif"
    fontSize: "14.5px"
    fontWeight: 700
    lineHeight: 1.2
    letterSpacing: "0.01em"
  body:
    fontFamily: "Manrope, -apple-system, BlinkMacSystemFont, system-ui, sans-serif"
    fontSize: "13px"
    fontWeight: 400
    lineHeight: 1.5
    letterSpacing: "0.01em"
    fontFeature: "\"tnum\" 1"
  data:
    fontFamily: "Manrope, -apple-system, BlinkMacSystemFont, system-ui, sans-serif"
    fontSize: "12.5px"
    fontWeight: 400
    lineHeight: 1.5
    fontFeature: "\"tnum\" 1"
  label:
    fontFamily: "Manrope, -apple-system, BlinkMacSystemFont, system-ui, sans-serif"
    fontSize: "12px"
    fontWeight: 700
    lineHeight: 1.2
    letterSpacing: "0.01em"
  mono:
    fontFamily: "ui-monospace, SF Mono, SFMono-Regular, Menlo, monospace"
    fontSize: "12px"
    fontWeight: 400
    lineHeight: 1.55
rounded:
  xs: "4px"
  sm: "6px"
  md: "8px"
  lg: "12px"
  full: "999px"
spacing:
  s-1: "4px"
  s-2: "8px"
  s-3: "12px"
  s-4: "16px"
  s-5: "20px"
  s-6: "24px"
  s-8: "32px"
  s-10: "40px"
  s-12: "48px"
components:
  topbar:
    backgroundColor: "{colors.petrol}"
    textColor: "{colors.surface}"
    height: "48px"
  topbar-production:
    backgroundColor: "{colors.band}"
    textColor: "{colors.surface}"
  env-plate-dev:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.petrol}"
    rounded: "{rounded.md}"
    size: "32px"
  env-plate-test:
    backgroundColor: "{colors.plate-test}"
    textColor: "{colors.ink}"
    rounded: "{rounded.md}"
    size: "32px"
  env-plate-staging:
    backgroundColor: "{colors.plate-staging}"
    textColor: "{colors.ink}"
    rounded: "{rounded.md}"
    size: "32px"
  env-plate-production:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.band}"
    rounded: "{rounded.md}"
    size: "32px"
  nav-item:
    textColor: "{colors.ink-2}"
    rounded: "{rounded.md}"
    height: "30px"
    padding: "0 10px 0 6px"
  nav-item-active:
    backgroundColor: "{colors.highlight}"
    textColor: "{colors.petrol}"
    rounded: "{rounded.md}"
  button-primary:
    backgroundColor: "{colors.petrol}"
    textColor: "{colors.surface}"
    typography: "{typography.data}"
    rounded: "{rounded.md}"
    height: "32px"
    padding: "0 14px"
  button-primary-hover:
    backgroundColor: "{colors.petrol-hover}"
  button-secondary:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.ink}"
    rounded: "{rounded.md}"
    height: "32px"
    padding: "0 14px"
  button-secondary-hover:
    backgroundColor: "{colors.surface-sunk}"
  button-danger:
    textColor: "{colors.red}"
    rounded: "{rounded.md}"
    height: "32px"
    padding: "0 14px"
  button-danger-hover:
    backgroundColor: "{colors.band}"
    textColor: "{colors.surface}"
  input:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.ink}"
    typography: "{typography.data}"
    rounded: "{rounded.md}"
    height: "34px"
    padding: "0 12px"
  panel:
    backgroundColor: "{colors.surface}"
    rounded: "{rounded.md}"
  band:
    backgroundColor: "{colors.band}"
    textColor: "{colors.surface}"
    padding: "8px 16px"
  pill-ok:
    backgroundColor: "{colors.green-soft}"
    textColor: "{colors.green}"
    rounded: "{rounded.full}"
    height: "22px"
    padding: "0 9px"
  pill-err:
    backgroundColor: "{colors.red-soft}"
    textColor: "{colors.red}"
    rounded: "{rounded.full}"
    height: "22px"
    padding: "0 9px"
  pill-plate-err:
    backgroundColor: "{colors.band}"
    textColor: "{colors.surface}"
    rounded: "{rounded.full}"
    height: "22px"
  table-header:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.ink-3}"
    typography: "{typography.label}"
  table-row:
    textColor: "{colors.ink-2}"
    height: "32px"
    padding: "0 12px"
  toast:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.ink}"
    rounded: "{rounded.md}"
    padding: "10px 14px"
  command-palette:
    backgroundColor: "{colors.surface}"
    rounded: "{rounded.lg}"
    width: "620px"
---

# Design System: LC Helper

## Overview

**Creative North Star: "The Petrol Console"**

LC Helper is an internal tool that wears the LillianCare corporate identity rather than inventing its own. The source of truth is the Flutter design system (`apps-frontend/packages/design_system`: colors.dart, fonts.dart, borders.dart): petrol primary, the turquoise of the logo, Manrope, white grounds and 8px corners. The helper takes that identity and makes it dense. It is a debugging console first, so the palette serves state and scanning, not decoration.

Day is the brand: a near-white ground, white panels, a petrol header carrying the white LillianCare logo. Night is a deep-petrol variant for late incidents, where petrol becomes the ground and turquoise takes over as the action colour. Both themes come from one generated token file (`public/theme.css`, written by `scripts/gen-theme.js`) shared by the shell, the monitoring iframe, and every tool page, so the app and its iframes always match.

Production must be unmistakable in the whole window: when the connection points at prod, the entire header turns into a red band. That is the one place the system gets loud.

**Key Characteristics:**
- Petrol header with white logo; white panels on a near-white ground (Day), petrol layers (Night).
- Numbered environment plates 1–4 (Dev, Test, Staging, Prod); production recolours the whole header red.
- Dense board-style tables with sticky headers, 32px rows, tabular figures.
- Flat panels with a hairline border and a barely-there card shadow; shadows only on floating layers.
- One radius family: 8px everywhere, 12px for floating sheets, full pills for status.
- Signal colours (red, amber, green, blue) carry state; greys never do.

## Colors

A restrained corporate palette: petrol and white carry the identity, turquoise marks the brand and Night action, and four signal colours carry state.

### Primary
- **LillianCare Petrol** (petrol): the header, primary buttons, the active nav item's text, active tab underline, focus ring and checkbox tint in Day. Hover deepens-by-lightening to **Petrol Hover** (petrol-hover), the design system's `filledHover`.

### Secondary
- **Logo Turquoise** (turquoise): the logo mark, healthy LEDs in the header ticker, and in Night the action colour itself (primary buttons, focus, active states) with ink-dark text on top. **Turquoise Light** (turquoise-light) is the text-selection colour; **Turquoise Wash** (turquoise-wash) is the soft accent surface.
- **Petrol Highlight** (highlight): the design system's `primaryHighlightAreaColor`. Active nav item, focused palette row, active table row, the preset chip that is "on", and the boxed port/where cells on boards.

### Signal
- **Disruption Red** (band): the production header, destructive bands, danger-button hover, `plate-err` pills and fatal log lines. Darker than the DS error red so white text on it stays legible.
- **Error Red** (red) / **Success Green** (green) / **Warning Amber** (amber, text as amber-ink) / **Info Blue** (blue), each paired with a `-soft` tint for pill and row backgrounds. In Night each brightens (night-red, night-green, night-amber, night-blue) and the soft tints become 14–15% alpha washes.
- **Plate Blue / Plate Amber** (plate-test, plate-staging): only the Test and Staging environment plates.

### Neutral
- **Ground** (ground): app background behind panels. **Surface** (surface): panels, inputs, toasts, sidebar. **Sunk** (surface-sunk): hover rows and hover buttons. **Deep** (surface-deep): segmented-control track, scrollbar thumb.
- **Ink ramp** (ink, ink-2, ink-3, ink-4): headings and first columns / body and table cells / labels, meta and placeholders / disabled dots. ink-2 is the DS `text` colour.
- **Rules** (rule, rule-strong): hairlines inside panels / panel headers, inputs, button borders. rule-strong is the DS `border` colour.
- **Night** layers: night-ground → night-surface → night-surface-2 → night-surface-3 → night-surface-4, each a step lighter petrol; ink becomes night-ink (the DS `secondary`, #F2FFFE).

### Named Rules
**The Brand Source Rule.** Every brand colour traces to `colors.dart`. New hex values go into `scripts/gen-theme.js` and are regenerated, never typed into a page.

**The Signal Rule.** Red, amber, green and blue mean error, warning, healthy and info. Nothing else uses them, and grey never signals state.

**The Whole-Window Production Rule.** Production is announced by the header band itself, not by a badge. Any new surface that can act on a database inherits this.

## Typography

**Display / Body / Label Font:** Manrope (with -apple-system, BlinkMacSystemFont, system-ui), self-hosted from `public/vendor/fonts`.
**Mono Font:** ui-monospace (SF Mono, Menlo) for hosts, ports, IDs, SQL, logs.

**Character:** One humanist-geometric sans, the brand's, doing all the work through weight: 800 for view titles, 700 for panel titles and labels, 400 for data. Tabular figures are on globally so times and counts line up in columns.

### Hierarchy
- **Board** (800, 26px, 1.15, -0.01em): the view title, once per view, above a strong rule.
- **Title** (700, 14.5px, 1.2): panel titles, env name in the header, band text (13–13.5px).
- **Body** (400, 13px, 1.5): default text, nav items.
- **Data** (400, 12.5px): table cells, buttons (600), inputs, subtitles.
- **Label** (700, 11.5–12px, 0.01–0.03em, sentence case): table headers, field labels, nav group labels, palette section labels.
- **Mono** (400, 11–12px): hosts, ports, kbd hints, code blocks, log streams.
- **Clock** (700, 22px): the header clock; seconds drop to 12px at 55% white.

Density modes rescale body/data: compact (12.5/12px, 26px rows) and comfortable (14/13px, 38px rows).

### Named Rules
**The Sentence-Case Rule.** Labels are sentence case in bold Manrope. No tracked uppercase micro-labels; the shell actively rewrites them in legacy views.

## Layout

A fixed app shell: a 48px header spanning the top, a 228px sidebar, and a scrolling main area. Views sit in a 1600px-max column padded 24px / 32px / 40px (top / sides / bottom). Each view opens with a header row (title + subtitle left, actions right) closed by a 1px strong rule, then stacks panels with 16–20px gaps. Spacing runs on a 4px base (4, 8, 12, 16, 20, 24, 32, 40, 48).

Navigation mode is a user setting: sidebar (default), topbar-only or palette-only, the latter two hiding the sidebar. In the Mac shell the sidebar goes 70% translucent and the brand block indents 84px for traffic lights. Below 1240px the header ticker collapses to LEDs only and the Jump-to field loses its label.

## Elevation & Depth

Flat by default, layered by tone. Panels sit on the ground with a hairline border and a near-invisible card shadow; in Night the card shadow is removed entirely and depth comes from lighter petrol layers. Only floating things lift: toasts, the command palette, the connection popover and the display-settings sheet.

### Shadow Vocabulary
- **Card** (`0 1px 2px rgba(0,33,42,.04), 0 1px 3px rgba(0,33,42,.06)`; Night: none): panels at rest.
- **Pop** (`0 16px 40px -12px rgba(0,33,42,.22), 0 2px 6px rgba(0,33,42,.06)`; Night: `0 22px 60px -10px rgba(0,0,0,.55), 0 2px 8px rgba(0,0,0,.3)`): floating layers only.

### Named Rules
**The Only-Floaters-Lift Rule.** A shadow above Card means the element floats over content. Buttons never carry shadows.

## Shapes

Gently rounded, one family: 8px (the DS `defaultRadius`) on panels, buttons, inputs, nav items, env plates and palette rows; 12px on floating sheets and empty-state icon tiles; 6px on small buttons, preset numerals and the boxed port cell; 4px on kbd keys; full pills for status and the "Helper" wordmark chip. Borders are 1px hairlines. Destructive panels get a 1px red border and a flat red band across the top corners.

## Components

### Header (petrol bar)
Petrol ground, white type. Left: the white LillianCare logo (20px tall) and a pill-outlined "Helper" chip. Then the environment button, a status ticker (LED + service + state), the Jump-to field (translucent white, 8px radius, ⌘K key), a display-settings icon button and the clock. In production the bar becomes Disruption Red, the ticker is replaced by "Production database. Every write is real." and the Jump-to field darkens.

### Environment plates
A 32px square, 8px radius, numeral in 800/20px Manrope: **1** Dev (white plate, petrol numeral), **2** Test (plate blue), **3** Staging (plate amber), **4** Prod (white plate, red numeral, on the red header). The same numbering and colours repeat in the connection popover's four preset chips. Switching plays a 260ms flip.

### Sidebar navigation
White (Night: petrol surface) with a right hairline. Grouped under sentence-case bold labels. Items are 30px, 8px radius, icon + label + optional mono shortcut hint. Hover: sunk surface. **Active: Petrol Highlight background, petrol text at 700, filled icon.** A footer lists server and time zone in mono.

### Board tables
The main data form. Sticky header in bold 12px ink-3 over a strong rule; 32px rows with hairline dividers; first column in ink at 600; numbers right-aligned; hover row goes sunk, the active row takes the highlight, error rows take red-soft. Where-columns (ports, hosts) use a boxed mono plate in highlight/petrol.

### Pills and LEDs
22px full pills in 600/11px: ok, warn (amber-700 text), err, info on their soft tints; ghost with an inset rule; `plate-err` (solid red, white) and `plate-warn` (solid amber, ink) for states that must shout. LEDs are 8px dots in the same signal colours; live ones blink on a 1.8s cycle.

### Destructive band
Destructive steps and panels sit under a Disruption Red strip (34px, white 700/13px text, top corners rounded) with a 1px red border around the section. Locked destructive steps dim only to 78% so the guard text stays readable. Danger actions are outline-red buttons that fill red on hover.

### Buttons
- **Shape:** 8px radius, 32px tall, 0 14px, 600/12.5px.
- **Primary:** petrol fill, white text, 700; hover petrol-hover. Night: turquoise fill with ink text; hover lighter turquoise.
- **Secondary:** white with a rule-strong border; hover sunk.
- **Ghost:** transparent, hover sunk. **Danger:** red text and 45% red border, fills Disruption Red on hover.
- **Sizes:** sm 26px / 6px radius, lg 34px. Disabled at 45% opacity. All transitions 140ms on the house curve.

### Inputs
34px, 8px radius, white (Night: surface-2) with a rule-strong border, 12.5px text, ink-3 placeholder. Focus: petrol border plus a 1px petrol ring (turquoise in Night). Host, port and credential fields use mono. Changed fields take amber-soft with an amber border.

### Toasts
Bottom-right stack, max 440px. White panel, rule-strong border, 8px radius, Pop shadow, 12.5px text with a leading icon; slides up 8px in 180ms.

### Command palette
⌘K opens a 620px sheet (12px radius, Pop shadow) 12vh from the top over a dimmed backdrop. 52px search field with a leading icon and Esc key, sectioned results in 36px rows; the focused row takes the highlight with petrol text and icon. Footer lists keys on a surface-2 strip.

### Tabs and switches
Tabs are 600/13px ink-3 labels; active tab is petrol with a 3px petrol underline. Switches are 32×18 pills, ink-4 off, petrol (Night turquoise) on.

## Do's and Don'ts

### Do:
- **Do** take every brand value from `public/theme.css`; add or change tokens only in `scripts/gen-theme.js` and regenerate.
- **Do** load `/theme.js` then `/theme.css` in every page and iframe so Day/Night/System follow the shell.
- **Do** keep the Tailwind bridge intact: Tailwind utility colours (`primary`, `surface`, `error`, `red-500`, `slate-*`…) resolve through `LC_TAILWIND_CONFIG` to `rgb(var(--rgb-*))` / `--tw-*` channel tokens, so legacy utility markup re-themes with the tokens. New Tailwind colour names must be mapped there, never hard-coded.
- **Do** put any database-writing step under the destructive band, and let production recolour the header.
- **Do** use mono for hosts, ports, IDs and logs, and Manrope for everything else.
- **Do** keep numbers tabular and right-aligned in tables.

### Don't:
- **Don't** reintroduce the rejected rail / departures-board world: no timetable-poster styling, platform signage, split-flap or station metaphors.
- **Don't** use gradients; the bridge flattens `bg-gradient-*` to none and petrol is always a solid fill.
- **Don't** use tracked uppercase micro-labels or eyebrows above titles.
- **Don't** add press-scale (`active:scale-*`) or lift-on-hover transforms to buttons.
- **Don't** use turquoise as a Day button fill or text colour on white; in Day it is the logo and LED colour only.
- **Don't** use signal colours decoratively, or show production with anything smaller than the whole header.
- **Don't** add radii outside 4 / 6 / 8 / 12 / full.
