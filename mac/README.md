# LC Helper for macOS

A native shell around the local helper tool (`http://localhost:3333`): a window hosting the SPA in a WKWebView, and a menu bar item that shows server and Serverpod status.

## Install

```bash
./mac/install.sh
```

The script:
1. Runs `build.sh`, which compiles the Swift package, builds the `.app` bundle with its icon, ad-hoc signs it and copies it to `~/Applications/LC Helper.app`.
2. Reads your `PATH` and `node` from `zsh -il`, then appends Docker's CLI dir and `/opt/homebrew/bin` to that `PATH`.
3. Installs `~/Library/LaunchAgents/care.lillian.helper.server.plist` and loads it with `launchctl bootstrap`.

If something else is already listening on :3333, such as a `node server.js` you started by hand, the script tells you and waits for you to stop it. It never kills that process for you.

You can re-run the script whenever you like. It updates the app and the LaunchAgent in place.

Re-run `install.sh` in two cases: after you switch Node versions with nvm, because the node path is written into the plist, and after you change your shell `PATH`.

## What runs where

| Piece | How it runs | Notes |
|---|---|---|
| `node server.js` | LaunchAgent `care.lillian.helper.server` (`RunAtLoad` + `KeepAlive`), cwd = `helper/` | Runs whether or not the app is open. It restarts itself if it crashes (with a 5 s throttle). |
| `LC Helper.app` | Normal app in `~/Applications` | UI only. **Quit** closes the app and leaves the server running. |
| Serverpod + Docker | Managed by the helper server (`/api/local-stack/*`) | You can control them from the menu bar item or from the **Local Stack** page (⌘5). |

The app shows a Dock icon only while a window is open. Closing the last window leaves just the menu bar item. **Launch at Login** is in the menu bar item. When the app starts at login, it opens no window.

## Logs

- Helper server: `~/Library/Logs/LCHelper/server.log` (menu bar ▸ Show Server Log, which opens it in Console)
- Serverpod: menu bar ▸ Show Serverpod Log, which opens the `#local-stack` page
- Web Inspector: Safari ▸ Develop ▸ *your Mac* ▸ LC Helper

## After changes

| You changed | Do this |
|---|---|
| `public/*.html` (web UI) | Nothing to rebuild. Reload with ⌘R, or ⇧⌘R to bypass the cache. |
| `server.js` | Menu bar ▸ **Restart Helper Server** (`launchctl kickstart -k gui/$UID/care.lillian.helper.server`) |
| `mac/Sources/**` (the app) | `./mac/build.sh`, then quit and reopen the app |
| Node version / PATH | `./mac/install.sh` |

## Uninstall

```bash
./mac/uninstall.sh
```

It asks for confirmation (y/N), then unloads and deletes the LaunchAgent, quits the app and removes it. Logs are kept.

## Page ↔ native bridge

When the page runs inside the app, it gets:
- `document.documentElement.dataset.shell === 'mac'`
- `window.__LC_SHELL__ = { platform: 'mac', version }`
- `window.lcNative.post(type, payload)`. Supported types:
  - `drag`: move the window
  - `zoom`: zoom the window
  - `notify {title, body}`: post a system notification
  - `setEnv {env}`: when `env` is `production`, the window gets a red top strip, the Dock icon a `PROD` badge and the menu bar dot a red ring
- Elements marked `[data-drag-region]` move the window when dragged and zoom it on double-click. This excludes buttons, links, form fields and anything marked `[data-no-drag]`.
