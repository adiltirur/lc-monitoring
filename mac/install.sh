#!/usr/bin/env bash
# Builds/installs "LC Helper.app" and (re)installs the LaunchAgent that keeps
# `node server.js` running on http://localhost:3333. Idempotent — re-run to update.
set -euo pipefail

MAC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HELPER_DIR="$(cd "$MAC_DIR/.." && pwd)"
LABEL="care.lillian.helper.server"
PLIST="$HOME/Library/LaunchAgents/$LABEL.plist"
LOG_DIR="$HOME/Library/Logs/LCHelper"
LOG_FILE="$LOG_DIR/server.log"
DOMAIN="gui/$UID"
PORT=3333

xml_escape() {
  local s="$1"
  s="${s//&/&amp;}"
  s="${s//</&lt;}"
  s="${s//>/&gt;}"
  s="${s//\"/&quot;}"
  printf '%s' "$s"
}

# Appends $2 to PATH-like string $1 unless already present.
path_append() {
  case ":$1:" in
    *":$2:"*) printf '%s' "$1" ;;
    *) printf '%s' "${1:+$1:}$2" ;;
  esac
}

job_pid() {
  launchctl print "$DOMAIN/$LABEL" 2>/dev/null | awk -F' = ' '/^[[:space:]]*pid = / { print $2; exit }'
}

# ─── 1. App bundle ──────────────────────────────────────────────────────────
"$MAC_DIR/build.sh"

# ─── 2. Resolve the user's PATH and node via an interactive login shell ────
echo "==> Resolving PATH and node from your login shell (zsh -il)"
USER_PATH="$(/bin/zsh -ilc 'echo $PATH' </dev/null 2>/dev/null | tail -n 1 || true)"
if [[ "$USER_PATH" != */* ]]; then
  echo "    warning: could not read PATH from zsh; falling back to a default PATH" >&2
  USER_PATH="/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
fi
AGENT_PATH="$(path_append "$USER_PATH" "/Applications/Docker.app/Contents/Resources/bin")"
AGENT_PATH="$(path_append "$AGENT_PATH" "/opt/homebrew/bin")"

NODE_BIN="$(/bin/zsh -ilc 'command -v node' </dev/null 2>/dev/null | tail -n 1 || true)"
if [[ -z "$NODE_BIN" || ! -x "$NODE_BIN" ]]; then
  NODE_BIN="$(PATH="$AGENT_PATH" command -v node || true)"
fi
if [[ -z "$NODE_BIN" || ! -x "$NODE_BIN" ]]; then
  echo "error: could not find 'node' in your login shell PATH." >&2
  exit 1
fi
echo "    node: $NODE_BIN ($("$NODE_BIN" --version))"
command -v aws >/dev/null 2>&1 || PATH="$AGENT_PATH" command -v aws >/dev/null 2>&1 \
  || echo "    warning: 'aws' CLI not found on PATH — SSM tunnels will not work." >&2

# ─── 3. Make sure :3333 is free (or owned by our job) ───────────────────────
while true; do
  OUR_PID="$(job_pid || true)"
  FOREIGN=()
  while IFS= read -r pid; do
    [[ -z "$pid" ]] && continue
    [[ "$pid" == "$OUR_PID" ]] && continue
    FOREIGN+=("$pid")
  done < <(lsof -nP -iTCP:$PORT -sTCP:LISTEN -t 2>/dev/null | sort -u)

  [[ ${#FOREIGN[@]} -eq 0 ]] && break

  echo
  echo "!! Port $PORT is already in use by a process that is NOT the $LABEL LaunchAgent:"
  ps -o pid=,command= -p "$(IFS=,; echo "${FOREIGN[*]}")" 2>/dev/null | sed 's/^/     /'
  echo "   Please stop it yourself (e.g. Ctrl-C the terminal running 'node server.js')."
  echo "   This script will not kill it for you."
  if [[ ! -t 0 ]]; then
    echo "error: not running interactively — stop the process above and re-run." >&2
    exit 1
  fi
  read -r -p "   Press Enter to re-check, or type q to abort: " answer
  [[ "$answer" == "q" || "$answer" == "Q" ]] && { echo "Aborted."; exit 1; }
done

# ─── 4. LaunchAgent plist ───────────────────────────────────────────────────
echo "==> Writing $PLIST"
mkdir -p "$LOG_DIR" "$(dirname "$PLIST")"
cat > "$PLIST" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>$LABEL</string>
  <key>ProgramArguments</key>
  <array>
    <string>$(xml_escape "$NODE_BIN")</string>
    <string>server.js</string>
  </array>
  <key>WorkingDirectory</key>
  <string>$(xml_escape "$HELPER_DIR")</string>
  <key>EnvironmentVariables</key>
  <dict>
    <key>PATH</key>
    <string>$(xml_escape "$AGENT_PATH")</string>
    <key>HOME</key>
    <string>$(xml_escape "$HOME")</string>
  </dict>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>ThrottleInterval</key>
  <integer>5</integer>
  <key>ProcessType</key>
  <string>Interactive</string>
  <key>StandardOutPath</key>
  <string>$(xml_escape "$LOG_FILE")</string>
  <key>StandardErrorPath</key>
  <string>$(xml_escape "$LOG_FILE")</string>
</dict>
</plist>
PLIST
plutil -lint "$PLIST"

# ─── 5. (Re)load the job ────────────────────────────────────────────────────
echo "==> Reloading LaunchAgent $LABEL"
launchctl bootout "$DOMAIN/$LABEL" 2>/dev/null || true
for _ in 1 2 3 4 5 6 7 8 9 10; do
  launchctl print "$DOMAIN/$LABEL" >/dev/null 2>&1 || break
  sleep 0.5
done

bootstrapped=0
for attempt in 1 2 3; do
  if launchctl bootstrap "$DOMAIN" "$PLIST"; then
    bootstrapped=1
    break
  fi
  echo "    bootstrap attempt $attempt failed; retrying…" >&2
  sleep 1
done
if [[ $bootstrapped -ne 1 ]]; then
  echo "error: launchctl bootstrap failed. See 'launchctl print $DOMAIN/$LABEL' and $LOG_FILE" >&2
  exit 1
fi

# ─── 6. Wait for the server ─────────────────────────────────────────────────
echo -n "==> Waiting for http://localhost:$PORT "
for _ in $(seq 1 30); do
  if curl -s -o /dev/null --max-time 1 "http://127.0.0.1:$PORT/"; then
    echo " up."
    echo
    echo "Installed. Open \"$HOME/Applications/LC Helper.app\" (or: open -a 'LC Helper')."
    echo "Server log: $LOG_FILE"
    exit 0
  fi
  echo -n "."
  sleep 1
done
echo
echo "warning: the server did not respond within 30s. Check $LOG_FILE" >&2
tail -n 20 "$LOG_FILE" 2>/dev/null | sed 's/^/    /' >&2 || true
exit 1
