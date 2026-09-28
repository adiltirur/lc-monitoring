#!/usr/bin/env bash
# Removes the helper-server LaunchAgent and "LC Helper.app". Logs are kept.
set -euo pipefail

LABEL="care.lillian.helper.server"
PLIST="$HOME/Library/LaunchAgents/$LABEL.plist"
APP="$HOME/Applications/LC Helper.app"
LOG_DIR="$HOME/Library/Logs/LCHelper"

echo "This will:"
echo "  - stop and unload the LaunchAgent $LABEL (the helper server on :3333)"
echo "  - delete $PLIST"
echo "  - quit and delete $APP"
read -r -p "Continue? [y/N] " answer
case "$answer" in
  y|Y|yes|YES) ;;
  *) echo "Aborted."; exit 0 ;;
esac

launchctl bootout "gui/$UID/$LABEL" 2>/dev/null || true
rm -f "$PLIST"
echo "Removed LaunchAgent."

# Ask the app to quit gracefully (ignored if it is not running).
osascript -e 'if application id "care.lillian.helper" is running then tell application id "care.lillian.helper" to quit' \
  >/dev/null 2>&1 || true
rm -rf "$APP"
echo "Removed $APP."

echo
echo "Logs were kept in $LOG_DIR (delete manually if you like)."
echo "If you had enabled 'Launch at Login', the stale entry disappears from"
echo "System Settings > General > Login Items once the app is gone."
