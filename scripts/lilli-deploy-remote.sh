#!/usr/bin/env bash
# Runs ON the Lilli box, piped over ssh by `scripts/lilli.js deploy|rollback`.
#
#   deploy <sha>   build <sha> as a new release beside the live one, switch /opt/lilli-deploy/current to it,
#                  restart PM2 and health-check; switch back automatically if the check fails
#   rollback       switch to the previous successful release (no rebuild)
#
# Layout:
#   /opt/lilli                          git checkout, used only to fetch and `git archive`
#   /opt/lilli-deploy/releases/<sha7>/  one release each (app/ with its own node_modules and .next)
#   /opt/lilli-deploy/current           symlink -> the live release's app/ (PM2 runs from here)
#   /opt/lilli-deploy/shared/app.env    the app's .env, symlinked into every release
#   /opt/lilli-deploy/shared/deploys.log
# /opt/lilli-deploy is created once with passwordless sudo (the deploy user can't write to /opt)
# and owned by the deploy user, so nothing after that needs sudo.
set -euo pipefail

REPO=/opt/lilli
BASE=/opt/lilli-deploy
RELEASES=$BASE/releases
CURRENT=$BASE/current
SHARED=$BASE/shared
ENV_FILE=$SHARED/app.env
LOG=$SHARED/deploys.log
KEEP=3
WEB=lilli-staging
WS=lilli-ws

say() { echo "[lilli] $*"; }

if [ ! -d "$BASE" ]; then
  sudo -n install -d -o "$(id -un)" -g "$(id -gn)" "$BASE" || { say "cannot create $BASE (needs passwordless sudo once)"; exit 1; }
  say "created $BASE"
fi
mkdir -p "$RELEASES" "$SHARED"
exec 9>"$SHARED/deploy.lock"
flock -n 9 || { say "another deploy is running"; exit 1; }

# One-time: move the env file out of the checkout so all releases share it.
if [ ! -f "$ENV_FILE" ]; then
  cp "$REPO/app/.env" "$ENV_FILE"
  chmod 600 "$ENV_FILE"
  say "created $ENV_FILE from $REPO/app/.env"
fi

env_value() { grep -E "^$1=" "$ENV_FILE" | tail -1 | cut -d= -f2-; }

pm2_cwd() {
  pm2 jlist | node -e 'const n=process.argv[1];const p=JSON.parse(require("fs").readFileSync(0,"utf8")).find(x=>x.name===n);console.log(p?p.pm2_env.pm_cwd:"")' "$1"
}

pm2_online() {
  pm2 jlist | node -e 'const names=process.argv.slice(1);console.log(JSON.parse(require("fs").readFileSync(0,"utf8")).filter(p=>names.includes(p.name)&&p.pm2_env.status==="online").length)' "$@"
}

# (Re)create both PM2 processes in <dir>. Used when they do not run from there yet.
pm2_start_in() {
  local dir=$1
  pm2 delete "$WEB" "$WS" >/dev/null 2>&1 || true
  pm2 start npm --name "$WEB" --cwd "$dir" --time -- start >/dev/null
  pm2 start "$dir/node_modules/.bin/tsx" --name "$WS" --cwd "$dir" --time -- server/ws-server.ts >/dev/null
  pm2 save >/dev/null
}

restart() {
  if [ "$(pm2_cwd "$WEB")" = "$CURRENT" ] && [ "$(pm2_cwd "$WS")" = "$CURRENT" ]; then
    pm2 restart "$WEB" "$WS" --update-env >/dev/null
  else
    say "pointing PM2 at $CURRENT"
    pm2_start_in "$CURRENT"
  fi
}

healthy() {
  local base code i
  base=$(env_value LILLI_BASE_PATH)
  for i in $(seq 1 30); do
    code=$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:3001${base}/login" || true)
    if [ "$code" = 200 ] && ss -ltn | grep -q ':3002 '; then
      sleep 5   # a WS server that crashes on boot is gone by now
      ss -ltn | grep -q ':3002 ' && [ "$(pm2_online "$WEB" "$WS")" = 2 ] && return 0
    fi
    sleep 2
  done
  say "health check failed (web: ${code:-none}, ws: $(ss -ltn | grep -q ':3002 ' && echo up || echo down))"
  return 1
}

switch_to() {
  ln -sfn "$1" "$CURRENT.tmp"
  mv -Tf "$CURRENT.tmp" "$CURRENT"
}

# Switch back after a failed health check: to the previous release, or on the very first
# deploy to the old in-place checkout.
revert() {
  local prev=$1
  if [ -n "$prev" ]; then
    say "reverting to $prev"
    switch_to "$prev"
    restart
  else
    say "reverting PM2 to $REPO/app"
    rm -f "$CURRENT"
    pm2_start_in "$REPO/app"
  fi
  healthy && say "reverted, live again" || say "REVERT ALSO UNHEALTHY — check pm2 logs"
}

prune() {
  local cur keep
  cur=$(dirname "$(readlink "$CURRENT")")
  keep=$(ls -1dt "$RELEASES"/*/ 2>/dev/null | head -n "$KEEP" | sed 's#/$##')
  for d in $(ls -1dt "$RELEASES"/*/ 2>/dev/null | sed 's#/$##'); do
    if [ "$d" != "$cur" ] && ! grep -qx "$d" <<<"$keep"; then rm -rf "$d"; say "pruned $(basename "$d")"; fi
  done
}

deploy() {
  local sha=$1 short dir prev
  git -C "$REPO" fetch -q origin
  sha=$(git -C "$REPO" rev-parse --verify "$sha^{commit}")
  short=${sha:0:7}
  dir=$RELEASES/$short
  prev=$(readlink "$CURRENT" 2>/dev/null || true)

  if [ "$(df --output=avail -k / | tail -1)" -lt 3000000 ]; then say "less than 3 GB free on /"; exit 1; fi

  if [ "$prev" = "$dir/app" ]; then
    say "$short is live; rebuilding it in place is not supported, restarting instead"
    restart; healthy; return
  fi

  say "building $short in $dir"
  rm -rf "$dir"
  mkdir -p "$dir"
  git -C "$REPO" archive "$sha" | tar -x -C "$dir"
  echo "$sha" >"$dir/REVISION"
  ln -s "$ENV_FILE" "$dir/app/.env"
  (
    cd "$dir/app"
    npm ci --no-audit --no-fund --loglevel=error || { say "npm ci failed, falling back to npm install"; npm install --no-audit --no-fund --loglevel=error; }
    npx prisma generate >/dev/null
    npm run build
  ) || { say "build failed; live release untouched"; rm -rf "$dir"; echo "$(date -Is) $short build-failed" >>"$LOG"; exit 1; }

  say "switching to $short"
  switch_to "$dir/app"
  restart
  if healthy; then
    echo "$(date -Is) $short ok" >>"$LOG"
    say "live: $short"
    prune
  else
    echo "$(date -Is) $short reverted" >>"$LOG"
    revert "$prev"
    exit 1
  fi
}

rollback() {
  local cur target
  cur=$(basename "$(dirname "$(readlink "$CURRENT" 2>/dev/null || echo /x/x)")")
  target=$(grep ' ok$' "$LOG" 2>/dev/null | awk '{print $2}' | grep -vx "$cur" | tail -1 || true)
  if [ -z "$target" ] || [ ! -d "$RELEASES/$target/app/.next" ]; then say "no previous release to roll back to"; exit 1; fi
  say "rolling back $cur -> $target"
  switch_to "$RELEASES/$target/app"
  restart
  if healthy; then echo "$(date -Is) $target ok rollback" >>"$LOG"; say "live: $target"; else say "rollback target unhealthy — check pm2 logs"; exit 1; fi
}

case "${1:-}" in
  deploy) deploy "${2:?sha required}" ;;
  rollback) rollback ;;
  *) echo "usage: deploy <sha> | rollback"; exit 2 ;;
esac
