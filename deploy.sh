#!/bin/sh
# Deploys the app's own files from this checkout to an installed copy over
# SSH, as the app user: backs up what's there, compile-checks each new file
# with the router's Python, swaps them in, restarts the server and checks it
# answers. Keeps the newest KEEP backups.
#
#   ./deploy.sh [ssh-host] [app-dir]      (default: synology /volume1/reward-time)
#
# Only the app user's files are deployed. The root-owned parts in
# <app-dir>-root and watchdog.sh (filled in by install.sh) are not touched -
# they need root, so they're installed separately.
set -e
HOST=${1:-${DEPLOY_HOST:-synology}}
APP_DIR=${2:-${DEPLOY_APP_DIR:-/volume1/reward-time}}
KEEP=${KEEP:-5}
FILES="reward_server.py schedule.py monitor.py set-alert-email.sh"
cd "$(dirname "$0")"

echo "== deploying to $HOST:$APP_DIR"
STAGE=".deploy-$$"
ssh "$HOST" "mkdir -m 700 $APP_DIR/$STAGE"
tar cf - $FILES | ssh "$HOST" "cd $APP_DIR/$STAGE && tar xf -"

ssh "$HOST" "APP_DIR=$APP_DIR STAGE=$STAGE KEEP=$KEEP FILES='$FILES' sh -s" << 'REMOTE'
set -e
cd "$APP_DIR"
cleanup() { rm -rf "$STAGE"; }
trap cleanup EXIT

for f in $FILES; do
  case "$f" in
    *.py) python -c "import compiler; compiler.parseFile('$STAGE/$f')" || { echo "compile check failed: $f"; exit 1; } ;;
    *.sh) sh -n "$STAGE/$f" || { echo "syntax check failed: $f"; exit 1; } ;;
  esac
done
echo "compile checks passed"

TS=$(date +%Y%m%d-%H%M%S)
mkdir -p backups && chmod 700 backups
mkdir "backups/$TS"
for f in $FILES; do
  [ -f "$f" ] && cp -p "$f" "backups/$TS/"
done
# Older deploys left reward_server.py.bak-* style files next to the app.
LEGACY=$(ls -d *.bak-* 2>/dev/null || true)
if [ -n "$LEGACY" ]; then
  mkdir -p "backups/$TS/legacy" && mv $LEGACY "backups/$TS/legacy/" && echo "moved old .bak files into backups/$TS/legacy"
fi
echo "backed up to $APP_DIR/backups/$TS"

for f in $FILES; do
  case "$f" in *.sh|monitor.py) mode=755 ;; *) mode=644 ;; esac
  chmod $mode "$STAGE/$f"
  mv "$STAGE/$f" "$f"
done

CRASH_BEFORE=$(wc -c < server.crash.log 2>/dev/null || echo 0)
[ -f server.pid ] && kill "$(cat server.pid)" 2>/dev/null || true
sleep 1
./watchdog.sh
sleep 3
PORT=$(python -c "import json; print(json.load(open('config.json'))['port'])")
CODE=$(curl -sk -m 10 -o /dev/null -w '%{http_code}' "https://localhost:$PORT/")
NEW_CRASH=$(tail -c +$((CRASH_BEFORE + 1)) server.crash.log 2>/dev/null | grep -v 'watchdog: starting' || true)
if [ "$CODE" = "000" ] || [ -n "$NEW_CRASH" ]; then
  echo "SERVER NOT HEALTHY (HTTP $CODE)"; [ -n "$NEW_CRASH" ] && echo "$NEW_CRASH"
  echo "to roll back: cp -p backups/$TS/* . && ./watchdog.sh"
  exit 1
fi
echo "server restarted and answering (HTTP $CODE)"

# Newest first; everything after the first KEEP goes. (BusyBox head has no -n -N.)
ls -1d backups/*/ | sort -r | tail -n +$((KEEP + 1)) | while read old; do rm -rf "$old"; echo "pruned $old"; done
echo "backups kept: $(ls -1d backups/*/ | wc -l)"
REMOTE
