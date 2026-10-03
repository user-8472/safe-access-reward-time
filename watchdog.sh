#!/bin/sh
# Runs as __APP_USER__, never root - it starts an internet-facing process.
# Root's crontab entry runs the root-owned app_watchdog.sh launcher (in the
# root-owned install dir), which hands off to this script via su. Root must
# never run anything from this directory itself: the app user can edit it.
if [ "$(id -un)" != "__APP_USER__" ]; then
  echo "watchdog.sh must run as __APP_USER__, not $(id -un)" >&2
  exit 1
fi

cd "$(dirname "$0")" || exit 1

PORT=__HTTPS_PORT__

is_alive() {
  [ -f server.pid ] && kill -0 "$(cat server.pid)" 2>/dev/null
}

is_healthy() {
  # A hung process (e.g. stuck mid TLS-handshake with a bad client) still passes
  # is_alive forever - an actual request is the only real proof it's serving.
  code=$(curl -sk -m 5 -o /dev/null -w '%{http_code}' "https://localhost:$PORT/" 2>/dev/null)
  [ -n "$code" ] && [ "$code" != "000" ]
}

if is_alive && is_healthy; then
  exit 0
fi

if is_alive; then
  # Alive but not responding - kill it before starting a fresh one, otherwise
  # the old hung process just keeps squatting on the port.
  kill -9 "$(cat server.pid)" 2>/dev/null
  sleep 1
fi

# server.log is the app's own rotating log, so it's never redirected here -
# "> server.log" used to wipe it on every restart, losing exactly the log
# you'd want after a crash. Anything printed outside the logger (startup
# errors, tracebacks) is appended to server.crash.log instead, with one
# previous copy kept once it passes 1MB. Each restart is also recorded there.
if [ -f server.crash.log ] && [ "$(wc -c < server.crash.log)" -gt 1048576 ]; then
  mv server.crash.log server.crash.log.1
fi
echo "$(date '+%Y-%m-%d %H:%M:%S') watchdog: starting reward_server.py" >> server.crash.log
nohup python reward_server.py >> server.crash.log 2>&1 &
echo $! > server.pid
