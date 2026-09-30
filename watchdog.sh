#!/bin/sh
# This must always run as __APP_USER__, never root - it starts an internet-facing
# process. crond on Synology routers does NOT reliably honor the "who" column in
# /etc/crontab, so the crontab entry invoking this script explicitly does
# `su __APP_USER__ -c ...` rather than relying on that column. This self-check is
# a second layer of defense in case it's ever invoked as root some other way.
if [ "$(id -un)" != "__APP_USER__" ]; then
  exec su __APP_USER__ -c "$0 $*"
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

nohup python reward_server.py > server.log 2>&1 &
echo $! > server.pid
