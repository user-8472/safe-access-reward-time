#!/bin/sh
# This must always run as __APP_USER__, never root - it starts an internet-facing
# process. The crontab entry invoking this script uses "root" as its "who"
# column, not __APP_USER__: a controlled test (two identical entries added,
# one as root and one as a regular user) confirmed this router's reboot
# strips any crontab entry whose "who" column isn't "root". So this script
# always self-corrects to __APP_USER__ internally instead of relying on
# crond to invoke it as the right user in the first place.
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
