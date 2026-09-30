#!/bin/sh
# OPTIONAL. Only useful if your router already has a real (e.g. Let's Encrypt)
# certificate for its own admin interface that you'd like this app to reuse,
# instead of the self-signed one the installer generates by default.
#
# Run as root (reads root-only SRM cert files). Builds a full certificate chain
# (leaf + intermediate) for this app and, if it changed, deploys it and kills
# the app so its watchdog (crontab) restarts it picking up the new cert.
# No-op if nothing changed.
#
# server.crt itself is leaf-only on SRM; Apache (port 8001/443) presents the
# full chain via a mechanism this script doesn't need to know about, so the
# intermediate is pulled directly from that live, already-correct connection.
set -e

APP_DIR="$(cd "$(dirname "$0")" && pwd)"
APP_USER=__APP_USER__
DDNS_HOSTNAME=__DDNS_HOSTNAME__

SRC_CERT=/usr/syno/etc/ssl/ssl.crt/server.crt
SRC_KEY=/usr/syno/etc/ssl/ssl.key/server.key
DST_DIR="$APP_DIR/cert"
DST_CERT="$DST_DIR/fullchain.pem"
DST_KEY="$DST_DIR/privkey.pem"
TMP_CHAIN="$DST_DIR/.fullchain.new"
TMP_KEY="$DST_DIR/.privkey.new"
APP_GROUP="$(id -gn "$APP_USER")"

cp "$SRC_CERT" "$TMP_CHAIN"
echo >> "$TMP_CHAIN"
echo | openssl s_client -connect localhost:8001 -servername "$DDNS_HOSTNAME" -showcerts 2>/dev/null \
  | awk '/BEGIN CERTIFICATE/{n++} n>1' >> "$TMP_CHAIN"
cp "$SRC_KEY" "$TMP_KEY"

if ! cmp -s "$TMP_CHAIN" "$DST_CERT" 2>/dev/null; then
  chown "$APP_USER:$APP_GROUP" "$TMP_CHAIN" "$TMP_KEY"
  chmod 644 "$TMP_CHAIN"
  chmod 600 "$TMP_KEY"
  mv "$TMP_CHAIN" "$DST_CERT"
  mv "$TMP_KEY" "$DST_KEY"

  if [ -f "$APP_DIR/server.pid" ]; then
    kill "$(cat "$APP_DIR/server.pid")" 2>/dev/null || true
  fi
else
  rm -f "$TMP_CHAIN" "$TMP_KEY"
fi
