#!/bin/sh
# OPTIONAL. Only useful if your router already has a real (e.g. Let's Encrypt)
# certificate for its own admin interface that you'd like this app to reuse,
# instead of the self-signed one the installer generates by default.
#
# Run as root (reads root-only SRM cert files). Builds a full certificate chain
# (leaf + intermediate) for this app and, if it changed, deploys it and stops
# the app so its watchdog (crontab) restarts it picking up the new cert.
# No-op if nothing changed.
#
# server.crt itself is leaf-only on SRM; Apache (port 8001/443) presents the
# full chain via a mechanism this script doesn't need to know about, so the
# intermediate is pulled directly from that live, already-correct connection.
#
# The app directory is writable by the app user, so root never writes,
# chowns or kills anything there itself: the chain is built in the root-only
# BUILD_DIR, and every step touching the app directory runs as the app user,
# with root only supplying the file contents on stdin.
set -e

ROOT_DIR=__ROOT_DIR__
APP_DIR=__APP_DIR__
APP_USER=__APP_USER__
DDNS_HOSTNAME=__DDNS_HOSTNAME__

SRC_CERT=/usr/syno/etc/ssl/ssl.crt/server.crt
SRC_KEY=/usr/syno/etc/ssl/ssl.key/server.key
BUILD_DIR="$ROOT_DIR/cert-build"
DST_DIR="$APP_DIR/cert"

as_app_user() {
  su "$APP_USER" -c "$1"
}

rm -rf "$BUILD_DIR"
mkdir -m 700 "$BUILD_DIR"
cp "$SRC_CERT" "$BUILD_DIR/fullchain.pem"
echo >> "$BUILD_DIR/fullchain.pem"
echo | openssl s_client -connect localhost:8001 -servername "$DDNS_HOSTNAME" -showcerts 2>/dev/null \
  | awk '/BEGIN CERTIFICATE/{n++} n>1' >> "$BUILD_DIR/fullchain.pem"
cp "$SRC_KEY" "$BUILD_DIR/privkey.pem"

if ! as_app_user "cat '$DST_DIR/fullchain.pem'" 2>/dev/null | cmp -s - "$BUILD_DIR/fullchain.pem"; then
  as_app_user "umask 022 && cat > '$DST_DIR/.fullchain.new' && mv '$DST_DIR/.fullchain.new' '$DST_DIR/fullchain.pem'" \
    < "$BUILD_DIR/fullchain.pem"
  as_app_user "umask 077 && cat > '$DST_DIR/.privkey.new' && mv '$DST_DIR/.privkey.new' '$DST_DIR/privkey.pem'" \
    < "$BUILD_DIR/privkey.pem"
  as_app_user "cd '$APP_DIR' && [ -f server.pid ] && kill \"\$(cat server.pid)\" 2>/dev/null; true"
fi
rm -rf "$BUILD_DIR"
