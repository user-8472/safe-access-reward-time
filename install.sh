#!/bin/sh
# Interactive installer for the Safe Access Reward Time app.
#
# Run this AS THE REGULAR ADMIN ACCOUNT you'll use day to day (not root),
# from inside the directory you cloned/copied this repo into - that
# directory becomes the app's permanent home, since a couple of the files
# it installs elsewhere point back to this exact path.
#
# This script only ever touches files in its own directory (plus generating
# a config file and a cert here). It never modifies system files, crontab,
# or anything requiring root - at the end it prints the exact commands you
# run yourself, as root, to finish setup. Nothing is auto-elevated.
set -e
umask 077

APP_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$APP_DIR"
# The few parts that run as root get their own root-owned directory next to
# this one - root must never run anything from a directory the app user can
# write to, since that would hand the app user root.
ROOT_DIR="$APP_DIR-root"

echo "=== Safe Access Reward Time - installer ==="
echo "Installing into: $APP_DIR"
echo

if [ "$(id -u)" = "0" ]; then
  echo "Please don't run this as root - run it as the regular admin account" >&2
  echo "you'll use to access this app day to day." >&2
  exit 1
fi

if ! which python >/dev/null 2>&1; then
  echo "python (2.7) not found - this needs to run on the Synology device itself" >&2
  echo "over SSH, not on your own computer." >&2
  exit 1
fi

DEFAULT_DB_PATH=/usr/syno/etc/packages/SafeAccess/synoaccesscontrol/database.db
if [ ! -f "$DEFAULT_DB_PATH" ]; then
  echo "Warning: Safe Access database not found at the expected path:" >&2
  echo "  $DEFAULT_DB_PATH" >&2
  echo "Is the Safe Access package installed on this device? You can still" >&2
  echo "continue and fix the path in config.json afterward if needed." >&2
  echo
fi

PARENT_OWNER="$(ls -ld "$(dirname "$APP_DIR")" | awk '{print $3}')"
if [ "$PARENT_OWNER" != "root" ]; then
  echo "$(dirname "$APP_DIR") is owned by $PARENT_OWNER, not root." >&2
  echo "Install into a directory directly under a root-owned one (e.g. /volume1)," >&2
  echo "so the root-owned $ROOT_DIR alongside it can't be swapped out." >&2
  exit 1
fi

APP_USER="$(id -un)"
echo "App will run as: $APP_USER (the account you're logged in as)"
echo

printf "HTTPS port to serve on [8443]: "
read HTTPS_PORT
HTTPS_PORT=${HTTPS_PORT:-8443}

echo
echo "If this router already has a real (e.g. Let's Encrypt) certificate for"
echo "its own admin interface, this app can reuse it instead of a self-signed"
echo "one - avoiding browser warnings. That's optional and can be set up later"
echo "(see README's 'Reusing a real certificate' section)."
printf "Router's public DDNS hostname, if you have one and want this now (leave blank to skip): "
read DDNS_HOSTNAME

echo
echo "Generating an access token..."
TOKEN=$(openssl rand -hex 24)

echo "Generating a self-signed certificate..."
mkdir -p cert
CERT_CN=${DDNS_HOSTNAME:-$(hostname)}
# Older OpenSSL builds (common on SRM) don't support -addext, so the SAN goes
# through an actual config file instead. No mktemp either on some BusyBox
# builds, so a PID-based name in /tmp is used instead - fine for a file this
# short-lived and non-sensitive (it's just the public cert's own metadata).
CERT_CONF="/tmp/reward_time_cert_$$.conf"
cat > "$CERT_CONF" << CERTEOF
[req]
distinguished_name = req_dn
x509_extensions = v3_req
prompt = no
[req_dn]
CN = $CERT_CN
[v3_req]
subjectAltName = DNS:$CERT_CN
CERTEOF
openssl req -x509 -newkey rsa:2048 -keyout cert/privkey.pem -out cert/fullchain.pem \
  -days 3650 -nodes -config "$CERT_CONF" >/dev/null 2>&1
rm -f "$CERT_CONF"

printf "Safe Access database path [%s]: " "$DEFAULT_DB_PATH"
read DB_PATH
DB_PATH=${DB_PATH:-$DEFAULT_DB_PATH}

cat > config.json << EOF
{
  "db_path": "$DB_PATH",
  "token": "$TOKEN",
  "port": $HTTPS_PORT,
  "cert_file": "$APP_DIR/cert/fullchain.pem",
  "key_file": "$APP_DIR/cert/privkey.pem"
}
EOF

echo "Filling in scripts with your settings..."
for f in watchdog.sh root/apply_daemon.py root/apply_watchdog.sh root/app_watchdog.sh \
         root/reward-time-rcd.sh root/reward-apply-rcd.sh root/cert-sync.sh; do
  sed -i \
    -e "s|__APP_USER__|$APP_USER|g" \
    -e "s|__ROOT_DIR__|$ROOT_DIR|g" \
    -e "s|__APP_DIR__|$APP_DIR|g" \
    -e "s|__DDNS_HOSTNAME__|${DDNS_HOSTNAME:-localhost}|g" \
    -e "s|PORT=__HTTPS_PORT__|PORT=$HTTPS_PORT|g" \
    "$f"
done
chmod +x watchdog.sh reward_server.py
chmod 600 cert/privkey.pem config.json
mkdir -p pending

echo
echo "=========================================================="
echo "Local setup done. A few things need root, so nothing here"
echo "was auto-elevated - copy/paste these yourself, as root"
echo "(e.g. 'su' at an SSH prompt):"
echo "=========================================================="
cat << EOF

# 1) Copy the parts that run as root into their own root-owned directory -
#    root never runs anything from $APP_DIR itself, since you (the app
#    user) can write there:
mkdir -m 755 $ROOT_DIR
cp $APP_DIR/root/apply_daemon.py $APP_DIR/root/apply_watchdog.sh \\
   $APP_DIR/root/app_watchdog.sh $APP_DIR/root/cert-sync.sh $ROOT_DIR/
chown -R root:root $ROOT_DIR
chmod 755 $ROOT_DIR/*

# 2) Install both background services to start at boot:
cp $APP_DIR/root/reward-time-rcd.sh /usr/local/etc/rc.d/reward-time.sh
cp $APP_DIR/root/reward-apply-rcd.sh /usr/local/etc/rc.d/reward-apply.sh
chown root:root /usr/local/etc/rc.d/reward-time.sh /usr/local/etc/rc.d/reward-apply.sh
chmod 755 /usr/local/etc/rc.d/reward-time.sh /usr/local/etc/rc.d/reward-apply.sh
/usr/local/etc/rc.d/reward-apply.sh start
/usr/local/etc/rc.d/reward-time.sh start

# 3) Add the watchdog cron entries (keeps both services running), then
#    restart crond so it picks them up. Both use "root" as the "who" column -
#    confirmed via a controlled test (two identical entries added, one as root
#    and one as a regular user) that this router's reboot strips any crontab
#    entry whose "who" column isn't "root". app_watchdog.sh drops to
#    $APP_USER before running anything from $APP_DIR.
printf '*/1\t*\t*\t*\t*\troot\t$ROOT_DIR/app_watchdog.sh\n' >> /etc/crontab
printf '*/1\t*\t*\t*\t*\troot\t$ROOT_DIR/apply_watchdog.sh\n' >> /etc/crontab
/usr/syno/sbin/synoservicectl --restart crond

# 4) Verify it's running:
ps w | grep -E 'reward_server.py|apply_daemon.py' | grep -v grep

EOF
echo "=========================================================="
echo "Then, in the SRM web interface (Control Panel -> Security ->"
echo "Firewall), add an Allow rule for TCP port $HTTPS_PORT from any"
echo "source - this app can't reach the internet without it."
echo "=========================================================="
echo
echo "Once that's done, open:"
if [ -n "$DDNS_HOSTNAME" ]; then
  echo "  https://$DDNS_HOSTNAME:$HTTPS_PORT/?token=$TOKEN"
else
  echo "  https://<this-router's-address>:$HTTPS_PORT/?token=$TOKEN"
fi
echo "and bookmark it / add it to your phone's home screen."
echo
echo "This uses a self-signed certificate, so your browser will warn the"
echo "first time - see the README for how to trust it permanently."
