#!/bin/sh
# Stores the Gmail account monitor.py sends alert emails from, then sends a
# test alert. Run it yourself over SSH, as the app user, from the app
# directory - the app password is typed here (not echoed) and saved only in
# config.json, which only the app user can read.
#
# Use a Gmail *app password* (Google account -> Security -> 2-Step
# Verification -> App passwords), not your normal password. It can only be
# used to send mail like this, and can be revoked from that page anytime.
# Who receives alerts is set per admin link on the admin page.
set -e
cd "$(dirname "$0")"

printf "Gmail address to send alerts from: "
read GMAIL_USER
printf "App password for %s (16 letters, not shown): " "$GMAIL_USER"
stty -echo
read APP_PASSWORD
stty echo
echo

GMAIL_USER="$GMAIL_USER" APP_PASSWORD="$APP_PASSWORD" python - << 'PYEOF'
import json, os
c = json.load(open('config.json'))
c['smtp'] = {'host': 'smtp.gmail.com', 'port': 465, 'user': os.environ['GMAIL_USER'],
             'password': os.environ['APP_PASSWORD'].replace(' ', '')}
with open('config.json.tmp', 'w') as f:
    json.dump(c, f, indent=2, sort_keys=True)
os.chmod('config.json.tmp', 0o600)
os.rename('config.json.tmp', 'config.json')
PYEOF
echo "Saved. Sending a test alert..."
python monitor.py --test-email
