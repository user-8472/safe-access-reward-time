#!/usr/bin/env python
# Health monitor, run every minute as the app user (root's crontab starts it
# through the root-owned monitor_launcher.sh, which drops to the app user -
# nothing here needs root, only files the root daemons make world-readable).
#
# Raises one alert when a check starts failing and one when it recovers,
# rather than repeating every minute, and also reports one-off events (a
# forced DDNS update, a matching line in a watched log). Alerts are always
# written to monitor.log and, when email is configured (see send_email), to
# every admin link that has an alert email. Alerts that couldn't be emailed
# stay queued and are retried on the next run. The current set of problems
# is kept in monitor.state, which the app reads to show a warning banner.
#
# Built-in checks: the web app answering, apply_daemon's heartbeat, and
# cert-sync.sh's last result. More can be added in config.json:
#   "monitor": {
#     "heartbeats": {"name": "/path/to/heartbeat"},
#     "status_files": {"name": {"path": "/path/to/status", "max_age": 180}},
#     "log_watches": {"name": {"path": "/path/to/log", "pattern": "regex"}}
#   }
import json
import logging
import logging.handlers
import os
import re
import smtplib
import socket
import sqlite3
import ssl
import subprocess
import sys
import time
from email.mime.text import MIMEText

APP_DIR = os.path.dirname(os.path.abspath(__file__))
STATE_PATH = os.path.join(APP_DIR, 'monitor.state')
TOKENS_DB_PATH = os.path.join(APP_DIR, 'tokens.db')
HEARTBEAT_MAX_AGE = 120
WEB_FAILS_BEFORE_ALERT = 3  # watchdog.sh restarts it within a minute; only a lasting outage alerts
MAX_QUEUED_ALERTS = 200

with open(os.path.join(APP_DIR, 'config.json')) as f:
    CONFIG = json.load(f)
ROOT_DIR = CONFIG.get('root_dir', APP_DIR + '-root')

log = logging.getLogger('monitor')
log.setLevel(logging.INFO)
_handler = logging.handlers.RotatingFileHandler(
    os.path.join(APP_DIR, 'monitor.log'), maxBytes=1024 * 1024, backupCount=1)
_handler.setFormatter(logging.Formatter('%(asctime)s %(message)s'))
log.addHandler(_handler)


def load_state():
    try:
        with open(STATE_PATH) as f:
            return json.load(f)
    except (IOError, ValueError):
        return {}


def save_state(state):
    tmp = STATE_PATH + '.tmp'
    with open(tmp, 'w') as f:
        json.dump(state, f, indent=1, sort_keys=True)
    os.rename(tmp, STATE_PATH)


def file_age(path):
    try:
        return time.time() - os.stat(path).st_mtime
    except OSError:
        return None


def check_web(state):
    code = subprocess.Popen(
        ['curl', '-sk', '-m', '5', '-o', '/dev/null', '-w', '%{http_code}',
         'https://localhost:%d/' % CONFIG['port']],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()[0].strip()
    fails = state.get('web_fails', 0)
    fails = 0 if code and code != '000' else fails + 1
    state['web_fails'] = fails
    if fails >= WEB_FAILS_BEFORE_ALERT:
        return 'web app not answering on port %d for %d minutes' % (CONFIG['port'], fails)
    return None


def check_heartbeat(path):
    age = file_age(path)
    if age is None:
        return 'no heartbeat file (%s) - daemon not running?' % path
    if age > HEARTBEAT_MAX_AGE:
        return 'heartbeat is %d minutes old - daemon stopped or hung?' % (age // 60)
    return None


def check_status_file(path, max_age):
    # Status files are one line: "<date> <time> <text>". A missing file just
    # means the job hasn't run yet (e.g. weekly cert-sync after an install).
    try:
        with open(path) as f:
            line = f.read().strip()
    except IOError:
        return None, None
    text = line.split(' ', 2)[2] if line.count(' ') >= 2 else line
    if max_age and file_age(path) > max_age:
        return 'last ran %d minutes ago (expected every %d)' % (file_age(path) // 60, max_age // 60), text
    if 'failed' in text.lower():
        return 'last run failed: %s' % text, text
    return None, text


def check_log_watch(name, path, pattern, state):
    # Reports each new line matching pattern since the last run, as events.
    offsets = state.setdefault('log_offsets', {})
    try:
        size = os.stat(path).st_size
    except OSError:
        return []
    offset = offsets.get(name)
    if offset is None or offset > size:  # first run, or the log rotated
        offset = 0 if offset is not None else size
    events = []
    with open(path) as f:
        f.seek(offset)
        for line in f:
            if re.search(pattern, line):
                events.append('%s: %s' % (name, line.strip()))
        offsets[name] = f.tell()
    return events


def run_checks(state):
    # Returns ({check name: problem text}, [event texts]).
    monitor_cfg = CONFIG.get('monitor', {})
    problems = {}
    events = []

    problem = check_web(state)
    if problem:
        problems['web app'] = problem

    heartbeats = {'apply_daemon': os.path.join(ROOT_DIR, 'apply_daemon.heartbeat')}
    heartbeats.update(monitor_cfg.get('heartbeats', {}))
    for name, path in sorted(heartbeats.items()):
        problem = check_heartbeat(path)
        if problem:
            problems[name] = problem

    status_files = {'cert-sync': {'path': os.path.join(ROOT_DIR, 'cert-sync.status'), 'max_age': 0}}
    status_files.update(monitor_cfg.get('status_files', {}))
    last_status = state.setdefault('last_status_text', {})
    for name, spec in sorted(status_files.items()):
        problem, text = check_status_file(spec['path'], spec.get('max_age', 0))
        if problem:
            problems[name] = problem
        if text and 'forced update' in text and text != last_status.get(name):
            events.append('%s: %s' % (name, text))
        if text:
            last_status[name] = text

    for name, spec in sorted(monitor_cfg.get('log_watches', {}).items()):
        events.extend(check_log_watch(name, spec['path'], spec['pattern'], state))

    return problems, events


def alert_recipients():
    # Admin links with an alert email (managed on the app's admin page).
    try:
        conn = sqlite3.connect(TOKENS_DB_PATH, timeout=10)
        try:
            rows = conn.execute(
                "SELECT email FROM admin_tokens WHERE email IS NOT NULL AND email != ''").fetchall()
        finally:
            conn.close()
    except sqlite3.Error:
        return []
    return sorted(set(r[0] for r in rows))


class VerifiedSMTP_SSL(smtplib.SMTP_SSL):
    # SRM's Python 2.7 smtplib predates SMTP_SSL's context argument, and its
    # stock SMTP_SSL wraps the socket without checking the server certificate
    # at all. This does the same connection with a verifying context
    # (certificate chain and hostname checked against the system CA bundle).
    def _get_socket(self, host, port, timeout):
        sock = socket.create_connection((host, port), timeout)
        sock = ssl.create_default_context().wrap_socket(sock, server_hostname=host)
        self.file = smtplib.SSLFakeFile(sock)
        return sock


def send_email(recipients, alerts):
    # config.json "smtp": {"host": "smtp.gmail.com", "port": 465,
    #                      "user": "...", "password": "<app password>"}
    smtp = CONFIG.get('smtp')
    if not smtp or not recipients:
        return False
    host = socket.gethostname()
    subject = 'Reward Time on %s: %s' % (host, alerts[0][1] if len(alerts) == 1 else '%d alerts' % len(alerts))
    body = '\n'.join('%s  %s' % (time.strftime('%Y-%m-%d %H:%M', time.localtime(ts)), text)
                     for ts, text in alerts)
    msg = MIMEText(body + '\n')
    msg['Subject'] = subject
    msg['From'] = smtp.get('from', smtp['user'])
    msg['To'] = ', '.join(recipients)
    server = VerifiedSMTP_SSL(smtp.get('host', 'smtp.gmail.com'), smtp.get('port', 465), timeout=20)
    try:
        server.login(smtp['user'], smtp['password'])
        server.sendmail(msg['From'], recipients, msg.as_string())
    finally:
        server.quit()
    return True


def main():
    state = load_state()
    now = int(time.time())
    problems, events = run_checks(state)

    active = state.get('problems', {})
    new_alerts = []
    for name, text in sorted(problems.items()):
        if name not in active:
            new_alerts.append('PROBLEM %s: %s' % (name, text))
    for name in sorted(active):
        if name not in problems:
            new_alerts.append('RECOVERED %s (was: %s)' % (name, active[name]))
    new_alerts.extend('EVENT ' + e for e in events)
    state['problems'] = problems

    queue = state.get('queue', []) + [[now, a] for a in new_alerts]
    for _, text in [[now, a] for a in new_alerts]:
        log.info(text)
    if queue:
        try:
            if send_email(alert_recipients(), queue):
                queue = []
        except Exception as exc:
            log.info('could not send alert email (will retry): %s', exc)
    state['queue'] = queue[-MAX_QUEUED_ALERTS:]
    state['last_run'] = now
    save_state(state)


def test_email():
    recipients = alert_recipients()
    if not CONFIG.get('smtp'):
        print('No "smtp" section in config.json - run set-alert-email.sh first.')
        return 1
    if not recipients:
        print('No admin link has an alert email - add one on the admin page.')
        return 1
    send_email(recipients, [[int(time.time()), 'Test alert - email alerts are working']])
    print('Sent a test alert to: %s' % ', '.join(recipients))
    return 0


if __name__ == '__main__':
    if sys.argv[1:] == ['--test-email']:
        sys.exit(test_email())
    main()
