#!/usr/bin/env python
# Health monitor, run every minute as the app user (root's crontab starts it
# through the root-owned monitor_launcher.sh, which drops to the app user -
# nothing here needs root, only files the root daemons make world-readable).
#
# Raises one alert when a check starts failing and one when it recovers,
# rather than repeating every minute, and also reports one-off events (a
# forced DDNS update, a matching line in a watched log, an action in the app's
# activity log that failed). It also sends the weekly usage summary (Sundays
# from WEEKLY_HOUR) to admin links that opted in. Alerts are always
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
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
try:
    from html import escape as html_escape
except ImportError:  # Python 2
    from cgi import escape as html_escape

APP_DIR = os.path.dirname(os.path.abspath(__file__))
STATE_PATH = os.path.join(APP_DIR, 'monitor.state')
TOKENS_DB_PATH = os.path.join(APP_DIR, 'tokens.db')
HEARTBEAT_MAX_AGE = 120
WEB_FAILS_BEFORE_ALERT = 3  # watchdog.sh restarts it within a minute; only a lasting outage alerts
MAX_QUEUED_ALERTS = 200
WEEKLY_WEEKDAY = 6   # Sunday (time.localtime: Monday = 0)
WEEKLY_HOUR = 18

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


def check_failed_actions(state):
    # Each activity row with ok=0 since the last run becomes one event. On the
    # first run, start from the newest row so old failures aren't re-sent.
    try:
        conn = sqlite3.connect(TOKENS_DB_PATH, timeout=10)
        try:
            newest = conn.execute("SELECT MAX(id) FROM activity").fetchone()[0] or 0
            last = state.get('last_activity_id')
            rows = [] if last is None else conn.execute(
                "SELECT ts, actor, action, profile_name, detail FROM activity "
                "WHERE ok = 0 AND id > ? ORDER BY id", (last,)).fetchall()
        finally:
            conn.close()
    except sqlite3.Error:
        return []
    state['last_activity_id'] = newest
    events = []
    for ts, actor, action, profile, detail in rows:
        try:
            detail = json.loads(detail).get('error', detail)  # schedule changes store JSON
        except (TypeError, ValueError, AttributeError):
            pass
        events.append('failed action: %s %s%s at %s - %s' % (
            actor, action, ' for ' + profile if profile else '',
            time.strftime('%H:%M', time.localtime(ts)), detail or 'no detail'))
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

    events.extend(check_failed_actions(state))

    return problems, events


def weekly_recipients():
    # [(email, admin token)] for admin links that ticked the weekly email;
    # each gets their own copy, since the link at the bottom is personal.
    try:
        conn = sqlite3.connect(TOKENS_DB_PATH, timeout=10)
        try:
            return conn.execute(
                "SELECT email, token FROM admin_tokens WHERE weekly = 1 "
                "AND email IS NOT NULL AND email != '' ORDER BY created_at").fetchall()
        finally:
            conn.close()
    except sqlite3.Error:
        return []


def alert_recipients(weekly=False):
    # Admin links with an alert email (managed on the app's admin page); for
    # the weekly summary, only those that also ticked "Weekly usage email".
    query = "SELECT email FROM admin_tokens WHERE email IS NOT NULL AND email != ''"
    if weekly:
        query += " AND weekly = 1"
    try:
        conn = sqlite3.connect(TOKENS_DB_PATH, timeout=10)
        try:
            rows = conn.execute(query).fetchall()
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
    host = socket.gethostname()
    subject = 'Reward Time on %s: %s' % (host, alerts[0][1] if len(alerts) == 1 else '%d alerts' % len(alerts))
    body = '\n'.join('%s  %s' % (time.strftime('%Y-%m-%d %H:%M', time.localtime(ts)), text)
                     for ts, text in alerts)
    return send_mail(recipients, subject, body)


def send_mail(recipients, subject, body, html=None):
    # config.json "smtp": {"host": "smtp.gmail.com", "port": 465,
    #                      "user": "...", "password": "<app password>"}
    smtp = CONFIG.get('smtp')
    if not smtp or not recipients:
        return False
    if html:
        msg = MIMEMultipart('alternative')
        msg.attach(MIMEText(body + '\n', 'plain', 'utf-8'))
        msg.attach(MIMEText(html, 'html', 'utf-8'))
    else:
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


def minutes_text(m):
    hours, mins = divmod(int(m), 60)
    parts = []
    if hours:
        parts.append('%d hr%s' % (hours, '' if hours == 1 else 's'))
    if mins or not parts:
        parts.append('%d min' % mins)
    return ' '.join(parts)


def weekly_data(now):
    # The week's numbers: per-profile internet use, then per-person activity.
    since = now - 7 * 86400
    sa = sqlite3.connect(CONFIG['db_path'], timeout=10)
    try:
        usage = sa.execute(
            "SELECT profile.name, SUM(t.normal_spent) + SUM(t.reward_spent), SUM(t.reward_spent) "
            "FROM profile JOIN config_group ON config_group.profile_id = profile.id "
            "LEFT JOIN config_group_hour_timespent t ON t.parent_id = config_group.id AND t.timestamp >= ? "
            "WHERE profile.visible = 1 AND profile.enable_blocktime = 1 AND profile.name NOT LIKE '$%' "
            "GROUP BY profile.id ORDER BY 2 DESC, profile.name", (since,)).fetchall()
    finally:
        sa.close()
    conn = sqlite3.connect(TOKENS_DB_PATH, timeout=10)
    try:
        people = conn.execute(
            "SELECT actor, actor_kind, "
            "SUM(action IN ('grant', 'set_until') AND ok = 1), "
            "SUM(CASE WHEN action IN ('grant', 'set_until') AND ok = 1 AND minutes > 0 THEN minutes ELSE 0 END), "
            "SUM(action = 'revoke' AND ok = 1), SUM(action = 'pause' AND ok = 1), "
            "SUM(action = 'schedule_set' AND ok = 1), SUM(ok = 0) "
            "FROM activity WHERE ts >= ? GROUP BY actor ORDER BY actor", (since,)).fetchall()
    finally:
        conn.close()
    period = '%s - %s' % (time.strftime('%b %d', time.localtime(since)), time.strftime('%b %d', time.localtime(now)))
    return period, [(n, t or 0, r or 0) for n, t, r in usage], \
        [(a, k, g or 0, m or 0, rv or 0, pz or 0, sc or 0, f or 0) for a, k, g, m, rv, pz, sc, f in people]


def admin_link(token):
    # Opens the app (or the installed web app on a phone) at Admin Access.
    base = CONFIG.get('public_url', '').rstrip('/')
    return '%s/?token=%s#admin-access' % (base, token) if base and token else None


def weekly_report(now, token=None):
    # (subject, plain text, html) for the 7 days up to now.
    period, usage, people = weekly_data(now)
    subject = 'Reward Time weekly summary: %s' % period
    link = admin_link(token)

    text = ['REWARD TIME - WEEK OF %s' % period.upper(), '', 'INTERNET USE', '-' * 12]
    for name, total, reward in usage:
        text.append('  %-22s %-16s%s' % (name, minutes_text(total),
                                         'reward %s' % minutes_text(reward) if reward else ''))
    text += ['', 'ACTIVITY', '-' * 8]
    if not people:
        text.append('  Nothing this week.')
    for actor, kind, grants, minutes, revokes, pauses, schedules, failed in people:
        who = actor + (' (babysitter)' if kind == 'guest' else '')
        text.append('  %s' % who)
        if grants:
            text.append('    Reward time: %d grant%s, %s' % (grants, '' if grants == 1 else 's', minutes_text(minutes)))
        for count, label in ((revokes, 'Revokes'), (pauses, 'Pauses'), (schedules, 'Schedule changes'),
                             (failed, 'FAILED actions')):
            if count:
                text.append('    %s: %d' % (label, count))
    text += ['', 'Manage alerts and this weekly email under Admin Access:', link or '(open the app)']

    cell = 'padding:6px 10px;border-bottom:1px solid #e5e5ea;'
    head = cell + 'text-align:left;color:#6e6e73;font-weight:600;'
    rows_usage = ''.join(
        '<tr><td style="%s">%s</td><td style="%s">%s</td><td style="%s">%s</td><td style="%s">%s</td></tr>' % (
            cell, html_escape(name), cell, minutes_text(total), cell,
            minutes_text(reward) if reward else '&ndash;', cell, minutes_text(total // 7))
        for name, total, reward in usage)
    rows_people = ''.join(
        '<tr><td style="%s">%s</td><td style="%s">%s</td><td style="%s">%s</td><td style="%s">%s</td>'
        '<td style="%s">%s</td><td style="%s">%s</td></tr>' % (
            cell, html_escape(actor) + (' <span style="color:#6e6e73">(babysitter)</span>' if kind == 'guest' else ''),
            cell, ('%d &middot; %s' % (grants, minutes_text(minutes))) if grants else '&ndash;',
            cell, revokes or '&ndash;', cell, pauses or '&ndash;', cell, schedules or '&ndash;',
            cell + ('color:#ff3b30;font-weight:600;' if failed else ''), failed or '&ndash;')
        for actor, kind, grants, minutes, revokes, pauses, schedules, failed in people) or \
        '<tr><td style="%s" colspan="6">Nothing this week.</td></tr>' % cell
    button = ('<p style="margin:28px 0 8px"><a href="%s" style="background:#0a84ff;color:#fff;padding:12px 18px;'
              'border-radius:10px;text-decoration:none;font-weight:600">Open Admin Access</a></p>'
              '<p style="color:#6e6e73;font-size:13px;margin:0">Opens the Reward Time app (the installed app on '
              'your phone) to change alert emails or turn this weekly email off.</p>' % html_escape(link)) \
        if link else '<p style="color:#6e6e73">Turn this off under Admin Access in the app.</p>'
    html = (
        '<div style="font-family:-apple-system,Segoe UI,Roboto,sans-serif;color:#1c1c1e;max-width:600px">'
        '<h2 style="margin:0 0 4px">Reward Time</h2>'
        '<div style="color:#6e6e73;margin-bottom:20px">Week of %s</div>'
        '<h3 style="margin:0 0 6px">Internet use</h3>'
        '<table style="border-collapse:collapse;width:100%%;font-size:14px">'
        '<tr><th style="%s">Kid / device</th><th style="%s">Total</th><th style="%s">Reward</th>'
        '<th style="%s">Per day</th></tr>%s</table>'
        '<h3 style="margin:24px 0 6px">Activity</h3>'
        '<table style="border-collapse:collapse;width:100%%;font-size:14px">'
        '<tr><th style="%s">Who</th><th style="%s">Reward grants</th><th style="%s">Revokes</th>'
        '<th style="%s">Pauses</th><th style="%s">Schedule changes</th><th style="%s">Failed</th></tr>%s</table>'
        '%s</div>' % (html_escape(period), head, head, head, head, rows_usage,
                      head, head, head, head, head, head, rows_people, button))
    return subject, '\n'.join(text), html


def maybe_send_weekly(state, now):
    lt = time.localtime(now)
    week = time.strftime('%Y-%W', lt)
    if lt.tm_wday != WEEKLY_WEEKDAY or lt.tm_hour < WEEKLY_HOUR or state.get('weekly_sent') == week:
        return
    sent = state.setdefault('weekly_sent_to', {})
    if sent.get('week') != week:
        sent.clear()
        sent['week'] = week
    for email, token in weekly_recipients():
        if sent.get(email):
            continue  # already got this week's copy (an earlier run failed part-way)
        try:
            send_mail([email], *weekly_report(now, token))
            sent[email] = True
            log.info('weekly summary sent to %s', email)
        except Exception as exc:
            log.info('could not send weekly summary to %s (will retry): %s', email, exc)
            return
    state['weekly_sent'] = week


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
    maybe_send_weekly(state, now)
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
    if sys.argv[1:] == ['--weekly-preview']:
        subject, text, html = weekly_report(int(time.time()))
        print(subject + '\n\n' + text)
        sys.exit(0)
    if sys.argv[1:] == ['--weekly-now']:
        recipients = weekly_recipients()
        if not recipients:
            sys.exit('No admin link has both an alert email and "Weekly usage email" ticked.')
        for email, token in recipients:
            send_mail([email], *weekly_report(int(time.time()), token))
            print('Sent the weekly summary to: %s' % email)
        sys.exit(0)
    main()
