#!/usr/bin/env python
# Reward-time web app for Synology Safe Access. Python 2.7, stdlib only.
import BaseHTTPServer
import SocketServer
import binascii
import cgi
import json
import logging
import logging.handlers
import os
import re
import socket
import sqlite3
import ssl
import time
import urlparse

REQUEST_TIMEOUT_SECONDS = 20

APP_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(APP_DIR, 'config.json')

with open(CONFIG_PATH) as f:
    CONFIG = json.load(f)

DB_PATH = CONFIG['db_path']
TOKEN = CONFIG['token']
PORT = CONFIG['port']

log = logging.getLogger('reward_server')
log.setLevel(logging.INFO)
_handler = logging.handlers.RotatingFileHandler(
    os.path.join(APP_DIR, 'server.log'), maxBytes=5 * 1024 * 1024, backupCount=1)
_handler.setFormatter(logging.Formatter('%(asctime)s %(message)s'))
log.addHandler(_handler)
CERT_FILE = CONFIG['cert_file']
KEY_FILE = CONFIG['key_file']

PRESETS = [5, 15, 30, 60]
DURATION_PRESETS_HOURS = [4, 8, 24, 48, 72]

TOKENS_DB_PATH = os.path.join(APP_DIR, 'tokens.db')


def get_tokens_db():
    conn = sqlite3.connect(TOKENS_DB_PATH, timeout=10)
    conn.execute(
        "CREATE TABLE IF NOT EXISTS guest_tokens ("
        "token TEXT PRIMARY KEY, label TEXT NOT NULL, "
        "created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL)"
    )
    return conn


def is_admin_token(supplied):
    return len(supplied) == len(TOKEN) and supplied == TOKEN


def is_token_valid(supplied):
    if not supplied:
        return False
    if is_admin_token(supplied):
        return True
    conn = get_tokens_db()
    try:
        row = conn.execute(
            "SELECT 1 FROM guest_tokens WHERE token = ? AND expires_at > ?",
            (supplied, int(time.time()))
        ).fetchone()
        return row is not None
    finally:
        conn.close()


def list_guest_tokens():
    conn = get_tokens_db()
    try:
        now = int(time.time())
        conn.execute("DELETE FROM guest_tokens WHERE expires_at <= ?", (now,))
        conn.commit()
        rows = conn.execute(
            "SELECT token, label, expires_at FROM guest_tokens ORDER BY expires_at"
        ).fetchall()
        return [{'token': t, 'label': label, 'expires_at': exp} for t, label, exp in rows]
    finally:
        conn.close()


def create_guest_token(label, expires_at):
    token = binascii.hexlify(os.urandom(24))
    now = int(time.time())
    conn = get_tokens_db()
    try:
        conn.execute(
            "INSERT INTO guest_tokens (token, label, created_at, expires_at) VALUES (?, ?, ?, ?)",
            (token, label, now, expires_at)
        )
        conn.commit()
    finally:
        conn.close()
    return token


def revoke_guest_token(token):
    conn = get_tokens_db()
    try:
        conn.execute("DELETE FROM guest_tokens WHERE token = ?", (token,))
        conn.commit()
    finally:
        conn.close()


def get_db():
    # DB is written concurrently by SRM's own daemons (WAL mode); short busy timeout avoids
    # SQLITE_BUSY errors when both sides touch it at nearly the same moment.
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.execute('PRAGMA busy_timeout = 10000')
    return conn


def get_profiles():
    conn = get_db()
    try:
        now = int(time.time())
        rows = conn.execute(
            "SELECT profile.id, profile.name "
            "FROM profile JOIN config_group ON config_group.profile_id = profile.id "
            "WHERE profile.visible = 1 AND profile.enable_blocktime = 1 "
            "AND profile.name NOT LIKE '$%' "
            "ORDER BY profile.name"
        ).fetchall()
        profiles = []
        for profile_id, name in rows:
            remaining_row = conn.execute(
                "SELECT MAX(expired) FROM ultra_reward WHERE config_group_id = ? AND expired > ?",
                (profile_id, now)
            ).fetchone()
            remaining = remaining_row[0]
            remaining_minutes = int((remaining - now) / 60) if remaining else 0
            profiles.append({
                'id': profile_id,
                'name': name,
                'remaining_minutes': remaining_minutes,
                'expires_at': remaining if remaining else None,
            })
        return profiles
    finally:
        conn.close()


PENDING_DIR = os.path.join(APP_DIR, 'pending')
APPLY_TIMEOUT_SECONDS = 5
REQUEST_ID_RE = re.compile(r'^[A-Za-z0-9_-]{1,64}$')


def safe_request_id(request_id):
    # Used directly as a filename, so validate strictly.
    if not request_id or not REQUEST_ID_RE.match(request_id):
        raise ValueError('bad request_id')
    return request_id


def enqueue_and_wait(action, config_group_id, request_id, timeout=APPLY_TIMEOUT_SECONDS, **params):
    # Writes are applied by the root-owned apply_daemon via the real Safe Access API
    # (a direct SQLite write here does NOT reliably trigger live enforcement - confirmed
    # the hard way). This app can't call that API itself (root-only), so it hands off
    # the request and waits briefly for the daemon to confirm it actually took effect.
    # request_id is client-supplied so the client can separately poll /api/request_status
    # for progress while this call is blocked waiting.
    base = safe_request_id(request_id)
    if not os.path.isdir(PENDING_DIR):
        os.makedirs(PENDING_DIR)
    req = {'action': action, 'config_group_id': config_group_id}
    req.update(params)
    tmp_path = os.path.join(PENDING_DIR, '.' + base + '.json')
    final_path = os.path.join(PENDING_DIR, base + '.json')
    with open(tmp_path, 'w') as f:
        json.dump(req, f)
    os.rename(tmp_path, final_path)

    done_path = os.path.join(PENDING_DIR, base + '.done')
    error_path = os.path.join(PENDING_DIR, base + '.error')
    deadline = time.time() + timeout
    while time.time() < deadline:
        if os.path.exists(done_path):
            os.remove(done_path)
            return
        if os.path.exists(error_path):
            with open(error_path) as f:
                msg = f.read()
            os.remove(error_path)
            raise RuntimeError(msg or 'apply failed')
        time.sleep(0.1)
    raise RuntimeError('timed out waiting for apply_daemon - is it running?')


def get_request_stage(request_id):
    base = safe_request_id(request_id)
    if os.path.exists(os.path.join(PENDING_DIR, base + '.done')):
        return 'done'
    error_path = os.path.join(PENDING_DIR, base + '.error')
    if os.path.exists(error_path):
        with open(error_path) as f:
            return 'error: ' + f.read()
    status_path = os.path.join(PENDING_DIR, base + '.status')
    if os.path.exists(status_path):
        with open(status_path) as f:
            return f.read().strip() or 'queued'
    if os.path.exists(os.path.join(PENDING_DIR, base + '.json')):
        return 'queued'
    return 'unknown'


def grant_time(profile_id, minutes, request_id):
    enqueue_and_wait('grant', profile_id, request_id, minutes=minutes)


def set_expiry(profile_id, expires_at, request_id):
    enqueue_and_wait('set_until', profile_id, request_id, until=expires_at)


def revoke_time(profile_id, request_id):
    enqueue_and_wait('revoke', profile_id, request_id)


ICON_SVG = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 128 128">
  <rect width="128" height="128" rx="28" fill="#0a84ff"/>
  <rect x="52" y="16" width="24" height="10" rx="5" fill="#eaf3ff"/>
  <circle cx="64" cy="68" r="40" fill="none" stroke="#eaf3ff" stroke-width="8"/>
  <line x1="64" y1="68" x2="64" y2="44" stroke="#eaf3ff" stroke-width="7" stroke-linecap="round"/>
  <line x1="64" y1="68" x2="82" y2="68" stroke="#eaf3ff" stroke-width="7" stroke-linecap="round"/>
  <circle cx="98" cy="94" r="22" fill="#30d158"/>
  <line x1="98" y1="84" x2="98" y2="104" stroke="#052e13" stroke-width="6" stroke-linecap="round"/>
  <line x1="88" y1="94" x2="108" y2="94" stroke="#052e13" stroke-width="6" stroke-linecap="round"/>
</svg>
"""

PAGE_TEMPLATE = """<!doctype html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1">
<meta name="theme-color" content="#0a84ff">
<title>Reward Time</title>
<link rel="icon" type="image/svg+xml" href="/icon.svg">
<link rel="apple-touch-icon" href="/icon.svg">
<style>
  body { font-family: -apple-system, sans-serif; background: #111; color: #eee; margin: 0;
         padding: 16px; font-size: 17px; max-width: 480px; margin-left: auto; margin-right: auto; }
  h1 { font-size: 24px; font-weight: 700; margin: 4px 0 18px; }
  .card { background: #1c1c1e; border-radius: 14px; padding: 16px; margin-bottom: 14px; }
  .card-head { display: flex; justify-content: space-between; align-items: center; cursor: pointer; }
  .move-btns { display: flex; gap: 6px; flex: none; }
  .move { flex: none; width: 48px; height: 48px; padding: 0; font-size: 18px;
          background: #2c2c2e; color: #b0b0b5; border-radius: 8px; }
  .move:disabled { opacity: 0.3; }
  .name { font-size: 20px; font-weight: 700; margin-bottom: 4px; }
  .remaining { font-size: 18px; color: #b8b8bd; margin-bottom: 14px; }
  .card.collapsed .remaining { margin-bottom: 0; }
  .card.collapsed .btns { display: none; }
  .card.collapsed .add-token-body { display: none; }
  .add-token-body { margin-top: 14px; }
  .btns { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; }
  button { padding: 18px 0; border: none; border-radius: 10px; background: #0a84ff;
           color: white; font-size: 19px; font-weight: 700; }
  button:active { background: #0060df; }
  .revoke { grid-column: 1 / -1; background: transparent; border: 1px solid #ff453a;
            color: #ff453a; padding: 14px 0; font-size: 15px; margin-top: 2px; }
  .revoke:active { background: rgba(255, 69, 58, 0.15); }
  .card.collapsed .custom-btn { display: none; }
  .custom-btn { grid-column: 1 / -1; background: #2c2c2e; margin-top: 2px; }
  .modal-backdrop { position: fixed; inset: 0; background: rgba(0,0,0,0.6); display: none;
                     align-items: center; justify-content: center; z-index: 100;
                     padding: 16px; box-sizing: border-box; }
  .modal-backdrop.open { display: flex; }
  .modal-box { background: #1c1c1e; border-radius: 16px; padding: 20px; width: 100%;
               max-width: 340px; max-height: 90vh; overflow-y: auto; box-sizing: border-box; }
  .modal-title { font-size: 18px; font-weight: 700; margin-bottom: 14px; text-align: center; }
  .spinner { display: inline-block; width: 15px; height: 15px; border: 2px solid rgba(255,255,255,0.35);
             border-top-color: #fff; border-radius: 50%; animation: spin 0.7s linear infinite;
             vertical-align: middle; margin-left: 6px; }
  @keyframes spin { to { transform: rotate(360deg); } }
  .modal-status-line { text-align: center; font-size: 14px; color: #9b9ba1; margin: -6px 0 14px; }
  .date-picker-wrap { position: relative; margin-bottom: 16px; }
  .date-toggle-btn { width: 100%; background: #2c2c2e; font-size: 15px; padding: 10px 0; }
  .cal-panel { display: none; position: absolute; top: calc(100% + 8px); left: 0; right: 0;
               background: #262628; border: 1px solid #3a3a3c; border-radius: 12px; padding: 14px;
               z-index: 10; box-shadow: 0 8px 24px rgba(0,0,0,0.45); box-sizing: border-box; }
  .cal-panel.open { display: block; }
  .cal-header { display: flex; align-items: center; justify-content: space-between; margin-bottom: 10px; }
  .cal-nav { flex: none; width: 40px; height: 40px; padding: 0; font-size: 20px;
             background: #2c2c2e; border-radius: 8px; }
  .cal-nav:disabled { opacity: 0.3; }
  .cal-month-label { font-size: 16px; font-weight: 600; }
  .cal-weekdays { display: grid; grid-template-columns: repeat(7, 1fr); text-align: center;
                  font-size: 12px; color: #8e8e93; margin-bottom: 4px; }
  .cal-grid { display: grid; grid-template-columns: repeat(7, 1fr); gap: 4px; }
  .cal-day { aspect-ratio: 1; padding: 0; font-size: 15px; font-weight: 600;
             background: transparent; color: #eee; border-radius: 8px; }
  .cal-day:disabled { color: #4a4a4c; }
  .cal-day.selected { background: #0a84ff; }
  .cal-day.empty { visibility: hidden; }
  .time-columns-header { display: flex; gap: 8px; text-align: center; font-size: 13px;
                          color: #8e8e93; font-weight: 600; margin-bottom: 6px; }
  .time-columns-header div { flex: 1; }
  .time-columns { display: flex; gap: 8px; margin-bottom: 18px; }
  .time-col { flex: 1; display: flex; flex-direction: column; gap: 6px; }
  .time-col button { flex: none; padding: 10px 0; font-size: 16px; font-weight: 600; background: #2c2c2e; }
  .time-col button.selected { background: #0a84ff; }
  .modal-actions { display: flex; gap: 10px; }
  .modal-actions button { flex: 1; padding: 14px 0; }
  .modal-cancel-btn { background: #2c2c2e; }
  .toast { position: fixed; bottom: 24px; left: 16px; right: 16px; background: #30d158;
           color: #052e13; padding: 16px; border-radius: 12px; text-align: center;
           font-size: 17px; font-weight: 700; display: none; }
  h2 { font-size: 18px; font-weight: 700; margin: 24px 0 10px; }
  .guest-row { display: flex; justify-content: space-between; align-items: center;
               background: #1c1c1e; border-radius: 10px; padding: 12px 14px; margin-bottom: 8px; }
  .guest-row .label { font-weight: 600; }
  .guest-row .expires { font-size: 13px; color: #9b9ba1; }
  .guest-row-btns { display: flex; gap: 6px; flex: none; }
  .guest-row-btns button { flex: none; width: auto; padding: 8px 12px; font-size: 13px; }
  .copy-guest { background: #2c2c2e; color: #eee; }
  .revoke-guest { background: transparent; border: 1px solid #ff453a; color: #ff453a; }
  .guest-label-input { width: 100%; box-sizing: border-box; padding: 14px; font-size: 16px;
                        border-radius: 10px; border: 1px solid #3a3a3c; background: #1c1c1e;
                        color: #eee; margin-bottom: 10px; }
  .guest-duration-btns { display: grid; grid-template-columns: 1fr 1fr; gap: 8px; }
  .guest-duration-btns button { background: #2c2c2e; font-size: 15px; padding: 12px 0; }
  .share-url { display: block; width: 100%; box-sizing: border-box; padding: 10px;
               border-radius: 8px; border: 1px solid #3a3a3c; background: #111; color: #9b9ba1;
               font-size: 13px; margin-bottom: 8px; word-break: break-all; }
</style>
</head>
<body>
<h1>Reward Time</h1>
<div id="cards"></div>
<div id="admin-section" style="display:none">
  <h2>Babysitter Access</h2>
  <div class="card" id="add-token-card">
    <div class="card-head" data-card-id="-1"><div class="name">Add a token</div></div>
    <div class="add-token-body">
      <input class="guest-label-input" id="guest-label" placeholder="Who is this for? (e.g. Grandma)">
      <div class="guest-duration-btns" id="guest-duration-btns"></div>
    </div>
  </div>
  <div id="guest-tokens-list"></div>
</div>
<div class="toast" id="toast"></div>
<div class="modal-backdrop" id="share-modal-backdrop">
  <div class="modal-box">
    <div class="modal-title">Share this link</div>
    <input class="share-url" id="share-url-input" readonly>
    <div class="modal-actions">
      <button type="button" class="modal-cancel-btn" id="share-modal-close">Done</button>
      <button type="button" id="copy-share-url">Copy Link</button>
    </div>
  </div>
</div>
<div class="modal-backdrop" id="modal-backdrop">
  <div class="modal-box">
    <div class="modal-title" id="modal-title">Custom time</div>
    <div class="modal-status-line" id="modal-status-line"></div>
    <div class="date-picker-wrap">
      <button type="button" class="date-toggle-btn" id="date-toggle-btn">Today</button>
      <div class="cal-panel" id="cal-panel">
        <div class="cal-header">
          <button type="button" class="cal-nav" id="cal-prev">&#8249;</button>
          <div class="cal-month-label" id="cal-month-label"></div>
          <button type="button" class="cal-nav" id="cal-next">&#8250;</button>
        </div>
        <div class="cal-weekdays"><div>S</div><div>M</div><div>T</div><div>W</div><div>T</div><div>F</div><div>S</div></div>
        <div class="cal-grid" id="cal-grid"></div>
      </div>
    </div>
    <div class="time-columns-header"><div>Hour</div><div>Min</div><div>&nbsp;</div></div>
    <div class="time-columns">
      <div class="time-col" id="hour-grid"></div>
      <div class="time-col" id="minute-grid"></div>
      <div class="time-col" id="ampm-row"></div>
    </div>
    <div class="modal-actions">
      <button type="button" class="modal-cancel-btn" id="modal-cancel-btn">Cancel</button>
      <button type="button" id="modal-set-btn">Set</button>
    </div>
  </div>
</div>
<script>
var TOKEN = new URLSearchParams(location.search).get('token') || localStorage.getItem('rt_token') || '';
if (TOKEN) { localStorage.setItem('rt_token', TOKEN); }
var PRESETS = __PRESETS__;
var DURATION_PRESETS = __DURATION_PRESETS__;

var modalContext = null; // { type: 'reward', profileId } or { type: 'guest' }
var calendarViewDate = new Date();
var selectedDay = null;
var selectedHour = 12;
var selectedMinute = 0;
var selectedAmPm = 'AM';

function pad2(n) { return (n < 10 ? '0' : '') + n; }

function sameDay(a, b) {
  return a.getFullYear() === b.getFullYear() && a.getMonth() === b.getMonth() && a.getDate() === b.getDate();
}

function scrollSelectedIntoView(container) {
  var sel = container.querySelector('.selected');
  if (sel) sel.scrollIntoView({ block: 'nearest' });
}

function renderHourGrid() {
  var html = '';
  for (var h = 1; h <= 12; h++) {
    html += '<button type="button" class="' + (h === selectedHour ? 'selected' : '') +
            '" data-hour="' + h + '">' + h + '</button>';
  }
  var el = document.getElementById('hour-grid');
  el.innerHTML = html;
  scrollSelectedIntoView(el);
}

function renderMinuteGrid() {
  var html = '';
  for (var m = 0; m < 60; m += 5) {
    html += '<button type="button" class="' + (m === selectedMinute ? 'selected' : '') +
            '" data-minute="' + m + '">' + pad2(m) + '</button>';
  }
  var el = document.getElementById('minute-grid');
  el.innerHTML = html;
  scrollSelectedIntoView(el);
}

function renderAmPm() {
  document.getElementById('ampm-row').innerHTML = ['AM', 'PM'].map(function (v) {
    return '<button type="button" class="' + (v === selectedAmPm ? 'selected' : '') +
           '" data-ampm="' + v + '">' + v + '</button>';
  }).join('');
}

function formatDateButtonLabel() {
  var today = new Date();
  today.setHours(0, 0, 0, 0);
  if (sameDay(selectedDay, today)) return 'Today';
  var tomorrow = new Date(today);
  tomorrow.setDate(tomorrow.getDate() + 1);
  if (sameDay(selectedDay, tomorrow)) return 'Tomorrow';
  return selectedDay.toLocaleDateString([], { weekday: 'short', month: 'short', day: 'numeric' });
}

function updateDateButton() {
  document.getElementById('date-toggle-btn').textContent = formatDateButtonLabel();
}

function setDefaultTime() {
  var now = new Date();
  var rounded = new Date(Math.ceil(now.getTime() / 300000) * 300000);
  var hour24 = rounded.getHours();
  selectedHour = hour24 % 12 || 12;
  selectedMinute = rounded.getMinutes() - (rounded.getMinutes() % 5);
  selectedAmPm = hour24 >= 12 ? 'PM' : 'AM';
}

function renderCalendarGrid() {
  var year = calendarViewDate.getFullYear();
  var month = calendarViewDate.getMonth();
  var today = new Date();
  today.setHours(0, 0, 0, 0);
  document.getElementById('cal-month-label').textContent =
    calendarViewDate.toLocaleDateString([], { month: 'long', year: 'numeric' });
  var firstWeekday = new Date(year, month, 1).getDay();
  var daysInMonth = new Date(year, month + 1, 0).getDate();
  var html = '';
  for (var i = 0; i < firstWeekday; i++) html += '<button class="cal-day empty" disabled></button>';
  for (var d = 1; d <= daysInMonth; d++) {
    var thisDate = new Date(year, month, d);
    var isPast = thisDate < today;
    var isSelected = selectedDay && sameDay(selectedDay, thisDate);
    html += '<button type="button" class="cal-day' + (isSelected ? ' selected' : '') + '"' +
            (isPast ? ' disabled' : ' data-day="' + d + '"') + '>' + d + '</button>';
  }
  document.getElementById('cal-grid').innerHTML = html;
  document.getElementById('cal-prev').disabled =
    (year === today.getFullYear() && month === today.getMonth());
}

function openPicker(context) {
  modalContext = context;
  calendarViewDate = new Date();
  selectedDay = new Date();
  selectedDay.setHours(0, 0, 0, 0);
  setDefaultTime();
  renderHourGrid();
  renderMinuteGrid();
  renderAmPm();
  renderCalendarGrid();
  updateDateButton();
  document.getElementById('cal-panel').classList.remove('open');
  document.getElementById('modal-title').textContent =
    context.type === 'reward' ? 'Custom reward time' : 'Custom access length';
  document.getElementById('modal-status-line').textContent = '';
  document.getElementById('modal-backdrop').classList.add('open');
}

function closePicker() {
  document.getElementById('modal-backdrop').classList.remove('open');
  modalContext = null;
}

function getPickerEpoch() {
  var hour24 = (selectedHour % 12) + (selectedAmPm === 'PM' ? 12 : 0);
  var d = new Date(selectedDay.getFullYear(), selectedDay.getMonth(), selectedDay.getDate(),
                    hour24, selectedMinute, 0, 0);
  return Math.floor(d.getTime() / 1000);
}

function submitPicker() {
  var epoch = getPickerEpoch();
  if (epoch <= Math.floor(Date.now() / 1000)) {
    toast('Pick a time in the future');
    return;
  }
  var setBtn = document.getElementById('modal-set-btn');
  var cancelBtn = document.getElementById('modal-cancel-btn');
  var statusLine = document.getElementById('modal-status-line');
  setBusy(setBtn, true);
  cancelBtn.disabled = true;

  var request, modalPoll;
  if (modalContext.type === 'reward') {
    var modalReqId = newRequestId();
    modalPoll = pollRequestStatus(modalReqId, function (label) { statusLine.textContent = label; });
    request = fetch('/api/set_until?token=' + encodeURIComponent(TOKEN) +
          '&profile_id=' + modalContext.profileId + '&until=' + epoch +
          '&request_id=' + modalReqId, { method: 'POST' })
      .then(parseResponse)
      .then(function () {
        toast('Reward time set');
        loadProfiles();
      });
  } else {
    var label = document.getElementById('guest-label').value.trim() || 'Guest';
    request = fetch('/api/tokens/create?token=' + encodeURIComponent(TOKEN) +
          '&label=' + encodeURIComponent(label) + '&until=' + epoch, { method: 'POST' })
      .then(parseResponse)
      .then(function (result) {
        showShareBox(guestUrl(result.token));
        document.getElementById('guest-label').value = '';
        loadGuestTokens();
        toast('Access link created');
      });
  }
  request
    .catch(function (err) { toast(err.message || 'Failed - check connection'); })
    .finally(function () {
      setBusy(setBtn, false);
      cancelBtn.disabled = false;
      if (modalPoll) clearInterval(modalPoll);
      closePicker();
    });
}

function formatDuration(hours) {
  if (hours < 24) return hours + 'h';
  var days = hours / 24;
  return days + (days === 1 ? ' day' : ' days');
}

function formatRemaining(totalMinutes) {
  var days = Math.floor(totalMinutes / 1440);
  var hours = Math.floor((totalMinutes % 1440) / 60);
  var minutes = totalMinutes % 60;
  var parts = [];
  if (days) parts.push(days + (days === 1 ? ' day' : ' days'));
  if (hours) parts.push(hours + (hours === 1 ? ' hr' : ' hrs'));
  if (minutes || !parts.length) parts.push(minutes + ' min');
  return parts.join(' ');
}

function formatUntil(epochSeconds) {
  var d = new Date(epochSeconds * 1000);
  var isToday = d.toDateString() === new Date().toDateString();
  return isToday
    ? d.toLocaleTimeString([], { hour: 'numeric', minute: '2-digit' })
    : d.toLocaleString([], { month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit' });
}

function parseResponse(r) {
  if (r.ok) return r.json();
  return r.json().catch(function () { return {}; }).then(function (body) {
    throw new Error(body.error || ('Failed (HTTP ' + r.status + ')'));
  });
}

function toast(msg) {
  var t = document.getElementById('toast');
  t.textContent = msg;
  t.style.display = 'block';
  setTimeout(function () { t.style.display = 'none'; }, 1800);
}

function setBusy(btn, busy) {
  if (busy) {
    btn.dataset.origText = btn.textContent;
    btn.innerHTML = '<span class="spinner"></span>';
    btn.disabled = true;
  } else {
    btn.textContent = btn.dataset.origText;
    btn.disabled = false;
  }
}

function newRequestId() {
  return Date.now().toString(36) + Math.random().toString(36).slice(2, 10);
}

var STAGE_LABELS = {
  queued: 'Sending request...',
  checking: 'Checking current status...',
  applying: 'Applying change...'
};

function pollRequestStatus(requestId, onStage) {
  return setInterval(function () {
    fetch('/api/request_status?token=' + encodeURIComponent(TOKEN) + '&request_id=' + requestId)
      .then(function (r) { return r.json(); })
      .then(function (data) { if (STAGE_LABELS[data.stage]) onStage(STAGE_LABELS[data.stage]); })
      .catch(function () {});
  }, 250);
}

var lastProfiles = [];

function loadOrder() {
  try { return JSON.parse(localStorage.getItem('rt_order') || '[]'); } catch (e) { return []; }
}

function saveOrder(ids) {
  try { localStorage.setItem('rt_order', JSON.stringify(ids)); } catch (e) {}
}

function loadExpanded() {
  try { return JSON.parse(localStorage.getItem('rt_expanded') || '[]'); } catch (e) { return []; }
}

function saveExpanded(ids) {
  try { localStorage.setItem('rt_expanded', JSON.stringify(ids)); } catch (e) {}
}

var ADD_TOKEN_CARD_ID = -1;

function toggleExpanded(id) {
  var expandedIds = loadExpanded();
  var pos = expandedIds.indexOf(id);
  if (pos === -1) { expandedIds.push(id); } else { expandedIds.splice(pos, 1); }
  saveExpanded(expandedIds);
  render(lastProfiles);
  updateAddTokenCardCollapsedState();
}

function updateAddTokenCardCollapsedState() {
  var isCollapsed = loadExpanded().indexOf(ADD_TOKEN_CARD_ID) === -1;
  document.getElementById('add-token-card').classList.toggle('collapsed', isCollapsed);
}

function applyOrder(profiles) {
  var order = loadOrder();
  if (!order.length) return profiles.slice();
  var byId = {};
  profiles.forEach(function (p) { byId[p.id] = p; });
  var ordered = order.filter(function (id) { return byId[id]; }).map(function (id) { return byId[id]; });
  profiles.forEach(function (p) { if (order.indexOf(p.id) === -1) ordered.push(p); });
  return ordered;
}

function render(profiles) {
  lastProfiles = profiles;
  var ordered = applyOrder(profiles);
  var expanded = loadExpanded();
  var el = document.getElementById('cards');
  el.innerHTML = '';
  ordered.forEach(function (p, idx) {
    var isCollapsed = expanded.indexOf(p.id) === -1;
    var card = document.createElement('div');
    card.className = 'card' + (isCollapsed ? ' collapsed' : '');
    var remainingText = 'No active reward time';
    if (p.remaining_minutes > 0 && p.expires_at) {
      remainingText = formatRemaining(p.remaining_minutes) + ' remaining (until ' + formatUntil(p.expires_at) + ')';
    }
    var btns = PRESETS.map(function (m) {
      return '<button data-id="' + p.id + '" data-minutes="' + m + '">+' + m + 'm</button>';
    }).join('');
    var revokeBtnHtml = '<button class="revoke" data-revoke-id="' + p.id + '">Revoke</button>';
    var moveBtns = '<div class="move-btns">' +
      '<button class="move" data-move-id="' + p.id + '" data-dir="up"' + (idx === 0 ? ' disabled' : '') + '>&#9650;</button>' +
      '<button class="move" data-move-id="' + p.id + '" data-dir="down"' + (idx === ordered.length - 1 ? ' disabled' : '') + '>&#9660;</button>' +
      '</div>';
    var untilRow = '<button class="custom-btn" data-open-reward-picker="' + p.id + '">Custom</button>';
    card.innerHTML = '<div class="card-head" data-card-id="' + p.id + '"><div class="name">' + p.name + '</div>' + moveBtns + '</div>' +
                      '<div class="remaining" data-remaining="' + p.id + '">' + remainingText + '</div>' +
                      '<div class="btns">' + btns + untilRow + revokeBtnHtml + '</div>';
    el.appendChild(card);
  });
}

var isAdmin = false;

function loadProfiles() {
  fetch('/api/status?token=' + encodeURIComponent(TOKEN))
    .then(function (r) { return r.json(); })
    .then(function (data) {
      render(data.profiles);
      isAdmin = data.is_admin;
      var section = document.getElementById('admin-section');
      section.style.display = isAdmin ? 'block' : 'none';
      if (isAdmin) {
        renderDurationButtons();
        loadGuestTokens();
        updateAddTokenCardCollapsedState();
      }
    });
}

function renderDurationButtons() {
  var el = document.getElementById('guest-duration-btns');
  if (el.childElementCount) return;
  var presetBtns = DURATION_PRESETS.map(function (h) {
    return '<button data-guest-hours="' + h + '">' + formatDuration(h) + '</button>';
  }).join('');
  var customPicker = '<button class="custom-btn" data-open-guest-picker="1">Custom</button>';
  el.innerHTML = presetBtns + customPicker;
}

function loadGuestTokens() {
  fetch('/api/tokens?token=' + encodeURIComponent(TOKEN))
    .then(function (r) { return r.json(); })
    .then(function (tokens) {
      var el = document.getElementById('guest-tokens-list');
      if (!tokens.length) { el.innerHTML = ''; return; }
      el.innerHTML = tokens.map(function (t) {
        var expiresStr = new Date(t.expires_at * 1000).toLocaleString([],
          { month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit' });
        return '<div class="guest-row"><div><div class="label">' + t.label + '</div>' +
               '<div class="expires">until ' + expiresStr + '</div></div>' +
               '<div class="guest-row-btns">' +
               '<button class="copy-guest" data-copy-guest="' + t.token + '">Copy</button>' +
               '<button class="revoke-guest" data-revoke-guest="' + t.token + '">Revoke</button>' +
               '</div></div>';
      }).join('');
    });
}

function copyText(text) {
  var done = function () { toast('Link copied'); };
  var fail = function () { toast('Copy failed - long-press the link to copy manually'); };
  if (navigator.clipboard) {
    navigator.clipboard.writeText(text).then(done, fail);
  } else {
    var tmp = document.createElement('textarea');
    tmp.value = text;
    tmp.style.position = 'fixed';
    tmp.style.opacity = '0';
    document.body.appendChild(tmp);
    tmp.select();
    try { document.execCommand('copy'); done(); } catch (e) { fail(); }
    document.body.removeChild(tmp);
  }
}

function guestUrl(token) {
  return location.origin + location.pathname + '?token=' + encodeURIComponent(token);
}

function showShareBox(url) {
  document.getElementById('share-url-input').value = url;
  document.getElementById('share-modal-backdrop').classList.add('open');
}


document.addEventListener('click', function (e) {
  var grantBtn = e.target.closest('button[data-id]');
  if (grantBtn) {
    setBusy(grantBtn, true);
    var grantReqId = newRequestId();
    var grantRemainingEl = document.querySelector('[data-remaining="' + grantBtn.dataset.id + '"]');
    var grantOrigText = grantRemainingEl ? grantRemainingEl.textContent : null;
    var grantPoll = pollRequestStatus(grantReqId, function (label) {
      if (grantRemainingEl) grantRemainingEl.textContent = label;
    });
    fetch('/api/grant?token=' + encodeURIComponent(TOKEN) +
          '&profile_id=' + grantBtn.dataset.id + '&minutes=' + grantBtn.dataset.minutes +
          '&request_id=' + grantReqId, { method: 'POST' })
      .then(parseResponse)
      .then(function () {
        toast('+' + grantBtn.dataset.minutes + ' min added');
        loadProfiles();
      })
      .catch(function (err) {
        toast(err.message || 'Failed - check connection');
        if (grantRemainingEl && grantOrigText !== null) grantRemainingEl.textContent = grantOrigText;
      })
      .finally(function () { setBusy(grantBtn, false); clearInterval(grantPoll); });
    return;
  }

  var revokeBtn = e.target.closest('button[data-revoke-id]');
  if (revokeBtn) {
    setBusy(revokeBtn, true);
    var revokeReqId = newRequestId();
    var revokeRemainingEl = document.querySelector('[data-remaining="' + revokeBtn.dataset.revokeId + '"]');
    var revokeOrigText = revokeRemainingEl ? revokeRemainingEl.textContent : null;
    var revokePoll = pollRequestStatus(revokeReqId, function (label) {
      if (revokeRemainingEl) revokeRemainingEl.textContent = label;
    });
    fetch('/api/revoke?token=' + encodeURIComponent(TOKEN) +
          '&profile_id=' + revokeBtn.dataset.revokeId + '&request_id=' + revokeReqId, { method: 'POST' })
      .then(parseResponse)
      .then(function () {
        toast('Reward time revoked');
        loadProfiles();
      })
      .catch(function (err) {
        toast(err.message || 'Failed - check connection');
        if (revokeRemainingEl && revokeOrigText !== null) revokeRemainingEl.textContent = revokeOrigText;
      })
      .finally(function () { setBusy(revokeBtn, false); clearInterval(revokePoll); });
    return;
  }

  var moveBtn = e.target.closest('button[data-move-id]');
  if (moveBtn && !moveBtn.disabled) {
    var ids = applyOrder(lastProfiles).map(function (p) { return p.id; });
    var idx = ids.indexOf(Number(moveBtn.dataset.moveId));
    var swapWith = moveBtn.dataset.dir === 'up' ? idx - 1 : idx + 1;
    if (idx !== -1 && swapWith >= 0 && swapWith < ids.length) {
      var tmp = ids[idx];
      ids[idx] = ids[swapWith];
      ids[swapWith] = tmp;
      saveOrder(ids);
      render(lastProfiles);
    }
    return;
  }

  var cardHead = e.target.closest('.card-head');
  if (cardHead) {
    toggleExpanded(Number(cardHead.dataset.cardId));
    return;
  }

  var durationBtn = e.target.closest('button[data-guest-hours]');
  if (durationBtn) {
    var label = document.getElementById('guest-label').value.trim() || 'Guest';
    setBusy(durationBtn, true);
    fetch('/api/tokens/create?token=' + encodeURIComponent(TOKEN) +
          '&label=' + encodeURIComponent(label) + '&hours=' + durationBtn.dataset.guestHours,
          { method: 'POST' })
      .then(parseResponse)
      .then(function (result) {
        var url = guestUrl(result.token);
        showShareBox(url);
        document.getElementById('guest-label').value = '';
        loadGuestTokens();
        toast('Access link created');
      })
      .catch(function (err) { toast(err.message || 'Failed - check connection'); })
      .finally(function () { setBusy(durationBtn, false); });
    return;
  }

  var revokeGuestBtn = e.target.closest('button[data-revoke-guest]');
  if (revokeGuestBtn) {
    revokeGuestBtn.disabled = true;
    fetch('/api/tokens/revoke?token=' + encodeURIComponent(TOKEN) +
          '&guest_token=' + encodeURIComponent(revokeGuestBtn.dataset.revokeGuest), { method: 'POST' })
      .then(parseResponse)
      .then(function () {
        toast('Access revoked');
        loadGuestTokens();
      })
      .catch(function (err) { toast(err.message || 'Failed - check connection'); })
      .finally(function () { revokeGuestBtn.disabled = false; });
    return;
  }

  if (e.target.id === 'copy-share-url') {
    copyText(document.getElementById('share-url-input').value);
    return;
  }

  if (e.target.id === 'share-modal-close' || e.target.id === 'share-modal-backdrop') {
    document.getElementById('share-modal-backdrop').classList.remove('open');
    return;
  }

  var copyGuestBtn = e.target.closest('button[data-copy-guest]');
  if (copyGuestBtn) {
    copyText(guestUrl(copyGuestBtn.dataset.copyGuest));
    return;
  }

  var openRewardBtn = e.target.closest('button[data-open-reward-picker]');
  if (openRewardBtn) {
    openPicker({ type: 'reward', profileId: openRewardBtn.dataset.openRewardPicker });
    return;
  }

  var openGuestBtn = e.target.closest('button[data-open-guest-picker]');
  if (openGuestBtn) {
    openPicker({ type: 'guest' });
    return;
  }

  if (e.target.id === 'cal-prev' || e.target.id === 'cal-next') {
    calendarViewDate.setMonth(calendarViewDate.getMonth() + (e.target.id === 'cal-next' ? 1 : -1));
    renderCalendarGrid();
    return;
  }

  var dayBtn = e.target.closest('.cal-day[data-day]');
  if (dayBtn) {
    selectedDay = new Date(calendarViewDate.getFullYear(), calendarViewDate.getMonth(), Number(dayBtn.dataset.day));
    updateDateButton();
    document.getElementById('cal-panel').classList.remove('open');
    return;
  }

  if (e.target.id === 'date-toggle-btn') {
    document.getElementById('cal-panel').classList.toggle('open');
    return;
  }

  var hourBtn = e.target.closest('#hour-grid button[data-hour]');
  if (hourBtn) {
    selectedHour = Number(hourBtn.dataset.hour);
    renderHourGrid();
    return;
  }

  var minuteBtn = e.target.closest('#minute-grid button[data-minute]');
  if (minuteBtn) {
    selectedMinute = Number(minuteBtn.dataset.minute);
    renderMinuteGrid();
    return;
  }

  var ampmBtn = e.target.closest('#ampm-row button[data-ampm]');
  if (ampmBtn) {
    selectedAmPm = ampmBtn.dataset.ampm;
    renderAmPm();
    return;
  }

  if (e.target.id === 'modal-set-btn') {
    submitPicker();
    return;
  }

  if (e.target.id === 'modal-cancel-btn' || e.target.id === 'modal-backdrop') {
    closePicker();
  }
});

loadProfiles();
</script>
</body>
</html>
"""


class Handler(BaseHTTPServer.BaseHTTPRequestHandler):
    # Without this, a slow/incomplete connection (scanner bots hit this port constantly
    # since it's open to the internet) can hang a handler thread indefinitely.
    timeout = REQUEST_TIMEOUT_SECONDS

    def setup(self):
        self.request.settimeout(REQUEST_TIMEOUT_SECONDS)
        BaseHTTPServer.BaseHTTPRequestHandler.setup(self)
        self._handshake_ok = True
        try:
            self.request.do_handshake()
        except (socket.timeout, ssl.SSLError):
            # Not a real client (scanner probing the port, incomplete/garbage TLS) - bail
            # out of this connection only; other threads are unaffected.
            self._handshake_ok = False

    def handle(self):
        if not self._handshake_ok:
            return
        try:
            BaseHTTPServer.BaseHTTPRequestHandler.handle(self)
        except (socket.timeout, ssl.SSLError):
            pass

    def _supplied_token(self, qs):
        supplied = qs.get('token', [''])[0]
        auth = self.headers.getheader('Authorization', '')
        if auth.startswith('Bearer '):
            supplied = auth[len('Bearer '):]
        return supplied

    def _request_id(self, qs):
        supplied = qs.get('request_id', [''])[0]
        if supplied and REQUEST_ID_RE.match(supplied):
            return supplied
        return '%d_%s' % (int(time.time() * 1000), binascii.hexlify(os.urandom(4)))

    def _token_ok(self, qs):
        return is_token_valid(self._supplied_token(qs))

    def _send_json(self, obj, status=200):
        body = json.dumps(obj)
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_html(self, body, status=200):
        self.send_response(status)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed = urlparse.urlparse(self.path)
        qs = urlparse.parse_qs(parsed.query)

        if parsed.path == '/icon.svg':
            body = ICON_SVG
            self.send_response(200)
            self.send_header('Content-Type', 'image/svg+xml')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        if parsed.path == '/':
            if not self._token_ok(qs):
                self._send_html('<h1>Forbidden</h1>', status=403)
                return
            page = PAGE_TEMPLATE.replace('__PRESETS__', json.dumps(PRESETS))
            page = page.replace('__DURATION_PRESETS__', json.dumps(DURATION_PRESETS_HOURS))
            self._send_html(page)
            return

        if parsed.path == '/api/status':
            if not self._token_ok(qs):
                self._send_json({'error': 'forbidden'}, status=403)
                return
            self._send_json({
                'profiles': get_profiles(),
                'is_admin': is_admin_token(self._supplied_token(qs)),
            })
            return

        if parsed.path == '/api/tokens':
            if not is_admin_token(self._supplied_token(qs)):
                self._send_json({'error': 'forbidden'}, status=403)
                return
            self._send_json(list_guest_tokens())
            return

        if parsed.path == '/api/request_status':
            if not self._token_ok(qs):
                self._send_json({'error': 'forbidden'}, status=403)
                return
            request_id = qs.get('request_id', [''])[0]
            try:
                stage = get_request_stage(request_id)
            except ValueError:
                self._send_json({'error': 'bad request'}, status=400)
                return
            self._send_json({'stage': stage})
            return

        self._send_html('<h1>Not found</h1>', status=404)

    def do_POST(self):
        parsed = urlparse.urlparse(self.path)
        qs = urlparse.parse_qs(parsed.query)

        if parsed.path == '/api/grant':
            if not self._token_ok(qs):
                self._send_json({'error': 'forbidden'}, status=403)
                return
            try:
                profile_id = int(qs['profile_id'][0])
                minutes = int(qs['minutes'][0])
            except (KeyError, ValueError):
                self._send_json({'error': 'bad request'}, status=400)
                return
            if minutes <= 0 or minutes > 24 * 60:
                self._send_json({'error': 'minutes out of range'}, status=400)
                return
            try:
                grant_time(profile_id, minutes, self._request_id(qs))
            except Exception as exc:
                log.exception('grant failed for profile_id=%s minutes=%s', profile_id, minutes)
                self._send_json({'error': str(exc)}, status=500)
                return
            self._send_json({'ok': True})
            return

        if parsed.path == '/api/revoke':
            if not self._token_ok(qs):
                self._send_json({'error': 'forbidden'}, status=403)
                return
            try:
                profile_id = int(qs['profile_id'][0])
            except (KeyError, ValueError):
                self._send_json({'error': 'bad request'}, status=400)
                return
            try:
                revoke_time(profile_id, self._request_id(qs))
            except Exception as exc:
                log.exception('revoke failed for profile_id=%s', profile_id)
                self._send_json({'error': str(exc)}, status=500)
                return
            self._send_json({'ok': True})
            return

        if parsed.path == '/api/set_until':
            if not self._token_ok(qs):
                self._send_json({'error': 'forbidden'}, status=403)
                return
            try:
                profile_id = int(qs['profile_id'][0])
                until = int(qs['until'][0])
            except (KeyError, ValueError):
                self._send_json({'error': 'bad request'}, status=400)
                return
            now = int(time.time())
            if until <= now or until > now + 32 * 24 * 3600:
                self._send_json({'error': 'Pick a date within one month from today'}, status=400)
                return
            try:
                set_expiry(profile_id, until, self._request_id(qs))
            except Exception as exc:
                log.exception('set_until failed for profile_id=%s', profile_id)
                self._send_json({'error': str(exc)}, status=500)
                return
            self._send_json({'ok': True})
            return

        if parsed.path == '/api/tokens/create':
            if not is_admin_token(self._supplied_token(qs)):
                self._send_json({'error': 'forbidden'}, status=403)
                return
            label = qs.get('label', [''])[0].strip() or 'Guest'
            now = int(time.time())
            if 'until' in qs:
                try:
                    expires_at = int(qs['until'][0])
                except ValueError:
                    self._send_json({'error': 'bad request'}, status=400)
                    return
            else:
                try:
                    expires_at = now + int(float(qs['hours'][0]) * 3600)
                except (KeyError, ValueError):
                    self._send_json({'error': 'bad request'}, status=400)
                    return
            if expires_at <= now or expires_at > now + 365 * 24 * 3600:
                self._send_json({'error': 'Pick a date within the next year'}, status=400)
                return
            new_token = create_guest_token(label, expires_at)
            self._send_json({'ok': True, 'token': new_token})
            return

        if parsed.path == '/api/tokens/revoke':
            if not is_admin_token(self._supplied_token(qs)):
                self._send_json({'error': 'forbidden'}, status=403)
                return
            guest_token = qs.get('guest_token', [''])[0]
            if not guest_token:
                self._send_json({'error': 'bad request'}, status=400)
                return
            revoke_guest_token(guest_token)
            self._send_json({'ok': True})
            return

        self._send_json({'error': 'not found'}, status=404)

    def log_message(self, fmt, *args):
        log.info("%s - %s", self.address_string(), fmt % args)


class ThreadingHTTPServer(SocketServer.ThreadingMixIn, BaseHTTPServer.HTTPServer):
    daemon_threads = True


def main():
    server = ThreadingHTTPServer(('0.0.0.0', PORT), Handler)
    server.socket = ssl.wrap_socket(
        server.socket, certfile=CERT_FILE, keyfile=KEY_FILE, server_side=True,
        do_handshake_on_connect=False)
    server.serve_forever()


if __name__ == '__main__':
    main()
