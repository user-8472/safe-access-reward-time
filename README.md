I've wanted something better than the DS router app for configuring Safe 
Access screen time for my kids.  I'd considered writing everything that is
included here but new it would be a lot of work and I wasn't that committed.
I realized yesterday that I could just ask Claude to write the app and here
we are less than 36 hours in and it does everything I wanted. This note here
is the only thing I've manually written for this project.  Everything else
was generated through Claude Code. I hope it can be useful for someone else 
in the future.


# Safe Access Reward Time

A small, self-hosted web app for managing kids' screen time on a Synology router running
**Safe Access** (SRM's parental-control package) - without the friction of the official DS Router
app. Built for phones: one card per kid or device with quick **+5/+15/+30/+60 minute** reward time,
**pause internet** buttons, a **weekly schedule editor**, today's usage, and time-limited
**babysitter links** you can text to someone else. It shows **who did what** (each parent and
babysitter has their own link), and emails you if something breaks, plus an optional weekly
summary.

It runs entirely on the router itself. No cloud service, no external dependencies beyond what SRM
already ships with.

**Jump to:** [Screenshots](#screenshots) · [What you get](#what-you-get) ·
[Prerequisites](#prerequisites) · [Router setup](#setting-up-your-router-first) ·
[Installing](#installing) · [Updating](#updating-an-install) · [Using it](#using-it) ·
[Architecture](#architecture) · [Troubleshooting](#troubleshooting) ·
[Uninstalling](#uninstalling) · [Security notes](#security-notes) · [Tests](#running-the-tests)

## Screenshots

<table>
<tr>
<td align="center" width="50%"><img src="docs/screenshots/01-main-list.png" width="260" alt="Main list"><br>
<sub>One card per kid or device: reward time, today's schedule window and usage</sub></td>
<td align="center" width="50%"><img src="docs/screenshots/02-expanded-cards.png" width="260" alt="Expanded cards"><br>
<sub>Quick reward buttons, pause (tap again to extend), Resume and Revoke</sub></td>
</tr>
<tr>
<td align="center"><img src="docs/screenshots/03-schedule-editor.png" width="260" alt="Schedule editor"><br>
<sub>Weekly schedule editor: the times internet is allowed</sub></td>
<td align="center"><img src="docs/screenshots/04-time-editor.png" width="260" alt="Time editor"><br>
<sub>Editing a time, and applying it to other days</sub></td>
</tr>
<tr>
<td align="center"><img src="docs/screenshots/05-babysitter-and-admin.png" width="260" alt="Babysitter and admin access"><br>
<sub>Babysitter links (optionally for some devices only) and per-person admin links</sub></td>
<td align="center"><img src="docs/screenshots/06-activity.png" width="260" alt="Activity"><br>
<sub>Who did what, with weekly and monthly totals</sub></td>
</tr>
</table>

## Why this exists, and why it's built the way it is

The official Safe Access apps write reward time through a specific webapi
call that also notifies SRM's enforcement daemons live. Writing directly to
the underlying SQLite database (which is tempting, since it's simple and the
data model is obvious once you've looked at it) **does not reliably apply
the change** - the value shows up as "granted" but the device doesn't
actually get network access until something else nudges the enforcement
daemons. This was discovered the hard way; see "Architecture" below for how
this app avoids it.

## What you get

- **A card per restricted profile or device** showing active reward time, today's schedule window
  ("Scheduled on now: 6:00 AM - 9:00 PM", or the next one) and today's usage, including how much was
  reward time. Cards collapse and reorder with tap arrows, remembered per browser.
- **Reward time:** +5m/+15m/+30m/+60m buttons that stack, and **Custom** for an exact date and time.
- **Pause internet:** **+30m** pauses (tap again to extend), **Until...** pauses to a set time.
  **Resume** ends a pause, and **Revoke** puts the profile back on its normal schedule (removes
  reward time and any pause).
- **Schedule editing:** a weekly editor of allowed times, saved to Safe Access live (it shows in the
  DS Router app too). Copy a time to other days, and undo any change from the activity log.
- **Per-person links:** each parent gets their own admin link (create or revoke more from the
  page), and **babysitter links** last anywhere from a few hours to a year, optionally limited to
  some devices. Babysitters can grant, revoke and pause, but can't create links or see the admin
  sections.
- **Activity log:** who did what and when, with per-person weekly and monthly totals.
- **Email alerts and a weekly summary:** a health monitor emails each admin who set an alert address
  when something breaks (and when it recovers) or an action fails, and optionally a Sunday summary
  of the week's usage.
- **Runs unattended:** watchdogs check real health every minute and restart things, and it survives
  router reboots.

## Prerequisites

- A Synology router or NAS running SRM/DSM with the **Safe Access** package
  installed and at least one profile with time restrictions configured.
- SSH access enabled (Control Panel -> Terminal & SNMP) and an admin-level
  account to install with.
- Roughly 20MB free space on a writable volume (`/volume1` typically exists
  even on router-only models).

This was built and tested on an RT2600ac running SRM. It should work on any
SRM/DSM device with Safe Access, but router models vary - if something in
here doesn't quite match what you see, that's likely why; the install
script tries to warn you when a key assumption doesn't hold.

## Setting up your router first

If you've never enabled SSH, set up DDNS, or added a firewall rule on SRM
before, this walks through all three - everything here is done through the
same SRM web admin page you already use for Safe Access, logged in as an
admin account.

### 1. Enable SSH

**Control Panel -> Terminal & SNMP -> Terminal** tab -> check **Enable SSH
service** -> leave the port at `22` unless you have a reason to change it
-> **Apply**.

### 2. Connect over SSH for the first time

You need a terminal/SSH client:

- **Mac or Linux**: the `Terminal` app already has `ssh` built in.
- **Windows 10/11**: `ssh` is built into PowerShell and Command Prompt -
  open either one. (Or use a GUI tool like PuTTY if you prefer.)

Connect using the same local IP address you normally use to open the SRM
web interface (not a DDNS hostname - that comes next):

```
ssh your-admin-username@192.168.x.x
```

The first time, you'll see a warning that the host's authenticity can't be
verified - type `yes` to continue. Then enter your admin password (the
same one you use to log into SRM); nothing will appear on screen as you
type, which is normal for password prompts. A prompt like `~$` means
you're in.

### 3. Set up DDNS

Your router's public IP can change, so the app needs a stable hostname to
be reachable from outside your home - this also solves the "my phone can't
reach it when I'm away" problem that `https://192.168.x.x` addresses can't,
since that address only works on your home network.

**Control Panel -> External Access -> DDNS -> Add**:

- **Service Provider**: `Synology` is the simplest option if you have a
  Synology account - it gives you a free `something.synology.me` hostname
  with nothing else to configure. A third-party provider (No-IP, etc.)
  works too if you already have an account with one.
- **Hostname**: pick anything available - it doesn't need to relate to
  your real name. Anyone who later gets your app link will see this
  hostname, though they'd also need the long random access token the
  installer generates to actually do anything with it.
- Follow whatever sign-in/verification step that provider asks for.
- After saving, the **Status** column should turn to a green "Normal"
  within a minute or so.

Keep this hostname handy - the installer asks for it in the next section.

### 4. Open the firewall for the app's port

This uses the port you'll choose during installation (the installer
defaults to `8443`), so you can do this step either now (using `8443`
unless you plan to pick something else) or right after installing.

**Control Panel -> Security -> Firewall**:

- Make sure the firewall is enabled. If this is the first custom rule
  you're adding, SRM may prompt you to create a default "allow" rule
  first - that's fine, accept it.
- Select the rule set for your main network interface (usually named
  something like `LAN 1`), then **Edit Rules -> Create**.
- Set **Ports** to **Custom**, protocol **TCP**, port `8443` (or your
  chosen port); **Source IP** to **All**; **Action** to **Allow**.
- **OK**, then **Save**. Make sure the new rule is enabled (checkbox) - if
  you already have other custom rules, order only matters if an earlier
  rule would otherwise block or shadow this one.

Without this step, the app only works from inside your home network.

**If your Synology device isn't your main internet gateway** - e.g. it's
running in Access Point mode, or another router does your actual NAT/port
forwarding - you'll also need to forward this same TCP port to this
device's LAN IP address on *that* router. The steps for that vary by
brand/model, so check that router's own documentation.

## Installing

1. SSH into the device as your admin account (not root) - see above if
   you haven't enabled/used SSH on this device before.
2. Pick a permanent home for the app and clone/copy this repo directly into
   it - it can't relocate itself afterward, so choose the real location up
   front. For example:

   ```
   cd /volume1
   mkdir reward-time && cd reward-time
   # copy this repo's files into this directory
   ```

3. Run the installer from inside that directory:

   ```
   sh install.sh
   ```

   It'll ask a few questions (HTTPS port, your router's DDNS hostname from
   step 3 above), generate a random access token and a self-signed
   certificate, fill in the scripts with your settings, and then print out
   the handful of commands that need root - copy/paste those into an `su`
   shell yourself. Nothing is auto-elevated; you see and run every
   privileged step.

4. If you haven't already, add the firewall rule from step 4 above for the
   port you just chose.

5. Open the URL the installer printed, bookmark it or add it to your
   phone's home screen.

6. Optional, for email alerts and the weekly summary: create a Gmail *app password*
   (Google account -> Security -> 2-Step Verification -> App passwords) and run
   `./set-alert-email.sh` from the app directory. It stores the sender and sends a test. Then
   set an alert email on your admin link (Admin Access on the page) and tick
   "Weekly usage email" if you want the Sunday summary.

Since it's a self-signed certificate by default, your browser will warn you
the first time. You can just tap through it, or - to make the warning go
away permanently - AirDrop/email yourself `cert/fullchain.pem`, install it
as a profile on your phone, then enable full trust for it under
**Settings -> General -> About -> Certificate Trust Settings** (iOS) or your
Android device's equivalent.

### Reusing a real certificate instead

If your router already has Let's Encrypt (or another real) certificate for
its own admin login page, `cert-sync.sh` can copy that into this app instead
of the self-signed one, so there's no browser warning at all. It's already
filled in with your settings from the installer, and was copied into the
root-owned `<your-install-dir>-root` directory along with the other parts
that run as root. To use it:

```
su -c '<your-install-dir>-root/cert-sync.sh'
```

and to keep it in sync automatically going forward, add (as root):

```
printf '0\t6\t*\t*\t5\troot\t<your-install-dir>-root/cert-sync.sh\n' >> /etc/crontab
/usr/syno/sbin/synoservicectl --restart crond
```

(Friday mornings, a few hours after SRM's own certificate renewal check.)
This only works if your router's certificate setup matches what this script
expects (a leaf-only `server.crt`/`server.key` pair at the standard SRM
path, chain completed via the local admin HTTPS port) - if it fails, you're
no worse off than the self-signed default.

## Updating an install

From a checkout of this repo on your own computer, with SSH access to the router as the app user:

```
./deploy.sh <ssh-host> [/volume1/reward-time]
```

It copies the app's own files, compile-checks them with the router's Python, backs up the current
ones into `backups/<timestamp>/` (keeping the newest 5), restarts the server and checks it answers.
If it doesn't, it prints how to roll back. Changes to the root-owned parts (`root/`) need root, so
copy those into `<your-install-dir>-root` yourself as in the installer's steps.

## Using it

Open your link. Each restricted Safe Access profile (a kid's account, or a specific device) has a
card; tap its header to expand it (see the [screenshots](#screenshots)).

### Reward time

The **+5m ... +60m** buttons stack: tap **+15m** then **+30m** and it ends up 45 minutes, with no
need to wait for the first to finish. **Custom** opens a date/time picker sized to fit the screen;
it closes as soon as you tap **Set** and applies in the background, so you can move on to the next
device.

### Pausing internet

**+30m** pauses the profile for 30 minutes; tapping it again adds another 30 to the end.
**Until...** pauses to a chosen time. While paused, the card shows "Paused until ..." and the last
row offers **Resume** (end the pause, keep any reward time) and **Revoke** (end both and go back to
the normal schedule). Safe Access itself only pauses indefinitely, so timed pauses are ended by the
app's background daemon.

### Editing schedules

**Edit schedule** (admins only) shows each day's allowed times. Tap a time to change its start or
end in the same picker; **Apply to...** adds it to other days too (merging with times already
there). **+ Add** adds a time, and **Copy to all days** makes every day match one. Nothing changes
until **Save**. A schedule with no allowed time at all asks for confirmation. Every change is
recorded with the previous schedule, and its entry in Activity has an **Undo** button.

### Babysitter access

Name who a link is for and pick how long it lasts (a few hours up to a year). By default it covers
all devices; untick **All devices** to pick some. Creating it copies the link to your clipboard. A
badge on the heading shows how many are active; open a row to see its link again or revoke it.

### Admin access and alerts

Every admin link has a name, which is what Activity shows. Open a row to copy its link, set an
alert email, tick **Weekly usage email (Sundays)**, or revoke it. You can't revoke your own link,
or the last one. A warning banner appears at the top of the page if the health monitor sees a
problem.

The weekly email lists each kid's or device's internet use, then each person's activity. Its
**Open Admin Access** button opens the app (the installed app, on a phone) on the recipient's own
link at Admin Access, to change or turn off emails. It uses `public_url` in `config.json`, which
the installer sets from your DDNS hostname and port.

### Activity

A per-person table of the last 7 and 30 days (actions and minutes granted, revokes, pauses), and the
recent actions, filterable by person. Failed actions show in red. The Babysitter Access, Admin
Access and Activity sections fold, remembered per browser.

## Architecture

```
Browser  --HTTPS-->  reward_server.py (runs as your regular user, unprivileged)
                          |
                          |  writes a small request file, waits briefly
                          v
                     pending/*.json
                          ^
                          |  polls every ~0.3s
                          |
                     apply_daemon.py (runs as root - required for the next step)
                          |
                          v
              synowebapi: SYNO.SafeAccess.AccessControl.ConfigGroup.Reward.Ultra
                          |
                          v
                 Safe Access's own enforcement daemons (notified live)
```

`reward_server.py` never touches the Safe Access database directly for
writes - only for fast, read-only status display. All writes go through
`apply_daemon.py`, which is the only part of this app that needs root, and
its only job is calling the same official API the Synology apps use. This
split exists specifically because a direct database write does *not*
reliably trigger live enforcement - confirmed by testing both paths against
a real device.

Pausing (`SYNO.SafeAccess.AccessControl.ConfigGroup`) and schedule changes
(`SYNO.SafeAccess.AccessControl.Profile.Schedule.Blocktime`) go the same way.
Safe Access only pauses indefinitely, so `apply_daemon.py` also keeps timed
pauses in `pauses.json` and ends them when due.

Around that:

- `tokens.db` (app directory) holds the admin and babysitter links and the
  activity log.
- `monitor.py` runs every minute as the app user and checks the web app, the
  daemons' heartbeats and the certificate sync. It emails problems,
  recoveries and failed actions, and sends the weekly summary. Its state also
  drives the page's warning banner.
- Everything else (watchdogs, boot scripts, log rotation, TLS handshake
  timeouts to survive internet port-scanning) exists because this app is
  reachable from the open internet by design, and needs to keep running
  unattended.

## Troubleshooting

- **Nothing loads / connection refused from outside your home network**:
  almost always the firewall rule (see "Setting up your router first"
  above), or your router's public IP having changed with DDNS not yet
  caught up (check **Control Panel -> External Access -> DDNS**, re-save
  the entry to force an update).
- **Grant/revoke says success but the device doesn't actually get
  internet**: check that `apply_daemon.py` is actually running
  (`ps w | grep apply_daemon.py`) and check `apply_daemon.log` in the
  `<your-install-dir>-root` directory for errors - most commonly this means the boot service wasn't
  installed correctly, or the root crontab watchdog entry is missing.
- **"Failed - check connection" on a request**: as of this version this
  should be rare - errors now surface the server's actual reason (e.g. a
  date picked too far out). If you see the generic message, check
  `server.log`.
- **A request seems to hang for exactly 5 seconds then fails**: means
  `apply_daemon.py` isn't picking up requests - check it's running and
  check its log.
- **A warning banner at the top of the page**: it lists what the health
  monitor found; `monitor.log` in the app directory has the history.
  "Health monitor last ran N minutes ago" means its cron entry
  (`monitor_launcher.sh`) isn't running.
- **The server keeps restarting**: `server.crash.log` has startup errors and
  tracebacks, plus a line for every restart. `server.log` is the request log.
- **No alert emails**: run `python monitor.py --test-email` in the app
  directory. Check the admin link has an alert email set, and that
  `set-alert-email.sh` was given a Gmail *app password*, not the account
  password.

## Uninstalling

As root:

```
/usr/local/etc/rc.d/reward-time.sh stop
/usr/local/etc/rc.d/reward-apply.sh stop
rm /usr/local/etc/rc.d/reward-time.sh /usr/local/etc/rc.d/reward-apply.sh
```

Then edit `/etc/crontab` to remove the lines this app added
(`app_watchdog.sh`, `apply_watchdog.sh`, `monitor_launcher.sh`, and
`cert-sync.sh` if you enabled it), restart crond (`/usr/syno/sbin/synoservicectl --restart crond`), and
delete both the app's install directory and its `-root` companion.

## Security notes

- The app is gated by a long random bearer token in the URL - anyone with
  an admin link has full access, and a babysitter link can only grant,
  revoke and pause (on its devices) until it expires. Each person has their
  own link, so one can be revoked without affecting the others, and the
  activity log shows which link did what. Don't post links anywhere public.
- It's directly internet-facing by design (that's the point - so you can
  use it away from home). It will get hit by routine internet-wide
  vulnerability scanners; the server handles this deliberately (threaded,
  per-connection timeouts, no endpoints beyond what it needs), but you
  should understand that's the tradeoff before exposing it.
- `apply_daemon.py` runs as root, but its attack surface is narrow: it only
  reads small JSON files from the app's `pending/` directory (written only
  by the unprivileged app, which validates and range-checks everything
  before writing) and calls one fixed `synowebapi` command with those
  values.
- Everything that runs as root (`apply_daemon.py`, the two watchdog
  launchers, `cert-sync.sh`) lives in a separate root-owned
  `<your-install-dir>-root` directory, never in the app's own directory.
  The app directory is writable by the app user - and so, in the worst
  case, by anyone who compromises the internet-facing server - so if root
  ran anything from there, that would be a path to root. For the same
  reason, root never follows a path inside the app directory that could be
  a planted symlink: `apply_daemon.py` reads requests with `O_NOFOLLOW` and
  writes its status files via fresh, randomly named files, and
  `cert-sync.sh` and the boot scripts do everything inside the app
  directory as the app user (via `su`).

## Running the tests

The schedule logic (windows, and converting between allowed times and Safe
Access's blocked periods) has unit tests that run on both the router's
Python 2.7 and Python 3:

```
python3 -m unittest discover -s tests -t .     # on your own computer
tests/run_on_router.sh <ssh-host>               # on the router itself
```

## License

MIT - see [LICENSE](LICENSE).
