# Safe Access Reward Time

A small, self-hosted web app for adding "reward time" to a kid's device on a
Synology router running **Safe Access** (SRM's parental-control package) —
without the friction of the official DS Router app. Built for phones: big
buttons, a quick +5/+15/+30/+60 minute grid per profile, a custom date/time
picker, and time-limited "babysitter" access links you can text to someone
else so they can manage screen time themselves for a few hours or a few days.

It runs entirely on the router itself. No cloud service, no external
dependencies beyond what SRM already ships with.

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

- A mobile-first page per restricted profile/device with quick-add buttons,
  a revoke button, and a full custom date/time picker (with your own
  built-in calendar and hour/minute/AM-PM columns - no fiddly native input).
- Drag-free reordering (tap arrows) and collapsible cards, remembered
  per-browser.
- **Babysitter/guest access**: generate a separate link, good for anywhere
  from a few hours up to a year, that lets whoever you send it to grant or
  revoke reward time themselves - without your admin token, and without
  them being able to create more links of their own. Revoke it early anytime.
- Runs as a resilient background service: a watchdog checks real health
  (not just "is the process alive") every minute and restarts it if needed,
  and it survives router reboots.

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

## Installing

1. SSH into the device as your admin account (not root).
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

   It'll ask a few questions (HTTPS port, optionally your router's DDNS
   hostname), generate a random access token and a self-signed certificate,
   fill in the scripts with your settings, and then print out the handful
   of commands that need root - copy/paste those into an `su` shell
   yourself. Nothing is auto-elevated; you see and run every privileged
   step.

4. In the SRM web interface, go to **Control Panel -> Security -> Firewall**
   and add an **Allow** rule for the TCP port you chose (default `8443`)
   from any source. Without this the app is only reachable from your home
   network.

5. Open the URL the installer printed, bookmark it or add it to your
   phone's home screen.

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
filled in with your settings from the installer. To use it:

```
su -c '<your-install-dir>/cert-sync.sh'
```

and to keep it in sync automatically going forward, add (as root):

```
printf '0\t6\t*\t*\t5\troot\t<your-install-dir>/cert-sync.sh\n' >> /etc/crontab
```

(Friday mornings, a few hours after SRM's own certificate renewal check.)
This only works if your router's certificate setup matches what this script
expects (a leaf-only `server.crt`/`server.key` pair at the standard SRM
path, chain completed via the local admin HTTPS port) - if it fails, you're
no worse off than the self-signed default.

## Using it

Open the app link. Each restricted profile gets a card: tap a preset for a
quick add, **Custom** for an exact date/time, or **Revoke** to end active
reward time early. Tap a card's header to collapse/expand it; use the small
arrows to reorder cards (both remembered per-browser, not shared across
devices).

**Babysitter Access**: at the bottom, the "Add a token" card lets you name
who it's for and pick a duration (or a custom date/time up to a year out).
This generates a separate link with its own token - send it to whoever
needs temporary access. It works exactly like your own link, except it
can't create more tokens or see the token list. Revoke it anytime from the
list below, or let it expire on its own.

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

Everything else (watchdogs, boot scripts, log rotation, TLS handshake
timeouts to survive internet port-scanning) exists because this app is
reachable from the open internet by design, and needs to keep running
unattended.

## Troubleshooting

- **Nothing loads / connection refused from outside your home network**:
  almost always the firewall rule from step 4 above, or your router's
  public IP having changed with DDNS not yet caught up (check
  **Control Panel -> External Access -> DDNS**, re-save the entry to force
  an update).
- **Grant/revoke says success but the device doesn't actually get
  internet**: check that `apply_daemon.py` is actually running
  (`ps w | grep apply_daemon.py`) and check `apply_daemon.log` in the app
  directory for errors - most commonly this means the boot service wasn't
  installed correctly, or the root crontab watchdog entry is missing.
- **"Failed - check connection" on a request**: as of this version this
  should be rare - errors now surface the server's actual reason (e.g. a
  date picked too far out). If you see the generic message, check
  `server.log`.
- **A request seems to hang for exactly 5 seconds then fails**: means
  `apply_daemon.py` isn't picking up requests - check it's running and
  check its log.

## Uninstalling

As root:

```
/usr/local/etc/rc.d/reward-time.sh stop
/usr/local/etc/rc.d/reward-apply.sh stop
rm /usr/local/etc/rc.d/reward-time.sh /usr/local/etc/rc.d/reward-apply.sh
```

Then edit `/etc/crontab` to remove the three lines this app added
(`watchdog.sh`, `apply_watchdog.sh`, and `cert-sync.sh` if you enabled it),
and delete the app's install directory.

## Security notes

- The app is gated by a long random bearer token in the URL - anyone with
  the link has full access (or, for a babysitter link, access limited to
  granting/revoking reward time until it expires). Don't post the link
  anywhere public.
- It's directly internet-facing by design (that's the point - so you can
  use it away from home). It will get hit by routine internet-wide
  vulnerability scanners; the server handles this deliberately (threaded,
  per-connection timeouts, no endpoints beyond what it needs), but you
  should understand that's the tradeoff before exposing it.
- `apply_daemon.py` runs as root, but its attack surface is narrow: it only
  reads small JSON files from its own `pending/` directory (written only by
  the unprivileged app, which validates and range-checks everything before
  writing) and calls one fixed `synowebapi` command with those values.

## License

MIT - see [LICENSE](LICENSE).
