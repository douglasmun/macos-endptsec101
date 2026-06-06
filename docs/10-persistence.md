# 10-persistence

**ES analog of:** nothing in ebpf101 — ES-only capability

Linux persistence is scattered: cron, systemd unit files, rc.d scripts, XDG
autostart, `/etc/profile.d`. There is no single kernel-visible registration
chokepoint. This chapter has no ebpf101 counterpart.

## The wall ch09 hits

ch09 sees a process acquiring camera access right now. But it cannot see that
process also installing a LaunchAgent that will call home on every login. The
TCC grant is ephemeral (it happens once and persists in TCC.db), but the
LaunchAgent is the persistence mechanism — the thing that ensures the malware
runs again after reboot. `NOTIFY_BTM_LAUNCH_ITEM_ADD` covers that.

## What BTM is

Background Task Management (BTM) is the macOS subsystem (introduced in macOS
13 Ventura) that mediates registration of:

- LaunchAgents (`~/Library/LaunchAgents/`, `/Library/LaunchAgents/`)
- LaunchDaemons (`/Library/LaunchDaemons/`, `/System/Library/LaunchDaemons/`)
- Login items (SMLoginItem, ServiceManagement framework)
- XPC services (partially)

Any attempt to register a new background task goes through BTM. ES
`NOTIFY_BTM_LAUNCH_ITEM_ADD` fires at registration time, before the item is
persisted to the BTM database.

## What BTM does NOT cover

- Cron jobs (`/var/at/tabs/`) — these bypass BTM entirely
- `/etc/periodic/` scripts
- Kernel extensions (separate NOTIFY_KEXTLOAD)
- Items registered via legacy `launchctl load` without BTM mediation (older
  macOS versions)

Documenting the gaps is as important as documenting what fires.

## New concepts introduced

- **`es_event_btm_launch_item_add_t`**: carries the item type
  (`ES_BTM_ITEM_TYPE_LAUNCH_AGENT`, `ES_BTM_ITEM_TYPE_LAUNCH_DAEMON`, etc.),
  the plist URL, the executable URL, and the registering process.
- **Combining signals**: a process that (1) arrived via a browser ancestry
  chain (ch08), (2) acquired microphone TCC access (ch09), and (3) installed a
  LaunchAgent (ch10) is a three-signal high-confidence malware indicator. Ch10
  is where these streams first converge into a single alert.
- **Item removal**: `NOTIFY_BTM_LAUNCH_ITEM_REMOVE` — malware that installs
  then immediately removes an item to execute once and clean up is also
  detectable.
- **Legitimate vs malicious**: many legitimate apps register LaunchAgents
  (Homebrew services, updaters, menu bar apps). The policy challenge is
  distinguishing them. Codesign context (`team_id`, `is_platform_binary`) on
  the registering process is the primary signal.

## Detection rules to implement

1. **Unsigned LaunchAgent installation**: non-platform, non-team-ID-allowlisted
   process registers a LaunchAgent or LaunchDaemon.
2. **Browser-ancestry persistence**: process with a browser or script
   interpreter in its ancestry chain installs any BTM item.
3. **Install-then-remove**: BTM add followed within N seconds by BTM remove
   for the same item — execute-once cleanup pattern.

## ES events

- `NOTIFY_BTM_LAUNCH_ITEM_ADD`
- `NOTIFY_BTM_LAUNCH_ITEM_REMOVE`

## Key ES API fields

- `es_event_btm_launch_item_add_t.item` — the `es_btm_launch_item_t` descriptor
- `es_btm_launch_item_t.item_type` — agent, daemon, login item, etc.
- `es_btm_launch_item_t.executable_url` — path to the launched binary
- `es_btm_launch_item_t.url` — path to the plist

## Relation to other chapters

- Combines with ch08 ancestry for registering process provenance.
- Combines with ch09 TCC state for the three-signal convergence rule.
- Shares the alert/JSON output pattern from ch07.

> Implemented: `10-persistence/persistence.c`
