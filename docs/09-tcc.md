# 09-tcc

**ES analog of:** nothing in ebpf101 — ES-only capability

Linux has no kernel-enforced privacy permission layer. Camera, microphone, and
contacts access are controlled by device file permissions and discretionary ACLs,
not a centralized grant system with a single observable hook. This chapter has
no ebpf101 counterpart.

## The wall ch08 hits

ch08 knows *who* launched a process and *where* it came from. But it cannot see
*what access the process has been granted*. A malicious process that quietly
acquires microphone access is invisible to the process tree — you see the exec,
you see the ancestry, but you don't see the capability grant. `NOTIFY_TCC_MODIFY`
closes that gap.

## What TCC is

TCC (Transparency, Consent, and Control) is the macOS subsystem that mediates
app access to privacy-sensitive resources:

- Camera, microphone, screen recording
- Contacts, calendar, reminders, photos
- Location services
- Full Disk Access, Accessibility, Input Monitoring
- Bluetooth, local network

Every access request goes through TCC. Grants are stored in
`/Library/Application Support/com.apple.TCC/TCC.db` (system-wide) and
`~/Library/Application Support/com.apple.TCC/TCC.db` (per-user). ES
`NOTIFY_TCC_MODIFY` fires when any entry in either database changes —
grant, revoke, or modify.

## New concepts introduced

- **`es_event_tcc_modify_t`**: carries the service name (e.g.
  `"kTCCServiceMicrophone"`), the app's bundle ID or executable path, the
  authorization value (allowed/denied/limited), and whether the grant was
  user-initiated or MDM-pushed.
- **Correlating with ancestry**: combining `NOTIFY_TCC_MODIFY` with the ch08
  process tree to answer "which process, spawned by whom, just acquired camera
  access?" A browser-spawned process acquiring microphone access is a
  high-confidence indicator.
- **Persistent vs ephemeral grants**: TCC grants persist across reboots. An
  app that acquires FDA once retains it. Detecting the initial grant is
  therefore the critical moment.
- **MDM grants**: system administrators can push TCC grants via MDM profiles.
  These appear in the same event stream but with a different authorization
  source. Policy should distinguish user-granted from MDM-granted.

## Detection rules to implement

1. **Sensitive grant from unsigned binary**: non-platform binary acquires
   microphone, camera, or screen recording access.
2. **FDA from browser-spawned process**: full disk access granted to a process
   with a browser in its ancestry chain.
3. **Grant storm**: more than N distinct TCC services acquired by the same
   process within a short window — characteristic of a permission-harvesting
   dropper.

## ES events

- `NOTIFY_TCC_MODIFY`

## Key ES API fields

- `es_event_tcc_modify_t.service` — the TCC service name string
- `es_event_tcc_modify_t.identity` — app identity (bundle ID or path)
- `es_event_tcc_modify_t.access_right` — new authorization value

## Relation to other chapters

- Combines with ch08 process tree for ancestry context on the granting process.
- Shares the JSON alert output pattern from ch07.
- The detection rules follow the same stateful pattern as ch07's rule engine.

> Implemented: `09-tcc/tcc.c`
