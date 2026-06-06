# 13-auth-open

**ES analog of:** nothing directly in ebpf101 — ES-only capability

`seccomp` can filter `openat` syscalls by argument, but carries no codesign
context and cannot make allow/deny decisions based on who is calling. LSM
`inode_permission` hooks are closer but carry no team_id, ancestry, or
is_platform_binary. `AUTH_OPEN` with full ES process identity has no Linux
equivalent. This chapter has no ebpf101 counterpart.

## The wall ch12 hits

ch12 can dynamically update which paths are muted. But muting only suppresses
events — it doesn't authorize or deny. To say "no process except the system
keychain daemon may open `/etc/passwd` for writing," you need an AUTH event,
not a mute. `AUTH_OPEN` is the pre-open authorization hook: it fires before
the kernel grants a file descriptor, with the full process identity and the
requested open flags attached.

## Why AUTH_OPEN is stronger than AUTH_CREATE/AUTH_UNLINK

ch06 used `AUTH_CREATE` and `AUTH_UNLINK` for file policy. These fire when a
file is being created or deleted — but for sensitive files that already exist
(e.g., `/etc/hosts`, `/etc/passwd`, `/Library/Preferences/com.apple.loginitems.plist`),
create and unlink never fire. The sensitive operation is the *write open* — an
existing process silently overwriting a file it was allowed to open. `AUTH_OPEN`
catches that.

| Event | Fires when | Misses |
|---|---|---|
| `AUTH_CREATE` | New file being created | Opens of existing files |
| `AUTH_UNLINK` | File being deleted | Modifications via write open |
| `AUTH_OPEN` | Any file open for any access mode | Nothing — fires before fd grant |

## New concepts introduced

- **`es_event_open_t`**: carries the target `es_file_t *` and `fflag` — the
  open flags as passed to `open(2)`: `O_RDONLY` (0), `O_WRONLY` (1),
  `O_RDWR` (2), plus modifier flags (`O_APPEND`, `O_TRUNC`, `O_CREAT`, etc.).
- **`fflag` policy**: distinguish read-only opens (generally safe) from write
  opens (require stronger justification). A process opening `/etc/passwd`
  `O_RDONLY` is normal; `O_WRONLY | O_TRUNC` is not.
- **Sensitive file list**: the policy is a set of exact paths (not prefixes)
  that require elevated justification to open for writing. These are files
  that exist on a stock system and should never be written by arbitrary
  processes: `/etc/hosts`, `/etc/sudoers`, `/etc/pam.d/sudo`, launchd plists,
  TCC database paths.
- **`AUTH_OPEN` + codesign**: the handler has full `msg->process` context —
  `team_id`, `is_platform_binary`, `cdhash`. A write open of `/etc/hosts` by
  a platform binary (e.g., `networksetup`) is legitimate; by an unsigned binary
  with no team ID it is not.
- **`AUTH_OPEN` + ancestry** (ch08 tree): a write open by a process with a
  browser in its ancestry chain is high-confidence malicious regardless of
  codesign status.

## Detection policy to implement

Default posture: ALLOW all opens. Deny only on explicit violation to avoid
system instability.

1. **Sensitive write by unsigned process**: `O_WRONLY` or `O_RDWR` open of a
   sensitive path by a non-platform, non-allowlisted binary → DENY.
2. **TCC database write**: any write open of the TCC database paths
   (`/Library/Application Support/com.apple.TCC/TCC.db`) by a non-platform
   binary → DENY. Direct database writes bypass the TCC consent UI.
3. **Sudoers write**: any write open of `/etc/sudoers` or `/etc/sudoers.d/`
   by any non-platform binary → DENY.
4. **Browser-ancestry write to sensitive path**: write open from a process
   with a browser ancestor → DENY regardless of codesign status.

## The culmination

ch13 is the natural end of the learning arc. It combines:
- `AUTH_OPEN` (new event type, this chapter)
- Codesign identity (ch11 — team_id, is_platform_binary)
- Process ancestry (ch08 — browser ancestor check)
- Sensitive path list (extends ch06's protected prefix approach)

A complete ES security monitor subscribes to: NOTIFY_EXEC, NOTIFY_FORK,
NOTIFY_EXIT (process tree), AUTH_EXEC (execution policy), AUTH_CREATE,
AUTH_UNLINK, AUTH_OPEN (file policy), NOTIFY_WRITE (sensitive file writes),
NOTIFY_UIPC_CONNECT (network), NOTIFY_TCC_MODIFY (privacy), and
NOTIFY_BTM_LAUNCH_ITEM_ADD (persistence). Chapters 01–13 have introduced
every one of these event types.

## ES events

- `AUTH_OPEN`

## Key ES API fields

- `msg->event.open.file` — the target `es_file_t *` (path + path_truncated)
- `msg->event.open.fflag` — open flags bitmask (`int32_t`)
- `msg->process` — full process identity including codesign fields

## Relation to other chapters

- Extends ch06's path-based AUTH policy to open-time rather than create/unlink.
- Uses ch08's process tree for ancestry checks on the opening process.
- Uses ch11's codesign identity for the authorization decision.
- Completes the event type coverage: every major ES event type has now appeared
  in at least one chapter.

> Not yet implemented.
