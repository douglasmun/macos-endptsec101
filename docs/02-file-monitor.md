# Chapter 2 — File Monitor

**Code:** `../02-file-monitor/file-monitor.c`
**Build:** `cd 02-file-monitor && make`
**Run:** `sudo ./file-monitor`

## ebpf101 analog

Covers ebpf101 ch9 (`openat`) and ch10 (`openat-ret`). Those two chapters exist
because the BPF probe fires at syscall entry — the return value (the fd, or the
error) is only available at exit. Correlating the two requires a BPF hash map
keyed by PID to stash arguments across the entry→exit boundary:

| ebpf101 wall | Why it doesn't exist here |
|---|---|
| ch9: only entry; no return value | ES NOTIFY events fire after the operation completes |
| ch10: stash + retire BPF map entries to correlate entry→exit | One callback delivers path, process identity, and outcome |
| ch9: kernel-side `O_RDONLY` filter to cut volume | `ES_MUTE_PATH_TYPE_TARGET_PREFIX` — same zero-cost suppression, configured in user space |

## What it does

Subscribes to four NOTIFY events and prints one line per event:

```
file-monitor: monitoring create/write/unlink/rename — Ctrl-C to stop
[CREATE] pid=1234   path=/Users/alice/Documents/notes.txt
[WRITE]  pid=1234   path=/Users/alice/Documents/notes.txt
[RENAME] pid=1234   src=/Users/alice/Documents/notes.txt dst=/Users/alice/Documents/notes-old.txt
[UNLINK] pid=1234   path=/Users/alice/.Trash/notes-old.txt
```

High-frequency noise directories (`/private/tmp`, `/private/var/folders`,
`.Spotlight-V100`) are suppressed via `ES_MUTE_PATH_TYPE_TARGET_PREFIX` before
subscribe, so the output remains readable on an active system.

## New building blocks

### NOTIFY_CREATE — es_event_create_t.destination_type

`NOTIFY_CREATE` fires in two contexts, distinguished by a `destination_type` union:

1. **New path** — `ES_DESTINATION_TYPE_NEW_PATH`. The event carries `dir` (the
   containing directory as `es_file_t *`) and `filename` (`es_string_token_t`).
   The full path is `dir/filename`.

2. **Creating on top of an existing file** — `ES_DESTINATION_TYPE_EXISTING_FILE`.
   The event carries `existing_file` (`es_file_t *`) with the full path already
   assembled.

Checking `destination_type` before accessing the union is not optional. The two
arms are different types at different offsets — accessing the wrong one is
undefined behavior.

### NOTIFY_RENAME — destination_type again

Rename has the same `destination_type` union as create. If the destination already
exists (an atomic overwrite), `existing_file` is populated. If the destination path
is new, `new_path.dir` + `new_path.filename` are populated. An atomic rename that
overwrites `/etc/hosts` with a malicious copy is only detectable if both branches
are handled.

### NOTIFY_WRITE and NOTIFY_UNLINK

Simpler — both carry a `target` (`es_file_t *`) pointing directly to the file
being modified or deleted.

### ES_MUTE_PATH_TYPE_TARGET_PREFIX — muting by target path

`es_mute_path(client, path, ES_MUTE_PATH_TYPE_TARGET_PREFIX)` suppresses events
where the **target of the operation** matches a path prefix — not events from a
specific process, but events whose payload path falls under the given directory.
Suppressed events never cross the delivery queue, so there is no handler overhead.

Contrast with `ES_MUTE_PATH_TYPE_PREFIX` (used in ch05), which matches the
**instigating binary's path** — the process binary that caused the event, not the
file being operated on.

### Symlink resolution in muting

`es_mute_path()` is applied after symlink resolution. On macOS, `/tmp` is a
symlink to `/private/tmp`. Muting `/tmp` has no effect — ES sees the resolved
`/private/tmp/...` path in every event. Always mute the resolved path.

### path_truncated at volume

`es_file_t.path_truncated` matters especially under file-monitor conditions: events
arrive at high volume and paths can be long. `print_path()` appends `...(truncated)`
when the flag is set so a reader knows the path is incomplete rather than silently
treating a prefix as the full path.

## What a real Mac shows

Running this monitor on an active machine immediately reveals:
- **Spotlight** (`mds`, `mdworker`) generating constant write activity against
  index files
- **Editors performing atomic rename-on-save**: write to `.tmp`, rename over the
  target — exactly the `NOTIFY_WRITE` + `NOTIFY_RENAME` with `EXISTING_FILE`
  sequence
- **`cfprefsd`** writing preference plists continuously
- **`com.apple.security.syspolicy`** reading and writing policy caches

The `TARGET_PREFIX` mutes on `/private/tmp` and `/private/var/folders` are what
keep the output navigable.

## Bugs found and fixed

Audit rounds found bugs related to the `destination_type` union and muting. Full
list in [`../BUGS.md`](../BUGS.md). The critical correctness issue:

- Accessing `msg->event.create.destination.existing_file` when `destination_type ==
  ES_DESTINATION_TYPE_NEW_PATH` (or vice versa) reads from the wrong union arm —
  undefined behavior that typically produces a garbage path or a crash.

## The wall this hits (→ [03-auth-exec](03-auth-exec.md))

We can observe every file operation system-wide, including destructive ones.
But observation cannot stop a malicious write to `/etc/hosts`. The next step is
AUTH events, which deliver a before-the-fact verdict opportunity.
