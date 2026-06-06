# Chapter 5 — Muting

**Code:** `../05-muting/muting.c`
**Build:** `cd 05-muting && make`
**Run:** `sudo ./muting`

## ebpf101 analog

Loose analog of two ebpf101 techniques:

- **ch9 kernel-side filter** (`if flags == O_RDONLY return 0`): drop events before
  they reach the ring buffer — the event is never emitted, so there is no user-space
  cost. ES muting is the same idea: suppressed events never cross the delivery queue.

- **ch19 tail-call dispatch**: route events to different handlers based on a
  property. ES's muting inversion (`es_invert_muting`) achieves the same effect as
  an allowlist — only events from selected paths arrive; everything else is silently
  dropped before delivery.

ES muting is more structured than either eBPF approach: suppression rules are
declared at configuration time in user space, and ES enforces them in the kernel.
There is no BPF program to write, no map to populate, no ring buffer to drain.

## What it does

Subscribes to `NOTIFY_EXEC` and demonstrates all five muting modes. Runs in
allowlist mode: only exec events from `/usr/bin/*` (and `/usr/sbin/dtrace` as a
literal) are delivered. Everything else is silently dropped.

```
muting: configuring allowlist for /usr/bin/*
  muted PREFIX  /usr/bin
  muted LITERAL /usr/sbin/dtrace
muting: inverted — now in allowlist mode (only /usr/bin/* and /usr/sbin/dtrace)
muting: monitoring exec — Ctrl-C to stop
[EXEC] pid=1234   ppid=567    path=/usr/bin/ls
[EXEC] pid=5678   ppid=567    path=/usr/bin/grep
```

## New building blocks

### Five muting modes

ES provides three path-muting types and one process-muting type:

| API | Matches on | Use case |
|---|---|---|
| `es_mute_process(client, &audit_token)` | The process that causes an event | Self-mute to prevent feedback loops |
| `es_mute_path(..., ES_MUTE_PATH_TYPE_PREFIX)` | Instigating binary path prefix | Silence all events from `/usr/libexec/*` |
| `es_mute_path(..., ES_MUTE_PATH_TYPE_LITERAL)` | Instigating binary exact path | Silence one specific binary |
| `es_mute_path(..., ES_MUTE_PATH_TYPE_TARGET_PREFIX)` | Target of the operation | Silence writes to `/private/tmp/*` (ch02) |

"Instigating binary" means the process whose exec'd image caused the event — the
path of the binary at `msg->process->executable`. "Target" means the file or path
that is the subject of the operation (what is being written, renamed, unlinked).

### es_invert_muting — denylist to allowlist

By default, muted paths/processes are suppressed (denylist). `es_invert_muting()`
flips the semantic: entries on the muting list are the **only** ones delivered;
everything else is suppressed.

```c
es_invert_muting(client, ES_MUTE_INVERSION_TYPE_PATH);
```

There are two independent inversion types, one per table:

- `ES_MUTE_INVERSION_TYPE_PATH` — inverts the path-muting table (populated by
  `es_mute_path` calls)
- `ES_MUTE_INVERSION_TYPE_PROCESS` — inverts the process-muting table (populated
  by `es_mute_process` calls)

They are independent. Calling `es_invert_muting(ES_MUTE_INVERSION_TYPE_PROCESS)`
does not affect the path table. Using the wrong type when trying to build a path
allowlist means the path table stays in denylist mode — nothing is suppressed and
the allowlist effect is never achieved.

### Mandatory ordering: mute before subscribe

`es_subscribe()` must be called **after** all muting is configured. Events are
delivered immediately on subscribe with whatever muting state is currently
installed. If subscribe precedes the muting calls, there is a race window where
events from paths that should be suppressed (or not in the allowlist) arrive.

The required order:
```
es_mute_process(self)         // always first — prevent feedback loop
es_mute_path(...)             // configure denylist entries
es_invert_muting(...)         // flip to allowlist if needed
es_subscribe(...)             // only now start receiving events
```

### Symlink resolution caveat

ES applies muting after symlink resolution. On macOS:
- `/tmp` → `/private/tmp`
- `/var` → `/private/var`

Muting `/tmp` with `ES_MUTE_PATH_TYPE_PREFIX` has no effect because ES sees
the resolved `/private/tmp/...` path. Muting `/private/tmp` works. This applies
to all three path muting types.

### Self-muting with process muting

Every chapter calls `es_mute_process(client, &self_token)` immediately after
`es_new_client()`. This prevents a feedback loop where a `printf` in the handler
generates a file-write event that re-enters the handler. The audit token for the
current process is obtained via `task_info(TASK_AUDIT_TOKEN)`.

Process muting and path muting operate on separate tables with separate
inversion states. Inverting the path table does not affect the self-mute —
the process table stays in denylist mode (suppress self) regardless.

## What a real Mac shows

In allowlist mode, only `/usr/bin/*` execs appear. On an active system this is
still a steady stream — shell builtins, scripting runtimes, and system commands
all live in `/usr/bin`. The difference from unfiltered ch01 output is dramatic:
the constant churn from Spotlight, `launchd` helpers, and XPC proxies disappears.

## Bugs found and fixed

Audit rounds found ordering bugs (muting configured after subscribe, creating a
race window) and inversion-type confusion. Full list in [`../BUGS.md`](../BUGS.md).
The key correctness issue:

- Using `ES_MUTE_INVERSION_TYPE_PROCESS` when the intent was to invert the path
  table leaves the path table in denylist mode. All muted paths remain suppressed
  (correct for a denylist) rather than becoming the only allowed paths (the
  intended allowlist). The result is a monitor that silently receives nothing from
  the paths the developer thought it was filtering to.

## The wall this hits (→ [06-lsm-analog](06-lsm-analog.md))

Muting controls which events arrive but doesn't act on them. A muted process can
still perform any operation — it's just invisible to this monitor. The next chapter
combines multiple AUTH event types into a policy engine that enforces verdicts.
