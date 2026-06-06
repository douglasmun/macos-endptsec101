# Chapter 1 — Hello Exec

**Code:** `../01-hello-exec/hello-exec.c`
**Build:** `cd 01-hello-exec && make`
**Run:** `sudo ./hello-exec`

## ebpf101 analog

Covers ebpf101 ch1–8 in one program (hello-world through argv-libbpf). Those eight
chapters exist because eBPF forces you to work around each limitation one at a time:

| ebpf101 wall | Why it doesn't exist here |
|---|---|
| ch1–2: only a constant string, no data | ES delivers a typed `es_message_t` struct with full process info |
| ch3: caller name, not launched binary | `msg->event.exec.target` is the post-exec image — path is always correct |
| ch4–5: argv requires double-pointer walk | `es_exec_arg_count()` / `es_exec_arg()` hand you argv directly |
| ch6: per-CPU perf buffer, silent drops | ES manages the delivery queue internally |
| ch7–8: BCC not portable, C toolchain transition | ES is always a compiled binary — no equivalent transition |

The learning here shifts from transport mechanics to **API correctness**.

## What it does

Subscribes to three NOTIFY events and prints one line per event to stdout:

```
hello-exec: monitoring exec/fork/exit — Ctrl-C to stop
[EXEC] pid=1234   ppid=567    path=/usr/bin/ls argv=[ls -la /tmp]
[FORK] parent=567    child=1234
[EXIT] pid=1234   ppid=567    status=0
```

## New building blocks

### es_new_client()

Creates an ES client and registers a handler block. The block runs on an
ES-managed serial dispatch queue — not the main thread. Three failure modes matter:

- `ERR_NOT_ENTITLED` — missing `com.apple.developer.endpoint-security.client`
- `ERR_NOT_PERMITTED` — Full Disk Access not granted to the terminal
- `ERR_NOT_PRIVILEGED` — not running as root

### es_subscribe()

Declares which event types to receive. Subscribing to new types later does not
cancel prior subscriptions. We start with three:

- `ES_EVENT_TYPE_NOTIFY_EXEC` — process image replaced (execve / posix_spawn)
- `ES_EVENT_TYPE_NOTIFY_FORK` — process forked
- `ES_EVENT_TYPE_NOTIFY_EXIT` — process exited

### NOTIFY_EXEC: two es_process_t structs

`NOTIFY_EXEC` is the subtlest event. It carries **two** `es_process_t` fields:

```
msg->process          ← pre-exec image (called execve, about to be replaced)
msg->event.exec.target ← post-exec image (the new binary)
```

Both share the same PID but have **different audit tokens** — the generation
counter increments across exec. Never mix fields from the two. Always use `target`
for path and argv.

### audit_token vs ppid

Every `es_process_t` carries an `audit_token_t`. This is a generation-counter-safe
process identity — if a process exits and its PID is reused before the event is
delivered, the audit token still identifies the original process correctly.

`ppid` is a raw `pid_t` and is susceptible to PID reuse. The ES header
(`ESMessageCore.h`) explicitly recommends using `parent_audit_token` instead.
`parent_pid()` in this program wraps `audit_token_to_pid(proc->parent_audit_token)`.

### es_exec_arg_count / es_exec_arg

The correct accessors for argv. Never walk `es_event_exec_t` fields directly —
the struct layout is ES version-dependent. Each arg is returned as
`es_string_token_t {length, data}` — `data` is **not null-terminated**.

### path_truncated

`es_file_t.path_truncated` is set when a path exceeds ~16K characters. In a
security monitor, a silently truncated path can misidentify a process. `print_path()`
appends `...(truncated)` when the flag is set.

### Self-muting

Without muting, every `printf` in the handler could trigger file/write events that
feed back into the handler. Immediately after `es_new_client()`, we call
`es_mute_process()` with our own audit token obtained via `task_info(TASK_AUDIT_TOKEN)`.

### Signal safety

`es_delete_client()` and `exit()` acquire locks internally — calling them from a
signal handler while the ES queue is mid-callback can deadlock. The signal handler
only sets an `atomic_int` flag and posts `dispatch_async_f()` to the main queue.
Teardown runs in `do_shutdown()` on the main queue where it is safe.

`dispatch_function_t` is `void (*)(void *)` — `do_shutdown` must match this
signature exactly. A mismatched cast is undefined behavior.

### dispatch_main()

Parks the main thread and lets GCD run the ES handler block on its queue.
`dispatch_main()` never returns — the only way out is `exit()`, which `do_shutdown()`
calls on the main queue after cleaning up the ES client.

## What this reveals on a real Mac

Because ES receives every exec system-wide, running `hello-exec` on an active
macOS machine immediately shows:

- **launchd chains**: a single user action spawns multiple processes in sequence
  under the same PID (fork → exec → exec), visible as FORK + EXEC pairs
- **Background daemons**: `mds`, `mdworker`, `com.apple.security.syspolicy`,
  `trustd` executing constantly even on an "idle" machine
- **Transient helper processes**: short-lived processes (`xpcproxy`, `distnoted`,
  `cfprefsd`) that live for milliseconds — EXEC immediately followed by EXIT

## Bugs found and fixed

Two audit rounds found 9 bugs in this file. See [`../BUGS.md`](../BUGS.md) for the
full list. The most instructive:

- **B1/B5**: signal handler safety — async-signal-unsafe calls, then a UB function
  pointer cast on the fix
- **B7**: `ppid` vs `parent_audit_token` — the ES header says to use the token;
  raw `ppid` is PID-reuse-unsafe
- **B6**: `path_truncated` ignored — a silently wrong path in a security tool

## Entitlements

`hello-exec.entitlements` contains a single key:

```xml
<key>com.apple.developer.endpoint-security.client</key>
<true/>
```

This plist is embedded into the binary at signing time via `codesign --entitlements`.
With an active Apple Developer membership the entitlement is enforced by the kernel —
ES rejects clients that lack it with `ERR_NOT_ENTITLED`. With ad-hoc signing (`make
sign-adhoc`) and SIP disabled, the entitlement is embedded but not enforced, allowing
local development without a paid membership.

## The wall this hits (→ [02-file-monitor](02-file-monitor.md))

We observe process lifecycle but have no visibility into what files those processes
touch. The next chapter adds file event monitoring.
