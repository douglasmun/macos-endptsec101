# Chapter 3 — Auth Exec

**Code:** `../03-auth-exec/auth-exec.c`
**Build:** `cd 03-auth-exec && make`
**Run:** `sudo ./auth-exec`

## ebpf101 analog

Direct analog of ebpf101 ch20 (`lsm` — `bprm_check_security`). That chapter is
the culmination of the eBPF series: an LSM BPF program hooks `bprm_check_security`
— the kernel gate that runs before any program image is loaded — and returns `0`
(allow) or `-EPERM` (deny).

`AUTH_EXEC` is the ES equivalent. The contract is the same: respond before the
kernel deadline or execution proceeds.

| ebpf101 concept | ES equivalent |
|---|---|
| `SEC("lsm/bprm_check_security")` | `ES_EVENT_TYPE_AUTH_EXEC` subscription |
| Return `0` / `-EPERM` | `es_respond_auth_result(..., ES_AUTH_RESULT_ALLOW/DENY, ...)` |
| Kernel deadline implicit | `msg->deadline` — explicit Mach absolute time |
| `bpf_get_current_comm()` for process name | `msg->event.exec.target->executable->path` |
| No code-identity fields in LSM BPF | `is_platform_binary`, `team_id`, `signing_id`, `cdhash` available |

## What it does

Subscribes to `AUTH_EXEC`. Every exec system-wide pauses until the handler
responds. Denies execution of binaries whose leaf name matches a configurable
deny list (`nc`, `ncat` by default); allows everything else. Platform binaries
are fast-allowed unconditionally.

```
auth-exec: intercepting all execs — denying: nc, ncat — Ctrl-C to stop
[ALLOW] pid=1234   ppid=567    path=/usr/bin/ls
[DENY]  pid=5678   ppid=567    path=/usr/bin/nc
[ALLOW] pid=5679   ppid=567    path=/bin/zsh
```

## New building blocks

### AUTH_EXEC vs NOTIFY_EXEC — the contract difference

`ES_EVENT_TYPE_AUTH_EXEC` and `ES_EVENT_TYPE_NOTIFY_EXEC` deliver identical data —
the same `es_event_exec_t` struct with the same `target` and `process` fields. The
difference is purely in contract:

- **NOTIFY**: informational. No response required. Handler can be slow.
- **AUTH**: the kernel is suspended waiting for a verdict. `es_respond_auth_result()`
  **must** be called on every code path through the handler, including early exits
  and error paths. Missing the deadline defaults to ALLOW — silence is not DENY.

### es_respond_auth_result — the verdict call

```c
es_respond_auth_result(client, msg, ES_AUTH_RESULT_DENY, false);
```

Arguments:
- `client` — the ES client handle
- `msg` — the message being responded to (the kernel is keyed to this)
- `result` — `ES_AUTH_RESULT_ALLOW` or `ES_AUTH_RESULT_DENY`
- `cache` — `true` tells ES to cache this verdict and skip the handler for future
  execs of the same binary. `false` means always call the handler. Use `false`
  during development; `true` in production for high-frequency allow paths.

The response may come from any thread — the handler does not need to respond
before returning. This enables deferred auth (ch15): retain the message, dispatch
expensive policy evaluation asynchronously, respond later.

### msg->deadline

`msg->deadline` is an absolute Mach time (from `mach_absolute_time()`) by which
the response must arrive. If the deadline passes without a response, the kernel
defaults to ALLOW and moves on. In practice, the handler has on the order of
seconds, but under system load it can be much shorter. Never block inside the
AUTH handler without a timeout.

### target vs process — two es_process_t structs

`AUTH_EXEC` carries the same two process views as `NOTIFY_EXEC`:

- `msg->process` — the pre-exec caller (the process that called `execve`)
- `msg->event.exec.target` — the post-exec image (the binary about to be loaded)

For policy purposes, `target` is the right choice: it has the path, argv, and
code signature of the binary that will actually run. `msg->process` reflects
the calling image, which for interpreter-wrapped scripts may be the shell.

### is_platform_binary — the safe fast-allow path

`es_process_t.is_platform_binary` is set by ES for Apple-signed system binaries
(those that ship with macOS and are signed by Apple's root certificate). Denying
a platform binary can render the system unusable — `launchd`, `mds`, `trustd`,
and hundreds of other daemons use `execve` continuously.

The correct policy structure is:

```
if (target->is_platform_binary) → ALLOW immediately
else → evaluate deny list
```

This pattern appears in ch03, ch06, ch11, and ch16.

### Path-based policy and its limits

This chapter denies by leaf filename (`nc`, `ncat`). Two fundamental limits:

1. **Renaming escapes it.** A copy of `nc` named `backup` is not denied. ch06
   introduces code-identity-based enforcement (team ID, CDHash) that survives
   renaming — the signature travels with the binary.

2. **Name collisions.** Any unrelated binary installed as `/usr/local/bin/nc`
   (including legitimate tools) is equally denied.

Path-based policy is a starting point, not a production approach. The upgrade
path is ch06 (code identity) and ch11 (CDHash allowlist).

## Bugs found and fixed

Audit rounds found bugs related to AUTH handler completeness and the `target`
vs `process` distinction. Full list in [`../BUGS.md`](../BUGS.md). Key issues:

- Every code path through the handler must call `es_respond_auth_result()`. An
  early `break` or `return` without a response leaves the kernel waiting until
  the deadline expires — effectively a slow ALLOW with a system stall.
- Using `msg->process` instead of `msg->event.exec.target` for policy evaluation
  matches the wrong binary (the caller, not the thing being exec'd).

## The wall this hits (→ [04-network](04-network.md))

We can govern process execution. But a blocked binary can still be invoked under
a different name, and a permitted binary can open any network connection without
restriction. The next chapter adds visibility into `connect(2)` calls.
