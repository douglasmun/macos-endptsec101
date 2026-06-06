# Chapter 7 — IDS

**Code:** `../07-ids/ids.c`
**Build:** `cd 07-ids && make`
**Run:** `sudo ./ids`

## ebpf101 analog

Direct analog of ebpf101 ch23 (`ids` — rule-based intrusion detection). That
chapter taps raw network frames via an `AF_PACKET` socket and runs detection logic
entirely in C user space. The kernel side is deliberately minimal: extract a
`flow_pkt` record per packet, push it via ring buffer, done. The ebpf101 docs
describe the trade-off explicitly: "dumb kernel tap, smart user-space rule engine."

This chapter takes the same side of that trade — the rule engine lives in C, where
it's readable and easy to evolve — but the ES tap is richer than a raw packet tap:

| ebpf101 ch23 | This chapter |
|---|---|
| Per-packet `flow_pkt` — 5-tuple only | Per-event: process path, code identity, file path, connection domain/type |
| Process identity: `comm[16]` (truncated, reusable) | Process identity: `audit_token_t` (generation-safe, full path) |
| Network events only | Exec, file, and network events in one handler |
| Stateless — one packet at a time | Stateful — per-process hash table accumulates event history |
| Port-based rules (port 4444, etc.) | Behavioral rules (wrote-tmp-then-connected, exec-chain, beaconing, fan-out) |

## What it does

Subscribes to `NOTIFY_EXEC`, `NOTIFY_WRITE`, `NOTIFY_UIPC_CONNECT`, and
`NOTIFY_EXIT`. Accumulates per-process state in a hash table keyed by
`audit_token_t`. Evaluates five detection rules on each event. Outputs human-
readable alerts to stderr and JSON event records to stdout.

```
ids: monitoring exec/write/connect — alerts on stderr, JSON on stdout — Ctrl-C to stop

# stderr:
[ALERT] 2024-01-15T12:34:56Z rule=unsigned-then-connect pid=5678   unsigned binary wrote /tmp then opened INET connection path=/tmp/dropper
[ALERT] 2024-01-15T12:34:57Z rule=exec-chain            pid=5678   4 execs in 2s path=/tmp/dropper
[ALERT] 2024-01-15T12:35:30Z rule=beaconing             pid=9012   6 INET connects at ~30s intervals path=/usr/bin/curl

# stdout (JSON, one record per alert):
{"ts":"2024-01-15T12:34:56Z","rule":"unsigned-then-connect","pid":5678,"detail":"unsigned binary wrote /tmp then opened INET connection path=/tmp/dropper"}
```

## New building blocks

### Per-process state hash table keyed by audit_token_t

The hash table replaces a per-packet stateless model with per-process memory that
persists across events. Key design decisions:

- **Key**: `audit_token_t`, not `pid_t`. PIDs are reused; `audit_token_t` includes
  a generation counter that makes each process lifetime unique.
- **Operations**: `state_get_or_create(token, pid)` on EXEC/WRITE/CONNECT;
  `state_remove(token)` on EXIT.
- **Hash function**: FNV-1a over the raw bytes of `audit_token_t`. Simple and
  adequate for 256 buckets.

Each `proc_state_t` stores: executable path, `is_platform_binary`, `wrote_tmp`
flag, exec counter + window start time, beacon ring buffer, and INET connect
counter + window start time.

### audit_token_t migration on exec

`audit_token_t` changes its generation field on every `execve()`. Without
migration, `NOTIFY_EXEC` creates a new state entry with zeroed counters while the
old entry is never cleaned up (`NOTIFY_EXIT` only removes the final image's token).
The result: the exec-chain counter never accumulates, and stale entries leak.

The migration pattern on `NOTIFY_EXEC`:
```
old = state_find(msg->process->audit_token)    // pre-exec token
new = state_get_or_create(target->audit_token) // post-exec token
copy old.exec_count, exec_window_start, wrote_tmp → new
state_remove(msg->process->audit_token)        // free old entry
```

This pattern is required wherever per-process state must survive across exec
boundaries. ch08 uses the same migration for the process tree.

### Rule 2 — unsigned-then-connect

Fires when: a non-platform binary has set `wrote_tmp = 1` (written to
`/private/tmp`) **and** subsequently opens an `AF_INET` or `AF_INET6` connection.

This catches a common dropper pattern: download payload to `/tmp`, execute it,
phone home. Each step individually is legal; the combination is suspicious.

ES resolves symlinks before delivering paths — `/tmp` always appears as
`/private/tmp` in `NOTIFY_WRITE`. The check uses `path_has_prefix(path, "/private/tmp")`.

### Rule 3 — exec-chain

Fires when a process execs more than `EXEC_CHAIN_LIMIT` (3) times within
`EXEC_CHAIN_WINDOW_S` (5 seconds). Resets after firing to emit one alert per
window rather than one per exec.

Distinguishes snapd-style launchers (exec a helper, which execs another, etc.)
from normal shell startup. The window arithmetic guards against clock step-backs:
if `now < exec_window_start`, the counter resets conservatively rather than
producing an underflow.

### Rule 4 — beaconing

Detects C2 heartbeat connections by looking for low-variance inter-arrival gaps
in `NOTIFY_UIPC_CONNECT` timestamps. Algorithm:

1. Record each INET connect time into a fixed-size ring buffer
   (`BEACON_RING_SIZE = 8` timestamps per process).
2. Once `BEACON_MIN_SAMPLES + 1` (6) timestamps are present, extract the 5
   inter-arrival gaps.
3. Compute the mean gap. Check that every gap is within `BEACON_VARIANCE_PCT`
   (30%) of the mean. If yes, fire.
4. Clear the ring buffer after firing to avoid re-alerting on every subsequent
   connection.

This requires **no remote address** — it fires purely from timing, using only
information ES delivers natively. A C2 client beaconing every 30 seconds produces
gaps of 30±9 seconds, which triggers the rule reliably.

### Rule 5 — fan-out

Fires when a process opens more than `FANOUT_LIMIT` (10) INET connections within
`FANOUT_WINDOW_S` (30 seconds). Resets after firing. Indicates port scanning,
lateral movement, or bulk connection patterns.

Same rolling-window pattern as exec-chain: reset on window expiry, fire once per
window crossing.

### Rule 1 — suspicious-port (scaffolding, not active)

Watches for connections to ports 4444, 31337, 6667, 50050 (common C2 and reverse
shell ports). The function exists (`rule_suspicious_port`) but is never called
from the handler because `NOTIFY_UIPC_CONNECT` does not deliver the remote port.
Activation requires wiring in a port data source: `dtrace` socket probes or
`NEFilterDataProvider`. Marked `__attribute__((unused))` to suppress the compiler
warning.

### JSON output with json_escape

Alert details may include process paths that contain backslashes, quotes, or
control characters (adversarial filenames). Emitting an unescaped path into a JSON
string field produces malformed JSON that breaks downstream log parsers.

`json_escape()` escapes `\`, `"`, and control characters (`\u00XX`) into a fixed
output buffer. The JSON line is then assembled with `printf` using the escaped
string.

### gmtime_r vs gmtime

`gmtime()` returns a pointer to a static struct. If the ES handler is called
concurrently (it runs on a serial ES queue, but multiple ES clients in the same
process could share logging helpers), `gmtime()` is not thread-safe. `gmtime_r()`
takes a caller-allocated `struct tm` — safe under any threading model.

### is_platform update from live events

A process that was already running at subscribe time (no `NOTIFY_EXEC` seen) has
`is_platform_binary = 0` by default in its state entry. `NOTIFY_WRITE` and
`NOTIFY_UIPC_CONNECT` carry `msg->process->is_platform_binary` — the handler
updates the state entry from the live event to correct this startup race.

## ES-only detection capabilities (no eBPF equivalent)

The IDS chapter is a natural point to note ES events with no Linux analog:

- **`NOTIFY_TCC_MODIFY`** (ch09): fires when any app gains or loses TCC privacy
  permissions (camera, microphone, screen recording, contacts, FDA). No eBPF
  equivalent — Linux has no centralized privacy permission layer.
- **`NOTIFY_BTM_LAUNCH_ITEM_ADD/REMOVE`** (ch10): fires when LaunchAgents or
  LaunchDaemons are registered or removed from Background Task Management.
  Critical for persistence detection. eBPF has no equivalent hook into
  `launchd`'s BTM subsystem.

## Bugs found and fixed

Audit rounds found migration bugs (state not carried across exec, old entries
leaked), `path_has_prefix` separator bugs, `gmtime()` thread-safety issues,
and `snprintf` return value cast bugs. Full list in [`../BUGS.md`](../BUGS.md).

The exec migration bug is the most consequential: without it, the exec-chain rule
never fires (counter resets to 0 on every exec) and long-running processes that
exec repeatedly leave accumulating memory leaks in the state table.

## The wall this hits (→ [08-ancestry](08-ancestry.md))

The IDS knows `msg->process->parent_audit_token` for every event but cannot look
up that parent — there is no table of live processes. A rule like "alert if `curl`
is spawned by a browser" requires walking the ancestor chain at event time, which
requires building and maintaining a process tree from FORK/EXEC/EXIT events.
