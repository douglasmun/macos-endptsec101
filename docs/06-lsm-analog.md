# Chapter 6 — LSM Analog

**Code:** `../06-lsm-analog/lsm-analog.c`
**Build:** `cd 06-lsm-analog && make`
**Run:** `sudo ./lsm-analog`

## ebpf101 analog

Direct analog of ebpf101 ch21 (`xdpfw` — XDP firewall with blocklist map). That
chapter builds a network firewall: a `blocklist` BPF hash map holds blocked
destination ports; the XDP program looks up each packet's port and returns
`XDP_DROP` or `XDP_PASS`. Rules are written to the map from user space at
runtime — no recompile.

| ebpf101 concept | ES equivalent |
|---|---|
| XDP hook on the NIC before the stack | AUTH hooks before exec/create/unlink completes |
| `blocklist` BPF hash map for blocked ports | C arrays of allowed team IDs and protected path prefixes |
| `XDP_DROP` / `XDP_PASS` | `ES_AUTH_RESULT_DENY` / `ES_AUTH_RESULT_ALLOW` |
| Policy input: 5-tuple (src/dst IP/port/proto) | Policy input: code identity + operation path |
| Rules updated at runtime via map writes | Rules are compiled in (dynamic policy: ch12) |
| One event type (packets) | Multiple AUTH event types in one client |

The ES version enforces policy across three operation types simultaneously —
exec, file create, and file unlink — in a single client. Each event type has its
own policy logic sharing the same process identity context.

## What it does

Subscribes to `AUTH_EXEC`, `AUTH_CREATE`, and `AUTH_UNLINK`. Enforces two
independent policies:

1. **Exec policy**: deny execution of non-platform binaries whose team ID is not
   in the allowlist. Binaries without a team ID (unsigned, ad-hoc-signed) are
   denied unless they are platform binaries.

2. **File policy**: deny create and unlink inside protected path prefixes
   (`/etc`, `/Library/LaunchDaemons`, `/Library/LaunchAgents`, `/System`) for
   non-platform binaries.

```
lsm-analog: enforcing exec team-ID policy + file path policy — Ctrl-C to stop
[EXEC:ALLOW] pid=1234  ppid=567  team=PABRCU3Y4G path=/usr/local/bin/mytool
[EXEC:DENY]  pid=5678  ppid=567  team=(none) path=/tmp/dropper
[CREATE:DENY ] pid=5679  ppid=567  path=/Library/LaunchDaemons/evil.plist
[UNLINK:ALLOW] pid=1234  ppid=567  path=/etc/resolv.conf   (platform binary)
```

## New building blocks

### Multiple AUTH event types in one client

A single ES client can subscribe to any combination of event types. The handler
uses a `switch` on `msg->event_type`. All events share one deadline per event —
each AUTH event requires its own response call:

```c
es_event_type_t events[] = {
    ES_EVENT_TYPE_AUTH_EXEC,
    ES_EVENT_TYPE_AUTH_CREATE,
    ES_EVENT_TYPE_AUTH_UNLINK,
};
```

Every code path through every `case` must call `es_respond_auth_result()`. Missing
a response in one event type while handling another correctly is a common mistake
during development.

### Code identity as a policy input

`es_process_t` exposes cryptographic process identity that has no eBPF equivalent:

| Field | Type | What it is |
|---|---|---|
| `is_platform_binary` | `bool` | Apple-signed system binary |
| `team_id` | `es_string_token_t` | Developer team ID from the code signature |
| `signing_id` | `es_string_token_t` | Bundle identifier or signing identifier |
| `cdhash` | `uint8_t[20]` | SHA-1 hash of the code directory — unique per binary version |
| `codesigning_flags` | `uint32_t` | `CS_VALID`, `CS_ADHOC`, `CS_RUNTIME`, etc. |

**The key advantage over path-based policy**: a binary renamed from `/usr/bin/nc`
to `/usr/bin/backup` still carries its original `team_id` and `signing_id`. The
code signature is cryptographically bound to the binary content — it cannot be
modified without breaking the signature.

### team_id_allowed — working with es_string_token_t values

`team_id` is an `es_string_token_t` **value** (not a pointer) embedded directly
in `es_process_t`. When passing it to a function, take the address:

```c
if (team_id_allowed(target->team_id)) { ... }
```

`es_string_token_t.data` is **not** null-terminated — always use `length` for
comparison. `memcmp` with the expected team ID string and an equal length check
is the correct pattern.

Note: `team_id_allowed()` is only reached for non-platform binaries (the
`is_platform_binary` fast-allow path runs first). Adding Apple's own team ID to
the allowlist would therefore allow *any* non-platform binary signed by Apple —
an unintended widening of policy.

### path_is_protected — separator-safe prefix matching

Simple `memcmp` against a prefix is insufficient. `/etcfoo` would match against
the prefix `/etc`. The correct check requires either:

- `path->length == plen` (exact match)
- `path->data[plen] == '/'` (separator after the prefix)
- `plen == 1` (prefix is `/` — any absolute path is a valid match, no separator
  check needed because `memcmp` already verified the first character)

This pattern appears in ch06, ch07, and ch16.

### AUTH_CREATE — policy_path vs log_file distinction

For `AUTH_CREATE`, the destination union must be checked before accessing either
path for policy evaluation:

```c
if (destination_type == ES_DESTINATION_TYPE_EXISTING_FILE) {
    policy_path = &existing_file->path;
} else {
    // new_path.dir is the containing directory — sufficient for prefix matching
    policy_path = &new_path.dir->path;
}
```

The distinction matters: `new_path.dir->path` is the parent directory's path, so
a prefix match against `/Library/LaunchDaemons` correctly catches any file being
created inside that directory regardless of filename.

## What a real Mac shows

With an unsigned binary deny policy active, many macOS developer tools fail to
exec (Homebrew installs, scripts, etc.) — production use requires a broader team
ID allowlist or a different policy axis. The file policy visibly blocks attempts
to write into `/etc` or launch daemon directories.

## Bugs found and fixed

Audit rounds found separator-safety bugs in `path_is_protected`, union-arm bugs
in `AUTH_CREATE`, and `team_id` pointer/value confusion. Full list in
[`../BUGS.md`](../BUGS.md).

## The wall this hits (→ [07-ids](07-ids.md))

Per-event policy catches known-bad patterns — a specific team ID, a specific
path prefix. But a threat actor operating entirely with signed binaries in
non-protected directories is invisible. Detecting unknown threats requires
correlating events across time: an exec followed by a write to `/tmp` followed
by a network connection is suspicious even if each individual event is allowed.
That requires stateful user-space logic.
