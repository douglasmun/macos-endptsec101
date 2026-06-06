# Chapter 8 — Ancestry

**Code:** `../08-ancestry/ancestry.c`
**Build:** `cd 08-ancestry && make`
**Run:** `sudo ./ancestry`

## ebpf101 analog

Analog of ebpf101 ch22 (`iter` — process iterator / snapshot). That chapter uses
`BPF_ITER_PROG` to walk the kernel task list and emit a point-in-time snapshot of
all running processes. It is a pull model: iterate on demand. The wall it hits is
that the snapshot is static — you cannot correlate a single event back to its
ancestor chain without re-iterating at query time, and the iteration itself is
not atomic.

This chapter takes the reactive side of that trade: build the process tree
incrementally from FORK/EXEC/EXIT events as they arrive. At any point in the
handler, an ancestor walk is a hash table lookup — no kernel iteration, no
snapshot lag, no data-race on the task list.

| ebpf101 ch22 | This chapter |
|---|---|
| Pull model — iterate on demand | Push model — tree updated on each event |
| Point-in-time snapshot | Live tree — always current at event delivery time |
| `BPF_ITER_PROG` — walk kernel task list | Hash table of `tree_node_t` entries keyed by `audit_token_t` |
| No ancestry walk in one BPF program | `ancestry_str()` walks parent chain up to 8 hops in O(depth) |
| Ancestry rule impossible in kernel | `rule_suspicious_ancestry()` — browser-spawned tool detection |

## The wall ch07 hits that this chapter resolves

ch07's IDS knows `msg->process->parent_audit_token` for every event. But it
cannot look up that token — there is no table mapping tokens to processes. A rule
like "alert if `curl` is spawned by a browser" is impossible without a table to
walk up through. ch08 builds that table and keeps it current.

## What it does

Subscribes to `NOTIFY_FORK`, `NOTIFY_EXEC`, and `NOTIFY_EXIT`. On every EXEC,
walks the ancestor chain and prints a provenance line. Fires
`rule_suspicious_ancestry()` when a download or execution tool appears in a
browser-rooted chain.

```
ancestry: tracking process provenance — Ctrl-C to stop
[EXEC] /bin/zsh(1234)  chain: launchd(1) → Terminal(789) → zsh(1234)
[EXEC] /usr/bin/curl(5678)  chain: launchd(1) → Safari(4321) → bash(1234) → curl(5678)
[ALERT] browser-spawned-tool: curl launched from browser ancestor Safari(4321)
  chain: launchd(1) → Safari(4321) → bash(1234) → curl(5678)
[EXEC] /usr/bin/ls(9012)  chain: (unknown) → bash(8888) → ls(9012)
```

The `(unknown)` prefix appears for processes that were already running when the
monitor started — no FORK was observed for them, so the ancestor chain is
incomplete.

## New building blocks

### NOTIFY_FORK — the anchor for parent→child linkage

In a `fork+exec` sequence (the standard shell pattern), the parent process calls
`fork()`, then the child immediately calls `exec()`. By the time `NOTIFY_EXEC`
fires for the child, the parent may already have exited.

`NOTIFY_FORK` fires while both parent and child are live. It is the only reliable
point to capture the parent→child relationship:

```c
case ES_EVENT_TYPE_NOTIFY_FORK:
    child = msg->event.fork.child;
    n = tree_get_or_create(&child->audit_token, child_pid);
    n->parent_token = msg->process->audit_token;  // parent is live now
    // child has not exec'd yet — copy parent path as placeholder
    copy_str_token(n->path, PATH_BUF, &msg->process->executable->path);
```

### Process tree node migration on exec

`audit_token_t` includes a generation counter that increments on every `execve()`.
The pre-exec and post-exec tokens are different even though the PID is the same.

Without migration, the tree breaks after the first exec: the child's FORK entry
(keyed to the pre-exec token) is never found by subsequent EXEC events (which use
the post-exec token), so the parent link is lost. The node also leaks — EXIT
fires with the final image's token, never matching the intermediate FORK entry.

Migration on `NOTIFY_EXEC`:
```c
old = tree_find(&msg->process->audit_token);  // pre-exec entry (has parent link)
n   = tree_get_or_create(&target->audit_token, pid);  // post-exec entry
if (old && old != n) {
    n->parent_token = old->parent_token;  // carry parent link forward
    tree_remove(&msg->process->audit_token);  // free stale entry
} else {
    // No FORK observed — use ES's parent_audit_token as fallback
    n->parent_token = target->parent_audit_token;
}
```

The guard `old && old != n` handles the edge case where the pre- and post-exec
tokens are equal (rare but possible). Calling `tree_remove` with `old == n` would
free `n` before it is used.

### Incomplete-tree startup

Processes running before the monitor subscribed never delivered a FORK event.
Their tree node has no `parent_token` set. `ancestry_str()` handles this with a
`missing_root` flag:

- If a parent lookup fails mid-walk, set `missing_root = 1` and stop.
- Prepend `"(unknown) → "` to the chain string if `missing_root` is set.
- Do **not** use `depth == 0` as the missing-root condition — `depth == 0` also
  fires for launchd (which skips the ancestor walk entirely via the self-parent
  sentinel). The launchd case has a complete chain; it should not be labeled
  `(unknown)`.

### ancestry_str — building the chain string

`ancestry_str()` walks the tree from the current node up to the root, collects
ancestors into a stack (so they can be printed root-first), then assembles the
output string:

```
launchd(1) → Safari(4321) → bash(1234) → curl(5678)
```

Two stopping conditions beyond `missing_root`:
1. **Depth cap**: `ANCESTRY_DEPTH_MAX = 8` hops. Prevents an unbounded walk if a
   stale entry creates a false parent chain (an edge case where a recycled token
   matches an unrelated live process).
2. **launchd sentinel**: launchd's `parent_token == token` (it is its own parent).
   When `token_eq(&anc->token, &anc->parent_token)`, the root is reached.

The launchd case is handled by skipping the ancestor walk entirely when
`start->token == start->parent_token`. Entering the walk for launchd would find
`start` itself in the table, push it, and print it twice.

### snprintf return value safety

`ancestry_str()` accumulates into a fixed buffer using repeated `snprintf` calls.
The return value must be captured and guarded:

```c
int rc = snprintf(buf + pos, bufsz - pos, "%s(%d) → ", leaf(n->path), n->pid);
if (rc > 0) pos += (size_t)rc;
```

Direct cast of a potentially-negative `int` return value (which `snprintf` returns
on encoding error) to `size_t` wraps to a huge value, corrupting `pos` and
writing past the end of the buffer on the next call.

### rule_suspicious_ancestry

Fires when:
1. The current process's leaf name matches a download/execution tool (`curl`,
   `wget`, `python`, `python3`, `ruby`, `perl`, `osascript`, `bash`, `sh`,
   `zsh`, `nc`, `ncat`).
2. Walking the ancestor chain finds a process whose name contains a browser
   substring (`Safari`, `firefox`, `Chrome`, `Chromium`, `Brave`, `Arc`,
   `Opera`, `webkit`, `WebContent`).

Substring match on browser names (via `strstr`) is intentional: browser helper
processes appear as `"Google Chrome Helper"`, `"WebContent"`, etc. A leaf-name
exact match would miss them.

The canonical trigger is the browser-exploitation sequence:
```
Safari(4321) → WebContent(5555) → bash(1234) → curl(5678)
```

WebContent is the sandboxed renderer; bash is the shell invoked by a malicious
script; curl is the downloader. Each individual exec is normal; the chain from
a browser to a shell to a download tool is the indicator.

## No eBPF equivalent for the ancestry rule

`bpf_iter` (ch22) gives a snapshot of the task list but cannot efficiently walk
the ancestry chain in a BPF program and match it against a pattern list. The
kernel data structures for parent relationships are complex and version-specific.
The user-space rule engine with a maintained hash table is necessary on both
platforms; ES makes the per-event data richer and the process identity reliable.

## Bugs found and fixed

Six audit-round bugs were found and fixed in this chapter. Full list in
[`../BUGS.md`](../BUGS.md). The most instructive:

- **Missing-root vs depth==0 confusion**: using `depth == 0` to prepend
  `(unknown)` incorrectly labeled launchd (which legitimately has no ancestors)
  as having an unknown root.
- **`old == n` guard in migration**: without this check, equal pre/post tokens
  cause `tree_remove` to free the node that is still in use, producing a
  use-after-free.
- **snprintf return value cast**: unchecked negative return cast to `size_t`
  wraps to `SIZE_MAX`, corrupting the buffer write position.
- **launchd double-print**: entering the ancestor walk for a node that is its
  own parent pushes and prints the same node twice.

## The wall this hits (→ [09-tcc](09-tcc.md))

The ancestry chain answers "who launched this process and from what chain." But
it cannot see what capabilities the process has been granted. A malicious process
that quietly acquires microphone or Full Disk Access via TCC is invisible — the
exec and the ancestry are observed, but the capability grant is not. ch09 adds
`NOTIFY_AUTHORIZATION_JUDGEMENT` to close that gap.
