# 16-unified-agent

**ES analog of:** nothing in ebpf101 — operational architecture unique to production ES deployments

Each chapter so far has run as a separate process with its own `es_new_client()`.
That is pedagogically clean but operationally impossible: ES limits the number of
concurrent clients per machine, each client adds scheduling overhead, and the
chapters need shared state (process tree from ch08, invalidation flags from ch14,
TCC grants from ch09) to cross-reference each other. A real security agent is one
client subscribed to many event types with all subsystems sharing a single process
tree. This chapter has no ebpf101 counterpart.

## The wall ch15 hits

ch15 defers expensive AUTH work correctly. But it runs in isolation — it has no
process tree (ch08), no TCC state (ch09), no invalidation flags (ch14). Its policy
is codesign-only because it cannot consult what the process's ancestors were. To
ask "should this exec be denied?" in full context, you need ancestry + TCC grants +
BTM state + codesign + invalidation flags all available at the moment the AUTH
arrives. That requires one process maintaining all of that state, not seven separate
binaries.

## What unified composition requires

### Single `es_new_client()` with a merged event list

All chapters' event types in one `es_subscribe()` call:

```
NOTIFY_FORK, NOTIFY_EXEC, NOTIFY_EXIT          — ch08 process tree (required foundation)
NOTIFY_TCC_MODIFY                              — ch09 TCC state
NOTIFY_BTM_LAUNCH_ITEM_ADD/REMOVE              — ch10 persistence tracking
AUTH_EXEC                                      — ch03/ch06/ch11/ch15 exec policy
NOTIFY_WRITE                                   — ch07 IDS + ch12 config watch
NOTIFY_UIPC_CONNECT                            — ch07 IDS network
AUTH_OPEN                                      — ch13 file auth
NOTIFY_CS_INVALIDATED                          — ch14 runtime integrity
```

The ES client delivers all of these on a single serial dispatch queue. Every event
type the client subscribes to shares that queue — there is no per-event-type
concurrency at the handler level.

### Shared state subsystems

Each chapter's state is now a subsystem (a set of data structures + functions)
linked into the same binary:

| Subsystem | State | Keyed by |
|---|---|---|
| Process tree (ch08) | `tree_node_t` hash table | `audit_token_t` |
| TCC state (ch09) | Per-pid service grant set | pid |
| BTM pending (ch10) | Install-then-remove tracker | executable path |
| IDS state (ch07) | Per-process event counters | `audit_token_t` |
| Invalidation flags (ch14) | Per-pid invalidation marker | pid |

All subsystems update on the same ES serial queue — no locking needed for
NOTIFY event handlers because ES serializes them. The deferred AUTH work queue
(ch15) runs concurrently and reads shared state — it must treat the process
tree as read-only after retaining the message, or snapshot the relevant fields
inside the handler before returning.

### Event ordering guarantees

ES delivers events in causal order per process: FORK before EXEC before EXIT
for a given audit token sequence. However, across different processes, delivery
order reflects arrival at the ES subsystem, not wall-clock order. Implications:

- A NOTIFY_EXEC and a NOTIFY_TCC_MODIFY from different processes may arrive
  interleaved — the unified handler must not assume any cross-process ordering.
- On AUTH_EXEC with deferred response, NOTIFY_FORK for a new child of the
  authed process may arrive before the AUTH verdict is sent. The process tree
  must handle this: the FORK handler creates the child node; the deferred AUTH
  verdict on the parent is unaffected.
- NOTIFY_EXIT may arrive before the deferred AUTH response for the exiting
  process. The verdict must still be sent — the kernel is waiting regardless
  of whether the process is still alive.

### Dispatch queue architecture

```
ES serial queue (managed by ES)
  └── handle_event()
        ├── NOTIFY events → update subsystem state inline (fast, no blocking)
        └── AUTH events → es_retain_message() + dispatch_async to g_work_queue

g_work_queue (concurrent, bounded)
  └── evaluate_and_respond()
        ├── snapshot process tree state (read-only, race-safe if tree is not
        │   mutated from the work queue)
        └── es_respond_auth_result() + es_release_message()

g_main_queue
  └── reload_config() — config file changes, es_mute_path() calls
      do_shutdown()   — signal handler posts here
```

The critical constraint: `es_mute_path()`, `es_unmute_path()`, and
`es_delete_client()` must not be called from the ES handler queue or the work
queue. They must run on the main queue (or a dedicated management queue).

### The snapshot pattern for deferred AUTH

The deferred AUTH worker (ch15) reads process tree state to make its verdict.
But the process tree is mutated on the ES serial queue, and the work queue is
concurrent with the ES queue. Two approaches:

1. **Snapshot at retain time**: before `dispatch_async`, copy the relevant
   fields (ancestry string, TCC grant set, invalidation flag) from shared state
   into a context struct. The background worker reads the snapshot, not live
   state. This is the recommended approach: it is race-free because the
   snapshot happens on the ES queue before returning.

2. **Read lock**: protect the process tree with a `pthread_rwlock_t`. Readers
   (work queue) take a read lock; writers (ES queue FORK/EXEC/EXIT handlers)
   take a write lock. More flexible but introduces latency on the ES queue when
   a write lock is contended.

The snapshot approach is simpler and sufficient for this project.

## New concepts introduced

- **Multi-event subscription**: one `es_subscribe()` call with a large event
  type array. ES delivers all subscribed types on the same handler queue.
- **Subsystem initialization order**: subsystems with dependencies must initialize
  in the right order. The process tree (ch08) must initialize before IDS state
  (ch07) and before the deferred AUTH worker (ch15), because both read the tree.
- **Graceful shutdown across subsystems**: `do_shutdown()` must drain the work
  queue before calling `es_delete_client()`. Use `dispatch_barrier_sync(g_work_queue, ^{})` 
  to wait for all in-flight deferred AUTH responses before teardown.
- **Cross-subsystem policy**: the auth verdict for AUTH_EXEC can now consult:
  - Codesign identity (ch11)
  - Ancestry chain (ch08)
  - TCC grants by the process (ch09)
  - Whether the process has been invalidated (ch14)
  - Whether the process installed persistence (ch10)
  This is the first time a single verdict can be driven by all of these signals
  simultaneously.
- **Telemetry**: with all subsystems in one process, a unified JSON event stream
  (extending ch07's SIEM output) can tag every event with cross-subsystem context:
  an EXEC event annotated with the process's ancestry chain, its TCC grants, its
  codesign flags, and whether it has a pending BTM install.

## Shutdown correctness

The unified agent has more complex shutdown requirements than any single chapter:

1. Signal received → set `g_stop`, post `do_shutdown` to main queue.
2. `do_shutdown`:
   a. `dispatch_barrier_sync(g_work_queue, ^{})` — wait for all deferred AUTH
      workers to complete and respond. This is essential: calling `es_delete_client()`
      while a deferred response is in-flight is undefined behavior.
   b. `es_delete_client(g_client)` — tears down the ES subscription.
   c. Free subsystem state (optional if exiting immediately).
   d. `exit(0)`.

Without the barrier, there is a window where a deferred AUTH worker calls
`es_respond_auth_result(g_client, ...)` after `es_delete_client()` has invalidated
`g_client` — a use-after-free.

## Architecture diagram

```
main()
 ├── init_timebase()
 ├── g_work_queue = dispatch_queue_create(CONCURRENT)
 ├── tree_init()         — ch08 subsystem
 ├── tcc_state_init()    — ch09 subsystem
 ├── btm_state_init()    — ch10 subsystem
 ├── ids_state_init()    — ch07 subsystem
 ├── inv_state_init()    — ch14 subsystem
 ├── load_config()       — ch12 policy config
 ├── es_new_client() → handle_event
 ├── task_info + es_mute_process(self)
 ├── for each config mute path: es_mute_path()
 ├── es_subscribe(ALL_EVENT_TYPES)
 └── dispatch_main()

handle_event()
 ├── NOTIFY_FORK   → tree_on_fork()
 ├── NOTIFY_EXEC   → tree_on_exec(), ids_on_exec(), [if invalidated: log]
 ├── NOTIFY_EXIT   → tree_on_exit(), ids_on_exit(), inv_remove()
 ├── NOTIFY_WRITE  → ids_on_write(), [if config path: dispatch reload_config]
 ├── NOTIFY_UIPC_CONNECT → ids_on_connect()
 ├── NOTIFY_TCC_MODIFY   → tcc_on_modify()
 ├── NOTIFY_BTM_LAUNCH_ITEM_ADD    → btm_on_add()
 ├── NOTIFY_BTM_LAUNCH_ITEM_REMOVE → btm_on_remove()
 ├── NOTIFY_CS_INVALIDATED → inv_on_invalidated()
 ├── AUTH_EXEC → snapshot_ctx() + es_retain_message() + dispatch to work queue
 └── AUTH_OPEN → snapshot_ctx() + es_retain_message() + dispatch to work queue

evaluate_and_respond(ctx)  ← g_work_queue (concurrent)
 ├── check deadline
 ├── read snapshot: ancestry, tcc_grants, cs_invalidated, btm_pending
 ├── apply policy (ch11 CDHash + ch08 ancestry + ch14 invalidation flag)
 └── es_respond_auth_result() + es_release_message()
```

## Detection policy in the unified agent

With full cross-subsystem context, the unified agent can enforce policies that
no individual chapter could:

1. **High-confidence malware triple**: exec by a process that (a) has a browser
   ancestor, (b) acquired microphone TCC access within the last 5 minutes, and
   (c) is installing a LaunchAgent — DENY the exec and alert.

2. **Invalidated process exec**: any AUTH_EXEC where the process pid is in the
   invalidation table (set by ch14) — DENY regardless of codesign status.

3. **Post-persistence exec**: AUTH_EXEC by a process that installed a BTM item
   within the last 60 seconds — DENY if unsigned, alert if signed.

4. **Full-context SIEM output**: every AUTH event emits a JSON record tagged
   with all cross-subsystem state at decision time. This is the unified telemetry
   stream a real EDR agent would send to a backend.

## ES event count limit

ES clients have a per-client event backlog limit. If the handler queue falls
behind (the deferred AUTH work queue is saturated), ES will terminate the client
with `ES_CLIENT_ERROR_TOO_SLOW`. The unified agent must monitor for this:

- Keep deferred work bounded: if the work queue depth exceeds a threshold,
  fall back to synchronous policy evaluation for new AUTH events (deny if
  uncertain, log the degradation).
- Monitor deadline miss rate from the ch15 pattern — a high rate signals
  the work queue is falling behind the incoming event rate.

## Relation to other chapters

This chapter synthesizes all prior chapters. Nothing new is introduced at the ES
API level — the new concepts are entirely about composition, state sharing, and
operational correctness in a multi-subsystem agent. It is the capstone chapter:
the goal every prior chapter was building toward.

A production macOS EDR agent is, in essence, this chapter — with more rules,
remote telemetry, and policy management. The ES API surface has been fully covered.

> Implemented: `16-unified-agent/unified-agent.c`
