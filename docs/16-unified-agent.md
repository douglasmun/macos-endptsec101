# 16-unified-agent

**ES analog of:** nothing in ebpf101 — operational architecture unique to production ES deployments

Each chapter so far has run as a separate process with its own `es_new_client()`.
That is pedagogically clean but operationally impossible: ES limits the number of
concurrent clients per machine, each client adds scheduling overhead, and richer
policy ultimately wants shared state (process tree from ch08, invalidation flags
from ch14, TCC grants from ch09) cross-referenced in one place. A real security
agent is one client subscribed to many event types with subsystems sharing a
single process tree. This chapter takes the composition step — one client, shared
tree + IDS state, deferred AUTH — while keeping each detection rule independent
(see the scope note below). This chapter has no ebpf101 counterpart.

## The wall ch15 hits

ch15 defers expensive AUTH work correctly. But it runs in isolation — it has no
process tree (ch08) and no runtime-invalidation flag (ch14). To ask "should this
exec be denied?" with any context beyond the binary in front of you, you need at
least the ancestry chain and the process's invalidation state available at the
moment the AUTH arrives. That requires one process maintaining shared state, not
seven separate binaries.

> **Scope note.** What this chapter *implements* is the single-client composition
> and the deferred-AUTH snapshot plumbing. The AUTH verdicts it actually enforces
> consult only the snapshot fields that exist (`cs_invalidated`, `CS_DEBUGGED`,
> team_id, sensitive path). Richer cross-subsystem verdicts (TCC grants and
> BTM-pending feeding an exec decision) are described later as the *design
> direction*, not as shipped code — see "Detection policy" below for exactly what
> fires.

## What unified composition requires

### Single `es_new_client()` with a merged event list

All chapters' event types in one `es_subscribe()` call:

```
NOTIFY_FORK, NOTIFY_EXEC, NOTIFY_EXIT          — ch08 process tree (required foundation)
NOTIFY_AUTHORIZATION_JUDGEMENT                 — ch09 TCC analog (NOTIFY_TCC_MODIFY is
                                                 not in this SDK; judgement is the
                                                 closest available event)
NOTIFY_BTM_LAUNCH_ITEM_ADD/REMOVE              — ch10 persistence tracking
AUTH_EXEC                                      — ch03/ch06/ch11/ch15 exec policy
NOTIFY_WRITE                                   — ch07 IDS (marks wrote_tmp; no
                                                 ch12 config watch in this agent)
NOTIFY_UIPC_CONNECT                            — ch07 IDS network
AUTH_OPEN                                      — ch13 file auth
NOTIFY_CS_INVALIDATED                          — ch14 runtime integrity
```

The ES client delivers all of these on a single serial dispatch queue. Every event
type the client subscribes to shares that queue — there is no per-event-type
concurrency at the handler level.

### Shared state subsystems

The shipped agent keeps **two** hash tables plus per-node flags — not five
separate subsystems. What actually exists:

| State | Structure | Keyed by | Holds |
|---|---|---|---|
| Process tree (ch08 + ch14) | `g_tree[]` of `tree_node_t` | `audit_token_t` | parent link, path, `cs_invalidated` flag |
| IDS state (ch07) | `g_state[]` of `proc_state_t` | `audit_token_t` | exec/INET counters + windows, `wrote_tmp` |

TCC (ch09) and BTM (ch10) are handled **inline in the event handler with no
stored per-process state** — they alert on the spot and keep nothing. ch14
invalidation is a `cs_invalidated` flag on the tree node, not a separate table.

Both tables update on the same ES serial queue — no locking needed for NOTIFY
handlers because ES serializes them. The deferred AUTH work queue (ch15) runs
concurrently; it does **not** read the tables live — instead the ES-queue handler
snapshots the needed fields (`ancestry`, `cs_invalidated`) into the `auth_ctx_t`
before dispatching, so the worker only ever reads its own snapshot.

### Event ordering guarantees

ES delivers events in causal order per process: FORK before EXEC before EXIT
for a given audit token sequence. However, across different processes, delivery
order reflects arrival at the ES subsystem, not wall-clock order. Implications:

- A NOTIFY_EXEC and a NOTIFY_AUTHORIZATION_JUDGEMENT from different processes may
  arrive interleaved — the unified handler must not assume cross-process ordering.
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

g_work_queue (concurrent)
  └── evaluate_exec_and_respond() / evaluate_open_and_respond()
        ├── read the auth_ctx_t snapshot taken on the ES queue (not live tree)
        └── es_respond_auth_result() + es_release_message()

g_main_queue
  └── do_shutdown()   — signal handler posts here
      (ch16 does not do live config reload or es_mute_path; the main queue is
       used only for shutdown)
```

The critical constraint: `es_delete_client()` (and, in chapters that use them,
`es_mute_path()` / `es_unmute_path()`) must not be called from the ES handler
queue or the work queue. They must run on the main queue.

### The snapshot pattern for deferred AUTH

The deferred AUTH worker (ch15) reads process tree state to make its verdict.
But the process tree is mutated on the ES serial queue, and the work queue is
concurrent with the ES queue. Two approaches:

1. **Snapshot at retain time**: before `dispatch_async`, copy the relevant
   fields from shared state into a context struct. The shipped `auth_ctx_t`
   carries exactly the `ancestry` string and the `cs_invalidated` flag (read off
   the tree node); a richer agent would also snapshot a TCC grant set and
   BTM-pending marker here. The background worker reads the snapshot, not live
   state. This is the approach used: it is race-free because the snapshot happens
   on the ES queue before returning.

2. **Read lock**: protect the process tree with a `pthread_rwlock_t`. Readers
   (work queue) take a read lock; writers (ES queue FORK/EXEC/EXIT handlers)
   take a write lock. More flexible but introduces latency on the ES queue when
   a write lock is contended.

The snapshot approach is simpler and sufficient for this project.

## New concepts introduced

- **Multi-event subscription**: one `es_subscribe()` call with a large event
  type array. ES delivers all subscribed types on the same handler queue.
- **Static state, no init order**: the two tables (`g_tree[]`, `g_state[]`) are
  static arrays zero-initialized at load — there are no `*_init()` calls to order.
  The dependency that matters is at runtime: the AUTH snapshot reads the tree, so
  the tree must be populated by NOTIFY_FORK/EXEC before an AUTH consults it (which
  ES ordering guarantees for a given process).
- **Graceful shutdown across subsystems**: `do_shutdown()` must drain the work
  queue before calling `es_delete_client()`. Use `dispatch_barrier_sync(g_work_queue, ^{})` 
  to wait for all in-flight deferred AUTH responses before teardown.
- **Cross-subsystem context at the AUTH point**: because all subsystems share one
  process, the AUTH evaluator *could* consult ancestry, TCC grants, invalidation,
  and BTM-pending together. What the shipped evaluator actually snapshots and uses:
  - **AUTH_EXEC**: `cs_invalidated` (ch14, carried on the tree node) and
    `CS_DEBUGGED` (ch11 flag). Ancestry is snapshotted and printed but does **not**
    affect the verdict.
  - **AUTH_OPEN**: team_id + sensitive-path match (ch13).
  TCC grants (ch09) and BTM-pending (ch10) are tracked and alerted on
  independently, but are **not** wired into any AUTH verdict. Doing so is the
  natural next step, not current behavior.
- **Telemetry**: the shipped agent emits plain human-readable lines
  (`[EXEC]`, `[AUTH-EXEC]`, `[AUTH-OPEN]`, `[BTM-ADD]`, `[AUTH-JUDGEMENT]`,
  `[ALERT] ...`) to stdout/stderr — **not** JSON. AUTH_EXEC lines are annotated
  with the ancestry chain. A unified JSON/SIEM stream tagging every event with
  full cross-subsystem context (TCC grants, BTM-pending, codesign flags) is the
  production extension, building on ch07's JSON output — it is not implemented here.

## Shutdown correctness

The unified agent has more complex shutdown requirements than any single chapter:

1. Signal received → set `g_stop`, post `do_shutdown` to main queue.
2. `do_shutdown`:
   a. `dispatch_barrier_sync(g_work_queue, ^{})` — wait for all deferred AUTH
      workers to complete and respond. This is essential: calling `es_delete_client()`
      while a deferred response is in-flight is undefined behavior.
   b. `es_delete_client(g_client)` — tears down the ES subscription.
   c. Print `evals=/deadline-misses=` counters.
   d. `exit(0)` — static state is reclaimed by the OS; no explicit free.

Without the barrier, there is a window where a deferred AUTH worker calls
`es_respond_auth_result(g_client, ...)` after `es_delete_client()` has invalidated
`g_client` — a use-after-free.

## Architecture diagram

```
main()
 ├── init_timebase()
 ├── g_work_queue = dispatch_queue_create(CONCURRENT)
 ├── es_new_client() → handle_event
 ├── task_info + es_mute_process(self)   (self-mute only; no es_mute_path)
 ├── es_subscribe(ALL_EVENT_TYPES)
 └── dispatch_main()
 (g_tree[]/g_state[] are static, zero-initialized — no *_init calls; ch16 has
  NO ch12 config-watch and NO es_mute_path)

handle_event()
 ├── NOTIFY_FORK   → tree_get_or_create(child), link to parent token
 ├── NOTIFY_EXEC   → tree migrate token + path/ancestry; state migrate counters;
 │                   rule_exec_chain(); rule_sensitive_file_write()
 ├── NOTIFY_EXIT   → tree_remove(); state_remove()
 ├── NOTIFY_WRITE  → if path under /private/tmp: mark proc_state.wrote_tmp
 ├── NOTIFY_UIPC_CONNECT → rule_fanout()
 ├── NOTIFY_AUTHORIZATION_JUDGEMENT → TCC sensitive-right alert (inline, no state)
 ├── NOTIFY_BTM_LAUNCH_ITEM_ADD    → log + persistence alert (inline, no state)
 ├── NOTIFY_BTM_LAUNCH_ITEM_REMOVE → log (inline, no state)
 ├── NOTIFY_CS_INVALIDATED → set tree node cs_invalidated flag + alert
 ├── AUTH_EXEC → fill auth_ctx_t (ancestry, cs_invalidated) + es_retain_message()
 │               + dispatch to g_work_queue → evaluate_exec_and_respond
 └── AUTH_OPEN → fill auth_ctx_t + es_retain_message()
                 + dispatch to g_work_queue → evaluate_open_and_respond

evaluate_exec_and_respond(ctx) / evaluate_open_and_respond(ctx)  ← g_work_queue
 ├── check deadline (allow + release on miss)
 ├── read snapshot: ancestry (printed only), cs_invalidated
 ├── EXEC: platform→allow; cs_invalidated→deny; CS_DEBUGGED→deny; else allow
 ├── OPEN: platform→allow; read-only→allow;
 │         sensitive path + no team_id→deny; else allow
 └── es_respond_auth_result() + es_release_message()
```

## Detection policy in the unified agent

These are the rules the shipped `unified-agent.c` actually fires. They are
**independent** — there is no cross-signal scoring or convergence; each rule
evaluates on its own subsystem's events.

AUTH (deferred, on the work queue):

1. **Invalidated-process exec**: AUTH_EXEC where the tree node's `cs_invalidated`
   flag is set (from a prior NOTIFY_CS_INVALIDATED) → DENY.
2. **Debugged exec**: AUTH_EXEC with `CS_DEBUGGED` in `codesigning_flags` → DENY.
   (Platform binaries are fast-allowed before either check.)
3. **Sensitive-write open**: AUTH_OPEN, write mode, non-platform process with an
   empty team_id, on a sensitive path (`/etc/hosts`, `/etc/sudoers`,
   `TCC.db`, `/private/var/db/auth.db`, + `/private/etc` forms) → DENY.

NOTIFY (inline, alert-only):

4. **exec-chain**: a process exceeding 5 execs within 10 s → alert.
5. **sensitive-file-write**: a process that wrote under `/private/tmp` then exec'd
   → alert (flag resets after firing).
6. **fanout**: a process exceeding 10 INET connects within 30 s → alert.
7. **TCC sensitive grant**: a non-platform process granted Microphone, Camera,
   ScreenCapture, or SystemPolicyAllFiles → alert.
8. **BTM persistence**: a non-platform, no-team_id process registers a launch
   item → alert.
9. **CS_INVALIDATED**: any runtime signature invalidation → alert (and sets the
   tree-node flag consumed by rule 1).

The "malware triple" (browser ancestor + recent mic TCC + LaunchAgent install
driving a single DENY) and "post-persistence exec" deny are **design directions**,
not implemented: they would require feeding the TCC and BTM subsystems' per-process
state into the AUTH snapshot, which the current `auth_ctx_t` does not carry.

## ES event count limit (operational guidance — not implemented here)

ES clients have a per-client event backlog limit. If the handler queue falls
behind (the deferred AUTH work queue is saturated), ES will terminate the client
with a too-slow condition. A production agent would defend against this; the
shipped agent does **not** implement backpressure — it only counts deadline
misses (`g_deadline_misses`, printed at shutdown). The defenses a real agent adds:

- Keep deferred work bounded: if the work queue depth exceeds a threshold,
  fall back to synchronous policy evaluation for new AUTH events (deny if
  uncertain, log the degradation).
- Monitor deadline miss rate from the ch15 pattern — a high rate signals
  the work queue is falling behind the incoming event rate. The agent already
  tracks this counter; acting on it is left as the production extension.

## Relation to other chapters

This chapter synthesizes all prior chapters. Nothing new is introduced at the ES
API level — the new concepts are entirely about composition, state sharing, and
operational correctness in a multi-subsystem agent. It is the capstone chapter:
the goal every prior chapter was building toward.

A production macOS EDR agent is, in essence, this chapter — with more rules,
remote telemetry, and policy management. The ES API surface has been fully covered.

> Implemented: `16-unified-agent/unified-agent.c`
