# Endpoint Security API Invariants

Canonical list of ES API correctness rules accumulated across the audit rounds in
this project (see `BUGS.md` for the findings that produced each one). These are the
non-obvious traps the C ES API exposes; every chapter is expected to obey them.

## Client lifecycle & shutdown

- **Never** call `es_delete_client()` or `exit()` from a signal handler — both acquire
  locks. Set an atomic flag and `dispatch_async_f` the real shutdown to the main queue.
- **Always** call `es_subscribe()` *after* all muting is configured (`es_mute_path`,
  `es_mute_process`, `es_invert_muting`). Events are delivered immediately on subscribe —
  any muting configured afterward has a race window.
- `es_mute_path()` must **never** be called from within the ES handler callback —
  deadlock risk. Dispatch to the main queue via `dispatch_async_f`. This applies to
  `es_unmute_path()` and `es_unsubscribe()` as well.
- Deferred-AUTH shutdown ordering (ch15, ch16) is **unsubscribe → barrier → delete**,
  not barrier → delete. `dispatch_barrier_sync` only waits for blocks enqueued *before*
  it; if the client is still subscribed during the barrier, a new AUTH event can enqueue
  a worker afterward that the barrier never waited for, and that worker touches a freed
  client. Call `es_unsubscribe_all` first to stop new deliveries, then drain
  (`dispatch_barrier_sync(g_work_queue, ^{})`), then `es_delete_client`. Additionally
  gate the AUTH handler case on the shutdown flag
  (`if (atomic_load(&g_stop)) { es_respond_auth_result(...ALLOW...); break; }`) so a
  callback already mid-flight when unsubscribe lands does not retain/dispatch a doomed
  worker — and the kernel is not left waiting.

## AUTH vs NOTIFY responses

- NOTIFY events require **no** response. AUTH events **must** respond before the kernel
  deadline or the kernel defaults to ALLOW. Every code path through an AUTH handler must
  call `es_respond_auth_result()` — including early exits and OOM paths.
- In deferred AUTH (ch15, ch16): `es_retain_message` / `es_release_message` must be
  balanced on **every** code path through the evaluator, including the deadline-miss and
  OOM paths. `es_respond_auth_result` must also be called on every path — missing it on
  the deadline-miss path leaves the kernel waiting forever.

## Message & field validity

- ES message fields are valid **only** for the duration of the handler callback unless
  `es_retain_message()` is called.
- `es_string_token_t.data` is **not** null-terminated — always use the `length` field.
  Never pass `.data` to `printf("%s")` or `strlen()`. Use `%.*s` with `(int)length`.
- **Always** check `es_file_t.path_truncated` before logging/comparing paths. Use a
  `print_path(file)` helper, not raw `print_str(&file->path)`.
- `es_process_t.executable` may be NULL — NULL-check before dereferencing
  `actor->executable->path` (e.g. ch09 TCC handlers). Helpers that take an `es_file_t *`
  (e.g. `print_path`) should also NULL-check their argument so a NULL executable cannot
  crash the client.
- `team_id` and `signing_id` in `es_process_t` are `es_string_token_t` **values** (not
  pointers) — pass `&proc->team_id` when a pointer is expected.
- `cdhash` in `es_process_t` is a `uint8_t[20]` — always print as hex (`%02x` loop),
  never as a string.
- **Always** use `parent_audit_token` instead of `ppid` — `ppid` is susceptible to PID
  reuse.

## argv / exec

- **Always** use `es_exec_arg_count()` / `es_exec_arg()` to access argv — never walk
  `es_event_exec_t` directly (layout is version-dependent).

## Muting

- `es_mute_path()` signature is `(client, path, type)` — path before type.
- `es_mute_path()` applies *after* symlink resolution — mute `/private/tmp`, not `/tmp`.
- `es_invert_muting()` has separate inversion types:
  `ES_MUTE_INVERSION_TYPE_PROCESS` for process muting and
  `ES_MUTE_INVERSION_TYPE_PATH` for path muting. They are independent.

## Path prefix matching

- Path prefix matching must require a `/` separator after the prefix — `memcmp` alone
  matches `/etcfoo` against `/etc`. When `prefix == "/"` (plen==1), skip the separator
  check — `memcmp` already verified the path starts with `/`, so any absolute path is a
  valid match.

## Network

- `NOTIFY_UIPC_CONNECT` does **not** deliver the remote sockaddr for AF_INET/AF_INET6 —
  `es_event_uipc_connect_t` carries only `domain`, `type`, `protocol`, and `file` (Unix
  socket path).

## Stateful tracking — process tree (ch08) & IDS state (ch07, ch16)

- NOTIFY_FORK is the **only** reliable point to capture the parent→child relationship.
  By the time EXEC fires for the child, the parent may have already exited in a
  fork+exec pattern. Record the link on FORK; update the path on EXEC.
- NOTIFY_EXEC must **migrate** the tree node / state entry from the pre-exec token to the
  post-exec token, carrying `parent_token` (tree) or counters (state) across. Without
  migration the ancestry walk breaks and exec-chain counters reset on every execve.
- The migration guard must be `if (old && old != n)` (and `if (old_s && old_s != s)` for
  the state table). If the pre- and post-exec tokens are equal, `old == n`; an unguarded
  `tree_remove`/`state_remove` would free the entry that the subsequent `rule_*()` calls
  dereference (use-after-free). In ch16 the guard is required on **both** the tree table
  and the IDS state table.
- Always call `state_remove` / `tree_remove` on the old pre-exec token when the old entry
  exists, **regardless** of whether the new `state_get_or_create` / `tree_get_or_create`
  succeeded (e.g. on the OOM path). NOTIFY_EXIT only delivers the final image token —
  pre-exec tokens not explicitly removed leak permanently.
- When no FORK was observed for a process (it was already running at subscribe time),
  fall back to `target->parent_audit_token` from the EXEC event as the best available
  parent link.
- Stateful rules that fire and reset a flag (e.g. `wrote_tmp`, an exec-chain counter)
  must reset the flag inside the rule function after firing — otherwise the rule re-fires
  on every subsequent event by the same process.

## Ancestry walk (ch08)

- `ancestry_str()` must cap the walk at a fixed depth (`ANCESTRY_DEPTH_MAX`) — stale
  parent-token entries could otherwise create a cycle. Also stop when a node's token
  equals its own parent token (launchd sentinel).
- `ancestry_str` must track a `missing_root` flag separately from `depth == 0`. A walk
  that terminates because an intermediate node is absent (not because the launchd
  sentinel was reached) is an incomplete chain and must be labeled `(unknown) → `
  regardless of how many ancestors were found.
- When `start->token == start->parent_token` (launchd passed to `ancestry_str`), skip the
  ancestor walk entirely — entering it would find `start` itself in the table, push it,
  and print it twice. After the skip, `depth==0` and `missing_root==0`. Use only
  `missing_root` as the condition to prepend `(unknown) →` — not `depth==0`, which fires
  for the launchd case too and would mislabel a complete chain.

## Numeric / formatting safety

- `snprintf` return values must be captured in `int rc` and guarded `if (rc > 0)` before
  casting to `size_t` for position accumulation. Direct cast of a potentially-negative
  `int` to `size_t` wraps to a huge value and corrupts the write position.
- Signed `time_t`: guard elapsed-time windows with `now >= t && now - t <= WINDOW`. A
  backward clock step makes `now < t`, so `now - t` is negative and would pass a bare
  `<= WINDOW` test, firing the rule with a nonsensical negative elapsed time.
- Use `gmtime_r()` not `gmtime()` — `gmtime()` returns a pointer to a static struct that
  is not safe under concurrent callers.

## Dispatch

- `dispatch_function_t` is `void (*)(void *)` — functions passed to `dispatch_async_f`
  must match this signature exactly.

## Policy / allowlist logic

- `team_id_allowed()` is only reached for non-platform binaries. Adding Apple's team ID
  to an allowlist does not cover platform binaries (they are allowed earlier) — it
  instead allows any non-platform binary signed by Apple.

## TCC / authorization (ch09)

- `NOTIFY_TCC_MODIFY` is not available in all SDK versions. Use
  `NOTIFY_AUTHORIZATION_JUDGEMENT` as the closest available alternative. TCC right names
  in Authorization Services judgements carry the prefix `com.apple.TCC.` — strip it
  before comparing against short service names (`kTCCServiceMicrophone` etc).

## BTM / persistence (ch10, ch16)

- In BTM handlers, `instigator` may be NULL — always NULL-check before dereferencing.
  Fall back to `msg->process` when NULL.
