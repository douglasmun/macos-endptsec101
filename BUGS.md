# BUGS.md

Audit findings and fixes across all chapters.

- Rounds 1–2: `01-hello-exec/hello-exec.c` — 9 bugs
- Round 3: `02-file-monitor` through `07-ids` — 11 findings
- Round 4: `02-file-monitor`, `05-muting`, `06-lsm-analog`, `07-ids` — 8 findings
- Round 5: `07-ids`, `06-lsm-analog` — 2 findings
- Round 6: `08-ancestry` — 4 findings
- Round 7: `08-ancestry` — 2 findings

---

## Round 1

### B1: Signal handler calls async-signal-unsafe functions
**Severity:** High  
**Location:** `on_signal()`

`es_delete_client()` and `exit()` are not async-signal-safe. Calling them directly from a signal handler while the ES dispatch queue is concurrently running the event callback can deadlock or corrupt internal ES state.

**Fix:** Signal handler now only sets an `atomic_int` flag and posts `dispatch_async_f()` to the main queue. Actual teardown runs in `do_shutdown()` on the main queue where it is safe.

---

### B2: EXEC case derived pid/ppid from wrong process
**Severity:** Medium  
**Location:** `handle_event()`, `ES_EVENT_TYPE_NOTIFY_EXEC` branch

`pid` and `ppid` were derived from `msg->process` (the pre-exec calling image) at the top of `handle_event`, then silently unused in the EXEC branch because we correctly used `target` there. This left stale variables in scope and made the code misleading.

**Fix:** Each case now derives its own `pid`/`ppid` from the correct source — `target` for EXEC, `msg->process` for FORK and EXIT.

---

### B3: No self-muting
**Severity:** Medium  
**Location:** `main()`

argus was not muted from its own ES client. Every `printf` to stdout could trigger file/write events that feed back into `handle_event`, potentially causing an event storm.

**Fix:** After `es_new_client()`, `es_mute_process()` is called with argus's own audit token obtained via `task_info(TASK_AUDIT_TOKEN)`.

---

### B4: Unused includes
**Severity:** Low  
**Location:** include block

`<stdlib.h>` and `<string.h>` were included but nothing from either was used.

**Fix:** Both removed.

---

## Round 2

### B5: UB function pointer cast in signal handler
**Severity:** High  
**Location:** `on_signal()`, line passing `do_shutdown` to `dispatch_async_f`

`dispatch_function_t` is `void (*)(void *)`. `do_shutdown` was declared as `void (void)`. Casting a mismatched function pointer and calling through it is undefined behavior per the C standard. On arm64 the callee receives a garbage x0 register — benign in practice here, but UB nonetheless.

**Fix:** `do_shutdown` signature changed to `void (void *)` with an unused `ctx` parameter, matching `dispatch_function_t` exactly. Cast removed.

---

### B6: path_truncated silently ignored
**Severity:** Medium  
**Location:** `handle_event()`, path printing for EXEC events

`es_file_t` has a `path_truncated` boolean. Paths exceeding ~16K characters are silently cut off. In a security monitor, a process with a truncated path could be misidentified or escape audit logging entirely.

**Fix:** Added `print_path()` helper that prints the path and appends `...(truncated)` when `path_truncated` is set.

---

### B7: ppid used instead of parent_audit_token
**Severity:** Medium  
**Location:** `handle_event()`, all three event cases

The ES header (`ESMessageCore.h:42`) explicitly documents: *"It is recommended to instead use the `parent_audit_token` field."* `ppid` is a raw `pid_t` — if the parent exits and its PID is reused before the ES event is delivered, `ppid` identifies the wrong process. `parent_audit_token` encodes a generation counter and is PID-reuse-safe. This distinction matters in a security tool.

**Fix:** Added `parent_pid()` helper using `audit_token_to_pid(proc->parent_audit_token)` instead of `proc->ppid`.

---

### B8: fflush called unconditionally including on unhandled events
**Severity:** Low  
**Location:** `handle_event()`, after the switch statement

`fflush(stdout)` was placed after the switch, so it fired on the `default:` branch even when no output was produced — a wasted syscall on every unsubscribed event type. Under high event volume this adds measurable overhead.

**Fix:** `fflush(stdout)` moved into each case branch, called only after actual output.

---

### B9: es_mute_process return value unchecked
**Severity:** Low  
**Location:** `main()`, self-mute block

`es_mute_process()` returns `es_return_t` which was ignored. If muting failed, argus continued silently without self-muting and could generate an event feedback storm with no indication of the problem.

**Fix:** Return value checked. Warnings emitted to stderr for both the `task_info` failure path and the `es_mute_process` failure path.

---

## Round 3 — ch02–ch07 audit

### B10: Wrong muting inversion type in 05-muting
**Severity:** High  
**Location:** `05-muting/muting.c`, `es_invert_muting()` call

`ES_MUTE_INVERSION_TYPE_PROCESS` was passed to `es_invert_muting()`, but the mute entries were added via `es_mute_path()`, which populates the path-muting table. `PROCESS` inversion operates on the process-muting table only. The path entries for `/usr/bin` and `/usr/sbin/dtrace` remained in denylist mode — the stated allowlist behavior was never achieved.

**Fix:** Changed to `ES_MUTE_INVERSION_TYPE_PATH`. Added comment explaining the two independent inversion tables.

---

### B11: Dead code — rule_suspicious_port unreachable in 07-ids
**Severity:** High  
**Location:** `07-ids/ids.c`, NOTIFY_UIPC_CONNECT handler

`port` was hardcoded to `0` immediately before an `if (port)` guard. `rule_suspicious_port()` could never be called. The file header listed Rule 1 (suspicious-port) as an active detection rule. Root cause: `es_event_uipc_connect_t` does not deliver the remote sockaddr for AF_INET/AF_INET6 connections.

**Fix:** Removed the dead call site. `rule_suspicious_port()` marked `__attribute__((unused))` as scaffolding for future dtrace/NEFilterDataProvider integration. File header and doc updated to reflect Rule 1 is inactive.

---

### B12: Path prefix matching allows false positives in 06-lsm-analog and 07-ids
**Severity:** Medium  
**Location:** `06-lsm-analog/lsm-analog.c` `path_is_protected()`; `07-ids/ids.c` `path_has_prefix()`

`memcmp(path, prefix, plen) == 0` without checking the character at `path[plen]`. `/etcfoo` matched `/etc`, `/tmpfile` matched `/tmp`. In ch06 this caused incorrect DENY verdicts; in ch07 it caused `wrote_tmp` to be set spuriously.

**Fix:** Added separator check: match only if `path->length == plen || path->data[plen] == '/'`.

---

### B13: Dead variable new_path_buf in 06-lsm-analog AUTH_CREATE
**Severity:** Medium  
**Location:** `06-lsm-analog/lsm-analog.c`, AUTH_CREATE case

`es_string_token_t new_path_buf` was declared and immediately suppressed with `(void)new_path_buf`. It was never written to or read. Implied intent (full path concatenation) was never implemented.

**Fix:** Variable removed. Comment added explaining that policy evaluates only the directory prefix.

---

### B14: JSON output not escape-safe in 07-ids
**Severity:** Medium  
**Location:** `07-ids/ids.c`, `emit_alert()`

The `detail` string was written directly into a JSON value field via `printf("%s")`. A path containing `"`, `\`, or a control character would produce malformed JSON, enabling content injection into the SIEM output stream.

**Fix:** Added `json_escape()` helper. All detail strings are escaped before the JSON `printf`.

---

### B15: path_truncated not checked for NEW_PATH directory in CREATE events
**Severity:** Low  
**Location:** `02-file-monitor/file-monitor.c` and `06-lsm-analog/lsm-analog.c`, `ES_DESTINATION_TYPE_NEW_PATH` branch

`print_str(&dir->path)` was used instead of `print_path(dir)`. `print_str` does not check `es_file_t.path_truncated`, so a deeply nested directory path could be silently logged truncated.

**Fix:** Changed to `print_path(dir)` in both files. For ch06, also switched logging of UNLINK target from `print_str(&target->path)` to `print_path(target)`.

---

### B16: sign-adhoc missing from .PHONY in 01-hello-exec Makefile
**Severity:** Low  
**Location:** `01-hello-exec/Makefile`

`sign-adhoc` was defined as a target but omitted from `.PHONY`. If a file named `sign-adhoc` existed, make would skip the target silently. This is the primary build path with an expired Developer membership.

**Fix:** Added `sign-adhoc` to `.PHONY`.

---

### B17: rule_unsigned_then_connect passed port=0, alert said "port=0"
**Severity:** Low  
**Location:** `07-ids/ids.c`

`rule_unsigned_then_connect()` accepted a `uint16_t port` parameter that was always `0`, producing alert text `"connected port=0"`. Port 0 is not a real destination port; it meant "unknown".

**Fix:** Removed `port` parameter. Alert text now reads `"opened INET connection"`.

---

### B18: es_mute_path argument order wrong in docs/05-muting.md
**Severity:** Low  
**Location:** `docs/05-muting.md`

The doc showed `es_mute_path(client, ES_MUTE_PATH_TYPE_PREFIX, "/usr/libexec")`. The actual API is `es_mute_path(client, path, type)` — path before type. The code was correct; only the doc was wrong.

**Fix:** Corrected to `es_mute_path(client, "/usr/libexec", ES_MUTE_PATH_TYPE_PREFIX)`.

---

### B19: docs/07-ids.md claimed beaconing and fan-out rules were implemented
**Severity:** Low  
**Location:** `docs/07-ids.md`

The doc listed "beaconing (connect interval regularity), fan-out (distinct destination ports per source)" as ported from ebpf101 ch23. Neither is implemented in `ids.c`.

**Fix:** Updated to accurately describe what is implemented (unsigned-then-connect, exec-chain), what is scaffolded (suspicious-port), and what is not yet written (beaconing, fan-out).

---

### B20: Deny list comment in 03-auth-exec omitted false-positive risk
**Severity:** Nit  
**Location:** `03-auth-exec/auth-exec.c`

The comment on `g_deny_list` noted that a renamed binary escapes the policy (false negative) but did not mention that any binary with the same leaf name is equally denied (false positive).

**Fix:** Comment extended to document both directions.

---

## Round 4 — code-review pass

### B21: Rule 3 (exec-chain) structurally inoperative — audit_token resets on every execve()
**Severity:** High  
**Location:** `07-ids/ids.c`, NOTIFY_EXEC handler

`proc_state_t` was keyed on `target->audit_token` (the post-exec process identity). Each `execve()` increments the audit token's generation counter, producing a new token that has no entry in the state table. `state_get_or_create()` always allocated a fresh `proc_state_t` with `exec_count=0`, so the counter could never accumulate past 1. Rule 3 could never fire regardless of exec frequency.

**Fix:** Exec-chain state is now tracked under `msg->process->audit_token` (the pre-exec caller token), which is stable across exec calls for the same process lifetime. Per-process data (path, is_platform, wrote_tmp) continues under `target->audit_token`, which matches the token carried by subsequent WRITE and CONNECT events.

---

### B22: exec_count not reset after alert fires — one alert per exec after threshold
**Severity:** High  
**Location:** `07-ids/ids.c`, `rule_exec_chain()`

After `exec_count` exceeded `EXEC_CHAIN_LIMIT`, the counter was incremented and the alert fired on every subsequent call within the same window. A process that execs 20 times in 4 seconds emitted 17 duplicate alerts for the same detection event, flooding stderr and the JSON output stream.

**Fix:** After emitting the alert, `exec_count` is reset to 0 and `exec_window_start` is set to `now`, starting a fresh window. One alert per window crossing.

---

### B23: es_subscribe called before es_invert_muting — startup window violates allowlist invariant
**Severity:** High  
**Location:** `05-muting/muting.c`, `main()`

`es_subscribe()` was called 47 lines before `es_invert_muting()`. During the intervening setup (mute_prefix, mute_literal, invert calls), EXEC events were delivered with an empty path denylist — every process on the system triggered the handler, the opposite of the intended "only /usr/bin/* reported" behavior.

**Fix:** `es_invert_muting()` and all `es_mute_path()` calls moved before `es_subscribe()`. Events are now only delivered after muting is fully configured.

---

### B24: Misleading Apple team ID in lsm-analog g_allowed_teams widens exec policy
**Severity:** Medium  
**Location:** `06-lsm-analog/lsm-analog.c`, `g_allowed_teams`

Apple's team ID `"59GAB85EFG"` was listed in `g_allowed_teams` with the comment "platform binaries handled separately." Platform binaries are short-circuited via `is_platform_binary` before `team_id_allowed()` is ever called — so the entry provides zero coverage for Apple's system binaries. What it actually did was allow any non-platform binary signed under Apple's team ID to exec unconditionally, silently widening the policy beyond intent.

**Fix:** Entry removed. Comment added explaining that the `is_platform_binary` fast-path makes an Apple team ID entry in this list both redundant and dangerous.

---

### B25: path_truncated not checked for RENAME new_path destination directory
**Severity:** Medium  
**Location:** `02-file-monitor/file-monitor.c`, NOTIFY_RENAME handler

The `ES_DESTINATION_TYPE_NEW_PATH` branch called `print_str(&dir->path)` directly, skipping the `path_truncated` check performed by `print_path()`. The `existing_file` branch on the line above correctly called `print_path()`. A rename into a deeply-nested directory with `path_truncated=true` was logged silently without the `...(truncated)` marker.

**Fix:** Changed to `print_path(dir)` with a comment that `filename` is separately printed via `print_str()` (filename is bounded by `NAME_MAX` and has no `path_truncated` field).

---

### B26: time_t signed underflow in rule_exec_chain on clock step-back
**Severity:** Medium  
**Location:** `07-ids/ids.c`, `rule_exec_chain()`

`now - s->exec_window_start` is a `time_t` (signed 64-bit on macOS). If the system clock steps backward (NTP correction, VM snapshot resume), `now < exec_window_start` and the subtraction yields a large negative value. Comparing a large negative `long` against `EXEC_CHAIN_WINDOW_S` (5) never satisfies the reset condition — the window never resets, `exec_count` grows without bound, and every exec fires a spurious alert indefinitely.

**Fix:** Added `now < s->exec_window_start` guard before the subtraction. Elapsed time stored in a separate `time_t elapsed` variable and cast to `unsigned long` for the alert format string, preventing negative values in the output.

---

### B27: gmtime() returns pointer to static struct — not safe under concurrent callers
**Severity:** Low  
**Location:** `07-ids/ids.c`, `emit_alert()`

`gmtime()` returns a pointer to a process-global static `struct tm`. The ES handler runs on a serial queue so no concurrent calls are possible today, but any future addition of a second ES client or concurrent dispatch queue would introduce a data race on the shared buffer, corrupting timestamps in alert records.

**Fix:** Replaced with `gmtime_r(&now, &tm_buf)` using a stack-local `struct tm tm_buf`.

---

### B28: Dead /tmp prefix check in NOTIFY_WRITE — ES always delivers resolved paths
**Severity:** Low  
**Location:** `07-ids/ids.c`, NOTIFY_WRITE handler

`path_has_prefix(path, "/tmp")` was checked alongside `path_has_prefix(path, "/private/tmp")`. On macOS, `/tmp` is a symlink to `/private/tmp`. ES populates `es_file_t.path` after symlink resolution, so the delivered path is always `/private/tmp/...` and the `/tmp` branch can never match. The `wrote_tmp` flag was still set correctly via the `/private/tmp` branch, but the dead check created a false impression of dual coverage and contradicted the project's documented understanding of ES symlink resolution.

**Fix:** `/tmp` prefix check removed. Explanatory comment added. Also, `s->is_platform` is now updated from `msg->process->is_platform_binary` on every WRITE and CONNECT event, correcting the startup race (B27-adjacent) where a process running before the IDS started had `is_platform` defaulting to 0.

---

## Round 5 — Gemini external review

### B29: Rule 3 exec-chain incomplete — state lost on every execve(), pre-exec entries leaked
**Severity:** High  
**Location:** `07-ids/ids.c`, NOTIFY_EXEC handler

The B21 fix changed the chain counter to be keyed on `msg->process->audit_token` (pre-exec) rather than `target->audit_token` (post-exec), but did not migrate state. The sequence was:

1. A execs to B: `state_get_or_create(&msg->process->audit_token)` found A's entry, incremented its `exec_count` to 1. `state_get_or_create(&target->audit_token)` created a fresh B entry.
2. B execs to C: `state_get_or_create(&msg->process->audit_token)` found B's entry — but B was created fresh in step 1 with `exec_count=0`, so it incremented to 1. A fresh C entry was created.

Every intermediate image's entry started with `exec_count=0`, so the chain counter never accumulated past 1. `EXEC_CHAIN_LIMIT` (3) was unreachable regardless of exec frequency. Additionally, intermediate state entries were never freed — NOTIFY_EXIT only fires for the final image token, so every intermediate proc_state_t leaked for the process lifetime.

**Fix:** State migration on NOTIFY_EXEC: `state_find(&msg->process->audit_token)` is called before creating the new entry. If found, `exec_count`, `exec_window_start`, and `wrote_tmp` are copied into the new entry. `state_remove(&msg->process->audit_token)` is then called immediately to free the old entry. `rule_exec_chain(s)` runs on the new (migrated) state, so counters accumulate correctly across the chain.

---

### B30: Prefix matching incorrectly rejects any absolute path when prefix is "/"
**Severity:** Low  
**Location:** `06-lsm-analog/lsm-analog.c` `path_is_protected()`; `07-ids/ids.c` `path_has_prefix()`

Both functions used `path->length == plen || path->data[plen] == '/'` to guard against false-positive prefix matches (e.g. `/etcfoo` matching `/etc`). When `prefix == "/"` (plen=1), this check evaluates `path->data[1] == '/'`. For any normal absolute path like `/usr/bin/ls`, `path->data[1]` is `'u'`, not `'/'` — so the match fails and the function returns 0. Any absolute path would be incorrectly excluded from a root-prefix match.

No current caller passes `"/"` as a prefix, but the guard is wrong for that case and misleads future use.

**Fix:** Added `plen == 1` as an additional branch. When `memcmp` already confirmed the path starts with `'/'`, a prefix of length 1 means "any absolute path" — the separator check is redundant and incorrect. Both files updated.

---

## Round 6 — ch08 audit

### B31: NOTIFY_EXEC migration: old == n use-after-free if pre- and post-exec tokens are equal
**Severity:** High  
**Location:** `08-ancestry/ancestry.c`, NOTIFY_EXEC handler

`tree_get_or_create(&target->audit_token, pid)` calls `tree_find` first. If a node already exists under `target->audit_token` (e.g., because a FORK event for this exact token was already processed), it returns that existing pointer. If `msg->process->audit_token == target->audit_token` (should not occur under normal ES semantics, but possible in edge cases), then `old == n`. The code then executed `tree_remove(&msg->process->audit_token)` which frees `n`, and the subsequent `copy_str_token(n->path, ...)` and `ancestry_str(n, ...)` become use-after-free.

**Fix:** Guard with `if (old && old != n)`. If `old == n`, skip the remove — the node already exists and no migration is needed. The `else if (!old)` branch handles the no-prior-entry case for the parent_token fallback.

---

### B32: ancestry_str silently omits unknown root when walk terminates at a missing table entry at depth > 0
**Severity:** Medium  
**Location:** `08-ancestry/ancestry.c`, `ancestry_str()`

When the ancestor walk terminates because an intermediate parent is not in the table (missing node), and at least one ancestor was already found (depth > 0), the chain was printed without any indication that the root is unknown. Only `depth == 0` (no ancestors at all found) prepended `(unknown) → `. A chain `bash(1234) → curl(9876)` was indistinguishable from a complete chain rooted at launchd vs. one missing several hops above bash.

**Fix:** Track `missing_root` as a separate flag set when the walk ends via `!anc`. Prepend `(unknown) → ` when either `depth == 0` or `missing_root == 1`. A complete chain (terminated at launchd sentinel) omits the prefix.

---

### B33: ancestry_str prints duplicate when start node is launchd (self-parent sentinel)
**Severity:** Low  
**Location:** `08-ancestry/ancestry.c`, `ancestry_str()`

When `ancestry_str` is called with a node whose `token == parent_token` (the launchd self-parent sentinel), the loop entered `&start->parent_token`, found the start node itself in the table, pushed it onto the stack (depth=1), then hit the sentinel check and broke. The printing code then printed the stack entry (`launchd(1) → `) followed by the start node again (`launchd(1)`), producing `launchd(1) → launchd(1)`.

**Fix:** Check `token_eq(&start->token, &start->parent_token)` before entering the ancestor loop. If true, skip the loop entirely. The node is printed alone with the `(unknown) → ` prefix (since depth==0 and missing_root==0 correctly indicates a known root with no ancestors).

---

### B34: ancestry_str casts snprintf return directly to size_t without negative check
**Severity:** Low  
**Location:** `08-ancestry/ancestry.c`, `ancestry_str()`

`pos += (size_t)snprintf(...)` casts the `int` return of `snprintf` directly to `size_t`. If `snprintf` returns a negative value (encoding error), the cast wraps to a very large `size_t`, setting `pos` far beyond the buffer. All subsequent writes via `buf + pos` are out-of-bounds. In practice `snprintf` with plain ASCII format strings never returns negative on macOS, but the cast is incorrect per the C standard.

**Fix:** Capture in `int rc`, guard `if (rc > 0) pos += (size_t)rc`. Applied to all `snprintf` calls in `ancestry_str` that contribute to `pos`.

---

## Round 7 — /code-review pass on 08-ancestry

### B35: ancestry_str incorrectly prepends "(unknown) →" for launchd as start node
**Severity:** Medium  
**Location:** `08-ancestry/ancestry.c`, `ancestry_str()`

The B33 fix added a self-parent sentinel check (`if (!token_eq(&start->token, &start->parent_token))`) that correctly skips the ancestor walk when `start` is launchd. However, the condition that prepends the `(unknown) →` prefix was `if (missing_root || depth == 0)`. After the skip, `depth == 0` and `missing_root == 0`. The `depth == 0` term fires unconditionally, producing `(unknown) → launchd(1)` — incorrectly marking launchd as having an unknown root when it is the root.

The two `depth == 0` cases are distinct:
- Walk skipped because start is the root (self-parent): chain is complete, no prefix needed.
- Walk attempted, first parent lookup returned NULL: `missing_root` is already set to 1 and covers this.

`depth == 0` is therefore redundant and incorrect when combined with `||`.

**Fix:** Replaced `if (missing_root || depth == 0)` with `if (missing_root)`. `missing_root` is set precisely when the walk terminates at a missing table entry. The launchd case leaves both flags at 0, producing `launchd(1)` alone as intended.

---

### B36: ancestry_str: old==n path leaves parent_token zero-initialized after fresh calloc
**Severity:** Low  
**Location:** `08-ancestry/ancestry.c`, NOTIFY_EXEC handler

When `old == n` (pre- and post-exec tokens equal — the B31 edge case), neither the `if (old && old != n)` branch nor the original `else if (!old)` branch ran. If `tree_get_or_create` allocated a fresh node (zeroed by `calloc`), `parent_token` was left as all-zeros. The subsequent `ancestry_str` call walked `tree_find(&zero_token)`, found nothing, set `missing_root=1`, and printed `(unknown) → process(pid)` — losing any parent link that could have been recovered from the ES event.

**Fix:** The `else if (!old)` branch was replaced with a plain `else` that handles both `!old` and `old==n`. Both cases fall back to `target->parent_audit_token` from the ES event, which is the best available parent information from the kernel. The comment documents both sub-cases explicitly.

---

## Round 8 — ch09–ch15 audit

### B37: storm_update deduplication substring-unsafe — right grants silently undercounted
**Severity:** Medium  
**Location:** `09-tcc/tcc.c`, `storm_update()` line 256

`strstr(e->rights, right_str)` was used to check whether a TCC right had already been counted in the storm window. A right whose full name is a substring of an already-stored right string (e.g., `"kTCCServiceCamera"` inside `"kTCCServiceCameraWithMicrophone"`) would falsely match, suppressing the count increment and undercounting the storm. Conversely, a previously stored short right could match as a substring of a new longer right name. The plain `strstr` has no word-boundary awareness.

**Fix:** Replaced with a boundary-aware search: `strstr` is still used to find candidate matches, but each match is accepted only if preceded by start-of-string or `','` and followed by `','` or `'\0'`. Both characters are delimiters in the comma-separated rights accumulation string.

---

### B38: handle_judgement attributes TCC grant to XPC broker instead of requesting app
**Severity:** High  
**Location:** `09-tcc/tcc.c`, `handle_judgement()` lines 317-319

`handle_judgement` preferred `ev->petitioner` over `ev->instigator` as the actor. In Authorization Services semantics, `instigator` is the actual requesting app; `petitioner` is the XPC broker (`authd`). The result: all three detection rules evaluated against the broker process (e.g., `authd`) rather than the app that requested the permission. `handle_petition` on line 292 correctly used `instigator`, making the two handlers inconsistent.

**Fix:** Swapped preference order — `ev->instigator` is now preferred over `ev->petitioner`, with `msg->process` as the final fallback. Added comment explaining the field semantics.

---

### B39: handle_judgement alert lines log silently-truncated path with no indicator
**Severity:** Low  
**Location:** `09-tcc/tcc.c`, `handle_judgement()` lines 335, 350, 360

`path_str` was built from `actor->executable->path` via `copy_str_token` without checking `path_truncated`. The `[TCC]` info log line (line 338) correctly used `print_path()` which flags truncation, but the alert `fprintf` lines on lines 350 and 360 used `path_str` directly, silently logging a truncated path with no indicator.

**Fix:** After building `path_str`, check `actor->executable->path_truncated` and `strlcat` a `"...(truncated)"` suffix into `path_str` when set, so all alert lines are consistent with the info line.

---

### B40: persistence self-mute failure silently skipped — feedback loop risk
**Severity:** Medium  
**Location:** `10-persistence/persistence.c`, lines 243-247

`task_info()` failure was silently ignored: if it failed, `es_mute_process()` was never called, the program continued, and every BTM event the daemon itself triggered would re-enter the handler in a feedback loop. The pattern was `if (kr == KERN_SUCCESS) { es_mute_process(...); }` with no else branch and no abort.

**Fix:** Both `task_info` and `es_mute_process` failures now abort with a `fprintf(stderr, ...)` and `es_delete_client` + `return 1`, consistent with the pattern in ch01 (B9) and ch03.

---

### B41: Rule 3 install-then-remove never fires — ADD and REMOVE use mismatched keys
**Severity:** High  
**Location:** `10-persistence/persistence.c`, lines 178-179 vs 193-208

The ADD handler stored `ev->executable_path` under the `g_pending` table. The REMOVE handler built its lookup key from `item->app_url`. These are structurally different fields (`executable_path` is a flat path on the ADD event; `app_url` is the BTM item's application URL). The two values will not match for the same item, so `pending_remove()` always returns 0 and the `[ALERT] execute-once-cleanup` message is never emitted regardless of how quickly an item is installed and removed.

**Fix:** Both handlers now use `item->item_url` (the BTM item's plist URL) as the common key, which is present and consistent across both ADD and REMOVE events for the same BTM item.

---

### B42: dynamic-policy data race — ES handler reads g_mute_paths while reload_config writes it
**Severity:** High  
**Location:** `12-dynamic-policy/dynamic-policy.c`, lines 139-144 (handler) vs 74-110 (reload_config)

`g_mute_paths` and `g_mute_count` were accessed without synchronization from two different queues: the ES handler queue (reads) and the main queue via `reload_config` (writes). On a multi-core system this is a data race under the C11 memory model: `g_mute_count` could be observed with the new value while `g_mute_paths` still contains old entries, causing an out-of-bounds prefix match or applying the wrong policy.

**Fix:** Added `os_unfair_lock g_config_lock`. The AUTH_EXEC handler locks before iterating `g_mute_paths`/`g_mute_count` and unlocks before calling `es_respond_auth_result`. `reload_config` snapshots the old list under lock, performs ES API calls outside the lock (to avoid holding the lock across potentially-blocking calls), then commits the new list under lock.

---

### B43: dynamic-policy NOTIFY_WRITE path_truncated not checked — spurious reload risk
**Severity:** Low  
**Location:** `12-dynamic-policy/dynamic-policy.c`, NOTIFY_WRITE handler line 170

`file->path_truncated` was not checked before comparing the write target path against `CONFIG_PATH`. A very long path that happens to share the first `MAX_PATH_LEN-1` bytes with `CONFIG_PATH` would trigger a spurious `reload_config` dispatch.

**Fix:** Added `if (file->path_truncated) break;` at the top of the NOTIFY_WRITE case — a truncated path cannot match `CONFIG_PATH` reliably, so skip.

---

### B44: auth-open is_write_open uses O_ flags against FREAD/FWRITE kernel flags
**Severity:** High  
**Location:** `13-auth-open/auth-open.c`, `is_write_open()` line 36

`AUTH_OPEN` delivers kernel `fflag` values (FREAD=0x1, FWRITE=0x2), not the open(2) `O_` flags (O_RDONLY=0, O_WRONLY=1, O_RDWR=2). The function used `(fflag & O_ACCMODE) != O_RDONLY` where `O_ACCMODE=3` and `O_RDONLY=0`. FREAD=1 masked with O_ACCMODE=3 yields 1, which is != 0 (O_RDONLY), so every read-only open was classified as a write open and subjected to the full deny policy. All read-only opens of sensitive files by non-platform processes were incorrectly denied.

**Fix:** Changed to `(fflag & FWRITE) != 0` using the `FWRITE` constant already defined in `<fcntl.h>` (included transitively). Removed the now-redundant local `#define FWRITE 0x2`.

---

### B45: auth-open path_is_sensitive ignores path_truncated — truncated sensitive path silently allowed
**Severity:** Low  
**Location:** `13-auth-open/auth-open.c`, `path_is_sensitive()` lines 43-44

`copy_str_token` was called without checking `file->path_truncated`. A file whose real path exceeds the buffer would have a truncated copy that fails the `strcmp` exact match, silently returning 0 (not sensitive) and allowing the write.

**Fix:** Added a `path_truncated` guard at the top of `path_is_sensitive`. A truncated path returns 0 (allow) with a comment noting the conservative choice for a learning chapter; a deny-by-default production policy would be the correct hardened behavior.

---

### B46: cs-invalidated inv table keyed on pid_t — PID reuse causes false-positive alerts
**Severity:** Medium  
**Location:** `14-cs-invalidated/cs-invalidated.c`, hash table and `handle_event()`

The invalidated-process table used `pid_t` as the key. If an invalidated process exits, its PID is recycled by an unrelated new process, and that new process execs, `inv_lookup(old_pid)` matches the innocent new process and emits `[ALERT] invalidated-process-exec` spuriously. `audit_token_t` encodes a generation counter and is PID-reuse-safe.

**Fix:** Changed `inv_entry_t` to store `audit_token_t token` instead of `pid_t pid`. Added `token_hash()` (XOR-fold over raw bytes mod table size) and `token_eq()` (memcmp). All `inv_insert`, `inv_lookup`, and `inv_remove` call sites updated to pass `&msg->process->audit_token` or `&target->audit_token` directly.

---

### B47: cs-invalidated path_truncated not checked before logging executable path
**Severity:** Low  
**Location:** `14-cs-invalidated/cs-invalidated.c`, NOTIFY_CS_INVALIDATED and NOTIFY_EXEC handlers

`copy_str_token` was used to build the path string without checking `exe->path_truncated`, so alerts for processes with very long executable paths silently logged a truncated path with no indicator.

**Fix:** After each `copy_str_token` call for an executable path, added `if (exe->path_truncated) strlcat(path, "...(truncated)", sizeof(path));` in both the NOTIFY_CS_INVALIDATED and NOTIFY_EXEC branches.

---

### B48: cs-invalidated task_info failure silently skips self-mute — feedback loop risk
**Severity:** Medium  
**Location:** `14-cs-invalidated/cs-invalidated.c`, lines 159-162

Same pattern as B40: `task_info` failure was silently ignored, skipping `es_mute_process`. The monitor would then receive and process its own ES events.

**Fix:** Both `task_info` and `es_mute_process` failures now abort with `fprintf(stderr, ...)` + `es_delete_client` + `return 1`.

---

### B49: deferred-auth path_truncated not checked in evaluate_policy — truncated paths logged silently
**Severity:** Low  
**Location:** `15-deferred-auth/deferred-auth.c`, `evaluate_policy()` lines 69, 81, 88, 95

All `printf`/`fprintf` calls in `evaluate_policy` used `%.*s` with `exe->path.length` and `exe->path.data` without checking `exe->path_truncated`. Processes with truncated paths were logged as if the path were complete.

**Fix:** Computed `const char *trunc = exe->path_truncated ? "...(truncated)" : ""` once at function entry and appended to all format strings as `%s` with `trunc`.

---

### B50: deferred-auth es_mute_process return value unchecked — blocked work queue risk
**Severity:** Medium  
**Location:** `15-deferred-auth/deferred-auth.c`, lines 224-227

`es_mute_process()` return value was unchecked. If muting failed, the tool would process its own `AUTH_EXEC` events on the concurrent `g_work_queue`. Each self-event would block a work queue thread waiting for the response that would only come once the already-blocked thread responded — a cascading deadlock pattern under high load.

**Fix:** Both `task_info` and `es_mute_process` failures now abort with `fprintf(stderr, ...)` + `es_delete_client` + `return 1`, preventing the dangerous unchecked-mute-failure state.

---

## Round 9 — ch16 audit

### B51: NOTIFY_AUTHORIZATION_JUDGEMENT TCC right-name matching wrong — prefix not stripped before comparing service name
**Severity:** High
**Location:** `16-unified-agent/unified-agent.c`, `handle_event` Authorization Judgement case

Authorization Services right names for TCC use the full qualified name `com.apple.TCC.kTCCServiceMicrophone`. The original code compared `r->right_name` directly against short service names like `"kTCCServiceMicrophone"` (length 24 vs full name length 38), so the length check `r->right_name.length == full` was correct in intent but the prefix stripping before the suffix comparison was inverted — it compared `r->right_name.data + plen` against `*sv` but `*sv` was the short service name without the TCC prefix. The net result: the comparison could never match since `svlen` equalled the suffix length but the comparison operand included `plen` offset incorrectly.

**Fix:** Rewrote the matching to: (1) check that `right_name.length > tcc_plen`, (2) memcmp the prefix, (3) extract `suffix_data = right_name.data + tcc_plen` and `suffix_len = right_name.length - tcc_plen`, (4) compare `suffix_data`/`suffix_len` against each short service name. Added NULL check on `ev` before use.

---

### B52: `rule_sensitive_file_write` never resets `wrote_tmp` after firing — re-fires on every subsequent exec
**Severity:** Medium
**Location:** `16-unified-agent/unified-agent.c`, `rule_sensitive_file_write()` line 337

After the alert fired, `wrote_tmp` remained 1. Every subsequent exec by the same process (including benign ones) re-triggered the alert, flooding stderr and masking real events.

**Fix:** Added `s->wrote_tmp = 0` after the `fprintf`/`fflush` in `rule_sensitive_file_write`.

---

### B53: IDS state old entry leaked on OOM in NOTIFY_EXEC handler — NOTIFY_EXIT cannot clean it up
**Severity:** Medium
**Location:** `16-unified-agent/unified-agent.c`, NOTIFY_EXEC handler, IDS state migration block

`state_remove` was only called inside `if (s && old_s)`. If `state_get_or_create` returned NULL (OOM) while `old_s` existed, the old entry remained under the pre-exec audit token indefinitely. `NOTIFY_EXIT` delivers the final image token (post all execs), not the pre-exec token, so the old entry was never freed.

**Fix:** Restructured to always call `state_remove(&msg->process->audit_token)` when `old_s` is non-NULL, regardless of whether the new allocation succeeded.

---

### B54: Tree node old entry leaked on OOM in NOTIFY_EXEC handler — same pattern as B53
**Severity:** Medium
**Location:** `16-unified-agent/unified-agent.c`, NOTIFY_EXEC handler, tree migration block

`if (!n) break` exited without removing the pre-exec tree entry when `tree_get_or_create` returned NULL. The old entry under `msg->process->audit_token` then leaked permanently.

**Fix:** Added `if (old) tree_remove(&msg->process->audit_token)` before the `break` on the OOM path.
