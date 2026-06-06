# 15-deferred-auth

**ES analog of:** nothing in ebpf101 — architectural pattern unique to ES AUTH events

eBPF LSM programs make synchronous verdicts inside the kernel — they cannot
defer to user space for expensive computation. ES AUTH events have a real
deadline (`msg->deadline`) but the response can come from any thread, enabling
a pattern that eBPF cannot express: retain the message, do expensive work on a
background queue, respond before the deadline. This chapter has no ebpf101
counterpart.

## The wall ch14 hits

Every AUTH handler in the project so far — ch03, ch06, ch11, ch13 — makes its
verdict synchronously inside the handler callback. The handler runs on ES's
internal serial dispatch queue. Any slow work (hashing a binary on disk,
querying a remote allowlist, reading a file) blocks that queue, which means
all other ES events for the entire system queue up behind it. Under high exec
load, the kernel deadline expires on queued events and defaults them to ALLOW
— defeating the policy entirely.

The production answer is `es_retain_message()`: take a reference on the
message, return from the handler immediately (freeing the ES queue for the next
event), do the expensive work on a separate queue, then call
`es_respond_auth_result()` from there before the deadline.

## What `es_retain_message` enables

Without retain: handler blocks ES queue → other events delayed → deadlines
expire → kernel defaults to ALLOW → policy defeated under load.

With retain:
```
handler()                       background queue
   es_retain_message(msg) ─────→ hash_binary(msg->event.exec.target)
   return                              ↓
                               es_respond_auth_result(verdict)
                               es_release_message(msg)
```

The ES queue is free immediately. The background queue races the deadline.
Multiple AUTH events can be in-flight simultaneously on different background
queue items.

## New concepts introduced

- **`es_retain_message(msg)`**: increments the reference count on the ES
  message, allowing it to be accessed after the handler returns. The message
  pointer remains valid until `es_release_message()` is called.
- **`es_release_message(msg)`**: decrements the reference count. Must be called
  exactly once for each `es_retain_message`. Forgetting to call it leaks the
  message allocation indefinitely.
- **Deadline arithmetic**: `msg->deadline` is a `uint64_t` Mach absolute time.
  Convert to a relative timeout with `mach_absolute_time()` and the
  `mach_timebase_info` conversion factor. The background work must complete and
  respond before this deadline or the kernel defaults to ALLOW.
- **`es_respond_auth_result` from any thread**: unlike most ES API calls,
  `es_respond_auth_result` is safe to call from any thread, not just the
  handler queue. This is what makes the deferred pattern possible.
- **Deadline expiry handling**: if the background work cannot complete in time
  (e.g., the binary to hash is on a slow NFS mount), the handler must have a
  fallback — either a conservative DENY or a permissive ALLOW with an alert.
  The choice is a policy decision, not a technical one, and must be explicit.
- **Dispatch queue sizing**: a serial background queue serializes all deferred
  work, which can cause its own backlog under load. A concurrent queue with a
  semaphore-bounded worker count is the production pattern.

## What to hash and why

The canonical expensive operation for an AUTH_EXEC deferred handler is
verifying the on-disk binary against its CDHash:

1. Open the binary path from `target->executable->path`
2. Read and SHA-1 hash the code directory (or use `SecStaticCodeCreateWithPath`
   + `SecCodeCopySigningInformation` for the full Apple verification chain)
3. Compare against `target->cdhash` (20 bytes) or the ch11 allowlist

This catches the attack that ch11 misses: a binary whose on-disk content was
modified *after* the codesign stamp was computed, but before exec. The kernel
maps the (now-modified) pages but the ES event carries the original cdhash. An
on-disk hash confirms the pages match what was signed.

## Deadline safety pattern

```c
case ES_EVENT_TYPE_AUTH_EXEC: {
    es_retain_message(msg);
    dispatch_async(g_work_queue, ^{
        uint64_t deadline = msg->deadline;
        uint64_t now      = mach_absolute_time();

        es_auth_result_t verdict;
        if (now >= deadline || deadline - now < MIN_WORK_BUDGET_TICKS) {
            /* Not enough time — fail safe */
            verdict = ES_AUTH_RESULT_DENY;
            log_deadline_miss(msg);
        } else {
            verdict = evaluate_policy(msg);
        }

        es_respond_auth_result(g_client, msg, verdict, false);
        es_release_message(msg);
    });
    break;
}
```

`MIN_WORK_BUDGET_TICKS` is a tunable — typically 50–100ms in Mach absolute
time units. If less than this remains before the deadline, fail to a known
verdict rather than racing.

## Detection rules to implement

This chapter is primarily architectural, demonstrating the deferred pattern.
The policy built on top of it is the ch11 CDHash verification extended with
on-disk hash confirmation:

1. **On-disk hash mismatch**: binary's on-disk SHA-1 does not match
   `target->cdhash` → DENY with high-severity alert. The binary was modified
   after signing.
2. **Deadline miss rate**: track how often the budget check fires. A high rate
   indicates the system is under load and the work queue needs tuning or the
   policy needs a faster path.

## ES events

- `AUTH_EXEC` (with `es_retain_message` / deferred response)

## Key ES API calls

- `es_retain_message(msg)` — take reference before returning from handler
- `es_release_message(msg)` — release after responding; must pair with retain
- `es_respond_auth_result(client, msg, verdict, cache)` — safe from any thread
- `msg->deadline` — `uint64_t` Mach absolute time; response must arrive before this

## Key system calls

- `mach_absolute_time()` — current Mach time for deadline arithmetic
- `mach_timebase_info()` — convert Mach ticks to nanoseconds
- `SecStaticCodeCreateWithPath` + `SecCodeCopySigningInformation` — full Apple
  codesign verification chain (links against Security.framework)

## The culmination

ch15 is the true production endpoint of the project. Every prior chapter
processed events synchronously. Ch15 introduces the pattern that a real
security agent must use: deferred, deadline-aware, concurrent AUTH processing.
The policy it enforces (on-disk hash verification) is also the strongest
binary identity check available — stronger than CDHash alone (ch11) because it
detects post-signing on-disk modification.

A production ES security agent is ch08 (process tree) + ch09 (TCC) +
ch10 (persistence) + ch11+ch15 (codesign + deferred verification) +
ch12 (live policy) + ch13 (AUTH_OPEN) + ch14 (runtime integrity) running as a
single client. The chapters have built every component of that agent
independently. Ch15 is where they would be composed.

## Relation to other chapters

- Extends ch11's CDHash policy with on-disk verification.
- The deferred queue pattern applies to any AUTH handler — ch06, ch13.
- Uses ch08's process tree for ancestry context in the background worker.
- Shares the JSON alert output pattern from ch07.

> Not yet implemented.
