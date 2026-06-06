# 14-cs-invalidated

**ES analog of:** nothing in ebpf101 — ES-only capability

Linux has no equivalent kernel hook for runtime code signature invalidation.
`ptrace` writes and `/proc/<pid>/mem` modifications are not mediated by a
single observable event. This chapter has no ebpf101 counterpart.

## The wall ch13 hits

ch13 authorizes file opens at the time the fd is granted. ch11 checks codesign
at exec time. But neither catches the most sophisticated attack class: **post-exec
code injection**. A process can pass both checks cleanly — valid CDHash at exec,
legitimate file opens — and then have its pages overwritten by a second process
via `ptrace`, task_vm_map, or a vulnerable dylib. The injected code runs with
the victim process's identity and privileges, invisible to every prior chapter.

`NOTIFY_CS_INVALIDATED` fires the moment the kernel marks a running process's
code signature as invalid — which happens when any of its code pages are
modified after exec. This is the detection hook for that class.

## What triggers CS invalidation

- `ptrace(PT_WRITE_I, ...)` — classic debugger code write
- `task_vm_map` / `mach_vm_write` — Mach task port injection
- Dylib hijack where the loaded dylib has a different CDHash than expected
- Memory-mapped file write to a code page that was already mapped executable
- `posix_spawn` with `POSIX_SPAWN_START_SUSPENDED` + injection before unsuspend

Notably: a process with `CS_HARD` set is killed by the kernel on invalidation
(`CS_KILL`). A process without those flags continues running with invalid
signature — and continues to receive AUTH verdicts and emit NOTIFY events as
if it were the original binary. `CS_INVALIDATED` is the only ES signal that
tells you this happened.

## What `CS_INVALIDATED` does NOT catch

- Injection via shared memory (no code page modification — the attacker maps
  executable memory in the victim and calls into it without modifying existing
  pages)
- ROP chains that reuse existing code pages (no invalidation — pages are not
  modified)
- Injection into a process that already has `CS_HARD`+`CS_KILL` (the kernel
  kills it before ES fires — you see NOTIFY_EXIT, not CS_INVALIDATED)

Documenting the gaps is essential: `CS_INVALIDATED` catches the naive injection
class, not the sophisticated one.

## New concepts introduced

- **`ES_EVENT_TYPE_NOTIFY_CS_INVALIDATED`**: the event carries only
  `msg->process` — the process whose signature was invalidated. No additional
  event-specific fields. The process identity, codesign flags, and ancestry
  are in `msg->process` as usual.
- **Correlating with prior state**: the useful signal is not the invalidation
  alone but what the process looked like before. Ch08's process tree already
  has the ancestry. Ch11's codesign context (was it `CS_HARD`? was it a
  platform binary?) determines severity. An unsigned binary being injected into
  is less alarming than a platform binary being injected into.
- **`codesigning_flags` at invalidation time**: after invalidation,
  `msg->process->codesigning_flags` will have `CS_VALID` cleared. Check
  `CS_KILL` — if set, the process is already dead and this event is the
  post-mortem notification. If `CS_KILL` is not set, the process is still
  running with injected code.
- **Response**: this is a NOTIFY event — no response required. The handler
  logs an alert and optionally feeds into ch07-style stateful rules (e.g.,
  flag any subsequent AUTH event from this process as suspicious).

## Detection rules to implement

1. **Any CS invalidation**: alert immediately. This is rare enough that every
   occurrence warrants investigation.
2. **Platform binary invalidated**: highest severity — a system binary has been
   injected into. Alert with full ancestry chain.
3. **Invalidated process subsequently opens sensitive file**: combine with
   AUTH_OPEN (ch13) — if an invalidated process later attempts to open
   `/etc/sudoers`, deny and alert regardless of its original codesign identity.
4. **Invalidated process with no CS_KILL**: process is still running with
   injected code. Flag its audit_token in the process tree so all subsequent
   events from it carry an "integrity compromised" marker.

## Architecture

Requires adding `CS_INVALIDATED` state to the ch08 process tree node
(`int cs_invalidated` flag). On `NOTIFY_CS_INVALIDATED`, set the flag. In
AUTH_OPEN (ch13) and AUTH_EXEC handlers, check the flag for the requesting
process — an invalidated process should be denied regardless of its original
codesign status.

## ES events

- `ES_EVENT_TYPE_NOTIFY_CS_INVALIDATED`

## Key ES API fields

- `msg->process->codesigning_flags` — `CS_VALID` will be clear; check `CS_KILL`
- `msg->process->audit_token` — look up in ch08 tree for ancestry context
- `msg->process->is_platform_binary` — platform binary injection is highest severity

## Relation to other chapters

- Extends ch11's codesign model from static (at exec) to dynamic (at runtime).
- Feeds into ch13's AUTH_OPEN handler: invalidated process → deny all sensitive opens.
- Uses ch08's process tree to add `cs_invalidated` state to the affected node.
- Shares the JSON alert output pattern from ch07.

> Implemented: `14-cs-invalidated/cs-invalidated.c`
