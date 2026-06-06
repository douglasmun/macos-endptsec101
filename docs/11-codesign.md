# 11-codesign

**ES analog of:** nothing in ebpf101 — ES-only capability

Linux `IMA/EVM` provides optional file integrity measurement, but it is not
universally deployed and is not a first-class security boundary. Apple Platform
Security makes codesign validation mandatory and kernel-enforced on every exec.
This chapter has no ebpf101 counterpart.

## The wall ch10 hits

ch10 can see that a process installed a LaunchAgent, and ch06 can see its
`team_id`. But `team_id` is coarse — it identifies the developer account, not
the specific binary. A compromised developer account, a malicious binary signed
under a valid team ID, or a binary with the team ID stripped would all evade a
team_id-only policy. `cdhash` is the answer: a cryptographic hash of the code
directory that is unique to the exact binary content and cannot be spoofed
without Apple's private key.

## The codesign identity hierarchy

From weakest to strongest:

| Identity | Survives rename? | Survives copy? | Survives re-sign? | Uniqueness |
|---|---|---|---|---|
| Path / leaf name | No | No | Yes | Non-unique |
| `team_id` | Yes | Yes | No | Per-developer-account |
| `signing_id` | Yes | Yes | No | Per-bundle-identifier |
| `cdhash` | Yes | Yes | No | Per-binary-content |

`cdhash` is the only identity that uniquely identifies a specific binary build.
A binary with the same source code compiled twice has a different cdhash if
any bit differs.

## `codesigning_flags` bitmask

Key flags (from `<sys/codesign.h>`):

| Flag | Meaning |
|---|---|
| `CS_VALID` | Signature present and valid |
| `CS_HARD` | Binary cannot run if signature becomes invalid |
| `CS_KILL` | Process is killed if signature becomes invalid at runtime |
| `CS_REQUIRE_LV` | Library validation: only platform or same-team dylibs may be loaded |
| `CS_PLATFORM_BINARY` | Apple platform binary |
| `CS_PLATFORM_PATH` | Loaded from platform path |
| `CS_DEBUGGED` | Process has been debugged (signature weakened) |

A binary with `CS_VALID` but not `CS_HARD` or `CS_KILL` can have its pages
invalidated at runtime without consequence — relevant for detecting runtime
patching.

## New concepts introduced

- **CDHash-keyed allowlist**: `AUTH_EXEC` handler that consults a table of
  allowed cdhashes. Only those exact binaries may execute. Rename, copy, or
  re-compile evade path-based and name-based policies but not CDHash policy.
- **`codesigning_flags` policy**: deny exec of binaries that are `CS_DEBUGGED`
  or lack `CS_HARD` (unsigned or weakly signed).
- **`signing_id` for bundle identity**: finer than `team_id` (identifies the
  specific app, not just the developer), coarser than `cdhash` (any version of
  the app matches).
- **CDHash persistence**: cdhashes must be enrolled in the allowlist at build
  time or via a trust-on-first-use mechanism. Ch11 implements a simple
  file-based allowlist with hex-encoded cdhash entries.

## Detection rules to implement

1. **CDHash allowlist**: `AUTH_EXEC` denies any binary whose cdhash is not in
   the compiled allowlist (opt-in model, not deny-by-default, to avoid locking
   out the system).
2. **Debugged binary exec**: alert when a process with `CS_DEBUGGED` set execs
   — a binary that has been attached to by a debugger has a weakened signature.
3. **Missing CS_HARD on sensitive binary**: alert when a binary in a sensitive
   path (e.g., `AUTH_OPEN` targets from ch13) lacks `CS_HARD` — it can be
   patched at runtime without consequence.

## ES events

- `AUTH_EXEC` (using codesign fields from `es_process_t`)

## Key ES API fields

- `target->cdhash` — 20-byte SHA-1 of the code directory (raw bytes)
- `target->codesigning_flags` — bitmask of CS_* flags
- `target->signing_id` — bundle identifier as `es_string_token_t`
- `target->team_id` — developer team ID as `es_string_token_t`
- `target->is_platform_binary` — Apple platform binary shortcut

## Relation to other chapters

- Extends ch06's AUTH_EXEC handler with CDHash and flags logic.
- CDHash context feeds into ch10's LaunchAgent policy (is the installed binary
  in the allowlist?).
- `CS_DEBUGGED` detection complements ch07's exec-chain rule.

> Implemented: `11-codesign/codesign.c`
