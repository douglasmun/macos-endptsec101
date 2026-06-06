# ebpf101 → macos-endptsec101 mapping

How each of the 23 ebpf101 chapters maps to an ES equivalent — and where the analogy breaks down.

## The one mental model (ebpf101 docs)

```
attach a hook → store/send data (map or buffer) → read in user space
```

ES equivalent:

```
es_new_client() + es_subscribe() → GCD dispatch queue → handle_event() prints/acts
```

The bridge (maps, perf buffers, ring buffers) collapses in ES: Apple manages the
delivery queue internally. You write a handler block; ES calls it. This makes ES
simpler to start with but less educational about the transport layer.

## Where ES is richer than eBPF (walls that don't exist here)

Several early ebpf101 chapters exist to work around limitations that ES doesn't have:

| ebpf101 wall | Why it doesn't exist in ES |
|---|---|
| Ch3: caller name, not launched binary | ES `NOTIFY_EXEC` gives you `target` (post-exec image) directly |
| Ch4→5: argv requires double-pointer walk | `es_exec_arg_count()` / `es_exec_arg()` hand you argv cleanly |
| Ch10: need exit tracepoint for return value | ES NOTIFY events carry outcome inline |
| Ch12→13: `comm` wrong in softirq context | ES always carries `audit_token` — PID-safe, context-safe |
| Ch6→7: BCC not portable | No equivalent — ES is always a compiled binary |

## Chapter-by-chapter mapping

### Group 1: Process observation (ebpf101 ch1–8 → macos-endptsec101 01)

| ebpf101 | Hook | New idea |
|---|---|---|
| 01 hello-world | kprobe + bpf_trace_printk | anything fires in kernel |
| 02 maps | BPF_HASH per-UID counter | kernel↔userspace shared state |
| 03 perf-buffer | BPF_PERF_OUTPUT, struct per event | per-event streaming |
| 04 tracepoint | sys_enter_execve, get filename | stable hook + launched binary path |
| 05 argv | double-ptr argv walk, multi-record | full command line |
| 06 ringbuf | BPF_RINGBUF, zero-copy | shared ring, back-pressure |
| 07 libbpf | CO-RE, skeleton, compiled binary | portable toolchain |
| 08 argv-libbpf | full argv in C | complete execsnoop in C |

**macos-endptsec101 01-hello-exec** covers all of this in one program because ES gives
you path, argv, PID, and PPID in a single `NOTIFY_EXEC` callback. The learning
here is the ES API shape, signal safety, and self-muting — not transport mechanics.

---

### Group 2: File monitoring (ebpf101 ch9–10 → macos-endptsec101 02)

| ebpf101 | Hook | New idea |
|---|---|---|
| 09 openat | sys_enter_openat | every file open with flags |
| 10 openat-ret | sys_enter + sys_exit stash map | return value / errno |

**macos-endptsec101 02-file-monitor**: `NOTIFY_CREATE`, `NOTIFY_WRITE`, `NOTIFY_UNLINK`,
`NOTIFY_RENAME`. ES gives both the operation and its target path — no entry/exit
stash needed. New idea: `es_mute_path()` with `TARGET_PREFIX` to filter noise
(analogous to ebpf101's kernel-side `O_RDONLY` filter).

---

### Group 3: Network (ebpf101 ch11–13 → macos-endptsec101 04)

| ebpf101 | Hook | New idea |
|---|---|---|
| 11 connect | sys_enter/exit_connect, sockaddr | outbound attempt + outcome |
| 12 tcpstates | kprobe tcp_set_state, BPF_CORE_READ | TCP state machine, kprobe CO-RE |
| 13 tcplife | tcp_sock cast, stash identity at SYN_SENT | per-connection summary |

**macos-endptsec101 04-network**: `NOTIFY_UIPC_CONNECT`. ES delivers process identity
correctly regardless of execution context (no softirq comm problem). The socket
address is available in `es_event_uipc_connect_t`. Simpler than ch11–13 combined.

---

### Group 4: AUTH / enforcement (ebpf101 ch20 → macos-endptsec101 03)

| ebpf101 | Hook | New idea |
|---|---|---|
| 20 lsm | LSM bprm_check_security | return value = security verdict |

**macos-endptsec101 03-auth-exec**: `AUTH_EXEC` + `es_respond_auth_result()`. Direct
analog — the ES AUTH event is macOS's `bprm_check_security`. Key new concepts:
deadline (`msg->deadline`), must respond or kernel defaults to ALLOW, response
must be from any thread (not necessarily the handler thread).

---

### Group 5: Noise filtering (ebpf101 ch19 → macos-endptsec101 05)

| ebpf101 | Hook | New idea |
|---|---|---|
| 19 tailcall | bpf_tail_call, PROG_ARRAY | program-to-program dispatch |

The analogy is loose. Tail calls are about program composition; ES muting is about
event suppression. But both solve the "too much data" problem.

**macos-endptsec101 05-muting**: `es_mute_process()`, `es_mute_path()` with prefix/literal
and target variants, `es_invert_muting()` for allowlist mode.

---

### Group 6: Policy engine (ebpf101 ch21 → macos-endptsec101 06)

| ebpf101 | Hook | New idea |
|---|---|---|
| 21 firewall | XDP + blocklist map, XDP_DROP | map-driven policy, drop at wire speed |

**macos-endptsec101 06-lsm-analog**: multiple AUTH events (`AUTH_EXEC`, `AUTH_CREATE`,
`AUTH_UNLINK`) evaluated against a rule set. Map-driven: rules loaded at startup,
evaluated synchronously in the handler. `is_platform_binary` and `codesigning_flags`
as policy inputs (no direct eBPF analog).

---

### Group 7: IDS (ebpf101 ch23 → macos-endptsec101 07)

| ebpf101 | Hook | New idea |
|---|---|---|
| 23 ids | AF_PACKET socket filter + ring buffer | dumb kernel tap, smart user-space rules |

**macos-endptsec101 07-ids**: multi-event ES subscription (exec + file + network). Same
architectural principle: ES side extracts raw events cheaply; C user-space runs
stateful detection rules (beaconing, suspicious exec chains, sensitive file access).
ES gives richer process context than a raw packet tap — process identity, code
signature, ancestry — so rules can be higher-level.

---

### Group 8: Process provenance (ebpf101 ch22 → macos-endptsec101 08, partial)

| ebpf101 | Hook | New idea |
|---|---|---|
| 22 iterator | BPF_ITER_PROG, seq_file | pull-model kernel task list snapshot |

**macos-endptsec101 08-ancestry**: live incremental process tree built from NOTIFY_FORK/EXEC/EXIT. The concept maps — both answer "what processes are running and how are they related?" — but the approach diverges. ebpf101 ch22 is a pull model: iterate the kernel task list on demand, get a snapshot. ch08 is a push model: maintain a live table updated by streaming events. The push model enables real-time ancestor walks at event time, which the pull model cannot do efficiently.

Key ideas ch22 cannot express: parent_audit_token as a PID-reuse-safe link, exec-time node migration (audit_token changes generation on execve), ancestry_str() as a real-time call during the event handler.

---

## Where the analogy ends: ch09–13 are ES-only

Chapters 01–07 have direct ebpf101 counterparts. Chapter 08 is a partial analog. From chapter 09 onwards there is no eBPF equivalent — the underlying macOS security mechanisms simply do not exist on Linux.

### 09-tcc — Privacy permission grants (`NOTIFY_TCC_MODIFY`)

TCC (Transparency, Consent, and Control) is macOS's unified privacy permission system. Every app access to camera, microphone, contacts, location, calendar, and Full Disk Access is mediated by TCC. `NOTIFY_TCC_MODIFY` fires when any permission is granted or revoked.

**Why no eBPF analog:** Linux has no kernel-enforced privacy permission layer. Camera and microphone access is controlled by device file permissions (`/dev/video0`, ALSA), not a centralized grant system. There is no single hook that fires when "an app acquires camera access."

**What this teaches:** TCC as macOS's capability system; how malware establishes persistent privacy access; correlating permission grants with the process and ancestry chain that triggered them; the distinction between user-granted and MDM-granted TCC entries.

### 10-persistence — LaunchAgent/Daemon installation (`NOTIFY_BTM_LAUNCH_ITEM_ADD/REMOVE`)

Background Task Management (BTM) is the macOS kernel subsystem that mediates registration of LaunchAgents, LaunchDaemons, and login items — the canonical macOS persistence mechanisms. `NOTIFY_BTM_LAUNCH_ITEM_ADD` fires when any persistence item is registered.

**Why no eBPF analog:** Linux persistence is scattered across cron, systemd unit files, rc.d, `/etc/profile.d`, and XDG autostart — no single kernel-visible registration chokepoint. There is no hook that fires when "a process installs a persistence mechanism."

**What this teaches:** How macOS persistence works at the BTM layer; what BTM covers (LaunchAgents/Daemons, login items) and what it misses (XPC services registered in bundles, cron, periodic scripts); combining BTM + TCC + ancestry into a high-confidence malware persistence signal.

### 11-codesign — Code identity policy (`cdhash`, `codesigning_flags`, `signing_id`)

ES carries full codesign context on every event. Ch06 used `team_id` for exec policy. Ch11 goes deeper: `cdhash` is a cryptographic hash of the code directory — the only identity that survives rename, copy, and re-signing. `codesigning_flags` exposes the full bitmask (`CS_VALID`, `CS_HARD`, `CS_KILL`, `CS_REQUIRE_LV`). `signing_id` is the bundle identifier.

**Why no eBPF analog:** Linux `IMA/EVM` provides file integrity measurement, but it is optional, not universally deployed, and not a first-class security boundary. Apple Platform Security makes codesign validation mandatory and kernel-enforced. The concept of a cryptographically bound identity carried on every process event has no Linux equivalent.

**What this teaches:** CDHash as the strongest available binary identity; `codesigning_flags` semantics; building a binary allowlist keyed by CDHash rather than path or team ID; why path-based and name-based policies are weaker than identity-based policies.

### 12-dynamic-policy — Runtime policy mutation

A production ES client cannot be restarted to change policy — that creates a gap window where events are missed. Ch12 teaches runtime mutation: `es_mute_path`/`es_unmute_path` called from a config file watcher (NOTIFY_WRITE on the config path), allowing policy changes without restarting the client or re-subscribing.

**Why no eBPF analog:** eBPF maps can be updated at runtime, but changing which event types are subscribed to requires reloading the program. ES allows subscription changes and muting changes on a live client. The operational model is fundamentally different.

**What this teaches:** The operational reality of a production ES client; hot policy reload without subscription gaps; separating the "what to watch" decision (muting) from the "what to do" decision (handler logic).

### 13-auth-open — Pre-open file descriptor authorization (`AUTH_OPEN`)


`AUTH_OPEN` fires before the kernel grants a file descriptor. This enables "no process except X may open `/etc/passwd` for writing" — a different cut than ch06's path prefix policy because it operates on the open, not the create or unlink. The `fflag` (open flags: `O_RDONLY`, `O_WRONLY`, `O_RDWR`) is available, so policy can distinguish read-only opens from write opens.

**Why no eBPF analog:** `seccomp` can filter `openat` syscalls by argument but carries no codesign context and cannot make allow/deny decisions based on who is calling (only what syscall with what arguments). LSM `inode_permission` hooks are closer but far less expressive — no team_id, no ancestry, no is_platform_binary.

**What this teaches:** AUTH_OPEN semantics and fflag interpretation; open-time policy vs create-time policy (why open-time is stronger for sensitive files that already exist); combining AUTH_OPEN with ancestry and codesign context for fine-grained file access control.

### 14-cs-invalidated — Runtime code injection detection (`NOTIFY_CS_INVALIDATED`)

`NOTIFY_CS_INVALIDATED` fires the moment the kernel marks a running process's
code signature as invalid — which happens when any of its code pages are
modified after exec via `ptrace`, `task_vm_map`, or a vulnerable dylib. This is
the detection hook for post-exec code injection, the most sophisticated attack
class that all prior chapters miss entirely.

**Why no eBPF analog:** Linux has no equivalent single hook for post-exec code
signature invalidation. `ptrace` writes to `/proc/<pid>/mem` are not mediated
by a unified observable event. There is no Linux kernel concept equivalent to
Apple's mandatory code signing boundary being invalidated at runtime.

**What this teaches:** The limits of static codesign checking (ch11 catches
exec-time; ch14 catches runtime); `CS_KILL` vs non-`CS_KILL` processes;
feeding `cs_invalidated` state into the ch08 process tree so subsequent AUTH
events from an injected process are denied; the attack surface that
`CS_INVALIDATED` covers and what it misses (ROP chains, shared-memory
injection).

### 15-deferred-auth — Deferred AUTH processing (`es_retain_message`)

Every AUTH handler in ch03–ch13 responds synchronously inside the handler
callback, blocking the ES serial queue for the duration of the policy
evaluation. Under high exec load this causes deadline expiry on queued events
— the kernel defaults them to ALLOW, defeating the policy. `es_retain_message`
solves this: retain the message, return from the handler immediately, do
expensive work (on-disk binary hashing, remote allowlist lookup) on a
background queue, respond before the deadline from there.

**Why no eBPF analog:** eBPF LSM programs make synchronous verdicts inside
the kernel. They cannot defer to user space for expensive computation — the
BPF program must return a verdict before the kernel hook returns. `es_retain_message`
has no eBPF counterpart because the entire ES deferred-response model has no
eBPF counterpart.

**What this teaches:** `es_retain_message` / `es_release_message` lifecycle;
deadline arithmetic with `mach_absolute_time()` and `mach_timebase_info`;
`es_respond_auth_result` safety from any thread; concurrent background queue
sizing; deadline-miss fallback policy; on-disk CDHash verification as the
canonical expensive AUTH operation.

---

## Chapters with no ES analog

| ebpf101 | Why no ES equivalent |
|---|---|
| 14 verifier | ES has no bytecode verifier — it's a compiled binary |
| 15 bashreadline | ES has no uprobe mechanism. dtrace uprobes or DynamoRIO could substitute |
| 16 bpftool | No equivalent operational tooling — `eslogger` (macOS 13+) is the closest |
| 17 xdp | XDP is NIC-level. Network Extension framework handles packet filtering on macOS |
| 18 tc | Same — Network Extension / NEFilterDataProvider |
| 22 iterator | ES is push-only; no pull/iterator model |

## What ES teaches that eBPF does not

- **Codesign context**: every ES event carries `is_platform_binary`, `codesigning_flags`,
  `team_id`, `signing_id`, `cdhash` — policy can be written against cryptographic code
  identity, not just path or process name.
- **Audit token vs PID**: ES bakes in generation-counter-safe process identity. eBPF
  programmers learn this the hard way (ch12→13 comm/softirq issues).
- **AUTH deadline**: ES AUTH events have a real kernel deadline. Missing it has
  consequences. eBPF LSM programs have no such constraint.
- **TCC events** (ch09): ES can observe privacy permission changes (`NOTIFY_TCC_MODIFY`)
  — camera, microphone, FDA, contacts. No eBPF analog exists because Linux has no
  unified privacy permission layer.
- **Persistence events** (ch10): `NOTIFY_BTM_LAUNCH_ITEM_ADD/REMOVE` fires when a
  LaunchAgent or LaunchDaemon is registered. No eBPF analog — Linux has no single
  persistence registration chokepoint.
- **Pre-open authorization** (ch13): `AUTH_OPEN` with `fflag` lets you block file opens
  by code identity before an fd is granted. `seccomp` filters syscalls by argument only;
  it has no codesign context.
- **Runtime integrity** (ch14): `NOTIFY_CS_INVALIDATED` fires when a live process's
  code pages are modified post-exec. Linux has no unified hook for this — `ptrace`
  writes are not mediated by a single observable event.
- **Deferred AUTH** (ch15): `es_retain_message` allows expensive policy work
  (on-disk hashing, remote lookup) to run on a background queue while the ES
  handler returns immediately. eBPF LSM programs must return synchronously from
  inside the kernel — this pattern is architecturally impossible in eBPF.
