# macos-endptsec101

A chapter-by-chapter macOS security monitoring project built on Apple's [Endpoint Security](https://developer.apple.com/documentation/endpointsecurity) C API — a deliberate analog of [ebpf101](https://github.com/douglasmun/ebpf101), which teaches the same lessons through Linux eBPF.

If you have worked through ebpf101 and want to understand how macOS kernel security works at the same depth, this is that project. If you are coming fresh, it stands alone — but the comparison to eBPF is woven into every chapter because the contrast is where the real learning lives.

---

## The premise

eBPF and Endpoint Security are solving the same problem from opposite directions.

eBPF gives you a programmable hook inside the Linux kernel. You write a small program, load it with the `bpf()` syscall, and it runs at tracepoints, kprobes, or LSM hooks — observing or intercepting system calls with minimal overhead. The power is raw and the surface is enormous, but so is the boilerplate. ebpf101 spends eight chapters just reaching full `execsnoop` output because every step is explicit: ring buffers, perf maps, CO-RE relocation, argv double-pointer walks. You earn each piece of the picture separately.

Endpoint Security is Apple's answer to the same need. Instead of a programmable kernel module, you register a client in user space, subscribe to event types, and receive structured messages on a GCD dispatch queue. The kernel does the marshalling. You get path, argv, PID, and a generation-safe parent identity in the first callback you write. What eBPF teaches across eight chapters, ES gives you in one — but it trades that convenience for a different set of constraints: a serial delivery queue, AUTH deadlines, a self-muting requirement, and an API where ignoring the invariants causes silent correctness failures rather than compiler errors.

The goal of this project is to make both sides of that tradeoff viscerally understood.

---

## The learning arc

### Chapters 01–04: learning to see

The first four chapters build the observational foundation. They cover the same ground as ebpf101 ch1–13, but the shape of the learning is completely different.

**Chapter 01 — process lifecycle** (`NOTIFY_EXEC`, `NOTIFY_FORK`, `NOTIFY_EXIT`) is where the ES programming model is introduced in full. The very first version of the program has nine bugs — not contrived ones, but the exact mistakes a careful programmer makes when encountering ES for the first time. You call `es_delete_client()` from a signal handler without knowing it acquires locks and can deadlock. You use `ppid` instead of `parent_audit_token` without knowing that PIDs are reused and `ppid` is therefore unsafe in a long-running security monitor. You pass `es_string_token_t.data` directly to `printf` without knowing it is not null-terminated. You forget to self-mute, and your own `printf` calls trigger file events that feed back into your handler. All nine bugs are documented in [BUGS.md](BUGS.md). Finding and fixing them is the chapter.

The eBPF analog is ch1–8. Those chapters are about transport mechanics — how to get data out of the kernel at all. ES skips that entirely. Chapter 01 teaches something different: the API has correctness invariants that are easy to miss, invisible to the compiler, and expensive to debug in production. Knowing them upfront is the curriculum.

**Chapter 02 — file events** (`NOTIFY_CREATE`, `NOTIFY_WRITE`, `NOTIFY_UNLINK`, `NOTIFY_RENAME`) extends observation to the filesystem. The central invariant is `path_truncated`: the kernel silently truncates paths longer than `PATH_MAX` and sets a flag on the `es_file_t`. Every path logged without checking this flag is a latent correctness bug that will not manifest until a deep directory tree hits the boundary. The eBPF approach (ch9–10) requires two separate `openat` probes and a BPF map to correlate entry and return. ES delivers the full event, process identity and all, in a single callback.

**Chapter 03 — blocking execution** (`AUTH_EXEC`) is the first departure from pure observation. ES introduces the AUTH event type: the kernel holds the process at the `execve` boundary and waits for your verdict before proceeding. Two rules define this chapter. First, `is_platform_binary` — system binaries signed by Apple must be fast-allowed before any policy evaluation, not as a courtesy but as a correctness requirement; blocking them will break the system in ways that are difficult to diagnose. Second, the AUTH deadline: if your handler returns without calling `es_respond_auth_result()`, the kernel defaults to ALLOW after a timeout. Every code path — including early exits and error returns — must respond. Missing a single path is a policy bypass that silently fails open. eBPF LSM (ch20) makes its verdict synchronously inside the kernel with no round trip. ES AUTH crosses to user space with a deadline, which trades latency for far greater expressiveness.

**Chapter 04 — network connections** (`NOTIFY_UIPC_CONNECT`) introduces one of ES's documented limitations and teaches you to read around it. For `AF_INET` and `AF_INET6` sockets, the remote `sockaddr` is not delivered. You observe that a connection was made, the socket domain and type, and the remote path for Unix domain sockets — but not the remote IP or port for TCP/UDP connections. eBPF at this point (ch11–13) captures the full `sockaddr` at the kprobe site. The chapter is as much about knowing what ES cannot tell you as what it can, and about designing monitors that compensate.

---

### Chapter 05: learning what not to see

**Chapter 05 — muting** (`es_mute_path`, `es_mute_process`, `es_invert_muting`) is the chapter ebpf101 never needed to write, because eBPF filters run inside the kernel where the cost of discarding an unwanted event is near zero. ES delivers every subscribed event across the user/kernel boundary. On a busy system that is tens of thousands of events per second from compilers, browsers, Spotlight, and system daemons — none of which you care about.

`es_mute_path()` suppresses all events for processes whose executable path matches a prefix. `es_mute_process()` suppresses by audit token. `es_invert_muting()` flips the polarity: instead of a denylist of noisy processes, you operate as an allowlist and receive events only from processes that are *not* muted. The ordering invariant is absolute: all muting configuration must complete before `es_subscribe()`. Events arrive the moment you subscribe. There is no race-free way to add mutes after that point — any mute added post-subscribe has a window where events it should have suppressed have already been delivered.

---

### Chapter 06: composing AUTH events into a policy engine

**Chapter 06 — LSM analog** (`AUTH_EXEC`, `AUTH_CREATE`, `AUTH_UNLINK`) combines multiple AUTH event types into a policy engine. A process cannot execute, create, or delete a protected file without passing a check that considers the executable path, codesign identity, and target path together. The eBPF analog is ch21 (XDP firewall): both enforce policy at a syscall boundary, but the ES version has codesign context baked into every event — something XDP has no concept of.

The non-obvious correctness problem here is prefix matching. `memcmp("/etc", path, 4)` returns 0 for both `/etc/passwd` and `/etcfoo`. The separator check — requiring a `/` immediately after the matched prefix, with a special case when the prefix is `/` itself — is the difference between a sound policy rule and one that is trivially bypassed with a crafted filename. This is one of six bugs found in this chapter across the audit rounds documented in BUGS.md.

---

### Chapter 07: stateful detection

**Chapter 07 — IDS** is where the architecture shifts from per-event policy to stateful behavioral detection. A hash table keyed by `audit_token_t` accumulates per-process counters — file writes, network connections, exec invocations. Rules fire when a process crosses a threshold across events, not because any single event is suspicious.

The chapter's central ES-specific challenge is token migration on `execve`. When a process calls `execve`, its audit token changes to reflect the new process image. Without explicit migration — copying the old process's counters into an entry keyed by the new token, then removing the old entry — exec chains silently reset their counters to zero on every `execve`, and old entries leak memory because `NOTIFY_EXIT` only removes the final image's token. Rules that should fire after N events across an exec chain never fire. The eBPF equivalent (ch23) never encounters this: eBPF sees a stable PID across exec. The ES audit token model is more correct for security purposes — it provides generation-safe identity that survives PID reuse — but correctness demands explicit migration at every `NOTIFY_EXEC`.

The eBPF parallel runs deep here: both ch07 and ebpf101 ch23 implement a user-space rule engine over a kernel event stream with the same dumb-tap / smart-analysis split. The architecture is identical. The ES version is cleaner to write but has a harder correctness surface.

---

### Chapter 08: provenance and process trees

**Chapter 08 — ancestry** builds a live, incrementally-maintained process tree from `NOTIFY_FORK` and `NOTIFY_EXEC` events. The goal is answering "what spawned this process?" without relying on `ps` or `/proc` — both of which reflect current state, not causal history, and are unreliable in a security context where a parent may have already exited.

The design is an `audit_token_t`-keyed hash table. `NOTIFY_FORK` is the only reliable point to capture the parent→child relationship: by the time `NOTIFY_EXEC` fires for the child in a fork+exec pattern, the parent may have already exited. `NOTIFY_EXEC` migrates the node — carrying `parent_token` forward under the new token, same as ch07. `NOTIFY_EXIT` removes it.

`ancestry_str()` walks the chain from any process up to `ANCESTRY_DEPTH_MAX` hops, stopping at the launchd sentinel — the process whose own token equals its parent token. Two correctness requirements interact here: capping depth prevents cycles from stale entries, and a `missing_root` flag (tracked separately from `depth == 0`) distinguishes a complete chain that terminates at launchd from one where an intermediate node was simply absent from the table. The `depth == 0` case alone is wrong: it fires for launchd itself and would incorrectly label a fully-resolved chain as having an unknown root.

The detection rule built on top of this infrastructure: flag any download tool (`curl`, `wget`, `python`, `nc`) whose ancestry chain contains a browser. On eBPF, ch22 does process iteration as a pull-model snapshot. This chapter builds a push-model live tree — a fundamentally different approach to the same provenance question.

---

### Chapters 09–16: what macOS can do that Linux cannot

Chapters 01–07 show ES as an alternative route to the same destination as eBPF — the same security visibility, achieved through a different mechanism. Chapter 08 is a partial analog. Chapters 09 through 16 are something different entirely: ES capabilities that have no eBPF counterpart, not because eBPF is limited as a technology, but because the macOS security model has kernel-enforced chokepoints that the Linux kernel simply does not have.

**Chapter 09 — TCC** (`NOTIFY_AUTHORIZATION_JUDGEMENT`) gives you visibility into privacy permission grants. When a process is granted or revoked access to the camera, microphone, Full Disk Access, contacts, or location, you receive a structured event with the requesting process's identity and the specific service affected. Linux has no equivalent: camera and microphone access is not kernel-mediated, and there is no unified privacy permission layer at the OS level.

**Chapter 10 — persistence** (`NOTIFY_BTM_LAUNCH_ITEM_ADD`, `NOTIFY_BTM_LAUNCH_ITEM_REMOVE`) detects LaunchAgent and LaunchDaemon installation at the BTM registration chokepoint — the single kernel-visible event through which all persistence items pass on modern macOS. On Linux, persistence is scattered across the filesystem (cron tabs, systemd unit files, rc.d scripts, shell profile modifications). There is no single event to hook.

**Chapter 11 — codesign** (`AUTH_EXEC` + `cdhash`) builds a CDHash-based binary allowlist. `cdhash` is a content-addressed identity — a SHA-256 of the code pages — that the kernel validates and provides on every `AUTH_EXEC`. An allowlist keyed by CDHash allows exactly the binaries you approved, not binaries with the same name or path. On Linux, IMA/EVM provides something superficially similar, but it is optional and not a first-class security boundary. On macOS, codesign identity is mandatory, always present, and kernel-enforced.

**Chapter 12 — dynamic policy** (`es_mute_path`, `es_unmute_path`) demonstrates live policy mutation without restarting the ES client. A config file watcher drives `es_mute_path`/`es_unmute_path` calls at runtime, changing which paths generate events while the client is running. eBPF maps can be updated at runtime, but adding or removing a subscription to a new event type requires reloading the BPF program. ES allows both muting changes and subscription changes without restart.

**Chapter 13 — AUTH_OPEN** intercepts file opens before the file descriptor is returned to the caller. Unlike `NOTIFY_CREATE` and `NOTIFY_UNLINK`, which fire after the fact, `AUTH_OPEN` fires before the kernel grants access — and it carries `fflag` to distinguish read intent from write intent. Combined with the process's codesign identity, this enables per-open access control policies that `seccomp` cannot match: `seccomp` can filter `openat` by syscall number but carries no process identity and no codesign context.

**Chapter 14 — CS_INVALIDATED** (`NOTIFY_CS_INVALIDATED`) detects runtime code injection. When a running process's code signature is invalidated — because unsigned code was injected into its address space via `ptrace`, a dylib was loaded without a valid signature, or a JIT engine wrote unsigned pages — ES fires this event. On Linux, there is no equivalent hook for post-exec code signature invalidation. `ptrace` writes happen without any single mediated event that a monitor could observe.

**Chapter 15 — deferred AUTH** (`es_retain_message`) addresses a performance constraint in the AUTH model. The ES serial queue delivers events one at a time. An `AUTH_EXEC` that requires a slow policy lookup — a network call, a cache miss, a hash computation — blocks all subsequent event delivery while it waits. `es_retain_message()` extends the message's lifetime beyond the handler callback, allowing you to move the policy evaluation onto a concurrent dispatch queue and respond asynchronously before the kernel deadline. eBPF LSM programs make synchronous verdicts inside the kernel with no round trip possible. The deadline model is unique to ES.

**Chapter 16 — unified agent** brings all subsystems together into a single `es_new_client()` instance. A single ES client can subscribe to every event type simultaneously, and this chapter exploits that: the IDS rule engine from ch07 is informed by the ancestry context from ch08, the codesign allowlist from ch11 gates `AUTH_EXEC` alongside the behavioral rules, and deferred AUTH from ch15 handles the latency. Shared state across what would be separate eBPF programs on Linux is the architectural point of this chapter — and the composability of a single ES client with a unified process tree is something the Linux eBPF model, which loads separate programs per event type, cannot replicate without external coordination.

---

## The structural observation

This is what the project as a whole teaches:

eBPF and ES are peers for the first seven chapters — the same security visibility, achieved differently. eBPF earns it through explicit transport mechanics; ES delivers it through structured marshalling with stricter API invariants. Chapters 01–07 show that if your goal is process monitoring, file monitoring, network monitoring, and basic policy enforcement, both tools get you there. The route is different; the destination is the same.

After chapter 07, the analogy stops holding. Chapters 09 through 15 are not "the ES way to do what ch14–22 of ebpf101 does." They are capabilities that exist in ES because macOS has kernel-enforced security primitives — TCC, BTM, mandatory codesign — that the Linux kernel has no equivalent of. You cannot build ch09 in eBPF because the Linux kernel does not mediate camera access. You cannot build ch11 in eBPF because Linux codesigning is optional. You cannot build ch15 in eBPF because eBPF LSM verdicts are synchronous by design.

That is the most important thing this project demonstrates: not that one framework is better than the other, but that the security surface they expose reflects the security model of the OS underneath them. macOS and Linux have made different architectural bets. ES and eBPF are the monitoring interfaces to those bets.

---

## Chapters

| Chapter | ES concepts | ebpf101 analog | Status |
|---|---|---|---|
| [01-hello-exec](01-hello-exec/) | `NOTIFY_EXEC/FORK/EXIT` — process lifecycle, `parent_audit_token`, self-muting, signal-safe shutdown | ch1–8 | Done |
| [02-file-monitor](02-file-monitor/) | `NOTIFY_CREATE/WRITE/UNLINK/RENAME` — file events by process, `path_truncated` | ch9–10 | Done |
| [03-auth-exec](03-auth-exec/) | `AUTH_EXEC` — pre-exec blocking, `is_platform_binary` fast-allow, AUTH deadline | ch20 | Done |
| [04-network](04-network/) | `NOTIFY_UIPC_CONNECT` — socket connections, remote address limitation | ch11–13 | Done |
| [05-muting](05-muting/) | `es_mute_path/process`, `es_invert_muting`, mute-before-subscribe ordering | ch9/19 | Done |
| [06-lsm-analog](06-lsm-analog/) | Multi-AUTH policy engine: `AUTH_EXEC` + `AUTH_CREATE` + `AUTH_UNLINK`, separator-safe prefix match | ch21 | Done |
| [07-ids](07-ids/) | Stateful per-process counters, `NOTIFY_EXEC` token migration, SIEM JSON output | ch23 | Done |
| [08-ancestry](08-ancestry/) | Live process tree from `NOTIFY_FORK`, ancestry chain walk, browser-spawn detection | ch22 (partial) | Done |
| [09-tcc](09-tcc/) | `NOTIFY_AUTHORIZATION_JUDGEMENT` — privacy permission grants (camera, mic, FDA, contacts) | No eBPF analog | Done |
| [10-persistence](10-persistence/) | `NOTIFY_BTM_LAUNCH_ITEM_ADD/REMOVE` — LaunchAgent/Daemon registration | No eBPF analog | Done |
| [11-codesign](11-codesign/) | `AUTH_EXEC` + `cdhash`, `codesigning_flags`, `signing_id` — CDHash allowlist | No eBPF analog | Done |
| [12-dynamic-policy](12-dynamic-policy/) | Live `es_mute_path`/`es_unmute_path` driven by config file watch | No eBPF analog | Done |
| [13-auth-open](13-auth-open/) | `AUTH_OPEN` + `fflag` — pre-open file descriptor authorization | No eBPF analog | Done |
| [14-cs-invalidated](14-cs-invalidated/) | `NOTIFY_CS_INVALIDATED` — runtime code injection detection | No eBPF analog | Done |
| [15-deferred-auth](15-deferred-auth/) | `es_retain_message` — deferred, deadline-aware concurrent AUTH | No eBPF analog | Done |
| [16-unified-agent](16-unified-agent/) | All subsystems in one ES client: shared process tree, cross-subsystem policy, multi-queue dispatch | No eBPF analog | Done |

---

## How ES compares to eBPF

| eBPF (Linux) | Endpoint Security (macOS) |
|---|---|
| `bpf_prog` loaded into kernel via `bpf()` syscall | Handler block registered in user space via `es_new_client()` |
| Attached to tracepoint / kprobe / LSM hook | Subscribed to event types via `es_subscribe()` |
| Ring buffer / perf map delivery to user space | GCD dispatch queue managed by the ES framework |
| `tracepoint/syscalls/sys_enter_execve` | `ES_EVENT_TYPE_NOTIFY_EXEC` |
| `bpf_get_current_pid_tgid()` | `audit_token_to_pid(proc->audit_token)` |
| `ppid` — susceptible to PID reuse | `parent_audit_token` — generation-counter-safe |
| Observe-only programs | `NOTIFY_*` events — no response required |
| Block/allow via `seccomp` / LSM return value | `AUTH_*` events + `es_respond_auth_result()` before kernel deadline |
| Map-based filtering inside the kernel | `es_mute_process()` / `es_mute_path()` in user space, configured before subscribe |
| Code signing check is manual | `is_platform_binary`, `codesigning_flags`, `team_id`, `cdhash` built into every `es_process_t` |
| Stable PID across `execve` | Audit token changes on `execve` — requires explicit state migration |
| No AUTH deadline concept | Missed AUTH deadline → kernel defaults to ALLOW |

---

## Requirements

| Requirement | Details |
|---|---|
| macOS | 10.15 Catalina or later (Endpoint Security debut) |
| Root | ES rejects non-root at `es_new_client()` with `ES_NEW_CLIENT_RESULT_ERR_NOT_PRIVILEGED` |
| Entitlement | `com.apple.developer.endpoint-security.client` — requires active Apple Developer Program membership and a provisioning profile with the ES capability granted |
| Full Disk Access | Grant to your terminal in System Settings → Privacy & Security → Full Disk Access |

## Build

Each chapter is self-contained:

```sh
cd 01-hello-exec
make              # compile only
make sign         # compile + sign with provisioning profile (requires active Developer membership)
make sign-adhoc   # compile + ad-hoc sign (requires SIP disabled)
make run          # sign + sudo ./hello-exec
make clean
```

Toolchain: `clang` only. No Swift, no Xcode project. Link flags: `-lEndpointSecurity -lbsm -framework Foundation`.

## Signing

**With active Apple Developer membership** (provisioning profile with ES entitlement):

```sh
cd 01-hello-exec && make run
```

**With SIP disabled** (ad-hoc signing, no membership required):

```sh
cd 01-hello-exec
make sign-adhoc
sudo ./hello-exec
```

To disable SIP: boot into Recovery Mode (hold power button → Options), open Terminal via Utilities menu, run `csrutil disable`, reboot. Only do this on a machine dedicated to development — it removes a meaningful layer of macOS security hardening.

## Files

| File | Purpose |
|---|---|
| `BUGS.md` | All audit findings and fixes across seven rounds — 36 bugs total (9 in ch01, 21 in ch02–07, 6 in ch08) |
| `CLAUDE.md` | ES API invariants, architecture notes, signing identity — guidance for Claude Code |
| `AGENTS.md` | Guidance for Codex code review |
| `GEMINI.md` | Guidance for Gemini code review |
| [`docs/`](docs/) | Learning notes per chapter; full ebpf101 chapter mapping |

## Signing identity

`Apple Development: Douglas Mun (PABRCU3Y4G)` — update `SIGN_ID` in each chapter's Makefile if you fork this.
