# Learning Notes — macos-endptsec101

Chapter-by-chapter notes for the macOS [Endpoint Security](https://developer.apple.com/documentation/endpointsecurity) learning project. Each document pairs with a source chapter and covers the ES concepts introduced, key API invariants discovered during implementation, and how the chapter maps to its [ebpf101](https://github.com/douglasmun/ebpf101) counterpart.

---

## Completed chapters

| Document | Chapter | Key ES concepts introduced | Closest ebpf101 analog and how the approach differs |
|---|---|---|---|
| [01-hello-exec.md](01-hello-exec.md) | `01-hello-exec` | `NOTIFY_EXEC`, `NOTIFY_FORK`, `NOTIFY_EXIT`; full path + argv in callback; `parent_audit_token` vs PID-reuse-unsafe `ppid`; self-muting to prevent feedback loop; signal-safe shutdown via `dispatch_async_f` | ch1–8 (hello-world through argv-libbpf): ES delivers path, argv, and PID-safe parent identity in a single callback — seven chapters of eBPF transport mechanics collapse to one |
| [02-file-monitor.md](02-file-monitor.md) | `02-file-monitor` | `NOTIFY_CREATE`, `NOTIFY_WRITE`, `NOTIFY_UNLINK`, `NOTIFY_RENAME`; `es_file_t.path_truncated` guard; attributing file events to the originating process by audit token | ch9–10 (openat, openat-ret): eBPF requires two separate probes and a map to correlate enter/return; ES delivers the full file path and process identity together in one event |
| [03-auth-exec.md](03-auth-exec.md) | `03-auth-exec` | `AUTH_EXEC` pre-execution interception; `es_respond_auth_result()` — every code path must respond; `is_platform_binary` fast-allow path; AUTH kernel deadline — missed deadline defaults to ALLOW | ch20 (LSM): eBPF LSM hooks intercept inside the kernel with no user-space round trip; ES AUTH events cross to user space with a deadline, trading latency for expressiveness |
| [04-network.md](04-network.md) | `04-network` | `NOTIFY_UIPC_CONNECT` for outbound socket connections; `domain`, `type`, `protocol` fields; limitation — remote `sockaddr` not delivered for `AF_INET`/`AF_INET6`, only Unix socket `file` path | ch11–13 (connect, tcpstates, tcplife): eBPF kprobes capture full `sockaddr` including remote IP/port; ES `NOTIFY_UIPC_CONNECT` omits remote address entirely for TCP/UDP sockets |
| [05-muting.md](05-muting.md) | `05-muting` | `es_mute_path()` with symlink-resolved paths; `es_mute_process()` by audit token; `es_invert_muting()` to allowlist instead of denylist; muting must be fully configured before `es_subscribe()` — no race-free way to add mutes after events begin arriving | ch9/19 (openat filter, tailcall): eBPF filtering runs inside the kernel at attach time; ES muting is a client-side subscription filter configured before the first event is delivered |
| [06-lsm-analog.md](06-lsm-analog.md) | `06-lsm-analog` | Multi-`AUTH` policy engine combining `AUTH_EXEC`, `AUTH_CREATE`, `AUTH_UNLINK`; `path_is_protected()` with separator-safe prefix matching (`/etcfoo` must not match `/etc`); codesign-aware allow rules | ch21 (XDP firewall): XDP enforces packet-level policy at the NIC; this chapter enforces file and process policy at syscall boundaries — the ES equivalent of a composable LSM module |
| [07-ids.md](07-ids.md) | `07-ids` | Stateful per-process event counters keyed by `audit_token_t`; `NOTIFY_EXEC` state migration from pre-exec to post-exec token to avoid counter reset and entry leak; SIEM-ready JSON output with `json_escape()`; `gmtime_r()` for thread-safe timestamps | ch23 (IDS): both implement rule-based detection in user space over a kernel event stream; the key ES-specific challenge is token migration on `execve` — eBPF programs see a stable PID, ES sees the audit token change under an exec chain |

## Planned chapters (notes not yet written)

| Chapter | Key ES concepts to be introduced | Closest ebpf101 analog and structural difference |
|---|---|---|
| `08-ancestry` | Incremental live process tree built from `NOTIFY_FORK` events; parent→child link captured on FORK (not EXEC); ancestry chain walk up to fixed depth; `audit_token_t`-keyed hash table; browser-spawned-tool detection rule | ch22 (process iterator): ebpf101 ch22 pulls a snapshot of running processes; this chapter builds an incrementally-maintained live tree — a fundamentally different model for the same question |
| `09-tcc` | `NOTIFY_TCC_MODIFY` — observe when processes are granted or revoked privacy permissions (camera, microphone, Full Disk Access, contacts, location); `tcc_modification_type`; `es_process_t` of the process receiving the grant | No eBPF analog: Linux has no unified privacy permission layer; camera and microphone access is not mediated by the kernel at all |
| `10-persistence` | `NOTIFY_BTM_LAUNCH_ITEM_ADD` and `NOTIFY_BTM_LAUNCH_ITEM_REMOVE` — detect installation and removal of LaunchAgent and LaunchDaemon persistence items at the BTM registration chokepoint | No eBPF analog: Linux persistence mechanisms (cron, systemd units, rc.d scripts) are scattered across the filesystem; no single kernel-visible registration event exists |
| `11-codesign` | `AUTH_EXEC` with CDHash-based allowlist; `cdhash` as a content-addressed binary identity; `codesigning_flags` to distinguish platform binaries, ad-hoc signed, and developer-signed executables; `signing_id` and `team_id` for organizational identity | No eBPF analog: Linux IMA/EVM is optional and not a first-class security boundary; Apple Platform Security makes codesign identity kernel-enforced and always present on `AUTH_EXEC` |
| `12-dynamic-policy` | Live policy mutation via `es_mute_path()` and `es_unmute_path()` without restarting the client; config file watch with `kqueue`/`FSEvents` to drive policy reloads at runtime | No eBPF analog: eBPF maps can be updated at runtime, but adding a new event type subscription requires reloading the program; ES allows subscription and mute changes without restart |
| `13-auth-open` | `AUTH_OPEN` — intercept file opens before the file descriptor is returned to the caller; `fflag` to distinguish read vs. write intent; combining process identity and codesign context to make per-open policy decisions | No eBPF analog: `seccomp` can filter `openat` syscalls but carries no process identity or codesign context; LSM hooks are closer but provide far less metadata |
| `14-cs-invalidated` | `NOTIFY_CS_INVALIDATED` — detect when a running process's code signature is invalidated at runtime, which indicates a code injection (e.g., via `ptrace` or unsigned library load) into a previously-valid process image | No eBPF analog: Linux has no equivalent hook for post-exec code signature invalidation; `ptrace`-based writes are not observable through a single mediated event |
| `15-deferred-auth` | `es_retain_message()` to extend message lifetime beyond the handler callback; deadline-aware deferred AUTH processing on a concurrent dispatch queue; responding before the kernel deadline under load without blocking the ES serial queue | No eBPF analog: eBPF LSM programs make synchronous verdicts inside the kernel and cannot defer to user space for expensive policy evaluation; the deadline model is unique to ES |
| `16-unified-agent` | All subsystems composed into a single `es_new_client()` instance: shared `audit_token_t`-keyed process tree, cross-subsystem policy (IDS rules informed by ancestry, codesign-aware file AUTH), and a multi-queue dispatch architecture for concurrent AUTH handling alongside NOTIFY processing | No eBPF analog: the composability lesson is ES-specific — a single ES client can subscribe to all event types simultaneously, sharing state across what would be separate eBPF programs on Linux |

---

## Cross-chapter reference

| Document | Contents |
|---|---|
| [ebpf101-mapping.md](ebpf101-mapping.md) | Complete mapping of all 23 ebpf101 chapters to ES equivalents; divergence analysis |

---

See the project [README](../README.md) for build instructions, runtime requirements, and signing setup.
