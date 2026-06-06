# Chapter 4 — Network Monitor

**Code:** `../04-network/network.c`
**Build:** `cd 04-network && make`
**Run:** `sudo ./network`

## ebpf101 analog

Covers ebpf101 ch11 (`connect`), ch12 (`tcpstates`), and ch13 (`tcplife`). Those
three chapters exist because eBPF forces a series of escalating workarounds to get
reliable process identity alongside a network connection:

| ebpf101 wall | Why it doesn't exist here |
|---|---|
| ch11: only entry; fd/error at exit | ES fires after the `connect(2)` call with both |
| ch11: stash sockaddr across entry→exit boundary | One `es_event_uipc_connect_t` delivers domain/type/protocol |
| ch12: `kprobe/tcp_set_state` — kernel struct layout dependency | ES abstracts transport state; no kernel struct access |
| ch12: softirq context — `bpf_get_current_comm()` returns `swapper` | Every ES event carries the responsible `audit_token` regardless of execution context |
| ch13: stash identity at `SYN_SENT` while still in process context | Not needed — `audit_token_to_pid()` is always correct |

The softirq problem is the core issue: when a TCP state transition fires in
interrupt context, there is no current process. eBPF must stash process identity
at the moment of `connect(2)` (ch13's insight) and retrieve it later. ES has no
equivalent problem — process identity is attached to every event by the kernel.

## What it does

Subscribes to `NOTIFY_UIPC_CONNECT` and prints one line per connection attempt,
classified by address family:

```
network: monitoring connect(2) (AF_UNIX/INET/INET6) — Ctrl-C to stop
[CONNECT] pid=1234   ppid=567  AF_INET  type=1 proto=6
[CONNECT] pid=5678   ppid=567  AF_INET6 type=1 proto=6
[CONNECT] pid=9012   ppid=567  AF_UNIX  path=/var/run/mDNSResponder
```

## New building blocks

### NOTIFY_UIPC_CONNECT — naming and scope

The event name is `UIPC` (Unix Interprocess Communication) because ES's internal
event taxonomy predates clean separation of Unix and INET sockets. Despite the
name, the `domain` field in `es_event_uipc_connect_t` distinguishes:

- `AF_UNIX` — named Unix domain socket (path in `ev->file`)
- `AF_INET` — IPv4 TCP/UDP connection
- `AF_INET6` — IPv6 TCP/UDP connection
- Other domains (rare) — distinguished by `ev->domain`

The event fires on the `connect(2)` syscall — the moment a process initiates a
connection, before the three-way handshake completes.

### es_event_uipc_connect_t fields

```c
int      domain;    // AF_UNIX, AF_INET, AF_INET6, ...
int      type;      // SOCK_STREAM, SOCK_DGRAM, SOCK_RAW
int      protocol;  // IPPROTO_TCP, IPPROTO_UDP, ...
es_file_t *file;    // Unix socket file (AF_UNIX only; NULL or invalid for INET)
```

**Critical limitation**: ES does **not** deliver the remote `sockaddr` for INET
or INET6 connections. The destination IP and port are not available in the event.
Only `domain`, `type`, and `protocol` distinguish a TCP connection from a UDP one.
For port-based rules (ch07's `rule_suspicious_port` scaffolding), a separate data
source is required — see below.

### process identity without the softirq problem

`msg->process->audit_token` is always the process that called `connect(2)`.
`audit_token_to_pid()` converts it to a PID. This is reliable because ES hooks
the syscall in process context, not in interrupt context. No stashing, no
generation-counter workaround.

`msg->process->parent_audit_token` gives the parent, `msg->process->executable`
gives the binary path, `msg->process->is_platform_binary` identifies system
daemons. The full code identity context of ch06 is available on every event.

### What ES cannot observe here

ES `NOTIFY_UIPC_CONNECT` covers the `connect(2)` syscall but not:

- **Remote address and port** — not delivered in `es_event_uipc_connect_t`
- **TCP state transitions** — no equivalent of ebpf101 ch12's `tcp_set_state`
- **Bytes transferred** — no per-flow counters
- **RTT, retransmits** — no transport-layer metrics

For full network visibility, combine ES with:
- **Network Extension framework** (`NEFilterDataProvider`) — intercepts flows
  with full 5-tuple, pre- and post-connection filtering
- **`dtrace` socket probes** — `syscall::connect:entry` with `arg1` as the
  sockaddr pointer delivers the remote address
- **Packet filter** (`pfctl`, `libpcap`) — full packet inspection

This is where the eBPF/ES analogy breaks down: ebpf101 ch12–13 have no clean
ES equivalent for TCP lifecycle monitoring. ES trades depth for reliability
(process identity always correct) and safety (no kernel struct layout dependency).

## What a real Mac shows

On an active system, `NOTIFY_UIPC_CONNECT` fires constantly:
- **mDNS**: `mDNSResponder` connecting to `AF_UNIX /var/run/mDNSResponder`
- **TLS**: browser processes opening `AF_INET` connections on port 443 (type
  visible; port invisible without a secondary source)
- **XPC**: many system daemons connecting to `AF_UNIX` sockets for IPC
- **Spotlight**: `mdworker` connecting to system services

The volume quickly motivates ch05 (muting).

## Bugs found and fixed

Audit rounds found bugs in the `AF_UNIX` branch and in the `ppid` vs
`parent_audit_token` choice. Full list in [`../BUGS.md`](../BUGS.md).

## The wall this hits (→ [05-muting](05-muting.md))

Subscribing to `NOTIFY_UIPC_CONNECT` system-wide produces enormous volume — every
Unix socket connect, every loopback connection, every XPC call fires an event.
Without surgical suppression the handler is overwhelmed. The next chapter introduces
the full muting API.
