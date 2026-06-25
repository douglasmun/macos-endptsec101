Most engineers know eBPF changed Linux observability. Fewer know macOS has had something more powerful — and more dangerous to get wrong — built into the kernel for years.

Last weekend I published ebpf101 — a chapter-by-chapter walk through Linux eBPF, from kernel probes to a user-space IDS.

This weekend I asked: what does the same curriculum look like on macOS?

The answer is macos-endptsec101 — 16 chapters on the macOS Endpoint Security framework, structured as a direct analog to the eBPF series.

**Why Endpoint Security matters**

Every process launch, file open, exec, fork, socket connect, and codesign change on macOS passes through a single kernel-mediated framework before it happens. ES gives you a user-space client that sits on that chokepoint. Get it wrong and you crash every process on the machine. Get it right and you can build EDR-grade visibility and enforcement entirely in C, with no kernel extension.

**What the project covers**

- AUTH vs NOTIFY: how to intercept and deny a syscall before the kernel commits it — with a deadline
- audit_token_t: why PIDs are race-unsafe and how process identity actually works across execve()
- es_string_token_t: the one mistake every newcomer makes (it is not null-terminated)
- Deferred AUTH: retain a message across threads, run policy asynchronously, respond before the kernel timeout
- Live process tree: incrementally built from NOTIFY_FORK, migrated across exec, used for ancestry-based rules
- TCC observation: watching privacy permission grants (camera, microphone, location) as they happen
- Code identity: CDHash-keyed allowlists, CS_DEBUGGED/CS_HARD flag policy, runtime signature invalidation

**The structural finding**

Chapters 1–8 show that ES and eBPF are alternate routes to the same place — process visibility and file monitoring.

Chapters 9–16 show what ES can do that eBPF structurally cannot. macOS has kernel-enforced chokepoints — TCC privacy grants, LaunchAgent registration, mandatory codesign, runtime code injection detection — that simply have no Linux hook.

The capstone (ch16) composes all subsystems into a single es_new_client() instance: shared process tree, IDS state, codesign-aware file AUTH, and deferred concurrent policy evaluation.

**Open source, MIT licensed.**
github.com/douglasmun/macos-endptsec101

If you work in macOS security or are curious how platform-level endpoint protection is actually built — the code is there, the docs explain every invariant, and the ebpf101 comparison tables show exactly where the two ecosystems diverge.
