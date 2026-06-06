# 12-dynamic-policy

**ES analog of:** nothing directly in ebpf101 — operational capability unique to ES

eBPF maps can be updated at runtime (key/value inserts), but changing which
event types are subscribed requires reloading the entire program, creating a
gap window where events are missed. ES separates subscription (what events to
receive) from muting (which processes/paths to suppress) and allows muting
changes on a live client without re-subscribing. This chapter has no ebpf101
counterpart.

## The wall ch11 hits

ch11's CDHash allowlist is compiled into the binary. To add a new trusted
binary you must recompile and restart the monitor. During restart there is a
window where AUTH_EXEC events are not answered — the kernel defaults to ALLOW,
and any exec during that window is ungated. For a security monitor, that window
is unacceptable. Ch12 teaches how to update policy without any gap.

## New concepts introduced

- **`es_mute_path` / `es_unmute_path`**: add or remove path-based mute entries
  on a live client. Called from a dispatch queue (not from the ES handler
  itself) in response to config changes.
- **Config file watch**: subscribe to `NOTIFY_WRITE` on a config file path.
  When the config changes, reload it and call `es_mute_path`/`es_unmute_path`
  to update the suppression list — no restart needed.
- **Muting vs subscription changes**: muting can be changed live. Subscription
  changes (`es_subscribe` / `es_unsubscribe`) can also be called on a live
  client, but require care: `es_unsubscribe` flushes queued events of the
  removed type, so there is still a brief ordering effect.
- **Thread safety**: `es_mute_path` is called from a different dispatch context
  than the ES handler. ES guarantees its internal state is thread-safe across
  these calls, but the config data structure shared between the config-reload
  path and the handler must be protected — use atomic swap of a pointer to an
  immutable config struct (read-copy-update pattern) or a `dispatch_barrier`.
- **`es_mute_path_events`**: mute a path only for specific event types (e.g.,
  suppress NOTIFY_WRITE for `/var/log` but not NOTIFY_UNLINK). Finer than the
  all-events mute used in ch05.

## Structure

```
main()
 ├── es_new_client() → AUTH_EXEC handler
 ├── load_config() → initial mute list
 ├── es_subscribe(AUTH_EXEC, NOTIFY_WRITE)  ← watch config file too
 └── dispatch_main()

handle_event()
 ├── NOTIFY_WRITE on config path → dispatch_async to reload_config()
 └── AUTH_EXEC → evaluate live policy

reload_config()  ← runs on main queue, not ES queue
 ├── parse new config file
 ├── es_unmute_path() for removed entries
 └── es_mute_path() for new entries
```

## Why the reload runs on the main queue

`es_mute_path()` must not be called from within the ES handler callback —
doing so risks deadlock (ES holds internal locks during handler dispatch).
Post the reload to a separate queue (main queue or a private serial queue)
via `dispatch_async_f`.

## Detection rules to implement

This chapter is primarily operational rather than detection-focused. The
"rule" is demonstrating that policy updates apply immediately:

1. **Live mute add**: add a new path prefix to the mute list by writing to the
   config file; verify events from that path stop arriving within one event
   cycle.
2. **Live mute remove**: remove a path from the mute list; verify events from
   that path resume.
3. **Zero-gap update**: AUTH_EXEC events from paths affected by the update are
   answered correctly both before and after the config change, with no ALLOW
   defaults during the transition.

## ES events

- `AUTH_EXEC` (primary policy enforcement)
- `NOTIFY_WRITE` (config file watch trigger)

## Key ES API calls

- `es_mute_path(client, path, ES_MUTE_PATH_TYPE_PREFIX)` — suppress by prefix
- `es_unmute_path(client, path, ES_MUTE_PATH_TYPE_PREFIX)` — restore
- `es_mute_path_events(client, path, type, event_types, count)` — per-event-type mute
- `es_unsubscribe(client, events, count)` — remove event type subscriptions live

## Relation to other chapters

- Generalizes ch05's static muting into a live, reloadable system.
- The config file watch reuses the NOTIFY_WRITE subscription from ch02.
- The AUTH_EXEC handler inherits from ch06 and ch11.

> Not yet implemented.
