# Event Schema (Layer 2 Reference)

Canonical reference for every event kind emitted by `aw-events`. Each event has the shape:

```json
{
  "timestamp": { "mono_ns": <u64>, "wall_anchor_ns": <u128> },
  "kind": "<snake_case kind>",
  "pid": <u32 or omitted>,
  "payload": { ... }
}
```

`timestamp.mono_ns` is the offset (in nanoseconds) from `wall_anchor_ns` (a unix-epoch-nanoseconds anchor captured at process start). Subtracting two `mono_ns` values within one capture yields a duration that is immune to wall-clock adjustments. To recover absolute time, add: `wall_anchor_ns + mono_ns`.

`pid` is the *primary acting entity* of the event when applicable. It is omitted for events that don't have one (e.g. `file_changed`).

`payload` is event-kind-specific structured JSON. Field semantics are documented below.

---

## process_birth

A new process was first observed on a snapshot tick. Identity is `(pid, start_unix_secs)` — PID reuse on macOS is handled by including the kernel-provided start time.

| field | type | notes |
|---|---|---|
| `pid` (top-level) | `u32` | process id |
| `comm` | `string?` | short kernel name (16 bytes max) |
| `name` | `string?` | longer process name |
| `exec_path` | `string?` | absolute path of the executable |
| `ppid` | `u32?` | parent pid |
| `uid` | `u32?` | effective user id |
| `pgid` | `u32?` | process group id |
| `start_unix_secs` | `u64` | kernel-reported start time, used as identity component |
| `status` | `u32?` | bsdinfo status bits |
| `nfiles` | `u32?` | open file descriptor count |

**Emission timing**: at the *next* snapshot tick boundary after the process appears (so up to ~2 seconds after the actual exec on the default 1Hz cadence). The first complete snapshot tick on capture start is suppressed — pids that were already alive when capture began are *not* emitted as births.

## process_death

A previously-observed process was absent from the most recent snapshot tick. The event timestamp is the tick boundary, not the (unobservable) true death moment.

| field | type | notes |
|---|---|---|
| `pid` (top-level) | `u32` | process id |
| `comm`, `name`, `exec_path`, `ppid`, `uid`, `start_unix_secs`, `status` | (same as `process_birth`) | snapshot from last-observed tick |
| `last_seen` | `Timestamp` | mono_ns at which we last observed this pid |

---

## app_focus

The macOS frontmost app changed (or was first observed at capture start). One event per transition.

| field | type | notes |
|---|---|---|
| `pid` (top-level) | `u32?` | the focused app's process id |
| `from_bundle_id` | `string?` | previous app's bundle id; `null` on first observed transition |
| `from_name` | `string?` | previous app's localized name |
| `to_bundle_id` | `string?` | new app's bundle id |
| `to_name` | `string?` | new app's localized name |
| `to_exec_path` | `string?` | new app's main executable path |

**Sampling note**: backed by a `Diff` source polled at 1Hz. Sub-second app switches (e.g. command-tab toggles) can be missed.

---

## connection_opened

A 5-tuple `(proto, local_addr, foreign_addr)` was first observed in a network snapshot tick. State changes (e.g. SYN_SENT → ESTABLISHED) on the same tuple do **not** generate spurious open events.

| field | type | notes |
|---|---|---|
| `pid` (top-level) | `u32?` | owning process pid (from netstat) |
| `proto` | `string` | `tcp4`, `tcp6`, `udp4`, `udp46`, `udp6` |
| `local_addr` | `string` | `<addr>.<port>`; addr may be `*` for wildcard |
| `foreign_addr` | `string` | `<addr>.<port>`; `*.*` for listening sockets |
| `state` | `string?` | TCP state (`ESTABLISHED`, `LISTEN`, …); `null` for UDP |
| `process_name` | `string?` | name as reported by netstat |
| `rxbytes` | `u64?` | bytes received at first observation |
| `txbytes` | `u64?` | bytes transmitted at first observation |
| `process` *(enriched)* | object? | see [Process enrichment](#process-enrichment) below |

## connection_closed

The 5-tuple was no longer present in the most recent snapshot tick.

Same fields as `connection_opened`, plus:

| field | type | notes |
|---|---|---|
| `last_seen` | `Timestamp` | last tick we observed this tuple |

**Sampling caveat**: short-lived connections (sub-second `curl` requests) may never appear in any snapshot tick and thus produce no opened/closed events.

## connection_completed

Synthetic per-connection summary. Emitted **alongside** `connection_closed` at the tick boundary that detects the disappearance — one summary event per real connection. Use this when you want a single record per network conversation; use `connection_opened`/`connection_closed` when you need the raw lifecycle pair.

| field | type | notes |
|---|---|---|
| `pid` (top-level) | `u32?` | owning process pid (carried from the last observation) |
| `proto`, `local_addr`, `foreign_addr` | `string` | same identity tuple as opened/closed |
| `final_state` | `string?` | last observed state (e.g. `ESTABLISHED`, `TIME_WAIT`); `null` for UDP |
| `process_name` | `string?` | last-observed netstat process name |
| `bytes_rx` | `u64?` | cumulative bytes received (final value reported by netstat) |
| `bytes_tx` | `u64?` | cumulative bytes transmitted |
| `opened_at` | `Timestamp` | mono_ns of the first observation of this tuple |
| `closed_at` | `Timestamp` | mono_ns of the last observation |
| `duration_ns` | `u64` | `closed_at.mono_ns - opened_at.mono_ns`; bounded above by the poll interval |
| `process` *(enriched)* | object? | see [Process enrichment](#process-enrichment) below |

**Accuracy note**: `opened_at` reflects when the *adapter* first saw the tuple, not when the kernel created the socket. For long-lived connections this is close; for short-lived ones it may be hundreds of milliseconds late or missed entirely.

---

## file_changed

One or more FSEvents on the same path within a 500ms tumbling window, compressed into a single event. `pid` is always omitted — FSEvents does not report which process triggered a change.

| field | type | notes |
|---|---|---|
| `path` | `string` | absolute filesystem path |
| `flags` | `string[]` | union of all observed flag names within the window (e.g. `["created", "modified", "xattr_mod", "is_file"]`) |
| `event_ids` | `u64[]` | underlying FSEvents stream-event ids that contributed |
| `count` | `u64` | length of `event_ids` |
| `first_seen` | `Timestamp` | mono_ns of the first contributing observation |
| `last_seen` | `Timestamp` | mono_ns of the last contributing observation |

The event `timestamp` is the **flush time** of the window, not the first or last observation timestamp. Use `first_seen`/`last_seen` for activity-time correlation.

---

## dns_query

A `DNSServiceQueryRecord START` line from macOS's mDNSResponder log subsystem.

| field | type | notes |
|---|---|---|
| `pid` (top-level) | `u32` | querying process pid |
| `qname` | `string?` | queried hostname *or* `<mask.hash: '...'>` if masked |
| `qtype` | `string?` | `A`, `AAAA`, `PTR`, `SRV`, … |
| `name_hash` | `string?` | hex hash, stable across runs for the same name |
| `masked` | `bool` | `true` iff Apple's privacy redaction replaced the qname |
| `interface_index` | `i64?` | network interface index (0 = any) |
| `client_process_name` | `string?` | process name from mDNSResponder's view |
| `process` *(enriched)* | object? | see [Process enrichment](#process-enrichment) below |

**Privacy note**: by default `qname` is masked. To see real hostnames, install Apple's `com.apple.system.logging.Enable-Private-Data` configuration profile. The `name_hash` is always present and is suitable for joining repeated queries to the same name without revealing the name itself.

---

## Process enrichment

`connection_opened`, `connection_closed`, and `dns_query` events are augmented at emission time with a `process` sub-object computed from the shared `ProcessTable`. The table is populated from observed `process_birth`/`process_death` events; processes that pre-existed capture start may not be in the table, in which case the enrichment is silently omitted.

```json
"process": {
  "pid": <u32>,
  "start_unix_secs": <u64>,
  "comm": "<string?>",
  "name": "<string?>",
  "exec_path": "<string?>",
  "ppid": <u32?>,
  "uid": <u32?>,
  "alive": <bool>,
  "ancestors": [
    { "pid": <u32>, "comm": "<string?>", "name": "<string?>", "exec_path": "<string?>" },
    ...
  ]
}
```

`ancestors` is the chain walked from `ppid` upward, stopping at PID 1 or the first ancestor not in the table. Maximum chain length is 32 entries; cycles are detected and broken.

---

## Stability

Event kinds and their payload field names are part of the public contract. New optional fields may be added to a payload without notice. Renaming or removing a field would be a breaking change and would require a version bump.
