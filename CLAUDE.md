# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project identity

`agentworld` is a **multi-sensor behavioral reconstruction kernel for macOS state**. It ingests heterogeneous OS telemetry (filesystem, process, network, window, system) and normalizes it into a unified observation stream.

It is **not** a logger, **not** a detector, **not** an agent framework. Treat it as a reconstruction kernel — its job is to make raw OS signals time-, entity-, and structure-consistent for downstream layers.

The authoritative architectural spec is [ARCHITECTURE.md](ARCHITECTURE.md). Read it before designing changes that cross layer boundaries.

## Layered architecture

- **Layer 1 — Observation Kernel** (implemented): source adapters → normalization → `Observation` stream on a bus.
- **Layer 2 — Event Reconstruction** (in progress): consumes `Observation`s, emits canonical `Event`s. Currently implements process-lifecycle compression (snapshot diff → `process_birth` / `process_death`). Lives in `aw-events`.
- **Layer 3 — World Model Graph** (first slice implemented): consumes Layer 1 observations + Layer 2 events and materializes an entity graph. Currently: `Process` and `App` nodes; `parent_of` and `frontmost_during` edges. Offline-only — `aw-graph-cli` reads a captured NDJSON trace and emits `graph.dot` + `graph.json`. Lives in `aw-graph`.

Hard boundaries — never blur:

- ingestion ≠ interpretation
- observation ≠ event
- event ≠ graph edge
- graph ≠ inference

If a change in Layer 1 starts inferring meaning, merging signals, or detecting anomalies, it belongs in Layer 2 — stop and reconsider.

## Design invariants (Layer 1 hard rules)

1. **Sensor heterogeneity.** Every source declares its behavior type — `Stream`, `Snapshot`, or `Diff`. The scheduler dispatches by type. Do not collapse them into a single polling model.
2. **Sampling invariance.** Equivalent behavior observed at different sampling rates must produce equivalent semantic representation downstream. Don't let raw event counts leak into the contract.
3. **Reduction before semantics.** Compression (Layer 2) happens *after* normalization, never inside an adapter. Adapters emit structured signals, not interpretations.
4. **Separation of concerns.** Layer 1 performs **no** aggregation, **no** deduplication, **no** anomaly detection, **no** cross-source fusion.

## Observation contract

The canonical record is `(timestamp, source, pid?, payload, tags?)`:

- `timestamp`: unified monotonic clock anchored to wall-clock at process start. Total ordering is required within a source.
- `source`: tagged enum (`FileSystem`, `Process`, `Network`, `Window`, `System`).
- `pid`: optional; never inferred — if the OS didn't provide it, leave it `None`.
- `payload`: structured (serde). **Never** raw log strings.
- `tags`: optional structured metadata; no free-form text.

Serialization must be deterministic. Adapters must tolerate event loss without corrupting the stream.

## Source behavior taxonomy

| Category    | Crate           | Behavior          | Notes                                                          |
| ----------- | --------------- | ----------------- | -------------------------------------------------------------- |
| Filesystem  | `aw-fsevents`   | Stream            | FSEvents callback-based, continuous                            |
| Process     | `aw-process`    | Snapshot          | Polled `ps`-equivalent state                                   |
| Network     | `aw-network`    | Snapshot + Stream | `nettop` snapshot + socket events; declare per-source          |
| Window / UI | `aw-window`     | Diff              | CGWindow / focus changes; requires prior-state memory          |
| System      | `aw-system`     | Snapshot          | sysctl / IORegistry / powermetrics                             |

`OpenBSM` (audit syscall stream) is a Layer 1 target but **not yet scaffolded** — it requires elevated privileges and a dedicated crate; add it next to `aw-fsevents` when implementing.

## Crate layout

- `crates/aw-core` — `Observation`, `Source`, `SourceBehavior`, `MonotonicClock`, `Bus`. The contract lives here.
- `crates/aw-scheduler` — ingestion scheduler: stream tasks, snapshot polling, diff state tracking.
- `crates/aw-fsevents`, `aw-process`, `aw-network`, `aw-window`, `aw-system` — Layer 1 adapters with real macOS bindings (FSEvents, libproc, netstat, NSWorkspace, sysctl).
- `crates/aw-eslogger` — Layer 1 adapter wrapping `sudo eslogger` for Endpoint Security events. Degrades to a single `warn!` and parks when sudo isn't available.
- `crates/aw-dns` — Layer 1 adapter tapping `mDNSResponder` via `log stream`. No root needed; hostnames are privacy-masked unless `com.apple.system.logging.Enable-Private-Data` is installed. See [EVENTS.md](EVENTS.md#dns_query) for the redaction details.
- `crates/aw-events` — Layer 2 library. `Reconstructor::process(&obs) -> Vec<Event>`. Stages live as submodules; first one is `process_lifecycle` (snapshot diff → birth/death). Each stage detects its own tick boundaries from gaps in its source's observation stream.
- `crates/aw-events-cli` — `aw-events` binary: NDJSON observations on stdin → NDJSON events on stdout. For offline reprocessing of captured Layer 1 traces.
- `crates/aw-graph` — Layer 3 library. `GraphBuilder` consumes observations + events; `build()` materializes a `Graph` of `ProcessNode`s, `AppNode`s, and edges (`parent_of`, `frontmost_during`). Includes a DOT serializer (`dot::to_dot`).
- `crates/aw-graph-cli` — `aw-graph` binary: NDJSON (mixed observations + events) on stdin → `graph.dot` + `graph.json` under `--out-dir`.
- `crates/aw-observe` — main binary. Default: emits Layer 2 events on stdout. `--raw` interleaves Layer 1 observations too.

## macOS permission requirements

Some sources need elevated access and **will not work on a default dev machine**:

- OpenBSM auditing (root + audit policy)
- Network Extensions / PF / NEFilter
- Some process introspection APIs (entitlements)

Tests must tolerate these being unavailable — gate with feature flags or runtime capability checks, never panic on missing permissions.

## Common commands

```
cargo build                          # build whole workspace
cargo test                           # run all tests
cargo test -p aw-core monotonic      # one test in one crate
cargo run --bin aw-observe           # emit Layer 2 events to stdout
cargo run --bin aw-observe -- --raw  # also include Layer 1 observations
cargo run --bin aw-observe -- --raw > obs.ndjson   # capture for offline
cargo run --bin aw-events < obs.ndjson             # reprocess captured trace
cargo run --bin aw-graph -- --out-dir ./out < obs.ndjson  # build Layer 3 graph
cargo clippy --all-targets -- -D warnings
cargo fmt
```

## Things Layer 1 does NOT do

- Does not assign meaning to events.
- Does not infer causality across sources.
- Does not deduplicate or merge.
- Does not detect anomalies.
- Does not back-pressure or rate-limit semantically — drop is preferred over distortion (see "Sampling invariance").

If you find yourself adding any of the above to an adapter or the scheduler, that work belongs in Layer 2 (not yet built).
