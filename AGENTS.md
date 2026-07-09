# AGENTS.md

This file provides guidance to Codex (Codex.ai/code) when working with code in this repository.

## Project identity

`agentworld` is a **multi-sensor behavioral reconstruction kernel for macOS state**. It ingests heterogeneous OS telemetry (filesystem, process, network, window, system) and normalizes it into a unified observation stream.

It is **not** a logger, **not** a detector, **not** an agent framework. Treat it as a reconstruction kernel — its job is to make raw OS signals time-, entity-, and structure-consistent for downstream layers.

The authoritative architectural spec is [ARCHITECTURE.md](ARCHITECTURE.md). Read it before designing changes that cross layer boundaries.

## Layered architecture

- **Layer 1 — Observation Kernel** (implemented): source adapters → normalization → `Observation` stream on a bus.
- **Layer 2 — Event Reconstruction** (implemented): consumes `Observation`s, emits canonical `Event`s. Lives in `aw-events`. Five stages implemented: `process_lifecycle` (snapshot diff → birth/death), `window_lifecycle` (frontmost transitions → `app_focus`), `network_lifecycle` (socket-set diff → connection open/close/complete), `fsevents_coalesce` (windowed compression → `file_changed`), `dns_lifecycle` (mDNSResponder stream → `dns_query`). Each stage detects its own tick boundaries from gaps in its source's observation stream.
- **Layer 3 — World Model Graph** (implemented, offline + in-process): consumes Layer 1 observations + Layer 2 events and materializes an entity graph. Nodes: `Process`, `App`, `Socket`, `File`, `Domain`. Edges: `parent_of`, `frontmost_during`, `opened_socket`, `queried_domain`. `aw-graph-cli` reads a captured NDJSON trace and emits `graph.dot` + `graph.json`. Lives in `aw-graph`. In-memory only; persistence is Layer 4.
- **Layer 4 — Persistent World Model** (implemented): SQLite-backed durable mirror of the graph. Tables `nodes` and `edges` use upsert-with-count semantics — repeated observations of the same entity increment a count rather than insert duplicate rows, so growth is bounded by distinct entities, not by sample rate. A third `events` table keeps the durable Layer 2 event history (grows with volume; bounded via `prune_before`). Opened in WAL mode so the `aw-mvp` daemon can write while `aw-query` reads. Wall-clock unix-ns timestamps. Lives in `aw-store`. Read by the apps layer; not consulted by the kernel.

Hard boundaries — never blur:

- ingestion ≠ interpretation
- observation ≠ event
- event ≠ graph edge
- graph ≠ inference
- kernel (Layers 1–3) ≠ apps layer

If a change in Layer 1 starts inferring meaning, merging signals, or detecting anomalies, it belongs in Layer 2 — stop and reconsider. If a change in Layers 1–3 starts narrating, scoring, or judging, it belongs in the apps layer — same rule.

## Apps layer (built on top of the kernel)

The apps layer reads Layers 2/3/4 and is allowed to do everything the kernel must not: infer, narrate, score, detect, summarize. Apps must never feed back into Layer 1–3 outputs; the kernel remains the source of truth.

- `aw-llm` — local model client. Currently wraps Ollama over HTTP; behind an `LlmClient` trait so apps can be tested without a live model.
- `aw-agents` — readers that consume Layer 2 events and/or Layer 3/4 graph state and call an `LlmClient`. Implemented: `TimelineNarrator` (focus segments → narrative), `ProcessAnomalyDetector` (lineage/uid/name heuristics), `NetworkReviewer` (notable connections), `DnsReviewer` (notable DNS names/query patterns).
- `aw-mvp` — end-to-end runner: spins all Layer 1 adapters, drives the Layer 2 reconstructor, materializes the Layer 3 graph, persists to Layer 4, and invokes agents. One-shot or `--daemon` mode. The daemon is service-grade: single-instance `flock` on the store, SIGTERM-clean shutdown (launchd-compatible), heartbeat in store meta (shown by `aw-query summary`), hourly self-pruning via `--retention-days` (default 30), `--no-narrate` collector mode needing no Ollama, and `--print-launchd-plist` for installation as a LaunchAgent.

Agents take `Arc<dyn LlmClient>`. Tests against the agents layer must use a mock client; never require Ollama at test time.

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

Kernel (Layers 1–3) and the persistence layer (Layer 4):

- `crates/aw-core` — `Observation`, `Source`, `SourceBehavior`, `MonotonicClock`, `Bus`. The contract lives here.
- `crates/aw-scheduler` — ingestion scheduler: stream tasks, snapshot polling, diff state tracking.
- `crates/aw-fsevents`, `aw-process`, `aw-network`, `aw-window`, `aw-system` — Layer 1 adapters with real macOS bindings (FSEvents, libproc, netstat, NSWorkspace, sysctl).
- `crates/aw-eslogger` — Layer 1 adapter wrapping `sudo eslogger` for Endpoint Security events. Degrades to a single `warn!` and parks when sudo isn't available.
- `crates/aw-dns` — Layer 1 adapter tapping `mDNSResponder` via `log stream`. No root needed; hostnames are privacy-masked unless `com.apple.system.logging.Enable-Private-Data` is installed. See [EVENTS.md](EVENTS.md#dns_query) for the redaction details.
- `crates/aw-events` — Layer 2 library. `Reconstructor::process(&obs) -> Vec<Event>`. Stages live as submodules: `process_lifecycle`, `window_lifecycle`, `network_lifecycle`, `fsevents_coalesce`, `dns_lifecycle`. Each stage detects its own tick boundaries from gaps in its source's observation stream.
- `crates/aw-graph` — Layer 3 library. `GraphBuilder` consumes observations + events; `build()` materializes a `Graph` of `ProcessNode`s, `AppNode`s, `SocketNode`s, `FileNode`s, `DomainNode`s, and edges (`parent_of`, `frontmost_during`, `opened_socket`, `queried_domain`). Includes a DOT serializer (`dot::to_dot`) and JSON output.
- `crates/aw-store` — Layer 4 library. SQLite-backed persistent mirror of the graph; `nodes` and `edges` tables with upsert-with-count semantics so growth is bounded by distinct entities. Wall-clock unix-ns timestamps for cross-session continuity.

Apps layer (everything below this line may infer, narrate, or judge):

- `crates/aw-llm` — local model client. Wraps Ollama over HTTP (`reqwest`); single `generate()` method on the `LlmClient` trait. Trait exists so apps can be tested with a mock client.
- `crates/aw-agents` — readers over Layer 2/3/4. `TimelineNarrator` builds a `CaptureSummary` (focus segments, top processes, endpoints, directories, DNS clients) and narrates it; `ProcessAnomalyDetector`, `NetworkReviewer`, and `DnsReviewer` flag notable items via the same `LlmClient`.

Binaries:

- `crates/aw-observe` — Layer 1 + 2 runner. Default: emits Layer 2 events on stdout. `--raw` interleaves Layer 1 observations too. Use this to capture NDJSON traces for offline replay.
- `crates/aw-events-cli` — `aw-events` binary: NDJSON observations on stdin → NDJSON events on stdout. For offline reprocessing of captured Layer 1 traces.
- `crates/aw-graph-cli` — `aw-graph` binary: NDJSON (mixed observations + events) on stdin → `graph.dot` + `graph.json` under `--out-dir`.
- `crates/aw-agents-cli` — runs one agent (`timeline`, `process-anomaly`, `network-review`, `dns-review`) against an events NDJSON file or a persisted graph/store path; outputs a JSON report (`--pretty` for text).
- `crates/aw-query` — store inspection CLI: `summary`, `processes`, `endpoints`, `domains`, `focus`, `events` (windowed history with `--kinds` filter) read a `world.db`; `prune --older-than-days N` is the retention knob (`Store::prune_before`, covers nodes, edges, and events).
- `crates/aw-mvp` — end-to-end runner: capture → reconstruct → graph → persist → narrate. Default 30s one-shot capture; `--daemon` runs forever emitting narration every `--tick` over `--window` (or silently with `--no-narrate`). Daemon extras: instance lock, SIGTERM handling, store heartbeat, `--retention-days` self-pruning, `--print-launchd-plist`. The natural seed for product surfaces built on top of the kernel.

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
cargo run --bin aw-observe -- --raw --duration 60 --out obs.ndjson  # timed capture to a file
cargo run --bin aw-events < obs.ndjson             # reprocess captured trace
cargo run --bin aw-events -- --kinds dns_query,connection_opened < obs.ndjson  # filtered
cargo run --bin aw-graph -- --out-dir ./out < obs.ndjson  # build Layer 3 graph
cargo run --bin aw-query -- summary --pretty        # inspect the persistent store
cargo run --bin aw-query -- domains --limit 20 --pretty  # top DNS names in world.db
cargo run --bin aw-mvp                              # one-shot 30s capture → narrate
cargo run --bin aw-mvp -- --daemon                  # run forever, narrate every --tick
cargo run --bin aw-mvp -- --daemon --no-narrate     # pure collector, no Ollama needed
cargo run --bin aw-mvp -- --print-launchd-plist     # emit LaunchAgent plist for install
cargo run --bin aw-agents-cli -- timeline --events events.ndjson --pretty
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
