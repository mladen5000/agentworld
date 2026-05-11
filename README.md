# agentworld

Multi-sensor behavioral reconstruction kernel for macOS state.

- **What it does:** ingests heterogeneous macOS telemetry (filesystem, process, network, window, system) and emits a unified, normalized observation stream.
- **What it isn't:** a logger, a detector, or an agent framework.

## Where to start

- [ARCHITECTURE.md](ARCHITECTURE.md) — full architectural spec (Layer 1 / 2 / 3).
- [CLAUDE.md](CLAUDE.md) — working notes, invariants, and crate layout.

## Quick start

```
cargo run --bin aw-observe
```

Emits NDJSON observations to stdout. Ctrl-C to stop.
