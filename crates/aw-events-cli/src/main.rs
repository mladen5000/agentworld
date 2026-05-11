//! `aw-events` — reads NDJSON observations from stdin and writes canonical
//! Layer 2 events as NDJSON to stdout.
//!
//! Usage:
//!
//!     aw-observe | aw-events
//!
//! Or against a captured file:
//!
//!     aw-events < observations.ndjson > events.ndjson
//!
//! This binary is a thin pump: it just calls `Reconstructor::process(obs)`
//! per line and writes any emitted events. Per-stage tick boundary detection
//! lives inside the stages themselves (see `aw_events::process_lifecycle`),
//! so the CLI does not need timing knowledge.

use std::io::{BufRead, BufReader, Write};

use anyhow::Result;
use aw_core::Observation;
use aw_events::Reconstructor;

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .init();

    let stdin = std::io::stdin();
    let mut reader = BufReader::new(stdin.lock());
    let stdout = std::io::stdout();
    let mut out = stdout.lock();

    let mut recon = Reconstructor::new();
    let mut line = String::new();

    loop {
        line.clear();
        let n = reader.read_line(&mut line)?;
        if n == 0 { break; } // EOF
        let trimmed = line.trim();
        if trimmed.is_empty() { continue; }

        let obs: Observation = match serde_json::from_str(trimmed) {
            Ok(o) => o,
            Err(e) => {
                tracing::warn!("skipping non-Observation line: {e}");
                continue;
            }
        };

        for ev in recon.process(&obs) {
            writeln!(out, "{}", serde_json::to_string(&ev)?)?;
        }
    }

    // No EOF flush: an in-flight (partial) tick would otherwise be diffed
    // against the prior tick, producing false deaths for pids we simply hadn't
    // ingested yet. The last complete tick was already emitted by the
    // self-detection logic when the next tick began; if the input ended
    // mid-tick, we drop those last events. That's the safer tradeoff.
    Ok(())
}
