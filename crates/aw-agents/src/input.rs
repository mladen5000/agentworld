//! Helpers for loading NDJSON event streams and graph JSON files into the
//! shapes the agents consume.

use std::io::{BufRead, BufReader, Read};
use std::path::Path;

use anyhow::{Context, Result};
use aw_events::Event;
use aw_graph::Graph;
use aw_store::Store;

/// Read NDJSON events from any `Read`. Lines that fail to parse as `Event`
/// are skipped with a `tracing::warn` (so a stream that includes both
/// observations and events — produced by `aw-observe --raw` — silently drops
/// the observation lines and keeps the events).
pub fn read_events(reader: impl Read) -> Result<Vec<Event>> {
    let buf = BufReader::new(reader);
    let mut out = Vec::new();
    let mut skipped = 0usize;
    for line in buf.lines() {
        let line = line?;
        let trimmed = line.trim();
        if trimmed.is_empty() { continue; }
        match serde_json::from_str::<Event>(trimmed) {
            Ok(ev) => out.push(ev),
            Err(_) => {
                skipped += 1;
                continue;
            }
        }
    }
    if skipped > 0 {
        tracing::debug!("read_events: skipped {skipped} non-Event lines");
    }
    Ok(out)
}

pub fn read_graph(path: impl AsRef<Path>) -> Result<Graph> {
    let s = std::fs::read_to_string(path.as_ref())
        .with_context(|| format!("reading {}", path.as_ref().display()))?;
    let g: Graph = serde_json::from_str(&s).context("parsing graph.json")?;
    Ok(g)
}

/// Load a graph from the Layer 4 persistent store. Wraps
/// `Store::load_graph` so callers don't have to depend on `aw-store`
/// directly.
pub fn read_graph_from_store(path: impl AsRef<Path>) -> Result<Graph> {
    let store = Store::open(path.as_ref())
        .with_context(|| format!("opening store at {}", path.as_ref().display()))?;
    let g = store.load_graph().context("loading graph from store")?;
    Ok(g)
}
