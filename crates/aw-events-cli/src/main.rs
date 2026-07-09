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
//! `--kinds <k1,k2,...>` emits only the named event kinds (snake_case, e.g.
//! `--kinds dns_query,connection_opened`). Reconstruction still runs over the
//! full stream — filtering happens at output, so cross-source enrichment and
//! tick detection see every observation.
//!
//! This binary is a thin pump: it just calls `Reconstructor::process(obs)`
//! per line and writes any emitted events. Per-stage tick boundary detection
//! lives inside the stages themselves (see `aw_events::process_lifecycle`),
//! so the CLI does not need timing knowledge.

use std::collections::HashSet;
use std::io::{BufRead, BufReader, Write};

use anyhow::{Context, Result};
use aw_core::Observation;
use aw_events::{EventKind, Reconstructor};

struct Args {
    /// `None` means "emit everything".
    kinds: Option<HashSet<EventKind>>,
}

fn parse_kind(s: &str) -> Result<EventKind> {
    // EventKind serializes as a snake_case JSON string; reuse that mapping so
    // the CLI never drifts from the enum.
    serde_json::from_value(serde_json::Value::String(s.to_string()))
        .with_context(|| format!("unknown event kind '{s}' (expected snake_case, e.g. dns_query)"))
}

fn parse_args() -> Result<Args> {
    let mut kinds = None;
    let mut iter = std::env::args().skip(1);
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--kinds" => {
                let v = iter
                    .next()
                    .context("--kinds requires a comma-separated list")?;
                let mut set = HashSet::new();
                for part in v.split(',').map(str::trim).filter(|p| !p.is_empty()) {
                    set.insert(parse_kind(part)?);
                }
                anyhow::ensure!(!set.is_empty(), "--kinds list is empty");
                kinds = Some(set);
            }
            "-h" | "--help" => {
                eprintln!("usage: aw-events [--kinds <k1,k2,...>]");
                eprintln!("  reads NDJSON observations on stdin, writes NDJSON events on stdout");
                eprintln!("  --kinds: only emit the named kinds, e.g. dns_query,connection_opened");
                std::process::exit(0);
            }
            other => anyhow::bail!("unknown argument: {other}"),
        }
    }
    Ok(Args { kinds })
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .init();

    let args = parse_args()?;
    let stdin = std::io::stdin();
    let mut reader = BufReader::new(stdin.lock());
    let stdout = std::io::stdout();
    let mut out = stdout.lock();

    let mut recon = Reconstructor::new();
    let mut line = String::new();

    loop {
        line.clear();
        let n = reader.read_line(&mut line)?;
        if n == 0 {
            break;
        } // EOF
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let obs: Observation = match serde_json::from_str(trimmed) {
            Ok(o) => o,
            Err(e) => {
                tracing::warn!("skipping non-Observation line: {e}");
                continue;
            }
        };

        for ev in recon.process(&obs) {
            if let Some(kinds) = &args.kinds {
                if !kinds.contains(&ev.kind) {
                    continue;
                }
            }
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
