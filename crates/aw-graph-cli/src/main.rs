//! `aw-graph` — reads NDJSON Layer 1 observations and/or Layer 2 events from
//! stdin and writes a Layer 3 graph as two files: `graph.dot` (Graphviz) and
//! `graph.json`. Optionally also merges the graph into a persistent SQLite
//! Layer 4 store.
//!
//! Discriminating input lines: an `Observation` JSON object has a top-level
//! `source` field; an `Event` has a top-level `kind` field. Anything else is
//! skipped with a warning.
//!
//! Usage:
//!
//!   aw-observe --raw | aw-graph --out-dir ./out
//!   aw-graph --out-dir ./out < trace.ndjson
//!   aw-graph --out-dir ./out --persist ~/.agentworld/world.db < trace.ndjson

use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;

use anyhow::{Context, Result};
use aw_core::Observation;
use aw_events::Event;
use aw_graph::{dot, GraphBuilder};
use aw_store::Store;

struct Args {
    out_dir: PathBuf,
    persist: Option<PathBuf>,
}

fn parse_args() -> Result<Args> {
    let mut out_dir: Option<PathBuf> = None;
    let mut persist: Option<PathBuf> = None;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--out-dir" => {
                let v = args.next().context("--out-dir requires a path")?;
                out_dir = Some(PathBuf::from(v));
            }
            "--persist" => {
                let v = args.next().context("--persist requires a path to a sqlite db file")?;
                persist = Some(PathBuf::from(v));
            }
            "-h" | "--help" => {
                eprintln!("usage: aw-graph --out-dir <path> [--persist <db-path>]");
                eprintln!("  reads NDJSON observations + events from stdin");
                eprintln!("  writes <out-dir>/graph.dot and <out-dir>/graph.json");
                eprintln!("  --persist <path>  merge graph into a SQLite Layer 4 store");
                std::process::exit(0);
            }
            other => anyhow::bail!("unknown argument: {other}"),
        }
    }
    let out_dir = out_dir.context("--out-dir is required")?;
    Ok(Args { out_dir, persist })
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .init();

    let args = parse_args()?;
    std::fs::create_dir_all(&args.out_dir)
        .with_context(|| format!("creating {}", args.out_dir.display()))?;

    let stdin = std::io::stdin();
    let mut reader = BufReader::new(stdin.lock());

    let mut builder = GraphBuilder::new();
    let mut line = String::new();
    let mut obs_count = 0usize;
    let mut ev_count = 0usize;
    let mut skipped = 0usize;

    loop {
        line.clear();
        let n = reader.read_line(&mut line)?;
        if n == 0 { break; }
        let trimmed = line.trim();
        if trimmed.is_empty() { continue; }

        let value: serde_json::Value = match serde_json::from_str(trimmed) {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!("skipping unparseable line: {e}");
                skipped += 1;
                continue;
            }
        };

        if value.get("source").is_some() {
            match serde_json::from_value::<Observation>(value) {
                Ok(obs) => { builder.on_observation(&obs); obs_count += 1; }
                Err(e) => { tracing::warn!("skipping malformed Observation: {e}"); skipped += 1; }
            }
        } else if value.get("kind").is_some() {
            match serde_json::from_value::<Event>(value) {
                Ok(ev) => { builder.on_event(&ev); ev_count += 1; }
                Err(e) => { tracing::warn!("skipping malformed Event: {e}"); skipped += 1; }
            }
        } else {
            skipped += 1;
        }
    }

    let graph = builder.build();
    let dot_path = args.out_dir.join("graph.dot");
    let json_path = args.out_dir.join("graph.json");

    let dot_src = dot::to_dot(&graph);
    std::fs::write(&dot_path, dot_src.as_bytes())
        .with_context(|| format!("writing {}", dot_path.display()))?;
    let json_src = serde_json::to_vec_pretty(&graph)?;
    std::fs::write(&json_path, &json_src)
        .with_context(|| format!("writing {}", json_path.display()))?;

    let parent_of = graph.edges.iter().filter(|e| matches!(e, aw_graph::Edge::ParentOf { .. })).count();
    let frontmost_during = graph.edges.iter().filter(|e| matches!(e, aw_graph::Edge::FrontmostDuring { .. })).count();
    let opened_socket = graph.edges.iter().filter(|e| matches!(e, aw_graph::Edge::OpenedSocket { .. })).count();

    let mut stderr = std::io::stderr().lock();
    writeln!(
        stderr,
        "aw-graph: read {obs_count} observations, {ev_count} events, skipped {skipped}",
    )?;
    writeln!(
        stderr,
        "aw-graph: built {} processes, {} apps, {} sockets, {} files",
        graph.processes.len(),
        graph.apps.len(),
        graph.sockets.len(),
        graph.files.len(),
    )?;
    writeln!(
        stderr,
        "aw-graph: edges: {parent_of} parent_of, {frontmost_during} frontmost_during, {opened_socket} opened_socket",
    )?;
    writeln!(stderr, "aw-graph: wrote {} and {}", dot_path.display(), json_path.display())?;

    if let Some(db_path) = args.persist.as_ref() {
        // SQLite needs the parent directory to exist; create it for the user.
        if let Some(parent) = db_path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)
                    .with_context(|| format!("creating parent of {}", db_path.display()))?;
            }
        }
        let mut store = Store::open(db_path)
            .with_context(|| format!("opening store at {}", db_path.display()))?;
        let report = store.merge_graph(&graph)
            .with_context(|| "merging graph into store")?;
        writeln!(
            stderr,
            "aw-graph: persisted to {}: nodes +{}/~{}, edges +{}/~{}",
            db_path.display(),
            report.nodes_inserted, report.nodes_updated,
            report.edges_inserted, report.edges_updated,
        )?;
    }

    Ok(())
}
