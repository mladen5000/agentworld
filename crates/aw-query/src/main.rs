//! `aw-query` — inspect and maintain a Layer 4 persistent world-model store.
//!
//! Read-only apps-layer tool: it consumes the store `aw-mvp` / `aw-graph`
//! maintain and answers "what does my world.db know?" without involving an
//! LLM. The one mutating subcommand is `prune`, the sanctioned retention knob.
//!
//! Usage:
//!
//!   aw-query summary                      # node/edge/event counts + time span
//!   aw-query processes  [--since-mins 60] # processes seen recently
//!   aw-query endpoints  [--limit 20]      # top endpoints by bytes
//!   aw-query domains    [--limit 20]      # top DNS names by query count
//!   aw-query focus      [--since-mins 60] # app-focus segments
//!   aw-query events     [--since-mins 60] [--kinds dns_query,...] [--limit 200]
//!   aw-query topology   [--since-mins 60] [--limit 20] # degree centrality + connected components
//!   aw-query prune      --older-than-days 30
//!
//! All subcommands accept `--store <path>` (default: the same
//! `~/Library/Application Support/agentworld/world.db` that `aw-mvp` writes)
//! and `--pretty` for human-readable text instead of JSON.

use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use aw_cli_fmt::{fmt_duration, fmt_unix_ns, now_unix_ns, title_bar};
use aw_events::EventKind;
use aw_store::Store;

enum Subcommand {
    Summary,
    Processes,
    Endpoints,
    Domains,
    Focus,
    Events,
    Topology,
    Prune,
}

struct Args {
    subcommand: Subcommand,
    store: Option<PathBuf>,
    pretty: bool,
    /// `None` = per-subcommand default (20 for top-N lists, 200 for events).
    limit: Option<usize>,
    since_mins: u64,
    older_than_days: Option<u64>,
    kinds: Option<Vec<EventKind>>,
}

fn default_store_path() -> Option<PathBuf> {
    let home = std::env::var_os("HOME")?;
    let mut p = PathBuf::from(home);
    p.push("Library/Application Support/agentworld/world.db");
    Some(p)
}

fn parse_args() -> Result<Args> {
    let mut iter = std::env::args().skip(1);
    let sub = match iter.next().as_deref() {
        Some("summary") => Subcommand::Summary,
        Some("processes") => Subcommand::Processes,
        Some("endpoints") => Subcommand::Endpoints,
        Some("domains") => Subcommand::Domains,
        Some("focus") => Subcommand::Focus,
        Some("events") => Subcommand::Events,
        Some("topology") => Subcommand::Topology,
        Some("prune") => Subcommand::Prune,
        Some("-h") | Some("--help") => {
            print_usage();
            std::process::exit(0);
        }
        Some(other) => bail!("unknown subcommand: {other}"),
        None => {
            print_usage();
            std::process::exit(2);
        }
    };

    let mut args = Args {
        subcommand: sub,
        store: None,
        pretty: false,
        limit: None,
        since_mins: 60,
        older_than_days: None,
        kinds: None,
    };
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--store" => {
                args.store = Some(PathBuf::from(
                    iter.next().context("--store requires a path")?,
                ))
            }
            "--pretty" => args.pretty = true,
            "--limit" => {
                let v = iter.next().context("--limit requires a value")?;
                args.limit = Some(v.parse().context("--limit must be an integer")?);
            }
            "--kinds" => {
                let v = iter
                    .next()
                    .context("--kinds requires a comma-separated list")?;
                let mut kinds = Vec::new();
                for part in v.split(',').map(str::trim).filter(|p| !p.is_empty()) {
                    let kind: EventKind = serde_json::from_value(serde_json::Value::String(
                        part.to_string(),
                    ))
                    .with_context(|| {
                        format!("unknown event kind '{part}' (expected snake_case, e.g. dns_query)")
                    })?;
                    kinds.push(kind);
                }
                anyhow::ensure!(!kinds.is_empty(), "--kinds list is empty");
                args.kinds = Some(kinds);
            }
            "--since-mins" => {
                let v = iter.next().context("--since-mins requires a value")?;
                args.since_mins = v.parse().context("--since-mins must be an integer")?;
            }
            "--older-than-days" => {
                let v = iter.next().context("--older-than-days requires a value")?;
                args.older_than_days =
                    Some(v.parse().context("--older-than-days must be an integer")?);
            }
            "-h" | "--help" => {
                print_usage();
                std::process::exit(0);
            }
            other => bail!("unknown argument: {other}"),
        }
    }
    Ok(args)
}

fn print_usage() {
    eprintln!("usage: aw-query <subcommand> [--store <db-path>] [--pretty] [options]");
    eprintln!();
    eprintln!("subcommands:");
    eprintln!("  summary                       node/edge counts and covered time span");
    eprintln!("  processes [--since-mins N]    processes seen in the last N minutes (default 60)");
    eprintln!("  endpoints [--limit N]         top endpoints by total bytes (default 20)");
    eprintln!("  domains   [--limit N]         top DNS names by query count (default 20)");
    eprintln!("  focus     [--since-mins N]    app focus segments in the last N minutes");
    eprintln!("  events    [--since-mins N] [--kinds k1,k2] [--limit N]");
    eprintln!("                                event history, oldest first (default limit 200)");
    eprintln!("  topology  [--since-mins N] [--limit N]");
    eprintln!("                                degree centrality + connected components (default limit 20)");
    eprintln!("  prune     --older-than-days N delete nodes/edges/events quiescent for N days");
    eprintln!();
    eprintln!("options:");
    eprintln!("  --store <path>   default: ~/Library/Application Support/agentworld/world.db");
    eprintln!("  --pretty         human-readable text instead of JSON");
}

/// Render the daemon heartbeat that `aw-mvp --daemon` writes into the meta
/// table. A pid with a recent heartbeat means "running"; a pid with an old
/// heartbeat means the daemon likely died without cleanup; an empty pid is
/// a clean stop.
fn daemon_status(store: &Store) -> String {
    let pid = store.get_meta("daemon_pid").ok().flatten();
    let beat = store
        .get_meta("daemon_heartbeat_unix_ns")
        .ok()
        .flatten()
        .and_then(|s| s.parse::<i64>().ok());
    match (pid.as_deref(), beat) {
        (Some(""), Some(b)) => format!("stopped cleanly (last tick {})", fmt_unix_ns(b)),
        (Some(pid), Some(b)) => {
            let age_secs = (now_unix_ns() - b) / 1_000_000_000;
            // Two ticks of the default 60s cadence without a heartbeat
            // reads as dead.
            if age_secs > 120 {
                format!(
                    "pid {pid}, heartbeat {} — likely not running",
                    fmt_unix_ns(b)
                )
            } else {
                format!("pid {pid}, heartbeat {}", fmt_unix_ns(b))
            }
        }
        _ => "never ran against this store".to_string(),
    }
}

/// Compact one-line rendering of an event payload for the pretty view,
/// truncated to `max` characters (full payloads are available via JSON mode).
fn compact_payload(v: &serde_json::Value, max: usize) -> String {
    let s = serde_json::to_string(v).unwrap_or_default();
    if s.chars().count() <= max {
        s
    } else {
        let truncated: String = s.chars().take(max).collect();
        format!("{truncated}…")
    }
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .init();

    let args = parse_args()?;
    let path = args
        .store
        .clone()
        .or_else(default_store_path)
        .context("no --store given and $HOME is unset")?;
    if !path.exists() {
        bail!(
            "store not found at {} (run aw-mvp or aw-graph --persist first)",
            path.display()
        );
    }
    let mut store =
        Store::open(&path).with_context(|| format!("opening store at {}", path.display()))?;

    match args.subcommand {
        Subcommand::Summary => {
            let sum = store.summary()?;
            if args.pretty {
                println!("{}", title_bar("summary"));
                println!("store: {}", path.display());
                println!("nodes:");
                for (kind, n) in &sum.node_counts {
                    println!("  {kind:<10} {n}");
                }
                println!("edges:");
                for (kind, n) in &sum.edge_counts {
                    println!("  {kind:<18} {n}");
                }
                println!("events: {}", sum.event_count);
                match (sum.first_seen_unix_ns, sum.last_seen_unix_ns) {
                    (Some(a), Some(b)) => {
                        println!("span:  {}  ..  {}", fmt_unix_ns(a), fmt_unix_ns(b));
                    }
                    _ => println!("span:  (empty store)"),
                }
                println!("daemon: {}", daemon_status(&store));
            } else {
                println!("{}", serde_json::to_string_pretty(&sum)?);
            }
        }
        Subcommand::Processes => {
            let since = now_unix_ns().saturating_sub((args.since_mins * 60) as i64 * 1_000_000_000);
            let procs = store.processes_seen_since(since.max(0) as u64)?;
            if args.pretty {
                println!("{}", title_bar("processes"));
                println!(
                    "{} processes seen in the last {}m:",
                    procs.len(),
                    args.since_mins
                );
                for p in &procs {
                    println!(
                        "  pid {:<6} uid {:<5} {:<20} {}",
                        p.id.pid,
                        p.uid.map(|u| u.to_string()).unwrap_or_else(|| "?".into()),
                        p.comm.as_deref().or(p.name.as_deref()).unwrap_or("?"),
                        p.exec_path.as_deref().unwrap_or(""),
                    );
                }
            } else {
                println!("{}", serde_json::to_string_pretty(&procs)?);
            }
        }
        Subcommand::Endpoints => {
            let rows = store.top_endpoints_by_bytes(args.limit.unwrap_or(20))?;
            if args.pretty {
                println!("{}", title_bar("endpoints"));
                println!("top {} endpoints by bytes:", rows.len());
                for r in &rows {
                    println!(
                        "  {:<40} {:>12} bytes  {:>3} conns  {:>3} procs",
                        r.foreign_addr, r.total_bytes, r.connection_count, r.distinct_processes,
                    );
                }
            } else {
                println!("{}", serde_json::to_string_pretty(&rows)?);
            }
        }
        Subcommand::Domains => {
            let rows = store.top_domains(args.limit.unwrap_or(20))?;
            if args.pretty {
                println!("{}", title_bar("domains"));
                println!("top {} domains by query count:", rows.len());
                for r in &rows {
                    println!(
                        "  {:<50} {:>6} queries  {:>3} procs  last {}",
                        r.name,
                        r.query_count,
                        r.distinct_processes,
                        fmt_unix_ns(r.last_seen_unix_ns),
                    );
                }
            } else {
                println!("{}", serde_json::to_string_pretty(&rows)?);
            }
        }
        Subcommand::Focus => {
            let to = now_unix_ns();
            let from = to.saturating_sub((args.since_mins * 60) as i64 * 1_000_000_000);
            let segs = store.focus_segments_in_window(from, to)?;
            if args.pretty {
                println!("{}", title_bar("focus"));
                println!(
                    "{} focus segments in the last {}m:",
                    segs.len(),
                    args.since_mins
                );
                for s in &segs {
                    println!(
                        "  {:<30} pid {:<6} {:>8}  starting {}",
                        s.app_name,
                        s.process_pid,
                        fmt_duration(s.duration_secs),
                        fmt_unix_ns(s.from_unix_ns),
                    );
                }
            } else {
                println!("{}", serde_json::to_string_pretty(&segs)?);
            }
        }
        Subcommand::Events => {
            let to = now_unix_ns();
            let from = to.saturating_sub((args.since_mins * 60) as i64 * 1_000_000_000);
            let events = store.events_in_window(
                from,
                to,
                args.kinds.as_deref(),
                args.limit.unwrap_or(200),
            )?;
            if args.pretty {
                println!("{}", title_bar("events"));
                println!(
                    "{} events in the last {}m (oldest first):",
                    events.len(),
                    args.since_mins
                );
                for ev in &events {
                    let kind = serde_json::to_value(ev.kind)
                        .ok()
                        .and_then(|v| v.as_str().map(String::from))
                        .unwrap_or_else(|| format!("{:?}", ev.kind));
                    println!(
                        "  {}  {:<20} pid {:<6} {}",
                        fmt_unix_ns(ev.timestamp.mono_ns as i64),
                        kind,
                        ev.pid.map(|p| p.to_string()).unwrap_or_else(|| "-".into()),
                        compact_payload(&ev.payload, 120),
                    );
                }
            } else {
                println!("{}", serde_json::to_string_pretty(&events)?);
            }
        }
        Subcommand::Topology => {
            let to = now_unix_ns();
            let from = to.saturating_sub((args.since_mins * 60) as i64 * 1_000_000_000);
            let g = store.graph_in_window(from, to)?;
            let adj = aw_graph::analytics::Adjacency::from_graph(&g);
            let degree = aw_graph::analytics::degree_centrality(&adj);
            let weighted_degree = aw_graph::analytics::weighted_degree_centrality(&adj);
            let mut top_by_degree: Vec<(String, u64, u64)> = degree
                .into_iter()
                .map(|(node, d)| {
                    let w = weighted_degree.get(&node).copied().unwrap_or(0);
                    (node.label(&g), d, w)
                })
                .collect();
            top_by_degree.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
            top_by_degree.truncate(args.limit.unwrap_or(20));

            let components = aw_graph::analytics::connected_components(&adj);
            let mut sizes = aw_graph::analytics::component_sizes(&components);
            sizes.sort_unstable_by(|a, b| b.cmp(a));

            if args.pretty {
                println!("{}", title_bar("topology"));
                println!(
                    "topology in the last {}m: {} connected components (largest: {})",
                    args.since_mins,
                    components.len(),
                    sizes.first().copied().unwrap_or(0),
                );
                println!("top {} by degree centrality:", top_by_degree.len());
                println!(
                    "  (weighted = re-observation count on queried_domain edges only — secondary signal)"
                );
                for (label, degree, weighted) in &top_by_degree {
                    println!("  {label:<50} degree {degree:>4}  weighted {weighted:>6}");
                }
            } else {
                let out = serde_json::json!({
                    "component_count": components.len(),
                    "component_sizes": sizes,
                    "top_by_degree": top_by_degree.iter().map(|(label, degree, weighted)| {
                        serde_json::json!({
                            "label": label,
                            "degree": degree,
                            "weighted_degree": weighted,
                        })
                    }).collect::<Vec<_>>(),
                });
                println!("{}", serde_json::to_string_pretty(&out)?);
            }
        }
        Subcommand::Prune => {
            let days = args
                .older_than_days
                .context("prune requires --older-than-days <n>")?;
            let cutoff = now_unix_ns().saturating_sub((days * 86_400) as i64 * 1_000_000_000);
            let report = store.prune_before(cutoff)?;
            if args.pretty {
                println!("{}", title_bar("prune"));
                println!(
                    "pruned {} nodes, {} edges, {} events older than {} days from {}",
                    report.nodes_deleted,
                    report.edges_deleted,
                    report.events_deleted,
                    days,
                    path.display(),
                );
            } else {
                println!("{}", serde_json::to_string_pretty(&report)?);
            }
        }
    }
    Ok(())
}
