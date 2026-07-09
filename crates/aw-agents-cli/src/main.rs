//! `aw-agents` — runs LLM agents over captured Layer 2 events and Layer 3 graphs.
//!
//! Usage:
//!
//!   aw-agents timeline         < events.ndjson
//!   aw-agents process-anomaly  --graph ./out/graph.json
//!   aw-agents process-anomaly  --store ./world.db
//!   aw-agents network-review   < events.ndjson
//!   aw-agents dns-review       < events.ndjson
//!
//! All subcommands accept `--model <name>` (default `gemma3:4b`),
//! `--ollama-url <url>` (default `http://127.0.0.1:11434`),
//! `--max-items <n>` (default 200), and `--pretty` to print the report as
//! human-readable text instead of JSON.

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{anyhow, bail, Context, Result};
use aw_agents::{AgentConfig, AgentCtx, Report};
use aw_llm::OllamaClient;

enum Subcommand {
    Timeline,
    ProcessAnomaly,
    NetworkReview,
    DnsReview,
}

struct Args {
    subcommand: Subcommand,
    model: String,
    ollama_url: String,
    graph_path: Option<PathBuf>,
    store_path: Option<PathBuf>,
    pretty: bool,
    max_input_items: usize,
}

fn parse_args() -> Result<Args> {
    let mut iter = std::env::args().skip(1);
    let sub = iter.next().ok_or_else(|| {
        anyhow!("missing subcommand (timeline|process-anomaly|network-review|dns-review)")
    })?;
    let subcommand = match sub.as_str() {
        "timeline" => Subcommand::Timeline,
        "process-anomaly" => Subcommand::ProcessAnomaly,
        "network-review" => Subcommand::NetworkReview,
        "dns-review" => Subcommand::DnsReview,
        "-h" | "--help" => {
            print_usage();
            std::process::exit(0);
        }
        other => bail!("unknown subcommand: {other}"),
    };

    let mut model = "gemma3:4b".to_string();
    let mut ollama_url = "http://127.0.0.1:11434".to_string();
    let mut graph_path = None;
    let mut store_path = None;
    let mut pretty = false;
    let mut max_input_items: usize = 200;

    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--model" => model = iter.next().context("--model requires a value")?,
            "--ollama-url" => ollama_url = iter.next().context("--ollama-url requires a value")?,
            "--graph" => {
                graph_path = Some(PathBuf::from(
                    iter.next().context("--graph requires a path")?,
                ))
            }
            "--store" => {
                store_path = Some(PathBuf::from(
                    iter.next().context("--store requires a path")?,
                ))
            }
            "--pretty" => pretty = true,
            "--max-items" => {
                let s = iter.next().context("--max-items requires a value")?;
                max_input_items = s.parse().context("--max-items must be an integer")?;
            }
            "-h" | "--help" => {
                print_usage();
                std::process::exit(0);
            }
            other => bail!("unknown argument: {other}"),
        }
    }

    Ok(Args {
        subcommand,
        model,
        ollama_url,
        graph_path,
        store_path,
        pretty,
        max_input_items,
    })
}

fn print_usage() {
    eprintln!("usage: aw-agents <subcommand> [options]");
    eprintln!();
    eprintln!("subcommands:");
    eprintln!("  timeline           reads NDJSON events from stdin");
    eprintln!("  process-anomaly    reads --graph <path> OR --store <db-path>");
    eprintln!("  network-review     reads NDJSON events from stdin");
    eprintln!("  dns-review         reads NDJSON events from stdin");
    eprintln!();
    eprintln!("options:");
    eprintln!("  --model <name>           default: gemma3:4b");
    eprintln!("  --ollama-url <url>       default: http://127.0.0.1:11434");
    eprintln!("  --graph <path>           graph.json source for process-anomaly");
    eprintln!("  --store <db-path>        Layer 4 sqlite source for process-anomaly");
    eprintln!("  --max-items <n>          default: 200");
    eprintln!("  --pretty                 human-readable output (default: JSON)");
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .init();

    let args = parse_args()?;
    let llm = Arc::new(OllamaClient::with_base_url(&args.ollama_url));
    let config = AgentConfig {
        model: args.model.clone(),
        max_input_items: args.max_input_items,
        temperature: 0.2,
    };
    let ctx = AgentCtx::new(llm, config);

    eprintln!("aw-agents: model={} url={}", args.model, args.ollama_url);

    let report: Report = match args.subcommand {
        Subcommand::Timeline => {
            let events = aw_agents::input::read_events(std::io::stdin())?;
            eprintln!("aw-agents: read {} events from stdin", events.len());
            aw_agents::timeline_narrator::TimelineNarrator::new(ctx)
                .run(&events)
                .await?
        }
        Subcommand::ProcessAnomaly => {
            let detector = aw_agents::process_anomaly::ProcessAnomalyDetector::new(ctx);
            match (args.graph_path.as_ref(), args.store_path.as_ref()) {
                (Some(_), Some(_)) => bail!("--graph and --store are mutually exclusive"),
                (Some(p), None) => {
                    let g = aw_agents::input::read_graph(p)?;
                    eprintln!(
                        "aw-agents: read graph from {} with {} processes",
                        p.display(),
                        g.processes.len()
                    );
                    detector.run(&g).await?
                }
                (None, Some(p)) => {
                    // `run_from_store` issues each suspicion query as its own
                    // SQL statement — the LLM only sees the candidates that
                    // matched, never the full process list.
                    let store = aw_store::Store::open(p)
                        .with_context(|| format!("opening store at {}", p.display()))?;
                    eprintln!(
                        "aw-agents: running suspicion queries against store {}",
                        p.display()
                    );
                    detector.run_from_store(&store).await?
                }
                (None, None) => {
                    bail!("process-anomaly requires --graph <path> or --store <db-path>")
                }
            }
        }
        Subcommand::NetworkReview => {
            let events = aw_agents::input::read_events(std::io::stdin())?;
            eprintln!("aw-agents: read {} events from stdin", events.len());
            aw_agents::network_reviewer::NetworkReviewer::new(ctx)
                .run(&events)
                .await?
        }
        Subcommand::DnsReview => {
            let events = aw_agents::input::read_events(std::io::stdin())?;
            eprintln!("aw-agents: read {} events from stdin", events.len());
            aw_agents::dns_reviewer::DnsReviewer::new(ctx)
                .run(&events)
                .await?
        }
    };

    if args.pretty {
        println!("=== Summary ({}) ===", report.model);
        println!("{}\n", report.summary);
        println!("=== Details ===");
        println!("{}", serde_json::to_string_pretty(&report.details)?);
    } else {
        println!("{}", serde_json::to_string_pretty(&report)?);
    }
    Ok(())
}
