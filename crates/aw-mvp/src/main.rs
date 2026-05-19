//! `aw-mvp` — agentworld pipeline runner.
//!
//! Two modes:
//!
//! - **One-shot** (default): capture for `--duration` seconds, narrate once,
//!   run anomaly pass, exit. Useful for quick "what just happened" checks.
//! - **Daemon** (`--daemon`): capture forever, emit a fresh narration
//!   paragraph every `--tick` seconds describing the last `--window`
//!   minutes of activity. Ctrl-C stops cleanly.
//!
//! Defaults are tuned for `cargo run` with no arguments (30s one-shot).
//! For continuous narration: `cargo run -- --daemon`.
//!
//! ## Output streams
//!
//! - `stdout`: narration paragraphs (one per tick in daemon mode, one
//!   total in one-shot). Pipe-friendly.
//! - `stderr`: status + tracing. Quiet by default; raise with `RUST_LOG`.

use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use aw_agents::process_anomaly::ProcessAnomalyDetector;
use aw_agents::timeline_narrator::TimelineNarrator;
use aw_agents::{AgentConfig, AgentCtx};
use aw_core::{Bus, MonotonicClock};
use aw_dns::DnsAdapter;
use aw_eslogger::EsLoggerAdapter;
use aw_events::{Event, Reconstructor};
use aw_fsevents::FsEventsAdapter;
use aw_graph::GraphBuilder;
use aw_llm::OllamaClient;
use aw_network::NetworkAdapter;
use aw_process::ProcessAdapter;
use aw_scheduler::Scheduler;
use aw_store::Store;
use aw_system::SystemAdapter;
use aw_window::WindowAdapter;

struct Args {
    /// One-shot capture duration (only used when `daemon == false`).
    duration: Duration,
    /// Run forever, narrating each `tick` over the last `window`.
    daemon: bool,
    /// Daemon: time between narration paragraphs.
    tick: Duration,
    /// Daemon: how far back each paragraph looks.
    window: Duration,
    model: String,
    ollama_url: String,
    /// Path to the persistent world-model SQLite store. `None` means
    /// "default location under ~/Library/Application Support/agentworld/".
    /// Pass `--no-store` to disable persistence entirely.
    store_path: Option<PathBuf>,
    /// Skip persistence. Useful for ephemeral runs and tests that don't
    /// want to touch the user's data directory.
    no_store: bool,
    /// Daemon: how stale an in-memory node can be before being dropped (after
    /// it's been persisted to the store). Caps RAM growth on long runs.
    store_ttl: Duration,
}

impl Default for Args {
    fn default() -> Self {
        Self {
            duration: Duration::from_secs(30),
            daemon: false,
            tick: Duration::from_secs(60),
            window: Duration::from_secs(300), // 5 min
            model: "gemma3:4b".to_string(),
            ollama_url: "http://127.0.0.1:11434".to_string(),
            store_path: None,
            no_store: false,
            store_ttl: Duration::from_secs(60 * 60), // 1 hour
        }
    }
}

/// Default store location: `~/Library/Application Support/agentworld/world.db`.
/// Creates the parent directory on demand. Returns `None` if `$HOME` is unset
/// (which would be unusual on macOS but worth not crashing over).
fn default_store_path() -> Option<PathBuf> {
    let home = std::env::var_os("HOME")?;
    let mut p = PathBuf::from(home);
    p.push("Library/Application Support/agentworld");
    p.push("world.db");
    Some(p)
}

/// Apply `--no-store` / `--store-path` / default to produce the path we should
/// use, or `None` if persistence is disabled / unresolvable.
fn resolve_store_path(args: &Args) -> Option<PathBuf> {
    if args.no_store { return None; }
    args.store_path.clone().or_else(default_store_path)
}

/// Open the store at `path`, creating parent directories if needed.
/// Returns the open `Store` plus the resolved path (for logging).
fn open_store(path: PathBuf) -> Result<(Store, PathBuf)> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)
            .with_context(|| format!("creating store directory {}", dir.display()))?;
    }
    let store = Store::open(&path)
        .with_context(|| format!("opening store at {}", path.display()))?;
    Ok((store, path))
}

fn parse_args() -> Result<Args> {
    let mut args = Args::default();
    let mut iter = std::env::args().skip(1);
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--duration" => {
                let v = iter.next().context("--duration requires a value (seconds)")?;
                args.duration = Duration::from_secs(v.parse().context("--duration must be an integer number of seconds")?);
            }
            "--daemon" => args.daemon = true,
            "--tick" => {
                let v = iter.next().context("--tick requires a value (seconds)")?;
                args.tick = Duration::from_secs(v.parse().context("--tick must be an integer number of seconds")?);
            }
            "--window" => {
                let v = iter.next().context("--window requires a value (seconds)")?;
                args.window = Duration::from_secs(v.parse().context("--window must be an integer number of seconds")?);
            }
            "--model" => args.model = iter.next().context("--model requires a value")?,
            "--ollama-url" => args.ollama_url = iter.next().context("--ollama-url requires a value")?,
            "--store-path" => {
                let v = iter.next().context("--store-path requires a value")?;
                args.store_path = Some(PathBuf::from(v));
            }
            "--no-store" => args.no_store = true,
            "--store-ttl" => {
                let v = iter.next().context("--store-ttl requires a value (seconds)")?;
                args.store_ttl = Duration::from_secs(v.parse().context("--store-ttl must be an integer number of seconds")?);
            }
            "-h" | "--help" => { print_usage(); std::process::exit(0); }
            other => anyhow::bail!("unknown argument: {other}"),
        }
    }
    // Cheap sanity: tick longer than window means the sliding view always
    // empties between paragraphs. Permitted (it just yields sparse paragraphs)
    // but worth warning about.
    if args.daemon && args.tick > args.window {
        eprintln!(
            "aw-mvp: warning — --tick ({tick}s) is longer than --window ({window}s); \
             each paragraph will only ever see a fraction of the captured activity.",
            tick = args.tick.as_secs(), window = args.window.as_secs(),
        );
    }
    Ok(args)
}

fn print_usage() {
    eprintln!("usage: aw-mvp [--daemon] [--duration <secs>] [--tick <secs>] [--window <secs>]");
    eprintln!("              [--model <name>] [--ollama-url <url>]");
    eprintln!("              [--store-path <path> | --no-store]");
    eprintln!();
    eprintln!("One-shot mode (default): captures for --duration seconds, narrates");
    eprintln!("once, runs an anomaly pass, exits.");
    eprintln!();
    eprintln!("Daemon mode (--daemon): captures forever; every --tick seconds emits");
    eprintln!("a present-tense paragraph describing the last --window seconds.");
    eprintln!();
    eprintln!("Persistence: the reconstructed graph is merged into a SQLite store");
    eprintln!("after each capture (one-shot) or each tick (daemon). Default path:");
    eprintln!("  ~/Library/Application Support/agentworld/world.db");
    eprintln!("Override with --store-path <path>, or disable with --no-store.");
    eprintln!();
    eprintln!("Daemon: --store-ttl <secs> drops in-memory nodes that have been");
    eprintln!("quiescent for longer than the TTL (default 3600s) after each merge.");
    eprintln!("The store keeps them — trimming only caps RAM use on long runs.");
    eprintln!();
    eprintln!("Defaults: --duration 30 --tick 60 --window 300 --model gemma3:4b");
    eprintln!("          --ollama-url http://127.0.0.1:11434");
    eprintln!();
    eprintln!("Ctrl-C stops cleanly in both modes.");
}

#[tokio::main]
async fn main() -> Result<()> {
    // Mute fsevent_stream's shutdown noise by default — its CFRunLoop
    // callback fires for a few hundred ms after the bus receiver drops
    // and would otherwise spam ERROR lines on every clean exit. Override
    // via RUST_LOG.
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn,fsevent_stream=off"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .init();

    let args = parse_args()?;
    if args.daemon { run_daemon(args).await } else { run_one_shot(args).await }
}

// ============================================================================
// One-shot
// ============================================================================

async fn run_one_shot(args: Args) -> Result<()> {
    eprintln!(
        "aw-mvp: capturing for {}s; model={} url={}",
        args.duration.as_secs(), args.model, args.ollama_url,
    );

    let events = capture_for_duration(args.duration).await?;
    eprintln!("aw-mvp: capture done — {} reconstructed events", events.len());

    let llm = Arc::new(OllamaClient::with_base_url(&args.ollama_url));
    let make_ctx = || AgentCtx::new(
        llm.clone(),
        AgentConfig { model: args.model.clone(), ..AgentConfig::default() },
    );

    eprintln!("aw-mvp: asking {} to narrate...", args.model);
    let narrative = TimelineNarrator::new(make_ctx())
        .run(&events)
        .await
        .context("timeline narrator failed (is Ollama running and the model pulled?)")?;
    println!("{}", narrative.summary);

    let graph = build_graph(&events);

    // Persist the graph before the anomaly pass so a crash or Ctrl-C during
    // narration doesn't lose the capture. `merge_graph` is idempotent: re-run
    // produces no duplicates, just bumps edge counts.
    if let Some(path) = resolve_store_path(&args) {
        match open_store(path) {
            Ok((mut store, p)) => match store.merge_graph(&graph) {
                Ok(report) => eprintln!(
                    "aw-mvp: persisted to {} (nodes +{}/{}, edges +{}/{})",
                    p.display(),
                    report.nodes_inserted, report.nodes_updated,
                    report.edges_inserted, report.edges_updated,
                ),
                Err(e) => eprintln!("aw-mvp: store merge failed: {e}"),
            },
            Err(e) => eprintln!("aw-mvp: could not open store: {e}"),
        }
    }

    eprintln!(
        "aw-mvp: anomaly pass over {} processes, {} edges...",
        graph.processes.len(), graph.edges.len(),
    );
    match ProcessAnomalyDetector::new(make_ctx()).run(&graph).await {
        Ok(report) => {
            println!();
            println!("--- anomaly check ---");
            println!("{}", report.summary);
        }
        Err(e) => eprintln!("aw-mvp: anomaly pass failed: {e}"),
    }
    Ok(())
}

fn build_graph(events: &[Event]) -> aw_graph::Graph {
    let mut builder = GraphBuilder::new();
    for ev in events { builder.on_event(ev); }
    builder.build()
}

async fn capture_for_duration(duration: Duration) -> Result<Vec<Event>> {
    let clock = Arc::new(MonotonicClock::new());
    let (bus, mut rx) = Bus::channel();
    let mut scheduler = build_scheduler(clock.clone(), bus.clone());
    let mut recon = Reconstructor::new();
    let mut events: Vec<Event> = Vec::new();
    let deadline = tokio::time::sleep(duration);
    tokio::pin!(deadline);

    loop {
        tokio::select! {
            biased;
            _ = tokio::signal::ctrl_c() => {
                eprintln!("aw-mvp: Ctrl-C — finishing early");
                break;
            }
            _ = &mut deadline => break,
            maybe = rx.recv() => match maybe {
                Some(obs) => { for ev in recon.process(&obs) { events.push(ev); } }
                None => break,
            },
        }
    }

    scheduler.shutdown();
    Ok(events)
}

// ============================================================================
// Daemon
// ============================================================================

async fn run_daemon(args: Args) -> Result<()> {
    eprintln!(
        "aw-mvp: daemon mode — tick={}s window={}s model={} url={}",
        args.tick.as_secs(), args.window.as_secs(), args.model, args.ollama_url,
    );
    eprintln!("aw-mvp: Ctrl-C to stop. First paragraph in ~{}s.", args.tick.as_secs());

    let clock = Arc::new(MonotonicClock::new());
    let (bus, mut rx) = Bus::channel();
    let mut scheduler = build_scheduler(clock.clone(), bus.clone());
    let mut recon = Reconstructor::new();

    // Sliding-window buffer. `mono_ns` on event timestamps is monotonic from
    // process start, so we can evict by `front().mono_ns < cutoff` without
    // wall-clock concerns.
    let mut window: VecDeque<Event> = VecDeque::new();
    let window_ns = args.window.as_nanos() as u64;

    // Persistent store + in-flight graph builder. The window above feeds the
    // *narrator*; this builder feeds the *store*. They're separate because the
    // narration is short-lived (one paragraph per tick) while the store is the
    // long-lived durable mirror.
    let mut store_and_builder: Option<(Store, GraphBuilder, PathBuf)> = match resolve_store_path(&args) {
        Some(path) => match open_store(path) {
            Ok((store, p)) => {
                eprintln!("aw-mvp: persisting to {}", p.display());
                Some((store, GraphBuilder::new(), p))
            }
            Err(e) => {
                eprintln!("aw-mvp: persistence disabled — could not open store: {e}");
                None
            }
        },
        None => {
            eprintln!("aw-mvp: persistence disabled (--no-store or $HOME unset)");
            None
        }
    };

    let llm = Arc::new(OllamaClient::with_base_url(&args.ollama_url));
    let make_ctx = || AgentCtx::new(
        llm.clone(),
        AgentConfig { model: args.model.clone(), ..AgentConfig::default() },
    );

    let mut ticker = tokio::time::interval(args.tick);
    // First tick fires immediately by default; skip it so the first paragraph
    // actually has data to narrate.
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    ticker.tick().await;

    // Hold the in-flight narration's join handle so a slow LLM doesn't block
    // event ingestion AND so we can detect "still running" at the next tick
    // and skip rather than queue. `None` means "no narration running".
    let mut narrating: Option<tokio::task::JoinHandle<()>> = None;

    loop {
        tokio::select! {
            biased;
            _ = tokio::signal::ctrl_c() => {
                eprintln!("aw-mvp: Ctrl-C — stopping daemon");
                break;
            }
            _ = ticker.tick() => {
                // Reap a previous narration if it already finished; if it's
                // still going, skip this tick rather than queue another call.
                if let Some(h) = &narrating {
                    if !h.is_finished() {
                        eprintln!("aw-mvp: previous narration still in flight; skipping tick");
                        continue;
                    }
                    narrating = None;
                }

                // Merge whatever the builder has into the store. Doing this
                // *before* narration means a crash during the LLM call still
                // preserves the capture. Merge is idempotent (counts increment
                // rather than duplicate), so re-firing is safe.
                //
                // After a successful merge, trim in-memory nodes older than
                // `store_ttl` relative to the newest event we hold. The store
                // retains them; this only caps daemon RAM growth.
                if let Some((store, builder, path)) = store_and_builder.as_mut() {
                    let snapshot = builder.snapshot();
                    match store.merge_graph(&snapshot) {
                        Ok(report) => {
                            let trimmed = if let Some(newest) = window.back().map(|e| e.timestamp.mono_ns) {
                                let ttl_ns = args.store_ttl.as_nanos() as u64;
                                let cutoff_ns = newest.saturating_sub(ttl_ns);
                                let cutoff = aw_core::Timestamp { mono_ns: cutoff_ns, wall_anchor_ns: 0 };
                                builder.trim_before(cutoff)
                            } else { 0 };
                            eprintln!(
                                "aw-mvp: merged into {} (nodes +{}/{}, edges +{}/{}, trimmed {trimmed})",
                                path.display(),
                                report.nodes_inserted, report.nodes_updated,
                                report.edges_inserted, report.edges_updated,
                            );
                        }
                        Err(e) => eprintln!("aw-mvp: store merge failed: {e}"),
                    }
                }

                if window.is_empty() {
                    eprintln!("aw-mvp: window empty — nothing to narrate yet");
                    continue;
                }
                // Snapshot the window for the LLM call. Cheap clone — Events
                // are small, and the window itself is bounded.
                let snapshot: Vec<Event> = window.iter().cloned().collect();
                let ctx = make_ctx();
                narrating = Some(tokio::spawn(async move {
                    let started = std::time::Instant::now();
                    let n = snapshot.len();
                    match TimelineNarrator::new(ctx).live().run(&snapshot).await {
                        Ok(report) => {
                            eprintln!(
                                "aw-mvp: narrated {n} events in {:.1}s",
                                started.elapsed().as_secs_f64(),
                            );
                            // println! is line-buffered + thread-safe; the
                            // ingest loop's stderr writes won't interleave.
                            println!("{}", report.summary);
                            println!();
                        }
                        Err(e) => eprintln!("aw-mvp: narration failed: {e}"),
                    }
                }));
            }
            maybe = rx.recv() => match maybe {
                Some(obs) => {
                    // Also feed the raw observation to the graph builder so
                    // app-focus intervals (which derive from `Window` source
                    // observations, not Layer 2 events) get captured.
                    if let Some((_, builder, _)) = store_and_builder.as_mut() {
                        builder.on_observation(&obs);
                    }
                    for ev in recon.process(&obs) {
                        if let Some((_, builder, _)) = store_and_builder.as_mut() {
                            builder.on_event(&ev);
                        }
                        window.push_back(ev);
                    }
                    // Evict anything older than `window` seconds from the
                    // newest event we hold. Using the newest as "now" rather
                    // than wall-clock keeps this robust if the model is
                    // briefly slow or the system was suspended.
                    if let Some(newest) = window.back().map(|e| e.timestamp.mono_ns) {
                        let cutoff = newest.saturating_sub(window_ns);
                        while let Some(front) = window.front() {
                            if front.timestamp.mono_ns < cutoff { window.pop_front(); }
                            else { break; }
                        }
                    }
                }
                None => break,
            },
        }
    }

    scheduler.shutdown();

    // Final merge so the events ingested since the last tick aren't lost on
    // Ctrl-C. Safe to re-run because merge is idempotent.
    if let Some((store, builder, path)) = store_and_builder.as_mut() {
        let snapshot = builder.snapshot();
        match store.merge_graph(&snapshot) {
            Ok(report) => eprintln!(
                "aw-mvp: final merge to {} (nodes +{}/{}, edges +{}/{})",
                path.display(),
                report.nodes_inserted, report.nodes_updated,
                report.edges_inserted, report.edges_updated,
            ),
            Err(e) => eprintln!("aw-mvp: final store merge failed: {e}"),
        }
    }

    // Give an in-flight narration up to 5s to finish so its paragraph
    // isn't lost. Anything longer and we abandon — the user just hit Ctrl-C
    // and doesn't want to wait.
    if let Some(h) = narrating {
        if !h.is_finished() {
            eprintln!("aw-mvp: waiting up to 5s for in-flight narration to finish...");
            let _ = tokio::time::timeout(Duration::from_secs(5), h).await;
        }
    }
    Ok(())
}

// ============================================================================
// Shared
// ============================================================================

fn build_scheduler(clock: Arc<MonotonicClock>, bus: Bus) -> Scheduler {
    let mut scheduler = Scheduler::new(clock, bus, Duration::from_secs(1));
    scheduler.register(FsEventsAdapter::new());
    scheduler.register(ProcessAdapter::new());
    scheduler.register(NetworkAdapter::new());
    scheduler.register(WindowAdapter::new());
    scheduler.register(SystemAdapter::new());
    scheduler.register(EsLoggerAdapter::new());
    scheduler.register(DnsAdapter::new());
    scheduler
}
