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

mod pipeline;

use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use aw_agents::baseline::BaselineEngine;
use aw_agents::process_anomaly::{
    suspicion_flags_from_store, ProcessAnomalyDetector, DEFAULT_PROLIFIC_PARENT_THRESHOLD,
    DEFAULT_TRUSTED_PATH_PREFIXES,
};
use aw_agents::timeline_narrator::{
    summarize_capture, NoveltySummary, ScoredSuspicion, TimelineNarrator,
};
use aw_agents::{AgentConfig, AgentCtx};
use aw_core::{Bus, MonotonicClock, Source};
use aw_dns::DnsAdapter;
use aw_eslogger::EsLoggerAdapter;
use aw_events::{Event, Reconstructor};
use aw_fsevents::FsEventsAdapter;
use aw_graph::GraphBuilder;
use aw_llm::OllamaClient;
use aw_network::NetworkAdapter;
use aw_process::ProcessAdapter;
use aw_scheduler::{PollConfig, Scheduler};
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
    /// Skip every LLM call: the daemon becomes a pure collector, one-shot
    /// just captures and persists. No Ollama required.
    no_narrate: bool,
    /// Daemon: delete store rows quiescent for longer than this many days,
    /// checked once per hour. 0 disables self-pruning.
    retention_days: u64,
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
            no_narrate: false,
            retention_days: 30,
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
    if args.no_store {
        return None;
    }
    args.store_path.clone().or_else(default_store_path)
}

/// Open the store at `path`, creating parent directories if needed.
/// Returns the open `Store` plus the resolved path (for logging).
fn open_store(path: PathBuf) -> Result<(Store, PathBuf)> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)
            .with_context(|| format!("creating store directory {}", dir.display()))?;
    }
    let store =
        Store::open(&path).with_context(|| format!("opening store at {}", path.display()))?;
    Ok((store, path))
}

fn parse_args() -> Result<Args> {
    let mut args = Args::default();
    let mut iter = std::env::args().skip(1);
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--duration" => {
                let v = iter
                    .next()
                    .context("--duration requires a value (seconds)")?;
                args.duration = Duration::from_secs(
                    v.parse()
                        .context("--duration must be an integer number of seconds")?,
                );
            }
            "--daemon" => args.daemon = true,
            "--tick" => {
                let v = iter.next().context("--tick requires a value (seconds)")?;
                args.tick = Duration::from_secs(
                    v.parse()
                        .context("--tick must be an integer number of seconds")?,
                );
            }
            "--window" => {
                let v = iter.next().context("--window requires a value (seconds)")?;
                args.window = Duration::from_secs(
                    v.parse()
                        .context("--window must be an integer number of seconds")?,
                );
            }
            "--model" => args.model = iter.next().context("--model requires a value")?,
            "--ollama-url" => {
                args.ollama_url = iter.next().context("--ollama-url requires a value")?
            }
            "--store-path" => {
                let v = iter.next().context("--store-path requires a value")?;
                args.store_path = Some(PathBuf::from(v));
            }
            "--no-store" => args.no_store = true,
            "--no-narrate" => args.no_narrate = true,
            "--retention-days" => {
                let v = iter.next().context("--retention-days requires a value")?;
                args.retention_days = v
                    .parse()
                    .context("--retention-days must be an integer (0 disables)")?;
            }
            "--print-launchd-plist" => {
                print_launchd_plist();
                std::process::exit(0);
            }
            "--store-ttl" => {
                let v = iter
                    .next()
                    .context("--store-ttl requires a value (seconds)")?;
                args.store_ttl = Duration::from_secs(
                    v.parse()
                        .context("--store-ttl must be an integer number of seconds")?,
                );
            }
            "-h" | "--help" => {
                print_usage();
                std::process::exit(0);
            }
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
            tick = args.tick.as_secs(),
            window = args.window.as_secs(),
        );
    }
    Ok(args)
}

fn print_usage() {
    eprintln!("usage: aw-mvp [--daemon] [--duration <secs>] [--tick <secs>] [--window <secs>]");
    eprintln!("              [--model <name>] [--ollama-url <url>] [--no-narrate]");
    eprintln!("              [--store-path <path> | --no-store] [--retention-days <n>]");
    eprintln!("              [--print-launchd-plist]");
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
    eprintln!("--no-narrate skips every LLM call (pure collector; no Ollama needed).");
    eprintln!();
    eprintln!("Daemon retention: rows quiescent for --retention-days (default 30)");
    eprintln!("are pruned from the store once per hour. 0 disables.");
    eprintln!();
    eprintln!("--print-launchd-plist writes a LaunchAgent plist to stdout:");
    eprintln!(
        "  aw-mvp --print-launchd-plist > ~/Library/LaunchAgents/com.agentworld.aw-mvp.plist"
    );
    eprintln!("  launchctl load ~/Library/LaunchAgents/com.agentworld.aw-mvp.plist");
    eprintln!();
    eprintln!("Defaults: --duration 30 --tick 60 --window 300 --model gemma3:4b");
    eprintln!("          --ollama-url http://127.0.0.1:11434");
    eprintln!();
    eprintln!("Ctrl-C or SIGTERM stops cleanly in both modes.");
}

/// Emit a launchd LaunchAgent plist for running the daemon as a background
/// service, using the currently-running binary's path. Written to stdout so
/// the user can inspect before installing; instructions go to stderr.
fn print_launchd_plist() {
    let exe = std::env::current_exe()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| "/usr/local/bin/aw-mvp".to_string());
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
    println!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.agentworld.aw-mvp</string>
    <key>ProgramArguments</key>
    <array>
        <string>{exe}</string>
        <string>--daemon</string>
        <string>--no-narrate</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>ProcessType</key>
    <string>Background</string>
    <key>StandardOutPath</key>
    <string>{home}/Library/Logs/agentworld/aw-mvp.log</string>
    <key>StandardErrorPath</key>
    <string>{home}/Library/Logs/agentworld/aw-mvp.err.log</string>
</dict>
</plist>"#
    );
    eprintln!();
    eprintln!("aw-mvp: install with:");
    eprintln!("  mkdir -p ~/Library/Logs/agentworld");
    eprintln!(
        "  aw-mvp --print-launchd-plist > ~/Library/LaunchAgents/com.agentworld.aw-mvp.plist"
    );
    eprintln!("  launchctl load ~/Library/LaunchAgents/com.agentworld.aw-mvp.plist");
    eprintln!("(drop --no-narrate from the plist if Ollama runs at login and you want narration)");
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
    if args.daemon {
        run_daemon(args).await
    } else {
        run_one_shot(args).await
    }
}

// ============================================================================
// One-shot
// ============================================================================

async fn run_one_shot(args: Args) -> Result<()> {
    eprintln!(
        "aw-mvp: capturing for {}s; model={} url={}",
        args.duration.as_secs(),
        args.model,
        args.ollama_url,
    );

    let (events, source_counts, bus) = capture_for_duration(args.duration).await?;
    eprintln!(
        "aw-mvp: capture done — {} reconstructed events",
        events.len()
    );
    report_capture_health("aw-mvp", &source_counts, &bus);

    let graph = build_graph(&events);

    // Persist the capture (graph + event history) BEFORE any LLM call so an
    // unreachable or slow model can't lose it. `merge_graph` is idempotent:
    // re-run produces no duplicates, just bumps edge counts. The store stays
    // open — narration enrichment (novelty, suspicion flags) reads it below.
    let mut opened_store: Option<(Store, PathBuf)> = None;
    if let Some(path) = resolve_store_path(&args) {
        match open_store(path) {
            Ok((mut store, p)) => {
                match store.merge_graph(&graph) {
                    Ok(report) => eprintln!(
                        "aw-mvp: persisted to {} (nodes +{}/{}, edges +{}/{})",
                        p.display(),
                        report.nodes_inserted,
                        report.nodes_updated,
                        report.edges_inserted,
                        report.edges_updated,
                    ),
                    Err(e) => eprintln!("aw-mvp: store merge failed: {e}"),
                }
                if !events.is_empty() {
                    match store.append_events(&events) {
                        Ok(n) => eprintln!("aw-mvp: appended {n} events to history"),
                        Err(e) => eprintln!("aw-mvp: event append failed: {e}"),
                    }
                }
                opened_store = Some((store, p));
            }
            Err(e) => eprintln!("aw-mvp: could not open store: {e}"),
        }
    }

    if args.no_narrate {
        eprintln!("aw-mvp: --no-narrate — skipping narration and anomaly passes");
        return Ok(());
    }

    let llm = Arc::new(OllamaClient::with_base_url(&args.ollama_url));
    let make_ctx = || {
        AgentCtx::new(
            llm.clone(),
            AgentConfig {
                model: args.model.clone(),
                ..AgentConfig::default()
            },
        )
    };

    // The capture is already durable; from here on LLM failures only cost
    // narration, never data.
    let mut summary = summarize_capture(&events);
    if let Some((store, _)) = opened_store.as_ref() {
        let from_unix_ns = now_unix_ns().saturating_sub(args.duration.as_nanos() as i64);
        enrich_summary_from_store(&mut summary, store, from_unix_ns);
    }
    let flags_fallback = summary.suspicions.clone();
    eprintln!("aw-mvp: asking {} to narrate...", args.model);
    match TimelineNarrator::new(make_ctx()).run_summary(summary).await {
        Ok(narrative) => println!("{}", narrative.summary),
        Err(e) => {
            eprintln!("aw-mvp: narration failed (is Ollama running and the model pulled?): {e}");
            if !flags_fallback.is_empty() {
                println!("[narration unavailable] anomaly flags this capture:");
                for f in &flags_fallback {
                    println!("  - {f}");
                }
            }
        }
    }

    eprintln!(
        "aw-mvp: anomaly pass over {} processes, {} edges...",
        graph.processes.len(),
        graph.edges.len(),
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
    for ev in events {
        builder.on_event(ev);
    }
    builder.build()
}

async fn capture_for_duration(
    duration: Duration,
) -> Result<(Vec<Event>, HashMap<Source, u64>, Bus)> {
    let clock = Arc::new(MonotonicClock::new());
    let (bus, mut rx) = Bus::channel();
    let mut scheduler = build_scheduler(clock.clone(), bus.clone());
    let mut recon = Reconstructor::new();
    let mut events: Vec<Event> = Vec::new();
    let mut source_counts: HashMap<Source, u64> = HashMap::new();
    let deadline = tokio::time::sleep(duration);
    tokio::pin!(deadline);

    loop {
        tokio::select! {
            biased;
            signal = shutdown_signal() => {
                eprintln!("aw-mvp: {signal} — finishing early");
                break;
            }
            _ = &mut deadline => break,
            maybe = rx.recv() => match maybe {
                Some(obs) => {
                    *source_counts.entry(obs.source).or_insert(0) += 1;
                    for ev in recon.process(&obs) { events.push(ev); }
                }
                None => break,
            },
        }
    }

    scheduler.shutdown();
    Ok((events, source_counts, bus))
}

/// Every Layer 1 source category, with its snake_case display name. Used to
/// spot sources that produced *nothing* — on macOS that usually means a
/// missing permission, not a quiet system.
const ALL_SOURCES: [(&str, Source); 5] = [
    ("file_system", Source::FileSystem),
    ("process", Source::Process),
    ("network", Source::Network),
    ("window", Source::Window),
    ("system", Source::System),
];

/// One stderr line of per-source observation counts, plus a warning naming
/// any source that stayed completely silent.
fn report_capture_health(prefix: &str, counts: &HashMap<Source, u64>, bus: &Bus) {
    let mut parts = Vec::new();
    let mut silent = Vec::new();
    for (name, src) in ALL_SOURCES {
        let n = counts.get(&src).copied().unwrap_or(0);
        if n == 0 {
            silent.push(name);
        }
        parts.push(format!("{name}={n}"));
    }
    let dropped = bus.dropped_total();
    if dropped > 0 {
        parts.push(format!("dropped={dropped}"));
    }
    eprintln!("{prefix}: source health: {}", parts.join(" "));
    if dropped > 0 {
        eprintln!(
            "{prefix}: warning — the bus dropped {dropped} observations (consumer \
             lag); the scheduler will widen poll intervals under sustained pressure.",
        );
    }
    if !silent.is_empty() {
        eprintln!(
            "{prefix}: warning — no observations from: {}. On macOS this usually \
             means a missing permission (Window needs Accessibility for the \
             frontmost-app poll; Endpoint Security events need sudo).",
            silent.join(", "),
        );
    }
}

/// Resolve when the process is asked to stop: SIGINT (Ctrl-C) or SIGTERM
/// (launchd / `kill`). Returns the signal name for logging. SIGTERM matters
/// for daemon use — launchd stops services with it, and without a handler
/// the final store merge would be lost.
async fn shutdown_signal() -> &'static str {
    use tokio::signal::unix::{signal, SignalKind};
    let mut term = match signal(SignalKind::terminate()) {
        Ok(s) => s,
        Err(e) => {
            // Registration only fails in exotic environments; degrade to
            // Ctrl-C-only rather than refusing to run.
            tracing::warn!("aw-mvp: SIGTERM handler unavailable ({e}); handling Ctrl-C only");
            let _ = tokio::signal::ctrl_c().await;
            return "Ctrl-C";
        }
    };
    tokio::select! {
        _ = tokio::signal::ctrl_c() => "Ctrl-C",
        _ = term.recv() => "SIGTERM",
    }
}

/// Advisory single-instance lock next to the store. Two daemons appending to
/// the same `world.db` would duplicate event history, so the second refuses
/// to start. `flock` is released by the kernel when the process exits —
/// including on crash — so there are no stale locks to clean up.
struct InstanceLock {
    _file: std::fs::File,
}

fn acquire_instance_lock(store_path: &std::path::Path) -> Result<InstanceLock> {
    use std::os::fd::AsRawFd;
    let lock_path = store_path.with_extension("lock");
    let file = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .open(&lock_path)
        .with_context(|| format!("creating lock file {}", lock_path.display()))?;
    let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if rc != 0 {
        anyhow::bail!(
            "another aw-mvp daemon is already writing {} (lock {} is held); \
             stop it first or use a different --store-path",
            store_path.display(),
            lock_path.display(),
        );
    }
    Ok(InstanceLock { _file: file })
}

/// The store's history must predate the narration window by at least this
/// long before "never seen before" claims are made — with less history the
/// baseline is cold and everything would falsely read as new.
const NOVELTY_MIN_BASELINE_NS: i64 = 30 * 60 * 1_000_000_000;

/// Store-backed enrichment shared by daemon ticks and one-shot runs: mark
/// what in `[from_unix_ns, now]` was seen for the first time ever, and append
/// the rule-based lineage/path/fan-out suspicion flags for the same window.
/// Failures degrade to an unenriched summary with a stderr note — narration
/// must never be lost to an enrichment query.
fn enrich_summary_from_store(
    summary: &mut aw_agents::timeline_narrator::CaptureSummary,
    store: &Store,
    from_unix_ns: i64,
) {
    match store.novel_since(from_unix_ns) {
        Ok(report) => {
            let cold = report.oldest_first_seen_unix_ns.map_or(true, |oldest| {
                oldest > from_unix_ns - NOVELTY_MIN_BASELINE_NS
            });
            summary.novelty = Some(NoveltySummary::from_report(&report, cold));
        }
        Err(e) => eprintln!("aw-mvp: novelty query failed: {e}"),
    }
    match suspicion_flags_from_store(
        store,
        from_unix_ns,
        DEFAULT_TRUSTED_PATH_PREFIXES,
        DEFAULT_PROLIFIC_PARENT_THRESHOLD,
    ) {
        Ok(flags) => summary.suspicions.extend(flags),
        Err(e) => eprintln!("aw-mvp: suspicion queries failed: {e}"),
    }
}

/// Cap on suspicion lines fed to the narrator. Mirrors the narrator's own
/// `MAX_EVENT_SUSPICIONS`.
const MAX_SUSPICIONS: usize = 8;

/// Score the window against the machine baseline and fold the existing
/// rule-based flags in underneath: scored anomalies keep their scores, rule
/// flags not superseded by an identical scored line join at a nominal 1.0,
/// and the result is sorted descending and capped. `suspicions` is rewritten
/// in the same order so the no-LLM fallback printer stays consistent.
fn apply_scored_suspicions(
    summary: &mut aw_agents::timeline_narrator::CaptureSummary,
    engine: &BaselineEngine,
    events: &[Event],
    now_unix_ns: i64,
) {
    let new_scores: Vec<ScoredSuspicion> = engine
        .score_window(events, now_unix_ns)
        .into_iter()
        .map(|a| ScoredSuspicion {
            text: a.text,
            score: a.score,
        })
        .collect();
    merge_scored_suspicions(summary, new_scores);
}

/// Structural (topology) anomaly signal: score the shape difference between
/// two graph snapshots and fold the result into `summary.scored_suspicions`
/// via the same merge/sort/truncate rule `apply_scored_suspicions` uses, so
/// statistical and structural flags share one ranked list.
fn apply_topology_suspicions(
    summary: &mut aw_agents::timeline_narrator::CaptureSummary,
    prev_graph: &aw_graph::Graph,
    curr_graph: &aw_graph::Graph,
) {
    let new_scores: Vec<ScoredSuspicion> = aw_agents::topology::score_snapshot_diff(prev_graph, curr_graph)
        .into_iter()
        .map(|a| ScoredSuspicion {
            text: a.text,
            score: a.score,
        })
        .collect();
    merge_scored_suspicions(summary, new_scores);
}

/// Fold `new_scores` into `summary`'s existing scored/rule-based suspicions:
/// existing scored suspicions and any plain-text rule flags not superseded
/// by an identical scored line join `new_scores` at a nominal 1.0, then the
/// combined list is sorted descending and capped. `suspicions` is rewritten
/// in the same order so the no-LLM fallback printer stays consistent.
fn merge_scored_suspicions(
    summary: &mut aw_agents::timeline_narrator::CaptureSummary,
    mut scored: Vec<ScoredSuspicion>,
) {
    for existing in summary.scored_suspicions.drain(..) {
        if !scored.iter().any(|s| s.text == existing.text) {
            scored.push(existing);
        }
    }
    for f in summary.suspicions.drain(..) {
        if !scored.iter().any(|s| s.text == f) {
            scored.push(ScoredSuspicion {
                text: f,
                score: 1.0,
            });
        }
    }
    scored.sort_by(|a, b| b.score.total_cmp(&a.score));
    scored.truncate(MAX_SUSPICIONS);
    summary.suspicions = scored.iter().map(|s| s.text.clone()).collect();
    summary.scored_suspicions = scored;
}

/// Wall-clock now in unix nanoseconds — the encoding the store uses.
fn now_unix_ns() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as i64)
        .unwrap_or(0)
}

// ============================================================================
// Daemon
// ============================================================================

async fn run_daemon(args: Args) -> Result<()> {
    eprintln!(
        "aw-mvp: daemon mode — tick={}s window={}s model={} url={}",
        args.tick.as_secs(),
        args.window.as_secs(),
        args.model,
        args.ollama_url,
    );
    if args.no_narrate {
        eprintln!("aw-mvp: collector mode (--no-narrate) — no LLM calls will be made");
    } else {
        eprintln!(
            "aw-mvp: Ctrl-C or SIGTERM to stop. First paragraph in ~{}s.",
            args.tick.as_secs()
        );
    }

    // Refuse to run two daemons against the same store: the event history
    // table has no dedup, so concurrent writers would double every event.
    // The lock is advisory and kernel-released on exit or crash. Held for
    // the daemon's whole lifetime.
    let _instance_lock: Option<InstanceLock> = match resolve_store_path(&args) {
        Some(path) => Some(acquire_instance_lock(&path)?),
        None => None,
    };

    let clock = Arc::new(MonotonicClock::new());
    let (bus, rx) = Bus::channel();
    let mut scheduler = build_scheduler(clock.clone(), bus.clone());
    // Staged pipeline: bus drain and Layer 2 reconstruction each run on
    // their own task, so a slow store write below can't stall ingestion.
    let (mut recon_rx, drain_stats, mut stage_handles) = pipeline::spawn(rx);

    // Sliding-window buffer. `mono_ns` on event timestamps is monotonic from
    // process start, so we can evict by `front().mono_ns < cutoff` without
    // wall-clock concerns.
    let mut window: VecDeque<Event> = VecDeque::new();
    let window_ns = args.window.as_nanos() as u64;

    // Events accumulated since the last successful store append; flushed to
    // the durable history table on each tick. Independent of `window`, which
    // evicts by age for the narrator.
    let mut pending_events: Vec<Event> = Vec::new();
    // Per-tick observation counts for the source-health line.
    let mut tick_sources: HashMap<Source, u64> = HashMap::new();

    // Persistent store + in-flight graph builder. The window above feeds the
    // *narrator*; this builder feeds the *store*. They're separate because the
    // narration is short-lived (one paragraph per tick) while the store is the
    // long-lived durable mirror.
    let mut store_and_builder: Option<(Store, GraphBuilder, PathBuf)> =
        match resolve_store_path(&args) {
            Some(path) => match open_store(path) {
                Ok((store, p)) => {
                    eprintln!("aw-mvp: persisting to {}", p.display());
                    // Heartbeat: pid + start time, refreshed every tick, so
                    // `aw-query summary` can say whether a daemon is alive.
                    let _ = store.set_meta("daemon_pid", &std::process::id().to_string());
                    let _ = store.set_meta("daemon_heartbeat_unix_ns", &now_unix_ns().to_string());
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
    let make_ctx = || {
        AgentCtx::new(
            llm.clone(),
            AgentConfig {
                model: args.model.clone(),
                ..AgentConfig::default()
            },
        )
    };

    let mut ticker = tokio::time::interval(args.tick);
    // First tick fires immediately by default; skip it so the first paragraph
    // actually has data to narrate.
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    ticker.tick().await;

    // Hold the in-flight narration's join handle so a slow LLM doesn't block
    // event ingestion AND so we can detect "still running" at the next tick
    // and skip rather than queue. `None` means "no narration running".
    let mut narrating: Option<tokio::task::JoinHandle<()>> = None;

    // Self-pruning: at most once per hour, delete store rows quiescent for
    // longer than --retention-days. `None` means "not yet pruned this run" —
    // the first tick prunes immediately so restarts don't defer cleanup.
    let mut last_prune: Option<std::time::Instant> = None;
    let retention_ns = (args.retention_days as i64) * 86_400 * 1_000_000_000;

    // Machine baseline for anomaly scoring, rebuilt at most hourly (same
    // cadence as pruning). `None` until the first narrated tick with a store.
    let mut baseline: Option<(BaselineEngine, std::time::Instant)> = None;
    // Previous tick's graph snapshot, kept purely to diff structural shape
    // against the current tick (aw_agents::topology::score_snapshot_diff).
    // `None` on the first tick — there's nothing yet to diff against.
    let mut prev_graph_snapshot: Option<aw_graph::Graph> = None;
    let baseline_lookback_days: u32 = match args.retention_days {
        0 => 30,
        d => d.min(30) as u32,
    };

    loop {
        tokio::select! {
            biased;
            signal = shutdown_signal() => {
                eprintln!("aw-mvp: {signal} — stopping daemon");
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
                // This tick's graph snapshot, stashed outside the merge block
                // below so it survives to (a) become `prev_graph_snapshot` for
                // next tick's structural diff, and (b) feed topology scoring
                // against the previous tick's snapshot further down.
                let mut curr_graph_snapshot: Option<aw_graph::Graph> = None;
                if let Some((store, builder, path)) = store_and_builder.as_mut() {
                    let snapshot = builder.snapshot();
                    // rusqlite is synchronous; `block_in_place` keeps a slow
                    // WAL write from stalling the other tasks (drain,
                    // reconstruction) multiplexed on this worker thread.
                    match tokio::task::block_in_place(|| store.merge_graph(&snapshot)) {
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
                    curr_graph_snapshot = Some(snapshot);
                    // Flush the event history. On failure the batch is
                    // dropped with a warning rather than retried — drop is
                    // preferred over unbounded buffering (same philosophy as
                    // the Layer 1 bus).
                    if !pending_events.is_empty() {
                        match tokio::task::block_in_place(|| store.append_events(&pending_events)) {
                            Ok(n) => eprintln!("aw-mvp: appended {n} events to history"),
                            Err(e) => eprintln!(
                                "aw-mvp: event append failed; dropping {} events: {e}",
                                pending_events.len(),
                            ),
                        }
                        pending_events.clear();
                    }

                    // Heartbeat + bus transport counters + hourly retention pass.
                    let _ = store.set_meta("daemon_heartbeat_unix_ns", &now_unix_ns().to_string());
                    if let Ok(stats_json) = serde_json::to_string(&bus.stats()) {
                        let _ = store.set_meta("bus_drops_json", &stats_json);
                    }
                    let prune_due = args.retention_days > 0
                        && last_prune.map(|t| t.elapsed() >= Duration::from_secs(3600)).unwrap_or(true);
                    if prune_due {
                        last_prune = Some(std::time::Instant::now());
                        let cutoff = now_unix_ns().saturating_sub(retention_ns);
                        match store.prune_before(cutoff) {
                            Ok(r) if r.nodes_deleted + r.edges_deleted + r.events_deleted > 0 => {
                                eprintln!(
                                    "aw-mvp: retention pruned {} nodes, {} edges, {} events older than {}d",
                                    r.nodes_deleted, r.edges_deleted, r.events_deleted, args.retention_days,
                                );
                            }
                            Ok(_) => {}
                            Err(e) => eprintln!("aw-mvp: retention prune failed: {e}"),
                        }
                    }
                }

                report_capture_health("aw-mvp", &tick_sources, &bus);
                let pipe_dropped = drain_stats.dropped_total();
                if pipe_dropped > 0 {
                    eprintln!(
                        "aw-mvp: warning — pipeline dropped {pipe_dropped} observations \
                         between drain and reconstruction (reconstructor lag)",
                    );
                }
                tick_sources.clear();

                if args.no_narrate {
                    continue;
                }
                if window.is_empty() {
                    eprintln!("aw-mvp: window empty — nothing to narrate yet");
                    continue;
                }
                // Snapshot the window for the LLM call. Cheap clone — Events
                // are small, and the window itself is bounded.
                let snapshot: Vec<Event> = window.iter().cloned().collect();
                // Aggregate + enrich synchronously (pure Rust + a few indexed
                // SQLite reads — fast); only the LLM call runs in the task.
                // The store was merged just above, so it already reflects
                // everything in this window.
                let mut summary = summarize_capture(&snapshot);
                if let Some((store, _, _)) = store_and_builder.as_ref() {
                    let from_unix_ns = now_unix_ns().saturating_sub(window_ns as i64);
                    enrich_summary_from_store(&mut summary, store, from_unix_ns);

                    // Rebuild the anomaly baseline at most hourly, then score
                    // this window against it. Failures degrade to the plain
                    // rule flags — never block narration.
                    let stale = baseline
                        .as_ref()
                        .map(|(_, at)| at.elapsed() >= Duration::from_secs(3600))
                        .unwrap_or(true);
                    if stale {
                        match tokio::task::block_in_place(|| {
                            BaselineEngine::from_store(store, now_unix_ns(), baseline_lookback_days)
                        }) {
                            Ok(engine) => {
                                if engine.is_cold() {
                                    eprintln!(
                                        "aw-mvp: anomaly baseline still cold — using fixed thresholds",
                                    );
                                }
                                baseline = Some((engine, std::time::Instant::now()));
                            }
                            Err(e) => eprintln!("aw-mvp: baseline rebuild failed: {e}"),
                        }
                    }
                    if let Some((engine, _)) = baseline.as_ref() {
                        apply_scored_suspicions(&mut summary, engine, &snapshot, now_unix_ns());
                    }
                }
                // Structural (topology) anomaly signal: diff this tick's
                // graph shape against last tick's. Folds into the same
                // scored-suspicions list via `apply_topology_suspicions` so
                // the LLM sees one ranked list, not two it must reconcile.
                if let (Some(prev), Some(curr)) = (prev_graph_snapshot.as_ref(), curr_graph_snapshot.as_ref()) {
                    apply_topology_suspicions(&mut summary, prev, curr);
                }
                if let Some(curr) = curr_graph_snapshot {
                    prev_graph_snapshot = Some(curr);
                }
                // The computed flags must survive an LLM outage — a watcher
                // wouldn't go blind just because the narrator lost its voice.
                let flags_fallback = summary.suspicions.clone();
                let n = snapshot.len();
                let ctx = make_ctx();
                narrating = Some(tokio::spawn(async move {
                    let started = std::time::Instant::now();
                    match TimelineNarrator::new(ctx).live().run_summary(summary).await {
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
                        Err(e) => {
                            eprintln!("aw-mvp: narration failed: {e}");
                            if !flags_fallback.is_empty() {
                                println!("[narration unavailable] anomaly flags this window:");
                                for f in &flags_fallback {
                                    println!("  - {f}");
                                }
                                println!();
                            }
                        }
                    }
                }));
            }
            maybe = recon_rx.recv() => match maybe {
                Some(out) => {
                    *tick_sources.entry(out.obs.source).or_insert(0) += 1;
                    // Also feed the raw observation to the graph builder so
                    // app-focus intervals (which derive from `Window` source
                    // observations, not Layer 2 events) get captured.
                    if let Some((_, builder, _)) = store_and_builder.as_mut() {
                        builder.on_observation(&out.obs);
                    }
                    for ev in out.events {
                        if let Some((_, builder, _)) = store_and_builder.as_mut() {
                            builder.on_event(&ev);
                        }
                        if store_and_builder.is_some() {
                            pending_events.push(ev.clone());
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
    // Stop the pipeline stages. In-flight observations may be lost — per
    // §8.3 that is acceptable; everything already consumed is merged below.
    for h in stage_handles.drain(..) {
        h.abort();
    }

    // Final merge so the events ingested since the last tick aren't lost on
    // Ctrl-C. Safe to re-run because merge is idempotent.
    if let Some((store, builder, path)) = store_and_builder.as_mut() {
        let snapshot = builder.snapshot();
        match store.merge_graph(&snapshot) {
            Ok(report) => eprintln!(
                "aw-mvp: final merge to {} (nodes +{}/{}, edges +{}/{})",
                path.display(),
                report.nodes_inserted,
                report.nodes_updated,
                report.edges_inserted,
                report.edges_updated,
            ),
            Err(e) => eprintln!("aw-mvp: final store merge failed: {e}"),
        }
        if !pending_events.is_empty() {
            match store.append_events(&pending_events) {
                Ok(n) => eprintln!("aw-mvp: appended final {n} events to history"),
                Err(e) => eprintln!("aw-mvp: final event append failed: {e}"),
            }
        }
        // Clear the pid so `aw-query summary` reports a clean stop instead
        // of a stale-looking heartbeat. Crashes skip this — that's exactly
        // the case where a stale heartbeat is the honest signal.
        let _ = store.set_meta("daemon_pid", "");
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
    // Stream sources ignore poll config.
    scheduler.register(FsEventsAdapter::new());
    scheduler.register(EsLoggerAdapter::new());
    scheduler.register(DnsAdapter::new());
    // Per-source cadence: expensive full-table snapshots at 1s, the cheap
    // frontmost-app diff at 500ms, slow-moving system stats at 5s. Each may
    // widen up to 8x its base under sustained bus-drop pressure.
    scheduler.register_with(
        ProcessAdapter::new(),
        PollConfig::new(Duration::from_secs(1)),
    );
    scheduler.register_with(
        NetworkAdapter::new(),
        PollConfig::new(Duration::from_secs(1)),
    );
    scheduler.register_with(
        WindowAdapter::new(),
        PollConfig::new(Duration::from_millis(500)),
    );
    scheduler.register_with(
        SystemAdapter::new(),
        PollConfig::new(Duration::from_secs(5)),
    );
    scheduler
}
