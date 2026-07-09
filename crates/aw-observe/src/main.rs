//! `aw-observe` — wires every Layer 1 adapter into the observation bus and
//! runs the Layer 2 `Reconstructor` in-process.
//!
//! Default output (stdout): NDJSON of canonical Layer 2 events.
//! With `--raw`: NDJSON of both Layer 1 observations and Layer 2 events,
//! interleaved. Distinguishable by `source` (observations) vs `kind` (events).
//!
//! `--duration <secs>` stops after a timed capture instead of waiting for
//! Ctrl-C; `--out <path>` writes to a file instead of stdout. Together they
//! make unattended trace capture a single command:
//!
//!     aw-observe --raw --duration 60 --out trace.ndjson

use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use aw_core::{Bus, MonotonicClock, Source};
use aw_dns::DnsAdapter;
use aw_eslogger::EsLoggerAdapter;
use aw_events::Reconstructor;
use aw_fsevents::FsEventsAdapter;
use aw_network::NetworkAdapter;
use aw_process::ProcessAdapter;
use aw_scheduler::Scheduler;
use aw_system::SystemAdapter;
use aw_window::WindowAdapter;

struct Args {
    raw: bool,
    /// Stop after this long; `None` runs until Ctrl-C.
    duration: Option<Duration>,
    /// Write NDJSON here instead of stdout.
    out: Option<PathBuf>,
}

fn parse_args() -> Result<Args> {
    let mut args = Args {
        raw: false,
        duration: None,
        out: None,
    };
    let mut iter = std::env::args().skip(1);
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--raw" => args.raw = true,
            "--duration" => {
                let v = iter
                    .next()
                    .context("--duration requires a value (seconds)")?;
                let secs: u64 = v
                    .parse()
                    .context("--duration must be an integer number of seconds")?;
                args.duration = Some(Duration::from_secs(secs));
            }
            "--out" => {
                let v = iter.next().context("--out requires a path")?;
                args.out = Some(PathBuf::from(v));
            }
            "-h" | "--help" => {
                eprintln!("usage: aw-observe [--raw] [--duration <secs>] [--out <path>]");
                eprintln!(
                    "  default: emit Layer 2 canonical events (NDJSON) to stdout until Ctrl-C"
                );
                eprintln!("  --raw:            also interleave Layer 1 observations");
                eprintln!("  --duration <s>:   stop after a timed capture");
                eprintln!("  --out <path>:     write NDJSON to a file instead of stdout");
                std::process::exit(0);
            }
            other => anyhow::bail!("unknown argument: {other}"),
        }
    }
    Ok(args)
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .init();

    let args = parse_args()?;
    let clock = Arc::new(MonotonicClock::new());
    let (bus, mut rx) = Bus::channel();

    let mut scheduler = Scheduler::new(clock.clone(), bus.clone(), Duration::from_secs(1));
    scheduler.register(FsEventsAdapter::new());
    scheduler.register(ProcessAdapter::new());
    scheduler.register(NetworkAdapter::new());
    scheduler.register(WindowAdapter::new());
    scheduler.register(SystemAdapter::new());
    scheduler.register(EsLoggerAdapter::new());
    scheduler.register(DnsAdapter::new());

    // BufWriter for files: capture rates make line-by-line unbuffered writes
    // measurable. Stdout keeps the pipe-friendly line-at-a-time behavior.
    let mut sink: Box<dyn Write> = match &args.out {
        Some(path) => Box::new(std::io::BufWriter::new(
            std::fs::File::create(path).with_context(|| format!("creating {}", path.display()))?,
        )),
        None => Box::new(std::io::stdout()),
    };

    tracing::info!(
        "aw-observe running; emitting {} to {}{}. Ctrl-C to stop.",
        if args.raw {
            "observations + events"
        } else {
            "events"
        },
        args.out
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "stdout".into()),
        args.duration
            .map(|d| format!(" for {}s", d.as_secs()))
            .unwrap_or_default(),
    );

    let mut recon = Reconstructor::new();
    let mut source_counts: std::collections::HashMap<Source, u64> =
        std::collections::HashMap::new();

    // A deadline far in the future stands in for "no --duration" so the
    // select arms stay uniform.
    let deadline = tokio::time::sleep(
        args.duration
            .unwrap_or(Duration::from_secs(u32::MAX as u64)),
    );
    tokio::pin!(deadline);

    loop {
        tokio::select! {
            biased;
            _ = tokio::signal::ctrl_c() => {
                tracing::info!("shutdown requested");
                break;
            }
            _ = &mut deadline, if args.duration.is_some() => {
                tracing::info!("capture duration elapsed");
                break;
            }
            maybe = rx.recv() => {
                match maybe {
                    Some(obs) => {
                        *source_counts.entry(obs.source).or_insert(0) += 1;
                        if args.raw {
                            writeln!(sink, "{}", serde_json::to_string(&obs)?)?;
                        }
                        for ev in recon.process(&obs) {
                            writeln!(sink, "{}", serde_json::to_string(&ev)?)?;
                        }
                    }
                    None => break,
                }
            }
        }
    }

    sink.flush()?;
    scheduler.shutdown();

    // Capture health: a source with zero observations usually means a
    // missing macOS permission, not a quiet system — say so explicitly
    // instead of leaving the user with a mysteriously thin trace.
    let all_sources: [(&str, Source); 5] = [
        ("file_system", Source::FileSystem),
        ("process", Source::Process),
        ("network", Source::Network),
        ("window", Source::Window),
        ("system", Source::System),
    ];
    let mut parts = Vec::new();
    let mut silent = Vec::new();
    for (name, src) in all_sources {
        let n = source_counts.get(&src).copied().unwrap_or(0);
        if n == 0 {
            silent.push(name);
        }
        parts.push(format!("{name}={n}"));
    }
    eprintln!("aw-observe: source health: {}", parts.join(" "));
    if !silent.is_empty() {
        eprintln!(
            "aw-observe: warning — no observations from: {}. On macOS this usually \
             means a missing permission (Window needs Accessibility for the \
             frontmost-app poll; Endpoint Security events need sudo).",
            silent.join(", "),
        );
    }
    Ok(())
}
