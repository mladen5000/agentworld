//! `aw-observe` — wires every Layer 1 adapter into the observation bus and
//! runs the Layer 2 `Reconstructor` in-process.
//!
//! Default output (stdout): NDJSON of canonical Layer 2 events.
//! With `--raw`: NDJSON of both Layer 1 observations and Layer 2 events,
//! interleaved. Distinguishable by `source` (observations) vs `kind` (events).

use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use aw_core::{Bus, MonotonicClock};
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
}

fn parse_args() -> Args {
    let mut raw = false;
    for arg in std::env::args().skip(1) {
        match arg.as_str() {
            "--raw" => raw = true,
            "-h" | "--help" => {
                eprintln!("usage: aw-observe [--raw]");
                eprintln!("  default: emit Layer 2 canonical events (NDJSON) to stdout");
                eprintln!("  --raw:   also interleave Layer 1 observations on stdout");
                std::process::exit(0);
            }
            other => {
                eprintln!("aw-observe: unknown argument: {other}");
                std::process::exit(2);
            }
        }
    }
    Args { raw }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .init();

    let args = parse_args();
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

    tracing::info!(
        "aw-observe running; emitting {} on stdout. Ctrl-C to stop.",
        if args.raw { "observations + events" } else { "events" }
    );

    let mut recon = Reconstructor::new();
    let stdout = std::io::stdout();

    loop {
        tokio::select! {
            biased;
            _ = tokio::signal::ctrl_c() => {
                tracing::info!("shutdown requested");
                break;
            }
            maybe = rx.recv() => {
                match maybe {
                    Some(obs) => {
                        use std::io::Write;
                        let mut h = stdout.lock();
                        if args.raw {
                            writeln!(h, "{}", serde_json::to_string(&obs)?)?;
                        }
                        for ev in recon.process(&obs) {
                            writeln!(h, "{}", serde_json::to_string(&ev)?)?;
                        }
                    }
                    None => break,
                }
            }
        }
    }

    scheduler.shutdown();
    Ok(())
}
