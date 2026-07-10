//! Staged daemon pipeline: bus drain → Layer 2 reconstruction → consumer.
//!
//! Splits the previously single consumer loop into bounded-queue stages so
//! reconstruction runs on its own task (own core) and a slow store write or
//! graph merge can no longer stall draining the Layer 1 bus.
//!
//! Backpressure policy:
//!
//! - drain → reconstructor uses `try_send` and counts drops — the drain task
//!   must never block, so pressure surfaces as counted observation loss
//!   (the loss class Layer 2's set-diff stages already tolerate).
//! - reconstructor → consumer uses `send().await` — reconstructed events are
//!   expensive to lose, so pressure propagates back to the counted drop
//!   point instead of silently discarding events.
//!
//! Ordering: a single FIFO channel chain and one serial `Reconstructor`
//! preserve per-source observation order. Tick-boundary detection keys off
//! the adapter-assigned `timestamp.mono_ns`, so queueing latency can neither
//! fabricate nor hide the gaps Layer 2 looks for.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use aw_core::Observation;
use aw_events::{Event, Reconstructor};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

/// One observation and every event Layer 2 reconstructed from it. Kept as an
/// atomic unit so the consumer can feed the graph builder observation-first,
/// exactly as the inline loop did.
pub struct ReconOut {
    pub obs: Observation,
    pub events: Vec<Event>,
}

/// Transport counters for the drain stage, shared with the daemon so the
/// health line can report pipeline drops alongside bus drops.
#[derive(Debug, Default)]
pub struct DrainStats {
    pub forwarded: AtomicU64,
    pub dropped: AtomicU64,
}

impl DrainStats {
    pub fn dropped_total(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }
}

/// Capacity of the drain → reconstructor queue.
const DRAIN_QUEUE_CAPACITY: usize = 4096;
/// Capacity of the reconstructor → consumer queue.
const RECON_QUEUE_CAPACITY: usize = 1024;

/// Stage 1: drain the bus receiver into a bounded queue without ever
/// blocking. On a full queue the observation is dropped and counted.
pub fn spawn_drain(
    mut rx: mpsc::Receiver<Observation>,
    tx: mpsc::Sender<Observation>,
    stats: Arc<DrainStats>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        while let Some(obs) = rx.recv().await {
            match tx.try_send(obs) {
                Ok(()) => {
                    stats.forwarded.fetch_add(1, Ordering::Relaxed);
                }
                Err(_) => {
                    stats.dropped.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
    })
}

/// Stage 2: own the `Reconstructor` and run Layer 2 per observation,
/// forwarding `(obs, events)` units. Awaits the downstream send so pressure
/// propagates back to the drain stage's counted drop point.
pub fn spawn_reconstructor(
    mut rx: mpsc::Receiver<Observation>,
    tx: mpsc::Sender<ReconOut>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut recon = Reconstructor::new();
        while let Some(obs) = rx.recv().await {
            let events = recon.process(&obs);
            if tx.send(ReconOut { obs, events }).await.is_err() {
                break;
            }
        }
    })
}

/// Assemble the full chain from a bus receiver. Returns the consumer-side
/// receiver, the drain stats, and the stage handles (abort them on shutdown;
/// in-flight loss at shutdown is acceptable per §8.3).
pub fn spawn(
    bus_rx: mpsc::Receiver<Observation>,
) -> (
    mpsc::Receiver<ReconOut>,
    Arc<DrainStats>,
    Vec<JoinHandle<()>>,
) {
    let stats = Arc::new(DrainStats::default());
    let (drain_tx, drain_rx) = mpsc::channel(DRAIN_QUEUE_CAPACITY);
    let (recon_tx, recon_rx) = mpsc::channel(RECON_QUEUE_CAPACITY);
    let handles = vec![
        spawn_drain(bus_rx, drain_tx, stats.clone()),
        spawn_reconstructor(drain_rx, recon_tx),
    ];
    (recon_rx, stats, handles)
}

#[cfg(test)]
mod tests {
    use super::*;
    use aw_core::{Source, Timestamp};

    /// Process observation matching what `aw-process` emits (same shape as
    /// the aw-events integration-test builders).
    fn obs_process(mono_ms: u64, pid: u32, comm: &str) -> Observation {
        Observation {
            timestamp: Timestamp {
                mono_ns: mono_ms * 1_000_000,
                wall_anchor_ns: 1_700_000_000_000_000_000,
            },
            source: Source::Process,
            pid: Some(pid),
            payload: serde_json::json!({
                "comm": comm,
                "name": comm,
                "ppid": 1u32,
                "uid": 501u32,
                "exec_path": format!("/usr/bin/{comm}"),
                "start_unix_secs": 1_700_000_000u64,
                "status": 2u32,
                "nfiles": 4u32,
            }),
            tags: None,
        }
    }

    /// A synthetic trace with >250ms gaps (tick boundaries) must produce the
    /// identical event list through the staged pipeline as through a bare
    /// `Reconstructor` — golden equivalence.
    #[tokio::test]
    async fn pipeline_matches_bare_reconstructor() {
        // Tick 1 (primes the diff): pids 100, 101. Gap >250ms. Tick 2:
        // pid 101 gone (death), pid 102 new (birth). Gap. Tick 3: flushes
        // tick 2's diff.
        let trace: Vec<Observation> = vec![
            obs_process(0, 100, "alpha"),
            obs_process(1, 101, "beta"),
            obs_process(400, 100, "alpha"),
            obs_process(401, 102, "gamma"),
            obs_process(800, 100, "alpha"),
            obs_process(801, 102, "gamma"),
        ];

        let mut bare = Reconstructor::new();
        let expected: Vec<Event> = trace.iter().flat_map(|o| bare.process(o)).collect();
        assert!(
            expected
                .iter()
                .any(|e| format!("{:?}", e.kind).contains("Birth")),
            "trace should reconstruct at least one birth"
        );

        let (bus_tx, bus_rx) = mpsc::channel(64);
        let (mut recon_rx, stats, handles) = spawn(bus_rx);
        for o in &trace {
            bus_tx.send(o.clone()).await.unwrap();
        }
        drop(bus_tx); // close the chain so the stages drain and exit

        let mut actual: Vec<Event> = Vec::new();
        while let Some(out) = recon_rx.recv().await {
            actual.extend(out.events);
        }
        for h in handles {
            let _ = h.await;
        }

        assert_eq!(stats.dropped_total(), 0);
        assert_eq!(
            serde_json::to_string(&actual).unwrap(),
            serde_json::to_string(&expected).unwrap(),
            "staged pipeline must emit the identical event stream"
        );
    }

    /// The drain stage never blocks: with a stalled reconstructor queue it
    /// counts drops instead.
    #[tokio::test]
    async fn drain_drops_when_downstream_stalls() {
        let stats = Arc::new(DrainStats::default());
        let (bus_tx, bus_rx) = mpsc::channel(64);
        let (drain_tx, _drain_rx_held) = mpsc::channel::<Observation>(2); // tiny, never drained
        let handle = spawn_drain(bus_rx, drain_tx, stats.clone());

        for i in 0..10 {
            bus_tx.send(obs_process(i, 100, "alpha")).await.unwrap();
        }
        drop(bus_tx);
        let _ = handle.await;

        assert_eq!(stats.forwarded.load(Ordering::Relaxed), 2);
        assert_eq!(stats.dropped_total(), 8);
    }
}
