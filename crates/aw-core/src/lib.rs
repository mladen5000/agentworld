//! Layer 1 observation contract.
//!
//! See `ARCHITECTURE.md` (sections 4.2, 4.5, "EVENT NORMALIZATION RULES") for
//! the authoritative description. This crate defines only the *shape* of an
//! observation and the transport primitives. It deliberately performs no
//! interpretation, aggregation, or deduplication.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;

/// Source category. Mirrors the whitepaper's source classification model (§4.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Source {
    FileSystem,
    Process,
    Network,
    Window,
    System,
}

impl Source {
    /// All source categories, in `index()` order.
    pub const ALL: [Source; 5] = [
        Source::FileSystem,
        Source::Process,
        Source::Network,
        Source::Window,
        Source::System,
    ];

    /// Stable dense index for per-source counter arrays.
    pub const fn index(self) -> usize {
        match self {
            Source::FileSystem => 0,
            Source::Process => 1,
            Source::Network => 2,
            Source::Window => 3,
            Source::System => 4,
        }
    }
}

/// Source behavior type (§4.4). The scheduler dispatches by this.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceBehavior {
    Stream,
    Snapshot,
    Diff,
}

/// Unified monotonic timestamp: nanoseconds since the clock's wall-clock anchor.
///
/// Combines monotonicity (no jumps from NTP) with a wall-clock-translatable
/// origin. Total ordering within a single source is required (§4.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Timestamp {
    /// Nanoseconds since the clock's wall-clock anchor.
    pub mono_ns: u64,
    /// Wall-clock anchor (unix epoch nanoseconds) for translation. u64 holds
    /// nanoseconds past 1970 through ~2554, ample for any current capture
    /// and round-trips cleanly through serde_json (which doesn't natively
    /// support u128 number deserialization).
    pub wall_anchor_ns: u64,
}

/// Process-aware monotonic clock. Anchors `Instant::now()` against a wall-clock
/// reading at construction so monotonic deltas can be translated to wall time.
#[derive(Debug, Clone)]
pub struct MonotonicClock {
    start: Instant,
    wall_anchor_ns: u64,
}

impl MonotonicClock {
    pub fn new() -> Self {
        // `Duration::as_nanos` returns u128 because it can represent
        // durations longer than u64::MAX nanoseconds; for unix-epoch
        // distances the value comfortably fits in u64.
        let wall_anchor_ns = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| u64::try_from(d.as_nanos()).unwrap_or(u64::MAX))
            .unwrap_or(0);
        Self {
            start: Instant::now(),
            wall_anchor_ns,
        }
    }

    pub fn now(&self) -> Timestamp {
        let elapsed: Duration = self.start.elapsed();
        Timestamp {
            mono_ns: elapsed.as_nanos() as u64,
            wall_anchor_ns: self.wall_anchor_ns,
        }
    }
}

impl Default for MonotonicClock {
    fn default() -> Self {
        Self::new()
    }
}

/// Canonical Layer 1 record. The contract: `(timestamp, source, pid?, payload, tags?)`.
///
/// `payload` is a structured JSON value — never a raw log string (§7).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Observation {
    pub timestamp: Timestamp,
    pub source: Source,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    pub payload: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<serde_json::Value>,
}

/// Per-source transport counters, shared across `Bus` clones. Pure accounting
/// of the channel itself — no interpretation, so Layer-1 legal.
#[derive(Debug, Default)]
struct BusCounters {
    sent: [AtomicU64; 5],
    dropped: [AtomicU64; 5],
}

/// Snapshot of one source's transport counters.
#[derive(Debug, Clone, Serialize)]
pub struct BusSourceStats {
    pub source: Source,
    pub sent: u64,
    pub dropped: u64,
}

/// Observation bus. Layer 1 emits onto this; Layer 2 consumes.
///
/// Bounded: when the consumer falls behind and the channel fills, `emit`
/// drops the observation and counts it — drop is preferred over block (§8.3),
/// and over unbounded memory growth.
#[derive(Debug, Clone)]
pub struct Bus {
    tx: mpsc::Sender<Observation>,
    counters: Arc<BusCounters>,
}

impl Bus {
    /// Default channel capacity. Must comfortably exceed one full snapshot
    /// burst (a busy machine emits ~500 process rows + ~1500 socket rows per
    /// poll tick) so drops only occur under sustained consumer lag.
    pub const DEFAULT_CAPACITY: usize = 16_384;

    pub fn channel() -> (Self, mpsc::Receiver<Observation>) {
        Self::channel_with_capacity(Self::DEFAULT_CAPACITY)
    }

    pub fn channel_with_capacity(capacity: usize) -> (Self, mpsc::Receiver<Observation>) {
        let (tx, rx) = mpsc::channel(capacity);
        (
            Self {
                tx,
                counters: Arc::new(BusCounters::default()),
            },
            rx,
        )
    }

    /// Emit. Drop is preferred over block — per §8.3, Layer 1 must tolerate
    /// loss without semantic corruption. A full channel or a gone receiver
    /// both count as a drop for that source.
    pub fn emit(&self, obs: Observation) {
        let idx = obs.source.index();
        match self.tx.try_send(obs) {
            Ok(()) => {
                self.counters.sent[idx].fetch_add(1, Ordering::Relaxed);
            }
            Err(_) => {
                self.counters.dropped[idx].fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Per-source transport counter snapshot (relaxed ordering).
    pub fn stats(&self) -> Vec<BusSourceStats> {
        Source::ALL
            .iter()
            .map(|&source| {
                let idx = source.index();
                BusSourceStats {
                    source,
                    sent: self.counters.sent[idx].load(Ordering::Relaxed),
                    dropped: self.counters.dropped[idx].load(Ordering::Relaxed),
                }
            })
            .collect()
    }

    /// Total drops across all sources. Cheap; read by the scheduler to detect
    /// sustained overload.
    pub fn dropped_total(&self) -> u64 {
        self.counters
            .dropped
            .iter()
            .map(|c| c.load(Ordering::Relaxed))
            .sum()
    }
}

/// Trait every source adapter implements. The behavior type is declared via
/// `behavior()` and dispatched by the scheduler. The scheduler calls one of
/// `run_stream`, `poll_snapshot`, or `poll_diff` based on that declaration.
#[async_trait::async_trait]
pub trait SourceAdapter: Send + Sync + 'static {
    fn source(&self) -> Source;
    fn behavior(&self) -> SourceBehavior;

    /// Stream sources: long-running task that emits onto the bus until cancelled.
    /// Default implementation panics — only override for `SourceBehavior::Stream`.
    async fn run_stream(&self, _clock: Arc<MonotonicClock>, _bus: Bus) {
        unimplemented!("source {:?} is not a stream source", self.source());
    }

    /// Snapshot sources: called on each tick. Emit zero or more observations.
    async fn poll_snapshot(&self, _clock: Arc<MonotonicClock>, _bus: Bus) {
        unimplemented!("source {:?} is not a snapshot source", self.source());
    }

    /// Diff sources: called on each tick. The adapter holds prior state
    /// internally (interior mutability) and emits only when state changes.
    async fn poll_diff(&self, _clock: Arc<MonotonicClock>, _bus: Bus) {
        unimplemented!("source {:?} is not a diff source", self.source());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn monotonic_clock_is_monotonic() {
        let clock = MonotonicClock::new();
        let a = clock.now();
        std::thread::sleep(Duration::from_millis(1));
        let b = clock.now();
        assert!(b.mono_ns > a.mono_ns);
        assert_eq!(a.wall_anchor_ns, b.wall_anchor_ns);
    }

    #[test]
    fn observation_serializes_deterministically() {
        let obs = Observation {
            timestamp: Timestamp {
                mono_ns: 42,
                wall_anchor_ns: 100,
            },
            source: Source::FileSystem,
            pid: Some(1234),
            payload: serde_json::json!({ "kind": "stub" }),
            tags: None,
        };
        let a = serde_json::to_string(&obs).unwrap();
        let b = serde_json::to_string(&obs).unwrap();
        assert_eq!(a, b);
        // `tags: None` must be omitted (deterministic shape).
        assert!(!a.contains("tags"));
        // `pid: Some(_)` must be present.
        assert!(a.contains("\"pid\":1234"));
    }

    fn stub_obs(source: Source) -> Observation {
        Observation {
            timestamp: Timestamp {
                mono_ns: 1,
                wall_anchor_ns: 1,
            },
            source,
            pid: None,
            payload: serde_json::json!({ "kind": "stub" }),
            tags: None,
        }
    }

    #[tokio::test]
    async fn bounded_bus_drops_on_full_and_counts() {
        let (bus, mut rx) = Bus::channel_with_capacity(2);
        for _ in 0..5 {
            bus.emit(stub_obs(Source::Process));
        }
        // Capacity 2, no consumer running: 2 delivered, 3 dropped.
        assert!(rx.try_recv().is_ok());
        assert!(rx.try_recv().is_ok());
        assert!(rx.try_recv().is_err());

        let stats = bus.stats();
        let proc = stats
            .iter()
            .find(|s| s.source == Source::Process)
            .expect("process stats present");
        assert_eq!(proc.sent, 2);
        assert_eq!(proc.dropped, 3);
        assert_eq!(bus.dropped_total(), 3);
        // Other sources untouched.
        let fs = stats.iter().find(|s| s.source == Source::FileSystem).unwrap();
        assert_eq!(fs.sent, 0);
        assert_eq!(fs.dropped, 0);
    }

    #[tokio::test]
    async fn bus_counters_shared_across_clones() {
        let (bus, _rx) = Bus::channel_with_capacity(1);
        let clone = bus.clone();
        bus.emit(stub_obs(Source::Window));
        clone.emit(stub_obs(Source::Window)); // full → dropped
        assert_eq!(bus.dropped_total(), 1);
        assert_eq!(clone.dropped_total(), 1);
    }

    #[test]
    fn source_index_matches_all_order() {
        for (i, s) in Source::ALL.iter().enumerate() {
            assert_eq!(s.index(), i);
        }
    }
}
