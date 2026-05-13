//! Layer 1 observation contract.
//!
//! See `ARCHITECTURE.md` (sections 4.2, 4.5, "EVENT NORMALIZATION RULES") for
//! the authoritative description. This crate defines only the *shape* of an
//! observation and the transport primitives. It deliberately performs no
//! interpretation, aggregation, or deduplication.

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
        Self { start: Instant::now(), wall_anchor_ns }
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
    fn default() -> Self { Self::new() }
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

/// Observation bus. Layer 1 emits onto this; Layer 2 (future) consumes.
#[derive(Debug, Clone)]
pub struct Bus {
    tx: mpsc::UnboundedSender<Observation>,
}

impl Bus {
    pub fn channel() -> (Self, mpsc::UnboundedReceiver<Observation>) {
        let (tx, rx) = mpsc::unbounded_channel();
        (Self { tx }, rx)
    }

    /// Emit. Drop is preferred over block — per §8.3, Layer 1 must tolerate
    /// loss without semantic corruption.
    pub fn emit(&self, obs: Observation) {
        let _ = self.tx.send(obs);
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
            timestamp: Timestamp { mono_ns: 42, wall_anchor_ns: 100 },
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
}
