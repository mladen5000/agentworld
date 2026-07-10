//! Layer 1 ingestion scheduler (§5.4).
//!
//! Dispatches each registered `SourceAdapter` according to its declared
//! `SourceBehavior`:
//!
//! - `Stream`   → long-running task (`run_stream`)
//! - `Snapshot` → polled per-source (`poll_snapshot`)
//! - `Diff`     → polled per-source; adapter holds prior state (`poll_diff`)
//!
//! Polling is per-source and adaptive:
//!
//! - Each poll runs in its own spawned task guarded by an in-flight flag, so
//!   a slow poll skips ticks instead of serializing them (drop over block).
//! - Missed ticks are skipped (`MissedTickBehavior::Skip`), never bursted.
//! - Under sustained bus drops the interval widens (up to `max_interval`)
//!   and narrows back once the bus is clean. This is mechanical adaptation
//!   of the *sampling rate*, not semantic rate limiting — by the sampling
//!   invariance rule (§ invariant 2), downstream semantics are unchanged.

use std::sync::Arc;
use std::time::Duration;

use aw_core::{Bus, MonotonicClock, SourceAdapter, SourceBehavior};
use tokio::task::JoinHandle;
use tokio::time::MissedTickBehavior;

/// Per-source polling configuration.
#[derive(Debug, Clone, Copy)]
pub struct PollConfig {
    /// Base poll interval; also the floor the interval narrows back to.
    /// Clamped to ≥ 500ms so widened *or* base polling never dips under the
    /// 250ms gap threshold Layer 2 uses for tick-boundary detection.
    pub interval: Duration,
    /// Ceiling the interval widens to under sustained bus-drop pressure.
    pub max_interval: Duration,
}

/// Floor for any poll interval; see `PollConfig::interval`.
const MIN_POLL_INTERVAL: Duration = Duration::from_millis(500);

/// Consecutive polls-with-drops before the interval doubles.
const WIDEN_AFTER_DIRTY_TICKS: u32 = 3;
/// Consecutive clean polls before the interval halves back toward base.
const NARROW_AFTER_CLEAN_TICKS: u32 = 10;

impl PollConfig {
    pub fn new(interval: Duration) -> Self {
        let interval = interval.max(MIN_POLL_INTERVAL);
        Self {
            interval,
            max_interval: interval * 8,
        }
    }

    pub fn with_max(mut self, max_interval: Duration) -> Self {
        self.max_interval = max_interval.max(self.interval);
        self
    }
}

pub struct Scheduler {
    clock: Arc<MonotonicClock>,
    bus: Bus,
    default_poll: PollConfig,
    handles: Vec<JoinHandle<()>>,
}

impl Scheduler {
    pub fn new(clock: Arc<MonotonicClock>, bus: Bus, poll_interval: Duration) -> Self {
        Self {
            clock,
            bus,
            default_poll: PollConfig::new(poll_interval),
            handles: Vec::new(),
        }
    }

    /// Register and start an adapter with the scheduler's default poll config.
    pub fn register<A: SourceAdapter>(&mut self, adapter: A) {
        let cfg = self.default_poll;
        self.register_with(adapter, cfg);
    }

    /// Register and start an adapter with a per-source poll config. The
    /// scheduler dispatches by the adapter's declared behavior — there is no
    /// other way to drive a source. (`cfg` is ignored for stream sources.)
    pub fn register_with<A: SourceAdapter>(&mut self, adapter: A, cfg: PollConfig) {
        let adapter = Arc::new(adapter);
        let clock = self.clock.clone();
        let bus = self.bus.clone();

        let handle = match adapter.behavior() {
            SourceBehavior::Stream => {
                let a = adapter.clone();
                tokio::spawn(async move {
                    a.run_stream(clock, bus).await;
                })
            }
            SourceBehavior::Snapshot => {
                let a = adapter.clone();
                tokio::spawn(poll_loop(cfg, clock, bus, move |clock, bus| {
                    let a = a.clone();
                    async move { a.poll_snapshot(clock, bus).await }
                }))
            }
            SourceBehavior::Diff => {
                let a = adapter.clone();
                tokio::spawn(poll_loop(cfg, clock, bus, move |clock, bus| {
                    let a = a.clone();
                    async move { a.poll_diff(clock, bus).await }
                }))
            }
        };

        self.handles.push(handle);
    }

    /// Abort all running tasks. The scheduler does not flush — per §8.3,
    /// in-flight observations may be lost and that is acceptable.
    pub fn shutdown(&mut self) {
        for h in self.handles.drain(..) {
            h.abort();
        }
    }
}

impl Drop for Scheduler {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// The per-source polling loop: skip missed ticks, spawn each poll so a slow
/// one can't serialize the next, skip ticks while a poll is in flight, and
/// adapt the interval to bus-drop pressure.
async fn poll_loop<F, Fut>(cfg: PollConfig, clock: Arc<MonotonicClock>, bus: Bus, poll: F)
where
    F: Fn(Arc<MonotonicClock>, Bus) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    let mut cur_interval = cfg.interval;
    let mut ticker = tokio::time::interval(cur_interval);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);

    let mut in_flight: Option<JoinHandle<()>> = None;
    let mut last_dropped = bus.dropped_total();
    let mut dirty_ticks: u32 = 0;
    let mut clean_ticks: u32 = 0;

    loop {
        ticker.tick().await;

        // Skip this tick if the previous poll is still running — the next
        // snapshot burst must stay temporally contiguous for Layer 2's
        // gap-based tick detection, and overlapping polls of the same
        // source would interleave their bursts.
        if let Some(h) = &in_flight {
            if !h.is_finished() {
                continue;
            }
        }
        in_flight = Some(tokio::spawn(poll(clock.clone(), bus.clone())));

        // Load shedding: track bus drops since the previous tick and widen
        // the interval under sustained pressure; narrow back once clean.
        let dropped = bus.dropped_total();
        if dropped > last_dropped {
            dirty_ticks += 1;
            clean_ticks = 0;
        } else {
            clean_ticks += 1;
            dirty_ticks = 0;
        }
        last_dropped = dropped;

        let next_interval = if dirty_ticks >= WIDEN_AFTER_DIRTY_TICKS {
            dirty_ticks = 0;
            (cur_interval * 2).min(cfg.max_interval)
        } else if clean_ticks >= NARROW_AFTER_CLEAN_TICKS {
            clean_ticks = 0;
            (cur_interval / 2).max(cfg.interval)
        } else {
            cur_interval
        };
        if next_interval != cur_interval {
            cur_interval = next_interval;
            ticker = tokio::time::interval(cur_interval);
            ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
            // A fresh interval fires immediately; consume that tick so the
            // new cadence starts after one full period.
            ticker.tick().await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aw_core::{Observation, Source, Timestamp};
    use std::sync::atomic::{AtomicU64, Ordering};

    /// Fake snapshot adapter: counts polls, optionally sleeps, emits one
    /// observation per poll.
    struct FakeSnapshot {
        source: Source,
        polls: Arc<AtomicU64>,
        poll_duration: Duration,
    }

    #[async_trait::async_trait]
    impl SourceAdapter for FakeSnapshot {
        fn source(&self) -> Source {
            self.source
        }
        fn behavior(&self) -> SourceBehavior {
            SourceBehavior::Snapshot
        }
        async fn poll_snapshot(&self, _clock: Arc<MonotonicClock>, bus: Bus) {
            self.polls.fetch_add(1, Ordering::SeqCst);
            if !self.poll_duration.is_zero() {
                tokio::time::sleep(self.poll_duration).await;
            }
            bus.emit(Observation {
                timestamp: Timestamp {
                    mono_ns: 0,
                    wall_anchor_ns: 0,
                },
                source: self.source,
                pid: None,
                payload: serde_json::json!({ "kind": "fake" }),
                tags: None,
            });
        }
    }

    #[tokio::test(start_paused = true)]
    async fn per_source_intervals_poll_proportionally() {
        let (bus, mut rx) = Bus::channel();
        let clock = Arc::new(MonotonicClock::new());
        let mut sched = Scheduler::new(clock, bus, Duration::from_secs(1));

        let fast = Arc::new(AtomicU64::new(0));
        let slow = Arc::new(AtomicU64::new(0));
        sched.register_with(
            FakeSnapshot {
                source: Source::Window,
                polls: fast.clone(),
                poll_duration: Duration::ZERO,
            },
            PollConfig::new(Duration::from_millis(500)),
        );
        sched.register_with(
            FakeSnapshot {
                source: Source::System,
                polls: slow.clone(),
                poll_duration: Duration::ZERO,
            },
            PollConfig::new(Duration::from_secs(5)),
        );

        // Keep the bus drained so no drops occur.
        let drain = tokio::spawn(async move { while rx.recv().await.is_some() {} });

        tokio::time::sleep(Duration::from_secs(10)).await;
        sched.shutdown();
        drain.abort();

        let fast_n = fast.load(Ordering::SeqCst);
        let slow_n = slow.load(Ordering::SeqCst);
        // 10s: ~20 fast polls (500ms), ~2-3 slow polls (5s).
        assert!(fast_n >= 15, "fast adapter polled only {fast_n} times");
        assert!(
            (1..=4).contains(&slow_n),
            "slow adapter polled {slow_n} times"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn slow_poll_skips_ticks_and_does_not_block_others() {
        let (bus, mut rx) = Bus::channel();
        let clock = Arc::new(MonotonicClock::new());
        let mut sched = Scheduler::new(clock, bus, Duration::from_secs(1));

        let stuck = Arc::new(AtomicU64::new(0));
        let healthy = Arc::new(AtomicU64::new(0));
        // Each poll of the stuck adapter takes 5s at a 1s interval.
        sched.register_with(
            FakeSnapshot {
                source: Source::Process,
                polls: stuck.clone(),
                poll_duration: Duration::from_secs(5),
            },
            PollConfig::new(Duration::from_secs(1)),
        );
        sched.register_with(
            FakeSnapshot {
                source: Source::Window,
                polls: healthy.clone(),
                poll_duration: Duration::ZERO,
            },
            PollConfig::new(Duration::from_secs(1)),
        );

        let drain = tokio::spawn(async move { while rx.recv().await.is_some() {} });

        tokio::time::sleep(Duration::from_secs(10)).await;
        sched.shutdown();
        drain.abort();

        let stuck_n = stuck.load(Ordering::SeqCst);
        let healthy_n = healthy.load(Ordering::SeqCst);
        // The stuck adapter self-skips while in flight: ~10s / 5s ≈ 2 polls,
        // never the 10 a burst-mode ticker would attempt.
        assert!(
            (1..=4).contains(&stuck_n),
            "stuck adapter polled {stuck_n} times (should self-skip)"
        );
        // The healthy adapter is unaffected by its sibling's slowness.
        assert!(
            healthy_n >= 8,
            "healthy adapter polled only {healthy_n} times"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn sustained_drops_widen_the_interval() {
        // Capacity-1 bus with no consumer: every poll after the first drops.
        let (bus, _rx) = Bus::channel_with_capacity(1);
        let clock = Arc::new(MonotonicClock::new());
        let mut sched = Scheduler::new(clock, bus.clone(), Duration::from_secs(1));

        let polls = Arc::new(AtomicU64::new(0));
        sched.register_with(
            FakeSnapshot {
                source: Source::Process,
                polls: polls.clone(),
                poll_duration: Duration::ZERO,
            },
            PollConfig::new(Duration::from_secs(1)).with_max(Duration::from_secs(8)),
        );

        tokio::time::sleep(Duration::from_secs(30)).await;
        let n = polls.load(Ordering::SeqCst);
        sched.shutdown();

        // At a fixed 1s cadence 30s would give ~30 polls. With widening
        // (1s → 2s → 4s → 8s after each 3 dirty ticks) it must be far fewer.
        assert!(bus.dropped_total() > 0, "expected bus drops");
        assert!(n < 20, "interval never widened: {n} polls in 30s");
    }
}
