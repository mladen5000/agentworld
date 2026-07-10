//! Layer 1 ingestion scheduler (§5.4).
//!
//! Dispatches each registered `SourceAdapter` according to its declared
//! `SourceBehavior`:
//!
//! - `Stream`   → long-running task (`run_stream`)
//! - `Snapshot` → polled at a fixed interval (`poll_snapshot`)
//! - `Diff`     → polled at a fixed interval; adapter holds prior state (`poll_diff`)

use std::sync::Arc;
use std::time::Duration;

use aw_core::{Bus, MonotonicClock, SourceAdapter, SourceBehavior};
use tokio::task::JoinHandle;

pub struct Scheduler {
    clock: Arc<MonotonicClock>,
    bus: Bus,
    poll_interval: Duration,
    handles: Vec<JoinHandle<()>>,
}

impl Scheduler {
    pub fn new(clock: Arc<MonotonicClock>, bus: Bus, poll_interval: Duration) -> Self {
        Self {
            clock,
            bus,
            poll_interval,
            handles: Vec::new(),
        }
    }

    /// Register and start an adapter. The scheduler dispatches by the adapter's
    /// declared behavior — there is no other way to drive a source.
    pub fn register<A: SourceAdapter>(&mut self, adapter: A) {
        let adapter = Arc::new(adapter);
        let clock = self.clock.clone();
        let bus = self.bus.clone();
        let interval = self.poll_interval;

        let handle = match adapter.behavior() {
            SourceBehavior::Stream => {
                let a = adapter.clone();
                tokio::spawn(async move {
                    a.run_stream(clock, bus).await;
                })
            }
            SourceBehavior::Snapshot => {
                let a = adapter.clone();
                tokio::spawn(async move {
                    let mut ticker = tokio::time::interval(interval);
                    loop {
                        ticker.tick().await;
                        a.poll_snapshot(clock.clone(), bus.clone()).await;
                    }
                })
            }
            SourceBehavior::Diff => {
                let a = adapter.clone();
                tokio::spawn(async move {
                    let mut ticker = tokio::time::interval(interval);
                    loop {
                        ticker.tick().await;
                        a.poll_diff(clock.clone(), bus.clone()).await;
                    }
                })
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
