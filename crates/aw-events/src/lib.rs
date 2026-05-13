//! Layer 2 event reconstruction.
//!
//! Consumes `aw_core::Observation`s and produces canonical `Event`s.
//! Per ARCHITECTURE.md §Layer 2, the responsibilities at this layer are
//! per-source compression, temporal windowing, deduplication, behavioral
//! clustering, and cross-source correlation. This crate starts with **only
//! per-source compression**, beginning with process-table snapshot diffing.
//!
//! Topology: a `Reconstructor` owns one stage per source. It is fed
//! observations one at a time via `process(obs)` and returns zero or more
//! events. The library is sync at the surface; the binary wraps it in a
//! tokio task that pumps the Layer 1 bus.
//!
//! What this crate does NOT do (Layer 1 boundary):
//! - It does not ingest raw OS signals. Only `Observation`s are accepted.
//! - It does not infer causality, attribute parents, or detect anomalies.
//!   It only compresses snapshots into birth/death events for now.

pub mod fsevents_coalesce;
pub mod network_lifecycle;
pub mod process_lifecycle;
pub mod window_lifecycle;

use aw_core::{Observation, Source, Timestamp};
use serde::{Deserialize, Serialize};

/// Canonical Layer 2 event. One event = one named, structured behavior.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    pub timestamp: Timestamp,
    pub kind: EventKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    pub payload: serde_json::Value,
}

/// Tagged kind. New variants go here; downstream consumers match on this.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    ProcessBirth,
    ProcessDeath,
    AppFocus,
    ConnectionOpened,
    ConnectionClosed,
    FileChanged,
}

/// The top-level Layer 2 pipeline. Routes each observation to the appropriate
/// per-source stage and collects emitted events.
pub struct Reconstructor {
    process: process_lifecycle::ProcessLifecycle,
    window: window_lifecycle::WindowLifecycle,
    network: network_lifecycle::NetworkLifecycle,
    fsevents: fsevents_coalesce::FsEventsCoalesce,
}

impl Reconstructor {
    pub fn new() -> Self {
        Self {
            process: process_lifecycle::ProcessLifecycle::new(),
            window: window_lifecycle::WindowLifecycle::new(),
            network: network_lifecycle::NetworkLifecycle::new(),
            fsevents: fsevents_coalesce::FsEventsCoalesce::new(),
        }
    }

    /// Feed one Layer 1 observation through the pipeline. Returns any events
    /// produced by stages that consumed it.
    pub fn process(&mut self, obs: &Observation) -> Vec<Event> {
        match obs.source {
            Source::Process => self.process.on_observation(obs),
            Source::Window => self.window.on_observation(obs),
            Source::Network => self.network.on_observation(obs),
            Source::FileSystem => self.fsevents.on_observation(obs),
            _ => Vec::new(),
        }
    }

    /// Force-emit any pending events. Called at scheduler-tick boundaries in
    /// live mode and at EOF in offline mode. Drains both snapshot-diff stages
    /// (for the last in-flight tick) and the fsevents coalescer's idle buffer.
    pub fn on_tick_complete(&mut self, now: Timestamp) -> Vec<Event> {
        let mut events = self.process.on_tick_complete(now);
        events.extend(self.network.on_tick_complete(now));
        events.extend(self.fsevents.flush_all());
        events
    }
}

impl Default for Reconstructor {
    fn default() -> Self { Self::new() }
}
