//! Process lifecycle stage: snapshot diff → birth/death events.
//!
//! Layer 1's `aw-process` emits one observation per PID per scheduler tick.
//! That's the raw signal Layer 2 must compress. We hold the prior tick's PID
//! set; when a new tick completes, any new PID is a `ProcessBirth` and any
//! missing PID is a `ProcessDeath`.
//!
//! Key identity: `(pid, start_unix_secs)`, not pid alone. macOS reuses PIDs,
//! and the kernel-provided `start_unix_secs` from `BSDInfo` makes the identity
//! stable across reuse. Without it, a fast death-then-birth-with-same-pid
//! would look like the same process never died.
//!
//! Tick boundaries: the stage accumulates observations into a "current tick"
//! set. When `on_tick_complete()` is called (by the bus pump after a quiet
//! period, or by tests deterministically), we compare against the prior set,
//! emit events, and rotate state.
//!
//! First-tick suppression: on cold start, we observe many already-alive PIDs.
//! Treating them as births would flood downstream. The first completed tick
//! seeds prior-state silently; from the second tick onward, diffs are emitted.

use std::collections::HashMap;

use aw_core::{Observation, Timestamp};
use serde_json::json;

use crate::{Event, EventKind, SCHEMA_VERSION};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ProcessKey {
    pid: u32,
    start_unix_secs: u64,
}

#[derive(Debug, Clone)]
struct ProcessRecord {
    comm: Option<String>,
    name: Option<String>,
    ppid: Option<u32>,
    uid: Option<u32>,
    exec_path: Option<String>,
    start_unix_secs: u64,
    last_seen: Timestamp,
}

pub struct ProcessLifecycle {
    /// Records seen at any point in the current tick being assembled.
    current: HashMap<ProcessKey, ProcessRecord>,
    /// Records that were alive as of the previous completed tick.
    prior: HashMap<ProcessKey, ProcessRecord>,
    /// Set once `on_tick_complete` runs for the first time. Suppresses births
    /// for the initial snapshot.
    primed: bool,
    /// Timestamp of the most recent process observation we've ingested. Used
    /// for the gap-based tick boundary heuristic in `on_observation`.
    last_obs_ts: Option<Timestamp>,
}

/// Process observations come in tight bursts (~500 obs in tens of ms), then
/// quiet for ~1s until the next snapshot tick. If consecutive process
/// observations are more than this gap apart, the previous burst is treated
/// as a completed tick. The threshold is well above the intra-burst max we
/// observe (~1ms) and well below the inter-tick gap (~1s).
const TICK_GAP_NS: u64 = 250 * 1_000_000;

impl ProcessLifecycle {
    pub fn new() -> Self {
        Self {
            current: HashMap::new(),
            prior: HashMap::new(),
            primed: false,
            last_obs_ts: None,
        }
    }

    /// Accept one Layer 1 observation. May emit events if this observation
    /// arrives more than `TICK_GAP_NS` after the previous process observation
    /// — that gap indicates the previous tick's snapshot burst is complete
    /// and a new one is starting, so we finalize the diff before accumulating
    /// the new tick.
    pub fn on_observation(&mut self, obs: &Observation) -> Vec<Event> {
        let Some(pid) = obs.pid else {
            return Vec::new();
        };
        let p = &obs.payload;
        let start_unix_secs = match p.get("start_unix_secs").and_then(|v| v.as_u64()) {
            Some(s) => s,
            None => return Vec::new(), // can't form stable identity; drop
        };

        // Self-detect tick boundary based on gaps between *process* observations.
        let mut events = Vec::new();
        if let Some(prev) = self.last_obs_ts {
            if obs.timestamp.mono_ns.saturating_sub(prev.mono_ns) > TICK_GAP_NS {
                events.extend(self.finalize_tick(prev));
            }
        }

        let key = ProcessKey {
            pid,
            start_unix_secs,
        };
        let record = ProcessRecord {
            comm: p.get("comm").and_then(|v| v.as_str()).map(String::from),
            name: p.get("name").and_then(|v| v.as_str()).map(String::from),
            ppid: p
                .get("ppid")
                .and_then(|v| v.as_u64())
                .and_then(|n| u32::try_from(n).ok()),
            uid: p
                .get("uid")
                .and_then(|v| v.as_u64())
                .and_then(|n| u32::try_from(n).ok()),
            exec_path: p
                .get("exec_path")
                .and_then(|v| v.as_str())
                .map(String::from),
            start_unix_secs,
            last_seen: obs.timestamp,
        };
        self.current.insert(key, record);
        self.last_obs_ts = Some(obs.timestamp);
        events
    }

    /// Finalize the current tick: diff against prior and emit events.
    /// Rotates state so the next tick can begin accumulating.
    /// Callers normally don't need this — `on_observation` self-detects ticks
    /// from gaps in the process observation stream. Call this at end-of-input
    /// (EOF for offline replay; shutdown for live runs) to flush the final tick.
    pub fn on_tick_complete(&mut self, now: Timestamp) -> Vec<Event> {
        self.finalize_tick(now)
    }

    fn finalize_tick(&mut self, now: Timestamp) -> Vec<Event> {
        let mut events = Vec::new();

        if self.primed {
            // Births: in current, not in prior.
            for (key, rec) in &self.current {
                if !self.prior.contains_key(key) {
                    events.push(birth_event(key, rec));
                }
            }
            // Deaths: in prior, not in current. Use `now` for the timestamp —
            // we know the death happened *between* the prior tick and this one.
            for (key, rec) in &self.prior {
                if !self.current.contains_key(key) {
                    events.push(death_event(key, rec, now));
                }
            }
        } else {
            self.primed = true;
        }

        // Rotate: current → prior, fresh current.
        self.prior = std::mem::take(&mut self.current);
        events
    }
}

impl Default for ProcessLifecycle {
    fn default() -> Self {
        Self::new()
    }
}

fn birth_event(key: &ProcessKey, rec: &ProcessRecord) -> Event {
    Event {
        schema_version: SCHEMA_VERSION,
        timestamp: rec.last_seen,
        kind: EventKind::ProcessBirth,
        pid: Some(key.pid),
        payload: json!({
            "comm": rec.comm,
            "name": rec.name,
            "ppid": rec.ppid,
            "uid": rec.uid,
            "exec_path": rec.exec_path,
            "start_unix_secs": rec.start_unix_secs,
        }),
    }
}

fn death_event(key: &ProcessKey, rec: &ProcessRecord, now: Timestamp) -> Event {
    Event {
        schema_version: SCHEMA_VERSION,
        timestamp: now,
        kind: EventKind::ProcessDeath,
        pid: Some(key.pid),
        payload: json!({
            "comm": rec.comm,
            "name": rec.name,
            "ppid": rec.ppid,
            "uid": rec.uid,
            "exec_path": rec.exec_path,
            "start_unix_secs": rec.start_unix_secs,
            "last_seen": rec.last_seen,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aw_core::{Observation, Source};
    use serde_json::json;

    fn ts(mono: u64) -> Timestamp {
        Timestamp {
            mono_ns: mono,
            wall_anchor_ns: 0,
        }
    }

    fn obs(pid: u32, start: u64, comm: &str, mono: u64) -> Observation {
        Observation {
            timestamp: ts(mono),
            source: Source::Process,
            pid: Some(pid),
            payload: json!({ "comm": comm, "ppid": 1u32, "uid": 501u32, "start_unix_secs": start }),
            tags: None,
        }
    }

    #[test]
    fn first_tick_emits_nothing() {
        let mut s = ProcessLifecycle::new();
        s.on_observation(&obs(100, 1000, "init", 1));
        s.on_observation(&obs(200, 1001, "shell", 2));
        let events = s.on_tick_complete(ts(3));
        assert!(
            events.is_empty(),
            "first tick must not emit births; got {events:?}"
        );
    }

    #[test]
    fn second_tick_emits_births_for_new_pids() {
        let mut s = ProcessLifecycle::new();
        s.on_observation(&obs(100, 1000, "init", 1));
        s.on_tick_complete(ts(2));

        s.on_observation(&obs(100, 1000, "init", 3));
        s.on_observation(&obs(200, 1001, "new-proc", 4));
        let events = s.on_tick_complete(ts(5));
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind, EventKind::ProcessBirth);
        assert_eq!(events[0].pid, Some(200));
        assert_eq!(
            events[0].payload.get("comm").and_then(|v| v.as_str()),
            Some("new-proc")
        );
    }

    #[test]
    fn missing_pid_in_new_tick_emits_death() {
        let mut s = ProcessLifecycle::new();
        s.on_observation(&obs(100, 1000, "doomed", 1));
        s.on_observation(&obs(200, 1001, "survivor", 2));
        s.on_tick_complete(ts(3));

        // Next tick: 100 is gone.
        s.on_observation(&obs(200, 1001, "survivor", 4));
        let events = s.on_tick_complete(ts(5));
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind, EventKind::ProcessDeath);
        assert_eq!(events[0].pid, Some(100));
        assert_eq!(events[0].timestamp, ts(5));
    }

    #[test]
    fn pid_reuse_distinguished_by_start_time() {
        let mut s = ProcessLifecycle::new();
        s.on_observation(&obs(100, 1000, "old", 1));
        s.on_tick_complete(ts(2));

        // Pid 100 dies, then a new process is born with the same pid but a
        // different start time. Expect both a death AND a birth.
        s.on_observation(&obs(100, 9999, "new-with-same-pid", 3));
        let events = s.on_tick_complete(ts(4));
        let kinds: Vec<EventKind> = events.iter().map(|e| e.kind).collect();
        assert!(kinds.contains(&EventKind::ProcessBirth), "{kinds:?}");
        assert!(kinds.contains(&EventKind::ProcessDeath), "{kinds:?}");
    }

    #[test]
    fn observations_without_start_are_dropped() {
        let mut s = ProcessLifecycle::new();
        let mut o = obs(100, 1000, "init", 1);
        o.payload = json!({ "comm": "no-start" }); // no start_unix_secs
        s.on_observation(&o);
        s.on_tick_complete(ts(2));
        s.on_tick_complete(ts(3));
        // No state to diff, no events.
        assert!(s.prior.is_empty());
    }

    #[test]
    fn observations_without_pid_are_dropped() {
        let mut s = ProcessLifecycle::new();
        let mut o = obs(100, 1000, "init", 1);
        o.pid = None;
        s.on_observation(&o);
        s.on_tick_complete(ts(2));
        assert!(s.prior.is_empty());
    }

    #[test]
    fn self_detects_tick_boundary_from_observation_gap() {
        let mut s = ProcessLifecycle::new();
        // Tick 1: two pids, observations close together (1ns apart).
        s.on_observation(&obs(100, 1000, "init", 1));
        s.on_observation(&obs(200, 1001, "doomed", 2));

        // After a 1-second gap, the next observation is in tick 2. The stage
        // should finalize tick 1 *before* accumulating this obs into tick 2.
        // Pid 200 is absent → death; pid 300 is new → birth (but tick 1 was
        // the priming tick, so nothing emits yet).
        let one_sec_ns = 1_000_000_000u64;
        let events_at_boundary = s.on_observation(&obs(100, 1000, "init", one_sec_ns + 1));
        assert!(events_at_boundary.is_empty(), "priming tick: no events yet");

        // Now in tick 2. Add a new pid to tick 2; tick 2 still being assembled.
        s.on_observation(&obs(300, 1002, "newcomer", one_sec_ns + 2));

        // Another gap → tick 3 starts; tick 2 finalizes against tick 1.
        let events = s.on_observation(&obs(100, 1000, "init", 2 * one_sec_ns + 1));
        // Tick 1 had {100, 200}; tick 2 had {100, 300}. Death: 200. Birth: 300.
        let kinds: Vec<EventKind> = events.iter().map(|e| e.kind).collect();
        assert_eq!(kinds.len(), 2, "got {kinds:?}");
        assert!(kinds.contains(&EventKind::ProcessBirth));
        assert!(kinds.contains(&EventKind::ProcessDeath));
        let death = events
            .iter()
            .find(|e| e.kind == EventKind::ProcessDeath)
            .unwrap();
        let birth = events
            .iter()
            .find(|e| e.kind == EventKind::ProcessBirth)
            .unwrap();
        assert_eq!(death.pid, Some(200));
        assert_eq!(birth.pid, Some(300));
    }
}
