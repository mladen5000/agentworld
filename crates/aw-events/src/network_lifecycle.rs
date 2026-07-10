//! Network connection lifecycle stage: snapshot diff → connection events.
//!
//! `aw-network` emits one observation per active socket per scheduler tick.
//! That stream is repetitive: an established TCP connection appears in every
//! tick until it closes. This stage compresses that into two events per
//! connection: `connection_opened` (first observed) and `connection_closed`
//! (no longer observed).
//!
//! Mirrors `process_lifecycle`'s shape:
//! - Accumulates observations into a "current tick" set.
//! - Gap-based tick boundary detection (250ms between network observations).
//! - First completed tick primes silently to avoid emitting `opened` for every
//!   socket alive at startup.
//!
//! Connection identity: `(proto, local_addr, foreign_addr)`. State
//! (`ESTABLISHED`, `LISTEN`, etc.) is a property, not identity — state
//! changes on the same 5-tuple don't produce close+reopen events.

use std::collections::HashMap;

use aw_core::{Observation, Timestamp};
use serde_json::json;

use crate::{Event, EventKind, SCHEMA_VERSION};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ConnectionKey {
    proto: String,
    local_addr: String,
    foreign_addr: String,
}

#[derive(Debug, Clone)]
struct ConnectionRecord {
    state: Option<String>,
    pid: Option<u32>,
    process_name: Option<String>,
    rxbytes: Option<u64>,
    txbytes: Option<u64>,
    /// First time we observed this `(proto, local, foreign)` tuple. Preserved
    /// across tick rotations so a `connection_completed` event can report the
    /// true open-to-close duration, not just the most recent tick.
    first_seen: Timestamp,
    last_seen: Timestamp,
}

pub struct NetworkLifecycle {
    current: HashMap<ConnectionKey, ConnectionRecord>,
    prior: HashMap<ConnectionKey, ConnectionRecord>,
    primed: bool,
    last_obs_ts: Option<Timestamp>,
}

/// Gap threshold for self-detecting tick boundaries. Well above the intra-burst
/// max (network observations within one tick arrive within ms of each other)
/// and well below the inter-tick interval (~1s for snapshot adapters).
const TICK_GAP_NS: u64 = 250 * 1_000_000;

impl NetworkLifecycle {
    pub fn new() -> Self {
        Self {
            current: HashMap::new(),
            prior: HashMap::new(),
            primed: false,
            last_obs_ts: None,
        }
    }

    pub fn on_observation(&mut self, obs: &Observation) -> Vec<Event> {
        let p = &obs.payload;
        let proto = match p.get("proto").and_then(|v| v.as_str()) {
            Some(s) => s.to_string(),
            None => return Vec::new(),
        };
        let local_addr = match p.get("local_addr").and_then(|v| v.as_str()) {
            Some(s) => s.to_string(),
            None => return Vec::new(),
        };
        let foreign_addr = match p.get("foreign_addr").and_then(|v| v.as_str()) {
            Some(s) => s.to_string(),
            None => return Vec::new(),
        };

        // Tick boundary self-detection.
        let mut events = Vec::new();
        if let Some(prev) = self.last_obs_ts {
            if obs.timestamp.mono_ns.saturating_sub(prev.mono_ns) > TICK_GAP_NS {
                events.extend(self.finalize_tick(prev));
            }
        }

        let key = ConnectionKey {
            proto,
            local_addr,
            foreign_addr,
        };
        // Preserve the original first_seen if we've seen this tuple before
        // either in the current tick (rare — duplicate inside one snapshot)
        // or in the immediately prior tick (the common case).
        let first_seen = self
            .current
            .get(&key)
            .map(|r| r.first_seen)
            .or_else(|| self.prior.get(&key).map(|r| r.first_seen))
            .unwrap_or(obs.timestamp);
        let record = ConnectionRecord {
            state: p.get("state").and_then(|v| v.as_str()).map(String::from),
            pid: obs.pid,
            process_name: p
                .get("process_name")
                .and_then(|v| v.as_str())
                .map(String::from),
            rxbytes: p.get("rxbytes").and_then(|v| v.as_u64()),
            txbytes: p.get("txbytes").and_then(|v| v.as_u64()),
            first_seen,
            last_seen: obs.timestamp,
        };
        self.current.insert(key, record);
        self.last_obs_ts = Some(obs.timestamp);
        events
    }

    /// End-of-input flush. Like `process_lifecycle`, the in-flight tick is
    /// kept; callers in real-time pipelines don't need to call this.
    pub fn on_tick_complete(&mut self, now: Timestamp) -> Vec<Event> {
        self.finalize_tick(now)
    }

    fn finalize_tick(&mut self, now: Timestamp) -> Vec<Event> {
        let mut events = Vec::new();

        if self.primed {
            for (key, rec) in &self.current {
                if !self.prior.contains_key(key) {
                    events.push(opened_event(key, rec));
                }
            }
            for (key, rec) in &self.prior {
                if !self.current.contains_key(key) {
                    events.push(closed_event(key, rec, now));
                    events.push(completed_event(key, rec, now));
                }
            }
        } else {
            self.primed = true;
        }

        self.prior = std::mem::take(&mut self.current);
        events
    }
}

impl Default for NetworkLifecycle {
    fn default() -> Self {
        Self::new()
    }
}

fn opened_event(key: &ConnectionKey, rec: &ConnectionRecord) -> Event {
    Event {
        schema_version: SCHEMA_VERSION,
        timestamp: rec.last_seen,
        kind: EventKind::ConnectionOpened,
        pid: rec.pid,
        payload: json!({
            "proto": key.proto,
            "local_addr": key.local_addr,
            "foreign_addr": key.foreign_addr,
            "state": rec.state,
            "process_name": rec.process_name,
            "rxbytes": rec.rxbytes,
            "txbytes": rec.txbytes,
        }),
    }
}

fn closed_event(key: &ConnectionKey, rec: &ConnectionRecord, now: Timestamp) -> Event {
    Event {
        schema_version: SCHEMA_VERSION,
        timestamp: now,
        kind: EventKind::ConnectionClosed,
        pid: rec.pid,
        payload: json!({
            "proto": key.proto,
            "local_addr": key.local_addr,
            "foreign_addr": key.foreign_addr,
            "state": rec.state,
            "process_name": rec.process_name,
            "rxbytes": rec.rxbytes,
            "txbytes": rec.txbytes,
            "last_seen": rec.last_seen,
        }),
    }
}

/// Synthetic per-connection summary. Emitted *alongside* `ConnectionClosed`
/// at the tick boundary that detects the disappearance, so a single
/// downstream consumer can derive answers like "what was the total bytes
/// exchanged with 1.2.3.4 by `curl` during its 7-second lifetime?" without
/// joining opened/closed pairs.
///
/// `duration_ns` is the wall-time span between `first_seen` and `last_seen`,
/// not the moment of detection. Practically this means the duration is
/// bounded above by the snapshot poll interval (the connection may have
/// actually closed up to one tick before we noticed).
fn completed_event(key: &ConnectionKey, rec: &ConnectionRecord, now: Timestamp) -> Event {
    let duration_ns = rec.last_seen.mono_ns.saturating_sub(rec.first_seen.mono_ns);
    Event {
        schema_version: SCHEMA_VERSION,
        timestamp: now,
        kind: EventKind::ConnectionCompleted,
        pid: rec.pid,
        payload: json!({
            "proto": key.proto,
            "local_addr": key.local_addr,
            "foreign_addr": key.foreign_addr,
            "final_state": rec.state,
            "process_name": rec.process_name,
            "bytes_rx": rec.rxbytes,
            "bytes_tx": rec.txbytes,
            "opened_at": rec.first_seen,
            "closed_at": rec.last_seen,
            "duration_ns": duration_ns,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aw_core::{Source, Timestamp};
    use serde_json::json;

    fn ts(n: u64) -> Timestamp {
        Timestamp {
            mono_ns: n,
            wall_anchor_ns: 0,
        }
    }

    fn netobs(
        proto: &str,
        local: &str,
        foreign: &str,
        state: Option<&str>,
        pid: u32,
        mono: u64,
    ) -> Observation {
        Observation {
            timestamp: ts(mono),
            source: Source::Network,
            pid: Some(pid),
            payload: json!({
                "proto": proto,
                "local_addr": local,
                "foreign_addr": foreign,
                "state": state,
                "process_name": "test",
                "rxbytes": 0u64,
                "txbytes": 0u64,
            }),
            tags: None,
        }
    }

    #[test]
    fn first_tick_emits_nothing() {
        let mut s = NetworkLifecycle::new();
        s.on_observation(&netobs(
            "tcp4",
            "10.0.0.1.50",
            "1.2.3.4.443",
            Some("ESTABLISHED"),
            100,
            1,
        ));
        let events = s.on_tick_complete(ts(2));
        assert!(events.is_empty());
    }

    #[test]
    fn new_connection_emits_opened() {
        let mut s = NetworkLifecycle::new();
        s.on_observation(&netobs(
            "tcp4",
            "10.0.0.1.50",
            "1.2.3.4.443",
            Some("ESTABLISHED"),
            100,
            1,
        ));
        s.on_tick_complete(ts(2));
        // New connection in tick 2.
        s.on_observation(&netobs(
            "tcp4",
            "10.0.0.1.50",
            "1.2.3.4.443",
            Some("ESTABLISHED"),
            100,
            3,
        ));
        s.on_observation(&netobs(
            "tcp4",
            "10.0.0.1.55",
            "9.9.9.9.80",
            Some("ESTABLISHED"),
            200,
            4,
        ));
        let events = s.on_tick_complete(ts(5));
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind, EventKind::ConnectionOpened);
        assert_eq!(events[0].pid, Some(200));
        assert_eq!(
            events[0]
                .payload
                .get("foreign_addr")
                .and_then(|v| v.as_str()),
            Some("9.9.9.9.80")
        );
    }

    #[test]
    fn disappeared_connection_emits_closed_and_completed() {
        let mut s = NetworkLifecycle::new();
        s.on_observation(&netobs("tcp4", "a.1", "b.2", Some("ESTABLISHED"), 100, 1));
        s.on_tick_complete(ts(2));
        // Tick 2: empty.
        let events = s.on_tick_complete(ts(3));
        // One Closed and one Completed, in that order.
        assert_eq!(events.len(), 2, "got {events:?}");
        let kinds: Vec<EventKind> = events.iter().map(|e| e.kind).collect();
        assert_eq!(
            kinds,
            vec![EventKind::ConnectionClosed, EventKind::ConnectionCompleted]
        );
        for e in &events {
            assert_eq!(
                e.payload.get("local_addr").and_then(|v| v.as_str()),
                Some("a.1")
            );
            assert_eq!(e.timestamp, ts(3));
        }
    }

    #[test]
    fn state_change_on_same_tuple_emits_nothing() {
        let mut s = NetworkLifecycle::new();
        s.on_observation(&netobs("tcp4", "a.1", "b.2", Some("SYN_SENT"), 100, 1));
        s.on_tick_complete(ts(2));
        s.on_observation(&netobs("tcp4", "a.1", "b.2", Some("ESTABLISHED"), 100, 3));
        let events = s.on_tick_complete(ts(4));
        assert!(
            events.is_empty(),
            "state change without identity change should not emit; got {events:?}"
        );
    }

    #[test]
    fn self_detects_tick_boundary_from_observation_gap() {
        let mut s = NetworkLifecycle::new();
        let one_sec = 1_000_000_000u64;

        // Tick 1: a.1/b.2 only.
        s.on_observation(&netobs("tcp4", "a.1", "b.2", Some("ESTABLISHED"), 100, 1));

        // Tick 2: a.1/b.2 again. Finalize tick 1 (primes); diff vs nothing → no events.
        let events = s.on_observation(&netobs(
            "tcp4",
            "a.1",
            "b.2",
            Some("ESTABLISHED"),
            100,
            one_sec + 1,
        ));
        assert!(
            events.is_empty(),
            "priming tick should not emit; got {events:?}"
        );

        // Tick 3: a.2/c.3 only. Finalize tick 2 vs tick 1: both had only a.1/b.2 → no events.
        let events = s.on_observation(&netobs(
            "tcp4",
            "a.2",
            "c.3",
            Some("ESTABLISHED"),
            200,
            2 * one_sec + 1,
        ));
        assert!(
            events.is_empty(),
            "tick 2 == tick 1 contents; got {events:?}"
        );

        // Tick 4: a.1/b.2 again. Finalize tick 3 vs tick 2: tick 3 had {a.2/c.3}, tick 2 had {a.1/b.2}.
        // Diff: a.2/c.3 opened, a.1/b.2 closed AND completed.
        let events = s.on_observation(&netobs(
            "tcp4",
            "a.1",
            "b.2",
            Some("ESTABLISHED"),
            100,
            3 * one_sec + 1,
        ));
        let kinds: Vec<EventKind> = events.iter().map(|e| e.kind).collect();
        assert_eq!(kinds.len(), 3, "got {kinds:?}");
        assert!(kinds.contains(&EventKind::ConnectionOpened));
        assert!(kinds.contains(&EventKind::ConnectionClosed));
        assert!(kinds.contains(&EventKind::ConnectionCompleted));
        let opened = events
            .iter()
            .find(|e| e.kind == EventKind::ConnectionOpened)
            .unwrap();
        let closed = events
            .iter()
            .find(|e| e.kind == EventKind::ConnectionClosed)
            .unwrap();
        let completed = events
            .iter()
            .find(|e| e.kind == EventKind::ConnectionCompleted)
            .unwrap();
        assert_eq!(
            opened.payload.get("local_addr").and_then(|v| v.as_str()),
            Some("a.2")
        );
        assert_eq!(
            closed.payload.get("local_addr").and_then(|v| v.as_str()),
            Some("a.1")
        );
        assert_eq!(
            completed.payload.get("local_addr").and_then(|v| v.as_str()),
            Some("a.1")
        );
    }

    #[test]
    fn observation_without_proto_is_dropped() {
        let mut s = NetworkLifecycle::new();
        let mut o = netobs("tcp4", "a", "b", Some("X"), 1, 1);
        o.payload.as_object_mut().unwrap().remove("proto");
        s.on_observation(&o);
        s.on_tick_complete(ts(2));
        assert!(s.prior.is_empty());
    }

    /// Helper that builds a netobs with explicit rxbytes/txbytes so we can
    /// verify the `ConnectionCompleted` payload preserves cumulative byte
    /// counts.
    fn netobs_bytes(local: &str, foreign: &str, rx: u64, tx: u64, mono: u64) -> Observation {
        Observation {
            timestamp: ts(mono),
            source: Source::Network,
            pid: Some(7),
            payload: json!({
                "proto": "tcp4",
                "local_addr": local,
                "foreign_addr": foreign,
                "state": "ESTABLISHED",
                "process_name": "test",
                "rxbytes": rx,
                "txbytes": tx,
            }),
            tags: None,
        }
    }

    #[test]
    fn completed_event_carries_duration_and_byte_deltas() {
        let mut s = NetworkLifecycle::new();
        // Tick 1: first observation of the tuple, at t=1000, 100/50 bytes.
        s.on_observation(&netobs_bytes("a.1", "b.2", 100, 50, 1000));
        s.on_tick_complete(ts(2000));
        // Tick 2: same tuple, more bytes accumulated. Note: nothing emits on
        // this tick because the tuple was already in `prior`.
        s.on_observation(&netobs_bytes("a.1", "b.2", 5000, 200, 3000));
        s.on_tick_complete(ts(4000));
        // Tick 3: tuple absent. Closed + Completed fire at ts=5000.
        let events = s.on_tick_complete(ts(5000));

        let completed = events
            .iter()
            .find(|e| e.kind == EventKind::ConnectionCompleted)
            .expect("ConnectionCompleted should fire");

        let p = &completed.payload;
        assert_eq!(p.get("local_addr").and_then(|v| v.as_str()), Some("a.1"));
        assert_eq!(p.get("foreign_addr").and_then(|v| v.as_str()), Some("b.2"));
        // last_seen.mono_ns - first_seen.mono_ns = 3000 - 1000 = 2000.
        assert_eq!(p.get("duration_ns").and_then(|v| v.as_u64()), Some(2000));
        // bytes_rx/tx are the *last observed* cumulative values.
        assert_eq!(p.get("bytes_rx").and_then(|v| v.as_u64()), Some(5000));
        assert_eq!(p.get("bytes_tx").and_then(|v| v.as_u64()), Some(200));
        // opened_at / closed_at preserved.
        assert_eq!(
            p.get("opened_at")
                .and_then(|v| v.get("mono_ns"))
                .and_then(|v| v.as_u64()),
            Some(1000),
        );
        assert_eq!(
            p.get("closed_at")
                .and_then(|v| v.get("mono_ns"))
                .and_then(|v| v.as_u64()),
            Some(3000),
        );
    }

    #[test]
    fn first_seen_is_preserved_across_many_ticks() {
        let mut s = NetworkLifecycle::new();
        // Tuple first seen at t=100, observed in four consecutive ticks.
        s.on_observation(&netobs("tcp4", "a", "b", Some("ESTABLISHED"), 1, 100));
        s.on_tick_complete(ts(1000));
        s.on_observation(&netobs("tcp4", "a", "b", Some("ESTABLISHED"), 1, 1100));
        s.on_tick_complete(ts(2000));
        s.on_observation(&netobs("tcp4", "a", "b", Some("ESTABLISHED"), 1, 2100));
        s.on_tick_complete(ts(3000));
        s.on_observation(&netobs("tcp4", "a", "b", Some("ESTABLISHED"), 1, 3100));
        s.on_tick_complete(ts(4000));
        // Tick where it vanishes (no obs for this tick at all):
        let events = s.on_tick_complete(ts(5000));
        let completed = events
            .iter()
            .find(|e| e.kind == EventKind::ConnectionCompleted)
            .unwrap_or_else(|| panic!("expected Completed; got {events:?}"));
        // Four rotations should not have lost first_seen.
        assert_eq!(
            completed
                .payload
                .get("opened_at")
                .and_then(|v| v.get("mono_ns"))
                .and_then(|v| v.as_u64()),
            Some(100),
            "first_seen survives rotation; payload={:?}",
            completed.payload,
        );
        // last_seen should be the most recent obs (3100), not the close time (5000).
        assert_eq!(
            completed
                .payload
                .get("closed_at")
                .and_then(|v| v.get("mono_ns"))
                .and_then(|v| v.as_u64()),
            Some(3100),
        );
        assert_eq!(
            completed
                .payload
                .get("duration_ns")
                .and_then(|v| v.as_u64()),
            Some(3000),
        );
    }
}
