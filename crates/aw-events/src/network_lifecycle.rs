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

use crate::{Event, EventKind};

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

        let key = ConnectionKey { proto, local_addr, foreign_addr };
        let record = ConnectionRecord {
            state: p.get("state").and_then(|v| v.as_str()).map(String::from),
            pid: obs.pid,
            process_name: p.get("process_name").and_then(|v| v.as_str()).map(String::from),
            rxbytes: p.get("rxbytes").and_then(|v| v.as_u64()),
            txbytes: p.get("txbytes").and_then(|v| v.as_u64()),
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
    fn default() -> Self { Self::new() }
}

fn opened_event(key: &ConnectionKey, rec: &ConnectionRecord) -> Event {
    Event {
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

#[cfg(test)]
mod tests {
    use super::*;
    use aw_core::{Source, Timestamp};
    use serde_json::json;

    fn ts(n: u64) -> Timestamp { Timestamp { mono_ns: n, wall_anchor_ns: 0 } }

    fn netobs(proto: &str, local: &str, foreign: &str, state: Option<&str>, pid: u32, mono: u64) -> Observation {
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
        s.on_observation(&netobs("tcp4", "10.0.0.1.50", "1.2.3.4.443", Some("ESTABLISHED"), 100, 1));
        let events = s.on_tick_complete(ts(2));
        assert!(events.is_empty());
    }

    #[test]
    fn new_connection_emits_opened() {
        let mut s = NetworkLifecycle::new();
        s.on_observation(&netobs("tcp4", "10.0.0.1.50", "1.2.3.4.443", Some("ESTABLISHED"), 100, 1));
        s.on_tick_complete(ts(2));
        // New connection in tick 2.
        s.on_observation(&netobs("tcp4", "10.0.0.1.50", "1.2.3.4.443", Some("ESTABLISHED"), 100, 3));
        s.on_observation(&netobs("tcp4", "10.0.0.1.55", "9.9.9.9.80", Some("ESTABLISHED"), 200, 4));
        let events = s.on_tick_complete(ts(5));
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind, EventKind::ConnectionOpened);
        assert_eq!(events[0].pid, Some(200));
        assert_eq!(events[0].payload.get("foreign_addr").and_then(|v| v.as_str()), Some("9.9.9.9.80"));
    }

    #[test]
    fn disappeared_connection_emits_closed() {
        let mut s = NetworkLifecycle::new();
        s.on_observation(&netobs("tcp4", "a.1", "b.2", Some("ESTABLISHED"), 100, 1));
        s.on_tick_complete(ts(2));
        // Tick 2: empty.
        let events = s.on_tick_complete(ts(3));
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind, EventKind::ConnectionClosed);
        assert_eq!(events[0].payload.get("local_addr").and_then(|v| v.as_str()), Some("a.1"));
        assert_eq!(events[0].timestamp, ts(3));
    }

    #[test]
    fn state_change_on_same_tuple_emits_nothing() {
        let mut s = NetworkLifecycle::new();
        s.on_observation(&netobs("tcp4", "a.1", "b.2", Some("SYN_SENT"), 100, 1));
        s.on_tick_complete(ts(2));
        s.on_observation(&netobs("tcp4", "a.1", "b.2", Some("ESTABLISHED"), 100, 3));
        let events = s.on_tick_complete(ts(4));
        assert!(events.is_empty(), "state change without identity change should not emit; got {events:?}");
    }

    #[test]
    fn self_detects_tick_boundary_from_observation_gap() {
        let mut s = NetworkLifecycle::new();
        let one_sec = 1_000_000_000u64;

        // Tick 1: a.1/b.2 only.
        s.on_observation(&netobs("tcp4", "a.1", "b.2", Some("ESTABLISHED"), 100, 1));

        // Tick 2: a.1/b.2 again. Finalize tick 1 (primes); diff vs nothing → no events.
        let events = s.on_observation(&netobs("tcp4", "a.1", "b.2", Some("ESTABLISHED"), 100, one_sec + 1));
        assert!(events.is_empty(), "priming tick should not emit; got {events:?}");

        // Tick 3: a.2/c.3 only. Finalize tick 2 vs tick 1: both had only a.1/b.2 → no events.
        let events = s.on_observation(&netobs("tcp4", "a.2", "c.3", Some("ESTABLISHED"), 200, 2 * one_sec + 1));
        assert!(events.is_empty(), "tick 2 == tick 1 contents; got {events:?}");

        // Tick 4: a.1/b.2 again. Finalize tick 3 vs tick 2: tick 3 had {a.2/c.3}, tick 2 had {a.1/b.2}.
        // Diff: a.2/c.3 opened, a.1/b.2 closed.
        let events = s.on_observation(&netobs("tcp4", "a.1", "b.2", Some("ESTABLISHED"), 100, 3 * one_sec + 1));
        let kinds: Vec<EventKind> = events.iter().map(|e| e.kind).collect();
        assert_eq!(kinds.len(), 2, "got {kinds:?}");
        assert!(kinds.contains(&EventKind::ConnectionOpened));
        assert!(kinds.contains(&EventKind::ConnectionClosed));
        let opened = events.iter().find(|e| e.kind == EventKind::ConnectionOpened).unwrap();
        let closed = events.iter().find(|e| e.kind == EventKind::ConnectionClosed).unwrap();
        assert_eq!(opened.payload.get("local_addr").and_then(|v| v.as_str()), Some("a.2"));
        assert_eq!(closed.payload.get("local_addr").and_then(|v| v.as_str()), Some("a.1"));
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
}
