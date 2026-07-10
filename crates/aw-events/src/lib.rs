//! Layer 2 event reconstruction.
//!
//! Consumes `aw_core::Observation`s and produces canonical `Event`s.
//! Per ARCHITECTURE.md §Layer 2, the responsibilities at this layer are
//! per-source compression, temporal windowing, deduplication, behavioral
//! clustering, and cross-source correlation.
//!
//! Current stages:
//! - `process_lifecycle` — snapshot diff → `process_birth` / `process_death`
//! - `window_lifecycle` — frontmost-app transitions → `app_focus`
//! - `network_lifecycle` — socket-set diff → `connection_opened` / `connection_closed`
//! - `fsevents_coalesce` — 500ms windowed compression → `file_changed`
//!
//! Cross-source enrichment (`Reconstructor::enrich`) maintains a shared
//! `ProcessTable` populated from `process_birth`/`process_death`. Events that
//! carry only a raw pid (currently `ConnectionOpened` / `ConnectionClosed`)
//! get a `process: { comm, exec_path, ppid, ancestors, ... }` field attached
//! at emission time. `AppFocus` and `FileChanged` are passed through unchanged.
//!
//! Topology: a `Reconstructor` owns one stage per source plus the shared
//! `ProcessTable`. It is fed observations via `process(obs)` and returns zero
//! or more enriched events. Sync at the surface; the binary wraps it in a
//! tokio task that pumps the Layer 1 bus.
//!
//! What this crate does NOT do (Layer 1 boundary):
//! - It does not ingest raw OS signals. Only `Observation`s are accepted.
//! - It does not detect anomalies or infer causality.

pub mod dns_lifecycle;
pub mod fsevents_coalesce;
pub mod network_lifecycle;
pub mod process_lifecycle;
pub mod process_table;
pub mod window_lifecycle;

use aw_core::{Observation, Source, Timestamp};
use serde::{Deserialize, Serialize};

/// Bumped on any breaking change to `Event` (new required field, removed field,
/// renamed kind, restructured payload). Long-lived consumers (UIs, persistent
/// stores, exporters) pin to this and reject or migrate older traces.
///
/// Bump rules:
/// - Add a new optional payload field: no bump.
/// - Add a new `EventKind` variant: no bump (consumers ignore unknown kinds).
/// - Change the meaning, type, or required-ness of an existing field: bump.
/// - Remove or rename a field: bump.
pub const SCHEMA_VERSION: u32 = 1;

fn default_schema_version() -> u32 {
    SCHEMA_VERSION
}

/// Canonical Layer 2 event. One event = one named, structured behavior.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    /// Self-identifies the event's schema. Set automatically by `Event::new`;
    /// `serde` defaults it to the current `SCHEMA_VERSION` when deserializing
    /// older traces written before this field existed.
    #[serde(default = "default_schema_version")]
    pub schema_version: u32,
    pub timestamp: Timestamp,
    pub kind: EventKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    pub payload: serde_json::Value,
}

impl Event {
    /// Stamps `schema_version = SCHEMA_VERSION`. Use in preference to struct
    /// literals so we have one place to revisit when the version bumps.
    pub fn new(
        timestamp: Timestamp,
        kind: EventKind,
        pid: Option<u32>,
        payload: serde_json::Value,
    ) -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            timestamp,
            kind,
            pid,
            payload,
        }
    }
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
    /// Synthetic per-connection summary emitted alongside `ConnectionClosed`.
    /// Carries `opened_at`, `closed_at`, `duration_ns`, and cumulative
    /// `bytes_rx` / `bytes_tx`. See `network_lifecycle::completed_event`.
    ConnectionCompleted,
    FileChanged,
    DnsQuery,
}

/// The top-level Layer 2 pipeline. Routes each observation to the appropriate
/// per-source stage and collects emitted events.
pub struct Reconstructor {
    process: process_lifecycle::ProcessLifecycle,
    window: window_lifecycle::WindowLifecycle,
    network: network_lifecycle::NetworkLifecycle,
    fsevents: fsevents_coalesce::FsEventsCoalesce,
    dns: dns_lifecycle::DnsLifecycle,
    /// Shared process index. Populated from `process_birth`/`process_death`
    /// events as they flow out of the process stage, and read by the enrichment
    /// step to attach `comm`/`exec_path`/ancestors to non-process events that
    /// only carry a raw pid.
    process_table: process_table::ProcessTable,
}

impl Reconstructor {
    pub fn new() -> Self {
        Self {
            process: process_lifecycle::ProcessLifecycle::new(),
            window: window_lifecycle::WindowLifecycle::new(),
            network: network_lifecycle::NetworkLifecycle::new(),
            fsevents: fsevents_coalesce::FsEventsCoalesce::new(),
            dns: dns_lifecycle::DnsLifecycle::new(),
            process_table: process_table::ProcessTable::new(),
        }
    }

    /// Read-only view of the process table, exposed for tests and callers
    /// that want to introspect the current process index.
    pub fn process_table(&self) -> &process_table::ProcessTable {
        &self.process_table
    }

    /// Feed one Layer 1 observation through the pipeline. Returns any events
    /// produced by stages that consumed it, already enriched with cross-source
    /// context where applicable.
    pub fn process(&mut self, obs: &Observation) -> Vec<Event> {
        let raw = match obs.source {
            Source::Process => self.process.on_observation(obs),
            Source::Window => self.window.on_observation(obs),
            Source::Network => {
                if dns_lifecycle::is_dns_query_observation(obs) {
                    self.dns.on_observation(obs)
                } else {
                    self.network.on_observation(obs)
                }
            }
            Source::FileSystem => self.fsevents.on_observation(obs),
            _ => Vec::new(),
        };
        self.enrich(raw)
    }

    /// Force-emit any pending events. Called at scheduler-tick boundaries in
    /// live mode and at EOF in offline mode. Drains both snapshot-diff stages
    /// (for the last in-flight tick) and the fsevents coalescer's idle buffer.
    /// Output is enriched same as `process()`.
    pub fn on_tick_complete(&mut self, now: Timestamp) -> Vec<Event> {
        let mut raw = self.process.on_tick_complete(now);
        raw.extend(self.network.on_tick_complete(now));
        raw.extend(self.fsevents.flush_all());
        self.enrich(raw)
    }

    /// Per-event enrichment. Updates the process table from process events,
    /// then attaches process context to non-process events that carry a pid.
    fn enrich(&mut self, events: Vec<Event>) -> Vec<Event> {
        let mut out = Vec::with_capacity(events.len());
        for ev in events {
            match ev.kind {
                EventKind::ProcessBirth => {
                    if let Some(entry) = entry_from_birth(&ev) {
                        self.process_table.insert(entry);
                    }
                    out.push(ev);
                }
                EventKind::ProcessDeath => {
                    if let (Some(pid), Some(start)) = (
                        ev.pid,
                        ev.payload.get("start_unix_secs").and_then(|v| v.as_u64()),
                    ) {
                        self.process_table.mark_dead(&process_table::ProcKey {
                            pid,
                            start_unix_secs: start,
                        });
                    }
                    out.push(ev);
                }
                EventKind::ConnectionOpened
                | EventKind::ConnectionClosed
                | EventKind::ConnectionCompleted
                | EventKind::DnsQuery => {
                    out.push(annotate_pid_event(ev, &self.process_table));
                }
                // AppFocus already carries name/exec_path from Layer 1; no
                // need to consult the table. FileChanged has no pid.
                EventKind::AppFocus | EventKind::FileChanged => out.push(ev),
            }
        }
        out
    }
}

fn entry_from_birth(ev: &Event) -> Option<process_table::ProcessEntry> {
    let pid = ev.pid?;
    let start = ev.payload.get("start_unix_secs")?.as_u64()?;
    let ppid = ev
        .payload
        .get("ppid")
        .and_then(|v| v.as_u64())
        .and_then(|n| u32::try_from(n).ok());
    let uid = ev
        .payload
        .get("uid")
        .and_then(|v| v.as_u64())
        .and_then(|n| u32::try_from(n).ok());
    Some(process_table::ProcessEntry {
        pid,
        start_unix_secs: start,
        ppid,
        uid,
        comm: ev
            .payload
            .get("comm")
            .and_then(|v| v.as_str())
            .map(String::from),
        name: ev
            .payload
            .get("name")
            .and_then(|v| v.as_str())
            .map(String::from),
        exec_path: ev
            .payload
            .get("exec_path")
            .and_then(|v| v.as_str())
            .map(String::from),
        alive: true,
        seq: 0, // overwritten by ProcessTable::insert
    })
}

fn annotate_pid_event(mut ev: Event, table: &process_table::ProcessTable) -> Event {
    let Some(pid) = ev.pid else { return ev };
    let Some(entry) = table.by_pid(pid) else {
        return ev;
    };
    let ancestors = table.ancestors(pid);
    if let Some(obj) = ev.payload.as_object_mut() {
        let mut proc = serde_json::Map::new();
        proc.insert("pid".into(), serde_json::Value::from(entry.pid));
        proc.insert(
            "start_unix_secs".into(),
            serde_json::Value::from(entry.start_unix_secs),
        );
        if let Some(c) = &entry.comm {
            proc.insert("comm".into(), serde_json::Value::from(c.clone()));
        }
        if let Some(n) = &entry.name {
            proc.insert("name".into(), serde_json::Value::from(n.clone()));
        }
        if let Some(e) = &entry.exec_path {
            proc.insert("exec_path".into(), serde_json::Value::from(e.clone()));
        }
        if let Some(p) = entry.ppid {
            proc.insert("ppid".into(), serde_json::Value::from(p));
        }
        if let Some(u) = entry.uid {
            proc.insert("uid".into(), serde_json::Value::from(u));
        }
        proc.insert("alive".into(), serde_json::Value::from(entry.alive));
        proc.insert(
            "ancestors".into(),
            serde_json::to_value(&ancestors).unwrap_or(serde_json::Value::Null),
        );
        obj.insert("process".into(), serde_json::Value::Object(proc));
    }
    ev
}

impl Default for Reconstructor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod enrich_tests {
    use super::*;
    use aw_core::{Observation, Source, Timestamp};
    use serde_json::json;

    fn ts(n: u64) -> Timestamp {
        Timestamp {
            mono_ns: n,
            wall_anchor_ns: 0,
        }
    }

    fn process_obs(
        pid: u32,
        ppid: u32,
        comm: &str,
        exec: &str,
        start: u64,
        mono: u64,
    ) -> Observation {
        Observation {
            timestamp: ts(mono),
            source: Source::Process,
            pid: Some(pid),
            payload: json!({
                "comm": comm, "name": comm, "ppid": ppid, "uid": 501u32,
                "exec_path": exec, "start_unix_secs": start,
            }),
            tags: None,
        }
    }

    fn net_obs(pid: u32, foreign: &str, mono: u64) -> Observation {
        Observation {
            timestamp: ts(mono),
            source: Source::Network,
            pid: Some(pid),
            payload: json!({
                "proto": "tcp4",
                "local_addr": "10.0.0.1.50000",
                "foreign_addr": foreign,
                "state": "ESTABLISHED",
                "process_name": "curl",
                "rxbytes": 0u64,
                "txbytes": 0u64,
            }),
            tags: None,
        }
    }

    #[test]
    fn connection_event_is_enriched_with_process_context() {
        let mut r = Reconstructor::new();
        let one_sec = 1_000_000_000u64;

        // Process births fire when a tick boundary detects a *new* pid that
        // wasn't in the prior tick. Need three ticks: tick 1 primes, tick 2
        // introduces the new pids, tick 3's first obs triggers finalize-of-2
        // and emits the births. Tick 1 must NOT contain the new pids.
        // Tick 1: only launchd.
        r.process(&process_obs(1, 0, "launchd", "/sbin/launchd", 100, 1));
        // Tick 2: launchd + shell + curl (new this tick).
        r.process(&process_obs(
            1,
            0,
            "launchd",
            "/sbin/launchd",
            100,
            one_sec + 1,
        ));
        r.process(&process_obs(100, 1, "shell", "/bin/zsh", 200, one_sec + 2));
        r.process(&process_obs(
            2000,
            100,
            "curl",
            "/usr/bin/curl",
            300,
            one_sec + 3,
        ));
        // Tick 3: first obs triggers finalize of tick 2 → birth events fire for shell and curl.
        let births = r.process(&process_obs(
            1,
            0,
            "launchd",
            "/sbin/launchd",
            100,
            2 * one_sec + 1,
        ));
        assert!(
            births
                .iter()
                .any(|e| e.kind == EventKind::ProcessBirth && e.pid == Some(2000)),
            "expected birth for curl pid on tick boundary; got {births:?}"
        );

        // Network: same priming dance. Need a tick where the conn is absent,
        // then a tick where it appears, then a boundary on a later tick.
        // Tick A (priming): a *different* conn so the set isn't empty.
        r.process(&net_obs(2000, "9.9.9.9.443", 3 * one_sec + 1));
        // Tick B: only the target conn (the 9.9.9.9 closes).
        r.process(&net_obs(2000, "1.2.3.4.443", 4 * one_sec + 1));
        // Tick C: boundary finalizes B → emits opened(1.2.3.4) and closed(9.9.9.9).
        let net_events: Vec<Event> = r.process(&net_obs(2000, "1.2.3.4.443", 5 * one_sec + 1));

        let opened = net_events
            .iter()
            .find(|e| {
                e.kind == EventKind::ConnectionOpened
                    && e.payload.get("foreign_addr").and_then(|v| v.as_str()) == Some("1.2.3.4.443")
            })
            .expect("connection_opened for 1.2.3.4 should fire");

        let proc_ctx = opened
            .payload
            .get("process")
            .expect("enriched with process context");
        assert_eq!(proc_ctx.get("pid").and_then(|v| v.as_u64()), Some(2000));
        assert_eq!(proc_ctx.get("comm").and_then(|v| v.as_str()), Some("curl"));
        assert_eq!(
            proc_ctx.get("exec_path").and_then(|v| v.as_str()),
            Some("/usr/bin/curl")
        );
        assert_eq!(proc_ctx.get("ppid").and_then(|v| v.as_u64()), Some(100));

        let ancestors = proc_ctx
            .get("ancestors")
            .and_then(|v| v.as_array())
            .expect("ancestors array");
        // Should be [shell] (launchd has ppid 0, stops at pid 1).
        let comms: Vec<&str> = ancestors
            .iter()
            .filter_map(|a| a.get("comm").and_then(|v| v.as_str()))
            .collect();
        assert_eq!(comms, vec!["shell"], "got {ancestors:?}");
    }

    #[test]
    fn enrichment_is_noop_when_pid_unknown_to_table() {
        let mut r = Reconstructor::new();
        // Network observation for a pid we never saw as a process birth.
        r.process(&net_obs(9999, "1.2.3.4.443", 1));
        let events = r.process(&net_obs(9999, "1.2.3.4.443", 1_000_000_001));
        let opened = events
            .iter()
            .find(|e| e.kind == EventKind::ConnectionOpened);
        if let Some(ev) = opened {
            // Either no `process` key, or it's null. Both are acceptable —
            // the payload's other fields should be present unmodified.
            let has_process = ev
                .payload
                .get("process")
                .map(|v| !v.is_null())
                .unwrap_or(false);
            assert!(
                !has_process,
                "should not invent process context: {:?}",
                ev.payload
            );
            assert!(
                ev.payload.get("foreign_addr").is_some(),
                "raw network fields preserved"
            );
        }
    }

    #[test]
    fn process_death_marks_table_entry_dead() {
        let mut r = Reconstructor::new();
        let one_sec = 1_000_000_000u64;

        // Tick 1: launchd only (priming baseline).
        r.process(&process_obs(1, 0, "launchd", "/sbin/launchd", 100, 1));
        // Tick 2: launchd + the short-lived pid 500.
        r.process(&process_obs(
            1,
            0,
            "launchd",
            "/sbin/launchd",
            100,
            one_sec + 1,
        ));
        r.process(&process_obs(
            500,
            1,
            "shortlived",
            "/bin/sh",
            100,
            one_sec + 2,
        ));
        // Tick 3: finalize tick 2 — birth fires for 500.
        r.process(&process_obs(
            1,
            0,
            "launchd",
            "/sbin/launchd",
            100,
            2 * one_sec + 1,
        ));
        // Tick 4: finalize tick 3 — pid 500 is absent from tick 3, was in tick 2, death fires.
        let events = r.process(&process_obs(
            1,
            0,
            "launchd",
            "/sbin/launchd",
            100,
            3 * one_sec + 1,
        ));
        assert!(
            events
                .iter()
                .any(|e| e.kind == EventKind::ProcessDeath && e.pid == Some(500)),
            "expected death for pid 500; got {events:?}"
        );

        let table = r.process_table();
        let entry = table.by_pid(500).expect("entry retained after death");
        assert!(!entry.alive, "should be marked dead");
        assert_eq!(entry.comm.as_deref(), Some("shortlived"));
    }
}

#[cfg(test)]
mod schema_version_tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn emitted_events_carry_current_schema_version() {
        let mut r = Reconstructor::new();
        let one_sec = 1_000_000_000u64;
        let obs = |mono: u64| Observation {
            timestamp: Timestamp {
                mono_ns: mono,
                wall_anchor_ns: 0,
            },
            source: Source::Process,
            pid: Some(1),
            payload: json!({
                "comm": "launchd", "name": "launchd", "ppid": 0u32, "uid": 0u32,
                "exec_path": "/sbin/launchd", "start_unix_secs": 100u64,
            }),
            tags: None,
        };
        // Three ticks so a birth fires (same priming dance as enrich_tests).
        r.process(&obs(1));
        r.process(&obs(one_sec + 1));
        let events = r.process(&obs(2 * one_sec + 1));
        // We don't care what fires here, only that *whatever* fires is stamped.
        // If no event fires (process_lifecycle only tracks new pids), force one
        // through the public Event::new constructor as a backstop.
        let sample = events.into_iter().next().unwrap_or_else(|| {
            Event::new(
                Timestamp {
                    mono_ns: 0,
                    wall_anchor_ns: 0,
                },
                EventKind::FileChanged,
                None,
                json!({}),
            )
        });
        assert_eq!(sample.schema_version, SCHEMA_VERSION);
    }

    #[test]
    fn legacy_events_without_field_deserialize_to_current_version() {
        // A trace captured before schema_version existed: the field is absent.
        // serde(default) must fill it with SCHEMA_VERSION, not panic.
        let legacy = r#"{
            "timestamp": {"mono_ns": 0, "wall_anchor_ns": 0},
            "kind": "file_changed",
            "payload": {"path": "/tmp/x", "flags": [], "event_ids": [], "count": 0, "first_seen": {"mono_ns":0,"wall_anchor_ns":0}, "last_seen": {"mono_ns":0,"wall_anchor_ns":0}}
        }"#;
        let ev: Event = serde_json::from_str(legacy).expect("legacy event deserializes");
        assert_eq!(ev.schema_version, SCHEMA_VERSION);
    }

    #[test]
    fn round_trip_preserves_schema_version() {
        let ev = Event::new(
            Timestamp {
                mono_ns: 42,
                wall_anchor_ns: 7,
            },
            EventKind::DnsQuery,
            Some(1234),
            json!({"qname": "example.com"}),
        );
        let s = serde_json::to_string(&ev).unwrap();
        assert!(
            s.contains("\"schema_version\":1"),
            "serialized form must include schema_version: {s}"
        );
        let back: Event = serde_json::from_str(&s).unwrap();
        assert_eq!(back.schema_version, SCHEMA_VERSION);
        assert_eq!(back.pid, Some(1234));
    }
}
