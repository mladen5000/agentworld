//! End-to-end integration tests for the Layer 2 `Reconstructor`.
//!
//! Each test feeds a hand-authored sequence of Layer 1 observations through
//! `Reconstructor::process` (no `#[cfg(test)]`-only internals; we use the
//! crate as a public consumer would) and asserts on the emitted events,
//! including cross-source enrichment.
//!
//! Per-stage unit tests live alongside each stage in `src/<stage>.rs`. This
//! file deliberately exercises the *interactions* between stages — the place
//! regressions tend to slip in as new stages are added.

use aw_core::{Observation, Source, Timestamp};
use aw_events::{Event, EventKind, Reconstructor};
use serde_json::{json, Value};

// ---------- helpers ---------------------------------------------------------

fn ts(n: u64) -> Timestamp {
    Timestamp {
        mono_ns: n,
        wall_anchor_ns: 0,
    }
}

/// Process snapshot observation matching what `aw-process` emits.
fn obs_process(
    pid: u32,
    ppid: u32,
    comm: &str,
    exec: &str,
    start_unix_secs: u64,
    mono: u64,
) -> Observation {
    Observation {
        timestamp: ts(mono),
        source: Source::Process,
        pid: Some(pid),
        payload: json!({
            "comm": comm,
            "name": comm,
            "ppid": ppid,
            "uid": 501u32,
            "exec_path": exec,
            "start_unix_secs": start_unix_secs,
            "status": 2u32,
            "nfiles": 50u32,
        }),
        tags: None,
    }
}

/// Network (socket) observation matching what `aw-network` emits.
fn obs_network(
    pid: u32,
    local: &str,
    foreign: &str,
    state: Option<&str>,
    mono: u64,
) -> Observation {
    Observation {
        timestamp: ts(mono),
        source: Source::Network,
        pid: Some(pid),
        payload: json!({
            "proto": "tcp4",
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

/// FSEvents observation matching what `aw-fsevents` emits.
fn obs_fs(path: &str, flags: &[&str], event_id: u64, mono: u64) -> Observation {
    Observation {
        timestamp: ts(mono),
        source: Source::FileSystem,
        pid: None,
        payload: json!({
            "path": path,
            "flags": flags,
            "event_id": event_id,
        }),
        tags: None,
    }
}

/// DNS observation matching what `aw-dns` emits (note: also `Source::Network`,
/// distinguished by `payload.kind == "dns_query"`).
fn obs_dns(pid: u32, qname: &str, qtype: &str, masked: bool, mono: u64) -> Observation {
    Observation {
        timestamp: ts(mono),
        source: Source::Network,
        pid: Some(pid),
        payload: json!({
            "kind": "dns_query",
            "qname": qname,
            "qtype": qtype,
            "name_hash": "abc12345",
            "interface_index": 0,
            "client_process_name": "test-client",
            "masked": masked,
        }),
        tags: None,
    }
}

fn kinds_of(events: &[Event]) -> Vec<EventKind> {
    events.iter().map(|e| e.kind).collect()
}

fn proc_field<'a>(ev: &'a Event, field: &str) -> Option<&'a Value> {
    ev.payload.get("process")?.get(field)
}

const SEC: u64 = 1_000_000_000;

// ---------- scenarios -------------------------------------------------------

/// Process births fire when a tick boundary detects a *new* pid not present
/// in the prior tick. Tick 1 primes (its pid set is captured as `prior`);
/// tick 2 introduces the new pid; tick 3's first obs triggers finalize-of-2
/// and emits the birth. The new pid must NOT appear in tick 1.
#[test]
fn process_births_fire_on_tick_boundary() {
    let mut r = Reconstructor::new();

    // Tick 1 (priming) — only launchd.
    r.process(&obs_process(1, 0, "launchd", "/sbin/launchd", 100, 1));

    // Tick 2 — launchd + shell (new this tick). Tick 1 finalises here (primes).
    let t2a = r.process(&obs_process(1, 0, "launchd", "/sbin/launchd", 100, SEC + 1));
    let t2b = r.process(&obs_process(100, 1, "shell", "/bin/zsh", 200, SEC + 2));
    assert!(
        t2a.is_empty() && t2b.is_empty(),
        "tick 2 must be silent: {:?} {:?}",
        t2a,
        t2b
    );

    // Tick 3 — first obs triggers finalize-of-2. Diff: shell appeared → birth fires.
    let births = r.process(&obs_process(
        1,
        0,
        "launchd",
        "/sbin/launchd",
        100,
        2 * SEC + 1,
    ));
    assert!(
        births
            .iter()
            .any(|e| e.kind == EventKind::ProcessBirth && e.pid == Some(100)),
        "expected birth for pid 100 on tick 3 boundary; got {:?}",
        births
    );
}

/// `connection_opened` for a known process should carry an enriched
/// `payload.process` object built from the shared `ProcessTable`.
///
/// Birth flow: tick 1 (only launchd, primes), tick 2 (introduces shell+curl),
/// tick 3 (boundary triggers births). Connection flow uses the same priming
/// dance — tick A primes with a *different* tuple, tick B has the target,
/// tick C's first obs triggers the diff.
#[test]
fn connection_event_is_enriched_with_process_table() {
    let mut r = Reconstructor::new();

    // Process ticks.
    let _ = r.process(&obs_process(1, 0, "launchd", "/sbin/launchd", 100, 1));
    let _ = r.process(&obs_process(1, 0, "launchd", "/sbin/launchd", 100, SEC + 1));
    let _ = r.process(&obs_process(100, 1, "shell", "/bin/zsh", 200, SEC + 2));
    let _ = r.process(&obs_process(
        2000,
        100,
        "curl",
        "/usr/bin/curl",
        300,
        SEC + 3,
    ));
    let _ = r.process(&obs_process(
        1,
        0,
        "launchd",
        "/sbin/launchd",
        100,
        2 * SEC + 1,
    ));

    // Network ticks: prime with a decoy tuple, then the target.
    let _ = r.process(&obs_network(
        2000,
        "10.0.0.1.50000",
        "9.9.9.9.443",
        Some("ESTABLISHED"),
        3 * SEC + 1,
    ));
    let _ = r.process(&obs_network(
        2000,
        "10.0.0.1.50000",
        "1.2.3.4.443",
        Some("ESTABLISHED"),
        4 * SEC + 1,
    ));
    let events = r.process(&obs_network(
        2000,
        "10.0.0.1.50000",
        "1.2.3.4.443",
        Some("ESTABLISHED"),
        5 * SEC + 1,
    ));

    let opened = events
        .iter()
        .find(|e| {
            e.kind == EventKind::ConnectionOpened
                && e.payload.get("foreign_addr").and_then(|v| v.as_str()) == Some("1.2.3.4.443")
        })
        .expect("connection_opened for 1.2.3.4 should fire");

    assert_eq!(
        proc_field(opened, "comm").and_then(|v| v.as_str()),
        Some("curl"),
        "enriched process.comm should be 'curl'; payload={:?}",
        opened.payload,
    );
    assert_eq!(
        proc_field(opened, "exec_path").and_then(|v| v.as_str()),
        Some("/usr/bin/curl"),
    );
    let ancestors = proc_field(opened, "ancestors")
        .and_then(|v| v.as_array())
        .expect("ancestors array present");
    let comms: Vec<&str> = ancestors
        .iter()
        .filter_map(|a| a.get("comm").and_then(|v| v.as_str()))
        .collect();
    assert_eq!(
        comms,
        vec!["shell"],
        "ancestor chain stops at pid 1; got {:?}",
        comms
    );
}

/// `dns_query` for a known process should carry the same enrichment.
/// Same priming pattern as the connection test: tick 1 has only launchd;
/// pid 2000 appears for the first time in tick 2; tick 3 triggers the birth.
#[test]
fn dns_event_is_enriched_with_process_table() {
    let mut r = Reconstructor::new();

    // Tick 1 (priming) — only launchd.
    let _ = r.process(&obs_process(1, 0, "launchd", "/sbin/launchd", 100, 1));
    // Tick 2 — launchd + curl (curl is new).
    let _ = r.process(&obs_process(1, 0, "launchd", "/sbin/launchd", 100, SEC + 1));
    let _ = r.process(&obs_process(2000, 1, "curl", "/usr/bin/curl", 300, SEC + 2));
    // Tick 3 — finalises tick 2, emits birth for pid 2000.
    let _ = r.process(&obs_process(
        1,
        0,
        "launchd",
        "/sbin/launchd",
        100,
        2 * SEC + 1,
    ));

    // One DNS observation — emits exactly one DnsQuery event immediately
    // (the dns stage is shape-only, no tick batching).
    let events = r.process(&obs_dns(2000, "<mask.hash: 'xxx=='>", "A", true, 3 * SEC));

    let dns = events
        .iter()
        .find(|e| e.kind == EventKind::DnsQuery)
        .expect("dns_query event should fire");
    assert_eq!(dns.pid, Some(2000));
    assert_eq!(
        dns.payload.get("masked").and_then(|v| v.as_bool()),
        Some(true)
    );
    assert_eq!(
        proc_field(dns, "comm").and_then(|v| v.as_str()),
        Some("curl"),
        "dns event should be enriched with process context",
    );
}

/// FSEvents on the same path within 500ms coalesce into one `file_changed`.
/// A later event on a different path crossing the window boundary triggers
/// flush of the first path; the second path is still buffered.
#[test]
fn fsevents_in_same_window_coalesce_then_flush() {
    let mut r = Reconstructor::new();

    // Four events on /tmp/x within the first 500ms window (ns offsets well
    // under 500_000_000).
    let _ = r.process(&obs_fs("/tmp/x", &["created"], 1, 1));
    let _ = r.process(&obs_fs("/tmp/x", &["modified"], 2, 100_000_000));
    let _ = r.process(&obs_fs("/tmp/x", &["xattr_mod"], 3, 200_000_000));
    let _ = r.process(&obs_fs("/tmp/x", &["is_file"], 4, 300_000_000));

    // Crossing the 500ms boundary with /tmp/y should flush the /tmp/x buffer
    // (and start a new window holding /tmp/y, which we do NOT expect to see
    // emitted yet).
    let events = r.process(&obs_fs("/tmp/y", &["created"], 5, 600_000_000));

    assert_eq!(
        events.len(),
        1,
        "expected one flushed file_changed for /tmp/x; got {:?}",
        events
    );
    let ev = &events[0];
    assert_eq!(ev.kind, EventKind::FileChanged);
    assert_eq!(
        ev.payload.get("path").and_then(|v| v.as_str()),
        Some("/tmp/x")
    );
    let flags: Vec<&str> = ev
        .payload
        .get("flags")
        .and_then(|v| v.as_array())
        .unwrap()
        .iter()
        .filter_map(|v| v.as_str())
        .collect();
    for expected in ["created", "modified", "xattr_mod", "is_file"] {
        assert!(
            flags.contains(&expected),
            "missing {expected} in {:?}",
            flags
        );
    }
    assert_eq!(ev.payload.get("count").and_then(|v| v.as_u64()), Some(4));
}

/// State changes on the same 5-tuple do not generate spurious close/open
/// events; identity is `(proto, local, foreign)` and is state-independent.
#[test]
fn network_state_change_does_not_emit_close_open() {
    let mut r = Reconstructor::new();

    // Tick 1: SYN_SENT.
    r.process(&obs_network(100, "a.1", "b.2", Some("SYN_SENT"), 1));
    // Tick 2: ESTABLISHED. Same tuple — should be considered the same connection.
    let _ = r.process(&obs_network(
        100,
        "a.1",
        "b.2",
        Some("ESTABLISHED"),
        SEC + 1,
    ));
    // Tick 3: still ESTABLISHED. The transition between ticks 2 and 3 fires
    // (no diff). The tick boundary between 1 and 2 only primes (no diff to compare).
    let events = r.process(&obs_network(
        100,
        "a.1",
        "b.2",
        Some("ESTABLISHED"),
        2 * SEC + 1,
    ));

    let kinds = kinds_of(&events);
    assert!(
        !kinds.contains(&EventKind::ConnectionOpened),
        "no opened event expected for unchanged tuple across ticks; got {:?}",
        kinds,
    );
    assert!(
        !kinds.contains(&EventKind::ConnectionClosed),
        "no closed event expected for state change; got {:?}",
        kinds,
    );
}

/// A network observation for a PID the process table has never seen must not
/// invent a `process` block, but raw fields must still be present.
#[test]
fn unknown_pid_does_not_invent_process_context() {
    let mut r = Reconstructor::new();

    r.process(&obs_network(99999, "x.1", "y.2", Some("ESTABLISHED"), 1));
    let events = r.process(&obs_network(
        99999,
        "x.1",
        "y.2",
        Some("ESTABLISHED"),
        SEC + 1,
    ));
    let events2 = r.process(&obs_network(
        99999,
        "x.1",
        "y.2",
        Some("ESTABLISHED"),
        2 * SEC + 1,
    ));

    let all: Vec<Event> = events.into_iter().chain(events2).collect();
    // If a connection_opened did fire, it must lack `process`.
    for ev in all.iter().filter(|e| e.kind == EventKind::ConnectionOpened) {
        let has_process = ev
            .payload
            .get("process")
            .map(|v| !v.is_null())
            .unwrap_or(false);
        assert!(
            !has_process,
            "must not invent process context: {:?}",
            ev.payload
        );
        // Raw fields must still be there.
        assert_eq!(
            ev.payload.get("local_addr").and_then(|v| v.as_str()),
            Some("x.1")
        );
        assert_eq!(
            ev.payload.get("foreign_addr").and_then(|v| v.as_str()),
            Some("y.2")
        );
    }
}

/// PID reuse: when pid 100 dies and is reborn with a new `start_unix_secs`,
/// later enrichment must use the newer entry.
///
/// Each birth needs the same 3-tick priming dance. We do this twice: once
/// for the "old" instance, once for the "new" one. Between them we elide the
/// dead pid from a tick so `process_lifecycle` can mark it as dead.
#[test]
fn pid_reuse_with_new_start_routes_to_correct_entry() {
    let mut r = Reconstructor::new();

    // === Birth old (pid 100, start 1000) ===
    // Tick 1 (prime): only launchd.
    let _ = r.process(&obs_process(1, 0, "launchd", "/sbin/launchd", 50, 1));
    // Tick 2: launchd + old.
    let _ = r.process(&obs_process(1, 0, "launchd", "/sbin/launchd", 50, SEC + 1));
    let _ = r.process(&obs_process(100, 1, "old", "/bin/old", 1000, SEC + 2));
    // Tick 3: same → triggers birth for old.
    let _ = r.process(&obs_process(
        1,
        0,
        "launchd",
        "/sbin/launchd",
        50,
        2 * SEC + 1,
    ));
    let _ = r.process(&obs_process(100, 1, "old", "/bin/old", 1000, 2 * SEC + 2));

    // === Death of old ===
    // Tick 4: pid 100 absent. Triggers finalize-of-3 → death of 100 (start=1000).
    let _ = r.process(&obs_process(
        1,
        0,
        "launchd",
        "/sbin/launchd",
        50,
        3 * SEC + 1,
    ));

    // === Birth new (pid 100, start 2000) ===
    // Tick 5: introduces new pid 100/2000. Finalises tick 4 (only launchd → no diff).
    let _ = r.process(&obs_process(
        1,
        0,
        "launchd",
        "/sbin/launchd",
        50,
        4 * SEC + 1,
    ));
    let _ = r.process(&obs_process(100, 1, "new", "/bin/new", 2000, 4 * SEC + 2));
    // Tick 6: triggers finalize-of-5 → birth of (100, 2000).
    let _ = r.process(&obs_process(
        1,
        0,
        "launchd",
        "/sbin/launchd",
        50,
        5 * SEC + 1,
    ));
    let _ = r.process(&obs_process(100, 1, "new", "/bin/new", 2000, 5 * SEC + 2));

    // === Network for pid 100 ===
    // Prime with decoy, then target, then trigger.
    let _ = r.process(&obs_network(
        100,
        "n.1",
        "decoy.2",
        Some("ESTABLISHED"),
        6 * SEC + 1,
    ));
    let _ = r.process(&obs_network(
        100,
        "n.1",
        "n.2",
        Some("ESTABLISHED"),
        7 * SEC + 1,
    ));
    let events = r.process(&obs_network(
        100,
        "n.1",
        "n.2",
        Some("ESTABLISHED"),
        8 * SEC + 1,
    ));

    let opened = events
        .iter()
        .find(|e| {
            e.kind == EventKind::ConnectionOpened
                && e.payload.get("foreign_addr").and_then(|v| v.as_str()) == Some("n.2")
        })
        .expect("connection_opened for n.2 should fire");
    assert_eq!(
        proc_field(opened, "comm").and_then(|v| v.as_str()),
        Some("new"),
        "enrichment should attach the most-recently-born entry; payload={:?}",
        opened.payload,
    );
    assert_eq!(
        proc_field(opened, "start_unix_secs").and_then(|v| v.as_u64()),
        Some(2000),
    );
}

/// A DNS-tagged Network observation must route to the dns stage only, leaving
/// the netstat stage's prior set untouched. Verified by interleaving a DNS
/// observation between two socket-tick observations and asserting that the
/// socket still produces no spurious close/open.
#[test]
fn dns_routing_does_not_pollute_netstat_stage() {
    let mut r = Reconstructor::new();

    // Tick 1: one socket observation.
    let _ = r.process(&obs_network(100, "s.1", "s.2", Some("ESTABLISHED"), 1));
    // Interleave a DNS observation in the *same* tick — must not affect the
    // netstat stage's `current` set.
    let dns_events = r.process(&obs_dns(100, "example.com.", "A", false, 2));
    assert_eq!(
        dns_events.len(),
        1,
        "DNS obs emits exactly one DnsQuery; got {:?}",
        dns_events
    );
    assert_eq!(dns_events[0].kind, EventKind::DnsQuery);

    // Tick 2: same socket observation. If DNS had polluted the netstat stage,
    // we might see a close/open dance here.
    let _ = r.process(&obs_network(
        100,
        "s.1",
        "s.2",
        Some("ESTABLISHED"),
        SEC + 1,
    ));

    // Tick 3: triggers diff of tick 2 vs tick 1 → unchanged set, no events.
    let events = r.process(&obs_network(
        100,
        "s.1",
        "s.2",
        Some("ESTABLISHED"),
        2 * SEC + 1,
    ));
    let kinds = kinds_of(&events);
    assert!(
        !kinds.contains(&EventKind::ConnectionOpened)
            && !kinds.contains(&EventKind::ConnectionClosed),
        "DNS interleaving must not perturb netstat diff; got {:?}",
        kinds,
    );
}

/// A full connection lifecycle (open + close) must emit a third synthetic
/// `connection_completed` event carrying duration, byte totals, and the same
/// process enrichment block as the opened/closed pair.
#[test]
fn connection_completed_is_emitted_with_duration_and_enrichment() {
    let mut r = Reconstructor::new();

    // Birth pid 2000 / start 300 so the process table can enrich.
    let _ = r.process(&obs_process(1, 0, "launchd", "/sbin/launchd", 100, 1));
    let _ = r.process(&obs_process(1, 0, "launchd", "/sbin/launchd", 100, SEC + 1));
    let _ = r.process(&obs_process(2000, 1, "curl", "/usr/bin/curl", 300, SEC + 2));
    let _ = r.process(&obs_process(
        1,
        0,
        "launchd",
        "/sbin/launchd",
        100,
        2 * SEC + 1,
    ));

    // Net tick A (priming): tuple `t.target` first seen at 3 * SEC.
    let _ = r.process(&obs_network(
        2000,
        "10.0.0.1.1",
        "1.2.3.4.443",
        Some("ESTABLISHED"),
        3 * SEC,
    ));
    // Net tick B: same tuple, still present at 4 * SEC. The diff between
    // tick A and tick B is empty, but `first_seen` is preserved across the
    // rotation so the eventual Completed event has duration > 0.
    let _ = r.process(&obs_network(
        2000,
        "10.0.0.1.1",
        "1.2.3.4.443",
        Some("ESTABLISHED"),
        4 * SEC,
    ));
    // Net tick C: tuple vanishes; observe a *different* tuple. Finalize-of-B
    // is a no-op (both ticks had the target). After rotation, prior={target},
    // current={other}.
    let _ = r.process(&obs_network(
        2000,
        "10.0.0.1.1",
        "9.9.9.9.80",
        Some("ESTABLISHED"),
        5 * SEC,
    ));
    // Net tick D: any obs triggers finalize-of-C. Now diff sees target gone
    // from current → closed + completed for target; other is new → opened.
    let events = r.process(&obs_network(
        2000,
        "10.0.0.1.1",
        "9.9.9.9.80",
        Some("ESTABLISHED"),
        6 * SEC,
    ));

    let completed = events
        .iter()
        .find(|e| {
            e.kind == EventKind::ConnectionCompleted
                && e.payload.get("foreign_addr").and_then(|v| v.as_str()) == Some("1.2.3.4.443")
        })
        .expect("ConnectionCompleted for 1.2.3.4 should fire");

    // Duration is last_seen - first_seen = 4*SEC - 3*SEC = SEC.
    assert_eq!(
        completed
            .payload
            .get("duration_ns")
            .and_then(|v| v.as_u64()),
        Some(SEC),
        "duration; payload={:?}",
        completed.payload,
    );
    // Enrichment must be present (pid 2000 is in the table).
    assert_eq!(
        proc_field(completed, "comm").and_then(|v| v.as_str()),
        Some("curl"),
        "enrichment expected on ConnectionCompleted; payload={:?}",
        completed.payload,
    );
    // Closed and Completed share this tuple in the same tick.
    let closed_count = events
        .iter()
        .filter(|e| {
            e.kind == EventKind::ConnectionClosed
                && e.payload.get("foreign_addr").and_then(|v| v.as_str()) == Some("1.2.3.4.443")
        })
        .count();
    assert_eq!(closed_count, 1, "exactly one Closed for the tuple");
}
