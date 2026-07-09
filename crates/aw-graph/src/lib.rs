//! Layer 3 world model graph.
//!
//! Builds an in-memory graph from Layer 1 observations and Layer 2 events:
//!
//! - **Process** nodes: id `(pid, start_unix_secs)` — same identity as Layer 2.
//!   Created from `process_birth` events; closed by `process_death` events.
//! - **App** nodes: id `bundle_id` (fallback: `exec_path`) — from Layer 2
//!   `AppFocus` events.
//! - **`parent_of`** edges: from each process's `ppid` field, linking parent →
//!   child. Edges to parents not in our node set are dropped.
//! - **`frontmost_during`** edges: app → process, for every pair whose lifetime
//!   intervals overlap. Built at finalize time.
//! - **Domain** nodes: id `qname` (trailing dot stripped; `hash:<name_hash>`
//!   fallback for privacy-masked queries) — from Layer 2 `DnsQuery` events.
//! - **`queried_domain`** edges: process → domain, attributed via the query's
//!   pid using the same alive-at-timestamp resolution as `opened_socket`.
//!
//! ## Pragmatic shortcuts
//!
//! - All processing is in-memory; the builder is intended for offline batch
//!   passes over captured traces, not unbounded live streams. A long live run
//!   would grow without bound.
//!
//! See ARCHITECTURE.md §Layer 3 for the eventual scope. This crate implements
//! the smallest interesting slice: two node types, two edge types.

use std::collections::HashMap;

use aw_core::{Observation, Timestamp};
#[cfg(test)]
use aw_events::SCHEMA_VERSION;
use aw_events::{Event, EventKind};
use serde::{Deserialize, Serialize};

pub mod dot;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ProcessId {
    pub pid: u32,
    pub start_unix_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessNode {
    pub id: ProcessId,
    pub comm: Option<String>,
    pub name: Option<String>,
    pub exec_path: Option<String>,
    pub ppid: Option<u32>,
    pub uid: Option<u32>,
    pub birth: Timestamp,
    pub death: Option<Timestamp>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppNode {
    pub id: String, // bundle_id, or exec_path fallback
    pub name: Option<String>,
    pub exec_path: Option<String>,
    pub intervals: Vec<Interval>, // closed-open [from, to); last may be open-ended
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SocketId {
    pub proto: String,
    pub local_addr: String,
    pub foreign_addr: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SocketNode {
    pub id: SocketId,
    pub state: Option<String>,
    pub process_name: Option<String>,
    pub pid_at_open: Option<u32>,
    pub opened: Timestamp,
    pub closed: Option<Timestamp>,
    pub rxbytes_last: Option<u64>,
    pub txbytes_last: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileNode {
    pub path: String,
    pub flags: Vec<String>, // union of all observed flag names
    pub first_seen: Timestamp,
    pub last_seen: Timestamp,
    pub touch_count: u64, // sum of `count` fields across coalesced events
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainNode {
    /// Queried name with a single trailing dot stripped, or `hash:<name_hash>`
    /// when the qname was privacy-masked by mDNSResponder.
    pub name: String,
    /// Union of all query types observed for this name (A, AAAA, HTTPS, ...).
    pub qtypes: Vec<String>,
    /// True iff every observation of this name was privacy-masked.
    pub masked: bool,
    pub first_seen: Timestamp,
    pub last_seen: Timestamp,
    pub query_count: u64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct Interval {
    pub from: Timestamp,
    /// `None` means open-ended (still frontmost / still alive at end of input).
    pub to: Option<Timestamp>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Edge {
    ParentOf {
        parent: ProcessId,
        child: ProcessId,
    },
    FrontmostDuring {
        app: String,
        process: ProcessId,
        overlap: Interval,
    },
    OpenedSocket {
        process: ProcessId,
        socket: SocketId,
    },
    QueriedDomain {
        process: ProcessId,
        domain: String,
        /// Number of queries this process issued for this name.
        count: u64,
    },
}

/// The materialized graph. Nodes and edges, both serializable.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Graph {
    pub processes: Vec<ProcessNode>,
    pub apps: Vec<AppNode>,
    pub sockets: Vec<SocketNode>,
    pub files: Vec<FileNode>,
    /// `serde(default)` so graph.json files written before domains existed
    /// still deserialize.
    #[serde(default)]
    pub domains: Vec<DomainNode>,
    pub edges: Vec<Edge>,
}

/// Streaming builder. Feed observations and events in arrival order; call
/// `build()` at end-of-input to finalize and produce the `Graph`.
///
/// `Clone` is intentional: long-running consumers (the `aw-mvp` daemon) want
/// to materialize a graph snapshot without consuming the builder, so they
/// clone-and-build on each tick. Underlying state is `HashMap`s of plain
/// data, so the clone is O(n) and avoids any unsafe sharing.
#[derive(Clone)]
pub struct GraphBuilder {
    processes: HashMap<ProcessId, ProcessNode>,
    /// Apps keyed by their canonical id (bundle_id or exec_path fallback).
    apps: HashMap<String, AppNode>,
    sockets: HashMap<SocketId, SocketNode>,
    files: HashMap<String, FileNode>,
    domains: HashMap<String, DomainNode>,
    /// Per-(pid, domain) query tallies, resolved to `queried_domain` edges at
    /// build time (pid → ProcessId needs the full process set).
    domain_queries: HashMap<(u32, String), DomainQueryAgg>,
    /// Currently-frontmost app id with the timestamp it became frontmost.
    /// Becomes `None` when the frontmost transitions to nothing.
    current_frontmost: Option<(String, Timestamp)>,
    /// Last observation/event timestamp seen, for closing open intervals at finalize.
    last_ts: Option<Timestamp>,
}

impl GraphBuilder {
    pub fn new() -> Self {
        Self {
            processes: HashMap::new(),
            apps: HashMap::new(),
            sockets: HashMap::new(),
            files: HashMap::new(),
            domains: HashMap::new(),
            domain_queries: HashMap::new(),
            current_frontmost: None,
            last_ts: None,
        }
    }

    /// Feed a Layer 2 event.
    pub fn on_event(&mut self, ev: &Event) {
        self.last_ts = Some(ev.timestamp);
        match ev.kind {
            EventKind::ProcessBirth => self.on_process_birth(ev),
            EventKind::ProcessDeath => self.on_process_death(ev),
            EventKind::AppFocus => self.on_app_focus(ev),
            EventKind::ConnectionOpened => self.on_connection_opened(ev),
            EventKind::ConnectionClosed => self.on_connection_closed(ev),
            EventKind::FileChanged => self.on_file_changed(ev),
            EventKind::DnsQuery => self.on_dns_query(ev),
            // `ConnectionCompleted` is a derived synthesis of data already
            // captured by Opened+Closed, so the graph does not double-consume
            // it. It still advances `last_ts` above so interval closure
            // remains correct.
            EventKind::ConnectionCompleted => {}
        }
    }

    /// Feed a Layer 1 observation. Used only to advance `last_ts` so open
    /// intervals close at the trace's true end, not at the last focus event.
    /// All semantic consumption happens via Layer 2 events (`on_event`).
    pub fn on_observation(&mut self, obs: &Observation) {
        self.last_ts = Some(obs.timestamp);
    }

    fn on_process_birth(&mut self, ev: &Event) {
        let Some(id) = process_id_from_event(ev) else {
            return;
        };
        let p = &ev.payload;
        let node = ProcessNode {
            id: id.clone(),
            comm: p.get("comm").and_then(|v| v.as_str()).map(String::from),
            name: p.get("name").and_then(|v| v.as_str()).map(String::from),
            exec_path: p
                .get("exec_path")
                .and_then(|v| v.as_str())
                .map(String::from),
            ppid: p
                .get("ppid")
                .and_then(|v| v.as_u64())
                .and_then(|n| u32::try_from(n).ok()),
            uid: p
                .get("uid")
                .and_then(|v| v.as_u64())
                .and_then(|n| u32::try_from(n).ok()),
            birth: ev.timestamp,
            death: None,
        };
        self.processes.insert(id, node);
    }

    fn on_process_death(&mut self, ev: &Event) {
        let Some(id) = process_id_from_event(ev) else {
            return;
        };
        if let Some(node) = self.processes.get_mut(&id) {
            node.death = Some(ev.timestamp);
        } else {
            // Death without a corresponding birth in our window. We synthesize
            // a node with whatever attributes the death event carries; birth
            // is set to the death timestamp (best we can do).
            let p = &ev.payload;
            let node = ProcessNode {
                id: id.clone(),
                comm: p.get("comm").and_then(|v| v.as_str()).map(String::from),
                name: p.get("name").and_then(|v| v.as_str()).map(String::from),
                exec_path: p
                    .get("exec_path")
                    .and_then(|v| v.as_str())
                    .map(String::from),
                ppid: p
                    .get("ppid")
                    .and_then(|v| v.as_u64())
                    .and_then(|n| u32::try_from(n).ok()),
                uid: p
                    .get("uid")
                    .and_then(|v| v.as_u64())
                    .and_then(|n| u32::try_from(n).ok()),
                birth: ev.timestamp,
                death: Some(ev.timestamp),
            };
            self.processes.insert(id, node);
        }
    }

    fn on_app_focus(&mut self, ev: &Event) {
        let p = &ev.payload;
        let id = match p.get("to_bundle_id").and_then(|v| v.as_str()) {
            Some(s) if !s.is_empty() => s.to_string(),
            _ => match p.get("to_exec_path").and_then(|v| v.as_str()) {
                Some(s) if !s.is_empty() => s.to_string(),
                _ => return,
            },
        };
        let name = p.get("to_name").and_then(|v| v.as_str()).map(String::from);
        let exec_path = p
            .get("to_exec_path")
            .and_then(|v| v.as_str())
            .map(String::from);

        // Close the prior frontmost's interval at `ev.timestamp`.
        if let Some((prev_id, prev_from)) = self.current_frontmost.take() {
            if let Some(app) = self.apps.get_mut(&prev_id) {
                if let Some(last) = app.intervals.last_mut() {
                    if last.to.is_none() {
                        last.to = Some(ev.timestamp);
                    }
                }
            }
            // Defensive: if upstream let a no-op through, keep folding.
            if prev_id == id {
                if let Some(app) = self.apps.get_mut(&prev_id) {
                    app.intervals.push(Interval {
                        from: prev_from,
                        to: None,
                    });
                }
                self.current_frontmost = Some((id, prev_from));
                return;
            }
        }

        let app = self.apps.entry(id.clone()).or_insert_with(|| AppNode {
            id: id.clone(),
            name: name.clone(),
            exec_path: exec_path.clone(),
            intervals: Vec::new(),
        });
        if app.name.is_none() {
            app.name = name;
        }
        if app.exec_path.is_none() {
            app.exec_path = exec_path;
        }
        app.intervals.push(Interval {
            from: ev.timestamp,
            to: None,
        });
        self.current_frontmost = Some((id, ev.timestamp));
    }

    fn on_connection_opened(&mut self, ev: &Event) {
        let Some(id) = socket_id_from_event(ev) else {
            return;
        };
        let p = &ev.payload;
        let node = SocketNode {
            id: id.clone(),
            state: p.get("state").and_then(|v| v.as_str()).map(String::from),
            process_name: p
                .get("process_name")
                .and_then(|v| v.as_str())
                .map(String::from),
            pid_at_open: ev.pid,
            opened: ev.timestamp,
            closed: None,
            rxbytes_last: p.get("rxbytes").and_then(|v| v.as_u64()),
            txbytes_last: p.get("txbytes").and_then(|v| v.as_u64()),
        };
        self.sockets.insert(id, node);
    }

    fn on_connection_closed(&mut self, ev: &Event) {
        let Some(id) = socket_id_from_event(ev) else {
            return;
        };
        if let Some(node) = self.sockets.get_mut(&id) {
            node.closed = Some(ev.timestamp);
            let p = &ev.payload;
            if let Some(rx) = p.get("rxbytes").and_then(|v| v.as_u64()) {
                node.rxbytes_last = Some(rx);
            }
            if let Some(tx) = p.get("txbytes").and_then(|v| v.as_u64()) {
                node.txbytes_last = Some(tx);
            }
        } else {
            // Close without a corresponding open in our window. Synthesize a
            // node so the graph is still complete; pid_at_open is what the
            // close event carried (best we can do).
            let p = &ev.payload;
            let node = SocketNode {
                id: id.clone(),
                state: p.get("state").and_then(|v| v.as_str()).map(String::from),
                process_name: p
                    .get("process_name")
                    .and_then(|v| v.as_str())
                    .map(String::from),
                pid_at_open: ev.pid,
                opened: ev.timestamp,
                closed: Some(ev.timestamp),
                rxbytes_last: p.get("rxbytes").and_then(|v| v.as_u64()),
                txbytes_last: p.get("txbytes").and_then(|v| v.as_u64()),
            };
            self.sockets.insert(id, node);
        }
    }

    fn on_file_changed(&mut self, ev: &Event) {
        let p = &ev.payload;
        let Some(path) = p.get("path").and_then(|v| v.as_str()) else {
            return;
        };
        let new_flags: Vec<String> = p
            .get("flags")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|x| x.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();
        let count = p.get("count").and_then(|v| v.as_u64()).unwrap_or(0);

        let entry = self
            .files
            .entry(path.to_string())
            .or_insert_with(|| FileNode {
                path: path.to_string(),
                flags: Vec::new(),
                first_seen: ev.timestamp,
                last_seen: ev.timestamp,
                touch_count: 0,
            });
        entry.last_seen = ev.timestamp;
        entry.touch_count += count;
        for f in new_flags {
            if !entry.flags.contains(&f) {
                entry.flags.push(f);
            }
        }
    }

    fn on_dns_query(&mut self, ev: &Event) {
        let p = &ev.payload;
        let masked = p.get("masked").and_then(|v| v.as_bool()).unwrap_or(false);
        let Some(name) = domain_id_from_payload(p) else {
            return;
        };
        let qtype = p.get("qtype").and_then(|v| v.as_str()).map(String::from);

        let node = self
            .domains
            .entry(name.clone())
            .or_insert_with(|| DomainNode {
                name: name.clone(),
                qtypes: Vec::new(),
                masked,
                first_seen: ev.timestamp,
                last_seen: ev.timestamp,
                query_count: 0,
            });
        node.last_seen = ev.timestamp;
        node.query_count += 1;
        // Any unmasked observation of the name clears the masked flag.
        node.masked = node.masked && masked;
        if let Some(q) = qtype {
            if !node.qtypes.contains(&q) {
                node.qtypes.push(q);
            }
        }

        if let Some(pid) = ev.pid {
            let agg = self
                .domain_queries
                .entry((pid, name))
                .or_insert(DomainQueryAgg {
                    count: 0,
                    first_ts: ev.timestamp,
                });
            agg.count += 1;
        }
    }

    /// Finalize and produce the graph. Open intervals are closed at the latest
    /// timestamp we've observed.
    /// Materialize a `Graph` from the current builder state *without*
    /// consuming the builder. Implemented by cloning then running `build`,
    /// so the consumed builder closes its in-flight frontmost interval on a
    /// throwaway copy and the original remains in a continuable state.
    ///
    /// Use this from long-running consumers that snapshot periodically
    /// (e.g. the `aw-mvp` daemon merging into the store on each tick).
    pub fn snapshot(&self) -> Graph {
        self.clone().build()
    }

    /// Drop in-memory nodes that have been quiescent before `cutoff`. Returns
    /// the number of nodes removed.
    ///
    /// Trim policy:
    /// - Dead processes (`death = Some(d)` with `d < cutoff`) — gone for good
    ///   from RAM; the persistent store retains them.
    /// - Closed sockets (`closed = Some(c)` with `c < cutoff`) — same.
    /// - Files whose `last_seen < cutoff` — fsevent paths accumulate fast and
    ///   are the dominant unbounded growth in long-running daemons.
    /// - Domains whose `last_seen < cutoff`, along with their pending
    ///   per-(pid, domain) query tallies.
    ///
    /// Apps are *not* trimmed: they have low cardinality, stable identity,
    /// and dropping the currently-frontmost app would corrupt the open
    /// interval tracked in `current_frontmost`. Live processes and open
    /// sockets are also left alone — there's nothing safe to drop yet.
    ///
    /// Re-introducing a trimmed entity later (e.g. a path touched again) is
    /// safe: the store treats it as a new node with the same id and bumps
    /// the merge count rather than duplicating.
    pub fn trim_before(&mut self, cutoff: Timestamp) -> usize {
        let cutoff_ns = cutoff.mono_ns;
        let before_p = self.processes.len();
        self.processes.retain(|_, p| match p.death {
            Some(d) => d.mono_ns >= cutoff_ns,
            None => true, // still alive
        });
        let before_s = self.sockets.len();
        self.sockets.retain(|_, s| match s.closed {
            Some(c) => c.mono_ns >= cutoff_ns,
            None => true, // still open
        });
        let before_f = self.files.len();
        self.files.retain(|_, f| f.last_seen.mono_ns >= cutoff_ns);
        let before_d = self.domains.len();
        self.domains.retain(|_, d| d.last_seen.mono_ns >= cutoff_ns);
        // Drop tallies for trimmed domains so this map doesn't grow forever.
        let domains = &self.domains;
        self.domain_queries
            .retain(|(_, name), _| domains.contains_key(name));

        (before_p - self.processes.len())
            + (before_s - self.sockets.len())
            + (before_f - self.files.len())
            + (before_d - self.domains.len())
    }

    pub fn build(mut self) -> Graph {
        let end_ts = self.last_ts;

        // Close currently-open frontmost interval.
        if let Some((id, _from)) = self.current_frontmost.take() {
            if let Some(app) = self.apps.get_mut(&id) {
                if let Some(last) = app.intervals.last_mut() {
                    if last.to.is_none() {
                        last.to = end_ts;
                    }
                }
            }
        }

        let processes: Vec<ProcessNode> = self.processes.values().cloned().collect();
        let apps: Vec<AppNode> = self.apps.values().cloned().collect();
        let sockets: Vec<SocketNode> = self.sockets.values().cloned().collect();
        let files: Vec<FileNode> = self.files.values().cloned().collect();
        let domains: Vec<DomainNode> = self.domains.values().cloned().collect();

        let mut edges = Vec::new();

        // parent_of edges
        let by_pid: HashMap<u32, &ProcessNode> = processes.iter().map(|p| (p.id.pid, p)).collect();
        for child in &processes {
            let Some(ppid) = child.ppid else {
                continue;
            };
            if let Some(parent) = by_pid.get(&ppid) {
                // Same pid table snapshot, so this is a *current* ppid match.
                // The parent must have been born by the child's birth time.
                if parent.id != child.id {
                    edges.push(Edge::ParentOf {
                        parent: parent.id.clone(),
                        child: child.id.clone(),
                    });
                }
            }
        }

        // frontmost_during edges
        for app in &apps {
            for interval in &app.intervals {
                let interval_to = interval.to.unwrap_or(Timestamp {
                    mono_ns: u64::MAX,
                    wall_anchor_ns: 0,
                });
                for proc in &processes {
                    let proc_to = proc.death.unwrap_or(Timestamp {
                        mono_ns: u64::MAX,
                        wall_anchor_ns: 0,
                    });
                    let overlap_from = max_ts(interval.from, proc.birth);
                    let overlap_to = min_ts(interval_to, proc_to);
                    if overlap_from.mono_ns < overlap_to.mono_ns {
                        edges.push(Edge::FrontmostDuring {
                            app: app.id.clone(),
                            process: proc.id.clone(),
                            overlap: Interval {
                                from: overlap_from,
                                to: if overlap_to.mono_ns == u64::MAX {
                                    None
                                } else {
                                    Some(overlap_to)
                                },
                            },
                        });
                    }
                }
            }
        }

        // opened_socket edges: each socket attributed to its owning pid if
        // that process is in our node set. We pick the process whose pid
        // matches `pid_at_open` and whose lifetime covers `socket.opened`.
        // If multiple processes share the pid (reused after death), tie-break
        // by the one alive at `opened`.
        for socket in &sockets {
            let Some(pid) = socket.pid_at_open else {
                continue;
            };
            let candidates = processes.iter().filter(|p| {
                p.id.pid == pid
                    && p.birth.mono_ns <= socket.opened.mono_ns
                    && p.death
                        .map(|d| d.mono_ns >= socket.opened.mono_ns)
                        .unwrap_or(true)
            });
            // Take the most-recently-born candidate (most likely the right one
            // under pid reuse).
            if let Some(proc) = candidates.max_by_key(|p| p.birth.mono_ns) {
                edges.push(Edge::OpenedSocket {
                    process: proc.id.clone(),
                    socket: socket.id.clone(),
                });
            }
        }

        // queried_domain edges: same pid-resolution rule as opened_socket —
        // among processes with the matching pid whose lifetime covers the
        // first query, take the most-recently-born (right one under pid reuse).
        for ((pid, name), agg) in &self.domain_queries {
            if !self.domains.contains_key(name) {
                continue; // domain was trimmed after the tally was recorded
            }
            let candidates = processes.iter().filter(|p| {
                p.id.pid == *pid
                    && p.birth.mono_ns <= agg.first_ts.mono_ns
                    && p.death
                        .map(|d| d.mono_ns >= agg.first_ts.mono_ns)
                        .unwrap_or(true)
            });
            if let Some(proc) = candidates.max_by_key(|p| p.birth.mono_ns) {
                edges.push(Edge::QueriedDomain {
                    process: proc.id.clone(),
                    domain: name.clone(),
                    count: agg.count,
                });
            }
        }

        Graph {
            processes,
            apps,
            sockets,
            files,
            domains,
            edges,
        }
    }
}

impl Default for GraphBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Per-(pid, domain) tally accumulated while streaming, resolved to a
/// `queried_domain` edge at build time.
#[derive(Clone)]
struct DomainQueryAgg {
    count: u64,
    first_ts: Timestamp,
}

/// Canonical domain-node id for a `dns_query` payload: the qname with one
/// trailing dot stripped, or `hash:<name_hash>` for privacy-masked queries
/// that carry no usable name. Returns `None` when neither is present.
fn domain_id_from_payload(p: &serde_json::Value) -> Option<String> {
    let masked = p.get("masked").and_then(|v| v.as_bool()).unwrap_or(false);
    match p.get("qname").and_then(|v| v.as_str()) {
        Some(q) if !q.is_empty() && !masked => Some(q.strip_suffix('.').unwrap_or(q).to_string()),
        _ => p
            .get("name_hash")
            .and_then(|v| v.as_str())
            .filter(|h| !h.is_empty())
            .map(|h| format!("hash:{h}")),
    }
}

fn process_id_from_event(ev: &Event) -> Option<ProcessId> {
    let pid = ev.pid?;
    let start = ev.payload.get("start_unix_secs")?.as_u64()?;
    Some(ProcessId {
        pid,
        start_unix_secs: start,
    })
}

fn socket_id_from_event(ev: &Event) -> Option<SocketId> {
    let p = &ev.payload;
    let proto = p.get("proto")?.as_str()?.to_string();
    let local_addr = p.get("local_addr")?.as_str()?.to_string();
    let foreign_addr = p.get("foreign_addr")?.as_str()?.to_string();
    Some(SocketId {
        proto,
        local_addr,
        foreign_addr,
    })
}

fn min_ts(a: Timestamp, b: Timestamp) -> Timestamp {
    if a.mono_ns <= b.mono_ns {
        a
    } else {
        b
    }
}

fn max_ts(a: Timestamp, b: Timestamp) -> Timestamp {
    if a.mono_ns >= b.mono_ns {
        a
    } else {
        b
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn ts(n: u64) -> Timestamp {
        Timestamp {
            mono_ns: n,
            wall_anchor_ns: 0,
        }
    }

    fn birth(pid: u32, start: u64, comm: &str, ppid: u32, mono: u64) -> Event {
        Event {
            schema_version: SCHEMA_VERSION,
            timestamp: ts(mono),
            kind: EventKind::ProcessBirth,
            pid: Some(pid),
            payload: json!({ "comm": comm, "name": comm, "ppid": ppid, "uid": 501, "start_unix_secs": start, "exec_path": format!("/bin/{comm}") }),
        }
    }

    fn death(pid: u32, start: u64, mono: u64) -> Event {
        Event {
            schema_version: SCHEMA_VERSION,
            timestamp: ts(mono),
            kind: EventKind::ProcessDeath,
            pid: Some(pid),
            payload: json!({ "start_unix_secs": start }),
        }
    }

    fn conn_open(pid: u32, proto: &str, local: &str, foreign: &str, mono: u64) -> Event {
        Event {
            schema_version: SCHEMA_VERSION,
            timestamp: ts(mono),
            kind: EventKind::ConnectionOpened,
            pid: Some(pid),
            payload: json!({
                "proto": proto, "local_addr": local, "foreign_addr": foreign,
                "state": "ESTABLISHED", "process_name": "test",
                "rxbytes": 0u64, "txbytes": 0u64,
            }),
        }
    }

    fn conn_close(pid: u32, proto: &str, local: &str, foreign: &str, mono: u64) -> Event {
        Event {
            schema_version: SCHEMA_VERSION,
            timestamp: ts(mono),
            kind: EventKind::ConnectionClosed,
            pid: Some(pid),
            payload: json!({
                "proto": proto, "local_addr": local, "foreign_addr": foreign,
                "state": "ESTABLISHED", "process_name": "test",
                "rxbytes": 100u64, "txbytes": 200u64,
            }),
        }
    }

    fn file_changed(path: &str, flags: &[&str], count: u64, mono: u64) -> Event {
        Event {
            schema_version: SCHEMA_VERSION,
            timestamp: ts(mono),
            kind: EventKind::FileChanged,
            pid: None,
            payload: json!({
                "path": path,
                "flags": flags,
                "count": count,
                "event_ids": [1u64],
            }),
        }
    }

    fn focus(bundle: &str, name: &str, mono: u64) -> Event {
        Event {
            schema_version: SCHEMA_VERSION,
            timestamp: ts(mono),
            kind: EventKind::AppFocus,
            pid: Some(999),
            payload: json!({
                "from_bundle_id": null,
                "from_name": null,
                "to_bundle_id": bundle,
                "to_name": name,
                "to_exec_path": format!("/Applications/{name}.app/Contents/MacOS/{name}"),
            }),
        }
    }

    #[test]
    fn process_birth_creates_node() {
        let mut b = GraphBuilder::new();
        b.on_event(&birth(100, 1000, "shell", 1, 10));
        let g = b.build();
        assert_eq!(g.processes.len(), 1);
        assert_eq!(g.processes[0].id.pid, 100);
        assert_eq!(g.processes[0].comm.as_deref(), Some("shell"));
        assert!(g.processes[0].death.is_none());
    }

    #[test]
    fn process_death_records_death_time() {
        let mut b = GraphBuilder::new();
        b.on_event(&birth(100, 1000, "shell", 1, 10));
        b.on_event(&death(100, 1000, 20));
        let g = b.build();
        assert_eq!(g.processes[0].death, Some(ts(20)));
    }

    #[test]
    fn parent_of_edge_built_from_ppid() {
        let mut b = GraphBuilder::new();
        b.on_event(&birth(100, 1000, "parent", 1, 10));
        b.on_event(&birth(200, 1001, "child", 100, 11)); // ppid = 100
        let g = b.build();
        let parent_edges: Vec<_> = g
            .edges
            .iter()
            .filter(|e| matches!(e, Edge::ParentOf { .. }))
            .collect();
        assert_eq!(parent_edges.len(), 1);
        match parent_edges[0] {
            Edge::ParentOf { parent, child } => {
                assert_eq!(parent.pid, 100);
                assert_eq!(child.pid, 200);
            }
            _ => panic!(),
        }
    }

    #[test]
    fn parent_outside_node_set_drops_edge() {
        let mut b = GraphBuilder::new();
        b.on_event(&birth(200, 1001, "orphan", 999, 11)); // ppid 999 not in graph
        let g = b.build();
        assert!(!g.edges.iter().any(|e| matches!(e, Edge::ParentOf { .. })));
    }

    #[test]
    fn app_focus_creates_app_with_interval() {
        let mut b = GraphBuilder::new();
        b.on_event(&focus("com.app.a", "AppA", 10));
        b.on_event(&focus("com.app.b", "AppB", 20));
        let g = b.build();
        let app_a = g.apps.iter().find(|a| a.id == "com.app.a").unwrap();
        // A's interval should be [10, 20).
        assert_eq!(app_a.intervals.len(), 1);
        assert_eq!(app_a.intervals[0].from, ts(10));
        assert_eq!(app_a.intervals[0].to, Some(ts(20)));
    }

    #[test]
    fn frontmost_during_edge_when_intervals_overlap() {
        let mut b = GraphBuilder::new();
        // App A is frontmost [10, 30); process P alive [15, 25). They overlap.
        b.on_event(&focus("com.app.a", "AppA", 10));
        b.on_event(&birth(100, 1000, "p", 1, 15));
        b.on_event(&death(100, 1000, 25));
        b.on_event(&focus("com.app.b", "AppB", 30));
        let g = b.build();
        let fronts: Vec<_> = g
            .edges
            .iter()
            .filter(|e| matches!(e, Edge::FrontmostDuring { .. }))
            .collect();
        // AppA overlaps with process p. AppB starts after p died, so no overlap.
        assert_eq!(fronts.len(), 1);
        if let Edge::FrontmostDuring {
            app,
            process,
            overlap,
        } = fronts[0]
        {
            assert_eq!(app, "com.app.a");
            assert_eq!(process.pid, 100);
            assert_eq!(overlap.from, ts(15));
            assert_eq!(overlap.to, Some(ts(25)));
        }
    }

    #[test]
    fn open_intervals_close_at_last_timestamp() {
        let mut b = GraphBuilder::new();
        b.on_event(&focus("com.app.a", "AppA", 10));
        b.on_event(&birth(100, 1000, "p", 1, 12)); // bumps last_ts to 12
        let g = b.build();
        let app_a = &g.apps[0];
        assert_eq!(app_a.intervals[0].to, Some(ts(12)));
    }

    #[test]
    fn connection_opened_creates_socket_node() {
        let mut b = GraphBuilder::new();
        b.on_event(&conn_open(100, "tcp4", "10.0.0.1.50", "1.2.3.4.443", 20));
        let g = b.build();
        assert_eq!(g.sockets.len(), 1);
        assert_eq!(g.sockets[0].id.proto, "tcp4");
        assert_eq!(g.sockets[0].pid_at_open, Some(100));
        assert!(g.sockets[0].closed.is_none());
    }

    #[test]
    fn connection_closed_records_close_time() {
        let mut b = GraphBuilder::new();
        b.on_event(&conn_open(100, "tcp4", "a", "b", 20));
        b.on_event(&conn_close(100, "tcp4", "a", "b", 30));
        let g = b.build();
        assert_eq!(g.sockets[0].closed, Some(ts(30)));
        assert_eq!(g.sockets[0].rxbytes_last, Some(100));
        assert_eq!(g.sockets[0].txbytes_last, Some(200));
    }

    #[test]
    fn opened_socket_edge_built_when_process_present() {
        let mut b = GraphBuilder::new();
        // Process is born first, then opens a socket.
        b.on_event(&birth(100, 1000, "curl", 1, 10));
        b.on_event(&conn_open(100, "tcp4", "a", "b", 20));
        let g = b.build();
        let edges: Vec<_> = g
            .edges
            .iter()
            .filter(|e| matches!(e, Edge::OpenedSocket { .. }))
            .collect();
        assert_eq!(edges.len(), 1);
        match edges[0] {
            Edge::OpenedSocket { process, socket } => {
                assert_eq!(process.pid, 100);
                assert_eq!(socket.proto, "tcp4");
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn opened_socket_edge_dropped_when_process_absent() {
        let mut b = GraphBuilder::new();
        // No process node — socket has nothing to attach to.
        b.on_event(&conn_open(999, "tcp4", "a", "b", 20));
        let g = b.build();
        assert!(!g
            .edges
            .iter()
            .any(|e| matches!(e, Edge::OpenedSocket { .. })));
    }

    #[test]
    fn file_changed_creates_file_node_and_unions_flags() {
        let mut b = GraphBuilder::new();
        b.on_event(&file_changed("/tmp/foo", &["created", "is_file"], 2, 10));
        b.on_event(&file_changed("/tmp/foo", &["modified", "is_file"], 3, 20));
        let g = b.build();
        assert_eq!(g.files.len(), 1);
        assert_eq!(g.files[0].path, "/tmp/foo");
        assert_eq!(g.files[0].touch_count, 5);
        assert!(g.files[0].flags.contains(&"created".to_string()));
        assert!(g.files[0].flags.contains(&"modified".to_string()));
        // Flag should appear once even though it was observed twice.
        assert_eq!(
            g.files[0].flags.iter().filter(|f| **f == "is_file").count(),
            1
        );
    }

    #[test]
    fn pid_reuse_picks_recent_process_for_socket_edge() {
        let mut b = GraphBuilder::new();
        // Pid 100 lives [10, 30) then is reused with a new start time [40, _).
        b.on_event(&birth(100, 1000, "old", 1, 10));
        b.on_event(&death(100, 1000, 30));
        b.on_event(&birth(100, 1001, "new", 1, 40));
        // Socket opens at t=50 while the new process is alive.
        b.on_event(&conn_open(100, "tcp4", "a", "b", 50));
        let g = b.build();
        let edges: Vec<_> = g
            .edges
            .iter()
            .filter_map(|e| match e {
                Edge::OpenedSocket { process, .. } => Some(process.start_unix_secs),
                _ => None,
            })
            .collect();
        assert_eq!(edges, vec![1001], "should attach to the newer process");
    }

    #[test]
    fn trim_before_drops_dead_processes_and_keeps_alive_ones() {
        let mut b = GraphBuilder::new();
        b.on_event(&birth(100, 1, "alive", 1, 1_000));
        b.on_event(&birth(200, 1, "dead", 1, 2_000));
        b.on_event(&death(200, 1, 3_000));
        // Cutoff at mono=2_500 — dead's death (3_000) is *after* cutoff, so it stays.
        let trimmed = b.trim_before(ts(2_500));
        assert_eq!(trimmed, 0, "no nodes old enough yet");
        // Cutoff at mono=10_000 — dead is now strictly older than cutoff; alive is still alive.
        let trimmed = b.trim_before(ts(10_000));
        assert_eq!(trimmed, 1, "dead process should be trimmed");
        let g = b.snapshot();
        let pids: Vec<u32> = g.processes.iter().map(|p| p.id.pid).collect();
        assert!(pids.contains(&100), "alive process must remain: {pids:?}");
        assert!(!pids.contains(&200), "dead process must be gone: {pids:?}");
    }

    #[test]
    fn trim_before_drops_files_quiescent_past_cutoff() {
        let mut b = GraphBuilder::new();
        b.on_event(&file_changed("/tmp/old", &["modified"], 1, 1_000));
        b.on_event(&file_changed("/tmp/recent", &["modified"], 1, 5_000));
        let trimmed = b.trim_before(ts(3_000));
        assert_eq!(trimmed, 1);
        let g = b.snapshot();
        let paths: Vec<&str> = g.files.iter().map(|f| f.path.as_str()).collect();
        assert!(paths.contains(&"/tmp/recent"));
        assert!(!paths.contains(&"/tmp/old"));
    }

    fn dns(pid: u32, qname: Option<&str>, qtype: &str, masked: bool, mono: u64) -> Event {
        Event {
            schema_version: SCHEMA_VERSION,
            timestamp: ts(mono),
            kind: EventKind::DnsQuery,
            pid: Some(pid),
            payload: json!({
                "qname": qname,
                "qtype": qtype,
                "name_hash": "abc123",
                "masked": masked,
                "client_process_name": "test",
            }),
        }
    }

    #[test]
    fn dns_query_creates_domain_node_and_strips_trailing_dot() {
        let mut b = GraphBuilder::new();
        b.on_event(&dns(100, Some("example.com."), "A", false, 10));
        b.on_event(&dns(100, Some("example.com."), "AAAA", false, 20));
        let g = b.build();
        assert_eq!(g.domains.len(), 1);
        let d = &g.domains[0];
        assert_eq!(d.name, "example.com");
        assert_eq!(d.query_count, 2);
        assert!(d.qtypes.contains(&"A".to_string()));
        assert!(d.qtypes.contains(&"AAAA".to_string()));
        assert_eq!(d.first_seen, ts(10));
        assert_eq!(d.last_seen, ts(20));
        assert!(!d.masked);
    }

    #[test]
    fn masked_dns_query_falls_back_to_name_hash() {
        let mut b = GraphBuilder::new();
        b.on_event(&dns(100, Some("<mask.hash: 'xxx=='>"), "A", true, 10));
        let g = b.build();
        assert_eq!(g.domains.len(), 1);
        assert_eq!(g.domains[0].name, "hash:abc123");
        assert!(g.domains[0].masked);
    }

    #[test]
    fn queried_domain_edge_built_when_process_present() {
        let mut b = GraphBuilder::new();
        b.on_event(&birth(100, 1000, "curl", 1, 10));
        b.on_event(&dns(100, Some("example.com."), "A", false, 20));
        b.on_event(&dns(100, Some("example.com."), "AAAA", false, 21));
        let g = b.build();
        let edges: Vec<_> = g
            .edges
            .iter()
            .filter_map(|e| match e {
                Edge::QueriedDomain {
                    process,
                    domain,
                    count,
                } => Some((process.pid, domain.as_str(), *count)),
                _ => None,
            })
            .collect();
        assert_eq!(edges, vec![(100, "example.com", 2)]);
    }

    #[test]
    fn queried_domain_edge_dropped_when_process_absent() {
        let mut b = GraphBuilder::new();
        b.on_event(&dns(999, Some("example.com."), "A", false, 20));
        let g = b.build();
        assert_eq!(g.domains.len(), 1, "domain node still materializes");
        assert!(!g
            .edges
            .iter()
            .any(|e| matches!(e, Edge::QueriedDomain { .. })));
    }

    #[test]
    fn trim_before_drops_quiescent_domains() {
        let mut b = GraphBuilder::new();
        b.on_event(&dns(100, Some("old.example."), "A", false, 1_000));
        b.on_event(&dns(100, Some("recent.example."), "A", false, 5_000));
        let trimmed = b.trim_before(ts(3_000));
        assert_eq!(trimmed, 1);
        let g = b.snapshot();
        let names: Vec<&str> = g.domains.iter().map(|d| d.name.as_str()).collect();
        assert!(names.contains(&"recent.example"));
        assert!(!names.contains(&"old.example"));
    }

    #[test]
    fn trim_before_keeps_open_sockets() {
        let mut b = GraphBuilder::new();
        // Only "opened" — never closed. Should always remain regardless of cutoff.
        b.on_event(&conn_open(
            42,
            "tcp4",
            "10.0.0.1.50000",
            "1.2.3.4.443",
            1_000,
        ));
        let trimmed = b.trim_before(ts(1_000_000_000));
        assert_eq!(trimmed, 0);
        let g = b.snapshot();
        assert_eq!(g.sockets.len(), 1, "open sockets must not be trimmed");
    }
}
