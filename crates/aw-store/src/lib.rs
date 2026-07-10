//! Layer 4 persistent world-model store, backed by SQLite.
//!
//! Two tables, both keyed by `(kind, id)` / `(kind, from_kind, from_id,
//! to_kind, to_id)`. Every merge is upsert-with-bumped-count semantics:
//! repeat observations strengthen an existing edge rather than duplicating
//! rows. This is what the architecture's "bounded growth" property means
//! in practice — the row count tracks distinct entities and relationships,
//! not the volume of observations producing them.
//!
//! Timestamps stored in the DB are **wall-clock unix nanoseconds**, computed
//! as `wall_anchor_ns + mono_ns` at merge time. Captures taken at different
//! moments are directly comparable; the monotonic-clock detail of an
//! in-flight capture stays inside Layer 1/2/3.

use std::path::Path;

use aw_core::Timestamp;
use aw_events::{Event, EventKind};
use aw_graph::{
    AppNode, DomainNode, Edge, FileNode, Graph, Interval, ProcessId, ProcessNode, SocketId,
    SocketNode,
};
use rusqlite::{params, Connection, OptionalExtension, Transaction};
use serde::{Deserialize, Serialize};

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("sqlite error: {0}")]
    Sql(#[from] rusqlite::Error),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("schema migration failed: {0}")]
    Migration(String),
}

pub type Result<T> = std::result::Result<T, StoreError>;

const SCHEMA_VERSION: i32 = 1;

const SCHEMA_SQL: &str = r#"
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS nodes (
    kind       TEXT    NOT NULL,
    id         TEXT    NOT NULL,
    attrs      TEXT    NOT NULL,
    first_seen INTEGER NOT NULL,
    last_seen  INTEGER NOT NULL,
    PRIMARY KEY (kind, id)
);

CREATE INDEX IF NOT EXISTS idx_nodes_last_seen ON nodes(last_seen);

CREATE TABLE IF NOT EXISTS edges (
    kind       TEXT    NOT NULL,
    from_kind  TEXT    NOT NULL,
    from_id    TEXT    NOT NULL,
    to_kind    TEXT    NOT NULL,
    to_id      TEXT    NOT NULL,
    count      INTEGER NOT NULL DEFAULT 1,
    first_seen INTEGER NOT NULL,
    last_seen  INTEGER NOT NULL,
    attrs      TEXT    NOT NULL DEFAULT '{}',
    PRIMARY KEY (kind, from_kind, from_id, to_kind, to_id)
);

CREATE INDEX IF NOT EXISTS idx_edges_to        ON edges(to_kind, to_id);
CREATE INDEX IF NOT EXISTS idx_edges_last_seen ON edges(last_seen);

CREATE TABLE IF NOT EXISTS events (
    id             INTEGER PRIMARY KEY,
    ts_unix_ns     INTEGER NOT NULL,
    kind           TEXT    NOT NULL,
    pid            INTEGER,
    schema_version INTEGER NOT NULL,
    payload        TEXT    NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_events_ts      ON events(ts_unix_ns);
CREATE INDEX IF NOT EXISTS idx_events_kind_ts ON events(kind, ts_unix_ns);
"#;

/// One row of [`Store::top_endpoints_by_bytes`]. Fields are derived from
/// socket-node attrs, so they reflect the **last observed** byte counters
/// (sockets are upserted, so this is the highest counter we've seen for
/// each socket id, not a delta).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointSummary {
    pub foreign_addr: String,
    pub total_bytes: u64,
    pub distinct_processes: u32,
    pub connection_count: u32,
}

/// One row of [`Store::focus_segments_in_window`]. Timestamps are
/// wall-clock unix nanoseconds, clipped to the requested window.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FocusSegment {
    /// App id (bundle id, or exec_path fallback for unbundled apps).
    pub app_id: String,
    /// Human-readable name. Falls back to `app_id` if no `name` attr exists.
    pub app_name: String,
    /// PID of the process that was frontmost during this segment.
    pub process_pid: u32,
    pub from_unix_ns: i64,
    pub to_unix_ns: i64,
    pub duration_secs: u64,
}

/// One row of [`Store::top_domains`]. Query counts come from the domain
/// node's attrs (highest observed tally per merge); distinct processes from
/// `queried_domain` edges.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainSummary {
    pub name: String,
    pub query_count: u64,
    pub distinct_processes: u32,
    pub last_seen_unix_ns: i64,
}

/// Per-kind cap on [`Store::novel_since`] result lists. Novelty feeds prose;
/// past ~20 items per kind the narrator would truncate anyway.
pub const NOVELTY_CAP_PER_KIND: usize = 20;

/// A never-before-seen process *identity* — process node rows are one per
/// run (`pid:start_secs`), so novelty collapses them by `(comm, exec_path)`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewProcessIdentity {
    pub comm: Option<String>,
    pub exec_path: Option<String>,
    pub first_seen_unix_ns: i64,
    /// Node rows collapsed into this identity (≥ 1).
    pub instances: u32,
}

/// A foreign endpoint whose *earliest* socket falls after the cutoff.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewEndpoint {
    pub foreign_addr: String,
    pub example_process: Option<String>,
    pub first_seen_unix_ns: i64,
    pub socket_count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewApp {
    pub id: String,
    pub name: Option<String>,
}

/// Result of [`Store::novel_since`]: entities first seen at/after the cutoff.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct NoveltyReport {
    pub new_processes: Vec<NewProcessIdentity>,
    pub new_domains: Vec<String>,
    pub new_endpoints: Vec<NewEndpoint>,
    pub new_apps: Vec<NewApp>,
    /// `MIN(first_seen)` across ALL nodes; `None` when the store is empty.
    /// Callers use this to detect a cold baseline — when history barely
    /// predates the cutoff, "first time ever seen" is not a meaningful claim.
    pub oldest_first_seen_unix_ns: Option<i64>,
}

/// Result of [`Store::prune_before`].
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct PruneReport {
    pub nodes_deleted: u64,
    pub edges_deleted: u64,
    #[serde(default)]
    pub events_deleted: u64,
}

/// Result of [`Store::summary`]: per-kind row counts plus the wall-clock
/// span the store covers.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct StoreSummary {
    /// `(node kind, row count)`, descending by count.
    pub node_counts: Vec<(String, u64)>,
    /// `(edge kind, row count)`, descending by count.
    pub edge_counts: Vec<(String, u64)>,
    /// Earliest `first_seen` across all nodes (unix ns); `None` if empty.
    pub first_seen_unix_ns: Option<i64>,
    /// Latest `last_seen` across all nodes (unix ns); `None` if empty.
    pub last_seen_unix_ns: Option<i64>,
    /// Rows in the `events` history table.
    #[serde(default)]
    pub event_count: u64,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct MergeReport {
    pub nodes_inserted: u64,
    pub nodes_updated: u64,
    pub edges_inserted: u64,
    pub edges_updated: u64,
}

/// One row of [`Store::event_hourly_profile`]: how many events of `kind`
/// fell in UTC hour-of-day `hour_of_day` since the query's cutoff.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HourlyKindCount {
    pub kind: String,
    pub hour_of_day: u8,
    pub count: u64,
}

/// One row of [`Store::event_field_window_counts`]: how many events of the
/// queried kind carried `value` in the queried payload field, per time
/// window.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldWindowCount {
    pub value: String,
    pub window_start_unix_ns: i64,
    pub count: u64,
}

/// One row of [`Store::edge_rates`]: an edge's raw observation tally and the
/// wall-clock span it was tallied over. `count / span` is the caller's rate;
/// the store only reports the mechanical columns.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EdgeRate {
    pub from_id: String,
    pub to_id: String,
    pub count: u64,
    pub first_seen_unix_ns: i64,
    pub last_seen_unix_ns: i64,
}

pub struct Store {
    conn: Connection,
}

impl Store {
    /// Open or create a store at `path`. Schema is applied idempotently.
    /// Use `":memory:"` for tests.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        let conn = Connection::open(path)?;
        Self::init(conn)
    }

    pub fn open_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        Self::init(conn)
    }

    fn init(conn: Connection) -> Result<Self> {
        // WAL lets the aw-mvp daemon keep writing while aw-query reads the
        // same file; the busy timeout absorbs the brief write locks that
        // remain. In-memory databases don't support WAL — the pragma then
        // returns "memory", which is fine, so the result value is ignored.
        let _: String = conn.pragma_update_and_check(None, "journal_mode", "WAL", |r| r.get(0))?;
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        conn.execute_batch(SCHEMA_SQL)?;
        // Record the schema version if not already present.
        let current: Option<String> = conn
            .query_row(
                "SELECT value FROM meta WHERE key = 'schema_version'",
                [],
                |r| r.get(0),
            )
            .optional()?;
        match current {
            None => {
                conn.execute(
                    "INSERT INTO meta(key, value) VALUES('schema_version', ?1)",
                    params![SCHEMA_VERSION.to_string()],
                )?;
            }
            Some(s) => {
                let v: i32 = s.parse().map_err(|_| {
                    StoreError::Migration(format!("non-integer schema_version: {s}"))
                })?;
                if v > SCHEMA_VERSION {
                    return Err(StoreError::Migration(format!(
                        "store schema_version={v} is newer than this binary supports ({SCHEMA_VERSION})"
                    )));
                }
                // v < SCHEMA_VERSION would run migrations here once we have any.
            }
        }
        Ok(Self { conn })
    }

    /// Set an operational metadata key (e.g. the daemon's heartbeat). The
    /// `schema_version` key is owned by `init` and rejected here so a caller
    /// can't accidentally break migration checks.
    pub fn set_meta(&self, key: &str, value: &str) -> Result<()> {
        if key == "schema_version" {
            return Err(StoreError::Migration(
                "schema_version is managed by the store itself".into(),
            ));
        }
        self.conn.execute(
            "INSERT INTO meta(key, value) VALUES(?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![key, value],
        )?;
        Ok(())
    }

    pub fn get_meta(&self, key: &str) -> Result<Option<String>> {
        Ok(self
            .conn
            .query_row("SELECT value FROM meta WHERE key = ?1", params![key], |r| {
                r.get(0)
            })
            .optional()?)
    }

    pub fn schema_version(&self) -> Result<i32> {
        let s: String = self.conn.query_row(
            "SELECT value FROM meta WHERE key = 'schema_version'",
            [],
            |r| r.get(0),
        )?;
        Ok(s.parse().unwrap_or(0))
    }

    /// Merge a graph into the store. Idempotent w.r.t. node/edge identity:
    /// re-merging the same graph bumps each edge's `count` by 1 and extends
    /// `last_seen`, but does not duplicate rows.
    pub fn merge_graph(&mut self, g: &Graph) -> Result<MergeReport> {
        let mut report = MergeReport::default();
        let tx = self.conn.transaction()?;

        for p in &g.processes {
            let kind = "process";
            let id = process_id_to_string(&p.id);
            let attrs = serde_json::to_string(&serde_json::json!({
                "comm": p.comm,
                "name": p.name,
                "exec_path": p.exec_path,
                "ppid": p.ppid,
                "uid": p.uid,
                "start_unix_secs": p.id.start_unix_secs,
                "death": p.death,
            }))?;
            upsert_node(
                &tx,
                kind,
                &id,
                &attrs,
                p.birth,
                p.death.unwrap_or(p.birth),
                &mut report,
            )?;
        }

        for a in &g.apps {
            let kind = "app";
            let id = &a.id;
            let attrs = serde_json::to_string(&serde_json::json!({
                "name": a.name,
                "exec_path": a.exec_path,
                "intervals": a.intervals,
            }))?;
            let first_seen = a
                .intervals
                .iter()
                .map(|i| i.from)
                .min()
                .unwrap_or(Timestamp {
                    mono_ns: 0,
                    wall_anchor_ns: 0,
                });
            let last_seen = a
                .intervals
                .iter()
                .filter_map(|i| i.to)
                .max()
                .unwrap_or(first_seen);
            upsert_node(&tx, kind, id, &attrs, first_seen, last_seen, &mut report)?;
        }

        for s in &g.sockets {
            let kind = "socket";
            let id = socket_id_to_string(&s.id);
            let attrs = serde_json::to_string(&serde_json::json!({
                "state": s.state,
                "process_name": s.process_name,
                "pid_at_open": s.pid_at_open,
                "rxbytes_last": s.rxbytes_last,
                "txbytes_last": s.txbytes_last,
                "proto": s.id.proto,
                "local_addr": s.id.local_addr,
                "foreign_addr": s.id.foreign_addr,
            }))?;
            upsert_node(
                &tx,
                kind,
                &id,
                &attrs,
                s.opened,
                s.closed.unwrap_or(s.opened),
                &mut report,
            )?;
        }

        for f in &g.files {
            let kind = "file";
            let id = &f.path;
            let attrs = serde_json::to_string(&serde_json::json!({
                "flags": f.flags,
                "touch_count": f.touch_count,
            }))?;
            upsert_node(
                &tx,
                kind,
                id,
                &attrs,
                f.first_seen,
                f.last_seen,
                &mut report,
            )?;
        }

        for d in &g.domains {
            let kind = "domain";
            let id = &d.name;
            let attrs = serde_json::to_string(&serde_json::json!({
                "qtypes": d.qtypes,
                "masked": d.masked,
                "query_count": d.query_count,
            }))?;
            upsert_node(
                &tx,
                kind,
                id,
                &attrs,
                d.first_seen,
                d.last_seen,
                &mut report,
            )?;
        }

        for edge in &g.edges {
            match edge {
                Edge::ParentOf { parent, child } => {
                    let from_id = process_id_to_string(parent);
                    let to_id = process_id_to_string(child);
                    // Edges built from process_birth don't carry their own
                    // wall time; fall back to the child node's last_seen.
                    let seen_at = node_last_seen(&tx, "process", &to_id)?;
                    upsert_edge(
                        &tx,
                        EdgeRow {
                            kind: "parent_of",
                            from_kind: "process",
                            from_id: &from_id,
                            to_kind: "process",
                            to_id: &to_id,
                            seen_at,
                            attrs: "{}",
                        },
                        &mut report,
                    )?;
                }
                Edge::FrontmostDuring {
                    app,
                    process,
                    overlap,
                } => {
                    let to_id = process_id_to_string(process);
                    let attrs = serde_json::to_string(&serde_json::json!({
                        "overlap": overlap,
                    }))?;
                    upsert_edge(
                        &tx,
                        EdgeRow {
                            kind: "frontmost_during",
                            from_kind: "app",
                            from_id: app,
                            to_kind: "process",
                            to_id: &to_id,
                            seen_at: overlap.to.unwrap_or(overlap.from),
                            attrs: &attrs,
                        },
                        &mut report,
                    )?;
                }
                Edge::OpenedSocket { process, socket } => {
                    let from_id = process_id_to_string(process);
                    let to_id = socket_id_to_string(socket);
                    let seen_at = node_last_seen(&tx, "socket", &to_id)?;
                    upsert_edge(
                        &tx,
                        EdgeRow {
                            kind: "opened_socket",
                            from_kind: "process",
                            from_id: &from_id,
                            to_kind: "socket",
                            to_id: &to_id,
                            seen_at,
                            attrs: "{}",
                        },
                        &mut report,
                    )?;
                }
                Edge::QueriedDomain {
                    process,
                    domain,
                    count,
                } => {
                    let from_id = process_id_to_string(process);
                    let seen_at = node_last_seen(&tx, "domain", domain)?;
                    let attrs = serde_json::to_string(&serde_json::json!({
                        "queries": count,
                    }))?;
                    upsert_edge(
                        &tx,
                        EdgeRow {
                            kind: "queried_domain",
                            from_kind: "process",
                            from_id: &from_id,
                            to_kind: "domain",
                            to_id: domain,
                            seen_at,
                            attrs: &attrs,
                        },
                        &mut report,
                    )?;
                }
            }
        }

        tx.commit()?;
        Ok(report)
    }

    /// Reconstruct an `aw_graph::Graph` from the store. Useful for handing
    /// a persisted graph back to downstream consumers (`aw-agents`).
    pub fn load_graph(&self) -> Result<Graph> {
        let mut g = Graph::default();

        // Processes
        let mut stmt = self
            .conn
            .prepare("SELECT id, attrs, first_seen, last_seen FROM nodes WHERE kind = 'process'")?;
        let rows = stmt.query_map([], |r| {
            let id: String = r.get(0)?;
            let attrs: String = r.get(1)?;
            let first_seen: i64 = r.get(2)?;
            let last_seen: i64 = r.get(3)?;
            Ok((id, attrs, first_seen, last_seen))
        })?;
        for row in rows {
            let (id_str, attrs, first_seen, _last_seen) = row?;
            let pid_id = process_id_from_string(&id_str);
            let v: serde_json::Value = serde_json::from_str(&attrs)?;
            let death_v = v.get("death").cloned().unwrap_or(serde_json::Value::Null);
            let death: Option<Timestamp> = if death_v.is_null() {
                None
            } else {
                serde_json::from_value(death_v).ok()
            };
            g.processes.push(ProcessNode {
                id: pid_id,
                comm: v.get("comm").and_then(|x| x.as_str()).map(String::from),
                name: v.get("name").and_then(|x| x.as_str()).map(String::from),
                exec_path: v
                    .get("exec_path")
                    .and_then(|x| x.as_str())
                    .map(String::from),
                ppid: v
                    .get("ppid")
                    .and_then(|x| x.as_u64())
                    .and_then(|n| u32::try_from(n).ok()),
                uid: v
                    .get("uid")
                    .and_then(|x| x.as_u64())
                    .and_then(|n| u32::try_from(n).ok()),
                birth: Timestamp {
                    mono_ns: first_seen as u64,
                    wall_anchor_ns: 0,
                },
                death,
            });
        }

        // Apps
        let mut stmt = self
            .conn
            .prepare("SELECT id, attrs FROM nodes WHERE kind = 'app'")?;
        let rows = stmt.query_map([], |r| {
            let id: String = r.get(0)?;
            let attrs: String = r.get(1)?;
            Ok((id, attrs))
        })?;
        for row in rows {
            let (id, attrs) = row?;
            let v: serde_json::Value = serde_json::from_str(&attrs)?;
            let intervals: Vec<Interval> = v
                .get("intervals")
                .cloned()
                .and_then(|x| serde_json::from_value(x).ok())
                .unwrap_or_default();
            g.apps.push(AppNode {
                id,
                name: v.get("name").and_then(|x| x.as_str()).map(String::from),
                exec_path: v
                    .get("exec_path")
                    .and_then(|x| x.as_str())
                    .map(String::from),
                intervals,
            });
        }

        // Sockets
        let mut stmt = self
            .conn
            .prepare("SELECT id, attrs, first_seen, last_seen FROM nodes WHERE kind = 'socket'")?;
        let rows = stmt.query_map([], |r| {
            let id: String = r.get(0)?;
            let attrs: String = r.get(1)?;
            let first_seen: i64 = r.get(2)?;
            let last_seen: i64 = r.get(3)?;
            Ok((id, attrs, first_seen, last_seen))
        })?;
        for row in rows {
            let (_id, attrs, first_seen, last_seen) = row?;
            let v: serde_json::Value = serde_json::from_str(&attrs)?;
            let sid = SocketId {
                proto: v
                    .get("proto")
                    .and_then(|x| x.as_str())
                    .unwrap_or("?")
                    .to_string(),
                local_addr: v
                    .get("local_addr")
                    .and_then(|x| x.as_str())
                    .unwrap_or("?")
                    .to_string(),
                foreign_addr: v
                    .get("foreign_addr")
                    .and_then(|x| x.as_str())
                    .unwrap_or("?")
                    .to_string(),
            };
            g.sockets.push(SocketNode {
                id: sid,
                state: v.get("state").and_then(|x| x.as_str()).map(String::from),
                process_name: v
                    .get("process_name")
                    .and_then(|x| x.as_str())
                    .map(String::from),
                pid_at_open: v
                    .get("pid_at_open")
                    .and_then(|x| x.as_u64())
                    .and_then(|n| u32::try_from(n).ok()),
                opened: Timestamp {
                    mono_ns: first_seen as u64,
                    wall_anchor_ns: 0,
                },
                closed: if last_seen > first_seen {
                    Some(Timestamp {
                        mono_ns: last_seen as u64,
                        wall_anchor_ns: 0,
                    })
                } else {
                    None
                },
                rxbytes_last: v.get("rxbytes_last").and_then(|x| x.as_u64()),
                txbytes_last: v.get("txbytes_last").and_then(|x| x.as_u64()),
            });
        }

        // Files
        let mut stmt = self
            .conn
            .prepare("SELECT id, attrs, first_seen, last_seen FROM nodes WHERE kind = 'file'")?;
        let rows = stmt.query_map([], |r| {
            let id: String = r.get(0)?;
            let attrs: String = r.get(1)?;
            let first_seen: i64 = r.get(2)?;
            let last_seen: i64 = r.get(3)?;
            Ok((id, attrs, first_seen, last_seen))
        })?;
        for row in rows {
            let (path, attrs, first_seen, last_seen) = row?;
            let v: serde_json::Value = serde_json::from_str(&attrs)?;
            let flags: Vec<String> = v
                .get("flags")
                .cloned()
                .and_then(|x| serde_json::from_value(x).ok())
                .unwrap_or_default();
            g.files.push(FileNode {
                path,
                flags,
                first_seen: Timestamp {
                    mono_ns: first_seen as u64,
                    wall_anchor_ns: 0,
                },
                last_seen: Timestamp {
                    mono_ns: last_seen as u64,
                    wall_anchor_ns: 0,
                },
                touch_count: v.get("touch_count").and_then(|x| x.as_u64()).unwrap_or(0),
            });
        }

        // Domains
        let mut stmt = self
            .conn
            .prepare("SELECT id, attrs, first_seen, last_seen FROM nodes WHERE kind = 'domain'")?;
        let rows = stmt.query_map([], |r| {
            let id: String = r.get(0)?;
            let attrs: String = r.get(1)?;
            let first_seen: i64 = r.get(2)?;
            let last_seen: i64 = r.get(3)?;
            Ok((id, attrs, first_seen, last_seen))
        })?;
        for row in rows {
            let (name, attrs, first_seen, last_seen) = row?;
            g.domains
                .push(domain_from_row((name, attrs, first_seen, last_seen))?);
        }

        // Edges
        let mut stmt = self
            .conn
            .prepare("SELECT kind, from_kind, from_id, to_kind, to_id, attrs FROM edges")?;
        let rows = stmt.query_map([], |r| {
            let kind: String = r.get(0)?;
            let from_kind: String = r.get(1)?;
            let from_id: String = r.get(2)?;
            let to_kind: String = r.get(3)?;
            let to_id: String = r.get(4)?;
            let attrs: String = r.get(5)?;
            Ok((kind, from_kind, from_id, to_kind, to_id, attrs))
        })?;
        for row in rows {
            let (kind, _fk, from_id, _tk, to_id, attrs) = row?;
            match kind.as_str() {
                "parent_of" => {
                    g.edges.push(Edge::ParentOf {
                        parent: process_id_from_string(&from_id),
                        child: process_id_from_string(&to_id),
                    });
                }
                "frontmost_during" => {
                    let v: serde_json::Value = serde_json::from_str(&attrs)?;
                    let overlap: Interval = v
                        .get("overlap")
                        .cloned()
                        .and_then(|x| serde_json::from_value(x).ok())
                        .unwrap_or(Interval {
                            from: Timestamp {
                                mono_ns: 0,
                                wall_anchor_ns: 0,
                            },
                            to: None,
                        });
                    g.edges.push(Edge::FrontmostDuring {
                        app: from_id,
                        process: process_id_from_string(&to_id),
                        overlap,
                    });
                }
                "opened_socket" => {
                    // Re-parse socket id (we stored "proto|local|foreign").
                    let parts: Vec<&str> = to_id.splitn(3, '|').collect();
                    if parts.len() != 3 {
                        continue;
                    }
                    g.edges.push(Edge::OpenedSocket {
                        process: process_id_from_string(&from_id),
                        socket: SocketId {
                            proto: parts[0].into(),
                            local_addr: parts[1].into(),
                            foreign_addr: parts[2].into(),
                        },
                    });
                }
                "queried_domain" => {
                    let v: serde_json::Value = serde_json::from_str(&attrs)?;
                    g.edges.push(Edge::QueriedDomain {
                        process: process_id_from_string(&from_id),
                        domain: to_id,
                        count: v.get("queries").and_then(|x| x.as_u64()).unwrap_or(1),
                    });
                }
                other => {
                    tracing::warn!("aw-store::load_graph: unknown edge kind '{other}'; skipping");
                }
            }
        }

        Ok(g)
    }

    /// Convenience: list processes whose `last_seen` is at or after `since_ns`.
    pub fn processes_seen_since(&self, since_ns: u64) -> Result<Vec<ProcessNode>> {
        let g = self.load_graph()?;
        Ok(g.processes
            .into_iter()
            .filter(|p| (p.death.unwrap_or(p.birth).mono_ns) >= since_ns)
            .collect())
    }

    /// Suspicion query: root-owned processes whose parent is a non-root user
    /// process. A classic privilege-escalation shape — `sudo` is the expected
    /// boring case, anything else warrants a look.
    ///
    /// The join is across the `parent_of` edge table; uid comparison happens
    /// on the JSON `attrs` payload of each end.
    ///
    /// `since_unix_ns` restricts to children active at/after that time
    /// (their `last_seen` column); pass `0` for all-time.
    pub fn processes_root_under_user_parent(&self, since_unix_ns: i64) -> Result<Vec<ProcessNode>> {
        let mut stmt = self.conn.prepare(
            "SELECT child.id, child.attrs, child.first_seen, child.last_seen
             FROM edges e
             JOIN nodes child  ON child.kind  = 'process' AND child.id  = e.to_id
             JOIN nodes parent ON parent.kind = 'process' AND parent.id = e.from_id
             WHERE e.kind = 'parent_of'
               AND child.last_seen >= ?1
               AND CAST(json_extract(child.attrs,  '$.uid') AS INTEGER) = 0
               AND CAST(json_extract(parent.attrs, '$.uid') AS INTEGER) > 0",
        )?;
        let rows = stmt.query_map(params![since_unix_ns], row_to_process_tuple)?;
        let mut out = Vec::new();
        for row in rows {
            out.push(process_from_row(row?)?);
        }
        Ok(out)
    }

    /// Suspicion query: processes whose `exec_path` does not begin with any
    /// of the allowed prefixes. Lets the agent supply its own policy of
    /// "trusted locations" (e.g. `/usr/bin/`, `/System/`, `/Applications/`)
    /// without baking it into the store.
    ///
    /// Processes with no `exec_path` at all are returned (we can't vouch for
    /// them either). Empty `allowed_prefixes` is treated as "everything is
    /// untrusted" and returns every process with an exec_path.
    ///
    /// `since_unix_ns` restricts to processes active at/after that time.
    /// Filtered on the raw `last_seen` column — `ProcessNode` doesn't carry
    /// it, and `death` is `None` for still-alive processes, so a node-level
    /// filter would wrongly drop active long-lived processes. Pass `0` for
    /// all-time.
    pub fn processes_outside_paths(
        &self,
        allowed_prefixes: &[&str],
        since_unix_ns: i64,
    ) -> Result<Vec<ProcessNode>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, attrs, first_seen, last_seen FROM nodes
             WHERE kind = 'process' AND last_seen >= ?1",
        )?;
        let rows = stmt.query_map(params![since_unix_ns], row_to_process_tuple)?;
        let mut out = Vec::new();
        for row in rows {
            let tuple = row?;
            let p = process_from_row(tuple)?;
            let trusted = match p.exec_path.as_deref() {
                None => false, // unknown path is not "trusted"
                Some(path) => allowed_prefixes
                    .iter()
                    .any(|prefix| path.starts_with(prefix)),
            };
            if !trusted {
                out.push(p);
            }
        }
        Ok(out)
    }

    // ---------- batch 2 graph queries ------------------------------------
    //
    // These four methods give agents windowed and surface-area queries
    // beyond the per-process suspicion checks. Conventions:
    //
    // - `from_unix_ns` / `to_unix_ns` are **wall-clock unix nanoseconds**,
    //   matching the encoding of the `first_seen` / `last_seen` columns
    //   (see `ts_to_unix_ns`). Use `wall_anchor + mono_ns` when calling
    //   from in-flight code; for round-tripped timestamps the
    //   `wall_anchor` is `0` and `mono_ns` is already unix nanos.
    // - Windows are inclusive on both ends and use "overlap" semantics:
    //   a node is in the window if `first_seen <= to AND last_seen >= from`.
    //   This matches the operator intuition that "things alive during the
    //   window count" even if they began before it.

    /// Materialize the slice of the graph whose nodes overlap
    /// `[from_unix_ns, to_unix_ns]`. Edges are included iff both endpoints
    /// survived the node filter. Cheap because `idx_nodes_last_seen` /
    /// `idx_edges_last_seen` carry the heavy lifting.
    pub fn graph_in_window(&self, from_unix_ns: i64, to_unix_ns: i64) -> Result<Graph> {
        let mut g = Graph::default();

        // Helper to read a (kind, id, attrs, first_seen, last_seen) projection
        // bounded by the window. Returns rows the caller will project further.
        let load_kind = |kind: &str| -> Result<Vec<(String, String, i64, i64)>> {
            let mut stmt = self.conn.prepare(
                "SELECT id, attrs, first_seen, last_seen FROM nodes
                 WHERE kind = ?1 AND first_seen <= ?2 AND last_seen >= ?3",
            )?;
            let rows = stmt.query_map(params![kind, to_unix_ns, from_unix_ns], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, i64>(2)?,
                    r.get::<_, i64>(3)?,
                ))
            })?;
            let mut out = Vec::new();
            for row in rows {
                out.push(row?);
            }
            Ok(out)
        };

        for (id_str, attrs, first_seen, last_seen) in load_kind("process")? {
            g.processes
                .push(process_from_row((id_str, attrs, first_seen, last_seen))?);
        }
        for (id, attrs, _first_seen, _last_seen) in load_kind("app")? {
            let v: serde_json::Value = serde_json::from_str(&attrs)?;
            let intervals: Vec<Interval> = v
                .get("intervals")
                .cloned()
                .and_then(|x| serde_json::from_value(x).ok())
                .unwrap_or_default();
            g.apps.push(AppNode {
                id,
                name: v.get("name").and_then(|x| x.as_str()).map(String::from),
                exec_path: v
                    .get("exec_path")
                    .and_then(|x| x.as_str())
                    .map(String::from),
                intervals,
            });
        }
        for (_id, attrs, first_seen, last_seen) in load_kind("socket")? {
            let v: serde_json::Value = serde_json::from_str(&attrs)?;
            let sid = SocketId {
                proto: v
                    .get("proto")
                    .and_then(|x| x.as_str())
                    .unwrap_or("?")
                    .to_string(),
                local_addr: v
                    .get("local_addr")
                    .and_then(|x| x.as_str())
                    .unwrap_or("?")
                    .to_string(),
                foreign_addr: v
                    .get("foreign_addr")
                    .and_then(|x| x.as_str())
                    .unwrap_or("?")
                    .to_string(),
            };
            g.sockets.push(SocketNode {
                id: sid,
                state: v.get("state").and_then(|x| x.as_str()).map(String::from),
                process_name: v
                    .get("process_name")
                    .and_then(|x| x.as_str())
                    .map(String::from),
                pid_at_open: v
                    .get("pid_at_open")
                    .and_then(|x| x.as_u64())
                    .and_then(|n| u32::try_from(n).ok()),
                opened: Timestamp {
                    mono_ns: first_seen as u64,
                    wall_anchor_ns: 0,
                },
                closed: if last_seen > first_seen {
                    Some(Timestamp {
                        mono_ns: last_seen as u64,
                        wall_anchor_ns: 0,
                    })
                } else {
                    None
                },
                rxbytes_last: v.get("rxbytes_last").and_then(|x| x.as_u64()),
                txbytes_last: v.get("txbytes_last").and_then(|x| x.as_u64()),
            });
        }
        for (path, attrs, first_seen, last_seen) in load_kind("file")? {
            let v: serde_json::Value = serde_json::from_str(&attrs)?;
            let flags: Vec<String> = v
                .get("flags")
                .cloned()
                .and_then(|x| serde_json::from_value(x).ok())
                .unwrap_or_default();
            g.files.push(FileNode {
                path,
                flags,
                first_seen: Timestamp {
                    mono_ns: first_seen as u64,
                    wall_anchor_ns: 0,
                },
                last_seen: Timestamp {
                    mono_ns: last_seen as u64,
                    wall_anchor_ns: 0,
                },
                touch_count: v.get("touch_count").and_then(|x| x.as_u64()).unwrap_or(0),
            });
        }

        for (name, attrs, first_seen, last_seen) in load_kind("domain")? {
            g.domains
                .push(domain_from_row((name, attrs, first_seen, last_seen))?);
        }

        // Build a quick membership set so we can drop edges whose endpoints
        // fell outside the window. Cheaper than re-issuing per-edge node
        // existence queries and bounds the edge set without trusting the
        // edges' own `last_seen` column.
        let mut have: std::collections::HashSet<(String, String)> =
            std::collections::HashSet::new();
        for p in &g.processes {
            have.insert(("process".into(), process_id_to_string(&p.id)));
        }
        for a in &g.apps {
            have.insert(("app".into(), a.id.clone()));
        }
        for s in &g.sockets {
            have.insert(("socket".into(), socket_id_to_string(&s.id)));
        }
        for f in &g.files {
            have.insert(("file".into(), f.path.clone()));
        }
        for d in &g.domains {
            have.insert(("domain".into(), d.name.clone()));
        }

        let mut stmt = self
            .conn
            .prepare("SELECT kind, from_kind, from_id, to_kind, to_id, attrs FROM edges")?;
        let rows = stmt.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, String>(4)?,
                r.get::<_, String>(5)?,
            ))
        })?;
        for row in rows {
            let (kind, from_kind, from_id, to_kind, to_id, attrs) = row?;
            if !have.contains(&(from_kind.clone(), from_id.clone())) {
                continue;
            }
            if !have.contains(&(to_kind.clone(), to_id.clone())) {
                continue;
            }
            match kind.as_str() {
                "parent_of" => g.edges.push(Edge::ParentOf {
                    parent: process_id_from_string(&from_id),
                    child: process_id_from_string(&to_id),
                }),
                "frontmost_during" => {
                    let v: serde_json::Value = serde_json::from_str(&attrs)?;
                    let overlap: Interval = v
                        .get("overlap")
                        .cloned()
                        .and_then(|x| serde_json::from_value(x).ok())
                        .unwrap_or(Interval {
                            from: Timestamp {
                                mono_ns: 0,
                                wall_anchor_ns: 0,
                            },
                            to: None,
                        });
                    g.edges.push(Edge::FrontmostDuring {
                        app: from_id,
                        process: process_id_from_string(&to_id),
                        overlap,
                    });
                }
                "opened_socket" => {
                    let parts: Vec<&str> = to_id.splitn(3, '|').collect();
                    if parts.len() != 3 {
                        continue;
                    }
                    g.edges.push(Edge::OpenedSocket {
                        process: process_id_from_string(&from_id),
                        socket: SocketId {
                            proto: parts[0].into(),
                            local_addr: parts[1].into(),
                            foreign_addr: parts[2].into(),
                        },
                    });
                }
                "queried_domain" => {
                    let v: serde_json::Value = serde_json::from_str(&attrs)?;
                    g.edges.push(Edge::QueriedDomain {
                        process: process_id_from_string(&from_id),
                        domain: to_id,
                        count: v.get("queries").and_then(|x| x.as_u64()).unwrap_or(1),
                    });
                }
                _ => {}
            }
        }
        Ok(g)
    }

    /// Aggregate socket nodes by `foreign_addr`. Returns the top N by total
    /// bytes (`rxbytes_last + txbytes_last`), descending. Distinct-process
    /// count is computed from the `pid_at_open` field.
    ///
    /// Use this from `network_reviewer` to skip re-aggregating raw events:
    /// the store already has every socket and its byte totals.
    pub fn top_endpoints_by_bytes(&self, limit: usize) -> Result<Vec<EndpointSummary>> {
        let mut stmt = self.conn.prepare(
            "SELECT
                 json_extract(attrs, '$.foreign_addr')  AS foreign_addr,
                 SUM(COALESCE(CAST(json_extract(attrs, '$.rxbytes_last') AS INTEGER), 0) +
                     COALESCE(CAST(json_extract(attrs, '$.txbytes_last') AS INTEGER), 0)) AS total_bytes,
                 COUNT(DISTINCT json_extract(attrs, '$.pid_at_open')) AS distinct_processes,
                 COUNT(*) AS connection_count
             FROM nodes
             WHERE kind = 'socket'
             GROUP BY foreign_addr
             ORDER BY total_bytes DESC
             LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![limit as i64], |r| {
            Ok(EndpointSummary {
                foreign_addr: r.get::<_, Option<String>>(0)?.unwrap_or_else(|| "?".into()),
                total_bytes: r.get::<_, i64>(1)?.max(0) as u64,
                distinct_processes: r.get::<_, i64>(2)?.max(0) as u32,
                connection_count: r.get::<_, i64>(3)?.max(0) as u32,
            })
        })?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    /// Return every (app, frontmost-process) overlap window that intersects
    /// `[from_unix_ns, to_unix_ns]`. Each row carries the app name + bundle
    /// id, the process that was in the foreground, the overlap's start and
    /// end in unix nanoseconds (clipped to the requested window), and the
    /// clipped duration in seconds.
    ///
    /// Lets `timeline_narrator` turn into a thin SQL-driven prose generator:
    /// pull these rows, render "you spent ~12m in Code, then 3m in Chrome".
    pub fn focus_segments_in_window(
        &self,
        from_unix_ns: i64,
        to_unix_ns: i64,
    ) -> Result<Vec<FocusSegment>> {
        // Pull edges + the app's display name from its node attrs. The
        // overlap interval is stored on the edge as a serialized
        // `Interval { from: Timestamp, to: Option<Timestamp> }`; we extract
        // the two fields via `json_extract` to keep filtering in SQL.
        //
        // `overlap.to` may be null (still frontmost at end-of-capture); in
        // that case we clip to `to_unix_ns` so the segment isn't infinite.
        let mut stmt = self.conn.prepare(
            "SELECT
                 e.from_id                                        AS app_id,
                 json_extract(app.attrs, '$.name')                AS app_name,
                 e.to_id                                          AS process_id,
                 CAST(json_extract(e.attrs, '$.overlap.from.mono_ns')        AS INTEGER) AS from_mono,
                 CAST(json_extract(e.attrs, '$.overlap.from.wall_anchor_ns') AS INTEGER) AS from_anchor,
                 CAST(json_extract(e.attrs, '$.overlap.to.mono_ns')          AS INTEGER) AS to_mono,
                 CAST(json_extract(e.attrs, '$.overlap.to.wall_anchor_ns')   AS INTEGER) AS to_anchor
             FROM edges e
             LEFT JOIN nodes app ON app.kind = 'app' AND app.id = e.from_id
             WHERE e.kind = 'frontmost_during'",
        )?;
        let raw = stmt.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, Option<String>>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, Option<i64>>(3)?,
                r.get::<_, Option<i64>>(4)?,
                r.get::<_, Option<i64>>(5)?,
                r.get::<_, Option<i64>>(6)?,
            ))
        })?;

        let mut out = Vec::new();
        for row in raw {
            let (app_id, app_name, process_id, from_mono, from_anchor, to_mono, to_anchor) = row?;
            // overlap.from is required; if it's missing the row is malformed
            // and we skip rather than guess.
            let Some(from_mono) = from_mono else {
                continue;
            };
            // For round-tripped graphs `wall_anchor_ns` may be 0, in which
            // case `mono_ns` is itself the unix-ns timestamp (same convention
            // as `ts_to_unix_ns` on the write side).
            let seg_from = combine_ts(from_mono, from_anchor.unwrap_or(0));
            let seg_to = match to_mono {
                Some(m) => combine_ts(m, to_anchor.unwrap_or(0)),
                None => to_unix_ns, // open-ended → clip to window end
            };
            // Overlap test against the requested window.
            if seg_to < from_unix_ns || seg_from > to_unix_ns {
                continue;
            }
            let clipped_from = seg_from.max(from_unix_ns);
            let clipped_to = seg_to.min(to_unix_ns);
            let duration_secs =
                (clipped_to.saturating_sub(clipped_from) / 1_000_000_000).max(0) as u64;
            // Bundle id is the edge's `from_id` (apps are keyed by bundle).
            out.push(FocusSegment {
                app_id: app_id.clone(),
                app_name: app_name.unwrap_or_else(|| app_id.clone()),
                process_pid: process_id_from_string(&process_id).pid,
                from_unix_ns: clipped_from,
                to_unix_ns: clipped_to,
                duration_secs,
            });
        }
        // Chronological order is what callers want for narration.
        out.sort_by_key(|s| s.from_unix_ns);
        Ok(out)
    }

    /// Walk `parent_of` edges upward from `pid_id` (formatted as
    /// `"pid:start_unix_secs"` — same encoding as `process_id_to_string`)
    /// up to `max_depth` hops, ordered child → root. Returns at most
    /// `max_depth` ancestors; stops early at a cycle or when no parent
    /// edge exists.
    ///
    /// Implemented as a recursive CTE so SQLite walks the chain in one
    /// query rather than per-hop round-trips.
    pub fn ancestors_of(&self, pid_id: &str, max_depth: u32) -> Result<Vec<ProcessNode>> {
        if max_depth == 0 {
            return Ok(Vec::new());
        }
        let mut stmt = self.conn.prepare(
            "WITH RECURSIVE chain(id, depth) AS (
                 SELECT e.from_id, 1
                   FROM edges e
                  WHERE e.kind = 'parent_of' AND e.to_id = ?1
                 UNION ALL
                 SELECT e.from_id, c.depth + 1
                   FROM edges e
                   JOIN chain  c ON e.to_id = c.id
                  WHERE e.kind = 'parent_of' AND c.depth < ?2
             )
             SELECT n.id, n.attrs, n.first_seen, n.last_seen, c.depth
               FROM chain c
               JOIN nodes n ON n.kind = 'process' AND n.id = c.id
              ORDER BY c.depth ASC",
        )?;
        let rows = stmt.query_map(params![pid_id, max_depth as i64], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, i64>(2)?,
                r.get::<_, i64>(3)?,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            out.push(process_from_row(row?)?);
        }
        Ok(out)
    }

    /// Suspicion query: parent processes whose child count is at least
    /// `min_children`. Useful for spotting fork bombs, shells running long
    /// scripts, or unusual fan-out from a process that normally doesn't
    /// spawn anything.
    ///
    /// Returns `(parent_process, child_count)` pairs, sorted by descending
    /// child count.
    ///
    /// `since_unix_ns` counts only children active at/after that time (their
    /// `last_seen` column), so a long-lived parent isn't flagged forever on
    /// the strength of children it spawned hours ago. Pass `0` for all-time.
    pub fn parents_with_many_children(
        &self,
        min_children: u32,
        since_unix_ns: i64,
    ) -> Result<Vec<(ProcessNode, u32)>> {
        let mut stmt = self.conn.prepare(
            "SELECT parent.id, parent.attrs, parent.first_seen, parent.last_seen, COUNT(*) AS n
             FROM edges e
             JOIN nodes parent ON parent.kind = 'process' AND parent.id = e.from_id
             JOIN nodes child  ON child.kind  = 'process' AND child.id  = e.to_id
             WHERE e.kind = 'parent_of'
               AND child.last_seen >= ?2
             GROUP BY parent.id
             HAVING n >= ?1
             ORDER BY n DESC",
        )?;
        let rows = stmt.query_map(params![min_children, since_unix_ns], |r| {
            let id: String = r.get(0)?;
            let attrs: String = r.get(1)?;
            let first_seen: i64 = r.get(2)?;
            let last_seen: i64 = r.get(3)?;
            let n: i64 = r.get(4)?;
            Ok(((id, attrs, first_seen, last_seen), n as u32))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (tuple, n) = row?;
            out.push((process_from_row(tuple)?, n));
        }
        Ok(out)
    }

    /// Top N domains by query count, descending. Distinct-process counts come
    /// from `queried_domain` edges (0 when no query could be attributed to a
    /// process).
    pub fn top_domains(&self, limit: usize) -> Result<Vec<DomainSummary>> {
        let mut stmt = self.conn.prepare(
            "SELECT
                 n.id,
                 COALESCE(CAST(json_extract(n.attrs, '$.query_count') AS INTEGER), 0) AS query_count,
                 (SELECT COUNT(DISTINCT e.from_id) FROM edges e
                   WHERE e.kind = 'queried_domain' AND e.to_id = n.id) AS distinct_processes,
                 n.last_seen
             FROM nodes n
             WHERE n.kind = 'domain'
             ORDER BY query_count DESC
             LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![limit as i64], |r| {
            Ok(DomainSummary {
                name: r.get::<_, String>(0)?,
                query_count: r.get::<_, i64>(1)?.max(0) as u64,
                distinct_processes: r.get::<_, i64>(2)?.max(0) as u32,
                last_seen_unix_ns: r.get::<_, i64>(3)?,
            })
        })?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    /// Entities whose first-ever `first_seen` is at/after `from_unix_ns` —
    /// i.e. never observed before that moment. Correct because `upsert_node`
    /// maintains `first_seen` with `MIN()`, so a re-observed entity keeps its
    /// original first sighting and can never re-qualify as new.
    ///
    /// The novelty horizon equals the retention horizon: an entity pruned by
    /// `prune_before` and later re-observed legitimately reports as new
    /// ("new within the retention window") — intended semantics.
    ///
    /// Lists are capped at [`NOVELTY_CAP_PER_KIND`], oldest first.
    pub fn novel_since(&self, from_unix_ns: i64) -> Result<NoveltyReport> {
        let cap = NOVELTY_CAP_PER_KIND as i64;
        let mut report = NoveltyReport::default();

        // Process node ids are one row per run (pid:start_secs), so collapse
        // by identity; the identity is new only if its EARLIEST run is.
        let mut stmt = self.conn.prepare(
            "SELECT json_extract(attrs, '$.comm')      AS comm,
                    json_extract(attrs, '$.exec_path') AS exec_path,
                    MIN(first_seen)                    AS first_ever,
                    COUNT(*)                           AS instances
             FROM nodes
             WHERE kind = 'process'
             GROUP BY comm, exec_path
             HAVING MIN(first_seen) >= ?1
                AND (comm IS NOT NULL OR exec_path IS NOT NULL)
             ORDER BY first_ever ASC
             LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![from_unix_ns, cap], |r| {
            Ok(NewProcessIdentity {
                comm: r.get(0)?,
                exec_path: r.get(1)?,
                first_seen_unix_ns: r.get(2)?,
                instances: r.get::<_, i64>(3)?.max(0) as u32,
            })
        })?;
        for row in rows {
            report.new_processes.push(row?);
        }

        // Domain node ids ARE the name and are stable per name, so the
        // node's own first_seen suffices. Masked names are hashes — noise in
        // prose — so they're excluded.
        let mut stmt = self.conn.prepare(
            "SELECT id FROM nodes
             WHERE kind = 'domain'
               AND first_seen >= ?1
               AND COALESCE(json_extract(attrs, '$.masked'), 0) = 0
             ORDER BY first_seen ASC
             LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![from_unix_ns, cap], |r| r.get::<_, String>(0))?;
        for row in rows {
            report.new_domains.push(row?);
        }

        // Socket node ids are PER-CONNECTION (proto|local|foreign): a repeat
        // connection to a known host creates a brand-new node with a fresh
        // first_seen. Group by the foreign endpoint and take MIN over the
        // group — the endpoint is new only if its earliest socket is.
        let mut stmt = self.conn.prepare(
            "SELECT json_extract(attrs, '$.foreign_addr')      AS fa,
                    MIN(first_seen)                            AS first_ever,
                    COUNT(*)                                   AS socket_count,
                    MAX(json_extract(attrs, '$.process_name')) AS example_process
             FROM nodes
             WHERE kind = 'socket'
               AND json_extract(attrs, '$.foreign_addr') IS NOT NULL
             GROUP BY fa
             HAVING MIN(first_seen) >= ?1
             ORDER BY first_ever ASC
             LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![from_unix_ns, cap], |r| {
            Ok(NewEndpoint {
                foreign_addr: r.get(0)?,
                first_seen_unix_ns: r.get(1)?,
                socket_count: r.get::<_, i64>(2)?.max(0) as u32,
                example_process: r.get(3)?,
            })
        })?;
        for row in rows {
            report.new_endpoints.push(row?);
        }

        // App ids are bundle ids — stable per app.
        let mut stmt = self.conn.prepare(
            "SELECT id, json_extract(attrs, '$.name') AS name
             FROM nodes
             WHERE kind = 'app' AND first_seen >= ?1
             ORDER BY first_seen ASC
             LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![from_unix_ns, cap], |r| {
            Ok(NewApp {
                id: r.get(0)?,
                name: r.get(1)?,
            })
        })?;
        for row in rows {
            report.new_apps.push(row?);
        }

        report.oldest_first_seen_unix_ns =
            self.conn
                .query_row("SELECT MIN(first_seen) FROM nodes", [], |r| r.get(0))?;

        Ok(report)
    }

    /// Append Layer 2 events to the durable history table. Unlike the graph
    /// tables this grows with event volume, not entity count — `prune_before`
    /// is the corresponding bound. Timestamps are stored as wall-clock unix
    /// nanoseconds (same convention as node/edge columns). Returns the number
    /// of rows written.
    pub fn append_events(&mut self, events: &[Event]) -> Result<u64> {
        let tx = self.conn.transaction()?;
        let mut written = 0u64;
        {
            let mut stmt = tx.prepare_cached(
                "INSERT INTO events(ts_unix_ns, kind, pid, schema_version, payload)
                 VALUES(?1, ?2, ?3, ?4, ?5)",
            )?;
            for ev in events {
                let ts = ts_to_unix_ns(ev.timestamp) as i64;
                let kind = event_kind_to_string(ev.kind)?;
                let payload = serde_json::to_string(&ev.payload)?;
                stmt.execute(params![ts, kind, ev.pid, ev.schema_version, payload])?;
                written += 1;
            }
        }
        tx.commit()?;
        Ok(written)
    }

    /// Read back events whose timestamp falls in `[from_unix_ns, to_unix_ns]`,
    /// oldest first, optionally filtered to `kinds`, capped at `limit` rows.
    /// Round-tripped events carry the unix-ns value in `timestamp.mono_ns`
    /// with a zero anchor — the same convention as graph round-trips.
    pub fn events_in_window(
        &self,
        from_unix_ns: i64,
        to_unix_ns: i64,
        kinds: Option<&[EventKind]>,
        limit: usize,
    ) -> Result<Vec<Event>> {
        // The kind filter is applied in Rust rather than SQL to keep the
        // statement static; event volume in a window is already bounded by
        // the time predicate + index.
        let mut stmt = self.conn.prepare(
            "SELECT ts_unix_ns, kind, pid, schema_version, payload
             FROM events
             WHERE ts_unix_ns >= ?1 AND ts_unix_ns <= ?2
             ORDER BY ts_unix_ns ASC",
        )?;
        let rows = stmt.query_map(params![from_unix_ns, to_unix_ns], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, Option<u32>>(2)?,
                r.get::<_, u32>(3)?,
                r.get::<_, String>(4)?,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            if out.len() >= limit {
                break;
            }
            let (ts, kind_str, pid, schema_version, payload) = row?;
            let Ok(kind) = event_kind_from_string(&kind_str) else {
                tracing::warn!(
                    "aw-store::events_in_window: unknown event kind '{kind_str}'; skipping"
                );
                continue;
            };
            if let Some(ks) = kinds {
                if !ks.contains(&kind) {
                    continue;
                }
            }
            out.push(Event {
                schema_version,
                timestamp: Timestamp {
                    mono_ns: ts as u64,
                    wall_anchor_ns: 0,
                },
                kind,
                pid,
                payload: serde_json::from_str(&payload)?,
            });
        }
        Ok(out)
    }

    /// Mechanical aggregate: per-kind event counts bucketed by UTC hour of
    /// day, over everything at or after `from_unix_ns`. Pure counting — no
    /// thresholds, no interpretation; the apps layer turns this into
    /// hour-of-day frequency profiles.
    pub fn event_hourly_profile(&self, from_unix_ns: i64) -> Result<Vec<HourlyKindCount>> {
        let mut stmt = self.conn.prepare(
            "SELECT kind, (ts_unix_ns / 3600000000000) % 24 AS hod, COUNT(*)
             FROM events
             WHERE ts_unix_ns >= ?1
             GROUP BY kind, hod
             ORDER BY kind, hod",
        )?;
        let rows = stmt.query_map(params![from_unix_ns], |r| {
            Ok(HourlyKindCount {
                kind: r.get(0)?,
                hour_of_day: r.get::<_, i64>(1)? as u8,
                count: r.get::<_, i64>(2)? as u64,
            })
        })?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(Into::into)
    }

    /// Mechanical aggregate: for events of `kind` at or after `from_unix_ns`,
    /// count occurrences of each distinct string value of payload field
    /// `json_field` per `window_ns`-wide time bucket. Rows with the field
    /// absent are skipped. E.g. per-hour counts of `process_death.comm` or
    /// `dns_query.process_name` — the raw material for per-entity baselines.
    pub fn event_field_window_counts(
        &self,
        kind: EventKind,
        json_field: &str,
        from_unix_ns: i64,
        window_ns: i64,
    ) -> Result<Vec<FieldWindowCount>> {
        let kind = event_kind_to_string(kind)?;
        let path = format!("$.{json_field}");
        let mut stmt = self.conn.prepare(
            "SELECT json_extract(payload, ?4) AS v,
                    (ts_unix_ns / ?3) * ?3 AS win,
                    COUNT(*)
             FROM events
             WHERE kind = ?1 AND ts_unix_ns >= ?2
               AND json_extract(payload, ?4) IS NOT NULL
             GROUP BY v, win
             ORDER BY v, win",
        )?;
        let rows = stmt.query_map(params![kind, from_unix_ns, window_ns, path], |r| {
            Ok(FieldWindowCount {
                value: r.get(0)?,
                window_start_unix_ns: r.get(1)?,
                count: r.get::<_, i64>(2)? as u64,
            })
        })?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(Into::into)
    }

    /// Mechanical aggregate: every edge of `kind` with its raw observation
    /// tally and observed lifespan, straight off existing columns. Lifetime
    /// rate = `count / (last_seen - first_seen)` is computed by the caller.
    pub fn edge_rates(&self, kind: &str) -> Result<Vec<EdgeRate>> {
        let mut stmt = self.conn.prepare(
            "SELECT from_id, to_id, count, first_seen, last_seen
             FROM edges
             WHERE kind = ?1",
        )?;
        let rows = stmt.query_map(params![kind], |r| {
            Ok(EdgeRate {
                from_id: r.get(0)?,
                to_id: r.get(1)?,
                count: r.get::<_, i64>(2)? as u64,
                first_seen_unix_ns: r.get(3)?,
                last_seen_unix_ns: r.get(4)?,
            })
        })?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(Into::into)
    }

    /// Retention: delete every node and edge whose `last_seen` is strictly
    /// before `cutoff_unix_ns`, any edge left dangling because one of its
    /// endpoints was deleted, and every event older than the cutoff. The
    /// store is otherwise append-only, so this is the one sanctioned way to
    /// bound a long-lived `world.db`.
    pub fn prune_before(&mut self, cutoff_unix_ns: i64) -> Result<PruneReport> {
        let tx = self.conn.transaction()?;
        let events_deleted = tx.execute(
            "DELETE FROM events WHERE ts_unix_ns < ?1",
            params![cutoff_unix_ns],
        )?;
        let edges_by_age = tx.execute(
            "DELETE FROM edges WHERE last_seen < ?1",
            params![cutoff_unix_ns],
        )?;
        let nodes_deleted = tx.execute(
            "DELETE FROM nodes WHERE last_seen < ?1",
            params![cutoff_unix_ns],
        )?;
        // Surviving edges may now reference deleted nodes; drop them too so
        // load_graph never materializes an edge with a missing endpoint.
        let edges_dangling = tx.execute(
            "DELETE FROM edges
             WHERE NOT EXISTS (SELECT 1 FROM nodes n
                               WHERE n.kind = edges.from_kind AND n.id = edges.from_id)
                OR NOT EXISTS (SELECT 1 FROM nodes n
                               WHERE n.kind = edges.to_kind AND n.id = edges.to_id)",
            [],
        )?;
        tx.commit()?;
        Ok(PruneReport {
            nodes_deleted: nodes_deleted as u64,
            edges_deleted: (edges_by_age + edges_dangling) as u64,
            events_deleted: events_deleted as u64,
        })
    }

    /// Cheap overview of what the store holds: row counts per node/edge kind
    /// and the wall-clock span covered. Powers `aw-query summary`.
    pub fn summary(&self) -> Result<StoreSummary> {
        let mut out = StoreSummary::default();
        let mut stmt = self
            .conn
            .prepare("SELECT kind, COUNT(*) FROM nodes GROUP BY kind ORDER BY COUNT(*) DESC")?;
        let rows = stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))?;
        for row in rows {
            let (kind, n) = row?;
            out.node_counts.push((kind, n.max(0) as u64));
        }
        let mut stmt = self
            .conn
            .prepare("SELECT kind, COUNT(*) FROM edges GROUP BY kind ORDER BY COUNT(*) DESC")?;
        let rows = stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))?;
        for row in rows {
            let (kind, n) = row?;
            out.edge_counts.push((kind, n.max(0) as u64));
        }
        let (first, last): (Option<i64>, Option<i64>) = self.conn.query_row(
            "SELECT MIN(first_seen), MAX(last_seen) FROM nodes",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        out.first_seen_unix_ns = first;
        out.last_seen_unix_ns = last;
        out.event_count = self
            .conn
            .query_row("SELECT COUNT(*) FROM events", [], |r| r.get::<_, i64>(0))?
            .max(0) as u64;
        Ok(out)
    }
}

// Shape of a `nodes` SELECT we project into `ProcessNode`: (id, attrs, first_seen, last_seen).
type ProcessRow = (String, String, i64, i64);

fn row_to_process_tuple(r: &rusqlite::Row<'_>) -> rusqlite::Result<ProcessRow> {
    Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
}

fn process_from_row(row: ProcessRow) -> Result<ProcessNode> {
    let (id_str, attrs, first_seen, _last_seen) = row;
    let pid_id = process_id_from_string(&id_str);
    let v: serde_json::Value = serde_json::from_str(&attrs)?;
    let death_v = v.get("death").cloned().unwrap_or(serde_json::Value::Null);
    let death: Option<Timestamp> = if death_v.is_null() {
        None
    } else {
        serde_json::from_value(death_v).ok()
    };
    Ok(ProcessNode {
        id: pid_id,
        comm: v.get("comm").and_then(|x| x.as_str()).map(String::from),
        name: v.get("name").and_then(|x| x.as_str()).map(String::from),
        exec_path: v
            .get("exec_path")
            .and_then(|x| x.as_str())
            .map(String::from),
        ppid: v
            .get("ppid")
            .and_then(|x| x.as_u64())
            .and_then(|n| u32::try_from(n).ok()),
        uid: v
            .get("uid")
            .and_then(|x| x.as_u64())
            .and_then(|n| u32::try_from(n).ok()),
        birth: Timestamp {
            mono_ns: first_seen as u64,
            wall_anchor_ns: 0,
        },
        death,
    })
}

/// Project a `(id, attrs, first_seen, last_seen)` domain-node row into a
/// `DomainNode`. Shared by `load_graph` and `graph_in_window`.
fn domain_from_row(row: (String, String, i64, i64)) -> Result<DomainNode> {
    let (name, attrs, first_seen, last_seen) = row;
    let v: serde_json::Value = serde_json::from_str(&attrs)?;
    let qtypes: Vec<String> = v
        .get("qtypes")
        .cloned()
        .and_then(|x| serde_json::from_value(x).ok())
        .unwrap_or_default();
    Ok(DomainNode {
        name,
        qtypes,
        masked: v.get("masked").and_then(|x| x.as_bool()).unwrap_or(false),
        first_seen: Timestamp {
            mono_ns: first_seen as u64,
            wall_anchor_ns: 0,
        },
        last_seen: Timestamp {
            mono_ns: last_seen as u64,
            wall_anchor_ns: 0,
        },
        query_count: v.get("query_count").and_then(|x| x.as_u64()).unwrap_or(0),
    })
}

/// `EventKind` ↔ its snake_case serde string, reusing the enum's own serde
/// mapping so the DB encoding can never drift from the wire encoding.
fn event_kind_to_string(kind: EventKind) -> Result<String> {
    match serde_json::to_value(kind)? {
        serde_json::Value::String(s) => Ok(s),
        other => Err(StoreError::Json(serde::de::Error::custom(format!(
            "EventKind serialized to non-string {other}"
        )))),
    }
}

fn event_kind_from_string(s: &str) -> Result<EventKind> {
    Ok(serde_json::from_value(serde_json::Value::String(
        s.to_string(),
    ))?)
}

// ---------- helpers --------------------------------------------------------

fn upsert_node(
    tx: &Transaction<'_>,
    kind: &str,
    id: &str,
    attrs: &str,
    first_seen: Timestamp,
    last_seen: Timestamp,
    report: &mut MergeReport,
) -> Result<()> {
    let first = ts_to_unix_ns(first_seen) as i64;
    let last = ts_to_unix_ns(last_seen) as i64;
    // Pre-check existence inside the transaction so the report can accurately
    // distinguish inserted from updated. Uses the PK index — cheap.
    let existed: bool = tx
        .query_row(
            "SELECT 1 FROM nodes WHERE kind = ?1 AND id = ?2",
            params![kind, id],
            |_| Ok(true),
        )
        .optional()?
        .unwrap_or(false);

    tx.execute(
        "INSERT INTO nodes(kind, id, attrs, first_seen, last_seen)
         VALUES(?1, ?2, ?3, ?4, ?5)
         ON CONFLICT(kind, id) DO UPDATE SET
             attrs      = excluded.attrs,
             last_seen  = MAX(excluded.last_seen, nodes.last_seen),
             first_seen = MIN(excluded.first_seen, nodes.first_seen)",
        params![kind, id, attrs, first, last],
    )?;

    if existed {
        report.nodes_updated += 1;
    } else {
        report.nodes_inserted += 1;
    }
    Ok(())
}

/// Edge upsert parameters. Wrapping these in a struct keeps the function
/// signature manageable and self-documenting at call sites.
struct EdgeRow<'a> {
    kind: &'a str,
    from_kind: &'a str,
    from_id: &'a str,
    to_kind: &'a str,
    to_id: &'a str,
    seen_at: Timestamp,
    attrs: &'a str,
}

fn upsert_edge(tx: &Transaction<'_>, e: EdgeRow<'_>, report: &mut MergeReport) -> Result<()> {
    let seen = ts_to_unix_ns(e.seen_at) as i64;
    // Detect pre-existence so the report counts correctly.
    let existed: bool = tx.query_row(
        "SELECT 1 FROM edges WHERE kind=?1 AND from_kind=?2 AND from_id=?3 AND to_kind=?4 AND to_id=?5",
        params![e.kind, e.from_kind, e.from_id, e.to_kind, e.to_id],
        |_| Ok(true),
    ).optional()?.unwrap_or(false);
    tx.execute(
        "INSERT INTO edges(kind, from_kind, from_id, to_kind, to_id, count, first_seen, last_seen, attrs)
         VALUES(?1, ?2, ?3, ?4, ?5, 1, ?6, ?6, ?7)
         ON CONFLICT(kind, from_kind, from_id, to_kind, to_id) DO UPDATE SET
             count     = edges.count + 1,
             last_seen = MAX(edges.last_seen, excluded.last_seen),
             attrs     = excluded.attrs",
        params![e.kind, e.from_kind, e.from_id, e.to_kind, e.to_id, seen, e.attrs],
    )?;
    if existed {
        report.edges_updated += 1;
    } else {
        report.edges_inserted += 1;
    }
    Ok(())
}

fn node_last_seen(tx: &Transaction<'_>, kind: &str, id: &str) -> Result<Timestamp> {
    let last: Option<i64> = tx
        .query_row(
            "SELECT last_seen FROM nodes WHERE kind=?1 AND id=?2",
            params![kind, id],
            |r| r.get(0),
        )
        .optional()?;
    Ok(Timestamp {
        mono_ns: last.unwrap_or(0) as u64,
        wall_anchor_ns: 0,
    })
}

/// Mirror of [`ts_to_unix_ns`] for fields read back out of `attrs` JSON
/// (where we round-tripped a `Timestamp` rather than the pre-computed
/// unix-ns column). When the anchor is 0 the `mono_ns` field already holds
/// unix nanoseconds (typical for round-tripped data); when non-zero, sum.
fn combine_ts(mono_ns: i64, wall_anchor_ns: i64) -> i64 {
    if wall_anchor_ns == 0 {
        mono_ns
    } else {
        wall_anchor_ns.saturating_add(mono_ns)
    }
}

fn ts_to_unix_ns(ts: Timestamp) -> u64 {
    // Stored timestamps are wall-clock unix nanos. If wall_anchor is unset
    // (in-memory builds during tests), fall back to mono_ns alone.
    if ts.wall_anchor_ns == 0 {
        ts.mono_ns
    } else {
        ts.wall_anchor_ns.saturating_add(ts.mono_ns)
    }
}

fn process_id_to_string(id: &ProcessId) -> String {
    format!("{}:{}", id.pid, id.start_unix_secs)
}

fn process_id_from_string(s: &str) -> ProcessId {
    let (pid, start) = s.split_once(':').unwrap_or((s, "0"));
    ProcessId {
        pid: pid.parse().unwrap_or(0),
        start_unix_secs: start.parse().unwrap_or(0),
    }
}

fn socket_id_to_string(id: &SocketId) -> String {
    format!("{}|{}|{}", id.proto, id.local_addr, id.foreign_addr)
}

// ---------- tests ---------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use aw_graph::{Interval, ProcessId};

    fn ts(n: u64) -> Timestamp {
        Timestamp {
            mono_ns: n,
            wall_anchor_ns: 0,
        }
    }

    fn small_graph() -> Graph {
        let parent_id = ProcessId {
            pid: 1,
            start_unix_secs: 1000,
        };
        let child_id = ProcessId {
            pid: 42,
            start_unix_secs: 1001,
        };
        let sock_id = SocketId {
            proto: "tcp4".into(),
            local_addr: "10.0.0.1.50000".into(),
            foreign_addr: "1.2.3.4.443".into(),
        };
        Graph {
            processes: vec![
                ProcessNode {
                    id: parent_id.clone(),
                    comm: Some("launchd".into()),
                    name: None,
                    exec_path: Some("/sbin/launchd".into()),
                    ppid: None,
                    uid: Some(0),
                    birth: ts(10),
                    death: None,
                },
                ProcessNode {
                    id: child_id.clone(),
                    comm: Some("curl".into()),
                    name: None,
                    exec_path: Some("/usr/bin/curl".into()),
                    ppid: Some(1),
                    uid: Some(501),
                    birth: ts(20),
                    death: Some(ts(50)),
                },
            ],
            apps: vec![],
            sockets: vec![SocketNode {
                id: sock_id.clone(),
                state: Some("ESTABLISHED".into()),
                process_name: Some("curl".into()),
                pid_at_open: Some(42),
                opened: ts(25),
                closed: Some(ts(45)),
                rxbytes_last: Some(1024),
                txbytes_last: Some(512),
            }],
            files: vec![FileNode {
                path: "/tmp/x".into(),
                flags: vec!["created".into(), "modified".into()],
                first_seen: ts(30),
                last_seen: ts(40),
                touch_count: 3,
            }],
            domains: vec![],
            edges: vec![
                Edge::ParentOf {
                    parent: parent_id.clone(),
                    child: child_id.clone(),
                },
                Edge::OpenedSocket {
                    process: child_id.clone(),
                    socket: sock_id.clone(),
                },
            ],
        }
    }

    #[test]
    fn schema_is_created_with_version() {
        let s = Store::open_in_memory().unwrap();
        assert_eq!(s.schema_version().unwrap(), 1);
    }

    #[test]
    fn merge_inserts_nodes_and_edges() {
        let mut s = Store::open_in_memory().unwrap();
        let r = s.merge_graph(&small_graph()).unwrap();
        assert_eq!(r.edges_inserted, 2);
        assert_eq!(r.edges_updated, 0);
    }

    #[test]
    fn merging_same_graph_twice_bumps_edge_count() {
        let mut s = Store::open_in_memory().unwrap();
        s.merge_graph(&small_graph()).unwrap();
        let r2 = s.merge_graph(&small_graph()).unwrap();
        assert_eq!(
            r2.edges_updated, 2,
            "every edge should be updated, not inserted; got {r2:?}"
        );
        // Verify count actually bumped in SQL.
        let c: i64 = s
            .conn
            .query_row("SELECT count FROM edges WHERE kind='parent_of'", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(c, 2);
    }

    #[test]
    fn load_graph_round_trips_processes() {
        let mut s = Store::open_in_memory().unwrap();
        let original = small_graph();
        s.merge_graph(&original).unwrap();
        let loaded = s.load_graph().unwrap();
        assert_eq!(loaded.processes.len(), 2);
        let curl = loaded.processes.iter().find(|p| p.id.pid == 42).unwrap();
        assert_eq!(curl.comm.as_deref(), Some("curl"));
        assert_eq!(curl.exec_path.as_deref(), Some("/usr/bin/curl"));
        assert_eq!(curl.ppid, Some(1));
    }

    #[test]
    fn load_graph_round_trips_sockets_and_files() {
        let mut s = Store::open_in_memory().unwrap();
        s.merge_graph(&small_graph()).unwrap();
        let loaded = s.load_graph().unwrap();
        assert_eq!(loaded.sockets.len(), 1);
        let sock = &loaded.sockets[0];
        assert_eq!(sock.id.proto, "tcp4");
        assert_eq!(sock.id.foreign_addr, "1.2.3.4.443");
        assert_eq!(sock.pid_at_open, Some(42));

        assert_eq!(loaded.files.len(), 1);
        let f = &loaded.files[0];
        assert_eq!(f.path, "/tmp/x");
        assert!(f.flags.contains(&"created".to_string()));
        assert_eq!(f.touch_count, 3);
    }

    #[test]
    fn load_graph_round_trips_edges() {
        let mut s = Store::open_in_memory().unwrap();
        s.merge_graph(&small_graph()).unwrap();
        let loaded = s.load_graph().unwrap();
        let parent_of = loaded
            .edges
            .iter()
            .filter(|e| matches!(e, Edge::ParentOf { .. }))
            .count();
        let opened_socket = loaded
            .edges
            .iter()
            .filter(|e| matches!(e, Edge::OpenedSocket { .. }))
            .count();
        assert_eq!(parent_of, 1);
        assert_eq!(opened_socket, 1);
    }

    #[test]
    fn first_seen_is_minimum_across_merges() {
        let mut s = Store::open_in_memory().unwrap();
        let mut g = small_graph();
        // First merge with high birth time.
        g.processes[1].birth = ts(100);
        s.merge_graph(&g).unwrap();
        // Second merge with lower birth time — first_seen should hold the older value.
        g.processes[1].birth = ts(20);
        s.merge_graph(&g).unwrap();
        let first_seen: i64 = s
            .conn
            .query_row(
                "SELECT first_seen FROM nodes WHERE kind='process' AND id='42:1001'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(first_seen, 20);
    }

    /// Build a graph with a configurable parent/child uid/exec mix so the
    /// suspicion-query tests are self-contained.
    fn suspicion_graph() -> Graph {
        let init = ProcessNode {
            id: ProcessId {
                pid: 1,
                start_unix_secs: 1000,
            },
            comm: Some("launchd".into()),
            name: None,
            exec_path: Some("/sbin/launchd".into()),
            ppid: None,
            uid: Some(0),
            birth: ts(1),
            death: None,
        };
        // Non-root user shell.
        let shell = ProcessNode {
            id: ProcessId {
                pid: 100,
                start_unix_secs: 1001,
            },
            comm: Some("zsh".into()),
            name: None,
            exec_path: Some("/bin/zsh".into()),
            ppid: Some(1),
            uid: Some(501),
            birth: ts(2),
            death: None,
        };
        // Root child of the non-root shell — the suspicious one.
        let suspicious = ProcessNode {
            id: ProcessId {
                pid: 200,
                start_unix_secs: 1002,
            },
            comm: Some("rooted".into()),
            name: None,
            exec_path: Some("/tmp/rooted".into()),
            ppid: Some(100),
            uid: Some(0),
            birth: ts(3),
            death: None,
        };
        // Boring user process in /usr/bin — should NOT be flagged by either query.
        let curl = ProcessNode {
            id: ProcessId {
                pid: 300,
                start_unix_secs: 1003,
            },
            comm: Some("curl".into()),
            name: None,
            exec_path: Some("/usr/bin/curl".into()),
            ppid: Some(100),
            uid: Some(501),
            birth: ts(4),
            death: None,
        };
        Graph {
            processes: vec![
                init.clone(),
                shell.clone(),
                suspicious.clone(),
                curl.clone(),
            ],
            apps: vec![],
            sockets: vec![],
            files: vec![],
            domains: vec![],
            edges: vec![
                Edge::ParentOf {
                    parent: init.id.clone(),
                    child: shell.id.clone(),
                },
                Edge::ParentOf {
                    parent: shell.id.clone(),
                    child: suspicious.id.clone(),
                },
                Edge::ParentOf {
                    parent: shell.id.clone(),
                    child: curl.id.clone(),
                },
            ],
        }
    }

    #[test]
    fn root_under_user_parent_finds_only_the_escalation() {
        let mut s = Store::open_in_memory().unwrap();
        s.merge_graph(&suspicion_graph()).unwrap();
        let hits = s.processes_root_under_user_parent(0).unwrap();
        assert_eq!(
            hits.len(),
            1,
            "expected exactly one escalation; got {hits:?}"
        );
        assert_eq!(hits[0].id.pid, 200);
        assert_eq!(hits[0].comm.as_deref(), Some("rooted"));
    }

    #[test]
    fn outside_paths_excludes_trusted_prefixes() {
        let mut s = Store::open_in_memory().unwrap();
        s.merge_graph(&suspicion_graph()).unwrap();
        // /sbin/, /bin/, /usr/bin/ all trusted — only /tmp/rooted should remain.
        let hits = s
            .processes_outside_paths(&["/sbin/", "/bin/", "/usr/bin/"], 0)
            .unwrap();
        assert_eq!(hits.len(), 1, "expected only /tmp/rooted; got {hits:?}");
        assert_eq!(hits[0].exec_path.as_deref(), Some("/tmp/rooted"));
    }

    #[test]
    fn parents_with_many_children_respects_threshold() {
        let mut s = Store::open_in_memory().unwrap();
        s.merge_graph(&suspicion_graph()).unwrap();
        // shell (pid 100) has 2 children; launchd (pid 1) has 1.
        let hits = s.parents_with_many_children(2, 0).unwrap();
        assert_eq!(hits.len(), 1, "only shell crosses threshold; got {hits:?}");
        assert_eq!(hits[0].0.id.pid, 100);
        assert_eq!(hits[0].1, 2);
        // Lower the bar — both parents qualify, sorted by child count desc.
        let all = s.parents_with_many_children(1, 0).unwrap();
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].0.id.pid, 100); // 2 children first
        assert_eq!(all[1].0.id.pid, 1); // then launchd with 1
    }

    #[test]
    fn parents_with_many_children_since_counts_only_recent_children() {
        let mut s = Store::open_in_memory().unwrap();
        s.merge_graph(&suspicion_graph()).unwrap();
        // Children's last_seen: rooted=3ns, curl=4ns, shell=2ns. From t=4 only
        // curl still counts, so shell drops below a threshold of 2...
        let hits = s.parents_with_many_children(2, 4).unwrap();
        assert!(hits.is_empty(), "old children must not count: {hits:?}");
        // ...but still qualifies at 1, on the strength of curl alone.
        let hits = s.parents_with_many_children(1, 4).unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].0.id.pid, 100);
        assert_eq!(hits[0].1, 1);
    }

    // ---------- batch 2 query tests --------------------------------------

    /// 1s spaced timestamps in unix nanoseconds; wall_anchor is 0 so
    /// `mono_ns` itself is the unix-ns value (matches round-trip convention).
    fn unix_ts(secs: u64) -> Timestamp {
        Timestamp {
            mono_ns: secs * 1_000_000_000,
            wall_anchor_ns: 0,
        }
    }

    /// Build a richer fixture than `small_graph` / `suspicion_graph`:
    /// 3 processes in a chain (1 → 100 → 200), one frontmost app over
    /// t=10..50s, two sockets owned by pid 200 with known byte counters,
    /// and a single file.
    fn windowed_graph() -> Graph {
        // NOTE: `merge_graph` collapses `last_seen` to `birth` when `death`
        // is None, so for tests we set an explicit death past the windows
        // we'll query. In a real long-running capture each process would
        // see its `last_seen` bumped on every re-merge.
        let p1 = ProcessNode {
            id: ProcessId {
                pid: 1,
                start_unix_secs: 1,
            },
            comm: Some("launchd".into()),
            name: None,
            exec_path: Some("/sbin/launchd".into()),
            ppid: None,
            uid: Some(0),
            birth: unix_ts(0),
            death: Some(unix_ts(60)),
        };
        let p100 = ProcessNode {
            id: ProcessId {
                pid: 100,
                start_unix_secs: 2,
            },
            comm: Some("Code".into()),
            name: None,
            exec_path: Some("/Applications/Code.app/Code".into()),
            ppid: Some(1),
            uid: Some(501),
            birth: unix_ts(5),
            death: Some(unix_ts(60)),
        };
        let p200 = ProcessNode {
            id: ProcessId {
                pid: 200,
                start_unix_secs: 3,
            },
            comm: Some("curl".into()),
            name: None,
            exec_path: Some("/usr/bin/curl".into()),
            ppid: Some(100),
            uid: Some(501),
            birth: unix_ts(10),
            death: Some(unix_ts(30)),
        };
        let sock_a = SocketId {
            proto: "tcp4".into(),
            local_addr: "10.0.0.1.55001".into(),
            foreign_addr: "1.1.1.1.443".into(),
        };
        let sock_b = SocketId {
            proto: "tcp4".into(),
            local_addr: "10.0.0.1.55002".into(),
            foreign_addr: "2.2.2.2.80".into(),
        };
        let app = AppNode {
            id: "com.microsoft.VSCode".into(),
            name: Some("Code".into()),
            exec_path: Some("/Applications/Code.app/Code".into()),
            intervals: vec![Interval {
                from: unix_ts(10),
                to: Some(unix_ts(50)),
            }],
        };
        Graph {
            processes: vec![p1.clone(), p100.clone(), p200.clone()],
            apps: vec![app],
            sockets: vec![
                SocketNode {
                    id: sock_a.clone(),
                    state: Some("ESTABLISHED".into()),
                    process_name: Some("curl".into()),
                    pid_at_open: Some(200),
                    opened: unix_ts(15),
                    closed: Some(unix_ts(25)),
                    rxbytes_last: Some(1_000),
                    txbytes_last: Some(200),
                },
                SocketNode {
                    id: sock_b.clone(),
                    state: Some("ESTABLISHED".into()),
                    process_name: Some("curl".into()),
                    pid_at_open: Some(200),
                    opened: unix_ts(16),
                    closed: Some(unix_ts(28)),
                    rxbytes_last: Some(5_000),
                    txbytes_last: Some(500),
                },
            ],
            files: vec![],
            domains: vec![],
            edges: vec![
                Edge::ParentOf {
                    parent: p1.id.clone(),
                    child: p100.id.clone(),
                },
                Edge::ParentOf {
                    parent: p100.id.clone(),
                    child: p200.id.clone(),
                },
                Edge::FrontmostDuring {
                    app: "com.microsoft.VSCode".into(),
                    process: p100.id.clone(),
                    overlap: Interval {
                        from: unix_ts(10),
                        to: Some(unix_ts(50)),
                    },
                },
                Edge::OpenedSocket {
                    process: p200.id.clone(),
                    socket: sock_a.clone(),
                },
                Edge::OpenedSocket {
                    process: p200.id.clone(),
                    socket: sock_b.clone(),
                },
            ],
        }
    }

    fn ns(secs: u64) -> i64 {
        (secs * 1_000_000_000) as i64
    }

    #[test]
    fn graph_in_window_keeps_overlapping_nodes_and_drops_outliers() {
        let mut s = Store::open_in_memory().unwrap();
        s.merge_graph(&windowed_graph()).unwrap();

        // Window 20..40s — all three processes overlap (p1 alive 0..60,
        // p100 alive 5..60, p200 alive 10..30), the app overlaps (10..50),
        // and both sockets overlap (15..25, 16..28).
        let g = s.graph_in_window(ns(20), ns(40)).unwrap();
        let pids: Vec<u32> = g.processes.iter().map(|p| p.id.pid).collect();
        assert!(pids.contains(&1));
        assert!(pids.contains(&100));
        assert!(pids.contains(&200));
        assert_eq!(g.apps.len(), 1);
        assert_eq!(g.sockets.len(), 2);

        // All edges survive — every endpoint is in the node set.
        let parent_edges = g
            .edges
            .iter()
            .filter(|e| matches!(e, Edge::ParentOf { .. }))
            .count();
        assert_eq!(
            parent_edges, 2,
            "both parent_of edges should survive: {:?}",
            g.edges
        );

        // Now a tighter window that excludes p200: 35..45 should drop the
        // 10..30 socket-owning curl process and both sockets that ended at
        // 25/28 — proving the filter actually filters.
        let g_late = s.graph_in_window(ns(35), ns(45)).unwrap();
        let late_pids: Vec<u32> = g_late.processes.iter().map(|p| p.id.pid).collect();
        assert!(
            !late_pids.contains(&200),
            "p200 ended at 30s, should be gone: {late_pids:?}"
        );
        assert!(
            g_late.sockets.is_empty(),
            "sockets ended before 35s: {:?}",
            g_late.sockets
        );
    }

    #[test]
    fn graph_in_window_empty_when_window_predates_everything() {
        let mut s = Store::open_in_memory().unwrap();
        s.merge_graph(&windowed_graph()).unwrap();
        // Window ends before anything was seen.
        let g = s.graph_in_window(-2_000_000_000, -1_000_000_000).unwrap();
        assert!(g.processes.is_empty());
        assert!(g.apps.is_empty());
        assert!(g.sockets.is_empty());
        assert!(g.edges.is_empty());
    }

    #[test]
    fn top_endpoints_by_bytes_sorted_desc_with_counts() {
        let mut s = Store::open_in_memory().unwrap();
        s.merge_graph(&windowed_graph()).unwrap();
        let top = s.top_endpoints_by_bytes(10).unwrap();
        assert_eq!(top.len(), 2, "expected both endpoints, got {top:?}");
        // sock_b is bigger (5_500 > 1_200) — comes first.
        assert_eq!(top[0].foreign_addr, "2.2.2.2.80");
        assert_eq!(top[0].total_bytes, 5_500);
        assert_eq!(top[0].distinct_processes, 1);
        assert_eq!(top[0].connection_count, 1);
        assert_eq!(top[1].foreign_addr, "1.1.1.1.443");
        assert_eq!(top[1].total_bytes, 1_200);
    }

    #[test]
    fn top_endpoints_respects_limit() {
        let mut s = Store::open_in_memory().unwrap();
        s.merge_graph(&windowed_graph()).unwrap();
        let top = s.top_endpoints_by_bytes(1).unwrap();
        assert_eq!(top.len(), 1);
        assert_eq!(top[0].foreign_addr, "2.2.2.2.80");
    }

    #[test]
    fn focus_segments_clipped_to_window() {
        let mut s = Store::open_in_memory().unwrap();
        s.merge_graph(&windowed_graph()).unwrap();
        // App was frontmost 10..50s; window 20..40s should yield one
        // segment clipped to 20..40 (duration 20s).
        let segs = s.focus_segments_in_window(ns(20), ns(40)).unwrap();
        assert_eq!(segs.len(), 1, "expected one segment: {segs:?}");
        let seg = &segs[0];
        assert_eq!(seg.app_id, "com.microsoft.VSCode");
        assert_eq!(seg.app_name, "Code");
        assert_eq!(seg.process_pid, 100);
        assert_eq!(seg.from_unix_ns, ns(20));
        assert_eq!(seg.to_unix_ns, ns(40));
        assert_eq!(seg.duration_secs, 20);
    }

    #[test]
    fn focus_segments_skipped_when_window_disjoint() {
        let mut s = Store::open_in_memory().unwrap();
        s.merge_graph(&windowed_graph()).unwrap();
        let segs = s.focus_segments_in_window(ns(100), ns(200)).unwrap();
        assert!(segs.is_empty(), "no overlap → no segments: {segs:?}");
    }

    #[test]
    fn ancestors_of_walks_chain_in_order() {
        let mut s = Store::open_in_memory().unwrap();
        s.merge_graph(&windowed_graph()).unwrap();
        // Chain is 200 → 100 → 1. ancestors_of(200) at depth 5 should
        // return [100, 1] in that order.
        let ancestors = s.ancestors_of("200:3", 5).unwrap();
        let pids: Vec<u32> = ancestors.iter().map(|p| p.id.pid).collect();
        assert_eq!(pids, vec![100, 1], "ancestor chain order: {pids:?}");
    }

    #[test]
    fn ancestors_of_respects_max_depth() {
        let mut s = Store::open_in_memory().unwrap();
        s.merge_graph(&windowed_graph()).unwrap();
        let one = s.ancestors_of("200:3", 1).unwrap();
        assert_eq!(one.len(), 1);
        assert_eq!(one[0].id.pid, 100);
    }

    #[test]
    fn ancestors_of_returns_empty_for_root() {
        let mut s = Store::open_in_memory().unwrap();
        s.merge_graph(&windowed_graph()).unwrap();
        let none = s.ancestors_of("1:1", 5).unwrap();
        assert!(none.is_empty(), "launchd has no parent edge: {none:?}");
    }

    /// Two processes querying two domains; both edges attributed.
    fn dns_graph() -> Graph {
        let curl = ProcessNode {
            id: ProcessId {
                pid: 42,
                start_unix_secs: 1001,
            },
            comm: Some("curl".into()),
            name: None,
            exec_path: Some("/usr/bin/curl".into()),
            ppid: Some(1),
            uid: Some(501),
            birth: unix_ts(10),
            death: Some(unix_ts(60)),
        };
        let node = ProcessNode {
            id: ProcessId {
                pid: 43,
                start_unix_secs: 1002,
            },
            comm: Some("node".into()),
            name: None,
            exec_path: Some("/usr/local/bin/node".into()),
            ppid: Some(1),
            uid: Some(501),
            birth: unix_ts(11),
            death: Some(unix_ts(60)),
        };
        Graph {
            processes: vec![curl.clone(), node.clone()],
            apps: vec![],
            sockets: vec![],
            files: vec![],
            domains: vec![
                DomainNode {
                    name: "example.com".into(),
                    qtypes: vec!["A".into(), "AAAA".into()],
                    masked: false,
                    first_seen: unix_ts(20),
                    last_seen: unix_ts(40),
                    query_count: 7,
                },
                DomainNode {
                    name: "hash:abc123".into(),
                    qtypes: vec!["HTTPS".into()],
                    masked: true,
                    first_seen: unix_ts(25),
                    last_seen: unix_ts(30),
                    query_count: 2,
                },
            ],
            edges: vec![
                Edge::QueriedDomain {
                    process: curl.id.clone(),
                    domain: "example.com".into(),
                    count: 4,
                },
                Edge::QueriedDomain {
                    process: node.id.clone(),
                    domain: "example.com".into(),
                    count: 3,
                },
                Edge::QueriedDomain {
                    process: node.id.clone(),
                    domain: "hash:abc123".into(),
                    count: 2,
                },
            ],
        }
    }

    #[test]
    fn domains_round_trip_through_store() {
        let mut s = Store::open_in_memory().unwrap();
        s.merge_graph(&dns_graph()).unwrap();
        let loaded = s.load_graph().unwrap();
        assert_eq!(loaded.domains.len(), 2);
        let ex = loaded
            .domains
            .iter()
            .find(|d| d.name == "example.com")
            .unwrap();
        assert_eq!(ex.query_count, 7);
        assert!(!ex.masked);
        assert!(ex.qtypes.contains(&"A".to_string()));
        let masked = loaded
            .domains
            .iter()
            .find(|d| d.name == "hash:abc123")
            .unwrap();
        assert!(masked.masked);

        let qd: Vec<(u32, &str, u64)> = loaded
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
        assert_eq!(qd.len(), 3, "all queried_domain edges round-trip: {qd:?}");
        assert!(qd.contains(&(42, "example.com", 4)));
    }

    #[test]
    fn graph_in_window_includes_overlapping_domains() {
        let mut s = Store::open_in_memory().unwrap();
        s.merge_graph(&dns_graph()).unwrap();
        // Window 35..50s: example.com (20..40) overlaps; hash domain (25..30) does not.
        let g = s.graph_in_window(ns(35), ns(50)).unwrap();
        let names: Vec<&str> = g.domains.iter().map(|d| d.name.as_str()).collect();
        assert_eq!(names, vec!["example.com"], "got {names:?}");
        // Both processes survive (alive to 60s), so example.com edges survive
        // but the hash-domain edge must drop with its node.
        let qd_domains: Vec<&str> = g
            .edges
            .iter()
            .filter_map(|e| match e {
                Edge::QueriedDomain { domain, .. } => Some(domain.as_str()),
                _ => None,
            })
            .collect();
        assert_eq!(qd_domains.len(), 2, "got {qd_domains:?}");
        assert!(qd_domains.iter().all(|d| *d == "example.com"));
    }

    #[test]
    fn top_domains_sorted_by_query_count_with_distinct_processes() {
        let mut s = Store::open_in_memory().unwrap();
        s.merge_graph(&dns_graph()).unwrap();
        let top = s.top_domains(10).unwrap();
        assert_eq!(top.len(), 2);
        assert_eq!(top[0].name, "example.com");
        assert_eq!(top[0].query_count, 7);
        assert_eq!(top[0].distinct_processes, 2);
        assert_eq!(top[1].name, "hash:abc123");
        assert_eq!(top[1].distinct_processes, 1);
        let one = s.top_domains(1).unwrap();
        assert_eq!(one.len(), 1);
        assert_eq!(one[0].name, "example.com");
    }

    #[test]
    fn prune_before_deletes_old_nodes_and_dangling_edges() {
        let mut s = Store::open_in_memory().unwrap();
        s.merge_graph(&windowed_graph()).unwrap();
        // Sockets closed at 25s/28s; processes die at 60s, app interval ends
        // at 50s. Cutoff 29s prunes exactly the two sockets.
        let report = s.prune_before(ns(29)).unwrap();
        assert_eq!(report.nodes_deleted, 2, "both sockets pruned: {report:?}");
        let loaded = s.load_graph().unwrap();
        assert!(loaded.sockets.is_empty());
        // opened_socket edges must be gone too (dangling cleanup).
        assert!(!loaded
            .edges
            .iter()
            .any(|e| matches!(e, Edge::OpenedSocket { .. })));
        // Processes and their parent_of edges survive.
        assert_eq!(loaded.processes.len(), 3);
        assert_eq!(
            loaded
                .edges
                .iter()
                .filter(|e| matches!(e, Edge::ParentOf { .. }))
                .count(),
            2
        );
    }

    #[test]
    fn prune_before_is_noop_for_ancient_cutoff() {
        let mut s = Store::open_in_memory().unwrap();
        s.merge_graph(&windowed_graph()).unwrap();
        let report = s.prune_before(0).unwrap();
        assert_eq!(report.nodes_deleted, 0);
        assert_eq!(report.edges_deleted, 0);
    }

    #[test]
    fn summary_reports_counts_and_span() {
        let mut s = Store::open_in_memory().unwrap();
        s.merge_graph(&windowed_graph()).unwrap();
        let sum = s.summary().unwrap();
        let nodes: std::collections::HashMap<String, u64> =
            sum.node_counts.iter().cloned().collect();
        assert_eq!(nodes.get("process"), Some(&3));
        assert_eq!(nodes.get("socket"), Some(&2));
        assert_eq!(nodes.get("app"), Some(&1));
        let edges: std::collections::HashMap<String, u64> =
            sum.edge_counts.iter().cloned().collect();
        assert_eq!(edges.get("parent_of"), Some(&2));
        assert_eq!(edges.get("opened_socket"), Some(&2));
        assert_eq!(sum.first_seen_unix_ns, Some(0));
        assert!(
            sum.last_seen_unix_ns >= Some(ns(50)),
            "got {:?}",
            sum.last_seen_unix_ns
        );
    }

    #[test]
    fn summary_on_empty_store() {
        let s = Store::open_in_memory().unwrap();
        let sum = s.summary().unwrap();
        assert!(sum.node_counts.is_empty());
        assert!(sum.edge_counts.is_empty());
        assert_eq!(sum.first_seen_unix_ns, None);
        assert_eq!(sum.last_seen_unix_ns, None);
    }

    fn sample_event(secs: u64, kind: EventKind, pid: Option<u32>) -> Event {
        Event {
            schema_version: aw_events::SCHEMA_VERSION,
            timestamp: unix_ts(secs),
            kind,
            pid,
            payload: serde_json::json!({ "marker": secs }),
        }
    }

    fn payload_event(secs: u64, kind: EventKind, payload: serde_json::Value) -> Event {
        Event {
            schema_version: aw_events::SCHEMA_VERSION,
            timestamp: unix_ts(secs),
            kind,
            pid: None,
            payload,
        }
    }

    #[test]
    fn hourly_profile_buckets_by_utc_hour() {
        let mut s = Store::open_in_memory().unwrap();
        // Two dns queries in hour 0, one process birth in hour 2 (UTC,
        // relative to the unix epoch since unix_ts starts at 0).
        s.append_events(&[
            sample_event(60, EventKind::DnsQuery, None),
            sample_event(120, EventKind::DnsQuery, None),
            sample_event(2 * 3600 + 5, EventKind::ProcessBirth, Some(1)),
        ])
        .unwrap();

        let profile = s.event_hourly_profile(0).unwrap();
        assert_eq!(profile.len(), 2);
        let dns = profile.iter().find(|r| r.kind == "dns_query").unwrap();
        assert_eq!((dns.hour_of_day, dns.count), (0, 2));
        let birth = profile.iter().find(|r| r.kind == "process_birth").unwrap();
        assert_eq!((birth.hour_of_day, birth.count), (2, 1));
    }

    #[test]
    fn field_window_counts_group_by_value_and_window() {
        let mut s = Store::open_in_memory().unwrap();
        let q = |name: &str| serde_json::json!({ "process_name": name });
        s.append_events(&[
            payload_event(10, EventKind::DnsQuery, q("chrome")),
            payload_event(20, EventKind::DnsQuery, q("chrome")),
            payload_event(3610, EventKind::DnsQuery, q("chrome")),
            payload_event(30, EventKind::DnsQuery, q("curl")),
            // Different kind and missing field must both be excluded.
            payload_event(40, EventKind::ProcessBirth, q("chrome")),
            payload_event(50, EventKind::DnsQuery, serde_json::json!({ "other": 1 })),
        ])
        .unwrap();

        let hour_ns: i64 = 3_600_000_000_000;
        let rows = s
            .event_field_window_counts(EventKind::DnsQuery, "process_name", 0, hour_ns)
            .unwrap();
        assert_eq!(rows.len(), 3);
        let chrome: Vec<_> = rows.iter().filter(|r| r.value == "chrome").collect();
        assert_eq!(chrome.len(), 2, "chrome spans two hour windows");
        assert_eq!(chrome[0].count, 2);
        assert_eq!(chrome[1].count, 1);
        assert_eq!(chrome[1].window_start_unix_ns, hour_ns);
        let curl = rows.iter().find(|r| r.value == "curl").unwrap();
        assert_eq!(curl.count, 1);
    }

    #[test]
    fn edge_rates_read_existing_columns() {
        let mut s = Store::open_in_memory().unwrap();
        let g = small_graph();
        s.merge_graph(&g).unwrap();
        s.merge_graph(&g).unwrap(); // second merge bumps count

        let rates = s.edge_rates("parent_of").unwrap();
        assert_eq!(rates.len(), 1);
        assert!(rates[0].count >= 2, "repeat merge must bump the tally");
        assert!(rates[0].last_seen_unix_ns >= rates[0].first_seen_unix_ns);
    }

    #[test]
    fn events_round_trip_in_order() {
        let mut s = Store::open_in_memory().unwrap();
        let evs = vec![
            sample_event(30, EventKind::DnsQuery, Some(42)),
            sample_event(10, EventKind::ProcessBirth, Some(1)),
            sample_event(20, EventKind::FileChanged, None),
        ];
        assert_eq!(s.append_events(&evs).unwrap(), 3);

        let back = s.events_in_window(ns(0), ns(100), None, 100).unwrap();
        assert_eq!(back.len(), 3);
        // Oldest first regardless of insert order.
        let kinds: Vec<EventKind> = back.iter().map(|e| e.kind).collect();
        assert_eq!(
            kinds,
            vec![
                EventKind::ProcessBirth,
                EventKind::FileChanged,
                EventKind::DnsQuery
            ]
        );
        assert_eq!(back[0].pid, Some(1));
        assert_eq!(
            back[0].payload.get("marker").and_then(|v| v.as_u64()),
            Some(10)
        );
        assert_eq!(back[0].schema_version, aw_events::SCHEMA_VERSION);
    }

    #[test]
    fn events_window_and_kind_filter_and_limit() {
        let mut s = Store::open_in_memory().unwrap();
        let evs = vec![
            sample_event(10, EventKind::DnsQuery, None),
            sample_event(20, EventKind::DnsQuery, None),
            sample_event(30, EventKind::FileChanged, None),
            sample_event(90, EventKind::DnsQuery, None),
        ];
        s.append_events(&evs).unwrap();

        // Window excludes t=90.
        let in_window = s.events_in_window(ns(0), ns(50), None, 100).unwrap();
        assert_eq!(in_window.len(), 3);

        // Kind filter keeps only DNS.
        let dns_only = s
            .events_in_window(ns(0), ns(50), Some(&[EventKind::DnsQuery]), 100)
            .unwrap();
        assert_eq!(dns_only.len(), 2);
        assert!(dns_only.iter().all(|e| e.kind == EventKind::DnsQuery));

        // Limit caps output (oldest first).
        let capped = s.events_in_window(ns(0), ns(100), None, 1).unwrap();
        assert_eq!(capped.len(), 1);
        assert_eq!(
            capped[0].payload.get("marker").and_then(|v| v.as_u64()),
            Some(10)
        );
    }

    #[test]
    fn prune_deletes_old_events_and_summary_counts_them() {
        let mut s = Store::open_in_memory().unwrap();
        s.append_events(&[
            sample_event(10, EventKind::DnsQuery, None),
            sample_event(50, EventKind::DnsQuery, None),
        ])
        .unwrap();
        assert_eq!(s.summary().unwrap().event_count, 2);

        let report = s.prune_before(ns(30)).unwrap();
        assert_eq!(report.events_deleted, 1);
        assert_eq!(s.summary().unwrap().event_count, 1);
        let left = s.events_in_window(ns(0), ns(100), None, 10).unwrap();
        assert_eq!(left.len(), 1);
        assert_eq!(
            left[0].payload.get("marker").and_then(|v| v.as_u64()),
            Some(50)
        );
    }

    #[test]
    fn meta_round_trip_and_schema_version_guard() {
        let s = Store::open_in_memory().unwrap();
        assert_eq!(s.get_meta("daemon_pid").unwrap(), None);
        s.set_meta("daemon_pid", "1234").unwrap();
        assert_eq!(s.get_meta("daemon_pid").unwrap().as_deref(), Some("1234"));
        // Overwrite wins.
        s.set_meta("daemon_pid", "5678").unwrap();
        assert_eq!(s.get_meta("daemon_pid").unwrap().as_deref(), Some("5678"));
        // The store's own key is protected.
        assert!(s.set_meta("schema_version", "99").is_err());
        assert_eq!(s.schema_version().unwrap(), 1);
    }

    #[test]
    fn two_connections_share_one_file_store() {
        // Simulates the daemon (writer) + aw-query (reader) racing on the
        // same world.db: WAL + busy timeout must let the read succeed while
        // a second connection is open.
        let path =
            std::env::temp_dir().join(format!("aw-store-wal-test-{}.db", std::process::id()));
        let _ = std::fs::remove_file(&path);

        let mut writer = Store::open(&path).unwrap();
        let reader = Store::open(&path).unwrap();

        writer.merge_graph(&small_graph()).unwrap();
        writer
            .append_events(&[sample_event(10, EventKind::DnsQuery, None)])
            .unwrap();

        let loaded = reader.load_graph().unwrap();
        assert_eq!(loaded.processes.len(), 2);
        assert_eq!(reader.summary().unwrap().event_count, 1);

        drop(writer);
        drop(reader);
        let _ = std::fs::remove_file(&path);
        // WAL sidecar files.
        let _ = std::fs::remove_file(path.with_extension("db-wal"));
        let _ = std::fs::remove_file(path.with_extension("db-shm"));
    }

    #[test]
    fn frontmost_during_edge_preserves_overlap() {
        let mut s = Store::open_in_memory().unwrap();
        let proc_id = ProcessId {
            pid: 100,
            start_unix_secs: 1,
        };
        let g = Graph {
            processes: vec![ProcessNode {
                id: proc_id.clone(),
                comm: Some("p".into()),
                name: None,
                exec_path: None,
                ppid: None,
                uid: None,
                birth: ts(10),
                death: None,
            }],
            apps: vec![AppNode {
                id: "com.app.X".into(),
                name: Some("X".into()),
                exec_path: None,
                intervals: vec![Interval {
                    from: ts(5),
                    to: Some(ts(50)),
                }],
            }],
            sockets: vec![],
            files: vec![],
            domains: vec![],
            edges: vec![Edge::FrontmostDuring {
                app: "com.app.X".into(),
                process: proc_id.clone(),
                overlap: Interval {
                    from: ts(10),
                    to: Some(ts(50)),
                },
            }],
        };
        s.merge_graph(&g).unwrap();
        let loaded = s.load_graph().unwrap();
        let fd = loaded
            .edges
            .iter()
            .find(|e| matches!(e, Edge::FrontmostDuring { .. }))
            .unwrap();
        match fd {
            Edge::FrontmostDuring {
                app,
                process,
                overlap,
            } => {
                assert_eq!(app, "com.app.X");
                assert_eq!(process.pid, 100);
                assert_eq!(overlap.from.mono_ns, 10);
                assert_eq!(overlap.to.map(|t| t.mono_ns), Some(50));
            }
            _ => unreachable!(),
        }
    }

    // ---------- novelty tests ---------------------------------------------

    /// Minimal graph with one of each novelty-relevant entity, all stamped
    /// at `t_secs` (unix seconds, zero anchor — round-trip convention).
    #[allow(clippy::too_many_arguments)]
    fn novelty_fixture(
        pid: u32,
        start: u64,
        comm: &str,
        local_port: u16,
        foreign: &str,
        domain: &str,
        masked: bool,
        app: &str,
        t_secs: u64,
    ) -> Graph {
        let t = unix_ts(t_secs);
        let p = ProcessNode {
            id: ProcessId {
                pid,
                start_unix_secs: start,
            },
            comm: Some(comm.into()),
            name: None,
            exec_path: Some(format!("/usr/bin/{comm}")),
            ppid: Some(1),
            uid: Some(501),
            birth: t,
            death: None,
        };
        let sock = SocketNode {
            id: SocketId {
                proto: "tcp4".into(),
                local_addr: format!("10.0.0.1.{local_port}"),
                foreign_addr: foreign.into(),
            },
            state: Some("ESTABLISHED".into()),
            process_name: Some(comm.into()),
            pid_at_open: Some(pid),
            opened: t,
            closed: None,
            rxbytes_last: Some(1),
            txbytes_last: Some(1),
        };
        let d = DomainNode {
            name: domain.into(),
            qtypes: vec!["A".into()],
            masked,
            first_seen: t,
            last_seen: t,
            query_count: 1,
        };
        let a = AppNode {
            id: app.into(),
            name: Some(app.into()),
            exec_path: None,
            intervals: vec![Interval {
                from: t,
                to: Some(unix_ts(t_secs + 1)),
            }],
        };
        Graph {
            processes: vec![p],
            apps: vec![a],
            sockets: vec![sock],
            files: vec![],
            domains: vec![d],
            edges: vec![],
        }
    }

    #[test]
    fn novel_since_empty_store_reports_nothing_and_no_baseline() {
        let s = Store::open_in_memory().unwrap();
        let r = s.novel_since(0).unwrap();
        assert!(r.new_processes.is_empty());
        assert!(r.new_domains.is_empty());
        assert!(r.new_endpoints.is_empty());
        assert!(r.new_apps.is_empty());
        assert_eq!(r.oldest_first_seen_unix_ns, None);
    }

    #[test]
    fn novel_since_only_reports_entities_first_seen_after_cutoff() {
        let mut s = Store::open_in_memory().unwrap();
        s.merge_graph(&novelty_fixture(
            42,
            1001,
            "curl",
            50000,
            "1.1.1.1.443",
            "old.example",
            false,
            "com.app.Old",
            10,
        ))
        .unwrap();
        s.merge_graph(&novelty_fixture(
            43,
            1002,
            "newtool",
            50001,
            "9.9.9.9.443",
            "new.example",
            false,
            "com.app.New",
            100,
        ))
        .unwrap();

        let r = s.novel_since(ns(50)).unwrap();
        assert_eq!(r.new_processes.len(), 1, "{:?}", r.new_processes);
        assert_eq!(r.new_processes[0].comm.as_deref(), Some("newtool"));
        assert_eq!(r.new_domains, vec!["new.example".to_string()]);
        assert_eq!(r.new_endpoints.len(), 1);
        assert_eq!(r.new_endpoints[0].foreign_addr, "9.9.9.9.443");
        assert_eq!(r.new_apps.len(), 1);
        assert_eq!(r.new_apps[0].id, "com.app.New");
        assert_eq!(r.oldest_first_seen_unix_ns, Some(ns(10)));
    }

    #[test]
    fn novel_since_dedupes_process_identity_across_pid_reuse() {
        let mut s = Store::open_in_memory().unwrap();
        // curl runs at t=10 (pid 42) and again at t=100 as a NEW node row
        // (pid 99, new start time). Same identity -> not new after cutoff 50.
        s.merge_graph(&novelty_fixture(
            42,
            1001,
            "curl",
            50000,
            "1.1.1.1.443",
            "a.example",
            false,
            "com.app.A",
            10,
        ))
        .unwrap();
        s.merge_graph(&novelty_fixture(
            99,
            2000,
            "curl",
            50002,
            "1.1.1.1.443",
            "a.example",
            false,
            "com.app.A",
            100,
        ))
        .unwrap();

        let r = s.novel_since(ns(50)).unwrap();
        assert!(
            r.new_processes.is_empty(),
            "same (comm, exec_path) identity must not re-qualify: {:?}",
            r.new_processes
        );
    }

    #[test]
    fn novel_since_groups_sockets_by_foreign_addr() {
        let mut s = Store::open_in_memory().unwrap();
        // t=10: connection to 1.1.1.1.443. t=100: a DIFFERENT socket node
        // (fresh local port) to the same endpoint — endpoint is not new.
        s.merge_graph(&novelty_fixture(
            42,
            1001,
            "curl",
            50000,
            "1.1.1.1.443",
            "a.example",
            false,
            "com.app.A",
            10,
        ))
        .unwrap();
        s.merge_graph(&novelty_fixture(
            42,
            1001,
            "curl",
            55555,
            "1.1.1.1.443",
            "a.example",
            false,
            "com.app.A",
            100,
        ))
        .unwrap();

        let r = s.novel_since(ns(50)).unwrap();
        assert!(
            r.new_endpoints.is_empty(),
            "known endpoint via a fresh socket must not be new: {:?}",
            r.new_endpoints
        );
    }

    #[test]
    fn novel_since_excludes_masked_domains() {
        let mut s = Store::open_in_memory().unwrap();
        s.merge_graph(&novelty_fixture(
            42,
            1001,
            "curl",
            50000,
            "1.1.1.1.443",
            "hash:abc==",
            true,
            "com.app.A",
            100,
        ))
        .unwrap();
        let r = s.novel_since(ns(50)).unwrap();
        assert!(
            r.new_domains.is_empty(),
            "masked domains are noise: {:?}",
            r.new_domains
        );
    }

    #[test]
    fn novel_since_respects_per_kind_cap() {
        let mut s = Store::open_in_memory().unwrap();
        let mut g = Graph::default();
        for i in 0..25 {
            g.domains.push(DomainNode {
                name: format!("d{i}.example"),
                qtypes: vec![],
                masked: false,
                first_seen: unix_ts(100 + i),
                last_seen: unix_ts(100 + i),
                query_count: 1,
            });
        }
        s.merge_graph(&g).unwrap();
        let r = s.novel_since(0).unwrap();
        assert_eq!(r.new_domains.len(), NOVELTY_CAP_PER_KIND);
        // Oldest first.
        assert_eq!(r.new_domains[0], "d0.example");
    }

    #[test]
    fn remerge_does_not_resurrect_novelty() {
        let mut s = Store::open_in_memory().unwrap();
        let mut g = novelty_fixture(
            42,
            1001,
            "curl",
            50000,
            "1.1.1.1.443",
            "a.example",
            false,
            "com.app.A",
            10,
        );
        s.merge_graph(&g).unwrap();
        // Same entities re-observed later: bump every timestamp to t=100 and
        // re-merge. first_seen is MIN-maintained, so nothing becomes new.
        g.processes[0].birth = unix_ts(100);
        g.sockets[0].opened = unix_ts(100);
        g.domains[0].first_seen = unix_ts(100);
        g.domains[0].last_seen = unix_ts(100);
        g.apps[0].intervals = vec![Interval {
            from: unix_ts(100),
            to: Some(unix_ts(101)),
        }];
        s.merge_graph(&g).unwrap();

        let r = s.novel_since(ns(50)).unwrap();
        assert!(r.new_processes.is_empty(), "{:?}", r.new_processes);
        assert!(r.new_domains.is_empty(), "{:?}", r.new_domains);
        assert!(r.new_endpoints.is_empty(), "{:?}", r.new_endpoints);
        assert!(r.new_apps.is_empty(), "{:?}", r.new_apps);
    }

    #[test]
    fn suspicion_queries_filter_by_last_seen_since() {
        let mut s = Store::open_in_memory().unwrap();
        s.merge_graph(&suspicion_graph()).unwrap();
        // suspicion_graph timestamps are raw mono ns 1..4 — since=0 sees all,
        // a cutoff beyond them sees none.
        assert_eq!(s.processes_root_under_user_parent(0).unwrap().len(), 1);
        assert!(s
            .processes_root_under_user_parent(1_000_000)
            .unwrap()
            .is_empty());

        let trusted = ["/sbin/", "/bin/", "/usr/bin/"];
        assert_eq!(s.processes_outside_paths(&trusted, 0).unwrap().len(), 1);
        assert!(s
            .processes_outside_paths(&trusted, 1_000_000)
            .unwrap()
            .is_empty());
    }
}
