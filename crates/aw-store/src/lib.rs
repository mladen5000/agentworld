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
use aw_graph::{
    AppNode, Edge, FileNode, Graph, Interval, ProcessId, ProcessNode, SocketId, SocketNode,
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

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct MergeReport {
    pub nodes_inserted: u64,
    pub nodes_updated: u64,
    pub edges_inserted: u64,
    pub edges_updated: u64,
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
            upsert_node(&tx, kind, &id, &attrs, p.birth, p.death.unwrap_or(p.birth), &mut report)?;
        }

        for a in &g.apps {
            let kind = "app";
            let id = &a.id;
            let attrs = serde_json::to_string(&serde_json::json!({
                "name": a.name,
                "exec_path": a.exec_path,
                "intervals": a.intervals,
            }))?;
            let first_seen = a.intervals.iter().map(|i| i.from).min().unwrap_or(Timestamp { mono_ns: 0, wall_anchor_ns: 0 });
            let last_seen = a.intervals.iter().filter_map(|i| i.to).max().unwrap_or(first_seen);
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
            upsert_node(&tx, kind, &id, &attrs, s.opened, s.closed.unwrap_or(s.opened), &mut report)?;
        }

        for f in &g.files {
            let kind = "file";
            let id = &f.path;
            let attrs = serde_json::to_string(&serde_json::json!({
                "flags": f.flags,
                "touch_count": f.touch_count,
            }))?;
            upsert_node(&tx, kind, id, &attrs, f.first_seen, f.last_seen, &mut report)?;
        }

        for edge in &g.edges {
            match edge {
                Edge::ParentOf { parent, child } => {
                    let from_id = process_id_to_string(parent);
                    let to_id = process_id_to_string(child);
                    // Edges built from process_birth don't carry their own
                    // wall time; fall back to the child node's last_seen.
                    let seen_at = node_last_seen(&tx, "process", &to_id)?;
                    upsert_edge(&tx, EdgeRow {
                        kind: "parent_of",
                        from_kind: "process", from_id: &from_id,
                        to_kind: "process",   to_id: &to_id,
                        seen_at,
                        attrs: "{}",
                    }, &mut report)?;
                }
                Edge::FrontmostDuring { app, process, overlap } => {
                    let to_id = process_id_to_string(process);
                    let attrs = serde_json::to_string(&serde_json::json!({
                        "overlap": overlap,
                    }))?;
                    upsert_edge(&tx, EdgeRow {
                        kind: "frontmost_during",
                        from_kind: "app",     from_id: app,
                        to_kind: "process",   to_id: &to_id,
                        seen_at: overlap.to.unwrap_or(overlap.from),
                        attrs: &attrs,
                    }, &mut report)?;
                }
                Edge::OpenedSocket { process, socket } => {
                    let from_id = process_id_to_string(process);
                    let to_id = socket_id_to_string(socket);
                    let seen_at = node_last_seen(&tx, "socket", &to_id)?;
                    upsert_edge(&tx, EdgeRow {
                        kind: "opened_socket",
                        from_kind: "process", from_id: &from_id,
                        to_kind: "socket",    to_id: &to_id,
                        seen_at,
                        attrs: "{}",
                    }, &mut report)?;
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
        let mut stmt = self.conn.prepare(
            "SELECT id, attrs, first_seen, last_seen FROM nodes WHERE kind = 'process'",
        )?;
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
            let death: Option<Timestamp> = if death_v.is_null() { None } else { serde_json::from_value(death_v).ok() };
            g.processes.push(ProcessNode {
                id: pid_id,
                comm: v.get("comm").and_then(|x| x.as_str()).map(String::from),
                name: v.get("name").and_then(|x| x.as_str()).map(String::from),
                exec_path: v.get("exec_path").and_then(|x| x.as_str()).map(String::from),
                ppid: v.get("ppid").and_then(|x| x.as_u64()).and_then(|n| u32::try_from(n).ok()),
                uid: v.get("uid").and_then(|x| x.as_u64()).and_then(|n| u32::try_from(n).ok()),
                birth: Timestamp { mono_ns: first_seen as u64, wall_anchor_ns: 0 },
                death,
            });
        }

        // Apps
        let mut stmt = self.conn.prepare(
            "SELECT id, attrs FROM nodes WHERE kind = 'app'",
        )?;
        let rows = stmt.query_map([], |r| {
            let id: String = r.get(0)?;
            let attrs: String = r.get(1)?;
            Ok((id, attrs))
        })?;
        for row in rows {
            let (id, attrs) = row?;
            let v: serde_json::Value = serde_json::from_str(&attrs)?;
            let intervals: Vec<Interval> = v.get("intervals")
                .cloned()
                .and_then(|x| serde_json::from_value(x).ok())
                .unwrap_or_default();
            g.apps.push(AppNode {
                id,
                name: v.get("name").and_then(|x| x.as_str()).map(String::from),
                exec_path: v.get("exec_path").and_then(|x| x.as_str()).map(String::from),
                intervals,
            });
        }

        // Sockets
        let mut stmt = self.conn.prepare(
            "SELECT id, attrs, first_seen, last_seen FROM nodes WHERE kind = 'socket'",
        )?;
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
                proto: v.get("proto").and_then(|x| x.as_str()).unwrap_or("?").to_string(),
                local_addr: v.get("local_addr").and_then(|x| x.as_str()).unwrap_or("?").to_string(),
                foreign_addr: v.get("foreign_addr").and_then(|x| x.as_str()).unwrap_or("?").to_string(),
            };
            g.sockets.push(SocketNode {
                id: sid,
                state: v.get("state").and_then(|x| x.as_str()).map(String::from),
                process_name: v.get("process_name").and_then(|x| x.as_str()).map(String::from),
                pid_at_open: v.get("pid_at_open").and_then(|x| x.as_u64()).and_then(|n| u32::try_from(n).ok()),
                opened: Timestamp { mono_ns: first_seen as u64, wall_anchor_ns: 0 },
                closed: if last_seen > first_seen {
                    Some(Timestamp { mono_ns: last_seen as u64, wall_anchor_ns: 0 })
                } else {
                    None
                },
                rxbytes_last: v.get("rxbytes_last").and_then(|x| x.as_u64()),
                txbytes_last: v.get("txbytes_last").and_then(|x| x.as_u64()),
            });
        }

        // Files
        let mut stmt = self.conn.prepare(
            "SELECT id, attrs, first_seen, last_seen FROM nodes WHERE kind = 'file'",
        )?;
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
            let flags: Vec<String> = v.get("flags").cloned()
                .and_then(|x| serde_json::from_value(x).ok())
                .unwrap_or_default();
            g.files.push(FileNode {
                path,
                flags,
                first_seen: Timestamp { mono_ns: first_seen as u64, wall_anchor_ns: 0 },
                last_seen: Timestamp { mono_ns: last_seen as u64, wall_anchor_ns: 0 },
                touch_count: v.get("touch_count").and_then(|x| x.as_u64()).unwrap_or(0),
            });
        }

        // Edges
        let mut stmt = self.conn.prepare(
            "SELECT kind, from_kind, from_id, to_kind, to_id, attrs FROM edges",
        )?;
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
                    let overlap: Interval = v.get("overlap").cloned()
                        .and_then(|x| serde_json::from_value(x).ok())
                        .unwrap_or(Interval { from: Timestamp { mono_ns: 0, wall_anchor_ns: 0 }, to: None });
                    g.edges.push(Edge::FrontmostDuring {
                        app: from_id,
                        process: process_id_from_string(&to_id),
                        overlap,
                    });
                }
                "opened_socket" => {
                    // Re-parse socket id (we stored "proto|local|foreign").
                    let parts: Vec<&str> = to_id.splitn(3, '|').collect();
                    if parts.len() != 3 { continue; }
                    g.edges.push(Edge::OpenedSocket {
                        process: process_id_from_string(&from_id),
                        socket: SocketId {
                            proto: parts[0].into(),
                            local_addr: parts[1].into(),
                            foreign_addr: parts[2].into(),
                        },
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
    pub fn processes_root_under_user_parent(&self) -> Result<Vec<ProcessNode>> {
        let mut stmt = self.conn.prepare(
            "SELECT child.id, child.attrs, child.first_seen, child.last_seen
             FROM edges e
             JOIN nodes child  ON child.kind  = 'process' AND child.id  = e.to_id
             JOIN nodes parent ON parent.kind = 'process' AND parent.id = e.from_id
             WHERE e.kind = 'parent_of'
               AND CAST(json_extract(child.attrs,  '$.uid') AS INTEGER) = 0
               AND CAST(json_extract(parent.attrs, '$.uid') AS INTEGER) > 0",
        )?;
        let rows = stmt.query_map([], row_to_process_tuple)?;
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
    pub fn processes_outside_paths(&self, allowed_prefixes: &[&str]) -> Result<Vec<ProcessNode>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, attrs, first_seen, last_seen FROM nodes WHERE kind = 'process'",
        )?;
        let rows = stmt.query_map([], row_to_process_tuple)?;
        let mut out = Vec::new();
        for row in rows {
            let tuple = row?;
            let p = process_from_row(tuple)?;
            let trusted = match p.exec_path.as_deref() {
                None => false, // unknown path is not "trusted"
                Some(path) => allowed_prefixes.iter().any(|prefix| path.starts_with(prefix)),
            };
            if !trusted { out.push(p); }
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
                Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, i64>(2)?, r.get::<_, i64>(3)?))
            })?;
            let mut out = Vec::new();
            for row in rows { out.push(row?); }
            Ok(out)
        };

        for (id_str, attrs, first_seen, last_seen) in load_kind("process")? {
            g.processes.push(process_from_row((id_str, attrs, first_seen, last_seen))?);
        }
        for (id, attrs, _first_seen, _last_seen) in load_kind("app")? {
            let v: serde_json::Value = serde_json::from_str(&attrs)?;
            let intervals: Vec<Interval> = v.get("intervals").cloned()
                .and_then(|x| serde_json::from_value(x).ok()).unwrap_or_default();
            g.apps.push(AppNode {
                id,
                name: v.get("name").and_then(|x| x.as_str()).map(String::from),
                exec_path: v.get("exec_path").and_then(|x| x.as_str()).map(String::from),
                intervals,
            });
        }
        for (_id, attrs, first_seen, last_seen) in load_kind("socket")? {
            let v: serde_json::Value = serde_json::from_str(&attrs)?;
            let sid = SocketId {
                proto: v.get("proto").and_then(|x| x.as_str()).unwrap_or("?").to_string(),
                local_addr: v.get("local_addr").and_then(|x| x.as_str()).unwrap_or("?").to_string(),
                foreign_addr: v.get("foreign_addr").and_then(|x| x.as_str()).unwrap_or("?").to_string(),
            };
            g.sockets.push(SocketNode {
                id: sid,
                state: v.get("state").and_then(|x| x.as_str()).map(String::from),
                process_name: v.get("process_name").and_then(|x| x.as_str()).map(String::from),
                pid_at_open: v.get("pid_at_open").and_then(|x| x.as_u64()).and_then(|n| u32::try_from(n).ok()),
                opened: Timestamp { mono_ns: first_seen as u64, wall_anchor_ns: 0 },
                closed: if last_seen > first_seen {
                    Some(Timestamp { mono_ns: last_seen as u64, wall_anchor_ns: 0 })
                } else { None },
                rxbytes_last: v.get("rxbytes_last").and_then(|x| x.as_u64()),
                txbytes_last: v.get("txbytes_last").and_then(|x| x.as_u64()),
            });
        }
        for (path, attrs, first_seen, last_seen) in load_kind("file")? {
            let v: serde_json::Value = serde_json::from_str(&attrs)?;
            let flags: Vec<String> = v.get("flags").cloned()
                .and_then(|x| serde_json::from_value(x).ok()).unwrap_or_default();
            g.files.push(FileNode {
                path,
                flags,
                first_seen: Timestamp { mono_ns: first_seen as u64, wall_anchor_ns: 0 },
                last_seen: Timestamp { mono_ns: last_seen as u64, wall_anchor_ns: 0 },
                touch_count: v.get("touch_count").and_then(|x| x.as_u64()).unwrap_or(0),
            });
        }

        // Build a quick membership set so we can drop edges whose endpoints
        // fell outside the window. Cheaper than re-issuing per-edge node
        // existence queries and bounds the edge set without trusting the
        // edges' own `last_seen` column.
        let mut have: std::collections::HashSet<(String, String)> = std::collections::HashSet::new();
        for p in &g.processes { have.insert(("process".into(), process_id_to_string(&p.id))); }
        for a in &g.apps      { have.insert(("app".into(), a.id.clone())); }
        for s in &g.sockets   { have.insert(("socket".into(), socket_id_to_string(&s.id))); }
        for f in &g.files     { have.insert(("file".into(), f.path.clone())); }

        let mut stmt = self.conn.prepare(
            "SELECT kind, from_kind, from_id, to_kind, to_id, attrs FROM edges",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?,
                r.get::<_, String>(3)?, r.get::<_, String>(4)?, r.get::<_, String>(5)?,
            ))
        })?;
        for row in rows {
            let (kind, from_kind, from_id, to_kind, to_id, attrs) = row?;
            if !have.contains(&(from_kind.clone(), from_id.clone())) { continue; }
            if !have.contains(&(to_kind.clone(), to_id.clone())) { continue; }
            match kind.as_str() {
                "parent_of" => g.edges.push(Edge::ParentOf {
                    parent: process_id_from_string(&from_id),
                    child: process_id_from_string(&to_id),
                }),
                "frontmost_during" => {
                    let v: serde_json::Value = serde_json::from_str(&attrs)?;
                    let overlap: Interval = v.get("overlap").cloned()
                        .and_then(|x| serde_json::from_value(x).ok())
                        .unwrap_or(Interval { from: Timestamp { mono_ns: 0, wall_anchor_ns: 0 }, to: None });
                    g.edges.push(Edge::FrontmostDuring {
                        app: from_id, process: process_id_from_string(&to_id), overlap,
                    });
                }
                "opened_socket" => {
                    let parts: Vec<&str> = to_id.splitn(3, '|').collect();
                    if parts.len() != 3 { continue; }
                    g.edges.push(Edge::OpenedSocket {
                        process: process_id_from_string(&from_id),
                        socket: SocketId {
                            proto: parts[0].into(),
                            local_addr: parts[1].into(),
                            foreign_addr: parts[2].into(),
                        },
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
        for row in rows { out.push(row?); }
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
            let Some(from_mono) = from_mono else { continue; };
            // For round-tripped graphs `wall_anchor_ns` may be 0, in which
            // case `mono_ns` is itself the unix-ns timestamp (same convention
            // as `ts_to_unix_ns` on the write side).
            let seg_from = combine_ts(from_mono, from_anchor.unwrap_or(0));
            let seg_to = match to_mono {
                Some(m) => combine_ts(m, to_anchor.unwrap_or(0)),
                None => to_unix_ns, // open-ended → clip to window end
            };
            // Overlap test against the requested window.
            if seg_to < from_unix_ns || seg_from > to_unix_ns { continue; }
            let clipped_from = seg_from.max(from_unix_ns);
            let clipped_to = seg_to.min(to_unix_ns);
            let duration_secs = (clipped_to.saturating_sub(clipped_from) / 1_000_000_000).max(0) as u64;
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
        if max_depth == 0 { return Ok(Vec::new()); }
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
                r.get::<_, String>(0)?, r.get::<_, String>(1)?,
                r.get::<_, i64>(2)?,    r.get::<_, i64>(3)?,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows { out.push(process_from_row(row?)?); }
        Ok(out)
    }

    /// Suspicion query: parent processes whose child count is at least
    /// `min_children`. Useful for spotting fork bombs, shells running long
    /// scripts, or unusual fan-out from a process that normally doesn't
    /// spawn anything.
    ///
    /// Returns `(parent_process, child_count)` pairs, sorted by descending
    /// child count.
    pub fn parents_with_many_children(&self, min_children: u32) -> Result<Vec<(ProcessNode, u32)>> {
        let mut stmt = self.conn.prepare(
            "SELECT parent.id, parent.attrs, parent.first_seen, parent.last_seen, COUNT(*) AS n
             FROM edges e
             JOIN nodes parent ON parent.kind = 'process' AND parent.id = e.from_id
             WHERE e.kind = 'parent_of'
             GROUP BY parent.id
             HAVING n >= ?1
             ORDER BY n DESC",
        )?;
        let rows = stmt.query_map(params![min_children], |r| {
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
    let death: Option<Timestamp> = if death_v.is_null() { None } else { serde_json::from_value(death_v).ok() };
    Ok(ProcessNode {
        id: pid_id,
        comm: v.get("comm").and_then(|x| x.as_str()).map(String::from),
        name: v.get("name").and_then(|x| x.as_str()).map(String::from),
        exec_path: v.get("exec_path").and_then(|x| x.as_str()).map(String::from),
        ppid: v.get("ppid").and_then(|x| x.as_u64()).and_then(|n| u32::try_from(n).ok()),
        uid: v.get("uid").and_then(|x| x.as_u64()).and_then(|n| u32::try_from(n).ok()),
        birth: Timestamp { mono_ns: first_seen as u64, wall_anchor_ns: 0 },
        death,
    })
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
    let existed: bool = tx.query_row(
        "SELECT 1 FROM nodes WHERE kind = ?1 AND id = ?2",
        params![kind, id],
        |_| Ok(true),
    ).optional()?.unwrap_or(false);

    tx.execute(
        "INSERT INTO nodes(kind, id, attrs, first_seen, last_seen)
         VALUES(?1, ?2, ?3, ?4, ?5)
         ON CONFLICT(kind, id) DO UPDATE SET
             attrs      = excluded.attrs,
             last_seen  = MAX(excluded.last_seen, nodes.last_seen),
             first_seen = MIN(excluded.first_seen, nodes.first_seen)",
        params![kind, id, attrs, first, last],
    )?;

    if existed { report.nodes_updated += 1; } else { report.nodes_inserted += 1; }
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
    if existed { report.edges_updated += 1; } else { report.edges_inserted += 1; }
    Ok(())
}

fn node_last_seen(tx: &Transaction<'_>, kind: &str, id: &str) -> Result<Timestamp> {
    let last: Option<i64> = tx.query_row(
        "SELECT last_seen FROM nodes WHERE kind=?1 AND id=?2",
        params![kind, id],
        |r| r.get(0),
    ).optional()?;
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
    if wall_anchor_ns == 0 { mono_ns } else { wall_anchor_ns.saturating_add(mono_ns) }
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
        Timestamp { mono_ns: n, wall_anchor_ns: 0 }
    }

    fn small_graph() -> Graph {
        let parent_id = ProcessId { pid: 1, start_unix_secs: 1000 };
        let child_id = ProcessId { pid: 42, start_unix_secs: 1001 };
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
            edges: vec![
                Edge::ParentOf { parent: parent_id.clone(), child: child_id.clone() },
                Edge::OpenedSocket { process: child_id.clone(), socket: sock_id.clone() },
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
        assert_eq!(r2.edges_updated, 2, "every edge should be updated, not inserted; got {r2:?}");
        // Verify count actually bumped in SQL.
        let c: i64 = s.conn.query_row(
            "SELECT count FROM edges WHERE kind='parent_of'",
            [],
            |r| r.get(0),
        ).unwrap();
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
        let parent_of = loaded.edges.iter()
            .filter(|e| matches!(e, Edge::ParentOf { .. }))
            .count();
        let opened_socket = loaded.edges.iter()
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
        let first_seen: i64 = s.conn.query_row(
            "SELECT first_seen FROM nodes WHERE kind='process' AND id='42:1001'",
            [],
            |r| r.get(0),
        ).unwrap();
        assert_eq!(first_seen, 20);
    }

    /// Build a graph with a configurable parent/child uid/exec mix so the
    /// suspicion-query tests are self-contained.
    fn suspicion_graph() -> Graph {
        let init = ProcessNode {
            id: ProcessId { pid: 1, start_unix_secs: 1000 },
            comm: Some("launchd".into()), name: None,
            exec_path: Some("/sbin/launchd".into()),
            ppid: None, uid: Some(0),
            birth: ts(1), death: None,
        };
        // Non-root user shell.
        let shell = ProcessNode {
            id: ProcessId { pid: 100, start_unix_secs: 1001 },
            comm: Some("zsh".into()), name: None,
            exec_path: Some("/bin/zsh".into()),
            ppid: Some(1), uid: Some(501),
            birth: ts(2), death: None,
        };
        // Root child of the non-root shell — the suspicious one.
        let suspicious = ProcessNode {
            id: ProcessId { pid: 200, start_unix_secs: 1002 },
            comm: Some("rooted".into()), name: None,
            exec_path: Some("/tmp/rooted".into()),
            ppid: Some(100), uid: Some(0),
            birth: ts(3), death: None,
        };
        // Boring user process in /usr/bin — should NOT be flagged by either query.
        let curl = ProcessNode {
            id: ProcessId { pid: 300, start_unix_secs: 1003 },
            comm: Some("curl".into()), name: None,
            exec_path: Some("/usr/bin/curl".into()),
            ppid: Some(100), uid: Some(501),
            birth: ts(4), death: None,
        };
        Graph {
            processes: vec![init.clone(), shell.clone(), suspicious.clone(), curl.clone()],
            apps: vec![], sockets: vec![], files: vec![],
            edges: vec![
                Edge::ParentOf { parent: init.id.clone(),  child: shell.id.clone() },
                Edge::ParentOf { parent: shell.id.clone(), child: suspicious.id.clone() },
                Edge::ParentOf { parent: shell.id.clone(), child: curl.id.clone() },
            ],
        }
    }

    #[test]
    fn root_under_user_parent_finds_only_the_escalation() {
        let mut s = Store::open_in_memory().unwrap();
        s.merge_graph(&suspicion_graph()).unwrap();
        let hits = s.processes_root_under_user_parent().unwrap();
        assert_eq!(hits.len(), 1, "expected exactly one escalation; got {hits:?}");
        assert_eq!(hits[0].id.pid, 200);
        assert_eq!(hits[0].comm.as_deref(), Some("rooted"));
    }

    #[test]
    fn outside_paths_excludes_trusted_prefixes() {
        let mut s = Store::open_in_memory().unwrap();
        s.merge_graph(&suspicion_graph()).unwrap();
        // /sbin/, /bin/, /usr/bin/ all trusted — only /tmp/rooted should remain.
        let hits = s.processes_outside_paths(&["/sbin/", "/bin/", "/usr/bin/"]).unwrap();
        assert_eq!(hits.len(), 1, "expected only /tmp/rooted; got {hits:?}");
        assert_eq!(hits[0].exec_path.as_deref(), Some("/tmp/rooted"));
    }

    #[test]
    fn parents_with_many_children_respects_threshold() {
        let mut s = Store::open_in_memory().unwrap();
        s.merge_graph(&suspicion_graph()).unwrap();
        // shell (pid 100) has 2 children; launchd (pid 1) has 1.
        let hits = s.parents_with_many_children(2).unwrap();
        assert_eq!(hits.len(), 1, "only shell crosses threshold; got {hits:?}");
        assert_eq!(hits[0].0.id.pid, 100);
        assert_eq!(hits[0].1, 2);
        // Lower the bar — both parents qualify, sorted by child count desc.
        let all = s.parents_with_many_children(1).unwrap();
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].0.id.pid, 100); // 2 children first
        assert_eq!(all[1].0.id.pid, 1);   // then launchd with 1
    }

    // ---------- batch 2 query tests --------------------------------------

    /// 1s spaced timestamps in unix nanoseconds; wall_anchor is 0 so
    /// `mono_ns` itself is the unix-ns value (matches round-trip convention).
    fn unix_ts(secs: u64) -> Timestamp {
        Timestamp { mono_ns: secs * 1_000_000_000, wall_anchor_ns: 0 }
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
            id: ProcessId { pid: 1, start_unix_secs: 1 },
            comm: Some("launchd".into()), name: None,
            exec_path: Some("/sbin/launchd".into()),
            ppid: None, uid: Some(0),
            birth: unix_ts(0), death: Some(unix_ts(60)),
        };
        let p100 = ProcessNode {
            id: ProcessId { pid: 100, start_unix_secs: 2 },
            comm: Some("Code".into()), name: None,
            exec_path: Some("/Applications/Code.app/Code".into()),
            ppid: Some(1), uid: Some(501),
            birth: unix_ts(5), death: Some(unix_ts(60)),
        };
        let p200 = ProcessNode {
            id: ProcessId { pid: 200, start_unix_secs: 3 },
            comm: Some("curl".into()), name: None,
            exec_path: Some("/usr/bin/curl".into()),
            ppid: Some(100), uid: Some(501),
            birth: unix_ts(10), death: Some(unix_ts(30)),
        };
        let sock_a = SocketId { proto: "tcp4".into(), local_addr: "10.0.0.1.55001".into(), foreign_addr: "1.1.1.1.443".into() };
        let sock_b = SocketId { proto: "tcp4".into(), local_addr: "10.0.0.1.55002".into(), foreign_addr: "2.2.2.2.80".into() };
        let app = AppNode {
            id: "com.microsoft.VSCode".into(),
            name: Some("Code".into()),
            exec_path: Some("/Applications/Code.app/Code".into()),
            intervals: vec![Interval { from: unix_ts(10), to: Some(unix_ts(50)) }],
        };
        Graph {
            processes: vec![p1.clone(), p100.clone(), p200.clone()],
            apps: vec![app],
            sockets: vec![
                SocketNode {
                    id: sock_a.clone(), state: Some("ESTABLISHED".into()),
                    process_name: Some("curl".into()), pid_at_open: Some(200),
                    opened: unix_ts(15), closed: Some(unix_ts(25)),
                    rxbytes_last: Some(1_000), txbytes_last: Some(200),
                },
                SocketNode {
                    id: sock_b.clone(), state: Some("ESTABLISHED".into()),
                    process_name: Some("curl".into()), pid_at_open: Some(200),
                    opened: unix_ts(16), closed: Some(unix_ts(28)),
                    rxbytes_last: Some(5_000), txbytes_last: Some(500),
                },
            ],
            files: vec![],
            edges: vec![
                Edge::ParentOf { parent: p1.id.clone(), child: p100.id.clone() },
                Edge::ParentOf { parent: p100.id.clone(), child: p200.id.clone() },
                Edge::FrontmostDuring {
                    app: "com.microsoft.VSCode".into(),
                    process: p100.id.clone(),
                    overlap: Interval { from: unix_ts(10), to: Some(unix_ts(50)) },
                },
                Edge::OpenedSocket { process: p200.id.clone(), socket: sock_a.clone() },
                Edge::OpenedSocket { process: p200.id.clone(), socket: sock_b.clone() },
            ],
        }
    }

    fn ns(secs: u64) -> i64 { (secs * 1_000_000_000) as i64 }

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
        let parent_edges = g.edges.iter().filter(|e| matches!(e, Edge::ParentOf { .. })).count();
        assert_eq!(parent_edges, 2, "both parent_of edges should survive: {:?}", g.edges);

        // Now a tighter window that excludes p200: 35..45 should drop the
        // 10..30 socket-owning curl process and both sockets that ended at
        // 25/28 — proving the filter actually filters.
        let g_late = s.graph_in_window(ns(35), ns(45)).unwrap();
        let late_pids: Vec<u32> = g_late.processes.iter().map(|p| p.id.pid).collect();
        assert!(!late_pids.contains(&200), "p200 ended at 30s, should be gone: {late_pids:?}");
        assert!(g_late.sockets.is_empty(), "sockets ended before 35s: {:?}", g_late.sockets);
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

    #[test]
    fn frontmost_during_edge_preserves_overlap() {
        let mut s = Store::open_in_memory().unwrap();
        let proc_id = ProcessId { pid: 100, start_unix_secs: 1 };
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
                intervals: vec![Interval { from: ts(5), to: Some(ts(50)) }],
            }],
            sockets: vec![],
            files: vec![],
            edges: vec![Edge::FrontmostDuring {
                app: "com.app.X".into(),
                process: proc_id.clone(),
                overlap: Interval { from: ts(10), to: Some(ts(50)) },
            }],
        };
        s.merge_graph(&g).unwrap();
        let loaded = s.load_graph().unwrap();
        let fd = loaded.edges.iter().find(|e| matches!(e, Edge::FrontmostDuring { .. })).unwrap();
        match fd {
            Edge::FrontmostDuring { app, process, overlap } => {
                assert_eq!(app, "com.app.X");
                assert_eq!(process.pid, 100);
                assert_eq!(overlap.from.mono_ns, 10);
                assert_eq!(overlap.to.map(|t| t.mono_ns), Some(50));
            }
            _ => unreachable!(),
        }
    }
}
