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
