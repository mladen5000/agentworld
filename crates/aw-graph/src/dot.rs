//! GraphViz DOT serializer.
//!
//! Renders a `Graph` as a `digraph` with four node shapes:
//!   - box       — process (color by uid: root red, user blue, other grey)
//!   - ellipse   — app
//!   - cylinder  — socket
//!   - note      — file
//!
//! Three edge styles:
//!   - solid black   — parent_of (process → process)
//!   - dashed grey   — frontmost_during (app → process)
//!   - solid green   — opened_socket (process → socket)
//!
//! Exec paths and other detail go into tooltips, not labels — labels stay short.

use crate::{Edge, Graph, ProcessId, ProcessNode, AppNode, SocketId, SocketNode, FileNode};

pub fn to_dot(graph: &Graph) -> String {
    let mut out = String::new();
    out.push_str("digraph agentworld {\n");
    out.push_str("  rankdir=LR;\n");
    out.push_str("  graph [fontname=\"Helvetica\"];\n");
    out.push_str("  node  [fontname=\"Helvetica\", fontsize=10];\n");
    out.push_str("  edge  [fontname=\"Helvetica\", fontsize=9];\n");

    for p in &graph.processes {
        out.push_str(&process_node_line(p));
    }
    for a in &graph.apps {
        out.push_str(&app_node_line(a));
    }
    for s in &graph.sockets {
        out.push_str(&socket_node_line(s));
    }
    for f in &graph.files {
        out.push_str(&file_node_line(f));
    }
    for e in &graph.edges {
        out.push_str(&edge_line(e));
    }

    out.push_str("}\n");
    out
}

fn process_node_line(p: &ProcessNode) -> String {
    let id = process_dot_id(&p.id);
    let label = format!(
        "{}\\npid {}",
        escape(p.comm.as_deref().or(p.name.as_deref()).unwrap_or("?")),
        p.id.pid,
    );
    let tooltip = escape(p.exec_path.as_deref().unwrap_or(""));
    let color = uid_color(p.uid);
    format!(
        "  \"{id}\" [shape=box, style=filled, fillcolor=\"{color}\", label=\"{label}\", tooltip=\"{tooltip}\"];\n"
    )
}

fn app_node_line(a: &AppNode) -> String {
    let id = app_dot_id(&a.id);
    let label = escape(a.name.as_deref().unwrap_or(&a.id));
    let tooltip = escape(a.exec_path.as_deref().unwrap_or(&a.id));
    format!(
        "  \"{id}\" [shape=ellipse, style=filled, fillcolor=\"#fff4c2\", label=\"{label}\", tooltip=\"{tooltip}\"];\n"
    )
}

fn socket_node_line(s: &SocketNode) -> String {
    let id = socket_dot_id(&s.id);
    // Compact label: proto + foreign endpoint (the local side is usually the
    // ephemeral port and adds noise).
    let label = escape(&format!("{}\\n{}", s.id.proto, s.id.foreign_addr));
    let tooltip = escape(&format!(
        "{} {} -> {} ({})",
        s.id.proto,
        s.id.local_addr,
        s.id.foreign_addr,
        s.state.as_deref().unwrap_or("?"),
    ));
    let color = if s.closed.is_some() { "#e6e6fa" } else { "#c6e6c6" };
    format!(
        "  \"{id}\" [shape=cylinder, style=filled, fillcolor=\"{color}\", label=\"{label}\", tooltip=\"{tooltip}\"];\n"
    )
}

fn file_node_line(f: &FileNode) -> String {
    let id = file_dot_id(&f.path);
    // Just the basename in the label; full path in tooltip.
    let basename = f.path.rsplit('/').next().unwrap_or(&f.path);
    let label = escape(basename);
    let tooltip = escape(&f.path);
    format!(
        "  \"{id}\" [shape=note, style=filled, fillcolor=\"#fde2c2\", label=\"{label}\", tooltip=\"{tooltip}\"];\n"
    )
}

fn edge_line(e: &Edge) -> String {
    match e {
        Edge::ParentOf { parent, child } => {
            format!(
                "  \"{}\" -> \"{}\" [color=\"#444\"];\n",
                process_dot_id(parent),
                process_dot_id(child),
            )
        }
        Edge::FrontmostDuring { app, process, .. } => {
            format!(
                "  \"{}\" -> \"{}\" [style=dashed, color=\"#bbb\"];\n",
                app_dot_id(app),
                process_dot_id(process),
            )
        }
        Edge::OpenedSocket { process, socket } => {
            format!(
                "  \"{}\" -> \"{}\" [color=\"#3a8a3a\"];\n",
                process_dot_id(process),
                socket_dot_id(socket),
            )
        }
    }
}

fn process_dot_id(id: &ProcessId) -> String {
    format!("p_{}_{}", id.pid, id.start_unix_secs)
}

fn socket_dot_id(id: &SocketId) -> String {
    // Slugify proto:local→foreign. Replace anything not safe with `_`.
    let raw = format!("{}_{}_{}", id.proto, id.local_addr, id.foreign_addr);
    let mut s = String::with_capacity(raw.len() + 2);
    s.push_str("s_");
    for c in raw.chars() {
        if c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_' {
            s.push(c);
        } else {
            s.push('_');
        }
    }
    s
}

fn file_dot_id(path: &str) -> String {
    let mut s = String::with_capacity(path.len() + 2);
    s.push_str("f_");
    for c in path.chars() {
        if c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_' {
            s.push(c);
        } else {
            s.push('_');
        }
    }
    s
}

fn app_dot_id(bundle_or_path: &str) -> String {
    // DOT identifiers in quoted form accept arbitrary chars except embedded
    // unescaped quotes. We still slugify slightly to avoid extreme strings.
    let mut s = String::with_capacity(bundle_or_path.len() + 2);
    s.push_str("a_");
    for c in bundle_or_path.chars() {
        if c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_' {
            s.push(c);
        } else {
            s.push('_');
        }
    }
    s
}

fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            _ => out.push(c),
        }
    }
    out
}

fn uid_color(uid: Option<u32>) -> &'static str {
    match uid {
        Some(0) => "#ffd0d0",   // root: red tint
        Some(501..=600) => "#d0e6ff", // primary user range: blue tint
        Some(_) => "#e8e8e8",   // other: grey
        None => "#f5f5f5",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AppNode, Edge, FileNode, Graph, Interval, ProcessId, ProcessNode, SocketId, SocketNode};
    use aw_core::Timestamp;

    fn ts(n: u64) -> Timestamp { Timestamp { mono_ns: n, wall_anchor_ns: 0 } }

    #[test]
    fn renders_minimal_graph() {
        let parent_id = ProcessId { pid: 1, start_unix_secs: 100 };
        let child_id = ProcessId { pid: 200, start_unix_secs: 101 };
        let g = Graph {
            processes: vec![
                ProcessNode {
                    id: parent_id.clone(),
                    comm: Some("init".into()),
                    name: None,
                    exec_path: Some("/sbin/init".into()),
                    ppid: None,
                    uid: Some(0),
                    birth: ts(10),
                    death: None,
                },
                ProcessNode {
                    id: child_id.clone(),
                    comm: Some("shell".into()),
                    name: None,
                    exec_path: Some("/bin/zsh".into()),
                    ppid: Some(1),
                    uid: Some(501),
                    birth: ts(20),
                    death: None,
                },
            ],
            apps: vec![AppNode {
                id: "com.apple.Terminal".into(),
                name: Some("Terminal".into()),
                exec_path: Some("/Applications/Terminal.app/Contents/MacOS/Terminal".into()),
                intervals: vec![Interval { from: ts(15), to: None }],
            }],
            sockets: vec![],
            files: vec![],
            edges: vec![
                Edge::ParentOf { parent: parent_id.clone(), child: child_id.clone() },
                Edge::FrontmostDuring {
                    app: "com.apple.Terminal".into(),
                    process: child_id.clone(),
                    overlap: Interval { from: ts(20), to: None },
                },
            ],
        };

        let dot = to_dot(&g);
        assert!(dot.starts_with("digraph agentworld {"));
        assert!(dot.contains("\"p_1_100\""), "missing parent node id: {dot}");
        assert!(dot.contains("\"p_200_101\""), "missing child node id");
        assert!(dot.contains("\"a_com.apple.Terminal\""));
        assert!(dot.contains("\"p_1_100\" -> \"p_200_101\""));
        assert!(dot.contains("\"a_com.apple.Terminal\" -> \"p_200_101\""));
        assert!(dot.contains("style=dashed"));
        // root colour applied to pid 1 (uid 0)
        assert!(dot.contains("#ffd0d0"));
        // user colour applied to pid 200 (uid 501)
        assert!(dot.contains("#d0e6ff"));
    }

    #[test]
    fn renders_sockets_files_and_opened_socket_edge() {
        let proc_id = ProcessId { pid: 100, start_unix_secs: 1 };
        let sock_id = SocketId {
            proto: "tcp4".into(),
            local_addr: "10.0.0.1.50000".into(),
            foreign_addr: "1.2.3.4.443".into(),
        };
        let g = Graph {
            processes: vec![ProcessNode {
                id: proc_id.clone(),
                comm: Some("curl".into()),
                name: None,
                exec_path: Some("/usr/bin/curl".into()),
                ppid: None,
                uid: Some(501),
                birth: ts(10),
                death: None,
            }],
            apps: vec![],
            sockets: vec![SocketNode {
                id: sock_id.clone(),
                state: Some("ESTABLISHED".into()),
                process_name: Some("curl".into()),
                pid_at_open: Some(100),
                opened: ts(11),
                closed: None,
                rxbytes_last: Some(0),
                txbytes_last: Some(0),
            }],
            files: vec![FileNode {
                path: "/tmp/output.txt".into(),
                flags: vec!["created".into(), "is_file".into()],
                first_seen: ts(12),
                last_seen: ts(13),
                touch_count: 2,
            }],
            edges: vec![Edge::OpenedSocket { process: proc_id.clone(), socket: sock_id.clone() }],
        };
        let dot = to_dot(&g);
        assert!(dot.contains("shape=cylinder"), "missing cylinder for socket");
        assert!(dot.contains("shape=note"), "missing note for file");
        assert!(dot.contains("output.txt"), "missing file basename");
        assert!(dot.contains("\"p_100_1\" -> \"s_tcp4_"), "missing opened_socket edge: {dot}");
        assert!(dot.contains("#3a8a3a"), "missing green color for opened_socket edge");
    }

    #[test]
    fn escapes_dangerous_chars_in_labels() {
        let id = ProcessId { pid: 7, start_unix_secs: 1 };
        let g = Graph {
            processes: vec![ProcessNode {
                id,
                comm: Some("weird \"name\" with\nnewline".into()),
                name: None,
                exec_path: Some("/tmp/with\"quote".into()),
                ppid: None,
                uid: Some(501),
                birth: ts(1),
                death: None,
            }],
            apps: vec![],
            sockets: vec![],
            files: vec![],
            edges: vec![],
        };
        let dot = to_dot(&g);
        // No unescaped quote should appear inside the label="..." value.
        // The escaped sequence \" should appear instead.
        assert!(dot.contains("\\\"name\\\""));
        assert!(dot.contains("\\n"));
    }
}
