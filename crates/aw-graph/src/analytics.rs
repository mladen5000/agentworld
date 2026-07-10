//! Read-only structural analytics over a `Graph`: adjacency, centrality, and
//! connected components.
//!
//! This module computes facts about graph *shape* only — no thresholds, no
//! judgments about what's anomalous. Interpretation of these numbers belongs
//! in the apps layer (see `aw-agents::topology`).

use std::collections::{HashMap, HashSet};

use crate::{Edge, Graph, ProcessId, SocketId};

/// Unifies the five heterogeneous node id types into one hashable key so
/// analytics can treat the graph as a single homogeneous structure.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum NodeRef {
    Process(ProcessId),
    App(String),
    Socket(SocketId),
    File(String),
    Domain(String),
}

impl NodeRef {
    /// Short human-readable label, following the same conventions as
    /// `dot::to_dot` (comm/name for processes, proto+foreign for sockets,
    /// basename for files).
    pub fn label(&self, graph: &Graph) -> String {
        match self {
            NodeRef::Process(id) => graph
                .processes
                .iter()
                .find(|p| &p.id == id)
                .and_then(|p| p.comm.as_deref().or(p.name.as_deref()))
                .map(|s| format!("{s} (pid {})", id.pid))
                .unwrap_or_else(|| format!("pid {}", id.pid)),
            NodeRef::App(id) => graph
                .apps
                .iter()
                .find(|a| &a.id == id)
                .and_then(|a| a.name.as_deref())
                .unwrap_or(id)
                .to_string(),
            NodeRef::Socket(id) => format!("{} {}", id.proto, id.foreign_addr),
            NodeRef::File(path) => path.rsplit('/').next().unwrap_or(path).to_string(),
            NodeRef::Domain(name) => name.clone(),
        }
    }
}

/// Read-only adjacency projection of a `Graph`, built once and reused by
/// every analytics function. Undirected by construction: centrality and
/// component membership here describe structural connectivity, not causal
/// flow direction.
pub struct Adjacency {
    pub neighbors: HashMap<NodeRef, Vec<(NodeRef, u64)>>,
}

impl Adjacency {
    pub fn from_graph(graph: &Graph) -> Self {
        let mut neighbors: HashMap<NodeRef, Vec<(NodeRef, u64)>> = HashMap::new();

        // Ensure every node appears as a key even if it has no edges, so
        // degree/component queries see isolated nodes too.
        for p in &graph.processes {
            neighbors.entry(NodeRef::Process(p.id.clone())).or_default();
        }
        for a in &graph.apps {
            neighbors.entry(NodeRef::App(a.id.clone())).or_default();
        }
        for s in &graph.sockets {
            neighbors.entry(NodeRef::Socket(s.id.clone())).or_default();
        }
        for f in &graph.files {
            neighbors.entry(NodeRef::File(f.path.clone())).or_default();
        }
        for d in &graph.domains {
            neighbors.entry(NodeRef::Domain(d.name.clone())).or_default();
        }

        let mut add_edge = |a: NodeRef, b: NodeRef, weight: u64| {
            neighbors.entry(a.clone()).or_default().push((b.clone(), weight));
            neighbors.entry(b).or_default().push((a, weight));
        };

        for e in &graph.edges {
            match e {
                Edge::ParentOf { parent, child } => {
                    add_edge(NodeRef::Process(parent.clone()), NodeRef::Process(child.clone()), 1);
                }
                Edge::FrontmostDuring { app, process, .. } => {
                    add_edge(NodeRef::App(app.clone()), NodeRef::Process(process.clone()), 1);
                }
                Edge::OpenedSocket { process, socket } => {
                    add_edge(
                        NodeRef::Process(process.clone()),
                        NodeRef::Socket(socket.clone()),
                        1,
                    );
                }
                Edge::QueriedDomain {
                    process,
                    domain,
                    count,
                } => {
                    add_edge(
                        NodeRef::Process(process.clone()),
                        NodeRef::Domain(domain.clone()),
                        *count,
                    );
                }
            }
        }

        Self { neighbors }
    }
}

/// Unweighted degree centrality: number of distinct neighbors per node.
///
/// This is the primary, trustworthy centrality measure here — it counts
/// distinct relationships, unaffected by how many times any one relationship
/// was re-observed.
pub fn degree_centrality(adj: &Adjacency) -> HashMap<NodeRef, u64> {
    adj.neighbors
        .iter()
        .map(|(n, neighbors)| (n.clone(), neighbors.len() as u64))
        .collect()
}

/// Weighted degree centrality: sum of edge weights per node.
///
/// Caveat: the only edge type carrying a non-trivial weight is
/// `queried_domain`, whose `count` is a *re-observation tally* incremented
/// each time the same process queries the same domain again (see
/// `aw_store::upsert_edge`'s `count = count + 1` semantics) — it is not a
/// measure of the relationship's semantic significance. Treat this as a
/// secondary, caveated signal; prefer `degree_centrality` as the primary
/// measure of a node's structural importance.
pub fn weighted_degree_centrality(adj: &Adjacency) -> HashMap<NodeRef, u64> {
    adj.neighbors
        .iter()
        .map(|(n, neighbors)| (n.clone(), neighbors.iter().map(|(_, w)| w).sum()))
        .collect()
}

/// Connected components of the undirected adjacency graph, via BFS.
///
/// Chosen over modularity-optimizing community detection (e.g. Louvain)
/// because this is a mixed-entity graph (five node kinds, four edge kinds),
/// not a homogeneous weighted graph those algorithms assume. Components
/// answer a directly meaningful question here: which processes, sockets,
/// domains, files, and apps are part of the same causally-linked activity
/// cluster.
pub fn connected_components(adj: &Adjacency) -> Vec<Vec<NodeRef>> {
    let mut visited: HashSet<NodeRef> = HashSet::new();
    let mut components = Vec::new();

    for start in adj.neighbors.keys() {
        if visited.contains(start) {
            continue;
        }
        let mut component = Vec::new();
        let mut queue = std::collections::VecDeque::new();
        queue.push_back(start.clone());
        visited.insert(start.clone());
        while let Some(node) = queue.pop_front() {
            component.push(node.clone());
            if let Some(neighbors) = adj.neighbors.get(&node) {
                for (next, _) in neighbors {
                    if visited.insert(next.clone()) {
                        queue.push_back(next.clone());
                    }
                }
            }
        }
        components.push(component);
    }

    components
}

/// Size of each component, in the same order as `connected_components`'
/// output.
pub fn component_sizes(components: &[Vec<NodeRef>]) -> Vec<usize> {
    components.iter().map(|c| c.len()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ProcessNode;
    use aw_core::Timestamp;

    fn ts(n: u64) -> Timestamp {
        Timestamp {
            mono_ns: n,
            wall_anchor_ns: 0,
        }
    }

    fn pid(n: u32) -> ProcessId {
        ProcessId {
            pid: n,
            start_unix_secs: 1,
        }
    }

    fn process_node(id: ProcessId, ppid: Option<u32>) -> ProcessNode {
        ProcessNode {
            id,
            comm: Some("proc".into()),
            name: None,
            exec_path: None,
            ppid,
            uid: Some(501),
            birth: ts(0),
            death: None,
        }
    }

    #[test]
    fn degree_centrality_counts_distinct_neighbors() {
        // parent(1) -> child(2), child(2) -> child(3): a chain.
        let graph = Graph {
            processes: vec![
                process_node(pid(1), None),
                process_node(pid(2), Some(1)),
                process_node(pid(3), Some(2)),
            ],
            apps: vec![],
            sockets: vec![],
            files: vec![],
            domains: vec![],
            edges: vec![
                Edge::ParentOf {
                    parent: pid(1),
                    child: pid(2),
                },
                Edge::ParentOf {
                    parent: pid(2),
                    child: pid(3),
                },
            ],
        };
        let adj = Adjacency::from_graph(&graph);
        let degree = degree_centrality(&adj);
        assert_eq!(degree[&NodeRef::Process(pid(1))], 1);
        assert_eq!(degree[&NodeRef::Process(pid(2))], 2);
        assert_eq!(degree[&NodeRef::Process(pid(3))], 1);
    }

    #[test]
    fn weighted_degree_sums_edge_counts() {
        let graph = Graph {
            processes: vec![process_node(pid(1), None)],
            apps: vec![],
            sockets: vec![],
            files: vec![],
            domains: vec![crate::DomainNode {
                name: "example.com".into(),
                qtypes: vec![],
                masked: false,
                first_seen: ts(0),
                last_seen: ts(0),
                query_count: 5,
            }],
            edges: vec![Edge::QueriedDomain {
                process: pid(1),
                domain: "example.com".into(),
                count: 5,
            }],
        };
        let adj = Adjacency::from_graph(&graph);
        let weighted = weighted_degree_centrality(&adj);
        assert_eq!(weighted[&NodeRef::Process(pid(1))], 5);
        assert_eq!(weighted[&NodeRef::Domain("example.com".into())], 5);
        // Unweighted degree is still 1 distinct neighbor each.
        let degree = degree_centrality(&adj);
        assert_eq!(degree[&NodeRef::Process(pid(1))], 1);
    }

    #[test]
    fn connected_components_splits_disjoint_clusters() {
        // Two disjoint parent->child pairs: (1->2) and (10->20).
        let graph = Graph {
            processes: vec![
                process_node(pid(1), None),
                process_node(pid(2), Some(1)),
                process_node(pid(10), None),
                process_node(pid(20), Some(10)),
            ],
            apps: vec![],
            sockets: vec![],
            files: vec![],
            domains: vec![],
            edges: vec![
                Edge::ParentOf {
                    parent: pid(1),
                    child: pid(2),
                },
                Edge::ParentOf {
                    parent: pid(10),
                    child: pid(20),
                },
            ],
        };
        let adj = Adjacency::from_graph(&graph);
        let components = connected_components(&adj);
        assert_eq!(components.len(), 2);
        let mut sizes = component_sizes(&components);
        sizes.sort_unstable();
        assert_eq!(sizes, vec![2, 2]);
    }

    #[test]
    fn isolated_node_is_its_own_component() {
        let graph = Graph {
            processes: vec![process_node(pid(1), None)],
            apps: vec![],
            sockets: vec![],
            files: vec![crate::FileNode {
                path: "/tmp/isolated".into(),
                flags: vec![],
                first_seen: ts(0),
                last_seen: ts(0),
                touch_count: 1,
            }],
            domains: vec![],
            edges: vec![],
        };
        let adj = Adjacency::from_graph(&graph);
        let components = connected_components(&adj);
        assert_eq!(components.len(), 2);
        assert!(component_sizes(&components).iter().all(|&s| s == 1));
    }

    #[test]
    fn label_uses_comm_and_pid_for_processes() {
        let graph = Graph {
            processes: vec![process_node(pid(42), None)],
            apps: vec![],
            sockets: vec![],
            files: vec![],
            domains: vec![],
            edges: vec![],
        };
        let node = NodeRef::Process(pid(42));
        assert_eq!(node.label(&graph), "proc (pid 42)");
    }
}
