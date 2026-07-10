//! Topology-based anomaly scoring (apps layer).
//!
//! Complements `baseline`'s statistical (volume/rate) anomaly signals with a
//! structural one: does this snapshot's *shape* differ unusually from the
//! previous snapshot's shape? Scoring stays here by design — `aw-graph`
//! supplies only mechanical facts about graph shape (`aw_graph::analytics`);
//! every judgment about what counts as an unusual shift happens in this
//! module.

use std::collections::HashSet;

use aw_graph::analytics::{self, NodeRef};
use aw_graph::Graph;

use crate::baseline::AnomalyScore;

/// A degree jump larger than this (in absolute distinct-neighbor count)
/// triggers a `degree_spike` flag. Chosen as a coarse, fixed prior —
/// analogous to `baseline`'s legacy constants for a cold store — since a
/// single snapshot pair has no history to learn a percentile from.
const DEGREE_SPIKE_MIN_DELTA: i64 = 5;

/// Score the structural difference between two graph snapshots of the same
/// machine (`prev` earlier, `curr` later). Returns one `AnomalyScore` per
/// notable structural shift; an unremarkable diff returns an empty vec.
pub fn score_snapshot_diff(prev: &Graph, curr: &Graph) -> Vec<AnomalyScore> {
    let mut scores = Vec::new();

    let prev_adj = analytics::Adjacency::from_graph(prev);
    let curr_adj = analytics::Adjacency::from_graph(curr);

    score_new_components(prev, &prev_adj, curr, &curr_adj, &mut scores);
    score_degree_spikes(prev, &prev_adj, curr, &curr_adj, &mut scores);

    scores
}

fn score_new_components(
    prev: &Graph,
    prev_adj: &analytics::Adjacency,
    curr: &Graph,
    curr_adj: &analytics::Adjacency,
    scores: &mut Vec<AnomalyScore>,
) {
    let prev_components = analytics::connected_components(prev_adj);
    let curr_components = analytics::connected_components(curr_adj);

    let prev_nodes: HashSet<&NodeRef> = prev_adj.neighbors.keys().collect();

    for component in &curr_components {
        // A component is "new" if every one of its nodes is absent from the
        // previous snapshot — i.e. this whole cluster of activity appeared
        // between snapshots, rather than merging into or growing off an
        // existing cluster.
        if component.len() < 2 {
            continue; // isolated single nodes are routine churn, not a cluster
        }
        if component.iter().all(|n| !prev_nodes.contains(n)) {
            let sample = component
                .iter()
                .max_by_key(|n| curr_adj.neighbors.get(n).map(|v| v.len()).unwrap_or(0))
                .map(|n| n.label(curr))
                .unwrap_or_else(|| "?".to_string());
            scores.push(AnomalyScore {
                entity: format!("component:{sample}"),
                metric: "new_component",
                observed: component.len() as f64,
                baseline_p99: 0.0,
                score: component.len() as f64,
                text: format!(
                    "New activity cluster appeared: {} entities including {sample} (no shared history with the prior snapshot)",
                    component.len()
                ),
            });
        }
    }

    // A component merge: two previously-disjoint prior components are now
    // both fully contained in one current component.
    let curr_component_of: std::collections::HashMap<&NodeRef, usize> = curr_components
        .iter()
        .enumerate()
        .flat_map(|(i, c)| c.iter().map(move |n| (n, i)))
        .collect();
    for prev_component in &prev_components {
        if prev_component.len() < 2 {
            continue;
        }
        let mut merged_into: HashSet<usize> = HashSet::new();
        for n in prev_component {
            if let Some(&idx) = curr_component_of.get(n) {
                merged_into.insert(idx);
            }
        }
        if merged_into.len() > 1 {
            let sample = prev_component
                .first()
                .map(|n| n.label(prev))
                .unwrap_or_else(|| "?".to_string());
            scores.push(AnomalyScore {
                entity: format!("component:{sample}"),
                metric: "component_merge",
                observed: merged_into.len() as f64,
                baseline_p99: 1.0,
                score: merged_into.len() as f64,
                text: format!(
                    "Previously separate activity clusters merged into one (near {sample})"
                ),
            });
        }
    }
}

fn score_degree_spikes(
    prev: &Graph,
    prev_adj: &analytics::Adjacency,
    curr: &Graph,
    curr_adj: &analytics::Adjacency,
    scores: &mut Vec<AnomalyScore>,
) {
    let prev_degree = analytics::degree_centrality(prev_adj);
    let curr_degree = analytics::degree_centrality(curr_adj);

    for (node, &curr_d) in &curr_degree {
        let prev_d = prev_degree.get(node).copied().unwrap_or(0);
        let delta = curr_d as i64 - prev_d as i64;
        if delta >= DEGREE_SPIKE_MIN_DELTA {
            scores.push(AnomalyScore {
                entity: node.label(curr),
                metric: "degree_spike",
                observed: curr_d as f64,
                baseline_p99: prev_d as f64,
                score: delta as f64,
                text: format!(
                    "{} became far more connected: {prev_d} -> {curr_d} distinct relationships",
                    node.label(curr)
                ),
            });
        }
    }
    let _ = prev; // kept for signature symmetry / future use (e.g. labeling prev-side entities)
}

#[cfg(test)]
mod tests {
    use super::*;
    use aw_core::Timestamp;
    use aw_graph::{Edge, ProcessId, ProcessNode};

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

    fn empty_graph() -> Graph {
        Graph::default()
    }

    #[test]
    fn no_diff_produces_no_scores() {
        let g = Graph {
            processes: vec![process_node(pid(1), None), process_node(pid(2), Some(1))],
            edges: vec![Edge::ParentOf {
                parent: pid(1),
                child: pid(2),
            }],
            ..empty_graph()
        };
        let scores = score_snapshot_diff(&g, &g);
        assert!(scores.is_empty(), "identical snapshots: {scores:?}");
    }

    #[test]
    fn new_component_is_flagged() {
        let prev = empty_graph();
        let curr = Graph {
            processes: vec![process_node(pid(1), None), process_node(pid(2), Some(1))],
            edges: vec![Edge::ParentOf {
                parent: pid(1),
                child: pid(2),
            }],
            ..empty_graph()
        };
        let scores = score_snapshot_diff(&prev, &curr);
        assert!(
            scores.iter().any(|s| s.metric == "new_component"),
            "expected new_component flag: {scores:?}"
        );
    }

    #[test]
    fn degree_spike_is_flagged() {
        // pid(1) goes from parent-of-none to parent-of-6 children.
        let prev = Graph {
            processes: vec![process_node(pid(1), None)],
            ..empty_graph()
        };
        let mut curr_processes = vec![process_node(pid(1), None)];
        let mut edges = Vec::new();
        for i in 2..8 {
            curr_processes.push(process_node(pid(i), Some(1)));
            edges.push(Edge::ParentOf {
                parent: pid(1),
                child: pid(i),
            });
        }
        let curr = Graph {
            processes: curr_processes,
            edges,
            ..empty_graph()
        };
        let scores = score_snapshot_diff(&prev, &curr);
        assert!(
            scores.iter().any(|s| s.metric == "degree_spike"),
            "expected degree_spike flag: {scores:?}"
        );
    }

    #[test]
    fn small_degree_change_not_flagged() {
        let prev = Graph {
            processes: vec![process_node(pid(1), None), process_node(pid(2), Some(1))],
            edges: vec![Edge::ParentOf {
                parent: pid(1),
                child: pid(2),
            }],
            ..empty_graph()
        };
        let curr = Graph {
            processes: vec![
                process_node(pid(1), None),
                process_node(pid(2), Some(1)),
                process_node(pid(3), Some(1)),
            ],
            edges: vec![
                Edge::ParentOf {
                    parent: pid(1),
                    child: pid(2),
                },
                Edge::ParentOf {
                    parent: pid(1),
                    child: pid(3),
                },
            ],
            ..empty_graph()
        };
        let scores = score_snapshot_diff(&prev, &curr);
        assert!(
            !scores.iter().any(|s| s.metric == "degree_spike"),
            "small delta should not spike: {scores:?}"
        );
    }
}
