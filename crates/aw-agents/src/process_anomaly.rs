//! Process anomaly detector.
//!
//! Builds a **candidate set** of processes worth showing the LLM by running
//! three suspicion-focused queries against the world model:
//!
//! - Root processes spawned under a non-root parent (privilege-escalation shape)
//! - Processes whose `exec_path` lies outside trusted prefixes
//! - Parents with unusually many children (fork-bomb / heavy shell)
//!
//! These queries scale with the count of *interesting* processes, not the
//! capture size, so the LLM never has to choose between blind sampling and
//! a context overflow.
//!
//! Two entry points:
//!
//! - [`ProcessAnomalyDetector::run_from_store`] — the preferred path; runs
//!   each query as a focused SQL statement against `aw-store`.
//! - [`ProcessAnomalyDetector::run`] — kept for callers (and tests) that have
//!   an in-memory `Graph` but no SQLite. It computes the same candidate set
//!   from `graph.processes` and `graph.edges` in Rust.
//!
//! Output is parsed structured JSON: a list of flagged processes with a
//! short reason each. We fall back to free-form text if JSON parsing fails.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use anyhow::Result;
use aw_graph::{Edge, Graph, ProcessNode};
use aw_llm::{Format, GenerateRequest, Options};
use aw_store::Store;
use serde::{Deserialize, Serialize};

use crate::{AgentCtx, Report};

/// Trusted-path policy. Anything whose `exec_path` does NOT start with one
/// of these prefixes is added to the candidate set. Tuned for stock macOS;
/// callers wanting different policy should construct their own and pass it
/// through [`ProcessAnomalyDetector::with_trusted_prefixes`].
pub const DEFAULT_TRUSTED_PATH_PREFIXES: &[&str] = &[
    "/System/",
    "/usr/bin/",
    "/usr/sbin/",
    "/usr/libexec/",
    "/sbin/",
    "/bin/",
    "/Applications/",
    "/Library/Apple/",
    // Homebrew's default prefix on Apple silicon. Not stock macOS, but so
    // ubiquitous on dev machines that flagging it every window buries real
    // signal under package-manager noise.
    "/opt/homebrew/",
];

/// At what fan-out a parent process becomes "unusually prolific". Picked
/// conservatively for desktop captures; raise it for long batch jobs.
pub const DEFAULT_PROLIFIC_PARENT_THRESHOLD: u32 = 8;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnomalyFinding {
    pub pid: u32,
    pub comm: Option<String>,
    pub exec_path: Option<String>,
    pub reason: String,
    /// "low" | "medium" | "high"
    pub severity: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LlmResponse {
    summary: String,
    findings: Vec<AnomalyFinding>,
}

/// Why each process landed in the candidate set. The agent surfaces this to
/// the LLM so it can weight findings by how it was selected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum CandidateReason {
    RootUnderUserParent,
    PathOutsideTrusted,
    ProlificParent(u32),
}

impl CandidateReason {
    fn tag(self) -> String {
        match self {
            Self::RootUnderUserParent => "root_under_user_parent".into(),
            Self::PathOutsideTrusted => "path_outside_trusted".into(),
            Self::ProlificParent(n) => format!("prolific_parent({n}_children)"),
        }
    }
}

pub struct ProcessAnomalyDetector {
    ctx: AgentCtx,
    trusted_prefixes: Vec<String>,
    prolific_threshold: u32,
}

impl ProcessAnomalyDetector {
    pub fn new(ctx: AgentCtx) -> Self {
        Self {
            ctx,
            trusted_prefixes: DEFAULT_TRUSTED_PATH_PREFIXES
                .iter()
                .map(|s| s.to_string())
                .collect(),
            prolific_threshold: DEFAULT_PROLIFIC_PARENT_THRESHOLD,
        }
    }

    pub fn with_trusted_prefixes(mut self, prefixes: Vec<String>) -> Self {
        self.trusted_prefixes = prefixes;
        self
    }

    pub fn with_prolific_threshold(mut self, n: u32) -> Self {
        self.prolific_threshold = n;
        self
    }

    /// Preferred path: run the suspicion queries against the persisted store.
    pub async fn run_from_store(&self, store: &Store) -> Result<Report> {
        let trusted: Vec<&str> = self.trusted_prefixes.iter().map(|s| s.as_str()).collect();
        let mut candidates: BTreeMap<u32, (ProcessNode, BTreeSet<CandidateReason>)> =
            BTreeMap::new();

        for p in store.processes_root_under_user_parent(0)? {
            candidates
                .entry(p.id.pid)
                .or_insert_with(|| (p.clone(), BTreeSet::new()))
                .1
                .insert(CandidateReason::RootUnderUserParent);
        }
        for p in store.processes_outside_paths(&trusted, 0)? {
            candidates
                .entry(p.id.pid)
                .or_insert_with(|| (p.clone(), BTreeSet::new()))
                .1
                .insert(CandidateReason::PathOutsideTrusted);
        }
        for (p, n) in store.parents_with_many_children(self.prolific_threshold, 0)? {
            candidates
                .entry(p.id.pid)
                .or_insert_with(|| (p.clone(), BTreeSet::new()))
                .1
                .insert(CandidateReason::ProlificParent(n));
        }

        // We need a process count for the report header. Cheaper to ask the
        // store than to re-load the whole graph just for `.len()`.
        let total = store.load_graph()?.processes.len();
        // Parent-comm lookup for rendering: build a tiny pid → comm map from
        // the candidates themselves plus any parents they point to.
        let candidate_vec: Vec<(ProcessNode, Vec<CandidateReason>)> = candidates
            .into_values()
            .map(|(p, rs)| (p, rs.into_iter().collect()))
            .collect();
        let parent_comm_lookup = build_parent_comm_lookup_from_store(store, &candidate_vec)?;
        self.ask_llm(&candidate_vec, total, &parent_comm_lookup)
            .await
    }

    /// Fallback path for callers that already have an in-memory `Graph`
    /// (e.g. `aw-graph-cli` pipelines that haven't been persisted). Mirrors
    /// `run_from_store` exactly: same three suspicion criteria, computed in
    /// Rust over `graph.processes` and `graph.edges`.
    pub async fn run(&self, graph: &Graph) -> Result<Report> {
        let candidates =
            candidates_from_graph(graph, &self.trusted_prefixes, self.prolific_threshold);
        let total = graph.processes.len();
        let parent_comm_lookup = build_parent_comm_lookup_from_graph(graph);
        self.ask_llm(&candidates, total, &parent_comm_lookup).await
    }

    async fn ask_llm(
        &self,
        candidates: &[(ProcessNode, Vec<CandidateReason>)],
        total: usize,
        parent_comm: &HashMap<u32, String>,
    ) -> Result<Report> {
        let candidate_count = candidates.len();

        // Apply the context-window cap as a final safeguard. With targeted
        // queries this almost never trips.
        let cap = self.ctx.config.max_input_items.min(candidate_count);
        let shown = &candidates[..cap];
        let process_block = render_candidates(shown, parent_comm);

        let prompt = if shown.is_empty() {
            format!(
                "A macOS capture observed {total} processes. None matched any of the \
                 suspicion queries (root-under-user-parent, exec outside trusted \
                 paths, prolific parents). Return JSON with an empty findings array \
                 and a one-sentence summary noting the all-clear:\n\
                 {{ \"summary\": \"<one sentence>\", \"findings\": [] }}"
            )
        } else {
            format!(
                "Below are {cap} processes (of {candidate_count} candidates from {total} total) \
                 pre-filtered by suspicion queries. Each line includes a `reasons=[...]` \
                 tag explaining why it was selected. Decide which are genuinely \
                 suspicious — the queries cast a wide net and many candidates will be \
                 benign (e.g. `sudo` is the expected `root_under_user_parent` case). \
                 Return ONLY valid JSON matching this exact shape:\n\
                 {{\n  \"summary\": \"<one or two sentences overall>\",\n  \
                 \"findings\": [\n    {{ \"pid\": <u32>, \"comm\": \"<string or null>\", \
                 \"exec_path\": \"<string or null>\", \"reason\": \"<concise English>\", \
                 \"severity\": \"low\"|\"medium\"|\"high\" }}\n  ]\n}}\n\n\
                 PROCESSES:\n{process_block}"
            )
        };

        let system = Some(
            "You are a macOS security analyst triaging pre-filtered process candidates. \
             Be precise and skeptical: many candidates will be benign tooling. Only \
             flag what is genuinely unusual. Output strictly valid JSON; no prose \
             outside the JSON object."
                .to_string(),
        );

        let req = GenerateRequest {
            model: self.ctx.config.model.clone(),
            prompt,
            system,
            options: Some(Options {
                temperature: Some(self.ctx.config.temperature),
                num_predict: Some(1024),
                num_ctx: Some(8192),
            }),
            format: Some(Format::Json),
            stream: false,
        };

        let resp = self.ctx.llm.generate(req).await?;
        let raw = resp.response.trim();

        let (summary, findings, parse_error) = match serde_json::from_str::<LlmResponse>(raw) {
            Ok(parsed) => (parsed.summary, parsed.findings, false),
            Err(e) => {
                tracing::warn!(
                    "process_anomaly: JSON parse failed ({e}); falling back to raw text"
                );
                (raw.to_string(), Vec::new(), true)
            }
        };

        Ok(Report {
            summary,
            details: serde_json::json!({
                "processes_total": total,
                "candidates_total": candidate_count,
                "candidates_shown": cap,
                "findings": findings,
                "parse_error": parse_error,
            }),
            model: resp.model,
        })
    }
}

/// Per-category cap on [`suspicion_flags_from_store`] output. Dev machines
/// legitimately run many binaries outside trusted paths; without a cap that
/// one category would drown the others in the narrator prompt.
const MAX_FLAGS_PER_CATEGORY: usize = 6;

/// Deterministic (no-LLM) suspicion flags for a time window, rendered as
/// short human-readable strings ready to drop into the timeline narrator's
/// `CaptureSummary::suspicions`. Same three heuristics as
/// [`ProcessAnomalyDetector`], but computed only — cheap enough to run on
/// every daemon tick without an LLM call.
///
/// `since_unix_ns` restricts all three queries to processes active at/after
/// that time; pass `0` for all-time.
pub fn suspicion_flags_from_store(
    store: &Store,
    since_unix_ns: i64,
    trusted_prefixes: &[&str],
    prolific_threshold: u32,
) -> Result<Vec<String>> {
    let mut flags = Vec::new();

    // Privilege-escalation shape. `sudo`/`doas` are the expected boring case
    // — a user typing sudo is not an anomaly worth a flag every window.
    let mut escalations = Vec::new();
    for p in store.processes_root_under_user_parent(since_unix_ns)? {
        if matches!(p.comm.as_deref(), Some("sudo") | Some("doas")) {
            continue;
        }
        escalations.push(format!(
            "root process '{}' (pid {}, {}) is running under a non-root user parent",
            p.comm.as_deref().unwrap_or("?"),
            p.id.pid,
            p.exec_path.as_deref().unwrap_or("path unknown"),
        ));
    }
    push_capped(&mut flags, escalations, "similar root-under-user processes");

    // Untrusted exec paths, deduped by (comm, exec_path) so N runs of the
    // same binary read as one flag rather than N.
    let mut seen: BTreeSet<(Option<String>, Option<String>)> = BTreeSet::new();
    let mut untrusted = Vec::new();
    for p in store.processes_outside_paths(trusted_prefixes, since_unix_ns)? {
        if !seen.insert((p.comm.clone(), p.exec_path.clone())) {
            continue;
        }
        untrusted.push(format!(
            "'{}' ran from an untrusted location: {}",
            p.comm.as_deref().unwrap_or("?"),
            p.exec_path.as_deref().unwrap_or("no exec path recorded"),
        ));
    }
    push_capped(&mut flags, untrusted, "more processes from untrusted paths");

    // Prolific parents — fan-out counted within the window, so a long-lived
    // shell is only flagged while it is actually spawning.
    let mut prolific = Vec::new();
    for (p, n) in store.parents_with_many_children(prolific_threshold, since_unix_ns)? {
        prolific.push(format!(
            "'{}' (pid {}) spawned {} child processes",
            p.comm.as_deref().unwrap_or("?"),
            p.id.pid,
            n,
        ));
    }
    push_capped(&mut flags, prolific, "more prolific parents");

    Ok(flags)
}

fn push_capped(out: &mut Vec<String>, items: Vec<String>, overflow_label: &str) {
    let extra = items.len().saturating_sub(MAX_FLAGS_PER_CATEGORY);
    out.extend(items.into_iter().take(MAX_FLAGS_PER_CATEGORY));
    if extra > 0 {
        out.push(format!("(+{extra} {overflow_label})"));
    }
}

/// Mirror of the SQL suspicion queries against an in-memory `Graph`. Kept in
/// sync with `Store::processes_root_under_user_parent`,
/// `processes_outside_paths`, and `parents_with_many_children`.
fn candidates_from_graph(
    graph: &Graph,
    trusted_prefixes: &[String],
    prolific_threshold: u32,
) -> Vec<(ProcessNode, Vec<CandidateReason>)> {
    let by_pid: HashMap<u32, &ProcessNode> =
        graph.processes.iter().map(|p| (p.id.pid, p)).collect();
    let mut child_counts: HashMap<u32, u32> = HashMap::new();
    for edge in &graph.edges {
        if let Edge::ParentOf { parent, .. } = edge {
            *child_counts.entry(parent.pid).or_insert(0) += 1;
        }
    }

    let mut candidates: BTreeMap<u32, (ProcessNode, BTreeSet<CandidateReason>)> = BTreeMap::new();

    for p in &graph.processes {
        // root under user parent
        if p.uid == Some(0) {
            if let Some(parent_pid) = p.ppid {
                if let Some(parent) = by_pid.get(&parent_pid) {
                    if parent.uid.is_some_and(|u| u > 0) {
                        candidates
                            .entry(p.id.pid)
                            .or_insert_with(|| (p.clone(), BTreeSet::new()))
                            .1
                            .insert(CandidateReason::RootUnderUserParent);
                    }
                }
            }
        }
        // exec path outside trusted prefixes
        let trusted = match p.exec_path.as_deref() {
            None => false,
            Some(path) => trusted_prefixes
                .iter()
                .any(|prefix| path.starts_with(prefix)),
        };
        if !trusted {
            candidates
                .entry(p.id.pid)
                .or_insert_with(|| (p.clone(), BTreeSet::new()))
                .1
                .insert(CandidateReason::PathOutsideTrusted);
        }
        // prolific parent
        if let Some(&n) = child_counts.get(&p.id.pid) {
            if n >= prolific_threshold {
                candidates
                    .entry(p.id.pid)
                    .or_insert_with(|| (p.clone(), BTreeSet::new()))
                    .1
                    .insert(CandidateReason::ProlificParent(n));
            }
        }
    }

    candidates
        .into_values()
        .map(|(p, rs)| (p, rs.into_iter().collect()))
        .collect()
}

fn build_parent_comm_lookup_from_graph(graph: &Graph) -> HashMap<u32, String> {
    graph
        .processes
        .iter()
        .filter_map(|p| p.comm.as_ref().map(|c| (p.id.pid, c.clone())))
        .collect()
}

fn build_parent_comm_lookup_from_store(
    store: &Store,
    candidates: &[(ProcessNode, Vec<CandidateReason>)],
) -> Result<HashMap<u32, String>> {
    // Cheap: load the whole graph (we already do this for the count) and
    // index by pid. For the volumes this agent runs against, a streaming
    // lookup is over-engineering — the store has at most thousands of
    // processes after even a long capture.
    let g = store.load_graph()?;
    let mut map: HashMap<u32, String> = g
        .processes
        .iter()
        .filter_map(|p| p.comm.as_ref().map(|c| (p.id.pid, c.clone())))
        .collect();
    // Make sure every candidate's own comm is in the map too (it usually is,
    // but candidates from a stale query could in theory race a graph load).
    for (p, _) in candidates {
        if let Some(c) = &p.comm {
            map.entry(p.id.pid).or_insert_with(|| c.clone());
        }
    }
    Ok(map)
}

fn render_candidates(
    candidates: &[(ProcessNode, Vec<CandidateReason>)],
    parent_comm: &HashMap<u32, String>,
) -> String {
    candidates
        .iter()
        .map(|(p, reasons)| {
            let parent_label = p
                .ppid
                .and_then(|pp| parent_comm.get(&pp).cloned())
                .unwrap_or_else(|| "?".into());
            let reason_tags: Vec<String> = reasons.iter().map(|r| r.tag()).collect();
            format!(
                "pid={} comm={} exec={} ppid={} parent_comm={} uid={} reasons=[{}]",
                p.id.pid,
                p.comm.as_deref().unwrap_or("?"),
                p.exec_path.as_deref().unwrap_or("?"),
                p.ppid.map(|n| n.to_string()).unwrap_or_else(|| "?".into()),
                parent_label,
                p.uid.map(|n| n.to_string()).unwrap_or_else(|| "?".into()),
                reason_tags.join(","),
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use aw_core::Timestamp;
    use aw_graph::{Edge, Graph, ProcessId};
    use aw_llm::mock::MockClient;

    use super::*;
    use crate::AgentConfig;

    fn proc(pid: u32, comm: &str, exec: &str, ppid: Option<u32>, uid: u32) -> ProcessNode {
        ProcessNode {
            id: ProcessId {
                pid,
                start_unix_secs: 1000 + pid as u64,
            },
            comm: Some(comm.into()),
            name: Some(comm.into()),
            exec_path: Some(exec.into()),
            ppid,
            uid: Some(uid),
            birth: Timestamp {
                mono_ns: pid as u64,
                wall_anchor_ns: 0,
            },
            death: None,
        }
    }

    fn parent_of(parent: &ProcessNode, child: &ProcessNode) -> Edge {
        Edge::ParentOf {
            parent: parent.id.clone(),
            child: child.id.clone(),
        }
    }

    /// Scenario: trusted root daemon, a user shell, a root child of the shell
    /// (escalation), and a binary in /tmp owned by the user.
    fn suspicious_graph() -> Graph {
        let init = proc(1, "launchd", "/sbin/launchd", None, 0);
        let shell = proc(100, "zsh", "/bin/zsh", Some(1), 501);
        let escalated = proc(200, "rooted", "/tmp/rooted", Some(100), 0);
        let weird = proc(300, "weird", "/tmp/weird", Some(100), 501);
        let curl = proc(400, "curl", "/usr/bin/curl", Some(100), 501);
        Graph {
            processes: vec![
                init.clone(),
                shell.clone(),
                escalated.clone(),
                weird.clone(),
                curl.clone(),
            ],
            apps: vec![],
            sockets: vec![],
            files: vec![],
            domains: vec![],
            edges: vec![
                parent_of(&init, &shell),
                parent_of(&shell, &escalated),
                parent_of(&shell, &weird),
                parent_of(&shell, &curl),
            ],
        }
    }

    #[test]
    fn candidates_match_three_suspicion_signals() {
        let g = suspicious_graph();
        let prefixes: Vec<String> = DEFAULT_TRUSTED_PATH_PREFIXES
            .iter()
            .map(|s| s.to_string())
            .collect();
        let cs = candidates_from_graph(&g, &prefixes, 2); // threshold=2 → shell qualifies as prolific
        let by_pid: HashMap<u32, &Vec<CandidateReason>> =
            cs.iter().map(|(p, rs)| (p.id.pid, rs)).collect();

        // Escalation hit on both signals: root-under-user-parent AND /tmp path.
        let reasons_200 = by_pid
            .get(&200)
            .expect("escalated process missing from candidates");
        assert!(reasons_200.contains(&CandidateReason::RootUnderUserParent));
        assert!(reasons_200.contains(&CandidateReason::PathOutsideTrusted));

        // /tmp/weird hit on path only.
        let reasons_300 = by_pid
            .get(&300)
            .expect("weird process missing from candidates");
        assert_eq!(reasons_300, &&vec![CandidateReason::PathOutsideTrusted]);

        // Shell hit on prolific (3 children >= threshold 2).
        let reasons_100 = by_pid.get(&100).expect("shell missing from candidates");
        assert!(reasons_100.contains(&CandidateReason::ProlificParent(3)));

        // Curl in /usr/bin is fully trusted — not a candidate at all.
        assert!(
            !by_pid.contains_key(&400),
            "curl should not appear: {by_pid:?}"
        );
        // launchd in /sbin is trusted and not root-under-user — not a candidate.
        assert!(
            !by_pid.contains_key(&1),
            "launchd should not appear: {by_pid:?}"
        );
    }

    #[tokio::test]
    async fn detector_parses_json_response() {
        let json = r#"{"summary":"One thing looks odd.","findings":[{"pid":200,"comm":"rooted","exec_path":"/tmp/rooted","reason":"root under user shell","severity":"high"}]}"#;
        let mock = Arc::new(MockClient::new(vec![json]));
        let agent =
            ProcessAnomalyDetector::new(AgentCtx::new(mock.clone(), AgentConfig::default()));
        let report = agent.run(&suspicious_graph()).await.unwrap();
        assert_eq!(report.summary, "One thing looks odd.");
        let findings = report.details.get("findings").unwrap().as_array().unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].get("pid").and_then(|v| v.as_u64()), Some(200));
        assert_eq!(
            report.details.get("parse_error").and_then(|v| v.as_bool()),
            Some(false)
        );
    }

    #[tokio::test]
    async fn detector_falls_back_to_text_on_bad_json_and_flags_parse_error() {
        let mock = Arc::new(MockClient::new(vec!["not json at all"]));
        let agent =
            ProcessAnomalyDetector::new(AgentCtx::new(mock.clone(), AgentConfig::default()));
        let report = agent.run(&suspicious_graph()).await.unwrap();
        assert_eq!(report.summary, "not json at all");
        let findings = report.details.get("findings").unwrap().as_array().unwrap();
        assert!(findings.is_empty());
        assert_eq!(
            report.details.get("parse_error").and_then(|v| v.as_bool()),
            Some(true)
        );
    }

    #[tokio::test]
    async fn rendered_prompt_includes_reasons_and_parent_comm() {
        let mock = Arc::new(MockClient::new(vec![r#"{"summary":"ok","findings":[]}"#]));
        let agent =
            ProcessAnomalyDetector::new(AgentCtx::new(mock.clone(), AgentConfig::default()));
        let _ = agent.run(&suspicious_graph()).await.unwrap();
        let calls = mock.calls();
        assert_eq!(calls.len(), 1);
        let prompt = &calls[0].prompt;
        assert!(
            prompt.contains("parent_comm=zsh"),
            "prompt should resolve parent comm; got: {prompt}"
        );
        assert!(
            prompt.contains("root_under_user_parent"),
            "prompt should tag the escalation reason; got: {prompt}"
        );
        assert!(
            prompt.contains("path_outside_trusted"),
            "prompt should tag the trusted-path reason; got: {prompt}"
        );
    }

    #[tokio::test]
    async fn empty_candidates_uses_all_clear_prompt() {
        let mock = Arc::new(MockClient::new(vec![
            r#"{"summary":"all clear","findings":[]}"#,
        ]));
        let agent =
            ProcessAnomalyDetector::new(AgentCtx::new(mock.clone(), AgentConfig::default()));
        // Graph with only trusted, non-suspicious processes.
        let init = proc(1, "launchd", "/sbin/launchd", None, 0);
        let curl = proc(2, "curl", "/usr/bin/curl", Some(1), 501);
        let g = Graph {
            processes: vec![init.clone(), curl.clone()],
            apps: vec![],
            sockets: vec![],
            files: vec![],
            domains: vec![],
            edges: vec![parent_of(&init, &curl)],
        };
        let report = agent.run(&g).await.unwrap();
        assert_eq!(report.summary, "all clear");
        assert_eq!(
            report
                .details
                .get("candidates_total")
                .and_then(|v| v.as_u64()),
            Some(0)
        );
        assert!(calls_contains(&mock.calls()[0].prompt, "None matched"));
    }

    fn calls_contains(prompt: &str, needle: &str) -> bool {
        prompt.contains(needle)
    }

    #[test]
    fn suspicion_flags_render_all_three_heuristics_and_skip_sudo() {
        use aw_store::Store;
        let mut g = suspicious_graph();
        // A root child named sudo under the user shell — the expected boring
        // escalation case, which must NOT produce a flag.
        let sudo = proc(500, "sudo", "/usr/bin/sudo", Some(100), 0);
        g.edges.push(parent_of(&g.processes[1].clone(), &sudo));
        g.processes.push(sudo);

        let mut store = Store::open_in_memory().unwrap();
        store.merge_graph(&g).unwrap();

        let trusted: Vec<&str> = DEFAULT_TRUSTED_PATH_PREFIXES.to_vec();
        let flags = suspicion_flags_from_store(&store, 0, &trusted, 2).unwrap();
        let joined = flags.join("\n");
        assert!(
            joined.contains("root process 'rooted'"),
            "escalation flag missing: {joined}"
        );
        assert!(!joined.contains("'sudo'"), "sudo must be exempt: {joined}");
        assert!(
            joined.contains("untrusted location: /tmp/rooted"),
            "path flag missing: {joined}"
        );
        assert!(
            joined.contains("untrusted location: /tmp/weird"),
            "path flag missing: {joined}"
        );
        assert!(
            joined.contains("'zsh' (pid 100) spawned 4 child processes"),
            "prolific flag missing: {joined}"
        );
    }

    #[test]
    fn suspicion_flags_cap_noisy_categories() {
        use aw_store::Store;
        let mut g = Graph {
            processes: vec![],
            apps: vec![],
            sockets: vec![],
            files: vec![],
            domains: vec![],
            edges: vec![],
        };
        for i in 0..10u32 {
            g.processes.push(proc(
                1000 + i,
                &format!("tool{i}"),
                &format!("/tmp/tool{i}"),
                None,
                501,
            ));
        }
        let mut store = Store::open_in_memory().unwrap();
        store.merge_graph(&g).unwrap();

        let trusted: Vec<&str> = DEFAULT_TRUSTED_PATH_PREFIXES.to_vec();
        let flags = suspicion_flags_from_store(&store, 0, &trusted, 8).unwrap();
        // 6 rendered + 1 overflow marker.
        assert_eq!(flags.len(), 7, "{flags:?}");
        assert!(
            flags
                .last()
                .unwrap()
                .contains("+4 more processes from untrusted paths"),
            "{flags:?}"
        );
    }

    #[tokio::test]
    async fn run_from_store_pulls_candidates_via_sql() {
        use aw_store::Store;
        let mut store = Store::open_in_memory().unwrap();
        store.merge_graph(&suspicious_graph()).unwrap();

        let mock = Arc::new(MockClient::new(vec![r#"{"summary":"ok","findings":[]}"#]));
        // Drop the prolific threshold to 2 so the shell qualifies in this small fixture.
        let agent =
            ProcessAnomalyDetector::new(AgentCtx::new(mock.clone(), AgentConfig::default()))
                .with_prolific_threshold(2);
        let report = agent.run_from_store(&store).await.unwrap();

        let prompt = &mock.calls()[0].prompt;
        assert!(
            prompt.contains("pid=200"),
            "escalation candidate should appear: {prompt}"
        );
        assert!(
            prompt.contains("pid=300"),
            "weird path candidate should appear: {prompt}"
        );
        assert!(
            prompt.contains("root_under_user_parent"),
            "reason tag missing: {prompt}"
        );
        assert_eq!(
            report
                .details
                .get("processes_total")
                .and_then(|v| v.as_u64()),
            Some(5)
        );
    }
}
