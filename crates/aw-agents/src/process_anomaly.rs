//! Process anomaly detector.
//!
//! Takes a Layer 3 `Graph` (or just its process nodes), summarizes the
//! process tree, and asks the LLM to flag anything that looks unusual:
//! - non-standard parent processes (e.g. a shell under a renderer)
//! - oddly-named binaries (random strings, hex names)
//! - processes running as root that usually shouldn't
//! - children of processes that don't normally spawn children
//!
//! Output is parsed structured JSON: a list of flagged processes with a
//! short reason each. We fall back to free-form text if JSON parsing fails.

use anyhow::Result;
use aw_graph::{Graph, ProcessNode};
use aw_llm::{Format, GenerateRequest, Options};
use serde::{Deserialize, Serialize};

use crate::{AgentCtx, Report};

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

pub struct ProcessAnomalyDetector {
    ctx: AgentCtx,
}

impl ProcessAnomalyDetector {
    pub fn new(ctx: AgentCtx) -> Self { Self { ctx } }

    pub async fn run(&self, graph: &Graph) -> Result<Report> {
        let processes = sample_processes(&graph.processes, self.ctx.config.max_input_items);
        let count_total = graph.processes.len();
        let count_used = processes.len();
        let process_block = render_processes(&processes, graph);

        let prompt = format!(
            "Below are {count_used} of {count_total} process nodes observed during a macOS \
             capture. Identify any that look suspicious. Consider: unusual parent/child \
             pairings, hex/random-looking names, binaries outside standard paths, \
             root-owned processes that shouldn't be, or odd combinations of \
             attributes. Do not flag normal macOS daemons unless they're clearly out \
             of place. Return ONLY valid JSON matching this exact shape:\n\
             {{\n  \"summary\": \"<one or two sentences overall>\",\n  \
             \"findings\": [\n    {{ \"pid\": <u32>, \"comm\": \"<string or null>\", \
             \"exec_path\": \"<string or null>\", \"reason\": \"<concise English>\", \
             \"severity\": \"low\"|\"medium\"|\"high\" }}\n  ]\n}}\n\n\
             PROCESSES:\n{process_block}"
        );

        let system = Some(
            "You are a macOS security analyst reviewing a list of running processes. \
             Be precise and skeptical: only flag things that are genuinely unusual. \
             Output strictly valid JSON; no prose outside the JSON object."
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

        let (summary, findings) = match serde_json::from_str::<LlmResponse>(raw) {
            Ok(parsed) => (parsed.summary, parsed.findings),
            Err(e) => {
                tracing::warn!("process_anomaly: JSON parse failed ({e}); falling back to raw text");
                (raw.to_string(), Vec::new())
            }
        };

        Ok(Report {
            summary,
            details: serde_json::json!({
                "processes_total": count_total,
                "processes_sampled": count_used,
                "findings": findings,
            }),
            model: resp.model,
        })
    }
}

fn sample_processes(processes: &[ProcessNode], max: usize) -> Vec<&ProcessNode> {
    if processes.len() <= max { return processes.iter().collect(); }
    let n = processes.len();
    (0..max).map(|i| &processes[i * (n - 1) / (max - 1).max(1)]).collect()
}

fn render_processes(processes: &[&ProcessNode], graph: &Graph) -> String {
    // For each process, render: pid, comm, exec_path, ppid, parent comm, uid.
    let by_pid: std::collections::HashMap<u32, &ProcessNode> =
        graph.processes.iter().map(|p| (p.id.pid, p)).collect();
    processes.iter().map(|p| {
        let parent_comm = p.ppid
            .and_then(|pp| by_pid.get(&pp))
            .and_then(|pn| pn.comm.as_deref())
            .unwrap_or("?");
        format!(
            "pid={} comm={} exec={} ppid={} parent_comm={} uid={}",
            p.id.pid,
            p.comm.as_deref().unwrap_or("?"),
            p.exec_path.as_deref().unwrap_or("?"),
            p.ppid.map(|n| n.to_string()).unwrap_or_else(|| "?".into()),
            parent_comm,
            p.uid.map(|n| n.to_string()).unwrap_or_else(|| "?".into()),
        )
    }).collect::<Vec<_>>().join("\n")
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use aw_core::Timestamp;
    use aw_graph::{Edge, Graph, ProcessId};
    use aw_llm::mock::MockClient;

    use super::*;
    use crate::AgentConfig;

    fn proc_node(pid: u32, comm: &str, ppid: Option<u32>, uid: u32) -> ProcessNode {
        ProcessNode {
            id: ProcessId { pid, start_unix_secs: 1000 },
            comm: Some(comm.into()),
            name: Some(comm.into()),
            exec_path: Some(format!("/bin/{comm}")),
            ppid,
            uid: Some(uid),
            birth: Timestamp { mono_ns: 0, wall_anchor_ns: 0 },
            death: None,
        }
    }

    fn graph_with(processes: Vec<ProcessNode>) -> Graph {
        Graph {
            processes,
            apps: vec![],
            sockets: vec![],
            files: vec![],
            edges: Vec::<Edge>::new(),
        }
    }

    #[tokio::test]
    async fn detector_parses_json_response() {
        let json = r#"{"summary":"One thing looks odd.","findings":[{"pid":42,"comm":"weird","exec_path":"/tmp/weird","reason":"binary in /tmp","severity":"high"}]}"#;
        let mock = Arc::new(MockClient::new(vec![json]));
        let agent = ProcessAnomalyDetector::new(AgentCtx::new(mock.clone(), AgentConfig::default()));
        let g = graph_with(vec![
            proc_node(1, "launchd", None, 0),
            proc_node(42, "weird", Some(1), 501),
        ]);
        let report = agent.run(&g).await.unwrap();
        assert_eq!(report.summary, "One thing looks odd.");
        let findings = report.details.get("findings").unwrap().as_array().unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].get("pid").and_then(|v| v.as_u64()), Some(42));
        assert_eq!(findings[0].get("severity").and_then(|v| v.as_str()), Some("high"));
    }

    #[tokio::test]
    async fn detector_falls_back_to_text_on_bad_json() {
        let mock = Arc::new(MockClient::new(vec!["not json at all"]));
        let agent = ProcessAnomalyDetector::new(AgentCtx::new(mock.clone(), AgentConfig::default()));
        let g = graph_with(vec![proc_node(1, "init", None, 0)]);
        let report = agent.run(&g).await.unwrap();
        assert_eq!(report.summary, "not json at all");
        let findings = report.details.get("findings").unwrap().as_array().unwrap();
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn rendered_prompt_includes_parent_comm() {
        let mock = Arc::new(MockClient::new(vec![r#"{"summary":"ok","findings":[]}"#]));
        let agent = ProcessAnomalyDetector::new(AgentCtx::new(mock.clone(), AgentConfig::default()));
        let g = graph_with(vec![
            proc_node(1, "launchd", None, 0),
            proc_node(100, "shell", Some(1), 501),
            proc_node(200, "child", Some(100), 501),
        ]);
        let _ = agent.run(&g).await.unwrap();
        let calls = mock.calls();
        assert_eq!(calls.len(), 1);
        let prompt = &calls[0].prompt;
        assert!(prompt.contains("parent_comm=shell"), "prompt should resolve parent comm; got: {prompt}");
    }
}
