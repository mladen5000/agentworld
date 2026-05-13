//! Network reviewer: feed it a stream of Layer 2 events and it summarizes
//! network conversations, flagging anything that looks notable.
//!
//! Strategy:
//! 1. Filter events to `ConnectionCompleted` (one row per real connection).
//! 2. Aggregate by `(foreign_addr_host, process_name)` so repeated TLS
//!    fan-out to the same host appears as one line.
//! 3. Render the aggregate, ask the LLM to flag anomalies.
//!
//! Output is structured JSON: a list of findings keyed by host+process.

use anyhow::Result;
use aw_events::{Event, EventKind};
use aw_llm::{Format, GenerateRequest, Options};
use serde::{Deserialize, Serialize};

use crate::{AgentCtx, Report};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkFinding {
    pub foreign_host: String,
    pub process_name: Option<String>,
    pub reason: String,
    pub severity: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LlmResponse {
    summary: String,
    findings: Vec<NetworkFinding>,
}

#[derive(Debug, Clone, Serialize)]
struct Aggregate {
    foreign_host: String,
    process_name: String,
    connections: u32,
    bytes_rx: u64,
    bytes_tx: u64,
    total_duration_ms: u64,
}

pub struct NetworkReviewer {
    ctx: AgentCtx,
}

impl NetworkReviewer {
    pub fn new(ctx: AgentCtx) -> Self { Self { ctx } }

    pub async fn run(&self, events: &[Event]) -> Result<Report> {
        let aggregates = aggregate(events);
        let cap = self.ctx.config.max_input_items.min(aggregates.len());
        let to_send = &aggregates[..cap];
        let count_unique = aggregates.len();

        let table = render_table(to_send);
        let prompt = format!(
            "Below is a summary of {used} of {total} (host, process) pairs that exchanged \
             traffic during a macOS capture. Identify any that look notable: unusual \
             destinations, processes that should not normally make network connections, \
             unexpected port choices, or suspiciously high volume. Do not flag well-known \
             services unless context suggests misuse. Return ONLY valid JSON of this shape:\n\
             {{\n  \"summary\": \"<one or two sentences\">\",\n  \
             \"findings\": [\n    {{ \"foreign_host\": \"<string>\", \
             \"process_name\": \"<string or null>\", \"reason\": \"<concise English>\", \
             \"severity\": \"low\"|\"medium\"|\"high\" }}\n  ]\n}}\n\n\
             CONVERSATIONS:\n{table}",
            used = to_send.len(),
            total = count_unique,
        );

        let system = Some(
            "You are a network security analyst summarising outbound and inbound \
             connections. Be conservative: flag only what is genuinely unusual. \
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
                tracing::warn!("network_reviewer: JSON parse failed ({e}); falling back to raw text");
                (raw.to_string(), Vec::new())
            }
        };

        Ok(Report {
            summary,
            details: serde_json::json!({
                "conversations_unique": count_unique,
                "conversations_sampled": to_send.len(),
                "findings": findings,
            }),
            model: resp.model,
        })
    }
}

fn aggregate(events: &[Event]) -> Vec<Aggregate> {
    use std::collections::HashMap;
    // Key: (foreign_host, process_name).
    let mut map: HashMap<(String, String), Aggregate> = HashMap::new();
    for ev in events.iter().filter(|e| e.kind == EventKind::ConnectionCompleted) {
        let foreign_addr = ev.payload.get("foreign_addr").and_then(|v| v.as_str()).unwrap_or("?");
        let foreign_host = foreign_addr.rsplit_once('.').map(|(host, _port)| host.to_string()).unwrap_or_else(|| foreign_addr.to_string());
        let proc_name = ev.payload.get("process_name").and_then(|v| v.as_str()).unwrap_or("?").to_string();
        let bytes_rx = ev.payload.get("bytes_rx").and_then(|v| v.as_u64()).unwrap_or(0);
        let bytes_tx = ev.payload.get("bytes_tx").and_then(|v| v.as_u64()).unwrap_or(0);
        let duration_ms = ev.payload.get("duration_ns").and_then(|v| v.as_u64()).unwrap_or(0) / 1_000_000;

        let entry = map.entry((foreign_host.clone(), proc_name.clone())).or_insert(Aggregate {
            foreign_host: foreign_host.clone(),
            process_name: proc_name,
            connections: 0,
            bytes_rx: 0,
            bytes_tx: 0,
            total_duration_ms: 0,
        });
        entry.connections += 1;
        entry.bytes_rx += bytes_rx;
        entry.bytes_tx += bytes_tx;
        entry.total_duration_ms += duration_ms;
    }
    // Sort by bytes (rx+tx) descending so we send the biggest conversations first.
    let mut out: Vec<Aggregate> = map.into_values().collect();
    // Descending by total bytes; negate by computing the sort key on `Reverse`.
    out.sort_by_key(|a| std::cmp::Reverse(a.bytes_rx + a.bytes_tx));
    out
}

fn render_table(rows: &[Aggregate]) -> String {
    rows.iter().map(|r| format!(
        "host={} process={} conns={} bytes_rx={} bytes_tx={} duration_ms={}",
        r.foreign_host, r.process_name, r.connections, r.bytes_rx, r.bytes_tx, r.total_duration_ms,
    )).collect::<Vec<_>>().join("\n")
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use aw_core::Timestamp;
    use aw_llm::mock::MockClient;
    use serde_json::json;

    use super::*;
    use crate::AgentConfig;

    fn completed(foreign: &str, process: &str, rx: u64, tx: u64, dur_ms: u64) -> Event {
        Event {
            timestamp: Timestamp { mono_ns: 0, wall_anchor_ns: 0 },
            kind: EventKind::ConnectionCompleted,
            pid: Some(1),
            payload: json!({
                "foreign_addr": foreign,
                "process_name": process,
                "bytes_rx": rx,
                "bytes_tx": tx,
                "duration_ns": dur_ms * 1_000_000,
            }),
        }
    }

    #[test]
    fn aggregate_collapses_same_host_and_process() {
        let evs = vec![
            completed("1.2.3.4.443", "curl", 100, 50, 10),
            completed("1.2.3.4.443", "curl", 200, 50, 20),
            completed("9.9.9.9.80", "curl", 5, 5, 1),
        ];
        let aggs = aggregate(&evs);
        // 1.2.3.4 collapses into one row; 9.9.9.9 is its own row.
        let s = aggs.iter().find(|a| a.foreign_host == "1.2.3.4").unwrap();
        assert_eq!(s.connections, 2);
        assert_eq!(s.bytes_rx, 300);
        assert_eq!(s.bytes_tx, 100);
        // First row by sort order is the bigger one.
        assert_eq!(aggs[0].foreign_host, "1.2.3.4");
    }

    #[tokio::test]
    async fn reviewer_parses_json_response() {
        let json = r#"{"summary":"all clear","findings":[]}"#;
        let mock = Arc::new(MockClient::new(vec![json]));
        let agent = NetworkReviewer::new(AgentCtx::new(mock.clone(), AgentConfig::default()));
        let evs = vec![completed("1.2.3.4.443", "curl", 100, 50, 10)];
        let report = agent.run(&evs).await.unwrap();
        assert_eq!(report.summary, "all clear");
        assert_eq!(report.details.get("conversations_unique").and_then(|v| v.as_u64()), Some(1));
    }

    #[tokio::test]
    async fn reviewer_ignores_non_completed_events() {
        let mock = Arc::new(MockClient::new(vec![r#"{"summary":"x","findings":[]}"#]));
        let agent = NetworkReviewer::new(AgentCtx::new(mock.clone(), AgentConfig::default()));
        let evs = vec![Event {
            timestamp: Timestamp { mono_ns: 0, wall_anchor_ns: 0 },
            kind: EventKind::DnsQuery, // not Completed
            pid: None,
            payload: json!({}),
        }];
        let report = agent.run(&evs).await.unwrap();
        assert_eq!(report.details.get("conversations_unique").and_then(|v| v.as_u64()), Some(0));
    }
}
