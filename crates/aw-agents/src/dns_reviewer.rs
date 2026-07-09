//! DNS reviewer: feed it a stream of Layer 2 events and it summarizes DNS
//! activity, flagging names that look notable.
//!
//! Strategy (mirrors `network_reviewer`):
//! 1. Filter events to `DnsQuery`.
//! 2. Aggregate by `(domain, client process)` so repeated lookups of the same
//!    name appear as one line with a count.
//! 3. Render the aggregate, ask the LLM to flag anomalies (DGA-looking
//!    names, raw-IP/punycode lookups, unusual TLDs, tunneling-scale volume).
//!
//! Privacy-masked queries (no plaintext qname) are aggregated under their
//! `hash:<name_hash>` id and marked masked; the LLM is told not to guess
//! what they are.

use anyhow::Result;
#[cfg(test)]
use aw_events::SCHEMA_VERSION;
use aw_events::{Event, EventKind};
use aw_llm::{Format, GenerateRequest, Options};
use serde::{Deserialize, Serialize};

use crate::{AgentCtx, Report};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsFinding {
    pub domain: String,
    pub client_process: Option<String>,
    pub reason: String,
    pub severity: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LlmResponse {
    summary: String,
    findings: Vec<DnsFinding>,
}

#[derive(Debug, Clone, Serialize)]
struct Aggregate {
    domain: String,
    client_process: String,
    queries: u32,
    qtypes: Vec<String>,
    masked: bool,
}

pub struct DnsReviewer {
    ctx: AgentCtx,
}

impl DnsReviewer {
    pub fn new(ctx: AgentCtx) -> Self {
        Self { ctx }
    }

    pub async fn run(&self, events: &[Event]) -> Result<Report> {
        let aggregates = aggregate(events);
        let cap = self.ctx.config.max_input_items.min(aggregates.len());
        let to_send = &aggregates[..cap];
        let count_unique = aggregates.len();

        let table = render_table(to_send);
        let prompt = format!(
            "Below is a summary of {used} of {total} (domain, client process) pairs \
             observed as DNS queries during a macOS capture. Identify any that look \
             notable: algorithmically-generated names, raw IPs or punycode, unusual \
             TLDs, processes that should not normally resolve names, or query volume \
             high enough to suggest DNS tunneling. Lines marked masked=true are \
             privacy-redacted by macOS — do not guess what they are; only flag them \
             if their volume alone is anomalous. Do not flag well-known services. \
             Return ONLY valid JSON of this shape:\n\
             {{\n  \"summary\": \"<one or two sentences>\",\n  \
             \"findings\": [\n    {{ \"domain\": \"<string>\", \
             \"client_process\": \"<string or null>\", \"reason\": \"<concise English>\", \
             \"severity\": \"low\"|\"medium\"|\"high\" }}\n  ]\n}}\n\n\
             QUERIES:\n{table}",
            used = to_send.len(),
            total = count_unique,
        );

        let system = Some(
            "You are a DNS security analyst reviewing name-resolution activity. \
             Be conservative: flag only what is genuinely unusual. Output strictly \
             valid JSON; no prose outside the JSON object."
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
                tracing::warn!("dns_reviewer: JSON parse failed ({e}); falling back to raw text");
                (raw.to_string(), Vec::new())
            }
        };

        Ok(Report {
            summary,
            details: serde_json::json!({
                "domains_unique": count_unique,
                "domains_sampled": to_send.len(),
                "findings": findings,
            }),
            model: resp.model,
        })
    }
}

/// Domain id for an event payload: qname with one trailing dot stripped, or
/// `hash:<name_hash>` for masked queries. Mirrors `aw_graph`'s domain-node id
/// so agent findings can be joined back to graph/store entities.
fn domain_id(p: &serde_json::Value) -> Option<String> {
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

/// The querying process's name: the enriched `process.comm` when the
/// cross-source `ProcessTable` matched the pid, else the raw
/// `client_process_name` mDNSResponder reported.
fn client_name(p: &serde_json::Value) -> String {
    p.get("process")
        .and_then(|v| v.get("comm"))
        .and_then(|v| v.as_str())
        .or_else(|| p.get("client_process_name").and_then(|v| v.as_str()))
        .unwrap_or("?")
        .to_string()
}

fn aggregate(events: &[Event]) -> Vec<Aggregate> {
    use std::collections::HashMap;
    let mut map: HashMap<(String, String), Aggregate> = HashMap::new();
    for ev in events.iter().filter(|e| e.kind == EventKind::DnsQuery) {
        let p = &ev.payload;
        let Some(domain) = domain_id(p) else { continue };
        let client = client_name(p);
        let masked = p.get("masked").and_then(|v| v.as_bool()).unwrap_or(false);
        let qtype = p.get("qtype").and_then(|v| v.as_str()).map(String::from);

        let entry = map
            .entry((domain.clone(), client.clone()))
            .or_insert(Aggregate {
                domain,
                client_process: client,
                queries: 0,
                qtypes: Vec::new(),
                masked,
            });
        entry.queries += 1;
        entry.masked = entry.masked && masked;
        if let Some(q) = qtype {
            if !entry.qtypes.contains(&q) {
                entry.qtypes.push(q);
            }
        }
    }
    // Busiest names first so a capped send keeps the interesting rows.
    let mut out: Vec<Aggregate> = map.into_values().collect();
    out.sort_by_key(|a| std::cmp::Reverse(a.queries));
    out
}

fn render_table(rows: &[Aggregate]) -> String {
    rows.iter()
        .map(|r| {
            format!(
                "domain={} process={} queries={} qtypes={} masked={}",
                r.domain,
                r.client_process,
                r.queries,
                if r.qtypes.is_empty() {
                    "?".to_string()
                } else {
                    r.qtypes.join(",")
                },
                r.masked,
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use aw_core::Timestamp;
    use aw_llm::mock::MockClient;
    use serde_json::json;

    use super::*;
    use crate::AgentConfig;

    fn query(qname: Option<&str>, qtype: &str, client: &str, masked: bool) -> Event {
        Event {
            schema_version: SCHEMA_VERSION,
            timestamp: Timestamp {
                mono_ns: 0,
                wall_anchor_ns: 0,
            },
            kind: EventKind::DnsQuery,
            pid: Some(42),
            payload: json!({
                "qname": qname,
                "qtype": qtype,
                "name_hash": "h1",
                "masked": masked,
                "client_process_name": client,
            }),
        }
    }

    #[test]
    fn aggregate_collapses_same_domain_and_client() {
        let evs = vec![
            query(Some("example.com."), "A", "curl", false),
            query(Some("example.com."), "AAAA", "curl", false),
            query(Some("example.com."), "A", "node", false),
        ];
        let aggs = aggregate(&evs);
        assert_eq!(aggs.len(), 2, "curl and node stay separate: {aggs:?}");
        let curl = aggs.iter().find(|a| a.client_process == "curl").unwrap();
        assert_eq!(curl.domain, "example.com");
        assert_eq!(curl.queries, 2);
        assert!(curl.qtypes.contains(&"A".to_string()));
        assert!(curl.qtypes.contains(&"AAAA".to_string()));
    }

    #[test]
    fn aggregate_uses_hash_for_masked_queries() {
        let evs = vec![query(Some("<mask.hash: 'x'>"), "HTTPS", "Safari", true)];
        let aggs = aggregate(&evs);
        assert_eq!(aggs.len(), 1);
        assert_eq!(aggs[0].domain, "hash:h1");
        assert!(aggs[0].masked);
    }

    #[test]
    fn aggregate_prefers_enriched_process_comm() {
        let mut ev = query(Some("example.com."), "A", "mDNSResponder-relay", false);
        ev.payload
            .as_object_mut()
            .unwrap()
            .insert("process".into(), json!({ "pid": 42, "comm": "curl" }));
        let aggs = aggregate(&[ev]);
        assert_eq!(aggs[0].client_process, "curl");
    }

    #[test]
    fn aggregate_sorts_busiest_first_and_ignores_other_kinds() {
        let mut evs = vec![
            query(Some("quiet.example."), "A", "curl", false),
            query(Some("busy.example."), "A", "curl", false),
            query(Some("busy.example."), "A", "curl", false),
        ];
        evs.push(Event {
            schema_version: SCHEMA_VERSION,
            timestamp: Timestamp {
                mono_ns: 0,
                wall_anchor_ns: 0,
            },
            kind: EventKind::FileChanged,
            pid: None,
            payload: json!({}),
        });
        let aggs = aggregate(&evs);
        assert_eq!(aggs.len(), 2);
        assert_eq!(aggs[0].domain, "busy.example");
        assert_eq!(aggs[0].queries, 2);
    }

    #[tokio::test]
    async fn reviewer_parses_json_response() {
        let json = r#"{"summary":"nothing notable","findings":[]}"#;
        let mock = Arc::new(MockClient::new(vec![json]));
        let agent = DnsReviewer::new(AgentCtx::new(mock.clone(), AgentConfig::default()));
        let evs = vec![query(Some("example.com."), "A", "curl", false)];
        let report = agent.run(&evs).await.unwrap();
        assert_eq!(report.summary, "nothing notable");
        assert_eq!(
            report
                .details
                .get("domains_unique")
                .and_then(|v| v.as_u64()),
            Some(1)
        );
    }

    #[tokio::test]
    async fn reviewer_survives_malformed_llm_output() {
        let mock = Arc::new(MockClient::new(vec!["not json at all"]));
        let agent = DnsReviewer::new(AgentCtx::new(mock.clone(), AgentConfig::default()));
        let evs = vec![query(Some("example.com."), "A", "curl", false)];
        let report = agent.run(&evs).await.unwrap();
        assert_eq!(report.summary, "not json at all");
        let findings = report
            .details
            .get("findings")
            .and_then(|v| v.as_array())
            .unwrap();
        assert!(findings.is_empty());
    }
}
