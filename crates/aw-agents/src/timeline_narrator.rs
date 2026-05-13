//! Timeline narrator: feed it a window of Layer 2 events and it produces a
//! human-readable chronological summary.
//!
//! Strategy: build a compact text rendering of each event (one line each),
//! truncate to `max_input_items`, send to the model with a short system
//! prompt. Output is free-form prose — no JSON parsing required.

use anyhow::Result;
use aw_events::{Event, EventKind};
use aw_llm::{GenerateRequest, Options};

use crate::{AgentCtx, Report};

pub struct TimelineNarrator {
    ctx: AgentCtx,
}

impl TimelineNarrator {
    pub fn new(ctx: AgentCtx) -> Self { Self { ctx } }

    pub async fn run(&self, events: &[Event]) -> Result<Report> {
        let lines = render_events(events, self.ctx.config.max_input_items);
        let count_total = events.len();
        let count_used = lines.lines().count();
        let prompt = format!(
            "Below are {count_used} of {count_total} events (sampled evenly by time) \
             from a macOS behavioural capture. Produce a concise chronological narrative \
             (5–10 bullet points) describing what happened. Group repeated activity. \
             Use plain English; mention process names, foreign addresses, and key file \
             paths when relevant. Do not invent details.\n\n\
             EVENTS:\n{lines}\n\n\
             NARRATIVE:"
        );

        let system = Some(
            "You are an analyst summarising operating-system telemetry into a brief \
             chronological narrative for an engineer. Be concise, factual, and never \
             speculate beyond the data shown."
                .to_string(),
        );

        let req = GenerateRequest {
            model: self.ctx.config.model.clone(),
            prompt,
            system,
            options: Some(Options {
                temperature: Some(self.ctx.config.temperature),
                num_predict: Some(800),
                num_ctx: Some(8192),
            }),
            format: None, // free-form prose
            stream: false,
        };

        let resp = self.ctx.llm.generate(req).await?;
        let summary = resp.response.trim().to_string();
        Ok(Report {
            summary,
            details: serde_json::json!({
                "events_total": count_total,
                "events_sampled": count_used,
            }),
            model: resp.model,
        })
    }
}

/// Render each event as a single short line. Returns at most `max_items`
/// lines, sampled evenly across the timeline (preserving first and last).
fn render_events(events: &[Event], max_items: usize) -> String {
    let chosen = sample_evenly(events, max_items);
    chosen.iter().map(|e| render_one(e)).collect::<Vec<_>>().join("\n")
}

fn sample_evenly<T>(items: &[T], max: usize) -> Vec<&T> {
    if items.is_empty() { return Vec::new(); }
    if items.len() <= max { return items.iter().collect(); }
    // Pick `max` items evenly spaced. Always include first and last.
    let n = items.len();
    let mut out = Vec::with_capacity(max);
    for i in 0..max {
        let idx = i * (n - 1) / (max - 1).max(1);
        out.push(&items[idx]);
    }
    out
}

fn render_one(ev: &Event) -> String {
    // Compact one-line format: [t=<ms>] kind pid=<pid> <kind-specific summary>
    let t_ms = ev.timestamp.mono_ns / 1_000_000;
    let pid = ev.pid.map(|p| format!(" pid={p}")).unwrap_or_default();
    let detail = match ev.kind {
        EventKind::ProcessBirth => format!(
            " comm={} exec={}",
            ev.payload.get("comm").and_then(|v| v.as_str()).unwrap_or("?"),
            ev.payload.get("exec_path").and_then(|v| v.as_str()).unwrap_or("?"),
        ),
        EventKind::ProcessDeath => format!(
            " comm={}",
            ev.payload.get("comm").and_then(|v| v.as_str()).unwrap_or("?"),
        ),
        EventKind::AppFocus => format!(
            " to={}",
            ev.payload.get("to_name").and_then(|v| v.as_str()).unwrap_or("?"),
        ),
        EventKind::ConnectionOpened | EventKind::ConnectionClosed => format!(
            " {} -> {} ({})",
            ev.payload.get("local_addr").and_then(|v| v.as_str()).unwrap_or("?"),
            ev.payload.get("foreign_addr").and_then(|v| v.as_str()).unwrap_or("?"),
            ev.payload.get("process_name").and_then(|v| v.as_str()).unwrap_or("?"),
        ),
        EventKind::ConnectionCompleted => format!(
            " {} bytes_rx={} bytes_tx={} duration_ms={} ({})",
            ev.payload.get("foreign_addr").and_then(|v| v.as_str()).unwrap_or("?"),
            ev.payload.get("bytes_rx").and_then(|v| v.as_u64()).unwrap_or(0),
            ev.payload.get("bytes_tx").and_then(|v| v.as_u64()).unwrap_or(0),
            ev.payload.get("duration_ns").and_then(|v| v.as_u64()).unwrap_or(0) / 1_000_000,
            ev.payload.get("process_name").and_then(|v| v.as_str()).unwrap_or("?"),
        ),
        EventKind::FileChanged => format!(
            " path={} flags={:?}",
            ev.payload.get("path").and_then(|v| v.as_str()).unwrap_or("?"),
            ev.payload.get("flags").and_then(|v| v.as_array())
                .map(|arr| arr.iter().filter_map(|x| x.as_str()).collect::<Vec<_>>())
                .unwrap_or_default(),
        ),
        EventKind::DnsQuery => format!(
            " qname={} qtype={} client={}",
            ev.payload.get("qname").and_then(|v| v.as_str()).unwrap_or("?"),
            ev.payload.get("qtype").and_then(|v| v.as_str()).unwrap_or("?"),
            ev.payload.get("client_process_name").and_then(|v| v.as_str()).unwrap_or("?"),
        ),
    };
    format!("[t={t_ms}ms] {:?}{pid}{detail}", ev.kind)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use aw_core::Timestamp;
    use aw_llm::mock::MockClient;
    use serde_json::json;

    use super::*;
    use crate::AgentConfig;

    fn ev(kind: EventKind, mono_ms: u64, pid: Option<u32>, payload: serde_json::Value) -> Event {
        Event {
            timestamp: Timestamp { mono_ns: mono_ms * 1_000_000, wall_anchor_ns: 0 },
            kind,
            pid,
            payload,
        }
    }

    #[tokio::test]
    async fn narrator_calls_llm_with_rendered_lines() {
        let mock = Arc::new(MockClient::new(vec!["A summary."]));
        let agent = TimelineNarrator::new(AgentCtx::new(mock.clone(), AgentConfig::default()));

        let events = vec![
            ev(EventKind::ProcessBirth, 100, Some(42),
                json!({"comm": "curl", "exec_path": "/usr/bin/curl", "start_unix_secs": 1u64})),
            ev(EventKind::ConnectionCompleted, 200, Some(42),
                json!({"foreign_addr": "1.2.3.4.443", "bytes_rx": 1024u64, "bytes_tx": 256u64, "duration_ns": 500_000_000u64, "process_name": "curl"})),
        ];
        let report = agent.run(&events).await.unwrap();
        assert_eq!(report.summary, "A summary.");

        let calls = mock.calls();
        assert_eq!(calls.len(), 1);
        let prompt = &calls[0].prompt;
        assert!(prompt.contains("curl"), "prompt should mention curl: {prompt}");
        assert!(prompt.contains("1.2.3.4.443"), "prompt should mention foreign addr");
        assert!(prompt.contains("EVENTS:"));
    }

    #[test]
    fn sampling_picks_first_and_last_when_clamped() {
        let xs: Vec<u32> = (0..1000).collect();
        let s = sample_evenly(&xs, 5);
        assert_eq!(s.len(), 5);
        assert_eq!(*s[0], 0);
        assert_eq!(*s[4], 999);
    }

    #[test]
    fn sampling_passes_through_when_under_max() {
        let xs = vec![1, 2, 3];
        let s = sample_evenly(&xs, 10);
        assert_eq!(s.len(), 3);
    }

    #[test]
    fn rendering_handles_all_event_kinds_without_panicking() {
        for kind in [
            EventKind::ProcessBirth,
            EventKind::ProcessDeath,
            EventKind::AppFocus,
            EventKind::ConnectionOpened,
            EventKind::ConnectionClosed,
            EventKind::ConnectionCompleted,
            EventKind::FileChanged,
            EventKind::DnsQuery,
        ] {
            let e = ev(kind, 0, Some(1), json!({}));
            let _line = render_one(&e);
        }
    }
}
