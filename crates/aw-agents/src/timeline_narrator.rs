//! Timeline narrator: turns a window of Layer 2 events into a short prose
//! summary of what the user was doing.
//!
//! ## Why aggregate, not stream
//!
//! Earlier versions of this agent sent the LLM up to N events sampled evenly
//! across the timeline. That works for tiny captures and fails badly for
//! anything longer — a 1h capture trivially contains 50k+ events, and
//! sampling either drops most signal or overflows the model's context.
//!
//! Instead, this agent extracts a small set of high-level **facts** from the
//! event stream (app-focus segments, dominant processes, network endpoints,
//! file activity, DNS clients), packs them into a `CaptureSummary`, and asks
//! the LLM to narrate that. Same triage pattern as `process_anomaly`.
//!
//! The summary is bounded by the *number of distinct things*, not the
//! capture size — so the LLM always sees a small, dense set of facts no
//! matter how long the capture ran.

use std::collections::{BTreeMap, HashMap};

use anyhow::Result;
use aw_events::{Event, EventKind};
#[cfg(test)]
use aw_events::SCHEMA_VERSION;
use aw_llm::{GenerateRequest, Options};
use serde::{Deserialize, Serialize};

use crate::{AgentCtx, Report};

const TOP_N_PROCESSES: usize = 8;
const TOP_N_ENDPOINTS: usize = 8;
const TOP_N_DIRECTORIES: usize = 6;
const TOP_N_DNS_CLIENTS: usize = 6;

/// Pre-aggregated facts the LLM narrates. Designed to fit in a tiny prompt
/// regardless of how much raw telemetry it summarises.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaptureSummary {
    /// Wall-clock span the events cover (seconds). Derived from the first
    /// and last event timestamps; 0 if zero or one events.
    pub duration_secs: u64,
    pub events_total: usize,

    /// App-focus segments in order, with duration. The narrator can say
    /// "VS Code for ~12m, then Chrome for ~3m".
    pub focus_segments: Vec<FocusSegment>,

    /// Top processes by spawn count. Filters out high-frequency system
    /// daemons (mdworker_shared, launchd helpers) by default so the LLM
    /// doesn't lead with noise.
    pub top_processes: Vec<ProcessFact>,

    /// Top remote endpoints by bytes transferred (rx + tx).
    pub top_endpoints: Vec<EndpointFact>,

    /// Top directories by file_changed count. Path is truncated to the
    /// first ~4 components so the LLM sees `~/Projects/agentworld/...`
    /// rather than dozens of leaf paths.
    pub top_directories: Vec<DirectoryFact>,

    /// Top DNS-issuing processes (by unique name_hash count).
    pub top_dns_clients: Vec<DnsClientFact>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FocusSegment {
    pub app_name: String,
    pub bundle_id: Option<String>,
    pub started_secs: u64,
    pub duration_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessFact {
    pub comm: String,
    pub spawns: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointFact {
    pub foreign_addr: String,
    pub process_name: String,
    pub bytes_total: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirectoryFact {
    pub directory: String,
    pub file_changes: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsClientFact {
    pub process_name: String,
    pub unique_names: u32,
    pub total_queries: u32,
}

pub struct TimelineNarrator {
    ctx: AgentCtx,
    /// When true, the prompt frames the window as a *live, in-progress*
    /// observation (present perfect: "you've been on X"), suitable for a
    /// daemon that emits a paragraph per tick. When false (default), past
    /// tense fits a one-shot capture.
    live: bool,
}

impl TimelineNarrator {
    pub fn new(ctx: AgentCtx) -> Self { Self { ctx, live: false } }

    /// Switch the prompt to present-tense framing — what you'd want from a
    /// daemon emitting a paragraph every minute.
    pub fn live(mut self) -> Self { self.live = true; self }

    /// Live / one-shot path: aggregate raw events, then narrate.
    pub async fn run(&self, events: &[Event]) -> Result<Report> {
        let summary = summarize_capture(events);
        self.run_summary(summary).await
    }

    /// Historical path: take a `Graph` (typically loaded from `aw-store` for
    /// some past window) and narrate the same way. Lossy compared to raw
    /// events — DNS and file_changed counts come from per-node `touch_count`
    /// rather than per-event payloads — but for "what was I doing yesterday"
    /// the headline facts (apps, processes, network bytes, directories)
    /// survive cleanly.
    pub async fn run_from_graph(&self, graph: &aw_graph::Graph) -> Result<Report> {
        let summary = summarize_graph(graph);
        self.run_summary(summary).await
    }

    /// Shared LLM call used by both `run` and `run_from_graph`. Public so
    /// callers that have already aggregated (e.g. tests, or a future agent
    /// that wants to merge multiple summaries) can hand a `CaptureSummary`
    /// in directly without re-deriving it.
    pub async fn run_summary(&self, summary: CaptureSummary) -> Result<Report> {
        let prompt = render_prompt(&summary, self.live);

        let system_text = if self.live {
            "You are narrating live macOS activity in the present, for the user who \
             is at the keyboard right now. Be concrete and human — start with what \
             they ARE doing (dominant app + apparent purpose), then mention notable \
             network destinations and any other striking signal from the last few \
             minutes. Use present-perfect tense (\"you've been …\") when describing \
             how long activity has lasted. Keep it to 2–4 sentences. Do NOT \
             speculate beyond the data. Do NOT output bullet points or JSON — plain \
             prose only."
        } else {
            "You are summarising a short macOS behavioural capture in plain English \
             for the user who was at the keyboard. Be concrete and human — start with \
             the dominant app(s) and what they appear to have been used for, then \
             mention notable network destinations and any other striking signal. \
             Keep it to 3–6 sentences. Speak in second person (\"you were …\"). Do \
             NOT speculate beyond the data. Do NOT output bullet points or JSON — \
             plain prose only."
        };
        let system = Some(system_text.to_string());

        let req = GenerateRequest {
            model: self.ctx.config.model.clone(),
            prompt,
            system,
            options: Some(Options {
                temperature: Some(self.ctx.config.temperature),
                num_predict: Some(400),
                num_ctx: Some(8192),
            }),
            format: None, // prose, not JSON
            stream: false,
        };

        let resp = self.ctx.llm.generate(req).await?;
        let summary_text = resp.response.trim().to_string();
        Ok(Report {
            summary: summary_text,
            details: serde_json::to_value(&summary)?,
            model: resp.model,
        })
    }
}

/// Extract high-level facts from a slice of Layer 2 events. Pure function —
/// no I/O, easy to test.
pub fn summarize_capture(events: &[Event]) -> CaptureSummary {
    if events.is_empty() {
        return CaptureSummary {
            duration_secs: 0,
            events_total: 0,
            focus_segments: Vec::new(),
            top_processes: Vec::new(),
            top_endpoints: Vec::new(),
            top_directories: Vec::new(),
            top_dns_clients: Vec::new(),
        };
    }

    // Total span — use min/max of mono_ns, robust to out-of-order events.
    let min_ns = events.iter().map(|e| e.timestamp.mono_ns).min().unwrap_or(0);
    let max_ns = events.iter().map(|e| e.timestamp.mono_ns).max().unwrap_or(0);
    let duration_secs = max_ns.saturating_sub(min_ns) / 1_000_000_000;

    CaptureSummary {
        duration_secs,
        events_total: events.len(),
        focus_segments: build_focus_segments(events, max_ns),
        top_processes: top_processes(events),
        top_endpoints: top_endpoints(events),
        top_directories: top_directories(events),
        top_dns_clients: top_dns_clients(events),
    }
}

/// Build the same `CaptureSummary` shape as `summarize_capture`, but from
/// a Layer 3 `Graph` (typically loaded from `aw-store` for some past
/// window) instead of raw events.
///
/// Notes vs. the event-driven path:
/// - DNS isn't materialized as graph nodes yet, so `top_dns_clients` is
///   always empty here. The narrator gracefully omits the section.
/// - Network bytes come from the **last observed** rx/tx counters on each
///   socket node (see [`aw_store::EndpointSummary`]'s caveat) — they
///   don't deduplicate across long-lived sockets that span captures.
/// - `events_total` is repurposed as a "things observed" tally summed
///   across node kinds, so the prompt's "{n} events" line still reads
///   sensibly.
pub fn summarize_graph(g: &aw_graph::Graph) -> CaptureSummary {
    let things = g.processes.len() + g.apps.len() + g.sockets.len() + g.files.len();
    if things == 0 {
        return CaptureSummary {
            duration_secs: 0,
            events_total: 0,
            focus_segments: Vec::new(),
            top_processes: Vec::new(),
            top_endpoints: Vec::new(),
            top_directories: Vec::new(),
            top_dns_clients: Vec::new(),
        };
    }

    // Span: min `birth` / max `death|birth` across processes, plus app
    // interval bounds and socket open/close. Timestamps are stored as
    // wall-clock unix-ns inside `mono_ns` after a store round-trip
    // (see `aw_store::process_from_row`), so subtraction yields seconds.
    let mut min_ns = u64::MAX;
    let mut max_ns = 0u64;
    let mut bump = |t: u64| {
        if t == 0 { return; }
        if t < min_ns { min_ns = t; }
        if t > max_ns { max_ns = t; }
    };
    for p in &g.processes {
        bump(p.birth.mono_ns);
        if let Some(d) = p.death { bump(d.mono_ns); }
    }
    for a in &g.apps {
        for iv in &a.intervals {
            bump(iv.from.mono_ns);
            if let Some(t) = iv.to { bump(t.mono_ns); }
        }
    }
    for s in &g.sockets {
        bump(s.opened.mono_ns);
        if let Some(c) = s.closed { bump(c.mono_ns); }
    }
    for f in &g.files {
        bump(f.first_seen.mono_ns);
        bump(f.last_seen.mono_ns);
    }
    let duration_secs = if max_ns >= min_ns && min_ns != u64::MAX {
        (max_ns - min_ns) / 1_000_000_000
    } else { 0 };

    CaptureSummary {
        duration_secs,
        events_total: things,
        focus_segments: focus_segments_from_apps(&g.apps),
        top_processes: top_processes_from_graph(&g.processes),
        top_endpoints: top_endpoints_from_graph(&g.sockets),
        top_directories: top_directories_from_graph(&g.files),
        top_dns_clients: Vec::new(),
    }
}

fn focus_segments_from_apps(apps: &[aw_graph::AppNode]) -> Vec<FocusSegment> {
    // Flatten every (app, interval) pair into a FocusSegment, then sort by
    // start time so the narrative reads chronologically. An app that was
    // frontmost three times shows up as three segments — exactly what the
    // event path produces.
    let mut out: Vec<FocusSegment> = apps.iter()
        .flat_map(|a| a.intervals.iter().map(move |iv| FocusSegment {
            app_name: a.name.clone().unwrap_or_else(|| a.id.clone()),
            bundle_id: Some(a.id.clone()),
            started_secs: iv.from.mono_ns / 1_000_000_000,
            duration_secs: iv.to
                .map(|t| t.mono_ns.saturating_sub(iv.from.mono_ns) / 1_000_000_000)
                .unwrap_or(0),
        }))
        .collect();
    out.sort_by_key(|s| s.started_secs);
    out
}

fn top_processes_from_graph(processes: &[aw_graph::ProcessNode]) -> Vec<ProcessFact> {
    let mut counts: HashMap<String, u32> = HashMap::new();
    for p in processes {
        let Some(comm) = p.comm.as_deref() else { continue; };
        if NOISY_COMMS.contains(&comm) { continue; }
        *counts.entry(comm.to_string()).or_insert(0) += 1;
    }
    let mut out: Vec<ProcessFact> = counts.into_iter()
        .map(|(comm, spawns)| ProcessFact { comm, spawns })
        .collect();
    out.sort_by(|a, b| b.spawns.cmp(&a.spawns).then_with(|| a.comm.cmp(&b.comm)));
    out.truncate(TOP_N_PROCESSES);
    out
}

fn top_endpoints_from_graph(sockets: &[aw_graph::SocketNode]) -> Vec<EndpointFact> {
    let mut totals: HashMap<(String, String), u64> = HashMap::new();
    for s in sockets {
        let proc = s.process_name.clone().unwrap_or_else(|| "?".into());
        let bytes = s.rxbytes_last.unwrap_or(0).saturating_add(s.txbytes_last.unwrap_or(0));
        *totals.entry((s.id.foreign_addr.clone(), proc)).or_insert(0) += bytes;
    }
    let mut out: Vec<EndpointFact> = totals.into_iter()
        .map(|((foreign_addr, process_name), bytes_total)| EndpointFact {
            foreign_addr, process_name, bytes_total,
        })
        .collect();
    out.sort_by_key(|e| std::cmp::Reverse(e.bytes_total));
    out.truncate(TOP_N_ENDPOINTS);
    out
}

fn top_directories_from_graph(files: &[aw_graph::FileNode]) -> Vec<DirectoryFact> {
    let mut counts: BTreeMap<String, u32> = BTreeMap::new();
    for f in files {
        // Each file node carries a `touch_count`; sum that into its bucket
        // so multi-touch files weigh appropriately (the event path counts
        // each event, which is roughly equivalent).
        let bucket = directory_bucket(&f.path);
        *counts.entry(bucket).or_insert(0) += f.touch_count.min(u32::MAX as u64) as u32;
    }
    let mut out: Vec<DirectoryFact> = counts.into_iter()
        .map(|(directory, file_changes)| DirectoryFact { directory, file_changes })
        .collect();
    out.sort_by(|a, b| b.file_changes.cmp(&a.file_changes).then_with(|| a.directory.cmp(&b.directory)));
    out.truncate(TOP_N_DIRECTORIES);
    out
}

/// Walk `app_focus` events in time order, pairing each with the next as its
/// end-of-segment. The final segment runs until `capture_end_ns`.
fn build_focus_segments(events: &[Event], capture_end_ns: u64) -> Vec<FocusSegment> {
    let mut focus_events: Vec<&Event> = events.iter()
        .filter(|e| e.kind == EventKind::AppFocus)
        .collect();
    focus_events.sort_by_key(|e| e.timestamp.mono_ns);

    let mut out = Vec::with_capacity(focus_events.len());
    for (i, ev) in focus_events.iter().enumerate() {
        let name = ev.payload.get("to_name").and_then(|v| v.as_str()).unwrap_or("(unknown)").to_string();
        let bundle = ev.payload.get("to_bundle_id").and_then(|v| v.as_str()).map(String::from);
        let start_ns = ev.timestamp.mono_ns;
        let end_ns = focus_events.get(i + 1)
            .map(|n| n.timestamp.mono_ns)
            .unwrap_or(capture_end_ns);
        out.push(FocusSegment {
            app_name: name,
            bundle_id: bundle,
            started_secs: start_ns / 1_000_000_000,
            duration_secs: end_ns.saturating_sub(start_ns) / 1_000_000_000,
        });
    }
    out
}

/// Comm names that are almost always background noise on macOS and would
/// otherwise dominate a "top processes" list without telling the user
/// anything useful about what they were doing.
const NOISY_COMMS: &[&str] = &[
    "mdworker_shared", "mdworker", "mds_stores", "mds",
    "WindowServer", "loginwindow", "launchd",
    "syspolicyd", "notifyd", "distnoted",
];

fn top_processes(events: &[Event]) -> Vec<ProcessFact> {
    let mut counts: HashMap<String, u32> = HashMap::new();
    for ev in events.iter().filter(|e| e.kind == EventKind::ProcessBirth) {
        if let Some(comm) = ev.payload.get("comm").and_then(|v| v.as_str()) {
            if NOISY_COMMS.contains(&comm) { continue; }
            *counts.entry(comm.to_string()).or_insert(0) += 1;
        }
    }
    let mut out: Vec<ProcessFact> = counts.into_iter()
        .map(|(comm, spawns)| ProcessFact { comm, spawns })
        .collect();
    out.sort_by(|a, b| b.spawns.cmp(&a.spawns).then_with(|| a.comm.cmp(&b.comm)));
    out.truncate(TOP_N_PROCESSES);
    out
}

fn top_endpoints(events: &[Event]) -> Vec<EndpointFact> {
    // (foreign_addr, process_name) → bytes
    let mut totals: HashMap<(String, String), u64> = HashMap::new();
    for ev in events.iter().filter(|e| e.kind == EventKind::ConnectionCompleted) {
        let foreign = ev.payload.get("foreign_addr").and_then(|v| v.as_str()).unwrap_or("?").to_string();
        let proc = ev.payload.get("process_name").and_then(|v| v.as_str()).unwrap_or("?").to_string();
        let rx = ev.payload.get("bytes_rx").and_then(|v| v.as_u64()).unwrap_or(0);
        let tx = ev.payload.get("bytes_tx").and_then(|v| v.as_u64()).unwrap_or(0);
        *totals.entry((foreign, proc)).or_insert(0) += rx + tx;
    }
    let mut out: Vec<EndpointFact> = totals.into_iter()
        .map(|((foreign_addr, process_name), bytes_total)| EndpointFact {
            foreign_addr, process_name, bytes_total,
        })
        .collect();
    out.sort_by_key(|e| std::cmp::Reverse(e.bytes_total));
    out.truncate(TOP_N_ENDPOINTS);
    out
}

fn top_directories(events: &[Event]) -> Vec<DirectoryFact> {
    let mut counts: BTreeMap<String, u32> = BTreeMap::new();
    for ev in events.iter().filter(|e| e.kind == EventKind::FileChanged) {
        let Some(path) = ev.payload.get("path").and_then(|v| v.as_str()) else { continue; };
        let dir = directory_bucket(path);
        *counts.entry(dir).or_insert(0) += 1;
    }
    let mut out: Vec<DirectoryFact> = counts.into_iter()
        .map(|(directory, file_changes)| DirectoryFact { directory, file_changes })
        .collect();
    out.sort_by(|a, b| b.file_changes.cmp(&a.file_changes).then_with(|| a.directory.cmp(&b.directory)));
    out.truncate(TOP_N_DIRECTORIES);
    out
}

/// Truncate a filesystem path to its first ~4 components so file activity
/// aggregates meaningfully. `/Users/me/Projects/agentworld/.git/FETCH_HEAD`
/// becomes `/Users/me/Projects/agentworld`. Paths shorter than that are
/// returned unchanged.
fn directory_bucket(path: &str) -> String {
    let mut comps: Vec<&str> = path.split('/').filter(|c| !c.is_empty()).collect();
    if comps.len() > 4 { comps.truncate(4); }
    let mut bucket = String::from("/");
    bucket.push_str(&comps.join("/"));
    bucket
}

fn top_dns_clients(events: &[Event]) -> Vec<DnsClientFact> {
    // process_name → (unique name_hashes seen, total queries)
    let mut tally: HashMap<String, (std::collections::HashSet<String>, u32)> = HashMap::new();
    for ev in events.iter().filter(|e| e.kind == EventKind::DnsQuery) {
        let proc = ev.payload.get("client_process_name").and_then(|v| v.as_str()).unwrap_or("?").to_string();
        let hash = ev.payload.get("name_hash").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let entry = tally.entry(proc).or_default();
        if !hash.is_empty() { entry.0.insert(hash); }
        entry.1 += 1;
    }
    let mut out: Vec<DnsClientFact> = tally.into_iter()
        .map(|(process_name, (set, total))| DnsClientFact {
            process_name,
            unique_names: set.len() as u32,
            total_queries: total,
        })
        .collect();
    // Sort by total queries desc, then by name for stability.
    out.sort_by(|a, b| b.total_queries.cmp(&a.total_queries).then_with(|| a.process_name.cmp(&b.process_name)));
    out.truncate(TOP_N_DNS_CLIENTS);
    out
}

fn render_prompt(s: &CaptureSummary, live: bool) -> String {
    let mut out = String::new();
    let dur_human = humanize_duration(s.duration_secs);
    if live {
        out.push_str(&format!(
            "Live window: the last {dur_human} of macOS activity ({n} events). \
             This is happening right now.\n\n",
            n = s.events_total,
        ));
    } else {
        out.push_str(&format!(
            "A {dur_human} macOS capture recorded {n} events.\n\n",
            n = s.events_total,
        ));
    }

    if !s.focus_segments.is_empty() {
        out.push_str("APP FOCUS (in order):\n");
        for seg in &s.focus_segments {
            let dur = humanize_duration(seg.duration_secs);
            let bundle = seg.bundle_id.as_deref().map(|b| format!(" [{b}]")).unwrap_or_default();
            out.push_str(&format!("  - {} for {}{bundle}\n", seg.app_name, dur));
        }
        out.push('\n');
    } else {
        out.push_str("APP FOCUS: no focus changes were captured.\n\n");
    }

    if !s.top_processes.is_empty() {
        out.push_str("TOP PROCESSES (by spawn count, system daemons filtered):\n");
        for p in &s.top_processes {
            out.push_str(&format!("  - {} ({}x)\n", p.comm, p.spawns));
        }
        out.push('\n');
    }

    if !s.top_endpoints.is_empty() {
        out.push_str("TOP NETWORK ENDPOINTS (by bytes):\n");
        for e in &s.top_endpoints {
            out.push_str(&format!(
                "  - {} via {} ({} bytes)\n",
                e.foreign_addr, e.process_name, e.bytes_total,
            ));
        }
        out.push('\n');
    }

    if !s.top_directories.is_empty() {
        out.push_str("TOP FILE-ACTIVITY DIRECTORIES:\n");
        for d in &s.top_directories {
            out.push_str(&format!("  - {} ({} changes)\n", d.directory, d.file_changes));
        }
        out.push('\n');
    }

    if !s.top_dns_clients.is_empty() {
        out.push_str("TOP DNS-ISSUING PROCESSES:\n");
        for d in &s.top_dns_clients {
            out.push_str(&format!(
                "  - {} ({} unique names, {} queries)\n",
                d.process_name, d.unique_names, d.total_queries,
            ));
        }
        out.push('\n');
    }

    if live {
        out.push_str("Write 2–4 sentences of present-tense prose addressed to the user.\n");
    } else {
        out.push_str("Write 3–6 sentences of plain prose addressed to the user.\n");
    }
    out
}

fn humanize_duration(secs: u64) -> String {
    if secs < 60 { return format!("{secs}s"); }
    let m = secs / 60;
    let s = secs % 60;
    if m < 60 {
        if s == 0 { format!("{m}m") } else { format!("{m}m{s}s") }
    } else {
        let h = m / 60;
        let mm = m % 60;
        if mm == 0 { format!("{h}h") } else { format!("{h}h{mm}m") }
    }
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
            schema_version: SCHEMA_VERSION,
            timestamp: Timestamp { mono_ns: mono_ms * 1_000_000, wall_anchor_ns: 0 },
            kind, pid, payload,
        }
    }

    #[test]
    fn humanize_duration_renders_seconds_minutes_hours() {
        assert_eq!(humanize_duration(0), "0s");
        assert_eq!(humanize_duration(45), "45s");
        assert_eq!(humanize_duration(60), "1m");
        assert_eq!(humanize_duration(125), "2m5s");
        assert_eq!(humanize_duration(3600), "1h");
        assert_eq!(humanize_duration(3725), "1h2m");
    }

    #[test]
    fn directory_bucket_truncates_to_four_components() {
        assert_eq!(
            directory_bucket("/Users/me/Projects/agentworld/.git/FETCH_HEAD"),
            "/Users/me/Projects/agentworld",
        );
        // Shorter path is unchanged.
        assert_eq!(directory_bucket("/tmp/x"), "/tmp/x");
    }

    #[test]
    fn focus_segments_use_next_focus_or_capture_end_as_boundary() {
        // VS Code at t=10s, Chrome at t=70s, capture ends at t=100s.
        let events = vec![
            ev(EventKind::AppFocus, 10_000, None,
                json!({"to_name": "Code", "to_bundle_id": "com.microsoft.VSCode"})),
            ev(EventKind::AppFocus, 70_000, None,
                json!({"to_name": "Chrome", "to_bundle_id": "com.google.Chrome"})),
            // A non-focus event at t=100s extends capture span.
            ev(EventKind::ProcessBirth, 100_000, None, json!({"comm": "x"})),
        ];
        let s = summarize_capture(&events);
        assert_eq!(s.focus_segments.len(), 2);
        assert_eq!(s.focus_segments[0].app_name, "Code");
        assert_eq!(s.focus_segments[0].duration_secs, 60); // 70 - 10
        assert_eq!(s.focus_segments[1].app_name, "Chrome");
        assert_eq!(s.focus_segments[1].duration_secs, 30); // 100 - 70 (capture end)
    }

    #[test]
    fn top_processes_filters_noisy_daemons() {
        let events = vec![
            ev(EventKind::ProcessBirth, 0, None, json!({"comm": "mdworker_shared"})),
            ev(EventKind::ProcessBirth, 1, None, json!({"comm": "mdworker_shared"})),
            ev(EventKind::ProcessBirth, 2, None, json!({"comm": "mdworker_shared"})),
            ev(EventKind::ProcessBirth, 3, None, json!({"comm": "git"})),
            ev(EventKind::ProcessBirth, 4, None, json!({"comm": "git"})),
            ev(EventKind::ProcessBirth, 5, None, json!({"comm": "bash"})),
        ];
        let s = summarize_capture(&events);
        let names: Vec<&str> = s.top_processes.iter().map(|p| p.comm.as_str()).collect();
        assert!(!names.contains(&"mdworker_shared"), "noisy daemon should be filtered: {names:?}");
        assert!(names.contains(&"git"));
        assert!(names.contains(&"bash"));
        // Sorted by spawn count desc: git (2) before bash (1).
        assert_eq!(s.top_processes[0].comm, "git");
    }

    #[test]
    fn top_endpoints_sorted_by_byte_total() {
        let events = vec![
            ev(EventKind::ConnectionCompleted, 0, None, json!({
                "foreign_addr": "1.1.1.1.443", "process_name": "curl",
                "bytes_rx": 100u64, "bytes_tx": 50u64,
            })),
            ev(EventKind::ConnectionCompleted, 1, None, json!({
                "foreign_addr": "2.2.2.2.443", "process_name": "chrome",
                "bytes_rx": 5000u64, "bytes_tx": 200u64,
            })),
        ];
        let s = summarize_capture(&events);
        assert_eq!(s.top_endpoints.len(), 2);
        assert_eq!(s.top_endpoints[0].foreign_addr, "2.2.2.2.443");
        assert_eq!(s.top_endpoints[0].bytes_total, 5200);
    }

    #[test]
    fn dns_clients_count_unique_names_and_queries() {
        let events = vec![
            ev(EventKind::DnsQuery, 0, None, json!({"client_process_name": "git", "name_hash": "aa"})),
            ev(EventKind::DnsQuery, 1, None, json!({"client_process_name": "git", "name_hash": "aa"})),
            ev(EventKind::DnsQuery, 2, None, json!({"client_process_name": "git", "name_hash": "bb"})),
            ev(EventKind::DnsQuery, 3, None, json!({"client_process_name": "Zoom", "name_hash": "cc"})),
        ];
        let s = summarize_capture(&events);
        let git = s.top_dns_clients.iter().find(|c| c.process_name == "git").unwrap();
        assert_eq!(git.unique_names, 2);
        assert_eq!(git.total_queries, 3);
    }

    #[tokio::test]
    async fn narrator_prompt_contains_aggregated_facts_not_raw_events() {
        let mock = Arc::new(MockClient::new(vec!["You spent 1m on Code."]));
        let agent = TimelineNarrator::new(AgentCtx::new(mock.clone(), AgentConfig::default()));

        let events = vec![
            ev(EventKind::AppFocus, 0, None, json!({"to_name": "Code", "to_bundle_id": "com.microsoft.VSCode"})),
            ev(EventKind::ProcessBirth, 30_000, None, json!({"comm": "git"})),
            ev(EventKind::ConnectionCompleted, 60_000, None, json!({
                "foreign_addr": "140.82.112.4.443", "process_name": "git-remote-http",
                "bytes_rx": 8000u64, "bytes_tx": 1000u64,
            })),
        ];
        let report = agent.run(&events).await.unwrap();
        assert_eq!(report.summary, "You spent 1m on Code.");

        let prompt = &mock.calls()[0].prompt;
        // Aggregated facts must appear:
        assert!(prompt.contains("APP FOCUS"), "prompt: {prompt}");
        assert!(prompt.contains("Code"), "prompt: {prompt}");
        assert!(prompt.contains("TOP NETWORK ENDPOINTS"), "prompt: {prompt}");
        assert!(prompt.contains("140.82.112.4.443"), "prompt: {prompt}");
        // The raw event-stream marker from the old implementation must not be there.
        assert!(!prompt.contains("EVENTS:"), "raw event dump should be gone");
        // Details should be the structured CaptureSummary, not just counts.
        assert!(report.details.get("focus_segments").is_some());
        assert!(report.details.get("top_endpoints").is_some());
    }

    #[tokio::test]
    async fn empty_events_still_produces_a_prompt_and_does_not_panic() {
        let mock = Arc::new(MockClient::new(vec!["Nothing happened."]));
        let agent = TimelineNarrator::new(AgentCtx::new(mock.clone(), AgentConfig::default()));
        let report = agent.run(&[]).await.unwrap();
        assert_eq!(report.summary, "Nothing happened.");
        assert_eq!(report.details.get("events_total").and_then(|v| v.as_u64()), Some(0));
    }
}
