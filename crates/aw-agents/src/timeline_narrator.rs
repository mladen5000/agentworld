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
#[cfg(test)]
use aw_events::SCHEMA_VERSION;
use aw_events::{Event, EventKind};
use aw_llm::{GenerateRequest, Options};
use serde::{Deserialize, Serialize};

use crate::{AgentCtx, Report};

const TOP_N_PROCESSES: usize = 8;
const TOP_N_ENDPOINTS: usize = 8;
const TOP_N_DIRECTORIES: usize = 6;
const TOP_N_DNS_CLIENTS: usize = 6;
/// Example query names carried per DNS client (only when unmasked).
const DNS_EXAMPLE_NAMES: usize = 3;

// --- event-level suspicion heuristics (rule-based, no LLM) -----------------

/// Remote-access / commonly-abused destination ports worth flagging even at
/// negligible byte volume — exactly the connections a byte-ranked top list
/// would drop first.
const SENSITIVE_PORTS: &[(u16, &str)] = &[
    (22, "ssh"),
    (23, "telnet"),
    (3389, "rdp"),
    (5900, "vnc"),
    (4444, "common reverse-shell port"),
];
/// A process that lived less than this counts as short-lived.
const SHORT_LIVED_MAX_SECS: u64 = 10;
/// How many short-lived instances of one comm make a "burst".
const SHORT_LIVED_BURST_MIN: u32 = 5;
/// Unique DNS names by a single client in one window that count as
/// unusually high fan-out.
const HEAVY_DNS_UNIQUE_NAMES: u32 = 50;
/// Overall cap on event-derived suspicion strings.
const MAX_EVENT_SUSPICIONS: usize = 8;

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

    /// Per-kind event counts (`process_birth=3 file_changed=120 …`), so the
    /// LLM sees the full activity mix even for kinds that have no dedicated
    /// section — nothing in the window is completely invisible.
    #[serde(default)]
    pub kind_counts: Vec<(String, u32)>,

    /// Store-backed novelty: what in this window was seen for the first time
    /// ever on this machine. `None` when no store was available (stdin/CLI
    /// paths) — the prompt then omits the section entirely and reads exactly
    /// as it did before novelty existed.
    #[serde(default)]
    pub novelty: Option<NoveltySummary>,

    /// Rule-based suspicion flags (computed, not LLM-authored), rendered as
    /// short human-readable strings. Empty = nothing flagged.
    #[serde(default)]
    pub suspicions: Vec<String>,
}

/// What in this window was never seen before, per entity kind. Lists are
/// pre-rendered strings ready for the prompt.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NoveltySummary {
    /// True when the store's history barely predates the window — "first
    /// time ever seen" is not yet a meaningful claim, so the lists are left
    /// empty and the prompt says the baseline is warming up.
    pub baseline_cold: bool,
    pub new_processes: Vec<String>,
    pub new_domains: Vec<String>,
    pub new_endpoints: Vec<String>,
    pub new_apps: Vec<String>,
}

impl NoveltySummary {
    pub fn has_novelty(&self) -> bool {
        !self.new_processes.is_empty()
            || !self.new_domains.is_empty()
            || !self.new_endpoints.is_empty()
            || !self.new_apps.is_empty()
    }

    /// Convert the store's raw [`aw_store::NoveltyReport`] into prompt-ready
    /// strings. `baseline_cold` short-circuits to empty lists: when the
    /// store's history barely predates the window, "first time ever seen" is
    /// not a meaningful claim and the prompt should say so instead.
    pub fn from_report(r: &aw_store::NoveltyReport, baseline_cold: bool) -> Self {
        if baseline_cold {
            return Self {
                baseline_cold: true,
                ..Self::default()
            };
        }
        let new_processes = r
            .new_processes
            .iter()
            .map(|p| {
                let mut s = match (p.comm.as_deref(), p.exec_path.as_deref()) {
                    (Some(c), Some(e)) => format!("{c} ({e})"),
                    (Some(c), None) => c.to_string(),
                    (None, Some(e)) => e.to_string(),
                    (None, None) => "?".to_string(),
                };
                if p.instances > 1 {
                    s.push_str(&format!(" — {} runs", p.instances));
                }
                s
            })
            .collect();
        let new_endpoints = r
            .new_endpoints
            .iter()
            .map(|e| match e.example_process.as_deref() {
                Some(p) => format!("{} (via {p})", e.foreign_addr),
                None => e.foreign_addr.clone(),
            })
            .collect();
        let new_apps = r
            .new_apps
            .iter()
            .map(|a| match a.name.as_deref() {
                Some(n) => format!("{n} [{}]", a.id),
                None => a.id.clone(),
            })
            .collect();
        Self {
            baseline_cold: false,
            new_processes,
            new_domains: r.new_domains.clone(),
            new_endpoints,
            new_apps,
        }
    }
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
    /// True when the connection was opened in the window but never completed
    /// — a long-lived connection still alive at window end. Byte counts for
    /// these are the snapshot at open time, usually an undercount.
    #[serde(default)]
    pub still_open: bool,
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
    /// Up to three example query names, only when the source delivered them
    /// unmasked. Empty on default installs where mDNSResponder redacts names.
    #[serde(default)]
    pub example_names: Vec<String>,
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
    pub fn new(ctx: AgentCtx) -> Self {
        Self { ctx, live: false }
    }

    /// Switch the prompt to present-tense framing — what you'd want from a
    /// daemon emitting a paragraph every minute.
    pub fn live(mut self) -> Self {
        self.live = true;
        self
    }

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
             is at the keyboard right now. If the prompt lists ANOMALY FLAGS or \
             NEVER-SEEN-BEFORE items, open with the most significant of those and \
             say concretely why it stands out (many flags are benign dev tooling — \
             use judgement, don't alarm over cargo/git/editor helpers). Then be \
             concrete and human about the rest: what they ARE doing (dominant app + \
             apparent purpose), notable network destinations, any other striking \
             signal from the last few minutes. Use present-perfect tense (\"you've \
             been …\") when describing how long activity has lasted. Keep it to 2–5 \
             sentences. Do NOT speculate beyond the data. Do NOT output bullet \
             points or JSON — plain prose only."
        } else {
            "You are summarising a short macOS behavioural capture in plain English \
             for the user who was at the keyboard. If the prompt lists ANOMALY \
             FLAGS or NEVER-SEEN-BEFORE items, open with the most significant of \
             those and say concretely why it stands out (many flags are benign dev \
             tooling — use judgement). Then be concrete and human about the rest: \
             the dominant app(s) and what they appear to have been used for, \
             notable network destinations, any other striking signal. Keep it to \
             3–6 sentences. Speak in second person (\"you were …\"). Do NOT \
             speculate beyond the data. Do NOT output bullet points or JSON — \
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
            kind_counts: Vec::new(),
            novelty: None,
            suspicions: Vec::new(),
        };
    }

    // Total span — use min/max of mono_ns, robust to out-of-order events.
    let min_ns = events
        .iter()
        .map(|e| e.timestamp.mono_ns)
        .min()
        .unwrap_or(0);
    let max_ns = events
        .iter()
        .map(|e| e.timestamp.mono_ns)
        .max()
        .unwrap_or(0);
    let duration_secs = max_ns.saturating_sub(min_ns) / 1_000_000_000;

    CaptureSummary {
        duration_secs,
        events_total: events.len(),
        focus_segments: build_focus_segments(events, max_ns),
        top_processes: top_processes(events),
        top_endpoints: top_endpoints(events),
        top_directories: top_directories(events),
        top_dns_clients: top_dns_clients(events),
        kind_counts: kind_counts(events),
        novelty: None,
        suspicions: event_suspicions(events),
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
            kind_counts: Vec::new(),
            novelty: None,
            suspicions: Vec::new(),
        };
    }

    // Span: min `birth` / max `death|birth` across processes, plus app
    // interval bounds and socket open/close. Timestamps are stored as
    // wall-clock unix-ns inside `mono_ns` after a store round-trip
    // (see `aw_store::process_from_row`), so subtraction yields seconds.
    let mut min_ns = u64::MAX;
    let mut max_ns = 0u64;
    let mut bump = |t: u64| {
        if t == 0 {
            return;
        }
        if t < min_ns {
            min_ns = t;
        }
        if t > max_ns {
            max_ns = t;
        }
    };
    for p in &g.processes {
        bump(p.birth.mono_ns);
        if let Some(d) = p.death {
            bump(d.mono_ns);
        }
    }
    for a in &g.apps {
        for iv in &a.intervals {
            bump(iv.from.mono_ns);
            if let Some(t) = iv.to {
                bump(t.mono_ns);
            }
        }
    }
    for s in &g.sockets {
        bump(s.opened.mono_ns);
        if let Some(c) = s.closed {
            bump(c.mono_ns);
        }
    }
    for f in &g.files {
        bump(f.first_seen.mono_ns);
        bump(f.last_seen.mono_ns);
    }
    let duration_secs = if max_ns >= min_ns && min_ns != u64::MAX {
        (max_ns - min_ns) / 1_000_000_000
    } else {
        0
    };

    CaptureSummary {
        duration_secs,
        events_total: things,
        focus_segments: focus_segments_from_apps(&g.apps),
        top_processes: top_processes_from_graph(&g.processes),
        top_endpoints: top_endpoints_from_graph(&g.sockets),
        top_directories: top_directories_from_graph(&g.files),
        top_dns_clients: Vec::new(),
        // Graph nodes are entities, not events, but the same "activity mix"
        // line still tells the LLM the shape of the window.
        kind_counts: vec![
            ("processes".into(), g.processes.len() as u32),
            ("apps".into(), g.apps.len() as u32),
            ("sockets".into(), g.sockets.len() as u32),
            ("files".into(), g.files.len() as u32),
            ("domains".into(), g.domains.len() as u32),
        ],
        novelty: None,
        suspicions: Vec::new(),
    }
}

fn focus_segments_from_apps(apps: &[aw_graph::AppNode]) -> Vec<FocusSegment> {
    // Flatten every (app, interval) pair into a FocusSegment, then sort by
    // start time so the narrative reads chronologically. An app that was
    // frontmost three times shows up as three segments — exactly what the
    // event path produces.
    let mut out: Vec<FocusSegment> = apps
        .iter()
        .flat_map(|a| {
            a.intervals.iter().map(move |iv| FocusSegment {
                app_name: a.name.clone().unwrap_or_else(|| a.id.clone()),
                bundle_id: Some(a.id.clone()),
                started_secs: iv.from.mono_ns / 1_000_000_000,
                duration_secs: iv
                    .to
                    .map(|t| t.mono_ns.saturating_sub(iv.from.mono_ns) / 1_000_000_000)
                    .unwrap_or(0),
            })
        })
        .collect();
    out.sort_by_key(|s| s.started_secs);
    out
}

fn top_processes_from_graph(processes: &[aw_graph::ProcessNode]) -> Vec<ProcessFact> {
    let mut counts: HashMap<String, u32> = HashMap::new();
    for p in processes {
        let Some(comm) = p.comm.as_deref() else {
            continue;
        };
        if NOISY_COMMS.contains(&comm) {
            continue;
        }
        *counts.entry(comm.to_string()).or_insert(0) += 1;
    }
    let mut out: Vec<ProcessFact> = counts
        .into_iter()
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
        let bytes = s
            .rxbytes_last
            .unwrap_or(0)
            .saturating_add(s.txbytes_last.unwrap_or(0));
        *totals.entry((s.id.foreign_addr.clone(), proc)).or_insert(0) += bytes;
    }
    let mut out: Vec<EndpointFact> = totals
        .into_iter()
        .map(|((foreign_addr, process_name), bytes_total)| EndpointFact {
            foreign_addr,
            process_name,
            bytes_total,
            still_open: false,
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
    let mut out: Vec<DirectoryFact> = counts
        .into_iter()
        .map(|(directory, file_changes)| DirectoryFact {
            directory,
            file_changes,
        })
        .collect();
    out.sort_by(|a, b| {
        b.file_changes
            .cmp(&a.file_changes)
            .then_with(|| a.directory.cmp(&b.directory))
    });
    out.truncate(TOP_N_DIRECTORIES);
    out
}

/// Walk `app_focus` events in time order, pairing each with the next as its
/// end-of-segment. The final segment runs until `capture_end_ns`.
fn build_focus_segments(events: &[Event], capture_end_ns: u64) -> Vec<FocusSegment> {
    let mut focus_events: Vec<&Event> = events
        .iter()
        .filter(|e| e.kind == EventKind::AppFocus)
        .collect();
    focus_events.sort_by_key(|e| e.timestamp.mono_ns);

    let mut out = Vec::with_capacity(focus_events.len());
    for (i, ev) in focus_events.iter().enumerate() {
        let name = ev
            .payload
            .get("to_name")
            .and_then(|v| v.as_str())
            .unwrap_or("(unknown)")
            .to_string();
        let bundle = ev
            .payload
            .get("to_bundle_id")
            .and_then(|v| v.as_str())
            .map(String::from);
        let start_ns = ev.timestamp.mono_ns;
        let end_ns = focus_events
            .get(i + 1)
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
    "mdworker_shared",
    "mdworker",
    "mds_stores",
    "mds",
    "WindowServer",
    "loginwindow",
    "launchd",
    "syspolicyd",
    "notifyd",
    "distnoted",
];

fn top_processes(events: &[Event]) -> Vec<ProcessFact> {
    let mut counts: HashMap<String, u32> = HashMap::new();
    for ev in events.iter().filter(|e| e.kind == EventKind::ProcessBirth) {
        if let Some(comm) = ev.payload.get("comm").and_then(|v| v.as_str()) {
            if NOISY_COMMS.contains(&comm) {
                continue;
            }
            *counts.entry(comm.to_string()).or_insert(0) += 1;
        }
    }
    let mut out: Vec<ProcessFact> = counts
        .into_iter()
        .map(|(comm, spawns)| ProcessFact { comm, spawns })
        .collect();
    out.sort_by(|a, b| b.spawns.cmp(&a.spawns).then_with(|| a.comm.cmp(&b.comm)));
    out.truncate(TOP_N_PROCESSES);
    out
}

fn top_endpoints(events: &[Event]) -> Vec<EndpointFact> {
    // (foreign_addr, process_name) → bytes, from completed connections.
    let mut totals: HashMap<(String, String), u64> = HashMap::new();
    for ev in events
        .iter()
        .filter(|e| e.kind == EventKind::ConnectionCompleted)
    {
        let foreign = ev
            .payload
            .get("foreign_addr")
            .and_then(|v| v.as_str())
            .unwrap_or("?")
            .to_string();
        let proc = ev
            .payload
            .get("process_name")
            .and_then(|v| v.as_str())
            .unwrap_or("?")
            .to_string();
        let rx = ev
            .payload
            .get("bytes_rx")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let tx = ev
            .payload
            .get("bytes_tx")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        *totals.entry((foreign, proc)).or_insert(0) += rx + tx;
    }
    // Connections opened but never completed in the window are still alive —
    // exactly the long-lived kind a live observer would notice. Track them
    // separately (byte counts are the snapshot at open, an undercount) so
    // completed traffic isn't double-counted.
    let mut open_only: HashMap<(String, String), u64> = HashMap::new();
    for ev in events
        .iter()
        .filter(|e| e.kind == EventKind::ConnectionOpened)
    {
        let foreign = ev
            .payload
            .get("foreign_addr")
            .and_then(|v| v.as_str())
            .unwrap_or("?")
            .to_string();
        let proc = ev
            .payload
            .get("process_name")
            .and_then(|v| v.as_str())
            .unwrap_or("?")
            .to_string();
        let key = (foreign, proc);
        if totals.contains_key(&key) {
            continue;
        }
        let rx = ev
            .payload
            .get("rxbytes")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let tx = ev
            .payload
            .get("txbytes")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        *open_only.entry(key).or_insert(0) += rx + tx;
    }

    let mut out: Vec<EndpointFact> = totals
        .into_iter()
        .map(|((foreign_addr, process_name), bytes_total)| EndpointFact {
            foreign_addr,
            process_name,
            bytes_total,
            still_open: false,
        })
        .chain(
            open_only
                .into_iter()
                .map(|((foreign_addr, process_name), bytes_total)| EndpointFact {
                    foreign_addr,
                    process_name,
                    bytes_total,
                    still_open: true,
                }),
        )
        .collect();
    out.sort_by_key(|e| std::cmp::Reverse(e.bytes_total));
    if out.len() > TOP_N_ENDPOINTS {
        // Don't let low-byte still-open connections vanish under the byte
        // ranking: keep the top N, then re-append up to two of the truncated
        // still-open endpoints so they stay visible.
        let overflow: Vec<EndpointFact> = out
            .split_off(TOP_N_ENDPOINTS)
            .into_iter()
            .filter(|e| e.still_open)
            .take(2)
            .collect();
        out.extend(overflow);
    }
    out
}

fn top_directories(events: &[Event]) -> Vec<DirectoryFact> {
    let mut counts: BTreeMap<String, u32> = BTreeMap::new();
    for ev in events.iter().filter(|e| e.kind == EventKind::FileChanged) {
        let Some(path) = ev.payload.get("path").and_then(|v| v.as_str()) else {
            continue;
        };
        let dir = directory_bucket(path);
        *counts.entry(dir).or_insert(0) += 1;
    }
    let mut out: Vec<DirectoryFact> = counts
        .into_iter()
        .map(|(directory, file_changes)| DirectoryFact {
            directory,
            file_changes,
        })
        .collect();
    out.sort_by(|a, b| {
        b.file_changes
            .cmp(&a.file_changes)
            .then_with(|| a.directory.cmp(&b.directory))
    });
    out.truncate(TOP_N_DIRECTORIES);
    out
}

/// Truncate a filesystem path to its first ~4 components so file activity
/// aggregates meaningfully. `/Users/me/Projects/agentworld/.git/FETCH_HEAD`
/// becomes `/Users/me/Projects/agentworld`. Paths shorter than that are
/// returned unchanged.
fn directory_bucket(path: &str) -> String {
    let mut comps: Vec<&str> = path.split('/').filter(|c| !c.is_empty()).collect();
    if comps.len() > 4 {
        comps.truncate(4);
    }
    let mut bucket = String::from("/");
    bucket.push_str(&comps.join("/"));
    bucket
}

fn top_dns_clients(events: &[Event]) -> Vec<DnsClientFact> {
    // process_name → (unique name_hashes seen, total queries, example qnames)
    #[derive(Default)]
    struct Tally {
        hashes: std::collections::HashSet<String>,
        total: u32,
        examples: Vec<String>,
    }
    let mut tally: HashMap<String, Tally> = HashMap::new();
    for ev in events.iter().filter(|e| e.kind == EventKind::DnsQuery) {
        let proc = ev
            .payload
            .get("client_process_name")
            .and_then(|v| v.as_str())
            .unwrap_or("?")
            .to_string();
        let hash = ev
            .payload
            .get("name_hash")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let entry = tally.entry(proc).or_default();
        if !hash.is_empty() {
            entry.hashes.insert(hash);
        }
        entry.total += 1;
        // Real names reach the prompt only when the source delivered them
        // unmasked; hashes stay out of prose.
        let masked = ev
            .payload
            .get("masked")
            .and_then(|v| v.as_bool())
            .unwrap_or(true);
        if !masked {
            if let Some(qname) = ev.payload.get("qname").and_then(|v| v.as_str()) {
                let qname = qname.trim_end_matches('.').to_string();
                if !qname.is_empty()
                    && entry.examples.len() < DNS_EXAMPLE_NAMES
                    && !entry.examples.contains(&qname)
                {
                    entry.examples.push(qname);
                }
            }
        }
    }
    let mut out: Vec<DnsClientFact> = tally
        .into_iter()
        .map(|(process_name, t)| DnsClientFact {
            process_name,
            unique_names: t.hashes.len() as u32,
            total_queries: t.total,
            example_names: t.examples,
        })
        .collect();
    // Sort by total queries desc, then by name for stability.
    out.sort_by(|a, b| {
        b.total_queries
            .cmp(&a.total_queries)
            .then_with(|| a.process_name.cmp(&b.process_name))
    });
    out.truncate(TOP_N_DNS_CLIENTS);
    out
}

/// Per-kind event counts in a stable order, so the LLM sees the full
/// activity mix — including kinds with no dedicated section (process deaths,
/// opened/closed connections). Zero-count kinds are omitted.
fn kind_counts(events: &[Event]) -> Vec<(String, u32)> {
    let mut counts: BTreeMap<&'static str, u32> = BTreeMap::new();
    for ev in events {
        let label = match ev.kind {
            EventKind::ProcessBirth => "process_birth",
            EventKind::ProcessDeath => "process_death",
            EventKind::AppFocus => "app_focus",
            EventKind::ConnectionOpened => "connection_opened",
            EventKind::ConnectionClosed => "connection_closed",
            EventKind::ConnectionCompleted => "connection_completed",
            EventKind::FileChanged => "file_changed",
            EventKind::DnsQuery => "dns_query",
        };
        *counts.entry(label).or_insert(0) += 1;
    }
    counts
        .into_iter()
        .map(|(k, n)| (k.to_string(), n))
        .collect()
}

/// Extract the destination port from a nettop-style foreign address
/// (`1.2.3.4.443`, `2607:f8b0::200e.443`). Only claims a port when the
/// prefix is a well-formed IP, so a bare `1.2.3.4` doesn't misread its last
/// octet as port 4.
fn foreign_port(addr: &str) -> Option<u16> {
    let (host, port) = addr.rsplit_once('.')?;
    let port: u16 = port.parse().ok()?;
    host.parse::<std::net::IpAddr>().ok().map(|_| port)
}

/// Rule-based anomaly flags visible from the window's events alone (store-
/// backed flags — novelty, lineage — are the caller's to append):
///
/// - connections to remote-access / commonly-abused ports, regardless of
///   byte volume;
/// - bursts of short-lived processes (same comm born AND dead within the
///   window, lifetime under [`SHORT_LIVED_MAX_SECS`]);
/// - a single client issuing unusually many unique DNS names.
fn event_suspicions(events: &[Event]) -> Vec<String> {
    let mut out = Vec::new();

    // Sensitive-port connections, deduped per (process, endpoint).
    let mut seen: std::collections::HashSet<(String, String)> = std::collections::HashSet::new();
    for ev in events {
        if !matches!(
            ev.kind,
            EventKind::ConnectionOpened | EventKind::ConnectionCompleted
        ) {
            continue;
        }
        let Some(foreign) = ev.payload.get("foreign_addr").and_then(|v| v.as_str()) else {
            continue;
        };
        let Some(port) = foreign_port(foreign) else {
            continue;
        };
        let Some((_, label)) = SENSITIVE_PORTS.iter().find(|(p, _)| *p == port) else {
            continue;
        };
        let proc = ev
            .payload
            .get("process_name")
            .and_then(|v| v.as_str())
            .unwrap_or("?");
        if !seen.insert((proc.to_string(), foreign.to_string())) {
            continue;
        }
        out.push(format!(
            "'{proc}' connected to {foreign} — port {port} ({label})"
        ));
    }

    // Short-lived process bursts: pair births and deaths by pid.
    let mut births: HashMap<u32, u64> = HashMap::new();
    for ev in events.iter().filter(|e| e.kind == EventKind::ProcessBirth) {
        if let Some(pid) = ev.pid {
            births.insert(pid, ev.timestamp.mono_ns);
        }
    }
    let mut short_lived: BTreeMap<String, u32> = BTreeMap::new();
    for ev in events.iter().filter(|e| e.kind == EventKind::ProcessDeath) {
        let Some(pid) = ev.pid else {
            continue;
        };
        let Some(&born_ns) = births.get(&pid) else {
            continue;
        };
        if ev.timestamp.mono_ns.saturating_sub(born_ns) >= SHORT_LIVED_MAX_SECS * 1_000_000_000 {
            continue;
        }
        let comm = ev
            .payload
            .get("comm")
            .and_then(|v| v.as_str())
            .unwrap_or("?");
        if NOISY_COMMS.contains(&comm) {
            continue;
        }
        *short_lived.entry(comm.to_string()).or_insert(0) += 1;
    }
    for (comm, n) in short_lived {
        if n >= SHORT_LIVED_BURST_MIN {
            out.push(format!(
                "burst of short-lived processes: {n} '{comm}' instances each started and exited within seconds"
            ));
        }
    }

    // Heavy DNS fan-out per client.
    for c in top_dns_clients(events) {
        if c.unique_names >= HEAVY_DNS_UNIQUE_NAMES {
            out.push(format!(
                "'{}' queried {} unique DNS names in this window — unusually high fan-out",
                c.process_name, c.unique_names,
            ));
        }
    }

    out.truncate(MAX_EVENT_SUSPICIONS);
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

    if !s.kind_counts.is_empty() {
        let mix: Vec<String> = s
            .kind_counts
            .iter()
            .map(|(k, n)| format!("{k}={n}"))
            .collect();
        out.push_str(&format!("EVENT MIX: {}\n\n", mix.join(" ")));
    }

    // Anomalies lead: flags and novelty come before routine activity so the
    // model weights them first.
    if !s.suspicions.is_empty() {
        out.push_str(
            "ANOMALY FLAGS (rule-based, pre-computed; some may be benign dev tooling — judge each):\n",
        );
        for f in &s.suspicions {
            out.push_str(&format!("  - {f}\n"));
        }
        out.push('\n');
    }

    if let Some(nv) = &s.novelty {
        if nv.baseline_cold {
            out.push_str(
                "NOVELTY: baseline still warming up — too little history to say what is new.\n\n",
            );
        } else if nv.has_novelty() {
            out.push_str("NEVER SEEN BEFORE ON THIS MACHINE (first observation ever):\n");
            for p in &nv.new_processes {
                out.push_str(&format!("  - new process: {p}\n"));
            }
            for d in &nv.new_domains {
                out.push_str(&format!("  - new domain: {d}\n"));
            }
            for e in &nv.new_endpoints {
                out.push_str(&format!("  - new endpoint: {e}\n"));
            }
            for a in &nv.new_apps {
                out.push_str(&format!("  - new app: {a}\n"));
            }
            out.push('\n');
        } else {
            out.push_str(
                "NOVELTY: nothing new — every process, domain, endpoint and app in this window \
                 had been seen before.\n\n",
            );
        }
    }

    if !s.focus_segments.is_empty() {
        out.push_str("APP FOCUS (in order):\n");
        for seg in &s.focus_segments {
            let dur = humanize_duration(seg.duration_secs);
            let bundle = seg
                .bundle_id
                .as_deref()
                .map(|b| format!(" [{b}]"))
                .unwrap_or_default();
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
            let open = if e.still_open { ", still open" } else { "" };
            out.push_str(&format!(
                "  - {} via {} ({} bytes{open})\n",
                e.foreign_addr, e.process_name, e.bytes_total,
            ));
        }
        out.push('\n');
    }

    if !s.top_directories.is_empty() {
        out.push_str("TOP FILE-ACTIVITY DIRECTORIES:\n");
        for d in &s.top_directories {
            out.push_str(&format!(
                "  - {} ({} changes)\n",
                d.directory, d.file_changes
            ));
        }
        out.push('\n');
    }

    if !s.top_dns_clients.is_empty() {
        out.push_str("TOP DNS-ISSUING PROCESSES:\n");
        for d in &s.top_dns_clients {
            let examples = if d.example_names.is_empty() {
                String::new()
            } else {
                format!("; e.g. {}", d.example_names.join(", "))
            };
            out.push_str(&format!(
                "  - {} ({} unique names, {} queries{examples})\n",
                d.process_name, d.unique_names, d.total_queries,
            ));
        }
        out.push('\n');
    }

    let has_anomalies =
        !s.suspicions.is_empty() || s.novelty.as_ref().is_some_and(|n| n.has_novelty());
    if has_anomalies {
        out.push_str(
            "Lead with the most significant anomaly flag or first-time-seen item and say \
             plainly why it stands out, then cover the routine activity. ",
        );
    }
    if live {
        out.push_str("Write 2–5 sentences of present-tense prose addressed to the user.\n");
    } else {
        out.push_str("Write 3–6 sentences of plain prose addressed to the user.\n");
    }
    out
}

fn humanize_duration(secs: u64) -> String {
    if secs < 60 {
        return format!("{secs}s");
    }
    let m = secs / 60;
    let s = secs % 60;
    if m < 60 {
        if s == 0 {
            format!("{m}m")
        } else {
            format!("{m}m{s}s")
        }
    } else {
        let h = m / 60;
        let mm = m % 60;
        if mm == 0 {
            format!("{h}h")
        } else {
            format!("{h}h{mm}m")
        }
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
            timestamp: Timestamp {
                mono_ns: mono_ms * 1_000_000,
                wall_anchor_ns: 0,
            },
            kind,
            pid,
            payload,
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
            ev(
                EventKind::AppFocus,
                10_000,
                None,
                json!({"to_name": "Code", "to_bundle_id": "com.microsoft.VSCode"}),
            ),
            ev(
                EventKind::AppFocus,
                70_000,
                None,
                json!({"to_name": "Chrome", "to_bundle_id": "com.google.Chrome"}),
            ),
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
            ev(
                EventKind::ProcessBirth,
                0,
                None,
                json!({"comm": "mdworker_shared"}),
            ),
            ev(
                EventKind::ProcessBirth,
                1,
                None,
                json!({"comm": "mdworker_shared"}),
            ),
            ev(
                EventKind::ProcessBirth,
                2,
                None,
                json!({"comm": "mdworker_shared"}),
            ),
            ev(EventKind::ProcessBirth, 3, None, json!({"comm": "git"})),
            ev(EventKind::ProcessBirth, 4, None, json!({"comm": "git"})),
            ev(EventKind::ProcessBirth, 5, None, json!({"comm": "bash"})),
        ];
        let s = summarize_capture(&events);
        let names: Vec<&str> = s.top_processes.iter().map(|p| p.comm.as_str()).collect();
        assert!(
            !names.contains(&"mdworker_shared"),
            "noisy daemon should be filtered: {names:?}"
        );
        assert!(names.contains(&"git"));
        assert!(names.contains(&"bash"));
        // Sorted by spawn count desc: git (2) before bash (1).
        assert_eq!(s.top_processes[0].comm, "git");
    }

    #[test]
    fn top_endpoints_sorted_by_byte_total() {
        let events = vec![
            ev(
                EventKind::ConnectionCompleted,
                0,
                None,
                json!({
                    "foreign_addr": "1.1.1.1.443", "process_name": "curl",
                    "bytes_rx": 100u64, "bytes_tx": 50u64,
                }),
            ),
            ev(
                EventKind::ConnectionCompleted,
                1,
                None,
                json!({
                    "foreign_addr": "2.2.2.2.443", "process_name": "chrome",
                    "bytes_rx": 5000u64, "bytes_tx": 200u64,
                }),
            ),
        ];
        let s = summarize_capture(&events);
        assert_eq!(s.top_endpoints.len(), 2);
        assert_eq!(s.top_endpoints[0].foreign_addr, "2.2.2.2.443");
        assert_eq!(s.top_endpoints[0].bytes_total, 5200);
    }

    #[test]
    fn dns_clients_count_unique_names_and_queries() {
        let events = vec![
            ev(
                EventKind::DnsQuery,
                0,
                None,
                json!({"client_process_name": "git", "name_hash": "aa"}),
            ),
            ev(
                EventKind::DnsQuery,
                1,
                None,
                json!({"client_process_name": "git", "name_hash": "aa"}),
            ),
            ev(
                EventKind::DnsQuery,
                2,
                None,
                json!({"client_process_name": "git", "name_hash": "bb"}),
            ),
            ev(
                EventKind::DnsQuery,
                3,
                None,
                json!({"client_process_name": "Zoom", "name_hash": "cc"}),
            ),
        ];
        let s = summarize_capture(&events);
        let git = s
            .top_dns_clients
            .iter()
            .find(|c| c.process_name == "git")
            .unwrap();
        assert_eq!(git.unique_names, 2);
        assert_eq!(git.total_queries, 3);
    }

    #[tokio::test]
    async fn narrator_prompt_contains_aggregated_facts_not_raw_events() {
        let mock = Arc::new(MockClient::new(vec!["You spent 1m on Code."]));
        let agent = TimelineNarrator::new(AgentCtx::new(mock.clone(), AgentConfig::default()));

        let events = vec![
            ev(
                EventKind::AppFocus,
                0,
                None,
                json!({"to_name": "Code", "to_bundle_id": "com.microsoft.VSCode"}),
            ),
            ev(
                EventKind::ProcessBirth,
                30_000,
                None,
                json!({"comm": "git"}),
            ),
            ev(
                EventKind::ConnectionCompleted,
                60_000,
                None,
                json!({
                    "foreign_addr": "140.82.112.4.443", "process_name": "git-remote-http",
                    "bytes_rx": 8000u64, "bytes_tx": 1000u64,
                }),
            ),
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

    #[test]
    fn kind_counts_cover_every_kind_present() {
        let events = vec![
            ev(EventKind::ProcessBirth, 0, Some(9), json!({"comm": "x"})),
            ev(EventKind::ProcessDeath, 1, Some(9), json!({"comm": "x"})),
            ev(EventKind::FileChanged, 2, None, json!({"path": "/tmp/a"})),
            ev(EventKind::FileChanged, 3, None, json!({"path": "/tmp/b"})),
        ];
        let s = summarize_capture(&events);
        assert!(
            s.kind_counts.contains(&("process_death".to_string(), 1)),
            "{:?}",
            s.kind_counts
        );
        assert!(
            s.kind_counts.contains(&("file_changed".to_string(), 2)),
            "{:?}",
            s.kind_counts
        );
    }

    #[test]
    fn still_open_connections_appear_without_double_counting_completed() {
        let events = vec![
            // Opens and completes in-window — must count once, via completed.
            ev(
                EventKind::ConnectionOpened,
                0,
                None,
                json!({
                    "foreign_addr": "1.1.1.1.443", "process_name": "curl",
                    "rxbytes": 10u64, "txbytes": 10u64,
                }),
            ),
            ev(
                EventKind::ConnectionCompleted,
                5,
                None,
                json!({
                    "foreign_addr": "1.1.1.1.443", "process_name": "curl",
                    "bytes_rx": 100u64, "bytes_tx": 50u64,
                }),
            ),
            // Opens and never completes — still alive at window end.
            ev(
                EventKind::ConnectionOpened,
                6,
                None,
                json!({
                    "foreign_addr": "9.9.9.9.8443", "process_name": "agentd",
                    "rxbytes": 5u64, "txbytes": 5u64,
                }),
            ),
        ];
        let s = summarize_capture(&events);
        let completed = s
            .top_endpoints
            .iter()
            .find(|e| e.foreign_addr == "1.1.1.1.443")
            .unwrap();
        assert_eq!(
            completed.bytes_total, 150,
            "opened snapshot must not be added on top"
        );
        assert!(!completed.still_open);
        let open = s
            .top_endpoints
            .iter()
            .find(|e| e.foreign_addr == "9.9.9.9.8443")
            .unwrap();
        assert!(open.still_open);
        assert_eq!(open.bytes_total, 10);
    }

    #[test]
    fn unmasked_qnames_become_example_names_masked_stay_out() {
        let events = vec![
            ev(
                EventKind::DnsQuery,
                0,
                None,
                json!({
                    "client_process_name": "git", "name_hash": "aa",
                    "qname": "github.com.", "masked": false,
                }),
            ),
            ev(
                EventKind::DnsQuery,
                1,
                None,
                json!({
                    "client_process_name": "git", "name_hash": "bb",
                    "qname": "hash:deadbeef", "masked": true,
                }),
            ),
        ];
        let s = summarize_capture(&events);
        let git = s
            .top_dns_clients
            .iter()
            .find(|c| c.process_name == "git")
            .unwrap();
        assert_eq!(
            git.example_names,
            vec!["github.com"],
            "trailing dot stripped, masked excluded"
        );
    }

    #[test]
    fn foreign_port_requires_a_well_formed_ip_prefix() {
        assert_eq!(foreign_port("140.82.112.4.443"), Some(443));
        assert_eq!(foreign_port("2607:f8b0::200e.443"), Some(443));
        assert_eq!(foreign_port("1.2.3.4"), None, "bare IPv4 has no port");
        assert_eq!(foreign_port("example.com"), None);
    }

    #[test]
    fn event_suspicions_flag_sensitive_ports_and_short_lived_bursts() {
        let mut events = vec![ev(
            EventKind::ConnectionCompleted,
            0,
            None,
            json!({
                "foreign_addr": "10.0.0.5.22", "process_name": "nc",
                "bytes_rx": 1u64, "bytes_tx": 1u64,
            }),
        )];
        // 5 short-lived 'payload' processes: born at t, dead 2s later.
        for i in 0..5u64 {
            let pid = Some(700 + i as u32);
            events.push(ev(
                EventKind::ProcessBirth,
                10_000 + i,
                pid,
                json!({"comm": "payload"}),
            ));
            events.push(ev(
                EventKind::ProcessDeath,
                12_000 + i,
                pid,
                json!({"comm": "payload"}),
            ));
        }
        let s = summarize_capture(&events);
        let joined = s.suspicions.join("\n");
        assert!(
            joined.contains("'nc' connected to 10.0.0.5.22 — port 22 (ssh)"),
            "{joined}"
        );
        assert!(
            joined.contains("burst of short-lived processes: 5 'payload'"),
            "{joined}"
        );
    }

    #[test]
    fn novelty_from_report_renders_strings_and_respects_cold_baseline() {
        let report = aw_store::NoveltyReport {
            new_processes: vec![aw_store::NewProcessIdentity {
                comm: Some("miner".into()),
                exec_path: Some("/tmp/miner".into()),
                first_seen_unix_ns: 1,
                instances: 3,
            }],
            new_domains: vec!["evil.example".into()],
            new_endpoints: vec![aw_store::NewEndpoint {
                foreign_addr: "6.6.6.6.443".into(),
                example_process: Some("miner".into()),
                first_seen_unix_ns: 1,
                socket_count: 1,
            }],
            new_apps: vec![aw_store::NewApp {
                id: "com.x.y".into(),
                name: Some("Y".into()),
            }],
            oldest_first_seen_unix_ns: Some(0),
        };
        let nv = NoveltySummary::from_report(&report, false);
        assert_eq!(nv.new_processes, vec!["miner (/tmp/miner) — 3 runs"]);
        assert_eq!(nv.new_endpoints, vec!["6.6.6.6.443 (via miner)"]);
        assert_eq!(nv.new_apps, vec!["Y [com.x.y]"]);
        assert!(nv.has_novelty());

        let cold = NoveltySummary::from_report(&report, true);
        assert!(cold.baseline_cold);
        assert!(!cold.has_novelty(), "cold baseline must suppress the lists");
    }

    #[tokio::test]
    async fn prompt_leads_with_anomaly_flags_and_novelty() {
        let mock = Arc::new(MockClient::new(vec!["Something new appeared."]));
        let agent = TimelineNarrator::new(AgentCtx::new(mock.clone(), AgentConfig::default()));

        let mut summary = summarize_capture(&[ev(
            EventKind::AppFocus,
            0,
            None,
            json!({"to_name": "Code", "to_bundle_id": "com.microsoft.VSCode"}),
        )]);
        summary.novelty = Some(NoveltySummary {
            baseline_cold: false,
            new_processes: vec!["miner (/tmp/miner)".into()],
            new_domains: vec![],
            new_endpoints: vec![],
            new_apps: vec![],
        });
        summary.suspicions.push(
            "root process 'rooted' (pid 200, /tmp/rooted) is running under a non-root user parent"
                .into(),
        );

        let _ = agent.run_summary(summary).await.unwrap();
        let prompt = &mock.calls()[0].prompt;
        assert!(prompt.contains("ANOMALY FLAGS"), "prompt: {prompt}");
        assert!(prompt.contains("root process 'rooted'"), "prompt: {prompt}");
        assert!(
            prompt.contains("NEVER SEEN BEFORE ON THIS MACHINE"),
            "prompt: {prompt}"
        );
        assert!(
            prompt.contains("new process: miner (/tmp/miner)"),
            "prompt: {prompt}"
        );
        assert!(
            prompt.contains("Lead with the most significant anomaly"),
            "prompt: {prompt}"
        );
        // Anomalies must come before routine activity in the prompt.
        let flags_at = prompt.find("ANOMALY FLAGS").unwrap();
        let focus_at = prompt.find("APP FOCUS").unwrap();
        assert!(flags_at < focus_at, "flags should precede focus: {prompt}");
    }

    #[tokio::test]
    async fn prompt_reports_cold_baseline_instead_of_novelty_claims() {
        let mock = Arc::new(MockClient::new(vec!["Baseline warming up."]));
        let agent = TimelineNarrator::new(AgentCtx::new(mock.clone(), AgentConfig::default()));
        let mut summary =
            summarize_capture(&[ev(EventKind::ProcessBirth, 0, None, json!({"comm": "git"}))]);
        summary.novelty = Some(NoveltySummary {
            baseline_cold: true,
            ..Default::default()
        });
        let _ = agent.run_summary(summary).await.unwrap();
        let prompt = &mock.calls()[0].prompt;
        assert!(
            prompt.contains("baseline still warming up"),
            "prompt: {prompt}"
        );
        assert!(!prompt.contains("NEVER SEEN BEFORE"), "prompt: {prompt}");
    }

    #[tokio::test]
    async fn empty_events_still_produces_a_prompt_and_does_not_panic() {
        let mock = Arc::new(MockClient::new(vec!["Nothing happened."]));
        let agent = TimelineNarrator::new(AgentCtx::new(mock.clone(), AgentConfig::default()));
        let report = agent.run(&[]).await.unwrap();
        assert_eq!(report.summary, "Nothing happened.");
        assert_eq!(
            report.details.get("events_total").and_then(|v| v.as_u64()),
            Some(0)
        );
    }
}
