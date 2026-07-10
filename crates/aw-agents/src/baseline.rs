//! Statistical baselining and anomaly scoring (apps layer).
//!
//! Builds per-machine baselines from the persistent store's event history —
//! per-entity hourly activity distributions, EWMA typical rates, and
//! hour-of-day frequency profiles — and scores a live window of Layer 2
//! events against them. This replaces the fixed rule thresholds (burst ≥ 5,
//! DNS fan-out ≥ 50, prolific parent ≥ 8) with adaptive per-machine p99s
//! once enough history exists; on a cold store (< [`MIN_BASELINE_DAYS`] days
//! of history) the legacy constants apply verbatim.
//!
//! Scoring stays in the apps layer by design: Layers 1–4 only supply
//! mechanical counts (`Store::event_field_window_counts`,
//! `Store::event_hourly_profile`, `Store::edge_rates`); every judgment about
//! what is "unusual" happens here.

use std::collections::{BTreeMap, HashMap};

use aw_events::{Event, EventKind};
use serde::{Deserialize, Serialize};

/// Legacy fixed thresholds, used verbatim while the baseline is cold.
const LEGACY_SHORT_LIVED_BURST_MIN: f64 = 5.0;
const LEGACY_HEAVY_DNS_QUERIES: f64 = 50.0;
const LEGACY_PROLIFIC_PARENT: f64 = 8.0;

/// Remote-access / commonly-abused ports. A categorical prior, not learnable
/// from history — connecting to one contributes a fixed score component.
const SENSITIVE_PORTS: &[(u16, &str)] = &[
    (22, "ssh"),
    (23, "telnet"),
    (3389, "rdp"),
    (5900, "vnc"),
    (4444, "common reverse-shell port"),
];
const SENSITIVE_PORT_SCORE: f64 = 5.0;

/// A process that lived less than this counts as short-lived (matches the
/// narrator's rule flag).
const SHORT_LIVED_MAX_SECS: u64 = 10;

/// History shorter than this is a cold baseline: per-machine percentiles are
/// not yet meaningful and the legacy constants are used instead.
const MIN_BASELINE_DAYS: f64 = 3.0;

/// Historical lookback bucket width for per-entity counts.
const HOUR_NS: i64 = 3_600_000_000_000;

/// Exponentially weighted running mean/variance. `alpha` is the weight of
/// each new sample.
#[derive(Debug, Clone)]
pub struct Ewma {
    pub mean: f64,
    pub var: f64,
    alpha: f64,
    primed: bool,
}

impl Ewma {
    pub fn new(alpha: f64) -> Self {
        Self {
            mean: 0.0,
            var: 0.0,
            alpha,
            primed: false,
        }
    }

    pub fn update(&mut self, x: f64) {
        if !self.primed {
            self.mean = x;
            self.var = 0.0;
            self.primed = true;
            return;
        }
        let d = x - self.mean;
        self.mean += self.alpha * d;
        self.var = (1.0 - self.alpha) * (self.var + self.alpha * d * d);
    }

    /// Standard score of `x` against the running estimate. A zero-variance
    /// baseline uses 1.0 as the deviation floor so a first spike still
    /// registers proportionally.
    pub fn z(&self, x: f64) -> f64 {
        let sd = self.var.sqrt().max(1.0);
        (x - self.mean) / sd
    }
}

/// Hour-of-day (UTC) activity profile for one event kind.
#[derive(Debug, Clone, Default)]
pub struct HourProfile {
    pub counts: [f64; 24],
}

impl HourProfile {
    /// How unusual activity at `hour` is for this profile, in `[0, 1]`:
    /// 0 at the busiest hour, approaching 1 at hours that never see
    /// activity. An empty profile is neutral (0).
    pub fn rarity(&self, hour: usize) -> f64 {
        let max = self.counts.iter().cloned().fold(0.0_f64, f64::max);
        if max <= 0.0 {
            return 0.0;
        }
        1.0 - (self.counts[hour % 24] / max)
    }
}

/// One scored anomaly in a window.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnomalyScore {
    /// What is being scored, e.g. `process:osascript`, `dns_client:Chrome`,
    /// `endpoint:1.2.3.4.4444`, `parent:723`.
    pub entity: String,
    /// Which metric fired: `spawn_burst`, `dns_fanout`, `prolific_parent`,
    /// `sensitive_port`.
    pub metric: &'static str,
    pub observed: f64,
    /// The per-machine threshold the observation was compared against (the
    /// legacy constant while the baseline is cold).
    pub baseline_p99: f64,
    /// Higher = more anomalous. Comparable across metrics.
    pub score: f64,
    /// Human-readable line, prompt-ready.
    pub text: String,
}

/// Per-entity baseline thresholds for one metric: p99 of historical hourly
/// counts blended with an EWMA-derived ceiling.
#[derive(Debug, Clone, Default)]
struct MetricBaseline {
    per_entity: HashMap<String, f64>,
    /// Threshold for entities with no history of their own: the p99 across
    /// all entities' thresholds.
    default: f64,
}

impl MetricBaseline {
    fn threshold(&self, entity: &str, legacy: f64, cold: bool) -> f64 {
        if cold {
            return legacy;
        }
        self.per_entity
            .get(entity)
            .copied()
            .unwrap_or(if self.default > 0.0 {
                self.default
            } else {
                legacy
            })
    }
}

/// Baselines built once from store history, then applied to live windows.
pub struct BaselineEngine {
    cold: bool,
    death_bursts: MetricBaseline,
    dns_queries: MetricBaseline,
    prolific_children: MetricBaseline,
    hour_profiles: HashMap<String, HourProfile>,
}

impl BaselineEngine {
    /// Build from the last `lookback_days` of store history. Cheap enough to
    /// rebuild hourly (a handful of indexed aggregate queries).
    pub fn from_store(
        store: &aw_store::Store,
        now_unix_ns: i64,
        lookback_days: u32,
    ) -> aw_store::Result<Self> {
        let from = now_unix_ns.saturating_sub(i64::from(lookback_days) * 24 * HOUR_NS);

        let death_rows =
            store.event_field_window_counts(EventKind::ProcessDeath, "comm", from, HOUR_NS)?;
        let dns_rows = store.event_field_window_counts(
            EventKind::DnsQuery,
            "client_process_name",
            from,
            HOUR_NS,
        )?;

        // Observed history span: node lifetimes or event history, whichever
        // is longer (a collector-only store may have events long before its
        // node span, and vice versa).
        let summary = store.summary()?;
        let node_span = match (summary.first_seen_unix_ns, summary.last_seen_unix_ns) {
            (Some(a), Some(b)) if b > a => b - a,
            _ => 0,
        };
        let event_span = death_rows
            .iter()
            .chain(dns_rows.iter())
            .map(|r| r.window_start_unix_ns)
            .fold(None::<(i64, i64)>, |acc, w| match acc {
                None => Some((w, w)),
                Some((lo, hi)) => Some((lo.min(w), hi.max(w))),
            })
            .map(|(lo, hi)| hi - lo + HOUR_NS)
            .unwrap_or(0);
        let span_days = node_span.max(event_span) as f64 / (24.0 * HOUR_NS as f64);
        let cold = span_days < MIN_BASELINE_DAYS;

        let death_bursts = metric_baseline(death_rows);
        let dns_queries = metric_baseline(dns_rows);

        // Prolific parents: lifetime children per parent from parent_of edge
        // tallies. One edge row per distinct child, so per-parent row count
        // is the child count.
        let mut children_per_parent: HashMap<String, f64> = HashMap::new();
        for e in store.edge_rates("parent_of")? {
            *children_per_parent.entry(e.from_id).or_insert(0.0) += 1.0;
        }
        let mut prolific_children = MetricBaseline::default();
        let all: Vec<f64> = children_per_parent.values().copied().collect();
        prolific_children.default = percentile(&all, 0.99);
        prolific_children.per_entity = children_per_parent;

        let mut hour_profiles: HashMap<String, HourProfile> = HashMap::new();
        for row in store.event_hourly_profile(from)? {
            hour_profiles.entry(row.kind).or_default().counts[row.hour_of_day as usize % 24] +=
                row.count as f64;
        }

        Ok(Self {
            cold,
            death_bursts,
            dns_queries,
            prolific_children,
            hour_profiles,
        })
    }

    /// True when the store history is too short for per-machine percentiles;
    /// scoring then falls back to the legacy fixed thresholds.
    pub fn is_cold(&self) -> bool {
        self.cold
    }

    /// Score a live window of events against the baselines. Returns
    /// anomalies sorted by descending score.
    pub fn score_window(&self, events: &[Event], _now_unix_ns: i64) -> Vec<AnomalyScore> {
        let mut out = Vec::new();

        // --- short-lived process bursts, per comm --------------------------
        let mut births: HashMap<u32, u64> = HashMap::new();
        for ev in events.iter().filter(|e| e.kind == EventKind::ProcessBirth) {
            if let Some(pid) = ev.pid {
                births.insert(pid, ev.timestamp.mono_ns);
            }
        }
        let mut short_lived: BTreeMap<String, f64> = BTreeMap::new();
        let mut last_hour: HashMap<String, usize> = HashMap::new();
        for ev in events.iter().filter(|e| e.kind == EventKind::ProcessDeath) {
            let Some(pid) = ev.pid else { continue };
            let Some(&born) = births.get(&pid) else {
                continue;
            };
            if ev.timestamp.mono_ns.saturating_sub(born) >= SHORT_LIVED_MAX_SECS * 1_000_000_000 {
                continue;
            }
            let comm = payload_str(ev, "comm").unwrap_or("?").to_string();
            last_hour.insert(comm.clone(), event_hour(ev));
            *short_lived.entry(comm).or_insert(0.0) += 1.0;
        }
        for (comm, n) in short_lived {
            let threshold =
                self.death_bursts
                    .threshold(&comm, LEGACY_SHORT_LIVED_BURST_MIN, self.cold);
            if n >= threshold {
                let rarity = self.kind_rarity("process_death", last_hour.get(&comm).copied());
                let score = 3.0 * n / threshold.max(1.0) + 2.0 * rarity;
                out.push(AnomalyScore {
                    entity: format!("process:{comm}"),
                    metric: "spawn_burst",
                    observed: n,
                    baseline_p99: threshold,
                    score,
                    text: format!(
                        "burst of short-lived processes: {n:.0} '{comm}' instances each \
                         started and exited within seconds (typical hourly ceiling {threshold:.0})",
                    ),
                });
            }
        }

        // --- DNS fan-out, per client ---------------------------------------
        #[derive(Default)]
        struct DnsTally {
            total: f64,
            unique: std::collections::HashSet<String>,
            hour: usize,
        }
        let mut dns: HashMap<String, DnsTally> = HashMap::new();
        for ev in events.iter().filter(|e| e.kind == EventKind::DnsQuery) {
            let client = payload_str(ev, "client_process_name").unwrap_or("?");
            let t = dns.entry(client.to_string()).or_default();
            t.total += 1.0;
            t.hour = event_hour(ev);
            if let Some(h) = payload_str(ev, "name_hash") {
                t.unique.insert(h.to_string());
            }
        }
        for (client, t) in dns {
            let threshold =
                self.dns_queries
                    .threshold(&client, LEGACY_HEAVY_DNS_QUERIES, self.cold);
            if t.total >= threshold {
                let rarity = self.kind_rarity("dns_query", Some(t.hour));
                let score = 3.0 * t.total / threshold.max(1.0) + 2.0 * rarity;
                out.push(AnomalyScore {
                    entity: format!("dns_client:{client}"),
                    metric: "dns_fanout",
                    observed: t.total,
                    baseline_p99: threshold,
                    score,
                    text: format!(
                        "'{client}' issued {:.0} DNS queries ({} unique names) in this window \
                         — typical hourly ceiling {threshold:.0}",
                        t.total,
                        t.unique.len(),
                    ),
                });
            }
        }

        // --- prolific parents, per ppid ------------------------------------
        let mut children: HashMap<u32, (f64, usize)> = HashMap::new();
        for ev in events.iter().filter(|e| e.kind == EventKind::ProcessBirth) {
            if let Some(ppid) = ev.payload.get("ppid").and_then(|v| v.as_u64()) {
                let entry = children.entry(ppid as u32).or_insert((0.0, 0));
                entry.0 += 1.0;
                entry.1 = event_hour(ev);
            }
        }
        for (ppid, (n, hour)) in children {
            // Per-instance parent ids in the store are pid:start keys we
            // can't reconstruct here, so live windows compare against the
            // cross-parent default percentile.
            let threshold = if self.cold || self.prolific_children.default <= 0.0 {
                LEGACY_PROLIFIC_PARENT
            } else {
                self.prolific_children.default
            };
            if n >= threshold {
                let rarity = self.kind_rarity("process_birth", Some(hour));
                let score = 3.0 * n / threshold.max(1.0) + 2.0 * rarity;
                out.push(AnomalyScore {
                    entity: format!("parent:{ppid}"),
                    metric: "prolific_parent",
                    observed: n,
                    baseline_p99: threshold,
                    score,
                    text: format!(
                        "parent pid {ppid} spawned {n:.0} children in this window \
                         (machine p99 {threshold:.0})",
                    ),
                });
            }
        }

        // --- sensitive ports (categorical prior) ---------------------------
        let mut seen: std::collections::HashSet<(String, String)> = Default::default();
        for ev in events.iter().filter(|e| {
            matches!(
                e.kind,
                EventKind::ConnectionOpened | EventKind::ConnectionCompleted
            )
        }) {
            let Some(foreign) = payload_str(ev, "foreign_addr") else {
                continue;
            };
            let Some(port) = foreign_port(foreign) else {
                continue;
            };
            let Some((_, label)) = SENSITIVE_PORTS.iter().find(|(p, _)| *p == port) else {
                continue;
            };
            let proc = payload_str(ev, "process_name").unwrap_or("?");
            if !seen.insert((proc.to_string(), foreign.to_string())) {
                continue;
            }
            let rarity = self.kind_rarity("connection_opened", Some(event_hour(ev)));
            out.push(AnomalyScore {
                entity: format!("endpoint:{foreign}"),
                metric: "sensitive_port",
                observed: f64::from(port),
                baseline_p99: 0.0,
                score: SENSITIVE_PORT_SCORE + 2.0 * rarity,
                text: format!("'{proc}' connected to {foreign} — port {port} ({label})"),
            });
        }

        out.sort_by(|a, b| b.score.total_cmp(&a.score));
        out
    }

    fn kind_rarity(&self, kind: &str, hour: Option<usize>) -> f64 {
        match (self.hour_profiles.get(kind), hour) {
            (Some(p), Some(h)) if !self.cold => p.rarity(h),
            _ => 0.0,
        }
    }
}

/// Fold per-entity windowed counts into per-entity thresholds:
/// `max(p99 of hourly counts, EWMA mean + 3σ)`, with the cross-entity p99 of
/// those thresholds as the default for unseen entities.
fn metric_baseline(rows: Vec<aw_store::FieldWindowCount>) -> MetricBaseline {
    let mut per_entity_counts: HashMap<String, Vec<f64>> = HashMap::new();
    for r in rows {
        per_entity_counts
            .entry(r.value)
            .or_default()
            .push(r.count as f64);
    }
    let mut per_entity: HashMap<String, f64> = HashMap::new();
    for (entity, counts) in per_entity_counts {
        let p99 = percentile(&counts, 0.99);
        let mut ewma = Ewma::new(0.3);
        for &c in &counts {
            ewma.update(c);
        }
        let ceiling = ewma.mean + 3.0 * ewma.var.sqrt().max(1.0);
        per_entity.insert(entity, p99.max(ceiling));
    }
    let all: Vec<f64> = per_entity.values().copied().collect();
    MetricBaseline {
        default: percentile(&all, 0.99),
        per_entity,
    }
}

/// Nearest-rank percentile; 0.0 for an empty slice.
fn percentile(values: &[f64], p: f64) -> f64 {
    if values.is_empty() {
        return 0.0;
    }
    let mut v: Vec<f64> = values.to_vec();
    v.sort_by(|a, b| a.total_cmp(b));
    let rank = ((p * v.len() as f64).ceil() as usize).clamp(1, v.len());
    v[rank - 1]
}

fn payload_str<'a>(ev: &'a Event, key: &str) -> Option<&'a str> {
    ev.payload.get(key).and_then(|v| v.as_str())
}

/// UTC hour-of-day of an event's wall-clock timestamp.
fn event_hour(ev: &Event) -> usize {
    let unix_ns = ev
        .timestamp
        .wall_anchor_ns
        .saturating_add(ev.timestamp.mono_ns);
    ((unix_ns / HOUR_NS as u64) % 24) as usize
}

/// Extract the destination port from a nettop-style foreign address
/// (`1.2.3.4.443`). Only claims a port when the prefix parses as an IP.
fn foreign_port(addr: &str) -> Option<u16> {
    let (host, port) = addr.rsplit_once('.')?;
    let port: u16 = port.parse().ok()?;
    host.parse::<std::net::IpAddr>().ok().map(|_| port)
}

#[cfg(test)]
mod tests {
    use super::*;
    use aw_core::Timestamp;
    use aw_events::SCHEMA_VERSION;

    const DAY_NS: i64 = 24 * HOUR_NS;

    fn store_event(
        unix_ns: i64,
        kind: EventKind,
        pid: Option<u32>,
        payload: serde_json::Value,
    ) -> Event {
        Event {
            schema_version: SCHEMA_VERSION,
            timestamp: Timestamp {
                mono_ns: unix_ns as u64,
                wall_anchor_ns: 0,
            },
            kind,
            pid,
            payload,
        }
    }

    fn window_event(
        unix_ns: i64,
        kind: EventKind,
        pid: Option<u32>,
        payload: serde_json::Value,
    ) -> Event {
        Event {
            schema_version: SCHEMA_VERSION,
            timestamp: Timestamp {
                mono_ns: 0,
                wall_anchor_ns: unix_ns as u64,
            },
            kind,
            pid,
            payload,
        }
    }

    fn dns(name_hash: &str) -> serde_json::Value {
        serde_json::json!({ "client_process_name": "chrome", "name_hash": name_hash })
    }

    /// Seed ~5 days of routine DNS load (2 queries/hour for chrome) so the
    /// baseline is warm and chrome's hourly ceiling is small.
    fn warm_store() -> aw_store::Store {
        let mut s = aw_store::Store::open_in_memory().unwrap();
        let mut evs = Vec::new();
        for day in 0..5i64 {
            for hour in 0..24i64 {
                let base = day * DAY_NS + hour * HOUR_NS;
                for q in 0..2i64 {
                    evs.push(store_event(
                        base + q * 1_000_000,
                        EventKind::DnsQuery,
                        None,
                        dns(&format!("h{day}-{hour}-{q}")),
                    ));
                }
            }
        }
        s.append_events(&evs).unwrap();
        s
    }

    #[test]
    fn ewma_tracks_mean_and_flags_spikes() {
        let mut e = Ewma::new(0.3);
        for _ in 0..20 {
            e.update(10.0);
        }
        assert!((e.mean - 10.0).abs() < 1e-6);
        assert!(e.z(10.0).abs() < 0.5);
        assert!(e.z(100.0) > 3.0);
    }

    #[test]
    fn percentile_nearest_rank() {
        let v: Vec<f64> = (1..=100).map(f64::from).collect();
        assert_eq!(percentile(&v, 0.99), 99.0);
        assert_eq!(percentile(&v, 1.0), 100.0);
        assert_eq!(percentile(&[], 0.99), 0.0);
    }

    #[test]
    fn hour_profile_rarity() {
        let mut p = HourProfile::default();
        p.counts[9] = 100.0;
        p.counts[3] = 1.0;
        assert!(p.rarity(9) < 0.01);
        assert!(p.rarity(3) > 0.9);
        assert!((HourProfile::default().rarity(5) - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn warm_baseline_flags_spike_but_not_routine_load() {
        let store = warm_store();
        let now = 5 * DAY_NS;
        let engine = BaselineEngine::from_store(&store, now, 30).unwrap();
        assert!(!engine.is_cold());

        // Routine: 2 chrome queries — an order of magnitude under any ceiling.
        let routine: Vec<Event> = (0..2)
            .map(|i| window_event(now + i, EventKind::DnsQuery, None, dns(&format!("r{i}"))))
            .collect();
        assert!(
            engine.score_window(&routine, now).is_empty(),
            "routine load must not be flagged"
        );

        // Spike: 40 queries in one window vs a ~2/hour baseline (well under
        // the legacy 50, so only an adaptive threshold catches it).
        let spike: Vec<Event> = (0..40)
            .map(|i| window_event(now + i, EventKind::DnsQuery, None, dns(&format!("s{i}"))))
            .collect();
        let scores = engine.score_window(&spike, now);
        let hit = scores
            .iter()
            .find(|a| a.metric == "dns_fanout")
            .expect("10x spike must be flagged on a warm baseline");
        assert!(hit.score > 0.0);
        assert!(hit.entity.contains("chrome"));
        assert!(hit.baseline_p99 < 40.0);
    }

    #[test]
    fn cold_baseline_falls_back_to_legacy_constants() {
        // A store with a few minutes of history: cold.
        let mut s = aw_store::Store::open_in_memory().unwrap();
        s.append_events(&[store_event(0, EventKind::DnsQuery, None, dns("x"))])
            .unwrap();
        let engine = BaselineEngine::from_store(&s, HOUR_NS, 30).unwrap();
        assert!(engine.is_cold());

        // 40 queries: over any warm adaptive ceiling but under the legacy 50
        // — must NOT flag while cold.
        let forty: Vec<Event> = (0..40)
            .map(|i| window_event(i, EventKind::DnsQuery, None, dns(&format!("a{i}"))))
            .collect();
        assert!(engine
            .score_window(&forty, HOUR_NS)
            .iter()
            .all(|a| a.metric != "dns_fanout"));

        // 60 queries: over the legacy 50 — must flag even while cold.
        let sixty: Vec<Event> = (0..60)
            .map(|i| window_event(i, EventKind::DnsQuery, None, dns(&format!("b{i}"))))
            .collect();
        let scores = engine.score_window(&sixty, HOUR_NS);
        let hit = scores.iter().find(|a| a.metric == "dns_fanout").unwrap();
        assert_eq!(hit.baseline_p99, LEGACY_HEAVY_DNS_QUERIES);
    }

    #[test]
    fn sensitive_port_is_scored_regardless_of_baseline() {
        let mut s = aw_store::Store::open_in_memory().unwrap();
        s.append_events(&[store_event(0, EventKind::DnsQuery, None, dns("x"))])
            .unwrap();
        let engine = BaselineEngine::from_store(&s, HOUR_NS, 30).unwrap();

        let ev = window_event(
            1,
            EventKind::ConnectionOpened,
            Some(9),
            serde_json::json!({ "foreign_addr": "1.2.3.4.4444", "process_name": "nc" }),
        );
        let scores = engine.score_window(&[ev], HOUR_NS);
        assert_eq!(scores.len(), 1);
        assert_eq!(scores[0].metric, "sensitive_port");
        assert!(scores[0].score >= SENSITIVE_PORT_SCORE);
        assert!(scores[0].text.contains("reverse-shell"));
    }
}
