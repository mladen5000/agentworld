//! Network adapter — socket snapshot (§4.3 NETWORK SOURCES, §5.2).
//!
//! Behavior: `Snapshot`. On each tick, runs `netstat -n -v` for tcp and udp,
//! parses the per-socket table, and emits one `Observation` per row.
//!
//! Why `netstat -n -v`: it is bundled with macOS, requires no entitlements,
//! and uniquely surfaces the owning **process:pid** for each socket — which
//! is precisely the entity attachment Layer 1 needs (§4.2). PF/NEFilter are
//! richer but need an extension and root.
//!
//! Layer 1 contract reminders enforced here:
//! - timestamps anchored to `MonotonicClock`, not to any field in netstat output.
//! - pid is `None` only if absent in the row (never inferred).
//! - payload is structured (not the raw line) — flag bitfields are pass-through hex
//!   strings; downstream layers can interpret. We do *not* decode them in Layer 1.
//! - no aggregation, dedup, or filtering — one row in, one observation out.

use std::sync::Arc;

use aw_core::{Bus, MonotonicClock, Observation, Source, SourceAdapter, SourceBehavior};

pub struct NetworkAdapter;

impl NetworkAdapter {
    pub fn new() -> Self {
        Self
    }
}

impl Default for NetworkAdapter {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl SourceAdapter for NetworkAdapter {
    fn source(&self) -> Source {
        Source::Network
    }
    fn behavior(&self) -> SourceBehavior {
        SourceBehavior::Snapshot
    }

    async fn poll_snapshot(&self, clock: Arc<MonotonicClock>, bus: Bus) {
        for proto in ["tcp", "udp"] {
            match run_netstat(proto).await {
                Ok(output) => {
                    for row in parse_netstat(&output) {
                        bus.emit(row_to_observation(row, &clock));
                    }
                }
                Err(e) => {
                    tracing::warn!("netstat -p {proto} failed: {e}");
                }
            }
        }
    }
}

async fn run_netstat(proto: &str) -> std::io::Result<String> {
    let out = tokio::process::Command::new("netstat")
        .args(["-n", "-v", "-p", proto])
        .output()
        .await?;
    if !out.status.success() {
        return Err(std::io::Error::other(format!(
            "netstat exited {}: {}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        )));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NetstatRow<'a> {
    pub proto: &'a str,
    pub local_addr: String,
    pub foreign_addr: String,
    pub state: Option<&'a str>,
    pub rxbytes: Option<u64>,
    pub txbytes: Option<u64>,
    pub process_name: String,
    pub pid: Option<u32>,
}

/// Parse the table portion of `netstat -n -v -p <proto>` output.
///
/// Token-based parser. The trailing 8 columns (`state options gencnt flags
/// flags1 usecnt rtncnt fltrs`) are stable. The `process:pid` token sits
/// immediately before them — recovered by scanning for `name…:digits`.
/// Process names may contain spaces (e.g. "Code - Insiders"), so we walk
/// leftward from the trailing anchor to find the `:digits` token and join
/// any preceding name tokens.
pub(crate) fn parse_netstat(output: &str) -> Vec<NetstatRow<'_>> {
    let mut lines = output.lines();
    // Skip lines until past the header row.
    for line in lines.by_ref() {
        if line.starts_with("Proto") {
            break;
        }
    }
    let mut rows = Vec::new();
    for line in lines {
        if line.trim().is_empty() {
            continue;
        }
        if let Some(row) = parse_row(line) {
            rows.push(row);
        }
    }
    rows
}

const TRAILING_COLS: usize = 8; // state options gencnt flags flags1 usecnt rtncnt fltrs

fn parse_row(line: &str) -> Option<NetstatRow<'_>> {
    let toks: Vec<&str> = line.split_whitespace().collect();
    if toks.len() < TRAILING_COLS + 6 {
        return None;
    }
    let proto = toks[0];
    if !(proto.starts_with("tcp") || proto.starts_with("udp")) {
        return None;
    }

    // Locate the `name…:pid` token. It is the rightmost token whose tail is
    // `:<digits>` and whose index is to the left of the 8 trailing columns.
    let max_proc_idx = toks.len() - TRAILING_COLS - 1;
    let mut proc_idx: Option<usize> = None;
    for i in (0..=max_proc_idx).rev() {
        if token_is_name_pid(toks[i]) {
            proc_idx = Some(i);
            break;
        }
    }
    let proc_idx = proc_idx?;
    let (process_name, pid) = split_name_pid(toks[proc_idx]);
    // Prepend any preceding non-numeric tokens that belong to the name.
    // The four columns before the process field are numeric: rxbytes txbytes rhiwat shiwat.
    // So any token at `proc_idx - 1` that is *not* a pure number is part of the name.
    let mut name_parts: Vec<&str> = Vec::new();
    let mut k = proc_idx;
    while k > 0 && !is_all_digits(toks[k - 1]) {
        k -= 1;
        name_parts.push(toks[k]);
    }
    name_parts.reverse();
    let process_name: String = if name_parts.is_empty() {
        process_name.to_string()
    } else {
        let mut s = name_parts.join(" ");
        s.push(' ');
        s.push_str(process_name);
        s
    };

    // After the merge, the four numeric tokens immediately before `k` are
    // shiwat, rhiwat, txbytes, rxbytes (reading right-to-left). Anything
    // further left up to index 3 (post-proto/recv/send/local/foreign) is the
    // optional `(state)` column.
    if k < 4 {
        return None;
    }
    let shiwat_idx = k - 1;
    let rhiwat_idx = k - 2;
    let txbytes_idx = k - 3;
    let rxbytes_idx = k - 4;
    let _ = (shiwat_idx, rhiwat_idx); // we don't surface these in payload
    let txbytes = toks[txbytes_idx].parse::<u64>().ok();
    let rxbytes = toks[rxbytes_idx].parse::<u64>().ok();

    // `(state)` is present iff there is exactly one extra token between the
    // foreign-address position (index 4) and rxbytes_idx. Proto/recv/send/local/foreign
    // are at indices 0..=4.
    let state = if rxbytes_idx == 6 {
        Some(toks[5])
    } else if rxbytes_idx == 5 {
        None
    } else {
        // Unexpected shape — leave state None and continue.
        None
    };

    let local_addr = toks[3].to_string();
    let foreign_addr = toks[4].to_string();

    Some(NetstatRow {
        proto,
        local_addr,
        foreign_addr,
        state,
        rxbytes,
        txbytes,
        process_name,
        pid,
    })
}

fn is_all_digits(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())
}

fn token_is_name_pid(tok: &str) -> bool {
    if let Some((name, pid)) = tok.rsplit_once(':') {
        !name.is_empty() && !pid.is_empty() && pid.bytes().all(|b| b.is_ascii_digit())
    } else {
        false
    }
}

fn split_name_pid(tok: &str) -> (&str, Option<u32>) {
    if let Some((name, pid)) = tok.rsplit_once(':') {
        (name, pid.parse().ok())
    } else {
        (tok, None)
    }
}

/// Used by the public `extract_process` test — accepts a chunk and returns
/// the canonical `(name, pid)` pair. Kept around so future Layer 1 tooling
/// can reuse it without going through `parse_row`.
#[cfg(test)]
fn extract_process(chunk: &str) -> (String, Option<u32>) {
    let toks: Vec<&str> = chunk.split_whitespace().collect();
    // The `:pid` token is the first token containing `:digits`.
    for (i, t) in toks.iter().enumerate() {
        if token_is_name_pid(t) {
            let (tail_name, pid) = split_name_pid(t);
            let prefix: Vec<&str> = toks[..i].to_vec();
            let name = if prefix.is_empty() {
                tail_name.to_string()
            } else {
                format!("{} {}", prefix.join(" "), tail_name)
            };
            return (name, pid);
        }
    }
    (chunk.trim().to_string(), None)
}

fn row_to_observation(row: NetstatRow<'_>, clock: &MonotonicClock) -> Observation {
    Observation {
        timestamp: clock.now(),
        source: Source::Network,
        pid: row.pid,
        payload: serde_json::json!({
            "proto": row.proto,
            "local_addr": row.local_addr,
            "foreign_addr": row.foreign_addr,
            "state": row.state,
            "rxbytes": row.rxbytes,
            "txbytes": row.txbytes,
            "process_name": row.process_name,
        }),
        tags: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "\
Active Internet connections
Proto Recv-Q Send-Q  Local Address                                 Foreign Address                               (state)          rxbytes      txbytes  rhiwat  shiwat          process:pid    state  options           gencnt    flags   flags1 usecnt rtncnt fltrs
tcp4       0      0  10.0.0.218.53005       160.79.104.10.443                       ESTABLISHED       121046      3959109  131072  320184           claude:23680  00102 00000000 0000000000073738 20000081 04000900      3      0 000004
tcp4       0      0  10.0.0.218.53107       23.216.5.151.443                        ESTABLISHED       157106582        2016 4194240  131712  Code - Insiders:661    00102 00020000 0000000000077161 00180081 040c0900      2      0 000000
udp4       0      0  10.0.0.218.63657       160.79.104.10.443                                         2415188       588764 1048576   29040    Claude Helper:94258  00102 00000000 000000000004be3e 20000000 04200900      2      0 000002
udp4       0      0  *.*                    *.*                                                            0            0  786896    9216        symptomsd:470    00000 00000000 0000000000040590 00000000 00002800      1      0 000000
";

    #[test]
    fn parses_tcp_with_state_and_pid() {
        let rows = parse_netstat(SAMPLE);
        let claude = rows
            .iter()
            .find(|r| r.pid == Some(23680))
            .expect("claude row");
        assert_eq!(claude.proto, "tcp4");
        assert_eq!(claude.local_addr, "10.0.0.218.53005");
        assert_eq!(claude.foreign_addr, "160.79.104.10.443");
        assert_eq!(claude.state, Some("ESTABLISHED"));
        assert_eq!(claude.rxbytes, Some(121046));
        assert_eq!(claude.txbytes, Some(3959109));
        assert_eq!(claude.process_name, "claude");
    }

    #[test]
    fn handles_process_name_with_spaces() {
        let rows = parse_netstat(SAMPLE);
        let vscode = rows
            .iter()
            .find(|r| r.pid == Some(661))
            .expect("vscode row");
        assert_eq!(vscode.process_name, "Code - Insiders");
        assert_eq!(vscode.proto, "tcp4");
    }

    #[test]
    fn udp_has_no_state_but_keeps_pid() {
        let rows = parse_netstat(SAMPLE);
        let helper = rows
            .iter()
            .find(|r| r.pid == Some(94258))
            .expect("helper row");
        assert_eq!(helper.proto, "udp4");
        assert_eq!(helper.state, None);
        assert_eq!(helper.process_name, "Claude Helper");
        assert_eq!(helper.rxbytes, Some(2415188));
    }

    #[test]
    fn unbound_udp_keeps_wildcards() {
        let rows = parse_netstat(SAMPLE);
        let sym = rows
            .iter()
            .find(|r| r.pid == Some(470))
            .expect("symptomsd row");
        assert_eq!(sym.local_addr, "*.*");
        assert_eq!(sym.foreign_addr, "*.*");
        assert_eq!(sym.process_name, "symptomsd");
    }

    #[test]
    fn extract_process_basic() {
        assert_eq!(extract_process("claude:23680  00102").0, "claude");
        assert_eq!(extract_process("claude:23680  00102").1, Some(23680));
        assert_eq!(
            extract_process("Code - Insiders:661 00102").0,
            "Code - Insiders"
        );
        assert_eq!(extract_process("Code - Insiders:661 00102").1, Some(661));
    }

    #[test]
    fn ignores_empty_lines() {
        let mixed = format!("{SAMPLE}\n\n");
        let rows = parse_netstat(&mixed);
        assert_eq!(rows.len(), 4);
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn live_netstat_emits_at_least_one_observation() {
        let adapter = NetworkAdapter::new();
        let clock = Arc::new(MonotonicClock::new());
        let (bus, mut rx) = Bus::channel();
        adapter.poll_snapshot(clock, bus).await;
        // We must have at least one socket on this machine (the test runner has stdout).
        // Drain the channel: must contain ≥1 Network observation.
        let mut count = 0;
        while let Ok(obs) = rx.try_recv() {
            assert_eq!(obs.source, Source::Network);
            assert!(obs.payload.get("proto").is_some());
            count += 1;
        }
        assert!(count > 0, "expected at least one socket observation; got 0");
    }
}
