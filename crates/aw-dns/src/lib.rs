//! DNS observation source — taps macOS `mDNSResponder` via the unified `log`
//! subsystem (no entitlements, no root). Spawns:
//!
//! ```text
//! log stream --style ndjson --predicate 'subsystem == "com.apple.mDNSResponder"'
//! ```
//!
//! and emits one `Observation` per `DNSServiceQueryRecord START` record. Other
//! mDNSResponder log lines (lifecycle, internal state) are skipped.
//!
//! ## Privacy
//!
//! On macOS 12+, the queried hostname is masked in logs (`<mask.hash: '...'>`)
//! unless the system has the `com.apple.system.logging.Enable-Private-Data`
//! profile installed. We always carry the *name hash* (which is sufficient to
//! correlate repeated queries to the same name across processes) and emit a
//! one-shot warning the first time we see a masked record so the operator
//! knows the deployment limitation.
//!
//! ## Source tagging
//!
//! Observations are tagged `Source::Network` — DNS is network behavior, and
//! the existing taxonomy doesn't have a dedicated DNS category. Distinguished
//! from socket observations by `payload.kind == "dns_query"`.

use std::process::Stdio;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use aw_core::{Bus, MonotonicClock, Observation, Source, SourceAdapter, SourceBehavior};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;

pub struct DnsAdapter;

impl DnsAdapter {
    pub fn new() -> Self {
        Self
    }
}

impl Default for DnsAdapter {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl SourceAdapter for DnsAdapter {
    fn source(&self) -> Source {
        Source::Network
    }
    fn behavior(&self) -> SourceBehavior {
        SourceBehavior::Stream
    }

    async fn run_stream(&self, clock: Arc<MonotonicClock>, bus: Bus) {
        // Build the command. The predicate must be passed as a single argv
        // entry; doing so via .arg() avoids any shell quoting concerns.
        let mut cmd = Command::new("log");
        cmd.arg("stream")
            .arg("--style")
            .arg("ndjson")
            .arg("--predicate")
            .arg("subsystem == \"com.apple.mDNSResponder\"")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .stdin(Stdio::null());

        let mut child = match cmd.spawn() {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!("aw-dns: failed to spawn `log stream` ({e}); adapter inert");
                std::future::pending::<()>().await;
                unreachable!();
            }
        };

        // Drain stderr concurrently so a startup error surfaces as a warning
        // instead of silently filling the pipe.
        if let Some(stderr) = child.stderr.take() {
            tokio::spawn(async move {
                let mut lines = BufReader::new(stderr).lines();
                while let Ok(Some(line)) = lines.next_line().await {
                    if !line.trim().is_empty() {
                        tracing::warn!("aw-dns stderr: {line}");
                    }
                }
            });
        }

        let stdout = match child.stdout.take() {
            Some(s) => s,
            None => {
                tracing::warn!("aw-dns: child has no stdout; adapter inert");
                let _ = child.kill().await;
                std::future::pending::<()>().await;
                unreachable!();
            }
        };

        let warned_about_masking = Arc::new(AtomicBool::new(false));
        let mut lines = BufReader::new(stdout).lines();
        loop {
            match lines.next_line().await {
                Ok(Some(line)) => {
                    if let Some(obs) = parse_line(&line, &clock, &warned_about_masking) {
                        bus.emit(obs);
                    }
                }
                Ok(None) => {
                    tracing::warn!("aw-dns: `log stream` child exited");
                    break;
                }
                Err(e) => {
                    tracing::warn!("aw-dns: stdout read error: {e}");
                    break;
                }
            }
        }
        let _ = child.kill().await;
    }
}

fn parse_line(line: &str, clock: &MonotonicClock, warned: &AtomicBool) -> Option<Observation> {
    if line.trim().is_empty() {
        return None;
    }
    let value: serde_json::Value = serde_json::from_str(line).ok()?;
    let message = value.get("eventMessage")?.as_str()?;
    // We're only interested in query-start records. mDNSResponder emits many
    // other lines (R%u->Q%u, lifecycle, etc.) which we ignore here.
    if !message.contains("DNSServiceQueryRecord START") {
        return None;
    }

    let q = extract_query(message)?;
    if q.masked && !warned.swap(true, Ordering::Relaxed) {
        tracing::warn!(
            "aw-dns: hostnames are masked (<mask.hash: ...>). To see real names, install \
             the `com.apple.system.logging.Enable-Private-Data` configuration profile."
        );
    }

    Some(Observation {
        timestamp: clock.now(),
        source: Source::Network,
        // The querying process's pid lives inside the message body, not the
        // log record's processID (that's mDNSResponder itself). We carry it
        // as the top-level pid so cross-source enrichment can attach context.
        pid: Some(q.client_pid),
        payload: serde_json::json!({
            "kind": "dns_query",
            "qname": q.qname,        // either a real domain or a "<mask.hash: 'xxx='>" string
            "qtype": q.qtype,        // "A", "AAAA", "PTR", ...
            "name_hash": q.name_hash, // hex string, stable across runs for the same name
            "interface_index": q.interface_index,
            "client_process_name": q.client_process_name,
            "masked": q.masked,
        }),
        tags: None,
    })
}

#[derive(Debug, PartialEq, Eq)]
struct Query {
    qname: String,
    qtype: String,
    name_hash: String,
    interface_index: i32,
    client_pid: u32,
    client_process_name: String,
    masked: bool,
}

/// Extract the fields from a `DNSServiceQueryRecord START` event message.
///
/// Expected format (masked):
///
/// ```text
/// [R12345] DNSServiceQueryRecord START -- qname: <mask.hash: 'abc=='>, qtype: A, flags: 0x..., interface index: 0, client pid: 17446 (gk_3_1_63), name hash: e325f5d4
/// ```
///
/// Unmasked variant:
///
/// ```text
/// ... qname: example.com., qtype: A, ...
/// ```
fn extract_query(msg: &str) -> Option<Query> {
    let qname_raw = field_between(msg, "qname: ", ", qtype:")?;
    let qtype = field_between(msg, "qtype: ", ",")?.to_string();
    let interface_index: i32 = field_between(msg, "interface index: ", ",")?.parse().ok()?;
    // "client pid: <pid> (<name>)"
    let pid_chunk = field_between(msg, "client pid: ", ",")?;
    // pid_chunk looks like "17446 (gk_3_1_63)"
    let (pid_str, rest) = pid_chunk.split_once(' ')?;
    let client_pid: u32 = pid_str.parse().ok()?;
    let client_process_name = rest
        .trim()
        .trim_start_matches('(')
        .trim_end_matches(')')
        .to_string();
    // "name hash: <hex>" runs to end of line; no trailing comma.
    let name_hash = msg
        .rsplit_once("name hash: ")
        .map(|(_, s)| s.trim().to_string())
        .unwrap_or_default();

    let masked = qname_raw.starts_with("<mask.hash");
    let qname = qname_raw.to_string();

    Some(Query {
        qname,
        qtype,
        name_hash,
        interface_index,
        client_pid,
        client_process_name,
        masked,
    })
}

/// Returns the substring strictly between `start` and `end`, both exclusive of
/// the markers. None if either marker is absent or `end` comes before `start`.
fn field_between<'a>(s: &'a str, start: &str, end: &str) -> Option<&'a str> {
    let s_i = s.find(start)? + start.len();
    let rest = &s[s_i..];
    let e_i = rest.find(end)?;
    Some(&rest[..e_i])
}

#[cfg(test)]
mod tests {
    use super::*;

    const MASKED_START_LINE: &str = r#"{"eventMessage":"[R63931] DNSServiceQueryRecord START -- qname: <mask.hash: 'JtfAKTlnkM4iYCvwbaIeXw=='>, qtype: A, flags: 0x15000, interface index: 0, client pid: 17446 (gk_3_1_63), name hash: e325f5d4"}"#;

    const UNMASKED_START_LINE: &str = r#"{"eventMessage":"[R63932] DNSServiceQueryRecord START -- qname: example.com., qtype: AAAA, flags: 0x0, interface index: 1, client pid: 99 (curl), name hash: deadbeef"}"#;

    const UNRELATED_LINE: &str =
        r#"{"eventMessage":"[R63931->Q36719] Question assigned DNS service 6"}"#;

    fn clock() -> MonotonicClock {
        MonotonicClock::new()
    }

    #[test]
    fn parses_masked_query() {
        let c = clock();
        let warned = AtomicBool::new(false);
        let obs = parse_line(MASKED_START_LINE, &c, &warned).expect("parses");
        assert_eq!(obs.source, Source::Network);
        assert_eq!(obs.pid, Some(17446));
        let p = &obs.payload;
        assert_eq!(p.get("kind").and_then(|v| v.as_str()), Some("dns_query"));
        assert_eq!(p.get("qtype").and_then(|v| v.as_str()), Some("A"));
        assert_eq!(p.get("masked").and_then(|v| v.as_bool()), Some(true));
        assert_eq!(
            p.get("name_hash").and_then(|v| v.as_str()),
            Some("e325f5d4")
        );
        assert_eq!(
            p.get("client_process_name").and_then(|v| v.as_str()),
            Some("gk_3_1_63")
        );
        assert_eq!(p.get("interface_index").and_then(|v| v.as_i64()), Some(0));
        // Warning was emitted (atomic flipped).
        assert!(warned.load(Ordering::Relaxed));
    }

    #[test]
    fn parses_unmasked_query() {
        let c = clock();
        let warned = AtomicBool::new(false);
        let obs = parse_line(UNMASKED_START_LINE, &c, &warned).expect("parses");
        let p = &obs.payload;
        assert_eq!(
            p.get("qname").and_then(|v| v.as_str()),
            Some("example.com.")
        );
        assert_eq!(p.get("qtype").and_then(|v| v.as_str()), Some("AAAA"));
        assert_eq!(p.get("masked").and_then(|v| v.as_bool()), Some(false));
        assert_eq!(
            p.get("client_process_name").and_then(|v| v.as_str()),
            Some("curl")
        );
        // No masking → no warning issued.
        assert!(!warned.load(Ordering::Relaxed));
    }

    #[test]
    fn skips_non_query_lines() {
        let c = clock();
        let warned = AtomicBool::new(false);
        assert!(parse_line(UNRELATED_LINE, &c, &warned).is_none());
    }

    #[test]
    fn skips_blank_and_garbage_lines() {
        let c = clock();
        let warned = AtomicBool::new(false);
        assert!(parse_line("", &c, &warned).is_none());
        assert!(parse_line("not json at all", &c, &warned).is_none());
        assert!(parse_line(r#"{"eventMessage":"some other message"}"#, &c, &warned).is_none());
    }

    #[test]
    fn warns_only_once_about_masking() {
        let c = clock();
        let warned = AtomicBool::new(false);
        parse_line(MASKED_START_LINE, &c, &warned).unwrap();
        assert!(warned.load(Ordering::Relaxed));
        // Second call: flag is already set; no second warning would be issued
        // (we can't easily observe `tracing::warn` here, but the atomic guard
        // is the mechanism).
        parse_line(MASKED_START_LINE, &c, &warned).unwrap();
        assert!(warned.load(Ordering::Relaxed));
    }
}
