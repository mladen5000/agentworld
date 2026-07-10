//! Endpoint Security (ES) syscall stream via `eslogger`.
//!
//! Apple's `eslogger(1)` is a first-party CLI wrapping the Endpoint Security
//! framework. It's pre-signed with the necessary entitlement, so we don't need
//! one of our own. The only requirement is **root** — we invoke it as
//! `sudo -n eslogger <event>...` and stream its newline-delimited JSON to the
//! observation bus.
//!
//! Behavior: `Stream` — `eslogger` emits records as syscalls happen.
//!
//! Layer 1 contract:
//! - default subscribed events are process-flow signals (`exec`, `fork`,
//!   `exit`). Each observation is tagged `Source::Process`; the `pid` is the
//!   acting process's audit-token pid. ES events for filesystem/network would
//!   need separate adapters that tag the right `Source` — out of scope here.
//! - payload is the structured ES JSON record, passed through as-is (`payload`
//!   is `serde_json::Value`, never a raw string). One ES record → one
//!   observation. No coalescing or filtering — Layer 2's job.
//! - `eslogger` failure modes: missing sudo / not root / not installed → log
//!   one warning and park. The scheduler stays healthy; other adapters keep
//!   producing data.
//! - if the child dies, we log and exit the run loop. The scheduler will not
//!   automatically restart it (avoids tight respawn loops on permission errors).

use std::process::Stdio;
use std::sync::Arc;

use aw_core::{Bus, MonotonicClock, Observation, Source, SourceAdapter, SourceBehavior};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;

#[derive(Debug, Clone)]
pub struct EsLoggerConfig {
    pub events: Vec<String>,
    /// Prepend `sudo -n` to the command. The user must have cached creds or a
    /// NOPASSWD rule for `eslogger`. With `sudo: false`, we run `eslogger`
    /// directly — useful when the binary is already privileged or under a
    /// different escalation mechanism.
    pub use_sudo: bool,
}

impl Default for EsLoggerConfig {
    fn default() -> Self {
        Self {
            events: vec!["exec".into(), "fork".into(), "exit".into()],
            use_sudo: true,
        }
    }
}

pub struct EsLoggerAdapter {
    config: EsLoggerConfig,
}

impl EsLoggerAdapter {
    pub fn new() -> Self {
        Self::with_config(EsLoggerConfig::default())
    }
    pub fn with_config(config: EsLoggerConfig) -> Self {
        Self { config }
    }
}

impl Default for EsLoggerAdapter {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl SourceAdapter for EsLoggerAdapter {
    fn source(&self) -> Source {
        Source::Process
    }
    fn behavior(&self) -> SourceBehavior {
        SourceBehavior::Stream
    }

    async fn run_stream(&self, clock: Arc<MonotonicClock>, bus: Bus) {
        let mut cmd = if self.config.use_sudo {
            let mut c = Command::new("sudo");
            c.arg("-n").arg("eslogger");
            c
        } else {
            Command::new("eslogger")
        };
        for evt in &self.config.events {
            cmd.arg(evt);
        }
        cmd.stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .stdin(Stdio::null());

        let mut child = match cmd.spawn() {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(
                    "aw-eslogger: failed to spawn eslogger ({e}); adapter inert. \
                    Hint: install eslogger? cache sudo creds? (`sudo -v` then restart aw-observe)"
                );
                std::future::pending::<()>().await;
                unreachable!();
            }
        };

        let stdout = match child.stdout.take() {
            Some(s) => s,
            None => {
                tracing::warn!("aw-eslogger: child has no stdout; adapter inert");
                let _ = child.kill().await;
                std::future::pending::<()>().await;
                unreachable!();
            }
        };

        // Drain stderr concurrently so a sudo prompt or permission error
        // surfaces as a single warning instead of silently filling the pipe.
        if let Some(stderr) = child.stderr.take() {
            tokio::spawn(async move {
                let mut lines = BufReader::new(stderr).lines();
                while let Ok(Some(line)) = lines.next_line().await {
                    if !line.trim().is_empty() {
                        tracing::warn!("aw-eslogger stderr: {line}");
                    }
                }
            });
        }

        let mut lines = BufReader::new(stdout).lines();
        loop {
            match lines.next_line().await {
                Ok(Some(line)) => {
                    if let Some(obs) = parse_line(&line, &clock) {
                        bus.emit(obs);
                    }
                }
                Ok(None) => {
                    tracing::warn!("aw-eslogger: eslogger child exited");
                    break;
                }
                Err(e) => {
                    tracing::warn!("aw-eslogger: read error: {e}");
                    break;
                }
            }
        }
        let _ = child.kill().await;
    }
}

fn parse_line(line: &str, clock: &MonotonicClock) -> Option<Observation> {
    if line.trim().is_empty() {
        return None;
    }
    let value: serde_json::Value = serde_json::from_str(line).ok()?;
    let pid = extract_pid(&value);
    Some(Observation {
        timestamp: clock.now(),
        source: Source::Process,
        pid,
        payload: value,
        tags: None,
    })
}

/// ES records contain an `audit_token` under `process` (and a different one
/// under `event.<verb>.target` for exec). The most stable acting-pid is
/// `process.audit_token.pid`.
fn extract_pid(v: &serde_json::Value) -> Option<u32> {
    v.get("process")?
        .get("audit_token")?
        .get("pid")?
        .as_u64()
        .and_then(|n| u32::try_from(n).ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_EXEC: &str = r#"{"event":{"exec":{"image_cputype":16777228,"target":{"audit_token":{"pid":43273}}}},"event_type":9,"action_type":1,"process":{"audit_token":{"pid":43273,"ppid":21417},"executable":{"path":"/bin/ls"}},"time":"2026-05-11T20:41:26Z","schema_version":1,"version":10}"#;

    const SAMPLE_FORK: &str = r#"{"event":{"fork":{}},"event_type":2,"process":{"audit_token":{"pid":1000}},"time":"2026-05-11T20:41:26Z"}"#;

    #[test]
    fn parse_extracts_pid_from_audit_token() {
        let clock = MonotonicClock::new();
        let obs = parse_line(SAMPLE_EXEC, &clock).expect("parses");
        assert_eq!(obs.pid, Some(43273));
        assert_eq!(obs.source, Source::Process);
    }

    #[test]
    fn parse_preserves_full_record_in_payload() {
        let clock = MonotonicClock::new();
        let obs = parse_line(SAMPLE_FORK, &clock).expect("parses");
        // Full payload echoes the input fields.
        assert!(obs
            .payload
            .get("event")
            .and_then(|v| v.get("fork"))
            .is_some());
        assert_eq!(obs.pid, Some(1000));
    }

    #[test]
    fn parse_empty_returns_none() {
        let clock = MonotonicClock::new();
        assert!(parse_line("", &clock).is_none());
        assert!(parse_line("   ", &clock).is_none());
    }

    #[test]
    fn parse_invalid_json_returns_none() {
        let clock = MonotonicClock::new();
        assert!(parse_line("not json", &clock).is_none());
    }

    #[test]
    fn pid_missing_when_audit_token_absent() {
        let clock = MonotonicClock::new();
        let obs = parse_line(r#"{"event":{"exit":{}}}"#, &clock).expect("parses");
        assert_eq!(obs.pid, None);
    }
}
