//! Process adapter — process table snapshot via libproc (§4.3 PROCESS SOURCES, §5.2).
//!
//! Behavior: `Snapshot`. On each tick, enumerates the live PID set with
//! `proc_listpids`, then queries `proc_pidinfo` (BSDInfo flavor) and
//! `proc_pidpath` per PID. Emits one `Observation` per process.
//!
//! Layer 1 contract:
//! - `pid` is the canonical entity identifier (top-level field).
//! - payload is structured: ppid, uid, gid, comm (short name), name (longer name),
//!   exec_path, start_time (unix seconds, derived from the kernel's bsd start tv).
//! - we tolerate per-PID failures: a process can vanish between `listpids` and
//!   `pidinfo`. Skip and continue — §8.3 (event loss possibility).
//! - no filtering, no diffing, no aggregation.

use std::sync::Arc;

use aw_core::{Bus, MonotonicClock, Observation, Source, SourceAdapter, SourceBehavior};
use serde::Serialize;

/// Typed process payload. Field names are the downstream contract —
/// `aw-events::process_lifecycle` and the process table read them by name —
/// and must stay byte-identical to the historical `json!` keys.
#[derive(Serialize)]
struct ProcessPayload<'a> {
    ppid: u32,
    uid: u32,
    gid: u32,
    pgid: u32,
    comm: &'a str,
    name: &'a str,
    exec_path: Option<&'a str>,
    start_unix_secs: u64,
    status: u32,
    nfiles: u32,
}

pub struct ProcessAdapter;

impl ProcessAdapter {
    pub fn new() -> Self {
        Self
    }
}

impl Default for ProcessAdapter {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl SourceAdapter for ProcessAdapter {
    fn source(&self) -> Source {
        Source::Process
    }
    fn behavior(&self) -> SourceBehavior {
        SourceBehavior::Snapshot
    }

    async fn poll_snapshot(&self, clock: Arc<MonotonicClock>, bus: Bus) {
        // libproc calls are blocking syscalls. Move off the async runtime.
        let clock_clone = clock.clone();
        let bus_clone = bus.clone();
        let _ = tokio::task::spawn_blocking(move || {
            imp::snapshot(&clock_clone, &bus_clone);
        })
        .await;
    }
}

#[cfg(target_os = "macos")]
mod imp {
    use super::*;
    use libproc::libproc::bsd_info::BSDInfo;
    use libproc::libproc::proc_pid::{pidinfo, pidpath};
    use libproc::processes::{pids_by_type, ProcFilter};

    pub(super) fn snapshot(clock: &MonotonicClock, bus: &Bus) {
        let pids = match pids_by_type(ProcFilter::All) {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!("libproc pids_by_type failed: {e}");
                return;
            }
        };
        for pid in pids {
            let pid = pid as i32;
            if pid <= 0 {
                continue;
            }
            let Ok(info): Result<BSDInfo, _> = pidinfo(pid, 0) else {
                continue;
            };
            let exec_path = pidpath(pid).ok();
            bus.emit(to_observation(
                pid as u32,
                &info,
                exec_path.as_deref(),
                clock,
            ));
        }
    }

    fn to_observation(
        pid: u32,
        info: &BSDInfo,
        exec_path: Option<&str>,
        clock: &MonotonicClock,
    ) -> Observation {
        let comm = c_array_to_str(&info.pbi_comm);
        let name = c_array_to_str(&info.pbi_name);
        Observation {
            timestamp: clock.now(),
            source: Source::Process,
            pid: Some(pid),
            payload: serde_json::to_value(super::ProcessPayload {
                ppid: info.pbi_ppid,
                uid: info.pbi_uid,
                gid: info.pbi_gid,
                pgid: info.pbi_pgid,
                comm: &comm,
                name: &name,
                exec_path,
                start_unix_secs: info.pbi_start_tvsec,
                status: info.pbi_status,
                nfiles: info.pbi_nfiles,
            })
            .expect("process payload serializes"),
            tags: None,
        }
    }

    /// NUL-truncate a fixed C-char array, borrowing when it is valid UTF-8
    /// (the common case) instead of always allocating.
    pub(super) fn c_array_to_str<const N: usize>(
        arr: &[std::os::raw::c_char; N],
    ) -> std::borrow::Cow<'_, str> {
        // c_char and u8 have identical size/layout; this only reinterprets
        // signedness.
        let bytes: &[u8] = unsafe { std::slice::from_raw_parts(arr.as_ptr().cast::<u8>(), N) };
        let end = bytes.iter().position(|&b| b == 0).unwrap_or(N);
        String::from_utf8_lossy(&bytes[..end])
    }
}

#[cfg(not(target_os = "macos"))]
mod imp {
    use super::*;
    pub(super) fn snapshot(_clock: &MonotonicClock, _bus: &Bus) {
        tracing::warn!("aw-process is a no-op on non-macOS platforms");
    }
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;

    #[test]
    fn c_array_to_str_truncates_at_nul() {
        let mut arr: [std::os::raw::c_char; 8] = [0; 8];
        for (i, b) in b"abc".iter().enumerate() {
            arr[i] = *b as std::os::raw::c_char;
        }
        assert_eq!(imp::c_array_to_str(&arr), "abc");
    }

    #[test]
    fn c_array_to_str_full_array_no_nul() {
        let mut arr: [std::os::raw::c_char; 4] = [0; 4];
        for (i, b) in b"abcd".iter().enumerate() {
            arr[i] = *b as std::os::raw::c_char;
        }
        assert_eq!(imp::c_array_to_str(&arr), "abcd");
    }

    /// The typed payload must serialize to exactly the historical key set —
    /// downstream `aw-events` reads these by name.
    #[test]
    fn process_payload_keys_are_stable() {
        let v = serde_json::to_value(ProcessPayload {
            ppid: 1,
            uid: 501,
            gid: 20,
            pgid: 2,
            comm: "c",
            name: "n",
            exec_path: Some("/bin/c"),
            start_unix_secs: 3,
            status: 2,
            nfiles: 4,
        })
        .unwrap();
        let mut keys: Vec<&str> = v.as_object().unwrap().keys().map(|s| s.as_str()).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            [
                "comm",
                "exec_path",
                "gid",
                "name",
                "nfiles",
                "pgid",
                "ppid",
                "start_unix_secs",
                "status",
                "uid",
            ]
        );
    }

    #[tokio::test]
    async fn live_snapshot_includes_current_process() {
        let adapter = ProcessAdapter::new();
        let clock = Arc::new(MonotonicClock::new());
        let (bus, mut rx) = Bus::channel();
        adapter.poll_snapshot(clock, bus).await;

        let my_pid = std::process::id();
        let mut saw_self = false;
        let mut count = 0;
        while let Ok(obs) = rx.try_recv() {
            assert_eq!(obs.source, Source::Process);
            count += 1;
            if obs.pid == Some(my_pid) {
                saw_self = true;
                let comm = obs
                    .payload
                    .get("comm")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                assert!(!comm.is_empty(), "comm should be non-empty for own pid");
            }
        }
        assert!(count > 10, "expected many processes; got {count}");
        assert!(saw_self, "did not observe our own pid {my_pid}");
    }
}
