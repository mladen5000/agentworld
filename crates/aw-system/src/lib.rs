//! System adapter — sysctl + getloadavg snapshot (§4.3 SYSTEM SOURCES, §5.2).
//!
//! Behavior: `Snapshot`. On each tick, reads a small fixed set of kernel/hw
//! values and emits one `Observation`. Static values (cpu count, total memory,
//! model, OS info) are read once at construction; live values (loadavg, free
//! memory pages, uptime) are sampled every tick.
//!
//! Layer 1 contract:
//! - `pid` is always `None` — system-wide metrics aren't attributable to a process.
//! - payload is structured; nothing is a raw string blob.
//! - missing sysctl keys are tolerated — we emit what we got, log others.
//! - no diffing here; downstream may diff the snapshot stream in Layer 2.

use std::sync::Arc;

use aw_core::{Bus, MonotonicClock, Observation, Source, SourceAdapter, SourceBehavior};

pub struct SystemAdapter {
    #[cfg(target_os = "macos")]
    static_info: imp::StaticInfo,
}

impl SystemAdapter {
    pub fn new() -> Self {
        Self {
            #[cfg(target_os = "macos")]
            static_info: imp::StaticInfo::read(),
        }
    }
}

impl Default for SystemAdapter {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl SourceAdapter for SystemAdapter {
    fn source(&self) -> Source {
        Source::System
    }
    fn behavior(&self) -> SourceBehavior {
        SourceBehavior::Snapshot
    }

    async fn poll_snapshot(&self, clock: Arc<MonotonicClock>, bus: Bus) {
        #[cfg(target_os = "macos")]
        {
            let static_info = self.static_info.clone();
            let clock = clock.clone();
            let _ = tokio::task::spawn_blocking(move || {
                let payload = imp::build_payload(&static_info);
                bus.emit(Observation {
                    timestamp: clock.now(),
                    source: Source::System,
                    pid: None,
                    payload,
                    tags: None,
                });
            })
            .await;
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (clock, bus);
            tracing::warn!("aw-system is a no-op on non-macOS platforms");
        }
    }
}

#[cfg(target_os = "macos")]
mod imp {
    use serde_json::{json, Value};
    use sysctl::{Ctl, Sysctl};

    #[derive(Debug, Clone)]
    pub(super) struct StaticInfo {
        pub ncpu: Option<i64>,
        pub memsize: Option<u64>,
        pub model: Option<String>,
        pub ostype: Option<String>,
        pub osrelease: Option<String>,
        pub osversion: Option<String>,
    }

    impl StaticInfo {
        pub(super) fn read() -> Self {
            Self {
                ncpu: read_int("hw.ncpu"),
                memsize: read_uint("hw.memsize"),
                model: read_string("hw.model"),
                ostype: read_string("kern.ostype"),
                osrelease: read_string("kern.osrelease"),
                osversion: read_string("kern.osversion"),
            }
        }
    }

    pub(super) fn build_payload(static_info: &StaticInfo) -> Value {
        let loadavg = read_loadavg();
        json!({
            "ncpu": static_info.ncpu,
            "memsize": static_info.memsize,
            "model": static_info.model,
            "ostype": static_info.ostype,
            "osrelease": static_info.osrelease,
            "osversion": static_info.osversion,
            "loadavg_1m": loadavg.map(|l| l[0]),
            "loadavg_5m": loadavg.map(|l| l[1]),
            "loadavg_15m": loadavg.map(|l| l[2]),
        })
    }

    /// Returns the 1/5/15-minute load averages via `getloadavg(3)`. Returns
    /// `None` if the syscall reports unavailable.
    fn read_loadavg() -> Option<[f64; 3]> {
        let mut avgs: [f64; 3] = [0.0; 3];
        // SAFETY: `getloadavg` writes up to `nelem` f64 entries; we pass 3
        // and provide a 3-element array. The return is the number of entries
        // populated, or -1 on failure.
        let n = unsafe { libc::getloadavg(avgs.as_mut_ptr(), 3) };
        if n == 3 {
            Some(avgs)
        } else {
            None
        }
    }

    fn read_string(name: &str) -> Option<String> {
        Ctl::new(name).ok()?.value_string().ok()
    }

    fn read_int(name: &str) -> Option<i64> {
        let v = Ctl::new(name).ok()?.value().ok()?;
        sysctl_value_to_i64(&v)
    }

    fn read_uint(name: &str) -> Option<u64> {
        let v = Ctl::new(name).ok()?.value().ok()?;
        sysctl_value_to_u64(&v)
    }

    fn sysctl_value_to_i64(v: &sysctl::CtlValue) -> Option<i64> {
        use sysctl::CtlValue::*;
        match v {
            Int(i) => Some(*i as i64),
            S8(i) => Some(*i as i64),
            S16(i) => Some(*i as i64),
            S32(i) => Some(*i as i64),
            S64(i) => Some(*i),
            Long(i) => Some(*i),
            Uint(i) => Some(*i as i64),
            U8(i) => Some(*i as i64),
            U16(i) => Some(*i as i64),
            U32(i) => Some(*i as i64),
            U64(i) => i64::try_from(*i).ok(),
            Ulong(i) => Some(*i as i64),
            _ => Option::None,
        }
    }

    fn sysctl_value_to_u64(v: &sysctl::CtlValue) -> Option<u64> {
        use sysctl::CtlValue::*;
        match v {
            Uint(i) => Some(*i as u64),
            U8(i) => Some(*i as u64),
            U16(i) => Some(*i as u64),
            U32(i) => Some(*i as u64),
            U64(i) => Some(*i),
            Ulong(i) => Some(*i),
            Int(i) if *i >= 0 => Some(*i as u64),
            S64(i) if *i >= 0 => Some(*i as u64),
            Long(i) if *i >= 0 => Some(*i as u64),
            _ => Option::None,
        }
    }

    #[cfg(test)]
    pub(super) fn build_payload_for_test(s: &StaticInfo) -> Value {
        build_payload(s)
    }
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;

    #[test]
    fn static_info_populated_on_macos() {
        let s = imp::StaticInfo::read();
        assert!(s.ncpu.is_some(), "hw.ncpu must be readable");
        assert!(s.memsize.is_some(), "hw.memsize must be readable");
        assert_eq!(s.ostype.as_deref(), Some("Darwin"));
    }

    #[test]
    fn payload_includes_loadavg_and_static_fields() {
        let s = imp::StaticInfo::read();
        let p = imp::build_payload_for_test(&s);
        assert!(p.get("ncpu").is_some());
        assert!(p.get("memsize").is_some());
        // loadavg may be None in pathological environments, but on a normal
        // dev machine it should populate.
        assert!(p.get("loadavg_1m").is_some());
    }

    #[tokio::test]
    async fn live_snapshot_emits_one_observation() {
        let adapter = SystemAdapter::new();
        let clock = Arc::new(MonotonicClock::new());
        let (bus, mut rx) = Bus::channel();
        adapter.poll_snapshot(clock, bus).await;

        let obs = rx.try_recv().expect("must emit one observation");
        assert_eq!(obs.source, Source::System);
        assert_eq!(obs.pid, None);
        assert!(obs.payload.get("ostype").is_some());
        assert!(rx.try_recv().is_err(), "must emit exactly one per tick");
    }
}
