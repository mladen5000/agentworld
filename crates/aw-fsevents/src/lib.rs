//! Filesystem adapter — FSEvents stream (§4.3 FILE SYSTEM SOURCES, §5.1).
//!
//! Behavior: `Stream`. Real FSEvents binding via the `fsevent-stream` crate
//! (which wraps CoreServices' callback-driven API into a tokio `Stream`).
//!
//! Emits one `Observation` per FSEvents event. Per the Layer 1 contract
//! (see `ARCHITECTURE.md`):
//! - timestamps are anchored to our monotonic clock, not FSEvents' `event_id`
//!   (the `event_id` is preserved inside the payload for downstream ordering).
//! - PID is left `None` — FSEvents does not report it; we do not infer.
//! - flags are decoded into stable string names so the payload is structured.
//! - no aggregation, dedup, or filtering happens here.

use std::path::PathBuf;
use std::sync::Arc;

use aw_core::{Bus, MonotonicClock, Observation, Source, SourceAdapter, SourceBehavior};

#[cfg(target_os = "macos")]
mod imp {
    use super::*;
    use std::time::Duration;

    use fsevent_stream::ffi::{
        kFSEventStreamCreateFlagFileEvents, kFSEventStreamCreateFlagNoDefer,
        kFSEventStreamEventIdSinceNow,
    };
    use fsevent_stream::stream::{create_event_stream, Event};
    use fsevent_stream::flags::StreamFlags;
    use futures_util::StreamExt;

    pub(super) async fn run(roots: Vec<PathBuf>, latency: Duration, clock: Arc<MonotonicClock>, bus: Bus) {
        // `create_event_stream` performs FFI setup on the calling thread; it is
        // synchronous and cheap. We then drive its async `Stream`.
        let (stream, mut handler) = match create_event_stream(
            roots.iter().map(|p| p.as_path()),
            kFSEventStreamEventIdSinceNow,
            latency,
            kFSEventStreamCreateFlagNoDefer | kFSEventStreamCreateFlagFileEvents,
        ) {
            Ok(pair) => pair,
            Err(e) => {
                tracing::error!("FSEvents stream creation failed: {e}");
                return;
            }
        };

        let mut events = stream.into_flatten();
        while let Some(event) = events.next().await {
            bus.emit(to_observation(&event, &clock));
        }

        // Stream ended — tear down the CFRunLoop thread cleanly. Without this,
        // dropping the handler leaves a thread behind (per crate docs).
        handler.abort();
    }

    fn to_observation(event: &Event, clock: &MonotonicClock) -> Observation {
        Observation {
            timestamp: clock.now(),
            source: Source::FileSystem,
            pid: None,
            payload: serde_json::json!({
                "path": event.path.display().to_string(),
                "flags": decode_flags(event.flags),
                "event_id": event.id,
            }),
            tags: None,
        }
    }

    pub(super) fn decode_flags(flags: StreamFlags) -> Vec<&'static str> {
        let mut out = Vec::new();
        let pairs: &[(StreamFlags, &'static str)] = &[
            (StreamFlags::MUST_SCAN_SUBDIRS, "must_scan_subdirs"),
            (StreamFlags::USER_DROPPED, "user_dropped"),
            (StreamFlags::KERNEL_DROPPED, "kernel_dropped"),
            (StreamFlags::IDS_WRAPPED, "ids_wrapped"),
            (StreamFlags::HISTORY_DONE, "history_done"),
            (StreamFlags::ROOT_CHANGED, "root_changed"),
            (StreamFlags::MOUNT, "mount"),
            (StreamFlags::UNMOUNT, "unmount"),
            (StreamFlags::ITEM_CREATED, "created"),
            (StreamFlags::ITEM_REMOVED, "removed"),
            (StreamFlags::INODE_META_MOD, "inode_meta_mod"),
            (StreamFlags::ITEM_RENAMED, "renamed"),
            (StreamFlags::ITEM_MODIFIED, "modified"),
            (StreamFlags::FINDER_INFO_MOD, "finder_info_mod"),
            (StreamFlags::ITEM_CHANGE_OWNER, "change_owner"),
            (StreamFlags::ITEM_XATTR_MOD, "xattr_mod"),
            (StreamFlags::IS_FILE, "is_file"),
            (StreamFlags::IS_DIR, "is_dir"),
            (StreamFlags::IS_SYMLINK, "is_symlink"),
            (StreamFlags::OWN_EVENT, "own_event"),
            (StreamFlags::IS_HARDLINK, "is_hardlink"),
            (StreamFlags::IS_LAST_HARDLINK, "is_last_hardlink"),
            (StreamFlags::ITEM_CLONED, "cloned"),
        ];
        for (bit, name) in pairs {
            if flags.contains(*bit) {
                out.push(*name);
            }
        }
        out
    }
}

#[cfg(not(target_os = "macos"))]
mod imp {
    use super::*;
    use std::time::Duration;

    pub(super) async fn run(_roots: Vec<PathBuf>, _latency: Duration, _clock: Arc<MonotonicClock>, _bus: Bus) {
        tracing::warn!("aw-fsevents is a no-op on non-macOS platforms");
        std::future::pending::<()>().await;
    }
}

#[derive(Debug, Clone)]
pub struct FsEventsConfig {
    pub roots: Vec<PathBuf>,
    pub latency: std::time::Duration,
}

impl FsEventsConfig {
    fn default_root() -> PathBuf {
        std::env::var_os("HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/tmp"))
    }
}

impl Default for FsEventsConfig {
    fn default() -> Self {
        Self {
            roots: vec![Self::default_root()],
            latency: std::time::Duration::from_millis(100),
        }
    }
}

pub struct FsEventsAdapter {
    config: FsEventsConfig,
}

impl FsEventsAdapter {
    pub fn new() -> Self {
        Self { config: FsEventsConfig::default() }
    }

    pub fn with_config(config: FsEventsConfig) -> Self {
        Self { config }
    }
}

impl Default for FsEventsAdapter {
    fn default() -> Self { Self::new() }
}

#[async_trait::async_trait]
impl SourceAdapter for FsEventsAdapter {
    fn source(&self) -> Source { Source::FileSystem }
    fn behavior(&self) -> SourceBehavior { SourceBehavior::Stream }

    async fn run_stream(&self, clock: Arc<MonotonicClock>, bus: Bus) {
        imp::run(self.config.roots.clone(), self.config.latency, clock, bus).await;
    }
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;
    use fsevent_stream::flags::StreamFlags;
    use std::time::Duration;

    #[test]
    fn decode_flags_picks_matching_names() {
        let flags = StreamFlags::ITEM_CREATED | StreamFlags::IS_FILE;
        let names = imp::decode_flags(flags);
        assert!(names.contains(&"created"), "got {names:?}");
        assert!(names.contains(&"is_file"), "got {names:?}");
        assert!(!names.contains(&"removed"), "got {names:?}");
        assert!(!names.contains(&"is_dir"), "got {names:?}");
    }

    #[test]
    fn decode_flags_empty_when_none() {
        assert!(imp::decode_flags(StreamFlags::empty()).is_empty());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn emits_observation_when_file_created() {
        let dir = tempfile::tempdir().expect("tempdir");
        // FSEvents resolves symlinks; macOS often makes tmpdirs under /var which
        // is a symlink to /private/var. Canonicalize so our path comparison works.
        let root = dir.path().canonicalize().expect("canonicalize tmpdir");

        let adapter = FsEventsAdapter::with_config(FsEventsConfig {
            roots: vec![root.clone()],
            latency: Duration::from_millis(20),
        });
        let clock = Arc::new(MonotonicClock::new());
        let (bus, mut rx) = Bus::channel();

        let handle = tokio::spawn({
            let clock = clock.clone();
            async move { adapter.run_stream(clock, bus).await; }
        });

        // Give FSEvents a moment to set up before we touch the file.
        tokio::time::sleep(Duration::from_millis(300)).await;

        let target = root.join("hello.txt");
        std::fs::write(&target, b"hi").expect("write target");

        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        let mut saw_target = false;
        while tokio::time::Instant::now() < deadline {
            let obs = match tokio::time::timeout(Duration::from_millis(500), rx.recv()).await {
                Ok(Some(o)) => o,
                _ => continue,
            };
            let path = obs.payload.get("path").and_then(|v| v.as_str()).unwrap_or("");
            if path.ends_with("hello.txt") {
                saw_target = true;
                break;
            }
        }

        handle.abort();
        assert!(saw_target, "did not observe creation of {target:?}");
    }
}
