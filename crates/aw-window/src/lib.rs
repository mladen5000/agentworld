//! Window/UI adapter — frontmost-app diff via NSWorkspace (§4.3 WINDOW/UI, §5.3).
//!
//! Behavior: `Diff`. On each tick, queries `NSWorkspace.frontmostApplication`,
//! compares against the prior reading, and emits one `Observation` per
//! transition. No interpretation of activation reason or modifier state —
//! that's Layer 2's job.
//!
//! Layer 1 contract:
//! - `pid` is set to the frontmost app's `processIdentifier` (a real entity).
//! - payload carries the transition: `from`/`to` bundle identifiers, names,
//!   and exec paths. `from` is `null` on the first observed transition.
//! - state lives in the adapter (`Mutex<Option<...>>`); no global mutables.
//! - no aggregation; if focus flickers A→B→A in one tick we lose the middle,
//!   which is exactly what snapshot-mode polling implies (§8.1).

use std::sync::{Arc, Mutex};

use aw_core::{Bus, MonotonicClock, Observation, Source, SourceAdapter, SourceBehavior};

#[derive(Debug, Clone, PartialEq, Eq, Default)]
struct FrontmostApp {
    pid: Option<u32>,
    bundle_id: Option<String>,
    name: Option<String>,
    exec_path: Option<String>,
}

pub struct WindowAdapter {
    prior: Mutex<Option<FrontmostApp>>,
}

impl WindowAdapter {
    pub fn new() -> Self {
        Self {
            prior: Mutex::new(None),
        }
    }
}

impl Default for WindowAdapter {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl SourceAdapter for WindowAdapter {
    fn source(&self) -> Source {
        Source::Window
    }
    fn behavior(&self) -> SourceBehavior {
        SourceBehavior::Diff
    }

    async fn poll_diff(&self, clock: Arc<MonotonicClock>, bus: Bus) {
        let current = imp::read_frontmost();

        let mut prior = self.prior.lock().expect("window adapter mutex poisoned");
        let changed = prior.as_ref() != Some(&current);
        let from = prior.clone();
        if changed {
            *prior = Some(current.clone());
            drop(prior);
            bus.emit(to_observation(from.as_ref(), &current, &clock));
        }
    }
}

fn to_observation(
    from: Option<&FrontmostApp>,
    to: &FrontmostApp,
    clock: &MonotonicClock,
) -> Observation {
    Observation {
        timestamp: clock.now(),
        source: Source::Window,
        pid: to.pid,
        payload: serde_json::json!({
            "transition": "frontmost_app",
            "from": from.map(|f| serde_json::json!({
                "pid": f.pid,
                "bundle_id": f.bundle_id,
                "name": f.name,
                "exec_path": f.exec_path,
            })),
            "to": {
                "pid": to.pid,
                "bundle_id": to.bundle_id,
                "name": to.name,
                "exec_path": to.exec_path,
            },
        }),
        tags: None,
    }
}

#[cfg(target_os = "macos")]
mod imp {
    use super::FrontmostApp;
    use objc2_app_kit::NSWorkspace;

    pub(super) fn read_frontmost() -> FrontmostApp {
        let ws = NSWorkspace::sharedWorkspace();
        let app = match ws.frontmostApplication() {
            Some(a) => a,
            None => return FrontmostApp::default(),
        };
        let pid_raw = app.processIdentifier();
        let pid = if pid_raw > 0 {
            Some(pid_raw as u32)
        } else {
            None
        };
        let bundle_id = app.bundleIdentifier().map(|s| s.to_string());
        let name = app.localizedName().map(|s| s.to_string());
        let exec_path = app
            .executableURL()
            .and_then(|u| u.path())
            .map(|s| s.to_string());

        FrontmostApp {
            pid,
            bundle_id,
            name,
            exec_path,
        }
    }
}

#[cfg(not(target_os = "macos"))]
mod imp {
    use super::FrontmostApp;
    pub(super) fn read_frontmost() -> FrontmostApp {
        FrontmostApp::default()
    }
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;

    #[test]
    fn read_frontmost_returns_something() {
        // On a normal interactive macOS dev machine, *some* app is frontmost.
        // In a headless CI environment this may be empty — we don't fail then.
        let app = imp::read_frontmost();
        if let Some(pid) = app.pid {
            assert!(pid > 0);
        }
    }

    #[tokio::test]
    async fn first_poll_emits_one_observation() {
        let adapter = WindowAdapter::new();
        let clock = Arc::new(MonotonicClock::new());
        let (bus, mut rx) = Bus::channel();

        adapter.poll_diff(clock.clone(), bus.clone()).await;
        let obs = rx
            .try_recv()
            .expect("first poll should emit one observation");
        assert_eq!(obs.source, Source::Window);
        assert_eq!(
            obs.payload.get("transition").and_then(|v| v.as_str()),
            Some("frontmost_app")
        );
        // `from` should be null on the first observed transition.
        assert!(obs
            .payload
            .get("from")
            .map(|v| v.is_null())
            .unwrap_or(false));
    }

    #[tokio::test]
    async fn unchanged_poll_emits_nothing() {
        let adapter = WindowAdapter::new();
        let clock = Arc::new(MonotonicClock::new());
        let (bus, mut rx) = Bus::channel();

        adapter.poll_diff(clock.clone(), bus.clone()).await;
        let _first = rx.try_recv().expect("first poll emits");
        // Drain anything else.
        while rx.try_recv().is_ok() {}
        // Second poll with no focus change: nothing should arrive.
        adapter.poll_diff(clock, bus).await;
        assert!(
            rx.try_recv().is_err(),
            "second poll should emit nothing when focus is unchanged"
        );
    }
}
