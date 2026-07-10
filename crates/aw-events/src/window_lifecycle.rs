//! Window lifecycle stage: frontmost-app transitions → `app_focus` events.
//!
//! `aw-window` (a Diff source) already emits one observation per real focus
//! change, so this stage is mostly a shape-changer: one window observation in,
//! one canonical `AppFocus` event out. Two responsibilities:
//!
//! - Flatten the nested `from`/`to` payload into a single structured event so
//!   downstream consumers (notably aw-graph) don't have to know about
//!   Layer 1's transition shape.
//! - Drop no-op observations (`from == to` by bundle id). The Layer 1 adapter
//!   should already filter these, but Layer 2 is the canonical place for
//!   "what counts as a meaningful event" — so we belt-and-brace it here.

use aw_core::Observation;
use serde_json::json;

use crate::{Event, EventKind, SCHEMA_VERSION};

pub struct WindowLifecycle;

impl WindowLifecycle {
    pub fn new() -> Self {
        Self
    }

    /// Convert a window observation into zero or one `AppFocus` event.
    pub fn on_observation(&self, obs: &Observation) -> Vec<Event> {
        let p = &obs.payload;
        let to = match p.get("to") {
            Some(v) if !v.is_null() => v,
            _ => return Vec::new(),
        };
        let from = p
            .get("from")
            .and_then(|v| if v.is_null() { None } else { Some(v) });

        let to_bundle = to
            .get("bundle_id")
            .and_then(|v| v.as_str())
            .map(String::from);
        let from_bundle = from
            .and_then(|f| f.get("bundle_id"))
            .and_then(|v| v.as_str())
            .map(String::from);

        // Belt-and-brace: drop no-op transitions.
        if from_bundle.is_some() && from_bundle == to_bundle {
            return Vec::new();
        }

        let to_name = to.get("name").and_then(|v| v.as_str()).map(String::from);
        let to_exec = to
            .get("exec_path")
            .and_then(|v| v.as_str())
            .map(String::from);
        let from_name = from
            .and_then(|f| f.get("name"))
            .and_then(|v| v.as_str())
            .map(String::from);

        // Prefer `to.pid` from the payload; fall back to the observation's
        // top-level pid. (They should agree for a well-formed Layer 1 emit.)
        let pid = to
            .get("pid")
            .and_then(|v| v.as_u64())
            .and_then(|n| u32::try_from(n).ok())
            .or(obs.pid);

        vec![Event {
            schema_version: SCHEMA_VERSION,
            timestamp: obs.timestamp,
            kind: EventKind::AppFocus,
            pid,
            payload: json!({
                "from_bundle_id": from_bundle,
                "from_name": from_name,
                "to_bundle_id": to_bundle,
                "to_name": to_name,
                "to_exec_path": to_exec,
            }),
        }]
    }
}

impl Default for WindowLifecycle {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aw_core::{Source, Timestamp};
    use serde_json::json;

    fn ts(n: u64) -> Timestamp {
        Timestamp {
            mono_ns: n,
            wall_anchor_ns: 0,
        }
    }

    fn obs(from_bundle: Option<&str>, to_bundle: &str, to_name: &str, pid: u32) -> Observation {
        let from = match from_bundle {
            Some(b) => json!({ "bundle_id": b, "name": "Old", "exec_path": "/old", "pid": 1 }),
            None => serde_json::Value::Null,
        };
        Observation {
            timestamp: ts(100),
            source: Source::Window,
            pid: Some(pid),
            payload: json!({
                "transition": "frontmost_app",
                "from": from,
                "to": { "bundle_id": to_bundle, "name": to_name, "exec_path": format!("/Applications/{to_name}.app/Contents/MacOS/{to_name}"), "pid": pid },
            }),
            tags: None,
        }
    }

    #[test]
    fn emits_event_for_real_transition() {
        let stage = WindowLifecycle::new();
        let events = stage.on_observation(&obs(Some("com.app.a"), "com.app.b", "AppB", 42));
        assert_eq!(events.len(), 1);
        let ev = &events[0];
        assert_eq!(ev.kind, EventKind::AppFocus);
        assert_eq!(ev.pid, Some(42));
        assert_eq!(
            ev.payload.get("from_bundle_id").and_then(|v| v.as_str()),
            Some("com.app.a")
        );
        assert_eq!(
            ev.payload.get("to_bundle_id").and_then(|v| v.as_str()),
            Some("com.app.b")
        );
        assert_eq!(
            ev.payload.get("to_name").and_then(|v| v.as_str()),
            Some("AppB")
        );
    }

    #[test]
    fn first_transition_has_null_from() {
        let stage = WindowLifecycle::new();
        let events = stage.on_observation(&obs(None, "com.app.a", "AppA", 99));
        assert_eq!(events.len(), 1);
        assert!(events[0]
            .payload
            .get("from_bundle_id")
            .map(|v| v.is_null())
            .unwrap_or(false));
    }

    #[test]
    fn drops_noop_transition() {
        let stage = WindowLifecycle::new();
        let events = stage.on_observation(&obs(Some("com.app.same"), "com.app.same", "Same", 1));
        assert!(events.is_empty());
    }

    #[test]
    fn drops_when_to_is_null() {
        let stage = WindowLifecycle::new();
        let mut o = obs(None, "com.app.a", "AppA", 1);
        o.payload["to"] = serde_json::Value::Null;
        assert!(stage.on_observation(&o).is_empty());
    }

    #[test]
    fn falls_back_to_top_level_pid_when_payload_pid_missing() {
        let stage = WindowLifecycle::new();
        let mut o = obs(None, "com.app.a", "AppA", 77);
        o.payload["to"].as_object_mut().unwrap().remove("pid");
        let events = stage.on_observation(&o);
        assert_eq!(events[0].pid, Some(77));
    }
}
