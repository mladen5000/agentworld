//! FSEvents coalescing stage: stream of file events → windowed `FileChanged`.
//!
//! FSEvents is a Stream source (callback-driven, not a polled snapshot), so
//! gap-based tick boundaries don't apply. Instead we tumble events into
//! fixed-width time windows keyed by `path`. When an event arrives whose
//! window id exceeds the most-recently-seen window, we flush the buffer:
//! one `FileChanged` event per path, with the union of all observed flags
//! and the list of contributing fsevent ids.
//!
//! Why this matters: a single editor save fires `created + modified +
//! xattr_mod + inode_meta_mod` for the same path within ~1ms. Layer 1 emits
//! them all faithfully; Layer 2 compresses them into one event the consumer
//! can reason about.
//!
//! Caveats:
//! - The buffer flushes only on a *later* event. If fsevents go idle, the
//!   final window's contents sit in memory until either new activity or
//!   `flush_all` (called at EOF in the offline path).
//! - FSEvents reports no PID. `pid` on emitted events is always `None`.

use std::collections::HashMap;

use aw_core::{Observation, Timestamp};
use serde_json::json;

use crate::{Event, EventKind};

/// Coalescing window size. 500ms balances responsiveness against compression
/// of editor-save bursts (which typically fire 4–6 events within ~10ms).
const WINDOW_NS: u64 = 500 * 1_000_000;

#[derive(Debug, Default, Clone)]
struct PathRecord {
    flags: Vec<String>,
    event_ids: Vec<u64>,
    first_seen: Option<Timestamp>,
    last_seen: Option<Timestamp>,
}

pub struct FsEventsCoalesce {
    /// Buffer for the current window, keyed by path.
    buffer: HashMap<String, PathRecord>,
    /// Window id of the current buffer's contents (`ts.mono_ns / WINDOW_NS`).
    current_window: Option<u64>,
    /// The latest fsevent timestamp seen; used as the emission timestamp on
    /// flush (best approximation of "when this window ended").
    last_ts: Option<Timestamp>,
}

impl FsEventsCoalesce {
    pub fn new() -> Self {
        Self {
            buffer: HashMap::new(),
            current_window: None,
            last_ts: None,
        }
    }

    pub fn on_observation(&mut self, obs: &Observation) -> Vec<Event> {
        let p = &obs.payload;
        let path = match p.get("path").and_then(|v| v.as_str()) {
            Some(s) if !s.is_empty() => s.to_string(),
            _ => return Vec::new(),
        };
        let flags: Vec<String> = p.get("flags")
            .and_then(|v| v.as_array())
            .map(|arr| arr.iter().filter_map(|x| x.as_str().map(String::from)).collect())
            .unwrap_or_default();
        let event_id = p.get("event_id").and_then(|v| v.as_u64()).unwrap_or(0);

        let window_id = obs.timestamp.mono_ns / WINDOW_NS;

        // If we've moved to a new window, flush the prior buffer first.
        let mut events = Vec::new();
        if let Some(prev_win) = self.current_window {
            if window_id > prev_win {
                let flush_ts = self.last_ts.unwrap_or(obs.timestamp);
                events.extend(self.drain_buffer(flush_ts));
            }
        }
        self.current_window = Some(window_id);

        // Merge into the per-path record.
        let rec = self.buffer.entry(path.clone()).or_default();
        rec.first_seen.get_or_insert(obs.timestamp);
        rec.last_seen = Some(obs.timestamp);
        for f in flags {
            if !rec.flags.contains(&f) {
                rec.flags.push(f);
            }
        }
        if event_id != 0 {
            rec.event_ids.push(event_id);
        }

        self.last_ts = Some(obs.timestamp);
        events
    }

    /// Flush any remaining buffered windows. Call at end-of-input (e.g. EOF in
    /// the offline binary; shutdown in live mode if you want a clean tail).
    pub fn flush_all(&mut self) -> Vec<Event> {
        let flush_ts = match self.last_ts { Some(t) => t, None => return Vec::new() };
        self.drain_buffer(flush_ts)
    }

    fn drain_buffer(&mut self, flush_ts: Timestamp) -> Vec<Event> {
        if self.buffer.is_empty() { return Vec::new(); }
        let mut out = Vec::with_capacity(self.buffer.len());
        for (path, rec) in self.buffer.drain() {
            out.push(file_changed_event(&path, &rec, flush_ts));
        }
        out
    }
}

impl Default for FsEventsCoalesce {
    fn default() -> Self { Self::new() }
}

fn file_changed_event(path: &str, rec: &PathRecord, flush_ts: Timestamp) -> Event {
    Event {
        timestamp: flush_ts,
        kind: EventKind::FileChanged,
        pid: None,
        payload: json!({
            "path": path,
            "flags": rec.flags,
            "event_ids": rec.event_ids,
            "count": rec.event_ids.len(),
            "first_seen": rec.first_seen,
            "last_seen": rec.last_seen,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aw_core::Source;
    use serde_json::json;

    fn ts(n: u64) -> Timestamp { Timestamp { mono_ns: n, wall_anchor_ns: 0 } }

    fn fsobs(path: &str, flags: &[&str], event_id: u64, mono: u64) -> Observation {
        Observation {
            timestamp: ts(mono),
            source: Source::FileSystem,
            pid: None,
            payload: json!({
                "path": path,
                "flags": flags,
                "event_id": event_id,
            }),
            tags: None,
        }
    }

    #[test]
    fn coalesces_same_path_in_one_window() {
        let mut s = FsEventsCoalesce::new();
        // Four events on the same path within the first 500ms window.
        s.on_observation(&fsobs("/tmp/x", &["created"], 1, 1));
        s.on_observation(&fsobs("/tmp/x", &["modified"], 2, 100_000_000));
        s.on_observation(&fsobs("/tmp/x", &["xattr_mod"], 3, 200_000_000));
        s.on_observation(&fsobs("/tmp/x", &["is_file"], 4, 300_000_000));

        // Force flush.
        let events = s.flush_all();
        assert_eq!(events.len(), 1, "got {events:?}");
        let p = &events[0].payload;
        assert_eq!(p.get("path").and_then(|v| v.as_str()), Some("/tmp/x"));
        let flags: Vec<&str> = p.get("flags").unwrap().as_array().unwrap()
            .iter().filter_map(|v| v.as_str()).collect();
        for expected in ["created", "modified", "xattr_mod", "is_file"] {
            assert!(flags.contains(&expected), "missing {expected}; got {flags:?}");
        }
        assert_eq!(p.get("count").and_then(|v| v.as_u64()), Some(4));
        assert_eq!(p.get("event_ids").unwrap().as_array().unwrap().len(), 4);
    }

    #[test]
    fn separate_paths_emit_separately() {
        let mut s = FsEventsCoalesce::new();
        s.on_observation(&fsobs("/a", &["created"], 1, 1));
        s.on_observation(&fsobs("/b", &["modified"], 2, 2));
        let events = s.flush_all();
        let paths: Vec<&str> = events.iter()
            .map(|e| e.payload.get("path").and_then(|v| v.as_str()).unwrap())
            .collect();
        assert_eq!(events.len(), 2);
        assert!(paths.contains(&"/a"));
        assert!(paths.contains(&"/b"));
    }

    #[test]
    fn new_window_triggers_flush() {
        let mut s = FsEventsCoalesce::new();
        // Window 0: /a touched twice.
        s.on_observation(&fsobs("/a", &["created"], 1, 1));
        s.on_observation(&fsobs("/a", &["modified"], 2, 200_000_000));
        // Window 1: /b touched. Should flush /a.
        let events = s.on_observation(&fsobs("/b", &["created"], 3, 600_000_000));
        assert_eq!(events.len(), 1, "expected /a flush; got {events:?}");
        assert_eq!(events[0].payload.get("path").and_then(|v| v.as_str()), Some("/a"));
        let flags: Vec<&str> = events[0].payload.get("flags").unwrap().as_array().unwrap()
            .iter().filter_map(|v| v.as_str()).collect();
        assert!(flags.contains(&"created"));
        assert!(flags.contains(&"modified"));

        // /b still buffered until next window.
        let tail = s.flush_all();
        assert_eq!(tail.len(), 1);
        assert_eq!(tail[0].payload.get("path").and_then(|v| v.as_str()), Some("/b"));
    }

    #[test]
    fn duplicate_flags_are_unioned_not_repeated() {
        let mut s = FsEventsCoalesce::new();
        s.on_observation(&fsobs("/x", &["modified", "is_file"], 1, 1));
        s.on_observation(&fsobs("/x", &["modified"], 2, 100_000_000));
        let events = s.flush_all();
        let flags: Vec<&str> = events[0].payload.get("flags").unwrap().as_array().unwrap()
            .iter().filter_map(|v| v.as_str()).collect();
        let modified_count = flags.iter().filter(|f| **f == "modified").count();
        assert_eq!(modified_count, 1, "modified should appear once; got {flags:?}");
        assert!(flags.contains(&"is_file"));
    }

    #[test]
    fn observation_without_path_is_dropped() {
        let mut s = FsEventsCoalesce::new();
        let mut o = fsobs("/x", &["modified"], 1, 1);
        o.payload.as_object_mut().unwrap().remove("path");
        s.on_observation(&o);
        assert!(s.flush_all().is_empty());
    }

    #[test]
    fn flush_all_on_empty_returns_nothing() {
        let mut s = FsEventsCoalesce::new();
        assert!(s.flush_all().is_empty());
    }
}
