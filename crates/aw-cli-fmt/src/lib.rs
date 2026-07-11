//! Shared terminal output formatting for agentworld's CLI binaries
//! (`aw-mvp`, `aw-query`): timestamps, durations, and colored title bars.
//!
//! Color is gated by [`is_color_enabled`], which checks whether stdout is a
//! TTY. Callers must never emit ANSI codes on a non-TTY stdout — `aw-mvp`'s
//! stdout is documented as pipe-friendly narration output, and `aw-query`'s
//! JSON mode must stay byte-identical/machine-parseable regardless of color.

use std::io::IsTerminal;
use std::time::{SystemTime, UNIX_EPOCH};

use owo_colors::OwoColorize;

/// Whether stdout is a terminal — the single gate for all coloring in this
/// crate. Callers should check this once per invocation, not per line.
pub fn is_color_enabled() -> bool {
    std::io::stdout().is_terminal()
}

/// Wall-clock now, in unix nanoseconds — the timestamp encoding the store
/// and event stream use throughout this workspace.
pub fn now_unix_ns() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as i64)
        .unwrap_or(0)
}

/// Render a unix-ns timestamp as `"unix {secs} ({age} ago)"`, or just
/// `"unix {secs}"` for a timestamp in the future (clock skew, test fixtures).
pub fn fmt_unix_ns(ns: i64) -> String {
    let secs = ns / 1_000_000_000;
    let age_secs = (now_unix_ns() - ns) / 1_000_000_000;
    if age_secs >= 0 {
        format!("unix {secs} ({} ago)", fmt_duration(age_secs as u64))
    } else {
        format!("unix {secs}")
    }
}

/// Humanize a duration in seconds as the largest one or two non-zero units,
/// e.g. `45s`, `2m5s`, `1h`, `1h2m`, `3d4h`. Trailing zero units are omitted
/// (`1h`, not `1h0m`).
pub fn fmt_duration(secs: u64) -> String {
    if secs < 60 {
        return format!("{secs}s");
    }
    if secs < 3_600 {
        let m = secs / 60;
        let s = secs % 60;
        return if s == 0 {
            format!("{m}m")
        } else {
            format!("{m}m{s}s")
        };
    }
    if secs < 86_400 {
        let h = secs / 3_600;
        let m = (secs % 3_600) / 60;
        return if m == 0 {
            format!("{h}h")
        } else {
            format!("{h}h{m}m")
        };
    }
    let d = secs / 86_400;
    let h = (secs % 86_400) / 3_600;
    if h == 0 {
        format!("{d}d")
    } else {
        format!("{d}d{h}h")
    }
}

/// A colored (when TTY), fixed-width-dash title bar with a timestamp, e.g.
/// `── capture start · unix 1752... (now) ──`. Not stretched to terminal
/// width — no box-drawing that assumes a column count.
pub fn title_bar(label: &str) -> String {
    let ts = fmt_unix_ns(now_unix_ns());
    let text = format!("── {label} · {ts} ──");
    if is_color_enabled() {
        text.bold().cyan().to_string()
    } else {
        text
    }
}

/// A colored (when TTY) section separator, upgrading the older plain
/// `"--- label ---"` convention. No timestamp — for sub-sections within a
/// block that already has its own `title_bar`.
pub fn section(label: &str) -> String {
    let text = format!("── {label} ──");
    if is_color_enabled() {
        text.bold().yellow().to_string()
    } else {
        text
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fmt_duration_omits_trailing_zero_units() {
        assert_eq!(fmt_duration(0), "0s");
        assert_eq!(fmt_duration(45), "45s");
        assert_eq!(fmt_duration(59), "59s");
        assert_eq!(fmt_duration(60), "1m");
        assert_eq!(fmt_duration(61), "1m1s");
        assert_eq!(fmt_duration(125), "2m5s");
        assert_eq!(fmt_duration(3600), "1h");
        assert_eq!(fmt_duration(3601), "1h");
        assert_eq!(fmt_duration(3660), "1h1m");
        assert_eq!(fmt_duration(3725), "1h2m");
        assert_eq!(fmt_duration(86_400), "1d");
        assert_eq!(fmt_duration(90_000), "1d1h");
    }

    #[test]
    fn fmt_unix_ns_reports_age_for_past_timestamps() {
        let now = now_unix_ns();
        let one_hour_ago = now - 3_600 * 1_000_000_000;
        let rendered = fmt_unix_ns(one_hour_ago);
        assert!(rendered.contains("ago)"), "expected an age suffix: {rendered}");
        assert!(rendered.contains("1h") || rendered.contains("59m"), "rendered: {rendered}");
    }

    #[test]
    fn fmt_unix_ns_handles_future_timestamps_without_age() {
        let far_future = now_unix_ns() + 3_600 * 1_000_000_000;
        let rendered = fmt_unix_ns(far_future);
        assert!(!rendered.contains("ago"), "rendered: {rendered}");
        assert!(rendered.starts_with("unix "));
    }

    #[test]
    fn title_bar_contains_label_and_timestamp() {
        let bar = title_bar("topology");
        // Color codes may or may not be present depending on the test
        // runner's stdout, so only assert on content, not exact bytes.
        assert!(bar.contains("topology"), "bar: {bar}");
        assert!(bar.contains("unix "), "bar: {bar}");
    }

    #[test]
    fn section_contains_label() {
        let s = section("anomaly check");
        assert!(s.contains("anomaly check"), "section: {s}");
    }
}
