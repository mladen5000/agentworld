//! Shared process index used by cross-source correlation.
//!
//! The `process_lifecycle` stage emits `process_birth` / `process_death` events
//! in isolation; this module accumulates them into a queryable index that
//! other stages (network, fsevents) can read at emission time to enrich their
//! own events with `comm`, `exec_path`, ppid, and an ancestry chain.
//!
//! Identity matches Layer 2's process key: `(pid, start_unix_secs)`. When
//! looking up by raw pid (which is what observations carry for *non*-process
//! sources), we return the most-recently-born matching entry — the right
//! answer under macOS PID reuse.
//!
//! Memory: entries are retained even after death so events emitted *after* a
//! process exited can still reference it. A simple bounded LRU keeps memory
//! tractable on long-running captures; the bound is intentionally generous
//! (8192 entries — even busy macOS systems have ≪1000 simultaneous PIDs).

use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct ProcessEntry {
    pub pid: u32,
    pub start_unix_secs: u64,
    pub ppid: Option<u32>,
    pub uid: Option<u32>,
    pub comm: Option<String>,
    pub name: Option<String>,
    pub exec_path: Option<String>,
    pub alive: bool,
    /// Monotonic insertion order, set inside `ProcessTable::insert`. Callers
    /// outside this module should leave it as 0; `insert` overwrites it.
    pub seq: u64,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct ProcKey {
    pub pid: u32,
    pub start_unix_secs: u64,
}

const CAP: usize = 8192;
/// Maximum ancestry depth to walk. Real process trees on macOS are shallow
/// (~10 levels); the cap is purely a cycle guard.
const MAX_ANCESTORS: usize = 32;

pub struct ProcessTable {
    by_key: HashMap<ProcKey, ProcessEntry>,
    /// Per-pid: the most-recently-inserted ProcKey for that pid, used to
    /// resolve raw-pid lookups (network/fsevents don't know start_unix_secs).
    latest_by_pid: HashMap<u32, ProcKey>,
    next_seq: u64,
}

impl ProcessTable {
    pub fn new() -> Self {
        Self {
            by_key: HashMap::new(),
            latest_by_pid: HashMap::new(),
            next_seq: 0,
        }
    }

    pub fn insert(&mut self, entry: ProcessEntry) {
        let key = ProcKey {
            pid: entry.pid,
            start_unix_secs: entry.start_unix_secs,
        };
        // Decide latest_by_pid: pick whichever has the larger start_unix_secs.
        // (Ties broken by insertion seq — we just updated `next_seq` below.)
        let should_replace_latest = match self.latest_by_pid.get(&key.pid) {
            None => true,
            Some(existing) => entry.start_unix_secs >= existing.start_unix_secs,
        };
        let mut entry = entry;
        entry.seq = self.next_seq;
        self.next_seq = self.next_seq.wrapping_add(1);

        self.by_key.insert(key.clone(), entry);
        if should_replace_latest {
            self.latest_by_pid.insert(key.pid, key.clone());
        }
        self.evict_if_needed();
    }

    pub fn mark_dead(&mut self, key: &ProcKey) {
        if let Some(e) = self.by_key.get_mut(key) {
            e.alive = false;
        }
    }

    /// Look up a process by raw pid. Returns the most-recently-born entry
    /// for that pid (right answer under reuse).
    pub fn by_pid(&self, pid: u32) -> Option<&ProcessEntry> {
        self.latest_by_pid
            .get(&pid)
            .and_then(|k| self.by_key.get(k))
    }

    pub fn by_key(&self, key: &ProcKey) -> Option<&ProcessEntry> {
        self.by_key.get(key)
    }

    /// Walk the ppid chain starting at `pid`. Returns `comm` (preferred) or
    /// `name` for each ancestor, up to root. Stops at PIDs 0 or 1, or when a
    /// parent isn't in the table.
    pub fn ancestors(&self, pid: u32) -> Vec<AncestorEntry> {
        let mut out = Vec::new();
        let mut seen = std::collections::HashSet::new();
        let mut cur_pid = match self.by_pid(pid).and_then(|e| e.ppid) {
            Some(p) if p > 1 => p,
            _ => return out,
        };
        for _ in 0..MAX_ANCESTORS {
            if !seen.insert(cur_pid) {
                break;
            } // cycle guard
            let Some(parent) = self.by_pid(cur_pid) else {
                break;
            };
            out.push(AncestorEntry {
                pid: parent.pid,
                comm: parent.comm.clone(),
                name: parent.name.clone(),
                exec_path: parent.exec_path.clone(),
            });
            match parent.ppid {
                Some(p) if p > 1 => cur_pid = p,
                _ => break,
            }
        }
        out
    }

    fn evict_if_needed(&mut self) {
        if self.by_key.len() <= CAP {
            return;
        }
        // Find the oldest entry by seq among the *not currently latest_by_pid*
        // set — we don't want to evict the entry a future raw-pid lookup needs.
        let latest_set: std::collections::HashSet<ProcKey> =
            self.latest_by_pid.values().cloned().collect();
        let victim = self
            .by_key
            .iter()
            .filter(|(k, _)| !latest_set.contains(k))
            .min_by_key(|(_, e)| e.seq)
            .map(|(k, _)| k.clone());
        if let Some(v) = victim {
            self.by_key.remove(&v);
        }
    }
}

impl Default for ProcessTable {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AncestorEntry {
    pub pid: u32,
    pub comm: Option<String>,
    pub name: Option<String>,
    pub exec_path: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(pid: u32, ppid: Option<u32>, comm: &str, start: u64) -> ProcessEntry {
        ProcessEntry {
            pid,
            start_unix_secs: start,
            ppid,
            uid: Some(501),
            comm: Some(comm.into()),
            name: Some(comm.into()),
            exec_path: Some(format!("/bin/{comm}")),
            alive: true,
            seq: 0,
        }
    }

    #[test]
    fn by_pid_returns_inserted_entry() {
        let mut t = ProcessTable::new();
        t.insert(entry(100, Some(1), "shell", 1000));
        let got = t.by_pid(100).expect("present");
        assert_eq!(got.comm.as_deref(), Some("shell"));
    }

    #[test]
    fn by_pid_picks_most_recent_under_reuse() {
        let mut t = ProcessTable::new();
        t.insert(entry(100, Some(1), "old", 1000));
        t.insert(entry(100, Some(1), "new", 2000));
        let got = t.by_pid(100).unwrap();
        assert_eq!(got.comm.as_deref(), Some("new"));
        assert_eq!(got.start_unix_secs, 2000);
    }

    #[test]
    fn mark_dead_keeps_entry_queryable() {
        let mut t = ProcessTable::new();
        t.insert(entry(100, Some(1), "shell", 1000));
        t.mark_dead(&ProcKey {
            pid: 100,
            start_unix_secs: 1000,
        });
        let got = t.by_pid(100).unwrap();
        assert!(!got.alive);
        assert_eq!(got.comm.as_deref(), Some("shell"));
    }

    #[test]
    fn ancestors_walks_ppid_chain() {
        let mut t = ProcessTable::new();
        // init (1) — root, ppid 0, not included
        t.insert(entry(1, Some(0), "launchd", 100));
        t.insert(entry(100, Some(1), "shell", 101));
        t.insert(entry(200, Some(100), "subshell", 102));
        t.insert(entry(300, Some(200), "leaf", 103));
        let chain = t.ancestors(300);
        let comms: Vec<&str> = chain.iter().filter_map(|a| a.comm.as_deref()).collect();
        // From 300 we walk ppid 200 -> 100 -> 1 (stops at 1).
        assert_eq!(comms, vec!["subshell", "shell"]);
    }

    #[test]
    fn ancestors_stops_when_parent_unknown() {
        let mut t = ProcessTable::new();
        t.insert(entry(300, Some(200), "leaf", 1));
        // pid 200 not in table
        let chain = t.ancestors(300);
        assert!(chain.is_empty());
    }

    #[test]
    fn ancestors_handles_cycle_without_hanging() {
        let mut t = ProcessTable::new();
        // Pathological: 100 says ppid=200, 200 says ppid=100. Shouldn't loop forever.
        t.insert(entry(100, Some(200), "a", 1));
        t.insert(entry(200, Some(100), "b", 2));
        let chain = t.ancestors(100);
        // Will yield 200 then attempt 100 which is in `seen`, stops.
        assert!(chain.len() <= MAX_ANCESTORS);
    }
}
