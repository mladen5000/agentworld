//! DNS stage: `Source::Network` observations tagged `kind == "dns_query"`
//! become canonical `DnsQuery` events.
//!
//! Shape-only — each observation maps to exactly one event. No coalescing or
//! diffing; mDNSResponder already emits one log line per query, and we don't
//! want to lose individual queries to a window. Cross-source enrichment (via
//! `Reconstructor::enrich`) attaches the querying process's `comm` /
//! `exec_path` / ancestry from the shared `ProcessTable`.

use aw_core::Observation;
use serde_json::json;

use crate::{Event, EventKind};

pub struct DnsLifecycle;

impl DnsLifecycle {
    pub fn new() -> Self { Self }

    pub fn on_observation(&self, obs: &Observation) -> Vec<Event> {
        let p = &obs.payload;
        // Only handle dns_query payloads. Other Source::Network observations
        // belong to the netstat stage.
        if p.get("kind").and_then(|v| v.as_str()) != Some("dns_query") {
            return Vec::new();
        }

        let qname = p.get("qname").and_then(|v| v.as_str()).map(String::from);
        let qtype = p.get("qtype").and_then(|v| v.as_str()).map(String::from);
        let name_hash = p.get("name_hash").and_then(|v| v.as_str()).map(String::from);
        let masked = p.get("masked").and_then(|v| v.as_bool()).unwrap_or(false);
        let interface_index = p.get("interface_index").and_then(|v| v.as_i64());
        let client_process_name = p.get("client_process_name").and_then(|v| v.as_str()).map(String::from);

        vec![Event {
            timestamp: obs.timestamp,
            kind: EventKind::DnsQuery,
            pid: obs.pid,
            payload: json!({
                "qname": qname,
                "qtype": qtype,
                "name_hash": name_hash,
                "masked": masked,
                "interface_index": interface_index,
                "client_process_name": client_process_name,
            }),
        }]
    }
}

impl Default for DnsLifecycle {
    fn default() -> Self { Self::new() }
}

/// True iff `obs` is a DNS-query-bearing observation. Used by the
/// `Reconstructor` to route Network observations between the netstat stage
/// (sockets) and this stage (DNS).
pub fn is_dns_query_observation(obs: &Observation) -> bool {
    obs.payload.get("kind").and_then(|v| v.as_str()) == Some("dns_query")
}

#[cfg(test)]
mod tests {
    use super::*;
    use aw_core::{Source, Timestamp};
    use serde_json::json;

    fn ts(n: u64) -> Timestamp { Timestamp { mono_ns: n, wall_anchor_ns: 0 } }

    fn dns_obs(pid: u32, qtype: &str, qname: &str, masked: bool) -> Observation {
        Observation {
            timestamp: ts(1),
            source: Source::Network,
            pid: Some(pid),
            payload: json!({
                "kind": "dns_query",
                "qname": qname,
                "qtype": qtype,
                "name_hash": "abc123",
                "masked": masked,
                "interface_index": 0,
                "client_process_name": "curl",
            }),
            tags: None,
        }
    }

    fn socket_obs() -> Observation {
        Observation {
            timestamp: ts(1),
            source: Source::Network,
            pid: Some(100),
            payload: json!({
                "proto": "tcp4", "local_addr": "a", "foreign_addr": "b",
                "state": "ESTABLISHED",
            }),
            tags: None,
        }
    }

    #[test]
    fn emits_one_event_per_dns_query() {
        let s = DnsLifecycle::new();
        let events = s.on_observation(&dns_obs(42, "A", "example.com.", false));
        assert_eq!(events.len(), 1);
        let e = &events[0];
        assert_eq!(e.kind, EventKind::DnsQuery);
        assert_eq!(e.pid, Some(42));
        assert_eq!(e.payload.get("qtype").and_then(|v| v.as_str()), Some("A"));
        assert_eq!(e.payload.get("qname").and_then(|v| v.as_str()), Some("example.com."));
        assert_eq!(e.payload.get("masked").and_then(|v| v.as_bool()), Some(false));
    }

    #[test]
    fn preserves_masked_flag_and_hash() {
        let s = DnsLifecycle::new();
        let events = s.on_observation(&dns_obs(42, "AAAA", "<mask.hash: 'xxx=='>", true));
        let e = &events[0];
        assert_eq!(e.payload.get("masked").and_then(|v| v.as_bool()), Some(true));
        assert_eq!(e.payload.get("name_hash").and_then(|v| v.as_str()), Some("abc123"));
    }

    #[test]
    fn ignores_non_dns_network_observations() {
        let s = DnsLifecycle::new();
        let events = s.on_observation(&socket_obs());
        assert!(events.is_empty());
    }

    #[test]
    fn route_helper_distinguishes_payloads() {
        assert!(is_dns_query_observation(&dns_obs(1, "A", "x.", false)));
        assert!(!is_dns_query_observation(&socket_obs()));
    }
}
