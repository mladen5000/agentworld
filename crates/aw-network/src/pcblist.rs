//! In-process socket enumeration via `sysctl net.inet.{tcp,udp}.pcblist_n`.
//!
//! Walks the same kernel records `netstat -n -v` prints from — `xinpcb_n`
//! (addresses/ports), `xsocket_n` (owning pid), `xtcpcb_n` (TCP state),
//! `xsockstat_n` (per-traffic-class byte counters) — without forking a
//! subprocess or parsing text.
//!
//! The records are read by explicit byte offset (`#pragma pack(4)` layout
//! from XNU's `netinet/in_pcb.h` / `sys/socketvar.h`), never by transmuting
//! structs, and every read is bounds-checked. If the sysctl itself fails (sandbox, exotic
//! kernel), the adapter falls back to the netstat path; if a record is
//! shorter than an offset we need, the field degrades to `None`/empty rather
//! than misparsing.

use std::collections::HashMap;

/// One socket row, shape-identical to the netstat parser's output.
#[derive(Debug, Clone)]
pub(crate) struct SocketRow {
    pub proto: &'static str,
    pub local_addr: String,
    pub foreign_addr: String,
    pub state: Option<&'static str>,
    pub rxbytes: Option<u64>,
    pub txbytes: Option<u64>,
    pub process_name: String,
    pub pid: Option<u32>,
}

/// Record kinds (XNU `sys/socketvar.h`).
const XSO_SOCKET: u32 = 0x001;
const XSO_RCVBUF: u32 = 0x002;
const XSO_SNDBUF: u32 = 0x004;
const XSO_STATS: u32 = 0x008;
const XSO_INPCB: u32 = 0x010;
const XSO_TCPCB: u32 = 0x020;

const ALL_KIND_INP: u32 = XSO_SOCKET | XSO_RCVBUF | XSO_SNDBUF | XSO_STATS | XSO_INPCB;
const ALL_KIND_TCP: u32 = ALL_KIND_INP | XSO_TCPCB;

/// `sizeof(struct xinpgen)` — the list is framed by one leading and one
/// trailing `xinpgen`; a record no longer than it is the end sentinel.
const XINPGEN_LEN: usize = 24;

/// `inp_vflag` bits.
const INP_IPV4: u8 = 0x1;
const INP_IPV6: u8 = 0x2;

/// TCP FSM states (XNU `netinet/tcp_fsm.h`), same strings netstat prints.
const TCP_STATES: [&str; 11] = [
    "CLOSED",
    "LISTEN",
    "SYN_SENT",
    "SYN_RCVD",
    "ESTABLISHED",
    "CLOSE_WAIT",
    "FIN_WAIT_1",
    "CLOSING",
    "LAST_ACK",
    "FIN_WAIT_2",
    "TIME_WAIT",
];

/// Snapshot every TCP and UDP socket. Blocking (raw sysctls) — call from
/// `spawn_blocking`. Errors mean "the native path is unavailable"; the
/// caller falls back to netstat.
pub(crate) fn snapshot() -> std::io::Result<Vec<SocketRow>> {
    let mut names: HashMap<i32, String> = HashMap::new();
    let mut rows = parse_pcblist(&sysctl_by_name("net.inet.tcp.pcblist_n")?, true, &mut names);
    rows.extend(parse_pcblist(
        &sysctl_by_name("net.inet.udp.pcblist_n")?,
        false,
        &mut names,
    ));
    Ok(rows)
}

#[cfg(target_os = "macos")]
fn sysctl_by_name(name: &str) -> std::io::Result<Vec<u8>> {
    let cname = std::ffi::CString::new(name).expect("static sysctl name");
    let mut len: libc::size_t = 0;
    // Size probe, then fetch with slack — the table can grow between calls.
    let rc = unsafe {
        libc::sysctlbyname(
            cname.as_ptr(),
            std::ptr::null_mut(),
            &mut len,
            std::ptr::null_mut(),
            0,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    len += len / 8;
    let mut buf = vec![0u8; len];
    let rc = unsafe {
        libc::sysctlbyname(
            cname.as_ptr(),
            buf.as_mut_ptr().cast(),
            &mut len,
            std::ptr::null_mut(),
            0,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    buf.truncate(len);
    Ok(buf)
}

#[cfg(not(target_os = "macos"))]
fn sysctl_by_name(_name: &str) -> std::io::Result<Vec<u8>> {
    Err(std::io::Error::other("pcblist_n is macOS-only"))
}

/// Walk the record stream. Each connection is a group of kind-tagged records;
/// a group is complete when every kind in the protocol's mask has been seen.
fn parse_pcblist(buf: &[u8], tcp: bool, names: &mut HashMap<i32, String>) -> Vec<SocketRow> {
    let mask = if tcp { ALL_KIND_TCP } else { ALL_KIND_INP };
    let mut rows = Vec::new();

    let Some(first_len) = read_u32(buf, 0) else {
        return rows;
    };
    let mut off = roundup8(first_len as usize);

    let mut which: u32 = 0;
    let mut inpcb: Option<&[u8]> = None;
    let mut socket: Option<&[u8]> = None;
    let mut tcpcb: Option<&[u8]> = None;
    let mut stats: Option<&[u8]> = None;

    while off + 8 <= buf.len() {
        let len = read_u32(buf, off).unwrap_or(0) as usize;
        if len <= XINPGEN_LEN || off + len > buf.len() {
            break; // trailing xinpgen sentinel or truncated buffer
        }
        let rec = &buf[off..off + len];
        let kind = read_u32(rec, 4).unwrap_or(0);
        match kind {
            XSO_INPCB => inpcb = Some(rec),
            XSO_SOCKET => socket = Some(rec),
            XSO_TCPCB => tcpcb = Some(rec),
            XSO_STATS => stats = Some(rec),
            _ => {}
        }
        which |= kind;
        if which & mask == mask {
            if let (Some(inp), Some(so)) = (inpcb, socket) {
                if let Some(row) = build_row(inp, so, tcpcb, stats, tcp, names) {
                    rows.push(row);
                }
            }
            which = 0;
            inpcb = None;
            socket = None;
            tcpcb = None;
            stats = None;
        }
        off += roundup8(len);
    }
    rows
}

/// Field offsets within `xinpcb_n`. XNU compiles these exported structs
/// under `#pragma pack(4)`, so u64 fields are 4-aligned and the layout is
/// denser than natural LP64 alignment: fport@16 lport@18 (network byte
/// order), vflag@44, faddr union@48, laddr union@64; IPv4 addresses sit at
/// +12 inside each 16-byte `in_addr_4in6` union. Verified empirically on
/// this kernel by the `native_snapshot_sees_own_listener` test.
fn build_row(
    inp: &[u8],
    so: &[u8],
    tcpcb: Option<&[u8]>,
    stats: Option<&[u8]>,
    tcp: bool,
    names: &mut HashMap<i32, String>,
) -> Option<SocketRow> {
    let fport = read_u16_be(inp, 16)?;
    let lport = read_u16_be(inp, 18)?;
    let vflag = *inp.get(44)?;

    let (proto, local_addr, foreign_addr) = if vflag & INP_IPV6 != 0 && vflag & INP_IPV4 == 0 {
        let laddr: [u8; 16] = inp.get(64..80)?.try_into().ok()?;
        let faddr: [u8; 16] = inp.get(48..64)?.try_into().ok()?;
        (
            if tcp { "tcp6" } else { "udp6" },
            fmt_addr6(laddr, lport),
            fmt_addr6(faddr, fport),
        )
    } else {
        let laddr: [u8; 4] = inp.get(76..80)?.try_into().ok()?;
        let faddr: [u8; 4] = inp.get(60..64)?.try_into().ok()?;
        let proto = if vflag & INP_IPV6 != 0 {
            if tcp {
                "tcp46"
            } else {
                "udp46"
            }
        } else if tcp {
            "tcp4"
        } else {
            "udp4"
        };
        (proto, fmt_addr4(laddr, lport), fmt_addr4(faddr, fport))
    };

    // xsocket_n (also pack(4)): so_last_pid@68.
    let last_pid = read_u32(so, 68).map(|v| v as i32).unwrap_or(0);
    let (pid, process_name) = if last_pid > 0 {
        let name = names
            .entry(last_pid)
            .or_insert_with(|| pid_name(last_pid).unwrap_or_default())
            .clone();
        (Some(last_pid as u32), name)
    } else {
        (None, String::new())
    };

    // xtcpcb_n: t_state@36 (after u64 t_segq, int t_dupacks, int t_timer[4]).
    let state = if tcp {
        tcpcb
            .and_then(|t| read_u32(t, 36))
            .and_then(|s| TCP_STATES.get(s as usize).copied())
    } else {
        None
    };

    // xsockstat_n: 4 × data_stats@8, each {rxpackets, rxbytes, txpackets,
    // txbytes} as u64; netstat's rxbytes/txbytes are the sums across classes.
    let (rxbytes, txbytes) = match stats {
        Some(st) => {
            let mut rx: u64 = 0;
            let mut tx: u64 = 0;
            let mut ok = true;
            for i in 0..4 {
                let base = 8 + i * 32;
                match (read_u64(st, base + 8), read_u64(st, base + 24)) {
                    (Some(r), Some(t)) => {
                        rx = rx.saturating_add(r);
                        tx = tx.saturating_add(t);
                    }
                    _ => {
                        ok = false;
                        break;
                    }
                }
            }
            if ok {
                (Some(rx), Some(tx))
            } else {
                (None, None)
            }
        }
        None => (None, None),
    };

    Some(SocketRow {
        proto,
        local_addr,
        foreign_addr,
        state,
        rxbytes,
        txbytes,
        process_name,
        pid,
    })
}

#[cfg(target_os = "macos")]
fn pid_name(pid: i32) -> Option<String> {
    libproc::libproc::proc_pid::name(pid).ok()
}

#[cfg(not(target_os = "macos"))]
fn pid_name(_pid: i32) -> Option<String> {
    None
}

/// netstat's address rendering: `*` for the wildcard address and port,
/// address and port joined with `.`.
fn fmt_addr4(addr: [u8; 4], port: u16) -> String {
    let host = if addr == [0, 0, 0, 0] {
        "*".to_string()
    } else {
        format!("{}.{}.{}.{}", addr[0], addr[1], addr[2], addr[3])
    };
    format!("{host}.{}", fmt_port(port))
}

fn fmt_addr6(addr: [u8; 16], port: u16) -> String {
    let host = if addr == [0u8; 16] {
        "*".to_string()
    } else {
        std::net::Ipv6Addr::from(addr).to_string()
    };
    format!("{host}.{}", fmt_port(port))
}

fn fmt_port(port: u16) -> String {
    if port == 0 {
        "*".to_string()
    } else {
        port.to_string()
    }
}

fn roundup8(n: usize) -> usize {
    n.div_ceil(8) * 8
}

fn read_u16_be(buf: &[u8], off: usize) -> Option<u16> {
    buf.get(off..off + 2)
        .map(|b| u16::from_be_bytes(b.try_into().unwrap()))
}

fn read_u32(buf: &[u8], off: usize) -> Option<u32> {
    buf.get(off..off + 4)
        .map(|b| u32::from_le_bytes(b.try_into().unwrap()))
}

fn read_u64(buf: &[u8], off: usize) -> Option<u64> {
    buf.get(off..off + 8)
        .map(|b| u64::from_le_bytes(b.try_into().unwrap()))
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;

    /// Bind a listener, snapshot natively, and find our own pid on the bound
    /// port — end-to-end proof the offsets are right on this kernel.
    #[test]
    fn native_snapshot_sees_own_listener() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().unwrap().port();

        let rows = snapshot().expect("pcblist_n sysctl should work unsandboxed");
        assert!(!rows.is_empty(), "no sockets at all?");

        let me = std::process::id();
        let mine = rows
            .iter()
            .find(|r| r.pid == Some(me) && r.local_addr.ends_with(&format!(".{port}")))
            .unwrap_or_else(|| {
                for r in &rows {
                    if r.pid == Some(me) || r.local_addr.contains(&port.to_string()) {
                        eprintln!("candidate: {r:?}");
                    }
                }
                eprintln!("total rows: {}", rows.len());
                panic!("own listener 127.0.0.1:{port} (pid {me}) not found")
            });
        assert!(mine.proto.starts_with("tcp"));
        assert_eq!(mine.state, Some("LISTEN"));
        assert_eq!(mine.local_addr, format!("127.0.0.1.{port}"));
        assert!(
            !mine.process_name.is_empty(),
            "process name should resolve for our own pid"
        );
    }

    /// TCP rows must carry a valid state string and UDP rows none.
    #[test]
    fn tcp_states_and_udp_statelessness() {
        let rows = snapshot().expect("pcblist_n");
        for r in &rows {
            if r.proto.starts_with("tcp") {
                if let Some(s) = r.state {
                    assert!(TCP_STATES.contains(&s));
                }
            } else {
                assert!(r.state.is_none(), "udp row has state {:?}", r.state);
            }
        }
    }
}
