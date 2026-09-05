//! PROXY protocol header builder (HAProxy PROXY protocol v1/v2).
//!
//! Port of Go frp v0.71.0 `pkg/util/net/proxyprotocol.go`, which delegates to
//! go-proxyproto v0.15.0 (`HeaderProxyFromAddrs`). The transport kind (TCP
//! stream vs UDP datagram) mirrors the `net.Addr` type Go hands the library:
//! TCP sessions produce `TCP4/TCP6` lines (v1) or transport bytes 0x11/0x21
//! (v2); UDP sessions produce `PROXY UNKNOWN` (v1 — the grammar has no UDP
//! line) or transport bytes 0x12/0x22 (v2).
//!
//! [`build_proxy_protocol_v1`]/[`build_proxy_protocol_v2`] are the TCP-stream
//! forms; UDP callers use [`build_proxy_protocol_header`] with
//! [`ProxyTransport::Udp`].

use std::net::IpAddr;

/// Transport the PROXY header describes (TCP stream vs UDP datagram).
///
/// go-proxyproto v0.15.0 derives both the v2 transport byte and the v1
/// address line from the `net.Addr` pair handed to `HeaderProxyFromAddrs`
/// (header.go): a `*net.TCPAddr` pair yields TCP and a `*net.UDPAddr` pair
/// yields UDP — v1 has no UDP line so it falls back to the short form
/// `PROXY UNKNOWN\r\n`, while v2 carries the datagram transport bytes
/// 0x12/0x22 (addr_proto.go).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ProxyTransport {
    /// TCP stream (`tcp`/`http`/`https`/`stcp`/`xtcp`/… proxies).
    Tcp,
    /// UDP datagram (`udp` proxies; the header prefixes the first packet of
    /// each remote session toward the local service).
    Udp,
}

/// TCP-stream form of the v1 builder (Go frp `client/proxy/proxy.go`
/// `HandleTCPWorkConnection`). UDP callers must use
/// [`build_proxy_protocol_header`] with [`ProxyTransport::Udp`] — the v1
/// grammar has no UDP address line, so UDP headers are the literal
/// `PROXY UNKNOWN\r\n` short form instead.
///
/// Produces `PROXY TCP4 <src> <dst> <sport> <dport>\r\n` for IPv4 pairs and
/// `PROXY TCP6 <src> <dst> <sport> <dport>\r\n` when either address is IPv6
/// (matching Go's go-proxyproto: the v1 family is chosen from the addresses).
///
/// Both addresses MUST parse as [`IpAddr`] — Go validates them via
/// `net.ResolveTCPAddr` (client/proxy/proxy.go) and skips the header on
/// failure. Rejecting unparsable addresses here also blocks header-injection
/// (a CRLF-bearing `src_addr` can never reach the wire verbatim).
pub fn build_proxy_protocol_v1(
    src_addr: &str,
    dst_addr: &str,
    src_port: u16,
    dst_port: u16,
) -> Result<String, String> {
    build_proxy_protocol_v1_with(src_addr, dst_addr, src_port, dst_port, ProxyTransport::Tcp)
}

fn build_proxy_protocol_v1_with(
    src_addr: &str,
    dst_addr: &str,
    src_port: u16,
    dst_port: u16,
    transport: ProxyTransport,
) -> Result<String, String> {
    if transport == ProxyTransport::Udp {
        // go-proxyproto v0.15.0 `formatVersion1`: the v1 grammar only knows
        // TCP4/TCP6, so any other transport — a *net.UDPAddr pair included —
        // falls to the short form `PROXY UNKNOWN\r\n` with NO addresses,
        // whatever family the addrs carry. The strings are deliberately NOT
        // parsed here: no address bytes can reach the wire, so a CRLF-bearing
        // string is inert rather than an injection (matching Go, which
        // inspects only the addr TYPE and cannot fail on this path).
        return Ok("PROXY UNKNOWN\r\n".to_string());
    }
    let src_ip: IpAddr = src_addr
        .parse()
        .map_err(|e| format!("v1 src_addr parse: {e}"))?;
    let dst_ip: IpAddr = dst_addr
        .parse()
        .map_err(|e| format!("v1 dst_addr parse: {e}"))?;
    let family = match (src_ip, dst_ip) {
        (IpAddr::V4(_), IpAddr::V4(_)) => "TCP4",
        // Mixed or IPv6 pairs use TCP6.
        _ => "TCP6",
    };
    Ok(format!(
        "PROXY {family} {} {} {} {}\r\n",
        src_addr, dst_addr, src_port, dst_port,
    ))
}

/// TCP-stream form of the v2 builder. UDP callers must use
/// [`build_proxy_protocol_header`] with [`ProxyTransport::Udp`], which emits
/// the UDP-DATAGRAM transport bytes 0x12/0x22 instead.
///
/// Format: 12-byte signature + 4-byte header block + address block.
/// Supports TCPv4 (transport 0x11) and TCPv6 (transport 0x21).
pub fn build_proxy_protocol_v2(
    src_addr: &str,
    dst_addr: &str,
    src_port: u16,
    dst_port: u16,
) -> Result<Vec<u8>, String> {
    build_proxy_protocol_v2_with(src_addr, dst_addr, src_port, dst_port, ProxyTransport::Tcp)
}

fn build_proxy_protocol_v2_with(
    src_addr: &str,
    dst_addr: &str,
    src_port: u16,
    dst_port: u16,
    transport: ProxyTransport,
) -> Result<Vec<u8>, String> {
    let src_ip: IpAddr = src_addr
        .parse()
        .map_err(|e| format!("v2 src_addr parse: {e}"))?;
    let dst_ip: IpAddr = dst_addr
        .parse()
        .map_err(|e| format!("v2 dst_addr parse: {e}"))?;

    // v2 transport byte layout (go-proxyproto addr_proto.go): the high
    // nibble is the address family (0x10 = AF_INET, 0x20 = AF_INET6) and the
    // low nibble the transport protocol (0x01 = STREAM/TCP, 0x02 =
    // DGRAM/UDP): TCPv4 0x11 / UDPv4 0x12 / TCPv6 0x21 / UDPv6 0x22. The
    // pre-fix builder hardcoded the TCP-STREAM bytes for UDP sessions too
    // (0x11/0x21), mislabeling every UDP PROXY v2 header as TCP.
    let (family_byte, addr_len) = match (&src_ip, &dst_ip) {
        (IpAddr::V4(_), IpAddr::V4(_)) => (0x10u8, 12u16),
        (IpAddr::V6(_), IpAddr::V6(_)) => (0x20u8, 36u16),
        _ => return Err("v2 PROXY: mismatched address families (IPv4/IPv6)".into()),
    };
    let proto_bit = match transport {
        ProxyTransport::Tcp => 0x01u8,
        ProxyTransport::Udp => 0x02u8,
    };
    let transport_byte = family_byte | proto_bit;

    let mut buf = Vec::with_capacity(16 + addr_len as usize);

    // 12-byte v2 signature
    buf.extend_from_slice(b"\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A");

    // 1 byte: version (0x20) | command (0x01 = PROXY)
    buf.push(0x21);

    // 1 byte: transport protocol
    buf.push(transport_byte);

    // 2 bytes: address length (big-endian)
    buf.extend_from_slice(&addr_len.to_be_bytes());

    // Address block
    match (&src_ip, &dst_ip) {
        (IpAddr::V4(s4), IpAddr::V4(d4)) => {
            buf.extend_from_slice(&s4.octets());
            buf.extend_from_slice(&d4.octets());
        }
        (IpAddr::V6(s6), IpAddr::V6(d6)) => {
            buf.extend_from_slice(&s6.octets());
            buf.extend_from_slice(&d6.octets());
        }
        // Guarded by the family check above; never panic on pub API input.
        _ => return Err("v2 PROXY: mismatched address families (IPv4/IPv6)".into()),
    }
    buf.extend_from_slice(&src_port.to_be_bytes());
    buf.extend_from_slice(&dst_port.to_be_bytes());

    Ok(buf)
}

/// Build a PROXY protocol header, picking v1 or v2 based on version string
/// and the transport kind (TCP stream vs UDP datagram).
///
/// Returns the header bytes ready to write to a stream.
pub fn build_proxy_protocol_header(
    src_addr: &str,
    dst_addr: &str,
    src_port: u16,
    dst_port: u16,
    version: &str,
    transport: ProxyTransport,
) -> Result<Vec<u8>, String> {
    match version {
        "v1" => build_proxy_protocol_v1_with(src_addr, dst_addr, src_port, dst_port, transport)
            .map(|s| s.into_bytes()),
        "v2" => build_proxy_protocol_v2_with(src_addr, dst_addr, src_port, dst_port, transport),
        _ => Err(format!("unknown PROXY protocol version: {version}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_v1_format() {
        let h = build_proxy_protocol_v1("10.0.0.1", "10.0.0.2", 1234, 5678).unwrap();
        assert_eq!(h, "PROXY TCP4 10.0.0.1 10.0.0.2 1234 5678\r\n");
    }

    #[test]
    fn test_v1_ipv6_emits_tcp6() {
        // Either address being IPv6 selects TCP6 (Go go-proxyproto family).
        let h = build_proxy_protocol_v1("::1", "2001:db8::2", 1234, 5678).unwrap();
        assert_eq!(h, "PROXY TCP6 ::1 2001:db8::2 1234 5678\r\n");
        // Mixed families also use TCP6.
        let mixed = build_proxy_protocol_v1("10.0.0.1", "::1", 1234, 5678).unwrap();
        assert_eq!(mixed, "PROXY TCP6 10.0.0.1 ::1 1234 5678\r\n");
    }

    #[test]
    fn test_v1_rejects_unparsable_addrs() {
        // M2 regression: Go resolves both addresses via net.ResolveTCPAddr
        // and SKIPS the header on failure (client/proxy/proxy.go:183-197).
        // A CRLF-bearing src_addr must never reach the wire verbatim — it
        // would let an attacker inject a second PROXY header / fake the
        // client address on the backend.
        let crlf = build_proxy_protocol_v1(
            "10.0.0.1\r\nPROXY TCP4 9.9.9.9 9.9.9.9 1 1",
            "10.0.0.2",
            1,
            2,
        );
        assert!(crlf.is_err(), "CRLF-bearing src_addr must be rejected");

        let hostname = build_proxy_protocol_v1("example.com", "10.0.0.2", 1, 2);
        assert!(hostname.is_err(), "hostname src_addr must be rejected");

        let bad_dst = build_proxy_protocol_v1("10.0.0.1", "not-an-ip\r\n", 1, 2);
        assert!(bad_dst.is_err(), "unparsable dst_addr must be rejected");

        // Ports are u16 already; a 0 port is rejected by the TCP caller gate
        // (Go `client/proxy/proxy.go` `m.SrcAddr != "" && m.SrcPort != 0`),
        // not here — the builder stays pure. The UDP path has no such gate
        // (`pkg/proto/udp/udp.go` Forwarder checks only `RemoteAddr != nil`).
        let ok = build_proxy_protocol_v1("10.0.0.1", "10.0.0.2", 0, 0).unwrap();
        assert_eq!(ok, "PROXY TCP4 10.0.0.1 10.0.0.2 0 0\r\n");
    }

    #[test]
    fn test_v2_tcpv4_binary() {
        let h = build_proxy_protocol_v2("10.0.0.1", "10.0.0.2", 1234, 5678).unwrap();
        // 12 sig + 4 hdr + 12 addr = 28 bytes
        assert_eq!(h.len(), 28);
        // Check signature
        assert_eq!(
            &h[..12],
            b"\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A"
        );
        // Version+command byte
        assert_eq!(h[12], 0x21);
        // Transport byte (TCPv4)
        assert_eq!(h[13], 0x11);
        // Address length (12)
        assert_eq!(u16::from_be_bytes([h[14], h[15]]), 12);
    }

    #[test]
    fn test_v2_tcpv6_binary() {
        let h = build_proxy_protocol_v2("::1", "::1", 8080, 9090).unwrap();
        // 12 sig + 4 hdr + 36 addr = 52 bytes
        assert_eq!(h.len(), 52);
        assert_eq!(h[13], 0x21); // TCPv6
        assert_eq!(u16::from_be_bytes([h[14], h[15]]), 36);
    }

    #[test]
    fn test_v2_mismatched_families() {
        let r = build_proxy_protocol_v2("10.0.0.1", "::1", 1, 2);
        assert!(r.is_err());
        assert!(r.unwrap_err().contains("mismatched"));
    }

    #[test]
    fn test_unified_v1() {
        let h =
            build_proxy_protocol_header("10.0.0.1", "10.0.0.2", 1, 2, "v1", ProxyTransport::Tcp)
                .unwrap();
        assert_eq!(h, b"PROXY TCP4 10.0.0.1 10.0.0.2 1 2\r\n");
        // The unified builder rejects unparsable addrs too (Go parity).
        let bad = build_proxy_protocol_header(
            "10.0.0.1\r\n",
            "10.0.0.2",
            1,
            2,
            "v1",
            ProxyTransport::Tcp,
        );
        assert!(bad.is_err(), "unified v1 must reject CRLF-bearing src_addr");
    }

    #[test]
    fn test_unified_v2() {
        let h =
            build_proxy_protocol_header("10.0.0.1", "10.0.0.2", 1, 2, "v2", ProxyTransport::Tcp)
                .unwrap();
        assert_eq!(h.len(), 28);
        // TCP regression guard: the unified builder must keep emitting the
        // TCP-STREAM transport byte for TCP inputs (0x11 — not 0x12).
        assert_eq!(h[13], 0x11);
    }

    #[test]
    fn test_unified_unknown_version() {
        let r = build_proxy_protocol_header("1.1.1.1", "2.2.2.2", 1, 2, "v3", ProxyTransport::Tcp);
        assert!(r.is_err());
    }

    #[test]
    fn test_udp_v1_emits_unknown_short_form() {
        // T2 (audit round 9): a PROXY v1 header for a UDP session. go-proxyproto
        // v0.15.0's formatVersion1 only knows TCP4/TCP6 — a *net.UDPAddr pair
        // (transport UDPv4/UDPv6) falls through to the short form, so the header
        // is the literal `PROXY UNKNOWN\r\n` with NO address block, whatever the
        // family (probe-verified against Go frp v0.71.0's go-proxyproto).
        let h = build_proxy_protocol_header(
            "10.0.0.1",
            "10.0.0.2",
            1234,
            5678,
            "v1",
            ProxyTransport::Udp,
        )
        .unwrap();
        assert_eq!(h, b"PROXY UNKNOWN\r\n");

        // Family-independent: an IPv6 pair yields the same short form.
        let h6 = build_proxy_protocol_header(
            "::1",
            "2001:db8::2",
            1234,
            5678,
            "v1",
            ProxyTransport::Udp,
        )
        .unwrap();
        assert_eq!(h6, b"PROXY UNKNOWN\r\n");

        // No address bytes ever reach the wire on this path: even a
        // CRLF-bearing src string collapses to the constant (Go hands typed
        // addrs to HeaderProxyFromAddrs and cannot fail on this path), so
        // there is no injection surface to guard.
        let hostile = build_proxy_protocol_header(
            "10.0.0.1\r\nPROXY TCP4 9.9.9.9 9.9.9.9 1 1",
            "10.0.0.2",
            1,
            2,
            "v1",
            ProxyTransport::Udp,
        )
        .unwrap();
        assert_eq!(hostile, b"PROXY UNKNOWN\r\n");
    }

    #[test]
    fn test_udp_v2_datagram_transport_bytes() {
        // T2 (audit round 9): a PROXY v2 header for a UDP session must carry
        // the UDP-DATAGRAM transport byte (UDPv4 0x12 / UDPv6 0x22 per
        // go-proxyproto addr_proto.go), NOT the TCP-STREAM bytes 0x11/0x21 the
        // shared builder hardcoded before (probe: Go frp v0.71.0 emits byte 13
        // = 0x12 for v2-UDP, 0x11 for v2-TCP). The address block layout is
        // identical to TCP's.
        let h = build_proxy_protocol_header(
            "10.0.0.1",
            "10.0.0.2",
            1234,
            5678,
            "v2",
            ProxyTransport::Udp,
        )
        .unwrap();
        // 12 sig + 4 hdr + 12 addr = 28 bytes
        assert_eq!(h.len(), 28);
        assert_eq!(
            &h[..12],
            b"\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A",
            "v2 signature"
        );
        assert_eq!(h[12], 0x21, "version+command byte");
        assert_eq!(h[13], 0x12, "UDPv4 transport byte (was TCPv4 0x11)");
        assert_eq!(u16::from_be_bytes([h[14], h[15]]), 12, "addr len");
        assert_eq!(&h[16..20], &[10, 0, 0, 1], "src IP");
        assert_eq!(&h[20..24], &[10, 0, 0, 2], "dst IP");
        assert_eq!(u16::from_be_bytes([h[24], h[25]]), 1234, "src port");
        assert_eq!(u16::from_be_bytes([h[26], h[27]]), 5678, "dst port");

        let h6 = build_proxy_protocol_header("::1", "::1", 8080, 9090, "v2", ProxyTransport::Udp)
            .unwrap();
        // 12 sig + 4 hdr + 36 addr = 52 bytes
        assert_eq!(h6.len(), 52);
        assert_eq!(h6[13], 0x22, "UDPv6 transport byte (was TCPv6 0x21)");
        assert_eq!(u16::from_be_bytes([h6[14], h6[15]]), 36, "addr len");
    }

    #[test]
    fn test_udp_v2_mismatched_families_rejected() {
        // Mixed IPv4/IPv6 pairs stay a hard error for UDP, uniform with the
        // v2 TCP path (Go's HeaderProxyFromAddrs would instead mislabel the
        // pair by its 16-byte forms — pre-existing frp-rs divergence for both
        // transports, kept consistent).
        let r = build_proxy_protocol_header("10.0.0.1", "::1", 1, 2, "v2", ProxyTransport::Udp);
        assert!(r.is_err());
        assert!(r.unwrap_err().contains("mismatched"));
    }
}
