//! PROXY protocol header builder (HAProxy PROXY protocol v1/v2).
//!
//! Port of Go frp v0.69.1 `pkg/util/net/proxyprotocol.go`.

use std::net::IpAddr;

/// Build a PROXY protocol v1 text header.
///
/// Produces `PROXY TCP4 <src> <dst> <sport> <dport>\r\n` for IPv4 pairs and
/// `PROXY TCP6 <src> <dst> <sport> <dport>\r\n` when either address is IPv6
/// (matching Go's go-proxyproto: the v1 family is chosen from the addresses).
pub fn build_proxy_protocol_v1(
    src_addr: &str,
    dst_addr: &str,
    src_port: u16,
    dst_port: u16,
) -> String {
    let family = match (src_addr.parse::<IpAddr>(), dst_addr.parse::<IpAddr>()) {
        (Ok(IpAddr::V4(_)), Ok(IpAddr::V4(_))) => "TCP4",
        // Mixed or IPv6 pairs use TCP6.
        _ => "TCP6",
    };
    format!(
        "PROXY {family} {} {} {} {}\r\n",
        src_addr, dst_addr, src_port, dst_port,
    )
}

/// Build a PROXY protocol v2 binary header.
///
/// Format: 12-byte signature + 4-byte header block + address block.
/// Supports TCPv4 (transport 0x11) and TCPv6 (transport 0x21).
pub fn build_proxy_protocol_v2(
    src_addr: &str,
    dst_addr: &str,
    src_port: u16,
    dst_port: u16,
) -> Result<Vec<u8>, String> {
    let src_ip: IpAddr = src_addr
        .parse()
        .map_err(|e| format!("v2 src_addr parse: {e}"))?;
    let dst_ip: IpAddr = dst_addr
        .parse()
        .map_err(|e| format!("v2 dst_addr parse: {e}"))?;

    let (transport_byte, addr_len) = match (&src_ip, &dst_ip) {
        (IpAddr::V4(_), IpAddr::V4(_)) => (0x11u8, 12u16),
        (IpAddr::V6(_), IpAddr::V6(_)) => (0x21u8, 36u16),
        _ => return Err("v2 PROXY: mismatched address families (IPv4/IPv6)".into()),
    };

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

/// Build a PROXY protocol header, picking v1 or v2 based on version string.
///
/// Returns the header bytes ready to write to a stream.
pub fn build_proxy_protocol_header(
    src_addr: &str,
    dst_addr: &str,
    src_port: u16,
    dst_port: u16,
    version: &str,
) -> Result<Vec<u8>, String> {
    match version {
        "v1" => Ok(build_proxy_protocol_v1(src_addr, dst_addr, src_port, dst_port).into_bytes()),
        "v2" => build_proxy_protocol_v2(src_addr, dst_addr, src_port, dst_port),
        _ => Err(format!("unknown PROXY protocol version: {version}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_v1_format() {
        let h = build_proxy_protocol_v1("10.0.0.1", "10.0.0.2", 1234, 5678);
        assert_eq!(h, "PROXY TCP4 10.0.0.1 10.0.0.2 1234 5678\r\n");
    }

    #[test]
    fn test_v1_ipv6_emits_tcp6() {
        // Either address being IPv6 selects TCP6 (Go go-proxyproto family).
        let h = build_proxy_protocol_v1("::1", "2001:db8::2", 1234, 5678);
        assert_eq!(h, "PROXY TCP6 ::1 2001:db8::2 1234 5678\r\n");
        // Mixed families also use TCP6.
        let mixed = build_proxy_protocol_v1("10.0.0.1", "::1", 1234, 5678);
        assert_eq!(mixed, "PROXY TCP6 10.0.0.1 ::1 1234 5678\r\n");
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
        let h = build_proxy_protocol_header("10.0.0.1", "10.0.0.2", 1, 2, "v1").unwrap();
        assert_eq!(h, b"PROXY TCP4 10.0.0.1 10.0.0.2 1 2\r\n");
    }

    #[test]
    fn test_unified_v2() {
        let h = build_proxy_protocol_header("10.0.0.1", "10.0.0.2", 1, 2, "v2").unwrap();
        assert_eq!(h.len(), 28);
    }

    #[test]
    fn test_unified_unknown_version() {
        let r = build_proxy_protocol_header("1.1.1.1", "2.2.2.2", 1, 2, "v3");
        assert!(r.is_err());
    }
}
