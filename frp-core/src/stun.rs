//! Minimal STUN (RFC 5389) client for NAT traversal.
//! Implements Binding Request/Response, XOR-MAPPED-ADDRESS, and OTHER-ADDRESS parsing.
//! Go frp v0.70 dev compat: pkg/util/stun/stun.go, pkg/nathole/discovery.go

use rand::Rng;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use tokio::net::UdpSocket;
use tracing::debug;

/// RFC 5389 magic cookie.
const MAGIC_COOKIE: u32 = 0x2112A442;

/// STUN attribute types.
const ATTR_MAPPED_ADDRESS: u16 = 0x0001;
const ATTR_CHANGED_ADDRESS: u16 = 0x0005;
const ATTR_ERROR_CODE: u16 = 0x0009;
const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;
/// OTHER-ADDRESS / CHANGED-ADDRESS (RFC 5780).
/// Go frp uses this to get a second STUN server address for
/// dual-server NAT probing (discovery.go:114).
const ATTR_OTHER_ADDRESS: u16 = 0x802c;

/// Result of a STUN Binding Response, including the mapped address
/// and optionally an OTHER-ADDRESS for dual-server NAT probing.
#[derive(Debug)]
pub struct StunResult {
    /// The primary mapped (external) address from XOR-MAPPED-ADDRESS
    /// or MAPPED-ADDRESS attribute.
    pub mapped_addr: String,
    /// The OTHER-ADDRESS attribute (RFC 5780), if present.
    /// Go frp uses this to send a second STUN request to a
    /// different server IP for better NAT classification.
    pub other_addr: Option<String>,
}

/// Resolve `addr_str` ("host:port" or "ip:port") to a `SocketAddr`, performing
/// DNS lookup if needed.
async fn resolve_stun_addr(addr_str: &str) -> Result<SocketAddr, String> {
    if let Ok(sa) = addr_str.parse::<SocketAddr>() {
        return Ok(sa);
    }
    let addrs = tokio::net::lookup_host(addr_str.to_string())
        .await
        .map_err(|e| format!("STUN DNS lookup failed for '{}': {}", addr_str, e))?;
    addrs
        .into_iter()
        .next()
        .ok_or_else(|| format!("STUN DNS: no addresses found for '{}'", addr_str))
}

/// Bind a UDP socket matching the address family of `target`.
/// Tries the family-matching bind first, falls back to the other family.
async fn bind_matching_family(target: SocketAddr) -> Result<UdpSocket, String> {
    if target.is_ipv4() {
        match UdpSocket::bind("0.0.0.0:0").await {
            Ok(s) => Ok(s),
            Err(_) => UdpSocket::bind("[::]:0")
                .await
                .map_err(|e| format!("STUN socket bind: {e}")),
        }
    } else {
        match UdpSocket::bind("[::]:0").await {
            Ok(s) => Ok(s),
            Err(_) => UdpSocket::bind("0.0.0.0:0")
                .await
                .map_err(|e| format!("STUN socket bind: {e}")),
        }
    }
}

/// Send a STUN Binding Request to `stun_addr` (format: "stun:host:port" or "host:port").
/// Returns the mapped address as "ip:port".
pub async fn stun_binding(stun_addr: &str) -> Result<String, String> {
    let addr_str = stun_addr.strip_prefix("stun:").unwrap_or(stun_addr);
    let addr = resolve_stun_addr(addr_str).await?;
    let socket = bind_matching_family(addr).await?;

    let mut tx_id = [0u8; 12];
    rand::thread_rng().fill(&mut tx_id);
    let request = build_binding_request(&tx_id);

    socket
        .send_to(&request, addr)
        .await
        .map_err(|e| format!("STUN send: {e}"))?;
    debug!(addr = %addr, "STUN Binding Request sent to {}", addr);

    let mut buf = [0u8; 256];
    let (n, _src) = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        socket.recv_from(&mut buf),
    )
    .await
    .map_err(|_| "STUN response timeout".to_string())?
    .map_err(|e| format!("STUN recv: {e}"))?;

    if n < 20 {
        return Err("STUN response too short".into());
    }

    parse_binding_response(&buf[..n], &tx_id)
}

/// Run STUN on an already-bound UDP socket, returning the mapped address.
/// Useful for XTCP: run STUN twice on the same socket to get ≥2 mapped
/// addresses for NAT classification, then reuse the socket for hole punching.
pub async fn stun_binding_on_socket(socket: &UdpSocket, stun_addr: &str) -> Result<String, String> {
    let addr_str = stun_addr.strip_prefix("stun:").unwrap_or(stun_addr);
    let addr = resolve_stun_addr(addr_str).await?;

    let mut tx_id = [0u8; 12];
    rand::thread_rng().fill(&mut tx_id);
    let request = build_binding_request(&tx_id);

    socket
        .send_to(&request, addr)
        .await
        .map_err(|e| format!("STUN send: {e}"))?;

    let mut buf = [0u8; 256];
    let (n, _src) = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        socket.recv_from(&mut buf),
    )
    .await
    .map_err(|_| "STUN response timeout".to_string())?
    .map_err(|e| format!("STUN recv: {e}"))?;

    if n < 20 {
        return Err("STUN response too short".into());
    }

    parse_binding_response(&buf[..n], &tx_id)
}

/// Like `stun_binding`, but returns the bound UDP socket along with the
/// mapped address. The caller can reuse the socket for subsequent NAT hole
/// punching (XTCP P2P).
pub async fn stun_binding_with_socket(stun_addr: &str) -> Result<(UdpSocket, String), String> {
    let addr_str = stun_addr.strip_prefix("stun:").unwrap_or(stun_addr);
    let addr = resolve_stun_addr(addr_str).await?;
    let socket = bind_matching_family(addr).await?;

    let mut tx_id = [0u8; 12];
    rand::thread_rng().fill(&mut tx_id);
    let request = build_binding_request(&tx_id);

    socket
        .send_to(&request, addr)
        .await
        .map_err(|e| format!("STUN send: {e}"))?;
    debug!(addr = %addr, "STUN Binding Request sent to {}", addr);

    let mut buf = [0u8; 256];
    let (n, _src) = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        socket.recv_from(&mut buf),
    )
    .await
    .map_err(|_| "STUN response timeout".to_string())?
    .map_err(|e| format!("STUN recv: {e}"))?;

    if n < 20 {
        return Err("STUN response too short".into());
    }

    let mapped = parse_binding_response(&buf[..n], &tx_id)?;
    Ok((socket, mapped))
}

/// Like `stun_binding_with_socket`, but also returns the OTHER-ADDRESS attribute
/// if present (RFC 5780). Go frp uses this for dual-server NAT probing
/// (discovery.go:114-116): the first STUN response's other-address is used
/// as the target for a second STUN request.
pub async fn stun_binding_with_details(stun_addr: &str) -> Result<(UdpSocket, StunResult), String> {
    let addr_str = stun_addr.strip_prefix("stun:").unwrap_or(stun_addr);
    let addr = resolve_stun_addr(addr_str).await?;
    let socket = bind_matching_family(addr).await?;

    let mut tx_id = [0u8; 12];
    rand::thread_rng().fill(&mut tx_id);
    let request = build_binding_request(&tx_id);

    socket
        .send_to(&request, addr)
        .await
        .map_err(|e| format!("STUN send: {e}"))?;
    debug!(addr = %addr, "STUN Binding Request sent to {}", addr);

    let mut buf = [0u8; 256];
    let (n, _src) = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        socket.recv_from(&mut buf),
    )
    .await
    .map_err(|_| "STUN response timeout".to_string())?
    .map_err(|e| format!("STUN recv: {e}"))?;

    if n < 20 {
        return Err("STUN response too short".into());
    }

    let result = parse_binding_response_full(&buf[..n], &tx_id)?;
    Ok((socket, result))
}

fn build_binding_request(tx_id: &[u8; 12]) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(20);
    pkt.extend_from_slice(&0x0001u16.to_be_bytes());
    pkt.extend_from_slice(&0u16.to_be_bytes());
    pkt.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
    pkt.extend_from_slice(tx_id);
    pkt
}

pub fn parse_binding_response(data: &[u8], expected_tx_id: &[u8; 12]) -> Result<String, String> {
    let msg_type = u16::from_be_bytes([data[0], data[1]]);
    match msg_type {
        0x0101 => {} // Binding Success Response — continue parsing
        0x0111 => match parse_error_response(data, expected_tx_id) {
            Err(e) => return Err(e),
            Ok(_) => unreachable!(),
        },
        _ => return Err(format!("unexpected STUN message type: 0x{msg_type:04x}")),
    }

    let msg_len = u16::from_be_bytes([data[2], data[3]]) as usize;
    if data.len() < 20 + msg_len {
        return Err("STUN message truncated".into());
    }

    let cookie = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    if cookie != MAGIC_COOKIE {
        return Err(format!("bad magic cookie: 0x{cookie:08x}"));
    }

    if data[8..20] != *expected_tx_id {
        return Err("STUN transaction ID mismatch".into());
    }

    let attrs = &data[20..20 + msg_len];
    let mut mapped: Option<String> = None;
    let mut i = 0;
    while i + 4 <= attrs.len() {
        let attr_type = u16::from_be_bytes([attrs[i], attrs[i + 1]]);
        let attr_len = u16::from_be_bytes([attrs[i + 2], attrs[i + 3]]) as usize;
        let padding = (4 - (attr_len % 4)) % 4;
        let attr_end = i + 4 + attr_len;
        if attr_end > attrs.len() {
            break;
        }
        let value = &attrs[i + 4..attr_end];

        match attr_type {
            ATTR_XOR_MAPPED_ADDRESS => {
                if let Some(addr) = parse_xor_mapped_address(value, MAGIC_COOKIE, expected_tx_id) {
                    debug!(addr = %addr, "STUN XOR-MAPPED-ADDRESS: {}", addr);
                    return Ok(addr);
                }
            }
            ATTR_MAPPED_ADDRESS if mapped.is_none() => {
                mapped = parse_mapped_address(value);
            }
            _ => {}
        }
        i = attr_end + padding;
    }

    mapped.ok_or_else(|| "STUN response missing MAPPED-ADDRESS".into())
}

/// Parse a STUN Binding Response and return both mapped and other addresses.
/// This is used for dual-server NAT probing (Go frp discovery.go:114).
pub fn parse_binding_response_full(
    data: &[u8],
    expected_tx_id: &[u8; 12],
) -> Result<StunResult, String> {
    let msg_type = u16::from_be_bytes([data[0], data[1]]);
    match msg_type {
        0x0101 => {} // Binding Success Response — continue parsing
        0x0111 => match parse_error_response(data, expected_tx_id) {
            Err(e) => return Err(e),
            Ok(_) => unreachable!(),
        },
        _ => return Err(format!("unexpected STUN message type: 0x{msg_type:04x}")),
    }

    let msg_len = u16::from_be_bytes([data[2], data[3]]) as usize;
    if data.len() < 20 + msg_len {
        return Err("STUN message truncated".into());
    }

    let cookie = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    if cookie != MAGIC_COOKIE {
        return Err(format!("bad magic cookie: 0x{cookie:08x}"));
    }

    if data[8..20] != *expected_tx_id {
        return Err("STUN transaction ID mismatch".into());
    }

    let attrs = &data[20..20 + msg_len];
    let mut mapped: Option<String> = None;
    let mut other: Option<String> = None;
    let mut i = 0;
    while i + 4 <= attrs.len() {
        let attr_type = u16::from_be_bytes([attrs[i], attrs[i + 1]]);
        let attr_len = u16::from_be_bytes([attrs[i + 2], attrs[i + 3]]) as usize;
        let padding = (4 - (attr_len % 4)) % 4;
        let attr_end = i + 4 + attr_len;
        if attr_end > attrs.len() {
            break;
        }
        let value = &attrs[i + 4..attr_end];

        match attr_type {
            ATTR_XOR_MAPPED_ADDRESS => {
                if let Some(addr) = parse_xor_mapped_address(value, MAGIC_COOKIE, expected_tx_id) {
                    debug!(addr = %addr, "STUN XOR-MAPPED-ADDRESS: {}", addr);
                    mapped = Some(addr);
                }
            }
            ATTR_MAPPED_ADDRESS if mapped.is_none() => {
                mapped = parse_mapped_address(value);
            }
            ATTR_OTHER_ADDRESS | ATTR_CHANGED_ADDRESS => {
                // OTHER-ADDRESS (RFC 5780) and CHANGED-ADDRESS (RFC 3489)
                // both use XOR-MAPPED-ADDRESS encoding.
                if let Some(addr) = parse_xor_mapped_address(value, MAGIC_COOKIE, expected_tx_id) {
                    debug!(addr = %addr, "STUN OTHER/CHANGED-ADDRESS: {}", addr);
                    other = Some(addr);
                }
            }
            _ => {}
        }
        i = attr_end + padding;
    }

    let mapped_addr = mapped.ok_or_else(|| String::from("STUN response missing MAPPED-ADDRESS"))?;
    Ok(StunResult {
        mapped_addr,
        other_addr: other,
    })
}

/// Parse a STUN Binding Error Response (type 0x0111) and return a
/// human-readable error string including the error code and reason phrase.
fn parse_error_response(data: &[u8], expected_tx_id: &[u8; 12]) -> Result<String, String> {
    let msg_len = u16::from_be_bytes([data[2], data[3]]) as usize;
    if data.len() < 20 + msg_len {
        return Err("STUN error message truncated".into());
    }

    let cookie = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    if cookie != MAGIC_COOKIE {
        return Err(format!(
            "STUN error response: bad magic cookie: 0x{cookie:08x}"
        ));
    }

    if data[8..20] != *expected_tx_id {
        return Err("STUN error response: transaction ID mismatch".into());
    }

    let attrs = &data[20..20 + msg_len];
    let mut i = 0;
    while i + 4 <= attrs.len() {
        let attr_type = u16::from_be_bytes([attrs[i], attrs[i + 1]]);
        let attr_len = u16::from_be_bytes([attrs[i + 2], attrs[i + 3]]) as usize;
        let padding = (4 - (attr_len % 4)) % 4;
        let attr_end = i + 4 + attr_len;
        if attr_end > attrs.len() {
            break;
        }
        let value = &attrs[i + 4..attr_end];

        if attr_type == ATTR_ERROR_CODE && attr_len >= 4 {
            // ERROR-CODE: first 3 bits = 0 (reserved), next 5 bits = error class
            // (hundreds digit), next byte = error number (units digit).
            // Remaining bytes = UTF-8 reason phrase.
            let class = (value[2] & 0x07) as u32;
            let number = value[3] as u32;
            let code = class * 100 + number;
            let reason = if attr_len > 4 {
                String::from_utf8_lossy(&value[4..attr_len]).into_owned()
            } else {
                String::new()
            };
            return Err(format!(
                "STUN error response: {code} {reason}",
                reason = reason.trim()
            ));
        }
        i = attr_end + padding;
    }

    Err("STUN error response (no ERROR-CODE attribute)".into())
}

fn parse_mapped_address(data: &[u8]) -> Option<String> {
    if data.len() < 4 {
        return None;
    }
    let family = data[1];
    match family {
        0x01 => {
            if data.len() < 8 {
                return None;
            }
            let port = u16::from_be_bytes([data[2], data[3]]);
            let ip = Ipv4Addr::new(data[4], data[5], data[6], data[7]);
            Some(format!("{}:{}", ip, port))
        }
        0x02 => {
            if data.len() < 20 {
                return None;
            }
            let port = u16::from_be_bytes([data[2], data[3]]);
            let ip = Ipv6Addr::from(<[u8; 16]>::try_from(&data[4..20]).ok()?);
            Some(format!("[{}]:{}", ip, port))
        }
        _ => None,
    }
}

fn parse_xor_mapped_address(data: &[u8], cookie: u32, tx_id: &[u8; 12]) -> Option<String> {
    if data.len() < 4 {
        return None;
    }
    let family = data[1];
    let cookie_hi = (cookie >> 16) as u16;
    let port = u16::from_be_bytes([data[2], data[3]]) ^ cookie_hi;
    match family {
        0x01 => {
            if data.len() < 8 {
                return None;
            }
            let addr_bytes: [u8; 4] = [data[4], data[5], data[6], data[7]];
            let xored = u32::from_be_bytes(addr_bytes) ^ cookie;
            let ip = Ipv4Addr::from(xored);
            Some(format!("{}:{}", ip, port))
        }
        0x02 => {
            // IPv6 XOR-MAPPED-ADDRESS (RFC 5389 §15.2):
            // XOR key = magic_cookie (4 bytes) || transaction_id (12 bytes)
            if data.len() < 20 {
                return None;
            }
            let mut ip_bytes = [0u8; 16];
            ip_bytes.copy_from_slice(&data[4..20]);
            let mut key = [0u8; 16];
            key[..4].copy_from_slice(&cookie.to_be_bytes());
            key[4..].copy_from_slice(tx_id);
            for i in 0..16 {
                ip_bytes[i] ^= key[i];
            }
            let ip = Ipv6Addr::from(ip_bytes);
            Some(format!("[{}]:{}", ip, port))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_binding_request() {
        let tx_id = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
        ];
        let pkt = build_binding_request(&tx_id);
        assert_eq!(pkt.len(), 20);
        assert_eq!(u16::from_be_bytes([pkt[0], pkt[1]]), 0x0001);
        assert_eq!(u16::from_be_bytes([pkt[2], pkt[3]]), 0);
        assert_eq!(
            u32::from_be_bytes([pkt[4], pkt[5], pkt[6], pkt[7]]),
            MAGIC_COOKIE
        );
        assert_eq!(&pkt[8..20], &tx_id);
    }

    #[test]
    fn test_parse_mapped_address_ipv4() {
        let data = [0x00, 0x01, 0x1F, 0x90, 192, 168, 1, 1];
        let result = parse_mapped_address(&data);
        assert_eq!(result, Some("192.168.1.1:8080".to_string()));
    }

    #[test]
    fn test_parse_mapped_address_ipv6() {
        let mut data = vec![0x00, 0x02, 0x1F, 0x90];
        data.extend_from_slice(&[
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
        ]);
        let result = parse_mapped_address(&data);
        assert_eq!(result, Some("[2001:db8::1]:8080".to_string()));
    }

    #[test]
    fn test_parse_mapped_address_too_short() {
        assert_eq!(parse_mapped_address(&[0x00, 0x01, 0x1F]), None);
        assert_eq!(
            parse_mapped_address(&[0x00, 0x01, 0x1F, 0x90, 192, 168]),
            None
        );
        assert_eq!(parse_mapped_address(&[0x00, 0x02, 0x1F, 0x90]), None);
    }

    #[test]
    fn test_parse_mapped_address_unknown_family() {
        let data = [0x00, 0x03, 0x1F, 0x90, 0, 0, 0, 0];
        assert_eq!(parse_mapped_address(&data), None);
    }

    #[test]
    fn test_parse_xor_mapped_address_ipv4() {
        let cookie: u32 = 0x2112A442;
        let cookie_hi = (cookie >> 16) as u16;
        let real_port: u16 = 8080;
        let xored_port = real_port ^ cookie_hi;
        let real_ip: [u8; 4] = [10, 0, 0, 1];
        let real_ip_u32 = u32::from_be_bytes(real_ip);
        let xored_ip = real_ip_u32 ^ cookie;

        let mut data = vec![0x00, 0x01];
        data.extend_from_slice(&xored_port.to_be_bytes());
        data.extend_from_slice(&xored_ip.to_be_bytes());

        let result = parse_xor_mapped_address(&data, cookie, &[0u8; 12]);
        assert_eq!(result, Some("10.0.0.1:8080".to_string()));
    }

    #[test]
    fn test_parse_xor_mapped_address_too_short() {
        assert_eq!(
            parse_xor_mapped_address(&[0x00, 0x01, 0x1F], MAGIC_COOKIE, &[0u8; 12]),
            None
        );
        assert_eq!(
            parse_xor_mapped_address(&[0x00, 0x01, 0x1F, 0x90, 10, 0], MAGIC_COOKIE, &[0u8; 12]),
            None
        );
    }

    #[test]
    fn test_parse_xor_mapped_address_unknown_family() {
        let data = [0x00, 0x03, 0x1F, 0x90, 0, 0, 0, 0];
        assert_eq!(
            parse_xor_mapped_address(&data, MAGIC_COOKIE, &[0u8; 12]),
            None
        );
    }

    fn build_binding_response(tx_id: &[u8; 12], attrs: &[u8]) -> Vec<u8> {
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&0x0101u16.to_be_bytes());
        pkt.extend_from_slice(&(attrs.len() as u16).to_be_bytes());
        pkt.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        pkt.extend_from_slice(tx_id);
        pkt.extend_from_slice(attrs);
        pkt
    }

    fn build_xor_mapped_attr(ip: &[u8; 4], port: u16) -> Vec<u8> {
        let cookie = MAGIC_COOKIE;
        let cookie_hi = (cookie >> 16) as u16;
        let xored_port = port ^ cookie_hi;
        let ip_u32 = u32::from_be_bytes(*ip);
        let xored_ip = ip_u32 ^ cookie;

        let mut attr = Vec::new();
        attr.extend_from_slice(&ATTR_XOR_MAPPED_ADDRESS.to_be_bytes());
        attr.extend_from_slice(&8u16.to_be_bytes());
        attr.push(0x00);
        attr.push(0x01);
        attr.extend_from_slice(&xored_port.to_be_bytes());
        attr.extend_from_slice(&xored_ip.to_be_bytes());
        attr
    }

    fn build_other_addr_attr(ip: &[u8; 4], port: u16) -> Vec<u8> {
        let cookie = MAGIC_COOKIE;
        let cookie_hi = (cookie >> 16) as u16;
        let xored_port = port ^ cookie_hi;
        let ip_u32 = u32::from_be_bytes(*ip);
        let xored_ip = ip_u32 ^ cookie;

        let mut attr = Vec::new();
        attr.extend_from_slice(&ATTR_OTHER_ADDRESS.to_be_bytes());
        attr.extend_from_slice(&8u16.to_be_bytes());
        attr.push(0x00);
        attr.push(0x01);
        attr.extend_from_slice(&xored_port.to_be_bytes());
        attr.extend_from_slice(&xored_ip.to_be_bytes());
        attr
    }

    #[test]
    fn test_parse_binding_response_full_with_other_addr() {
        let tx_id = [0xBB; 12];
        let mapped_attr = build_xor_mapped_attr(&[10, 20, 30, 40], 12345);
        let other_attr = build_other_addr_attr(&[192, 168, 1, 1], 3478);
        let mut combined = mapped_attr;
        combined.extend_from_slice(&other_attr);
        let pkt = build_binding_response(&tx_id, &combined);

        let result = parse_binding_response_full(&pkt, &tx_id).unwrap();
        assert_eq!(result.mapped_addr, "10.20.30.40:12345");
        assert_eq!(result.other_addr, Some("192.168.1.1:3478".to_string()));
    }

    #[test]
    fn test_parse_binding_response_full_no_other_addr() {
        let tx_id = [0xCC; 12];
        let attr = build_xor_mapped_attr(&[10, 20, 30, 40], 12345);
        let pkt = build_binding_response(&tx_id, &attr);

        let result = parse_binding_response_full(&pkt, &tx_id).unwrap();
        assert_eq!(result.mapped_addr, "10.20.30.40:12345");
        assert_eq!(result.other_addr, None);
    }

    #[test]
    fn test_parse_binding_response_full_other_addr_mapped_fallback() {
        // OTHER-ADDRESS present, but no XOR-MAPPED-ADDRESS → fall back to MAPPED-ADDRESS
        let tx_id = [0xDD; 12];
        let mapped_attr = {
            let mut attr = Vec::new();
            attr.extend_from_slice(&ATTR_MAPPED_ADDRESS.to_be_bytes());
            attr.extend_from_slice(&8u16.to_be_bytes());
            attr.push(0x00);
            attr.push(0x01);
            attr.extend_from_slice(&8080u16.to_be_bytes());
            attr.extend_from_slice(&[10, 0, 0, 1]);
            attr
        };
        let other_attr = build_other_addr_attr(&[192, 168, 1, 1], 3478);
        let mut combined = mapped_attr;
        combined.extend_from_slice(&other_attr);
        let pkt = build_binding_response(&tx_id, &combined);

        let result = parse_binding_response_full(&pkt, &tx_id).unwrap();
        assert_eq!(result.mapped_addr, "10.0.0.1:8080");
        assert_eq!(result.other_addr, Some("192.168.1.1:3478".to_string()));
    }

    #[test]
    fn test_parse_binding_response_success() {
        let tx_id = [0xAA; 12];
        let attr = build_xor_mapped_attr(&[10, 20, 30, 40], 12345);
        let pkt = build_binding_response(&tx_id, &attr);

        let result = parse_binding_response(&pkt, &tx_id);
        assert_eq!(result, Ok("10.20.30.40:12345".to_string()));
    }

    #[test]
    fn test_parse_binding_response_wrong_type() {
        let tx_id = [0xBB; 12];
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&0x0001u16.to_be_bytes());
        pkt.extend_from_slice(&0u16.to_be_bytes());
        pkt.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        pkt.extend_from_slice(&tx_id);

        let result = parse_binding_response(&pkt, &tx_id);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("unexpected STUN message type"));
    }

    #[test]
    fn test_parse_binding_response_bad_cookie() {
        let tx_id = [0xCC; 12];
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&0x0101u16.to_be_bytes());
        pkt.extend_from_slice(&0u16.to_be_bytes());
        pkt.extend_from_slice(&0xDEADBEEFu32.to_be_bytes());
        pkt.extend_from_slice(&tx_id);

        let result = parse_binding_response(&pkt, &tx_id);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("bad magic cookie"));
    }

    #[test]
    fn test_parse_binding_response_tx_id_mismatch() {
        let tx_id = [0x11; 12];
        let other_id = [0x22; 12];
        let attr = build_xor_mapped_attr(&[1, 2, 3, 4], 80);
        let pkt = build_binding_response(&tx_id, &attr);

        let result = parse_binding_response(&pkt, &other_id);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("transaction ID mismatch"));
    }

    #[test]
    fn test_parse_binding_response_truncated() {
        let tx_id = [0xDD; 12];
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&0x0101u16.to_be_bytes());
        pkt.extend_from_slice(&0u16.to_be_bytes());
        pkt.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        pkt.extend_from_slice(&tx_id);

        let mut pkt2 = pkt.clone();
        pkt2[2] = 0x00;
        pkt2[3] = 0x10;
        let result = parse_binding_response(&pkt2, &tx_id);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("truncated"));

        let result = parse_binding_response(&pkt, &tx_id);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("missing MAPPED-ADDRESS"));
    }

    #[test]
    fn test_parse_binding_response_too_short() {
        // 20-byte header claims 10 bytes of attrs, but only header present
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&0x0101u16.to_be_bytes());
        pkt.extend_from_slice(&10u16.to_be_bytes()); // claims 10 bytes of attributes
        pkt.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        pkt.extend_from_slice(&[0u8; 12]);
        // No attributes — data is shorter than 20 + 10
        let result = parse_binding_response(&pkt, &[0u8; 12]);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("truncated"));
    }

    // --- IPv6 XOR-MAPPED-ADDRESS tests ---

    #[test]
    fn test_parse_xor_mapped_address_ipv6() {
        // XOR key = cookie (4 bytes) || tx_id (12 bytes) = 16 bytes
        let cookie: u32 = 0x2112A442;
        let tx_id: [u8; 12] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
        ];
        let mut key = [0u8; 16];
        key[..4].copy_from_slice(&cookie.to_be_bytes());
        key[4..].copy_from_slice(&tx_id);

        let real_ip: [u8; 16] = [
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
        ];
        let cookie_hi = (cookie >> 16) as u16;
        let real_port: u16 = 8080;
        let xored_port = real_port ^ cookie_hi;
        let mut xored_ip = [0u8; 16];
        for i in 0..16 {
            xored_ip[i] = real_ip[i] ^ key[i];
        }

        let mut data = vec![0x00, 0x02]; // family = IPv6
        data.extend_from_slice(&xored_port.to_be_bytes());
        data.extend_from_slice(&xored_ip);

        let result = parse_xor_mapped_address(&data, cookie, &tx_id);
        assert_eq!(result, Some("[2001:db8::1]:8080".to_string()));
    }

    #[test]
    fn test_parse_xor_mapped_address_ipv6_too_short() {
        let data = [0x00, 0x02, 0x1F, 0x90, 0, 0, 0, 0]; // only 8 bytes, need 20
        assert_eq!(
            parse_xor_mapped_address(&data, MAGIC_COOKIE, &[0u8; 12]),
            None
        );
    }

    #[test]
    fn test_parse_binding_response_xor_ipv6() {
        let tx_id = [0xEE; 12];
        let cookie = MAGIC_COOKIE;
        let mut key = [0u8; 16];
        key[..4].copy_from_slice(&cookie.to_be_bytes());
        key[4..].copy_from_slice(&tx_id);

        let real_ip: [u8; 16] = [
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
        ];
        let cookie_hi = (cookie >> 16) as u16;
        let real_port: u16 = 443;
        let xored_port = real_port ^ cookie_hi;
        let mut xored_ip = [0u8; 16];
        for i in 0..16 {
            xored_ip[i] = real_ip[i] ^ key[i];
        }

        let mut attr = Vec::new();
        attr.extend_from_slice(&ATTR_XOR_MAPPED_ADDRESS.to_be_bytes());
        attr.extend_from_slice(&20u16.to_be_bytes()); // 4 + 16 bytes
        attr.push(0x00);
        attr.push(0x02); // IPv6
        attr.extend_from_slice(&xored_port.to_be_bytes());
        attr.extend_from_slice(&xored_ip);

        let pkt = build_binding_response(&tx_id, &attr);
        let result = parse_binding_response(&pkt, &tx_id).unwrap();
        assert_eq!(result, "[2001:db8::1]:443");
    }

    // --- CHANGED-ADDRESS fallback test ---

    #[test]
    fn test_parse_binding_response_full_changed_address_fallback() {
        let tx_id = [0xFF; 12];
        let cookie = MAGIC_COOKIE;
        let cookie_hi = (cookie >> 16) as u16;

        // Build XOR-MAPPED-ADDRESS for the primary mapped address
        let mapped_ip: [u8; 4] = [10, 20, 30, 40];
        let mapped_port: u16 = 12345;
        let xored_mapped_port = mapped_port ^ cookie_hi;
        let mapped_ip_u32 = u32::from_be_bytes(mapped_ip);
        let xored_mapped_ip = mapped_ip_u32 ^ cookie;
        let mut mapped_attr = Vec::new();
        mapped_attr.extend_from_slice(&ATTR_XOR_MAPPED_ADDRESS.to_be_bytes());
        mapped_attr.extend_from_slice(&8u16.to_be_bytes());
        mapped_attr.push(0x00);
        mapped_attr.push(0x01);
        mapped_attr.extend_from_slice(&xored_mapped_port.to_be_bytes());
        mapped_attr.extend_from_slice(&xored_mapped_ip.to_be_bytes());

        // Build CHANGED-ADDRESS (0x0005) as the second server address
        let changed_ip: [u8; 4] = [192, 168, 1, 1];
        let changed_port: u16 = 3478;
        let xored_changed_port = changed_port ^ cookie_hi;
        let changed_ip_u32 = u32::from_be_bytes(changed_ip);
        let xored_changed_ip = changed_ip_u32 ^ cookie;
        let mut changed_attr = Vec::new();
        changed_attr.extend_from_slice(&ATTR_CHANGED_ADDRESS.to_be_bytes());
        changed_attr.extend_from_slice(&8u16.to_be_bytes());
        changed_attr.push(0x00);
        changed_attr.push(0x01);
        changed_attr.extend_from_slice(&xored_changed_port.to_be_bytes());
        changed_attr.extend_from_slice(&xored_changed_ip.to_be_bytes());

        let mut combined = mapped_attr;
        combined.extend_from_slice(&changed_attr);
        let pkt = build_binding_response(&tx_id, &combined);

        let result = parse_binding_response_full(&pkt, &tx_id).unwrap();
        assert_eq!(result.mapped_addr, "10.20.30.40:12345");
        // CHANGED-ADDRESS should be picked up as the other_addr (RFC 3489 fallback)
        assert_eq!(result.other_addr, Some("192.168.1.1:3478".to_string()));
    }

    // --- STUN Error Response tests ---

    fn build_error_response(tx_id: &[u8; 12], code: u32, reason: &str) -> Vec<u8> {
        let class = (code / 100) as u8;
        let number = (code % 100) as u8;
        let reason_bytes = reason.as_bytes();
        // ERROR-CODE attribute: 4 + reason length (padded to 4-byte boundary)
        let attr_value_len = 4 + reason_bytes.len();
        let padding = (4 - (attr_value_len % 4)) % 4;
        let attr_len = attr_value_len + padding;

        let mut pkt = Vec::new();
        pkt.extend_from_slice(&0x0111u16.to_be_bytes()); // type = Binding Error Response
        pkt.extend_from_slice(&((4 + attr_len) as u16).to_be_bytes()); // length
        pkt.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        pkt.extend_from_slice(tx_id);
        // ERROR-CODE attribute TLV
        pkt.extend_from_slice(&ATTR_ERROR_CODE.to_be_bytes());
        pkt.extend_from_slice(&(attr_value_len as u16).to_be_bytes());
        pkt.push(0x00);
        pkt.push(0x00);
        pkt.push(class & 0x07);
        pkt.push(number);
        pkt.extend_from_slice(reason_bytes);
        // padding
        if padding > 0 {
            pkt.extend(std::iter::repeat_n(0x00, padding));
        }
        pkt
    }

    #[test]
    fn test_parse_error_response_unknown_attribute() {
        let tx_id = [0xAB; 12];
        let pkt = build_error_response(&tx_id, 420, "Unknown Attribute");
        let result = parse_binding_response(&pkt, &tx_id);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.contains("420"), "expected error code 420, got: {err}");
        assert!(
            err.contains("Unknown Attribute"),
            "expected reason, got: {err}"
        );
    }

    #[test]
    fn test_parse_error_response_server_error() {
        let tx_id = [0xCD; 12];
        let pkt = build_error_response(&tx_id, 500, "Server Error");
        let result = parse_binding_response_full(&pkt, &tx_id);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.contains("500"), "expected error code 500, got: {err}");
    }

    #[test]
    fn test_parse_error_response_truncated() {
        let tx_id = [0xEF; 12];
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&0x0111u16.to_be_bytes());
        pkt.extend_from_slice(&100u16.to_be_bytes()); // claims 100 bytes
        pkt.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        pkt.extend_from_slice(&tx_id);
        // no actual attributes
        let result = parse_binding_response(&pkt, &tx_id);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("truncated"));
    }
}
