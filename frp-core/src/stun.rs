//! Minimal STUN (RFC 5389) client for NAT traversal.
//! Only implements Binding Request/Response and XOR-MAPPED-ADDRESS parsing.
//! Go frp v0.69.1 compat: pkg/util/stun/stun.go

use std::net::{SocketAddr, Ipv4Addr, Ipv6Addr};
use tokio::net::UdpSocket;
use rand::Rng;
use tracing::debug;

/// RFC 5389 magic cookie.
const MAGIC_COOKIE: u32 = 0x2112A442;

/// STUN attribute types.
const ATTR_MAPPED_ADDRESS: u16 = 0x0001;
const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;

/// Send a STUN Binding Request to `stun_addr` (format: "stun:host:port" or "host:port").
/// Returns the mapped address as "ip:port".
pub async fn stun_binding(stun_addr: &str) -> Result<String, String> {
    let addr_str = stun_addr.strip_prefix("stun:").unwrap_or(stun_addr);
    let addr: SocketAddr = addr_str
        .parse()
        .map_err(|e| format!("invalid STUN address '{}': {}", stun_addr, e))?;

    let socket = UdpSocket::bind("0.0.0.0:0")
        .await
        .map_err(|e| format!("STUN socket bind: {e}"))?;

    let mut tx_id = [0u8; 12];
    rand::thread_rng().fill(&mut tx_id);
    let request = build_binding_request(&tx_id);

    socket
        .send_to(&request, addr)
        .await
        .map_err(|e| format!("STUN send: {e}"))?;
    debug!("STUN Binding Request sent to {}", addr);

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
    if msg_type != 0x0101 {
        return Err(format!("unexpected STUN message type: 0x{msg_type:04x}"));
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
                if let Some(addr) = parse_xor_mapped_address(value, MAGIC_COOKIE) {
                    debug!("STUN XOR-MAPPED-ADDRESS: {}", addr);
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

fn parse_xor_mapped_address(data: &[u8], cookie: u32) -> Option<String> {
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
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_binding_request() {
        let tx_id = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c];
        let pkt = build_binding_request(&tx_id);
        assert_eq!(pkt.len(), 20);
        assert_eq!(u16::from_be_bytes([pkt[0], pkt[1]]), 0x0001);
        assert_eq!(u16::from_be_bytes([pkt[2], pkt[3]]), 0);
        assert_eq!(u32::from_be_bytes([pkt[4], pkt[5], pkt[6], pkt[7]]), MAGIC_COOKIE);
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
        data.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01]);
        let result = parse_mapped_address(&data);
        assert_eq!(result, Some("[2001:db8::1]:8080".to_string()));
    }

    #[test]
    fn test_parse_mapped_address_too_short() {
        assert_eq!(parse_mapped_address(&[0x00, 0x01, 0x1F]), None);
        assert_eq!(parse_mapped_address(&[0x00, 0x01, 0x1F, 0x90, 192, 168]), None);
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

        let result = parse_xor_mapped_address(&data, cookie);
        assert_eq!(result, Some("10.0.0.1:8080".to_string()));
    }

    #[test]
    fn test_parse_xor_mapped_address_too_short() {
        assert_eq!(parse_xor_mapped_address(&[0x00, 0x01, 0x1F], MAGIC_COOKIE), None);
        assert_eq!(parse_xor_mapped_address(&[0x00, 0x01, 0x1F, 0x90, 10, 0], MAGIC_COOKIE), None);
    }

    #[test]
    fn test_parse_xor_mapped_address_unknown_family() {
        let data = [0x00, 0x03, 0x1F, 0x90, 0, 0, 0, 0];
        assert_eq!(parse_xor_mapped_address(&data, MAGIC_COOKIE), None);
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
}
