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

fn parse_binding_response(data: &[u8], expected_tx_id: &[u8; 12]) -> Result<String, String> {
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
            ATTR_MAPPED_ADDRESS => {
                if mapped.is_none() {
                    mapped = parse_mapped_address(value);
                }
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
