//! Minimal STUN client for NAT address discovery.
//! Sends STUN Binding Requests from multiple local ports to observe
//! NAT port-mapping behavior (consistent vs random).
//! Go frp v0.69.1 compat: pkg/nathole/discovery.go
//!
//! IPv4 only — STUN responses with IPv6 XOR-MAPPED-ADDRESS (family 0x02)
//! are not decoded. Production Go frp deployments use IPv4 STUN servers.

use std::collections::HashSet;
use std::net::{SocketAddr, UdpSocket};
use std::time::Duration;

/// STUN magic cookie (RFC 5389).
const MAGIC_COOKIE: [u8; 4] = [0x21, 0x12, 0xA4, 0x42];

/// Number of STUN probes from distinct local ports.
/// More probes = better NAT behavior classification.
const PROBE_COUNT: usize = 3;

/// Discover external addresses by querying a STUN server from multiple
/// local ports. Returns deduplicated "ip:port" strings.
/// Multi-port probing reveals whether NAT uses consistent vs random
/// port mapping — essential for classify_nat_feature().
pub fn discover(stun_server: &str) -> Result<Vec<String>, String> {
    let server_addr: SocketAddr = stun_server
        .parse()
        .map_err(|e| format!("invalid STUN server address '{}': {}", stun_server, e))?;

    let mut seen = HashSet::new();

    for probe in 0..PROBE_COUNT {
        // Each probe binds a fresh port — if NAT uses random port mapping,
        // each probe gets a different external port.
        let socket = UdpSocket::bind("0.0.0.0:0")
            .map_err(|e| format!("failed to bind UDP socket for STUN probe {}: {}", probe, e))?;
        socket
            .set_read_timeout(Some(Duration::from_secs(3)))
            .map_err(|e| format!("failed to set timeout on probe {}: {}", probe, e))?;

        let request = build_binding_request(probe);
        socket
            .send_to(&request, server_addr)
            .map_err(|e| format!("STUN send failed on probe {}: {}", probe, e))?;

        // Read response, validate source
        let mut buf = [0u8; 512];
        let (len, src) = socket
            .recv_from(&mut buf)
            .map_err(|e| format!("STUN recv failed on probe {}: {}", probe, e))?;

        // Security: reject responses from unexpected sources.
        if src != server_addr {
            return Err(format!(
                "STUN response from unexpected source {} (expected {})",
                src, server_addr
            ));
        }

        match parse_stun_response(&buf[..len]) {
            Ok(addr) => {
                seen.insert(addr);
            }
            Err(e) => {
                // Non-fatal per probe — one probe can fail while others succeed
                tracing::debug!("STUN probe {} failed to parse: {}", probe, e);
            }
        }
    }

    if seen.is_empty() {
        return Err("all STUN probes failed".into());
    }

    Ok(seen.into_iter().collect())
}

/// Build a minimal STUN Binding Request (20 bytes) with probe-specific
/// transaction ID so responses can be distinguished.
fn build_binding_request(probe: usize) -> Vec<u8> {
    let mut req = Vec::with_capacity(20);
    // Message type: Binding Request (0x0001)
    req.extend_from_slice(&[0x00, 0x01]);
    // Message length: 0 (no attributes)
    req.extend_from_slice(&[0x00, 0x00]);
    // Magic cookie
    req.extend_from_slice(&MAGIC_COOKIE);
    // Transaction ID (12 bytes) — probe index in first byte for uniqueness
    let mut tid = [0u8; 12];
    tid[0] = probe as u8;
    // Fill remaining with probe-specific pattern
    for i in 1..12 {
        tid[i] = (probe.wrapping_mul(17).wrapping_add(i)) as u8;
    }
    req.extend_from_slice(&tid);
    req
}

/// Parse XOR-MAPPED-ADDRESS (0x0020) from a STUN response.
/// Falls back to MAPPED-ADDRESS (0x0001).
/// IPv4 only — IPv6 family (0x02) is skipped.
fn parse_stun_response(data: &[u8]) -> Result<String, String> {
    if data.len() < 20 {
        return Err("response too short".into());
    }

    let msg_type = u16::from_be_bytes([data[0], data[1]]);
    if msg_type != 0x0101 {
        return Err(format!("unexpected message type: 0x{:04x}", msg_type));
    }

    let msg_len = u16::from_be_bytes([data[2], data[3]]) as usize;
    let attr_data = &data[20..(20 + msg_len).min(data.len())];

    let mut i = 0usize;
    while i + 4 <= attr_data.len() {
        let attr_type = u16::from_be_bytes([attr_data[i], attr_data[i + 1]]);
        let attr_len = u16::from_be_bytes([attr_data[i + 2], attr_data[i + 3]]) as usize;

        if i + 4 + attr_len > attr_data.len() {
            break;
        }

        match attr_type {
            0x0020 => {
                // XOR-MAPPED-ADDRESS (RFC 5389)
                if attr_len >= 8 && attr_data[i + 5] == 0x01 {
                    // IPv4 family
                    let port_x = u16::from_be_bytes([
                        attr_data[i + 6] ^ MAGIC_COOKIE[0],
                        attr_data[i + 7] ^ MAGIC_COOKIE[1],
                    ]);
                    let ip_x: Vec<u8> = attr_data[i + 8..i + 12]
                        .iter()
                        .enumerate()
                        .map(|(j, b)| b ^ MAGIC_COOKIE[j])
                        .collect();
                    return Ok(format!(
                        "{}.{}.{}.{}:{}",
                        ip_x[0], ip_x[1], ip_x[2], ip_x[3], port_x
                    ));
                }
                // IPv6 family (0x02) not decoded — production uses IPv4 STUN
            }
            0x0001 => {
                // MAPPED-ADDRESS (RFC 3489, deprecated but still used)
                if attr_len >= 8 && attr_data[i + 5] == 0x01 {
                    let port = u16::from_be_bytes([attr_data[i + 6], attr_data[i + 7]]);
                    let ip = &attr_data[i + 8..i + 12];
                    return Ok(format!("{}.{}.{}.{}:{}", ip[0], ip[1], ip[2], ip[3], port));
                }
            }
            _ => {}
        }

        // Advance to next attribute (aligned to 4 bytes)
        i += 4 + ((attr_len + 3) & !3);
    }

    Err("no mapped address in STUN response".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_binding_request() {
        let req = build_binding_request(0);
        assert_eq!(req.len(), 20);
        assert_eq!(&req[0..2], &[0x00, 0x01]); // Binding Request
        assert_eq!(&req[4..8], &MAGIC_COOKIE);
        assert_eq!(req[8], 0); // probe 0 in first tid byte
    }

    #[test]
    fn test_probes_have_different_tids() {
        let req0 = build_binding_request(0);
        let req1 = build_binding_request(1);
        let req2 = build_binding_request(2);
        assert_ne!(&req0[8..20], &req1[8..20]);
        assert_ne!(&req1[8..20], &req2[8..20]);
    }

    #[test]
    fn test_parse_xor_mapped_address() {
        // Minimal STUN Binding Success Response with XOR-MAPPED-ADDRESS
        let mut resp = Vec::new();
        resp.extend_from_slice(&[0x01, 0x01]); // Binding Success
        resp.extend_from_slice(&[0x00, 0x0c]); // Length: 12
        resp.extend_from_slice(&MAGIC_COOKIE);
        resp.extend_from_slice(&[0; 12]); // Transaction ID
        // XOR-MAPPED-ADDRESS attribute
        resp.extend_from_slice(&[0x00, 0x20]); // Type: XOR-MAPPED-ADDRESS
        resp.extend_from_slice(&[0x00, 0x08]); // Length: 8
        resp.extend_from_slice(&[0x00, 0x01]); // Family: IPv4
        // Port XOR magic cookie bytes 0-1: 1234 ^ 0x2112 = 0x0536
        resp.push(1234u16.to_be_bytes()[0] ^ MAGIC_COOKIE[0]);
        resp.push(1234u16.to_be_bytes()[1] ^ MAGIC_COOKIE[1]);
        // IP 1.2.3.4 XOR magic cookie
        resp.push(1 ^ MAGIC_COOKIE[0]);
        resp.push(2 ^ MAGIC_COOKIE[1]);
        resp.push(3 ^ MAGIC_COOKIE[2]);
        resp.push(4 ^ MAGIC_COOKIE[3]);

        let addr = parse_stun_response(&resp).unwrap();
        assert_eq!(addr, "1.2.3.4:1234");
    }
}
