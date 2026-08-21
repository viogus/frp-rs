//! Binary codec for UDPPacket message bodies, negotiated under wire protocol
//! v2 via the `udpPacketCodecs` capability (Go frp v0.71.0, codec name
//! `binary-v1`).
//!
//! Wire format of the codec body (carried inside a V2 message frame with
//! type ID 19, `V2_TYPE_UDP_PACKET_BINARY`):
//!
//! ```text
//! [flags: 1B]              bit0 = local addr present, bit1 = remote addr present
//! [localAddr: optional]    binaryUDPAddr, present iff flags & 0x01
//! [remoteAddr: required]   binaryUDPAddr, present iff flags & 0x02
//! [payloadLen: 2B BE]      UDP payload length (<= 65507)
//! [payload: payloadLen B]
//! ```
//!
//! `binaryUDPAddr`:
//! ```text
//! [family: 1B]            4 = IPv4, 6 = IPv6
//! [ip: 4B | 16B]
//! [port: 2B BE]
//! [zoneLen: 1B]           IPv6 scope zone string length
//! [zone: zoneLen B]       IPv6 only; IPv4 zone must be empty
//! ```
//!
//! Matches Go frp v0.71.0 `pkg/msg/udp_binary.go`.

use crate::msg::{UDPPacket, UdpAddr};

/// Maximum UDP payload length carried in one packet (Go: MaxUDPPayloadSize).
pub const MAX_UDP_PAYLOAD_SIZE: usize = 65_507;

const UDP_PACKET_FLAG_LOCAL_ADDR: u8 = 1 << 0;
const UDP_PACKET_FLAG_REMOTE_ADDR: u8 = 1 << 1;
const UDP_PACKET_VALID_FLAGS: u8 = UDP_PACKET_FLAG_LOCAL_ADDR | UDP_PACKET_FLAG_REMOTE_ADDR;

/// Codec name advertised/selected during the V2 handshake (Go: wire.UDPPacketCodecBinary).
pub const UDP_PACKET_CODEC_BINARY: &str = "binary-v1";

#[derive(Debug, Clone, PartialEq, Eq)]
struct BinaryUdpAddr {
    family: u8,
    ip: Vec<u8>,
    port: u16,
    zone: String,
}

impl BinaryUdpAddr {
    fn len(&self) -> usize {
        1 + self.ip.len() + 2 + 1 + self.zone.len()
    }
}

fn addr_to_binary(addr: &UdpAddr) -> Result<BinaryUdpAddr, String> {
    if addr.port == 0 && addr.ip.is_empty() {
        // Zero-valued UdpAddr (e.g. a default-constructed placeholder) has no
        // valid encoding; treat as error rather than emitting garbage.
        return Err("empty UDP address".into());
    }
    let ip = addr
        .ip
        .parse::<std::net::IpAddr>()
        .map_err(|e| format!("invalid UDP address IP '{}': {e}", addr.ip))?;
    match ip {
        std::net::IpAddr::V4(v4) => {
            if !addr.zone.is_empty() {
                return Err("IPv4 zone is forbidden".into());
            }
            Ok(BinaryUdpAddr {
                family: 4,
                ip: v4.octets().to_vec(),
                port: addr.port,
                zone: String::new(),
            })
        }
        std::net::IpAddr::V6(v6) => {
            if addr.zone.len() > 255 {
                return Err("zone exceeds 255 bytes".into());
            }
            if !addr.zone.is_ascii() {
                // Go checks UTF-8 validity; scope zones are ascii in practice,
                // and we mirror the rejection of non-UTF-8 zone strings.
                return Err("zone is not valid UTF-8".into());
            }
            Ok(BinaryUdpAddr {
                family: 6,
                ip: v6.octets().to_vec(),
                port: addr.port,
                zone: addr.zone.clone(),
            })
        }
    }
}

fn put_addr(buf: &mut Vec<u8>, addr: &BinaryUdpAddr) {
    buf.push(addr.family);
    buf.extend_from_slice(&addr.ip);
    buf.extend_from_slice(&addr.port.to_be_bytes());
    buf.push(addr.zone.len() as u8);
    buf.extend_from_slice(addr.zone.as_bytes());
}

fn read_addr(body: &[u8], offset: usize) -> Result<(UdpAddr, usize), String> {
    let err = |msg: String| format!("UDP binary address at offset {offset}: {msg}");
    if body.len() - offset < 4 {
        return Err(err("truncated address header".into()));
    }
    let family = body[offset];
    let ip_len = match family {
        4 => 4usize,
        6 => 16usize,
        f => return Err(err(format!("invalid address family {f}"))),
    };
    if body.len() - offset < 4 + ip_len {
        return Err(err("truncated address".into()));
    }
    let ip_start = offset + 1;
    let ip = &body[ip_start..ip_start + ip_len];
    let port = u16::from_be_bytes([body[ip_start + ip_len], body[ip_start + ip_len + 1]]);
    let zone_len = body[ip_start + ip_len + 2] as usize;
    if body.len() - offset < 4 + ip_len + zone_len {
        return Err(err("truncated zone".into()));
    }
    let zone = std::str::from_utf8(&body[ip_start + ip_len + 3..ip_start + ip_len + 3 + zone_len])
        .map_err(|e| err(format!("invalid zone UTF-8: {e}")))?
        .to_string();
    let ip = match family {
        4 => {
            if !zone.is_empty() {
                return Err(err("IPv4 zone is forbidden".into()));
            }
            format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3])
        }
        6 => {
            let octets: [u8; 16] = ip.try_into().expect("16-byte IPv6 slice");
            std::net::Ipv6Addr::from(octets).to_string()
        }
        _ => unreachable!("family validated above"),
    };
    Ok((
        UdpAddr { ip, port, zone },
        offset + 3 + ip_len + zone_len + 1,
    ))
}

/// Convenience wrapper: encode into a fresh Vec.
pub fn encode_udp_packet_binary(packet: &UDPPacket) -> Result<Vec<u8>, String> {
    let mut body = Vec::new();
    encode_udp_packet_binary_into(packet, &mut body)?;
    Ok(body)
}

/// Encode a UDPPacket into the binary codec body (the payload following the
/// 2-byte type ID inside a V2 message frame), appending after any existing
/// content of `out`. Callers that encode packet after packet reuse one buffer
/// and pay the allocation once per bridge, not once per packet.
///
/// RemoteAddr is required (Go: EncodeUDPPacketBinary errors without it).
pub fn encode_udp_packet_binary_into(packet: &UDPPacket, out: &mut Vec<u8>) -> Result<(), String> {
    let remote = packet
        .remote_addr
        .as_ref()
        .ok_or("UDP packet missing remote address")?;
    if packet.content.len() > MAX_UDP_PAYLOAD_SIZE {
        return Err(format!(
            "UDP payload length {} exceeds limit {MAX_UDP_PAYLOAD_SIZE}",
            packet.content.len()
        ));
    }
    let mut flags = UDP_PACKET_FLAG_REMOTE_ADDR;
    let mut body_len = 1 + 2 + packet.content.len();
    let local = if let Some(l) = packet.local_addr.as_ref() {
        flags |= UDP_PACKET_FLAG_LOCAL_ADDR;
        let b = addr_to_binary(l)?;
        body_len += b.len();
        Some(b)
    } else {
        None
    };
    let remote_b = addr_to_binary(remote)?;
    body_len += remote_b.len();
    // Go bounds the whole frame payload at DefaultMaxFramePayloadSize (64 KiB);
    // the 2 is the type-id prefix. Mirror the check so oversized bodies fail
    // before the frame layer would.
    if 2 + body_len > crate::protocol::V2_MAX_FRAME_PAYLOAD as usize {
        return Err(format!(
            "v2 frame payload length {} exceeds limit {}",
            2 + body_len,
            crate::protocol::V2_MAX_FRAME_PAYLOAD
        ));
    }

    let start = out.len();
    out.reserve(body_len);
    out.push(flags);
    if let Some(l) = local {
        put_addr(out, &l);
    }
    put_addr(out, &remote_b);
    out.extend_from_slice(&(packet.content.len() as u16).to_be_bytes());
    out.extend_from_slice(&packet.content);
    debug_assert_eq!(out.len() - start, body_len);
    Ok(())
}

/// Decode a UDPPacket from a binary codec body.
pub fn decode_udp_packet_binary(body: &[u8]) -> Result<UDPPacket, String> {
    if body.len() < 3 {
        return Err(format!("UDP packet body too short: {}", body.len()));
    }
    if 2 + body.len() > crate::protocol::V2_MAX_FRAME_PAYLOAD as usize {
        return Err(format!(
            "v2 frame payload length {} exceeds limit {}",
            2 + body.len(),
            crate::protocol::V2_MAX_FRAME_PAYLOAD
        ));
    }
    let flags = body[0];
    if flags & !UDP_PACKET_VALID_FLAGS != 0 {
        return Err(format!("reserved UDP packet flags set: {flags:#04x}"));
    }
    if flags & UDP_PACKET_FLAG_REMOTE_ADDR == 0 {
        return Err("UDP packet missing remote address".into());
    }
    let mut offset = 1usize;
    let local_addr = if flags & UDP_PACKET_FLAG_LOCAL_ADDR != 0 {
        let (a, o) = read_addr(body, offset)?;
        offset = o;
        Some(a)
    } else {
        None
    };
    let (remote_addr, o) = read_addr(body, offset)?;
    offset = o;
    if body.len() - offset < 2 {
        return Err("truncated UDP payload length".into());
    }
    let payload_len = u16::from_be_bytes([body[offset], body[offset + 1]]) as usize;
    offset += 2;
    if payload_len > MAX_UDP_PAYLOAD_SIZE {
        return Err(format!(
            "UDP payload length {payload_len} exceeds limit {MAX_UDP_PAYLOAD_SIZE}"
        ));
    }
    let remaining = body.len() - offset;
    if remaining < payload_len {
        return Err(format!(
            "truncated UDP payload: have {remaining} want {payload_len}"
        ));
    }
    if remaining > payload_len {
        return Err(format!(
            "trailing UDP packet bytes: {}",
            remaining - payload_len
        ));
    }
    Ok(UDPPacket {
        content: body[offset..offset + payload_len].to_vec(),
        local_addr,
        remote_addr: Some(remote_addr),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_packet() -> UDPPacket {
        UDPPacket {
            content: b"hello".to_vec(),
            local_addr: Some(UdpAddr {
                ip: "127.0.0.1".into(),
                port: 53001,
                zone: String::new(),
            }),
            remote_addr: Some(UdpAddr {
                ip: "10.0.0.2".into(),
                port: 53,
                zone: String::new(),
            }),
        }
    }

    #[test]
    fn roundtrip_v4() {
        let pkt = sample_packet();
        let body = encode_udp_packet_binary(&pkt).unwrap();
        let out = decode_udp_packet_binary(&body).unwrap();
        assert_eq!(out.content, pkt.content);
        assert_eq!(out.local_addr, pkt.local_addr);
        assert_eq!(out.remote_addr, pkt.remote_addr);
    }

    #[test]
    fn roundtrip_v6_with_zone() {
        let pkt = UDPPacket {
            content: vec![1u8, 2, 3],
            local_addr: None,
            remote_addr: Some(UdpAddr {
                ip: "fe80::1".into(),
                port: 8080,
                zone: "eth0".into(),
            }),
        };
        let body = encode_udp_packet_binary(&pkt).unwrap();
        let out = decode_udp_packet_binary(&body).unwrap();
        assert_eq!(out.remote_addr.as_ref().unwrap().ip, "fe80::1");
        assert_eq!(out.remote_addr.as_ref().unwrap().port, 8080);
        assert_eq!(out.remote_addr.as_ref().unwrap().zone, "eth0");
        assert!(out.local_addr.is_none());
    }

    #[test]
    fn empty_local_addr_ok_remote_required() {
        let pkt = UDPPacket {
            content: vec![],
            local_addr: None,
            remote_addr: Some(UdpAddr {
                ip: "192.168.1.1".into(),
                port: 9,
                zone: String::new(),
            }),
        };
        let body = encode_udp_packet_binary(&pkt).unwrap();
        let out = decode_udp_packet_binary(&body).unwrap();
        assert_eq!(out.content, Vec::<u8>::new());
        assert_eq!(out.remote_addr.as_ref().unwrap().port, 9);
    }

    #[test]
    fn missing_remote_rejected() {
        let pkt = UDPPacket {
            content: vec![1],
            local_addr: None,
            remote_addr: None,
        };
        assert!(encode_udp_packet_binary(&pkt).is_err());
    }

    #[test]
    fn malformed_rejected() {
        // Truncated: flags + remote flag but no address bytes.
        assert!(decode_udp_packet_binary(&[UDP_PACKET_FLAG_REMOTE_ADDR, 0, 0]).is_err());
        // Reserved flag bit set.
        let mut body = encode_udp_packet_binary(&sample_packet()).unwrap();
        body[0] |= 0x80;
        assert!(decode_udp_packet_binary(&body).is_err());
        // Trailing bytes after payload.
        let mut body = encode_udp_packet_binary(&sample_packet()).unwrap();
        body.push(0);
        assert!(decode_udp_packet_binary(&body).is_err());
        // Payload length mismatch.
        let mut body = encode_udp_packet_binary(&sample_packet()).unwrap();
        let payload_len_at = body.len() - 1 - 5; // content "hello" = 5 bytes
        body[payload_len_at] = 0xFF;
        assert!(decode_udp_packet_binary(&body).is_err());
    }

    #[test]
    fn oversized_payload_rejected() {
        let pkt = UDPPacket {
            content: vec![0u8; MAX_UDP_PAYLOAD_SIZE + 1],
            local_addr: None,
            remote_addr: Some(UdpAddr {
                ip: "127.0.0.1".into(),
                port: 1,
                zone: String::new(),
            }),
        };
        assert!(encode_udp_packet_binary(&pkt).is_err());
    }
}
