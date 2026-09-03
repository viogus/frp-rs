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
            // Go frp's validateBinaryUDPAddr applies net.IP.To4() first: an
            // IPv4-mapped IPv6 address (e.g. the JSON string
            // "::ffff:192.168.0.1") is normalized to family 4 with the
            // 4-byte dotted-quad form on the wire, never family 6 (review
            // finding C1 — Go parity).
            if let Some(v4) = v6.to_ipv4_mapped() {
                if !addr.zone.is_empty() {
                    return Err("IPv4 zone is forbidden".into());
                }
                return Ok(BinaryUdpAddr {
                    family: 4,
                    ip: v4.octets().to_vec(),
                    port: addr.port,
                    zone: String::new(),
                });
            }
            if addr.zone.len() > 255 {
                return Err("zone exceeds 255 bytes".into());
            }
            // Go validates the zone with utf8.ValidString (udp_binary.go:160-162)
            // and accepts any valid UTF-8 — scope zones need not be ASCII. The
            // zone here is a Rust String, so valid UTF-8 is guaranteed by
            // construction and no check is needed: non-ASCII valid-UTF-8 zones
            // (e.g. "接口") encode exactly as Go does (review finding W1). The
            // byte-length cap above matches Go's `len(addr.Zone) > 255`.
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
    let local_b = packet.local_addr.as_ref().map(addr_to_binary).transpose()?;
    let remote_b = addr_to_binary(remote)?;
    encode_body(&packet.content, local_b.as_ref(), &remote_b, out)
}

/// Encode a UDP packet whose remote address is a `SocketAddr` directly into
/// the binary codec body, appending after any existing content of `out`.
///
/// Equivalent to [`encode_udp_packet_binary_into`] with `remote_addr` built
/// from `remote.ip().to_string()`, but skips that per-packet String alloc and
/// the re-parse in [`addr_to_binary`]: the caller (frp-server UDP bridge
/// writer) already holds a parsed `SocketAddr` on the V2 binary path, where
/// the String form exists only for the V1 JSON codec. Output is byte-identical
/// to the string round trip.
pub fn encode_udp_packet_binary_socket_addr(
    content: &[u8],
    local: Option<&UdpAddr>,
    remote: &std::net::SocketAddr,
    out: &mut Vec<u8>,
) -> Result<(), String> {
    if content.len() > MAX_UDP_PAYLOAD_SIZE {
        return Err(format!(
            "UDP payload length {} exceeds limit {MAX_UDP_PAYLOAD_SIZE}",
            content.len()
        ));
    }
    let local_b = local.map(addr_to_binary).transpose()?;
    let remote_b = socket_addr_to_binary(remote);
    encode_body(content, local_b.as_ref(), &remote_b, out)
}

/// Shared body writer: flags, optional local addr, required remote addr,
/// payload length, payload. Error precedence (missing remote → oversized
/// payload → invalid local addr → invalid remote addr → frame-size cap)
/// matches the callers' original ordering.
fn encode_body(
    content: &[u8],
    local: Option<&BinaryUdpAddr>,
    remote: &BinaryUdpAddr,
    out: &mut Vec<u8>,
) -> Result<(), String> {
    let mut flags = UDP_PACKET_FLAG_REMOTE_ADDR;
    let mut body_len = 1 + 2 + content.len();
    if let Some(l) = local {
        flags |= UDP_PACKET_FLAG_LOCAL_ADDR;
        body_len += l.len();
    }
    body_len += remote.len();
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
        put_addr(out, l);
    }
    put_addr(out, remote);
    out.extend_from_slice(&(content.len() as u16).to_be_bytes());
    out.extend_from_slice(content);
    debug_assert_eq!(out.len() - start, body_len);
    Ok(())
}

/// Convert a parsed `SocketAddr` to its binaryUDPAddr form without the
/// `ip.to_string()` + re-parse round trip. A `SocketAddr` is always valid
/// (no error paths — no empty IP, no zone), and `SocketAddrV6`'s scope id
/// is never rendered by `Ipv6Addr::to_string()`, so the resulting bytes are
/// exactly what [`addr_to_binary`] would produce for the string form.
fn socket_addr_to_binary(addr: &std::net::SocketAddr) -> BinaryUdpAddr {
    match addr {
        std::net::SocketAddr::V4(v4) => BinaryUdpAddr {
            family: 4,
            ip: v4.ip().octets().to_vec(),
            port: v4.port(),
            zone: String::new(),
        },
        std::net::SocketAddr::V6(v6) => {
            // Same To4() normalization as [`addr_to_binary`]: a dual-stack
            // socket recv of an IPv4 peer yields an IPv4-mapped address,
            // which must go on the wire as family 4 (Go parity, review
            // finding C1).
            if let Some(v4) = v6.ip().to_ipv4_mapped() {
                BinaryUdpAddr {
                    family: 4,
                    ip: v4.octets().to_vec(),
                    port: v6.port(),
                    zone: String::new(),
                }
            } else {
                BinaryUdpAddr {
                    family: 6,
                    ip: v6.ip().octets().to_vec(),
                    port: v6.port(),
                    zone: String::new(),
                }
            }
        }
    }
}

/// Decode a UDPPacket from a binary codec body.
pub fn decode_udp_packet_binary(body: &[u8]) -> Result<UDPPacket, String> {
    let h = parse_udp_packet_header(body)?;
    Ok(UDPPacket {
        content: body[h.payload_offset..h.payload_offset + h.payload_len].to_vec(),
        local_addr: h.local_addr,
        remote_addr: Some(h.remote_addr),
    })
}

/// Decode a UDPPacket from an owned binary codec body. For large datagrams
/// (payload ≥ [`crate::buffer_pool::BUFFER_SIZE`]) ownership of the buffer is
/// taken: the packet's `content` IS the input buffer (payload memmoved to the
/// front, buffer truncated to the payload), so the per-packet allocation +
/// copy of [`decode_udp_packet_binary`] is avoided and the caller's scratch is
/// emptied. For typical smaller payloads the payload is copied out and `body`
/// is left intact for reuse across frames. On error the buffer is left
/// untouched and still owned by the caller.
///
/// The parse is byte-for-byte the same as [`decode_udp_packet_binary`] (same
/// checks, same error strings). When the buffer was taken (empty on return),
/// the caller should refill for the next read (the V2 UDP read path
/// re-acquires from `frp_core::buffer_pool::BUFFER_POOL`).
pub fn decode_udp_packet_binary_owned(body: &mut Vec<u8>) -> Result<UDPPacket, String> {
    let h = parse_udp_packet_header(body)?;
    // Steady-state path (review finding M2): copy the payload out and keep
    // `body` in the caller's loop — the buffer pool is untouched, zero alloc
    // per packet. Only for large datagrams (payload ≥ the 32 KiB pool buffer,
    // where the copy would double the packet cost) is the buffer moved into
    // the packet; that buffer then never returns to the pool, so the pool
    // drains at most one buffer per large datagram — acceptable, they are
    // the rare case (UDP payloads are typically ≤ 1.5 KiB MTU-sized).
    let content = if h.payload_len < *crate::buffer_pool::BUFFER_SIZE {
        body[h.payload_offset..h.payload_offset + h.payload_len].to_vec()
    } else {
        // The trailing-bytes check guarantees `payload_offset + payload_len
        // == body.len()`, so the payload is exactly the buffer tail: move it
        // to the front and truncate — one in-place memmove, zero allocation.
        body.copy_within(h.payload_offset.., 0);
        body.truncate(h.payload_len);
        std::mem::take(body)
    };
    Ok(UDPPacket {
        content,
        local_addr: h.local_addr,
        remote_addr: Some(h.remote_addr),
    })
}

/// Parsed header of a binary codec body (everything before the payload).
struct DecodedHeader {
    local_addr: Option<UdpAddr>,
    remote_addr: UdpAddr,
    payload_len: usize,
    /// Offset within the body of the first payload byte.
    payload_offset: usize,
}

/// Shared body parser: flags, optional local addr, required remote addr,
/// payload length — all strictness checks and error strings live here.
fn parse_udp_packet_header(body: &[u8]) -> Result<DecodedHeader, String> {
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
    Ok(DecodedHeader {
        local_addr,
        remote_addr,
        payload_len,
        payload_offset: offset,
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
    fn roundtrip_v6_with_unicode_zone() {
        // Go accepts any valid-UTF-8 zone (utf8.ValidString, udp_binary.go:160-162);
        // a Rust String is always valid UTF-8, so a non-ASCII zone must encode and
        // round-trip — the old is_ascii() check rejected it (review finding W1).
        let pkt = UDPPacket {
            content: vec![1u8, 2, 3],
            local_addr: None,
            remote_addr: Some(UdpAddr {
                ip: "fe80::1".into(),
                port: 8080,
                zone: "接口".into(),
            }),
        };
        let body = encode_udp_packet_binary(&pkt).unwrap();
        let out = decode_udp_packet_binary(&body).unwrap();
        assert_eq!(out.remote_addr.as_ref().unwrap().ip, "fe80::1");
        assert_eq!(out.remote_addr.as_ref().unwrap().port, 8080);
        assert_eq!(out.remote_addr.as_ref().unwrap().zone, "接口");
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

    /// Per-branch malformed decode table: every strictness check in
    /// `parse_udp_packet_header`/`read_addr` must return Err (with the
    /// branch's error text), never panic and never silently succeed.
    #[test]
    fn malformed_decode_branch_errors() {
        let ipv4 = [192u8, 168, 0, 1];
        let ipv6 = [0u8; 16];

        let mut truncated_zone = vec![UDP_PACKET_FLAG_REMOTE_ADDR, 6];
        truncated_zone.extend_from_slice(&ipv6);
        truncated_zone.extend_from_slice(&8080u16.to_be_bytes());
        truncated_zone.push(10); // zone_len claims 10...
        truncated_zone.extend_from_slice(b"abc"); // ...but only 3 bytes follow

        let mut ipv4_with_zone = vec![UDP_PACKET_FLAG_REMOTE_ADDR, 4];
        ipv4_with_zone.extend_from_slice(&ipv4);
        ipv4_with_zone.extend_from_slice(&53u16.to_be_bytes());
        ipv4_with_zone.push(1);
        ipv4_with_zone.push(b'z');

        let mut bad_utf8_zone = vec![UDP_PACKET_FLAG_REMOTE_ADDR, 6];
        bad_utf8_zone.extend_from_slice(&ipv6);
        bad_utf8_zone.extend_from_slice(&8080u16.to_be_bytes());
        bad_utf8_zone.push(2);
        bad_utf8_zone.extend_from_slice(&[0xFF, 0xFE]); // invalid UTF-8

        let mut oversized_payload_len = vec![UDP_PACKET_FLAG_REMOTE_ADDR, 4];
        oversized_payload_len.extend_from_slice(&ipv4);
        oversized_payload_len.extend_from_slice(&53u16.to_be_bytes());
        oversized_payload_len.push(0); // empty zone
        oversized_payload_len.extend_from_slice(&65535u16.to_be_bytes()); // > 65507

        // Valid address prefix, then only 1 of the 2 payload-length bytes.
        let mut truncated_len_field = vec![UDP_PACKET_FLAG_REMOTE_ADDR, 4];
        truncated_len_field.extend_from_slice(&ipv4);
        truncated_len_field.extend_from_slice(&53u16.to_be_bytes());
        truncated_len_field.push(0); // empty zone
        truncated_len_field.push(0x00);

        // Valid length field declaring 5 bytes, only 2 follow.
        let mut truncated_payload = vec![UDP_PACKET_FLAG_REMOTE_ADDR, 4];
        truncated_payload.extend_from_slice(&ipv4);
        truncated_payload.extend_from_slice(&53u16.to_be_bytes());
        truncated_payload.push(0); // empty zone
        truncated_payload.extend_from_slice(&5u16.to_be_bytes());
        truncated_payload.extend_from_slice(&[0xDE, 0xAD]);

        let cases: Vec<(&str, Vec<u8>, &str)> = vec![
            ("empty body", vec![], "too short"),
            (
                "one-byte body",
                vec![UDP_PACKET_FLAG_REMOTE_ADDR],
                "too short",
            ),
            (
                "two-byte body",
                vec![UDP_PACKET_FLAG_REMOTE_ADDR, 0],
                "too short",
            ),
            (
                "invalid address family",
                vec![UDP_PACKET_FLAG_REMOTE_ADDR, 7, 0, 0, 0],
                "invalid address family",
            ),
            (
                "truncated mid-IP",
                vec![UDP_PACKET_FLAG_REMOTE_ADDR, 4, 192, 168],
                "truncated address",
            ),
            ("truncated mid-zone", truncated_zone, "truncated zone"),
            (
                "IPv4 with non-empty zone",
                ipv4_with_zone,
                "IPv4 zone is forbidden",
            ),
            ("invalid UTF-8 zone", bad_utf8_zone, "invalid zone UTF-8"),
            (
                "payload length above 65507",
                oversized_payload_len,
                "exceeds limit",
            ),
            (
                "length field truncated to one byte",
                truncated_len_field,
                "truncated UDP payload length",
            ),
            (
                "declared payload truncated",
                truncated_payload,
                "truncated UDP payload",
            ),
        ];

        for (name, body, expected) in cases {
            let err = decode_udp_packet_binary(&body)
                .err()
                .unwrap_or_else(|| panic!("{name} must be rejected, not panic"));
            assert!(
                err.contains(expected),
                "{name}: expected error containing {expected:?}, got {err:?}"
            );
            // The owned decode path shares the parser — same rejection.
            let mut owned = body.clone();
            assert!(
                decode_udp_packet_binary_owned(&mut owned).is_err(),
                "{name}: owned decode must reject too"
            );
        }
    }

    /// Encode-side branch errors: empty (zero-valued) addresses and
    /// over-long zones must be rejected, never panic or emit garbage.
    #[test]
    fn malformed_encode_branch_errors() {
        let empty = UDPPacket {
            content: vec![],
            local_addr: None,
            remote_addr: Some(UdpAddr {
                ip: String::new(),
                port: 0,
                zone: String::new(),
            }),
        };
        let err = encode_udp_packet_binary(&empty).unwrap_err();
        assert!(err.contains("empty UDP address"), "got {err:?}");

        let big_zone = UDPPacket {
            content: vec![],
            local_addr: None,
            remote_addr: Some(UdpAddr {
                ip: "fe80::1".into(),
                port: 8080,
                zone: "a".repeat(256),
            }),
        };
        let err = encode_udp_packet_binary(&big_zone).unwrap_err();
        assert!(err.contains("zone exceeds 255 bytes"), "got {err:?}");

        // A non-empty zone on an IPv4 address is also rejected on encode
        // (Go validateBinaryUDPAddr parity).
        let v4_zone = UDPPacket {
            content: vec![],
            local_addr: None,
            remote_addr: Some(UdpAddr {
                ip: "192.168.0.1".into(),
                port: 53,
                zone: "eth0".into(),
            }),
        };
        let err = encode_udp_packet_binary(&v4_zone).unwrap_err();
        assert!(err.contains("IPv4 zone is forbidden"), "got {err:?}");
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

    #[test]
    fn owned_decode_matches_slice_decode_and_consumes_buffer() {
        // Typical packet (payload < BUFFER_SIZE): copied out, caller's
        // scratch buffer left intact so the read loop reuses it (the pool is
        // untouched — review finding M2).
        let pkt = sample_packet();
        let body = encode_udp_packet_binary(&pkt).unwrap();
        let expected = decode_udp_packet_binary(&body).unwrap();
        let mut owned = body.clone();
        let out = decode_udp_packet_binary_owned(&mut owned).unwrap();
        assert_eq!(out.content, expected.content);
        assert_eq!(out.local_addr, expected.local_addr);
        assert_eq!(out.remote_addr, expected.remote_addr);
        assert_eq!(out.content, pkt.content);
        assert_eq!(
            owned, body,
            "small payload must leave the caller's buffer intact"
        );

        // Large datagram (payload ≥ BUFFER_SIZE): the packet content IS the
        // caller's buffer — ownership moved out, caller must refill.
        let big = UDPPacket {
            content: vec![0xabu8; *crate::buffer_pool::BUFFER_SIZE],
            local_addr: None,
            remote_addr: Some(UdpAddr {
                ip: "127.0.0.1".into(),
                port: 1,
                zone: String::new(),
            }),
        };
        let mut owned = encode_udp_packet_binary(&big).unwrap();
        let out = decode_udp_packet_binary_owned(&mut owned).unwrap();
        assert_eq!(out.content, big.content);
        assert!(owned.is_empty(), "large payload must consume the buffer");
    }

    #[test]
    fn owned_decode_error_leaves_buffer_untouched() {
        let pkt = sample_packet();
        let mut body = encode_udp_packet_binary(&pkt).unwrap();
        body.push(0); // trailing byte -> parse error
        let before = body.clone();
        assert!(decode_udp_packet_binary_owned(&mut body).is_err());
        assert_eq!(body, before, "failed decode must not consume the buffer");
    }

    #[test]
    fn socket_addr_encode_is_byte_identical_to_string_round_trip() {
        // The direct-SocketAddr encoder must produce the same bytes as the
        // UdpAddr-string round trip the V1/JSON path uses — this is the
        // Rust↔Rust + Rust↔Go V2 interop invariant.
        for addr in [
            "127.0.0.1:53001",
            "10.0.0.2:53",
            "[::1]:8080",
            "[fe80::1]:5353",
            "[::ffff:192.168.0.1]:12345",
        ] {
            let sa: std::net::SocketAddr = addr.parse().unwrap();
            let pkt = UDPPacket {
                content: b"ping".to_vec(),
                local_addr: Some(UdpAddr {
                    ip: "127.0.0.1".into(),
                    port: 1,
                    zone: String::new(),
                }),
                remote_addr: Some(UdpAddr {
                    ip: sa.ip().to_string(),
                    port: sa.port(),
                    zone: String::new(),
                }),
            };
            let mut via_string = Vec::new();
            encode_udp_packet_binary_into(&pkt, &mut via_string).unwrap();
            let mut direct = Vec::new();
            encode_udp_packet_binary_socket_addr(
                &pkt.content,
                pkt.local_addr.as_ref(),
                &sa,
                &mut direct,
            )
            .unwrap();
            assert_eq!(direct, via_string, "address {addr}");
        }
    }

    #[test]
    fn ipv4_mapped_encodes_as_family_4() {
        // Go frp's validateBinaryUDPAddr applies net.IP.To4() first: an
        // IPv4-mapped IPv6 address must go on the wire as family 4 with the
        // 4-byte dotted-quad form, never family 6 (review finding C1).
        let sa: std::net::SocketAddr = "[::ffff:192.168.0.1]:12345".parse().unwrap();
        let mut buf = Vec::new();
        encode_udp_packet_binary_socket_addr(b"ping", None, &sa, &mut buf).unwrap();
        // Layout: [flags=0] [family] [ip bytes] [port] [zone len] [zone] ...
        assert_eq!(buf[1], 4, "mapped address must encode as family 4");
        assert_eq!(&buf[2..6], &[192, 168, 0, 1], "4-byte dotted-quad form");
        assert_eq!(buf[6..8], 12345u16.to_be_bytes(), "port");
    }

    /// Round M1 decode-side pin: a peer that puts an IPv4-mapped address on
    /// the wire as family 6 (16-byte form — Go's readBinaryUDPAddr performs
    /// NO To4 normalization on decode, unlike validateBinaryUDPAddr on
    /// encode) must decode to the mapped textual form Go's net.UDPAddr
    /// would render, and a re-encode of the decoded value must normalize
    /// back to family 4 (Go encode symmetry — the typed `SocketAddr` the
    /// consumer builds re-enters the encode side, which applies To4()).
    #[test]
    fn ipv4_mapped_family6_decodes_and_reencores_as_family_4() {
        // flags=remote(0x02), family 6, ::ffff:192.0.2.1, port 53,
        // zoneLen 0, payload len 4, payload b"ping".
        let mut body = vec![
            0x02, 0x06, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 0, 2, 1,
        ];
        body.extend_from_slice(&53u16.to_be_bytes());
        body.push(0); // zoneLen
        body.extend_from_slice(&4u16.to_be_bytes());
        body.extend_from_slice(b"ping");

        let pkt = decode_udp_packet_binary(&body).unwrap();
        assert_eq!(pkt.content, b"ping");
        let ra = pkt.remote_addr.as_ref().unwrap();
        assert_eq!(
            ra.ip, "::ffff:192.0.2.1",
            "family-6 decode must not normalize to dotted-quad (Go decode parity)"
        );
        assert_eq!(ra.port, 53);
        assert!(ra.zone.is_empty());

        // Re-encode: the decoded value flows back through encode, which
        // applies the Go To4() normalization — family 4 on the wire.
        let re = encode_udp_packet_binary(&pkt).unwrap();
        assert_eq!(
            re[1], 4,
            "re-encode must normalize the mapped address to family 4"
        );
        assert_eq!(&re[2..6], &[192, 0, 2, 1]);
    }
}
