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

/// Stack-only pre-encoded form of one `binaryUDPAddr` — the zero-allocation
/// replacement for the former `BinaryUdpAddr` (Vec ip + String zone)
/// intermediates, which cost one Vec and one String heap alloc per address
/// per datagram (audit P1). The ip octets sit in a fixed 16-byte array and
/// the zone is borrowed from the source [`UdpAddr`], so nothing is cloned or
/// heap-allocated anywhere in the encode chain; the wire bytes are pushed
/// straight from here into the caller's output buffer.
#[derive(Clone, Copy, Debug)]
struct EncAddr<'a> {
    family: u8,
    /// 4 (family 4) or 16 (family 6) octets, at the front of the array.
    ip: [u8; 16],
    ip_len: usize,
    port: u16,
    /// Zone bytes; empty for family 4 and for every
    /// [`std::net::SocketAddr`] source (std has no zone names).
    zone: &'a str,
}

impl EncAddr<'_> {
    fn len(&self) -> usize {
        1 + self.ip_len + 2 + 1 + self.zone.len()
    }
}

/// Build a pre-encoded address from parsed octets and a borrowed zone. The
/// octets are copied into the fixed stack array — no heap allocation.
fn enc_from_octets<'a>(family: u8, octets: &[u8], port: u16, zone: &'a str) -> EncAddr<'a> {
    debug_assert!(matches!((family, octets.len()), (4, 4) | (6, 16)));
    let mut ip = [0u8; 16];
    ip[..octets.len()].copy_from_slice(octets);
    EncAddr {
        family,
        ip,
        ip_len: octets.len(),
        port,
        zone,
    }
}

/// Validate a message-form [`UdpAddr`] into its pre-encoded form (audit P1:
/// the former `addr_to_binary` built a Vec ip + String zone per address;
/// this parses the ip String in place and borrows the zone — no heap
/// allocation). Error strings and Go-parity rules are unchanged.
fn udp_addr_to_enc(addr: &UdpAddr) -> Result<EncAddr<'_>, String> {
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
            Ok(enc_from_octets(4, &v4.octets(), addr.port, ""))
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
                return Ok(enc_from_octets(4, &v4.octets(), addr.port, ""));
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
            Ok(enc_from_octets(6, &v6.octets(), addr.port, &addr.zone))
        }
    }
}

/// Append one pre-encoded address: family byte, ip octets, port (2B BE),
/// zone-length byte, zone bytes — the same wire bytes the former
/// `put_addr`/`BinaryUdpAddr` pair produced, now pushed straight from the
/// source octets and the borrowed zone.
fn put_enc_addr(out: &mut Vec<u8>, addr: &EncAddr<'_>) {
    out.push(addr.family);
    out.extend_from_slice(&addr.ip[..addr.ip_len]);
    out.extend_from_slice(&addr.port.to_be_bytes());
    out.push(addr.zone.len() as u8);
    out.extend_from_slice(addr.zone.as_bytes());
}

/// Raw decoded fields of one `binaryUDPAddr`, before any `String` formatting.
///
/// Split out of the original `read_addr` (audit B4): the hot terminal UDP
/// readers decode straight to native [`std::net::SocketAddr`] and must not
/// pay a per-datagram `ip` `String` alloc + re-parse that only message-form
/// consumers (V1/JSON, the SUDP message relay) need. All wire-strictness
/// checks (and their error strings) live here, shared by both forms.
#[derive(Clone, Copy)]
struct AddrParts<'a> {
    family: u8,
    /// 4 (family 4) or 16 (family 6) bytes, unvalidated content.
    ip: &'a [u8],
    port: u16,
    /// Zone bytes, unvalidated UTF-8 (validated only when formatted).
    zone: &'a [u8],
    /// Offset of the family byte (error-message prefix).
    offset: usize,
    /// One past the last zone byte.
    end: usize,
}

impl AddrParts<'_> {
    fn is_zoned(&self) -> bool {
        self.family == 6 && !self.zone.is_empty()
    }
}

fn parse_addr_parts(body: &[u8], offset: usize) -> Result<AddrParts<'_>, String> {
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
    let zone = &body[ip_start + ip_len + 3..ip_start + ip_len + 3 + zone_len];
    Ok(AddrParts {
        family,
        ip,
        port,
        zone,
        offset,
        end: offset + 3 + ip_len + zone_len + 1,
    })
}

/// Address-level semantic checks in the original `read_addr` order: the
/// zone bytes must be valid UTF-8, and an IPv4 address must not carry a
/// zone. Run inline during the header parse so a malformed address errors
/// BEFORE the later payload-length checks — the pre-refactor message
/// ordering (pin: `malformed_decode_branch_errors`).
fn validate_addr_parts(p: &AddrParts<'_>) -> Result<(), String> {
    let err = |msg: String| format!("UDP binary address at offset {}: {msg}", p.offset);
    if let Err(e) = std::str::from_utf8(p.zone) {
        return Err(err(format!("invalid zone UTF-8: {e}")));
    }
    if p.family == 4 && !p.zone.is_empty() {
        return Err(err("IPv4 zone is forbidden".into()));
    }
    Ok(())
}

/// Format parsed address parts back to the message-form [`UdpAddr`] used by
/// the V1/JSON path and the SUDP message relay. Errors (text and order
/// within one address) match the original `read_addr`.
fn addr_parts_to_udp(p: &AddrParts<'_>) -> Result<UdpAddr, String> {
    let err = |msg: String| format!("UDP binary address at offset {}: {msg}", p.offset);
    let zone = std::str::from_utf8(p.zone)
        .map_err(|e| err(format!("invalid zone UTF-8: {e}")))?
        .to_string();
    let ip = match p.family {
        4 => {
            if !zone.is_empty() {
                return Err(err("IPv4 zone is forbidden".into()));
            }
            format!("{}.{}.{}.{}", p.ip[0], p.ip[1], p.ip[2], p.ip[3])
        }
        6 => {
            let octets: [u8; 16] = p.ip.try_into().expect("16-byte IPv6 slice");
            std::net::Ipv6Addr::from(octets).to_string()
        }
        _ => unreachable!("family validated above"),
    };
    Ok(UdpAddr {
        ip,
        port: p.port,
        zone,
    })
}

/// Native-address conversion of parsed parts: infallible for plain
/// addresses (IPv4 octets and unzoned IPv6 octets always parse).
fn addr_parts_to_socket(p: &AddrParts<'_>) -> std::net::SocketAddr {
    match p.family {
        4 => {
            let octets: [u8; 4] = p.ip.try_into().expect("4-byte IPv4 slice");
            std::net::SocketAddr::new(
                std::net::IpAddr::V4(std::net::Ipv4Addr::from(octets)),
                p.port,
            )
        }
        6 => {
            let octets: [u8; 16] = p.ip.try_into().expect("16-byte IPv6 slice");
            // flowinfo/scope 0 — the wire form has neither (Go decode of a
            // zone-less address likewise yields a zero-scope UDPAddr).
            std::net::SocketAddr::V6(std::net::SocketAddrV6::new(
                std::net::Ipv6Addr::from(octets),
                p.port,
                0,
                0,
            ))
        }
        _ => unreachable!("family validated above"),
    }
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
    let local_b = packet
        .local_addr
        .as_ref()
        .map(udp_addr_to_enc)
        .transpose()?;
    let remote_b = udp_addr_to_enc(remote)?;
    encode_body(&packet.content, local_b.as_ref(), &remote_b, out)
}

/// Encode a UDP packet whose remote address is a `SocketAddr` directly into
/// the binary codec body, appending after any existing content of `out`.
///
/// Equivalent to [`encode_udp_packet_binary_into`] with `remote_addr` built
/// from `remote.ip().to_string()`, but the caller (frp-server UDP bridge
/// writer) already holds a parsed `SocketAddr` on the V2 binary path, where
/// the String form exists only for the V1 JSON codec. Output is byte-identical
/// to the string round trip.
///
/// Zero heap allocations per datagram (audit P1): the remote is pre-encoded
/// straight from its octets and neither address ever builds a Vec/String
/// intermediate. The message-form `local` (loop-invariant in the callers) is
/// parsed in place and its zone, if any, is borrowed — nothing cloned.
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
    let local_b = local.map(udp_addr_to_enc).transpose()?;
    let remote_b = socket_addr_to_enc(remote);
    encode_body(content, local_b.as_ref(), &remote_b, out)
}

/// Shared body writer: flags, optional local addr, required remote addr,
/// payload length, payload. Error precedence (missing remote → oversized
/// payload → invalid local addr → invalid remote addr → frame-size cap)
/// matches the callers' original ordering.
fn encode_body(
    content: &[u8],
    local: Option<&EncAddr<'_>>,
    remote: &EncAddr<'_>,
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
        put_enc_addr(out, l);
    }
    put_enc_addr(out, remote);
    out.extend_from_slice(&(content.len() as u16).to_be_bytes());
    out.extend_from_slice(content);
    debug_assert_eq!(out.len() - start, body_len);
    Ok(())
}

/// Pre-encode a parsed `SocketAddr` without any allocation (audit P1: the
/// former `socket_addr_to_binary` built a Vec ip + String zone per address).
/// Infallible — a `SocketAddr` is always valid (no error paths — no empty
/// IP, no zone), and `SocketAddrV6`'s scope id is never rendered by
/// `Ipv6Addr::to_string()`, so the resulting bytes are exactly what
/// [`udp_addr_to_enc`] would produce for the string form.
fn socket_addr_to_enc(addr: &std::net::SocketAddr) -> EncAddr<'static> {
    match addr {
        std::net::SocketAddr::V4(v4) => enc_from_octets(4, &v4.ip().octets(), v4.port(), ""),
        std::net::SocketAddr::V6(v6) => {
            // Same To4() normalization as [`udp_addr_to_enc`]: a dual-stack
            // socket recv of an IPv4 peer yields an IPv4-mapped address,
            // which must go on the wire as family 4 (Go parity, review
            // finding C1).
            if let Some(v4) = v6.ip().to_ipv4_mapped() {
                enc_from_octets(4, &v4.octets(), v6.port(), "")
            } else {
                enc_from_octets(6, &v6.ip().octets(), v6.port(), "")
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
///
/// Message-form decode: the addresses come out as [`UdpAddr`] `String`s for
/// consumers that re-serialize the message (V1/JSON path, the SUDP message
/// relay). Terminal readers that only send the datagram on should use
/// [`decode_udp_packet_binary_socket_owned`] instead (audit B4).
pub fn decode_udp_packet_binary_owned(body: &mut Vec<u8>) -> Result<UDPPacket, String> {
    let h = parse_udp_packet_header(body)?;
    let content = take_or_copy_payload(body, h.payload_len, h.payload_offset);
    Ok(UDPPacket {
        content,
        local_addr: h.local_addr,
        remote_addr: Some(h.remote_addr),
    })
}

/// Native-address decode of an owned binary codec body (audit B4, the
/// read-side mirror of [`encode_udp_packet_binary_socket_addr`]): same wire
/// parse and payload semantics as [`decode_udp_packet_binary_owned`], but
/// addresses decode straight to [`std::net::SocketAddr`] — no per-datagram
/// `ip` `String` alloc + re-parse. Go decodes the binary codec to
/// `net.UDPAddr` with no intermediate text; this form matches.
///
/// A [`std::net::SocketAddr`] cannot carry an IPv6 scope *zone* (std has a
/// numeric scope id, not an interface name), so a body whose address has a
/// zone returns `Ok(None)` — the caller falls back to
/// [`decode_udp_packet_binary_owned`] on the same buffer (rare path: the
/// Rust encode side never writes zones; only a Go peer with a link-local
/// service would). An IPv4 address with a zone is malformed in both
/// decoders (same error text). On error the buffer is left untouched.
pub fn decode_udp_packet_binary_socket_owned(
    body: &mut Vec<u8>,
) -> Result<Option<SocketUdpPacket>, String> {
    // Malformed-address checks (utf8 zone, IPv4-with-zone) already ran
    // inline in the parts parse with the original error ordering. What
    // remains: a family-6 zone is representable in the message form but not
    // natively — fall back to it (the caller re-decodes the same buffer).
    let h = parse_udp_packet_header_parts(body)?;
    if h.local_addr.as_ref().is_some_and(AddrParts::is_zoned) || h.remote_addr.is_zoned() {
        return Ok(None);
    }
    let local_addr = h.local_addr.as_ref().map(addr_parts_to_socket);
    let remote_addr = addr_parts_to_socket(&h.remote_addr);
    // Drop `h` (borrows `body`) before the payload extraction mutates it.
    let (payload_len, payload_offset) = (h.payload_len, h.payload_offset);
    let content = take_or_copy_payload(body, payload_len, payload_offset);
    Ok(Some(SocketUdpPacket {
        content,
        local_addr,
        remote_addr,
    }))
}

/// UDP packet decoded to native-address form by
/// [`decode_udp_packet_binary_socket_owned`].
#[derive(Debug)]
pub struct SocketUdpPacket {
    /// UDP payload (ownership semantics of
    /// [`decode_udp_packet_binary_owned`]: payloads ≥ the pool buffer take
    /// the caller's buffer, which is left empty — refill before the next
    /// read).
    pub content: Vec<u8>,
    /// Decoded local address when flagged. No current terminal reader uses
    /// it (the proxy's own bound address is loop-invariant config), kept
    /// for symmetry with the wire flags.
    pub local_addr: Option<std::net::SocketAddr>,
    pub remote_addr: std::net::SocketAddr,
}

/// Parse a decoded message-form address into a native [`std::net::SocketAddr`]
/// without allocating.
///
/// Audit B4: replaces the per-datagram `format!("ip:port")` + re-parse on the
/// V1/JSON inbound arms (where the text form is inherent to the message) and
/// the SUDP visitor's inbound reader task. An IPv6 scope *zone* (which
/// [`std::net::SocketAddr`] cannot express) is ignored, matching the
/// callers' original behavior of sending scope-less.
pub fn udp_addr_to_socket(addr: &UdpAddr) -> Option<std::net::SocketAddr> {
    let ip: std::net::IpAddr = addr.ip.parse().ok()?;
    Some(std::net::SocketAddr::new(ip, addr.port))
}

/// Parsed header of a binary codec body (everything before the payload).
struct DecodedHeader {
    local_addr: Option<UdpAddr>,
    remote_addr: UdpAddr,
    payload_len: usize,
    /// Offset within the body of the first payload byte.
    payload_offset: usize,
}

/// Raw (unformatted) parsed header; the socket-form decode consumes this
/// and never formats the addresses.
struct DecodedHeaderParts<'a> {
    local_addr: Option<AddrParts<'a>>,
    remote_addr: AddrParts<'a>,
    payload_len: usize,
    payload_offset: usize,
}

/// Shared body parser: flags, optional local addr, required remote addr,
/// payload length — all strictness checks and error strings live here.
/// Addresses stay in raw wire form (no `String` formatting); their
/// semantic checks (utf8 zone, IPv4-with-zone) run inline in the original
/// per-address error order (`validate_addr_parts`).
fn parse_udp_packet_header_parts(body: &[u8]) -> Result<DecodedHeaderParts<'_>, String> {
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
        let a = parse_addr_parts(body, offset)?;
        validate_addr_parts(&a)?;
        offset = a.end;
        Some(a)
    } else {
        None
    };
    let remote_addr = parse_addr_parts(body, offset)?;
    validate_addr_parts(&remote_addr)?;
    offset = remote_addr.end;
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
    Ok(DecodedHeaderParts {
        local_addr,
        remote_addr,
        payload_len,
        payload_offset: offset,
    })
}

/// Message-form header parse (addresses formatted to [`UdpAddr`] strings).
fn parse_udp_packet_header(body: &[u8]) -> Result<DecodedHeader, String> {
    let h = parse_udp_packet_header_parts(body)?;
    let local_addr = h.local_addr.as_ref().map(addr_parts_to_udp).transpose()?;
    let remote_addr = addr_parts_to_udp(&h.remote_addr)?;
    Ok(DecodedHeader {
        local_addr,
        remote_addr,
        payload_len: h.payload_len,
        payload_offset: h.payload_offset,
    })
}

/// Copy-or-take the payload out of a decoded body.
///
/// Steady-state path (review finding M2): copy the payload out and keep
/// `body` in the caller's loop — no per-packet 32 KiB pool-buffer churn
/// (one small payload copy remains; large datagrams move the buffer into
/// the packet instead of copying). Only for payloads ≥ the pool buffer is
/// the buffer moved into the packet; that buffer then never returns to the
/// pool, so the pool drains at most one buffer per large datagram —
/// acceptable, they are the rare case (UDP payloads are typically ≤
/// 1.5 KiB MTU-sized).
fn take_or_copy_payload(body: &mut Vec<u8>, payload_len: usize, payload_offset: usize) -> Vec<u8> {
    if payload_len < *crate::buffer_pool::BUFFER_SIZE {
        body[payload_offset..payload_offset + payload_len].to_vec()
    } else {
        // The trailing-bytes check guarantees `payload_offset + payload_len
        // == body.len()`, so the payload is exactly the buffer tail: move it
        // to the front and truncate — one in-place memmove, zero allocation.
        body.copy_within(payload_offset.., 0);
        body.truncate(payload_len);
        std::mem::take(body)
    }
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

    /// Exact wire bytes for the zero-alloc encode (audit round 3 finding
    /// C-LOW-1: the P1 refactor landed no byte-equivalence pins). Go-parity
    /// rules pinned here: IPv4-mapped IPv6 ("::ffff:a.b.c.d") normalizes to
    /// family 4 with the dotted-quad octets (Go `net.IP.To4()` in
    /// `validateBinaryUDPAddr`); zones carry a 1-byte length and arbitrary
    /// UTF-8 bytes; the `SocketAddr` form must be byte-identical to the
    /// message form. Layout: flags, [local], remote, payloadLen (2B BE),
    /// payload.
    #[test]
    fn encode_exact_wire_bytes_pin() {
        // (a) v4 local + remote, message form.
        let mut expected: Vec<u8> = vec![0x03]; // flags: local | remote
        expected.extend_from_slice(&[4, 127, 0, 0, 1, 0xCF, 0x09, 0]); // 127.0.0.1:53001
        expected.extend_from_slice(&[4, 10, 0, 0, 2, 0, 53, 0]); // 10.0.0.2:53
        expected.extend_from_slice(&[0, 5]); // len 5
        expected.extend_from_slice(b"hello");
        assert_eq!(
            encode_udp_packet_binary(&sample_packet()).unwrap(),
            expected
        );

        // (b) IPv4-mapped IPv6 remote — family 4 + dotted-quad octets, NOT
        // family 6 (Go To4 parity). Empty payload.
        let mapped = UDPPacket {
            content: vec![],
            local_addr: None,
            remote_addr: Some(UdpAddr {
                ip: "::ffff:192.168.0.1".into(),
                port: 53,
                zone: String::new(),
            }),
        };
        let expected: Vec<u8> = vec![0x02, 4, 192, 168, 0, 1, 0, 53, 0, 0, 0];
        assert_eq!(encode_udp_packet_binary(&mapped).unwrap(), expected);

        // (c) zoned v6 — 16 octets, port BE, zone-length byte then raw zone
        // bytes; non-ASCII zone (接口 = 6 UTF-8 bytes) pins the byte count.
        let zoned = UDPPacket {
            content: vec![],
            local_addr: None,
            remote_addr: Some(UdpAddr {
                ip: "fe80::1".into(),
                port: 8080,
                zone: "接口".into(),
            }),
        };
        let mut expected: Vec<u8> = vec![0x02, 6];
        expected.extend_from_slice(&[
            0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, // fe80::1
        ]);
        expected.extend_from_slice(&[0x1F, 0x90]); // port 8080
        expected.extend_from_slice(&[6]); // zone length
        expected.extend_from_slice("接口".as_bytes());
        expected.extend_from_slice(&[0, 0]); // empty payload
        assert_eq!(encode_udp_packet_binary(&zoned).unwrap(), expected);

        // (d) SocketAddr form is byte-identical to the message form for the
        // same address (v4, plain v6, and mapped-v6 → family 4).
        let plain_v4: std::net::SocketAddr = "10.0.0.2:53".parse().unwrap();
        let expected = vec![0x02, 4, 10, 0, 0, 2, 0, 53, 0, 0, 2, b'h', b'i'];
        let mut out = Vec::new();
        encode_udp_packet_binary_socket_addr(b"hi", None, &plain_v4, &mut out).unwrap();
        assert_eq!(out, expected);

        let plain_v6: std::net::SocketAddr = "[fe80::1]:8080".parse().unwrap();
        let mut expected: Vec<u8> = vec![0x02, 6];
        expected.extend_from_slice(&[0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        expected.extend_from_slice(&[0x1F, 0x90, 0, 0, 0]); // port, empty zone, len 0
        let mut out = Vec::new();
        encode_udp_packet_binary_socket_addr(b"", None, &plain_v6, &mut out).unwrap();
        assert_eq!(out, expected);

        let mapped_v6 = std::net::SocketAddr::V6(std::net::SocketAddrV6::new(
            "::ffff:192.168.0.1".parse().unwrap(),
            53,
            0,
            0,
        ));
        let mut out = Vec::new();
        encode_udp_packet_binary_socket_addr(b"", None, &mapped_v6, &mut out).unwrap();
        assert_eq!(out, vec![0x02, 4, 192, 168, 0, 1, 0, 53, 0, 0, 0]);
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

    // --- Audit B4: native-SocketAddr decode ---

    fn socket_sample_body() -> Vec<u8> {
        // Both addresses present, encoded by the direct-SocketAddr encoder so
        // the socket decode runs against real wire bytes.
        let mut body = Vec::new();
        encode_udp_packet_binary_socket_addr(
            b"hello",
            Some(&UdpAddr {
                ip: "127.0.0.1".into(),
                port: 53001,
                zone: String::new(),
            }),
            &"10.0.0.2:53".parse().unwrap(),
            &mut body,
        )
        .unwrap();
        body
    }

    #[test]
    fn socket_decode_matches_message_decode() {
        // Byte-parity invariant: the native decode must produce the same
        // address the message-form decode yields (after its String re-parse).
        let body = socket_sample_body();
        let msg = decode_udp_packet_binary(&body).unwrap();
        let mut owned = body.clone();
        let sock = decode_udp_packet_binary_socket_owned(&mut owned)
            .unwrap()
            .expect("plain addresses decode natively");
        assert_eq!(sock.content, msg.content);
        let msg_remote =
            udp_addr_to_socket(msg.remote_addr.as_ref().unwrap()).expect("msg remote parses");
        assert_eq!(sock.remote_addr, msg_remote);
        let msg_local = msg.local_addr.as_ref().and_then(udp_addr_to_socket);
        assert_eq!(sock.local_addr, msg_local);
        assert_eq!(
            owned, body,
            "small payload must leave the caller's buffer intact"
        );
    }

    #[test]
    fn socket_decode_v6_addresses_match_message_decode() {
        for remote in ["[::1]:8080", "[2001:db8::1]:12345"] {
            let remote: std::net::SocketAddr = remote.parse().unwrap();
            let mut body = Vec::new();
            encode_udp_packet_binary_socket_addr(b"ping", None, &remote, &mut body).unwrap();
            let msg = decode_udp_packet_binary(&body).unwrap();
            let mut owned = body.clone();
            let sock = decode_udp_packet_binary_socket_owned(&mut owned)
                .unwrap()
                .expect("zone-less v6 decodes natively");
            assert_eq!(sock.remote_addr, remote, "v6 decode must be exact");
            assert_eq!(
                sock.remote_addr,
                udp_addr_to_socket(msg.remote_addr.as_ref().unwrap()).unwrap()
            );
        }
    }

    #[test]
    fn socket_decode_mapped_v6_comes_back_family_4() {
        // The direct-SocketAddr encoder applies Go's To4() normalization, so
        // a mapped-v6 remote goes on the wire as family 4 and the native
        // decode returns a plain V4 socket — encode/decode symmetry.
        let remote: std::net::SocketAddr = "[::ffff:192.0.2.1]:53".parse().unwrap();
        let mut body = Vec::new();
        encode_udp_packet_binary_socket_addr(b"ping", None, &remote, &mut body).unwrap();
        let mut owned = body.clone();
        let sock = decode_udp_packet_binary_socket_owned(&mut owned)
            .unwrap()
            .expect("family-4 wire decodes natively");
        assert_eq!(sock.remote_addr, "192.0.2.1:53".parse().unwrap());
        // Family-6 wire form (Go decode parity — a foreign encoder can emit
        // it) stays mapped, matching the message decoder's String form.
        let mut mapped = vec![
            0x02, 0x06, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 0, 2, 1,
        ];
        mapped.extend_from_slice(&53u16.to_be_bytes());
        mapped.push(0); // zoneLen
        mapped.extend_from_slice(&4u16.to_be_bytes());
        mapped.extend_from_slice(b"ping");
        let sock = decode_udp_packet_binary_socket_owned(&mut mapped.clone())
            .unwrap()
            .expect("family-6 mapped decodes natively");
        match sock.remote_addr {
            std::net::SocketAddr::V6(v6) => {
                assert!(v6.ip().to_ipv4().is_some(), "mapped address stays mapped");
                assert_eq!(v6.port(), 53);
            }
            _ => panic!("family-6 wire must decode to a V6 socket"),
        }
    }

    #[test]
    fn socket_decode_zone_returns_none_and_leaves_buffer_for_fallback() {
        // A family-6 zone is representable in the message form but not as a
        // SocketAddr: the native decode yields None and must not consume the
        // buffer — the caller falls back to the message-form decode.
        let pkt = UDPPacket {
            content: b"hello".to_vec(),
            local_addr: None,
            remote_addr: Some(UdpAddr {
                ip: "fe80::1".into(),
                port: 9,
                zone: "eth0".into(),
            }),
        };
        let body = encode_udp_packet_binary(&pkt).unwrap();
        let mut owned = body.clone();
        assert!(
            decode_udp_packet_binary_socket_owned(&mut owned)
                .unwrap()
                .is_none(),
            "zoned address must fall back to the message-form decode"
        );
        assert_eq!(owned, body, "None must leave the buffer untouched");
        let msg = decode_udp_packet_binary_owned(&mut owned).unwrap();
        assert_eq!(msg.content, pkt.content);
        let ra = msg.remote_addr.as_ref().unwrap();
        assert_eq!(ra.ip, "fe80::1");
        assert_eq!(ra.zone, "eth0", "fallback keeps the zone string");
    }

    #[test]
    fn socket_decode_ipv4_zone_is_forbidden_like_message_decode() {
        // family 4 with a non-empty zone: malformed in both decoders with
        // identical error text.
        let mut body = vec![0x02, 0x04, 192, 0, 2, 1];
        body.extend_from_slice(&53u16.to_be_bytes());
        body.push(1);
        body.push(b'x');
        body.extend_from_slice(&4u16.to_be_bytes());
        body.extend_from_slice(b"ping");
        let msg_err = decode_udp_packet_binary(&body).unwrap_err();
        let mut owned = body.clone();
        let sock_err = decode_udp_packet_binary_socket_owned(&mut owned).unwrap_err();
        assert_eq!(sock_err, msg_err);
        assert_eq!(owned, body, "failed decode must not consume the buffer");
    }

    #[test]
    fn socket_decode_error_parity_with_message_decode() {
        // Every malformed-body error must read identically from both
        // decoders (they share the parts parser).
        let mut bodies: Vec<Vec<u8>> = vec![
            vec![],                             // body too short
            vec![0x02],                         // address header truncated
            vec![0x04],                         // reserved flags
            vec![0x00],                         // missing remote address
            vec![0x06, 0x02],                   // invalid address family
            vec![0x02, 0x06],                   // truncated v6 address
            vec![0x02, 0x04, 1, 2, 3],          // truncated v4 address
            vec![0x02, 0x03, 0x02, 0x01, 0x00], // invalid family (inside addr)
        ];
        // Full v4 address then a truncated payload-length field.
        let mut tail = vec![0x02, 0x04, 192, 0, 2, 1];
        tail.extend_from_slice(&53u16.to_be_bytes());
        tail.push(0);
        tail.push(0x00);
        bodies.push(tail);
        // Full header + payload-length declaring more than the body holds.
        let mut tail = vec![0x02, 0x04, 192, 0, 2, 1];
        tail.extend_from_slice(&53u16.to_be_bytes());
        tail.push(0);
        tail.extend_from_slice(&10u16.to_be_bytes());
        tail.extend_from_slice(b"hi");
        bodies.push(tail);
        for body in bodies {
            let msg_err = decode_udp_packet_binary(&body).unwrap_err();
            let mut owned = body.clone();
            let sock_err = decode_udp_packet_binary_socket_owned(&mut owned).unwrap_err();
            assert_eq!(sock_err, msg_err, "error text must match for body {body:?}");
        }
    }

    #[test]
    fn socket_decode_large_payload_consumes_buffer() {
        let big_len = *crate::buffer_pool::BUFFER_SIZE;
        let mut body = Vec::new();
        encode_udp_packet_binary_socket_addr(
            &vec![0xabu8; big_len],
            None,
            &"[::1]:8080".parse().unwrap(),
            &mut body,
        )
        .unwrap();
        let mut owned = body.clone();
        let out = decode_udp_packet_binary_socket_owned(&mut owned)
            .unwrap()
            .expect("large plain datagram decodes natively");
        assert_eq!(out.content, vec![0xabu8; big_len]);
        assert_eq!(out.remote_addr, "[::1]:8080".parse().unwrap());
        assert!(out.local_addr.is_none());
        assert!(owned.is_empty(), "large payload must consume the buffer");
    }

    #[test]
    fn udp_addr_to_socket_parses_plain_addresses() {
        // Message-form parse helper for the SUDP visitor path: replaces the
        // old per-datagram format!("ip:port") + re-parse chain, which dropped
        // bare-v6 addresses (std SocketAddr parse needs brackets) — the
        // helper parses them natively, a benign v6-delivery fix (Go parity:
        // Go resolves the ip string via net.ResolveUDPAddr, v6 included).
        let mk = |ip: &str, port: u16, zone: &str| UdpAddr {
            ip: ip.into(),
            port,
            zone: zone.into(),
        };
        for (ip, port) in [
            ("127.0.0.1", 53001u16),
            ("10.0.0.2", 53),
            ("::1", 8080),
            ("2001:db8::1", 12345),
            ("::ffff:192.0.2.1", 53),
        ] {
            let a = mk(ip, port, "");
            let got = udp_addr_to_socket(&a).expect("plain address parses");
            assert_eq!(got.ip().to_string(), ip, "addr {ip}:{port}");
            assert_eq!(got.port(), port, "addr {ip}:{port}");
        }
        // The zone field never enters the address string (same as the old
        // format!("{}:{}", ip, port) chain) — a zoned v6 with a plain ip
        // parses with the zone dropped.
        assert_eq!(
            udp_addr_to_socket(&mk("fe80::1", 9, "eth0")),
            Some("[fe80::1]:9".parse().unwrap())
        );
        // An embedded %zone in the ip string is unparseable by IpAddr.
        assert_eq!(udp_addr_to_socket(&mk("fe80::1%eth0", 9, "")), None);
        assert_eq!(udp_addr_to_socket(&mk("", 53, "")), None);
        assert_eq!(udp_addr_to_socket(&mk("not-an-ip", 53, "")), None);
    }
}
