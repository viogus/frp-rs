use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::msg::{self, FrpMessage};

/// Go frp's defaultMaxMsgLength is 10KB (10240). Rust must not send
/// messages larger than this to remain compatible with Go peers.
pub const V1_MAX_MSG_LENGTH: i64 = 10_240;
pub const V1_HEADER_LEN: usize = 9;

pub async fn write_v1_frame<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    msg: &FrpMessage,
) -> Result<(), crate::Error> {
    let mut scratch = Vec::new();
    write_v1_frame_scratch(writer, msg, &mut scratch).await
}

/// [`write_v1_frame`] with a caller-owned serialization scratch buffer.
///
/// The JSON payload is serialized straight into `scratch` (cleared per call)
/// after a reserved 9-byte header slot, so a task that sends frame after frame
/// reuses one allocation instead of paying for a fresh `Vec` on every control
/// message — [`write_v1_frame`] allocates one per call. Wire bytes are
/// identical: same serializer, same 9-byte header.
///
/// The caller owns the buffer, so the scratch is only ever touched by one
/// task; a partially-serialized buffer left by a serialization error is
/// cleared before the error is returned.
pub async fn write_v1_frame_scratch<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    msg: &FrpMessage,
    scratch: &mut Vec<u8>,
) -> Result<(), crate::Error> {
    // NOTE: V1 type bytes 7 (CloseProxyResp) and 8 (Error) are Rust-only
    // extensions. Go frp v0.70.0 treats unknown type bytes as errors.
    // These MUST NOT be sent to Go peers. See msg.rs lines 26-29.
    let type_byte = msg.v1_type_byte();
    // Reserve the header slot BEFORE serializing so header and payload share
    // one contiguous allocation — the serializer appends at the end of
    // `scratch`, a zero-copy reservation. Non-vectored writers then hand the
    // whole frame to a single `write_all` instead of two writes (tokio's
    // default `poll_write_vectored` only writes the first non-empty iovec).
    // On yamux the old two-iovec loop issued the 9-byte header and the
    // payload as two DATA frames per UDP packet.
    scratch.clear();
    scratch.resize(V1_HEADER_LEN, 0);
    if let Err(e) = serde_json::to_writer(&mut *scratch, msg) {
        scratch.clear();
        return Err(crate::Error::Protocol(
            format!("serialize V1 msg: {e}").into(),
        ));
    }
    let payload_len = (scratch.len() - V1_HEADER_LEN) as u64;

    if payload_len > V1_MAX_MSG_LENGTH as u64 {
        return Err(crate::Error::Protocol("V1 message too large".into()));
    }

    scratch[0] = type_byte;
    scratch[1..V1_HEADER_LEN].copy_from_slice(&payload_len.to_be_bytes());

    tracing::trace!(
        type_byte = %type_byte,
        payload_len = payload_len,
        "V1 frame: type=0x{:02x} len={}",
        type_byte,
        payload_len
    );

    if !writer.is_write_vectored() {
        // One write, one frame on buffered transports (yamux, KCP, WebSocket,
        // CipherWriter). The header is already contiguous with its payload,
        // so no merge copy is needed.
        writer
            .write_all(scratch)
            .await
            .map_err(|e| crate::Error::Protocol(format!("write V1 frame: {e}").into()))?;
        return Ok(());
    }

    // Native vectored write (TcpStream): header + payload go out as ONE
    // writev(2) call — one syscall, no payload copy. writev may consume a
    // partial iovec, so retries continue from the exact unwritten byte.
    let (header, buf) = scratch.split_at(V1_HEADER_LEN);
    let mut hdr_off = 0usize;
    let mut payload_off = 0usize;
    loop {
        if hdr_off >= V1_HEADER_LEN && payload_off >= buf.len() {
            break;
        }
        let bufs = [
            std::io::IoSlice::new(&header[hdr_off..]),
            std::io::IoSlice::new(&buf[payload_off..]),
        ];
        let n = writer
            .write_vectored(&bufs)
            .await
            .map_err(|e| crate::Error::Protocol(format!("write V1 frame: {e}").into()))?;
        if n == 0 {
            return Err(crate::Error::Protocol(
                "write V1 frame: zero-length write".into(),
            ));
        }
        let mut rem = n;
        if hdr_off < V1_HEADER_LEN {
            let take = rem.min(V1_HEADER_LEN - hdr_off);
            hdr_off += take;
            rem -= take;
        }
        let take = rem.min(buf.len() - payload_off);
        payload_off += take;
        rem -= take;
        debug_assert_eq!(rem, 0);
    }
    // Flush is NOT called here — callers that need it (KCP control channel
    // after login) flush explicitly.  Adding a blanket flush breaks CipherStream
    // layered writes because the intermediate flush can split encrypted blocks.
    Ok(())
}

pub async fn read_v1_frame<R: AsyncReadExt + Unpin>(
    reader: &mut R,
) -> Result<(u8, Vec<u8>), crate::Error> {
    let mut header = [0u8; V1_HEADER_LEN];
    reader
        .read_exact(&mut header)
        .await
        .map_err(|e| crate::Error::Protocol(format!("read V1 header: {e}").into()))?;

    let type_byte = header[0];
    let length = u64::from_be_bytes([
        header[1], header[2], header[3], header[4], header[5], header[6], header[7], header[8],
    ]);

    tracing::debug!(
        type_byte = %type_byte,
        length = %length,
        raw = %crate::hex_encode(&header),
        "V1 header: type={:#04x} len={} raw={}",
        type_byte,
        length,
        crate::hex_encode(&header)
    );

    if length > V1_MAX_MSG_LENGTH as u64 {
        return Err(crate::Error::Protocol(
            format!(
                "invalid V1 msg length: {length} (max: {V1_MAX_MSG_LENGTH}), raw header: {}",
                crate::hex_encode(&header)
            )
            .into(),
        ));
    }

    let length = length as usize;
    // Zero-initialize: passing &mut [u8] pointing to uninitialized memory
    // to read_exact is UB (Rust reference validity requirements), even
    // though u8 has no invalid bit patterns.
    let mut payload = vec![0u8; length];
    reader
        .read_exact(&mut payload)
        .await
        .map_err(|e| crate::Error::Protocol(format!("read V1 payload: {e}").into()))?;

    Ok((type_byte, payload))
}

pub async fn read_msg_v1<R: AsyncReadExt + Unpin>(
    reader: &mut R,
) -> Result<FrpMessage, crate::Error> {
    let mut header = [0u8; V1_HEADER_LEN];
    reader
        .read_exact(&mut header)
        .await
        .map_err(|e| crate::Error::Protocol(format!("read V1 header: {e}").into()))?;

    let type_byte = header[0];
    let length = u64::from_be_bytes([
        header[1], header[2], header[3], header[4], header[5], header[6], header[7], header[8],
    ]);

    tracing::debug!(
        type_byte = %type_byte,
        length = %length,
        raw = %crate::hex_encode(&header),
        "V1 header: type={:#04x} len={} raw={}",
        type_byte,
        length,
        crate::hex_encode(&header)
    );

    if length > V1_MAX_MSG_LENGTH as u64 {
        return Err(crate::Error::Protocol(
            format!(
                "invalid V1 msg length: {length} (max: {V1_MAX_MSG_LENGTH}), raw header: {}",
                crate::hex_encode(&header)
            )
            .into(),
        ));
    }
    let length = length as usize;
    // Use the global buffer pool for small payloads (<= BUFFER_SIZE, 64 KiB
    // by default).  Larger payloads fall back to a heap
    // allocation.  The
    // PoolGuard is dropped after deserialization, returning the buffer.
    let pool_size = *crate::buffer_pool::BUFFER_SIZE;
    if length <= pool_size {
        let mut guard = crate::buffer_pool::PoolGuard::acquire();
        reader
            .read_exact(&mut guard.as_mut_slice()[..length])
            .await
            .map_err(|e| crate::Error::Protocol(format!("read V1 payload: {e}").into()))?;
        deserialize_v1(type_byte, &guard.raw_buf()[..length])
    } else {
        let mut payload = vec![0u8; length];
        reader
            .read_exact(&mut payload)
            .await
            .map_err(|e| crate::Error::Protocol(format!("read V1 payload: {e}").into()))?;
        deserialize_v1(type_byte, &payload)
    }
}

pub async fn write_msg_v1<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    msg: &FrpMessage,
) -> Result<(), crate::Error> {
    write_v1_frame(writer, msg).await
}

/// Shared deserialization helper: `serde_json::from_slice` + `FrpMessage` wrap.
/// `$version_suffix` distinguishes V1 ("") from V2 (" (v2)") in error messages.
macro_rules! deser_msg {
    ($payload:expr, $MsgType:ident, $version_suffix:literal) => {{
        let v: msg::$MsgType = serde_json::from_slice($payload).map_err(|e| {
            crate::Error::Protocol(
                format!(
                    "deserialize {}{}: {}",
                    stringify!($MsgType),
                    $version_suffix,
                    e
                )
                .into(),
            )
        })?;
        FrpMessage::$MsgType(v)
    }};
}

/// Variant of `deser_msg!` for heap-allocated (Boxed) message types.
macro_rules! deser_msg_boxed {
    ($payload:expr, $MsgType:ident, $version_suffix:literal) => {{
        let v: msg::$MsgType = serde_json::from_slice($payload).map_err(|e| {
            crate::Error::Protocol(
                format!(
                    "deserialize {}{}: {}",
                    stringify!($MsgType),
                    $version_suffix,
                    e
                )
                .into(),
            )
        })?;
        FrpMessage::$MsgType(Box::new(v))
    }};
}

/// Deserialize a V2 message from its type ID and JSON payload bytes.
/// V2 uses numeric type IDs (u16) instead of V1's ASCII type bytes.
pub fn deserialize_v2(type_id: u16, json_bytes: &[u8]) -> Result<FrpMessage, crate::Error> {
    let msg = match type_id {
        msg::V2_TYPE_LOGIN => deser_msg_boxed!(json_bytes, Login, " (v2)"),
        msg::V2_TYPE_LOGIN_RESP => deser_msg!(json_bytes, LoginResp, " (v2)"),
        msg::V2_TYPE_NEW_PROXY => deser_msg_boxed!(json_bytes, NewProxy, " (v2)"),
        msg::V2_TYPE_NEW_PROXY_RESP => deser_msg!(json_bytes, NewProxyResp, " (v2)"),
        msg::V2_TYPE_CLOSE_PROXY => deser_msg!(json_bytes, CloseProxy, " (v2)"),
        msg::V2_TYPE_CLOSE_PROXY_RESP => deser_msg!(json_bytes, CloseProxyResp, " (v2)"),
        msg::V2_TYPE_ERROR => deser_msg!(json_bytes, Error, " (v2)"),
        msg::V2_TYPE_NEW_WORK_CONN => deser_msg!(json_bytes, NewWorkConn, " (v2)"),
        msg::V2_TYPE_REQ_WORK_CONN => deser_msg!(json_bytes, ReqWorkConn, " (v2)"),
        msg::V2_TYPE_START_WORK_CONN => deser_msg_boxed!(json_bytes, StartWorkConn, " (v2)"),
        msg::V2_TYPE_NEW_VISITOR_CONN => deser_msg!(json_bytes, NewVisitorConn, " (v2)"),
        msg::V2_TYPE_NEW_VISITOR_CONN_RESP => deser_msg!(json_bytes, NewVisitorConnResp, " (v2)"),
        msg::V2_TYPE_PING => deser_msg!(json_bytes, Ping, " (v2)"),
        msg::V2_TYPE_PONG => deser_msg!(json_bytes, Pong, " (v2)"),
        msg::V2_TYPE_UDP_PACKET => deser_msg!(json_bytes, UDPPacket, " (v2)"),
        msg::V2_TYPE_NAT_HOLE_VISITOR => deser_msg!(json_bytes, NatHoleVisitor, " (v2)"),
        msg::V2_TYPE_NAT_HOLE_CLIENT => deser_msg_boxed!(json_bytes, NatHoleClient, " (v2)"),
        msg::V2_TYPE_NAT_HOLE_RESP => deser_msg_boxed!(json_bytes, NatHoleResp, " (v2)"),
        msg::V2_TYPE_NAT_HOLE_SID => deser_msg!(json_bytes, NatHoleSid, " (v2)"),
        msg::V2_TYPE_NAT_HOLE_REPORT => deser_msg!(json_bytes, NatHoleReport, " (v2)"),
        #[cfg(feature = "vnet")]
        msg::V2_TYPE_VNET_ROUTE_ADVERTISE => deser_msg!(json_bytes, VnetRouteAdvertise, " (v2)"),
        #[cfg(feature = "vnet")]
        msg::V2_TYPE_VNET_PACKET => deser_msg!(json_bytes, VnetPacket, " (v2)"),
        #[cfg(feature = "vnet")]
        msg::V2_TYPE_VNET_ROUTE_REMOVE => deser_msg!(json_bytes, VnetRouteRemove, " (v2)"),
        _ => {
            return Err(crate::Error::Protocol(
                format!("unknown V2 message type ID: {type_id}").into(),
            ))
        }
    };
    Ok(msg)
}

pub fn deserialize_v1(type_byte: u8, payload: &[u8]) -> Result<FrpMessage, crate::Error> {
    let msg = match type_byte {
        msg::TYPE_LOGIN => deser_msg_boxed!(payload, Login, ""),
        msg::TYPE_LOGIN_RESP => deser_msg!(payload, LoginResp, ""),
        msg::TYPE_NEW_PROXY => deser_msg_boxed!(payload, NewProxy, ""),
        msg::TYPE_NEW_PROXY_RESP => deser_msg!(payload, NewProxyResp, ""),
        msg::TYPE_CLOSE_PROXY => deser_msg!(payload, CloseProxy, ""),
        msg::TYPE_CLOSE_PROXY_RESP => deser_msg!(payload, CloseProxyResp, ""),
        msg::TYPE_ERROR => deser_msg!(payload, Error, ""),
        msg::TYPE_NEW_WORK_CONN => deser_msg!(payload, NewWorkConn, ""),
        msg::TYPE_REQ_WORK_CONN => deser_msg!(payload, ReqWorkConn, ""),
        msg::TYPE_START_WORK_CONN => deser_msg_boxed!(payload, StartWorkConn, ""),
        msg::TYPE_PING => deser_msg!(payload, Ping, ""),
        msg::TYPE_PONG => deser_msg!(payload, Pong, ""),
        msg::TYPE_NEW_VISITOR_CONN => deser_msg!(payload, NewVisitorConn, ""),
        msg::TYPE_NEW_VISITOR_CONN_RESP => deser_msg!(payload, NewVisitorConnResp, ""),
        msg::TYPE_UDP_PACKET => deser_msg!(payload, UDPPacket, ""),
        msg::TYPE_NAT_HOLE_VISITOR => {
            let v: msg::NatHoleVisitor = serde_json::from_slice(payload).map_err(|e| {
                crate::Error::Protocol(format!("deserialize NatHoleVisitor: {e}").into())
            })?;
            tracing::debug!(
                transaction_id = ?v.transaction_id,
                proxy_name = %v.proxy_name,
                pre_check = %v.pre_check,
                "NatHoleVisitor deserialized: transaction_id={:?}, proxy_name={}, pre_check={}",
                v.transaction_id,
                v.proxy_name,
                v.pre_check
            );
            FrpMessage::NatHoleVisitor(v)
        }
        msg::TYPE_NAT_HOLE_CLIENT => deser_msg_boxed!(payload, NatHoleClient, ""),
        msg::TYPE_NAT_HOLE_RESP => deser_msg_boxed!(payload, NatHoleResp, ""),
        msg::TYPE_NAT_HOLE_SID => deser_msg!(payload, NatHoleSid, ""),
        msg::TYPE_NAT_HOLE_REPORT => deser_msg!(payload, NatHoleReport, ""),
        #[cfg(feature = "vnet")]
        msg::TYPE_VNET_ROUTE_ADVERTISE => deser_msg!(payload, VnetRouteAdvertise, ""),
        #[cfg(feature = "vnet")]
        msg::TYPE_VNET_PACKET => deser_msg!(payload, VnetPacket, ""),
        #[cfg(feature = "vnet")]
        msg::TYPE_VNET_ROUTE_REMOVE => deser_msg!(payload, VnetRouteRemove, ""),
        _ => {
            return Err(crate::Error::Protocol(
                format!("unknown V1 type byte: 0x{type_byte:02x}").into(),
            ))
        }
    };
    Ok(msg)
}

pub const V2_MAGIC_LEN: usize = 7;
pub const V2_MAGIC_BYTES: [u8; 7] = [0x46, 0x52, 0x50, 0x00, 0x02, 0x0D, 0x0A];
pub const V2_FRAME_TYPE_MESSAGE: u16 = 16;
pub const V2_MAX_FRAME_PAYLOAD: u32 = 64 * 1024;

/// V2 frame header size (Go wire.Conn format): type(2) + flags(2) + length(4) = 8 bytes.
/// Does NOT include magic bytes — magic is only at connection start.
pub const V2_FRAME_HEADER_LEN: usize = 8;

/// V2 frame type constants (matching Go frp pkg/proto/wire/wire.go).
pub const V2_FRAME_TYPE_CLIENT_HELLO: u16 = 1;
pub const V2_FRAME_TYPE_SERVER_HELLO: u16 = 2;
// V2_FRAME_TYPE_MESSAGE = 16 already exists above.

pub async fn write_v2_magic<W: AsyncWriteExt + Unpin>(writer: &mut W) -> Result<(), crate::Error> {
    writer
        .write_all(&V2_MAGIC_BYTES)
        .await
        .map_err(|e| crate::Error::Protocol(format!("write V2 magic: {e}").into()))?;
    Ok(())
}

/// Read and check V2 magic bytes from a stream.
/// Returns `Ok(None)` if magic matches (consumed).
/// Returns `Ok(Some(bytes))` if magic doesn't match — caller should replay these bytes.
/// Returns `Err` if the read itself fails.
pub async fn read_v2_magic_or_replay<R: AsyncReadExt + Unpin>(
    reader: &mut R,
) -> Result<Option<Vec<u8>>, crate::Error> {
    let mut buf = [0u8; V2_MAGIC_LEN];
    reader
        .read_exact(&mut buf)
        .await
        .map_err(|e| crate::Error::Protocol(format!("read V2 magic: {e}").into()))?;
    if buf == V2_MAGIC_BYTES {
        Ok(None)
    } else {
        Ok(Some(buf.to_vec()))
    }
}

/// Write a V2 frame whose 8-byte header slot (`buf[..V2_FRAME_HEADER_LEN]`)
/// was already reserved by the caller ahead of the payload.
///
/// Patches the header in place and issues a single contiguous `write_all(buf)`
/// — zero heap allocation and zero payload copy on every transport (including
/// non-vectored transports like yamux, TLS, WebSocket, and `CipherWriter`
/// where [`write_v2_frame_raw`] would otherwise merge header + payload into a
/// temporary buffer).
pub async fn write_v2_frame_in_place<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    frame_type: u16,
    flags: u16,
    buf: &mut [u8],
) -> Result<(), crate::Error> {
    if buf.len() < V2_FRAME_HEADER_LEN {
        return Err(crate::Error::Protocol(
            "V2 frame buffer shorter than header".into(),
        ));
    }
    let payload_len = buf.len() - V2_FRAME_HEADER_LEN;
    if payload_len > V2_MAX_FRAME_PAYLOAD as usize {
        return Err(crate::Error::Protocol(
            format!("V2 payload too large: {payload_len} > {V2_MAX_FRAME_PAYLOAD}").into(),
        ));
    }
    buf[0..2].copy_from_slice(&frame_type.to_be_bytes());
    buf[2..4].copy_from_slice(&flags.to_be_bytes());
    buf[4..8].copy_from_slice(&(payload_len as u32).to_be_bytes());

    tracing::trace!(
        frame_type = %frame_type,
        flags = %flags,
        payload_len = payload_len,
        "write V2 frame (in-place): type={}, flags={}, len={}",
        frame_type,
        flags,
        payload_len
    );

    writer
        .write_all(buf)
        .await
        .map_err(|e| crate::Error::Protocol(format!("write V2 frame: {e}").into()))?;
    Ok(())
}

/// Write a raw V2 frame: type(2 BE) + flags(2 BE) + length(4 BE) + payload.
/// This is the Go wire.Conn.WriteFrame format — magic is NOT repeated per frame.
pub async fn write_v2_frame_raw<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    frame_type: u16,
    flags: u16,
    payload: &[u8],
) -> Result<(), crate::Error> {
    if payload.len() > V2_MAX_FRAME_PAYLOAD as usize {
        return Err(crate::Error::Protocol(
            format!(
                "V2 payload too large: {} > {}",
                payload.len(),
                V2_MAX_FRAME_PAYLOAD
            )
            .into(),
        ));
    }
    let mut header = [0u8; V2_FRAME_HEADER_LEN];
    header[0..2].copy_from_slice(&frame_type.to_be_bytes());
    header[2..4].copy_from_slice(&flags.to_be_bytes());
    header[4..8].copy_from_slice(&(payload.len() as u32).to_be_bytes());

    tracing::trace!(
        frame_type = %frame_type,
        flags = %flags,
        payload_len = payload.len(),
        "write V2 frame: type={}, flags={}, len={}",
        frame_type,
        flags,
        payload.len()
    );

    // Header + payload go out as ONE writev(2) call. The old two write_all's
    // were two send() syscalls per frame on a raw TcpStream — and with
    // TCP_NODELAY (set on every data-path socket) the 8-byte header went out
    // as its own tiny segment: two packets and ~40 extra bytes of IP/TCP
    // header per frame on the UDP data plane. write_vectored maps to writev
    // on TcpStream: one syscall, no allocation, no payload memcpy, and the
    // kernel packs header + payload into one segment. writev may consume a
    // partial iovec, so retries continue from the exact unwritten byte.
    //
    // Transports whose is_write_vectored is false (yamux, KCP, WebSocket,
    // CipherWriter) take the merge branch below instead: tokio's default
    // poll_write_vectored only writes the first non-empty iovec, so the
    // vectored loop would issue the 8-byte header and the payload as TWO
    // writes. On yamux each poll_write becomes its own DATA frame, so a UDP
    // packet cost two frames (two frame headers + two body copies) instead of
    // one. Merging into a single buffer restores one write per frame; wire
    // bytes are unchanged because the header is still followed contiguously
    // by the same payload.
    if !writer.is_write_vectored() {
        // Merge, then write once. `total` includes the 8-byte header: at
        // most 256 B copies into a stack buffer (no allocation), above that
        // into one temporary heap buffer. Either buffer goes out through a
        // single `write_all`. The vectored path below is unchanged: each
        // poll passes the two original iovecs to `write_vectored` — no copy
        // and no allocation — retrying from the first unwritten byte.
        const MERGE_STACK_MAX: usize = 256;
        let total = header.len() + payload.len();
        if total <= MERGE_STACK_MAX {
            let mut merged = [0u8; MERGE_STACK_MAX];
            merged[..header.len()].copy_from_slice(&header);
            merged[header.len()..total].copy_from_slice(payload);
            writer
                .write_all(&merged[..total])
                .await
                .map_err(|e| crate::Error::Protocol(format!("write V2 frame: {e}").into()))?;
        } else {
            let mut merged = Vec::with_capacity(total);
            merged.extend_from_slice(&header);
            merged.extend_from_slice(payload);
            writer
                .write_all(&merged)
                .await
                .map_err(|e| crate::Error::Protocol(format!("write V2 frame: {e}").into()))?;
        }
        return Ok(());
    }

    let mut hdr_off = 0usize;
    let mut payload_off = 0usize;
    loop {
        if hdr_off >= header.len() && payload_off >= payload.len() {
            break;
        }
        let bufs = [
            std::io::IoSlice::new(&header[hdr_off..]),
            std::io::IoSlice::new(&payload[payload_off..]),
        ];
        let n = writer
            .write_vectored(&bufs)
            .await
            .map_err(|e| crate::Error::Protocol(format!("write V2 frame: {e}").into()))?;
        if n == 0 {
            return Err(crate::Error::Protocol(
                "write V2 frame: zero-length write".into(),
            ));
        }
        let mut rem = n;
        if hdr_off < header.len() {
            let take = rem.min(header.len() - hdr_off);
            hdr_off += take;
            rem -= take;
        }
        let take = rem.min(payload.len() - payload_off);
        payload_off += take;
        rem -= take;
        debug_assert_eq!(rem, 0);
    }
    Ok(())
}

/// Read a V2 frame header (8 bytes) and validate its flags and payload length.
/// Shared by [`read_v2_frame_raw`] (owned payload) and [`read_msg_v2`] (which
/// deserializes directly from the buffer pool, avoiding a `to_vec` copy).
async fn read_v2_frame_header<R: AsyncReadExt + Unpin>(
    reader: &mut R,
) -> Result<(u16, u16, usize), crate::Error> {
    let mut header = [0u8; V2_FRAME_HEADER_LEN];
    reader
        .read_exact(&mut header)
        .await
        .map_err(|e| crate::Error::Protocol(format!("read V2 frame: {e}").into()))?;

    let frame_type = u16::from_be_bytes([header[0], header[1]]);
    let flags = u16::from_be_bytes([header[2], header[3]]);
    let payload_len = u32::from_be_bytes([header[4], header[5], header[6], header[7]]) as usize;

    tracing::debug!(
        frame_type = %frame_type,
        flags = %flags,
        payload_len = %payload_len,
        "read V2 frame: type={}, flags={}, len={}",
        frame_type,
        flags,
        payload_len
    );

    if flags != 0 {
        return Err(crate::Error::Protocol(
            format!("unsupported V2 frame flags: {flags}").into(),
        ));
    }
    if payload_len > V2_MAX_FRAME_PAYLOAD as usize {
        return Err(crate::Error::Protocol(
            format!("V2 frame payload too large: {payload_len}").into(),
        ));
    }

    Ok((frame_type, flags, payload_len))
}

/// Read a raw V2 frame. Returns (frame_type, flags, payload).
/// This is the Go wire.Conn.ReadFrame format.
///
/// Frame type bytes: V2 uses wire-level constants from Go frp's
/// `pkg/proto/wire/wire.go`:
///   - `1` — ClientHello
///   - `2` — ServerHello
///   - `16` — Message (data-carrying frame)
///
/// Go-compatible peers recognize only these three types. Unknown types
/// are rejected. (V1 type bytes 7 (CloseProxyResp) and 8 (Error) are
/// Rust-only extensions and do NOT apply to the V2 frame path.)
pub async fn read_v2_frame_raw<R: AsyncReadExt + Unpin>(
    reader: &mut R,
) -> Result<(u16, u16, Vec<u8>), crate::Error> {
    let (frame_type, flags, payload_len) = read_v2_frame_header(reader).await?;

    // Read directly into the returned Vec, mirroring read_v1_frame. The
    // global buffer pool is deliberately not used here: its payoff is
    // avoiding copies for buffers that outlive one message, but this API
    // must hand back an owned `Vec<u8>`, so a pooled read would still
    // `to_vec` the payload before the guard drops — one extra copy plus
    // pool acquire/release traffic for nothing. The per-message control-path
    // reader (`read_msg_v2`) keeps the pooled no-copy fast path; this
    // raw-frame reader is handshake / once-per-connection only.
    let mut payload = vec![0u8; payload_len];
    reader
        .read_exact(&mut payload)
        .await
        .map_err(|e| crate::Error::Protocol(format!("read V2 payload: {e}").into()))?;

    Ok((frame_type, flags, payload))
}

/// Write V2 frame payload without flushing the writer.
///
/// Builds the V2 frame (header + type_id + JSON) and calls `write_all`.
/// Does NOT flush — callers that wrap a buffered transport (TLS, KCP,
/// WebSocket, yamux) must flush to push data to the underlying socket.
/// Callers that write to a raw TcpStream (with TCP_NODELAY) can skip flush.
pub(crate) async fn write_msg_v2_inner<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    msg: &FrpMessage,
) -> Result<(), crate::Error> {
    let mut buf = Vec::with_capacity(V2_FRAME_HEADER_LEN + 2 + 512);
    write_msg_v2_inner_scratch(writer, msg, &mut buf).await
}

/// [`write_msg_v2_inner`] reusing a caller-owned `scratch` buffer (cleared per
/// call) with 8-byte V2 frame header headroom, eliminating per-message heap
/// allocations on repeated V2 JSON sends.
async fn write_msg_v2_inner_scratch<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    msg: &FrpMessage,
    scratch: &mut Vec<u8>,
) -> Result<(), crate::Error> {
    let type_id = msg.v2_type_id();

    scratch.clear();
    scratch.resize(V2_FRAME_HEADER_LEN, 0);
    scratch.extend_from_slice(&type_id.to_be_bytes());
    if let Err(e) = serde_json::to_writer(&mut *scratch, msg) {
        scratch.clear();
        return Err(crate::Error::Protocol(
            format!("V2 JSON serialize: {e}").into(),
        ));
    }

    write_v2_frame_in_place(writer, V2_FRAME_TYPE_MESSAGE, 0, scratch).await
}

/// Write a FrpMessage using Go-compatible V2 framing.
/// Frame: type=16(Message) flags=0, payload = type_id(2 BE) + JSON.
///
/// NOTE: V2 type IDs 21 (CloseProxyResp) and 22 (Error) are Rust-only
/// extensions (renumbered off 19/20 after Go frp v0.71.0 assigned 19 to
/// UDPPacketBinary). Go frp treats unknown type IDs as errors — these MUST
/// NOT be sent to Go peers. See msg.rs lines 59-68.
///
/// Flush is called after write to support buffered transports (TLS, KCP,
/// WebSocket, yamux). For callers that manage flush themselves (e.g.
/// `IoStream::write_v2_frame`), use `write_msg_v2_inner` to avoid a
/// redundant flush on raw TcpStream where TCP_NODELAY already sends immediately.
pub async fn write_msg_v2<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    msg: &FrpMessage,
) -> Result<(), crate::Error> {
    write_msg_v2_inner(writer, msg).await?;
    writer
        .flush()
        .await
        .map_err(|e| crate::Error::Protocol(format!("flush after write_msg_v2: {e}").into()))?;
    Ok(())
}

/// Read a FrpMessage using Go-compatible V2 framing.
/// Expects frame type=16, extracts 2-byte type ID from payload prefix.
pub async fn read_msg_v2<R: AsyncReadExt + Unpin>(
    reader: &mut R,
) -> Result<FrpMessage, crate::Error> {
    let (frame_type, _flags, payload_len) = read_v2_frame_header(reader).await?;
    if frame_type != V2_FRAME_TYPE_MESSAGE {
        return Err(crate::Error::Protocol(
            format!(
                "unexpected V2 frame type: {frame_type}, expected {} (Message)",
                V2_FRAME_TYPE_MESSAGE
            )
            .into(),
        ));
    }
    if payload_len < 2 {
        return Err(crate::Error::Protocol(
            "V2 message payload too short".into(),
        ));
    }

    // Deserialize directly from the pooled buffer for small payloads,
    // matching the V1 read path — no intermediate `to_vec` copy.  Larger
    // payloads fall back to a direct heap allocation.
    let pool_size = *crate::buffer_pool::BUFFER_SIZE;
    if payload_len <= pool_size {
        let mut guard = crate::buffer_pool::PoolGuard::acquire();
        reader
            .read_exact(&mut guard.as_mut_slice()[..payload_len])
            .await
            .map_err(|e| crate::Error::Protocol(format!("read V2 payload: {e}").into()))?;
        let payload = &guard.raw_buf()[..payload_len];
        let type_id = u16::from_be_bytes([payload[0], payload[1]]);
        deserialize_v2(type_id, &payload[2..])
    } else {
        let mut payload = vec![0u8; payload_len];
        reader
            .read_exact(&mut payload)
            .await
            .map_err(|e| crate::Error::Protocol(format!("read V2 payload: {e}").into()))?;
        let type_id = u16::from_be_bytes([payload[0], payload[1]]);
        deserialize_v2(type_id, &payload[2..])
    }
}

/// Read a V2 frame's 2-byte message type ID and body into the caller's
/// `scratch` (shared by [`read_msg_v2_with_udp_codec`] and
/// [`read_msg_v2_udp_binary_socket`]).
///
/// The codec body lands at the start of `scratch`: the binary UDP decoders
/// then hand `scratch`'s buffer to the packet content Vec (zero copy, zero
/// alloc), and the callers refill `scratch` from the global pool when a
/// decoder took it. All callers wrap the read half in a BufReader, so the
/// extra `read_exact` is a buffer hit, not a syscall.
async fn read_v2_message_body<R: AsyncReadExt + Unpin>(
    reader: &mut R,
    payload_len: usize,
    scratch: &mut Vec<u8>,
) -> Result<u16, crate::Error> {
    // Read the payload into the caller-supplied scratch (this path is UDP
    // data-plane only; the buffer-pool fast path of read_msg_v2 is not worth
    // duplicating here since UDP payloads are typically small). The caller
    // holds `scratch` outside its message loop and reuses it across frames,
    // avoiding a heap allocation per UDP packet.
    let mut type_id_buf = [0u8; 2];
    reader
        .read_exact(&mut type_id_buf)
        .await
        .map_err(|e| crate::Error::Protocol(format!("read V2 payload: {e}").into()))?;
    let type_id = u16::from_be_bytes(type_id_buf);
    let body_len = payload_len - 2;
    scratch.clear();
    scratch.reserve(body_len);
    // Set the length without the `resize`-style zero-fill: `read_exact`
    // below immediately overwrites the entire buffer, so the memset would be
    // pure waste on the per-UDP-packet hot path (audit #14d).
    // SAFETY: the region is written in full by `read_exact` on the next line
    // *before* any element is read; tokio::io::AsyncReadExt then reads into
    // the exact length we just set. `#[allow(clippy::uninit_vec)]` silences
    // clippy's uninit_vec lint (flags the reserve→set_len shape), which is
    // precisely the intentional use here.
    #[allow(clippy::uninit_vec)]
    unsafe {
        scratch.set_len(body_len);
    }
    reader
        .read_exact(scratch.as_mut_slice())
        .await
        .map_err(|e| crate::Error::Protocol(format!("read V2 payload: {e}").into()))?;
    Ok(type_id)
}

/// Read a V2 message on a connection where a UDP packet binary codec may be
/// negotiated (Go frp v0.71.0). When `udp_packet_codec` is `Some("binary-v1")`,
/// a frame with type ID 19 (`V2_TYPE_UDP_PACKET_BINARY`) is decoded with the
/// binary codec into a `FrpMessage::UDPPacket`; a JSON `UDPPacket` (type 13)
/// after binary negotiation is a protocol error, matching Go
/// `V2BinaryUDPPacketReadWriter`. When `udp_packet_codec` is `None`/empty,
/// this is exactly `read_msg_v2`.
pub async fn read_msg_v2_with_udp_codec<R: AsyncReadExt + Unpin>(
    reader: &mut R,
    udp_packet_codec: Option<&str>,
    scratch: &mut Vec<u8>,
) -> Result<FrpMessage, crate::Error> {
    let (frame_type, _flags, payload_len) = read_v2_frame_header(reader).await?;
    if frame_type != V2_FRAME_TYPE_MESSAGE {
        return Err(crate::Error::Protocol(
            format!(
                "unexpected V2 frame type: {frame_type}, expected {} (Message)",
                V2_FRAME_TYPE_MESSAGE
            )
            .into(),
        ));
    }
    if payload_len < 2 {
        return Err(crate::Error::Protocol(
            "V2 message payload too short".into(),
        ));
    }

    let type_id = read_v2_message_body(reader, payload_len, scratch).await?;

    let binary = udp_packet_codec == Some(crate::udp_binary::UDP_PACKET_CODEC_BINARY);
    if type_id == msg::V2_TYPE_UDP_PACKET_BINARY {
        if !binary {
            return Err(crate::Error::Protocol(
                format!(
                    "received binary UDP packet (type {}) without negotiated codec",
                    msg::V2_TYPE_UDP_PACKET_BINARY
                )
                .into(),
            ));
        }
        let packet = crate::udp_binary::decode_udp_packet_binary_owned(scratch)
            .map_err(|e| crate::Error::Protocol(format!("decode binary UDP packet: {e}").into()))?;
        // Small packets: the decoder copied the payload out and left
        // `scratch` intact — keep it in the loop, so the buffer pool is
        // untouched and the steady-state read path is zero-alloc (round-7
        // audit M2 follow-up: the unconditional refill drained one pool
        // buffer per packet — the pool was exhausted after 128 packets and
        // every packet cost a fresh pool-sized malloc + free). Large datagrams
        // (≥ `udp_binary::TAKE_PAYLOAD_THRESHOLD`): the decoder moved the
        // buffer into the packet's content Vec (a plain Vec, freed to the
        // allocator on drop — it never returns to the pool), so refill from
        // the pool here.
        if scratch.is_empty() {
            *scratch = crate::buffer_pool::BUFFER_POOL.acquire();
        }
        return Ok(FrpMessage::UDPPacket(packet));
    }
    if binary && type_id == msg::V2_TYPE_UDP_PACKET {
        // Go: received JSON UDP packet after binary codec negotiation.
        return Err(crate::Error::Protocol(
            "received JSON UDP packet after binary codec negotiation".into(),
        ));
    }
    deserialize_v2(type_id, scratch)
}

/// A frame read on a binary-UDP-codec data plane
/// ([`read_msg_v2_udp_binary_socket`]).
#[derive(Debug)]
pub enum UdpBinaryRead {
    /// Type-19 frame decoded to native addresses — neither address was
    /// formatted to a String (audit: the terminal consumers re-parsed the
    /// formatted text per datagram).
    Socket(crate::udp_binary::SocketUdpPacket),
    /// Any other frame JSON-decoded, or a type-19 frame whose address carries
    /// a family-6 *zone* (not representable in a
    /// [`std::net::SocketAddr`] — std has a numeric scope id, not an
    /// interface name) that fell back to the message-form decoder.
    Message(FrpMessage),
}

/// Read a V2 message frame on a binary-UDP-codec data plane
/// (callers gate on `udp_packet_codec == Some("binary-v1")`). A type-19
/// frame decodes to [`UdpBinaryRead::Socket`] when both addresses are
/// zone-less — the zero-alloc decode of
/// [`decode_udp_packet_binary_socket_owned`](crate::udp_binary::decode_udp_packet_binary_socket_owned),
/// no per-packet String alloc. A zoned type-19 frame falls back to the
/// message-form decode of the same buffer (`UdpBinaryRead::Message`), which
/// every consumer of [`read_msg_v2_with_udp_codec`] already handles.
pub async fn read_msg_v2_udp_binary_socket<R: AsyncReadExt + Unpin>(
    reader: &mut R,
    scratch: &mut Vec<u8>,
) -> Result<UdpBinaryRead, crate::Error> {
    let (frame_type, _flags, payload_len) = read_v2_frame_header(reader).await?;
    if frame_type != V2_FRAME_TYPE_MESSAGE {
        return Err(crate::Error::Protocol(
            format!(
                "unexpected V2 frame type: {frame_type}, expected {} (Message)",
                V2_FRAME_TYPE_MESSAGE
            )
            .into(),
        ));
    }
    if payload_len < 2 {
        return Err(crate::Error::Protocol(
            "V2 message payload too short".into(),
        ));
    }
    let type_id = read_v2_message_body(reader, payload_len, scratch).await?;
    match type_id {
        msg::V2_TYPE_UDP_PACKET_BINARY => {
            match crate::udp_binary::decode_udp_packet_binary_socket_owned(scratch).map_err(
                |e| crate::Error::Protocol(format!("decode binary UDP packet: {e}").into()),
            )? {
                Some(packet) => {
                    // Large datagram (≥ TAKE_PAYLOAD_THRESHOLD): the decoder moved the
                    // buffer into the packet's content Vec (same ownership
                    // semantics as the message-form decoder, round-7 M2) —
                    // refill from the pool for the next read.
                    if scratch.is_empty() {
                        *scratch = crate::buffer_pool::BUFFER_POOL.acquire();
                    }
                    Ok(UdpBinaryRead::Socket(packet))
                }
                None => {
                    // Zoned family-6 address (a Go peer with a link-local
                    // service): re-decode the untouched buffer to the
                    // message form, which carries the zone as text.
                    let packet = crate::udp_binary::decode_udp_packet_binary_owned(scratch)
                        .map_err(|e| {
                            crate::Error::Protocol(format!("decode binary UDP packet: {e}").into())
                        })?;
                    if scratch.is_empty() {
                        *scratch = crate::buffer_pool::BUFFER_POOL.acquire();
                    }
                    Ok(UdpBinaryRead::Message(FrpMessage::UDPPacket(packet)))
                }
            }
        }
        msg::V2_TYPE_UDP_PACKET => {
            // Go: received JSON UDP packet after binary codec negotiation.
            Err(crate::Error::Protocol(
                "received JSON UDP packet after binary codec negotiation".into(),
            ))
        }
        _ => deserialize_v2(type_id, scratch).map(UdpBinaryRead::Message),
    }
}

/// Write a V2 message frame, using the binary UDP packet codec for
/// `UDPPacket` messages when `udp_packet_codec` is `Some("binary-v1")`
/// (Go frp v0.71.0). Non-UDPPacket messages always use JSON framing.
/// When `udp_packet_codec` is `None`/empty this is exactly
/// `write_msg_v2_inner`.
///
/// `no_flush` mirrors `write_msg_v2_nof`: skip the trailing flush syscall for
/// raw TcpStream data planes where TCP_NODELAY already flushes per write.
/// `scratch` is the reusable buffer for both the binary codec and JSON paths
/// (cleared per call) — pass a buffer owned by the caller's task to avoid
/// per-packet allocations.
pub async fn write_msg_v2_with_udp_codec<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    msg: &FrpMessage,
    udp_packet_codec: Option<&str>,
    no_flush: bool,
    scratch: &mut Vec<u8>,
) -> Result<(), crate::Error> {
    let binary = udp_packet_codec == Some(crate::udp_binary::UDP_PACKET_CODEC_BINARY);
    if binary {
        if let FrpMessage::UDPPacket(packet) = msg {
            // Reserve the 8-byte V2 frame header slot ahead of type_id + body
            // so `write_v2_frame_in_place` patches the header in place and
            // emits one contiguous write — zero alloc and zero payload copy
            // even on non-vectored transports (yamux, TLS, CipherWriter).
            scratch.clear();
            scratch.resize(V2_FRAME_HEADER_LEN, 0);
            scratch.extend_from_slice(&msg::V2_TYPE_UDP_PACKET_BINARY.to_be_bytes());
            if let Err(e) = crate::udp_binary::encode_udp_packet_binary_into(packet, scratch) {
                scratch.clear();
                return Err(crate::Error::Protocol(
                    format!("encode binary UDP packet: {e}").into(),
                ));
            }
            write_v2_frame_in_place(writer, V2_FRAME_TYPE_MESSAGE, 0, scratch).await?;
            // Flush unless the caller manages it (raw TcpStream + TCP_NODELAY,
            // or a CipherWriter that must flush to emit its IV). Without this,
            // buffered transports (TLS, yamux, WebSocket) and encrypted
            // streams leave binary UDP frames stuck in the buffer.
            if !no_flush {
                writer.flush().await.map_err(|e| {
                    crate::Error::Protocol(format!("flush after binary UDP packet: {e}").into())
                })?;
            }
            return Ok(());
        }
    }
    write_msg_v2_inner_scratch(writer, msg, scratch).await?;
    if !no_flush {
        writer
            .flush()
            .await
            .map_err(|e| crate::Error::Protocol(format!("flush after write_msg_v2: {e}").into()))?;
    }
    Ok(())
}

/// Protocol-aware message read: dispatches to V1 or V2 framing based on the `v2` flag.
pub async fn read_msg<R: AsyncReadExt + Unpin>(
    reader: &mut R,
    v2: bool,
) -> Result<FrpMessage, crate::Error> {
    if v2 {
        read_msg_v2(reader).await
    } else {
        read_msg_v1(reader).await
    }
}

/// Protocol-aware message write: dispatches to V1 or V2 framing based on the `v2` flag.
pub async fn write_msg<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    msg: &FrpMessage,
    v2: bool,
) -> Result<(), crate::Error> {
    if v2 {
        write_msg_v2(writer, msg).await
    } else {
        write_msg_v1(writer, msg).await
    }
}

#[cfg(test)]
mod tests;
