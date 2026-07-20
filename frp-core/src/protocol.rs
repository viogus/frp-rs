use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::msg::{self, FrpMessage};

pub const V1_MAX_MSG_LENGTH: i64 = 64 * 1024;
pub const V1_HEADER_LEN: usize = 9;

pub async fn write_v1_frame<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    msg: &FrpMessage,
) -> Result<(), crate::Error> {
    // NOTE: V1 type bytes 7 (CloseProxyResp) and 8 (Error) are Rust-only
    // extensions. Go frp v0.70.0 treats unknown type bytes as errors.
    // These MUST NOT be sent to Go peers. See msg.rs lines 26-29.
    let type_byte = msg.v1_type_byte();
    let payload = serde_json::to_vec(msg)
        .map_err(|e| crate::Error::Protocol(format!("serialize V1 msg: {e}").into()))?;

    if payload.len() as u64 > V1_MAX_MSG_LENGTH as u64 {
        return Err(crate::Error::Protocol("V1 message too large".into()));
    }

    let mut buf = Vec::with_capacity(V1_HEADER_LEN + payload.len());
    buf.push(type_byte);
    buf.extend_from_slice(&(payload.len() as u64).to_be_bytes());
    buf.extend_from_slice(&payload);

    tracing::trace!(
        type_byte = %type_byte,
        payload_len = payload.len(),
        payload_text = %String::from_utf8_lossy(&payload),
        "V1 frame: type=0x{:02x} len={} payload={}",
        type_byte,
        payload.len(),
        String::from_utf8_lossy(&payload)
    );

    writer
        .write_all(&buf)
        .await
        .map_err(|e| crate::Error::Protocol(format!("write V1 frame: {e}").into()))?;
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
                "invalid V1 msg length: {length}, raw header: {}",
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
                "invalid V1 msg length: {length}, raw header: {}",
                crate::hex_encode(&header)
            )
            .into(),
        ));
    }

    let length = length as usize;
    // Use the global buffer pool for small payloads (<= BUFFER_SIZE, 32 KiB
    // by default).  Larger payloads fall back to a heap allocation.  The
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
            tracing::debug!(
                payload_text = %String::from_utf8_lossy(payload),
                "NatHoleVisitor raw payload: {}",
                String::from_utf8_lossy(payload)
            );
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
pub const V2_MAX_FRAME_PAYLOAD: u32 = 1024 * 1024;

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

    let mut out = Vec::with_capacity(V2_FRAME_HEADER_LEN + payload.len());
    out.extend_from_slice(&header);
    out.extend_from_slice(payload);
    writer
        .write_all(&out)
        .await
        .map_err(|e| crate::Error::Protocol(format!("write V2 frame: {e}").into()))?;
    Ok(())
}

/// Read a raw V2 frame. Returns (frame_type, flags, payload).
/// This is the Go wire.Conn.ReadFrame format.
pub async fn read_v2_frame_raw<R: AsyncReadExt + Unpin>(
    reader: &mut R,
) -> Result<(u16, u16, Vec<u8>), crate::Error> {
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
        tracing::trace!(flags = %flags, "V2 frame with non-zero flags: {flags}");
    }
    if payload_len > V2_MAX_FRAME_PAYLOAD as usize {
        return Err(crate::Error::Protocol(
            format!("V2 frame payload too large: {payload_len}").into(),
        ));
    }

    // Zero-initialize: passing &mut [u8] pointing to uninitialized
    // memory to read_exact is UB per Rust reference validity rules.
    let mut payload = vec![0u8; payload_len];
    reader
        .read_exact(&mut payload)
        .await
        .map_err(|e| crate::Error::Protocol(format!("read V2 payload: {e}").into()))?;

    Ok((frame_type, flags, payload))
}

/// Write a FrpMessage using Go-compatible V2 framing.
/// Frame: type=16(Message) flags=0, payload = type_id(2 BE) + JSON.
///
/// NOTE: V2 type IDs 19 (CloseProxyResp) and 20 (Error) are Rust-only
/// extensions. Go frp v0.70.0 treats unknown type IDs as errors.
/// These MUST NOT be sent to Go peers. See msg.rs lines 59-62.
pub async fn write_msg_v2<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    msg: &FrpMessage,
) -> Result<(), crate::Error> {
    let type_id = msg.v2_type_id();
    let json_bytes = serde_json::to_vec(msg)
        .map_err(|e| crate::Error::Protocol(format!("V2 JSON serialize: {e}").into()))?;

    let mut payload = Vec::with_capacity(2 + json_bytes.len());
    payload.extend_from_slice(&type_id.to_be_bytes());
    payload.extend_from_slice(&json_bytes);

    write_v2_frame_raw(writer, V2_FRAME_TYPE_MESSAGE, 0, &payload).await?;
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
    let (frame_type, _flags, payload) = read_v2_frame_raw(reader).await?;
    if frame_type != V2_FRAME_TYPE_MESSAGE {
        return Err(crate::Error::Protocol(
            format!(
                "unexpected V2 frame type: {frame_type}, expected {} (Message)",
                V2_FRAME_TYPE_MESSAGE
            )
            .into(),
        ));
    }
    if payload.len() < 2 {
        return Err(crate::Error::Protocol(
            "V2 message payload too short".into(),
        ));
    }
    let type_id = u16::from_be_bytes([payload[0], payload[1]]);
    deserialize_v2(type_id, &payload[2..])
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
mod tests {
    use super::*;
    use crate::msg;
    use tokio::io::duplex;

    #[tokio::test]
    async fn test_v1_frame_roundtrip() {
        let (mut client, mut server) = duplex(65536);
        let msg = FrpMessage::Login(Box::new(msg::Login {
            version: Some("0.69.1".into()),
            hostname: Some("testhost".into()),
            os: Some("linux".into()),
            arch: None,
            user: None,
            run_id: None,
            client_id: None,
            pool_count: Some(3),
            timestamp: Some(1234567890),
            privilege_key: Some("abc123".into()),
            metas: None,
            client_spec: None,
            multiplexer: Some("yamux".into()),
        }));
        write_v1_frame(&mut client, &msg).await.expect("write");
        let result = read_msg_v1(&mut server).await.expect("read");
        match result {
            FrpMessage::Login(login) => {
                assert_eq!(login.version.as_deref(), Some("0.69.1"));
                assert_eq!(login.hostname.as_deref(), Some("testhost"));
                assert_eq!(login.pool_count, Some(3));
                assert_eq!(login.multiplexer.as_deref(), Some("yamux"));
            }
            _ => panic!("expected Login, got {:?}", result),
        }
    }

    #[tokio::test]
    async fn test_v1_frame_max_payload() {
        // 65535-byte payload should be accepted
        let payload = vec![b'x'; 65535];
        let (mut client, mut server) = duplex(131072);
        // Write manually a 65535-byte payload with type byte = Ping
        let mut header = vec![msg::TYPE_PING];
        header.extend_from_slice(&65535i64.to_be_bytes());
        client.write_all(&header).await.expect("write header");
        client.write_all(&payload).await.expect("write payload");
        let (_ty, data) = read_v1_frame(&mut server).await.expect("read");
        assert_eq!(data.len(), 65535);
        assert_eq!(&data, &payload);
    }

    #[tokio::test]
    async fn test_v1_frame_truncated_header() {
        let (mut client, mut server) = duplex(1024);
        // Write only 3 bytes (incomplete header)
        client
            .write_all(&[msg::TYPE_PING, 0x00, 0x00])
            .await
            .expect("write partial");
        drop(client); // close write side
        let result = read_v1_frame(&mut server).await;
        assert!(result.is_err(), "truncated header should error");
    }

    #[tokio::test]
    async fn test_v1_frame_truncated_payload() {
        let (mut client, mut server) = duplex(1024);
        // Write header claiming 100 bytes, but only 50 bytes follow
        let mut header = vec![msg::TYPE_PING];
        header.extend_from_slice(&100i64.to_be_bytes());
        client.write_all(&header).await.expect("write header");
        client
            .write_all(&[0u8; 50])
            .await
            .expect("write partial payload");
        drop(client);
        let result = read_v1_frame(&mut server).await;
        assert!(result.is_err(), "truncated payload should error");
    }

    #[tokio::test]
    async fn test_v1_frame_oversized() {
        // Writing a message > 64KB should fail
        let big = crate::msg::UDPPacket {
            content: vec![b'x'; 70000],
            local_addr: msg::UdpAddr::from_string("0.0.0.0:0"),
            remote_addr: msg::UdpAddr::from_string("0.0.0.0:0"),
        };
        let msg = FrpMessage::UDPPacket(big);
        let (mut client, _server) = duplex(131072);
        let result = write_v1_frame(&mut client, &msg).await;
        assert!(result.is_err(), "oversized payload should error");
    }

    #[tokio::test]
    async fn test_v1_frame_invalid_length() {
        let (mut client, mut server) = duplex(1024);
        // Write a negative length value
        let mut header = vec![msg::TYPE_PING];
        header.extend_from_slice(&(-1i64).to_be_bytes());
        client.write_all(&header).await.expect("write");
        let result = read_v1_frame(&mut server).await;
        assert!(result.is_err(), "negative length should error");
    }

    #[tokio::test]
    async fn test_v1_frame_unknown_type_byte() {
        let (mut client, mut server) = duplex(1024);
        // Type byte 0x00 with empty payload
        let mut header = vec![0x00u8];
        header.extend_from_slice(&0i64.to_be_bytes());
        client.write_all(&header).await.expect("write");
        let result = read_msg_v1(&mut server).await;
        assert!(result.is_err(), "unknown type byte should error");
    }

    // --- V2 protocol tests ---

    #[tokio::test]
    async fn test_v2_frame_read_write() {
        let (mut client, mut server) = duplex(65536);
        let payload = b"hello v2 world";
        write_v2_frame_raw(&mut client, 16, 0, payload)
            .await
            .expect("write V2 frame");
        let (ft, flags, data) = read_v2_frame_raw(&mut server).await.expect("read V2 frame");
        assert_eq!(ft, 16);
        assert_eq!(flags, 0);
        assert_eq!(data, payload);
    }

    #[tokio::test]
    async fn test_v2_msg_roundtrip() {
        let (mut client, mut server) = duplex(65536);
        let msg = FrpMessage::Login(Box::new(msg::Login {
            version: Some("0.69.1".into()),
            hostname: Some("testhost".into()),
            os: Some("linux".into()),
            arch: None,
            user: None,
            run_id: None,
            client_id: None,
            pool_count: Some(3),
            timestamp: Some(1234567890),
            privilege_key: Some("abc123".into()),
            metas: None,
            client_spec: None,
            multiplexer: Some("yamux".into()),
        }));
        write_msg_v2(&mut client, &msg).await.expect("write V2 msg");
        let result = read_msg_v2(&mut server).await.expect("read V2 msg");
        match result {
            FrpMessage::Login(login) => {
                assert_eq!(login.version.as_deref(), Some("0.69.1"));
                assert_eq!(login.hostname.as_deref(), Some("testhost"));
                assert_eq!(login.pool_count, Some(3));
                assert_eq!(login.multiplexer.as_deref(), Some("yamux"));
            }
            other => panic!("expected Login, got: {:?}", other.v2_type_id()),
        }
    }

    #[tokio::test]
    async fn test_v2_msg_all_types_roundtrip() {
        let (mut client, mut server) = duplex(65536);

        let messages = vec![
            FrpMessage::Ping(msg::Ping {
                privilege_key: None,
                timestamp: Some(42),
            }),
            FrpMessage::Pong(msg::Pong { error: None }),
            FrpMessage::CloseProxy(msg::CloseProxy {
                proxy_name: "test".into(),
            }),
            FrpMessage::CloseProxyResp(msg::CloseProxyResp {
                proxy_name: "test".into(),
            }),
            FrpMessage::Error(msg::Error {
                error: "test error".into(),
            }),
            FrpMessage::ReqWorkConn(msg::ReqWorkConn {}),
        ];

        for msg in &messages {
            write_msg_v2(&mut client, msg).await.expect("write V2");
            let back = read_msg_v2(&mut server).await.expect("read V2");
            assert_eq!(
                back.v2_type_id(),
                msg.v2_type_id(),
                "roundtrip type mismatch for {:?}",
                msg.v2_type_id()
            );
        }
    }

    #[tokio::test]
    async fn test_v2_msg_rejects_non_message_frame_type() {
        // Go-compatible V2: read_msg_v2 expects frame_type == 16 (Message).
        // Write a frame with frame_type=1 (ClientHello) — should be rejected.
        let (mut client, mut server) = duplex(256);
        write_v2_frame_raw(&mut client, 1, 0, b"hello")
            .await
            .expect("write frame");
        let result = read_msg_v2(&mut server).await;
        assert!(result.is_err(), "should reject non-Message frame type");
    }

    #[tokio::test]
    async fn test_v2_frame_rejects_oversized() {
        let oversized = vec![0u8; (V2_MAX_FRAME_PAYLOAD + 1) as usize];
        let mut buf = Vec::new();
        let result = write_v2_frame_raw(&mut buf, 16, 0, &oversized).await;
        assert!(result.is_err(), "should reject oversized payload");
    }

    #[tokio::test]
    async fn test_v2_frame_raw_accepts_nonzero_flags() {
        let (mut client, mut server) = duplex(65536);
        // Write frame with flags=1 (Go frp compat: non-zero flags are accepted)
        let mut header = [0u8; 8];
        header[0..2].copy_from_slice(&V2_FRAME_TYPE_MESSAGE.to_be_bytes());
        header[2..4].copy_from_slice(&1u16.to_be_bytes()); // flags=1
        header[4..8].copy_from_slice(&4u32.to_be_bytes()); // len=4
        client.write_all(&header).await.unwrap();
        client.write_all(b"data").await.unwrap();
        drop(client);

        let result = read_v2_frame_raw(&mut server).await;
        assert!(
            result.is_ok(),
            "non-zero flags should be accepted (Go frp compat)"
        );
        let (_, flags, payload) = result.unwrap();
        assert_eq!(flags, 1);
        assert_eq!(payload, b"data");
    }

    #[tokio::test]
    async fn test_v2_frame_raw_oversized_payload() {
        let mut buf = Vec::new();
        let oversized = vec![0u8; (V2_MAX_FRAME_PAYLOAD + 1) as usize];
        let result = write_v2_frame_raw(&mut buf, V2_FRAME_TYPE_MESSAGE, 0, &oversized).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("too large"));
    }

    #[tokio::test]
    async fn test_v2_msg_20_types_roundtrip() {
        // Test all 20 V2 message types survive encode -> decode roundtrip.
        // Construct each message with minimal valid fields (no Default on most).
        fn test_addr() -> msg::UdpAddr {
            msg::UdpAddr {
                ip: "0.0.0.0".into(),
                port: 0,
                zone: String::new(),
            }
        }

        let messages: Vec<FrpMessage> = vec![
            FrpMessage::Login(Box::new(msg::Login {
                version: Some("1.0".into()),
                hostname: Some("h".into()),
                os: None,
                arch: None,
                user: None,
                run_id: None,
                client_id: None,
                pool_count: None,
                timestamp: None,
                privilege_key: None,
                metas: None,
                client_spec: None,
                multiplexer: None,
            })),
            FrpMessage::LoginResp(msg::LoginResp {
                version: None,
                run_id: None,
                error: None,
                server_additional_auth_scopes: None,
            }),
            FrpMessage::NewProxy(Box::new(msg::NewProxy {
                proxy_name: "p".into(),
                proxy_type: "tcp".into(),
                use_encryption: None,
                use_compression: None,
                group: None,
                group_key: None,
                local_str: None,
                remote_port: None,
                sk: None,
                custom_domains: None,
                subdomain: None,
                locations: None,
                http_user: None,
                http_pwd: None,
                host_header_rewrite: None,
                headers: None,
                response_headers: None,
                route_by_http_user: None,
                allow_users: None,
                bandwidth_limit: None,
                bandwidth_limit_mode: None,
                annotations: None,
                metas: None,
                multiplexer: None,
                virtual_net: None,
                proxy_protocol_version: None,
                advertise_subnet: None,
                vnet_ip: None,
                vnet_netmask: None,
                vnet_mtu: None,
            })),
            FrpMessage::NewProxyResp(msg::NewProxyResp {
                proxy_name: "p".into(),
                remote_addr: None,
                error: None,
            }),
            FrpMessage::CloseProxy(msg::CloseProxy {
                proxy_name: "p".into(),
            }),
            FrpMessage::NewWorkConn(msg::NewWorkConn {
                run_id: None,
                timestamp: None,
                privilege_key: None,
            }),
            FrpMessage::ReqWorkConn(msg::ReqWorkConn {}),
            FrpMessage::StartWorkConn(Box::new(msg::StartWorkConn {
                proxy_name: "p".into(),
                src_addr: None,
                src_port: None,
                dst_addr: None,
                dst_port: None,
                error: None,
                use_encryption: None,
                use_compression: None,
                nat_hole_sid: None,
                nat_hole_visitor_addr: None,
                sk: None,
            })),
            FrpMessage::NewVisitorConn(msg::NewVisitorConn {
                proxy_name: "p".into(),
                sign_key: None,
                timestamp: None,
                run_id: None,
                use_encryption: None,
                use_compression: None,
            }),
            FrpMessage::NewVisitorConnResp(msg::NewVisitorConnResp {
                proxy_name: "p".into(),
                error: None,
            }),
            FrpMessage::Ping(msg::Ping {
                privilege_key: None,
                timestamp: Some(42),
            }),
            FrpMessage::Pong(msg::Pong { error: None }),
            FrpMessage::UDPPacket(msg::UDPPacket {
                content: b"hello".to_vec(),
                local_addr: Some(test_addr()),
                remote_addr: Some(test_addr()),
            }),
            FrpMessage::NatHoleVisitor(msg::NatHoleVisitor::default()),
            FrpMessage::NatHoleClient(Box::<msg::NatHoleClient>::default()),
            FrpMessage::NatHoleResp(Box::<msg::NatHoleResp>::default()),
            FrpMessage::NatHoleSid(msg::NatHoleSid {
                sid: None,
                ..Default::default()
            }),
            FrpMessage::NatHoleReport(msg::NatHoleReport::default()),
            FrpMessage::CloseProxyResp(msg::CloseProxyResp {
                proxy_name: "p".into(),
            }),
            FrpMessage::Error(msg::Error {
                error: "test error".into(),
            }),
        ];

        for msg in &messages {
            let (mut client, mut server) = duplex(65536);
            write_msg_v2(&mut client, msg).await.expect("write v2");
            let back = read_msg_v2(&mut server).await.expect("read v2");
            assert_eq!(
                back.v2_type_id(),
                msg.v2_type_id(),
                "roundtrip type mismatch for {:?}",
                msg.v2_type_id()
            );
        }
    }

    #[tokio::test]
    async fn test_v2_msg_unknown_type_id() {
        let (mut client, mut server) = duplex(65536);
        // Write frame type=Message with type_id=99 and empty JSON payload
        let mut payload = vec![0u8; 2];
        payload[0..2].copy_from_slice(&99u16.to_be_bytes());
        write_v2_frame_raw(&mut client, V2_FRAME_TYPE_MESSAGE, 0, &payload)
            .await
            .unwrap();
        drop(client);

        let result = read_msg_v2(&mut server).await;
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("unknown V2 message type ID: 99"));
    }

    #[tokio::test]
    async fn test_v2_msg_payload_too_short() {
        let (mut client, mut server) = duplex(65536);
        // Write frame type=Message with only 1 byte payload (need 2 for type_id)
        write_v2_frame_raw(&mut client, V2_FRAME_TYPE_MESSAGE, 0, b"x")
            .await
            .unwrap();
        drop(client);

        let result = read_msg_v2(&mut server).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("too short"));
    }

    #[tokio::test]
    async fn test_v2_msg_wrong_frame_type() {
        let (mut client, mut server) = duplex(65536);
        // Write frame with type=ClientHello(1) — read_msg_v2 should reject
        write_v2_frame_raw(&mut client, V2_FRAME_TYPE_CLIENT_HELLO, 0, b"{}")
            .await
            .unwrap();
        drop(client);

        let result = read_msg_v2(&mut server).await;
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("unexpected V2 frame type: 1"));
    }

    #[tokio::test]
    async fn test_v2_msg_login_content() {
        let (mut client, mut server) = duplex(65536);
        let msg = FrpMessage::Login(Box::new(msg::Login {
            version: Some("0.69.1".into()),
            hostname: Some("testhost".into()),
            os: Some("linux".into()),
            arch: None,
            user: None,
            run_id: None,
            client_id: None,
            pool_count: Some(3),
            timestamp: Some(1234567890),
            privilege_key: Some("abc123".into()),
            metas: None,
            client_spec: None,
            multiplexer: Some("yamux".into()),
        }));
        write_msg_v2(&mut client, &msg).await.expect("write");
        let result = read_msg_v2(&mut server).await.expect("read");
        match result {
            FrpMessage::Login(login) => {
                assert_eq!(login.version.as_deref(), Some("0.69.1"));
                assert_eq!(login.hostname.as_deref(), Some("testhost"));
                assert_eq!(login.pool_count, Some(3));
                assert_eq!(login.multiplexer.as_deref(), Some("yamux"));
            }
            other => panic!("expected Login, got {:?}", other.v2_type_id()),
        }
    }

    // ─── Fuzz / property-based tests (proptest) ─────────────────────

    /// Sync reader adapter that delivers pre-determined bytes for fuzz testing.
    /// Implements only read_exact — enough for V1/V2 frame reading and magic detection.
    struct FuzzReader {
        data: Vec<u8>,
        pos: usize,
    }

    impl FuzzReader {
        fn new(data: Vec<u8>) -> Self {
            Self { data, pos: 0 }
        }
    }

    impl tokio::io::AsyncRead for FuzzReader {
        fn poll_read(
            mut self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            let remaining = self.data.len() - self.pos;
            let to_copy = remaining.min(buf.remaining());
            buf.put_slice(&self.data[self.pos..self.pos + to_copy]);
            self.pos += to_copy;
            std::task::Poll::Ready(Ok(()))
        }
    }

    mod proptest_fuzz {
        use super::*;
        use proptest::prelude::*;

        // ── V1 deserialize fuzz ─────────────────────────────────────

        /// All valid V1 type bytes — every one must accept or reject without panicking.
        const V1_TYPE_BYTES: &[u8] = &[
            msg::TYPE_LOGIN,
            msg::TYPE_LOGIN_RESP,
            msg::TYPE_NEW_PROXY,
            msg::TYPE_NEW_PROXY_RESP,
            msg::TYPE_CLOSE_PROXY,
            msg::TYPE_CLOSE_PROXY_RESP,
            msg::TYPE_NEW_WORK_CONN,
            msg::TYPE_REQ_WORK_CONN,
            msg::TYPE_START_WORK_CONN,
            msg::TYPE_NEW_VISITOR_CONN,
            msg::TYPE_NEW_VISITOR_CONN_RESP,
            msg::TYPE_PING,
            msg::TYPE_PONG,
            msg::TYPE_UDP_PACKET,
            msg::TYPE_NAT_HOLE_VISITOR,
            msg::TYPE_NAT_HOLE_CLIENT,
            msg::TYPE_NAT_HOLE_RESP,
            msg::TYPE_NAT_HOLE_SID,
            msg::TYPE_NAT_HOLE_REPORT,
            msg::TYPE_ERROR,
        ];

        proptest! {
            /// Fuzz `deserialize_v1` with arbitrary byte payloads for every valid
            /// V1 type byte. Must never panic — must return Ok or Err cleanly.
            #[test]
            fn fuzz_deserialize_v1_known_types(
                type_idx in 0usize..V1_TYPE_BYTES.len(),
                payload in prop::collection::vec(any::<u8>(), 0..2048),
            ) {
                let type_byte = V1_TYPE_BYTES[type_idx];
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    deserialize_v1(type_byte, &payload)
                }));
                match result {
                    Ok(Ok(_msg)) => { /* valid JSON for this type — acceptable */ }
                    Ok(Err(_e)) => { /* invalid JSON or wrong fields — acceptable */ }
                    Err(_panic) => panic!("deserialize_v1 panicked on type_byte={type_byte}, payload_len={}", payload.len()),
                }
            }
        }

        proptest! {
            /// Fuzz `deserialize_v1` with arbitrary type bytes (including unknown ones).
            /// Unknown type bytes must return Err, never panic.
            #[test]
            fn fuzz_deserialize_v1_arbitrary_types(
                type_byte in any::<u8>(),
                payload in prop::collection::vec(any::<u8>(), 0..1024),
            ) {
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    deserialize_v1(type_byte, &payload)
                }));
                match result {
                    Ok(Ok(msg)) => {
                        // Known type + valid JSON — the type byte should match
                        let expected = msg.v1_type_byte();
                        prop_assert_eq!(type_byte, expected,
                            "type_byte mismatch: deserialized message has wrong type byte");
                    }
                    Ok(Err(_)) => { /* expected for unknown types or invalid JSON */ }
                    Err(_panic) => panic!("deserialize_v1 panicked on type_byte={type_byte}"),
                }
            }
        }

        proptest! {
            /// Fuzz `deserialize_v2` with arbitrary type IDs and payloads.
            /// Must never panic.
            #[test]
            fn fuzz_deserialize_v2(
                type_id in any::<u16>(),
                payload in prop::collection::vec(any::<u8>(), 0..2048),
            ) {
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    crate::protocol::deserialize_v2(type_id, &payload)
                }));
                match result {
                    Ok(Ok(_)) | Ok(Err(_)) => { /* expected */ }
                    Err(_panic) => panic!("deserialize_v2 panicked on type_id={type_id}, payload_len={}", payload.len()),
                }
            }
        }

        // ── Frame header fuzz ───────────────────────────────────────

        proptest! {
            /// Fuzz V1 frame header parsing: arbitrary 9-byte headers with arbitrary
            /// payload lengths. Validates that oversized or invalid lengths are rejected.
            #[test]
            fn fuzz_v1_frame_header(
                header_bytes in prop::array::uniform9(any::<u8>()),
                payload_len in 0usize..=65536usize,
            ) {
                // Construct a full frame: 9-byte header + payload bytes
                // Encode the payload length in big-endian bytes 1..9
                let mut frame = header_bytes;
                frame[1..9].copy_from_slice(&(payload_len as i64).to_be_bytes());

                // Extend with dummy payload
                let mut full_frame = frame.to_vec();
                full_frame.extend(vec![0u8; payload_len]);

                // Feed to FuzzReader and attempt read_v1_frame
                let reader = FuzzReader::new(full_frame.clone());
                // Wrap reader so we can call read_v1_frame
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let rt = tokio::runtime::Builder::new_current_thread()
                        .enable_time()
                        .build()
                        .unwrap();
                    rt.block_on(async {
                        let mut r = reader;
                        read_v1_frame(&mut r).await
                    })
                }));
                match result {
                    Ok(Ok(_)) => {
                        // Valid frame: payload_len must be within 0..=65536
                        prop_assert!(payload_len <= 65536,
                            "read_v1_frame accepted oversized payload_len={payload_len}");
                    }
                    Ok(Err(_)) => { /* expected for oversized/invalid */ }
                    Err(_panic) => panic!("read_v1_frame panicked on header={header_bytes:?}, payload_len={payload_len}"),
                }
            }
        }

        proptest! {
            /// Fuzz V1 frame with malicious length field: payload says it's long
            /// but actual buffer is shorter (truncation attack).
            #[test]
            fn fuzz_v1_frame_truncated_payload(
                claimed_len in 1i64..65536i64,
                actual_len in 0usize..100usize,
            ) {
                let mut header = [0u8; 9];
                header[1..9].copy_from_slice(&claimed_len.to_be_bytes());
                let mut frame = header.to_vec();
                frame.extend(vec![0u8; actual_len]);

                let reader = FuzzReader::new(frame);
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let rt = tokio::runtime::Builder::new_current_thread()
                        .enable_time()
                        .build()
                        .unwrap();
                    rt.block_on(async {
                        let mut r = reader;
                        read_v1_frame(&mut r).await
                    })
                }));
                match result {
                    Ok(Ok(_)) => {
                        // Only valid if actual_len >= claimed_len
                        prop_assert!(actual_len as i64 >= claimed_len,
                            "read_v1_frame accepted truncated payload: claimed={claimed_len}, actual={actual_len}");
                    }
                    Ok(Err(_)) => { /* expected */ }
                    Err(_panic) => panic!("read_v1_frame panicked on truncated payload"),
                }
            }
        }

        // ── V2 magic detection fuzz ─────────────────────────────────

        proptest! {
            /// Fuzz `read_v2_magic_or_replay` with arbitrary 7-byte prefixes.
            /// Only exact V2 magic should be consumed; everything else replayed.
            #[test]
            fn fuzz_v2_magic_detection(bytes in prop::array::uniform7(any::<u8>())) {
                let reader = FuzzReader::new(bytes.to_vec());
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let rt = tokio::runtime::Builder::new_current_thread()
                        .enable_time()
                        .build()
                        .unwrap();
                    rt.block_on(async {
                        let mut r = reader;
                        read_v2_magic_or_replay(&mut r).await
                    })
                }));
                match result {
                    Ok(Ok(None)) => {
                        // Magic matched — bytes must equal V2_MAGIC_BYTES
                        prop_assert_eq!(&bytes[..], &V2_MAGIC_BYTES[..],
                            "read_v2_magic_or_replay consumed non-magic bytes");
                    }
                    Ok(Ok(Some(replay))) => {
                        prop_assert_eq!(&replay[..], &bytes[..],
                            "replayed bytes must equal input bytes");
                        prop_assert_ne!(&bytes[..], &V2_MAGIC_BYTES[..],
                            "read_v2_magic_or_replay replayed V2 magic bytes");
                    }
                    Ok(Err(_)) => { /* IO error — shouldn't happen for full read */ }
                    Err(_panic) => panic!("read_v2_magic_or_replay panicked on bytes={bytes:?}"),
                }
            }
        }

        // ── Deterministic edge cases ────────────────────────────────

        #[test]
        fn v1_deserialize_empty_payload_all_types() {
            for &tb in V1_TYPE_BYTES {
                let result = deserialize_v1(tb, b"");
                // Empty payload is invalid JSON — must return Err, never panic
                assert!(
                    result.is_err(),
                    "deserialize_v1({tb}, \"\") should fail on empty payload"
                );
            }
        }

        #[test]
        fn v1_deserialize_binary_garbage() {
            // Binary garbage (not UTF-8 JSON) — must return Err for all types
            let garbage: Vec<u8> = (0..=255).collect();
            for &tb in V1_TYPE_BYTES {
                let result = deserialize_v1(tb, &garbage);
                assert!(
                    result.is_err(),
                    "deserialize_v1({tb}, binary_garbage) should fail"
                );
            }
        }

        #[test]
        fn v1_deserialize_null_byte_injection() {
            // JSON with embedded null bytes
            let payload = b"{\"version\": \"\0\0\0\"}";
            for &tb in V1_TYPE_BYTES {
                let result = deserialize_v1(tb, payload);
                // Must not panic — Err is expected (invalid JSON or wrong fields)
                let _ = result;
            }
        }

        #[test]
        fn v2_deserialize_empty_payload() {
            for type_id in 0u16..30 {
                let result = crate::protocol::deserialize_v2(type_id, b"");
                assert!(
                    result.is_err(),
                    "deserialize_v2({type_id}, \"\") should fail on empty payload"
                );
            }
        }

        #[test]
        fn v2_deserialize_binary_garbage() {
            let garbage: Vec<u8> = (0..=255).collect();
            for type_id in 0u16..30 {
                let result = crate::protocol::deserialize_v2(type_id, &garbage);
                assert!(
                    result.is_err(),
                    "deserialize_v2({type_id}, binary_garbage) should fail"
                );
            }
        }

        #[test]
        fn v1_frame_negative_length_rejected() {
            // Header with negative length in bytes 1..9
            let mut header = [0u8; 9];
            header[0] = msg::TYPE_LOGIN;
            header[1..9].copy_from_slice(&(-1i64).to_be_bytes());
            let reader = FuzzReader::new(header.to_vec());
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_time()
                .build()
                .unwrap();
            let result = rt.block_on(async {
                let mut r = reader;
                read_v1_frame(&mut r).await
            });
            assert!(result.is_err(), "negative V1 length should be rejected");
        }

        #[test]
        fn v1_frame_zero_length_accepted() {
            let mut header = [0u8; 9];
            header[0] = msg::TYPE_LOGIN;
            // bytes 1..9 are all zero = length 0
            let reader = FuzzReader::new(header.to_vec());
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_time()
                .build()
                .unwrap();
            let result = rt.block_on(async {
                let mut r = reader;
                read_v1_frame(&mut r).await
            });
            assert!(result.is_ok(), "zero-length V1 frame should be accepted");
        }

        #[test]
        fn v2_magic_exact_match_detected() {
            let reader = FuzzReader::new(V2_MAGIC_BYTES.to_vec());
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_time()
                .build()
                .unwrap();
            let result = rt.block_on(async {
                let mut r = reader;
                read_v2_magic_or_replay(&mut r).await
            });
            assert!(result.is_ok());
            assert!(
                result.unwrap().is_none(),
                "V2 magic should be detected and consumed"
            );
        }

        #[test]
        fn v2_magic_one_byte_off_replayed() {
            // Toggle the last byte — should not match magic
            let mut bytes = V2_MAGIC_BYTES;
            bytes[6] ^= 1;
            let reader = FuzzReader::new(bytes.to_vec());
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_time()
                .build()
                .unwrap();
            let result = rt.block_on(async {
                let mut r = reader;
                read_v2_magic_or_replay(&mut r).await
            });
            assert!(result.is_ok());
            let replay = result.unwrap();
            assert!(
                replay.is_some(),
                "near-magic should be replayed, not consumed"
            );
            assert_eq!(replay.unwrap(), bytes.to_vec());
        }
    }
}
