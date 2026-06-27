use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::msg::{self, FrpMessage};

pub const V1_MAX_MSG_LENGTH: i64 = 64 * 1024;
pub const V1_HEADER_LEN: usize = 9;

pub async fn write_v1_frame<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    msg: &FrpMessage,
) -> Result<(), crate::Error> {
    let type_byte = msg.v1_type_byte();
    let payload = serde_json::to_vec(msg)
        .map_err(|e| crate::Error::Protocol(format!("serialize V1 msg: {e}")))?;

    if payload.len() as i64 > V1_MAX_MSG_LENGTH {
        return Err(crate::Error::Protocol("V1 message too large".into()));
    }

    let mut buf = Vec::with_capacity(V1_HEADER_LEN + payload.len());
    buf.push(type_byte);
   buf.extend_from_slice(&(payload.len() as i64).to_be_bytes());
   buf.extend_from_slice(&payload);

    tracing::trace!(
        "V1 frame: type=0x{:02x} len={} payload={}",
        type_byte,
        payload.len(),
        String::from_utf8_lossy(&payload)
    );

   writer
       .write_all(&buf)
       .await
        .map_err(|e| crate::Error::Protocol(format!("write V1 frame: {e}")))?;
    Ok(())
}

pub async fn read_v1_frame<R: AsyncReadExt + Unpin>(
    reader: &mut R,
) -> Result<(u8, Vec<u8>), crate::Error> {
    let mut header = [0u8; V1_HEADER_LEN];
    reader
        .read_exact(&mut header)
        .await
        .map_err(|e| crate::Error::Protocol(format!("read V1 header: {e}")))?;

    let type_byte = header[0];
    let length = i64::from_be_bytes([
        header[1], header[2], header[3], header[4],
        header[5], header[6], header[7], header[8],
    ]);

    tracing::debug!("V1 header: type={:#04x} len={} raw={}", type_byte, length, hex::encode(header));

    if !(0..=V1_MAX_MSG_LENGTH).contains(&length) {
        return Err(crate::Error::Protocol(format!("invalid V1 msg length: {length}")));
    }

    let mut payload = vec![0u8; length as usize];
    reader
        .read_exact(&mut payload)
        .await
        .map_err(|e| crate::Error::Protocol(format!("read V1 payload: {e}")))?;

    Ok((type_byte, payload))
}

pub async fn read_msg_v1<R: AsyncReadExt + Unpin>(
    reader: &mut R,
) -> Result<FrpMessage, crate::Error> {
    let (type_byte, payload) = read_v1_frame(reader).await?;
    deserialize_v1(type_byte, &payload)
}

pub async fn write_msg_v1<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    msg: &FrpMessage,
) -> Result<(), crate::Error> {
    write_v1_frame(writer, msg).await
}

/// Deserialize a V2 message from its type ID and JSON payload bytes.
/// V2 uses numeric type IDs (u16) instead of V1's ASCII type bytes.
pub fn deserialize_v2(type_id: u16, json_bytes: &[u8]) -> Result<FrpMessage, crate::Error> {
    let msg = match type_id {
        msg::V2_TYPE_LOGIN => {
            let v: msg::Login = serde_json::from_slice(json_bytes)
                .map_err(|e| crate::Error::Protocol(format!("deserialize Login (v2): {e}")))?;
            FrpMessage::Login(v)
        }
        msg::V2_TYPE_LOGIN_RESP => {
            let v: msg::LoginResp = serde_json::from_slice(json_bytes)
                .map_err(|e| crate::Error::Protocol(format!("deserialize LoginResp (v2): {e}")))?;
            FrpMessage::LoginResp(v)
        }
        msg::V2_TYPE_NEW_PROXY => {
            let v: msg::NewProxy = serde_json::from_slice(json_bytes)
                .map_err(|e| crate::Error::Protocol(format!("deserialize NewProxy (v2): {e}")))?;
            FrpMessage::NewProxy(v)
        }
        msg::V2_TYPE_NEW_PROXY_RESP => {
            let v: msg::NewProxyResp = serde_json::from_slice(json_bytes)
                .map_err(|e| crate::Error::Protocol(format!("deserialize NewProxyResp (v2): {e}")))?;
            FrpMessage::NewProxyResp(v)
        }
        msg::V2_TYPE_CLOSE_PROXY => {
            let v: msg::CloseProxy = serde_json::from_slice(json_bytes)
                .map_err(|e| crate::Error::Protocol(format!("deserialize CloseProxy (v2): {e}")))?;
            FrpMessage::CloseProxy(v)
        }
        msg::V2_TYPE_NEW_WORK_CONN => {
            let v: msg::NewWorkConn = serde_json::from_slice(json_bytes)
                .map_err(|e| crate::Error::Protocol(format!("deserialize NewWorkConn (v2): {e}")))?;
            FrpMessage::NewWorkConn(v)
        }
        msg::V2_TYPE_REQ_WORK_CONN => {
            let v: msg::ReqWorkConn = serde_json::from_slice(json_bytes)
                .map_err(|e| crate::Error::Protocol(format!("deserialize ReqWorkConn (v2): {e}")))?;
            FrpMessage::ReqWorkConn(v)
        }
        msg::V2_TYPE_START_WORK_CONN => {
            let v: msg::StartWorkConn = serde_json::from_slice(json_bytes)
                .map_err(|e| crate::Error::Protocol(format!("deserialize StartWorkConn (v2): {e}")))?;
            FrpMessage::StartWorkConn(v)
        }
        msg::V2_TYPE_NEW_VISITOR_CONN => {
            let v: msg::NewVisitorConn = serde_json::from_slice(json_bytes)
                .map_err(|e| crate::Error::Protocol(format!("deserialize NewVisitorConn (v2): {e}")))?;
            FrpMessage::NewVisitorConn(v)
        }
        msg::V2_TYPE_NEW_VISITOR_CONN_RESP => {
            let v: msg::NewVisitorConnResp = serde_json::from_slice(json_bytes)
                .map_err(|e| crate::Error::Protocol(format!("deserialize NewVisitorConnResp (v2): {e}")))?;
            FrpMessage::NewVisitorConnResp(v)
        }
        msg::V2_TYPE_PING => {
            let v: msg::Ping = serde_json::from_slice(json_bytes)
                .map_err(|e| crate::Error::Protocol(format!("deserialize Ping (v2): {e}")))?;
            FrpMessage::Ping(v)
        }
        msg::V2_TYPE_PONG => {
            let v: msg::Pong = serde_json::from_slice(json_bytes)
                .map_err(|e| crate::Error::Protocol(format!("deserialize Pong (v2): {e}")))?;
            FrpMessage::Pong(v)
        }
        msg::V2_TYPE_UDP_PACKET => {
            let v: msg::UDPPacket = serde_json::from_slice(json_bytes)
                .map_err(|e| crate::Error::Protocol(format!("deserialize UDPPacket (v2): {e}")))?;
            FrpMessage::UDPPacket(v)
        }
        msg::V2_TYPE_NAT_HOLE_VISITOR => {
            let v: msg::NatHoleVisitor = serde_json::from_slice(json_bytes)
                .map_err(|e| crate::Error::Protocol(format!("deserialize NatHoleVisitor (v2): {e}")))?;
            FrpMessage::NatHoleVisitor(v)
        }
        msg::V2_TYPE_NAT_HOLE_CLIENT => {
            let v: msg::NatHoleClient = serde_json::from_slice(json_bytes)
                .map_err(|e| crate::Error::Protocol(format!("deserialize NatHoleClient (v2): {e}")))?;
            FrpMessage::NatHoleClient(v)
        }
        msg::V2_TYPE_NAT_HOLE_RESP => {
            let v: msg::NatHoleResp = serde_json::from_slice(json_bytes)
                .map_err(|e| crate::Error::Protocol(format!("deserialize NatHoleResp (v2): {e}")))?;
            FrpMessage::NatHoleResp(v)
        }
        msg::V2_TYPE_NAT_HOLE_SID => {
            let v: msg::NatHoleSid = serde_json::from_slice(json_bytes)
                .map_err(|e| crate::Error::Protocol(format!("deserialize NatHoleSid (v2): {e}")))?;
            FrpMessage::NatHoleSid(v)
        }
        msg::V2_TYPE_NAT_HOLE_REPORT => {
            let v: msg::NatHoleReport = serde_json::from_slice(json_bytes)
                .map_err(|e| crate::Error::Protocol(format!("deserialize NatHoleReport (v2): {e}")))?;
            FrpMessage::NatHoleReport(v)
        }
        _ => return Err(crate::Error::Protocol(format!(
            "unknown V2 message type ID: {type_id}"
        ))),
    };
    Ok(msg)
}

fn deserialize_v1(type_byte: u8, payload: &[u8]) -> Result<FrpMessage, crate::Error> {
    let msg = match type_byte {
        msg::TYPE_LOGIN => {
            let v: msg::Login = serde_json::from_slice(payload)
                .map_err(|e| crate::Error::Protocol(format!("deserialize Login: {e}")))?;
            FrpMessage::Login(v)
        }
        msg::TYPE_LOGIN_RESP => {
            let v: msg::LoginResp = serde_json::from_slice(payload)
                .map_err(|e| crate::Error::Protocol(format!("deserialize LoginResp: {e}")))?;
            FrpMessage::LoginResp(v)
        }
        msg::TYPE_NEW_PROXY => {
            let v: msg::NewProxy = serde_json::from_slice(payload)
                .map_err(|e| crate::Error::Protocol(format!("deserialize NewProxy: {e}")))?;
            FrpMessage::NewProxy(v)
        }
        msg::TYPE_NEW_PROXY_RESP => {
            let v: msg::NewProxyResp = serde_json::from_slice(payload)
                .map_err(|e| crate::Error::Protocol(format!("deserialize NewProxyResp: {e}")))?;
            FrpMessage::NewProxyResp(v)
        }
        msg::TYPE_CLOSE_PROXY => {
            let v: msg::CloseProxy = serde_json::from_slice(payload)
                .map_err(|e| crate::Error::Protocol(format!("deserialize CloseProxy: {e}")))?;
            FrpMessage::CloseProxy(v)
        }
        msg::TYPE_CLOSE_PROXY_RESP => {
            let v: msg::CloseProxyResp = serde_json::from_slice(payload)
                .map_err(|e| crate::Error::Protocol(format!("deserialize CloseProxyResp: {e}")))?;
            FrpMessage::CloseProxyResp(v)
        }
        msg::TYPE_ERROR => {
            let v: msg::Error = serde_json::from_slice(payload)
                .map_err(|e| crate::Error::Protocol(format!("deserialize Error: {e}")))?;
            FrpMessage::Error(v)
        }
        msg::TYPE_NEW_WORK_CONN => {
            let v: msg::NewWorkConn = serde_json::from_slice(payload)
                .map_err(|e| crate::Error::Protocol(format!("deserialize NewWorkConn: {e}")))?;
            FrpMessage::NewWorkConn(v)
        }
        msg::TYPE_REQ_WORK_CONN => {
            let v: msg::ReqWorkConn = serde_json::from_slice(payload)
                .map_err(|e| crate::Error::Protocol(format!("deserialize ReqWorkConn: {e}")))?;
            FrpMessage::ReqWorkConn(v)
        }
        msg::TYPE_START_WORK_CONN => {
            let v: msg::StartWorkConn = serde_json::from_slice(payload)
                .map_err(|e| crate::Error::Protocol(format!("deserialize StartWorkConn: {e}")))?;
            FrpMessage::StartWorkConn(v)
        }
        msg::TYPE_PING => {
            let v: msg::Ping = serde_json::from_slice(payload)
                .map_err(|e| crate::Error::Protocol(format!("deserialize Ping: {e}")))?;
            FrpMessage::Ping(v)
        }
        msg::TYPE_PONG => {
            let v: msg::Pong = serde_json::from_slice(payload)
                .map_err(|e| crate::Error::Protocol(format!("deserialize Pong: {e}")))?;
            FrpMessage::Pong(v)
        }
        msg::TYPE_NEW_VISITOR_CONN => {
            let v: msg::NewVisitorConn = serde_json::from_slice(payload)
                .map_err(|e| crate::Error::Protocol(format!("deserialize NewVisitorConn: {e}")))?;
            FrpMessage::NewVisitorConn(v)
        }
        msg::TYPE_NEW_VISITOR_CONN_RESP => {
            let v: msg::NewVisitorConnResp = serde_json::from_slice(payload)
                .map_err(|e| crate::Error::Protocol(format!("deserialize NewVisitorConnResp: {e}")))?;
            FrpMessage::NewVisitorConnResp(v)
        }
        msg::TYPE_UDP_PACKET => {
            let v: msg::UDPPacket = serde_json::from_slice(payload)
                .map_err(|e| crate::Error::Protocol(format!("deserialize UDPPacket: {e}")))?;
            FrpMessage::UDPPacket(v)
        }
        msg::TYPE_NAT_HOLE_VISITOR => {
            tracing::debug!("NatHoleVisitor raw payload: {}", String::from_utf8_lossy(payload));
            let v: msg::NatHoleVisitor = serde_json::from_slice(payload)
                .map_err(|e| crate::Error::Protocol(format!("deserialize NatHoleVisitor: {e}")))?;
            tracing::debug!("NatHoleVisitor deserialized: transaction_id={:?}, proxy_name={}, pre_check={}",
                v.transaction_id, v.proxy_name, v.pre_check);
            FrpMessage::NatHoleVisitor(v)
        }
        msg::TYPE_NAT_HOLE_CLIENT => {
            let v: msg::NatHoleClient = serde_json::from_slice(payload)
                .map_err(|e| crate::Error::Protocol(format!("deserialize NatHoleClient: {e}")))?;
            FrpMessage::NatHoleClient(v)
        }
        msg::TYPE_NAT_HOLE_RESP => {
            let v: msg::NatHoleResp = serde_json::from_slice(payload)
                .map_err(|e| crate::Error::Protocol(format!("deserialize NatHoleResp: {e}")))?;
            FrpMessage::NatHoleResp(v)
        }
        msg::TYPE_NAT_HOLE_SID => {
            let v: msg::NatHoleSid = serde_json::from_slice(payload)
                .map_err(|e| crate::Error::Protocol(format!("deserialize NatHoleSid: {e}")))?;
            FrpMessage::NatHoleSid(v)
        }
        msg::TYPE_NAT_HOLE_REPORT => {
            let v: msg::NatHoleReport = serde_json::from_slice(payload)
                .map_err(|e| crate::Error::Protocol(format!("deserialize NatHoleReport: {e}")))?;
            FrpMessage::NatHoleReport(v)
        }
        _ => return Err(crate::Error::Protocol(format!("unknown V1 type byte: 0x{type_byte:02x}"))),
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

pub async fn detect_v2_magic<R: AsyncReadExt + Unpin>(
    reader: &mut R,
) -> Result<bool, crate::Error> {
    let mut buf = [0u8; V2_MAGIC_LEN];
    match reader.read_exact(&mut buf).await {
        Ok(_) => Ok(buf == V2_MAGIC_BYTES),
        Err(e) => Err(crate::Error::Protocol(format!("detect V2 magic: {e}"))),
    }
}

pub async fn write_v2_magic<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
) -> Result<(), crate::Error> {
    writer
        .write_all(&V2_MAGIC_BYTES)
        .await
        .map_err(|e| crate::Error::Protocol(format!("write V2 magic: {e}")))?;
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
        return Err(crate::Error::Protocol(format!(
            "V2 payload too large: {} > {}",
            payload.len(),
            V2_MAX_FRAME_PAYLOAD
        )));
    }
    let mut header = [0u8; V2_FRAME_HEADER_LEN];
    header[0..2].copy_from_slice(&frame_type.to_be_bytes());
    header[2..4].copy_from_slice(&flags.to_be_bytes());
    header[4..8].copy_from_slice(&(payload.len() as u32).to_be_bytes());

    tracing::trace!("write V2 frame: type={}, flags={}, len={}", frame_type, flags, payload.len());

    let mut out = Vec::with_capacity(V2_FRAME_HEADER_LEN + payload.len());
    out.extend_from_slice(&header);
    out.extend_from_slice(payload);
    writer.write_all(&out).await
        .map_err(|e| crate::Error::Protocol(format!("write V2 frame: {e}")))?;
    Ok(())
}

/// Read a raw V2 frame. Returns (frame_type, flags, payload).
/// This is the Go wire.Conn.ReadFrame format.
pub async fn read_v2_frame_raw<R: AsyncReadExt + Unpin>(
    reader: &mut R,
) -> Result<(u16, u16, Vec<u8>), crate::Error> {
    let mut header = [0u8; V2_FRAME_HEADER_LEN];
    reader.read_exact(&mut header).await
        .map_err(|e| crate::Error::Protocol(format!("read V2 frame: {e}")))?;

    let frame_type = u16::from_be_bytes([header[0], header[1]]);
    let flags = u16::from_be_bytes([header[2], header[3]]);
    let payload_len = u32::from_be_bytes([header[4], header[5], header[6], header[7]]) as usize;

    tracing::debug!("read V2 frame: type={}, flags={}, len={}", frame_type, flags, payload_len);

    if flags != 0 {
        return Err(crate::Error::Protocol(format!(
            "unsupported V2 frame flags: {flags}"
        )));
    }
    if payload_len > V2_MAX_FRAME_PAYLOAD as usize {
        return Err(crate::Error::Protocol(format!(
            "V2 frame payload too large: {payload_len}"
        )));
    }

    let mut payload = vec![0u8; payload_len];
    reader.read_exact(&mut payload).await
        .map_err(|e| crate::Error::Protocol(format!("read V2 payload: {e}")))?;

    Ok((frame_type, flags, payload))
}

/// Write a FrpMessage using Go-compatible V2 framing.
/// Frame: type=16(Message) flags=0, payload = type_id(2 BE) + JSON.
pub async fn write_msg_v2<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    msg: &FrpMessage,
) -> Result<(), crate::Error> {
    let type_id = msg.v2_type_id();
    let json_bytes = serde_json::to_vec(msg)
        .map_err(|e| crate::Error::Protocol(format!("V2 JSON serialize: {e}")))?;

    let mut payload = Vec::with_capacity(2 + json_bytes.len());
    payload.extend_from_slice(&type_id.to_be_bytes());
    payload.extend_from_slice(&json_bytes);

    write_v2_frame_raw(writer, V2_FRAME_TYPE_MESSAGE, 0, &payload).await
}

/// Read a FrpMessage using Go-compatible V2 framing.
/// Expects frame type=16, extracts 2-byte type ID from payload prefix.
pub async fn read_msg_v2<R: AsyncReadExt + Unpin>(
    reader: &mut R,
) -> Result<FrpMessage, crate::Error> {
    let (frame_type, _flags, payload) = read_v2_frame_raw(reader).await?;
    if frame_type != V2_FRAME_TYPE_MESSAGE {
        return Err(crate::Error::Protocol(format!(
            "unexpected V2 frame type: {frame_type}, expected {} (Message)",
            V2_FRAME_TYPE_MESSAGE
        )));
    }
    if payload.len() < 2 {
        return Err(crate::Error::Protocol("V2 message payload too short".into()));
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
        let msg = FrpMessage::Login(msg::Login {
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
        });
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
        client.write_all(&[msg::TYPE_PING, 0x00, 0x00]).await.expect("write partial");
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
        client.write_all(&vec![0u8; 50]).await.expect("write partial payload");
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
        write_v2_frame_raw(&mut client, 16, 0, payload).await.expect("write V2 frame");
        let (ft, flags, data) = read_v2_frame_raw(&mut server).await.expect("read V2 frame");
        assert_eq!(ft, 16);
        assert_eq!(flags, 0);
        assert_eq!(data, payload);
    }

    #[tokio::test]
    async fn test_v2_msg_roundtrip() {
        let (mut client, mut server) = duplex(65536);
        let msg = FrpMessage::Login(msg::Login {
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
        });
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
            FrpMessage::Ping(msg::Ping { privilege_key: None, timestamp: Some(42) }),
            FrpMessage::Pong(msg::Pong { error: None }),
            FrpMessage::CloseProxy(msg::CloseProxy { proxy_name: "test".into() }),
            FrpMessage::ReqWorkConn(msg::ReqWorkConn {}),
            // Note: CloseProxyResp and Error are V1-only (v2_type_id() == 0),
            // so they are excluded from this V2 roundtrip test.
        ];

        for msg in &messages {
            write_msg_v2(&mut client, msg).await.expect("write V2");
            let back = read_msg_v2(&mut server).await.expect("read V2");
            assert_eq!(back.v2_type_id(), msg.v2_type_id(),
                "roundtrip type mismatch for {:?}", msg.v2_type_id());
        }
    }

    #[tokio::test]
    async fn test_v2_msg_rejects_non_message_frame_type() {
        // Go-compatible V2: read_msg_v2 expects frame_type == 16 (Message).
        // Write a frame with frame_type=1 (ClientHello) — should be rejected.
        let (mut client, mut server) = duplex(256);
        write_v2_frame_raw(&mut client, 1, 0, b"hello").await.expect("write frame");
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
}
