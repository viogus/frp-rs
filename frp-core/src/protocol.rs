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

    if length < 0 || length > V1_MAX_MSG_LENGTH {
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
            let v: msg::NatHoleVisitor = serde_json::from_slice(payload)
                .map_err(|e| crate::Error::Protocol(format!("deserialize NatHoleVisitor: {e}")))?;
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
            local_addr: "0.0.0.0:0".into(),
            remote_addr: "0.0.0.0:0".into(),
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
}
