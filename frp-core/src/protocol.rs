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
        msg::TYPE_UDP_PACKET => {
            let v: msg::UDPPacket = serde_json::from_slice(payload)
                .map_err(|e| crate::Error::Protocol(format!("deserialize UDPPacket: {e}")))?;
            FrpMessage::UDPPacket(v)
        }
        _ => return Err(crate::Error::Protocol(format!("unknown V1 type: {type_byte}"))),
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
