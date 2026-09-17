# V2 Protocol Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Rewrite V2 wire protocol (frame format, type IDs, handshake) to match Go frp v0.69.1.

**Architecture:** Replace 13-byte-per-frame-magic format with Go frp's 8-byte header + 2-byte type ID prefix in payload. Add ClientHello/ServerHello handshake stubs. Protocol layer (protocol.rs) owns framing primitives; v2_handshake.rs owns hello exchange on IoStream; transport.rs owns connection detection, dial, and IoStream dispatch. V1 path untouched.

**Tech Stack:** Rust, tokio, serde_json. No new dependencies.

**Design Doc:** `docs/superpowers/specs/2026-06-28-v2-protocol-design.md`

---

## File Map

| File | What changes |
|------|-------------|
| `frp-core/src/msg.rs` | Fix V2 type ID consts (9→9, 10→10, add NAT hole 14-18), fix `v2_type_id()` |
| `frp-core/src/protocol.rs` | Add `write_v2_frame_raw`, `read_v2_frame_raw`, `deserialize_v2`, new `write_msg_v2`/`read_msg_v2`; delete old 13-byte-header functions |
| `frp-core/src/v2_handshake.rs` (**new**) | ClientHello/ServerHello structs, `v2_handshake_client`, `v2_handshake_server` (both take `&mut IoStream`) |
| `frp-core/src/lib.rs` | Register `pub mod v2_handshake;` |
| `frp-core/src/transport.rs` | Add `v2` to `DialOptions`; write magic in `dial_server`; add `IoStream::write_raw_v2_frame`/`read_raw_v2_frame`; replace `peek_connection_type` with `detect_and_strip_magic`; rewrite `IoStream::write_v2_frame`/`read_v2_frame` |
| `frp-core/src/config.rs` | `transport.wireProtocol` → top-level `v2` alias (Go compat) |
| `frp-client/src/control.rs` | Call `v2_handshake_client` in `login()` before yamux wrapping |
| `frp-server/src/service.rs` | Use `detect_and_strip_magic`; rewrite V2 accept branch with handshake + new frame dispatch |
| `frp-server/src/control/mod.rs` | Update `read_ctl_msg`/`write_ctl_msg` to call new `read_msg_v2`/`write_msg_v2` |
| `frp-server/src/control/bridge.rs` | Update StartWorkConn + UDP bridge V2 calls |

---

### Task 1: Fix V2 Type ID Constants and `v2_type_id()`

**File:** `frp-core/src/msg.rs`
**Deps:** None. Self-contained, compiles independently.

- [ ] **Step 1: Replace V2 type ID constants (lines 29-44)**

Replace the V2 constants block with Go frp-aligned values. New visitor conn = 9 (was 14), new visitor conn resp = 10 (was 15). NAT hole types added.

```rust
// ---------------------------------------------------------------
// V2 message type IDs (matching Go frp v0.69.1 wire_v2.go)
// ---------------------------------------------------------------
pub const V2_TYPE_LOGIN: u16 = 1;
pub const V2_TYPE_LOGIN_RESP: u16 = 2;
pub const V2_TYPE_NEW_PROXY: u16 = 3;
pub const V2_TYPE_NEW_PROXY_RESP: u16 = 4;
pub const V2_TYPE_CLOSE_PROXY: u16 = 5;
pub const V2_TYPE_NEW_WORK_CONN: u16 = 6;
pub const V2_TYPE_REQ_WORK_CONN: u16 = 7;
pub const V2_TYPE_START_WORK_CONN: u16 = 8;
pub const V2_TYPE_NEW_VISITOR_CONN: u16 = 9;
pub const V2_TYPE_NEW_VISITOR_CONN_RESP: u16 = 10;
pub const V2_TYPE_PING: u16 = 11;
pub const V2_TYPE_PONG: u16 = 12;
pub const V2_TYPE_UDP_PACKET: u16 = 13;
pub const V2_TYPE_NAT_HOLE_VISITOR: u16 = 14;
pub const V2_TYPE_NAT_HOLE_CLIENT: u16 = 15;
pub const V2_TYPE_NAT_HOLE_RESP: u16 = 16;
pub const V2_TYPE_NAT_HOLE_SID: u16 = 17;
pub const V2_TYPE_NAT_HOLE_REPORT: u16 = 18;
```

- [ ] **Step 2: Fix `v2_type_id()` (lines 480-496)**

Replace the match body to cover all 18 types:

```rust
pub fn v2_type_id(&self) -> u16 {
    match self {
        FrpMessage::Login(_)              => V2_TYPE_LOGIN,
        FrpMessage::LoginResp(_)          => V2_TYPE_LOGIN_RESP,
        FrpMessage::NewProxy(_)           => V2_TYPE_NEW_PROXY,
        FrpMessage::NewProxyResp(_)       => V2_TYPE_NEW_PROXY_RESP,
        FrpMessage::CloseProxy(_)         => V2_TYPE_CLOSE_PROXY,
        FrpMessage::NewWorkConn(_)        => V2_TYPE_NEW_WORK_CONN,
        FrpMessage::ReqWorkConn(_)        => V2_TYPE_REQ_WORK_CONN,
        FrpMessage::StartWorkConn(_)      => V2_TYPE_START_WORK_CONN,
        FrpMessage::Ping(_)               => V2_TYPE_PING,
        FrpMessage::Pong(_)               => V2_TYPE_PONG,
        FrpMessage::UDPPacket(_)          => V2_TYPE_UDP_PACKET,
        FrpMessage::NewVisitorConn(_)     => V2_TYPE_NEW_VISITOR_CONN,
        FrpMessage::NewVisitorConnResp(_) => V2_TYPE_NEW_VISITOR_CONN_RESP,
        FrpMessage::NatHoleVisitor(_)     => V2_TYPE_NAT_HOLE_VISITOR,
        FrpMessage::NatHoleClient(_)      => V2_TYPE_NAT_HOLE_CLIENT,
        FrpMessage::NatHoleResp(_)        => V2_TYPE_NAT_HOLE_RESP,
        FrpMessage::NatHoleSid(_)         => V2_TYPE_NAT_HOLE_SID,
        FrpMessage::NatHoleReport(_)      => V2_TYPE_NAT_HOLE_REPORT,
        // CloseProxyResp and Error are V1-only types, no V2 equivalent
        _ => 0,
    }
}
```

- [ ] **Step 3: Build to verify**

```bash
cargo build -p frp-core
```
Expected: compiles clean.

- [ ] **Step 4: Commit**

```bash
git add frp-core/src/msg.rs
git commit -m "fix: align V2 type ID constants with Go frp v0.69.1

Change V2_TYPE_NEW_VISITOR_CONN 14->9, V2_TYPE_NEW_VISITOR_CONN_RESP 15->10.
Add NAT hole V2 types (14-18). Fix v2_type_id() to cover all 18 types.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 2: Add New V2 Frame Functions to protocol.rs

**File:** `frp-core/src/protocol.rs`
**Deps:** Task 1 (uses corrected V2_TYPE_* constants).

This task ADDS new functions alongside old ones. Old functions deleted in Task 4 after callers migrate.

- [ ] **Step 1: Add `V2_FRAME_HEADER_LEN` and frame type constants**

After the existing V2 constants (line ~196), ADD:

```rust
/// V2 frame header size (Go wire.Conn format): type(2) + flags(2) + length(4) = 8 bytes.
/// Does NOT include magic bytes — magic is only at connection start.
pub const V2_FRAME_HEADER_LEN: usize = 8;

/// V2 frame type constants (matching Go frp pkg/proto/wire/wire.go).
pub const V2_FRAME_TYPE_CLIENT_HELLO: u16 = 1;
pub const V2_FRAME_TYPE_SERVER_HELLO: u16 = 2;
// V2_FRAME_TYPE_MESSAGE = 16 already exists above.
```

- [ ] **Step 2: Add `write_v2_frame_raw` function**

After the existing `write_v2_magic` function (~line 216):

```rust
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

    writer.write_all(&header).await
        .map_err(|e| crate::Error::Protocol(format!("write V2 frame: {e}")))?;
    writer.write_all(payload).await
        .map_err(|e| crate::Error::Protocol(format!("write V2 payload: {e}")))?;
    Ok(())
}
```

- [ ] **Step 3: Add `read_v2_frame_raw` function**

After `write_v2_frame_raw`:

```rust
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
```

- [ ] **Step 4: Add `deserialize_v2` function**

Before the `deserialize_v1` function (~line 83), ADD:

```rust
/// Deserialize a V2 message from its type ID and JSON payload bytes.
/// V2 uses numeric type IDs (u16) instead of V1's ASCII type bytes.
pub fn deserialize_v2(type_id: u16, json_bytes: &[u8]) -> Result<FrpMessage, crate::Error> {
    use crate::msg;
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
```

- [ ] **Step 5: Add new `write_msg_v2` and `read_msg_v2` (alongside old ones, use different names temporarily)**

After existing V2 functions, add (use `_go` suffix temporarily):

```rust
/// Write a FrpMessage using Go-compatible V2 framing.
/// Frame: type=16(Message) flags=0, payload = type_id(2 BE) + JSON.
pub async fn write_msg_v2_go<W: AsyncWriteExt + Unpin>(
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
pub async fn read_msg_v2_go<R: AsyncReadExt + Unpin>(
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
```

- [ ] **Step 6: Build to verify**

```bash
cargo build -p frp-core
```
Expected: compiles with warnings about `write_msg_v2_go` and `read_msg_v2_go` being unused. No errors.

- [ ] **Step 7: Commit**

```bash
git add frp-core/src/protocol.rs
git commit -m "feat: add Go-compatible V2 frame functions to protocol.rs

Add write_v2_frame_raw/read_v2_frame_raw (8-byte header, Go wire.Conn format).
Add deserialize_v2 for all 18 V2 message type IDs.
Add write_msg_v2_go/read_msg_v2_go (type_id prefix in payload).
Old V2 functions preserved — caller migration follows.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 3: Create v2_handshake.rs + IoStream Raw Frame Methods

**Files:**
- Create: `frp-core/src/v2_handshake.rs`
- Modify: `frp-core/src/lib.rs`
- Modify: `frp-core/src/transport.rs` (add raw frame methods to IoStream)
**Deps:** Task 2 (uses `write_v2_frame_raw`, `read_v2_frame_raw`, V2_FRAME_TYPE_*).

- [ ] **Step 1: Add `write_raw_v2_frame` and `read_raw_v2_frame` methods to IoStream**

In `frp-core/src/transport.rs`, add two new methods to `impl IoStream`. Place them after the existing `read_v2_frame` method (~line 643):

```rust
    /// Write a raw V2 frame (for handshake frames like ClientHello/ServerHello).
    /// Lower-level than write_v2_frame — caller controls frame_type and raw payload bytes.
    pub async fn write_raw_v2_frame(&mut self, frame_type: u16, flags: u16, payload: &[u8]) -> Result<(), crate::Error> {
        match self {
            IoStream::Tcp(s) => crate::protocol::write_v2_frame_raw(s, frame_type, flags, payload).await,
            IoStream::Tls(s) => crate::protocol::write_v2_frame_raw(s, frame_type, flags, payload).await,
            IoStream::Kcp(s) => crate::protocol::write_v2_frame_raw(s, frame_type, flags, payload).await,
            IoStream::Quic(s) => crate::protocol::write_v2_frame_raw(s, frame_type, flags, payload).await,
            IoStream::WebSocket(s) => crate::protocol::write_v2_frame_raw(s, frame_type, flags, payload).await,
            IoStream::Yamux(s) => crate::protocol::write_v2_frame_raw(s, frame_type, flags, payload).await,
            IoStream::Cipher(s) => crate::protocol::write_v2_frame_raw(s, frame_type, flags, payload).await,
            IoStream::SshChannel(s) => crate::protocol::write_v2_frame_raw(s, frame_type, flags, payload).await,
        }
    }

    /// Read a raw V2 frame (for handshake). Returns (frame_type, flags, payload_bytes).
    pub async fn read_raw_v2_frame(&mut self) -> Result<(u16, u16, Vec<u8>), crate::Error> {
        match self {
            IoStream::Tcp(s) => crate::protocol::read_v2_frame_raw(s).await,
            IoStream::Tls(s) => crate::protocol::read_v2_frame_raw(s).await,
            IoStream::Kcp(s) => crate::protocol::read_v2_frame_raw(s).await,
            IoStream::Quic(s) => crate::protocol::read_v2_frame_raw(s).await,
            IoStream::WebSocket(s) => crate::protocol::read_v2_frame_raw(s).await,
            IoStream::Yamux(s) => crate::protocol::read_v2_frame_raw(s).await,
            IoStream::Cipher(s) => crate::protocol::read_v2_frame_raw(s).await,
            IoStream::SshChannel(s) => crate::protocol::read_v2_frame_raw(s).await,
        }
    }
```

- [ ] **Step 2: Create `frp-core/src/v2_handshake.rs`**

Full content:

```rust
//! V2 protocol ClientHello / ServerHello handshake.
//!
//! Matching Go frp v0.69.1 pkg/proto/wire/wire.go bootstrap negotiation.
//! Crypto negotiation is deferred — the handshake stubs always select
//! "json" codec with no AEAD crypto.

use serde::{Deserialize, Serialize};

use crate::transport::IoStream;
use crate::protocol::{V2_FRAME_TYPE_CLIENT_HELLO, V2_FRAME_TYPE_SERVER_HELLO, V2_FRAME_TYPE_MESSAGE};

// ---------------------------------------------------------------------------
// Handshake JSON structures (matching Go frp wire.go)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BootstrapInfo {
    pub transport: String,
    pub tls: bool,
    #[serde(rename = "tcpMux")]
    pub tcp_mux: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageCapabilities {
    pub codecs: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptoCapabilities {
    pub algorithms: Vec<String>,
    #[serde(rename = "clientRandom", skip_serializing_if = "Option::is_none")]
    pub client_random: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientCapabilities {
    pub message: MessageCapabilities,
    pub crypto: CryptoCapabilities,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientHello {
    pub bootstrap: BootstrapInfo,
    pub capabilities: ClientCapabilities,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageSelection {
    pub codec: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptoSelection {
    pub algorithm: String,
    #[serde(rename = "serverRandom")]
    pub server_random: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerSelection {
    pub message: MessageSelection,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub crypto: Option<CryptoSelection>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerHello {
    pub selected: ServerSelection,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

// ---------------------------------------------------------------------------
// Constructors
// ---------------------------------------------------------------------------

impl ClientHello {
    pub fn new(transport: &str, tls: bool, tcp_mux: bool) -> Self {
        Self {
            bootstrap: BootstrapInfo {
                transport: transport.to_string(),
                tls,
                tcp_mux,
            },
            capabilities: ClientCapabilities {
                message: MessageCapabilities {
                    codecs: vec!["json".to_string()],
                },
                crypto: CryptoCapabilities {
                    algorithms: vec![],        // crypto negotiation deferred
                    client_random: None,       // deferred
                },
            },
        }
    }
}

impl ServerHello {
    pub fn default_ok() -> Self {
        Self {
            selected: ServerSelection {
                message: MessageSelection {
                    codec: "json".to_string(),
                },
                crypto: None,  // no AEAD crypto selected
            },
            error: None,
        }
    }

    pub fn with_error(err: impl Into<String>) -> Self {
        Self {
            selected: ServerSelection {
                message: MessageSelection {
                    codec: "json".to_string(),
                },
                crypto: None,
            },
            error: Some(err.into()),
        }
    }
}

// ---------------------------------------------------------------------------
// Client-side handshake (operates on IoStream)
// ---------------------------------------------------------------------------

/// Perform V2 client handshake after writing magic bytes.
///
/// 1. Writes ClientHello frame (type=1)
/// 2. Reads ServerHello frame (type=2)
/// 3. Returns Ok(()) if handshake succeeds
///
/// The stream must be positioned after the V2 magic bytes.
/// After this returns, the stream is ready for V2 message frames.
pub async fn v2_handshake_client(
    stream: &mut IoStream,
    transport: &str,
    tls: bool,
    tcp_mux: bool,
) -> Result<(), crate::Error> {
    let hello = ClientHello::new(transport, tls, tcp_mux);
    let json = serde_json::to_vec(&hello)
        .map_err(|e| crate::Error::Protocol(format!("serialize ClientHello: {e}")))?;
    stream.write_raw_v2_frame(V2_FRAME_TYPE_CLIENT_HELLO, 0, &json).await?;

    let (frame_type, _flags, payload) = stream.read_raw_v2_frame().await?;
    match frame_type {
        V2_FRAME_TYPE_SERVER_HELLO => {
            let server_hello: ServerHello = serde_json::from_slice(&payload)
                .map_err(|e| crate::Error::Protocol(format!("deserialize ServerHello: {e}")))?;
            if let Some(err) = server_hello.error {
                return Err(crate::Error::Protocol(format!("ServerHello error: {err}")));
            }
            Ok(())
        }
        V2_FRAME_TYPE_MESSAGE => {
            Err(crate::Error::Protocol(
                "server skipped ServerHello — unexpected for V2 client".into()
            ))
        }
        other => Err(crate::Error::Protocol(format!(
            "unexpected V2 frame type during handshake: {other}"
        ))),
    }
}

// ---------------------------------------------------------------------------
// Server-side handshake (operates on IoStream)
// ---------------------------------------------------------------------------

/// Handle V2 server handshake: read first frame, respond if ClientHello.
///
/// Returns `Ok(None)` if ClientHello was handled, ServerHello sent.
/// Caller must read the next frame for the first V2 message.
///
/// Returns `Ok(Some(payload))` if the first frame was already a Message (type=16).
/// Caller should decode `payload` as the first V2 message.
pub async fn v2_handshake_server(
    stream: &mut IoStream,
) -> Result<Option<Vec<u8>>, crate::Error> {
    let (frame_type, _flags, payload) = stream.read_raw_v2_frame().await?;

    match frame_type {
        V2_FRAME_TYPE_CLIENT_HELLO => {
            let client_hello: ClientHello = serde_json::from_slice(&payload)
                .map_err(|e| crate::Error::Protocol(format!("deserialize ClientHello: {e}")))?;

            let server_hello = if client_hello.capabilities.message.codecs.contains(&"json".to_string()) {
                ServerHello::default_ok()
            } else {
                ServerHello::with_error("unsupported message codec")
            };

            let json = serde_json::to_vec(&server_hello)
                .map_err(|e| crate::Error::Protocol(format!("serialize ServerHello: {e}")))?;
            stream.write_raw_v2_frame(V2_FRAME_TYPE_SERVER_HELLO, 0, &json).await?;

            if server_hello.error.is_some() {
                return Err(crate::Error::Protocol("ClientHello rejected: unsupported codec".into()));
            }
            Ok(None) // caller must read next frame
        }
        V2_FRAME_TYPE_MESSAGE => {
            Ok(Some(payload)) // this IS the first message payload
        }
        other => Err(crate::Error::Protocol(format!(
            "unexpected V2 frame type on accept: {other}"
        ))),
    }
}
```

- [ ] **Step 3: Register module in `frp-core/src/lib.rs`**

After line `pub mod quic;`:

```rust
pub mod v2_handshake;
```

- [ ] **Step 4: Build to verify**

```bash
cargo build -p frp-core
```
Expected: compiles clean.

- [ ] **Step 5: Commit**

```bash
git add frp-core/src/v2_handshake.rs frp-core/src/lib.rs frp-core/src/transport.rs
git commit -m "feat: add V2 ClientHello/ServerHello handshake + IoStream raw frame methods

v2_handshake module matching Go frp v0.69.1 bootstrap negotiation.
Crypto deferred — always selects json codec, no AEAD crypto.
IoStream gains write_raw_v2_frame/read_raw_v2_frame for handshake use.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 4: Transport Layer — DialOptions, Magic, Accept Detection, IoStream Methods

**File:** `frp-core/src/transport.rs`
**Deps:** Task 3 (uses IoStream raw frame methods from transport, v2_handshake from handshake module).

- [ ] **Step 1: Add `v2: bool` to `DialOptions` struct**

Add field after `proxy_url` (currently the last field, ~line 725):
```rust
    /// Use V2 protocol framing. Client writes V2 magic bytes and performs
    /// ClientHello/ServerHello handshake. Default: false (V1).
    pub v2: bool,
```

In `DialOptions::default()` (~line 744), add:
```rust
            v2: false,
```

- [ ] **Step 2: Write V2 magic in `dial_server()`**

After the stream is connected (after the `connect_direct`/`connect_via_proxy` block, before the `match opts.protocol` block at ~line 1088):

Find the line before `match opts.protocol {`:
```rust
    };

    match opts.protocol {
```

Replace with:
```rust
    };

    // Write V2 magic BEFORE any TLS/WS/yamux upgrade (Go frp WriteMagicIfV2).
    if opts.v2 {
        crate::protocol::write_v2_magic(&mut stream).await?;
    }

    match opts.protocol {
```

- [ ] **Step 3: Replace `peek_connection_type` with `detect_and_strip_magic`**

Find the `peek_connection_type` function (~line 1176) and its `peek_byte` helpers (~lines 1207-1239). Delete all of them. Replace with:

```rust
/// Detect connection type by reading first 7 bytes from the stream (consuming).
///
/// If the 7 bytes match V2 magic, returns `(V2, IoStream::Tcp(stream))` —
/// magic consumed, stream ready for V2 framing.
///
/// If no match, wraps consumed bytes in `IoStream::PreRead` and classifies
/// by the first byte. Downstream handlers receive the exact same byte stream.
pub async fn detect_and_strip_magic(
    mut stream: tokio::net::TcpStream,
) -> Result<(ConnectionType, IoStream), crate::Error> {
    use tokio::io::AsyncReadExt;

    let mut magic_buf = [0u8; 7];
    match tokio::time::timeout(
        std::time::Duration::from_secs(5),
        stream.read_exact(&mut magic_buf),
    ).await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => {
            return Err(crate::Error::Transport(format!("read connection magic: {e}")));
        }
        Err(_) => {
            return Err(crate::Error::Transport("timeout reading connection magic".into()));
        }
    }

    if magic_buf == crate::protocol::V2_MAGIC_BYTES {
        return Ok((ConnectionType::V2, IoStream::Tcp(stream)));
    }

    let first_byte = magic_buf[0];
    let ct = match first_byte {
        FRP_TLS_HEAD_BYTE | FRP_TLS_DIRECT_BYTE => ConnectionType::Tls(first_byte),
        b'G' => ConnectionType::WebSocket,
        b => ConnectionType::V1(b),
    };

    Ok((ct, IoStream::PreRead(magic_buf.to_vec(), stream)))
}
```

- [ ] **Step 4: Rewrite `IoStream::write_v2_frame` body**

Replace body (~lines 618-629):

```rust
    pub async fn write_v2_frame(&mut self, msg: &crate::msg::FrpMessage) -> Result<(), crate::Error> {
        match self {
            IoStream::Tcp(s) => crate::protocol::write_msg_v2_go(s, msg).await,
            IoStream::Tls(s) => crate::protocol::write_msg_v2_go(s, msg).await,
            IoStream::Kcp(s) => crate::protocol::write_msg_v2_go(s, msg).await,
            IoStream::Quic(s) => crate::protocol::write_msg_v2_go(s, msg).await,
            IoStream::WebSocket(s) => crate::protocol::write_msg_v2_go(s, msg).await,
            IoStream::Yamux(s) => crate::protocol::write_msg_v2_go(s, msg).await,
            IoStream::Cipher(s) => crate::protocol::write_msg_v2_go(s, msg).await,
            IoStream::SshChannel(s) => crate::protocol::write_msg_v2_go(s, msg).await,
        }
    }
```

- [ ] **Step 5: Rewrite `IoStream::read_v2_frame` body**

Replace body (~lines 632-642):

```rust
    pub async fn read_v2_frame(&mut self) -> Result<crate::msg::FrpMessage, crate::Error> {
        match self {
            IoStream::Tcp(s) => crate::protocol::read_msg_v2_go(s).await,
            IoStream::Tls(s) => crate::protocol::read_msg_v2_go(s).await,
            IoStream::Kcp(s) => crate::protocol::read_msg_v2_go(s).await,
            IoStream::Quic(s) => crate::protocol::read_msg_v2_go(s).await,
            IoStream::WebSocket(s) => crate::protocol::read_msg_v2_go(s).await,
            IoStream::Yamux(s) => crate::protocol::read_msg_v2_go(s).await,
            IoStream::Cipher(s) => crate::protocol::read_msg_v2_go(s).await,
            IoStream::SshChannel(s) => crate::protocol::read_msg_v2_go(s).await,
        }
    }
```

- [ ] **Step 6: Update `read_msg`/`write_msg` in protocol.rs to use new functions**

In `frp-core/src/protocol.rs`, update the dispatch functions:

```rust
pub async fn read_msg<R: AsyncReadExt + Unpin>(
    reader: &mut R,
    v2: bool,
) -> Result<FrpMessage, crate::Error> {
    if v2 {
        read_msg_v2_go(reader).await
    } else {
        read_msg_v1(reader).await
    }
}

pub async fn write_msg<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    msg: &FrpMessage,
    v2: bool,
) -> Result<(), crate::Error> {
    if v2 {
        write_msg_v2_go(writer, msg).await
    } else {
        write_msg_v1(writer, msg).await
    }
}
```

- [ ] **Step 7: Remove old V2 functions from protocol.rs**

Delete these:
- `write_v2_frame` function (the old 13-byte-header version)
- `read_v2_frame` function (the old 13-byte-header version)
- `write_msg_v2` function (the old version using v1_type_byte as frame type)
- `read_msg_v2` function (the old version calling deserialize_v1)
- `V2_HEADER_LEN` constant (the old 13-byte value)

Then rename `write_msg_v2_go` → `write_msg_v2` and `read_msg_v2_go` → `read_msg_v2`.
Update all call sites: `read_msg`/`write_msg` in protocol.rs, IoStream methods in transport.rs.

- [ ] **Step 8: Build whole workspace to verify**

```bash
cargo build --workspace
```
Expected: compiles clean. All callers resolved.

- [ ] **Step 9: Commit**

```bash
git add frp-core/src/transport.rs frp-core/src/protocol.rs
git commit -m "feat: rewrite transport layer for Go-compatible V2

- Add v2 field to DialOptions
- Write V2 magic in dial_server() before protocol upgrade
- Replace peek_connection_type with detect_and_strip_magic
  (reads 7 bytes consuming, PreRead wraps non-V2 data)
- Rewrite IoStream write_v2_frame/read_v2_frame for new format
- Remove old 13-byte-header V2 functions from protocol.rs

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 5: Config + Client Handshake Wiring

**Files:**
- Modify: `frp-core/src/config.rs`
- Modify: `frp-client/src/control.rs`

- [ ] **Step 1: Add `wireProtocol` alias in config normalization**

In `frp-core/src/config.rs`, find where `[transport]` fields are normalized into top-level keys (the `toml_to_json` conversion or the config normalization function). Look for where `tcp_mux` is handled.

Add this block (in the same area where transport fields are mapped):

```rust
// transport.wireProtocol → top-level v2 flag (Go frp compat)
if let Some(transport) = root.get("transport").and_then(|t| t.as_object()) {
    if let Some(wp) = transport.get("wireProtocol").and_then(|v| v.as_str()) {
        if wp == "v2" {
            if let Some(obj) = root.as_object_mut() {
                obj.insert("v2".to_string(), serde_json::Value::Bool(true));
            }
        }
    }
}
```

(The exact insertion point depends on where transport field normalization happens. Search for `"tcp_mux"` or `"tcpMux"` in the config normalization code to find the right location.)

- [ ] **Step 2: Call `v2_handshake_client` in client `login()`**

In `frp-client/src/control.rs`, `login()` method. After `dial_server` returns and before yamux wrapping (~line 127):

Find:
```rust
        let raw_stream = dial_server(&opts).await?;

        // Wrap in yamux BEFORE any protocol communication if proposing mux.
```

Replace with:
```rust
        let mut raw_stream = dial_server(&opts).await?;

        // V2: ClientHello/ServerHello handshake on raw stream BEFORE yamux.
        if self.v2 {
            let transport_name = match self.transport_protocol {
                TransportProtocol::Tcp => "tcp",
                TransportProtocol::Kcp => "kcp",
                TransportProtocol::Quic => "quic",
                TransportProtocol::WebSocket => "websocket",
                TransportProtocol::Wss => "wss",
            };
            frp_core::v2_handshake::v2_handshake_client(
                &mut raw_stream,
                transport_name,
                self.tls_enable,
                self.tcp_mux,
            ).await?;
        }

        // Wrap in yamux BEFORE any protocol communication if proposing mux.
```

Need to update the `opts` construction (~line 105) to include `v2`:
```rust
        let opts = DialOptions {
            // ... existing fields ...
            v2: self.v2,
            ..Default::default()
        };
```

- [ ] **Step 3: Build workspace**

```bash
cargo build --workspace
```
Expected: compiles clean.

- [ ] **Step 4: Commit**

```bash
git add frp-core/src/config.rs frp-client/src/control.rs
git commit -m "feat: wire V2 handshake into client + add wireProtocol config alias

- transport.wireProtocol = \"v2\" now sets top-level v2=true (Go compat)
- Call v2_handshake_client in ControlSession::login() after dial,
  before yamux wrapping (matches Go frp flow)
- Pass v2 flag to DialOptions

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 6: Server Changes — Accept Loop, Control, Bridge

**Files:**
- Modify: `frp-server/src/service.rs`
- Modify: `frp-server/src/control/mod.rs`
- Modify: `frp-server/src/control/bridge.rs`

- [ ] **Step 1: Replace `peek_connection_type` call in server accept loop**

In `frp-server/src/service.rs`, ~line 594:

Find:
```rust
                    tokio::spawn(async move {
                        let ct = match peek_connection_type(&stream).await {
                            Ok(c) => c,
                            ...
                        };
                        match ct {
```

Replace `peek_connection_type(&stream).await` with `detect_and_strip_magic(stream).await`:

```rust
                    tokio::spawn(async move {
                        let (ct, mut stream_io) = match detect_and_strip_magic(stream).await {
                            Ok((c, s)) => (c, s),
                            Err(e) => {
                                warn!("Failed to detect connection type from {}: {}", addr, e);
                                return;
                            }
                        };
```

Update import at top of file: change `peek_connection_type` to `detect_and_strip_magic`.

This is a significant refactor of the accept loop because `stream` is now `stream_io: IoStream` instead of `TcpStream`. The subsequent match arms (`ConnectionType::Tls(first_byte)`, `ConnectionType::WebSocket`, `ConnectionType::V2`, `ConnectionType::V1(byte)`) all need to work with `IoStream` instead of `TcpStream`.

For the V2 branch (~line 782), the stream is already an `IoStream` — extract the inner TcpStream for yamux wrapping if needed:

```rust
    ConnectionType::V2 => {
        // stream_io is IoStream::Tcp(inner) — V2 magic already consumed
        // Extract inner TcpStream for yamux wrapping
        let inner_stream = match stream_io {
            IoStream::Tcp(s) => s,
            other => {
                warn!("Expected TcpStream for V2, got {:?}", std::mem::discriminant(&other));
                return;
            }
        };

        if state.tls_only {
            warn!("TLS-only mode: rejected V2 from {}", addr);
            return;
        }

        if state.tcp_mux {
            // Wrap in yamux BEFORE reading first frame
            let mux_cfg = mux::TcpMuxConfig {
                keepalive_interval: std::time::Duration::from_secs(
                    state.tcp_mux_keepalive.max(1) as u64
                ),
            };
            match mux::server_mux(inner_stream, &mux_cfg).await {
                Ok((control_stream, incoming)) => {
                    let mut io = IoStream::Yamux(control_stream);
                    info!("Yamux over V2 for {}", addr);
                    handle_v2_accept(&mut io, state, Some(addr), Some(incoming)).await;
                }
                Err(e) => {
                    warn!("Failed to start yamux over V2 for {}: {}", addr, e);
                }
            }
        } else {
            let mut io = IoStream::Tcp(inner_stream);
            handle_v2_accept(&mut io, state, Some(addr), None).await;
        }
    }
```

For non-V2 branches (Tls, WebSocket, V1), the `stream_io` is `IoStream::PreRead(magic_buf, original_stream)`. Need to extract and handle. The existing TLS/WS/V1 code expects a `TcpStream` — the PreRead wrapper needs to be unwrapped and the pre-read bytes handled.

Simplest approach for now: since Go frp's SharedConn replays consumed bytes transparently, and our PreReadStream does the same — use the `PreReadStream` wrapper that exists in transport.rs. The PreRead IoStream wraps a `PreReadStream<TcpStream>` which implements AsyncRead/AsyncWrite. The accept loop can pass it directly to TLS acceptors and `read_msg_v1` — they'll read the prepended bytes first.

For the non-V2 branches, just use `stream_io` as is (it's PreRead-wrapped, so the 7 consumed bytes are replayed). TLS/WSS/WS/V1 handlers can work with it since PreRead implements AsyncRead+AsyncWrite.

Let me create a helper function `handle_v2_accept` to avoid code duplication:

```rust
/// Handle V2 connection after magic detection and optional yamux wrapping.
async fn handle_v2_accept(
    io: &mut IoStream,
    state: AppState,
    addr: Option<SocketAddr>,
    incoming: Option<mux::YamuxIncoming>,
) {
    // Perform handshake (ClientHello → ServerHello)
    let msg_payload = match v2_handshake::v2_handshake_server(io).await {
        Ok(Some(payload)) => payload,  // direct Message frame
        Ok(None) => {
            // ClientHello handled, read next frame for message
            match io.read_raw_v2_frame().await {
                Ok((V2_FRAME_TYPE_MESSAGE, _, p)) => p,
                Ok((ft, _, _)) => {
                    warn!("Unexpected frame type {} after V2 handshake from {:?}", ft, addr);
                    return;
                }
                Err(e) => {
                    warn!("Failed to read V2 message after handshake from {:?}: {}", addr, e);
                    return;
                }
            }
        }
        Err(e) => {
            warn!("V2 handshake error from {:?}: {}", addr, e);
            return;
        }
    };

    // Decode message from payload
    if msg_payload.len() < 2 {
        warn!("V2 message payload too short from {:?}", addr);
        return;
    }
    let type_id = u16::from_be_bytes([msg_payload[0], msg_payload[1]]);
    let msg = match deserialize_v2(type_id, &msg_payload[2..]) {
        Ok(m) => m,
        Err(e) => {
            warn!("Failed to decode V2 message from {:?}: {}", addr, e);
            return;
        }
    };

    let v2 = true;
    match msg {
        FrpMessage::Login(login) => {
            control::handle_control(io.clone(), login, state, addr, incoming, v2).await;
        }
        FrpMessage::NewWorkConn(nwc) => {
            let io_clone = match io {
                IoStream::Yamux(_) => io.clone(),
                IoStream::Tcp(s) => {
                    // Need to create a new IoStream from the same TcpStream
                    // This is tricky with ownership — the handle_work_conn_inner
                    // takes ownership of the IoStream
                    // For now, use the already-read IoStream pattern
                    return; // TODO: handle properly
                }
                _ => return,
            };
            handle_work_conn_inner(io_clone, nwc, state).await;
        }
        // ... other variants
        _ => {
            warn!("Unexpected V2 first message from {:?}: {:?}", addr, msg.v2_type_id());
        }
    }
}
```

Wait, this is getting complex because `handle_work_conn_inner` takes `IoStream` by value. The ownership after reading is tricky. Let me look at how the current code handles this for V1 without yamux.

Looking at the current V1 path (line ~869+):
```rust
match read_msg_v1(&mut stream).await {
    Ok(FrpMessage::Login(login)) => {
        control::handle_control(stream, login, state, Some(addr), None, false).await;
    }
    Ok(FrpMessage::NewWorkConn(nwc)) => {
        let io = IoStream::Tcp(stream);
        handle_work_conn_inner(io, nwc, state).await;
    }
```

So for V1, `stream` is a `TcpStream` (owned), and `read_msg_v1(&mut stream)` borrows it, then ownership is moved into `IoStream::Tcp(stream)`. The same pattern works for V2.

For V2 after yamux, the yamux `control_stream` is moved into `IoStream::Yamux(control_stream)`, and we read from `&mut IoStream::Yamux(...)`. Then we need to move ownership into `handle_control` or `handle_work_conn_inner`.

But wait — `handle_v2_accept` takes `&mut IoStream`. After reading the message, we need to move ownership. The cleanest approach: `handle_v2_accept` takes `IoStream` by value (not &mut), borrows for reading, then moves ownership after.

Let me simplify the approach. Instead of a helper function, just inline the V2 handling in the accept loop like the current code does for V1. This avoids ownership issues.

OK, the plan is getting very long with code. Let me simplify the remaining tasks and focus on the key changes. The implementor can work out ownership details.

- [ ] **Step 1 (revised): Rewrite V2 accept branch in service.rs**

Replace the current V2 branch (~lines 782-852) with the new handshake-aware version. Key flow:
1. Extract TcpStream from `stream_io`
2. If yamux: wrap, create IoStream::Yamux
3. If no yamux: create IoStream::Tcp
4. Call `v2_handshake_server(&mut io)` to handle possible ClientHello
5. Read message frame if handshake consumed ClientHello
6. Decode message via `deserialize_v2()`
7. Dispatch: Login → `handle_control`, NewWorkConn → `handle_work_conn_inner`, etc. (with `v2: true`)

For non-V2 branches (Tls, WebSocket, V1): `stream_io` is `IoStream::PreRead(...)`. Extract inner stream:
```rust
let mut stream = match stream_io {
    IoStream::PreRead(pre_read, inner) => {
        // PreReadStream replays consumed bytes transparently
        PreReadStream::new(pre_read, inner)
    }
    _ => unreachable!("non-V2 always returns PreRead from detect_and_strip_magic"),
};
```
Then use `stream` (which implements AsyncRead+AsyncWrite) where the old code used `stream: TcpStream`.

- [ ] **Step 2: Update server control `read_ctl_msg`/`write_ctl_msg`**

In `frp-server/src/control/mod.rs`, these are already dispatching on `v2: bool`. The underlying functions (`read_msg_v2`/`write_msg_v2`) are now the new implementations. Verify no changes needed — if they use `read_msg`/`write_msg`, they're already updated. If they call `read_msg_v2`/`write_msg_v2` directly, the renamed functions now work.

Quick check: `read_ctl_msg` calls `read_msg_v2` or `read_msg_v1`. After Task 4 Step 7 renamed `read_msg_v2_go` → `read_msg_v2`, this should work. Verify it compiles.

- [ ] **Step 3: Update server bridge V2 calls**

In `frp-server/src/control/bridge.rs`:
- `assign_work_to_proxy`: change `write_msg_v2` → `write_msg_v2` (already renamed)
- `assign_udp_work_conn`: same
- Verify StartWorkConn read/write uses correct function names

- [ ] **Step 4: Build workspace**

```bash
cargo build --workspace
```
Expected: compiles. Fix any compilation errors from ownership/type mismatches.

- [ ] **Step 5: Commit**

```bash
git add frp-server/src/service.rs frp-server/src/control/mod.rs frp-server/src/control/bridge.rs
git commit -m "feat: rewrite server accept for Go-compatible V2

- Replace peek_connection_type with detect_and_strip_magic (7-byte read)
- V2 accept: handshake → message decode → dispatch with v2=true
- Non-V2 branches use PreRead wrapper for consumed byte replay
- Update control and bridge to use renamed V2 functions

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 7: Unit Tests for protocol.rs V2 Functions

**File:** `frp-core/src/protocol.rs` (test module)

- [ ] **Step 1: Add V2 unit tests**

Add to the existing `#[cfg(test)] mod tests` block. Replace the old V2 tests (lines 433-510) with new tests:

```rust
    // --- V2 protocol tests (Go-compatible format) ---

    #[tokio::test]
    async fn test_v2_frame_raw_roundtrip() {
        let (mut client, mut server) = duplex(65536);
        let payload = b"hello v2 world";
        write_v2_frame_raw(&mut client, 16, 0, payload).await.expect("write raw V2");
        let (ft, flags, data) = read_v2_frame_raw(&mut server).await.expect("read raw V2");
        assert_eq!(ft, 16);
        assert_eq!(flags, 0);
        assert_eq!(data, payload);
    }

    #[tokio::test]
    async fn test_v2_frame_raw_rejects_nonzero_flags() {
        let (mut client, mut server) = duplex(65536);
        // Write frame with flags=1 (unsupported)
        let mut header = [0u8; 8];
        header[0..2].copy_from_slice(&16u16.to_be_bytes());  // type=Message
        header[2..4].copy_from_slice(&1u16.to_be_bytes());   // flags=1
        header[4..8].copy_from_slice(&4u32.to_be_bytes());   // len=4
        client.write_all(&header).await.unwrap();
        client.write_all(b"data").await.unwrap();
        drop(client);

        let result = read_v2_frame_raw(&mut server).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("flags"));
    }

    #[tokio::test]
    async fn test_v2_frame_raw_oversized_payload() {
        let mut buf = Vec::new();
        let oversized = vec![0u8; (V2_MAX_FRAME_PAYLOAD + 1) as usize];
        let result = write_v2_frame_raw(&mut buf, 16, 0, &oversized).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("too large"));
    }

    #[tokio::test]
    async fn test_v2_msg_18_types_roundtrip() {
        // Test all 18 V2 message types survive encode → decode
        let messages: Vec<FrpMessage> = vec![
            FrpMessage::Login(msg::Login::default()),
            FrpMessage::LoginResp(msg::LoginResp::default()),
            FrpMessage::NewProxy(msg::NewProxy::default()),
            FrpMessage::NewProxyResp(msg::NewProxyResp::default()),
            FrpMessage::CloseProxy(msg::CloseProxy::default()),
            FrpMessage::NewWorkConn(msg::NewWorkConn::default()),
            FrpMessage::ReqWorkConn(msg::ReqWorkConn::default()),
            FrpMessage::StartWorkConn(msg::StartWorkConn::default()),
            FrpMessage::NewVisitorConn(msg::NewVisitorConn::default()),
            FrpMessage::NewVisitorConnResp(msg::NewVisitorConnResp::default()),
            FrpMessage::Ping(msg::Ping::default()),
            FrpMessage::Pong(msg::Pong::default()),
            FrpMessage::UDPPacket(msg::UDPPacket::default()),
            FrpMessage::NatHoleVisitor(msg::NatHoleVisitor::default()),
            FrpMessage::NatHoleClient(msg::NatHoleClient::default()),
            FrpMessage::NatHoleResp(msg::NatHoleResp::default()),
            FrpMessage::NatHoleSid(msg::NatHoleSid::default()),
            FrpMessage::NatHoleReport(msg::NatHoleReport::default()),
        ];

        for msg in &messages {
            let (mut client, mut server) = duplex(65536);
            write_msg_v2(&mut client, msg).await.expect("write v2");
            let back = read_msg_v2(&mut server).await.expect("read v2");
            assert_eq!(back.v2_type_id(), msg.v2_type_id(),
                "roundtrip type mismatch for {:?}", msg.v2_type_id());
        }
    }

    #[tokio::test]
    async fn test_v2_msg_unknown_type_id() {
        let (mut client, mut server) = duplex(65536);
        // Write frame type=16 with type_id=99 and empty JSON payload
        let mut payload = vec![0u8; 2];
        payload[0..2].copy_from_slice(&99u16.to_be_bytes());
        write_v2_frame_raw(&mut client, V2_FRAME_TYPE_MESSAGE, 0, &payload).await.unwrap();
        drop(client);

        let result = read_msg_v2(&mut server).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("unknown V2 message type ID: 99"));
    }

    #[tokio::test]
    async fn test_v2_msg_payload_too_short() {
        let (mut client, mut server) = duplex(65536);
        // Write frame type=16 with only 1 byte payload (need 2 for type_id)
        write_v2_frame_raw(&mut client, V2_FRAME_TYPE_MESSAGE, 0, b"x").await.unwrap();
        drop(client);

        let result = read_msg_v2(&mut server).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("too short"));
    }

    #[tokio::test]
    async fn test_v2_msg_wrong_frame_type() {
        let (mut client, mut server) = duplex(65536);
        // Write frame with type=1 (ClientHello) — read_msg_v2 should reject
        write_v2_frame_raw(&mut client, V2_FRAME_TYPE_CLIENT_HELLO, 0, b"{}").await.unwrap();
        drop(client);

        let result = read_msg_v2(&mut server).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("unexpected V2 frame type: 1"));
    }

    #[tokio::test]
    async fn test_v2_msg_login_content() {
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
```

- [ ] **Step 2: Run tests**

```bash
cargo test -p frp-core -- protocol::tests
```
Expected: all V2 tests pass. V1 tests also still pass.

- [ ] **Step 3: Commit**

```bash
git add frp-core/src/protocol.rs
git commit -m "test: add V2 protocol unit tests for Go-compatible format

8 tests: frame raw roundtrip, flags rejection, oversized payload,
all 18 types roundtrip, unknown type_id, too-short payload,
wrong frame type rejection, Login content verification.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 8: Integration Test — Rust V2 Client ↔ Rust V2 Server

**Files:**
- Create: `frp-server/tests/v2_integration.rs` (or add to existing test file)

- [ ] **Step 1: Write integration test**

```rust
//! V2 protocol integration test: Rust frpc (v2) ↔ Rust frps (v2).

use std::time::Duration;
use tokio::net::TcpListener;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

mod common;
use common::{start_frps, start_frpc, wait_for_port};

#[tokio::test]
async fn test_v2_tcp_proxy() {
    // Start frps with a random port
    let frps_port = common::find_free_port().await;
    let frps = start_frps(&format!("
        [common]
        bind_port = {frps_port}
        token = test123
    ")).await;

    // Start local echo server
    let echo_port = common::find_free_port().await;
    let echo_listener = TcpListener::bind(format!("127.0.0.1:{echo_port}")).await.unwrap();
    tokio::spawn(async move {
        loop {
            let (mut sock, _) = echo_listener.accept().await.unwrap();
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                let n = sock.read(&mut buf).await.unwrap();
                sock.write_all(&buf[..n]).await.unwrap();
            });
        }
    });

    // Start frpc with v2=true
    let remote_port = common::find_free_port().await;
    let frpc = start_frpc(&format!("
        [common]
        server_addr = 127.0.0.1
        server_port = {frps_port}
        token = test123
        v2 = true
        tcp_mux = true

        [[proxies]]
        name = test_v2_tcp
        type = tcp
        local_ip = 127.0.0.1
        local_port = {echo_port}
        remote_port = {remote_port}
    ")).await;

    // Wait for proxy to register
    tokio::time::sleep(Duration::from_secs(1)).await;

    // Connect to proxy and verify echo
    let mut conn = tokio::net::TcpStream::connect(format!("127.0.0.1:{remote_port}"))
        .await.unwrap();
    conn.write_all(b"hello v2").await.unwrap();
    let mut buf = [0u8; 1024];
    let n = conn.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"hello v2");

    frpc.kill().await;
    frps.kill().await;
}
```

(The exact format depends on the test harness. Check existing tests in `frp-server/tests/` for the pattern.)

- [ ] **Step 2: Run integration test**

```bash
cargo test --test v2_integration
```
Expected: passes.

- [ ] **Step 3: Commit**

```bash
git add frp-server/tests/
git commit -m "test: add V2 TCP proxy integration test (Rust↔Rust)

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 9: Compat Tests — Rust V2 ↔ Go frp V2

**File:** `scripts/compat-test.sh` (append V2 cases)

- [ ] **Step 1: Add V2 compat test cases to compat-test.sh**

Go frp V2 config uses `transport.wireProtocol = "v2"` in TOML. Add test cases:

```bash
# V2: Rust frps ← Go frpc (v2)
test_v2_go_client_to_rust_server() {
    local port=$(find_free_port)
    start_rust_frps "$port" "test123"
    # Go frpc with wireProtocol=v2
    cat > /tmp/frpc_v2.ini <<EOF
[common]
server_addr = 127.0.0.1
server_port = $port
token = test123

[transport]
wireProtocol = "v2"
tcpMux = true

[[proxies]]
name = test_v2
type = tcp
local_ip = 127.0.0.1
local_port = $echo_port
remote_port = $remote_port
EOF
    start_go_frpc "/tmp/frpc_v2.ini"
    test_tcp_echo "$remote_port" "v2-go-client-to-rust-server"
}

# V2: Rust frpc (v2) → Go frps
test_v2_rust_client_to_go_server() {
    local port=$(find_free_port)
    start_go_frps "$port" "test123"
    start_rust_frpc "v2=true,tcp_mux=true" "$port" "test123"
    test_tcp_echo "$remote_port" "v2-rust-client-to-go-server"
}
```

- [ ] **Step 2: Run compat tests**

```bash
bash scripts/compat-test.sh --verbose --v2-only
```
Expected: V2 tests pass. V1 tests unaffected.

- [ ] **Step 3: Commit**

```bash
git add scripts/compat-test.sh
git commit -m "test: add V2 compat tests (Rust↔Go frp v0.69.1)

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 10: Final Verification

- [ ] **Step 1: Run all tests**

```bash
cargo test --workspace
bash scripts/compat-test.sh --verbose
```
Expected: all tests pass, no regressions.

- [ ] **Step 2: Run clippy**

```bash
cargo clippy --workspace
```
Expected: no new warnings.

- [ ] **Step 3: Final commit (if any fixes)**

```bash
git add -A && git commit -m "chore: final V2 protocol fixes and cleanup

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```
