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

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BootstrapInfo {
    #[serde(default)]
    pub transport: String,
    #[serde(default)]
    pub tls: bool,
    #[serde(default, rename = "tcpMux")]
    pub tcp_mux: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MessageCapabilities {
    #[serde(default)]
    pub codecs: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CryptoCapabilities {
    #[serde(default)]
    pub algorithms: Vec<String>,
    // Go json encodes []byte as base64 string; accept String for now (crypto deferred).
    #[serde(default, rename = "clientRandom")]
    pub client_random: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ClientCapabilities {
    #[serde(default)]
    pub message: MessageCapabilities,
    #[serde(default)]
    pub crypto: CryptoCapabilities,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ClientHello {
    #[serde(default)]
    pub bootstrap: BootstrapInfo,
    #[serde(default)]
    pub capabilities: ClientCapabilities,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MessageSelection {
    #[serde(default)]
    pub codec: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CryptoSelection {
    #[serde(default)]
    pub algorithm: String,
    // Go json encodes []byte as base64 string; accept String for now (crypto deferred).
    #[serde(default, rename = "serverRandom")]
    pub server_random: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ServerSelection {
    #[serde(default)]
    pub message: MessageSelection,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub crypto: Option<CryptoSelection>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ServerHello {
    #[serde(default)]
    pub selected: ServerSelection,
    #[serde(default, skip_serializing_if = "Option::is_none")]
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
            if server_hello.selected.message.codec != "json" {
                return Err(crate::Error::Protocol(format!(
                    "server selected unsupported codec: {}",
                    server_hello.selected.message.codec
                )));
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

            let server_hello = if client_hello.capabilities.message.codecs.iter().any(|c| c == "json") {
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
