//! V2 protocol ClientHello / ServerHello handshake with AEAD crypto negotiation.
//!
//! Matching Go frp pkg/proto/wire/wire.go + crypto.go bootstrap negotiation.
//!
//! Flow:
//! 1. Client sends ClientHello with supported AEAD algorithms + client_random
//! 2. Server selects algorithm, generates server_random, sends ServerHello
//! 3. Both sides compute transcript_hash from raw handshake JSON payloads
//! 4. Both sides derive directional AEAD keys via HKDF-SHA256
//! 5. All subsequent V2 frames are encrypted with the selected AEAD algorithm

use std::time::Duration;

use base64::Engine;
use rand::RngCore;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};

use crate::crypto::AeadAlgorithm;
use crate::transport::IoStream;
use crate::protocol::{V2_FRAME_TYPE_CLIENT_HELLO, V2_FRAME_TYPE_SERVER_HELLO, V2_FRAME_TYPE_MESSAGE};

/// Timeout for V2 handshake reads (matching Go frp connReadTimeout).
const V2_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Crypto random size in bytes (matching Go frp CryptoRandomSize = 32).
const CRYPTO_RANDOM_SIZE: usize = 32;

/// Transcript label used in hash computation.
const CRYPTO_TRANSCRIPT_LABEL: &str = "frp wire v2 crypto transcript";

// ---------------------------------------------------------------------------
// base64 helper for Vec<u8> serde (matching Go's []byte → base64 JSON)
// ---------------------------------------------------------------------------

fn base64_serialize<S: Serializer>(bytes: &Option<Vec<u8>>, s: S) -> Result<S::Ok, S::Error> {
    match bytes {
        Some(b) => {
            let encoded = base64::engine::general_purpose::STANDARD.encode(b);
            s.serialize_some(&encoded)
        }
        None => s.serialize_none(),
    }
}

fn base64_deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Vec<u8>>, D::Error> {
    let opt: Option<String> = Option::deserialize(d)?;
    match opt {
        Some(s) => {
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(s.as_bytes())
                .map_err(serde::de::Error::custom)?;
            Ok(Some(bytes))
        }
        None => Ok(None),
    }
}

fn base64_serialize_non_null<S: Serializer>(bytes: &Vec<u8>, s: S) -> Result<S::Ok, S::Error> {
    let encoded = base64::engine::general_purpose::STANDARD.encode(bytes);
    s.serialize_str(&encoded)
}

fn base64_deserialize_non_null<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
    let s: String = String::deserialize(d)?;
    base64::engine::general_purpose::STANDARD
        .decode(s.as_bytes())
        .map_err(serde::de::Error::custom)
}

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
    /// 32 random bytes, base64-encoded in JSON (matching Go []byte).
    #[serde(
        default,
        serialize_with = "base64_serialize",
        deserialize_with = "base64_deserialize",
        rename = "clientRandom"
    )]
    pub client_random: Option<Vec<u8>>,
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
    /// 32 random bytes, base64-encoded in JSON (matching Go []byte).
    #[serde(
        default,
        serialize_with = "base64_serialize_non_null",
        deserialize_with = "base64_deserialize_non_null",
        rename = "serverRandom"
    )]
    pub server_random: Vec<u8>,
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
// CryptoContext — returned after successful handshake
// ---------------------------------------------------------------------------

/// Cryptographic context established during V2 handshake.
///
/// Contains the selected algorithm and transcript hash, which are used to
/// derive directional AEAD keys via HKDF-SHA256.
#[derive(Debug, Clone)]
pub struct CryptoContext {
    pub algorithm: AeadAlgorithm,
    pub transcript_hash: Vec<u8>,
}

// ---------------------------------------------------------------------------
// Preferred algorithm order (matching Go frp PreferredAEADAlgorithms)
// ---------------------------------------------------------------------------

/// Return preferred AEAD algorithms in order. AES-256-GCM first on x86 with
/// AES-NI, otherwise XChaCha20-Poly1305 first. We always prefer AES-256-GCM
/// on modern hardware.
pub fn preferred_aead_algorithms() -> Vec<String> {
    vec![
        AeadAlgorithm::Aes256Gcm.as_str().to_string(),
        AeadAlgorithm::XChaCha20Poly1305.as_str().to_string(),
    ]
}

/// Select first algorithm from client list that we support.
pub fn select_aead_algorithm(client_algorithms: &[String]) -> Option<AeadAlgorithm> {
    for alg in client_algorithms {
        if let Some(a) = AeadAlgorithm::from_str(alg) {
            return Some(a);
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Constructors
// ---------------------------------------------------------------------------

impl ClientHello {
    /// Build a ClientHello with crypto capabilities.
    /// Generates 32 random bytes for client_random.
    pub fn new(transport: &str, tls: bool, tcp_mux: bool) -> Self {
        let mut client_random = vec![0u8; CRYPTO_RANDOM_SIZE];
        rand::rngs::OsRng.fill_bytes(&mut client_random);

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
                    algorithms: preferred_aead_algorithms(),
                    client_random: Some(client_random),
                },
            },
        }
    }

    /// Build a ClientHello without crypto (for Rust↔Rust V2 without AEAD).
    pub fn new_without_crypto(transport: &str, tls: bool, tcp_mux: bool) -> Self {
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
                    algorithms: vec![],
                    client_random: None,
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
                crypto: None,
            },
            error: None,
        }
    }

    /// Build a ServerHello with AEAD crypto selection.
    pub fn with_crypto(algorithm: AeadAlgorithm, server_random: Vec<u8>) -> Self {
        Self {
            selected: ServerSelection {
                message: MessageSelection {
                    codec: "json".to_string(),
                },
                crypto: Some(CryptoSelection {
                    algorithm: algorithm.as_str().to_string(),
                    server_random,
                }),
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
// Transcript Hash (matching Go frp crypto.go HashCryptoTranscript)
// ---------------------------------------------------------------------------

/// Compute transcript hash from raw ClientHello and ServerHello JSON payloads.
///
/// Matches Go frp `HashCryptoTranscript`:
///   SHA256("frp wire v2 crypto transcript" || part("client hello", ch) || part("server hello", sh))
/// where part(label, payload) = "\x00" || label || "\x00" || BE64(len(payload)) || payload
pub fn compute_transcript_hash(client_hello_payload: &[u8], server_hello_payload: &[u8]) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(CRYPTO_TRANSCRIPT_LABEL.as_bytes());
    write_transcript_part(&mut h, "client hello", client_hello_payload);
    write_transcript_part(&mut h, "server hello", server_hello_payload);
    h.finalize().to_vec()
}

fn write_transcript_part(h: &mut Sha256, label: &str, payload: &[u8]) {
    h.update(&[0u8]);
    h.update(label.as_bytes());
    h.update(&[0u8]);
    h.update((payload.len() as u64).to_be_bytes());
    h.update(payload);
}

// ---------------------------------------------------------------------------
// Client-side handshake (operates on IoStream)
// ---------------------------------------------------------------------------

/// Perform V2 client handshake after writing magic bytes.
///
/// 1. Writes ClientHello frame (type=1) with crypto capabilities
/// 2. Reads ServerHello frame (type=2)
/// 3. Returns CryptoContext if AEAD crypto was negotiated, None otherwise
///
/// The stream must be positioned after the V2 magic bytes.
/// After this returns, the stream is ready for V2 message frames (encrypted if
/// CryptoContext is Some).
///
/// If `with_crypto` is false, crypto is not proposed and the handshake runs
/// in plain V2 mode (used for Rust↔Rust V2 without AEAD interop).
pub async fn v2_handshake_client(
    stream: &mut IoStream,
    transport: &str,
    tls: bool,
    tcp_mux: bool,
    with_crypto: bool,
) -> Result<Option<CryptoContext>, crate::Error> {
    let hello = if with_crypto {
        ClientHello::new(transport, tls, tcp_mux)
    } else {
        ClientHello::new_without_crypto(transport, tls, tcp_mux)
    };
    let client_hello_json = serde_json::to_vec(&hello)
        .map_err(|e| crate::Error::Protocol(format!("serialize ClientHello: {e}")))?;
    stream.write_raw_v2_frame(V2_FRAME_TYPE_CLIENT_HELLO, 0, &client_hello_json).await?;

    let (frame_type, _flags, server_hello_json) = tokio::time::timeout(
        V2_HANDSHAKE_TIMEOUT,
        stream.read_raw_v2_frame()
    ).await.map_err(|_| crate::Error::Protocol("V2 handshake timeout".into()))??;
    match frame_type {
        V2_FRAME_TYPE_SERVER_HELLO => {
            let server_hello: ServerHello = serde_json::from_slice(&server_hello_json)
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

            // If server selected crypto, validate and build context
            if let Some(ref crypto_sel) = server_hello.selected.crypto {
                let algorithm = AeadAlgorithm::from_str(&crypto_sel.algorithm)
                    .ok_or_else(|| crate::Error::Protocol(format!(
                        "server selected unknown algorithm: {}", crypto_sel.algorithm
                    )))?;
                if crypto_sel.server_random.len() != CRYPTO_RANDOM_SIZE {
                    return Err(crate::Error::Protocol(format!(
                        "invalid server random length: {}",
                        crypto_sel.server_random.len()
                    )));
                }
                // Validate server selected algo was in our offer
                let offered = &hello.capabilities.crypto.algorithms;
                if !offered.iter().any(|a| AeadAlgorithm::from_str(a) == Some(algorithm)) {
                    return Err(crate::Error::Protocol(format!(
                        "server selected algorithm not offered by client: {}", crypto_sel.algorithm
                    )));
                }

                let transcript_hash = compute_transcript_hash(&client_hello_json, &server_hello_json);
                Ok(Some(CryptoContext { algorithm, transcript_hash }))
            } else {
                Ok(None)
            }
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
/// Returns `Ok((None, Some(crypto_ctx)))` if ClientHello was handled with crypto,
/// `Ok((None, None))` if ClientHello was handled without crypto,
/// `Ok((Some(payload), None))` if the first frame was already a Message (type=16).
///
/// `payload` is the raw V2 message payload: [type_id: u16 BE][JSON bytes].
pub async fn v2_handshake_server(
    stream: &mut IoStream,
) -> Result<(Option<Vec<u8>>, Option<CryptoContext>), crate::Error> {
    let (frame_type, _flags, payload) = tokio::time::timeout(
        V2_HANDSHAKE_TIMEOUT,
        stream.read_raw_v2_frame()
    ).await.map_err(|_| crate::Error::Protocol("V2 handshake timeout".into()))??;

    match frame_type {
        V2_FRAME_TYPE_CLIENT_HELLO => {
            let client_hello: ClientHello = serde_json::from_slice(&payload)
                .map_err(|e| crate::Error::Protocol(format!("deserialize ClientHello: {e}")))?;

            if !client_hello.capabilities.message.codecs.iter().any(|c| c == "json") {
                let err_hello = ServerHello::with_error("unsupported message codec");
                let json = serde_json::to_vec(&err_hello)
                    .map_err(|e| crate::Error::Protocol(format!("serialize ServerHello: {e}")))?;
                stream.write_raw_v2_frame(V2_FRAME_TYPE_SERVER_HELLO, 0, &json).await?;
                return Err(crate::Error::Protocol("ClientHello rejected: unsupported codec".into()));
            }

            // Try to negotiate AEAD crypto
            let client_algorithms = &client_hello.capabilities.crypto.algorithms;
            tracing::debug!("[V2-HS] ClientHello algorithms: {:?}, client_random: {:?}",
                client_algorithms,
                client_hello.capabilities.crypto.client_random.as_ref().map(|_| "present"));
            if let Some(algorithm) = select_aead_algorithm(client_algorithms) {
                tracing::debug!("[V2-HS] Selected algorithm: {:?}", algorithm);
                // Validate client_random
                let client_random = client_hello.capabilities.crypto.client_random.as_ref()
                    .ok_or_else(|| crate::Error::Protocol(
                        "ClientHello crypto algorithms present but no client_random".into()
                    ))?;
                if client_random.len() != CRYPTO_RANDOM_SIZE {
                    return Err(crate::Error::Protocol(format!(
                        "invalid client random length: {}", client_random.len()
                    )));
                }

                let mut server_random = vec![0u8; CRYPTO_RANDOM_SIZE];
                rand::rngs::OsRng.fill_bytes(&mut server_random);
                let server_hello = ServerHello::with_crypto(algorithm, server_random);

                let server_hello_json = serde_json::to_vec(&server_hello)
                    .map_err(|e| crate::Error::Protocol(format!("serialize ServerHello: {e}")))?;
                stream.write_raw_v2_frame(V2_FRAME_TYPE_SERVER_HELLO, 0, &server_hello_json).await?;

                let transcript_hash = compute_transcript_hash(&payload, &server_hello_json);
                Ok((None, Some(CryptoContext { algorithm, transcript_hash })))
            } else {
                // No crypto: send plain ServerHello
                tracing::debug!("[V2-HS] No crypto negotiated (client offered {:?})", client_algorithms);
                let server_hello = ServerHello::default_ok();
                let json = serde_json::to_vec(&server_hello)
                    .map_err(|e| crate::Error::Protocol(format!("serialize ServerHello: {e}")))?;
                stream.write_raw_v2_frame(V2_FRAME_TYPE_SERVER_HELLO, 0, &json).await?;
                Ok((None, None))
            }
        }
        V2_FRAME_TYPE_MESSAGE => {
            Ok((Some(payload), None)) // this IS the first message payload
        }
        other => Err(crate::Error::Protocol(format!(
            "unexpected V2 frame type on accept: {other}"
        ))),
    }
}
