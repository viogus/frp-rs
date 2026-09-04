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

use std::borrow::Cow;
use std::str::FromStr;
use std::time::Duration;

use crate::base64::{decode as b64_decode, encode as b64_encode};
use rand::TryRng;
use ring::digest;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::crypto::AeadAlgorithm;
use crate::protocol::{
    V2_FRAME_TYPE_CLIENT_HELLO, V2_FRAME_TYPE_MESSAGE, V2_FRAME_TYPE_SERVER_HELLO,
};
use crate::transport::IoStream;

/// Timeout for V2 handshake reads.
///
/// Post-handshake read bound, matching `POST_HANDSHAKE_READ_TIMEOUT` (30s)
/// on the V1 paths. Go frp v0.70.1 applies a single `connReadTimeout = 10s`
/// deadline to the whole initial read phase, but 10s is too tight for the
/// pre-Login OIDC JWT fetch (fetched over the proxyURL after the handshake,
/// before Login — killed a >10s fetch in test_g2r_oidc_proxy), so frp-rs
/// deliberately hardens all post-magic reads to 30s. These reads are
/// post-magic-detection on every path (TCP/WS/KCP/QUIC):
/// `v2_handshake_server` first frame, `read_first_frame_after_handshake`,
/// and the client-side ServerHello read. The server accept paths wrap
/// handshake + first frame in an outer `timeout_at(post_deadline, …)` so
/// the per-read 30s does not stack with the magic-read timeout.
const V2_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

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
            let encoded = b64_encode(b);
            s.serialize_some(&encoded)
        }
        None => s.serialize_none(),
    }
}

fn base64_deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Vec<u8>>, D::Error> {
    let opt: Option<String> = Option::deserialize(d)?;
    match opt {
        Some(s) => {
            let bytes = b64_decode(&s).map_err(serde::de::Error::custom)?;
            Ok(Some(bytes))
        }
        None => Ok(None),
    }
}

fn base64_serialize_non_null<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
    let encoded = b64_encode(bytes);
    s.serialize_str(&encoded)
}

fn base64_deserialize_non_null<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
    let s: String = String::deserialize(d)?;
    b64_decode(&s).map_err(serde::de::Error::custom)
}

// ---------------------------------------------------------------------------
// Handshake JSON structures (matching Go frp wire.go)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BootstrapInfo {
    #[serde(default)]
    pub transport: Cow<'static, str>,
    #[serde(default)]
    pub tls: bool,
    #[serde(default, rename = "tcpMux")]
    pub tcp_mux: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MessageCapabilities {
    #[serde(default)]
    pub codecs: Vec<Cow<'static, str>>,
    /// UDPPacket payload codecs (Go frp v0.71.0: `udpPacketCodecs`).
    /// frp-rs advertises `binary-v1` like Go 0.71.0; when the server selects
    /// it, UDPPacket messages on V2 work connections use the compact binary
    /// codec (type 19) instead of JSON (type 13).
    #[serde(default, rename = "udpPacketCodecs")]
    pub udp_packet_codecs: Vec<Cow<'static, str>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CryptoCapabilities {
    #[serde(default)]
    pub algorithms: Vec<Cow<'static, str>>,
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
    pub codec: Cow<'static, str>,
    /// Selected UDPPacket codec (Go frp v0.71.0: `udpPacketCodec`).
    /// Empty when the peer did not advertise `binary-v1` (JSON fallback).
    #[serde(default, rename = "udpPacketCodec")]
    pub udp_packet_codec: Cow<'static, str>,
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
    /// Negotiated UDPPacket codec: `"binary-v1"` or empty (JSON fallback).
    /// Go frp v0.71.0 `udpPacketCodec` from ServerHello. Immutable for the
    /// lifetime of the session; the UDP/SUDP data plane selects the packet
    /// codec from this value.
    pub udp_packet_codec: String,
}

// ---------------------------------------------------------------------------
// Preferred algorithm order (matching Go frp PreferredAEADAlgorithms)
// ---------------------------------------------------------------------------

/// Return preferred AEAD algorithms in order. AES-256-GCM first on x86 with
/// AES-NI, otherwise XChaCha20-Poly1305 first. We always prefer AES-256-GCM
/// on modern hardware.
pub fn preferred_aead_algorithms() -> Vec<Cow<'static, str>> {
    #[cfg(feature = "chacha20")]
    {
        vec![
            AeadAlgorithm::Aes256Gcm.as_str().into(),
            AeadAlgorithm::XChaCha20Poly1305.as_str().into(),
        ]
    }
    #[cfg(not(feature = "chacha20"))]
    {
        vec![AeadAlgorithm::Aes256Gcm.as_str().into()]
    }
}

/// Select first algorithm from client list that we support.
pub fn select_aead_algorithm(client_algorithms: &[Cow<'static, str>]) -> Option<AeadAlgorithm> {
    for alg in client_algorithms {
        if let Ok(a) = AeadAlgorithm::from_str(alg) {
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
    pub fn new(transport: &'static str, tls: bool, tcp_mux: bool) -> Result<Self, crate::Error> {
        // Audit B2: OS-RNG failure surfaces as an error (this handshake is
        // already in a Result context) instead of aborting the process.
        let mut client_random = vec![0u8; CRYPTO_RANDOM_SIZE];
        rand::rngs::SysRng
            .try_fill_bytes(&mut client_random)
            .map_err(|e| crate::Error::Protocol(format!("SysRng failure: {e}").into()))?;

        Ok(Self {
            bootstrap: BootstrapInfo {
                transport: transport.into(),
                tls,
                tcp_mux,
            },
            capabilities: ClientCapabilities {
                message: MessageCapabilities {
                    codecs: vec!["json".into()],
                    // Advertise the UDP packet binary codec, matching Go frp
                    // v0.71.0's clientHelloWithCryptoRandom.
                    udp_packet_codecs: vec![crate::udp_binary::UDP_PACKET_CODEC_BINARY.into()],
                },
                crypto: CryptoCapabilities {
                    algorithms: preferred_aead_algorithms(),
                    client_random: Some(client_random),
                },
            },
        })
    }

    /// Build a ClientHello without crypto (for Rust↔Rust V2 without AEAD).
    pub fn new_without_crypto(transport: &'static str, tls: bool, tcp_mux: bool) -> Self {
        Self {
            bootstrap: BootstrapInfo {
                transport: transport.into(),
                tls,
                tcp_mux,
            },
            capabilities: ClientCapabilities {
                message: MessageCapabilities {
                    codecs: vec!["json".into()],
                    udp_packet_codecs: vec![crate::udp_binary::UDP_PACKET_CODEC_BINARY.into()],
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
                    codec: Cow::Borrowed("json"),
                    udp_packet_codec: Cow::Borrowed(""),
                },
                crypto: None,
            },
            error: None,
        }
    }

    /// Build a ServerHello with AEAD crypto selection.
    pub fn with_crypto(algorithm: AeadAlgorithm, server_random: Vec<u8>) -> Self {
        Self::with_crypto_and_udp(algorithm, server_random, "")
    }

    /// Build a ServerHello with AEAD crypto selection and a negotiated
    /// UDPPacket codec (`"binary-v1"` or empty for JSON fallback).
    pub fn with_crypto_and_udp(
        algorithm: AeadAlgorithm,
        server_random: Vec<u8>,
        udp_packet_codec: &str,
    ) -> Self {
        Self {
            selected: ServerSelection {
                message: MessageSelection {
                    codec: Cow::Borrowed("json"),
                    udp_packet_codec: Cow::Owned(udp_packet_codec.to_string()),
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
                    codec: Cow::Borrowed("json"),
                    udp_packet_codec: Cow::Borrowed(""),
                },
                crypto: None,
            },
            error: Some(err.into()),
        }
    }
}

/// Select a UDPPacket codec from the client's advertised list, mirroring Go
/// frp v0.71.0 `selectUDPPacketCodec`: `binary-v1` if advertised, else "".
pub fn select_udp_packet_codec(codecs: &[Cow<'static, str>]) -> &'static str {
    if codecs
        .iter()
        .any(|c| c == crate::udp_binary::UDP_PACKET_CODEC_BINARY)
    {
        crate::udp_binary::UDP_PACKET_CODEC_BINARY
    } else {
        ""
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
///
/// # Security note: transcript provides key confirmation, not handshake integrity
///
/// The transcript hash is included in the AEAD key derivation (via HKDF) so both
/// sides derive the same session keys only if they saw the same handshake messages.
/// This provides **key confirmation** — a mismatch produces different keys and the
/// first encrypted message will fail to decrypt.
///
/// However, the transcript itself is NOT MAC'd or signed. An active MITM could
/// modify ClientHello/ServerHello in transit without detection; the connection
/// would simply fail to decrypt (denial of service) rather than produce a
/// cryptographic alert. Handshake **integrity** (protection against modification)
/// depends on the outer TLS layer. When TLS is disabled, an active attacker can
/// disrupt the handshake but cannot impersonate either side without the pre-shared
/// key (used as the HKDF salt).
///
/// See also: `compute_session_key` which uses this transcript hash as HKDF info.
pub fn compute_transcript_hash(
    client_hello_payload: &[u8],
    server_hello_payload: &[u8],
) -> Vec<u8> {
    let mut ctx = digest::Context::new(&digest::SHA256);
    ctx.update(CRYPTO_TRANSCRIPT_LABEL.as_bytes());
    write_transcript_part(&mut ctx, "client hello", client_hello_payload);
    write_transcript_part(&mut ctx, "server hello", server_hello_payload);
    ctx.finish().as_ref().to_vec()
}

fn write_transcript_part(ctx: &mut digest::Context, label: &str, payload: &[u8]) {
    ctx.update(&[0u8]);
    ctx.update(label.as_bytes());
    ctx.update(&[0u8]);
    ctx.update(&(payload.len() as u64).to_be_bytes());
    ctx.update(payload);
}

// ---------------------------------------------------------------------------
// Client-side handshake (operates on IoStream)
// ---------------------------------------------------------------------------

/// V2 client handshake step 1: write ClientHello and return the serialized
/// payload byte vector for transcript hash computation.
///
/// After this call, the caller may send the Login message on `stream`
/// BEFORE reading ServerHello (matching Go frp's pipelined order:
/// ClientHello → Login → ServerHello → LoginResp).
pub async fn v2_handshake_client_send_hello(
    stream: &mut IoStream,
    transport: &'static str,
    tls: bool,
    tcp_mux: bool,
    with_crypto: bool,
) -> Result<Vec<u8>, crate::Error> {
    let hello = if with_crypto {
        ClientHello::new(transport, tls, tcp_mux)?
    } else {
        ClientHello::new_without_crypto(transport, tls, tcp_mux)
    };
    let client_hello_json = serde_json::to_vec(&hello)
        .map_err(|e| crate::Error::Protocol(format!("serialize ClientHello: {e}").into()))?;
    stream
        .write_raw_v2_frame(V2_FRAME_TYPE_CLIENT_HELLO, 0, &client_hello_json)
        .await?;
    Ok(client_hello_json)
}

/// V2 client handshake step 2: read and validate ServerHello, returning
/// CryptoContext if AEAD crypto was negotiated.
///
/// Must be called AFTER `v2_handshake_client_send_hello`. The caller
/// may send the Login message between the two calls.
///
/// `client_hello_json` must be the byte vector returned by
/// `v2_handshake_client_send_hello` (needed for transcript hash).
/// The remaining parameters are needed to re-derive the ClientHello
/// for algorithm-offer validation.
pub async fn v2_handshake_client_recv_hello(
    stream: &mut IoStream,
    client_hello_json: &[u8],
    transport: &'static str,
    tls: bool,
    tcp_mux: bool,
    with_crypto: bool,
) -> Result<Option<CryptoContext>, crate::Error> {
    // Re-derive hello for algorithm-offer validation.
    // NOTE: this re-creates ClientHello with fresh SysRng. Currently safe
    // because `preferred_aead_algorithms()` is deterministic. If algorithm
    // preferences ever become non-deterministic (e.g. runtime feature
    // detection), this validation will use a different algorithm list than
    // what was actually sent in the handshake — producing a transcript hash
    // mismatch. In that case, the client must cache the original
    // ClientHello struct or the algorithm list used during send.
    let hello = if with_crypto {
        ClientHello::new(transport, tls, tcp_mux)?
    } else {
        ClientHello::new_without_crypto(transport, tls, tcp_mux)
    };

    let (frame_type, _flags, server_hello_json) =
        tokio::time::timeout(V2_HANDSHAKE_TIMEOUT, stream.read_raw_v2_frame())
            .await
            .map_err(|_| crate::Error::Protocol("V2 handshake timeout".into()))??;
    match frame_type {
        V2_FRAME_TYPE_SERVER_HELLO => {
            let server_hello: ServerHello =
                serde_json::from_slice(&server_hello_json).map_err(|e| {
                    crate::Error::Protocol(format!("deserialize ServerHello: {e}").into())
                })?;
            if let Some(err) = server_hello.error {
                return Err(crate::Error::Protocol(
                    format!("ServerHello error: {err}").into(),
                ));
            }
            if server_hello.selected.message.codec != "json" {
                return Err(crate::Error::Protocol(
                    format!(
                        "server selected unsupported codec: {}",
                        server_hello.selected.message.codec
                    )
                    .into(),
                ));
            }
            // Validate the negotiated UDPPacket codec (Go frp v0.71.0
            // ValidateServerHelloForClient): it must be empty or `binary-v1`,
            // and if set it must have been advertised by us.
            let udp_packet_codec = server_hello.selected.message.udp_packet_codec.to_string();
            if !udp_packet_codec.is_empty() {
                if udp_packet_codec != crate::udp_binary::UDP_PACKET_CODEC_BINARY {
                    return Err(crate::Error::Protocol(
                        format!("server selected unsupported UDP packet codec: {udp_packet_codec}")
                            .into(),
                    ));
                }
                if !hello
                    .capabilities
                    .message
                    .udp_packet_codecs
                    .iter()
                    .any(|c| c == &udp_packet_codec)
                {
                    return Err(crate::Error::Protocol(
                        format!(
                            "server selected UDP packet codec not advertised by client: {udp_packet_codec}"
                        )
                        .into(),
                    ));
                }
            }

            // If server selected crypto, validate and build context
            if let Some(ref crypto_sel) = server_hello.selected.crypto {
                let algorithm = AeadAlgorithm::from_str(&crypto_sel.algorithm).map_err(|_| {
                    crate::Error::Protocol(
                        format!(
                            "server selected unknown algorithm: {}",
                            crypto_sel.algorithm
                        )
                        .into(),
                    )
                })?;
                if crypto_sel.server_random.len() != CRYPTO_RANDOM_SIZE {
                    return Err(crate::Error::Protocol(
                        format!(
                            "invalid server random length: {}",
                            crypto_sel.server_random.len()
                        )
                        .into(),
                    ));
                }
                // Validate server selected algo was in our offer
                let offered = &hello.capabilities.crypto.algorithms;
                if !offered
                    .iter()
                    .any(|a| AeadAlgorithm::from_str(a) == Ok(algorithm))
                {
                    return Err(crate::Error::Protocol(
                        format!(
                            "server selected algorithm not offered by client: {}",
                            crypto_sel.algorithm
                        )
                        .into(),
                    ));
                }

                let transcript_hash =
                    compute_transcript_hash(client_hello_json, &server_hello_json);
                Ok(Some(CryptoContext {
                    algorithm,
                    transcript_hash,
                    udp_packet_codec,
                }))
            } else {
                // Round-8 blocker: Go has no "no crypto selected" path —
                // ValidateServerHelloForClient (pkg/proto/wire/crypto.go)
                // fails closed on an empty algorithm ("unknown selected
                // crypto algorithm"). When we proposed crypto and the
                // server answered with no selection, fail instead of
                // silently downgrading the whole V2 session to plaintext.
                // Only a client that never proposed crypto
                // (with_crypto=false, Rust↔Rust plain V2) accepts None.
                if with_crypto {
                    return Err(crate::Error::Protocol(
                        "server did not select crypto although client proposed it".into(),
                    ));
                }
                Ok(None)
            }
        }
        V2_FRAME_TYPE_MESSAGE => Err(crate::Error::Protocol(
            "server skipped ServerHello — unexpected for V2 client".into(),
        )),
        other => Err(crate::Error::Protocol(
            format!("unexpected V2 frame type during handshake: {other}").into(),
        )),
    }
}

/// Perform V2 client handshake after writing magic bytes.
///
/// Equivalent to calling `v2_handshake_client_send_hello` then
/// `v2_handshake_client_recv_hello` sequentially (no pipelining).
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
    transport: &'static str,
    tls: bool,
    tcp_mux: bool,
    with_crypto: bool,
) -> Result<Option<CryptoContext>, crate::Error> {
    let client_hello_json =
        v2_handshake_client_send_hello(stream, transport, tls, tcp_mux, with_crypto).await?;
    v2_handshake_client_recv_hello(
        stream,
        &client_hello_json,
        transport,
        tls,
        tcp_mux,
        with_crypto,
    )
    .await
}

// ---------------------------------------------------------------------------
// Server-side handshake (operates on IoStream)
// ---------------------------------------------------------------------------

/// Read the first message frame after a ClientHello-based V2 handshake,
/// bounded by the same `V2_HANDSHAKE_TIMEOUT` (30s) as the handshake itself.
///
/// `v2_handshake_server` returns `Ok((None, crypto_ctx))` after it processed a
/// ClientHello; the caller must then read the next frame (the Login message)
/// itself. This helper wraps that read in `V2_HANDSHAKE_TIMEOUT` so a peer that
/// completes ClientHello but never sends Login cannot pin the task and file
/// descriptor forever. 30s (not Go's 10s `connReadTimeout`) because the
/// pre-Login OIDC JWT fetch can exceed 10s — see the constant's doc comment.
///
/// Returns the same tuple as `IoStream::read_raw_v2_frame`:
/// `(frame_type, flags, payload_bytes)`.
pub async fn read_first_frame_after_handshake(
    stream: &mut IoStream,
) -> Result<(u16, u16, Vec<u8>), crate::Error> {
    tokio::time::timeout(V2_HANDSHAKE_TIMEOUT, stream.read_raw_v2_frame())
        .await
        .map_err(|_| {
            crate::Error::Protocol("V2 handshake timeout waiting for first message".into())
        })?
}

/// Handle V2 server handshake: read first frame, respond if ClientHello.
///
/// Returns `Ok((None, Some(crypto_ctx)))` if ClientHello was handled with crypto,
/// `Ok((Some(payload), None))` if the first frame was already a Message (type=16).
/// A ClientHello offering no supported AEAD algorithm is rejected with a
/// ServerHello carrying the error (Go parity — see the negotiation branch
/// below), so the no-crypto `Ok((None, None))` case no longer exists.
///
/// `payload` is the raw V2 message payload: [type_id: u16 BE][JSON bytes].
///
/// When the first frame was a ClientHello (return `Ok((None, _))`), the caller
/// MUST use [`read_first_frame_after_handshake`] (not a bare
/// `read_raw_v2_frame`) to read the next frame, so the read stays bounded by
/// `V2_HANDSHAKE_TIMEOUT` (30s — the post-handshake deadline, matching the
/// V1 paths; see the constant's doc comment).
pub async fn v2_handshake_server(
    stream: &mut IoStream,
) -> Result<(Option<Vec<u8>>, Option<CryptoContext>), crate::Error> {
    let (frame_type, _flags, payload) =
        tokio::time::timeout(V2_HANDSHAKE_TIMEOUT, stream.read_raw_v2_frame())
            .await
            .map_err(|_| crate::Error::Protocol("V2 handshake timeout".into()))??;

    match frame_type {
        V2_FRAME_TYPE_CLIENT_HELLO => {
            let client_hello: ClientHello = serde_json::from_slice(&payload).map_err(|e| {
                crate::Error::Protocol(format!("deserialize ClientHello: {e}").into())
            })?;

            if !client_hello
                .capabilities
                .message
                .codecs
                .iter()
                .any(|c| c == "json")
            {
                let err_hello = ServerHello::with_error("unsupported message codec");
                let json = serde_json::to_vec(&err_hello).map_err(|e| {
                    crate::Error::Protocol(format!("serialize ServerHello: {e}").into())
                })?;
                stream
                    .write_raw_v2_frame(V2_FRAME_TYPE_SERVER_HELLO, 0, &json)
                    .await?;
                return Err(crate::Error::Protocol(
                    "ClientHello rejected: unsupported codec".into(),
                ));
            }

            // Try to negotiate AEAD crypto
            let client_algorithms = &client_hello.capabilities.crypto.algorithms;
            tracing::debug!(client_algorithms = ?client_algorithms, client_random_present = ?client_hello.capabilities.crypto.client_random.as_ref().map(|_| "present"), "[V2-HS] ClientHello algorithms: {:?}, client_random: {:?}",
                client_algorithms,
                client_hello.capabilities.crypto.client_random.as_ref().map(|_| "present"));
            if let Some(algorithm) = select_aead_algorithm(client_algorithms) {
                tracing::debug!(algorithm = ?algorithm, "[V2-HS] Selected algorithm: {:?}", algorithm);
                // Validate client_random
                let client_random = client_hello
                    .capabilities
                    .crypto
                    .client_random
                    .as_ref()
                    .ok_or_else(|| {
                        crate::Error::Protocol(
                            "ClientHello crypto algorithms present but no client_random".into(),
                        )
                    })?;
                if client_random.len() != CRYPTO_RANDOM_SIZE {
                    return Err(crate::Error::Protocol(
                        format!("invalid client random length: {}", client_random.len()).into(),
                    ));
                }

                let mut server_random = vec![0u8; CRYPTO_RANDOM_SIZE];
                // Audit B2: OS-RNG failure propagates as a handshake error
                // (whole-process abort was the alternative under
                // panic=abort).
                rand::rngs::SysRng
                    .try_fill_bytes(&mut server_random)
                    .map_err(|e| crate::Error::Protocol(format!("SysRng failure: {e}").into()))?;
                // Negotiate the UDPPacket codec: mirror Go frp v0.71.0
                // NewServerHello (selectUDPPacketCodec over client's offers).
                let udp_codec =
                    select_udp_packet_codec(&client_hello.capabilities.message.udp_packet_codecs);
                let server_hello =
                    ServerHello::with_crypto_and_udp(algorithm, server_random, udp_codec);

                let server_hello_json = serde_json::to_vec(&server_hello).map_err(|e| {
                    crate::Error::Protocol(format!("serialize ServerHello: {e}").into())
                })?;
                stream
                    .write_raw_v2_frame(V2_FRAME_TYPE_SERVER_HELLO, 0, &server_hello_json)
                    .await?;

                let transcript_hash = compute_transcript_hash(&payload, &server_hello_json);
                Ok((
                    None,
                    Some(CryptoContext {
                        algorithm,
                        transcript_hash,
                        udp_packet_codec: udp_codec.to_string(),
                    }),
                ))
            } else {
                // Go's NewServerHello rejects a ClientHello offering no
                // supported AEAD algorithm ("no supported crypto algorithm",
                // pkg/proto/wire/crypto.go:60-63); the server sends a
                // ServerHello carrying the error before tearing down the
                // connection (server/service.go handleClientHello). Mirror
                // that rejection (same shape as the unsupported-codec path
                // above) instead of proceeding without crypto. Rust↔Rust-only
                // behavior: Rust clients always offer aes-256-gcm
                // (ClientHello::new → preferred_aead_algorithms), so the Go
                // compat matrix is unaffected.
                tracing::debug!(client_algorithms = ?client_algorithms, "[V2-HS] No supported crypto algorithm (client offered {:?})", client_algorithms);
                let err_hello = ServerHello::with_error("no supported crypto algorithm");
                let json = serde_json::to_vec(&err_hello).map_err(|e| {
                    crate::Error::Protocol(format!("serialize ServerHello: {e}").into())
                })?;
                stream
                    .write_raw_v2_frame(V2_FRAME_TYPE_SERVER_HELLO, 0, &json)
                    .await?;
                Err(crate::Error::Protocol(
                    "ClientHello rejected: no supported crypto algorithm".into(),
                ))
            }
        }
        V2_FRAME_TYPE_MESSAGE => {
            Ok((Some(payload), None)) // this IS the first message payload
        }
        other => Err(crate::Error::Protocol(
            format!("unexpected V2 frame type on accept: {other}").into(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::digest;

    /// Build a transcript part from the spec:
    /// part(label, payload) = "\x00" || label || "\x00" || BE64(len(payload)) || payload
    fn make_part(label: &str, payload: &[u8]) -> Vec<u8> {
        let mut part = Vec::new();
        part.push(0u8);
        part.extend_from_slice(label.as_bytes());
        part.push(0u8);
        part.extend_from_slice(&(payload.len() as u64).to_be_bytes());
        part.extend_from_slice(payload);
        part
    }

    /// Compute expected transcript hash directly from the spec.
    fn expected_transcript_hash(ch: &[u8], sh: &[u8]) -> Vec<u8> {
        let mut ctx = digest::Context::new(&digest::SHA256);
        ctx.update(CRYPTO_TRANSCRIPT_LABEL.as_bytes());
        ctx.update(&make_part("client hello", ch));
        ctx.update(&make_part("server hello", sh));
        ctx.finish().as_ref().to_vec()
    }

    #[test]
    fn transcript_hash_known_payloads() {
        let ch = br#"{"test":"client"}"#;
        let sh = br#"{"test":"server"}"#;
        let result = compute_transcript_hash(ch, sh);
        let expected = expected_transcript_hash(ch, sh);
        assert_eq!(result, expected);
    }

    #[test]
    fn transcript_hash_empty_payloads() {
        let result = compute_transcript_hash(b"", b"");
        let expected = expected_transcript_hash(b"", b"");
        assert_eq!(result, expected);
    }

    #[test]
    fn transcript_hash_asymmetric_payloads() {
        let ch = b"client payload";
        let sh = br#"{"error":"rejected"}"#;
        let result = compute_transcript_hash(ch, sh);
        let expected = expected_transcript_hash(ch, sh);
        assert_eq!(result, expected);
    }

    #[test]
    fn transcript_hash_large_payloads() {
        let ch = vec![b'C'; 4096];
        let sh = vec![b'S'; 4096];
        let result = compute_transcript_hash(&ch, &sh);
        let expected = expected_transcript_hash(&ch, &sh);
        assert_eq!(result, expected);
    }

    // --- UDP packet codec negotiation (Go frp v0.71.0) ---

    #[test]
    fn client_hello_advertises_binary_udp_codec() {
        let hello = ClientHello::new("tcp", false, true).unwrap();
        assert_eq!(
            hello.capabilities.message.udp_packet_codecs,
            vec![std::borrow::Cow::Borrowed(
                crate::udp_binary::UDP_PACKET_CODEC_BINARY
            )]
        );
        // Wire name is camelCase udpPacketCodecs (Go field name).
        let json = serde_json::to_string(&hello).unwrap();
        assert!(json.contains("\"udpPacketCodecs\""), "got: {json}");
    }

    #[test]
    fn select_udp_packet_codec_prefers_binary_and_falls_back_empty() {
        use std::borrow::Cow;
        assert_eq!(
            select_udp_packet_codec(&[Cow::Borrowed(crate::udp_binary::UDP_PACKET_CODEC_BINARY)]),
            crate::udp_binary::UDP_PACKET_CODEC_BINARY
        );
        // Legacy client without the capability → empty (JSON fallback).
        assert_eq!(select_udp_packet_codec(&[]), "");
        // Unknown codec offer → empty (Go selectUDPPacketCodec only picks binary-v1).
        assert_eq!(select_udp_packet_codec(&[Cow::Borrowed("unknown")]), "");
    }

    #[test]
    fn server_hello_carries_udp_packet_codec_on_wire() {
        let hello = ServerHello::with_crypto_and_udp(
            AeadAlgorithm::Aes256Gcm,
            vec![0u8; CRYPTO_RANDOM_SIZE],
            crate::udp_binary::UDP_PACKET_CODEC_BINARY,
        );
        let json = serde_json::to_string(&hello).unwrap();
        assert!(
            json.contains("\"udpPacketCodec\":\"binary-v1\""),
            "got: {json}"
        );
        // Empty codec is serialized as "" (Go omits it, but "" is tolerated
        // by Go's JSON unmarshal and by our own validation).
        let plain = ServerHello::default_ok();
        let json = serde_json::to_string(&plain).unwrap();
        assert!(json.contains("\"udpPacketCodec\":\"\""), "got: {json}");
    }

    #[test]
    fn crypto_context_defaults_empty_udp_codec() {
        // Construction sites that don't negotiate a codec must default to
        // empty (JSON fallback) so the data plane never misbehaves.
        let ctx = CryptoContext {
            algorithm: AeadAlgorithm::Aes256Gcm,
            transcript_hash: vec![1, 2, 3],
            udp_packet_codec: String::new(),
        };
        assert!(ctx.udp_packet_codec.is_empty());
    }

    #[tokio::test]
    async fn server_rejects_client_hello_without_supported_crypto() {
        // Go's NewServerHello errors a ClientHello offering no supported AEAD
        // algorithm ("no supported crypto algorithm", crypto.go:60-63) and the
        // server sends a ServerHello carrying the error before tearing down
        // (server/service.go handleClientHello). The Rust server must reject
        // with a ServerHello error, not proceed without crypto (review
        // finding W2).
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut io = IoStream::Tcp(stream);
            v2_handshake_server(&mut io).await
        });

        let client = tokio::net::TcpStream::connect(addr).await.unwrap();
        let mut client_io = IoStream::Tcp(client);
        let mut hello = ClientHello::new("tcp", false, true).unwrap();
        hello.capabilities.crypto.algorithms = vec![Cow::Borrowed("unsupported-alg")];
        let hello_json = serde_json::to_vec(&hello).unwrap();
        client_io
            .write_raw_v2_frame(V2_FRAME_TYPE_CLIENT_HELLO, 0, &hello_json)
            .await
            .unwrap();

        // Server must answer with a ServerHello carrying the error, not a
        // crypto-less success.
        let (frame_type, _flags, payload) = client_io.read_raw_v2_frame().await.unwrap();
        assert_eq!(frame_type, V2_FRAME_TYPE_SERVER_HELLO);
        let server_hello: ServerHello = serde_json::from_slice(&payload).unwrap();
        assert_eq!(
            server_hello.error.as_deref(),
            Some("no supported crypto algorithm")
        );
        assert!(server_hello.selected.crypto.is_none());

        let result = server.await.unwrap();
        assert!(
            matches!(result, Err(crate::Error::Protocol(_))),
            "server must reject the ClientHello, got {result:?}"
        );
    }

    #[tokio::test]
    async fn client_rejects_server_hello_without_crypto_when_crypto_was_proposed() {
        // Round-8 blocker: a server answering a crypto-proposing ClientHello
        // with no crypto selection used to pass `Ok(None)` — the session
        // silently downgraded to plaintext. Go's ValidateServerHelloForClient
        // (pkg/proto/wire/crypto.go) has no such path and fails closed.
        // The client must Err; only a client that never proposed crypto
        // (with_crypto=false) may accept None.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut io = IoStream::Tcp(stream);
            let (frame_type, _flags, _payload) = io.read_raw_v2_frame().await.unwrap();
            assert_eq!(frame_type, V2_FRAME_TYPE_CLIENT_HELLO);
            // Answer with a ServerHello that selects NO crypto at all.
            let sh_json = serde_json::to_vec(&ServerHello::default_ok()).unwrap();
            io.write_raw_v2_frame(V2_FRAME_TYPE_SERVER_HELLO, 0, &sh_json)
                .await
                .unwrap();
        });

        let client = tokio::net::TcpStream::connect(addr).await.unwrap();
        let mut client_io = IoStream::Tcp(client);
        let hello_json = v2_handshake_client_send_hello(&mut client_io, "tcp", false, true, true)
            .await
            .unwrap();
        let result =
            v2_handshake_client_recv_hello(&mut client_io, &hello_json, "tcp", false, true, true)
                .await;
        assert!(
            matches!(result, Err(crate::Error::Protocol(_))),
            "crypto-proposing client must reject a crypto-less ServerHello, got {result:?}"
        );
        server.await.unwrap();
    }

    #[tokio::test]
    async fn client_without_crypto_offer_accepts_crypto_less_server_hello() {
        // Rust↔Rust plain V2 (with_crypto=false): no crypto was proposed,
        // so a ServerHello without a crypto selection is the expected
        // handshake — Ok(None), not an error.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut io = IoStream::Tcp(stream);
            let (frame_type, _flags, _payload) = io.read_raw_v2_frame().await.unwrap();
            assert_eq!(frame_type, V2_FRAME_TYPE_CLIENT_HELLO);
            let sh_json = serde_json::to_vec(&ServerHello::default_ok()).unwrap();
            io.write_raw_v2_frame(V2_FRAME_TYPE_SERVER_HELLO, 0, &sh_json)
                .await
                .unwrap();
        });

        let client = tokio::net::TcpStream::connect(addr).await.unwrap();
        let mut client_io = IoStream::Tcp(client);
        let hello_json = v2_handshake_client_send_hello(&mut client_io, "tcp", false, true, false)
            .await
            .unwrap();
        let result =
            v2_handshake_client_recv_hello(&mut client_io, &hello_json, "tcp", false, true, false)
                .await;
        match result {
            Ok(None) => {}
            other => panic!("plain-V2 client must accept a crypto-less ServerHello, got {other:?}"),
        }
        server.await.unwrap();
    }
}
