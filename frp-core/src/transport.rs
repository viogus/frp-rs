use std::io;
#[allow(unused_imports)] // unused in the micro (no-feature) build
use std::net::SocketAddr;
use std::pin::Pin;
use std::time::Duration;

#[cfg(feature = "kcp")]
use crate::kcp::KcpStream;
#[cfg(feature = "quic")]
use crate::quic::QuicStream;
#[cfg(any(feature = "tls", feature = "websocket"))]
use crate::TransportError;
#[cfg(feature = "websocket")]
use futures_util::{sink::Sink, Stream};
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
#[cfg(feature = "websocket")]
use tokio_tungstenite::tungstenite::Message;
#[cfg(feature = "websocket")]
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};

#[cfg(feature = "tls")]
use std::sync::Arc;
#[cfg(feature = "tls")]
use tokio_rustls::TlsAcceptor;
#[cfg(feature = "tls")]
use tokio_rustls::TlsConnector;

use crate::mux::YamuxStream;

#[cfg(feature = "tls")]
use rustls_platform_verifier::BuilderVerifierExt;
#[cfg(feature = "tls")]
use rustls_platform_verifier::ConfigVerifierExt;

/// Go frp v0.69.1 FRPTLSHeadByte — sent before TLS handshake to allow
/// mixed TLS/plaintext on the same port.
pub const FRP_TLS_HEAD_BYTE: u8 = 0x17;
/// Standard TLS ClientHello record content type (0x16).
/// Go frp v0.69.1 clients may send this directly without the 0x17 prefix.
pub const FRP_TLS_DIRECT_BYTE: u8 = 0x16;

/// Result of peeking the first byte on the main accept port.
#[derive(Debug, PartialEq)]
pub enum ConnectionType {
    /// First byte: 0x17 (Go frp prefix) or 0x16 (standard TLS ClientHello).
    /// The caller must check the byte to decide whether to skip it before TLS handshake.
    Tls(u8),
    /// 'G' (GET) → HTTP WebSocket upgrade
    #[cfg(feature = "websocket")]
    WebSocket,
    /// V1 type byte → plain frp protocol (the byte is the V1 message type)
    V1(u8),
    /// 0x46 ('F') → V2 protocol (magic bytes: FRP\0\x02\r\n)
    V2,
}

/// The WebSocket path used by frp (matching the Go version).
pub const FRP_WEBSOCKET_PATH: &str = "/~!frp";

/// Maximum WebSocket frame payload accepted by the raw decoder. The V2
/// framing layer permits 64 KiB messages, so the transport must not clamp
/// below that; the V1 10 KiB limit stays enforced by `protocol.rs`.
/// +128 bytes covers the V2 AEAD overhead (AES-256-GCM tag + nonce) so an
/// encrypted V2 frame at the payload cap is not rejected by the transport.
#[cfg(feature = "websocket")]
const MAX_WS_FRAME_PAYLOAD: u64 = crate::protocol::V2_MAX_FRAME_PAYLOAD as u64 + 128;

/// Transport protocol variant.
#[derive(Debug, Clone, PartialEq)]
pub enum TransportProtocol {
    Tcp,
    #[cfg(feature = "kcp")]
    Kcp,
    #[cfg(feature = "websocket")]
    WebSocket,
    #[cfg(feature = "websocket")]
    Wss,
    #[cfg(feature = "quic")]
    Quic,
}

impl std::str::FromStr for TransportProtocol {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s.to_lowercase().as_str() {
            #[cfg(feature = "kcp")]
            "kcp" => TransportProtocol::Kcp,
            #[cfg(feature = "websocket")]
            "websocket" | "ws" => TransportProtocol::WebSocket,
            #[cfg(feature = "websocket")]
            "wss" => TransportProtocol::Wss,
            #[cfg(feature = "quic")]
            "quic" => TransportProtocol::Quic,
            "tcp" => TransportProtocol::Tcp,
            _ => return Err(()),
        })
    }
}

// ---------------------------------------------------------------
// WsByteStream — WebSocket-to-byte-stream adapter
// Defined BEFORE IoStream so IoStream can hold it as a variant.
// ---------------------------------------------------------------

/// A WebSocket-to-byte-stream adapter that implements AsyncRead/AsyncWrite.
/// Converts between WebSocket messages and a byte stream suitable
/// for use with the V1 protocol functions.
///
/// Two modes:
/// - Tungstenite: client side (binary frames, RFC 6455 compliant)
/// - Raw: server side (manual framing, tolerates text frames for
///   backward compatibility with Go frp < v0.70.1)
#[cfg(feature = "websocket")]
pub struct WsByteStream {
    inner: WsInner,
    read_buf: Vec<u8>,
    read_pos: usize,
    /// Write buffer for the Raw variant (frame bytes not yet flushed).
    write_buf: Vec<u8>,
    write_pos: usize,
    needs_flush: bool,
    /// When true, outgoing frames are masked (RFC 6455 §5.3 — client requirement).
    client_mode: bool,
    /// State machine for incremental WebSocket frame reads (Raw variant).
    raw_read_state: RawReadState,
    /// Frame opcode from the last fully-read WS header.
    raw_frame_opcode: u8,
    /// Whether the last fully-read WS header had the MASK bit set.
    raw_frame_masked: bool,
    /// Masking key from the last fully-read WS header.
    raw_frame_mask_key: [u8; 4],
    /// Payload length from the last fully-read WS header (after extended length parsing).
    raw_frame_payload_len: u64,
}

#[cfg(feature = "websocket")]
enum WsInner {
    Tungstenite(Pin<Box<WebSocketStream<MaybeTlsStream<TcpStream>>>>),
    /// Raw stream post-upgrade. Manual WebSocket frame handling.
    /// Type-erased to support both plain TCP and TLS-wrapped streams.
    Raw(Box<dyn AsyncReadWrite>),
}

#[cfg(feature = "websocket")]
impl WsInner {
    /// Poll-write logic for the Raw variant.
    /// Takes buffer state as separate params to avoid borrow conflicts
    /// with the outer WsByteStream struct — the match on WsInner variants
    /// borrows self (the WsInner), not the buffer fields.
    fn poll_write_raw(
        raw: &mut Box<dyn AsyncReadWrite>,
        cx: &mut Context<'_>,
        buf: &[u8],
        write_buf: &mut Vec<u8>,
        write_pos: &mut usize,
        needs_flush: &mut bool,
        new_frame: Option<Vec<u8>>,
    ) -> Poll<io::Result<usize>> {
        // Build new frame if provided (pre-built before the match)
        if let Some(frame) = new_frame {
            match Pin::new(raw.as_mut()).poll_write(cx, &frame) {
                Poll::Ready(Ok(n)) if n >= frame.len() => {
                    // Full write — success
                    return Poll::Ready(Ok(buf.len()));
                }
                Poll::Ready(Ok(n)) => {
                    *write_buf = frame;
                    *write_pos = n;
                    *needs_flush = true;
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => {
                    *write_buf = frame;
                    *write_pos = 0;
                    *needs_flush = true;
                    return Poll::Pending;
                }
            }
        }
        // Flush pending write buffer
        if *needs_flush {
            let remaining = &write_buf[*write_pos..];
            match Pin::new(raw.as_mut()).poll_write(cx, remaining) {
                Poll::Ready(Ok(n)) => {
                    *write_pos += n;
                    if *write_pos >= write_buf.len() {
                        *write_pos = 0;
                        *needs_flush = false;
                        Poll::Ready(Ok(buf.len()))
                    } else {
                        cx.waker().wake_by_ref();
                        Poll::Pending
                    }
                }
                Poll::Ready(Err(e)) => {
                    *needs_flush = false;
                    Poll::Ready(Err(e))
                }
                Poll::Pending => Poll::Pending,
            }
        } else {
            Poll::Ready(Ok(0))
        }
    }

    /// Build a WebSocket data frame (FIN + BINARY opcode) for the Raw path.
    fn build_frame(buf: &[u8], client_mode: bool) -> Vec<u8> {
        let len = buf.len();
        let mut frame = Vec::with_capacity(len + 14); // header + mask + payload
        frame.push(0x82); // FIN + BINARY opcode
        if client_mode {
            // Client MUST mask frames per RFC 6455 §5.3
            if len < 126 {
                frame.push(0x80 | len as u8);
            } else if len <= 65535 {
                frame.push(0x80 | 126);
                frame.extend_from_slice(&(len as u16).to_be_bytes());
            } else {
                frame.push(0x80 | 127);
                frame.extend_from_slice(&(len as u64).to_be_bytes());
            }
            let mask: [u8; 4] = rand::random();
            frame.extend_from_slice(&mask);
            for i in 0..len {
                frame.push(buf[i] ^ mask[i % 4]);
            }
        } else {
            // Server MUST NOT mask frames per RFC 6455 §5.1
            if len < 126 {
                frame.push(len as u8);
            } else if len <= 65535 {
                frame.push(126);
                frame.extend_from_slice(&(len as u16).to_be_bytes());
            } else {
                frame.push(127);
                frame.extend_from_slice(&(len as u64).to_be_bytes());
            }
            frame.extend_from_slice(buf);
        }
        frame
    }
}

/// State machine for incremental WebSocket frame reads on Raw streams.
/// Resumes partial reads across async yield points so frame header/mask/payload
/// parsing does not lose progress when the underlying stream returns Pending.
#[cfg(feature = "websocket")]
enum RawReadState {
    Idle,
    ReadingHeader { head: [u8; 2], filled: usize },
    ReadingExtendedLen2 { ext: [u8; 2], filled: usize },
    ReadingExtendedLen8 { ext: [u8; 8], filled: usize },
    ReadingMaskKey { mask_key: [u8; 4], filled: usize },
    ReadingPayload { payload: Vec<u8>, filled: usize },
}

/// Dispatch a fully-read WebSocket frame payload (Raw path).
/// Resets `raw_read_state` to Idle. Returns Poll::Pending for ping/pong
/// so the caller loops back to read the next frame.
#[cfg(feature = "websocket")]
#[allow(clippy::too_many_arguments)]
fn dispatch_raw_frame(
    read_buf: &mut Vec<u8>,
    read_pos: &mut usize,
    raw_read_state: &mut RawReadState,
    opcode: u8,
    raw: &mut Box<dyn AsyncReadWrite>,
    cx: &mut Context<'_>,
    buf: &mut ReadBuf<'_>,
    payload: &[u8],
) -> Poll<io::Result<()>> {
    *raw_read_state = RawReadState::Idle;
    match opcode {
        0x00..=0x02 => {
            let n = payload.len().min(buf.remaining());
            buf.put_slice(&payload[..n]);
            if n < payload.len() {
                *read_buf = payload[n..].to_vec();
                *read_pos = 0;
            }
            Poll::Ready(Ok(()))
        }
        0x08 => {
            let _ = Pin::new(raw.as_mut()).poll_write(cx, &[0x88, 0x02, 0x03, 0xe8]);
            Poll::Ready(Ok(()))
        }
        0x09 => {
            // RFC 6455 §5.5: control frame payload MUST be ≤125 bytes.
            // Extended length encoding is disallowed for control frames.
            let pong_payload = if payload.len() > 125 {
                tracing::warn!(
                    "WS pong payload {} bytes exceeds 125-byte limit, truncating",
                    payload.len()
                );
                &payload[..125]
            } else {
                payload
            };
            let mut pong = vec![0x8a, pong_payload.len() as u8];
            pong.extend_from_slice(pong_payload);
            if let Poll::Ready(Err(e)) = Pin::new(raw.as_mut()).poll_write(cx, &pong) {
                tracing::debug!(error = %e, "WS pong write failed");
            }
            cx.waker().wake_by_ref();
            Poll::Pending
        }
        0x0a => {
            cx.waker().wake_by_ref();
            Poll::Pending
        }
        _ => Poll::Ready(Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unexpected WS opcode: {opcode:#x}"),
        ))),
    }
}

#[cfg(feature = "websocket")]
impl WsByteStream {
    pub fn new(ws: WebSocketStream<MaybeTlsStream<TcpStream>>) -> Self {
        Self {
            inner: WsInner::Tungstenite(Box::pin(ws)),
            read_buf: Vec::new(),
            read_pos: 0,
            write_buf: Vec::new(),
            write_pos: 0,
            needs_flush: false,
            client_mode: false,
            raw_read_state: RawReadState::Idle,
            raw_frame_opcode: 0,
            raw_frame_masked: false,
            raw_frame_mask_key: [0u8; 4],
            raw_frame_payload_len: 0,
        }
    }

    /// Create from a raw stream after manual WebSocket upgrade.
    /// Used on the server accept path for Go frp compat.
    /// When `client_mode` is true, outgoing frames are masked per RFC 6455 §5.3.
    pub fn from_raw(stream: Box<dyn AsyncReadWrite>, client_mode: bool) -> Self {
        Self {
            inner: WsInner::Raw(stream),
            read_buf: Vec::new(),
            read_pos: 0,
            write_buf: Vec::new(),
            write_pos: 0,
            needs_flush: false,
            client_mode,
            raw_read_state: RawReadState::Idle,
            raw_frame_opcode: 0,
            raw_frame_masked: false,
            raw_frame_mask_key: [0u8; 4],
            raw_frame_payload_len: 0,
        }
    }

    /// Consume the adapter and return the underlying WebSocket stream.
    /// Panics if called on a Raw variant.
    pub fn into_inner(self) -> WebSocketStream<MaybeTlsStream<TcpStream>> {
        match self.inner {
            WsInner::Tungstenite(ws) => *Pin::into_inner(ws),
            WsInner::Raw(_) => panic!("into_inner called on Raw variant — Raw stores Box<dyn AsyncReadWrite>, not WebSocketStream"),
        }
    }
}

#[cfg(feature = "websocket")]
impl AsyncRead for WsByteStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // If we have buffered data, return it
        if self.read_pos < self.read_buf.len() {
            let available = &self.read_buf[self.read_pos..];
            let len = available.len().min(buf.remaining());
            buf.put_slice(&available[..len]);
            self.read_pos += len;
            if self.read_pos >= self.read_buf.len() {
                self.read_buf.clear();
                self.read_pos = 0;
            }
            return Poll::Ready(Ok(()));
        }

        // Destructure to get independent field borrows, avoiding borrow conflicts
        // between inner (Raw) and the raw_read_state / raw_frame_* fields.
        // &mut *self is safe because WsByteStream is Unpin (all fields are Unpin),
        // so Pin<&mut Self> implements DerefMut.
        let this = &mut *self;
        let WsByteStream {
            inner,
            read_buf,
            read_pos,
            write_buf: _,
            write_pos: _,
            needs_flush: _,
            client_mode: _,
            raw_read_state,
            raw_frame_opcode,
            raw_frame_masked,
            raw_frame_mask_key,
            raw_frame_payload_len,
        } = this;

        match inner {
            WsInner::Tungstenite(inner) => loop {
                match inner.as_mut().poll_next(cx) {
                    Poll::Ready(Some(Ok(Message::Binary(data)))) => {
                        let len = data.len().min(buf.remaining());
                        buf.put_slice(&data[..len]);
                        if len < data.len() {
                            *read_buf = data[len..].to_vec();
                            *read_pos = 0;
                        }
                        return Poll::Ready(Ok(()));
                    }
                    Poll::Ready(Some(Ok(Message::Text(text)))) => {
                        let data = text.into_bytes();
                        let len = data.len().min(buf.remaining());
                        buf.put_slice(&data[..len]);
                        if len < data.len() {
                            *read_buf = data[len..].to_vec();
                            *read_pos = 0;
                        }
                        return Poll::Ready(Ok(()));
                    }
                    Poll::Ready(Some(Ok(Message::Ping(_)))) => continue,
                    Poll::Ready(Some(Ok(Message::Close(_)))) => return Poll::Ready(Ok(())),
                    Poll::Ready(Some(Ok(_))) => continue,
                    Poll::Ready(Some(Err(e))) => {
                        return Poll::Ready(Err(io::Error::other(e)));
                    }
                    Poll::Ready(None) => return Poll::Ready(Ok(())),
                    Poll::Pending => return Poll::Pending,
                }
            },
            WsInner::Raw(raw) => {
                loop {
                    match raw_read_state {
                        RawReadState::Idle => {
                            *raw_read_state = RawReadState::ReadingHeader {
                                head: [0u8; 2],
                                filled: 0,
                            };
                            continue;
                        }
                        RawReadState::ReadingHeader {
                            ref mut head,
                            ref mut filled,
                        } => {
                            let mut frame_read_buf = ReadBuf::new(&mut head[*filled..]);
                            match Pin::new(raw.as_mut()).poll_read(cx, &mut frame_read_buf) {
                                Poll::Ready(Ok(())) => {
                                    let n = frame_read_buf.filled().len();
                                    if n == 0 {
                                        return Poll::Ready(Ok(()));
                                    }
                                    *filled += n;
                                    if *filled < 2 {
                                        return Poll::Pending;
                                    }
                                    let opcode = head[0] & 0x0f;
                                    let masked = (head[1] & 0x80) != 0;
                                    let raw_len = (head[1] & 0x7f) as u64;
                                    *raw_frame_opcode = opcode;
                                    *raw_frame_masked = masked;
                                    if raw_len == 126 {
                                        *raw_read_state = RawReadState::ReadingExtendedLen2 {
                                            ext: [0u8; 2],
                                            filled: 0,
                                        };
                                    } else if raw_len == 127 {
                                        *raw_read_state = RawReadState::ReadingExtendedLen8 {
                                            ext: [0u8; 8],
                                            filled: 0,
                                        };
                                    } else {
                                        if raw_len > MAX_WS_FRAME_PAYLOAD {
                                            *raw_read_state = RawReadState::Idle;
                                            return Poll::Ready(Err(io::Error::new(
                                                io::ErrorKind::InvalidData,
                                                "WS frame too large",
                                            )));
                                        }
                                        *raw_frame_payload_len = raw_len;
                                        if masked {
                                            *raw_read_state = RawReadState::ReadingMaskKey {
                                                mask_key: [0u8; 4],
                                                filled: 0,
                                            };
                                        } else if raw_len > 0 {
                                            *raw_read_state = RawReadState::ReadingPayload {
                                                payload: vec![0u8; raw_len as usize],
                                                filled: 0,
                                            };
                                        } else {
                                            let disp = dispatch_raw_frame(
                                                read_buf,
                                                read_pos,
                                                raw_read_state,
                                                *raw_frame_opcode,
                                                raw,
                                                cx,
                                                buf,
                                                &[],
                                            );
                                            if disp.is_pending() {
                                                continue;
                                            } else {
                                                return disp;
                                            }
                                        }
                                    }
                                    continue;
                                }
                                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                                Poll::Pending => return Poll::Pending,
                            }
                        }
                        RawReadState::ReadingExtendedLen2 {
                            ref mut ext,
                            ref mut filled,
                        } => {
                            let mut frame_read_buf = ReadBuf::new(&mut ext[*filled..]);
                            match Pin::new(raw.as_mut()).poll_read(cx, &mut frame_read_buf) {
                                Poll::Ready(Ok(())) => {
                                    let n = frame_read_buf.filled().len();
                                    if n == 0 {
                                        return Poll::Ready(Ok(()));
                                    }
                                    *filled += n;
                                    if *filled < 2 {
                                        return Poll::Pending;
                                    }
                                    let payload_len = u16::from_be_bytes(*ext) as u64;
                                    if payload_len > MAX_WS_FRAME_PAYLOAD {
                                        *raw_read_state = RawReadState::Idle;
                                        return Poll::Ready(Err(io::Error::new(
                                            io::ErrorKind::InvalidData,
                                            "WS frame too large",
                                        )));
                                    }
                                    *raw_frame_payload_len = payload_len;
                                    if *raw_frame_masked {
                                        *raw_read_state = RawReadState::ReadingMaskKey {
                                            mask_key: [0u8; 4],
                                            filled: 0,
                                        };
                                    } else if payload_len > 0 {
                                        *raw_read_state = RawReadState::ReadingPayload {
                                            payload: vec![0u8; payload_len as usize],
                                            filled: 0,
                                        };
                                    } else {
                                        let disp = dispatch_raw_frame(
                                            read_buf,
                                            read_pos,
                                            raw_read_state,
                                            *raw_frame_opcode,
                                            raw,
                                            cx,
                                            buf,
                                            &[],
                                        );
                                        if disp.is_pending() {
                                            continue;
                                        } else {
                                            return disp;
                                        }
                                    }
                                    continue;
                                }
                                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                                Poll::Pending => return Poll::Pending,
                            }
                        }
                        RawReadState::ReadingExtendedLen8 {
                            ref mut ext,
                            ref mut filled,
                        } => {
                            let mut frame_read_buf = ReadBuf::new(&mut ext[*filled..]);
                            match Pin::new(raw.as_mut()).poll_read(cx, &mut frame_read_buf) {
                                Poll::Ready(Ok(())) => {
                                    let n = frame_read_buf.filled().len();
                                    if n == 0 {
                                        return Poll::Ready(Ok(()));
                                    }
                                    *filled += n;
                                    if *filled < 8 {
                                        return Poll::Pending;
                                    }
                                    let payload_len = u64::from_be_bytes(*ext);
                                    if payload_len > MAX_WS_FRAME_PAYLOAD {
                                        *raw_read_state = RawReadState::Idle;
                                        return Poll::Ready(Err(io::Error::new(
                                            io::ErrorKind::InvalidData,
                                            "WS frame too large",
                                        )));
                                    }
                                    *raw_frame_payload_len = payload_len;
                                    if *raw_frame_masked {
                                        *raw_read_state = RawReadState::ReadingMaskKey {
                                            mask_key: [0u8; 4],
                                            filled: 0,
                                        };
                                    } else if payload_len > 0 {
                                        *raw_read_state = RawReadState::ReadingPayload {
                                            payload: vec![0u8; payload_len as usize],
                                            filled: 0,
                                        };
                                    } else {
                                        let disp = dispatch_raw_frame(
                                            read_buf,
                                            read_pos,
                                            raw_read_state,
                                            *raw_frame_opcode,
                                            raw,
                                            cx,
                                            buf,
                                            &[],
                                        );
                                        if disp.is_pending() {
                                            continue;
                                        } else {
                                            return disp;
                                        }
                                    }
                                    continue;
                                }
                                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                                Poll::Pending => return Poll::Pending,
                            }
                        }
                        RawReadState::ReadingMaskKey {
                            ref mut mask_key,
                            ref mut filled,
                        } => {
                            let mut frame_read_buf = ReadBuf::new(&mut mask_key[*filled..]);
                            match Pin::new(raw.as_mut()).poll_read(cx, &mut frame_read_buf) {
                                Poll::Ready(Ok(())) => {
                                    let n = frame_read_buf.filled().len();
                                    if n == 0 {
                                        return Poll::Ready(Ok(()));
                                    }
                                    *filled += n;
                                    if *filled < 4 {
                                        return Poll::Pending;
                                    }
                                    *raw_frame_mask_key = *mask_key;
                                    let pl = *raw_frame_payload_len;
                                    if pl > 0 {
                                        *raw_read_state = RawReadState::ReadingPayload {
                                            payload: vec![0u8; pl as usize],
                                            filled: 0,
                                        };
                                    } else {
                                        let disp = dispatch_raw_frame(
                                            read_buf,
                                            read_pos,
                                            raw_read_state,
                                            *raw_frame_opcode,
                                            raw,
                                            cx,
                                            buf,
                                            &[],
                                        );
                                        if disp.is_pending() {
                                            continue;
                                        } else {
                                            return disp;
                                        }
                                    }
                                    continue;
                                }
                                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                                Poll::Pending => return Poll::Pending,
                            }
                        }
                        RawReadState::ReadingPayload {
                            ref mut payload,
                            ref mut filled,
                        } => {
                            let mut frame_read_buf = ReadBuf::new(&mut payload[*filled..]);
                            match Pin::new(raw.as_mut()).poll_read(cx, &mut frame_read_buf) {
                                Poll::Ready(Ok(())) => {
                                    let n = frame_read_buf.filled().len();
                                    if n == 0 {
                                        return Poll::Ready(Ok(()));
                                    }
                                    *filled += n;
                                    if *filled < payload.len() {
                                        return Poll::Pending;
                                    }
                                    if *raw_frame_masked {
                                        for i in 0..payload.len() {
                                            payload[i] ^= raw_frame_mask_key[i % 4];
                                        }
                                    }
                                    // Take ownership of payload and reset state before
                                    // dispatch to avoid double-borrow on raw_read_state.
                                    let owned_payload = std::mem::take(payload);
                                    *raw_read_state = RawReadState::Idle;
                                    let disp = dispatch_raw_frame(
                                        read_buf,
                                        read_pos,
                                        raw_read_state,
                                        *raw_frame_opcode,
                                        raw,
                                        cx,
                                        buf,
                                        &owned_payload,
                                    );
                                    if disp.is_pending() {
                                        continue;
                                    } else {
                                        return disp;
                                    }
                                }
                                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                                Poll::Pending => return Poll::Pending,
                            }
                        }
                    }
                }
            }
        }
    }
}

#[cfg(feature = "websocket")]
impl AsyncWrite for WsByteStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        // Destructure self to get separate borrows on each field.
        // This is safe because WsByteStream is Unpin.
        let this = &mut *self;
        let WsByteStream {
            inner,
            write_buf,
            write_pos,
            needs_flush,
            client_mode,
            ..
        } = this;
        let mut needs_flush_local = *needs_flush;

        // Pre-build WebSocket frame for Raw variant before the match
        let new_frame = if !needs_flush_local && !buf.is_empty() {
            if matches!(inner, WsInner::Raw(_)) {
                Some(WsInner::build_frame(buf, *client_mode))
            } else {
                None
            }
        } else {
            None
        };

        match inner {
            WsInner::Tungstenite(tungstenite) => {
                if !needs_flush_local && !buf.is_empty() {
                    match tungstenite.as_mut().poll_ready(cx) {
                        Poll::Ready(Ok(())) => {
                            match tungstenite
                                .as_mut()
                                .start_send(Message::Binary(buf.to_vec()))
                            {
                                Ok(()) => needs_flush_local = true,
                                Err(e) => return Poll::Ready(Err(io::Error::other(e))),
                            }
                        }
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(io::Error::other(e))),
                        Poll::Pending => {
                            *needs_flush = needs_flush_local;
                            return Poll::Pending;
                        }
                    }
                }
                if needs_flush_local {
                    match tungstenite.as_mut().poll_flush(cx) {
                        Poll::Ready(Ok(())) => {
                            *needs_flush = false;
                            Poll::Ready(Ok(buf.len()))
                        }
                        Poll::Ready(Err(e)) => {
                            *needs_flush = false;
                            Poll::Ready(Err(io::Error::other(e)))
                        }
                        Poll::Pending => {
                            *needs_flush = true;
                            Poll::Pending
                        }
                    }
                } else {
                    *needs_flush = false;
                    Poll::Ready(Ok(0))
                }
            }
            WsInner::Raw(raw) => {
                WsInner::poll_write_raw(raw, cx, buf, write_buf, write_pos, needs_flush, new_frame)
            }
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // Destructure to get separate borrows — same pattern as poll_write.
        let this = &mut *self;
        let WsByteStream {
            inner,
            write_buf,
            write_pos,
            needs_flush,
            ..
        } = this;
        let needs_flush_local = *needs_flush;
        match inner {
            WsInner::Tungstenite(tungstenite) => {
                if needs_flush_local {
                    match tungstenite.as_mut().poll_flush(cx) {
                        Poll::Ready(Ok(())) => {
                            *needs_flush = false;
                            Poll::Ready(Ok(()))
                        }
                        Poll::Ready(Err(e)) => Poll::Ready(Err(io::Error::other(e))),
                        Poll::Pending => {
                            *needs_flush = true;
                            Poll::Pending
                        }
                    }
                } else {
                    Poll::Ready(Ok(()))
                }
            }
            WsInner::Raw(raw) => {
                if needs_flush_local {
                    let remaining = &write_buf[*write_pos..];
                    match Pin::new(raw.as_mut()).poll_write(cx, remaining) {
                        Poll::Ready(Ok(n)) => {
                            *write_pos += n;
                            if *write_pos >= write_buf.len() {
                                *write_pos = 0;
                                *needs_flush = false;
                                Poll::Ready(Ok(()))
                            } else {
                                cx.waker().wake_by_ref();
                                Poll::Pending
                            }
                        }
                        Poll::Ready(Err(e)) => {
                            *needs_flush = false;
                            Poll::Ready(Err(e))
                        }
                        Poll::Pending => Poll::Pending,
                    }
                } else {
                    Poll::Ready(Ok(()))
                }
            }
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut self.inner {
            WsInner::Tungstenite(inner) => inner.as_mut().poll_close(cx).map_err(io::Error::other),
            WsInner::Raw(raw) => {
                let _ = Pin::new(raw.as_mut()).poll_write(cx, &[0x88, 0x02, 0x03, 0xe8]);
                Pin::new(raw.as_mut()).poll_shutdown(cx)
            }
        }
    }
}

// ---------------------------------------------------------------
// IoStream — unified stream type over TCP, TLS, KCP, WebSocket
// ---------------------------------------------------------------

/// Helper trait bundling AsyncRead + AsyncWrite + Unpin + Send for
/// use as a dyn-compatible trait object in IoStream::Tls.
pub trait AsyncReadWrite: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> AsyncReadWrite for T {}

/// Stream wrapper that serves a byte prefix before delegating to the
/// underlying stream. Used by the WebSocket client upgrade path to feed
/// leftover bytes (a WS frame that arrived in the same TCP segment as the
/// HTTP 101 response) through the raw WS frame parser instead of exposing
/// them as application bytes.
#[cfg(feature = "websocket")]
struct PrependStream {
    prepend: Vec<u8>,
    pos: usize,
    inner: Box<dyn AsyncReadWrite>,
}

#[cfg(feature = "websocket")]
impl AsyncRead for PrependStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.pos < self.prepend.len() {
            let n = (self.prepend.len() - self.pos).min(buf.remaining());
            buf.put_slice(&self.prepend[self.pos..self.pos + n]);
            self.pos += n;
            if self.pos >= self.prepend.len() {
                self.prepend.clear();
                self.pos = 0;
            }
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

#[cfg(feature = "websocket")]
impl AsyncWrite for PrependStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Unified stream type for TCP, TLS, KCP, and WebSocket.
/// WebSocket variant wraps a WsByteStream adapter so all variants
/// transparently support AsyncRead/AsyncWrite and V1 frame I/O.
pub enum IoStream {
    Tcp(TcpStream),
    /// Boxed TLS stream — type-erased to accept any TLS-wrapped transport
    /// (e.g. TlsStream<TcpStream> or TlsStream<PreReadStream<TcpStream>>).
    /// Stores the peer `SocketAddr` alongside the stream so `peer_addr()`
    /// can return it — unlike the boxed trait object which has no such method.
    #[cfg(feature = "tls")]
    Tls(Box<dyn AsyncReadWrite>, SocketAddr),
    #[cfg(feature = "kcp")]
    Kcp(KcpStream),
    #[cfg(feature = "quic")]
    Quic(QuicStream),
    #[cfg(feature = "websocket")]
    WebSocket(WsByteStream),
    Yamux(YamuxStream),
    /// AES-128-CFB encrypted control stream.
    /// Created after login by wrapping the inner IoStream.
    Cipher(Box<crate::cipher_stream::CipherStream<IoStream>>),
    /// AEAD encrypted V2 control stream (AES-256-GCM or XChaCha20-Poly1305).
    /// Created after V2 handshake with crypto negotiation.
    Aead(Box<crate::crypto::AeadStream>),
    /// SSH reverse-forward channel (type-erased).
    SshChannel(Box<dyn AsyncReadWrite>),
    /// Pre-read bytes followed by a TCP stream.
    /// Used after connection type detection when bytes have been consumed
    /// but need to be replayed (e.g., V1 type byte in non-V2 connections).
    PreRead(Vec<u8>, TcpStream),
    /// Buffered bytes followed by an inner IoStream.
    /// Used when V2 magic is detected on a yamux stream: if the bytes
    /// are NOT V2 magic, they're buffered and replayed for V1 processing.
    /// The usize tracks the current read position into the buffer.
    BufferedRead(Vec<u8>, usize, Box<IoStream>),
}

// -----------------------------------------------------------------
// ReadHalf / WriteHalf — static-dispatch halves of IoStream::into_split()
// -----------------------------------------------------------------

/// Read half of an [`IoStream`] after [`IoStream::into_split`].
///
/// Each variant wraps the corresponding split-half for its inner stream
/// type. Enum dispatch replaces the old `Box<dyn AsyncRead>` — zero heap
/// allocation, match-based static dispatch instead of vtable.
pub enum ReadHalf {
    Tcp(tokio::io::ReadHalf<tokio::net::TcpStream>),
    #[cfg(feature = "tls")]
    Tls(tokio::io::ReadHalf<Box<dyn AsyncReadWrite>>),
    #[cfg(feature = "kcp")]
    Kcp(tokio::io::ReadHalf<crate::kcp::KcpStream>),
    #[cfg(feature = "quic")]
    Quic(quinn::RecvStream),
    #[cfg(feature = "websocket")]
    WebSocket(tokio::io::ReadHalf<WsByteStream>),
    Yamux(tokio::io::ReadHalf<YamuxStream>),
    Cipher(tokio::io::ReadHalf<Box<crate::cipher_stream::CipherStream<IoStream>>>),
    Aead(tokio::io::ReadHalf<Box<crate::crypto::AeadStream>>),
    SshChannel(tokio::io::ReadHalf<Box<dyn AsyncReadWrite>>),
}

impl ReadHalf {
    // NOTE: into_boxed() removed after PR #161. Use `From` impl below for
    // cold-path conversions (NAT hole session storage, auth).
}

impl From<ReadHalf> for Box<dyn tokio::io::AsyncRead + Unpin + Send> {
    fn from(r: ReadHalf) -> Self {
        match r {
            ReadHalf::Tcp(r) => Box::new(r),
            #[cfg(feature = "tls")]
            ReadHalf::Tls(r) => Box::new(r),
            #[cfg(feature = "kcp")]
            ReadHalf::Kcp(r) => Box::new(r),
            #[cfg(feature = "quic")]
            ReadHalf::Quic(r) => Box::new(r),
            #[cfg(feature = "websocket")]
            ReadHalf::WebSocket(r) => Box::new(r),
            ReadHalf::Yamux(r) => Box::new(r),
            ReadHalf::Cipher(r) => Box::new(r),
            ReadHalf::Aead(r) => Box::new(r),
            ReadHalf::SshChannel(r) => Box::new(r),
        }
    }
}

/// Write half of an [`IoStream`] after [`IoStream::into_split`].
pub enum WriteHalf {
    Tcp(tokio::io::WriteHalf<tokio::net::TcpStream>),
    #[cfg(feature = "tls")]
    Tls(tokio::io::WriteHalf<Box<dyn AsyncReadWrite>>),
    #[cfg(feature = "kcp")]
    Kcp(tokio::io::WriteHalf<crate::kcp::KcpStream>),
    #[cfg(feature = "quic")]
    Quic(quinn::SendStream),
    #[cfg(feature = "websocket")]
    WebSocket(tokio::io::WriteHalf<WsByteStream>),
    Yamux(tokio::io::WriteHalf<YamuxStream>),
    Cipher(tokio::io::WriteHalf<Box<crate::cipher_stream::CipherStream<IoStream>>>),
    Aead(tokio::io::WriteHalf<Box<crate::crypto::AeadStream>>),
    SshChannel(tokio::io::WriteHalf<Box<dyn AsyncReadWrite>>),
}

impl WriteHalf {
    // NOTE: into_boxed() removed after PR #161. Use `From` impl below for
    // cold-path conversions (NAT hole session storage).
}

impl From<WriteHalf> for Box<dyn tokio::io::AsyncWrite + Unpin + Send> {
    fn from(w: WriteHalf) -> Self {
        match w {
            WriteHalf::Tcp(w) => Box::new(w),
            #[cfg(feature = "tls")]
            WriteHalf::Tls(w) => Box::new(w),
            #[cfg(feature = "kcp")]
            WriteHalf::Kcp(w) => Box::new(w),
            #[cfg(feature = "quic")]
            WriteHalf::Quic(w) => Box::new(w),
            #[cfg(feature = "websocket")]
            WriteHalf::WebSocket(w) => Box::new(w),
            WriteHalf::Yamux(w) => Box::new(w),
            WriteHalf::Cipher(w) => Box::new(w),
            WriteHalf::Aead(w) => Box::new(w),
            WriteHalf::SshChannel(w) => Box::new(w),
        }
    }
}

impl std::fmt::Debug for ReadHalf {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReadHalf::Tcp(_) => f.debug_struct("ReadHalf::Tcp").finish_non_exhaustive(),
            #[cfg(feature = "tls")]
            ReadHalf::Tls(_) => f.debug_struct("ReadHalf::Tls").finish_non_exhaustive(),
            #[cfg(feature = "kcp")]
            ReadHalf::Kcp(_) => f.debug_struct("ReadHalf::Kcp").finish_non_exhaustive(),
            #[cfg(feature = "quic")]
            ReadHalf::Quic(_) => f.debug_struct("ReadHalf::Quic").finish_non_exhaustive(),
            #[cfg(feature = "websocket")]
            ReadHalf::WebSocket(_) => f
                .debug_struct("ReadHalf::WebSocket")
                .finish_non_exhaustive(),
            ReadHalf::Yamux(_) => f.debug_struct("ReadHalf::Yamux").finish_non_exhaustive(),
            ReadHalf::Cipher(_) => f.debug_struct("ReadHalf::Cipher").finish_non_exhaustive(),
            ReadHalf::Aead(_) => f.debug_struct("ReadHalf::Aead").finish_non_exhaustive(),
            ReadHalf::SshChannel(_) => f
                .debug_struct("ReadHalf::SshChannel")
                .finish_non_exhaustive(),
        }
    }
}

impl std::fmt::Debug for WriteHalf {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WriteHalf::Tcp(_) => f.debug_struct("WriteHalf::Tcp").finish_non_exhaustive(),
            #[cfg(feature = "tls")]
            WriteHalf::Tls(_) => f.debug_struct("WriteHalf::Tls").finish_non_exhaustive(),
            #[cfg(feature = "kcp")]
            WriteHalf::Kcp(_) => f.debug_struct("WriteHalf::Kcp").finish_non_exhaustive(),
            #[cfg(feature = "quic")]
            WriteHalf::Quic(_) => f.debug_struct("WriteHalf::Quic").finish_non_exhaustive(),
            #[cfg(feature = "websocket")]
            WriteHalf::WebSocket(_) => f
                .debug_struct("WriteHalf::WebSocket")
                .finish_non_exhaustive(),
            WriteHalf::Yamux(_) => f.debug_struct("WriteHalf::Yamux").finish_non_exhaustive(),
            WriteHalf::Cipher(_) => f.debug_struct("WriteHalf::Cipher").finish_non_exhaustive(),
            WriteHalf::Aead(_) => f.debug_struct("WriteHalf::Aead").finish_non_exhaustive(),
            WriteHalf::SshChannel(_) => f
                .debug_struct("WriteHalf::SshChannel")
                .finish_non_exhaustive(),
        }
    }
}

impl tokio::io::AsyncRead for ReadHalf {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match &mut *self {
            ReadHalf::Tcp(r) => Pin::new(r).poll_read(cx, buf),
            #[cfg(feature = "tls")]
            ReadHalf::Tls(r) => Pin::new(r).poll_read(cx, buf),
            #[cfg(feature = "kcp")]
            ReadHalf::Kcp(r) => Pin::new(r).poll_read(cx, buf),
            #[cfg(feature = "quic")]
            ReadHalf::Quic(r) => Pin::new(r).poll_read(cx, buf),
            #[cfg(feature = "websocket")]
            ReadHalf::WebSocket(r) => Pin::new(r).poll_read(cx, buf),
            ReadHalf::Yamux(r) => Pin::new(r).poll_read(cx, buf),
            ReadHalf::Cipher(r) => Pin::new(r).poll_read(cx, buf),
            ReadHalf::Aead(r) => Pin::new(r).poll_read(cx, buf),
            ReadHalf::SshChannel(r) => Pin::new(r).poll_read(cx, buf),
        }
    }
}

impl tokio::io::AsyncWrite for WriteHalf {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        match &mut *self {
            WriteHalf::Tcp(w) => Pin::new(w).poll_write(cx, buf),
            #[cfg(feature = "tls")]
            WriteHalf::Tls(w) => Pin::new(w).poll_write(cx, buf),
            #[cfg(feature = "kcp")]
            WriteHalf::Kcp(w) => Pin::new(w).poll_write(cx, buf),
            #[cfg(feature = "quic")]
            WriteHalf::Quic(w) => Pin::new(w)
                .poll_write(cx, buf)
                .map_err(std::io::Error::other),
            #[cfg(feature = "websocket")]
            WriteHalf::WebSocket(w) => Pin::new(w).poll_write(cx, buf),
            WriteHalf::Yamux(w) => Pin::new(w).poll_write(cx, buf),
            WriteHalf::Cipher(w) => Pin::new(w).poll_write(cx, buf),
            WriteHalf::Aead(w) => Pin::new(w).poll_write(cx, buf),
            WriteHalf::SshChannel(w) => Pin::new(w).poll_write(cx, buf),
        }
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match &mut *self {
            WriteHalf::Tcp(w) => Pin::new(w).poll_flush(cx),
            #[cfg(feature = "tls")]
            WriteHalf::Tls(w) => Pin::new(w).poll_flush(cx),
            #[cfg(feature = "kcp")]
            WriteHalf::Kcp(w) => Pin::new(w).poll_flush(cx),
            #[cfg(feature = "quic")]
            WriteHalf::Quic(w) => Pin::new(w).poll_flush(cx).map_err(std::io::Error::other),
            #[cfg(feature = "websocket")]
            WriteHalf::WebSocket(w) => Pin::new(w).poll_flush(cx),
            WriteHalf::Yamux(w) => Pin::new(w).poll_flush(cx),
            WriteHalf::Cipher(w) => Pin::new(w).poll_flush(cx),
            WriteHalf::Aead(w) => Pin::new(w).poll_flush(cx),
            WriteHalf::SshChannel(w) => Pin::new(w).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match &mut *self {
            WriteHalf::Tcp(w) => Pin::new(w).poll_shutdown(cx),
            #[cfg(feature = "tls")]
            WriteHalf::Tls(w) => Pin::new(w).poll_shutdown(cx),
            #[cfg(feature = "kcp")]
            WriteHalf::Kcp(w) => Pin::new(w).poll_shutdown(cx),
            #[cfg(feature = "quic")]
            WriteHalf::Quic(w) => Pin::new(w).poll_shutdown(cx),
            #[cfg(feature = "websocket")]
            WriteHalf::WebSocket(w) => Pin::new(w).poll_shutdown(cx),
            WriteHalf::Yamux(w) => Pin::new(w).poll_shutdown(cx),
            WriteHalf::Cipher(w) => Pin::new(w).poll_shutdown(cx),
            WriteHalf::Aead(w) => Pin::new(w).poll_shutdown(cx),
            WriteHalf::SshChannel(w) => Pin::new(w).poll_shutdown(cx),
        }
    }
}

impl std::fmt::Debug for IoStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IoStream::Tcp(_) => f.debug_struct("IoStream::Tcp").finish_non_exhaustive(),
            #[cfg(feature = "tls")]
            IoStream::Tls(..) => f.debug_struct("IoStream::Tls").finish_non_exhaustive(),
            #[cfg(feature = "kcp")]
            IoStream::Kcp(_) => f.debug_struct("IoStream::Kcp").finish_non_exhaustive(),
            #[cfg(feature = "quic")]
            IoStream::Quic(_) => f.debug_struct("IoStream::Quic").finish_non_exhaustive(),
            #[cfg(feature = "websocket")]
            IoStream::WebSocket(_) => f
                .debug_struct("IoStream::WebSocket")
                .finish_non_exhaustive(),
            IoStream::Yamux(_) => f.debug_struct("IoStream::Yamux").finish_non_exhaustive(),
            IoStream::Cipher(_) => f.debug_struct("IoStream::Cipher").finish_non_exhaustive(),
            IoStream::Aead(_) => f.debug_struct("IoStream::Aead").finish_non_exhaustive(),
            IoStream::SshChannel(_) => f
                .debug_struct("IoStream::SshChannel")
                .finish_non_exhaustive(),
            IoStream::PreRead(..) => f.debug_struct("IoStream::PreRead").finish_non_exhaustive(),
            IoStream::BufferedRead(..) => f
                .debug_struct("IoStream::BufferedRead")
                .finish_non_exhaustive(),
        }
    }
}

// All inner types (TcpStream, TlsStream, DuplexStream, WsByteStream) are Unpin.
impl tokio::io::AsyncRead for IoStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        // BufferedRead: replay buffered bytes first, then delegate to inner IoStream.
        if let IoStream::BufferedRead(buffered_data, pos, inner) = this {
            if *pos < buffered_data.len() {
                let remaining = &buffered_data[*pos..];
                let n = remaining.len().min(buf.remaining());
                buf.put_slice(&remaining[..n]);
                *pos += n;
                return Poll::Ready(Ok(()));
            }
            return Pin::new(inner.as_mut()).poll_read(cx, buf);
        }
        // PreRead: replay buffered bytes first, then delegate to inner TcpStream.
        if let IoStream::PreRead(pre_read, tcp) = this {
            if !pre_read.is_empty() {
                let n = pre_read.len().min(buf.remaining());
                buf.put_slice(&pre_read[..n]);
                pre_read.drain(..n);
                return Poll::Ready(Ok(()));
            }
            return Pin::new(tcp).poll_read(cx, buf);
        }
        match this {
            IoStream::Tcp(s) => Pin::new(s).poll_read(cx, buf),
            #[cfg(feature = "tls")]
            IoStream::Tls(s, _) => Pin::new(s).poll_read(cx, buf),
            #[cfg(feature = "kcp")]
            IoStream::Kcp(s) => Pin::new(s).poll_read(cx, buf),
            #[cfg(feature = "quic")]
            IoStream::Quic(s) => Pin::new(s).poll_read(cx, buf),
            #[cfg(feature = "websocket")]
            IoStream::WebSocket(s) => Pin::new(s).poll_read(cx, buf),
            IoStream::Yamux(s) => Pin::new(s).poll_read(cx, buf),
            IoStream::Cipher(s) => Pin::new(s).poll_read(cx, buf),
            IoStream::Aead(s) => Pin::new(s).poll_read(cx, buf),
            IoStream::SshChannel(s) => Pin::new(s.as_mut()).poll_read(cx, buf),
            IoStream::PreRead(_, _) | IoStream::BufferedRead(..) => {
                // PreRead/BufferedRead are ephemeral — they only exist to carry
                // pre-consumed bytes after detect_and_strip_magic. By the time
                // poll_read is called they should have been unwrapped.
                Poll::Ready(Err(io::Error::other(
                    "IoStream::PreRead/BufferedRead is ephemeral — stream was not unwrapped before use",
                )))
            }
        }
    }
}

// Shared by poll_flush/poll_shutdown — dispatch over 11 IoStream variants.
macro_rules! io_stream_dispatch_poll {
    ($self:expr, $cx:expr, $method:ident) => {
        match $self.get_mut() {
            IoStream::Tcp(s) => Pin::new(s).$method($cx),
            #[cfg(feature = "tls")]
            IoStream::Tls(s, _) => Pin::new(s).$method($cx),
            #[cfg(feature = "kcp")]
            IoStream::Kcp(s) => Pin::new(s).$method($cx),
            #[cfg(feature = "quic")]
            IoStream::Quic(s) => Pin::new(s).$method($cx),
            #[cfg(feature = "websocket")]
            IoStream::WebSocket(s) => Pin::new(s).$method($cx),
            IoStream::Yamux(s) => Pin::new(s).$method($cx),
            IoStream::Cipher(s) => Pin::new(s).$method($cx),
            IoStream::Aead(s) => Pin::new(s).$method($cx),
            IoStream::SshChannel(s) => Pin::new(s.as_mut()).$method($cx),
            IoStream::PreRead(_, s) => Pin::new(s).$method($cx),
            IoStream::BufferedRead(_, _, inner) => Pin::new(inner.as_mut()).$method($cx),
        }
    };
}

impl tokio::io::AsyncWrite for IoStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            IoStream::Tcp(s) => Pin::new(s).poll_write(cx, buf),
            #[cfg(feature = "tls")]
            IoStream::Tls(s, _) => Pin::new(s).poll_write(cx, buf),
            #[cfg(feature = "kcp")]
            IoStream::Kcp(s) => Pin::new(s).poll_write(cx, buf),
            #[cfg(feature = "quic")]
            IoStream::Quic(s) => Pin::new(s).poll_write(cx, buf),
            #[cfg(feature = "websocket")]
            IoStream::WebSocket(s) => Pin::new(s).poll_write(cx, buf),
            IoStream::Yamux(s) => Pin::new(s).poll_write(cx, buf),
            IoStream::Cipher(s) => Pin::new(s).poll_write(cx, buf),
            IoStream::Aead(s) => Pin::new(s).poll_write(cx, buf),
            IoStream::SshChannel(s) => Pin::new(s.as_mut()).poll_write(cx, buf),
            IoStream::PreRead(_, s) => Pin::new(s).poll_write(cx, buf),
            IoStream::BufferedRead(_, _, inner) => Pin::new(inner.as_mut()).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        io_stream_dispatch_poll!(self, cx, poll_flush)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        io_stream_dispatch_poll!(self, cx, poll_shutdown)
    }
}

impl IoStream {
    /// Write a V1 protocol frame to this stream.
    pub async fn write_v1_frame(
        &mut self,
        msg: &crate::msg::FrpMessage,
    ) -> Result<(), crate::Error> {
        match self {
            IoStream::Tcp(s) => crate::protocol::write_msg_v1(s, msg).await,
            #[cfg(feature = "tls")]
            IoStream::Tls(s, _) => crate::protocol::write_msg_v1(s, msg).await,
            #[cfg(feature = "kcp")]
            IoStream::Kcp(s) => crate::protocol::write_msg_v1(s, msg).await,
            #[cfg(feature = "quic")]
            IoStream::Quic(s) => crate::protocol::write_msg_v1(s, msg).await,
            #[cfg(feature = "websocket")]
            IoStream::WebSocket(s) => crate::protocol::write_msg_v1(s, msg).await,
            IoStream::Yamux(s) => crate::protocol::write_msg_v1(s, msg).await,
            IoStream::Cipher(s) => crate::protocol::write_msg_v1(s, msg).await,
            IoStream::Aead(s) => crate::protocol::write_msg_v1(s, msg).await,
            IoStream::SshChannel(s) => crate::protocol::write_msg_v1(s, msg).await,
            IoStream::PreRead(_, s) => crate::protocol::write_msg_v1(s, msg).await,
            IoStream::BufferedRead(_, _, inner) => {
                crate::protocol::write_msg_v1(inner.as_mut(), msg).await
            }
        }
    }

    /// Read a V1 protocol frame from this stream.
    pub async fn read_v1_frame(&mut self) -> Result<crate::msg::FrpMessage, crate::Error> {
        match self {
            IoStream::Tcp(s) => crate::protocol::read_msg_v1(s).await,
            #[cfg(feature = "tls")]
            IoStream::Tls(s, _) => crate::protocol::read_msg_v1(s).await,
            #[cfg(feature = "kcp")]
            IoStream::Kcp(s) => crate::protocol::read_msg_v1(s).await,
            #[cfg(feature = "quic")]
            IoStream::Quic(s) => crate::protocol::read_msg_v1(s).await,
            #[cfg(feature = "websocket")]
            IoStream::WebSocket(s) => crate::protocol::read_msg_v1(s).await,
            IoStream::Yamux(s) => crate::protocol::read_msg_v1(s).await,
            IoStream::Cipher(s) => crate::protocol::read_msg_v1(s).await,
            IoStream::Aead(s) => crate::protocol::read_msg_v1(s).await,
            IoStream::SshChannel(s) => crate::protocol::read_msg_v1(s).await,
            IoStream::PreRead(..) => crate::protocol::read_msg_v1(self).await,
            IoStream::BufferedRead(..) => crate::protocol::read_msg_v1(self).await,
        }
    }

    /// Write a V2 protocol frame (binary framing + JSON payload) to this stream.
    pub async fn write_v2_frame(
        &mut self,
        msg: &crate::msg::FrpMessage,
    ) -> Result<(), crate::Error> {
        use tokio::io::AsyncWriteExt;
        match self {
            IoStream::Tcp(s) => {
                crate::protocol::write_msg_v2_inner(s, msg).await?;
                s.flush()
                    .await
                    .map_err(|e| crate::Error::Transport(format!("flush: {e}").into()))?;
            }
            #[cfg(feature = "tls")]
            IoStream::Tls(s, _) => {
                crate::protocol::write_msg_v2_inner(s, msg).await?;
                s.flush()
                    .await
                    .map_err(|e| crate::Error::Transport(format!("flush: {e}").into()))?;
            }
            #[cfg(feature = "kcp")]
            IoStream::Kcp(s) => {
                crate::protocol::write_msg_v2_inner(s, msg).await?;
                s.flush()
                    .await
                    .map_err(|e| crate::Error::Transport(format!("flush: {e}").into()))?;
            }
            #[cfg(feature = "quic")]
            IoStream::Quic(s) => {
                crate::protocol::write_msg_v2_inner(s, msg).await?;
                s.flush()
                    .await
                    .map_err(|e| crate::Error::Transport(format!("flush: {e}").into()))?;
            }
            #[cfg(feature = "websocket")]
            IoStream::WebSocket(s) => {
                crate::protocol::write_msg_v2_inner(s, msg).await?;
                s.flush()
                    .await
                    .map_err(|e| crate::Error::Transport(format!("flush: {e}").into()))?;
            }
            IoStream::Yamux(s) => {
                crate::protocol::write_msg_v2_inner(s, msg).await?;
                s.flush()
                    .await
                    .map_err(|e| crate::Error::Transport(format!("flush: {e}").into()))?;
            }
            IoStream::Cipher(s) => {
                crate::protocol::write_msg_v2_inner(s, msg).await?;
                s.flush()
                    .await
                    .map_err(|e| crate::Error::Transport(format!("flush: {e}").into()))?;
            }
            IoStream::Aead(s) => {
                crate::protocol::write_msg_v2_inner(s, msg).await?;
                s.flush()
                    .await
                    .map_err(|e| crate::Error::Transport(format!("flush: {e}").into()))?;
            }
            IoStream::SshChannel(s) => {
                crate::protocol::write_msg_v2_inner(s, msg).await?;
                s.flush()
                    .await
                    .map_err(|e| crate::Error::Transport(format!("flush: {e}").into()))?;
            }
            IoStream::PreRead(_, s) => {
                crate::protocol::write_msg_v2_inner(s, msg).await?;
                s.flush()
                    .await
                    .map_err(|e| crate::Error::Transport(format!("flush: {e}").into()))?;
            }
            IoStream::BufferedRead(_, _, inner) => {
                crate::protocol::write_msg_v2_inner(inner.as_mut(), msg).await?;
                inner
                    .flush()
                    .await
                    .map_err(|e| crate::Error::Transport(format!("flush: {e}").into()))?;
            }
        }
        Ok(())
    }

    /// Read a V2 protocol frame (binary framing + JSON payload) from this stream.
    pub async fn read_v2_frame(&mut self) -> Result<crate::msg::FrpMessage, crate::Error> {
        match self {
            IoStream::Tcp(s) => crate::protocol::read_msg_v2(s).await,
            #[cfg(feature = "tls")]
            IoStream::Tls(s, _) => crate::protocol::read_msg_v2(s).await,
            #[cfg(feature = "kcp")]
            IoStream::Kcp(s) => crate::protocol::read_msg_v2(s).await,
            #[cfg(feature = "quic")]
            IoStream::Quic(s) => crate::protocol::read_msg_v2(s).await,
            #[cfg(feature = "websocket")]
            IoStream::WebSocket(s) => crate::protocol::read_msg_v2(s).await,
            IoStream::Yamux(s) => crate::protocol::read_msg_v2(s).await,
            IoStream::Cipher(s) => crate::protocol::read_msg_v2(s).await,
            IoStream::Aead(s) => crate::protocol::read_msg_v2(s).await,
            IoStream::SshChannel(s) => crate::protocol::read_msg_v2(s).await,
            IoStream::PreRead(..) => crate::protocol::read_msg_v2(self).await,
            IoStream::BufferedRead(..) => crate::protocol::read_msg_v2(self).await,
        }
    }

    /// Write a raw V2 frame (for handshake frames like ClientHello/ServerHello).
    /// Lower-level than write_v2_frame — caller controls frame_type and raw payload bytes.
    pub async fn write_raw_v2_frame(
        &mut self,
        frame_type: u16,
        flags: u16,
        payload: &[u8],
    ) -> Result<(), crate::Error> {
        match self {
            IoStream::Tcp(s) => {
                crate::protocol::write_v2_frame_raw(s, frame_type, flags, payload).await
            }
            #[cfg(feature = "tls")]
            IoStream::Tls(s, _) => {
                crate::protocol::write_v2_frame_raw(s, frame_type, flags, payload).await
            }
            #[cfg(feature = "kcp")]
            IoStream::Kcp(s) => {
                crate::protocol::write_v2_frame_raw(s, frame_type, flags, payload).await
            }
            #[cfg(feature = "quic")]
            IoStream::Quic(s) => {
                crate::protocol::write_v2_frame_raw(s, frame_type, flags, payload).await
            }
            #[cfg(feature = "websocket")]
            IoStream::WebSocket(s) => {
                crate::protocol::write_v2_frame_raw(s, frame_type, flags, payload).await
            }
            IoStream::Yamux(s) => {
                crate::protocol::write_v2_frame_raw(s, frame_type, flags, payload).await
            }
            IoStream::Cipher(s) => {
                crate::protocol::write_v2_frame_raw(s, frame_type, flags, payload).await
            }
            IoStream::Aead(s) => {
                crate::protocol::write_v2_frame_raw(s, frame_type, flags, payload).await
            }
            IoStream::SshChannel(s) => {
                crate::protocol::write_v2_frame_raw(s, frame_type, flags, payload).await
            }
            IoStream::PreRead(_, s) => {
                crate::protocol::write_v2_frame_raw(s, frame_type, flags, payload).await
            }
            IoStream::BufferedRead(_, _, inner) => {
                crate::protocol::write_v2_frame_raw(inner.as_mut(), frame_type, flags, payload)
                    .await
            }
        }
    }

    /// Read a raw V2 frame (for handshake). Returns (frame_type, flags, payload_bytes).
    pub async fn read_raw_v2_frame(&mut self) -> Result<(u16, u16, Vec<u8>), crate::Error> {
        match self {
            IoStream::Tcp(s) => crate::protocol::read_v2_frame_raw(s).await,
            #[cfg(feature = "tls")]
            IoStream::Tls(s, _) => crate::protocol::read_v2_frame_raw(s).await,
            #[cfg(feature = "kcp")]
            IoStream::Kcp(s) => crate::protocol::read_v2_frame_raw(s).await,
            #[cfg(feature = "quic")]
            IoStream::Quic(s) => crate::protocol::read_v2_frame_raw(s).await,
            #[cfg(feature = "websocket")]
            IoStream::WebSocket(s) => crate::protocol::read_v2_frame_raw(s).await,
            IoStream::Yamux(s) => crate::protocol::read_v2_frame_raw(s).await,
            IoStream::Cipher(s) => crate::protocol::read_v2_frame_raw(s).await,
            IoStream::Aead(s) => crate::protocol::read_v2_frame_raw(s).await,
            IoStream::SshChannel(s) => crate::protocol::read_v2_frame_raw(s).await,
            IoStream::PreRead(..) => crate::protocol::read_v2_frame_raw(self).await,
            IoStream::BufferedRead(..) => crate::protocol::read_v2_frame_raw(self).await,
        }
    }

    /// Get the peer address of this stream, if available.
    pub fn peer_addr(&self) -> Option<std::net::SocketAddr> {
        match self {
            IoStream::Tcp(s) => s.peer_addr().ok(),
            IoStream::PreRead(_, s) => s.peer_addr().ok(),
            IoStream::BufferedRead(_, _, inner) => inner.peer_addr(),
            #[cfg(feature = "tls")]
            IoStream::Tls(_, addr) => Some(*addr),
            IoStream::Yamux(_)
            | IoStream::Cipher(_)
            | IoStream::Aead(_)
            | IoStream::SshChannel(_) => None,
            #[cfg(feature = "kcp")]
            IoStream::Kcp(_) => None,
            #[cfg(feature = "quic")]
            IoStream::Quic(_) => None,
            #[cfg(feature = "websocket")]
            IoStream::WebSocket(_) => None,
        }
    }

    /// Split the stream into owned read and write halves.
    pub fn into_split(self) -> std::io::Result<(ReadHalf, WriteHalf)> {
        match self {
            IoStream::Tcp(s) => {
                let (r, w) = tokio::io::split(s);
                Ok((ReadHalf::Tcp(r), WriteHalf::Tcp(w)))
            }
            #[cfg(feature = "tls")]
            IoStream::Tls(s, _) => {
                let (r, w) = tokio::io::split(s);
                Ok((ReadHalf::Tls(r), WriteHalf::Tls(w)))
            }
            #[cfg(feature = "kcp")]
            IoStream::Kcp(stream) => {
                let (r, w) = tokio::io::split(stream);
                Ok((ReadHalf::Kcp(r), WriteHalf::Kcp(w)))
            }
            #[cfg(feature = "quic")]
            IoStream::Quic(stream) => {
                let (r, w) = stream.into_split();
                Ok((ReadHalf::Quic(r), WriteHalf::Quic(w)))
            }
            #[cfg(feature = "websocket")]
            IoStream::WebSocket(adapter) => {
                let (r, w) = tokio::io::split(adapter);
                Ok((ReadHalf::WebSocket(r), WriteHalf::WebSocket(w)))
            }
            IoStream::Yamux(stream) => {
                let (r, w) = tokio::io::split(stream);
                Ok((ReadHalf::Yamux(r), WriteHalf::Yamux(w)))
            }
            IoStream::Cipher(stream) => {
                let (r, w) = tokio::io::split(stream);
                Ok((ReadHalf::Cipher(r), WriteHalf::Cipher(w)))
            }
            IoStream::Aead(stream) => {
                let (r, w) = tokio::io::split(stream);
                Ok((ReadHalf::Aead(r), WriteHalf::Aead(w)))
            }
            IoStream::SshChannel(s) => {
                let (r, w) = tokio::io::split(s);
                Ok((ReadHalf::SshChannel(r), WriteHalf::SshChannel(w)))
            }
            IoStream::PreRead(pre_read, s) => {
                if !pre_read.is_empty() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "into_split called with buffered bytes",
                    ));
                }
                let (r, w) = tokio::io::split(s);
                Ok((ReadHalf::Tcp(r), WriteHalf::Tcp(w)))
            }
            IoStream::BufferedRead(buf, pos, inner) => {
                if pos < buf.len() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "into_split called with buffered bytes",
                    ));
                }
                inner.into_split()
            }
        }
    }

    /// Return a reference to the underlying `TcpStream` if this variant is
    /// raw TCP. Returns `None` for `PreRead` (has unconsumed bytes that
    /// cannot be spliced), TLS, KCP, WebSocket, yamux, cipher, and other
    /// wrapped variants.
    ///
    /// Useful for zero-copy fast paths (e.g. `splice(2)`) that only work
    /// with raw kernel TCP sockets.
    pub fn try_tcp(&self) -> Option<&TcpStream> {
        match self {
            IoStream::Tcp(s) => Some(s),
            _ => None,
        }
    }

    /// Mutable variant of [`try_tcp`].
    pub fn try_tcp_mut(&mut self) -> Option<&mut TcpStream> {
        match self {
            IoStream::Tcp(s) => Some(s),
            _ => None,
        }
    }

    /// Wrap this stream in AES-128-CFB encryption for control messages.
    /// Must be called after login (the Login message is NOT encrypted).
    pub fn into_encrypted(self, key: [u8; 16]) -> Self {
        match self {
            IoStream::BufferedRead(buf, pos, inner) => {
                // Buffered bytes are preserved inside the returned Cipher wrapper;
                // they will be replayed before encrypted reads begin.
                assert!(
                    pos >= buf.len(),
                    "into_encrypted called before buffered bytes consumed"
                );
                IoStream::BufferedRead(buf, pos, Box::new(inner.into_encrypted(key)))
            }
            IoStream::Aead(inner) => {
                // Already AEAD-encrypted (V2 with crypto). Don't double-wrap.
                IoStream::Aead(inner)
            }
            other => {
                let c = crate::cipher_stream::CipherStream::new(other, key);
                IoStream::Cipher(Box::new(c))
            }
        }
    }
}

/// Options for dialing the server.
#[derive(Debug, Clone)]
pub struct DialOptions {
    pub server_addr: String,
    pub server_port: u16,
    pub protocol: TransportProtocol,
    pub tls_enable: bool,
    pub tls_server_name: String,
    pub tls_ca_file: Option<String>,
    pub tls_cert_file: Option<String>,
    pub tls_key_file: Option<String>,
    pub dns_server: Option<String>,
    pub dial_timeout_secs: u64,
    pub disable_custom_tls_first_byte: bool,
    /// TCP keepalive interval in seconds for outbound connections. 0 = disabled.
    pub keepalive_secs: u64,
    /// Local IP address to bind before dialing. None = system default.
    pub bind_addr: Option<String>,
    /// Upstream proxy URL. Supports http:// and socks5:// schemes.
    /// When set, the TCP connection goes through the proxy instead of
    /// connecting directly. Empty = direct connection.
    /// Go frp compat: transport.proxyURL.
    pub proxy_url: Option<String>,
    /// Use V2 protocol framing. Client writes V2 magic bytes and performs
    /// ClientHello/ServerHello handshake. Default: false (V1).
    pub v2: bool,
}

impl Default for DialOptions {
    fn default() -> Self {
        Self {
            server_addr: "0.0.0.0".into(),
            server_port: 7000,
            protocol: TransportProtocol::Tcp,
            tls_enable: false,
            tls_server_name: String::new(),
            tls_ca_file: None,
            tls_cert_file: None,
            tls_key_file: None,
            dns_server: None,
            dial_timeout_secs: 10,
            disable_custom_tls_first_byte: false,
            keepalive_secs: 0,
            bind_addr: None,
            proxy_url: None,
            v2: false,
        }
    }
}

/// Resolve a hostname to an IP address using a specific DNS server.
///
/// Sends a standard DNS A-record query over UDP. Handles name compression
/// pointers in the response. IPv6 (AAAA) is not supported — the custom DNS
/// server option is typically used with IPv4-only internal resolvers.
pub async fn resolve_host_with_dns(host: &str, dns_server: &str) -> Result<String, crate::Error> {
    use std::net::SocketAddr;
    use std::str::FromStr;
    use tokio::net::UdpSocket;
    use tokio::time::{timeout, Duration};

    // If host is already an IP, return it as-is
    if host.parse::<std::net::IpAddr>().is_ok() {
        return Ok(host.to_string());
    }

    // Parse DNS server address (default port 53)
    let dns_addr = if dns_server.contains(':') {
        SocketAddr::from_str(dns_server).map_err(|e| {
            crate::Error::Transport(format!("invalid dns_server '{dns_server}': {e}").into())
        })?
    } else {
        SocketAddr::from_str(&format!("{dns_server}:53")).map_err(|e| {
            crate::Error::Transport(format!("invalid dns_server '{dns_server}': {e}").into())
        })?
    };

    // Build DNS A-record query
    let mut query = Vec::with_capacity(64);
    let txid: u16 = rand::random();
    query.extend_from_slice(&txid.to_be_bytes());
    query.extend_from_slice(&[0x01, 0x00]); // flags: standard query, RD=1
    query.extend_from_slice(&[0x00, 0x01]); // QDCOUNT = 1
    query.extend_from_slice(&[0x00, 0x00]); // ANCOUNT = 0
    query.extend_from_slice(&[0x00, 0x00]); // NSCOUNT = 0
    query.extend_from_slice(&[0x00, 0x00]); // ARCOUNT = 0
    for label in host.split('.') {
        query.push(label.len() as u8);
        query.extend_from_slice(label.as_bytes());
    }
    query.push(0x00); // terminator
    query.extend_from_slice(&[0x00, 0x01]); // QTYPE = A
    query.extend_from_slice(&[0x00, 0x01]); // QCLASS = IN

    // Send query over UDP
    let socket = UdpSocket::bind("0.0.0.0:0")
        .await
        .map_err(|e| crate::Error::Transport(format!("DNS: bind: {e}").into()))?;
    socket
        .connect(dns_addr)
        .await
        .map_err(|e| crate::Error::Transport(format!("DNS: connect {dns_server}: {e}").into()))?;
    socket
        .send(&query)
        .await
        .map_err(|e| crate::Error::Transport(format!("DNS: send to {dns_server}: {e}").into()))?;

    let mut buf = [0u8; 512];
    let n = timeout(Duration::from_secs(5), socket.recv(&mut buf))
        .await
        .map_err(|_| crate::Error::Transport("DNS: timeout".into()))?
        .map_err(|e| crate::Error::Transport(format!("DNS: recv: {e}").into()))?;

    // Parse response
    let response = &buf[..n];
    if response.len() < 12 {
        return Err(crate::Error::Transport("DNS: response too short".into()));
    }

    // Verify transaction ID
    let resp_txid = u16::from_be_bytes([response[0], response[1]]);
    if resp_txid != txid {
        return Err(crate::Error::Transport(
            format!("DNS: txid mismatch (sent {txid}, got {resp_txid})").into(),
        ));
    }

    let ancount = u16::from_be_bytes([response[6], response[7]]) as usize;
    if ancount == 0 {
        return Err(crate::Error::Transport(
            format!("DNS resolve {host}: no records found").into(),
        ));
    }

    // Skip 12-byte header + question section to reach answers
    let mut pos = 12;
    pos = skip_dns_name(response, pos); // QNAME
    pos += 4; // QTYPE (2) + QCLASS (2)

    // Read answers
    for _ in 0..ancount {
        if pos + 10 > response.len() {
            return Err(crate::Error::Transport(
                "DNS: truncated answer section".into(),
            ));
        }
        pos = skip_dns_name(response, pos); // NAME (may be compression pointer)
        let qtype = u16::from_be_bytes([response[pos], response[pos + 1]]);
        let rdlength = u16::from_be_bytes([response[pos + 8], response[pos + 9]]) as usize;
        pos += 10; // past TYPE(2)+CLASS(2)+TTL(4)+RDLENGTH(2)
        if pos + rdlength > response.len() {
            return Err(crate::Error::Transport("DNS: truncated RDATA".into()));
        }
        if qtype == 1 && rdlength == 4 {
            // A record: 4-byte IPv4 address
            let ip = std::net::Ipv4Addr::new(
                response[pos],
                response[pos + 1],
                response[pos + 2],
                response[pos + 3],
            );
            return Ok(ip.to_string());
        }
        pos += rdlength;
    }

    Err(crate::Error::Transport(
        format!("DNS resolve {host}: no A record found").into(),
    ))
}

/// Skip a DNS name in the response, handling compression pointers.
/// Returns the new position after the name.
fn skip_dns_name(response: &[u8], mut pos: usize) -> usize {
    loop {
        if pos >= response.len() {
            return pos;
        }
        let len = response[pos];
        if len == 0 {
            return pos + 1; // end of name
        }
        if len & 0xC0 == 0xC0 {
            return pos + 2; // compression pointer (2 bytes total)
        }
        pos += 1 + len as usize; // label
    }
}

/// Direct TCP connection with optional bind and keepalive.
async fn connect_direct(
    addr: &str,
    peer: std::net::SocketAddr,
    opts: &DialOptions,
) -> Result<tokio::net::TcpStream, crate::Error> {
    use tokio::net::TcpSocket;
    use tokio::time::{timeout, Duration};

    // Create socket for optional local bind
    let socket = if peer.is_ipv4() {
        TcpSocket::new_v4()
    } else {
        TcpSocket::new_v6()
    }
    .map_err(|e| crate::Error::Transport(format!("create socket: {e}").into()))?;

    // Bind to specific local IP if configured
    if let Some(ref bind_ip) = opts.bind_addr {
        let bind_addr: std::net::SocketAddr = format!("{bind_ip}:0").parse().map_err(|e| {
            crate::Error::Transport(format!("invalid bind_addr '{bind_ip}': {e}").into())
        })?;
        socket
            .bind(bind_addr)
            .map_err(|e| crate::Error::Transport(format!("bind to {bind_ip}: {e}").into()))?;
    }

    let stream = timeout(
        Duration::from_secs(opts.dial_timeout_secs),
        socket.connect(peer),
    )
    .await
    .map_err(|_| crate::Error::Transport(format!("dial timeout to {addr}").into()))?
    .map_err(|e| crate::Error::Transport(format!("dial to {addr}: {e}").into()))?;

    // Configure TCP keepalive after connection
    if opts.keepalive_secs > 0 {
        let keepalive = socket2::SockRef::from(&stream);
        let ka = socket2::TcpKeepalive::new().with_time(Duration::from_secs(opts.keepalive_secs));
        keepalive
            .set_tcp_keepalive(&ka)
            .map_err(|e| crate::Error::Transport(format!("set keepalive: {e}").into()))?;
    }

    // Disable Nagle for low-latency small-message RTT (Go frp parity).
    crate::transport::set_nodelay(&stream);

    Ok(stream)
}

/// Enable TCP_NODELAY (disable Nagle) on a stream, matching Go frp's default
/// (`net.TCPConn` sets NoDelay(true)). A failed socket option must not kill the
/// connection, so errors are logged at debug and ignored. Wire-invisible.
pub fn set_nodelay(stream: &tokio::net::TcpStream) {
    if let Err(e) = stream.set_nodelay(true) {
        tracing::debug!(error = %e, "set_nodelay failed (continuing with Nagle on)");
    }
}

/// Set TCP keepalive interval on a stream, matching Go frp's server-side
/// `muxer.SetKeepAlive(7200s)` behavior. Uses socket2 to configure the
/// keepalive timeout. A failed socket option is logged at debug and ignored
/// — consistent with `set_nodelay` error-handling policy.
pub fn set_keepalive(stream: &tokio::net::TcpStream, secs: u64) {
    if secs == 0 {
        return;
    }
    let keepalive = socket2::SockRef::from(stream);
    let ka = socket2::TcpKeepalive::new().with_time(Duration::from_secs(secs));
    if let Err(e) = keepalive.set_tcp_keepalive(&ka) {
        tracing::debug!(error = %e, keepalive_secs = secs,
            "set_keepalive failed (continuing without keepalive)");
    }
}

/// Connect to a target through an HTTP CONNECT or SOCKS5 proxy.
/// Returns a raw TcpStream that tunnels to `target_host:target_port`.
async fn connect_via_proxy(
    proxy_url: &str,
    target_host: &str,
    target_port: u16,
    dial_timeout_secs: u64,
) -> Result<tokio::net::TcpStream, crate::Error> {
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
    use tokio::time::{timeout, Duration};

    let (scheme, auth, proxy_host, proxy_port) = parse_proxy_url(proxy_url)?;
    let proxy_addr = format!("{proxy_host}:{proxy_port}");
    let proxy_peer: std::net::SocketAddr = proxy_addr.parse().map_err(|e| {
        crate::Error::Transport(format!("invalid proxy address '{proxy_addr}': {e}").into())
    })?;

    let mut stream = timeout(
        Duration::from_secs(dial_timeout_secs),
        tokio::net::TcpStream::connect(proxy_peer),
    )
    .await
    .map_err(|_| crate::Error::Transport(format!("proxy dial timeout to {proxy_addr}").into()))?
    .map_err(|e| crate::Error::Transport(format!("proxy dial to {proxy_addr}: {e}").into()))?;

    match scheme {
        "http" | "https" => {
            // HTTP CONNECT tunnel. Go golib: proxy auth via Basic
            // Authorization on the CONNECT request.
            let auth_header = match auth {
                Some((user, pass)) => format!(
                    "Proxy-Authorization: Basic {}\r\n",
                    base64_encode(format!("{user}:{pass}").as_bytes())
                ),
                None => String::new(),
            };
            let connect_req = format!(
                "CONNECT {target_host}:{target_port} HTTP/1.1\r\nHost: {target_host}:{target_port}\r\n{auth_header}\r\n"
            );
            timeout(
                Duration::from_secs(dial_timeout_secs),
                stream.write_all(connect_req.as_bytes()),
            )
            .await
            .map_err(|_| crate::Error::Transport("proxy CONNECT write timeout".into()))?
            .map_err(|e| crate::Error::Transport(format!("proxy CONNECT write: {e}").into()))?;

            let mut reader = BufReader::new(&mut stream);

            const HTTP_PROXY_MAX_LINE: usize = 16 * 1024; // 16 KiB per line
            const HTTP_PROXY_MAX_TOTAL: usize = 64 * 1024; // 64 KiB total headers

            let mut total_read = 0usize;

            // Read status line with size limit
            let mut status_buf = Vec::new();
            timeout(
                Duration::from_secs(dial_timeout_secs),
                reader.read_until(b'\n', &mut status_buf),
            )
            .await
            .map_err(|_| crate::Error::Transport("proxy CONNECT read timeout".into()))?
            .map_err(|e| crate::Error::Transport(format!("proxy CONNECT read: {e}").into()))?;

            total_read += status_buf.len();
            if status_buf.len() > HTTP_PROXY_MAX_LINE {
                return Err(crate::Error::Transport(
                    "proxy CONNECT status line too long".into(),
                ));
            }
            if total_read > HTTP_PROXY_MAX_TOTAL {
                return Err(crate::Error::Transport(
                    "proxy CONNECT headers too large".into(),
                ));
            }

            let status_line = String::from_utf8_lossy(&status_buf);
            if !status_line.contains("200") {
                return Err(crate::Error::Transport(
                    format!("proxy CONNECT rejected: {}", status_line.trim()).into(),
                ));
            }

            // Read remaining headers until \r\n\r\n with per-line and total limits
            loop {
                let mut line_buf = Vec::new();
                timeout(
                    Duration::from_secs(dial_timeout_secs),
                    reader.read_until(b'\n', &mut line_buf),
                )
                .await
                .map_err(|_| crate::Error::Transport("proxy CONNECT headers timeout".into()))?
                .map_err(|e| {
                    crate::Error::Transport(format!("proxy CONNECT headers: {e}").into())
                })?;

                total_read += line_buf.len();
                if line_buf.len() > HTTP_PROXY_MAX_LINE {
                    return Err(crate::Error::Transport(
                        "proxy CONNECT header line too long".into(),
                    ));
                }
                if total_read > HTTP_PROXY_MAX_TOTAL {
                    return Err(crate::Error::Transport(
                        "proxy CONNECT headers too large".into(),
                    ));
                }

                if line_buf == b"\r\n" || line_buf.is_empty() {
                    break;
                }
            }
        }
        "socks5" | "socks5h" => {
            // SOCKS5 handshake. Go golib semantics:
            // - "socks5": target hostname resolved locally (must be an IP
            //   by the time it reaches us); "socks5h": remote DNS — the
            //   hostname is sent to the proxy via ATYP 0x03.
            // - userinfo → RFC 1929 username/password auth (method 0x02).
            let use_auth = auth.is_some();
            let methods: &[u8] = if use_auth {
                &[0x05, 0x02, 0x00, 0x02] // no-auth + user/pass
            } else {
                &[0x05, 0x01, 0x00] // no-auth only
            };
            timeout(
                Duration::from_secs(dial_timeout_secs),
                stream.write_all(methods),
            )
            .await
            .map_err(|_| crate::Error::Transport("SOCKS5 auth write timeout".into()))?
            .map_err(|e| crate::Error::Transport(format!("SOCKS5 auth write: {e}").into()))?;

            // 2. Read server response: [0x05, method]
            let mut auth_resp = [0u8; 2];
            timeout(
                Duration::from_secs(dial_timeout_secs),
                stream.read_exact(&mut auth_resp),
            )
            .await
            .map_err(|_| crate::Error::Transport("SOCKS5 auth read timeout".into()))?
            .map_err(|e| crate::Error::Transport(format!("SOCKS5 auth read: {e}").into()))?;

            if auth_resp[0] != 0x05 {
                return Err(crate::Error::Transport(
                    format!("SOCKS5 auth rejected: {:02x?}", auth_resp).into(),
                ));
            }

            if auth_resp[1] == 0x02 {
                // RFC 1929 username/password sub-negotiation.
                let (user, pass) = auth.expect("method 0x02 requires userinfo");
                let mut auth_msg = Vec::with_capacity(3 + user.len() + pass.len());
                auth_msg.push(0x01);
                auth_msg.push(user.len() as u8);
                auth_msg.extend_from_slice(user.as_bytes());
                auth_msg.push(pass.len() as u8);
                auth_msg.extend_from_slice(pass.as_bytes());
                timeout(
                    Duration::from_secs(dial_timeout_secs),
                    stream.write_all(&auth_msg),
                )
                .await
                .map_err(|_| crate::Error::Transport("SOCKS5 user/pass write timeout".into()))?
                .map_err(|e| {
                    crate::Error::Transport(format!("SOCKS5 user/pass write: {e}").into())
                })?;
                let mut auth_status = [0u8; 2];
                timeout(
                    Duration::from_secs(dial_timeout_secs),
                    stream.read_exact(&mut auth_status),
                )
                .await
                .map_err(|_| crate::Error::Transport("SOCKS5 user/pass read timeout".into()))?
                .map_err(|e| {
                    crate::Error::Transport(format!("SOCKS5 user/pass read: {e}").into())
                })?;
                if auth_status[0] != 0x01 || auth_status[1] != 0x00 {
                    return Err(crate::Error::Transport(
                        format!("SOCKS5 user/pass auth failed: {:02x?}", auth_status).into(),
                    ));
                }
            } else if auth_resp[1] != 0x00 {
                return Err(crate::Error::Transport(
                    format!("SOCKS5 auth rejected: method={}", auth_resp[1]).into(),
                ));
            }

            // 3. Build the CONNECT request. socks5h sends the hostname as a
            // domain (ATYP 0x03) so the proxy performs remote DNS; plain
            // socks5 requires an IP (resolved locally).
            let mut connect_req = Vec::with_capacity(10 + target_host.len());
            connect_req.extend_from_slice(&[0x05, 0x01, 0x00]); // SOCKS5, CONNECT, reserved
            if scheme == "socks5h" {
                let domain = target_host.as_bytes();
                if domain.is_empty() || domain.len() > 255 {
                    return Err(crate::Error::Transport(
                        "SOCKS5h: invalid domain length".into(),
                    ));
                }
                connect_req.push(0x03); // domain
                connect_req.push(domain.len() as u8);
                connect_req.extend_from_slice(domain);
            } else {
                let target_ip: std::net::IpAddr = target_host.parse().map_err(|_| {
                    crate::Error::Transport(
                        format!("SOCKS5: cannot resolve hostname '{target_host}' — use socks5h or an IP").into(),
                    )
                })?;
                match target_ip {
                    std::net::IpAddr::V4(ip) => {
                        connect_req.push(0x01); // IPv4
                        connect_req.extend_from_slice(&ip.octets());
                    }
                    std::net::IpAddr::V6(ip) => {
                        connect_req.push(0x04); // IPv6
                        connect_req.extend_from_slice(&ip.octets());
                    }
                }
            }
            connect_req.extend_from_slice(&target_port.to_be_bytes());

            timeout(
                Duration::from_secs(dial_timeout_secs),
                stream.write_all(&connect_req),
            )
            .await
            .map_err(|_| crate::Error::Transport("SOCKS5 connect write timeout".into()))?
            .map_err(|e| crate::Error::Transport(format!("SOCKS5 connect write: {e}").into()))?;

            // 4. Read connect response: [0x05, rep, 0x00, atyp, bind_addr..., bind_port...]
            let mut resp = [0u8; 10];
            timeout(
                Duration::from_secs(dial_timeout_secs),
                stream.read_exact(&mut resp),
            )
            .await
            .map_err(|_| crate::Error::Transport("SOCKS5 connect read timeout".into()))?
            .map_err(|e| crate::Error::Transport(format!("SOCKS5 connect read: {e}").into()))?;

            if resp[0] != 0x05 || resp[1] != 0x00 {
                return Err(crate::Error::Transport(
                    format!("SOCKS5 connect rejected: rep=0x{:02x}", resp[1]).into(),
                ));
            }

            // Read remaining bind address bytes.
            // resp[4..10] already contains first 6 bytes of bind address.
            // IPv4: 4(IP)+2(port)=6 → all already in resp[4..10] → extra=0.
            // IPv6: 16(IP)+2(port)=18 → 6 in resp[4..10] → extra=12.
            let extra = match resp[3] {
                0x01 => 0,
                0x04 => 12,
                _ => 0,
            };
            if extra > 0 {
                let mut extra_buf = vec![0u8; extra as usize];
                timeout(
                    Duration::from_secs(dial_timeout_secs),
                    stream.read_exact(&mut extra_buf),
                )
                .await
                .map_err(|_| crate::Error::Transport("SOCKS5 bind addr read timeout".into()))?
                .map_err(|e| {
                    crate::Error::Transport(format!("SOCKS5 bind addr read: {e}").into())
                })?;
            }
        }
        other => {
            return Err(crate::Error::Transport(
                format!("unsupported proxy scheme: '{other}'. Supported: http, socks5, socks5h")
                    .into(),
            ));
        }
    }

    // Disable Nagle on the tunneled stream (Go frp parity).
    crate::transport::set_nodelay(&stream);

    Ok(stream)
}

/// Parse a proxy URL into (scheme, auth, host, port).
///
/// Supports `scheme://host:port` and `scheme://user:pass@host:port`
/// (Go golib `ParseProxyURL` semantics). `auth` is `Some((user, pass))`
/// when userinfo is present.
#[allow(clippy::type_complexity)]
fn parse_proxy_url(url: &str) -> Result<(&str, Option<(&str, &str)>, &str, u16), crate::Error> {
    let (scheme, rest) = url.split_once("://").ok_or_else(|| {
        crate::Error::Transport(format!("invalid proxy URL '{url}': missing scheme").into())
    })?;

    // Optional userinfo: "user:pass@host:port" (golib ParseProxyURL).
    let (auth, hostport) = match rest.rsplit_once('@') {
        Some((userinfo, hostport)) if !userinfo.is_empty() && !hostport.is_empty() => {
            let (user, pass) = match userinfo.split_once(':') {
                Some((u, p)) => (u, p),
                None => (userinfo, ""),
            };
            (Some((user, pass)), hostport)
        }
        _ => (None, rest),
    };

    let (host, port_str) = if let Some((h, p)) = hostport.rsplit_once(':') {
        (h, p)
    } else {
        return Err(crate::Error::Transport(
            format!("invalid proxy URL '{url}': missing port").into(),
        ));
    };

    let port: u16 = port_str.parse().map_err(|_| {
        crate::Error::Transport(format!("invalid proxy port '{port_str}' in '{url}'").into())
    })?;

    // Strip brackets from IPv6 addresses
    let host = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);

    Ok((scheme, auth, host, port))
}

/// Connect to the server with the given options.
pub async fn dial_server(opts: &DialOptions) -> Result<IoStream, crate::Error> {
    #[cfg(any(feature = "tls", feature = "websocket"))]
    use tokio::io::AsyncWriteExt;

    // Resolve server_addr via custom DNS server if configured.
    // Otherwise let TcpStream::connect use system DNS.
    let target_ip = if let Some(ref dns) = opts.dns_server {
        if !dns.is_empty() {
            resolve_host_with_dns(&opts.server_addr, dns).await?
        } else {
            opts.server_addr.clone()
        }
    } else {
        opts.server_addr.clone()
    };
    let addr = format!("{target_ip}:{}", opts.server_port);
    let peer: std::net::SocketAddr = match addr.parse() {
        Ok(peer) => peer,
        Err(_) => {
            // target_ip is a hostname, not an IP — resolve via system DNS.
            // Mirrors what TcpStream::connect(addr) did before b4a9359.
            tokio::net::lookup_host(&addr)
                .await
                .map_err(|e| {
                    crate::Error::Transport(format!("invalid server address '{addr}': {e}").into())
                })?
                .next()
                .ok_or_else(|| {
                    crate::Error::Transport(
                        format!("DNS resolve '{addr}': no records found").into(),
                    )
                })?
        }
    };

    match opts.protocol {
        #[cfg(feature = "kcp")]
        TransportProtocol::Kcp => {
            let addr = format!("{target_ip}:{}", opts.server_port);
            let stream = crate::kcp::dial_kcp(&addr, crate::kcp::default_kcp_client_config())
                .await
                .map_err(|e| crate::Error::Transport(format!("KCP dial: {e}").into()))?;
            // KCP+TLS (Go frp compat): Go frpc wraps the KCP stream in TLS
            // with the 0x17 head byte; the server accept path handles both
            // 0x17-prefixed and raw ClientHello.
            if opts.tls_enable {
                #[cfg(not(feature = "tls"))]
                {
                    Err(crate::Error::Transport(
                        "TLS support not compiled (enable the 'tls' feature)".into(),
                    ))
                }
                #[cfg(feature = "tls")]
                {
                    let mut stream = stream;
                    if !opts.disable_custom_tls_first_byte {
                        stream.write_all(&[FRP_TLS_HEAD_BYTE]).await.map_err(|e| {
                            crate::Error::Transport(format!("write TLS head byte: {e}").into())
                        })?;
                    }
                    let connector = build_tls_connector_skip_verify(
                        opts.tls_ca_file.as_deref(),
                        opts.tls_cert_file.as_deref(),
                        opts.tls_key_file.as_deref(),
                    )?;
                    let server_name = if !opts.tls_server_name.is_empty() {
                        opts.tls_server_name.clone()
                    } else {
                        opts.server_addr.clone()
                    };
                    let server_name = rustls::pki_types::ServerName::try_from(server_name)
                        .map_err(|e| {
                            crate::Error::Transport(format!("invalid server name: {e}").into())
                        })?;
                    let peer_addr = peer;
                    let tls = connector.connect(server_name, stream).await.map_err(|e| {
                        crate::Error::Transport(format!("KCP TLS connect: {e}").into())
                    })?;
                    return Ok(IoStream::Tls(
                        Box::new(tokio_rustls::TlsStream::Client(tls)),
                        peer_addr,
                    ));
                }
            } else {
                return Ok(IoStream::Kcp(stream));
            }
        }
        #[cfg(feature = "quic")]
        TransportProtocol::Quic => {
            let addr = format!("{target_ip}:{}", opts.server_port);
            let server_name = if !opts.tls_server_name.is_empty() {
                &opts.tls_server_name
            } else {
                &opts.server_addr
            };
            let ca_file = opts.tls_ca_file.as_deref();
            let (stream, _conn) = crate::quic::dial_quic(&addr, server_name, ca_file)
                .await
                .map_err(|e| crate::Error::Transport(format!("QUIC dial: {e}").into()))?;
            return Ok(IoStream::Quic(stream));
        }
        _ => {}
    }

    // TCP, WebSocket, WSS: connect via upstream proxy if configured, otherwise direct TCP.
    #[cfg_attr(not(feature = "tls"), allow(unused_mut))]
    let mut stream = if let Some(ref proxy_url) = opts.proxy_url {
        if proxy_url.is_empty() {
            // Empty string = direct connection
            connect_direct(&addr, peer, opts).await?
        } else {
            // socks5h: the proxy resolves the hostname (remote DNS) — pass the
            // original server_addr instead of the locally resolved IP.
            let proxy_target = if proxy_url.starts_with("socks5h://") {
                &opts.server_addr
            } else {
                &target_ip
            };
            connect_via_proxy(
                proxy_url,
                proxy_target,
                opts.server_port,
                opts.dial_timeout_secs,
            )
            .await?
        }
    } else {
        connect_direct(&addr, peer, opts).await?
    };

    // Tls detect / yamux wrapping / V2-V1 detection are all handled by the
    // accept-side dispatch. The dial side writes V2 magic at the call site
    // (control.rs) after all transport layers are established, matching Go frp
    // v0.70's pattern (WriteMagicIfV2 on the fully-upgraded connector result).
    match opts.protocol {
        TransportProtocol::Tcp => {
            if opts.tls_enable {
                #[cfg(not(feature = "tls"))]
                {
                    Err(crate::Error::Transport(
                        "TLS support not compiled (enable the 'tls' feature)".into(),
                    ))
                }
                #[cfg(feature = "tls")]
                {
                    if !opts.disable_custom_tls_first_byte {
                        // Write FRPTLSHeadByte (0x17) before TLS handshake, matching Go frp v0.69.1
                        stream.write_all(&[FRP_TLS_HEAD_BYTE]).await.map_err(|e| {
                            crate::Error::Transport(format!("write TLS head byte: {e}").into())
                        })?;
                    }
                    let connector = build_tls_connector_skip_verify(
                        opts.tls_ca_file.as_deref(),
                        opts.tls_cert_file.as_deref(),
                        opts.tls_key_file.as_deref(),
                    )?;
                    let server_name = if !opts.tls_server_name.is_empty() {
                        opts.tls_server_name.clone()
                    } else {
                        opts.server_addr.clone()
                    };
                    let server_name = rustls::pki_types::ServerName::try_from(server_name)
                        .map_err(|e| {
                            crate::Error::Transport(format!("invalid server name: {e}").into())
                        })?;
                    let peer_addr = peer;
                    let tls = connector
                        .connect(server_name, stream)
                        .await
                        .map_err(|e| crate::Error::Transport(format!("TLS connect: {e}").into()))?;
                    Ok(IoStream::Tls(
                        Box::new(tokio_rustls::TlsStream::Client(tls)),
                        peer_addr,
                    ))
                }
            } else {
                Ok(IoStream::Tcp(stream))
            }
        }
        #[cfg(feature = "websocket")]
        TransportProtocol::WebSocket | TransportProtocol::Wss => {
            let is_wss = opts.protocol == TransportProtocol::Wss || opts.tls_enable;
            let host = if !opts.tls_server_name.is_empty() {
                opts.tls_server_name.clone()
            } else {
                opts.server_addr.clone()
            };

            if is_wss {
                // WSS raw mode: TLS handshake + manual HTTP upgrade.
                // Avoids tungstenite UTF-8 validation on TEXT frames from Go frps.
                #[cfg(not(feature = "tls"))]
                {
                    return Err(crate::Error::Transport(
                        "TLS support not compiled (enable the 'tls' feature for WSS)".into(),
                    ));
                }
                #[cfg(feature = "tls")]
                {
                    if !opts.disable_custom_tls_first_byte {
                        stream.write_all(&[FRP_TLS_HEAD_BYTE]).await.map_err(|e| {
                            crate::Error::Transport(format!("write TLS head byte: {e}").into())
                        })?;
                    }
                    let connector = build_tls_connector_skip_verify(
                        opts.tls_ca_file.as_deref(),
                        opts.tls_cert_file.as_deref(),
                        opts.tls_key_file.as_deref(),
                    )?;
                    let server_name = if !opts.tls_server_name.is_empty() {
                        opts.tls_server_name.clone()
                    } else {
                        opts.server_addr.clone()
                    };
                    let server_name = rustls::pki_types::ServerName::try_from(server_name)
                        .map_err(|e| {
                            crate::Error::Transport(format!("invalid server name: {e}").into())
                        })?;
                    let tls_stream = connector
                        .connect(server_name, stream)
                        .await
                        .map_err(|e| crate::Error::Transport(format!("TLS connect: {e}").into()))?;
                    connect_ws_raw(
                        tls_stream,
                        &host,
                        opts.server_port,
                        FRP_WEBSOCKET_PATH,
                        "https",
                    )
                    .await
                }
            } else {
                // Plain WS: use raw mode to tolerate TEXT frames with
                // non-UTF-8 payload from Go frps (golang.org/x/net/websocket).
                connect_ws_raw(stream, &host, opts.server_port, FRP_WEBSOCKET_PATH, "http").await
            }
        }
        #[cfg(feature = "kcp")]
        TransportProtocol::Kcp => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "KCP should be handled before TCP connect path",
        )
        .into()),
        #[cfg(feature = "quic")]
        TransportProtocol::Quic => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "QUIC should be handled before TCP connect path",
        )
        .into()),
    }
}

/// Detect connection type by reading first 7 bytes from the stream (consuming).
///
/// If the 7 bytes match V2 magic, returns `(V2, IoStream::Tcp(stream))` —
/// magic consumed, stream ready for V2 framing.
///
/// If no match, wraps consumed bytes in `IoStream::PreRead` and classifies
/// by the first byte. Downstream handlers receive the exact same byte stream.
///
/// ## Read timeout
///
/// No timeout is applied inside this function: the caller wraps the call with
/// the connection-read timeout so the value stays in one place. frp-server
/// applies 10s, matching the compile-time `connReadTimeout = 10 * time.Second`
/// constant in Go frp v0.70.1 `server/service.go`. That constant is **not**
/// configurable — there is no `ServerConfig.Transport.connReadTimeout` field.
pub async fn detect_and_strip_magic(
    mut stream: tokio::net::TcpStream,
) -> Result<(ConnectionType, IoStream), crate::Error> {
    use tokio::io::AsyncReadExt;

    let mut magic_buf = [0u8; 7];
    if let Err(e) = stream.read_exact(&mut magic_buf).await {
        return Err(crate::Error::Transport(
            format!("read connection magic: {e}").into(),
        ));
    }

    if magic_buf == crate::protocol::V2_MAGIC_BYTES {
        return Ok((ConnectionType::V2, IoStream::Tcp(stream)));
    }

    let first_byte = magic_buf[0];
    let ct = match first_byte {
        FRP_TLS_HEAD_BYTE | FRP_TLS_DIRECT_BYTE => ConnectionType::Tls(first_byte),
        #[cfg(feature = "websocket")]
        b'G' => ConnectionType::WebSocket,
        b => ConnectionType::V1(b),
    };

    Ok((ct, IoStream::PreRead(magic_buf.to_vec(), stream)))
}

// consume_tls_head_byte removed — dead code. detect_and_strip_magic
// consumes TLS magic upfront during connection classification.

/// Base64 encode (RFC 4648). Shared by the WebSocket upgrade key and the
/// HTTP proxy Basic auth header — kept outside the websocket feature gate.
fn base64_encode(bytes: &[u8]) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut s = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let triple = (b0 << 16) | (b1 << 8) | b2;
        s.push(CHARS[((triple >> 18) & 0x3f) as usize] as char);
        s.push(CHARS[((triple >> 12) & 0x3f) as usize] as char);
        if chunk.len() > 1 {
            s.push(CHARS[((triple >> 6) & 0x3f) as usize] as char);
        } else {
            s.push('=');
        }
        if chunk.len() > 2 {
            s.push(CHARS[(triple & 0x3f) as usize] as char);
        } else {
            s.push('=');
        }
    }
    s
}

/// Accept a WebSocket connection on a raw TcpStream.
///
/// Does NOT use tungstenite — Go frp v0.70.1 (`golang.org/x/net/websocket`)
/// sends frp V1 frames as BINARY frames (BinaryFrame). The Raw path handles
/// both binary and text frames for backward compatibility.
///
/// This implementation handles the HTTP upgrade manually and returns a
/// WsByteStream in Raw mode — all data frames are treated as opaque bytes.
#[cfg(feature = "websocket")]
pub async fn accept_websocket(stream: IoStream) -> Result<IoStream, crate::Error> {
    use tokio::io::{AsyncWriteExt, BufReader};

    let mut reader = BufReader::new(stream);
    let mut key = String::new();
    let mut is_upgrade = false;
    let mut first_line = true;
    let mut valid_path = false;

    // Read HTTP upgrade request with size limits and timeout.
    // Uses a bounded byte-oriented parser: checks limits BEFORE extending
    // buffers, unlike read_line which extends the String unboundedly until
    // a newline arrives.
    const MAX_LINE_LEN: usize = 16 * 1024; // 16 KiB per header line
    const MAX_TOTAL_HEADERS: usize = 64 * 1024; // 64 KiB total headers
    const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

    let header_result = tokio::time::timeout(HANDSHAKE_TIMEOUT, async {
        use tokio::io::AsyncReadExt;
        let mut buf = Vec::with_capacity(4096);
        let mut total_bytes = 0usize;
        loop {
            // Read one byte at a time to stay bounded. BufReader's internal
            // buffer (default 8 KiB) amortises the syscall cost, so this is
            // not one syscall per byte.
            let mut byte = [0u8; 1];
            reader
                .read_exact(&mut byte)
                .await
                .map_err(|e| crate::Error::Transport(format!("WS read request: {e}").into()))?;
            buf.push(byte[0]);
            total_bytes += 1;

            // Check total limit BEFORE allowing more reads.
            if total_bytes > MAX_TOTAL_HEADERS {
                return Err(crate::Error::Transport(TransportError::WebSocketUpgrade(
                    "request headers too large".into(),
                )));
            }

            // Only parse when we hit a newline.
            if byte[0] != b'\n' {
                continue;
            }

            // Got a complete line — check per-line length.
            if buf.len() > MAX_LINE_LEN {
                return Err(crate::Error::Transport(TransportError::WebSocketUpgrade(
                    format!(
                        "header line too long ({} bytes, max {})",
                        buf.len(),
                        MAX_LINE_LEN
                    ),
                )));
            }

            let line = String::from_utf8_lossy(&buf);
            let line_str = line.as_ref();

            if line_str == "\r\n" || line_str == "\n" || line_str.is_empty() {
                break;
            }
            if first_line {
                // Validate request line: GET /~!frp HTTP/1.x
                first_line = false;
                let parts: Vec<&str> = line_str.split_whitespace().collect();
                if parts.len() < 2 || !parts[0].eq_ignore_ascii_case("GET") {
                    return Err(crate::Error::Transport(TransportError::WebSocketUpgrade(
                        format!("expected GET request, got: {}", line_str.trim()),
                    )));
                }
                if parts[1] == FRP_WEBSOCKET_PATH {
                    valid_path = true;
                }
            }
            if line_str.len() > 1 {
                let lower = line_str.to_lowercase();
                if lower.starts_with("sec-websocket-key:") {
                    key = line_str
                        .split_once(':')
                        .map(|x| x.1)
                        .unwrap_or("")
                        .trim()
                        .to_string();
                } else if lower.starts_with("upgrade:") && lower.contains("websocket") {
                    is_upgrade = true;
                }
            }
            // Reset for next line.
            buf.clear();
        }
        Ok(())
    })
    .await;

    match header_result {
        Ok(Ok(())) => {}
        Ok(Err(e)) => return Err(e),
        Err(_elapsed) => {
            return Err(crate::Error::Transport(TransportError::WebSocketUpgrade(
                "handshake timed out".into(),
            )));
        }
    }

    if key.is_empty() {
        return Err(crate::Error::Transport("Missing Sec-WebSocket-Key".into()));
    }
    if !is_upgrade {
        return Err(crate::Error::Transport(TransportError::WebSocketUpgrade(
            "missing Upgrade: websocket header".into(),
        )));
    }
    if !valid_path {
        return Err(crate::Error::Transport(TransportError::WebSocketUpgrade(
            format!("unexpected path (expected {})", FRP_WEBSOCKET_PATH),
        )));
    }

    // Compute accept key: base64(sha1(key + magic GUID))
    use sha1::{Digest, Sha1};
    let mut hasher = Sha1::new();
    hasher.update(key.as_bytes());
    hasher.update(b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
    let hash = hasher.finalize();
    let accept = base64_encode(&hash);

    // Send HTTP 101 Switching Protocols.
    // Capture any bytes BufReader may have read-ahead past headers
    // (defensive: client should wait for 101 before sending frames).
    let leftover = reader.buffer().to_vec();
    tracing::debug!(
        leftover_len = leftover.len(),
        leftover_first16 = %if !leftover.is_empty() {
            leftover.iter().take(16).map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join("")
        } else {
            String::from("(empty)")
        },
        "accept_websocket leftover: {} bytes",
        leftover.len()
    );
    let mut stream = reader.into_inner();

    let resp = format!(
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n"
    );
    stream
        .write_all(resp.as_bytes())
        .await
        .map_err(|e| crate::Error::Transport(format!("WS write response: {e}").into()))?;

    // Feed leftover BufReader bytes back so WsByteStream parses them
    // as WebSocket frames. Works with any IoStream variant (Tcp, Tls,
    // BufferedRead, etc.) — no TcpStream extraction needed.
    let raw_stream: Box<dyn AsyncReadWrite> = if !leftover.is_empty() {
        tracing::trace!(
            leftover_len = leftover.len(),
            "Replaying {} BufReader leftover bytes for WS frame parsing",
            leftover.len()
        );
        Box::new(IoStream::BufferedRead(leftover, 0, Box::new(stream)))
    } else {
        Box::new(stream)
    };
    let ws = WsByteStream::from_raw(raw_stream, false);
    Ok(IoStream::WebSocket(ws))
}

/// Accept a WebSocket upgrade from pre-peeked HTTP request bytes and a raw stream.
///
/// Unlike [`accept_websocket`], this function does NOT wrap the stream in a
/// `BufReader` — it parses the HTTP request from `peeked` (already read from the
/// stream) and writes the 101 response directly to `raw`. Any bytes pipelined
/// after the HTTP headers (`extra`) are replayed through a single
/// [`IoStream::BufferedRead`] layer placed *below* the WsByteStream, so they
/// reach the WS frame parser's input before any further socket bytes. This is
/// the correct replay mechanism: a `BufReader` would silently swallow bytes and
/// corrupt reads when the inner stream is TLS, whereas a single `BufferedRead`
/// only prepends the captured plaintext and preserves ordering.
#[cfg(feature = "websocket")]
pub async fn accept_websocket_from_peeked(
    peeked: Vec<u8>,
    mut raw: IoStream,
) -> Result<IoStream, crate::Error> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // Parse HTTP headers from peeked data with size limits and timeout,
    // matching accept_websocket()'s protections.
    const MAX_TOTAL_HEADERS: usize = 64 * 1024;
    const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

    let mut buf = peeked;
    let mut read_more = false;
    let extra: Vec<u8> = tokio::time::timeout(HANDSHAKE_TIMEOUT, async {
        loop {
            if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                let tail = buf.split_off(pos + 4);
                buf.truncate(pos + 4);
                return Ok::<_, crate::Error>(tail);
            }
            read_more = true;
            // Check size limit BEFORE reading more.
            if buf.len() >= MAX_TOTAL_HEADERS {
                return Err(crate::Error::Transport(TransportError::WebSocketUpgrade(
                    "request headers too large".into(),
                )));
            }
            let mut chunk = vec![0u8; 1024];
            let n = raw.read(&mut chunk).await.map_err(|e| {
                crate::Error::Transport(format!("WS read remaining headers: {e}").into())
            })?;
            if n == 0 {
                return Err(crate::Error::Transport(
                    "WS: connection closed during headers".into(),
                ));
            }
            tracing::debug!(
                read_n = n,
                chunk_hex = %crate::hex_encode(&chunk[..n.min(32)]),
                "accept_websocket_from_peeked: read {} more bytes from raw stream",
                n
            );
            buf.extend_from_slice(&chunk[..n]);
        }
    })
    .await
    .map_err(|_| {
        crate::Error::Transport(TransportError::WebSocketUpgrade(
            "handshake timed out".into(),
        ))
    })??;

    tracing::debug!(
        peeked_len = buf.len(),
        read_more = read_more,
        extra_len = extra.len(),
        "accept_websocket_from_peeked: headers complete"
    );

    let headers_str = String::from_utf8_lossy(&buf);
    let mut key = String::new();
    let mut is_upgrade = false;
    let mut first_line = true;
    let mut valid_path = false;
    for line in headers_str.lines() {
        if first_line {
            first_line = false;
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                if !parts[0].eq_ignore_ascii_case("GET") {
                    return Err(crate::Error::Transport(TransportError::WebSocketUpgrade(
                        format!("expected GET request, got: {}", line),
                    )));
                }
                if parts[1] == FRP_WEBSOCKET_PATH {
                    valid_path = true;
                }
            }
        }
        if line.len() > 1 {
            let lower = line.to_lowercase();
            if lower.starts_with("sec-websocket-key:") {
                key = line
                    .split_once(':')
                    .map(|x| x.1)
                    .unwrap_or("")
                    .trim()
                    .to_string();
            } else if lower.starts_with("upgrade:") && lower.contains("websocket") {
                is_upgrade = true;
            }
        }
    }

    if key.is_empty() {
        return Err(crate::Error::Transport("Missing Sec-WebSocket-Key".into()));
    }
    if !is_upgrade {
        return Err(crate::Error::Transport(TransportError::WebSocketUpgrade(
            "missing Upgrade: websocket header".into(),
        )));
    }
    if !valid_path {
        return Err(crate::Error::Transport(TransportError::WebSocketUpgrade(
            format!("unexpected path (expected {})", FRP_WEBSOCKET_PATH),
        )));
    }

    // Compute accept key: base64(sha1(key + magic GUID))
    use sha1::{Digest, Sha1};
    let mut hasher = Sha1::new();
    hasher.update(key.as_bytes());
    hasher.update(b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
    let hash = hasher.finalize();
    let accept = base64_encode(&hash);

    // Send 101 Switching Protocols
    let resp = format!(
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n"
    );
    raw.write_all(resp.as_bytes())
        .await
        .map_err(|e| crate::Error::Transport(format!("WS write response: {e}").into()))?;

    if !extra.is_empty() {
        tracing::debug!(
            extra_len = extra.len(),
            "Pipelined data after HTTP headers — wrapping in BufferedRead for WS frame parsing"
        );
        let inner = IoStream::BufferedRead(extra, 0, Box::new(raw));
        let ws = WsByteStream::from_raw(Box::new(inner), false);
        Ok(IoStream::WebSocket(ws))
    } else {
        let ws = WsByteStream::from_raw(Box::new(raw), false);
        Ok(IoStream::WebSocket(ws))
    }
}

/// Connect via WebSocket using manual HTTP upgrade (Raw mode, client side).
/// Returns an IoStream with a WsByteStream adapter in client mode,
/// so callers can use read_msg_v1/write_msg_v1 directly.
///
/// Unlike the tungstenite path, Raw mode tolerates TEXT frames containing
/// non-UTF-8 payload — Go frp v0.69.1 (`golang.org/x/net/websocket`) sends
/// encrypted binary data in TEXT frames, which violates RFC 6455 §5.6.
/// Raw mode treats all data frames as opaque bytes.
///
/// The returned WsByteStream masks outgoing frames per RFC 6455 §5.3.
#[cfg(feature = "websocket")]
pub async fn connect_ws_raw<S>(
    stream: S,
    host: &str,
    port: u16,
    path: &str,
    origin_scheme: &str,
) -> Result<IoStream, crate::Error>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    let mut stream = stream;

    // Generate WebSocket key: 16 random bytes, base64 encoded
    let key_bytes: [u8; 16] = rand::random();
    let key = base64_encode(&key_bytes);

    let req = format!(
        "GET {path} HTTP/1.1\r\n\
         Host: {host}:{port}\r\n\
         Connection: Upgrade\r\n\
         Upgrade: websocket\r\n\
         Sec-WebSocket-Version: 13\r\n\
         Sec-WebSocket-Key: {key}\r\n\
         Origin: {origin_scheme}://{host}:{port}\r\n\
         \r\n"
    );

    stream
        .write_all(req.as_bytes())
        .await
        .map_err(|e| crate::Error::Transport(format!("WS raw connect write: {e}").into()))?;

    // Read HTTP 101 response with timeout.
    // BufReader may buffer WebSocket frame bytes past \r\n\r\n — capture
    // them before into_inner() to avoid permanent stream desync.
    let (stream, leftover) = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        let mut reader = BufReader::new(stream);
        let mut status_line = String::new();
        reader.read_line(&mut status_line).await.map_err(|e| {
            crate::Error::Transport(format!("WS raw connect read status: {e}").into())
        })?;

        if !status_line.starts_with("HTTP/1.1 101") {
            return Err(crate::Error::Transport(
                format!("WS upgrade rejected: {}", status_line.trim()).into(),
            ));
        }

        // Consume response headers until \r\n\r\n
        loop {
            let mut line = String::new();
            reader.read_line(&mut line).await.map_err(|e| {
                crate::Error::Transport(format!("WS raw connect read headers: {e}").into())
            })?;
            if line == "\r\n" || line.is_empty() {
                break;
            }
        }

        let leftover = reader.buffer().to_vec();
        let stream = reader.into_inner();
        Ok::<_, crate::Error>((stream, leftover))
    })
    .await
    .map_err(|_| {
        crate::Error::Transport("WS raw connect: timeout waiting for 101 response".into())
    })??;

    let ws = if leftover.is_empty() {
        WsByteStream::from_raw(Box::new(stream), true)
    } else {
        // Go frps may pipeline the first WS frame in the same TCP segment
        // as the 101 response. Feed the leftover bytes through the raw WS
        // frame parser (PrependStream) so frame headers are consumed and
        // only the payload reaches the application.
        let prepend = PrependStream {
            prepend: leftover,
            pos: 0,
            inner: Box::new(stream),
        };
        WsByteStream::from_raw(Box::new(prepend), true)
    };
    Ok(IoStream::WebSocket(ws))
}

/// TLS configuration.
#[cfg(feature = "tls")]
#[derive(Debug, Clone)]
pub struct TlsConfig {
    pub enable: bool,
    pub cert_file: Option<String>,
    pub key_file: Option<String>,
    pub ca_file: Option<String>,
}

/// Build a [`rustls::ServerConfig`] from PEM-encoded cert and key files.
/// If `ca_file` is provided, client certificates are required and verified (mTLS).
#[cfg(feature = "tls")]
pub fn build_tls_server_config(
    cert_file: &str,
    key_file: &str,
    ca_file: Option<&str>,
) -> Result<rustls::ServerConfig, crate::Error> {
    use rustls::pki_types::pem::PemObject;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};

    let cert_bytes = std::fs::read(cert_file).map_err(|e| {
        crate::Error::Transport(TransportError::Other(format!("open cert file: {e}")))
    })?;
    let certs = CertificateDer::pem_slice_iter(&cert_bytes)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| crate::Error::Transport(TransportError::Other(format!("read certs: {e}"))))?;

    let key_bytes = std::fs::read(key_file).map_err(|e| {
        crate::Error::Transport(TransportError::Other(format!("open key file: {e}")))
    })?;
    let key = PrivateKeyDer::from_pem_slice(&key_bytes).map_err(|e| {
        crate::Error::Transport(TransportError::Other(format!("read private key: {e}")))
    })?;

    // Build server config with optional client certificate verification (mTLS)
    let config = if let Some(ca_path) = ca_file {
        if !ca_path.is_empty() {
            let mut roots = rustls::RootCertStore::empty();
            let ca_bytes = std::fs::read(ca_path).map_err(|e| {
                crate::Error::Transport(TransportError::Other(format!("open CA file: {e}")))
            })?;
            let ca_certs = CertificateDer::pem_slice_iter(&ca_bytes)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| {
                    crate::Error::Transport(TransportError::Other(format!("read CA certs: {e}")))
                })?;
            roots.add_parsable_certificates(ca_certs);

            let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(roots))
                .build()
                .map_err(|e| {
                    crate::Error::Transport(TransportError::Other(format!(
                        "build client cert verifier: {e}"
                    )))
                })?;

            rustls::ServerConfig::builder()
                .with_client_cert_verifier(verifier)
                .with_single_cert(certs, key)
                .map_err(|e| {
                    crate::Error::Transport(TransportError::Other(format!(
                        "build mTLS config: {e}"
                    )))
                })?
        } else {
            rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(certs, key)
                .map_err(|e| {
                    crate::Error::Transport(TransportError::Other(format!("build TLS config: {e}")))
                })?
        }
    } else {
        rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|e| {
                crate::Error::Transport(TransportError::Other(format!("build TLS config: {e}")))
            })?
    };

    Ok(config)
}

/// Create a TLS acceptor from PEM-encoded cert and key files.
/// If ca_file is provided, client certificates will be verified against it (mTLS).
#[cfg(feature = "tls")]
pub fn build_tls_acceptor(
    cert_file: &str,
    key_file: &str,
    ca_file: Option<&str>,
) -> Result<TlsAcceptor, crate::Error> {
    let config = build_tls_server_config(cert_file, key_file, ca_file)?;
    Ok(TlsAcceptor::from(Arc::new(config)))
}

/// Generate a self-signed TLS certificate and build a [`rustls::ServerConfig`].
///
/// Matches Go frp's `newRandomTLSKeyPair()` behavior: when no cert/key files
/// are configured, frps auto-generates a self-signed cert so it can always
/// accept TLS connections (Go frpc sends TLS ClientHello by default).
///
/// Uses ECDSA P-256 (ring backend) — Go frp uses RSA 2048 but the algorithm
/// difference is irrelevant for TLS compatibility.
#[cfg(feature = "tls")]
fn generate_self_signed_cert_and_key() -> Result<
    (
        rustls::pki_types::CertificateDer<'static>,
        rustls::pki_types::PrivateKeyDer<'static>,
    ),
    crate::Error,
> {
    use rcgen::{CertificateParams, DistinguishedName, DnType, IsCa, KeyPair};

    let key_pair = KeyPair::generate().map_err(|e| {
        crate::Error::Transport(TransportError::Other(format!("generate TLS key pair: {e}")))
    })?;

    let mut params = CertificateParams::new(vec!["frp".to_string()]).map_err(|e| {
        crate::Error::Transport(TransportError::Other(format!(
            "create TLS cert params: {e}"
        )))
    })?;

    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "frp");
    dn.push(DnType::OrganizationName, "frp-rs auto-generated");
    params.distinguished_name = dn;
    params.is_ca = IsCa::NoCa;
    params.key_usages = vec![
        rcgen::KeyUsagePurpose::DigitalSignature,
        rcgen::KeyUsagePurpose::KeyEncipherment,
    ];
    // Uses rcgen's default validity (now → now + 365 days).
    // Go frp uses 10 years but the auto-generated cert is regenerated on every
    // frps restart, so a shorter validity is acceptable.

    let cert = params.self_signed(&key_pair).map_err(|e| {
        crate::Error::Transport(TransportError::Other(format!("self-sign TLS cert: {e}")))
    })?;

    let cert_der = cert.der().clone();
    let key_der: rustls::pki_types::PrivateKeyDer<'static> =
        rustls::pki_types::PrivatePkcs8KeyDer::from(key_pair.serialize_der()).into();

    Ok((cert_der, key_der))
}

#[cfg(feature = "tls")]
pub fn generate_self_signed_tls_config() -> Result<rustls::ServerConfig, crate::Error> {
    let (cert_der, key_der) = generate_self_signed_cert_and_key()?;
    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .map_err(|e| {
            crate::Error::Transport(TransportError::Other(format!(
                "build TLS config from generated cert: {e}"
            )))
        })?;

    Ok(config)
}

/// Build a self-signed server identity, optionally requiring and verifying
/// client certificates against `ca_file` (mTLS). Go frp does this whenever
/// `trustedCaFile` is set, even with a generated server certificate.
#[cfg(feature = "tls")]
pub fn generate_self_signed_tls_config_with_ca(
    ca_file: Option<&str>,
) -> Result<rustls::ServerConfig, crate::Error> {
    let (cert_der, key_der) = generate_self_signed_cert_and_key()?;
    match ca_file {
        Some(ca_path) if !ca_path.is_empty() => {
            let roots = build_root_store(Some(ca_path))?.ok_or_else(|| {
                crate::Error::Transport(TransportError::Other("empty client CA store".into()))
            })?;
            let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(roots))
                .build()
                .map_err(|e| {
                    crate::Error::Transport(TransportError::Other(format!(
                        "build client cert verifier: {e}"
                    )))
                })?;
            rustls::ServerConfig::builder()
                .with_client_cert_verifier(verifier)
                .with_single_cert(vec![cert_der], key_der)
                .map_err(|e| {
                    crate::Error::Transport(TransportError::Other(format!(
                        "build mTLS config from generated cert: {e}"
                    )))
                })
        }
        _ => rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key_der)
            .map_err(|e| {
                crate::Error::Transport(TransportError::Other(format!(
                    "build TLS config from generated cert: {e}"
                )))
            }),
    }
}

/// Build a [`TlsAcceptor`] from cert/key files, or auto-generate a self-signed
/// cert when no files are configured (matching Go frp behavior).
///
/// When both `cert_file` and `key_file` are non-empty, this delegates to
/// [`build_tls_acceptor`]. When `ca_file` is non-empty, the acceptor always
/// requires and verifies client certificates (mTLS), even when the server
/// identity is a generated self-signed certificate (Go frp compat).
/// Providing exactly one of cert/key is a startup error.
#[cfg(feature = "tls")]
pub fn build_tls_acceptor_or_generate(
    cert_file: &str,
    key_file: &str,
    ca_file: Option<&str>,
) -> Result<TlsAcceptor, crate::Error> {
    let cert_set = !cert_file.is_empty();
    let key_set = !key_file.is_empty();
    if cert_set != key_set {
        return Err(crate::Error::Transport(TransportError::Other(
            "TLS requires both cert_file and key_file to be set; got only one".into(),
        )));
    }
    if cert_set {
        return build_tls_acceptor(cert_file, key_file, ca_file);
    }
    tracing::info!("No TLS cert files configured — auto-generating self-signed certificate");
    let config = generate_self_signed_tls_config_with_ca(ca_file)?;
    Ok(TlsAcceptor::from(Arc::new(config)))
}

/// Build a `RootCertStore` from a custom CA file path.
/// Returns `None` when no custom CA is specified (caller should use
/// the platform verifier instead).
#[cfg(feature = "tls")]
pub fn build_root_store(
    ca_file: Option<&str>,
) -> Result<Option<rustls::RootCertStore>, crate::Error> {
    use rustls::pki_types::pem::PemObject;
    use rustls::pki_types::CertificateDer;

    match ca_file {
        Some(ca_path) if !ca_path.is_empty() => {
            let mut root_store = rustls::RootCertStore::empty();
            let ca_bytes = std::fs::read(ca_path).map_err(|e| {
                crate::Error::Transport(TransportError::Other(format!("open CA file: {e}")))
            })?;
            let certs = CertificateDer::pem_slice_iter(&ca_bytes)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| {
                    crate::Error::Transport(TransportError::Other(format!("read CA certs: {e}")))
                })?;
            root_store.add_parsable_certificates(certs);
            Ok(Some(root_store))
        }
        _ => Ok(None),
    }
}

/// Create a TLS connector with platform certificate verification.
///
/// Uses the OS platform trust store for certificate verification (safe default).
/// Used by plugin backends connecting to user-specified HTTPS servers.
///
/// If ca_file is provided, verifies against that custom root store instead.
/// If cert_file/key_file are provided, present client certificate to server (mTLS).
#[cfg(feature = "tls")]
pub fn build_tls_connector(
    ca_file: Option<&str>,
    cert_file: Option<&str>,
    key_file: Option<&str>,
) -> Result<TlsConnector, crate::Error> {
    use rustls::pki_types::pem::PemObject;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};

    let root_store = build_root_store(ca_file)?;

    let config = if let Some(store) = root_store {
        // Custom CA: verify against the provided root store.
        if let (Some(cert_path), Some(key_path)) = (cert_file, key_file) {
            if !cert_path.is_empty() && !key_path.is_empty() {
                let cert_bytes = std::fs::read(cert_path).map_err(|e| {
                    crate::Error::Transport(TransportError::Other(format!(
                        "open client cert file: {e}"
                    )))
                })?;
                let client_certs = CertificateDer::pem_slice_iter(&cert_bytes)
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|e| {
                        crate::Error::Transport(TransportError::Other(format!(
                            "read client certs: {e}"
                        )))
                    })?;
                let key_bytes = std::fs::read(key_path).map_err(|e| {
                    crate::Error::Transport(TransportError::Other(format!(
                        "open client key file: {e}"
                    )))
                })?;
                let client_key = PrivateKeyDer::from_pem_slice(&key_bytes).map_err(|e| {
                    crate::Error::Transport(TransportError::Other(format!("read client key: {e}")))
                })?;
                rustls::ClientConfig::builder()
                    .with_root_certificates(Arc::new(store))
                    .with_client_auth_cert(client_certs, client_key)
                    .map_err(|e| {
                        crate::Error::Transport(TransportError::Other(format!(
                            "build mTLS client config: {e}"
                        )))
                    })?
            } else {
                rustls::ClientConfig::builder()
                    .with_root_certificates(Arc::new(store))
                    .with_no_client_auth()
            }
        } else {
            rustls::ClientConfig::builder()
                .with_root_certificates(Arc::new(store))
                .with_no_client_auth()
        }
    } else {
        // No custom CA: use platform verifier for OS trust store (default safe behavior).
        // Used by plugin backends connecting to user-specified HTTPS servers.
        if let (Some(cert_path), Some(key_path)) = (cert_file, key_file) {
            if !cert_path.is_empty() && !key_path.is_empty() {
                let cert_bytes = std::fs::read(cert_path).map_err(|e| {
                    crate::Error::Transport(TransportError::Other(format!(
                        "open client cert file: {e}"
                    )))
                })?;
                let client_certs = CertificateDer::pem_slice_iter(&cert_bytes)
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|e| {
                        crate::Error::Transport(TransportError::Other(format!(
                            "read client certs: {e}"
                        )))
                    })?;
                let key_bytes = std::fs::read(key_path).map_err(|e| {
                    crate::Error::Transport(TransportError::Other(format!(
                        "open client key file: {e}"
                    )))
                })?;
                let client_key = PrivateKeyDer::from_pem_slice(&key_bytes).map_err(|e| {
                    crate::Error::Transport(TransportError::Other(format!("read client key: {e}")))
                })?;
                rustls::ClientConfig::builder()
                    .with_platform_verifier()
                    .map_err(|e| {
                        crate::Error::Transport(TransportError::Other(format!(
                            "platform verifier: {e}"
                        )))
                    })?
                    .with_client_auth_cert(client_certs, client_key)
                    .map_err(|e| {
                        crate::Error::Transport(TransportError::Other(format!(
                            "build mTLS client config: {e}"
                        )))
                    })?
            } else {
                rustls::ClientConfig::builder()
                    .with_platform_verifier()
                    .map_err(|e| {
                        crate::Error::Transport(TransportError::Other(format!(
                            "platform verifier: {e}"
                        )))
                    })?
                    .with_no_client_auth()
            }
        } else {
            <rustls::ClientConfig as ConfigVerifierExt>::with_platform_verifier().map_err(|e| {
                crate::Error::Transport(TransportError::Other(format!("platform verifier: {e}")))
            })?
        }
    };

    Ok(TlsConnector::from(Arc::new(config)))
}

/// Build a TLS connector that skips certificate verification.
///
/// Matches Go frp's `NewClientTLSConfig` behavior when no CA file is configured:
/// sets `InsecureSkipVerify=true`, accepting any server certificate (including
/// self-signed). Used for frp control connections to Go frp servers which
/// auto-generate self-signed certificates.
///
/// If cert_file/key_file are provided, present client certificate to server (mTLS).
#[cfg(feature = "tls")]
pub fn build_tls_connector_skip_verify(
    ca_file: Option<&str>,
    cert_file: Option<&str>,
    key_file: Option<&str>,
) -> Result<TlsConnector, crate::Error> {
    use rustls::pki_types::pem::PemObject;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};

    let root_store = build_root_store(ca_file)?;

    let config = if let Some(store) = root_store {
        // Custom CA provided: verify against it normally.
        if let (Some(cert_path), Some(key_path)) = (cert_file, key_file) {
            if !cert_path.is_empty() && !key_path.is_empty() {
                let cert_bytes = std::fs::read(cert_path).map_err(|e| {
                    crate::Error::Transport(TransportError::Other(format!(
                        "open client cert file: {e}"
                    )))
                })?;
                let client_certs = CertificateDer::pem_slice_iter(&cert_bytes)
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|e| {
                        crate::Error::Transport(TransportError::Other(format!(
                            "read client certs: {e}"
                        )))
                    })?;
                let key_bytes = std::fs::read(key_path).map_err(|e| {
                    crate::Error::Transport(TransportError::Other(format!(
                        "open client key file: {e}"
                    )))
                })?;
                let client_key = PrivateKeyDer::from_pem_slice(&key_bytes).map_err(|e| {
                    crate::Error::Transport(TransportError::Other(format!("read client key: {e}")))
                })?;
                rustls::ClientConfig::builder()
                    .with_root_certificates(Arc::new(store))
                    .with_client_auth_cert(client_certs, client_key)
                    .map_err(|e| {
                        crate::Error::Transport(TransportError::Other(format!(
                            "build mTLS client config: {e}"
                        )))
                    })?
            } else {
                rustls::ClientConfig::builder()
                    .with_root_certificates(Arc::new(store))
                    .with_no_client_auth()
            }
        } else {
            rustls::ClientConfig::builder()
                .with_root_certificates(Arc::new(store))
                .with_no_client_auth()
        }
    } else {
        // No CA file: skip certificate verification (InsecureSkipVerify=true).
        // Matches Go frp's default — auto-generated self-signed certs.
        tracing::warn!(
            "TLS certificate verification disabled (InsecureSkipVerify=true). \
             Set tls.ca_file in config to enable verification."
        );
        let verifier = Arc::new(InsecureSkipVerify);
        if let (Some(cert_path), Some(key_path)) = (cert_file, key_file) {
            if !cert_path.is_empty() && !key_path.is_empty() {
                let cert_bytes = std::fs::read(cert_path).map_err(|e| {
                    crate::Error::Transport(TransportError::Other(format!(
                        "open client cert file: {e}"
                    )))
                })?;
                let client_certs = CertificateDer::pem_slice_iter(&cert_bytes)
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|e| {
                        crate::Error::Transport(TransportError::Other(format!(
                            "read client certs: {e}"
                        )))
                    })?;
                let key_bytes = std::fs::read(key_path).map_err(|e| {
                    crate::Error::Transport(TransportError::Other(format!(
                        "open client key file: {e}"
                    )))
                })?;
                let client_key = PrivateKeyDer::from_pem_slice(&key_bytes).map_err(|e| {
                    crate::Error::Transport(TransportError::Other(format!("read client key: {e}")))
                })?;
                rustls::ClientConfig::builder()
                    .dangerous()
                    .with_custom_certificate_verifier(verifier)
                    .with_client_auth_cert(client_certs, client_key)
                    .map_err(|e| {
                        crate::Error::Transport(TransportError::Other(format!(
                            "build mTLS client config with skip-verify: {e}"
                        )))
                    })?
            } else {
                rustls::ClientConfig::builder()
                    .dangerous()
                    .with_custom_certificate_verifier(verifier)
                    .with_no_client_auth()
            }
        } else {
            rustls::ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(verifier)
                .with_no_client_auth()
        }
    };

    Ok(TlsConnector::from(Arc::new(config)))
}

/// A certificate verifier that accepts all server certificates (InsecureSkipVerify=true).
#[cfg(feature = "tls")]
#[derive(Debug)]
pub(crate) struct InsecureSkipVerify;

#[cfg(feature = "tls")]
impl rustls::client::danger::ServerCertVerifier for InsecureSkipVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ED25519,
        ]
    }
}

/// A stream wrapper that yields pre-read bytes before the inner stream.
/// Used when bytes have been consumed for protocol detection (e.g., SNI peek)
/// but need to be replayed for the actual protocol handler (e.g., TLS handshake).
pub struct PreReadStream<S> {
    pre_read: Vec<u8>,
    pos: usize,
    inner: S,
}

impl<S> PreReadStream<S> {
    pub fn new(pre_read: Vec<u8>, inner: S) -> Self {
        Self {
            pre_read,
            pos: 0,
            inner,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for PreReadStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.pos < self.pre_read.len() {
            let remaining = &self.pre_read[self.pos..];
            let n = remaining.len().min(buf.remaining());
            buf.put_slice(&remaining[..n]);
            self.pos += n;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for PreReadStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(feature = "websocket")]
    fn ws_frame_cap_covers_v2_aead_overhead() {
        // The transport frame cap must accept a full-size V2 frame plus the
        // AEAD overhead (tag + nonce), not just the plaintext cap.
        assert!(MAX_WS_FRAME_PAYLOAD >= crate::protocol::V2_MAX_FRAME_PAYLOAD as u64 + 128);
    }

    /// Go frps may send the first WS frame in the same TCP segment as the
    /// HTTP 101 response. The client must parse the frame instead of
    /// exposing frame bytes as application bytes.
    #[tokio::test]
    #[cfg(feature = "websocket")]
    async fn ws_client_parses_pipelined_frame_after_upgrade() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let (client, mut server) = tokio::io::duplex(8192);
        let payload: &[u8] = b"hello-from-go-frps";
        let mut frame = vec![0x82u8, payload.len() as u8]; // FIN + BINARY
        frame.extend_from_slice(payload);

        let server_task = tokio::spawn(async move {
            // Consume the upgrade request up to the blank line.
            let mut req = vec![0u8; 4096];
            let mut total = 0usize;
            loop {
                let n = server.read(&mut req[total..]).await.expect("read request");
                assert!(n > 0, "client closed before request completed");
                total += n;
                if req[..total].windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            // 101 response + first WS frame in a single segment.
            server
                .write_all(
                    b"HTTP/1.1 101 Switching Protocols\r\n\
                      Upgrade: websocket\r\n\
                      Connection: Upgrade\r\n\
                      \r\n",
                )
                .await
                .expect("write 101");
            server
                .write_all(&frame)
                .await
                .expect("write pipelined frame");
        });

        let mut io = connect_ws_raw(client, "example.com", 7000, FRP_WEBSOCKET_PATH, "http")
            .await
            .expect("ws upgrade");

        let mut buf = [0u8; 64];
        let n = io.read(&mut buf).await.expect("read ws payload");
        assert_eq!(
            &buf[..n],
            payload,
            "read must return the frame payload only, got: {:?}",
            &buf[..n]
        );
        server_task.await.expect("server task");
    }

    #[test]
    #[cfg(feature = "tls")]
    fn test_build_tls_connector_with_platform_verifier() {
        let result = build_tls_connector(None, None, None);
        assert!(
            result.is_ok(),
            "TLS connector with default roots should build"
        );
    }

    #[test]
    #[cfg(feature = "tls")]
    fn test_build_tls_acceptor_missing_cert() {
        let result = build_tls_acceptor("/nonexistent/cert.pem", "/nonexistent/key.pem", None);
        assert!(
            result.is_err(),
            "TLS acceptor with missing files should fail"
        );
    }

    #[test]
    #[cfg(feature = "tls")]
    fn test_build_tls_acceptor_or_generate_rejects_partial_cert_key() {
        let cert_only = build_tls_acceptor_or_generate("/tmp/cert.pem", "", None)
            .err()
            .expect("cert without key must fail");
        assert!(
            cert_only
                .to_string()
                .contains("both cert_file and key_file"),
            "unexpected error: {cert_only}"
        );
        let key_only = build_tls_acceptor_or_generate("", "/tmp/key.pem", None)
            .err()
            .expect("key without cert must fail");
        assert!(
            key_only.to_string().contains("both cert_file and key_file"),
            "unexpected error: {key_only}"
        );
    }

    #[tokio::test]
    #[cfg(feature = "tls")]
    async fn test_generated_mtls_rejects_client_without_cert() {
        use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair};
        use rustls::pki_types::ServerName;
        use std::io::Write;
        use std::sync::Arc;
        use tokio::net::{TcpListener, TcpStream};
        use tokio_rustls::TlsConnector;

        let mut ca_params =
            CertificateParams::new(Vec::<String>::default()).expect("empty SAN is valid");
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params
            .key_usages
            .push(rcgen::KeyUsagePurpose::DigitalSignature);
        ca_params
            .key_usages
            .push(rcgen::KeyUsagePurpose::KeyCertSign);
        ca_params.key_usages.push(rcgen::KeyUsagePurpose::CrlSign);
        let ca_key = KeyPair::generate().expect("generate CA key");
        let ca_cert = ca_params
            .self_signed(&ca_key)
            .expect("self-sign CA certificate");

        let mut ca_file = tempfile::NamedTempFile::new().expect("create CA tempfile");
        let ca_der = ca_cert.der();
        let ca_b64 = data_encoding::BASE64.encode(ca_der.as_ref());
        let mut ca_pem = String::from("-----BEGIN CERTIFICATE-----\n");
        for chunk in ca_b64.as_bytes().chunks(64) {
            ca_pem.push_str(std::str::from_utf8(chunk).expect("base64 is ASCII"));
            ca_pem.push('\n');
        }
        ca_pem.push_str("-----END CERTIFICATE-----\n");
        ca_file.write_all(ca_pem.as_bytes()).expect("write CA PEM");

        let acceptor = build_tls_acceptor_or_generate(
            "",
            "",
            Some(ca_file.path().to_str().expect("temp path")),
        )
        .expect("generated identity with CA must build");

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind listener");
        let addr = listener.local_addr().expect("listener addr");
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept connection");
            acceptor.accept(stream).await
        });

        let client_config = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(InsecureSkipVerify))
            .with_no_client_auth();
        let connector = TlsConnector::from(Arc::new(client_config));
        let tcp = TcpStream::connect(addr).await.expect("connect to server");
        let _handshake = connector
            .connect(ServerName::try_from("frp").expect("valid server name"), tcp)
            .await;

        let server_result = tokio::time::timeout(std::time::Duration::from_secs(5), server)
            .await
            .expect("server handshake must not hang")
            .expect("server task must complete");
        assert!(
            server_result.is_err(),
            "mTLS acceptor must reject a client without a certificate"
        );
    }

    #[cfg(feature = "websocket")]
    fn ws_binary_frame(payload: &[u8]) -> Vec<u8> {
        let mut frame = vec![0x82];
        if payload.len() <= 125 {
            frame.push(payload.len() as u8);
        } else if payload.len() <= u16::MAX as usize {
            frame.push(126);
            frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        } else {
            frame.push(127);
            frame.extend_from_slice(&(payload.len() as u64).to_be_bytes());
        }
        frame.extend_from_slice(payload);
        frame
    }

    #[tokio::test]
    #[cfg(feature = "websocket")]
    async fn ws_raw_accepts_v2_sized_frames_and_rejects_oversized() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let (mut server_io, client_io) = tokio::io::duplex(1024 * 1024);
        let mut ws = WsByteStream::from_raw(Box::new(client_io), false);

        // Between the old 14 KiB clamp and the V2 64 KiB cap: the WS
        // transport must accept it; V1 enforcement happens in protocol.rs.
        let payload = vec![0x5a; 20 * 1024];
        server_io
            .write_all(&ws_binary_frame(&payload))
            .await
            .unwrap();
        let mut out = vec![0u8; payload.len()];
        let n = ws.read(&mut out).await.unwrap();
        assert_eq!(n, payload.len());
        assert_eq!(&out[..n], &payload[..]);

        // Exactly 64 KiB is the V2 limit and must pass the WS decoder.
        let big = vec![0x6b; 64 * 1024];
        server_io.write_all(&ws_binary_frame(&big)).await.unwrap();
        let mut big_out = vec![0u8; big.len()];
        let n2 = ws.read(&mut big_out).await.unwrap();
        assert_eq!(n2, big.len());
        assert_eq!(&big_out[..n2], &big[..]);

        // A V2 frame at the cap plus AEAD overhead (128 bytes) is accepted —
        // the transport must not clamp encrypted V2 frames below the cap.
        let aead_padded = vec![0x6c; 64 * 1024 + 128];
        server_io
            .write_all(&ws_binary_frame(&aead_padded))
            .await
            .unwrap();
        let mut padded_out = vec![0u8; aead_padded.len()];
        let n3 = ws.read(&mut padded_out).await.unwrap();
        assert_eq!(n3, aead_padded.len());
        assert_eq!(&padded_out[..n3], &aead_padded[..]);

        // One byte over the cap + AEAD overhead is rejected at the transport.
        let huge = vec![0x6c; 64 * 1024 + 129];
        server_io.write_all(&ws_binary_frame(&huge)).await.unwrap();
        let err = ws.read(&mut big_out).await.unwrap_err();
        assert!(
            err.to_string().contains("WS frame too large"),
            "unexpected error: {err}"
        );
    }
}
