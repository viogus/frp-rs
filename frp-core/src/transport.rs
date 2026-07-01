use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
#[cfg(feature = "websocket")]
use tokio_tungstenite::tungstenite::Message;
#[cfg(feature = "websocket")]
use futures_util::{sink::Sink, Stream};
use tokio::net::TcpStream;
#[cfg(feature = "websocket")]
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};
#[cfg(feature = "kcp")]
use crate::kcp::KcpStream;
#[cfg(feature = "quic")]
use crate::quic::QuicStream;

#[cfg(feature = "tls")]
use std::sync::Arc;
#[cfg(feature = "tls")]
use tokio_rustls::TlsAcceptor;
#[cfg(feature = "tls")]
use tokio_rustls::TlsConnector;

use crate::mux::YamuxStream;

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
            _ => TransportProtocol::Tcp,
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
/// - Raw: server side (manual framing, tolerates text frames with non-UTF-8
///   payload — Go frp v0.69.1 sends these via golang.org/x/net/websocket)
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
            debug_assert!(payload.len() <= 125, "WS pong payload too long for short framing ({} bytes), would be truncated", payload.len());
            let mut pong = vec![0x8a, payload.len() as u8];
            pong.extend_from_slice(payload);
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
        // SAFETY: WsByteStream is Unpin (all fields are Unpin), so
        // Pin<&mut Self> is equivalent to &mut Self with no move risk.
        let this = unsafe { self.as_mut().get_unchecked_mut() };
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
            WsInner::Tungstenite(inner) => {
                loop {
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
                }
            }
            WsInner::Raw(raw) => {
                loop {
                    match raw_read_state {
                        RawReadState::Idle => {
                            *raw_read_state = RawReadState::ReadingHeader { head: [0u8; 2], filled: 0 };
                            continue;
                        }
                        RawReadState::ReadingHeader { ref mut head, ref mut filled } => {
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
                                        *raw_read_state = RawReadState::ReadingExtendedLen2 { ext: [0u8; 2], filled: 0 };
                                    } else if raw_len == 127 {
                                        *raw_read_state = RawReadState::ReadingExtendedLen8 { ext: [0u8; 8], filled: 0 };
                                    } else {
                                        if raw_len > crate::protocol::V1_MAX_MSG_LENGTH as u64 + 4096 {
                                            *raw_read_state = RawReadState::Idle;
                                            return Poll::Ready(Err(io::Error::new(
                                                io::ErrorKind::InvalidData,
                                                "WS frame too large",
                                            )));
                                        }
                                        *raw_frame_payload_len = raw_len;
                                        if masked {
                                            *raw_read_state = RawReadState::ReadingMaskKey { mask_key: [0u8; 4], filled: 0 };
                                        } else if raw_len > 0 {
                                            *raw_read_state = RawReadState::ReadingPayload { payload: vec![0u8; raw_len as usize], filled: 0 };
                                        } else {
                                            let disp = dispatch_raw_frame(
                                                read_buf, read_pos,
                                                raw_read_state, *raw_frame_opcode,
                                                raw, cx, buf, &[],
                                            );
                                            if disp.is_pending() { continue; } else { return disp; }
                                        }
                                    }
                                    continue;
                                }
                                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                                Poll::Pending => return Poll::Pending,
                            }
                        }
                        RawReadState::ReadingExtendedLen2 { ref mut ext, ref mut filled } => {
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
                                    if payload_len > crate::protocol::V1_MAX_MSG_LENGTH as u64 + 4096 {
                                        *raw_read_state = RawReadState::Idle;
                                        return Poll::Ready(Err(io::Error::new(
                                            io::ErrorKind::InvalidData,
                                            "WS frame too large",
                                        )));
                                    }
                                    *raw_frame_payload_len = payload_len;
                                    if *raw_frame_masked {
                                        *raw_read_state = RawReadState::ReadingMaskKey { mask_key: [0u8; 4], filled: 0 };
                                    } else if payload_len > 0 {
                                        *raw_read_state = RawReadState::ReadingPayload { payload: vec![0u8; payload_len as usize], filled: 0 };
                                    } else {
                                        let disp = dispatch_raw_frame(
                                            read_buf, read_pos,
                                            raw_read_state, *raw_frame_opcode,
                                            raw, cx, buf, &[],
                                        );
                                        if disp.is_pending() { continue; } else { return disp; }
                                    }
                                    continue;
                                }
                                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                                Poll::Pending => return Poll::Pending,
                            }
                        }
                        RawReadState::ReadingExtendedLen8 { ref mut ext, ref mut filled } => {
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
                                    if payload_len > crate::protocol::V1_MAX_MSG_LENGTH as u64 + 4096 {
                                        *raw_read_state = RawReadState::Idle;
                                        return Poll::Ready(Err(io::Error::new(
                                            io::ErrorKind::InvalidData,
                                            "WS frame too large",
                                        )));
                                    }
                                    *raw_frame_payload_len = payload_len;
                                    if *raw_frame_masked {
                                        *raw_read_state = RawReadState::ReadingMaskKey { mask_key: [0u8; 4], filled: 0 };
                                    } else if payload_len > 0 {
                                        *raw_read_state = RawReadState::ReadingPayload { payload: vec![0u8; payload_len as usize], filled: 0 };
                                    } else {
                                        let disp = dispatch_raw_frame(
                                            read_buf, read_pos,
                                            raw_read_state, *raw_frame_opcode,
                                            raw, cx, buf, &[],
                                        );
                                        if disp.is_pending() { continue; } else { return disp; }
                                    }
                                    continue;
                                }
                                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                                Poll::Pending => return Poll::Pending,
                            }
                        }
                        RawReadState::ReadingMaskKey { ref mut mask_key, ref mut filled } => {
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
                                        *raw_read_state = RawReadState::ReadingPayload { payload: vec![0u8; pl as usize], filled: 0 };
                                    } else {
                                        let disp = dispatch_raw_frame(
                                            read_buf, read_pos,
                                            raw_read_state, *raw_frame_opcode,
                                            raw, cx, buf, &[],
                                        );
                                        if disp.is_pending() { continue; } else { return disp; }
                                    }
                                    continue;
                                }
                                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                                Poll::Pending => return Poll::Pending,
                            }
                        }
                        RawReadState::ReadingPayload { ref mut payload, ref mut filled } => {
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
                                        read_buf, read_pos,
                                        raw_read_state, *raw_frame_opcode,
                                        raw, cx, buf, &owned_payload,
                                    );
                                    if disp.is_pending() { continue; } else { return disp; }
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
                            match tungstenite.as_mut().start_send(Message::Binary(buf.to_vec())) {
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
                WsInner::poll_write_raw(
                    raw, cx, buf,
                    write_buf, write_pos, needs_flush,
                    new_frame,
                )
            }
        }
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        // Destructure to get separate borrows — same pattern as poll_write.
        let this = &mut *self;
        let WsByteStream { inner, write_buf, write_pos, needs_flush, .. } = this;
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

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        match &mut self.inner {
            WsInner::Tungstenite(inner) => inner
                .as_mut()
                .poll_close(cx)
                .map_err(io::Error::other),
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

/// Unified stream type for TCP, TLS, KCP, and WebSocket.
/// WebSocket variant wraps a WsByteStream adapter so all variants
/// transparently support AsyncRead/AsyncWrite and V1 frame I/O.
pub enum IoStream {
    Tcp(TcpStream),
    /// Boxed TLS stream — type-erased to accept any TLS-wrapped transport
    /// (e.g. TlsStream<TcpStream> or TlsStream<PreReadStream<TcpStream>>).
    #[cfg(feature = "tls")]
    Tls(Box<dyn AsyncReadWrite>),
    #[cfg(feature = "kcp")]
    Kcp(KcpStream),
    #[cfg(feature = "quic")]
    Quic(QuicStream),
    #[cfg(feature = "websocket")]
    WebSocket(WsByteStream),
    Yamux(YamuxStream),
    /// AES-128-CFB encrypted control stream.
    /// Created after login by wrapping the inner IoStream.
    Cipher(Box<crate::cipher_stream::CipherStream>),
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

impl std::fmt::Debug for IoStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IoStream::Tcp(_) => f.debug_struct("IoStream::Tcp").finish_non_exhaustive(),
            #[cfg(feature = "tls")]
            IoStream::Tls(_) => f.debug_struct("IoStream::Tls").finish_non_exhaustive(),
            #[cfg(feature = "kcp")]
            IoStream::Kcp(_) => f.debug_struct("IoStream::Kcp").finish_non_exhaustive(),
            #[cfg(feature = "quic")]
            IoStream::Quic(_) => f.debug_struct("IoStream::Quic").finish_non_exhaustive(),
            #[cfg(feature = "websocket")]
            IoStream::WebSocket(_) => f.debug_struct("IoStream::WebSocket").finish_non_exhaustive(),
            IoStream::Yamux(_) => f.debug_struct("IoStream::Yamux").finish_non_exhaustive(),
            IoStream::Cipher(_) => f.debug_struct("IoStream::Cipher").finish_non_exhaustive(),
            IoStream::Aead(_) => f.debug_struct("IoStream::Aead").finish_non_exhaustive(),
            IoStream::SshChannel(_) => f.debug_struct("IoStream::SshChannel").finish_non_exhaustive(),
            IoStream::PreRead(..) => f.debug_struct("IoStream::PreRead").finish_non_exhaustive(),
            IoStream::BufferedRead(..) => f.debug_struct("IoStream::BufferedRead").finish_non_exhaustive(),
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
            IoStream::Tls(s) => Pin::new(s).poll_read(cx, buf),
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

impl tokio::io::AsyncWrite for IoStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            IoStream::Tcp(s) => Pin::new(s).poll_write(cx, buf),
            #[cfg(feature = "tls")]
            IoStream::Tls(s) => Pin::new(s).poll_write(cx, buf),
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
        match self.get_mut() {
            IoStream::Tcp(s) => Pin::new(s).poll_flush(cx),
            #[cfg(feature = "tls")]
            IoStream::Tls(s) => Pin::new(s).poll_flush(cx),
            #[cfg(feature = "kcp")]
            IoStream::Kcp(s) => Pin::new(s).poll_flush(cx),
            #[cfg(feature = "quic")]
            IoStream::Quic(s) => Pin::new(s).poll_flush(cx),
            #[cfg(feature = "websocket")]
            IoStream::WebSocket(s) => Pin::new(s).poll_flush(cx),
            IoStream::Yamux(s) => Pin::new(s).poll_flush(cx),
            IoStream::Cipher(s) => Pin::new(s).poll_flush(cx),
            IoStream::Aead(s) => Pin::new(s).poll_flush(cx),
            IoStream::SshChannel(s) => Pin::new(s.as_mut()).poll_flush(cx),
            IoStream::PreRead(_, s) => Pin::new(s).poll_flush(cx),
            IoStream::BufferedRead(_, _, inner) => Pin::new(inner.as_mut()).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            IoStream::Tcp(s) => Pin::new(s).poll_shutdown(cx),
            #[cfg(feature = "tls")]
            IoStream::Tls(s) => Pin::new(s).poll_shutdown(cx),
            #[cfg(feature = "kcp")]
            IoStream::Kcp(s) => Pin::new(s).poll_shutdown(cx),
            #[cfg(feature = "quic")]
            IoStream::Quic(s) => Pin::new(s).poll_shutdown(cx),
            #[cfg(feature = "websocket")]
            IoStream::WebSocket(s) => Pin::new(s).poll_shutdown(cx),
            IoStream::Yamux(s) => Pin::new(s).poll_shutdown(cx),
            IoStream::Cipher(s) => Pin::new(s).poll_shutdown(cx),
            IoStream::Aead(s) => Pin::new(s).poll_shutdown(cx),
            IoStream::SshChannel(s) => Pin::new(s.as_mut()).poll_shutdown(cx),
            IoStream::PreRead(_, s) => Pin::new(s).poll_shutdown(cx),
            IoStream::BufferedRead(_, _, inner) => Pin::new(inner.as_mut()).poll_shutdown(cx),
        }
    }
}

impl IoStream {
    /// Write a V1 protocol frame to this stream.
    pub async fn write_v1_frame(&mut self, msg: &crate::msg::FrpMessage) -> Result<(), crate::Error> {
        match self {
            IoStream::Tcp(s) => crate::protocol::write_msg_v1(s, msg).await,
            #[cfg(feature = "tls")]
            IoStream::Tls(s) => crate::protocol::write_msg_v1(s, msg).await,
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
            IoStream::BufferedRead(_, _, inner) => crate::protocol::write_msg_v1(inner.as_mut(), msg).await,
        }
    }

    /// Read a V1 protocol frame from this stream.
    pub async fn read_v1_frame(&mut self) -> Result<crate::msg::FrpMessage, crate::Error> {
        match self {
            IoStream::Tcp(s) => crate::protocol::read_msg_v1(s).await,
            #[cfg(feature = "tls")]
            IoStream::Tls(s) => crate::protocol::read_msg_v1(s).await,
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
    pub async fn write_v2_frame(&mut self, msg: &crate::msg::FrpMessage) -> Result<(), crate::Error> {
        use tokio::io::AsyncWriteExt;
        match self {
            IoStream::Tcp(s) => { crate::protocol::write_msg_v2(s, msg).await?; s.flush().await.map_err(|e| crate::Error::Transport(format!("flush: {e}")))?; }
            #[cfg(feature = "tls")]
            IoStream::Tls(s) => { crate::protocol::write_msg_v2(s, msg).await?; s.flush().await.map_err(|e| crate::Error::Transport(format!("flush: {e}")))?; }
            #[cfg(feature = "kcp")]
            IoStream::Kcp(s) => { crate::protocol::write_msg_v2(s, msg).await?; s.flush().await.map_err(|e| crate::Error::Transport(format!("flush: {e}")))?; }
            #[cfg(feature = "quic")]
            IoStream::Quic(s) => { crate::protocol::write_msg_v2(s, msg).await?; s.flush().await.map_err(|e| crate::Error::Transport(format!("flush: {e}")))?; }
            #[cfg(feature = "websocket")]
            IoStream::WebSocket(s) => { crate::protocol::write_msg_v2(s, msg).await?; s.flush().await.map_err(|e| crate::Error::Transport(format!("flush: {e}")))?; }
            IoStream::Yamux(s) => { crate::protocol::write_msg_v2(s, msg).await?; s.flush().await.map_err(|e| crate::Error::Transport(format!("flush: {e}")))?; }
            IoStream::Cipher(s) => { crate::protocol::write_msg_v2(s, msg).await?; s.flush().await.map_err(|e| crate::Error::Transport(format!("flush: {e}")))?; }
            IoStream::Aead(s) => { crate::protocol::write_msg_v2(s, msg).await?; s.flush().await.map_err(|e| crate::Error::Transport(format!("flush: {e}")))?; }
            IoStream::SshChannel(s) => { crate::protocol::write_msg_v2(s, msg).await?; s.flush().await.map_err(|e| crate::Error::Transport(format!("flush: {e}")))?; }
            IoStream::PreRead(_, s) => { crate::protocol::write_msg_v2(s, msg).await?; s.flush().await.map_err(|e| crate::Error::Transport(format!("flush: {e}")))?; }
            IoStream::BufferedRead(_, _, inner) => { crate::protocol::write_msg_v2(inner.as_mut(), msg).await?; inner.flush().await.map_err(|e| crate::Error::Transport(format!("flush: {e}")))?; }
        }
        Ok(())
    }

    /// Read a V2 protocol frame (binary framing + JSON payload) from this stream.
    pub async fn read_v2_frame(&mut self) -> Result<crate::msg::FrpMessage, crate::Error> {
        match self {
            IoStream::Tcp(s) => crate::protocol::read_msg_v2(s).await,
            #[cfg(feature = "tls")]
            IoStream::Tls(s) => crate::protocol::read_msg_v2(s).await,
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
    pub async fn write_raw_v2_frame(&mut self, frame_type: u16, flags: u16, payload: &[u8]) -> Result<(), crate::Error> {
        match self {
            IoStream::Tcp(s) => crate::protocol::write_v2_frame_raw(s, frame_type, flags, payload).await,
            #[cfg(feature = "tls")]
            IoStream::Tls(s) => crate::protocol::write_v2_frame_raw(s, frame_type, flags, payload).await,
            #[cfg(feature = "kcp")]
            IoStream::Kcp(s) => crate::protocol::write_v2_frame_raw(s, frame_type, flags, payload).await,
            #[cfg(feature = "quic")]
            IoStream::Quic(s) => crate::protocol::write_v2_frame_raw(s, frame_type, flags, payload).await,
            #[cfg(feature = "websocket")]
            IoStream::WebSocket(s) => crate::protocol::write_v2_frame_raw(s, frame_type, flags, payload).await,
            IoStream::Yamux(s) => crate::protocol::write_v2_frame_raw(s, frame_type, flags, payload).await,
            IoStream::Cipher(s) => crate::protocol::write_v2_frame_raw(s, frame_type, flags, payload).await,
            IoStream::Aead(s) => crate::protocol::write_v2_frame_raw(s, frame_type, flags, payload).await,
            IoStream::SshChannel(s) => crate::protocol::write_v2_frame_raw(s, frame_type, flags, payload).await,
            IoStream::PreRead(_, s) => crate::protocol::write_v2_frame_raw(s, frame_type, flags, payload).await,
            IoStream::BufferedRead(_, _, inner) => crate::protocol::write_v2_frame_raw(inner.as_mut(), frame_type, flags, payload).await,
        }
    }

    /// Read a raw V2 frame (for handshake). Returns (frame_type, flags, payload_bytes).
    pub async fn read_raw_v2_frame(&mut self) -> Result<(u16, u16, Vec<u8>), crate::Error> {
        match self {
            IoStream::Tcp(s) => crate::protocol::read_v2_frame_raw(s).await,
            #[cfg(feature = "tls")]
            IoStream::Tls(s) => crate::protocol::read_v2_frame_raw(s).await,
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
            IoStream::Tls(_) => None,
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
    pub fn into_split(
        self,
    ) -> (
        Box<dyn tokio::io::AsyncRead + Unpin + Send>,
        Box<dyn tokio::io::AsyncWrite + Unpin + Send>,
    ) {
        match self {
            IoStream::Tcp(s) => {
                let (r, w) = tokio::io::split(s);
                (Box::new(r), Box::new(w))
            }
            #[cfg(feature = "tls")]
            IoStream::Tls(s) => {
                let (r, w) = tokio::io::split(s);
                (Box::new(r), Box::new(w))
            }
            #[cfg(feature = "kcp")]
            IoStream::Kcp(stream) => {
                let (r, w) = tokio::io::split(stream);
                (Box::new(r), Box::new(w))
            }
            #[cfg(feature = "quic")]
            IoStream::Quic(stream) => {
                stream.into_split()
            }
            #[cfg(feature = "websocket")]
            IoStream::WebSocket(adapter) => {
                let (r, w) = tokio::io::split(adapter);
                (Box::new(r), Box::new(w))
            }
            IoStream::Yamux(stream) => {
                let (r, w) = tokio::io::split(stream);
                (Box::new(r), Box::new(w))
            }
            IoStream::Cipher(stream) => {
                let (r, w) = tokio::io::split(stream);
                (Box::new(r), Box::new(w))
            }
            IoStream::Aead(stream) => {
                let (r, w) = tokio::io::split(stream);
                (Box::new(r), Box::new(w))
            }
            IoStream::SshChannel(s) => {
                let (r, w) = tokio::io::split(s);
                (Box::new(r), Box::new(w))
            }
            IoStream::PreRead(pre_read, s) => {
                debug_assert!(pre_read.is_empty(), "into_split called before pre_read bytes consumed");
                let (r, w) = tokio::io::split(s);
                (Box::new(r), Box::new(w))
            }
            IoStream::BufferedRead(buf, pos, inner) => {
                debug_assert!(pos >= buf.len(), "into_split called before buffered bytes consumed");
                inner.into_split()
            }
        }
    }

    /// Wrap this stream in AES-128-CFB encryption for control messages.
    /// Must be called after login (the Login message is NOT encrypted).
    pub fn into_encrypted(self, key: [u8; 16]) -> Self {
        match self {
            IoStream::BufferedRead(buf, pos, inner) => {
                // Buffered bytes are preserved inside the returned Cipher wrapper;
                // they will be replayed before encrypted reads begin.
                debug_assert!(pos >= buf.len(), "into_encrypted called before buffered bytes consumed");
                IoStream::BufferedRead(buf, pos, Box::new(inner.into_encrypted(key)))
            }
            IoStream::Aead(inner) => {
                // Already AEAD-encrypted (V2 with crypto). Don't double-wrap.
                IoStream::Aead(inner)
            }
            other => {
                let c = crate::cipher_stream::CipherStream::new(Box::new(other), key);
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
    /// When true, V2 magic is NOT written on raw TCP — the caller will write
    /// it on the yamux stream after wrapping. Default: false.
    pub caller_handles_mux: bool,
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
            caller_handles_mux: false,
        }
    }
}

/// Resolve a hostname to an IP address using a specific DNS server.
///
/// Sends a standard DNS A-record query over UDP. Handles name compression
/// pointers in the response. IPv6 (AAAA) is not supported — the custom DNS
/// server option is typically used with IPv4-only internal resolvers.
async fn resolve_host_with_dns(host: &str, dns_server: &str) -> Result<String, crate::Error> {
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
        SocketAddr::from_str(dns_server)
            .map_err(|e| crate::Error::Transport(format!("invalid dns_server '{dns_server}': {e}")))?
    } else {
        SocketAddr::from_str(&format!("{dns_server}:53"))
            .map_err(|e| crate::Error::Transport(format!("invalid dns_server '{dns_server}': {e}")))?
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
    let socket = UdpSocket::bind("0.0.0.0:0").await
        .map_err(|e| crate::Error::Transport(format!("DNS: bind: {e}")))?;
    socket.connect(dns_addr).await
        .map_err(|e| crate::Error::Transport(format!("DNS: connect {dns_server}: {e}")))?;
    socket.send(&query).await
        .map_err(|e| crate::Error::Transport(format!("DNS: send to {dns_server}: {e}")))?;

    let mut buf = [0u8; 512];
    let n = timeout(Duration::from_secs(5), socket.recv(&mut buf)).await
        .map_err(|_| crate::Error::Transport("DNS: timeout".into()))?
        .map_err(|e| crate::Error::Transport(format!("DNS: recv: {e}")))?;

    // Parse response
    let response = &buf[..n];
    if response.len() < 12 {
        return Err(crate::Error::Transport("DNS: response too short".into()));
    }

    // Verify transaction ID
    let resp_txid = u16::from_be_bytes([response[0], response[1]]);
    if resp_txid != txid {
        return Err(crate::Error::Transport(format!(
            "DNS: txid mismatch (sent {txid}, got {resp_txid})"
        )));
    }

    let ancount = u16::from_be_bytes([response[6], response[7]]) as usize;
    if ancount == 0 {
        return Err(crate::Error::Transport(format!("DNS resolve {host}: no records found")));
    }

    // Skip 12-byte header + question section to reach answers
    let mut pos = 12;
    pos = skip_dns_name(response, pos); // QNAME
    pos += 4; // QTYPE (2) + QCLASS (2)

    // Read answers
    for _ in 0..ancount {
        if pos + 10 > response.len() {
            return Err(crate::Error::Transport("DNS: truncated answer section".into()));
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
            let ip = std::net::Ipv4Addr::new(response[pos], response[pos + 1],
                                              response[pos + 2], response[pos + 3]);
            return Ok(ip.to_string());
        }
        pos += rdlength;
    }

    Err(crate::Error::Transport(format!("DNS resolve {host}: no A record found")))
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
    }.map_err(|e| crate::Error::Transport(format!("create socket: {e}")))?;

    // Bind to specific local IP if configured
    if let Some(ref bind_ip) = opts.bind_addr {
        let bind_addr: std::net::SocketAddr = format!("{bind_ip}:0").parse().map_err(|e| {
            crate::Error::Transport(format!("invalid bind_addr '{bind_ip}': {e}"))
        })?;
        socket.bind(bind_addr).map_err(|e| {
            crate::Error::Transport(format!("bind to {bind_ip}: {e}"))
        })?;
    }

    let stream = timeout(
        Duration::from_secs(opts.dial_timeout_secs),
        socket.connect(peer),
    )
    .await
    .map_err(|_| crate::Error::Transport(format!("dial timeout to {addr}")))?
    .map_err(|e| crate::Error::Transport(format!("dial to {addr}: {e}")))?;

    // Configure TCP keepalive after connection
    if opts.keepalive_secs > 0 {
        let keepalive = socket2::SockRef::from(&stream);
        let ka = socket2::TcpKeepalive::new()
            .with_time(Duration::from_secs(opts.keepalive_secs));
        keepalive.set_tcp_keepalive(&ka).map_err(|e| {
            crate::Error::Transport(format!("set keepalive: {e}"))
        })?;
    }

    Ok(stream)
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

    let (scheme, proxy_host, proxy_port) = parse_proxy_url(proxy_url)?;
    let proxy_addr = format!("{proxy_host}:{proxy_port}");
    let proxy_peer: std::net::SocketAddr = proxy_addr.parse().map_err(|e| {
        crate::Error::Transport(format!("invalid proxy address '{proxy_addr}': {e}"))
    })?;

    let mut stream = timeout(
        Duration::from_secs(dial_timeout_secs),
        tokio::net::TcpStream::connect(proxy_peer),
    )
    .await
    .map_err(|_| crate::Error::Transport(format!("proxy dial timeout to {proxy_addr}")))?
    .map_err(|e| crate::Error::Transport(format!("proxy dial to {proxy_addr}: {e}")))?;

    match scheme {
        "http" | "https" => {
            // HTTP CONNECT tunnel
            let connect_req = format!(
                "CONNECT {target_host}:{target_port} HTTP/1.1\r\nHost: {target_host}:{target_port}\r\n\r\n"
            );
            timeout(Duration::from_secs(dial_timeout_secs), stream.write_all(connect_req.as_bytes()))
                .await
                .map_err(|_| crate::Error::Transport("proxy CONNECT write timeout".into()))?
                .map_err(|e| crate::Error::Transport(format!("proxy CONNECT write: {e}")))?;

            let mut reader = BufReader::new(&mut stream);
            let mut status_line = String::new();
            timeout(Duration::from_secs(dial_timeout_secs), reader.read_line(&mut status_line))
                .await
                .map_err(|_| crate::Error::Transport("proxy CONNECT read timeout".into()))?
                .map_err(|e| crate::Error::Transport(format!("proxy CONNECT read: {e}")))?;

            if !status_line.contains("200") {
                return Err(crate::Error::Transport(format!(
                    "proxy CONNECT rejected: {}",
                    status_line.trim()
                )));
            }

            // Read remaining headers until \r\n\r\n
            let mut buf = Vec::new();
            loop {
                let mut line = String::new();
                timeout(Duration::from_secs(dial_timeout_secs), reader.read_line(&mut line))
                    .await
                    .map_err(|_| crate::Error::Transport("proxy CONNECT headers timeout".into()))?
                    .map_err(|e| crate::Error::Transport(format!("proxy CONNECT headers: {e}")))?;
                if line == "\r\n" || line.is_empty() {
                    break;
                }
                buf.push(line);
            }
        }
        "socks5" => {
            // SOCKS5 handshake
            // 1. Auth negotiation: send [0x05, 0x01, 0x00] (SOCKS5, 1 method, no auth)
            timeout(
                Duration::from_secs(dial_timeout_secs),
                stream.write_all(&[0x05, 0x01, 0x00]),
            )
            .await
            .map_err(|_| crate::Error::Transport("SOCKS5 auth write timeout".into()))?
            .map_err(|e| crate::Error::Transport(format!("SOCKS5 auth write: {e}")))?;

            // 2. Read server response: [0x05, method]
            let mut auth_resp = [0u8; 2];
            timeout(
                Duration::from_secs(dial_timeout_secs),
                stream.read_exact(&mut auth_resp),
            )
            .await
            .map_err(|_| crate::Error::Transport("SOCKS5 auth read timeout".into()))?
            .map_err(|e| crate::Error::Transport(format!("SOCKS5 auth read: {e}")))?;

            if auth_resp[0] != 0x05 || auth_resp[1] != 0x00 {
                return Err(crate::Error::Transport(format!(
                    "SOCKS5 auth rejected: {:02x?}", auth_resp
                )));
            }

            // 3. Resolve target address and build connect request
            let target_ip: std::net::IpAddr = target_host.parse().map_err(|_| {
                crate::Error::Transport(format!("SOCKS5: cannot resolve hostname '{target_host}' — use IP"))
            })?;

            let mut connect_req = Vec::with_capacity(10);
            connect_req.extend_from_slice(&[0x05, 0x01, 0x00]); // SOCKS5, CONNECT, reserved
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
            connect_req.extend_from_slice(&target_port.to_be_bytes());

            timeout(
                Duration::from_secs(dial_timeout_secs),
                stream.write_all(&connect_req),
            )
            .await
            .map_err(|_| crate::Error::Transport("SOCKS5 connect write timeout".into()))?
            .map_err(|e| crate::Error::Transport(format!("SOCKS5 connect write: {e}")))?;

            // 4. Read connect response: [0x05, rep, 0x00, atyp, bind_addr..., bind_port...]
            let mut resp = [0u8; 10];
            timeout(
                Duration::from_secs(dial_timeout_secs),
                stream.read_exact(&mut resp),
            )
            .await
            .map_err(|_| crate::Error::Transport("SOCKS5 connect read timeout".into()))?
            .map_err(|e| crate::Error::Transport(format!("SOCKS5 connect read: {e}")))?;

            if resp[0] != 0x05 || resp[1] != 0x00 {
                return Err(crate::Error::Transport(format!(
                    "SOCKS5 connect rejected: rep=0x{:02x}",
                    resp[1]
                )));
            }

            // Read remaining bind address bytes
            let extra = match resp[3] {
                0x01 => 4 - 2, // IPv4: we already read 6 bytes of address (4 IP + 2 port), correct
                0x04 => 16 - 2, // IPv6: need 14 more bytes
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
                .map_err(|e| crate::Error::Transport(format!("SOCKS5 bind addr read: {e}")))?;
            }
        }
        other => {
            return Err(crate::Error::Transport(format!(
                "unsupported proxy scheme: '{other}'. Supported: http, socks5"
            )));
        }
    }

    Ok(stream)
}

/// Parse a proxy URL into (scheme, host, port).
fn parse_proxy_url(url: &str) -> Result<(&str, &str, u16), crate::Error> {
    let (scheme, rest) = url
        .split_once("://")
        .ok_or_else(|| crate::Error::Transport(format!("invalid proxy URL '{url}': missing scheme")))?;

    let (host, port_str) = if let Some((h, p)) = rest.rsplit_once(':') {
        (h, p)
    } else {
        return Err(crate::Error::Transport(format!(
            "invalid proxy URL '{url}': missing port"
        )));
    };

    let port: u16 = port_str.parse().map_err(|_| {
        crate::Error::Transport(format!("invalid proxy port '{port_str}' in '{url}'"))
    })?;

    // Strip brackets from IPv6 addresses
    let host = host.strip_prefix('[').and_then(|h| h.strip_suffix(']')).unwrap_or(host);

    Ok((scheme, host, port))
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
            tokio::net::lookup_host(&addr).await
                .map_err(|e| crate::Error::Transport(format!(
                    "invalid server address '{addr}': {e}"
                )))?
                .next()
                .ok_or_else(|| crate::Error::Transport(format!(
                    "DNS resolve '{addr}': no records found"
                )))?
        }
    };

    match opts.protocol {
        #[cfg(feature = "kcp")]
        TransportProtocol::Kcp => {
            let addr = format!("{}:{}", opts.server_addr, opts.server_port);
            let stream = crate::kcp::dial_kcp(&addr, Default::default()).await
                .map_err(|e| crate::Error::Transport(format!("KCP dial: {e}")))?;
            return Ok(IoStream::Kcp(stream));
        }
        #[cfg(feature = "quic")]
        TransportProtocol::Quic => {
            let addr = format!("{}:{}", opts.server_addr, opts.server_port);
            let server_name = if !opts.tls_server_name.is_empty() {
                &opts.tls_server_name
            } else {
                &opts.server_addr
            };
            let ca_file = opts.tls_ca_file.as_deref();
            let (stream, _conn) = crate::quic::dial_quic(&addr, server_name, ca_file).await
                .map_err(|e| crate::Error::Transport(format!("QUIC dial: {e}")))?;
            return Ok(IoStream::Quic(stream));
        }
        _ => {}
    }

    // TCP, WebSocket, WSS: connect via upstream proxy if configured, otherwise direct TCP.
    let mut stream = if let Some(ref proxy_url) = opts.proxy_url {
        if proxy_url.is_empty() {
            // Empty string = direct connection
            connect_direct(&addr, peer, opts).await?
        } else {
            connect_via_proxy(proxy_url, &target_ip, opts.server_port, opts.dial_timeout_secs).await?
        }
    } else {
        connect_direct(&addr, peer, opts).await?
    };

    // Write V2 magic BEFORE any TLS/WS/yamux upgrade (Go frp WriteMagicIfV2).
    // Skip when tcpMux is enabled — magic goes on the yamux stream instead.
    if opts.v2 && !opts.caller_handles_mux {
        crate::protocol::write_v2_magic(&mut stream).await?;
    }

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
                        stream.write_all(&[FRP_TLS_HEAD_BYTE]).await
                            .map_err(|e| crate::Error::Transport(format!("write TLS head byte: {e}")))?;
                    }
                    let connector = build_tls_connector(
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
                        .map_err(|e| crate::Error::Transport(format!("invalid server name: {e}")))?;
                    let tls = connector.connect(server_name, stream).await
                        .map_err(|e| crate::Error::Transport(format!("TLS connect: {e}")))?;
                    Ok(IoStream::Tls(Box::new(tokio_rustls::TlsStream::Client(tls))))
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
                        stream.write_all(&[FRP_TLS_HEAD_BYTE]).await
                            .map_err(|e| crate::Error::Transport(format!("write TLS head byte: {e}")))?;
                    }
                    let connector = build_tls_connector(
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
                        .map_err(|e| crate::Error::Transport(format!("invalid server name: {e}")))?;
                    let tls_stream = connector.connect(server_name, stream).await
                        .map_err(|e| crate::Error::Transport(format!("TLS connect: {e}")))?;
                    connect_ws_raw(tls_stream, &host, opts.server_port, FRP_WEBSOCKET_PATH, "https").await
                }
            } else {
                // Plain WS: use raw mode to tolerate TEXT frames with
                // non-UTF-8 payload from Go frps (golang.org/x/net/websocket).
                connect_ws_raw(stream, &host, opts.server_port, FRP_WEBSOCKET_PATH, "http").await
            }
        }
        #[cfg(any(feature = "kcp", feature = "quic"))]
        TransportProtocol::Kcp | TransportProtocol::Quic => {
            Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "KCP/QUIC should be handled before TCP connect path",
            )
            .into())
        }
    }
}

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
        Ok(Ok(_n)) => {}
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
        #[cfg(feature = "websocket")]
        b'G' => ConnectionType::WebSocket,
        b => ConnectionType::V1(b),
    };

    Ok((ct, IoStream::PreRead(magic_buf.to_vec(), stream)))
}

// consume_tls_head_byte removed — dead code. detect_and_strip_magic
// consumes TLS magic upfront during connection classification.

/// Accept a WebSocket upgrade on the server side.
/// Returns an IoStream with a WsByteStream adapter already applied,
/// so callers can use read_msg_v1/write_msg_v1 directly.
/// Accept a WebSocket connection on a raw TcpStream.
///
/// Does NOT use tungstenite — Go frp v0.69.1 (`golang.org/x/net/websocket`)
/// sends frp V1 frames as TEXT frames. The V1 binary header contains bytes
/// that aren't valid UTF-8 (e.g. the big-endian length field). Tungstenite
/// rejects these text frames per RFC 6455 §5.6.
///
/// This implementation handles the HTTP upgrade manually and returns a
/// WsByteStream in Raw mode — all data frames are treated as opaque bytes.
#[cfg(feature = "websocket")]
pub async fn accept_websocket(stream: IoStream) -> Result<IoStream, crate::Error> {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    let mut reader = BufReader::new(stream);
    let mut key = String::new();

    // Read HTTP upgrade request line by line.
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).await
            .map_err(|e| crate::Error::Transport(format!("WS read request: {e}")))?;
        if line == "\r\n" || line.is_empty() {
            break;
        }
        if line.len() > 1 {
            let lower = line[..1].to_lowercase() + &line[1..].to_lowercase();
            if lower.starts_with("sec-websocket-key:") {
                key = line.split_once(':').map(|x| x.1).unwrap_or("").trim().to_string();
            }
        }
    }

    if key.is_empty() {
        return Err(crate::Error::Transport("Missing Sec-WebSocket-Key".into()));
    }

    // Compute accept key: base64(sha1(key + magic GUID))
    use sha1::{Digest, Sha1};
    let mut hasher = Sha1::new();
    hasher.update(key.as_bytes());
    hasher.update(b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
    let hash = hasher.finalize();
    let accept = {
        // Inline base64 encoding
        const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut s = String::with_capacity(28);
        for chunk in hash.chunks(3) {
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
    };

    // Send HTTP 101 Switching Protocols.
    // Capture any bytes BufReader may have read-ahead past headers
    // (defensive: client should wait for 101 before sending frames).
    let leftover = reader.buffer().to_vec();
    tracing::info!(
        leftover_len = leftover.len(),
        leftover_first16 = %if leftover.len() > 0 {
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
    stream.write_all(resp.as_bytes()).await
        .map_err(|e| crate::Error::Transport(format!("WS write response: {e}")))?;

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
/// Unlike [`accept_websocket`], this function does NOT wrap the stream in BufReader
/// or BufferedRead — it parses the HTTP request from `peeked` (already read from the
/// stream), writes the 101 response directly to `raw`, and returns a WsByteStream
/// backed by the original stream. This avoids the nested BufferedRead issue that
/// corrupts reads when the inner stream is TLS.
#[cfg(feature = "websocket")]
pub async fn accept_websocket_from_peeked(
    peeked: Vec<u8>,
    mut raw: IoStream,
) -> Result<IoStream, crate::Error> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // Parse HTTP headers from peeked data. Read more from raw if the
    // complete request (ending with \r\n\r\n) is not in peeked.
    let mut buf = peeked;
    let mut read_more = false;
    let extra: Vec<u8> = loop {
        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let tail = buf.split_off(pos + 4);
            buf.truncate(pos + 4);
            break tail;
        }
        read_more = true;
        // Need more data — read from raw stream
        let mut chunk = vec![0u8; 1024];
        let n = raw
            .read(&mut chunk)
            .await
            .map_err(|e| crate::Error::Transport(format!("WS read remaining headers: {e}")))?;
        if n == 0 {
            return Err(crate::Error::Transport("WS: connection closed during headers".into()));
        }
        tracing::info!(
            read_n = n,
            chunk_hex = %hex::encode(&chunk[..n.min(32)]),
            "accept_websocket_from_peeked: read {} more bytes from raw stream",
            n
        );
        buf.extend_from_slice(&chunk[..n]);
    };

    tracing::info!(
        peeked_len = buf.len(),
        read_more = read_more,
        extra_len = extra.len(),
        "accept_websocket_from_peeked: headers complete"
    );

    let headers_str = String::from_utf8_lossy(&buf);
    let mut key = String::new();
    for line in headers_str.lines() {
        if line.len() > 1 {
            let lower = line.to_lowercase();
            if lower.starts_with("sec-websocket-key:") {
                key = line.split_once(':').map(|x| x.1).unwrap_or("").trim().to_string();
            }
        }
    }

    if key.is_empty() {
        return Err(crate::Error::Transport("Missing Sec-WebSocket-Key".into()));
    }

    // Compute accept key: base64(sha1(key + magic GUID))
    use sha1::{Digest, Sha1};
    let mut hasher = Sha1::new();
    hasher.update(key.as_bytes());
    hasher.update(b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
    let hash = hasher.finalize();
    let accept = {
        const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut s = String::with_capacity(28);
        for chunk in hash.chunks(3) {
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
    };

    // Send 101 Switching Protocols
    let resp = format!(
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n"
    );
    raw.write_all(resp.as_bytes())
        .await
        .map_err(|e| crate::Error::Transport(format!("WS write response: {e}")))?;

    if !extra.is_empty() {
        tracing::debug!(
            extra_len = extra.len(),
            "Pipelined data after HTTP headers — Go frpc sent WS frame before 101"
        );
    }

    let ws = WsByteStream::from_raw(Box::new(raw), false);
    Ok(IoStream::WebSocket(ws))
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
    let key = {
        const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut s = String::with_capacity(24);
        for chunk in key_bytes.chunks(3) {
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
    };

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

    stream.write_all(req.as_bytes()).await
        .map_err(|e| crate::Error::Transport(format!("WS raw connect write: {e}")))?;

    // Read HTTP 101 response with timeout.
    // BufReader may buffer WebSocket frame bytes past \r\n\r\n — capture
    // them before into_inner() to avoid permanent stream desync.
    let (stream, leftover) = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        async {
            let mut reader = BufReader::new(stream);
            let mut status_line = String::new();
            reader.read_line(&mut status_line).await
                .map_err(|e| crate::Error::Transport(format!("WS raw connect read status: {e}")))?;

            if !status_line.starts_with("HTTP/1.1 101") {
                return Err(crate::Error::Transport(format!(
                    "WS upgrade rejected: {}",
                    status_line.trim()
                )));
            }

            // Consume response headers until \r\n\r\n
            loop {
                let mut line = String::new();
                reader.read_line(&mut line).await
                    .map_err(|e| crate::Error::Transport(format!("WS raw connect read headers: {e}")))?;
                if line == "\r\n" || line.is_empty() {
                    break;
                }
            }

            let leftover = reader.buffer().to_vec();
            let stream = reader.into_inner();
            Ok::<_, crate::Error>((stream, leftover))
        }
    ).await
        .map_err(|_| crate::Error::Transport("WS raw connect: timeout waiting for 101 response".into()))??;

    let mut ws = WsByteStream::from_raw(Box::new(stream), true);
    if !leftover.is_empty() {
        ws.read_buf = leftover;
        ws.read_pos = 0;
    }
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

/// Create a TLS acceptor from PEM-encoded cert and key files.
/// If ca_file is provided, client certificates will be verified against it (mTLS).
#[cfg(feature = "tls")]
pub fn build_tls_acceptor(
    cert_file: &str,
    key_file: &str,
    ca_file: Option<&str>,
) -> Result<TlsAcceptor, crate::Error> {
    use std::fs::File;
    use std::io::BufReader;

    let cert_file = File::open(cert_file)
        .map_err(|e| crate::Error::Other(format!("open cert file: {e}")))?;
    let mut reader = BufReader::new(cert_file);
    let certs = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| crate::Error::Other(format!("read certs: {e}")))?;

    let key_file = File::open(key_file)
        .map_err(|e| crate::Error::Other(format!("open key file: {e}")))?;
    let mut reader = BufReader::new(key_file);
    let key = rustls_pemfile::private_key(&mut reader)
        .map_err(|e| crate::Error::Other(format!("read private key: {e}")))?
        .ok_or_else(|| crate::Error::Other("no private key found".into()))?;

    // Build server config with optional client certificate verification (mTLS)
    let config = if let Some(ca_path) = ca_file {
        if !ca_path.is_empty() {
            let mut roots = rustls::RootCertStore::empty();
            let ca_file = File::open(ca_path)
                .map_err(|e| crate::Error::Other(format!("open CA file: {e}")))?;
            let mut ca_reader = BufReader::new(ca_file);
            let ca_certs = rustls_pemfile::certs(&mut ca_reader)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| crate::Error::Other(format!("read CA certs: {e}")))?;
            roots.add_parsable_certificates(ca_certs);

            let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(roots))
                .build()
                .map_err(|e| crate::Error::Other(format!("build client cert verifier: {e}")))?;

            rustls::ServerConfig::builder()
                .with_client_cert_verifier(verifier)
                .with_single_cert(certs, key)
                .map_err(|e| crate::Error::Other(format!("build mTLS config: {e}")))?
        } else {
            rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(certs, key)
                .map_err(|e| crate::Error::Other(format!("build TLS config: {e}")))?
        }
    } else {
        rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|e| crate::Error::Other(format!("build TLS config: {e}")))?
    };

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
pub fn generate_self_signed_tls_config() -> Result<rustls::ServerConfig, crate::Error> {
    use rcgen::{CertificateParams, DistinguishedName, DnType, IsCa, BasicConstraints, KeyPair};

    let key_pair = KeyPair::generate()
        .map_err(|e| crate::Error::Other(format!("generate TLS key pair: {e}")))?;

    let mut params = CertificateParams::new(vec!["frp".to_string()])
        .map_err(|e| crate::Error::Other(format!("create TLS cert params: {e}")))?;

    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "frp");
    dn.push(DnType::OrganizationName, "frp-rs auto-generated");
    params.distinguished_name = dn;
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![
        rcgen::KeyUsagePurpose::DigitalSignature,
        rcgen::KeyUsagePurpose::KeyEncipherment,
        rcgen::KeyUsagePurpose::KeyCertSign,
    ];
    // Uses rcgen's default validity (now → now + 365 days).
    // Go frp uses 10 years but the auto-generated cert is regenerated on every
    // frps restart, so a shorter validity is acceptable.

    let cert = params.self_signed(&key_pair)
        .map_err(|e| crate::Error::Other(format!("self-sign TLS cert: {e}")))?;

    let cert_der = cert.der().clone();
    let key_der = rustls::pki_types::PrivatePkcs8KeyDer::from(key_pair.serialize_der()).into();

    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .map_err(|e| crate::Error::Other(format!("build TLS config from generated cert: {e}")))?;

    Ok(config)
}

/// Build a [`TlsAcceptor`] from cert/key files, or auto-generate a self-signed
/// cert when no files are configured (matching Go frp behavior).
///
/// When both `cert_file` and `key_file` are non-empty, this delegates to
/// [`build_tls_acceptor`]. Otherwise, it calls [`generate_self_signed_tls_config`]
/// to create an ephemeral self-signed certificate.
///
/// Auto-generated certs never enable mTLS (CA verification) — if you need
/// mTLS, provide explicit cert files and a CA file.
#[cfg(feature = "tls")]
pub fn build_tls_acceptor_or_generate(
    cert_file: &str,
    key_file: &str,
    ca_file: Option<&str>,
) -> Result<TlsAcceptor, crate::Error> {
    if !cert_file.is_empty() && !key_file.is_empty() {
        return build_tls_acceptor(cert_file, key_file, ca_file);
    }
    tracing::info!("No TLS cert files configured — auto-generating self-signed certificate");
    let config = generate_self_signed_tls_config()?;
    Ok(TlsAcceptor::from(Arc::new(config)))
}

/// Build a `RootCertStore` from a custom CA file path.
/// Returns `None` when no custom CA is specified (caller should use
/// the platform verifier instead).
#[cfg(feature = "tls")]
pub fn build_root_store(ca_file: Option<&str>) -> Result<Option<rustls::RootCertStore>, crate::Error> {
    match ca_file {
        Some(ca_path) if !ca_path.is_empty() => {
            let mut root_store = rustls::RootCertStore::empty();
            let file = std::fs::File::open(ca_path)
                .map_err(|e| crate::Error::Other(format!("open CA file: {e}")))?;
            let mut reader = std::io::BufReader::new(file);
            let certs = rustls_pemfile::certs(&mut reader)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| crate::Error::Other(format!("read CA certs: {e}")))?;
            root_store.add_parsable_certificates(certs);
            Ok(Some(root_store))
        }
        _ => Ok(None),
    }
}

/// Create a TLS connector for client-side TLS.
/// If ca_file is provided, use it as a custom root CA; otherwise use
/// the OS platform verifier (macOS Security.framework, Windows Schannel,
/// Linux system CA bundle).
/// If cert_file/key_file are provided, present client certificate to server (mTLS).
#[cfg(feature = "tls")]
pub fn build_tls_connector(
    ca_file: Option<&str>,
    cert_file: Option<&str>,
    key_file: Option<&str>,
) -> Result<TlsConnector, crate::Error> {
    use rustls_platform_verifier::BuilderVerifierExt;
    use rustls_platform_verifier::ConfigVerifierExt;

    let root_store = build_root_store(ca_file)?;

    let config = if let Some(store) = root_store {
        // Custom CA: use RootCertStore
        if let (Some(cert_path), Some(key_path)) = (cert_file, key_file) {
            if !cert_path.is_empty() && !key_path.is_empty() {
                let cert_file = std::fs::File::open(cert_path)
                    .map_err(|e| crate::Error::Other(format!("open client cert file: {e}")))?;
                let mut cert_reader = std::io::BufReader::new(cert_file);
                let client_certs = rustls_pemfile::certs(&mut cert_reader)
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|e| crate::Error::Other(format!("read client certs: {e}")))?;
                let key_file = std::fs::File::open(key_path)
                    .map_err(|e| crate::Error::Other(format!("open client key file: {e}")))?;
                let mut key_reader = std::io::BufReader::new(key_file);
                let client_key = rustls_pemfile::private_key(&mut key_reader)
                    .map_err(|e| crate::Error::Other(format!("read client key: {e}")))?
                    .ok_or_else(|| crate::Error::Other("no client private key found".into()))?;
                rustls::ClientConfig::builder()
                    .with_root_certificates(Arc::new(store))
                    .with_client_auth_cert(client_certs, client_key)
                    .map_err(|e| crate::Error::Other(format!("build mTLS client config: {e}")))?
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
    } else if let (Some(cert_path), Some(key_path)) = (cert_file, key_file) {
        // Platform verifier with client certificate (mTLS)
        if !cert_path.is_empty() && !key_path.is_empty() {
            let cert_file = std::fs::File::open(cert_path)
                .map_err(|e| crate::Error::Other(format!("open client cert file: {e}")))?;
            let mut cert_reader = std::io::BufReader::new(cert_file);
            let client_certs = rustls_pemfile::certs(&mut cert_reader)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| crate::Error::Other(format!("read client certs: {e}")))?;
            let key_file = std::fs::File::open(key_path)
                .map_err(|e| crate::Error::Other(format!("open client key file: {e}")))?;
            let mut key_reader = std::io::BufReader::new(key_file);
            let client_key = rustls_pemfile::private_key(&mut key_reader)
                .map_err(|e| crate::Error::Other(format!("read client key: {e}")))?
                .ok_or_else(|| crate::Error::Other("no client private key found".into()))?;
            rustls::ClientConfig::builder()
                .with_platform_verifier()
                .map_err(|e| crate::Error::Other(format!("platform verifier: {e}")))?
                .with_client_auth_cert(client_certs, client_key)
                .map_err(|e| crate::Error::Other(format!("build mTLS client config: {e}")))?
        } else {
            // Platform verifier, no client certificate
            <rustls::ClientConfig as ConfigVerifierExt>::with_platform_verifier()
                .map_err(|e| crate::Error::Other(format!("platform verifier: {e}")))?
        }
    } else {
        // Platform verifier, no client certificate
        <rustls::ClientConfig as ConfigVerifierExt>::with_platform_verifier()
            .map_err(|e| crate::Error::Other(format!("platform verifier: {e}")))?
    };

    Ok(TlsConnector::from(Arc::new(config)))
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
        Self { pre_read, pos: 0, inner }
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
    #[cfg(feature = "tls")]
    fn test_build_tls_connector_with_default_roots() {
        let result = build_tls_connector(None, None, None);
        assert!(result.is_ok(), "TLS connector with default roots should build");
    }

    #[test]
    #[cfg(feature = "tls")]
    fn test_build_tls_acceptor_missing_cert() {
        let result = build_tls_acceptor(
            "/nonexistent/cert.pem",
            "/nonexistent/key.pem",
            None,
        );
        assert!(result.is_err(), "TLS acceptor with missing files should fail");
    }
}

