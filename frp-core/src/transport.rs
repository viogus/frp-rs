use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_tungstenite::tungstenite::Message;
use futures_util::stream::Stream;
use futures_util::sink::Sink;
use tokio::net::{TcpListener, TcpStream};
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};
use crate::kcp::KcpStream;
use crate::quic::QuicStream;

use std::sync::Arc;
use tokio_rustls::TlsAcceptor;
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
    Kcp,
    WebSocket,
    Wss,
    Quic,
}

impl std::str::FromStr for TransportProtocol {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s.to_lowercase().as_str() {
            "kcp" => TransportProtocol::Kcp,
            "websocket" | "ws" => TransportProtocol::WebSocket,
            "wss" => TransportProtocol::Wss,
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
pub struct WsByteStream {
    inner: WsInner,
    read_buf: Vec<u8>,
    read_pos: usize,
    /// Write buffer for the Raw variant (frame bytes not yet flushed).
    write_buf: Vec<u8>,
    write_pos: usize,
    needs_flush: bool,
}

enum WsInner {
    Tungstenite(Pin<Box<WebSocketStream<MaybeTlsStream<TcpStream>>>>),
    /// Raw TCP stream post-upgrade. Manual WebSocket frame handling.
    /// Server-side only — client frames are always masked (RFC 6455 §5.3).
    Raw(TcpStream),
}

impl WsByteStream {
    pub fn new(ws: WebSocketStream<MaybeTlsStream<TcpStream>>) -> Self {
        Self {
            inner: WsInner::Tungstenite(Box::pin(ws)),
            read_buf: Vec::new(),
            read_pos: 0,
            write_buf: Vec::new(),
            write_pos: 0,
            needs_flush: false,
        }
    }

    /// Create from a raw TCP stream after manual WebSocket upgrade.
    /// Used on the server accept path for Go frp compat.
    pub fn from_raw_tcp(tcp: TcpStream) -> Self {
        Self {
            inner: WsInner::Raw(tcp),
            read_buf: Vec::new(),
            read_pos: 0,
            write_buf: Vec::new(),
            write_pos: 0,
            needs_flush: false,
        }
    }

    /// Consume the adapter and return the underlying WebSocket stream.
    /// Panics if called on a Raw variant.
    pub fn into_inner(self) -> WebSocketStream<MaybeTlsStream<TcpStream>> {
        match self.inner {
            WsInner::Tungstenite(ws) => *Pin::into_inner(ws),
            WsInner::Raw(_) => panic!("into_inner called on Raw variant"),
        }
    }
}

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

        // Extract inner ref to avoid borrow conflict with self.{read_buf,read_pos}
        match &mut self.inner {
            WsInner::Tungstenite(inner) => {
                loop {
                    match inner.as_mut().poll_next(cx) {
                        Poll::Ready(Some(Ok(Message::Binary(data)))) => {
                            let len = data.len().min(buf.remaining());
                            buf.put_slice(&data[..len]);
                            if len < data.len() {
                                self.read_buf = data[len..].to_vec();
                                self.read_pos = 0;
                            }
                            return Poll::Ready(Ok(()));
                        }
                        Poll::Ready(Some(Ok(Message::Text(text)))) => {
                            let data = text.into_bytes();
                            let len = data.len().min(buf.remaining());
                            buf.put_slice(&data[..len]);
                            if len < data.len() {
                                self.read_buf = data[len..].to_vec();
                                self.read_pos = 0;
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
            WsInner::Raw(tcp) => {
                // --- Read WebSocket frame header ---
                // Byte 0: FIN(1) RSV(3) OPCODE(4)
                // Byte 1: MASK(1) PAYLOAD_LEN(7)
                let mut head = [0u8; 2];
                match Pin::new(&mut *tcp).poll_read(cx, &mut ReadBuf::new(&mut head)) {
                    Poll::Ready(Ok(())) => {}
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                }

                let opcode = head[0] & 0x0f;
                let masked = (head[1] & 0x80) != 0;
                let mut payload_len = (head[1] & 0x7f) as u64;

                // Extended payload length
                if payload_len == 126 {
                    let mut ext = [0u8; 2];
                    match Pin::new(&mut *tcp).poll_read(cx, &mut ReadBuf::new(&mut ext)) {
                        Poll::Ready(Ok(())) => {}
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Pending => return Poll::Pending,
                    }
                    payload_len = u16::from_be_bytes(ext) as u64;
                } else if payload_len == 127 {
                    let mut ext = [0u8; 8];
                    match Pin::new(&mut *tcp).poll_read(cx, &mut ReadBuf::new(&mut ext)) {
                        Poll::Ready(Ok(())) => {}
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Pending => return Poll::Pending,
                    }
                    payload_len = u64::from_be_bytes(ext);
                }

                if payload_len > 16 * 1024 * 1024 {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "WS frame too large",
                    )));
                }

                // Read mask key
                let mut mask_key = [0u8; 4];
                if masked {
                    match Pin::new(&mut *tcp).poll_read(cx, &mut ReadBuf::new(&mut mask_key)) {
                        Poll::Ready(Ok(())) => {}
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Pending => return Poll::Pending,
                    }
                }

                // Read payload
                let mut payload = vec![0u8; payload_len as usize];
                if payload_len > 0 {
                    match Pin::new(&mut *tcp).poll_read(cx, &mut ReadBuf::new(&mut payload)) {
                        Poll::Ready(Ok(())) => {}
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Pending => return Poll::Pending,
                    }
                }

                // Unmask
                if masked {
                    for i in 0..payload.len() {
                        payload[i] ^= mask_key[i % 4];
                    }
                }

                match opcode {
                    // Text, Binary, Continuation — deliver as raw bytes
                    0x00..=0x02 => {
                        let n = payload.len().min(buf.remaining());
                        buf.put_slice(&payload[..n]);
                        if n < payload.len() {
                            self.read_buf = payload[n..].to_vec();
                            self.read_pos = 0;
                        }
                        Poll::Ready(Ok(()))
                    }
                    // Close
                    0x08 => {
                        let _ = Pin::new(&mut *tcp).poll_write(cx, &[0x88, 0x02, 0x03, 0xe8]);
                        Poll::Ready(Ok(()))
                    }
                    // Ping → reply Pong, retry
                    0x09 => {
                        let mut pong = vec![0x8a, payload.len() as u8];
                        pong.extend_from_slice(&payload);
                        let _ = Pin::new(&mut *tcp).poll_write(cx, &pong);
                        cx.waker().wake_by_ref();
                        Poll::Pending
                    }
                    // Pong → ignore, retry
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
        }
    }
}

impl AsyncWrite for WsByteStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        // Use locals to avoid borrow conflicts between &mut self.inner and self.{needs_flush, write_buf}
        let mut needs_flush = self.needs_flush;

        match &mut self.inner {
            WsInner::Tungstenite(inner) => {
                if !needs_flush && !buf.is_empty() {
                    match inner.as_mut().poll_ready(cx) {
                        Poll::Ready(Ok(())) => {
                            match inner.as_mut().start_send(Message::Binary(buf.to_vec())) {
                                Ok(()) => needs_flush = true,
                                Err(e) => return Poll::Ready(Err(io::Error::other(e))),
                            }
                        }
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(io::Error::other(e))),
                        Poll::Pending => {
                            self.needs_flush = needs_flush;
                            return Poll::Pending;
                        }
                    }
                }
                if needs_flush {
                    match inner.as_mut().poll_flush(cx) {
                        Poll::Ready(Ok(())) => {
                            self.needs_flush = false;
                            Poll::Ready(Ok(buf.len()))
                        }
                        Poll::Ready(Err(e)) => {
                            self.needs_flush = false;
                            Poll::Ready(Err(io::Error::other(e)))
                        }
                        Poll::Pending => {
                            self.needs_flush = true;
                            Poll::Pending
                        }
                    }
                } else {
                    self.needs_flush = false;
                    Poll::Ready(Ok(0))
                }
            }
            WsInner::Raw(tcp) => {
                let tcp_ptr: *mut TcpStream = tcp;
                if !needs_flush && !buf.is_empty() {
                    let len = buf.len();
                    self.write_buf.clear();
                    self.write_buf.push(0x82);
                    if len < 126 {
                        self.write_buf.push(len as u8);
                    } else if len <= 65535 {
                        self.write_buf.push(126);
                        self.write_buf.extend_from_slice(&(len as u16).to_be_bytes());
                    } else {
                        self.write_buf.push(127);
                        self.write_buf.extend_from_slice(&(len as u64).to_be_bytes());
                    }
                    self.write_buf.extend_from_slice(buf);
                    self.write_pos = 0;
                    self.needs_flush = true;
                }
                if self.needs_flush {
                    let remaining = &self.write_buf[self.write_pos..];
                    // SAFETY: tcp_ptr derived from &mut self.inner, fields are disjoint
                    let tcp = unsafe { &mut *tcp_ptr };
                    match Pin::new(tcp).poll_write(cx, remaining) {
                        Poll::Ready(Ok(n)) => {
                            self.write_pos += n;
                            if self.write_pos >= self.write_buf.len() {
                                self.write_pos = 0;
                                self.needs_flush = false;
                                Poll::Ready(Ok(buf.len()))
                            } else {
                                cx.waker().wake_by_ref();
                                Poll::Pending
                            }
                        }
                        Poll::Ready(Err(e)) => {
                            self.needs_flush = false;
                            Poll::Ready(Err(e))
                        }
                        Poll::Pending => Poll::Pending,
                    }
                } else {
                    Poll::Ready(Ok(0))
                }
            }
        }
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        let needs_flush = self.needs_flush;
        match &mut self.inner {
            WsInner::Tungstenite(inner) => {
                if needs_flush {
                    match inner.as_mut().poll_flush(cx) {
                        Poll::Ready(Ok(())) => {
                            self.needs_flush = false;
                            Poll::Ready(Ok(()))
                        }
                        Poll::Ready(Err(e)) => Poll::Ready(Err(io::Error::other(e))),
                        Poll::Pending => {
                            self.needs_flush = true;
                            Poll::Pending
                        }
                    }
                } else {
                    Poll::Ready(Ok(()))
                }
            }
            WsInner::Raw(tcp) => {
                let tcp_ptr: *mut TcpStream = tcp;
                if needs_flush {
                    let remaining = &self.write_buf[self.write_pos..];
                    let tcp = unsafe { &mut *tcp_ptr };
                    match Pin::new(tcp).poll_write(cx, remaining) {
                        Poll::Ready(Ok(n)) => {
                            self.write_pos += n;
                            if self.write_pos >= self.write_buf.len() {
                                self.write_pos = 0;
                                self.needs_flush = false;
                                Poll::Ready(Ok(()))
                            } else {
                                cx.waker().wake_by_ref();
                                Poll::Pending
                            }
                        }
                        Poll::Ready(Err(e)) => {
                            self.needs_flush = false;
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
            WsInner::Raw(tcp) => {
                let _ = Pin::new(&mut *tcp).poll_write(cx, &[0x88, 0x02, 0x03, 0xe8]);
                Pin::new(&mut *tcp).poll_shutdown(cx)
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
    Tls(Box<dyn AsyncReadWrite>),
    Kcp(KcpStream),
    Quic(QuicStream),
    WebSocket(WsByteStream),
    Yamux(YamuxStream),
    /// AES-128-CFB encrypted control stream.
    /// Created after login by wrapping the inner IoStream.
    Cipher(Box<crate::cipher_stream::CipherStream>),
}

impl std::fmt::Debug for IoStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IoStream::Tcp(_) => f.debug_struct("IoStream::Tcp").finish_non_exhaustive(),
            IoStream::Tls(_) => f.debug_struct("IoStream::Tls").finish_non_exhaustive(),
            IoStream::Kcp(_) => f.debug_struct("IoStream::Kcp").finish_non_exhaustive(),
            IoStream::Quic(_) => f.debug_struct("IoStream::Quic").finish_non_exhaustive(),
            IoStream::WebSocket(_) => f.debug_struct("IoStream::WebSocket").finish_non_exhaustive(),
            IoStream::Yamux(_) => f.debug_struct("IoStream::Yamux").finish_non_exhaustive(),
            IoStream::Cipher(_) => f.debug_struct("IoStream::Cipher").finish_non_exhaustive(),
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
        match self.get_mut() {
            IoStream::Tcp(s) => Pin::new(s).poll_read(cx, buf),
            IoStream::Tls(s) => Pin::new(s).poll_read(cx, buf),
            IoStream::Kcp(s) => Pin::new(s).poll_read(cx, buf),
            IoStream::Quic(s) => Pin::new(s).poll_read(cx, buf),
            IoStream::WebSocket(s) => Pin::new(s).poll_read(cx, buf),
            IoStream::Yamux(s) => Pin::new(s).poll_read(cx, buf),
            IoStream::Cipher(s) => Pin::new(s).poll_read(cx, buf),
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
            IoStream::Tls(s) => Pin::new(s).poll_write(cx, buf),
            IoStream::Kcp(s) => Pin::new(s).poll_write(cx, buf),
            IoStream::Quic(s) => Pin::new(s).poll_write(cx, buf),
            IoStream::WebSocket(s) => Pin::new(s).poll_write(cx, buf),
            IoStream::Yamux(s) => Pin::new(s).poll_write(cx, buf),
            IoStream::Cipher(s) => Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            IoStream::Tcp(s) => Pin::new(s).poll_flush(cx),
            IoStream::Tls(s) => Pin::new(s).poll_flush(cx),
            IoStream::Kcp(s) => Pin::new(s).poll_flush(cx),
            IoStream::Quic(s) => Pin::new(s).poll_flush(cx),
            IoStream::WebSocket(s) => Pin::new(s).poll_flush(cx),
            IoStream::Yamux(s) => Pin::new(s).poll_flush(cx),
            IoStream::Cipher(s) => Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            IoStream::Tcp(s) => Pin::new(s).poll_shutdown(cx),
            IoStream::Tls(s) => Pin::new(s).poll_shutdown(cx),
            IoStream::Kcp(s) => Pin::new(s).poll_shutdown(cx),
            IoStream::Quic(s) => Pin::new(s).poll_shutdown(cx),
            IoStream::WebSocket(s) => Pin::new(s).poll_shutdown(cx),
            IoStream::Yamux(s) => Pin::new(s).poll_shutdown(cx),
            IoStream::Cipher(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}

impl IoStream {
    /// Write a V1 protocol frame to this stream.
    pub async fn write_v1_frame(&mut self, msg: &crate::msg::FrpMessage) -> Result<(), crate::Error> {
        match self {
            IoStream::Tcp(s) => crate::protocol::write_msg_v1(s, msg).await,
            IoStream::Tls(s) => crate::protocol::write_msg_v1(s, msg).await,
            IoStream::Kcp(s) => crate::protocol::write_msg_v1(s, msg).await,
            IoStream::Quic(s) => crate::protocol::write_msg_v1(s, msg).await,
            IoStream::WebSocket(s) => crate::protocol::write_msg_v1(s, msg).await,
            IoStream::Yamux(s) => crate::protocol::write_msg_v1(s, msg).await,
            IoStream::Cipher(s) => crate::protocol::write_msg_v1(s, msg).await,
        }
    }

    /// Read a V1 protocol frame from this stream.
    pub async fn read_v1_frame(&mut self) -> Result<crate::msg::FrpMessage, crate::Error> {
        match self {
            IoStream::Tcp(s) => crate::protocol::read_msg_v1(s).await,
            IoStream::Tls(s) => crate::protocol::read_msg_v1(s).await,
            IoStream::Kcp(s) => crate::protocol::read_msg_v1(s).await,
            IoStream::Quic(s) => crate::protocol::read_msg_v1(s).await,
            IoStream::WebSocket(s) => crate::protocol::read_msg_v1(s).await,
            IoStream::Yamux(s) => crate::protocol::read_msg_v1(s).await,
            IoStream::Cipher(s) => crate::protocol::read_msg_v1(s).await,
        }
    }

    /// Write a V2 protocol frame (binary framing + JSON payload) to this stream.
    pub async fn write_v2_frame(&mut self, msg: &crate::msg::FrpMessage) -> Result<(), crate::Error> {
        match self {
            IoStream::Tcp(s) => crate::protocol::write_msg_v2(s, msg).await,
            IoStream::Tls(s) => crate::protocol::write_msg_v2(s, msg).await,
            IoStream::Kcp(s) => crate::protocol::write_msg_v2(s, msg).await,
            IoStream::Quic(s) => crate::protocol::write_msg_v2(s, msg).await,
            IoStream::WebSocket(s) => crate::protocol::write_msg_v2(s, msg).await,
            IoStream::Yamux(s) => crate::protocol::write_msg_v2(s, msg).await,
            IoStream::Cipher(s) => crate::protocol::write_msg_v2(s, msg).await,
        }
    }

    /// Read a V2 protocol frame (binary framing + JSON payload) from this stream.
    pub async fn read_v2_frame(&mut self) -> Result<crate::msg::FrpMessage, crate::Error> {
        match self {
            IoStream::Tcp(s) => crate::protocol::read_msg_v2(s).await,
            IoStream::Tls(s) => crate::protocol::read_msg_v2(s).await,
            IoStream::Kcp(s) => crate::protocol::read_msg_v2(s).await,
            IoStream::Quic(s) => crate::protocol::read_msg_v2(s).await,
            IoStream::WebSocket(s) => crate::protocol::read_msg_v2(s).await,
            IoStream::Yamux(s) => crate::protocol::read_msg_v2(s).await,
            IoStream::Cipher(s) => crate::protocol::read_msg_v2(s).await,
        }
    }

    /// Get the peer address of this stream, if available.
    pub fn peer_addr(&self) -> Option<std::net::SocketAddr> {
        match self {
            IoStream::Tcp(s) => s.peer_addr().ok(),
            IoStream::Tls(_) | IoStream::Kcp(_) | IoStream::Quic(_) | IoStream::WebSocket(_) | IoStream::Yamux(_) | IoStream::Cipher(_) => None,
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
            IoStream::Tls(s) => {
                let (r, w) = tokio::io::split(s);
                (Box::new(r), Box::new(w))
            }
            IoStream::Kcp(stream) => {
                let (r, w) = tokio::io::split(stream);
                (Box::new(r), Box::new(w))
            }
            IoStream::Quic(stream) => {
                stream.into_split()
            }
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
        }
    }

    /// Wrap this stream in AES-128-CFB encryption for control messages.
    /// Must be called after login (the Login message is NOT encrypted).
    pub fn into_encrypted(self, key: [u8; 16]) -> Self {
        let c = crate::cipher_stream::CipherStream::new(Box::new(self), key);
        IoStream::Cipher(Box::new(c))
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
        }
    }
}

/// Resolve a hostname to an IP address using a specific DNS server.
async fn resolve_host_with_dns(host: &str, dns_server: &str) -> Result<String, crate::Error> {
    use hickory_resolver::config::{NameServerConfig, Protocol, ResolverConfig, ResolverOpts};
    use hickory_resolver::TokioAsyncResolver;
    use std::net::SocketAddr;
    use std::str::FromStr;

    // Parse DNS server address (default port 53)
    let dns_addr = if dns_server.contains(':') {
        SocketAddr::from_str(dns_server)
            .map_err(|e| crate::Error::Transport(format!("invalid dns_server '{dns_server}': {e}")))?
    } else {
        SocketAddr::from_str(&format!("{dns_server}:53"))
            .map_err(|e| crate::Error::Transport(format!("invalid dns_server '{dns_server}': {e}")))?
    };

    let ns_config = NameServerConfig {
        socket_addr: dns_addr,
        protocol: Protocol::Udp,
        tls_dns_name: None,
        trust_negative_responses: true,
        bind_addr: None,
    };
    let config = ResolverConfig::from_parts(None, vec![], vec![ns_config]);
    let resolver = TokioAsyncResolver::tokio(config, ResolverOpts::default());

    // If host is already an IP, return it as-is
    if host.parse::<std::net::IpAddr>().is_ok() {
        return Ok(host.to_string());
    }

    let response = resolver.lookup_ip(host).await
        .map_err(|e| crate::Error::Transport(format!("DNS resolve {host} via {dns_server}: {e}")))?;

    response.iter()
        .next()
        .map(|ip| ip.to_string())
        .ok_or_else(|| crate::Error::Transport(format!("DNS resolve {host}: no records found")))
}

/// Connect to the server with the given options.
pub async fn dial_server(opts: &DialOptions) -> Result<IoStream, crate::Error> {
    use tokio::io::AsyncWriteExt;
    use tokio::time::{timeout, Duration};

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
    let mut stream = timeout(
        Duration::from_secs(opts.dial_timeout_secs),
        TcpStream::connect(&addr),
    )
    .await
    .map_err(|_| crate::Error::Transport(format!("dial timeout to {addr}")))?
    .map_err(|e| crate::Error::Transport(format!("dial to {addr}: {e}")))?;

    match opts.protocol {
        TransportProtocol::Tcp => {
            if opts.tls_enable {
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
            } else {
                Ok(IoStream::Tcp(stream))
            }
        }
        TransportProtocol::WebSocket | TransportProtocol::Wss => {
            let is_wss = opts.protocol == TransportProtocol::Wss || opts.tls_enable;
            let host = if !opts.tls_server_name.is_empty() {
                opts.tls_server_name.clone()
            } else {
                opts.server_addr.clone()
            };
            let url = format!(
                "{}://{}:{}{}",
                if is_wss { "wss" } else { "ws" },
                host,
                opts.server_port,
                FRP_WEBSOCKET_PATH
            );
            // Build request with Origin header — Go frp v0.69.1
            // (golang.org/x/net/websocket) requires Origin.
            use tokio_tungstenite::tungstenite::http::Request as HttpRequest;
            let origin = format!("http://{}:{}", host, opts.server_port);
            let req = HttpRequest::builder()
                .method("GET")
                .uri(&url)
                .header("Host", format!("{}:{}", host, opts.server_port))
                .header("Connection", "Upgrade")
                .header("Upgrade", "websocket")
                .header("Sec-WebSocket-Version", "13")
                .header("Sec-WebSocket-Key", tokio_tungstenite::tungstenite::handshake::client::generate_key())
                .header("Origin", origin)
                .body(())
                .map_err(|e| crate::Error::Transport(format!("WS request build: {e}")))?;
            let (ws_stream, _) = tokio_tungstenite::connect_async(req)
                .await
                .map_err(|e| crate::Error::Transport(format!("WebSocket connect: {e}")))?;
            Ok(IoStream::WebSocket(WsByteStream::new(ws_stream)))
        }
        TransportProtocol::Kcp => {
            let addr = format!("{}:{}", opts.server_addr, opts.server_port);
            let stream = crate::kcp::dial_kcp(&addr, Default::default()).await
                .map_err(|e| crate::Error::Transport(format!("KCP dial: {e}")))?;
            Ok(IoStream::Kcp(stream))
        }
        TransportProtocol::Quic => {
            let addr = format!("{}:{}", opts.server_addr, opts.server_port);
            let server_name = if !opts.tls_server_name.is_empty() {
                &opts.tls_server_name
            } else {
                &opts.server_addr
            };
            let stream = crate::quic::dial_quic(&addr, server_name).await
                .map_err(|e| crate::Error::Transport(format!("QUIC dial: {e}")))?;
            Ok(IoStream::Quic(stream))
        }
    }
}

/// Peek the first byte of a TCP stream to determine connection type.
/// Uses MSG_PEEK so the byte remains in the socket buffer — the caller
/// uses the existing stream directly without needing to prepend bytes.
///
/// Returns:
/// - `Tls` if first byte is 0x17 (TLS head byte, must be consumed before TLS handshake)
/// - `WebSocket` if first byte is 'G' (HTTP GET for WS upgrade)
/// - `V1(byte)` otherwise (frp protocol, byte is V1 message type byte)
///
/// Tokio TcpStreams are non-blocking. If no data has arrived yet, recv
/// returns EAGAIN. We retry with short sleeps until data arrives or timeout.
pub async fn peek_connection_type(stream: &TcpStream) -> Result<ConnectionType, crate::Error> {
    let mut buf = [0u8; 1];

    // Retry loop: tokio TcpStream is non-blocking, recv may return EAGAIN
    // if the client hasn't written yet.
    let deadline = tokio::time::Instant::now() + tokio::time::Duration::from_secs(5);
    loop {
        match peek_byte(stream, &mut buf) {
            Ok(1) => break,
            Ok(0) => return Err(crate::Error::Transport("peek connection type: stream closed".into())),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                if tokio::time::Instant::now() >= deadline {
                    return Err(crate::Error::Transport("peek connection type: timeout waiting for data".into()));
                }
                tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
                continue;
            }
            Err(e) => return Err(crate::Error::Transport(format!("peek connection type: {}", e))),
            _ => {}
        }
    }

    match buf[0] {
        FRP_TLS_HEAD_BYTE | FRP_TLS_DIRECT_BYTE => Ok(ConnectionType::Tls(buf[0])),
        b'G' => Ok(ConnectionType::WebSocket),
        b'F' => Ok(ConnectionType::V2),
        b => Ok(ConnectionType::V1(b)),
    }
}

/// Platform-specific peek of one byte from a TCP stream without consuming it.
#[cfg(unix)]
fn peek_byte(stream: &TcpStream, buf: &mut [u8; 1]) -> io::Result<usize> {
    use std::os::fd::AsRawFd;
    let fd = stream.as_raw_fd();
    let n = unsafe {
        libc::recv(fd, buf.as_mut_ptr() as *mut libc::c_void, 1, libc::MSG_PEEK)
    };
    if n >= 0 {
        Ok(n as usize)
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(windows)]
fn peek_byte(stream: &TcpStream, buf: &mut [u8; 1]) -> io::Result<usize> {
    use std::os::windows::io::AsRawSocket;
    // libc crate does not expose recv/MSG_PEEK on Windows targets.
    // Declare WinSock2 recv directly — ws2_32.dll is linked by std.
    extern "system" {
        fn recv(socket: usize, buf: *mut std::ffi::c_void, len: i32, flags: i32) -> i32;
    }
    const MSG_PEEK: i32 = 0x2;
    let socket = stream.as_raw_socket();
    let n = unsafe {
        recv(socket as usize, buf.as_mut_ptr() as *mut std::ffi::c_void, 1, MSG_PEEK)
    };
    if n >= 0 {
        Ok(n as usize)
    } else {
        Err(io::Error::last_os_error())
    }
}

/// After peeking ConnectionType::Tls, consume the 0x17 head byte from the stream.
/// Must be called before TLS handshake.
pub async fn consume_tls_head_byte(stream: &mut TcpStream) -> Result<(), crate::Error> {
    let mut buf = [0u8; 1];
    tokio::io::AsyncReadExt::read_exact(stream, &mut buf)
        .await
        .map_err(|e| crate::Error::Transport(format!("consume TLS head byte: {e}")))?;
    debug_assert_eq!(buf[0], FRP_TLS_HEAD_BYTE, "expected TLS head byte 0x17");
    Ok(())
}

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
pub async fn accept_websocket(stream: TcpStream) -> Result<IoStream, crate::Error> {
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

    // Send HTTP 101 Switching Protocols
    let mut tcp = reader.into_inner();
    let resp = format!(
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n"
    );
    tcp.write_all(resp.as_bytes()).await
        .map_err(|e| crate::Error::Transport(format!("WS write response: {e}")))?;

    Ok(IoStream::WebSocket(WsByteStream::from_raw_tcp(tcp)))
}

/// TLS configuration.
#[derive(Debug, Clone)]
pub struct TlsConfig {
    pub enable: bool,
    pub cert_file: Option<String>,
    pub key_file: Option<String>,
    pub ca_file: Option<String>,
}

/// Create a TLS acceptor from PEM-encoded cert and key files.
/// If ca_file is provided, client certificates will be verified against it (mTLS).
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

/// Create a TLS connector for client-side TLS.
/// If ca_file is provided, use it as a custom root CA; otherwise use webpki roots.
/// If cert_file/key_file are provided, present client certificate to server (mTLS).
pub fn build_tls_connector(
    ca_file: Option<&str>,
    cert_file: Option<&str>,
    key_file: Option<&str>,
) -> Result<TlsConnector, crate::Error> {
    let mut root_store = rustls::RootCertStore::empty();

    if let Some(ca_path) = ca_file {
        if !ca_path.is_empty() {
            let file = std::fs::File::open(ca_path)
                .map_err(|e| crate::Error::Other(format!("open CA file: {e}")))?;
            let mut reader = std::io::BufReader::new(file);
            let certs = rustls_pemfile::certs(&mut reader)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| crate::Error::Other(format!("read CA certs: {e}")))?;
            root_store.add_parsable_certificates(certs);
        } else {
            root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        }
    } else {
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    }

    let config = if let (Some(cert_path), Some(key_path)) = (cert_file, key_file) {
        if !cert_path.is_empty() && !key_path.is_empty() {
            // Load client certificate chain
            let cert_file = std::fs::File::open(cert_path)
                .map_err(|e| crate::Error::Other(format!("open client cert file: {e}")))?;
            let mut cert_reader = std::io::BufReader::new(cert_file);
            let client_certs = rustls_pemfile::certs(&mut cert_reader)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| crate::Error::Other(format!("read client certs: {e}")))?;

            // Load client private key
            let key_file = std::fs::File::open(key_path)
                .map_err(|e| crate::Error::Other(format!("open client key file: {e}")))?;
            let mut key_reader = std::io::BufReader::new(key_file);
            let client_key = rustls_pemfile::private_key(&mut key_reader)
                .map_err(|e| crate::Error::Other(format!("read client key: {e}")))?
                .ok_or_else(|| crate::Error::Other("no client private key found".into()))?;

            rustls::ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_client_auth_cert(client_certs, client_key)
                .map_err(|e| crate::Error::Other(format!("build mTLS client config: {e}")))?
        } else {
            rustls::ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth()
        }
    } else {
        rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth()
    };

    Ok(TlsConnector::from(Arc::new(config)))
}

/// TLS listener wrapper implementing axum's Listener trait.
/// Used by dashboard and admin API servers to accept TLS connections.
pub struct TlsListener {
    inner: TcpListener,
    acceptor: TlsAcceptor,
}

impl TlsListener {
    pub fn new(inner: TcpListener, acceptor: TlsAcceptor) -> Self {
        Self { inner, acceptor }
    }
}

impl axum::serve::Listener for TlsListener {
    type Io = tokio_rustls::server::TlsStream<TcpStream>;
    type Addr = std::net::SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            let (stream, addr) = match self.inner.accept().await {
                Ok(conn) => conn,
                Err(e) => {
                    tracing::warn!("TLS listener accept error: {}", e);
                    continue;
                }
            };
            match self.acceptor.accept(stream).await {
                Ok(tls_stream) => return (tls_stream, addr),
                Err(e) => {
                    tracing::warn!("TLS handshake error from {}: {}", addr, e);
                    continue;
                }
            }
        }
    }

    fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.inner.local_addr()
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
    fn test_build_tls_connector_with_default_roots() {
        let result = build_tls_connector(None, None, None);
        assert!(result.is_ok(), "TLS connector with default roots should build");
    }

    #[test]
    fn test_build_tls_acceptor_missing_cert() {
        let result = build_tls_acceptor(
            "/nonexistent/cert.pem",
            "/nonexistent/key.pem",
            None,
        );
        assert!(result.is_err(), "TLS acceptor with missing files should fail");
    }
}

