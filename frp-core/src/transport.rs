use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_tungstenite::tungstenite::Message;
use futures_util::stream::Stream;
use futures_util::sink::Sink;
use tokio::net::TcpStream;
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

/// Result of peeking the first byte on the main accept port.
#[derive(Debug, PartialEq)]
pub enum ConnectionType {
    /// 0x17 byte → route to TLS
    Tls,
    /// 'G' (GET) → HTTP WebSocket upgrade
    WebSocket,
    /// V1 type byte → plain frp protocol (the byte is the V1 message type)
    V1(u8),
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
/// Converts between WebSocket binary messages and a byte stream suitable
/// for use with the V1 protocol functions.
pub struct WsByteStream {
    inner: Pin<Box<WebSocketStream<MaybeTlsStream<TcpStream>>>>,
    read_buf: Vec<u8>,
    read_pos: usize,
    needs_flush: bool,
}

impl WsByteStream {
    pub fn new(ws: WebSocketStream<MaybeTlsStream<TcpStream>>) -> Self {
        Self {
            inner: Box::pin(ws),
            read_buf: Vec::new(),
            read_pos: 0,
            needs_flush: false,
        }
    }

    /// Consume the adapter and return the underlying WebSocket stream.
    pub fn into_inner(self) -> WebSocketStream<MaybeTlsStream<TcpStream>> {
        *Pin::into_inner(self.inner)
    }
}

impl AsyncRead for WsByteStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;

        // If we have buffered data, return it
        if this.read_pos < this.read_buf.len() {
            let available = &this.read_buf[this.read_pos..];
            let len = available.len().min(buf.remaining());
            buf.put_slice(&available[..len]);
            this.read_pos += len;
            if this.read_pos >= this.read_buf.len() {
                this.read_buf.clear();
                this.read_pos = 0;
            }
            return Poll::Ready(Ok(()));
        }

        // Read the next WS message
        loop {
            match this.inner.as_mut().poll_next(cx) {
                Poll::Ready(Some(Ok(Message::Binary(data)))) => {
                    let len = data.len().min(buf.remaining());
                    buf.put_slice(&data[..len]);
                    if len < data.len() {
                        this.read_buf = data[len..].to_vec();
                        this.read_pos = 0;
                    }
                    return Poll::Ready(Ok(()));
                }
                Poll::Ready(Some(Ok(Message::Text(text)))) => {
                    let data = text.into_bytes();
                    let len = data.len().min(buf.remaining());
                    buf.put_slice(&data[..len]);
                    if len < data.len() {
                        this.read_buf = data[len..].to_vec();
                        this.read_pos = 0;
                    }
                    return Poll::Ready(Ok(()));
                }
                Poll::Ready(Some(Ok(Message::Ping(_)))) => {
                    // Ignore ping (tungstenite handles pong automatically)
                    continue;
                }
                Poll::Ready(Some(Ok(Message::Close(_)))) => {
                    return Poll::Ready(Ok(()));
                }
                Poll::Ready(Some(Ok(_))) => continue,
                Poll::Ready(Some(Err(e))) => {
                    return Poll::Ready(Err(io::Error::new(io::ErrorKind::Other, e)));
                }
                Poll::Ready(None) => return Poll::Ready(Ok(())),
                Poll::Pending => return Poll::Pending,
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
        let this = &mut *self;
        // If we have unflushed data, flush it first before accepting more.
        // This prevents duplicate messages when write_all re-polls after Pending.
        if !this.needs_flush && !buf.is_empty() {
            match this.inner.as_mut().poll_ready(cx) {
                Poll::Ready(Ok(())) => {
                    match this.inner.as_mut().start_send(Message::Binary(buf.to_vec())) {
                        Ok(()) => {
                            this.needs_flush = true;
                            // Fall through to flush below
                        }
                        Err(e) => return Poll::Ready(Err(io::Error::new(io::ErrorKind::Other, e))),
                    }
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(io::Error::new(io::ErrorKind::Other, e))),
                Poll::Pending => return Poll::Pending,
            }
        }
        // Flush queued data so write_all (which may not call poll_flush) works.
        // tokio's write_all only loops poll_write; it doesn't call poll_flush.
        if this.needs_flush {
            match this.inner.as_mut().poll_flush(cx) {
                Poll::Ready(Ok(())) => {
                    this.needs_flush = false;
                    Poll::Ready(Ok(buf.len()))
                }
                Poll::Ready(Err(e)) => {
                    this.needs_flush = false;
                    Poll::Ready(Err(io::Error::new(io::ErrorKind::Other, e)))
                }
                Poll::Pending => Poll::Pending,
            }
        } else {
            Poll::Ready(Ok(0))
        }
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        if self.needs_flush {
            match self.inner.as_mut().poll_flush(cx) {
                Poll::Ready(Ok(())) => {
                    self.needs_flush = false;
                    Poll::Ready(Ok(()))
                }
                Poll::Ready(Err(e)) => Poll::Ready(Err(io::Error::new(io::ErrorKind::Other, e))),
                Poll::Pending => Poll::Pending,
            }
        } else {
            Poll::Ready(Ok(()))
        }
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        self.inner.as_mut().poll_close(cx)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))
    }
}

// ---------------------------------------------------------------
// IoStream — unified stream type over TCP, TLS, KCP, WebSocket
// ---------------------------------------------------------------

/// Unified stream type for TCP, TLS, KCP, and WebSocket.
/// WebSocket variant wraps a WsByteStream adapter so all variants
/// transparently support AsyncRead/AsyncWrite and V1 frame I/O.
pub enum IoStream {
    Tcp(TcpStream),
    Tls(tokio_rustls::TlsStream<TcpStream>),
    Kcp(KcpStream),
    Quic(QuicStream),
    WebSocket(WsByteStream),
    Yamux(YamuxStream),
    /// AES-128-CFB encrypted control stream.
    /// Created after login by wrapping the inner IoStream.
    Cipher(crate::cipher_stream::CipherStream),
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
        IoStream::Cipher(c)
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
    pub dial_timeout_secs: u64,
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
            dial_timeout_secs: 10,
        }
    }
}

/// Connect to the server with the given options.
pub async fn dial_server(opts: &DialOptions) -> Result<IoStream, crate::Error> {
    use tokio::io::AsyncWriteExt;
    use tokio::time::{timeout, Duration};

    let addr = format!("{}:{}", opts.server_addr, opts.server_port);
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
                // Write FRPTLSHeadByte (0x17) before TLS handshake, matching Go frp v0.69.1
                stream.write_all(&[FRP_TLS_HEAD_BYTE]).await
                    .map_err(|e| crate::Error::Transport(format!("write TLS head byte: {e}")))?;
                let connector = build_tls_connector(opts.tls_ca_file.as_deref())?;
                let server_name = if !opts.tls_server_name.is_empty() {
                    opts.tls_server_name.clone()
                } else {
                    opts.server_addr.clone()
                };
                let server_name = rustls::pki_types::ServerName::try_from(server_name)
                    .map_err(|e| crate::Error::Transport(format!("invalid server name: {e}")))?;
                let tls = connector.connect(server_name, stream).await
                    .map_err(|e| crate::Error::Transport(format!("TLS connect: {e}")))?;
                Ok(IoStream::Tls(tokio_rustls::TlsStream::Client(tls)))
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
            let (ws_stream, _) = tokio_tungstenite::connect_async(url)
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
        FRP_TLS_HEAD_BYTE => Ok(ConnectionType::Tls),
        b'G' => Ok(ConnectionType::WebSocket),
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
pub async fn accept_websocket(stream: TcpStream) -> Result<IoStream, crate::Error> {
    let tls_stream = MaybeTlsStream::Plain(stream);
    let ws_stream = tokio_tungstenite::accept_async(tls_stream)
        .await
        .map_err(|e| crate::Error::Transport(format!("WebSocket accept: {e}")))?;
    Ok(IoStream::WebSocket(WsByteStream::new(ws_stream)))
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
pub fn build_tls_acceptor(
    cert_file: &str,
    key_file: &str,
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

    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| crate::Error::Other(format!("build TLS config: {e}")))?;

    Ok(TlsAcceptor::from(Arc::new(config)))
}

/// Create a TLS connector for client-side TLS.
/// If ca_file is provided, use it as a custom root CA; otherwise use webpki roots.
pub fn build_tls_connector(
    ca_file: Option<&str>,
) -> Result<TlsConnector, crate::Error> {
    let mut root_store = rustls::RootCertStore::empty();

    if let Some(ca_path) = ca_file {
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

    let config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    Ok(TlsConnector::from(Arc::new(config)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_tls_connector_with_default_roots() {
        let result = build_tls_connector(None);
        assert!(result.is_ok(), "TLS connector with default roots should build");
    }

    #[test]
    fn test_build_tls_acceptor_missing_cert() {
        let result = build_tls_acceptor(
            "/nonexistent/cert.pem",
            "/nonexistent/key.pem",
        );
        assert!(result.is_err(), "TLS acceptor with missing files should fail");
    }
}

