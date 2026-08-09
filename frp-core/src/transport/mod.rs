use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::time::Duration;

#[cfg(feature = "kcp")]
use crate::kcp::KcpStream;
#[cfg(feature = "quic")]
use crate::quic::QuicStream;
#[cfg(feature = "websocket")]
use crate::TransportError;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;

use crate::cipher_stream::CipherStream;
use crate::crypto::AeadStream;
use crate::mux::YamuxStream;

mod aead;
mod buffered_read;
mod cipher;
#[cfg(feature = "kcp")]
mod kcp;
mod pre_read;
#[cfg(feature = "quic")]
mod quic;
mod ssh_channel;
mod tcp;
#[cfg(feature = "tls")]
mod tls;
#[cfg(feature = "websocket")]
mod websocket;
mod yamux;

use buffered_read::BufferedReadTransport;
use pre_read::PreReadTransport;
use ssh_channel::SshChannelTransport;
#[cfg(feature = "tls")]
pub use tls::*;
#[cfg(feature = "websocket")]
use websocket::PrependStream;
#[cfg(feature = "websocket")]
pub use websocket::WsByteStream;

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
            "tcp" => TransportProtocol::Tcp,
            _ => return Err(()),
        })
    }
}

// ---------------------------------------------------------------
// IoStream — unified transport over TCP, TLS, KCP, WebSocket, ...
// ---------------------------------------------------------------

/// Helper trait bundling AsyncRead + AsyncWrite + Unpin + Send for
/// use as a dyn-compatible trait object (Tls/SshChannel erasure).
pub trait AsyncReadWrite: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> AsyncReadWrite for T {}

// Transport trait — type-erased transport abstraction
// -----------------------------------------------------------------

/// Type-erased read half of a split [`IoStream`].
pub type BoxedReadHalf = Box<dyn AsyncRead + Unpin + Send>;
/// Type-erased write half of a split [`IoStream`].
pub type BoxedWriteHalf = Box<dyn AsyncWrite + Unpin + Send>;

/// Common trait for every transport layer: raw TCP, TLS, KCP, QUIC,
/// WebSocket, yamux, the AES-128-CFB and AEAD cipher streams, SSH reverse
/// channels, and the PreRead/BufferedRead byte-replay wrappers.
///
/// [`IoStream`] is a type-erased `Box<dyn Transport>`: each implementor is
/// one of the old enum variants, and the consuming methods (`into_encrypted`,
/// `into_split`, `into_tcp`, `into_parts`) replace the per-variant match
/// dispatch.
pub trait Transport: AsyncRead + AsyncWrite + Unpin + Send + 'static {
    /// Variant name for logging / Debug, e.g. `"IoStream::Tcp"`.
    fn debug_name(&self) -> &'static str;

    /// Get the peer address of this stream, if available.
    fn peer_addr(&self) -> Option<SocketAddr> {
        None
    }

    /// Return a reference to the underlying `TcpStream` if this transport is
    /// raw TCP. Useful for zero-copy fast paths (e.g. `splice(2)`) that only
    /// work with raw kernel TCP sockets.
    fn try_tcp(&self) -> Option<&TcpStream> {
        None
    }

    /// Mutable variant of [`Transport::try_tcp`].
    fn try_tcp_mut(&mut self) -> Option<&mut TcpStream> {
        None
    }

    /// Consume and return the underlying `TcpStream` if this transport is raw
    /// TCP. Owned counterpart of [`Transport::try_tcp`] — lets the splice(2)
    /// fast path take ownership of both sockets.
    fn into_tcp(self: Box<Self>) -> Option<TcpStream> {
        None
    }

    /// Consume and return the yamux stream if this is a yamux transport.
    fn into_yamux(self: Box<Self>) -> Option<YamuxStream> {
        None
    }

    /// Wrap this transport in AES-128-CFB encryption for control messages.
    /// Must be called after login (the Login message is NOT encrypted).
    ///
    /// The default wraps in [`CipherStream`]; [`AeadStream`] (already
    /// AEAD-encrypted) and the BufferedRead wrapper override it. `Self` may be
    /// unsized (trait object), so the wrap operates on the box.
    fn into_encrypted(self: Box<Self>, key: [u8; 16]) -> Box<dyn Transport> {
        Box::new(CipherStream::new(self, key))
    }

    /// Split the transport into owned boxed read and write halves.
    ///
    /// The default uses `tokio::io::split`; QUIC overrides with quinn's native
    /// stream halves. The byte-replay wrappers error when unconsumed buffered
    /// bytes remain (mirroring the old `IoStream::into_split` semantics).
    fn into_split(self: Box<Self>) -> io::Result<(BoxedReadHalf, BoxedWriteHalf)> {
        let (r, w) = tokio::io::split(self);
        Ok((Box::new(r), Box::new(w)))
    }

    /// Peel the PreRead byte-replay layer: returns the buffered bytes (minus
    /// any already consumed) and the inner transport. Only
    /// [`PreReadTransport`] overrides this; everything else returns `None`.
    fn into_parts(self: Box<Self>) -> Option<(Vec<u8>, Box<dyn Transport>)> {
        None
    }

    /// Whether Go frp would wrap this transport in yamux (every non-QUIC
    /// transport). QUIC never gets yamux-wrapped — the QUIC connection itself
    /// multiplexes streams.
    fn is_yamux_wrappable(&self) -> bool {
        true
    }

    /// Reason this transport must not be split for bridging, if any.
    /// Encrypted control streams (`Cipher`/`Aead`) are never bridgeable —
    /// splitting them would produce a broken double-encrypted bridge.
    fn bridge_split_err(&self) -> Option<&'static str> {
        None
    }

    /// Consume and return the TLS wrapper if this is a TLS transport.
    #[cfg(feature = "tls")]
    fn into_tls(self: Box<Self>) -> Option<TlsTransport> {
        None
    }
}

/// Unified transport type for TCP, TLS, KCP, QUIC, WebSocket, yamux, the
/// AES-128-CFB / AEAD cipher streams, SSH channels, and the PreRead /
/// BufferedRead byte-replay wrappers.
///
/// A type-erased `Box<dyn Transport>`: each old `IoStream` enum variant is now
/// a [`Transport`] implementor, and the consuming methods (`into_encrypted`,
/// `into_split`, `into_tcp`, `into_parts`) replace the per-variant match
/// dispatch. Constructors are named after the old variants so construction
/// sites read identically.
pub struct IoStream(Box<dyn Transport>);

impl IoStream {
    // ---------------------------------------------------------------
    // Constructors — named after the old enum variants
    // ---------------------------------------------------------------

    /// Raw TCP stream.
    #[allow(non_snake_case)]
    pub fn Tcp(stream: TcpStream) -> Self {
        Self(Box::new(stream))
    }

    /// TLS-wrapped stream — type-erased to accept any TLS-wrapped transport
    /// (e.g. TlsStream<TcpStream> or TlsStream<PreReadStream<..>>). Stores
    /// the peer `SocketAddr` alongside the stream so `peer_addr()` can return
    /// it — unlike the boxed trait object which has no such method.
    #[cfg(feature = "tls")]
    #[allow(non_snake_case)]
    pub fn Tls(stream: Box<dyn AsyncReadWrite>, peer_addr: SocketAddr) -> Self {
        Self(Box::new(TlsTransport::new(stream, peer_addr)))
    }

    /// KCP stream.
    #[cfg(feature = "kcp")]
    #[allow(non_snake_case)]
    pub fn Kcp(stream: KcpStream) -> Self {
        Self(Box::new(stream))
    }

    /// QUIC stream.
    #[cfg(feature = "quic")]
    #[allow(non_snake_case)]
    pub fn Quic(stream: QuicStream) -> Self {
        Self(Box::new(stream))
    }

    /// WebSocket stream (WsByteStream adapter).
    #[cfg(feature = "websocket")]
    #[allow(non_snake_case)]
    pub fn WebSocket(ws: WsByteStream) -> Self {
        Self(Box::new(ws))
    }

    /// Yamux stream.
    #[allow(non_snake_case)]
    pub fn Yamux(stream: YamuxStream) -> Self {
        Self(Box::new(stream))
    }

    /// AEAD encrypted V2 control stream (AES-256-GCM or XChaCha20-Poly1305).
    /// Created after V2 handshake with crypto negotiation.
    #[allow(non_snake_case)]
    pub fn Aead(inner: Box<AeadStream>) -> Self {
        Self(inner)
    }

    /// SSH reverse-forward channel (type-erased).
    #[allow(non_snake_case)]
    pub fn SshChannel(inner: Box<dyn AsyncReadWrite>) -> Self {
        Self(Box::new(SshChannelTransport(inner)))
    }

    /// Pre-read bytes followed by an inner transport.
    /// Used after connection type detection when bytes have been consumed
    /// but need to be replayed (e.g., V1 type byte in non-V2 connections).
    #[allow(non_snake_case)]
    pub fn PreRead(bytes: Vec<u8>, inner: Box<dyn Transport>) -> Self {
        Self(Box::new(PreReadTransport::new(bytes, inner)))
    }

    /// Buffered bytes followed by an inner transport.
    /// Used when V2 magic is detected on a yamux stream: if the bytes are NOT
    /// V2 magic, they're buffered and replayed for V1 processing. The usize
    /// tracks the current read position into the buffer.
    #[allow(non_snake_case)]
    pub fn BufferedRead(buf: Vec<u8>, pos: usize, inner: Box<dyn Transport>) -> Self {
        Self(Box::new(BufferedReadTransport::new(buf, pos, inner)))
    }

    /// Consume and return the inner boxed transport.
    pub fn into_boxed(self) -> Box<dyn Transport> {
        self.0
    }

    // ---------------------------------------------------------------
    // Delegated methods (one level of indirection over the trait object)
    // ---------------------------------------------------------------

    /// Variant name for logging / Debug, e.g. `"IoStream::Tcp"`.
    pub fn debug_name(&self) -> &'static str {
        self.0.debug_name()
    }

    /// Write a V1 protocol frame to this stream.
    pub async fn write_v1_frame(
        &mut self,
        msg: &crate::msg::FrpMessage,
    ) -> Result<(), crate::Error> {
        crate::protocol::write_msg_v1(&mut self.0, msg).await
    }

    /// Read a V1 protocol frame from this stream.
    pub async fn read_v1_frame(&mut self) -> Result<crate::msg::FrpMessage, crate::Error> {
        crate::protocol::read_msg_v1(&mut self.0).await
    }

    /// Write a V2 protocol frame (binary framing + JSON payload) to this
    /// stream.
    pub async fn write_v2_frame(
        &mut self,
        msg: &crate::msg::FrpMessage,
    ) -> Result<(), crate::Error> {
        use tokio::io::AsyncWriteExt;
        crate::protocol::write_msg_v2_inner(&mut self.0, msg).await?;
        self.0
            .flush()
            .await
            .map_err(|e| crate::Error::Transport(format!("flush: {e}").into()))
    }

    /// Read a V2 protocol frame (binary framing + JSON payload) from this
    /// stream.
    pub async fn read_v2_frame(&mut self) -> Result<crate::msg::FrpMessage, crate::Error> {
        crate::protocol::read_msg_v2(&mut self.0).await
    }

    /// Write a raw V2 frame (for handshake frames like ClientHello/ServerHello).
    /// Lower-level than write_v2_frame — caller controls frame_type and raw
    /// payload bytes.
    pub async fn write_raw_v2_frame(
        &mut self,
        frame_type: u16,
        flags: u16,
        payload: &[u8],
    ) -> Result<(), crate::Error> {
        crate::protocol::write_v2_frame_raw(&mut self.0, frame_type, flags, payload).await
    }

    /// Read a raw V2 frame (for handshake). Returns (frame_type, flags,
    /// payload_bytes).
    pub async fn read_raw_v2_frame(&mut self) -> Result<(u16, u16, Vec<u8>), crate::Error> {
        crate::protocol::read_v2_frame_raw(&mut self.0).await
    }

    /// Get the peer address of this stream, if available.
    pub fn peer_addr(&self) -> Option<SocketAddr> {
        self.0.peer_addr()
    }

    /// Return a reference to the underlying `TcpStream` if this transport is
    /// raw TCP. Returns `None` for PreRead (has unconsumed bytes that cannot
    /// be spliced), TLS, KCP, WebSocket, yamux, cipher, and other wrapped
    /// transports.
    ///
    /// Useful for zero-copy fast paths (e.g. `splice(2)`) that only work
    /// with raw kernel TCP sockets.
    pub fn try_tcp(&self) -> Option<&TcpStream> {
        self.0.try_tcp()
    }

    /// Mutable variant of [`IoStream::try_tcp`].
    pub fn try_tcp_mut(&mut self) -> Option<&mut TcpStream> {
        self.0.try_tcp_mut()
    }

    /// Consume and return the underlying `TcpStream` if this is raw TCP.
    /// Owned counterpart of [`IoStream::try_tcp`].
    pub fn into_tcp(self) -> Option<TcpStream> {
        self.0.into_tcp()
    }

    /// Consume and return the yamux stream if this is a yamux transport.
    pub fn into_yamux(self) -> Option<YamuxStream> {
        self.0.into_yamux()
    }

    /// Peel the PreRead byte-replay layer: buffered bytes (minus any already
    /// consumed) plus the inner transport. `None` for non-PreRead transports.
    pub fn into_parts(self) -> Option<(Vec<u8>, Box<dyn Transport>)> {
        self.0.into_parts()
    }

    /// Whether Go frp would wrap this transport in yamux (every non-QUIC
    /// transport).
    pub fn is_yamux_wrappable(&self) -> bool {
        self.0.is_yamux_wrappable()
    }

    /// Consume and return the TLS wrapper if this is a TLS transport.
    #[cfg(feature = "tls")]
    pub fn into_tls(self) -> Option<TlsTransport> {
        self.0.into_tls()
    }

    /// Wrap this stream in AES-128-CFB encryption for control messages.
    /// Must be called after login (the Login message is NOT encrypted).
    pub fn into_encrypted(self, key: [u8; 16]) -> Self {
        Self(self.0.into_encrypted(key))
    }

    /// Split the stream into owned boxed read and write halves.
    pub fn into_split(self) -> io::Result<(BoxedReadHalf, BoxedWriteHalf)> {
        self.0.into_split()
    }
}

impl From<Box<dyn Transport>> for IoStream {
    fn from(inner: Box<dyn Transport>) -> Self {
        Self(inner)
    }
}

impl std::fmt::Debug for IoStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0.debug_name())
    }
}

// IoStream itself is a transport: lets `Box<IoStream>` nest inside the
// PreRead/BufferedRead wrappers (and any future wrapper) without special
// handling — the boxed IoStream delegates down to the concrete transport.
impl Transport for IoStream {
    fn debug_name(&self) -> &'static str {
        self.0.debug_name()
    }
    fn peer_addr(&self) -> Option<SocketAddr> {
        self.0.peer_addr()
    }
    fn try_tcp(&self) -> Option<&TcpStream> {
        self.0.try_tcp()
    }
    fn try_tcp_mut(&mut self) -> Option<&mut TcpStream> {
        self.0.try_tcp_mut()
    }
    fn into_tcp(self: Box<Self>) -> Option<TcpStream> {
        self.0.into_tcp()
    }
    fn into_yamux(self: Box<Self>) -> Option<YamuxStream> {
        self.0.into_yamux()
    }
    fn into_encrypted(self: Box<Self>, key: [u8; 16]) -> Box<dyn Transport> {
        self.0.into_encrypted(key)
    }
    fn into_split(self: Box<Self>) -> io::Result<(BoxedReadHalf, BoxedWriteHalf)> {
        self.0.into_split()
    }
    fn into_parts(self: Box<Self>) -> Option<(Vec<u8>, Box<dyn Transport>)> {
        self.0.into_parts()
    }
    fn is_yamux_wrappable(&self) -> bool {
        self.0.is_yamux_wrappable()
    }
    fn bridge_split_err(&self) -> Option<&'static str> {
        self.0.bridge_split_err()
    }
    #[cfg(feature = "tls")]
    fn into_tls(self: Box<Self>) -> Option<TlsTransport> {
        self.0.into_tls()
    }
}

impl AsyncRead for IoStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_read(cx, buf)
    }
}

impl AsyncWrite for IoStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().0).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_shutdown(cx)
    }
}

// ---------------------------------------------------------------
// Per-transport Transport impls (one per old enum variant)
// ---------------------------------------------------------------

// TcpStream's impl lives in `tcp.rs`.

// TlsTransport and the TLS builders live in `tls.rs`.

// YamuxStream's impl lives in `yamux.rs`.

// PreReadTransport lives in `pre_read.rs`.
// BufferedReadTransport lives in `buffered_read.rs`.

/// Split an `IoStream` into boxed read/write halves for bridging.
///
/// The bridge helpers (`bridge_encrypted` & friends) are generic over their
/// stream types, so splitting per-transport would monomorphize each bridge
/// once per `IoStream` variant (~10 copies, each several KiB). Boxing the
/// halves erases the types so a single monomorphization is shared by every
/// transport.
///
/// Splits exactly like [`IoStream::into_split`] per transport, so the halves
/// wrap the same streams. Returns an `Err` with a log message for transports
/// that cannot be bridged.
///
/// Reachability note: on the old encrypted+injector path the work conn was
/// split with `into_split().unwrap()` — panicking on `PreRead`/`BufferedRead`
/// carrying unconsumed buffered bytes, and silently splitting `Cipher`/`Aead`
/// into a broken double-encrypted bridge. Here those cases degrade to an `Err`
/// warn or a plain split instead. Reachable work conns arrive as
/// `Tcp`/`Tls`/`Kcp`/`WS`/`Yamux`/`SshChannel`/empty-`PreRead`/consumed-
/// `BufferedRead` (all split identically to the old code), so the reachable
/// behavior is unchanged.
pub fn split_work_conn_halves(
    work_conn: IoStream,
) -> Result<(BoxedReadHalf, BoxedWriteHalf), &'static str> {
    // Cipher/Aead control streams are never bridgeable (defensive guard —
    // unreachable on the bridge path, preserved from the old match).
    if let Some(msg) = work_conn.bridge_split_err() {
        return Err(msg);
    }
    work_conn
        .into_split()
        .map_err(|_| "BufferedRead with unconsumed bytes in bridge")
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

/// DNS record types used by the custom resolver.
const DNS_QTYPE_A: u16 = 1;
const DNS_QTYPE_AAAA: u16 = 28;

/// Resolve a hostname to an IP address using a specific DNS server.
///
/// Sends standard DNS A and AAAA queries over UDP concurrently and handles
/// name compression pointers in the response. IPv4 is preferred: if the A
/// query succeeds its address wins even when AAAA also succeeds. If A fails
/// but AAAA succeeds, the IPv6 address is returned. When both fail, the A
/// query's error is returned (preserving the pre-AAAA behaviour).
pub async fn resolve_host_with_dns(host: &str, dns_server: &str) -> Result<String, crate::Error> {
    use std::net::SocketAddr;
    use std::str::FromStr;

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

    // Query A and AAAA concurrently. IPv4 is preferred — an A answer wins
    // even when AAAA also succeeds; only fall back to AAAA when A fails.
    // The AAAA query runs in a spawned task so an A success returns
    // immediately (join! would otherwise stall the whole resolution on the
    // AAAA timeout, a 5s regression on every connect when AAAA is dropped).
    let host_for_aaaa = host.to_string();
    let aaaa_task =
        tokio::spawn(async move { dns_query(&host_for_aaaa, dns_addr, DNS_QTYPE_AAAA).await });
    let a_result = dns_query(host, dns_addr, DNS_QTYPE_A).await;
    match a_result {
        Ok(ip) => {
            aaaa_task.abort();
            Ok(ip)
        }
        Err(a_err) => match aaaa_task.await {
            Ok(Ok(ip)) => Ok(ip),
            _ => Err(a_err),
        },
    }
}

/// Send one DNS query for `qtype` (A or AAAA) to `dns_addr` over UDP and
/// return the first matching address as a string.
///
/// Uses a random transaction ID and a 5s timeout, mirroring the historical
/// single-query behaviour.
async fn dns_query(
    host: &str,
    dns_addr: std::net::SocketAddr,
    qtype: u16,
) -> Result<String, crate::Error> {
    use tokio::net::UdpSocket;
    use tokio::time::{timeout, Duration};

    // Build DNS query (single question, RD=1)
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
    query.extend_from_slice(&qtype.to_be_bytes()); // QTYPE = A / AAAA
    query.extend_from_slice(&[0x00, 0x01]); // QCLASS = IN

    // Send query over UDP
    let socket = UdpSocket::bind("0.0.0.0:0")
        .await
        .map_err(|e| crate::Error::Transport(format!("DNS: bind: {e}").into()))?;
    socket
        .connect(dns_addr)
        .await
        .map_err(|e| crate::Error::Transport(format!("DNS: connect {dns_addr}: {e}").into()))?;
    socket
        .send(&query)
        .await
        .map_err(|e| crate::Error::Transport(format!("DNS: send to {dns_addr}: {e}").into()))?;

    let mut buf = [0u8; 512];
    let n = timeout(Duration::from_secs(5), socket.recv(&mut buf))
        .await
        .map_err(|_| crate::Error::Transport("DNS: timeout".into()))?
        .map_err(|e| crate::Error::Transport(format!("DNS: recv: {e}").into()))?;

    let ips = parse_dns_response(&buf[..n], txid, qtype)
        .map_err(|e| crate::Error::Transport(format!("DNS resolve {host}: {e}").into()))?;
    // First matching address only (A preferred by the caller; the Vec keeps
    // the door open for future Happy-Eyeballs style multi-address use).
    Ok(ips[0].to_string())
}

/// Parse a DNS response, verifying the transaction ID and collecting every
/// answer record whose type matches `qtype` (1 = A, 28 = AAAA).
///
/// Returns the matching IP addresses or an error string (without the
/// "DNS resolve {host}: " prefix — callers add it) explaining why no
/// matching record was found. Pure function: no I/O, so it is unit-testable
/// against hand-built response bytes.
fn parse_dns_response(
    response: &[u8],
    txid: u16,
    qtype: u16,
) -> Result<Vec<std::net::IpAddr>, String> {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    if response.len() < 12 {
        return Err("response too short".into());
    }

    // Verify transaction ID
    let resp_txid = u16::from_be_bytes([response[0], response[1]]);
    if resp_txid != txid {
        return Err(format!("txid mismatch (sent {txid}, got {resp_txid})"));
    }

    let ancount = u16::from_be_bytes([response[6], response[7]]) as usize;
    if ancount == 0 {
        return Err("no records found".into());
    }

    // Skip 12-byte header + question section to reach answers
    let mut pos = 12;
    pos = skip_dns_name(response, pos); // QNAME
    pos += 4; // QTYPE (2) + QCLASS (2)

    let mut ips: Vec<IpAddr> = Vec::new();
    // Read answers
    for _ in 0..ancount {
        if pos + 10 > response.len() {
            return Err("truncated answer section".into());
        }
        pos = skip_dns_name(response, pos); // NAME (may be compression pointer)
                                            // skip_dns_name trusts the wire's label lengths and may advance past
                                            // the buffer on a malformed response — re-check before indexing
                                            // (a crafted DNS reply must never panic the resolver).
        if pos + 10 > response.len() {
            return Err("truncated answer section".into());
        }
        let rdtype = u16::from_be_bytes([response[pos], response[pos + 1]]);
        let rdlength = u16::from_be_bytes([response[pos + 8], response[pos + 9]]) as usize;
        pos += 10; // past TYPE(2)+CLASS(2)+TTL(4)+RDLENGTH(2)
        if pos + rdlength > response.len() {
            return Err("truncated RDATA".into());
        }
        if rdtype == qtype {
            if qtype == DNS_QTYPE_A && rdlength == 4 {
                // A record: 4-byte IPv4 address
                ips.push(IpAddr::V4(Ipv4Addr::new(
                    response[pos],
                    response[pos + 1],
                    response[pos + 2],
                    response[pos + 3],
                )));
            } else if qtype == DNS_QTYPE_AAAA && rdlength == 16 {
                // AAAA record: 16-byte IPv6 address
                let octets: [u8; 16] = response[pos..pos + 16]
                    .try_into()
                    .map_err(|_| "truncated RDATA".to_string())?;
                ips.push(IpAddr::V6(Ipv6Addr::from(octets)));
            }
        }
        pos += rdlength;
    }

    if ips.is_empty() {
        return Err(match qtype {
            DNS_QTYPE_A => "no A record found",
            DNS_QTYPE_AAAA => "no AAAA record found",
            _ => "no matching record found",
        }
        .into());
    }
    Ok(ips)
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

    // Configure TCP keepalive after connection: idle time + probe
    // interval/retries via `set_keepalive` (same behavior as server-side
    // accepted connections; a failed socket option is debug-logged and
    // ignored, matching `set_nodelay`).
    crate::transport::set_keepalive(&stream, opts.keepalive_secs);

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

/// Set TCP keepalive on a stream.
///
/// In addition to the idle time, supported platforms also set a short probe
/// interval and a small probe count so a dead peer is reclaimed in minutes
/// instead of hours (kernel defaults can otherwise stretch one probe period
/// to ~75s with 9 retries). A failed socket option is logged at debug and
/// ignored — consistent with `set_nodelay` error-handling policy.
pub fn set_keepalive(stream: &tokio::net::TcpStream, secs: u64) {
    if secs == 0 {
        return;
    }
    let keepalive = socket2::SockRef::from(stream);
    let ka = socket2::TcpKeepalive::new().with_time(Duration::from_secs(secs));
    // Probe interval/retries mirror socket2 0.6.5's `with_interval` support
    // list (allow-list, so platforms added upstream are covered automatically
    // instead of drifting from a denylist). `with_retries` needs the `all`
    // feature, enabled at the workspace level.
    #[cfg(any(
        target_os = "android",
        target_os = "dragonfly",
        target_os = "emscripten",
        target_os = "freebsd",
        target_os = "fuchsia",
        target_os = "illumos",
        target_os = "ios",
        target_os = "visionos",
        target_os = "linux",
        target_os = "macos",
        target_os = "netbsd",
        target_os = "tvos",
        target_os = "watchos",
        target_os = "windows",
        target_os = "cygwin",
        target_os = "nuttx",
        target_os = "wasi",
    ))]
    let ka = ka
        .with_interval(Duration::from_secs((secs / 10).clamp(1, 60)))
        .with_retries(3);
    if let Err(e) = keepalive.set_tcp_keepalive(&ka) {
        tracing::debug!(error = %e, keepalive_secs = secs,
            "set_keepalive failed (continuing without keepalive)");
    }
}

/// Connect to a target through an HTTP CONNECT or SOCKS5 proxy.
/// Returns an IoStream that tunnels to `target_host:target_port` — an
/// `IoStream::BufferedRead` when the CONNECT response read-ahead captured
/// bytes past the headers.
pub(crate) async fn connect_via_proxy(
    proxy_url: &str,
    target_host: &str,
    target_port: u16,
    dial_timeout_secs: u64,
    keepalive_secs: u64,
) -> Result<IoStream, crate::Error> {
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

    // Configure TCP keepalive and disable Nagle on the tunneled connection,
    // matching connect_direct (Go frp parity).
    set_keepalive(&stream, keepalive_secs);
    crate::transport::set_nodelay(&stream);

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

            let mut reader = BufReader::new(stream);

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

            // Capture any bytes BufReader read-ahead past the CONNECT response
            // headers — the tunneled peer's first message can arrive in the
            // same TCP segment. Dropping them (the previous behavior) silently
            // ate up to 8 KiB of read-ahead, corrupting the first protocol
            // message. Mirrors the WS upgrade paths' leftover handling.
            let leftover = reader.buffer().to_vec();
            let stream = reader.into_inner();

            if !leftover.is_empty() {
                tracing::debug!(
                    leftover_len = leftover.len(),
                    "proxy CONNECT: replaying {} read-ahead bytes via BufferedRead",
                    leftover.len()
                );
                return Ok(IoStream::BufferedRead(
                    leftover,
                    0,
                    Box::new(IoStream::Tcp(stream)),
                ));
            }
            return Ok(IoStream::Tcp(stream));
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
                // RFC 1929 username/password sub-negotiation. The server
                // demanded credentials we never offered (no userinfo in the
                // proxy URL) — a broken or malicious proxy. Fail the dial
                // instead of panicking on remote input.
                let (user, pass) = match auth {
                    Some(creds) => creds,
                    None => {
                        return Err(crate::Error::Transport(
                            "SOCKS5 auth rejected: server requires username/password but none configured"
                                .into(),
                        ));
                    }
                };
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

    Ok(IoStream::Tcp(stream))
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
            let (stream, _conn) =
                crate::quic::dial_quic(&addr, server_name, ca_file, Some(opts.dial_timeout_secs))
                    .await
                    .map_err(|e| crate::Error::Transport(format!("QUIC dial: {e}").into()))?;
            return Ok(IoStream::Quic(stream));
        }
        _ => {}
    }

    // TCP, WebSocket, WSS: connect via upstream proxy if configured, otherwise direct TCP.
    #[cfg_attr(not(feature = "tls"), allow(unused_mut))]
    let mut stream: IoStream = if let Some(ref proxy_url) = opts.proxy_url {
        if proxy_url.is_empty() {
            // Empty string = direct connection
            IoStream::Tcp(connect_direct(&addr, peer, opts).await?)
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
                opts.keepalive_secs,
            )
            .await?
        }
    } else {
        IoStream::Tcp(connect_direct(&addr, peer, opts).await?)
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
                Ok(stream)
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

    Ok((ct, IoStream::PreRead(magic_buf.to_vec(), Box::new(stream))))
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

/// Serve buffered bytes from `pre_read` starting at `pos`.
/// Returns `true` if bytes were served from the buffer, `false` if exhausted.
pub(crate) fn poll_pre_read(pre_read: &[u8], pos: &mut usize, buf: &mut ReadBuf<'_>) -> bool {
    if *pos < pre_read.len() {
        let remaining = &pre_read[*pos..];
        let n = remaining.len().min(buf.remaining());
        buf.put_slice(&remaining[..n]);
        *pos += n;
        true
    } else {
        false
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
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if poll_pre_read(&this.pre_read, &mut this.pos, buf) {
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut this.inner).poll_read(cx, buf)
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
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn test_socks5_auth_required_without_credentials_returns_error() {
        // Regression test: a proxy that demands RFC 1929 user/pass auth
        // (method 0x02) while the proxy URL carries no userinfo must fail the
        // dial with an error — NOT panic on remote input (the pre-fix behavior).
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let srv = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            // No userinfo in the proxy URL, so the client offers the no-auth
            // greeting [0x05, 0x01, 0x00] — exactly 3 bytes (one method), not
            // 4. Reading 4 bytes here would deadlock: the client blocks on the
            // auth response after its 3-byte greeting.
            let mut greeting = [0u8; 3];
            sock.read_exact(&mut greeting).await.unwrap();
            assert_eq!(greeting[0], 0x05, "SOCKS5 greeting version");
            assert_eq!(greeting[1], 0x01, "client must offer no-auth method");
            // Demand username/password (method 0x02) even though the client
            // never offered it — a broken/malicious proxy.
            sock.write_all(&[0x05, 0x02]).await.unwrap();
            // The client must bail out here without sending a CONNECT request;
            // dropping the socket closes the connection once it returns Err.
        });

        let err = connect_via_proxy(&format!("socks5://{addr}"), "127.0.0.1", 80, 5, 0)
            .await
            .expect_err("auth-demanding proxy with no credentials in URL must fail");
        assert!(
            err.to_string().contains("username/password"),
            "error should explain missing credentials, got: {err}"
        );

        srv.await.unwrap();
    }

    #[tokio::test]
    async fn test_socks5_no_auth_connect_succeeds() {
        // Sanity check that the plain no-auth handshake path is not broken by
        // the auth-required fix: greeting → no-auth method selection →
        // CONNECT request → success response.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let srv = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            // Greeting: VER + single no-auth method.
            let mut greeting = [0u8; 3];
            sock.read_exact(&mut greeting).await.unwrap();
            assert_eq!(greeting, [0x05, 0x01, 0x00], "no-auth greeting");
            // Accept no-auth.
            sock.write_all(&[0x05, 0x00]).await.unwrap();
            // CONNECT request: VER CMD RSV ATYP DST.ADDR DST.PORT.
            // Plain socks5 resolves locally → target "127.0.0.1" is an IP → ATYP=1.
            let mut req = [0u8; 10];
            sock.read_exact(&mut req).await.unwrap();
            assert_eq!(req[0], 0x05, "VER");
            assert_eq!(req[1], 0x01, "CMD=CONNECT");
            assert_eq!(req[2], 0x00, "RSV");
            assert_eq!(req[3], 0x01, "ATYP=IPv4");
            assert_eq!(&req[4..8], &[127, 0, 0, 1], "DST.ADDR=127.0.0.1");
            assert_eq!(u16::from_be_bytes([req[8], req[9]]), 12345, "DST.PORT");
            // Success reply: VER REP RSV ATYP BND.ADDR BND.PORT.
            sock.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await
                .unwrap();
            // Dropping the socket closes the tunnel once the test drops the stream.
        });

        match connect_via_proxy(&format!("socks5://{addr}"), "127.0.0.1", 12345, 5, 0).await {
            Ok(_) => {}
            Err(e) => panic!("no-auth SOCKS5 handshake should succeed, got: {e}"),
        }

        srv.await.unwrap();
    }

    #[tokio::test]
    async fn test_resolve_host_with_dns_aaaa_fallback() {
        // A mock DNS server that answers A queries with NXDOMAIN-style empty
        // answers and AAAA queries with an IPv6 address. resolve_host_with_dns
        // must fall back from A to AAAA.
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let dns_addr = socket.local_addr().unwrap();
        let srv = tokio::spawn(async move {
            // Answer every datagram the resolver sends (one A + one AAAA).
            let mut buf = [0u8; 512];
            for _ in 0..2 {
                let (n, peer) = socket.recv_from(&mut buf).await.unwrap();
                let req = &buf[..n];
                let txid = [req[0], req[1]];
                // QTYPE is the 2 bytes right before the QCLASS at the end.
                let qtype = u16::from_be_bytes([req[n - 4], req[n - 3]]);
                let mut resp = Vec::new();
                resp.extend_from_slice(&txid);
                resp.extend_from_slice(&[0x81, 0x80]); // flags: response, RD, RA
                resp.extend_from_slice(&[0x00, 0x01]); // QDCOUNT
                let has_answer = qtype == DNS_QTYPE_AAAA;
                resp.extend_from_slice(&[0x00, if has_answer { 1 } else { 0 }]); // ANCOUNT
                resp.extend_from_slice(&[0x00, 0x00]); // NSCOUNT
                resp.extend_from_slice(&[0x00, 0x00]); // ARCOUNT
                                                       // Echo the question section verbatim.
                resp.extend_from_slice(&req[12..n - 4]);
                resp.extend_from_slice(&qtype.to_be_bytes());
                resp.extend_from_slice(&[0x00, 0x01]); // QCLASS = IN
                if has_answer {
                    resp.extend_from_slice(&[0xC0, 0x0C]); // pointer to QNAME
                    resp.extend_from_slice(&qtype.to_be_bytes());
                    resp.extend_from_slice(&[0x00, 0x01]); // CLASS = IN
                    resp.extend_from_slice(&[0x00, 0x00, 0x00, 0x3C]); // TTL = 60
                    resp.extend_from_slice(&[0x00, 0x10]); // RDLENGTH = 16
                    resp.extend_from_slice(&[
                        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
                    ]);
                }
                socket.send_to(&resp, peer).await.unwrap();
            }
        });

        let ip = resolve_host_with_dns("example.com", &dns_addr.to_string())
            .await
            .unwrap();
        assert_eq!(ip, "2001:db8::1");

        srv.await.unwrap();
    }

    #[tokio::test]
    async fn test_resolve_host_with_dns_ipv4_preferred() {
        // When both A and AAAA succeed, the A result wins.
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let dns_addr = socket.local_addr().unwrap();
        let srv = tokio::spawn(async move {
            let mut buf = [0u8; 512];
            for _ in 0..2 {
                let (n, peer) = socket.recv_from(&mut buf).await.unwrap();
                let req = &buf[..n];
                let txid = [req[0], req[1]];
                let qtype = u16::from_be_bytes([req[n - 4], req[n - 3]]);
                let mut resp = Vec::new();
                resp.extend_from_slice(&txid);
                resp.extend_from_slice(&[0x81, 0x80]);
                resp.extend_from_slice(&[0x00, 0x01]); // QDCOUNT
                resp.extend_from_slice(&[0x00, 0x01]); // ANCOUNT
                resp.extend_from_slice(&[0x00, 0x00]);
                resp.extend_from_slice(&[0x00, 0x00]);
                resp.extend_from_slice(&req[12..n - 4]);
                resp.extend_from_slice(&qtype.to_be_bytes());
                resp.extend_from_slice(&[0x00, 0x01]);
                resp.extend_from_slice(&[0xC0, 0x0C]);
                resp.extend_from_slice(&qtype.to_be_bytes());
                resp.extend_from_slice(&[0x00, 0x01]);
                resp.extend_from_slice(&[0x00, 0x00, 0x00, 0x3C]);
                match qtype {
                    DNS_QTYPE_A => {
                        resp.extend_from_slice(&[0x00, 0x04]); // RDLENGTH = 4
                        resp.extend_from_slice(&[1, 2, 3, 4]);
                    }
                    _ => {
                        resp.extend_from_slice(&[0x00, 0x10]); // RDLENGTH = 16
                        resp.extend_from_slice(&[
                            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
                        ]);
                    }
                }
                socket.send_to(&resp, peer).await.unwrap();
            }
        });

        let ip = resolve_host_with_dns("example.com", &dns_addr.to_string())
            .await
            .unwrap();
        assert_eq!(ip, "1.2.3.4");

        srv.await.unwrap();
    }

    #[test]
    fn test_parse_dns_response_a_record() {
        // A query answered with a single A record.
        let resp = dns_response_bytes(0x1234, &[(DNS_QTYPE_A, &[1, 2, 3, 4])]);
        let ips = parse_dns_response(&resp, 0x1234, DNS_QTYPE_A).unwrap();
        assert_eq!(ips, vec![std::net::IpAddr::from([1, 2, 3, 4])]);
    }

    #[test]
    fn test_parse_dns_response_aaaa_record() {
        let v6 = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let resp = dns_response_bytes(0x1234, &[(DNS_QTYPE_AAAA, &v6)]);
        let ips = parse_dns_response(&resp, 0x1234, DNS_QTYPE_AAAA).unwrap();
        assert_eq!(
            ips,
            vec![std::net::IpAddr::from([
                0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1
            ])]
        );
    }

    #[test]
    fn test_parse_dns_response_mixed_answers() {
        // A response carrying both an A and an AAAA record: each qtype query
        // only sees its own records.
        let resp = dns_response_bytes(
            0x1234,
            &[
                (DNS_QTYPE_A, &[10, 0, 0, 1]),
                (
                    DNS_QTYPE_AAAA,
                    &[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2],
                ),
            ],
        );
        let a_ips = parse_dns_response(&resp, 0x1234, DNS_QTYPE_A).unwrap();
        assert_eq!(a_ips, vec![std::net::IpAddr::from([10, 0, 0, 1])]);
        let aaaa_ips = parse_dns_response(&resp, 0x1234, DNS_QTYPE_AAAA).unwrap();
        assert_eq!(aaaa_ips.len(), 1);
        assert!(aaaa_ips[0].is_ipv6());
    }

    #[test]
    fn test_parse_dns_response_no_records() {
        // ANCOUNT = 0.
        let resp = dns_response_bytes(0x1234, &[]);
        let err = parse_dns_response(&resp, 0x1234, DNS_QTYPE_A).unwrap_err();
        assert!(err.contains("no records found"), "got: {err}");
    }

    #[test]
    fn test_parse_dns_response_wrong_type() {
        // A query but the answer is AAAA-only -> "no A record found".
        let resp = dns_response_bytes(
            0x1234,
            &[(
                DNS_QTYPE_AAAA,
                &[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            )],
        );
        let err = parse_dns_response(&resp, 0x1234, DNS_QTYPE_A).unwrap_err();
        assert!(err.contains("no A record found"), "got: {err}");
        // And the reverse for AAAA.
        let resp = dns_response_bytes(0x1234, &[(DNS_QTYPE_A, &[1, 2, 3, 4])]);
        let err = parse_dns_response(&resp, 0x1234, DNS_QTYPE_AAAA).unwrap_err();
        assert!(err.contains("no AAAA record found"), "got: {err}");
    }

    #[test]
    fn test_parse_dns_response_txid_mismatch() {
        let resp = dns_response_bytes(0x1234, &[(DNS_QTYPE_A, &[1, 2, 3, 4])]);
        let err = parse_dns_response(&resp, 0x5678, DNS_QTYPE_A).unwrap_err();
        assert!(err.contains("txid mismatch"), "got: {err}");
    }

    /// Build a well-formed DNS response header + question ("example.com") +
    /// the given answers, using the supplied transaction ID.
    fn dns_response_bytes(txid: u16, answers: &[(u16, &[u8])]) -> Vec<u8> {
        let mut resp = Vec::new();
        resp.extend_from_slice(&txid.to_be_bytes());
        resp.extend_from_slice(&[0x81, 0x80]); // flags: response, RD, RA
        resp.extend_from_slice(&[0x00, 0x01]); // QDCOUNT = 1
        resp.extend_from_slice(&(answers.len() as u16).to_be_bytes()); // ANCOUNT
        resp.extend_from_slice(&[0x00, 0x00]); // NSCOUNT
        resp.extend_from_slice(&[0x00, 0x00]); // ARCOUNT
                                               // Question: "example.com", QTYPE=A, QCLASS=IN
        resp.extend_from_slice(&[0x07]);
        resp.extend_from_slice(b"example");
        resp.extend_from_slice(&[0x03]);
        resp.extend_from_slice(b"com");
        resp.push(0x00);
        resp.extend_from_slice(&DNS_QTYPE_A.to_be_bytes());
        resp.extend_from_slice(&[0x00, 0x01]);
        // Answers
        for (qtype, rdata) in answers {
            resp.extend_from_slice(&[0xC0, 0x0C]); // pointer to QNAME
            resp.extend_from_slice(&qtype.to_be_bytes());
            resp.extend_from_slice(&[0x00, 0x01]); // CLASS = IN
            resp.extend_from_slice(&[0x00, 0x00, 0x00, 0x3C]); // TTL = 60
            resp.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
            resp.extend_from_slice(rdata);
        }
        resp
    }
}

#[test]
fn test_parse_dns_response_malformed_never_panics() {
    // A crafted response whose answer NAME label length overruns the
    // buffer must produce an error, never a panic (regression guard for
    // the post-skip bounds re-check).
    // Header (12B): txid 0x1234, flags 0x0100, QDCOUNT=1, ANCOUNT=1.
    let mut resp = vec![0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x01, 0, 0, 0, 0];
    // Question: "example.com" + QTYPE/QCLASS.
    resp.extend_from_slice(&[7]); // label len 7
    resp.extend_from_slice(b"example");
    resp.extend_from_slice(&[3]);
    resp.extend_from_slice(b"com");
    resp.push(0); // root
    resp.extend_from_slice(&[0, 1, 0, 1]); // QTYPE=A QCLASS=IN

    // Answer: NAME claims a 63-byte label but the buffer ends before the
    // claimed label body — the loop-top check passes but skip_dns_name
    // overruns; the post-skip re-check must return Err, not panic.
    resp.extend_from_slice(&[63]);
    resp.extend_from_slice(&[0, 1, 0, 1, 0, 0, 0, 0, 0, 4]); // 10B fake answer hdr
    let err = parse_dns_response(&resp, 0x1234, DNS_QTYPE_A).unwrap_err();
    assert!(
        err.contains("truncated") || err.contains("too short"),
        "got: {err}"
    );
    // Also: answer NAME is a compression pointer to beyond EOF.
    let mut resp2 = vec![0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x01, 0, 0, 0, 0];
    resp2.extend_from_slice(&[0]); // empty QNAME
    resp2.extend_from_slice(&[0, 1, 0, 1]); // QTYPE/QCLASS
    resp2.extend_from_slice(&[0xC0, 0xFF]); // pointer to 255 (past EOF)
    resp2.extend_from_slice(&[0, 1, 0, 1, 0, 0, 0, 0, 0, 4, 1, 2, 3, 4]); // hdr
    let ok = parse_dns_response(&resp2, 0x1234, DNS_QTYPE_A);
    // Compression pointers are skipped without following, so the answer
    // below is still parsed; the pointer target is never dereferenced.
    assert!(ok.is_ok(), "pointer is not followed; got: {ok:?}");
}
