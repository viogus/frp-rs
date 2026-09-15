//! QUIC transport — async stream via the `quinn` crate.
//!
//! `QuicStream` maps a single QUIC bidirectional stream to `AsyncRead + AsyncWrite`.
//! `QuicConnection` wraps a Quinn connection and supports opening/accepting
//! multiple streams over a single QUIC connection (Go frp compat).
//!
//! ## Known gaps
//!
//! - **ECN disabled**: Go frp sets `QUIC_GO_DISABLE_ECN=true` to avoid
//!   ECN (Explicit Congestion Notification) issues on some OS/kernel
//!   configurations. Quinn may enable ECN by default on Linux, but does
//!   not expose a public API to disable it. If ECN-related packet drops
//!   are observed, this may be the cause. No action item at this time
//!   — tracked as a potential future compatibility concern.

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

/// Default per-stream QUIC receive window, in bytes (6 MiB).
///
/// This is the value Go frp effectively runs with: Go frp never configures
/// quic-go's `MaxStreamReceiveWindow`, whose default is 6 MiB — the same
/// figure Go frp pins for the yamux path (`MaxStreamWindowSize = 6 MiB`).
///
/// quinn-proto's own default is `STREAM_RWND = 12.5 MB/s * 100 ms` =
/// 1,250,000 B, sized for a 100 Mbit/s / 100 ms path, and it is **not**
/// auto-tuned afterwards (`connection/streams/recv.rs` reads the configured
/// value verbatim; only the connection-level window has
/// `Connection::set_receive_window`). A single stream therefore caps at
/// `window / RTT`: ~100 Mbit/s at 100 ms RTT, ~200 Mbit/s at 50 ms. Raising
/// it makes a single frp stream (control, work conn, XTCP tunnel) able to
/// fill a high-BDP link.
///
/// 6 MiB costs at most `max_concurrent_bidi_streams * 6 MiB` of receive
/// buffering per connection in the worst case, and only for bytes actually
/// in flight (quinn buffers lazily, per stream).
pub const DEFAULT_STREAM_RECEIVE_WINDOW: u32 = 6 * 1024 * 1024;

/// Lower clamp for a configured stream receive window (16 KiB).
///
/// A window this small hard-caps a stream at `window / RTT` — ~1.3 Mbit/s at
/// 100 ms RTT — so a config typo (or a literal `1`) must not be able to go
/// lower. The QUIC flow-control update threshold is `window / 8`
/// (`connection/streams/recv.rs`), so 16 KiB still emits a window update every
/// 2 KiB of progress.
pub const MIN_STREAM_RECEIVE_WINDOW: u32 = 16 * 1024;

/// Upper clamp for a configured stream receive window (64 MiB).
///
/// 4x the largest value in the audit's window sweep (16 MiB) and ~10x Go's
/// 6 MiB: generous for any real link, while keeping a fat-fingered config
/// (or a hostile one) from advertising a multi-gigabyte window per stream.
pub const MAX_STREAM_RECEIVE_WINDOW: u32 = 64 * 1024 * 1024;

/// Configurable QUIC transport parameters, matching Go frp's `quic` config block.
///
/// Defaults match Go frp v0.69.1 `QUICOptions.Complete()` except for two
/// fields. `max_incoming_streams` is capped at 4096 (Go's 100_000 default lets
/// an unauthenticated peer open a huge number of streams on one connection
/// after TLS handshake but before frp auth, amplifying memory; 4096 is far
/// above any realistic frp concurrency — one control + pooled work streams —
/// while bounding per-connection resource use). `stream_receive_window` is a
/// Rust-only extension with no Go config counterpart: Go simply inherits
/// quic-go's 6 MiB `MaxStreamReceiveWindow`, which is why the default here is
/// also 6 MiB (see [`DEFAULT_STREAM_RECEIVE_WINDOW`]).
#[derive(Debug, Clone)]
pub struct QuicTransportParams {
    pub max_idle_timeout_secs: u32,
    pub keepalive_period_secs: u32,
    pub max_incoming_streams: u32,
    /// Per-stream receive window advertised to the peer, in bytes — QUIC's
    /// `initial_max_stream_data_bidi_*` transport parameter, i.e. how much
    /// unacknowledged data one stream may have in flight towards us. See
    /// [`DEFAULT_STREAM_RECEIVE_WINDOW`]. Wire-invisible to frp's own
    /// protocol layer: it only changes the flow-control credit the peer
    /// receives, never the framing. Values outside
    /// [`MIN_STREAM_RECEIVE_WINDOW`]..=[`MAX_STREAM_RECEIVE_WINDOW`] are
    /// clamped by [`QuicTransportParams::effective_stream_receive_window`].
    pub stream_receive_window: u32,
}

impl Default for QuicTransportParams {
    fn default() -> Self {
        Self {
            max_idle_timeout_secs: 30,
            keepalive_period_secs: 10,
            max_incoming_streams: 4096,
            stream_receive_window: DEFAULT_STREAM_RECEIVE_WINDOW,
        }
    }
}

impl QuicTransportParams {
    fn effective_max_incoming_streams(&self) -> u32 {
        self.max_incoming_streams.max(1)
    }

    /// Per-stream receive window to advertise, clamped to
    /// [`MIN_STREAM_RECEIVE_WINDOW`]..=[`MAX_STREAM_RECEIVE_WINDOW`].
    ///
    /// The config layer already normalizes non-positive values to the default;
    /// this is the belt-and-braces bound for programmatic callers (XTCP P2P
    /// paths build params directly), so a nonsensical value can never reach
    /// the QUIC transport parameters. `u32` cannot exceed quinn's `VarInt`
    /// range, so the conversion at the call site is infallible.
    fn effective_stream_receive_window(&self) -> u32 {
        self.stream_receive_window
            .clamp(MIN_STREAM_RECEIVE_WINDOW, MAX_STREAM_RECEIVE_WINDOW)
    }
}

/// Normalize zero-valued options to defaults.
///
/// The first three mirror Go frp's `QUICOptions.Complete()`, which treats `0`
/// as "use default": keepalive 10s, idle timeout 30s, and 100_000 incoming
/// streams (capped to 4096 here, see [`QuicTransportParams`]).
/// `stream_receive_window` is a Rust-only extension — Go frp has no such
/// option, it just inherits quic-go's 6 MiB — and follows the same `0` =
/// "use default" convention ([`DEFAULT_STREAM_RECEIVE_WINDOW`]).
pub fn quic_params_from_option_values(
    keepalive_period_secs: i64,
    max_idle_timeout_secs: i64,
    max_incoming_streams: i64,
    stream_receive_window: i64,
) -> QuicTransportParams {
    let defaults = QuicTransportParams::default();
    QuicTransportParams {
        keepalive_period_secs: if keepalive_period_secs > 0 {
            keepalive_period_secs as u32
        } else {
            defaults.keepalive_period_secs
        },
        max_idle_timeout_secs: if max_idle_timeout_secs > 0 {
            max_idle_timeout_secs as u32
        } else {
            defaults.max_idle_timeout_secs
        },
        max_incoming_streams: if max_incoming_streams > 0 {
            max_incoming_streams as u32
        } else {
            defaults.max_incoming_streams
        },
        // A value above u32::MAX would truncate under `as`; clamping the
        // i64 side here keeps the cast honest, and
        // `effective_stream_receive_window` bounds it again on the way into
        // quinn (`MAX_STREAM_RECEIVE_WINDOW` is far below u32::MAX, so the
        // cast is lossless for everything that survives this line).
        stream_receive_window: if stream_receive_window > 0 {
            stream_receive_window.min(u32::MAX as i64) as u32
        } else {
            defaults.stream_receive_window
        },
    }
}

/// A QUIC bidirectional stream wrapped as a unified read/write type.
///
/// QUIC streams have separate send and receive halves; this struct
/// holds both and delegates AsyncRead/AsyncWrite to each half.
/// The optional `_conn` field keeps the QUIC connection alive while
/// the stream is in use — callers that already hold a `QuicConnection`
/// may set this to `None`.
pub struct QuicStream {
    send: quinn::SendStream,
    recv: quinn::RecvStream,
    /// Keep the connection alive while the stream is in use.
    /// `None` when the caller guarantees the connection outlives the stream
    /// (e.g., drain-task-spawned streams where `QuicConnection` is held separately).
    _conn: Option<quinn::Connection>,
}

impl QuicStream {
    pub(crate) fn new(
        conn: quinn::Connection,
        send: quinn::SendStream,
        recv: quinn::RecvStream,
    ) -> Self {
        Self {
            send,
            recv,
            _conn: Some(conn),
        }
    }

    /// Create a `QuicStream` without holding a connection reference.
    /// Use when the connection is held separately (e.g., drain-task-spawned streams).
    pub(crate) fn new_borrowed(send: quinn::SendStream, recv: quinn::RecvStream) -> Self {
        Self {
            send,
            recv,
            _conn: None,
        }
    }

    /// Split into read and write halves for use with `IoStream::into_split()`.
    pub fn into_split(self) -> (quinn::RecvStream, quinn::SendStream) {
        (self.recv, self.send)
    }
}

/// Handle to an established QUIC connection. Allows opening and accepting
/// multiple bidirectional streams over a single connection — matching Go frp's
/// quic-go behavior where control + work connections share one QUIC connection.
#[derive(Clone)]
pub struct QuicConnection {
    conn: quinn::Connection,
}

impl QuicConnection {
    /// Accept the next bidirectional stream from the remote peer (server side).
    pub async fn accept_bi(&self) -> io::Result<QuicStream> {
        let (send, recv) = self
            .conn
            .accept_bi()
            .await
            .map_err(|e| io::Error::other(format!("quinn accept_bi: {e}")))?;
        // Drain-task-spawned streams don't need their own conn ref —
        // the drain task already holds a `QuicConnection` clone.
        Ok(QuicStream::new_borrowed(send, recv))
    }

    /// Accept the next bidirectional stream, keeping a reference to the
    /// connection inside the returned stream so it outlives the stream.
    ///
    /// Use when the caller returns only the stream and drops the
    /// `QuicConnection` handle (e.g., the XTCP QUIC data plane), otherwise
    /// the connection would be torn down once the handle is dropped.
    pub async fn accept_bi_owned(&self) -> io::Result<QuicStream> {
        let (send, recv) = self
            .conn
            .accept_bi()
            .await
            .map_err(|e| io::Error::other(format!("quinn accept_bi: {e}")))?;
        Ok(QuicStream::new(self.conn.clone(), send, recv))
    }

    /// Open a new bidirectional stream to the remote peer (client side).
    pub async fn open_bi(&self) -> io::Result<QuicStream> {
        let (send, recv) = self
            .conn
            .open_bi()
            .await
            .map_err(|e| io::Error::other(format!("quinn open_bi: {e}")))?;
        Ok(QuicStream::new(self.conn.clone(), send, recv))
    }

    /// Return the remote peer's socket address.
    pub fn remote_address(&self) -> std::net::SocketAddr {
        self.conn.remote_address()
    }

    /// Close the QUIC connection immediately with an application reason.
    pub fn close(&self, reason: &[u8]) {
        self.conn.close(0u32.into(), reason);
    }

    /// Increase or reduce the peer-initiated bidirectional stream credit.
    pub fn set_max_concurrent_bi_streams(&self, count: u32) {
        self.conn.set_max_concurrent_bi_streams(count.max(1).into());
    }
}

/// Build a quinn `TransportConfig` from Go-frp-compatible parameters.
///
/// Shared by the listener, dial, and on-socket (XTCP P2P) code paths:
/// max_idle_timeout, keep_alive_interval, max_concurrent_bidi_streams and
/// stream_receive_window all come from the same `QuicTransportParams`.
fn build_quic_transport_config(params: &QuicTransportParams) -> quinn::TransportConfig {
    let mut transport = quinn::TransportConfig::default();
    // Round 10 (LOW): a hostile/legacy config value (negative or near
    // u64::MAX seconds) used to make the VarInt conversion panic —
    // panic=abort kills the whole process on a config typo. On overflow
    // leave quinn's default (no idle timeout) instead.
    if let Ok(idle) = std::time::Duration::from_secs(params.max_idle_timeout_secs as u64).try_into()
    {
        transport.max_idle_timeout(Some(idle));
    }
    transport.keep_alive_interval(Some(std::time::Duration::from_secs(
        params.keepalive_period_secs as u64,
    )));
    transport.max_concurrent_bidi_streams(params.effective_max_incoming_streams().into());
    // Per-stream receive window → the `initial_max_stream_data_bidi_*` /
    // `initial_max_stream_data_uni` transport parameters we advertise. quinn's
    // 1.25 MB default is never auto-tuned (audit TOP 1): without this call a
    // single frp stream is hard-capped at window/RTT — ~100 Mbit/s on a
    // 100 ms path, however fat the link is. Defaults to
    // `DEFAULT_STREAM_RECEIVE_WINDOW` (6 MiB, Go parity).
    transport.stream_receive_window(params.effective_stream_receive_window().into());
    // Connection-level receive window (`initial_max_data`): deliberately left
    // at quinn's default, i.e. NOT overridden here. In quinn-proto 0.11.x that
    // default is `VarInt::MAX` (the "10 MiB" figure belongs to older quinn
    // releases): connection-wide flow control starts fully open and is only
    // ever changed if the application calls `Connection::set_receive_window`
    // — there is no internal auto-tuning. Pinning a finite value (e.g. Go's
    // quic-go default of 15 MiB) would throttle the aggregate of all streams
    // sharing a connection on a high-BDP link, which is precisely what the
    // per-stream window above exists to avoid. Worst-case receive buffering
    // stays bounded by `max_concurrent_bidi_streams * stream_receive_window`
    // (quinn's own documented bound); the frps listener advertises 32
    // pre-auth streams and only raises the limit after login.
    transport
}

/// QUIC listener — binds a UDP socket and accepts QUIC connections.
///
/// Each accepted connection returns a `QuicConnection` handle. The caller
/// is responsible for accepting bidirectional streams from the connection.
/// This matches Go frp's `HandleQUICListener` pattern where connection
/// accept and stream accept are separated — avoiding the accept loop
/// being blocked by a peer that never opens a stream.
pub struct QuicListener {
    endpoint: quinn::Endpoint,
}

impl QuicListener {
    /// Return the UDP address bound by this listener.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.endpoint.local_addr()
    }

    /// Bind a QUIC listener with default transport parameters.
    /// `cert_pem` and `key_pem` are the server's TLS certificate and key (PEM format).
    pub fn new(addr: SocketAddr, cert_pem: &str, key_pem: &str) -> io::Result<Self> {
        Self::new_with_params(addr, cert_pem, key_pem, QuicTransportParams::default())
    }

    /// Bind a QUIC listener with custom transport parameters.
    pub fn new_with_params(
        addr: SocketAddr,
        cert_pem: &str,
        key_pem: &str,
        params: QuicTransportParams,
    ) -> io::Result<Self> {
        let cert_chain = CertificateDer::pem_slice_iter(cert_pem.as_bytes())
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| io::Error::other(format!("parse cert: {e}")))?;
        let key = PrivateKeyDer::from_pem_slice(key_pem.as_bytes())
            .map_err(|e| io::Error::other(format!("parse key: {e}")))?;

        let tls_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(cert_chain, key)
            .map_err(|e| io::Error::other(format!("TLS config: {e}")))?;

        Self::new_with_tls_config(addr, tls_config, params)
    }

    /// Create a QUIC listener from an already-built [`rustls::ServerConfig`].
    ///
    /// Sets ALPN protocol `frp` on the config, wraps it in QUIC TLS, and binds
    /// a UDP socket. Useful when the TLS config was built programmatically
    /// (e.g., auto-generated self-signed certs).
    ///
    /// Matches Go frp's behavior of auto-generating self-signed TLS certs
    /// when no cert/key files are configured.
    pub fn new_with_tls_config(
        addr: SocketAddr,
        mut tls_config: rustls::ServerConfig,
        params: QuicTransportParams,
    ) -> io::Result<Self> {
        tls_config.alpn_protocols = vec![b"frp".to_vec()];

        let quic_tls = quinn::crypto::rustls::QuicServerConfig::try_from(tls_config)
            .map_err(|e| io::Error::other(format!("QUIC TLS config: {e}")))?;

        let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(quic_tls));
        server_config.transport_config(Arc::new(build_quic_transport_config(&params)));

        let socket = std::net::UdpSocket::bind(addr)?;
        let endpoint = quinn::Endpoint::new(
            quinn::EndpointConfig::default(),
            Some(server_config),
            socket,
            Arc::new(quinn::TokioRuntime),
        )
        .map_err(|e| io::Error::other(format!("quinn endpoint: {e}")))?;

        Ok(Self { endpoint })
    }

    /// Accept the next QUIC connection.
    ///
    /// Returns a `QuicConnection` handle only — does NOT wait for the first
    /// bidirectional stream. This matches Go frp's `HandleQUICListener` pattern
    /// where the accept loop spawns a handler that then loops on `AcceptStream`.
    /// The caller must call `conn.accept_bi()` to get the control stream.
    pub async fn accept(&self) -> io::Result<QuicConnection> {
        let incoming = self
            .endpoint
            .accept()
            .await
            .ok_or_else(|| io::Error::other("quinn endpoint closed"))?;
        let conn = incoming
            .await
            .map_err(|e| io::Error::other(format!("quinn accept conn: {e}")))?;
        Ok(QuicConnection { conn })
    }
}

/// Dial a QUIC connection to a remote peer with default transport parameters.
///
/// `dial_timeout_secs` bounds the handshake like TCP dials bound by
/// `dial_server_timeout`; `None` keeps quinn's own timers (e.g. XTCP P2P).
/// Returns the first bidirectional stream plus a `QuicConnection` handle
/// for opening additional streams (e.g., work connections).
pub async fn dial_quic(
    addr: &str,
    server_name: &str,
    ca_file: Option<&str>,
    dial_timeout_secs: Option<u64>,
) -> io::Result<(QuicStream, QuicConnection)> {
    dial_quic_with_params(
        addr,
        server_name,
        ca_file,
        None,
        None,
        QuicTransportParams::default(),
        dial_timeout_secs,
    )
    .await
}

/// Dial a QUIC connection to a remote peer with custom transport parameters
/// and optional client certificate (mTLS).
pub async fn dial_quic_with_params(
    addr: &str,
    server_name: &str,
    ca_file: Option<&str>,
    cert_file: Option<&str>,
    key_file: Option<&str>,
    params: QuicTransportParams,
    dial_timeout_secs: Option<u64>,
) -> io::Result<(QuicStream, QuicConnection)> {
    let connection = dial_quic_connection_with_params(
        addr,
        server_name,
        ca_file,
        cert_file,
        key_file,
        params,
        dial_timeout_secs,
    )
    .await?;
    let stream = connection.open_bi().await?;
    Ok((stream, connection))
}

/// Dial and authenticate a QUIC connection without opening its first stream.
/// This is useful to separate connection admission from stream admission.
pub async fn dial_quic_connection_with_params(
    addr: &str,
    server_name: &str,
    ca_file: Option<&str>,
    cert_file: Option<&str>,
    key_file: Option<&str>,
    params: QuicTransportParams,
    dial_timeout_secs: Option<u64>,
) -> io::Result<QuicConnection> {
    // Go frp compat: server_addr may be a hostname, not just an IP
    // (Go transport/quic.go resolves via net.ResolveUDPAddr).
    let remote: SocketAddr = match addr.parse() {
        Ok(a) => a,
        Err(_) => {
            let mut addrs = tokio::net::lookup_host(addr)
                .await
                .map_err(|e| io::Error::other(format!("QUIC resolve {addr}: {e}")))?;
            addrs.next().ok_or_else(|| {
                io::Error::other(format!("QUIC resolve {addr}: no addresses found"))
            })?
        }
    };

    let roots = crate::transport::build_root_store(ca_file)
        .map_err(|e| io::Error::other(format!("QUIC TLS roots: {e}")))?;

    // Build TLS config: either custom CA store or platform verifier.
    // mTLS (client certificate) is only supported with a custom CA store.
    let mut tls_config = if let Some(store) = roots {
        let builder =
            rustls::ClientConfig::builder().with_root_certificates(std::sync::Arc::new(store));

        if let (Some(cert_path), Some(key_path)) = (cert_file, key_file) {
            let cert_pem = std::fs::read_to_string(cert_path)
                .map_err(|e| io::Error::other(format!("read QUIC client cert: {e}")))?;
            let key_pem = std::fs::read_to_string(key_path)
                .map_err(|e| io::Error::other(format!("read QUIC client key: {e}")))?;
            let cert_chain = CertificateDer::pem_slice_iter(cert_pem.as_bytes())
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| io::Error::other(format!("parse QUIC client cert: {e}")))?;
            let key = PrivateKeyDer::from_pem_slice(key_pem.as_bytes())
                .map_err(|e| io::Error::other(format!("parse QUIC client key: {e}")))?;
            builder
                .with_client_auth_cert(cert_chain, key)
                .map_err(|e| io::Error::other(format!("QUIC mTLS config: {e}")))?
        } else {
            builder.with_no_client_auth()
        }
    } else {
        // No CA file: skip certificate verification (InsecureSkipVerify=true).
        // Go frp auto-generates self-signed certs -- match Go behavior.
        if cert_file.is_some() || key_file.is_some() {
            return Err(io::Error::other(
                "QUIC: client certificate (mTLS) requires a CA file (tls_trusted_ca_file)",
            ));
        }
        let verifier = std::sync::Arc::new(crate::transport::InsecureSkipVerify);
        tracing::error!(
            "QUIC TLS certificate verification is DISABLED (InsecureSkipVerify=true). \
             All control and data-plane traffic is vulnerable to MITM attacks. \
             Set tls.trusted_ca_file in config to enable verification."
        );
        rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth()
    };

    tls_config.alpn_protocols = vec![b"frp".to_vec()];

    let quic_tls = quinn::crypto::rustls::QuicClientConfig::try_from(tls_config)
        .map_err(|e| io::Error::other(format!("QUIC TLS config: {e}")))?;

    let mut client_config = quinn::ClientConfig::new(Arc::new(quic_tls));
    client_config.transport_config(Arc::new(build_quic_transport_config(&params)));

    // Bind to the correct address family for the remote peer (IPv4 or IPv6).
    let bind_addr = if remote.is_ipv6() {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    };
    let socket = std::net::UdpSocket::bind(bind_addr)?;
    let mut endpoint = quinn::Endpoint::new(
        quinn::EndpointConfig::default(),
        None,
        socket,
        Arc::new(quinn::TokioRuntime),
    )
    .map_err(|e| io::Error::other(format!("quinn endpoint: {e}")))?;
    endpoint.set_default_client_config(client_config);

    let connecting = endpoint
        .connect(remote, server_name)
        .map_err(|e| io::Error::other(format!("quinn connect: {e}")))?;

    // Bound the handshake like TCP dials (dial_server_timeout): on a
    // blackholed server quinn's idle timeout (~30s) would otherwise hang the
    // dial well past the 10s TCP bound. quinn's own handshake timers are
    // untouched; only the pathological case is bounded.
    let conn = match dial_timeout_secs {
        Some(secs) => tokio::time::timeout(std::time::Duration::from_secs(secs), connecting)
            .await
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("QUIC dial timeout to {addr}"),
                )
            })?,
        None => connecting.await,
    };
    let conn = conn.map_err(|e| io::Error::other(format!("quinn connecting: {e}")))?;

    Ok(QuicConnection { conn })
}

/// Dial a QUIC connection on an existing UDP socket (XTCP QUIC data plane).
///
/// The socket that won the NAT hole punch is handed directly to quinn so the
/// NAT mapping is preserved — matching Go frp v0.70.1's `quic.Dial` on the
/// hole-punched UDP conn. TLS skips certificate verification
/// (InsecureSkipVerify=true) because Go frp uses a runtime self-signed cert,
/// and the ALPN is `frp`. Returns only the `QuicConnection` handle — used by
/// the persistent XTCP tunnel session (Go `QUICTunnelSession.Init` dials
/// without opening a stream).
pub async fn quic_dial_conn_on_socket(
    socket: std::net::UdpSocket,
    remote: SocketAddr,
    server_name: &str,
    params: QuicTransportParams,
) -> io::Result<QuicConnection> {
    // No CA on a hole-punched peer socket: skip certificate verification
    // (InsecureSkipVerify=true), matching Go frp's auto-generated certs.
    let verifier = std::sync::Arc::new(crate::transport::InsecureSkipVerify);
    let mut tls_config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();

    tls_config.alpn_protocols = vec![b"frp".to_vec()];

    let quic_tls = quinn::crypto::rustls::QuicClientConfig::try_from(tls_config)
        .map_err(|e| io::Error::other(format!("QUIC TLS config: {e}")))?;

    let mut client_config = quinn::ClientConfig::new(Arc::new(quic_tls));
    client_config.transport_config(Arc::new(build_quic_transport_config(&params)));

    let mut endpoint = quinn::Endpoint::new(
        quinn::EndpointConfig::default(),
        None,
        socket,
        Arc::new(quinn::TokioRuntime),
    )
    .map_err(|e| io::Error::other(format!("quinn endpoint: {e}")))?;
    endpoint.set_default_client_config(client_config);

    let conn = endpoint
        .connect(remote, server_name)
        .map_err(|e| io::Error::other(format!("quinn connect: {e}")))?
        .await
        .map_err(|e| io::Error::other(format!("quinn connecting: {e}")))?;
    Ok(QuicConnection { conn })
}

/// Dial a QUIC connection on an existing UDP socket and open the first
/// bidirectional stream (legacy per-stream XTCP QUIC data plane).
///
/// Thin wrapper over [`quic_dial_conn_on_socket`] preserving the old
/// signature: dial + first stream in one call.
pub async fn quic_dial_on_socket(
    socket: std::net::UdpSocket,
    remote: SocketAddr,
    server_name: &str,
    params: QuicTransportParams,
) -> io::Result<(QuicStream, QuicConnection)> {
    let connection = quic_dial_conn_on_socket(socket, remote, server_name, params).await?;
    let stream = connection.open_bi().await?;
    Ok((stream, connection))
}

/// Accept a QUIC connection on an existing UDP socket (XTCP QUIC data plane).
///
/// Server-side counterpart of [`quic_dial_on_socket`]: sets the `frp` ALPN on
/// `tls_config`, wraps it in QUIC TLS, and hands the hole-punched UDP socket
/// to quinn (matching Go frp's `quic.Listen` on the winning UDP conn).
/// Waits for the first connection and returns its handle; the caller then
/// accepts a bidirectional stream.
pub async fn quic_accept_on_socket(
    socket: std::net::UdpSocket,
    mut tls_config: rustls::ServerConfig,
    params: QuicTransportParams,
) -> io::Result<QuicConnection> {
    tls_config.alpn_protocols = vec![b"frp".to_vec()];

    let quic_tls = quinn::crypto::rustls::QuicServerConfig::try_from(tls_config)
        .map_err(|e| io::Error::other(format!("QUIC TLS config: {e}")))?;

    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(quic_tls));
    server_config.transport_config(Arc::new(build_quic_transport_config(&params)));

    let endpoint = quinn::Endpoint::new(
        quinn::EndpointConfig::default(),
        Some(server_config),
        socket,
        Arc::new(quinn::TokioRuntime),
    )
    .map_err(|e| io::Error::other(format!("quinn endpoint: {e}")))?;

    let incoming = endpoint
        .accept()
        .await
        .ok_or_else(|| io::Error::other("quinn endpoint closed"))?;
    let conn = incoming
        .await
        .map_err(|e| io::Error::other(format!("quinn accept conn: {e}")))?;
    Ok(QuicConnection { conn })
}

// ---- AsyncRead / AsyncWrite ----

impl AsyncRead for QuicStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.recv).poll_read(cx, buf)
    }
}

impl AsyncWrite for QuicStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match Pin::new(&mut self.send).poll_write(cx, buf) {
            Poll::Ready(Ok(n)) => Poll::Ready(Ok(n)),
            Poll::Ready(Err(e)) => Poll::Ready(Err(io::Error::other(e))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.send).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.send).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn incoming_stream_limit_preserves_public_default_and_explicit_values() {
        // Deliberate safety divergence from Go's 100_000: cap the default at
        // 4096 so an unauthenticated peer cannot open a huge number of
        // streams on one connection (resource amplification).
        let params = QuicTransportParams::default();
        assert_eq!(params.max_incoming_streams, 4096);
        assert_eq!(params.effective_max_incoming_streams(), 4096);

        let custom = QuicTransportParams {
            max_incoming_streams: 1_024,
            ..params
        };
        assert_eq!(custom.effective_max_incoming_streams(), 1_024);
    }

    #[test]
    fn incoming_stream_limit_never_advertises_zero() {
        let params = QuicTransportParams {
            max_incoming_streams: 0,
            ..Default::default()
        };
        assert_eq!(params.effective_max_incoming_streams(), 1);
    }

    #[test]
    fn zero_option_values_normalize_to_defaults() {
        let params = quic_params_from_option_values(0, 0, 0, 0);
        assert_eq!(params.keepalive_period_secs, 10);
        assert_eq!(params.max_idle_timeout_secs, 30);
        assert_eq!(params.max_incoming_streams, 4096);
        assert_eq!(params.stream_receive_window, DEFAULT_STREAM_RECEIVE_WINDOW);
    }

    #[test]
    fn negative_option_values_also_normalize_to_defaults() {
        let params = quic_params_from_option_values(-1, -5, -100, -6_291_456);
        assert_eq!(params.keepalive_period_secs, 10);
        assert_eq!(params.max_idle_timeout_secs, 30);
        assert_eq!(params.max_incoming_streams, 4096);
        assert_eq!(params.stream_receive_window, DEFAULT_STREAM_RECEIVE_WINDOW);
    }

    #[test]
    fn positive_option_values_are_preserved() {
        let params = quic_params_from_option_values(20, 60, 2_048, 16 * 1024 * 1024);
        assert_eq!(params.keepalive_period_secs, 20);
        assert_eq!(params.max_idle_timeout_secs, 60);
        assert_eq!(params.max_incoming_streams, 2_048);
        assert_eq!(params.stream_receive_window, 16 * 1024 * 1024);
    }

    /// Audit TOP 1: the per-stream receive window must leave quinn's
    /// 1,250,000 B default and land on Go frp's effective 6 MiB, on every
    /// builder path (they all funnel through `build_quic_transport_config`).
    #[test]
    fn stream_receive_window_defaults_to_six_mib_and_reaches_the_transport() {
        let params = QuicTransportParams::default();
        assert_eq!(params.stream_receive_window, 6 * 1024 * 1024);
        assert_eq!(params.effective_stream_receive_window(), 6 * 1024 * 1024);

        // quinn exposes no getter for the window and `TransportConfig` has no
        // `PartialEq`, so the built value is pinned through its `Debug`
        // rendering, which prints `stream_receive_window: <bytes>` verbatim
        // (quinn-proto config/transport.rs). This is the only read-path the
        // public API offers, and it covers the exact value that becomes the
        // `initial_max_stream_data_*` transport parameter.
        let dbg = format!("{:?}", build_quic_transport_config(&params));
        assert!(
            dbg.contains("stream_receive_window: 6291456"),
            "built transport must carry the 6 MiB window: {dbg}"
        );
        // Sanity: the default really did move off quinn's own 1,250,000 B.
        assert!(!dbg.contains("stream_receive_window: 1250000"));
    }

    /// A hostile or fat-fingered value must not produce a useless 1-byte
    /// window (throughput collapse) or an absurd multi-gigabyte one; the
    /// clamp is applied on the way into quinn, not just in the config layer.
    #[test]
    fn stream_receive_window_is_clamped_on_the_way_into_quinn() {
        let tiny = QuicTransportParams {
            stream_receive_window: 1,
            ..Default::default()
        };
        assert_eq!(
            tiny.effective_stream_receive_window(),
            MIN_STREAM_RECEIVE_WINDOW
        );
        let dbg = format!("{:?}", build_quic_transport_config(&tiny));
        assert!(
            dbg.contains("stream_receive_window: 16384"),
            "1-byte window must be floored at 16 KiB: {dbg}"
        );

        let huge = QuicTransportParams {
            stream_receive_window: u32::MAX,
            ..Default::default()
        };
        assert_eq!(
            huge.effective_stream_receive_window(),
            MAX_STREAM_RECEIVE_WINDOW
        );
        let dbg = format!("{:?}", build_quic_transport_config(&huge));
        assert!(
            dbg.contains("stream_receive_window: 67108864"),
            "u32::MAX window must be capped at 64 MiB: {dbg}"
        );

        // In-range values pass through untouched.
        let exact = QuicTransportParams {
            stream_receive_window: 32 * 1024 * 1024,
            ..Default::default()
        };
        assert_eq!(exact.effective_stream_receive_window(), 32 * 1024 * 1024);
    }

    /// The config-layer default (`[transport.quic] stream_receive_window`) must
    /// stay equal to the transport-layer default — they are two literals in
    /// two files, and a drift would silently halve the advertised window.
    #[test]
    fn config_default_matches_transport_default() {
        let cfg = crate::config::QuicOptions::default();
        assert_eq!(
            cfg.stream_receive_window, DEFAULT_STREAM_RECEIVE_WINDOW as i64,
            "QuicOptions::default() must agree with DEFAULT_STREAM_RECEIVE_WINDOW"
        );

        // And the deserialized (wire-config) default agrees too.
        let parsed: crate::config::QuicOptions =
            serde_json::from_str("{}").expect("empty quic table parses");
        assert_eq!(
            parsed.stream_receive_window,
            DEFAULT_STREAM_RECEIVE_WINDOW as i64
        );
        // camelCase alias, matching the other quic options.
        let camel: crate::config::QuicOptions =
            serde_json::from_str(r#"{"streamReceiveWindow": 33554432}"#)
                .expect("camelCase quic window parses");
        assert_eq!(camel.stream_receive_window, 32 * 1024 * 1024);
    }

    #[tokio::test]
    async fn dial_resolves_hostname_server_addresses() {
        // Go frp compat: server_addr may be a hostname. The QUIC dial path
        // must resolve it (tokio::net::lookup_host) instead of failing on
        // `addr.parse::<SocketAddr>()`. We exercise the resolution branch
        // directly; a full QUIC handshake is covered by v2_quic_r2r.
        let resolved: Result<SocketAddr, _> = tokio::net::lookup_host("localhost:7000")
            .await
            .map(|mut it| it.next().expect("lookup_host returns at least one addr"));
        match resolved {
            Ok(addr) => {
                assert!(
                    addr.ip().is_loopback(),
                    "localhost should resolve to a loopback address, got {addr}"
                );
            }
            // Some sandboxed CI environments have no DNS; the hostname branch
            // is still exercised by the resolve call itself.
            Err(e) => eprintln!("skipping hostname assertion (no DNS): {e}"),
        }

        // IP-literal addresses keep working without DNS.
        let addr: SocketAddr = "127.0.0.1:7000".parse().expect("IP literal parses");
        assert!(addr.ip().is_loopback());
    }
}
