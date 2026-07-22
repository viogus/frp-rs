//! QUIC transport — async stream via the `quinn` crate.
//!
//! `QuicStream` maps a single QUIC bidirectional stream to `AsyncRead + AsyncWrite`.
//! `QuicConnection` wraps a Quinn connection and supports opening/accepting
//! multiple streams over a single QUIC connection (Go frp compat).

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

/// Configurable QUIC transport parameters, matching Go frp's `quic` config block.
///
/// Defaults match Go frp v0.69.1 `QUICOptions.Complete()`:
/// - keepalive_period: 10s
/// - max_idle_timeout: 30s
/// - max_incoming_streams: 100_000
#[derive(Debug, Clone)]
pub struct QuicTransportParams {
    pub max_idle_timeout_secs: u32,
    pub keepalive_period_secs: u32,
    pub max_incoming_streams: u32,
}

impl Default for QuicTransportParams {
    fn default() -> Self {
        Self {
            max_idle_timeout_secs: 30,
            keepalive_period_secs: 10,
            max_incoming_streams: 100_000,
        }
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

        let mut tls_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(cert_chain, key)
            .map_err(|e| io::Error::other(format!("TLS config: {e}")))?;
        tls_config.alpn_protocols = vec![b"frp".to_vec()];

        let quic_tls = quinn::crypto::rustls::QuicServerConfig::try_from(tls_config)
            .map_err(|e| io::Error::other(format!("QUIC TLS config: {e}")))?;

        let mut transport = quinn::TransportConfig::default();
        transport.max_idle_timeout(Some(
            std::time::Duration::from_secs(params.max_idle_timeout_secs as u64)
                .try_into()
                .unwrap(),
        ));
        transport.keep_alive_interval(Some(std::time::Duration::from_secs(
            params.keepalive_period_secs as u64,
        )));
        transport.max_concurrent_bidi_streams(params.max_incoming_streams.into());

        let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(quic_tls));
        server_config.transport_config(Arc::new(transport));

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
/// Returns the first bidirectional stream plus a `QuicConnection` handle
/// for opening additional streams (e.g., work connections).
pub async fn dial_quic(
    addr: &str,
    server_name: &str,
    ca_file: Option<&str>,
) -> io::Result<(QuicStream, QuicConnection)> {
    dial_quic_with_params(
        addr,
        server_name,
        ca_file,
        None,
        None,
        QuicTransportParams::default(),
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
) -> io::Result<(QuicStream, QuicConnection)> {
    let remote: SocketAddr = addr.parse().map_err(io::Error::other)?;

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
        rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth()
    };

    tls_config.alpn_protocols = vec![b"frp".to_vec()];

    let quic_tls = quinn::crypto::rustls::QuicClientConfig::try_from(tls_config)
        .map_err(|e| io::Error::other(format!("QUIC TLS config: {e}")))?;

    let mut transport = quinn::TransportConfig::default();
    transport.max_idle_timeout(Some(
        std::time::Duration::from_secs(params.max_idle_timeout_secs as u64)
            .try_into()
            .unwrap(),
    ));
    transport.keep_alive_interval(Some(std::time::Duration::from_secs(
        params.keepalive_period_secs as u64,
    )));
    transport.max_concurrent_bidi_streams(params.max_incoming_streams.into());

    let mut client_config = quinn::ClientConfig::new(Arc::new(quic_tls));
    client_config.transport_config(Arc::new(transport));

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

    let conn = endpoint
        .connect(remote, server_name)
        .map_err(|e| io::Error::other(format!("quinn connect: {e}")))?
        .await
        .map_err(|e| io::Error::other(format!("quinn connecting: {e}")))?;

    let (send, recv) = conn
        .open_bi()
        .await
        .map_err(|e| io::Error::other(format!("quinn open stream: {e}")))?;

    let qc = QuicConnection { conn: conn.clone() };
    let stream = QuicStream::new(conn, send, recv);
    Ok((stream, qc))
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
