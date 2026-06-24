//! QUIC transport — async stream via the `quinn` crate.
//!
//! Maps a single QUIC bidirectional stream to `AsyncRead + AsyncWrite`.
//! The QUIC connection is established first, then a single stream is opened.
//! This matches how Go frp uses quic-go: one stream per logical connection.

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// A QUIC bidirectional stream wrapped as a unified read/write type.
///
/// QUIC streams have separate send and receive halves; this struct
/// holds both and delegates AsyncRead/AsyncWrite to each half.
pub struct QuicStream {
    send: quinn::SendStream,
    recv: quinn::RecvStream,
    /// Keep the connection alive while the stream is in use.
    _conn: quinn::Connection,
}

impl QuicStream {
    pub(crate) fn new(conn: quinn::Connection, send: quinn::SendStream, recv: quinn::RecvStream) -> Self {
        Self { send, recv, _conn: conn }
    }

    /// Split into boxed read and write halves for use with `IoStream::into_split()`.
    pub fn into_split(self) -> (Box<dyn AsyncRead + Unpin + Send>, Box<dyn AsyncWrite + Unpin + Send>) {
        (Box::new(self.recv), Box::new(self.send))
    }
}

/// QUIC listener — binds a UDP socket and accepts QUIC connections.
/// Each accepted connection opens a single bidirectional stream.
pub struct QuicListener {
    endpoint: quinn::Endpoint,
}

impl QuicListener {
    /// Bind a QUIC listener.
    /// `cert_pem` and `key_pem` are the server's TLS certificate and key (PEM format).
    pub fn new(
        addr: SocketAddr,
        cert_pem: &str,
        key_pem: &str,
    ) -> io::Result<Self> {
        let cert_chain = rustls_pemfile::certs(&mut cert_pem.as_bytes())
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| io::Error::other(format!("parse cert: {e}")))?;
        let key = rustls_pemfile::private_key(&mut key_pem.as_bytes())
            .map_err(|e| io::Error::other(format!("parse key: {e}")))?
            .ok_or_else(|| io::Error::other("missing private key"))?;

        let mut tls_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(cert_chain, key)
            .map_err(|e| io::Error::other(format!("TLS config: {e}")))?;
        tls_config.alpn_protocols = vec![b"frp-rs".to_vec()];

        let quic_tls = quinn::crypto::rustls::QuicServerConfig::try_from(tls_config)
            .map_err(|e| io::Error::other(format!("QUIC TLS config: {e}")))?;

        let mut transport = quinn::TransportConfig::default();
        transport.max_idle_timeout(Some(std::time::Duration::from_secs(30).try_into().unwrap()));
        transport.keep_alive_interval(Some(std::time::Duration::from_secs(10)));

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
    /// Opens a single bidirectional stream for the connection.
    pub async fn accept(&self) -> io::Result<QuicStream> {
        let incoming = self.endpoint.accept().await
            .ok_or_else(|| io::Error::other("quinn endpoint closed"))?;
        let conn = incoming.await
            .map_err(|e| io::Error::other(format!("quinn accept conn: {e}")))?;
        let (send, recv) = conn.accept_bi().await
            .map_err(|e| io::Error::other(format!("quinn accept stream: {e}")))?;
        Ok(QuicStream::new(conn, send, recv))
    }
}

/// Dial a QUIC connection to a remote peer.
/// Opens a single bidirectional stream.
pub async fn dial_quic(addr: &str, server_name: &str) -> io::Result<QuicStream> {
    let remote: SocketAddr = addr.parse().map_err(io::Error::other)?;

    // Use webpki roots for server certificate verification,
    // matching the TLS connector behaviour in frp-core.
    let roots = rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
    let tls_config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();

    let quic_tls = quinn::crypto::rustls::QuicClientConfig::try_from(tls_config)
        .map_err(|e| io::Error::other(format!("QUIC TLS config: {e}")))?;

    let mut transport = quinn::TransportConfig::default();
    transport.max_idle_timeout(Some(std::time::Duration::from_secs(30).try_into().unwrap()));
    transport.keep_alive_interval(Some(std::time::Duration::from_secs(10)));

    let mut client_config = quinn::ClientConfig::new(Arc::new(quic_tls));
    client_config.transport_config(Arc::new(transport));

    let socket = std::net::UdpSocket::bind("0.0.0.0:0")?;
    let mut endpoint = quinn::Endpoint::new(
        quinn::EndpointConfig::default(),
        None,
        socket,
        Arc::new(quinn::TokioRuntime),
    )
    .map_err(|e| io::Error::other(format!("quinn endpoint: {e}")))?;
    endpoint.set_default_client_config(client_config);

    let conn = endpoint.connect(remote, server_name)
        .map_err(|e| io::Error::other(format!("quinn connect: {e}")))?
        .await
        .map_err(|e| io::Error::other(format!("quinn connecting: {e}")))?;

    let (send, recv) = conn.open_bi().await
        .map_err(|e| io::Error::other(format!("quinn open stream: {e}")))?;

    Ok(QuicStream::new(conn, send, recv))
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

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.send).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.send).poll_shutdown(cx)
    }
}
