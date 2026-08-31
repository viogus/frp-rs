//! tls2raw plugin — tunnel-side TLS termination forwarding to a raw local TCP service.
//!
//! Go frp v0.70.0 compat: `TLS2RawPlugin` (`pkg/plugin/client/tls2raw.go`).
//!
//! frp-rs bridge model: the work-conn bridge connects to this plugin's local
//! listener (the tunnel data path). When the proxy configures
//! `proxy_protocol_version = "v1"|"v2"`, `work_conn.rs` writes the PROXY
//! protocol header to the plugin's local socket before bridging the tunnel
//! stream — the frp-rs equivalent of Go writing `connInfo.ProxyProtocolHeader`
//! before `libio.Join`.
//!
//! Per-connection flow (Go v0.70.0 `Handle`):
//! 1. Read (and strip) the PROXY protocol header from the tunnel stream,
//!    replaying any TLS bytes that arrived in the same TCP read — the
//!    work-conn header write and the TLS ClientHello frequently coalesce on
//!    loopback, so the reader must not swallow handshake bytes.
//! 2. Terminate TLS on the tunnel side (frpc acts as the TLS server using
//!    `plugin_crt_path` / `plugin_key_path`).
//! 3. Connect to the raw local TCP service (`plugin_local_addr`).
//! 4. Write the PROXY protocol header to the local raw connection so the
//!    service sees the real client IP/port — the v0.70.0 fix (it was not
//!    written before).
//! 5. Bridge the decrypted TLS stream and the raw TCP connection
//!    (`tokio::io::copy_bidirectional_with_sizes`, Go: `libio.Join`).
//!
//! Config:
//! - plugin_local_addr: local raw TCP service address
//! - plugin_crt_path / plugin_key_path: TLS certificate and key for tunnel-side termination
//! - proxy_protocol_version: "v1" or "v2" (optional, written to raw TCP before bridging)

use frp_core::config::PluginConfig;

#[cfg(feature = "tls")]
use super::serve_plugin;
use super::PluginHandle;

#[cfg(feature = "tls")]
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
#[cfg(feature = "tls")]
use tokio::net::TcpStream;
#[cfg(feature = "tls")]
use tokio::time::{timeout, Duration};
#[cfg(feature = "tls")]
use tracing::{debug, warn};

/// Bounded time for the tls2raw handshake phase (PROXY header read + TLS
/// ServerHello): a remote client that sends TLS bytes but never completes
/// the handshake must not pin the handler task + fd (and the work-conn
/// bridge) forever. The subsequent bridge is long-lived and NOT bounded.
#[cfg(feature = "tls")]
const PLUGIN_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(60);

/// Start a TLS-to-raw plugin (Go frp compat: TLS2RawPlugin).
#[cfg(feature = "tls")]
pub async fn start_tls2raw_plugin(cfg: &PluginConfig) -> Result<PluginHandle, frp_core::Error> {
    let target_addr = if !cfg.local_addr.is_empty() {
        cfg.local_addr.clone()
    } else {
        return Err(frp_core::Error::Transport(
            "tls2raw plugin: plugin_local_addr is required".into(),
        ));
    };

    // Load TLS certificate and key — fail fast at startup (Go frp compat).
    let crt_file = if cfg.crt_file.is_empty() {
        return Err(frp_core::Error::Transport(
            "tls2raw plugin: plugin_crt_path is required".into(),
        ));
    } else {
        cfg.crt_file.clone()
    };
    let key_file = if cfg.key_file.is_empty() {
        return Err(frp_core::Error::Transport(
            "tls2raw plugin: plugin_key_path is required".into(),
        ));
    } else {
        cfg.key_file.clone()
    };

    let tls_acceptor = frp_core::transport::build_tls_acceptor(&crt_file, &key_file, None::<&str>)
        .map_err(|e| {
            frp_core::Error::Transport(format!("tls2raw plugin: TLS acceptor: {e}").into())
        })?;

    let proxy_protocol_version = cfg.proxy_protocol_version.clone();
    debug!(%target_addr, %proxy_protocol_version,
        "tls2raw plugin: TLS termination → raw TCP at {target_addr}");

    let state = (target_addr, tls_acceptor, proxy_protocol_version);
    serve_plugin(
        "tls2raw",
        state,
        |mut tunnel_stream, _peer, (target, acceptor, proxy_proto_ver)| async move {
            // 1. Read PROXY protocol header from the tunnel stream BEFORE TLS
            //    handshake (Go: connInfo.ProxyProtocolHeader is built from the
            //    StartWorkConn SrcAddr/DstAddr; frp-rs work_conn.rs writes it
            //    to this plugin's local socket ahead of the tunnel bytes).
            //    Any bytes that arrived past the header are returned and
            //    replayed into the TLS handshake below.
            let (proxy_header, extra) = match proxy_proto_ver.as_str() {
                "v1" => match timeout(PLUGIN_HANDSHAKE_TIMEOUT, read_proxy_header_v1(&mut tunnel_stream))
                    .await
                {
                    Ok(Ok(v)) => v,
                    Ok(Err(e)) => {
                        warn!(%target, ?e, "tls2raw: failed to read PROXY v1 header: {e}");
                        return;
                    }
                    Err(_elapsed) => {
                        warn!(%target, timeout = ?PLUGIN_HANDSHAKE_TIMEOUT, "tls2raw: PROXY v1 header read timed out");
                        return;
                    }
                },
                "v2" => match timeout(PLUGIN_HANDSHAKE_TIMEOUT, read_proxy_header_v2(&mut tunnel_stream))
                    .await
                {
                    Ok(Ok(v)) => v,
                    Ok(Err(e)) => {
                        warn!(%target, ?e, "tls2raw: failed to read PROXY v2 header: {e}");
                        return;
                    }
                    Err(_elapsed) => {
                        warn!(%target, timeout = ?PLUGIN_HANDSHAKE_TIMEOUT, "tls2raw: PROXY v2 header read timed out");
                        return;
                    }
                },
                _ => (Vec::new(), Vec::new()),
            };

            // 2. Perform TLS handshake on the tunnel side (Go: tls.Server +
            //    Handshake), replaying bytes read past the PROXY header.
            let mut stream = Tls2RawStream::new(tunnel_stream);
            stream.prepend(extra);
            let mut tls_stream = match timeout(PLUGIN_HANDSHAKE_TIMEOUT, acceptor.accept(stream)).await {
                Ok(Ok(tls)) => tls,
                Ok(Err(e)) => {
                    warn!(%target, ?e, "tls2raw: TLS handshake failed: {e}");
                    return;
                }
                Err(_elapsed) => {
                    warn!(%target, timeout = ?PLUGIN_HANDSHAKE_TIMEOUT, "tls2raw: TLS handshake timed out");
                    return;
                }
            };

            // 3. Connect to local raw TCP service.
            let mut raw_conn = match TcpStream::connect(&target).await {
                Ok(c) => c,
                Err(e) => {
                    warn!(%target, ?e, "tls2raw: TCP connect to {target} failed: {e}");
                    return;
                }
            };
            frp_core::transport::set_nodelay(&raw_conn);

            // 4. Write PROXY protocol header to raw TCP before bridging
            //    (Go v0.70.0: connInfo.ProxyProtocolHeader.WriteTo(rawConn)).
            if !proxy_header.is_empty() {
                if let Err(e) = raw_conn.write_all(&proxy_header).await {
                    warn!(%target, ?e, "tls2raw: failed to write PROXY header: {e}");
                    return;
                }
            }

            // 5. Bridge TLS (tunnel) ↔ raw TCP (local).
            if let Err(e) = tokio::io::copy_bidirectional_with_sizes(
                &mut tls_stream,
                &mut raw_conn,
                *frp_core::buffer_pool::BUFFER_SIZE,
                *frp_core::buffer_pool::BUFFER_SIZE,
            )
            .await
            {
                tracing::debug!(error = %e, "plugin relay error: {}", e);
            }
        },
    )
    .await
}

#[cfg(not(feature = "tls"))]
pub async fn start_tls2raw_plugin(_cfg: &PluginConfig) -> Result<PluginHandle, frp_core::Error> {
    Err(frp_core::Error::Transport(
        "tls2raw plugin: TLS support not compiled in".into(),
    ))
}

/// A `TcpStream` with a replay buffer in front of it. Bytes that were read
/// past the PROXY protocol header (e.g. the start of the TLS handshake) are
/// fed through this buffer first, so the TLS acceptor sees the exact byte
/// stream that arrived on the wire.
#[cfg(feature = "tls")]
struct Tls2RawStream {
    inner: TcpStream,
    /// Bytes to replay before reading from `inner`.
    leftover: Vec<u8>,
    leftover_pos: usize,
}

#[cfg(feature = "tls")]
impl Tls2RawStream {
    fn new(inner: TcpStream) -> Self {
        Self {
            inner,
            leftover: Vec::new(),
            leftover_pos: 0,
        }
    }

    /// Insert `bytes` at the head of the stream. Safe to call only once,
    /// right after construction, before any reads.
    fn prepend(&mut self, mut bytes: Vec<u8>) {
        if bytes.is_empty() {
            return;
        }
        bytes.extend_from_slice(&self.leftover);
        self.leftover = bytes;
        self.leftover_pos = 0;
    }
}

#[cfg(feature = "tls")]
impl AsyncRead for Tls2RawStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        if self.leftover_pos < self.leftover.len() {
            let n = std::cmp::min(buf.remaining(), self.leftover.len() - self.leftover_pos);
            let src = &self.leftover[self.leftover_pos..self.leftover_pos + n];
            buf.put_slice(src);
            self.leftover_pos += n;
            return std::task::Poll::Ready(Ok(()));
        }
        std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

#[cfg(feature = "tls")]
impl AsyncWrite for Tls2RawStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Read a PROXY protocol v1 header from the stream.
///
/// Returns `(header, trailing)` where `header` is the raw header bytes
/// (including the trailing `\r\n`) and `trailing` is any application data
/// that arrived in the same TCP segment after the header. `trailing` must be
/// replayed into the TLS handshake — discarding it would corrupt the stream
/// whenever the work-conn's header write coalesces with the ClientHello
/// (which is the common case on loopback).
#[cfg(feature = "tls")]
async fn read_proxy_header_v1(stream: &mut TcpStream) -> std::io::Result<(Vec<u8>, Vec<u8>)> {
    let mut buf = Vec::with_capacity(128);
    let mut chunk = [0u8; 128];
    loop {
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "EOF while reading PROXY v1 header",
            ));
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(pos) = buf.windows(2).position(|w| w == b"\r\n") {
            if !buf.starts_with(b"PROXY ") {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "PROXY v1 header must start with \"PROXY \"",
                ));
            }
            let header_end = pos + 2;
            let header = buf[..header_end].to_vec();
            let trailing = buf[header_end..].to_vec();
            return Ok((header, trailing));
        }
        if buf.len() > 200 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "PROXY v1 header exceeds 200 bytes",
            ));
        }
    }
}

/// Read a PROXY protocol v2 header from the stream.
///
/// The v2 header is length-prefixed, so `read_exact` never consumes more than
/// the header itself; `trailing` is always empty.
#[cfg(feature = "tls")]
async fn read_proxy_header_v2(stream: &mut TcpStream) -> std::io::Result<(Vec<u8>, Vec<u8>)> {
    let mut fixed = [0u8; 16];
    stream.read_exact(&mut fixed).await?;

    const V2_SIG: &[u8; 12] = b"\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A";
    if fixed[0..12] != V2_SIG[..] {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "invalid PROXY v2 signature",
        ));
    }

    let addr_len = u16::from_be_bytes([fixed[14], fixed[15]]) as usize;
    if addr_len > 512 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("PROXY v2 address length too large: {addr_len}"),
        ));
    }

    let total_len = 16 + addr_len;
    let mut header = Vec::with_capacity(total_len);
    header.extend_from_slice(&fixed);
    let mut addr = vec![0u8; addr_len];
    stream.read_exact(&mut addr).await?;
    header.extend_from_slice(&addr);
    Ok((header, Vec::new()))
}

#[cfg(all(test, feature = "tls"))]
mod tests {
    use super::*;
    use rustls::pki_types::ServerName;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    /// Write a self-signed cert/key pair as PEM into `dir` and return the
    /// file paths (rcgen is a dev-dependency; frp-core's generator is private).
    fn write_self_signed_pem(dir: &tempfile::TempDir) -> (String, String) {
        let cert_path = dir.path().join("cert.pem");
        let key_path = dir.path().join("key.pem");
        let key_pair = rcgen::KeyPair::generate().expect("keypair");
        let params =
            rcgen::CertificateParams::new(vec!["127.0.0.1".to_string()]).expect("cert params");
        let cert = params.self_signed(&key_pair).expect("self-signed cert");
        let wrap_pem = |label: &str, der: &[u8]| -> String {
            let b64 = frp_core::base64::encode(der);
            let mut out = format!("-----BEGIN {label}-----\n");
            for chunk in b64.as_bytes().chunks(64) {
                out.push_str(std::str::from_utf8(chunk).unwrap());
                out.push('\n');
            }
            out.push_str(&format!("-----END {label}-----\n"));
            out
        };
        std::fs::write(&cert_path, wrap_pem("CERTIFICATE", cert.der())).unwrap();
        std::fs::write(
            &key_path,
            wrap_pem("PRIVATE KEY", &key_pair.serialize_der()),
        )
        .unwrap();
        (
            cert_path.to_str().unwrap().to_string(),
            key_path.to_str().unwrap().to_string(),
        )
    }

    /// A raw TCP backend that captures every byte it receives (until EOF) and
    /// replies "pong" once so the bidirectional bridge can be asserted.
    async fn start_raw_backend() -> (
        std::net::SocketAddr,
        tokio::sync::oneshot::Receiver<Vec<u8>>,
    ) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            if let Ok((mut conn, _)) = listener.accept().await {
                let mut buf = Vec::new();
                let mut chunk = [0u8; 512];
                let mut ponged = false;
                loop {
                    match conn.read(&mut chunk).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            buf.extend_from_slice(&chunk[..n]);
                            if !ponged {
                                ponged = true;
                                if let Err(e) = conn.write_all(b"pong").await {
                                    tracing::debug!(error = %e, "plugin relay error: {}", e);
                                }
                            }
                        }
                    }
                }
                let _ = tx.send(buf);
            }
        });
        (addr, rx)
    }

    fn plugin_cfg(
        local_addr: String,
        cert: String,
        key: String,
        proxy_protocol_version: &str,
    ) -> PluginConfig {
        PluginConfig {
            plugin_type: "tls2raw".into(),
            local_addr,
            crt_file: cert,
            key_file: key,
            proxy_protocol_version: proxy_protocol_version.into(),
            ..Default::default()
        }
    }

    /// Connect to the plugin listener, write the PROXY header the way
    /// work_conn.rs does, then complete a TLS handshake (self-signed cert,
    /// so verification is skipped). Returns the TLS stream.
    async fn connect_with_proxy_header(
        plugin_addr: std::net::SocketAddr,
        header: &[u8],
    ) -> tokio_rustls::client::TlsStream<TcpStream> {
        let mut tcp = TcpStream::connect(plugin_addr).await.unwrap();
        tcp.write_all(header).await.unwrap();
        let connector =
            frp_core::transport::build_tls_connector_skip_verify(None, None, None, false)
                .expect("tls connector");
        let server_name = ServerName::try_from("127.0.0.1".to_string()).unwrap();
        connector
            .connect(server_name, tcp)
            .await
            .expect("tunnel tls handshake")
    }

    #[tokio::test]
    async fn test_tls2raw_v1_proxy_protocol() {
        let (backend_addr, rx) = start_raw_backend().await;
        let dir = tempfile::tempdir().unwrap();
        let (cert, key) = write_self_signed_pem(&dir);
        let handle = start_tls2raw_plugin(&plugin_cfg(backend_addr.to_string(), cert, key, "v1"))
            .await
            .expect("start tls2raw plugin");

        // Simulate work_conn.rs: write the PROXY v1 header, then the TLS
        // ClientHello follows immediately (they may coalesce on loopback —
        // the plugin must not swallow handshake bytes).
        let header = frp_core::proxy_protocol::build_proxy_protocol_v1(
            "203.0.113.7",
            "127.0.0.1",
            45678,
            6000,
        )
        .expect("valid v1 header");
        let mut tls = connect_with_proxy_header(handle.local_addr, header.as_bytes()).await;

        tls.write_all(b"hello-tls2raw").await.unwrap();
        let mut resp = Vec::new();
        let mut chunk = [0u8; 128];
        loop {
            match tls.read(&mut chunk).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    resp.extend_from_slice(&chunk[..n]);
                    if resp == b"pong" {
                        break;
                    }
                }
            }
        }
        assert_eq!(resp, b"pong", "raw response must be bridged back");
        drop(tls);

        // The raw backend must receive the PROXY v1 header followed by the
        // decrypted TLS payload (the v0.70.0 fix: header written to the raw
        // local connection).
        let bytes = rx.await.expect("backend captured bytes");
        let text = String::from_utf8_lossy(&bytes);
        assert!(
            text.starts_with("PROXY TCP4 203.0.113.7 127.0.0.1 45678 6000\r\n"),
            "v1 header missing on raw conn: {text:?}"
        );
        assert!(
            text.contains("hello-tls2raw"),
            "decrypted payload missing on raw conn: {text:?}"
        );
    }

    #[tokio::test]
    async fn test_tls2raw_v2_proxy_protocol() {
        let (backend_addr, rx) = start_raw_backend().await;
        let dir = tempfile::tempdir().unwrap();
        let (cert, key) = write_self_signed_pem(&dir);
        let handle = start_tls2raw_plugin(&plugin_cfg(backend_addr.to_string(), cert, key, "v2"))
            .await
            .expect("start tls2raw plugin");

        let header = frp_core::proxy_protocol::build_proxy_protocol_v2(
            "203.0.113.7",
            "127.0.0.1",
            45678,
            6000,
        )
        .unwrap();
        let mut tls = connect_with_proxy_header(handle.local_addr, &header).await;

        tls.write_all(b"hello-tls2raw").await.unwrap();
        let mut resp = Vec::new();
        let mut chunk = [0u8; 128];
        loop {
            match tls.read(&mut chunk).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    resp.extend_from_slice(&chunk[..n]);
                    if resp == b"pong" {
                        break;
                    }
                }
            }
        }
        assert_eq!(resp, b"pong", "raw response must be bridged back");
        drop(tls);

        let bytes = rx.await.expect("backend captured bytes");
        // 12-byte signature + 4-byte block + 12-byte IPv4 address block.
        assert_eq!(
            &bytes[..12],
            b"\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A",
            "v2 signature missing"
        );
        assert_eq!(bytes[12], 0x21, "version/command byte");
        assert_eq!(bytes[13], 0x11, "TCPv4 transport byte");
        assert_eq!(u16::from_be_bytes([bytes[14], bytes[15]]), 12, "addr len");
        assert_eq!(&bytes[16..20], &[203, 0, 113, 7], "src IP mismatch");
        assert_eq!(
            &bytes[28..],
            b"hello-tls2raw",
            "payload must follow v2 header"
        );
    }

    #[tokio::test]
    async fn test_tls2raw_no_proxy_protocol_passthrough() {
        let (backend_addr, rx) = start_raw_backend().await;
        let dir = tempfile::tempdir().unwrap();
        let (cert, key) = write_self_signed_pem(&dir);
        let handle = start_tls2raw_plugin(&plugin_cfg(backend_addr.to_string(), cert, key, ""))
            .await
            .expect("start tls2raw plugin");

        let mut tls = connect_with_proxy_header(handle.local_addr, b"").await;
        tls.write_all(b"hello-tls2raw").await.unwrap();
        let mut resp = Vec::new();
        let mut chunk = [0u8; 128];
        loop {
            match tls.read(&mut chunk).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    resp.extend_from_slice(&chunk[..n]);
                    if resp == b"pong" {
                        break;
                    }
                }
            }
        }
        assert_eq!(resp, b"pong", "raw response must be bridged back");
        drop(tls);

        let bytes = rx.await.expect("backend captured bytes");
        assert_eq!(
            bytes, b"hello-tls2raw",
            "no PROXY header expected without proxy_protocol_version"
        );
    }

    /// Regression: a TCP read that contains both the PROXY v1 header and
    /// following bytes (the coalesced TLS ClientHello) must return the
    /// trailing bytes for replay, not discard them.
    #[tokio::test]
    async fn test_read_v1_header_keeps_trailing_bytes() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok((mut conn, _)) = listener.accept().await {
                if let Err(e) = conn
                    .write_all(b"PROXY TCP4 203.0.113.7 127.0.0.1 45678 6000\r\nCLIENT_HELLO_START")
                    .await
                {
                    tracing::debug!(error = %e, "plugin relay error: {}", e);
                }
            }
        });
        let mut client = TcpStream::connect(addr).await.unwrap();
        let (header, trailing) = read_proxy_header_v1(&mut client).await.unwrap();
        assert_eq!(header, b"PROXY TCP4 203.0.113.7 127.0.0.1 45678 6000\r\n");
        assert_eq!(trailing, b"CLIENT_HELLO_START");
    }

    #[tokio::test]
    async fn test_read_v2_header() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let header =
            frp_core::proxy_protocol::build_proxy_protocol_v2("203.0.113.7", "127.0.0.1", 1, 2)
                .unwrap();
        let header_for_task = header.clone();
        tokio::spawn(async move {
            if let Ok((mut conn, _)) = listener.accept().await {
                if let Err(e) = conn.write_all(&header_for_task).await {
                    tracing::debug!(error = %e, "plugin relay error: {}", e);
                }
            }
        });
        let mut client = TcpStream::connect(addr).await.unwrap();
        let (got, trailing) = read_proxy_header_v2(&mut client).await.unwrap();
        assert_eq!(got, header);
        assert!(trailing.is_empty());
    }

    #[tokio::test]
    async fn test_read_v1_rejects_missing_prefix() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok((mut conn, _)) = listener.accept().await {
                if let Err(e) = conn.write_all(b"NOPE 1.2.3.4 127.0.0.1 1 2\r\n").await {
                    tracing::debug!(error = %e, "plugin relay error: {}", e);
                }
            }
        });
        let mut client = TcpStream::connect(addr).await.unwrap();
        assert!(read_proxy_header_v1(&mut client).await.is_err());
    }
}
