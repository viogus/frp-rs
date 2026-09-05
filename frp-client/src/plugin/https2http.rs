//! https2http plugin — HTTPS listener, HTTP backend.
//!
//! frpc listens on HTTPS (TLS-terminated) and forwards to a plain HTTP backend.
//! Requires TLS certificate and key for the listener.
//!
//! Go frp compat: HTTPSToHTTPPlugin.
//!
//! Config:
//! - local_addr: backend host:port (e.g. "127.0.0.1:8080")
//! - crt_file: path to TLS certificate PEM file
//! - key_file: path to TLS private key PEM file
//! - host_header_rewrite: optional Host header override

#[cfg(feature = "tls")]
use tokio::io::AsyncWriteExt;
#[cfg(feature = "tls")]
use tokio::net::TcpStream;
#[cfg(feature = "tls")]
use tracing::debug;

use frp_core::config::PluginConfig;
#[cfg(feature = "tls")]
use frp_core::transport::build_tls_acceptor_with_alpn;

#[cfg(feature = "http2http")]
use super::h2::{serve_h2_connection, Backend};
#[cfg(feature = "tls")]
use super::serve_plugin;
#[cfg(feature = "tls")]
use super::split_host_port;
use super::PluginHandle;

/// Start an https2http plugin server.
#[cfg(feature = "tls")]
pub async fn start_https2http_plugin(cfg: &PluginConfig) -> Result<PluginHandle, frp_core::Error> {
    let target_addr = if !cfg.local_addr.is_empty() {
        cfg.local_addr.clone()
    } else {
        return Err(frp_core::Error::Transport(
            "https2http plugin: local_addr is required".into(),
        ));
    };
    if cfg.crt_file.is_empty() || cfg.key_file.is_empty() {
        return Err(frp_core::Error::Transport(
            "https2http plugin: crt_file and key_file are required".into(),
        ));
    }
    let host_rewrite = cfg.host_header_rewrite.clone();
    let request_headers = cfg.request_headers.clone();
    // Go frp compat: enableHTTP2 defaults to true and only exists on the
    // https2http/https2https options — it controls whether the TLS listener
    // negotiates h2 via ALPN (http2http/http2https are plaintext HTTP/1.1
    // only and have no such field).
    let enable_h2 = cfg.enable_http2 != Some(false);
    // Without the `http2http` feature the h2 decoder is not compiled, so the
    // listener must not advertise ALPN h2 even when enable_http2 is on — a
    // client would negotiate h2 and then fail (audit A1 P1). `cfg!` folds at
    // compile time, so tiny builds always advertise only http/1.1.
    let alpn: &[&[u8]] = if enable_h2 && cfg!(feature = "http2http") {
        &[b"h2", b"http/1.1"]
    } else {
        &[b"http/1.1"]
    };
    let tls_acceptor = build_tls_acceptor_with_alpn(&cfg.crt_file, &cfg.key_file, None, alpn)?;
    let (backend_host, backend_port) = split_host_port(&target_addr);
    let backend_host = backend_host.to_string();
    serve_plugin(
        "https2http",
        (
            target_addr,
            host_rewrite,
            request_headers,
            tls_acceptor,
            backend_host,
            backend_port,
            enable_h2,
        ),
        |tcp, peer, (target, rewrite, headers, acceptor, _host, _port, _enable_h2)| async move {
            // M9: peer.ip() is always 127.0.0.1 (the plugin listener is
            // loopback); the real tunnel peer comes from StartWorkConn via
            // the work-conn registry (Go http_common.go:116-117).
            let real_peer = super::plugin_peer_ip(peer).await;
            // Audit round-8 F6: the bare accept parked the handler task + fd
            // forever on a partial-ClientHello peer (rustls waits for the
            // record body); the shared PLUGIN_HANDSHAKE_TIMEOUT window
            // releases it (same bound tls2raw already had).
            match super::accept_tls_bounded(&acceptor, tcp).await {
                Ok(tls) => {
                    #[cfg(feature = "http2http")]
                    {
                        // ALPN h2 negotiated → decode h2 frames and forward to the
                        // backend as HTTP/1.1 (Go http.Server + ReverseProxy).
                        if _enable_h2 && tls.get_ref().1.alpn_protocol() == Some(b"h2") {
                            let backend = Backend::Plain {
                                host: _host,
                                port: _port,
                            };
                            serve_h2_connection(tls, target, rewrite, headers, backend, real_peer)
                                .await;
                        } else if let Err(e) =
                            handle_conn(tls, &target, &rewrite, &headers, real_peer).await
                        {
                            debug!(%peer, error = %e, "https2http: {peer} error: {e}");
                        }
                    }
                    #[cfg(not(feature = "http2http"))]
                    if let Err(e) = handle_conn(tls, &target, &rewrite, &headers, real_peer).await {
                        debug!(%peer, error = %e, "https2http: {peer} error: {e}");
                    }
                }
                Err(e) => debug!(%peer, %e, "https2http: {peer} TLS error: {e}"),
            }
        },
    )
    .await
}

#[cfg(not(feature = "tls"))]
pub async fn start_https2http_plugin(_cfg: &PluginConfig) -> Result<PluginHandle, frp_core::Error> {
    Err(frp_core::Error::Transport(
        "https2http plugin: TLS support not compiled in".into(),
    ))
}

#[cfg(feature = "tls")]
async fn handle_conn(
    mut tls: tokio_rustls::server::TlsStream<TcpStream>,
    target: &str,
    host_rewrite: &str,
    request_headers: &std::collections::HashMap<String, String>,
    peer_ip: std::net::IpAddr,
) -> Result<(), String> {
    // Go https2http.go SetXForwarded: append the connection peer as
    // X-Forwarded-For (the tunnel peer — see the L3 note in the report).
    let fwd = crate::plugin::read_request_and_build_forward(
        &mut tls,
        host_rewrite,
        request_headers,
        Some(peer_ip),
    )
    .await?;

    // Connect to plain HTTP backend
    let (host, port) = split_host_port(target);
    let mut remote = TcpStream::connect(format!("{host}:{port}"))
        .await
        .map_err(|e| format!("connect to {host}:{port}: {e}"))?;
    frp_core::transport::set_nodelay(&remote);

    remote
        .write_all(fwd.head.as_bytes())
        .await
        .map_err(|e| format!("write forward request: {e}"))?;

    // Stream the request body (pre-read bytes plus the rest per its framing)
    // before relaying the response — Go's ReverseProxy streams request bodies,
    // and a backend that waits for the full request would hang otherwise.
    // A body-forward error must NOT drop the connection: backends reply early
    // without reading the full request (e.g. nginx's 413 client_max_body_size),
    // and Go's Transport still delivers those responses.
    if let Err(e) = crate::plugin::forward_request_body(
        &mut tls,
        &mut remote,
        &fwd.body_prefix,
        fwd.body,
        &fwd.method,
    )
    .await
    {
        tracing::debug!(error = %e, "request body forward failed, relaying response anyway: {}", e);
    }

    // Copy response back to client
    if let Err(e) = super::copy_stream_large(remote, &mut tls).await {
        tracing::debug!(error = %e, "plugin relay error: {}", e);
    }
    Ok(())
}

#[cfg(all(test, feature = "tls"))]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_https2http_missing_cert() {
        let cfg = PluginConfig {
            plugin_type: "https2http".into(),
            local_addr: "127.0.0.1:8080".into(),
            ..Default::default()
        };

        let result = start_https2http_plugin(&cfg).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("crt_file"));
    }

    /// Write a self-signed cert/key pair as PEM into `dir` and return the
    /// file paths (rcgen is a dev-dependency; frp-core's generator is
    /// private — same helper shape as the tls2raw tests).
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

    /// Audit round-8 F6 pin: a TLS client that sends a partial ClientHello
    /// (rustls waits for the record body) must be released by the 60 s
    /// handshake deadline — the handler task + fd cannot park forever.
    /// Pinned under paused time through the REAL plugin listener:
    /// RED (bare `acceptor.accept`) — no deadline timer exists, so only the
    /// test's own 70 s read bound fires and the client read times out while
    /// the server conn stays open. GREEN (accept wrapped in the shared
    /// PLUGIN_HANDSHAKE_TIMEOUT window) — the accept fails at t=60 s, the
    /// handler drops the conn, and the client read returns EOF well inside
    /// the 70 s bound. The RED phase uses a local 60 s literal; the fix
    /// hoists the shared const and this test switches to it.
    #[tokio::test(start_paused = true)]
    async fn test_tls_handshake_deadline_releases_handler() {
        use tokio::io::AsyncReadExt;
        use tokio::io::AsyncWriteExt;
        // The hoisted shared const (RED phase used a local 60 s literal).
        let handshake_timeout = crate::plugin::PLUGIN_HANDSHAKE_TIMEOUT;
        let dir = tempfile::tempdir().unwrap();
        let (crt_file, key_file) = write_self_signed_pem(&dir);
        let cfg = PluginConfig {
            plugin_type: "https2http".into(),
            local_addr: "127.0.0.1:0".into(),
            crt_file,
            key_file,
            ..Default::default()
        };
        let handle = match start_https2http_plugin(&cfg).await {
            Ok(h) => h,
            Err(e) => {
                eprintln!("Skipping test: plugin start failed (sandboxed?): {e}");
                return;
            }
        };
        let mut client = match tokio::net::TcpStream::connect(handle.local_addr).await {
            Ok(c) => c,
            Err(e) => {
                eprintln!("Skipping test: cannot connect (sandboxed?): {e}");
                return;
            }
        };
        // Partial TLS record header only (0x16 0x03 0x01 + no length/body):
        // rustls cannot complete OR reject the handshake until more bytes
        // arrive, so a bare accept parks on this conn forever.
        client.write_all(&[0x16, 0x03, 0x01]).await.unwrap();
        tokio::task::yield_now().await;

        let mut buf = [0u8; 1];
        match tokio::time::timeout(
            handshake_timeout + std::time::Duration::from_secs(10),
            client.read(&mut buf),
        )
        .await
        {
            Ok(Ok(0)) => {}
            Ok(Ok(n)) => panic!("unexpected {n} bytes from a stalled TLS handshake"),
            Ok(Err(e)) => panic!("read error from a stalled TLS handshake: {e}"),
            Err(_elapsed) => panic!(
                "stalled TLS handshake was not released: conn still open after {}",
                handshake_timeout.as_secs() + 10
            ),
        }
    }
}
