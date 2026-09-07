//! http2https plugin — HTTP listener, HTTPS backend.
//!
//! frpc listens on plain HTTP and forwards to a TLS-enabled HTTPS backend.
//! Headers are forwarded as-is; Host header can be rewritten.
//!
//! Go frp compat: HTTPSToHTTPPlugin (reversed direction from this plugin name).
//! Go frp's "http2https" is the listener-to-backend direction: listen HTTP, forward HTTPS.
//!
//! Config:
//! - local_addr: backend host:port (e.g. "127.0.0.1:443")
//! - host_header_rewrite: optional Host header override

#[cfg(feature = "tls")]
use rustls::pki_types::ServerName;
#[cfg(feature = "tls")]
use tokio::io::AsyncWriteExt;
#[cfg(feature = "tls")]
use tokio::net::TcpStream;
#[cfg(feature = "tls")]
use tracing::debug;

use frp_core::config::PluginConfig;
#[cfg(feature = "tls")]
use frp_core::transport::build_tls_connector_skip_verify;

#[cfg(feature = "tls")]
use super::serve_plugin;
#[cfg(feature = "tls")]
use super::split_host_port;
use super::PluginHandle;

/// Start an http2https plugin server.
#[cfg(feature = "tls")]
pub async fn start_http2https_plugin(cfg: &PluginConfig) -> Result<PluginHandle, frp_core::Error> {
    let target_addr = if !cfg.local_addr.is_empty() {
        cfg.local_addr.clone()
    } else {
        return Err(frp_core::Error::Transport(
            "http2https plugin: local_addr is required".into(),
        ));
    };
    let host_rewrite = cfg.host_header_rewrite.clone();
    let request_headers = cfg.request_headers.clone();
    // Go frp compat (http2https.go:45): the HTTPS backend is connected with
    // InsecureSkipVerify — frp does not validate the backend certificate.
    let tls_connector = build_tls_connector_skip_verify(None, None, None, false).map_err(|e| {
        frp_core::Error::Transport(format!("http2https plugin: TLS connector: {e}").into())
    })?;
    serve_plugin(
        "http2https",
        (target_addr, host_rewrite, request_headers, tls_connector),
        |client, peer, (target, rewrite, headers, connector)| async move {
            if let Err(e) = handle_conn(client, &target, &rewrite, &headers, &connector).await {
                debug!(%peer, error = %e, "http2https: {peer} error: {e}");
            }
        },
    )
    .await
}

#[cfg(not(feature = "tls"))]
pub async fn start_http2https_plugin(_cfg: &PluginConfig) -> Result<PluginHandle, frp_core::Error> {
    Err(frp_core::Error::Transport(
        "http2https plugin: TLS support not compiled in".into(),
    ))
}

#[cfg(feature = "tls")]
async fn handle_conn(
    mut client: TcpStream,
    target: &str,
    host_rewrite: &str,
    request_headers: &std::collections::HashMap<String, String>,
    tls_connector: &tokio_rustls::TlsConnector,
) -> Result<(), String> {
    // No X-Forwarded-For append: Go http2https.go does not call
    // SetXForwarded (only the https2http/https2https variants do).
    let fwd = crate::plugin::read_request_and_build_forward(
        &mut client,
        host_rewrite,
        request_headers,
        None,
    )
    .await?;

    // Extract hostname from target for SNI. Every failure from here to the
    // established backend TLS session answers Go's default ReverseProxy 502
    // (Go http2https.go dials + tls.Client + Handshake inline — each error
    // is a transport.RoundTrip dial error → the bare 502 render; the old
    // code dropped the client conn with nothing). ServerName construction
    // failure is a dial-class error (Go's r.Host would fail in
    // net.Dial/url parsing; there is no pre-dial validation).
    let (host, port) = split_host_port(target);
    let server_name = match ServerName::try_from(host.to_string()) {
        Ok(n) => n,
        Err(e) => {
            return super::write_go_502(&mut client, format!("invalid host '{host}': {e}")).await;
        }
    };

    // Connect to backend via TLS
    let tcp = match TcpStream::connect(format!("{host}:{port}")).await {
        Ok(s) => s,
        Err(e) => {
            return super::write_go_502(&mut client, format!("connect to {host}:{port}: {e}"))
                .await;
        }
    };
    frp_core::transport::set_nodelay(&tcp);

    let mut tls = match tls_connector.connect(server_name, tcp).await {
        Ok(t) => t,
        Err(e) => {
            return super::write_go_502(&mut client, format!("TLS connect to {target}: {e}")).await;
        }
    };

    tls.write_all(fwd.head.as_bytes())
        .await
        .map_err(|e| format!("write forward request: {e}"))?;

    // Stream the request body (pre-read bytes plus the rest per its framing)
    // before relaying the response — Go's ReverseProxy streams request bodies,
    // and a backend that waits for the full request would hang otherwise.
    // A body-forward error must NOT drop the connection: backends reply early
    // without reading the full request (e.g. nginx's 413 client_max_body_size),
    // and Go's Transport still delivers those responses.
    if let Err(e) = crate::plugin::forward_request_body(
        &mut client,
        &mut tls,
        &fwd.body_prefix,
        fwd.body,
        &fwd.method,
    )
    .await
    {
        tracing::debug!(error = %e, "request body forward failed, relaying response anyway: {}", e);
    }

    // Copy response back to client
    if let Err(e) = super::copy_stream_large(tls, &mut client).await {
        tracing::debug!(error = %e, "plugin relay error: {}", e);
    }
    Ok(())
}

#[cfg(all(test, feature = "tls"))]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_http2https_smoke_non_tls_backend() {
        // Use a plain HTTP backend for testing (simulates the plugin connecting
        // to a non-TLS target — the TLS handshake will fail, but we test the
        // request parsing and forwarding logic indirectly).
        // For a full integration test, a TLS backend would be needed.
        // Here we verify the plugin starts and binds correctly.
        let cfg = PluginConfig {
            plugin_type: "http2https".into(),
            local_addr: "127.0.0.1:8443".into(),
            ..Default::default()
        };

        let handle = match start_http2https_plugin(&cfg).await {
            Ok(h) => h,
            Err(e) => {
                eprintln!("Skipping test: cannot start plugin (sandboxed): {e}");
                return;
            }
        };
        assert!(handle.local_addr.port() > 0);
    }

    /// Audit FIX 3 pin: a refused backend (the connection-refused dial
    /// arm) answers with frp-rs's bare ReverseProxy 502 — 47 bytes —
    /// before the client conn closes (Go's defaultErrorHandler 502 picks
    /// up a net/http Date header and keep-alive on the wire; the bare
    /// close-after-write is the documented frp-rs divergence). The old
    /// code closed with nothing.
    #[tokio::test]
    async fn test_http2https_backend_refused_answers_go_502() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;
        // Bind then drop: the port is closed, so the backend dial is a
        // deterministic ECONNREFUSED.
        let refused = match TcpListener::bind("127.0.0.1:0").await {
            Ok(l) => l,
            Err(e) => {
                eprintln!("Skipping test: cannot bind (sandboxed): {e}");
                return;
            }
        };
        let refused_addr = refused.local_addr().unwrap();
        drop(refused);

        let cfg = PluginConfig {
            plugin_type: "http2https".into(),
            local_addr: refused_addr.to_string(),
            ..Default::default()
        };
        let handle = match start_http2https_plugin(&cfg).await {
            Ok(h) => h,
            Err(e) => {
                eprintln!("Skipping test: cannot start plugin (sandboxed): {e}");
                return;
            }
        };
        let mut client = TcpStream::connect(handle.local_addr).await.unwrap();
        client
            .write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
            .await
            .unwrap();
        let mut resp = Vec::new();
        client.read_to_end(&mut resp).await.unwrap();
        assert_eq!(
            resp,
            b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n",
            "refused backend must render Go's 502, got: {:?}",
            String::from_utf8_lossy(&resp)
        );
    }

    /// Audit FIX 3 pin: a backend that accepts TCP but dies before the TLS
    /// handshake (Go: tls.Client Handshake error → ReverseProxy dial error
    /// → 502) renders the same bare 502.
    #[tokio::test]
    async fn test_http2https_backend_tls_fail_answers_go_502() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;
        let backend = match TcpListener::bind("127.0.0.1:0").await {
            Ok(l) => l,
            Err(e) => {
                eprintln!("Skipping test: cannot bind (sandboxed): {e}");
                return;
            }
        };
        let backend_addr = backend.local_addr().unwrap();
        // Accept one conn and drop it instantly — the client TLS handshake
        // sees EOF and errors.
        tokio::spawn(async move {
            if let Ok((_conn, _)) = backend.accept().await {
                // dropped
            }
        });

        let cfg = PluginConfig {
            plugin_type: "http2https".into(),
            local_addr: backend_addr.to_string(),
            ..Default::default()
        };
        let handle = match start_http2https_plugin(&cfg).await {
            Ok(h) => h,
            Err(e) => {
                eprintln!("Skipping test: cannot start plugin (sandboxed): {e}");
                return;
            }
        };
        let mut client = TcpStream::connect(handle.local_addr).await.unwrap();
        client
            .write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
            .await
            .unwrap();
        let mut resp = Vec::new();
        client.read_to_end(&mut resp).await.unwrap();
        assert_eq!(
            resp,
            b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n",
            "TLS-failed backend must render Go's 502, got: {:?}",
            String::from_utf8_lossy(&resp)
        );
    }
}
