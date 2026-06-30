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
use tokio::io::{AsyncReadExt, AsyncWriteExt};
#[cfg(feature = "tls")]
use tokio::net::{TcpListener, TcpStream};
#[cfg(feature = "tls")]
use rustls::pki_types::ServerName;
#[cfg(feature = "tls")]
use tracing::{debug, warn};

use frp_core::config::PluginConfig;
#[cfg(feature = "tls")]
use frp_core::transport::build_tls_connector;

use super::PluginHandle;
#[cfg(feature = "tls")]
use super::split_host_port;

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

    let listener = TcpListener::bind("127.0.0.1:0").await.map_err(|e| {
        frp_core::Error::Transport(format!("http2https plugin: bind: {e}"))
    })?;
    let local_addr = listener.local_addr().map_err(|e| {
        frp_core::Error::Transport(format!("http2https plugin: local_addr: {e}"))
    })?;

    let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel::<()>();

    let task = tokio::spawn(async move {
        let tls_connector = match build_tls_connector(None, None, None) {
            Ok(c) => c,
            Err(e) => {
                tracing::error!(error = %e, "http2https plugin: failed to build TLS connector: {}", e);
                return;
            }
        };

        debug!(local_addr = %local_addr, "http2https plugin listening on {}", local_addr);
        loop {
            tokio::select! {
                result = listener.accept() => {
                    match result {
                        Ok((client, peer)) => {
                            let target = target_addr.clone();
                            let rewrite = host_rewrite.clone();
                            let connector = tls_connector.clone();
                            tokio::spawn(async move {
                                if let Err(e) = handle_conn(client, &target, &rewrite, &connector).await {
                                    debug!(peer = %peer, error = %e, "http2https: {peer} error: {e}");
                                }
                            });
                        }
                        Err(e) => {
                            warn!(error = %e, "http2https plugin accept error: {e}");
                            break;
                        }
                    }
                }
                _ = &mut shutdown_rx => {
                    debug!("http2https plugin shutting down");
                    break;
                }
            }
        }
    });

    Ok(PluginHandle {
        local_addr,
        _task: task,
        shutdown: Some(shutdown_tx),
    })
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
    tls_connector: &tokio_rustls::TlsConnector,
) -> Result<(), String> {
    // Read HTTP headers until \r\n\r\n
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        client.read_exact(&mut byte).await.map_err(|e| format!("read: {e}"))?;
        buf.push(byte[0]);
        if buf.len() >= 4
            && buf[buf.len() - 4] == b'\r'
            && buf[buf.len() - 3] == b'\n'
            && buf[buf.len() - 2] == b'\r'
            && buf[buf.len() - 1] == b'\n'
        {
            break;
        }
        if buf.len() > 65536 {
            return Err("request headers too large".into());
        }
    }

    let headers_str = String::from_utf8_lossy(&buf);
    let mut lines = headers_str.lines();

    // Parse request line: METHOD URL HTTP/1.x
    let request_line = lines.next().ok_or("empty request")?;
    let parts: Vec<&str> = request_line.split_whitespace().collect();
    if parts.len() < 2 {
        return Err(format!("bad request line: {request_line}"));
    }
    let method = parts[0];
    let path = parts[1];

    // Extract hostname from target for SNI
    let (host, port) = split_host_port(target);
    let server_name = ServerName::try_from(host.to_string())
        .map_err(|e| format!("invalid host '{host}': {e}"))?;

    // Connect to backend via TLS
    let tcp = TcpStream::connect(format!("{host}:{port}"))
        .await
        .map_err(|e| format!("connect to {host}:{port}: {e}"))?;

    let mut tls = tls_connector
        .connect(server_name, tcp)
        .await
        .map_err(|e| format!("TLS connect to {target}: {e}"))?;

    // Build forwarded request
    let mut fwd = format!("{method} {path} HTTP/1.0\r\n");
    for line in lines {
        if line.is_empty() {
            continue;
        }
        if !host_rewrite.is_empty() && line.to_lowercase().starts_with("host:") {
            fwd.push_str(&format!("Host: {host_rewrite}\r\n"));
        } else {
            fwd.push_str(line);
            fwd.push_str("\r\n");
        }
    }
    fwd.push_str("Connection: close\r\n\r\n");

    tls.write_all(fwd.as_bytes())
        .await
        .map_err(|e| format!("write forward request: {e}"))?;

    // Copy response back to client
    let _ = tokio::io::copy(&mut tls, &mut client).await;
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

        let handle = start_http2https_plugin(&cfg).await.unwrap();
        assert!(handle.local_addr.port() > 0);
    }
}
