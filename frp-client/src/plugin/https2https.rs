//! https2https plugin — HTTPS listener, HTTPS backend.
//!
//! frpc listens on HTTPS (TLS-terminated) and forwards to an HTTPS backend.
//! Requires TLS certificate and key for the listener.
//! Backend TLS certificate is verified using system root CAs.
//!
//! Go frp compat: HTTPSToHTTPSPlugin.
//!
//! Config:
//! - local_addr: backend host:port (e.g. "127.0.0.1:443")
//! - crt_file: path to TLS certificate PEM file for listener
//! - key_file: path to TLS private key PEM file for listener
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
use frp_core::transport::{build_tls_acceptor, build_tls_connector};

use super::PluginHandle;
#[cfg(feature = "tls")]
use super::split_host_port;

/// Start an https2https plugin server.
#[cfg(feature = "tls")]
pub async fn start_https2https_plugin(cfg: &PluginConfig) -> Result<PluginHandle, frp_core::Error> {
    let target_addr = if !cfg.local_addr.is_empty() {
        cfg.local_addr.clone()
    } else {
        return Err(frp_core::Error::Transport(
            "https2https plugin: local_addr is required".into(),
        ));
    };

    if cfg.crt_file.is_empty() || cfg.key_file.is_empty() {
        return Err(frp_core::Error::Transport(
            "https2https plugin: crt_file and key_file are required".into(),
        ));
    }

    let host_rewrite = cfg.host_header_rewrite.clone();

    let tls_acceptor = build_tls_acceptor(&cfg.crt_file, &cfg.key_file, None)?;

    let listener = TcpListener::bind("127.0.0.1:0").await.map_err(|e| {
        frp_core::Error::Transport(format!("https2https plugin: bind: {e}"))
    })?;
    let local_addr = listener.local_addr().map_err(|e| {
        frp_core::Error::Transport(format!("https2https plugin: local_addr: {e}"))
    })?;

    let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel::<()>();

    let task = tokio::spawn(async move {
        let tls_connector = match build_tls_connector(None, None, None) {
            Ok(c) => c,
            Err(e) => {
                tracing::error!(error = %e, "https2https plugin: failed to build TLS connector: {}", e);
                return;
            }
        };

        debug!(local_addr = %local_addr, "https2https plugin listening on {} (TLS)", local_addr);
        loop {
            tokio::select! {
                result = listener.accept() => {
                    match result {
                        Ok((tcp, peer)) => {
                            let target = target_addr.clone();
                            let rewrite = host_rewrite.clone();
                            let acceptor = tls_acceptor.clone();
                            let connector = tls_connector.clone();
                            tokio::spawn(async move {
                                match acceptor.accept(tcp).await {
                                    Ok(client_tls) => {
                                        if let Err(e) = handle_conn(
                                            client_tls, &target, &rewrite, &connector,
                                        ).await {
                                            debug!(peer = %peer, error = %e, "https2https: {peer} error: {e}");
                                        }
                                    }
                                    Err(e) => {
                                        debug!(peer = %peer, error = %e, "https2https: {peer} TLS accept error: {e}");
                                    }
                                }
                            });
                        }
                        Err(e) => {
                            warn!(error = %e, "https2https plugin accept error: {e}");
                            break;
                        }
                    }
                }
                _ = &mut shutdown_rx => {
                    debug!("https2https plugin shutting down");
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
pub async fn start_https2https_plugin(_cfg: &PluginConfig) -> Result<PluginHandle, frp_core::Error> {
    Err(frp_core::Error::Transport(
        "https2https plugin: TLS support not compiled in".into(),
    ))
}

#[cfg(feature = "tls")]
async fn handle_conn(
    mut client_tls: tokio_rustls::server::TlsStream<TcpStream>,
    target: &str,
    host_rewrite: &str,
    tls_connector: &tokio_rustls::TlsConnector,
) -> Result<(), String> {
    // Read HTTP headers from the decrypted client TLS stream in chunks
    let mut buf = Vec::new();
    let mut chunk = [0u8; 512];
    loop {
        let n = client_tls.read(&mut chunk).await.map_err(|e| format!("read: {e}"))?;
        if n == 0 {
            return Err("connection closed".into());
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.len() >= 4 && buf[buf.len() - 4..] == *b"\r\n\r\n" {
            break;
        }
        if buf.len() > 65536 {
            return Err("request headers too large".into());
        }
    }

    // Split buffer on first \r\n\r\n to separate headers from any pre-read body data.
    let header_end = buf
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|i| i + 4)
        .unwrap_or(buf.len());
    let headers_str = String::from_utf8_lossy(&buf[..header_end]);
    let mut lines = headers_str.lines();

    let request_line = lines.next().ok_or("empty request")?;
    let parts: Vec<&str> = request_line.split_whitespace().collect();
    if parts.len() < 2 {
        return Err(format!("bad request line: {request_line}"));
    }
    let method = parts[0];
    let path = parts[1];

    // Connect to HTTPS backend
    let (host, port) = split_host_port(target);
    let server_name = ServerName::try_from(host.to_string())
        .map_err(|e| format!("invalid host '{host}': {e}"))?;

    let tcp = TcpStream::connect(format!("{host}:{port}"))
        .await
        .map_err(|e| format!("connect to {host}:{port}: {e}"))?;

    let mut backend_tls = tls_connector
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

    backend_tls
        .write_all(fwd.as_bytes())
        .await
        .map_err(|e| format!("write forward request: {e}"))?;

    // Copy response back to client
    let _ = tokio::io::copy(&mut backend_tls, &mut client_tls).await;
    Ok(())
}

#[cfg(all(test, feature = "tls"))]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_https2https_missing_cert() {
        let cfg = PluginConfig {
            plugin_type: "https2https".into(),
            local_addr: "127.0.0.1:443".into(),
            ..Default::default()
        };

        let result = start_https2https_plugin(&cfg).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("crt_file"));
    }
}
