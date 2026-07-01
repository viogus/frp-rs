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
use tokio::io::{AsyncReadExt, AsyncWriteExt};
#[cfg(feature = "tls")]
use tokio::net::{TcpListener, TcpStream};
#[cfg(feature = "tls")]
use tracing::{debug, warn};

use frp_core::config::PluginConfig;
#[cfg(feature = "tls")]
use frp_core::transport::build_tls_acceptor;

use super::PluginHandle;
#[cfg(feature = "tls")]
use super::split_host_port;

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

    let tls_acceptor = build_tls_acceptor(&cfg.crt_file, &cfg.key_file, None)?;

    let listener = TcpListener::bind("127.0.0.1:0").await.map_err(|e| {
        frp_core::Error::Transport(format!("https2http plugin: bind: {e}"))
    })?;
    let local_addr = listener.local_addr().map_err(|e| {
        frp_core::Error::Transport(format!("https2http plugin: local_addr: {e}"))
    })?;

    let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel::<()>();

    let task = tokio::spawn(async move {
        debug!(local_addr = %local_addr, "https2http plugin listening on {} (TLS)", local_addr);
        loop {
            tokio::select! {
                result = listener.accept() => {
                    match result {
                        Ok((tcp, peer)) => {
                            let target = target_addr.clone();
                            let rewrite = host_rewrite.clone();
                            let acceptor = tls_acceptor.clone();
                            tokio::spawn(async move {
                                // Accept TLS on the incoming connection
                                match acceptor.accept(tcp).await {
                                    Ok(tls) => {
                                        if let Err(e) = handle_conn(tls, &target, &rewrite).await {
                                            debug!(peer = %peer, error = %e, "https2http: {peer} error: {e}");
                                        }
                                    }
                                    Err(e) => {
                                        debug!(peer = %peer, error = %e, "https2http: {peer} TLS error: {e}");
                                    }
                                }
                            });
                        }
                        Err(e) => {
                            warn!(error = %e, "https2http plugin accept error: {e}");
                            break;
                        }
                    }
                }
                _ = &mut shutdown_rx => {
                    debug!("https2http plugin shutting down");
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
) -> Result<(), String> {
    // Read HTTP headers from the decrypted TLS stream in chunks
    let mut buf = Vec::new();
    let mut chunk = [0u8; 512];
    loop {
        let n = tls.read(&mut chunk).await.map_err(|e| format!("read: {e}"))?;
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

    let headers_str = String::from_utf8_lossy(&buf);
    let mut lines = headers_str.lines();

    // Parse request line
    let request_line = lines.next().ok_or("empty request")?;
    let parts: Vec<&str> = request_line.split_whitespace().collect();
    if parts.len() < 2 {
        return Err(format!("bad request line: {request_line}"));
    }
    let method = parts[0];
    let path = parts[1];

    // Connect to plain HTTP backend
    let (host, port) = split_host_port(target);
    let mut remote = TcpStream::connect(format!("{host}:{port}"))
        .await
        .map_err(|e| format!("connect to {host}:{port}: {e}"))?;

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

    remote
        .write_all(fwd.as_bytes())
        .await
        .map_err(|e| format!("write forward request: {e}"))?;

    // Copy response back to client
    let _ = tokio::io::copy(&mut remote, &mut tls).await;
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
}
