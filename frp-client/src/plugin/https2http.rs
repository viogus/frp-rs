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
use frp_core::transport::build_tls_acceptor;

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
    let tls_acceptor = build_tls_acceptor(&cfg.crt_file, &cfg.key_file, None)?;
    serve_plugin(
        "https2http",
        (target_addr, host_rewrite, request_headers, tls_acceptor),
        |tcp, peer, (target, rewrite, headers, acceptor)| async move {
            match acceptor.accept(tcp).await {
                Ok(tls) => {
                    if let Err(e) = handle_conn(tls, &target, &rewrite, &headers).await {
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
) -> Result<(), String> {
    let fwd =
        crate::plugin::read_request_and_build_forward(&mut tls, host_rewrite, request_headers)
            .await?;

    // Connect to plain HTTP backend
    let (host, port) = split_host_port(target);
    let mut remote = TcpStream::connect(format!("{host}:{port}"))
        .await
        .map_err(|e| format!("connect to {host}:{port}: {e}"))?;
    frp_core::transport::set_nodelay(&remote);

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
