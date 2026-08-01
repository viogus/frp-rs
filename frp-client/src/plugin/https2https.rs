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
use rustls::pki_types::ServerName;
#[cfg(feature = "tls")]
use tokio::io::AsyncWriteExt;
#[cfg(feature = "tls")]
use tokio::net::TcpStream;
#[cfg(feature = "tls")]
use tracing::debug;

use frp_core::config::PluginConfig;
#[cfg(feature = "tls")]
use frp_core::transport::{build_tls_acceptor, build_tls_connector_skip_verify};

#[cfg(feature = "tls")]
use super::serve_plugin;
#[cfg(feature = "tls")]
use super::split_host_port;
use super::PluginHandle;

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
    let request_headers = cfg.request_headers.clone();
    let tls_acceptor = build_tls_acceptor(&cfg.crt_file, &cfg.key_file, None)?;
    // Go frp compat (https2https.go:45): the HTTPS backend is connected with
    // InsecureSkipVerify — frp does not validate the backend certificate.
    let tls_connector = build_tls_connector_skip_verify(None, None, None).map_err(|e| {
        frp_core::Error::Transport(format!("https2https plugin: TLS connector: {e}").into())
    })?;
    serve_plugin(
        "https2https",
        (
            target_addr,
            host_rewrite,
            request_headers,
            tls_acceptor,
            tls_connector,
        ),
        |tcp, peer, (target, rewrite, headers, acceptor, connector)| async move {
            match acceptor.accept(tcp).await {
                Ok(client_tls) => {
                    if let Err(e) = handle_conn(client_tls, &target, &rewrite, &headers, &connector)
                        .await
                    {
                        debug!(%peer, error = %e, "https2https: {peer} error: {e}");
                    }
                }
                Err(e) => debug!(%peer, %e, "https2https: {peer} TLS accept error: {e}"),
            }
        },
    )
    .await
}

#[cfg(not(feature = "tls"))]
pub async fn start_https2https_plugin(
    _cfg: &PluginConfig,
) -> Result<PluginHandle, frp_core::Error> {
    Err(frp_core::Error::Transport(
        "https2https plugin: TLS support not compiled in".into(),
    ))
}

#[cfg(feature = "tls")]
async fn handle_conn(
    mut client_tls: tokio_rustls::server::TlsStream<TcpStream>,
    target: &str,
    host_rewrite: &str,
    request_headers: &std::collections::HashMap<String, String>,
    tls_connector: &tokio_rustls::TlsConnector,
) -> Result<(), String> {
    let fwd = crate::plugin::read_request_and_build_forward(
        &mut client_tls,
        host_rewrite,
        request_headers,
    )
    .await?;

    // Connect to HTTPS backend
    let (host, port) = split_host_port(target);
    let server_name = ServerName::try_from(host.to_string())
        .map_err(|e| format!("invalid host '{host}': {e}"))?;

    let tcp = TcpStream::connect(format!("{host}:{port}"))
        .await
        .map_err(|e| format!("connect to {host}:{port}: {e}"))?;
    frp_core::transport::set_nodelay(&tcp);

    let mut backend_tls = tls_connector
        .connect(server_name, tcp)
        .await
        .map_err(|e| format!("TLS connect to {target}: {e}"))?;

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
