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
use frp_core::transport::{build_tls_acceptor_with_alpn, build_tls_connector_skip_verify};

#[cfg(feature = "http2http")]
use super::h2::{serve_h2_connection, Backend};
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
    // Go frp compat: enableHTTP2 defaults to true, controls ALPN h2 on the
    // inbound TLS listener only (outbound is always HTTP/1.1).
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
    // Go frp compat (https2https.go:45): the HTTPS backend is connected with
    // InsecureSkipVerify — frp does not validate the backend certificate.
    let tls_connector = build_tls_connector_skip_verify(None, None, None).map_err(|e| {
        frp_core::Error::Transport(format!("https2https plugin: TLS connector: {e}").into())
    })?;
    let (backend_host, backend_port) = split_host_port(&target_addr);
    let backend_host = backend_host.to_string();
    serve_plugin(
        "https2https",
        (
            target_addr,
            host_rewrite,
            request_headers,
            tls_acceptor,
            tls_connector,
            backend_host,
            backend_port,
            enable_h2,
        ),
        |tcp, peer, (target, rewrite, headers, acceptor, connector, _host, _port, _enable_h2)| {
            async move {
                match acceptor.accept(tcp).await {
                    Ok(client_tls) => {
                        #[cfg(feature = "http2http")]
                        {
                            if _enable_h2 && client_tls.get_ref().1.alpn_protocol() == Some(b"h2") {
                                let backend = Backend::Tls {
                                    connector,
                                    host: _host,
                                    port: _port,
                                };
                                serve_h2_connection(client_tls, target, rewrite, headers, backend)
                                    .await;
                            } else if let Err(e) =
                                handle_conn(client_tls, &target, &rewrite, &headers, &connector).await
                            {
                                debug!(%peer, error = %e, "https2https: {peer} error: {e}");
                            }
                        }
                        #[cfg(not(feature = "http2http"))]
                        if let Err(e) =
                            handle_conn(client_tls, &target, &rewrite, &headers, &connector).await
                        {
                            debug!(%peer, error = %e, "https2https: {peer} error: {e}");
                        }
                    }
                    Err(e) => debug!(%peer, %e, "https2https: {peer} TLS accept error: {e}"),
                }
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
        &mut client_tls,
        &mut backend_tls,
        &fwd.body_prefix,
        fwd.body,
        &fwd.method,
    )
    .await
    {
        tracing::debug!(error = %e, "request body forward failed, relaying response anyway: {}", e);
    }

    // Copy response back to client
    if let Err(e) = super::copy_stream_large(backend_tls, &mut client_tls).await {
        tracing::debug!(error = %e, "plugin relay error: {}", e);
    }
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
