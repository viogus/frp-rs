#[cfg(feature = "tls")]
use tokio::net::TcpStream;
#[cfg(feature = "tls")]
use rustls::pki_types::ServerName;
#[cfg(feature = "tls")]
use tracing::debug;

use frp_core::config::PluginConfig;
#[cfg(feature = "tls")]
use frp_core::transport::build_tls_connector;

use super::PluginHandle;

/// Start a TLS-to-raw plugin.
///
/// frpc connects to the local service via TLS, then forwards through
/// the frp tunnel. frpc acts as TLS client to the local service.
///
/// Go frp compat: TLSToRawPlugin.
///
/// Config:
/// - plugin_local_addr: "127.0.0.1:8080" (the local TLS service)
#[cfg(feature = "tls")]
pub async fn start_tls2raw_plugin(cfg: &PluginConfig) -> Result<PluginHandle, frp_core::Error> {
    let target_addr = if !cfg.local_addr.is_empty() {
        cfg.local_addr.clone()
    } else {
        return Err(frp_core::Error::Transport(
            "tls2raw plugin: plugin_local_addr is required".into(),
        ));
    };

    debug!(target_addr = %target_addr, "tls2raw plugin: target TLS service at {}", target_addr);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.map_err(|e| {
        frp_core::Error::Transport(format!("tls2raw plugin: bind: {e}"))
    })?;
    let local_addr = listener.local_addr().map_err(|e| {
        frp_core::Error::Transport(format!("tls2raw plugin: local_addr: {e}"))
    })?;

    let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let target_addr_clone = target_addr.clone();

    let task = tokio::spawn(async move {
        // Build TLS connector once (system root CAs, no client auth)
        let tls_connector = match build_tls_connector(None, None, None) {
            Ok(c) => c,
            Err(e) => {
                tracing::error!(error = %e, "tls2raw plugin: failed to build TLS connector: {}", e);
                return;
            }
        };

        debug!(local_addr = %local_addr, "tls2raw plugin listening on {}", local_addr);
        loop {
            tokio::select! {
                _ = &mut shutdown_rx => {
                    debug!("tls2raw plugin shutting down");
                    break;
                }
                result = listener.accept() => {
                    match result {
                        Ok((tunnel_stream, peer)) => {
                            debug!(peer = %peer, "tls2raw plugin: new tunnel connection from {}", peer);
                            let target = target_addr_clone.clone();
                            let connector = tls_connector.clone();
                            tokio::spawn(async move {
                                // Extract hostname from target for SNI
                                let host = if let Some((host_str, _)) = target.rsplit_once(':') {
                                    host_str.to_string()
                                } else {
                                    target.clone()
                                };
                                let server_name = match ServerName::try_from(host) {
                                    Ok(n) => n,
                                    Err(e) => {
                                        tracing::warn!(
                                            target = %target, error = ?e,
                                            "tls2raw plugin: invalid hostname '{}': {:?}",
                                            target, e
                                        );
                                        return;
                                    }
                                };

                                // Connect to local service via TCP first
                                match TcpStream::connect(&target).await {
                                    Ok(tcp_stream) => {
                                        // Then upgrade to TLS
                                        match connector.connect(server_name, tcp_stream).await {
                                            Ok(mut tls_stream) => {
                                                let mut tunnel = tunnel_stream;
                                                let _ = tokio::io::copy_bidirectional(
                                                    &mut tunnel,
                                                    &mut tls_stream,
                                                ).await;
                                            }
                                            Err(e) => {
                                                tracing::warn!(
                                                    target = %target, error = %e,
                                                    "tls2raw plugin: TLS connect to {} failed: {}",
                                                    target, e
                                                );
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        tracing::warn!(
                                            target = %target, error = %e,
                                            "tls2raw plugin: TCP connect to {} failed: {}",
                                            target, e
                                        );
                                    }
                                }
                            });
                        }
                        Err(e) => {
                            tracing::warn!(error = %e, "tls2raw plugin: accept error: {}", e);
                            break;
                        }
                    }
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
pub async fn start_tls2raw_plugin(_cfg: &PluginConfig) -> Result<PluginHandle, frp_core::Error> {
    Err(frp_core::Error::Transport(
        "tls2raw plugin: TLS support not compiled in".into(),
    ))
}
