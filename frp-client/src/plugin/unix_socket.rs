use frp_core::config::PluginConfig;

use super::PluginHandle;

/// Start a Unix domain socket plugin.
///
/// Bridges frp tunnel connections to a local Unix domain socket instead of TCP.
/// Config: plugin_local_addr = "/var/run/docker.sock"
///
/// Go frp compat: UnixDomainSocketPlugin.
#[cfg(unix)]
pub async fn start_unix_socket_plugin(cfg: &PluginConfig) -> Result<PluginHandle, frp_core::Error> {
    use tokio::net::UnixStream;
    use tracing::debug;
    let path = if !cfg.local_addr.is_empty() {
        cfg.local_addr.clone()
    } else {
        return Err(frp_core::Error::Transport(
            "unix_domain_socket plugin: plugin_local_addr is required".into(),
        ));
    };

    debug!(path = %path, "unix_domain_socket plugin: connecting to {}", path);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.map_err(|e| {
        frp_core::Error::Transport(format!("unix_domain_socket plugin: bind: {e}").into())
    })?;
    let local_addr = listener.local_addr().map_err(|e| {
        frp_core::Error::Transport(format!("unix_domain_socket plugin: local_addr: {e}").into())
    })?;

    let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let path_clone = path.clone();

    let task = tokio::spawn(async move {
        debug!(local_addr = %local_addr, "unix_domain_socket plugin listening on {}", local_addr);
        loop {
            tokio::select! {
                _ = &mut shutdown_rx => {
                    debug!("unix_domain_socket plugin shutting down");
                    break;
                }
                result = listener.accept() => {
                    match result {
                        Ok((mut tcp_stream, peer)) => {
                            debug!(peer = %peer, "unix_domain_socket plugin: new connection from {}", peer);
                            // Forwarded interactive data path — disable Nagle.
                            frp_core::transport::set_nodelay(&tcp_stream);
                            let path = path_clone.clone();
                            tokio::spawn(async move {
                                match UnixStream::connect(&path).await {
                                    Ok(mut unix_stream) => {
                                        let _ = tokio::io::copy_bidirectional(
                                            &mut tcp_stream,
                                            &mut unix_stream,
                                        ).await;
                                    }
                                    Err(e) => {
                                        tracing::warn!(
                                            path = %path, error = %e,
                                            "unix_domain_socket plugin: connect to {} failed: {}",
                                            path, e
                                        );
                                    }
                                }
                            });
                        }
                        Err(e) => {
                            tracing::warn!(error = %e, "unix_domain_socket plugin: accept error: {}", e);
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

#[cfg(not(unix))]
pub async fn start_unix_socket_plugin(_cfg: &PluginConfig) -> Result<PluginHandle, frp_core::Error> {
    Err(frp_core::Error::Transport(
        "unix_domain_socket plugin is not supported on this platform".into(),
    ))
}
