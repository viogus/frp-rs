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

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|e| {
            frp_core::Error::Transport(format!("unix_domain_socket plugin: bind: {e}").into())
        })?;
    let local_addr = listener.local_addr().map_err(|e| {
        frp_core::Error::Transport(format!("unix_domain_socket plugin: local_addr: {e}").into())
    })?;

    let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let path_clone = path.clone();

    let task = tokio::spawn(async move {
        debug!(local_addr = %local_addr, "unix_domain_socket plugin listening on {}", local_addr);
        // Throttle accept-error warnings: under persistent EMFILE the loop
        // fails ~10/s (100ms pause below), which would flood the logs.
        let mut last_accept_warn: Option<std::time::Instant> = None;
        // In-flight connection handlers, so shutdown can abort them — mirrors
        // serve_plugin's JoinSet (audit r4/client#5). Without this a dropped
        // PluginHandle left relay tasks running until the tunnel closed.
        let mut handlers: tokio::task::JoinSet<()> = tokio::task::JoinSet::new();
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
                            handlers.spawn(async move {
                                match UnixStream::connect(&path).await {
                                    Ok(mut unix_stream) => {
                                        if let Err(e) = tokio::io::copy_bidirectional_with_sizes(
                                            &mut tcp_stream,
                                            &mut unix_stream,
                                            *frp_core::buffer_pool::BUFFER_SIZE,
                                            *frp_core::buffer_pool::BUFFER_SIZE,
                                        )
                                        .await
                                        {
                                            tracing::debug!(error = %e, "plugin relay error: {}", e);
                                        }
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
                            // Warn at most once per second while the accept
                            // failure persists (the first failure warns too).
                            if last_accept_warn
                                .map(|t| t.elapsed() >= std::time::Duration::from_secs(1))
                                .unwrap_or(true)
                            {
                                tracing::warn!(error = %e, "unix_domain_socket plugin: accept error: {}", e);
                                last_accept_warn = Some(std::time::Instant::now());
                            }
                            // Transient accept errors (EMFILE/ENFILE fd
                            // exhaustion, etc.) must not kill the listener —
                            // pause briefly and retry; only the shutdown
                            // signal breaks the loop.
                            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                        }
                    }
                }
            }
        }
        // Abort in-flight relay tasks and wait until every one has stopped,
        // so the plugin's local port is never left half-served after the
        // handle is dropped (serve_plugin parity).
        handlers.abort_all();
        while handlers.join_next().await.is_some() {}
    });

    Ok(PluginHandle {
        local_addr,
        _task: task,
        shutdown: Some(shutdown_tx),
    })
}

#[cfg(not(unix))]
pub async fn start_unix_socket_plugin(
    _cfg: &PluginConfig,
) -> Result<PluginHandle, frp_core::Error> {
    Err(frp_core::Error::Transport(
        "unix_domain_socket plugin is not supported on this platform".into(),
    ))
}
