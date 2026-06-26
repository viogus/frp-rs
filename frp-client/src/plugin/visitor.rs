use tokio::net::TcpListener;
use tracing::debug;

use frp_core::config::PluginConfig;

use super::PluginHandle;

/// Start a visitor plugin.
///
/// Visitor plugins provide customization hooks for STCP/XTCP visitor
/// connections. Currently this starts a local TCP listener that frpc
/// connects to; the visitor traffic flows through this listener.
/// Future: custom TCP simultaneous open strategies, pre-connection
/// filters, virtual_net-aware routing.
///
/// Go frp compat: VisitorPlugin (minimal implementation).
pub async fn start_visitor_plugin(
    cfg: &PluginConfig,
) -> Result<PluginHandle, frp_core::Error> {
    let bind_addr = if !cfg.local_addr.is_empty() {
        cfg.local_addr.clone()
    } else {
        "127.0.0.1:0".to_string()
    };

    debug!("visitor plugin: binding to {}", bind_addr);

    let listener = TcpListener::bind(&bind_addr).await.map_err(|e| {
        frp_core::Error::Transport(format!("visitor plugin: bind {}: {e}", bind_addr))
    })?;
    let local_addr = listener.local_addr().map_err(|e| {
        frp_core::Error::Transport(format!("visitor plugin: local_addr: {e}"))
    })?;

    let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel::<()>();

    let task = tokio::spawn(async move {
        debug!("visitor plugin listening on {}", local_addr);
        loop {
            tokio::select! {
                _ = &mut shutdown_rx => {
                    debug!("visitor plugin shutting down");
                    break;
                }
                result = listener.accept() => {
                    match result {
                        Ok((tunnel_stream, peer)) => {
                            debug!("visitor plugin: new connection from {}", peer);
                            // Visitor plugin: future hooks for STCP/XTCP visitor logic.
                            // For now, just drop the connection after logging.
                            drop(tunnel_stream);
                        }
                        Err(e) => {
                            tracing::warn!("visitor plugin: accept error: {}", e);
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
