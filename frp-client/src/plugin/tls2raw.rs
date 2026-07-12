#[cfg(feature = "tls")]
use tokio::net::TcpStream;
#[cfg(feature = "tls")]
use rustls::pki_types::ServerName;
#[cfg(feature = "tls")]
use tracing::debug;

use frp_core::config::PluginConfig;
#[cfg(feature = "tls")]
use frp_core::transport::build_tls_connector;

use super::{PluginHandle, serve_plugin};

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
    // Build TLS connector once — fail fast if it can't be created.
    let tls_connector = build_tls_connector(None, None, None).map_err(|e| {
        frp_core::Error::Transport(format!("tls2raw plugin: TLS connector: {e}").into())
    })?;
    debug!(%target_addr, "tls2raw plugin: target TLS service at {target_addr}");

    let state = (target_addr, tls_connector);
    serve_plugin("tls2raw", state, |tunnel_stream, _peer, (target, connector)| async move {
        let host = if let Some((host_str, _)) = target.rsplit_once(':') {
            host_str.to_string()
        } else {
            target.clone()
        };
        let server_name = match ServerName::try_from(host) {
            Ok(n) => n,
            Err(e) => {
                tracing::warn!(%target, ?e, "tls2raw plugin: invalid hostname '{target}': {e:?}");
                return;
            }
        };
        match TcpStream::connect(&target).await {
            Ok(tcp_stream) => {
                // Interactive forwarded data path — disable Nagle before TLS-wrapping.
                frp_core::transport::set_nodelay(&tcp_stream);
                match connector.connect(server_name, tcp_stream).await {
                    Ok(mut tls_stream) => {
                        let mut tunnel = tunnel_stream;
                        let _ = tokio::io::copy_bidirectional(&mut tunnel, &mut tls_stream).await;
                    }
                    Err(e) => tracing::warn!(%target, %e, "tls2raw: TLS connect to {target} failed: {e}"),
                }
            }
            Err(e) => tracing::warn!(%target, %e, "tls2raw: TCP connect to {target} failed: {e}"),
        }
    }).await
}

#[cfg(not(feature = "tls"))]
pub async fn start_tls2raw_plugin(_cfg: &PluginConfig) -> Result<PluginHandle, frp_core::Error> {
    Err(frp_core::Error::Transport(
        "tls2raw plugin: TLS support not compiled in".into(),
    ))
}
