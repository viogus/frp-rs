use tokio::net::TcpStream;
use tracing::{info, warn, debug};

use frp_core::msg::{self, FrpMessage};
use frp_core::bridge;

/// Creates the NewProxy message for registering a proxy with the server.
pub fn create_new_proxy_msg(
    name: &str,
    proxy_type: &str,
    local_addr: &str,
    remote_port: u16,
    use_encryption: bool,
    use_compression: bool,
    sk: &str,
    custom_domains: &[String],
) -> FrpMessage {
    FrpMessage::NewProxy(msg::NewProxy {
        proxy_name: name.to_string(),
        proxy_type: proxy_type.to_string(),
        use_encryption: Some(use_encryption),
        use_compression: Some(use_compression),
        group: None,
        group_key: None,
        local_str: Some(local_addr.to_string()),
        remote_port: Some(remote_port as i32),
        sk: if sk.is_empty() { None } else { Some(sk.to_string()) },
        custom_domains: if custom_domains.is_empty() { None } else { Some(custom_domains.to_vec()) },
        subdomain: None,
        locations: None,
        http_user: None,
        http_pwd: None,
        host_header_rewrite: None,
        headers: None,
        response_headers: None,
        route_by_http_user: None,
        allow_users: None,
        bandwidth_limit: None,
        bandwidth_limit_mode: None,
        annotations: None,
        metas: None,
        multiplexer: None,
    })
}

/// Connects to a local service and returns the TCP stream.
pub async fn connect_local(addr: &str) -> Result<TcpStream, frp_core::Error> {
    TcpStream::connect(addr)
        .await
        .map_err(|e| frp_core::Error::Transport(format!("connect to local {}: {}", addr, e)))
}

/// Bridge data between two streams with optional encryption.
pub async fn bridge_streams(
    local: TcpStream,
    work: TcpStream,
    name: &str,
    use_encryption: bool,
    enc_key: Option<&[u8; 32]>,
) {
    info!("Bridging streams for proxy: {} (encrypted: {})", name, use_encryption);
    if use_encryption {
        if let Some(key) = enc_key {
            let (l_r, l_w) = tokio::io::split(local);
            let (w_r, w_w) = tokio::io::split(work);
            bridge::bridge_encrypted(l_r, l_w, w_r, w_w, key).await;
            debug!("Proxy {} encrypted bridge closed", name);
            return;
        }
        warn!("Proxy {}: encryption requested but no key available, falling back to plain", name);
    }
    let mut local = local;
    let mut work = work;
    match tokio::io::copy_bidirectional(&mut local, &mut work).await {
        Ok((to_a, to_b)) => {
            debug!("Proxy {} closed: {}B to server, {}B to local", name, to_a, to_b);
        }
        Err(e) => {
            debug!("Proxy {} bridge error: {}", name, e);
        }
    }
}
