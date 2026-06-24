use tokio::net::TcpStream;
use tracing::{info, warn, debug};

use frp_core::msg::{self, FrpMessage};
use frp_core::bridge;

/// Creates the NewProxy message for registering a proxy with the server.
/// All relevant fields from ProxyConfig are wired through (Go frp v0.69.1 compat).
pub fn create_new_proxy_msg(
    p: &frp_core::config::ProxyConfig,
    local_addr: &str,
) -> FrpMessage {
    FrpMessage::NewProxy(msg::NewProxy {
        proxy_name: p.name.clone(),
        proxy_type: p.proxy_type.clone(),
        use_encryption: Some(p.use_encryption),
        use_compression: Some(p.use_compression),
        group: if p.group.is_empty() { None } else { Some(p.group.clone()) },
        group_key: if p.group_key.is_empty() { None } else { Some(p.group_key.clone()) },
        local_str: Some(local_addr.to_string()),
        remote_port: Some(p.remote_port as i32),
        sk: if p.sk.is_empty() { None } else { Some(p.sk.clone()) },
        custom_domains: if p.custom_domains.is_empty() { None } else { Some(p.custom_domains.clone()) },
        subdomain: if p.subdomain.is_empty() { None } else { Some(p.subdomain.clone()) },
        locations: if p.locations.is_empty() { None } else { Some(p.locations.clone()) },
        http_user: if p.http_user.is_empty() { None } else { Some(p.http_user.clone()) },
        http_pwd: {
            // Prefer http_pwd; fall back to http_password for Go compat
            let pwd = if !p.http_pwd.is_empty() { &p.http_pwd } else { &p.http_password };
            if pwd.is_empty() { None } else { Some(pwd.clone()) }
        },
        host_header_rewrite: if p.host_header_rewrite.is_empty() { None } else { Some(p.host_header_rewrite.clone()) },
        headers: if p.headers.is_empty() { None } else { Some(p.headers.clone()) },
        response_headers: if p.response_headers.is_empty() { None } else { Some(p.response_headers.clone()) },
        route_by_http_user: if p.route_by_http_user.is_empty() { None } else { Some(p.route_by_http_user.clone()) },
        allow_users: if p.allow_users.is_empty() { None } else { Some(p.allow_users.clone()) },
        bandwidth_limit: if p.bandwidth_limit.is_empty() { None } else { Some(p.bandwidth_limit.clone()) },
        bandwidth_limit_mode: if p.bandwidth_limit_mode.is_empty() { None } else { Some(p.bandwidth_limit_mode.clone()) },
        annotations: if p.annotations.is_empty() { None } else { Some(p.annotations.clone()) },
        metas: if p.metas.is_empty() { None } else { Some(p.metas.clone()) },
        multiplexer: if p.multiplexer.is_empty() { None } else { Some(p.multiplexer.clone()) },
    })
}

/// Connects to a local service and returns the TCP stream.
pub async fn connect_local(addr: &str) -> Result<TcpStream, frp_core::Error> {
    TcpStream::connect(addr)
        .await
        .map_err(|e| frp_core::Error::Transport(format!("connect to local {}: {}", addr, e)))
}

/// Bridge data between two streams with optional encryption and compression.
pub async fn bridge_streams(
    local: TcpStream,
    work: TcpStream,
    name: &str,
    use_encryption: bool,
    use_compression: bool,
    enc_key: Option<&[u8; 16]>,
) {
    info!("Bridging streams for proxy: {} (encrypted: {}, compressed: {})", name, use_encryption, use_compression);
    if use_encryption {
        if let Some(key) = enc_key {
            let (l_r, l_w) = tokio::io::split(local);
            let (w_r, w_w) = tokio::io::split(work);
            bridge::bridge_encrypted(l_r, l_w, w_r, w_w, key, use_compression).await;
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
