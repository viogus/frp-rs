use tokio::net::TcpStream;
use tracing::{info, debug};

use frp_core::msg::{self, FrpMessage};

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
        metas: None,
    })
}

/// Connects to a local service and returns the TCP stream.
pub async fn connect_local(addr: &str) -> Result<TcpStream, frp_core::Error> {
    TcpStream::connect(addr)
        .await
        .map_err(|e| frp_core::Error::Transport(format!("connect to local {}: {}", addr, e)))
}

/// Bridge data between two streams (bidirectional copy).
pub async fn bridge_streams(mut a: TcpStream, mut b: TcpStream, name: &str) {
    info!("Bridging streams for proxy: {}", name);
    match tokio::io::copy_bidirectional(&mut a, &mut b).await {
        Ok((to_a, to_b)) => {
            debug!("Proxy {} closed: {}B to server, {}B to local", name, to_a, to_b);
        }
        Err(e) => {
            debug!("Proxy {} bridge error: {}", name, e);
        }
    }
}
