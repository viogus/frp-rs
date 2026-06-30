use std::sync::Arc;
use std::sync::atomic::Ordering;

use tokio::net::TcpStream;
use tracing::{warn, debug};

use frp_core::bandwidth::BandwidthLimiter;
use frp_core::metrics::{ProxyMetricsRegistry, ConnGuard};
use frp_core::msg::{self, FrpMessage};
use frp_core::bridge;
use frp_core::transport::IoStream;

/// Build a NewVisitorConn message for an STCP/XTCP visitor connection.
/// sign_key = MD5(sk + timestamp) matching Go frp v0.69.1 behaviour.
pub fn create_visitor_conn_msg(server_name: &str, secret_key: &str, use_encryption: bool, use_compression: bool) -> FrpMessage {
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    let sign_key = if secret_key.is_empty() {
        None
    } else {
        let hash = frp_core::auth::generate_token(secret_key, timestamp);
        debug!(
            secret_key = %secret_key, timestamp = %timestamp, sign_key = %hash,
            "STCP visitor auth: sk='{}' ts={} sign_key={}",
            secret_key, timestamp, hash
        );
        Some(hash)
    };
    FrpMessage::NewVisitorConn(msg::NewVisitorConn {
        proxy_name: server_name.to_string(),
        sign_key,
        timestamp: Some(timestamp),
        run_id: None,
        use_encryption: Some(use_encryption),
        use_compression: Some(use_compression),
    })
}

/// Creates the NewProxy message for registering a proxy with the server.
/// All relevant fields from ProxyConfig are wired through (Go frp v0.69.1 compat).
pub fn create_new_proxy_msg(
    p: &frp_core::config::ProxyConfig,
    local_addr: &str,
) -> FrpMessage {
    let mut result = FrpMessage::NewProxy(msg::NewProxy {
        proxy_name: p.name.clone(),
        proxy_type: p.proxy_type.clone(),
        use_encryption: if p.use_encryption { Some(true) } else { None },
        use_compression: if p.use_compression { Some(true) } else { None },
        group: if p.group.is_empty() { None } else { Some(p.group.clone()) },
        group_key: if p.group_key.is_empty() { None } else { Some(p.group_key.clone()) },
        local_str: Some(local_addr.to_string()),
        remote_port: if p.remote_port == 0 { None } else { Some(p.remote_port as i32) },
        sk: {
            let sk_val = if p.sk.is_empty() { None } else { Some(p.sk.clone()) };
            debug!(name = %p.name, sk = ?sk_val, "NewProxy '{}': sk={:?}", p.name, sk_val);
            sk_val
        },
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
        virtual_net: if p.virtual_net.is_empty() { None } else { Some(p.virtual_net.clone()) },
        proxy_protocol_version: if p.proxy_protocol_version.is_empty() { None } else { Some(p.proxy_protocol_version.clone()) },
        #[cfg(feature = "vnet")]
        advertise_subnet: if p.advertise_subnet.is_empty() { None } else { Some(p.advertise_subnet.clone()) },
        #[cfg(feature = "vnet")]
        vnet_ip: if p.vnet_ip.is_empty() { None } else { Some(p.vnet_ip.clone()) },
        #[cfg(feature = "vnet")]
        vnet_netmask: if p.vnet_netmask.is_empty() { None } else { Some(p.vnet_netmask.clone()) },
        #[cfg(feature = "vnet")]
        vnet_mtu: if p.vnet_mtu == 0 { None } else { Some(p.vnet_mtu) },
    });

    // Strip local_str for Go frps compatibility — Go frps v0.69.1
    // NewProxy struct does not have this field. While Go json.Unmarshal
    // ignores unknown fields, removing it produces wire-identical JSON
    // to Go frpc and eliminates a potential compatibility variable.
    if let FrpMessage::NewProxy(ref mut np) = result {
        np.local_str = None;
    }
    result
}

/// Connects to a local service and returns the TCP stream.
pub async fn connect_local(addr: &str) -> Result<TcpStream, frp_core::Error> {
    TcpStream::connect(addr)
        .await
        .map_err(|e| frp_core::Error::Transport(format!("connect to local {}: {}", addr, e)))
}

/// Bridge data between two streams with optional encryption, compression,
/// and bandwidth limiting.
///
/// `bandwidth_limit` is in bytes/sec (0 = unlimited).
/// `bandwidth_limit_mode` is "client" (upload), "server" (download), or "both".
#[allow(clippy::too_many_arguments)]
pub async fn bridge_streams(
    local: tokio::net::TcpStream,
    work: IoStream,
    name: &str,
    use_encryption: bool,
    use_compression: bool,
    enc_key: Option<&[u8; 16]>,
    bandwidth_limit: u64,
    bandwidth_limit_mode: &str,
    metrics: Arc<ProxyMetricsRegistry>,
) {
    debug!(name = %name, encrypted = %use_encryption, compressed = %use_compression, bw_limit = %bandwidth_limit, bw_mode = %bandwidth_limit_mode,
        "Bridging streams for proxy: {} (encrypted: {}, compressed: {}, bw_limit: {} {})",
        name, use_encryption, use_compression, bandwidth_limit, bandwidth_limit_mode);

    let proxy_metrics = metrics.get_or_create(name).await;
    let _guard = ConnGuard::new(proxy_metrics.clone());

    // Build bandwidth limiters per direction.
    // "client" throttles upload (local→server, write to work).
    // "server" throttles download (server→local, read from work).
    let mut read_lim = if bandwidth_limit > 0 && (bandwidth_limit_mode == "server" || bandwidth_limit_mode == "both") {
        Some(BandwidthLimiter::new(bandwidth_limit))
    } else {
        None
    };
    let mut write_lim = if bandwidth_limit > 0 && (bandwidth_limit_mode == "client" || bandwidth_limit_mode == "both") {
        Some(BandwidthLimiter::new(bandwidth_limit))
    } else {
        None
    };

    if use_encryption {
        if let Some(key) = enc_key {
            let key = *key;
            let local_io = IoStream::Tcp(local);
            frp_core::bridge::bridge_encrypted_io(
                local_io, work, &key, use_compression, Vec::new(),
                read_lim.as_mut(), write_lim.as_mut(), Some(proxy_metrics.clone()),
            ).await;
            debug!(name = %name, "Proxy {} encrypted bridge closed", name);
            return;
        }
        warn!(name = %name, "Proxy {}: encryption requested but no key available, falling back to plain", name);
    }

    // Plain path: use compression-aware bridge when compression is on,
    // rate-limited bridge when bandwidth limiting is active,
    // otherwise use the fast copy_bidirectional path.
    if use_compression {
        let (l_r, l_w) = tokio::io::split(local);
        let (w_r, w_w) = work.into_split();
        bridge::bridge_plain(l_r, l_w, w_r, w_w, true, Vec::new(), Some(proxy_metrics.clone())).await;
        debug!(name = %name, "Proxy {} compressed plain bridge closed", name);
    } else if read_lim.is_some() || write_lim.is_some() {
        let (l_r, l_w) = tokio::io::split(local);
        let (w_r, w_w) = work.into_split();
        bridge::bridge_plain_rate_limited(
            l_r, l_w, w_r, w_w,
            read_lim.as_mut(), write_lim.as_mut(), Some(proxy_metrics.clone()),
        ).await;
        debug!(name = %name, "Proxy {} rate-limited bridge closed", name);
    } else {
        let mut local = local;
        let mut work = work;
        match tokio::io::copy_bidirectional(&mut local, &mut work).await {
            Ok((to_work, to_local)) => {
                proxy_metrics.bytes_in.fetch_add(to_work, Ordering::Relaxed);
                proxy_metrics.bytes_out.fetch_add(to_local, Ordering::Relaxed);
                debug!(name = %name, to_work = %to_work, to_local = %to_local, "Proxy {} closed: {}B to server, {}B to local", name, to_work, to_local);
            }
            Err(e) => {
                debug!(name = %name, error = %e, "Proxy {} bridge error: {}", name, e);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use md5::Digest;

    /// Compute the expected MD5 sign_key the same way `create_visitor_conn_msg`
    /// does internally via `frp_core::auth::generate_token(sk, timestamp)`.
    fn expected_sign_key(sk: &str, ts: i64) -> String {
        let mut hasher = md5::Md5::new();
        hasher.update(sk.as_bytes());
        hasher.update(ts.to_string().as_bytes());
        format!("{:x}", hasher.finalize())
    }

    #[test]
    fn test_create_visitor_conn_sign_key_with_sk() {
        let sk = "test_secret";
        let msg = create_visitor_conn_msg("stcp-proxy", sk, false, false);

        match msg {
            FrpMessage::NewVisitorConn(ref nvc) => {
                let ts = nvc.timestamp.expect("timestamp should be set");
                let got = nvc.sign_key.as_ref().expect("sign_key should be Some");
                let expected = expected_sign_key(sk, ts);
                assert_eq!(*got, expected, "sign_key mismatch");
                // MD5 hex digest is always 32 characters
                assert_eq!(got.len(), 32, "sign_key should be 32-char hex string");
            }
            _ => panic!("expected NewVisitorConn variant"),
        }
    }

    #[test]
    fn test_create_visitor_conn_sign_key_empty_sk() {
        let msg = create_visitor_conn_msg("stcp-proxy", "", false, false);

        match msg {
            FrpMessage::NewVisitorConn(ref nvc) => {
                assert!(nvc.sign_key.is_none(), "sign_key should be None for empty sk");
            }
            _ => panic!("expected NewVisitorConn variant"),
        }
    }

    #[test]
    fn test_create_visitor_conn_sign_key_format() {
        // sign_key should be a 32-char hex string (MD5 digest)
        let msg = create_visitor_conn_msg("stcp-proxy", "another_key", true, true);

        match msg {
            FrpMessage::NewVisitorConn(ref nvc) => {
                let sig = nvc.sign_key.as_ref().expect("sign_key should be Some");
                assert_eq!(sig.len(), 32, "sign_key length should be 32");
                assert!(sig.chars().all(|c| c.is_ascii_hexdigit()), "all chars must be hex digits");
            }
            _ => panic!("expected NewVisitorConn variant"),
        }
    }
}
