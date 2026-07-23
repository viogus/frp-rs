use std::net::ToSocketAddrs;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use tokio::net::TcpStream;
use tracing::{debug, warn};

use frp_core::bandwidth::BandwidthLimiter;
use frp_core::bridge;
use frp_core::metrics::{ConnGuard, ProxyMetricsRegistry};
use frp_core::msg::{self, FrpMessage};
use frp_core::transport::IoStream;

use crate::util::opt_if_empty;

/// Build a NewVisitorConn message for an STCP/XTCP visitor connection.
/// sign_key = MD5(sk + timestamp) matching Go frp v0.69.1 behaviour.
pub fn create_visitor_conn_msg(
    server_name: &str,
    secret_key: &str,
    use_encryption: bool,
    use_compression: bool,
) -> FrpMessage {
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    let sign_key = if secret_key.is_empty() {
        None
    } else {
        let hash = frp_core::auth::generate_token(secret_key, timestamp);
        // Redact secret key in logs: show only first 4 chars (safe on any UTF-8).
        let sk_redacted: String = secret_key.chars().take(4).collect();
        let sk_redacted = if sk_redacted.len() < secret_key.len() {
            format!("{sk_redacted}...")
        } else {
            sk_redacted
        };
        debug!(
            secret_key = %sk_redacted, timestamp = %timestamp, sign_key = %hash,
            "STCP visitor auth: sk='{}' ts={} sign_key={}",
            sk_redacted, timestamp, hash
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
pub fn create_new_proxy_msg(p: &frp_core::config::ProxyConfig, local_addr: &str) -> FrpMessage {
    let mut result = FrpMessage::NewProxy(Box::new(msg::NewProxy {
        proxy_name: p.name.clone(),
        proxy_type: p.proxy_type.clone(),
        use_encryption: if p.use_encryption { Some(true) } else { None },
        use_compression: if p.use_compression { Some(true) } else { None },
        group: opt_if_empty!(p.group),
        group_key: opt_if_empty!(p.group_key),
        local_str: Some(local_addr.to_string()),
        remote_port: if p.remote_port == 0 {
            None
        } else {
            Some(p.remote_port as i32)
        },
        sk: {
            let sk_val = opt_if_empty!(p.sk);
            debug!(name = %p.name, sk = ?sk_val, "NewProxy '{}': sk={:?}", p.name, sk_val);
            sk_val
        },
        custom_domains: opt_if_empty!(p.custom_domains),
        subdomain: opt_if_empty!(p.subdomain),
        locations: opt_if_empty!(p.locations),
        http_user: opt_if_empty!(p.http_user),
        http_pwd: {
            // Prefer http_pwd; fall back to http_password for Go compat
            let pwd = if !p.http_pwd.is_empty() {
                &p.http_pwd
            } else {
                &p.http_password
            };
            if pwd.is_empty() {
                None
            } else {
                Some(pwd.clone())
            }
        },
        host_header_rewrite: opt_if_empty!(p.host_header_rewrite),
        headers: opt_if_empty!(p.headers),
        response_headers: opt_if_empty!(p.response_headers),
        route_by_http_user: opt_if_empty!(p.route_by_http_user),
        allow_users: opt_if_empty!(p.allow_users),
        bandwidth_limit: opt_if_empty!(p.bandwidth_limit),
        bandwidth_limit_mode: opt_if_empty!(p.bandwidth_limit_mode),
        annotations: opt_if_empty!(p.annotations),
        metas: opt_if_empty!(p.metas),
        multiplexer: opt_if_empty!(p.multiplexer),
        virtual_net: opt_if_empty!(p.virtual_net),
        proxy_protocol_version: opt_if_empty!(p.proxy_protocol_version),
        advertise_subnet: opt_if_empty!(p.advertise_subnet),
        vnet_ip: opt_if_empty!(p.vnet_ip),
        vnet_netmask: opt_if_empty!(p.vnet_netmask),
        vnet_mtu: if p.vnet_mtu == 0 {
            None
        } else {
            Some(p.vnet_mtu)
        },
    }));

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
///
/// Uses spawn_blocking + std TcpStream to avoid a tokio I/O driver hang that
/// occurs in V2 plain work_conn tasks. The hang manifests as TcpStream::connect
/// never returning, even with tokio::time::timeout. Using spawn_blocking
/// bypasses the tokio I/O driver entirely for the connect.
///
/// `addr` may be a hostname like `"localhost:8080"` or an IP literal.
/// DNS resolution happens on the async runtime (before spawn_blocking).
pub async fn connect_local(addr: &str) -> Result<TcpStream, frp_core::Error> {
    // Resolve hostname on the async runtime before spawn_blocking.
    // Only the first resolved address is used — matches the original
    // tokio::TcpStream::connect behavior.
    let resolved: std::net::SocketAddr = addr
        .to_socket_addrs()
        .map_err(|e| frp_core::Error::Transport(format!("resolve {}: {}", addr, e).into()))?
        .next()
        .ok_or_else(|| {
            frp_core::Error::Transport(format!("no address found for {}", addr).into())
        })?;
    let std_stream = tokio::task::spawn_blocking(move || {
        std::net::TcpStream::connect_timeout(&resolved, std::time::Duration::from_secs(5))
    })
    .await
    .map_err(|e| frp_core::Error::Transport(format!("spawn_blocking: {}", e).into()))?
    .map_err(|e| frp_core::Error::Transport(format!("connect {}: {}", resolved, e).into()))?;
    // Convert to tokio TcpStream
    std_stream
        .set_nonblocking(true)
        .map_err(|e| frp_core::Error::Transport(format!("set_nonblocking: {}", e).into()))?;
    let stream = TcpStream::from_std(std_stream)
        .map_err(|e| frp_core::Error::Transport(format!("from_std: {}", e).into()))?;
    frp_core::transport::set_nodelay(&stream);
    Ok(stream)
}

/// Bridge data between two streams with optional encryption, compression,
/// Parameters for `bridge_streams`.
pub struct BridgeStreamsParams<'a> {
    pub local: tokio::net::TcpStream,
    pub work: IoStream,
    pub name: &'a str,
    pub use_encryption: bool,
    pub use_compression: bool,
    pub enc_key: Option<&'a [u8; 16]>,
    pub bandwidth_limit: u64,
    pub bandwidth_limit_mode: &'a str,
    pub metrics: Arc<ProxyMetricsRegistry>,
}

/// Bridge user↔work connections with optional encryption, compression,
/// and bandwidth limiting.
///
/// `bandwidth_limit` is in bytes/sec (0 = unlimited).
/// `bandwidth_limit_mode` is "client" (upload), "server" (download), or "both".
pub async fn bridge_streams(params: BridgeStreamsParams<'_>) {
    let BridgeStreamsParams {
        local,
        work,
        name,
        use_encryption,
        use_compression,
        enc_key,
        bandwidth_limit,
        bandwidth_limit_mode,
        metrics,
    } = params;
    debug!(name = %name, encrypted = %use_encryption, compressed = %use_compression, bw_limit = %bandwidth_limit, bw_mode = %bandwidth_limit_mode,
        "Bridging streams for proxy: {} (encrypted: {}, compressed: {}, bw_limit: {} {})",
        name, use_encryption, use_compression, bandwidth_limit, bandwidth_limit_mode);

    let proxy_metrics = metrics.get_or_create(name).await;
    let _guard = ConnGuard::new(proxy_metrics.clone());

    // Build bandwidth limiters per direction.
    // "client" throttles upload (local→server, write to work).
    // "server" throttles download (server→local, read from work).
    // Empty/unspecified: apply both (backward compat).
    let apply_read = bandwidth_limit_mode == "server"
        || bandwidth_limit_mode == "both"
        || bandwidth_limit_mode.is_empty();
    let apply_write = bandwidth_limit_mode == "client"
        || bandwidth_limit_mode == "both"
        || bandwidth_limit_mode.is_empty();
    let mut read_lim = if bandwidth_limit > 0 && apply_read {
        Some(BandwidthLimiter::new(bandwidth_limit))
    } else {
        None
    };
    let mut write_lim = if bandwidth_limit > 0 && apply_write {
        Some(BandwidthLimiter::new(bandwidth_limit))
    } else {
        None
    };

    if use_encryption {
        if let Some(key) = enc_key {
            let key = *key;
            let local_io = IoStream::Tcp(local);
            frp_core::bridge::bridge_encrypted_io(
                local_io,
                work,
                &key,
                use_compression,
                Vec::new(),
                read_lim.as_mut(),
                write_lim.as_mut(),
                Some(proxy_metrics.clone()),
            )
            .await;
            debug!(name = %name, "Proxy {} encrypted bridge closed", name);
            return;
        }
        warn!(name = %name, "Proxy {}: encryption requested but no key available, falling back to plain", name);
    }

    // Plain path: use rate-limited bridge when bandwidth limiting or compression
    // is active, otherwise use the fast copy_bidirectional path.
    if use_compression || read_lim.is_some() || write_lim.is_some() {
        let (l_r, l_w) = tokio::io::split(local);
        let (w_r, w_w) = work.into_split().unwrap();
        bridge::bridge_plain_rate_limited(
            l_r,
            l_w,
            w_r,
            w_w,
            use_compression,
            Vec::new(),
            read_lim.as_mut(),
            write_lim.as_mut(),
            Some(proxy_metrics.clone()),
        )
        .await;
        debug!(name = %name, "Proxy {} rate-limited bridge closed", name);
    } else {
        let mut local = local;
        let mut work = work;
        match tokio::io::copy_bidirectional(&mut local, &mut work).await {
            Ok((to_work, to_local)) => {
                proxy_metrics.bytes_in.fetch_add(to_work, Ordering::Relaxed);
                proxy_metrics
                    .bytes_out
                    .fetch_add(to_local, Ordering::Relaxed);
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
                assert!(
                    nvc.sign_key.is_none(),
                    "sign_key should be None for empty sk"
                );
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
                assert!(
                    sig.chars().all(|c| c.is_ascii_hexdigit()),
                    "all chars must be hex digits"
                );
            }
            _ => panic!("expected NewVisitorConn variant"),
        }
    }
}
