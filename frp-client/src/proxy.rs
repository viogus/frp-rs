use std::future::Future;
use std::net::SocketAddr;
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
    server_user: Option<&str>,
    user: Option<&str>,
    run_id: Option<&str>,
) -> FrpMessage {
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    let sign_key = if secret_key.is_empty() {
        None
    } else {
        let hash = frp_core::auth::generate_token(secret_key, timestamp);
        debug!(
            server_name = %server_name,
            "STCP visitor auth credentials generated"
        );
        Some(hash)
    };
    // Build proxy_name matching Go frp's BuildTargetServerProxyName:
    // - If server_user is non-empty: {server_user}.{server_name}
    // - Else if client user is non-empty: {user}.{server_name}
    // - Otherwise: {server_name}
    let proxy_name = match (server_user, user) {
        (Some(su), _) if !su.is_empty() => format!("{su}.{server_name}"),
        (_, Some(u)) if !u.is_empty() => format!("{u}.{server_name}"),
        _ => server_name.to_string(),
    };
    FrpMessage::NewVisitorConn(msg::NewVisitorConn {
        proxy_name,
        sign_key,
        timestamp: Some(timestamp),
        run_id: run_id.map(|s| s.to_string()),
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
        sk: opt_if_empty!(p.sk),
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
/// `addr` may be a hostname like `"localhost:8080"` or an IP literal.
pub async fn connect_local(addr: &str) -> Result<TcpStream, frp_core::Error> {
    connect_local_with_resolver(
        addr,
        std::time::Duration::from_secs(5),
        |query| async move {
            tokio::net::lookup_host(query)
                .await
                .map(|addresses| addresses.collect())
        },
    )
    .await
}

async fn connect_local_with_resolver<R, F>(
    addr: &str,
    timeout: std::time::Duration,
    resolver: R,
) -> Result<TcpStream, frp_core::Error>
where
    R: FnOnce(String) -> F,
    F: Future<Output = std::io::Result<Vec<SocketAddr>>>,
{
    // Bound each address attempt well below the overall wall deadline so a
    // blackholed first address cannot consume the whole window and leave
    // later addresses with zero remaining time.
    let per_attempt_timeout = std::cmp::min(timeout, std::time::Duration::from_secs(1));
    connect_local_with_resolver_and_connector(
        addr,
        timeout,
        resolver,
        TcpStream::connect,
        per_attempt_timeout,
    )
    .await
}

async fn connect_local_with_resolver_and_connector<R, F, C, G>(
    addr: &str,
    timeout: std::time::Duration,
    resolver: R,
    connector: C,
    per_attempt_timeout: std::time::Duration,
) -> Result<TcpStream, frp_core::Error>
where
    R: FnOnce(String) -> F,
    F: Future<Output = std::io::Result<Vec<SocketAddr>>>,
    C: Fn(SocketAddr) -> G,
    G: Future<Output = std::io::Result<TcpStream>>,
{
    // Resolved addresses are attempted sequentially under one wall deadline
    // shared by DNS and all connects. Each attempt gets its own bounded timeout
    // so a blackholed address cannot consume the whole window: on per-address
    // timeout we continue with the next address until the wall deadline expires.
    // This is deliberately not a Happy Eyeballs race.
    let deadline = tokio::time::Instant::now() + timeout;
    let addresses = tokio::time::timeout_at(deadline, resolver(addr.to_owned()))
        .await
        .map_err(|_| frp_core::Error::Transport(format!("resolve {}: timed out", addr).into()))?
        .map_err(|e| frp_core::Error::Transport(format!("resolve {}: {}", addr, e).into()))?;

    if addresses.is_empty() {
        return Err(frp_core::Error::Transport(
            format!("no address found for {}", addr).into(),
        ));
    }

    let mut last_error = None;
    for socket_addr in addresses {
        let now = tokio::time::Instant::now();
        let remaining = deadline.saturating_duration_since(now);
        let attempt_deadline = now + std::cmp::min(per_attempt_timeout, remaining);
        match tokio::time::timeout_at(attempt_deadline, connector(socket_addr)).await {
            Ok(Ok(stream)) => {
                frp_core::transport::set_nodelay(&stream);
                return Ok(stream);
            }
            Ok(Err(error)) => last_error = Some(error.to_string()),
            Err(_) => {
                last_error = Some("timed out".to_string());
            }
        }
    }

    let detail = last_error.unwrap_or_else(|| "no address succeeded".to_string());
    Err(frp_core::Error::Transport(
        format!("connect {}: {}", addr, detail).into(),
    ))
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
    use std::io::{self, Write};
    use std::sync::{Arc, Mutex};

    #[tokio::test]
    async fn slow_dns_does_not_starve_runtime_timers() {
        let ticks = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let timer_ticks = ticks.clone();
        let ticker = tokio::spawn(async move {
            for _ in 0..5 {
                tokio::time::sleep(std::time::Duration::from_millis(2)).await;
                timer_ticks.fetch_add(1, Ordering::Relaxed);
            }
        });

        let result = connect_local_with_resolver(
            "slow.invalid:80",
            std::time::Duration::from_millis(20),
            |_| std::future::pending(),
        )
        .await;
        ticker.await.unwrap();

        assert!(result.is_err());
        assert_eq!(ticks.load(Ordering::Relaxed), 5);
    }

    #[tokio::test]
    async fn failed_dns_returns_transport_error() {
        let result = connect_local_with_resolver(
            "missing.invalid:80",
            std::time::Duration::from_secs(1),
            |_| async { Err(std::io::Error::other("injected DNS failure")) },
        )
        .await;

        assert!(result.unwrap_err().to_string().contains("resolve"));
    }

    #[tokio::test]
    async fn connect_tries_second_resolved_address_after_first_fails() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let success = listener.local_addr().unwrap();
        let failed: SocketAddr = "127.0.0.1:0".parse().unwrap();

        let stream = connect_local_with_resolver(
            "local.test:80",
            std::time::Duration::from_secs(1),
            move |_| async move { Ok(vec![failed, success]) },
        )
        .await
        .unwrap();

        assert_eq!(stream.peer_addr().unwrap(), success);
    }

    #[tokio::test]
    async fn connect_supports_resolved_ipv6_loopback() {
        let Ok(listener) = tokio::net::TcpListener::bind("[::1]:0").await else {
            return; // IPv6 may be disabled in a minimal CI network namespace.
        };
        let address = listener.local_addr().unwrap();

        let stream = connect_local_with_resolver(
            "ipv6.test:80",
            std::time::Duration::from_secs(1),
            move |_| async move { Ok(vec![address]) },
        )
        .await
        .unwrap();

        assert!(stream.peer_addr().unwrap().is_ipv6());
    }

    #[tokio::test]
    async fn connect_continues_after_first_address_stalls_until_deadline() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let success = listener.local_addr().unwrap();
        let stalled: SocketAddr = "127.0.0.1:1".parse().unwrap();

        let stream = connect_local_with_resolver_and_connector(
            "local.test:80",
            std::time::Duration::from_secs(2),
            move |_| async move { Ok(vec![stalled, success]) },
            move |addr| {
                async move {
                    if addr.port() == 1 {
                        // Simulate a blackholed first address: wait for the shared
                        // deadline instead of returning an immediate error.
                        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                        Err(std::io::Error::other("stalled address"))
                    } else {
                        tokio::net::TcpStream::connect(addr).await
                    }
                }
            },
            std::time::Duration::from_millis(100),
        )
        .await
        .unwrap();

        assert_eq!(stream.peer_addr().unwrap(), success);
    }

    #[derive(Clone)]
    struct CapturedLogs(Arc<Mutex<Vec<u8>>>);

    impl Write for CapturedLogs {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn test_visitor_auth_debug_log_does_not_leak_secret_or_replay_proof() {
        const SECRET_SENTINEL: &str = "S3KR-secret-key-sentinel";
        let output = Arc::new(Mutex::new(Vec::new()));
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .without_time()
            .with_writer({
                let output = output.clone();
                move || CapturedLogs(output.clone())
            })
            .finish();
        let _guard = tracing::subscriber::set_default(subscriber);

        let msg = create_visitor_conn_msg(
            "proxy-safe-name",
            SECRET_SENTINEL,
            false,
            false,
            None,
            None,
            None,
        );
        let (proof, timestamp) = match msg {
            FrpMessage::NewVisitorConn(nvc) => (nvc.sign_key.unwrap(), nvc.timestamp.unwrap()),
            _ => unreachable!(),
        };
        let logs = String::from_utf8(output.lock().unwrap().clone()).unwrap();

        assert!(logs.contains("STCP visitor auth"));
        assert!(!logs.contains("S3KR"), "secret prefix leaked: {logs}");
        assert!(!logs.contains(&proof), "replay proof leaked: {logs}");
        assert!(
            !logs.contains(&timestamp.to_string()),
            "auth timestamp leaked: {logs}"
        );
    }

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
        let msg = create_visitor_conn_msg("stcp-proxy", sk, false, false, None, None, None);

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
        let msg = create_visitor_conn_msg("stcp-proxy", "", false, false, None, None, None);

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
        let msg =
            create_visitor_conn_msg("stcp-proxy", "another_key", true, true, None, None, None);

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
