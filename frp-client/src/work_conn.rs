use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, Mutex, RwLock};
use tracing::{debug, info, warn};

use frp_core::auth::{AuthConfig, OidcClient};
use frp_core::encryption;
use frp_core::metrics::ProxyMetricsRegistry;
use frp_core::msg::{self, FrpMessage};
use frp_core::mux::YamuxSession;
use frp_core::protocol::{read_msg_v1, read_msg_v2, write_msg_v1, write_msg_v2};
#[cfg(feature = "quic")]
use frp_core::quic::QuicConnection;
use frp_core::transport::{dial_server, DialOptions, IoStream};

use crate::proxy;
use crate::proxy_runtime::ProxyRuntimeInfo;

#[cfg(feature = "vnet")]
type VnetTunMap = Arc<Mutex<HashMap<String, Option<Box<dyn frp_vnet::tun::TunDevice>>>>>;

/// Conditional type for the QUIC connection parameter.
/// When the `quic` feature is disabled, the parameter is `()` (ZST, no-op).
#[cfg(feature = "quic")]
type QuicConnOpt = Option<Arc<QuicConnection>>;
#[cfg(not(feature = "quic"))]
type QuicConnOpt = ();

/// Notification from a work connection that an XTCP NatHoleSid was received.
/// Sent to the control message loop so it can do STUN and send NatHoleClient.
#[derive(Debug)]
pub(crate) struct XtcpNotification {
    pub sid: String,
    pub proxy_name: String,
}

/// Check if an auth scope is enabled, considering both client and server config.
pub(crate) fn scope_requires_auth(
    client_scopes: &[String],
    server_scopes: &[String],
    scope: &str,
) -> bool {
    client_scopes.iter().any(|s| s == scope) || server_scopes.iter().any(|s| s == scope)
}

/// Configuration for spawning a work connection.
pub(crate) struct WorkConnConfig {
    pub server_addr: String,
    pub server_port: u16,
    pub protocol: frp_core::transport::TransportProtocol,
    pub run_id: String,
    pub proxy_info_map: Arc<RwLock<HashMap<String, ProxyRuntimeInfo>>>,
    pub enc_key: [u8; 16],
    pub pool_id: i32,
    pub auth_cfg: Arc<AuthConfig>,
    pub tls_enable: bool,
    pub tls_server_name: String,
    pub tls_ca_file: Option<String>,
    pub yamux: Option<Arc<YamuxSession>>,
    pub quic_conn: QuicConnOpt,
    pub v2: bool,
    pub oidc_client: Option<Arc<OidcClient>>,
    pub udp_sockets: Arc<Mutex<HashMap<String, Arc<UdpSocket>>>>,
    pub udp_enc_cfg: Arc<Mutex<HashMap<String, (bool, bool)>>>,
    pub proxy_metrics: Arc<ProxyMetricsRegistry>,
    pub client_auth_scopes: Vec<String>,
    pub server_auth_scopes: Vec<String>,
    pub disable_custom_tls_first_byte: bool,
    pub keepalive_secs: u64,
    pub bind_addr: Option<String>,
    pub proxy_url: String,
    pub user: String,
    pub dial_timeout_secs: u64,
    pub xtcp_tx: mpsc::Sender<XtcpNotification>,
    pub session_alive: Arc<AtomicBool>,
    /// Test-only probe: each spawned work-conn task increments this counter when
    /// it starts. Always `None` in production configs.
    pub spawned_counter: Option<Arc<std::sync::atomic::AtomicUsize>>,
    #[cfg(feature = "vnet")]
    pub vnet_tuns: VnetTunMap,
    #[cfg(feature = "vnet")]
    pub vnet_controller: Arc<frp_vnet::controller::ClientVnetController>,
    #[cfg(feature = "vnet")]
    pub vnet_tun_tx: Arc<Mutex<HashMap<String, mpsc::Sender<Vec<u8>>>>>,
}

/// Bundled parameters for work connection transport acquisition.
/// Extracted from `connect_yamux_or_dial` to keep the argument count manageable.
struct WorkConnDialConfig<'a> {
    yamux: &'a Option<Arc<YamuxSession>>,
    label: &'a str,
    server_addr: &'a str,
    server_port: u16,
    protocol: &'a frp_core::transport::TransportProtocol,
    tls_enable: bool,
    tls_server_name: &'a str,
    tls_ca_file: &'a Option<String>,
    disable_custom_tls_first_byte: bool,
    keepalive_secs: u64,
    bind_addr: &'a Option<String>,
    proxy_url: &'a str,
    dial_timeout_secs: u64,
}

/// Shared yamux-or-dial path for work connection transport acquisition.
/// Used by both QUIC and non-QUIC branches.
async fn connect_yamux_or_dial(cfg: &WorkConnDialConfig<'_>) -> Option<IoStream> {
    if let Some(ref yamux) = *cfg.yamux {
        match yamux.open_stream().await {
            Some(stream) => {
                debug!(label = %cfg.label, "Work conn {} opened yamux stream", cfg.label);
                Some(IoStream::Yamux(stream))
            }
            None => {
                warn!(label = %cfg.label, "Work conn {}: yamux open stream failed, session closed?", cfg.label);
                None
            }
        }
    } else {
        debug!(label = %cfg.label, "Work conn {} dialing server", cfg.label);
        let opts = DialOptions {
            server_addr: cfg.server_addr.to_string(),
            server_port: cfg.server_port,
            protocol: cfg.protocol.clone(),
            tls_enable: cfg.tls_enable,
            tls_server_name: cfg.tls_server_name.to_string(),
            tls_ca_file: cfg.tls_ca_file.clone(),
            disable_custom_tls_first_byte: cfg.disable_custom_tls_first_byte,
            keepalive_secs: cfg.keepalive_secs,
            bind_addr: cfg.bind_addr.clone(),
            proxy_url: if cfg.proxy_url.is_empty() {
                None
            } else {
                Some(cfg.proxy_url.to_string())
            },
            dial_timeout_secs: cfg.dial_timeout_secs,
            ..Default::default()
        };
        match dial_server(&opts).await {
            Ok(io) => Some(io),
            Err(e) => {
                debug!(label = %cfg.label, error = %e, "Work conn {} dial failed: {}", cfg.label, e);
                None
            }
        }
    }
}

fn start_work_conn_timeout(dial_timeout_secs: u64) -> Duration {
    Duration::from_secs(dial_timeout_secs.max(1))
}

async fn read_start_work_conn_with_timeout(
    work: &mut IoStream,
    v2: bool,
    timeout: Duration,
) -> std::io::Result<FrpMessage> {
    // Rust-only transport safety: Go frp v0.70.1 has no client-side timeout for
    // StartWorkConn. This bounds only the dial/handshake phase and is dropped as
    // soon as StartWorkConn arrives, so it never limits a long-lived bridge.
    tokio::time::timeout(timeout, async {
        if v2 {
            work.read_v2_frame().await
        } else {
            work.read_v1_frame().await
        }
    })
    .await
    .map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "timed out waiting for StartWorkConn",
        )
    })?
    .map_err(std::io::Error::other)
}

#[allow(clippy::too_many_arguments)]
async fn run_udp_work_conn(
    work: IoStream,
    sock: Arc<UdpSocket>,
    proxy_name: String,
    local_addr_str: String,
    enc_key: [u8; 16],
    use_enc: bool,
    use_comp: bool,
    v2: bool,
    session_alive: Arc<AtomicBool>,
) {
    let (mut w_r, mut w_w) = work.into_split().unwrap();
    let (cancel_tx, cancel_rx) = tokio::sync::watch::channel(false);
    let last_remote: Arc<std::sync::Mutex<Option<std::net::SocketAddr>>> =
        Arc::new(std::sync::Mutex::new(None));

    let sock_r = sock.clone();
    let pn_r = proxy_name.clone();
    let last_remote_r = last_remote.clone();
    let session_alive_r = session_alive.clone();
    let mut reader_cancel = cancel_rx.clone();
    let reader = async move {
        debug!(proxy_name = %pn_r, "UDP reader '{}' started", pn_r);
        loop {
            tokio::select! {
                biased;
                changed = reader_cancel.changed() => {
                    if changed.is_err() || *reader_cancel.borrow() { break; }
                }
                result = async {
                    if v2 { read_msg_v2(&mut w_r).await } else { read_msg_v1(&mut w_r).await }
                } => {
                    match result {
                        Ok(FrpMessage::UDPPacket(up)) => {
                            if let Some(ref ra) = up.remote_addr {
                                if let Ok(ip) = ra.ip.parse::<std::net::IpAddr>() {
                                    *last_remote_r.lock().unwrap() =
                                        Some(std::net::SocketAddr::new(ip, ra.port));
                                } else {
                                    warn!(ip = %ra.ip, port = ra.port,
                                        "UDP packet: unparseable remote IP, keeping previous last_remote");
                                }
                            }
                            let n = up.content.len();
                            let mut payload = up.content;
                            if use_enc {
                                if let Ok(d) = encryption::decrypt(&payload, &enc_key) {
                                    payload = d;
                                }
                            }
                            if use_comp {
                                if let Ok(d) = encryption::decompress(&payload) {
                                    payload = d;
                                }
                            }
                            debug!(proxy_name = %pn_r, byte_count = n,
                                "UDP reader '{}': forwarding {} bytes to local", pn_r, n);
                            if let Err(e) = sock_r.send(&payload).await {
                                debug!(proxy_name = %pn_r, error = %e,
                                    "UDP '{}' send to local failed: {}", pn_r, e);
                                break;
                            }
                        }
                        Ok(FrpMessage::Ping(_)) | Ok(FrpMessage::Pong(_)) => continue,
                        Ok(other) => {
                            debug!(proxy_name = %pn_r, v1_type = ?other.v1_type_byte(),
                                "UDP work conn '{}': unexpected msg 0x{:02x}", pn_r, other.v1_type_byte());
                        }
                        Err(e) => {
                            debug!(proxy_name = %pn_r, error = %e,
                                "UDP work conn '{}' read closed: {}", pn_r, e);
                            break;
                        }
                    }
                }
                _ = tokio::time::sleep(Duration::from_secs(5)) => {
                    if !session_alive_r.load(Ordering::Acquire) {
                        debug!(proxy_name = %pn_r, "UDP reader '{}': session dead, stopping", pn_r);
                        break;
                    }
                }
            }
        }
    };

    let bridge_name = proxy_name.clone();
    let pn_w = proxy_name;
    let last_remote_w = last_remote;
    let session_alive_w = session_alive;
    let mut writer_cancel = cancel_rx;
    let writer = async move {
        debug!(proxy_name = %pn_w, "UDP writer '{}' started", pn_w);
        let mut buf = vec![0u8; 65535];
        let mut payload = Vec::with_capacity(65535);
        let mut keepalive = tokio::time::interval(Duration::from_secs(30));
        keepalive.tick().await;
        loop {
            tokio::select! {
                biased;
                changed = writer_cancel.changed() => {
                    if changed.is_err() || *writer_cancel.borrow() { break; }
                }
                result = sock.recv_from(&mut buf) => {
                    match result {
                        Ok((n, src)) => {
                            debug!(proxy_name = %pn_w, byte_count = n, src_addr = %src,
                                "UDP writer '{}': recv'd {} bytes from local {}", pn_w, n, src);
                            payload.clear();
                            payload.extend_from_slice(&buf[..n]);
                            if use_comp {
                                if let Ok(c) = encryption::compress(&payload) { payload = c; }
                            }
                            if use_enc {
                                if let Ok(e) = encryption::encrypt(&payload, &enc_key) { payload = e; }
                            }
                            let remote_addr = last_remote_w.lock().unwrap().map(|sa| msg::UdpAddr {
                                ip: sa.ip().to_string(),
                                port: sa.port(),
                                zone: String::new(),
                            });
                            let pkt = FrpMessage::UDPPacket(msg::UDPPacket {
                                content: std::mem::take(&mut payload),
                                local_addr: msg::UdpAddr::from_string(&local_addr_str),
                                remote_addr,
                            });
                            let result = if v2 {
                                write_msg_v2(&mut w_w, &pkt).await
                            } else {
                                write_msg_v1(&mut w_w, &pkt).await
                            };
                            if let Err(e) = result {
                                debug!(proxy_name = %pn_w, error = %e,
                                    "UDP '{}' send to work conn failed: {}", pn_w, e);
                                break;
                            }
                        }
                        Err(e) => {
                            debug!(proxy_name = %pn_w, error = %e,
                                "UDP '{}' recv from local failed: {}", pn_w, e);
                            break;
                        }
                    }
                }
                _ = tokio::time::sleep(Duration::from_secs(5)) => {
                    if !session_alive_w.load(Ordering::Acquire) {
                        debug!(proxy_name = %pn_w, "UDP writer '{}': session dead, stopping", pn_w);
                        break;
                    }
                }
                _ = keepalive.tick() => {
                    let ping = FrpMessage::Ping(msg::Ping { privilege_key: None, timestamp: None });
                    let result = if v2 {
                        write_msg_v2(&mut w_w, &ping).await
                    } else {
                        write_msg_v1(&mut w_w, &ping).await
                    };
                    if let Err(e) = result {
                        debug!(proxy_name = %pn_w, error = %e,
                            "UDP work conn '{}' keepalive ping failed: {}", pn_w, e);
                        break;
                    }
                }
            }
        }
    };

    tokio::pin!(reader, writer);
    tokio::select! {
        _ = &mut reader => {
            debug!(proxy_name = %bridge_name, "UDP reader exited; draining then cancelling writer");
            let _ = cancel_tx.send(true);
            let _ = tokio::time::timeout(Duration::from_millis(100), &mut writer).await;
        }
        _ = &mut writer => {
            debug!(proxy_name = %bridge_name, "UDP writer exited; draining then cancelling reader");
            let _ = cancel_tx.send(true);
            let _ = tokio::time::timeout(Duration::from_millis(100), &mut reader).await;
        }
    }
}

/// Bridge a `virtual_net` plugin work connection to the shared vnet controller.
///
/// Equivalent to Go frp's `VnetController.StartServerConnReadLoop`: bytes
/// arriving from the remote visitor tunnel are written into the local TUN,
/// and the remote source IP is registered so TUN return packets are written
/// back to this work connection.
#[cfg(feature = "vnet")]
async fn run_virtual_net_plugin_work_conn(
    work: IoStream,
    proxy_name: String,
    vnet_controller: Arc<frp_vnet::controller::ClientVnetController>,
    vnet_tun_tx: Arc<Mutex<HashMap<String, mpsc::Sender<Vec<u8>>>>>,
) {
    let tun_tx = {
        let txs = vnet_tun_tx.lock().await;
        txs.get(&proxy_name).cloned()
    };
    let Some(tun_tx) = tun_tx else {
        warn!(proxy_name = %proxy_name, "virtual_net plugin: no TUN channel for '{}'", proxy_name);
        return;
    };

    let (mut work_r, mut work_w) = work.into_split().expect("work conn split");
    let (return_tx, mut return_rx) = mpsc::channel::<Vec<u8>>(256);
    let (cancel_tx, cancel_rx) = tokio::sync::watch::channel(false);

    let reader_name = proxy_name.clone();
    let reader_ctrl = vnet_controller.clone();
    let reader_rtx = return_tx.clone();
    let reader_tun = tun_tx;
    let mut reader_cancel = cancel_rx.clone();
    let reader = async move {
        let mut registered_ips = Vec::<std::net::Ipv4Addr>::new();
        let mut buf = vec![0u8; 1420];
        loop {
            tokio::select! {
                biased;
                changed = reader_cancel.changed() => {
                    if changed.is_err() || *reader_cancel.borrow() { break; }
                }
                n = work_r.read(&mut buf) => {
                    match n {
                        Ok(0) => break,
                        Ok(n) => {
                            let packet = buf[..n].to_vec();
                            // Learn the remote host's source IP so return
                            // packets can be routed back on this connection.
                            if packet.len() >= 20 && (packet[0] >> 4) == 4 {
                                let src_ip = std::net::Ipv4Addr::new(
                                    packet[12], packet[13], packet[14], packet[15],
                                );
                                reader_ctrl
                                    .register_server_conn(src_ip, reader_rtx.clone())
                                    .await;
                                registered_ips.push(src_ip);
                            }
                            if let Err(e) = reader_tun.try_send(packet) {
                                match e {
                                    mpsc::error::TrySendError::Full(_) => {
                                        warn!(
                                            proxy_name = %reader_name,
                                            "virtual_net plugin TUN queue full; dropping packet"
                                        );
                                    }
                                    mpsc::error::TrySendError::Closed(_) => break,
                                }
                            }
                        }
                        Err(e) => {
                            warn!(
                                proxy_name = %reader_name,
                                error = %e,
                                "virtual_net plugin work conn read error: {}",
                                e
                            );
                            break;
                        }
                    }
                }
            }
        }
        for src_ip in &registered_ips {
            reader_ctrl
                .unregister_server_conn_if_matches(src_ip, &reader_rtx)
                .await;
        }
    };

    let writer_name = proxy_name;
    let mut writer_cancel = cancel_rx;
    let writer = async move {
        loop {
            tokio::select! {
                biased;
                changed = writer_cancel.changed() => {
                    if changed.is_err() || *writer_cancel.borrow() { break; }
                }
                pkt = return_rx.recv() => {
                    match pkt {
                        Some(pkt) => {
                            if let Err(e) = work_w.write_all(&pkt).await {
                                warn!(
                                    proxy_name = %writer_name,
                                    error = %e,
                                    "virtual_net plugin work conn write error: {}",
                                    e
                                );
                                break;
                            }
                        }
                        None => break,
                    }
                }
            }
        }
    };

    tokio::pin!(reader, writer);
    tokio::select! {
        _ = &mut reader => {
            let _ = cancel_tx.send(true);
            let _ = tokio::time::timeout(Duration::from_millis(100), &mut writer).await;
        }
        _ = &mut writer => {
            let _ = cancel_tx.send(true);
            let _ = tokio::time::timeout(Duration::from_millis(100), &mut reader).await;
        }
    }
}

/// Spawn a single work connection task.
///
/// The task:
/// 1. Under TcpMux: opens a yamux stream on the shared session
///    Without TcpMux: dials the server via TCP/TLS/WS
/// 2. Without TcpMux: sends NewWorkConn (with run_id + auth)
/// 3. Reads StartWorkConn from the server
/// 4. Connects to the local service
/// 5. Bridges data bidirectionally
///
/// `pool_id` is for logging only (< 0 means on-demand).
pub(crate) fn spawn_work_conn(cfg: WorkConnConfig) {
    tokio::spawn(async move {
        if let Some(counter) = &cfg.spawned_counter {
            counter.fetch_add(1, Ordering::SeqCst);
        }

        let WorkConnConfig {
            server_addr,
            server_port,
            protocol,
            run_id,
            proxy_info_map,
            enc_key,
            pool_id,
            auth_cfg,
            tls_enable,
            tls_server_name,
            tls_ca_file,
            yamux,
            quic_conn: _quic_conn,
            v2,
            oidc_client,
            udp_sockets,
            udp_enc_cfg,
            proxy_metrics,
            client_auth_scopes: client_scopes,
            server_auth_scopes: server_scopes,
            disable_custom_tls_first_byte,
            keepalive_secs,
            bind_addr,
            proxy_url,
            user,
            dial_timeout_secs,
            xtcp_tx,
            session_alive,
            spawned_counter: _spawned_counter,
            #[cfg(feature = "vnet")]
                vnet_tuns: _vnet_tuns,
            #[cfg(feature = "vnet")]
            vnet_controller,
            #[cfg(feature = "vnet")]
            vnet_tun_tx,
        } = cfg;

        let label = if pool_id >= 0 {
            format!("pool-{}", pool_id)
        } else {
            "on-demand".to_string()
        };

        // Acquire the underlying transport stream.
        // Priority: QUIC multi-stream > TcpMux yamux > direct dial.
        // Go frp compat: QUIC work connections open new streams on the
        // existing QUIC connection (multi-stream-per-connection).
        #[cfg(feature = "quic")]
        let mut work = if let Some(ref quic) = _quic_conn {
            match quic.open_bi().await {
                Ok(stream) => {
                    debug!(label = %label, "Work conn {} opened QUIC stream", label);
                    IoStream::Quic(stream)
                }
                Err(e) => {
                    warn!(label = %label, error = %e, "Work conn {}: QUIC open_bi failed: {}", label, e);
                    return;
                }
            }
        } else {
            let dial_cfg = WorkConnDialConfig {
                yamux: &yamux,
                label: &label,
                server_addr: &server_addr,
                server_port,
                protocol: &protocol,
                tls_enable,
                tls_server_name: &tls_server_name,
                tls_ca_file: &tls_ca_file,
                disable_custom_tls_first_byte,
                keepalive_secs,
                bind_addr: &bind_addr,
                proxy_url: &proxy_url,
                dial_timeout_secs,
            };
            match connect_yamux_or_dial(&dial_cfg).await {
                Some(io) => io,
                None => return,
            }
        };

        #[cfg(not(feature = "quic"))]
        let dial_cfg = WorkConnDialConfig {
            yamux: &yamux,
            label: &label,
            server_addr: &server_addr,
            server_port,
            protocol: &protocol,
            tls_enable,
            tls_server_name: &tls_server_name,
            tls_ca_file: &tls_ca_file,
            disable_custom_tls_first_byte,
            keepalive_secs,
            bind_addr: &bind_addr,
            proxy_url: &proxy_url,
            dial_timeout_secs,
        };
        #[cfg(not(feature = "quic"))]
        let mut work = match connect_yamux_or_dial(&dial_cfg).await {
            Some(io) => io,
            None => return,
        };

        // Send NewWorkConn — required for both yamux and raw transports.
        // Go frps needs the run_id and auth to associate the stream.
        {
            let mut nwc_msg = msg::NewWorkConn {
                run_id: Some(run_id.clone()),
                timestamp: None,
                privilege_key: None,
            };
            let requires_auth = scope_requires_auth(&client_scopes, &server_scopes, "NewWorkConns");
            if requires_auth {
                if let Some(ref oidc) = oidc_client {
                    if let Err(e) = oidc.set_new_work_conn(&mut nwc_msg).await {
                        warn!(label = %label, error = %e, "Work conn {} OIDC NewWorkConn auth failed: {}", label, e);
                        return;
                    }
                } else {
                    let timestamp = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs() as i64;
                    match auth_cfg.try_generate_login_key(timestamp) {
                        Ok(key) => {
                            nwc_msg.privilege_key = Some(key);
                            nwc_msg.timestamp = Some(timestamp);
                        }
                        Err(e) => {
                            warn!(label = %label, error = %e, "Work conn {} token source failed: {}", label, e);
                            return;
                        }
                    }
                }
            }
            // Write V2 magic before NewWorkConn on work connection streams.
            // Both Go frp and Rust frp write V2 magic on yamux work conn
            // streams, matching Go frp's messageConnector.Connect() which
            // calls WriteMagicIfV2 before returning the stream.
            if v2 {
                if let Err(e) = frp_core::protocol::write_v2_magic(&mut work).await {
                    warn!(label = %label, error = %e, "Work conn {} failed to write V2 magic: {}", label, e);
                    return;
                }
            }
            let nwc = FrpMessage::NewWorkConn(nwc_msg);
            let write_result = if v2 {
                work.write_v2_frame(&nwc).await
            } else {
                work.write_v1_frame(&nwc).await
            };
            if let Err(e) = write_result {
                warn!(label = %label, error = %e, "Work conn {} failed to send NewWorkConn: {}", label, e);
                return;
            }
            debug!(label = %label, "Work conn {} sent NewWorkConn, waiting for StartWorkConn", label);
        }

        // Read StartWorkConn
        let swc_result = read_start_work_conn_with_timeout(
            &mut work,
            v2,
            start_work_conn_timeout(dial_timeout_secs),
        )
        .await;
        match swc_result {
            Ok(FrpMessage::StartWorkConn(swc)) => {
                let proxy_name = &swc.proxy_name;
                debug!(label = %label, proxy_name = %proxy_name, "Work conn {} assigned to proxy '{}'", label, proxy_name);

                // Strip `{user}.` prefix from proxy_name if configured.
                // Go frp server prefixes proxy names with `{user}.` when
                // the client has a non-empty user (multi-tenant support).
                // The local proxy_info_map uses the bare proxy name (no prefix).
                let proxy_name = if !user.is_empty() {
                    let prefix = format!("{}.", user);
                    if let Some(rest) = proxy_name.strip_prefix(&prefix) {
                        debug!(label = %label, original = %swc.proxy_name, stripped = %rest, "Work conn {}: stripped user prefix from '{}' -> '{}'", label, swc.proxy_name, rest);
                        rest.to_string()
                    } else {
                        proxy_name.to_string()
                    }
                } else {
                    proxy_name.to_string()
                };

                // Look up the proxy runtime info
                let info = {
                    let map = proxy_info_map.read().await;
                    map.get(&proxy_name).cloned()
                };
                let info = match info {
                    Some(info) => info,
                    None => {
                        warn!(label = %label, proxy_name = %proxy_name, "Work conn {}: unknown proxy '{}'", label, proxy_name);
                        return;
                    }
                };

                if info.proxy_type == "xtcp" {
                    // XTCP proxy: after StartWorkConn, the next data on the work
                    // connection is either a NatHoleSid frame (XTCP notification)
                    // or raw bridge data (STCP fallback).
                    //
                    // Rust frps embeds nat_hole_sid in StartWorkConn JSON (new).
                    // Go frps sends a separate NatHoleSid V1 frame after (old).
                    // Check the embedded field first, then fall back to byte-peek.
                    if let Some(sid) = swc.nat_hole_sid.clone() {
                        if sid.is_empty() {
                            // STCP fallback marker from Rust frps.
                            // nat_hole_sid: Some("") (empty string) signals
                            // that this work conn is for STCP bridging, not
                            // XTCP notification. No dummy frame follows —
                            // the StartWorkConn payload is immediately
                            // followed by bridge data.
                            debug!(label = %label, proxy_name = %proxy_name, "XTCP work conn {}: STCP fallback for '{}'", label, proxy_name);
                            // Fall through to bridging
                        } else {
                            debug!(label = %label, proxy_name = %proxy_name, "XTCP work conn {}: NatHoleSid in StartWorkConn for '{}'", label, proxy_name);
                            // send().await: backpressure is correct here —
                            // if the control loop cannot drain XTCP notifications,
                            // the work connection should wait rather than silently
                            // drop the notification (which would hang the visitor).
                            let _ = xtcp_tx
                                .send(XtcpNotification {
                                    sid,
                                    proxy_name: proxy_name.clone(),
                                })
                                .await;
                            return; // XTCP notification: work conn consumed
                        }
                    }

                    // No embedded sid. Could be Go frps XTCP notification
                    // (separate NatHoleSid V1 frame with type byte 0x35 follows)
                    // or STCP fallback (bridge data follows).
                    // Byte-peek: read 1 byte, check if it's NatHoleSid type.
                    if !v2 {
                        use tokio::io::AsyncReadExt;
                        let mut peek = [0u8; 1];
                        match work.read_exact(&mut peek).await {
                            Ok(_) if peek[0] == msg::TYPE_NAT_HOLE_SID => {
                                // Likely Go frps NatHoleSid V1 frame.
                                // Read remaining 8 header bytes + payload.
                                let mut header = [0u8; 8];
                                let mut consumed = vec![msg::TYPE_NAT_HOLE_SID];
                                match work.read_exact(&mut header).await {
                                    Ok(_) => {
                                        consumed.extend_from_slice(&header);
                                        let length = i64::from_be_bytes(header);
                                        if (0..=frp_core::protocol::V1_MAX_MSG_LENGTH)
                                            .contains(&length)
                                        {
                                            let mut payload = vec![0u8; length as usize];
                                            if work.read_exact(&mut payload).await.is_ok() {
                                                consumed.extend_from_slice(&payload);
                                                match serde_json::from_slice::<msg::NatHoleSid>(
                                                    &payload,
                                                ) {
                                                    Ok(sid_msg) => {
                                                        if let Some(sid) = sid_msg.sid {
                                                            debug!(label = %label, proxy_name = %proxy_name, "XTCP work conn {}: NatHoleSid (Go frps) for '{}'", label, proxy_name);
                                                            let _ = xtcp_tx
                                                                .send(XtcpNotification {
                                                                    sid,
                                                                    proxy_name: proxy_name.clone(),
                                                                })
                                                                .await;
                                                            return;
                                                        }
                                                        // sid=None: STCP fallback (Go frps — unlikely)
                                                        debug!(label = %label, "XTCP work conn {}: NatHoleSid without sid (Go frps STCP fallback)", label);
                                                        // Fall through to bridging — no pre-read needed (NatHoleSid consumed).
                                                    }
                                                    _ => {
                                                        // Parsed as non-NatHoleSid — bridge data with a
                                                        // very unlikely 0x35 collision. Wrap consumed bytes.
                                                        work = IoStream::BufferedRead(
                                                            consumed,
                                                            0,
                                                            Box::new(work),
                                                        );
                                                    }
                                                }
                                            } else {
                                                // Payload read failed — wrap consumed header bytes.
                                                work = IoStream::BufferedRead(
                                                    consumed,
                                                    0,
                                                    Box::new(work),
                                                );
                                            }
                                        } else {
                                            // Invalid V1 length — wrap consumed header bytes.
                                            work =
                                                IoStream::BufferedRead(consumed, 0, Box::new(work));
                                        }
                                    }
                                    Err(_) => {
                                        // Header read failed after 0x35 — wrap 1 byte.
                                        work = IoStream::BufferedRead(consumed, 0, Box::new(work));
                                    }
                                }
                            }
                            Ok(_) => {
                                // Not 0x35 — STCP fallback. Wrap the peeked byte
                                // as pre-read bridge data.
                                work = IoStream::BufferedRead(vec![peek[0]], 0, Box::new(work));
                            }
                            Err(_) => {
                                // EOF after StartWorkConn — bridge will get 0 bytes.
                            }
                        }
                    }
                    // V2: read one frame and check for NatHoleSid.
                    // Rust frps sends a V2 NatHoleSid frame after StartWorkConn
                    // for XTCP notification (separate frame for Go frp compat).
                    // Go frp v0.69.1 doesn't support V2 XTCP, so this is
                    // Rust↔Rust only.
                    if v2 {
                        use frp_core::protocol::{read_v2_frame_raw, V2_FRAME_TYPE_MESSAGE};
                        let mut peek_buf = Vec::new();
                        match read_v2_frame_raw(&mut work).await {
                            Ok((V2_FRAME_TYPE_MESSAGE, flags, payload)) => {
                                peek_buf.extend_from_slice(&V2_FRAME_TYPE_MESSAGE.to_be_bytes());
                                peek_buf.extend_from_slice(&flags.to_be_bytes());
                                peek_buf.extend_from_slice(&(payload.len() as u32).to_be_bytes());
                                peek_buf.extend_from_slice(&payload);
                                if payload.len() >= 2 {
                                    let type_id = u16::from_be_bytes([payload[0], payload[1]]);
                                    if type_id == msg::V2_TYPE_NAT_HOLE_SID {
                                        if let Ok(sid_msg) =
                                            serde_json::from_slice::<msg::NatHoleSid>(&payload[2..])
                                        {
                                            if let Some(sid) = sid_msg.sid {
                                                if !sid.is_empty() {
                                                    debug!(label = %label, proxy_name = %proxy_name, "XTCP work conn {}: NatHoleSid (V2) for '{}'", label, proxy_name);
                                                    let _ = xtcp_tx
                                                        .send(XtcpNotification {
                                                            sid,
                                                            proxy_name: proxy_name.clone(),
                                                        })
                                                        .await;
                                                    return;
                                                }
                                            }
                                            // sid=None or empty: STCP fallback — replay frame
                                        }
                                    }
                                }
                                // Not a NatHoleSid with non-empty sid — replay for STCP bridging
                                work = IoStream::BufferedRead(peek_buf, 0, Box::new(work));
                            }
                            Ok((frame_type, flags, payload)) => {
                                // Non-Message frame type — replay for STCP bridging
                                peek_buf.extend_from_slice(&frame_type.to_be_bytes());
                                peek_buf.extend_from_slice(&flags.to_be_bytes());
                                peek_buf.extend_from_slice(&(payload.len() as u32).to_be_bytes());
                                peek_buf.extend_from_slice(&payload);
                                work = IoStream::BufferedRead(peek_buf, 0, Box::new(work));
                            }
                            Err(_) => {
                                // Not a V2 frame — raw bridge data for STCP fallback.
                                // read_v2_frame_raw already consumed some bytes; the
                                // stream is in an indeterminate state. Fall through to
                                // bridging — the bridge will get an error or partial data.
                            }
                        }
                    }

                    // Fall through to normal bridging for STCP fallback
                }

                #[cfg(feature = "vnet")]
                if info.proxy_type == "vnet" {
                    // VnetController is spawned in the service layer after TUN
                    // creation. The work connection for vnet proxies carries
                    // StartWorkConn for connection lifecycle signaling;
                    // VnetPackets flow on the control connection.
                    info!(label = %label, proxy_name = %proxy_name, "vnet work conn established (controller in service layer)");
                    return;
                }

                #[cfg(feature = "vnet")]
                if info.plugin == "virtual_net" {
                    info!(label = %label, proxy_name = %proxy_name, "Work conn {} handed to virtual_net plugin controller", label);
                    run_virtual_net_plugin_work_conn(
                        work,
                        proxy_name.clone(),
                        vnet_controller,
                        vnet_tun_tx,
                    )
                    .await;
                    return;
                }

                if info.proxy_type == "udp" {
                    // UDP proxy: bridge work conn ↔ local UDP socket
                    let sock = {
                        let map = udp_sockets.lock().await;
                        map.get(&proxy_name).cloned()
                    };
                    let sock = match sock {
                        Some(s) => s,
                        None => {
                            warn!(label = %label, proxy_name = %proxy_name, "Work conn {}: no UDP socket for proxy '{}'", label, proxy_name);
                            return;
                        }
                    };
                    let enc_cfg = {
                        let cfg = udp_enc_cfg.lock().await;
                        cfg.get(&proxy_name).copied().unwrap_or((false, false))
                    };
                    let (use_enc, use_comp) = enc_cfg;

                    info!(label = %label, proxy_name = %proxy_name, use_enc = %use_enc, use_comp = %use_comp,
                        "Work conn {} bridging UDP for '{}' (enc={}, comp={})",
                        label, proxy_name, use_enc, use_comp);

                    run_udp_work_conn(
                        work,
                        sock,
                        proxy_name.clone(),
                        info.local_addr.clone(),
                        enc_key,
                        use_enc,
                        use_comp,
                        v2,
                        session_alive.clone(),
                    )
                    .await;
                } else {
                    // Check if session is still alive before bridging
                    if !session_alive.load(Ordering::Acquire) {
                        debug!(label = %label, "Work conn {}: session dead, skipping bridge", label);
                        return;
                    }
                    // TCP/HTTP/STCP: connect to local TCP service and bridge
                    match proxy::connect_local(&info.local_addr).await {
                        Ok(mut local) => {
                            // Write PROXY protocol header if configured
                            if !info.proxy_protocol_version.is_empty() {
                                if let Some(ref src) = swc.src_addr {
                                    if info.proxy_protocol_version == "v1" {
                                        let header =
                                            frp_core::proxy_protocol::build_proxy_protocol_v1(
                                                src,
                                                swc.dst_addr.as_deref().unwrap_or("0.0.0.0"),
                                                swc.src_port.unwrap_or(0) as u16,
                                                swc.dst_port.unwrap_or(0) as u16,
                                            );
                                        if let Err(e) = local.write_all(header.as_bytes()).await {
                                            warn!(error = %e, "Failed to write PROXY v1 header: {}", e);
                                        }
                                    } else if info.proxy_protocol_version == "v2" {
                                        match frp_core::proxy_protocol::build_proxy_protocol_v2(
                                            src,
                                            swc.dst_addr.as_deref().unwrap_or("0.0.0.0"),
                                            swc.src_port.unwrap_or(0) as u16,
                                            swc.dst_port.unwrap_or(0) as u16,
                                        ) {
                                            Ok(header) => {
                                                if let Err(e) = local.write_all(&header).await {
                                                    warn!(error = %e, "Failed to write PROXY v2 header: {}", e);
                                                }
                                            }
                                            Err(e) => {
                                                warn!(error = %e, "Failed to build PROXY v2 header: {}", e);
                                            }
                                        }
                                    }
                                }
                            }
                            // Respect StartWorkConn's use_encryption/use_compression
                            // if explicitly set (Some), otherwise fall back to
                            // proxy info. This allows the server to disable
                            // encryption for XTCP STCP fallback work connections
                            // to avoid the dual-CipherWriter deadlock.
                            let use_enc = swc.use_encryption.unwrap_or(info.use_encryption);
                            let use_comp = swc.use_compression.unwrap_or(info.use_compression);
                            let enc = if use_enc { Some(&enc_key) } else { None };
                            proxy::bridge_streams(proxy::BridgeStreamsParams {
                                local,
                                work,
                                name: &proxy_name,
                                use_encryption: use_enc,
                                use_compression: use_comp,
                                enc_key: enc,
                                bandwidth_limit: info.bandwidth_limit,
                                bandwidth_limit_mode: &info.bandwidth_limit_mode,
                                metrics: proxy_metrics,
                            })
                            .await;
                        }
                        Err(e) => {
                            warn!(label = %label, local_addr = %info.local_addr, error = %e, "Work conn {}: failed to connect to local {}: {}", label, info.local_addr, e);
                        }
                    }
                }
            }
            Ok(other) => {
                warn!(label = %label, v1_type = ?other.v1_type_byte(), "Work conn {}: unexpected message: {:?}", label, other.v1_type_byte());
            }
            Err(e) => {
                debug!(label = %label, error = %e, "Work conn {}: read error: {}", label, e);
            }
        }

        debug!(label = %label, "Work conn {} completed", label);

        // Pool replenishment is server-driven (ReqWorkConn), matching Go frp
        // v0.70. The client does NOT auto-spawn replacements — if it did,
        // concurrent completions could push the pool past server pool_cap
        // before the server can refuse, wasting TCP/TLS/yamux setup.
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Work stream whose reads block forever and whose writes fail
    /// deterministically. Used to test writer-error cancellation without
    /// depending on platform TCP shutdown/RST timing.
    struct FailingWorkStream;

    impl tokio::io::AsyncRead for FailingWorkStream {
        fn poll_read(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            _buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Pending
        }
    }

    impl tokio::io::AsyncWrite for FailingWorkStream {
        fn poll_write(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            _buf: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            std::task::Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "injected writer failure",
            )))
        }

        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }

        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
    }

    async fn tcp_pair() -> (tokio::net::TcpStream, tokio::net::TcpStream) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (client, accepted) =
            tokio::join!(tokio::net::TcpStream::connect(addr), listener.accept(),);
        (client.unwrap(), accepted.unwrap().0)
    }

    fn test_work_conn_config(
        pool_id: i32,
        xtcp_tx: mpsc::Sender<XtcpNotification>,
        session_alive: Arc<AtomicBool>,
        spawned_counter: Option<Arc<std::sync::atomic::AtomicUsize>>,
    ) -> WorkConnConfig {
        #[cfg(feature = "quic")]
        let quic_conn = None;
        #[cfg(not(feature = "quic"))]
        let quic_conn = ();

        WorkConnConfig {
            server_addr: "127.0.0.1".to_string(),
            server_port: 1,
            protocol: frp_core::transport::TransportProtocol::Tcp,
            run_id: "burst-test-run-id".to_string(),
            proxy_info_map: Arc::new(RwLock::new(HashMap::new())),
            enc_key: [0; 16],
            pool_id,
            auth_cfg: Arc::new(AuthConfig::with_token("test-token")),
            tls_enable: false,
            tls_server_name: String::new(),
            tls_ca_file: None,
            yamux: None,
            quic_conn,
            v2: false,
            oidc_client: None,
            udp_sockets: Arc::new(Mutex::new(HashMap::new())),
            udp_enc_cfg: Arc::new(Mutex::new(HashMap::new())),
            proxy_metrics: Arc::new(frp_core::metrics::ProxyMetricsRegistry::new()),
            client_auth_scopes: Vec::new(),
            server_auth_scopes: Vec::new(),
            disable_custom_tls_first_byte: true,
            keepalive_secs: 0,
            bind_addr: None,
            proxy_url: String::new(),
            user: String::new(),
            dial_timeout_secs: 1,
            xtcp_tx,
            session_alive,
            spawned_counter,
            #[cfg(feature = "vnet")]
            vnet_tuns: Arc::new(Mutex::new(HashMap::new())),
            #[cfg(feature = "vnet")]
            vnet_controller: Arc::new(frp_vnet::controller::ClientVnetController::new()),
            #[cfg(feature = "vnet")]
            vnet_tun_tx: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    #[test]
    fn start_work_conn_timeout_has_one_second_floor() {
        assert_eq!(
            start_work_conn_timeout(0),
            Duration::from_secs(1),
            "disabled/zero dial timeout must not permit an unbounded handshake"
        );
        assert_eq!(start_work_conn_timeout(7), Duration::from_secs(7));
    }

    #[tokio::test]
    async fn silent_start_work_conn_handshake_times_out() {
        let (client, _silent_server) = tcp_pair().await;
        let mut work = IoStream::Tcp(client);

        let err = read_start_work_conn_with_timeout(&mut work, false, Duration::from_millis(20))
            .await
            .unwrap_err();

        assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);
    }

    #[tokio::test]
    async fn burst_of_req_work_conn_spawns_immediately_without_cap() {
        // Go frp v0.70.1 runs each ReqWorkConn handler asynchronously with no
        // client-side in-flight cap. The control loop spawns directly, so a
        // burst larger than the removed 64-inflight limit must all start. The
        // tasks dial 127.0.0.1:1, which fails immediately; the counter proves
        // every task began concurrently rather than waiting on a limiter.
        let started = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let (xtcp_tx, _xtcp_rx) = mpsc::channel(64);
        let session_alive = Arc::new(AtomicBool::new(true));
        let expected = 200;

        for pool_id in 0..expected {
            let cfg = test_work_conn_config(
                pool_id as i32,
                xtcp_tx.clone(),
                session_alive.clone(),
                Some(started.clone()),
            );
            spawn_work_conn(cfg);
        }

        tokio::time::timeout(Duration::from_secs(2), async {
            while started.load(Ordering::SeqCst) < expected {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("all spawned work conn tasks should start immediately");
    }

    #[tokio::test]
    async fn udp_work_reader_eof_cancels_blocked_local_writer() {
        let (work, peer) = tcp_pair().await;
        let socket = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let socket_addr = socket.local_addr().unwrap();
        let retained_socket = socket.clone();
        let session_alive = Arc::new(AtomicBool::new(true));

        let bridge = tokio::spawn(run_udp_work_conn(
            IoStream::Tcp(work),
            socket,
            "udp-test".to_string(),
            "127.0.0.1:9".to_string(),
            [0; 16],
            false,
            false,
            false,
            session_alive,
        ));
        drop(peer);

        tokio::time::timeout(Duration::from_millis(200), bridge)
            .await
            .expect("reader EOF must cancel the sibling blocked on UDP recv")
            .unwrap();

        let sender = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        sender.send_to(b"after-stop", socket_addr).await.unwrap();
        let mut buf = [0; 32];
        let (n, _) = tokio::time::timeout(
            Duration::from_millis(200),
            retained_socket.recv_from(&mut buf),
        )
        .await
        .expect("stopped writer must not consume a later datagram")
        .unwrap();
        assert_eq!(&buf[..n], b"after-stop");
    }

    #[tokio::test]
    async fn udp_work_writer_error_cancels_blocked_work_reader() {
        let socket = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let sender = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let socket_addr = socket.local_addr().unwrap();

        let bridge = tokio::spawn(run_udp_work_conn(
            IoStream::SshChannel(Box::new(FailingWorkStream)),
            socket,
            "udp-test".to_string(),
            "127.0.0.1:9".to_string(),
            [0; 16],
            false,
            false,
            false,
            Arc::new(AtomicBool::new(true)),
        ));
        sender.send_to(b"force-write", socket_addr).await.unwrap();

        tokio::time::timeout(Duration::from_secs(1), bridge)
            .await
            .expect("writer error must cancel the sibling blocked on work read")
            .unwrap();
    }

    #[tokio::test]
    async fn udp_work_forwards_packets_and_preserves_remote_address() {
        let (work, peer) = tcp_pair().await;
        let mut peer = IoStream::Tcp(peer);
        let local = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let socket = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        socket.connect(local.local_addr().unwrap()).await.unwrap();
        let remote = msg::UdpAddr {
            ip: "203.0.113.7".to_string(),
            port: 4242,
            zone: String::new(),
        };
        let bridge = tokio::spawn(run_udp_work_conn(
            IoStream::Tcp(work),
            socket,
            "udp-test".to_string(),
            local.local_addr().unwrap().to_string(),
            [0; 16],
            false,
            false,
            false,
            Arc::new(AtomicBool::new(true)),
        ));

        peer.write_v1_frame(&FrpMessage::UDPPacket(msg::UDPPacket {
            content: b"request".to_vec(),
            local_addr: None,
            remote_addr: Some(remote.clone()),
        }))
        .await
        .unwrap();
        let mut buf = [0u8; 32];
        let (n, proxy_addr) = local.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"request");

        local.send_to(b"response", proxy_addr).await.unwrap();
        let response = peer.read_v1_frame().await.unwrap();
        match response {
            FrpMessage::UDPPacket(packet) => {
                assert_eq!(packet.content, b"response");
                assert_eq!(packet.remote_addr.unwrap().to_string(), remote.to_string());
            }
            other => panic!("expected UDPPacket, got type {}", other.v1_type_byte()),
        }

        drop(peer);
        tokio::time::timeout(Duration::from_secs(1), bridge)
            .await
            .unwrap()
            .unwrap();
    }

    #[cfg(feature = "vnet")]
    #[tokio::test]
    async fn virtual_net_plugin_work_conn_round_trips_packets() {
        use std::net::Ipv4Addr;
        use tokio::io::AsyncWriteExt;

        let controller = Arc::new(frp_vnet::controller::ClientVnetController::new());
        let tun_txs = Arc::new(Mutex::new(HashMap::new()));
        let (tun_tx, mut tun_rx) = mpsc::channel::<Vec<u8>>(16);
        tun_txs
            .lock()
            .await
            .insert("vnet-proxy".to_string(), tun_tx);

        let (work, mut peer) = tokio::io::duplex(4096);
        let task = tokio::spawn(run_virtual_net_plugin_work_conn(
            IoStream::SshChannel(Box::new(work)),
            "vnet-proxy".to_string(),
            controller.clone(),
            tun_txs,
        ));

        let inbound = vec![
            0x45, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x40, 0x06, 0x00, 0x00, 100, 86, 0, 1,
            100, 86, 0, 2,
        ];
        peer.write_all(&inbound).await.unwrap();
        assert_eq!(tun_rx.recv().await, Some(inbound.clone()));

        let src = Ipv4Addr::new(100, 86, 0, 1);
        let return_tx = controller
            .server_conn_sender(&src)
            .await
            .expect("remote source IP must be registered for return traffic");
        return_tx.try_send(inbound.clone()).unwrap();
        let mut buf = vec![0u8; 64];
        let n = peer.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], &inbound[..]);

        drop(peer);
        tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .unwrap()
            .unwrap();
        assert!(controller.server_conn_sender(&src).await.is_none());
    }
}
