#[cfg(feature = "vnet")]
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::{mpsc, oneshot};
use tokio::time::Duration;
use tracing::{debug, info, warn};

use frp_core::msg::{self, FrpMessage};
use frp_core::mux::YamuxSession;
use frp_core::protocol::{
    read_msg_v1, read_msg_v2_with_udp_codec, write_msg_v1, write_msg_v2_with_udp_codec,
};
use frp_core::transport::{
    dial_server, split_work_conn_halves, BoxedReadHalf, BoxedWriteHalf, DialOptions, IoStream,
    TransportProtocol,
};

#[cfg(feature = "vnet")]
type VnetTunTxMap = Arc<std::sync::Mutex<HashMap<String, mpsc::Sender<Vec<u8>>>>>;

/// Configuration for an STCP/XTCP visitor listener.
pub(crate) struct VisitorListenerConfig {
    pub server_addr: String,
    pub server_port: u16,
    pub protocol: TransportProtocol,
    pub server_name: String,
    pub server_user: String,
    pub secret_key: String,
    pub bind_addr: String,
    pub use_encryption: bool,
    pub use_compression: bool,
    pub name: String,
    pub tls_enable: bool,
    pub tls_server_name: String,
    pub tls_ca_file: Option<String>,
    pub visitor_type: String,
    pub fallback_timeout_ms: u64,
    pub keep_tunnel_open: bool,
    pub max_retries_an_hour: i32,
    pub min_retry_interval: i64,
    pub stun_server: String,
    /// XTCP P2P data plane protocol: "kcp" (default) or "quic".
    /// Both data planes are implemented; "kcp" is the default (Go compat
    /// matrix forces kcp), "quic" requires the `quic` feature.
    pub p2p_protocol: String,
    pub visitor_tx: mpsc::Sender<crate::service::VisitorRequest>,
    pub fallback_to: String,
    pub disable_assisted_addrs: bool,
    /// Graceful shutdown signal. When true, the listener stops accepting
    /// new connections and exits. Checked between accept iterations.
    pub shutdown: Arc<AtomicBool>,
    /// Client's user name for proxy_name prefix (Go frp BuildTargetServerProxyName compat).
    pub user: String,
    /// Current session run_id for NewVisitorConn (Go frp compat).
    pub run_id: String,
    // --- Transport options matching DialOptions / Go frp connector ---
    pub tcp_mux: bool,
    pub tcp_mux_keepalive_interval: i64,
    pub proxy_url: Option<String>,
    pub dns_server: Option<String>,
    pub dial_timeout_secs: u64,
    pub keepalive_secs: u64,
    pub connect_bind_addr: Option<String>,
    pub disable_custom_tls_first_byte: bool,
    pub tls_cert_file: Option<String>,
    pub tls_key_file: Option<String>,
    pub v2: bool,
    /// Negotiated UDPPacket codec (`"binary-v1"` or empty) of this frpc's
    /// control session (Go frp v0.71.0). The SUDP visitor data plane uses it
    /// so the visitor segment matches the provider segment's packet codec
    /// when wire protocol v2 is negotiated; empty means JSON framing.
    pub udp_packet_codec: String,
}

/// Configuration for a no-bind `virtual_net` visitor tunnel.
#[cfg(feature = "vnet")]
pub(crate) struct VirtualNetVisitorConfig {
    pub server_addr: String,
    pub server_port: u16,
    pub protocol: TransportProtocol,
    pub server_name: String,
    pub server_user: String,
    pub secret_key: String,
    pub use_encryption: bool,
    pub use_compression: bool,
    pub name: String,
    pub tls_enable: bool,
    pub tls_server_name: String,
    pub tls_ca_file: Option<String>,
    /// Client's user name for proxy_name prefix (Go frp BuildTargetServerProxyName compat).
    pub user: String,
    /// Current session run_id for NewVisitorConn (Go frp compat).
    pub run_id: String,
    /// Host-route CIDR advertised for this visitor (destinationIP/32).
    pub destination_cidr: String,
    /// Shared client-side vnet controller used for route registration and
    /// inbound packet delivery.
    pub controller: Arc<frp_vnet::controller::ClientVnetController>,
    /// TUN delivery channels keyed by proxy name. Tunnel ingress packets are
    /// forwarded into the local TUN-backed vnet proxy so return traffic from
    /// a remote `virtual_net` plugin reaches the local TUN.
    pub vnet_tun_tx: VnetTunTxMap,
    /// Proxy name → subnet CIDR used to direct tunnel ingress packets to the
    /// correct local TUN instead of broadcasting to every TUN.
    pub tun_subnets: Arc<tokio::sync::Mutex<HashMap<String, String>>>,
    /// Graceful shutdown signal. When true, the tunnel exits and the route is
    /// unregistered.
    pub shutdown: Arc<AtomicBool>,
    // --- Transport options matching DialOptions / Go frp connector ---
    pub tcp_mux: bool,
    pub tcp_mux_keepalive_interval: i64,
    pub proxy_url: Option<String>,
    pub dns_server: Option<String>,
    pub dial_timeout_secs: u64,
    pub keepalive_secs: u64,
    pub connect_bind_addr: Option<String>,
    pub disable_custom_tls_first_byte: bool,
    pub tls_cert_file: Option<String>,
    pub tls_key_file: Option<String>,
    pub v2: bool,
}

// ── Visitor dial planning (pure, testable) ────────────────────────────

/// Subset of visitor config fields that influence the dial and yamux
/// decision. Kept as a standalone struct so the dial-planning logic
/// can be exercised in unit tests without a running server.
#[derive(Debug, Clone, PartialEq)]
struct VisitorTransportConfig {
    pub tcp_mux: bool,
    pub tcp_mux_keepalive_interval: i64,
    pub proxy_url: Option<String>,
    pub dns_server: Option<String>,
    pub dial_timeout_secs: u64,
    pub keepalive_secs: u64,
    pub connect_bind_addr: Option<String>,
    pub disable_custom_tls_first_byte: bool,
    pub tls_cert_file: Option<String>,
    pub tls_key_file: Option<String>,
    pub v2: bool,
}

impl VisitorTransportConfig {}

/// Result of visitor dial planning: the DialOptions to pass to
/// dial_server, together with an optional yamux keepalive interval.
/// When `yamux_keepalive_secs` is `Some(n)`, the caller must wrap
/// the raw stream in yamux via `wrap_client_mux(raw, n)`.
#[derive(Debug)]
struct VisitorDialPlan {
    opts: DialOptions,
    yamux_keepalive_secs: Option<i64>,
}

/// Build the DialOptions and yamux decision for a visitor→server
/// connection.  Pure — no I/O, no spawn, no network.  The caller
/// is responsible for calling `dial_server(&plan.opts)` and, when
/// `plan.yamux_keepalive_secs` is `Some(n)`, wrapping the result
/// with `crate::control::wrap_client_mux(raw_stream, n)`.
fn plan_visitor_dial(
    server_addr: &str,
    server_port: u16,
    protocol: &TransportProtocol,
    tls_enable: bool,
    tls_server_name: &str,
    tls_ca_file: &Option<String>,
    transport: &VisitorTransportConfig,
) -> VisitorDialPlan {
    let opts = DialOptions {
        server_addr: server_addr.to_string(),
        server_port,
        protocol: protocol.clone(),
        tls_enable,
        tls_server_name: tls_server_name.to_string(),
        tls_ca_file: tls_ca_file.clone(),
        tls_cert_file: transport.tls_cert_file.clone(),
        tls_key_file: transport.tls_key_file.clone(),
        dns_server: transport.dns_server.clone(),
        disable_custom_tls_first_byte: transport.disable_custom_tls_first_byte,
        keepalive_secs: transport.keepalive_secs,
        bind_addr: transport.connect_bind_addr.clone(),
        proxy_url: transport.proxy_url.clone(),
        dial_timeout_secs: transport.dial_timeout_secs,
        v2: transport.v2,
    };
    let yamux_keepalive_secs = if transport.tcp_mux {
        Some(transport.tcp_mux_keepalive_interval)
    } else {
        None
    };
    VisitorDialPlan {
        opts,
        yamux_keepalive_secs,
    }
}

/// Run the packet loop over an established `virtual_net` visitor tunnel.
///
/// After the NewVisitorConn handshake, tunnel bytes are wrapped in the same
/// compress → encrypt / decrypt → decompress pipeline used by work conns.
#[cfg(feature = "vnet")]
#[allow(clippy::too_many_arguments)]
async fn run_virtual_net_tunnel_io(
    server_conn: IoStream,
    name: String,
    packet_rx: mpsc::Receiver<Vec<u8>>,
    vnet_tun_tx: VnetTunTxMap,
    tun_subnets: Arc<tokio::sync::Mutex<HashMap<String, String>>>,
    shutdown: Arc<AtomicBool>,
    use_encryption: bool,
    use_compression: bool,
    key: [u8; 16],
) {
    let mut packet_rx = packet_rx;
    let (server_r, server_w) = match server_conn.into_split() {
        Ok(parts) => parts,
        Err(e) => {
            warn!(visitor_name = %name, error = %e, "virtual_net visitor tunnel split failed: {}", e);
            return;
        }
    };
    // into_split already returns boxed halves — only the encrypted branch
    // re-boxes (the CipherReader wrapper).
    let server_r: Box<dyn tokio::io::AsyncRead + Unpin + Send> = if use_encryption {
        Box::new(frp_core::cipher_stream::CipherReader::new(server_r, key))
    } else {
        server_r
    };
    let mut packet_reader = crate::work_conn::TunnelPacketReader::new(server_r, use_compression);
    let mut packet_writer = if use_encryption {
        crate::work_conn::TunnelPacketWriter::Encrypted(frp_core::cipher_stream::CipherWriter::new(
            server_w, key,
        ))
    } else {
        crate::work_conn::TunnelPacketWriter::Plain(server_w)
    };
    if let Err(e) = packet_writer.flush().await {
        warn!(visitor_name = %name, error = %e, "virtual_net visitor tunnel IV flush failed: {}", e);
        return;
    }

    let mut tunnel_closed = false;
    while !tunnel_closed {
        tokio::select! {
            _ = wait_for_shutdown_signal(&shutdown) => {
                info!(visitor_name = %name, "virtual_net visitor '{}' shutting down", name);
                break;
            }
            packet = packet_rx.recv() => {
                match packet {
                    Some(pkt) => {
                        if let Err(e) = packet_writer.write_packet(&pkt, use_compression).await {
                            warn!(visitor_name = %name, error = %e, "virtual_net visitor '{}': tunnel write error: {}", name, e);
                            tunnel_closed = true;
                        }
                    }
                    None => {
                        debug!(visitor_name = %name, "virtual_net visitor packet channel closed");
                        tunnel_closed = true;
                    }
                }
            }
            packet = packet_reader.next_packet() => {
                match packet {
                    Ok(None) => {
                        debug!(visitor_name = %name, "virtual_net visitor tunnel closed by peer");
                        tunnel_closed = true;
                    }
                    Ok(Some(pkt)) => {
                        if !deliver_tunnel_ingress(&name, pkt, &vnet_tun_tx, &tun_subnets).await {
                            debug!(visitor_name = %name, "virtual_net visitor tunnel ingress bytes have no TUN target");
                        }
                    }
                    Err(e) => {
                        warn!(visitor_name = %name, error = %e, "virtual_net visitor '{}': tunnel read error: {}", name, e);
                        tunnel_closed = true;
                    }
                }
            }
        }
    }
}

/// Run an STCP/XTCP visitor listener.
/// Binds a local port, accepts connections, and tunnels them
/// through the frps server to the remote STCP proxy.
pub(crate) async fn run_visitor_listener(config: VisitorListenerConfig) {
    // SUDP visitors use a dedicated UDP-based lazy tunnel (Go frp
    // client/visitor/sudp.go). Route them to their own listener before the
    // TCP accept loop, so they never fall into the STCP TCP path.
    if config.visitor_type == "sudp" {
        return run_sudp_visitor_listener(config).await;
    }
    let VisitorListenerConfig {
        server_addr,
        server_port,
        protocol,
        server_name,
        server_user,
        secret_key,
        bind_addr,
        use_encryption,
        use_compression,
        name,
        tls_enable,
        tls_server_name,
        tls_ca_file,
        visitor_type,
        fallback_timeout_ms,
        keep_tunnel_open,
        max_retries_an_hour,
        min_retry_interval,
        stun_server,
        p2p_protocol,
        visitor_tx,
        fallback_to,
        disable_assisted_addrs,
        shutdown,
        user,
        run_id,
        tcp_mux,
        tcp_mux_keepalive_interval,
        proxy_url,
        dns_server,
        dial_timeout_secs,
        keepalive_secs,
        connect_bind_addr,
        disable_custom_tls_first_byte,
        tls_cert_file,
        tls_key_file,
        v2,
        // SUDP-only: the STCP TCP accept path ignores the negotiated
        // UDPPacket codec.
        udp_packet_codec: _,
    } = config;
    let listener = match tokio::net::TcpListener::bind(&bind_addr).await {
        Ok(l) => l,
        Err(e) => {
            warn!(name = %name, bind_addr = %bind_addr, error = %e, "Visitor '{}': bind {} failed: {}", name, bind_addr, e);
            return;
        }
    };
    info!(name = %name, bind_addr = %bind_addr, "Visitor '{}' listening on {}", name, bind_addr);

    loop {
        // Check graceful shutdown signal before each accept (Go frp compat:
        // visitor listeners exit cleanly instead of being aborted).
        if shutdown.load(Ordering::Relaxed) {
            info!(name = %name, "Visitor '{}' shutting down gracefully", name);
            return;
        }

        match listener.accept().await {
            Ok((user_conn, peer)) => {
                frp_core::transport::set_nodelay(&user_conn);
                debug!(name = %name, peer = %peer, "Visitor '{}': user connection from {}", name, peer);

                let sa = server_addr.clone();
                let sp = server_port;
                let pt = protocol.clone();
                let sn = server_name.clone();
                let su = server_user.clone();
                let sk = secret_key.clone();
                let visitor_name = name.clone();
                let tls_sn = tls_server_name.clone();
                let tls_ca = tls_ca_file.clone();
                let vt = visitor_type.clone();
                let stun_server = stun_server.clone();
                let vtx = visitor_tx.clone();
                let fb_to = fallback_to.clone();
                let daa = disable_assisted_addrs;
                let pp = p2p_protocol.clone();
                let u = user.clone();
                let rid = run_id.clone();
                let transport = VisitorTransportConfig {
                    tcp_mux,
                    tcp_mux_keepalive_interval,
                    proxy_url: proxy_url.clone(),
                    dns_server: dns_server.clone(),
                    dial_timeout_secs,
                    keepalive_secs,
                    connect_bind_addr: connect_bind_addr.clone(),
                    disable_custom_tls_first_byte,
                    tls_cert_file: tls_cert_file.clone(),
                    tls_key_file: tls_key_file.clone(),
                    v2,
                };

                tokio::spawn(async move {
                    // Dial options for STCP fallback (fresh connections only).
                    let plan =
                        plan_visitor_dial(&sa, sp, &pt, tls_enable, &tls_sn, &tls_ca, &transport);
                    let opts = plan.opts;
                    let yamux_keepalive = plan.yamux_keepalive_secs;

                    if vt == "xtcp" {
                        // --- XTCP NAT hole punch via control connection ---
                        // Go frps v0.69.1 only handles NatHoleVisitor on the existing
                        // control connection path, not on fresh TCP connections.
                        // We send the message through the control loop and receive the
                        // NatHoleResp via a oneshot channel.
                        // When keep_tunnel_open is false, still retry once (2 total attempts).
                        // TCP simultaneous open timing is finicky — a second attempt with fresh
                        // STUN addresses often succeeds even when the first times out.
                        // When keep_tunnel_open is true, use the configured retry count/delay.
                        let max_retries = if keep_tunnel_open {
                            max_retries_an_hour.max(0) as usize
                        } else {
                            1 // 2 total attempts
                        };
                        let retry_delay = if keep_tunnel_open {
                            Duration::from_secs(min_retry_interval.max(1) as u64)
                        } else {
                            Duration::from_secs(2) // Quick retry for one-shot mode
                        };
                        let mut hole_punch_ok = false;
                        // Wrap in Option — P2P success arm moves it out via take().
                        let mut user_conn = Some(user_conn);

                        // --- PreCheck: validate proxy existence/permissions before STUN ---
                        // Go frp two-phase approach: first send pre_check=true to validate
                        // auth/permissions, THEN do STUN + full request. Skipping this
                        // wastes STUN calls on auth/proxy-not-found failures.
                        {
                            let (reply_tx, reply_rx) = oneshot::channel();
                            let ts = std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .unwrap_or_default()
                                .as_millis() as i64;
                            let sign_key = if sk.is_empty() {
                                None
                            } else {
                                Some(frp_core::auth::generate_token(&sk, ts))
                            };
                            let pre_check_req = crate::service::VisitorRequest {
                                nhv: msg::NatHoleVisitor {
                                    transaction_id: uuid::Uuid::new_v4().to_string(),
                                    proxy_name: sn.clone(),
                                    pre_check: true,
                                    protocol: Some(pp.to_string()),
                                    sign_key,
                                    timestamp: Some(ts),
                                    mapped_addrs: None,
                                    assisted_addrs: None,
                                },
                                reply: reply_tx,
                            };
                            if vtx.try_send(pre_check_req).is_err() {
                                warn!(visitor_name = %visitor_name, "Visitor '{}': failed to send pre_check to control loop (channel closed)", visitor_name);
                                return;
                            }
                            debug!(visitor_name = %visitor_name, sn = %sn, "Visitor '{}': sent NatHoleVisitor pre_check for '{}'", visitor_name, sn);

                            match tokio::time::timeout(Duration::from_secs(1), reply_rx).await {
                                Ok(Ok(Ok(resp))) => {
                                    if let Some(err) = resp.error {
                                        warn!(visitor_name = %visitor_name, error = %err, "Visitor '{}': pre_check failed: {}", visitor_name, err);
                                        return;
                                    }
                                    debug!(visitor_name = %visitor_name, sn = %sn, "Visitor '{}': pre_check OK for '{}'", visitor_name, sn);
                                }
                                Ok(Ok(Err(e))) => {
                                    warn!(visitor_name = %visitor_name, error = %e, "Visitor '{}': pre_check error: {}", visitor_name, e);
                                    return;
                                }
                                Ok(Err(_)) => {
                                    warn!(visitor_name = %visitor_name, "Visitor '{}': pre_check channel closed (control loop dropped)", visitor_name);
                                    return;
                                }
                                Err(_elapsed) => {
                                    // Timeout on pre_check: server may not support
                                    // pre_check on control channel. Proceed with
                                    // full request anyway (graceful degradation).
                                    // Short timeout — 15s per connection stalled
                                    // every XTCP connect against servers that
                                    // ignore pre_check.
                                    warn!(visitor_name = %visitor_name, "Visitor '{}': pre_check timed out after 1s, proceeding with full request", visitor_name);
                                }
                            }
                        }

                        for attempt in 0..=max_retries {
                            if attempt > 0 {
                                debug!(
                                    visitor_name = %visitor_name, attempt = %attempt, max_retries = %max_retries, retry_delay = ?retry_delay,
                                    "Visitor '{}': XTCP retry {}/{} after {:?}",
                                    visitor_name, attempt, max_retries, retry_delay
                                );
                                tokio::time::sleep(retry_delay).await;
                            }

                            // --- STUN Discovery (UDP socket for XTCP P2P) ---
                            // Go frp v0.70 NAT classifier needs ≥2 mapped
                            // addresses. Reuse the same UDP socket for both
                            // STUN calls and subsequent KCP data plane.
                            //
                            // First STUN: get mapped address + optional OTHER-ADDRESS
                            // (RFC 5780). If OTHER-ADDRESS is present, use it for the
                            // second STUN request (Go frp discovery.go:137-138 dual-server
                            // NAT probing). Otherwise fall back to the same stun_server.
                            let (stun_socket, mapped_addrs, assisted_addrs) =
                                match frp_core::stun::stun_binding_with_details(&stun_server).await
                                {
                                    Ok((sock, result1)) => {
                                        let addr1 = result1.mapped_addr;
                                        debug!(visitor_name = %visitor_name, addr = %addr1, "Visitor '{}': STUN #1: {}", visitor_name, addr1);
                                        let mut addrs = vec![addr1];

                                        // Use OTHER-ADDRESS as second STUN target if available
                                        // (Go frp discovery.go:137 dual-server probing).
                                        let second_target =
                                            result1.other_addr.as_deref().unwrap_or(&stun_server);
                                        match frp_core::stun::stun_binding_on_socket(
                                            &sock,
                                            second_target,
                                        )
                                        .await
                                        {
                                            Ok(addr2) => {
                                                debug!(visitor_name = %visitor_name, addr = %addr2, "Visitor '{}': STUN #2 from '{}': {}", visitor_name, second_target, addr2);
                                                // Go frp NAT classifier needs ≥2 addresses.
                                                // Always push — Go frp doesn't dedup, and
                                                // fewer than 2 causes "not enough addresses".
                                                addrs.push(addr2);
                                            }
                                            Err(e) => {
                                                warn!(visitor_name = %visitor_name, error = %e, "Visitor '{}': STUN #2 failed: {}", visitor_name, e);
                                            }
                                        }

                                        // Build assisted addresses from local IPs + STUN socket port
                                        // (Go frp nathole.go:143-150 ListLocalIPsForNatHole).
                                        let assisted = if daa {
                                            vec![]
                                        } else {
                                            let stun_port = sock
                                                .local_addr()
                                                .ok()
                                                .map(|a| a.port())
                                                .unwrap_or(0);
                                            let local_ips = list_local_ips();
                                            debug!(
                                                visitor_name = %visitor_name, local_ips = ?local_ips, port = %stun_port,
                                                "Visitor '{}': building assisted_addrs from {} local IPs port {}",
                                                visitor_name, local_ips.len(), stun_port
                                            );
                                            local_ips
                                                .into_iter()
                                                .map(|ip| format!("{}:{}", ip, stun_port))
                                                .collect()
                                        };
                                        (Some(sock), addrs, assisted)
                                    }
                                    Err(e) => {
                                        warn!(visitor_name = %visitor_name, error = %e, "Visitor '{}': STUN failed: {}", visitor_name, e);
                                        (None, vec![], vec![])
                                    }
                                };

                            // --- Send NatHoleVisitor on control connection ---
                            let txn_id = uuid::Uuid::new_v4().to_string();
                            // Generate auth credentials (Go frps v0.69.1 requires sign_key+timestamp)
                            let ts = std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .unwrap_or_default()
                                .as_millis() as i64;
                            let sign_key = if sk.is_empty() {
                                None
                            } else {
                                Some(frp_core::auth::generate_token(&sk, ts))
                            };
                            let (reply_tx, reply_rx) = oneshot::channel();
                            // Go v0.70 compat: XTCP P2P uses KCP over UDP.
                            let nhv = crate::service::VisitorRequest {
                                nhv: msg::NatHoleVisitor {
                                    transaction_id: txn_id.clone(),
                                    proxy_name: sn.clone(),
                                    pre_check: false,
                                    protocol: Some(pp.to_string()),
                                    sign_key,
                                    timestamp: Some(ts),
                                    mapped_addrs: if mapped_addrs.is_empty() {
                                        None
                                    } else {
                                        Some(mapped_addrs.clone())
                                    },
                                    assisted_addrs: if assisted_addrs.is_empty() {
                                        None
                                    } else {
                                        Some(assisted_addrs)
                                    },
                                },
                                reply: reply_tx,
                            };
                            if vtx.try_send(nhv).is_err() {
                                warn!(visitor_name = %visitor_name, "Visitor '{}': failed to send NatHoleVisitor to control loop (channel closed)", visitor_name);
                                return;
                            }
                            debug!(visitor_name = %visitor_name, sn = %sn, "Visitor '{}': sent NatHoleVisitor on control connection for '{}'", visitor_name, sn);

                            // --- Wait for NatHoleResp from control loop ---
                            // Timeout after 15s (server NAT_HOLE_TIMEOUT is 10s)
                            let resp = match tokio::time::timeout(Duration::from_secs(15), reply_rx)
                                .await
                            {
                                Ok(Ok(Ok(resp))) => resp,
                                Ok(Ok(Err(e))) => {
                                    warn!(visitor_name = %visitor_name, error = %e, "Visitor '{}': NatHoleResp error from server: {}", visitor_name, e);
                                    if keep_tunnel_open && attempt < max_retries {
                                        continue;
                                    }
                                    return;
                                }
                                Ok(Err(_)) => {
                                    warn!(visitor_name = %visitor_name, "Visitor '{}': NatHoleResp channel closed (control loop dropped)", visitor_name);
                                    if keep_tunnel_open && attempt < max_retries {
                                        continue;
                                    }
                                    return;
                                }
                                Err(_elapsed) => {
                                    warn!(visitor_name = %visitor_name, "Visitor '{}': NatHoleResp timed out after 15s", visitor_name);
                                    if keep_tunnel_open && attempt < max_retries {
                                        continue;
                                    }
                                    return;
                                }
                            };
                            debug!(visitor_name = %visitor_name, "Visitor '{}': received NatHoleResp from server", visitor_name);

                            let candidates = resp.candidate_addrs.unwrap_or_default();
                            debug!(visitor_name = %visitor_name, candidate_count = %candidates.len(), "Visitor '{}': got {} candidate addresses from server", visitor_name, candidates.len());

                            // UDP hole punch + KCP data plane (Go v0.70 compat).
                            // Uses the STUN socket to punch a hole and create
                            // a KCP stream over UDP.
                            if let Some(socket) = stun_socket {
                                // Derive shared KCP conv from the NAT session ID
                                // (both sides get the same sid from the server).
                                let sid = resp.sid.clone().unwrap_or_default();
                                let conv = frp_core::xtcp_p2p::conv_from_sid(&sid);
                                let kcp_cfg = frp_core::kcp::default_kcp_config();
                                // Go v0.70 compat: NatHoleSid detect + yamux client.
                                let p2p_key = if !sk.is_empty() {
                                    Some(frp_core::xtcp_p2p::derive_detect_key(&sk))
                                } else {
                                    None
                                };
                                let p2p_sid = if sid.is_empty() {
                                    None
                                } else {
                                    Some(sid.as_str())
                                };
                                // Use read_timeout_ms from server's detect_behavior as
                                // the hole-punch timeout (Go frp v0.70.1 compat).
                                // Keep fallback_timeout_ms as the outer STCP fallback
                                // deadline (retry loop).
                                let hp_timeout = resp
                                    .detect_behavior
                                    .as_ref()
                                    .map(|db| db.read_timeout_ms.max(0) as u64)
                                    .unwrap_or(fallback_timeout_ms);
                                let assisted = resp.assisted_addrs.clone().unwrap_or_default();
                                let behavior = resp.detect_behavior.clone();
                                // Data-plane dispatch: the configured
                                // `p2p_protocol` ("kcp" default, "quic" for the
                                // QUIC data plane, Go v0.70.1 compat) selects the
                                // transport. The visitor is the QUIC client /
                                // yamux client (opens the stream).
                                let p2p_stream: Result<
                                    Box<dyn frp_core::xtcp_p2p::P2pStream>,
                                    String,
                                > = if pp.as_str() == "quic" {
                                    #[cfg(all(feature = "quic", feature = "kcp"))]
                                    {
                                        match frp_core::xtcp_p2p::xtcp_p2p_connect_quic(
                                            socket,
                                            &candidates,
                                            &assisted,
                                            behavior.as_ref(),
                                            hp_timeout,
                                            p2p_sid,
                                            p2p_key.as_ref(),
                                            false, // is_server = false (visitor is QUIC client)
                                        )
                                        .await
                                        {
                                            Ok(s) => Ok(Box::new(s) as Box<_>),
                                            Err(e) => Err(e),
                                        }
                                    }
                                    #[cfg(not(all(feature = "quic", feature = "kcp")))]
                                    {
                                        warn!(visitor_name = %visitor_name, "Visitor '{}': protocol 'quic' requires both the quic and kcp features (the QUIC data plane reuses the KCP hole-punch machinery); refusing to silently fall back to KCP (Go peers may be on a QUIC data plane)", visitor_name);
                                        Err(format!(
                                            "Visitor '{}': protocol 'quic' requires both the quic and kcp features",
                                            visitor_name
                                        ))
                                    }
                                } else {
                                    match frp_core::xtcp_p2p::xtcp_p2p_connect_yamux(
                                        socket,
                                        &candidates,
                                        &assisted,
                                        behavior.as_ref(),
                                        conv,
                                        kcp_cfg,
                                        hp_timeout,
                                        true, // yamux_client = visitor
                                        p2p_sid,
                                        p2p_key.as_ref(),
                                    )
                                    .await
                                    {
                                        Ok(s) => Ok(Box::new(s) as Box<_>),
                                        Err(e) => Err(e),
                                    }
                                };
                                match p2p_stream {
                                    Ok(mut p2p_stream) => {
                                        info!(visitor_name = %visitor_name, "Visitor '{}': XTCP P2P connected", visitor_name);
                                        let use_enc = use_encryption && !sk.is_empty();
                                        let (user_r, user_w) = user_conn
                                            .take()
                                            .expect("user_conn set Some above, not yet consumed")
                                            .into_split();
                                        let (p2p_r, p2p_w) = tokio::io::split(&mut p2p_stream);
                                        if use_enc {
                                            let key = frp_core::encryption::derive_key(&sk);
                                            frp_core::bridge::bridge_encrypted(
                                                user_r,
                                                user_w,
                                                p2p_r,
                                                p2p_w,
                                                &key,
                                                use_compression,
                                                vec![],
                                                None,
                                                None,
                                                None,
                                                None,
                                            )
                                            .await;
                                            debug!(visitor_name = %visitor_name, "Visitor '{}' XTCP encrypted P2P closed", visitor_name);
                                        } else {
                                            frp_core::bridge::bridge_plain(
                                                user_r,
                                                user_w,
                                                p2p_r,
                                                p2p_w,
                                                use_compression,
                                                vec![],
                                                None,
                                                None,
                                            )
                                            .await;
                                            debug!(visitor_name = %visitor_name, "Visitor '{}' XTCP closed", visitor_name);
                                        }
                                        hole_punch_ok = true;
                                    }
                                    Err(e) => {
                                        debug!(visitor_name = %visitor_name, error = %e, "Visitor '{}': UDP hole punch + data plane connect failed: {}", visitor_name, e);
                                    }
                                }
                            } else {
                                warn!(visitor_name = %visitor_name, "Visitor '{}': no STUN socket for XTCP P2P", visitor_name);
                            }
                            if hole_punch_ok {
                                break; // Exit retry loop
                            }
                        }

                        if hole_punch_ok {
                            return; // XTCP P2P succeeded
                        }

                        // Unwrap user_conn for STCP fallback (hole punch failed, so not moved).
                        let Some(user_conn) = user_conn else {
                            warn!(visitor_name = %visitor_name, "Visitor '{}': user_conn missing in XTCP fallback path", visitor_name);
                            return;
                        };

                        // --- STCP fallback (hole punch failed) ---
                        // STCP relay via NewVisitorConn on a fresh connection works against
                        // Rust frps (which looks up the proxy in proxy_manager regardless of type).
                        // Against Go frps v0.69.1, XTCP proxies do NOT create a custom listener
                        // (only NatHoleController listener), so NewVisitorConn fails with
                        // "custom listener for [X] doesn't exist". This is expected — Go frp's
                        // XTCP fallback uses a separate STCP proxy+visitor, not the same proxy.
                        // Open a NEW connection for STCP relay
                        let raw_stream = match dial_server(&opts).await {
                            Ok(io) => io,
                            Err(e) => {
                                debug!(visitor_name = %visitor_name, error = %e, "Visitor '{}': STCP fallback dial failed: {}", visitor_name, e);
                                return;
                            }
                        };
                        // Wrap in yamux when tcp_mux is enabled (Go frp compat).
                        let mut _yamux_sess_fb: Option<YamuxSession> = None;
                        let mut server_conn = if let Some(ka) = yamux_keepalive {
                            match crate::control::wrap_client_mux(raw_stream, ka).await {
                                Ok((io, session)) => {
                                    _yamux_sess_fb = session;
                                    io
                                }
                                Err(e) => {
                                    warn!(visitor_name = %visitor_name, error = %e, "Visitor '{}': yamux wrap failed: {}", visitor_name, e);
                                    return;
                                }
                            }
                        } else {
                            raw_stream
                        };

                        let stcp_proxy_name = if fb_to.is_empty() {
                            sn.clone()
                        } else {
                            fb_to.clone()
                        };
                        // Apply the visitor's own encryption/compression config to the
                        // STCP fallback bridge. Go frp semantics: `fallbackTo` routes to
                        // a SEPARATE STCP visitor with its own encryption config, but we
                        // don't have access to that separate config here. Using the XTCP
                        // visitor's encryption/compression is a pragmatic approximation
                        // that is strictly better than the previous always-plain behavior.
                        let nvc = crate::proxy::create_visitor_conn_msg(
                            &stcp_proxy_name,
                            &sk,
                            use_encryption,
                            use_compression,
                            Some(su.as_str()).filter(|s| !s.is_empty()),
                            Some(u.as_str()).filter(|s| !s.is_empty()),
                            Some(rid.as_str()).filter(|s| !s.is_empty()),
                        );
                        debug!(visitor_name = %visitor_name, "NewVisitorConn message prepared");
                        if let Err(e) = server_conn.write_v1_frame(&nvc).await {
                            warn!(visitor_name = %visitor_name, error = %e, "Visitor '{}': STCP fallback send NewVisitorConn failed: {}", visitor_name, e);
                            return;
                        }
                        info!(visitor_name = %visitor_name, stcp_proxy_name = %stcp_proxy_name, "Visitor '{}': fell back to STCP relay for '{}'", visitor_name, stcp_proxy_name);

                        // Read NewVisitorConnResp before bridging. Bound the
                        // wait: a server that accepts the dial but never answers
                        // must not pin this task (and its user connection) for
                        // the lifetime of the tunnel — mirrors
                        // read_start_work_conn_with_timeout (work_conn.rs).
                        let resp_timeout = Duration::from_secs(transport.dial_timeout_secs.max(1));
                        match tokio::time::timeout(resp_timeout, server_conn.read_v1_frame()).await
                        {
                            Ok(Ok(FrpMessage::NewVisitorConnResp(resp))) => {
                                if let Some(err) = resp.error {
                                    warn!(visitor_name = %visitor_name, error = %err, "Visitor '{}': STCP server error: {}", visitor_name, err);
                                    return;
                                }
                                debug!(visitor_name = %visitor_name, proxy_name = %resp.proxy_name, "Visitor '{}': STCP relay ready for '{}'", visitor_name, resp.proxy_name);
                            }
                            Ok(Ok(other)) => {
                                warn!(visitor_name = %visitor_name, type_byte = %other.v1_type_byte(), "Visitor received unexpected response type");
                                return;
                            }
                            Ok(Err(e)) => {
                                warn!(visitor_name = %visitor_name, error = %e, "Visitor '{}': read NewVisitorConnResp failed: {}", visitor_name, e);
                                return;
                            }
                            Err(_elapsed) => {
                                warn!(visitor_name = %visitor_name, timeout = ?resp_timeout, "Visitor '{}': timed out waiting for NewVisitorConnResp", visitor_name);
                                return;
                            }
                        }

                        let user = user_conn;
                        let (user_r, user_w) = user.into_split();
                        let (srv_r, srv_w) = match split_work_conn_halves(server_conn) {
                            Ok(pair) => pair,
                            Err(e) => {
                                warn!(visitor_name = %visitor_name, error = e, "Visitor '{}': STCP relay could not split server conn: {}", visitor_name, e);
                                return;
                            }
                        };
                        let use_enc_relay = use_encryption && !sk.is_empty();
                        if use_enc_relay {
                            let key = frp_core::encryption::derive_key(&sk);
                            frp_core::bridge::bridge_encrypted(
                                user_r,
                                user_w,
                                srv_r,
                                srv_w,
                                &key,
                                use_compression,
                                vec![],
                                None,
                                None,
                                None,
                                None,
                            )
                            .await;
                            debug!(visitor_name = %visitor_name, "Visitor '{}' STCP fallback encrypted relay closed", visitor_name);
                        } else {
                            frp_core::bridge::bridge_plain(
                                user_r,
                                user_w,
                                srv_r,
                                srv_w,
                                use_compression,
                                vec![],
                                None,
                                None,
                            )
                            .await;
                            debug!(visitor_name = %visitor_name, "Visitor '{}' STCP fallback relay closed", visitor_name);
                        }
                    } else {
                        // --- STCP relay path (TCP-based visitors) ---
                        // Handles: stcp. SUDP is routed to the dedicated UDP
                        // visitor (run_sudp_visitor_listener) before the accept
                        // loop, so it never reaches this TCP path.
                        let raw_stream = match dial_server(&opts).await {
                            Ok(io) => io,
                            Err(e) => {
                                warn!(visitor_name = %visitor_name, error = %e, "Visitor '{}': dial server failed: {}", visitor_name, e);
                                return;
                            }
                        };
                        // Wrap in yamux when tcp_mux is enabled (Go frp compat).
                        let mut _yamux_sess_stcp: Option<YamuxSession> = None;
                        let mut server_conn = if let Some(ka) = yamux_keepalive {
                            match crate::control::wrap_client_mux(raw_stream, ka).await {
                                Ok((io, session)) => {
                                    _yamux_sess_stcp = session;
                                    io
                                }
                                Err(e) => {
                                    warn!(visitor_name = %visitor_name, error = %e, "Visitor '{}': yamux wrap failed: {}", visitor_name, e);
                                    return;
                                }
                            }
                        } else {
                            raw_stream
                        };

                        let nvc = crate::proxy::create_visitor_conn_msg(
                            &sn,
                            &sk,
                            use_encryption,
                            use_compression,
                            Some(su.as_str()).filter(|s| !s.is_empty()),
                            Some(u.as_str()).filter(|s| !s.is_empty()),
                            Some(rid.as_str()).filter(|s| !s.is_empty()),
                        );
                        debug!(visitor_name = %visitor_name, "NewVisitorConn message prepared");
                        if let Err(e) = server_conn.write_v1_frame(&nvc).await {
                            warn!(visitor_name = %visitor_name, error = %e, "Visitor '{}': send NewVisitorConn failed: {}", visitor_name, e);
                            return;
                        }
                        debug!(visitor_name = %visitor_name, sn = %sn, "Visitor '{}': sent NewVisitorConn for '{}'", visitor_name, sn);

                        // Read NewVisitorConnResp before bridging. Bound the
                        // wait: a server that accepts the dial but never answers
                        // must not pin this task (and its user connection) for
                        // the lifetime of the tunnel — mirrors
                        // read_start_work_conn_with_timeout (work_conn.rs).
                        let resp_timeout = Duration::from_secs(transport.dial_timeout_secs.max(1));
                        match tokio::time::timeout(resp_timeout, server_conn.read_v1_frame()).await
                        {
                            Ok(Ok(FrpMessage::NewVisitorConnResp(resp))) => {
                                if let Some(err) = resp.error {
                                    warn!(visitor_name = %visitor_name, error = %err, "Visitor '{}': STCP server error: {}", visitor_name, err);
                                    return;
                                }
                                debug!(visitor_name = %visitor_name, proxy_name = %resp.proxy_name, "Visitor '{}': STCP relay ready for '{}'", visitor_name, resp.proxy_name);
                            }
                            Ok(Ok(other)) => {
                                warn!(visitor_name = %visitor_name, type_byte = %other.v1_type_byte(), "Visitor received unexpected response type");
                                return;
                            }
                            Ok(Err(e)) => {
                                warn!(visitor_name = %visitor_name, error = %e, "Visitor '{}': read NewVisitorConnResp failed: {}", visitor_name, e);
                                return;
                            }
                            Err(_elapsed) => {
                                warn!(visitor_name = %visitor_name, timeout = ?resp_timeout, "Visitor '{}': timed out waiting for NewVisitorConnResp", visitor_name);
                                return;
                            }
                        }

                        let user = user_conn;
                        let (user_r, user_w) = user.into_split();
                        let (srv_r, srv_w) = match split_work_conn_halves(server_conn) {
                            Ok(pair) => pair,
                            Err(e) => {
                                warn!(visitor_name = %visitor_name, error = e, "Visitor '{}': STCP relay could not split server conn: {}", visitor_name, e);
                                return;
                            }
                        };
                        let use_enc_relay = use_encryption && !sk.is_empty();
                        if use_enc_relay {
                            let key = frp_core::encryption::derive_key(&sk);
                            frp_core::bridge::bridge_encrypted(
                                user_r,
                                user_w,
                                srv_r,
                                srv_w,
                                &key,
                                use_compression,
                                vec![],
                                None,
                                None,
                                None,
                                None,
                            )
                            .await;
                            debug!(visitor_name = %visitor_name, "Visitor '{}' STCP encrypted relay closed", visitor_name);
                        } else {
                            frp_core::bridge::bridge_plain(
                                user_r,
                                user_w,
                                srv_r,
                                srv_w,
                                use_compression,
                                vec![],
                                None,
                                None,
                            )
                            .await;
                            debug!(visitor_name = %visitor_name, "Visitor '{}' STCP relay closed", visitor_name);
                        }
                    }
                });
            }
            Err(e) => {
                warn!(name = %name, error = %e, "Visitor '{}': accept error: {}", name, e);
                break;
            }
        }
    }
}

/// Run a SUDP visitor listener.
///
/// Binds a local UDP socket and tunnels datagrams to a remote SUDP proxy
/// through the frps server, mirroring Go frp's `client/visitor/sudp.go`:
/// - one shared UDP socket, multiplexed by datagram source address: inbound
///   datagrams are answered back to their `UdpAddr` source, outbound
///   datagrams carry their own source address in `UDPPacket.remote_addr`
/// - lazy connection: no server connection is held until the first datagram
///   arrives; the first datagram triggers a fresh NewVisitorConn handshake
/// - on disconnect/idle timeout the worker returns to the wait state and the
///   next datagram reconnects
///
/// ENCRYPTION/COMPRESSION: the SUDP data plane uses the Go-frp three-segment
/// model — the visitor segment (visitor frpc ↔ frps) is encrypted with
/// `derive_key(sk)` and compressed with a Snappy stream (SnappyStream +
/// CipherReader/CipherWriter around the conn in `run_sudp_worker`, symmetric
/// with the server's `split_user_side`, snappy inner / CFB outer), the
/// provider segment (frps ↔ provider frpc) with `derive_key(auth token)`.
pub(crate) async fn run_sudp_visitor_listener(config: VisitorListenerConfig) {
    let VisitorListenerConfig {
        server_addr,
        server_port,
        protocol,
        server_name,
        server_user,
        secret_key,
        bind_addr,
        use_encryption,
        use_compression,
        name,
        tls_enable,
        tls_server_name,
        tls_ca_file,
        // SUDP has no retry / NAT-traversal / fallback options; all unused.
        visitor_type: _,
        fallback_timeout_ms: _,
        keep_tunnel_open: _,
        max_retries_an_hour: _,
        min_retry_interval: _,
        stun_server: _,
        p2p_protocol: _,
        visitor_tx: _,
        fallback_to: _,
        disable_assisted_addrs: _,
        shutdown,
        user,
        run_id,
        tcp_mux,
        tcp_mux_keepalive_interval,
        proxy_url,
        dns_server,
        dial_timeout_secs,
        keepalive_secs,
        connect_bind_addr,
        disable_custom_tls_first_byte,
        tls_cert_file,
        tls_key_file,
        v2,
        udp_packet_codec,
    } = config;

    // Go frp v0.70.1 three-stage model: the visitor segment is encrypted
    // with `derive_key(sk)` when the visitor declares use_encryption and
    // compressed with a Snappy stream when it declares use_compression. The
    // server (bridge.rs `split_user_side`) wraps its user-side connection
    // with the same key / Snappy layer, and we wrap the data-plane stream in
    // `run_sudp_worker` — the NewVisitorConn declaration and both ends of the
    // visitor segment now agree (snappy inner, CFB outer, Go parity).

    let socket = match tokio::net::UdpSocket::bind(&bind_addr).await {
        Ok(s) => Arc::new(s),
        Err(e) => {
            warn!(visitor_name = %name, bind_addr = %bind_addr, error = %e, "SUDP visitor '{}': bind {} failed: {}", name, bind_addr, e);
            return;
        }
    };
    let bound = socket
        .local_addr()
        .unwrap_or_else(|_| "0.0.0.0:0".parse().unwrap());
    info!(visitor_name = %name, local_addr = %bound, "SUDP visitor '{}' listening on {} (lazy tunnel: no server connection until first datagram)", name, bound);

    // Go sudp.go uses capacity-1024 channels for both directions.
    let (send_tx, mut send_rx) = mpsc::channel::<msg::UDPPacket>(1024);
    let (read_tx, mut read_rx) = mpsc::channel::<msg::UDPPacket>(1024);

    // --- Reader loop: tunnel → local UDP clients ---
    // Datagrams coming back through the tunnel carry the originating local
    // client address in UDPPacket.remote_addr; send them back to it.
    // The reader/listener tasks exit on their own once the shutdown flag is
    // set or the channels close (their senders are dropped when the dispatcher
    // returns), so the JoinHandles are intentionally not joined.
    let _reader_task = {
        let socket_r = socket.clone();
        let shutdown_r = shutdown.clone();
        let name_r = name.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    biased;
                    _ = wait_sudp_shutdown(&shutdown_r) => {
                        info!(visitor_name = %name_r, "SUDP visitor '{}' reader shutting down", name_r);
                        break;
                    }
                    pkt = read_rx.recv() => {
                        match pkt {
                            Some(up) => {
                                if let Some(ref ra) = up.remote_addr {
                                    if let Ok(addr) = format!("{}:{}", ra.ip, ra.port).parse::<std::net::SocketAddr>() {
                                        if let Err(e) = socket_r.send_to(&up.content, addr).await {
                                            debug!(visitor_name = %name_r, remote = %addr, error = %e, "SUDP visitor '{}': send_to local client {} failed: {}", name_r, addr, e);
                                        }
                                    } else {
                                        warn!(visitor_name = %name_r, ip = %ra.ip, port = ra.port, "SUDP visitor '{}': unparseable remote address, dropping packet", name_r);
                                    }
                                } else {
                                    warn!(visitor_name = %name_r, "SUDP visitor '{}': UDPPacket without remote_addr, dropping", name_r);
                                }
                            }
                            None => {
                                debug!(visitor_name = %name_r, "SUDP visitor '{}' read channel closed", name_r);
                                break;
                            }
                        }
                    }
                }
            }
        })
    };

    // --- Listener loop: local UDP clients → tunnel ---
    // Every datagram becomes a UDPPacket with its source as remote_addr.
    // The tunnel is (re)connected lazily by the dispatcher below.
    let _listener_task = {
        let socket_l = socket.clone();
        let send_tx_l = send_tx.clone();
        let shutdown_l = shutdown.clone();
        let name_l = name.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65535];
            loop {
                // Deliberately NOT biased: under heavy local UDP traffic the
                // recv_from branch would always be ready and starve the
                // shutdown poll.
                tokio::select! {
                    _ = wait_sudp_shutdown(&shutdown_l) => {
                        info!(visitor_name = %name_l, "SUDP visitor '{}' listener shutting down", name_l);
                        break;
                    }
                    result = socket_l.recv_from(&mut buf) => {
                        match result {
                            Ok((n, src)) => {
                                debug!(visitor_name = %name_l, byte_count = n, src_addr = %src, "SUDP visitor '{}': received {} bytes from local {}", name_l, n, src);
                                let pkt = msg::UDPPacket {
                                    content: buf[..n].to_vec(),
                                    local_addr: None, // SUDP: local_addr is always None (Go sudp.go)
                                    remote_addr: Some(msg::UdpAddr {
                                        ip: src.ip().to_string(),
                                        port: src.port(),
                                        zone: String::new(),
                                    }),
                                };
                                if send_tx_l.send(pkt).await.is_err() {
                                    debug!(visitor_name = %name_l, "SUDP visitor '{}' send channel closed", name_l);
                                    break;
                                }
                            }
                            Err(e) => {
                                warn!(visitor_name = %name_l, error = %e, "SUDP visitor '{}': recv_from failed: {}", name_l, e);
                                break;
                            }
                        }
                    }
                }
            }
        })
    };

    let transport = VisitorTransportConfig {
        tcp_mux,
        tcp_mux_keepalive_interval,
        proxy_url,
        dns_server,
        dial_timeout_secs,
        keepalive_secs,
        connect_bind_addr,
        disable_custom_tls_first_byte,
        tls_cert_file,
        tls_key_file,
        v2,
    };

    // --- Dispatcher: lazy connect + reconnect ---
    // Wait for the first datagram (wait state), then establish a tunnel.
    // While the worker runs it consumes further datagrams. When the worker
    // exits (disconnect / 60s idle timeout) we return to the wait state and
    // the next datagram reconnects (Go sudp.go Run()/worker()).
    let mut first_pkt = match sudp_next_datagram(&mut send_rx, &shutdown, &name).await {
        Some(p) => p,
        None => {
            debug!(visitor_name = %name, "SUDP visitor '{}' send channel closed (listener exited)", name);
            return;
        }
    };

    loop {
        if shutdown.load(Ordering::Relaxed) {
            info!(visitor_name = %name, "SUDP visitor '{}' shutting down", name);
            return;
        }
        let server_conn = match connect_sudp_visitor_stream(
            &server_addr,
            server_port,
            &protocol,
            tls_enable,
            &tls_server_name,
            &tls_ca_file,
            &transport,
            &name,
            &server_name,
            &server_user,
            &secret_key,
            use_encryption,
            use_compression,
            &user,
            &run_id,
            v2,
        )
        .await
        {
            Some(conn) => conn,
            None => {
                warn!(visitor_name = %name, "SUDP visitor '{}': tunnel connect failed; dropping packet and waiting for the next datagram", name);
                match sudp_next_datagram(&mut send_rx, &shutdown, &name).await {
                    Some(p) => {
                        first_pkt = p;
                        continue;
                    }
                    None => return,
                }
            }
        };
        run_sudp_worker(
            server_conn,
            &mut send_rx,
            first_pkt,
            read_tx.clone(),
            &name,
            &shutdown,
            use_encryption,
            use_compression,
            &secret_key,
            v2,
            &udp_packet_codec,
        )
        .await;
        // Worker ended (disconnect / idle timeout): back to the wait state.
        debug!(visitor_name = %name, "SUDP visitor '{}': tunnel closed, waiting for the next datagram to reconnect", name);
        match sudp_next_datagram(&mut send_rx, &shutdown, &name).await {
            Some(p) => first_pkt = p,
            None => return,
        }
    }
}

/// Wait for the next local datagram, aborting early on shutdown.
///
/// Every place the dispatcher blocks on `send_rx.recv()` must race it
/// against the shutdown flag — otherwise a shutdown that arrives while the
/// worker is exiting (or after a connect failure) leaves the dispatcher
/// parked on `recv()` forever, holding the UDP socket Arc and leaking the
/// bind port until process exit.
async fn sudp_next_datagram(
    send_rx: &mut mpsc::Receiver<msg::UDPPacket>,
    shutdown: &Arc<AtomicBool>,
    name: &str,
) -> Option<msg::UDPPacket> {
    tokio::select! {
        biased;
        _ = wait_sudp_shutdown(shutdown) => {
            info!(visitor_name = %name, "SUDP visitor '{}' shutting down", name);
            None
        }
        p = send_rx.recv() => p,
    }
}

/// Dial the server and complete the NewVisitorConn handshake for a SUDP
/// visitor tunnel. Mirrors the STCP visitor connect skeleton
/// (`dial_server` → yamux → `NewVisitorConn` → `NewVisitorConnResp`).
#[allow(clippy::too_many_arguments)]
async fn connect_sudp_visitor_stream(
    server_addr: &str,
    server_port: u16,
    protocol: &TransportProtocol,
    tls_enable: bool,
    tls_server_name: &str,
    tls_ca_file: &Option<String>,
    transport: &VisitorTransportConfig,
    visitor_name: &str,
    server_name: &str,
    server_user: &str,
    secret_key: &str,
    use_encryption: bool,
    use_compression: bool,
    user: &str,
    run_id: &str,
    v2: bool,
) -> Option<IoStream> {
    let plan = plan_visitor_dial(
        server_addr,
        server_port,
        protocol,
        tls_enable,
        tls_server_name,
        tls_ca_file,
        transport,
    );
    let raw_stream = match dial_server(&plan.opts).await {
        Ok(io) => io,
        Err(e) => {
            warn!(visitor_name = %visitor_name, error = %e, "SUDP visitor '{}': dial server failed: {}", visitor_name, e);
            return None;
        }
    };
    let mut server_conn = if let Some(ka) = plan.yamux_keepalive_secs {
        match crate::control::wrap_client_mux(raw_stream, ka).await {
            Ok((io, _session)) => io,
            Err(e) => {
                warn!(visitor_name = %visitor_name, error = %e, "SUDP visitor '{}': yamux wrap failed: {}", visitor_name, e);
                return None;
            }
        }
    } else {
        raw_stream
    };
    let nvc = crate::proxy::create_visitor_conn_msg(
        server_name,
        secret_key,
        use_encryption,
        use_compression,
        Some(server_user).filter(|s| !s.is_empty()),
        Some(user).filter(|s| !s.is_empty()),
        Some(run_id).filter(|s| !s.is_empty()),
    );
    // V2: write the connection magic before the NewVisitorConn frame (Go frp
    // messageConnector.Connect → WriteMagicIfV2; work conns do the same).
    // The server's accept loop consumes the magic, detects V2, and routes the
    // frame to handle_visitor_conn_inner; all subsequent frames on the
    // connection are magic-less V2 frames.
    let send_result = async {
        if v2 {
            frp_core::protocol::write_v2_magic(&mut server_conn).await?;
            server_conn.write_v2_frame(&nvc).await
        } else {
            server_conn.write_v1_frame(&nvc).await
        }
    }
    .await;
    if let Err(e) = send_result {
        warn!(visitor_name = %visitor_name, error = %e, "SUDP visitor '{}': send NewVisitorConn failed: {}", visitor_name, e);
        return None;
    }
    // Bound the response wait (mirrors read_start_work_conn_with_timeout in
    // work_conn.rs): a silent server must not leave the tunnel connect
    // hanging — the dispatcher falls back to waiting for the next datagram.
    let resp_timeout = Duration::from_secs(transport.dial_timeout_secs.max(1));
    let read_resp = if v2 {
        tokio::time::timeout(resp_timeout, server_conn.read_v2_frame()).await
    } else {
        tokio::time::timeout(resp_timeout, server_conn.read_v1_frame()).await
    };
    match read_resp {
        Ok(Ok(FrpMessage::NewVisitorConnResp(resp))) => {
            if let Some(err) = resp.error {
                warn!(visitor_name = %visitor_name, error = %err, "SUDP visitor '{}': server error: {}", visitor_name, err);
                return None;
            }
            debug!(visitor_name = %visitor_name, proxy_name = %resp.proxy_name, "SUDP visitor '{}': relay ready for '{}'", visitor_name, resp.proxy_name);
        }
        Ok(Ok(other)) => {
            warn!(visitor_name = %visitor_name, type_byte = %other.v1_type_byte(), "SUDP visitor '{}': unexpected response type", visitor_name);
            return None;
        }
        Ok(Err(e)) => {
            warn!(visitor_name = %visitor_name, error = %e, "SUDP visitor '{}': read NewVisitorConnResp failed: {}", visitor_name, e);
            return None;
        }
        Err(_elapsed) => {
            warn!(visitor_name = %visitor_name, timeout = ?resp_timeout, "SUDP visitor '{}': timed out waiting for NewVisitorConnResp", visitor_name);
            return None;
        }
    }
    Some(server_conn)
}

/// Data-plane worker for an established SUDP visitor tunnel.
///
/// - write side: datagrams from the local UDP socket (`send_rx`) are written
///   to the server connection as `UDPPacket` messages (V1 framing, type 'u',
///   matching Go frp's UDP data plane)
/// - read side: `UDPPacket` messages from the server are forwarded to the
///   reader loop (`read_tx`) which sends them back to the local client;
///   `Ping` is ignored (Go sudp.go)
/// - a 60s idle timeout closes the tunnel (Go sudp.go `connTimeout`); the
///   dispatcher then reconnects on the next datagram
///
/// When the visitor declared `use_encryption` (and `sk` is non-empty), the
/// server-side half of the connection is wrapped in `CipherReader` /
/// `CipherWriter` with `derive_key(sk)`, and when it declared
/// `use_compression` the halves are additionally wrapped in
/// `SnappyStreamReader`/`SnappyStreamWriter` — the visitor segment of Go
/// frp's three-stage model, snappy **inner** and CFB **outer** (Go
/// `WithCompression` + `WithEncryption`). The V1 frame protocol then runs on
/// top of the wrapped stream, symmetric with the server's `split_user_side`.
/// CipherWriter sends its random IV on the first write (or eager flush), so
/// the first `UDPPacket` carries the IV.
#[allow(clippy::too_many_arguments)]
async fn run_sudp_worker(
    server_conn: IoStream,
    send_rx: &mut mpsc::Receiver<msg::UDPPacket>,
    first_pkt: msg::UDPPacket,
    read_tx: mpsc::Sender<msg::UDPPacket>,
    visitor_name: &str,
    shutdown: &Arc<AtomicBool>,
    use_encryption: bool,
    use_compression: bool,
    secret_key: &str,
    v2: bool,
    udp_packet_codec: &str,
) {
    // Negotiated UDPPacket codec (Go frp v0.71.0): `"binary-v1"` when the
    // control session negotiated it (wire protocol v2), empty otherwise.
    // The visitor segment must use the same codec as the provider segment
    // or the server bridges the two message-level (transcoding).
    let udp_codec_opt = if v2 && !udp_packet_codec.is_empty() {
        Some(udp_packet_codec)
    } else {
        None
    };
    let (srv_r, srv_w) = match split_work_conn_halves(server_conn) {
        Ok(pair) => pair,
        Err(e) => {
            warn!(visitor_name = %visitor_name, error = e, "SUDP visitor '{}': could not split server conn: {}", visitor_name, e);
            return;
        }
    };
    // Visitor-segment encryption/compression: wrap both halves symmetrically
    // with the server's split_user_side. Wire order (Go parity): snappy is
    // the inner layer, CFB the outer — write plaintext → snappy → CFB →
    // socket. The V1 frame protocol (read_msg_v1/write_msg_v1) then runs over
    // the wrapped stream.
    let use_enc = use_encryption && !secret_key.is_empty();
    let enc_key = use_enc.then(|| frp_core::encryption::derive_key(secret_key));
    let srv_r: BoxedReadHalf = if use_compression {
        let inner: BoxedReadHalf = if let Some(key) = enc_key {
            Box::new(frp_core::cipher_stream::CipherReader::new(srv_r, key))
        } else {
            srv_r
        };
        Box::new(frp_core::snappy_stream::SnappyStreamReader::new(inner))
    } else if let Some(key) = enc_key {
        Box::new(frp_core::cipher_stream::CipherReader::new(srv_r, key))
    } else {
        srv_r
    };
    let mut srv_w: BoxedWriteHalf = if use_compression {
        let inner: BoxedWriteHalf = if let Some(key) = enc_key {
            Box::new(frp_core::cipher_stream::CipherWriter::new(srv_w, key))
        } else {
            srv_w
        };
        Box::new(frp_core::snappy_stream::SnappyStreamWriter::new(inner))
    } else if let Some(key) = enc_key {
        Box::new(frp_core::cipher_stream::CipherWriter::new(srv_w, key))
    } else {
        srv_w
    };
    // Buffer frame reads: read_msg_v1 issues two read_exact calls per message.
    let mut srv_r = tokio::io::BufReader::with_capacity(16 * 1024, srv_r);
    // The first packet (which triggered the connect) is written immediately.
    let first_write = if v2 {
        write_msg_v2_with_udp_codec(
            &mut srv_w,
            &FrpMessage::UDPPacket(first_pkt),
            udp_codec_opt,
            false,
        )
        .await
    } else {
        write_msg_v1(&mut srv_w, &FrpMessage::UDPPacket(first_pkt)).await
    };
    if let Err(e) = first_write {
        warn!(visitor_name = %visitor_name, error = %e, "SUDP visitor '{}': write first UDPPacket failed: {}", visitor_name, e);
        return;
    }
    // Go sudp.go: a 60s idle tunnel (no traffic either way) tears down and
    // the next datagram reconnects. Deadline is reset on every activity —
    // NOT a fresh sleep() per loop iteration, which would never fire (the
    // 100ms shutdown poll would always win the select and restart it).
    let mut idle_deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    loop {
        // Fast-path shutdown check: the 100ms wait_sudp_shutdown poll below
        // can be starved under sustained bidirectional traffic (unbiased
        // select picks among ready branches), so check the flag directly on
        // every iteration.
        if shutdown.load(Ordering::Relaxed) {
            info!(visitor_name = %visitor_name, "SUDP visitor '{}' shutting down", visitor_name);
            break;
        }
        // Deliberately NOT biased: an always-ready send channel (local UDP
        // flood) must not starve the read side (return traffic), and the
        // idle/shutdown branches must stay reachable.
        tokio::select! {
            _ = wait_sudp_shutdown(shutdown) => {
                info!(visitor_name = %visitor_name, "SUDP visitor '{}' shutting down", visitor_name);
                break;
            }
            _ = tokio::time::sleep_until(idle_deadline) => {
                debug!(visitor_name = %visitor_name, "SUDP visitor '{}': 60s idle timeout, closing tunnel", visitor_name);
                break;
            }
            pkt = send_rx.recv() => {
                match pkt {
                    Some(p) => {
                        let write = if v2 {
                            write_msg_v2_with_udp_codec(
                                &mut srv_w,
                                &FrpMessage::UDPPacket(p),
                                udp_codec_opt,
                                false,
                            )
                            .await
                        } else {
                            write_msg_v1(&mut srv_w, &FrpMessage::UDPPacket(p)).await
                        };
                        if let Err(e) = write {
                            debug!(visitor_name = %visitor_name, error = %e, "SUDP visitor '{}': write UDPPacket failed: {}", visitor_name, e);
                            break;
                        }
                        idle_deadline = tokio::time::Instant::now() + Duration::from_secs(60);
                    }
                    None => {
                        debug!(visitor_name = %visitor_name, "SUDP visitor '{}': send channel closed", visitor_name);
                        break;
                    }
                }
            }
            msg_result = async {
                if v2 {
                    read_msg_v2_with_udp_codec(&mut srv_r, udp_codec_opt).await
                } else {
                    read_msg_v1(&mut srv_r).await
                }
            } => {
                match msg_result {
                    Ok(FrpMessage::UDPPacket(up)) => {
                        idle_deadline = tokio::time::Instant::now() + Duration::from_secs(60);
                        if read_tx.send(up).await.is_err() {
                            debug!(visitor_name = %visitor_name, "SUDP visitor '{}': reader loop dropped", visitor_name);
                            break;
                        }
                    }
                    Ok(FrpMessage::Ping(_)) | Ok(FrpMessage::Pong(_)) => {
                        // Go sudp.go ignores Ping on the data plane.
                        continue;
                    }
                    Ok(other) => {
                        debug!(visitor_name = %visitor_name, v1_type = %other.v1_type_byte(), "SUDP visitor '{}': unexpected message 0x{:02x}", visitor_name, other.v1_type_byte());
                    }
                    Err(e) => {
                        debug!(visitor_name = %visitor_name, error = %e, "SUDP visitor '{}': read closed: {}", visitor_name, e);
                        break;
                    }
                }
            }
        }
    }
}

/// Polls `shutdown` every 100ms until it is set.
async fn wait_sudp_shutdown(shutdown: &Arc<AtomicBool>) {
    loop {
        if shutdown.load(Ordering::Relaxed) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// Run a no-bind `virtual_net` visitor tunnel.
///
/// Establishes an STCP/XTCP tunnel connection to the remote proxy and
/// registers the visitor's `destinationIP` host route with the shared client
/// vnet controller. Inbound [`VnetPacket`]s addressed to the visitor name are
/// delivered into the tunnel connection; when the connection closes the route
/// is unregistered. The tunnel is re-established after a short backoff so a
/// transient remote-side failure does not permanently disable the visitor.
#[cfg(feature = "vnet")]
pub(crate) async fn run_virtual_net_visitor(config: VirtualNetVisitorConfig) {
    let VirtualNetVisitorConfig {
        server_addr,
        server_port,
        protocol,
        server_name,
        server_user,
        secret_key,
        use_encryption,
        use_compression,
        name,
        tls_enable,
        tls_server_name,
        tls_ca_file,
        user,
        run_id,
        destination_cidr,
        controller,
        vnet_tun_tx,
        tun_subnets,
        shutdown,
        tcp_mux,
        tcp_mux_keepalive_interval,
        proxy_url,
        dns_server,
        dial_timeout_secs,
        keepalive_secs,
        connect_bind_addr,
        disable_custom_tls_first_byte,
        tls_cert_file,
        tls_key_file,
        v2,
    } = config;

    'reconnect: loop {
        if shutdown.load(Ordering::Relaxed) {
            return;
        }

        let transport = VisitorTransportConfig {
            tcp_mux,
            tcp_mux_keepalive_interval,
            proxy_url: proxy_url.clone(),
            dns_server: dns_server.clone(),
            dial_timeout_secs,
            keepalive_secs,
            connect_bind_addr: connect_bind_addr.clone(),
            disable_custom_tls_first_byte,
            tls_cert_file: tls_cert_file.clone(),
            tls_key_file: tls_key_file.clone(),
            v2,
        };
        let plan = plan_visitor_dial(
            &server_addr,
            server_port,
            &protocol,
            tls_enable,
            &tls_server_name,
            &tls_ca_file,
            &transport,
        );
        let raw_stream = match dial_server(&plan.opts).await {
            Ok(io) => io,
            Err(e) => {
                warn!(visitor_name = %name, error = %e, "Virtual net visitor '{}': dial server failed: {}", name, e);
                if wait_for_shutdown_or_delay(&shutdown, Duration::from_secs(10)).await {
                    return;
                }
                continue 'reconnect;
            }
        };
        // Wrap in yamux when tcp_mux is enabled (Go frp compat).
        let yamux_keepalive = plan.yamux_keepalive_secs;
        let mut _yamux_sess_vnet: Option<YamuxSession> = None;
        let mut server_conn = if let Some(ka) = yamux_keepalive {
            match crate::control::wrap_client_mux(raw_stream, ka).await {
                Ok((io, session)) => {
                    _yamux_sess_vnet = session;
                    io
                }
                Err(e) => {
                    warn!(visitor_name = %name, error = %e, "Virtual net visitor '{}': yamux wrap failed: {}", name, e);
                    if wait_for_shutdown_or_delay(&shutdown, Duration::from_secs(10)).await {
                        return;
                    }
                    continue 'reconnect;
                }
            }
        } else {
            raw_stream
        };

        let nvc = crate::proxy::create_visitor_conn_msg(
            &server_name,
            &secret_key,
            use_encryption,
            use_compression,
            Some(server_user.as_str()).filter(|s| !s.is_empty()),
            Some(user.as_str()).filter(|s| !s.is_empty()),
            Some(run_id.as_str()).filter(|s| !s.is_empty()),
        );
        if let Err(e) = server_conn.write_v1_frame(&nvc).await {
            warn!(visitor_name = %name, error = %e, "Virtual net visitor '{}': send NewVisitorConn failed: {}", name, e);
            if wait_for_shutdown_or_delay(&shutdown, Duration::from_secs(10)).await {
                return;
            }
            continue 'reconnect;
        }
        debug!(visitor_name = %name, sn = %server_name, "Virtual net visitor '{}': sent NewVisitorConn for '{}'", name, server_name);

        // Bound the response wait (mirrors read_start_work_conn_with_timeout
        // in work_conn.rs): a silent server must not pin the tunnel connect —
        // fail over to the reconnect backoff instead.
        let resp_timeout = Duration::from_secs(dial_timeout_secs.max(1));
        match tokio::time::timeout(resp_timeout, server_conn.read_v1_frame()).await {
            Ok(Ok(FrpMessage::NewVisitorConnResp(resp))) => {
                if let Some(err) = resp.error {
                    warn!(visitor_name = %name, error = %err, "Virtual net visitor '{}': tunnel setup failed: {}", name, err);
                    if wait_for_shutdown_or_delay(&shutdown, Duration::from_secs(10)).await {
                        return;
                    }
                    continue 'reconnect;
                }
                debug!(visitor_name = %name, proxy_name = %resp.proxy_name, "Virtual net visitor '{}': tunnel ready for '{}'", name, resp.proxy_name);
            }
            Ok(Ok(FrpMessage::ReqWorkConn(_))) => {
                // Go frps responds to NewVisitorConn with ReqWorkConn; treat as success.
                debug!(visitor_name = %name, "Virtual net visitor '{}': tunnel ready (Go frps ReqWorkConn)", name);
            }
            Ok(Ok(other)) => {
                warn!(visitor_name = %name, type_byte = %other.v1_type_byte(), "Virtual net visitor received unexpected response type");
                if wait_for_shutdown_or_delay(&shutdown, Duration::from_secs(10)).await {
                    return;
                }
                continue 'reconnect;
            }
            Ok(Err(e)) => {
                warn!(visitor_name = %name, error = %e, "Virtual net visitor '{}': read tunnel response failed: {}", name, e);
                if wait_for_shutdown_or_delay(&shutdown, Duration::from_secs(10)).await {
                    return;
                }
                continue 'reconnect;
            }
            Err(_elapsed) => {
                warn!(visitor_name = %name, timeout = ?resp_timeout, "Virtual net visitor '{}': timed out waiting for tunnel response", name);
                if wait_for_shutdown_or_delay(&shutdown, Duration::from_secs(10)).await {
                    return;
                }
                continue 'reconnect;
            }
        }

        let (packet_tx, packet_rx) = mpsc::channel::<Vec<u8>>(256);
        if let Err(e) = controller
            .register_visitor_route(&name, &destination_cidr, packet_tx)
            .await
        {
            warn!(visitor_name = %name, error = %e, "Virtual net visitor '{}': route registration failed: {}", name, e);
            if wait_for_shutdown_or_delay(&shutdown, Duration::from_secs(10)).await {
                return;
            }
            continue 'reconnect;
        }
        info!(
            visitor_name = %name,
            destination = %destination_cidr,
            "Virtual net visitor '{}' tunnel established, host route {} registered",
            name,
            destination_cidr
        );

        let key = frp_core::encryption::derive_key(&secret_key);
        run_virtual_net_tunnel_io(
            server_conn,
            name.clone(),
            packet_rx,
            vnet_tun_tx.clone(),
            tun_subnets.clone(),
            shutdown.clone(),
            use_encryption,
            use_compression,
            key,
        )
        .await;

        controller.unregister_visitor_route(&name).await;
        info!(visitor_name = %name, "Virtual net visitor '{}' tunnel closed, route removed", name);
        if shutdown.load(Ordering::Relaxed) {
            return;
        }
        if wait_for_shutdown_or_delay(&shutdown, Duration::from_secs(10)).await {
            return;
        }
    }
}

/// Deliver bytes received from a `virtual_net` visitor tunnel into the local
/// TUN delivery channels used by control-connection [`FrpMessage::VnetPacket`]s.
///
/// Returns `true` when at least one TUN channel accepted the packet.
#[cfg(feature = "vnet")]
async fn deliver_tunnel_ingress(
    visitor_name: &str,
    packet: Vec<u8>,
    vnet_tun_tx: &VnetTunTxMap,
    tun_subnets: &Arc<tokio::sync::Mutex<HashMap<String, String>>>,
) -> bool {
    // Take the tokio lock first so the std Mutex guard never spans an await
    // point (the guarded section below is fully synchronous).
    let subnets = tun_subnets.lock().await;
    let txs = vnet_tun_tx.lock().unwrap_or_else(|e| e.into_inner());
    let dst = frp_vnet::router::packet_dst_ip(&packet);
    let mut delivered = false;
    for (proxy, tx) in txs.iter() {
        let matched = dst.as_ref().is_some_and(|ip| {
            subnets.get(proxy).is_some_and(|cidr| {
                let mut rt = frp_vnet::router::RouteTable::new();
                // Single-route match; the vnet dimension is not relevant here.
                rt.insert("", proxy, cidr)
                    .is_ok_and(|_| rt.lookup("", ip) == Some(proxy))
            })
        });
        if matched {
            match tx.try_send(packet.clone()) {
                Ok(()) => delivered = true,
                Err(mpsc::error::TrySendError::Full(_)) => {
                    warn!(
                        visitor_name = %visitor_name,
                        proxy_name = %proxy,
                        "virtual_net visitor TUN queue full; dropping packet"
                    );
                }
                Err(mpsc::error::TrySendError::Closed(_)) => {}
            }
        }
    }
    if delivered {
        return true;
    }

    // No subnet matched. A single local TUN is unambiguous and receives the
    // packet; multiple TUNs would make the target ambiguous, so drop instead
    // of broadcasting (the pre-fix behavior).
    let open: Vec<&mpsc::Sender<Vec<u8>>> = txs.values().filter(|tx| !tx.is_closed()).collect();
    if open.len() == 1 {
        match open[0].try_send(packet) {
            Ok(()) => return true,
            Err(mpsc::error::TrySendError::Full(_)) => {
                warn!(
                    visitor_name = %visitor_name,
                    "virtual_net visitor TUN queue full; dropping packet"
                );
                return true;
            }
            Err(mpsc::error::TrySendError::Closed(_)) => return false,
        }
    }
    if open.len() > 1 {
        warn!(
            visitor_name = %visitor_name,
            "virtual_net visitor ingress packet has no subnet match; dropping instead of broadcasting"
        );
    }
    false
}

/// Wait for `shutdown` or `delay`, whichever comes first. Returns `true` when
/// shutdown was requested so the caller can exit.
#[cfg(feature = "vnet")]
async fn wait_for_shutdown_or_delay(shutdown: &Arc<AtomicBool>, delay: Duration) -> bool {
    let deadline = Instant::now() + delay;
    loop {
        if shutdown.load(Ordering::Relaxed) {
            return true;
        }
        let now = Instant::now();
        if now >= deadline {
            return false;
        }
        tokio::time::sleep((deadline - now).min(Duration::from_millis(100))).await;
    }
}

/// Resolves when the graceful shutdown signal is set.
#[cfg(feature = "vnet")]
async fn wait_for_shutdown_signal(shutdown: &Arc<AtomicBool>) {
    loop {
        if shutdown.load(Ordering::Relaxed) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// Discover local non-loopback IPv4 addresses for assisted NAT hole punching.
/// Go frp equivalent: ListLocalIPsForNatHole(10) in pkg/nathole/utils.go:65-93.
/// Filters out IPv6, loopback, link-local unicast, and link-local multicast addresses.
///
/// On Linux, reads /proc/net/fib_trie to enumerate local IPs without requiring
/// external crate dependencies. Falls back to a simpler method if unavailable.
fn list_local_ips() -> Vec<String> {
    // Cache result with 30-second TTL to avoid per-connection
    // filesystem reads (/proc/net/fib_trie) and UDP socket creation.
    static CACHE: std::sync::Mutex<Option<(Vec<String>, Instant)>> = std::sync::Mutex::new(None);
    {
        if let Ok(cache) = CACHE.lock() {
            if let Some((ref ips, ref time)) = *cache {
                if time.elapsed() < std::time::Duration::from_secs(30) {
                    return ips.clone();
                }
            }
        }
    }

    let mut ips = Vec::new();

    // Linux-specific: parse /proc/net/fib_trie for local IPv4 addresses.
    // On non-Linux platforms (macOS, Windows), this path is skipped and we
    // fall through to the UDP connect fallback below, which only discovers
    // the default-route IP. For full multi-homed NAT hole punching on macOS,
    // a getifaddrs-based approach would be needed.
    //
    // Lines like "|-- 192.168.1.100" followed by "/32 host LOCAL" indicate
    // local interface IPs assigned to this machine.
    if let Ok(content) = std::fs::read_to_string("/proc/net/fib_trie") {
        let lines: Vec<&str> = content.lines().collect();
        for (i, line) in lines.iter().enumerate() {
            let trimmed = line.trim();
            // Look for a line containing a dotted IPv4 address
            if trimmed.starts_with("|--") || trimmed.starts_with("+--") {
                if let Some(ip_str) = trimmed
                    .split_whitespace()
                    .find(|s| s.contains('.') && s.parse::<std::net::Ipv4Addr>().is_ok())
                {
                    // Check next non-empty line for /32 host LOCAL marker
                    let is_local = lines
                        .get(i + 1)
                        .or(lines.get(i.wrapping_add(2)))
                        .map(|n| {
                            let n = n.trim();
                            n.contains("/32 host LOCAL") || n.contains("LOCAL")
                        })
                        .unwrap_or(false);
                    if is_local {
                        if let Ok(ip) = ip_str.parse::<std::net::Ipv4Addr>() {
                            if !ip.is_loopback() && !ip.is_link_local() && !ip.is_multicast() {
                                ips.push(ip.to_string());
                                if ips.len() >= 10 {
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // Fallback: try to get the default route interface IP.
    if ips.is_empty() {
        if let Ok(socket) = std::net::UdpSocket::bind("0.0.0.0:0") {
            // Connect to 8.8.8.8:53 — no data sent, just triggers the kernel
            // to select the default route interface for us.
            if socket.connect("8.8.8.8:53").is_ok() {
                if let Ok(local_addr) = socket.local_addr() {
                    let ip = local_addr.ip();
                    if ip.is_ipv4() {
                        let ipv4 = match ip {
                            std::net::IpAddr::V4(v4) => v4,
                            _ => unreachable!(),
                        };
                        if !ipv4.is_loopback() && !ipv4.is_link_local() && !ipv4.is_multicast() {
                            ips.push(ipv4.to_string());
                        }
                    }
                }
            }
        }
    }

    // Update cache
    if let Ok(mut cache) = CACHE.lock() {
        *cache = Some((ips.clone(), Instant::now()));
    }

    ips
}

#[cfg(all(test, feature = "vnet"))]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;
    use tokio::io::AsyncWriteExt;

    #[tokio::test]
    async fn tunnel_ingress_delivers_to_local_tun_channels() {
        let txs: VnetTunTxMap = Arc::new(std::sync::Mutex::new(HashMap::new()));
        let subnets: Arc<tokio::sync::Mutex<HashMap<String, String>>> =
            Arc::new(tokio::sync::Mutex::new(HashMap::new()));
        let (tx, mut rx) = mpsc::channel::<Vec<u8>>(16);
        txs.lock().unwrap().insert("tun-proxy".to_string(), tx);
        subnets
            .lock()
            .await
            .insert("tun-proxy".to_string(), "10.0.0.0/24".to_string());

        assert!(
            deliver_tunnel_ingress("vnet-visitor", vec![0x45], &txs, &subnets).await,
            "single open TUN channel must accept an unmatched packet as fallback"
        );
        assert_eq!(rx.recv().await, Some(vec![0x45]));

        let (closed_tx, closed_rx) = mpsc::channel::<Vec<u8>>(16);
        txs.lock()
            .unwrap()
            .insert("gone-tun".to_string(), closed_tx);
        subnets
            .lock()
            .await
            .insert("gone-tun".to_string(), "10.0.1.0/24".to_string());
        drop(closed_rx);
        assert!(
            deliver_tunnel_ingress("vnet-visitor", vec![0x46], &txs, &subnets).await,
            "an open channel still counts as delivered"
        );

        let empty: VnetTunTxMap = Arc::new(std::sync::Mutex::new(HashMap::new()));
        let empty_subnets: Arc<tokio::sync::Mutex<HashMap<String, String>>> =
            Arc::new(tokio::sync::Mutex::new(HashMap::new()));
        assert!(
            !deliver_tunnel_ingress("vnet-visitor", vec![0x47], &empty, &empty_subnets).await,
            "no TUN target must report undelivered"
        );
    }

    #[tokio::test]
    async fn tunnel_ingress_directs_by_ip_family_subnet() {
        let txs: VnetTunTxMap = Arc::new(std::sync::Mutex::new(HashMap::new()));
        let subnets: Arc<tokio::sync::Mutex<HashMap<String, String>>> =
            Arc::new(tokio::sync::Mutex::new(HashMap::new()));
        let (tx4, mut rx4) = mpsc::channel::<Vec<u8>>(16);
        let (tx6, mut rx6) = mpsc::channel::<Vec<u8>>(16);
        txs.lock().unwrap().insert("tun-v4".to_string(), tx4);
        txs.lock().unwrap().insert("tun-v6".to_string(), tx6);
        subnets
            .lock()
            .await
            .insert("tun-v4".to_string(), "10.0.0.0/24".to_string());
        subnets
            .lock()
            .await
            .insert("tun-v6".to_string(), "2001:db8::/64".to_string());

        let v4 = vec![
            0x45, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x40, 0x06, 0x00, 0x00, 10, 0, 0, 2,
            10, 0, 0, 5,
        ];
        let v6 = vec![
            0x60, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x20, 0x01, 0x0d, 0xb8,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05,
        ];

        assert!(deliver_tunnel_ingress("vnet-visitor", v4.clone(), &txs, &subnets).await);
        assert_eq!(rx4.recv().await, Some(v4));
        assert!(
            tokio::time::timeout(Duration::from_millis(50), rx6.recv())
                .await
                .is_err(),
            "IPv4 packet must not be broadcast to the IPv6 TUN"
        );

        assert!(deliver_tunnel_ingress("vnet-visitor", v6.clone(), &txs, &subnets).await);
        assert_eq!(rx6.recv().await, Some(v6));
        assert!(
            tokio::time::timeout(Duration::from_millis(50), rx4.recv())
                .await
                .is_err(),
            "IPv6 packet must not be broadcast to the IPv4 TUN"
        );
    }

    #[cfg(feature = "compression")]
    #[tokio::test]
    async fn virtual_net_tunnel_io_wraps_encrypted_compressed_bytes() {
        let key = frp_core::encryption::derive_key("visitor-secret");
        let (server, mut peer) = tokio::io::duplex(8192);
        let (packet_tx, packet_rx) = mpsc::channel::<Vec<u8>>(16);
        let txs: VnetTunTxMap = Arc::new(std::sync::Mutex::new(HashMap::new()));
        let subnets: Arc<tokio::sync::Mutex<HashMap<String, String>>> =
            Arc::new(tokio::sync::Mutex::new(HashMap::new()));
        let (tun_tx, mut tun_rx) = mpsc::channel::<Vec<u8>>(16);
        let shutdown = Arc::new(AtomicBool::new(false));
        txs.lock().unwrap().insert("tun-v4".to_string(), tun_tx);
        subnets
            .lock()
            .await
            .insert("tun-v4".to_string(), "10.0.0.0/24".to_string());

        let task = tokio::spawn(run_virtual_net_tunnel_io(
            frp_core::transport::IoStream::SshChannel(Box::new(server)),
            "vnet-visitor".to_string(),
            packet_rx,
            txs,
            subnets,
            shutdown,
            true,
            true,
            key,
        ));

        let inbound = vec![
            0x45, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x40, 0x06, 0x00, 0x00, 10, 0, 0, 2,
            10, 0, 0, 5,
        ];
        let mut framed = Vec::new();
        framed.extend_from_slice(&(inbound.len() as u32).to_le_bytes());
        framed.extend_from_slice(&inbound);
        let mut compressed = Vec::new();
        frp_core::encryption::compress_into(&framed, &mut compressed).unwrap();
        let wire = frp_core::encryption::encrypt(&compressed, &key).unwrap();
        peer.write_all(&wire).await.unwrap();
        assert_eq!(tun_rx.recv().await, Some(inbound.clone()));

        packet_tx.send(inbound.clone()).await.unwrap();
        let mut raw = vec![0u8; wire.len()];
        peer.read_exact(&mut raw).await.unwrap();
        assert_ne!(raw, wire);
        let decrypted = frp_core::encryption::decrypt(&raw, &key).unwrap();
        assert_eq!(
            frp_core::encryption::decompress(&decrypted).unwrap(),
            framed
        );

        drop(packet_tx);
        drop(peer);
        let _ = tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .unwrap();
    }
}

#[cfg(test)]
mod transport_tests {
    use super::*;

    fn make_transport() -> VisitorTransportConfig {
        VisitorTransportConfig {
            tcp_mux: true,
            tcp_mux_keepalive_interval: 30,
            proxy_url: Some("socks5://proxy:1080".into()),
            dns_server: Some("8.8.8.8".into()),
            dial_timeout_secs: 15,
            keepalive_secs: 60,
            connect_bind_addr: Some("10.0.0.1".into()),
            disable_custom_tls_first_byte: true,
            tls_cert_file: Some("/path/cert.pem".into()),
            tls_key_file: Some("/path/key.pem".into()),
            v2: true,
        }
    }

    /// When tcp_mux=true, plan_visitor_dial sets yamux_keepalive_secs
    /// to the configured keepalive interval and populates proxy_url
    /// into the DialOptions.
    #[test]
    fn plan_with_tcp_mux_yields_yamux_and_proxy() {
        let transport = make_transport();
        let plan = plan_visitor_dial(
            "frps.example.com",
            7443,
            &TransportProtocol::Tcp,
            true,
            "frps.example.com",
            &Some("/etc/ca.pem".into()),
            &transport,
        );

        // Yamux decision
        assert_eq!(
            plan.yamux_keepalive_secs,
            Some(30),
            "tcp_mux=true must request yamux wrapping with keepalive 30"
        );

        // Key transport fields in DialOptions
        assert_eq!(plan.opts.server_addr, "frps.example.com");
        assert_eq!(plan.opts.server_port, 7443);
        assert_eq!(plan.opts.proxy_url.as_deref(), Some("socks5://proxy:1080"));
        assert_eq!(plan.opts.dns_server.as_deref(), Some("8.8.8.8"));
        assert_eq!(plan.opts.dial_timeout_secs, 15);
        assert_eq!(plan.opts.keepalive_secs, 60);
        assert_eq!(plan.opts.bind_addr.as_deref(), Some("10.0.0.1"));
        assert!(plan.opts.disable_custom_tls_first_byte);
        assert_eq!(plan.opts.tls_cert_file.as_deref(), Some("/path/cert.pem"));
        assert_eq!(plan.opts.tls_key_file.as_deref(), Some("/path/key.pem"));
        assert!(plan.opts.v2);
        assert!(plan.opts.tls_enable);
        assert_eq!(plan.opts.tls_ca_file.as_deref(), Some("/etc/ca.pem"));
    }

    /// When tcp_mux=false, plan_visitor_dial returns no yamux keepalive
    /// and still propagates all other transport fields.
    #[test]
    fn plan_without_tcp_mux_omits_yamux() {
        let mut transport = make_transport();
        transport.tcp_mux = false;
        let plan = plan_visitor_dial(
            "frps.example.com",
            7000,
            &TransportProtocol::Tcp,
            false,
            "",
            &None,
            &transport,
        );

        assert_eq!(plan.yamux_keepalive_secs, None);
        // Proxy and other fields still flow through even without yamux
        assert_eq!(plan.opts.proxy_url.as_deref(), Some("socks5://proxy:1080"));
        assert_eq!(plan.opts.dial_timeout_secs, 15);
        assert!(plan.opts.v2);
    }

    /// Building a VisitorTransportConfig inline (the pattern used by
    /// run_visitor_listener) and passing it to plan_visitor_dial preserves
    /// all fields through to the DialOptions.
    #[test]
    fn inline_transport_to_dial_options_round_trip() {
        let transport = VisitorTransportConfig {
            tcp_mux: true,
            tcp_mux_keepalive_interval: 45,
            proxy_url: Some("http://p:8080".into()),
            dns_server: Some("1.1.1.1".into()),
            dial_timeout_secs: 25,
            keepalive_secs: 90,
            connect_bind_addr: Some("192.168.0.1".into()),
            disable_custom_tls_first_byte: false,
            tls_cert_file: Some("/c.pem".into()),
            tls_key_file: Some("/k.pem".into()),
            v2: false,
        };
        let plan = plan_visitor_dial(
            "frps.example.com",
            7443,
            &TransportProtocol::Tcp,
            false,
            "",
            &None,
            &transport,
        );

        assert_eq!(plan.yamux_keepalive_secs, Some(45));
        assert_eq!(plan.opts.proxy_url.as_deref(), Some("http://p:8080"));
        assert_eq!(plan.opts.dns_server.as_deref(), Some("1.1.1.1"));
        assert_eq!(plan.opts.dial_timeout_secs, 25);
        assert_eq!(plan.opts.keepalive_secs, 90);
        assert_eq!(plan.opts.bind_addr.as_deref(), Some("192.168.0.1"));
        assert!(!plan.opts.disable_custom_tls_first_byte);
        assert_eq!(plan.opts.tls_cert_file.as_deref(), Some("/c.pem"));
        assert_eq!(plan.opts.tls_key_file.as_deref(), Some("/k.pem"));
        assert!(!plan.opts.v2);
    }
}
