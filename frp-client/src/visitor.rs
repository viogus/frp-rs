#[cfg(feature = "vnet")]
use std::collections::HashMap;
use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::{mpsc, oneshot};
use tokio::time::Duration;
use tokio_util::sync::CancellationToken;
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
    /// XTCP P2P data plane protocol: "quic" (default, Go parity) or "kcp".
    /// Both data planes are implemented; "quic" requires BOTH the `quic` and
    /// `kcp` features (the QUIC data plane reuses the KCP hole-punch
    /// machinery).
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
        tls_skip_verify: false,
        tls_cert_file: transport.tls_cert_file.clone(),
        tls_key_file: transport.tls_key_file.clone(),
        dns_server: transport.dns_server.clone(),
        disable_custom_tls_first_byte: transport.disable_custom_tls_first_byte,
        keepalive_secs: transport.keepalive_secs,
        bind_addr: transport.connect_bind_addr.clone(),
        tcp_send_buffer_size: 0,
        tcp_recv_buffer_size: 0,
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

// ── Persistent XTCP tunnel session (Go frp v0.71 keepTunnelOpenWorker) ──
//
// Go frp v0.71 keeps ONE hole-punched data-plane session per XTCP visitor
// (`KCPTunnelSession` / `QUICTunnelSession` in client/visitor/xtcp.go) and
// reuses it across user connections. A dead session is closed and re-punched
// in the background (`processTunnelStartEvents`), optionally kept alive by
// `keepTunnelOpenWorker`. User connections wait up to a budget for the
// session to yield a stream (`openTunnel` / `getTunnelConn`); there is NO
// per-connection punch+retry loop anymore.

/// Minimum gap between hole punches (Go `processTunnelStartEvents` sleeps
/// the remainder of 10s after each makeNatHole).
const MIN_PUNCH_INTERVAL: Duration = Duration::from_secs(10);

/// A persistent XTCP data-plane session, one per visitor listener.
///
/// `Kcp` is the yamux-over-KCP session (raw KCP when `tcp-mux` is off; an
/// erroring stub when `kcp` is off — tiny/micro builds fall back to STCP).
/// `Quic` is the QUIC session (no yamux), requiring both `quic` and `kcp`
/// features (the QUIC data plane reuses the KCP hole-punch machinery).
pub(crate) enum TunnelSession {
    Kcp(frp_core::xtcp_p2p::XtcpTunnelSession),
    #[cfg(all(feature = "quic", feature = "kcp"))]
    Quic(frp_core::xtcp_p2p::QuicTunnelSession),
}

impl TunnelSession {
    /// Open a new stream (visitor / client role).
    pub(crate) async fn open_stream(
        &self,
        timeout: Duration,
    ) -> Result<Box<dyn frp_core::xtcp_p2p::P2pStream>, String> {
        match self {
            TunnelSession::Kcp(s) => s.open_stream(timeout).await,
            #[cfg(all(feature = "quic", feature = "kcp"))]
            TunnelSession::Quic(s) => s.open_stream(timeout).await,
        }
    }

    /// Accept the next inbound stream (provider / server role).
    pub(crate) async fn accept_stream(
        &self,
        timeout: Duration,
    ) -> Result<Box<dyn frp_core::xtcp_p2p::P2pStream>, String> {
        match self {
            TunnelSession::Kcp(s) => s.accept_stream(timeout).await,
            #[cfg(all(feature = "quic", feature = "kcp"))]
            TunnelSession::Quic(s) => s.accept_stream(timeout).await,
        }
    }

    /// Whether the session is alive.
    pub(crate) fn is_alive(&self) -> bool {
        match self {
            TunnelSession::Kcp(s) => s.is_alive(),
            #[cfg(all(feature = "quic", feature = "kcp"))]
            TunnelSession::Quic(s) => s.is_alive(),
        }
    }

    /// Close the session (releases the UDP socket / KCP / yamux / QUIC).
    pub(crate) async fn close(&self) {
        match self {
            TunnelSession::Kcp(s) => s.close().await,
            #[cfg(all(feature = "quic", feature = "kcp"))]
            TunnelSession::Quic(s) => s.close().await,
        }
    }
}

/// Config for the background XTCP hole-punch task (Go `makeNatHole`).
/// Cloned once per listener; drives `do_hole_punch` in
/// `process_tunnel_start_events` / `keep_tunnel_open_worker`.
#[derive(Clone)]
struct XtcpPunchConfig {
    visitor_name: String,
    /// target server proxy name (`server_name`).
    sn: String,
    /// secret key for auth + detect probing.
    sk: String,
    stun_server: String,
    /// XTCP P2P data plane protocol: "quic" (default, Go parity) or "kcp".
    pp: String,
    /// disable assisted addresses.
    daa: bool,
    /// Control-channel sender for NatHoleVisitor.
    vtx: mpsc::Sender<crate::service::VisitorRequest>,
}

/// Full XTCP hole punch (Go `makeNatHole`): PreCheck → STUN → NatHoleVisitor
/// exchange → MakeHole → session creation. Returns the persistent session —
/// NO stream is opened here (streams are opened per user connection).
async fn do_hole_punch(cfg: &XtcpPunchConfig) -> Result<TunnelSession, String> {
    // 1. PreCheck: validate proxy existence/permissions before STUN (Go
    //    nathole.PreCheck, 5s timeout). A timeout proceeds with the full
    //    request — graceful degradation against servers that ignore
    //    pre_check. In the background-task model a 5s wait cannot stall a
    //    user connection, so the full Go timeout is used (the old
    //    per-connection code shortened it to 1s).
    {
        let (reply_tx, reply_rx) = oneshot::channel();
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;
        let sign_key = if cfg.sk.is_empty() {
            None
        } else {
            Some(frp_core::auth::generate_token(&cfg.sk, ts))
        };
        let pre_check_req = crate::service::VisitorRequest {
            nhv: msg::NatHoleVisitor {
                transaction_id: uuid::Uuid::new_v4().to_string(),
                proxy_name: cfg.sn.clone(),
                pre_check: true,
                protocol: Some(cfg.pp.to_string()),
                sign_key,
                timestamp: Some(ts),
                mapped_addrs: None,
                assisted_addrs: None,
            },
            reply: reply_tx,
        };
        if cfg.vtx.try_send(pre_check_req).is_err() {
            // try_send also fails on Full (backpressure) — a closed channel
            // and a backlogged control loop are different failures.
            return Err(if cfg.vtx.is_closed() {
                "failed to send pre_check to control loop (channel closed)".into()
            } else {
                "failed to send pre_check to control loop (backlogged, not draining)".into()
            });
        }
        match tokio::time::timeout(Duration::from_secs(5), reply_rx).await {
            Ok(Ok(Ok(resp))) => {
                if let Some(err) = resp.error {
                    return Err(format!("pre_check failed: {err}"));
                }
            }
            Ok(Ok(Err(e))) => return Err(format!("pre_check error: {e}")),
            Ok(Err(_)) => return Err("pre_check channel closed (control loop dropped)".into()),
            Err(_elapsed) => {
                warn!(visitor_name = %cfg.visitor_name, "Visitor '{}': pre_check timed out after 5s, proceeding with full request", cfg.visitor_name);
            }
        }
    }

    // 2. STUN discovery: first STUN gives the mapped address + optional
    //    OTHER-ADDRESS (RFC 5780); use it (or the same server) for the
    //    second request so the NAT classifier gets ≥2 addresses. The socket
    //    is reused for the punch + data plane.
    let (stun_socket, mapped_addrs, assisted_addrs) =
        match frp_core::stun::stun_binding_with_details(&cfg.stun_server).await {
            Ok((sock, result1)) => {
                let addr1 = result1.mapped_addr;
                debug!(visitor_name = %cfg.visitor_name, addr = %addr1, "Visitor '{}': STUN #1: {}", cfg.visitor_name, addr1);
                let mut addrs = vec![addr1];
                let second_target = result1.other_addr.as_deref().unwrap_or(&cfg.stun_server);
                match frp_core::stun::stun_binding_on_socket(&sock, second_target).await {
                    Ok(addr2) => {
                        debug!(visitor_name = %cfg.visitor_name, addr = %addr2, "Visitor '{}': STUN #2 from '{}': {}", cfg.visitor_name, second_target, addr2);
                        addrs.push(addr2);
                    }
                    Err(e) => {
                        warn!(visitor_name = %cfg.visitor_name, error = %e, "Visitor '{}': STUN #2 failed: {}", cfg.visitor_name, e);
                    }
                }
                let assisted = if cfg.daa {
                    vec![]
                } else {
                    let stun_port = sock.local_addr().ok().map(|a| a.port()).unwrap_or(0);
                    let local_ips = list_local_ips();
                    debug!(
                        visitor_name = %cfg.visitor_name, local_ips = ?local_ips, port = %stun_port,
                        "Visitor '{}': building assisted_addrs from {} local IPs port {}",
                        cfg.visitor_name, local_ips.len(), stun_port
                    );
                    local_ips
                        .into_iter()
                        .map(|ip| format!("{}:{}", ip, stun_port))
                        .collect()
                };
                (Some(sock), addrs, assisted)
            }
            Err(e) => {
                warn!(visitor_name = %cfg.visitor_name, error = %e, "Visitor '{}': STUN failed: {}", cfg.visitor_name, e);
                (None, vec![], vec![])
            }
        };
    let Some(socket) = stun_socket else {
        return Err(format!(
            "Visitor '{}': STUN failed, no socket for XTCP P2P",
            cfg.visitor_name
        ));
    };

    // 3. Send NatHoleVisitor on the control connection and wait for
    //    NatHoleResp (15s — server NAT_HOLE_TIMEOUT is 10s).
    let txn_id = uuid::Uuid::new_v4().to_string();
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64;
    let sign_key = if cfg.sk.is_empty() {
        None
    } else {
        Some(frp_core::auth::generate_token(&cfg.sk, ts))
    };
    let (reply_tx, reply_rx) = oneshot::channel();
    let nhv = crate::service::VisitorRequest {
        nhv: msg::NatHoleVisitor {
            transaction_id: txn_id.clone(),
            proxy_name: cfg.sn.clone(),
            pre_check: false,
            protocol: Some(cfg.pp.to_string()),
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
    if cfg.vtx.try_send(nhv).is_err() {
        // try_send also fails on Full (backpressure) — a closed channel and a
        // backlogged control loop are different failures.
        return Err(if cfg.vtx.is_closed() {
            "failed to send NatHoleVisitor to control loop (channel closed)".into()
        } else {
            "failed to send NatHoleVisitor to control loop (backlogged, not draining)".into()
        });
    }
    let resp = match tokio::time::timeout(Duration::from_secs(15), reply_rx).await {
        Ok(Ok(Ok(resp))) => resp,
        Ok(Ok(Err(e))) => return Err(format!("NatHoleResp error from server: {e}")),
        Ok(Err(_)) => return Err("NatHoleResp channel closed (control loop dropped)".into()),
        Err(_elapsed) => return Err("NatHoleResp timed out after 15s".into()),
    };
    debug!(visitor_name = %cfg.visitor_name, "Visitor '{}': received NatHoleResp from server", cfg.visitor_name);

    let candidates = resp.candidate_addrs.unwrap_or_default();
    debug!(visitor_name = %cfg.visitor_name, candidate_count = %candidates.len(), "Visitor '{}': got {} candidate addresses from server", cfg.visitor_name, candidates.len());

    // 4. UDP hole punch + session creation (Go v0.71 tunnel-session model —
    //    the session, not a single stream, is the punch result).
    let sid = resp.sid.clone().unwrap_or_default();
    let conv = frp_core::xtcp_p2p::conv_from_sid(&sid);
    let kcp_cfg = frp_core::kcp::default_kcp_config();
    let p2p_key = if !cfg.sk.is_empty() {
        Some(frp_core::xtcp_p2p::derive_detect_key(&cfg.sk))
    } else {
        None
    };
    let p2p_sid = if sid.is_empty() {
        None
    } else {
        Some(sid.as_str())
    };
    // Use read_timeout_ms from the server's detect_behavior as the
    // hole-punch timeout (Go parity); default to Go's MakeHole 5s. The
    // punch no longer shares a budget with the per-connection wait — it runs
    // in the background.
    let hp_timeout = resp
        .detect_behavior
        .as_ref()
        .map(|db| db.read_timeout_ms.max(0) as u64)
        .unwrap_or(frp_core::xtcp_p2p::DEFAULT_HOLE_PUNCH_TIMEOUT_MS);
    let assisted = resp.assisted_addrs.clone().unwrap_or_default();
    let behavior = resp.detect_behavior.clone();
    if cfg.pp.as_str() == "quic" {
        #[cfg(all(feature = "quic", feature = "kcp"))]
        {
            let s = frp_core::xtcp_p2p::xtcp_p2p_connect_quic_session(
                socket,
                &candidates,
                &assisted,
                behavior.as_ref(),
                hp_timeout,
                p2p_sid,
                p2p_key.as_ref(),
                false, // is_server = false (visitor is QUIC client)
            )
            .await?;
            Ok(TunnelSession::Quic(s))
        }
        #[cfg(not(all(feature = "quic", feature = "kcp")))]
        {
            warn!(visitor_name = %cfg.visitor_name, "Visitor '{}': protocol 'quic' requires both the quic and kcp features (the QUIC data plane reuses the KCP hole-punch machinery); refusing to silently fall back to KCP (Go peers may be on a QUIC data plane)", cfg.visitor_name);
            Err(format!(
                "Visitor '{}': protocol 'quic' requires both the quic and kcp features",
                cfg.visitor_name
            ))
        }
    } else {
        let s = frp_core::xtcp_p2p::xtcp_p2p_connect_yamux_session(
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
        .await?;
        Ok(TunnelSession::Kcp(s))
    }
}

/// Go frp v0.71 `processTunnelStartEvents`: on each start signal, punch a
/// new hole and swap the fresh session into the slot (closing the old one
/// first). At least `MIN_PUNCH_INTERVAL` between punches.
async fn process_tunnel_start_events(
    cfg: XtcpPunchConfig,
    slot: Arc<tokio::sync::Mutex<Option<Arc<TunnelSession>>>>,
    mut start_rx: mpsc::Receiver<()>,
    armed: &AtomicBool,
    cancel: CancellationToken,
) {
    loop {
        // Parked-gate (Go unbuffered startTunnelCh): while this receiver is
        // parked in recv, non-blocking senders may deliver a signal; once a
        // signal arrives the gate drops — the receiver is busy punching and
        // sleeping, and further signals are dropped, exactly like a send to
        // Go's unbuffered channel while the receiver is not in select.
        armed.store(true, Ordering::Relaxed);
        tokio::select! {
            _ = cancel.cancelled() => return,
            _ = start_rx.recv() => {
                armed.store(false, Ordering::Relaxed);
                let start = std::time::Instant::now();
                match do_hole_punch(&cfg).await {
                    Ok(new_session) => {
                        let old = {
                            let mut guard = slot.lock().await;
                            guard.replace(Arc::new(new_session))
                        };
                        if let Some(old) = old {
                            old.close().await;
                        }
                        info!(visitor_name = %cfg.visitor_name, "Visitor '{}': XTCP tunnel session (re)established", cfg.visitor_name);
                    }
                    Err(e) => {
                        warn!(visitor_name = %cfg.visitor_name, error = %e, "Visitor '{}': XTCP hole punch failed: {}", cfg.visitor_name, e);
                    }
                }
                // avoid too frequently (Go: sleep remainder of 10s)
                let elapsed = start.elapsed();
                if elapsed < MIN_PUNCH_INTERVAL {
                    tokio::select! {
                        _ = tokio::time::sleep(MIN_PUNCH_INTERVAL - elapsed) => {}
                        _ = cancel.cancelled() => return,
                    }
                }
            }
        }
    }
}

/// Go frp v0.71 `getTunnelConn`: open a stream on the persistent session; on
/// any error, close + clear the session and signal `startTunnelCh`
/// (non-blocking) so `process_tunnel_start_events` re-punches. The signal
/// fires on EVERY error path — empty slot included (Go: getTunnelConn sends
/// the non-blocking startTunnelCh after any OpenConn failure) — gated on the
/// receiver being parked (`armed`): Go's unbuffered channel drops the signal
/// when the receiver is busy punching/sleeping, so the gate keeps the
/// cap-1 channel empty and drops those signals too.
async fn get_tunnel_conn(
    slot: &Arc<tokio::sync::Mutex<Option<Arc<TunnelSession>>>>,
    start_tx: &mpsc::Sender<()>,
    armed: &AtomicBool,
    timeout: Duration,
) -> Result<Box<dyn frp_core::xtcp_p2p::P2pStream>, String> {
    let session = {
        let guard = slot.lock().await;
        match guard.as_ref() {
            Some(s) => s.clone(),
            None => {
                // Go parity: getTunnelConn signals startTunnelCh (non-blocking)
                // on every error path — with keep_tunnel_open=false the first
                // user connection's failure is what triggers the initial punch.
                if armed.load(Ordering::Relaxed) {
                    let _ = start_tx.try_send(());
                }
                return Err("no tunnel session".into());
            }
        }
    };
    match session.open_stream(timeout).await {
        Ok(stream) => Ok(stream),
        Err(e) => {
            // The session is dead: close it, and clear the slot only if it
            // still holds THIS session (a re-punch may have swapped in a
            // fresh one while we were failing). Then signal a re-punch —
            // only when we cleared the slot, so a fresh session is not
            // churned by a stale failure; gated on the receiver parked.
            session.close().await;
            let mut guard = slot.lock().await;
            let cleared = guard
                .as_ref()
                .map(|cur| Arc::ptr_eq(cur, &session))
                .unwrap_or(false);
            if cleared {
                guard.take();
            }
            drop(guard);
            if cleared && armed.load(Ordering::Relaxed) {
                let _ = start_tx.try_send(());
            }
            Err(e)
        }
    }
}

/// Go frp v0.71 `openTunnel`: poll `get_tunnel_conn` until a tunnel stream is
/// available or `budget` expires. The effective budget is capped at 20s — Go
/// ALWAYS wraps the caller's ctx in `context.WithTimeout(ctx, 20s)`
/// (xtcp.go:202-206), so when `fallback_to` is set the budget is
/// min(20s, fallback_timeout_ms), never the raw fallback timeout. Each probe
/// is bounded by 500ms so a dead session cannot eat the whole budget on one
/// attempt (Go: OpenConn carries the full deadline, timer.Reset(500ms) paces
/// retries).
async fn open_tunnel(
    visitor_name: &str,
    slot: &Arc<tokio::sync::Mutex<Option<Arc<TunnelSession>>>>,
    start_tx: &mpsc::Sender<()>,
    armed: &AtomicBool,
    conn_cancel: &CancellationToken,
    budget: Duration,
) -> Result<Box<dyn frp_core::xtcp_p2p::P2pStream>, String> {
    let deadline = tokio::time::Instant::now() + budget;
    loop {
        if conn_cancel.is_cancelled() {
            return Err("visitor shutting down".into());
        }
        match get_tunnel_conn(slot, start_tx, armed, Duration::from_millis(500)).await {
            Ok(stream) => return Ok(stream),
            Err(e) => {
                debug!(visitor_name = %visitor_name, error = %e, "Visitor '{}': open tunnel attempt failed: {}", visitor_name, e);
                if tokio::time::Instant::now() >= deadline {
                    return Err(format!("open tunnel timeout after {budget:?}"));
                }
            }
        }
        // Pace attempts (Go: timer.Reset(500ms)); a healthy session answers
        // in milliseconds so this only paces failures. Cancellation-aware: a
        // bare sleep would park up to 500ms past shutdown.
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_millis(500)) => {}
            _ = conn_cancel.cancelled() => return Err("visitor shutting down".into()),
        }
    }
}

/// Go frp v0.71 `keepTunnelOpenWorker`: keep a live session punched in the
/// background. FIRST action is a BLOCKING startTunnelCh send (initial
/// punch); then every `min_retry_interval` seconds probe the session via
/// `get_tunnel_conn` — a healthy session yields a probe stream that is
/// closed immediately; a failure waits on the retry limiter (token bucket:
/// `max_retries_an_hour` per hour) before the next tick.
async fn keep_tunnel_open_worker(
    cfg: XtcpPunchConfig,
    slot: Arc<tokio::sync::Mutex<Option<Arc<TunnelSession>>>>,
    start_tx: mpsc::Sender<()>,
    armed: &AtomicBool,
    cancel: CancellationToken,
    min_retry_interval: i64,
    max_retries_an_hour: i32,
) {
    // FIRST action: blocking send (Go: `sv.startTunnelCh <- struct{}{}`).
    // UNGATED on purpose: Go's initial send blocks until received; the
    // cap-1 buffer absorbs it if the receiver has not parked yet (the gate
    // covers only non-blocking sends — same net effect).
    tokio::select! {
        _ = start_tx.send(()) => {}
        _ = cancel.cancelled() => return,
    }
    // Token bucket: burst = max_retries_an_hour, one token per
    // (3600 / max_retries_an_hour) seconds (Go
    // rate.NewLimiter(rate.Every(Hour/MaxRetriesAnHour), MaxRetriesAnHour)).
    // The limiter starts full (Go rate.NewLimiter initial burst).
    let burst = max_retries_an_hour.max(1) as usize;
    let refill_secs = (3600.0 / max_retries_an_hour.max(1) as f64).max(1.0);
    let mut tokens = burst;
    let mut ticker = tokio::time::interval(Duration::from_secs(min_retry_interval.max(1) as u64));
    // Consume the immediate first tick: the initial punch above already
    // covers the first check (Go's ticker also fires after one interval).
    ticker.tick().await;
    loop {
        tokio::select! {
            _ = cancel.cancelled() => return,
            _ = ticker.tick() => {
                // Probe the session: open a stream (bounded — a healthy
                // session answers in milliseconds; 30s covers a
                // dead-but-undetected peer until KCP dead-link trips).
                // On success close the probe stream; on failure rate-limit
                // and continue (Go: retryLimiter.Wait + continue).
                match get_tunnel_conn(&slot, &start_tx, armed, Duration::from_secs(30)).await
                {
                    Ok(stream) => drop(stream),
                    Err(e) => {
                        warn!(visitor_name = %cfg.visitor_name, error = %e, "Visitor '{}': keepTunnelOpenWorker probe failed, rate-limiting retries", cfg.visitor_name);
                        tokio::select! {
                            _ = cancel.cancelled() => return,
                            _ = wait_for_retry_token(&mut tokens, refill_secs) => {}
                        }
                    }
                }
            }
        }
    }
}

/// Wait for the next retry token (token bucket, single consumer — the
/// `keepTunnelOpenWorker`). Consumes one token when the burst is available;
/// otherwise sleeps one refill interval (Go `rate.Limiter.Wait`).
async fn wait_for_retry_token(tokens: &mut usize, refill_secs: f64) {
    if *tokens > 0 {
        *tokens -= 1;
        return;
    }
    tokio::time::sleep(Duration::from_secs_f64(refill_secs)).await;
    // Tokens stay at 0: the sleep IS the refill for this single consumer.
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

/// Runs a bridge future to completion, aborting early when the
/// per-connection cancellation token is cancelled (listener teardown /
/// proxy removal). Without the select, the bridge task holds the UDP fd +
/// KCP session + yamux and a 10ms driver task forever while the peer is
/// alive. Returns true when the bridge completed normally; false when the
/// token was cancelled (callers return and drop the bridge halves).
async fn bridge_until_cancelled(
    visitor_name: &str,
    closed_debug: &str,
    abort_info: &str,
    conn_cancel: &CancellationToken,
    bridge_fut: impl Future,
) -> bool {
    tokio::select! {
        _ = bridge_fut => {
            debug!(visitor_name = %visitor_name, "Visitor '{}' {} closed", visitor_name, closed_debug);
            true
        }
        _ = conn_cancel.cancelled() => {
            info!(visitor_name = %visitor_name, "Visitor '{}': {}", visitor_name, abort_info);
            false
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

    // Parent cancellation token: every accepted connection gets a child token,
    // cancelled when the listener exits (shutdown, accept error, or the
    // listener task being aborted). In-flight connection tasks otherwise run
    // to completion after shutdown — an XTCP visitor with keep_tunnel_open
    // retries for up to an hour per connection. Go frpc cancels a per-visitor
    // context on teardown; the token is the Rust equivalent. The drop guard
    // covers the abort path (service.rs aborts a listener stuck in accept()
    // after 500ms): dropping the guard cancels the parent and every child.
    let listener_cancel = CancellationToken::new();
    let _cancel_guard = listener_cancel.clone().drop_guard();

    // XTCP: persistent tunnel session state (Go frp v0.71 keepTunnelOpenWorker).
    // One session slot + start-signal channel per listener, shared by the
    // accept loop (open_tunnel → get_tunnel_conn), the background re-punch
    // task (process_tunnel_start_events) and — when keep_tunnel_open is set —
    // the keepTunnelOpenWorker. The session outlives individual user
    // connections; only listener teardown cancels the background tasks.
    let tunnel_slot: Arc<tokio::sync::Mutex<Option<Arc<TunnelSession>>>> =
        Arc::new(tokio::sync::Mutex::new(None));
    // Go: `startTunnelCh: make(chan struct{})` is UNBUFFERED (visitor.go:114)
    // — a non-blocking send succeeds only while the receiver is parked in
    // select. tokio's mpsc panics on capacity 0 ("requires buffer > 0"), so
    // the cap-1 channel plus the `start_armed` flag emulate the Go unbuffered
    // parked-gate: try_sends are gated on the flag (set only while the
    // receiver is parked in recv), so a signal is never buffered mid-punch —
    // the cap-1 slot stays empty.
    let (start_tx, start_rx) = mpsc::channel::<()>(1);
    let start_armed: Arc<AtomicBool> = Arc::new(AtomicBool::new(false));

    if visitor_type == "xtcp" {
        let punch_cfg = XtcpPunchConfig {
            visitor_name: name.clone(),
            sn: server_name.clone(),
            sk: secret_key.clone(),
            stun_server: stun_server.clone(),
            pp: p2p_protocol.clone(),
            daa: disable_assisted_addrs,
            vtx: visitor_tx.clone(),
        };
        // processTunnelStartEvents (Go parity): re-punch on demand, ≥10s
        // apart. Runs for the listener lifetime. It owns the receiver side of
        // the parked-gate: armed=true only while it is parked in recv.
        let slot_ev = tunnel_slot.clone();
        let cancel_ev = listener_cancel.clone();
        let punch_cfg_ev = punch_cfg.clone();
        let armed_ev = start_armed.clone();
        tokio::spawn(async move {
            process_tunnel_start_events(punch_cfg_ev, slot_ev, start_rx, &armed_ev, cancel_ev).await
        });
        if keep_tunnel_open {
            // keepTunnelOpenWorker (Go parity): keep the tunnel punched in
            // the background. NO per-connection retry loop anymore — user
            // connections wait on the session via open_tunnel.
            let slot_w = tunnel_slot.clone();
            let start_tx_w = start_tx.clone();
            let cancel_w = listener_cancel.clone();
            let armed_w = start_armed.clone();
            tokio::spawn(async move {
                keep_tunnel_open_worker(
                    punch_cfg,
                    slot_w,
                    start_tx_w,
                    &armed_w,
                    cancel_w,
                    min_retry_interval,
                    max_retries_an_hour,
                )
                .await
            });
        }
    }

    loop {
        // Check graceful shutdown signal before each accept (Go frp compat:
        // visitor listeners exit cleanly instead of being aborted).
        if shutdown.load(Ordering::Relaxed) {
            info!(name = %name, "Visitor '{}' shutting down gracefully", name);
            listener_cancel.cancel();
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
                let fb_to = fallback_to.clone();
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

                // Per-connection shutdown token: a child of the listener
                // token, cancelled on listener exit so this task aborts its
                // open-tunnel wait / pending bridge instead of running out its
                // budget after shutdown has been requested. The child dies
                // with the task — no pruning needed.
                let conn_cancel = listener_cancel.child_token();

                // XTCP: the listener's session slot + re-punch signal, shared
                // with the background tasks above (Go v0.71 persistent tunnel).
                // `start_armed` is the parked-gate: signals only reach the
                // receiver while it is parked in recv (Go unbuffered
                // startTunnelCh semantics).
                let tunnel_slot = tunnel_slot.clone();
                let start_tx = start_tx.clone();
                let start_armed = start_armed.clone();

                tokio::spawn(async move {
                    // Dial options for STCP fallback (fresh connections only).
                    let plan =
                        plan_visitor_dial(&sa, sp, &pt, tls_enable, &tls_sn, &tls_ca, &transport);
                    let opts = plan.opts;
                    let yamux_keepalive = plan.yamux_keepalive_secs;

                    if vt == "xtcp" {
                        // --- XTCP persistent tunnel session (Go frp v0.71) ---
                        // The listener owns ONE hole-punched data-plane session,
                        // reused across user connections (Go getTunnelConn /
                        // openTunnel). A dead session is closed + re-punched in
                        // the background by process_tunnel_start_events; there is
                        // NO per-connection punch+retry loop anymore.
                        // Wrap in Option — P2P success arm moves it out via take().
                        let mut user_conn = Some(user_conn);

                        // Go openTunnel budget: openTunnel ALWAYS wraps the
                        // ctx in a 20s timeout (xtcp.go:202-206), so with
                        // fallback_to set the effective budget is
                        // min(20s, fallback_timeout_ms) — never the raw
                        // fallback timeout. A failing open signals the
                        // background re-punch (startTunnelCh) inside the
                        // budget.
                        let budget = if fb_to.is_empty() {
                            Duration::from_secs(20)
                        } else {
                            Duration::from_millis(fallback_timeout_ms.clamp(1, 20_000))
                        };
                        match open_tunnel(
                            &visitor_name,
                            &tunnel_slot,
                            &start_tx,
                            &start_armed,
                            &conn_cancel,
                            budget,
                        )
                        .await
                        {
                            Ok(mut p2p_stream) => {
                                // Shutdown boundary: don't start the P2P bridge —
                                // drop the user connection and return.
                                if conn_cancel.is_cancelled() {
                                    info!(visitor_name = %visitor_name, "Visitor '{}': shutting down, abandoning XTCP P2P connection", visitor_name);
                                    return; // drops the user connection unbridged
                                }
                                info!(visitor_name = %visitor_name, "Visitor '{}': XTCP P2P connected", visitor_name);
                                let use_enc = use_encryption && !sk.is_empty();
                                let (user_r, user_w) = user_conn
                                    .take()
                                    .expect("user_conn set Some above, not yet consumed")
                                    .into_split();
                                let (p2p_r, p2p_w) = tokio::io::split(&mut p2p_stream);
                                if use_enc {
                                    let key = frp_core::encryption::derive_key(&sk);
                                    if !bridge_until_cancelled(
                                        &visitor_name,
                                        "XTCP encrypted P2P",
                                        "shutting down, aborting XTCP encrypted P2P bridge",
                                        &conn_cancel,
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
                                            false,
                                        ),
                                    )
                                    .await
                                    {
                                        return; // drops both bridge halves
                                    }
                                } else if !bridge_until_cancelled(
                                    &visitor_name,
                                    "XTCP",
                                    "shutting down, aborting XTCP P2P bridge",
                                    &conn_cancel,
                                    frp_core::bridge::bridge_plain(
                                        user_r,
                                        user_w,
                                        p2p_r,
                                        p2p_w,
                                        use_compression,
                                        vec![],
                                        None,
                                        None,
                                    ),
                                )
                                .await
                                {
                                    return; // drops both bridge halves
                                }
                                return; // XTCP P2P succeeded (bridge ended)
                            }
                            Err(e) => {
                                debug!(visitor_name = %visitor_name, error = %e, "Visitor '{}': open tunnel failed, trying STCP fallback: {}", visitor_name, e);
                            }
                        }

                        // Unwrap user_conn for STCP fallback (tunnel open failed, so not moved).
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

                        // Shutdown boundary: don't start the fallback relay —
                        // drop the user connection and return.
                        if conn_cancel.is_cancelled() {
                            info!(visitor_name = %visitor_name, "Visitor '{}': shutting down, abandoning STCP fallback connection", visitor_name);
                            return; // drops the user connection unbridged
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
                            if !bridge_until_cancelled(
                                &visitor_name,
                                "STCP fallback encrypted relay",
                                "shutting down, aborting STCP fallback encrypted relay",
                                &conn_cancel,
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
                                    false,
                                ),
                            )
                            .await
                            {}
                        } else {
                            if !bridge_until_cancelled(
                                &visitor_name,
                                "STCP fallback relay",
                                "shutting down, aborting STCP fallback relay",
                                &conn_cancel,
                                frp_core::bridge::bridge_plain(
                                    user_r,
                                    user_w,
                                    srv_r,
                                    srv_w,
                                    use_compression,
                                    vec![],
                                    None,
                                    None,
                                ),
                            )
                            .await
                            {}
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

                        // Shutdown boundary: don't start the relay bridge —
                        // drop the user connection and return.
                        if conn_cancel.is_cancelled() {
                            info!(visitor_name = %visitor_name, "Visitor '{}': shutting down, abandoning STCP connection", visitor_name);
                            return; // drops the user connection unbridged
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
                            if !bridge_until_cancelled(
                                &visitor_name,
                                "STCP encrypted relay",
                                "shutting down, aborting STCP encrypted relay",
                                &conn_cancel,
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
                                    false,
                                ),
                            )
                            .await
                            {}
                        } else {
                            if !bridge_until_cancelled(
                                &visitor_name,
                                "STCP relay",
                                "shutting down, aborting STCP relay",
                                &conn_cancel,
                                frp_core::bridge::bridge_plain(
                                    user_r,
                                    user_w,
                                    srv_r,
                                    srv_w,
                                    use_compression,
                                    vec![],
                                    None,
                                    None,
                                ),
                            )
                            .await
                            {}
                        }
                    }
                });
            }
            Err(e) => {
                warn!(name = %name, error = %e, "Visitor '{}': accept error: {}", name, e);
                listener_cancel.cancel();
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
    // Reused binary-codec wire buffer (write side; the `scratch` inside the
    // loop is the read side).
    let mut wire_scratch: Vec<u8> = Vec::new();
    // The first packet (which triggered the connect) is written immediately.
    let first_write = if v2 {
        write_msg_v2_with_udp_codec(
            &mut srv_w,
            &FrpMessage::UDPPacket(first_pkt),
            udp_codec_opt,
            false,
            &mut wire_scratch,
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
    // Reusable payload buffer for the V2 UDP read path (avoids a heap alloc
    // per UDP packet).
    let mut scratch = Vec::new();
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
                                &mut wire_scratch,
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
                    read_msg_v2_with_udp_codec(&mut srv_r, udp_codec_opt, &mut scratch).await
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

#[cfg(all(test, feature = "kcp"))]
mod tunnel_session_tests {
    use super::*;

    /// Hole-punch two loopback UDP sockets into a yamux session pair
    /// (Rust↔Rust "frp" magic, no sid/key — same pattern as
    /// frp-core/tests/xtcp_p2p.rs). Returns (server/provider, client/visitor)
    /// sessions; both drivers run in the background.
    async fn loopback_session_pair() -> (Arc<TunnelSession>, Arc<TunnelSession>) {
        let sock_a = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let sock_b = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr_a = sock_a.local_addr().unwrap();
        let addr_b = sock_b.local_addr().unwrap();
        let cand_b = vec![addr_b.to_string()];
        let cand_a = vec![addr_a.to_string()];
        let kcp_cfg = frp_core::kcp::default_kcp_config();
        let conv = 42u32;
        let (server, client) = tokio::join!(
            frp_core::xtcp_p2p::xtcp_p2p_connect_yamux_session(
                sock_a,
                &cand_b,
                &[],
                None,
                conv,
                kcp_cfg.clone(),
                3000,
                false, // yamux_client = false (provider)
                None,
                None,
            ),
            frp_core::xtcp_p2p::xtcp_p2p_connect_yamux_session(
                sock_b,
                &cand_a,
                &[],
                None,
                conv,
                kcp_cfg,
                3000,
                true, // yamux_client = visitor
                None,
                None,
            ),
        );
        let server = server.expect("server-side session");
        let client = client.expect("client-side session");
        (
            Arc::new(TunnelSession::Kcp(server)),
            Arc::new(TunnelSession::Kcp(client)),
        )
    }

    /// get_tunnel_conn on an empty slot fails immediately AND signals a
    /// re-punch (Go getTunnelConn sends the non-blocking startTunnelCh signal
    /// on every error path, empty slot included — with keep_tunnel_open=false
    /// the first user connection's failure is what triggers the initial
    /// punch). armed=true + cap-1 channel: try_send always succeeds,
    /// making the "signal is sent" assertion deterministic.
    #[tokio::test]
    async fn get_tunnel_conn_empty_slot_signals_repunch() {
        let slot: Arc<tokio::sync::Mutex<Option<Arc<TunnelSession>>>> =
            Arc::new(tokio::sync::Mutex::new(None));
        let (start_tx, mut start_rx) = mpsc::channel::<()>(1);
        let armed = AtomicBool::new(true);
        let err = get_tunnel_conn(&slot, &start_tx, &armed, Duration::from_millis(100)).await;
        match err {
            Err(e) => assert!(
                e.contains("no tunnel session"),
                "error must mention no tunnel session, got: {e}"
            ),
            Ok(_) => panic!("empty slot must error"),
        }
        assert!(
            start_rx.try_recv().is_ok(),
            "empty slot must signal a re-punch"
        );
    }

    /// get_tunnel_conn on an empty slot with the parked-gate DOWN (receiver
    /// busy punching) drops the signal — Go unbuffered startTunnelCh: a send
    /// only succeeds while the receiver is parked in select.
    #[tokio::test]
    async fn get_tunnel_conn_empty_slot_armed_false_drops_signal() {
        let slot: Arc<tokio::sync::Mutex<Option<Arc<TunnelSession>>>> =
            Arc::new(tokio::sync::Mutex::new(None));
        let (start_tx, mut start_rx) = mpsc::channel::<()>(1);
        let armed = AtomicBool::new(false);
        let err = get_tunnel_conn(&slot, &start_tx, &armed, Duration::from_millis(100)).await;
        match err {
            Err(e) => assert!(
                e.contains("no tunnel session"),
                "error must mention no tunnel session, got: {e}"
            ),
            Ok(_) => panic!("empty slot must error"),
        }
        // Parked recv: nothing may arrive (armed=false dropped the signal).
        let recv_task = tokio::spawn(async move { start_rx.recv().await });
        assert!(
            tokio::time::timeout(Duration::from_millis(200), recv_task)
                .await
                .is_err(),
            "armed=false must drop the re-punch signal"
        );
    }

    /// get_tunnel_conn on a dead session: errors, clears the slot, and
    /// signals startTunnelCh (triggering a re-punch). Every error path
    /// signals — a second call on the cleared slot errors AND re-signals
    /// (Go: getTunnelConn sends the non-blocking startTunnelCh on any error;
    /// in production the armed gate drops it unless the receiver is parked,
    /// so there is no pile-up).
    #[tokio::test]
    async fn get_tunnel_conn_dead_session_clears_slot_and_signals_repunch() {
        let (_server, client) = loopback_session_pair().await;
        let slot: Arc<tokio::sync::Mutex<Option<Arc<TunnelSession>>>> =
            Arc::new(tokio::sync::Mutex::new(None));
        *slot.lock().await = Some(client.clone());
        let (start_tx, mut start_rx) = mpsc::channel::<()>(1);
        let armed = AtomicBool::new(true);

        // Close the session → open_stream fails (alive=false).
        client.close().await;
        let err = get_tunnel_conn(&slot, &start_tx, &armed, Duration::from_millis(100)).await;
        assert!(err.is_err(), "closed session must fail open_stream");
        assert!(slot.lock().await.is_none(), "dead session must be cleared");
        assert!(
            start_rx.try_recv().is_ok(),
            "clearing the slot must signal a re-punch"
        );
        // Second call: slot is empty → error, but STILL signals (Go: every
        // error path sends the non-blocking signal; the armed gate only drops
        // it when the receiver is not parked).
        let err = get_tunnel_conn(&slot, &start_tx, &armed, Duration::from_millis(100)).await;
        assert!(err.is_err());
        assert!(
            start_rx.try_recv().is_ok(),
            "empty slot must still signal a re-punch"
        );
    }

    /// get_tunnel_conn on a live session opens a stream without touching the
    /// slot or signalling a re-punch.
    #[tokio::test]
    async fn get_tunnel_conn_live_session_opens_stream() {
        let (server, client) = loopback_session_pair().await;
        let slot: Arc<tokio::sync::Mutex<Option<Arc<TunnelSession>>>> =
            Arc::new(tokio::sync::Mutex::new(None));
        *slot.lock().await = Some(client.clone());
        let (start_tx, mut start_rx) = mpsc::channel::<()>(1);
        let armed = AtomicBool::new(true);

        // Provider side accepts (the driver pushes the stream into the
        // inbound queue; accept completes the yamux open).
        let accept_task = tokio::spawn({
            let server = server.clone();
            async move {
                server
                    .accept_stream(Duration::from_secs(3))
                    .await
                    .expect("provider accept_stream")
            }
        });
        let stream = get_tunnel_conn(&slot, &start_tx, &armed, Duration::from_secs(3))
            .await
            .expect("live session must open a stream");
        let _accepted = accept_task.await.expect("accept task");

        assert!(
            slot.lock().await.is_some(),
            "live session stays in the slot"
        );
        assert!(
            start_rx.try_recv().is_err(),
            "successful open must not signal a re-punch"
        );
        drop(stream); // closes the probe stream
        assert!(client.is_alive(), "session survives a stream close");
    }

    /// open_tunnel polls (every 500ms) until a session appears in the slot;
    /// the budget bounds the wait.
    #[tokio::test]
    async fn open_tunnel_polls_until_session_appears() {
        let (server, client) = loopback_session_pair().await;
        let slot: Arc<tokio::sync::Mutex<Option<Arc<TunnelSession>>>> =
            Arc::new(tokio::sync::Mutex::new(None));
        let (start_tx, _start_rx) = mpsc::channel::<()>(1);
        let armed = AtomicBool::new(true);
        let conn_cancel = CancellationToken::new();

        // Populate the slot + start accepting after 300ms — the first probe
        // fails, later ones succeed.
        let accept_task = tokio::spawn({
            let server = server.clone();
            async move {
                tokio::time::sleep(Duration::from_millis(300)).await;
                server
                    .accept_stream(Duration::from_secs(3))
                    .await
                    .expect("provider accept_stream")
            }
        });
        tokio::spawn({
            let slot = slot.clone();
            let client = client.clone();
            async move {
                tokio::time::sleep(Duration::from_millis(300)).await;
                *slot.lock().await = Some(client);
            }
        });
        let stream = open_tunnel(
            "t",
            &slot,
            &start_tx,
            &armed,
            &conn_cancel,
            Duration::from_secs(5),
        )
        .await
        .expect("open_tunnel must poll until the session appears");
        let _accepted = accept_task.await.expect("accept task");
        drop(stream);
    }

    /// open_tunnel gives up once the budget is exhausted.
    #[tokio::test]
    async fn open_tunnel_times_out_without_session() {
        let slot: Arc<tokio::sync::Mutex<Option<Arc<TunnelSession>>>> =
            Arc::new(tokio::sync::Mutex::new(None));
        let (start_tx, _start_rx) = mpsc::channel::<()>(1);
        let armed = AtomicBool::new(true);
        let conn_cancel = CancellationToken::new();
        let start = std::time::Instant::now();
        let result = open_tunnel(
            "t",
            &slot,
            &start_tx,
            &armed,
            &conn_cancel,
            Duration::from_millis(150),
        )
        .await;
        let err = match result {
            Err(e) => e,
            Ok(_) => panic!("empty slot with a tiny budget must time out"),
        };
        assert!(
            err.contains("timeout"),
            "error must mention the timeout, got: {err}"
        );
        assert!(
            start.elapsed() < Duration::from_secs(2),
            "timeout must respect the budget (elapsed {:?})",
            start.elapsed()
        );
    }

    /// open_tunnel aborts on cancellation even with a budget left.
    #[tokio::test]
    async fn open_tunnel_aborts_on_cancellation() {
        let slot: Arc<tokio::sync::Mutex<Option<Arc<TunnelSession>>>> =
            Arc::new(tokio::sync::Mutex::new(None));
        let (start_tx, _start_rx) = mpsc::channel::<()>(1);
        let armed = AtomicBool::new(true);
        let conn_cancel = CancellationToken::new();
        let task = tokio::spawn({
            let slot = slot.clone();
            let start_tx = start_tx.clone();
            let conn_cancel = conn_cancel.clone();
            async move {
                open_tunnel(
                    "t",
                    &slot,
                    &start_tx,
                    &armed,
                    &conn_cancel,
                    Duration::from_secs(30),
                )
                .await
            }
        });
        tokio::time::sleep(Duration::from_millis(100)).await;
        conn_cancel.cancel();
        let result = task.await.expect("open_tunnel task");
        let err = match result {
            Err(e) => e,
            Ok(_) => panic!("cancelled wait must error"),
        };
        assert!(err.contains("shutting down"), "got: {err}");
    }

    /// keepTunnelOpenWorker's FIRST action is a blocking startTunnelCh send
    /// (the initial punch signal), even with an empty slot.
    #[tokio::test]
    async fn keep_tunnel_open_worker_sends_initial_punch_signal() {
        let slot: Arc<tokio::sync::Mutex<Option<Arc<TunnelSession>>>> =
            Arc::new(tokio::sync::Mutex::new(None));
        let (start_tx, mut start_rx) = mpsc::channel::<()>(1);
        let (vtx, _vtx_rx) = mpsc::channel::<crate::service::VisitorRequest>(1);
        let cfg = XtcpPunchConfig {
            visitor_name: "t".into(),
            sn: "tunnel".into(),
            sk: String::new(),
            stun_server: String::new(),
            pp: "kcp".into(),
            daa: true,
            vtx,
        };
        let cancel = CancellationToken::new();
        let armed = AtomicBool::new(true);
        let worker = tokio::spawn({
            let cfg = cfg.clone();
            let slot = slot.clone();
            let start_tx = start_tx.clone();
            let cancel = cancel.clone();
            async move {
                keep_tunnel_open_worker(cfg, slot, start_tx, &armed, cancel, 1, 8).await;
            }
        });
        tokio::time::timeout(Duration::from_secs(3), start_rx.recv())
            .await
            .expect("initial punch signal must be sent")
            .expect("channel open");
        cancel.cancel();
        let _ = worker.await;
    }

    /// keepTunnelOpenWorker probes the session every min_retry_interval; a
    /// dead session fails the probe, gets cleared, and re-signals
    /// startTunnelCh.
    #[tokio::test]
    async fn keep_tunnel_open_worker_probes_and_resignals_on_dead_session() {
        let (_server, client) = loopback_session_pair().await;
        client.close().await;
        let slot: Arc<tokio::sync::Mutex<Option<Arc<TunnelSession>>>> =
            Arc::new(tokio::sync::Mutex::new(None));
        *slot.lock().await = Some(client.clone());
        let (start_tx, mut start_rx) = mpsc::channel::<()>(1);
        let (vtx, _vtx_rx) = mpsc::channel::<crate::service::VisitorRequest>(1);
        let cfg = XtcpPunchConfig {
            visitor_name: "t".into(),
            sn: "tunnel".into(),
            sk: String::new(),
            stun_server: String::new(),
            pp: "kcp".into(),
            daa: true,
            vtx,
        };
        let cancel = CancellationToken::new();
        let armed = AtomicBool::new(true);
        let worker = tokio::spawn({
            let slot = slot.clone();
            let start_tx = start_tx.clone();
            let cancel = cancel.clone();
            async move {
                keep_tunnel_open_worker(cfg, slot, start_tx, &armed, cancel, 1, 8).await;
            }
        });
        // Initial punch signal (first action).
        tokio::time::timeout(Duration::from_secs(3), start_rx.recv())
            .await
            .expect("initial punch signal")
            .expect("channel open");
        // The first tick (1s) probes the dead session → cleared + re-signal.
        tokio::time::timeout(Duration::from_secs(5), start_rx.recv())
            .await
            .expect("re-punch signal after dead probe")
            .expect("channel open");
        assert!(slot.lock().await.is_none(), "dead session must be cleared");
        cancel.cancel();
        let _ = worker.await;
    }

    /// The retry token bucket: burst tokens are consumed without waiting; an
    /// exhausted bucket sleeps one refill interval.
    #[tokio::test]
    async fn retry_token_bucket_limits_consecutive_failures() {
        let mut tokens = 2usize;
        let start = tokio::time::Instant::now();
        wait_for_retry_token(&mut tokens, 10.0).await;
        wait_for_retry_token(&mut tokens, 10.0).await;
        assert_eq!(tokens, 0);
        assert!(
            start.elapsed() < Duration::from_millis(100),
            "burst tokens must not sleep (elapsed {:?})",
            start.elapsed()
        );
        // Exhausted bucket sleeps one refill interval.
        let start = tokio::time::Instant::now();
        wait_for_retry_token(&mut tokens, 0.05).await;
        assert!(
            start.elapsed() >= Duration::from_millis(50),
            "exhausted bucket must sleep the refill interval (elapsed {:?})",
            start.elapsed()
        );
    }
}

#[cfg(test)]
mod bridge_cancel_tests {
    use super::*;

    /// The shared bridge-until-cancelled helper (used by the XTCP P2P and
    /// STCP relay sites) must abort when the per-connection cancellation
    /// token is cancelled (listener teardown / proxy removal). Without the
    /// select, the bridge task holds the UDP fd + KCP session + yamux and a
    /// 10ms driver task forever while the peer is alive. Two duplex pairs
    /// stand in for the user connection and the peer stream; bridge_plain
    /// would block on reads indefinitely, so only the cancellation arm can
    /// resolve the select.
    #[tokio::test]
    async fn p2p_bridge_cancels_on_token_cancel() {
        let (user_a, _user_b) = tokio::io::duplex(8192);
        let (p2p_a, _p2p_b) = tokio::io::duplex(8192);
        let (user_r, user_w) = tokio::io::split(user_a);
        let (p2p_r, p2p_w) = tokio::io::split(p2p_a);
        let conn_cancel = CancellationToken::new();
        let bridge_cancel = conn_cancel.clone();

        let bridge_task = tokio::spawn(async move {
            // Production bridge site: exercises the same select path the
            // XTCP P2P / STCP relay sites use.
            bridge_until_cancelled(
                "test",
                "XTCP",
                "shutting down, aborting XTCP P2P bridge",
                &bridge_cancel,
                frp_core::bridge::bridge_plain(
                    user_r,
                    user_w,
                    p2p_r,
                    p2p_w,
                    false,
                    vec![],
                    None,
                    None,
                ),
            )
            .await;
        });

        conn_cancel.cancel();
        tokio::time::timeout(Duration::from_secs(1), bridge_task)
            .await
            .expect("bridge must abort when the connection token is cancelled")
            .expect("bridge task must not panic");
    }
}
