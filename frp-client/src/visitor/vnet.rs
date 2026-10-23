//! The `virtual_net` visitor cluster: the no-bind visitor tunnel
//! (`run_virtual_net_visitor` + `VirtualNetVisitorConfig`), its established-tunnel
//! packet loop (`run_virtual_net_tunnel_io`), the TUN-ingress fan-out
//! (`deliver_tunnel_ingress`), the two shutdown waiters
//! (`wait_for_shutdown_or_delay`, `wait_for_shutdown_signal`) and the
//! `VnetTunTxMap`/`VnetTunSubnetMap` aliases those items share.
//!
//! Its reconnect backoff (`virtual_net_reconnect_delay`, `VirtualNetTunnelEnd`,
//! `next_reconnect_delay`, `wait_after_virtual_net_round`) mirrors Go frp's
//! virtual_net plugin: the setup-failure backoff dates from v0.71.0, the
//! bounded (non-overflowing) delay computation from v0.71.1.
//!
//! Split out of `frp-client/src/visitor.rs` by the plan's P3 seam 4
//! (`docs/refactor-large-modules.md` P3, `visitor/vnet.rs`) as a pure move:
//! every moved line is byte-for-byte identical to its base text (the seam-4
//! report carries the per-span sha1s). This module is a *child* of `visitor`,
//! so through `use super::*;` it reaches the parent-private items the moved
//! code needs — `VisitorTransportConfig` and `plan_visitor_dial` — plus the
//! parent's own imports (`mpsc`, `Arc`, `Duration`, `Instant`, `AtomicBool`,
//! `Ordering`, the tracing macros, `frp_core::mux::YamuxSession` and
//! `frp_core::transport::{IoStream, TransportProtocol}`), with no visibility
//! change on any of them.
//!
//! Visibility: `run_virtual_net_visitor` and `VirtualNetVisitorConfig` keep
//! their original `pub(crate)` tokens; the four helpers keep their original
//! private tokens. The parent re-exports the two externally-reached names
//! (`pub(crate) use vnet::{run_virtual_net_visitor, VirtualNetVisitorConfig};`)
//! because they are the spelled paths at their only external caller, the
//! `virtual_net` visitor spawn in `frp-client/src/service/session.rs` — the
//! re-export preserves the original effective visibility, it does not widen it.
//! The unit tests travel
//! with the code precisely because `deliver_tunnel_ingress` and
//! `run_virtual_net_tunnel_io` are private here: leaving them behind would
//! force `pub(super)` on them, i.e. a visibility change.

use super::*;
#[cfg(all(feature = "vnet", test))]
use std::collections::HashMap;
#[cfg(feature = "vnet")]
type VnetTunTxMap = crate::vnet::VnetTunTxMap;

#[cfg(feature = "vnet")]
type VnetTunSubnetMap = crate::vnet::VnetTunSubnetMap;
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
    /// Proxy name → precompiled subnet used to direct tunnel ingress packets
    /// to the correct local TUN instead of broadcasting to every TUN. The
    /// prefix set is compiled once at registration, so the per-packet check
    /// is a mask+compare with no CIDR parsing.
    pub tun_subnets: VnetTunSubnetMap,
    /// Graceful shutdown signal. When true, the tunnel exits and the route is
    /// unregistered.
    pub shutdown: Arc<AtomicBool>,
    // --- Transport options matching DialOptions / Go frp connector ---
    pub tcp_mux: bool,
    pub tcp_mux_keepalive_interval: i64,
    pub tcp_mux_keepalive_timeout: i64,
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

// --- Reconnect backoff (Go frp `pkg/plugin/visitor/virtual_net.go`) ---
// The setup-failure backoff dates from v0.71.0; v0.71.1 makes its delay
// computation bounded so a large error count cannot overflow the shift.

#[cfg(feature = "vnet")]
const VIRTUAL_NET_RECONNECT_BASE_DELAY: Duration = Duration::from_secs(60);
#[cfg(feature = "vnet")]
const VIRTUAL_NET_RECONNECT_MAX_DELAY: Duration = Duration::from_secs(300);
#[cfg(feature = "vnet")]
const VIRTUAL_NET_RECONNECT_CLEAN_DELAY: Duration = Duration::from_secs(10);

/// Go frp `virtualNetReconnectDelay` (`pkg/plugin/visitor/virtual_net.go`):
/// 60s, 120s, 240s, then the 300s cap.
///
/// The backoff itself dates from v0.71.0, which computed it inline as
/// `min(60s << (n-1), 300s)`: `1<<n` overflows `int`, so the product wraps to
/// a **zero or negative** `time.Duration` for large counts (measured: negative
/// at n = 52/53, exactly 0 s for n >= 54, including the 329769 upstream saw),
/// `min(..., 300s)` keeps that value, and `time.After` then fires immediately —
/// the retry storm v0.71.1 fixed by bounding the shift before it happens
/// (n <= 1 and n >= 4 never shift). This mirrors the bounded form, so no shift
/// is performed for large counts and `u32::MAX` cannot overflow.
#[cfg(feature = "vnet")]
fn virtual_net_reconnect_delay(consecutive_errors: u32) -> Duration {
    if consecutive_errors <= 1 {
        return VIRTUAL_NET_RECONNECT_BASE_DELAY;
    }
    if consecutive_errors >= 4 {
        return VIRTUAL_NET_RECONNECT_MAX_DELAY;
    }
    VIRTUAL_NET_RECONNECT_BASE_DELAY * (1u32 << (consecutive_errors - 1))
}

/// How [`run_virtual_net_tunnel_io`] ended, for the reconnect backoff.
///
/// Go frp reports only *tunnel-establishment* failures through
/// `CloseWithError`: `client/visitor/stcp.go` and `client/visitor/xtcp.go` set
/// `tunnelErr` on the dial / `NewVisitorConn` / response / encryption-wrap
/// paths and nowhere else, so only those reach the plugin's error branch. Once
/// `libio.Join` returns, the conn is closed with `Close()` and a nil error
/// whatever the join outcome (the join errors are discarded in stcp and only
/// trace-logged in xtcp), which the plugin takes as a clean close.
#[cfg(feature = "vnet")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum VirtualNetTunnelEnd {
    /// Our own shutdown signal: the caller returns without waiting.
    Shutdown,
    /// The tunnel reached its data plane and then ended — local side closed,
    /// peer EOF, or a data-plane IO error. Go closes all of these with a nil
    /// error, so they take the clean 10s delay and reset the error counter.
    Clean,
    /// The tunnel never reached its data plane and failed before it: the
    /// stream split, or cipher *construction* (RNG/key). Go's counterpart —
    /// a `wrapVisitorConn` failure — is a `CloseWithError`. A failed IV flush
    /// is **not** here: Go writes the IV lazily inside `libio.Join` and
    /// discards that write error, so it is a [`Clean`](Self::Clean) end.
    Error,
}

/// The per-round Go frp reconnect rule: advance the consecutive-error counter
/// for one finished round and return the delay to wait before the next attempt.
///
/// * `Error` — bump the counter (saturating) and back off 60/120/240/300 s.
/// * `Clean` — reset the counter to 0 and wait the fixed 10 s. Go resets only
///   on a clean close, never on a successful connection.
/// * `Shutdown` — no reconnect is scheduled; the caller returns (`None`).
///
/// This is the only place the counter moves. [`wait_after_virtual_net_round`]
/// only logs and sleeps around it, and the reconnect loop only calls that
/// wrapper, so the decision has exactly one implementation.
#[cfg(feature = "vnet")]
fn next_reconnect_delay(
    consecutive_errors: &mut u32,
    end: VirtualNetTunnelEnd,
) -> Option<Duration> {
    match end {
        VirtualNetTunnelEnd::Shutdown => None,
        VirtualNetTunnelEnd::Clean => {
            *consecutive_errors = 0;
            Some(VIRTUAL_NET_RECONNECT_CLEAN_DELAY)
        }
        VirtualNetTunnelEnd::Error => {
            *consecutive_errors = consecutive_errors.saturating_add(1);
            Some(virtual_net_reconnect_delay(*consecutive_errors))
        }
    }
}

/// Account for one finished `virtual_net` round: apply [`next_reconnect_delay`],
/// log the delay as upstream does, then wait for it (interruptibly). Returns
/// `true` when shutdown was requested or the round was our own shutdown, i.e.
/// when the caller must leave the reconnect loop.
#[cfg(feature = "vnet")]
async fn wait_after_virtual_net_round(
    visitor_name: &str,
    shutdown: &Arc<AtomicBool>,
    consecutive_errors: &mut u32,
    end: VirtualNetTunnelEnd,
) -> bool {
    let previous = *consecutive_errors;
    let Some(delay) = next_reconnect_delay(consecutive_errors, end) else {
        // Our own shutdown schedules no reconnect; the caller returns.
        return true;
    };
    if end == VirtualNetTunnelEnd::Error {
        warn!(
            visitor_name = %visitor_name,
            consecutive_errors = *consecutive_errors,
            delay_secs = delay.as_secs(),
            "virtual_net visitor '{}' reconnecting after {} consecutive error(s), waiting {}s",
            visitor_name,
            *consecutive_errors,
            delay.as_secs()
        );
    } else if previous > 0 {
        info!(
            visitor_name = %visitor_name,
            consecutive_errors = previous,
            "virtual_net visitor '{}' tunnel closed cleanly, resetting error counter (was {})",
            visitor_name,
            previous
        );
    }
    wait_for_shutdown_or_delay(shutdown, delay).await
}

/// Shorthand for the pre-tunnel failure sites, which are always error rounds.
#[cfg(feature = "vnet")]
async fn wait_after_virtual_net_error(
    visitor_name: &str,
    shutdown: &Arc<AtomicBool>,
    consecutive_errors: &mut u32,
) -> bool {
    wait_after_virtual_net_round(
        visitor_name,
        shutdown,
        consecutive_errors,
        VirtualNetTunnelEnd::Error,
    )
    .await
}

/// Run the packet loop over an established `virtual_net` visitor tunnel.
///
/// After the NewVisitorConn handshake, tunnel bytes are wrapped in the same
/// compress → encrypt / decrypt → decompress pipeline used by work conns.
///
/// Returns how the tunnel ended so the caller can pick the reconnect delay.
#[cfg(feature = "vnet")]
#[allow(clippy::too_many_arguments)]
async fn run_virtual_net_tunnel_io(
    server_conn: IoStream,
    name: String,
    packet_rx: mpsc::Receiver<Vec<u8>>,
    vnet_tun_tx: VnetTunTxMap,
    tun_subnets: VnetTunSubnetMap,
    shutdown: Arc<AtomicBool>,
    use_encryption: bool,
    use_compression: bool,
    key: [u8; 16],
) -> VirtualNetTunnelEnd {
    let mut packet_rx = packet_rx;
    let (server_r, server_w) = match server_conn.into_split() {
        Ok(parts) => parts,
        Err(e) => {
            warn!(visitor_name = %name, error = %e, "virtual_net visitor tunnel split failed: {}", e);
            return VirtualNetTunnelEnd::Error;
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
        // Audit B2: OS-RNG failure (IV generation) ends this tunnel setup
        // instead of aborting the process.
        match frp_core::cipher_stream::CipherWriter::new(server_w, key) {
            Ok(w) => crate::work_conn::TunnelPacketWriter::Encrypted(w),
            Err(e) => {
                warn!(visitor_name = %name, error = %e, "virtual_net visitor tunnel IV generation failed: {}", e);
                return VirtualNetTunnelEnd::Error;
            }
        }
    } else {
        crate::work_conn::TunnelPacketWriter::Plain(server_w)
    };
    if let Err(e) = packet_writer.flush().await {
        // Go sends the IV lazily inside `libio.Join` and discards that write
        // error (stcp) / trace-logs it (xtcp), so a failed IV flush is a clean
        // end with the nil-error `Close()` the plugin resets on — only cipher
        // *construction* above is the counterpart of Go's wrap failure.
        warn!(visitor_name = %name, error = %e, "virtual_net visitor tunnel IV flush failed: {}", e);
        return VirtualNetTunnelEnd::Clean;
    }

    loop {
        tokio::select! {
            _ = wait_for_shutdown_signal(&shutdown) => {
                info!(visitor_name = %name, "virtual_net visitor '{}' shutting down", name);
                return VirtualNetTunnelEnd::Shutdown;
            }
            packet = packet_rx.recv() => {
                match packet {
                    Some(pkt) => {
                        if let Err(e) = packet_writer.write_packet(&pkt, use_compression).await {
                            warn!(visitor_name = %name, error = %e, "virtual_net visitor '{}': tunnel write error: {}", name, e);
                            break;
                        }
                    }
                    None => {
                        debug!(visitor_name = %name, "virtual_net visitor packet channel closed");
                        break;
                    }
                }
            }
            packet = packet_reader.next_packet() => {
                match packet {
                    Ok(None) => {
                        debug!(visitor_name = %name, "virtual_net visitor tunnel closed by peer");
                        break;
                    }
                    Ok(Some(pkt)) => {
                        if !deliver_tunnel_ingress(&name, pkt, &vnet_tun_tx, &tun_subnets).await {
                            debug!(visitor_name = %name, "virtual_net visitor tunnel ingress bytes have no TUN target");
                        }
                    }
                    Err(e) => {
                        warn!(visitor_name = %name, error = %e, "virtual_net visitor '{}': tunnel read error: {}", name, e);
                        break;
                    }
                }
            }
        }
    }
    // Every data-plane exit above is a `Close()` (nil error) in Go frp.
    VirtualNetTunnelEnd::Clean
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
        tcp_mux_keepalive_timeout,
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

    // Go frp `consecutiveErrors` (v0.71.0, unchanged in v0.71.1): only
    // *failed* reconnect attempts (establishment failures) bump it; a clean
    // close of an established tunnel resets it. A successful connection does
    // not reset it.
    let mut consecutive_errors: u32 = 0;
    'reconnect: loop {
        if shutdown.load(Ordering::Relaxed) {
            return;
        }

        let transport = VisitorTransportConfig {
            tcp_mux,
            tcp_mux_keepalive_interval,
            tcp_mux_keepalive_timeout,
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
                if wait_after_virtual_net_error(&name, &shutdown, &mut consecutive_errors).await {
                    return;
                }
                continue 'reconnect;
            }
        };
        // Wrap in yamux when tcp_mux is enabled (Go frp compat).
        let yamux_keepalive = plan.yamux_keepalive_secs;
        let yamux_idle_dead_timeout = plan.yamux_idle_dead_timeout_secs;
        let mut _yamux_sess_vnet: Option<YamuxSession> = None;
        let mut server_conn = if let (Some(ka), Some(ka_timeout)) =
            (yamux_keepalive, yamux_idle_dead_timeout)
        {
            match crate::control::wrap_client_mux(raw_stream, ka, ka_timeout).await {
                Ok((io, session)) => {
                    _yamux_sess_vnet = session;
                    io
                }
                Err(e) => {
                    warn!(visitor_name = %name, error = %e, "Virtual net visitor '{}': yamux wrap failed: {}", name, e);
                    if wait_after_virtual_net_error(&name, &shutdown, &mut consecutive_errors).await
                    {
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
            if wait_after_virtual_net_error(&name, &shutdown, &mut consecutive_errors).await {
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
                    if wait_after_virtual_net_error(&name, &shutdown, &mut consecutive_errors).await
                    {
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
                if wait_after_virtual_net_error(&name, &shutdown, &mut consecutive_errors).await {
                    return;
                }
                continue 'reconnect;
            }
            Ok(Err(e)) => {
                warn!(visitor_name = %name, error = %e, "Virtual net visitor '{}': read tunnel response failed: {}", name, e);
                if wait_after_virtual_net_error(&name, &shutdown, &mut consecutive_errors).await {
                    return;
                }
                continue 'reconnect;
            }
            Err(_elapsed) => {
                warn!(visitor_name = %name, timeout = ?resp_timeout, "Virtual net visitor '{}': timed out waiting for tunnel response", name);
                if wait_after_virtual_net_error(&name, &shutdown, &mut consecutive_errors).await {
                    return;
                }
                continue 'reconnect;
            }
        }

        let (packet_tx, packet_rx) = mpsc::channel::<Vec<u8>>(256);
        let route_owner = packet_tx.clone();
        match controller
            .register_visitor_route_if_active(&name, &destination_cidr, packet_tx, &shutdown)
            .await
        {
            Ok(true) => {}
            // Shutdown was signaled before registration: exit rather than
            // clobber a replacement route (Go frp #5512).
            Ok(false) => return,
            Err(e) => {
                warn!(visitor_name = %name, error = %e, "Virtual net visitor '{}': route registration failed: {}", name, e);
                if wait_after_virtual_net_error(&name, &shutdown, &mut consecutive_errors).await {
                    return;
                }
                continue 'reconnect;
            }
        }
        info!(
            visitor_name = %name,
            destination = %destination_cidr,
            "Virtual net visitor '{}' tunnel established, host route {} registered",
            name,
            destination_cidr
        );

        let key = frp_core::encryption::derive_key(&secret_key);
        let tunnel_end = run_virtual_net_tunnel_io(
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

        controller
            .unregister_visitor_route_if_matches(&name, &route_owner)
            .await;
        info!(visitor_name = %name, "Virtual net visitor '{}' tunnel closed, route removed", name);
        if shutdown.load(Ordering::Relaxed) {
            return;
        }
        // The one place the Go round rule is applied. `Shutdown` normally
        // already returned at the check above; the wrapper still answers
        // `true` for it, so a reorder cannot make the loop wait at shutdown.
        if wait_after_virtual_net_round(&name, &shutdown, &mut consecutive_errors, tunnel_end).await
        {
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
    tun_subnets: &VnetTunSubnetMap,
) -> bool {
    // Take the tokio lock first so the std Mutex guard never spans an await
    // point (the guarded section below is fully synchronous).
    let subnets = tun_subnets.lock().await;
    let txs = vnet_tun_tx.lock().unwrap_or_else(|e| e.into_inner());
    let dst = frp_vnet::router::packet_dst_ip(&packet);
    let mut delivered = false;
    // The packet is converted into the shared `Arc<[u8]>` form at most once
    // for the whole fan-out: every matching TUN channel then receives the same
    // buffer by refcount instead of a deep copy per peer. A packet that
    // matches nothing pays nothing — the `Vec` is moved into the fallback
    // send below.
    let mut shared: Option<Arc<[u8]>> = None;
    for (proxy, tx) in txs.iter() {
        // Precompiled prefix membership (compiled at registration): a
        // mask+compare, no per-packet CIDR parse.
        let matched = dst
            .as_ref()
            .is_some_and(|ip| subnets.get(proxy).is_some_and(|subnet| subnet.contains(ip)));
        if matched {
            let pkt = shared
                .get_or_insert_with(|| Arc::from(packet.as_slice()))
                .clone();
            match tx.try_send(pkt) {
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
    // of broadcasting (the pre-fix behavior). One pass, no allocation — the
    // old `Vec<&Sender>` collect allocated per packet.
    let mut open: Option<&mpsc::Sender<Arc<[u8]>>> = None;
    let mut ambiguous = false;
    for tx in txs.values() {
        if tx.is_closed() {
            continue;
        }
        if open.is_some() {
            ambiguous = true;
            break;
        }
        open = Some(tx);
    }
    if let Some(tx) = open {
        if ambiguous {
            warn!(
                visitor_name = %visitor_name,
                "virtual_net visitor ingress packet has no subnet match; dropping instead of broadcasting"
            );
            return false;
        }
        match tx.try_send(Arc::from(packet)) {
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
#[cfg(all(test, feature = "vnet"))]
mod tests {
    use super::*;
    // Only `virtual_net_tunnel_io_wraps_encrypted_compressed_bytes` drives a
    // duplex peer through these extension traits, and it is
    // `#[cfg(feature = "compression")]` — so with `vnet` on and `compression`
    // off the imports have no user and trip `unused_imports` under
    // `-D warnings`. Gate the imports exactly where the methods are called.
    #[cfg(feature = "compression")]
    use tokio::io::AsyncReadExt;
    #[cfg(feature = "compression")]
    use tokio::io::AsyncWriteExt;

    #[test]
    fn hp_timeout_floor_and_cap() {
        // Go MakeHole floors at the 5s default: 0 / negative must not make
        // the punch fail instantly.
        assert_eq!(clamp_hp_timeout(0), 5000);
        assert_eq!(clamp_hp_timeout(-5), 5000);
        // Legitimate analyzer emissions (~5-45s) pass through.
        assert_eq!(clamp_hp_timeout(5000), 5000);
        assert_eq!(clamp_hp_timeout(35000), 35000);
        // Hostile server values are capped at 60s (i32 uncapped would wait
        // ~24.8 days before the visitor could re-punch).
        assert_eq!(clamp_hp_timeout(70_000), 60_000);
        assert_eq!(clamp_hp_timeout(i32::MAX), 60_000);
    }

    #[tokio::test]
    async fn tunnel_ingress_delivers_to_local_tun_channels() {
        let txs: VnetTunTxMap = Arc::new(std::sync::Mutex::new(HashMap::new()));
        let subnets: VnetTunSubnetMap = Arc::new(tokio::sync::Mutex::new(HashMap::new()));
        let (tx, mut rx) = mpsc::channel::<Arc<[u8]>>(16);
        txs.lock().unwrap().insert("tun-proxy".to_string(), tx);
        subnets.lock().await.insert(
            "tun-proxy".to_string(),
            frp_vnet::router::PrecompiledSubnet::new("10.0.0.0/24"),
        );

        assert!(
            deliver_tunnel_ingress("vnet-visitor", vec![0x45], &txs, &subnets).await,
            "single open TUN channel must accept an unmatched packet as fallback"
        );
        assert_eq!(rx.recv().await.as_deref(), Some(&[0x45u8][..]));

        let (closed_tx, closed_rx) = mpsc::channel::<Arc<[u8]>>(16);
        txs.lock()
            .unwrap()
            .insert("gone-tun".to_string(), closed_tx);
        subnets.lock().await.insert(
            "gone-tun".to_string(),
            frp_vnet::router::PrecompiledSubnet::new("10.0.1.0/24"),
        );
        drop(closed_rx);
        assert!(
            deliver_tunnel_ingress("vnet-visitor", vec![0x46], &txs, &subnets).await,
            "an open channel still counts as delivered"
        );

        let empty: VnetTunTxMap = Arc::new(std::sync::Mutex::new(HashMap::new()));
        let empty_subnets: VnetTunSubnetMap = Arc::new(tokio::sync::Mutex::new(HashMap::new()));
        assert!(
            !deliver_tunnel_ingress("vnet-visitor", vec![0x47], &empty, &empty_subnets).await,
            "no TUN target must report undelivered"
        );
    }

    #[tokio::test]
    async fn tunnel_ingress_directs_by_ip_family_subnet() {
        let txs: VnetTunTxMap = Arc::new(std::sync::Mutex::new(HashMap::new()));
        let subnets: VnetTunSubnetMap = Arc::new(tokio::sync::Mutex::new(HashMap::new()));
        let (tx4, mut rx4) = mpsc::channel::<Arc<[u8]>>(16);
        let (tx6, mut rx6) = mpsc::channel::<Arc<[u8]>>(16);
        txs.lock().unwrap().insert("tun-v4".to_string(), tx4);
        txs.lock().unwrap().insert("tun-v6".to_string(), tx6);
        subnets.lock().await.insert(
            "tun-v4".to_string(),
            frp_vnet::router::PrecompiledSubnet::new("10.0.0.0/24"),
        );
        subnets.lock().await.insert(
            "tun-v6".to_string(),
            frp_vnet::router::PrecompiledSubnet::new("2001:db8::/64"),
        );

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
        assert_eq!(rx4.recv().await.as_deref(), Some(&v4[..]));
        assert!(
            tokio::time::timeout(Duration::from_millis(50), rx6.recv())
                .await
                .is_err(),
            "IPv4 packet must not be broadcast to the IPv6 TUN"
        );

        assert!(deliver_tunnel_ingress("vnet-visitor", v6.clone(), &txs, &subnets).await);
        assert_eq!(rx6.recv().await.as_deref(), Some(&v6[..]));
        assert!(
            tokio::time::timeout(Duration::from_millis(50), rx4.recv())
                .await
                .is_err(),
            "IPv6 packet must not be broadcast to the IPv4 TUN"
        );
    }

    /// Fan-out must copy the packet at most once: every matching TUN channel
    /// receives the *same* `Arc<[u8]>` buffer by refcount, so the peer count
    /// never multiplies the bytes copied.
    #[tokio::test]
    async fn tunnel_ingress_fan_out_shares_one_packet_buffer() {
        let txs: VnetTunTxMap = Arc::new(std::sync::Mutex::new(HashMap::new()));
        let subnets: VnetTunSubnetMap = Arc::new(tokio::sync::Mutex::new(HashMap::new()));
        let (tx_a, mut rx_a) = mpsc::channel::<Arc<[u8]>>(16);
        let (tx_b, mut rx_b) = mpsc::channel::<Arc<[u8]>>(16);
        let (tx_c, mut rx_c) = mpsc::channel::<Arc<[u8]>>(16);
        txs.lock().unwrap().insert("tun-a".to_string(), tx_a);
        txs.lock().unwrap().insert("tun-b".to_string(), tx_b);
        txs.lock().unwrap().insert("tun-c".to_string(), tx_c);
        // Three TUNs on the same subnet: one packet matches all three.
        for name in ["tun-a", "tun-b", "tun-c"] {
            subnets.lock().await.insert(
                name.to_string(),
                frp_vnet::router::PrecompiledSubnet::new("10.0.0.0/24"),
            );
        }

        let packet = vec![
            0x45, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x40, 0x06, 0x00, 0x00, 10, 0, 0, 2,
            10, 0, 0, 5,
        ];
        assert!(deliver_tunnel_ingress("vnet-visitor", packet.clone(), &txs, &subnets).await);

        let a = rx_a.recv().await.expect("tun-a received the packet");
        let b = rx_b.recv().await.expect("tun-b received the packet");
        let c = rx_c.recv().await.expect("tun-c received the packet");
        assert_eq!(&*a, &packet[..], "bytes must be identical per peer");
        assert_eq!(&*b, &packet[..], "bytes must be identical per peer");
        assert_eq!(&*c, &packet[..], "bytes must be identical per peer");
        assert!(
            Arc::ptr_eq(&a, &b),
            "peers must share one buffer, not a copy each"
        );
        assert!(
            Arc::ptr_eq(&b, &c),
            "peers must share one buffer, not a copy each"
        );
        assert_eq!(
            Arc::strong_count(&a),
            3,
            "exactly one buffer for three channels"
        );
    }

    /// Two open TUNs and no subnet match: the target is ambiguous, so the
    /// packet is dropped rather than broadcast (unchanged fallback semantics;
    /// the scan is now allocation-free).
    #[tokio::test]
    async fn tunnel_ingress_ambiguous_fallback_drops_instead_of_broadcasting() {
        let txs: VnetTunTxMap = Arc::new(std::sync::Mutex::new(HashMap::new()));
        let subnets: VnetTunSubnetMap = Arc::new(tokio::sync::Mutex::new(HashMap::new()));
        let (tx_a, mut rx_a) = mpsc::channel::<Arc<[u8]>>(16);
        let (tx_b, mut rx_b) = mpsc::channel::<Arc<[u8]>>(16);
        txs.lock().unwrap().insert("tun-a".to_string(), tx_a);
        txs.lock().unwrap().insert("tun-b".to_string(), tx_b);
        // Subnets registered, but neither covers the packet's destination.
        subnets.lock().await.insert(
            "tun-a".to_string(),
            frp_vnet::router::PrecompiledSubnet::new("10.9.0.0/24"),
        );
        subnets.lock().await.insert(
            "tun-b".to_string(),
            frp_vnet::router::PrecompiledSubnet::new("10.9.1.0/24"),
        );

        let packet = vec![
            0x45, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x40, 0x06, 0x00, 0x00, 10, 0, 0, 2,
            10, 0, 0, 5,
        ];
        assert!(
            !deliver_tunnel_ingress("vnet-visitor", packet, &txs, &subnets).await,
            "an ambiguous target must report undelivered"
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(50), rx_a.recv())
                .await
                .is_err(),
            "ambiguous fallback must not broadcast to tun-a"
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(50), rx_b.recv())
                .await
                .is_err(),
            "ambiguous fallback must not broadcast to tun-b"
        );
    }

    /// Go frp v0.71.1 `virtualNetReconnectDelay`: 60s, 120s, 240s, then the
    /// 300s cap. Counts at/past the shift width and `u32::MAX` must clamp, not
    /// shift (Go had to add the bound because the old `1<<n` overflowed).
    #[test]
    fn virtual_net_reconnect_delay_matches_go_backoff() {
        assert_eq!(virtual_net_reconnect_delay(0), Duration::from_secs(60));
        assert_eq!(virtual_net_reconnect_delay(1), Duration::from_secs(60));
        assert_eq!(virtual_net_reconnect_delay(2), Duration::from_secs(120));
        assert_eq!(virtual_net_reconnect_delay(3), Duration::from_secs(240));
        assert_eq!(virtual_net_reconnect_delay(4), Duration::from_secs(300));
        assert_eq!(virtual_net_reconnect_delay(5), Duration::from_secs(300));
        assert_eq!(virtual_net_reconnect_delay(64), Duration::from_secs(300));
        assert_eq!(
            virtual_net_reconnect_delay(u32::MAX),
            Duration::from_secs(300)
        );
    }

    /// The per-round decision the reconnect loop applies, pinned as a sequence:
    /// error rounds climb 60 -> 120 -> 240 -> 300 and bump the counter, a clean
    /// round resets it and waits the fixed 10 s, and the reset therefore makes
    /// the next error round start over at 60 s. Also pins shutdown (no delay,
    /// counter untouched) and saturation at `u32::MAX`.
    #[test]
    fn next_reconnect_delay_pins_error_and_clean_rounds() {
        let mut n = 0u32;
        assert_eq!(
            next_reconnect_delay(&mut n, VirtualNetTunnelEnd::Error),
            Some(Duration::from_secs(60))
        );
        assert_eq!(n, 1, "one error round counts one consecutive error");
        assert_eq!(
            next_reconnect_delay(&mut n, VirtualNetTunnelEnd::Error),
            Some(Duration::from_secs(120))
        );
        assert_eq!(n, 2);
        assert_eq!(
            next_reconnect_delay(&mut n, VirtualNetTunnelEnd::Error),
            Some(Duration::from_secs(240))
        );
        assert_eq!(n, 3);
        assert_eq!(
            next_reconnect_delay(&mut n, VirtualNetTunnelEnd::Error),
            Some(Duration::from_secs(300))
        );
        assert_eq!(n, 4);
        assert_eq!(
            next_reconnect_delay(&mut n, VirtualNetTunnelEnd::Error),
            Some(Duration::from_secs(300)),
            "further errors stay capped"
        );
        assert_eq!(n, 5);

        // A clean close resets the counter and takes the fixed 10 s delay.
        assert_eq!(
            next_reconnect_delay(&mut n, VirtualNetTunnelEnd::Clean),
            Some(Duration::from_secs(10))
        );
        assert_eq!(n, 0, "clean resets the consecutive-error count");
        // ...so the next error round starts the schedule over at 60 s.
        assert_eq!(
            next_reconnect_delay(&mut n, VirtualNetTunnelEnd::Error),
            Some(Duration::from_secs(60))
        );
        assert_eq!(n, 1);

        // Our own shutdown schedules no reconnect and must not touch the count.
        assert_eq!(
            next_reconnect_delay(&mut n, VirtualNetTunnelEnd::Shutdown),
            None
        );
        assert_eq!(n, 1);

        // Saturation: the increment cannot overflow or panic.
        n = u32::MAX;
        assert_eq!(
            next_reconnect_delay(&mut n, VirtualNetTunnelEnd::Error),
            Some(Duration::from_secs(300))
        );
        assert_eq!(n, u32::MAX);
    }

    /// Spawn `run_virtual_net_tunnel_io` over the given transport with no TUN
    /// channels registered, so a test can drive one exit path and read back how
    /// the tunnel ended. No real time is waited for.
    fn spawn_tunnel_io(
        tunnel: Box<dyn frp_core::transport::AsyncReadWrite>,
        use_encryption: bool,
        shutdown: Arc<AtomicBool>,
    ) -> (
        tokio::task::JoinHandle<VirtualNetTunnelEnd>,
        mpsc::Sender<Vec<u8>>,
    ) {
        let key = frp_core::encryption::derive_key("visitor-secret");
        let (packet_tx, packet_rx) = mpsc::channel::<Vec<u8>>(16);
        let txs: VnetTunTxMap = Arc::new(std::sync::Mutex::new(HashMap::new()));
        let subnets: VnetTunSubnetMap = Arc::new(tokio::sync::Mutex::new(HashMap::new()));
        let task = tokio::spawn(run_virtual_net_tunnel_io(
            frp_core::transport::IoStream::SshChannel(tunnel),
            "vnet-visitor".to_string(),
            packet_rx,
            txs,
            subnets,
            shutdown,
            use_encryption,
            false,
            key,
        ));
        (task, packet_tx)
    }

    /// A scripted tunnel transport for the data-plane failure tests: the read
    /// side is either an injected error or permanently pending, and the write
    /// side either fails or accepts bytes. Deterministic — unlike a `duplex`
    /// peer, whose close would race the pending read with the EOF branch.
    struct ScriptedTunnel {
        read_err: Option<std::io::ErrorKind>,
        write_err: Option<std::io::ErrorKind>,
    }

    impl tokio::io::AsyncRead for ScriptedTunnel {
        fn poll_read(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            _buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            match self.read_err {
                Some(kind) => std::task::Poll::Ready(Err(kind.into())),
                None => std::task::Poll::Pending,
            }
        }
    }

    impl tokio::io::AsyncWrite for ScriptedTunnel {
        fn poll_write(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            match self.write_err {
                Some(kind) => std::task::Poll::Ready(Err(kind.into())),
                None => std::task::Poll::Ready(Ok(buf.len())),
            }
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

    /// Peer EOF after establishment: Go's `libio.Join` returns normally and the
    /// conn is closed with a nil error (stcp discards the join errors, xtcp
    /// only trace-logs them), so this is the clean 10s path.
    #[tokio::test]
    async fn tunnel_io_peer_eof_is_a_clean_end() {
        let (server, peer) = tokio::io::duplex(8192);
        let (task, _packet_tx) =
            spawn_tunnel_io(Box::new(server), false, Arc::new(AtomicBool::new(false)));
        drop(peer);
        assert_eq!(task.await.expect("tunnel task"), VirtualNetTunnelEnd::Clean);
    }

    /// Local route channel closed while the peer is still open: the local side
    /// ended the tunnel, which Go reports through `Close()` (nil error).
    #[tokio::test]
    async fn tunnel_io_local_route_close_is_a_clean_end() {
        let (server, _peer) = tokio::io::duplex(8192);
        let (task, packet_tx) =
            spawn_tunnel_io(Box::new(server), false, Arc::new(AtomicBool::new(false)));
        drop(packet_tx);
        assert_eq!(task.await.expect("tunnel task"), VirtualNetTunnelEnd::Clean);
    }

    /// Our own shutdown is not a reconnect at all: the caller returns.
    #[tokio::test]
    async fn tunnel_io_shutdown_reports_shutdown() {
        let (server, _peer) = tokio::io::duplex(8192);
        let (task, _packet_tx) =
            spawn_tunnel_io(Box::new(server), false, Arc::new(AtomicBool::new(true)));
        assert_eq!(
            task.await.expect("tunnel task"),
            VirtualNetTunnelEnd::Shutdown
        );
    }

    /// A data-plane write error after establishment: `libio.Join` returns it,
    /// stcp discards it (xtcp trace-logs it) and the conn is closed with a nil
    /// error, so the plugin takes the clean 10s path.
    #[tokio::test]
    async fn tunnel_io_write_error_is_a_clean_end() {
        let (task, packet_tx) = spawn_tunnel_io(
            Box::new(ScriptedTunnel {
                read_err: None,
                write_err: Some(std::io::ErrorKind::BrokenPipe),
            }),
            false,
            Arc::new(AtomicBool::new(false)),
        );
        packet_tx
            .send(vec![0x45])
            .await
            .expect("queue a packet for the tunnel writer");
        assert_eq!(task.await.expect("tunnel task"), VirtualNetTunnelEnd::Clean);
    }

    /// A data-plane read error (`next_packet` yields `Err`) is likewise clean:
    /// Go discards / trace-logs the join error and then closes with nil.
    #[tokio::test]
    async fn tunnel_io_read_error_is_a_clean_end() {
        let (task, _packet_tx) = spawn_tunnel_io(
            Box::new(ScriptedTunnel {
                read_err: Some(std::io::ErrorKind::ConnectionReset),
                write_err: None,
            }),
            false,
            Arc::new(AtomicBool::new(false)),
        );
        assert_eq!(task.await.expect("tunnel task"), VirtualNetTunnelEnd::Clean);
    }

    /// The encrypted writer's IV flush fails before any data flows, but Go
    /// writes the IV lazily inside `libio.Join` and discards that write error,
    /// so this is the **clean** end — only cipher *construction* (RNG/key) is
    /// the counterpart of Go's `wrapVisitorConn` failure, and that cannot be
    /// forced without an RNG seam. The scripted transport rejects the IV write
    /// while its read side stays pending, so the flush arm is the only way out.
    #[tokio::test]
    async fn tunnel_io_iv_flush_failure_is_a_clean_end() {
        let (task, _packet_tx) = spawn_tunnel_io(
            Box::new(ScriptedTunnel {
                read_err: None,
                write_err: Some(std::io::ErrorKind::BrokenPipe),
            }),
            true,
            Arc::new(AtomicBool::new(false)),
        );
        assert_eq!(task.await.expect("tunnel task"), VirtualNetTunnelEnd::Clean);
    }

    #[cfg(feature = "compression")]
    #[tokio::test]
    async fn virtual_net_tunnel_io_wraps_encrypted_compressed_bytes() {
        let key = frp_core::encryption::derive_key("visitor-secret");
        let (server, mut peer) = tokio::io::duplex(8192);
        let (packet_tx, packet_rx) = mpsc::channel::<Vec<u8>>(16);
        let txs: VnetTunTxMap = Arc::new(std::sync::Mutex::new(HashMap::new()));
        let subnets: VnetTunSubnetMap = Arc::new(tokio::sync::Mutex::new(HashMap::new()));
        let (tun_tx, mut tun_rx) = mpsc::channel::<Arc<[u8]>>(16);
        let shutdown = Arc::new(AtomicBool::new(false));
        txs.lock().unwrap().insert("tun-v4".to_string(), tun_tx);
        subnets.lock().await.insert(
            "tun-v4".to_string(),
            frp_vnet::router::PrecompiledSubnet::new("10.0.0.0/24"),
        );

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
        assert_eq!(tun_rx.recv().await.as_deref(), Some(&inbound[..]));

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
