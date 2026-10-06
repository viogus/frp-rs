//! The `virtual_net` visitor cluster: the no-bind visitor tunnel
//! (`run_virtual_net_visitor` + `VirtualNetVisitorConfig`), its established-tunnel
//! packet loop (`run_virtual_net_tunnel_io`), the TUN-ingress fan-out
//! (`deliver_tunnel_ingress`), the two shutdown waiters
//! (`wait_for_shutdown_or_delay`, `wait_for_shutdown_signal`) and the
//! `VnetTunTxMap`/`VnetTunSubnetMap` aliases those items share.
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
    tun_subnets: VnetTunSubnetMap,
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
        // Audit B2: OS-RNG failure (IV generation) ends this tunnel setup
        // instead of aborting the process.
        match frp_core::cipher_stream::CipherWriter::new(server_w, key) {
            Ok(w) => crate::work_conn::TunnelPacketWriter::Encrypted(w),
            Err(e) => {
                warn!(visitor_name = %name, error = %e, "virtual_net visitor tunnel IV generation failed: {}", e);
                return;
            }
        }
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
                if wait_for_shutdown_or_delay(&shutdown, Duration::from_secs(10)).await {
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
                if wait_for_shutdown_or_delay(&shutdown, Duration::from_secs(10)).await {
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

        controller
            .unregister_visitor_route_if_matches(&name, &route_owner)
            .await;
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
