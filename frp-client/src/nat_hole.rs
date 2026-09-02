//! XTCP NAT hole punching — client side.
//!
//! Provider-side handlers for the `NatHoleClient`/`NatHoleResp` control
//! messages (STUN discovery, UDP hole punch, KCP+yamux/QUIC data plane,
//! bridging to the local service) plus the local-IP enumeration helper used
//! for `assisted_addrs`.
//!
//! Compiled unconditionally: frp-core provides stub modules for `kcp` and
//! `xtcp_p2p` when those features are off, so these paths also compile in
//! tiny/micro builds (the message-loop dispatch arms stay uniform).

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::oneshot;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::service::ControlWriter;
use frp_core::msg::{self, FrpMessage};

use crate::service::Service;

impl Service {
    /// Handle a NatHoleClient message from the server (XTCP provider side).
    ///
    /// Sends NatHoleSid to synchronize with the visitor, performs TCP simultaneous
    /// open, connects to local service, and spawns a P2P bridge task.
    pub(crate) async fn handle_nat_hole_client(
        &self,
        nhc: msg::NatHoleClient,
        writer: &Arc<ControlWriter>,
        v2: bool,
        session_alive: Arc<AtomicBool>,
        proxy_token: CancellationToken,
    ) {
        debug!(proxy_name = %nhc.proxy_name, "Received NatHoleClient for proxy '{}'", nhc.proxy_name);
        let visitor_addr = nhc.visitor_addr.unwrap_or_default();
        let proxy_name = nhc.proxy_name.clone();
        let sid = nhc.transaction_id.clone();
        // F2 cancel-before-reinsert guard (defense in depth; the message-loop
        // arm guards before arming the token): a reload-removed or
        // health-closed proxy must not punch — its P2P token was cancelled at
        // the removal/close, so spawning here would arm an uncancelled bridge
        // that runs until the peer closes. Mirrors the visitor.rs
        // conn_cancel.is_cancelled() early-bail pattern. Bails before the UDP
        // bind so a dead proxy cannot even hold a socket briefly.
        if !self.punch_proxy_still_live(&proxy_name).await {
            debug!(proxy_name = %proxy_name, "XTCP provider '{}': proxy no longer live (reload/health close), aborting NatHoleClient", proxy_name);
            return;
        }
        let proxy_info = self.proxy_info_map.read().await.get(&proxy_name).map(|p| {
            (
                p.local_addr.clone(),
                p.use_encryption,
                p.use_compression,
                p.sk.clone(),
            )
        });
        let local_addr = proxy_info.as_ref().map(|p| p.0.clone());
        let xtcp_use_enc = proxy_info.as_ref().map(|p| p.1).unwrap_or(false);
        let xtcp_use_comp = proxy_info.as_ref().map(|p| p.2).unwrap_or(false);
        let xtcp_sk = proxy_info.as_ref().map(|p| p.3.clone()).unwrap_or_default();

        if visitor_addr.is_empty() {
            warn!(proxy_name = %proxy_name, "NatHoleClient without visitor_addr for '{}'", proxy_name);
            Self::send_nat_hole_report(writer, v2, sid.clone(), false, "no visitor_addr").await;
            return;
        }

        // Go v0.70 compat: UDP hole punch + KCP data plane.
        // Bind socket FIRST (before sending NatHoleSid) so the UDP port
        // is ready when the visitor starts sending probe packets.
        // Go frp compat: bind UDP before sending NatHoleSid notification.
        let is_v4 = visitor_addr
            .parse::<std::net::SocketAddr>()
            .map(|a| a.is_ipv4())
            .unwrap_or(false);
        let bind_addr = if is_v4 { "0.0.0.0:0" } else { "[::]:0" };
        let fallback = if is_v4 { "[::]:0" } else { "0.0.0.0:0" };
        let socket = match tokio::net::UdpSocket::bind(bind_addr).await {
            Ok(s) => s,
            Err(_) => match tokio::net::UdpSocket::bind(fallback).await {
                Ok(s) => s,
                Err(e) => {
                    warn!(proxy_name = %proxy_name, error = %e, "XTCP: failed to bind UDP socket: {}", e);
                    Self::send_nat_hole_report(writer, v2, sid, false, "bind failed").await;
                    return;
                }
            },
        };

        // Send NatHoleSid now that the UDP socket is bound and ready.
        let sid_msg = FrpMessage::NatHoleSid(msg::NatHoleSid {
            sid: Some(sid.clone()),
            ..Default::default()
        });
        if let Err(e) = writer.send(sid_msg, v2) {
            warn!(error = %e, "Failed to send NatHoleSid: {}", e);
            return;
        }

        // Spawn the blocking P2P connection + bridging into a detached task
        // so it doesn't starve the control loop's ping/health/reload handling.
        // The task is session-bound: `session_alive` is cleared at session
        // teardown, which aborts both the hole punch and the P2P bridge
        // instead of leaving them probing a dead control channel. It is also
        // proxy-bound: `proxy_token` is cancelled on CloseProxy/reload removal
        // so a deleted proxy cannot leak the bridge task + UDP fd + KCP + yamux.
        let w = writer.clone();
        tokio::spawn(async move {
            let alive = session_alive;
            let candidates = vec![visitor_addr];
            let conv = frp_core::xtcp_p2p::conv_from_sid(&sid);
            let kcp_cfg = frp_core::kcp::default_kcp_config();
            let p2p_key = if !xtcp_sk.is_empty() {
                Some(frp_core::xtcp_p2p::derive_detect_key(&xtcp_sk))
            } else {
                None
            };
            let p2p_sid2 = if sid.is_empty() {
                None
            } else {
                Some(sid.as_str())
            };

            // Legacy NatHoleClient path (no server detect_behavior): the
            // simplified punch. candidate_addrs must be the visitor's mapped
            // address (Go `mapped_addrs`); previously it was passed as
            // candidates=&[]/assisted, which always failed with
            // "no candidate addresses" — the provider never hole-punched.
            // Go frp v0.71: the punch creates a persistent SESSION (one
            // session per punch); user connections are accepted from it.
            // Scope the pinned punch future so its borrows of `sid`/`p2p_sid`
            // are released before the match arms below move those values.
            let session_result = {
                let punch = frp_core::xtcp_p2p::xtcp_p2p_connect_yamux_session(
                    socket,
                    &candidates,
                    &[],
                    None,
                    conv,
                    kcp_cfg,
                    5000,
                    false, // yamux_client = false (provider/server)
                    p2p_sid2,
                    p2p_key.as_ref(),
                );
                tokio::pin!(punch);
                tokio::select! {
                    r = &mut punch => r,
                    _ = wait_session_dead(&alive) => {
                        // Session torn down (reconnect/stop): drop the punch
                        // future, releasing its UDP socket, instead of probing
                        // a dead control channel for up to 5s more.
                        debug!(proxy_name = %proxy_name, "XTCP provider '{}': session ended during hole punch, aborting", proxy_name);
                        return;
                    }
                    _ = proxy_token.cancelled() => {
                        // Proxy deleted (CloseProxy/reload): drop the punch
                        // future, releasing its UDP socket.
                        debug!(proxy_name = %proxy_name, "XTCP provider '{}': proxy deleted during hole punch, aborting", proxy_name);
                        return;
                    }
                }
            };
            match session_result {
                Ok(session) => {
                    // Send NatHoleReport with success=true after successful hole punch
                    // (Go frp compat: provider reports the punch result to the server
                    // BEFORE the accept loop — Go listenByKCP runs after the report).
                    Self::send_nat_hole_report(&w, v2, sid.clone(), true, "hole punch succeeded")
                        .await;
                    let session = crate::visitor::TunnelSession::Kcp(session);
                    Self::provider_accept_loop(
                        session,
                        local_addr,
                        xtcp_use_enc,
                        xtcp_use_comp,
                        xtcp_sk,
                        proxy_name,
                        alive,
                        proxy_token,
                    )
                    .await;
                }
                Err(e) => {
                    warn!(proxy_name = %proxy_name, error = %e, "XTCP hole punch for '{}' failed: {}", proxy_name, e);
                    Self::send_nat_hole_report(&w, v2, sid, false, "hole punch failed").await;
                }
            }
        });
    }

    /// Build and send a NatHoleReport for `sid`; log at debug on failure.
    /// `reason` labels the failure context in the log line.
    pub(crate) async fn send_nat_hole_report(
        writer: &Arc<ControlWriter>,
        v2: bool,
        sid: String,
        success: bool,
        reason: &str,
    ) {
        let report = FrpMessage::NatHoleReport(msg::NatHoleReport {
            sid: Some(sid),
            success,
        });
        if let Err(e) = writer.send(report, v2) {
            debug!(error = %e, "Failed to send NatHoleReport ({reason})");
        }
    }

    /// Go frp v0.71 `listenByKCP`/`listenByQUIC` accept loop: after the punch
    /// succeeds, ONE session serves all subsequent user connections until it
    /// dies. Each accepted stream is dialed to the local service and bridged
    /// in a detached task; a local-dial failure only drops that stream (Go
    /// `HandleTCPWorkConnection` runs per stream and never kills the
    /// session). The loop exits when the session dies (accept error on a
    /// dead session), the control session ends (`session_alive`), or the
    /// proxy is deleted (`proxy_token`).
    ///
    /// `PROVIDER_ACCEPT_TIMEOUT` bounds each accept so an idle live session
    /// is not pinned forever on one recv; after a timeout the loop re-checks
    /// `is_alive()` to distinguish an idle session (keep accepting) from a
    /// dead one (exit).
    ///
    /// The local dial also runs inside the per-stream task, bounded by
    /// session teardown, proxy deletion, and `LOCAL_DIAL_TIMEOUT` — a
    /// blackholed local service can no longer wedge the shared accept loop
    /// (Go parity: the dial is per-goroutine there; we additionally bound it
    /// where Go leaks the goroutine forever).
    #[allow(clippy::too_many_arguments)]
    async fn provider_accept_loop(
        session: crate::visitor::TunnelSession,
        local_addr: Option<String>,
        use_enc: bool,
        use_comp: bool,
        sk: String,
        proxy_name: String,
        alive: Arc<AtomicBool>,
        proxy_token: CancellationToken,
    ) {
        const PROVIDER_ACCEPT_TIMEOUT: Duration = Duration::from_secs(30);
        // Bounded per-stream local dial: a blackholed local service (SYN
        // silently dropped) must not park the stream + fd forever. Go frp
        // leaves the dial unbounded in the per-stream goroutine (a leak);
        // 15s is far beyond any sane local connect.
        const LOCAL_DIAL_TIMEOUT: Duration = Duration::from_secs(15);
        loop {
            tokio::select! {
                _ = wait_session_dead(&alive) => {
                    // Control session torn down (reconnect/stop): the
                    // detached bridge tasks are session-bound and abort via
                    // the same flag; exit here.
                    debug!(proxy_name = %proxy_name, "XTCP provider '{}': session ended, closing P2P accept loop", proxy_name);
                    return;
                }
                _ = proxy_token.cancelled() => {
                    // Proxy deleted (CloseProxy/reload): close the session
                    // (releases UDP socket + KCP + yamux) and exit.
                    debug!(proxy_name = %proxy_name, "XTCP provider '{}': proxy deleted, closing P2P accept loop", proxy_name);
                    session.close().await;
                    return;
                }
                accepted = session.accept_stream(PROVIDER_ACCEPT_TIMEOUT) => {
                    match accepted {
                        Ok(mut stream) => {
                            let Some(local) = local_addr.clone() else {
                                // No local service for this proxy (should not
                                // happen — registration requires it); drop the
                                // stream, keep accepting.
                                warn!(proxy_name = %proxy_name, "XTCP provider '{}': no local address for P2P stream, dropping", proxy_name);
                                drop(stream);
                                continue;
                            };
                            // Go parity: the provider accept loop (Go
                            // client/proxy/xtcp.go listenByKCP/listenByQUIC
                            // ~145-172) spawns a GOROUTINE per accepted
                            // stream — the per-stream local dial must never
                            // block the shared session's accept loop. The
                            // dial + bridge run in a spawned task, bounded by
                            // session teardown, proxy deletion, and
                            // LOCAL_DIAL_TIMEOUT (bounded divergence from Go,
                            // which leaks the goroutine on a blackholed local
                            // service).
                            let use_enc2 = use_enc && !sk.is_empty();
                            let sk2 = sk.clone();
                            let pn = proxy_name.clone();
                            let alive_inner = alive.clone();
                            let p2p_token = proxy_token.clone();
                            tokio::spawn(async move {
                                // Bound the local connect: session teardown /
                                // proxy deletion / dial timeout drop the dial
                                // + stream and return; the accept loop is
                                // never parked.
                                let connect_fut =
                                    tokio::net::TcpStream::connect(local.as_str());
                                tokio::pin!(connect_fut);
                                let dial_timeout = tokio::time::sleep(LOCAL_DIAL_TIMEOUT);
                                tokio::pin!(dial_timeout);
                                let local_stream = tokio::select! {
                                    r = &mut connect_fut => match r {
                                        Ok(s) => s,
                                        Err(e) => {
                                            // Go parity: HandleTCPWorkConnection
                                            // logs and returns; the session
                                            // accept loop continues.
                                            warn!(proxy_name = %pn, error = %e, "XTCP provider '{}': connect local failed, dropping P2P stream", pn);
                                            return;
                                        }
                                    },
                                    _ = wait_session_dead(&alive_inner) => {
                                        // Session torn down (reconnect/stop):
                                        // drop the dial + stream.
                                        debug!(proxy_name = %pn, "XTCP provider '{}': session ended during local connect, dropping P2P stream", pn);
                                        return;
                                    }
                                    _ = p2p_token.cancelled() => {
                                        // Proxy deleted (CloseProxy/reload):
                                        // drop the dial + stream.
                                        debug!(proxy_name = %pn, "XTCP provider '{}': proxy deleted during local connect, dropping P2P stream", pn);
                                        return;
                                    }
                                    _ = &mut dial_timeout => {
                                        // Bounded dial: a blackholed local
                                        // service (SYN silently dropped) must
                                        // not hold the stream + fd forever.
                                        warn!(proxy_name = %pn, local = %local, "XTCP provider '{}': local dial timed out ({}s), dropping P2P stream", pn, LOCAL_DIAL_TIMEOUT.as_secs());
                                        return;
                                    }
                                };
                                frp_core::transport::set_nodelay(&local_stream);
                                let (local_r, local_w) = local_stream.into_split();
                                let (p2p_r, p2p_w) = tokio::io::split(&mut stream);
                                let bridge = async {
                                    if use_enc2 {
                                        let key =
                                            frp_core::encryption::derive_key(&sk2);
                                        frp_core::bridge::bridge_encrypted(
                                            local_r,
                                            local_w,
                                            p2p_r,
                                            p2p_w,
                                            &key,
                                            use_comp,
                                            vec![],
                                            None,
                                            None,
                                            None,
                                            false,
                                        )
                                        .await;
                                    } else {
                                        frp_core::bridge::bridge_plain(
                                            local_r,
                                            local_w,
                                            p2p_r,
                                            p2p_w,
                                            use_comp,
                                            vec![],
                                            None,
                                            None,
                                        )
                                        .await;
                                    }
                                };
                                tokio::pin!(bridge);
                                tokio::select! {
                                    _ = &mut bridge => {}
                                    _ = wait_session_dead(&alive_inner) => {
                                        // Session torn down: drop the
                                        // bridge futures, closing the
                                        // P2P stream and the local
                                        // connection.
                                        debug!(proxy_name = %pn, "XTCP provider '{}': session ended, closing P2P bridge", pn);
                                    }
                                    _ = p2p_token.cancelled() => {
                                        // Proxy deleted: drop the
                                        // bridge futures, closing the
                                        // P2P stream and the local
                                        // connection.
                                        debug!(proxy_name = %pn, "XTCP provider '{}': proxy deleted, closing P2P bridge", pn);
                                    }
                                }
                            });
                        }
                        Err(e) => {
                            if session.is_alive() {
                                // Idle timeout on a live session: keep
                                // accepting.
                                continue;
                            }
                            // Session dead (closed, peer gone, driver exit):
                            // close the session (releases UDP socket + KCP +
                            // yamux / QUIC) and exit.
                            debug!(proxy_name = %proxy_name, error = %e, "XTCP provider '{}': P2P session closed: {}", proxy_name, e);
                            session.close().await;
                            return;
                        }
                    }
                }
            }
        }
    }

    /// Handle a NatHoleResp message from the server (XTCP response).
    ///
    /// Routes to waiting visitor (by transaction_id) or spawns provider hole
    /// punch task (by sid). Provider side iterates candidate addresses from
    /// the server's NAT analysis.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn handle_nat_hole_resp(
        &self,
        resp: msg::NatHoleResp,
        pending_xtcp: &mut HashMap<String, String>,
        visitor_pending: &mut HashMap<String, oneshot::Sender<Result<msg::NatHoleResp, String>>>,
        xtcp_sockets: &std::sync::Arc<
            tokio::sync::Mutex<
                std::collections::HashMap<String, std::sync::Arc<tokio::net::UdpSocket>>,
            >,
        >,
        writer: &Arc<ControlWriter>,
        session_alive: Arc<AtomicBool>,
        proxy_token: CancellationToken,
    ) {
        // Route to waiting visitor first (Go frps compat path).
        let txn_id = resp.transaction_id.clone();
        if !txn_id.is_empty() {
            if let Some(tx) = visitor_pending.remove(&txn_id) {
                info!(transaction_id = %txn_id, "XTCP visitor: received NatHoleResp for txn '{}'", txn_id);
                let _ = tx.send(Ok(resp));
                return;
            }
        }
        // Fall through: route to provider by server sid
        let sid = resp.sid.clone().unwrap_or_default();
        if let Some(err) = resp.error {
            warn!(error = %err, "XTCP NatHoleResp error: {}", err);
            if let Some(ref sid) = resp.sid {
                pending_xtcp.remove(sid);
            }
            // Close the STUN UDP socket cached for this sid (and drop its map
            // entry). Without this, every failed hole punch leaks one UDP
            // socket + one map entry until the control loop is torn down.
            xtcp_sockets.lock().await.remove(&sid);
            return;
        }
        let proxy_name = pending_xtcp.remove(&sid).unwrap_or_default();
        if proxy_name.is_empty() {
            warn!(sid = %sid, "XTCP NatHoleResp: unknown sid '{}'", sid);
            // The STUN socket may still be cached under this sid (e.g. when the
            // NatHoleClient write failed before `pending_xtcp` was populated,
            // leaving an orphaned socket). Drop it here so an unknown sid
            // cannot leak a UDP socket + map entry.
            xtcp_sockets.lock().await.remove(&sid);
            return;
        }
        // F2 cancel-before-reinsert guard (defense in depth; the message-loop
        // arm guards before arming the token): a reload-removed or
        // health-closed proxy must not punch — its P2P token was cancelled at
        // the removal/close, so spawning here would arm an uncancelled bridge
        // that runs until the peer closes. Mirrors the visitor.rs
        // conn_cancel.is_cancelled() early-bail pattern. `pending_xtcp` was
        // already reclaimed above; drop the cached STUN socket so the bailed
        // resp cannot leak it either.
        if !self.punch_proxy_still_live(&proxy_name).await {
            debug!(proxy_name = %proxy_name, "XTCP provider '{}': proxy no longer live (reload/health close), aborting NatHoleResp", proxy_name);
            xtcp_sockets.lock().await.remove(&sid);
            return;
        }
        let candidate_addrs = resp.candidate_addrs.unwrap_or_default();
        let assisted_addrs = resp.assisted_addrs.unwrap_or_default();
        let detect_behavior = resp.detect_behavior.clone();
        let p2p_protocol = resp.protocol.clone().unwrap_or_default();
        info!(proxy_name = %proxy_name, candidate_count = %candidate_addrs.len(), "XTCP provider '{}': received {} candidate addresses from server",
            proxy_name, candidate_addrs.len());

        // Go frp v0.69.1 compat: use ReadTimeoutMs from the server's
        // NatHoleResp.detect_behavior as the hole-punch timeout, not a
        // hardcoded 5000ms. The server computes this as max(SendDelayMs) + 5000
        // (+30000 if listen_random_ports) minus the side's own send_delay.
        // Default to 5000ms if detect_behavior is not available. Go MakeHole
        // floors the guard at 5s too: `timeout := 5*time.Second; if
        // m.DetectBehavior.ReadTimeoutMs > 0 {...}` (pkg/nathole/nathole.go:
        // 248-250) — a hostile/misbehaving server sending 0 (or a negative)
        // must not make the punch fail instantly.
        let hole_punch_timeout = resp
            .detect_behavior
            .as_ref()
            .map(|db| {
                (db.read_timeout_ms.max(0) as u64)
                    .max(frp_core::xtcp_p2p::DEFAULT_HOLE_PUNCH_TIMEOUT_MS)
            })
            .unwrap_or(frp_core::xtcp_p2p::DEFAULT_HOLE_PUNCH_TIMEOUT_MS);

        // Spawn hole punch task (don't block control loop)
        let proxy_info = self.proxy_info_map.read().await.get(&proxy_name).map(|p| {
            (
                p.local_addr.clone(),
                p.use_encryption,
                p.use_compression,
                p.sk.clone(),
            )
        });
        let local_addr = proxy_info.as_ref().map(|p| p.0.clone());
        let xtcp_use_enc = proxy_info.as_ref().map(|p| p.1).unwrap_or(false);
        let xtcp_use_comp = proxy_info.as_ref().map(|p| p.2).unwrap_or(false);
        let xtcp_sk = proxy_info.as_ref().map(|p| p.3.clone()).unwrap_or_default();
        let proxy_name_clone = proxy_name.clone();
        let sid_clone = sid.clone();
        let xtcp_sockets_clone = xtcp_sockets.clone();
        let hp_timeout = hole_punch_timeout;
        let resp_writer = writer.clone();
        let resp_v2 = self.cfg.read().await.v2;
        // Client QUIC transport params for the provider-side tunnel session
        // (Go `listenByQUIC` reads `pxy.clientCfg.Transport.QUIC`).
        #[cfg(feature = "quic")]
        let quic_params = {
            let cfg = self.cfg.read().await;
            frp_core::quic::quic_params_from_option_values(
                cfg.quic_options
                    .as_ref()
                    .map(|q| q.keepalive_period)
                    .unwrap_or(0),
                cfg.quic_options
                    .as_ref()
                    .map(|q| q.max_idle_timeout)
                    .unwrap_or(0),
                cfg.quic_options
                    .as_ref()
                    .map(|q| q.max_incoming_streams)
                    .unwrap_or(0),
            )
        };
        tokio::spawn(async move {
            // Session-bound task: `session_alive` is cleared at session
            // teardown, which aborts both the hole punch and the P2P bridge
            // instead of leaving them probing a dead control channel. Also
            // proxy-bound: `proxy_token` is cancelled on CloseProxy/reload
            // removal so a deleted proxy cannot leak the bridge task + UDP
            // fd + KCP + yamux.
            let alive = session_alive;
            // Retrieve the STUN socket persisted by the control loop.
            let stun_socket = {
                let mut map = xtcp_sockets_clone.lock().await;
                map.remove(&sid_clone)
            };

            // Bind socket address family matching the first candidate to avoid
            // IPv4/IPv6 mismatch (EINVAL on macOS).
            let is_v4 = candidate_addrs
                .first()
                .and_then(|a| a.parse::<std::net::SocketAddr>().ok())
                .map(|a| a.is_ipv4())
                .unwrap_or(false);
            let bind_addr = if is_v4 { "0.0.0.0:0" } else { "[::]:0" };
            let fallback_bind = if is_v4 { "[::]:0" } else { "0.0.0.0:0" };

            let socket = if let Some(arc_sock) = stun_socket {
                // Try to unwrap the Arc. If there are other references,
                // bind a fresh socket (unlikely — we removed from map).
                match std::sync::Arc::try_unwrap(arc_sock) {
                    Ok(s) => s,
                    Err(_) => {
                        warn!(proxy_name = %proxy_name_clone, "XTCP provider '{}': STUN socket still shared, binding fresh", proxy_name_clone);
                        match tokio::net::UdpSocket::bind(bind_addr).await {
                            Ok(s) => s,
                            Err(_) => match tokio::net::UdpSocket::bind(fallback_bind).await {
                                Ok(s) => s,
                                Err(e) => {
                                    warn!(proxy_name = %proxy_name_clone, error = %e, "XTCP provider '{}': failed to bind UDP socket", proxy_name_clone);
                                    return;
                                }
                            },
                        }
                    }
                }
            } else {
                match tokio::net::UdpSocket::bind(bind_addr).await {
                    Ok(s) => s,
                    Err(_) => match tokio::net::UdpSocket::bind(fallback_bind).await {
                        Ok(s) => s,
                        Err(e) => {
                            warn!(proxy_name = %proxy_name_clone, error = %e, "XTCP provider '{}': failed to bind UDP socket", proxy_name_clone);
                            return;
                        }
                    },
                }
            };

            // Go frp v0.71: the punch creates a persistent SESSION (one
            // session per punch); user connections are accepted from it.
            // Data-plane protocol dispatch: the server echoes the visitor's
            // `protocol` (NatHoleVisitor → NatHoleResp) back to both peers.
            // Go provider dispatch (client/proxy/xtcp.go:124): ONLY "kcp"
            // selects listenByKCP; anything else — "quic", "" or an unknown
            // value — falls through to listenByQUIC. (Round-8 read "" as
            // KCP — a divergence for explicitly-empty protocol echoes.)
            //
            // Provider roles: yamux server (accepts the visitor's yamux
            // streams) or QUIC server (accepts the QUIC connection + streams).
            // candidate_addrs = the peer's mapped addrs, assisted_addrs = the
            // peer's assisted addrs, and the server's detect_behavior drives
            // the MakeHole probe. Scope the pinned punch future so its
            // borrows of `candidate_addrs`/`p2p_sid` are released before the
            // match arms below move the session values.
            let conv = frp_core::xtcp_p2p::conv_from_sid(&sid_clone);
            let kcp_cfg = frp_core::kcp::default_kcp_config();
            let p2p_key = if !xtcp_sk.is_empty() {
                Some(frp_core::xtcp_p2p::derive_detect_key(&xtcp_sk))
            } else {
                None
            };
            let p2p_sid = if sid_clone.is_empty() {
                None
            } else {
                Some(sid_clone.as_str())
            };
            let session_result: Result<crate::visitor::TunnelSession, String> = {
                let p2p_fut = async {
                    if p2p_protocol == "kcp" {
                        match frp_core::xtcp_p2p::xtcp_p2p_connect_yamux_session(
                            socket,
                            &candidate_addrs,
                            &assisted_addrs,
                            detect_behavior.as_ref(),
                            conv,
                            kcp_cfg,
                            hp_timeout,
                            false, // yamux_client = false (provider/server)
                            p2p_sid,
                            p2p_key.as_ref(),
                        )
                        .await
                        {
                            Ok(s) => Ok(crate::visitor::TunnelSession::Kcp(s)),
                            Err(e) => Err(e),
                        }
                    } else {
                        // default is quic (Go parity: anything not "kcp")
                        #[cfg(all(feature = "quic", feature = "kcp"))]
                        {
                            match frp_core::xtcp_session::xtcp_p2p_connect_quic_session_with_params(
                                socket,
                                &candidate_addrs,
                                &assisted_addrs,
                                detect_behavior.as_ref(),
                                hp_timeout,
                                p2p_sid,
                                p2p_key.as_ref(),
                                true, // is_server = true (provider is QUIC server)
                                quic_params,
                            )
                            .await
                            {
                                Ok(s) => Ok(crate::visitor::TunnelSession::Quic(s)),
                                Err(e) => Err(e),
                            }
                        }
                        #[cfg(not(all(feature = "quic", feature = "kcp")))]
                        {
                            warn!(proxy_name = %proxy_name_clone,
                            "XTCP provider '{}': protocol 'quic' requires both the quic and kcp features (the QUIC data plane reuses the KCP hole-punch machinery); refusing to silently fall back to KCP (Go peers may be on a QUIC data plane)",
                            proxy_name_clone);
                            Err(format!(
                                "XTCP provider '{}': protocol 'quic' requires both the quic and kcp features",
                                proxy_name_clone
                            ))
                        }
                    }
                };
                tokio::pin!(p2p_fut);
                tokio::select! {
                    r = &mut p2p_fut => r,
                    _ = wait_session_dead(&alive) => {
                        // Session torn down (reconnect/stop): drop the punch
                        // future, releasing its UDP socket, instead of probing
                        // a dead control channel for the full punch timeout.
                        debug!(proxy_name = %proxy_name_clone, "XTCP provider '{}': session ended during hole punch, aborting", proxy_name_clone);
                        return;
                    }
                    _ = proxy_token.cancelled() => {
                        // Proxy deleted (CloseProxy/reload): drop the punch
                        // future, releasing its UDP socket.
                        debug!(proxy_name = %proxy_name_clone, "XTCP provider '{}': proxy deleted during hole punch, aborting", proxy_name_clone);
                        return;
                    }
                }
            };
            match session_result {
                Ok(session) => {
                    // Send NatHoleReport with success=true after successful hole punch
                    // (Go frp compat: provider reports the punch result to the server
                    // BEFORE the accept loop — Go listenByKCP/listenByQUIC run
                    // after the report).
                    let ok_report = FrpMessage::NatHoleReport(msg::NatHoleReport {
                        sid: Some(sid_clone.clone()),
                        success: true,
                    });
                    let _ = resp_writer.send(ok_report, resp_v2);
                    info!(proxy_name = %proxy_name_clone, protocol = %p2p_protocol, "XTCP provider '{}': P2P session established", proxy_name_clone);
                    Self::provider_accept_loop(
                        session,
                        local_addr,
                        xtcp_use_enc,
                        xtcp_use_comp,
                        xtcp_sk,
                        proxy_name_clone,
                        alive,
                        proxy_token,
                    )
                    .await;
                }
                Err(e) => {
                    warn!(proxy_name = %proxy_name_clone, error = %e, "XTCP provider '{}': UDP hole punch + session connect failed", proxy_name_clone);
                    let fail_report = FrpMessage::NatHoleReport(msg::NatHoleReport {
                        sid: Some(sid_clone.clone()),
                        success: false,
                    });
                    let _ = resp_writer.send(fail_report, resp_v2);
                }
            }
        });
    }
}

/// Resolves once the control session has ended (session_alive == false).
/// Polls at 100ms so detached XTCP tasks (hole punch, P2P bridge) unwind
/// within one poll interval of session teardown instead of lingering up to
/// the punch timeout. Mirrors wait_sudp_shutdown in visitor.rs.
async fn wait_session_dead(session_alive: &Arc<AtomicBool>) {
    loop {
        if !session_alive.load(Ordering::Acquire) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// List local non-loopback IPv4 addresses for NAT hole punching.
/// Go frp v0.69.1 compat: nathole.ListLocalIPsForNatHole.
///
/// Enumerates local network interfaces and returns up to `max_items`
/// non-loopback, non-link-local IPv4 addresses. On Linux, reads from
/// /proc/net/fib_trie, with a fallback to `ip -o -4 addr show`. On
/// macOS, uses `/sbin/ifconfig`. On other platforms (e.g. Windows),
/// returns an empty vec.
pub(crate) fn list_local_ips_for_nat_hole(max_items: usize) -> Vec<String> {
    // Cache with 30s TTL: the XTCP provider path calls this once per
    // provider session, and each call re-reads /proc/net/fib_trie (or spawns
    // /sbin/ifconfig / `ip` subprocesses on the fallback paths). Local IPs
    // change rarely; the refresh cadence mirrors the visitor path's 30s TTL
    // cache in visitor.rs. Keyed on max_items so a caller asking for more
    // entries than the cached result holds never gets a short answer.
    static CACHE: std::sync::Mutex<Option<(usize, Vec<String>, Instant)>> =
        std::sync::Mutex::new(None);
    {
        if let Ok(cache) = CACHE.lock() {
            if let Some((ref cached_max, ref ips, ref time)) = *cache {
                if *cached_max == max_items && time.elapsed() < std::time::Duration::from_secs(30) {
                    return ips.clone();
                }
            }
        }
    }

    let mut ips: Vec<String> = Vec::new();

    // Linux: parse /proc/net/fib_trie for local IPs
    #[cfg(target_os = "linux")]
    {
        if ips.len() < max_items {
            if let Ok(content) = std::fs::read_to_string("/proc/net/fib_trie") {
                let mut in_local = false;
                for line in content.lines() {
                    if ips.len() >= max_items {
                        break;
                    }
                    let trimmed = line.trim();
                    if trimmed == "Local:" {
                        in_local = true;
                        continue;
                    }
                    if in_local && trimmed.is_empty() {
                        break;
                    }
                    if in_local {
                        // Lines with "|" under "Local:" section contain local IPs
                        if let Some(ip_part) = trimmed
                            .strip_prefix('|')
                            .or_else(|| trimmed.strip_prefix("+-"))
                        {
                            for word in ip_part.split_whitespace() {
                                if let Ok(ip) = word.parse::<std::net::Ipv4Addr>() {
                                    if !ip.is_loopback()
                                        && !ip.is_link_local()
                                        && !ip.is_multicast()
                                    {
                                        ips.push(ip.to_string());
                                    }
                                    break; // first valid IP per line
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // Linux fallback: `ip -o -4 addr show`
    #[cfg(target_os = "linux")]
    {
        if ips.is_empty() {
            if let Ok(output) = std::process::Command::new("ip")
                .args(["-o", "-4", "addr", "show"])
                .output()
            {
                if output.status.success() {
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    for line in stdout.lines() {
                        if ips.len() >= max_items {
                            break;
                        }
                        // Format: "1: lo    inet 127.0.0.1/8 scope host lo"
                        // We want the "inet" line with the IP address
                        let parts: Vec<&str> = line.split_whitespace().collect();
                        for part in &parts {
                            if let Some(ip_str) = part.split('/').next() {
                                if let Ok(ip) = ip_str.parse::<std::net::Ipv4Addr>() {
                                    if !ip.is_loopback()
                                        && !ip.is_link_local()
                                        && !ip.is_multicast()
                                    {
                                        ips.push(ip.to_string());
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // macOS fallback: parse ifconfig output
    #[cfg(target_os = "macos")]
    {
        if ips.is_empty() {
            if let Ok(output) = std::process::Command::new("/sbin/ifconfig").output() {
                if output.status.success() {
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    for line in stdout.lines() {
                        if ips.len() >= max_items {
                            break;
                        }
                        let trimmed = line.trim();
                        if let Some(ip_str) = trimmed.strip_prefix("inet ") {
                            let fields: Vec<&str> = ip_str.split_whitespace().collect();
                            if let Some(addr) = fields.first() {
                                if let Ok(ip) = addr.parse::<std::net::Ipv4Addr>() {
                                    if !ip.is_loopback()
                                        && !ip.is_link_local()
                                        && !ip.is_multicast()
                                    {
                                        ips.push(ip.to_string());
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // Update cache. Empty results are NOT cached: the first call in a
    // container where /proc/net/fib_trie is unreadable would otherwise pin
    // an empty list for the 30s TTL, masking a later re-read that succeeds
    // (e.g. once the `ip` fallback works or the network comes up).
    if !ips.is_empty() {
        if let Ok(mut cache) = CACHE.lock() {
            *cache = Some((max_items, ips.clone(), Instant::now()));
        }
    }

    ips
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Regression: `wait_session_dead` must resolve promptly when the
    /// session flag is cleared (100ms poll) so detached XTCP tasks unwind
    /// within one poll interval of session teardown instead of lingering up
    /// to the hole-punch timeout.
    #[tokio::test]
    async fn wait_session_dead_resolves_after_session_teardown() {
        let alive = Arc::new(AtomicBool::new(true));
        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
        let alive2 = alive.clone();
        let task = tokio::spawn(async move {
            let _ = entered_tx.send(());
            wait_session_dead(&alive2).await;
        });
        entered_rx.await.expect("session watcher never started");
        alive.store(false, Ordering::Release);
        tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .expect("wait_session_dead did not resolve after session teardown")
            .expect("session watcher task panicked");
    }

    /// Regression: a hole-punch future selected against `wait_session_dead`
    /// (the session-bound pattern used by `handle_nat_hole_client` and
    /// `handle_nat_hole_resp`) must abort on session teardown, dropping the
    /// resource it holds instead of probing a dead control channel for the
    /// full punch timeout. When the sandbox denies the UDP bind, a channel
    /// sender stands in for the socket and the abort-release assertion runs
    /// against the channel — the test never silently skips.
    #[tokio::test]
    async fn session_teardown_aborts_hole_punch_and_releases_socket() {
        let socket = match tokio::net::UdpSocket::bind("127.0.0.1:0").await {
            Ok(s) => Some(Arc::new(s)),
            Err(e) => {
                eprintln!(
                    "UDP bind denied ({e}); asserting abort semantics with a channel stand-in"
                );
                None
            }
        };
        // Channel stand-in for the socket: the sender is held by the punch
        // future and dropped on abort, resolving the receiver with Err —
        // the same drop-observable shape as the socket's Arc count.
        let (release_tx, release_rx) = tokio::sync::oneshot::channel::<()>();
        let alive = Arc::new(AtomicBool::new(true));
        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
        let alive2 = alive.clone();
        let socket_held = socket.clone();
        let task = tokio::spawn(async move {
            let _ = entered_tx.send(());
            // Stand-in for the real hole-punch future
            // (`xtcp_p2p_connect_yamux`): pending forever, and holding the
            // resource (the UDP socket, or the channel sender when the
            // sandbox denied the bind) so the select's drop path is
            // observable.
            let punch = async {
                let _guard = socket_held;
                let _sender = release_tx;
                std::future::pending::<Result<(), String>>().await
            };
            tokio::pin!(punch);
            tokio::select! {
                _ = &mut punch => {}
                _ = wait_session_dead(&alive2) => {}
            }
        });
        entered_rx.await.expect("hole punch task never started");
        alive.store(false, Ordering::Release);
        tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .expect("session-bound hole punch did not abort after session teardown")
            .expect("hole punch task panicked");
        // The aborted punch was dropped: whatever resource it held is released.
        match socket {
            Some(socket) => assert!(
                Arc::try_unwrap(socket).is_ok(),
                "UDP socket still referenced after abort"
            ),
            None => assert!(
                release_rx.await.is_err(),
                "channel stand-in still held after abort"
            ),
        }
    }

    /// Regression: a hole-punch future selected against the proxy's cancel
    /// token — the per-proxy deletion bound added alongside `wait_session_dead`
    /// in `handle_nat_hole_client`/`handle_nat_hole_resp` — must abort when the
    /// proxy is deleted (CloseProxy / reload removal), dropping the punch
    /// instead of probing until the peer closes. Covers the case
    /// `wait_session_dead` cannot: single-proxy deletion without session
    /// teardown.
    #[tokio::test]
    async fn p2p_punch_aborts_on_proxy_token_cancel() {
        let token = CancellationToken::new();
        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
        let token2 = token.clone();
        let task = tokio::spawn(async move {
            let _ = entered_tx.send(());
            // Stand-in for the real hole-punch future
            // (`xtcp_p2p_connect_yamux`): pending forever, like a punch against
            // a peer that never answers.
            let punch = std::future::pending::<Result<(), String>>();
            tokio::pin!(punch);
            tokio::select! {
                _ = &mut punch => {}
                _ = token2.cancelled() => {}
            }
        });
        entered_rx.await.expect("punch task never started");
        token.cancel();
        tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .expect("proxy-token-bound hole punch did not abort after proxy deletion")
            .expect("hole punch task panicked");
    }
}
