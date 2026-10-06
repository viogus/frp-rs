//! The STCP/XTCP visitor listener: the local TCP accept loop
//! (`run_visitor_listener`) and the loop-invariant per-connection payload it
//! shares with each accepted connection's handler task (`VisitorConnCtx`).
//!
//! Split out of `frp-client/src/visitor.rs` by the plan's P3 seam 1
//! (`docs/refactor-large-modules.md` P3, `visitor/stcp.rs`) as a pure move: the
//! function body and every comment in it travel verbatim. This module is a
//! *child* of `visitor`, which is what lets it keep reaching the parent's
//! private items (`VisitorTransportConfig`, `VisitorDialPlan`,
//! `plan_visitor_dial`, `bridge_until_cancelled`, `XtcpPunchConfig`,
//! `TunnelSession`, `process_tunnel_start_events`, `open_tunnel`,
//! `run_sudp_visitor_listener`, ...) without a single visibility change; the
//! two items it *defines* (`run_visitor_listener`, `VisitorConnCtx`) keep
//! their original `pub(crate)` / private tokens. `visitor.rs` re-exports
//! `run_visitor_listener`, so the spelled path at the `service/session.rs`
//! call site (`crate::visitor::run_visitor_listener`) is unchanged.
//!
//! Coverage of the moved code, measured at the split (see the batch report for
//! the lane-by-lane evidence): the STCP relay success path, the SUDP dispatch
//! and the XTCP fallback path have end-to-end lanes; the `tcp_mux`-enabled
//! yamux-wrap arms, the accept-error arm and the three "shutting down,
//! abandoning" arms have none.

use super::*;

/// Loop-invariant per-listener state an accepted user connection needs to
/// spawn its handler task. Built ONCE per listener from the destructured
/// `VisitorListenerConfig`; each accepted connection clones the `Arc`
/// (one refcount bump) instead of cloning ~16 Strings + a
/// `VisitorTransportConfig` per connection (round-17 audit C). The handler
/// task borrows from the Arc it owns for its whole lifetime.
struct VisitorConnCtx {
    server_addr: String,
    server_port: u16,
    protocol: TransportProtocol,
    server_name: String,
    server_user: String,
    secret_key: String,
    name: String,
    tls_enable: bool,
    tls_server_name: String,
    tls_ca_file: Option<String>,
    visitor_type: String,
    fallback_timeout_ms: u64,
    fallback_to: String,
    user: String,
    run_id: String,
    transport: VisitorTransportConfig,
    use_encryption: bool,
    use_compression: bool,
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
        // SUDP-only: the STCP TCP accept path ignores the negotiated
        // UDPPacket codec.
        udp_packet_codec: _,
        // Client QUIC transport params for the XTCP tunnel session (Go
        // clientCfg.Transport.QUIC).
        #[cfg(all(feature = "quic", feature = "kcp"))]
        quic_params,
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
            cancel: listener_cancel.clone(),
            #[cfg(all(feature = "quic", feature = "kcp"))]
            quic_params,
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

    // Round-17 audit C: the per-connection payload used to clone ~16 Strings
    // + a VisitorTransportConfig on every accepted connection. All of it is
    // loop-invariant — build once, share via Arc, clone the Arc per conn.
    let conn_cfg = Arc::new(VisitorConnCtx {
        server_addr,
        server_port,
        protocol,
        server_name,
        server_user,
        secret_key,
        name,
        tls_enable,
        tls_server_name,
        tls_ca_file,
        visitor_type,
        fallback_timeout_ms,
        fallback_to,
        user,
        run_id,
        transport: VisitorTransportConfig {
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
        },
        use_encryption,
        use_compression,
    });

    loop {
        // Check graceful shutdown signal before each accept (Go frp compat:
        // visitor listeners exit cleanly instead of being aborted).
        if shutdown.load(Ordering::Relaxed) {
            info!(name = %conn_cfg.name, "Visitor '{}' shutting down gracefully", conn_cfg.name);
            listener_cancel.cancel();
            return;
        }

        match listener.accept().await {
            Ok((user_conn, peer)) => {
                frp_core::transport::set_nodelay(&user_conn);
                debug!(name = %conn_cfg.name, peer = %peer, "Visitor '{}': user connection from {}", conn_cfg.name, peer);

                // Round-17 audit C: one Arc clone per connection instead of the
                // ~16 String + transport-struct clones. The spawned task
                // borrows from the Arc it owns (binds below).
                let conn_cfg = conn_cfg.clone();

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
                    // Borrow the listener-invariant payload from the Arc this
                    // task owns (round-17 audit C) — no per-connection clones.
                    let sa: &str = &conn_cfg.server_addr;
                    let sp = conn_cfg.server_port;
                    let pt: &TransportProtocol = &conn_cfg.protocol;
                    let tls_enable = conn_cfg.tls_enable;
                    let tls_sn: &str = &conn_cfg.tls_server_name;
                    let tls_ca: &Option<String> = &conn_cfg.tls_ca_file;
                    let sn: &str = &conn_cfg.server_name;
                    let su: &str = &conn_cfg.server_user;
                    let sk: &str = &conn_cfg.secret_key;
                    let visitor_name: &str = &conn_cfg.name;
                    let vt: &str = &conn_cfg.visitor_type;
                    let fb_to: &str = &conn_cfg.fallback_to;
                    let u: &str = &conn_cfg.user;
                    let rid: &str = &conn_cfg.run_id;
                    let transport: &VisitorTransportConfig = &conn_cfg.transport;
                    let use_encryption = conn_cfg.use_encryption;
                    let use_compression = conn_cfg.use_compression;
                    let fallback_timeout_ms = conn_cfg.fallback_timeout_ms;

                    // Dial options for STCP fallback (fresh connections only).
                    let plan = plan_visitor_dial(sa, sp, pt, tls_enable, tls_sn, tls_ca, transport);
                    let opts = plan.opts;
                    let yamux_keepalive = plan.yamux_keepalive_secs;
                    let yamux_idle_dead_timeout = plan.yamux_idle_dead_timeout_secs;

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
                            visitor_name,
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
                                    let key = frp_core::encryption::derive_key(sk);
                                    if !bridge_until_cancelled(
                                        visitor_name,
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
                                            false,
                                        ),
                                    )
                                    .await
                                    {
                                        return; // drops both bridge halves
                                    }
                                } else if !bridge_until_cancelled(
                                    visitor_name,
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
                        let mut server_conn = if let (Some(ka), Some(ka_timeout)) =
                            (yamux_keepalive, yamux_idle_dead_timeout)
                        {
                            match crate::control::wrap_client_mux(raw_stream, ka, ka_timeout).await
                            {
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

                        let stcp_proxy_name = if fb_to.is_empty() { sn } else { fb_to };
                        // Apply the visitor's own encryption/compression config to the
                        // STCP fallback bridge. Go frp semantics: `fallbackTo` routes to
                        // a SEPARATE STCP visitor with its own encryption config, but we
                        // don't have access to that separate config here. Using the XTCP
                        // visitor's encryption/compression is a pragmatic approximation
                        // that is strictly better than the previous always-plain behavior.
                        let nvc = crate::proxy::create_visitor_conn_msg(
                            stcp_proxy_name,
                            sk,
                            use_encryption,
                            use_compression,
                            Some(su).filter(|s| !s.is_empty()),
                            Some(u).filter(|s| !s.is_empty()),
                            Some(rid).filter(|s| !s.is_empty()),
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
                            let key = frp_core::encryption::derive_key(sk);
                            if !bridge_until_cancelled(
                                visitor_name,
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
                                    false,
                                ),
                            )
                            .await
                            {}
                        } else {
                            if !bridge_until_cancelled(
                                visitor_name,
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
                        let mut server_conn = if let (Some(ka), Some(ka_timeout)) =
                            (yamux_keepalive, yamux_idle_dead_timeout)
                        {
                            match crate::control::wrap_client_mux(raw_stream, ka, ka_timeout).await
                            {
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
                            sn,
                            sk,
                            use_encryption,
                            use_compression,
                            Some(su).filter(|s| !s.is_empty()),
                            Some(u).filter(|s| !s.is_empty()),
                            Some(rid).filter(|s| !s.is_empty()),
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
                            let key = frp_core::encryption::derive_key(sk);
                            if !bridge_until_cancelled(
                                visitor_name,
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
                                    false,
                                ),
                            )
                            .await
                            {}
                        } else {
                            if !bridge_until_cancelled(
                                visitor_name,
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
                                ),
                            )
                            .await
                            {}
                        }
                    }
                });
            }
            Err(e) => {
                warn!(name = %conn_cfg.name, error = %e, "Visitor '{}': accept error: {}", conn_cfg.name, e);
                listener_cancel.cancel();
                break;
            }
        }
    }
}
