//! Work-conn assignment: `StartWorkConn` construction and the dispatcher.

use super::*;

/// Build a StartWorkConn message from request and address info.
/// Pure data construction — no `.await` calls. Extracted from the
/// async state machine in `assign_work_to_proxy`.
#[inline(never)]
fn build_start_work_conn(
    req: &PendingRequest,
    src_addr: &str,
    src_port: u16,
    dst_addr: &str,
    dst_port: u16,
) -> FrpMessage {
    FrpMessage::StartWorkConn(Box::new(msg::StartWorkConn {
        proxy_name: req.proxy_name.clone(),
        src_addr: if !src_addr.is_empty() {
            Some(src_addr.to_string())
        } else {
            None
        },
        src_port: if src_port != 0 { Some(src_port) } else { None },
        dst_addr: if !dst_addr.is_empty() {
            Some(dst_addr.to_string())
        } else {
            None
        },
        dst_port: if dst_port != 0 { Some(dst_port) } else { None },
        error: None,
        // use_encryption/use_compression: propagate proxy config settings.
        // Go frpc v0.69.1 ignores these fields (not in its StartWorkConn struct)
        // and uses its own proxy config. The server must match whatever the
        // provider does, so the bridge type (plain vs encrypted) is determined
        // below based on req.use_encryption/compression, NOT forced to false.
        // Rust frpc (work_conn.rs) respects swc.use_encryption over its own config.
        // CipherWriter now eagerly flushes IV on first poll_flush, preventing the
        // dual-CipherWriter deadlock that previously forced plain bridge for XTCP.
        use_encryption: if req.use_encryption { Some(true) } else { None },
        use_compression: if req.use_compression {
            Some(true)
        } else {
            None
        },
        // For XTCP STCP fallback: set empty nat_hole_sid marker so Rust frpc
        // knows this work conn is for STCP bridging, not XTCP notification.
        // When `proxy_info` is None the proxy was already unregistered in the
        // enqueue→bridge window, so this path is already broken (the bridge
        // fails or the peer rejects the StartWorkConn); omitting the marker
        // there is acceptable because the proxy type is unknown anyway.
        nat_hole_sid: if req
            .proxy_info
            .as_ref()
            .is_some_and(|p| p.proxy_type == "xtcp")
        {
            Some(String::new())
        } else {
            None
        },
        nat_hole_visitor_addr: None,
        sk: None,
    }))
}

/// The backend response-head deadline (seconds) for a `proxy_type == "http"`
/// non-CONNECT leg — Go frp v0.71.0 `VhostHTTPTimeout` →
/// `httputil.ReverseProxy.ResponseHeaderTimeoutS`. Pure wrapper over
/// [`crate::vhost::clamp_vhost_timeout`] so the floor/cap semantics have a
/// unit pin without spawning a bridge: a `<= 0` config floors to 60s — Go's
/// own `NewHTTPReverseProxy` does this floor (pkg/util/vhost/http.go:50-52:
/// `if option.ResponseHeaderTimeoutS <= 0 { option.ResponseHeaderTimeoutS =
/// 60 }`), so an unset value is 60s, never "no deadline" — and positive
/// values cap at 24h (Rust-only hardening against hostile huge configs; Go
/// has no cap).
pub(super) fn http_leg_head_deadline(vhost_http_timeout_secs: i64) -> u64 {
    crate::vhost::clamp_vhost_timeout(vhost_http_timeout_secs)
}

/// Assign `req` to `work_conn`, starting the bridge.
///
/// Returns `Ok(())` once the bridge task is spawned (work_conn and req are
/// consumed), or `Err(req)` if the StartWorkConn write failed — the work
/// conn is dead and the request (with its user conn) is returned so the
/// caller can retry it against a fresh work conn instead of dropping the
/// user connection (audit fix: dead pooled work conns used to fail the user
/// conn with no retry). Boxed: the request is large and this error is cold
/// (one alloc on the retry path; keeps `result_large_err` quiet).
pub(crate) async fn assign_work_to_proxy(
    mut work_conn: IoStream,
    req: PendingRequest,
    encryption_key: [u8; 16],
    state: Arc<AppState>,
    v2: bool,
    bridge_cancel: tokio_util::sync::CancellationToken,
) -> Result<(), Box<PendingRequest>> {
    // Extract peer address from user connection for PROXY protocol support
    let (src_addr, src_port) = req
        .user_conn
        .try_tcp()
        .and_then(|s| s.peer_addr().ok())
        .map(|a| (a.ip().to_string(), a.port()))
        .unwrap_or_default();

    // Proxy metadata is carried in the request (fetched once by the
    // dispatcher). When the snapshot is None — the STCP/XTCP
    // visitor-before-provider-registration race, where the request was
    // enqueued before the proxy was visible to the dispatcher — re-fetch
    // from the proxy map at bridge time (the old behavior), so the bridge
    // uses the now-registered proxy's metadata instead of empty
    // local_addr/dst_port. Clone the Arc (cheap refcount bump) so the
    // borrow does not block moving `req` into the spawned bridge task
    // below.
    let proxy_info = match req.proxy_info.clone() {
        Some(info) => Some(info),
        None => state.proxy_manager.get(&req.proxy_name).await,
    };
    // DstAddr/DstPort family semantics (Go v0.71.0): only the HTTP
    // reverse-proxy family sends NONE. Go wires its vhost http CreateConnFn
    // to `GetRealConn(rAddr, nil)` (server/proxy/http.go:64/114-122) — the
    // conn's remote address survives as src, the local endpoint is dropped,
    // and Go frpc falls back to 127.0.0.1:0 for the PROXY-protocol
    // destination pair (client/proxy/proxy.go:179-211:
    // `if m.DstAddr == "" { m.DstAddr = "127.0.0.1" }` — round-12 audit
    // B1: the pre-round-12 code reported the real vhost accept addr here,
    // shape-differing from Go on every http-type leg). Every OTHER raw
    // user-conn leg (tcp + https + tcpmux + stcp) reports the server-side
    // endpoint the user actually dialed (Go `handleUserTCPConnection` →
    // `GetWorkConnFromPool(userConn.RemoteAddr(), userConn.LocalAddr())`,
    // server/proxy/proxy.go:288, dst fields at 178-186), NOT the
    // client-declared local service (round-11 audit F1: local_str is never
    // set by Go frpc and is the wrong semantic even when set — the
    // frpc-side local service is not the address the user's connection
    // targeted on frps). HTTPS vhost legs reach here as raw passthrough
    // conns (`run_vhost_https_listener` enqueues the un-wrapped
    // `IoStream::Tcp` — frps only peeks the ClientHello SNI, vhost.rs), so
    // they report their real local addr exactly like Go's https handler.
    // The `local_addr` fallback below stays as the STCP/XTCP
    // visitor-before-registration safety net and for any future wrapped
    // conn; it is NOT a Go-parity path.
    let user_local = req.user_conn.try_tcp().and_then(|s| s.local_addr().ok());
    let http_reverse_proxy_leg = proxy_info.as_ref().is_some_and(|p| p.proxy_type == "http");
    let dst_addr = if http_reverse_proxy_leg {
        String::new()
    } else {
        user_local
            .map(|a| a.ip().to_string())
            .or_else(|| proxy_info.as_ref().and_then(|p| p.local_addr.clone()))
            .unwrap_or_default()
    };
    let dst_port = if http_reverse_proxy_leg {
        0
    } else {
        user_local
            .map(|a| a.port())
            .or_else(|| proxy_info.as_ref().and_then(|p| p.remote_port))
            .unwrap_or(0)
    };

    let swc = build_start_work_conn(&req, &src_addr, src_port, &dst_addr, dst_port);

    let write_result = if v2 {
        work_conn.write_v2_frame(&swc).await
    } else {
        work_conn.write_v1_frame(&swc).await
    };

    if let Err(e) = write_result {
        warn!(error = %e, "Failed to send StartWorkConn: {}", e);
        // The work conn is dead (e.g. the client closed it while pooled).
        // Return the request so the caller can re-enqueue it against a
        // fresh work conn instead of failing the user connection.
        return Err(Box::new(req));
    }

    // Flush StartWorkConn to wire before bridge data. KcpStream::poll_flush
    // now triggers immediate force_flush (update + drain + FEC encode + UDP send)
    // in the KCP driver, so Go frpc receives StartWorkConn as a separate KCP
    // output before bridge data arrives.
    if let Err(e) = work_conn.flush().await {
        warn!(error = %e, "Failed to flush StartWorkConn: {}", e);
    }

    // For XTCP STCP fallback: send a dummy NatHoleSid frame with
    // empty sid after StartWorkConn for Go frpc compatibility.
    // Go frpc's InWorkConn expects either an embedded nat_hole_sid in
    // StartWorkConn JSON (newer frp) or a separate NatHoleSid frame
    // immediately after StartWorkConn (Go frp v0.69.1). Our Rust frpc
    // provider's byte-peek (V1) / V2 frame read handles both formats.
    // The copy_bidirectional-semantics relay (used for XTCP STCP fallback
    // below) doesn't send a premature FIN, so the provider can safely
    // consume this frame without the old ECONNRESET race.
    // V2-aware: use V2 or V1 framing based on protocol version.
    if proxy_info.as_ref().is_some_and(|p| p.proxy_type == "xtcp") {
        let dummy = FrpMessage::NatHoleSid(msg::NatHoleSid::default());
        let write_result = if v2 {
            work_conn.write_v2_frame(&dummy).await
        } else {
            work_conn.write_v1_frame(&dummy).await
        };
        // A failure to deliver the empty NatHoleSid marker means the Go frpc
        // provider may not start its XTCP STCP fallback bridge; log it (unlike
        // the StartWorkConn write above, this one didn't name the failing frame).
        if let Err(e) = write_result {
            debug!(
                proxy_name = %req.proxy_name,
                error = %e,
                "failed to write dummy NatHoleSid frame to work conn: {e}"
            );
        }
    }

    debug!(proxy_name = %req.proxy_name, proxy_type = %proxy_info.as_ref().map(|p| p.proxy_type.as_str()).unwrap_or(""), "Bridging user conn to work conn for proxy '{}' (type={})", req.proxy_name, proxy_info.as_ref().map(|p| p.proxy_type.as_str()).unwrap_or(""));

    let proxy_name = req.proxy_name.clone();
    let metrics = state.proxy_metrics.get_or_create(&proxy_name).await;

    // HTTP vhost backend response-header timeout (Go frp compat:
    // VhostHTTPTimeout drives httputil.ReverseProxy.ResponseHeaderTimeoutS).
    // Exactly `proxy_type == "http"` on a NON-CONNECT request — the two
    // gates mirror Go v0.71.0's vhost architecture:
    //   * CONNECT: http.go:229-234 + 282-285 route CONNECT to
    //     connectHandler, which hijacks the conn and joins raw — the
    //     ReverseProxy transport (and with it ResponseHeaderTimeout) never
    //     arms, and the server never answers 504 on a silent backend.
    //   * https tunnels: the HTTPS Muxer's registryRouter serves raw TLS
    //     bytes (SNI routing only) — no ReverseProxy, no header deadline.
    // TCP/STCP/XTCP bridges have no such semantic either. The deadline
    // VALUE goes through the shared vhost clamp (`http_leg_head_deadline`
    // below, wrapping crate::vhost::clamp_vhost_timeout): a `<= 0` config
    // FLOORS to 60s and everything caps at 24h. The floor is not frp-rs
    // hardening — Go frp v0.71.0's NewHTTPReverseProxy floors
    // `ResponseHeaderTimeoutS <= 0` to 60s itself
    // (pkg/util/vhost/http.go:50-51), so an unset `vhost_http_timeout`
    // (config default 60) and an explicit 0 both arm the same 60s deadline;
    // there is no "0 disables the timeout" in Go (the old `> 0` gate —
    // arming nothing for a 0 config — carried a false Go citation; round-16
    // finding).
    let header_timeout = if proxy_info
        .as_ref()
        .is_some_and(|p| p.proxy_type == "http" && !req.request_is_connect)
    {
        Some(std::time::Duration::from_secs(http_leg_head_deadline(
            state.vhost_http_timeout,
        )))
    } else {
        None
    };

    // Spawn the bridge; select against the server shutdown token so a
    // graceful shutdown can interrupt half-open idle bridges instead of
    // waiting on TCP keepalive (2h) or yamux keepalive (90s) — audit D2-4 —
    // AND against the per-control `bridge_cancel` token so control teardown
    // (disconnect / supersession) stops the bridge: the work conn is owned
    // by this control, and a half-open client-side conn would otherwise
    // copy forever, leaking 1 task + 2 fds per reconnect with active
    // tunnels (HIGH finding). ONE task per bridged connection instead of
    // the old nested spawn whose JoinHandle was awaited only to extract the
    // panic payload (audit round 5, MEDIUM): the select is polled in-place
    // and panics are surfaced via catch_unwind, halving the task
    // allocations and wakeup registrations. The task is fire-and-forget
    // (bridges are connection-bounded and self-terminate; shutdown just
    // accelerates teardown). Note: in the release panic=abort profile the
    // panic aborts before catch_unwind fires — exactly as the old
    // JoinHandle-await also never fired there; in unwinding builds (tests)
    // the payload still reaches log_bridge_panic and the RAII ConnGuard
    // still releases the slot during unwind.
    let shutdown = state.shutdown_token.clone();
    let state_for_bridge = state.clone();
    let log_proxy_name = req.proxy_name.clone();
    tokio::spawn(async move {
        let fut = async {
            tokio::select! {
                _ = run_work_bridge(
                    work_conn,
                    req,
                    proxy_info,
                    encryption_key,
                    metrics,
                    header_timeout,
                    state_for_bridge,
                    v2,
                ) => {}
                _ = shutdown.cancelled() => {}
                _ = bridge_cancel.cancelled() => {}
            }
        };
        if let Err(p) = AssertUnwindSafe(fut).catch_unwind().await {
            log_bridge_panic(&log_proxy_name, "bridge", p);
        }
    });
    Ok(())
}
