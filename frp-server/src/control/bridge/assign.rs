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

/// Assign `req` to `work_conn`, starting the bridge off the control loop.
/// How long to wait for capacity on the retry channel before giving up.
///
/// The control loop drains `retry_rx` on every iteration, so `Full` is a short
/// transient (a mass pooled-conn death can emit many retries in one loop pass).
/// Waiting is cheap here — this runs on the spawned bridge task, not the
/// control loop — and losing the request closes a user conn the server could
/// still have served.
const RETRY_ENQUEUE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(1);

/// Hand a request whose work conn died back to the control loop.
///
/// `try_send` first (the common case: nothing queued), then wait briefly for
/// capacity instead of dropping the request — the pre-diff path re-enqueued
/// unconditionally into the `MAX_PENDING_REQUESTS`-bounded queue, so a
/// momentarily full channel here must not close the user conn. `None` is the
/// caller's explicit "do not retry" (fresh work conn: a dead one means the
/// client is gone), logged at debug to keep that pre-existing path quiet.
async fn requeue_dead_work_conn(
    retry_tx: Option<&tokio::sync::mpsc::Sender<Box<PendingRequest>>>,
    req: PendingRequest,
    proxy_name: &str,
    reason: &str,
) {
    let Some(tx) = retry_tx else {
        debug!(
            proxy_name = %proxy_name,
            "Dropping request after {}: no retry channel (fresh work conn)",
            reason
        );
        return;
    };
    let mut req = Box::new(req);
    let deadline = tokio::time::Instant::now() + RETRY_ENQUEUE_TIMEOUT;
    loop {
        match tx.try_send(req) {
            Ok(()) => return,
            Err(tokio::sync::mpsc::error::TrySendError::Closed(r)) => {
                warn!(
                    proxy_name = %proxy_name,
                    "Retry channel closed, dropping request after {}",
                    reason
                );
                drop(r);
                return;
            }
            Err(tokio::sync::mpsc::error::TrySendError::Full(r)) => {
                req = r;
                if tokio::time::Instant::now() >= deadline {
                    warn!(
                        proxy_name = %proxy_name,
                        timeout = ?RETRY_ENQUEUE_TIMEOUT,
                        "Retry channel full for {:?}, dropping request after {}",
                        RETRY_ENQUEUE_TIMEOUT,
                        reason
                    );
                    return;
                }
                tokio::time::sleep(std::time::Duration::from_millis(2)).await;
            }
        }
    }
}

///
/// Synchronous by design: no network I/O runs on the caller's task, so a
/// stalled or congested work connection can never head-of-line block the
/// control loop. The spawned task writes `StartWorkConn` (and any XTCP
/// `NatHoleSid` marker) under a bounded per-attempt timeout
/// (`pool::start_work_conn_write_timeout`) — deliberately shorter than the
/// request's `pending_request_timeout`, so a wedged work conn still leaves
/// budget for the retry. If writing `StartWorkConn` fails or times out and
/// `retry_tx` is `Some` (dead pooled work conn), the untouched
/// `PendingRequest` is handed back to the control loop for retry against a
/// replacement work connection.
pub(crate) fn assign_work_to_proxy(
    mut work_conn: IoStream,
    req: PendingRequest,
    encryption_key: [u8; 16],
    state: Arc<AppState>,
    v2: bool,
    bridge_cancel: tokio_util::sync::CancellationToken,
    retry_tx: Option<tokio::sync::mpsc::Sender<Box<PendingRequest>>>,
) {
    let shutdown = state.shutdown_token.clone();
    let log_proxy_name = req.proxy_name.clone();
    let request_budget = super::super::pool::pending_request_timeout(state.user_conn_timeout);
    let write_timeout = super::super::pool::start_work_conn_write_timeout(request_budget);
    tokio::spawn(async move {
        let fut = async {
            // Resolve metadata, build and deliver StartWorkConn under the
            // shutdown/bridge_cancel gates and a bounded write timeout so a
            // wedged work conn cannot park this task or stall the control loop.
            let setup = async {
                // Extract peer address from user connection for PROXY protocol support
                let (src_addr, src_port) = req
                    .user_conn
                    .try_tcp()
                    .and_then(|s| s.peer_addr().ok())
                    .map(|a| (a.ip().to_string(), a.port()))
                    .unwrap_or_default();

                // Proxy metadata is carried in the request (fetched once by the
                // dispatcher). When the snapshot is None — the STCP/XTCP
                // visitor-before-provider-registration race — re-fetch from
                // the proxy map at bridge time.
                let proxy_info = match req.proxy_info.clone() {
                    Some(info) => Some(info),
                    None => state.proxy_manager.get(&req.proxy_name).await,
                };

                // DstAddr/DstPort family semantics (Go v0.71.0): only the HTTP
                // reverse-proxy family sends NONE; every other raw user-conn leg
                // reports the server-side endpoint the user actually dialed.
                let user_local = req.user_conn.try_tcp().and_then(|s| s.local_addr().ok());
                let http_reverse_proxy_leg =
                    proxy_info.as_ref().is_some_and(|p| p.proxy_type == "http");
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

                let deadline = tokio::time::Instant::now() + write_timeout;
                let write_res = tokio::time::timeout_at(deadline, async {
                    if v2 {
                        work_conn.write_v2_frame(&swc).await
                    } else {
                        work_conn.write_v1_frame(&swc).await
                    }
                })
                .await;

                match write_res {
                    Ok(Ok(())) => {}
                    Ok(Err(e)) => {
                        warn!(error = %e, "Failed to send StartWorkConn: {}", e);
                        requeue_dead_work_conn(
                            retry_tx.as_ref(),
                            req,
                            &log_proxy_name,
                            "write failed",
                        )
                        .await;
                        return None;
                    }
                    Err(_elapsed) => {
                        warn!(
                            proxy_name = %log_proxy_name,
                            timeout = ?write_timeout,
                            "Timed out sending StartWorkConn after {:?}",
                            write_timeout
                        );
                        requeue_dead_work_conn(
                            retry_tx.as_ref(),
                            req,
                            &log_proxy_name,
                            "write timed out",
                        )
                        .await;
                        return None;
                    }
                }

                // Flush StartWorkConn to wire before bridge data.
                match tokio::time::timeout_at(deadline, work_conn.flush()).await {
                    Ok(Ok(())) => {}
                    Ok(Err(e)) => {
                        warn!(error = %e, "Failed to flush StartWorkConn: {}", e);
                    }
                    Err(_elapsed) => {
                        warn!(
                            proxy_name = %log_proxy_name,
                            "Timed out flushing StartWorkConn"
                        );
                    }
                }

                // For XTCP STCP fallback: send a dummy NatHoleSid frame with
                // empty sid after StartWorkConn for Go frpc compatibility.
                if proxy_info.as_ref().is_some_and(|p| p.proxy_type == "xtcp") {
                    let dummy = FrpMessage::NatHoleSid(msg::NatHoleSid::default());
                    let nat_res = tokio::time::timeout_at(deadline, async {
                        if v2 {
                            work_conn.write_v2_frame(&dummy).await
                        } else {
                            work_conn.write_v1_frame(&dummy).await
                        }
                    })
                    .await;
                    match nat_res {
                        Ok(Ok(())) => {}
                        Ok(Err(e)) => {
                            debug!(
                                proxy_name = %req.proxy_name,
                                error = %e,
                                "failed to write dummy NatHoleSid frame to work conn: {e}"
                            );
                        }
                        Err(_) => {
                            debug!(
                                proxy_name = %req.proxy_name,
                                "timed out writing dummy NatHoleSid frame to work conn"
                            );
                        }
                    }
                }

                debug!(
                    proxy_name = %req.proxy_name,
                    proxy_type = %proxy_info.as_ref().map(|p| p.proxy_type.as_str()).unwrap_or(""),
                    "Bridging user conn to work conn for proxy '{}' (type={})",
                    req.proxy_name,
                    proxy_info.as_ref().map(|p| p.proxy_type.as_str()).unwrap_or("")
                );

                // Registry lookup per connection. `ProxyMetricsRegistry` is a
                // sync (std `RwLock`) read-mostly map, so this costs one
                // uncontended read lock — far less than caching the handle on
                // `ProxyInfo`, which could diverge from the registry when the
                // entry is removed (teardown / unregister) while a `ProxyInfo`
                // clone is still alive.
                let metrics = state.proxy_metrics.get_or_create(&req.proxy_name);

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

                Some((work_conn, req, proxy_info, metrics, header_timeout))
            };

            let ready = tokio::select! {
                res = setup => res,
                _ = shutdown.cancelled() => None,
                _ = bridge_cancel.cancelled() => None,
            };

            let Some((work_conn, req, proxy_info, metrics, header_timeout)) = ready else {
                return;
            };

            tokio::select! {
                _ = run_work_bridge(
                    work_conn,
                    req,
                    proxy_info,
                    encryption_key,
                    metrics,
                    header_timeout,
                    state,
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
}
