#[cfg(feature = "quic")]
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::AsyncReadExt;
use tokio::sync::oneshot;
use tracing::{debug, info, instrument, warn};

use frp_core::msg::{self, FrpMessage};
use frp_core::mux;
use frp_core::protocol::write_msg;
#[cfg(feature = "websocket")]
use frp_core::transport::{accept_websocket, accept_websocket_from_peeked};
use frp_core::transport::{split_work_conn_halves, IoStream, PreReadStream};
#[cfg(feature = "quic")]
use tokio_util::sync::CancellationToken;

use crate::control;
use crate::lock::RwLockExt;
use crate::nathole::controller as nathole_ctrl;
use crate::nathole::{classify, NAT_HOLE_TIMEOUT};
use crate::state::{AppState, InternalMsg};

/// Go frp visitor authorization: empty `allow_users` is owner-only, `*` is a
/// wildcard, otherwise the list is a specific allow-list.
pub(crate) fn visitor_user_allowed(
    authenticated_user: &str,
    owner: &str,
    allow_users: &[String],
) -> bool {
    if allow_users.is_empty() {
        authenticated_user == owner
    } else {
        allow_users
            .iter()
            .any(|user| user == "*" || user == authenticated_user)
    }
}

// ---------------------------------------------------------------
// STCP visitor connection handler
// ---------------------------------------------------------------

/// Handle an incoming STCP NewVisitorConn on the main accept port.
///
/// Supports two auth modes:
/// 1. Go-compatible: sign_key = MD5(proxy.sk + timestamp), lookup by proxy_name
///    then validate the hash against the registered sk.
/// 2. Legacy Rust: sign_key = raw sk value, looked up directly in sk_index.
pub(crate) async fn handle_visitor_conn_inner(
    mut stream: IoStream,
    msg: msg::NewVisitorConn,
    state: Arc<AppState>,
    v2: bool,
) {
    let sign_key = msg.sign_key.unwrap_or_default();
    let timestamp = msg.timestamp.unwrap_or(0);

    // Visitor-segment encryption/compression flags (Go 三段式第 1 段).
    // `use_encryption` from the visitor's `[[visitors]] transport.useEncryption`
    // decides whether the bridge wraps the visitor conn with `derive_key(sk)`.
    // `use_compression` is NOT implemented for the visitor segment yet — log it
    // and ignore (the server still bridges the visitor segment plaintext when
    // only compression is requested).
    let visitor_use_encryption = msg.use_encryption.unwrap_or(false);
    let visitor_use_compression = msg.use_compression.unwrap_or(false);
    if visitor_use_compression {
        debug!(
            proxy_name = %msg.proxy_name,
            "NewVisitorConn use_compression requested by visitor for '{}' — visitor-segment compression not implemented yet, ignoring (only visitor-segment encryption is supported)",
            msg.proxy_name
        );
    }

    // Validate timestamp freshness to prevent replay attacks.
    // A MISSING timestamp skips the freshness window — same semantics as the
    // control-channel Login path — so legacy/Go clients that omit it are not
    // rejected once the server enables authenticationTimeout. A PRESENT ts=0
    // is still validated (and rejected as stale), like Login.
    let auth_timeout = state.reloadable.read_ok().auth_cfg.authentication_timeout;
    let ts_valid = if msg.timestamp.is_none() {
        Ok(())
    } else {
        frp_core::auth::validate_timestamp_freshness(timestamp, auth_timeout)
    };

    // --- Mode 1: Go-compatible — lookup by proxy_name, validate MD5(sk + timestamp) ---
    let proxy_name = if let Some(proxy_info) = state.proxy_manager.get(&msg.proxy_name).await {
        match proxy_info.sk.as_deref().filter(|s| !s.is_empty()) {
            Some(sk) => {
                // Verify the token first, freshness second: an unauthenticated
                // caller must not learn whether the timestamp window was
                // exceeded, and the freshness check runs on attacker-controlled
                // input.
                if sign_key.is_empty() {
                    warn!(proxy_name = %msg.proxy_name, "STCP visitor: missing sign_key for protected proxy '{}'", msg.proxy_name);
                    None
                } else if !frp_core::auth::verify_token(sk, timestamp, &sign_key) {
                    warn!(proxy_name = %msg.proxy_name, "STCP visitor MD5 auth mismatch for proxy '{}'", msg.proxy_name);
                    None
                } else if let Err(e) = &ts_valid {
                    warn!(proxy_name = %msg.proxy_name, error = %e, "STCP visitor: timestamp rejected for proxy '{}'", msg.proxy_name);
                    None
                } else {
                    debug!(proxy_name = %msg.proxy_name, "STCP visitor auth OK (Go-compat MD5, constant-time) for proxy '{}'", msg.proxy_name);
                    Some(msg.proxy_name.clone())
                }
            }
            None => {
                // No sk configured — no cryptographic proof of access.
                // Go frp parity: admit the visitor (the owner/allow_users
                // check above still applies; empty allow_users is owner-only).
                // A no-sk proxy with no allow_users and an empty owner user
                // is open to any anonymous frps client — surface that loudly
                // per connection so operators configure an sk or allow_users.
                if proxy_info.allow_users.is_empty() && proxy_info.user.is_empty() {
                    warn!(proxy_name = %msg.proxy_name, "STCP visitor: proxy '{}' has no sk and no visitor authorization — anyone with frps access can connect (configure secret_key or allow_users)", msg.proxy_name);
                } else {
                    debug!(proxy_name = %msg.proxy_name, "STCP visitor: proxy '{}' has no sk, relying on visitor authorization", msg.proxy_name);
                }
                Some(msg.proxy_name.clone())
            }
        }
    } else {
        None
    };

    // --- Mode 2: Legacy Rust — raw sk_index lookup (backward compat) ---
    let proxy_name = match proxy_name {
        Some(pn) => pn,
        None => {
            // Fall back to raw sk lookup for old Rust clients that send raw sk as sign_key.
            // Look up by msg.proxy_name directly — do NOT iterate the whole map:
            // multiple proxies sharing the same sk would route to the wrong one.
            let sk_map = state.xtcp.sk_index.read().await;
            let pn = match sk_map.get(&msg.proxy_name) {
                Some(stored_sk) if *stored_sk == sign_key => {
                    debug!(proxy_name = %msg.proxy_name, "STCP visitor auth OK (raw sk_index lookup) for proxy '{}'", msg.proxy_name);
                    Some(msg.proxy_name.clone())
                }
                _ => None,
            };
            match pn {
                Some(pn) => pn,
                None => {
                    // SAFETY: chars().take(8) is safe on any UTF-8 input, including
                    // multi-byte characters. Byte-index slicing (&s[..8]) would
                    // panic if byte 8 falls inside a multi-byte char boundary.
                    let sign_key_prefix: String = sign_key.chars().take(8).collect();
                    warn!(proxy_name = %msg.proxy_name, sign_key_prefix = %sign_key_prefix, "NewVisitorConn: no STCP proxy found for proxy_name='{}', sign_key='{}...'",
                        msg.proxy_name, sign_key_prefix);
                    // Send error response to visitor (Go frp expects NewVisitorConnResp)
                    let resp = FrpMessage::NewVisitorConnResp(msg::NewVisitorConnResp {
                        proxy_name: msg.proxy_name.clone(),
                        error: Some("proxy not found".into()),
                    });
                    let _ = write_msg(&mut stream, &resp, v2).await;
                    return;
                }
            }
        }
    };

    // Look up the provider's run_id from proxy_manager
    let run_id = state.proxy_manager.get_run_id(&proxy_name).await;
    let run_id = match run_id {
        Some(id) => id,
        None => {
            warn!(proxy_name = %proxy_name, "NewVisitorConn: no run_id found for proxy '{}'", proxy_name);
            // Send error response to visitor
            let resp = FrpMessage::NewVisitorConnResp(msg::NewVisitorConnResp {
                proxy_name: proxy_name.clone(),
                error: Some("provider not found".into()),
            });
            let _ = write_msg(&mut stream, &resp, v2).await;
            return;
        }
    };

    // Bind fresh visitor authorization to an existing authenticated control.
    // Go v0.70.1 fallback: visitors without a run_id are admitted with the
    // empty identity and the normal owner/allow-users check.
    if let Some(proxy_info) = state.proxy_manager.get(&proxy_name).await {
        let visitor_identity = match msg.run_id.as_deref() {
            Some(visitor_run_id) if !visitor_run_id.is_empty() => state
                .run_id_to_ctl_tx
                .read()
                .await
                .get(visitor_run_id)
                .map(|control| control.user.clone())
                .unwrap_or_default(),
            _ => String::new(),
        };
        if !visitor_user_allowed(&visitor_identity, &proxy_info.user, &proxy_info.allow_users) {
            warn!(visitor_run_id = ?msg.run_id, proxy_name = %proxy_name, "STCP visitor has no trusted identity allowed for proxy '{}'", proxy_name);
            let resp = FrpMessage::NewVisitorConnResp(msg::NewVisitorConnResp {
                proxy_name: proxy_name.clone(),
                error: Some("visitor not allowed".into()),
            });
            let _ = write_msg(&mut stream, &resp, v2).await;
            return;
        }
    }

    // Check for graceful shutdown before proceeding — if the server is shutting
    // down, the control handler may no longer be accepting messages and the
    // visitor connection would be silently dropped. Return an error immediately
    // so the visitor can retry against a healthy server.
    //
    // NOTE: This check may produce false-positive rejections during the drain
    // phase. The CancellationToken fires before individual control handlers
    // finish draining, so a visitor arriving during drain can be rejected even
    // though the control handler is still processing VisitorConn messages.
    // This is acceptable defense-in-depth: the visitor receives a clean error
    // response ("server shutting down") and retries, which is better than
    // silently dropping the connection with no response.
    if state.shutdown_token.is_cancelled() {
        warn!(
            proxy_name = %proxy_name, run_id = %run_id,
            "STCP visitor for proxy '{}' rejected: server is shutting down",
            proxy_name
        );
        let resp = FrpMessage::NewVisitorConnResp(msg::NewVisitorConnResp {
            proxy_name: proxy_name.clone(),
            error: Some("server shutting down".into()),
        });
        let _ = write_msg(&mut stream, &resp, v2).await;
        return;
    }

    let ctl_tx = {
        let map = state.run_id_to_ctl_tx.read().await;
        map.get(&run_id).cloned()
    };

    match ctl_tx {
        Some(ctl) => {
            info!(proxy_name = %proxy_name, run_id = %run_id, "STCP visitor for proxy '{}' routed to provider {}", proxy_name, run_id);
            // Send success response to visitor BEFORE forwarding the stream
            // (Go frp visitor expects NewVisitorConnResp on the same connection)
            let resp = FrpMessage::NewVisitorConnResp(msg::NewVisitorConnResp {
                proxy_name: proxy_name.clone(),
                error: None,
            });
            if let Err(e) = write_msg(&mut stream, &resp, v2).await {
                warn!(proxy_name = %proxy_name, error = %e, "Failed to send NewVisitorConnResp for proxy '{}': {}", proxy_name, e);
                return;
            }
            // Use send().await, not try_send: we already sent success to the
            // visitor, so this connection MUST be delivered. Backpressure is
            // correct here — the visitor is waiting anyway.
            if ctl
                .tx
                .send(InternalMsg::VisitorConn {
                    proxy_name,
                    visitor_conn: stream,
                    visitor_use_encryption,
                })
                .await
                .is_err()
            {
                // Channel closed: provider disconnected between auth check
                // and delivery. Visitor will time out and retry.
                warn!(run_id = %run_id, "Provider for run_id {} disconnected during visitor delivery", run_id);
            }
        }
        None => {
            warn!(run_id = %run_id, "No provider found for run_id {}", run_id);
            // Send error response to visitor
            let resp = FrpMessage::NewVisitorConnResp(msg::NewVisitorConnResp {
                proxy_name: proxy_name.clone(),
                error: Some("provider disconnected".into()),
            });
            let _ = write_msg(&mut stream, &resp, v2).await;
        }
    }
}

// ---------------------------------------------------------------
// XTCP NAT hole visitor handler
// ---------------------------------------------------------------

/// Handle an incoming XTCP NatHoleVisitor connection.
///
/// Uses transaction_id and proxy_name from the message directly.
/// Validates proxy exists, looks up the provider, creates a NAT session,
/// forwards NatHoleClient to the provider via InternalMsg,
/// writes NatHoleResp (OK or error) to the visitor via the accept-loop writer,
/// and waits for the provider's report signal.
#[instrument(skip(stream, state), fields(proxy_name = %msg.proxy_name, transaction_id = %msg.transaction_id))]
pub(crate) async fn handle_nat_hole_visitor(
    stream: IoStream,
    msg: msg::NatHoleVisitor,
    state: Arc<AppState>,
    _visitor_addr: Option<String>, // not used in Go compat path; kept for callers
    v2: bool,
) {
    let transaction_id = msg.transaction_id.clone();
    let proxy_name = msg.proxy_name.clone();

    if proxy_name.is_empty() {
        warn!("NatHoleVisitor without proxy_name, ignoring");
        return;
    }

    // Validate proxy exists and capture its info for auth.
    let proxy_info = match state.proxy_manager.get(&proxy_name).await {
        Some(info) => info,
        None => {
            warn!(proxy_name = %proxy_name, "NatHoleVisitor: proxy '{}' not found", proxy_name);
            let Ok((_, mut writer)) = split_work_conn_halves(stream) else {
                warn!(proxy_name = %proxy_name, "NatHoleVisitor: cannot split visitor stream, dropping");
                return;
            };
            let resp = FrpMessage::NatHoleResp(Box::new(msg::NatHoleResp {
                transaction_id: transaction_id.clone(),
                error: Some("proxy not found".into()),
                ..Default::default()
            }));
            let _ = write_msg(&mut writer, &resp, v2).await;
            return;
        }
    };

    // Look up the provider's run_id from proxy_manager
    let run_id = state.proxy_manager.get_run_id(&proxy_name).await;
    let run_id = match run_id {
        Some(id) => id,
        None => {
            warn!(proxy_name = %proxy_name, "NatHoleVisitor: no run_id found for proxy '{}'", proxy_name);
            let Ok((_, mut writer)) = split_work_conn_halves(stream) else {
                warn!(proxy_name = %proxy_name, "NatHoleVisitor: cannot split visitor stream, dropping");
                return;
            };
            let resp = FrpMessage::NatHoleResp(Box::new(msg::NatHoleResp {
                transaction_id: transaction_id.clone(),
                error: Some("provider offline".into()),
                ..Default::default()
            }));
            let _ = write_msg(&mut writer, &resp, v2).await;
            return;
        }
    };

    let ctl_tx = {
        let map = state.run_id_to_ctl_tx.read().await;
        map.get(&run_id).cloned()
    };

    let ctl_tx = match ctl_tx {
        Some(ctl) => ctl,
        None => {
            warn!(run_id = %run_id, "No provider control handler for run_id {}", run_id);
            let Ok((_, mut writer)) = split_work_conn_halves(stream) else {
                warn!(proxy_name = %proxy_name, "NatHoleVisitor: cannot split visitor stream, dropping");
                return;
            };
            let resp = FrpMessage::NatHoleResp(Box::new(msg::NatHoleResp {
                transaction_id: transaction_id.clone(),
                error: Some("provider disconnected".into()),
                ..Default::default()
            }));
            let _ = write_msg(&mut writer, &resp, v2).await;
            return;
        }
    };

    // --- Go frp v0.69.1 compat: pre_check validates proxy and permissions
    // without creating a session. Visitor proceeds to STUN after receiving OK.
    // Go frp controller.go: checks proxy exists + user in allow_users
    // (fresh-TCP path uses visitorUser="", so only "*" wildcard passes).
    if msg.pre_check {
        // Validate allow_users: on fresh TCP the visitor identity is "".
        // Empty allow_users is owner-only, so an owner-less proxy admits;
        // otherwise the normal Go v0.70.1 owner/allow-list check applies.
        let allowed = visitor_user_allowed("", &proxy_info.user, &proxy_info.allow_users);
        if !allowed {
            debug!(
                proxy_name = %proxy_name,
                allow_users = ?proxy_info.allow_users,
                "NatHoleVisitor pre_check for proxy '{}': denied (fresh-TCP identity '' does not match owner/allow_users)",
                proxy_name
            );
            let Ok((_, mut writer)) = split_work_conn_halves(stream) else {
                warn!(proxy_name = %proxy_name, "NatHoleVisitor: cannot split visitor stream, dropping");
                return;
            };
            let resp = FrpMessage::NatHoleResp(Box::new(msg::NatHoleResp {
                transaction_id: transaction_id.clone(),
                error: Some("access denied: restricted to authenticated users".into()),
                ..Default::default()
            }));
            let _ = write_msg(&mut writer, &resp, v2).await;
            return;
        }
        debug!(
            proxy_name = %proxy_name,
            "NatHoleVisitor pre_check for proxy '{}': OK",
            proxy_name
        );
        let Ok((_, mut writer)) = split_work_conn_halves(stream) else {
            warn!(proxy_name = %proxy_name, "NatHoleVisitor: cannot split visitor stream, dropping");
            return;
        };
        let resp = FrpMessage::NatHoleResp(Box::new(msg::NatHoleResp {
            transaction_id: transaction_id.clone(),
            error: None,
            ..Default::default()
        }));
        let _ = write_msg(&mut writer, &resp, v2).await;
        return;
    }

    // --- Auth: verify visitor knows the shared secret ---
    // NatHoleVisitor on a fresh TCP connection must prove knowledge of the
    // proxy's secret key, just like NewVisitorConn. Without this check, an
    // attacker can trigger NAT traversal and provider simultaneous-open for
    // any proxy they can name.
    {
        let sign_key = msg.sign_key.as_deref().unwrap_or("");
        let timestamp = msg.timestamp.unwrap_or(0);

        // Require sign_key for non-pre_check requests on fresh connections.
        // The sign_key must equal MD5(proxy_sk + timestamp), verified with
        // constant-time comparison and timestamp freshness check to prevent
        // replay attacks.
        if sign_key.is_empty() {
            warn!(proxy_name = %proxy_name, "NatHoleVisitor: missing sign_key, rejecting");
            let Ok((_, mut writer)) = split_work_conn_halves(stream) else {
                warn!(proxy_name = %proxy_name, "NatHoleVisitor: cannot split visitor stream, dropping");
                return;
            };
            let resp = FrpMessage::NatHoleResp(Box::new(msg::NatHoleResp {
                transaction_id: transaction_id.clone(),
                error: Some("auth required".into()),
                ..Default::default()
            }));
            let _ = write_msg(&mut writer, &resp, v2).await;
            return;
        }

        let proxy_sk = proxy_info.sk.as_deref().unwrap_or("");
        if proxy_sk.is_empty() {
            // XTCP proxy without a shared secret: no way to authenticate
            // visitors on fresh connections. Reject.
            warn!(proxy_name = %proxy_name, "NatHoleVisitor: proxy has no sk configured — rejecting fresh connection");
            let Ok((_, mut writer)) = split_work_conn_halves(stream) else {
                warn!(proxy_name = %proxy_name, "NatHoleVisitor: cannot split visitor stream, dropping");
                return;
            };
            let resp = FrpMessage::NatHoleResp(Box::new(msg::NatHoleResp {
                transaction_id: transaction_id.clone(),
                error: Some("proxy has no shared secret".into()),
                ..Default::default()
            }));
            let _ = write_msg(&mut writer, &resp, v2).await;
            return;
        }

        // Validate timestamp freshness (replay attack prevention).
        let auth_timeout = state.reloadable.read_ok().auth_cfg.authentication_timeout;
        if let Err(freshness_err) =
            frp_core::auth::validate_timestamp_freshness(timestamp, auth_timeout)
        {
            warn!(proxy_name = %proxy_name, error = %freshness_err, "NatHoleVisitor: timestamp rejected for proxy '{}'", proxy_name);
            let Ok((_, mut writer)) = split_work_conn_halves(stream) else {
                warn!(proxy_name = %proxy_name, "NatHoleVisitor: cannot split visitor stream, dropping");
                return;
            };
            let resp = FrpMessage::NatHoleResp(Box::new(msg::NatHoleResp {
                transaction_id: transaction_id.clone(),
                error: Some(freshness_err),
                ..Default::default()
            }));
            let _ = write_msg(&mut writer, &resp, v2).await;
            return;
        }

        if !frp_core::auth::verify_token(proxy_sk, timestamp, sign_key) {
            warn!(proxy_name = %proxy_name, "NatHoleVisitor auth failed for proxy '{}'", proxy_name);
            let Ok((_, mut writer)) = split_work_conn_halves(stream) else {
                warn!(proxy_name = %proxy_name, "NatHoleVisitor: cannot split visitor stream, dropping");
                return;
            };
            let resp = FrpMessage::NatHoleResp(Box::new(msg::NatHoleResp {
                transaction_id: transaction_id.clone(),
                error: Some("auth failed".into()),
                ..Default::default()
            }));
            let _ = write_msg(&mut writer, &resp, v2).await;
            return;
        }
        debug!(proxy_name = %proxy_name, "NatHoleVisitor auth OK (constant-time) for proxy '{}'", proxy_name);

        // --- allow_users check on fresh connections ---
        // Fresh TCP connections carry no user identity, so the Go v0.70.1
        // admission identity is "". Empty allow_users is owner-only, so an
        // owner-less proxy admits; restricted proxies require the control
        // channel path (control/mod.rs NatHoleVisitor handler).
        if !visitor_user_allowed("", &proxy_info.user, &proxy_info.allow_users) {
            warn!(proxy_name = %proxy_name, "NatHoleVisitor: fresh connection identity '' denied for proxy '{}'", proxy_name);
            let Ok((_, mut writer)) = split_work_conn_halves(stream) else {
                warn!(proxy_name = %proxy_name, "NatHoleVisitor: cannot split visitor stream, dropping");
                return;
            };
            let resp = FrpMessage::NatHoleResp(Box::new(msg::NatHoleResp {
                transaction_id: transaction_id.clone(),
                error: Some("access denied: use control channel for user-based auth".into()),
                ..Default::default()
            }));
            let _ = write_msg(&mut writer, &resp, v2).await;
            return;
        }
    }

    let Ok((reader, writer)) = split_work_conn_halves(stream) else {
        warn!(proxy_name = %proxy_name, "NatHoleVisitor: cannot split visitor stream, dropping");
        return;
    };
    let sid = transaction_id.clone();

    // --- Step 1: Create session and notify provider ---
    let (session, report_rx) = match state
        .xtcp
        .nat_hole
        .create_session_with_writer(sid.clone(), proxy_name.clone(), msg.clone(), writer)
        .await
    {
        Ok(s) => s,
        Err(e) => {
            warn!(error = %e, "NatHole session creation failed: {}", e);
            return;
        }
    };

    // --- Step 2: Set up notify channel BEFORE sending to provider ---
    // Must happen before the provider notification to avoid a race:
    // if the provider responds with NatHoleClient before we set up
    // notify_rx, the signal is lost and we timeout spuriously.
    let notify_rx = {
        let mut guard = session.notify_ch.lock().await;
        let (tx, rx) = oneshot::channel();
        *guard = Some(tx);
        rx
    };

    // Send NatHoleSid to provider ON A WORK CONNECTION (Go frp v0.69.1 compat).
    // The provider reads NatHoleSid from the work connection, does its own STUN,
    // and sends NatHoleClient back on its control connection with its mapped addresses.
    // handle_client() signals notify_ch when the provider's response arrives.
    //
    // Use send().await with a 5s timeout instead of try_send(). try_send() conflates
    // two distinct failure modes:
    //   - Channel full (temporary backpressure): the provider is alive but busy.
    //     try_send() returns TrySendError::Full, but is_err() discards the variant.
    //   - Provider disconnected (permanent): the channel is closed. try_send()
    //     returns TrySendError::Closed.
    // With send().await + timeout we wait briefly for capacity, and can distinguish
    // timeout from SendError in the log message.
    let send_result = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        ctl_tx.tx.send(InternalMsg::NatHoleSidOnWorkConn {
            sid: sid.clone(),
            proxy_name: proxy_name.clone(),
        }),
    )
    .await;
    match send_result {
        Ok(Ok(())) => {
            // Message delivered successfully.
        }
        Ok(Err(_send_err)) => {
            warn!(run_id = %run_id, "Provider for run_id {} has disconnected (channel closed)", run_id);
            state.xtcp.nat_hole.remove(&transaction_id).await;
            return;
        }
        Err(_elapsed) => {
            warn!(run_id = %run_id, "Provider for run_id {} is overloaded (channel full for 5s)", run_id);
            state.xtcp.nat_hole.remove(&transaction_id).await;
            return;
        }
    }

    info!(
        proxy_name = %proxy_name, sid = %sid,
        "NatHoleVisitor for proxy '{}': created session {}, waiting for provider",
        proxy_name, sid
    );

    // Wait for provider's NatHoleClient with STUN addresses.
    // The provider does its own STUN discovery and sends
    // NatHoleClient back with mapped_addrs/assisted_addrs.
    // Go frp v0.69.1 compat: server is a pure relay.
    // handle_client() signals notify_ch when the message arrives.

    let client_msg_received =
        tokio::time::timeout(Duration::from_secs(NAT_HOLE_TIMEOUT), notify_rx).await;

    if client_msg_received.is_err() {
        warn!(
            sid = %sid,
            "NatHole session {}: timeout waiting for provider NatHoleClient",
            sid
        );
        // Take the writer out of the option so we can perform async I/O
        // without holding the tokio::sync::Mutex guard.
        let mut taken_writer = session.visitor_writer.lock().await.take();
        if let Some(ref mut w) = taken_writer {
            let resp = FrpMessage::NatHoleResp(Box::new(msg::NatHoleResp {
                transaction_id: transaction_id.clone(),
                error: Some("provider NAT detection timeout".into()),
                sid: None,
                protocol: None,
                candidate_addrs: None,
                assisted_addrs: None,
                detect_behavior: None,
            }));
            let _ = write_msg(w, &resp, v2).await;
            // Return the writer to the session
            *session.visitor_writer.lock().await = taken_writer;
        }
        state.xtcp.nat_hole.remove(&sid).await;
        drop(reader);
        return;
    }

    // --- Step 3: Get provider's addresses from session ---
    let client_msg_opt = session.client_msg.lock().await.take();
    let client_msg = match client_msg_opt {
        Some(m) => m,
        None => {
            warn!(sid = %sid, "NatHole session {}: no client message after notify", sid);
            state.xtcp.nat_hole.remove(&sid).await;
            drop(reader);
            return;
        }
    };

    let client_mapped = client_msg.mapped_addrs.unwrap_or_default();
    let client_assisted = client_msg.assisted_addrs.unwrap_or_default();
    let visitor_mapped = msg.mapped_addrs.unwrap_or_default();
    let visitor_assisted = msg.assisted_addrs.unwrap_or_default();

    // --- Step 4: Classify both NAT features ---
    let visitor_local_ips = classify::parse_ips(&visitor_assisted);
    let client_local_ips = classify::parse_ips(&client_assisted);
    let v_feature = classify::classify_nat_feature(&visitor_mapped, &visitor_local_ips).ok();
    let c_feature = classify::classify_nat_feature(&client_mapped, &client_local_ips).ok();

    // Store features on session
    if let Some(ref vf) = v_feature {
        *session.v_nat_feature.lock().await = Some(vf.clone());
    }
    if let Some(ref cf) = c_feature {
        *session.c_nat_feature.lock().await = Some(cf.clone());
    }

    // --- Step 5: Run analysis and build responses ---
    let (v_resp, c_resp) = if let (Some(ref vf), Some(ref cf)) = (&v_feature, &c_feature) {
        let key = nathole_ctrl::gen_analysis_key(cf, vf, &client_mapped, &visitor_mapped);
        *session
            .analysis_key
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(key.clone());
        let (mode, index, c_behavior, v_behavior) = state
            .xtcp
            .nat_hole
            .analyzer
            .get_recommend_behaviors(&key, cf, vf);
        *session.selected_index.lock().await = Some(index);

        let extra_timeout =
            if c_behavior.listen_random_ports > 0 || v_behavior.listen_random_ports > 0 {
                30000
            } else {
                0
            };
        let timeout_ms =
            c_behavior.send_delay_ms.max(v_behavior.send_delay_ms) + 5000 + extra_timeout;
        let v_read_timeout = timeout_ms - v_behavior.send_delay_ms;
        let c_read_timeout = timeout_ms - c_behavior.send_delay_ms;
        let c_ports_diff = cf.ports_difference;
        let v_ports_diff = vf.ports_difference;

        let v_resp = nathole_ctrl::build_nat_hole_response(nathole_ctrl::NatHoleResponseParams {
            transaction_id: transaction_id.clone(),
            sid: sid.clone(),
            protocol: msg.protocol.clone(),
            mode,
            candidate_addrs: client_mapped.clone(), // visitor gets PROVIDER's addresses
            assisted_addrs: client_assisted.clone(),
            behavior: v_behavior,
            read_timeout_ms: v_read_timeout,
            ports_difference: c_ports_diff,
        });

        // Use visitor's protocol for provider's response too —
        // Go frp provider reads NatHoleResp.protocol to decide
        // KCP vs TCP transport. If empty, Go falls back to TCP
        // which is incompatible with visitor's KCP.
        let protocol_for_provider = msg.protocol.clone().or_else(|| client_msg.protocol.clone());
        let c_resp = nathole_ctrl::build_nat_hole_response(nathole_ctrl::NatHoleResponseParams {
            transaction_id: client_msg.transaction_id.clone(),
            sid: sid.clone(),
            protocol: protocol_for_provider,
            mode,
            candidate_addrs: visitor_mapped.clone(), // provider gets VISITOR's addresses
            assisted_addrs: visitor_assisted.clone(),
            behavior: c_behavior,
            read_timeout_ms: c_read_timeout,
            ports_difference: v_ports_diff,
        });

        (v_resp, Some(c_resp))
    } else {
        // Fallback: simple exchange without analysis
        let v_resp = msg::NatHoleResp {
            transaction_id: transaction_id.clone(),
            error: None,
            sid: Some(sid.clone()),
            protocol: msg.protocol.clone(),
            candidate_addrs: if client_mapped.is_empty() {
                None
            } else {
                Some(client_mapped)
            },
            assisted_addrs: if client_assisted.is_empty() {
                None
            } else {
                Some(client_assisted)
            },
            ..Default::default()
        };
        let protocol_for_provider = msg.protocol.clone().or_else(|| client_msg.protocol.clone());
        let c_resp = msg::NatHoleResp {
            transaction_id: client_msg.transaction_id.clone(),
            error: None,
            sid: Some(sid.clone()),
            protocol: protocol_for_provider,
            candidate_addrs: if visitor_mapped.is_empty() {
                None
            } else {
                Some(visitor_mapped)
            },
            assisted_addrs: if visitor_assisted.is_empty() {
                None
            } else {
                Some(visitor_assisted)
            },
            ..Default::default()
        };
        (v_resp, Some(c_resp))
    };

    // Store v_resp for reporting
    *session.v_resp.lock().await = Some(v_resp.clone());

    // --- Step 6: Send NatHoleResp to both sides ---

    // Go frp dev compat: if the visitor has the "sender" role, wait 1s
    // before sending NatHoleResp. This gives the sender time to complete
    // STUN and start sending detect messages before the receiver gets
    // the response and starts detecting.
    if v_resp
        .detect_behavior
        .as_ref()
        .is_some_and(|db| db.role.as_deref() == Some("sender"))
    {
        tokio::time::sleep(Duration::from_secs(1)).await;
    }

    // Send to visitor via writer
    {
        let mut writer_guard = session.visitor_writer.lock().await;
        if let Some(ref mut w) = *writer_guard {
            if let Err(e) = write_msg(w, &FrpMessage::NatHoleResp(Box::new(v_resp)), v2).await {
                warn!(error = %e, "failed to write NatHoleResp to visitor");
            }
        }
    }

    // Go frp dev compat: if the provider has the "sender" role, wait 1s
    // before sending NatHoleResp (see comment above for rationale).
    if let Some(ref cr) = c_resp {
        if cr
            .detect_behavior
            .as_ref()
            .is_some_and(|db| db.role.as_deref() == Some("sender"))
        {
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }

    // Send to provider via control channel.
    // send().await: backpressure is correct — if the provider's
    // control handler cannot drain messages, the XTCP session
    // should wait rather than silently drop the NatHoleResp
    // (which would cause a permanent visitor hang).
    if let Some(ref cr) = c_resp {
        let _ = ctl_tx
            .tx
            .send(InternalMsg::WriteNatHoleResp {
                transaction_id: cr.transaction_id.clone(),
                error: cr.error.clone(),
                sid: cr.sid.clone(),
                protocol: cr.protocol.clone(),
                candidate_addrs: cr.candidate_addrs.clone(),
                assisted_addrs: cr.assisted_addrs.clone(),
                detect_behavior: cr.detect_behavior.clone(),
            })
            .await;
    }

    info!(sid = %sid, "NatHole session {}: NatHoleResp sent to both sides", sid);

    // --- Step 7: Wait for report ---
    // Go frp v0.69.1 compat: sleep ReadTimeoutMs + 30000ms after sending
    // NatHoleResp to keep the session alive for hole-punch completion and
    // NatHoleReport. Use a dynamic timeout from the provider's detect_behavior
    // rather than a fixed 30s timeout.
    let wait_ms = c_resp
        .as_ref()
        .and_then(|cr| cr.detect_behavior.as_ref())
        .map(|db| (db.read_timeout_ms.max(0) as u64) + 30000)
        .unwrap_or(30000);
    match tokio::time::timeout(Duration::from_millis(wait_ms), report_rx).await {
        Ok(Ok(_report)) => {
            debug!(sid = %sid, "NatHole session {}: provider completed", sid);
        }
        Ok(Err(_)) => {
            debug!(sid = %sid, "NatHole session {}: provider dropped without report", sid);
            state.xtcp.nat_hole.remove(&sid).await;
        }
        Err(_) => {
            warn!(sid = %sid, "NatHole session {}: timed out waiting for provider report", sid);
            state.xtcp.nat_hole.remove(&sid).await;
            drop(reader);
        }
    }
    // reader dropped → connection closes
}

// ---------------------------------------------------------------
// V2 message dispatch
// ---------------------------------------------------------------

/// Decode a V2 message from raw frame payload and dispatch to the appropriate handler.
/// `payload` is the frame payload: [type_id: u16 BE][JSON bytes].
pub(crate) async fn dispatch_v2_message(
    io: IoStream,
    payload: Vec<u8>,
    state: std::sync::Arc<AppState>,
    addr: std::net::SocketAddr,
    incoming: Option<frp_core::mux::IncomingStreams>,
    visitor_addr: Option<String>,
    crypto_ctx: Option<frp_core::v2_handshake::CryptoContext>,
) {
    dispatch_v2_message_inner(
        io,
        payload,
        state,
        addr,
        incoming,
        visitor_addr,
        crypto_ctx,
        None,
    )
    .await;
}

#[allow(clippy::too_many_arguments)]
#[cfg(feature = "quic")]
pub(crate) async fn dispatch_v2_message_with_auth_signal(
    io: IoStream,
    payload: Vec<u8>,
    state: std::sync::Arc<AppState>,
    addr: std::net::SocketAddr,
    incoming: Option<frp_core::mux::IncomingStreams>,
    visitor_addr: Option<String>,
    crypto_ctx: Option<frp_core::v2_handshake::CryptoContext>,
    auth_success: tokio::sync::oneshot::Sender<()>,
) {
    dispatch_v2_message_inner(
        io,
        payload,
        state,
        addr,
        incoming,
        visitor_addr,
        crypto_ctx,
        Some(auth_success),
    )
    .await;
}

#[allow(clippy::too_many_arguments)]
async fn dispatch_v2_message_inner(
    io: IoStream,
    payload: Vec<u8>,
    state: std::sync::Arc<AppState>,
    addr: std::net::SocketAddr,
    incoming: Option<frp_core::mux::IncomingStreams>,
    visitor_addr: Option<String>,
    crypto_ctx: Option<frp_core::v2_handshake::CryptoContext>,
    auth_success: Option<tokio::sync::oneshot::Sender<()>>,
) {
    if payload.len() < 2 {
        warn!(addr = %addr, "V2 message payload too short from {}", addr);
        return;
    }
    let type_id = u16::from_be_bytes([payload[0], payload[1]]);
    let msg = match frp_core::protocol::deserialize_v2(type_id, &payload[2..]) {
        Ok(m) => m,
        Err(e) => {
            warn!(addr = %addr, error = %e, "Failed to decode V2 message from {}: {}", addr, e);
            return;
        }
    };
    match msg {
        FrpMessage::Login(login) => {
            if let Some(auth_success) = auth_success {
                control::handle_control_with_auth_signal(
                    io,
                    *login,
                    state,
                    Some(addr),
                    incoming,
                    true,
                    crypto_ctx,
                    false,
                    auth_success,
                )
                .await;
            } else {
                control::handle_control(
                    io,
                    *login,
                    state,
                    Some(addr),
                    incoming,
                    true,
                    crypto_ctx,
                    false,
                )
                .await;
            }
        }
        FrpMessage::NewWorkConn(nwc) => {
            handle_work_conn_inner(io, nwc, state).await;
        }
        FrpMessage::NewVisitorConn(vc) => {
            handle_visitor_conn_inner(io, vc, state, true).await;
        }
        FrpMessage::NatHoleVisitor(nhv) => {
            handle_nat_hole_visitor(io, nhv, state, visitor_addr, true).await;
        }
        other => {
            warn!(addr = %addr, type_id = ?other.v2_type_id(), "Unexpected V2 first message from {}: {:?}", addr, other.v2_type_id());
        }
    }
}

/// V1 mirror of `dispatch_v2_message`: read one V1 message off `io` and route
/// it to the matching handler. `addr`/`incoming`/`visitor_addr` vary per call
/// site; everything else is uniform (V1 => v2=false, no crypto context).
///
/// Go frp compat: applies a 10-second read deadline for the first message
/// to prevent slow/malicious clients from holding connections open
/// (connReadTimeout in Go service.go:553).
pub(crate) async fn dispatch_v1_message(
    mut io: IoStream,
    state: std::sync::Arc<AppState>,
    addr: Option<std::net::SocketAddr>,
    incoming: Option<frp_core::mux::IncomingStreams>,
    visitor_addr: Option<String>,
    deadline: tokio::time::Instant,
) {
    match tokio::time::timeout_at(deadline, frp_core::protocol::read_msg_v1(&mut io)).await {
        Ok(Ok(FrpMessage::Login(login))) => {
            control::handle_control(io, *login, state, addr, incoming, false, None, false).await;
        }
        Ok(Ok(FrpMessage::NewWorkConn(nwc))) => {
            handle_work_conn_inner(io, nwc, state).await;
        }
        Ok(Ok(FrpMessage::NewVisitorConn(nvc))) => {
            handle_visitor_conn_inner(io, nvc, state, false).await;
        }
        Ok(Ok(FrpMessage::NatHoleVisitor(nhv))) => {
            handle_nat_hole_visitor(io, nhv, state, visitor_addr, false).await;
        }
        Ok(Ok(other)) => {
            warn!(other = ?other.v1_type_byte(), "Unexpected V1 first message: {:?}", other.v1_type_byte());
        }
        Ok(Err(e)) => {
            warn!(error = %e, "V1 read error: {}", e);
        }
        Err(_elapsed) => {
            warn!("V1 first message read timed out after 10s");
        }
    }
}

// ---------------------------------------------------------------
// Work connection handler
// ---------------------------------------------------------------

/// Validate NewWorkConn credentials (privilege_key + timestamp) for both
/// standalone TCP work connections and yamux-stream work connections.
///
/// Go frp v0.69.1 compat: always attempt work connection auth verification.
/// Go's RegisterWorkConn unconditionally calls AuthVerifier.VerifyNewWorkConn
/// — the verifier decides whether to enforce based on additional_auth_scopes.
///
/// When "NewWorkConns" is NOT in the scope, we skip verification only if no
/// privilege_key was sent (backward compat). If a key IS present, it must be
/// valid — this catches invalid credentials even when the scope is not
/// configured. When the scope IS set, a privilege_key is always required.
#[instrument(skip(state), fields(run_id = %run_id))]
pub(crate) async fn validate_new_work_conn_auth(
    msg: &msg::NewWorkConn,
    run_id: &str,
    state: &AppState,
) -> Result<(), String> {
    let nwc_auth_scope = state
        .reloadable
        .read_ok()
        .additional_auth_scopes
        .iter()
        .any(|s| s == "NewWorkConns");
    let has_key = msg
        .privilege_key
        .as_deref()
        .map(|k| !k.is_empty())
        .unwrap_or(false);

    if !has_key && !nwc_auth_scope {
        // No key sent and scope does not require it — skip auth.
        return Ok(());
    }
    if let Some(ref verifier) = state.oidc.verifier {
        let expected_sub = state
            .oidc
            .subjects
            .read()
            .await
            .get(run_id)
            .map(|(subject, _)| subject.clone())
            .unwrap_or_default();
        verifier
            .verify_new_work_conn(msg.privilege_key.as_deref().unwrap_or(""), &expected_sub)
            .await
    } else {
        let auth_cfg = state.reloadable.read_ok().auth_cfg.clone();
        auth_cfg.resolve_token().and_then(|token| {
            auth_cfg
                .validate_login_with_token(&token, msg.privilege_key.as_deref(), msg.timestamp)
                .map(|_| ())
        })
    }
}

/// Run the NewWorkConn plugin hook. Returns `Err(reason)` if a plugin
/// rejects the connection.
#[instrument(skip(state), fields(run_id = %run_id))]
pub(crate) async fn run_new_work_conn_plugin(run_id: &str, state: &AppState) -> Result<(), String> {
    // Skip payload construction entirely when no plugins are configured
    // (the default) — every work conn / yamux stream used to build a
    // full json! Value just for the notify loop.
    if state.plugin_manager.is_empty() {
        return Ok(());
    }
    let nwc_content = serde_json::json!({
        "run_id": run_id,
    });
    state
        .plugin_manager
        .notify("new_work_conn", nwc_content)
        .await
        // Mutated content from plugins is intentionally not consumed here:
        // frp-rs applies reject/approve but not content mutation (Go's
        // handleMutableContent mutation path is not wired into the server
        // lifecycle). Noted so the Ok(Some(..)) return is understood.
        .map(|_| ())
}

/// Handle an incoming work connection. Verifies auth, then routes the
/// IoStream to the appropriate control handler via InternalMsg.
#[instrument(skip(stream, state), fields(run_id = %msg.run_id.clone().unwrap_or_default()))]
pub(crate) async fn handle_work_conn_inner(
    stream: IoStream,
    msg: msg::NewWorkConn,
    state: Arc<AppState>,
) {
    let run_id = match &msg.run_id {
        Some(id) => id.clone(),
        None => {
            warn!("NewWorkConn without run_id, ignoring");
            return;
        }
    };

    if let Err(e) = validate_new_work_conn_auth(&msg, &run_id, &state).await {
        warn!(run_id = %run_id, error = %e, "Work conn auth failed for run_id {}: {}", run_id, e);
        return;
    }

    // NewWorkConn plugin hook — control-enabled plugins can reject
    if let Err(reason) = run_new_work_conn_plugin(&run_id, &state).await {
        warn!(run_id = %run_id, reason = %reason, "NewWorkConn plugin hook rejected: {}", reason);
        return;
    }

    let ctl_tx = {
        let map = state.run_id_to_ctl_tx.read().await;
        map.get(&run_id).cloned()
    };

    match ctl_tx {
        Some(ctl) => {
            // Use send().await: a dropped NewWorkConn leaves the proxy
            // without a work connection until the control handler times out
            // and requests a new one. Backpressure is correct.
            if ctl.tx.send(InternalMsg::NewWorkConn(stream)).await.is_err() {
                warn!(run_id = %run_id, "Control handler for {} has gone away", run_id);
            }
        }
        None => {
            warn!(run_id = %run_id, "No control handler found for run_id {}", run_id);
        }
    }
}

// ---------------------------------------------------------------
// Accepted-connection handlers (extracted from the accept-loop
// dispatch so each transport path gets its own state machine
// instead of one ~100 KiB combined closure in Service::run)
// ---------------------------------------------------------------

#[cfg(feature = "tls")]
#[inline(never)]
pub(crate) async fn handle_tls_connection(
    state: Arc<AppState>,
    addr: std::net::SocketAddr,
    accept_deadline: tokio::time::Instant,
    first_byte: u8,
    stream_io: IoStream,
) {
    // Read the TLS acceptor lazily: only TLS
    // connections need it. Taking the RwLock read
    // + clone on every accepted connection
    // (including plain V1/WS traffic) was pure
    // overhead on the hot accept path.
    let acceptor = state.tls_acceptor.read_ok().clone();
    // Extract inner transport and pre-read bytes.
    // detect_and_strip_magic consumed 7 bytes; replay them
    // (minus the Go frp 0x17 prefix) for TLS.
    let (mut pre_read_bytes, mut inner_stream) = match stream_io.into_parts() {
        Some(parts) => parts,
        None => {
            warn!(addr = %addr, "Expected PreRead for TLS connection from {}", addr);
            return;
        }
    };

    // 0x17 = Go frp TLS prefix (already consumed, strip from replay)
    // 0x16 = standard TLS ClientHello (keep all bytes)
    if first_byte == frp_core::transport::FRP_TLS_HEAD_BYTE && !pre_read_bytes.is_empty() {
        pre_read_bytes.remove(0); // discard 0x17
    }

    // --- SNI peek for HTTPS proxy routing ---
    // Only pay the cost (2x4KiB heap allocs + a
    // 4KiB blocking pre-read + ClientHello parse +
    // vhost lookup) when at least one HTTPS proxy
    // is registered; otherwise the sniff could
    // never match a route, so skip straight to the
    // normal TLS accept. The count is maintained
    // by https registration/unregistration.
    let mut sni_data = if state
        .https_proxy_count
        .load(std::sync::atomic::Ordering::Relaxed)
        > 0
    {
        // Read ClientHello bytes (up to 4KB) from inner stream.
        // The inner stream is positioned at byte 7 of the original
        // connection. Combine with pre_read_bytes for full ClientHello.
        // 10s timeout matches Go frp's connReadTimeout, which
        // CheckAndEnableTLSServerConnWithTimeout applies during
        // TLS detection (server/service.go constant, 10s).
        let mut sni_buf = [0u8; 4096];
        let sni_peek_n =
            match tokio::time::timeout_at(accept_deadline, inner_stream.read(&mut sni_buf)).await {
                Ok(Ok(n)) if n >= 43 => n,
                Ok(Ok(_)) => 0,
                _ => {
                    warn!(addr = %addr, "TLS read timeout from {} during SNI check", addr);
                    return;
                }
            };

        // Build full ClientHello data (pre-read magic bytes + SNI peek)
        // in a single allocation instead of clone-then-extend.
        let mut sni_data = Vec::with_capacity(pre_read_bytes.len() + sni_peek_n);
        sni_data.extend_from_slice(&pre_read_bytes);
        if sni_peek_n > 0 {
            sni_data.extend_from_slice(&sni_buf[..sni_peek_n]);
        }

        // Try SNI-based routing for HTTPS proxies
        if !sni_data.is_empty() {
            if let Some(sni_host) = crate::vhost::extract_sni_from_client_hello(&sni_data) {
                debug!(addr = %addr, sni_host = %sni_host, "SNI from {}: {}", addr, sni_host);
                // SNI routing: no HTTP auth, so http_user is empty string.
                // SNI routing: no HTTP path, so pass empty string.
                // Routes with empty locations (HTTPS SNI) match any path.
                if let Some(route) = state.vhost_manager.lookup_wildcard(&sni_host, "", "").await {
                    let ctl_tx = {
                        let map = state.run_id_to_ctl_tx.read().await;
                        map.get(route.run_id.as_ref()).cloned()
                    };
                    if let Some(ctl) = ctl_tx {
                        info!(sni_host = %sni_host, proxy_name = %route.proxy_name, addr = %addr,
                                                        "SNI route '{}' → HTTPS proxy '{}' from {}",
                                                        sni_host, route.proxy_name, addr);
                        // send().await: backpressure is correct —
                        // silently dropping the connection after
                        // consuming TLS ClientHello bytes would
                        // confuse the client.
                        let _ = ctl
                            .tx
                            .send(InternalMsg::ProxyUserConn {
                                proxy_name: route.proxy_name.to_string(),
                                user_conn: IoStream::from(inner_stream),
                                pre_read: sni_data,
                            })
                            .await;
                        return;
                    }
                }
            }
        }
        sni_data
    } else {
        // No HTTPS proxies — replay just the pre-read
        // bytes; the TLS handshake reads the rest from
        // the socket.
        pre_read_bytes
    };

    // No SNI match — check acceptor before creating stream.
    let acceptor = match acceptor {
        Some(a) => a,
        None => {
            // TLS.Force mode: if tls_only is set, reject connections
            // that attempt TLS without a configured acceptor.
            if state.tls_only {
                warn!(addr = %addr,
                                                "TLS-only mode: TLS byte (0x{:02x}) but TLS not configured, rejecting",
                                                first_byte);
                return;
            }
            // Go frp compat: Go frpc sends 0x17 (FRP_TLS_HEAD_BYTE)
            // or 0x16 (FRP_TLS_DIRECT_BYTE) as the first byte when
            // TLS is enabled on the client but not on the server.
            // Go frps falls back to plain TCP via
            // CheckAndEnableTLSServerConnWithTimeout.
            // Match that behavior: strip the first byte and
            // treat the remaining data as V1.
            if first_byte == frp_core::transport::FRP_TLS_HEAD_BYTE
                || first_byte == frp_core::transport::FRP_TLS_DIRECT_BYTE
            {
                info!(addr = %addr, first_byte = first_byte,
                                                "TLS byte (0x{:02x}) but TLS not configured, falling back to V1",
                                                first_byte);
                // 0x17 is already stripped from pre_read_bytes above,
                // but 0x16 is not (kept for TLS handshake path).
                // Strip it here so V1 dispatch sees valid data.
                if first_byte == frp_core::transport::FRP_TLS_DIRECT_BYTE && !sni_data.is_empty() {
                    sni_data.remove(0);
                }
                let stream = IoStream::PreRead(sni_data, inner_stream);
                crate::handlers::dispatch_v1_message(
                    stream,
                    state,
                    Some(addr),
                    None,
                    Some(addr.to_string()),
                    accept_deadline,
                )
                .await;
                return;
            }
            // first_byte is always 0x17 or 0x16 here
            // (ConnectionType::Tls only matches those),
            // but the compiler needs an explicit fallback.
            debug!(addr = %addr, first_byte = first_byte,
                                            "TLS byte (0x{:02x}) — unexpected, dropping",
                                            first_byte);
            return;
        }
    };

    // TLS acceptor exists — wrap stream to replay consumed bytes
    // for the TLS handshake.
    let stream = PreReadStream::new(sni_data, inner_stream);
    // Bound the TLS handshake: when https_proxy_count == 0 the
    // SNI-sniff peek is skipped and its timeout was the only
    // bound on this accept. A client that sends only the TLS
    // marker byte (0x17/0x16) then goes silent would otherwise
    // park here forever, holding a task, fd, and a
    // conn_semaphore permit (slowloris / permit exhaustion).
    // Same deadline and shape as the WS+TLS accept above.
    let tls_stream = match tokio::time::timeout_at(accept_deadline, acceptor.accept(stream)).await {
        Ok(r) => match r {
            Ok(s) => s,
            Err(e) => {
                warn!(addr = %addr, error = %e, "TLS handshake failed from {}: {}", addr, e);
                return;
            }
        },
        Err(_elapsed) => {
            warn!(addr = %addr, "TLS handshake timeout from {}", addr);
            return;
        }
    };
    info!(addr = %addr, "TLS connection from {}", addr);

    // Wrap TLS stream for unified V2/V1/WS handling.
    let mut io = IoStream::Tls(Box::new(tokio_rustls::TlsStream::Server(tls_stream)), addr);

    // Peek for WebSocket upgrade inside TLS (Go frp 'ws'
    // transport sends TLS ClientHello first, then WebSocket
    // upgrade inside the TLS tunnel).
    //
    // Two-phase detection to avoid false positives from
    // health checks, scanners, and other non-frp HTTP
    // clients that connect to the frps TLS port.
    // Two-phase WebSocket detection.
    // Peek reads the first bytes of the post-TLS byte
    // stream (i.e. the first message); Go frp reads this
    // under its connReadTimeout = 10s deadline, so use
    // the same value instead of a shorter hardcoded one.
    let mut ws_peek = vec![0u8; 4];
    #[cfg(feature = "websocket")]
    let got_http =
        match tokio::time::timeout_at(accept_deadline, io.read_exact(&mut ws_peek[..4])).await {
            Ok(Ok(n)) if n >= 4 => &ws_peek[..4] == b"GET ",
            _ => false,
        };
    #[cfg(not(feature = "websocket"))]
    let _ = tokio::time::timeout_at(accept_deadline, io.read_exact(&mut ws_peek[..4])).await;

    // Secondary validation: read more bytes and confirm
    // WebSocket upgrade headers are present before committing
    // to the WS path (which sends a 101 response and cannot
    // be undone).
    #[cfg(feature = "websocket")]
    let is_ws_tls = if got_http {
        ws_peek.resize(1024, 0);
        let extra = match tokio::time::timeout(
            std::time::Duration::from_millis(500),
            io.read(&mut ws_peek[4..]),
        )
        .await
        {
            Ok(Ok(n)) => n,
            _ => 0,
        };
        ws_peek.truncate(4 + extra);
        let data = String::from_utf8_lossy(&ws_peek);
        let lower = data.to_lowercase();
        lower.contains("upgrade: websocket") && lower.contains("sec-websocket-key:")
    } else {
        false
    };

    #[cfg(feature = "websocket")]
    if is_ws_tls {
        // WebSocket upgrade over TLS (Go frpc ws transport).
        // accept_websocket_from_peeked replays pipelined bytes
        // through a single BufferedRead layer (no BufReader),
        // which preserves the read position on TLS streams —
        // `ws_peek` here is already TLS-decrypted plaintext.
        match accept_websocket_from_peeked(ws_peek, io).await {
            Ok(mut ws) => {
                info!(addr = %addr, "WebSocket upgrade over TLS for {}", addr);
                let mut magic = [0u8; 7];
                let is_v2 = match ws.read_exact(&mut magic).await {
                    Ok(_) => is_v2_magic(&magic),
                    Err(e) => {
                        warn!(addr = %addr, error = %e, "WS+TLS failed to read first 7 bytes: {}", e);
                        return;
                    }
                };
                if is_v2 {
                    let (msg_payload, crypto_ctx) = match tokio::time::timeout_at(
                        accept_deadline,
                        frp_core::v2_handshake::v2_handshake_server(&mut ws),
                    )
                    .await
                    {
                        Ok(r) => match r {
                            Ok((Some(p), crypto)) => (p, crypto),
                            Ok((None, crypto)) => {
                                match tokio::time::timeout_at(
                                    accept_deadline,
                                    frp_core::v2_handshake::read_first_frame_after_handshake(
                                        &mut ws,
                                    ),
                                )
                                .await
                                {
                                    Ok(r) => match r {
                                        Ok((frp_core::protocol::V2_FRAME_TYPE_MESSAGE, _, p)) => {
                                            (p, crypto)
                                        }
                                        Ok((ft, _, _)) => {
                                            warn!(frame_type = ?ft, addr = %addr, "WS+TLS V2: unexpected frame type {} from {}", ft, addr);
                                            return;
                                        }
                                        Err(e) => {
                                            warn!(addr = %addr, error = %e, "WS+TLS V2: failed to read message: {}", e);
                                            return;
                                        }
                                    },
                                    Err(_elapsed) => {
                                        warn!(addr = %addr, "WS+TLS V2: read first frame after handshake timeout from {}", addr);
                                        return;
                                    }
                                }
                            }
                            Err(e) => {
                                warn!(addr = %addr, error = %e, "WS+TLS V2 handshake error: {}", e);
                                return;
                            }
                        },
                        Err(_elapsed) => {
                            warn!(addr = %addr, "WS+TLS V2 handshake timeout from {}", addr);
                            return;
                        }
                    };
                    crate::handlers::dispatch_v2_message(
                        ws,
                        msg_payload,
                        state,
                        addr,
                        None,
                        None,
                        crypto_ctx,
                    )
                    .await;
                } else if magic[0] == 0x00 {
                    // yamux over WebSocket (Go frp tcpMux + wss).
                    // First byte 0x00 = yamux version; the 7-byte peek
                    // contains the start of a yamux WindowUpdate+SYN frame.
                    let ws = IoStream::BufferedRead(magic.to_vec(), 0, Box::new(ws));
                    let mux_cfg = mux::TcpMuxConfig {
                        keepalive_interval: std::time::Duration::from_secs(
                            state.tcp_mux_keepalive.max(1) as u64,
                        ),

                        ..Default::default()
                    };
                    match mux::server_mux(ws, &mux_cfg).await {
                        Ok((control_stream, incoming)) => {
                            let mut io = IoStream::Yamux(control_stream);
                            info!(addr = %addr, "Yamux over WS+TLS session established for {}", addr);

                            // Try V2 detection on yamux stream
                            let mut v2_magic = [0u8; 7];
                            let is_v2 = match io.read_exact(&mut v2_magic).await {
                                Ok(_) => is_v2_magic(&v2_magic),
                                Err(_) => false,
                            };
                            if is_v2 {
                                let (msg_payload, crypto_ctx) = match tokio::time::timeout_at(accept_deadline, frp_core::v2_handshake::v2_handshake_server(&mut io)).await {
                                                                Ok(r) => match r {
                                                                    Ok((Some(p), crypto)) => (p, crypto),
                                                                    Ok((None, crypto)) => {
                                                                        match tokio::time::timeout_at(accept_deadline, frp_core::v2_handshake::read_first_frame_after_handshake(&mut io)).await {
                                                                            Ok(r) => match r {
                                                                                Ok((frp_core::protocol::V2_FRAME_TYPE_MESSAGE, _, p)) => (p, crypto),
                                                                                Ok((ft, _, _)) => {
                                                                                    warn!(frame_type = ?ft, addr = %addr, "WS+TLS+yamux V2: unexpected frame type {} from {}", ft, addr);
                                                                                    return;
                                                                                }
                                                                                Err(e) => {
                                                                                    warn!(addr = %addr, error = %e, "WS+TLS+yamux V2: failed to read message: {}", e);
                                                                                    return;
                                                                                }
                                                                            },
                                                                            Err(_elapsed) => {
                                                                                warn!(addr = %addr, "WS+TLS+yamux V2: read first frame after handshake timeout from {}", addr);
                                                                                return;
                                                                            }
                                                                        }
                                                                    }
                                                                    Err(e) => {
                                                                        warn!(addr = %addr, error = %e, "WS+TLS+yamux V2 handshake error from {}: {}", addr, e);
                                                                        return;
                                                                    }
                                                                },
                                                                Err(_elapsed) => {
                                                                    warn!(addr = %addr, "WS+TLS+yamux V2 handshake timeout from {}", addr);
                                                                    return;
                                                                }
                                                            };
                                crate::handlers::dispatch_v2_message(
                                    io,
                                    msg_payload,
                                    state,
                                    addr,
                                    Some(incoming),
                                    None,
                                    crypto_ctx,
                                )
                                .await;
                            } else {
                                let io = IoStream::BufferedRead(v2_magic.to_vec(), 0, Box::new(io));
                                crate::handlers::dispatch_v1_message(
                                    io,
                                    state,
                                    Some(addr),
                                    Some(incoming),
                                    None,
                                    accept_deadline,
                                )
                                .await;
                            }
                        }
                        Err(e) => {
                            warn!(addr = %addr, error = %e, "Failed to start yamux over WS+TLS for {}: {}", addr, e);
                        }
                    }
                } else {
                    let ws = IoStream::BufferedRead(magic.to_vec(), 0, Box::new(ws));
                    crate::handlers::dispatch_v1_message(
                        ws,
                        state,
                        Some(addr),
                        None,
                        None,
                        accept_deadline,
                    )
                    .await;
                }
            }
            Err(e) => {
                warn!(addr = %addr, error = %e, "WebSocket upgrade over TLS failed: {}", e);
            }
        }
        return;
    }

    // Not WebSocket — replay peeked bytes.
    let mut io = IoStream::BufferedRead(ws_peek, 0, Box::new(io));

    // When tcp_mux is enabled, wrap TLS stream in yamux
    // before reading the first message (matches Go frp).
    if state.tcp_mux {
        let mux_cfg = mux::TcpMuxConfig {
            keepalive_interval: std::time::Duration::from_secs(
                state.tcp_mux_keepalive.max(1) as u64
            ),

            ..Default::default()
        };
        match mux::server_mux(io, &mux_cfg).await {
            Ok((control_stream, incoming)) => {
                let mut io = IoStream::Yamux(control_stream);
                info!(addr = ?addr, "Yamux over TLS session established for {:?}", addr);

                // Try V2 detection on yamux stream (Go frp: magic on stream)
                let mut magic = [0u8; 7];
                let is_v2 = match io.read_exact(&mut magic).await {
                    Ok(_) => is_v2_magic(&magic),
                    Err(_) => false,
                };
                if is_v2 {
                    // V2 detected on TLS+yamux stream
                    let (msg_payload, crypto_ctx) = match tokio::time::timeout_at(
                        accept_deadline,
                        frp_core::v2_handshake::v2_handshake_server(&mut io),
                    )
                    .await
                    {
                        Ok(r) => match r {
                            Ok((Some(p), crypto)) => (p, crypto),
                            Ok((None, crypto)) => {
                                // Read Login in plaintext. AEAD wrapping happens in
                                // handle_control after LoginResp (matching Go frp flow).
                                match tokio::time::timeout_at(
                                    accept_deadline,
                                    frp_core::v2_handshake::read_first_frame_after_handshake(
                                        &mut io,
                                    ),
                                )
                                .await
                                {
                                    Ok(r) => match r {
                                        Ok((frp_core::protocol::V2_FRAME_TYPE_MESSAGE, _, p)) => {
                                            (p, crypto)
                                        }
                                        Ok((ft, _, _)) => {
                                            warn!(frame_type = ?ft, addr = %addr, "Unexpected frame type {} after V2 TLS+yamux handshake from {}", ft, addr);
                                            return;
                                        }
                                        Err(e) => {
                                            warn!(addr = %addr, error = %e, "Failed to read V2 message after TLS+yamux handshake from {}: {}", addr, e);
                                            return;
                                        }
                                    },
                                    Err(_elapsed) => {
                                        warn!(addr = %addr, "V2 TLS+yamux: read first frame after handshake timeout from {}", addr);
                                        return;
                                    }
                                }
                            }
                            Err(e) => {
                                warn!(addr = %addr, error = %e, "V2 TLS+yamux handshake error from {}: {}", addr, e);
                                return;
                            }
                        },
                        Err(_elapsed) => {
                            warn!(addr = %addr, "V2 TLS+yamux handshake timeout from {}", addr);
                            return;
                        }
                    };
                    crate::handlers::dispatch_v2_message(
                        io,
                        msg_payload,
                        state,
                        addr,
                        Some(incoming),
                        None,
                        crypto_ctx,
                    )
                    .await;
                } else {
                    // Not V2. Replay consumed bytes for V1 processing.
                    let io = IoStream::BufferedRead(magic.to_vec(), 0, Box::new(io));
                    crate::handlers::dispatch_v1_message(
                        io,
                        state,
                        Some(addr),
                        Some(incoming),
                        None,
                        accept_deadline,
                    )
                    .await;
                }
            }
            Err(e) => {
                warn!(addr = ?addr, error = %e, "Failed to start yamux over TLS for {:?}: {}", addr, e);
            }
        }
    } else {
        // io already includes peeked bytes via BufferedRead.
        // Proceed with V2/V1 detection on the TLS stream.
        // Try V2 magic detection
        let mut magic = [0u8; 7];
        let is_v2 = match io.read_exact(&mut magic).await {
            Ok(_) => is_v2_magic(&magic),
            Err(_) => false,
        };

        if is_v2 {
            // V2 path: ClientHello/ServerHello handshake
            let (msg_payload, crypto_ctx) = match tokio::time::timeout_at(
                accept_deadline,
                frp_core::v2_handshake::v2_handshake_server(&mut io),
            )
            .await
            {
                Ok(r) => match r {
                    Ok((Some(p), crypto)) => (p, crypto),
                    Ok((None, crypto)) => {
                        match tokio::time::timeout_at(
                            accept_deadline,
                            frp_core::v2_handshake::read_first_frame_after_handshake(&mut io),
                        )
                        .await
                        {
                            Ok(r) => match r {
                                Ok((frp_core::protocol::V2_FRAME_TYPE_MESSAGE, _, p)) => {
                                    (p, crypto)
                                }
                                Ok((ft, _, _)) => {
                                    tracing::warn!(frame_type = ?ft, addr = %addr, "TLS V2: unexpected frame type {} after handshake from {}", ft, addr);
                                    return;
                                }
                                Err(e) => {
                                    tracing::warn!(addr = %addr, error = %e, "TLS V2: failed to read message after handshake from {}: {}", addr, e);
                                    return;
                                }
                            },
                            Err(_elapsed) => {
                                tracing::warn!(addr = %addr, "TLS V2: read first frame after handshake timeout from {}", addr);
                                return;
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!(addr = %addr, error = %e, "TLS V2 handshake error from {}: {}", addr, e);
                        return;
                    }
                },
                Err(_elapsed) => {
                    tracing::warn!(addr = %addr, "TLS V2 handshake timeout from {}", addr);
                    return;
                }
            };
            // Pass visitor_addr to match V1 TLS plain behavior for NatHoleVisitor
            crate::handlers::dispatch_v2_message(
                io,
                msg_payload,
                state,
                addr,
                None,
                Some(addr.to_string()),
                crypto_ctx,
            )
            .await;
        } else {
            // V1 fallback: replay consumed 7 bytes
            let io = IoStream::BufferedRead(magic.to_vec(), 0, Box::new(io));
            crate::handlers::dispatch_v1_message(
                io,
                state,
                Some(addr),
                None,
                Some(addr.to_string()),
                accept_deadline,
            )
            .await;
        }
    }
}

#[cfg(not(feature = "tls"))]
#[inline(never)]
pub(crate) async fn handle_tls_connection(
    state: Arc<AppState>,
    addr: std::net::SocketAddr,
    accept_deadline: tokio::time::Instant,
    first_byte: u8,
    stream_io: IoStream,
) {
    // Go frp compat: when TLS feature is not compiled in
    // but frpc sends 0x17 prefix, fall back to V1.
    if first_byte == frp_core::transport::FRP_TLS_HEAD_BYTE {
        let (mut pre_read_bytes, inner_stream) = match stream_io.into_parts() {
            Some(parts) => parts,
            None => {
                warn!(addr = %addr, "Expected PreRead for 0x17 connection from {}", addr);
                return;
            }
        };
        // Strip 0x17 (Go frp TLS head byte).
        if !pre_read_bytes.is_empty() {
            pre_read_bytes.remove(0);
        }
        info!(addr = %addr, "TLS head byte (0x17) but TLS feature not enabled, falling back to V1");
        let stream = IoStream::PreRead(pre_read_bytes, inner_stream);
        crate::handlers::dispatch_v1_message(
            stream,
            state,
            Some(addr),
            None,
            Some(addr.to_string()),
            accept_deadline,
        )
        .await;
        return;
    }
    warn!(addr = %addr, "TLS connection from {} but TLS feature not enabled", addr);
}

#[cfg(feature = "websocket")]
#[inline(never)]
pub(crate) async fn handle_websocket_connection(
    state: Arc<AppState>,
    addr: std::net::SocketAddr,
    accept_deadline: tokio::time::Instant,
    stream_io: IoStream,
) {
    if state.tls_only {
        warn!(addr = %addr, "TLS-only mode: rejected WebSocket from {}", addr);
        return;
    }
    // stream_io is IoStream::PreRead — its AsyncRead replays
    // the 7 consumed bytes (starting with 'G' for GET).
    match accept_websocket(stream_io).await {
        Ok(mut ws) => {
            info!(addr = %addr, "WebSocket upgrade on main port for {}", addr);

            // Try V2 magic detection
            let mut magic = [0u8; 7];
            let is_v2 = match ws.read_exact(&mut magic).await {
                Ok(_) => {
                    let matches = is_v2_magic(&magic);
                    debug!(
                        addr = %addr,
                        magic_hex = %magic.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(""),
                        is_v2 = matches,
                        "WS post-upgrade first 7 bytes"
                    );
                    matches
                }
                Err(_) => false,
            };

            if magic[0] == 0x16 {
                // TLS-over-WebSocket: Go frpc (Docker default) sends
                // TLS ClientHello as first WebSocket frame payload.
                // Replay consumed bytes and wrap in TLS, matching
                // Go frps auto-generated cert behavior.
                #[cfg(feature = "tls")]
                {
                    let tls_acceptor = match state.tls_acceptor.read_ok().clone() {
                        Some(a) => a,
                        None => {
                            warn!(addr = %addr, "TLS ClientHello in WS frame but TLS not configured");
                            return;
                        }
                    };
                    // Replay the 7 consumed payload bytes (TLS ClientHello
                    // prefix), then delegate to WsByteStream for subsequent
                    // WebSocket frames. The TLS handshake runs INSIDE the
                    // WebSocket framing — ServerHello/Certificate/etc. are
                    // wrapped in WS frames by WsByteStream.
                    let stream = frp_core::transport::IoStream::BufferedRead(
                        magic.to_vec(),
                        0,
                        Box::new(ws),
                    );
                    let tls_stream = match tokio::time::timeout_at(
                        accept_deadline,
                        tls_acceptor.accept(stream),
                    )
                    .await
                    {
                        Ok(r) => match r {
                            Ok(s) => s,
                            Err(e) => {
                                warn!(addr = %addr, error = %e, "TLS handshake failed on WS from {}: {}", addr, e);
                                return;
                            }
                        },
                        Err(_elapsed) => {
                            warn!(addr = %addr, "TLS handshake timeout from {}", addr);
                            return;
                        }
                    };
                    info!(addr = %addr, "TLS-over-WebSocket connection from {}", addr);

                    // When tcp_mux is enabled, wrap TLS stream in yamux before
                    // reading the first message (matches Go frp — Go frpc uses
                    // tcp_mux by default over all transports, including
                    // WebSocket-tunneled TLS).
                    if state.tcp_mux {
                        let mux_cfg = mux::TcpMuxConfig {
                            keepalive_interval: std::time::Duration::from_secs(
                                state.tcp_mux_keepalive.max(1) as u64,
                            ),

                            ..Default::default()
                        };
                        match mux::server_mux(tls_stream, &mux_cfg).await {
                            Ok((control_stream, incoming)) => {
                                let mut io = IoStream::Yamux(control_stream);
                                info!(addr = ?addr, "Yamux over WS+TLS session established for {:?}", addr);

                                // V2 detection on yamux stream
                                let mut magic = [0u8; 7];
                                let is_v2 = match io.read_exact(&mut magic).await {
                                    Ok(_) => is_v2_magic(&magic),
                                    Err(_) => false,
                                };
                                if is_v2 {
                                    let (msg_payload, crypto_ctx) = match tokio::time::timeout_at(accept_deadline, frp_core::v2_handshake::v2_handshake_server(&mut io)).await {
                                                                    Ok(r) => match r {
                                                                        Ok((Some(p), crypto)) => (p, crypto),
                                                                        Ok((None, crypto)) => {
                                                                            match tokio::time::timeout_at(accept_deadline, frp_core::v2_handshake::read_first_frame_after_handshake(&mut io)).await {
                                                                                Ok(r) => match r {
                                                                                    Ok((frp_core::protocol::V2_FRAME_TYPE_MESSAGE, _, p)) => (p, crypto),
                                                                                    Ok((ft, _, _)) => {
                                                                                        warn!(frame_type = ?ft, addr = %addr, "WS+TLS+yamux V2: unexpected frame type {} from {}", ft, addr);
                                                                                        return;
                                                                                    }
                                                                                    Err(e) => {
                                                                                        warn!(addr = %addr, error = %e, "WS+TLS+yamux V2: failed to read message from {}: {}", addr, e);
                                                                                        return;
                                                                                    }
                                                                                },
                                                                                Err(_elapsed) => {
                                                                                    warn!(addr = %addr, "WS+TLS+yamux V2: read first frame after handshake timeout from {}", addr);
                                                                                    return;
                                                                                }
                                                                            }
                                                                        }
                                                                        Err(e) => {
                                                                            warn!(addr = %addr, error = %e, "WS+TLS+yamux V2 handshake error from {}: {}", addr, e);
                                                                            return;
                                                                        }
                                                                    },
                                                                    Err(_elapsed) => {
                                                                        warn!(addr = %addr, "WS+TLS+yamux V2 handshake timeout from {}", addr);
                                                                        return;
                                                                    }
                                                                };
                                    crate::handlers::dispatch_v2_message(
                                        io,
                                        msg_payload,
                                        state.clone(),
                                        addr,
                                        Some(incoming),
                                        None,
                                        crypto_ctx,
                                    )
                                    .await;
                                } else {
                                    // V1 over WS+TLS+yamux
                                    let io = frp_core::transport::IoStream::BufferedRead(
                                        magic.to_vec(),
                                        0,
                                        Box::new(io),
                                    );
                                    crate::handlers::dispatch_v1_message(
                                        io,
                                        state.clone(),
                                        Some(addr),
                                        Some(incoming),
                                        None,
                                        accept_deadline,
                                    )
                                    .await;
                                }
                            }
                            Err(e) => {
                                warn!(addr = ?addr, error = %e, "Failed to start yamux over WS+TLS for {:?}: {}", addr, e);
                            }
                        }
                    } else {
                        let mut io = IoStream::Tls(Box::new(tls_stream), addr);

                        // V2 chicken check on the decrypted TLS stream
                        let mut chicken = [0u8; 7];
                        let is_tls_v2 = match io.read_exact(&mut chicken).await {
                            Ok(_) => is_v2_magic(&chicken),
                            Err(_) => false,
                        };
                        if is_tls_v2 {
                            let (msg_payload, crypto_ctx) = match tokio::time::timeout_at(
                                accept_deadline,
                                frp_core::v2_handshake::v2_handshake_server(&mut io),
                            )
                            .await
                            {
                                Ok(r) => match r {
                                    Ok((Some(p), crypto)) => (p, crypto),
                                    Ok((None, crypto)) => {
                                        match tokio::time::timeout_at(accept_deadline, frp_core::v2_handshake::read_first_frame_after_handshake(&mut io)).await {
                                                                        Ok(r) => match r {
                                                                            Ok((frp_core::protocol::V2_FRAME_TYPE_MESSAGE, _, p)) => (p, crypto),
                                                                            Ok((ft, _, _)) => {
                                                                                warn!(frame_type = ?ft, addr = %addr, "WS+TLS+V2: unexpected frame type {} from {}", ft, addr);
                                                                                return;
                                                                            }
                                                                            Err(e) => {
                                                                                warn!(addr = %addr, error = %e, "WS+TLS+V2: failed to read message from {}: {}", addr, e);
                                                                                return;
                                                                            }
                                                                        },
                                                                        Err(_elapsed) => {
                                                                            warn!(addr = %addr, "WS+TLS+V2: read first frame after handshake timeout from {}", addr);
                                                                            return;
                                                                        }
                                                                    }
                                    }
                                    Err(e) => {
                                        warn!(addr = %addr, error = %e, "WS+TLS+V2 handshake error from {}: {}", addr, e);
                                        return;
                                    }
                                },
                                Err(_elapsed) => {
                                    warn!(addr = %addr, "WS+TLS+V2 handshake timeout from {}", addr);
                                    return;
                                }
                            };
                            crate::handlers::dispatch_v2_message(
                                io,
                                msg_payload,
                                state.clone(),
                                addr,
                                None,
                                None,
                                crypto_ctx,
                            )
                            .await;
                        } else {
                            // V1 over TLS-over-WS
                            let io = frp_core::transport::IoStream::BufferedRead(
                                chicken.to_vec(),
                                0,
                                Box::new(io),
                            );
                            crate::handlers::dispatch_v1_message(
                                io,
                                state.clone(),
                                Some(addr),
                                None,
                                None,
                                accept_deadline,
                            )
                            .await;
                        }
                    }
                }
                #[cfg(not(feature = "tls"))]
                {
                    warn!(addr = %addr, "TLS ClientHello in WebSocket frame but TLS feature not enabled, dropping connection from {}", addr);
                }
            } else if state.tcp_mux {
                // Plain WebSocket + tcp_mux: Go frp v0.70.1 wraps the
                // upgraded stream in yamux before any FRP bytes, so
                // wrap here and run V2/V1 detection on the yamux stream.
                let stream = IoStream::BufferedRead(magic.to_vec(), 0, Box::new(ws));
                let mux_cfg = mux::TcpMuxConfig {
                    keepalive_interval: std::time::Duration::from_secs(
                        state.tcp_mux_keepalive.max(1) as u64,
                    ),

                    ..Default::default()
                };
                match mux::server_mux(stream, &mux_cfg).await {
                    Ok((control_stream, incoming)) => {
                        let mut io = IoStream::Yamux(control_stream);
                        info!(addr = ?addr, "Yamux over WebSocket session established for {:?}", addr);

                        // V2 detection on yamux stream
                        let mut mux_magic = [0u8; 7];
                        let is_v2 = match io.read_exact(&mut mux_magic).await {
                            Ok(_) => is_v2_magic(&mux_magic),
                            Err(_) => false,
                        };
                        if is_v2 {
                            let (msg_payload, crypto_ctx) = match tokio::time::timeout_at(
                                accept_deadline,
                                frp_core::v2_handshake::v2_handshake_server(&mut io),
                            )
                            .await
                            {
                                Ok(r) => match r {
                                    Ok((Some(p), crypto)) => (p, crypto),
                                    Ok((None, crypto)) => {
                                        match tokio::time::timeout_at(accept_deadline, frp_core::v2_handshake::read_first_frame_after_handshake(&mut io)).await {
                                                                        Ok(r) => match r {
                                                                            Ok((frp_core::protocol::V2_FRAME_TYPE_MESSAGE, _, p)) => (p, crypto),
                                                                            Ok((ft, _, _)) => {
                                                                                warn!(frame_type = ?ft, addr = %addr, "WS+yamux V2: unexpected frame type {} from {}", ft, addr);
                                                                                return;
                                                                            }
                                                                            Err(e) => {
                                                                                warn!(addr = %addr, error = %e, "WS+yamux V2: failed to read message from {}: {}", addr, e);
                                                                                return;
                                                                            }
                                                                        },
                                                                        Err(_elapsed) => {
                                                                            warn!(addr = %addr, "WS+yamux V2: read first frame after handshake timeout from {}", addr);
                                                                            return;
                                                                        }
                                                                    }
                                    }
                                    Err(e) => {
                                        warn!(addr = %addr, error = %e, "WS+yamux V2 handshake error from {}: {}", addr, e);
                                        return;
                                    }
                                },
                                Err(_elapsed) => {
                                    warn!(addr = %addr, "WS+yamux V2 handshake timeout from {}", addr);
                                    return;
                                }
                            };
                            crate::handlers::dispatch_v2_message(
                                io,
                                msg_payload,
                                state.clone(),
                                addr,
                                Some(incoming),
                                None,
                                crypto_ctx,
                            )
                            .await;
                        } else {
                            // V1 over plain WS+yamux
                            let io = IoStream::BufferedRead(mux_magic.to_vec(), 0, Box::new(io));
                            crate::handlers::dispatch_v1_message(
                                io,
                                state.clone(),
                                Some(addr),
                                Some(incoming),
                                None,
                                accept_deadline,
                            )
                            .await;
                        }
                    }
                    Err(e) => {
                        warn!(addr = ?addr, error = %e, "Failed to start yamux over WebSocket for {:?}: {}", addr, e);
                    }
                }
            } else if is_v2 {
                // V2 path: ClientHello/ServerHello handshake
                let (msg_payload, crypto_ctx) = match tokio::time::timeout_at(
                    accept_deadline,
                    frp_core::v2_handshake::v2_handshake_server(&mut ws),
                )
                .await
                {
                    Ok(r) => match r {
                        Ok((Some(p), crypto)) => (p, crypto),
                        Ok((None, crypto)) => {
                            match tokio::time::timeout_at(
                                accept_deadline,
                                frp_core::v2_handshake::read_first_frame_after_handshake(&mut ws),
                            )
                            .await
                            {
                                Ok(r) => match r {
                                    Ok((frp_core::protocol::V2_FRAME_TYPE_MESSAGE, _, p)) => {
                                        (p, crypto)
                                    }
                                    Ok((ft, _, _)) => {
                                        warn!(frame_type = ?ft, addr = %addr, "WS V2 (main): unexpected frame type {} after handshake from {}", ft, addr);
                                        return;
                                    }
                                    Err(e) => {
                                        warn!(addr = %addr, error = %e, "WS V2 (main): failed to read message after handshake from {}: {}", addr, e);
                                        return;
                                    }
                                },
                                Err(_elapsed) => {
                                    warn!(addr = %addr, "WS V2 (main): read first frame after handshake timeout from {}", addr);
                                    return;
                                }
                            }
                        }
                        Err(e) => {
                            warn!(addr = %addr, error = %e, "WS V2 (main) handshake error from {}: {}", addr, e);
                            return;
                        }
                    },
                    Err(_elapsed) => {
                        warn!(addr = %addr, "WS V2 (main) handshake timeout from {}", addr);
                        return;
                    }
                };
                crate::handlers::dispatch_v2_message(
                    ws,
                    msg_payload,
                    state.clone(),
                    addr,
                    None,
                    None,
                    crypto_ctx,
                )
                .await;
            } else {
                // V1 fallback: replay consumed 7 bytes
                let ws =
                    frp_core::transport::IoStream::BufferedRead(magic.to_vec(), 0, Box::new(ws));
                crate::handlers::dispatch_v1_message(
                    ws,
                    state.clone(),
                    Some(addr),
                    None,
                    None,
                    accept_deadline,
                )
                .await;
            }
        }
        Err(e) => {
            warn!(addr = %addr, error = %e, "WebSocket upgrade failed for {}: {}", addr, e);
        }
    }
}

#[inline(never)]
pub(crate) async fn handle_v2_connection(
    state: Arc<AppState>,
    addr: std::net::SocketAddr,
    accept_deadline: tokio::time::Instant,
    stream_io: IoStream,
) {
    // Already consumed V2 magic. Extract TcpStream.
    let inner_stream = match stream_io.into_tcp() {
        Some(s) => s,
        None => {
            warn!(addr = %addr, "Expected TcpStream for V2 connection from {}, got unexpected stream type", addr);
            return;
        }
    };

    if state.tls_only {
        warn!(addr = %addr, "TLS-only mode: rejected V2 from {}", addr);
        return;
    }

    if state.tcp_mux {
        // Wrap in yamux BEFORE handshake (matches Go frp flow).
        let mux_cfg = mux::TcpMuxConfig {
            keepalive_interval: std::time::Duration::from_secs(
                state.tcp_mux_keepalive.max(1) as u64
            ),

            ..Default::default()
        };
        match mux::server_mux(inner_stream, &mux_cfg).await {
            Ok((control_stream, incoming)) => {
                let mut io = IoStream::Yamux(control_stream);
                info!(addr = ?addr, "Yamux over V2 session established for {:?}", addr);

                match frp_core::protocol::read_v2_magic_or_replay(&mut io).await {
                    Ok(None) => {} // magic consumed
                    Ok(Some(bytes)) => {
                        // Older V2 client without per-stream magic —
                        // replay bytes as start of next frame.
                        io = IoStream::BufferedRead(bytes, 0, Box::new(io));
                    }
                    Err(e) => {
                        warn!(error = %e, "Failed to read V2 magic from yamux stream: {}", e);
                        return;
                    }
                }

                // V2 handshake: may receive ClientHello or first message
                let (msg_payload, crypto_ctx) = match tokio::time::timeout_at(
                    accept_deadline,
                    frp_core::v2_handshake::v2_handshake_server(&mut io),
                )
                .await
                {
                    Ok(r) => match r {
                        Ok((Some(p), crypto)) => (p, crypto),
                        Ok((None, crypto)) => {
                            // Read Login in plaintext. AEAD wrapping happens in
                            // handle_control after LoginResp (matching Go frp flow).
                            match tokio::time::timeout_at(
                                accept_deadline,
                                frp_core::v2_handshake::read_first_frame_after_handshake(&mut io),
                            )
                            .await
                            {
                                Ok(r) => match r {
                                    Ok((frp_core::protocol::V2_FRAME_TYPE_MESSAGE, _, p)) => {
                                        (p, crypto)
                                    }
                                    Ok((ft, _, _)) => {
                                        warn!(frame_type = ?ft, addr = %addr, "Unexpected frame type {} after V2 handshake from {}", ft, addr);
                                        return;
                                    }
                                    Err(e) => {
                                        warn!(addr = %addr, error = %e, "Failed to read V2 message after handshake from {}: {}", addr, e);
                                        return;
                                    }
                                },
                                Err(_elapsed) => {
                                    warn!(addr = %addr, "V2 yamux: read first frame after handshake timeout from {}", addr);
                                    return;
                                }
                            }
                        }
                        Err(e) => {
                            warn!(addr = %addr, error = %e, "V2 handshake error from {}: {}", addr, e);
                            return;
                        }
                    },
                    Err(_elapsed) => {
                        warn!(addr = %addr, "V2 yamux handshake timeout from {}", addr);
                        return;
                    }
                };

                crate::handlers::dispatch_v2_message(
                    io,
                    msg_payload,
                    state,
                    addr,
                    Some(incoming),
                    None,
                    crypto_ctx,
                )
                .await;
            }
            Err(e) => {
                warn!(addr = ?addr, error = %e, "Failed to start yamux over V2 for {:?}: {}", addr, e);
            }
        }
    } else {
        // No tcp_mux: V2 directly on raw TCP
        let mut io = IoStream::Tcp(inner_stream);

        // V2 handshake: may receive ClientHello or first message
        let (msg_payload, crypto_ctx) = match tokio::time::timeout_at(
            accept_deadline,
            frp_core::v2_handshake::v2_handshake_server(&mut io),
        )
        .await
        {
            Ok(r) => match r {
                Ok((Some(p), crypto)) => (p, crypto),
                Ok((None, crypto)) => {
                    // Read Login in plaintext. AEAD wrapping happens in
                    // handle_control after LoginResp (matching Go frp flow).
                    match tokio::time::timeout_at(
                        accept_deadline,
                        frp_core::v2_handshake::read_first_frame_after_handshake(&mut io),
                    )
                    .await
                    {
                        Ok(r) => match r {
                            Ok((frp_core::protocol::V2_FRAME_TYPE_MESSAGE, _, p)) => (p, crypto),
                            Ok((ft, _, _)) => {
                                warn!(frame_type = ?ft, addr = %addr, "Unexpected frame type {} after V2 handshake from {}", ft, addr);
                                return;
                            }
                            Err(e) => {
                                warn!(addr = %addr, error = %e, "Failed to read V2 message after handshake from {}: {}", addr, e);
                                return;
                            }
                        },
                        Err(_elapsed) => {
                            warn!(addr = %addr, "V2: read first frame after handshake timeout from {}", addr);
                            return;
                        }
                    }
                }
                Err(e) => {
                    warn!(addr = %addr, error = %e, "V2 handshake error from {}: {}", addr, e);
                    return;
                }
            },
            Err(_elapsed) => {
                warn!(addr = %addr, "V2 handshake timeout from {}", addr);
                return;
            }
        };

        crate::handlers::dispatch_v2_message(
            io,
            msg_payload,
            state,
            addr,
            None,
            Some(addr.to_string()),
            crypto_ctx,
        )
        .await;
    }
}

#[inline(never)]
pub(crate) async fn handle_v1_connection(
    state: Arc<AppState>,
    addr: std::net::SocketAddr,
    accept_deadline: tokio::time::Instant,
    stream_io: IoStream,
) {
    if state.tls_only {
        warn!(addr = %addr, "TLS-only mode: rejected plain TCP from {}", addr);
        return;
    }
    if state.tcp_mux {
        // Extract inner transport and pre-read bytes.
        // Wrap in PreReadStream so yamux sees the full byte stream
        // (including the type byte consumed by detect_and_strip_magic).
        let (pre_read, inner_transport) = match stream_io.into_parts() {
            Some(parts) => parts,
            None => {
                warn!(addr = %addr,
                    "Expected PreRead stream after detect_and_strip_magic from {}, got unexpected stream type",
                    addr
                );
                return;
            }
        };
        let stream = PreReadStream::new(pre_read, inner_transport);

        let mux_cfg = mux::TcpMuxConfig {
            keepalive_interval: std::time::Duration::from_secs(
                state.tcp_mux_keepalive.max(1) as u64
            ),

            ..Default::default()
        };
        match mux::server_mux(stream, &mux_cfg).await {
            Ok((control_stream, incoming)) => {
                let mut io = IoStream::Yamux(control_stream);
                info!(addr = ?addr, "Yamux session established for {:?}", addr);

                // Try V2 detection: read 7 magic bytes from yamux stream.
                // Go frp sends V2 magic on yamux stream (not raw TCP) when tcpMux.
                let mut magic = [0u8; 7];
                let is_v2 = match io.read_exact(&mut magic).await {
                    Ok(_) => is_v2_magic(&magic),
                    Err(_) => false,
                };
                if is_v2 {
                    // V2 detected on yamux stream! Do V2 handshake + dispatch
                    let (msg_payload, crypto_ctx) = match tokio::time::timeout_at(
                        accept_deadline,
                        frp_core::v2_handshake::v2_handshake_server(&mut io),
                    )
                    .await
                    {
                        Ok(r) => match r {
                            Ok((Some(p), crypto)) => (p, crypto),
                            Ok((None, crypto)) => {
                                // Read Login in plaintext. AEAD wrapping happens in
                                // handle_control after LoginResp (matching Go frp flow).
                                match tokio::time::timeout_at(
                                    accept_deadline,
                                    frp_core::v2_handshake::read_first_frame_after_handshake(
                                        &mut io,
                                    ),
                                )
                                .await
                                {
                                    Ok(r) => match r {
                                        Ok((frp_core::protocol::V2_FRAME_TYPE_MESSAGE, _, p)) => {
                                            (p, crypto)
                                        }
                                        Ok((ft, _, _)) => {
                                            warn!(frame_type = ?ft, addr = %addr, "Unexpected frame type {} after V2 handshake from {}", ft, addr);
                                            return;
                                        }
                                        Err(e) => {
                                            warn!(addr = %addr, error = %e, "Failed to read V2 message after handshake from {}: {}", addr, e);
                                            return;
                                        }
                                    },
                                    Err(_elapsed) => {
                                        warn!(addr = %addr, "V2: read first frame after handshake timeout from {}", addr);
                                        return;
                                    }
                                }
                            }
                            Err(e) => {
                                warn!(addr = %addr, error = %e, "V2 handshake error from {}: {}", addr, e);
                                return;
                            }
                        },
                        Err(_elapsed) => {
                            warn!(addr = %addr, "V2 handshake timeout from {}", addr);
                            return;
                        }
                    };
                    crate::handlers::dispatch_v2_message(
                        io,
                        msg_payload,
                        state,
                        addr,
                        Some(incoming),
                        None,
                        crypto_ctx,
                    )
                    .await;
                } else {
                    // Not V2. Replay consumed bytes and process as V1.
                    let io = IoStream::BufferedRead(magic.to_vec(), 0, Box::new(io));
                    crate::handlers::dispatch_v1_message(
                        io,
                        state,
                        Some(addr),
                        Some(incoming),
                        None,
                        accept_deadline,
                    )
                    .await;
                }
            }
            Err(e) => {
                warn!(addr = ?addr, error = %e, "Failed to start yamux server for {:?}: {}", addr, e);
            }
        }
    } else {
        // stream_io is IoStream::PreRead — its AsyncRead replays
        // the consumed bytes (including type byte) before reading
        // the rest from the TcpStream.
        crate::handlers::dispatch_v1_message(
            stream_io,
            state,
            Some(addr),
            None,
            Some(addr.to_string()),
            accept_deadline,
        )
        .await;
    }
}

// ---------------------------------------------------------------
// Protocol detection helpers
// ---------------------------------------------------------------

/// Check if a 7-byte buffer matches the V2 protocol magic bytes.
/// This check is repeated across all transport paths (TCP, KCP, QUIC, WS,
/// with/without TLS, with/without yamux).
/// See V2_MAGIC_BYTES in frp_core::protocol.
#[inline]
pub(crate) fn is_v2_magic(buf: &[u8]) -> bool {
    buf.len() >= 7 && buf[..7] == frp_core::protocol::V2_MAGIC_BYTES
}

/// Check if a byte could be a V1 protocol type byte.
/// All V1 type bytes are ASCII alphanumeric (e.g., 'o'=Login, '1'=LoginResp,
/// 'w'=NewWorkConn, 'h'=Ping). Used to distinguish raw V1 data from yamux
/// headers (which start with 0x00).
#[inline]
#[allow(dead_code)] // only used in TLS/WS/KCP accept paths, not in every feature set
pub(crate) fn is_v1_type_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric()
}

#[cfg(feature = "quic")]
pub(crate) const QUIC_FIRST_FRAME_TIMEOUT: Duration = Duration::from_secs(10);

#[cfg(feature = "quic")]
pub(crate) const QUIC_PREAUTH_STREAM_LIMIT: usize = 32;

#[cfg(feature = "quic")]
fn new_quic_preauth_stream_limiter() -> Arc<tokio::sync::Semaphore> {
    Arc::new(tokio::sync::Semaphore::new(QUIC_PREAUTH_STREAM_LIMIT))
}

#[cfg(feature = "quic")]
fn new_quic_authenticated_stream_limiter(configured: usize) -> Arc<tokio::sync::Semaphore> {
    Arc::new(tokio::sync::Semaphore::new(configured.max(1)))
}

#[cfg(feature = "quic")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum QuicPreauthError {
    TimedOut,
    Cancelled,
}

#[cfg(feature = "quic")]
pub(crate) async fn await_quic_preauth<F, T>(
    future: F,
    deadline: tokio::time::Instant,
    cancel: &CancellationToken,
) -> Result<T, QuicPreauthError>
where
    F: Future<Output = T>,
{
    tokio::select! {
        biased;
        _ = cancel.cancelled() => Err(QuicPreauthError::Cancelled),
        result = tokio::time::timeout_at(deadline, future) => {
            result.map_err(|_| QuicPreauthError::TimedOut)
        }
    }
}

/// Run V2 handshake then read the first message frame. Returns `None` on error
/// (already logged). `addr` is `None` for listeners that don't capture peer addr.
#[cfg(feature = "websocket")]
pub(crate) async fn v2_handshake_and_read(
    io: &mut IoStream,
    addr: Option<std::net::SocketAddr>,
    deadline: tokio::time::Instant,
    log_prefix: &str,
) -> Option<(Vec<u8>, Option<frp_core::v2_handshake::CryptoContext>)> {
    let (msg_payload, crypto_ctx) = match tokio::time::timeout_at(
        deadline,
        frp_core::v2_handshake::v2_handshake_server(io),
    )
    .await
    {
        Ok(r) => match r {
            Ok((Some(p), crypto)) => (p, crypto),
            Ok((None, crypto)) => {
                match tokio::time::timeout_at(
                    deadline,
                    frp_core::v2_handshake::read_first_frame_after_handshake(io),
                )
                .await
                {
                    Ok(r) => match r {
                        Ok((frp_core::protocol::V2_FRAME_TYPE_MESSAGE, _, p)) => (p, crypto),
                        Ok((ft, _, _)) => {
                            tracing::warn!(frame_type = ?ft, peer = ?addr, "{}: unexpected frame type {} after handshake", log_prefix, ft);
                            return None;
                        }
                        Err(e) => {
                            tracing::warn!(peer = ?addr, error = %e, "{}: failed to read message after handshake: {}", log_prefix, e);
                            return None;
                        }
                    },
                    Err(_elapsed) => {
                        tracing::warn!(peer = ?addr, "{}: read first frame after handshake timeout", log_prefix);
                        return None;
                    }
                }
            }
            Err(e) => {
                tracing::warn!(peer = ?addr, error = %e, "{} handshake error: {}", log_prefix, e);
                return None;
            }
        },
        Err(_elapsed) => {
            tracing::warn!(peer = ?addr, "{} handshake timeout", log_prefix);
            return None;
        }
    };
    Some((msg_payload, crypto_ctx))
}

// ---------------------------------------------------------------
// QUIC transport handlers (extracted from Service::run so each
// transport path is a file-level function)
// ---------------------------------------------------------------
/// Handle a QUIC stream (control or work connection).
/// Accepts the first bidirectional stream from `conn`, then runs
/// V1/V2 protocol detection and dispatch. Spawns a drain task to
/// accept additional streams as work connections.
#[cfg(feature = "quic")]
pub(crate) async fn handle_quic_stream(
    first_stream: frp_core::quic::QuicStream,
    conn: frp_core::quic::QuicConnection,
    state: Arc<AppState>,
    first_frame_deadline: tokio::time::Instant,
    authenticated_stream_limit: usize,
) {
    let mut ctl = frp_core::transport::IoStream::Quic(first_stream);

    // Try V2 magic detection on first stream.
    // Per-stream independence: each QUIC stream gets its own
    // V2 detection, matching Go frp's WriteMagicIfV2() per stream.
    let mut magic = [0u8; 7];
    let is_v2 =
        match tokio::time::timeout_at(first_frame_deadline, ctl.read_exact(&mut magic)).await {
            Ok(Ok(_)) => is_v2_magic(&magic),
            Ok(Err(_)) => false,
            Err(_) => {
                tracing::warn!("QUIC control stream timed out before protocol magic");
                conn.close(b"control stream timeout");
                return;
            }
        };

    if is_v2 {
        // --- V2 path ---
        let first_message = tokio::time::timeout_at(first_frame_deadline, async {
            match frp_core::v2_handshake::v2_handshake_server(&mut ctl).await {
            Ok((Some(p), crypto)) => (p, crypto),
            Ok((None, crypto)) => match ctl.read_raw_v2_frame().await {
                Ok((frp_core::protocol::V2_FRAME_TYPE_MESSAGE, _, p)) => (p, crypto),
                Ok((ft, _, _)) => {
                    tracing::warn!(frame_type = ?ft, "QUIC V2: unexpected frame type {} after handshake", ft);
                    return None;
                }
                Err(e) => {
                    tracing::warn!(error = %e, "QUIC V2: failed to read message after handshake: {}", e);
                    return None;
                }
            },
            Err(e) => {
                tracing::warn!(error = %e, "QUIC V2 handshake error: {}", e);
                return None;
            }
            }.into()
        }).await;
        let (msg_payload, crypto_ctx) = match first_message {
            Ok(Some(message)) => message,
            Ok(None) => {
                conn.close(b"control stream error");
                return;
            }
            Err(_) => {
                tracing::warn!("QUIC V2 control stream timed out before first message");
                conn.close(b"control stream timeout");
                return;
            }
        };

        let addr: std::net::SocketAddr = conn.remote_address();
        let (auth_tx, auth_rx) = tokio::sync::oneshot::channel();
        let control = crate::handlers::dispatch_v2_message_with_auth_signal(
            ctl,
            msg_payload,
            Arc::clone(&state),
            addr,
            None,
            None,
            crypto_ctx,
            auth_tx,
        );
        tokio::pin!(control);
        tokio::select! {
            biased;
            _ = &mut control => {}
            auth = auth_rx => {
                if auth.is_err() {
                    return;
                }
                conn.set_max_concurrent_bi_streams(
                    authenticated_stream_limit.min(u32::MAX as usize) as u32,
                );
                let cancel = spawn_quic_drain(
                    conn,
                    Arc::clone(&state),
                    "V2",
                    authenticated_stream_limit,
                );
                control.await;
                cancel.cancel();
            }
        }
    } else {
        // --- V1 fallback ---
        let mut ctl = frp_core::transport::IoStream::BufferedRead(magic.to_vec(), 0, Box::new(ctl));

        match tokio::time::timeout_at(
            first_frame_deadline,
            frp_core::protocol::read_msg_v1(&mut ctl),
        )
        .await
        {
            Err(_) => {
                tracing::warn!("QUIC V1 control stream timed out before Login");
                conn.close(b"control stream timeout");
            }
            Ok(result) => match result {
                Ok(frp_core::msg::FrpMessage::Login(login)) => {
                    let (auth_tx, auth_rx) = tokio::sync::oneshot::channel();
                    let control = control::handle_control_with_auth_signal(
                        ctl,
                        *login,
                        Arc::clone(&state),
                        Some(conn.remote_address()),
                        None,
                        false,
                        None,
                        false,
                        auth_tx,
                    );
                    tokio::pin!(control);
                    tokio::select! {
                        biased;
                        _ = &mut control => {}
                        auth = auth_rx => {
                            if auth.is_err() {
                                return;
                            }
                            conn.set_max_concurrent_bi_streams(
                                authenticated_stream_limit.min(u32::MAX as usize) as u32,
                            );
                            let cancel = spawn_quic_drain(
                                conn,
                                Arc::clone(&state),
                                "V1",
                                authenticated_stream_limit,
                            );
                            control.await;
                            cancel.cancel();
                        }
                    }
                }
                Ok(frp_core::msg::FrpMessage::NewWorkConn(nwc)) => {
                    crate::handlers::handle_work_conn_inner(ctl, nwc, state).await;
                }
                Ok(other) => {
                    tracing::warn!(other = ?other.v1_type_byte(), "Unexpected QUIC message: {:?}", other.v1_type_byte());
                }
                Err(e) => {
                    tracing::warn!(error = %e, "QUIC read error: {}", e);
                    conn.close(b"control stream error");
                }
            },
        }
    }
}

/// Spawn a drain task that accepts additional QUIC streams as work connections.
/// Returns a `CancellationToken` — call `.cancel()` to stop the drain loop.
#[cfg(feature = "quic")]
pub(crate) fn spawn_quic_drain(
    conn: frp_core::quic::QuicConnection,
    state: Arc<AppState>,
    tag: &'static str,
    authenticated_stream_limit: usize,
) -> CancellationToken {
    let cancel = CancellationToken::new();
    let drain_cancel = cancel.clone();
    let drain_conn = conn;
    tokio::spawn(async move {
        tracing::debug!(tag, "QUIC drain ({tag}) started");
        let preauth_limiter = new_quic_preauth_stream_limiter();
        let authenticated_limiter =
            new_quic_authenticated_stream_limiter(authenticated_stream_limit);
        let mut stream_tasks = tokio::task::JoinSet::new();
        let accept_next = drain_conn.accept_bi();
        tokio::pin!(accept_next);
        loop {
            tokio::select! {
                biased;
                _ = drain_cancel.cancelled() => {
                    tracing::debug!(tag, "QUIC drain ({tag}) cancelled");
                    break;
                }
                Some(result) = stream_tasks.join_next(), if !stream_tasks.is_empty() => {
                    if let Err(e) = result {
                        tracing::debug!(error = %e, tag, "QUIC stream task ended with error");
                    }
                }
                result = &mut accept_next => {
                    let result = if drain_cancel.is_cancelled() {
                        break;
                    } else {
                        result
                    };
                    match result {
                        Ok(work_stream) => {
                            tracing::debug!(tag, "QUIC drain ({tag}): accepted new stream");
                            let s = Arc::clone(&state);
                            let authenticated_limiter = authenticated_limiter.clone();
                            let preauth_limiter = preauth_limiter.clone();
                            stream_tasks.spawn(async move {
                                // Bound concurrent unauthenticated first-frame waits:
                                // acquire only after the stream was accepted so the
                                // limiter caps actual reads, not the accept backlog.
                                let preauth_permit = match preauth_limiter.acquire_owned().await {
                                    Ok(permit) => permit,
                                    Err(_) => return,
                                };
                                let mut wc = frp_core::transport::IoStream::Quic(work_stream);
                                let request = tokio::time::timeout(QUIC_FIRST_FRAME_TIMEOUT, async {
                                    let mut wmagic = [0u8; 7];
                                    let w_is_v2 = match wc.read_exact(&mut wmagic).await {
                                        Ok(_) => is_v2_magic(&wmagic),
                                        Err(e) => return Err(e.into()),
                                    };
                                    if w_is_v2 {
                                        match wc.read_v2_frame().await {
                                            Ok(frp_core::msg::FrpMessage::NewWorkConn(nwc)) => Ok((wc, nwc)),
                                            Ok(other) => Err(frp_core::Error::Protocol(format!("unexpected QUIC V2 message {:?}", other.v2_type_id()).into())),
                                            Err(e) => Err(e),
                                        }
                                    } else {
                                        wc = frp_core::transport::IoStream::BufferedRead(wmagic.to_vec(), 0, Box::new(wc));
                                        match frp_core::protocol::read_msg_v1(&mut wc).await {
                                            Ok(frp_core::msg::FrpMessage::NewWorkConn(nwc)) => Ok((wc, nwc)),
                                            Ok(other) => Err(frp_core::Error::Protocol(format!("unexpected QUIC V1 message {:?}", other.v1_type_byte()).into())),
                                            Err(e) => Err(e),
                                        }
                                    }
                                }).await;
                                match request {
                                    Ok(Ok((wc, nwc))) => {
                                        drop(preauth_permit);
                                        let Ok(_authenticated_permit) =
                                            authenticated_limiter.acquire_owned().await
                                        else {
                                            return;
                                        };
                                        crate::handlers::handle_work_conn_inner(wc, nwc, s).await
                                    },
                                    Ok(Err(e)) => tracing::warn!(error = %e, "QUIC drain: invalid first frame"),
                                    Err(_) => tracing::warn!(timeout_secs = QUIC_FIRST_FRAME_TIMEOUT.as_secs(), "QUIC work stream first-frame timeout"),
                                }
                            });
                            accept_next.set(drain_conn.accept_bi());
                        }
                        Err(e) => {
                            tracing::debug!(error = %e, tag, "QUIC drain ({tag}) done: {e}");
                            break;
                        }
                    }
                }
            }
        }
        stream_tasks.abort_all();
        while stream_tasks.join_next().await.is_some() {}
    });
    cancel
}

#[cfg(test)]
mod visitor_admission_tests {
    use super::*;

    #[test]
    fn legacy_visitor_without_run_id_uses_empty_identity_admission() {
        // Go v0.70.1: empty run_id falls back to identity "" and the normal
        // owner/allow-users check, so an owner-less unrestricted proxy admits.
        assert!(visitor_user_allowed("", "", &[]));
        assert!(visitor_user_allowed("", "", &["*".to_string()]));
        assert!(!visitor_user_allowed("", "", &["alice".to_string()]));
        assert!(!visitor_user_allowed("", "owner", &[]));
    }
}

#[cfg(all(test, feature = "quic"))]
mod quic_admission_tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    async fn simulated_silent_first_frame(
        limiter: Arc<tokio::sync::Semaphore>,
        active: Arc<AtomicUsize>,
        max_active: Arc<AtomicUsize>,
    ) {
        let _permit = limiter.acquire_owned().await.unwrap();
        let now = active.fetch_add(1, Ordering::SeqCst) + 1;
        max_active.fetch_max(now, Ordering::SeqCst);
        let _ = tokio::time::timeout(Duration::from_millis(10), std::future::pending::<()>()).await;
        active.fetch_sub(1, Ordering::SeqCst);
    }

    #[tokio::test]
    async fn unauthenticated_silent_streams_are_bounded_and_timeout_releases_permits() {
        let limit = 4;
        let limiter = Arc::new(tokio::sync::Semaphore::new(limit));
        let active = Arc::new(AtomicUsize::new(0));
        let max_active = Arc::new(AtomicUsize::new(0));
        let mut tasks = tokio::task::JoinSet::new();

        for _ in 0..64 {
            tasks.spawn(simulated_silent_first_frame(
                limiter.clone(),
                active.clone(),
                max_active.clone(),
            ));
        }
        while tasks.join_next().await.is_some() {}

        assert_eq!(max_active.load(Ordering::SeqCst), limit);
        assert_eq!(active.load(Ordering::SeqCst), 0);
        assert_eq!(limiter.available_permits(), limit);
    }

    #[tokio::test]
    async fn drain_preauth_limiter_bounds_concurrent_first_frame_waits() {
        // Mirrors the drain loop: the stream is already accepted, then the
        // preauth permit is acquired before the first-frame read. The
        // limiter must cap concurrent waits at QUIC_PREAUTH_STREAM_LIMIT.
        let limiter = new_quic_preauth_stream_limiter();
        let active = Arc::new(AtomicUsize::new(0));
        let max_active = Arc::new(AtomicUsize::new(0));
        let mut tasks = tokio::task::JoinSet::new();

        for _ in 0..(QUIC_PREAUTH_STREAM_LIMIT * 4) {
            let limiter = limiter.clone();
            let active = active.clone();
            let max_active = max_active.clone();
            tasks.spawn(async move {
                let _permit = limiter.acquire_owned().await.unwrap();
                let now = active.fetch_add(1, Ordering::SeqCst) + 1;
                max_active.fetch_max(now, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_millis(5)).await;
                active.fetch_sub(1, Ordering::SeqCst);
            });
        }
        while tasks.join_next().await.is_some() {}

        assert_eq!(max_active.load(Ordering::SeqCst), QUIC_PREAUTH_STREAM_LIMIT);
        assert_eq!(active.load(Ordering::SeqCst), 0);
        assert_eq!(limiter.available_permits(), QUIC_PREAUTH_STREAM_LIMIT);
    }

    #[tokio::test]
    async fn preauth_stream_admission_uses_small_safety_cap() {
        let limiter = new_quic_preauth_stream_limiter();
        let mut permits = Vec::new();
        for _ in 0..QUIC_PREAUTH_STREAM_LIMIT {
            permits.push(limiter.clone().try_acquire_owned().unwrap());
        }
        assert!(limiter.clone().try_acquire_owned().is_err());
        drop(permits.pop());
        assert!(limiter.clone().try_acquire_owned().is_ok());
    }

    #[tokio::test]
    async fn authenticated_stream_admission_preserves_configured_boundary_above_256() {
        let configured = 1_024usize;
        let limiter = new_quic_authenticated_stream_limiter(configured);
        let mut permits = Vec::new();
        for _ in 0..configured {
            permits.push(limiter.clone().try_acquire_owned().unwrap());
        }
        assert!(limiter.clone().try_acquire_owned().is_err());
        drop(permits.pop());
        assert!(limiter.clone().try_acquire_owned().is_ok());
    }

    #[tokio::test]
    async fn first_control_accept_obeys_absolute_preauth_deadline() {
        let cancel = CancellationToken::new();
        let deadline = tokio::time::Instant::now() + Duration::from_millis(10);
        let result = await_quic_preauth(std::future::pending::<()>(), deadline, &cancel).await;
        assert!(matches!(result, Err(QuicPreauthError::TimedOut)));
    }

    #[tokio::test]
    async fn real_quic_connection_without_first_stream_times_out() {
        let tls = frp_core::transport::generate_self_signed_tls_config().unwrap();
        let listener = frp_core::quic::QuicListener::new_with_tls_config(
            "127.0.0.1:0".parse().unwrap(),
            tls,
            frp_core::quic::QuicTransportParams::default(),
        )
        .unwrap();
        let address = listener.local_addr().unwrap();

        let client = tokio::spawn(async move {
            frp_core::quic::dial_quic_connection_with_params(
                &address.to_string(),
                "localhost",
                None,
                None,
                None,
                frp_core::quic::QuicTransportParams::default(),
                None,
            )
            .await
            .unwrap()
        });
        let server = tokio::time::timeout(Duration::from_secs(2), listener.accept())
            .await
            .expect("server should complete QUIC handshake")
            .unwrap();
        let _client = tokio::time::timeout(Duration::from_secs(2), client)
            .await
            .expect("client should complete QUIC handshake")
            .unwrap();
        let cancel = CancellationToken::new();
        let deadline = tokio::time::Instant::now() + Duration::from_millis(50);

        let result = await_quic_preauth(server.accept_bi(), deadline, &cancel).await;
        assert!(matches!(result, Err(QuicPreauthError::TimedOut)));
        server.close(b"test timeout");
    }

    #[tokio::test]
    async fn cancelling_stream_tasks_reclaims_all_admission_permits() {
        let limit = 8;
        let limiter = Arc::new(tokio::sync::Semaphore::new(limit));
        let mut tasks = tokio::task::JoinSet::new();
        for _ in 0..limit {
            let permit = limiter.clone().acquire_owned().await.unwrap();
            tasks.spawn(async move {
                let _permit = permit;
                std::future::pending::<()>().await;
            });
        }
        assert_eq!(limiter.available_permits(), 0);
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
        assert_eq!(limiter.available_permits(), limit);
    }
}
