//! Login authentication for control connections.
//!
//! Handles OIDC verification, token-based auth, PBKDF2 key derivation,
//! duplicate `run_id` shutdown, encryption setup, and per-client state
//! initialisation.

use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio::time::{Duration, Instant, Interval};
use tracing::{debug, info, warn};

use frp_core::encryption;
use frp_core::msg::{self, FrpMessage};
use frp_core::mux::IncomingStreams;

use crate::lock::RwLockExt;
use crate::state::{AppState, ControlTx, InternalMsg, PoolStats};

use super::pool::{PendingRequest, PoolEntry, WORK_POOL_EXTRA};
use super::proxy_ops::{err_msg, unregister_control};
use super::{write_ctl_msg, ControlContext, ControlState};

/// Authenticate a new control connection and set up per-client state.
/// On success returns all state needed by the main select! loop.
/// On failure sends LoginResp with an error and returns `Err(())`.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn authenticate<S>(
    mut stream: S,
    login: &msg::Login,
    state: Arc<AppState>,
    peer: Option<SocketAddr>,
    incoming: Option<IncomingStreams>,
    v2: bool,
    crypto_ctx: Option<frp_core::v2_handshake::CryptoContext>,
) -> Result<
    (
        ControlContext,
        ControlState,
        mpsc::Sender<InternalMsg>,
        mpsc::Receiver<InternalMsg>,
        Box<dyn AsyncRead + Unpin + Send>,
        Box<dyn AsyncWrite + Unpin + Send>,
        Option<IncomingStreams>,
        Interval,
    ),
    (),
>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    // --- Login throttle: max 5 failed attempts per 60s per IP ---
    if let Some(ref peer_addr) = peer {
        if !state.check_login_throttle(*peer_addr).await {
            warn!(peer = %peer_addr, "Login throttle: too many failed attempts from {}", peer_addr);
            return Err(());
        }
    }

    // --- Authenticate ---
    let oidc_subject: Option<String> = if let Some(ref verifier) = state.oidc.verifier {
        let token = login.privilege_key.as_deref().unwrap_or("");
        match verifier.verify_login(token).await {
            Ok(oidc_token) => {
                info!(subject = %oidc_token.subject, "OIDC login verified: subject={}", oidc_token.subject);
                Some(oidc_token.subject)
            }
            Err(e) => {
                warn!(peer = ?peer, error = %e, "OIDC auth failed for {:?}: {}", peer, e);
                if let Some(ref peer_addr) = peer {
                    state.record_login_failure(*peer_addr).await;
                }
                let (_, mut writer) = tokio::io::split(stream);
                let resp = FrpMessage::LoginResp(msg::LoginResp {
                    version: Some(frp_core::VERSION.into()),
                    run_id: None,
                    error: Some(err_msg(
                        state.detailed_errors_to_client,
                        format!("OIDC authentication failed: {e}"),
                        "OIDC authentication failed",
                    )),
                    server_additional_auth_scopes: None,
                });
                let _ = write_ctl_msg(&mut writer, &resp, v2).await;
                return Err(());
            }
        }
    } else {
        let auth_cfg = state.reloadable.read_ok().auth_cfg.clone();
        if let Err(e) = auth_cfg.validate_login(login.privilege_key.as_deref(), login.timestamp) {
            warn!(peer = ?peer, error = %e, "Authentication failed for {:?}: {}", peer, e);
            if let Some(ref peer_addr) = peer {
                state.record_login_failure(*peer_addr).await;
            }
            // Emit WebSocket event for dashboard subscribers
            #[cfg(feature = "dashboard")]
            {
                let _ = state.event_tx.send(crate::event::ServerEvent::Error {
                    message: format!("Authentication failed for {:?}", peer),
                    context: Some("login".into()),
                });
            }
            let (_, mut writer) = tokio::io::split(stream);
            let resp = FrpMessage::LoginResp(msg::LoginResp {
                version: Some(frp_core::VERSION.into()),
                run_id: None,
                error: Some(err_msg(
                    state.detailed_errors_to_client,
                    e,
                    "token authentication failed",
                )),
                server_additional_auth_scopes: None,
            });
            let _ = write_ctl_msg(&mut writer, &resp, v2).await;
            return Err(());
        }
        None
    };

    let reloadable = state.reloadable.read_ok().clone();

    let run_id = login
        .run_id
        .clone()
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
    info!(peer = ?peer, run_id = %run_id, "Client {:?} logged in with run_id: {}", peer, run_id);

    // Store OIDC subject for ping/NWC verification
    if let Some(ref sub) = oidc_subject {
        state
            .oidc
            .subjects
            .write()
            .await
            .insert(run_id.clone(), sub.clone());
    }

    // --- Server plugin: login hook ---
    let login_content = serde_json::json!({
        "version": login.version,
        "hostname": login.hostname,
        "os": login.os,
        "user": login.user,
        "run_id": run_id,
        "remote_addr": peer.map(|a| a.to_string()),
        "metas": login.metas,
    });
    if let Err(reason) = state.plugin_manager.notify("login", login_content).await {
        warn!(run_id = %run_id, reason = %reason, "Login for run_id {} rejected by server plugin: {}", run_id, reason);
        let (_, mut writer) = tokio::io::split(stream);
        let resp = FrpMessage::LoginResp(msg::LoginResp {
            version: Some(frp_core::VERSION.into()),
            run_id: None,
            error: Some(reason),
            server_additional_auth_scopes: None,
        });
        let _ = write_ctl_msg(&mut writer, &resp, v2).await;
        // Clean up OIDC subject inserted before login validation.
        if oidc_subject.is_some() {
            state.oidc.subjects.write().await.remove(&run_id);
        }
        return Err(());
    }

    // --- Set up internal channel ---
    let (internal_tx, internal_rx) = mpsc::channel::<InternalMsg>(1024);

    // Register control channel. If a previous handler exists for this run_id,
    // send Shutdown to it so it stops listening (Go frp v0.69.1 compat).
    let pool_stats = Arc::new(PoolStats::default());
    {
        let mut map = state.run_id_to_ctl_tx.write().await;
        if let Some(old_ctl) = map.get(&run_id) {
            warn!(run_id = %run_id, "Duplicate run_id {}: shutting down old control handler", run_id);
            match old_ctl.tx.try_send(InternalMsg::Shutdown) {
                Ok(()) => {}
                Err(mpsc::error::TrySendError::Full(_)) => {
                    debug!(run_id = %run_id, "Old control handler channel full; cleanup by timeout");
                }
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    debug!(run_id = %run_id, "Old control handler already shut down");
                }
            }
        }
        map.insert(
            run_id.clone(),
            ControlTx {
                tx: internal_tx.clone(),
                client_addr: peer,
                login_time: std::time::Instant::now(),
                login_time_unix: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs() as i64)
                    .unwrap_or(0),
                pool_stats: pool_stats.clone(),
                user: login.user.clone().unwrap_or_default(),
            },
        );
    }

    // --- Send login response (plain, before encryption) ---
    {
        let additional_auth_scopes = reloadable.additional_auth_scopes.clone();
        let resp = FrpMessage::LoginResp(msg::LoginResp {
            version: Some(frp_core::VERSION.into()),
            run_id: Some(run_id.clone()),
            error: None,
            server_additional_auth_scopes: if additional_auth_scopes.is_empty() {
                None
            } else {
                Some(additional_auth_scopes)
            },
        });
        // Hex-dump the raw LoginResp V1 frame for Go compat debugging
        let type_byte = resp.v1_type_byte();
        let payload = serde_json::to_vec(&resp).unwrap_or_default();
        let frame_len = 9 + payload.len();
        info!(
            peer = ?peer, run_id = %run_id,
            type_byte = format_args!("{:#04x}", type_byte),
            payload_len = payload.len(),
            payload_text = %String::from_utf8_lossy(&payload),
            "LoginResp V1 frame: type={:#04x} len={} frame_total={} json={}",
            type_byte, payload.len(), frame_len,
            String::from_utf8_lossy(&payload),
        );
        if let Err(e) = write_ctl_msg(&mut stream, &resp, v2).await {
            warn!(peer = ?peer, error = %e, "Failed to send login response to {:?}: {}", peer, e);
            unregister_control(&state, &run_id, false).await;
            return Err(());
        }
        // Flush TLS stream to ensure LoginResp reaches KCP before we wrap in CipherStream
        if let Err(e) = stream.flush().await {
            warn!(peer = ?peer, error = %e, "Failed to flush after LoginResp: {}", e);
        }
        info!(peer = ?peer, run_id = %run_id, "LoginResp sent to {:?}, flushed", peer);

        // Emit WebSocket event for dashboard subscribers
        #[cfg(feature = "dashboard")]
        {
            let _ = state
                .event_tx
                .send(crate::event::ServerEvent::ClientConnected {
                    run_id: run_id.clone(),
                    client_addr: peer.map(|a| a.to_string()),
                });
        }
    }

    // --- Wrap in encryption (matches client after login) ---
    // V2 with AEAD crypto: wrap stream in AEAD here, AFTER LoginResp sent
    // (matching Go frp flow: ClientHello/ServerHello + Login/LoginResp in
    // plaintext, then AEAD for all subsequent messages).
    // V1 or V2 without AEAD: wrap in AES-128-CFB (CipherStream) for backward compat.
    let (reader, writer): (
        Box<dyn AsyncRead + Unpin + Send>,
        Box<dyn AsyncWrite + Unpin + Send>,
    ) = if let (true, Some(ctx)) = (v2, crypto_ctx.as_ref()) {
        let token = reloadable.auth_cfg.token.clone();
        match frp_core::crypto::derive_aead_control_keys(
            token.as_bytes(),
            ctx.algorithm,
            &ctx.transcript_hash,
        ) {
            Ok((read_key, write_key)) => {
                // derive_aead_control_keys returns (client_to_server, server_to_client).
                // Server reads from client → client_to_server (= read_key).
                // Server writes to client → server_to_client (= write_key).
                match frp_core::crypto::AeadStream::new(
                    Box::new(stream),
                    ctx.algorithm,
                    &read_key,
                    &write_key,
                ) {
                    Ok(aead) => {
                        let (r, w) = tokio::io::split(aead);
                        (Box::new(r), Box::new(w))
                    }
                    Err(e) => {
                        warn!(peer = ?peer, error = %e, "Failed to create AEAD stream for {:?}: {}", peer, e);
                        unregister_control(&state, &run_id, false).await;
                        return Err(());
                    }
                }
            }
            Err(e) => {
                warn!(peer = ?peer, error = %e, "Failed to derive AEAD keys for {:?}: {}", peer, e);
                unregister_control(&state, &run_id, false).await;
                return Err(());
            }
        }
    } else {
        // V1 or plain V2: ALWAYS wrap in AES-128-CFB after LoginResp.
        // Go frp v0.69.1 always encrypts the control connection after login
        // (both frps service.go:460 and frpc control_session.go:219 call
        // NewCryptoReadWriter unconditionally — no config flag gates it).
        // The use_encryption config flag controls proxy bridge (data plane)
        // encryption, not control plane encryption.
        info!(peer = ?peer, run_id = %run_id, "Wrapping control stream in CipherStream (AES-128-CFB)");
        let enc_key = encryption::derive_key(&reloadable.auth_cfg.token);
        let mut cipher = frp_core::cipher_stream::CipherStream::new(Box::new(stream), enc_key);

        // --- Send ReqWorkConn BEFORE tokio::io::split ---
        // Matching Go frps service.go:496 ctl.Start() which sends ReqWorkConn
        // immediately after LoginResp. This triggers our first encrypted write
        // (IV + ReqWorkConn), unblocking Go frpc's crypto.Reader.Read().
        {
            let max_pool = state.server_config_snapshot.max_pool_count;
            let raw_pool = login.pool_count.unwrap_or(1).max(1) as i64;
            let pool_count = if max_pool > 0 {
                raw_pool.min(max_pool)
            } else {
                raw_pool
            } as usize;
            info!(peer = ?peer, pool_count = pool_count, max_pool_count = max_pool, "Sending ReqWorkConn x{} through cipher (before split)", pool_count);
            for i in 0..pool_count {
                if let Err(e) = write_ctl_msg(
                    &mut cipher,
                    &FrpMessage::ReqWorkConn(msg::ReqWorkConn {}),
                    v2,
                )
                .await
                {
                    warn!(peer = ?peer, error = %e, i = i, "Failed to send ReqWorkConn #{}/{}: {}", i, pool_count, e);
                    unregister_control(&state, &run_id, false).await;
                    return Err(());
                }
            }
            if let Err(e) = cipher.flush().await {
                warn!(peer = ?peer, error = %e, "Failed to flush after ReqWorkConn: {}", e);
            }
            info!(peer = ?peer, pool_count = pool_count, "ReqWorkConn x{} sent (pre-split)", pool_count);
        }

        let (r, w) = tokio::io::split(cipher);
        (Box::new(r), Box::new(w))
    };

    info!(peer = ?peer, run_id = %run_id, "Control stream encrypted, entering message loop");

    // --- Per-client state ---
    let max_pool = state.server_config_snapshot.max_pool_count;
    let raw_pool = login.pool_count.unwrap_or(1).max(0) as i64;
    let capped_pool = if max_pool > 0 {
        raw_pool.min(max_pool)
    } else {
        raw_pool
    } as usize;
    let pool_cap = capped_pool + WORK_POOL_EXTRA;
    let work_pool: VecDeque<PoolEntry> = VecDeque::new();
    let pending_requests: VecDeque<PendingRequest> = VecDeque::new();
    let pending_udp: VecDeque<(String, Instant)> = VecDeque::new();
    let pending_nat_hole_sids: VecDeque<(String, String, Instant)> = VecDeque::new();
    // TCP/HTTP/STCP listener handles. UDP listeners are managed via the work-connection
    // mechanism (UdpNeedsWorkConn → ReqWorkConn → assign_udp_work_conn).
    let listener_handles: HashMap<String, tokio::task::JoinHandle<()>> = HashMap::new();
    let udp_sockets: HashMap<String, std::sync::Arc<tokio::net::UdpSocket>> = HashMap::new();
    // Reverse mapping: local_addr → proxy_name for routing UDPPacket responses
    let udp_local_to_proxy: HashMap<String, String> = HashMap::new();
    let shutting_down = false;
    let last_ping = Instant::now();
    // Ping interval: max 10s to stay well within Go frpc's heartbeat timeout
    let ping_interval = Duration::from_secs(10);
    let mut ping_tick = tokio::time::interval(ping_interval);
    // Defer first ping to ping_interval from now (Go frpc heartbeat timeout is 90s)
    ping_tick.reset();
    ping_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    Ok((
        ControlContext {
            state: state.clone(),
            pool_stats: pool_stats.clone(),
            reloadable,
            v2,
            run_id,
            pool_cap,
            internal_tx: internal_tx.clone(),
            peer,
        },
        ControlState {
            shutting_down,
            work_pool,
            pending_requests,
            pending_udp,
            pending_nat_hole_sids,
            listener_handles,
            udp_sockets,
            udp_local_to_proxy,
            last_ping,
        },
        internal_tx,
        internal_rx,
        reader,
        writer,
        incoming,
        ping_tick,
    ))
}
