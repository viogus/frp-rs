//! The XTCP visitor hole-punch worker: the punch configuration the background
//! punch tasks share (`XtcpPunchConfig`) and the full punch sequence itself
//! (`do_hole_punch` — Go `makeNatHole`: PreCheck → STUN → NatHoleVisitor
//! exchange → MakeHole → session creation).
//!
//! Split out of `frp-client/src/visitor.rs` by the plan's P3 seam 2
//! (`docs/refactor-large-modules.md` P3, `visitor/xtcp.rs`) as a pure move:
//! both spans travel verbatim and their bodies are byte-for-byte identical to
//! the base revision. This module is a *child* of `visitor`, which is what lets
//! it keep reaching every parent-private item it needs (`TunnelSession`,
//! `clamp_hp_timeout`, and the parent's imports — `mpsc`, `oneshot`, `Duration`,
//! `debug`/`info`/`warn`, `CancellationToken`, ...) through `use super::*;`
//! with no visibility change on any parent item.
//!
//! Visibility: the two items this module *defines* (`XtcpPunchConfig` and
//! `do_hole_punch`) were private items of `visitor.rs` — reachable from
//! `visitor` and every descendant (`visitor::stcp`, the in-file test modules,
//! ...). An item declared `pub(super)` in the child `xtcp` module is reachable
//! from `visitor` and its descendants, which is exactly that same set, so the
//! effective visibility is unchanged; only the module-boundary spelling
//! differs. The parent's `use xtcp::{do_hole_punch, XtcpPunchConfig};` is a
//! private import, so nothing becomes nameable outside `visitor`.
//!
//! Coverage of the moved code, measured at the split (see the batch report for
//! the lane-by-lane evidence): the XTCP happy-path pair lanes punch a real
//! loopback hole through to session creation; the ghost-provider failure lane
//! drives the `pre_check failed` return; the unit test added with this move
//! covers the PreCheck closed/backlogged split and its cancel arm; the compat
//! `--xtcp-only` matrix drives both data planes against real frp peers.

use super::*;

/// Config for the background XTCP hole-punch task (Go `makeNatHole`).
/// Cloned once per listener; drives `do_hole_punch` in
/// `process_tunnel_start_events` / `keep_tunnel_open_worker`.
#[derive(Clone)]
pub(super) struct XtcpPunchConfig {
    pub(super) visitor_name: String,
    /// target server proxy name (`server_name`).
    pub(super) sn: String,
    /// secret key for auth + detect probing.
    pub(super) sk: String,
    pub(super) stun_server: String,
    /// XTCP P2P data plane protocol: "quic" (default, Go parity) or "kcp".
    pub(super) pp: String,
    /// disable assisted addresses.
    pub(super) daa: bool,
    /// Control-channel sender for NatHoleVisitor.
    pub(super) vtx: mpsc::Sender<crate::service::VisitorRequest>,
    /// Listener-teardown token. `do_hole_punch` races its awaits (pre_check,
    /// NatHoleResp, MakeHole) against this so a cancelled listener exits in
    /// milliseconds instead of lingering through the full punch sequence
    /// (pre_check 5s + NatHoleResp 15s + punch up to ~35s ≈ 50s).
    pub(super) cancel: CancellationToken,
    #[cfg(all(feature = "quic", feature = "kcp"))]
    /// Client-configured QUIC transport params for the tunnel session (Go
    /// `clientCfg.Transport.QUIC` — both the visitor and provider tunnel
    /// sessions read it).
    pub(super) quic_params: frp_core::quic::QuicTransportParams,
}

/// Full XTCP hole punch (Go `makeNatHole`): PreCheck → STUN → NatHoleVisitor
/// exchange → MakeHole → session creation. Returns the persistent session —
/// NO stream is opened here (streams are opened per user connection).
pub(super) async fn do_hole_punch(cfg: &XtcpPunchConfig) -> Result<TunnelSession, String> {
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
        match tokio::select! {
            _ = cfg.cancel.cancelled() => {
                return Err(format!(
                    "Visitor '{}': pre_check cancelled (listener shutting down)",
                    cfg.visitor_name
                ));
            }
            r = tokio::time::timeout(Duration::from_secs(5), reply_rx) => r,
        } {
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
    //    is reused for the punch + data plane. Both STUN awaits are raced
    //    against cfg.cancel so listener teardown aborts the STUN phase too
    //    (the socket is dropped with the future — the shutdown exits in
    //    milliseconds instead of lingering through the STUN timeouts).
    let stun_first = tokio::select! {
        _ = cfg.cancel.cancelled() => {
            return Err(format!(
                "Visitor '{}': STUN cancelled (listener shutting down)",
                cfg.visitor_name
            ));
        }
        r = frp_core::stun::stun_binding_with_details(&cfg.stun_server) => r,
    };
    let (stun_socket, mapped_addrs, assisted_addrs) = match stun_first {
        Ok((sock, result1)) => {
            let addr1 = result1.mapped_addr;
            debug!(visitor_name = %cfg.visitor_name, addr = %addr1, "Visitor '{}': STUN #1: {}", cfg.visitor_name, addr1);
            let mut addrs = vec![addr1];
            let second_target = result1.other_addr.as_deref().unwrap_or(&cfg.stun_server);
            let stun_second = tokio::select! {
                _ = cfg.cancel.cancelled() => {
                    return Err(format!(
                        "Visitor '{}': STUN #2 cancelled (listener shutting down)",
                        cfg.visitor_name
                    ));
                }
                r = frp_core::stun::stun_binding_on_socket(&sock, second_target) => r,
            };
            match stun_second {
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
    //    NatHoleResp (5s — Go frp client/xtcp.go waits 5s for the server's
    //    NatHoleResp; the server's own NAT_HOLE_TIMEOUT is 10s).
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
    let resp = match tokio::select! {
        _ = cfg.cancel.cancelled() => {
            return Err(format!(
                "Visitor '{}': NatHoleResp wait cancelled (listener shutting down)",
                cfg.visitor_name
            ));
        }
        r = tokio::time::timeout(Duration::from_secs(5), reply_rx) => r,
    } {
        Ok(Ok(Ok(resp))) => resp,
        Ok(Ok(Err(e))) => return Err(format!("NatHoleResp error from server: {e}")),
        Ok(Err(_)) => return Err("NatHoleResp channel closed (control loop dropped)".into()),
        Err(_elapsed) => return Err("NatHoleResp timed out after 5s".into()),
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
    // hole-punch timeout (Go parity); default to Go's MakeHole 5s (see
    // `clamp_hp_timeout` for the floor/cap semantics).
    let hp_timeout = resp
        .detect_behavior
        .as_ref()
        .map(|db| clamp_hp_timeout(db.read_timeout_ms))
        .unwrap_or(frp_core::xtcp_p2p::DEFAULT_HOLE_PUNCH_TIMEOUT_MS);
    let assisted = resp.assisted_addrs.clone().unwrap_or_default();
    let behavior = resp.detect_behavior.clone();
    // Data-plane protocol dispatch (Go parity, client/visitor/xtcp.go:57-60):
    // ONLY "kcp" selects the KCP+yamux data plane; anything else — "quic",
    // "", or an unknown value — selects QUIC. The config layer already
    // normalizes an explicitly empty protocol to "quic" (Go EmptyOr), so ""
    // here means a non-Rust peer or a hostile server echo.
    let session_fut = async {
        if cfg.pp.as_str() == "kcp" {
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
        } else {
            #[cfg(all(feature = "quic", feature = "kcp"))]
            {
                let s = frp_core::xtcp_session::xtcp_p2p_connect_quic_session_with_params(
                    socket,
                    &candidates,
                    &assisted,
                    behavior.as_ref(),
                    hp_timeout,
                    p2p_sid,
                    p2p_key.as_ref(),
                    false, // is_server = false (visitor is QUIC client)
                    cfg.quic_params.clone(),
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
        }
    };
    // Race the punch (up to hp_timeout ≈ 35s) against listener teardown so
    // the background task exits promptly instead of lingering.
    tokio::pin!(session_fut);
    tokio::select! {
        _ = cfg.cancel.cancelled() => {
            Err(format!(
                "Visitor '{}': hole punch cancelled (listener shutting down)",
                cfg.visitor_name
            ))
        }
        r = &mut session_fut => r,
    }
}
