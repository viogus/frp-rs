#[cfg(feature = "quic")]
use std::future::Future;
use std::sync::Arc;
#[cfg(feature = "quic")]
use std::time::Duration;

use tokio::io::AsyncReadExt;
#[cfg(any(feature = "tls", feature = "websocket"))]
use tracing::debug;
use tracing::{info, warn};

use frp_core::mux;
#[cfg(feature = "websocket")]
use frp_core::transport::{accept_websocket, accept_websocket_from_peeked};
use frp_core::transport::{IoStream, PreReadStream};
#[cfg(feature = "quic")]
use tokio_util::sync::CancellationToken;

#[cfg(feature = "quic")]
use crate::control;
#[cfg(any(feature = "tls", feature = "websocket"))]
use crate::lock::RwLockExt;
use crate::state::AppState;
#[cfg(feature = "tls")]
use crate::state::InternalMsg;

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
                // Every byte read is replayed below — dropping a short read
                // (1-42 bytes, e.g. a fragmented ClientHello) corrupted the
                // TLS handshake (audit fix). The SNI lookup itself is
                // naturally skipped for short data: extract_sni_from_client_hello
                // requires a full record (≥44 bytes).
                Ok(Ok(n)) => n,
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
                    let ctl_tx = state
                        .run_id_to_ctl_tx
                        .get(route.run_id.as_ref())
                        .map(|v| v.clone());
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
                                user_conn_permit: None,
                                // Local sender — no group selection was done.
                                group_selected: false,
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
                // Bounded by the same accept deadline as the TLS/WS accept
                // above: a client that completes the WS upgrade then goes
                // silent must not park the task/fd/permit forever (Go frp
                // connReadTimeout=10s covers this post-upgrade read too).
                let is_v2 = match tokio::time::timeout_at(
                    accept_deadline,
                    ws.read_exact(&mut magic),
                )
                .await
                {
                    Ok(Ok(_)) => is_v2_magic(&magic),
                    Ok(Err(e)) => {
                        warn!(addr = %addr, error = %e, "WS+TLS failed to read first 7 bytes: {}", e);
                        return;
                    }
                    Err(_elapsed) => {
                        warn!(addr = %addr, "WS+TLS timed out reading first 7 bytes from {}", addr);
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
                    match mux::server_mux(ws, &mux_cfg, accept_deadline).await {
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
        match mux::server_mux(io, &mux_cfg, accept_deadline).await {
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
        // Try V2 magic detection. Bounded by the accept deadline: a client
        // that finishes the TLS handshake then sends nothing must be
        // dropped instead of parking the task/fd/permit forever (Go frp
        // connReadTimeout=10s covers this read).
        let mut magic = [0u8; 7];
        let is_v2 = match tokio::time::timeout_at(accept_deadline, io.read_exact(&mut magic)).await
        {
            Ok(Ok(_)) => is_v2_magic(&magic),
            Ok(Err(_)) => false,
            Err(_elapsed) => {
                warn!(addr = %addr, "TLS: timed out reading first 7 bytes from {}", addr);
                return;
            }
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

            // Try V2 magic detection. Bounded by the accept deadline: a
            // client that completes the WS upgrade then goes silent must
            // not park the task/fd/permit forever (Go frp connReadTimeout
            // =10s covers this post-upgrade read).
            let mut magic = [0u8; 7];
            let is_v2 = match tokio::time::timeout_at(accept_deadline, ws.read_exact(&mut magic))
                .await
            {
                Ok(Ok(_)) => {
                    let matches = is_v2_magic(&magic);
                    debug!(
                        addr = %addr,
                        magic_hex = %magic.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(""),
                        is_v2 = matches,
                        "WS post-upgrade first 7 bytes"
                    );
                    matches
                }
                Ok(Err(_)) => false,
                Err(_elapsed) => {
                    warn!(addr = %addr, "WS: timed out reading first 7 bytes from {}", addr);
                    return;
                }
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
                        match mux::server_mux(tls_stream, &mux_cfg, accept_deadline).await {
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

                        // V2 chicken check on the decrypted TLS stream.
                        // Bounded by the accept deadline: a client that
                        // stops after the WS+TLS handshakes must not park
                        // the task/fd/permit forever.
                        let mut chicken = [0u8; 7];
                        let is_tls_v2 = match tokio::time::timeout_at(
                            accept_deadline,
                            io.read_exact(&mut chicken),
                        )
                        .await
                        {
                            Ok(Ok(_)) => is_v2_magic(&chicken),
                            Ok(Err(_)) => false,
                            Err(_elapsed) => {
                                warn!(addr = %addr, "WS+TLS: timed out reading first 7 bytes from {}", addr);
                                return;
                            }
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
                match mux::server_mux(stream, &mux_cfg, accept_deadline).await {
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
        match mux::server_mux(inner_stream, &mux_cfg, accept_deadline).await {
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
        match mux::server_mux(stream, &mux_cfg, accept_deadline).await {
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
                    crate::handlers::handle_work_conn_inner(ctl, nwc, state, false).await;
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
fn spawn_quic_drain(
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
                                            Ok(frp_core::msg::FrpMessage::NewWorkConn(nwc)) => Ok((wc, nwc, true)),
                                            Ok(other) => Err(frp_core::Error::Protocol(format!("unexpected QUIC V2 message {:?}", other.v2_type_id()).into())),
                                            Err(e) => Err(e),
                                        }
                                    } else {
                                        wc = frp_core::transport::IoStream::BufferedRead(wmagic.to_vec(), 0, Box::new(wc));
                                        match frp_core::protocol::read_msg_v1(&mut wc).await {
                                            Ok(frp_core::msg::FrpMessage::NewWorkConn(nwc)) => Ok((wc, nwc, false)),
                                            Ok(other) => Err(frp_core::Error::Protocol(format!("unexpected QUIC V1 message {:?}", other.v1_type_byte()).into())),
                                            Err(e) => Err(e),
                                        }
                                    }
                                }).await;
                                match request {
                                    Ok(Ok((wc, nwc, wv2))) => {
                                        drop(preauth_permit);
                                        let Ok(_authenticated_permit) =
                                            authenticated_limiter.acquire_owned().await
                                        else {
                                            return;
                                        };
                                        crate::handlers::handle_work_conn_inner(wc, nwc, s, wv2).await
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
