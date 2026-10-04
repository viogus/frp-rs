#[cfg(any(feature = "websocket", feature = "kcp", feature = "quic"))]
use std::time::Duration;

#[cfg(any(feature = "websocket", feature = "kcp"))]
use tokio::io::AsyncReadExt;
#[cfg(feature = "websocket")]
use tokio::net::TcpListener;
#[cfg(feature = "websocket")]
use tracing::info;
#[cfg(any(feature = "websocket", feature = "kcp", feature = "quic"))]
use tracing::warn;

use frp_core::format_socket_addr;
#[cfg(feature = "websocket")]
use frp_core::mux;
#[cfg(feature = "websocket")]
use frp_core::transport::IoStream;

#[cfg(feature = "kcp")]
use crate::control;
#[cfg(all(feature = "tls", any(feature = "websocket", feature = "kcp")))]
use crate::lock::RwLockExt;

#[cfg(any(feature = "websocket", feature = "kcp", feature = "quic"))]
use super::spawn_boxed;
use super::Service;

impl Service {
    // `rate_limiter_enabled` is captured from `run`'s scope; passed explicitly.
    #[cfg(feature = "websocket")]
    pub(super) async fn start_websocket_listener(&self, rate_limiter_enabled: bool) {
        if self.cfg.websocket_port > 0 {
            let ws_addr = format_socket_addr(&self.cfg.bind_addr, self.cfg.websocket_port);
            let ws_addr2 = ws_addr.clone();
            let ws_state = self.state.clone();
            let (ws_bind_tx, ws_bind_rx) = tokio::sync::oneshot::channel::<()>();
            spawn_boxed(Box::pin(async move {
                match TcpListener::bind(&ws_addr2).await {
                    Ok(listener) => {
                        let _ = ws_bind_tx.send(());
                        info!(addr = %ws_addr2, "WebSocket listener ready on {}", ws_addr2);
                        loop {
                            tokio::select! {
                                result = listener.accept() => {
                                    match result {
                                        Ok((stream, addr)) => {
                                // Disable Nagle for low-latency small-message RTT
                                // (Go frp parity: control path uses NoDelay(true)).
                                frp_core::transport::set_nodelay(&stream);
                                if ws_state.tcp_keepalive > 0 {
                                    frp_core::transport::set_keepalive(
                                        &stream,
                                        ws_state.tcp_keepalive as u64,
                                    );
                                }
                                info!(addr = %addr, "New WebSocket connection from {}", addr);
                                let state = ws_state.clone();
                                let permit = state.conn_semaphore.as_ref()
                                    .and_then(|s| s.clone().try_acquire_owned().ok());
                                if permit.is_none() && state.conn_semaphore.is_some() {
                                    warn!(addr = %addr, "Max connections reached, rejecting WebSocket from {}", addr);
                                    continue;
                                }
                                let rate_wait = if rate_limiter_enabled {
                                    state.accept_rate_limiter.try_acquire().err()
                                } else {
                                    None
                                };
                                if let Some(wait) = rate_wait {
                                    warn!(addr = %addr, wait_ms = wait.as_millis(), "accept rate limit reached, delaying WebSocket {}ms", wait.as_millis());
                                    drop(permit);
                                    tokio::time::sleep(wait).await;
                                    continue;
                                }
                                spawn_boxed(Box::pin(async move {
                                    let _permit = permit;
                                    // Single absolute deadline covering the initial read phase
                                    // (V2 handshake + first frame) after the WS upgrade, matching
                                    // Go frp's single SetReadDeadline(10s) connReadTimeout
                                    // semantics. The upgrade itself is bounded by accept_websocket's
                                    // internal HANDSHAKE_TIMEOUT.
                                    let accept_deadline = tokio::time::Instant::now() + Duration::from_secs(10);
                                    // Post-upgrade reads (V2 magic, handshake, first frame,
                                    // V1 Login) get their own deadline: the 10s accept
                                    // deadline covers only the WS upgrade; a client that
                                    // upgrades then goes silent must not park the
                                    // task/fd/permit beyond 30s (slowloris), and a slow
                                    // pre-Login OIDC JWT fetch must not be cut off at 10s.
                                    let post_deadline = accept_deadline
                                        .max(tokio::time::Instant::now() + crate::handlers::POST_HANDSHAKE_READ_TIMEOUT);
                                    match frp_core::transport::accept_websocket(IoStream::Tcp(stream)).await {
                                        Ok(mut ws) => {
                                            info!(addr = %addr, "WebSocket upgrade completed for {}", addr);

                                            // Reject plain WebSocket when tls_only is set.
                                            // The main TCP accept loop enforces this for all
                                            // connection types, but the dedicated WS listener
                                            // on proxy_bind_addr bypasses that check.
                                            if state.tls_only {
                                                warn!(addr = %addr, "TLS-only mode: rejected WebSocket on dedicated WS port from {}", addr);
                                                return;
                                            }

                                            // Try V2 magic detection. Bounded by the 30s
                                            // post-handshake deadline: a client that completes
                                            // the WS upgrade then goes silent must not park the
                                            // task/fd/permit forever (Go frp connReadTimeout=10s
                                            // covers only the accept phase, not a slow pre-Login
                                            // OIDC token fetch).
                                            let mut magic = [0u8; 7];
                                            let is_v2 = match tokio::time::timeout_at(post_deadline, ws.read_exact(&mut magic)).await {
                                                Ok(Ok(_)) => crate::handlers::is_v2_magic(&magic),
                                                Ok(Err(_)) => false,
                                                Err(_elapsed) => {
                                                    tracing::warn!(addr = %addr, "WS (dedicated port): timed out reading first 7 bytes from {}", addr);
                                                    return;
                                                }
                                            };

                                            if magic[0] == 0x16 {
                                                #[cfg(feature = "tls")]
                                                {
                                                    let tls_acceptor = match state.tls_acceptor.read_ok().clone() {
                                                        Some(a) => a,
                                                        None => {
                                                            tracing::warn!(addr = %addr, "TLS ClientHello in WS frame but TLS not configured");
                                                            return;
                                                        }
                                                    };
                                                    let stream = frp_core::transport::IoStream::BufferedRead(
                                                        magic.to_vec(), 0, Box::new(ws),
                                                    );
                                                    let tls_stream = match tokio::time::timeout_at(accept_deadline, tls_acceptor.accept(stream)).await {
                                                        Ok(r) => match r {
                                                            Ok(s) => s,
                                                            Err(e) => {
                                                                tracing::warn!(addr = %addr, error = %e, "TLS handshake failed on WS from {}: {}", addr, e);
                                                                return;
                                                            }
                                                        },
                                                        Err(_elapsed) => {
                                                            tracing::warn!(addr = %addr, "TLS handshake timeout from {}", addr);
                                                            return;
                                                        }
                                                    };
                                                    tracing::info!(addr = %addr, "TLS-over-WebSocket connection from {}", addr);

                                                    // When tcp_mux is enabled, wrap TLS stream in yamux before
                                                    // reading the first message (matches Go frp — Go frpc uses
                                                    // tcp_mux by default over all transports).
                                                    if state.tcp_mux {
                                                        let mux_cfg = mux::TcpMuxConfig {
                                                            keepalive_interval: std::time::Duration::from_secs(
                                                                state.tcp_mux_keepalive.max(1) as u64
                                                            ),
                                                            idle_dead_timeout: state.tcp_mux_keepalive_timeout,

                                                        ..Default::default()
                                                        };
                                                        match mux::server_mux(tls_stream, &mux_cfg, accept_deadline).await {
                                                            Ok((control_stream, incoming)) => {
                                                                let mut io = IoStream::Yamux(control_stream);
                                                                tracing::info!(addr = ?addr, "Yamux over WS+TLS session established for {:?}", addr);

                                                                // V2 detection on yamux stream. Bounded by
                                                                // POST_HANDSHAKE_READ_TIMEOUT (30s): a peer that
                                                                // completes the yamux handshake then sends nothing
                                                                // must not park the task and conn_semaphore permit
                                                                // indefinitely (slowloris).
                                                                let mut magic = [0u8; 7];
                                                                let is_v2 = match tokio::time::timeout_at(post_deadline, io.read_exact(&mut magic)).await {
                                                                    Ok(Ok(_)) => crate::handlers::is_v2_magic(&magic),
                                                                    Ok(Err(_)) => false,
                                                                    Err(_elapsed) => {
                                                                        tracing::warn!(addr = ?addr, "WS+TLS+yamux: timed out reading first 7 bytes from {:?}", addr);
                                                                        return;
                                                                    }
                                                                };
                                                                if is_v2 {
                                                                    let (msg_payload, crypto_ctx) = match crate::handlers::v2_handshake_and_read(&mut io, Some(addr), post_deadline, "WS+TLS+yamux V2").await {
                                                                        Some(v) => v,
                                                                        None => return,
                                                                    };
                                                                    crate::handlers::dispatch_v2_message(io, msg_payload, state.clone(), addr, Some(incoming), None, crypto_ctx).await;
                                                                } else {
                                                                    // V1 over WS+TLS+yamux
                                                                    let io = frp_core::transport::IoStream::BufferedRead(
                                                                        magic.to_vec(), 0, Box::new(io),
                                                                    );
                                                                    crate::handlers::dispatch_v1_message(io, state.clone(), Some(addr), Some(incoming), None, post_deadline).await;
                                                                }
                                                            }
                                                            Err(e) => {
                                                                tracing::warn!(addr = ?addr, error = %e, "Failed to start yamux over WS+TLS for {:?}: {}", addr, e);
                                                            }
                                                        }
                                                    } else {
                                                        let mut io = IoStream::Tls(Box::new(tls_stream), addr);

                                                        let mut chicken = [0u8; 7];
                                                        // Bounded by POST_HANDSHAKE_READ_TIMEOUT (30s): a peer
                                                        // that completes WS+TLS then sends nothing must not
                                                        // park the task and conn_semaphore permit indefinitely
                                                        // (slowloris).
                                                        let is_tls_v2 = match tokio::time::timeout_at(post_deadline, io.read_exact(&mut chicken)).await {
                                                            Ok(Ok(_)) => crate::handlers::is_v2_magic(&chicken),
                                                            Ok(Err(_)) => false,
                                                            Err(_elapsed) => {
                                                                tracing::warn!(addr = ?addr, "WS+TLS: timed out reading first 7 bytes from {:?}", addr);
                                                                return;
                                                            }
                                                        };
                                                        if is_tls_v2 {
                                                            let (msg_payload, crypto_ctx) = match crate::handlers::v2_handshake_and_read(&mut io, Some(addr), post_deadline, "WS+TLS+V2").await {
                                                                Some(v) => v,
                                                                None => return,
                                                            };
                                                            crate::handlers::dispatch_v2_message(io, msg_payload, state.clone(), addr, None, None, crypto_ctx).await;
                                                        } else {
                                                            let io = frp_core::transport::IoStream::BufferedRead(
                                                                chicken.to_vec(), 0, Box::new(io),
                                                            );
                                                            crate::handlers::dispatch_v1_message(io, state.clone(), Some(addr), None, None, post_deadline).await;
                                                        }
                                                    }
                                                }
                                                #[cfg(not(feature = "tls"))]
                                                {
                                                    tracing::warn!(addr = %addr, "TLS ClientHello in WebSocket frame but TLS feature not enabled, dropping connection from {}", addr);
                                                }
                                            } else if state.tcp_mux {
                                                // Plain WebSocket + tcp_mux: Go frp v0.70.1 wraps the
                                                // upgraded stream in yamux before any FRP bytes, so
                                                // wrap here and run V2/V1 detection on the yamux stream.
                                                let stream = IoStream::BufferedRead(magic.to_vec(), 0, Box::new(ws));
                                                let mux_cfg = mux::TcpMuxConfig {
                                                    keepalive_interval: std::time::Duration::from_secs(
                                                        state.tcp_mux_keepalive.max(1) as u64
                                                    ),
                                                    idle_dead_timeout: state.tcp_mux_keepalive_timeout,

                                                ..Default::default()
                                                };
                                                match mux::server_mux(stream, &mux_cfg, accept_deadline).await {
                                                    Ok((control_stream, incoming)) => {
                                                        let mut io = IoStream::Yamux(control_stream);
                                                        tracing::info!(addr = ?addr, "Yamux over WebSocket session established for {:?}", addr);

                                                        // V2 detection on yamux stream. Bounded by
                                                        // POST_HANDSHAKE_READ_TIMEOUT (30s): a peer that
                                                        // completes the yamux handshake then sends nothing
                                                        // must not park the task and conn_semaphore permit
                                                        // indefinitely (slowloris).
                                                        let mut mux_magic = [0u8; 7];
                                                        let is_v2 = match tokio::time::timeout_at(post_deadline, io.read_exact(&mut mux_magic)).await {
                                                            Ok(Ok(_)) => crate::handlers::is_v2_magic(&mux_magic),
                                                            Ok(Err(_)) => false,
                                                            Err(_elapsed) => {
                                                                tracing::warn!(addr = ?addr, "WS+yamux: timed out reading first 7 bytes from {:?}", addr);
                                                                return;
                                                            }
                                                        };
                                                        if is_v2 {
                                                            let (msg_payload, crypto_ctx) = match crate::handlers::v2_handshake_and_read(&mut io, Some(addr), post_deadline, "WS+yamux V2").await {
                                                                Some(v) => v,
                                                                None => return,
                                                            };
                                                            crate::handlers::dispatch_v2_message(io, msg_payload, state.clone(), addr, Some(incoming), None, crypto_ctx).await;
                                                        } else {
                                                            // V1 over plain WS+yamux
                                                            let io = IoStream::BufferedRead(
                                                                mux_magic.to_vec(), 0, Box::new(io),
                                                            );
                                                            crate::handlers::dispatch_v1_message(io, state.clone(), Some(addr), Some(incoming), None, post_deadline).await;
                                                        }
                                                    }
                                                    Err(e) => {
                                                        tracing::warn!(addr = ?addr, error = %e, "Failed to start yamux over WebSocket for {:?}: {}", addr, e);
                                                    }
                                                }
                                            } else if is_v2 {
                                                // V2 path: ClientHello/ServerHello handshake
                                                let (msg_payload, crypto_ctx) = match crate::handlers::v2_handshake_and_read(&mut ws, Some(addr), post_deadline, "WS V2").await {
                                                    Some(v) => v,
                                                    None => return,
                                                };
                                                crate::handlers::dispatch_v2_message(ws, msg_payload, state.clone(), addr, None, None, crypto_ctx).await;
                                            } else {
                                                // V1 fallback: replay consumed 7 bytes
                                                let ws = frp_core::transport::IoStream::BufferedRead(magic.to_vec(), 0, Box::new(ws));
                                                crate::handlers::dispatch_v1_message(ws, state.clone(), Some(addr), None, None, post_deadline).await;
                                            }
                                        }
                                        Err(e) => {
                                            warn!(addr = %addr, error = %e, "WebSocket upgrade failed for {}: {}", addr, e);
                                        }
                                    }
                                }));
                                        }
                                        Err(e) => {
                                            tracing::warn!(error = %e, "WS accept error, retrying...");
                                            tokio::time::sleep(Duration::from_millis(100)).await;
                                            continue;
                                        }
                                    }
                                }
                                _ = ws_state.shutdown_token.cancelled() => break,
                            }
                        }
                    }
                    Err(e) => {
                        tracing::error!(addr = %ws_addr2, error = %e, "WebSocket listener bind failed: {}", e);
                    }
                }
            }));
            match ws_bind_rx.await {
                Ok(_) => info!(addr = %ws_addr, "WebSocket listener started on {}", ws_addr),
                Err(_) => tracing::error!(addr = %ws_addr, "WebSocket listener failed to start"),
            }
        }
    }

    // `rate_limiter_enabled` is captured from `run`'s scope; passed explicitly.
    #[cfg(feature = "kcp")]
    pub(super) async fn start_kcp_listener(&self, rate_limiter_enabled: bool) {
        if self.cfg.kcp_bind_port > 0 {
            let kcp_state = self.state.clone();
            let kcp_addr = format_socket_addr(&self.cfg.bind_addr, self.cfg.kcp_bind_port);
            let kcp_addr2 = kcp_addr.clone();
            let (kcp_bind_tx, kcp_bind_rx) = tokio::sync::oneshot::channel::<()>();
            spawn_boxed(Box::pin(async move {
                let mut listener = match frp_core::kcp::KcpListener::bind(
                    &kcp_addr2,
                    frp_core::kcp::default_kcp_config(),
                )
                .await
                {
                    Ok(l) => {
                        let _ = kcp_bind_tx.send(());
                        l
                    }
                    Err(e) => {
                        tracing::error!(error = %e, "KCP listener bind failed: {}", e);
                        return;
                    }
                };
                tracing::info!(addr = %kcp_addr2, "KCP listener started on {}", kcp_addr2);
                'kcp_accept: loop {
                    tokio::select! {
                            result = listener.accept() => {
                                match result {
                                    Ok(stream) => {
                                        tracing::debug!("KCP ACCEPT: got stream, spawning handler");
                                        let state = kcp_state.clone();
                                        let addr = stream.peer_addr;
                                        let permit = state.conn_semaphore.as_ref()
                                            .and_then(|s| s.clone().try_acquire_owned().ok());
                                        if permit.is_none() && state.conn_semaphore.is_some() {
                                            warn!(addr = %addr, "Max connections reached, rejecting KCP from {}", addr);
                                            continue;
                                        }
                                        let rate_wait = if rate_limiter_enabled {
                                            state.accept_rate_limiter.try_acquire().err()
                                        } else {
                                            None
                                        };
                                        if let Some(wait) = rate_wait {
                                            warn!(addr = %addr, wait_ms = wait.as_millis(), "accept rate limit reached, delaying KCP {}ms", wait.as_millis());
                                            drop(permit);
                                            tokio::time::sleep(wait).await;
                                            continue;
                                        }
                                        spawn_boxed(Box::pin(async move {
                                            let _permit = permit;
                                            // Absolute deadline for the post-handshake read
                                            // phase (first yamux stream), matching Go frp's
                                            // connReadTimeout=10s and the main TCP accept loop.
                                            // Bounds the server_mux first-stream wait below — a
                                            // peer that sends the magic bytes but no yamux frame
                                            // would otherwise park the task and conn_semaphore
                                            // permit indefinitely (slowloris).
                                            let peer = stream.peer_addr;
                                    let conv = stream.conv();
                                    tracing::debug!(peer = %peer, conv = conv, "KCP HANDLER: spawned");
                                    tracing::info!(peer = %peer, conv = conv, "KCP handler: spawned for {} conv={}", peer, conv);
                                    let mut ctl = frp_core::transport::IoStream::Kcp(stream);

                                    // Try V2 magic detection with a 30s timeout.
                                    // Without a timeout, an attacker sending only
                                    // KCP ACKs (no app data) can hold a session
                                    // slot indefinitely, exhausting the 1024-slot
                                    // session table. 30s = same as unaccepted timeout.
                                    const KCP_AUTH_TIMEOUT: Duration = Duration::from_secs(30);
                                    let mut magic = [0u8; 7];
                                    let is_v2 = match tokio::time::timeout(
                                        KCP_AUTH_TIMEOUT,
                                        ctl.read_exact(&mut magic),
                                    )
                                    .await
                                    {
                                        Ok(Ok(_)) => crate::handlers::is_v2_magic(&magic),
                                        Ok(Err(e)) => {
                                            tracing::debug!(peer = %peer, error = %e, "KCP: failed to read initial 7 bytes from {}", peer);
                                            false
                                        }
                                        Err(_elapsed) => {
                                            tracing::warn!(peer = %peer, conv = conv, "KCP: auth timeout ({}s) — no data from peer", KCP_AUTH_TIMEOUT.as_secs());
                                            return;
                                        }
                                    };
                                    tracing::info!(peer = %peer, first_byte = ?format_args!("0x{:02x}", magic[0]), is_v2, "KCP: new session from {} (first_byte=0x{:02x}, is_v2={})", peer, magic[0], is_v2);

                                    // Handshake deadlines are anchored AFTER the 30s magic read,
                                    // not at handler start: a slow KCP peer spending T seconds
                                    // on the magic read must not erode the post-handshake budget
                                    // — the pre-Login OIDC JWT fetch via proxyURL needs the full
                                    // 30s (QUIC anchors the same way).
                                    let accept_deadline = tokio::time::Instant::now() + Duration::from_secs(10);
                                    // Post-handshake reads (V2 handshake, first frame, V1 Login)
                                    // get their own deadline: the 10s accept deadline covers only
                                    // yamux/TLS handshakes; a slow pre-Login OIDC JWT fetch must
                                    // not be cut off at 10s, nor left unbounded.
                                    let post_deadline = accept_deadline
                                        .max(tokio::time::Instant::now() + crate::handlers::POST_HANDSHAKE_READ_TIMEOUT);

                                    if is_v2 {
                                        // V2 path: ClientHello/ServerHello + first frame,
                                        // bounded by post_deadline (30s) like TCP/WS — the
                                        // per-read 30s V2_HANDSHAKE_TIMEOUT would stack with
                                        // KCP_AUTH_TIMEOUT to ~90s on this path.
                                        let (msg_payload, crypto_ctx) = match crate::handlers::v2_handshake_and_read(&mut ctl, Some(peer), post_deadline, "KCP V2").await {
                                            Some((p, crypto)) => (p, crypto),
                                            None => return,
                                        };
                                        crate::handlers::dispatch_v2_message_inner(ctl, msg_payload, state, peer, None, None, crypto_ctx, None, false).await; // KCP: spoofable UDP source — login-throttle exempt (E1/S1)
                                    } else {
                                        let first_byte = magic[0];

                                        #[cfg(feature = "tls")]
                                        let is_tls = state.tls_acceptor.read_ok().is_some()
                                            && (first_byte == 0x16 || first_byte == frp_core::transport::FRP_TLS_HEAD_BYTE);
                                        #[cfg(not(feature = "tls"))]
                                        let is_tls = false;

                                        if is_tls {
                                            #[cfg(feature = "tls")]
                                            {
                                                // TLS over KCP: Go frpc performs TLS handshake inside the KCP
                                                // stream before sending any FRP protocol data. Strip the
                                                // Go frp 0x17 prefix byte if present, replay remaining
                                                // pre-read bytes, then do TLS accept.
                                                let tls_pre_read = if first_byte == frp_core::transport::FRP_TLS_HEAD_BYTE {
                                                    magic[1..].to_vec()
                                                } else {
                                                    magic.to_vec()
                                                };
                                                let pre_read_len = tls_pre_read.len();
                                                let ctl = frp_core::transport::IoStream::BufferedRead(
                                                    tls_pre_read, 0, Box::new(ctl),
                                                );
                                                let acceptor = match state.tls_acceptor.read_ok().clone() {
                                                    Some(a) => a,
                                                    None => {
                                                        tracing::warn!("KCP TLS connection but no TLS acceptor configured");
                                                        return;
                                                    }
                                                };
                                                tracing::info!(peer = %peer, pre_read_len, "KCP TLS: starting TLS accept ({} bytes pre-read)", pre_read_len);
                                                let tls_stream = match tokio::time::timeout(
                                                    std::time::Duration::from_secs(10),
                                                    acceptor.accept(ctl),
                                                ).await {
                                                    Ok(Ok(s)) => {
                                                        tracing::info!(peer = %peer, "KCP TLS handshake succeeded from {}", peer);
                                                        s
                                                    }
                                                    Ok(Err(e)) => {
                                                        tracing::warn!(error = %e, "KCP TLS handshake failed: {}", e);
                                                        return;
                                                    }
                                                    Err(_elapsed) => {
                                                        tracing::warn!(peer = %peer, "KCP TLS handshake timed out after 10s");
                                                        return;
                                                    }
                                                };
                                                let tls_io = frp_core::transport::IoStream::Tls(Box::new(tls_stream), peer);

                                                // After TLS: if tcpMux, wrap in yamux before V2/V1
                                                // (matching Go frps: TLS accept → yamux → V2/V1 on yamux stream).
                                                if state.tcp_mux {
                                                    let mux_cfg = frp_core::mux::TcpMuxConfig {
                                                        keepalive_interval: std::time::Duration::from_secs(
                                                            state.tcp_mux_keepalive.max(1) as u64
                                                        ),
                                                        idle_dead_timeout: state.tcp_mux_keepalive_timeout,

                                                    ..Default::default()
                                                    };
                                                    match frp_core::mux::server_mux(tls_io, &mux_cfg, accept_deadline).await {
                                                        Ok((control_stream, incoming)) => {
                                                            let mut io = frp_core::transport::IoStream::Yamux(control_stream);
                                                            tracing::info!(peer = %peer, "KCP TLS+yamux session established for {}", peer);

                                                            // V2 magic read on the yamux stream. Bounded by
                                                            // POST_HANDSHAKE_READ_TIMEOUT (30s): a peer that
                                                            // completes the yamux handshake then sends nothing
                                                            // must not park the task and conn_semaphore permit
                                                            // indefinitely (slowloris).
                                                            let mut yamux_magic = [0u8; 7];
                                                            let is_v2 = match tokio::time::timeout_at(post_deadline, io.read_exact(&mut yamux_magic)).await {
                                                                Ok(Ok(_)) => crate::handlers::is_v2_magic(&yamux_magic),
                                                                Ok(Err(_)) => false,
                                                                Err(_elapsed) => {
                                                                    tracing::warn!(peer = %peer, "KCP TLS+yamux: timed out reading first 7 bytes from {}", peer);
                                                                    return;
                                                                }
                                                            };
                                                            if is_v2 {
                                                                let (msg_payload, crypto_ctx) = match crate::handlers::v2_handshake_and_read(&mut io, Some(peer), post_deadline, "KCP TLS+yamux V2").await {
                                                                    Some((p, crypto)) => (p, crypto),
                                                                    None => return,
                                                                };
                                                                crate::handlers::dispatch_v2_message_inner(io, msg_payload, state, peer, Some(incoming), None, crypto_ctx, None, true).await; // KCP+TLS: completed rustls handshake = non-spoofable source — throttle keyed
                                                            } else {
                                                                let mut io = frp_core::transport::IoStream::BufferedRead(yamux_magic.to_vec(), 0, Box::new(io));
                                                                match tokio::time::timeout_at(post_deadline, frp_core::protocol::read_msg_v1(&mut io)).await {
                                                                    Ok(Ok(frp_core::msg::FrpMessage::Login(login))) => {
                                                                        tracing::info!(peer = %peer, "KCP TLS+yamux Login from {}", peer);
                                                                        control::handle_control_inner(io, *login, state, Some(peer), Some(incoming), false, None, false, None, true).await; // KCP+TLS: completed rustls handshake = non-spoofable source — throttle keyed
                                                                    }
                                                                    Ok(Ok(frp_core::msg::FrpMessage::NewWorkConn(nwc))) => {
                                                                        tracing::info!(peer = %peer, run_id = ?nwc.run_id, "KCP TLS+yamux NewWorkConn from {}", peer);
                                                                        crate::handlers::handle_work_conn_inner(io, nwc, state, false).await;
                                                                    }
                                                                    Ok(Ok(frp_core::msg::FrpMessage::NewVisitorConn(nvc))) => {
                                                                        tracing::info!(peer = %peer, proxy_name = %nvc.proxy_name, "KCP TLS+yamux NewVisitorConn from {}", peer);
                                                                        crate::handlers::handle_visitor_conn_inner(io, nvc, state, false, Some(peer)).await;
                                                                    }
                                                                    Ok(Ok(frp_core::msg::FrpMessage::NatHoleVisitor(nhv))) => {
                                                                        tracing::info!(peer = %peer, "KCP TLS+yamux NatHoleVisitor from {}", peer);
                                                                        crate::handlers::handle_nat_hole_visitor(io, nhv, state, None, false).await;
                                                                    }
                                                                    Ok(Ok(other)) => {
                                                                        tracing::warn!(peer = %peer, other = ?other.v1_type_byte(), "Unexpected KCP TLS+yamux message: {:?}", other.v1_type_byte());
                                                                    }
                                                                    Err(_elapsed) => {
                                                                        // No `return`: the io drops at block end (closing the slow peer's
                                                                        // connection); the accept loop must keep accepting other peers.
                                                                        tracing::warn!(peer = %peer, "KCP: timed out waiting for first V1 message (post-handshake deadline 30s) from {}", peer);
                                                                        }
                                                                    Ok(Err(e)) => {
                                                                        tracing::warn!(peer = %peer, error = %e, "KCP TLS+yamux read error: {}", e);
                                                                    }
                                                                }
                                                            }
                                                        }
                                                        Err(e) => {
                                                            tracing::warn!(peer = %peer, error = %e, "KCP TLS+yamux server error: {}", e);
                                                        }
                                                    }
                                                    return;
                                                }

                                                // tcpMux disabled: V2/V1 directly on TLS-decrypted stream
                                                let mut ctl = tls_io;

                                                // After TLS: detect V2 then V1 on the decrypted stream.
                                                // Bounded by POST_HANDSHAKE_READ_TIMEOUT (30s): a peer
                                                // that completes the KCP TLS handshake then sends nothing
                                                // must not park the task and conn_semaphore permit
                                                // indefinitely (slowloris).
                                                let mut tls_magic = [0u8; 7];
                                                let is_v2 = match tokio::time::timeout_at(post_deadline, ctl.read_exact(&mut tls_magic)).await {
                                                    Ok(Ok(_)) => crate::handlers::is_v2_magic(&tls_magic),
                                                    Ok(Err(_)) => false,
                                                    Err(_elapsed) => {
                                                        tracing::warn!(peer = %peer, "KCP TLS: timed out reading first 7 bytes from {}", peer);
                                                        return;
                                                    }
                                                };
                                                if is_v2 {
                                                    let (msg_payload, crypto_ctx) = match crate::handlers::v2_handshake_and_read(&mut ctl, Some(peer), post_deadline, "KCP TLS V2").await {
                                                        Some((p, crypto)) => (p, crypto),
                                                        None => return,
                                                    };
                                                    crate::handlers::dispatch_v2_message_inner(ctl, msg_payload, state, peer, None, None, crypto_ctx, None, true).await; // KCP+TLS: completed rustls handshake = non-spoofable source — throttle keyed
                                                } else {
                                                    // After KCP TLS handshake, Go frpc's decrypted stream
                                                    // starts with non-FRP bytes (TLS Finished verify_data
                                                    // or other post-handshake data that rustls doesn't
                                                    // fully consume). The actual V1 Login/NewWorkConn
                                                    // message follows in subsequent TLS records.
                                                    //
                                                    // Accumulate data across TLS records until we find
                                                    // a valid V1 header or reach 2 KiB without one.
                                                    let mut scan_data = tls_magic.to_vec();
                                                    let find_v1 = |data: &[u8]| -> Option<usize> {
                                                        data.windows(9).position(|w| {
                                                            crate::handlers::is_v1_type_byte(w[0])
                                                                && u64::from_be_bytes([
                                                                    w[1], w[2], w[3], w[4],
                                                                    w[5], w[6], w[7], w[8],
                                                                ]) <= frp_core::protocol::V1_MAX_MSG_LENGTH as u64
                                                        })
                                                    };

                                                    // Keep reading TLS records until we find a V1 header
                                                    // or run out of data. Each read() returns one TLS
                                                    // record's plaintext; Go frpc sends a small prefix
                                                    // record (~12 bytes) then the Login record (~200 bytes).
                                                    //
                                                    // All reads share the ONE absolute post-handshake
                                                    // deadline anchored before the loop: a peer that
                                                    // drips 1 byte per TLS record must not get a fresh
                                                    // 30s per read and hold the task + conn_semaphore
                                                    // permit for ~17h (slowloris).
                                                    let v1_offset = loop {
                                                        if let Some(off) = find_v1(&scan_data) {
                                                            break Some(off);
                                                        }
                                                        if scan_data.len() > 2048 {
                                                            break None;
                                                        }
                                                        let mut buf = vec![0u8; 1024];
                                                        match tokio::time::timeout_at(post_deadline, ctl.read(&mut buf)).await {
                                                            Ok(Ok(n)) if n > 0 => {
                                                                scan_data.extend_from_slice(&buf[..n]);
                                                            }
                                                            Ok(Ok(_)) => break None, // EOF
                                                            Ok(Err(e)) => {
                                                                tracing::debug!(peer = %peer, error = %e, "KCP TLS: read error during scan");
                                                                break None;
                                                            }
                                                            Err(_elapsed) => {
                                                                tracing::warn!(peer = %peer, "KCP TLS: timed out reading during V1 scan from {}", peer);
                                                                return;
                                                            }
                                                        }
                                                    };

                                                    let scan_len = scan_data.len();
                                                    match v1_offset {
                                                        Some(off) => {
                                                            tracing::debug!(peer = %peer, offset = off, scan_len, "KCP TLS: found V1 message at offset {} ({} bytes scanned)", off, scan_len);
                                                            let mut ctl = frp_core::transport::IoStream::BufferedRead(
                                                                scan_data[off..].to_vec(), 0, Box::new(ctl),
                                                            );
                                                            match tokio::time::timeout_at(post_deadline, frp_core::protocol::read_msg_v1(&mut ctl)).await {
                                                                Ok(Ok(frp_core::msg::FrpMessage::Login(login))) => {
                                                                    tracing::info!(peer = %peer, "KCP TLS Login from {}", peer);
                                                                    control::handle_control_inner(ctl, *login, state, Some(peer), None, false, None, false, None, true).await; // KCP+TLS: completed rustls handshake = non-spoofable source — throttle keyed
                                                                }
                                                                Ok(Ok(frp_core::msg::FrpMessage::NewWorkConn(nwc))) => {
                                                                    tracing::info!(peer = %peer, run_id = ?nwc.run_id, "KCP TLS NewWorkConn from {}", peer);
                                                                    crate::handlers::handle_work_conn_inner(ctl, nwc, state, false).await;
                                                                }
                                                                Ok(Ok(frp_core::msg::FrpMessage::NewVisitorConn(nvc))) => {
                                                                    tracing::info!(peer = %peer, proxy_name = %nvc.proxy_name, "KCP TLS NewVisitorConn from {}", peer);
                                                                    crate::handlers::handle_visitor_conn_inner(ctl, nvc, state, false, Some(peer)).await;
                                                                }
                                                                Ok(Ok(frp_core::msg::FrpMessage::NatHoleVisitor(nhv))) => {
                                                                    tracing::info!(peer = %peer, "KCP TLS NatHoleVisitor from {}", peer);
                                                                    crate::handlers::handle_nat_hole_visitor(ctl, nhv, state, None, false).await;
                                                                }
                                                                Ok(Ok(other)) => {
                                                                    tracing::warn!(other = ?other.v1_type_byte(), "Unexpected KCP TLS message: {:?}", other.v1_type_byte());
                                                                }
                                                                Err(_elapsed) => {
                                                                    // No `return`: the io drops at block end (closing the slow peer's
                                                                    // connection); the accept loop must keep accepting other peers.
                                                                    tracing::warn!(peer = %peer, "KCP: timed out waiting for first V1 message (post-handshake deadline 30s) from {}", peer);
                                                                    }
                                                                Ok(Err(e)) => {
                                                                    tracing::warn!(error = %e, "KCP TLS read error: {}", e);
                                                                }
                                                            }
                                                        }
                                                        None => {
                                                            tracing::debug!(peer = %peer, scan_len, scan_hex = %frp_core::hex_encode(&scan_data[..scan_len.min(128)]), "KCP TLS: no valid V1 header found in {} bytes", scan_len);
                                                        }
                                                    }
                                                }
                                            }
                                            #[cfg(not(feature = "tls"))]
                                            {
                                                tracing::warn!("KCP TLS connection requires TLS feature (disabled in this build)");
                                            }
                                        } else {
                                            // Reject plain KCP when tls_only is set
                                            if state.tls_only {
                                                warn!(peer = %peer, "TLS-only mode: rejected plain KCP from {}", peer);
                                                return;
                                            }
                                            // tcp_mux enabled: Go frpc and frp-rs wrap KCP conns in
                                            // yamux before sending Login (matching Go frps flow).
                                            // If the first byte is a V1 type byte (e.g. 0x6f Login),
                                            // this is a legacy Rust frpc or custom client sending raw
                                            // V1; keep handling it directly so those clients work.
                                            if state.tcp_mux && !crate::handlers::is_v1_type_byte(first_byte) {
                                            // Replay the 7 bytes consumed by magic check —
                                            // they are part of the yamux SYN header.
                                            let stream = frp_core::transport::IoStream::BufferedRead(magic.to_vec(), 0, Box::new(ctl));
                                            let mux_cfg = frp_core::mux::TcpMuxConfig {
                                                keepalive_interval: std::time::Duration::from_secs(
                                                    state.tcp_mux_keepalive.max(1) as u64
                                                ),
                                                idle_dead_timeout: state.tcp_mux_keepalive_timeout,

                                            ..Default::default()
                                            };
                                            match frp_core::mux::server_mux(stream, &mux_cfg, accept_deadline).await {
                                                Ok((control_stream, incoming)) => {
                                                    let mut io = frp_core::transport::IoStream::Yamux(control_stream);
                                                    tracing::info!(peer = %peer, "KCP yamux session established for {}", peer);

                                                    // V2 magic detection on yamux stream. Bounded by
                                                    // POST_HANDSHAKE_READ_TIMEOUT (30s): a peer that
                                                    // completes the yamux handshake then sends nothing
                                                    // must not park the task and conn_semaphore permit
                                                    // indefinitely (slowloris).
                                                    let mut yamux_magic = [0u8; 7];
                                                    let is_v2 = match tokio::time::timeout_at(post_deadline, io.read_exact(&mut yamux_magic)).await {
                                                        Ok(Ok(_)) => crate::handlers::is_v2_magic(&yamux_magic),
                                                        Ok(Err(_)) => false,
                                                        Err(_elapsed) => {
                                                            tracing::warn!(peer = %peer, "KCP yamux: timed out reading first 7 bytes from {}", peer);
                                                            return;
                                                        }
                                                    };
                                                    if is_v2 {
                                                        let (msg_payload, crypto_ctx) = match crate::handlers::v2_handshake_and_read(&mut io, Some(peer), post_deadline, "KCP yamux V2").await {
                                                            Some((p, crypto)) => (p, crypto),
                                                            None => return,
                                                        };
                                                        crate::handlers::dispatch_v2_message_inner(io, msg_payload, state, peer, Some(incoming), None, crypto_ctx, None, false).await; // KCP: spoofable UDP source — login-throttle exempt (E1/S1)
                                                    } else {
                                                        // V1 on yamux: replay consumed bytes, read Login/NewWorkConn
                                                        let mut io = frp_core::transport::IoStream::BufferedRead(yamux_magic.to_vec(), 0, Box::new(io));
                                                        match tokio::time::timeout_at(post_deadline, frp_core::protocol::read_msg_v1(&mut io)).await {
                                                            Ok(Ok(frp_core::msg::FrpMessage::Login(login))) => {
                                                                tracing::info!(peer = %peer, "KCP yamux Login from {}", peer);
                                                                control::handle_control_inner(io, *login, state, Some(peer), Some(incoming), false, None, false, None, false).await; // KCP: spoofable UDP source — login-throttle exempt (E1/S1)
                                                            }
                                                            Ok(Ok(frp_core::msg::FrpMessage::NewWorkConn(nwc))) => {
                                                                tracing::info!(peer = %peer, run_id = ?nwc.run_id, "KCP yamux NewWorkConn from {}", peer);
                                                                crate::handlers::handle_work_conn_inner(io, nwc, state, false).await;
                                                            }
                                                            Ok(Ok(frp_core::msg::FrpMessage::NewVisitorConn(nvc))) => {
                                                                tracing::info!(peer = %peer, proxy_name = %nvc.proxy_name, "KCP yamux NewVisitorConn from {}", peer);
                                                                crate::handlers::handle_visitor_conn_inner(io, nvc, state, false, Some(peer)).await;
                                                            }
                                                            Ok(Ok(frp_core::msg::FrpMessage::NatHoleVisitor(nhv))) => {
                                                                tracing::info!(peer = %peer, "KCP yamux NatHoleVisitor from {}", peer);
                                                                crate::handlers::handle_nat_hole_visitor(io, nhv, state, None, false).await;
                                                            }
                                                            Ok(Ok(other)) => {
                                                                tracing::warn!(peer = %peer, other = ?other.v1_type_byte(), "Unexpected KCP yamux message: {:?}", other.v1_type_byte());
                                                            }
                                                            Err(_elapsed) => {
                                                                // No `return`: the io drops at block end (closing the slow peer's
                                                                // connection); the accept loop must keep accepting other peers.
                                                                tracing::warn!(peer = %peer, "KCP: timed out waiting for first V1 message (post-handshake deadline 30s) from {}", peer);
                                                                }
                                                            Ok(Err(e)) => {
                                                                tracing::warn!(peer = %peer, error = %e, "KCP yamux read error: {}", e);
                                                            }
                                                        }
                                                    }
                                                }
                                                Err(e) => {
                                                    tracing::warn!(peer = %peer, error = %e, "KCP yamux server error: {}", e);
                                                }
                                            }
                                        } else {
                                            // No tcp_mux: replay consumed 7 bytes, read V1 frame directly
                                            let mut ctl = frp_core::transport::IoStream::BufferedRead(magic.to_vec(), 0, Box::new(ctl));
                                            match tokio::time::timeout_at(post_deadline, frp_core::protocol::read_msg_v1(&mut ctl)).await {
                                                Ok(Ok(frp_core::msg::FrpMessage::Login(login))) => {
                                                                    tracing::info!(peer = %peer, "KCP Login from {}", peer);
                                                                    control::handle_control_inner(ctl, *login, state, Some(peer), None, false, None, false, None, false).await; // KCP: spoofable UDP source — login-throttle exempt (E1/S1)
                                                }
                                                Ok(Ok(frp_core::msg::FrpMessage::NewWorkConn(nwc))) => {
                                                    tracing::info!(peer = %peer, run_id = ?nwc.run_id, "KCP NewWorkConn from {}", peer);
                                                    crate::handlers::handle_work_conn_inner(ctl, nwc, state, false).await;
                                                }
                                                Ok(Ok(frp_core::msg::FrpMessage::NewVisitorConn(nvc))) => {
                                                    tracing::info!(peer = %peer, proxy_name = %nvc.proxy_name, "KCP NewVisitorConn from {}", peer);
                                                    crate::handlers::handle_visitor_conn_inner(ctl, nvc, state, false, Some(peer)).await;
                                                }
                                                Ok(Ok(frp_core::msg::FrpMessage::NatHoleVisitor(nhv))) => {
                                                    tracing::info!(peer = %peer, "KCP NatHoleVisitor from {}", peer);
                                                    crate::handlers::handle_nat_hole_visitor(ctl, nhv, state, None, false).await;
                                                }
                                                Ok(Ok(other)) => {
                                                    tracing::warn!(other = ?other.v1_type_byte(), "Unexpected KCP message: {:?}", other.v1_type_byte());
                                                }
                                                Err(_elapsed) => {
                                                    // No `return`: the io drops at block end (closing the slow peer's
                                                    // connection); the accept loop must keep accepting other peers.
                                                    tracing::warn!(peer = %peer, "KCP: timed out waiting for first V1 message (post-handshake deadline 30s) from {}", peer);
                                                    }
                                                Ok(Err(e)) => {
                                                    tracing::warn!(error = %e, "KCP read error: {}", e);
                                                }
                                            }
                                        }
                                    }
                                    }
                                }));
                            }
                            Err(e) => {
                                tracing::warn!(error = %e, "KCP accept error, retrying...");
                                tokio::time::sleep(Duration::from_millis(100)).await;
                                continue;
                            }
                        }
                        }
                        _ = kcp_state.shutdown_token.cancelled() => break 'kcp_accept,
                    }
                }
            }));
            match kcp_bind_rx.await {
                Ok(_) => tracing::info!(addr = %kcp_addr, "KCP listener started on {}", kcp_addr),
                Err(_) => tracing::error!(addr = %kcp_addr, "KCP listener failed to start"),
            }
        }
    }

    // `rate_limiter_enabled` is captured from `run`'s scope; passed explicitly.
    #[cfg(feature = "quic")]
    pub(super) async fn start_quic_listener(&self, rate_limiter_enabled: bool) {
        if self.cfg.quic_bind_port > 0 {
            let quic_state = self.state.clone();
            let quic_options = self.cfg.transport.quic_options.clone().unwrap_or_default();
            let quic_params = frp_core::quic::quic_params_from_option_values(
                quic_options.keepalive_period,
                quic_options.max_idle_timeout,
                quic_options.max_incoming_streams,
                quic_options.stream_receive_window,
            );
            let authenticated_stream_limit = quic_params.max_incoming_streams as usize;
            let mut listener_quic_params = quic_params.clone();
            listener_quic_params.max_incoming_streams = quic_params
                .max_incoming_streams
                .min(crate::handlers::QUIC_PREAUTH_STREAM_LIMIT as u32)
                .max(1);
            let quic_addr = format_socket_addr(&self.cfg.bind_addr, self.cfg.quic_bind_port);
            let quic_addr2 = quic_addr.clone();
            let (quic_bind_tx, quic_bind_rx) = tokio::sync::oneshot::channel::<()>();
            let cert_path = self.cfg.tls_cert_file.clone();
            let key_path = self.cfg.tls_key_file.clone();
            let ca_path = if self.cfg.tls_ca_file.is_empty() {
                None
            } else {
                Some(self.cfg.tls_ca_file.clone())
            };
            spawn_boxed(Box::pin(async move {
                let sockaddr: std::net::SocketAddr = match quic_addr.parse() {
                    Ok(a) => a,
                    Err(e) => {
                        tracing::error!(addr = %quic_addr, error = %e, "QUIC: invalid bind address");
                        return;
                    }
                };

                // Build a TLS server config that honors `trustedCaFile`
                // (mTLS) exactly like the TCP/TLS path, then hand it to the
                // QUIC listener. Go frp reuses NewServerTLSConfig for QUIC.
                let tls_config = if !cert_path.is_empty() && !key_path.is_empty() {
                    frp_core::transport::build_tls_server_config(
                        &cert_path,
                        &key_path,
                        ca_path.as_deref(),
                    )
                } else {
                    tracing::info!(
                        "QUIC: no TLS cert/key configured, \
                         auto-generating self-signed certificate"
                    );
                    frp_core::transport::generate_self_signed_tls_config_with_ca(ca_path.as_deref())
                };
                let tls_config = match tls_config {
                    Ok(c) => c,
                    Err(e) => {
                        tracing::error!(
                            error = %e,
                            "QUIC: failed to build TLS config"
                        );
                        return;
                    }
                };
                let listener = match frp_core::quic::QuicListener::new_with_tls_config(
                    sockaddr,
                    tls_config,
                    listener_quic_params.clone(),
                ) {
                    Ok(l) => l,
                    Err(e) => {
                        tracing::error!(
                            error = %e,
                            "QUIC: listen failed with built TLS config"
                        );
                        return;
                    }
                };
                let _ = quic_bind_tx.send(());

                tracing::info!(addr = %quic_addr, "QUIC listener started on {}", quic_addr);
                'quic_accept: loop {
                    tokio::select! {
                            result = listener.accept() => {
                                match result {
                                    Ok(conn) => {
                                        let state = quic_state.clone();
                                        let quic_addr = conn.remote_address();
                                        let permit = state.conn_semaphore.as_ref()
                                            .and_then(|s| s.clone().try_acquire_owned().ok());
                                        if permit.is_none() && state.conn_semaphore.is_some() {
                                            warn!(addr = %quic_addr, "Max connections reached, rejecting QUIC from {}", quic_addr);
                                            continue;
                                        }
                                        let rate_wait = if rate_limiter_enabled {
                                            state.accept_rate_limiter.try_acquire().err()
                                        } else {
                                            None
                                        };
                                        if let Some(wait) = rate_wait {
                                            warn!(addr = %quic_addr, wait_ms = wait.as_millis(), "accept rate limit reached, delaying QUIC {}ms", wait.as_millis());
                                            drop(permit);
                                            tokio::time::sleep(wait).await;
                                            continue;
                                        }
                                        spawn_boxed(Box::pin(async move {
                                            let _permit = permit;
                                            // Accept first bidirectional stream (control channel).
                                            // This is inside the handler, not in the accept loop —
                                            // matching Go frp's HandleQUICListener pattern where
                                            // the accept loop never blocks on a stream.
                                            let stream = match crate::handlers::await_quic_preauth(
                                                conn.accept_bi(),
                                                tokio::time::Instant::now()
                                                    + crate::handlers::QUIC_FIRST_FRAME_TIMEOUT,
                                                &state.shutdown_token,
                                            )
                                            .await
                                            {
                                                Ok(Ok(stream)) => stream,
                                                Ok(Err(e)) => {
                                                    tracing::warn!(error = %e, "QUIC: failed to accept first stream: {e}");
                                                    return;
                                                }
                                                Err(crate::handlers::QuicPreauthError::TimedOut) => {
                                                    tracing::warn!(addr = %quic_addr, "QUIC connection timed out before opening control stream");
                                                    conn.close(b"control stream timeout");
                                                    return;
                                                }
                                                Err(crate::handlers::QuicPreauthError::Cancelled) => {
                                                    conn.close(b"server shutdown");
                                                    return;
                                                }
                                            };
                                            // The first-frame budget starts after the stream is
                                            // accepted, not while we are waiting for the peer to
                                            // open it (Go frp applies the read deadline post-accept).
                                            let deadline = tokio::time::Instant::now()
                                                + crate::handlers::QUIC_FIRST_FRAME_TIMEOUT;
                                            crate::handlers::handle_quic_stream(
                                                stream,
                                                conn,
                                                state,
                                                deadline,
                                                authenticated_stream_limit,
                                            ).await;
                                        }));
                                    }
                            Err(e) => {
                                tracing::warn!(error = %e, "QUIC accept error, retrying...");
                                tokio::time::sleep(Duration::from_millis(100)).await;
                                continue;
                            }
                        }
                        }
                        _ = quic_state.shutdown_token.cancelled() => {
                            tracing::debug!("QUIC accept loop: shutdown requested");
                            break 'quic_accept;
                        }
                    }
                }
                tracing::info!("QUIC accept loop shut down gracefully");
            }));
            match quic_bind_rx.await {
                Ok(_) => {
                    tracing::info!(addr = %quic_addr2, "QUIC listener started on {}", quic_addr2)
                }
                Err(_) => tracing::error!(addr = %quic_addr2, "QUIC listener failed to start"),
            }
        }
    }

    #[cfg(feature = "dashboard")]
    pub(super) async fn start_dashboard_listener(&self) {
        if self.cfg.web_server.port > 0 {
            let dash_addr = format_socket_addr(&self.cfg.web_server.addr, self.cfg.web_server.port);
            let dash_addr2 = dash_addr.clone();
            let dash_state = self.state.clone();
            let dash_user = self.cfg.web_server.user.clone();
            let dash_pwd = self.cfg.web_server.password.clone();
            let dash_tls_cert = if self.cfg.web_server.tls_cert().is_empty() {
                None
            } else {
                Some(self.cfg.web_server.tls_cert().to_string())
            };
            let dash_tls_key = if self.cfg.web_server.tls_key().is_empty() {
                None
            } else {
                Some(self.cfg.web_server.tls_key().to_string())
            };
            let enable_prom = self.cfg.web_server.enable_prometheus;
            let dash_assets = self.cfg.web_server.assets_dir.clone();
            let dash_shutdown = self.state.shutdown_token.clone();
            tokio::spawn(async move {
                if let Err(e) = crate::dashboard::run_dashboard(
                    dash_addr,
                    dash_state,
                    dash_user,
                    dash_pwd,
                    enable_prom,
                    dash_tls_cert,
                    dash_tls_key,
                    dash_assets,
                    dash_shutdown,
                )
                .await
                {
                    tracing::error!(error = %e, "Dashboard server failed: {}", e);
                }
            });
            tracing::info!(addr = %dash_addr2, "Dashboard web UI starting on {}", dash_addr2);
        }
    }
}
