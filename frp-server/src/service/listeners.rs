use std::time::Duration;

use tokio::io::AsyncReadExt;
use tokio::net::TcpListener;
use tracing::{info, warn};

use frp_core::format_socket_addr;
use frp_core::mux;
use frp_core::transport::IoStream;

#[cfg(feature = "tls")]
use crate::lock::RwLockExt;

use super::{spawn_boxed, Service};

impl Service {
    // `rate_limiter_enabled` is captured from `run`'s scope; passed explicitly.
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
}
