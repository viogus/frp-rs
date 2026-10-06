//! The SUDP visitor cluster: the lazy UDP listener (`run_sudp_visitor_listener`),
//! its shutdown/datagram helpers (`sudp_next_datagram`, `wait_sudp_shutdown`),
//! the server-side tunnel dial (`connect_sudp_visitor_stream`) and the
//! established-tunnel data-plane worker (`run_sudp_worker`) together with the
//! frame-read task guard (`SudpReaderAbort`).
//!
//! Split out of `frp-client/src/visitor.rs` by the plan's P3 seam 3
//! (`docs/refactor-large-modules.md` P3, `visitor/sudp.rs`) as a pure move: the
//! six moved items are byte-for-byte identical to their base text (evidence in
//! `/tmp/m38-author-report.md`). This module is a *child* of `visitor`, so
//! through `use super::*;` it reaches the parent-private items it needs —
//! `VisitorListenerConfig`, `VisitorTransportConfig` and `plan_visitor_dial` —
//! plus the parent's own imports, with no visibility change on any of them.
//!
//! Visibility: `run_sudp_visitor_listener` keeps its original `pub(crate)` token;
//! the five other items keep their original private tokens. The parent
//! re-exports the listener (`pub(crate) use sudp::run_sudp_visitor_listener;`)
//! because the only caller is `frp-client/src/visitor/stcp.rs`, which dispatches
//! SUDP visitors to it through that file's `use super::*;` — the re-export
//! preserves the original effective visibility, it does not widen it.

use super::*;

/// Run a SUDP visitor listener.
///
/// Binds a local UDP socket and tunnels datagrams to a remote SUDP proxy
/// through the frps server, mirroring Go frp's `client/visitor/sudp.go`:
/// - one shared UDP socket, multiplexed by datagram source address: inbound
///   datagrams are answered back to their `UdpAddr` source, outbound
///   datagrams carry their own source address in `UDPPacket.remote_addr`
/// - lazy connection: no server connection is held until the first datagram
///   arrives; the first datagram triggers a fresh NewVisitorConn handshake
/// - on disconnect/idle timeout the worker returns to the wait state and the
///   next datagram reconnects
///
/// ENCRYPTION/COMPRESSION: the SUDP data plane uses the Go-frp three-segment
/// model — the visitor segment (visitor frpc ↔ frps) is encrypted with
/// `derive_key(sk)` and compressed with a Snappy stream (SnappyStream +
/// CipherReader/CipherWriter around the conn in `run_sudp_worker`, symmetric
/// with the server's `split_user_side`, snappy inner / CFB outer), the
/// provider segment (frps ↔ provider frpc) with `derive_key(auth token)`.
pub(crate) async fn run_sudp_visitor_listener(config: VisitorListenerConfig) {
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
        // SUDP has no retry / NAT-traversal / fallback options; all unused.
        visitor_type: _,
        fallback_timeout_ms: _,
        keep_tunnel_open: _,
        max_retries_an_hour: _,
        min_retry_interval: _,
        stun_server: _,
        p2p_protocol: _,
        visitor_tx: _,
        fallback_to: _,
        disable_assisted_addrs: _,
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
        udp_packet_codec,
        // SUDP: no NAT traversal / tunnel session.
        #[cfg(all(feature = "quic", feature = "kcp"))]
            quic_params: _,
    } = config;

    // Go frp v0.70.1 three-stage model: the visitor segment is encrypted
    // with `derive_key(sk)` when the visitor declares use_encryption and
    // compressed with a Snappy stream when it declares use_compression. The
    // server (bridge.rs `split_user_side`) wraps its user-side connection
    // with the same key / Snappy layer, and we wrap the data-plane stream in
    // `run_sudp_worker` — the NewVisitorConn declaration and both ends of the
    // visitor segment now agree (snappy inner, CFB outer, Go parity).

    let socket = match tokio::net::UdpSocket::bind(&bind_addr).await {
        Ok(s) => Arc::new(s),
        Err(e) => {
            warn!(visitor_name = %name, bind_addr = %bind_addr, error = %e, "SUDP visitor '{}': bind {} failed: {}", name, bind_addr, e);
            return;
        }
    };
    let bound = socket
        .local_addr()
        .unwrap_or_else(|_| "0.0.0.0:0".parse().unwrap());
    info!(visitor_name = %name, local_addr = %bound, "SUDP visitor '{}' listening on {} (lazy tunnel: no server connection until first datagram)", name, bound);

    // Go sudp.go uses capacity-1024 channels for both directions.
    let (send_tx, mut send_rx) = mpsc::channel::<msg::UDPPacket>(1024);
    let (read_tx, mut read_rx) = mpsc::channel::<msg::UDPPacket>(1024);

    // --- Reader loop: tunnel → local UDP clients ---
    // Datagrams coming back through the tunnel carry the originating local
    // client address in UDPPacket.remote_addr; send them back to it.
    // The reader/listener tasks exit on their own once the shutdown flag is
    // set or the channels close (their senders are dropped when the dispatcher
    // returns), so the JoinHandles are intentionally not joined.
    let _reader_task = {
        let socket_r = socket.clone();
        let shutdown_r = shutdown.clone();
        let name_r = name.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    biased;
                    _ = wait_sudp_shutdown(&shutdown_r) => {
                        info!(visitor_name = %name_r, "SUDP visitor '{}' reader shutting down", name_r);
                        break;
                    }
                    pkt = read_rx.recv() => {
                        match pkt {
                            Some(up) => {
                                if let Some(ref ra) = up.remote_addr {
                                    // Zero-alloc parse (audit: the old
                                    // per-packet format!("{}:{}") + re-parse
                                    // chain also DROPPED bare-v6 addresses —
                                    // std SocketAddr parse needs brackets; the
                                    // helper parses them natively, delivering
                                    // v6 SUDP replies like Go (which resolves
                                    // the ip string via net.ResolveUDPAddr).
                                    // A zone-bearing ip string stays
                                    // unparseable (warn+drop, as before).
                                    if let Some(addr) = frp_core::udp_binary::udp_addr_to_socket(ra)
                                    {
                                        if let Err(e) = socket_r.send_to(&up.content, addr).await {
                                            debug!(visitor_name = %name_r, remote = %addr, error = %e, "SUDP visitor '{}': send_to local client {} failed: {}", name_r, addr, e);
                                        }
                                    } else {
                                        warn!(visitor_name = %name_r, ip = %ra.ip, port = ra.port, "SUDP visitor '{}': unparseable remote address, dropping packet", name_r);
                                    }
                                } else {
                                    warn!(visitor_name = %name_r, "SUDP visitor '{}': UDPPacket without remote_addr, dropping", name_r);
                                }
                            }
                            None => {
                                debug!(visitor_name = %name_r, "SUDP visitor '{}' read channel closed", name_r);
                                break;
                            }
                        }
                    }
                }
            }
        })
    };

    // --- Listener loop: local UDP clients → tunnel ---
    // Every datagram becomes a UDPPacket with its source as remote_addr.
    // The tunnel is (re)connected lazily by the dispatcher below.
    let _listener_task = {
        let socket_l = socket.clone();
        let send_tx_l = send_tx.clone();
        let shutdown_l = shutdown.clone();
        let name_l = name.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65535];
            loop {
                // Deliberately NOT biased: under heavy local UDP traffic the
                // recv_from branch would always be ready and starve the
                // shutdown poll.
                tokio::select! {
                    _ = wait_sudp_shutdown(&shutdown_l) => {
                        info!(visitor_name = %name_l, "SUDP visitor '{}' listener shutting down", name_l);
                        break;
                    }
                    result = socket_l.recv_from(&mut buf) => {
                        match result {
                            Ok((n, src)) => {
                                debug!(visitor_name = %name_l, byte_count = n, src_addr = %src, "SUDP visitor '{}': received {} bytes from local {}", name_l, n, src);
                                let pkt = msg::UDPPacket {
                                    content: buf[..n].to_vec(),
                                    local_addr: None, // SUDP: local_addr is always None (Go sudp.go)
                                    remote_addr: Some(msg::UdpAddr {
                                        ip: src.ip().to_string(),
                                        port: src.port(),
                                        zone: String::new(),
                                    }),
                                };
                                if send_tx_l.send(pkt).await.is_err() {
                                    debug!(visitor_name = %name_l, "SUDP visitor '{}' send channel closed", name_l);
                                    break;
                                }
                            }
                            Err(e) => {
                                warn!(visitor_name = %name_l, error = %e, "SUDP visitor '{}': recv_from failed: {}", name_l, e);
                                break;
                            }
                        }
                    }
                }
            }
        })
    };

    let transport = VisitorTransportConfig {
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
    };

    // --- Dispatcher: lazy connect + reconnect ---
    // Wait for the first datagram (wait state), then establish a tunnel.
    // While the worker runs it consumes further datagrams. When the worker
    // exits (disconnect / 60s idle timeout) we return to the wait state and
    // the next datagram reconnects (Go sudp.go Run()/worker()).
    let mut first_pkt = match sudp_next_datagram(&mut send_rx, &shutdown, &name).await {
        Some(p) => p,
        None => {
            debug!(visitor_name = %name, "SUDP visitor '{}' send channel closed (listener exited)", name);
            return;
        }
    };

    loop {
        if shutdown.load(Ordering::Relaxed) {
            info!(visitor_name = %name, "SUDP visitor '{}' shutting down", name);
            return;
        }
        let server_conn = match connect_sudp_visitor_stream(
            &server_addr,
            server_port,
            &protocol,
            tls_enable,
            &tls_server_name,
            &tls_ca_file,
            &transport,
            &name,
            &server_name,
            &server_user,
            &secret_key,
            use_encryption,
            use_compression,
            &user,
            &run_id,
            v2,
        )
        .await
        {
            Some(conn) => conn,
            None => {
                warn!(visitor_name = %name, "SUDP visitor '{}': tunnel connect failed; dropping packet and waiting for the next datagram", name);
                match sudp_next_datagram(&mut send_rx, &shutdown, &name).await {
                    Some(p) => {
                        first_pkt = p;
                        continue;
                    }
                    None => return,
                }
            }
        };
        run_sudp_worker(
            server_conn,
            &mut send_rx,
            first_pkt,
            read_tx.clone(),
            &name,
            &shutdown,
            use_encryption,
            use_compression,
            &secret_key,
            v2,
            &udp_packet_codec,
        )
        .await;
        // Worker ended (disconnect / idle timeout): back to the wait state.
        debug!(visitor_name = %name, "SUDP visitor '{}': tunnel closed, waiting for the next datagram to reconnect", name);
        match sudp_next_datagram(&mut send_rx, &shutdown, &name).await {
            Some(p) => first_pkt = p,
            None => return,
        }
    }
}

/// Wait for the next local datagram, aborting early on shutdown.
///
/// Every place the dispatcher blocks on `send_rx.recv()` must race it
/// against the shutdown flag — otherwise a shutdown that arrives while the
/// worker is exiting (or after a connect failure) leaves the dispatcher
/// parked on `recv()` forever, holding the UDP socket Arc and leaking the
/// bind port until process exit.
async fn sudp_next_datagram(
    send_rx: &mut mpsc::Receiver<msg::UDPPacket>,
    shutdown: &Arc<AtomicBool>,
    name: &str,
) -> Option<msg::UDPPacket> {
    tokio::select! {
        biased;
        _ = wait_sudp_shutdown(shutdown) => {
            info!(visitor_name = %name, "SUDP visitor '{}' shutting down", name);
            None
        }
        p = send_rx.recv() => p,
    }
}

/// Dial the server and complete the NewVisitorConn handshake for a SUDP
/// visitor tunnel. Mirrors the STCP visitor connect skeleton
/// (`dial_server` → yamux → `NewVisitorConn` → `NewVisitorConnResp`).
#[allow(clippy::too_many_arguments)]
async fn connect_sudp_visitor_stream(
    server_addr: &str,
    server_port: u16,
    protocol: &TransportProtocol,
    tls_enable: bool,
    tls_server_name: &str,
    tls_ca_file: &Option<String>,
    transport: &VisitorTransportConfig,
    visitor_name: &str,
    server_name: &str,
    server_user: &str,
    secret_key: &str,
    use_encryption: bool,
    use_compression: bool,
    user: &str,
    run_id: &str,
    v2: bool,
) -> Option<IoStream> {
    let plan = plan_visitor_dial(
        server_addr,
        server_port,
        protocol,
        tls_enable,
        tls_server_name,
        tls_ca_file,
        transport,
    );
    let raw_stream = match dial_server(&plan.opts).await {
        Ok(io) => io,
        Err(e) => {
            warn!(visitor_name = %visitor_name, error = %e, "SUDP visitor '{}': dial server failed: {}", visitor_name, e);
            return None;
        }
    };
    let mut server_conn = if let (Some(ka), Some(ka_timeout)) =
        (plan.yamux_keepalive_secs, plan.yamux_idle_dead_timeout_secs)
    {
        match crate::control::wrap_client_mux(raw_stream, ka, ka_timeout).await {
            Ok((io, _session)) => io,
            Err(e) => {
                warn!(visitor_name = %visitor_name, error = %e, "SUDP visitor '{}': yamux wrap failed: {}", visitor_name, e);
                return None;
            }
        }
    } else {
        raw_stream
    };
    let nvc = crate::proxy::create_visitor_conn_msg(
        server_name,
        secret_key,
        use_encryption,
        use_compression,
        Some(server_user).filter(|s| !s.is_empty()),
        Some(user).filter(|s| !s.is_empty()),
        Some(run_id).filter(|s| !s.is_empty()),
    );
    // V2: write the connection magic before the NewVisitorConn frame (Go frp
    // messageConnector.Connect → WriteMagicIfV2; work conns do the same).
    // The server's accept loop consumes the magic, detects V2, and routes the
    // frame to handle_visitor_conn_inner; all subsequent frames on the
    // connection are magic-less V2 frames.
    let send_result = async {
        if v2 {
            frp_core::protocol::write_v2_magic(&mut server_conn).await?;
            server_conn.write_v2_frame(&nvc).await
        } else {
            server_conn.write_v1_frame(&nvc).await
        }
    }
    .await;
    if let Err(e) = send_result {
        warn!(visitor_name = %visitor_name, error = %e, "SUDP visitor '{}': send NewVisitorConn failed: {}", visitor_name, e);
        return None;
    }
    // Bound the response wait (mirrors read_start_work_conn_with_timeout in
    // work_conn.rs): a silent server must not leave the tunnel connect
    // hanging — the dispatcher falls back to waiting for the next datagram.
    let resp_timeout = Duration::from_secs(transport.dial_timeout_secs.max(1));
    let read_resp = if v2 {
        tokio::time::timeout(resp_timeout, server_conn.read_v2_frame()).await
    } else {
        tokio::time::timeout(resp_timeout, server_conn.read_v1_frame()).await
    };
    match read_resp {
        Ok(Ok(FrpMessage::NewVisitorConnResp(resp))) => {
            if let Some(err) = resp.error {
                warn!(visitor_name = %visitor_name, error = %err, "SUDP visitor '{}': server error: {}", visitor_name, err);
                return None;
            }
            debug!(visitor_name = %visitor_name, proxy_name = %resp.proxy_name, "SUDP visitor '{}': relay ready for '{}'", visitor_name, resp.proxy_name);
        }
        Ok(Ok(other)) => {
            warn!(visitor_name = %visitor_name, type_byte = %other.v1_type_byte(), "SUDP visitor '{}': unexpected response type", visitor_name);
            return None;
        }
        Ok(Err(e)) => {
            warn!(visitor_name = %visitor_name, error = %e, "SUDP visitor '{}': read NewVisitorConnResp failed: {}", visitor_name, e);
            return None;
        }
        Err(_elapsed) => {
            warn!(visitor_name = %visitor_name, timeout = ?resp_timeout, "SUDP visitor '{}': timed out waiting for NewVisitorConnResp", visitor_name);
            return None;
        }
    }
    Some(server_conn)
}

/// Data-plane worker for an established SUDP visitor tunnel.
///
/// - write side: datagrams from the local UDP socket (`send_rx`) are written
///   to the server connection as `UDPPacket` messages (V1 framing, type 'u',
///   matching Go frp's UDP data plane)
/// - read side: `UDPPacket` messages from the server are forwarded to the
///   reader loop (`read_tx`) which sends them back to the local client;
///   `Ping` is ignored (Go sudp.go)
/// - a 60s idle timeout closes the tunnel (Go sudp.go `connTimeout`); the
///   dispatcher then reconnects on the next datagram
///
/// When the visitor declared `use_encryption` (and `sk` is non-empty), the
/// server-side half of the connection is wrapped in `CipherReader` /
/// `CipherWriter` with `derive_key(sk)`, and when it declared
/// `use_compression` the halves are additionally wrapped in
/// `SnappyStreamReader`/`SnappyStreamWriter` — the visitor segment of Go
/// frp's three-stage model, snappy **inner** and CFB **outer** (Go
/// `WithCompression` + `WithEncryption`). The V1 frame protocol then runs on
/// top of the wrapped stream, symmetric with the server's `split_user_side`.
/// CipherWriter sends its random IV on the first write (or eager flush), so
/// the first `UDPPacket` carries the IV.
#[allow(clippy::too_many_arguments)]
async fn run_sudp_worker(
    server_conn: IoStream,
    send_rx: &mut mpsc::Receiver<msg::UDPPacket>,
    first_pkt: msg::UDPPacket,
    read_tx: mpsc::Sender<msg::UDPPacket>,
    visitor_name: &str,
    shutdown: &Arc<AtomicBool>,
    use_encryption: bool,
    use_compression: bool,
    secret_key: &str,
    v2: bool,
    udp_packet_codec: &str,
) {
    // Negotiated UDPPacket codec (Go frp v0.71.0): `"binary-v1"` when the
    // control session negotiated it (wire protocol v2), empty otherwise.
    // The visitor segment must use the same codec as the provider segment
    // or the server bridges the two message-level (transcoding).
    let udp_codec_opt = if v2 && !udp_packet_codec.is_empty() {
        Some(udp_packet_codec)
    } else {
        None
    };
    let (srv_r, srv_w) = match split_work_conn_halves(server_conn) {
        Ok(pair) => pair,
        Err(e) => {
            warn!(visitor_name = %visitor_name, error = e, "SUDP visitor '{}': could not split server conn: {}", visitor_name, e);
            return;
        }
    };
    // Visitor-segment encryption/compression: wrap both halves symmetrically
    // with the server's split_user_side. Wire order (Go parity): snappy is
    // the inner layer, CFB the outer — write plaintext → snappy → CFB →
    // socket. The V1 frame protocol (read_msg_v1/write_msg_v1) then runs over
    // the wrapped stream.
    let use_enc = use_encryption && !secret_key.is_empty();
    let enc_key = use_enc.then(|| frp_core::encryption::derive_key(secret_key));
    let srv_r: BoxedReadHalf = if use_compression {
        let inner: BoxedReadHalf = if let Some(key) = enc_key {
            Box::new(frp_core::cipher_stream::CipherReader::new(srv_r, key))
        } else {
            srv_r
        };
        Box::new(frp_core::snappy_stream::SnappyStreamReader::new(inner))
    } else if let Some(key) = enc_key {
        Box::new(frp_core::cipher_stream::CipherReader::new(srv_r, key))
    } else {
        srv_r
    };
    let mut srv_w: BoxedWriteHalf = if use_compression {
        let inner: BoxedWriteHalf = if let Some(key) = enc_key {
            // Audit B2: OS-RNG failure (IV generation) ends this worker
            // instead of aborting the process.
            match frp_core::cipher_stream::CipherWriter::new(srv_w, key) {
                Ok(w) => Box::new(w),
                Err(e) => {
                    warn!(visitor_name = %visitor_name, error = %e, "sudp visitor: IV generation failed");
                    return;
                }
            }
        } else {
            srv_w
        };
        Box::new(frp_core::snappy_stream::SnappyStreamWriter::new(inner))
    } else if let Some(key) = enc_key {
        // Audit B2: OS-RNG failure (IV generation) ends this worker
        // instead of aborting the process.
        match frp_core::cipher_stream::CipherWriter::new(srv_w, key) {
            Ok(w) => Box::new(w),
            Err(e) => {
                warn!(visitor_name = %visitor_name, error = %e, "sudp visitor: IV generation failed");
                return;
            }
        }
    } else {
        srv_w
    };
    // Buffer frame reads: read_msg_v1 issues two read_exact calls per message.
    let srv_r = tokio::io::BufReader::with_capacity(16 * 1024, srv_r);
    // Reused wire buffer (write side; the `scratch` inside the loop is the
    // read side). Shared by the V2 binary-codec body and the V1 JSON payload
    // below — the two writes are mutually exclusive per packet and both
    // writers clear it first, so the V1 path no longer allocates a fresh
    // `serde_json` Vec per datagram (perf audit TOP 2).
    let mut wire_scratch: Vec<u8> = Vec::new();
    // The first packet (which triggered the connect) is written immediately.
    let first_write = if v2 {
        write_msg_v2_with_udp_codec(
            &mut srv_w,
            &FrpMessage::UDPPacket(first_pkt),
            udp_codec_opt,
            false,
            &mut wire_scratch,
        )
        .await
    } else {
        write_v1_frame_scratch(
            &mut srv_w,
            &FrpMessage::UDPPacket(first_pkt),
            &mut wire_scratch,
        )
        .await
    };
    if let Err(e) = first_write {
        warn!(visitor_name = %visitor_name, error = %e, "SUDP visitor '{}': write first UDPPacket failed: {}", visitor_name, e);
        return;
    }
    // Go sudp.go: a 60s idle tunnel (no traffic either way) tears down and
    // the next datagram reconnects. Deadline is reset on every activity —
    // NOT a fresh sleep() per loop iteration, which would never fire (the
    // 100ms shutdown poll would always win the select and restart it).
    let mut idle_deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    // Dedicated frame-read task (audit round-8 F13): the read owns `srv_r`
    // exclusively, so a frame that is only partially read when the local
    // branch wins the select below is never discarded — the old
    // per-iteration rebuild dropped the consumed prefix mid-frame and the
    // next parse read the frame tail as a header (garbage → tunnel
    // teardown + reconnect churn). The task stops on shutdown (select arm)
    // or after a read error, and its end reaches the loop via the channel.
    let (frame_tx, mut frame_rx) = tokio::sync::mpsc::channel(8);
    let shutdown_task = shutdown.clone();
    let udp_codec_owned = udp_codec_opt.map(str::to_string);
    let reader_handle = tokio::spawn(async move {
        let mut srv_r = srv_r;
        // Reusable payload buffer for the V2 UDP read path (avoids a heap
        // alloc per UDP packet).
        let mut scratch = Vec::new();
        loop {
            tokio::select! {
                _ = wait_sudp_shutdown(&shutdown_task) => break,
                res = async {
                    if v2 {
                        read_msg_v2_with_udp_codec(&mut srv_r, udp_codec_owned.as_deref(), &mut scratch).await
                    } else {
                        read_msg_v1(&mut srv_r).await
                    }
                } => {
                    let is_err = res.is_err();
                    if frame_tx.send(res).await.is_err() {
                        break;
                    }
                    if is_err {
                        break;
                    }
                }
            }
        }
    });
    // Abort-guard: the reader task exclusively owns the read half, so every
    // worker exit path (idle deadline, shutdown, channel close, write/read
    // error — the breaks below and the return at the function end) must kill
    // it or the tunnel conn stays half-open forever with one task parked in
    // read_msg_*. Pre-fix the idle-deadline break dropped only `srv_w`, and
    // the reader — parked on a read the peer never answers — neither saw the
    // channel close (it only sends after a read completes) nor the shutdown
    // flag: one leaked task + fd + 16 KiB BufReader per idle cycle. Aborting
    // drops `srv_r`, both halves close, and the conn FINs. (Round-2 review,
    // audit round 8.)
    let _reader_guard = SudpReaderAbort(reader_handle);
    loop {
        // Fast-path shutdown check: the 100ms wait_sudp_shutdown poll below
        // can be starved under sustained bidirectional traffic (unbiased
        // select picks among ready branches), so check the flag directly on
        // every iteration.
        if shutdown.load(Ordering::Relaxed) {
            info!(visitor_name = %visitor_name, "SUDP visitor '{}' shutting down", visitor_name);
            break;
        }
        // Deliberately NOT biased: an always-ready send channel (local UDP
        // flood) must not starve the read side (return traffic), and the
        // idle/shutdown branches must stay reachable.
        tokio::select! {
            _ = wait_sudp_shutdown(shutdown) => {
                info!(visitor_name = %visitor_name, "SUDP visitor '{}' shutting down", visitor_name);
                break;
            }
            _ = tokio::time::sleep_until(idle_deadline) => {
                debug!(visitor_name = %visitor_name, "SUDP visitor '{}': 60s idle timeout, closing tunnel", visitor_name);
                break;
            }
            pkt = send_rx.recv() => {
                match pkt {
                    Some(p) => {
                        let write = if v2 {
                            write_msg_v2_with_udp_codec(
                                &mut srv_w,
                                &FrpMessage::UDPPacket(p),
                                udp_codec_opt,
                                false,
                                &mut wire_scratch,
                            )
                            .await
                        } else {
                            // V1 JSON: reuse the loop's shared scratch.
                            write_v1_frame_scratch(
                                &mut srv_w,
                                &FrpMessage::UDPPacket(p),
                                &mut wire_scratch,
                            )
                            .await
                        };
                        if let Err(e) = write {
                            debug!(visitor_name = %visitor_name, error = %e, "SUDP visitor '{}': write UDPPacket failed: {}", visitor_name, e);
                            break;
                        }
                        idle_deadline = tokio::time::Instant::now() + Duration::from_secs(60);
                    }
                    None => {
                        debug!(visitor_name = %visitor_name, "SUDP visitor '{}': send channel closed", visitor_name);
                        break;
                    }
                }
            }
            msg = frame_rx.recv() => {
                match msg {
                    Some(Ok(FrpMessage::UDPPacket(up))) => {
                        idle_deadline = tokio::time::Instant::now() + Duration::from_secs(60);
                        if read_tx.send(up).await.is_err() {
                            debug!(visitor_name = %visitor_name, "SUDP visitor '{}': reader loop dropped", visitor_name);
                            break;
                        }
                    }
                    Some(Ok(FrpMessage::Ping(_))) | Some(Ok(FrpMessage::Pong(_))) => {
                        // Go sudp.go ignores Ping on the data plane.
                    }
                    Some(Ok(other)) => {
                        debug!(visitor_name = %visitor_name, v1_type = %other.v1_type_byte(), "SUDP visitor '{}': unexpected message 0x{:02x}", visitor_name, other.v1_type_byte());
                    }
                    Some(Err(e)) => {
                        debug!(visitor_name = %visitor_name, error = %e, "SUDP visitor '{}': read closed: {}", visitor_name, e);
                        break;
                    }
                    None => {
                        debug!(visitor_name = %visitor_name, "SUDP visitor '{}': frame reader ended", visitor_name);
                        break;
                    }
                }
            }
        }
    }
}

/// Aborts the SUDP frame-read task when the worker exits by any path.
struct SudpReaderAbort(tokio::task::JoinHandle<()>);

impl Drop for SudpReaderAbort {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Polls `shutdown` every 100ms until it is set.
async fn wait_sudp_shutdown(shutdown: &Arc<AtomicBool>) {
    loop {
        if shutdown.load(Ordering::Relaxed) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}
