//! Server-side UDP/SUDP work-connection plumbing.

use super::*;

/// Maximum consecutive ready UDP datagrams written before issuing a single
/// `flush()` on buffered transports (yamux, TLS, KCP, `CipherWriter`).
/// Single datagrams still flush immediately (`try_recv_from` returns
/// `WouldBlock`); bursts amortize per-packet flush syscalls / cipher blocks.
const UDP_FLUSH_BATCH_MAX: usize = 16;

/// Read one UDP work-conn frame into the caller-owned `scratch` buffer.
///
/// Stack-pinned inside `run_udp_work_conn`'s reader loop (zero `Box::pin`
/// heap allocation per packet) and kept alive across benign
/// `reader_cancel.changed()` (`false -> false`) wakeups and lazy-watchdog
/// re-arms so a partially-read frame is never dropped or restarted (M1).
async fn read_one_udp_frame(
    r: &mut tokio::io::BufReader<Box<dyn AsyncRead + Unpin + Send>>,
    scratch: &mut Vec<u8>,
    v2: bool,
    codec: Option<&str>,
) -> Result<UdpBinaryRead, frp_core::Error> {
    if v2 {
        if codec.is_some() {
            // Binary UDP codec negotiated (Go v0.71.0): type-19 frames
            // decode to native SocketAddr form, skipping the per-packet
            // String alloc + reparse that the message path performs
            // (audit LOW: decode formats then re-parses).
            read_msg_v2_udp_binary_socket(r, scratch).await
        } else {
            read_msg_v2_with_udp_codec(r, codec, scratch)
                .await
                .map(UdpBinaryRead::Message)
        }
    } else {
        read_msg_v1(r).await.map(UdpBinaryRead::Message)
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn run_udp_work_conn(
    work_conn: IoStream,
    sock: Arc<tokio::net::UdpSocket>,
    proxy_name: String,
    local_addr: Option<msg::UdpAddr>,
    use_enc: bool,
    enc_key: [u8; 16],
    v2: bool,
    udp_packet_size: usize,
    bw_limiter: Option<frp_core::bandwidth::SharedBandwidthLimiter>,
    cancel: tokio_util::sync::CancellationToken,
    // Negotiated UDPPacket codec (`"binary-v1"` or empty). When set, UDP
    // packets on this V2 work conn use the binary codec (Go frp v0.71.0).
    udp_packet_codec: String,
    // M1 (audit round 3): read deadline for this work conn, mirroring Go
    // server/proxy/udp.go `workConnReaderFn` SetReadDeadline(60s). The
    // client pings at a FIXED 30s (audit F1 — Go client/proxy/udp.go
    // heartbeatFn hardcodes 30s; frp-rs used to wire dial_server_keepalive
    // here, whose 7200s default let this 60s deadline kill idle conns), so
    // 60s of frame silence means the peer is dead or the conn is
    // half-open — the bridge must end so the assign supervisor re-requests
    // a replacement (Go udpWorker loop parity). Without it a silent
    // half-open peer parked the reader forever, leaving the UDP proxy dead
    // until control reconnect. The deadline applies per read (each
    // completed frame — a Ping included — starts a fresh 60s), so an
    // active conn is never reaped.
    read_timeout: std::time::Duration,
    // Test-only injection point for the reader's cancel watch SENDER
    // (round-19 test-gap fix). `None` in production. When set, the reader
    // subscribes to the injected channel instead of the internal one, so a
    // test can fire the reader-cancel tick directly. The reader select
    // treats a true value as a break; a false-to-false tick (two
    // back-to-back sends) is a benign wakeup that MUST NOT strand a
    // partially-read frame — the persisted `read_fut` (M1) survives it.
    reader_cancel_override: Option<tokio::sync::watch::Sender<bool>>,
) {
    // write_msg_v2_nof skips the flush syscall. That is only safe for a raw
    // TcpStream: TLS/mux/WS-wrapped streams buffer internally and would leave
    // frames in flight without flush — and a CipherWriter must flush to emit
    // its IV.
    let no_flush = work_conn.try_tcp().is_some() && !use_enc;
    let udp_codec_opt = if udp_packet_codec.is_empty() {
        None
    } else {
        Some(udp_packet_codec.as_str())
    };
    let Some((w_r, w_w)) = try_split_work_halves(work_conn) else {
        return;
    };
    // Provider-segment encryption (Go parity): when the UDP proxy configures
    // use_encryption, the work conn carries a CipherStream (AES-128-CFB,
    // derive_key(token)) with the V1/V2 frame protocol inside it — matching
    // the client side (frp-client work_conn.rs) and Go's
    // libio.WithEncryption(rwc, token) on the UDP proxy work conn.
    let w_r: Box<dyn tokio::io::AsyncRead + Unpin + Send> = if use_enc {
        Box::new(CipherReader::new(w_r, enc_key))
    } else {
        w_r
    };
    let mut w_w: Box<dyn tokio::io::AsyncWrite + Unpin + Send> = if use_enc {
        // Audit B2: OS-RNG failure (IV generation) ends this work conn
        // instead of aborting the process.
        match CipherWriter::new(w_w, enc_key) {
            Ok(w) => Box::new(w),
            Err(e) => {
                tracing::warn!(error = %e, "udp work conn: IV generation failed");
                return;
            }
        }
    } else {
        w_w
    };
    // Buffer the frame reads: read_msg_v1/v2 issue two read_exact calls per
    // packet (header + payload), so BufReader amortizes them into one
    // syscall per packet — and one syscall for several small packets. The
    // write half is untouched (separate object), so no flush semantics
    // change.
    let mut w_r = tokio::io::BufReader::with_capacity(16 * 1024, w_r);
    let (cancel_tx, cancel_rx) = match reader_cancel_override {
        // Subscribe to the injected channel so the reader's cancel watch
        // observes the same sender the test fires (and the writer below
        // still reaches the reader with its exit signal).
        Some(tx) => {
            let rx = tx.subscribe();
            (tx, rx)
        }
        None => tokio::sync::watch::channel(false),
    };

    let sock_reader = sock.clone();
    let reader_name = proxy_name.clone();
    let mut reader_cancel = cancel_rx.clone();
    let cancel_reader = cancel.clone();
    // UDP bandwidth limiting (frp-rs extension; Go frp v0.70.1 has no UDP
    // limiter). Go v0.71.0 parity for the model: ONE per-proxy shared
    // limiter created at registration (mode == "server"/"both"), wrapping
    // BOTH directions with the same bucket (proxy.go single-`rate.Limiter`
    // semantics). Both bridge tasks clone the Arc; empty/unset rate (0)
    // stays unlimited (limiter is None).
    let reader_lim = bw_limiter.clone();
    let reader = async move {
        debug!(proxy_name = %reader_name, "UDP work conn reader task started for '{}'", reader_name);
        let mut scratch: Vec<u8> = Vec::new();
        // M1 (audit §4 示例 A): each frame read is stack-pinned via
        // `tokio::pin!` (zero `Box::pin` heap allocation per packet) and polled
        // inside an inner loop so benign `reader_cancel.changed()` wakeups
        // (`false -> false`) or lazy-watchdog re-arms never drop or restart a
        // partially-read frame. `idle` uses lazy deadline re-arming: frames
        // only stamp `last_activity` (zero timer-wheel resets on the hot path);
        // when `idle` fires, it re-arms once to `last_activity + read_timeout`
        // if activity occurred since the previous arm, otherwise expires.
        let mut last_activity = tokio::time::Instant::now();
        let idle = tokio::time::sleep_until(last_activity + read_timeout);
        tokio::pin!(idle);
        'frames: loop {
            let result = {
                let read_fut = read_one_udp_frame(&mut w_r, &mut scratch, v2, udp_codec_opt);
                tokio::pin!(read_fut);
                loop {
                    tokio::select! {
                        biased;
                        _ = cancel_reader.cancelled() => break 'frames,
                        changed = reader_cancel.changed() => {
                            if changed.is_err() || *reader_cancel.borrow() {
                                break 'frames;
                            }
                            continue;
                        }
                        frame = &mut read_fut => {
                            // A real frame (Ping/Pong included) refreshes
                            // `last_activity`; `idle` is only re-armed lazily
                            // when it fires (zero timer-wheel churn per packet).
                            last_activity = tokio::time::Instant::now();
                            break frame;
                        }
                        // M1: 60s of frame silence (Go udp.go read-deadline
                        // parity) = dead/half-open peer. Listed AFTER the read
                        // arm (biased select) so a frame ready at deadline
                        // expiry is still delivered.
                        _ = &mut idle => {
                            let deadline = last_activity + read_timeout;
                            if tokio::time::Instant::now() < deadline {
                                idle.as_mut().reset(deadline);
                                continue;
                            }
                            break Err(frp_core::Error::Protocol(
                                format!(
                                    "UDP work conn read deadline ({read_timeout:?}) expired with no frame from the client"
                                )
                                .into(),
                            ));
                        }
                    }
                }
            };
            match result {
                // Native-address form (binary codec): the destination is
                // already a SocketAddr — send directly, no text round trip.
                Ok(UdpBinaryRead::Socket(pkt)) => {
                    if let Some(lim) = reader_lim.as_ref() {
                        frp_core::bandwidth::BandwidthLimiter::consume_shared(
                            lim,
                            pkt.content.len(),
                        )
                        .await;
                    }
                    if let Err(e) = sock_reader.send_to(&pkt.content, pkt.remote_addr).await {
                        debug!(proxy_name = %reader_name, error = %e,
                            "UDP send_to failed for '{}': {}", reader_name, e);
                    }
                }
                Ok(UdpBinaryRead::Message(FrpMessage::UDPPacket(up))) => {
                    // Rate-limit only bytes actually forwarded. Counting a
                    // dropped (malformed, no remote_addr) packet against the
                    // budget without delivering it would silently bill the
                    // user for nothing — refund=true by consuming only here,
                    // and log the drop for diagnosability.
                    if let Some(ref remote) = up.remote_addr {
                        if let Some(lim) = reader_lim.as_ref() {
                            frp_core::bandwidth::BandwidthLimiter::consume_shared(
                                lim,
                                up.content.len(),
                            )
                            .await;
                        }
                        // Prefer a direct `SocketAddr` (no per-packet String
                        // alloc + reparse of the destination, audit #14a); fall
                        // back to the string form when the address carries an
                        // IPv6 zone that `SocketAddr` cannot express.
                        if let Some(dest) = udp_dest_socket_addr(remote) {
                            if let Err(e) = sock_reader.send_to(&up.content, dest).await {
                                debug!(proxy_name = %reader_name, error = %e,
                                    "UDP send_to failed for '{}': {}", reader_name, e);
                            }
                        } else if let Err(e) =
                            sock_reader.send_to(&up.content, remote.to_string()).await
                        {
                            debug!(proxy_name = %reader_name, error = %e,
                                "UDP send_to failed for '{}': {}", reader_name, e);
                        }
                    } else {
                        debug!(
                            proxy_name = %reader_name,
                            bytes = up.content.len(),
                            "UDP work conn for '{}': dropped datagram with no remote_addr (malformed)",
                            reader_name
                        );
                    }
                }
                Ok(UdpBinaryRead::Message(FrpMessage::Ping(_)))
                | Ok(UdpBinaryRead::Message(FrpMessage::Pong(_))) => continue,
                Ok(UdpBinaryRead::Message(other)) => {
                    debug!(proxy_name = %reader_name, msg_type = %other.v1_type_byte(),
                        "UDP work conn for '{}': unexpected msg 0x{:02x}", reader_name, other.v1_type_byte());
                }
                Err(e) => {
                    debug!(proxy_name = %reader_name, error = %e,
                        "UDP work conn for '{}' read closed: {}", reader_name, e);
                    break;
                }
            }
        }
    };

    let writer_name = proxy_name.clone();
    let mut writer_cancel = cancel_rx;
    let cancel_writer = cancel;
    let writer_lim = bw_limiter.clone();
    let writer = async move {
        debug!(proxy_name = %writer_name, "UDP work conn writer task started for '{}'", writer_name);
        let mut buf = vec![0u8; udp_packet_size];
        // local_addr is loop-invariant (comes from proxy config). Move the
        // owned value into each packet and back out afterwards, so the
        // Option<UdpAddr> String heap allocs happen once per bridge instead
        // of once per packet. Single-task writer: no concurrency risk.
        let mut local_addr = local_addr;
        // Audit item 6: pre-encode the loop-invariant local once per bridge
        // for the V2 binary codec — the per-datagram `UdpAddr` ip String
        // re-parse is gone. Validation happens here instead of on the first
        // datagram; a bad config local fails the bridge the same way (writer
        // exits, supervisor requests a replacement) but without the loop.
        let local_enc: Option<frp_core::udp_binary::PreEncodedUdpAddr> = match local_addr
            .as_ref()
            .map(frp_core::udp_binary::pre_encode_udp_addr)
            .transpose()
        {
            Ok(enc) => enc,
            Err(e) => {
                warn!(proxy_name = %writer_name, error = %e,
                        "UDP work conn writer for '{}': invalid local address: {}", writer_name, e);
                return;
            }
        };
        // Spare Vec for the packet content on the JSON path (V2 binary encodes
        // straight from `&buf[..n]` without touching `spare`).
        let mut spare: Vec<u8> = if v2 && udp_codec_opt.is_some() {
            Vec::new()
        } else {
            Vec::with_capacity(udp_packet_size)
        };
        // Reused wire buffer for the V2 binary codec (8B header + 2B type ID +
        // encoded packet) and for the V1/V2 JSON serializer.
        let mut wire_scratch: Vec<u8> = Vec::with_capacity(udp_packet_size + 64);
        // Only coalesce bursts on unthrottled buffered/encrypted V2 transports:
        // when `writer_lim` is active, flushing per packet prevents already-
        // written packets from stalling behind the next packet's limiter sleep
        // and keeps cancellation responsive; V1 does not flush per packet.
        let batch_flush = !no_flush && v2 && writer_lim.is_none();
        'writer: loop {
            let received = tokio::select! {
                biased;
                _ = cancel_writer.cancelled() => break,
                changed = writer_cancel.changed() => {
                    if changed.is_err() || *writer_cancel.borrow() { break; }
                    continue;
                }
                result = sock.recv_from(&mut buf) => result,
            };
            let (mut n, mut src) = match received {
                Ok(pair) => pair,
                Err(e) => {
                    debug!(proxy_name = %writer_name, error = %e,
                        "UDP recv_from error for '{}': {}", writer_name, e);
                    break;
                }
            };
            // Write this datagram plus up to `UDP_FLUSH_BATCH_MAX - 1`
            // immediately-queued datagrams, then flush `w_w` ONCE at the end
            // of the burst (when `!no_flush`).
            let mut written_in_burst = 0usize;
            let mut fatal_recv_err: Option<std::io::Error> = None;
            loop {
                if let Some(lim) = writer_lim.as_ref() {
                    frp_core::bandwidth::BandwidthLimiter::consume_shared(lim, n).await;
                }
                let result = if v2 && udp_codec_opt.is_some() {
                    // V2 binary codec fast path: encode directly from `&buf[..n]`
                    // into `wire_scratch` with 8B V2 frame header headroom —
                    // zero intermediate `spare` copy and zero `write_v2_frame_raw`
                    // merge alloc/copy.
                    wire_scratch.clear();
                    wire_scratch.resize(V2_FRAME_HEADER_LEN, 0);
                    wire_scratch.extend_from_slice(&msg::V2_TYPE_UDP_PACKET_BINARY.to_be_bytes());
                    match frp_core::udp_binary::encode_udp_packet_binary_local_pre(
                        &buf[..n],
                        local_enc.as_ref(),
                        &src,
                        &mut wire_scratch,
                    ) {
                        Err(e) => Err(frp_core::Error::Protocol(
                            format!("encode binary UDP packet: {e}").into(),
                        )),
                        Ok(()) => {
                            write_v2_frame_in_place(
                                &mut w_w,
                                V2_FRAME_TYPE_MESSAGE,
                                0,
                                &mut wire_scratch,
                            )
                            .await
                        }
                    }
                } else {
                    spare.clear();
                    spare.extend_from_slice(&buf[..n]);
                    let content = std::mem::take(&mut spare);
                    let pkt = FrpMessage::UDPPacket(msg::UDPPacket {
                        content,
                        local_addr: local_addr.take(),
                        remote_addr: Some(msg::UdpAddr {
                            // Go net.IP.String() collapses IPv4-mapped
                            // IPv6 to the dotted-quad form; mirror that
                            // on the V1 JSON path too (same normalization
                            // as the V2 binary codec, review finding C1).
                            ip: match src.ip() {
                                std::net::IpAddr::V6(v6) => v6
                                    .to_ipv4_mapped()
                                    .map(|v4| v4.to_string())
                                    .unwrap_or_else(|| src.ip().to_string()),
                                _ => src.ip().to_string(),
                            },
                            port: src.port(),
                            zone: String::new(),
                        }),
                    });
                    let r = if v2 {
                        write_msg_v2_with_udp_codec(
                            &mut w_w,
                            &pkt,
                            udp_codec_opt,
                            true, // flushed once at burst end below
                            &mut wire_scratch,
                        )
                        .await
                    } else {
                        // Same scratch on the V1 path: `write_v1_frame`
                        // allocates one Vec per frame, this reuses the
                        // loop's buffer (wire bytes identical — the
                        // scratch is cleared per call; audit §3 item 1).
                        write_v1_frame_scratch(&mut w_w, &pkt, &mut wire_scratch).await
                    };
                    // Return the invariant values to their locals for the
                    // next packet before checking the write result.
                    if let FrpMessage::UDPPacket(p) = pkt {
                        local_addr = p.local_addr;
                        spare = p.content;
                    }
                    r
                };
                if let Err(e) = result {
                    debug!(proxy_name = %writer_name, error = %e,
                        "UDP work conn write failed for '{}': {}", writer_name, e);
                    break 'writer;
                }
                written_in_burst += 1;
                if !batch_flush || written_in_burst >= UDP_FLUSH_BATCH_MAX {
                    break;
                }
                match sock.try_recv_from(&mut buf) {
                    Ok(pair) => {
                        n = pair.0;
                        src = pair.1;
                    }
                    Err(e)
                        if matches!(
                            e.kind(),
                            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                        ) =>
                    {
                        break
                    }
                    Err(e) => {
                        fatal_recv_err = Some(e);
                        break;
                    }
                }
            }
            if !no_flush && v2 {
                if let Err(e) = w_w.flush().await {
                    debug!(proxy_name = %writer_name, error = %e,
                        "UDP work conn flush failed for '{}': {}", writer_name, e);
                    break;
                }
            }
            if let Some(e) = fatal_recv_err {
                debug!(proxy_name = %writer_name, error = %e,
                    "UDP recv_from error for '{}': {}", writer_name, e);
                break;
            }
        }
    };

    tokio::pin!(reader, writer);
    tokio::select! {
        _ = &mut reader => {
            debug!(proxy_name = %proxy_name, "UDP reader exited; draining then cancelling writer");
            // Best-effort signal to the writer; a closed watch channel is fine.
            let _ = cancel_tx.send(true);
            // Give the writer a bounded window to drain before we drop it.
            let _ = tokio::time::timeout(
                std::time::Duration::from_millis(100),
                &mut writer,
            )
            .await;
        }
        _ = &mut writer => {
            debug!(proxy_name = %proxy_name, "UDP writer exited; draining then cancelling reader");
            // Best-effort signal to the reader; a closed watch channel is fine.
            let _ = cancel_tx.send(true);
            // Give the reader a bounded window to drain before we drop it.
            let _ = tokio::time::timeout(
                std::time::Duration::from_millis(100),
                &mut reader,
            )
            .await;
        }
    }
}

/// Server-side UDP work-conn read deadline (Go server/proxy/udp.go
/// `workConnReaderFn` SetReadDeadline(60s) parity, M1 audit round 3). The
/// client pings at a FIXED 30s (audit F1 — Go client/proxy/udp.go
/// heartbeatFn hardcodes 30s, no config knob; frp-rs matches), so 60s
/// without ANY frame — a Ping included — means the peer is gone or the
/// conn is half-open.
pub(super) const UDP_WORK_CONN_READ_TIMEOUT: std::time::Duration =
    std::time::Duration::from_secs(60);

/// Re-request a UDP work conn after the previous one died (M1, audit
/// round 3). Mirrors Go's udpWorker replacement loop
/// (server/proxy/udp.go:184-243): a UDP proxy needs one live work conn
/// for its lifetime, and work-conn death must not strand it until control
/// reconnect. The cancel guard lives at the call site — a proxy close or
/// control teardown must not re-request. The existence guard in
/// `handle_udp_work_conn` closes the remaining cancel-vs-send race (a
/// close that lands between the guard check here and the internal send).
async fn request_udp_work_conn_replacement(
    internal_tx: &tokio::sync::mpsc::Sender<crate::state::InternalMsg>,
    proxy_name: &str,
    reason: &str,
) {
    if let Err(e) = internal_tx
        .send(crate::state::InternalMsg::UdpNeedsWorkConn {
            proxy_name: proxy_name.to_string(),
        })
        .await
    {
        debug!(
            proxy_name = %proxy_name,
            error = %e,
            "UDP work-conn re-request after {reason} failed for '{}': {}",
            proxy_name,
            e
        );
    }
}

/// Assign a work connection to a UDP proxy for bidirectional data forwarding.
/// Matches Go frp v0.69.1 behavior: sends StartWorkConn, then bridges
/// UDP socket ↔ work connection via UDPPacket messages.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn assign_udp_work_conn(
    work_conn: IoStream,
    proxy_name: &str,
    udp_sockets: &std::collections::HashMap<String, std::sync::Arc<tokio::net::UdpSocket>>,
    local_addr: Option<msg::UdpAddr>,
    use_enc: bool,
    enc_key: [u8; 16],
    v2: bool,
    udp_packet_size: usize,
    bw_limiter: Option<frp_core::bandwidth::SharedBandwidthLimiter>,
    cancel: tokio_util::sync::CancellationToken,
    udp_packet_codec: String,
    // M1 (audit round 3): internal channel back to the control loop — used
    // to re-request a replacement work conn when this one dies.
    internal_tx: tokio::sync::mpsc::Sender<crate::state::InternalMsg>,
) {
    let mut work_conn = work_conn;
    let sock = match udp_sockets.get(proxy_name) {
        Some(s) => s.clone(),
        None => {
            // Proxy closed between the pending_udp enqueue and this work
            // conn's arrival (CloseProxy removed the socket) — nothing to
            // assign to, and no re-request: the proxy is gone.
            warn!(proxy_name = %proxy_name, "UDP socket not found for proxy '{}'", proxy_name);
            return;
        }
    };
    let proxy_name = proxy_name.to_string();

    // Control is shutting down (supersession / disconnect) — do not start a
    // bridge that would immediately be cancelled anyway.
    if cancel.is_cancelled() {
        debug!(proxy_name = %proxy_name, "Control is shutting down, not starting UDP bridge for '{}'", proxy_name);
        return;
    }

    // Send StartWorkConn to tell the client which proxy to associate
    let swc = FrpMessage::StartWorkConn(Box::new(msg::StartWorkConn {
        proxy_name: proxy_name.clone(),
        src_addr: None,
        dst_addr: None,
        src_port: None,
        dst_port: None,
        error: None,
        use_encryption: if use_enc { Some(true) } else { None },
        use_compression: None,
        nat_hole_sid: None,
        nat_hole_visitor_addr: None,
        sk: None,
    }));
    if v2 {
        if let Err(e) = work_conn.write_v2_frame(&swc).await {
            warn!(proxy_name = %proxy_name, error = %e, "Failed to send StartWorkConn (V2) for UDP '{}': {}", proxy_name, e);
            // M1: the fresh work conn died before the bridge could start
            // and the pending_udp entry was already consumed — re-request
            // so the proxy is not stranded.
            request_udp_work_conn_replacement(
                &internal_tx,
                &proxy_name,
                "StartWorkConn (V2) write failure",
            )
            .await;
            return;
        }
    } else if let Err(e) = work_conn.write_v1_frame(&swc).await {
        warn!(proxy_name = %proxy_name, error = %e, "Failed to send StartWorkConn for UDP '{}': {}", proxy_name, e);
        // M1: same as the V2 branch above.
        request_udp_work_conn_replacement(&internal_tx, &proxy_name, "StartWorkConn write failure")
            .await;
        return;
    }
    debug!(proxy_name = %proxy_name, "UDP work conn assigned to '{}', starting bridge supervisor", proxy_name);

    let log_proxy_name = proxy_name.clone();
    let bridge_cancel = cancel.clone();
    let req_tx = internal_tx;
    tokio::spawn(async move {
        // Await the bridge's JoinHandle instead of dropping it: if the task
        // panics, JoinError carries the panic payload (audit round 5, MEDIUM).
        // The RAII ConnGuard still releases the slot during unwind; this just
        // preserves the panic cause in the logs.
        let handle = tokio::spawn(run_udp_work_conn(
            work_conn,
            sock,
            proxy_name,
            local_addr,
            use_enc,
            enc_key,
            v2,
            udp_packet_size,
            bw_limiter,
            bridge_cancel,
            udp_packet_codec,
            UDP_WORK_CONN_READ_TIMEOUT,
            None,
        ));
        if let Err(e) = handle.await {
            if e.is_panic() {
                log_bridge_panic(&log_proxy_name, "UDP bridge", e.into_panic());
            }
        }
        // M1 (audit round 3): work-conn death (EOF / read error / 60s
        // frame silence) must not strand the UDP proxy until control
        // reconnect — Go's udpWorker loop replaces the conn
        // (server/proxy/udp.go:184-243). Re-request a replacement unless
        // the exit was a cancellation (proxy closed or control teardown:
        // the socket entry is gone, and a ReqWorkConn would dial a work
        // conn into nothing). The existence guard in handle_udp_work_conn
        // closes the remaining cancel-vs-send race.
        if !cancel.is_cancelled() {
            request_udp_work_conn_replacement(&req_tx, &log_proxy_name, "work-conn death").await;
        }
    });
}

/// Build a `SocketAddr` for `remote` without allocating, when the address is a
/// plain IPv4/IPv6 (no zone). Returns `None` when the ip does not parse or the
/// address carries an IPv6 scope zone — the caller falls back to the string
/// form in that case. Hot-path helper for the UDP reader (audit #14a): avoids
/// a `String` alloc + reparse per datagram in the common case.
fn udp_dest_socket_addr(remote: &msg::UdpAddr) -> Option<std::net::SocketAddr> {
    if !remote.zone.is_empty() {
        return None;
    }
    let ip: std::net::IpAddr = remote.ip.parse().ok()?;
    Some(std::net::SocketAddr::new(ip, remote.port))
}
