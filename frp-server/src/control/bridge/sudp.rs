//! Message-level SUDP bridge for mixed packet encodings.

use super::*;

/// Message-level SUDP bridge (Go frp v0.71.0 `joinSUDPMessageBridge`).
///
/// Used when the visitor segment and the provider segment negotiate
/// different packet encodings (e.g. a V1/JSON visitor talking to a
/// V2/binary provider during an upgrade). A plain byte-stream relay would
/// make the provider misparse the visitor's frames as its own protocol
/// ("unexpected V2 frame type"), so every `UDPPacket` is decoded on the
/// source side and re-encoded on the destination side.
///
/// Direction semantics match Go:
/// - visitor → provider: `UDPPacket` forwarded, `Ping` dropped
///   (`bridgeSUDPVisitorToProxy`);
/// - provider → visitor: `UDPPacket` forwarded, `Ping` forwarded
///   (`bridgeSUDPProxyToVisitor`).
///
/// `Pong` is ignored on both sides (frp-rs UDP data planes treat
/// Ping/Pong as keepalive and never forward them); any other message type
/// is a protocol violation and closes the pair.
#[allow(clippy::too_many_arguments)]
pub(super) async fn run_sudp_message_bridge(
    work_conn: IoStream,
    req: PendingRequest,
    proxy_info: Option<Arc<crate::proxy::ProxyInfo>>,
    encryption_key: [u8; 16],
    metrics: Arc<frp_core::metrics::ProxyMetrics>,
    state: Arc<AppState>,
    provider_v2: bool,
    provider_codec: &str,
) {
    let _guard = ConnGuard::new(metrics.clone());
    let _drain = ActiveGuard::new(&state);
    let visitor_v2 = req.visitor_v2;
    let visitor_codec = req.visitor_udp_packet_codec.as_str();

    // Visitor-segment encryption/compression (Go 三段式第 1 段): identical
    // decision to the byte-stream bridge — sk-derived key when the visitor
    let visitor_enc_key = visitor_encryption_key(
        proxy_info.as_ref(),
        &req.proxy_name,
        req.visitor_use_encryption,
    );
    let Some((v_r, mut v_w)) =
        try_split_user_side(visitor_enc_key, req.visitor_use_compression, req.user_conn)
    else {
        return;
    };
    // Provider-segment encryption (token-derived key) wraps the work halves
    // before the message loop, matching the byte-stream bridge.
    let Some((w_r, w_w)) = try_split_work_halves(work_conn) else {
        return;
    };
    let w_r: frp_core::transport::BoxedReadHalf = if req.use_encryption {
        Box::new(CipherReader::new(w_r, encryption_key))
    } else {
        w_r
    };
    let mut w_w: frp_core::transport::BoxedWriteHalf = if req.use_encryption {
        // Audit B2: OS-RNG failure (IV generation) ends this bridge instead
        // of aborting the process.
        match CipherWriter::new(w_w, encryption_key) {
            Ok(w) => Box::new(w),
            Err(e) => {
                tracing::warn!(error = %e, "udp bridge: IV generation failed");
                return;
            }
        }
    } else {
        w_w
    };
    // Frame reads issue two read_exact calls per message; buffer them.
    let mut v_r = tokio::io::BufReader::with_capacity(16 * 1024, v_r);
    let mut w_r = tokio::io::BufReader::with_capacity(16 * 1024, w_r);

    let visitor_codec_opt = if visitor_codec.is_empty() {
        None
    } else {
        Some(visitor_codec)
    };
    let provider_codec_opt = if provider_codec.is_empty() {
        None
    } else {
        Some(provider_codec)
    };
    let proxy_name = req.proxy_name.clone();

    // Direction 1: visitor → provider. Ping is dropped (Go
    // bridgeSUDPVisitorToProxy). Traffic is accumulated locally and flushed
    // to metrics periodically so the live dashboard/otel counters are not
    // frozen at 0 for the whole (possibly long-lived) bridge — and so an
    // aborted/joined-interrupted task does not lose the session's bytes or
    // dump them wholesale into the teardown day's bucket (#4).
    const SUDP_TRAFFIC_REPORT_EVERY: u32 = 64;
    let visitor_to_provider = async {
        // Reusable payload buffer for the V2 UDP read path.
        let mut scratch: Vec<u8> = Vec::new();
        // Reusable binary-codec wire buffer (write side; `scratch` above is
        // the read side).
        let mut wire_scratch: Vec<u8> = Vec::new();
        let mut fwd_in: u64 = 0;
        let mut report = 0u32;
        loop {
            let read = if visitor_v2 {
                read_msg_v2_with_udp_codec(&mut v_r, visitor_codec_opt, &mut scratch).await
            } else {
                read_msg_v1(&mut v_r).await
            };
            let msg = match read {
                Ok(m) => m,
                Err(e) => {
                    debug!(
                        proxy_name = %proxy_name,
                        error = %e,
                        "SUDP message bridge: visitor read closed: {}",
                        e
                    );
                    break;
                }
            };
            match &msg {
                FrpMessage::UDPPacket(pkt) => {
                    fwd_in += pkt.content.len() as u64;
                }
                FrpMessage::Ping(_) | FrpMessage::Pong(_) => {
                    // Go drops SUDP pings on the visitor→proxy leg.
                    continue;
                }
                other => {
                    warn!(
                        proxy_name = %proxy_name,
                        type_byte = %other.v1_type_byte(),
                        "SUDP message bridge: unexpected visitor message 0x{:02x}",
                        other.v1_type_byte()
                    );
                    break;
                }
            }
            let write = if provider_v2 {
                write_msg_v2_with_udp_codec(
                    &mut w_w,
                    &msg,
                    provider_codec_opt,
                    false,
                    &mut wire_scratch,
                )
                .await
            } else {
                write_msg_v1(&mut w_w, &msg).await
            };
            if let Err(e) = write {
                debug!(
                    proxy_name = %proxy_name,
                    error = %e,
                    "SUDP message bridge: provider write failed: {}",
                    e
                );
                break;
            }
            report += 1;
            if report >= SUDP_TRAFFIC_REPORT_EVERY {
                metrics.record_traffic(fwd_in, 0);
                fwd_in = 0;
                report = 0;
            }
        }
        metrics.record_traffic(fwd_in, 0);
    };

    // Direction 2: provider → visitor. Ping is forwarded (Go
    // bridgeSUDPProxyToVisitor). Traffic is accumulated locally and flushed
    // periodically (see direction 1's rationale: live counters, no loss on
    // abort, no single-day dump).
    let provider_to_visitor = async {
        // Reusable payload buffer for the V2 UDP read path (own buffer; the
        // two directions run concurrently via tokio::join!).
        let mut scratch: Vec<u8> = Vec::new();
        // Reusable binary-codec wire buffer (write side; `scratch` above is
        // the read side).
        let mut wire_scratch: Vec<u8> = Vec::new();
        let mut fwd_out: u64 = 0;
        let mut report = 0u32;
        loop {
            let read = if provider_v2 {
                read_msg_v2_with_udp_codec(&mut w_r, provider_codec_opt, &mut scratch).await
            } else {
                read_msg_v1(&mut w_r).await
            };
            let msg = match read {
                Ok(m) => m,
                Err(e) => {
                    debug!(
                        proxy_name = %proxy_name,
                        error = %e,
                        "SUDP message bridge: provider read closed: {}",
                        e
                    );
                    break;
                }
            };
            match &msg {
                FrpMessage::UDPPacket(pkt) => {
                    fwd_out += pkt.content.len() as u64;
                }
                FrpMessage::Ping(_) => {
                    // Go forwards SUDP pings provider→visitor
                    // (bridgeSUDPProxyToVisitor).
                }
                FrpMessage::Pong(_) => {
                    // Pong is never forwarded (Go has no Pong in this
                    // direction; frp-rs data planes treat Ping/Pong as
                    // keepalive and ignore them).
                    continue;
                }
                other => {
                    warn!(
                        proxy_name = %proxy_name,
                        type_byte = %other.v1_type_byte(),
                        "SUDP message bridge: unexpected provider message 0x{:02x}",
                        other.v1_type_byte()
                    );
                    break;
                }
            }
            let write = if visitor_v2 {
                write_msg_v2_with_udp_codec(
                    &mut v_w,
                    &msg,
                    visitor_codec_opt,
                    false,
                    &mut wire_scratch,
                )
                .await
            } else {
                write_msg_v1(&mut v_w, &msg).await
            };
            if let Err(e) = write {
                debug!(
                    proxy_name = %proxy_name,
                    error = %e,
                    "SUDP message bridge: visitor write failed: {}",
                    e
                );
                break;
            }
            report += 1;
            if report >= SUDP_TRAFFIC_REPORT_EVERY {
                metrics.record_traffic(0, fwd_out);
                fwd_out = 0;
                report = 0;
            }
        }
        metrics.record_traffic(0, fwd_out);
    };

    tokio::join!(visitor_to_provider, provider_to_visitor);
    debug!(proxy_name = %proxy_name, "SUDP message bridge completed");
}
