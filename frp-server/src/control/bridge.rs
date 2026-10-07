use std::future::Future;
use std::panic::AssertUnwindSafe;
use std::pin::Pin;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWriteExt, ReadBuf};
use tracing::{debug, warn};

use futures_util::FutureExt;

use frp_core::cipher_stream::{CipherReader, CipherWriter};
use frp_core::encryption::derive_key;
use frp_core::metrics::ConnGuard;
use frp_core::msg::{self, FrpMessage};
use frp_core::protocol::{
    read_msg_v1, read_msg_v2_udp_binary_socket, read_msg_v2_with_udp_codec, write_msg_v1,
    write_msg_v2_with_udp_codec, write_v1_frame_scratch, write_v2_frame_raw, UdpBinaryRead,
    V2_FRAME_TYPE_MESSAGE,
};
use frp_core::snappy_stream::{SnappyStreamReader, SnappyStreamWriter};
use frp_core::transport::{split_work_conn_halves, IoStream};

use crate::service::AppState;

use super::pool::PendingRequest;

mod injector;
use injector::ResponseHeaderInjector;

mod sudp;
use sudp::run_sudp_message_bridge;

mod udp;
pub(crate) use udp::assign_udp_work_conn;
#[cfg(test)]
use udp::run_udp_work_conn;
#[cfg(test)]
use udp::UDP_WORK_CONN_READ_TIMEOUT;

mod assign;
pub(crate) use assign::assign_work_to_proxy;
#[cfg(test)]
use assign::http_leg_head_deadline;

/// RAII guard that tracks an active bridge connection for graceful shutdown drain.
struct ActiveGuard(std::sync::Arc<AppState>);
impl ActiveGuard {
    fn new(state: &std::sync::Arc<AppState>) -> Self {
        state.active_connections.fetch_add(1, Ordering::Relaxed);
        Self(state.clone())
    }
}
impl Drop for ActiveGuard {
    fn drop(&mut self) {
        self.0.active_connections.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Log a bridge-task panic. Bridge tasks are spawned fire-and-forget and
/// their JoinHandles deliberately dropped, so a panic used to be silently
/// swallowed by Tokio (audit round 5, MEDIUM). The RAII `ConnGuard` still
/// releases the connection slot during unwind, but the panic cause was lost
/// — `catch_unwind` at the spawn sites preserves the diagnostic.
fn log_bridge_panic(proxy_name: &str, what: &str, p: Box<dyn std::any::Any + Send>) {
    let msg = p
        .downcast_ref::<&str>()
        .copied()
        .or_else(|| p.downcast_ref::<String>().map(|s| s.as_str()))
        .unwrap_or("(unknown)");
    tracing::error!(
        proxy_name = %proxy_name,
        panic = %msg,
        "Bridge task panicked: {what} (proxy '{}', panic: {})",
        proxy_name,
        msg
    );
}

/// Relay plain traffic between two IoStreams, preferring zero-copy splice
/// on Linux when both sides are raw TCP.
async fn relay_plain_fast(
    user_conn: IoStream,
    work_conn: IoStream,
    metrics: &Arc<frp_core::metrics::ProxyMetrics>,
) {
    relay_plain_fast_inner(user_conn, work_conn, metrics).await
}

/// Linux: try splice(2) zero-copy relay when both sides are raw TCP.
#[cfg(target_os = "linux")]
async fn relay_plain_fast_inner(
    user_conn: IoStream,
    work_conn: IoStream,
    metrics: &Arc<frp_core::metrics::ProxyMetrics>,
) {
    // Two-arm dispatch so the Tcp arm consumes the streams while the other
    // arm binds new mutable variables for the copy_bidirectional fallthrough.
    // try_tcp() (borrow check) then into_tcp() (owned) — no await between,
    // so the transport cannot change.
    if user_conn.try_tcp().is_some() && work_conn.try_tcp().is_some() {
        let user = user_conn
            .into_tcp()
            .expect("try_tcp confirmed raw TCP above");
        let work = work_conn
            .into_tcp()
            .expect("try_tcp confirmed raw TCP above");
        match frp_core::splice::bridge_splice(user, work).await {
            Ok((a, b)) => {
                metrics.record_traffic(a, b);
            }
            Err(e) => {
                tracing::warn!(error = %e, "splice bridge closed with error: {}", e);
            }
        }
    } else {
        // Pooled-buffer relay (P3): copy_bidirectional_with_sizes allocated
        // two fresh 32 KiB buffers per bridge call; PoolGuard recycles them
        // across connections (FRP_BRIDGE_BUF_KB still governs the size).
        match frp_core::bridge::relay_plain_pooled(user_conn, work_conn).await {
            Ok((a, b)) => {
                metrics.record_traffic(a, b);
            }
            Err(e) => {
                tracing::debug!(error = %e, "plain fast-path bridge closed: {}", e);
            }
        }
    }
}

/// Non-Linux: pooled-buffer bidirectional relay (splice(2) unavailable).
#[cfg(not(target_os = "linux"))]
async fn relay_plain_fast_inner(
    user_conn: IoStream,
    work_conn: IoStream,
    metrics: &Arc<frp_core::metrics::ProxyMetrics>,
) {
    match frp_core::bridge::relay_plain_pooled(user_conn, work_conn).await {
        Ok((a, b)) => {
            metrics.record_traffic(a, b);
        }
        Err(e) => {
            tracing::debug!(error = %e, "plain fast-path bridge closed: {}", e);
        }
    }
}

/// Type-erased user-side bridge halves: erasing the per-transport types lets
/// `bridge_encrypted` & friends share one monomorphization, and lets the
/// visitor-segment Cipher wrapper (`CipherReader`/`CipherWriter`) and the
/// plain boxed halves be handled uniformly.
type UserBridgeHalves = (
    Box<dyn tokio::io::AsyncRead + Unpin + Send>,
    Box<dyn tokio::io::AsyncWrite + Unpin + Send>,
);

/// Split the visitor (user) conn into bridge halves, wrapping them in
/// `CipherReader`/`CipherWriter` with `derive_key(sk)` when visitor-segment
/// encryption is enabled (`visitor_enc_key = Some(key)`) and in
/// `SnappyStreamReader`/`SnappyStreamWriter` when visitor-segment compression
/// is enabled (`visitor_comp`).
///
/// Wire order matches Go frp's `VisitorManager.NewConn` (`WithEncryption`
/// outer, `WithCompression` inner): write plaintext → snappy → CFB → socket,
/// so the enc+comp wrapper is `SnappyStreamReader::new(CipherReader::new(...))`
/// / `SnappyStreamWriter::new(CipherWriter::new(...))`. A compression-only
/// visitor wraps the raw halves in Snappy directly.
///
/// When the `compression` feature is disabled, `SnappyStream*` degrades to a
/// transparent passthrough, so a compression-only visitor bridges plaintext
/// (same behavior as the provider-segment `compress_chunk_into` passthrough).
///
/// Returns `Err` (with a warn-worthy message) only when the underlying
/// transport cannot be split (same guard as `split_work_conn_halves`).
fn split_user_side(
    visitor_enc_key: Option<[u8; 16]>,
    visitor_comp: bool,
    user_conn: IoStream,
) -> Result<UserBridgeHalves, &'static str> {
    let (u_r, u_w) = split_work_conn_halves(user_conn)?;
    let (u_r, u_w): UserBridgeHalves = if let Some(key) = visitor_enc_key {
        (
            Box::new(CipherReader::new(u_r, key)),
            // Audit B2: IV-generation failure is an error, not an abort.
            Box::new(CipherWriter::new(u_w, key).map_err(|_| "OS random generator failed")?),
        )
    } else {
        (u_r, u_w)
    };
    if visitor_comp {
        Ok((
            Box::new(SnappyStreamReader::new(u_r)),
            Box::new(SnappyStreamWriter::new(u_w)),
        ))
    } else {
        Ok((u_r, u_w))
    }
}

/// Compute the visitor-segment encryption key from the proxy's `sk`
/// (`derive_key(sk)`), when the visitor declared `use_encryption`. Empty sk is
/// treated as "no key": we warn and bridge plaintext (robustness over exact
/// Go parity — Go would PBKDF2 an empty string into a weak key). Shared by the
/// byte-stream and SUDP message bridges so the logic (and its warn) cannot
/// drift apart (audit #12).
fn visitor_encryption_key(
    proxy_info: Option<&std::sync::Arc<crate::proxy::ProxyInfo>>,
    proxy_name: &str,
    use_encryption: bool,
) -> Option<[u8; 16]> {
    if !use_encryption {
        return None;
    }
    match proxy_info
        .and_then(|p| p.sk.as_deref())
        .filter(|s| !s.is_empty())
    {
        Some(sk) => Some(derive_key(sk)),
        None => {
            warn!(
                proxy_name = %proxy_name,
                "visitor declared use_encryption but proxy '{}' has no secret_key; \
                 bridging visitor segment in plaintext",
                proxy_name
            );
            None
        }
    }
}

/// Checked split of the user-side (visitor-segment) conn: calls `split_user_side`
/// and turns the `Err(&'static str)` into a `warn!`-and-None, so call sites use
/// `let Some((u_r, u_w)) = try_split_user_side(...) else { return };` instead of
/// repeating the five-line warn-return match (audit #12 — the pattern drifted
/// across SUDP and byte-stream bridges).
fn try_split_user_side(
    visitor_enc_key: Option<[u8; 16]>,
    visitor_comp: bool,
    user_conn: IoStream,
) -> Option<UserBridgeHalves> {
    match split_user_side(visitor_enc_key, visitor_comp, user_conn) {
        Ok(pair) => Some(pair),
        Err(msg) => {
            warn!("{msg}");
            None
        }
    }
}

/// Checked split of the work-conn halves: turns the `Err(&'static str)` into a
/// `warn!`-and-None (audit #12, dedup of the repeated warn-return match).
fn try_split_work_halves(
    work_conn: IoStream,
) -> Option<(
    Box<dyn tokio::io::AsyncRead + Unpin + Send>,
    Box<dyn tokio::io::AsyncWrite + Unpin + Send>,
)> {
    match split_work_conn_halves(work_conn) {
        Ok(pair) => Some(pair),
        Err(msg) => {
            warn!("{msg}");
            None
        }
    }
}

/// Holds split user-side halves as one `AsyncRead`+`AsyncWrite` object so the
/// XTCP STCP fallback can keep its `copy_bidirectional` semantics via the
/// pooled relay `relay_plain_pooled` (both directions run to completion; the
/// work side is only shut down after the full bidirectional copy — avoids
/// the premature-FIN race that a join-of-two-halves bridge would
/// reintroduce).
struct UserSide<R, W> {
    r: R,
    w: W,
}

impl<R: AsyncRead + Unpin, W: tokio::io::AsyncWrite + Unpin> AsyncRead for UserSide<R, W> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.r).poll_read(cx, buf)
    }
}

impl<R: AsyncRead + Unpin, W: tokio::io::AsyncWrite + Unpin> tokio::io::AsyncWrite
    for UserSide<R, W>
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.w).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.w).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.w).poll_shutdown(cx)
    }
}

/// Bridge a user connection to a work connection for one proxy.
///
/// Runs inside the spawned bridge task. Extracted from `assign_work_to_proxy`
/// so the spawn site is a plain call and the bridge logic lives in its own
/// state machine instead of a 54 KiB inline closure.
#[inline(never)]
#[allow(clippy::too_many_arguments)]
async fn run_work_bridge(
    work_conn: IoStream,
    req: PendingRequest,
    proxy_info: Option<Arc<crate::proxy::ProxyInfo>>,
    encryption_key: [u8; 16],
    metrics: Arc<frp_core::metrics::ProxyMetrics>,
    header_timeout: Option<std::time::Duration>,
    state: Arc<AppState>,
    v2: bool,
) {
    let _guard = ConnGuard::new(metrics.clone());
    let _drain = ActiveGuard::new(&state);

    // --- Encryption decisions (Go frp three-stage model) ---
    // Provider segment (work conn): token-based encryption from the proxy
    // config (`req.use_encryption`). SUDP previously forced plaintext here —
    // the per-packet transform model is now aligned with Go's stream
    // encryption, so SUDP honors the provider-segment encryption too.
    // (SUDP compression stays off — see `comp_key` below.)
    let is_sudp = proxy_info.as_ref().is_some_and(|p| p.proxy_type == "sudp");
    let use_enc = req.use_encryption;

    // SUDP data plane: when the visitor and provider segments use the same
    // wire protocol + packet codec, the byte-stream bridge below is
    // correct (Go `libio.Join`); when they differ, Go frp v0.71.0 routes
    // the pair through `joinSUDPMessageBridge`, which decodes and re-encodes
    // every packet on each side. The mismatch happens during upgrades —
    // e.g. a V1/JSON visitor talking to a V2/binary provider — and a plain
    // byte-stream relay would make the provider misparse the visitor's
    // frames ("unexpected V2 frame type"). Route mismatches to the
    // message-level bridge; identical encodings keep the zero-copy path.
    if is_sudp {
        let provider_codec = proxy_info
            .as_ref()
            .map(|p| p.udp_packet_codec.clone())
            .unwrap_or_default();
        let visitor_codec = req.visitor_udp_packet_codec.as_str();
        let mixed = normalize_wire_protocol(v2) != normalize_wire_protocol(req.visitor_v2)
            || provider_codec != visitor_codec;
        if mixed {
            tracing::info!(
                proxy_name = %req.proxy_name,
                provider_wire = %normalize_wire_protocol(v2),
                provider_codec = %provider_codec,
                visitor_wire = %normalize_wire_protocol(req.visitor_v2),
                visitor_codec = %visitor_codec,
                "bridging mixed SUDP packet encodings (message-level bridge)"
            );
            return run_sudp_message_bridge(
                work_conn,
                req,
                proxy_info,
                encryption_key,
                metrics,
                state,
                v2,
                &provider_codec,
            )
            .await;
        }
    }

    // Visitor segment (user conn): sk-based encryption when the visitor
    // declared `use_encryption` in NewVisitorConn (Go three-stage model,
    // stage 1). The visitor conn is wrapped in CipherReader/CipherWriter with
    // `derive_key(sk)` and only then joined to the provider segment
    // (token encryption or plaintext) — two nested layers, mirroring Go's
    // three-stage model.
    //
    // Empty sk: Go frp would still PBKDF2 an empty string and encrypt (the
    // key is just weak); we warn and bridge plaintext to keep the tunnel
    // usable (robustness over exact parity).
    let visitor_enc_key = visitor_encryption_key(
        proxy_info.as_ref(),
        &req.proxy_name,
        req.visitor_use_encryption,
    );

    // Whether visitor-segment encryption/compression is on. The user conn is
    // NOT split here — each bridge branch below calls
    // `split_user_side(visitor_enc_key, visitor_comp, req.user_conn)`, which
    // wraps the halves in CipherReader/CipherWriter (when the key is present)
    // and SnappyStreamReader/SnappyStreamWriter (when compression is on),
    // keeping the plain IoStream available for the relay_plain_fast splice
    // path (only taken when neither wrapping applies). CipherWriter::poll_flush
    // already sends the IV eagerly, and the first write to the user side
    // carries it, so no manual IV flush is needed.
    let visitor_encrypted = visitor_enc_key.is_some();
    if visitor_encrypted {
        debug!(
            proxy_name = %req.proxy_name,
            "Visitor-segment encryption on for proxy '{}' (derive_key(sk))", req.proxy_name
        );
    }

    // Visitor-segment compression: from the visitor's NewVisitorConn
    // use_compression declaration (`[[visitors]] transport.useCompression`),
    // Go 三段式第 1 段. Applied in `split_user_side` below — Snappy stream
    // inside the CFB layer when visitor-segment encryption is also on.
    let visitor_comp = req.visitor_use_compression;
    if visitor_comp {
        debug!(
            proxy_name = %req.proxy_name,
            "Visitor-segment compression on for proxy '{}'", req.proxy_name
        );
    }

    // The per-proxy SHARED bandwidth limiter (F1/F2): created once at proxy
    // registration (build_proxy_info) when mode == "server"/"both" and a
    // rate is set; one bucket covers BOTH directions and all concurrent
    // connections (Go frp v0.71.0 single-`rate.Limiter` parity — the mode
    // gate lives at registration, not per bridge call). "client"/empty mode
    // is the client's responsibility (Go: server creates a limiter only in
    // "server" mode).
    let bw_limiter = proxy_info
        .as_ref()
        .and_then(|p| p.bandwidth_limiter.clone());

    // The response-header injector runs for EVERY plain-HTTP non-CONNECT
    // leg (`proxy_type == "http"`, NOT `starts_with("http")`); clone the
    // HashMap at bridge time instead of deep-cloning it into every pending
    // request at enqueue time. Uses the resolved metadata (bridge-time
    // re-fetch when the enqueue-time snapshot was None).
    //
    // The empty-map case is deliberate: when
    // `response_headers` is not configured the injector carries NO headers
    // and is a pure deadline-only pass-through — splice no-ops over the
    // empty map and the response bytes are byte-identical to the
    // injector-less bridge, with TWO deliberate wire mutations (round-16
    // + round-18 C3b): a final 204/304 head loses its framing headers at
    // the splice (Go's write-layer suppression — Content-Length and
    // Transfer-Encoding on both, Content-Type on a 304 — see the inject
    // branch above), and a declared body a lying backend writes behind
    // that head is consumed, never relayed. Exactly those two statuses
    // differ from the raw bridge by design.
    // But the leg still gets Go
    // ResponseHeaderTimeout parity: the injector's absolute deadline
    // (armed at construction, never extended by interim 1xx) must run for
    // http non-CONNECT legs even with no headers configured — Go's
    // ReverseProxy arms ResponseHeaderTimeoutS from the transport config,
    // independent of any ModifyResponse. Routing these legs through the
    // injector also removes the duplicate one-shot first-read timeout in
    // the frp-core bridge (see the injector arms below).
    //
    // The two exclusions mirror Go v0.71.0 exactly:
    //   * https tunnels: HTTPSProxyConfig (pkg/config/v1/proxy.go:369) has
    //     no ResponseHeaders field — a wire-declared response_headers on an
    //     https proxy is silently dropped by Go, and the bridge here sees
    //     raw TLS bytes anyway (injecting would corrupt the ciphertext).
    //   * CONNECT tunnels on an http proxy: Go's connectHandler joins raw
    //     (http.go:282-285) — no host rewrite, no ModifyResponse, no
    //     ResponseHeaderTimeout — so the injector must not splice into the
    //     tunnel stream nor arm a head deadline on it. `request_is_connect`
    //     is set by the two vhost HTTP send sites (h1 + h2c) and rides the
    //     PendingRequest, including across run_id group forwarders.
    let injector_headers = proxy_info
        .as_ref()
        .filter(|p| p.proxy_type == "http" && !req.request_is_connect)
        .map(|p| p.response_headers.clone());

    // For encrypted bridges, pre_read bytes are passed into bridge_encrypted
    // which writes them through the CipherWriter (matching Go frp streaming CFB).
    if use_enc {
        let key = encryption_key;
        let Some((u_r, u_w)) = try_split_user_side(visitor_enc_key, visitor_comp, req.user_conn)
        else {
            return;
        };
        // One boxed split for every IoStream variant — a single
        // monomorphization of bridge_encrypted instead of one per variant.
        let Some((w_r, w_w)) = try_split_work_halves(work_conn) else {
            return;
        };
        // SUDP provider-segment compression stays off in BOTH bridge modes:
        // bridge_encrypted's Snappy stream would be misread by the provider's
        // frame reader as a V1 header (sNaPpY magic → "invalid V1 msg length").
        // Go's streaming compression model for the per-packet SUDP plane is
        // not unified here yet — this change is encryption-focused.
        let comp_key = req.use_compression && !is_sudp;
        if let Some(headers) = injector_headers {
            // Response-header injection MUST observe plaintext: the work
            // conn carries AES-128-CFB ciphertext, so decrypt FIRST via
            // CipherReader, THEN wrap in the injector. Audit round-14 A1:
            // with use_compression the decrypted stream is STILL
            // Snappy-encoded — the bridge's own decompressor runs below any
            // reader passed as work_r — so a `SnappyStreamReader` goes
            // between the CipherReader and the injector, and the
            // `_decompressed_read` bridge variant skips its read-side decode
            // (the user→work write side keeps compressing). Go parity: frp's
            // vhost ReverseProxy/ModifyResponse sits ABOVE the transport's
            // snappy layer and always injects into plaintext. Without this a
            // compressed http proxy + response_headers would splice into
            // Snappy bytes (corrupt stream) or silently never inject.
            let decrypted: Box<dyn AsyncRead + Unpin + Send> =
                Box::new(CipherReader::new(w_r, key));
            let injector_r: Box<dyn AsyncRead + Unpin + Send> = if comp_key {
                Box::new(frp_core::snappy_stream::SnappyStreamReader::new(decrypted))
            } else {
                decrypted
            };
            let injector = ResponseHeaderInjector::new(injector_r, headers, header_timeout);
            // The injector owns the absolute response-head deadline (armed
            // at construction above); the frp-core bridge gets NO one-shot
            // header_timeout here — a duplicate would consume on the first
            // read (an interim 100 already served raw would burn it, and a
            // backend stalling after interim bytes would park the bridge
            // task + conns forever). The injector's TimedOut errors through
            // the bridge Err arm into the Go-shaped 504.
            frp_core::bridge::bridge_encrypted_decompressed_read(
                u_r,
                u_w,
                injector,
                w_w,
                &key,
                comp_key,
                req.pre_read,
                bw_limiter.as_ref(),
                Some(metrics.clone()),
            )
            .await;
            // Matches the original inline closure: the injector path skips
            // the "bridge completed" debug below.
            return;
        }
        frp_core::bridge::bridge_encrypted(
            u_r,
            u_w,
            w_r,
            w_w,
            &key,
            comp_key,
            req.pre_read,
            bw_limiter.as_ref(),
            Some(metrics.clone()),
            false,
        )
        .await;
    } else {
        // Pass VHost pre-read bytes through bridge_plain so the bridge
        // can coordinate: write pre_read first, then skip work_w shutdown
        // to let the backend response flow back to the user.
        let bridge_pre_read = req.pre_read;
        // SUDP: compression stays forced off — bridge_plain wraps the stream
        // in Snappy when comp_key is set, which the provider's plaintext
        // read_msg_v1 would misread as a V1 frame header (sNaPpY magic →
        // "invalid V1 msg length"). Go's streaming compression model for the
        // per-packet SUDP plane is not unified here yet; this change is
        // encryption-focused, so SUDP compression remains off (only the
        // provider-segment encryption restriction was lifted above).
        let comp_key = req.use_compression && !is_sudp;

        // XTCP STCP fallback: keep copy_bidirectional semantics for both
        // directions — bridge_plain's join! pattern drops the work writer
        // (sending FIN) as soon as the user reader reaches EOF. For STCP
        // fallback the visitor's test client half-closes after sending data,
        // so the server sees EOF on the user side ~60ms before the provider
        // starts its bridge. The premature FIN on the work connection races
        // with the provider's copy_bidirectional startup and produces
        // ECONNRESET on VPS. relay_plain_pooled avoids this exactly like
        // copy_bidirectional: both directions run to completion within the
        // same function, and the work side is only shut down after the full
        // bidirectional copy finishes (pooled buffers — audit round-8 P1).
        //
        // Visitor-segment encryption/compression (if on) split the user conn
        // into wrapped halves (via `split_user_side`), re-combined via
        // `UserSide` for the same relay call.
        if proxy_info.as_ref().is_some_and(|p| p.proxy_type == "xtcp") {
            let Some((u_r, u_w)) =
                try_split_user_side(visitor_enc_key, visitor_comp, req.user_conn)
            else {
                return;
            };
            // Pooled-buffer relay (audit round-8 P1): relay_plain_pooled has
            // EXACTLY the copy_bidirectional semantics this arm's comment
            // above requires — both directions run to completion and the
            // work side is only shut down after the full bidirectional copy
            // (FIN-propagation, no premature-FIN race), without the
            // per-conn buffer pair. Buffer size stays FRP_BRIDGE_BUF_KB
            // (the pool's BUFFER_SIZE governs the XTCP STCP fallback path).
            let user_side = UserSide { r: u_r, w: u_w };
            match frp_core::bridge::relay_plain_pooled(user_side, work_conn).await {
                Ok((a, b)) => {
                    metrics.record_traffic(a, b);
                }
                Err(e) => {
                    debug!(error = %e, "XTCP STCP fallback bridge closed: {}", e);
                }
            }
        } else if bw_limiter.is_some() {
            // Bandwidth limiting active: use rate-limited plain bridge.
            let Some((u_r, u_w)) =
                try_split_user_side(visitor_enc_key, visitor_comp, req.user_conn)
            else {
                return;
            };
            let Some((w_r, w_w)) = try_split_work_halves(work_conn) else {
                return;
            };
            if let Some(headers) = injector_headers {
                // A1: decompress the work stream before the injector when the
                // proxy uses compression (see the encrypted arm above).
                let injector_r: Box<dyn AsyncRead + Unpin + Send> = if comp_key {
                    Box::new(frp_core::snappy_stream::SnappyStreamReader::new(w_r))
                } else {
                    w_r
                };
                let injector = ResponseHeaderInjector::new(injector_r, headers, header_timeout);
                // No one-shot header_timeout to the bridge: the injector
                // owns the absolute response-head deadline (see the
                // encrypted arm above).
                frp_core::bridge::bridge_plain_rate_limited_decompressed_read(
                    u_r,
                    u_w,
                    injector,
                    w_w,
                    comp_key,
                    bridge_pre_read,
                    bw_limiter.as_ref(),
                    Some(metrics.clone()),
                )
                .await;
            } else {
                frp_core::bridge::bridge_plain_rate_limited(
                    u_r,
                    u_w,
                    w_r,
                    w_w,
                    comp_key,
                    bridge_pre_read,
                    bw_limiter.as_ref(),
                    Some(metrics.clone()),
                )
                .await;
            }
        } else if !comp_key
            && bridge_pre_read.is_empty()
            && injector_headers.is_none()
            && !visitor_encrypted
            && !visitor_comp
        {
            // Fast path: pure plain relay with no compression, no VHost
            // pre-read, no header injection, and no visitor-segment
            // encryption/compression (splice needs the raw IoStream; visitor
            // wrapping already split it into wrapped halves). On Linux, try
            // zero-copy splice for Tcp-to-Tcp; otherwise use
            // copy_bidirectional.
            relay_plain_fast(req.user_conn, work_conn, &metrics).await;
        } else {
            // Slow path: compression, VHost pre-read, header injection, or
            // visitor-segment encryption.
            let Some((u_r, u_w)) =
                try_split_user_side(visitor_enc_key, visitor_comp, req.user_conn)
            else {
                return;
            };
            let Some((w_r, w_w)) = try_split_work_halves(work_conn) else {
                return;
            };
            if let Some(headers) = injector_headers {
                // A1: decompress the work stream before the injector when the
                // proxy uses compression (see the encrypted arm above).
                let injector_r: Box<dyn AsyncRead + Unpin + Send> = if comp_key {
                    Box::new(frp_core::snappy_stream::SnappyStreamReader::new(w_r))
                } else {
                    w_r
                };
                let injector = ResponseHeaderInjector::new(injector_r, headers, header_timeout);
                // No one-shot header_timeout to the bridge: the injector
                // owns the absolute response-head deadline (see the
                // encrypted arm above).
                frp_core::bridge::bridge_plain_decompressed_read(
                    u_r,
                    u_w,
                    injector,
                    w_w,
                    comp_key,
                    bridge_pre_read,
                    Some(metrics.clone()),
                )
                .await;
            } else {
                frp_core::bridge::bridge_plain(
                    u_r,
                    u_w,
                    w_r,
                    w_w,
                    comp_key,
                    bridge_pre_read,
                    Some(metrics.clone()),
                )
                .await;
            }
        }
    }
    debug!(proxy_name = %req.proxy_name, "Proxy '{}' bridge completed", req.proxy_name);
}

/// Go frp v0.71.0 `normalizeWireProtocol`: "" and "v1" both normalize to
/// "v1"; only "v2" stays "v2".
fn normalize_wire_protocol(v2: bool) -> &'static str {
    if v2 {
        "v2"
    } else {
        "v1"
    }
}

#[cfg(test)]
mod tests;
