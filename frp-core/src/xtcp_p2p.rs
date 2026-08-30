//! XTCP P2P data plane: UDP hole punching + KCP-over-UDP stream.
//!
//! Go frp v0.70 uses UDP for XTCP NAT hole punching, then runs KCP
//! (with yamux on top) or QUIC as the data-plane transport. The Rust
//! frp prior to v0.7.0 used TCP simultaneous-open, which is incompatible.
//!
//! This module implements the Go v0.70-compatible path:
//! 1. Reuse the STUN UDP socket for hole punching
//! 2. Exchange UDP punch packets with the peer's candidate addresses
//! 3. Create a KCP session over the established UDP path
//! 4. Expose an AsyncRead + AsyncWrite stream for bridging
//!
//! ## Hole-punch protocol (dual-mode)
//!
//! Two hole-punch modes are supported:
//!
//! **Rust↔Rust (simple "frp" magic):** Each side sends the 3-byte magic
//! `b"frp"` to the peer's candidate addresses and waits for the same
//! magic in response. Fast and simple — used when no secret key is
//! provided.
//!
//! **Go-compat (encrypted NatHoleSid):** When a secret key is provided,
//! the hole-punch sends Go frp-compatible `NatHoleSid` messages (JSON
//! encrypted with AES-128-CFB). This is required for Go↔Rust XTCP P2P.
//! The Rust side acts as sender (sends `response:false` first, waits for
//! `response:true` echo) and also echoes back any incoming
//! `response:false` probes (like Go's receiver role). This dual-role
//! ensures compatibility with Go peers regardless of detect_behavior
//! role assignment.
//!
//! ## Hole-punch paths
//!
//! Two hole-punch paths exist:
//!
//! **Simplified punch (`punch_udp_hole`):** used when no server-provided
//! `detect_behavior` is available (Rust↔Rust, legacy `NatHoleClient` path).
//! Sends a single detect burst and waits for the first valid reply.
//!
//! **Go-compat MakeHole (`punch_udp_hole_makehole`):** used whenever the
//! server sent a `detect_behavior` in `NatHoleResp`. This mirrors Go frp
//! v0.70.1 `pkg/nathole/nathole.go` `MakeHole` and executes the 5-mode
//! behavior parameters selected by the server analyzer:
//!
//! | Parameter | Executed | Notes |
//! |-----------|----------|-------|
//! | `role` (sender/receiver) | Yes | Sender waits `send_delay_ms`, probes assisted+candidate addrs; receiver optionally binds `listen_random_ports` extra sockets |
//! | `ttl` | Yes | Applied to all probe packets for the probe phase, restored afterwards (Go defer semantics); ttl<=0 leaves the socket TTL untouched |
//! | `send_delay_ms` | Yes | Sender sleeps before probing |
//! | `candidate_ports` | Yes | Receiver scans each candidate IP's port range, 2 ms per port (Go `sendSidMessageToRangePorts`) |
//! | `send_random_ports` | Yes | One concurrent task per socket probing that many distinct random ports in [1024, 65535], 15 ms apart (Go `sendSidMessageToRandomPorts`) |
//! | `read_timeout_ms` | Yes | Used as the detect-wait timeout (Go `ReadTimeoutMs`) |
//!
//! The winning socket — the one the peer's detect reply arrived on — is
//! returned and used for the data plane, matching Go's `result.lConn`
//! semantics (a reply on an extra listener socket only has a working NAT
//! mapping on that socket). The data plane is either KCP (with yamux on
//! top, `xtcp_p2p_connect_yamux`) or, when the `quic` feature is enabled and
//! the negotiated `protocol` is `"quic"`, QUIC directly over the punched
//! socket (`xtcp_p2p_connect_quic` — no yamux, since QUIC multiplexes
//! streams itself; Go v0.70.1 `quic.Dial`/`quic.Listen` on `result.lConn`).
//!
//! **Known remaining differences from Go:** `slices.Compact` in Go only
//! removes *adjacent* duplicates, we sort+dedup the detect-address set;
//! the shared probe `transaction_id` in Go is a single value per MakeHole
//! call while we generate one per packet (Go peers never validate it); and
//! Go's TTL set/restore races under concurrent random-port probing while we
//! keep a constant probe-phase TTL (cleaner, same observable behavior).

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Instant;

use futures_util::FutureExt;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, Notify};
// Round 6 (feature-matrix cleanup): `watch` is used only inside
// `xtcp_p2p_connect_yamux` (cfg tcp-mux) — a kcp-only build warned unused.
#[cfg(feature = "tcp-mux")]
use tokio::sync::watch;

use crate::kcp::{KcpConfig, KcpSession};

/// Hole-punch magic bytes — must match Go frp v0.70 `var holePunchPacket = []byte("frp")`.
const HOLE_PUNCH_MAGIC: &[u8] = b"frp";

/// Default KCP tick interval (ms). 10 ms matches Go frp kcp-go default.
/// `pub(crate)` — the persistent tunnel-session driver (xtcp_session.rs)
/// uses the same tick to keep the KCP state machine alive.
pub(crate) const KCP_TICK_MS: u32 = 10;

/// Default timeout for hole-punch response.
pub const DEFAULT_HOLE_PUNCH_TIMEOUT_MS: u64 = 5000;

/// Upper bound on the server-supplied hole-punch detect-wait timeout (ms).
/// Go's NAT analyzer emits `ReadTimeoutMs` = max(SendDelayMs)+5000
/// [+30000 when listen_random_ports] — at most ~45s — so 60s is far above
/// any legitimate value. Without the cap a hostile server could stretch a
/// punch to ~24.8 days (`read_timeout_ms` is i32).
pub const MAX_HOLE_PUNCH_TIMEOUT_MS: u64 = 60_000;

/// Upper bound on the sender's pre-probe sleep (ms). Go's analyzer emits
/// `SendDelayMs` ≤ 10s (nathole/analysis.go), so 15s is far above any
/// legitimate value; a hostile server must not be able to delay the whole
/// punch for weeks via `send_delay_ms` (also i32).
pub const MAX_SEND_DELAY_MS: u64 = 15_000;

/// Go `nathole.go` `MakeHole` role resolution: only the exact string
/// `"sender"` takes the sender arm (sleep + probe assisted/candidates);
/// EVERYTHING else — including a missing role from a hostile or legacy
/// server — is the receiver (Go `else` branch, verified against v0.71.0
/// nathole.go:201-208).
fn resolve_punch_role(role: Option<&str>) -> &'static str {
    match role {
        Some("sender") => "sender",
        _ => "receiver",
    }
}

// Persistent tunnel-session API (Go frp v0.71 keepTunnelOpenWorker): the
// one hole-punched session per XTCP proxy, reused across user connections.
// Implemented in xtcp_session.rs; re-exported here so callers have a single
// XTCP entry point.
#[cfg(all(feature = "kcp", feature = "quic"))]
pub use crate::xtcp_session::{xtcp_p2p_connect_quic_session, QuicTunnelSession};
#[cfg(feature = "kcp")]
pub use crate::xtcp_session::{xtcp_p2p_connect_yamux_session, XtcpTunnelSession};

/// Derive a KCP conversation ID from a shared session identifier.
///
/// Both sides of an XTCP P2P connection must use the same `conv` for KCP
/// packets to be accepted by the peer's session (the `kcp` crate drops
/// packets with mismatched `conv` when `input_conv` is `false`).
///
/// The NAT hole-punch session ID (`sid`) is known to both visitor (via
/// `NatHoleResp.sid`) and provider (via `XtcpNotification` / `NatHoleResp`).
pub fn conv_from_sid(_sid: &str) -> u32 {
    // Go frp v0.70 uses kcp-go's auto-assigned conv (global atomic counter
    // starting from 0, with atomic.AddUint32 returning 1 on first call).
    // The XTCP P2P KCP session is the first (and only) KCP session created
    // by Go frp for P2P, so it always gets conv=1.
    //
    // Hard-coding conv=1 on the Rust side ensures KCP conv matches Go's
    // without fragile conv learning (input_conv). Each XtcpP2pStream has
    // its own UDP socket, so conv collisions are harmless for multiplexed
    // P2P sessions.
    //
    // Previously used MD5(sid) for deterministic cross-process conv, but
    // this diverges from Go's auto-assigned conv and requires input_conv
    // which is vulnerable to stray KCP packets on shared-VPS CI.
    1u32
}

// ---------------------------------------------------------------------------
// Go-compat NatHoleSid detect messages
// ---------------------------------------------------------------------------

/// Go frp v0.70 NatHoleSid message used during UDP hole-punch detection.
///
/// Matches Go struct wire format exactly: `json:"...,omitempty"` on all
/// fields. Go's omitempty omits zero values (false for bool, "" for string).
/// Deserialization uses `#[serde(default)]` to handle missing fields.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct NatHoleDetectSid {
    #[serde(
        rename = "transaction_id",
        default,
        skip_serializing_if = "String::is_empty"
    )]
    transaction_id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    sid: String,
    #[serde(default, skip_serializing_if = "is_false")]
    response: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    nonce: String,
}

/// Serde helper: skip serializing `false` bool values (match Go omitempty).
fn is_false(b: &bool) -> bool {
    !b
}

impl NatHoleDetectSid {
    fn new(sid: &str, response: bool) -> Self {
        Self {
            transaction_id: uuid::Uuid::new_v4().to_string(),
            sid: sid.to_string(),
            response,
            // Go v0.70.1 sets Nonce to a random string of 0-19 '0' chars
            // (`strings.Repeat("0", rand.IntN(20))` in sendSidMessage).
            nonce: "0".repeat(rand::random::<usize>() % 20),
        }
    }
}

/// Encode a `NatHoleDetectSid` for UDP hole-punch detection.
/// Format matches Go frp v0.70 `EncodeMessage` in nathole/utils.go:
///   V1 framing (type byte '5' + 8-byte BE length + JSON) → AES-128-CFB encrypt
///   with PBKDF2-SHA1(key, salt="frp", iter=64, len=16) key + random 16-byte IV.
fn encode_detect_msg(msg: &NatHoleDetectSid, key: &[u8; 16]) -> Result<Vec<u8>, String> {
    // V1 framing: 1-byte type + 8-byte BE length + JSON payload.
    // Go frp TypeNatHoleSid = '5' = 0x35.
    let json = serde_json::to_vec(msg).map_err(|e| format!("json encode: {e}"))?;
    let json_len = json.len() as u64;
    let mut frame = Vec::with_capacity(9 + json.len());
    frame.push(0x35u8); // TypeNatHoleSid = '5'
    frame.extend_from_slice(&json_len.to_be_bytes());
    frame.extend_from_slice(&json);
    crate::encryption::encrypt(&frame, key)
}

/// Decode a `NatHoleDetectSid` from UDP hole-punch detection data.
/// Reverse of `encode_detect_msg`: AES-128-CFB decrypt → parse V1 framing
/// (1-byte type + 8-byte BE length + JSON) → deserialize JSON.
fn decode_detect_msg(data: &[u8], key: &[u8; 16]) -> Result<NatHoleDetectSid, String> {
    let frame = crate::encryption::decrypt(data, key)?;
    if frame.len() < 9 {
        return Err("frame too short for V1 header".into());
    }
    // Type byte is at offset 0; we don't validate it strictly since some
    // Go messages may use different framing.
    let json_len = u64::from_be_bytes(
        frame[1..9]
            .try_into()
            .map_err(|_| "invalid frame: missing length bytes".to_string())?,
    ) as usize;
    let need = 9usize
        .checked_add(json_len)
        .ok_or_else(|| "invalid frame: length overflow".to_string())?;
    if frame.len() < need {
        return Err(format!(
            "frame truncated: need {} bytes, have {}",
            need,
            frame.len()
        ));
    }
    let json = &frame[9..need];
    serde_json::from_slice(json).map_err(|e| format!("json decode: {e}"))
}

/// Derive a 16-byte AES key from a secret key string for NatHoleSid detection.
///
/// Go frp v0.70 calls `crypto.Encode()` from `github.com/fatedier/golib/crypto`,
/// which internally derives: `pbkdf2.Key(key, "frp", 64, 16, sha1.New)`.
/// Go frp sets `crypto.DefaultSalt = "frp"` at startup in both client and
/// server. This matches Rust's `encryption::derive_key`.
pub fn derive_detect_key(sk: &str) -> [u8; 16] {
    crate::encryption::derive_key(sk)
}

// ---------------------------------------------------------------------------
// Hole punching
// ---------------------------------------------------------------------------

/// Punch a UDP hole to the peer. Returns the confirmed peer address.
///
/// Two modes:
/// - **Simple** (no key): send "frp" magic, wait for "frp" back. Used for Rust↔Rust.
/// - **Go-compat** (with key): send encrypted NatHoleSid, accept both
///   NatHoleSid{response:true} and "frp" magic as valid responses.
///   Also echoes NatHoleSid{response:false} probes (Go receiver role).
///
/// `socket` should be the same UDP socket used for STUN (already bound).
/// `candidates` are the peer's candidate addresses from the server's
/// NatHoleResp. `sid` and `key` are only used in Go-compat mode.
pub async fn punch_udp_hole(
    socket: &UdpSocket,
    candidates: &[String],
    timeout_ms: u64,
    sid: Option<&str>,
    key: Option<&[u8; 16]>,
) -> Result<SocketAddr, String> {
    if candidates.is_empty() {
        return Err("no candidate addresses".into());
    }

    // Parse all candidates upfront.
    let peers: Vec<SocketAddr> = candidates.iter().filter_map(|a| a.parse().ok()).collect();
    if peers.is_empty() {
        return Err("no valid candidate addresses".into());
    }

    // --- Send phase: Go-compat NatHoleSid (only when key+sid present) ---
    // Go frp v0.70 sends only encrypted NatHoleSid probes; it does NOT
    // understand "frp" magic. Sending "frp" (3 bytes) to a Go peer causes
    // "decode sid message error: ciphertext too short" because Go tries
    // crypto.Decode on the 3-byte magic (< 16-byte AES IV).
    let go_compat = sid.is_some() && key.is_some();
    if go_compat {
        let sid_str = sid.expect("go_compat above requires sid.is_some()");
        let enc_key = key.expect("go_compat above requires key.is_some()");
        let detect_msg = NatHoleDetectSid::new(sid_str, false);
        let encoded = match encode_detect_msg(&detect_msg, enc_key) {
            Ok(e) => e,
            Err(e) => {
                tracing::debug!("XTCP P2P: failed to encode NatHoleSid: {e}");
                return Err(format!("encode NatHoleSid: {e}"));
            }
        };
        for peer in &peers {
            if let Err(e) = socket.send_to(&encoded, *peer).await {
                tracing::debug!(%peer, error = %e, "XTCP P2P: failed to send NatHoleSid message");
            }
        }
    } else {
        // Simple "frp" magic (Rust↔Rust with no encryption key).
        for peer in &peers {
            if let Err(e) = socket.send_to(HOLE_PUNCH_MAGIC, *peer).await {
                tracing::debug!(%peer, error = %e, "XTCP P2P: failed to send hole-punch magic");
            }
        }
    }

    // --- Receive phase: accept "frp" magic OR NatHoleSid{response:true} ---
    let mut buf = [0u8; 1024];
    let deadline = tokio::time::timeout(
        std::time::Duration::from_millis(timeout_ms),
        socket.recv_from(&mut buf),
    )
    .await
    .map_err(|_| format!("hole punch timeout after {}ms", timeout_ms))?;

    match deadline {
        Ok((n, peer)) => {
            let data = &buf[..n];

            // 1. Check for "frp" magic (Rust↔Rust).
            if data == HOLE_PUNCH_MAGIC {
                if peers.contains(&peer) {
                    return Ok(peer);
                }
                // From non-candidate — retry once.
                return recv_second_attempt(socket, timeout_ms, sid, key, &peers).await;
            }

            // 2. Check for Go-compat NatHoleSid.
            if let (Some(sid_str), Some(enc_key)) = (sid, key) {
                match decode_detect_msg(data, enc_key) {
                    Ok(msg) => {
                        if msg.sid != sid_str {
                            // Wrong sid — retry once.
                            tracing::debug!(peer = %peer, msg_sid = %msg.sid, our_sid = %sid_str,
                                "XTCP P2P: NatHoleSid with wrong sid");
                            return recv_second_attempt(socket, timeout_ms, sid, key, &peers).await;
                        }
                        if msg.response {
                            // Got response:true from peer → hole punched!
                            tracing::debug!(peer = %peer, "XTCP P2P: got NatHoleSid response from {}", peer);
                            return Ok(peer);
                        }
                        // Got response:false probe → echo back (Go receiver role).
                        // Go frp v0.70 receiver returns raddr immediately after
                        // echoing; it does NOT wait for a response:true from the
                        // sender (the sender never sends response:true — it only
                        // waits for an echo). If we enter recv_second_attempt,
                        // we deadlock waiting for a message that never comes.
                        let mut echo = msg;
                        echo.response = true;
                        if let Ok(encoded) = encode_detect_msg(&echo, enc_key) {
                            if let Err(e) = socket.send_to(&encoded, peer).await {
                                tracing::debug!(%peer, error = %e, "XTCP P2P: failed to echo NatHoleSid response");
                            }
                            tracing::debug!(peer = %peer, "XTCP P2P: echoed NatHoleSid response to {}", peer);
                        }
                        // Hole punch complete after echoing the probe.
                        // The sender will receive our echo and proceed.
                        return Ok(peer);
                    }
                    Err(_) => {
                        // Not NatHoleSid either — unknown data.
                        tracing::debug!(peer = %peer, n, "XTCP P2P: unexpected hole-punch data from {}", peer);
                        return recv_second_attempt(socket, timeout_ms, sid, key, &peers).await;
                    }
                }
            }

            // No key provided and data != "frp" — unknown, retry once.
            tracing::debug!(peer = %peer, n, "XTCP P2P: unexpected hole-punch data from {}", peer);
            recv_second_attempt(socket, timeout_ms, sid, key, &peers).await
        }
        Err(e) => Err(format!("recv error: {}", e)),
    }
}

/// Second receive attempt. See `punch_udp_hole` for semantics of `sid`/`key`.
async fn recv_second_attempt(
    socket: &UdpSocket,
    timeout_ms: u64,
    sid: Option<&str>,
    key: Option<&[u8; 16]>,
    peers: &[SocketAddr],
) -> Result<SocketAddr, String> {
    let mut buf = [0u8; 1024];
    let deadline2 = tokio::time::timeout(
        std::time::Duration::from_millis(timeout_ms),
        socket.recv_from(&mut buf),
    )
    .await
    .map_err(|_| "hole punch timeout (2nd attempt)".to_string())?;

    match deadline2 {
        Ok((n, peer)) => {
            let data = &buf[..n];

            if data == HOLE_PUNCH_MAGIC {
                if peers.contains(&peer) {
                    return Ok(peer);
                }
                return Err(format!("magic response from non-candidate {}", peer));
            }

            if let (Some(sid_str), Some(enc_key)) = (sid, key) {
                if let Ok(msg) = decode_detect_msg(data, enc_key) {
                    if msg.sid == sid_str && msg.response {
                        return Ok(peer);
                    }
                    // Echo response:false probe → return immediately.
                    // Same as Go receiver: after echoing, the hole punch is
                    // complete. Don't wait for response:true — the sender side
                    // never sends one (it's waiting for our echo).
                    if msg.sid == sid_str && !msg.response {
                        let mut echo = msg;
                        echo.response = true;
                        if let Ok(encoded) = encode_detect_msg(&echo, enc_key) {
                            if let Err(e) = socket.send_to(&encoded, peer).await {
                                tracing::debug!(%peer, error = %e, "XTCP P2P: failed to echo NatHoleSid response");
                            }
                        }
                        return Ok(peer);
                    }
                }
            }

            Err(format!("unexpected hole-punch data from {}", peer))
        }
        Err(e) => Err(format!("recv error: {}", e)),
    }
}

// ---------------------------------------------------------------------------
// XtcpP2pStream — AsyncRead + AsyncWrite over KCP-in-UDP
// ---------------------------------------------------------------------------

/// A bidirectional KCP stream over a single UDP socket to a specific peer.
///
/// This is a self-contained KCP session — no separate driver task or
/// multi-session KcpSocket. The KCP state machine is driven inline from
/// poll_read / poll_write / poll_flush.
pub struct XtcpP2pStream {
    socket: UdpSocket,
    peer_addr: SocketAddr,
    session: KcpSession,
    read_rx: mpsc::Receiver<Vec<u8>>,
    read_buffer: Vec<u8>,
    read_pos: usize,
    /// Monotonic clock: Instant when the stream was created.
    created: Instant,
    /// Last time we ran kcp.update().
    last_update: Instant,
    shutdown: bool,
    /// Data written via poll_write, waiting to be flushed to KCP.
    pending_send: Vec<u8>,
    /// Waker to signal when pending_send is drained (write backpressure).
    write_notify: Arc<Notify>,
    /// Stored HWM-park wait future (round 13 fix). The round-10 fix built
    /// `select(notified, sleep)` inside poll_write and returned Pending with
    /// the select dropped — tokio unregisters BOTH wakers when a future is
    /// dropped (Sleep cancel in the timer wheel + OwnedNotified waiter
    /// removal from notify.rs), so the 10ms timer never fired and the
    /// raw-KCP path (tcp-mux off, no background driver) deadlocked at the
    /// high-water mark forever. Storing the select across polls (the
    /// KcpStream `backpressure_fut` pattern) keeps both wakers registered
    /// until the wait resolves. Select is Unpin when both halves are Unpin
    /// (they are boxed), so the struct stays Unpin.
    hwm_wait_fut: Option<HwmWaitFut>,
}

/// Parked HWM wait: race the drain notify against a KCP_TICK_MS timer so a
/// parked writer re-polls even when no peer traffic ever drains (raw-KCP
/// path has no background driver). Type alias keeps the struct field
/// readable (clippy::type_complexity).
type HwmWaitFut = futures_util::future::Select<
    Pin<Box<tokio::sync::futures::OwnedNotified>>,
    Pin<Box<tokio::time::Sleep>>,
>;

/// High-water mark for pending_send in bytes. When pending_send exceeds
/// this, poll_write returns Pending to signal backpressure to the caller.
/// KCP drains pending_send on each tick (every 10ms), so this only gates
/// burst writes that outpace the UDP send rate.
const PENDING_SEND_HIGH_WATER: usize = 256 * 1024; // 256 KiB

impl XtcpP2pStream {
    /// Create a new P2P stream from a hole-punched UDP socket.
    ///
    /// `socket` must already have had `punch_udp_hole()` called on it.
    /// `peer_addr` is the peer's confirmed address from the hole punch.
    /// `conv` is the KCP conversation ID (should be random, non-zero).
    /// `kcp_config` configures the KCP session (nodelay, window, MTU).
    pub fn new(
        socket: UdpSocket,
        peer_addr: SocketAddr,
        conv: u32,
        kcp_config: KcpConfig,
    ) -> io::Result<Self> {
        debug_assert!(conv != 0, "KCP conv must be non-zero");

        let (read_tx, read_rx) = mpsc::channel(256);
        let session = KcpSession::new(conv, peer_addr, kcp_config, read_tx);

        let now = Instant::now();
        Ok(Self {
            socket,
            peer_addr,
            session,
            read_rx,
            read_buffer: Vec::new(),
            read_pos: 0,
            created: now,
            last_update: now,
            shutdown: false,
            pending_send: Vec::new(),
            write_notify: Arc::new(Notify::new()),
            hwm_wait_fut: None,
        })
    }

    /// Return the peer's socket address.
    pub fn peer_addr(&self) -> SocketAddr {
        self.peer_addr
    }

    /// Return a clone of the write notifier for external wakeup.
    /// Used by the yamux background driver to wake on write activity
    /// instead of relying solely on the periodic KCP tick.
    pub fn write_notifier(&self) -> Arc<Notify> {
        self.write_notify.clone()
    }

    /// Drive one KCP tick: update clock, send output, recv input.
    fn drive_kcp(&mut self, now_ms: u32) -> io::Result<()> {
        // 1. Flush pending send data to KCP.
        let was_full = self.pending_send.len() >= PENDING_SEND_HIGH_WATER;
        if !self.pending_send.is_empty() {
            let data = std::mem::take(&mut self.pending_send);
            // send_chunked: kcp.send rejects one buffer >= the send window
            // (128 segments); a HWM-parked drain can hold up to
            // PENDING_SEND_HIGH_WATER + one write chunk, so the whole
            // buffer must be split (see KcpSession::send_chunked).
            self.session.send_chunked(&data)?;
            // Wake write pollers that were blocked on the high-water mark.
            // notify_one() stores a permit if no waiters exist, preventing
            // the lost-wake race between poll_write's notified_owned() and
            // our drain. (notify_waiters() would lose the notification.)
            if was_full {
                self.write_notify.notify_one();
            }
        }

        // 2. Update KCP state machine → produce output packets.
        let out_packets = self.session.update(now_ms)?;

        // 3. Send output packets (KCP data + ACKs) to peer via UDP.
        for pkt in &out_packets {
            // Non-blocking send: UDP send buffer is typically large enough.
            // If it's full, we drop the packet (KCP retransmits).
            match self.socket.try_send_to(pkt, self.peer_addr) {
                Ok(_) => {}
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    tracing::debug!(
                        peer = %self.peer_addr,
                        len = pkt.len(),
                        "XTCP P2P: UDP send would block, dropping KCP packet"
                    );
                }
                Err(e) => return Err(e),
            }
        }

        // 4. Drain incoming UDP data and feed to KCP.
        let mut buf = [0u8; 2048];
        loop {
            match self.socket.try_recv_from(&mut buf) {
                Ok((n, src)) => {
                    if src == self.peer_addr {
                        // Skip hole-punch magic ("frp") that may arrive
                        // after hole punch completes (stray packets still
                        // in-flight). KCP's input() rejects packets < 24
                        // bytes (header size); 3-byte "frp" causes an
                        // error that kills the KCP session → yamux timeout.
                        if &buf[..n] == HOLE_PUNCH_MAGIC {
                            continue;
                        }
                        self.session.input(&buf[..n])?;
                    } else {
                        // Drop packets from unexpected sources after
                        // hole punch is established.
                        tracing::trace!(
                            peer = %self.peer_addr,
                            src = %src,
                            "XTCP P2P: ignoring packet from non-peer"
                        );
                    }
                }
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) => return Err(e),
            }
        }

        // 5. Push received KCP app data to the read channel.
        self.session.recv_and_push()?;

        self.last_update = Instant::now();
        Ok(())
    }

    /// Run a KCP tick if enough time has passed.
    fn maybe_tick(&mut self) -> io::Result<()> {
        let elapsed_ms = self.last_update.elapsed().as_millis() as u32;
        if elapsed_ms >= KCP_TICK_MS {
            // Monotonic millisecond clock: elapsed since stream creation.
            let now_ms = self.created.elapsed().as_millis() as u32;
            self.drive_kcp(now_ms)?;
            // Check for dead link after driving KCP so the background yamux
            // task (and raw KCP users) can detect dead peers and exit.
            if self.session.is_dead_link() {
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionReset,
                    "KCP dead link (too many retransmissions)",
                ));
            }
            Ok(())
        } else {
            Ok(())
        }
    }
}

impl AsyncRead for XtcpP2pStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.shutdown {
            return Poll::Ready(Ok(()));
        }

        // Drain buffered data first.
        if self.read_pos < self.read_buffer.len() {
            let remaining = &self.read_buffer[self.read_pos..];
            let n = remaining.len().min(buf.remaining());
            buf.put_slice(&remaining[..n]);
            self.read_pos += n;
            return Poll::Ready(Ok(()));
        }

        // Drive KCP to get new data.
        self.maybe_tick()?;

        // Poll the read channel for app data from KCP.
        match self.read_rx.poll_recv(cx) {
            Poll::Ready(Some(data)) => {
                // Diagnostic: log every yamux frame received (infrequent after handshake).
                if data.len() >= 12 {
                    let frame_type = data[1];
                    let frame_flags = u16::from_be_bytes([data[2], data[3]]);
                    let frame_sid = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
                    let frame_len = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
                    tracing::debug!(
                        peer = %self.peer_addr,
                        total_bytes = data.len(),
                        yamux_type = frame_type,
                        yamux_flags = format_args!("0x{frame_flags:04x}"),
                        yamux_stream_id = frame_sid,
                        yamux_len = frame_len,
                        "XTCP P2P: poll_read got yamux frame"
                    );
                }
                let n = data.len().min(buf.remaining());
                buf.put_slice(&data[..n]);
                if n < data.len() {
                    self.read_buffer = data;
                    self.read_pos = n;
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(None) => {
                // Channel closed — EOF.
                self.shutdown = true;
                Poll::Ready(Ok(()))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for XtcpP2pStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.shutdown {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "XTCP P2P stream shut down",
            )));
        }

        // Backpressure: if the pending send buffer exceeds the high-water
        // mark, return Pending and register the waker. The waker is woken
        // in drive_kcp (and poll_flush) after pending_send is flushed to
        // KCP. Without this, a write-heavy one-directional stream could
        // grow pending_send without bound if UDP sends are slower than
        // data arrival.
        //
        // Round 10 (MEDIUM, found RED): the raw-KCP path (tcp-mux off,
        // micro builds) has no background yamux driver re-polling this
        // stream, so a silent peer deadlocks: the write half parks here,
        // the read half parks on the empty read channel, and drive_kcp —
        // the only drain site — never runs again. A timer wake alongside
        // the notify guarantees a re-poll, and the drain below forces one
        // KCP tick so parked writers make progress even without peer
        // traffic.
        //
        // Round 13: the round-10 fix built `select(notified, sleep)`
        // locally and returned Pending with the select dropped — tokio
        // unregisters both wakers when a future is dropped, so the timer
        // never fired and the HWM-parked write deadlocked forever. The
        // select is now stored in `hwm_wait_fut` across polls (KcpStream's
        // `backpressure_fut` pattern) so both wakers stay registered until
        // the wait resolves; it is cleared on Ready and whenever the HWM
        // condition clears without this poll_write draining it.
        if self.pending_send.len() >= PENDING_SEND_HIGH_WATER {
            // Both futures are !Unpin (tokio Notify waiter / Sleep), so
            // box-pin them to satisfy futures_util select's Unpin bounds.
            // Two box allocs on the rare HWM-parked path only. get_or_insert
            // keeps an existing parked wait alive across polls.
            let write_notify = self.write_notify.clone();
            let fut = self.hwm_wait_fut.get_or_insert_with(|| {
                let notified = write_notify.notified_owned();
                let wake = tokio::time::sleep(std::time::Duration::from_millis(KCP_TICK_MS as u64));
                futures_util::future::select(Box::pin(notified), Box::pin(wake))
            });
            match futures_util::FutureExt::poll_unpin(fut, cx) {
                Poll::Ready(_) => {
                    self.hwm_wait_fut = None;
                    // Drain pending_send immediately: bypass the 10ms tick
                    // gate, which the yamux driver path does not need but
                    // the raw path cannot afford (see above).
                    let now_ms = self.created.elapsed().as_millis() as u32;
                    self.drive_kcp(now_ms)?;
                }
                Poll::Pending => return Poll::Pending,
            }
        } else if self.hwm_wait_fut.is_some() {
            // HWM cleared without this poll_write draining (drive_kcp ran
            // from poll_read/poll_flush): drop the stale parked future so
            // its timer entry and Notify waiter are released.
            self.hwm_wait_fut = None;
        }

        // Accumulate send data — flush happens in drive_kcp.
        self.pending_send.extend_from_slice(buf);

        // Drive KCP to flush.
        self.maybe_tick()?;

        // Diagnostic: log every yamux frame write (infrequent after handshake).
        // Yamux header: [ver:1B, type:1B, flags:2B BE, stream_id:4B BE, len:4B BE]
        if buf.len() >= 12 {
            let frame_type = buf[1];
            let frame_flags = u16::from_be_bytes([buf[2], buf[3]]);
            let frame_sid = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
            let frame_len = u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]);
            tracing::debug!(
                peer = %self.peer_addr,
                total_bytes = buf.len(),
                yamux_type = frame_type,
                yamux_flags = format_args!("0x{frame_flags:04x}"),
                yamux_stream_id = frame_sid,
                yamux_len = frame_len,
                "XTCP P2P: poll_write yamux frame sent"
            );
        }

        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.shutdown {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "XTCP P2P stream shut down",
            )));
        }

        // Drain any pending_send buffered during the current tick window
        // (maybe_tick skips drive_kcp when elapsed < KCP_TICK_MS, so poll_write
        // data may sit in pending_send without reaching KCP's snd_queue).
        let was_full = self.pending_send.len() >= PENDING_SEND_HIGH_WATER;
        let pending_drain_len = self.pending_send.len();
        if !self.pending_send.is_empty() {
            let data = std::mem::take(&mut self.pending_send);
            let _ = self.session.send_chunked(&data);
            // Round 10 (LOW): symmetric with drive_kcp's was_full notify —
            // a flush-drain landing between a writer's gate check and the
            // next drive_kcp must still wake parked writers.
            if was_full {
                self.write_notify.notify_one();
            }
        }

        // Force-flush: update KCP and send all output immediately.
        let now_ms = self.created.elapsed().as_millis() as u32;
        let out_packets = match self.session.force_flush(now_ms) {
            Ok(pkts) => pkts,
            Err(e) => return Poll::Ready(Err(e)),
        };

        if pending_drain_len > 0 || !out_packets.is_empty() {
            let total_sent: usize = out_packets.iter().map(|p| p.len()).sum();
            tracing::debug!(
                peer = %self.peer_addr,
                pending_bytes = pending_drain_len,
                kcp_packets = out_packets.len(),
                total_udp_bytes = total_sent,
                "XTCP P2P: poll_flush sent KCP data"
            );
        }

        for pkt in &out_packets {
            match self.socket.try_send_to(pkt, self.peer_addr) {
                Ok(_) => {}
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    tracing::debug!(
                        peer = %self.peer_addr,
                        "XTCP P2P: UDP send would block on flush"
                    );
                }
                Err(e) => return Poll::Ready(Err(e)),
            }
        }

        // Also drain any incoming data and push decoded KCP app data
        // to the read channel. MUST call recv_and_push after input —
        // otherwise KCP decodes data internally but never exposes it
        // to poll_read, and the subsequent maybe_tick() would skip
        // drive_kcp() because poll_flush reset last_update (before fix).
        let mut buf = [0u8; 2048];
        loop {
            match self.socket.try_recv_from(&mut buf) {
                Ok((n, src)) if src == self.peer_addr => {
                    if &buf[..n] == HOLE_PUNCH_MAGIC {
                        continue;
                    }
                    if let Err(e) = self.session.input(&buf[..n]) {
                        tracing::debug!(error = %e, "XTCP P2P: input error on flush");
                    }
                }
                Ok(_) => {} // Non-peer packet, ignore
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(_) => break,
            }
        }
        if let Err(e) = self.session.recv_and_push() {
            tracing::debug!(error = %e, "XTCP P2P: recv_and_push error on flush");
        }

        // Do NOT reset last_update here. poll_flush is called on every yamux
        // I/O drive; resetting would prevent maybe_tick from ever reaching
        // KCP_TICK_MS, permanently stalling the data receive path.
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.shutdown = true;
        Poll::Ready(Ok(()))
    }
}

// Drop: UDP socket is closed when XtcpP2pStream is dropped.
// KCP session cleanup is automatic (drop).

// ---------------------------------------------------------------------------
// XTCP P2P io::stream helper: punch hole + create KCP stream in one step
// ---------------------------------------------------------------------------

/// Punch a UDP NAT hole to the peer and create a KCP-over-UDP stream.
///
/// This is the main entry point for XTCP P2P connections. It:
/// 1. Binds a UDP socket (or reuses an existing one)
/// 2. Sends hole-punch packets to candidates
/// 3. Waits for peer's hole-punch response
/// 4. Creates a KCP session over the established UDP path
/// 5. Returns an AsyncRead + AsyncWrite stream
///
/// `sid` and `key` enable Go-compat hole-punch (encrypted NatHoleSid
/// exchange). When both are `None`, uses simple "frp" magic (Rust↔Rust).
#[allow(clippy::too_many_arguments)]
pub async fn xtcp_p2p_connect(
    socket: UdpSocket,
    candidates: &[String],
    assisted: &[String],
    behavior: Option<&crate::msg::NatHoleDetectBehavior>,
    conv: u32,
    kcp_config: KcpConfig,
    hole_punch_timeout_ms: u64,
    sid: Option<&str>,
    key: Option<&[u8; 16]>,
) -> Result<XtcpP2pStream, String> {
    // 1. Punch hole. With a server-provided DetectBehavior, use the full Go
    //    MakeHole state machine; otherwise the simplified punch.
    //    MakeHole returns the socket the peer's detect reply arrived on —
    //    only that socket has a NAT mapping the peer can reach, so the KCP
    //    data plane must run on it (Go `result.lConn` semantics).
    let (win_socket, peer_addr) = match behavior {
        Some(b) => {
            punch_udp_hole_makehole_owned(
                socket,
                candidates,
                assisted,
                b,
                hole_punch_timeout_ms,
                sid,
                key,
            )
            .await?
        }
        None => {
            let peer_addr =
                punch_udp_hole(&socket, candidates, hole_punch_timeout_ms, sid, key).await?;
            (socket, peer_addr)
        }
    };

    tracing::info!(
        peer = %peer_addr,
        conv,
        candidates = candidates.len(),
        "XTCP P2P: hole punched to {}, conv={}",
        peer_addr,
        conv,
    );

    // 2. Create KCP stream.
    XtcpP2pStream::new(win_socket, peer_addr, conv, kcp_config)
        .map_err(|e| format!("create P2P stream: {}", e))
}

// ---------------------------------------------------------------------------
// XTCP P2P connect with yamux multiplexing (Go v0.70 compat)
// ---------------------------------------------------------------------------
//
// Go frp v0.70 wraps KCP with yamux before sending application data:
//   UDP socket → KCP → yamux → user stream
//
// When the `tcp-mux` feature is enabled (default), yamux multiplexing is
// used for Go v0.70 wire compatibility. When disabled, falls back to raw
// KCP (Rust↔Rust only).

/// Create a KCP-over-UDP P2P stream with yamux multiplexing (Go v0.70 compat).
///
/// `yamux_client` selects the yamux role:
/// - `true` = visitor (opens yamux stream, Mode::Client)
/// - `false` = provider (accepts yamux stream, Mode::Server)
///
/// `sid` and `key` enable Go-compat NatHoleSid detection protocol.
/// When both are `None`, uses simple "frp" magic (Rust↔Rust).
///
/// When `tcp-mux` feature is enabled, returns a yamux `Stream` (compat'd to
/// tokio traits). When disabled, returns the raw KCP stream.
///
/// A background task is spawned to drive the yamux Connection, which also
/// keeps KCP ticking (poll_read/poll_write trigger `maybe_tick` every 10ms).
/// Dead link detection in `maybe_tick` ensures the background task exits
/// when the peer stops responding; the returned
/// [`XtcpP2pYamuxStream`] additionally signals the driver to exit when the
/// caller drops the stream (so the UDP socket + KCP session are released
/// instead of leaking per ended XTCP session).
// --- yamux-enabled path (default) ---
#[cfg(feature = "tcp-mux")]
#[allow(clippy::too_many_arguments)]
pub async fn xtcp_p2p_connect_yamux(
    socket: UdpSocket,
    candidates: &[String],
    assisted: &[String],
    behavior: Option<&crate::msg::NatHoleDetectBehavior>,
    conv: u32,
    kcp_config: KcpConfig,
    hole_punch_timeout_ms: u64,
    yamux_client: bool,
    sid: Option<&str>,
    key: Option<&[u8; 16]>,
) -> Result<XtcpP2pYamuxStream, String> {
    use futures_util::future::poll_fn;
    use std::time::Duration;
    use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
    use yamux::{Config, Connection, Mode};

    // 1. Punch hole + create KCP stream.
    let kcp_stream = xtcp_p2p_connect(
        socket,
        candidates,
        assisted,
        behavior,
        conv,
        kcp_config,
        hole_punch_timeout_ms,
        sid,
        key,
    )
    .await?;

    // 2. Compat KCP stream to futures traits for yamux.
    let compat_stream = kcp_stream.compat();

    // 3. Create yamux Connection behind a tokio Mutex so lock
    //    contention yields instead of blocking the worker thread.
    //    Go frp sets MaxStreamWindowSize = 6 MB in the xtcp path.
    let mut yamux_cfg = Config::default();
    yamux_cfg.set_max_connection_receive_window(Some(6 * 1024 * 1024 * 64));
    yamux_cfg.set_max_num_streams(256);

    let mode = if yamux_client {
        Mode::Client
    } else {
        Mode::Server
    };
    let conn = Connection::new(compat_stream, yamux_cfg, mode);
    tracing::info!(
        conv,
        role = if yamux_client { "client" } else { "server" },
        "yamux P2P: Connection created"
    );
    let conn = Arc::new(tokio::sync::Mutex::new(conn));

    // 4. Background driver: periodically poll yamux to drive KCP ticks.
    //    Uses a noop-waker poll so each call is a single non-blocking
    //    probe — no circular waker dependency, no select! deadlock.
    //
    //    The driver's lifetime is bound to the caller's stream via the
    //    `driver_drop_tx`/`driver_drop_rx` watch channel: the caller-side
    //    guard ([`XtcpP2pYamuxStream`]) holds the sender and drops it when
    //    the bridge ends, at which point the driver selects out and exits,
    //    releasing the `Arc<Mutex<Connection>>` — and with it the UDP
    //    socket and KCP session. Without this, an ended XTCP session leaks
    //    one task + one UDP fd + KCP state permanently: an idle connection
    //    never trips `is_dead_link` (that needs unacked segments in flight;
    //    yamux keepalive pings are ACKed by the peer's still-alive session).
    let tick_ms = KCP_TICK_MS as u64;
    let bg_conn = conn.clone();
    let (stream_tx, stream_rx) = tokio::sync::oneshot::channel::<Result<yamux::Stream, String>>();
    let (driver_drop_tx, mut driver_drop_rx) = watch::channel(());

    tokio::spawn(async move {
        let keepalive = Duration::from_millis(tick_ms);
        let mut stream_tx = Some(stream_tx);
        let mut loop_count: u64 = 0;
        loop {
            loop_count += 1;
            // Acquire the lock (async — yields if contended).
            let mut c = bg_conn.lock().await;
            // Use timeout + poll_fn with a real tokio waker, matching the
            // server_mux pattern in mux.rs. The timeout ensures periodic
            // KCP ticks (via poll_read → maybe_tick → drive_kcp) even when
            // poll_next_inbound returns Pending (which is always, because
            // XtcpP2pStream's waker is self-referential — data is pushed by
            // maybe_tick which runs inside poll_read itself).
            //
            // The watch branch resolves when the caller-side guard
            // ([`XtcpP2pYamuxStream`]) is dropped (the sender is dropped,
            // closing the channel) — i.e. the caller's bridge ended and the
            // connection is no longer needed. A watch channel (not Notify)
            // guarantees the wakeup cannot be missed: the sender-drop
            // releases every registered receiver waker.
            let result = tokio::select! {
                _ = driver_drop_rx.changed() => break,
                r = tokio::time::timeout(
                    keepalive,
                    poll_fn(|cx| {
                        match c.poll_next_inbound(cx) {
                            Poll::Ready(r) => Poll::Ready(r),
                            Poll::Pending => {
                                // Double-poll: first poll processes stream
                                // commands into pending_frames; second poll
                                // sends them on the wire (matches mux.rs).
                                c.poll_next_inbound(cx)
                            }
                        }
                    }),
                ) => r,
            };
            match result {
                Ok(Some(Ok(stream))) => {
                    drop(c);
                    tracing::info!(
                        stream_id = stream.id().val(),
                        "yamux P2P: accepted inbound stream"
                    );
                    if let Some(tx) = stream_tx.take() {
                        if tx.send(Ok(stream)).is_err() {
                            tracing::debug!("yamux P2P: caller dropped, exiting");
                            break;
                        }
                    }
                }
                Ok(Some(Err(e))) => {
                    drop(c);
                    if let Some(tx) = stream_tx.take() {
                        let _ = tx.send(Err(format!("yamux: {e}")));
                    }
                    tracing::warn!(
                        error = %e,
                        kind = ?e,
                        loop_count,
                        "yamux P2P: connection error, exiting"
                    );
                    break;
                }
                Ok(None) => {
                    drop(c);
                    if let Some(tx) = stream_tx.take() {
                        let _ = tx.send(Err("yamux: connection closed before stream".into()));
                    }
                    tracing::warn!(
                        loop_count,
                        "yamux P2P: connection closed before stream (EOF)"
                    );
                    break;
                }
                Err(_elapsed) => {
                    // Timeout: keepalive expired without a stream.
                    // KCP tick was driven by poll_read→maybe_tick inside
                    // poll_next_inbound. Drop lock, loop, try again.
                    drop(c);
                    if loop_count <= 5 {
                        tracing::debug!(loop_count, "yamux P2P: bg driver tick (no stream yet)");
                    }
                }
            }
        }
        tracing::debug!("yamux P2P: background driver exiting");
    });

    // 5. Open or accept the first yamux stream.
    let stream = if yamux_client {
        // Visitor: acquire lock, open outbound stream, release.
        let mut c = conn.lock().await;
        tracing::info!("yamux P2P: opening outbound stream...");
        let stream = tokio::time::timeout(
            Duration::from_secs(10),
            poll_fn(|cx| c.poll_new_outbound(cx)),
        )
        .await
        .map_err(|_| "yamux: timeout opening stream (10s)".to_string())?
        .map_err(|e| format!("yamux open stream: {e}"))?;
        tracing::info!(
            stream_id = stream.id().val(),
            "yamux P2P: outbound stream opened"
        );
        stream
    } else {
        // Provider: wait for the background task to accept the first stream.
        tracing::info!("yamux P2P: waiting for inbound stream...");
        tokio::time::timeout(Duration::from_secs(10), stream_rx)
            .await
            .map_err(|_| "yamux: timeout waiting for stream (10s)".to_string())?
            .map_err(|e| format!("yamux accept: recv error: {e}"))?
            .map_err(|e| format!("yamux accept: {e}"))?
    };

    let tokio_stream = stream.compat();

    tracing::info!(
        conv,
        role = if yamux_client { "client" } else { "server" },
        "XTCP P2P yamux: stream established, conv={}",
        conv,
    );

    // Wrap the stream in the drop-signal guard: while this wrapper is alive
    // the background driver keeps the connection (and KCP/UDP state) alive;
    // dropping it closes the watch channel, making the driver exit and free
    // the UDP socket + KCP session. Any error path above this point returns
    // without a wrapper, so `driver_drop_tx` drops with the function's
    // locals and the driver exits the same way.
    Ok(XtcpP2pYamuxStream {
        inner: tokio_stream,
        driver_drop_tx,
    })
}

/// The yamux stream returned by [`xtcp_p2p_connect_yamux`], carrying the
/// driver-lifetime drop signal.
///
/// The background yamux driver task spawned by [`xtcp_p2p_connect_yamux`]
/// must keep polling the connection for the whole time the caller uses the
/// stream (yamux stream writes are queued to the connection driver, and
/// inbound frames / window updates are only processed when the connection is
/// polled), but must exit once the stream is gone so the connection — and
/// with it the XTCP P2P UDP socket and KCP session — is released instead of
/// leaking forever. This wrapper owns the `watch::Sender` end of the
/// driver's exit signal: when the wrapper is dropped (the caller's bridge
/// ended), the sender is dropped, the channel closes, and the driver's
/// `select!` resolves and exits.
#[cfg(feature = "tcp-mux")]
pub struct XtcpP2pYamuxStream {
    inner: crate::mux::YamuxStream,
    /// Drop signal to the background driver. Dropping this (with the
    /// wrapper) closes the channel and makes the driver exit. The driver
    /// holds only the `watch::Receiver`, so this is the sole sender.
    driver_drop_tx: watch::Sender<()>,
}

#[cfg(feature = "tcp-mux")]
impl Drop for XtcpP2pYamuxStream {
    fn drop(&mut self) {
        // Signal the background driver to exit. The watch channel fires on
        // sender drop anyway (the driver's select! waits on changed()); the
        // explicit send is belt-and-braces so the wakeup happens before any
        // other Drop logic runs. An Err here just means the driver already
        // exited, which is the desired end state.
        let _ = self.driver_drop_tx.send(());
    }
}

#[cfg(feature = "tcp-mux")]
impl tokio::io::AsyncRead for XtcpP2pYamuxStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

#[cfg(feature = "tcp-mux")]
impl tokio::io::AsyncWrite for XtcpP2pYamuxStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

// ---------------------------------------------------------------------------
// XTCP P2P connect with QUIC data plane (Go v0.70.1 `protocol=quic` compat)
// ---------------------------------------------------------------------------
//
// Go frp v0.70.1 runs QUIC directly over the hole-punched UDP socket — no
// yamux, because QUIC multiplexes streams itself:
//   UDP socket → QUIC connection → bidirectional stream → user stream
//
// The visitor acts as the QUIC client (dials + opens a stream), the provider
// as the QUIC server (accepts + accepts a stream). TLS uses a runtime
// self-signed cert on the server and InsecureSkipVerify on the client (Go
// frp behavior); the ALPN is `frp`.

/// Trait object for a P2P data-plane stream — either the KCP/yamux stream
/// (`xtcp_p2p_connect_yamux`) or the QUIC stream (`xtcp_p2p_connect_quic`).
/// Call sites box the chosen transport so the bridge code is shared.
pub trait P2pStream: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send> P2pStream for T {}

/// Punch a UDP NAT hole and create a QUIC-over-UDP P2P stream.
///
/// Counterpart of [`xtcp_p2p_connect_yamux`] for the QUIC data plane
/// (`protocol = "quic"` in Go frp v0.70.1). `is_server` selects the QUIC
/// role: `true` = provider (QUIC server, accepts the connection + stream),
/// `false` = visitor (QUIC client, dials + opens the stream).
///
/// The winning hole-punch socket is handed to quinn directly so the NAT
/// mapping is preserved (`quic.Dial`/`quic.Listen` on `result.lConn` in Go).
/// `sid`/`key` enable Go-compat NatHoleSid detection; when both are `None`
/// the simple "frp" magic is used (Rust↔Rust).
#[cfg(feature = "quic")]
#[allow(clippy::too_many_arguments)]
pub async fn xtcp_p2p_connect_quic(
    socket: UdpSocket,
    candidates: &[String],
    assisted: &[String],
    behavior: Option<&crate::msg::NatHoleDetectBehavior>,
    timeout_ms: u64,
    sid: Option<&str>,
    key: Option<&[u8; 16]>,
    is_server: bool,
) -> Result<crate::quic::QuicStream, String> {
    // 1. Punch hole. With a server-provided DetectBehavior use the full Go
    //    MakeHole state machine, otherwise the simplified punch. The winning
    //    socket (the one the peer's detect reply arrived on) keeps the only
    //    NAT mapping the peer can reach, so the QUIC endpoint must use it.
    let (win_socket, peer_addr) = match behavior {
        Some(b) => {
            punch_udp_hole_makehole_owned(socket, candidates, assisted, b, timeout_ms, sid, key)
                .await?
        }
        None => {
            let peer_addr = punch_udp_hole(&socket, candidates, timeout_ms, sid, key).await?;
            (socket, peer_addr)
        }
    };

    tracing::info!(
        peer = %peer_addr,
        role = if is_server { "server" } else { "client" },
        "XTCP P2P QUIC: hole punched to {}",
        peer_addr,
    );

    // 2. Hand the winning tokio socket to quinn as a std socket.
    let std_socket = win_socket
        .into_std()
        .map_err(|e| format!("convert UDP socket to std: {e}"))?;
    let params = crate::quic::QuicTransportParams::default();

    // 3. QUIC data plane over the punched socket.
    if is_server {
        // Provider = QUIC server: self-signed TLS, accept connection + stream.
        // Bound the stream accept by the hole-punch timeout so a visitor that
        // never writes (quinn opens streams lazily on first write) cannot pin
        // the provider task forever — the caller reports NatHoleReport(false)
        // on error.
        let tls_config = crate::transport::generate_self_signed_tls_config()
            .map_err(|e| format!("generate self-signed TLS config: {e}"))?;
        let conn = crate::quic::quic_accept_on_socket(std_socket, tls_config, params)
            .await
            .map_err(|e| format!("QUIC accept: {e}"))?;
        let stream = tokio::time::timeout(
            std::time::Duration::from_millis(timeout_ms.max(1)),
            conn.accept_bi_owned(),
        )
        .await
        .map_err(|_| format!("QUIC stream accept timeout after {timeout_ms}ms"))?
        .map_err(|e| format!("QUIC accept stream: {e}"))?;
        Ok(stream)
    } else {
        // Visitor = QUIC client: dial (InsecureSkipVerify) + open stream.
        let (stream, _conn) = crate::quic::quic_dial_on_socket(
            std_socket,
            peer_addr,
            &peer_addr.ip().to_string(),
            params,
        )
        .await
        .map_err(|e| format!("QUIC dial: {e}"))?;
        Ok(stream)
    }
}

// --- Fallback when tcp-mux is disabled ---

#[cfg(not(feature = "tcp-mux"))]
#[allow(clippy::too_many_arguments)]
pub async fn xtcp_p2p_connect_yamux(
    socket: UdpSocket,
    candidates: &[String],
    assisted: &[String],
    behavior: Option<&crate::msg::NatHoleDetectBehavior>,
    conv: u32,
    kcp_config: KcpConfig,
    hole_punch_timeout_ms: u64,
    _yamux_client: bool,
    _sid: Option<&str>,
    _key: Option<&[u8; 16]>,
) -> Result<XtcpP2pStream, String> {
    tracing::info!(
        conv,
        "XTCP P2P: yamux disabled (tcp-mux feature off), using raw KCP stream, conv={}",
        conv,
    );
    xtcp_p2p_connect(
        socket,
        candidates,
        assisted,
        behavior,
        conv,
        kcp_config,
        hole_punch_timeout_ms,
        _sid,
        _key,
    )
    .await
}

// ---------------------------------------------------------------------------
// Go MakeHole state machine (pkg/nathole/nathole.go MakeHole)
// ---------------------------------------------------------------------------
//
// Full-feature hole punch matching Go frp v0.70.1:
// - sender role: optional SendDelayMs wait, probes AssistedAddrs + CandidateAddrs
// - receiver role: optional ListenRandomPorts extra sockets
// - CandidatePorts range scanning on receiver side
// - SendRandomPorts random-port probing
// - TTL applied to probe packets
// The simplified `punch_udp_hole` remains for Rust↔Rust/no-behavior callers.

/// Send an encrypted NatHoleSid probe (or "frp" magic) from `socket` to `addr`.
///
/// TTL is managed by `punch_udp_hole_makehole`, which sets it once for the
/// whole probe phase and restores the original value afterwards (Go
/// `sendSidMessage` sets the TTL per packet with a deferred restore).
async fn send_sid_probe(
    socket: &UdpSocket,
    addr: SocketAddr,
    sid: Option<&str>,
    key: Option<&[u8; 16]>,
) {
    match (sid, key) {
        (Some(sid_str), Some(enc_key)) => {
            let msg = NatHoleDetectSid::new(sid_str, false);
            if let Ok(encoded) = encode_detect_msg(&msg, enc_key) {
                if let Err(e) = socket.send_to(&encoded, addr).await {
                    tracing::debug!(%addr, error = %e, "XTCP MakeHole: sid probe send failed");
                }
            }
        }
        _ => {
            if let Err(e) = socket.send_to(HOLE_PUNCH_MAGIC, addr).await {
                tracing::debug!(%addr, error = %e, "XTCP MakeHole: magic probe send failed");
            }
        }
    }
}

/// Wait for a NatHoleSid/magic detect message on any of `sockets`, returning
/// the index of the socket that received the answer and the peer address.
/// Mirrors Go `waitDetectMessage` + multi-socket select:
/// - receiver: echoes a non-response probe back as `response:true`, then
///   returns the peer (Go nathole.go waitDetectMessage).
/// - sender: only accepts `response:true` (or the Rust "frp" magic from a
///   candidate address).
///
/// The winning socket index is important: in Go the NAT mapping that the peer
/// replies to is specific to the socket that received the probe, so the data
/// plane must run on that exact socket (`result.lConn`), not on the original
/// STUN socket.
///
/// All sockets are polled concurrently under ONE shared deadline (Go spawns
/// one goroutine per socket and selects on the result channel, nathole.go
/// 264-287). The old sequential 50 ms-per-socket scan took 257×50 ms ≈ 12.8s
/// per pass with `listen_random_ports` at its cap — longer than the whole 5s
/// detect budget — so a reply on the last socket was never seen in time.
async fn wait_detect_on_any(
    sockets: &[&UdpSocket],
    peers: &[SocketAddr],
    role: &str,
    timeout_ms: u64,
    sid: Option<&str>,
    key: Option<&[u8; 16]>,
) -> Result<(usize, SocketAddr), String> {
    let start = std::time::Instant::now();
    loop {
        let remaining_ms = timeout_ms.saturating_sub(start.elapsed().as_millis() as u64);
        if remaining_ms == 0 {
            return Err(format!(
                "wait detect message timeout after {}ms",
                timeout_ms
            ));
        }
        // One future per socket, each owning its receive buffer (a shared
        // buffer cannot be mutably borrowed by concurrent recv futures).
        // Boxed so select_all can poll them (async blocks are !Unpin).
        let futures: Vec<_> = sockets
            .iter()
            .enumerate()
            .map(|(idx, s)| {
                let s = *s;
                async move {
                    let mut buf = [0u8; 1024];
                    let r = s.recv_from(&mut buf).await;
                    (idx, r, buf)
                }
                .boxed()
            })
            .collect();
        let (idx, r, buf) = match tokio::time::timeout(
            std::time::Duration::from_millis(remaining_ms),
            futures_util::future::select_all(futures),
        )
        .await
        {
            Ok((winner, _, _)) => winner,
            Err(_elapsed) => {
                return Err(format!(
                    "wait detect message timeout after {}ms",
                    timeout_ms
                ));
            }
        };
        let s = sockets[idx];
        match r {
            Ok((n, peer)) => {
                let data = &buf[..n];
                if data == HOLE_PUNCH_MAGIC {
                    // Rust magic: only accept from a known candidate
                    // (a receiver's extra listener socket is not one).
                    if peers.contains(&peer) {
                        return Ok((idx, peer));
                    }
                    continue;
                }
                if let (Some(sid_str), Some(enc_key)) = (sid, key) {
                    if let Ok(msg) = decode_detect_msg(data, enc_key) {
                        if msg.sid == sid_str && (msg.response || role == "receiver") {
                            // Receiver echoes the probe as a response
                            // (Go waitDetectMessage), then returns.
                            if role == "receiver" && !msg.response {
                                let mut echo = msg;
                                echo.response = true;
                                if let Ok(encoded) = encode_detect_msg(&echo, enc_key) {
                                    let _ = s.send_to(&encoded, peer).await;
                                }
                            }
                            return Ok((idx, peer));
                        }
                        // Sender got a plain probe — keep waiting.
                    }
                }
            }
            Err(_) => return Err("recv error during MakeHole detect".into()),
        }
    }
}

/// Defensive caps on server-supplied probe parameters. `detect_behavior`
/// arrives from the frps over the control channel; a compromised or buggy
/// server must not be able to drive an unbounded probe flood (each probe is
/// a UDP send, and candidate-port scanning also sleeps 2 ms per port).
/// These are upper bounds far above anything the NAT analyzer emits, so
/// legitimate behaviors are unaffected.
const MAX_LISTEN_RANDOM_PORTS: i32 = 256; // extra receiver listener sockets (Go NAT analyzer recommends up to 256)
const MAX_CANDIDATE_PORT_PROBES: u64 = 2048; // total candidate-port-range probes

/// Go `MakeHole` full-feature hole punch (owned socket variant).
///
/// `socket` is the STUN socket (owned; extra listener sockets are created
/// internally for `ListenRandomPorts`). `candidates` are the peer's STUN
/// addresses, `assisted` its assisted addresses.
///
/// Returns the socket that won the detect phase (the one the peer's detect
/// reply arrived on) plus the peer address. This mirrors Go's `result.lConn`
/// semantics: only the winning socket has a NAT mapping that the peer can
/// reach, so the KCP data plane must run on it.
#[allow(clippy::too_many_arguments)]
pub async fn punch_udp_hole_makehole_owned(
    socket: UdpSocket,
    candidates: &[String],
    assisted: &[String],
    behavior: &crate::msg::NatHoleDetectBehavior,
    timeout_ms: u64,
    sid: Option<&str>,
    key: Option<&[u8; 16]>,
) -> Result<(UdpSocket, SocketAddr), String> {
    // Go nathole.go MakeHole: only `Role == DetectRoleSender` takes the
    // sender arm (sleep + probe assisted+candidates); EVERYTHING else —
    // including an unknown/empty role from a hostile or legacy server — is
    // the receiver (see `resolve_punch_role`).
    let role = resolve_punch_role(behavior.role.as_deref());
    let ttl = behavior.ttl;
    // Go MakeHole: `timeout := 5 * time.Second; if ReadTimeoutMs > 0 {
    // timeout = ReadTimeoutMs * ms }`. The server computes ReadTimeoutMs as
    // (max(SendDelayMs)+5000 [+30000 if listen_random_ports]) minus the
    // side's own send_delay, so it is normally positive; fall back to 5s
    // when the server sent 0 or negative (Go keeps 5s in that case). Also
    // capped at MAX_HOLE_PUNCH_TIMEOUT_MS — a hostile server must not be
    // able to stretch the detect wait to ~24.8 days (the caller caps too;
    // this is the punch's own invariant).
    let timeout_ms = if timeout_ms > 0 {
        timeout_ms.min(MAX_HOLE_PUNCH_TIMEOUT_MS)
    } else {
        DEFAULT_HOLE_PUNCH_TIMEOUT_MS
    };

    // Sender waits SendDelayMs before probing (Go MakeHole). Capped: Go's
    // analyzer emits ≤ 10s, so anything above MAX_SEND_DELAY_MS is a hostile
    // server trying to stall the punch (send_delay_ms is i32 — uncapped it
    // would sleep ~24.8 days).
    if role == "sender" && behavior.send_delay_ms > 0 {
        let delay_ms = (behavior.send_delay_ms as u64).min(MAX_SEND_DELAY_MS);
        if behavior.send_delay_ms as u64 > MAX_SEND_DELAY_MS {
            tracing::warn!(
                configured = behavior.send_delay_ms,
                capped = MAX_SEND_DELAY_MS,
                "XTCP MakeHole: send_delay_ms capped"
            );
        }
        tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
    }

    // Detect address set: assisted + candidates (sender), or candidates when
    // the receiver has no candidate ports to scan (Go MakeHole).
    let mut detect_addrs: Vec<String> = Vec::new();
    if role == "sender" {
        detect_addrs.extend(assisted.iter().cloned());
        detect_addrs.extend(candidates.iter().cloned());
    } else if behavior
        .candidate_ports
        .as_ref()
        .is_none_or(|v| v.is_empty())
    {
        detect_addrs.extend(candidates.iter().cloned());
    }
    detect_addrs.sort();
    detect_addrs.dedup();

    let parsed: Vec<SocketAddr> = detect_addrs.iter().filter_map(|a| a.parse().ok()).collect();

    // All sockets: the STUN socket plus extra receiver listener sockets
    // (Go ListenRandomPorts). Index 0 is always the STUN socket.
    let mut all: Vec<Arc<UdpSocket>> = Vec::new();
    all.push(Arc::new(socket));
    let mut orig_ttls: Vec<Option<u32>> = vec![all[0].ttl().ok()];
    // Go sets the probe TTL for the whole detect phase (defer-restored after
    // each send); keep it constant here and restore at the end. ttl <= 0
    // leaves the socket TTL untouched (Go `if ttl > 0`).
    if ttl > 0 {
        let _ = all[0].set_ttl(ttl as u32);
    }
    if role == "receiver" && behavior.listen_random_ports > 0 {
        // Cap the number of extra listener sockets (defensive — a
        // server-supplied value must not force an unbounded socket bind
        // flood; see MAX_LISTEN_RANDOM_PORTS).
        let n = behavior.listen_random_ports.min(MAX_LISTEN_RANDOM_PORTS);
        if behavior.listen_random_ports > MAX_LISTEN_RANDOM_PORTS {
            tracing::warn!(
                configured = behavior.listen_random_ports,
                capped = MAX_LISTEN_RANDOM_PORTS,
                "XTCP MakeHole: listen_random_ports capped"
            );
        }
        for _ in 0..n {
            if let Ok(s) = tokio::net::UdpSocket::bind("0.0.0.0:0").await {
                orig_ttls.push(s.ttl().ok());
                if ttl > 0 {
                    let _ = s.set_ttl(ttl as u32);
                }
                all.push(Arc::new(s));
            }
        }
    }

    // Base probes: every detect address from every socket (Go MakeHole
    // `for detectAddr { for conn { sendSidMessage } }`).
    for addr in &parsed {
        for s in &all {
            send_sid_probe(s, *addr, sid, key).await;
        }
    }

    // Candidate port range scanning (Go sendSidMessageToRangePorts): probe
    // each candidate IP's port range from every socket, 2 ms between ports.
    if let Some(ref ranges) = behavior.candidate_ports {
        // Cap the total number of range-scan probes (defensive — a
        // server-supplied value must not force an unbounded probe flood;
        // see MAX_CANDIDATE_PORT_PROBES). Counts across sockets ×
        // candidates × ranges so a malicious server cannot multiply the
        // budget by repeating entries.
        let mut probe_count: u64 = 0;
        'scan: for s in &all {
            for cand in candidates {
                let Ok(base) = cand.parse::<SocketAddr>() else {
                    continue;
                };
                for r in ranges {
                    for p in r.from.max(1)..=r.to.max(1) {
                        probe_count += 1;
                        if probe_count > MAX_CANDIDATE_PORT_PROBES {
                            tracing::warn!(
                                capped = MAX_CANDIDATE_PORT_PROBES,
                                "XTCP MakeHole: candidate_ports probe count capped"
                            );
                            break 'scan;
                        }
                        let target = SocketAddr::new(base.ip(), p as u16);
                        send_sid_probe(s, target, sid, key).await;
                        tokio::time::sleep(std::time::Duration::from_millis(2)).await;
                    }
                }
            }
        }
    }

    // SendRandomPorts: one concurrent probing task per socket (Go spawns a
    // goroutine per listen conn). Random ports in [1024, 65535], 15 ms apart.
    // The tasks keep probing while we wait for the detect reply and are
    // stopped once a reply arrives (Go cancels the shared context).
    let cancelled = Arc::new(AtomicBool::new(false));
    let mut random_handles = Vec::new();
    if behavior.send_random_ports > 0 {
        let candidate_ips: Vec<SocketAddr> =
            candidates.iter().filter_map(|a| a.parse().ok()).collect();
        // Owned copies for the spawned tasks (spawn requires 'static).
        let sid_owned = sid.map(|s| s.to_string());
        let key_owned = key.copied();
        for s in &all {
            let s = s.clone();
            let cancelled = cancelled.clone();
            let cips = candidate_ips.clone();
            let sid_task = sid_owned.clone();
            let key_task = key_owned;
            let n = behavior.send_random_ports as usize;
            random_handles.push(tokio::spawn(async move {
                send_random_ports_probe(
                    &s,
                    &cips,
                    n,
                    &cancelled,
                    sid_task.as_deref(),
                    key_task.as_ref(),
                )
                .await;
            }));
        }
    }

    // Wait for a detect response on any socket. The source-address allowlist
    // is the peer's candidate set (a receiver's extra listener sockets are
    // not candidates and must be ignored).
    let candidate_peers: Vec<SocketAddr> =
        candidates.iter().filter_map(|a| a.parse().ok()).collect();
    let refs: Vec<&UdpSocket> = all.iter().map(|a| a.as_ref()).collect();
    let detect_result =
        wait_detect_on_any(&refs, &candidate_peers, role, timeout_ms, sid, key).await;

    // Always stop the random-port probing tasks and restore the original TTL
    // on the winning socket, mirroring Go's `defer cancel()` + `defer
    // SetTTL(original)` — even when the detect wait failed.
    cancelled.store(true, Ordering::Relaxed);
    for h in random_handles {
        let _ = h.await;
    }
    let (win_idx, peer_addr) = detect_result?;
    if ttl > 0 {
        if let Some(ot) = orig_ttls[win_idx] {
            let _ = all[win_idx].set_ttl(ot);
        }
    }

    // Extract the winning socket; the rest are dropped (Go closes the losers).
    let win_socket = Arc::try_unwrap(all.swap_remove(win_idx))
        .map_err(|_| "MakeHole: winning socket still referenced".to_string())?;
    Ok((win_socket, peer_addr))
}

/// Go `sendSidMessageToRandomPorts`: probe `count` distinct random ports in
/// [1024, 65535] on every candidate IP, pausing 15 ms between sends. Stops
/// early once `cancelled` is set (Go ctx.Done).
async fn send_random_ports_probe(
    socket: &UdpSocket,
    candidate_addrs: &[SocketAddr],
    count: usize,
    cancelled: &AtomicBool,
    sid: Option<&str>,
    key: Option<&[u8; 16]>,
) {
    let mut used: std::collections::HashSet<u16> = std::collections::HashSet::new();
    for _ in 0..count {
        if cancelled.load(Ordering::Relaxed) {
            return;
        }
        let port = get_unused_random_port(&mut used);
        if port == 0 {
            continue;
        }
        for base in candidate_addrs {
            if cancelled.load(Ordering::Relaxed) {
                return;
            }
            let target = SocketAddr::new(base.ip(), port);
            send_sid_probe(socket, target, sid, key).await;
            tokio::time::sleep(std::time::Duration::from_millis(15)).await;
        }
    }
}

/// Go `getUnusedPort`: a random port in [1024, 65535] not yet used, retrying
/// up to 10 times; returns 0 when none was found (caller skips the round).
fn get_unused_random_port(used: &mut std::collections::HashSet<u16>) -> u16 {
    let mut rng = rand::thread_rng();
    for _ in 0..10 {
        let port = rand::Rng::gen_range(&mut rng, 1024..=65534);
        if used.insert(port) {
            return port;
        }
    }
    0
}

#[cfg(test)]
mod tests {
    use super::resolve_punch_role;

    #[test]
    fn punch_role_defaults_to_receiver() {
        // Go nathole.go MakeHole (v0.71.0): `if role == DetectRoleSender`
        // takes the sender arm; any other value — empty, unknown, or
        // missing — falls into the `else` (receiver) branch.
        assert_eq!(resolve_punch_role(None), "receiver");
        assert_eq!(resolve_punch_role(Some("")), "receiver");
        assert_eq!(resolve_punch_role(Some("spoofer")), "receiver");
        assert_eq!(resolve_punch_role(Some("sender")), "sender");
    }
}
