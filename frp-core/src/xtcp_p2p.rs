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

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Instant;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, Notify};

use crate::kcp::{KcpConfig, KcpSession};

/// Hole-punch magic bytes — must match Go frp v0.70 `var holePunchPacket = []byte("frp")`.
const HOLE_PUNCH_MAGIC: &[u8] = b"frp";

/// Default KCP tick interval (ms). 10 ms matches Go frp kcp-go default.
const KCP_TICK_MS: u32 = 10;

/// Default timeout for hole-punch response.
pub const DEFAULT_HOLE_PUNCH_TIMEOUT_MS: u64 = 5000;

/// Derive a KCP conversation ID from a shared session identifier.
///
/// Both sides of an XTCP P2P connection must use the same `conv` for KCP
/// packets to be accepted by the peer's session (the `kcp` crate drops
/// packets with mismatched `conv` when `input_conv` is `false`).
///
/// The NAT hole-punch session ID (`sid`) is known to both visitor (via
/// `NatHoleResp.sid`) and provider (via `XtcpNotification` / `NatHoleResp`).
pub fn conv_from_sid(sid: &str) -> u32 {
    // Use MD5 for deterministic cross-process hashing.
    // DefaultHasher (SipHash) uses a per-process random key — two processes
    // hashing the same sid get different values, causing KCP conv mismatch
    // and "conv inconsistent" errors on P2P hole-punched connections.
    use md5::{Digest, Md5};
    let digest = Md5::digest(sid.as_bytes());
    let mut buf = [0u8; 4];
    buf.copy_from_slice(&digest[..4]);
    (u32::from_be_bytes(buf)).max(1)
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
            nonce: String::new(),
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
    let json_len = u64::from_be_bytes(frame[1..9].try_into().unwrap()) as usize;
    if frame.len() < 9 + json_len {
        return Err(format!(
            "frame truncated: need {} bytes, have {}",
            9 + json_len,
            frame.len()
        ));
    }
    let json = &frame[9..9 + json_len];
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
        let sid_str = sid.unwrap();
        let enc_key = key.unwrap();
        let detect_msg = NatHoleDetectSid::new(sid_str, false);
        let encoded = match encode_detect_msg(&detect_msg, enc_key) {
            Ok(e) => e,
            Err(e) => {
                tracing::debug!("XTCP P2P: failed to encode NatHoleSid: {e}");
                return Err(format!("encode NatHoleSid: {e}"));
            }
        };
        for peer in &peers {
            let _ = socket.send_to(&encoded, *peer).await;
        }
    } else {
        // Simple "frp" magic (Rust↔Rust with no encryption key).
        for peer in &peers {
            let _ = socket.send_to(HOLE_PUNCH_MAGIC, *peer).await;
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
                            let _ = socket.send_to(&encoded, peer).await;
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
                            let _ = socket.send_to(&encoded, peer).await;
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
}

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
            self.session.send(&data)?;
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
        // in drive_kcp after pending_send is flushed to KCP. Without this,
        // a write-heavy one-directional stream could grow pending_send
        // without bound if UDP sends are slower than data arrival.
        if self.pending_send.len() >= PENDING_SEND_HIGH_WATER {
            let notified = self.write_notify.clone().notified_owned();
            let mut pinned = Box::pin(notified);
            match pinned.as_mut().poll(cx) {
                Poll::Ready(()) => {
                    // pending_send was drained between check and here.
                    // Fall through to append data.
                }
                Poll::Pending => return Poll::Pending,
            }
        }

        // Accumulate send data — flush happens in drive_kcp.
        self.pending_send.extend_from_slice(buf);

        // Drive KCP to flush.
        self.maybe_tick()?;

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
        if !self.pending_send.is_empty() {
            let data = std::mem::take(&mut self.pending_send);
            let _ = self.session.send(&data);
        }

        // Force-flush: update KCP and send all output immediately.
        let now_ms = self.created.elapsed().as_millis() as u32;
        let out_packets = match self.session.force_flush(now_ms) {
            Ok(pkts) => pkts,
            Err(e) => return Poll::Ready(Err(e)),
        };

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
pub async fn xtcp_p2p_connect(
    socket: UdpSocket,
    candidates: &[String],
    conv: u32,
    kcp_config: KcpConfig,
    hole_punch_timeout_ms: u64,
    sid: Option<&str>,
    key: Option<&[u8; 16]>,
) -> Result<XtcpP2pStream, String> {
    // 1. Punch hole.
    let peer_addr = punch_udp_hole(&socket, candidates, hole_punch_timeout_ms, sid, key).await?;

    tracing::info!(
        peer = %peer_addr,
        conv,
        candidates = candidates.len(),
        "XTCP P2P: hole punched to {}, conv={}",
        peer_addr,
        conv,
    );

    // 2. Create KCP stream.
    XtcpP2pStream::new(socket, peer_addr, conv, kcp_config)
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
/// when the peer stops responding.
// --- yamux-enabled path (default) ---
#[cfg(feature = "tcp-mux")]
#[allow(clippy::too_many_arguments)]
pub async fn xtcp_p2p_connect_yamux(
    socket: UdpSocket,
    candidates: &[String],
    conv: u32,
    kcp_config: KcpConfig,
    hole_punch_timeout_ms: u64,
    yamux_client: bool,
    sid: Option<&str>,
    key: Option<&[u8; 16]>,
) -> Result<crate::mux::YamuxStream, String> {
    use futures_util::future::poll_fn;
    use std::time::Duration;
    use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
    use yamux::{Config, Connection, Mode};

    // 1. Punch hole + create KCP stream.
    let kcp_stream = xtcp_p2p_connect(
        socket,
        candidates,
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
    let mut yamux_cfg = Config::default();
    yamux_cfg.set_max_connection_receive_window(Some(128 * 1024 * 1024));
    yamux_cfg.set_max_num_streams(256);

    let mode = if yamux_client {
        Mode::Client
    } else {
        Mode::Server
    };
    let conn = Connection::new(compat_stream, yamux_cfg, mode);
    let conn = Arc::new(tokio::sync::Mutex::new(conn));

    // 4. Background driver: periodically poll yamux to drive KCP ticks.
    //    Uses a noop-waker poll so each call is a single non-blocking
    //    probe — no circular waker dependency, no select! deadlock.
    let tick_ms = KCP_TICK_MS as u64;
    let bg_conn = conn.clone();
    let (stream_tx, stream_rx) = tokio::sync::oneshot::channel::<Result<yamux::Stream, String>>();

    tokio::spawn(async move {
        let keepalive = Duration::from_millis(tick_ms);
        let mut stream_tx = Some(stream_tx);
        loop {
            // Acquire the lock (async — yields if contended).
            let mut c = bg_conn.lock().await;
            // Use timeout + poll_fn with a real tokio waker, matching the
            // server_mux pattern in mux.rs. The timeout ensures periodic
            // KCP ticks (via poll_read → maybe_tick → drive_kcp) even when
            // poll_next_inbound returns Pending (which is always, because
            // XtcpP2pStream's waker is self-referential — data is pushed by
            // maybe_tick which runs inside poll_read itself).
            let result = tokio::time::timeout(
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
            )
            .await;
            match result {
                Ok(Some(Ok(stream))) => {
                    drop(c);
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
                    tracing::debug!("yamux P2P: connection error, exiting");
                    break;
                }
                Ok(None) => {
                    drop(c);
                    if let Some(tx) = stream_tx.take() {
                        let _ = tx.send(Err("yamux: connection closed before stream".into()));
                    }
                    tracing::debug!("yamux P2P: connection closed, exiting");
                    break;
                }
                Err(_elapsed) => {
                    // Timeout: keepalive expired without a stream.
                    // KCP tick was driven by poll_read→maybe_tick inside
                    // poll_next_inbound. Drop lock, loop, try again.
                    drop(c);
                }
            }
        }
        tracing::debug!("yamux P2P: background driver exiting");
    });

    // 5. Open or accept the first yamux stream.
    let stream = if yamux_client {
        // Visitor: acquire lock, open outbound stream, release.
        let mut c = conn.lock().await;
        tokio::time::timeout(
            Duration::from_secs(10),
            poll_fn(|cx| c.poll_new_outbound(cx)),
        )
        .await
        .map_err(|_| "yamux: timeout opening stream (10s)".to_string())?
        .map_err(|e| format!("yamux open stream: {e}"))?
    } else {
        // Provider: wait for the background task to accept the first stream.
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

    Ok(tokio_stream)
}

// --- Fallback when tcp-mux is disabled ---

#[cfg(not(feature = "tcp-mux"))]
pub async fn xtcp_p2p_connect_yamux(
    socket: UdpSocket,
    candidates: &[String],
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
        conv,
        kcp_config,
        hole_punch_timeout_ms,
        _sid,
        _key,
    )
    .await
}
