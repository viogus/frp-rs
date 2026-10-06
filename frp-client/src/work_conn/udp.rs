//! Client-side UDP/SUDP work-connection family.
//!
//! Split out of `work_conn.rs` as a pure text move; the parent imports
//! `run_udp_work_conn` and its inline test module re-imports the UDP session
//! helpers it drives.

use super::*;

#[allow(clippy::too_many_arguments)]
/// Per-remote UDP session: receives replies from the local service on its
/// dedicated socket and forwards them to the work-conn writer channel.
/// Exits after `UDP_SESSION_IDLE_TIMEOUT` of no traffic and removes itself
/// from the session table so its ephemeral port is released.
///
/// 30s = Go parity (pkg/proto/udp/udp.go writerFn): Go sets a 30s
/// `SetReadDeadline` on the REAL dialed UDP conn, refreshed on every packet
/// in BOTH directions — a session that goes 30s without ANY traffic (inbound
/// reply or outbound write) is evicted. frp-rs was 60s; the extra 30s held
/// ephemeral ports + a session-table entry on idle remotes.
pub(super) const UDP_SESSION_IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// The same idle threshold in milliseconds, for the u64 epoch-millis
/// liveness timestamps (kept in sync with `UDP_SESSION_IDLE_TIMEOUT`).
pub(super) const UDP_SESSION_IDLE_TIMEOUT_MS: u64 = UDP_SESSION_IDLE_TIMEOUT.as_millis() as u64;

/// Application-level keepalive Ping interval on UDP/SUDP work conns,
/// FIXED at 30s (audit F1).
///
/// Go parity: client/proxy/udp.go heartbeatFn hardcodes 30s and is wired
/// unconditionally — no config can change it (Go has no per-proxy
/// transport keepalive knob for this; dial_server_keepalive in frp-rs is a
/// socket-level SO_KEEPALIVE setting for the control/TCP dials and never
/// reaches this pinger). The server side relies on it: server/proxy/udp.go
/// workConnReaderFn sets a 60s per-read deadline on the UDP work conn, so a
/// configurable (7200s default) interval killed idle conns after 60s — the
/// Rust server's UDP_WORK_CONN_READ_TIMEOUT is the same 60s.
pub(super) const UDP_WORK_CONN_PING_INTERVAL: Duration = Duration::from_secs(30);

/// Current time as u64 epoch milliseconds. The timestamp is only a liveness
/// signal (all sites use Relaxed stores/loads, no happens-before needed), so
/// wall-clock rather than monotonic time is fine; saturates to 0 if the
/// clock is before the Unix epoch (unreachable in practice).
pub(super) fn now_epoch_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// One remote visitor's UDP session: its own local socket (bound to a fresh
/// ephemeral port on the local IP) plus bookkeeping.
///
/// `last_active` is an `Arc<AtomicU64>` holding epoch milliseconds, SHARED
/// with the session's reader task (`run_udp_session`). The reader task
/// refreshes it per inbound packet (local replies) with one lock-free
/// Relaxed store — that side of the per-packet path takes no shard lock.
/// The work-conn reader refreshes it per remote datagram too, but it must
/// reach the entry through the shard to find the `Arc`: it clones the Arc
/// under the shard lock and performs the store AFTER the guard drops (the
/// store itself has no ordering dependency on the shard — both writers use
/// Relaxed). The shard lock therefore guards only map access (lookup,
/// insert/remove, the reap sweep), never a liveness write.
pub(super) struct UdpSession {
    pub(super) socket: Arc<UdpSocket>,
    pub(super) last_active: Arc<AtomicU64>,
    pub(super) first_packet: bool,
}

/// Sharded remote-visitor session table (8 shards).
///
/// The session reader task's per-packet liveness refresh is lock-free: it
/// shares an `Arc<AtomicU64>` with the table entry, so its per-packet path
/// is one Relaxed store with no shard-lock acquire or hash lookup. The
/// work-conn reader's per-packet path DOES take the shard — a short
/// lock + hash lookup to fetch the session's send socket (via the
/// reader-owned mirror) and its `last_active` Arc — but concurrent remotes
/// hash to different shards, so traffic never serializes on a single cache
/// line, and no critical section is held across an await (bind/connect
/// happen outside any lock). The `first_packet` flag is written only by the
/// work-conn reader between the map insert and the same iteration's clear
/// (no await in between), so mirror-arm hits can only ever observe it as
/// `false`; the session reader task never touches it.
pub(super) struct UdpSessionTable {
    shards: [std::sync::Mutex<HashMap<SocketAddr, UdpSession>>; UDP_SESSION_SHARDS],
}

const UDP_SESSION_SHARDS: usize = 8;

impl UdpSessionTable {
    pub(super) fn new() -> Self {
        Self {
            shards: std::array::from_fn(|_| std::sync::Mutex::new(HashMap::new())),
        }
    }

    /// Lock the shard owning `remote`.
    pub(super) fn shard(
        &self,
        remote: &SocketAddr,
    ) -> std::sync::MutexGuard<'_, HashMap<SocketAddr, UdpSession>> {
        use std::hash::{Hash, Hasher};
        let mut h = std::collections::hash_map::DefaultHasher::new();
        remote.hash(&mut h);
        let idx = (h.finish() as usize) % UDP_SESSION_SHARDS;
        self.shards[idx].lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Lock every shard (cold paths: sweep, global inspection).
    fn lock_all(&self) -> Vec<std::sync::MutexGuard<'_, HashMap<SocketAddr, UdpSession>>> {
        self.shards
            .iter()
            .map(|m| m.lock().unwrap_or_else(|e| e.into_inner()))
            .collect()
    }

    /// Total live sessions across all shards. Cold path — called only when
    /// creating a NEW remote session, so the 8 lock acquisitions amortize
    /// over the session's lifetime.
    pub(super) fn total_len(&self) -> usize {
        self.lock_all().iter().map(|m| m.len()).sum()
    }

    /// True when the per-work-conn session cap is reached (audit F6).
    pub(super) fn at_session_cap(&self) -> bool {
        self.total_len() >= UDP_SESSION_CAP
    }
}

/// Per-work-conn cap on concurrent remote-visitor UDP sessions (audit F6).
///
/// Deliberate divergence from Go frp, which grows its session map
/// unboundedly (pkg/proto/udp/udp.go — entries are only ever removed by
/// the 30s idle reap). Each distinct remote source address costs a bound
/// local socket (an fd + an ephemeral port), a spawned reader task, a
/// writer-channel slot, and two map entries (sessions + reader mirror) —
/// and remote_addr values on the wire are attacker-influenced, so a
/// spoofing peer could otherwise pin an unbounded number of fds until the
/// reap frees them. 1024 bounds that exposure at roughly the fd ceiling
/// the kernel gives a default process while dwarfing any realistic
/// concurrent-visitor count: a UDP proxy with 1024 ACTIVE remotes has
/// saturated its local service long before the table becomes the limit.
/// Refuse-new semantics: an unknown remote arriving at the cap has its
/// datagram dropped (rate-limited warn); sessions that already exist keep
/// working until their 30s idle reap frees a slot (Go removes nothing
/// early either — a session Go would still serve, frp-rs still serves).
pub(super) const UDP_SESSION_CAP: usize = 1024;

/// Bounded wait for the writer to return the buffer of the packet it is
/// still encoding (P1). Under a reply burst the session recv loop can outrun
/// the writer by one packet; a miss is a scheduling race, not a lost
/// steady-state buffer — this window reuses it instead of allocating a fresh
/// Vec per datagram. Absent/oversized spares still fall through to the alloc
/// after at most this delay.
const UDP_SPARE_RETURN_WAIT: Duration = Duration::from_millis(1);

#[allow(clippy::too_many_arguments)]
async fn run_udp_session(
    socket: Arc<UdpSocket>,
    remote: SocketAddr,
    tx: mpsc::Sender<(SocketAddr, Vec<u8>, mpsc::Sender<Vec<u8>>)>,
    session_alive: Arc<AtomicBool>,
    udp_packet_size: usize,
    sessions: Arc<UdpSessionTable>,
    last_active: Arc<AtomicU64>,
    mut cancel_rx: tokio::sync::watch::Receiver<bool>,
    // Buffer-return channel pair: ret_tx rides along with each packet so the
    // writer can hand the content Vec back; ret_rx receives the returned
    // buffer for reuse as the next recv target.
    ret_tx: mpsc::Sender<Vec<u8>>,
    mut ret_rx: mpsc::Receiver<Vec<u8>>,
) {
    let mut buf = vec![0u8; udp_packet_size.max(1)];
    let mut idle = tokio::time::interval(Duration::from_secs(1));
    idle.tick().await;
    loop {
        tokio::select! {
            biased;
            changed = cancel_rx.changed() => {
                if changed.is_err() || *cancel_rx.borrow() { break; }
            }
            res = socket.recv_from(&mut buf) => {
                match res {
                    Ok((n, _src)) => {
                        // Refresh the shared liveness timestamp so inbound-heavy
                        // remotes (rare/no replies) are not reaped. The
                        // per-packet path is lock-free: one Relaxed atomic
                        // store into the Arc shared with the session table —
                        // no shard-lock acquire, no hash lookup.
                        last_active.store(now_epoch_ms(), Ordering::Relaxed);
                        // P1: reuse a buffer the writer returned (try_recv —
                        // no spare is not an error), but only when it is big
                        // enough for the next datagram: the writer may hand
                        // back a small compressed buffer, and recv_from into
                        // an undersized buffer would TRUNCATE the packet.
                        // A too-small spare is dropped and the steady-state
                        // buffer is copied as before.
                        let payload = match ret_rx.try_recv() {
                            Ok(mut spare) if spare.capacity() >= udp_packet_size.max(1) => {
                                spare.clear();
                                spare.extend_from_slice(&buf[..n]);
                                spare
                            }
                            // No usable spare waiting: the writer returns a
                            // buffer only after wire-encoding the packet that
                            // carried it, so under a reply burst this miss is
                            // a race with the writer — wait out a bounded
                            // scheduling quantum for its return before paying
                            // a fresh per-datagram alloc. Oversized/absent
                            // spares fall straight through.
                            _ => match tokio::time::timeout(UDP_SPARE_RETURN_WAIT, ret_rx.recv())
                                .await
                            {
                                Ok(Some(mut spare))
                                    if spare.capacity() >= udp_packet_size.max(1) =>
                                {
                                    spare.clear();
                                    spare.extend_from_slice(&buf[..n]);
                                    spare
                                }
                                _ => buf[..n].to_vec(),
                            },
                        };
                        if tx.send((remote, payload, ret_tx.clone())).await.is_err() {
                            break;
                        }
                    }
                    Err(e) => {
                        debug!(remote = %remote, error = %e, "UDP session recv error");
                        break;
                    }
                }
            }
            _ = idle.tick() => {
                // Reap only when BOTH directions have been idle: the entry's
                // last_active is refreshed by the reader on inbound remote
                // packets and by us on local replies.
                let idle_for = {
                    let map = sessions.shard(&remote);
                    map.get(&remote)
                        .map(|e| now_epoch_ms().saturating_sub(e.last_active.load(Ordering::Relaxed)))
                        .unwrap_or(UDP_SESSION_IDLE_TIMEOUT_MS)
                };
                if idle_for > UDP_SESSION_IDLE_TIMEOUT_MS {
                    debug!(remote = %remote, "UDP session idle for >30s, closing");
                    break;
                }
                if !session_alive.load(Ordering::Acquire) {
                    break;
                }
            }
        }
    }
    // Remove self from the session table (only if it still refers to us).
    let mut map = sessions.shard(&remote);
    if let Some(entry) = map.get(&remote) {
        if Arc::ptr_eq(&entry.socket, &socket) {
            map.remove(&remote);
        }
    }
}

/// Go frp v0.70.1 compat (client/proxy/udp.go + pkg/proto/udp/udp.go):
/// each distinct remote visitor gets its OWN local UDP socket bound to a
/// fresh ephemeral port on the local IP. The local service therefore sees a
/// different source address per remote and replies to the right one. A
/// single shared socket + single `last_remote` (the old model) misrouted
/// responses when multiple remotes were active concurrently — every reply
/// went to whoever sent last.
///
/// Layout:
///   work-conn read loop   -> per-remote socket (keyed by UDPPacket.remote_addr)
///   per-remote socket     -> work-conn write loop (mpsc; single writer)
///   idle sessions         -> closed after UDP_SESSION_IDLE_TIMEOUT
/// Resolve the UDP local-service target from its config `host:port` string
/// (audit F2).
///
/// Go parity: the UDP proxy's Run() resolves local_ip via net.ResolveUDPAddr
/// and rebinds with JoinHostPort (client/proxy/udp.go:62-65) — a full DNS
/// lookup when local_ip is a hostname, a plain parse when it is an IP
/// literal. frp-rs configs carry the already-joined `host:port` string:
/// the fast path is a SocketAddr parse; on failure the LAST-colon split
/// isolates a numeric port so UNBRACKETED IPv6 (`"::1:8080"`) and hostnames
/// (`"db.internal:5300"`) both resolve. IP literals never hit DNS
/// (tokio lookup_host parses them as IpAddr first — same as Go, which
/// resolves IP literals without querying DNS).
pub(super) async fn resolve_udp_local_addr(
    local_addr_str: &str,
    proxy_name: &str,
) -> Option<SocketAddr> {
    if let Ok(sa) = local_addr_str.parse::<SocketAddr>() {
        return Some(sa);
    }
    let (host, port) = match local_addr_str.rsplit_once(':') {
        Some(pair) => pair,
        None => {
            warn!(proxy_name = %proxy_name, local_addr = %local_addr_str,
                "UDP work conn '{}': invalid local_addr '{}': no ':' separator", proxy_name, local_addr_str);
            return None;
        }
    };
    if host.is_empty() || port.is_empty() || !port.bytes().all(|b| b.is_ascii_digit()) {
        warn!(proxy_name = %proxy_name, local_addr = %local_addr_str,
            "UDP work conn '{}': invalid local_addr '{}': malformed host or port", proxy_name, local_addr_str);
        return None;
    }
    // The host half of a ':'-bearing string must itself be a valid IPv6
    // literal (bare "::1" without a port splits into host ":" → rejected).
    if host.contains(':') && host.parse::<IpAddr>().is_err() {
        warn!(proxy_name = %proxy_name, local_addr = %local_addr_str,
            "UDP work conn '{}': invalid local_addr '{}': malformed IPv6 host", proxy_name, local_addr_str);
        return None;
    }
    let port: u16 = match port.parse() {
        Ok(p) => p,
        Err(_) => {
            warn!(proxy_name = %proxy_name, local_addr = %local_addr_str,
                "UDP work conn '{}': invalid local_addr '{}': port out of range", proxy_name, local_addr_str);
            return None;
        }
    };
    let host_owned = host.to_string();
    // Bind the lookup iterator to a local: it borrows host_owned, and a
    // tail-expression temporary would outlive the local (E0597).
    let mut lookup = match tokio::net::lookup_host((host_owned.as_str(), port)).await {
        Ok(addrs) => addrs,
        Err(e) => {
            warn!(proxy_name = %proxy_name, local_addr = %local_addr_str, error = %e,
                "UDP work conn '{}': local_addr '{}' failed to resolve: {}", proxy_name, local_addr_str, e);
            return None;
        }
    };
    match lookup.next() {
        Some(sa) => Some(sa),
        None => {
            warn!(proxy_name = %proxy_name, local_addr = %local_addr_str,
                "UDP work conn '{}': local_addr '{}' resolved to no addresses", proxy_name, local_addr_str);
            None
        }
    }
}

/// msg::UdpAddr for a resolved local SocketAddr — the value Go sends as
/// UDPPacket.LocalAddr: the real bound socket's address (resolved, so a
/// hostname local_ip arrives here already canonical — never the raw config
/// string, which would fail UdpAddr::from_string for hostnames).
pub(super) fn udp_addr_of(sa: &SocketAddr) -> msg::UdpAddr {
    msg::UdpAddr {
        ip: sa.ip().to_string(),
        port: sa.port(),
        zone: String::new(),
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn run_udp_work_conn(
    work: IoStream,
    proxy_name: String,
    local_addr_str: String,
    enc_key: [u8; 16],
    use_enc: bool,
    use_comp: bool,
    v2: bool,
    session_alive: Arc<AtomicBool>,
    udp_packet_size: usize,
    proxy_protocol_version: String,
    // Per-proxy SHARED bandwidth limiter (Go frp v0.71.0 `BaseProxy.limiter`
    // parity — one bucket covers both directions and all concurrent
    // connections). None when the server owns the limiting or no rate set.
    // Note: Go frp v0.70.1 has no client-side UDP limiter at all; frp-rs
    // keeps one for consistency with the TCP shared-limiter model.
    bw_limiter: Option<SharedBandwidthLimiter>,
    // Negotiated UDPPacket codec (`"binary-v1"` or empty; Go frp v0.71.0).
    // When set on a V2 work conn, UDPPacket frames use the binary codec.
    udp_packet_codec: String,
) {
    let local_addr = match resolve_udp_local_addr(&local_addr_str, &proxy_name).await {
        Some(a) => a,
        None => {
            // Already warned with the reason by the resolver.
            return;
        }
    };
    // UDP bandwidth limiting (frp-rs extension; Go frp has no UDP limiter).
    // Shared-limiter model (F1): one bucket for both directions, already
    // created at registration when mode == ""/"client"/"both" (the client
    // side owns the limiting); None in "server" mode. rate 0 → None.
    let (w_r, w_w) = match split_work_conn_halves(work) {
        Ok(pair) => pair,
        Err(e) => {
            warn!(proxy_name = %proxy_name, error = e, "UDP work conn '{}' could not be split: {}", proxy_name, e);
            return;
        }
    };
    // Provider-segment encryption (Go frp v0.70.1 three-stage model): when
    // use_enc is set, the whole work-conn byte stream is wrapped in
    // CipherReader/CipherWriter with the token-derived key — the same stream
    // cipher the server applies via bridge_encrypted. The V1/V2 frame
    // protocol then runs over the encrypted stream (CipherWriter sends its
    // random IV on the first write, so no manual IV flush is needed).
    // Per-packet payload transforms are gone: encryption is stream-level.
    let w_r: BoxedReadHalf = if use_enc {
        Box::new(CipherReader::new(w_r, enc_key)) as BoxedReadHalf
    } else {
        w_r
    };
    let mut w_w: BoxedWriteHalf = if use_enc {
        // Audit B2: OS-RNG failure (IV generation) ends this tunnel setup
        // instead of aborting the process.
        match CipherWriter::new(w_w, enc_key) {
            Ok(w) => Box::new(w) as BoxedWriteHalf,
            Err(e) => {
                warn!(error = %e, "vnet tunnel: IV generation failed");
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
    // change. The BufReader sits on top of the CipherReader (already
    // decrypted plaintext), so exact-read framing is safe.
    let mut w_r = tokio::io::BufReader::with_capacity(16 * 1024, w_r);
    let (cancel_tx, cancel_rx) = tokio::sync::watch::channel(false);

    // Remote-visitor session table. std Mutex (short critical sections,
    // never held across an await — bind() happens outside the lock).
    let sessions: Arc<UdpSessionTable> = Arc::new(UdpSessionTable::new());
    // Per-session socket -> single writer aggregation channel. Each packet
    // carries its session's buffer-return channel (P1): the writer returns
    // the content Vec after wire encode and the session reuses it as the
    // next recv buffer — the per-datagram `buf[..n].to_vec()` alloc is gone
    // in the steady state.
    let (write_tx, mut write_rx) =
        mpsc::channel::<(SocketAddr, Vec<u8>, mpsc::Sender<Vec<u8>>)>(64);

    // ---- Reader: work conn -> per-remote sockets ----
    let pn_r = proxy_name.clone();
    let session_alive_r = session_alive.clone();
    let mut reader_cancel = cancel_rx.clone();
    let reader_udp_codec = udp_packet_codec.clone();
    let reader_lim = bw_limiter.clone();
    let reader = async move {
        debug!(proxy_name = %pn_r, "UDP reader '{}' started", pn_r);
        // Ping-pong scratch for the per-packet decompress chain (per-session).
        let mut scratch_b: Vec<u8> = Vec::new();
        // Reader-owned mirror of the per-remote session sockets. The hot path
        // sends on `&Arc<UdpSocket>` from here instead of cloning the Arc out
        // of the shared `sessions` map (an atomic refcount inc/dec pair per
        // packet). Invariant: an entry is (re)inserted in the same bind path
        // that (re)inserts into `sessions`, so a shared-map hit implies a
        // mirror hit. A reaped session may leave a stale mirror entry until
        // the next periodic sweep (every ~5s); the next packet from that
        // remote misses the shared map, re-creates the session, and replaces
        // the entry.
        let mut reader_socks: HashMap<SocketAddr, Arc<UdpSocket>> = HashMap::new();
        // F6: rate-limiter for the session-cap warning (one per 5s).
        let mut last_cap_warn: Option<tokio::time::Instant> = None;
        // Reusable payload buffer for the V2 UDP read path (avoids a heap
        // alloc per UDP packet).
        let mut read_scratch: Vec<u8> = Vec::new();
        loop {
            tokio::select! {
                biased;
                changed = reader_cancel.changed() => {
                    if changed.is_err() || *reader_cancel.borrow() { break; }
                }
                result = async {
                    if v2 && !reader_udp_codec.is_empty() {
                        // Binary UDP codec negotiated (Go v0.71.0): type-19
                        // frames decode to native SocketAddr form, skipping
                        // the per-packet String alloc + reparse the message
                        // path performs (audit LOW: decode formats then
                        // re-parses).
                        read_msg_v2_udp_binary_socket(&mut w_r, &mut read_scratch).await
                    } else if v2 {
                        read_msg_v2_with_udp_codec(&mut w_r, None, &mut read_scratch)
                            .await
                            .map(UdpBinaryRead::Message)
                    } else {
                        read_msg_v1(&mut w_r).await.map(UdpBinaryRead::Message)
                    }
                } => {
                    match result {
                        Ok(rd) => {
                            // Normalize both read forms to a (remote, payload)
                            // pair; the session machinery below is form-agnostic.
                            let (remote, mut payload) = match rd {
                                // Native-address form: destination is already a
                                // SocketAddr, no text round trip.
                                UdpBinaryRead::Socket(pkt) => {
                                    (pkt.remote_addr, pkt.content)
                                }
                                UdpBinaryRead::Message(FrpMessage::UDPPacket(up)) => {
                                    let remote = match up.remote_addr {
                                        Some(ref ra) => match ra.ip.parse::<IpAddr>() {
                                            Ok(ip) => SocketAddr::new(ip, ra.port),
                                            // The `%zone` scope suffix can never
                                            // appear here: the wire format carries
                                            // the zone in the SEPARATE `Zone` field
                                            // (msg.rs UdpAddr mirrors Go
                                            // net.UDPAddr marshal), so `ra.ip` is
                                            // always zone-free and this arm is
                                            // dead code — kept as defense-in-depth
                                            // (round-13 audit note: the real
                                            // zoned-v6 loss is the `Zone` field
                                            // being dropped below — Rust std
                                            // SocketAddr cannot carry a scope id,
                                            // and Go's own V2 binary codec drops
                                            // zones in Go↔Go too, so this is
                                            // parity, not a regression).
                                            Err(_) => {
                                                warn!(ip = %ra.ip, port = ra.port,
                                                    "UDP packet: unparseable remote IP, dropping");
                                                continue;
                                            }
                                        },
                                        None => {
                                            debug!(proxy_name = %pn_r, "UDP packet without remote_addr; dropping");
                                            continue;
                                        }
                                    };
                                    (remote, up.content)
                                }
                                UdpBinaryRead::Message(FrpMessage::Ping(_))
                                | UdpBinaryRead::Message(FrpMessage::Pong(_)) => continue,
                                UdpBinaryRead::Message(other) => {
                                    debug!(proxy_name = %pn_r, v1_type = ?other.v1_type_byte(),
                                        "UDP work conn '{}': unexpected msg 0x{:02x}", pn_r, other.v1_type_byte());
                                    continue;
                                }
                            };
                            // Per-packet decompression only (compression stays
                            // per-packet for UDP; stream-level encryption was
                            // already applied by the CipherReader above).
                            if use_comp
                                && encryption::decompress_into(&payload, &mut scratch_b).is_ok()
                            {
                                std::mem::swap(&mut payload, &mut scratch_b);
                            }
                            // Session lookup / create. The std Mutex guard is
                            // never held across an await: if the session is
                            // missing we drop the lock, bind outside, then
                            // re-lock and insert (the only concurrent actor is
                            // a session task's self-removal, which the
                            // Arc::ptr_eq guard in run_udp_session protects
                            // against clobbering a live replacement).
                            // The send socket comes back by reference from the
                            // reader-owned mirror instead of an Arc clone per
                            // packet (mirror invariant: shared-map hit implies
                            // mirror hit).
                            let mut liveness: Option<Arc<AtomicU64>> = None;
                            let entry = {
                                let mut map = sessions.shard(&remote);
                                match map.get_mut(&remote) {
                                    Some(entry) => {
                                        // Clone the shared liveness timestamp
                                        // and store into it AFTER the guard
                                        // drops below: the store has no
                                        // ordering dependency on the shard
                                        // lock (both writers use Relaxed), so
                                        // the lock need not be held for it.
                                        liveness = Some(entry.last_active.clone());
                                        let mirror = reader_socks
                                            .get(&remote)
                                            .cloned()
                                            .unwrap_or_else(|| entry.socket.clone());
                                        (Some(mirror), entry.first_packet)
                                    }
                                    None => (None, false),
                                }
                            };
                            // Liveness refresh outside the shard lock.
                            if let Some(la) = liveness {
                                la.store(now_epoch_ms(), Ordering::Relaxed);
                            }
                            let (sock, first_packet) = match entry {
                                (Some(sock), first_packet) => (sock, first_packet),
                                (None, _) => {
                                    // F6: refuse NEW remotes once the
                                    // per-work-conn session cap is reached.
                                    // Unknown remotes drop their datagram
                                    // (warn throttled to one per 5s); known
                                    // remotes never reach this arm. A reaped
                                    // session's slot is freed by the next
                                    // create. See UDP_SESSION_CAP.
                                    if sessions.at_session_cap() {
                                        let now = tokio::time::Instant::now();
                                        if last_cap_warn
                                            .is_none_or(|t| now.duration_since(t) > Duration::from_secs(5))
                                        {
                                            warn!(proxy_name = %pn_r, cap = %UDP_SESSION_CAP, remote = %remote,
                                                "UDP '{}': session cap {} reached; dropping datagram from new remote {}",
                                                pn_r, UDP_SESSION_CAP, remote);
                                            last_cap_warn = Some(now);
                                        }
                                        continue;
                                    }
                                    let bind = SocketAddr::new(local_addr.ip(), 0);
                                    let sock = match UdpSocket::bind(bind).await {
                                        Ok(s) => s,
                                        Err(e) => {
                                            warn!(proxy_name = %pn_r, remote = %remote, error = %e,
                                                "UDP: failed to bind per-remote socket");
                                            continue;
                                        }
                                    };
                                    // Connect to the local service so replies
                                    // can only arrive from it (source
                                    // filtering — a local process can no
                                    // longer inject datagrams tagged as this
                                    // remote). Requests still go out via
                                    // send_to(local_addr), the connect addr.
                                    if let Err(e) = sock.connect(local_addr).await {
                                        warn!(proxy_name = %pn_r, remote = %remote, error = %e,
                                            "UDP: failed to connect per-remote socket to local service");
                                        continue;
                                    }
                                    let sock = Arc::new(sock);
                                    let mut map = sessions.shard(&remote);
                                    match map.get(&remote) {
                                        // Defensive: unreachable today (the
                                        // reader is the sole sessions inserter
                                        // and held the lock across the bind
                                        // gap), but if a future concurrent
                                        // inserter is added, reuse its socket
                                        // rather than silently re-create.
                                        Some(entry) => {
                                            // Defensive: unreachable today (the
                                            // reader is the sole sessions
                                            // inserter and held the lock across
                                            // the bind gap), but degrade
                                            // gracefully instead of panicking
                                            // on the UDP hot path if a future
                                            // concurrent inserter appears — the
                                            // session itself carries the socket.
                                            let mirror = reader_socks
                                                .get(&remote)
                                                .cloned()
                                                .unwrap_or_else(|| entry.socket.clone());
                                            (mirror, entry.first_packet)
                                        }
                                        None => {
                                            let stx = write_tx.clone();
                                            let s_alive = session_alive_r.clone();
                                            let sessions_for_task = sessions.clone();
                                            // Shared liveness timestamp: the
                                            // reader task refreshes it per
                                            // packet without taking the shard
                                            // lock (one Relaxed store).
                                            let last_active =
                                                Arc::new(AtomicU64::new(now_epoch_ms()));
                                            // P1: per-session buffer-return
                                            // channel (cap 8 — the writer's
                                            // try_send drops a full channel;
                                            // the spare is an optimization).
                                            let (ret_tx, ret_rx) =
                                                mpsc::channel::<Vec<u8>>(8);
                                            tokio::spawn(run_udp_session(
                                                sock.clone(),
                                                remote,
                                                stx,
                                                s_alive,
                                                udp_packet_size,
                                                sessions_for_task,
                                                last_active.clone(),
                                                reader_cancel.clone(),
                                                ret_tx,
                                                ret_rx,
                                            ));
                                            map.insert(
                                                remote,
                                                UdpSession {
                                                    socket: sock.clone(),
                                                    last_active,
                                                    first_packet: true,
                                                },
                                            );
                                            reader_socks.insert(remote, sock.clone());
                                            (sock, true)
                                        }
                                    }
                                }
                            };
                            // PROXY header on the first packet of each remote
                            // session (Go: first packet of each remote conn).
                            // Go parity (pkg/proto/udp/udp.go Forwarder +
                            // go-proxyproto v0.15.0): the ONLY gate is the
                            // remote address being present
                            // (`!ok && proxyProtocolVersion != "" &&
                            // udpMsg.RemoteAddr != nil`) — there is NO
                            // source-port-0 skip on the UDP path (the TCP
                            // `m.SrcAddr != "" && m.SrcPort != 0` gate of
                            // client/proxy/proxy.go does not apply here).
                            // `remote` is always a parsed SocketAddr, so the
                            // header is emitted for every new remote session
                            // when a version is configured — a port-0 source
                            // (legal on the wire) rides in the header block
                            // exactly as Go would write it. The transport kind
                            // threads into the builder so UDP sessions are
                            // never mislabeled as TCP: v1 collapses to the
                            // literal `PROXY UNKNOWN\r\n` (the v1 grammar has
                            // no UDP address line) and v2 emits the
                            // UDP-DATAGRAM frame (transport 0x12/0x22).
                            let mut final_payload = payload;
                            if first_packet && !proxy_protocol_version.is_empty() {
                                if let Ok(header) =
                                    frp_core::proxy_protocol::build_proxy_protocol_header(
                                        &remote.ip().to_string(),
                                        // Local service address as an IP string.
                                        // The old `split(':').next()` on the raw
                                        // config string mis-split hostnames and
                                        // IPv6 (F2): the resolved socket addr is
                                        // always canonical.
                                        &local_addr.ip().to_string(),
                                        remote.port(),
                                        local_addr.port(),
                                        &proxy_protocol_version,
                                        frp_core::proxy_protocol::ProxyTransport::Udp,
                                    )
                                {
                                    let mut buf =
                                        Vec::with_capacity(header.len() + final_payload.len());
                                    buf.extend_from_slice(&header);
                                    buf.extend_from_slice(&final_payload);
                                    final_payload = buf;
                                }
                            }
                            // Clear `first_packet` only when THIS datagram was
                            // the session's first (create arm). Mirror-arm
                            // hits carry `first_packet == false` — the flag is
                            // true only between the create arm's insert and
                            // this clear, with no await in between, and the
                            // session reader task never writes it — so gating
                            // the clear on the observed flag turns the old
                            // unconditional second shard-lock + hash lookup
                            // per packet into a no-op on the steady-state
                            // path.
                            if first_packet {
                                if let Some(entry) = sessions.shard(&remote).get_mut(&remote) {
                                    entry.first_packet = false;
                                }
                            }
                            debug!(proxy_name = %pn_r, byte_count = final_payload.len(),
                                "UDP reader '{}': forwarding {} bytes to local", pn_r, final_payload.len());
                            // The session socket is connect()ed to local_addr,
                            // so use send() — send_to() on a connected socket
                            // returns EISCONN on macOS/BSD after the first
                            // packet (platform divergence; Linux allows it).
                            // A failure here (e.g. ECONNREFUSED while the
                            // local service restarts) drops the packet but
                            // must NOT tear down the whole work conn —
                            // Go frp logs and skips (per-remote model means
                            // other remotes and future packets still work).
                            if let Some(lim) = reader_lim.as_ref() {
                                frp_core::bandwidth::BandwidthLimiter::consume_shared(
                                    lim,
                                    final_payload.len(),
                                )
                                .await;
                            }
                            if let Err(e) = sock.send(&final_payload).await {
                                debug!(proxy_name = %pn_r, error = %e, local = %local_addr,
                                    "UDP '{}' send to local failed, dropping packet: {}", pn_r, e);
                            }
                        }
                        Err(e) => {
                            debug!(proxy_name = %pn_r, error = %e,
                                "UDP work conn '{}' read closed: {}", pn_r, e);
                            break;
                        }
                    }
                }
                _ = tokio::time::sleep(Duration::from_secs(5)) => {
                    if !session_alive_r.load(Ordering::Acquire) {
                        debug!(proxy_name = %pn_r, "UDP reader '{}': session dead, stopping", pn_r);
                        break;
                    }
                    // Sweep stale mirror entries for sessions reaped by the
                    // idle timeout. Without this, the per-remote connected UDP
                    // sockets accumulate FDs and ephemeral ports for the work
                    // conn's lifetime — bounded only by distinct remotes seen.
                    {
                        let maps = sessions.lock_all();
                        reader_socks.retain(|_k, v| {
                            // retain by value: keep only entries whose Arc
                            // still matches a live session entry in ANY shard.
                            maps.iter().any(|m| m.values().any(|e| Arc::ptr_eq(&e.socket, v)))
                        });
                    }
                }
            }
        }
    };

    // ---- Writer: per-session channel -> work conn (single writer) ----
    let bridge_name = proxy_name.clone();
    let pn_w = proxy_name;
    let session_alive_w = session_alive;
    let mut writer_cancel = cancel_rx;
    let writer_lim = bw_limiter;
    let writer = async move {
        debug!(proxy_name = %pn_w, "UDP writer '{}' started", pn_w);
        // Each packet brings its own Vec by move (round-17 audit B); the slot
        // is (re)assigned before every use, so no initializer is needed.
        let mut payload: Vec<u8>;
        // local_addr is loop-invariant (already resolved to a SocketAddr at
        // startup); pre-build the UdpAddr once and move it in/out per packet
        // instead of re-formatting every packet (audit D1-5). The value is
        // built from the RESOLVED socket addr (F2) — the raw config string
        // would fail UdpAddr::from_string for hostnames and unbracketed
        // IPv6, and Go sends the real bound address (resolved, canonical).
        let mut local_udp_addr: Option<msg::UdpAddr> = Some(udp_addr_of(&local_addr));
        // Ping-pong scratch for the per-packet compress chain (per-session).
        let mut scratch_c: Vec<u8> = Vec::new();
        // Reused binary-codec wire buffer: type ID + encoded packet. The V1
        // JSON arm below shares it (the two arms are mutually exclusive per
        // packet, and both writers clear it first), so the per-packet
        // `serde_json` Vec allocation is gone on the V1 path too (perf audit
        // TOP 2; `write_v1_frame_scratch` is byte-identical to
        // `write_v1_frame`).
        let mut wire_scratch: Vec<u8> = Vec::new();
        // Per-remote IP-string cache. UDPPacket.remote_addr.ip is a String
        // (Go msg.UDPPacket.RemoteAddr parity), so the IpAddr would be
        // re-formatted per packet. Cache the formatted string per remote:
        // repeated packets to the same remote (the dominant UDP pattern)
        // skip the formatting work (IPv6 to_string scans for zero runs).
        // Bounded: distinct remotes mirror the reader-side session map
        // (idle-swept), but a hostile flood of distinct source addrs must
        // not grow this unboundedly — clear on overflow (cheap fail-safe;
        // the cache is a perf aid, not state). V1 JSON frames and V2
        // JSON-fallback frames only: the V2 binary-codec path encodes the
        // remote straight from the SocketAddr (audit B1), no String needed.
        let mut ip_cache: HashMap<SocketAddr, String> = HashMap::new();
        // Application-level keepalive Ping, FIXED at 30s (audit F1): Go
        // frp's UDP heartbeatFn hardcodes 30s with no config knob, and the
        // server enforces a 60s per-read deadline on the work conn. This
        // interval deliberately never reads any config (the old wiring to
        // dial_server_keepalive — default 7200s — let idle UDP conns hit the
        // server's 60s read deadline and die); dial_server_keepalive remains
        // the socket-level TCP keepalive for the dial phase only.
        let mut keepalive = tokio::time::interval(UDP_WORK_CONN_PING_INTERVAL);
        keepalive.tick().await;
        loop {
            tokio::select! {
                biased;
                changed = writer_cancel.changed() => {
                    if changed.is_err() || *writer_cancel.borrow() { break; }
                }
                Some((remote, data, ret_tx)) = write_rx.recv() => {
                    // Round-17 audit B: take the received Vec by move — it
                    // crossed the async channel already owned, so the old
                    // clear + extend_from_slice was a second full datagram
                    // copy per packet. Compression (when enabled) compresses
                    // out of the moved-in payload and swaps the scratch in,
                    // preserving the reused-buffer path exactly.
                    payload = data;
                    if use_comp && encryption::compress_into(&payload, &mut scratch_c).is_ok()
                    {
                        std::mem::swap(&mut payload, &mut scratch_c);
                    }
                    // Stream-level encryption is applied by the CipherWriter
                    // that wraps w_w (Go frp three-stage model); the frame
                    // below is written over the encrypted stream.
                    // Each reply is tagged with its own remote — no shared
                    // last_remote, so concurrent remotes never cross wires.
                    let pkt_len = payload.len();
                    // Audit B1: on the V2 binary-codec path the remote is a
                    // parsed SocketAddr here while the codec wants family /
                    // port / zone bytes — the msg::UdpAddr String form exists
                    // only for the V1 JSON codec. Direct-encode from the
                    // SocketAddr via the frp-core shared helper (byte-identical
                    // to the String round trip: same To4() mapped-v4
                    // normalization, same empty zone) instead of building the
                    // message struct — the per-packet ip_cache clone and the
                    // re-parse inside the String round trip are gone on this path.
                    let binary_codec =
                        v2 && udp_packet_codec == frp_core::udp_binary::UDP_PACKET_CODEC_BINARY;
                    if let Some(lim) = writer_lim.as_ref() {
                        // Limiter counts the (compressed) payload the tunnel
                        // actually carries.
                        frp_core::bandwidth::BandwidthLimiter::consume_shared(lim, pkt_len).await;
                    }
                    let result = if binary_codec {
                        // Mirrors the binary arm of
                        // write_msg_v2_with_udp_codec: type ID + codec body
                        // share one scratch buffer, then one frame write and
                        // a flush (CipherWriter must flush to emit its IV).
                        wire_scratch.clear();
                        wire_scratch
                            .extend_from_slice(&msg::V2_TYPE_UDP_PACKET_BINARY.to_be_bytes());
                        let result =
                            match frp_core::udp_binary::encode_udp_packet_binary_socket_addr_local(
                                &payload,
                                // Audit item 6: `local_addr` is the resolved
                                // loop-invariant SocketAddr; encode it
                                // straight from its octets — the per-datagram
                                // ip String re-parse of the UdpAddr form is
                                // gone (that form stays only for the JSON
                                // arm below). Byte-identical output.
                                Some(&local_addr),
                                &remote,
                                &mut wire_scratch,
                            ) {
                                Err(e) => Err(frp_core::Error::Protocol(format!(
                                    "encode binary UDP packet: {e}"
                                )
                                .into())),
                                Ok(()) => {
                                    match write_v2_frame_raw(
                                        &mut w_w,
                                        V2_FRAME_TYPE_MESSAGE,
                                        0,
                                        &wire_scratch,
                                    )
                                    .await
                                    {
                                        Err(e) => Err(e),
                                        Ok(()) => w_w.flush().await.map_err(|e| {
                                            frp_core::Error::Protocol(format!(
                                                "flush after binary UDP packet: {e}"
                                            )
                                            .into())
                                        }),
                                    }
                                }
                            };
                        // Hand the content buffer back to the session (P1) —
                        // see the JSON arm's comment below. local_udp_addr is
                        // never taken on this path, so it stays invariant.
                        let _ = ret_tx.try_send(payload);
                        result
                    } else {
                        // V1 JSON frame, or V2 without the binary codec
                        // negotiated (JSON fallback): the message needs the
                        // msg::UdpAddr String form of the remote.
                        let pkt = FrpMessage::UDPPacket(msg::UDPPacket {
                            content: std::mem::take(&mut payload),
                            local_addr: local_udp_addr.take().or_else(|| {
                                // Unreachable after the first packet (returned
                                // below); defensive fallback.
                                Some(udp_addr_of(&local_addr))
                            }),
                            remote_addr: Some(msg::UdpAddr {
                                ip: match ip_cache.get(&remote) {
                                    Some(s) => s.clone(),
                                    None => {
                                        let s = remote.ip().to_string();
                                        if ip_cache.len() >= 256 {
                                            ip_cache.clear();
                                        }
                                        ip_cache.insert(remote, s.clone());
                                        s
                                    }
                                },
                                port: remote.port(),
                                zone: String::new(),
                            }),
                        });
                        let result = if v2 {
                            // The codec cannot be binary-v1 here (that arm is
                            // above); any other negotiated codec name — or
                            // none — falls through to the JSON writer.
                            let codec_opt = if udp_packet_codec.is_empty() {
                                None
                            } else {
                                Some(udp_packet_codec.as_str())
                            };
                            write_msg_v2_with_udp_codec(
                                &mut w_w,
                                &pkt,
                                codec_opt,
                                false,
                                &mut wire_scratch,
                            )
                            .await
                        } else {
                            // V1 JSON: serialize into the loop's shared
                            // scratch (`wire_scratch`) instead of letting the
                            // writer allocate a fresh Vec per datagram.
                            write_v1_frame_scratch(&mut w_w, &pkt, &mut wire_scratch).await
                        };
                        // Return the invariant UdpAddr for the next packet and
                        // hand the content buffer back to the session (P1) —
                        // it becomes the session's next recv target. try_send:
                        // a closed/full return channel just drops the buffer
                        // (the spare is an optimization, and the session
                        // already re-allocated if no spare arrived). Note the
                        // returned Vec may be the writer's compress scratch
                        // after a swap — either way it is a live allocation
                        // the session can recv into, so no allocation is
                        // lost.
                        if let FrpMessage::UDPPacket(p) = pkt {
                            local_udp_addr = p.local_addr;
                            let _ = ret_tx.try_send(p.content);
                        }
                        result
                    };
                    if let Err(e) = result {
                        debug!(proxy_name = %pn_w, error = %e,
                            "UDP '{}' send to work conn failed: {}", pn_w, e);
                        break;
                    }
                }
                _ = tokio::time::sleep(Duration::from_secs(5)) => {
                    if !session_alive_w.load(Ordering::Acquire) {
                        debug!(proxy_name = %pn_w, "UDP writer '{}': session dead, stopping", pn_w);
                        break;
                    }
                }
                _ = keepalive.tick() => {
                    let ping = FrpMessage::Ping(msg::Ping { privilege_key: None, timestamp: None });
                    let result = if v2 {
                        write_msg_v2(&mut w_w, &ping).await
                    } else {
                        write_msg_v1(&mut w_w, &ping).await
                    };
                    if let Err(e) = result {
                        debug!(proxy_name = %pn_w, error = %e,
                            "UDP work conn '{}' keepalive ping failed: {}", pn_w, e);
                        break;
                    }
                }
            }
        }
    };

    tokio::pin!(reader, writer);
    tokio::select! {
        _ = &mut reader => {
            debug!(proxy_name = %bridge_name, "UDP reader exited; draining then cancelling writer");
            let _ = cancel_tx.send(true);
            let _ = tokio::time::timeout(Duration::from_millis(100), &mut writer).await;
        }
        _ = &mut writer => {
            debug!(proxy_name = %bridge_name, "UDP writer exited; draining then cancelling reader");
            let _ = cancel_tx.send(true);
            let _ = tokio::time::timeout(Duration::from_millis(100), &mut reader).await;
        }
    }
}
