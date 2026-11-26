//! SOCKS5 UDP ASSOCIATE relay (RFC 1928 §7, frp-rs extension).
//!
//! The `socks5` plugin's TCP control connection is tunneled through frp; UDP
//! datagrams cannot use that TCP stream. This module implements the relay half
//! of the RFC: a UDP socket that speaks the SOCKS5 UDP request/reply framing
//! (`RSV RSV FRAG ATYP DST.ADDR DST.PORT DATA`) and forwards the payload to the
//! target. The address the client is told to use (`BND.ADDR`/`BND.PORT`) is
//! configured separately, because a relay bound on frpc's loopback is reachable
//! through a companion `type = "udp"` frp proxy (which dials the loopback
//! socket) but is not reachable by a remote SOCKS5 client directly.
//!
//! Go frp's `socks5` plugin is CONNECT-only (`armon/go-socks5`); this whole
//! module is a frp-rs extension.

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::net::UdpSocket;
use tracing::{debug, info, warn};

use frp_core::config::PluginConfig;

const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;

/// How long a client address stays trusted for UDP requests. The RFC ties an
/// association to its TCP control connection, but the relay socket is shared
/// and sees only the datagram source, so this is a coalescing window, not an
/// authentication lifetime.
const CLIENT_TTL: Duration = Duration::from_secs(600);
const CLIENT_TTL_NS: u64 = CLIENT_TTL.as_nanos() as u64;
/// Minimum interval between atomic timestamp writes for an active client (1 s
/// granularity for a 600 s TTL avoids cross-core cache-line bouncing on hot
/// bidirectional UDP flows while nanosecond storage preserves strict ordering
/// across rapid client insertions).
const LAST_TOUCH_GRANULARITY_NS: u64 = 1_000_000_000;
/// Maximum SOCKS5 UDP header size: `RSV(2) + FRAG(1) + ATYP(1) + IPv6(16) + PORT(2)`.
const MAX_UDP_HDR: usize = 22;
/// Opportunistic non-blocking drain cap per reactor wakeup (adds zero wait for
/// isolated packets; amortizes `select!` overhead across bursts).
const UDP_BATCH_MAX: usize = 32;
/// DNS answer cache lifetime.
const DNS_TTL: Duration = Duration::from_secs(60);
/// Negative DNS cache lifetime (a name that failed resolution must not be
/// retried per datagram).
const DNS_NEGATIVE_TTL: Duration = Duration::from_secs(10);
/// Bound on concurrent DNS lookups. Lookups run in spawned tasks so a slow
/// resolver cannot stall the relay's receive loop for every client.
const MAX_PENDING_DNS: usize = 32;
const DNS_LOOKUP_TIMEOUT: Duration = Duration::from_secs(5);

/// Bounded so the relay cannot exhaust a default 1024-fd process limit:
/// 128 clients × at most two family sockets = 256 fds.
const MAX_CLIENTS: usize = 128;
/// Per-client route cap (target addresses). At the cap the oldest target is
/// evicted; a reply from that evicted target is then dropped, while every other
/// live flow keeps working.
const MAX_ROUTES_PER_CLIENT: usize = 256;
const MAX_DNS_ENTRIES: usize = 256;

/// Largest datagram the relay will read. RFC 1928 has no explicit cap; the IP
/// payload limit is 65507 bytes for IPv4 and 65527 for IPv6.
/// Deliberately below the 65 507-byte IPv4 UDP maximum: 16 KiB covers any
/// practical MTU-sized datagram while keeping 128 clients × 2 families ×
/// buffer ≈ 4 MiB, not 128 MiB.
const MAX_DATAGRAM: usize = 16 * 1024;

/// Concurrent UDP associations per plugin. Each guard keeps the relay gate open
/// for the plugin, so this is the blast radius of a leaked (silently dead)
/// control connection.
const MAX_ASSOCIATIONS: usize = 64;

/// Handle passed to the TCP accept handler. The relay socket is bound lazily on
/// the first `UDP ASSOCIATE`, so reloading a proxy with a fixed
/// `udp_bind_addr` does not collide with the previous plugin instance (which is
/// still running until the reload commits).
#[derive(Clone)]
pub(crate) struct UdpAssociateHandle {
    inner: Arc<UdpAssociateInner>,
}

struct UdpAssociateInner {
    bind_addr: String,
    advertise_raw: String,
    cancel: tokio_util::sync::CancellationToken,
    active: Arc<AtomicUsize>,
    /// `Some` once the relay has been bound and its task started.
    bound: tokio::sync::Mutex<Option<BoundRelay>>,
}

struct BoundRelay {
    /// Resolved address written into the UDP ASSOCIATE reply.
    advertise: SocketAddr,
}

impl UdpAssociateHandle {
    /// Register one live UDP association, binding the relay on first use.
    /// Dropping the guard (when the TCP control connection ends, or the handler
    /// task is aborted) unregisters it. The relay drops datagrams while the
    /// count is zero: without a successful (and, when configured,
    /// authenticated) TCP handshake it does not relay.
    ///
    /// Returns the advertised relay address for the `UDP ASSOCIATE` reply.
    pub(crate) async fn enter(&self) -> Result<(AssociationGuard, SocketAddr), String> {
        if self.inner.cancel.is_cancelled() {
            return Err("socks5 udp relay: plugin is shutting down".into());
        }
        let advertise = {
            let mut bound = self.inner.bound.lock().await;
            match bound.as_ref() {
                Some(relay) => relay.advertise,
                None => {
                    let socket = UdpSocket::bind(&self.inner.bind_addr).await.map_err(|e| {
                        format!("socks5 udp relay: bind {}: {e}", self.inner.bind_addr)
                    })?;
                    let local = socket
                        .local_addr()
                        .map_err(|e| format!("socks5 udp relay: local_addr: {e}"))?;
                    let advertise = tokio::time::timeout(
                        Duration::from_secs(5),
                        resolve_advertise_addr(&self.inner.advertise_raw, local),
                    )
                    .await
                    .map_err(|_| "socks5 udp relay: advertise resolution timed out".to_string())?
                    .map_err(|e| e.to_string())?;
                    if self.inner.cancel.is_cancelled() {
                        return Err("socks5 udp relay: plugin is shutting down".into());
                    }
                    info!(
                        bind = %local,
                        advertise = %advertise,
                        "socks5 UDP relay listening (UDP ASSOCIATE enabled)"
                    );
                    let socket = Arc::new(socket);
                    tokio::spawn(run_relay(
                        socket,
                        self.inner.active.clone(),
                        self.inner.cancel.clone(),
                    ));
                    *bound = Some(BoundRelay { advertise });
                    advertise
                }
            }
        };
        let previous = self.inner.active.fetch_add(1, Ordering::AcqRel);
        if previous >= MAX_ASSOCIATIONS {
            self.inner.active.fetch_sub(1, Ordering::AcqRel);
            return Err(format!(
                "socks5 udp relay: too many concurrent associations (max {MAX_ASSOCIATIONS})"
            ));
        }
        Ok((
            AssociationGuard {
                active: self.inner.active.clone(),
            },
            advertise,
        ))
    }
}

pub(crate) struct AssociationGuard {
    active: Arc<AtomicUsize>,
}

impl Drop for AssociationGuard {
    fn drop(&mut self) {
        // fetch_sub is safe against a racing enter(): `enter` only ever adds,
        // and each guard is created after exactly one successful add. The
        // AcqRel/Acquire pair gives the relay task a happens-before edge from
        // the handler's increment, so the comment in socks5.rs is literally
        // true under the memory model, not just wall-clock.
        self.active.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Configuration for the optionally-enabled relay.
pub(crate) struct UdpRelay;

impl UdpRelay {
    /// Validate the plugin's UDP config and build the shared handle. Returns
    /// `Ok(None)` when `udp_enable` is false, preserving the CONNECT-only
    /// behaviour (and the `REP_CMD_NOT_SUPPORTED` reply) for existing configs.
    pub(crate) async fn from_config(
        cfg: &PluginConfig,
        cancel: tokio_util::sync::CancellationToken,
    ) -> Result<Option<UdpAssociateHandle>, frp_core::Error> {
        if !cfg.udp_enable {
            return Ok(None);
        }
        let bind_addr = if cfg.udp_bind_addr.trim().is_empty() {
            "127.0.0.1:0".to_string()
        } else {
            cfg.udp_bind_addr.trim().to_string()
        };
        // Validate without binding: a DNS lookup catches a bad host/port at
        // startup instead of at the first UDP ASSOCIATE. The actual bind is
        // deferred (see `enter`).
        {
            let mut addrs = tokio::net::lookup_host(&bind_addr).await.map_err(|e| {
                frp_core::Error::Config(
                    format!("socks5 udp_bind_addr '{bind_addr}' is invalid: {e}").into(),
                )
            })?;
            if addrs.next().is_none() {
                return Err(frp_core::Error::Config(
                    format!("socks5 udp_bind_addr '{bind_addr}' resolved to no addresses").into(),
                ));
            }
        }
        if !cfg.udp_advertise_addr.trim().is_empty() {
            let raw = cfg.udp_advertise_addr.trim();
            let candidate = if raw.parse::<IpAddr>().is_ok() {
                format!("{raw}:0")
            } else {
                raw.to_string()
            };
            {
                let mut addrs = tokio::net::lookup_host(&candidate).await.map_err(|e| {
                    frp_core::Error::Config(
                        format!("socks5 udp_advertise_addr '{raw}' is invalid: {e}").into(),
                    )
                })?;
                if addrs.next().is_none() {
                    return Err(frp_core::Error::Config(
                        format!("socks5 udp_advertise_addr '{raw}' resolved to no addresses")
                            .into(),
                    ));
                }
            }
        }
        Ok(Some(UdpAssociateHandle {
            inner: Arc::new(UdpAssociateInner {
                bind_addr,
                advertise_raw: cfg.udp_advertise_addr.trim().to_string(),
                cancel,
                active: Arc::new(AtomicUsize::new(0)),
                bound: tokio::sync::Mutex::new(None),
            }),
        }))
    }
}

async fn run_relay(
    socket: Arc<UdpSocket>,
    active: Arc<AtomicUsize>,
    cancel: tokio_util::sync::CancellationToken,
) {
    let mut state = RelayState::new(cancel.clone());
    let mut buf = vec![0u8; MAX_DATAGRAM];
    let mut last_recv_warn: Option<Instant> = None;
    // Idle clients are otherwise only reaped on the next request; an
    // association whose client disappears would pin a task + socket + 16 KiB
    // buffer forever on an otherwise quiet relay.
    let mut sweep = tokio::time::interval(Duration::from_secs(60));
    sweep.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => break,
            _ = sweep.tick() => state.sweep(Instant::now()),
            result = socket.recv_from(&mut buf) => match result {
                Ok((n, from)) => {
                    let now = Instant::now();
                    let now_ns = state.elapsed_ns(now);
                    if n > 0 && active.load(Ordering::Acquire) > 0 {
                        state.handle_at(&socket, &buf[..n], from, now, now_ns).await;
                    }
                    // Opportunistically drain already-queued datagrams from the
                    // kernel receive buffer to amortize `select!` wakeups across
                    // bursts; isolated packets hit `WouldBlock` immediately.
                    for _ in 1..UDP_BATCH_MAX {
                        match socket.try_recv_from(&mut buf) {
                            Ok((m, src)) => {
                                if m > 0 && active.load(Ordering::Acquire) > 0 {
                                    state.handle_at(&socket, &buf[..m], src, now, now_ns).await;
                                }
                            }
                            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                            Err(_) => break,
                        }
                    }
                }
                Err(e) => {
                    // A persistent recv error must not spin. Transient errors
                    // (e.g. an ICMP-induced error on some platforms) are
                    // retried after a short pause; the warn is throttled.
                    if last_recv_warn
                        .map(|t| t.elapsed() >= Duration::from_secs(1))
                        .unwrap_or(true)
                    {
                        warn!(error = %e, "socks5 UDP relay recv error: {e}");
                        last_recv_warn = Some(Instant::now());
                    }
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            },
        }
    }
}

/// Resolve the address returned to clients. An empty value means "use the bound
/// socket's own address"; an unspecified bind address (0.0.0.0/::) is rewritten
/// to loopback so a local client gets a usable value. A configured host:port is
/// resolved (the port must be present; a bare IP uses the bound port).
async fn resolve_advertise_addr(
    raw: &str,
    local: SocketAddr,
) -> Result<SocketAddr, frp_core::Error> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Ok(mask_unspecified(local));
    }
    // `lookup_host` needs a port. Accept a bare IP by pairing it with the
    // relay's bound port; otherwise require host:port.
    let candidate = if raw.parse::<IpAddr>().is_ok() {
        format!("{raw}:{}", local.port())
    } else {
        raw.to_string()
    };
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host(&candidate)
        .await
        .map_err(|e| {
            frp_core::Error::Config(
                format!("socks5 udp_advertise_addr '{raw}' is not a valid address: {e}").into(),
            )
        })?
        .collect();
    // Prefer the bind socket's address family: a client that can reach the
    // relay must use the same family, and `localhost` often resolves to ::1
    // first on a dual-stack host.
    let mut addr = addrs
        .iter()
        .find(|a| a.is_ipv4() == local.is_ipv4())
        .or_else(|| addrs.first())
        .copied()
        .ok_or_else(|| {
            frp_core::Error::Config(
                format!("socks5 udp_advertise_addr '{raw}' resolved to no addresses").into(),
            )
        })?;
    if addr.port() == 0 {
        addr.set_port(local.port());
    }
    Ok(mask_unspecified(addr))
}

fn mask_unspecified(addr: SocketAddr) -> SocketAddr {
    match addr.ip() {
        IpAddr::V4(ip) if ip.is_unspecified() => {
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), addr.port())
        }
        IpAddr::V6(ip) if ip.is_unspecified() => {
            SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), addr.port())
        }
        _ => addr,
    }
}

// ---------------------------------------------------------------
// SOCKS5 UDP framing
// ---------------------------------------------------------------

/// Parsed SOCKS5 UDP request. The reply header is rebuilt from the concrete
/// target address (RFC 1928 §7: the reply ATYP/ADDR is the host that sent it),
/// so a domain request yields an IP reply header.
struct UdpRequest<'a> {
    payload: &'a [u8],
    target: UdpTarget<'a>,
}

enum UdpTarget<'a> {
    Addr(SocketAddr),
    Domain(&'a str, u16),
}

impl<'a> UdpRequest<'a> {
    fn parse(data: &'a [u8]) -> Option<Self> {
        if data.len() < 4 {
            return None;
        }
        // RSV(2) must be zero; FRAG other than 0 means a fragmented datagram,
        // which this relay does not implement (RFC 1928 allows dropping it).
        if data[0] != 0 || data[1] != 0 || data[2] != 0 {
            return None;
        }
        let (target, header_len) = match data[3] {
            ATYP_IPV4 => {
                if data.len() < 10 {
                    return None;
                }
                let ip = Ipv4Addr::new(data[4], data[5], data[6], data[7]);
                let port = u16::from_be_bytes([data[8], data[9]]);
                (UdpTarget::Addr(SocketAddr::new(IpAddr::V4(ip), port)), 10)
            }
            ATYP_IPV6 => {
                if data.len() < 22 {
                    return None;
                }
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&data[4..20]);
                let ip = Ipv6Addr::from(octets);
                let port = u16::from_be_bytes([data[20], data[21]]);
                (UdpTarget::Addr(SocketAddr::new(IpAddr::V6(ip), port)), 22)
            }
            ATYP_DOMAIN => {
                if data.len() < 5 {
                    return None;
                }
                let dlen = data[4] as usize;
                if dlen == 0 || data.len() < 5 + dlen + 2 {
                    return None;
                }
                let host = std::str::from_utf8(&data[5..5 + dlen]).ok()?;
                let port = u16::from_be_bytes([data[5 + dlen], data[5 + dlen + 1]]);
                (UdpTarget::Domain(host, port), 5 + dlen + 2)
            }
            _ => return None,
        };
        Some(UdpRequest {
            payload: &data[header_len..],
            target,
        })
    }
}

// ---------------------------------------------------------------
// Relay state / forwarding
// ---------------------------------------------------------------

/// Non-blocking UDP send fast path; falls back to async `send_to` only if the
/// kernel send buffer returns `WouldBlock`.
#[inline]
async fn try_send_to_udp(
    socket: &UdpSocket,
    buf: &[u8],
    target: SocketAddr,
) -> std::io::Result<usize> {
    loop {
        match socket.try_send_to(buf, target) {
            Ok(n) => return Ok(n),
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                return socket.send_to(buf, target).await;
            }
            Err(e) => return Err(e),
        }
    }
}

#[inline]
fn elapsed_ns_since(epoch: Instant, now: Instant) -> u64 {
    u64::try_from(now.saturating_duration_since(epoch).as_nanos()).unwrap_or(u64::MAX)
}

#[inline]
fn touch_last_ns(last_ns: &AtomicU64, now_ns: u64) {
    let prev = last_ns.load(Ordering::Relaxed);
    if now_ns.saturating_sub(prev) >= LAST_TOUCH_GRANULARITY_NS {
        last_ns.fetch_max(now_ns, Ordering::Relaxed);
    }
}

/// Prepend `RSV(2) + FRAG(1) + ATYP + SRV.ADDR + SRV.PORT` directly before
/// `buf[MAX_UDP_HDR..]` (in-place, zero heap allocation, zero payload copy).
/// Returns the start offset in `buf` (`12` for IPv4, `0` for IPv6).
#[inline]
fn encode_reply_header(buf: &mut [u8], target: SocketAddr) -> usize {
    match target.ip() {
        IpAddr::V4(ip) => {
            let start = MAX_UDP_HDR - 10;
            buf[start] = 0;
            buf[start + 1] = 0;
            buf[start + 2] = 0;
            buf[start + 3] = ATYP_IPV4;
            buf[start + 4..start + 8].copy_from_slice(&ip.octets());
            buf[start + 8..start + 10].copy_from_slice(&target.port().to_be_bytes());
            start
        }
        IpAddr::V6(ip) => {
            buf[0] = 0;
            buf[1] = 0;
            buf[2] = 0;
            buf[3] = ATYP_IPV6;
            buf[4..20].copy_from_slice(&ip.octets());
            buf[20..22].copy_from_slice(&target.port().to_be_bytes());
            0
        }
    }
}

/// Per-client relay: dedicated outbound sockets so replies from N clients that
/// target the same server stay separable (one shared socket would conflate
/// `target -> client` routes). A socket is created per address family on
/// demand, so an IPv4-bound relay can still reach IPv6 targets.
/// Replies are framed and written back through the advertised relay socket, so
/// the client still sees BND.ADDR as the source.
struct ClientRelay {
    v4: Option<FamilyRelay>,
    v6: Option<FamilyRelay>,
    /// Last activity timestamp in nanoseconds since `RelayState::epoch`
    /// (`u64::MAX` ns ≈ 584 years).
    last_ns: Arc<AtomicU64>,
}

/// Bounded set of target addresses a client has asked for, used both as the
/// reply allow-list and as the request de-duplicator. Evicts the oldest entry
/// at the cap instead of clearing the whole set (a clear would silently drop
/// replies for every live flow).
#[derive(Default)]
struct RouteSet {
    set: HashSet<SocketAddr>,
    order: VecDeque<SocketAddr>,
}

impl RouteSet {
    /// Insert `target`, returning `true` if any oldest entry was evicted.
    fn insert(&mut self, target: SocketAddr) -> bool {
        if !self.set.insert(target) {
            return false;
        }
        self.order.push_back(target);
        let mut evicted = false;
        while self.set.len() > MAX_ROUTES_PER_CLIENT {
            let Some(oldest) = self.order.pop_front() else {
                break;
            };
            self.set.remove(&oldest);
            evicted = true;
        }
        evicted
    }

    fn contains(&self, target: &SocketAddr) -> bool {
        self.set.contains(target)
    }
}

/// Shared route allow-list with a monotonic eviction generation counter so
/// steady-state single-target flows skip mutex acquisition on both uplink and
/// downlink while preserving exact eviction semantics.
#[derive(Default)]
struct RouteTable {
    set: Mutex<RouteSet>,
    evict_gen: AtomicU64,
}

impl RouteTable {
    /// Insert `target` and return the exact `evict_gen` observed while holding
    /// the mutex, so callers caching `(target, gen)` cannot observe a stale
    /// generation bumped by a concurrent `insert_many` eviction after unlock.
    fn insert(&self, target: SocketAddr) -> u64 {
        let mut guard = self.set.lock().unwrap_or_else(|e| e.into_inner());
        if guard.insert(target) {
            self.evict_gen.fetch_add(1, Ordering::Release) + 1
        } else {
            self.evict_gen.load(Ordering::Relaxed)
        }
    }

    fn insert_many(&self, targets: impl Iterator<Item = SocketAddr>) {
        let mut guard = self.set.lock().unwrap_or_else(|e| e.into_inner());
        let mut evicted = false;
        for target in targets {
            evicted |= guard.insert(target);
        }
        if evicted {
            self.evict_gen.fetch_add(1, Ordering::Release);
        }
    }

    fn contains(&self, target: &SocketAddr) -> bool {
        self.set
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .contains(target)
    }
}

/// Outbound socket for one address family plus the targets requested through it.
type FamilySocket = (Arc<UdpSocket>, Arc<RouteTable>);

struct FamilyRelay {
    socket: Arc<UdpSocket>,
    /// Resolved target addresses this client has asked for. The reply header
    /// is encoded in-place from the source address without allocation.
    routes: Arc<RouteTable>,
    /// Lock-free uplink hint: when `target == last_target` and `evict_gen` is
    /// unchanged since `RouteTable::insert` returned `last_evict_gen`, `target`
    /// is guaranteed to remain present in `routes`.
    last_target: Option<SocketAddr>,
    last_evict_gen: u64,
    task: tokio::task::JoinHandle<()>,
}

impl FamilyRelay {
    #[inline]
    fn record_route(&mut self, target: SocketAddr) {
        let cur_gen = self.routes.evict_gen.load(Ordering::Acquire);
        if self.last_target != Some(target) || self.last_evict_gen != cur_gen {
            self.last_evict_gen = self.routes.insert(target);
            self.last_target = Some(target);
        }
    }
}

impl ClientRelay {
    fn family_mut(&mut self, v6: bool) -> &mut Option<FamilyRelay> {
        if v6 {
            &mut self.v6
        } else {
            &mut self.v4
        }
    }

    fn abort(&self) {
        for family in [&self.v4, &self.v6].into_iter().flatten() {
            family.task.abort();
        }
    }
}

async fn spawn_family(
    main: Arc<UdpSocket>,
    client: SocketAddr,
    cancel: tokio_util::sync::CancellationToken,
    last_ns: Arc<AtomicU64>,
    epoch: Instant,
    v6: bool,
) -> std::io::Result<FamilyRelay> {
    // Unspecified on purpose: the kernel picks the source address for each
    // target, and the family must match the target (not the advertised relay).
    let bind: SocketAddr = if v6 {
        "[::]:0"
            .parse()
            .expect("constant literal socket addr always parses")
    } else {
        "0.0.0.0:0"
            .parse()
            .expect("constant literal socket addr always parses")
    };
    let socket = Arc::new(UdpSocket::bind(bind).await?);
    let routes: Arc<RouteTable> = Arc::new(RouteTable::default());

    let task_socket = socket.clone();
    let task_routes = routes.clone();
    let task_last = last_ns;
    let task = tokio::spawn(async move {
        // Reserve MAX_UDP_HDR (22 B) headroom so replies are framed in-place
        // with zero per-packet heap allocation and zero payload copy.
        let mut buf = vec![0u8; MAX_UDP_HDR + MAX_DATAGRAM];
        let mut last_warn: Option<Instant> = None;
        let mut last_ok: Option<SocketAddr> = None;
        let mut seen_gen = 0u64;
        loop {
            let result = tokio::select! {
                biased;
                _ = cancel.cancelled() => break,
                result = task_socket.recv_from(&mut buf[MAX_UDP_HDR..]) => result,
            };
            match result {
                Ok((first_n, first_target)) => {
                    let now_ns = elapsed_ns_since(epoch, Instant::now());
                    touch_last_ns(&task_last, now_ns);
                    forward_reply(
                        &main,
                        client,
                        &task_routes,
                        &mut last_ok,
                        &mut seen_gen,
                        &mut buf,
                        first_n,
                        first_target,
                    )
                    .await;
                    // Opportunistically drain already-queued replies without
                    // waiting on isolated packets.
                    for _ in 1..UDP_BATCH_MAX {
                        match task_socket.try_recv_from(&mut buf[MAX_UDP_HDR..]) {
                            Ok((n, target)) => {
                                forward_reply(
                                    &main,
                                    client,
                                    &task_routes,
                                    &mut last_ok,
                                    &mut seen_gen,
                                    &mut buf,
                                    n,
                                    target,
                                )
                                .await;
                            }
                            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                            Err(_) => break,
                        }
                    }
                }
                Err(e) => {
                    if last_warn
                        .map(|t| t.elapsed() >= Duration::from_secs(1))
                        .unwrap_or(true)
                    {
                        warn!(client = %client, error = %e,
                            "socks5 UDP relay: client socket recv error: {e}");
                        last_warn = Some(Instant::now());
                    }
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        }
    });

    Ok(FamilyRelay {
        socket,
        routes,
        last_target: None,
        last_evict_gen: 0,
        task,
    })
}

#[allow(clippy::too_many_arguments)]
#[inline]
async fn forward_reply(
    main: &UdpSocket,
    client: SocketAddr,
    routes: &RouteTable,
    last_ok: &mut Option<SocketAddr>,
    seen_gen: &mut u64,
    buf: &mut [u8],
    n: usize,
    target: SocketAddr,
) {
    let cur_gen = routes.evict_gen.load(Ordering::Acquire);
    let requested = if *last_ok == Some(target) && cur_gen == *seen_gen {
        true
    } else {
        let ok = routes.contains(&target);
        if ok {
            *last_ok = Some(target);
            *seen_gen = cur_gen;
        }
        ok
    };
    if !requested {
        debug!(target = %target, client = %client,
            "socks5 UDP relay: reply from an unrequested address dropped");
        return;
    }
    let start = encode_reply_header(buf, target);
    if let Err(e) = try_send_to_udp(main, &buf[start..MAX_UDP_HDR + n], client).await {
        debug!(client = %client, error = %e,
            "socks5 UDP relay: reply send failed: {e}");
    }
}

struct DnsEntry {
    ips: Arc<[IpAddr]>,
    at: Instant,
}

type DnsCache = Arc<Mutex<HashMap<Box<str>, DnsEntry>>>;

/// Zero-allocation lowercase lookup into the shared DNS cache (RFC 1928 domain
/// length is at most 255 bytes). Returns `Some(ips)` on both positive and
/// negative cache hits, or `None` on cache miss / expiration.
fn lookup_dns_cache(dns: &DnsCache, host: &str, now: Instant) -> Option<Arc<[IpAddr]>> {
    if host.len() > 255 {
        return None;
    }
    let mut lower = [0u8; 255];
    for (dst, src) in lower.iter_mut().zip(host.as_bytes()) {
        *dst = src.to_ascii_lowercase();
    }
    // SAFETY-free: lowercasing ASCII bytes preserves valid UTF-8.
    let key = std::str::from_utf8(&lower[..host.len()]).ok()?;
    let cache = dns.lock().unwrap_or_else(|e| e.into_inner());
    let entry = cache.get(key)?;
    let ttl = if entry.ips.is_empty() {
        DNS_NEGATIVE_TTL
    } else {
        DNS_TTL
    };
    if now.saturating_duration_since(entry.at) < ttl {
        Some(Arc::clone(&entry.ips))
    } else {
        None
    }
}

struct RelayState {
    clients: HashMap<SocketAddr, ClientRelay>,
    /// Shared with spawned DNS tasks; keyed by lowercase hostname (port-free)
    /// so lookups borrow `&str` with zero heap allocation and share entries
    /// across ports.
    dns: DnsCache,
    pending_dns: Arc<AtomicUsize>,
    cancel: tokio_util::sync::CancellationToken,
    epoch: Instant,
    /// Monotonic floor for newly inserted client timestamps so rapid insertions
    /// within the same OS timer tick keep strict FIFO tie-breaking.
    last_insert_ns: u64,
    last_spawn_warn: Option<Instant>,
}

impl RelayState {
    fn new(cancel: tokio_util::sync::CancellationToken) -> Self {
        Self {
            clients: HashMap::new(),
            dns: Arc::new(Mutex::new(HashMap::new())),
            pending_dns: Arc::new(AtomicUsize::new(0)),
            cancel,
            epoch: Instant::now(),
            last_insert_ns: 0,
            last_spawn_warn: None,
        }
    }

    #[inline]
    fn elapsed_ns(&self, now: Instant) -> u64 {
        elapsed_ns_since(self.epoch, now)
    }

    #[cfg(test)]
    async fn handle(&mut self, main: &Arc<UdpSocket>, data: &[u8], from: SocketAddr) {
        let now = Instant::now();
        let now_ns = self.elapsed_ns(now);
        self.handle_at(main, data, from, now, now_ns).await;
    }

    async fn handle_at(
        &mut self,
        main: &Arc<UdpSocket>,
        data: &[u8],
        from: SocketAddr,
        now: Instant,
        now_ns: u64,
    ) {
        let Some(request) = UdpRequest::parse(data) else {
            debug!(from = %from, bytes = data.len(),
                "socks5 UDP relay: malformed request dropped");
            return;
        };

        // Enforce the fd bound before inserting a brand-new client; when below
        // MAX_CLIENTS (steady state), the `entry()` below is a single lookup.
        if self.clients.len() >= MAX_CLIENTS && !self.clients.contains_key(&from) {
            self.make_room_for_client();
        }
        let last_insert_ns = &mut self.last_insert_ns;
        let client = self.clients.entry(from).or_insert_with(|| {
            let insert_ns = now_ns.max(last_insert_ns.saturating_add(1));
            *last_insert_ns = insert_ns;
            ClientRelay {
                v4: None,
                v6: None,
                last_ns: Arc::new(AtomicU64::new(insert_ns)),
            }
        });
        touch_last_ns(&client.last_ns, now_ns);

        // Normalize IP literals sent inside ATYP_DOMAIN straight to Addr.
        let target = match request.target {
            UdpTarget::Addr(addr) => UdpTarget::Addr(addr),
            UdpTarget::Domain(host, port) => match host.parse::<IpAddr>() {
                Ok(ip) => UdpTarget::Addr(SocketAddr::new(ip, port)),
                Err(_) => UdpTarget::Domain(host, port),
            },
        };

        match target {
            UdpTarget::Addr(target) => {
                let Some(family) = ensure_family_on_client(
                    client,
                    main,
                    from,
                    &self.cancel,
                    self.epoch,
                    &mut self.last_spawn_warn,
                    target.is_ipv6(),
                )
                .await
                else {
                    return;
                };
                family.record_route(target);
                if let Err(e) = try_send_to_udp(&family.socket, request.payload, target).await {
                    debug!(target = %target, error = %e,
                        "socks5 UDP relay: forward failed: {e}");
                }
            }
            UdpTarget::Domain(host, port) => {
                // Fast path: check DNS cache synchronously with zero heap
                // allocation and zero task spawn on cache hit (99.9% of domain
                // UDP traffic). Only cache misses spawn an async resolver task.
                if let Some(ips) = lookup_dns_cache(&self.dns, host, now) {
                    if ips.is_empty() {
                        return;
                    }
                    let prefer_v6 = ips[0].is_ipv6();
                    let chosen_v6 = if ensure_family_on_client(
                        client,
                        main,
                        from,
                        &self.cancel,
                        self.epoch,
                        &mut self.last_spawn_warn,
                        prefer_v6,
                    )
                    .await
                    .is_some()
                    {
                        prefer_v6
                    } else if ips.iter().any(|ip| ip.is_ipv6() != prefer_v6)
                        && ensure_family_on_client(
                            client,
                            main,
                            from,
                            &self.cancel,
                            self.epoch,
                            &mut self.last_spawn_warn,
                            !prefer_v6,
                        )
                        .await
                        .is_some()
                    {
                        !prefer_v6
                    } else {
                        return;
                    };
                    let Some(family) = client.family_mut(chosen_v6).as_mut() else {
                        return;
                    };
                    let mut matching = ips
                        .iter()
                        .copied()
                        .filter(|ip| ip.is_ipv6() == chosen_v6)
                        .map(|ip| SocketAddr::new(ip, port));
                    let Some(first) = matching.next() else {
                        return;
                    };
                    if let Some(second) = matching.next() {
                        family.routes.insert_many(
                            std::iter::once(first)
                                .chain(std::iter::once(second))
                                .chain(matching),
                        );
                    } else {
                        family.record_route(first);
                    }
                    for ip in ips.iter().copied().filter(|ip| ip.is_ipv6() == chosen_v6) {
                        if try_send_to_udp(
                            &family.socket,
                            request.payload,
                            SocketAddr::new(ip, port),
                        )
                        .await
                        .is_ok()
                        {
                            return;
                        }
                    }
                    return;
                }

                // Avoid allocating payload/host and spawning a task when the
                // concurrent DNS lookup budget is already full.
                if self.pending_dns.load(Ordering::Relaxed) >= MAX_PENDING_DNS {
                    debug!(host = %host, port = %port,
                        "socks5 UDP relay: DNS lookup budget exhausted; dropping request");
                    return;
                }

                // Slow path (DNS cache miss / expired): bind both families so
                // the spawned resolver can deliver whichever address family
                // answers without stalling the main receive loop.
                let v4 = ensure_family_on_client(
                    client,
                    main,
                    from,
                    &self.cancel,
                    self.epoch,
                    &mut self.last_spawn_warn,
                    false,
                )
                .await
                .map(|f| (f.socket.clone(), f.routes.clone()));
                let v6 = ensure_family_on_client(
                    client,
                    main,
                    from,
                    &self.cancel,
                    self.epoch,
                    &mut self.last_spawn_warn,
                    true,
                )
                .await
                .map(|f| (f.socket.clone(), f.routes.clone()));
                if v4.is_none() && v6.is_none() {
                    return;
                }
                let payload = request.payload.to_vec();
                let host = host.to_string();
                let dns = self.dns.clone();
                let pending = self.pending_dns.clone();
                let cancel = self.cancel.clone();
                tokio::spawn(async move {
                    let Some(ips) = resolve_cached(&dns, &pending, &host, port).await else {
                        return;
                    };
                    deliver_resolved(ips, port, payload, v4, v6, cancel).await;
                });
            }
        }
    }

    /// Evict the least-recently-active client until a new one fits. Runs only
    /// at insertion; with MAX_CLIENTS = 128 the linear scan is bounded and the
    /// map can never exceed the cap between sweeps.
    fn make_room_for_client(&mut self) {
        while self.clients.len() >= MAX_CLIENTS {
            let oldest = self
                .clients
                .iter()
                .min_by_key(|(_, c)| c.last_ns.load(Ordering::Relaxed))
                .map(|(addr, _)| *addr);
            match oldest {
                Some(addr) => {
                    if let Some(client) = self.clients.remove(&addr) {
                        client.abort();
                    }
                }
                None => break,
            }
        }
    }

    fn sweep(&mut self, now: Instant) {
        let now_ns = self.elapsed_ns(now);
        self.clients.retain(|_, client| {
            let last_ns = client.last_ns.load(Ordering::Relaxed);
            let alive = now_ns.saturating_sub(last_ns) < CLIENT_TTL_NS;
            if !alive {
                client.abort();
            }
            alive
        });
        // The insertion path (`make_room_for_client`) is the only place that
        // adds entries and it enforces MAX_CLIENTS, so the map is never over
        // the cap here; this sweep only reaps idle clients.
    }
}

/// Ensure `client` has an outbound socket for `v6`, returning a mutable
/// reference to it without a second `HashMap` lookup.
async fn ensure_family_on_client<'a>(
    client: &'a mut ClientRelay,
    main: &Arc<UdpSocket>,
    from: SocketAddr,
    cancel: &tokio_util::sync::CancellationToken,
    epoch: Instant,
    last_spawn_warn: &mut Option<Instant>,
    v6: bool,
) -> Option<&'a mut FamilyRelay> {
    if client.family_mut(v6).is_none() {
        match spawn_family(
            main.clone(),
            from,
            cancel.clone(),
            client.last_ns.clone(),
            epoch,
            v6,
        )
        .await
        {
            Ok(family) => *client.family_mut(v6) = Some(family),
            Err(e) => {
                if last_spawn_warn
                    .map(|t| t.elapsed() >= Duration::from_secs(1))
                    .unwrap_or(true)
                {
                    warn!(client = %from, error = %e,
                        "socks5 UDP relay: could not create client socket: {e}");
                    *last_spawn_warn = Some(Instant::now());
                }
                return None;
            }
        }
    }
    client.family_mut(v6).as_mut()
}

/// Resolve a domain off the relay receive path. Returns a (possibly empty,
/// negatively cached) IP list, or `None` when the lookup budget is exhausted.
/// The shared cache is capped and evicts the oldest entry.
async fn resolve_cached(
    dns: &DnsCache,
    pending: &Arc<AtomicUsize>,
    host: &str,
    port: u16,
) -> Option<Arc<[IpAddr]>> {
    if let Some(ips) = lookup_dns_cache(dns, host, Instant::now()) {
        return Some(ips);
    }

    if pending.fetch_add(1, Ordering::AcqRel) >= MAX_PENDING_DNS {
        pending.fetch_sub(1, Ordering::AcqRel);
        debug!(host = %host, port = %port,
            "socks5 UDP relay: DNS lookup budget exhausted; dropping request");
        return None;
    }
    let result =
        tokio::time::timeout(DNS_LOOKUP_TIMEOUT, tokio::net::lookup_host((host, port))).await;
    pending.fetch_sub(1, Ordering::AcqRel);

    let ips: Arc<[IpAddr]> = match result {
        Ok(Ok(iter)) => iter.map(|a| a.ip()).collect::<Vec<_>>().into(),
        Ok(Err(e)) => {
            debug!(host = %host, port = %port, error = %e,
                "socks5 UDP relay: resolve failed: {e}");
            Arc::from([])
        }
        Err(_) => {
            debug!(host = %host, port = %port,
                "socks5 UDP relay: resolve timed out");
            Arc::from([])
        }
    };

    let inserted_at = Instant::now();
    let key: Box<str> = host.to_ascii_lowercase().into_boxed_str();
    {
        let mut cache = dns.lock().unwrap_or_else(|e| e.into_inner());
        if cache.len() >= MAX_DNS_ENTRIES {
            cache.retain(|_, entry| {
                let ttl = if entry.ips.is_empty() {
                    DNS_NEGATIVE_TTL
                } else {
                    DNS_TTL
                };
                inserted_at.saturating_duration_since(entry.at) < ttl
            });
            if cache.len() >= MAX_DNS_ENTRIES {
                if let Some(oldest) = cache
                    .iter()
                    .min_by_key(|(_, entry)| entry.at)
                    .map(|(key, _)| key.clone())
                {
                    cache.remove(&oldest);
                }
            }
        }
        cache.insert(
            key,
            DnsEntry {
                ips: Arc::clone(&ips),
                at: inserted_at,
            },
        );
    }
    Some(ips)
}

/// Deliver a resolved datagram, choosing the first address whose family has a
/// usable outbound socket. All addresses of that family are recorded as
/// requested so their replies are accepted.
async fn deliver_resolved(
    ips: Arc<[IpAddr]>,
    port: u16,
    payload: Vec<u8>,
    v4: Option<FamilySocket>,
    v6: Option<FamilySocket>,
    cancel: tokio_util::sync::CancellationToken,
) {
    if ips.is_empty() || cancel.is_cancelled() {
        return;
    }
    let (socket, routes, chosen_v4) = match (v4, v6) {
        (Some((s, r)), _) if ips[0].is_ipv4() => (s, r, true),
        (Some((s, r)), None) => (s, r, true),
        (_, Some((s, r))) => (s, r, false),
        (None, None) => return,
    };
    routes.insert_many(
        ips.iter()
            .copied()
            .filter(|ip| ip.is_ipv6() == !chosen_v4)
            .map(|ip| SocketAddr::new(ip, port)),
    );
    for ip in ips.iter().copied().filter(|ip| ip.is_ipv6() == !chosen_v4) {
        if try_send_to_udp(&socket, &payload, SocketAddr::new(ip, port))
            .await
            .is_ok()
        {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ipv4_req(target: SocketAddr, payload: &[u8]) -> Vec<u8> {
        let mut v = vec![0, 0, 0, ATYP_IPV4];
        match target {
            SocketAddr::V4(a) => {
                v.extend_from_slice(&a.ip().octets());
                v.extend_from_slice(&a.port().to_be_bytes());
            }
            SocketAddr::V6(_) => panic!("expected v4"),
        }
        v.extend_from_slice(payload);
        v
    }

    #[test]
    fn parses_ipv4_request() {
        let target: SocketAddr = "192.0.2.7:5353".parse().unwrap();
        let data = ipv4_req(target, b"dns");
        let req = UdpRequest::parse(&data).expect("valid request");
        assert_eq!(req.payload, b"dns");
        match req.target {
            UdpTarget::Addr(a) => assert_eq!(a, target),
            _ => panic!("expected address target"),
        }
    }

    #[test]
    fn parses_ipv6_and_domain_requests() {
        let target: SocketAddr = "[2001:db8::1]:443".parse().unwrap();
        let mut data = vec![0, 0, 0, ATYP_IPV6];
        match target {
            SocketAddr::V6(a) => {
                data.extend_from_slice(&a.ip().octets());
                data.extend_from_slice(&a.port().to_be_bytes());
            }
            _ => unreachable!(),
        }
        data.extend_from_slice(b"x");
        let req = UdpRequest::parse(&data).expect("valid ipv6 request");
        assert_eq!(req.payload, b"x");
        assert!(matches!(req.target, UdpTarget::Addr(a) if a == target));

        let mut data = vec![0, 0, 0, ATYP_DOMAIN, 11];
        data.extend_from_slice(b"example.com");
        data.extend_from_slice(&53u16.to_be_bytes());
        data.extend_from_slice(b"q");
        let req = UdpRequest::parse(&data).expect("valid domain request");
        assert_eq!(req.payload, b"q");
        assert!(matches!(req.target, UdpTarget::Domain("example.com", 53)));
    }

    #[test]
    fn rejects_rsv_frag_truncation_and_unknown_atyp() {
        let target: SocketAddr = "192.0.2.7:5353".parse().unwrap();
        let base = ipv4_req(target, b"x");

        for bad in [1usize, 2usize] {
            let mut v = base.clone();
            v[0] = bad as u8;
            assert!(UdpRequest::parse(&v).is_none(), "nonzero RSV byte accepted");
        }
        let mut v = base.clone();
        v[2] = 1;
        assert!(
            UdpRequest::parse(&v).is_none(),
            "fragmented request accepted"
        );
        assert!(
            UdpRequest::parse(&base[..9]).is_none(),
            "truncated header accepted"
        );
        let mut v = base.clone();
        v[3] = 0x05;
        assert!(UdpRequest::parse(&v).is_none(), "unknown ATYP accepted");
        let mut v = base;
        v[4] = 0; // domain length 0
        v[3] = ATYP_DOMAIN;
        assert!(UdpRequest::parse(&v).is_none(), "empty domain accepted");
    }

    #[test]
    fn route_set_evicts_only_the_oldest() {
        let mut routes = RouteSet::default();
        let first = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1);
        for port in 1..=(MAX_ROUTES_PER_CLIENT as u16 + 10) {
            routes.insert(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port));
        }
        assert!(!routes.contains(&first), "oldest route must be evicted");
        assert!(routes.contains(&SocketAddr::new(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            MAX_ROUTES_PER_CLIENT as u16 + 10
        )));
    }

    #[tokio::test]
    async fn client_cap_is_enforced_via_handle() {
        let main = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let mut state = RelayState::new(tokio_util::sync::CancellationToken::new());
        let target: SocketAddr = "127.0.0.1:9".parse().unwrap();
        let data = ipv4_req(target, b"x");
        let first = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 20_000);
        for i in 0..=MAX_CLIENTS {
            let from = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 20_000 + i as u16);
            state.handle(&main, &data, from).await;
        }
        assert_eq!(
            state.clients.len(),
            MAX_CLIENTS,
            "the handle path must not exceed MAX_CLIENTS"
        );
        assert!(
            !state.clients.contains_key(&first),
            "the oldest client must be evicted by the handle path"
        );
        state.cancel.cancel();
    }

    #[tokio::test]
    async fn client_map_cap_holds_at_insertion() {
        let cancel = tokio_util::sync::CancellationToken::new();
        let mut state = RelayState::new(cancel);
        for i in 0..MAX_CLIENTS {
            // Insertion order is the eviction order: client 1 is oldest.
            state.clients.insert(
                SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), i as u16 + 1),
                ClientRelay {
                    v4: None,
                    v6: None,
                    last_ns: Arc::new(AtomicU64::new(i as u64 * 1_000_000_000)),
                },
            );
        }
        state.make_room_for_client();
        assert_eq!(state.clients.len(), MAX_CLIENTS - 1);
        assert!(
            !state
                .clients
                .contains_key(&SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1)),
            "oldest client must be evicted first"
        );
    }

    #[test]
    fn route_table_evict_gen_bumps_on_eviction() {
        let table = RouteTable::default();
        assert_eq!(table.evict_gen.load(Ordering::Acquire), 0);
        let first = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1);
        for port in 1..=(MAX_ROUTES_PER_CLIENT as u16) {
            assert_eq!(
                table.insert(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)),
                0,
                "filling up to cap must return evict_gen 0"
            );
        }
        assert_eq!(
            table.insert(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                MAX_ROUTES_PER_CLIENT as u16 + 1,
            )),
            1,
            "evicting oldest route must return bumped evict_gen 1"
        );
        assert_eq!(table.evict_gen.load(Ordering::Acquire), 1);
        assert!(!table.contains(&first));
    }

    #[tokio::test]
    async fn domain_cache_hit_forwards_synchronously_without_spawning() {
        // Pre-populate the DNS cache with an unresolvable `.invalid` host and
        // confirm `handle` forwards synchronously via the cache-hit fast path
        // without bumping `pending_dns` or binding an unused IPv6 socket.
        let target_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let target_addr = target_sock.local_addr().unwrap();
        let main = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let mut state = RelayState::new(tokio_util::sync::CancellationToken::new());
        state.dns.lock().unwrap().insert(
            "cached.invalid".into(),
            DnsEntry {
                ips: Arc::from([target_addr.ip()]),
                at: Instant::now(),
            },
        );

        let host = b"Cached.Invalid";
        let mut req = vec![0, 0, 0, ATYP_DOMAIN, host.len() as u8];
        req.extend_from_slice(host);
        req.extend_from_slice(&target_addr.port().to_be_bytes());
        req.extend_from_slice(b"sync-hit");

        let from: SocketAddr = "127.0.0.1:21000".parse().unwrap();
        state.handle(&main, &req, from).await;

        assert_eq!(state.pending_dns.load(Ordering::Acquire), 0);
        let client = state.clients.get(&from).expect("client registered");
        assert!(client.v4.is_some(), "IPv4 socket must be created");
        assert!(
            client.v6.is_none(),
            "cache-hit IPv4 target must not bind an unused IPv6 socket"
        );

        let mut buf = [0u8; 64];
        let (n, _) = tokio::time::timeout(Duration::from_secs(1), target_sock.recv_from(&mut buf))
            .await
            .expect("sync-hit packet must arrive")
            .unwrap();
        assert_eq!(&buf[..n], b"sync-hit");
        state.cancel.cancel();
    }

    #[tokio::test]
    async fn association_cap_is_enforced() {
        let cfg = PluginConfig {
            udp_enable: true,
            udp_bind_addr: "127.0.0.1:0".into(),
            ..Default::default()
        };
        let cancel = tokio_util::sync::CancellationToken::new();
        let handle = UdpRelay::from_config(&cfg, cancel.clone())
            .await
            .unwrap()
            .expect("UDP enabled");
        let mut guards = Vec::new();
        for _ in 0..MAX_ASSOCIATIONS {
            guards.push(handle.enter().await.expect("association below cap").0);
        }
        assert!(
            handle.enter().await.is_err(),
            "the {MAX_ASSOCIATIONS}th association must be rejected"
        );
        drop(guards);
        cancel.cancel();
    }

    #[test]
    fn unspecified_bind_address_is_advertised_as_loopback() {
        let a: SocketAddr = "0.0.0.0:1234".parse().unwrap();
        assert_eq!(mask_unspecified(a), "127.0.0.1:1234".parse().unwrap());
        let a: SocketAddr = "[::]:1234".parse().unwrap();
        assert_eq!(mask_unspecified(a), "[::1]:1234".parse().unwrap());
        let a: SocketAddr = "192.0.2.1:1234".parse().unwrap();
        assert_eq!(mask_unspecified(a), a);
    }
}
