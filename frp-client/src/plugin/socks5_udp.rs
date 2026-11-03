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
use std::sync::atomic::{AtomicUsize, Ordering};
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
    // association whose client disappears would pin a task + socket + 64 KiB
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
                    if n == 0 || active.load(Ordering::Acquire) == 0 {
                        continue;
                    }
                    state.handle(&socket, &buf[..n], from).await;
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

/// Per-client relay: dedicated outbound sockets so replies from N clients that
/// target the same server stay separable (one shared socket would conflate
/// `target -> client` routes). A socket is created per address family on
/// demand, so an IPv4-bound relay can still reach IPv6 targets.
/// Replies are framed and written back through the advertised relay socket, so
/// the client still sees BND.ADDR as the source.
struct ClientRelay {
    v4: Option<FamilyRelay>,
    v6: Option<FamilyRelay>,
    last: Arc<Mutex<Instant>>,
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
    fn insert(&mut self, target: SocketAddr) {
        if !self.set.insert(target) {
            return;
        }
        self.order.push_back(target);
        while self.set.len() > MAX_ROUTES_PER_CLIENT {
            let Some(oldest) = self.order.pop_front() else {
                break;
            };
            self.set.remove(&oldest);
        }
    }

    fn contains(&self, target: &SocketAddr) -> bool {
        self.set.contains(target)
    }
}

/// Outbound socket for one address family plus the targets requested through it.
type FamilySocket = (Arc<UdpSocket>, Arc<Mutex<RouteSet>>);

struct FamilyRelay {
    socket: Arc<UdpSocket>,
    /// Resolved target addresses this client has asked for. The reply header
    /// is a pure function of the key, so storing it would allocate per packet.
    routes: Arc<Mutex<RouteSet>>,
    task: tokio::task::JoinHandle<()>,
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
    last: Arc<Mutex<Instant>>,
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
    let routes: Arc<Mutex<RouteSet>> = Arc::new(Mutex::new(RouteSet::default()));

    let task_socket = socket.clone();
    let task_routes = routes.clone();
    let task_last = last;
    let task = tokio::spawn(async move {
        let mut buf = vec![0u8; MAX_DATAGRAM];
        let mut last_warn: Option<Instant> = None;
        loop {
            let result = tokio::select! {
                biased;
                _ = cancel.cancelled() => break,
                result = task_socket.recv_from(&mut buf) => result,
            };
            match result {
                Ok((n, target)) => {
                    *task_last.lock().unwrap_or_else(|e| e.into_inner()) = Instant::now();
                    let requested = task_routes
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .contains(&target);
                    if !requested {
                        debug!(target = %target, client = %client,
                            "socks5 UDP relay: reply from an unrequested address dropped");
                        continue;
                    }
                    let header = reply_header(target);
                    let mut out = Vec::with_capacity(3 + header.len() + n);
                    out.extend_from_slice(&[0, 0, 0]); // RSV RSV FRAG
                    out.extend_from_slice(&header);
                    out.extend_from_slice(&buf[..n]);
                    if let Err(e) = main.send_to(&out, client).await {
                        debug!(client = %client, error = %e,
                            "socks5 UDP relay: reply send failed: {e}");
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
        task,
    })
}

/// `ATYP + SRV.ADDR + SRV.PORT` for a reply datagram.
fn reply_header(target: SocketAddr) -> Vec<u8> {
    match target.ip() {
        IpAddr::V4(ip) => {
            let mut h = Vec::with_capacity(7);
            h.push(ATYP_IPV4);
            h.extend_from_slice(&ip.octets());
            h.extend_from_slice(&target.port().to_be_bytes());
            h
        }
        IpAddr::V6(ip) => {
            let mut h = Vec::with_capacity(19);
            h.push(ATYP_IPV6);
            h.extend_from_slice(&ip.octets());
            h.extend_from_slice(&target.port().to_be_bytes());
            h
        }
    }
}

struct DnsEntry {
    addrs: Vec<SocketAddr>,
    at: Instant,
}

struct RelayState {
    clients: HashMap<SocketAddr, ClientRelay>,
    /// Shared with spawned DNS tasks; std Mutex (short critical sections, no
    /// await while held).
    dns: Arc<Mutex<HashMap<(String, u16), DnsEntry>>>,
    pending_dns: Arc<AtomicUsize>,
    cancel: tokio_util::sync::CancellationToken,
    last_spawn_warn: Option<Instant>,
}

impl RelayState {
    fn new(cancel: tokio_util::sync::CancellationToken) -> Self {
        Self {
            clients: HashMap::new(),
            dns: Arc::new(Mutex::new(HashMap::new())),
            pending_dns: Arc::new(AtomicUsize::new(0)),
            cancel,
            last_spawn_warn: None,
        }
    }

    async fn handle(&mut self, main: &Arc<UdpSocket>, data: &[u8], from: SocketAddr) {
        let Some(request) = UdpRequest::parse(data) else {
            debug!(from = %from, bytes = data.len(),
                "socks5 UDP relay: malformed request dropped");
            return;
        };
        let now = Instant::now();
        // Do NOT sweep here: the run loop already ticks every 60s, and a
        // per-datagram O(#clients) pass would sit on the hot path.
        if !self.clients.contains_key(&from) {
            // Enforce the fd bound at insertion, not only on the 60s sweep:
            // an unauthenticated source-address spray must not grow the map
            // (and its sockets/tasks) for a whole sweep window.
            self.make_room_for_client();
            self.clients.insert(
                from,
                ClientRelay {
                    v4: None,
                    v6: None,
                    last: Arc::new(Mutex::new(now)),
                },
            );
        }
        if let Some(client) = self.clients.get(&from) {
            *client.last.lock().unwrap_or_else(|e| e.into_inner()) = now;
        }

        match request.target {
            UdpTarget::Addr(target) => {
                let Some((socket, routes)) = self
                    .ensure_client_family(main, from, target.is_ipv6())
                    .await
                else {
                    return;
                };
                routes
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .insert(target);
                if let Err(e) = socket.send_to(request.payload, target).await {
                    debug!(target = %target, error = %e,
                        "socks5 UDP relay: forward failed: {e}");
                }
            }
            UdpTarget::Domain(host, port) => {
                // Bind both families now (IPv4/IPv6) so the spawned resolver
                // can deliver whichever address the name resolves to. The
                // lookup itself runs off the receive loop: one slow resolver
                // must not stall every other client's datagrams.
                let v4 = self.ensure_client_family(main, from, false).await;
                let v6 = self.ensure_client_family(main, from, true).await;
                if v4.is_none() && v6.is_none() {
                    return;
                }
                let payload = request.payload.to_vec();
                let host = host.to_string();
                let dns = self.dns.clone();
                let pending = self.pending_dns.clone();
                let cancel = self.cancel.clone();
                tokio::spawn(async move {
                    let Some(addrs) = resolve_cached(&dns, &pending, &host, port).await else {
                        return;
                    };
                    deliver_resolved(addrs, payload, v4, v6, cancel).await;
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
                .min_by_key(|(_, c)| *c.last.lock().unwrap_or_else(|e| e.into_inner()))
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

    /// Ensure the client has an outbound socket for `v6`, returning it plus
    /// its route set. Bind failures (e.g. no IPv6 on the host) are throttled
    /// and yield `None`.
    async fn ensure_client_family(
        &mut self,
        main: &Arc<UdpSocket>,
        from: SocketAddr,
        v6: bool,
    ) -> Option<FamilySocket> {
        let client = self.clients.get_mut(&from)?;
        if client.family_mut(v6).is_none() {
            match spawn_family(
                main.clone(),
                from,
                self.cancel.clone(),
                client.last.clone(),
                v6,
            )
            .await
            {
                Ok(family) => *client.family_mut(v6) = Some(family),
                Err(e) => {
                    if self
                        .last_spawn_warn
                        .map(|t| t.elapsed() >= Duration::from_secs(1))
                        .unwrap_or(true)
                    {
                        warn!(client = %from, error = %e,
                            "socks5 UDP relay: could not create client socket: {e}");
                        self.last_spawn_warn = Some(Instant::now());
                    }
                    return None;
                }
            }
        }
        let family = client.family_mut(v6).as_ref()?;
        Some((family.socket.clone(), family.routes.clone()))
    }

    fn sweep(&mut self, now: Instant) {
        self.clients.retain(|_, client| {
            let idle = {
                let last = client.last.lock().unwrap_or_else(|e| e.into_inner());
                now.duration_since(*last) < CLIENT_TTL
            };
            if !idle {
                client.abort();
            }
            idle
        });
        // The insertion path (`make_room_for_client`) is the only place that
        // adds entries and it enforces MAX_CLIENTS, so the map is never over
        // the cap here; this sweep only reaps idle clients.
    }
}

/// Resolve a domain off the relay receive path. Returns a (possibly empty,
/// negatively cached) address list, or `None` when the lookup budget is
/// exhausted. The shared cache is capped and evicts the oldest entry.
async fn resolve_cached(
    dns: &Arc<Mutex<HashMap<(String, u16), DnsEntry>>>,
    pending: &Arc<AtomicUsize>,
    host: &str,
    port: u16,
) -> Option<Vec<SocketAddr>> {
    let key = (host.to_ascii_lowercase(), port);
    let now = Instant::now();
    {
        let cache = dns.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(entry) = cache.get(&key) {
            let ttl = if entry.addrs.is_empty() {
                DNS_NEGATIVE_TTL
            } else {
                DNS_TTL
            };
            if now.duration_since(entry.at) < ttl {
                return Some(entry.addrs.clone());
            }
        }
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

    let addrs: Vec<SocketAddr> = match result {
        Ok(Ok(iter)) => iter.collect(),
        Ok(Err(e)) => {
            debug!(host = %host, port = %port, error = %e,
                "socks5 UDP relay: resolve failed: {e}");
            Vec::new()
        }
        Err(_) => {
            debug!(host = %host, port = %port,
                "socks5 UDP relay: resolve timed out");
            Vec::new()
        }
    };

    {
        let mut cache = dns.lock().unwrap_or_else(|e| e.into_inner());
        if cache.len() >= MAX_DNS_ENTRIES {
            let now = Instant::now();
            cache.retain(|_, entry| {
                let ttl = if entry.addrs.is_empty() {
                    DNS_NEGATIVE_TTL
                } else {
                    DNS_TTL
                };
                now.duration_since(entry.at) < ttl
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
                addrs: addrs.clone(),
                at: now,
            },
        );
    }
    Some(addrs)
}

/// Deliver a resolved datagram, choosing the first address whose family has a
/// usable outbound socket. All addresses of that family are recorded as
/// requested so their replies are accepted.
async fn deliver_resolved(
    addrs: Vec<SocketAddr>,
    payload: Vec<u8>,
    v4: Option<FamilySocket>,
    v6: Option<FamilySocket>,
    cancel: tokio_util::sync::CancellationToken,
) {
    if addrs.is_empty() || cancel.is_cancelled() {
        return;
    }
    let (socket, routes, chosen_v4) = match (v4, v6) {
        (Some((s, r)), _) if addrs[0].is_ipv4() => (s, r, true),
        (Some((s, r)), None) => (s, r, true),
        (_, Some((s, r))) => (s, r, false),
        (None, None) => return,
    };
    {
        let mut routes = routes.lock().unwrap_or_else(|e| e.into_inner());
        for target in addrs.iter().filter(|t| t.is_ipv6() == !chosen_v4) {
            routes.insert(*target);
        }
    }
    for target in addrs.iter().filter(|t| t.is_ipv6() == !chosen_v4) {
        if socket.send_to(&payload, *target).await.is_ok() {
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
        let base = Instant::now();
        for i in 0..MAX_CLIENTS {
            // Insertion order is the eviction order: client 1 is oldest.
            let last = base + Duration::from_secs(i as u64);
            state.clients.insert(
                SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), i as u16 + 1),
                ClientRelay {
                    v4: None,
                    v6: None,
                    last: Arc::new(Mutex::new(last)),
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
