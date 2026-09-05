use dashmap::DashMap;
use std::collections::HashMap;
#[cfg(feature = "vnet")]
use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::atomic::{
    AtomicBool, AtomicI64, AtomicU64, AtomicUsize, Ordering as AtomicOrdering,
};
use std::sync::{Arc, LazyLock};
use std::time::{Duration, Instant};
#[cfg(feature = "dashboard")]
use tokio::sync::broadcast;
use tokio::sync::mpsc;
use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;

use frp_core::auth::{AuthConfig, OidcVerifier};
use frp_core::metrics::ProxyMetricsRegistry;
use frp_core::msg;
#[cfg(feature = "vnet")]
use frp_core::msg::{VnetRouteAdvertise, VnetRouteRemove};
use frp_core::transport::IoStream;

use crate::nathole::controller::Controller;
use crate::proxy::ProxyManager;
use crate::registry::ClientRegistry;
use crate::tcpmux::TcpMuxManager;
use crate::vhost::VhostManager;

#[cfg(feature = "vnet")]
type VnetRouteMap = Arc<RwLock<HashMap<(String, String), (String, String)>>>;

// ---------------------------------------------------------------
// Shared state for cross-task communication
// ---------------------------------------------------------------

/// Deadline for `InternalMsg` channel sends from accept-path tasks
/// (NewWorkConn / VisitorConn / ProxyUserConn) into a control handler.
/// A control handler that stops draining its channel (wedged but alive)
/// must not pin the accept-path task + fd + conn_semaphore permit forever;
/// on timeout the sender drops the connection instead — the control-side
/// work pool re-requests work conns and frpc retries (audit H3).
pub(crate) const CTL_SEND_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

#[derive(Debug)]
pub enum InternalMsg {
    NewWorkConn(IoStream),
    VisitorConn {
        proxy_name: String,
        visitor_conn: IoStream,
        /// Visitor-segment encryption (Go 三段式第 1 段): whether the visitor
        /// declared `use_encryption` in NewVisitorConn. When true, the bridge
        /// wraps the visitor conn with `derive_key(proxy.sk)` before joining it
        /// to the provider work conn (which keeps its own token-based
        /// encryption or plaintext).
        visitor_use_encryption: bool,
        /// Visitor-segment compression (Go 三段式第 1 段): whether the visitor
        /// declared `use_compression` in NewVisitorConn (Go source:
        /// `[[visitors]] transport.useCompression`). When true, the bridge
        /// wraps the visitor conn in a Snappy stream (inside the CFB layer
        /// when encryption is also on — snappy inner, CFB outer, matching Go's
        /// `WithCompression` + `WithEncryption` order).
        visitor_use_compression: bool,
        /// Wire protocol of the visitor's connection (V2 frame detection).
        /// Go frp v0.71.0 `RegisterVisitorConn` records the visitor conn's
        /// wireProtocol; the SUDP bridge needs it to pick the visitor-side
        /// packet codec (and to detect mixed SUDP packet encodings).
        visitor_v2: bool,
        /// Visitor-segment UDPPacket codec (`"binary-v1"` or empty),
        /// determined at accept time (Go frp v0.71.0 `admitVisitorByRunID`:
        /// V2 visitors inherit their own control session's negotiated codec;
        /// V1 visitors use JSON).
        visitor_udp_packet_codec: String,
    },
    ProxyUserConn {
        proxy_name: String,
        user_conn: IoStream,
        pre_read: Vec<u8>,
        /// Per-proxy user-conn cap permit (audit M5). Acquired by the
        /// FORWARDER before the cross-run_id group-LB try_send so an
        /// at-cap/slow backend cannot accumulate raw sockets (fds) in this
        /// shared 1024-slot channel ahead of the permit check. The backend
        /// handler CONSUMES this permit instead of re-acquiring — never
        /// both. `None` means "no permit carried" (unlimited proxy, or a
        /// local sender like vhost/tcpmux that never acquired one; the
        /// backend handler acquires one then).
        user_conn_permit: Option<tokio::sync::OwnedSemaphorePermit>,
        /// Set by forwarders that ALREADY chose the backend (the TCP group
        /// shared listener and the cross-run_id group-LB M5 forwarder). The
        /// receiving handler must route directly to the named `proxy_name`
        /// instead of re-running group selection — re-selecting an
        /// already-selected conn bounces it between group members forever
        /// (the manager-level round-robin counter makes every hop pick the
        /// next member) when the group spans run_ids without a group_key.
        group_selected: bool,
    },
    /// UDP proxy needs a work connection for data forwarding
    /// (Go frp v0.69.1 uses work connections, not control connection).
    UdpNeedsWorkConn {
        proxy_name: String,
    },
    /// Sent when a new control connection claims the same run_id.
    /// The old handler should stop listening and clean up.
    /// The `done` oneshot is signaled after cleanup completes,
    /// allowing the new handler to wait for handoff.
    Shutdown {
        done: tokio::sync::oneshot::Sender<()>,
    },
    // NatHoleClient variant removed — dead code. Go frp compat uses
    // NatHoleSidOnWorkConn path (server is pure relay, provider does STUN).
    /// Send NatHoleSid to provider on a work connection (Go frp v0.69.1 XTCP compat).
    /// The server writes NatHoleSid on a pooled work connection to notify
    /// the provider that a new XTCP visitor has arrived. The provider then
    /// does its own STUN discovery and sends NatHoleClient back on the
    /// control connection with its mapped addresses.
    NatHoleSidOnWorkConn {
        sid: String,
        proxy_name: String,
    },
    /// Forward NatHoleSid to visitor via control channel (Go frp compat).
    WriteNatHoleSid {
        sid: String,
    },
    /// Forward NatHoleReport to visitor via control channel (Go frp compat).
    WriteNatHoleReport {
        sid: String,
    },
    /// Forward NatHoleResp to visitor via control channel (Go frp XTCP compat).
    /// Carries provider's candidate/assisted addresses for NAT traversal.
    WriteNatHoleResp {
        transaction_id: String,
        error: Option<String>,
        sid: Option<String>,
        protocol: Option<String>,
        candidate_addrs: Option<Vec<String>>,
        assisted_addrs: Option<Vec<String>>,
        detect_behavior: Option<msg::NatHoleDetectBehavior>,
    },
    /// Send a CloseProxy message to the client via its control channel.
    /// Used by the dashboard delete API to notify the client to shut
    /// down its proxy listener.
    WriteCloseProxy {
        proxy_name: String,
    },
    /// Forward a vnet IP packet to a target client's control handler.
    #[cfg(feature = "vnet")]
    VnetPacketForward {
        proxy_name: Arc<str>,
        data: Arc<str>, // base64-encoded IP packet
    },
    /// Forward a vnet route advertisement to a peer client's control handler.
    #[cfg(feature = "vnet")]
    VnetRouteAdvertiseForward {
        msg: VnetRouteAdvertise,
    },
    /// Forward a vnet route removal to a peer client's control handler.
    #[cfg(feature = "vnet")]
    VnetRouteRemoveForward {
        msg: VnetRouteRemove,
    },
}

/// Per-client pool statistics, shared between the control handler
/// and Prometheus scrape / admin API threads.
#[derive(Debug, Default)]
pub struct PoolStats {
    pub pool_size: AtomicI64,
    pub pending_requests: AtomicI64,
}

#[derive(Debug, Clone)]
pub struct ControlTx {
    pub tx: mpsc::Sender<InternalMsg>,
    pub client_addr: Option<SocketAddr>,
    pub login_time: Instant,
    /// Absolute Unix epoch timestamp of login, for dashboard v2 API.
    pub login_time_unix: i64,
    pub pool_stats: Arc<PoolStats>,
    pub user: String,
    /// Monotonically increasing control generation ID.
    /// Distinguished old vs new control connections with the same run_id.
    pub control_id: u64,
    /// Negotiated UDPPacket codec (`"binary-v1"` or empty) for this control
    /// session (Go frp v0.71.0 sessionCtx.UDPPacketCodec). Used by SUDP
    /// visitor routing to inherit the provider's packet codec (Go
    /// `admitVisitorByRunID`) and by proxy registration metadata.
    pub udp_packet_codec: String,
    /// Wire protocol of this control session (true = v2). Go frp v0.71.0
    /// enforces that work connections and run_id-bearing visitor connections
    /// use the same wire protocol as the control they reference.
    pub wire_v2: bool,
    /// Set by a superseding login (same run_id) whose Shutdown message could
    /// not be delivered through a full internal channel: the old control
    /// handler checks this at its loop top and exits as soon as it is free,
    /// so cleanup (registrations, bridges, conn_semaphore) runs at wedge-end
    /// instead of after the heartbeat timeout (round-7 review finding).
    pub superseded: Arc<AtomicBool>,
}

/// Hot-reloadable server configuration subset, updated atomically on SIGUSR1.
#[derive(Debug, Clone)]
pub struct ReloadableState {
    pub auth_cfg: Arc<AuthConfig>,
    pub encryption_key: [u8; 16],
    pub allow_ports: Arc<Vec<frp_core::config::PortsRange>>,
    pub additional_auth_scopes: Vec<String>,
}

/// Aggregate work-conn pool metrics, read by Prometheus / admin API.
#[derive(Debug, Default)]
pub struct PoolMetrics {
    pub hits: AtomicU64,
    pub misses: AtomicU64,
    pub drops: AtomicU64,
    // (pooled-conn idle timeout was removed 2026-08-09, audit D2-3: never
    // wired from config, Go parity keeps pooled conns alive; the field and
    // its consumer were dead code.)
}

/// Result of a TCP group join query.
///
/// Mirrors Go frp `server/group/tcp.go` `TCPGroup.Listen` validation:
/// the first member creates the group with its params (no validation —
/// first-wins), later members are validated in Go's check order and
/// rejected on mismatch (Go error texts from `server/group/group.go`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum GroupPortQuery {
    /// Group exists and this member's params match — the shared port.
    Matched(u16),
    /// No group with this name exists — the caller creates it.
    NotFound,
    /// Group exists but a param differs — Go rejects the registration with
    /// the carried error text.
    Mismatch(&'static str),
}

/// State for a TCP group's shared listener.
pub(crate) struct TcpGroupEntry {
    /// The REAL port the shared listener is bound on — Go `realPort`
    /// (server/group/tcp.go: the first member's `portManager.Acquire`
    /// result, auto-assigned when the first member declared 0). Every
    /// member's ProxyInfo reports this port.
    pub port: u16,
    /// The FIRST member's DECLARED remote port — Go `tg.port`
    /// (tcp.go:83 `tg.port = port`, the declared value; an auto-assign
    /// declaration stays 0). Later members must declare the SAME value:
    /// Go's join check is `tg.port != port` on the DECLARED numbers, no
    /// zero exemption — a member declaring an explicit port cannot join a
    /// group whose first member auto-assigned, even if the numbers happen
    /// to coincide.
    pub declared_port: u16,
    pub group_key: String,
    pub bind_addr: String,
    /// Shared listener task handle. None when stopped.
    #[allow(dead_code)]
    pub handle: Option<tokio::task::JoinHandle<()>>,
    pub cancel_token: CancellationToken,
}

/// TCP group shared listener management (Go frp dev compat).
/// Groups of TCP proxies share a single listener port with round-robin
/// dispatch across group members. The first proxy to register in a group
/// creates the shared listener; subsequent members reuse the port.
pub(crate) struct TcpGroupCtl {
    groups: RwLock<HashMap<String, TcpGroupEntry>>,
}

impl TcpGroupCtl {
    pub fn new() -> Self {
        Self {
            groups: RwLock::new(HashMap::new()),
        }
    }

    /// Query an existing group, validating that params match (Go frp
    /// `server/group/tcp.go` `TCPGroup.Listen` check order: addr →
    /// port → group_key). `NotFound` and each mismatch kind are
    /// distinguished so callers reject with the Go error text instead of
    /// silently falling through to group-create (F5 review finding).
    /// `declared_port` is the JOINING member's DECLARED remote port (0 =
    /// auto-assign): Go compares declared-vs-declared
    /// (`tg.port != port`, tcp.go:111-113) with NO zero exemption — a
    /// group whose first member declared an explicit port rejects an
    /// auto-assign joiner and vice versa. The matched entry's REAL bound
    /// port is returned for the joiner's ProxyInfo.
    pub async fn get_group_port(
        &self,
        group: &str,
        group_key: &str,
        declared_port: u16,
        bind_addr: &str,
    ) -> GroupPortQuery {
        let groups = self.groups.read().await;
        let Some(entry) = groups.get(group) else {
            return GroupPortQuery::NotFound;
        };
        // Go: `tg.group != group || tg.addr != addr` → ErrGroupParamsInvalid.
        // (group is the lookup key here, so only addr can differ.)
        if entry.bind_addr != bind_addr {
            return GroupPortQuery::Mismatch("group params invalid");
        }
        // Go: `tg.port != port` (DECLARED numbers) → ErrGroupDifferentPort.
        if entry.declared_port != declared_port {
            return GroupPortQuery::Mismatch("group should have same remote port");
        }
        // Go: `tg.groupKey != groupKey` → ErrGroupAuthFailed.
        if entry.group_key != group_key {
            return GroupPortQuery::Mismatch("group auth failed");
        }
        GroupPortQuery::Matched(entry.port)
    }

    /// Register a new TCP group. Returns Err if group already exists.
    /// `port` is the REAL bound port of the shared listener (Go
    /// `realPort`); `declared_port` the first member's DECLARED remote port
    /// (Go `tg.port` — 0 when it auto-assigned, and the value later
    /// members must declare to join).
    #[allow(clippy::too_many_arguments)] // mirrors the register_member signature shape
    pub async fn create_group(
        &self,
        group: &str,
        group_key: &str,
        port: u16,
        declared_port: u16,
        bind_addr: &str,
        handle: tokio::task::JoinHandle<()>,
        cancel_token: CancellationToken,
    ) -> Result<(), String> {
        let mut groups = self.groups.write().await;
        if groups.contains_key(group) {
            return Err(format!("TCP group '{}' already exists", group));
        }
        groups.insert(
            group.to_string(),
            TcpGroupEntry {
                port,
                declared_port,
                group_key: group_key.to_string(),
                bind_addr: bind_addr.to_string(),
                handle: Some(handle),
                cancel_token,
            },
        );
        Ok(())
    }

    /// Remove a group and stop its shared listener.
    /// Returns the port that was used by the group, if any.
    pub async fn remove_group(&self, group: &str) {
        let mut groups = self.groups.write().await;
        if let Some(entry) = groups.remove(group) {
            // Cancel the shared listener
            entry.cancel_token.cancel();
        }
    }

    /// Check if a group exists and has a running listener.
    #[allow(dead_code)]
    pub async fn group_exists(&self, group: &str) -> bool {
        self.groups.read().await.contains_key(group)
    }

    /// Get the port for a group, if it exists.
    #[allow(dead_code)]
    pub async fn group_port(&self, group: &str) -> Option<u16> {
        self.groups.read().await.get(group).map(|e| e.port)
    }
}

/// OIDC verification state.
pub struct OidcState {
    pub verifier: Option<Arc<OidcVerifier>>,
    /// run_id -> (verified subject, control generation)
    pub subjects: Arc<RwLock<HashMap<String, (String, u64)>>>,
}

/// XTCP NAT-hole-punch coordination state.
pub struct XtcpState {
    pub nat_hole: Arc<Controller>,
    /// Key: `proxy_name` (unique per ProxyManager — no collision when
    /// multiple STCP/XTCP proxies share the same secret key).
    /// Value: `raw_sk` — used for fallback auth during the
    /// NewVisitorConn-before-registration race window.
    ///
    /// DashMap (like `run_id_to_ctl_tx`): the per-NewVisitorConn lookup is
    /// lock-free and never queues behind STCP registration/unregister
    /// writes (a tokio RwLock is writer-fair, so visitor-lookup readers
    /// could serialize behind sk_index writes).
    pub sk_index: Arc<DashMap<String, String>>,
}

/// Token bucket rate limiter for connection accept loops.
///
/// Lock-free: a single `AtomicU64` packs the limiter state as
/// `(elapsed_ms_since_process_start << 32) | tokens_fixed_point`, so
/// concurrent accept loops CAS-refill without contending on one shared
/// mutex (no cache-line bouncing under high connection churn). Best-effort
/// semantics — `Ordering::Relaxed` is fine for a rate limiter. Zero
/// allocation per check.
pub struct RateLimiter {
    /// Tokens per second; 0.0 = unlimited.
    rate: f64,
    /// Max tokens that can accumulate (never changes after `new`).
    burst: u32,
    state: AtomicU64,
}

/// Fixed-point scale: 1 token = 1000 units. burst ≤ 1024 → 1,024,000 units
/// < u32::MAX, so the low 32 bits of the packed state never overflow.
const SCALE: u64 = 1000;

/// Process-start epoch for the high-32-bit relative timestamps.
static EPOCH: LazyLock<Instant> = LazyLock::new(Instant::now);

/// Per-run_id lifecycle mutex plus the number of live lifecycle participants.
///
/// A control login or an active control handler holds one reference while it
/// participates in the run_id lifecycle. The map entry is removed once the
/// last reference drops, so reconnect churn cannot grow `run_mu_map`
/// without bound while in-flight logins still inherit the same mutex.
pub struct RunMuEntry {
    mu: Arc<tokio::sync::Mutex<()>>,
    refs: AtomicUsize,
}

/// RAII reference to a per-run_id lifecycle mutex.
///
/// Dropping the last guard removes the entry from `run_mu_map` (and thus the
/// stored `Arc<Mutex<()>>`), but any in-flight login or active control that
/// already acquired the entry keeps using the same mutex for the remainder of
/// its lifecycle transition.
pub struct RunMuGuard {
    map: Arc<std::sync::Mutex<HashMap<String, Arc<RunMuEntry>>>>,
    run_id: String,
    entry: Arc<RunMuEntry>,
}

impl Drop for RunMuGuard {
    fn drop(&mut self) {
        let mut map = self.map.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(entry) = map.get(&self.run_id) {
            if Arc::ptr_eq(entry, &self.entry)
                && entry.refs.fetch_sub(1, AtomicOrdering::SeqCst) == 1
            {
                map.remove(&self.run_id);
            }
        }
    }
}

impl RateLimiter {
    /// `max_per_sec`: 0 = unlimited. Burst = min(max_per_sec, 1024).
    pub fn new(max_per_sec: u32) -> Self {
        let rate = max_per_sec as f64;
        let burst = if rate > 0.0 {
            rate.min(1024.0) as u32
        } else {
            0
        };
        Self {
            rate,
            burst,
            state: AtomicU64::new(burst as u64 * SCALE),
        }
    }

    /// Configured rate in tokens per second (0 = unlimited).
    pub fn rate(&self) -> f64 {
        self.rate
    }

    /// Try to consume one token. Returns `Ok(())` if allowed, or the
    /// duration to wait before a token becomes available.
    ///
    /// Lock-free CAS loop: read the packed state, compute the refilled token
    /// balance from elapsed seconds, then CAS the updated state. On CAS
    /// failure another thread won the race, so the loop retries with the
    /// fresh state.
    pub fn try_acquire(&self) -> Result<(), Duration> {
        if self.rate == 0.0 {
            return Ok(());
        }
        // Millisecond-resolution relative timestamp (u32). wrapping_sub treats
        // (now, last) as a mod-2^32 ring, so the 49.7-day wrap of the ms
        // counter is handled correctly as long as no single gap between two
        // samples exceeds ~24.8 days (2^31 ms) — always true in practice.
        let now_ms = EPOCH.elapsed().as_millis() as u32;
        loop {
            let state = self.state.load(AtomicOrdering::Relaxed);
            let last_ms = (state >> 32) as u32;
            let tokens = state & 0xFFFF_FFFF;
            let elapsed_secs = now_ms.wrapping_sub(last_ms) as f64 / 1000.0;
            let new_tokens = (tokens as f64 + elapsed_secs * self.rate * SCALE as f64)
                .min(self.burst as f64 * SCALE as f64) as u64;
            if new_tokens >= SCALE {
                let next = ((now_ms as u64) << 32) | (new_tokens - SCALE);
                if self
                    .state
                    .compare_exchange(
                        state,
                        next,
                        AtomicOrdering::Relaxed,
                        AtomicOrdering::Relaxed,
                    )
                    .is_ok()
                {
                    return Ok(());
                }
                // CAS failed → another thread refilled; retry.
            } else {
                // Time until one token (SCALE units) refills.
                let wait = Duration::from_secs_f64(
                    (SCALE as f64 - new_tokens as f64) / (self.rate * SCALE as f64),
                );
                return Err(wait);
            }
        }
    }
}

/// (proxy_name) → (port, is_udp, closed_at) for the 24h port reservation.
pub type PortReservationMap = std::collections::HashMap<String, (u16, bool, std::time::Instant)>;

/// HTTP/HTTPS group shared-route load balancing (Go frp v0.71.0
/// `server/group/http.go` HTTPGroupController). Group members share one
/// vhost route; HTTP requests hitting the route are dispatched round-robin
/// across the members (Go `HTTPGroup.chooseEndpoint`).
///
/// The first member to register creates the group and (through
/// `register_http_vhost`/`register_https_vhost`) the shared vhost route;
/// subsequent members only join the member list after the group_key and
/// kind-specific routing params match: http groups compare
/// domain/location/route_by_http_user (Go HTTPGroup.Register) while https
/// groups compare the domain ONLY (Go HTTPSGroup.Listen — audit round 8,
/// F5). Go keeps the two kinds in SEPARATE controllers (HTTPGroupController
/// on the httpVhostRouter, HTTPSGroupController on the httpsMuxer —
/// server/service.go), so an http group "grp" and an https group "grp"
/// coexist without conflict; the frp-rs registry keys on (group name, kind)
/// to mirror that (the kind is the key, not a struct field).
pub(crate) struct HttpGroup {
    group_key: String,
    domain: String,
    location: String,
    route_by_http_user: String,
    /// Member proxy names, in registration order (round-robin).
    members: RwLock<Vec<String>>,
    /// Round-robin cursor (Go `atomic.Uint64` index).
    index: AtomicU64,
    /// The FIRST member to register — it owns the shared vhost route
    /// (vhost_manager's by_proxy index keys on this name). When the group
    /// empties, the route must be unregistered with THIS name, not the
    /// last member that happened to leave.
    route_owner: String,
}

pub(crate) struct HttpGroupController {
    /// Keyed by (group name, is_https): Go keeps HTTP and HTTPS groups in
    /// separate controllers, so the same group NAME may exist in both kinds
    /// at once (server/group/http.go + https.go, wired in server/service.go
    /// on the httpVhostRouter and the httpsMuxer respectively).
    groups: RwLock<HashMap<(String, bool), Arc<HttpGroup>>>,
}

impl HttpGroupController {
    pub fn new() -> Self {
        Self {
            groups: RwLock::new(HashMap::new()),
        }
    }

    /// Register an HTTP-kind group member. The FIRST member creates the
    /// group (the caller then registers the shared vhost route); subsequent
    /// members are validated against the existing group (Go
    /// HTTPGroup.Register): routing params must be identical
    /// (`ErrGroupParamsInvalid`) and group_key must match
    /// (`ErrGroupAuthFailed`) — both texts verbatim, Go's check order
    /// (http.go:96-109). A duplicate member registration is
    /// `ErrProxyRepeated` ("group proxy repeated", http.go:111-113) — the
    /// text verbatim, checked after the join validations exactly like Go.
    /// Returns `(group, is_first_member)` on success, Err(String) on
    /// mismatch/repeat. The caller registers the shared vhost route only for
    /// the first member.
    /// Lock ordering: `groups` write lock is always acquired BEFORE any
    /// `members` lock (never the reverse), so nested awaits cannot deadlock.
    pub async fn register_member(
        &self,
        group: &str,
        group_key: &str,
        domain: &str,
        location: &str,
        route_by_http_user: &str,
        proxy_name: &str,
    ) -> Result<(Arc<HttpGroup>, bool), String> {
        let mut groups = self.groups.write().await;
        if let Some(g) = groups.get(&(group.to_string(), false)) {
            // Existing http-kind group: validate the routing params (Go
            // ErrGroupParamsInvalid).
            if g.domain != domain
                || g.location != location
                || g.route_by_http_user != route_by_http_user
            {
                return Err("group params invalid".to_string());
            }
            if g.group_key != group_key {
                return Err("group auth failed".to_string());
            }
            let mut members = g.members.write().await;
            if members.iter().any(|m| m == proxy_name) {
                return Err("group proxy repeated".to_string());
            }
            members.push(proxy_name.to_string());
            return Ok((g.clone(), false));
        }
        let g = Arc::new(HttpGroup {
            group_key: group_key.to_string(),
            domain: domain.to_string(),
            location: location.to_string(),
            route_by_http_user: route_by_http_user.to_string(),
            members: RwLock::new(vec![proxy_name.to_string()]),
            index: AtomicU64::new(0),
            route_owner: proxy_name.to_string(),
        });
        groups.insert((group.to_string(), false), g.clone());
        Ok((g, true))
    }

    /// Register an HTTPS group member (Go frp v0.71.0 `HTTPSGroup.Listen`,
    /// server/group/https.go). HTTPS group membership compares ONLY the
    /// group name and domain — the route config's location and
    /// route_by_http_user never participate (an https proxy carries no
    /// locations and Go's listenForDomain builds an empty RouteConfig, so
    /// rubu is meaningless). Validation ORDER matches Go: params (domain)
    /// before the key. Errors are the Go constants verbatim
    /// (`ErrGroupParamsInvalid` / `ErrGroupAuthFailed`,
    /// server/group/group.go:22-26) — the caller sends them to the client
    /// unconditionally. Repeated identical same-domain registration (a
    /// proxy listing the same custom_domain twice) is accepted; the member
    /// is added once.
    pub async fn register_https_member(
        &self,
        group: &str,
        group_key: &str,
        domain: &str,
        proxy_name: &str,
    ) -> Result<(Arc<HttpGroup>, bool), String> {
        let mut groups = self.groups.write().await;
        if let Some(g) = groups.get(&(group.to_string(), true)) {
            // Go HTTPSGroup.Listen (https.go): route config in the same
            // group must be equal — and ONLY the domain is part of it.
            if g.domain != domain {
                return Err("group params invalid".to_string());
            }
            if g.group_key != group_key {
                return Err("group auth failed".to_string());
            }
            let mut members = g.members.write().await;
            if !members.iter().any(|m| m == proxy_name) {
                members.push(proxy_name.to_string());
            }
            return Ok((g.clone(), false));
        }
        let g = Arc::new(HttpGroup {
            group_key: group_key.to_string(),
            domain: domain.to_string(),
            location: String::new(),
            route_by_http_user: String::new(),
            members: RwLock::new(vec![proxy_name.to_string()]),
            index: AtomicU64::new(0),
            route_owner: proxy_name.to_string(),
        });
        groups.insert((group.to_string(), true), g.clone());
        Ok((g, true))
    }

    /// Remove a member. Returns `Some(route_owner)` when the group became
    /// empty — the caller must then drop the shared vhost route using the
    /// OWNER's name (the first member registered it) and the group is
    /// removed. Returns `None` when the group still has members or did not
    /// exist. `is_https` selects the kind registry (an http and an https
    /// group may share the name).
    pub async fn unregister_member(
        &self,
        group: &str,
        proxy_name: &str,
        is_https: bool,
    ) -> Option<String> {
        let mut groups = self.groups.write().await;
        let key = (group.to_string(), is_https);
        let g = groups.get(&key)?;
        let empty = {
            let mut members = g.members.write().await;
            members.retain(|m| m != proxy_name);
            members.is_empty()
        };
        if empty {
            let owner = g.route_owner.clone();
            groups.remove(&key);
            Some(owner)
        } else {
            None
        }
    }

    /// Round-robin pick a member proxy name (Go HTTPGroup.chooseEndpoint /
    /// HTTPSGroup listener dispatch). Returns None when the group has no
    /// members. `is_https` selects the kind registry.
    pub async fn choose_endpoint(&self, group: &str, is_https: bool) -> Option<String> {
        let groups = self.groups.read().await;
        let g = groups.get(&(group.to_string(), is_https))?;
        let members = g.members.read().await;
        if members.is_empty() {
            return None;
        }
        let idx = g.index.fetch_add(1, AtomicOrdering::Relaxed) as usize % members.len();
        Some(members[idx].clone())
    }
}

/// A TCPMux load-balancing group (Go frp v0.71.0 `group.TCPMuxGroup`): the
/// FIRST member to register creates the group and (through the caller) the
/// shared tcpmux route; subsequent members only join the member list after
/// the group_key and routing params (domain/routeByHTTPUser/httpUser/
/// httpPassword) match the first member's — Go `TCPMuxGroup.HTTPConnectListen`
/// returns `ErrGroupParamsInvalid` on param mismatch and `ErrGroupAuthFailed`
/// on group_key mismatch (both verbatim, in Go's check order: params first).
/// Accepted CONNECTs fan out to members round-robin (`choose_endpoint`).
///
/// Go parity note: Go's group stores ONE (domain, routeByHTTPUser, user,
/// password) route per group name, so a same-group proxy whose second
/// domain differs from the first member's is rejected with
/// ErrGroupParamsInvalid — the caller enforces `domains.len() == 1` up
/// front (same as the HTTP group path).
#[derive(Debug)]
pub(crate) struct TcpMuxGroup {
    group_key: String,
    domain: String,
    route_by_http_user: String,
    http_user: String,
    http_pwd: String,
    /// Member proxy names, in registration order (round-robin).
    members: RwLock<Vec<String>>,
    /// Round-robin cursor (Go `atomic.Uint64` index).
    index: AtomicU64,
    /// The FIRST member to register — it owns the shared tcpmux route
    /// (tcpmux_manager's by_proxy index keys on this name). When the group
    /// empties, the route must be unregistered with THIS name, not the
    /// last member that happened to leave.
    route_owner: String,
}

pub(crate) struct TcpMuxGroupController {
    groups: RwLock<HashMap<String, Arc<TcpMuxGroup>>>,
}

impl TcpMuxGroupController {
    pub fn new() -> Self {
        Self {
            groups: RwLock::new(HashMap::new()),
        }
    }

    /// Register a group member. The FIRST member creates the group (the
    /// caller then registers the shared tcpmux route); subsequent members
    /// are validated against the existing group (Go TCPMuxGroup
    /// HTTPConnectListen): routing params must be identical
    /// (`ErrGroupParamsInvalid` "group params invalid") and group_key must
    /// match (`ErrGroupAuthFailed` "group auth failed") — both texts
    /// verbatim, checked in Go's order.
    /// Returns `(group, is_first_member)` on success, Err(String) on
    /// mismatch/repeat. The caller registers the shared tcpmux route only
    /// for the first member.
    /// Lock ordering: `groups` write lock is always acquired BEFORE any
    /// `members` lock (never the reverse), so nested awaits cannot deadlock.
    #[allow(clippy::too_many_arguments)] // mirrors HttpGroupController::register_member
    pub async fn register_member(
        &self,
        group: &str,
        group_key: &str,
        domain: &str,
        route_by_http_user: &str,
        http_user: &str,
        http_pwd: &str,
        proxy_name: &str,
    ) -> Result<(Arc<TcpMuxGroup>, bool), String> {
        let mut groups = self.groups.write().await;
        if let Some(g) = groups.get(group) {
            // Existing group: validate routing params first, then the
            // group_key — Go TCPMuxGroup.HTTPConnectListen check order
            // (group/tcpmux.go: params → ErrGroupParamsInvalid, then key →
            // ErrGroupAuthFailed). domain/route_by_http_user equality is
            // structural here (the caller routes one domain through one
            // bucket), but checked anyway so the guard stands alone.
            if g.domain != domain
                || g.route_by_http_user != route_by_http_user
                || g.http_user != http_user
                || g.http_pwd != http_pwd
            {
                return Err("group params invalid".to_string());
            }
            if g.group_key != group_key {
                return Err("group auth failed".to_string());
            }
            let mut members = g.members.write().await;
            if members.iter().any(|m| m == proxy_name) {
                return Err(format!(
                    "proxy [{}] is already a member of tcpmux group [{}]",
                    proxy_name, group
                ));
            }
            members.push(proxy_name.to_string());
            return Ok((g.clone(), false));
        }
        let g = Arc::new(TcpMuxGroup {
            group_key: group_key.to_string(),
            domain: domain.to_string(),
            route_by_http_user: route_by_http_user.to_string(),
            http_user: http_user.to_string(),
            http_pwd: http_pwd.to_string(),
            members: RwLock::new(vec![proxy_name.to_string()]),
            index: AtomicU64::new(0),
            route_owner: proxy_name.to_string(),
        });
        groups.insert(group.to_string(), g.clone());
        Ok((g, true))
    }

    /// Remove a member. Returns `Some(route_owner)` when the group became
    /// empty — the caller must then drop the shared tcpmux route using the
    /// OWNER's name (the first member registered it) and the group is
    /// removed. Returns `None` when the group still has members or did not
    /// exist.
    pub async fn unregister_member(&self, group: &str, proxy_name: &str) -> Option<String> {
        let mut groups = self.groups.write().await;
        let g = groups.get(group)?;
        let empty = {
            let mut members = g.members.write().await;
            members.retain(|m| m != proxy_name);
            members.is_empty()
        };
        if empty {
            let owner = g.route_owner.clone();
            groups.remove(group);
            Some(owner)
        } else {
            None
        }
    }

    /// Round-robin pick a member proxy name (Go TCPMuxGroup fan-out).
    /// Returns None when the group has no members.
    pub async fn choose_endpoint(&self, group: &str) -> Option<String> {
        let groups = self.groups.read().await;
        let g = groups.get(group)?;
        let members = g.members.read().await;
        if members.is_empty() {
            return None;
        }
        let idx = g.index.fetch_add(1, AtomicOrdering::Relaxed) as usize % members.len();
        Some(members[idx].clone())
    }
}

// ---------------------------------------------------------------
// Replay-detection table (login timestamp → run_ids)
// ---------------------------------------------------------------

/// Threshold separating seconds-precision (Go frpc) from
/// milliseconds-precision (Rust frpc) login timestamps. Keys < this
/// are seconds, keys >= this are milliseconds.
pub const MS_EPOCH: i64 = 1_000_000_000_000;

/// Cap on distinct run_ids recorded per timestamp in the replay-detection
/// table. Bounds memory for a single timestamp key (a token-holder could
/// otherwise inject unique run_ids within one second and grow the table
/// without bound). On cap-hit the OLDEST run_id is evicted to admit the
/// new one (F3) — rejecting on cap-hit would lock out a legitimate
/// same-run_id reconnect at a flooded timestamp.
pub const MAX_ENTRIES_PER_TIMESTAMP: usize = 100;

/// Global cap on replay-detection table entries (defense-in-depth against
/// token-reachable memory growth). On cap-hit whole oldest timestamp keys
/// are evicted until under the cap (F4), so in-window timestamps keep
/// their duplicate detection — the previous behavior degraded dedup to
/// freshness-only for ALL clients.
pub const MAX_TOTAL_REPLAY_ENTRIES: usize = 100_000;

/// Outcome of recording a (timestamp, run_id) pair.
#[derive(Debug, PartialEq, Eq)]
pub enum ReplayCheck {
    /// New (ts, run_id) pair recorded — the login may proceed.
    Admitted,
    /// run_id already logged at an identical seconds-precision timestamp.
    /// Go frpc reuses its run_id and sends seconds keys, so a reconnect
    /// within the same wall-clock second is indistinguishable from a
    /// replay; the caller admits it (the freshness window still bounds
    /// real replays).
    DuplicateSecondsPrecision,
    /// run_id already logged at an identical ms-precision timestamp — a
    /// genuine replay (Rust frpc sends ms keys); the caller rejects.
    Replay,
}

/// Timestamp-indexed run_id log for login replay-attack detection
/// (`AppState::used_timestamps`).
///
/// The per-timestamp value is an insertion-ordered `Vec` (not a set) so
/// the OLDEST run_id can be evicted deterministically when the
/// per-timestamp cap is hit (F3). Both memory bounds evict instead of
/// reject — a login is only ever refused here for an identical
/// ms-precision (run_id, ts) replay.
///
/// `total` is maintained incrementally (increment on insert, decrement on
/// prune/evict) so the global cap check is O(1) instead of a full-map
/// sum, and cleanup is a leading-key drain — BTreeMap is ordered by
/// timestamp, so expired keys are always the smallest keys — instead of
/// a full-map `retain` scan (F4).
#[derive(Default)]
pub struct ReplayTable {
    map: std::collections::BTreeMap<i64, Vec<String>>,
    /// Running count of run_id entries across all timestamps.
    total: usize,
}

impl ReplayTable {
    pub fn new() -> Self {
        Self {
            map: std::collections::BTreeMap::new(),
            total: 0,
        }
    }

    /// Number of run_id entries currently tracked across all timestamps.
    pub fn total(&self) -> usize {
        self.total
    }

    /// Prune timestamp keys outside the freshness window.
    ///
    /// O(expired keys) per call: timestamps are the map keys, so expired
    /// keys are always the smallest ones. Two precision domains sort
    /// together (seconds keys < `MS_EPOCH` < ms keys), so a live seconds
    /// key does NOT imply the ms keys after it are live — each domain is
    /// drained separately. Returns the number of entries pruned.
    pub fn prune_expired(&mut self, now_ms: i64, timeout_secs: i64) -> usize {
        if timeout_secs <= 0 {
            return 0;
        }
        let threshold_ms = now_ms.saturating_sub(timeout_secs.saturating_mul(1000));
        let threshold_s = (now_ms / 1000).saturating_sub(timeout_secs);
        let before = self.total;
        // Seconds-precision keys (Go frpc) form a prefix of the map.
        while let Some((&k, _)) = self.map.first_key_value() {
            if k >= MS_EPOCH || k >= threshold_s {
                break;
            }
            self.total -= self.map.remove(&k).map_or(0, |v| v.len());
        }
        // ms-precision keys (Rust frpc) form a prefix of [MS_EPOCH, +∞),
        // so a live seconds key left in place by the pass above is
        // skipped without removal.
        while let Some((&k, _)) = self.map.range(MS_EPOCH..).next() {
            if k >= threshold_ms {
                break;
            }
            self.total -= self.map.remove(&k).map_or(0, |v| v.len());
        }
        // Round 6 (LOW B7): FUTURE timestamps sort to the map tail and
        // were never pruned — an attacker recording now+window keys would
        // park entries that outlive every legitimate one, pushing real
        // keys toward the global cap's eviction order and shrinking their
        // dedup coverage. Prune anything ahead of now in each precision
        // domain. Anything further than `timeout` ahead is already
        // rejected by validate_timestamp_freshness before record; a
        // slightly-ahead key from a fast client clock costs only its own
        // dedup coverage (the login itself is unaffected).
        let future_s = (now_ms / 1000).saturating_add(1);
        let future_ms = now_ms.saturating_add(1);
        while let Some((&k, _)) = self.map.range(future_s..MS_EPOCH).next() {
            self.total -= self.map.remove(&k).map_or(0, |v| v.len());
        }
        while let Some((&k, _)) = self.map.range(future_ms..).next() {
            self.total -= self.map.remove(&k).map_or(0, |v| v.len());
        }
        before - self.total
    }

    /// Record a (timestamp, run_id) pair for duplicate detection.
    ///
    /// Neither memory bound rejects a login:
    /// - Global cap (`MAX_TOTAL_REPLAY_ENTRIES`): whole oldest timestamp
    ///   keys are evicted until there is room (F4).
    /// - Per-timestamp cap (`MAX_ENTRIES_PER_TIMESTAMP`): the OLDEST
    ///   run_id is evicted to admit the new one (F3) — the evicted entry
    ///   loses dedup coverage only.
    pub fn record(&mut self, ts: i64, run_id: &str) -> ReplayCheck {
        // Duplicate check FIRST: a duplicate login must never evict other
        // entries to make room for itself — that would discard innocent
        // run_ids' dedup coverage, and under the global cap would let an
        // attacker replaying one (ts, run_id) pair repeatedly evict fresh
        // keys, shrinking the replay window.
        if let Some(entry) = self.map.get(&ts) {
            if entry.iter().any(|r| r == run_id) {
                return if ts < MS_EPOCH {
                    ReplayCheck::DuplicateSecondsPrecision
                } else {
                    ReplayCheck::Replay
                };
            }
        }
        // Global cap: evict whole oldest keys until there is room. The
        // caller prunes first, so the oldest remaining keys are the
        // freshest possible eviction targets.
        while self.total >= MAX_TOTAL_REPLAY_ENTRIES {
            let Some((&oldest_ts, _)) = self.map.first_key_value() else {
                break;
            };
            self.total -= self.map.remove(&oldest_ts).map_or(0, |v| v.len());
        }
        let entry = self.map.entry(ts).or_default();
        // Per-timestamp cap: evict the oldest run_id (insertion-ordered
        // Vec → index 0) and admit the new one.
        if entry.len() >= MAX_ENTRIES_PER_TIMESTAMP {
            entry.remove(0);
            self.total -= 1;
        }
        entry.push(run_id.to_string());
        self.total += 1;
        ReplayCheck::Admitted
    }
}

/// Shared state for cross-task communication
pub struct AppState {
    pub proxy_manager: Arc<ProxyManager>,
    /// (proxy_name) → (port, is_udp, closed_at) for the 24h port reservation.
    pub port_reservations: Arc<RwLock<PortReservationMap>>,
    /// Hot-reloadable config (auth, encryption, allow_ports).
    /// Uses std::sync::RwLock — blocking read has no async overhead.
    /// Writes only happen on SIGUSR1 reload (vanishingly rare).
    pub reloadable: Arc<std::sync::RwLock<ReloadableState>>,
    pub used_ports: Arc<RwLock<std::collections::HashSet<u16>>>,
    /// Separate UDP port tracking (Go frp compat). TCP port 8080 can coexist
    /// with UDP port 8080 — Go has separate TCPPortManager and UDPPortManager.
    pub used_udp_ports: Arc<RwLock<std::collections::HashSet<u16>>>,
    /// (run_id) → control-channel sender. DashMap: sharded locks, so the
    /// per-work-conn lookup on every dispatch no longer contends on one
    /// global read lock.
    pub run_id_to_ctl_tx: Arc<DashMap<String, ControlTx>>,
    /// Client registry tracking connected frpc instances with metadata.
    pub client_registry: Arc<ClientRegistry>,
    /// Monotonically increasing counter for control generation IDs.
    /// Starts at 1; 0 is reserved as the "no generation" sentinel in
    /// `unregister_control`'s legacy remove path. Never reset — a wrap back
    /// to 0 (after 2^64 logins) would over-match there.
    pub control_id_counter: AtomicU64,
    /// Per-runID mutex for serializing control lifecycle transitions
    /// (Add/Activate/completeLogin/Remove). Inherited from old to new control
    /// to prevent concurrent lifecycle operations for the same run_id.
    pub run_mu_map: Arc<std::sync::Mutex<HashMap<String, Arc<RunMuEntry>>>>,
    pub proxy_bind_addr: String,
    pub vhost_manager: Arc<VhostManager>,
    /// Accounting counter for HTTPS proxies with registered SNI routes.
    /// NOTE (audit round 6d): the main-port SNI sniff it used to gate was
    /// removed in round 13 (Go reads only the 0x17/0x16 TLS marker on the
    /// main port; https SNI routing lives on vhost_https_port), so no
    /// production reader remains — the counter is retained for tests.
    /// Kept monotone-asymmetric by design: https GROUP members return
    /// before the increment yet are decremented on removal (saturating,
    /// see `dec_https_proxy_count`), so it can sit at 0 while https
    /// proxies exist.
    pub https_proxy_count: AtomicUsize,
    pub vhost_http_port: u16,
    pub xtcp: XtcpState,
    pub oidc: OidcState,
    pub dashboard_start: std::time::Instant,
    pub sub_domain_host: String,
    pub tcp_mux: bool,
    pub tcp_mux_keepalive: i64,
    pub tcp_keepalive: i64,
    /// SO_SNDBUF for accepted sockets (0 = OS default). frp-rs extension.
    pub tcp_send_buffer_size: u32,
    /// SO_RCVBUF for accepted sockets (0 = OS default). frp-rs extension.
    pub tcp_recv_buffer_size: u32,
    pub heartbeat_timeout: i64,
    pub udp_packet_size: usize,
    pub tls_only: bool,
    /// Shared UDP port for SUDP proxies. When > 0, all SUDP proxies
    /// use this port instead of their individual remote_port.
    pub sudp_port: u16,
    /// TCP group shared listener management (Go frp dev compat).
    /// Groups proxies that share the same remote port with round-robin dispatch.
    pub(crate) tcp_group_ctl: TcpGroupCtl,
    /// HTTP/HTTPS group shared-route load balancing (Go frp v0.71.0
    /// server/group/http.go). Groups of http/https proxies share one vhost
    /// route; requests are dispatched round-robin across members.
    pub(crate) http_group_ctl: HttpGroupController,
    /// TCPMux load-balancing groups (Go frp group.TCPMuxGroupController):
    /// multi-client tcpmux proxies sharing one domain route, fanned out
    /// round-robin. Members register through `register_member`; accepted
    /// CONNECTs pick a member via `choose_endpoint` at dispatch time.
    pub(crate) tcpmux_group_ctl: TcpMuxGroupController,
    pub vhost_http_timeout: u64,
    pub user_conn_timeout: u64,
    pub tcp_mux_passthrough: bool,
    /// Custom 404 page body (HTML) from WebServerConfig.
    pub custom_404_page: String,
    /// Server-side HTTP plugin manager for lifecycle hooks.
    pub plugin_manager: Arc<crate::plugin::HttpPluginManager>,
    /// In-memory store for proxy configs submitted via dashboard Store API.
    pub proxy_config_store: Arc<RwLock<HashMap<String, frp_core::config::ProxyConfig>>>,
    /// Path to the JSON store file for proxy_config_store persistence.
    pub store_path: Option<std::path::PathBuf>,
    /// TCPMux HTTP CONNECT route table (domain → proxy mapping).
    pub tcpmux_manager: Arc<TcpMuxManager>,
    /// Per-proxy traffic metrics for dashboard API.
    pub proxy_metrics: Arc<ProxyMetricsRegistry>,
    /// Per-client proxy count limit. 0 = unlimited.
    pub max_ports_per_client: u64,
    /// Per-client TOTAL proxy-count limit (any type, not just port-using).
    /// 0 = unlimited (default, Go-relaxed). Bounds the growth of
    /// proxy_manager / vhost / tcpmux / sk_index / prometheus labels that a
    /// single authenticated client could otherwise drive without a port.
    /// Rust-only opt-in; see `ServerConfig.max_proxies_per_client`.
    pub max_proxies_per_client: u64,
    /// Per-proxy concurrent user-connection cap. 0 = unlimited (Go frp
    /// default). Bounds per-proxy connection floods (audit D2-2).
    pub max_conns_per_proxy: u64,
    /// Per-client port usage count: run_id → number of ports currently used.
    /// Incremented when a proxy registers a remote port, decremented on close.
    /// Matches Go frp's portsUsedNum tracking.
    pub client_ports_used: Arc<RwLock<std::collections::HashMap<String, u64>>>,
    /// When false (default), internal error details are not sent to clients.
    pub detailed_errors_to_client: bool,
    /// Shared TLS acceptor for hot-reload. Cert renewal tools (certbot, cert-manager)
    /// replace cert files in-place — periodic poll detects mtime changes and swaps
    /// this acceptor atomically. SIGUSR1 reload also swaps when cert paths change.
    #[cfg(feature = "tls")]
    pub tls_acceptor: Arc<std::sync::RwLock<Option<tokio_rustls::TlsAcceptor>>>,
    /// Semaphore to limit concurrent connections. None = unlimited.
    pub conn_semaphore: Option<Arc<tokio::sync::Semaphore>>,
    /// Token bucket rate limiter for the accept loop.
    /// Limits connections-per-second across all listeners.
    pub accept_rate_limiter: Arc<RateLimiter>,
    /// Per-IP failed login attempt counter: IP -> (count, window_start).
    /// Window resets after 60 seconds. Max 5 failed attempts per window.
    ///
    /// Scope (audit E1/S1): only logins from non-spoofable sources key this
    /// table — TCP/TLS/WS/QUIC, where the peer IP was authenticated by the
    /// transport handshake, plus the KCP+TLS arms (a completed rustls
    /// handshake proves the source received the server flight — review
    /// round-9 finding). PLAIN KCP-sourced frpc logins are EXEMPT: the
    /// source address of a UDP datagram is attacker-spoofable, and a fresh
    /// KCP session (new conv) delivers a full V1 wrong-token Login from the
    /// FIRST datagram (sn=0, no ACK round-trip needed), so 5 spoofed
    /// failures would hard-lock the victim IP's real logins for the 60s
    /// anchored window — refreshable ~5/min indefinitely — turning the
    /// throttle into a targeted lockout primitive. `login::authenticate`
    /// expresses this by forwarding `throttle_keyed=false` from the plain
    /// KCP accept arms (service.rs — the 4 non-TLS sites) and calling the
    /// throttle helpers with `peer = None`: no slot consumption, no pre-auth
    /// gate. The socket-layer KCP session caps (32 sessions/IP/10s, 256
    /// sessions/10s global, frp-core/src/kcp/socket.rs) remain the attempt
    /// bound on that path.
    /// SSH-gateway auth failures share this SAME table with main-port
    /// logins (ssh_gateway.rs) — TCP-sourced, not spoofable, so that is
    /// cross-surface collateral only, not a new attack.
    pub login_throttle: Arc<
        tokio::sync::Mutex<std::collections::HashMap<std::net::IpAddr, (u32, std::time::Instant)>>,
    >,
    /// Coarse-grained per-IP counter used when `login_throttle` is full:
    /// untracked IPs are still rate-limited (not unlimited) while the main
    /// table drains. Same (count, window_start) shape as `login_throttle`.
    pub login_throttle_overflow: Arc<
        tokio::sync::Mutex<std::collections::HashMap<std::net::IpAddr, (u32, std::time::Instant)>>,
    >,
    /// Timestamp-indexed run_id log for replay attack detection.
    ///
    /// Key: Unix timestamp (seconds for Go frpc, milliseconds for Rust
    /// frpc — see `MS_EPOCH`). Value: insertion-ordered run_ids that
    /// logged in at that timestamp. Duplicate (run_id, ts) pairs within
    /// the freshness window are rejected as replay attacks.
    ///
    /// Memory is bounded two ways, and neither bound rejects a login:
    /// `MAX_ENTRIES_PER_TIMESTAMP` (100) per timestamp key — on cap-hit
    /// the oldest run_id is evicted to admit the new one (F3); and
    /// `MAX_TOTAL_REPLAY_ENTRIES` (100k) globally — on cap-hit whole
    /// oldest timestamp keys are evicted (F4), so in-window timestamps
    /// keep their duplicate detection. Cleanup is a leading-key drain
    /// (O(expired keys) per login) plus an incrementally tracked total,
    /// not a full-map scan.
    ///
    /// Memory bound: at `R` logins/sec and default 90s timeout, ~90·R
    /// entries, or ~9,000 entries (~0.5 MB) at 100 QPS; hard-capped at
    /// `MAX_TOTAL_REPLAY_ENTRIES`.
    /// Protected by a tokio::sync::Mutex (async-safe).
    pub used_timestamps: tokio::sync::Mutex<ReplayTable>,
    /// CancellationToken for graceful shutdown. Cancelled on SIGTERM/SIGINT.
    /// Main accept loop and control handlers watch this to stop accepting new
    /// connections while letting existing bridge tasks drain.
    pub shutdown_token: CancellationToken,
    /// Active bridge connection counter. Incremented when a bridge task starts,
    /// decremented when it completes. The drain phase polls this counter.
    ///
    /// This counter is shared between two independent subsystems:
    /// 1. Bridge tasks (control/bridge.rs ActiveGuard RAII) — increment on start,
    ///    decrement on drop.
    /// 2. Pool idle expiry (control/pool.rs) — when the work-conn pool expires
    ///    idle connections, the associated bridge tasks drop their ActiveGuards,
    ///    which decrements this counter.
    ///
    /// During the drain phase, pool idle expiry may run concurrently with bridge
    /// task completion, causing the counter to fluctuate. The drain loop handles
    /// this by polling repeatedly (with the graceful_shutdown_timeout as a hard
    /// deadline) until the counter reaches zero or the timeout expires. Brief
    /// counter increases from new connections started just before the accept
    /// loop shut down are expected and handled.
    pub active_connections: AtomicU64,
    /// Aggregate work-conn pool metrics (hits/misses/drops).
    /// Updated atomically from control handlers, read by Prometheus /admin API.
    pub pool: PoolMetrics,
    /// Immutable snapshot of server config fields exposed via dashboard v2 API.
    /// Captured at startup; not affected by reload. Go frp v0.70.0 compat.
    pub server_config_snapshot: frp_core::config::ServerConfigSnapshot,
    /// Virtual network routing table: (virtual_net, subnet) → (run_id, proxy_name).
    /// Populated by VnetRouteAdvertise messages, used to forward VnetPacket.
    #[cfg(feature = "vnet")]
    pub vnet_routes: VnetRouteMap,
    /// Broadcast channel for admin WebSocket event stream.
    /// Capacity 1024 — each event is ~200 bytes JSON (max ~200 KiB).
    /// Slow clients get `Lagged` and receive a synthetic Error event
    /// telling them to re-sync via the REST API.
    #[cfg(feature = "dashboard")]
    pub event_tx: broadcast::Sender<crate::event::ServerEvent>,
}

impl AppState {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        auth_cfg: AuthConfig,
        proxy_bind_addr: String,
        encryption_key: [u8; 16],
        allow_ports: Vec<frp_core::config::PortsRange>,
        sub_domain_host: String,
        tcp_mux: bool,
        tcp_mux_keepalive: i64,
        tcp_keepalive: i64,
        tcp_send_buffer_size: u32,
        tcp_recv_buffer_size: u32,
        heartbeat_timeout: i64,
        udp_packet_size: usize,
        tls_only: bool,
        oidc_verifier: Option<Arc<OidcVerifier>>,
        sudp_port: u16,
        vhost_http_timeout: u64,
        user_conn_timeout: u64,
        tcp_mux_passthrough: bool,
        custom_404_page: String,
        plugin_manager: Arc<crate::plugin::HttpPluginManager>,
        max_ports_per_client: u64,
        max_conns_per_proxy: u64,
        max_proxies_per_client: u64,
        nat_hole_analysis_data_reserve_hours: u64,
        detailed_errors_to_client: bool,
        max_connections: usize,
        max_accept_rate: u32,
        server_config_snapshot: frp_core::config::ServerConfigSnapshot,
    ) -> Self {
        Self {
            proxy_manager: Arc::new(ProxyManager::new()),
            reloadable: Arc::new(std::sync::RwLock::new(ReloadableState {
                auth_cfg: Arc::new(auth_cfg.clone()),
                encryption_key,
                allow_ports: Arc::new(allow_ports),
                additional_auth_scopes: auth_cfg.additional_auth_scopes.clone(),
            })),
            used_ports: Arc::new(RwLock::new(std::collections::HashSet::new())),
            used_udp_ports: Arc::new(RwLock::new(std::collections::HashSet::new())),
            port_reservations: Arc::new(RwLock::new(PortReservationMap::new())),
            run_id_to_ctl_tx: Arc::new(DashMap::new()),
            client_registry: Arc::new(ClientRegistry::new()),
            control_id_counter: AtomicU64::new(1),
            run_mu_map: Arc::new(std::sync::Mutex::new(HashMap::new())),
            proxy_bind_addr,
            vhost_manager: Arc::new(VhostManager::new()),
            https_proxy_count: AtomicUsize::new(0),
            vhost_http_port: 0, // set by Service::run() before starting listeners
            dashboard_start: std::time::Instant::now(),
            xtcp: XtcpState {
                nat_hole: Arc::new(Controller::new(Duration::from_secs(
                    nat_hole_analysis_data_reserve_hours.saturating_mul(3600),
                ))),
                sk_index: Arc::new(DashMap::new()),
            },
            sub_domain_host,
            tcp_mux,
            tcp_mux_keepalive,
            tcp_keepalive,
            tcp_send_buffer_size,
            tcp_recv_buffer_size,
            heartbeat_timeout,
            udp_packet_size,
            tls_only,
            oidc: OidcState {
                verifier: oidc_verifier,
                subjects: Arc::new(RwLock::new(HashMap::new())),
            },
            tcpmux_manager: Arc::new(TcpMuxManager::new()),
            proxy_metrics: Arc::new(ProxyMetricsRegistry::new()),
            max_ports_per_client,
            max_conns_per_proxy,
            max_proxies_per_client,
            client_ports_used: Arc::new(RwLock::new(std::collections::HashMap::new())),
            sudp_port,
            tcp_group_ctl: TcpGroupCtl::new(),
            http_group_ctl: HttpGroupController::new(),
            tcpmux_group_ctl: TcpMuxGroupController::new(),
            vhost_http_timeout,
            user_conn_timeout,
            tcp_mux_passthrough,
            custom_404_page,
            plugin_manager,
            proxy_config_store: Arc::new(RwLock::new(HashMap::new())),
            store_path: None,
            detailed_errors_to_client,
            conn_semaphore: if max_connections > 0 {
                Some(Arc::new(tokio::sync::Semaphore::new(max_connections)))
            } else {
                None
            },
            accept_rate_limiter: Arc::new(RateLimiter::new(max_accept_rate)),
            login_throttle: Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new())),
            login_throttle_overflow: Arc::new(tokio::sync::Mutex::new(
                std::collections::HashMap::new(),
            )),
            used_timestamps: tokio::sync::Mutex::new(ReplayTable::new()),
            #[cfg(feature = "tls")]
            tls_acceptor: Arc::new(std::sync::RwLock::new(None)),
            shutdown_token: CancellationToken::new(),
            active_connections: AtomicU64::new(0),
            pool: PoolMetrics::default(),
            #[cfg(feature = "vnet")]
            vnet_routes: Arc::new(RwLock::new(HashMap::new())),
            server_config_snapshot,
            #[cfg(feature = "dashboard")]
            event_tx: broadcast::channel(1024).0,
        }
    }

    /// Check if an IP has exceeded the login attempt throttle.
    /// Returns true if the login should be allowed, false if throttled.
    ///
    /// This method atomically checks AND reserves an attempt slot within
    /// a single lock hold. Counts FAILED login attempts only — the sole
    /// caller is `throttled_login_error` (login.rs), which runs on failure
    /// paths (bad token, replay, OIDC reject). Successful logins never
    /// consume a slot, so a legitimate frpc reconnect loop is never
    /// throttled (round 6, finding B9: the comment previously claimed
    /// "counts ALL login attempts" — wrong; verified against call sites).
    /// This is acceptable because:
    /// - A successful login means the attacker knew the token — they don't
    ///   need to brute-force.
    /// - The 60s window means even a legitimate frpc restart-loop (6+
    ///   reconnects/minute) self-throttles briefly then recovers.
    /// - Counting failures-only (old design) had a TOCTOU race: concurrent
    ///   attackers all passed the check before any reached the increment.
    ///
    /// Max 5 attempts per 60-second window per IP.
    ///
    /// Also performs inline cleanup of expired entries to prevent unbounded
    /// memory growth from DDoS attacks with randomized source IPs.
    pub async fn check_login_throttle(&self, addr: std::net::SocketAddr) -> bool {
        const MAX_THROTTLE_ENTRIES: usize = 512;

        let ip = addr.ip();
        let now = std::time::Instant::now();
        let mut throttle = self.login_throttle.lock().await;

        // Cleanup: remove entries older than 90s (60s window + 30s grace).
        const CLEANUP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(90);
        throttle.retain(|_, (_, window_start)| now.duration_since(*window_start) < CLEANUP_TIMEOUT);

        // Cap: when the main table is full, fall back to a COARSE per-IP
        // counter for untracked IPs instead of either (a) rejecting every
        // new IP for up to 90s (distributed flood -> DoS of legit new
        // clients) or (b) allowing them completely unlimited (brute-force
        // bypass). The overflow bucket keeps a generous per-IP cap so a
        // distributed attacker cannot brute-force the token with zero rate
        // limiting while the table drains.
        if !throttle.contains_key(&ip) && throttle.len() >= MAX_THROTTLE_ENTRIES {
            const OVERFLOW_MAX_PER_IP: u32 = 50;
            // Overflow-bucket bound (audit round 8, F11): the 90s retain
            // alone left the bucket UNBOUNDED under a sustained flood of
            // fresh source IPs (every new IP inside the 90s window was
            // kept, ~4096+ rows per 90s forever). Cap the bucket and evict
            // the OLDEST entry (earliest window_start) at the cap
            // (ReplayTable cap-evicts-oldest precedent). Both the 90s
            // retain and the eviction scan are O(OVERFLOW_CAP) and run
            // ONLY at cap pressure — never O(n) per attempt below it
            // (entries below the cap expire via the at-cap retain; memory
            // is bounded by the cap either way). Per-IP semantics are
            // unchanged: 50 attempts per 60s window.
            const OVERFLOW_CAP: usize = 4096;
            // Drop the main-table guard before acquiring the overflow lock —
            // the nested acquisition was safe (no reverse order anywhere) but
            // fragile to future refactoring (audit round 5, MEDIUM 3.1).
            drop(throttle);
            let mut overflow = self.login_throttle_overflow.lock().await;
            // Cleanup mirrors the main table (90s) — amortized to cap
            // pressure only: below the cap expired rows cost nothing to
            // keep (the cap bounds memory) and the 60s window logic below
            // resets a stale row in place when its IP returns.
            if !overflow.contains_key(&ip) && overflow.len() >= OVERFLOW_CAP {
                overflow.retain(|_, (_, window_start)| {
                    now.duration_since(*window_start) < CLEANUP_TIMEOUT
                });
                if overflow.len() >= OVERFLOW_CAP {
                    // Still full of live entries — evict the oldest so the
                    // new IP is admitted (ReplayTable precedent). Ties in
                    // window_start evict the first row iterated: any
                    // oldest-age row is a valid victim.
                    let mut oldest_ip: Option<std::net::IpAddr> = None;
                    let mut oldest_start = now;
                    for (entry_ip, (_, window_start)) in overflow.iter() {
                        if oldest_ip.is_none() || *window_start < oldest_start {
                            oldest_start = *window_start;
                            oldest_ip = Some(*entry_ip);
                        }
                    }
                    if let Some(oldest) = oldest_ip {
                        overflow.remove(&oldest);
                    }
                }
            }
            let (count, window_start) = overflow.entry(ip).or_insert((0, now));
            if now.duration_since(*window_start) > std::time::Duration::from_secs(60) {
                *count = 1;
                *window_start = now;
                return true;
            }
            if *count >= OVERFLOW_MAX_PER_IP {
                tracing::warn!(ip = %ip, "Login throttle overflow cap hit for {} (50 attempts); throttling", ip);
                return false; // Coarse-throttled
            }
            *count += 1;
            return true;
        }

        let (count, window_start) = throttle.entry(ip).or_insert((0, now));
        if now.duration_since(*window_start) > std::time::Duration::from_secs(60) {
            // Window expired — reset and allow this attempt.
            *count = 1;
            *window_start = now;
            return true;
        }
        if *count >= 5 {
            return false; // Throttled
        }
        *count += 1; // Reserve this attempt atomically
        true
    }

    /// Pure throttle check (no slot consumed, no mutation): is this IP
    /// currently inside its throttle window?
    ///
    /// Used BEFORE auth runs (round 6, MEDIUM B5) so an already-throttled
    /// brute-force IP is rejected without paying the CPU cost of a full
    /// MD5 / OIDC JWT verify per attempt. Mirrors `check_login_throttle`
    /// window semantics: main table 5 per 60s, overflow bucket 50 per 60s.
    /// Lock order matches `check_login_throttle` (main table dropped before
    /// overflow) — no nested acquisition.
    pub async fn is_login_throttled(&self, addr: Option<std::net::SocketAddr>) -> bool {
        let Some(addr) = addr else {
            return false; // no peer address → cannot throttle
        };
        let ip = addr.ip();
        let now = std::time::Instant::now();
        const WINDOW: std::time::Duration = std::time::Duration::from_secs(60);
        {
            let throttle = self.login_throttle.lock().await;
            if let Some((count, window_start)) = throttle.get(&ip) {
                if now.duration_since(*window_start) <= WINDOW && *count >= 5 {
                    return true;
                }
            }
        }
        let overflow = self.login_throttle_overflow.lock().await;
        if let Some((count, window_start)) = overflow.get(&ip) {
            if now.duration_since(*window_start) <= WINDOW && *count >= 50 {
                return true;
            }
        }
        false
    }

    /// Get or create the per-run_id serialization mutex.
    ///
    /// This mutex ensures that only one lifecycle transition (admit/activate/
    /// completeLogin/remove) happens at a time for a given run_id. It is
    /// inherited by new control connections when they supersede old ones.
    pub fn get_run_mu(&self, run_id: &str) -> (Arc<tokio::sync::Mutex<()>>, RunMuGuard) {
        let mut map = self.run_mu_map.lock().unwrap_or_else(|e| e.into_inner());
        let entry = map
            .entry(run_id.to_string())
            .or_insert_with(|| {
                Arc::new(RunMuEntry {
                    mu: Arc::new(tokio::sync::Mutex::new(())),
                    refs: AtomicUsize::new(0),
                })
            })
            .clone();
        entry.refs.fetch_add(1, AtomicOrdering::SeqCst);
        let guard = RunMuGuard {
            map: self.run_mu_map.clone(),
            run_id: run_id.to_string(),
            entry: entry.clone(),
        };
        (entry.mu.clone(), guard)
    }

    /// Decrement `https_proxy_count`, saturating at zero. The dashboard
    /// delete path and the client CloseProxy path can race — both observe
    /// the proxy before either removes it — and a plain fetch_sub would
    /// underflow to `usize::MAX`. The saturating form also absorbs the
    /// round-6d group asymmetry: https GROUP members never increment yet
    /// are decremented on removal, so the counter must not go negative
    /// (accounting-only today; no production reader).
    pub fn dec_https_proxy_count(&self) {
        let mut cur = self.https_proxy_count.load(AtomicOrdering::Relaxed);
        while cur > 0 {
            match self.https_proxy_count.compare_exchange_weak(
                cur,
                cur - 1,
                AtomicOrdering::Relaxed,
                AtomicOrdering::Relaxed,
            ) {
                Ok(_) => return,
                Err(actual) => cur = actual,
            }
        }
    }
}

#[cfg(feature = "vnet")]
impl AppState {
    /// Queue a route advertisement to every online control that participates in
    /// the advertisement's virtual net (except `exclude_run_id`). Controls
    /// without any route in that vnet never see it — the isolation guarantee.
    pub(crate) async fn broadcast_vnet_route_advertise(
        &self,
        exclude_run_id: &str,
        adv: &msg::VnetRouteAdvertise,
    ) {
        let vnet = adv.virtual_net.clone().unwrap_or_default();
        for tx in self.control_txs_in_vnet(exclude_run_id, &vnet).await {
            let _ = tx.try_send(InternalMsg::VnetRouteAdvertiseForward { msg: adv.clone() });
        }
    }

    /// Queue a route removal to every online control that participates in the
    /// removal's virtual net (except `exclude_run_id`).
    pub(crate) async fn broadcast_vnet_route_remove(
        &self,
        exclude_run_id: &str,
        rem: &msg::VnetRouteRemove,
    ) {
        let vnet = rem.virtual_net.clone().unwrap_or_default();
        for tx in self.control_txs_in_vnet(exclude_run_id, &vnet).await {
            let _ = tx.try_send(InternalMsg::VnetRouteRemoveForward { msg: rem.clone() });
        }
    }

    /// Remove every route registered by `run_id` and broadcast matching removals.
    pub(crate) async fn remove_run_id_vnet_routes(&self, run_id: &str) {
        let removed = {
            let mut routes = self.vnet_routes.write().await;
            let removed: Vec<(String, String)> = routes
                .iter()
                .filter(|(_, (rid, _))| rid == run_id)
                .map(|((vn, _), (_, proxy_name))| (vn.clone(), proxy_name.clone()))
                .collect();
            routes.retain(|_, (rid, _)| rid != run_id);
            removed
        };

        let mut seen = HashSet::new();
        for (vn, proxy_name) in removed {
            if seen.insert((vn.clone(), proxy_name.clone())) {
                self.broadcast_vnet_route_remove(
                    run_id,
                    &msg::VnetRouteRemove {
                        proxy_name,
                        virtual_net: (!vn.is_empty()).then_some(vn),
                    },
                )
                .await;
            }
        }
    }

    /// Senders for every online control (other than `exclude_run_id`) that has
    /// at least one route in `vnet`. Used to scope vnet route broadcasts to
    /// peers on the same virtual net.
    async fn control_txs_in_vnet(
        &self,
        exclude_run_id: &str,
        vnet: &str,
    ) -> Vec<mpsc::Sender<InternalMsg>> {
        let mut run_ids: HashSet<String> = HashSet::new();
        {
            let routes = self.vnet_routes.read().await;
            for ((vn, _), (rid, _)) in routes.iter() {
                if vn == vnet && rid != exclude_run_id {
                    run_ids.insert(rid.clone());
                }
            }
        }
        run_ids
            .iter()
            .filter_map(|rid| self.run_id_to_ctl_tx.get(rid).map(|ctl| ctl.tx.clone()))
            .collect()
    }

    /// Remove every vnet route registered by `proxy_name` for `run_id` and
    /// broadcast a removal to peers on the same virtual nets. Called by the
    /// close-proxy handler so peer clients invalidate their routes when a
    /// proxy closes. The retain is guarded by `run_id`: visitor route names
    /// are per-client, so a same-named route owned by another client must
    /// survive.
    pub(crate) async fn remove_proxy_vnet_routes_and_broadcast(
        &self,
        run_id: &str,
        proxy_name: &str,
    ) {
        let removed: Vec<(String, String)> = {
            let mut routes = self.vnet_routes.write().await;
            let removed: Vec<(String, String)> = routes
                .iter()
                .filter(|(_, (rid, name))| rid == run_id && name == proxy_name)
                .map(|((vn, _), _)| (vn.clone(), proxy_name.to_string()))
                .collect();
            routes.retain(|_, (rid, name)| !(rid == run_id && name == proxy_name));
            removed
        };
        let mut seen = HashSet::new();
        for (vn, name) in removed {
            if seen.insert(vn.clone()) {
                self.broadcast_vnet_route_remove(
                    run_id,
                    &msg::VnetRouteRemove {
                        proxy_name: name,
                        virtual_net: (!vn.is_empty()).then_some(vn),
                    },
                )
                .await;
            }
        }
    }

    /// Whether `run_id` may send a `VnetPacket` addressed to `proxy_name`.
    ///
    /// Isolation check: the source must participate in the target route's
    /// virtual net (i.e. it must own at least one route in that vnet). Unknown
    /// target routes are denied — drop by default. Different virtual nets have
    /// isolated routing tables (design spec).
    pub(crate) async fn vnet_packet_source_allowed(&self, run_id: &str, proxy_name: &str) -> bool {
        let routes = self.vnet_routes.read().await;
        // Existence check: the source is allowed iff there is *some* virtual
        // net in which both the source has a route and the target route lives.
        // (A multi-homed proxy may be reached by members of any of its vnets;
        // a `find`-then-verify would depend on HashMap iteration order.)
        // Single-pass variant for the per-packet hot path: collect the virtual
        // nets the source participates in, then verify the target route lives
        // in one of them — O(n) instead of the previous O(n²) nested scan.
        let source_vnets: std::collections::HashSet<&String> = routes
            .iter()
            .filter(|(_, (rid, _))| rid == run_id)
            .map(|((vn, _), _)| vn)
            .collect();
        routes
            .iter()
            .any(|((vn, _), (_, name))| name == proxy_name && source_vnets.contains(vn))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_state() -> Arc<AppState> {
        let cfg = frp_core::config::ServerConfig::default();
        Arc::new(AppState::new(
            frp_core::auth::AuthConfig::with_token("test-token"),
            "127.0.0.1".into(),
            frp_core::encryption::derive_key("test-token"),
            vec![frp_core::config::PortsRange {
                start: 1,
                end: u16::MAX,
                single: 0,
            }],
            String::new(),
            true,
            30,
            7200,
            0,
            0,
            90,
            1500,
            false,
            None,
            0,
            60,
            10,
            false,
            String::new(),
            Arc::new(crate::plugin::HttpPluginManager::new(Vec::new())),
            0,
            0,
            0,
            168,
            true,
            0,
            0,
            frp_core::config::ServerConfigSnapshot::from_config(&cfg),
        ))
    }

    /// Audit H1 regression: "0 = unlimited" must build NO connection
    /// semaphore (`conn_semaphore = None`). The old service.rs mapping
    /// `Some(0) => usize::MAX` passed the `> 0` gate and called
    /// `Semaphore::new(usize::MAX)`, which panics (tokio MAX_PERMITS
    /// assertion) — aborting frps at boot with panic=abort.
    #[test]
    fn max_connections_zero_creates_no_semaphore() {
        // test_state() constructs AppState::new with max_connections = 0.
        let state = test_state();
        assert!(
            state.conn_semaphore.is_none(),
            "max_connections = 0 must mean unlimited (no semaphore)"
        );
    }

    #[tokio::test]
    async fn run_mu_entries_are_reclaimed_when_last_guard_drops() {
        let state = test_state();

        let (mu_a, guard_a) = state.get_run_mu("run-a");
        let (_mu_b, guard_b) = state.get_run_mu("run-b");
        assert_eq!(state.run_mu_map.lock().unwrap().len(), 2);

        // A second lifecycle participant inherits the same mutex.
        let (mu_a2, guard_a2) = state.get_run_mu("run-a");
        assert!(Arc::ptr_eq(&mu_a, &mu_a2));

        drop(guard_a);
        // run-a still has one live participant, so its entry must persist.
        assert_eq!(state.run_mu_map.lock().unwrap().len(), 2);
        drop(guard_a2);
        // run-b still holds its entry; run-a is fully reclaimed.
        assert_eq!(state.run_mu_map.lock().unwrap().len(), 1);

        drop(guard_b);
        assert!(state.run_mu_map.lock().unwrap().is_empty());
    }

    #[cfg(feature = "vnet")]
    async fn insert_control(state: &Arc<AppState>, run_id: &str) -> mpsc::Receiver<InternalMsg> {
        let (tx, rx) = mpsc::channel(16);
        state.run_id_to_ctl_tx.insert(
            run_id.to_string(),
            ControlTx {
                tx,
                client_addr: None,
                login_time: Instant::now(),
                login_time_unix: 0,
                pool_stats: Arc::new(PoolStats::default()),
                user: String::new(),
                control_id: 1,
                udp_packet_codec: String::new(),
                wire_v2: false,
                superseded: Arc::new(AtomicBool::new(false)),
            },
        );
        rx
    }

    #[cfg(feature = "vnet")]
    #[tokio::test]
    async fn vnet_route_broadcast_only_reaches_same_vnet_peers() {
        let state = test_state();
        let mut sender_rx = insert_control(&state, "run-a").await;
        let mut peer_rx = insert_control(&state, "run-b").await;
        let mut other_vnet_rx = insert_control(&state, "run-c").await;
        // run-b participates in vnet-a; run-c only in vnet-b.
        {
            let mut routes = state.vnet_routes.write().await;
            routes.insert(
                ("vnet-a".to_string(), "10.0.0.0/24".to_string()),
                ("run-b".to_string(), "peer-b".to_string()),
            );
            routes.insert(
                ("vnet-b".to_string(), "10.1.0.0/24".to_string()),
                ("run-c".to_string(), "peer-c".to_string()),
            );
        }
        let adv = msg::VnetRouteAdvertise {
            proxy_name: "vnet-visitor".to_string(),
            subnet: "2001:db8::1/128".to_string(),
            virtual_net: Some("vnet-a".to_string()),
        };
        state.broadcast_vnet_route_advertise("run-a", &adv).await;

        match tokio::time::timeout(Duration::from_secs(5), peer_rx.recv()).await {
            Ok(Some(InternalMsg::VnetRouteAdvertiseForward { msg })) => {
                assert_eq!(msg.proxy_name, "vnet-visitor");
                assert_eq!(msg.virtual_net.as_deref(), Some("vnet-a"));
            }
            other => panic!("expected forwarded advertise, got {:?}", other),
        }
        assert!(
            sender_rx.try_recv().is_err(),
            "source run must not receive its own broadcast"
        );
        assert!(
            other_vnet_rx.try_recv().is_err(),
            "different-vnet peer must not receive the broadcast"
        );
    }

    #[cfg(feature = "vnet")]
    #[tokio::test]
    async fn remove_proxy_vnet_routes_broadcasts_to_same_vnet_peers() {
        let state = test_state();
        let mut peer_rx = insert_control(&state, "run-b").await;
        {
            let mut routes = state.vnet_routes.write().await;
            // run-a's proxy owns two vnet-a routes and one vnet-b route.
            routes.insert(
                ("vnet-a".to_string(), "10.0.0.0/24".to_string()),
                ("run-a".to_string(), "vnet-proxy".to_string()),
            );
            routes.insert(
                ("vnet-a".to_string(), "2001:db8::/64".to_string()),
                ("run-a".to_string(), "vnet-proxy".to_string()),
            );
            routes.insert(
                ("vnet-b".to_string(), "10.1.0.0/24".to_string()),
                ("run-a".to_string(), "vnet-proxy".to_string()),
            );
            // run-b participates in vnet-a, so it receives the vnet-a removal.
            routes.insert(
                ("vnet-a".to_string(), "172.16.0.0/16".to_string()),
                ("run-b".to_string(), "peer-b".to_string()),
            );
        }

        state
            .remove_proxy_vnet_routes_and_broadcast("run-a", "vnet-proxy")
            .await;

        assert!(
            state
                .vnet_routes
                .read()
                .await
                .iter()
                .all(|(_, (_, name))| name != "vnet-proxy"),
            "all routes for the closed proxy must be removed"
        );

        // Two removals are broadcast (vnet-a + vnet-b), but run-b only
        // receives the one for vnet-a.
        let mut received = Vec::new();
        while let Ok(InternalMsg::VnetRouteRemoveForward { msg }) = peer_rx.try_recv() {
            received.push(msg);
        }
        assert_eq!(received.len(), 1);
        assert_eq!(received[0].proxy_name, "vnet-proxy");
        assert_eq!(received[0].virtual_net.as_deref(), Some("vnet-a"));
    }

    #[cfg(feature = "vnet")]
    #[tokio::test]
    async fn vnet_packet_source_allowed_respects_isolation() {
        let state = test_state();
        {
            let mut routes = state.vnet_routes.write().await;
            routes.insert(
                ("vnet-a".to_string(), "10.0.0.0/24".to_string()),
                ("run-a".to_string(), "peer-a".to_string()),
            );
            routes.insert(
                ("vnet-a".to_string(), "10.0.1.0/24".to_string()),
                ("run-b".to_string(), "target-b".to_string()),
            );
            routes.insert(
                ("vnet-b".to_string(), "10.1.0.0/24".to_string()),
                ("run-c".to_string(), "target-c".to_string()),
            );
        }
        // run-a is in vnet-a and may reach target-b (also vnet-a).
        assert!(state.vnet_packet_source_allowed("run-a", "target-b").await);
        // run-c is only in vnet-b; reaching target-b (vnet-a) is denied.
        assert!(!state.vnet_packet_source_allowed("run-c", "target-b").await);
        // A source with no route in the target's vnet is denied.
        assert!(!state.vnet_packet_source_allowed("run-b", "target-c").await);
        // Unknown target routes are denied.
        assert!(!state.vnet_packet_source_allowed("run-a", "missing").await);
    }

    // --- ReplayTable tests (F3/F4) ---

    /// ms-precision key, "now" for prune tests (>= MS_EPOCH).
    const MS_NOW: i64 = 1_750_000_000_000;
    const MS_TS: i64 = MS_NOW + 123;

    #[test]
    fn replay_table_dedup_rejects_ms_duplicate() {
        let mut t = ReplayTable::new();
        // ms-precision key (Rust frpc): an identical (run_id, ts) replay
        // is rejected.
        assert_eq!(t.record(MS_TS, "run-1"), ReplayCheck::Admitted);
        assert_eq!(t.total(), 1);
        assert_eq!(t.record(MS_TS, "run-1"), ReplayCheck::Replay);
        assert_eq!(t.total(), 1, "duplicates must not count as new entries");
        // Distinct run_ids at the same timestamp are fine.
        assert_eq!(t.record(MS_TS, "run-2"), ReplayCheck::Admitted);
        assert_eq!(t.total(), 2);
    }

    #[test]
    fn replay_table_seconds_duplicate_is_admitted() {
        // Go frpc reuses its run_id and sends seconds keys: a reconnect
        // in the same wall-clock second is indistinguishable from a replay
        // and must be admitted (freshness window still bounds real replays).
        let mut t = ReplayTable::new();
        let ts = MS_NOW / 1000; // < MS_EPOCH
        assert_eq!(t.record(ts, "run-1"), ReplayCheck::Admitted);
        assert_eq!(
            t.record(ts, "run-1"),
            ReplayCheck::DuplicateSecondsPrecision
        );
    }

    #[test]
    fn replay_table_duplicate_at_global_cap_does_not_evict() {
        // S5: the duplicate check runs BEFORE the global-cap eviction — a
        // replayed (ts, run_id) at (or over) the cap must return Replay
        // without evicting anything. Otherwise an attacker replaying one
        // captured pair could repeatedly evict fresh keys, shrinking the
        // replay window.
        let mut t = ReplayTable::new();
        let n_ts = MAX_TOTAL_REPLAY_ENTRIES / MAX_ENTRIES_PER_TIMESTAMP;
        for ts_i in 0..n_ts {
            let ts = MS_NOW + ts_i as i64;
            for i in 0..MAX_ENTRIES_PER_TIMESTAMP {
                assert_eq!(
                    t.record(ts, &format!("run-{ts_i}-{i}")),
                    ReplayCheck::Admitted
                );
            }
        }
        assert_eq!(t.total(), MAX_TOTAL_REPLAY_ENTRIES);
        let before = t.total();
        let oldest_ts = MS_NOW; // still present at the cap
        assert!(t.map.contains_key(&oldest_ts));

        // A duplicate of the OLDEST still-present key: rejected, and
        // neither the table nor any key is touched.
        assert_eq!(t.record(oldest_ts, "run-0-0"), ReplayCheck::Replay);
        assert_eq!(t.total(), before, "replay must not evict at the cap");
        assert!(t.map.contains_key(&oldest_ts));
        assert_eq!(t.map[&oldest_ts].len(), MAX_ENTRIES_PER_TIMESTAMP);
        // The victim's coverage is intact: a fresh run_id at that key is
        // still admitted — the whole oldest timestamp key is evicted
        // first (global cap), so the fresh entry lands in an empty bucket.
        assert_eq!(
            t.record(oldest_ts, "run-new"),
            ReplayCheck::Admitted,
            "non-duplicate logins still admitted at the cap"
        );
    }

    #[test]
    fn replay_table_prunes_future_timestamps() {
        // Round 6 (LOW B7): timestamps ahead of now sort to the map tail
        // and must be pruned, not parked where they squeeze legitimate
        // entries in the global cap's eviction order. (Keys further ahead
        // than the freshness window never reach record — the login is
        // rejected first.)
        let mut t = ReplayTable::new();
        let now_ms = 2_000_000_000_000i64; // epoch-ms anchor
        let now_s = now_ms / 1000;
        // stale (age-pruned, beyond the 10s window), live (kept), future
        // (B7-pruned)
        t.record(now_ms - 15_000, "old");
        t.record(now_ms, "live");
        t.record(now_ms + 3000, "future");
        let pruned = t.prune_expired(now_ms, 10);
        assert_eq!(pruned, 2, "stale + future key pruned");
        assert_eq!(t.total(), 1);
        assert!(t.map.contains_key(&now_ms));
        // Seconds domain (Go frpc keys) gets the same tail treatment.
        let mut t2 = ReplayTable::new();
        t2.record(now_s, "live-s");
        t2.record(now_s + 5, "future-s");
        t2.prune_expired(now_ms, 10);
        assert_eq!(t2.total(), 1);
        assert!(t2.map.contains_key(&now_s));
    }

    #[test]
    fn replay_table_per_timestamp_cap_evicts_oldest_and_admits() {
        // 101 distinct run_ids at the same timestamp: ALL admitted (F3 —
        // the old behavior rejected every login at a full key, locking
        // out a legitimate same-run_id reconnect), with the OLDEST run_id
        // evicted to keep the set bounded.
        let mut t = ReplayTable::new();
        for i in 0..MAX_ENTRIES_PER_TIMESTAMP {
            assert_eq!(
                t.record(MS_TS, &format!("run-{i:03}")),
                ReplayCheck::Admitted
            );
        }
        assert_eq!(t.total(), MAX_ENTRIES_PER_TIMESTAMP);
        assert_eq!(
            t.record(MS_TS, "run-100"),
            ReplayCheck::Admitted,
            "cap-hit must evict, not reject"
        );
        let entry = &t.map[&MS_TS];
        assert_eq!(entry.len(), MAX_ENTRIES_PER_TIMESTAMP);
        // The first-inserted run_id was evicted; the newest is kept.
        assert!(
            !entry.iter().any(|r| r == "run-000"),
            "oldest run_id must be evicted, got: {entry:?}"
        );
        assert!(entry.iter().any(|r| r == "run-100"));
        // The evicted run_id loses dedup coverage only; in-set run_ids
        // still replay, and the total stays consistent through the
        // evict+insert cycle.
        assert_eq!(t.record(MS_TS, "run-001"), ReplayCheck::Replay);
        assert_eq!(t.record(MS_TS, "run-000"), ReplayCheck::Admitted);
        assert_eq!(t.total(), MAX_ENTRIES_PER_TIMESTAMP);
    }

    #[test]
    fn replay_table_global_cap_evicts_oldest_keys_and_keeps_recent_dedup() {
        // Fill the table to the global cap (100 run_ids per timestamp ×
        // 1000 timestamps), then record one more login at a NEW timestamp.
        // The OLDEST whole timestamp keys are evicted and the new login is
        // admitted (F4 — the old behavior degraded to freshness-only dedup
        // for ALL clients instead of evicting).
        let mut t = ReplayTable::new();
        let n_ts = MAX_TOTAL_REPLAY_ENTRIES / MAX_ENTRIES_PER_TIMESTAMP;
        for ts_i in 0..n_ts {
            let ts = MS_NOW + ts_i as i64;
            for i in 0..MAX_ENTRIES_PER_TIMESTAMP {
                assert_eq!(
                    t.record(ts, &format!("run-{ts_i}-{i}")),
                    ReplayCheck::Admitted
                );
            }
        }
        assert_eq!(t.total(), MAX_TOTAL_REPLAY_ENTRIES);

        let newest_ts = MS_NOW + n_ts as i64;
        assert_eq!(t.record(newest_ts, "run-new"), ReplayCheck::Admitted);
        assert!(
            t.total() <= MAX_TOTAL_REPLAY_ENTRIES,
            "total must stay bounded after cap eviction"
        );
        assert!(t.map.contains_key(&newest_ts));
        // The oldest timestamp key was evicted (the next-oldest stays —
        // eviction drains one key per record, just enough to admit the
        // new login)...
        assert!(!t.map.contains_key(&MS_NOW));
        assert!(
            t.map.contains_key(&(MS_NOW + 1)),
            "eviction must drain the oldest keys first"
        );
        // ...and dedup STILL works for a recent key — the security
        // property the old global-degrade path lost.
        assert_eq!(
            t.record(newest_ts, "run-new"),
            ReplayCheck::Replay,
            "in-window timestamps must keep duplicate detection after cap eviction"
        );
    }

    #[test]
    fn replay_table_prune_drains_expired_keys_and_keeps_total_consistent() {
        let mut t = ReplayTable::new();
        // Expired seconds keys (Go frpc): 200s ago.
        t.record(MS_NOW / 1000 - 200, "old-sec-1");
        t.record(MS_NOW / 1000 - 200, "old-sec-2");
        // Live seconds key: 30s ago.
        t.record(MS_NOW / 1000 - 30, "live-sec");
        // Expired ms key (Rust frpc): 200s ago — sorts AFTER the live
        // seconds key, which is the two-precision-domain trap the prune
        // must handle (a single leading-key break on the first live key
        // would miss it).
        t.record(MS_NOW - 200_000, "old-ms");
        // Live ms key.
        t.record(MS_NOW - 30_000, "live-ms");
        assert_eq!(t.total(), 5);

        let pruned = t.prune_expired(MS_NOW, 90);
        assert_eq!(pruned, 3, "two old seconds keys + one old ms key");
        assert_eq!(t.total(), 2, "total counter must track the prune");
        assert!(!t.map.contains_key(&(MS_NOW / 1000 - 200)));
        assert!(!t.map.contains_key(&(MS_NOW - 200_000)));
        assert!(t.map.contains_key(&(MS_NOW / 1000 - 30)));
        assert!(t.map.contains_key(&(MS_NOW - 30_000)));
        // After the prune, dedup still works for the surviving keys.
        assert_eq!(t.record(MS_NOW - 30_000, "live-ms"), ReplayCheck::Replay);
        assert_eq!(t.total(), 2);
    }

    // --- Login throttle tests (check_login_throttle) ---
    //
    // check_login_throttle keys on `addr.ip()` and reads std::time::Instant,
    // which tokio's test-util clock does NOT mock: `tokio::time::pause` /
    // `advance` only affect tokio::time utilities, and clock.rs's mocked
    // `now()` falls through to real std::time::Instant for everything else.
    // The 60s-window and 90s-cleanup branches are therefore exercised by
    // seeding stale `window_start` values directly into the (pub) throttle
    // maps — deterministic, no 60s real sleeps, and it hits the exact
    // `duration_since(window_start)` comparisons the production paths use.

    #[tokio::test]
    async fn check_login_throttle_five_allowed_then_sixth_rejected() {
        let state = test_state();
        let addr = |port: u16| std::net::SocketAddr::from(([127, 0, 0, 1], port));
        // 5 attempts per 60s window per IP; distinct ports still hit the
        // same per-IP bucket (keyed by addr.ip()).
        for port in 1..=5 {
            assert!(
                state.check_login_throttle(addr(port)).await,
                "attempt {port} must be allowed"
            );
        }
        assert!(
            !state.check_login_throttle(addr(6)).await,
            "6th attempt must be throttled"
        );
        // Same IP, different port: still throttled (per-IP, not per-addr).
        assert!(!state.check_login_throttle(addr(7)).await);
        // The pre-auth gate (is_login_throttled) mirrors the same table
        // state; a missing peer address is never throttled.
        assert!(state.is_login_throttled(Some(addr(8))).await);
        assert!(!state.is_login_throttled(None).await);
        // A different IP is unaffected by the throttled one.
        assert!(
            state
                .check_login_throttle(std::net::SocketAddr::from(([127, 0, 0, 2], 1)))
                .await
        );
    }

    #[tokio::test]
    async fn check_login_throttle_window_expiry_resets_count() {
        let state = test_state();
        let ip = std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1));
        let addr = |port: u16| std::net::SocketAddr::from((ip, port));
        // Seed a stale entry: 5 failures whose 60s window started 61s ago.
        {
            let mut t = state.login_throttle.lock().await;
            t.insert(
                ip,
                (
                    5,
                    std::time::Instant::now() - std::time::Duration::from_secs(61),
                ),
            );
        }
        // Window expired → attempt allowed, count resets to 1.
        assert!(state.check_login_throttle(addr(1)).await);
        // Fresh window: 4 more allowed (counts 2..=5), then throttled.
        for port in 2..=5 {
            assert!(
                state.check_login_throttle(addr(port)).await,
                "post-reset attempt {port} must be allowed"
            );
        }
        assert!(!state.check_login_throttle(addr(6)).await);
        // A full count INSIDE its window stays throttled (no reset).
        let ip2 = std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 9));
        {
            let mut t = state.login_throttle.lock().await;
            t.insert(
                ip2,
                (
                    5,
                    std::time::Instant::now() - std::time::Duration::from_secs(1),
                ),
            );
        }
        assert!(
            !state
                .check_login_throttle(std::net::SocketAddr::from((ip2, 1)))
                .await
        );
    }

    #[tokio::test]
    async fn check_login_throttle_cleanup_removes_entries_older_than_90s() {
        let state = test_state();
        let stale_ip = std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 77));
        let fresh_ip = std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 78));
        {
            let mut t = state.login_throttle.lock().await;
            t.insert(
                stale_ip,
                (
                    5,
                    std::time::Instant::now() - std::time::Duration::from_secs(91),
                ),
            );
            t.insert(fresh_ip, (1, std::time::Instant::now()));
        }
        // Any call runs the inline cleanup (90s grace) — the stale entry
        // must go, the fresh one must survive.
        assert!(
            state
                .check_login_throttle(std::net::SocketAddr::from(([127, 0, 0, 79], 1)))
                .await
        );
        let t = state.login_throttle.lock().await;
        assert!(!t.contains_key(&stale_ip), "91s-old entry must be cleaned");
        assert!(t.contains_key(&fresh_ip), "fresh entry must survive");
    }

    #[tokio::test]
    async fn check_login_throttle_overflow_bucket_caps_untracked_ips() {
        let state = test_state();
        // Fill the main table to the 512-entry cap with distinct IPs.
        for i in 0u16..512 {
            let ip = std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                127,
                (i >> 8) as u8,
                (i & 0xff) as u8,
                1,
            ));
            assert!(
                state
                    .check_login_throttle(std::net::SocketAddr::from((ip, 1)))
                    .await
            );
        }
        {
            let t = state.login_throttle.lock().await;
            assert_eq!(t.len(), 512, "main table must be full at the cap");
        }
        // A TRACKED IP still uses the main table (not the coarse overflow).
        let tracked = std::net::SocketAddr::from(([127, 0, 0, 1], 1));
        assert!(state.check_login_throttle(tracked).await);
        // An untracked IP hits the overflow bucket: 50 allowed, then false.
        let untracked = std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 99, 0, 1));
        for i in 1..=50 {
            assert!(
                state
                    .check_login_throttle(std::net::SocketAddr::from((untracked, i)))
                    .await,
                "overflow attempt {i} must be allowed"
            );
        }
        assert!(
            !state
                .check_login_throttle(std::net::SocketAddr::from((untracked, 51)))
                .await,
            "51st overflow attempt must be throttled"
        );
        // The pre-auth gate sees the coarse cap too.
        assert!(
            state
                .is_login_throttled(Some(std::net::SocketAddr::from((untracked, 52))))
                .await
        );
        // Overflow window expiry resets the coarse counter (count -> 1).
        {
            let mut o = state.login_throttle_overflow.lock().await;
            o.get_mut(&untracked).expect("overflow entry").1 =
                std::time::Instant::now() - std::time::Duration::from_secs(61);
        }
        assert!(
            state
                .check_login_throttle(std::net::SocketAddr::from((untracked, 53)))
                .await,
            "expired overflow window must reset the counter"
        );
        // 49 more allowed after the reset (counts 2..=50)...
        for i in 54..=102 {
            assert!(
                state
                    .check_login_throttle(std::net::SocketAddr::from((untracked, i)))
                    .await,
                "post-reset overflow attempt {i} must be allowed"
            );
        }
        // ...then capped again.
        assert!(
            !state
                .check_login_throttle(std::net::SocketAddr::from((untracked, 103)))
                .await
        );
    }

    // F11: the overflow bucket must be BOUNDED. The main table caps at 512
    // and the 90s retain only removes TIME-expired rows, so the overflow
    // bucket previously grew without limit under a sustained flood of fresh
    // source IPs (~4096+ rows per 90s forever). A cap with oldest-eviction
    // (ReplayTable precedent) bounds total per-IP state at
    // MAX_THROTTLE_ENTRIES + OVERFLOW_CAP; per-IP 50/60s semantics are
    // unchanged.
    #[tokio::test]
    async fn check_login_throttle_overflow_bucket_bounded_under_ip_burst() {
        let state = test_state();
        // Fill the main table to its 512-entry cap with distinct IPs.
        for i in 0u16..512 {
            let ip = std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                10,
                (i >> 8) as u8,
                (i & 0xff) as u8,
                1,
            ));
            assert!(
                state
                    .check_login_throttle(std::net::SocketAddr::from((ip, 1)))
                    .await
            );
        }
        // Burst ~6200 more distinct IPs (all inside the 90s retain window —
        // the whole burst runs in milliseconds). Pre-fix the overflow
        // bucket kept every one of them.
        let mut newest = std::net::IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0));
        for i in 512u32..=6800 {
            let ip = std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                172,
                (i >> 16) as u8,
                ((i >> 8) & 0xff) as u8,
                (i & 0xff) as u8,
            ));
            assert!(
                state
                    .check_login_throttle(std::net::SocketAddr::from((ip, 1)))
                    .await,
                "first attempt of burst IP {i} must be allowed"
            );
            newest = ip;
        }
        {
            let t = state.login_throttle.lock().await;
            assert_eq!(t.len(), 512, "main table must stay at its cap");
        }
        let o = state.login_throttle_overflow.lock().await;
        assert!(
            o.len() <= 4096,
            "overflow bucket must be capped at 4096 entries, got {}",
            o.len()
        );
        assert!(
            o.contains_key(&newest),
            "the newest burst IP must survive (just admitted)"
        );
    }

    // F11: eviction at the cap must remove the OLDEST entry (earliest
    // window_start), never an arbitrary/newer one — the flood victim is
    // always the entry whose throttle state is closest to expiry.
    #[tokio::test]
    async fn check_login_throttle_overflow_at_cap_evicts_oldest() {
        let state = test_state();
        // Fill the main table so untracked IPs fall into the overflow
        // bucket.
        for i in 0u16..512 {
            let ip = std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                10,
                (i >> 8) as u8,
                (i & 0xff) as u8,
                1,
            ));
            state
                .check_login_throttle(std::net::SocketAddr::from((ip, 1)))
                .await;
        }
        // Seed the overflow bucket AT the cap (4096) with staggered
        // timestamps all inside the 90s retain window: entry i is
        // 2s + i*20ms old → entry 4095 (83.9s old) is the oldest and must
        // be the eviction victim.
        let now = std::time::Instant::now();
        {
            let mut o = state.login_throttle_overflow.lock().await;
            for i in 0..4096u32 {
                let ip = std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                    172,
                    16 + (i >> 8) as u8,
                    (i & 0xff) as u8,
                    1,
                ));
                o.insert(
                    ip,
                    (
                        1,
                        now - std::time::Duration::from_millis(2000 + 20 * i as u64),
                    ),
                );
            }
        }
        let new_ip = std::net::IpAddr::V4(std::net::Ipv4Addr::new(172, 32, 0, 1));
        assert!(
            state
                .check_login_throttle(std::net::SocketAddr::from((new_ip, 1)))
                .await,
            "new IP must be admitted at the cap (evict-oldest)"
        );
        let o = state.login_throttle_overflow.lock().await;
        assert_eq!(o.len(), 4096, "cap must hold: one eviction per admission");
        assert!(o.contains_key(&new_ip), "new IP must be present");
        let oldest = std::net::IpAddr::V4(std::net::Ipv4Addr::new(172, 31, 255, 1));
        assert!(
            !o.contains_key(&oldest),
            "the oldest entry (i=4095) must be the eviction victim"
        );
        let newest_seed = std::net::IpAddr::V4(std::net::Ipv4Addr::new(172, 16, 0, 1));
        assert!(
            o.contains_key(&newest_seed),
            "the newest seeded entry (i=0) must survive"
        );
    }

    // F11: at-cap admission must FIRST sweep 90s-expired rows so live
    // entries are only evicted when the bucket is genuinely full of fresh
    // state.
    #[tokio::test]
    async fn check_login_throttle_overflow_at_cap_cleans_stale_before_evicting() {
        let state = test_state();
        for i in 0u16..512 {
            let ip = std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                10,
                (i >> 8) as u8,
                (i & 0xff) as u8,
                1,
            ));
            state
                .check_login_throttle(std::net::SocketAddr::from((ip, 1)))
                .await;
        }
        let now = std::time::Instant::now();
        {
            let mut o = state.login_throttle_overflow.lock().await;
            // 100 stale rows (>90s old, would be retained forever pre-fix
            // without an at-cap sweep)...
            for i in 0..100u32 {
                let ip = std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                    172,
                    16 + (i >> 8) as u8,
                    (i & 0xff) as u8,
                    1,
                ));
                o.insert(
                    ip,
                    (
                        50,
                        now - std::time::Duration::from_millis(91_000 + 20 * i as u64),
                    ),
                );
            }
            // ...and 3996 live rows fill the rest of the cap.
            for i in 100..4096u32 {
                let ip = std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                    172,
                    16 + (i >> 8) as u8,
                    (i & 0xff) as u8,
                    1,
                ));
                o.insert(ip, (1, now - std::time::Duration::from_secs(10)));
            }
        }
        let new_ip = std::net::IpAddr::V4(std::net::Ipv4Addr::new(172, 32, 0, 1));
        assert!(
            state
                .check_login_throttle(std::net::SocketAddr::from((new_ip, 1)))
                .await,
            "new IP must be admitted via the stale sweep (no live eviction needed)"
        );
        let o = state.login_throttle_overflow.lock().await;
        assert_eq!(
            o.len(),
            4096 - 100 + 1,
            "stale rows must be swept at cap pressure before any admission"
        );
        assert!(o.contains_key(&new_ip));
        // A live row must NOT have been evicted (the sweep made room).
        let live = std::net::IpAddr::V4(std::net::Ipv4Addr::new(172, 17, 0, 1));
        assert!(o.contains_key(&live), "live rows must survive the sweep");
        let stale = std::net::IpAddr::V4(std::net::Ipv4Addr::new(172, 16, 0, 1));
        assert!(!o.contains_key(&stale), "91s+ rows must be swept");
    }
    // M2: tcpmux group fan-out (Go frp v0.71.0 group.TCPMuxGroup). Second
    // members join after Go-order validation (params → "group params
    // invalid", key → "group auth failed", both verbatim); the route owner
    // is the first member and surfaces only when the group empties;
    // choose_endpoint round-robins.
    #[tokio::test]
    async fn tcpmux_group_controller_join_validation_and_round_robin() {
        let ctl = TcpMuxGroupController::new();

        // First member creates the group.
        let (g, first) = ctl
            .register_member(
                "web",
                "k1",
                "tunnel.example.com",
                "",
                "user",
                "pwd",
                "mux-a",
            )
            .await
            .expect("first member must create the group");
        assert!(first);
        assert_eq!(g.route_owner, "mux-a");

        // Second member, identical params + key → joins.
        let (_, first) = ctl
            .register_member(
                "web",
                "k1",
                "tunnel.example.com",
                "",
                "user",
                "pwd",
                "mux-b",
            )
            .await
            .expect("matching second member must join");
        assert!(!first);

        // Round-robin: 3 picks alternate mux-a, mux-b, mux-a.
        assert_eq!(ctl.choose_endpoint("web").await.as_deref(), Some("mux-a"));
        assert_eq!(ctl.choose_endpoint("web").await.as_deref(), Some("mux-b"));
        assert_eq!(ctl.choose_endpoint("web").await.as_deref(), Some("mux-a"));

        // Go ErrGroupParamsInvalid: params checked BEFORE the key — a
        // user/pwd mismatch rejects verbatim even with the right key.
        let err = ctl
            .register_member(
                "web",
                "k1",
                "tunnel.example.com",
                "",
                "user",
                "OTHER",
                "mux-c",
            )
            .await
            .expect_err("password mismatch must reject");
        assert_eq!(err, "group params invalid");
        let err = ctl
            .register_member("web", "k1", "other.example.com", "", "user", "pwd", "mux-c")
            .await
            .expect_err("domain mismatch must reject");
        assert_eq!(err, "group params invalid");
        // Go ErrGroupAuthFailed: same params, wrong key.
        let err = ctl
            .register_member(
                "web",
                "WRONG",
                "tunnel.example.com",
                "",
                "user",
                "pwd",
                "mux-c",
            )
            .await
            .expect_err("group_key mismatch must reject");
        assert_eq!(err, "group auth failed");
        // Duplicate member.
        let err = ctl
            .register_member(
                "web",
                "k1",
                "tunnel.example.com",
                "",
                "user",
                "pwd",
                "mux-b",
            )
            .await
            .expect_err("duplicate member must reject");
        assert!(err.contains("already a member"), "err: {err}");

        // Member close (non-owner): group survives, owner still registered.
        assert_eq!(
            ctl.unregister_member("web", "mux-b").await,
            None,
            "group with a remaining member must not return the owner"
        );
        assert_eq!(
            ctl.choose_endpoint("web").await.as_deref(),
            Some("mux-a"),
            "surviving owner keeps serving"
        );

        // Owner close empties the group → owner surfaces for route removal,
        // and the group is gone (choose_endpoint → None).
        assert_eq!(
            ctl.unregister_member("web", "mux-a").await.as_deref(),
            Some("mux-a"),
            "emptying the group must surface the route owner"
        );
        assert_eq!(ctl.choose_endpoint("web").await, None);
    }
}
