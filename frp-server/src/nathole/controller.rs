//! NAT hole punch controller: coordinates XTCP sessions between
//! visitor and provider. Runs NAT classification and analysis to
//! recommend hole-punch behaviors. Go frp v0.69.1 compat: pkg/nathole/controller.go

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::AsyncWrite;
use tokio::sync::{mpsc, oneshot, Mutex, RwLock};
use tracing::{instrument, trace, warn};

use frp_core::msg::{self, FrpMessage, NatHoleDetectBehavior, PortsRange};

use super::analysis::{Analyzer, RecommendBehavior};
use super::classify::NatFeature;
use crate::service::InternalMsg;

/// Maximum concurrent NAT hole punch sessions.
/// Prevents unbounded memory growth under load or attack.
/// Enforced table-wide by `SessionTable`'s atomic reservation (the sharded
/// table has no single lock to check a length under).
const MAX_SESSIONS: usize = 256;

/// Provider registration for XTCP.
pub struct ClientCfg {
    pub name: String,
    pub sk: String,
    pub allow_users: Vec<String>,
    pub sid_ch: mpsc::Sender<String>,
}

/// Active NAT hole-punch session between visitor and provider.
pub struct Session {
    pub sid: String,
    pub proxy_name: String,

    // Visitor side
    pub visitor_msg: msg::NatHoleVisitor,
    pub visitor_writer: Mutex<Option<Box<dyn AsyncWrite + Send + Unpin>>>,
    pub visitor_ctl_tx: Option<mpsc::Sender<InternalMsg>>,
    pub v_resp: Mutex<Option<msg::NatHoleResp>>,
    pub v_nat_feature: Mutex<Option<NatFeature>>,

    // Provider side
    pub client_msg: Mutex<Option<msg::NatHoleClient>>,
    pub c_resp: Mutex<Option<msg::NatHoleResp>>,
    pub c_nat_feature: Mutex<Option<NatFeature>>,

    // Coordination
    pub notify_ch: Mutex<Option<oneshot::Sender<()>>>,
    pub report_tx: Mutex<Option<oneshot::Sender<msg::NatHoleReport>>>,
    pub created_at: Instant,
    /// Last activity timestamp for expiry (updated on handle_client and handle_report).
    pub last_activity: std::sync::Mutex<Instant>,
    /// Selected behavior index from get_recommend_behaviors, stored for report_success feedback.
    pub selected_index: Mutex<Option<i32>>,
    /// Analysis key for report_success lookup. Set during analysis, reused during reporting.
    pub analysis_key: std::sync::Mutex<Option<String>>,
}

/// Number of shards the session table is split into (audit Phase 2 item 5).
///
/// 16 is enough to make a single shard's lock a non-issue at the table's
/// 256-session cap (16 sessions per shard on average) while keeping the
/// janitor's per-shard sweep cheap.
pub const SESSION_SHARDS: usize = 16;

/// Shard index for a session id.
///
/// `sid` is a client-generated UUID, so any decent hash spreads it uniformly;
/// `DefaultHasher` is std (no new dependency) and uses fixed keys, i.e. it is
/// deterministic for a given sid both within and across processes — a sid
/// always maps to the same shard, which is what makes every lookup routable
/// without consulting the other shards.
fn shard_index(sid: &str) -> usize {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    sid.hash(&mut hasher);
    (hasher.finish() % SESSION_SHARDS as u64) as usize
}

/// Sharded session table: `sid` → session, split across `SESSION_SHARDS`
/// independently locked maps.
///
/// The single `RwLock<HashMap<..>>` this replaces was one contention point for
/// every XTCP session operation (audit TOP 3): a scan on one side of the table
/// serialized with a removal on the other, and vice versa. Sharding keeps the
/// same operations and the same end state, but a lookup/insert/remove now only
/// ever waits on its own shard.
///
/// The global `MAX_SESSIONS` cap is preserved exactly by `total`, an atomic
/// reservation counter: the slot is taken (CAS) *before* the shard insert, so
/// two concurrent inserts can never both slip past the cap, and the counter is
/// released only when a removal actually took an entry out of a shard.
pub struct SessionTable {
    shards: [RwLock<HashMap<String, Arc<Session>>>; SESSION_SHARDS],
    /// Live reservations (sessions in a shard, plus inserts in flight between
    /// their CAS and their shard lock). O(1) global count without a global
    /// lock.
    total: AtomicUsize,
}

impl SessionTable {
    pub fn new() -> Self {
        SessionTable {
            shards: std::array::from_fn(|_| RwLock::new(HashMap::new())),
            total: AtomicUsize::new(0),
        }
    }

    /// The owning shard of `sid` — the only shard any `sid`-addressed
    /// operation touches.
    fn shard(&self, sid: &str) -> &RwLock<HashMap<String, Arc<Session>>> {
        &self.shards[shard_index(sid)]
    }

    /// All shards, for the janitor's sweep (and lock-shape tests).
    pub(crate) fn shards(&self) -> &[RwLock<HashMap<String, Arc<Session>>>] {
        &self.shards
    }

    /// Reserved session count. O(1); may briefly count an insert that has
    /// reserved its slot but not yet taken its shard lock.
    pub fn count(&self) -> usize {
        self.total.load(Ordering::Acquire)
    }

    /// True when no session is live (nothing reserved, nothing inserted).
    pub fn is_empty(&self) -> bool {
        self.total.load(Ordering::Acquire) == 0
    }

    /// Look up a session, cloning its `Arc` under the shard read lock. The
    /// shard lock is released before the caller touches any per-session lock.
    pub async fn get(&self, sid: &str) -> Option<Arc<Session>> {
        self.shard(sid).read().await.get(sid).cloned()
    }

    /// Run `f` with the session, holding the shard read lock for the duration.
    /// `f` must be synchronous (no await): the shard lock is a table lock and
    /// must never be held across a per-session await.
    pub async fn with_session<R>(
        &self,
        sid: &str,
        f: impl FnOnce(&Arc<Session>) -> R,
    ) -> Option<R> {
        let shard = self.shard(sid).read().await;
        shard.get(sid).map(f)
    }

    /// Reserve a slot against the global cap and insert the session into its
    /// shard. Returns `false` when the table is at `MAX_SESSIONS` — nothing is
    /// inserted and the caller owns rejection.
    pub async fn insert(&self, sid: String, session: Arc<Session>) -> bool {
        if self
            .total
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                (n < MAX_SESSIONS).then_some(n + 1)
            })
            .is_err()
        {
            return false;
        }
        // Armed until the entry lands: a create cancelled while waiting for
        // the shard lock must not leak a permanent slot against the cap.
        let mut slot = ReservedSlot {
            total: &self.total,
            consumed: false,
        };
        // Insert under the owning shard's write lock only.
        let replaced = self
            .shard(&sid)
            .write()
            .await
            .insert(sid, session)
            .is_some();
        // A landed insert is what the reservation now counts — unless it
        // replaced an existing sid, where the entry count did not change and
        // the extra reservation has to go back.
        slot.consumed = !replaced;
        true
    }

    /// Remove a session. The shard write lock is released before this returns,
    /// so callers may await per-session locks afterwards (audit §3 item 2).
    pub async fn remove(&self, sid: &str) -> Option<Arc<Session>> {
        let removed = self.shard(sid).write().await.remove(sid);
        if removed.is_some() {
            self.total.fetch_sub(1, Ordering::AcqRel);
        }
        removed
    }
}

impl Default for SessionTable {
    fn default() -> Self {
        Self::new()
    }
}

/// Releases a `MAX_SESSIONS` reservation unless a landed insert consumed it.
/// The drop path covers an insert future cancelled while it waited for its
/// shard lock.
struct ReservedSlot<'a> {
    total: &'a AtomicUsize,
    consumed: bool,
}

impl Drop for ReservedSlot<'_> {
    fn drop(&mut self) {
        if !self.consumed {
            self.total.fetch_sub(1, Ordering::AcqRel);
        }
    }
}

/// Central XTCP NAT hole punch controller.
pub struct Controller {
    pub client_cfgs: RwLock<HashMap<String, ClientCfg>>,
    pub sessions: SessionTable,
    pub analyzer: Analyzer,
}

impl Controller {
    pub fn new(analysis_data_reserve_duration: Duration) -> Self {
        Controller {
            client_cfgs: RwLock::new(HashMap::new()),
            sessions: SessionTable::new(),
            analyzer: Analyzer::new(analysis_data_reserve_duration),
        }
    }

    /// Register a provider (XTCP proxy).
    pub async fn listen_client(
        &self,
        name: String,
        sk: String,
        allow_users: Vec<String>,
    ) -> Result<mpsc::Receiver<String>, String> {
        let (tx, rx) = mpsc::channel(64);
        let cfg = ClientCfg {
            name: name.clone(),
            sk,
            allow_users,
            sid_ch: tx,
        };
        let mut cfgs = self.client_cfgs.write().await;
        if cfgs.contains_key(&name) {
            return Err(format!("proxy [{}] is repeated", name));
        }
        cfgs.insert(name, cfg);
        Ok(rx)
    }

    // NOTE: Go frp's `CloseClient` (server/proxy/xtcp.go:98, called from
    // proxy close) has NO counterpart here by design: frp-rs never registers
    // providers in `client_cfgs` — `listen_client`/`notify_provider` have
    // zero callers and the visitor path resolves providers via
    // `proxy_manager`/`run_id_to_ctl_tx` (dispatch.rs handle_nat_hole_visitor)
    // instead, which `unregister_control` already cleans up on control exit.
    // Wiring CloseClient here would be a no-op on a permanently empty map.
    // Go sessions are deleted by the visitor's own goroutine
    // (`defer delete(c.sessions, sid)` — controller.go newSessionForVisitor),
    // not by provider close; frp-rs sessions are likewise owned by the
    // visitor/control paths (NAT_HOLE_TIMEOUT + session completion), so the
    // "cleanup orphaned sessions" half has nothing to add either.

    /// Notify a provider about a new visitor (send sid to provider).
    pub async fn notify_provider(&self, name: &str, sid: &str) -> Result<(), String> {
        let cfgs = self.client_cfgs.read().await;
        let cfg = cfgs
            .get(name)
            .ok_or_else(|| format!("xtcp server for [{}] doesn't exist", name))?;
        cfg.sid_ch
            .try_send(sid.to_string())
            .map_err(|_| format!("provider [{}] channel closed", name))
    }

    /// Create a session with a visitor writer (fresh connection path).
    /// Returns `Err` when the global session cap is reached.
    pub async fn create_session_with_writer(
        &self,
        sid: String,
        proxy_name: String,
        visitor_msg: msg::NatHoleVisitor,
        writer: Box<dyn AsyncWrite + Send + Unpin>,
    ) -> Result<(Arc<Session>, oneshot::Receiver<msg::NatHoleReport>), String> {
        let (report_tx, report_rx) = oneshot::channel();
        let session = Arc::new(Session {
            sid: sid.clone(),
            proxy_name,
            visitor_msg,
            visitor_writer: Mutex::new(Some(writer)),
            visitor_ctl_tx: None,
            v_resp: Mutex::new(None),
            v_nat_feature: Mutex::new(None),
            client_msg: Mutex::new(None),
            c_resp: Mutex::new(None),
            c_nat_feature: Mutex::new(None),
            notify_ch: Mutex::new(None), // caller sets up before notifying provider
            report_tx: Mutex::new(Some(report_tx)),
            created_at: Instant::now(),
            last_activity: std::sync::Mutex::new(Instant::now()),
            selected_index: Mutex::new(None),
            analysis_key: std::sync::Mutex::new(None),
        });
        // Reserve-and-insert stays atomic (TOCTOU-free) without a table-wide
        // lock: the slot is CAS-reserved against the global cap, then the
        // session goes into its own shard.
        if !self.sessions.insert(sid.clone(), session.clone()).await {
            warn!(
                max_sessions = MAX_SESSIONS,
                "NAT hole session limit reached ({MAX_SESSIONS}), rejecting new session"
            );
            // Send the error response to the visitor so it doesn't hang. No
            // table lock is held here at all, so a wedged visitor TCP buffer
            // cannot stall any other XTCP session operation while blocked on
            // this write.
            let rejection = FrpMessage::NatHoleResp(Box::new(msg::NatHoleResp {
                transaction_id: session.visitor_msg.transaction_id.clone(),
                sid: Some(sid.clone()),
                error: Some("NAT hole session limit reached".into()),
                ..Default::default()
            }));
            let mut guard = session.visitor_writer.lock().await;
            if let Some(ref mut w) = *guard {
                // Best-effort: the session is rejected either way, so a failed
                // write to the wedged visitor is not actionable.
                let _ = frp_core::protocol::write_v1_frame(w, &rejection).await;
            }
            return Err(format!("NAT hole session limit reached ({MAX_SESSIONS})"));
        }
        Ok((session, report_rx))
    }

    /// Create a session for the control-connection path (Go frp compat).
    /// Returns `Err` when the global session cap is reached.
    pub async fn create_session_with_ctl(
        &self,
        sid: String,
        proxy_name: String,
        visitor_msg: msg::NatHoleVisitor,
        visitor_ctl_tx: mpsc::Sender<InternalMsg>,
    ) -> Result<(Arc<Session>, oneshot::Receiver<msg::NatHoleReport>), String> {
        let (report_tx, report_rx) = oneshot::channel();
        // NOTE: The notify_ch oneshot created here is set up for use by the
        // caller; the _notify_rx receiver may be replaced. The initial oneshot
        // allocation is intentional (API symmetry with create_session).
        let (notify_tx, _notify_rx) = oneshot::channel();
        let session = Arc::new(Session {
            sid: sid.clone(),
            proxy_name,
            visitor_msg,
            visitor_writer: Mutex::new(None),
            visitor_ctl_tx: Some(visitor_ctl_tx),
            v_resp: Mutex::new(None),
            v_nat_feature: Mutex::new(None),
            client_msg: Mutex::new(None),
            c_resp: Mutex::new(None),
            c_nat_feature: Mutex::new(None),
            notify_ch: Mutex::new(Some(notify_tx)),
            report_tx: Mutex::new(Some(report_tx)),
            created_at: Instant::now(),
            last_activity: std::sync::Mutex::new(Instant::now()),
            selected_index: Mutex::new(None),
            analysis_key: std::sync::Mutex::new(None),
        });
        // Reserve-and-insert stays atomic (TOCTOU-free) without a table-wide
        // lock: the slot is CAS-reserved against the global cap, then the
        // session goes into its own shard.
        if !self.sessions.insert(sid.clone(), session.clone()).await {
            warn!(
                max_sessions = MAX_SESSIONS,
                "NAT hole session limit reached ({MAX_SESSIONS}), rejecting new session"
            );
            // Send error response via control channel so visitor doesn't hang.
            if let Some(ref tx) = session.visitor_ctl_tx {
                let _ = tx.try_send(InternalMsg::WriteNatHoleResp {
                    transaction_id: session.visitor_msg.transaction_id.clone(),
                    error: Some("NAT hole session limit reached".into()),
                    sid: Some(sid.clone()),
                    protocol: None,
                    candidate_addrs: None,
                    assisted_addrs: None,
                    detect_behavior: None,
                });
            }
            return Err(format!("NAT hole session limit reached ({MAX_SESSIONS})"));
        }
        Ok((session, report_rx))
    }

    /// Handle the provider's NatHoleClient response (with STUN addresses).
    /// Signals the session's notify channel so the waiting HandleVisitor can proceed.
    #[instrument(skip(self, msg), fields(transaction_id = %msg.transaction_id, sid = ?msg.sid))]
    pub async fn handle_client(&self, msg: msg::NatHoleClient) {
        if let Some(ref sid) = msg.sid {
            // Clone Arc<Session> while holding the shard read lock, then drop
            // it before acquiring per-session mutexes to avoid blocking
            // writers.
            let session = self.sessions.get(sid).await;
            if let Some(session) = session {
                trace!(
                    sid = %sid,
                    proxy_name = %msg.proxy_name,
                    "handle client message, sid [{}], proxy: {}",
                    sid,
                    msg.proxy_name
                );
                *session.client_msg.lock().await = Some(msg);
                *session
                    .last_activity
                    .lock()
                    .unwrap_or_else(|e| e.into_inner()) = Instant::now();
                // Signal the waiting HandleVisitor
                if let Some(notify) = session.notify_ch.lock().await.take() {
                    let _ = notify.send(());
                }
            }
        }
    }

    /// Handle NatHoleReport from provider.
    pub async fn handle_report(&self, msg: &msg::NatHoleReport) {
        if let Some(sid) = msg.sid.as_deref() {
            // Clone Arc<Session> while holding the shard read lock, then drop
            // it before acquiring per-session mutexes to avoid blocking
            // writers.
            let session = self.sessions.get(sid).await;
            if let Some(session) = session {
                *session
                    .last_activity
                    .lock()
                    .unwrap_or_else(|e| e.into_inner()) = Instant::now();
                // Report success to analyzer — only when the provider
                // reports the hole punch actually succeeded (Go frp compat:
                // HandleReport only calls ReportSuccess when m.Success is true).
                if msg.success {
                    let v_resp = session.v_resp.lock().await;
                    if let Some(ref resp) = *v_resp {
                        if let Some(ref db) = resp.detect_behavior {
                            // Use stored analysis key set during get_recommend_behaviors.
                            // Go frp compat: genAnalysisKey includes mapped IPs, so the
                            // key must match the one used when the recommendation was made.
                            let key = session
                                .analysis_key
                                .lock()
                                .unwrap_or_else(|e| e.into_inner())
                                .clone()
                                .unwrap_or_default();
                            let index = *session.selected_index.lock().await;
                            self.analyzer
                                .report_success(&key, db.mode, index.unwrap_or(0));
                        }
                    }
                }
            }
        }
    }

    /// Complete a session and clean up.
    ///
    /// The session leaves its shard under that shard's write lock, but the
    /// per-session locks are taken only AFTER it is released (audit §3 item 2
    /// / HIGH #3): awaiting another task's `visitor_writer` mutex while
    /// holding a table lock parked every other session operation behind this
    /// one. Sharding narrows that to the session's own shard, and the lock is
    /// still dropped before the first per-session await. A concurrent task can
    /// only hold the removed session's `Arc` from an earlier lookup; the
    /// fields it touches are still individually mutex-protected, and the end
    /// state (writer dropped, connection closed) is unchanged.
    pub async fn complete(&self, sid: &str) -> Option<String> {
        let session = self.sessions.remove(sid).await?;

        // Drop visitor writer (closes connection)
        let mut guard = session.visitor_writer.lock().await;
        drop(guard.take());
        drop(guard);

        // Signal report
        if let Some(tx) = session.report_tx.lock().await.take() {
            let _ = tx.send(msg::NatHoleReport {
                sid: Some(sid.to_string()),
                success: false,
            });
        }
        Some(session.proxy_name.clone())
    }

    /// Remove a session without signalling.
    pub async fn remove(&self, sid: &str) {
        self.sessions.remove(sid).await;
    }

    /// Remove expired sessions.
    ///
    /// Expired ids are collected under a READ lock and removed one by one
    /// (audit §3 item 2): the scan needs no exclusive access, and the
    /// removals do not depend on each other. Expiry is monotonic —
    /// `last_activity` only ever advances — so a session that was stale at
    /// scan time is still stale when its removal runs.
    ///
    /// Sharded (audit Phase 2 item 5): the sweep walks one shard at a time and
    /// never holds more than one shard lock, so the 60s janitor cannot stall
    /// the whole table. Each shard keeps the same scan-then-remove shape — its
    /// read guard is released before its removals run, which route back to
    /// that same shard. A session inserted into an already-swept shard during
    /// this pass survives to the next one, exactly as a session inserted after
    /// the old single scan did.
    pub async fn expire_sessions(&self, timeout: Duration) {
        let now = Instant::now();
        for shard in self.sessions.shards() {
            let expired: Vec<String> = {
                let sessions = shard.read().await;
                sessions
                    .iter()
                    .filter(|(_sid, s)| {
                        let last = *s.last_activity.lock().unwrap_or_else(|e| e.into_inner());
                        now.duration_since(last) >= timeout
                    })
                    .map(|(sid, _)| sid.clone())
                    .collect()
            };
            for sid in expired {
                self.remove(&sid).await;
            }
        }
    }

    // --- Backward-compat methods matching old NatHoleCoordinator API ---

    /// Take the visitor writer for a session (accept-loop path).
    ///
    /// The shard read lock is dropped before the per-session writer lock is
    /// awaited (audit TOP 3): holding the table lock across it turned every
    /// bridge write into table-wide write starvation.
    pub async fn take_writer(&self, sid: &str) -> Option<Box<dyn AsyncWrite + Send + Unpin>> {
        let session = self.sessions.get(sid).await?;
        let mut guard = session.visitor_writer.lock().await;
        guard.take()
    }

    /// Return the writer back to the session after use.
    pub async fn return_writer(&self, sid: &str, writer: Box<dyn AsyncWrite + Send + Unpin>) {
        if let Some(session) = self.sessions.get(sid).await {
            *session.visitor_writer.lock().await = Some(writer);
        }
    }

    /// Forward NatHoleSid to the visitor via control channel.
    /// Returns true if forwarded via ctl path.
    pub async fn forward_sid_via_ctl(&self, sid: &str) -> bool {
        let tx = self
            .sessions
            .get(sid)
            .await
            .and_then(|s| s.visitor_ctl_tx.clone());
        if let Some(tx) = tx {
            // Protocol-critical one-shot message: use send().await for
            // reliable delivery. try_send Full would silently drop the
            // NAT hole punch handshake, breaking XTCP setup.
            let _ = tx
                .send(InternalMsg::WriteNatHoleSid {
                    sid: sid.to_string(),
                })
                .await;
            return true;
        }
        false
    }

    /// Forward NatHoleResp to the visitor via control channel.
    #[allow(clippy::too_many_arguments)]
    pub async fn forward_nat_hole_resp_via_ctl(
        &self,
        sid: &str,
        error: Option<String>,
        resp_sid: Option<String>,
        protocol: Option<String>,
        candidate_addrs: Option<Vec<String>>,
        assisted_addrs: Option<Vec<String>>,
        detect_behavior: Option<msg::NatHoleDetectBehavior>,
    ) -> bool {
        let tx = self
            .sessions
            .get(sid)
            .await
            .and_then(|s| s.visitor_ctl_tx.clone());
        if let Some(tx) = tx {
            let _ = tx
                .send(InternalMsg::WriteNatHoleResp {
                    transaction_id: sid.to_string(),
                    error,
                    sid: resp_sid,
                    protocol,
                    candidate_addrs,
                    assisted_addrs,
                    detect_behavior,
                })
                .await;
            return true;
        }
        false
    }

    /// Forward NatHoleReport to the visitor via control channel.
    pub async fn forward_report_via_ctl(&self, sid: &str) -> bool {
        let tx = self
            .sessions
            .get(sid)
            .await
            .and_then(|s| s.visitor_ctl_tx.clone());
        if let Some(tx) = tx {
            let _ = tx
                .send(InternalMsg::WriteNatHoleReport {
                    sid: sid.to_string(),
                })
                .await;
            return true;
        }
        false
    }
}

/// Extract the IP portion from an "ip:port" address string.
/// Handles IPv4 ("1.2.3.4:1234") and bracketed IPv6 ("[::1]:8080").
fn extract_ip_from_addr(addr: &str) -> Option<String> {
    let addr = addr.trim();
    if addr.is_empty() {
        return None;
    }
    if addr.starts_with('[') {
        // Bracketed IPv6: [::1]:8080
        let close = addr.find(']')?;
        Some(addr[1..close].to_string())
    } else {
        // IPv4 or hostname — split on last ':'
        let colon = addr.rfind(':')?;
        Some(addr[..colon].to_string())
    }
}

/// Generate a stable analysis key from two NAT features for analyzer lookup.
/// Go frp v0.70.1 compat: controller.go genAnalysisKey() uses a single MD5
/// over visitorIP + visitorNatType + visitorBehavior + visitorRegularPortsChange
/// + clientIP + clientNatType + clientBehavior + clientRegularPortsChange,
///   then hex-encodes the result.
pub fn gen_analysis_key(
    c: &NatFeature,
    v: &NatFeature,
    client_mapped: &[String],
    visitor_mapped: &[String],
) -> String {
    use md5::{Digest, Md5};
    let mut hash = Md5::new();

    // Go frp genAnalysisKey order: visitor fields first, then client fields.
    let v_ip = visitor_mapped
        .first()
        .and_then(|a| extract_ip_from_addr(a))
        .unwrap_or_default();
    hash.update(v_ip.as_bytes());
    hash.update(v.nat_type.as_bytes());
    hash.update(v.behavior.as_bytes());
    hash.update(v.regular_ports_change.to_string().as_bytes());

    let c_ip = client_mapped
        .first()
        .and_then(|a| extract_ip_from_addr(a))
        .unwrap_or_default();
    hash.update(c_ip.as_bytes());
    hash.update(c.nat_type.as_bytes());
    hash.update(c.behavior.as_bytes());
    hash.update(c.regular_ports_change.to_string().as_bytes());

    frp_core::hex_encode(hash.finalize().as_slice())
}

/// Parameters for building a NatHoleResp message.
pub struct NatHoleResponseParams {
    pub transaction_id: String,
    pub sid: String,
    pub protocol: Option<String>,
    pub mode: i32,
    pub candidate_addrs: Vec<String>,
    pub assisted_addrs: Vec<String>,
    pub behavior: RecommendBehavior,
    pub read_timeout_ms: i32,
    pub ports_difference: i32,
}

/// Build a NatHoleResp with detect_behavior filled in.
/// Go frp v0.69.1 compat: newNatHoleResponse in controller.go
pub fn build_nat_hole_response(params: NatHoleResponseParams) -> msg::NatHoleResp {
    let NatHoleResponseParams {
        transaction_id,
        sid,
        protocol,
        mode,
        candidate_addrs,
        assisted_addrs,
        behavior,
        read_timeout_ms,
        ports_difference,
    } = params;
    let compact_candidates: Vec<String> = {
        let mut seen = std::collections::HashSet::new();
        candidate_addrs
            .into_iter()
            .filter(|a| seen.insert(a.clone()))
            .collect()
    };
    let compact_assisted: Vec<String> = {
        let mut seen = std::collections::HashSet::new();
        assisted_addrs
            .into_iter()
            .filter(|a| seen.insert(a.clone()))
            .collect()
    };

    let candidate_ports = if behavior.ports_range_number > 0 {
        if let Some(last_addr) = compact_candidates.last() {
            if let Some(port_str) = last_addr.rsplit(':').next() {
                if let Ok(port) = port_str.parse::<i32>() {
                    let from = (port - ports_difference - 5)
                        .max(port - behavior.ports_range_number)
                        .max(1);
                    let to = (port + ports_difference + 5)
                        .min(port + behavior.ports_range_number)
                        .min(65535);
                    Some(vec![PortsRange { from, to }])
                } else {
                    None
                }
            } else {
                None
            }
        } else {
            None
        }
    } else {
        None
    };

    msg::NatHoleResp {
        transaction_id,
        error: None,
        sid: Some(sid),
        protocol,
        candidate_addrs: if compact_candidates.is_empty() {
            None
        } else {
            Some(compact_candidates)
        },
        assisted_addrs: if compact_assisted.is_empty() {
            None
        } else {
            Some(compact_assisted)
        },
        detect_behavior: Some(NatHoleDetectBehavior {
            mode,
            role: Some(behavior.role),
            ttl: behavior.ttl,
            send_delay_ms: behavior.send_delay_ms,
            read_timeout_ms,
            send_random_ports: behavior.ports_random_number,
            listen_random_ports: behavior.listen_random_ports,
            candidate_ports,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::pin::Pin;
    use std::task::{Context, Poll};

    /// A writer whose write never completes — simulates a visitor with a
    /// wedged TCP send buffer.
    struct WedgedWriter {
        /// Fires on the first write attempt so the test can observe the
        /// rejection write in flight.
        started: Option<tokio::sync::oneshot::Sender<()>>,
    }

    impl Unpin for WedgedWriter {}

    impl AsyncWrite for WedgedWriter {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &[u8],
        ) -> Poll<Result<usize, std::io::Error>> {
            if let Some(tx) = self.started.take() {
                let _ = tx.send(());
            }
            Poll::Pending
        }
        fn poll_flush(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), std::io::Error>> {
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), std::io::Error>> {
            Poll::Ready(Ok(()))
        }
    }

    fn dummy_session(sid: &str) -> Arc<Session> {
        let (notify_tx, _notify_rx) = tokio::sync::oneshot::channel();
        let (report_tx, _report_rx) = tokio::sync::oneshot::channel();
        Arc::new(Session {
            sid: sid.to_string(),
            proxy_name: "filler".to_string(),
            visitor_msg: msg::NatHoleVisitor::default(),
            visitor_writer: Mutex::new(None),
            visitor_ctl_tx: None,
            v_resp: Mutex::new(None),
            v_nat_feature: Mutex::new(None),
            client_msg: Mutex::new(None),
            c_resp: Mutex::new(None),
            c_nat_feature: Mutex::new(None),
            notify_ch: Mutex::new(Some(notify_tx)),
            report_tx: Mutex::new(Some(report_tx)),
            created_at: Instant::now(),
            last_activity: std::sync::Mutex::new(Instant::now()),
            selected_index: Mutex::new(None),
            analysis_key: std::sync::Mutex::new(None),
        })
    }

    /// A sid that lands on `target` shard. `shard_index` is a pure hash of the
    /// sid, so tests can pin sessions to chosen shards without knowing it.
    fn sid_for_shard(target: usize, salt: &str) -> String {
        for i in 0..10_000 {
            let sid = format!("sid-{salt}-{target}-{i}");
            if shard_index(&sid) == target {
                return sid;
            }
        }
        panic!("no sid landed on shard {target}");
    }

    /// Is `sid` present in the shard it hashes to?
    async fn table_contains(controller: &Controller, sid: &str) -> bool {
        controller
            .sessions
            .shard(sid)
            .read()
            .await
            .contains_key(sid)
    }

    /// Regression: rejecting a session at MAX_SESSIONS must not hold a
    /// `sessions` lock across the rejection write to the visitor — a wedged
    /// visitor TCP buffer must not stall all other XTCP session operations.
    /// The rejection frame is written after the cap check, and the cap check
    /// itself is an atomic reservation, so no shard lock exists to hold.
    #[tokio::test]
    async fn max_sessions_rejection_does_not_hold_lock_across_write() {
        let controller = Arc::new(Controller::new(Duration::from_secs(3600)));
        // Fill the session table to the cap.
        for i in 0..MAX_SESSIONS {
            let sid = format!("filler-{i}");
            assert!(
                controller
                    .sessions
                    .insert(sid.clone(), dummy_session(&sid))
                    .await
            );
        }
        assert_eq!(controller.sessions.count(), MAX_SESSIONS);
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let writer: Box<dyn AsyncWrite + Send + Unpin> = Box::new(WedgedWriter {
            started: Some(started_tx),
        });
        let ctl = controller.clone();
        let handle = tokio::spawn(async move {
            ctl.create_session_with_writer(
                "rejected".to_string(),
                "xtcp-test".to_string(),
                msg::NatHoleVisitor::default(),
                writer,
            )
            .await
        });
        // Wait until the rejection write to the wedged visitor is in flight.
        started_rx
            .await
            .expect("rejection write to wedged visitor started");
        // Every shard lock must be acquirable while the write is blocked.
        tokio::time::timeout(Duration::from_millis(500), async {
            for shard in controller.sessions.shards() {
                let _held = shard.read().await;
            }
        })
        .await
        .expect("a sessions shard lock held across the rejection write");
        // The create call is still stuck on the wedged write (not completed).
        assert!(
            !handle.is_finished(),
            "rejection task should still be writing"
        );
        handle.abort();
    }

    /// Regression (audit §3 item 2 / HIGH #3): `complete` must drop its shard
    /// write lock BEFORE it awaits the per-session locks. Holding the table
    /// lock across them parked every other session operation in the table —
    /// and compounded with the visitor-writer lock being taken for network
    /// writes elsewhere.
    #[tokio::test]
    async fn complete_releases_sessions_lock_before_per_session_lock() {
        let controller = Arc::new(Controller::new(Duration::from_secs(3600)));
        let session = dummy_session("sid-1");
        assert!(
            controller
                .sessions
                .insert("sid-1".to_string(), session.clone())
                .await
        );

        // Park the session's writer lock the way a bridge write would.
        let held = session.visitor_writer.lock().await;

        let ctl = controller.clone();
        let handle = tokio::spawn(async move { ctl.complete("sid-1").await });

        // The entry must be gone while the completion is still parked on the
        // writer lock — proof the shard lock was released first. On the old
        // shape (table lock held across the per-session await) this poll times
        // out.
        let removed = tokio::time::timeout(Duration::from_secs(5), async {
            while table_contains(&controller, "sid-1").await {
                tokio::task::yield_now().await;
            }
        })
        .await;
        assert!(
            removed.is_ok(),
            "sessions shard lock held across the per-session lock"
        );
        assert!(
            !handle.is_finished(),
            "completion should still be waiting on the writer lock"
        );

        // Releasing it lets the completion finish and report the session.
        drop(held);
        assert_eq!(handle.await.unwrap(), Some("filler".to_string()));
    }

    /// `expire_sessions` drops stale sessions and keeps fresh ones (the scan
    /// runs under a shard read lock, the removals one by one under that
    /// shard's write lock).
    #[tokio::test]
    async fn expire_sessions_removes_stale_keeps_fresh() {
        let controller = Controller::new(Duration::from_secs(3600));
        let stale = dummy_session("stale");
        assert!(
            controller
                .sessions
                .insert("stale".to_string(), stale.clone())
                .await
        );
        assert!(
            controller
                .sessions
                .insert("fresh".to_string(), dummy_session("fresh"))
                .await
        );
        // Scope the std-Mutex guard: it must be released before the await.
        // `expire_sessions` locks the same `last_activity` mutex synchronously
        // while scanning, so leaving the guard alive across the await parks the
        // current-thread test runtime forever.
        {
            let mut last = stale
                .last_activity
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            *last = Instant::now() - Duration::from_secs(120);
        }

        controller.expire_sessions(Duration::from_secs(60)).await;

        assert!(
            !table_contains(&controller, "stale").await,
            "stale session must expire"
        );
        assert!(
            table_contains(&controller, "fresh").await,
            "fresh session must survive"
        );
    }

    /// Sharding sanity (audit Phase 2 item 5): UUID-shaped ids must spread
    /// across every shard, and a stored session must be reachable through the
    /// shard its hash predicts. A degenerate hash would quietly put every
    /// session back behind one lock — the exact contention point the sharded
    /// table exists to remove.
    #[tokio::test]
    async fn session_table_spreads_sids_across_shards() {
        // Deterministic UUID-shaped ids: `shard_index` is a fixed hash, so the
        // distribution below is deterministic too (no rng, no flake).
        let sids: Vec<String> = (0..512u32)
            .map(|i| format!("{i:08x}-{i:04x}-{i:04x}-{i:04x}-{i:012x}"))
            .collect();
        let mut per_shard = [0usize; SESSION_SHARDS];
        for sid in &sids {
            per_shard[shard_index(sid)] += 1;
        }
        let occupied = per_shard.iter().filter(|n| **n > 0).count();
        assert_eq!(
            occupied, SESSION_SHARDS,
            "every shard must be used, got {per_shard:?}"
        );
        // 512 ids over 16 shards: 32 expected per shard. The band only has to
        // catch a hash that piles sessions onto a few shards.
        let max = *per_shard.iter().max().unwrap();
        assert!(max <= 96, "poor shard balance: {per_shard:?}");

        // Insert routes to the owning shard and nowhere else.
        let controller = Controller::new(Duration::from_secs(3600));
        let sid = sids[0].clone();
        assert!(
            controller
                .sessions
                .insert(sid.clone(), dummy_session(&sid))
                .await
        );
        let owner = shard_index(&sid);
        assert!(controller
            .sessions
            .shards()
            .get(owner)
            .unwrap()
            .read()
            .await
            .contains_key(&sid));
        for (i, shard) in controller.sessions.shards().iter().enumerate() {
            if i != owner {
                assert!(
                    shard.read().await.get(&sid).is_none(),
                    "sid must live in exactly one shard ({owner}), found in {i}"
                );
            }
        }
        assert_eq!(controller.sessions.count(), 1);
    }

    /// Sharding (audit Phase 2 item 5): `complete` drops the session from its
    /// OWN shard and releases that shard's lock before it awaits the
    /// per-session locks, so a session parked on a bridge write cannot block
    /// the rest of the table. Pinned by expiring a stale session on a
    /// DIFFERENT shard while the completion is still parked.
    #[tokio::test]
    async fn complete_removes_from_owning_shard_and_releases_shard_lock() {
        let controller = Arc::new(Controller::new(Duration::from_secs(3600)));
        let parked_sid = sid_for_shard(0, "parked");
        let stale_sid = sid_for_shard(1, "stale");
        assert_ne!(shard_index(&parked_sid), shard_index(&stale_sid));

        let parked = dummy_session(&parked_sid);
        assert!(
            controller
                .sessions
                .insert(parked_sid.clone(), parked.clone())
                .await
        );
        let stale = dummy_session(&stale_sid);
        assert!(
            controller
                .sessions
                .insert(stale_sid.clone(), stale.clone())
                .await
        );
        // Age the other-shard session past the janitor timeout, scoping the
        // std-Mutex guard so it is released before any await.
        {
            let mut last = stale
                .last_activity
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            *last = Instant::now() - Duration::from_secs(120);
        }
        assert!(table_contains(&controller, &stale_sid).await);

        // Park the session's writer lock the way a bridge write would.
        let held = parked.visitor_writer.lock().await;

        let ctl = controller.clone();
        let sid = parked_sid.clone();
        let handle = tokio::spawn(async move { ctl.complete(&sid).await });

        // The entry must be gone from its own shard while the completion is
        // still parked on the writer lock — proof the shard lock was released
        // first.
        let removed = tokio::time::timeout(Duration::from_secs(5), async {
            while table_contains(&controller, &parked_sid).await {
                tokio::task::yield_now().await;
            }
        })
        .await;
        assert!(
            removed.is_ok(),
            "shard write lock held across the per-session lock"
        );
        assert!(
            !handle.is_finished(),
            "completion should still be waiting on the writer lock"
        );

        // The shard's write lock is free too (not held across the await)...
        {
            let guard = tokio::time::timeout(
                Duration::from_millis(500),
                controller.sessions.shard(&parked_sid).write(),
            )
            .await
            .expect("shard write lock held across the per-session await");
            assert!(!guard.contains_key(&parked_sid));
        }

        // ... and the janitor keeps making progress on the other shards.
        controller.expire_sessions(Duration::from_secs(60)).await;
        assert!(
            !table_contains(&controller, &stale_sid).await,
            "expiry must proceed on other shards while complete() is parked"
        );

        // Releasing it lets the completion finish and report the session.
        drop(held);
        assert_eq!(handle.await.unwrap(), Some("filler".to_string()));
        assert!(!table_contains(&controller, &parked_sid).await);
    }

    /// Sharding (audit Phase 2 item 5): the janitor sweeps every shard — one
    /// stale session per shard expires, and the fresh sibling sharing its
    /// shard survives.
    #[tokio::test]
    async fn expire_sessions_removes_expired_across_all_shards() {
        let controller = Controller::new(Duration::from_secs(3600));
        let mut stale_sids = Vec::new();
        let mut fresh_sids = Vec::new();
        for shard in 0..SESSION_SHARDS {
            let stale_sid = sid_for_shard(shard, "stale");
            let fresh_sid = sid_for_shard(shard, "fresh");
            assert_eq!(shard_index(&stale_sid), shard);
            assert_eq!(shard_index(&fresh_sid), shard);
            let stale = dummy_session(&stale_sid);
            assert!(
                controller
                    .sessions
                    .insert(stale_sid.clone(), stale.clone())
                    .await
            );
            assert!(
                controller
                    .sessions
                    .insert(fresh_sid.clone(), dummy_session(&fresh_sid))
                    .await
            );
            {
                let mut last = stale
                    .last_activity
                    .lock()
                    .unwrap_or_else(|e| e.into_inner());
                *last = Instant::now() - Duration::from_secs(120);
            }
            stale_sids.push(stale_sid);
            fresh_sids.push(fresh_sid);
        }
        // One stale + one fresh session in every shard.
        assert_eq!(controller.sessions.count(), 2 * SESSION_SHARDS);

        controller.expire_sessions(Duration::from_secs(60)).await;

        assert_eq!(
            controller.sessions.count(),
            SESSION_SHARDS,
            "exactly the stale half of every shard must expire"
        );
        for sid in &stale_sids {
            assert!(
                !table_contains(&controller, sid).await,
                "stale {sid} must expire from its shard"
            );
        }
        for sid in &fresh_sids {
            assert!(
                table_contains(&controller, sid).await,
                "fresh {sid} must survive in its shard"
            );
        }
    }
}
