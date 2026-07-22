//! NAT hole punch controller: coordinates XTCP sessions between
//! visitor and provider. Runs NAT classification and analysis to
//! recommend hole-punch behaviors. Go frp v0.69.1 compat: pkg/nathole/controller.go

use std::collections::HashMap;
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

/// Central XTCP NAT hole punch controller.
pub struct Controller {
    pub client_cfgs: RwLock<HashMap<String, ClientCfg>>,
    pub sessions: RwLock<HashMap<String, Arc<Session>>>,
    pub analyzer: Analyzer,
}

impl Controller {
    pub fn new(analysis_data_reserve_duration: Duration) -> Self {
        Controller {
            client_cfgs: RwLock::new(HashMap::new()),
            sessions: RwLock::new(HashMap::new()),
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

    /// Unregister a provider and cleanup orphaned sessions.
    pub async fn close_client(&self, name: &str) {
        self.client_cfgs.write().await.remove(name);
        // Remove any sessions belonging to this provider.
        let mut sessions = self.sessions.write().await;
        sessions.retain(|_sid, session| session.proxy_name != name);
    }

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
        // Check-and-insert atomically under write lock (fixes TOCTOU).
        {
            let mut sessions = self.sessions.write().await;
            if sessions.len() >= MAX_SESSIONS {
                warn!(
                    max_sessions = MAX_SESSIONS,
                    "NAT hole session limit reached ({MAX_SESSIONS}), rejecting new session"
                );
                // Send error response to visitor so it doesn't hang.
                let mut guard = session.visitor_writer.lock().await;
                if let Some(ref mut w) = *guard {
                    let _ = frp_core::protocol::write_v1_frame(
                        w,
                        &FrpMessage::NatHoleResp(Box::new(msg::NatHoleResp {
                            transaction_id: session.visitor_msg.transaction_id.clone(),
                            sid: Some(sid.clone()),
                            error: Some("NAT hole session limit reached".into()),
                            ..Default::default()
                        })),
                    )
                    .await;
                }
                return Err(format!("NAT hole session limit reached ({MAX_SESSIONS})"));
            }
            sessions.insert(sid.clone(), session.clone());
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
        // Check-and-insert atomically under write lock (fixes TOCTOU).
        {
            let mut sessions = self.sessions.write().await;
            if sessions.len() >= MAX_SESSIONS {
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
                    });
                }
                return Err(format!("NAT hole session limit reached ({MAX_SESSIONS})"));
            }
            sessions.insert(sid.clone(), session.clone());
        }
        Ok((session, report_rx))
    }

    /// Handle the provider's NatHoleClient response (with STUN addresses).
    /// Signals the session's notify channel so the waiting HandleVisitor can proceed.
    #[instrument(skip(self, msg), fields(transaction_id = %msg.transaction_id, sid = ?msg.sid))]
    pub async fn handle_client(&self, msg: msg::NatHoleClient) {
        if let Some(ref sid) = msg.sid {
            // Clone Arc<Session> while holding read lock, then drop the lock
            // before acquiring per-session mutexes to avoid blocking writers.
            let session = {
                let sessions = self.sessions.read().await;
                sessions.get(sid).cloned()
            };
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
            // Clone Arc<Session> while holding read lock, then drop the lock
            // before acquiring per-session mutexes to avoid blocking writers.
            let session = {
                let sessions = self.sessions.read().await;
                sessions.get(sid).cloned()
            };
            if let Some(session) = session {
                *session
                    .last_activity
                    .lock()
                    .unwrap_or_else(|e| e.into_inner()) = Instant::now();
                // Report success to analyzer — only when the provider
                // reports the hole punch actually succeeded (Go frp compat:
                // HandleReport only calls ReportSuccess when m.Success is true).
                if msg.success.unwrap_or(false) {
                    let v_resp = session.v_resp.lock().await;
                    if let Some(ref resp) = *v_resp {
                        if let Some(ref db) = resp.detect_behavior {
                            // Use stored analysis key set during get_recommend_behaviors.
                            // Go frp compat: genAnalysisKey includes mapped IPs, so the
                            // key must match the one used when the recommendation was made.
                            let key = session.analysis_key.lock()
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
    pub async fn complete(&self, sid: &str) -> Option<String> {
        let mut sessions = self.sessions.write().await;
        if let Some(session) = sessions.remove(sid) {
            // Drop visitor writer (closes connection)
            let mut guard = session.visitor_writer.lock().await;
            drop(guard.take());
            drop(guard);

            // Signal report
            if let Some(tx) = session.report_tx.lock().await.take() {
                let _ = tx.send(msg::NatHoleReport {
                    sid: Some(sid.to_string()),
                    success: None,
                });
            }
            return Some(session.proxy_name.clone());
        }
        None
    }

    /// Remove a session without signalling.
    pub async fn remove(&self, sid: &str) {
        self.sessions.write().await.remove(sid);
    }

    /// Remove expired sessions.
    pub async fn expire_sessions(&self, timeout: Duration) {
        let now = Instant::now();
        let mut sessions = self.sessions.write().await;
        sessions.retain(|_sid, s| {
            let last = *s.last_activity.lock().unwrap_or_else(|e| e.into_inner());
            now.duration_since(last) < timeout
        });
    }

    // --- Backward-compat methods matching old NatHoleCoordinator API ---

    /// Take the visitor writer for a session (accept-loop path).
    pub async fn take_writer(&self, sid: &str) -> Option<Box<dyn AsyncWrite + Send + Unpin>> {
        let sessions = self.sessions.read().await;
        let session = sessions.get(sid)?;
        let mut guard = session.visitor_writer.lock().await;
        guard.take()
    }

    /// Return the writer back to the session after use.
    pub async fn return_writer(&self, sid: &str, writer: Box<dyn AsyncWrite + Send + Unpin>) {
        let sessions = self.sessions.read().await;
        if let Some(session) = sessions.get(sid) {
            *session.visitor_writer.lock().await = Some(writer);
        }
    }

    /// Forward NatHoleSid to the visitor via control channel.
    /// Returns true if forwarded via ctl path.
    pub async fn forward_sid_via_ctl(&self, sid: &str) -> bool {
        let tx = {
            let sessions = self.sessions.read().await;
            sessions.get(sid).and_then(|s| s.visitor_ctl_tx.clone())
        };
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
    pub async fn forward_nat_hole_resp_via_ctl(
        &self,
        sid: &str,
        error: Option<String>,
        resp_sid: Option<String>,
        protocol: Option<String>,
        candidate_addrs: Option<Vec<String>>,
        assisted_addrs: Option<Vec<String>>,
    ) -> bool {
        let tx = {
            let sessions = self.sessions.read().await;
            sessions.get(sid).and_then(|s| s.visitor_ctl_tx.clone())
        };
        if let Some(tx) = tx {
            let _ = tx
                .send(InternalMsg::WriteNatHoleResp {
                    transaction_id: sid.to_string(),
                    error,
                    sid: resp_sid,
                    protocol,
                    candidate_addrs,
                    assisted_addrs,
                })
                .await;
            return true;
        }
        false
    }

    /// Forward NatHoleReport to the visitor via control channel.
    pub async fn forward_report_via_ctl(&self, sid: &str) -> bool {
        let tx = {
            let sessions = self.sessions.read().await;
            sessions.get(sid).and_then(|s| s.visitor_ctl_tx.clone())
        };
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

/// Generate a stable analysis key from two NAT features for analyzer lookup.
/// Includes the first mapped IP of each peer to distinguish different IP pairs
/// with the same NAT characteristics (Go frp v0.69.1 compat: genAnalysisKey
/// incorporates first IP of each peer's mapped_addrs into the key).
/// Uses a canonical string representation — stable across Rust versions and
/// platforms, and human-readable for debugging.
pub fn gen_analysis_key(c: &NatFeature, v: &NatFeature, c_mapped: &[String], v_mapped: &[String]) -> String {
    let c_first_ip = c_mapped.first().and_then(|a| a.rsplit(':').nth(1)).unwrap_or("");
    let v_first_ip = v_mapped.first().and_then(|a| a.rsplit(':').nth(1)).unwrap_or("");
    format!(
        "{}:{}:{}:{}|{}:{}:{}:{}",
        c.nat_type,
        c.behavior,
        c.regular_ports_change as u8,
        c_first_ip,
        v.nat_type,
        v.behavior,
        v.regular_ports_change as u8,
        v_first_ip,
    )
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
