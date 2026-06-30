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

use crate::service::InternalMsg;
use super::analysis::{Analyzer, RecommendBehavior};
use super::classify::NatFeature;

/// Maximum concurrent NAT hole punch sessions.
/// Prevents unbounded memory growth under load or attack.
const MAX_SESSIONS: usize = 256;

/// Provider registration for XTCP.
pub struct ClientCfg {
    pub name: String,
    pub sk: String,
    pub allow_users: Vec<String>,
    pub sid_ch: mpsc::UnboundedSender<String>,
}

/// Active NAT hole-punch session between visitor and provider.
pub struct Session {
    pub sid: String,
    pub proxy_name: String,

    // Visitor side
    pub visitor_msg: msg::NatHoleVisitor,
    pub visitor_writer: Mutex<Option<Box<dyn AsyncWrite + Send + Unpin>>>,
    pub visitor_ctl_tx: Option<mpsc::UnboundedSender<InternalMsg>>,
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
    ) -> Result<mpsc::UnboundedReceiver<String>, String> {
        let (tx, rx) = mpsc::unbounded_channel();
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
            .send(sid.to_string())
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
            notify_ch: Mutex::new(None),  // caller sets up before notifying provider
            report_tx: Mutex::new(Some(report_tx)),
            created_at: Instant::now(),
            last_activity: std::sync::Mutex::new(Instant::now()),
        });
        // Check-and-insert atomically under write lock (fixes TOCTOU).
        {
            let mut sessions = self.sessions.write().await;
            if sessions.len() >= MAX_SESSIONS {
                warn!(max_sessions = MAX_SESSIONS, "NAT hole session limit reached ({MAX_SESSIONS}), rejecting new session");
                // Send error response to visitor so it doesn't hang.
                let mut guard = session.visitor_writer.lock().await;
                if let Some(ref mut w) = *guard {
                    let _ = frp_core::protocol::write_v1_frame(
                        w,
                        &FrpMessage::NatHoleResp(msg::NatHoleResp {
                            transaction_id: session.visitor_msg.transaction_id.clone(),
                            sid: Some(sid.clone()),
                            error: Some("NAT hole session limit reached".into()),
                            ..Default::default()
                        }),
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
        visitor_ctl_tx: mpsc::UnboundedSender<InternalMsg>,
    ) -> Result<(Arc<Session>, oneshot::Receiver<msg::NatHoleReport>), String> {
        let (report_tx, report_rx) = oneshot::channel();
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
        });
        // Check-and-insert atomically under write lock (fixes TOCTOU).
        {
            let mut sessions = self.sessions.write().await;
            if sessions.len() >= MAX_SESSIONS {
                warn!(max_sessions = MAX_SESSIONS, "NAT hole session limit reached ({MAX_SESSIONS}), rejecting new session");
                // Send error response via control channel so visitor doesn't hang.
                if let Some(ref tx) = session.visitor_ctl_tx {
                    let _ = tx.send(InternalMsg::WriteNatHoleResp {
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
            let sessions = self.sessions.read().await;
            if let Some(session) = sessions.get(sid) {
                trace!(
                    sid = %sid,
                    proxy_name = %msg.proxy_name,
                    "handle client message, sid [{}], proxy: {}",
                    sid,
                    msg.proxy_name
                );
                *session.client_msg.lock().await = Some(msg);
                *session.last_activity.lock().unwrap() = Instant::now();
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
            let sessions = self.sessions.read().await;
            if let Some(session) = sessions.get(sid) {
                *session.last_activity.lock().unwrap() = Instant::now();
                // Report success to analyzer
                let v_resp = session.v_resp.lock().await;
                if let Some(ref resp) = *v_resp {
                    if let Some(ref db) = resp.detect_behavior {
                        let v_feat = session.v_nat_feature.lock().await;
                        let c_feat = session.c_nat_feature.lock().await;
                        if let (Some(ref vf), Some(ref cf)) = (&*v_feat, &*c_feat) {
                            let key = gen_analysis_key(cf, vf);
                            self.analyzer.report_success(&key, db.mode, 0);
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
            let last = *s.last_activity.lock().unwrap();
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
    pub async fn forward_sid_via_ctl(
        &self,
        sid: &str,
        provider_addr: Option<String>,
    ) -> bool {
        let sessions = self.sessions.read().await;
        if let Some(session) = sessions.get(sid) {
            if let Some(ref tx) = session.visitor_ctl_tx {
                let _ = tx.send(InternalMsg::WriteNatHoleSid {
                    sid: sid.to_string(),
                    provider_addr,
                });
                return true;
            }
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
        let sessions = self.sessions.read().await;
        if let Some(session) = sessions.get(sid) {
            if let Some(ref tx) = session.visitor_ctl_tx {
                let _ = tx.send(InternalMsg::WriteNatHoleResp {
                    transaction_id: sid.to_string(),
                    error,
                    sid: resp_sid,
                    protocol,
                    candidate_addrs,
                    assisted_addrs,
                });
                return true;
            }
        }
        false
    }

    /// Forward NatHoleReport to the visitor via control channel.
    pub async fn forward_report_via_ctl(&self, sid: &str) -> bool {
        let sessions = self.sessions.read().await;
        if let Some(session) = sessions.get(sid) {
            if let Some(ref tx) = session.visitor_ctl_tx {
                let _ = tx.send(InternalMsg::WriteNatHoleReport {
                    sid: sid.to_string(),
                });
                return true;
            }
        }
        false
    }

}

/// Generate a stable analysis key from two NAT features for analyzer lookup.
/// Uses a canonical string representation — stable across Rust versions and
/// platforms, and human-readable for debugging.
pub fn gen_analysis_key(c: &NatFeature, v: &NatFeature) -> String {
    format!(
        "{}:{}:{}|{}:{}:{}",
        c.nat_type, c.behavior, c.regular_ports_change as u8,
        v.nat_type, v.behavior, v.regular_ports_change as u8,
    )
}

/// Build a NatHoleResp with detect_behavior filled in.
/// Go frp v0.69.1 compat: newNatHoleResponse in controller.go
#[allow(clippy::too_many_arguments)]
pub fn build_nat_hole_response(
    transaction_id: &str,
    sid: &str,
    protocol: Option<String>,
    mode: i32,
    candidate_addrs: Vec<String>,
    assisted_addrs: Vec<String>,
    behavior: RecommendBehavior,
    read_timeout_ms: i32,
    ports_difference: i32,
) -> msg::NatHoleResp {
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
        transaction_id: transaction_id.to_string(),
        error: None,
        sid: Some(sid.to_string()),
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
