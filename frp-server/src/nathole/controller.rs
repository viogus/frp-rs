//! NAT hole punch controller: coordinates XTCP sessions between
//! visitor and provider. Runs NAT classification and analysis to
//! recommend hole-punch behaviors. Go frp v0.69.1 compat: pkg/nathole/controller.go

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use tokio::io::AsyncWrite;
use tokio::sync::{mpsc, oneshot, Mutex, RwLock};
use tracing::{debug, trace, warn};

use frp_core::msg::{self, FrpMessage, NatHoleDetectBehavior, PortsRange};
use frp_core::protocol::write_msg_v1;

use crate::service::InternalMsg;
use super::analysis::{Analyzer, RecommandBehavior};
use super::classify::{classify_nat_feature, NatFeature};

/// Generates unique transaction/session IDs.
static ID_COUNTER: AtomicU64 = AtomicU64::new(0);

fn gen_sid() -> String {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let id = ID_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("{}{}", ts, id)
}

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

    /// Unregister a provider.
    pub async fn close_client(&self, name: &str) {
        self.client_cfgs.write().await.remove(name);
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
    pub async fn create_session_with_writer(
        &self,
        sid: String,
        proxy_name: String,
        visitor_msg: msg::NatHoleVisitor,
        writer: Box<dyn AsyncWrite + Send + Unpin>,
    ) -> (Arc<Session>, oneshot::Receiver<msg::NatHoleReport>) {
        let (report_tx, report_rx) = oneshot::channel();
        let (notify_tx, _notify_rx) = oneshot::channel();
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
            notify_ch: Mutex::new(Some(notify_tx)),
            report_tx: Mutex::new(Some(report_tx)),
            created_at: Instant::now(),
        });
        self.sessions
            .write()
            .await
            .insert(sid.clone(), session.clone());
        (session, report_rx)
    }

    /// Create a session for the control-connection path (Go frp compat).
    pub async fn create_session_with_ctl(
        &self,
        sid: String,
        proxy_name: String,
        visitor_msg: msg::NatHoleVisitor,
        visitor_ctl_tx: mpsc::UnboundedSender<InternalMsg>,
    ) -> (Arc<Session>, oneshot::Receiver<msg::NatHoleReport>) {
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
        });
        self.sessions
            .write()
            .await
            .insert(sid.clone(), session.clone());
        (session, report_rx)
    }

    /// Handle the provider's NatHoleClient response (with STUN addresses).
    /// Signals the session's notify channel so the waiting HandleVisitor can proceed.
    pub async fn handle_client(&self, msg: msg::NatHoleClient) {
        if let Some(ref sid) = msg.sid {
            let sessions = self.sessions.read().await;
            if let Some(session) = sessions.get(sid) {
                trace!(
                    "handle client message, sid [{}], proxy: {}",
                    sid,
                    msg.proxy_name
                );
                *session.client_msg.lock().await = Some(msg);
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
        sessions.retain(|_sid, s| now.duration_since(s.created_at) < timeout);
    }

    /// Send NatHoleResp to visitor. Tries writer path first, then ctl path.
    pub async fn send_to_visitor(&self, session: &Session, resp: &msg::NatHoleResp) {
        // Try writer path
        let mut writer_guard = session.visitor_writer.lock().await;
        if let Some(ref mut writer) = *writer_guard {
            if let Err(e) = write_msg_v1(writer, &FrpMessage::NatHoleResp(resp.clone())).await {
                warn!("Failed to write NatHoleResp to visitor via writer: {}", e);
            }
        } else if let Some(ref tx) = session.visitor_ctl_tx {
            let _ = tx.send(InternalMsg::WriteNatHoleResp {
                transaction_id: resp.transaction_id.clone(),
                error: resp.error.clone(),
                sid: resp.sid.clone(),
                protocol: resp.protocol.clone(),
                candidate_addrs: resp.candidate_addrs.clone(),
                assisted_addrs: resp.assisted_addrs.clone(),
            });
        }
    }
}

/// Generate an analysis key from two NAT features for analyzer lookup.
pub fn gen_analysis_key(c: &NatFeature, v: &NatFeature) -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut hasher = DefaultHasher::new();
    c.nat_type.hash(&mut hasher);
    c.behavior.hash(&mut hasher);
    c.regular_ports_change.hash(&mut hasher);
    v.nat_type.hash(&mut hasher);
    v.behavior.hash(&mut hasher);
    v.regular_ports_change.hash(&mut hasher);
    format!("{:x}", hasher.finish())
}

/// Build a NatHoleResp with detect_behavior filled in.
/// Go frp v0.69.1 compat: newNatHoleResponse in controller.go
pub fn build_nat_hole_response(
    transaction_id: &str,
    sid: &str,
    protocol: Option<String>,
    mode: i32,
    candidate_addrs: Vec<String>,
    assisted_addrs: Vec<String>,
    behavior: RecommandBehavior,
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
