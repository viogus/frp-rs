use std::collections::HashMap;
use std::time::{Duration, Instant};
use tokio::io::AsyncWrite;
use tokio::sync::{mpsc, oneshot, Mutex, RwLock};

use frp_core::msg;

use crate::service::InternalMsg;

/// Coordinates NAT hole punch sessions between visitor and provider.
///
/// Two paths for forwarding NatHoleSid/NatHoleReport:
/// 1. **Writer path** (accept loop): stores the visitor's TCP writer from a
///    fresh connection. Used by handle_nat_hole_visitor.
/// 2. **Channel path** (control connection): stores the visitor's control
///    channel sender. Used when Go frpc sends NatHoleVisitor on the control
///    connection.
pub struct NatHoleCoordinator {
    sessions: RwLock<HashMap<String, NatHoleSession>>,
}

struct NatHoleSession {
    #[allow(dead_code)]
    sid: String,
    #[allow(dead_code)]
    proxy_name: String,
    /// Writer for accept-loop path (fresh connection).
    visitor_writer: Mutex<Option<Box<dyn AsyncWrite + Send + Unpin>>>,
    /// Channel sender for control-connection path (Go frp compat).
    visitor_ctl_tx: Option<mpsc::UnboundedSender<InternalMsg>>,
    /// Signalled when NatHoleReport arrives.
    report_tx: Option<oneshot::Sender<msg::NatHoleReport>>,
    created_at: Instant,
}

impl Default for NatHoleCoordinator {
    fn default() -> Self {
        Self {
            sessions: RwLock::new(HashMap::new()),
        }
    }
}

impl NatHoleCoordinator {
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a session for the accept-loop path (fresh connection with writer).
    pub async fn create_session(
        &self,
        sid: String,
        proxy_name: String,
        visitor_writer: Box<dyn AsyncWrite + Send + Unpin>,
    ) -> oneshot::Receiver<msg::NatHoleReport> {
        let (tx, rx) = oneshot::channel();
        let session = NatHoleSession {
            sid: sid.clone(),
            proxy_name,
            visitor_writer: Mutex::new(Some(visitor_writer)),
            visitor_ctl_tx: None,
            report_tx: Some(tx),
            created_at: Instant::now(),
        };
        self.sessions.write().await.insert(sid, session);
        rx
    }

    /// Create a session for the control-connection path (Go frp compat).
    pub async fn create_session_with_ctl(
        &self,
        sid: String,
        proxy_name: String,
        visitor_ctl_tx: mpsc::UnboundedSender<InternalMsg>,
    ) -> oneshot::Receiver<msg::NatHoleReport> {
        let (tx, rx) = oneshot::channel();
        let session = NatHoleSession {
            sid: sid.clone(),
            proxy_name,
            visitor_writer: Mutex::new(None),
            visitor_ctl_tx: Some(visitor_ctl_tx),
            report_tx: Some(tx),
            created_at: Instant::now(),
        };
        self.sessions.write().await.insert(sid, session);
        rx
    }

    /// Take the visitor writer for a session.
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

    /// Forward NatHoleSid to the visitor. For control-connection sessions
    /// this sends via InternalMsg; for accept-loop sessions this is a no-op
    /// (caller should use take_writer/return_writer directly).
    pub async fn forward_sid_via_ctl(&self, sid: &str, provider_addr: Option<String>) -> bool {
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

    /// Signal completion with a NatHoleReport and remove the session.
    pub async fn complete(&self, sid: &str) -> Option<String> {
        let mut sessions = self.sessions.write().await;
        let session = sessions.remove(sid)?;
        let name = session.proxy_name.clone();
        // Drop the writer (closes visitor connection)
        drop(session.visitor_writer.lock().await.take());
        // Signal the oneshot if still present
        if let Some(tx) = session.report_tx {
            let _ = tx.send(msg::NatHoleReport {
                sid: Some(sid.to_string()),
            });
        }
        Some(name)
    }

    /// Remove a session without signalling (cleanup on error).
    pub async fn remove(&self, sid: &str) {
        self.sessions.write().await.remove(sid);
    }

    /// Remove sessions older than `timeout`.
    pub async fn expire_sessions(&self, timeout: Duration) {
        let now = Instant::now();
        let mut sessions = self.sessions.write().await;
        sessions.retain(|_sid, s| now.duration_since(s.created_at) < timeout);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_create_and_complete_session() {
        let coord = NatHoleCoordinator::new();
        let (writer, _reader) = tokio::io::duplex(64);
        let rx = coord
            .create_session("test-sid".into(), "test-proxy".into(), Box::new(writer))
            .await;

        let name = coord.complete("test-sid").await;
        assert_eq!(name, Some("test-proxy".to_string()));

        let report = rx.await.unwrap();
        assert_eq!(report.sid, Some("test-sid".to_string()));
    }

    #[tokio::test]
    async fn test_forward_sid_and_report_ctl_path() {
        let coord = NatHoleCoordinator::new();
        let (tx, mut rx) = mpsc::unbounded_channel::<InternalMsg>();

        coord
            .create_session_with_ctl("sid-1".into(), "p1".into(), tx)
            .await;

        // Forward NatHoleSid via control channel
        assert!(coord
            .forward_sid_via_ctl("sid-1", Some("1.2.3.4:5678".into()))
            .await);

        match rx.try_recv() {
            Ok(InternalMsg::WriteNatHoleSid { sid, provider_addr }) => {
                assert_eq!(sid, "sid-1");
                assert_eq!(provider_addr, Some("1.2.3.4:5678".into()));
            }
            other => panic!("expected WriteNatHoleSid, got {:?}", other),
        }

        // Forward NatHoleReport via control channel
        assert!(coord.forward_report_via_ctl("sid-1").await);

        match rx.try_recv() {
            Ok(InternalMsg::WriteNatHoleReport { sid }) => {
                assert_eq!(sid, "sid-1");
            }
            other => panic!("expected WriteNatHoleReport, got {:?}", other),
        }

        // Complete the session
        let name = coord.complete("sid-1").await;
        assert_eq!(name, Some("p1".to_string()));
        assert!(!coord.forward_sid_via_ctl("sid-1", None).await);
    }

    #[tokio::test]
    async fn test_expire_old_sessions() {
        let coord = NatHoleCoordinator::new();
        let (writer, _reader) = tokio::io::duplex(64);
        let _rx = coord
            .create_session("old-sid".into(), "p1".into(), Box::new(writer))
            .await;

        coord.expire_sessions(Duration::from_secs(0)).await;
        assert!(coord.take_writer("old-sid").await.is_none());
    }
}
