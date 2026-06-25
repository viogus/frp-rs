use std::collections::HashMap;
use std::time::{Duration, Instant};
use tokio::io::AsyncWrite;
use tokio::sync::{oneshot, Mutex, RwLock};

use frp_core::msg;

/// Coordinates NAT hole punch sessions between visitor and provider.
pub struct NatHoleCoordinator {
    sessions: RwLock<HashMap<String, NatHoleSession>>,
}

struct NatHoleSession {
    sid: String,
    proxy_name: String,
    /// Writer half of the visitor's connection — used to forward
    /// NatHoleSid and NatHoleReport from the provider control handler.
    visitor_writer: Mutex<Option<Box<dyn AsyncWrite + Send + Unpin>>>,
    /// Signalled by the provider control handler when NatHoleReport arrives.
    report_tx: Mutex<Option<oneshot::Sender<msg::NatHoleReport>>>,
    created_at: Instant,
}

impl NatHoleCoordinator {
    pub fn new() -> Self {
        Self {
            sessions: RwLock::new(HashMap::new()),
        }
    }

    /// Create a session and return the oneshot receiver for NatHoleReport.
    /// The caller (handle_nat_hole_visitor) awaits this receiver.
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
            report_tx: Mutex::new(Some(tx)),
            created_at: Instant::now(),
        };
        self.sessions.write().await.insert(sid, session);
        rx
    }

    /// Take the visitor writer for a session (used by control handler).
    /// Returns None if session not found or writer already taken.
    pub async fn take_writer(&self, sid: &str) -> Option<Box<dyn AsyncWrite + Send + Unpin>> {
        let sessions = self.sessions.read().await;
        let session = sessions.get(sid)?;
        let writer = session.visitor_writer.lock().await.take();
        writer
    }

    /// Return the writer back to the session after use.
    pub async fn return_writer(&self, sid: &str, writer: Box<dyn AsyncWrite + Send + Unpin>) {
        let sessions = self.sessions.read().await;
        if let Some(session) = sessions.get(sid) {
            *session.visitor_writer.lock().await = Some(writer);
        }
    }

    /// Signal completion with a NatHoleReport and remove the session.
    /// Returns the removed session's proxy_name, or None if not found.
    pub async fn complete(&self, sid: &str) -> Option<String> {
        let mut sessions = self.sessions.write().await;
        let session = sessions.remove(sid)?;
        let name = session.proxy_name.clone();
        // Drop the writer (closes visitor connection)
        let _writer = session.visitor_writer.lock().await.take();
        drop(_writer);
        // Signal the oneshot if still present (don't error if receiver gone)
        if let Some(tx) = session.report_tx.lock().await.take() {
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
        sessions.retain(|_sid, s| {
            let keep = now.duration_since(s.created_at) < timeout;
            if !keep {
                // Drop writer to close stale visitor connections
                let _ = s.visitor_writer.try_lock().map(|mut w| w.take());
                let _ = s.report_tx.try_lock().map(|mut tx| tx.take());
            }
            keep
        });
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

        // oneshot should fire
        let report = rx.await.unwrap();
        assert_eq!(report.sid, Some("test-sid".to_string()));
    }

    #[tokio::test]
    async fn test_take_and_return_writer() {
        let coord = NatHoleCoordinator::new();
        let (writer, _reader) = tokio::io::duplex(64);
        let _rx = coord
            .create_session("sid-1".into(), "p1".into(), Box::new(writer))
            .await;

        let w = coord.take_writer("sid-1").await;
        assert!(w.is_some());
        coord.return_writer("sid-1", w.unwrap()).await;

        let w2 = coord.take_writer("sid-1").await;
        assert!(w2.is_some());
    }

    #[tokio::test]
    async fn test_expire_old_sessions() {
        let coord = NatHoleCoordinator::new();
        let (writer, _reader) = tokio::io::duplex(64);
        let _rx = coord
            .create_session("old-sid".into(), "p1".into(), Box::new(writer))
            .await;

        // Expire immediately (age 0)
        coord.expire_sessions(Duration::from_secs(0)).await;

        // Session should be gone
        assert!(coord.take_writer("old-sid").await.is_none());
    }
}
