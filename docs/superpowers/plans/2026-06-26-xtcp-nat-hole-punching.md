# XTCP NAT Hole Punching Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement XTCP NAT hole punching with STCP relay fallback, matching Go frp v0.69.1 behavior.

**Architecture:** Server coordinates NAT session via new `NatHoleCoordinator` (message relay + session tracking). Visitor client opens a fresh TCP connection per request, sends `NatHoleVisitor`, reads `NatHoleSid`/`NatHoleReport`, then attempts TCP simultaneous open. On failure, falls back to existing STCP relay path via a new connection. Provider client handles `NatHoleClient` in its control message loop, performs simultaneous open, and reports result. New InternalMsg variant `NatHoleClient` carries session coordination data between server accept loop and provider control handler.

**Tech Stack:** tokio async TCP, SO_REUSEADDR for simultaneous open, existing InternalMsg channel for intra-server dispatch, oneshot channels for session lifecycle.

**Files Summary:**

| File | Action | Lines (est.) |
|------|--------|-------------|
| `frp-core/src/msg.rs` | Modify | ~15 (addr/sid fields) |
| `frp-server/src/nat_hole.rs` | Create | ~80 |
| `frp-server/src/service.rs` | Modify | ~100 (AppState, InternalMsg, accept loop, handler) |
| `frp-server/src/control.rs` | Modify | ~70 (3 message arms) |
| `frp-server/src/lib.rs` | Modify | ~1 |
| `frp-client/src/service.rs` | Modify | ~180 (visitor XTCP, provider handler, simultaneous open) |
| `frp-server/tests/xtcp_hole_punch.rs` | Create | ~120 (integration test) |

---
### Task 1: Add addr/sid fields to NatHole message structs

**Files:**
- Modify: `frp-core/src/msg.rs:285-311`

Add `visitor_addr` to `NatHoleClient`, `provider_addr` to `NatHoleSid`, and `sid` to `NatHoleClient` for session correlation.

- [ ] **Step 1: Modify NatHoleClient struct**

In `frp-core/src/msg.rs`, replace the NatHoleClient struct (lines 285-292):

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NatHoleClient {
    pub proxy_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sign_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub run_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub visitor_addr: Option<String>,
}
```

- [ ] **Step 2: Modify NatHoleSid struct**

Replace the NatHoleSid struct (lines 301-305):

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NatHoleSid {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider_addr: Option<String>,
}
```

- [ ] **Step 3: Update from_v1_type_byte constructors**

Update the `FrpMessage::NatHoleClient` constructor in `from_v1_type_byte()` (around line ~462) to include the new fields:

```rust
TYPE_NAT_HOLE_CLIENT => FrpMessage::NatHoleClient(NatHoleClient {
    proxy_name: String::new(),
    sign_key: None,
    run_id: None,
    sid: None,
    visitor_addr: None,
}),
```

- [ ] **Step 4: Build and verify**

```bash
cargo build
```

Expected: compiles cleanly. No tests broken (NatHole types are unused except serialization tests).

- [ ] **Step 5: Commit**

```bash
git add frp-core/src/msg.rs
git commit -m "feat: add addr/sid fields to NatHoleClient and NatHoleSid"
```

---
### Task 2: Create NatHoleCoordinator

**Files:**
- Create: `frp-server/src/nat_hole.rs`

Create the `NatHoleCoordinator` module that manages NAT hole punch sessions. Each session stores the visitor connection writer (so the provider's control handler can forward messages) and a oneshot channel for signaling completion.

- [ ] **Step 1: Write the module with unit tests**

Create `frp-server/src/nat_hole.rs`:

```rust
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::AsyncWrite;
use tokio::sync::{Mutex, oneshot, RwLock};

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
        session.visitor_writer.lock().await.take()
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
        drop(session.visitor_writer.lock().await.take());
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
        let rx = coord.create_session(
            "test-sid".into(),
            "test-proxy".into(),
            Box::new(writer),
        ).await;

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
        let _rx = coord.create_session(
            "sid-1".into(),
            "p1".into(),
            Box::new(writer),
        ).await;

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
        let _rx = coord.create_session(
            "old-sid".into(),
            "p1".into(),
            Box::new(writer),
        ).await;

        // Expire immediately (age 0)
        coord.expire_sessions(Duration::from_secs(0)).await;

        // Session should be gone
        assert!(coord.take_writer("old-sid").await.is_none());
    }
}
```

- [ ] **Step 2: Run tests**

```bash
cargo test -p frp-server -- nat_hole
```

Expected: 3 tests pass.

- [ ] **Step 3: Commit**

```bash
git add frp-server/src/nat_hole.rs
git commit -m "feat: add NatHoleCoordinator for XTCP session management"
```

---
### Task 3: Wire NatHoleCoordinator into AppState + lib.rs

**Files:**
- Modify: `frp-server/src/lib.rs:1-5`
- Modify: `frp-server/src/service.rs:54-72`

- [ ] **Step 1: Declare module in lib.rs**

Add `pub mod nat_hole;` to `frp-server/src/lib.rs`:

```rust
pub mod service;
pub mod control;
pub mod proxy;
pub mod vhost;
pub mod dashboard;
pub mod nat_hole;
```

- [ ] **Step 2: Add NatHoleCoordinator to AppState**

In `frp-server/src/service.rs`, add to the `AppState` struct (after the `oidc_subjects` field at line ~70):

```rust
pub nat_hole: Arc<NatHoleCoordinator>,
```

Add the import at the top of service.rs:

```rust
use crate::nat_hole::NatHoleCoordinator;
```

- [ ] **Step 3: Initialize NatHoleCoordinator in Service::new()**

In `Service::new()`, find where `AppState` is constructed (around line ~100-120) and add:

```rust
nat_hole: Arc::new(NatHoleCoordinator::new()),
```

- [ ] **Step 4: Build and verify**

```bash
cargo build
```

Expected: compiles cleanly.

- [ ] **Step 5: Commit**

```bash
git add frp-server/src/lib.rs frp-server/src/service.rs
git commit -m "feat: wire NatHoleCoordinator into AppState"
```

---
### Task 4: Add InternalMsg::NatHoleClient variant

**Files:**
- Modify: `frp-server/src/service.rs:28-47`

- [ ] **Step 1: Add InternalMsg variant**

Replace the `InternalMsg` enum to add the `NatHoleClient` variant:

```rust
#[derive(Debug)]
pub enum InternalMsg {
    NewWorkConn(IoStream),
    VisitorConn {
        proxy_name: String,
        visitor_conn: IoStream,
    },
    ProxyUserConn {
        proxy_name: String,
        user_conn: IoStream,
        pre_read: Vec<u8>,
    },
    UdpData {
        proxy_name: String,
        content: Vec<u8>,
        remote_addr: String,
    },
    /// Sent when a new control connection claims the same run_id.
    /// The old handler should stop listening and clean up.
    Shutdown,
    /// NAT hole punch: server tells provider to initiate hole punch.
    NatHoleClient {
        proxy_name: String,
        sign_key: Option<String>,
        run_id: Option<String>,
        sid: String,
        visitor_addr: Option<String>,
    },
}
```

- [ ] **Step 2: Build and verify**

```bash
cargo build
```

Expected: compiles cleanly. No new match exhaustiveness errors because `InternalMsg` matches already use catch-all or covered patterns.

- [ ] **Step 3: Commit**

```bash
git add frp-server/src/service.rs
git commit -m "feat: add InternalMsg::NatHoleClient variant"
```

---
### Task 5: Add handle_nat_hole_visitor + accept loop dispatch

**Files:**
- Modify: `frp-server/src/service.rs` (accept loop ~lines 490-553, new function after handle_visitor_conn_inner)

Add the server-side handler for `NatHoleVisitor` messages on fresh connections. This function validates the sign key, creates a NAT session, splits the stream, sends `NatHoleClient` to the provider, and waits for the report.

- [ ] **Step 1: Add handle_nat_hole_visitor function**

Add this function after `handle_visitor_conn_inner` (after line 620 in service.rs):

```rust
/// Handle an incoming XTCP NatHoleVisitor connection.
///
/// Validates sign_key (MD5(sk + timestamp)), looks up the provider,
/// creates a NAT session, forwards NatHoleClient to the provider
/// via InternalMsg, writes NatHoleSid + NatHoleReport to the visitor,
/// and waits for the provider's report signal.
async fn handle_nat_hole_visitor(
    stream: IoStream,
    msg: msg::NatHoleVisitor,
    state: Arc<AppState>,
    visitor_addr: Option<String>,
) {
    let sign_key = msg.sign_key.unwrap_or_default();
    let timestamp = msg.timestamp.unwrap_or(0);

    if sign_key.is_empty() {
        warn!("NatHoleVisitor without sign_key, ignoring");
        return;
    }

    // Look up proxy name from sk_index
    let proxy_name = {
        state.sk_index.read().await.get(&sign_key).cloned()
    };
    let proxy_name = match proxy_name {
        Some(pn) => pn,
        None => {
            // Also try MD5 validation: sign_key might be MD5(sk + timestamp)
            // We need to find which sk produces this sign_key
            warn!("NatHoleVisitor: no proxy found by raw sk, trying MD5 match");
            let found = {
                let sk_idx = state.sk_index.read().await;
                sk_idx.iter().find_map(|(sk, pn)| {
                    let expected = frp_core::auth::generate_token(sk, timestamp);
                    if expected == sign_key {
                        Some(pn.clone())
                    } else {
                        None
                    }
                })
            };
            match found {
                Some(pn) => pn,
                None => {
                    warn!("NatHoleVisitor: no STCP/XTCP proxy found for sign_key");
                    // Send error response
                    let mut writer = stream.into_split().1;
                    let resp = FrpMessage::NatHoleResp(msg::NatHoleResp {
                        proxy_name: String::new(),
                        error: Some("proxy not found".into()),
                    });
                    let _ = write_msg_v1(&mut writer, &resp).await;
                    return;
                }
            }
        }
    };

    // Look up the provider's run_id from proxy_manager
    let run_id = state.proxy_manager.get_run_id(&proxy_name).await;
    let run_id = match run_id {
        Some(id) => id,
        None => {
            warn!("NatHoleVisitor: no run_id found for proxy '{}'", proxy_name);
            let mut writer = stream.into_split().1;
            let resp = FrpMessage::NatHoleResp(msg::NatHoleResp {
                proxy_name,
                error: Some("provider offline".into()),
            });
            let _ = write_msg_v1(&mut writer, &resp).await;
            return;
        }
    };

    let ctl_tx = {
        let map = state.run_id_to_ctl_tx.read().await;
        map.get(&run_id).cloned()
    };

    let ctl_tx = match ctl_tx {
        Some(ctl) => ctl,
        None => {
            warn!("No provider control handler for run_id {}", run_id);
            let mut writer = stream.into_split().1;
            let resp = FrpMessage::NatHoleResp(msg::NatHoleResp {
                proxy_name,
                error: Some("provider disconnected".into()),
            });
            let _ = write_msg_v1(&mut writer, &resp).await;
            return;
        }
    };

    // Generate session ID
    let sid = uuid::Uuid::new_v4().to_string();

    // Split the stream: writer goes into session, reader is kept for
    // potential STCP fallback read.
    let (mut reader, writer) = stream.into_split();

    // Create NAT session and get report receiver
    let report_rx = state.nat_hole.create_session(
        sid.clone(),
        proxy_name.clone(),
        writer,
    ).await;

    info!("NatHoleVisitor for proxy '{}': created session {}", proxy_name, sid);

    // Send NatHoleClient to provider
    if ctl_tx.tx.send(InternalMsg::NatHoleClient {
        proxy_name: proxy_name.clone(),
        sign_key: Some(sign_key),
        run_id: Some(run_id),
        sid: sid.clone(),
        visitor_addr,
    }).is_err() {
        warn!("Provider for run_id {} has gone away", run_id);
        state.nat_hole.remove(&sid).await;
        return;
    }

    // Wait for the provider to complete the hole punch (via report oneshot)
    // 30s timeout — generous to cover hole punch attempt
    match tokio::time::timeout(Duration::from_secs(30), report_rx).await {
        Ok(Ok(_report)) => {
            debug!("NatHole session {}: provider completed", sid);
            // The writer has already been dropped by complete().
            // If visitor wants STCP fallback, it opens a new connection.
        }
        Ok(Err(_)) => {
            debug!("NatHole session {}: provider dropped without report", sid);
            state.nat_hole.remove(&sid).await;
        }
        Err(_) => {
            warn!("NatHole session {}: timed out waiting for provider report", sid);
            state.nat_hole.remove(&sid).await;
            // Write error to visitor
            let resp = FrpMessage::NatHoleResp(msg::NatHoleResp {
                proxy_name,
                error: Some("hole punch timeout".into()),
            });
            let _ = write_msg_v1(&mut reader, &resp).await;
        }
    }
    // reader is dropped here — connection closes
}
```

- [ ] **Step 2: Add import at top of service.rs**

```rust
use std::time::Duration;
use frp_core::protocol::write_msg_v1;
```

- [ ] **Step 3: Wire NatHoleVisitor dispatch in accept loop**

In the accept loop, add handling for `NatHoleVisitor` alongside the existing `NewVisitorConn` dispatch.

For the **plain TCP** path (around line 541-544), add after the `NewVisitorConn` arm:

```rust
Ok(FrpMessage::NatHoleVisitor(nhv)) => {
    let io = IoStream::Tcp(stream);
    let visitor_addr = Some(addr.to_string());
    handle_nat_hole_visitor(io, nhv, state, visitor_addr).await;
}
```

For the **yamux** path (around line 516-517), add:

```rust
Ok(FrpMessage::NatHoleVisitor(nhv)) => {
    handle_nat_hole_visitor(io, nhv, state, None).await;
}
```

For the **WebSocket** path (around line 473-475), add:

```rust
Ok(FrpMessage::NatHoleVisitor(nhv)) => {
    handle_nat_hole_visitor(ws, nhv, state, None).await;
}
```

- [ ] **Step 4: Build and verify**

```bash
cargo build
```

Expected: compiles cleanly.

- [ ] **Step 5: Commit**

```bash
git add frp-server/src/service.rs
git commit -m "feat: add handle_nat_hole_visitor server function"
```

---
### Task 6: Add NatHole handling to server control.rs

**Files:**
- Modify: `frp-server/src/control.rs:147-456`

Add three new arms to the server control loop: writing `NatHoleClient` to the provider client (from InternalMsg), and forwarding `NatHoleSid`/`NatHoleReport` from the provider to the visitor via `NatHoleCoordinator`.

- [ ] **Step 1: Fix XTCP sk_index registration**

In `handle_new_proxy`, the STCP sk registration only matches `"stcp"`. XTCP must also be registered. Find (around line 659):

```rust
if np.proxy_type == "stcp" {
```

Change to:

```rust
if np.proxy_type == "stcp" || np.proxy_type == "xtcp" {
```

- [ ] **Step 2: Add InternalMsg::NatHoleClient handler**

In the `internal_rx.recv()` arm of the select loop (after the `InternalMsg::VisitorConn` handler, around line 206), add:

```rust
Some(InternalMsg::NatHoleClient { proxy_name, sign_key, run_id, sid, visitor_addr }) => {
    debug!("Sending NatHoleClient for session {} to provider", sid);
    let nhc = FrpMessage::NatHoleClient(msg::NatHoleClient {
        proxy_name,
        sign_key,
        run_id,
        sid: Some(sid),
        visitor_addr,
    });
    if let Err(e) = write_msg_v1(&mut writer, &nhc).await {
        warn!("Failed to send NatHoleClient: {}", e);
        break;
    }
}
```

- [ ] **Step 3: Add NatHoleSid handler in read_msg_v1 arm**

In the `read_msg_v1(&mut reader)` arm (around line 447, before the catch-all), add:

```rust
Ok(FrpMessage::NatHoleSid(ref sid_msg)) => {
    debug!("Received NatHoleSid from provider: {:?}", sid_msg.sid);
    if let Some(ref sid) = sid_msg.sid {
        // Forward NatHoleSid to the visitor via the session's writer.
        // The server adds provider_addr to the forwarded message.
        if let Some(mut writer) = state.nat_hole.take_writer(sid).await {
            let forward = FrpMessage::NatHoleSid(msg::NatHoleSid {
                sid: Some(sid.clone()),
                provider_addr: peer.as_ref().map(|a| a.to_string()),
            });
            if write_msg_v1(&mut writer, &forward).await.is_ok() {
                debug!("Forwarded NatHoleSid to visitor for session {}", sid);
            } else {
                warn!("Failed to write NatHoleSid to visitor for session {}", sid);
            }
            state.nat_hole.return_writer(sid, writer).await;
        } else {
            warn!("NatHoleSid for unknown session {}", sid);
        }
    }
}
```

- [ ] **Step 4: Add NatHoleReport handler in read_msg_v1 arm** (no change, step number already correct)

```rust
Ok(FrpMessage::NatHoleReport(ref report_msg)) => {
    debug!("Received NatHoleReport from provider: {:?}", report_msg.sid);
    if let Some(ref sid) = report_msg.sid {
        // Forward NatHoleReport to the visitor and complete the session
        if let Some(mut writer) = state.nat_hole.take_writer(sid).await {
            let forward = FrpMessage::NatHoleReport(msg::NatHoleReport {
                sid: Some(sid.clone()),
            });
            let _ = write_msg_v1(&mut writer, &forward).await;
        }
        state.nat_hole.complete(sid).await;
    }
}
```

- [ ] **Step 5: Build and verify**

```bash
cargo build
```

Expected: compiles cleanly.

- [ ] **Step 6: Commit**

```bash
git add frp-server/src/control.rs
git commit -m "feat: add NatHole message handling in server control loop"
```

---
### Task 7: Add TCP simultaneous open utility

**Files:**
- Modify: `frp-client/src/service.rs` (new function before run_visitor_listener)

TCP simultaneous open for NAT hole punching: both sides bind to a local port with `SO_REUSEADDR`, then each dials the other's public address. This works through most NAT types except symmetric NAT.

- [ ] **Step 1: Add tcp_simultaneous_open function**

Add this function in `frp-client/src/service.rs`, before `run_visitor_listener` (before line 806):

```rust
/// Attempt TCP simultaneous open to `peer_addr`.
///
/// Binds a local port with SO_REUSEADDR (required for simultaneous open),
/// then dials the peer. When both sides do this at roughly the same time,
/// the kernel's TCP stack matches the SYN packets and establishes a P2P
/// connection through most NAT types.
///
/// Returns the connected TcpStream on success, or an error on timeout (5s)
/// or other failures.
async fn tcp_simultaneous_open(peer_addr: &str) -> Result<tokio::net::TcpStream, String> {
    use std::net::SocketAddr;
    use tokio::net::TcpSocket;

    let peer: SocketAddr = peer_addr
        .parse()
        .map_err(|e| format!("invalid peer address '{}': {}", peer_addr, e))?;

    let local = TcpSocket::new_v4().map_err(|e| format!("TcpSocket::new_v4: {}", e))?;

    // SO_REUSEADDR is required for TCP simultaneous open:
    // both sides bind to the same port they use to connect.
    local.set_reuseaddr(true).map_err(|e| format!("set_reuseaddr: {}", e))?;
    #[cfg(unix)]
    local.set_reuseport(true).ok();

    // Bind to any available port
    local
        .bind("0.0.0.0:0".parse().unwrap())
        .map_err(|e| format!("bind: {}", e))?;

    debug!("TCP simultaneous open: bound to local, dialing {}", peer);

    // Dial with 5-second timeout
    match tokio::time::timeout(Duration::from_secs(5), local.connect(peer)).await {
        Ok(Ok(stream)) => {
            debug!("TCP simultaneous open to {} succeeded", peer);
            Ok(stream)
        }
        Ok(Err(e)) => {
            debug!("TCP simultaneous open to {} failed: {}", peer, e);
            Err(format!("connect failed: {}", e))
        }
        Err(_) => {
            debug!("TCP simultaneous open to {} timed out after 5s", peer);
            Err("hole punch timeout".into())
        }
    }
}
```

Note: `Duration` is already imported in service.rs (used by `ping_interval`).

- [ ] **Step 2: Build and verify**

```bash
cargo build
```

Expected: compiles cleanly.

- [ ] **Step 3: Commit**

```bash
git add frp-client/src/service.rs
git commit -m "feat: add tcp_simultaneous_open utility for XTCP"
```

---
### Task 8: Modify run_visitor_listener for XTCP

**Files:**
- Modify: `frp-client/src/service.rs:294-316` (spawn call site)
- Modify: `frp-client/src/service.rs:806-892` (run_visitor_listener function)

- [ ] **Step 1: Add visitor_type parameter to run_visitor_listener**

Change the function signature (line 809) and the spawn call site (lines 294-314):

At the call site, add `visitor_type` to the cloned variables and pass it:

```rust
let visitor_type = v.visitor_type.clone();
// ... in the tokio::spawn closure:
run_visitor_listener(sa, sp, pt, server_name, secret_key, bind_addr, use_enc, use_comp, name,
    tls_enable, tls_server_name, tls_ca_file, visitor_type).await;
```

Update the function signature:

```rust
async fn run_visitor_listener(
    server_addr: String,
    server_port: u16,
    protocol: TransportProtocol,
    server_name: String,
    secret_key: String,
    bind_addr: String,
    use_encryption: bool,
    use_compression: bool,
    name: String,
    tls_enable: bool,
    tls_server_name: String,
    tls_ca_file: Option<String>,
    visitor_type: String,
) {
```

- [ ] **Step 2: Add XTCP branch in the connection handling**

Replace the per-connection spawned task (lines 846-884) with XTCP-aware logic:

```rust
tokio::spawn(async move {
    // Connect to the server
    let opts = DialOptions {
        server_addr: sa.clone(),
        server_port: sp,
        protocol: pt.clone(),
        tls_enable,
        tls_server_name: tls_sn,
        tls_ca_file: tls_ca,
        ..Default::default()
    };

    if visitor_type == "xtcp" {
        // --- XTCP NAT hole punch path ---
        let mut server_conn = match dial_server(&opts).await {
            Ok(io) => io,
            Err(e) => {
                warn!("Visitor '{}': dial server failed: {}", visitor_name, e);
                return;
            }
        };

        // Build NatHoleVisitor with MD5 sign_key
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        let sign_key = if sk.is_empty() {
            sk.clone()
        } else {
            frp_core::auth::generate_token(&sk, timestamp)
        };
        let nhv = FrpMessage::NatHoleVisitor(msg::NatHoleVisitor {
            proxy_name: sn.clone(),
            sign_key: Some(sign_key),
            timestamp: Some(timestamp),
            run_id: None,
            use_encryption: Some(use_encryption),
            use_compression: Some(use_compression),
        });
        if let Err(e) = server_conn.write_v1_frame(&nhv).await {
            warn!("Visitor '{}': send NatHoleVisitor failed: {}", visitor_name, e);
            return;
        }
        debug!("Visitor '{}': sent NatHoleVisitor for '{}'", visitor_name, sn);

        // Read NatHoleSid (contains provider address)
        match server_conn.read_v1_frame().await {
            Ok(FrpMessage::NatHoleSid(sid_msg)) => {
                let provider_addr = sid_msg.provider_addr.unwrap_or_default();
                debug!("Visitor '{}': got provider addr '{}'", visitor_name, provider_addr);

                // Read NatHoleReport (provider is ready)
                match server_conn.read_v1_frame().await {
                    Ok(FrpMessage::NatHoleReport(_)) => {
                        debug!("Visitor '{}': provider ready, attempting P2P", visitor_name);

                        if !provider_addr.is_empty() {
                            match tcp_simultaneous_open(&provider_addr).await {
                                Ok(p2p_stream) => {
                                    info!("Visitor '{}': XTCP P2P connected to {}", visitor_name, provider_addr);
                                    let mut user = user_conn;
                                    let mut p2p = p2p_stream;
                                    match tokio::io::copy_bidirectional(&mut user, &mut p2p).await {
                                        Ok((to_p2p, to_user)) => {
                                            debug!("Visitor '{}' XTCP closed: {}B to P2P, {}B to user",
                                                visitor_name, to_p2p, to_user);
                                        }
                                        Err(e) => {
                                            debug!("Visitor '{}' XTCP bridge error: {}", visitor_name, e);
                                        }
                                    }
                                    return; // P2P succeeded, done
                                }
                                Err(e) => {
                                    warn!("Visitor '{}': XTCP hole punch failed: {}", visitor_name, e);
                                    // Fall through to STCP fallback
                                }
                            }
                        }
                    }
                    Ok(FrpMessage::NatHoleResp(resp)) => {
                        if let Some(err) = resp.error {
                            warn!("Visitor '{}': server error: {}", visitor_name, err);
                        }
                        return;
                    }
                    other => {
                        warn!("Visitor '{}': unexpected NatHole response: {:?}", visitor_name,
                            other.as_ref().map(|m| m.v1_type_byte()));
                        return;
                    }
                }
            }
            Ok(FrpMessage::NatHoleResp(resp)) => {
                if let Some(err) = resp.error {
                    warn!("Visitor '{}': server error: {}", visitor_name, err);
                }
                return;
            }
            other => {
                warn!("Visitor '{}': unexpected response to NatHoleVisitor: {:?}", visitor_name,
                    other.as_ref().map(|m| m.v1_type_byte()));
                return;
            }
        }

        // --- STCP fallback (hole punch failed) ---
        // Open a NEW connection for STCP relay
        let mut server_conn = match dial_server(&opts).await {
            Ok(io) => io,
            Err(e) => {
                warn!("Visitor '{}': STCP fallback dial failed: {}", visitor_name, e);
                return;
            }
        };

        let nvc = crate::proxy::create_visitor_conn_msg(&sn, &sk, use_encryption, use_compression);
        if let Err(e) = server_conn.write_v1_frame(&nvc).await {
            warn!("Visitor '{}': STCP fallback send NewVisitorConn failed: {}", visitor_name, e);
            return;
        }
        info!("Visitor '{}': fell back to STCP relay for '{}'", visitor_name, sn);

        let mut user = user_conn;
        match tokio::io::copy_bidirectional(&mut user, &mut server_conn).await {
            Ok((to_server, to_user)) => {
                debug!("Visitor '{}' STCP relay closed: {}B to server, {}B to user",
                    visitor_name, to_server, to_user);
            }
            Err(e) => {
                debug!("Visitor '{}' STCP relay bridge error: {}", visitor_name, e);
            }
        }
    } else {
        // --- STCP relay path (existing) ---
        let mut server_conn = match dial_server(&opts).await {
            Ok(io) => io,
            Err(e) => {
                warn!("Visitor '{}': dial server failed: {}", visitor_name, e);
                return;
            }
        };

        let nvc = crate::proxy::create_visitor_conn_msg(&sn, &sk, use_encryption, use_compression);
        if let Err(e) = server_conn.write_v1_frame(&nvc).await {
            warn!("Visitor '{}': send NewVisitorConn failed: {}", visitor_name, e);
            return;
        }
        debug!("Visitor '{}': sent NewVisitorConn for '{}'", visitor_name, sn);

        let mut user = user_conn;
        match tokio::io::copy_bidirectional(&mut user, &mut server_conn).await {
            Ok((to_server, to_user)) => {
                debug!("Visitor '{}' closed: {}B to server, {}B to user", visitor_name, to_server, to_user);
            }
            Err(e) => {
                debug!("Visitor '{}' bridge error: {}", visitor_name, e);
            }
        }
    }
});
```

- [ ] **Step 3: Build and verify**

```bash
cargo build
```

Expected: compiles cleanly.

- [ ] **Step 4: Commit**

```bash
git add frp-client/src/service.rs
git commit -m "feat: add XTCP visitor path with STCP fallback"
```

---
### Task 9: Add NatHoleClient handler to client service.rs run() loop

**Files:**
- Modify: `frp-client/src/service.rs:395-473` (message loop)

Add a handler for `FrpMessage::NatHoleClient` in the provider client's message loop. The provider reads this, performs TCP simultaneous open, connects to the local service, and bridges.

- [ ] **Step 1: Add NatHoleClient message handler**

The NatHoleClient handler must be inline (not spawned) because it needs access to `writer` for sending NatHoleSid and NatHoleReport back to the server. Add this before the `Ok(_)` catch-all (around line 466):

```rust
Ok(FrpMessage::NatHoleClient(nhc)) => {
    debug!("Received NatHoleClient for proxy '{}'", nhc.proxy_name);
    let visitor_addr = nhc.visitor_addr.unwrap_or_default();
    let proxy_name = nhc.proxy_name.clone();
    let sid = nhc.sid.unwrap_or_default();
    let local_addr = self.proxy_info_map
        .get(&proxy_name)
        .and_then(|p| p.local_addr.clone());

    if visitor_addr.is_empty() {
        warn!("NatHoleClient without visitor_addr for '{}'", proxy_name);
        let report = FrpMessage::NatHoleReport(msg::NatHoleReport {
            sid: Some(sid.clone()),
        });
        let _ = write_msg_v1(&mut writer, &report).await;
        continue;
    }

    // Send NatHoleSid FIRST — so visitor can start punching concurrently
    let sid_msg = FrpMessage::NatHoleSid(msg::NatHoleSid {
        sid: Some(sid.clone()),
        provider_addr: None, // server fills from control connection peer addr
    });
    if let Err(e) = write_msg_v1(&mut writer, &sid_msg).await {
        warn!("Failed to send NatHoleSid: {}", e);
        continue;
    }

    // TCP simultaneous open (visitor is punching at the same time)
    match tcp_simultaneous_open(&visitor_addr).await {
        Ok(p2p_stream) => {
            // Connect to local service and bridge
            if let Some(ref local) = local_addr {
                match tokio::net::TcpStream::connect(local).await {
                    Ok(local_stream) => {
                        let enc_key = self.encryption_key;
                        tokio::spawn(async move {
                            let mut p2p = p2p_stream;
                            let mut local = local_stream;
                            match tokio::io::copy_bidirectional(&mut p2p, &mut local).await {
                                Ok((to_local, to_p2p)) => {
                                    debug!("XTCP provider '{}' closed: {}B to local, {}B to P2P",
                                        proxy_name, to_local, to_p2p);
                                }
                                Err(e) => {
                                    debug!("XTCP provider '{}' bridge error: {}", proxy_name, e);
                                }
                            }
                        });
                        // Don't send NatHoleReport — Go frp uses implicit success.
                        // If bridge fails, the TCP close propagates naturally.
                    }
                    Err(e) => {
                        warn!("XTCP provider '{}': connect local failed: {}", proxy_name, e);
                        let report = FrpMessage::NatHoleReport(msg::NatHoleReport {
                            sid: Some(sid),
                        });
                        let _ = write_msg_v1(&mut writer, &report).await;
                    }
                }
            } else {
                warn!("XTCP provider '{}': no local address", proxy_name);
                let report = FrpMessage::NatHoleReport(msg::NatHoleReport {
                    sid: Some(sid),
                });
                let _ = write_msg_v1(&mut writer, &report).await;
            }
        }
        Err(e) => {
            warn!("XTCP hole punch for '{}' failed: {}", proxy_name, e);
            // Report failure — triggers STCP fallback on visitor side
            let report = FrpMessage::NatHoleReport(msg::NatHoleReport {
                sid: Some(sid),
            });
            let _ = write_msg_v1(&mut writer, &report).await;
        }
    }
}
```

- [ ] **Step 2: Build and verify**

```bash
cargo build
```

Expected: compiles cleanly.

- [ ] **Step 3: Commit**

```bash
git add frp-client/src/service.rs
git commit -m "feat: add NatHoleClient handler in client message loop"
```

---
### Task 10: Integration test — localhost XTCP hole punch

**Files:**
- Create: `frp-server/tests/xtcp_hole_punch.rs`

An integration test that verifies the complete XTCP flow using localhost (TCP simultaneous open always works on localhost).

- [ ] **Step 1: Write the integration test**

Create `frp-server/tests/xtcp_hole_punch.rs`:

```rust
mod common;

use frp_core::config::ServerConfig;
use frp_core::msg::{self, FrpMessage, NewProxy};
use frp_core::protocol::{read_msg_v1, write_msg_v1};
use frp_core::transport::IoStream;
use common::{allocate_port, raw_login, start_test_server};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Server-side XTCP message routing test.
///
/// Verifies that the server correctly routes NatHole messages between
/// visitor (fresh connection) and provider (control connection).
///
/// Flow:
/// 1. Provider logs in and registers an XTCP proxy with sk
/// 2. Visitor sends NatHoleVisitor via fresh TCP connection
/// 3. Server validates sign_key and looks up provider
/// 4. Server sends NatHoleClient to provider on control connection
/// 5. Provider (test) reads NatHoleClient, sends NatHoleSid back
/// 6. Server forwards NatHoleSid (with provider_addr) to visitor
/// 7. Provider (test) sends NatHoleReport back
/// 8. Server forwards NatHoleReport to visitor and cleans up session
#[tokio::test]
async fn test_xtcp_nat_hole_message_routing() {
    let _ = tracing_subscriber::fmt::try_init();
    let port = allocate_port();
    let cfg = ServerConfig {
        bind_addr: "127.0.0.1".into(),
        bind_port: port,
        ..Default::default()
    };
    let (_handle, _) = start_test_server(cfg).await;
    let addr: std::net::SocketAddr = format!("127.0.0.1:{}", port).parse().unwrap();

    // --- Step 1: Provider logs in and registers XTCP proxy ---
    let (mut provider, resp) = raw_login(addr, None, None, "").await.expect("provider login");
    let _run_id = resp.run_id.expect("provider should get run_id");

    let xtcp_sk = "xtcp-test-sk";
    let np = FrpMessage::NewProxy(NewProxy {
        proxy_name: "xtcp-test".into(),
        proxy_type: "xtcp".into(),
        sk: Some(xtcp_sk.to_string()),
        use_encryption: None,
        use_compression: None,
        group: None,
        group_key: None,
        local_str: Some("127.0.0.1:9999".into()),
        remote_port: Some(0),
        custom_domains: None,
        subdomain: None,
        locations: None,
        http_user: None,
        http_pwd: None,
        host_header_rewrite: None,
        headers: None,
        response_headers: None,
        route_by_http_user: None,
        allow_users: None,
        bandwidth_limit: None,
        bandwidth_limit_mode: None,
        annotations: None,
        metas: None,
        multiplexer: None,
    });
    write_msg_v1(&mut provider, &np).await.expect("send NewProxy");
    match read_msg_v1(&mut provider).await.expect("read NewProxyResp") {
        FrpMessage::NewProxyResp(ref resp) => {
            assert!(resp.error.is_none(), "XTCP proxy registration should succeed: {:?}", resp.error);
        }
        other => panic!("expected NewProxyResp, got: {:?}", other.v1_type_byte()),
    }

    // --- Step 2: Visitor sends NatHoleVisitor on fresh connection ---
    let mut visitor_conn = IoStream::Tcp(
        tokio::net::TcpStream::connect(addr).await.expect("visitor connect"),
    );
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let sign_key = frp_core::auth::generate_token(xtcp_sk, timestamp);
    let nhv = FrpMessage::NatHoleVisitor(msg::NatHoleVisitor {
        proxy_name: "xtcp-test".into(),
        sign_key: Some(sign_key.clone()),
        timestamp: Some(timestamp),
        run_id: None,
        use_encryption: None,
        use_compression: None,
    });
    write_msg_v1(&mut visitor_conn, &nhv).await.expect("send NatHoleVisitor");

    // --- Step 3: Provider reads NatHoleClient from server ---
    let sid = match read_msg_v1(&mut provider).await.expect("read NatHoleClient from provider") {
        FrpMessage::NatHoleClient(nhc) => {
            assert_eq!(nhc.proxy_name, "xtcp-test");
            assert!(nhc.visitor_addr.is_some(), "should have visitor_addr");
            println!(
                "Provider received NatHoleClient: proxy={}, visitor_addr={}",
                nhc.proxy_name,
                nhc.visitor_addr.as_deref().unwrap_or("none")
            );
            nhc.sid.expect("should have sid")
        }
        other => panic!("expected NatHoleClient, got: {:?}", other.v1_type_byte()),
    };

    // --- Step 4: Provider sends NatHoleSid back (simulating hole punch start) ---
    let sid_msg = FrpMessage::NatHoleSid(msg::NatHoleSid {
        sid: Some(sid.clone()),
        provider_addr: None, // server fills from control connection peer addr
    });
    write_msg_v1(&mut provider, &sid_msg).await.expect("send NatHoleSid");
    println!("Provider sent NatHoleSid for session {}", sid);

    // --- Step 5: Visitor reads NatHoleSid (should have provider_addr filled by server) ---
    let provider_addr = match read_msg_v1(&mut visitor_conn).await.expect("read NatHoleSid from visitor") {
        FrpMessage::NatHoleSid(sid_resp) => {
            let pa = sid_resp.provider_addr.expect("server should fill provider_addr");
            println!("Visitor received NatHoleSid with provider_addr={}", pa);
            pa
        }
        FrpMessage::NatHoleResp(resp) => {
            panic!("NatHoleVisitor rejected: {:?}", resp.error);
        }
        other => panic!("expected NatHoleSid, got: {:?}", other.v1_type_byte()),
    };

    // --- Step 6: Provider sends NatHoleReport (hole punch complete) ---
    let report = FrpMessage::NatHoleReport(msg::NatHoleReport {
        sid: Some(sid.clone()),
    });
    write_msg_v1(&mut provider, &report).await.expect("send NatHoleReport");
    println!("Provider sent NatHoleReport for session {}", sid);

    // --- Step 7: Visitor reads NatHoleReport ---
    match read_msg_v1(&mut visitor_conn).await.expect("read NatHoleReport from visitor") {
        FrpMessage::NatHoleReport(report_resp) => {
            assert_eq!(report_resp.sid, Some(sid.clone()));
            println!("Visitor received NatHoleReport — hole punch complete");
        }
        other => panic!("expected NatHoleReport, got: {:?}", other.v1_type_byte()),
    }

    // --- Verify: provider connection still usable after NAT hole session ---
    // Send another NewProxy to confirm connection alive
    let np2 = FrpMessage::NewProxy(NewProxy {
        proxy_name: "xtcp-test-2".into(),
        proxy_type: "xtcp".into(),
        sk: Some("another-sk".to_string()),
        use_encryption: None, use_compression: None,
        group: None, group_key: None,
        local_str: Some("127.0.0.1:9998".into()),
        remote_port: Some(0),
        custom_domains: None, subdomain: None, locations: None,
        http_user: None, http_pwd: None, host_header_rewrite: None,
        headers: None, response_headers: None, route_by_http_user: None,
        allow_users: None, bandwidth_limit: None, bandwidth_limit_mode: None,
        annotations: None, metas: None, multiplexer: None,
    });
    write_msg_v1(&mut provider, &np2).await.expect("send NewProxy after hole punch");
    match read_msg_v1(&mut provider).await.expect("read NewProxyResp after hole punch") {
        FrpMessage::NewProxyResp(ref resp) => {
            assert!(resp.error.is_none(), "second proxy registration should succeed: {:?}", resp.error);
        }
        other => panic!("expected NewProxyResp, got: {:?}", other.v1_type_byte()),
    }

    println!("XTCP message routing verified — all messages routed correctly");
    drop(provider);
    drop(visitor_conn);
}
```

- [ ] **Step 2: Run the integration test**

```bash
cargo test -p frp-server --test xtcp_hole_punch -- --nocapture
```

Expected: test passes, NatHoleSid received with provider_addr, NatHoleReport received.

- [ ] **Step 3: Commit**

```bash
git add frp-server/tests/xtcp_hole_punch.rs
git commit -m "test: add XTCP NAT hole punch integration test"
```

---
### Task 11: End-to-end fixup and verification

**Files:**
- All modified files

Final verification pass: run all tests, clippy, and fix any issues.

- [ ] **Step 1: Run full test suite**

```bash
cargo test --workspace
```

Expected: all existing tests pass, new XTCP test passes.

- [ ] **Step 2: Run clippy**

```bash
cargo clippy --workspace
```

Expected: no warnings.

- [ ] **Step 3: Fix any issues found**

- [ ] **Step 4: Final commit**

```bash
git add -A
git commit -m "chore: final XTCP implementation cleanup"
```
