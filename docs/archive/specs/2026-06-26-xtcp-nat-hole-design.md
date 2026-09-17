# XTCP NAT Hole Punching — Design Spec

**Goal:** Implement XTCP NAT hole punching with STCP relay fallback, matching Go frp v0.69.1 behavior.

**Architecture:** Server coordinates NAT session via new `NatHoleCoordinator` (message relay + session tracking). Provider and visitor both attempt TCP simultaneous open. On failure, falls back to existing STCP relay path. Reuses 5 existing NatHole message types (`NatHoleVisitor/Client/Resp/Sid/Report`).

**Tech Stack:** tokio async TCP, SO_REUSEADDR for simultaneous open, existing InternalMsg channel for intra-server dispatch.

---

## 1. Message Flow

```
Visitor                    Server                      Provider
  |                          |                           |
  |-- NatHoleVisitor ------->|                           |
  |   {proxy_name, sign_key, |                           |
  |    timestamp, run_id,    |                           |
  |    use_enc, use_comp}    |                           |
  |                          |-- NatHoleClient --------->|
  |                          |   (via InternalMsg)       |
  |                          |   {proxy_name, sign_key,  |
  |                          |    run_id, visitor_addr?} |
  |                          |<-- NatHoleSid ------------|
  |                          |   {sid}                   |
  |<-- NatHoleSid -----------|                           |
  |   {sid}                  |                           |
  |                          |<-- NatHoleReport ---------|
  |                          |   {sid}                   |
  |<-- NatHoleReport --------|                           |
  |   {sid}                  |                           |
  |                          |                           |
  |==== TCP simultaneous open (hole punch) ==============|
  |  (both bind, both dial, SO_REUSEADDR, 5s timeout)    |
  |                          |                           |
  |<========= direct P2P connection ====================>|
  |                          |                           |
  |  (on failure: STCP relay fallback via ReqWorkConn)   |
  |                          |                           |
```

## 2. Components

### 2.1 Server: `NatHoleCoordinator` (`frp-server/src/nat_hole.rs`)

New module. Singleton stored in `AppState`.

```rust
pub struct NatHoleCoordinator {
    sessions: RwLock<HashMap<String, NatHoleSession>>,
}

struct NatHoleSession {
    sid: String,
    proxy_name: String,
    visitor_ctl_tx: mpsc::UnboundedSender<InternalMsg>,
    provider_ctl_tx: mpsc::UnboundedSender<InternalMsg>,
    created_at: Instant,
}
```

Methods:
- `create_session(proxy_name, visitor_ctl, provider_ctl) -> sid`: registers NAT session, returns transaction ID
- `get_session(sid) -> Option<NatHoleSession>`: lookup for message routing
- `remove_session(sid)`: cleanup
- `expire_sessions(timeout)`: periodic cleanup of stale sessions (60s timeout)

### 2.2 Server: `control.rs` changes

Three new message arms in the select loop:

**NatHoleVisitor handler:**
1. Validate sign_key = MD5(proxy.sk + timestamp), reject if wrong
2. Resolve provider run_id from proxy_manager
3. Lookup provider control_tx from run_id_to_ctl_tx
4. Generate sid (UUID v4)
5. Store session: `nat_hole.create_session(proxy_name, this_ctl_tx, provider_ctl_tx)`
6. Send `InternalMsg::NatHoleClient` → provider

**NatHoleSid handler (from provider):**
7. Lookup session by sid
8. Forward `NatHoleSid { sid }` → visitor via `InternalMsg::NatHoleSid`

**NatHoleReport handler (from provider):**
9. Lookup session by sid
10. Forward `NatHoleReport { sid }` → visitor via `InternalMsg::NatHoleReport`
11. If report indicates failure: trigger STCP fallback (visitor sends ReqWorkConn, existing work conn path handles relay)
12. Cleanup session

### 2.3 Client: Visitor side (`frp-client/src/service.rs`)

In `run_visitor_listener`, split behavior by visitor type:

**XTCP path (new):**
1. Accept user connection on visitor listener port
2. Dial server, send `NatHoleVisitor`
3. Read `NatHoleSid` from server (ack + transaction ID)
4. Read `NatHoleReport` from server (provider ready signal)
5. TCP simultaneous open:
   - Bind local port with `SO_REUSEADDR`
   - Dial provider's address (received in NatHoleSid or earlier)
   - Timeout: 5 seconds
6. If P2P connected: bridge user_conn ↔ p2p_stream
7. If timeout/error: fall back to STCP relay (send NewVisitorConn, bridge via server)

**STCP path (existing):** unchanged.

### 2.4 Client: Provider side (`frp-client/src/service.rs` control loop)

New message arm in the run() select loop:

**NatHoleClient handler:**
1. Receive `InternalMsg::NatHoleClient` from server (via work conn or control conn)
2. TCP simultaneous open:
   - Bind local port with `SO_REUSEADDR`
   - Extract visitor addr from NatHoleClient
   - Dial visitor addr with `SO_REUSEADDR`
   - Timeout: 5 seconds
3. Send `NatHoleSid` back to server (ack + self addr)
4. If P2P connected:
   - Connect to local service
   - Bridge p2p_stream ↔ local_service
   - Send `NatHoleReport` success
5. If timeout: send `NatHoleReport` error → triggers STCP fallback on visitor side

### 2.5 InternalMsg additions (`frp-server/src/service.rs`)

```rust
pub enum InternalMsg {
    // ... existing variants ...
    NatHoleClient(msg::NatHoleClient),
    NatHoleSid(msg::NatHoleSid),
    NatHoleReport(msg::NatHoleReport),
}
```

## 3. Public Address Exchange

Server acts as signaling relay — tells each side the other's address:

1. Visitor connects to server, sends `NatHoleVisitor`
2. Server extracts visitor's public addr from TCP connection metadata
3. Server sends `NatHoleClient { ..., visitor_addr }` to provider
4. Provider begins simultaneous open, sends `NatHoleSid { sid }` to server
5. Server extracts provider's public addr from its control connection
6. Server forwards `NatHoleSid { sid, provider_addr }` to visitor
7. Both now know each other's addr → TCP simultaneous open

**Message field additions:**
- `NatHoleClient`: add `visitor_addr: Option<String>` — server sets this
- `NatHoleSid`: add `provider_addr: Option<String>` — server fills from provider's control conn

These additions are backward-compatible (Option<String> with skip_serializing_if).

## 4. Simultaneous Open Mechanics

```
Both sides:
1. local = TcpSocket::bind("0.0.0.0:0")
2. local.set_reuseaddr(true)
3. local.set_reuseport(true)  // if available
4. local.connect(peer_addr)   // with 5s timeout
5. If both connect → kernel matches SYN packets → P2P established
```

TCP simultaneous open requires:
- Both sides bind BEFORE dialing
- Both sides use same port for bind+connect (or SO_REUSEADDR)
- Works through most NAT types (full-cone, restricted-cone, port-restricted-cone)
- Does NOT work through symmetric NAT

## 5. STCP Fallback

When hole punch fails (5s timeout):
1. Provider sends `NatHoleReport { sid }` to server
2. Server forwards to visitor
3. Visitor falls back to current STCP flow:
   - Send `NewVisitorConn` to server
   - Server sends `ReqWorkConn` to provider
   - Provider spawns work conn (existing path)
   - Server bridges visitor ↔ provider via work conn
4. No new code needed for fallback — reuse existing STCP infrastructure

## 6. Sign Key Validation

Provider registers XTCP proxy with `sk` (secret key). Visitor sends:
```
sign_key = MD5(sk + timestamp)
```

Server validates against proxy's stored `sk`. Same pattern as token auth in `AuthConfig`.

## 7. Config

No new config fields needed. Existing `VisitorConfig` and `ProxyConfig` already have:
- `type: "xtcp"` — distinguishes XTCP from STCP
- `sk` — secret key for sign validation
- `server_name` — proxy name to connect to
- `bind_addr`, `bind_port` — visitor listener

## 8. Error Handling

| Scenario | Server response | Visitor outcome |
|----------|----------------|-----------------|
| Invalid sign_key | NatHoleSid with error, cleanup session | Connection refused |
| Provider not found | NatHoleSid with error | Connection refused |
| Hole punch timeout (5s) | Forward NatHoleReport error | STCP fallback |
| Session expired (60s) | Drop session, log warning | STCP fallback |
| Duplicate sid | Reject, log warn | — |

## 9. Testing Plan

| Test | Type | What it verifies |
|------|------|-----------------|
| sign_key validation rejects wrong sk | unit | Auth check |
| provider not found returns error | unit | Lookup failure |
| localhost simultaneous open connects | integration | P2P path on same machine |
| STCP fallback on blocked P2P | integration | Fallback when hole punch fails |
| session expiry cleans up | unit | Timeout cleanup |
| visitor NatHoleVisitor format | unit | JSON serialization matches Go frp |

## 10. Go frp Parity

| Feature | Go frp v0.69.1 | This spec |
|---------|---------------|-----------|
| NatHoleVisitor/Client/Sid/Report messages | ✅ | ✅ (already defined) |
| MD5 sign_key validation | ✅ | ✅ |
| TCP simultaneous open | ✅ | ✅ |
| SO_REUSEADDR | ✅ | ✅ |
| STCP fallback on failure | ✅ | ✅ |
| Session timeout (60s) | ✅ | ✅ |
| NAT type detection | ✅ | ❌ (not needed for hole punch) |
| STUN | ❌ | ❌ |

## 11. Files Summary

| File | Action | Lines (est.) |
|------|--------|-------------|
| `frp-server/src/nat_hole.rs` | Create | ~100 |
| `frp-server/src/service.rs` | Modify | ~20 (InternalMsg variants, AppState field, imports) |
| `frp-server/src/control.rs` | Modify | ~80 (3 message arms) |
| `frp-server/src/lib.rs` | Modify | ~2 (pub mod nat_hole) |
| `frp-client/src/service.rs` | Modify | ~120 (visitor XTCP path, provider NatHoleClient handler, simultaneous open) |
| `frp-core/src/msg.rs` | Modify | ~8 (addr fields on NatHoleClient, NatHoleSid) |
| `frp-core/src/protocol.rs` | No change | 0 (dispatch already exists) |
| **Total** | | **~330** |
