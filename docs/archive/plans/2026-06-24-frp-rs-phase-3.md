# frp-rs Phase 3: Feature Gaps vs Go frp v0.69.1

**Goal:** Close the remaining feature gaps between frp-rs and Go frp v0.69.1 — STCP/XTCP/SUDP pairing, KCP stream wrapper, QUIC transport, TCP MUX, and Dashboard v2 API.

**Architecture:** Each feature is independent. STCP/XTCP extend the existing proxy type system. KCP/QUIC add new transport variants. TCP MUX is a cross-cutting architectural change. Dashboard v2 is an extension of the existing axum-based dashboard.

---

## Remaining Gaps (4 features, ~2-5 days each)

### A: STCP/XTCP/SUDP Pairing

**What's missing:** Message types (`NewVisitorConn`, `NewVisitorConnResp`) defined, `sk_index` in AppState exists, but the actual visitor→secret proxy pairing and bridging is not implemented.

**What needs to happen:**
- `frp-server/src/visitor.rs` — Create a `VisitorManager` that tracks secret proxies by `sk` and matches visitor connections
- `frp-server/src/control.rs` — When `NewVisitorConn` arrives, look up `sk`, bridge visitor's work connection to secret proxy's work connection
- `frp-client/src/control.rs` — Add visitor proxy type handling: send `NewVisitorConn`, wait for response, create work connection
- `frp-core/src/msg.rs` — Message types already defined, may need additional fields

**Key design:** Unlike TCP, STCP doesn't use port-based proxy listeners. Instead, the server matches visitor connections to secret proxy work connections using the `sk` field as a lookup key.

**Estimated effort:** 2-3 days

---

### B: KCP Stream Wrapper

**What's missing:** `kcp2` dependency added, `TransportProtocol::Kcp` exists, `IoStream::Kcp(DuplexStream)` variant exists. But no actual KCP ↔ TCP bridge or AsyncRead/AsyncWrite implementation.

**What needs to happen:**
- `frp-core/src/transport.rs` — Implement `kcp_connect()` and `kcp_accept()` functions
- `frp-core/src/transport.rs` — Implement KCP stream wrapper that provides `AsyncRead` + `AsyncWrite` over UDP + KCP
- — Use a background task that runs the KCP update loop and bridges to a `tokio::io::duplex()` channel
- Wire into `frp-server/src/service.rs` when `kcp_bind_port > 0`
- Wire into `frp-client/src/control.rs` for KCP transport connections

**Key challenge:** KCP is poll-based (`kcp.update()`, `kcp.input()`, `kcp.recv()`, `kcp.send()`). Need to bridge between poll-based KCP and tokio's async I/O model. Recommended approach: background task with `tokio::io::duplex()`.

```rust
pub async fn kcp_bridge(udp: UdpSocket, peer: SocketAddr, mut kcp: Kcp) -> (impl AsyncRead, impl AsyncWrite) {
    let (mut tx, mut rx) = tokio::io::duplex(65536);
    tokio::spawn(async move {
        let mut buf = vec![0u8; 2048];
        loop {
            tokio::select! {
                // UDP → KCP → Duplex
                Ok((n, _)) = udp.recv_from(&mut buf) => {
                    kcp.input(&buf[..n]);
                    while let Ok(n) = kcp.recv(&mut buf) {
                        if tx.write_all(&buf[..n]).await.is_err() { break; }
                    }
                }
                // Duplex → KCP → UDP
                Ok(n) = rx.read(&mut buf) => {
                    kcp.send(&buf[..n]);
                    kcp.flush();
                    let mut send_buf = vec![0u8; 2048];
                    while let Ok(n) = kcp.recv_send_buf(&mut send_buf) {
                        udp.send_to(&send_buf[..n], &peer).await;
                    }
                }
            }
        }
    });
    (tx, rx)
}
```

**Estimated effort:** 1-2 days

---

### C: QUIC Transport

**What's missing:** No dependency, no implementation. QUIC uses TLS 1.3 natively and provides connection multiplexing.

**What needs to happen:**
- Add `quinn` and `rustls` dependencies to frp-core
- `frp-core/src/transport.rs` — Add `TransportProtocol::Quic` (already exists as placeholder)
- Implement `quic_connect()` and `quic_accept()` using `quinn::Endpoint`
- — QUIC provides `AsyncRead`/`AsyncWrite` natively through `quinn::SendStream`/`RecvStream`
- Wire into `frp-server/src/service.rs` when `quic_bind_port > 0`
- Wire into `frp-client/src/control.rs` for QUIC transport connections

**Key challenge:** QUIC requires TLS 1.3 certificates even for the handshake. Need to integrate with existing `rustls` infrastructure.

**Estimated effort:** 2-3 days

---

### D: TCP MUX

**What's missing:** Full architecture change. TCP MUX multiplexes control messages and data streams over a single TCP connection using a multiplexing protocol like yamux.

**What needs to happen:**
- Add `yamux` or similar crate dependency
- — On the server: when a client connects, wrap the connection with yamux. Control messages and work connections are multiplexed streams over the same connection.
- — On the client: use yamux to multiplex all control and data traffic over one TCP connection
- — Control handler reads/writes from the yamux control stream
- — Work connections are opened as new yamux streams

**Key challenge:** Fundamental change to the connection model. Currently, work connections are separate TCP connections. With TCP MUX, they become multiplexed streams on the same TCP connection. This affects:
- The accept loop (no longer dispatches Login vs NewWorkConn by listening on TCP)
- Work connection pool management
- Connection lifecycle and error handling

**Estimated effort:** 3-5 days

---

## Execution Priority

| Priority | Feature | Effort | Impact | Dependencies |
|---|---|---|---|---|
| P1 | STCP/XTCP pairing | 2-3 days | New proxy types | Message types done |
| P2 | KCP stream wrapper | 1-2 days | Alternative transport | kcp2 dep done |
| P3 | QUIC transport | 2-3 days | Alternative transport | New dep (quinn) |
| P4 | TCP MUX | 3-5 days | Performance | No deps |
| P5 | Dashboard v2 API | 1-2 days | Operations | axum dep done |

**Recommended order:** STCP → KCP → QUIC → TCP MUX → Dashboard v2
