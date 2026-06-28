# V2+QUIC Handshake — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Wire V2 handshake (ClientHello/ServerHello + AEAD) into QUIC transport paths for Rust↔Rust and Go↔Rust interop.

**Architecture:** Per-stream independence (matches Go frp): V2 magic on every QUIC stream, ClientHello/ServerHello only on control stream, AEAD only on control stream. Client-side change: 1 line (magic write). Server-side: V2 detection + handshake on control stream, per-stream V2 detection in drain task.

**Tech Stack:** tokio, quinn (via frp-core/quic.rs), existing V2 handshake/AEAD in frp-core

---

### Task 1: Expose `QuicConnection::remote_address()`

**Files:**
- Modify: `frp-core/src/quic.rs:41-59`

**Why:** Server V2 dispatch (`dispatch_v2_message`) requires `SocketAddr` for logging. `QuicConnection` wraps `quinn::Connection` which has `remote_address()` but doesn't expose it.

- [ ] **Step 1: Add method to QuicConnection**

```rust
// In frp-core/src/quic.rs, after accept_bi() and open_bi() methods, add:

    /// Return the remote peer's socket address.
    pub fn remote_address(&self) -> std::net::SocketAddr {
        self.conn.remote_address()
    }
```

- [ ] **Step 2: Build check**

```bash
cargo build -p frp-core --features quic
```

Expected: compiles clean.

- [ ] **Step 3: Commit**

```bash
git add frp-core/src/quic.rs
git commit -m "feat(quic): expose QuicConnection::remote_address() for V2 logging

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 2: Client — write V2 magic on QUIC control stream

**Files:**
- Modify: `frp-client/src/control.rs:222`

**Context:** When `self.v2 && TransportProtocol::Quic`, `dial_quic()` creates a raw QUIC stream. V2 magic must be written before `v2_handshake_client()` sends ClientHello. Currently the magic-write at line 222 is gated behind `propose_mux` which is `false` for QUIC (tcpMux only on TCP). Everything else — transport_name mapping ("quic"), v2_handshake_client call, AEAD wrap after LoginResp — already works.

- [ ] **Step 1: Extend V2 magic write condition**

In `frp-client/src/control.rs`, line 222, change:

```rust
            if propose_mux {
                frp_core::protocol::write_v2_magic(&mut io_stream).await?;
            }
```

To:

```rust
            // Write V2 magic on transports that haven't already done so:
            // - TCP mux: yamux stream needs explicit magic (caller_handles_mux=true in dial opts)
            // - QUIC: dial_quic() doesn't write magic (per-stream independence)
            // - TCP non-mux/KCP/WS/WSS: magic already written by dial_server() (opts.v2=true)
            if propose_mux || matches!(self.transport_protocol, TransportProtocol::Quic) {
                frp_core::protocol::write_v2_magic(&mut io_stream).await?;
            }
```

- [ ] **Step 2: Build check**

```bash
cargo build -p frpc --features quic
```

Expected: compiles clean.

- [ ] **Step 3: Commit**

```bash
git add frp-client/src/control.rs
git commit -m "feat(client): write V2 magic on QUIC control stream

ClientHello/ServerHello handshake + AEAD wrap already work over
IoStream::Quic — only the initial V2 magic write was missing
(gated behind propose_mux which is false for QUIC).

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 3: Server — V2 detection + handshake on QUIC accept loop

**Files:**
- Modify: `frp-server/src/service.rs:375-453` (QUIC listener accept loop)

**Context:** The QUIC accept loop (lines 375-453) currently reads the first message with `read_msg_v1()` — V1 only. Drain task (lines 391-428) also V1 only. Both need V2 detection per-stream.

**Strategy:** Try 7-byte V2 magic read on every new QUIC stream. If V2: `v2_handshake_server()` → read plaintext Login → `dispatch_v2_message()`. If V1: `BufferedRead` replay consumed bytes → existing `read_msg_v1()` path. Drain task becomes universal (detects V2 per-stream, falls back to V1).

- [ ] **Step 1: Replace QUIC accept loop block**

Replace lines 375-453 (from `loop {` inside the QUIC listener task through the end of the accept match) with the updated version below.

**File location:** `frp-server/src/service.rs`, starting at line 375 `loop {` inside the QUIC listener `tokio::spawn(async move { ... })` block.

Replace the entire `match listener.accept().await { Ok((stream, conn)) => { ... } }` block (lines 376-443) with:

```rust
                loop {
                    match listener.accept().await {
                        Ok((stream, conn)) => {
                            let state = quic_state.clone();
                            tokio::spawn(async move {
                                let mut ctl = frp_core::transport::IoStream::Quic(stream);

                                // Try V2 magic detection on first stream.
                                // Per-stream independence: each QUIC stream gets its own
                                // V2 detection, matching Go frp's WriteMagicIfV2() per stream.
                                let mut magic = [0u8; 7];
                                let is_v2 = match ctl.read_exact(&mut magic).await {
                                    Ok(_) => magic == frp_core::protocol::V2_MAGIC_BYTES,
                                    Err(_) => false,
                                };

                                if is_v2 {
                                    // --- V2 path ---
                                    // ClientHello/ServerHello handshake → AEAD crypto negotiation.
                                    // Login is read as plaintext V2 message; AEAD wrapping happens
                                    // inside handle_control after LoginResp (matching Go frp flow).
                                    let (msg_payload, crypto_ctx) = match frp_core::v2_handshake::v2_handshake_server(&mut ctl).await {
                                        Ok((Some(p), crypto)) => (p, crypto),
                                        Ok((None, crypto)) => {
                                            match ctl.read_raw_v2_frame().await {
                                                Ok((frp_core::protocol::V2_FRAME_TYPE_MESSAGE, _, p)) => (p, crypto),
                                                Ok((ft, _, _)) => {
                                                    tracing::warn!("QUIC V2: unexpected frame type {} after handshake", ft);
                                                    return;
                                                }
                                                Err(e) => {
                                                    tracing::warn!("QUIC V2: failed to read message after handshake: {}", e);
                                                    return;
                                                }
                                            }
                                        }
                                        Err(e) => {
                                            tracing::warn!("QUIC V2 handshake error: {}", e);
                                            return;
                                        }
                                    };

                                    // Get remote address before moving conn into drain task.
                                    let addr: std::net::SocketAddr = conn.remote_address();

                                    // Universal drain task: handles both V2 and V1 work streams.
                                    // Each accepted stream independently detects V2 magic — if V2,
                                    // reads first V2 message; if V1, replays consumed bytes + read_msg_v1.
                                    let cancel = tokio_util::sync::CancellationToken::new();
                                    let drain_cancel = cancel.clone();
                                    let drain_state = state.clone();
                                    let drain_conn = conn.clone();
                                    tokio::spawn(async move {
                                        tracing::debug!("QUIC drain (V2 ctl) started");
                                        loop {
                                            tokio::select! {
                                                _ = drain_cancel.cancelled() => {
                                                    tracing::debug!("QUIC drain (V2 ctl) cancelled");
                                                    break;
                                                }
                                                result = drain_conn.accept_bi() => {
                                                    match result {
                                                        Ok(work_stream) => {
                                                            tracing::debug!("QUIC drain (V2 ctl): accepted new stream");
                                                            let s = drain_state.clone();
                                                            tokio::spawn(async move {
                                                                let mut wc = frp_core::transport::IoStream::Quic(work_stream);
                                                                let mut wmagic = [0u8; 7];
                                                                let w_is_v2 = match wc.read_exact(&mut wmagic).await {
                                                                    Ok(_) => wmagic == frp_core::protocol::V2_MAGIC_BYTES,
                                                                    Err(_) => false,
                                                                };
                                                                if w_is_v2 {
                                                                    match wc.read_v2_frame().await {
                                                                        Ok(frp_core::msg::FrpMessage::NewWorkConn(nwc)) => {
                                                                            crate::handlers::handle_work_conn_inner(wc, nwc, s).await;
                                                                        }
                                                                        Ok(other) => {
                                                                            tracing::warn!("QUIC V2 drain: unexpected msg type_id={:?}", other.v2_type_id());
                                                                        }
                                                                        Err(e) => {
                                                                            tracing::warn!("QUIC V2 drain: read error: {}", e);
                                                                        }
                                                                    }
                                                                } else {
                                                                    let mut wc = frp_core::transport::IoStream::BufferedRead(wmagic.to_vec(), 0, Box::new(wc));
                                                                    match frp_core::protocol::read_msg_v1(&mut wc).await {
                                                                        Ok(frp_core::msg::FrpMessage::NewWorkConn(nwc)) => {
                                                                            crate::handlers::handle_work_conn_inner(wc, nwc, s).await;
                                                                        }
                                                                        Ok(other) => {
                                                                            tracing::warn!("QUIC V1 drain: unexpected msg type_byte={:?}", other.v1_type_byte());
                                                                        }
                                                                        Err(e) => {
                                                                            tracing::warn!("QUIC V1 drain: read error: {}", e);
                                                                        }
                                                                    }
                                                                }
                                                            });
                                                        }
                                                        Err(e) => {
                                                            tracing::debug!("QUIC drain (V2 ctl) done: {e}");
                                                            break;
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    });

                                    // Dispatch V2 Login → handle_control(v2=true, crypto_ctx).
                                    // handle_control wraps stream in AEAD after LoginResp.
                                    crate::handlers::dispatch_v2_message(ctl, msg_payload, state, addr, None, None, crypto_ctx).await;
                                    cancel.cancel();
                                } else {
                                    // --- V1 fallback ---
                                    // Replay consumed 7 bytes so read_msg_v1 sees the full V1 header.
                                    let mut ctl = frp_core::transport::IoStream::BufferedRead(magic.to_vec(), 0, Box::new(ctl));

                                    match frp_core::protocol::read_msg_v1(&mut ctl).await {
                                        Ok(frp_core::msg::FrpMessage::Login(login)) => {
                                            // Universal drain task (V2-aware, same pattern as V2 path above).
                                            let cancel = tokio_util::sync::CancellationToken::new();
                                            let drain_cancel = cancel.clone();
                                            let drain_state = state.clone();
                                            let drain_conn = conn.clone();
                                            tokio::spawn(async move {
                                                tracing::debug!("QUIC drain (V1 ctl) started");
                                                loop {
                                                    tokio::select! {
                                                        _ = drain_cancel.cancelled() => {
                                                            tracing::debug!("QUIC drain (V1 ctl) cancelled");
                                                            break;
                                                        }
                                                        result = drain_conn.accept_bi() => {
                                                            match result {
                                                                Ok(work_stream) => {
                                                                    tracing::debug!("QUIC drain (V1 ctl): accepted new stream");
                                                                    let s = drain_state.clone();
                                                                    tokio::spawn(async move {
                                                                        let mut wc = frp_core::transport::IoStream::Quic(work_stream);
                                                                        let mut wmagic = [0u8; 7];
                                                                        let w_is_v2 = match wc.read_exact(&mut wmagic).await {
                                                                            Ok(_) => wmagic == frp_core::protocol::V2_MAGIC_BYTES,
                                                                            Err(_) => false,
                                                                        };
                                                                        if w_is_v2 {
                                                                            match wc.read_v2_frame().await {
                                                                                Ok(frp_core::msg::FrpMessage::NewWorkConn(nwc)) => {
                                                                                    crate::handlers::handle_work_conn_inner(wc, nwc, s).await;
                                                                                }
                                                                                Ok(other) => {
                                                                                    tracing::warn!("QUIC V2 drain: unexpected msg type_id={:?}", other.v2_type_id());
                                                                                }
                                                                                Err(e) => {
                                                                                    tracing::warn!("QUIC V2 drain: read error: {}", e);
                                                                                }
                                                                            }
                                                                        } else {
                                                                            let mut wc = frp_core::transport::IoStream::BufferedRead(wmagic.to_vec(), 0, Box::new(wc));
                                                                            match frp_core::protocol::read_msg_v1(&mut wc).await {
                                                                                Ok(frp_core::msg::FrpMessage::NewWorkConn(nwc)) => {
                                                                                    crate::handlers::handle_work_conn_inner(wc, nwc, s).await;
                                                                                }
                                                                                Ok(other) => {
                                                                                    tracing::warn!("QUIC V1 drain: unexpected msg type_byte={:?}", other.v1_type_byte());
                                                                                }
                                                                                Err(e) => {
                                                                                    tracing::warn!("QUIC V1 drain: read error: {}", e);
                                                                                }
                                                                            }
                                                                        }
                                                                    });
                                                                }
                                                                Err(e) => {
                                                                    tracing::debug!("QUIC drain (V1 ctl) done: {e}");
                                                                    break;
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            });
                                            // Run control handler on first stream (blocking).
                                            control::handle_control(ctl, login, state, None, None, false, None).await;
                                            cancel.cancel();
                                        }
                                        Ok(frp_core::msg::FrpMessage::NewWorkConn(nwc)) => {
                                            crate::handlers::handle_work_conn_inner(ctl, nwc, state).await;
                                        }
                                        Ok(other) => {
                                            tracing::warn!("Unexpected QUIC message: {:?}", other.v1_type_byte());
                                        }
                                        Err(e) => {
                                            tracing::warn!("QUIC read error: {}", e);
                                        }
                                    }
                                }
                            });
                        }
                        Err(e) => {
                            tracing::error!("QUIC accept error: {}", e);
                            break;
                        }
                    }
                }
```

- [ ] **Step 2: Build check**

```bash
cargo build -p frps --features quic
```

Expected: compiles clean. If compilation fails, check that `CancellationToken` import is still at the top of the file (line 7: `use tokio_util::sync::CancellationToken;` — already present for `#[cfg(feature = "quic")]`).

- [ ] **Step 3: Commit**

```bash
git add frp-server/src/service.rs
git commit -m "feat(server): V2 detection + handshake on QUIC accept loop

Control stream: 7-byte magic detection → v2_handshake_server →
dispatch_v2_message (Login → handle_control with v2=true, crypto_ctx).
V1 fallback: BufferedRead replays consumed bytes for backward compat.

Drain task: per-stream V2 detection on work streams. Each accepted
QUIC stream independently detects V2 magic — V2 work streams dispatch
via read_v2_frame, V1 work streams fall back to read_msg_v1.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 4: Full workspace build + clippy

**Files:** (none, verification only)

- [ ] **Step 1: Build all crates with quic feature**

```bash
cargo build --workspace --features quic
```

Expected: all crates compile without errors.

- [ ] **Step 2: Clippy with quic feature**

```bash
cargo clippy --workspace --features quic -- -D warnings
```

Expected: 0 warnings.

- [ ] **Step 3: Build without quic feature (regression check)**

```bash
cargo build --workspace
```

Expected: all crates compile (QUIC code is `#[cfg(feature = "quic")]` gated).

---

### Task 5: Write `v2_quic_r2r` compat test

**Files:**
- Create: `frp-server/tests/v2_quic_r2r.rs`

**Why:** Verify Rust frpc ↔ Rust frps over QUIC with V2 handshake end-to-end. TCP proxy tunnel over V2-QUIC control + work connections.

- [ ] **Step 1: Write the test**

```rust
//! Rust↔Rust V2+QUIC compatibility test.
//!
//! Verifies: V2 handshake (ClientHello/ServerHello) + AEAD crypto +
//! TCP proxy tunnel over QUIC transport.
//!
//! Prerequisites:
//!   cargo build -p frps -p frpc --features quic
//!
//! Run:
//!   cargo test -p frp-server --test v2_quic_r2r -- --nocapture
//!
//! Skip if no QUIC support or no TLS certs:
//!   RUSTIC_SKIP_QUIC=1 cargo test ...

use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::{Child, Command};
use std::time::Duration;

/// Wait for a TCP port to be ready.
fn wait_for_port(port: u16, timeout: Duration) -> bool {
    let start = std::time::Instant::now();
    while start.elapsed() < timeout {
        if std::net::TcpStream::connect_timeout(
            &format!("127.0.0.1:{}", port).parse().unwrap(),
            Duration::from_millis(200),
        )
        .is_ok()
        {
            return true;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    false
}

/// Generate self-signed TLS cert/key for QUIC test.
fn ensure_tls_certs() -> (String, String) {
    let dir = std::env::temp_dir().join("frp-v2-quic-test");
    std::fs::create_dir_all(&dir).ok();
    let cert_path = dir.join("cert.pem");
    let key_path = dir.join("key.pem");
    let cert_str = cert_path.to_str().unwrap().to_string();
    let key_str = key_path.to_str().unwrap().to_string();

    if cert_path.exists() && key_path.exists() {
        return (cert_str, key_str);
    }

    // Generate self-signed cert with openssl (available on most systems).
    let output = Command::new("openssl")
        .args([
            "req", "-x509", "-newkey", "rsa:2048", "-keyout",
            &key_str, "-out", &cert_str, "-days", "1", "-nodes",
            "-subj", "/CN=localhost",
        ])
        .output()
        .expect("openssl not found — install openssl or set RUSTIC_SKIP_QUIC=1");
    assert!(output.status.success(), "openssl cert gen failed: {:?}", output);

    (cert_str, key_str)
}

struct FrpsProcess {
    child: Child,
    port: u16,
}

impl FrpsProcess {
    fn start(port: u16, cert: &str, key: &str) -> Self {
        let dir = std::env::temp_dir().join("frp-v2-quic-test");
        std::fs::create_dir_all(&dir).ok();
        let config_path = dir.join("frps.toml");
        let config = format!(
            r#"
bind_port = {bind_port}
quic_bind_port = {quic_port}
vhost_http_port = 0
vhost_https_port = 0
tcpmux_httpconnect_port = 0

[auth]
method = "token"
token = "test123"

[tls]
tls_enable = true
tls_cert_file = "{cert}"
tls_key_file = "{key}"

[transport]
tcp_mux = false

[web_server]
port = 0
"#,
            bind_port = port,
            quic_port = port,
            cert = cert,
            key = key,
        );
        std::fs::write(&config_path, &config).unwrap();

        let child = Command::new(
            std::env::current_dir()
                .unwrap()
                .join("target/debug/frps"),
        )
        .args(["-c", config_path.to_str().unwrap()])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("failed to start frps");

        assert!(wait_for_port(port, Duration::from_secs(10)), "frps did not start");

        FrpsProcess { child, port }
    }
}

impl Drop for FrpsProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

struct FrpcProcess {
    child: Child,
}

impl FrpcProcess {
    fn start(server_port: u16, cert: &str) -> Self {
        let dir = std::env::temp_dir().join("frp-v2-quic-test");
        std::fs::create_dir_all(&dir).ok();
        let config_path = dir.join("frpc.toml");
        let config = format!(
            r#"
server_addr = "127.0.0.1"
server_port = {server_port}
transport_protocol = "quic"
tls_enable = true
tls_server_name = "localhost"
tls_ca_file = "{cert}"
tcp_mux = false
v2 = true
login_fail_exit = false

[auth]
method = "token"
token = "test123"

[[proxies]]
name = "tcp-test"
type = "tcp"
local_ip = "127.0.0.1"
local_port = {backend_port}
remote_port = {proxy_port}
"#,
            server_port = server_port,
            cert = cert,
            backend_port = BACKEND_PORT,
            proxy_port = PROXY_PORT,
        );
        std::fs::write(&config_path, &config).unwrap();

        let child = Command::new(
            std::env::current_dir()
                .unwrap()
                .join("target/debug/frpc"),
        )
        .args(["-c", config_path.to_str().unwrap()])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("failed to start frpc");

        FrpcProcess { child }
    }
}

impl Drop for FrpcProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

const SERVER_PORT: u16 = 17890;
const PROXY_PORT: u16 = 17891;
const BACKEND_PORT: u16 = 17892;

#[test]
fn v2_quic_r2r_tcp_proxy() {
    // Skip if RUSTIC_SKIP_QUIC is set.
    if std::env::var("RUSTIC_SKIP_QUIC").is_ok() {
        eprintln!("Skipping: RUSTIC_SKIP_QUIC set");
        return;
    }

    let (cert, key) = ensure_tls_certs();

    // Start backend TCP echo server.
    let backend = std::net::TcpListener::bind(format!("127.0.0.1:{}", BACKEND_PORT))
        .expect("bind backend");
    std::thread::spawn(move || {
        for stream in backend.incoming() {
            if let Ok(mut s) = stream {
                let mut buf = [0u8; 1024];
                while let Ok(n) = s.read(&mut buf) {
                    if n == 0 { break; }
                    s.write_all(&buf[..n]).ok();
                }
            }
        }
    });

    // Start frps.
    let _frps = FrpsProcess::start(SERVER_PORT, &cert, &key);

    // Start frpc (V2 + QUIC).
    let _frpc = FrpcProcess::start(SERVER_PORT, &cert);

    // Wait for proxy to be ready.
    assert!(wait_for_port(PROXY_PORT, Duration::from_secs(10)), "proxy port not ready");

    // Test TCP tunnel through V2-QUIC proxy.
    let mut stream = TcpStream::connect_timeout(
        &format!("127.0.0.1:{}", PROXY_PORT).parse().unwrap(),
        Duration::from_secs(5),
    )
    .expect("connect to proxy");

    let msg = b"hello v2 quic!";
    stream.write_all(msg).expect("write");
    stream.flush().ok();

    let mut buf = [0u8; 64];
    let n = stream.read(&mut buf).expect("read");
    assert_eq!(&buf[..n], msg, "echo mismatch");

    eprintln!("✓ V2+QUIC TCP proxy tunnel works");
}
```

- [ ] **Step 2: Build test dependencies**

```bash
cargo test -p frp-server --test v2_quic_r2r --no-run --features quic
```

Expected: test binary compiles.

- [ ] **Step 3: Run the test**

```bash
cargo test -p frp-server --test v2_quic_r2r -- --nocapture
```

Expected: `✓ V2+QUIC TCP proxy tunnel works` — test passes.

- [ ] **Step 4: Commit**

```bash
git add frp-server/tests/v2_quic_r2r.rs
git commit -m "test: add v2_quic_r2r compat test (V2+QUIC Rust↔Rust)

Verifies: V2 handshake + AEAD crypto + TCP proxy tunnel over QUIC
transport. Uses self-signed TLS certs (openssl), tests end-to-end
echo through frps→frpc→backend.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 6: Run full regression test suite

**Files:** (none, verification only)

- [ ] **Step 1: Run all workspace tests**

```bash
cargo test --workspace --features quic
```

Expected: all existing tests pass (213+ tests). New `v2_quic_r2r` test passes.

- [ ] **Step 2: Run compat test suite**

```bash
bash scripts/compat-test.sh --verbose
```

Expected: 40/40 CI tests pass, 2 guarded (XTCP needs public network, V2 has protocol bug — known, pre-existing).

- [ ] **Step 3: Final clippy**

```bash
cargo clippy --workspace --features quic -- -D warnings
```

Expected: 0 warnings.

---

## Modified Files Summary

| File | Change | Lines |
|------|--------|-------|
| `frp-core/src/quic.rs` | Add `remote_address()` method | +4 |
| `frp-client/src/control.rs` | Extend V2 magic write condition | +4 (1 logic change) |
| `frp-server/src/service.rs` | V2 detection + handshake + universal drain task | ~100 replaced |
| `frp-server/tests/v2_quic_r2r.rs` | New compat test | ~210 new |

No new dependencies. All building blocks in `frp-core` (V2 handshake, AEAD stream, V2 frame I/O) already existed — this plan just wires them into the QUIC dial/accept paths.
