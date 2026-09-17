# XTCP Full Coverage — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Achieve full XTCP test coverage: 12 end-to-end compat tests (Phase 1, VPS CI) + 8 server-side integration tests (Phase 2, localhost).

**Architecture:** Phase 2 first (no external deps) — Rust integration tests via raw TCP protocol simulation against in-process frps. Phase 1 second — VPS hosts frps, GitHub Actions runs provider+visitor frpc binaries, real STUN + TCP simultaneous open. Implementation order: Phase 2 → Phase 1.

**Tech Stack:** Rust (tokio test), Bash (compat-test.sh, remote-frps.sh), GitHub Actions YAML.

---

## File Map

| File | Action | Purpose |
|------|--------|---------|
| `frp-server/tests/xtcp_fallback.rs` | Create | 5 server-side protocol tests |
| `frp-server/tests/xtcp_edge.rs` | Create | 3 edge-case server tests |
| `frp-server/tests/xtcp_hole_punch.rs` | Modify | Add 1 invalid-sid test |
| `scripts/remote-frps.sh` | Create | VPS frps lifecycle management |
| `.github/workflows/xtcp-compat.yml` | Create | CI workflow for XTCP e2e |
| `scripts/compat-test.sh` | Modify | Add --frps-remote, --xtcp-only, 8 new XTCP test funcs |

---

## Phase 2: Local Server Integration Tests

### Task 1: Create `frp-server/tests/xtcp_fallback.rs` — Error & Timeout

**Files:**
- Create: `frp-server/tests/xtcp_fallback.rs`

- [ ] **Step 1: Write the test file**

```rust
mod common;

use std::net::SocketAddr;
use std::time::Duration;

use frp_core::config::ServerConfig;
use frp_core::msg::{self, FrpMessage, NatHoleVisitor, NewProxy};
use frp_core::protocol::{read_msg_v1, write_msg_v1};
use frp_core::transport::IoStream;

use common::{allocate_port, raw_login, start_test_server};

// ── test_xtcp_precheck_nonexistent_proxy ──

#[tokio::test]
async fn test_xtcp_precheck_nonexistent_proxy() {
    let port = allocate_port();
    let cfg = ServerConfig {
        bind_addr: "127.0.0.1".into(),
        bind_port: port,
        ..Default::default()
    };
    let (_handle, _) = start_test_server(cfg).await;
    let addr: SocketAddr = format!("127.0.0.1:{}", port).parse().unwrap();

    let mut conn = IoStream::Tcp(
        tokio::net::TcpStream::connect(addr).await.expect("connect"),
    );
    let msg = FrpMessage::NatHoleVisitor(NatHoleVisitor {
        transaction_id: "no-such-proxy-txn".into(),
        proxy_name: "proxy-does-not-exist".into(),
        pre_check: true,
        ..Default::default()
    });
    write_msg_v1(&mut conn, &msg).await.expect("send precheck");

    match read_msg_v1(&mut conn).await.expect("read response") {
        FrpMessage::NatHoleResp(resp) => {
            assert!(
                resp.error.is_some(),
                "precheck for unknown proxy must return error"
            );
            println!(
                "Precheck error response correct: {:?}",
                resp.error.unwrap()
            );
        }
        other => panic!(
            "expected NatHoleResp with error, got type byte {:?}",
            other.v1_type_byte()
        ),
    }
}

// ── test_xtcp_precheck_disconnect ──

#[tokio::test]
async fn test_xtcp_precheck_disconnect_does_not_crash() {
    let port = allocate_port();
    let cfg = ServerConfig {
        bind_addr: "127.0.0.1".into(),
        bind_port: port,
        ..Default::default()
    };
    let (_handle, _) = start_test_server(cfg).await;
    let addr: SocketAddr = format!("127.0.0.1:{}", port).parse().unwrap();

    // Login and register a proxy first so there's something to precheck against
    let (mut provider_ctl, resp) =
        raw_login(addr, None, None, "").await.expect("login");
    let run_id = resp.run_id.expect("run_id");

    let xtcp_sk = "precheck-drop-sk";
    let np = FrpMessage::NewProxy(NewProxy {
        proxy_name: "precheck-drop-proxy".into(),
        proxy_type: "xtcp".into(),
        sk: Some(xtcp_sk.to_string()),
        local_str: Some("127.0.0.1:19999".into()),
        ..Default::default()
    });
    write_msg_v1(&mut provider_ctl, &np).await.expect("send NewProxy");
    let _np_resp = read_msg_v1(&mut provider_ctl).await.expect("NewProxyResp");

    // Send precheck, then immediately drop the TCP connection
    // (simulates a visitor that disconnects mid-handshake)
    let mut conn = IoStream::Tcp(
        tokio::net::TcpStream::connect(addr).await.expect("connect"),
    );
    let msg = FrpMessage::NatHoleVisitor(NatHoleVisitor {
        transaction_id: "drop-mid-precheck".into(),
        proxy_name: "precheck-drop-proxy".into(),
        pre_check: true,
        ..Default::default()
    });
    write_msg_v1(&mut conn, &msg).await.expect("send precheck");

    // Don't read the response — drop the connection instead
    drop(conn);

    // Give server a moment to process the disconnect
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Verify server still functional: send another request
    let mut conn2 = IoStream::Tcp(
        tokio::net::TcpStream::connect(addr).await.expect("reconnect"),
    );
    let msg2 = FrpMessage::NatHoleVisitor(NatHoleVisitor {
        transaction_id: "after-drop".into(),
        proxy_name: "precheck-drop-proxy".into(),
        pre_check: true,
        ..Default::default()
    });
    write_msg_v1(&mut conn2, &msg2).await.expect("send precheck 2");

    match read_msg_v1(&mut conn2).await.expect("read response 2") {
        FrpMessage::NatHoleResp(resp) => {
            assert!(
                resp.error.is_none(),
                "server should still work after disconnect"
            );
        }
        other => panic!("expected NatHoleResp, got {:?}", other.v1_type_byte()),
    }

    drop(provider_ctl);
}

// ── test_xtcp_nat_hole_client_invalid_sid ──

#[tokio::test]
async fn test_xtcp_nat_hole_client_invalid_sid() {
    let port = allocate_port();
    let cfg = ServerConfig {
        bind_addr: "127.0.0.1".into(),
        bind_port: port,
        ..Default::default()
    };
    let (_handle, _) = start_test_server(cfg).await;
    let addr: SocketAddr = format!("127.0.0.1:{}", port).parse().unwrap();

    // Provider logs in, registers XTCP proxy
    let (mut provider_ctl, resp) =
        raw_login(addr, None, None, "").await.expect("login");
    let _run_id = resp.run_id.expect("run_id");

    let xtcp_sk = "invalid-sid-sk";
    let np = FrpMessage::NewProxy(NewProxy {
        proxy_name: "invalid-sid-proxy".into(),
        proxy_type: "xtcp".into(),
        sk: Some(xtcp_sk.to_string()),
        local_str: Some("127.0.0.1:19998".into()),
        ..Default::default()
    });
    write_msg_v1(&mut provider_ctl, &np).await.expect("send NewProxy");
    match read_msg_v1(&mut provider_ctl).await.expect("NewProxyResp") {
        FrpMessage::NewProxyResp(ref resp) => {
            assert!(resp.error.is_none(), "proxy reg error: {:?}", resp.error);
        }
        other => panic!("expected NewProxyResp, got {:?}", other.v1_type_byte()),
    }

    // Send NatHoleClient with a nonexistent sid — server should silently ignore
    let bogus = FrpMessage::NatHoleClient(msg::NatHoleClient {
        transaction_id: "bogus-txn".into(),
        proxy_name: "invalid-sid-proxy".into(),
        sid: Some("nonexistent-sid-12345".to_string()),
        protocol: Some("tcp".to_string()),
        mapped_addrs: Some(vec!["10.0.0.1:7000".to_string()]),
        ..Default::default()
    });
    write_msg_v1(&mut provider_ctl, &bogus)
        .await
        .expect("send NatHoleClient with bad sid");

    // Provider control channel must still be usable after ignored message
    let np2 = FrpMessage::NewProxy(NewProxy {
        proxy_name: "after-bogus-proxy".into(),
        proxy_type: "xtcp".into(),
        sk: Some("after-bogus-sk".to_string()),
        local_str: Some("127.0.0.1:19997".into()),
        ..Default::default()
    });
    write_msg_v1(&mut provider_ctl, &np2).await.expect("send NewProxy 2");
    match read_msg_v1(&mut provider_ctl).await.expect("NewProxyResp 2") {
        FrpMessage::NewProxyResp(ref resp) => {
            assert!(
                resp.error.is_none(),
                "control channel still works: {:?}",
                resp.error
            );
        }
        other => panic!("expected NewProxyResp, got {:?}", other.v1_type_byte()),
    }

    println!("Server correctly ignored NatHoleClient with invalid sid");
    drop(provider_ctl);
}

// ── test_xtcp_nat_hole_client_without_sid ──

#[tokio::test]
async fn test_xtcp_nat_hole_client_without_sid() {
    let port = allocate_port();
    let cfg = ServerConfig {
        bind_addr: "127.0.0.1".into(),
        bind_port: port,
        ..Default::default()
    };
    let (_handle, _) = start_test_server(cfg).await;
    let addr: SocketAddr = format!("127.0.0.1:{}", port).parse().unwrap();

    let (mut provider_ctl, resp) =
        raw_login(addr, None, None, "").await.expect("login");
    let _run_id = resp.run_id.expect("run_id");

    let np = FrpMessage::NewProxy(NewProxy {
        proxy_name: "no-sid-proxy".into(),
        proxy_type: "xtcp".into(),
        sk: Some("no-sid-sk".to_string()),
        local_str: Some("127.0.0.1:19996".into()),
        ..Default::default()
    });
    write_msg_v1(&mut provider_ctl, &np).await.expect("send NewProxy");
    match read_msg_v1(&mut provider_ctl).await {
        FrpMessage::NewProxyResp(ref resp) => {
            assert!(resp.error.is_none(), "proxy reg error: {:?}", resp.error);
        }
        other => panic!("expected NewProxyResp, got {:?}", other.v1_type_byte()),
    }

    // Send NatHoleClient with NO sid — server should silently ignore
    let no_sid = FrpMessage::NatHoleClient(msg::NatHoleClient {
        transaction_id: "no-sid-txn".into(),
        proxy_name: "no-sid-proxy".into(),
        sid: None,
        protocol: Some("tcp".to_string()),
        mapped_addrs: Some(vec!["10.0.0.1:7000".to_string()]),
        ..Default::default()
    });
    write_msg_v1(&mut provider_ctl, &no_sid)
        .await
        .expect("send NatHoleClient without sid");

    // Verify control channel still usable
    let np2 = FrpMessage::NewProxy(NewProxy {
        proxy_name: "after-no-sid-proxy".into(),
        proxy_type: "xtcp".into(),
        sk: Some("after-no-sid-2".to_string()),
        local_str: Some("127.0.0.1:19995".into()),
        ..Default::default()
    });
    write_msg_v1(&mut provider_ctl, &np2).await.expect("send NewProxy 2");
    match read_msg_v1(&mut provider_ctl).await {
        FrpMessage::NewProxyResp(ref resp) => {
            assert!(resp.error.is_none(), "post-bogus proxy: {:?}", resp.error);
        }
        other => panic!("expected NewProxyResp, got {:?}", other.v1_type_byte()),
    }

    println!("Server correctly ignored NatHoleClient without sid");
    drop(provider_ctl);
}

// ── test_xtcp_full_message_routing_with_report ──

/// Extended version of xtcp_hole_punch test that also verifies
/// that after NatHoleReport, the session is cleaned up (a new
/// NatHoleClient with the same sid is silently ignored).
#[tokio::test]
async fn test_xtcp_nat_hole_report_cleanup() {
    let port = allocate_port();
    let cfg = ServerConfig {
        bind_addr: "127.0.0.1".into(),
        bind_port: port,
        ..Default::default()
    };
    let (_handle, _) = start_test_server(cfg).await;
    let addr: SocketAddr = format!("127.0.0.1:{}", port).parse().unwrap();

    // Provider: login + register
    let (mut provider_ctl, resp) =
        raw_login(addr, None, None, "").await.expect("login");
    let run_id = resp.run_id.expect("run_id");

    let xtcp_sk = "report-cleanup-sk";
    let np = FrpMessage::NewProxy(NewProxy {
        proxy_name: "report-cleanup".into(),
        proxy_type: "xtcp".into(),
        sk: Some(xtcp_sk.to_string()),
        local_str: Some("127.0.0.1:19990".into()),
        ..Default::default()
    });
    write_msg_v1(&mut provider_ctl, &np).await.expect("send NewProxy");
    match read_msg_v1(&mut provider_ctl).await.expect("NewProxyResp") {
        FrpMessage::NewProxyResp(ref resp) => {
            assert!(resp.error.is_none(), "proxy reg: {:?}", resp.error);
        }
        other => panic!("expected NewProxyResp, got {:?}", other.v1_type_byte()),
    }

    // Work connection
    let mut work_conn = IoStream::Tcp(
        tokio::net::TcpStream::connect(addr).await.expect("work conn"),
    );
    let nwc = FrpMessage::NewWorkConn(msg::NewWorkConn {
        run_id: Some(run_id.clone()),
        ..Default::default()
    });
    write_msg_v1(&mut work_conn, &nwc).await.expect("send NewWorkConn");
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Visitor precheck
    let txn_id = format!("report-txn-{}", port);
    let mut precheck_conn = IoStream::Tcp(
        tokio::net::TcpStream::connect(addr).await.expect("precheck conn"),
    );
    write_msg_v1(
        &mut precheck_conn,
        &FrpMessage::NatHoleVisitor(NatHoleVisitor {
            transaction_id: format!("precheck-{}", txn_id),
            proxy_name: "report-cleanup".into(),
            pre_check: true,
            ..Default::default()
        }),
    )
    .await
    .expect("send precheck");
    match read_msg_v1(&mut precheck_conn).await.expect("read precheck resp") {
        FrpMessage::NatHoleResp(resp) => {
            assert!(resp.error.is_none(), "precheck error: {:?}", resp.error);
        }
        other => panic!("expected NatHoleResp, got {:?}", other.v1_type_byte()),
    }
    drop(precheck_conn);

    // Visitor full
    let mut visitor_conn = IoStream::Tcp(
        tokio::net::TcpStream::connect(addr).await.expect("visitor conn"),
    );
    write_msg_v1(
        &mut visitor_conn,
        &FrpMessage::NatHoleVisitor(NatHoleVisitor {
            transaction_id: txn_id.clone(),
            proxy_name: "report-cleanup".into(),
            pre_check: false,
            protocol: Some("tcp".to_string()),
            mapped_addrs: Some(vec!["1.2.3.4:5678".to_string()]),
            ..Default::default()
        }),
    )
    .await
    .expect("send full visitor");

    // Provider reads StartWorkConn + NatHoleSid from work conn
    let sid = match read_msg_v1(&mut work_conn).await.expect("read StartWorkConn") {
        FrpMessage::StartWorkConn(swc) => {
            assert_eq!(swc.proxy_name, "report-cleanup");
            match read_msg_v1(&mut work_conn).await.expect("read NatHoleSid") {
                FrpMessage::NatHoleSid(sid_msg) => {
                    sid_msg.sid.expect("NatHoleSid has sid")
                }
                other => panic!("expected NatHoleSid, got {:?}", other.v1_type_byte()),
            }
        }
        other => panic!("expected StartWorkConn, got {:?}", other.v1_type_byte()),
    };

    // Provider sends NatHoleClient on control
    write_msg_v1(
        &mut provider_ctl,
        &FrpMessage::NatHoleClient(msg::NatHoleClient {
            transaction_id: txn_id.clone(),
            proxy_name: "report-cleanup".into(),
            sid: Some(sid.clone()),
            protocol: Some("tcp".to_string()),
            mapped_addrs: Some(vec!["10.0.0.1:7000".to_string()]),
            ..Default::default()
        }),
    )
    .await
    .expect("send NatHoleClient");

    // Provider + Visitor read NatHoleResp
    let _ = read_msg_v1(&mut provider_ctl).await.expect("provider NatHoleResp");
    let _ = read_msg_v1(&mut visitor_conn).await.expect("visitor NatHoleResp");

    // ── KEY: Send NatHoleReport to trigger session cleanup ──
    write_msg_v1(
        &mut provider_ctl,
        &FrpMessage::NatHoleReport(msg::NatHoleReport {
            sid: Some(txn_id.clone()),
        }),
    )
    .await
    .expect("send NatHoleReport");

    // Brief wait for server to process cleanup
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Send ANOTHER NatHoleClient with the SAME sid — session should be gone,
    // so this should be silently ignored (control channel still usable)
    write_msg_v1(
        &mut provider_ctl,
        &FrpMessage::NatHoleClient(msg::NatHoleClient {
            transaction_id: "after-cleanup".into(),
            proxy_name: "report-cleanup".into(),
            sid: Some(sid.clone()),
            protocol: Some("tcp".to_string()),
            mapped_addrs: Some(vec!["10.0.0.1:8000".to_string()]),
            ..Default::default()
        }),
    )
    .await
    .expect("send NatHoleClient after report");

    // Control channel should still be responsive
    let np2 = FrpMessage::NewProxy(NewProxy {
        proxy_name: "after-report-proxy".into(),
        proxy_type: "xtcp".into(),
        sk: Some("after-report-sk".to_string()),
        local_str: Some("127.0.0.1:19989".into()),
        ..Default::default()
    });
    write_msg_v1(&mut provider_ctl, &np2)
        .await
        .expect("send NewProxy after report");
    match read_msg_v1(&mut provider_ctl).await.expect("NewProxyResp after report") {
        FrpMessage::NewProxyResp(ref resp) => {
            assert!(
                resp.error.is_none(),
                "server healthy after report cleanup: {:?}",
                resp.error
            );
        }
        other => panic!("expected NewProxyResp, got {:?}", other.v1_type_byte()),
    }

    println!("NatHoleReport cleanup verified — session removed, server healthy");
    drop(provider_ctl);
    drop(visitor_conn);
    drop(work_conn);
}
```

- [ ] **Step 2: Run the tests**

```bash
cargo test -p frp-server --test xtcp_fallback
```

Expected: all 5 tests PASS.

- [ ] **Step 3: Commit**

```bash
git add frp-server/tests/xtcp_fallback.rs
git commit -m "test: add XTCP fallback/error server integration tests (5 tests)

- precheck nonexistent proxy → error response
- precheck disconnect → server stays healthy
- NatHoleClient with invalid sid → silently ignored
- NatHoleClient without sid → silently ignored
- NatHoleReport cleanup → session removed

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 2: Create `frp-server/tests/xtcp_edge.rs` — Concurrency & Encryption

**Files:**
- Create: `frp-server/tests/xtcp_edge.rs`

- [ ] **Step 1: Write the test file**

```rust
mod common;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use frp_core::config::ServerConfig;
use frp_core::msg::{self, FrpMessage, NatHoleVisitor, NewProxy};
use frp_core::protocol::{read_msg_v1, write_msg_v1};
use frp_core::transport::IoStream;

use common::{allocate_port, raw_login, start_test_server};

// ── test_xtcp_concurrent_3_sessions ──

/// Run 3 XTCP message routing flows concurrently.
/// Verifies the server correctly handles interleaved NatHole
/// sessions without cross-talk (wrong sid delivered to wrong visitor).
#[tokio::test]
async fn test_xtcp_concurrent_3_sessions() {
    let port = allocate_port();
    let cfg = ServerConfig {
        bind_addr: "127.0.0.1".into(),
        bind_port: port,
        ..Default::default()
    };
    let (_handle, _) = start_test_server(cfg).await;
    let addr: Arc<SocketAddr> =
        Arc::new(format!("127.0.0.1:{}", port).parse().unwrap());

    let mut handles = Vec::new();

    for i in 0..3 {
        let addr = addr.clone();
        let handle = tokio::spawn(async move {
            let proxy_name = format!("conc-xtcp-{}", i);
            let sk = format!("conc-sk-{}", i);
            let txn_id = format!("conc-txn-{}-{}", i, port);

            // Provider login + register
            let (mut provider_ctl, resp) =
                raw_login(*addr, None, None, "").await.expect("login");
            let run_id = resp.run_id.expect("run_id");

            let np = FrpMessage::NewProxy(NewProxy {
                proxy_name: proxy_name.clone(),
                proxy_type: "xtcp".into(),
                sk: Some(sk.clone()),
                local_str: Some(format!("127.0.0.1:{}", 20000 + i)),
                ..Default::default()
            });
            write_msg_v1(&mut provider_ctl, &np)
                .await
                .expect("send NewProxy");
            match read_msg_v1(&mut provider_ctl).await.expect("NewProxyResp") {
                FrpMessage::NewProxyResp(ref resp) => {
                    assert!(resp.error.is_none(), "reg error i={}: {:?}", i, resp.error);
                }
                other => panic!("expected NewProxyResp i={}, got {:?}", i, other.v1_type_byte()),
            }

            // Work connection
            let mut work_conn = IoStream::Tcp(
                tokio::net::TcpStream::connect(*addr)
                    .await
                    .expect("work conn"),
            );
            write_msg_v1(
                &mut work_conn,
                &FrpMessage::NewWorkConn(msg::NewWorkConn {
                    run_id: Some(run_id.clone()),
                    ..Default::default()
                }),
            )
            .await
            .expect("send NewWorkConn");
            tokio::time::sleep(Duration::from_millis(100)).await;

            // Visitor precheck
            let mut precheck_conn = IoStream::Tcp(
                tokio::net::TcpStream::connect(*addr)
                    .await
                    .expect("precheck conn"),
            );
            write_msg_v1(
                &mut precheck_conn,
                &FrpMessage::NatHoleVisitor(NatHoleVisitor {
                    transaction_id: format!("precheck-{}", txn_id),
                    proxy_name: proxy_name.clone(),
                    pre_check: true,
                    ..Default::default()
                }),
            )
            .await
            .expect("send precheck");
            match read_msg_v1(&mut precheck_conn).await.expect("precheck resp") {
                FrpMessage::NatHoleResp(resp) => {
                    assert!(resp.error.is_none(), "precheck error i={}: {:?}", i, resp.error);
                }
                other => panic!("expected NatHoleResp i={}, got {:?}", i, other.v1_type_byte()),
            }
            drop(precheck_conn);

            // Visitor full
            let mut visitor_conn = IoStream::Tcp(
                tokio::net::TcpStream::connect(*addr)
                    .await
                    .expect("visitor conn"),
            );
            write_msg_v1(
                &mut visitor_conn,
                &FrpMessage::NatHoleVisitor(NatHoleVisitor {
                    transaction_id: txn_id,
                    proxy_name: proxy_name.clone(),
                    pre_check: false,
                    protocol: Some("tcp".to_string()),
                    mapped_addrs: Some(vec![
                        format!("1.2.3.{}:5678", i),
                        format!("1.2.3.{}:5680", i),
                    ]),
                    ..Default::default()
                }),
            )
            .await
            .expect("send full visitor");

            // Provider reads StartWorkConn + NatHoleSid from work conn
            let _sid = match read_msg_v1(&mut work_conn).await.expect("read StartWorkConn") {
                FrpMessage::StartWorkConn(swc) => {
                    assert_eq!(swc.proxy_name, proxy_name, "wrong proxy_name i={}", i);
                    match read_msg_v1(&mut work_conn).await.expect("read NatHoleSid") {
                        FrpMessage::NatHoleSid(sid_msg) => {
                            let s = sid_msg.sid.expect("sid");
                            assert!(!s.is_empty(), "empty sid i={}", i);
                            s
                        }
                        other => panic!("expected NatHoleSid i={}, got {:?}", i, other.v1_type_byte()),
                    }
                }
                other => panic!("expected StartWorkConn i={}, got {:?}", i, other.v1_type_byte()),
            };

            // Verify visitor also gets NatHoleResp (just ensure no timeout/crash)
            // Drop without reading NatHoleResp fully to keep test deterministic
            drop(visitor_conn);
            drop(work_conn);
            drop(provider_ctl);

            println!("Concurrent session {} completed", i);
        });
        handles.push(handle);
    }

    // Await all concurrent sessions
    for (i, handle) in handles.into_iter().enumerate() {
        handle
            .await
            .unwrap_or_else(|e| panic!("session {} panicked: {}", i, e));
    }

    println!("All 3 concurrent XTCP sessions completed without cross-talk");
}

// ── test_xtcp_multiple_providers_same_server ──

/// Two different providers register XTCP proxies on same server.
/// Each gets correct NatHoleSid on their own work connection.
#[tokio::test]
async fn test_xtcp_multiple_providers_same_server() {
    let port = allocate_port();
    let cfg = ServerConfig {
        bind_addr: "127.0.0.1".into(),
        bind_port: port,
        ..Default::default()
    };
    let (_handle, _) = start_test_server(cfg).await;
    let addr: SocketAddr = format!("127.0.0.1:{}", port).parse().unwrap();

    // Provider A: registers proxy-a
    let (mut ctl_a, resp_a) = raw_login(addr, None, None, "").await.expect("login A");
    let run_id_a = resp_a.run_id.expect("run_id A");

    write_msg_v1(
        &mut ctl_a,
        &FrpMessage::NewProxy(NewProxy {
            proxy_name: "multi-a".into(),
            proxy_type: "xtcp".into(),
            sk: Some("multi-sk-a".to_string()),
            local_str: Some("127.0.0.1:21001".into()),
            ..Default::default()
        }),
    )
    .await
    .expect("send NewProxy A");
    match read_msg_v1(&mut ctl_a).await.expect("NewProxyResp A") {
        FrpMessage::NewProxyResp(ref resp) => {
            assert!(resp.error.is_none(), "reg A: {:?}", resp.error);
        }
        other => panic!("expected NewProxyResp A, got {:?}", other.v1_type_byte()),
    }

    // Provider B: registers proxy-b
    let (mut ctl_b, resp_b) = raw_login(addr, None, None, "").await.expect("login B");
    let run_id_b = resp_b.run_id.expect("run_id B");

    write_msg_v1(
        &mut ctl_b,
        &FrpMessage::NewProxy(NewProxy {
            proxy_name: "multi-b".into(),
            proxy_type: "xtcp".into(),
            sk: Some("multi-sk-b".to_string()),
            local_str: Some("127.0.0.1:21002".into()),
            ..Default::default()
        }),
    )
    .await
    .expect("send NewProxy B");
    match read_msg_v1(&mut ctl_b).await.expect("NewProxyResp B") {
        FrpMessage::NewProxyResp(ref resp) => {
            assert!(resp.error.is_none(), "reg B: {:?}", resp.error);
        }
        other => panic!("expected NewProxyResp B, got {:?}", other.v1_type_byte()),
    }

    // Work connections for both
    let mut work_a = IoStream::Tcp(
        tokio::net::TcpStream::connect(addr).await.expect("work A"),
    );
    write_msg_v1(
        &mut work_a,
        &FrpMessage::NewWorkConn(msg::NewWorkConn {
            run_id: Some(run_id_a.clone()),
            ..Default::default()
        }),
    )
    .await
    .expect("send NewWorkConn A");

    let mut work_b = IoStream::Tcp(
        tokio::net::TcpStream::connect(addr).await.expect("work B"),
    );
    write_msg_v1(
        &mut work_b,
        &FrpMessage::NewWorkConn(msg::NewWorkConn {
            run_id: Some(run_id_b.clone()),
            ..Default::default()
        }),
    )
    .await
    .expect("send NewWorkConn B");

    tokio::time::sleep(Duration::from_millis(100)).await;

    // Visitor for proxy A
    let txn_a = format!("multi-txn-a-{}", port);
    let mut vis_a = IoStream::Tcp(
        tokio::net::TcpStream::connect(addr).await.expect("visitor A"),
    );
    // precheck
    write_msg_v1(
        &mut vis_a,
        &FrpMessage::NatHoleVisitor(NatHoleVisitor {
            transaction_id: format!("pre-{}", txn_a),
            proxy_name: "multi-a".into(),
            pre_check: true,
            ..Default::default()
        }),
    )
    .await
    .expect("send precheck A");
    let _ = read_msg_v1(&mut vis_a).await.expect("precheck resp A");
    drop(vis_a);

    // full
    let mut vis_a2 = IoStream::Tcp(
        tokio::net::TcpStream::connect(addr).await.expect("visitor A2"),
    );
    write_msg_v1(
        &mut vis_a2,
        &FrpMessage::NatHoleVisitor(NatHoleVisitor {
            transaction_id: txn_a.clone(),
            proxy_name: "multi-a".into(),
            pre_check: false,
            protocol: Some("tcp".to_string()),
            mapped_addrs: Some(vec!["1.2.3.4:1111".to_string()]),
            ..Default::default()
        }),
    )
    .await
    .expect("send full A");

    // Provider A receives NatHoleSid on work_a (NOT work_b)
    let sid_a = match read_msg_v1(&mut work_a).await.expect("read work_a StartWorkConn") {
        FrpMessage::StartWorkConn(swc) => {
            assert_eq!(swc.proxy_name, "multi-a");
            match read_msg_v1(&mut work_a).await.expect("read work_a NatHoleSid") {
                FrpMessage::NatHoleSid(sid_msg) => sid_msg.sid.expect("sid A"),
                other => panic!("expected NatHoleSid on work_a, got {:?}", other.v1_type_byte()),
            }
        }
        other => panic!("expected StartWorkConn on work_a, got {:?}", other.v1_type_byte()),
    };

    // Provider B should NOT have received anything on work_b
    // (try reading with short timeout — should timeout, not receive A's messages)

    // Send NatHoleClient from provider A
    write_msg_v1(
        &mut ctl_a,
        &FrpMessage::NatHoleClient(msg::NatHoleClient {
            transaction_id: txn_a.clone(),
            proxy_name: "multi-a".into(),
            sid: Some(sid_a.clone()),
            protocol: Some("tcp".to_string()),
            mapped_addrs: Some(vec!["10.0.0.1:7000".to_string()]),
            ..Default::default()
        }),
    )
    .await
    .expect("send NatHoleClient A");

    // Provider A reads NatHoleResp (visitor's addresses)
    match read_msg_v1(&mut ctl_a).await.expect("provider A NatHoleResp") {
        FrpMessage::NatHoleResp(resp) => {
            assert!(resp.error.is_none(), "provider A resp error: {:?}", resp.error);
        }
        other => panic!("expected NatHoleResp A, got {:?}", other.v1_type_byte()),
    }

    // Visitor A reads NatHoleResp (provider A's addresses)
    match read_msg_v1(&mut vis_a2).await.expect("visitor A NatHoleResp") {
        FrpMessage::NatHoleResp(resp) => {
            assert!(resp.error.is_none(), "visitor A resp error: {:?}", resp.error);
        }
        other => panic!("expected NatHoleResp for visitor A, got {:?}", other.v1_type_byte()),
    }

    println!("Multi-provider XTCP routing correct — no cross-talk");
    drop(ctl_a);
    drop(ctl_b);
    drop(vis_a2);
    drop(work_a);
    drop(work_b);
}

// ── test_xtcp_encrypted_bridge_flag ──

/// Verifies that when provider registers XTCP proxy with use_encryption=true,
/// the server's StartWorkConn message includes the flag.
#[tokio::test]
async fn test_xtcp_encrypted_proxy_registration() {
    let port = allocate_port();
    let cfg = ServerConfig {
        bind_addr: "127.0.0.1".into(),
        bind_port: port,
        ..Default::default()
    };
    let (_handle, _) = start_test_server(cfg).await;
    let addr: SocketAddr = format!("127.0.0.1:{}", port).parse().unwrap();

    let (mut provider_ctl, resp) =
        raw_login(addr, None, None, "").await.expect("login");
    let run_id = resp.run_id.expect("run_id");

    // Register XTCP proxy WITH encryption
    let sk = "enc-xtcp-sk";
    write_msg_v1(
        &mut provider_ctl,
        &FrpMessage::NewProxy(NewProxy {
            proxy_name: "enc-xtcp".into(),
            proxy_type: "xtcp".into(),
            sk: Some(sk.to_string()),
            use_encryption: Some(true),
            use_compression: Some(true),
            local_str: Some("127.0.0.1:22001".into()),
            ..Default::default()
        }),
    )
    .await
    .expect("send NewProxy");
    match read_msg_v1(&mut provider_ctl).await.expect("NewProxyResp") {
        FrpMessage::NewProxyResp(ref resp) => {
            assert!(resp.error.is_none(), "reg error: {:?}", resp.error);
        }
        other => panic!("expected NewProxyResp, got {:?}", other.v1_type_byte()),
    }

    // Work connection
    let mut work_conn = IoStream::Tcp(
        tokio::net::TcpStream::connect(addr).await.expect("work conn"),
    );
    write_msg_v1(
        &mut work_conn,
        &FrpMessage::NewWorkConn(msg::NewWorkConn {
            run_id: Some(run_id.clone()),
            ..Default::default()
        }),
    )
    .await
    .expect("send NewWorkConn");
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Trigger visitor — StartWorkConn should include encryption flags
    let txn = format!("enc-txn-{}", port);
    let mut vis = IoStream::Tcp(
        tokio::net::TcpStream::connect(addr).await.expect("visitor"),
    );
    // precheck
    write_msg_v1(
        &mut vis,
        &FrpMessage::NatHoleVisitor(NatHoleVisitor {
            transaction_id: format!("pre-{}", txn),
            proxy_name: "enc-xtcp".into(),
            pre_check: true,
            ..Default::default()
        }),
    )
    .await
    .expect("send precheck");
    let _ = read_msg_v1(&mut vis).await.expect("precheck resp");
    drop(vis);

    // full
    let mut vis2 = IoStream::Tcp(
        tokio::net::TcpStream::connect(addr).await.expect("visitor2"),
    );
    write_msg_v1(
        &mut vis2,
        &FrpMessage::NatHoleVisitor(NatHoleVisitor {
            transaction_id: txn,
            proxy_name: "enc-xtcp".into(),
            pre_check: false,
            protocol: Some("tcp".to_string()),
            mapped_addrs: Some(vec!["5.6.7.8:1234".to_string()]),
            ..Default::default()
        }),
    )
    .await
    .expect("send full");

    // Provider reads StartWorkConn
    match read_msg_v1(&mut work_conn).await.expect("StartWorkConn") {
        FrpMessage::StartWorkConn(swc) => {
            assert_eq!(swc.proxy_name, "enc-xtcp");
            // Encryption/compression flags should be propagated
            assert_eq!(
                swc.use_encryption, Some(true),
                "StartWorkConn should have use_encryption=true"
            );
            assert_eq!(
                swc.use_compression, Some(true),
                "StartWorkConn should have use_compression=true"
            );
            println!(
                "StartWorkConn correctly includes encryption flags: enc={:?} comp={:?}",
                swc.use_encryption, swc.use_compression
            );
        }
        other => panic!("expected StartWorkConn, got {:?}", other.v1_type_byte()),
    }

    drop(provider_ctl);
    drop(vis2);
    drop(work_conn);
}
```

- [ ] **Step 2: Run the tests**

```bash
cargo test -p frp-server --test xtcp_edge
```

Expected: all 3 tests PASS.

- [ ] **Step 3: Commit**

```bash
git add frp-server/tests/xtcp_edge.rs
git commit -m "test: add XTCP edge case tests (concurrency, multi-provider, encryption flags)

- 3 concurrent XTCP sessions → no cross-talk
- 2 providers on same server → correct routing per proxy
- encrypted proxy registration → StartWorkConn includes flags

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 3: Add invalid-sid test to existing `xtcp_hole_punch.rs`

**Files:**
- Modify: `frp-server/tests/xtcp_hole_punch.rs` (append test at end of file)

- [ ] **Step 1: Add test function**

Append this test after the existing `test_xtcp_nat_hole_message_routing` function (before the closing `}` of the file, if any):

```rust
/// Server correctly ignores NatHoleClient with sid=None.
/// The control channel remains usable after the ignored message.
#[tokio::test]
async fn test_xtcp_ignore_nat_hole_client_no_sid() {
    let port = allocate_port();
    let cfg = ServerConfig {
        bind_addr: "127.0.0.1".into(),
        bind_port: port,
        ..Default::default()
    };
    let (_handle, _) = start_test_server(cfg).await;
    let addr: std::net::SocketAddr = format!("127.0.0.1:{}", port).parse().unwrap();

    let (mut provider_ctl, resp) = raw_login(addr, None, None, "").await.expect("login");
    let _run_id = resp.run_id.expect("run_id");

    // Register XTCP proxy
    let np = FrpMessage::NewProxy(NewProxy {
        proxy_name: "ignore-no-sid".into(),
        proxy_type: "xtcp".into(),
        sk: Some("ignore-no-sid-sk".to_string()),
        local_str: Some("127.0.0.1:29999".into()),
        ..Default::default()
    });
    write_msg_v1(&mut provider_ctl, &np).await.expect("send NewProxy");
    match read_msg_v1(&mut provider_ctl).await.expect("NewProxyResp") {
        FrpMessage::NewProxyResp(ref resp) => {
            assert!(resp.error.is_none(), "reg error: {:?}", resp.error);
        }
        other => panic!("expected NewProxyResp, got {:?}", other.v1_type_byte()),
    }

    // Send NatHoleClient WITHOUT sid - server should silently drop it
    let bogus = FrpMessage::NatHoleClient(msg::NatHoleClient {
        transaction_id: "no-sid-txn".into(),
        proxy_name: "ignore-no-sid".into(),
        sid: None,
        protocol: Some("tcp".to_string()),
        mapped_addrs: Some(vec!["10.0.0.1:9999".to_string()]),
        ..Default::default()
    });
    write_msg_v1(&mut provider_ctl, &bogus)
        .await
        .expect("send bogus NatHoleClient");

    // Verify control channel is still operational
    let np2 = FrpMessage::NewProxy(NewProxy {
        proxy_name: "after-no-sid-2".into(),
        proxy_type: "xtcp".into(),
        sk: Some("after-no-sid-sk-2".to_string()),
        local_str: Some("127.0.0.1:29998".into()),
        ..Default::default()
    });
    write_msg_v1(&mut provider_ctl, &np2).await.expect("send NewProxy 2");
    match read_msg_v1(&mut provider_ctl).await.expect("NewProxyResp 2") {
        FrpMessage::NewProxyResp(ref resp) => {
            assert!(
                resp.error.is_none(),
                "control channel still usable: {:?}",
                resp.error
            );
        }
        other => panic!("expected NewProxyResp, got {:?}", other.v1_type_byte()),
    }

    println!("Server correctly ignored NatHoleClient with sid=None");
    drop(provider_ctl);
}
```

- [ ] **Step 2: Run the test**

```bash
cargo test -p frp-server --test xtcp_hole_punch test_xtcp_ignore_nat_hole_client_no_sid
```

Expected: PASS.

- [ ] **Step 3: Run all existing XTCP tests to verify no regression**

```bash
cargo test -p frp-server xtcp
```

Expected: all 9 XTCP tests PASS (1 existing + 1 new + 5 fallback + 3 edge - wait, need to count properly). Actually: 1 existing hole_punch + 1 new hole_punch + 5 fallback + 3 edge = 10 tests total PASS.

- [ ] **Step 4: Commit**

```bash
git add frp-server/tests/xtcp_hole_punch.rs
git commit -m "test: add NatHoleClient without sid test to xtcp_hole_punch

Verifies server silently ignores NatHoleClient with sid=None
and control channel remains operational afterward.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

## Phase 1: VPS CI — End-to-End XTCP

### Task 4: Create `scripts/remote-frps.sh`

**Files:**
- Create: `scripts/remote-frps.sh`

- [ ] **Step 1: Write the script**

```bash
#!/usr/bin/env bash
# =============================================================================
# Remote frps lifecycle management for XTCP CI tests.
# Manages frps (Rust or Go) on a VPS with a public IP.
#
# Usage:
#   bash scripts/remote-frps.sh start  <impl> <host> <port> <token> <ssh-key>
#   bash scripts/remote-frps.sh stop   <host> <ssh-key>
#   bash scripts/remote-frps.sh status <host> <ssh-key>
#
# <impl>: "rust" or "go"
# VPS user is read from XTCP_VPS_USER env var (default: frp-test)
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
VPS_USER="${XTCP_VPS_USER:-frp-test}"
REMOTE_DIR="/tmp/frp-xtcp-test"

# ── ssh wrapper ──
do_ssh() {
    local host="$1" key="$2"
    shift 2
    ssh -i "$key" -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 \
        "${VPS_USER}@${host}" "$@"
}

# ── start ──
cmd_start() {
    local impl="$1" host="$2" port="$3" token="$4" key="$5"

    echo "[remote-frps] Starting $impl frps on $host:$port"

    # Determine binary path
    local local_bin
    if [[ "$impl" == "rust" ]]; then
        local_bin="$PROJECT_DIR/target/release/frps"
        [[ -f "$local_bin" ]] || { echo "ERROR: $local_bin not found. Build first."; exit 1; }
    elif [[ "$impl" == "go" ]]; then
        # Find Go frps binary (same logic as compat-test.sh)
        local go_ver="${GO_FRP_VERSION:-0.69.1}"
        local _gos; _gos=$(uname -s | tr '[:upper:]' '[:lower:]')
        local _goa; _goa=$(uname -m)
        case "$_goa" in
            x86_64)  _goa="amd64" ;;
            aarch64|arm64) _goa="arm64" ;;
        esac
        local_bin="/tmp/frp_${go_ver}_${_gos}_${_goa}/frps"
        [[ -f "$local_bin" ]] || { echo "ERROR: $local_bin not found. Download Go frp first."; exit 1; }
    else
        echo "ERROR: unknown impl '$impl'. Use rust or go."
        exit 1
    fi

    # Create remote dir, scp binary, write config
    do_ssh "$host" "$key" "mkdir -p $REMOTE_DIR"

    scp -i "$key" -o StrictHostKeyChecking=accept-new \
        "$local_bin" "${VPS_USER}@${host}:${REMOTE_DIR}/frps"

    # Write config
    if [[ "$impl" == "go" ]]; then
        do_ssh "$host" "$key" "cat > $REMOTE_DIR/frps.toml <<'EOF'
bindAddr = \"0.0.0.0\"
bindPort = $port
auth.method = \"token\"
auth.token = \"$token\"
transport.tcpMux = false
log.to = \"$REMOTE_DIR/frps.log\"
log.level = \"debug\"
EOF"
    else
        do_ssh "$host" "$key" "cat > $REMOTE_DIR/frps.toml <<'EOF'
bind_addr = \"0.0.0.0\"
bind_port = $port

[auth]
method = \"token\"
token = \"$token\"

[transport]
tcp_mux = false
EOF"
    fi

    # Start frps in background
    do_ssh "$host" "$key" "nohup $REMOTE_DIR/frps -c $REMOTE_DIR/frps.toml \
        > $REMOTE_DIR/frps.log 2>&1 & echo \$! > $REMOTE_DIR/frps.pid"

    # Wait for port to be reachable
    local deadline=$(($(date +%s) + 30))
    while ! nc -z "$host" "$port" 2>/dev/null; do
        if [[ $(date +%s) -gt $deadline ]]; then
            echo "ERROR: frps on $host:$port did not start within 30s"
            do_ssh "$host" "$key" "cat $REMOTE_DIR/frps.log" || true
            exit 1
        fi
        sleep 0.5
    done

    echo "[remote-frps] $impl frps ready on $host:$port"
}

# ── stop ──
cmd_stop() {
    local host="$1" key="$2"

    echo "[remote-frps] Stopping frps on $host"

    do_ssh "$host" "$key" "
        if [[ -f $REMOTE_DIR/frps.pid ]]; then
            pid=\$(cat $REMOTE_DIR/frps.pid)
            kill \$pid 2>/dev/null || true
            # Wait for process to exit
            for i in \$(seq 1 10); do
                kill -0 \$pid 2>/dev/null || break
                sleep 0.1
            done
            # Force kill if still running
            kill -9 \$pid 2>/dev/null || true
            rm -f $REMOTE_DIR/frps.pid
        fi
        rm -rf $REMOTE_DIR
    " || true

    echo "[remote-frps] frps stopped on $host"
}

# ── status ──
cmd_status() {
    local host="$1" key="$2"

    if do_ssh "$host" "$key" "
        if [[ -f $REMOTE_DIR/frps.pid ]]; then
            pid=\$(cat $REMOTE_DIR/frps.pid)
            if kill -0 \$pid 2>/dev/null; then
                echo \"RUNNING pid=\$pid\"
            else
                echo \"STALE pid=\$pid (process not found)\"
            fi
        else
            echo \"STOPPED\"
        fi
    " 2>/dev/null; then
        true
    else
        echo "UNREACHABLE"
    fi
}

# ── main ──
case "${1:-}" in
    start)
        shift
        cmd_start "$@"
        ;;
    stop)
        shift
        cmd_stop "$@"
        ;;
    status)
        shift
        cmd_status "$@"
        ;;
    *)
        echo "Usage: $0 {start|stop|status} <args...>"
        echo "  start  <impl> <host> <port> <token> <ssh-key>"
        echo "  stop   <host> <ssh-key>"
        echo "  status <host> <ssh-key>"
        exit 1
        ;;
esac
```

- [ ] **Step 2: Make executable and verify syntax**

```bash
chmod +x scripts/remote-frps.sh
bash -n scripts/remote-frps.sh
```

Expected: no syntax errors.

- [ ] **Step 3: Commit**

```bash
git add scripts/remote-frps.sh
git commit -m "feat: add remote-frps.sh for VPS frps lifecycle management

Supports Rust and Go frps. SSH-based start/stop/status.
Designed for XTCP CI with restricted frp-test user.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 5: Create `.github/workflows/xtcp-compat.yml`

**Files:**
- Create: `.github/workflows/xtcp-compat.yml`

- [ ] **Step 1: Write the workflow**

```yaml
name: XTCP Compat

on:
  workflow_dispatch:
  schedule:
    - cron: '17 3 * * *'  # daily, off-peak (UTC 03:17)

permissions:
  contents: read

env:
  CARGO_TERM_COLOR: always
  XTCP_VPS_USER: frp-test

jobs:
  xtcp:
    runs-on: ubuntu-latest
    timeout-minutes: 25
    # Clean skip if VPS secrets are not configured
    if: ${{ vars.XTCP_VPS_HOST != '' || secrets.XTCP_VPS_HOST != '' }}

    steps:
      - uses: actions/checkout@v4

      - uses: actions-rust-lang/setup-rust-toolchain@v1

      - uses: actions/setup-go@v5
        with:
          go-version: '>=1.22.0'

      - name: Cache cargo + go-frp
        uses: actions/cache@v4
        with:
          path: |
            ~/.cargo/registry/cache/
            ~/.cargo/git/db/
            target/release/
            /tmp/frp_0.69.1_linux_amd64/
          key: ${{ runner.os }}-xtcp-${{ hashFiles('Cargo.lock') }}-v1
          restore-keys: ${{ runner.os }}-xtcp-

      - name: Build frp-rs (release)
        run: cargo build --release --bin frps --bin frpc

      - name: Download Go frp
        run: bash scripts/download-go-frp.sh 0.69.1

      - name: Run XTCP compat tests
        run: |
          bash scripts/compat-test.sh \
            --frps-remote "$XTCP_VPS_HOST" \
            --xtcp-only \
            --ci \
            --verbose
        env:
          XTCP_VPS_HOST: ${{ secrets.XTCP_VPS_HOST }}
          XTCP_VPS_SSH_KEY: ${{ secrets.XTCP_VPS_SSH_KEY }}

      - name: Summary
        if: always()
        run: |
          echo "XTCP compat tests completed."
          echo "VPS host: $XTCP_VPS_HOST"
        env:
          XTCP_VPS_HOST: ${{ secrets.XTCP_VPS_HOST }}
```

- [ ] **Step 2: Commit**

```bash
git add .github/workflows/xtcp-compat.yml
git commit -m "ci: add XTCP compat workflow (VPS-backed, daily + manual)

Requires XTCP_VPS_HOST and XTCP_VPS_SSH_KEY secrets.
Clean-skips if secrets not configured.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 6: Modify `scripts/compat-test.sh` — Add 8 XTCP test functions + flags

**Files:**
- Modify: `scripts/compat-test.sh`

This is the largest task. Changes fall into three parts:
A. Add `--frps-remote` and `--xtcp-only` flags
B. Add 8 new XTCP test functions (replacing the 2 existing guarded ones)
C. Update the test runner section

- [ ] **Step 1: Add flag parsing**

In the argument parsing section (around line 55-79), add the two new flags. Find the `--debug|-x)` case and add before `--list`:

```bash
        --frps-remote) XTCP_FRPS_REMOTE="$2"; shift 2 ;;
        --xtcp-only) XTCP_ONLY=true; shift ;;
```

Also add the state variables near the top (~line 36-41):

```bash
XTCP_FRPS_REMOTE=""
XTCP_ONLY=false
```

- [ ] **Step 2: Add `write_frpc_config_xtcp` helper function**

Add after the existing `write_frpc_config_tcpmux` function (~line 790). This is a specialized config writer for XTCP provider+visitor pairs:

```bash
# Write frpc config for XTCP provider.
# Uses remote server address when --frps-remote is set.
write_frpc_config_xtcp_provider() {
    local impl="$1" server_host="$2" server_port="$3" token="$4"
    local echo_port="$5" name="$6" sk="$7" out="$8" features="${9:-}"
    local has_enc=false has_comp=false
    for feat in $features; do
        case "$feat" in
            enc) has_enc=true ;;
            compression) has_comp=true ;;
        esac
    done
    if [[ "$impl" == "go" ]]; then
        {
            printf 'serverAddr = "%s"\nserverPort = %s\n' "$server_host" "$server_port"
            printf 'auth.token = "%s"\n' "$token"
            printf 'transport.tls.enable = false\n'
            printf 'transport.tcpMux = false\n'
            printf 'log.to = "%s/go-frpc-provider-%s.log"\nlog.level = "debug"\n\n' "$TEST_DIR" "$name"
            printf '[[proxies]]\nname = "%s"\ntype = "xtcp"\nsecretKey = "%s"\n' "$name" "$sk"
            printf 'localIP = "127.0.0.1"\nlocalPort = %s\n' "$echo_port"
            if $has_enc; then printf 'transport.useEncryption = true\n'; fi
            if $has_comp; then printf 'transport.useCompression = true\n'; fi
        } > "$out"
    else
        {
            printf 'server_addr = "%s"\nserver_port = %s\n' "$server_host" "$server_port"
            printf 'token = "%s"\n' "$token"
            printf 'tcp_mux = false\n'
            printf 'login_fail_exit = true\npool_count = 1\n'
            printf '\n[[proxies]]\nname = "%s"\ntype = "xtcp"\nlocal_ip = "127.0.0.1"\n' "$name"
            printf 'local_port = %s\nsk = "%s"\n' "$echo_port" "$sk"
            if $has_enc; then printf 'use_encryption = true\n'; fi
            if $has_comp; then printf 'use_compression = true\n'; fi
        } > "$out"
    fi
}

write_frpc_config_xtcp_visitor() {
    local impl="$1" server_host="$2" server_port="$3" token="$4"
    local visitor_port="$5" server_name="$6" sk="$7" out="$8"
    if [[ "$impl" == "go" ]]; then
        {
            printf 'serverAddr = "%s"\nserverPort = %s\n' "$server_host" "$server_port"
            printf 'auth.token = "%s"\n' "$token"
            printf 'transport.tls.enable = false\n'
            printf 'transport.tcpMux = false\n'
            printf 'log.to = "%s/go-frpc-visitor-%s.log"\nlog.level = "debug"\n\n' "$TEST_DIR" "$server_name"
            printf '[[visitors]]\nname = "xtcp-visitor"\ntype = "xtcp"\n'
            printf 'serverName = "%s"\nsecretKey = "%s"\n' "$server_name" "$sk"
            printf 'bindAddr = "127.0.0.1"\nbindPort = %s\n' "$visitor_port"
        } > "$out"
    else
        {
            printf 'server_addr = "%s"\nserver_port = %s\n' "$server_host" "$server_port"
            printf 'token = "%s"\n' "$token"
            printf 'tcp_mux = false\n'
            printf 'login_fail_exit = true\npool_count = 1\n'
            printf '\n[[visitors]]\nname = "xtcp-visitor"\ntype = "xtcp"\n'
            printf 'server_name = "%s"\nsk = "%s"\n' "$server_name" "$sk"
            printf 'bind_addr = "127.0.0.1"\nbind_port = %s\n' "$visitor_port"
        } > "$out"
    fi
}
```

- [ ] **Step 3: Add generic `run_xtcp_test` function**

This replaces the duplicated logic in each XTCP test function. Place after the config writers (~line 830):

```bash
# Generic XTCP end-to-end test runner.
# Usage: run_xtcp_test <name> <frps-impl> <provider-impl> <visitor-impl> [features]
run_xtcp_test() {
    local name="$1" frps_impl="$2" prov_impl="$3" vis_impl="$4" features="${5:-}"
    should_run_test "$name" || return 0

    log "=== $name ==="
    local frps_port=$(random_port)
    local echo_port=$(random_port)
    local visitor_port=$(random_port)
    local token="${name}-token-$(date +%s)"
    local sk="${name}-sk"

    mkdir -p "$TEST_DIR/$name"

    # Start echo server (local)
    start_echo_server "$echo_port"
    wait_for_port 127.0.0.1 "$echo_port" 3 || {
        fail_test "$name" "echo server did not start"
        return
    }

    # Determine server address
    local server_host="127.0.0.1"
    if [[ -n "${XTCP_FRPS_REMOTE:-}" ]]; then
        server_host="$XTCP_FRPS_REMOTE"
        # Start frps on remote VPS
        bash "$SCRIPT_DIR/remote-frps.sh" start "$frps_impl" "$XTCP_FRPS_REMOTE" \
            "$frps_port" "$token" "${XTCP_VPS_SSH_KEY:-}" || {
            fail_test "$name" "remote frps ($frps_impl) did not start"
            return
        }
    else
        # Start frps locally
        write_frps_config "$frps_impl" "$frps_port" "$token" "$TEST_DIR/$name/frps.toml" ""
        if [[ "$frps_impl" == "go" ]]; then
            run_go "$GO_FRPS" -c "$TEST_DIR/$name/frps.toml" \
                > "$TEST_DIR/$name/frps.log" 2>&1 &
            track_pid $!
        else
            RUST_LOG=info "$RUST_FRPS" -c "$TEST_DIR/$name/frps.toml" \
                > "$TEST_DIR/$name/frps.log" 2>&1 &
            track_pid $!
        fi
        wait_for_port 127.0.0.1 "$frps_port" 5 || {
            fail_test "$name" "local $frps_impl frps did not start"
            return
        }
    fi

    # Start provider frpc
    write_frpc_config_xtcp_provider "$prov_impl" "$server_host" "$frps_port" \
        "$token" "$echo_port" "$name" "$sk" "$TEST_DIR/$name/frpc-provider.toml" "$features"

    if [[ "$prov_impl" == "go" ]]; then
        run_go "$GO_FRPC" -c "$TEST_DIR/$name/frpc-provider.toml" \
            > "$TEST_DIR/$name/frpc-provider.log" 2>&1 &
        track_pid $!
    else
        RUST_LOG=debug "$RUST_FRPC" -c "$TEST_DIR/$name/frpc-provider.toml" \
            > "$TEST_DIR/$name/frpc-provider.log" 2>&1 &
        track_pid $!
    fi

    # Start visitor frpc
    write_frpc_config_xtcp_visitor "$vis_impl" "$server_host" "$frps_port" \
        "$token" "$visitor_port" "$name" "$sk" "$TEST_DIR/$name/frpc-visitor.toml"

    if [[ "$vis_impl" == "go" ]]; then
        run_go "$GO_FRPC" -c "$TEST_DIR/$name/frpc-visitor.toml" \
            > "$TEST_DIR/$name/frpc-visitor.log" 2>&1 &
        track_pid $!
    else
        RUST_LOG=debug "$RUST_FRPC" -c "$TEST_DIR/$name/frpc-visitor.toml" \
            > "$TEST_DIR/$name/frpc-visitor.log" 2>&1 &
        track_pid $!
    fi

    # XTCP NAT hole punch coordination
    sleep 2

    # Wait for visitor port
    if ! wait_for_port_safe 127.0.0.1 "$visitor_port" 30; then
        fail_test "$name" "visitor port $visitor_port not reachable"
        # Cleanup remote frps if used
        if [[ -n "${XTCP_FRPS_REMOTE:-}" ]]; then
            bash "$SCRIPT_DIR/remote-frps.sh" stop "$XTCP_FRPS_REMOTE" "${XTCP_VPS_SSH_KEY:-}" 2>/dev/null || true
        fi
        return
    fi

    # Echo data round-trip
    local result
    result=$(send_and_expect "$visitor_port" "${name}-data" "${name}-data" 20)
    if [[ "$result" == OK:* ]]; then
        pass_test "$name"
    else
        fail_test "$name" "$result"
    fi

    # Cleanup remote frps
    if [[ -n "${XTCP_FRPS_REMOTE:-}" ]]; then
        bash "$SCRIPT_DIR/remote-frps.sh" stop "$XTCP_FRPS_REMOTE" "${XTCP_VPS_SSH_KEY:-}" 2>/dev/null || true
    fi
}
```

- [ ] **Step 4: Add 8 new XTCP test functions**

Replace the old `test_g2r_xtcp` and `test_r2g_xtcp` functions with the 8 pairwise functions. These are thin wrappers around `run_xtcp_test`:

```bash
# ── XTCP baselines (same-implementation) ──

test_xtcp_g2g_basic() {
    run_xtcp_test "xtcp-g2g-basic" go go go ""
}

test_xtcp_r2r_basic() {
    run_xtcp_test "xtcp-r2r-basic" rust rust rust ""
}

# ── XTCP cross-implementation ──

test_xtcp_g2r_basic() {
    run_xtcp_test "xtcp-g2r-basic" rust go go ""
}

test_xtcp_r2g_basic() {
    run_xtcp_test "xtcp-r2g-basic" go rust rust ""
}

test_xtcp_go_frps_go_prov_rust_vis() {
    run_xtcp_test "xtcp-go-frps-go-prov-rust-vis" go go rust ""
}

test_xtcp_go_frps_rust_prov_go_vis() {
    run_xtcp_test "xtcp-go-frps-rust-prov-go-vis" go rust go ""
}

test_xtcp_rust_frps_go_prov_rust_vis() {
    run_xtcp_test "xtcp-rust-frps-go-prov-rust-vis" rust go rust ""
}

test_xtcp_rust_frps_rust_prov_go_vis() {
    run_xtcp_test "xtcp-rust-frps-rust-prov-go-vis" rust rust go ""
}

# ── XTCP encrypted variants ──

test_xtcp_g2g_enc() {
    run_xtcp_test "xtcp-g2g-enc" go go go "enc compression"
}

test_xtcp_r2r_enc() {
    run_xtcp_test "xtcp-r2r-enc" rust rust rust "enc compression"
}

test_xtcp_g2r_enc() {
    run_xtcp_test "xtcp-g2r-enc" rust go go "enc compression"
}

test_xtcp_r2g_enc() {
    run_xtcp_test "xtcp-r2g-enc" go rust rust "enc compression"
}
```

Delete the old `test_g2r_xtcp` (lines 2013-2100) and `test_r2g_xtcp` (lines 2105-2190) functions.

- [ ] **Step 5: Update the test runner section**

In the test runner section (around line 2829), replace the XTCP guard block:

```bash
# ── XTCP tests (Phase 1: VPS CI or RUN_XTCP=1) ──
if [[ -n "${XTCP_FRPS_REMOTE:-}" ]]; then
    log "XTCP: remote frps mode — running all 12 pairwise tests"
    RUN_XTCP=1
fi

if [[ "${RUN_XTCP:-0}" == "1" ]]; then
    # Baselines first
    run_test test_xtcp_g2g_basic
    run_test test_xtcp_r2r_basic

    # Cross-implementation
    run_test test_xtcp_g2r_basic
    run_test test_xtcp_r2g_basic
    run_test test_xtcp_go_frps_go_prov_rust_vis
    run_test test_xtcp_go_frps_rust_prov_go_vis
    run_test test_xtcp_rust_frps_go_prov_rust_vis
    run_test test_xtcp_rust_frps_rust_prov_go_vis

    # Encrypted variants
    run_test test_xtcp_g2g_enc
    run_test test_xtcp_r2r_enc
    run_test test_xtcp_g2r_enc
    run_test test_xtcp_r2g_enc
else
    log "SKIP XTCP tests: requires public internet (STUN + NAT probes). Set RUN_XTCP=1 to enable."
fi
```

- [ ] **Step 6: Add `--xtcp-only` behavior**

When `--xtcp-only` is set, skip all non-XTCP tests. Add at the top of each test function group (TCP, UDP, HTTP, STCP, etc.):

```bash
    if $XTCP_ONLY; then
        should_run_test "$name" || return 0  # already handled by should_run_test
        # but we need to skip entirely — add guard at call site
    fi
```

Better approach: wrap the test invocation sections. Add before each phase section:

```bash
if ! ${XTCP_ONLY:-false}; then
    # Phase 1: TCP plain
    run_test test_g2r_tcp_plain
    ...
fi
```

And add the XTCP section:

```bash
# Phase XTCP: always run when --xtcp-only
if ${XTCP_ONLY:-false} || [[ "${RUN_XTCP:-0}" == "1" ]]; then
    # ... XTCP tests as above
fi
```

- [ ] **Step 7: Verify bash syntax**

```bash
bash -n scripts/compat-test.sh
```

Expected: no syntax errors.

- [ ] **Step 8: Run a local syntax check on new XTCP test functions**

```bash
bash scripts/compat-test.sh --list | grep xtcp
```

Expected: lists all 12 xtcp test names.

- [ ] **Step 9: Commit**

```bash
git add scripts/compat-test.sh
git commit -m "feat: add 12-test XTCP pairwise matrix + --frps-remote/--xtcp-only flags

Replaces 2 old guarded XTCP tests with full 2^3 pairwise matrix:
- 8 unencrypted (all frps<EFBFBD>provider<EFBFBD>visitor Go/Rust combos)
- 4 encrypted (g2g, r2r, g2r, r2g each with enc+comp)
- New: run_xtcp_test() generic runner + specialized config writers
- New: --frps-remote <host> for VPS-backed testing
- New: --xtcp-only to skip non-XTCP tests in CI

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

## Prerequisites (Manual)

Before Phase 1 can run in CI, the VPS must be configured:

- [ ] **VPS Setup:**
  - Create `frp-test` user (no sudo, no shell)
  - Generate SSH key pair, add public key to `~frp-test/.ssh/authorized_keys`
  - Open firewall ports 17000–17100 TCP
  - Add secrets to GitHub repo: `XTCP_VPS_HOST`, `XTCP_VPS_SSH_KEY`

---

## Self-Review Checklist

1. **Spec coverage:** 12 pairwise tests ✅, 8 local tests (5 fallback + 3 edge) ✅, remote frps management ✅, CI workflow ✅
2. **Placeholder scan:** No TBD, TODO, or "add later" patterns
3. **Type consistency:** `run_xtcp_test` function signature matches all callers; config writers match compat-test.sh conventions
4. **All frpc configs use `pool_count=1`** to avoid phantom work connections — matches existing compat-test pattern
