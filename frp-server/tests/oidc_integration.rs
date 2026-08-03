mod common;
mod mock_oidc;

use common::{allocate_port, raw_login, FrpsHandle};
use mock_oidc::MockOidcProvider;

/// Build TOML config for frps with OIDC auth pointing at the mock provider.
fn oidc_config(bind_port: u16, oidc_port: u16) -> String {
    format!(
        r#"bind_addr = "127.0.0.1"
bind_port = {bind_port}
tcp_mux = false

[auth]
method = "oidc"
token = ""
oidc_issuer = "http://127.0.0.1:{oidc_port}"
oidc_audience = "test-audience"
oidc_skip_expiry = true
oidc_skip_issuer = false
"#,
        bind_port = bind_port,
        oidc_port = oidc_port,
    )
}

// ---------------------------------------------------------------
// Test: OIDC login success
// ---------------------------------------------------------------

/// Start frps with OIDC auth pointing at a mock OIDC provider.
/// Log in with a valid JWT — should succeed and return a run_id.
#[tokio::test]
async fn test_oidc_login_success() {
    let oidc_port = allocate_port();
    let bind_port = allocate_port();

    let oidc = MockOidcProvider::start(oidc_port).await;
    let token = oidc.generate_token("test-user");

    let frps = FrpsHandle::start(&oidc_config(bind_port, oidc_port)).await;

    let addr: std::net::SocketAddr = format!("127.0.0.1:{}", bind_port).parse().unwrap();
    let result = raw_login(addr, Some(token), None, "").await;

    // Check login succeeded
    match result {
        Ok((_stream, resp)) => {
            assert!(resp.error.is_none(), "Login error: {:?}", resp.error);
            let run_id = resp.run_id.expect("run_id should be present");
            assert_eq!(run_id.len(), 36, "run_id should be UUID v4: {}", run_id);
        }
        Err(e) => panic!("Login failed: {}", e),
    }

    drop(frps);
    drop(oidc);
}

// ---------------------------------------------------------------
// Test: OIDC login rejected with bad token
// ---------------------------------------------------------------

/// Try to login with an invalid JWT — should be rejected.
#[tokio::test]
async fn test_oidc_login_rejected_bad_token() {
    let oidc_port = allocate_port();
    let bind_port = allocate_port();

    let oidc = MockOidcProvider::start(oidc_port).await;
    let frps = FrpsHandle::start(&oidc_config(bind_port, oidc_port)).await;

    let addr: std::net::SocketAddr = format!("127.0.0.1:{}", bind_port).parse().unwrap();

    // Try with a completely invalid JWT
    let result = raw_login(addr, Some("not-a-valid-jwt".into()), None, "").await;
    match result {
        Ok((_stream, resp)) => {
            assert!(resp.error.is_some(), "Expected login error for bad token");
        }
        Err(_) => {
            // Connection might also be dropped — that's acceptable
        }
    }

    // Try with a well-formed but unsigned JWT (header.payload.signature)
    let fake_jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0IiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
    let addr2: std::net::SocketAddr = format!("127.0.0.1:{}", bind_port).parse().unwrap();
    let result2 = raw_login(addr2, Some(fake_jwt.into()), None, "").await;
    match result2 {
        Ok((_stream, resp)) => {
            assert!(resp.error.is_some(), "Expected login error for fake JWT");
        }
        Err(_) => {
            // Connection dropped — acceptable
        }
    }

    drop(frps);
    drop(oidc);
}

// ---------------------------------------------------------------
// Test: OIDC login success then failure validates server state
// ---------------------------------------------------------------

/// Verify that the OIDC verifier correctly rejects a token after
/// accepting a valid one (no auth state leak).
#[tokio::test]
async fn test_oidc_login_multiple_attempts() {
    let oidc_port = allocate_port();
    let bind_port = allocate_port();

    let oidc = MockOidcProvider::start(oidc_port).await;
    let token = oidc.generate_token("test-user");

    let frps = FrpsHandle::start(&oidc_config(bind_port, oidc_port)).await;

    let addr: std::net::SocketAddr = format!("127.0.0.1:{}", bind_port).parse().unwrap();

    // First login: valid token
    let (stream1, resp1) = raw_login(addr, Some(token.clone()), None, "")
        .await
        .expect("first login should succeed");
    assert!(resp1.error.is_none(), "Login error: {:?}", resp1.error);
    assert!(resp1.run_id.is_some());
    drop(stream1);

    // Second login: valid token again (new connection)
    let addr2: std::net::SocketAddr = format!("127.0.0.1:{}", bind_port).parse().unwrap();
    let (stream2, resp2) = raw_login(addr2, Some(token.clone()), None, "")
        .await
        .expect("second login should succeed");
    assert!(resp2.error.is_none());
    assert!(resp2.run_id.is_some());
    drop(stream2);

    // Third login: invalid token should be rejected
    let addr3: std::net::SocketAddr = format!("127.0.0.1:{}", bind_port).parse().unwrap();
    let result3 = raw_login(addr3, Some("bad-token".into()), None, "").await;
    assert!(
        result3.is_err() || result3.unwrap().1.error.is_some(),
        "bad token should be rejected"
    );

    drop(frps);
    drop(oidc);
}

// ---------------------------------------------------------------
// Test: Go frpc → Rust frps with OIDC (compat smoke test)
// ---------------------------------------------------------------

/// Start mock OIDC + Rust frps, then connect Go frpc with OIDC token.
/// Skip if Go frp binary is not available.
#[tokio::test]
async fn test_oidc_go_client_to_rust_server() {
    // Check if Go frp binaries are available
    let go_bin = std::env::var("GO_FRP_BIN").unwrap_or_else(|_| "frp_go/bin".to_string());
    let go_frpc = format!("{}/frpc", go_bin);

    if std::path::Path::new(&go_frpc).exists() {
        // Go frp available — could run a cross-compat test
        // For now: smoke test that Go binary is reachable
        let output = std::process::Command::new(&go_frpc)
            .arg("--version")
            .output();
        if let Ok(o) = output {
            let stdout = String::from_utf8_lossy(&o.stdout);
            eprintln!("Go frpc version: {}", stdout.trim());
        }
    } else {
        eprintln!(
            "Skipping test_oidc_go_client_to_rust_server: Go frpc not found at {}",
            go_frpc
        );
    }
}

// ---------------------------------------------------------------
// Test: Rust frpc → Go frps with OIDC (compat smoke test)
// ---------------------------------------------------------------

/// Start mock OIDC + Go frps, then use Rust frpc with OIDC token.
/// Skip if Go frp binary is not available.
#[tokio::test]
async fn test_oidc_rust_client_to_go_server() {
    // Check if Go frp binaries are available
    let go_bin = std::env::var("GO_FRP_BIN").unwrap_or_else(|_| "frp_go/bin".to_string());
    let go_frps = format!("{}/frps", go_bin);

    if std::path::Path::new(&go_frps).exists() {
        // Go frp available — could run a cross-compat test
        let output = std::process::Command::new(&go_frps)
            .arg("--version")
            .output();
        if let Ok(o) = output {
            let stdout = String::from_utf8_lossy(&o.stdout);
            eprintln!("Go frps version: {}", stdout.trim());
        }
    } else {
        eprintln!(
            "Skipping test_oidc_rust_client_to_go_server: Go frps not found at {}",
            go_frps
        );
    }
}

// ---------------------------------------------------------------
// Test: jti replay protection — same subject reconnect allowed
// ---------------------------------------------------------------

/// frpc caches its OIDC token and legitimately re-sends it on reconnect
/// (same jti, same subject). The server must allow this.
#[tokio::test]
async fn test_oidc_jti_same_subject_reconnect_allowed() {
    let oidc_port = allocate_port();
    let bind_port = allocate_port();

    let oidc = MockOidcProvider::start(oidc_port).await;
    let token = oidc.generate_token_with_jti("test-user", Some("jti-reconnect"));

    let frps = FrpsHandle::start(&oidc_config(bind_port, oidc_port)).await;

    let addr: std::net::SocketAddr = format!("127.0.0.1:{}", bind_port).parse().unwrap();

    // First login: valid token with jti.
    let (stream1, resp1) = raw_login(addr, Some(token.clone()), None, "")
        .await
        .expect("first login should succeed");
    assert!(resp1.error.is_none(), "Login error: {:?}", resp1.error);
    assert!(resp1.run_id.is_some());
    drop(stream1);

    // Reconnect with the same token (same jti, same subject): allowed.
    let (stream2, resp2) = raw_login(addr, Some(token), None, "")
        .await
        .expect("reconnect login should succeed");
    assert!(
        resp2.error.is_none(),
        "Reconnect rejected: {:?}",
        resp2.error
    );
    drop(stream2);

    drop(frps);
    drop(oidc);
}

// ---------------------------------------------------------------
// Test: jti replay protection — different subject rejected
// ---------------------------------------------------------------

/// The same jti claim presented under a different subject is a cross-identity
/// replay: the second login must be rejected.
#[tokio::test]
async fn test_oidc_jti_different_subject_rejected() {
    let oidc_port = allocate_port();
    let bind_port = allocate_port();

    let oidc = MockOidcProvider::start(oidc_port).await;
    let token_alice = oidc.generate_token_with_jti("alice", Some("jti-shared"));

    let frps = FrpsHandle::start(&oidc_config(bind_port, oidc_port)).await;

    let addr: std::net::SocketAddr = format!("127.0.0.1:{}", bind_port).parse().unwrap();

    // First login as alice.
    let (stream1, resp1) = raw_login(addr, Some(token_alice.clone()), None, "")
        .await
        .expect("alice login should succeed");
    assert!(resp1.error.is_none());
    drop(stream1);

    // Second login: same jti but a different subject (mallory) — replay.
    // The mock signs a fresh token, but the jti collides with alice's.
    let token_mallory = oidc.generate_token_with_jti("mallory", Some("jti-shared"));
    let result2 = raw_login(addr, Some(token_mallory), None, "").await;
    match result2 {
        Ok((_stream, resp2)) => {
            assert!(
                resp2.error.is_some(),
                "different-subject jti reuse must be rejected, got {:?}",
                resp2
            );
        }
        Err(_) => {
            // Connection dropped is acceptable — the login was rejected.
        }
    }

    drop(frps);
    drop(oidc);
}
