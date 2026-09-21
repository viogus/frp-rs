//! Audit round-10 coverage gap C: the frpc reload path with a MALFORMED
//! config must hit the Err arm and keep the old config serving.
//!
//! The rejected arm lives at frp-client/src/service.rs:4198-4199
//! (`reload_from_sources`): `load_client_config(...).map_err(|e|
//! format!("failed to load config: {e}"))?` — the load failure propagates
//! BEFORE any mutation, so `self.cfg`/`self.proxies` are untouched,
//! `reload::do_reload` never runs, and the previously running proxies keep
//! serving. (reload.rs:205-217 is a DIFFERENT arm: the no-changes shortcut
//! for a config that *loaded fine*.)
//!
//! Observability note: `Service::request_reload()` (the SIGUSR1 path) drops
//! the reply oneshot (`service.rs:1097-1100`), so the Err *string* is only
//! observable on the admin-API path, where the requester waits on the reply
//! (`admin.rs reload_and_wait` → HTTP 400 with the Err text). Both sides of
//! the gap are covered here:
//!
//! 1. `reload_malformed_config_rejected_keeps_old_proxy_serving` (default
//!    features) — drives `request_reload()` with a TOML-syntax-broken file
//!    and with a parseable-but-invalid config (bogus proxy type), then
//!    asserts the pre-reload proxy still answers traffic, the client run
//!    task did not die, and the would-be port change never happened — and
//!    finishes with a VALID reload that DOES apply, proving the reload
//!    machinery itself is alive (the negative results are not vacuous).
//! 2. `reload_malformed_config_admin_api_reports_400_keeps_old_proxy`
//!    (`feature = "admin"`) — drives the same two bad configs through the
//!    real `/api/reload` HTTP endpoint and asserts the 400 body contains
//!    the exact Err-arm text `failed to load config` (plus the validation
//!    reason for the semantic case), with the old proxy still serving and
//!    the client alive afterwards; a well-formed reload through the same
//!    endpoint returns 200 as the positive control.

mod common;

use std::sync::Arc;
use std::time::Duration;

use frp_client::service::Service as ClientService;
use frp_core::config::load_client_config;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use common::{allocate_port, init_tracing, start_echo_server, wait_for_port};

const ECHO_PAYLOAD: &[u8] = b"malformed-reload-echo\n";
const RELOAD_SETTLE: Duration = Duration::from_millis(400);

// ---------------------------------------------------------------------------
// Config writers.
// ---------------------------------------------------------------------------

/// A fully valid config: one tcp proxy `main` (echo backend) on `remote_port`.
/// `web_server_port: Some(p)` adds an `[webServer]` section for the admin API.
fn write_valid_config(
    path: &std::path::Path,
    server_port: u16,
    echo_port: u16,
    remote_port: u16,
    web_server_port: Option<u16>,
) {
    let web_server = match web_server_port {
        Some(p) => format!("\n[webServer]\naddr = \"127.0.0.1\"\nport = {p}\n"),
        None => String::new(),
    };
    std::fs::write(
        path,
        format!(
            r#"serverAddr = "127.0.0.1"
serverPort = {server_port}
loginFailExit = false
token = "reload-malformed-token"

[transport]
tcpMux = false

[[proxies]]
name = "main"
type = "tcp"
localIp = "127.0.0.1"
localPort = {echo_port}
remotePort = {remote_port}
{web_server}"#
        ),
    )
    .expect("write config");
}

/// Syntax-broken TOML: the bare-key line `this is not valid toml ...` makes
/// the file unparseable, so `load_client_config` fails with a parse error
/// (never reaches deserialization/validation).
fn write_malformed_toml(path: &std::path::Path) {
    std::fs::write(
        path,
        "serverAddr = \"127.0.0.1\"\n\
         serverPort = 12345\n\
         token = \"reload-malformed-token\"\n\
         this is not valid toml [[[proxies]\n",
    )
    .expect("write malformed config");
}

/// Parseable TOML, semantically invalid: `type = "bogus-proxy-type"` is
/// rejected by `validate_proxy_configs` (loader.rs:222-228) inside
/// `load_client_config` — this is the failure `validate_client_config`
/// reports, independent of the `strict` flag. Carries `remote_port` so a
/// buggy partial-apply would be observable (the proxy would move ports).
fn write_invalid_proxy_type_config(
    path: &std::path::Path,
    server_port: u16,
    echo_port: u16,
    remote_port: u16,
) {
    std::fs::write(
        path,
        format!(
            r#"serverAddr = "127.0.0.1"
serverPort = {server_port}
loginFailExit = false
token = "reload-malformed-token"

[transport]
tcpMux = false

[[proxies]]
name = "main"
type = "bogus-proxy-type"
localIp = "127.0.0.1"
localPort = {echo_port}
remotePort = {remote_port}
"#
        ),
    )
    .expect("write semantically invalid config");
}

/// A valid config plus a top-level key frp does not know. Non-strict loads
/// ignore it (serde's default); a strict load rejects it in
/// `run_strict_check` (frp-core/src/config/strict.rs) with
/// `unknown field "notAKnownFrpKey"`. That makes strict vs non-strict
/// observable from the HTTP status alone: strict -> 400, non-strict -> 200.
#[cfg(feature = "admin")]
fn write_unknown_key_config(
    path: &std::path::Path,
    server_port: u16,
    echo_port: u16,
    remote_port: u16,
    web_server_port: Option<u16>,
) {
    let web_server = match web_server_port {
        Some(p) => format!("\n[webServer]\naddr = \"127.0.0.1\"\nport = {p}\n"),
        None => String::new(),
    };
    std::fs::write(
        path,
        format!(
            r#"serverAddr = "127.0.0.1"
serverPort = {server_port}
loginFailExit = false
token = "reload-malformed-token"

notAKnownFrpKey = "strict-mode-probe"

[transport]
tcpMux = false

[[proxies]]
name = "main"
type = "tcp"
localIp = "127.0.0.1"
localPort = {echo_port}
remotePort = {remote_port}
{web_server}"#
        ),
    )
    .expect("write unknown-key config");
}

// ---------------------------------------------------------------------------
// Small traffic helpers.
// ---------------------------------------------------------------------------

/// Connect to `addr`, send `payload`, read back exactly `payload.len()`
/// echoed bytes. Err on connect/io failure.
async fn echo_roundtrip(addr: std::net::SocketAddr, payload: &[u8]) -> std::io::Result<Vec<u8>> {
    let mut stream = tokio::net::TcpStream::connect(addr).await?;
    stream.write_all(payload).await?;
    let mut buf = vec![0u8; payload.len()];
    stream.read_exact(&mut buf).await?;
    Ok(buf)
}

/// Assert one echo roundtrip through the given socket address returns the
/// payload byte-exact.
async fn assert_echo_serving(addr: std::net::SocketAddr, context: &str) {
    let echoed = tokio::time::timeout(Duration::from_secs(5), echo_roundtrip(addr, ECHO_PAYLOAD))
        .await
        .expect(context)
        .expect(context);
    assert_eq!(&echoed, ECHO_PAYLOAD, "echo payload mismatch ({context})");
}

// ---------------------------------------------------------------------------
// Test 1 — signal-path reload (request_reload): the Err arm keeps the old
// config serving and the client alive; a valid reload still applies.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn reload_malformed_config_rejected_keeps_old_proxy_serving() {
    init_tracing();
    let echo_port = allocate_port();
    let server_port = allocate_port();
    let p1 = allocate_port(); // initial remote port
    let p2 = allocate_port(); // port the (invalid then valid) rewrites would move to

    // 1. Echo backend + in-process frps.
    let _echo = start_echo_server(echo_port);
    let _server = common::start_frps(server_port, "reload-malformed-token").await;
    let server_addr: std::net::SocketAddr = format!("127.0.0.1:{server_port}").parse().unwrap();
    wait_for_port(server_addr, Duration::from_secs(5))
        .await
        .expect("server ready");

    // 2. Client started from a valid config file on p1.
    let dir = std::env::temp_dir().join(format!(
        "frp-reload-malformed-signal-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let cfg_path = dir.join("frpc.toml");
    write_valid_config(&cfg_path, server_port, echo_port, p1, None);

    let cfg = load_client_config(cfg_path.to_str().unwrap(), false).expect("load initial config");
    let client = Arc::new(
        ClientService::new(cfg, Some(cfg_path.to_string_lossy().into()))
            .await
            .expect("create client service"),
    );
    let runner = {
        let client = client.clone();
        tokio::spawn(async move {
            let _ = client.run().await;
        })
    };
    let p1_addr: std::net::SocketAddr = format!("127.0.0.1:{p1}").parse().unwrap();
    wait_for_port(p1_addr, Duration::from_secs(15))
        .await
        .expect("initial proxy port ready");
    assert_echo_serving(p1_addr, "baseline echo before any reload").await;

    // 3. Syntax-broken TOML reload: must be rejected before any mutation.
    write_malformed_toml(&cfg_path);
    client.request_reload();
    tokio::time::sleep(RELOAD_SETTLE).await;
    assert!(
        !runner.is_finished(),
        "client run task ended after a reload with a TOML syntax error"
    );
    // The pre-reload proxy still answers traffic (a buggy partial-apply or
    // accept-with-empty-config would have torn the registration down).
    assert_echo_serving(
        p1_addr,
        "old proxy must keep serving after a syntax-error reload",
    )
    .await;

    // 4. Parseable-but-invalid reload (bogus proxy type). If the load
    //    failure were not caught, this config would move the proxy to p2;
    //    the old p1 proxy must keep serving AND p2 must never open.
    write_invalid_proxy_type_config(&cfg_path, server_port, echo_port, p2);
    client.request_reload();
    tokio::time::sleep(RELOAD_SETTLE).await;
    assert!(
        !runner.is_finished(),
        "client run task ended after a reload with an invalid proxy type"
    );
    assert_echo_serving(
        p1_addr,
        "old proxy must keep serving after a validation-error reload",
    )
    .await;
    let p2_addr: std::net::SocketAddr = format!("127.0.0.1:{p2}").parse().unwrap();
    assert!(
        wait_for_port(p2_addr, Duration::from_secs(2))
            .await
            .is_err(),
        "a config rejected at load must not be applied: proxy 'main' moved to p2"
    );

    // 5. Positive control: the reload machinery is alive — a valid rewrite
    //    (same file, proxy moved to p2) DOES apply after the rejected ones.
    write_valid_config(&cfg_path, server_port, echo_port, p2, None);
    client.request_reload();
    wait_for_port(p2_addr, Duration::from_secs(15))
        .await
        .expect("valid reload after the rejected reloads never applied");
    assert_echo_serving(p2_addr, "echo through the validly reloaded proxy (p2)").await;

    client.request_stop();
    tokio::time::timeout(Duration::from_secs(5), runner)
        .await
        .expect("client did not shut down after request_stop")
        .expect("client run() panicked");
    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// Test 2 — admin-path reload (feature "admin"): the requester-visible Err
// arm. POST /api/reload with a malformed config file must answer HTTP 400
// with the exact Err-arm text, and the old proxy must keep serving.
// ---------------------------------------------------------------------------

/// Raw HTTP request to the frpc admin API. `body`, when `Some`, is sent as a
/// JSON body with the matching `Content-Type`/`Content-Length`. Returns the
/// status line and the response body text.
#[cfg(feature = "admin")]
async fn admin_request(
    admin_port: u16,
    method: &str,
    path: &str,
    body: Option<&str>,
) -> (String, String) {
    let mut conn = tokio::net::TcpStream::connect(("127.0.0.1", admin_port))
        .await
        .expect("connect frpc admin server");
    let mut request =
        format!("{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n");
    match body {
        Some(body) => request.push_str(&format!(
            "Content-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        )),
        None => request.push_str("\r\n"),
    }
    conn.write_all(request.as_bytes())
        .await
        .expect("write admin request");
    let mut raw = Vec::new();
    conn.read_to_end(&mut raw)
        .await
        .expect("read admin response");
    let text = String::from_utf8_lossy(&raw).to_string();
    let (head, body) = text.split_once("\r\n\r\n").unwrap_or((text.as_str(), ""));
    let status_line = head.lines().next().unwrap_or("").to_string();
    (status_line, body.to_string())
}

/// Raw HTTP POST /api/reload with an empty JSON body (`{}`). Returns the
/// status line and the response body text.
#[cfg(feature = "admin")]
async fn post_admin_reload(admin_port: u16) -> (String, String) {
    admin_request(admin_port, "POST", "/api/reload", Some("{}")).await
}

#[cfg(feature = "admin")]
#[tokio::test]
async fn reload_malformed_config_admin_api_reports_400_keeps_old_proxy() {
    init_tracing();
    let echo_port = allocate_port();
    let server_port = allocate_port();
    let admin_port = allocate_port();
    let p1 = allocate_port();

    // 1. Echo backend + in-process frps + client with an admin [webServer].
    let _echo = start_echo_server(echo_port);
    let _server = common::start_frps(server_port, "reload-malformed-token").await;
    let server_addr: std::net::SocketAddr = format!("127.0.0.1:{server_port}").parse().unwrap();
    wait_for_port(server_addr, Duration::from_secs(5))
        .await
        .expect("server ready");

    let dir =
        std::env::temp_dir().join(format!("frp-reload-malformed-admin-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let cfg_path = dir.join("frpc.toml");
    write_valid_config(&cfg_path, server_port, echo_port, p1, Some(admin_port));

    let cfg = load_client_config(cfg_path.to_str().unwrap(), false).expect("load initial config");
    let client = Arc::new(
        ClientService::new(cfg, Some(cfg_path.to_string_lossy().into()))
            .await
            .expect("create client service"),
    );
    let runner = {
        let client = client.clone();
        tokio::spawn(async move {
            let _ = client.run().await;
        })
    };
    let p1_addr: std::net::SocketAddr = format!("127.0.0.1:{p1}").parse().unwrap();
    wait_for_port(p1_addr, Duration::from_secs(15))
        .await
        .expect("initial proxy port ready");
    assert_echo_serving(p1_addr, "baseline echo before any reload").await;

    // 2. Admin HTTP server up (spawned at the start of run()).
    let admin_addr: std::net::SocketAddr = format!("127.0.0.1:{admin_port}").parse().unwrap();
    wait_for_port(admin_addr, Duration::from_secs(10))
        .await
        .expect("frpc admin server never came up");

    // 3. Syntax-broken TOML → HTTP 400 with the Err-arm text. The admin
    //    requester waits on the reply oneshot, so the 400 proves the run
    //    loop actually processed the reload and rejected it at load.
    write_malformed_toml(&cfg_path);
    let (status, body) = post_admin_reload(admin_port).await;
    assert!(
        status.contains("400"),
        "syntax-error reload must answer 400, got: {status} / {body}"
    );
    assert!(
        body.contains("failed to load config"),
        "400 body must carry the service.rs Err arm ('failed to load config'), got: {body}"
    );
    assert!(
        !runner.is_finished(),
        "client run task ended after a rejected admin reload"
    );
    assert_echo_serving(
        p1_addr,
        "old proxy must keep serving after a syntax-error admin reload",
    )
    .await;

    // 4. Parseable-but-invalid (bogus proxy type) → 400 with the validation
    //    reason appended after the Err-arm prefix.
    write_invalid_proxy_type_config(&cfg_path, server_port, echo_port, p1);
    let (status, body) = post_admin_reload(admin_port).await;
    assert!(
        status.contains("400"),
        "invalid-proxy-type reload must answer 400, got: {status} / {body}"
    );
    assert!(
        body.contains("failed to load config"),
        "400 body must carry the service.rs Err arm ('failed to load config'), got: {body}"
    );
    assert!(
        body.contains("invalid proxy_type 'bogus-proxy-type'"),
        "400 body must carry the loader validation reason, got: {body}"
    );
    assert!(
        !runner.is_finished(),
        "client run task ended after a rejected admin reload"
    );
    assert_echo_serving(
        p1_addr,
        "old proxy must keep serving after a validation-error admin reload",
    )
    .await;

    // 5. Positive control: an unchanged valid config through the same
    //    endpoint returns 200 (no-changes shortcut in reload.rs).
    write_valid_config(&cfg_path, server_port, echo_port, p1, Some(admin_port));
    let (status, body) = post_admin_reload(admin_port).await;
    assert!(
        status.contains("200"),
        "well-formed reload must answer 200, got: {status} / {body}"
    );
    assert_echo_serving(
        p1_addr,
        "old proxy still serving after the 200 control reload",
    )
    .await;

    client.request_stop();
    tokio::time::timeout(Duration::from_secs(5), runner)
        .await
        .expect("client did not shut down after request_stop")
        .expect("client run() panicked");
    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// Test 3 — the Go-parity reload channel. Go frp v0.71.0 registers GET only
// (`client/api_router.go` at commit 4a23aa18) and its handler reads NO body:
// strict mode comes from `?strictConfig=`, parsed with strconv.ParseBool and
// with the parse error discarded (`client/http/controller.go`), so a garbage
// value is a 200 non-strict, never a 400. frp-rs keeps its JSON-body
// extension (used by frpc's own CLI) and adds the query channel.
//
// Strictness is made observable by an unknown top-level config key: a strict
// reload rejects it with 400 (`unknown field "notAKnownFrpKey"`), a
// non-strict reload ignores it and answers 200 — proving the flag took
// effect rather than only that the request was answered.
// ---------------------------------------------------------------------------

#[cfg(feature = "admin")]
#[tokio::test]
async fn reload_admin_go_query_parity_and_body_extension() {
    init_tracing();
    let echo_port = allocate_port();
    let server_port = allocate_port();
    let admin_port = allocate_port();
    let p1 = allocate_port();

    // 1. Echo backend + in-process frps + client with an admin [webServer].
    let _echo = start_echo_server(echo_port);
    let _server = common::start_frps(server_port, "reload-malformed-token").await;
    let server_addr: std::net::SocketAddr = format!("127.0.0.1:{server_port}").parse().unwrap();
    wait_for_port(server_addr, Duration::from_secs(5))
        .await
        .expect("server ready");

    let dir = std::env::temp_dir().join(format!("frp-reload-admin-parity-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let cfg_path = dir.join("frpc.toml");
    write_valid_config(&cfg_path, server_port, echo_port, p1, Some(admin_port));

    let cfg = load_client_config(cfg_path.to_str().unwrap(), false).expect("load initial config");
    let client = Arc::new(
        ClientService::new(cfg, Some(cfg_path.to_string_lossy().into()))
            .await
            .expect("create client service"),
    );
    let runner = {
        let client = client.clone();
        tokio::spawn(async move {
            let _ = client.run().await;
        })
    };
    let p1_addr: std::net::SocketAddr = format!("127.0.0.1:{p1}").parse().unwrap();
    wait_for_port(p1_addr, Duration::from_secs(15))
        .await
        .expect("initial proxy port ready");

    let admin_addr: std::net::SocketAddr = format!("127.0.0.1:{admin_port}").parse().unwrap();
    wait_for_port(admin_addr, Duration::from_secs(10))
        .await
        .expect("frpc admin server never came up");

    // Every reload below reads this one file: valid except for the unknown key.
    write_unknown_key_config(&cfg_path, server_port, echo_port, p1, Some(admin_port));

    // 2. Go's exact call shape — GET, no body, no query. Must be a 200
    //    non-strict reload (previously a 415 from axum's Json extractor).
    let (status, body) = admin_request(admin_port, "GET", "/api/reload", None).await;
    assert!(
        status.contains("200"),
        "body-less GET /api/reload must answer 200, got: {status} / {body}"
    );

    // 3. Go's strict channel: ?strictConfig=true must reach the loader as
    //    strict=true, so the unknown key is rejected with 400.
    let (status, body) =
        admin_request(admin_port, "GET", "/api/reload?strictConfig=true", None).await;
    assert!(
        status.contains("400"),
        "?strictConfig=true must be strict (400 on the unknown key), got: {status} / {body}"
    );
    assert!(
        body.contains(r#"unknown field "notAKnownFrpKey""#),
        "strict rejection must name the unknown key, got: {body}"
    );

    // 4. The full strconv.ParseBool true accept set -> strict (400).
    for v in ["1", "t", "T", "TRUE", "true", "True"] {
        let (status, body) = admin_request(
            admin_port,
            "GET",
            &format!("/api/reload?strictConfig={v}"),
            None,
        )
        .await;
        assert!(
            status.contains("400"),
            "?strictConfig={v} must be strict, got: {status} / {body}"
        );
    }

    // 5. The false accept set AND ParseBool errors -> non-strict (200). The
    //    error case is the parity point: Go discards the error, so
    //    `yes`/`garbage`/empty must be a 200 non-strict, NOT a 400.
    for v in [
        "0", "f", "F", "FALSE", "false", "False", "yes", "garbage", "",
    ] {
        let (status, body) = admin_request(
            admin_port,
            "GET",
            &format!("/api/reload?strictConfig={v}"),
            None,
        )
        .await;
        assert!(
            status.contains("200"),
            "?strictConfig={v} must be a non-strict 200, got: {status} / {body}"
        );
    }

    // 5b. A REPEATED parameter is not an error: Go's `url.Values.Get` reads
    //     the first value, so `?strictConfig=true&strictConfig=false` is a
    //     strict reload (400 on the unknown key), and the reverse order is a
    //     non-strict 200. axum's typed `Query<Struct>` used to reject the
    //     duplicate with serde's `duplicate_field` -> 400 before the handler.
    let (status, body) = admin_request(
        admin_port,
        "GET",
        "/api/reload?strictConfig=true&strictConfig=false",
        None,
    )
    .await;
    assert!(
        status.contains("400"),
        "duplicate ?strictConfig must take the FIRST value (true -> strict 400), got: {status} / {body}"
    );
    let (status, body) = admin_request(
        admin_port,
        "GET",
        "/api/reload?strictConfig=false&strictConfig=true",
        None,
    )
    .await;
    assert!(
        status.contains("200"),
        "duplicate ?strictConfig must take the FIRST value (false -> non-strict 200), got: {status} / {body}"
    );

    // 5c. Go discards `url.ParseQuery`'s error and keeps every pair it could
    //     unescape, so a malformed escape makes `strictConfig` *absent*
    //     (non-strict 200), not a 400. Real Go v0.71.0-equivalent behaviour
    //     (`net/url.ParseQuery`, verified with go1.27.1):
    //       strictConfig=%zz            -> Get("") -> non-strict 200
    //       strictConfig=%ff            -> Get("\xff") -> non-strict 200
    //       foo=%zz&strictConfig=true   -> Get("true") -> strict 400
    //     axum's `Query` extractor rejected the whole query with 400 instead.
    let (status, body) =
        admin_request(admin_port, "GET", "/api/reload?strictConfig=%zz", None).await;
    assert!(
        status.contains("200"),
        "?strictConfig=%zz drops only its own pair (Go) -> non-strict 200, got: {status} / {body}"
    );
    let (status, body) = admin_request(
        admin_port,
        "GET",
        "/api/reload?foo=%zz&strictConfig=true",
        None,
    )
    .await;
    assert!(
        status.contains("400"),
        "a malformed pair elsewhere must not hide strictConfig=true, got: {status} / {body}"
    );
    // A bare key (no `=`) is the empty value -> ParseBool error -> non-strict.
    let (status, body) = admin_request(admin_port, "GET", "/api/reload?strictConfig", None).await;
    assert!(
        status.contains("200"),
        "bare ?strictConfig must be the empty value -> non-strict 200, got: {status} / {body}"
    );
    // `%ff` unescapes fine (Go does not validate UTF-8) but ParseBool rejects
    // the byte -> non-strict 200. axum's `Query` 400'd on the decode instead.
    let (status, body) =
        admin_request(admin_port, "GET", "/api/reload?strictConfig=%ff", None).await;
    assert!(
        status.contains("200"),
        "?strictConfig=%ff must be a non-strict 200, got: {status} / {body}"
    );

    // 6. Preserved frp-rs extension: POST + JSON body (snake_case).
    let (status, body) = admin_request(
        admin_port,
        "POST",
        "/api/reload",
        Some(r#"{"strict_config": true}"#),
    )
    .await;
    assert!(
        status.contains("400"),
        "POST {{\"strict_config\": true}} must be strict, got: {status} / {body}"
    );

    // 7. frpc's own CLI sends the camelCase spelling (`frpc/src/main.rs`
    //    run_reload), so it must select strict mode too rather than being
    //    silently ignored as an unknown JSON field.
    let (status, body) = admin_request(
        admin_port,
        "POST",
        "/api/reload",
        Some(r#"{"strictConfig": true}"#),
    )
    .await;
    assert!(
        status.contains("400"),
        "POST {{\"strictConfig\": true}} (frpc CLI spelling) must be strict, got: {status} / {body}"
    );

    // 8. Explicit false in the body -> non-strict 200.
    let (status, body) = admin_request(
        admin_port,
        "POST",
        "/api/reload",
        Some(r#"{"strict_config": false}"#),
    )
    .await;
    assert!(
        status.contains("200"),
        "POST {{\"strict_config\": false}} must be non-strict, got: {status} / {body}"
    );

    // 9. Precedence: the query wins over a conflicting body, both ways.
    let (status, body) = admin_request(
        admin_port,
        "POST",
        "/api/reload?strictConfig=true",
        Some(r#"{"strict_config": false}"#),
    )
    .await;
    assert!(
        status.contains("400"),
        "query true must win over body false (strict 400), got: {status} / {body}"
    );
    let (status, body) = admin_request(
        admin_port,
        "POST",
        "/api/reload?strictConfig=false",
        Some(r#"{"strict_config": true}"#),
    )
    .await;
    assert!(
        status.contains("200"),
        "query false must win over body true (non-strict 200), got: {status} / {body}"
    );

    // 10. A body that is present but malformed is a 400 on every method —
    //     `Option<Json<..>>` would have swallowed it as "no body".
    for method in ["POST", "GET"] {
        let (status, body) = admin_request(
            admin_port,
            method,
            "/api/reload",
            Some(r#"{"strict_config": "#),
        )
        .await;
        assert!(
            status.contains("400"),
            "malformed JSON body on {method} must answer 400, got: {status} / {body}"
        );
        assert!(
            body.contains("invalid JSON body"),
            "malformed-body 400 must say so, got: {body}"
        );
    }

    // 11. None of the rejected reloads disturbed the running proxy or the
    //     client run loop.
    assert!(
        !runner.is_finished(),
        "client run task ended after the admin reload matrix"
    );
    assert_echo_serving(
        p1_addr,
        "proxy keeps serving across the admin reload matrix",
    )
    .await;

    client.request_stop();
    tokio::time::timeout(Duration::from_secs(5), runner)
        .await
        .expect("client did not shut down after request_stop")
        .expect("client run() panicked");
    let _ = std::fs::remove_dir_all(&dir);
}
