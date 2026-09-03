//! R3: a reload that changes ONLY request headers (`requestHeaders` set)
//! must not be silently dropped.
//!
//! M7 (reload.rs `config_snapshot`): pre-fix, the change-detection snapshot
//! omitted the NewProxy-wire header fields, so a config edit that only
//! touched `[proxies.requestHeaders.set]` (or response_headers/metas)
//! produced an empty delta — the proxy was never re-registered with the
//! server and the old headers stayed in effect forever.
//!
//! Two e2e observations:
//! 1. Wire-level (mock server): the headers-only reload must emit exactly
//!    one CloseProxy + one NewProxy for the changed http proxy, and no
//!    frame at all for an untouched sibling tcp proxy.
//! 2. Behavior-level (in-process frps): the header change must actually
//!    reach the server's vhost route — a request forwarded through frps
//!    after the reload carries the NEW header value, not the old one.
//!
//! Both drive `ClientService::request_reload()` against a config FILE (the
//! reload path is file-based), with frp-server as an in-process dev-dep —
//! no frps/frpc binaries needed.

mod common;

use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use frp_client::service::Service as ClientService;
use frp_core::config::{load_client_config, ClientConfig, ServerConfig};
use frp_core::msg::FrpMessage;
use frp_core::transport::IoStream;

use common::{allocate_port, init_tracing, start_echo_server, wait_for_port};

const ASSERT_TIMEOUT: Duration = Duration::from_secs(10);
const HTTP_DOMAIN: &str = "web-reload.example.com";

fn write_config(
    path: &std::path::Path,
    server_port: u16,
    http_backend_port: u16,
    echo_port: u16,
    tcp_remote_port: u16,
    x_custom: &str,
) {
    std::fs::write(
        path,
        format!(
            r#"serverAddr = "127.0.0.1"
serverPort = {server_port}
loginFailExit = false
token = "reload-headers-token"
tls_enable = false

[transport]
tcpMux = false

[[proxies]]
name = "web"
type = "http"
localIp = "127.0.0.1"
localPort = {http_backend_port}
customDomains = ["{HTTP_DOMAIN}"]

[proxies.requestHeaders.set]
X-Custom = "{x_custom}"

[[proxies]]
name = "other"
type = "tcp"
localIp = "127.0.0.1"
localPort = {echo_port}
remotePort = {tcp_remote_port}
"#
        ),
    )
    .expect("write config");
}

fn client_config(path: &std::path::Path) -> (ClientConfig, String) {
    let path_str = path.to_string_lossy().into_owned();
    let cfg = load_client_config(&path_str, false).expect("load client config");
    (cfg, path_str)
}

/// Send one plain HTTP/1.1 GET to `host` on `port`; return the raw response
/// bytes (the capture backend replies and closes, so read_to_end ends).
async fn send_http_get(port: u16, host: &str) -> std::io::Result<String> {
    let mut conn = TcpStream::connect(("127.0.0.1", port)).await?;
    let req = format!("GET /r3-check HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    conn.write_all(req.as_bytes()).await?;
    let mut resp = Vec::new();
    conn.read_to_end(&mut resp).await?;
    Ok(String::from_utf8_lossy(&resp).to_string())
}

/// Local HTTP backend: accepts connections, reads one request head (up to
/// the blank line), ships it over the channel, replies 200 and closes.
/// The test asserts on the REQUEST head the backend receives — the header
/// injection happens server-side (frps vhost) before the request is
/// forwarded here. The listener is bound synchronously (returned from the
/// join handle) so the client can never dial a not-yet-bound backend.
async fn spawn_http_capture_backend(
    port: u16,
) -> (
    tokio::sync::mpsc::UnboundedReceiver<String>,
    tokio::task::JoinHandle<()>,
) {
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    let listener = TcpListener::bind(("127.0.0.1", port))
        .await
        .expect("backend bind");
    let handle = tokio::spawn(async move {
        loop {
            let Ok((mut conn, _)) = listener.accept().await else {
                break;
            };
            let tx = tx.clone();
            tokio::spawn(async move {
                let mut buf = Vec::new();
                let mut chunk = [0u8; 1024];
                loop {
                    match conn.read(&mut chunk).await {
                        Ok(0) => break,
                        Ok(n) => buf.extend_from_slice(&chunk[..n]),
                        Err(_) => break,
                    }
                    if buf.windows(4).any(|w| w == b"\r\n\r\n") || buf.len() > 64 * 1024 {
                        break;
                    }
                }
                let _ = tx.send(String::from_utf8_lossy(&buf).to_string());
                let _ = conn
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                    .await;
            });
        }
    });
    (rx, handle)
}

// ---------------------------------------------------------------------------
// Test 1 — wire-level exact-count against a mock server.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn reload_headers_only_change_emits_exactly_one_reregistration() {
    init_tracing();
    let token = "reload-headers-token";
    let server_port = allocate_port();
    let http_backend_port = allocate_port();
    let echo_port = allocate_port();
    let tcp_remote_port = allocate_port();

    // Config file (no real backend needed — the mock never opens work conns).
    let dir = std::env::temp_dir().join(format!("frp-reload-headers-mock-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let cfg_path = dir.join("frpc.toml");
    write_config(
        &cfg_path,
        server_port,
        http_backend_port,
        echo_port,
        tcp_remote_port,
        "v1",
    );

    // Mock server: complete login, Pong pings, answer every NewProxy with a
    // success NewProxyResp, and record the ordered frame list (NewProxy and
    // CloseProxy carry the proxy name).
    let listener = TcpListener::bind(("127.0.0.1", server_port)).await.unwrap();
    let frames: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let record = frames.clone();
    let login_resp = FrpMessage::LoginResp(frp_core::msg::LoginResp {
        version: Some(frp_core::VERSION.into()),
        run_id: Some("mock-r3".into()),
        error: None,
        server_additional_auth_scopes: None,
    });
    let enc_key = frp_core::encryption::derive_key(token);
    let mock = tokio::spawn(async move {
        let (conn, _) = listener.accept().await.expect("control conn");
        let mut stream = IoStream::Tcp(conn);
        let login = tokio::time::timeout(Duration::from_secs(10), stream.read_v1_frame())
            .await
            .expect("login timeout")
            .expect("read Login");
        assert!(matches!(login, FrpMessage::Login(_)));
        stream
            .write_v1_frame(&login_resp)
            .await
            .expect("write LoginResp");
        let mut enc = stream
            .into_encrypted(enc_key)
            .expect("plain test stream is encryptable");
        loop {
            let msg = match enc.read_v1_frame().await {
                Ok(m) => m,
                Err(_) => break,
            };
            match msg {
                FrpMessage::NewProxy(np) => {
                    record
                        .lock()
                        .unwrap()
                        .push(format!("NewProxy:{}", np.proxy_name));
                    enc.write_v1_frame(&FrpMessage::NewProxyResp(frp_core::msg::NewProxyResp {
                        proxy_name: np.proxy_name,
                        remote_addr: Some("0.0.0.0:80".into()),
                        error: None,
                    }))
                    .await
                    .expect("write NewProxyResp");
                }
                FrpMessage::CloseProxy(cp) => {
                    record
                        .lock()
                        .unwrap()
                        .push(format!("CloseProxy:{}", cp.proxy_name));
                }
                FrpMessage::Ping(_) => {
                    enc.write_v1_frame(&FrpMessage::Pong(frp_core::msg::Pong { error: None }))
                        .await
                        .expect("write Pong");
                }
                _ => {}
            }
        }
    });

    // Client up against the mock, initial registration of web + other.
    let (cfg, cfg_path_str) = client_config(&cfg_path);
    let client = Arc::new(
        ClientService::new(cfg, Some(cfg_path_str))
            .await
            .expect("create client service"),
    );
    let runner = {
        let client = client.clone();
        tokio::spawn(async move {
            let _ = client.run().await;
        })
    };
    tokio::time::timeout(ASSERT_TIMEOUT, async {
        while frames.lock().unwrap().len() < 2 {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("initial registration frames never arrived");
    assert_eq!(
        *frames.lock().unwrap(),
        vec!["NewProxy:web".to_string(), "NewProxy:other".to_string()],
        "unexpected initial registration frame order"
    );

    // Headers-only change: X-Custom v1 -> v2. Nothing else moves.
    write_config(
        &cfg_path,
        server_port,
        http_backend_port,
        echo_port,
        tcp_remote_port,
        "v2",
    );
    client.request_reload();

    // Exactly one re-registration: CloseProxy(web) + NewProxy(web), and no
    // frame for 'other'. Pre-M7 the delta was empty and NO frame arrived
    // (this assert times out); a regression re-registering everything would
    // add frames for 'other' too (length/order mismatch).
    tokio::time::timeout(ASSERT_TIMEOUT, async {
        while frames.lock().unwrap().len() < 4 {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("headers-only reload was silently dropped: no re-registration frames");
    let all = frames.lock().unwrap().clone();
    assert_eq!(
        all,
        vec![
            "NewProxy:web".to_string(),
            "NewProxy:other".to_string(),
            "CloseProxy:web".to_string(),
            "NewProxy:web".to_string()
        ],
        "headers-only reload must re-register exactly the changed proxy once"
    );

    client.request_stop();
    tokio::time::timeout(Duration::from_secs(5), runner)
        .await
        .expect("client did not shut down after request_stop")
        .expect("client run() panicked");
    std::mem::drop(mock);
}

// ---------------------------------------------------------------------------
// Test 2 — behavior-level: the header change reaches the real server's
// vhost route (in-process frps), and the untouched tcp proxy keeps working.
// ---------------------------------------------------------------------------

async fn start_frps_with_vhost(
    bind_port: u16,
    vhost_http_port: u16,
    token: &str,
) -> tokio::task::JoinHandle<()> {
    let cfg = ServerConfig {
        bind_addr: "127.0.0.1".into(),
        bind_port,
        vhost_http_port,
        auth: frp_core::config::AuthServerConfig {
            method: "token".into(),
            token: token.into(),
            ..Default::default()
        },
        allow_port_start: 0,
        allow_port_end: 0,
        transport: frp_core::config::ServerTransportConfig {
            tcp_mux: Some(false),
            ..Default::default()
        },
        ..Default::default()
    };
    let service = frp_server::service::Service::new(cfg, None)
        .await
        .expect("create server service");
    tokio::spawn(async move {
        let _ = service.run().await;
    })
}

#[tokio::test]
async fn reload_headers_only_change_reaches_server_vhost_route() {
    init_tracing();
    let token = "reload-headers-token";
    let server_port = allocate_port();
    let vhost_port = allocate_port();
    let http_backend_port = allocate_port();
    let echo_port = allocate_port();
    let tcp_remote_port = allocate_port();

    // In-process frps with a dedicated vhost HTTP port.
    let _server = start_frps_with_vhost(server_port, vhost_port, token).await;
    let _echo = start_echo_server(echo_port);
    let server_addr: std::net::SocketAddr = format!("127.0.0.1:{server_port}").parse().unwrap();
    wait_for_port(server_addr, Duration::from_secs(5))
        .await
        .expect("server ready");

    // HTTP capture backend (receives the injected request head). Bound
    // before the client starts so a forwarded request can never hit a
    // not-yet-listening backend.
    let (mut http_rx, _backend) = spawn_http_capture_backend(http_backend_port).await;

    // Config file with X-Custom: v1.
    let dir = std::env::temp_dir().join(format!("frp-reload-headers-e2e-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let cfg_path = dir.join("frpc.toml");
    write_config(
        &cfg_path,
        server_port,
        http_backend_port,
        echo_port,
        tcp_remote_port,
        "v1",
    );
    let (cfg, cfg_path_str) = client_config(&cfg_path);
    let client = Arc::new(
        ClientService::new(cfg, Some(cfg_path_str))
            .await
            .expect("create client service"),
    );
    let runner = {
        let client = client.clone();
        tokio::spawn(async move {
            let _ = client.run().await;
        })
    };

    // Wait until the tcp proxy's remote port is bound (both proxies
    // register in one batch, so the vhost route for 'web' is live too).
    let p1_addr: std::net::SocketAddr = format!("127.0.0.1:{tcp_remote_port}").parse().unwrap();
    wait_for_port(p1_addr, Duration::from_secs(15))
        .await
        .expect("initial tcp proxy port ready");

    // First request through the vhost: backend must see X-Custom: v1.
    let _ = send_http_get(vhost_port, HTTP_DOMAIN).await;
    let head_v1 = tokio::time::timeout(ASSERT_TIMEOUT, http_rx.recv())
        .await
        .expect("no request reached the backend (v1)")
        .expect("backend channel closed");
    assert!(
        head_v1.contains("X-Custom: v1"),
        "initial request must carry X-Custom: v1 at the backend: {head_v1}"
    );

    // Headers-only reload: X-Custom v1 -> v2.
    write_config(
        &cfg_path,
        server_port,
        http_backend_port,
        echo_port,
        tcp_remote_port,
        "v2",
    );
    client.request_reload();

    // Poll requests until the backend sees the NEW value. A silently
    // dropped reload would serve X-Custom: v1 forever and time out.
    let mut saw_v2: Option<String> = None;
    for _ in 0..50 {
        let _ = send_http_get(vhost_port, HTTP_DOMAIN).await;
        let head = match tokio::time::timeout(Duration::from_secs(2), http_rx.recv()).await {
            Ok(Some(h)) => h,
            _ => continue,
        };
        if head.contains("X-Custom: v2") {
            saw_v2 = Some(head);
            break;
        }
    }
    let head_v2 = saw_v2.expect(
        "headers-only reload never reached the server vhost route (still serving the old header)",
    );
    assert!(
        !head_v2.contains("X-Custom: v1"),
        "stale X-Custom: v1 after reload: {head_v2}"
    );

    // The untouched tcp proxy still works end-to-end after the reload.
    let mut echo_conn = TcpStream::connect(p1_addr)
        .await
        .expect("connect tcp proxy");
    echo_conn.write_all(b"r3-echo").await.unwrap();
    let mut echoed = [0u8; 7];
    tokio::time::timeout(Duration::from_secs(5), echo_conn.read_exact(&mut echoed))
        .await
        .expect("echo through untouched tcp proxy timed out")
        .expect("echo through untouched tcp proxy failed");
    assert_eq!(&echoed, b"r3-echo", "echo data mismatch after reload");

    client.request_stop();
    tokio::time::timeout(Duration::from_secs(5), runner)
        .await
        .expect("client did not shut down after request_stop")
        .expect("client run() panicked");
    // Server + echo + backend tasks end when the runtime shuts down.
    std::mem::drop(_server);
    std::mem::drop(_echo);
}
