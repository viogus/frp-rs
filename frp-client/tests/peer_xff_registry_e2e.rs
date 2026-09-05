//! M9 / audit-claim R1 e2e pin: the real-tunnel-peer registry must reach the
//! WIRE — a https2http plugin request forwarded through a full frps+frpc
//! tunnel must carry the REAL user IP in `X-Forwarded-For`.
//!
//! Background: the https2http/https2https plugin listener is loopback-bound,
//! so the plugin accept handler's `peer.ip()` is always 127.0.0.1 and an
//! X-Forwarded-For appended from it would lie about the tunnel peer (Go frp
//! http_common.go:116-117 parity — Go calls `SetRemoteAddr(connInfo.SrcAddr)`
//! for these variants only). The real peer address arrives on the frpc side
//! in StartWorkConn (`src_addr`/`src_port`, filled by the frps from the user
//! connection it accepted) and is handed to the plugin via the port-keyed
//! registry (`register_plugin_peer` → `plugin_peer_ip` in
//! frp-client/src/plugin/mod.rs).
//!
//! Every pre-existing plugin test connects STRAIGHT to the plugin's loopback
//! listener, so the registry always misses and the registry-to-wire path
//! (work-conn dial → register → accept-handler take → XFF line) had ZERO e2e
//! coverage — only unit pins in plugin/mod.rs.
//!
//! The trick that makes a registry hit distinguishable from the loopback
//! fallback: the user socket is BOUND to 127.0.0.2 before dialing the frps
//! proxy port (Linux/macOS treat all of 127.0.0.0/8 as loopback). The frps
//! therefore sees src_addr 127.0.0.2 and the backend must receive exactly
//! `X-Forwarded-For: 127.0.0.2`. If the registry were broken the captured
//! head would say `127.0.0.1` (fallback) or carry no XFF line at all — both
//! failure modes are asserted against.

#![cfg(feature = "tls")]

mod common;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpSocket, TcpStream};

use frp_client::service::Service as ClientService;
use frp_core::config::{
    AuthServerConfig, ClientConfig, PluginConfig, ProxyConfig, ServerConfig, ServerTransportConfig,
};
use frp_server::service::Service as ServerService;

use common::{allocate_port, init_tracing, wait_for_port};

/// Generate a self-signed cert/key pair with rcgen (dev-dependency) and write
/// them as PEM files. Returns (cert_path, key_path, cert_der).
fn write_plugin_cert(dir: &tempfile::TempDir) -> (PathBuf, PathBuf, Vec<u8>) {
    let key_pair = rcgen::KeyPair::generate().expect("keypair");
    let params = rcgen::CertificateParams::new(vec!["127.0.0.1".to_string()]).expect("cert params");
    let cert = params.self_signed(&key_pair).expect("self-signed cert");

    let wrap_pem = |label: &str, der: &[u8]| -> String {
        let b64 = frp_core::base64::encode(der);
        let mut out = format!("-----BEGIN {label}-----\n");
        for chunk in b64.as_bytes().chunks(64) {
            out.push_str(std::str::from_utf8(chunk).unwrap());
            out.push('\n');
        }
        out.push_str(&format!("-----END {label}-----\n"));
        out
    };
    let cert_path = dir.path().join("cert.pem");
    let key_path = dir.path().join("key.pem");
    std::fs::write(&cert_path, wrap_pem("CERTIFICATE", cert.der())).unwrap();
    std::fs::write(
        &key_path,
        wrap_pem("PRIVATE KEY", &key_pair.serialize_der()),
    )
    .unwrap();
    (cert_path, key_path, cert.der().to_vec())
}

/// Build a rustls client connector that trusts `cert_der` and offers only
/// ALPN http/1.1 (the plugin runs with `enable_http2 = false`).
fn http1_connector(cert_der: &[u8]) -> tokio_rustls::TlsConnector {
    let mut roots = rustls::RootCertStore::empty();
    roots.add_parsable_certificates([rustls::pki_types::CertificateDer::from(cert_der.to_vec())]);
    let mut config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    tokio_rustls::TlsConnector::from(Arc::new(config))
}

/// Start a plaintext HTTP/1.1 backend that captures each connection's head
/// (read up to the `\r\n\r\n` terminator — a single TCP read could return a
/// truncated head if the plugin's head write ever split across segments) and
/// replies 200 with a small body. One captured string per accepted conn is
/// sent down the returned receiver (the listener task holds the sender for
/// the test's lifetime, so `recv` never returns None — callers use timeouts).
async fn start_capture_backend() -> (SocketAddr, tokio::sync::mpsc::UnboundedReceiver<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(async move {
        while let Ok((mut conn, _)) = listener.accept().await {
            let tx = tx.clone();
            tokio::spawn(async move {
                let mut buf = Vec::new();
                let mut chunk = [0u8; 4096];
                loop {
                    match conn.read(&mut chunk).await {
                        Ok(0) => break,
                        Ok(n) => {
                            buf.extend_from_slice(&chunk[..n]);
                            if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
                let _ = tx.send(String::from_utf8_lossy(&buf).to_string());
                let _ = conn
                    .write_all(b"HTTP/1.0 200 OK\r\nContent-Length: 5\r\n\r\nhello")
                    .await;
                let _ = conn.flush().await;
            });
        }
    });
    (addr, rx)
}

/// End-to-end: https2http plugin behind a full frps+frpc tunnel must append
/// the REAL user IP (as seen by the frps) to X-Forwarded-For.
#[tokio::test]
async fn test_https2http_xff_carries_real_user_ip_through_tunnel() {
    init_tracing();
    let server_port = allocate_port();
    let proxy_port = allocate_port();
    let probe_port = allocate_port();
    let token = "peer-xff-token";

    // 1. Backend capture servers: one for the https2http plugin target, one
    //    for the PROXY-v1 src probe (a plain TCP proxy whose PROXY v1 header
    //    echoes StartWorkConn.src_addr directly to a plaintext backend with
    //    no cross-task registry handoff — it observes what src the frps
    //    actually delivered on the wire).
    let (backend_addr, mut backend_rx) = start_capture_backend().await;
    let (probe_backend_addr, mut probe_backend_rx) = start_capture_backend().await;

    // 2. Plugin cert, self-signed for SAN 127.0.0.1. The tempdir lives until
    //    the end of the test; the plugin read the files at startup.
    let _cert_dir = tempfile::tempdir().unwrap();
    let (cert_path, key_path, cert_der) = write_plugin_cert(&_cert_dir);

    // 3. Plugin proxy config: type tcp + [proxies.plugin] (production frpc
    //    shape for plugin proxies). enable_http2 = false keeps the listener
    //    on ALPN http/1.1 — no h2 machinery in this test.
    let mut plugin_cfg = PluginConfig {
        plugin_type: "https2http".into(),
        local_addr: backend_addr.to_string(),
        ..Default::default()
    };
    plugin_cfg.crt_file = cert_path.to_str().unwrap().to_string();
    plugin_cfg.key_file = key_path.to_str().unwrap().to_string();
    plugin_cfg.enable_http2 = Some(false);

    let proxy_cfg = ProxyConfig {
        name: "xff-plugin".into(),
        proxy_type: "tcp".into(),
        local_ip: "127.0.0.1".into(),
        local_port: backend_addr.port(),
        remote_port: proxy_port,
        use_encryption: false,
        use_compression: false,
        sk: String::new(),
        plugin: Some(plugin_cfg),
        custom_domains: vec![],
        subdomain: String::new(),
        http_user: String::new(),
        http_pwd: String::new(),
        http_password: String::new(),
        locations: vec![],
        host_header_rewrite: String::new(),
        headers: std::collections::HashMap::new(),
        response_headers: std::collections::HashMap::new(),
        route_by_http_user: String::new(),
        allow_users: vec![],
        bandwidth_limit: String::new(),
        bandwidth_limit_mode: String::new(),
        annotations: std::collections::HashMap::new(),
        metas: std::collections::HashMap::new(),
        multiplexer: String::new(),
        group: String::new(),
        group_key: String::new(),
        health_check_type: String::new(),
        health_check_url: String::new(),
        health_check_interval_seconds: 0,
        health_check_timeout_seconds: 0,
        health_check_max_failed: 0,
        virtual_net: String::new(),
        advertise_subnet: String::new(),
        vnet_ip: String::new(),
        vnet_netmask: String::new(),
        vnet_mtu: 1420,
        health_check_http_headers: Vec::new(),
        proxy_protocol_version: String::new(),
        enabled: true,
        disable_assisted_addrs: false,
    };

    // 3b. SRC PROBE — a second plain TCP proxy with proxy_protocol_version =
    //    "v1". Its work-conn task writes a PROXY v1 header straight to the
    //    local backend from the same swc.src_addr the M9 register block
    //    consumes (work_conn.rs, ~30 lines below the register). The backend
    //    captures that header race-free — if the src on the wire is
    //    127.0.0.2, the header must read `PROXY TCP4 127.0.0.2`; anything
    //    else (or a missing header) proves the src delivery itself is broken
    //    and the XFF fallback to 127.0.0.1 needs no further explanation.
    let probe_cfg = ProxyConfig {
        name: "src-probe".into(),
        local_ip: "127.0.0.1".into(),
        local_port: probe_backend_addr.port(),
        remote_port: probe_port,
        plugin: None,
        proxy_protocol_version: "v1".into(),
        ..proxy_cfg.clone()
    };

    // 4. frps in-process (same shape as common/mod.rs `start_frps`, but the
    //    spawned service handle stays in scope for cleanup).
    let server_cfg = ServerConfig {
        bind_addr: "127.0.0.1".into(),
        bind_port: server_port,
        auth: AuthServerConfig {
            method: "token".into(),
            token: token.to_string(),
            ..Default::default()
        },
        // No port restriction in e2e tests — proxy ports can be anywhere.
        allow_port_start: 0,
        allow_port_end: 0,
        transport: ServerTransportConfig {
            tcp_mux: Some(false),
            ..Default::default()
        },
        ..Default::default()
    };
    let server_svc = ServerService::new(server_cfg, None)
        .await
        .expect("create frps");
    let server_handle = tokio::spawn(async move {
        let _ = server_svc.run().await;
    });
    let server_addr: SocketAddr = format!("127.0.0.1:{server_port}").parse().unwrap();
    wait_for_port(server_addr, Duration::from_secs(5))
        .await
        .expect("frps main port did not become ready");

    // 5. frpc in-process. The plugin listener binds inside ClientService::new;
    //    login + NewProxy registration happen once run() starts.
    let client_cfg = ClientConfig {
        server_addr: "127.0.0.1".into(),
        server_port,
        token: token.to_string(),
        login_fail_exit: false,
        pool_count: 2,
        tcp_mux: false,
        tls_enable: false,
        proxies: vec![proxy_cfg, probe_cfg],
        ..Default::default()
    };
    let client_svc = ClientService::new(client_cfg, None)
        .await
        .expect("create frpc");
    let client_handle = tokio::spawn(async move {
        let _ = client_svc.run().await;
    });

    // 6. Readiness: sleep first (the proxy listener + registration follow
    //    login + NewProxyResp), then poll-dial the frps remote port until it
    //    accepts. Each probe is dropped immediately — its empty bridge tears
    //    down on its own (a probe may burn one work conn; tolerable here).
    tokio::time::sleep(Duration::from_millis(1000)).await;
    let proxy_addr: SocketAddr = format!("127.0.0.1:{proxy_port}").parse().unwrap();
    let probe_deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        if TcpStream::connect(proxy_addr).await.is_ok() {
            break;
        }
        assert!(
            tokio::time::Instant::now() < probe_deadline,
            "frps remote port {proxy_port} never accepted a connection"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    // Same readiness poll for the src-probe proxy port — but bound to
    // 127.0.0.2 like every other conn in this test. A dropped readiness conn
    // still gets bridged: the frpc dials the probe backend and writes the
    // PROXY v1 head before the empty user conn tears down, and the backend
    // capture would record that head. Binding 127.0.0.2 keeps every possible
    // captured head identical to the real request's head (no 127.0.0.1
    // contamination to drain around).
    let probe_addr: SocketAddr = format!("127.0.0.1:{probe_port}").parse().unwrap();
    let probe_deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let poll_socket = TcpSocket::new_v4().expect("new_v4 socket");
        let _ = poll_socket.bind("127.0.0.2:0".parse::<SocketAddr>().unwrap());
        if poll_socket.connect(probe_addr).await.is_ok() {
            break;
        }
        assert!(
            tokio::time::Instant::now() < probe_deadline,
            "frps src-probe port {probe_port} never accepted a connection"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    // Let the readiness probes' bridges wind down before the real requests.
    tokio::time::sleep(Duration::from_millis(200)).await;
    // Drain any head captured from the readiness conns above. (With every
    // conn 127.0.0.2-sourced the drain is cosmetic, but it keeps the assert
    // below tied to the real request's head, not the poll's.)
    while probe_backend_rx.try_recv().is_ok() {}

    // 6b. SRC PROBE REQUEST — bound to 127.0.0.2 like the XFF request below.
    // The PROXY v1 head is written by the work-conn task directly from
    // swc.src_addr; asserting its value tells us what the frps actually put
    // on the wire for a 127.0.0.2 user conn.
    let socket = TcpSocket::new_v4().expect("new_v4 socket");
    socket
        .bind("127.0.0.2:0".parse::<SocketAddr>().unwrap())
        .expect("bind probe socket to 127.0.0.2");
    let mut probe_tcp = socket
        .connect(probe_addr)
        .await
        .expect("connect to frps src-probe port");
    probe_tcp
        .write_all(b"GET /probe HTTP/1.1\r\nHost: probe\r\nConnection: close\r\n\r\n")
        .await
        .expect("write probe request");
    probe_tcp.flush().await.expect("flush probe request");
    let mut probe_resp = Vec::new();
    let mut chunk = [0u8; 4096];
    let _ = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            match probe_tcp.read(&mut chunk).await {
                Ok(0) | Err(_) => break,
                Ok(n) => probe_resp.extend_from_slice(&chunk[..n]),
            }
        }
    })
    .await;
    drop(probe_tcp);
    let probe_head = tokio::time::timeout(Duration::from_secs(10), probe_backend_rx.recv())
        .await
        .expect("src-probe backend never captured a head")
        .unwrap_or_default();
    assert!(
        probe_head.starts_with("PROXY TCP4 127.0.0.2"),
        "PROXY v1 head must echo the real src (127.0.0.2), got: {probe_head:?}"
    );

    // 7. THE KEY STEP — four CONCURRENT real requests from distinguishable
    //    source addresses. Binding 127.0.0.x (x >= 2) means the frps sees
    //    src_addr 127.0.0.x (all of 127.0.0.0/8 is local loopback), so a
    //    registry hit produces `X-Forwarded-For: 127.0.0.x` while the
    //    loopback fallback would produce `127.0.0.1` — distinguishable.
    //    Four requests from four sources in one run sharpen the probe: each
    //    conn registers its own key and its own accept-handler take consumes
    //    it, so if the register->take path works every capture must mirror
    //    its own source, while a structural break collapses all four onto
    //    the 127.0.0.1 fallback.
    let sources = ["127.0.0.2", "127.0.0.3", "127.0.0.4", "127.0.0.5"];
    let connector = http1_connector(&cert_der);
    let mut request_tasks = Vec::new();
    for src in sources {
        let connector = connector.clone();
        let src = src.to_string();
        request_tasks.push(tokio::spawn(async move {
            let socket = TcpSocket::new_v4().expect("new_v4 socket");
            socket
                .bind(format!("{src}:0").parse::<SocketAddr>().unwrap())
                .expect("bind user socket to loopback source");
            let tcp = socket
                .connect(proxy_addr)
                .await
                .expect("connect to frps proxy port");
            let server_name = rustls::pki_types::ServerName::try_from("127.0.0.1").unwrap();
            let mut tls = connector
                .connect(server_name, tcp)
                .await
                .expect("TLS handshake through the tunnel to the plugin listener");
            tls.write_all(b"GET /xff HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
                .await
                .expect("write request through tunnel");
            tls.flush().await.expect("flush request");

            // 8. Drain the relayed response (smoke check that the round-trip
            //    completed); the backend reply arrives after it captured the
            //    head.
            let mut resp = Vec::new();
            let mut chunk = [0u8; 4096];
            let _ = tokio::time::timeout(Duration::from_secs(10), async {
                loop {
                    match tls.read(&mut chunk).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => resp.extend_from_slice(&chunk[..n]),
                    }
                }
            })
            .await;
            assert!(
                String::from_utf8_lossy(&resp).contains("hello"),
                "expected the backend 200 body through the relay, got: {:?}",
                String::from_utf8_lossy(&resp)
            );
            drop(tls);
        }));
    }
    for task in request_tasks {
        task.await.expect("request task panicked");
    }

    // 9. Each captured backend head must carry the REAL user IP of the conn
    //    that carried it. The plugin forwards as HTTP/1.1 (Go ReverseProxy
    //    http.DefaultTransport parity — see read_request_and_build_forward
    //    in plugin/mod.rs; audit round-9 B1 aligned frp-rs with Go).
    let mut reqs: Vec<String> = Vec::new();
    for i in 0..sources.len() {
        reqs.push(
            tokio::time::timeout(Duration::from_secs(10), backend_rx.recv())
                .await
                .unwrap_or_else(|_| panic!("backend never captured request #{i}"))
                .unwrap_or_default(),
        );
    }
    for req in &reqs {
        assert!(req.starts_with("GET /xff HTTP/1.1"), "got: {req}");
        assert_eq!(
            req.matches("X-Forwarded-For").count(),
            1,
            "exactly one X-Forwarded-For line (R5 single-line semantics), got: {req}"
        );
    }
    let mut seen_xff: Vec<String> = reqs
        .iter()
        .filter_map(|req| {
            req.lines()
                .find_map(|l| l.strip_prefix("X-Forwarded-For: "))
                .map(|v| v.trim().to_string())
        })
        .collect();
    let mut expected: Vec<String> = sources.iter().map(|s| s.to_string()).collect();
    seen_xff.sort();
    expected.sort();
    assert_eq!(
        seen_xff, expected,
        "each request must carry its own source in X-Forwarded-For; a registry \
         miss collapses every capture onto the 127.0.0.1 loopback fallback"
    );

    // Cleanup: abort the background services (mirrors TestHarness::drop).
    server_handle.abort();
    client_handle.abort();
}
