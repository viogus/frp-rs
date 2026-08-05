//! Regression test for the pipelined-registration visitor-ack ordering bug.
//!
//! The server writes its pool pre-warm ReqWorkConn frames immediately after
//! LoginResp, BEFORE it processes any registration frames, so they always
//! precede every NewProxyResp/NewVisitorConnResp on the wire. The client's
//! registration read loop must NOT FIFO-attribute those pool conns to
//! pending visitors: a visitor whose NewVisitorConn is rejected by the
//! server (named `NewVisitorConnResp{error}`) must be logged as failed, and
//! must NOT be logged as registered.
//!
//! Fails on the old code: the first pool ReqWorkConn was FIFO-attributed to
//! the visitor as a "success ack", its real rejection response then hit the
//! "not in this registration batch" branch and was discarded — the auth
//! failure was silently masked as a successful registration.

mod common;

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use frp_client::service::Service as ClientService;
use frp_core::config::{ClientConfig, ProxyConfig, VisitorConfig};
use frp_server::service::Service as ServerService;

use common::{allocate_port, wait_for_port};

/// A fmt writer that appends every formatted log line to a shared buffer.
#[derive(Clone)]
struct RecordingWriter(Arc<Mutex<String>>);

impl std::io::Write for RecordingWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if let Ok(mut logs) = self.0.lock() {
            logs.push_str(&String::from_utf8_lossy(buf));
        }
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for RecordingWriter {
    type Writer = RecordingWriter;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

#[tokio::test]
async fn rejected_visitor_is_logged_failed_not_registered() {
    let server_port = allocate_port();
    let visitor_port = allocate_port();
    let token = "i2-reject-token";

    // Capture the client's logs: install a thread-local subscriber BEFORE
    // starting anything. The thread-local default takes precedence over any
    // global default other tests installed via common::init_tracing, and the
    // current-thread runtime keeps every spawned task (frps, frpc) on this
    // thread, so all their tracing events land in the buffer.
    let logs: Arc<Mutex<String>> = Arc::new(Mutex::new(String::new()));
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_writer(RecordingWriter(logs.clone()))
        .finish();
    // The guard is !Send but never leaves this thread; it stays alive for
    // the whole test body, past every .await.
    let _subscriber_guard = tracing::subscriber::set_default(subscriber);

    // Start frps in-process (like the other frp-client e2e tests).
    let server_cfg = frp_core::config::ServerConfig {
        bind_addr: "127.0.0.1".into(),
        bind_port: server_port,
        auth: frp_core::config::AuthServerConfig {
            method: "token".into(),
            token: token.into(),
            ..Default::default()
        },
        // No port restriction in e2e tests — proxy ports can be anywhere.
        allow_port_start: 0,
        allow_port_end: 0,
        transport: frp_core::config::ServerTransportConfig {
            tcp_mux: Some(false),
            ..Default::default()
        },
        ..Default::default()
    };
    let server_service = ServerService::new(server_cfg, None)
        .await
        .expect("create server service");
    let _server_handle = tokio::spawn(async move {
        let _ = server_service.run().await;
    });
    let server_addr: SocketAddr = format!("127.0.0.1:{}", server_port).parse().unwrap();
    wait_for_port(server_addr, Duration::from_secs(5))
        .await
        .expect("server port ready");

    // Client: one STCP proxy with a secret_key, and one visitor that uses a
    // DIFFERENT secret_key — the server must reject the NewVisitorConn.
    let client_cfg = ClientConfig {
        server_addr: "127.0.0.1".into(),
        server_port,
        token: token.into(),
        login_fail_exit: false,
        tcp_mux: false,
        tls_enable: false,
        pool_count: 1,
        proxies: vec![ProxyConfig {
            name: "stcp-sec".into(),
            proxy_type: "stcp".into(),
            local_ip: "127.0.0.1".into(),
            local_port: 1, // STCP proxies bind no listener; port unused
            remote_port: 0,
            sk: "correct-secret".into(),
            use_encryption: false,
            use_compression: false,
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
            health_check_http_headers: std::collections::HashMap::new(),
            proxy_protocol_version: String::new(),
            enabled: true,
            disable_assisted_addrs: false,
            plugin: None,
        }],
        visitors: vec![VisitorConfig {
            name: "rejected-visitor".into(),
            visitor_type: "stcp".into(),
            server_name: "stcp-sec".into(),
            secret_key: "wrong-secret".into(),
            bind_addr: "127.0.0.1".into(),
            bind_port: visitor_port as i32,
            ..Default::default()
        }],
        ..Default::default()
    };

    let client_service = ClientService::new(client_cfg, None)
        .await
        .expect("create client service");
    let _client_handle = tokio::spawn(async move {
        let _ = client_service.run().await;
    });

    // The rejection response arrives during the registration phase; the
    // session stays alive afterwards (login_fail_exit = false), so poll the
    // captured log for the failure.
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    let mut failed = false;
    while std::time::Instant::now() < deadline {
        if logs
            .lock()
            .unwrap()
            .contains("Failed to register visitor 'rejected-visitor'")
        {
            failed = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let captured = logs.lock().unwrap().clone();
    assert!(
        failed,
        "expected 'Failed to register visitor' for the rejected visitor; captured client log:\n{}",
        captured
    );

    // Give any (wrong) success attribution a moment to appear, then make
    // sure the visitor was never logged as registered.
    tokio::time::sleep(Duration::from_secs(1)).await;
    let captured = logs.lock().unwrap().clone();
    assert!(
        !captured.contains("Visitor 'rejected-visitor' registered"),
        "rejected visitor must not be logged as registered; captured client log:\n{}",
        captured
    );
}
