//! F2 regression (audit round 8): health-check registration gate parity
//! with Go frp v0.71.0.
//!
//! Go `client/proxy/proxy_wrapper.go` NewWrapper arms health monitoring only
//! when `HealthCheck.Type != "" && LocalPort > 0`. Plugin proxies have config
//! `local_port == 0` (their real listener lives on 127.0.0.1 at the plugin's
//! own port), so a health-configured plugin proxy is NEVER monitored and
//! registers immediately, like a non-health proxy.
//!
//! Pre-fix the frp-rs client gated registration on `health_check_type != ""`
//! alone: the plugin proxy's registration waited for a first "healthy" probe
//! of its plugin listener — a probe that can never succeed when the plugin
//! does not speak the probe protocol (here: a plain-HTTP GET against the
//! socks5 listener). The proxy stayed unregistered forever.
//!
//! Pin 1 (RED pre-fix): a health-configured PLUGIN proxy (local_port == 0,
//! probe can never succeed) registers immediately — the mock server receives
//! NewProxy without any healthy probe.
//! Pin 2 (unchanged behavior): a health-configured LOCAL-port proxy whose
//! probe target stays unhealthy (silent listener) still does NOT register.

mod common;

use std::sync::Arc;
use std::time::Duration;

use tokio::net::TcpListener;

use frp_client::service::Service as ClientService;
use frp_core::config::{ClientConfig, PluginConfig, ProxyConfig};
use frp_core::msg::{self, FrpMessage};
use frp_core::transport::IoStream;

use common::allocate_port;

/// TCP listener that accepts connections, reads a bit, and sends nothing.
/// An HTTP health probe against it always times out — deterministically
/// unhealthy, no closed-port race.
async fn start_silent_listener() -> u16 {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((mut conn, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                use tokio::io::AsyncReadExt;
                // Hold the connection open, send nothing. The probe gives up
                // after its own timeout and closes; read returns at EOF.
                let mut buf = [0u8; 512];
                let _ = conn.read(&mut buf).await;
            });
        }
    });
    port
}

#[tokio::test]
async fn health_configured_plugin_proxy_registers_without_healthy_probe() {
    common::init_tracing();
    let token = "f2-health-plugin-token";
    let server_port = allocate_port();
    let listener = TcpListener::bind(("127.0.0.1", server_port)).await.unwrap();
    let silent_port = start_silent_listener().await;

    // Mock frps: complete login, then expect registration of the PLUGIN
    // proxy. Answer its NewProxyResp. Then hold a silence window and assert
    // the LOCAL-port health proxy does NOT register while its probe target
    // is unhealthy.
    let (plug_seen_tx, plug_seen_rx) = tokio::sync::oneshot::channel::<()>();
    let mock = tokio::spawn(async move {
        let (conn, _) = listener.accept().await.expect("control conn");
        let mut stream = IoStream::Tcp(conn);
        let login = tokio::time::timeout(Duration::from_secs(10), stream.read_v1_frame())
            .await
            .expect("login timeout")
            .expect("read Login");
        assert!(matches!(login, FrpMessage::Login(_)));
        let login_resp = FrpMessage::LoginResp(msg::LoginResp {
            version: Some(frp_core::VERSION.into()),
            run_id: Some("mock-server-run".into()),
            error: None,
            server_additional_auth_scopes: None,
        });
        stream
            .write_v1_frame(&login_resp)
            .await
            .expect("write LoginResp");
        let enc_key = frp_core::encryption::derive_key(token);
        let mut enc = stream
            .into_encrypted(enc_key)
            .expect("plain test stream is encryptable");

        // Pin 1: the health-configured plugin proxy must register WITHOUT a
        // healthy probe. Pre-fix its registration waited on a monitor whose
        // plain-HTTP probe of the socks5 listener can never succeed — the
        // 8s timeout fires and the proxy never appears.
        let np = tokio::time::timeout(Duration::from_secs(8), enc.read_v1_frame())
            .await
            .expect("pin 1 RED: health-configured plugin proxy (local_port == 0) never registered — registration waits for a first healthy probe of the plugin listener (Go proxy_wrapper.go gates monitoring on LocalPort > 0)")
            .expect("read NewProxy");
        match np {
            FrpMessage::NewProxy(ref m) => {
                assert_eq!(
                    m.proxy_name, "plug",
                    "first registered proxy must be the plugin proxy"
                );
            }
            other => panic!("expected NewProxy(plug), got {other:?}"),
        }
        enc.write_v1_frame(&FrpMessage::NewProxyResp(msg::NewProxyResp {
            proxy_name: "plug".into(),
            remote_addr: None,
            error: None,
        }))
        .await
        .expect("write NewProxyResp");
        let _ = plug_seen_tx.send(());

        // Pin 2: with the plugin proxy registered and the session idle in
        // the message loop, the LOCAL-port health proxy (probe target: the
        // silent listener) must stay unregistered. Probe interval 1s, probe
        // timeout 1s — a 3s window covers three failing ticks. Any frame is
        // a failure (heartbeat is disabled in this client config).
        let late = tokio::time::timeout(Duration::from_secs(3), enc.read_v1_frame()).await;
        match late {
            Err(_) => {}
            Ok(Ok(FrpMessage::NewProxy(ref m))) => {
                panic!(
                    "pin 2 broken: health-configured local-port proxy '{}' registered before a healthy probe",
                    m.proxy_name
                );
            }
            Ok(Ok(other)) => panic!("unexpected frame in absence window: {other:?}"),
            Ok(Err(e)) => panic!("control read failed in absence window: {e}"),
        }
    });

    let client_cfg = ClientConfig {
        server_addr: "127.0.0.1".into(),
        server_port,
        token: token.into(),
        login_fail_exit: false,
        tcp_mux: false,
        tls_enable: false,
        // No heartbeats: the mock's pin-2 silence window must be frame-free.
        heartbeat_interval: 0,
        heartbeat_timeout: 0,
        proxies: vec![
            ProxyConfig {
                name: "plug".into(),
                proxy_type: "tcp".into(),
                // Plugin proxies carry local_port == 0: the plugin's own
                // listener (started in Service::new) is the real target.
                local_port: 0,
                remote_port: 17091,
                plugin: Some(PluginConfig {
                    plugin_type: "socks5".into(),
                    ..Default::default()
                }),
                // A health config that can never probe successfully: the
                // plain-HTTP GET of the health monitor against the socks5
                // listener never gets a 2xx.
                health_check_type: "http".into(),
                health_check_interval_seconds: 1,
                health_check_timeout_seconds: 1,
                health_check_max_failed: 1,
                enabled: true,
                ..Default::default()
            },
            ProxyConfig {
                name: "local".into(),
                proxy_type: "tcp".into(),
                local_ip: "127.0.0.1".into(),
                local_port: silent_port,
                remote_port: 17092,
                health_check_type: "http".into(),
                health_check_interval_seconds: 1,
                health_check_timeout_seconds: 1,
                health_check_max_failed: 1,
                enabled: true,
                ..Default::default()
            },
        ],
        ..Default::default()
    };
    let client = Arc::new(ClientService::new(client_cfg, None).await.unwrap());
    let runner = {
        let client = client.clone();
        tokio::spawn(async move {
            let _ = client.run().await;
        })
    };

    // Pin 1 gate: the plugin proxy must register promptly. 12s > the mock's
    // 8s read timeout, so a pre-fix failure surfaces first as the mock's
    // panic (printed) and then as this timeout.
    let plug_registered = tokio::time::timeout(Duration::from_secs(12), plug_seen_rx)
        .await
        .expect("pin 1 RED: health-configured plugin proxy (local_port 0) never registered (mock saw no NewProxy)");
    assert!(
        plug_registered.is_ok(),
        "mock failed to answer the plugin proxy"
    );

    // Pin 2 window is enforced inside the mock (3s of silence after the
    // plugin proxy's registration); wait a beat past it, then stop.
    tokio::time::sleep(Duration::from_millis(3500)).await;
    client.request_stop();
    tokio::time::timeout(Duration::from_secs(5), runner)
        .await
        .expect("client did not shut down after request_stop")
        .expect("client run() panicked");
    // The mock exits after its pin-2 window; surface any assertion failure
    // inside it (pin 1 pre-fix panic, pin 2 registration, unexpected frame).
    let mock_result = tokio::time::timeout(Duration::from_secs(5), mock)
        .await
        .expect("mock server did not finish");
    mock_result.expect("mock server panicked");
}
