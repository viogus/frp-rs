//! R2 P2 regression: a stop must be observed during the registration **write**
//! phase, not only in the response-read loop. `register_proxies` writes the
//! pipelined `NewProxy` frames with `write_v1_frame(...).await`; a peer that
//! answers LoginResp and then stops reading fills the TCP send/receive
//! windows, so a write blocks indefinitely once the batch no longer fits.
//! Without a stop arm around the write, `request_stop()` is not seen until the
//! (never-arriving) response phase, wedging `run()` past the old 30s
//! registration timeout.
//!
//! The mock forces the wedge deterministically: the listener has a 4 KiB
//! receive buffer and the client a 4 KiB send buffer, and the batch is large
//! enough (2000 padded `NewProxy` frames, each just under the 10 KiB V1 frame
//! limit, ~16 MiB total) that it cannot be buffered; after LoginResp the mock
//! stops reading.
//! The token is then cancelled while a write is blocked.
//!
//! Oracle: `run()` returns `Ok(())` within ~2s of `request_stop()` (RED on
//! the commit before the write arm: the write never completes).

mod common;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::TcpSocket;
use tokio::sync::oneshot;

use frp_client::service::Service as ClientService;
use frp_core::config::{ClientConfig, ProxyConfig};
use frp_core::msg::FrpMessage;
use frp_core::transport::IoStream;

use common::allocate_port;

/// Padding per proxy, kept under the 10 KiB V1 frame limit (a single frame
/// must stay <= `V1_MAX_MSG_LENGTH`). 2000 such frames (~16 MiB) exceed even
/// the maximum TCP send+receive buffers (Linux/macOS autotune caps are a few
/// MiB per side), so the batch must block partway through once the mock stops
/// reading.
const META_BYTES: usize = 8_000;
const PROXY_COUNT: usize = 2_000;

#[tokio::test]
async fn stop_during_registration_write_exits_promptly() {
    common::init_tracing();
    let token = "stop-during-registration-write-token";
    let server_port = allocate_port();

    let socket = TcpSocket::new_v4().expect("create tcp socket");
    socket
        .set_recv_buffer_size(4096)
        .expect("set mock receive buffer");
    socket
        .bind(std::net::SocketAddr::from(([127, 0, 0, 1], server_port)))
        .expect("bind mock listener");
    let listener = socket.listen(64).expect("listen");

    let (login_resp_tx, login_resp_rx) = oneshot::channel::<()>();
    let mock = tokio::spawn(async move {
        let (conn, _) = listener.accept().await.expect("control conn");
        let mut stream = IoStream::Tcp(conn);
        let login = tokio::time::timeout(Duration::from_secs(10), stream.read_v1_frame())
            .await
            .expect("login timeout")
            .expect("read Login");
        assert!(matches!(login, FrpMessage::Login(_)));
        let login_resp = FrpMessage::LoginResp(frp_core::msg::LoginResp {
            version: Some(frp_core::VERSION.into()),
            run_id: Some("mock-server-run".into()),
            error: None,
            server_additional_auth_scopes: None,
        });
        stream
            .write_v1_frame(&login_resp)
            .await
            .expect("write LoginResp");
        let _ = login_resp_tx.send(());
        // Never read the encrypted NewProxy frame(s): the client's next
        // write fills the small windows and blocks. Hold the connection open.
        tokio::time::sleep(Duration::from_secs(30)).await;
    });

    let client_cfg = ClientConfig {
        server_addr: "127.0.0.1".into(),
        server_port,
        token: token.into(),
        login_fail_exit: false,
        tcp_mux: false,
        tls_enable: false,
        // Force the write to block once the mock stops reading.
        tcp_send_buffer_size: 4096,
        heartbeat_interval: 1,
        // Longer than the test: only the stop token can end the wait.
        heartbeat_timeout: 30,
        proxies: (0..PROXY_COUNT)
            .map(|i| ProxyConfig {
                name: format!("p{i}"),
                proxy_type: "tcp".into(),
                local_ip: "127.0.0.1".into(),
                local_port: 8080,
                remote_port: 8081 + i as u16,
                enabled: true,
                metas: HashMap::from([("pad".to_string(), "x".repeat(META_BYTES))]),
                ..Default::default()
            })
            .collect(),
        ..Default::default()
    };
    let client = Arc::new(ClientService::new(client_cfg, None).await.unwrap());

    let stopper = {
        let client = client.clone();
        tokio::spawn(async move {
            let _ = login_resp_rx.await;
            // Let the client build + enter the first NewProxy write; the
            // frame cannot fit the forced ~4 KiB windows, so the write is
            // blocked when the stop lands.
            tokio::time::sleep(Duration::from_millis(200)).await;
            client.request_stop();
        })
    };

    let stopped_at = std::time::Instant::now();
    tokio::time::timeout(Duration::from_secs(2), client.run())
        .await
        .expect(
            "run() did not exit promptly after a stop during the registration write phase \
             (the NewProxy write arm must race the stop token, not just the response read)",
        )
        .expect("a stop during registration is the clean-stop contract (`Ok(())`)");
    assert!(
        stopped_at.elapsed() < Duration::from_secs(2),
        "run() exit was not prompt"
    );

    stopper.await.expect("stopper task panicked");
    mock.abort();
    match mock.await {
        Err(e) if e.is_cancelled() => {}
        other => panic!("mock task ended abnormally: {other:?}"),
    }
}
