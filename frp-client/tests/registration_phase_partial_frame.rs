//! F10 regression (audit round 8): a partially-consumed control frame must
//! survive the registration-phase timer arms, exactly as the message loop's
//! S3 persisted-read fix (partial_frame_survives_competing_ping_tick.rs)
//! guarantees for its own select.
//!
//! The registration response loop rebuilds a fresh `read_v1_frame` future
//! over the control stream every iteration, and `read_msg` V1 framing is two
//! sequential read_exact calls (9-byte header, then payload). When a
//! registration timer wins between the two reads, the consumed header bytes
//! die with the dropped branch future. Here the competing arm is the 2s
//! visitor-grace timer of a visitor-only client:
//!   t0         mock completes login; client sends NewVisitorConn
//!              (registration phase: only visitors pending → every response
//!              read is bounded by the 2s grace timer);
//!   t0+0.5s    mock writes the 9-byte header of a NewVisitorConnResp; the
//!              client's read consumes it and parks on the payload read —
//!              mid-frame;
//!   t0+2.0s    the 2s grace timer fires mid-frame. Old code dropped the
//!              header bytes with the branch future, drained the visitor as
//!              "assumed registered", and continued the session on a stream
//!              whose next bytes are the frame tail — the message loop then
//!              parses the tail as a fresh header (garbage type/length) →
//!              protocol error → reconnect;
//!   t0+2.5s    mock writes the frame tail. Fixed code completed the frame,
//!              matched the NewVisitorConnResp to the still-pending visitor,
//!              and never reconnects; old code is already misaligned.
//!
//! Heartbeat is enabled (interval 1s, timeout 10s) so an old-code stall in
//! the misaligned read cannot hide behind a parked frame read: the mock
//! Pongs every heartbeat, so a clean session never trips the watchdog, while
//! a corrupted one reconnects within the assertion window.
//!
//! Oracle: exactly one Login (no re-registration) over the whole test.
//! Old code: the frame tail misparses as a garbage header and the session
//! reconnects → a second Login lands at the mock.

mod common;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;

use frp_client::service::Service as ClientService;
use frp_core::config::ClientConfig;
use frp_core::msg::{self, FrpMessage};
use frp_core::transport::IoStream;

use common::allocate_port;

#[tokio::test]
async fn registration_phase_partial_frame_survives_visitor_grace_timer() {
    common::init_tracing();
    let token = "reg-phase-partial-frame-token";
    let server_port = allocate_port();
    let listener = TcpListener::bind(("127.0.0.1", server_port)).await.unwrap();

    let login_resp = FrpMessage::LoginResp(msg::LoginResp {
        version: Some(frp_core::VERSION.into()),
        run_id: Some("mock-server-run".into()),
        error: None,
        server_additional_auth_scopes: None,
    });
    let enc_key = frp_core::encryption::derive_key(token);
    let pong = FrpMessage::Pong(msg::Pong { error: None });

    // V1 frame bytes of a NewVisitorConnResp: 9-byte header + JSON payload.
    let resp = FrpMessage::NewVisitorConnResp(msg::NewVisitorConnResp {
        proxy_name: "srv-vis".into(),
        error: None,
    });
    let type_byte = resp.v1_type_byte();
    let payload = serde_json::to_vec(&resp).expect("encode NewVisitorConnResp");
    let mut frame = Vec::with_capacity(9 + payload.len());
    frame.push(type_byte);
    frame.extend_from_slice(&(payload.len() as u64).to_be_bytes());
    frame.extend_from_slice(&payload);
    assert!(frame.len() > 9, "response frame must have a payload");

    let login_count = Arc::new(AtomicUsize::new(0));
    let count = login_count.clone();
    let mock = tokio::spawn(async move {
        loop {
            let (conn, _) = listener.accept().await.expect("control conn");
            let mut stream = IoStream::Tcp(conn);
            let login = tokio::time::timeout(Duration::from_secs(10), stream.read_v1_frame())
                .await
                .expect("login timeout")
                .expect("read Login");
            assert!(matches!(login, FrpMessage::Login(_)));
            count.fetch_add(1, Ordering::SeqCst);
            stream
                .write_v1_frame(&login_resp)
                .await
                .expect("write LoginResp");
            let mut enc = stream
                .into_encrypted(enc_key)
                .expect("plain test stream is encryptable");

            // Registration: the visitor-only client sends NewVisitorConn and
            // then waits with the 2s grace bound.
            let nvc = tokio::time::timeout(Duration::from_secs(10), enc.read_v1_frame())
                .await
                .expect("NewVisitorConn timeout")
                .expect("read NewVisitorConn");
            assert!(
                matches!(nvc, FrpMessage::NewVisitorConn(_)),
                "expected NewVisitorConn, got {nvc:?}"
            );

            if count.load(Ordering::SeqCst) == 1 {
                // First session: split the response frame across the 2s
                // visitor-grace timer.
                // Chunk 1: the 9-byte frame header only. The client's read
                // consumes it and parks mid-frame on the payload read.
                tokio::time::sleep(Duration::from_millis(500)).await;
                enc.write_all(&frame[..9])
                    .await
                    .expect("write frame header");

                // Hold the frame open across the grace timer (2s bound for a
                // visitor-only registration). The mock writes NOTHING while
                // the frame is open: the parked payload read absorbs every
                // inbound byte until the frame completes.
                tokio::time::sleep(Duration::from_millis(2000)).await;

                // Chunk 2: the frame tail. Fixed code completes the frame
                // (the visitor registers normally); old code lost the header
                // to the grace-timer arm and reads this tail as a fresh
                // header in the message loop → garbage → reconnect.
                enc.write_all(&frame[9..]).await.expect("write frame tail");

                // Keep the session alive with Pongs (heartbeat interval 1s
                // from login success; timeout 10s — far beyond the window).
                // If the client reconnects, the read below errors and the
                // accept loop takes the next connection.
                tokio::time::timeout(Duration::from_secs(6), async {
                    loop {
                        match enc.read_v1_frame().await {
                            Ok(FrpMessage::Ping(_)) => {
                                enc.write_v1_frame(&pong).await.expect("write Pong");
                            }
                            Ok(_) => {}
                            Err(_) => break, // client closed or reconnected
                        }
                    }
                })
                .await
                .ok();
            } else {
                // Reconnect session (old-code path): answer any heartbeats
                // until the client closes this connection at stop.
                let pong = pong.clone();
                tokio::spawn(async move {
                    loop {
                        match enc.read_v1_frame().await {
                            Ok(FrpMessage::Ping(_)) => {
                                enc.write_v1_frame(&pong).await.expect("write Pong");
                            }
                            Ok(_) => {}
                            Err(_) => break,
                        }
                    }
                });
            }
        }
    });

    let client_cfg = ClientConfig {
        server_addr: "127.0.0.1".into(),
        server_port,
        token: token.into(),
        login_fail_exit: false,
        tcp_mux: false,
        tls_enable: false,
        // Heartbeats on (1s): old-code sessions that misalign on the frame
        // tail either reconnect on the garbage parse or stall in the
        // misaligned read — a stall parks the read forever and only the
        // watchdog (mock Pongs nothing back into it, but the watchdog is
        // armed on last_pong = login) would fire after 10s. The mock Pongs
        // every Ping, so a CLEAN session never trips the watchdog; the 6s
        // Pong loop below bounds the wait for the corrupted path.
        heartbeat_interval: 1,
        heartbeat_timeout: 10,
        // A visitor-only client: no proxies, so the registration response
        // loop runs under the 2s visitor-grace timer (no proxy arm, no
        // REGISTRATION_RESPONSE_TIMEOUT).
        proxies: vec![],
        visitors: vec![frp_core::config::VisitorConfig {
            name: "vis1".into(),
            visitor_type: "stcp".into(),
            bind_port: allocate_port() as i32,
            server_name: "srv-vis".into(),
            secret_key: "sk".into(),
            ..Default::default()
        }],
        ..Default::default()
    };
    let client = Arc::new(ClientService::new(client_cfg, None).await.unwrap());
    let runner = {
        let client = client.clone();
        tokio::spawn(async move {
            let _ = client.run().await;
        })
    };

    // Oracle: exactly one Login. Old code loses the frame header to the 2s
    // grace arm; the message loop parses the tail as a garbage header →
    // protocol error → reconnect → a second Login lands at the mock.
    // Window: the split completes at ~2.5s; the corrupted old-code session
    // reconnects within ~1s of the misparse (mock Pongs heartbeats in
    // between); a fixed session stays put. 5s of quiet after the tail is
    // decisive.
    tokio::time::sleep(Duration::from_secs(5)).await;
    assert_eq!(
        login_count.load(Ordering::SeqCst),
        1,
        "client reconnected after the visitor-grace timer won mid-frame: the partial registration read must survive (F10)"
    );

    client.request_stop();
    tokio::time::timeout(Duration::from_secs(5), runner)
        .await
        .expect("client did not shut down after request_stop")
        .expect("client run() panicked");
    assert_eq!(
        login_count.load(Ordering::SeqCst),
        1,
        "client reconnected during the whole session"
    );
    // Mock teardown (round-2 review, audit round 8): the mock is an
    // infinite accept loop, so abort it, then await — a JoinHandle that
    // already panicked reports Panicked even after abort, so any mid-test
    // mock assertion failure fails THIS test instead of vanishing with the
    // runtime at scope end.
    mock.abort();
    match mock.await {
        Err(e) if e.is_cancelled() => {}
        other => panic!("mock task ended abnormally: {other:?}"),
    }
}
