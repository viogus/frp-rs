//! Audit finding S3 (HIGH) regression: the client main control message loop
//! must not lose a partially-consumed control frame when a competing select
//! arm wins mid-frame.
//!
//! The old loop created a fresh `read_msg(&mut reader, ctx.v2)` future every
//! select iteration, and `read_msg` V1 framing performs TWO sequential
//! `read_exact` calls (9-byte header, then payload). When a competing arm won
//! between the two reads, the consumed header bytes died with the dropped
//! branch future — the next iteration parsed the frame tail as a fresh header
//! (garbage type/length → protocol error → LoopExit::Reconnect → reconnect
//! churn under a slow-dribbling peer). Exact client-side mirror of the server
//! round-14 fix + `partial_frame_survives_competing_internal_message`
//! (frp-server/src/control/mod.rs); this test is its client analog.
//!
//! The competing arm here is the client's OWN heartbeat ping tick
//! (heartbeat_interval = 1s): it is always live in the message loop and needs
//! no harness plumbing to trigger. Timeline:
//!   t0         mock completes login + registration (NewProxyResp);
//!   t0+0.5s    mock writes the 9-byte header of a server Ping frame; the
//!              client's read consumes the header and parks on the payload
//!              read — mid-frame;
//!   t0+1s,+2s  client heartbeat ticks win select rounds mid-frame (the
//!              read is Pending, only the tick is Ready). Old code dropped
//!              the header bytes with the branch future; the persisted
//!              future (fix) retains them;
//!   t0+2.8s    mock writes the frame tail. Fixed code completes the frame,
//!              parses the Ping and replies Pong. Old code (header lost)
//!              reads the short tail as a fresh header and stalls — no Pong
//!              ever comes, and no re-login happens either.
//!
//! Determinism: heartbeat ticks are anchored ~1s apart from the session
//! start, and the mid-frame window [t0+0.5s, t0+2.8s] spans 2.3s, so at
//! least one (usually two) ticks fire strictly inside it — the read is
//! provably mid-frame (header consumed, payload absent) when they win.
//! The mock writes NOTHING while the frame is open: the parked payload
//! read absorbs every inbound byte until the frame completes, so any
//! mid-window write (e.g. a Pong reply to the client's heartbeat) would
//! corrupt the Ping payload — the corruption the first draft of this test
//! produced, observed as "invalid type: integer `4`" (a Pong frame's type
//! byte 0x34 = ASCII '4' led the payload). Pongs are unneeded for liveness:
//! the watchdog fires only after heartbeat_timeout (10s) of silence, far
//! beyond this window.
//!
//! Oracles (both red on the old code, green on the fix):
//!   1. the client's Pong reply to the split Ping must arrive (old code:
//!      the Ping was destroyed — the tail is misparsed as a fresh header
//!      and stalls, so no Pong ever comes; the wait times out);
//!   2. exactly one Login total (guards the other old-code failure shape,
//!      a fast reconnect after a garbage frame parse).

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
async fn partial_control_frame_survives_competing_ping_tick() {
    common::init_tracing();
    let token = "partial-frame-ping-tick-token";
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

    // V1 frame bytes of a server Ping: type byte + 8-byte BE length + JSON.
    let ping_msg = FrpMessage::Ping(msg::Ping {
        privilege_key: None,
        timestamp: None,
    });
    let type_byte = ping_msg.v1_type_byte();
    let payload = serde_json::to_vec(&ping_msg).expect("encode Ping");
    let mut frame = Vec::with_capacity(9 + payload.len());
    frame.push(type_byte);
    frame.extend_from_slice(&(payload.len() as u64).to_be_bytes());
    frame.extend_from_slice(&payload);
    let frame_len = frame.len();

    // The header/tail split must not land on a frame boundary the mock's
    // own writes would coalesce: the mock writes the two chunks 2.3s apart,
    // so the client's two read_exact calls can never see both at once.
    assert!(frame_len > 9, "Ping frame must have a payload");

    // (pong_seen) fires when the client's reply Pong to the split Ping
    // arrives — the frame parsed end to end.
    let (pong_seen_tx, pong_seen_rx) = tokio::sync::oneshot::channel::<()>();
    // Option + take: the send site sits inside the mock's per-connection
    // accept loop (which iterates on reconnect), and Sender::send consumes
    // the sender — take() reinitializes the slot to None so the move is
    // single-shot across loop iterations.
    let mut pong_seen_tx = Some(pong_seen_tx);
    let login_count = Arc::new(AtomicUsize::new(0));
    let count = login_count.clone();
    let mock = tokio::spawn(async move {
        let mut first_conn = true;
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

            // Complete registration so the client settles into the message
            // loop (the loop under test).
            let np = tokio::time::timeout(Duration::from_secs(10), enc.read_v1_frame())
                .await
                .expect("NewProxy timeout")
                .expect("read NewProxy");
            assert!(
                matches!(np, FrpMessage::NewProxy(_)),
                "expected NewProxy, got {np:?}"
            );
            enc.write_v1_frame(&FrpMessage::NewProxyResp(msg::NewProxyResp {
                proxy_name: "p1".into(),
                remote_addr: Some("127.0.0.1:8081".into()),
                error: None,
            }))
            .await
            .expect("write NewProxyResp");

            if first_conn {
                first_conn = false;
                // Chunk 1: the 9-byte frame header only. The client's read
                // consumes it and parks mid-frame on the payload read.
                tokio::time::sleep(Duration::from_millis(500)).await;
                enc.write_all(&frame[..9])
                    .await
                    .expect("write frame header");

                // Hold the frame open across at least one client heartbeat
                // tick (the competing arm; 1s cadence from the loop start,
                // so ticks land inside this 2.3s window). The mock writes
                // NOTHING while the frame is open: the client's parked
                // payload read absorbs every inbound byte until the frame
                // completes, so any mid-window Pong reply would corrupt the
                // Ping payload (a Pong frame's type byte 0x34 parses as
                // JSON `4`) — observed as a flaky red on fixed code. Pongs
                // are not needed to keep the client alive here: its
                // watchdog fires only after heartbeat_timeout (10s) of
                // silence, far beyond this ~2.3s window.
                tokio::time::sleep(Duration::from_millis(2300)).await;

                // Chunk 2: the frame tail. Fixed code completes the frame,
                // parses the Ping and replies Pong; old code (header lost to
                // the mid-frame tick) reads the 2-byte tail as a fresh
                // header and stalls, never replying.
                enc.write_all(&frame[9..]).await.expect("write frame tail");

                // Expect the client's Pong reply (the oracle that the Ping
                // survived the interrupted read). Keep Ponging heartbeats
                // so the watchdog cannot fire during the wait.
                let pong_deadline = tokio::time::sleep(Duration::from_secs(6));
                tokio::pin!(pong_deadline);
                let mut replied = false;
                loop {
                    tokio::select! {
                        r = enc.read_v1_frame() => {
                            match r {
                                Ok(FrpMessage::Ping(_)) => {
                                    enc.write_v1_frame(&pong).await.expect("write Pong");
                                }
                                Ok(FrpMessage::Pong(_)) => {
                                    replied = true;
                                    break;
                                }
                                Ok(_) => {}
                                Err(_) => break, // client closed
                            }
                        }
                        _ = &mut pong_deadline => break,
                    }
                }
                if replied {
                    // The oracle: the client answered the interrupted Ping
                    // with a Pong. Signal before the drain loop.
                    if let Some(tx) = pong_seen_tx.take() {
                        let _ = tx.send(());
                    }
                    // Drain: keep the session alive (Pong heartbeats) until
                    // the test stops the client, then fall through to the
                    // accept loop (a buggy reconnect would arrive there).
                    loop {
                        match enc.read_v1_frame().await {
                            Ok(FrpMessage::Ping(_)) => {
                                enc.write_v1_frame(&pong).await.expect("write Pong");
                            }
                            Ok(_) => {}
                            Err(_) => break,
                        }
                    }
                }
                // No Pong reply: fall through to the accept loop — old code
                // reconnects (Login #2) and the login_count assertion fails.
            } else {
                // Reconnect session (old-code path): complete registration,
                // then drain silently until the client closes this
                // connection at stop.
                tokio::spawn(async move { while enc.read_v1_frame().await.is_ok() {} });
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
        // The 1s heartbeat ping tick is the competing select arm that wins
        // mid-frame. The 10s timeout keeps the watchdog far outside the
        // ~2.3s mid-frame window (the mock Pongs every heartbeat anyway).
        heartbeat_interval: 1,
        heartbeat_timeout: 10,
        proxies: vec![frp_core::config::ProxyConfig {
            name: "p1".into(),
            proxy_type: "tcp".into(),
            local_ip: "127.0.0.1".into(),
            local_port: 8080,
            remote_port: 8081,
            enabled: true,
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

    // Oracle 1: the client must parse the interrupted Ping and reply Pong.
    // Old code destroyed the Ping with the dropped mid-frame read — no
    // Pong ever arrives and this times out.
    tokio::time::timeout(Duration::from_secs(7), pong_seen_rx)
        .await
        .expect("client never replied Pong to the split-frame Ping: the mid-frame partial read was lost (S3)")
        .expect("mock task ended before signaling the Pong");

    // Oracle 2: no reconnect — exactly one Login throughout. Old code
    // parses the frame tail as a garbage header → protocol error →
    // LoopExit::Reconnect → a second Login lands at the mock.
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert_eq!(
        login_count.load(Ordering::SeqCst),
        1,
        "client reconnected after a mid-frame competing arm: the partial read must survive (S3)"
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
    // The mock's accept loop ends when the listener is dropped at runtime
    // shutdown; detach it explicitly for the let_underscore lint.
    std::mem::drop(mock);
}
