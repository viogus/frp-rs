//! F13 regression (audit round 8): a partially-consumed frame on the SUDP
//! data plane must survive the dispatcher select, like the S3 persisted-read
//! fix in the message loop and the F10 fix in the registration phase.
//!
//! `run_sudp_worker` (frp-client/src/visitor.rs) rebuilds its read future
//! (`read_msg_v1` / `read_msg_v2_with_udp_codec`) every loop iteration over a
//! loop-local `BufReader`. V1 framing is two sequential reads (9-byte header,
//! then payload), so when the `send_rx.recv()` arm wins between the two — a
//! local datagram arriving while the server's frame is still in flight — the
//! consumed header bytes die with the dropped branch future. The next
//! iteration reads the frame TAIL as a fresh header (the JSON payload's `{`
//! is an invalid type byte) → protocol error → the tunnel tears down and the
//! dispatcher waits for the next datagram to reconnect — losing the server's
//! response frame entirely. Under bidirectional traffic the loss is
//! systematic for every frame that spans a TCP segmentation boundary while a
//! local datagram is queued.
//!
//! Mock timeline (all on the SUDP data-plane conn):
//!   t0          client dials the tunnel (triggered by datagram d1, written
//!               immediately after NewVisitorConnResp);
//!   t0+250ms    mock writes the 9-byte header of UDPPacket frame "A";
//!               the client consumes it and parks mid-frame on the payload;
//!   t0+500ms    test sends local datagram d2 → the send_rx arm wins the
//!               select while the read is parked. Old code drops the header
//!               with the branch future; the persisted-read fix does not;
//!   t0+~600ms   mock reads d2 off the wire (proof the client's write arm
//!               won mid-frame), then writes the "A" frame tail. Old code
//!               parses the tail as a fresh header → error → tunnel teardown;
//!               fixed code completes frame "A" and delivers it to the local
//!               UDP socket;
//!   t0+1500ms   test sends datagram d3. Fixed code: same tunnel. Old code:
//!               dispatcher reconnects → a second data-plane conn.
//!
//! Oracles: (1) the local UDP socket receives "A" (old code never completes
//! the frame); (2) exactly one data-plane conn over the whole test (old code
//! reconnects on d3). Heartbeat is enabled on the control conn (interval 1s,
//! timeout 10s) and the mock Pongs, so a clean session never trips the
//! control watchdog — reconnects can only come from the data plane.

mod common;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, UdpSocket};

use frp_client::service::Service as ClientService;
use frp_core::config::ClientConfig;
use frp_core::msg::{self, FrpMessage};
use frp_core::transport::IoStream;

use common::allocate_port;

/// Raw V1 frame bytes (9-byte header + JSON payload) of a `UDPPacket`, for
/// split writes: the mock writes `frame[..9]` and `frame[9..]` separately to
/// control the client's read progress.
fn udp_packet_frame(content: &str, dst_port: u16) -> Vec<u8> {
    let m = FrpMessage::UDPPacket(msg::UDPPacket {
        content: content.as_bytes().to_vec(),
        local_addr: None,
        remote_addr: Some(msg::UdpAddr {
            ip: "127.0.0.1".into(),
            port: dst_port,
            zone: String::new(),
        }),
    });
    let type_byte = m.v1_type_byte();
    let payload = serde_json::to_vec(&m).expect("encode UDPPacket");
    let mut frame = Vec::with_capacity(9 + payload.len());
    frame.push(type_byte);
    frame.extend_from_slice(&(payload.len() as u64).to_be_bytes());
    frame.extend_from_slice(&payload);
    frame
}

#[tokio::test]
async fn sudp_worker_partial_frame_survives_local_datagram() {
    common::init_tracing();
    let token = "sudp-partial-frame-token";
    let server_port = allocate_port();
    let listener = TcpListener::bind(("127.0.0.1", server_port)).await.unwrap();
    let client_udp = UdpSocket::bind(("127.0.0.1", 0)).await.unwrap();
    let client_udp_port = client_udp.local_addr().unwrap().port();
    let visitor_port = allocate_port();

    // Frames the mock will send on the data plane. Owned halves: conn tasks
    // are 'static and outlive this scope, so the split must not borrow
    // `frame_a` (that outlives-borrow is exactly what the compiler rejects).
    let frame_a = udp_packet_frame("A", client_udp_port);
    assert!(frame_a.len() > 9, "frame A must have a payload");
    let a_hdr = frame_a[..9].to_vec();
    let a_tail = frame_a[9..].to_vec();

    let login_resp = FrpMessage::LoginResp(msg::LoginResp {
        version: Some(frp_core::VERSION.into()),
        run_id: Some("mock-server-run".into()),
        error: None,
        server_additional_auth_scopes: None,
    });
    let enc_key = frp_core::encryption::derive_key(token);
    let nvc_resp = FrpMessage::NewVisitorConnResp(msg::NewVisitorConnResp {
        proxy_name: "srv-sudp".into(),
        error: None,
    });
    let pong = FrpMessage::Pong(msg::Pong { error: None });

    let login_count = Arc::new(AtomicUsize::new(0));
    // Data-plane connection count: old code reconnects the tunnel on d3.
    let conn_count = Arc::new(AtomicUsize::new(0));
    let ccount = conn_count.clone();
    let visitor_port_c = visitor_port;
    // Signals the "A" header went out. Notify stores the permit if the test's
    // waiter registers late, so either ordering is safe — and it is Clone,
    // which a oneshot Sender is not (per-conn tasks each need a copy).
    let hdr_sent = Arc::new(tokio::sync::Notify::new());
    // Coroutine env: one clone per shared value, moved into the mock task.
    // Copy values (enc_key, ports) are captured by copy directly. The accept
    // loop re-clones from these per connection.
    let lcount_env = login_count.clone();
    let ccount_env = ccount.clone();
    let hdr_sent_env = hdr_sent.clone();
    let login_resp_env = login_resp.clone();
    let nvc_resp_env = nvc_resp.clone();
    let pong_env = pong.clone();
    let a_hdr_env = a_hdr.clone();
    let a_tail_env = a_tail.clone();

    let mock = tokio::spawn(async move {
        loop {
            let (conn, _) = listener.accept().await.expect("accept conn");
            let lcount = lcount_env.clone();
            let ccount = ccount_env.clone();
            let hdr_sent = hdr_sent_env.clone();
            let login_resp = login_resp_env.clone();
            let nvc_resp = nvc_resp_env.clone();
            let pong = pong_env.clone();
            let a_hdr = a_hdr_env.clone();
            let a_tail = a_tail_env.clone();
            tokio::spawn(async move {
                let mut stream = IoStream::Tcp(conn);
                let first = tokio::time::timeout(Duration::from_secs(10), stream.read_v1_frame())
                    .await
                    .expect("first-frame timeout")
                    .expect("read first frame");
                match first {
                    FrpMessage::Login(_) => {
                        lcount.fetch_add(1, Ordering::SeqCst);
                        stream
                            .write_v1_frame(&login_resp)
                            .await
                            .expect("write LoginResp");
                        let mut enc = stream
                            .into_encrypted(enc_key)
                            .expect("plain test stream is encryptable");
                        // Control conn: Pong every heartbeat until the
                        // client closes at stop.
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
                    FrpMessage::NewVisitorConn(_) => {
                        stream
                            .write_v1_frame(&nvc_resp)
                            .await
                            .expect("write NewVisitorConnResp");
                        // The client forwards the triggering datagram (d1)
                        // immediately after the resp; consume it BEFORE
                        // counting so the test's d1-spam loop cannot observe
                        // a connection that has not consumed its trigger yet.
                        let _d1 =
                            tokio::time::timeout(Duration::from_secs(10), stream.read_v1_frame())
                                .await
                                .expect("d1 timeout")
                                .expect("read d1");
                        let conn_no = ccount.fetch_add(1, Ordering::SeqCst) + 1;
                        if conn_no == 1 {
                            // Session 1 (fixed-code session): the split-frame
                            // scenario. d1 already proves the tunnel is up.
                            tokio::time::sleep(Duration::from_millis(250)).await;
                            // Header only: the client's read consumes it and
                            // parks mid-frame on the payload read.
                            stream
                                .write_all(&a_hdr)
                                .await
                                .expect("write frame A header");
                            hdr_sent.notify_one();
                            // Read the REAL d2 off the wire, content-checked:
                            // stray d1 retries from the test's connect spam
                            // may sit queued. d2 proves the client's send_rx
                            // arm won the select while its read was parked
                            // mid-frame — the loss moment for old code. (Old
                            // code's read never completes; a timeout here
                            // means the pin schedule failed, not the code.)
                            tokio::time::timeout(Duration::from_secs(5), async {
                                loop {
                                    match stream.read_v1_frame().await {
                                        Ok(FrpMessage::UDPPacket(p))
                                            if String::from_utf8_lossy(&p.content) == "d2" =>
                                        {
                                            return;
                                        }
                                        Ok(_) => continue,
                                        Err(e) => panic!("mock read error waiting for d2: {e}"),
                                    }
                                }
                            })
                            .await
                            .expect("d2 timeout — test schedule broken");
                            // Frame tail: fixed code completes frame A; old
                            // code reads this as a fresh header → invalid
                            // type byte `{` → error → tunnel teardown.
                            stream.write_all(&a_tail).await.expect("write frame A tail");
                            // Hold the conn open: fixed code serves d3 on it.
                            // Old code already broke on the tail misparse;
                            // the dispatcher waits for the next datagram.
                            let _ = tokio::time::timeout(Duration::from_secs(6), async {
                                while stream.read_v1_frame().await.is_ok() {}
                            })
                            .await;
                        } else {
                            // Reconnect session (old-code path): hold until
                            // the client closes.
                            let _ = tokio::time::timeout(Duration::from_secs(6), async {
                                while stream.read_v1_frame().await.is_ok() {}
                            })
                            .await;
                        }
                    }
                    other => panic!("unexpected first frame on mock conn: {other:?}"),
                }
            });
        }
    });

    let client_cfg = ClientConfig {
        server_addr: "127.0.0.1".into(),
        server_port,
        token: token.into(),
        login_fail_exit: false,
        tcp_mux: false,
        tls_enable: false,
        // Heartbeats on: the mock Pongs, so control-side reconnects cannot
        // fake a data-plane reconnect.
        heartbeat_interval: 1,
        heartbeat_timeout: 10,
        proxies: vec![],
        visitors: vec![frp_core::config::VisitorConfig {
            name: "svis".into(),
            visitor_type: "sudp".into(),
            bind_addr: "127.0.0.1".into(),
            bind_port: visitor_port_c as i32,
            server_name: "srv-sudp".into(),
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

    // d1: trigger the lazy tunnel. Registration (login + visitor resp) can
    // outlast a single fire-and-forget datagram on a loaded host, so spam d1
    // until the mock reports a data-plane conn that has already consumed its
    // trigger (d1 is content-dropped by the mock, never echoed, and stray
    // retries are ignored by the d2 content check — see the mock above).
    let d1_deadline = tokio::time::Instant::now() + Duration::from_secs(12);
    loop {
        let _ = client_udp
            .send_to(b"d1", ("127.0.0.1", visitor_port))
            .await
            .expect("send d1");
        if conn_count.load(Ordering::SeqCst) >= 1 {
            break;
        }
        assert!(
            tokio::time::Instant::now() < d1_deadline,
            "SUDP tunnel never came up ({} data-plane conns after 12s)",
            conn_count.load(Ordering::SeqCst)
        );
        tokio::time::sleep(Duration::from_millis(150)).await;
    }

    // Mock wrote the "A" header; wait a beat for the client to consume it
    // (localhost), then send d2 — the datagram that must NOT kill the
    // mid-frame read.
    tokio::time::timeout(Duration::from_secs(5), hdr_sent.notified())
        .await
        .expect("mock never wrote the frame header");
    tokio::time::sleep(Duration::from_millis(250)).await;
    client_udp
        .send_to(b"d2", ("127.0.0.1", visitor_port))
        .await
        .expect("send d2");

    // Oracle 1: frame "A" completes and reaches the local UDP socket. Old
    // code never delivers it — the header died with the dropped read future.
    let got_a = tokio::time::timeout(Duration::from_secs(4), async {
        let mut buf = [0u8; 65535];
        loop {
            let (n, _) = client_udp
                .recv_from(&mut buf)
                .await
                .expect("recv from visitor");
            let content = String::from_utf8_lossy(&buf[..n]).into_owned();
            if content == "A" {
                return;
            }
            // d1/d2 are not echoed by the mock; any other content is
            // unexpected but keep waiting for "A" until the deadline.
            debug_assert!(content.is_empty(), "unexpected datagram: {content}");
        }
    })
    .await;
    assert!(
        got_a.is_ok(),
        "F13 RED: frame 'A' never completed — a local datagram mid-frame killed the partial read (send_rx arm dropped the read future between header and payload): {}",
        match got_a {
            Err(e) => e.to_string(),
            Ok(_) => unreachable!(),
        }
    );

    // d3: old code reconnects the tunnel here (the misparsed tail broke the
    // worker); fixed code stays on the one session.
    tokio::time::sleep(Duration::from_millis(700)).await;
    client_udp
        .send_to(b"d3", ("127.0.0.1", visitor_port))
        .await
        .expect("send d3");
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert_eq!(
        conn_count.load(Ordering::SeqCst),
        1,
        "F13 RED: the tunnel reconnected after a datagram won mid-frame — the partial data-plane read must survive (saw {} data-plane conns)",
        conn_count.load(Ordering::SeqCst)
    );

    client.request_stop();
    tokio::time::timeout(Duration::from_secs(5), runner)
        .await
        .expect("client did not shut down after request_stop")
        .expect("client run() panicked");
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
