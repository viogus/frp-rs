//! Yamux work-connection validation chain (control/mod.rs yamux accept
//! path). With tcp_mux (yamux) enabled, work connections arrive as NEW
//! yamux streams on the client's control session and must be validated
//! exactly like standalone TCP work connections — this was a real prior
//! auth-bypass bug class (yamux streams skipped NewWorkConn verification).
//!
//! Each invalid stream must be REJECTED by the server: a wrong run_id
//! (control/mod.rs run_id mismatch) or a bad privilege_key
//! (validate_new_work_conn_auth) gets a StartWorkConn error frame written
//! back before the stream drops (round-11 F2 — Go parity:
//! server/service.go:512-522 writes StartWorkConn{Error: "invalid
//! NewWorkConn"} then closes). An unexpected message type (Login) is an
//! accept-loop shape error, dropped with no reply. A stream the server
//! accepted would be pooled (kept OPEN); a rejected stream is closed.

mod common;

use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::AsyncReadExt;

use common::{
    allocate_port, login_with_test_token, start_test_server, start_test_server_tcpmux_on,
    test_auth_cfg, TEST_TOKEN,
};
use frp_core::auth;
use frp_core::config::ServerConfig;
use frp_core::encryption;
use frp_core::msg::{self, FrpMessage};
use frp_core::mux;
use frp_core::protocol::{read_msg_v1, write_msg_v1};
use frp_core::transport::IoStream;

/// Log in over a yamux control stream (V1, tcp_mux ON): dial, wrap in
/// yamux, open the control stream, send Login, read LoginResp. Returns the
/// encrypted control stream, the yamux session (for opening work streams),
/// and the run_id.
///
/// NOTE: the control stream is NOT silent right after login — the server
/// sends `pool_count` ReqWorkConn pre-warming requests immediately after
/// LoginResp (Go control.go:690; the login below uses 1, the production
/// frpc default — the old `capped_pool_count` floor that gave pool_count 0
/// one prewarm was removed in round-8 F3, Go clamps with
/// `min(PoolCount, MaxPoolCount)` only). This helper drains it, so callers
/// can assert silence afterwards.
async fn yamux_login(addr: SocketAddr) -> (IoStream, mux::YamuxSession, String) {
    let tcp = tokio::net::TcpStream::connect(addr)
        .await
        .expect("connect to server");
    let (control_yamux, session) = mux::client_mux(tcp, &mux::TcpMuxConfig::default())
        .await
        .expect("yamux client init");
    let mut control = IoStream::Yamux(control_yamux);

    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let key = auth::generate_token(TEST_TOKEN, ts);
    let login = FrpMessage::Login(Box::new(msg::Login {
        version: Some(frp_core::VERSION.into()),
        hostname: Some("yamux-auth-test".into()),
        os: Some(std::env::consts::OS.into()),
        arch: Some(std::env::consts::ARCH.into()),
        user: None,
        run_id: None,
        client_id: None,
        pool_count: Some(1),
        timestamp: Some(ts),
        privilege_key: Some(key),
        metas: None,
        client_spec: None,
        multiplexer: Some("yamux".into()),
    }));
    write_msg_v1(&mut control, &login)
        .await
        .expect("send Login");

    let run_id = match read_msg_v1(&mut control).await.expect("read LoginResp") {
        FrpMessage::LoginResp(resp) => {
            assert!(resp.error.is_none(), "login failed: {:?}", resp.error);
            resp.run_id.expect("run_id")
        }
        other => panic!("expected LoginResp, got {:?}", other.v1_type_byte()),
    };

    // V1 wraps the control stream in AES-128-CFB after LoginResp (matching
    // the server); the pre-warm ReqWorkConn arrives through the encrypted
    // writer, so drain it here (see the doc comment above).
    let mut control = control
        .into_encrypted(encryption::derive_key(TEST_TOKEN))
        .expect("wrap control in encryption");
    let warm = tokio::time::timeout(Duration::from_secs(2), read_msg_v1(&mut control))
        .await
        .expect("pre-warm ReqWorkConn must arrive after LoginResp")
        .expect("read pre-warm ReqWorkConn");
    match warm {
        FrpMessage::ReqWorkConn(_) => {}
        other => panic!(
            "expected pre-warm ReqWorkConn after login, got type {}",
            other.v1_type_byte(),
        ),
    }
    (control, session, run_id)
}

/// Assert the server REJECTS the yamux stream with a StartWorkConn error
/// frame (round-11 F2, Go parity) and then closes it: the first read is the
/// rejection frame, the second read is EOF (Ok(0)) or an error (RST) within
/// 2s. The callers below run the default `detailed_errors_to_client = true`
/// and pass the full Go-style detail text; under
/// `detailed_errors_to_client = false` the same rejection collapses to the
/// generic "invalid NewWorkConn" summary (proxy_ops::err_msg) — exercised by
/// test_pool_full_rejection_detailed_and_generic.
async fn assert_stream_rejected(mut io: IoStream, what: &str, expected: &str) {
    let frame = tokio::time::timeout(Duration::from_secs(2), read_msg_v1(&mut io))
        .await
        .unwrap_or_else(|_| panic!("{what}: rejection StartWorkConn frame timed out"))
        .unwrap_or_else(|e| panic!("{what}: read of rejection frame errored: {e}"));
    match frame {
        FrpMessage::StartWorkConn(swc) => {
            // The test config uses default `detailed_errors_to_client =
            // true`, so the rejection carries the full Go-style detail.
            assert_eq!(
                swc.error.as_deref(),
                Some(expected),
                "{what}: rejection error text"
            );
        }
        other => panic!(
            "{what}: expected StartWorkConn rejection, got type {}",
            other.v1_type_byte()
        ),
    }
    let mut buf = [0u8; 64];
    match tokio::time::timeout(Duration::from_secs(2), io.read(&mut buf)).await {
        Ok(Ok(0)) => {}
        Ok(Ok(n)) => panic!("{what}: expected EOF after rejection frame, got {n} bytes"),
        Ok(Err(_)) => {} // RST is also a valid close
        Err(_) => panic!("{what}: stream was NOT closed after the rejection frame"),
    }
}

/// Assert the server DROPS the yamux stream with no reply (the Login-frame
/// accept-shape error): EOF (Ok(0), clean FIN) or an error (RST) within 2s.
/// A timeout — the stream still open — means the server pooled/accepted it.
async fn assert_stream_closed(mut io: IoStream, what: &str) {
    let mut buf = [0u8; 64];
    match tokio::time::timeout(Duration::from_secs(2), io.read(&mut buf)).await {
        Ok(Ok(0)) => {}
        Ok(Ok(n)) => panic!("{what}: expected EOF, got {n} bytes"),
        Ok(Err(_)) => {} // RST is also a valid close
        Err(_) => panic!("{what}: stream was NOT closed by the server (still open / pooled)"),
    }
}

/// Open a fresh yamux stream on `session` and write one message on it.
async fn open_and_write(session: &mux::YamuxSession, msg: &FrpMessage) -> IoStream {
    let stream = session.open_stream().await.expect("open yamux stream");
    let mut io = IoStream::Yamux(stream);
    write_msg_v1(&mut io, msg)
        .await
        .expect("write message on yamux stream");
    io
}

/// The validation chain on yamux work streams:
/// (a) wrong run_id, (b) bad privilege_key — each rejected with a
/// StartWorkConn error frame (F2) and dropped; (c) unexpected message type
/// (Login) — dropped with no reply. A subsequent VALID NewWorkConn must
/// still be accepted (pooled, i.e. kept open), proving the rejections were
/// validation, not a broken yamux accept path.
#[tokio::test]
async fn test_yamux_work_conn_validation_drops_bad_streams() {
    let bind_port = allocate_port();
    let cfg = ServerConfig {
        bind_addr: "127.0.0.1".into(),
        bind_port,
        auth: test_auth_cfg(),
        ..Default::default()
    };
    let (_handle, _) = start_test_server_tcpmux_on(cfg).await;
    let addr: SocketAddr = format!("127.0.0.1:{bind_port}").parse().unwrap();

    let (mut control, session, run_id) = yamux_login(addr).await;

    // (a) wrong run_id → StartWorkConn error frame, then dropped.
    let io = open_and_write(
        &session,
        &FrpMessage::NewWorkConn(msg::NewWorkConn {
            run_id: Some("wrong-run-id".into()),
            timestamp: None,
            privilege_key: None,
        }),
    )
    .await;
    assert_stream_rejected(
        io,
        "wrong run_id",
        "no client control found for run id [wrong-run-id]",
    )
    .await;

    // (b) correct run_id but bad privilege_key → rejection frame, then dropped.
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let io = open_and_write(
        &session,
        &FrpMessage::NewWorkConn(msg::NewWorkConn {
            run_id: Some(run_id.clone()),
            timestamp: Some(ts),
            privilege_key: Some("bogus-key".into()),
        }),
    )
    .await;
    assert_stream_rejected(
        io,
        "bad privilege_key",
        "token in login doesn't match token from configuration",
    )
    .await;

    // (c) unexpected message type (a Login frame) → dropped, no reply.
    let io = open_and_write(
        &session,
        &FrpMessage::Login(Box::new(msg::Login {
            version: Some(frp_core::VERSION.into()),
            hostname: Some("work-stream-login".into()),
            os: Some(std::env::consts::OS.into()),
            arch: Some(std::env::consts::ARCH.into()),
            user: None,
            run_id: None,
            client_id: None,
            pool_count: Some(0),
            timestamp: Some(ts),
            privilege_key: None,
            metas: None,
            client_spec: None,
            multiplexer: None,
        })),
    )
    .await;
    assert_stream_closed(io, "Login message on work stream").await;

    // No StartWorkConn / ReqWorkConn leaked onto the control stream from
    // the rejections: it must stay silent (the login pre-warm ReqWorkConn
    // was already drained in yamux_login, and no work was requested).
    let silent = tokio::time::timeout(Duration::from_millis(300), read_msg_v1(&mut control)).await;
    match silent {
        Ok(Ok(msg)) => panic!(
            "control stream must stay silent after rejected work conns, got type {}: {:?}",
            msg.v1_type_byte(),
            msg.v1_type_byte(),
        ),
        Ok(Err(e)) => panic!("control stream read errored after rejected work conns: {e}"),
        Err(_) => {}
    }

    // (d) a VALID NewWorkConn is still accepted: the server pools it, so
    // the stream stays OPEN (the read must time out, not return EOF).
    let mut io = open_and_write(
        &session,
        &FrpMessage::NewWorkConn(msg::NewWorkConn {
            run_id: Some(run_id),
            timestamp: None,
            privilege_key: None,
        }),
    )
    .await;
    let mut buf2 = [0u8; 64];
    let kept = tokio::time::timeout(Duration::from_millis(300), async {
        io.read(&mut buf2).await
    })
    .await;
    assert!(
        kept.is_err(),
        "valid NewWorkConn must be pooled (stream stays open), not closed"
    );
}

/// Raw-TCP work-connection validation chain (dispatch.rs
/// handle_work_conn_inner). With tcp_mux OFF, work connections are
/// standalone TCP connections to the main port carrying one V1 NewWorkConn
/// frame — the same validation chain as the yamux streams above must hold:
/// a wrong run_id or a bad privilege_key gets a StartWorkConn error frame
/// (F2) and then the connection is dropped; the control stream stays
/// silent. A subsequent VALID NewWorkConn is pooled (connection kept
/// open), proving the rejections were validation, not a broken work-conn
/// accept path.
///
/// NOTE: the yamux chain's case (c) — a Login frame on a work stream — has
/// NO raw-TCP analogue: on raw TCP a Login frame on a NEW connection is a
/// legitimate control login (the main-port accept loop dispatches by
/// message type), not a work-conn rejection. Raw work conns are validated
/// by run_id + privilege_key only.
#[tokio::test]
async fn test_raw_tcp_work_conn_validation_drops_bad_connections() {
    let bind_port = allocate_port();
    let cfg = ServerConfig {
        bind_addr: "127.0.0.1".into(),
        bind_port,
        auth: test_auth_cfg(),
        ..Default::default()
    };
    let (_handle, _) = start_test_server(cfg).await;
    let addr: SocketAddr = format!("127.0.0.1:{bind_port}").parse().unwrap();

    // Raw control login (tcp_mux OFF). login_with_test_token drains the
    // post-login pre-warm ReqWorkConn, so the control stream is silent
    // afterwards and the server has an empty pool.
    let (mut control, resp) = login_with_test_token(addr).await.expect("control login");
    let run_id = resp.run_id.expect("run_id in LoginResp");

    // (a) wrong run_id → StartWorkConn error frame, then dropped.
    let stream = tokio::net::TcpStream::connect(addr)
        .await
        .expect("dial work conn");
    let (mut rd, mut wr) = stream.into_split();
    write_msg_v1(
        &mut wr,
        &FrpMessage::NewWorkConn(msg::NewWorkConn {
            run_id: Some("wrong-run-id".into()),
            timestamp: None,
            privilege_key: None,
        }),
    )
    .await
    .expect("write wrong-run_id NewWorkConn");
    assert_raw_rejected(
        &mut rd,
        "wrong run_id",
        "no client control found for run id [wrong-run-id]",
    )
    .await;

    // (b) correct run_id but bad privilege_key → rejection frame, then dropped.
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let stream = tokio::net::TcpStream::connect(addr)
        .await
        .expect("dial work conn");
    let (mut rd, mut wr) = stream.into_split();
    write_msg_v1(
        &mut wr,
        &FrpMessage::NewWorkConn(msg::NewWorkConn {
            run_id: Some(run_id.clone()),
            timestamp: Some(ts),
            privilege_key: Some("bogus-key".into()),
        }),
    )
    .await
    .expect("write bad-key NewWorkConn");
    assert_raw_rejected(
        &mut rd,
        "bad privilege_key",
        "token in login doesn't match token from configuration",
    )
    .await;

    // No StartWorkConn / ReqWorkConn leaked onto the control stream from the
    // rejections: it must stay silent (the login pre-warm ReqWorkConn was
    // already drained in login_with_test_token).
    let silent = tokio::time::timeout(Duration::from_millis(300), read_msg_v1(&mut control)).await;
    match silent {
        Ok(Ok(msg)) => panic!(
            "control stream must stay silent after rejected work conns, got type {}",
            msg.v1_type_byte(),
        ),
        Ok(Err(e)) => panic!("control stream read errored after rejected work conns: {e}"),
        Err(_) => {}
    }

    // (c) a VALID NewWorkConn (fresh timestamp + correct privilege_key) is
    // still accepted: the server pools it, so the connection stays OPEN
    // (the read must time out, not return EOF).
    let stream = tokio::net::TcpStream::connect(addr)
        .await
        .expect("dial work conn");
    let (mut rd, mut wr) = stream.into_split();
    write_msg_v1(
        &mut wr,
        &FrpMessage::NewWorkConn(msg::NewWorkConn {
            run_id: Some(run_id),
            timestamp: Some(ts),
            privilege_key: Some(auth::generate_token(TEST_TOKEN, ts)),
        }),
    )
    .await
    .expect("write valid NewWorkConn");
    let mut buf = [0u8; 64];
    let kept = tokio::time::timeout(Duration::from_millis(300), rd.read(&mut buf)).await;
    assert!(
        kept.is_err(),
        "valid NewWorkConn must be pooled (connection stays open), not closed"
    );
}

/// Assert the server REJECTS a raw work connection: read the StartWorkConn
/// error frame (F2), then EOF (Ok(0)) or RST within 2s. A timeout — the
/// conn still open — means the server pooled/accepted it instead.
async fn assert_raw_rejected(rd: &mut tokio::net::tcp::OwnedReadHalf, what: &str, expected: &str) {
    let frame = tokio::time::timeout(Duration::from_secs(2), read_msg_v1(rd))
        .await
        .unwrap_or_else(|_| panic!("{what}: rejection StartWorkConn frame timed out"))
        .unwrap_or_else(|e| panic!("{what}: read of rejection frame errored: {e}"));
    match frame {
        FrpMessage::StartWorkConn(swc) => {
            assert_eq!(
                swc.error.as_deref(),
                Some(expected),
                "{what}: rejection error text"
            );
        }
        other => panic!(
            "{what}: expected StartWorkConn rejection, got type {}",
            other.v1_type_byte()
        ),
    }
    let mut buf = [0u8; 64];
    match tokio::time::timeout(Duration::from_secs(2), rd.read(&mut buf)).await {
        Ok(Ok(0)) => {}
        Ok(Ok(n)) => panic!("{what}: expected EOF after rejection frame, got {n} bytes"),
        Ok(Err(_)) => {} // RST is also a valid close
        Err(_) => panic!("{what}: connection was NOT dropped after the rejection frame"),
    }
}

/// Pool-full rejection (F2, Go parity): with `pool_count` 1 the server
/// pre-warms exactly one work conn, so the pool fills at capacity 1 — the
/// second NewWorkConn must be REJECTED with a StartWorkConn error frame
/// carrying Go's verbatim literal "work connection pool is full,
/// discarding" (control.go:335 — NO run id), not silently dropped, and the
/// stream must then close. Under `detailed_errors_to_client = false` the
/// same rejection collapses to the generic "invalid NewWorkConn" summary.
#[tokio::test]
async fn test_pool_full_rejection_detailed_and_generic() {
    for detailed in [true, false] {
        let bind_port = allocate_port();
        let cfg = ServerConfig {
            bind_addr: "127.0.0.1".into(),
            bind_port,
            auth: test_auth_cfg(),
            detailed_errors_to_client: detailed,
            ..Default::default()
        };
        let (_handle, _) = start_test_server_tcpmux_on(cfg).await;
        let addr: SocketAddr = format!("127.0.0.1:{bind_port}").parse().unwrap();

        let (mut _control, session, run_id) = yamux_login(addr).await;

        // Pool capacity = pool_count(1) + WORK_POOL_EXTRA(10) headroom = 11
        // (login.rs pool_cap construction). Fill it: the first 10 conns are
        // opened write-only and held, the 11th must be pooled (stays OPEN),
        // and the 12th hits the full pool.
        let mut held: Vec<IoStream> = Vec::new();
        for _i in 0..10 {
            held.push(
                open_and_write(
                    &session,
                    &FrpMessage::NewWorkConn(msg::NewWorkConn {
                        run_id: Some(run_id.clone()),
                        timestamp: None,
                        privilege_key: None,
                    }),
                )
                .await,
            );
        }
        let mut pooled_conn = open_and_write(
            &session,
            &FrpMessage::NewWorkConn(msg::NewWorkConn {
                run_id: Some(run_id.clone()),
                timestamp: None,
                privilege_key: None,
            }),
        )
        .await;
        let mut buf = [0u8; 64];
        let kept =
            tokio::time::timeout(Duration::from_millis(300), pooled_conn.read(&mut buf)).await;
        assert!(
            kept.is_err(),
            "11th NewWorkConn must be pooled (stream stays open), not rejected"
        );
        held.push(pooled_conn);

        // 12th NewWorkConn hits the full pool: rejection frame + close.
        let io = open_and_write(
            &session,
            &FrpMessage::NewWorkConn(msg::NewWorkConn {
                run_id: Some(run_id.clone()),
                timestamp: None,
                privilege_key: None,
            }),
        )
        .await;
        let expected = if detailed {
            "work connection pool is full, discarding"
        } else {
            "invalid NewWorkConn"
        };
        assert_stream_rejected(io, "pool-full 12th NewWorkConn", expected).await;
    }
}
