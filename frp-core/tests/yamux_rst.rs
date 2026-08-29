//! Wire-shape verification of the vendored yamux per-stream RST patch.
//!
//! The vendor fork (vendor/yamux) replaces the session-killing GoAway that
//! crates.io yamux 0.14 sends when the inbound stream cap is reached with a
//! per-stream RST (Go fatedier/yamux semantics): the offending SYN is
//! answered with a 12-byte header frame of type Data (0) + flags RST (8),
//! targeting the offending stream id with zero length. The connection must
//! survive — no GoAway, no session teardown.

#![cfg(feature = "tcp-mux")]

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::compat::TokioAsyncReadCompatExt;
use yamux::{Config, Connection, Mode};

/// When the inbound-stream cap is reached, an over-cap SYN must receive a
/// Data-typed + RST-flag 12-byte header (stream id located, length 0), NOT a
/// GoAway, and the session must stay alive. This shape matches yamux-rs's own
/// on-drop RST path and is the shape Go's fatedier/yamux fork understands
/// (it handles flagRST on both Data and WindowUpdate frame types).
#[tokio::test]
async fn yamux_inbound_cap_sends_per_stream_rst_wire_shape() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server = tokio::spawn(async move {
        let (sock, _) = listener.accept().await.unwrap();
        // The vendored fork has no `Config::new` — `default` + setters only.
        let mut cfg = Config::default();
        cfg.set_max_num_streams(3);
        let mut conn = Connection::new(sock.compat(), cfg, Mode::Server);
        let mut held: Vec<yamux::Stream> = Vec::new();
        let mut accepted = 0u32;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
        std::future::poll_fn(move |cx| loop {
            match conn.poll_next_inbound(cx) {
                std::task::Poll::Ready(Some(Ok(s))) => {
                    accepted += 1;
                    held.push(s);
                }
                std::task::Poll::Ready(Some(Err(_))) | std::task::Poll::Ready(None) => {
                    return std::task::Poll::Ready(accepted);
                }
                std::task::Poll::Pending => {
                    if tokio::time::Instant::now() >= deadline {
                        return std::task::Poll::Ready(accepted);
                    }
                    return std::task::Poll::Pending;
                }
            }
        })
        .await
    });

    let mut cli = tokio::net::TcpStream::connect(addr).await.unwrap();
    // 12-byte yamux header: [ver u8=0, type u8, flags u16 BE, sid u32 BE, len u32 BE]
    fn syn(sid: u32) -> [u8; 12] {
        let mut h = [0u8; 12];
        h[3] = 1; // flags: SYN
        h[4..8].copy_from_slice(&sid.to_be_bytes());
        h
    }
    // Three streams are admitted (client-side stream ids must be odd).
    for sid in [1u32, 3, 5] {
        cli.write_all(&syn(sid)).await.unwrap();
    }
    // Over-cap SYN: expect a Data+RST locating the offending stream.
    for sid in [7u32, 9] {
        cli.write_all(&syn(sid)).await.unwrap();
    }
    // The server answers in one batch: its connection-level initial credit
    // grant (WindowUpdate-typed frame on connection id 0, emitted at
    // connection creation and flushed on the first poll), then the two
    // over-cap SYNs get Data-typed RSTs (type 0, RST flag) targeting the
    // offending sids with zero length. Accepted streams send NO initial
    // window update (a fresh stream has half-or-more of its 256 KiB window
    // available, so `next_window_update` yields None). Classify frames:
    // exactly 1 WindowUpdate and 2 RSTs.
    let mut rsts: Vec<u32> = Vec::new();
    let mut window_updates = 0u32;
    for _ in 0..3 {
        let mut hdr = [0u8; 12];
        tokio::time::timeout(Duration::from_secs(2), cli.read_exact(&mut hdr))
            .await
            .expect("server must answer the over-cap SYNs")
            .unwrap();
        assert_eq!(hdr[0], 0, "version 0");
        match hdr[1] {
            0 => {
                assert_eq!(u16::from_be_bytes([hdr[2], hdr[3]]), 8, "flags RST");
                assert_eq!(
                    u32::from_be_bytes(hdr[8..12].try_into().unwrap()),
                    0,
                    "zero length"
                );
                rsts.push(u32::from_be_bytes(hdr[4..8].try_into().unwrap()));
            }
            2 => {
                window_updates += 1;
            }
            other => panic!("unexpected frame type {other} (expected WindowUpdate or Data-RST)"),
        }
    }
    assert_eq!(
        rsts,
        vec![7, 9],
        "RSTs target the offending streams in order"
    );
    assert_eq!(
        window_updates, 1,
        "only the connection-level credit grant precedes the RSTs"
    );
    // Session alive: after RSTs there is no GoAway and the connection is not
    // killed. The server's poll_fn parks on the socket waker with no further
    // client data — it only completes on EOF, so close the client before
    // joining (its deadline check never runs on its own: no tokio timer is
    // registered, the park is on the socket read waker).
    let mut hdr = [0u8; 12];
    assert!(
        tokio::time::timeout(Duration::from_millis(200), cli.read_exact(&mut hdr))
            .await
            .is_err(),
        "no GoAway: connection must survive per-stream RST"
    );
    drop(cli);
    assert_eq!(
        server.await.unwrap(),
        3,
        "server admitted exactly 3 streams"
    );
}
