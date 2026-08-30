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
    // The server answers in one batch: its initial ping (Ping-typed frame
    // with the SYN flag and the ping id in the length field — `Rtt::new`
    // starts `Waiting { next: Instant::now() }` so the first poll sends a
    // ping immediately), then the two over-cap SYNs get Data-typed RSTs
    // (type 0, RST flag) targeting the offending sids with zero length.
    // Accepted streams send NO initial window update (a fresh stream has
    // half-or-more of its 256 KiB window available, so `next_window_update`
    // yields None). Classify frames: exactly 1 ping and 2 RSTs.
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
    assert_eq!(window_updates, 1, "only the initial ping precedes the RSTs");
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

/// 12-byte yamux header: [ver u8=0, type u8, flags u16 BE, sid u32 BE, len u32 BE]
fn cap_syn(sid: u32) -> [u8; 12] {
    let mut h = [0u8; 12];
    h[3] = 1; // flags: SYN
    h[4..8].copy_from_slice(&sid.to_be_bytes());
    h
}

/// Server connection type used by the backpressure tests below.
type CapConn = yamux::Connection<tokio_util::compat::Compat<tokio::io::DuplexStream>>;

/// Poll the server connection until `target` inbound streams are admitted
/// (panics on connection error/EOF or an admission stall).
async fn pump_until_admitted(conn: &mut CapConn, held: &mut Vec<yamux::Stream>, target: usize) {
    std::future::poll_fn(|cx| loop {
        match conn.poll_next_inbound(cx) {
            std::task::Poll::Ready(Some(Ok(s))) => {
                held.push(s);
                if held.len() >= target {
                    return std::task::Poll::Ready(());
                }
            }
            std::task::Poll::Ready(Some(Err(_))) | std::task::Poll::Ready(None) => {
                panic!("connection ended before admitting {target} streams");
            }
            std::task::Poll::Pending => return std::task::Poll::Pending,
        }
    })
    .await;
}

/// Poll the server connection until it goes idle, processing everything
/// currently readable (e.g. queueing RSTs for over-cap SYNs).
async fn pump_until_pending(conn: &mut CapConn, held: &mut Vec<yamux::Stream>) {
    std::future::poll_fn(|cx| loop {
        match conn.poll_next_inbound(cx) {
            std::task::Poll::Ready(Some(Ok(s))) => held.push(s),
            std::task::Poll::Ready(Some(Err(_))) | std::task::Poll::Ready(None) => {
                panic!("connection ended during pump");
            }
            std::task::Poll::Pending => return std::task::Poll::Ready(()),
        }
    })
    .await;
}

/// Read one 12-byte frame from the raw client side with a bounded timeout.
async fn read_frame(client: &mut tokio::io::DuplexStream) -> [u8; 12] {
    let mut hdr = [0u8; 12];
    tokio::time::timeout(Duration::from_secs(3), client.read_exact(&mut hdr))
        .await
        .expect("timeout waiting for a yamux frame")
        .expect("yamux frame read failed");
    hdr
}

/// Read frames until `n` RST frames have been collected, returning their
/// stream ids in arrival order. Non-RST frames are skipped (the connection
/// emits an initial ping at creation — Data-typed RSTs are type 0 + RST
/// flag 8; yamux's `Frame::ping` sets the SYN flag on a Ping-typed frame).
async fn read_rsts(client: &mut tokio::io::DuplexStream, n: usize) -> Vec<u32> {
    let mut rsts = Vec::new();
    for _ in 0..(n + 8) {
        if rsts.len() >= n {
            break;
        }
        let hdr = read_frame(client).await;
        assert_eq!(hdr[0], 0, "version 0");
        if hdr[1] != 0 || u16::from_be_bytes([hdr[2], hdr[3]]) != 8 {
            continue; // not an RST (initial ping / window update / ack)
        }
        rsts.push(u32::from_be_bytes(hdr[4..8].try_into().unwrap()));
    }
    assert_eq!(rsts.len(), n, "expected {n} RST frames");
    rsts
}

/// Assert the server sends nothing further within a short quiet window.
async fn assert_no_more_frames(client: &mut tokio::io::DuplexStream) {
    let mut hdr = [0u8; 12];
    assert!(
        tokio::time::timeout(Duration::from_millis(200), client.read_exact(&mut hdr))
            .await
            .is_err(),
        "unexpected extra yamux frame"
    );
}

/// Spawn a pump task that keeps the server connection making progress (the
/// per-stream RSTs are only written when the connection is polled). Exits
/// quietly on EOF/error once the client side is dropped.
fn spawn_server_pump(
    mut conn: CapConn,
    held: &mut Vec<yamux::Stream>,
) -> tokio::task::JoinHandle<()> {
    let mut held = std::mem::take(held);
    tokio::spawn(async move {
        std::future::poll_fn(|cx| loop {
            match conn.poll_next_inbound(cx) {
                std::task::Poll::Ready(Some(Ok(s))) => held.push(s),
                std::task::Poll::Ready(Some(Err(_))) | std::task::Poll::Ready(None) => {
                    return std::task::Poll::Ready(());
                }
                std::task::Poll::Pending => return std::task::Poll::Pending,
            }
        })
        .await
    })
}

/// Round-15 regression: the vendored fork's RST queue must be a bounded FIFO.
///
/// With the old single-slot `pending_reset_frame`, cap-hit SYNs processed
/// while the socket write was backpressured (client not reading) overwrote
/// previously queued RSTs — those streams' resets never reached the peer,
/// leaving half-open streams until session timeout.
///
/// THREE over-cap SYNs are needed to expose this, not two: the drain site
/// pops the first RST into the frame sink before the write blocks (the
/// socket was still idle when it ran), so with two SYNs the first RST
/// escapes to the sink and the old slot is empty when the second arrives.
/// The loss bites when the sink is already busy holding that first RST and
/// TWO more SYNs are processed: the old slot keeps only the last one. The
/// bounded FIFO queue must deliver ALL THREE, in order, once the write
/// unblocks.
#[tokio::test]
async fn yamux_cap_backpressure_delivers_all_rsts() {
    let (server_io, mut client_io) = tokio::io::duplex(12);
    let mut cfg = Config::default();
    cfg.set_max_num_streams(2);
    let mut conn = Connection::new(server_io.compat(), cfg, Mode::Server);
    let mut held: Vec<yamux::Stream> = Vec::new();

    // Admit two streams (cap = 2). The server-side frames written so far
    // (its initial ping, 12 bytes) fill the client-side read buffer, so
    // every RST queued below stays queued until the client starts reading.
    for (i, sid) in [1u32, 3].into_iter().enumerate() {
        client_io.write_all(&cap_syn(sid)).await.unwrap();
        pump_until_admitted(&mut conn, &mut held, i + 1).await;
    }

    // Three over-cap SYNs arrive while the write side is backpressured:
    // the first RST goes to the blocked frame sink, the next two must stay
    // queued (the old single slot dropped the middle one).
    for sid in [5u32, 7, 9] {
        client_io.write_all(&cap_syn(sid)).await.unwrap();
        pump_until_pending(&mut conn, &mut held).await;
    }

    // Pump the server concurrently while the client reads; all three RSTs
    // must arrive, in FIFO order.
    let server_task = spawn_server_pump(conn, &mut held);

    let rsts = read_rsts(&mut client_io, 3).await;
    assert_eq!(
        rsts,
        vec![5, 7, 9],
        "all cap-hit RSTs reach the peer, FIFO (single slot dropped the middle one)"
    );
    assert_no_more_frames(&mut client_io).await;

    drop(client_io);
    server_task.await.unwrap();
}

/// The RST queue is bounded (cap 32): a 34-SYN burst drops the OLDEST
/// queued RST, delivers the rest in FIFO order, and the session survives.
///
/// Note on the sink: the first over-cap RST is handed to the frame sink
/// immediately (the drain site pops it before the socket write blocks), so
/// the bounded queue receives one RST per subsequent SYN. With 34 over-cap
/// SYNs (sids 5..=71) the queue holds 33: the cap evicts sid 7 (oldest),
/// and the wire shows `[5] + [9..=71]` — 33 RSTs, bounded.
#[tokio::test]
async fn yamux_reset_queue_cap_drops_oldest() {
    let (server_io, mut client_io) = tokio::io::duplex(12);
    let mut cfg = Config::default();
    cfg.set_max_num_streams(2);
    let mut conn = Connection::new(server_io.compat(), cfg, Mode::Server);
    let mut held: Vec<yamux::Stream> = Vec::new();

    for (i, sid) in [1u32, 3].into_iter().enumerate() {
        client_io.write_all(&cap_syn(sid)).await.unwrap();
        pump_until_admitted(&mut conn, &mut held, i + 1).await;
    }

    // 34 over-cap SYNs while the write is backpressured: 33 RSTs are
    // queued/sink-held; at cap the oldest queued (sid 7) is dropped.
    for sid in (5u32..=71).step_by(2) {
        client_io.write_all(&cap_syn(sid)).await.unwrap();
        pump_until_pending(&mut conn, &mut held).await;
    }

    let server_task = spawn_server_pump(conn, &mut held);

    let sids = read_rsts(&mut client_io, 33).await;
    let expected: Vec<u32> = std::iter::once(5).chain((9u32..=71).step_by(2)).collect();
    assert_eq!(
        sids, expected,
        "33 RSTs delivered FIFO; the oldest queued (sid 7) was dropped at cap"
    );
    assert!(!sids.contains(&7), "oldest queued RST dropped at cap");
    assert_no_more_frames(&mut client_io).await;

    drop(client_io);
    server_task.await.unwrap();
}
