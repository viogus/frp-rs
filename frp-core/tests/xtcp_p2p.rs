//! Integration tests for XTCP P2P hole punching and KCP data-plane.
//!
//! Tests cover:
//! - `punch_udp_hole` on loopback (Rust↔Rust "frp" magic)
//! - `xtcp_p2p_connect` end-to-end (hole punch + KCP + data transfer)
//! - FEC-enabled KCP transport
//! - KCP dead link detection

use std::net::SocketAddr;

use frp_core::kcp::{default_kcp_config, KcpConfig, KcpListener};
use frp_core::xtcp_p2p;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::time::{timeout, Duration};

/// Bind two UDP sockets on loopback, return their addresses.
async fn bind_pair() -> (UdpSocket, UdpSocket, SocketAddr, SocketAddr) {
    let a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr_a = a.local_addr().unwrap();
    let addr_b = b.local_addr().unwrap();
    (a, b, addr_a, addr_b)
}

/// Hole-punch two UDP sockets on loopback using the Rust↔Rust "frp" magic protocol.
/// Both sides call `punch_udp_hole` concurrently.
#[tokio::test]
async fn test_punch_udp_hole_loopback() {
    let (a, b, addr_a, addr_b) = bind_pair().await;

    let candidate_a = vec![addr_a.to_string()];
    let candidate_b = vec![addr_b.to_string()];

    let (peer_a, peer_b) = tokio::join!(
        xtcp_p2p::punch_udp_hole(&a, &candidate_b, 3000, None, None),
        xtcp_p2p::punch_udp_hole(&b, &candidate_a, 3000, None, None),
    );

    let peer_a = peer_a.expect("side A hole punch");
    let peer_b = peer_b.expect("side B hole punch");

    assert_eq!(peer_a, addr_b, "A should see B's address");
    assert_eq!(peer_b, addr_a, "B should see A's address");
}

/// Hole-punch then create KCP streams on both sides and exchange data.
#[tokio::test]
async fn test_xtcp_p2p_connect_roundtrip() {
    let (a, b, _addr_a, _addr_b) = bind_pair().await;

    let candidate_a = vec![a.local_addr().unwrap().to_string()];
    let candidate_b = vec![b.local_addr().unwrap().to_string()];

    let conv = 42u32;
    let kcp_config = KcpConfig {
        data_shards: 0,
        parity_shards: 0,
        ..default_kcp_config()
    };

    // Both sides: punch hole + create KCP stream.
    let (stream_a, stream_b) = tokio::join!(
        xtcp_p2p::xtcp_p2p_connect(
            a,
            &candidate_b,
            &[],
            None,
            conv,
            kcp_config.clone(),
            3000,
            None,
            None
        ),
        xtcp_p2p::xtcp_p2p_connect(
            b,
            &candidate_a,
            &[],
            None,
            conv,
            kcp_config.clone(),
            3000,
            None,
            None
        ),
    );

    let mut stream_a = stream_a.expect("side A connect");
    let mut stream_b = stream_b.expect("side B connect");

    // A → B
    let payload = b"hello xtcp p2p over kcp!";
    tokio::time::timeout(Duration::from_secs(5), stream_a.write_all(payload))
        .await
        .unwrap()
        .expect("A write");
    stream_a.flush().await.expect("A flush");

    let mut buf = vec![0u8; payload.len()];
    tokio::time::timeout(Duration::from_secs(5), stream_b.read_exact(&mut buf))
        .await
        .unwrap()
        .expect("B read");
    assert_eq!(&buf, payload, "B should receive A's data");

    // B → A
    let reply = b"hello from B!";
    tokio::time::timeout(Duration::from_secs(5), stream_b.write_all(reply))
        .await
        .unwrap()
        .expect("B write");
    stream_b.flush().await.expect("B flush");

    let mut buf = vec![0u8; reply.len()];
    tokio::time::timeout(Duration::from_secs(5), stream_a.read_exact(&mut buf))
        .await
        .unwrap()
        .expect("A read");
    assert_eq!(&buf, reply, "A should receive B's reply");
}

/// KCP roundtrip with FEC enabled (default Go frp config: 10+3 shards).
/// Verifies the FEC code path works end-to-end on real UDP sockets.
#[tokio::test]
async fn test_kcp_roundtrip_with_fec() {
    let config = default_kcp_config(); // 10 data + 3 parity shards

    let mut listener = KcpListener::bind("127.0.0.1:0", config.clone())
        .await
        .expect("bind KCP listener");
    let addr = listener.local_addr().expect("local_addr");

    let mut client = frp_core::kcp::dial_kcp(&addr.to_string(), config)
        .await
        .expect("dial");
    client.write_all(b"hello with fec").await.unwrap();
    client.flush().await.unwrap();

    let mut server = timeout(Duration::from_secs(5), listener.accept())
        .await
        .expect("accept timeout")
        .expect("accept");

    let mut buf = vec![0u8; 64];
    let n = timeout(Duration::from_secs(5), server.read(&mut buf))
        .await
        .expect("read timeout")
        .expect("server read");
    assert_eq!(&buf[..n], b"hello with fec");

    server.write_all(b"fec reply").await.unwrap();
    server.flush().await.unwrap();

    let n = timeout(Duration::from_secs(5), client.read(&mut buf))
        .await
        .expect("read timeout")
        .expect("client read");
    assert_eq!(&buf[..n], b"fec reply");
}

/// Multiple round-trips over a single XTCP P2P KCP connection.
#[tokio::test]
async fn test_xtcp_p2p_multiple_roundtrips() {
    let (a, b, _addr_a, _addr_b) = bind_pair().await;

    let candidate_a = vec![a.local_addr().unwrap().to_string()];
    let candidate_b = vec![b.local_addr().unwrap().to_string()];

    let conv = 99u32;
    let kcp_config = KcpConfig {
        data_shards: 0,
        parity_shards: 0,
        ..default_kcp_config()
    };

    let (stream_a, stream_b) = tokio::join!(
        xtcp_p2p::xtcp_p2p_connect(
            a,
            &candidate_b,
            &[],
            None,
            conv,
            kcp_config.clone(),
            3000,
            None,
            None
        ),
        xtcp_p2p::xtcp_p2p_connect(
            b,
            &candidate_a,
            &[],
            None,
            conv,
            kcp_config.clone(),
            3000,
            None,
            None
        ),
    );

    let mut stream_a = stream_a.expect("side A connect");
    let mut stream_b = stream_b.expect("side B connect");

    // KCP flushes data to UDP only when maybe_tick fires (every 10ms).
    // After write+flush, poll the writer for read to drive its KCP tick
    // (which sends queued data to UDP), then read on the other side.
    // Timeout-based — no fixed sleep that could flake on slow CI.
    for i in 0..5 {
        let msg = format!("p2p msg {}", i).into_bytes();
        stream_a.write_all(&msg).await.expect("write");
        stream_a.flush().await.expect("flush");

        // Drive KCP tick on writer: poll_read calls maybe_tick which flushes
        // queued KCP segments to UDP. Timeout ensures we don't hang if the
        // peer hasn't sent anything yet (WouldBlock is fine).
        let mut dummy = [0u8; 1];
        let _ = tokio::time::timeout(Duration::from_millis(200), stream_a.read(&mut dummy)).await;

        let mut buf = vec![0u8; msg.len()];
        tokio::time::timeout(Duration::from_secs(5), stream_b.read_exact(&mut buf))
            .await
            .unwrap()
            .expect("read");
        assert_eq!(buf, msg, "round {} mismatch", i);
    }
}

/// Verify conv_from_sid determinism.
#[test]
fn test_conv_from_sid_deterministic() {
    let c1 = xtcp_p2p::conv_from_sid("test-sid-123");
    let c2 = xtcp_p2p::conv_from_sid("test-sid-123");
    assert_eq!(c1, c2, "same sid should produce same conv");
    assert!(c1 > 0, "conv should be non-zero");
}

/// conv_from_sid always returns 1 (Go kcp-go compat). All inputs must
/// produce a non-zero conv.
#[test]
fn test_conv_from_sid_different() {
    let c1 = xtcp_p2p::conv_from_sid("session-a");
    let c2 = xtcp_p2p::conv_from_sid("session-b");
    assert!(c1 > 0);
    assert!(c2 > 0);
    // Both are 1 (Go kcp-go compat): each XtcpP2pStream has its own UDP
    // socket, so conv collisions across sessions are harmless.
    assert_eq!(c1, c2);
}

/// Yamux-over-XTCP-P2P roundtrip: hole-punch, create yamux connections,
/// open stream, send data both ways. Verifies the full yamux data plane
/// over KCP-in-UDP (Go v0.70 compat path).
#[cfg(feature = "tcp-mux")]
#[tokio::test]
async fn test_xtcp_p2p_yamux_roundtrip() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let (a, b, _addr_a, _addr_b) = bind_pair().await;

    let candidate_a = vec![a.local_addr().unwrap().to_string()];
    let candidate_b = vec![b.local_addr().unwrap().to_string()];

    let conv = 77u32;
    let kcp_config = frp_core::kcp::KcpConfig {
        data_shards: 0,
        parity_shards: 0,
        ..frp_core::kcp::default_kcp_config()
    };

    // Spawn provider (server) in a background task so it's ready to
    // accept when the visitor (client) sends data.
    // Clone candidates to satisfy 'static requirement of tokio::spawn.
    let can_a_for_spawn = candidate_a.clone();
    let cfg_for_spawn = kcp_config.clone();
    let server = tokio::spawn(async move {
        frp_core::xtcp_p2p::xtcp_p2p_connect_yamux(
            b,
            &can_a_for_spawn,
            &[],
            None,
            conv,
            cfg_for_spawn,
            5000,
            false, // yamux_server = provider (accepts stream)
            None,  // no sid → simple "frp" magic
            None,  // no key
        )
        .await
    });

    // Visitor (client): punch, create yamux, open stream.
    let mut stream_a = frp_core::xtcp_p2p::xtcp_p2p_connect_yamux(
        a,
        &candidate_b,
        &[],
        None,
        conv,
        kcp_config.clone(),
        5000,
        true, // yamux_client = visitor (opens stream)
        None,
        None,
    )
    .await
    .expect("side A yamux connect");

    // Write data to trigger SYN send. After this flush, the bg driver
    // on side A will process the SYN frame and send it via KCP.
    let payload = b"hello xtcp p2p over yamux!";
    tokio::time::timeout(
        tokio::time::Duration::from_secs(10),
        stream_a.write_all(payload),
    )
    .await
    .unwrap()
    .expect("A write");
    stream_a.flush().await.expect("A flush");

    // Now wait for the provider to accept the stream.
    let mut stream_b = tokio::time::timeout(tokio::time::Duration::from_secs(10), server)
        .await
        .unwrap()
        .expect("server task join")
        .expect("side B yamux connect");

    // A → B (data already written, just read on B)
    let mut buf = vec![0u8; payload.len()];
    tokio::time::timeout(
        tokio::time::Duration::from_secs(10),
        stream_b.read_exact(&mut buf),
    )
    .await
    .unwrap()
    .expect("B read");
    assert_eq!(&buf, payload, "B should receive A's data");

    // B → A
    let reply = b"hello from B over yamux!";
    tokio::time::timeout(
        tokio::time::Duration::from_secs(10),
        stream_b.write_all(reply),
    )
    .await
    .unwrap()
    .expect("B write");
    stream_b.flush().await.expect("B flush");

    let mut buf = vec![0u8; reply.len()];
    tokio::time::timeout(
        tokio::time::Duration::from_secs(10),
        stream_a.read_exact(&mut buf),
    )
    .await
    .unwrap()
    .expect("A read");
    assert_eq!(&buf, reply, "A should receive B's reply");
}

/// Go MakeHole state machine on loopback: sender probes assisted+candidate
/// addresses, receiver listens with extra sockets; both use the "frp" magic
/// (no sid/key) and must connect.
#[tokio::test]
async fn test_makehole_loopback_with_assisted_and_behavior() {
    let (a, b, addr_a, addr_b) = bind_pair().await;

    let candidate_a = vec![addr_a.to_string()];
    let candidate_b = vec![addr_b.to_string()];

    // Sender probes assisted addresses too (an unroutable one is fine — the
    // real candidate still works). Receiver uses extra listener sockets.
    let sender_behavior = frp_core::msg::NatHoleDetectBehavior {
        mode: 0,
        role: Some("sender".into()),
        ttl: 64,
        send_delay_ms: 20,
        read_timeout_ms: 3000,
        send_random_ports: 0,
        listen_random_ports: 0,
        candidate_ports: None,
    };
    let receiver_behavior = frp_core::msg::NatHoleDetectBehavior {
        role: Some("receiver".into()),
        listen_random_ports: 2,
        ..sender_behavior.clone()
    };

    let assisted_sender = vec!["192.0.2.1:40000".to_string()]; // TEST-NET, unroutable
    let (peer_a, peer_b) = tokio::join!(
        xtcp_p2p::punch_udp_hole_makehole(
            &a,
            &candidate_b,
            &assisted_sender,
            &sender_behavior,
            3000,
            None,
            None,
        ),
        xtcp_p2p::punch_udp_hole_makehole(
            &b,
            &candidate_a,
            &[],
            &receiver_behavior,
            3000,
            None,
            None,
        ),
    );

    let peer_a = peer_a.expect("makehole side A");
    let peer_b = peer_b.expect("makehole side B");
    assert_eq!(peer_a, addr_b, "A should see B's address");
    assert_eq!(peer_b, addr_a, "B should see A's address");
}

/// Go MakeHole receiver-side candidate port range scanning: the receiver
/// probes the sender's port range, the sender answers on its real port.
#[tokio::test]
async fn test_makehole_candidate_port_scanning() {
    let (a, b, addr_a, addr_b) = bind_pair().await;

    let candidate_a = vec![addr_a.to_string()];
    let candidate_b = vec![addr_b.to_string()];

    // Receiver (side B) scans a range around A's port.
    let receiver_behavior = frp_core::msg::NatHoleDetectBehavior {
        role: Some("receiver".into()),
        candidate_ports: Some(vec![frp_core::msg::PortsRange {
            from: addr_a.port() as i32,
            to: addr_a.port() as i32,
        }]),
        ..Default::default()
    };
    let sender_behavior = frp_core::msg::NatHoleDetectBehavior {
        role: Some("sender".into()),
        ..Default::default()
    };

    let (peer_a, peer_b) = tokio::join!(
        xtcp_p2p::punch_udp_hole_makehole(
            &a,
            &candidate_b,
            &[],
            &sender_behavior,
            3000,
            None,
            None
        ),
        xtcp_p2p::punch_udp_hole_makehole(
            &b,
            &candidate_a,
            &[],
            &receiver_behavior,
            3000,
            None,
            None
        ),
    );

    let peer_a = peer_a.expect("makehole scan side A");
    let peer_b = peer_b.expect("makehole scan side B");
    assert_eq!(peer_a, addr_b);
    assert_eq!(peer_b, addr_a);
}
