//! Integration test: KCP dial → send → recv round-trip.
//!
//! The whole file is driven by `frp-core`'s `kcp` feature: it uses
//! `dial_kcp`/`dial_kcp_with_driver`/`KcpListener` and the `data_shards`/
//! `parity_shards` fields of `KcpConfig`, none of which exist in the
//! feature-off stub module `frp_core::kcp` (frp-core/src/lib.rs:107).
#![cfg(feature = "kcp")]

use std::time::Duration;

use frp_core::kcp::{default_kcp_config, dial_kcp, dial_kcp_with_driver, KcpConfig, KcpListener};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::{sleep, timeout};

fn no_fec_config() -> KcpConfig {
    KcpConfig {
        data_shards: 0,
        parity_shards: 0,
        ..default_kcp_config()
    }
}

/// Integration test for KCP dial/accept/send/recv round-trip.
///
/// Uses multi-threaded runtime because the KcpSocket driver tasks are spawned
/// on separate tasks and the single-threaded runtime can starve them when
/// the test harness captures output.
#[tokio::test(flavor = "multi_thread")]
async fn test_kcp_dial_send_recv() {
    let config = no_fec_config();
    let mut listener = KcpListener::bind("127.0.0.1:0", config.clone())
        .await
        .expect("bind");
    let addr = format!("127.0.0.1:{}", listener.local_addr().unwrap().port());

    // Allow driver event loops to start.
    sleep(Duration::from_millis(50)).await;

    // Spawn the dialer: connect, write, shutdown.
    let dial_handle = tokio::spawn(async move {
        let mut stream = timeout(Duration::from_secs(10), dial_kcp(&addr, config))
            .await
            .expect("dial timeout")
            .expect("dial_kcp");
        stream.write_all(b"hello from dialer").await.expect("write");
        stream.shutdown().await.expect("shutdown");
    });

    // Accept the incoming connection.
    let mut stream = timeout(Duration::from_secs(10), listener.accept())
        .await
        .expect("accept timeout")
        .expect("accept");

    // Read with timeout.
    let mut buf = vec![0u8; 1024];
    let n = timeout(Duration::from_secs(10), stream.read(&mut buf))
        .await
        .expect("read timeout")
        .expect("read");

    assert_eq!(&buf[..n], b"hello from dialer");
    dial_handle.await.expect("dial task");
}

/// Regression (HIGH leak): the dial-path KcpSocket driver used to loop
/// forever after the last stream was dropped — sessions empty, but run()
/// still spinning on tick/recv with the UDP socket open, leaking one task +
/// socket per KCP dial (control conn, each work conn) for the process
/// lifetime; reconnect churn grew it unbounded. The driver must self-exit
/// once its only stream is dropped. Fails (timeout) without the fix.
#[tokio::test(flavor = "multi_thread")]
async fn test_kcp_dial_driver_self_exits_after_stream_drop() {
    let config = no_fec_config();

    // Real dial (binds a UDP socket and spawns the driver), then drop the
    // stream immediately — no peer needed, the driver's liveness signal is
    // the stream itself.
    let (stream, driver) = timeout(
        Duration::from_secs(10),
        dial_kcp_with_driver("127.0.0.1:1", config),
    )
    .await
    .expect("dial timeout")
    .expect("dial_kcp_with_driver");
    drop(stream);

    // The driver must terminate promptly once its only stream is gone.
    // (The outer Result is the timeout — the failure this test exists to
    // catch; the driver's own exit status is irrelevant once it resolves.)
    let _: Result<(), _> = timeout(Duration::from_secs(5), driver)
        .await
        .expect("KCP dial driver must self-exit after the last stream is dropped");
}

/// KCP+TLS round-trip: the client wraps the KCP stream in TLS with the
/// 0x17 head byte (Go frp compat); the server strips the head byte and
/// performs a TLS accept, exactly like frp-server/src/service.rs KCP TLS
/// accept path. Verifies dial_server's KCP branch honors tls_enable.
#[cfg(feature = "tls")]
#[tokio::test(flavor = "multi_thread")]
async fn test_kcp_tls_round_trip() {
    use frp_core::transport::{dial_server, DialOptions};
    use tokio::io::AsyncReadExt;

    // dial_server uses default_kcp_client_config (FEC 10,3); the listener
    // must match or FEC-wrapped packets will be unparseable.
    let config = KcpConfig {
        data_shards: 10,
        parity_shards: 3,
        ..default_kcp_config()
    };
    let mut listener = KcpListener::bind("127.0.0.1:0", config.clone())
        .await
        .expect("bind");
    let port = listener.local_addr().unwrap().port();

    // Allow driver event loops to start.
    sleep(Duration::from_millis(50)).await;

    let server_cfg = frp_core::transport::generate_self_signed_tls_config()
        .expect("generate self-signed TLS config");
    let acceptor = tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(server_cfg));

    let server_handle = tokio::spawn(async move {
        let mut kcp_stream = timeout(Duration::from_secs(10), listener.accept())
            .await
            .expect("accept timeout")
            .expect("accept");
        // Strip the Go frp 0x17 head byte (service.rs KCP TLS accept path).
        let mut first = [0u8; 1];
        timeout(Duration::from_secs(10), kcp_stream.read_exact(&mut first))
            .await
            .expect("read head byte timeout")
            .expect("read head byte");
        assert_eq!(first[0], frp_core::transport::FRP_TLS_HEAD_BYTE);
        let mut tls_stream = timeout(Duration::from_secs(10), acceptor.accept(kcp_stream))
            .await
            .expect("tls accept timeout")
            .expect("tls accept");
        let mut buf = vec![0u8; 1024];
        let n = timeout(Duration::from_secs(10), tls_stream.read(&mut buf))
            .await
            .expect("tls read timeout")
            .expect("tls read");
        assert_eq!(&buf[..n], b"hello over kcp+tls");
    });

    let opts = DialOptions {
        server_addr: "127.0.0.1".to_string(),
        server_port: port,
        protocol: frp_core::transport::TransportProtocol::Kcp,
        tls_enable: true,
        ..Default::default()
    };
    let io = timeout(Duration::from_secs(10), dial_server(&opts))
        .await
        .expect("dial timeout")
        .expect("dial_server");
    let mut tls_io = io.into_tls().expect("expected IoStream::Tls for KCP+TLS");
    {
        use tokio::io::AsyncWriteExt;
        tls_io
            .write_all(b"hello over kcp+tls")
            .await
            .expect("tls write");
        tls_io.flush().await.expect("tls flush");
    }

    server_handle.await.expect("server task");
}

/// 512 KiB of patterned data over real UDP loopback — many KCP windows
/// worth (the receive window is ~256 packets), exercising window
/// advances, retransmission pacing and the multi-packet reassembly path
/// under genuine socket backpressure. Byte-exactness proves no
/// reorder/drop corruption survives the journey.
#[tokio::test(flavor = "multi_thread")]
async fn test_kcp_512kib_volume_byte_exact() {
    let config = no_fec_config();
    let mut listener = KcpListener::bind("127.0.0.1:0", config.clone())
        .await
        .expect("bind");
    let addr = format!("127.0.0.1:{}", listener.local_addr().unwrap().port());

    // Allow driver event loops to start.
    sleep(Duration::from_millis(50)).await;

    const N: usize = 512 * 1024;
    let payload: Vec<u8> = (0..N).map(|i| ((i * 13 + 5) % 251) as u8).collect();
    let write_data = payload.clone();

    // Spawn the dialer: connect, write the full volume (write_all may park
    // on KCP write backpressure while the listener drains), flush.
    let dial_handle = tokio::spawn(async move {
        let mut stream = timeout(Duration::from_secs(10), dial_kcp(&addr, config))
            .await
            .expect("dial timeout")
            .expect("dial_kcp");
        stream.write_all(&write_data).await.expect("write_all");
        stream.flush().await.expect("flush");
        stream.shutdown().await.expect("shutdown");
    });

    let mut stream = timeout(Duration::from_secs(10), listener.accept())
        .await
        .expect("accept timeout")
        .expect("accept");

    let mut got = vec![0u8; N];
    timeout(Duration::from_secs(30), stream.read_exact(&mut got))
        .await
        .expect("read timeout")
        .expect("read");
    assert_eq!(got, payload, "512 KiB payload must be byte-exact");
    dial_handle.await.expect("dial task");
}

/// Bind a KCP listener on the address family a `localhost` dial will use.
///
/// `dial_kcp` and `dial_server`'s KCP arm pick the address Go's
/// `net.ResolveUDPAddr` — what kcp-go's `Dial` uses — returns, by
/// `addrList.forResolve` (`net/ipsock.go:79-107`): IPv4 is preferred, and the
/// list's first entry is used only when the name has no IPv4 address. That is
/// not the resolver's first entry on this platform (macOS answers `::1` before
/// `127.0.0.1`), so a listener hardcoded to `127.0.0.1` would still be right
/// here but wrong on an IPv6-only `localhost`; binding the family the dialer
/// actually picks keeps the assertion about frp-rs's hostname handling rather
/// than about the host's address stack.
async fn bind_where_go_resolves_localhost(config: KcpConfig) -> KcpListener {
    let peers: Vec<std::net::SocketAddr> = tokio::net::lookup_host("localhost:0")
        .await
        .expect("resolve localhost")
        .collect();
    assert!(
        !peers.is_empty(),
        "localhost must resolve to at least one address"
    );
    let go_peer = peers
        .iter()
        .find(|peer| peer.is_ipv4())
        .copied()
        .unwrap_or(peers[0]);
    let bind = if go_peer.is_ipv4() {
        "127.0.0.1:0"
    } else {
        "[::1]:0"
    };
    KcpListener::bind(bind, config).await.expect("bind")
}

/// Regression: a KCP dial target may be a **hostname**, not a literal socket
/// address. `dial_kcp_with_driver` used to `addr.parse::<SocketAddr>()`
/// unconditionally, so `serverAddr = "kr.cdf.mba"` + `transport.protocol =
/// "kcp"` died one layer up as `transport error: KCP dial: invalid socket
/// address syntax` with no UDP socket ever bound and zero packets sent, while
/// the same domain worked on TCP/TLS/WS/QUIC. Go's kcp-go `Dial(raddr string)`
/// goes through `net.ResolveUDPAddr`, so a hostname is a valid target.
#[tokio::test(flavor = "multi_thread")]
async fn test_kcp_dial_hostname_round_trip() {
    let config = no_fec_config();
    let mut listener = bind_where_go_resolves_localhost(config.clone()).await;
    let addr = format!("localhost:{}", listener.local_addr().unwrap().port());

    // Allow driver event loops to start.
    sleep(Duration::from_millis(50)).await;

    let dial_handle = tokio::spawn(async move {
        let mut stream = timeout(Duration::from_secs(10), dial_kcp(&addr, config))
            .await
            .expect("dial timeout")
            .expect("dial_kcp must accept a hostname");
        stream
            .write_all(b"hello via hostname")
            .await
            .expect("write");
        stream.shutdown().await.expect("shutdown");
    });

    let mut stream = timeout(Duration::from_secs(10), listener.accept())
        .await
        .expect("accept timeout")
        .expect("accept");
    let mut buf = vec![0u8; 64];
    let n = timeout(Duration::from_secs(10), stream.read(&mut buf))
        .await
        .expect("read timeout")
        .expect("read");
    assert_eq!(&buf[..n], b"hello via hostname");
    dial_handle.await.expect("dial task");
}

/// Regression at the layer a user's config actually reaches:
/// `dial_server` with `serverAddr = "localhost"`, `transport.protocol = "kcp"`
/// and no `dns_server`. The KCP arm rebuilt the address from the *unresolved*
/// `serverAddr` (`format!("{target_ip}:{port}")`) and handed that to
/// `dial_kcp`, so the hostname failed before a socket existed — the reported
/// `frpc 不支持域名` symptom. The arm now dials the address `dial_server`
/// resolved once for every transport.
#[tokio::test(flavor = "multi_thread")]
async fn test_kcp_dial_server_accepts_a_hostname() {
    use frp_core::kcp::default_kcp_client_config;
    use frp_core::transport::{dial_server, DialOptions, TransportProtocol};

    // dial_server's KCP arm builds its client config with
    // default_kcp_client_config (FEC 10,3); the listener must match or the
    // FEC-wrapped packets are unparseable.
    let config = default_kcp_client_config();
    let mut listener = bind_where_go_resolves_localhost(config).await;
    let port = listener.local_addr().unwrap().port();

    // Allow driver event loops to start.
    sleep(Duration::from_millis(50)).await;

    let server = tokio::spawn(async move {
        let mut stream = timeout(Duration::from_secs(10), listener.accept())
            .await
            .expect("accept timeout")
            .expect("accept");
        let mut buf = vec![0u8; 64];
        let n = timeout(Duration::from_secs(10), stream.read(&mut buf))
            .await
            .expect("read timeout")
            .expect("read");
        assert_eq!(&buf[..n], b"hello via dial_server hostname");
    });

    let opts = DialOptions {
        server_addr: "localhost".to_string(),
        server_port: port,
        protocol: TransportProtocol::Kcp,
        ..Default::default()
    };
    let mut io = timeout(Duration::from_secs(10), dial_server(&opts))
        .await
        .expect("dial timeout")
        .expect("dial_server must accept a hostname on KCP");
    io.write_all(b"hello via dial_server hostname")
        .await
        .expect("write");
    io.flush().await.expect("flush");
    server.await.expect("server task");
}

/// Regression: a bare IPv6 literal is a valid `serverAddr` on KCP.
///
/// Before the fix this configuration could not work at any layer: the KCP arm
/// string-formatted the address into `"::1:<port>"`, which is not a parseable
/// socket address, and the dial socket was bound to `0.0.0.0:0` no matter what
/// the remote's family was, so an `AF_INET6` remote was unreachable even once
/// resolved (a cross-family datagram is dropped without an error — see the
/// socket-family note in `frp-core/src/kcp/listener.rs`). This test pins the
/// IPv6 branch of the family-aware bind, which the two `localhost` tests above
/// only reach on a host whose resolver returns IPv6 first: here the remote is
/// unambiguously IPv6 on every platform. The CI lane that runs this target
/// (`cargo test -p frp-core`, ubuntu-latest) provides an IPv6 loopback.
#[tokio::test(flavor = "multi_thread")]
async fn test_kcp_dial_server_accepts_a_bare_ipv6_literal() {
    use frp_core::kcp::default_kcp_client_config;
    use frp_core::transport::{dial_server, DialOptions, TransportProtocol};

    let config = default_kcp_client_config();
    let mut listener = KcpListener::bind("[::1]:0", config)
        .await
        .expect("bind [::1]:0 — an IPv6 loopback is required by this test");
    let port = listener.local_addr().unwrap().port();

    // Allow driver event loops to start.
    sleep(Duration::from_millis(50)).await;

    let server = tokio::spawn(async move {
        let mut stream = timeout(Duration::from_secs(10), listener.accept())
            .await
            .expect("accept timeout")
            .expect("accept");
        let mut buf = vec![0u8; 64];
        let n = timeout(Duration::from_secs(10), stream.read(&mut buf))
            .await
            .expect("read timeout")
            .expect("read");
        assert_eq!(&buf[..n], b"hello over a bare IPv6 literal");
    });

    let opts = DialOptions {
        server_addr: "::1".to_string(),
        server_port: port,
        protocol: TransportProtocol::Kcp,
        ..Default::default()
    };
    let mut io = timeout(Duration::from_secs(10), dial_server(&opts))
        .await
        .expect("dial timeout")
        .expect("dial_server must accept a bare IPv6 literal on KCP");
    io.write_all(b"hello over a bare IPv6 literal")
        .await
        .expect("write");
    io.flush().await.expect("flush");
    server.await.expect("server task");
}
