//! Go parity for a `serverAddr` that resolves to more than one address.
//!
//! Go resolves every address and, for TCP, tries them in sequence
//! (`net/dial.go:552-560`, `:659-745`); for UDP it returns one address by
//! `addrList.forResolve` (`net/ipsock.go:79-107`: IPv4 preferred unless the
//! dialled string is a bracketed IPv6 literal). frp-rs used the resolver's
//! *first* entry for every transport, so `serverAddr = "localhost"` on a host
//! whose resolver answers `[::1]` first never reached an IPv4-only `frps`
//! (`TODO.md`'s residual of the KCP-hostname round).
//!
//! Both tests below bind their listener on only **one** address, chosen from
//! the host's own resolver output, so they assert the selection rather than
//! "some loopback address is reachable".

use std::net::SocketAddr;
use std::time::Duration;

use frp_core::transport::{dial_server, DialOptions, TransportProtocol};
use tokio::net::{lookup_host, TcpListener};
use tokio::time::timeout;

/// The addresses `localhost` resolves to on this host, in resolver order.
async fn localhost_peers() -> Vec<SocketAddr> {
    lookup_host("localhost:7000")
        .await
        .expect("resolve localhost")
        .collect()
}

fn dial_opts(port: u16, protocol: TransportProtocol) -> DialOptions {
    DialOptions {
        server_addr: "localhost".to_string(),
        server_port: port,
        protocol,
        tls_enable: false,
        dial_timeout_secs: 5,
        ..DialOptions::default()
    }
}

/// Go's `net.Dial` tries the second resolved address when the first has no
/// listener. Before this change `dial_server` took `.next()` and returned the
/// first address's `Connection refused`.
#[tokio::test]
async fn tcp_dial_falls_back_to_the_second_resolved_address() {
    let peers = localhost_peers().await;
    let first_family_is_v4 = peers[0].is_ipv4();
    let Some(second_family) = peers
        .iter()
        .find(|peer| peer.is_ipv4() != first_family_is_v4)
        .copied()
    else {
        // A host whose `localhost` has one family cannot distinguish the old
        // behaviour from the new one; say so instead of passing silently.
        eprintln!("skipped: localhost resolves to one family only: {peers:?}");
        return;
    };

    let listener = TcpListener::bind(SocketAddr::new(second_family.ip(), 0))
        .await
        .expect("bind the second resolved family");
    let port = listener.local_addr().unwrap().port();
    let accept = tokio::spawn(async move { listener.accept().await.map(|_| ()) });

    let io = timeout(
        Duration::from_secs(10),
        dial_server(&dial_opts(port, TransportProtocol::Tcp)),
    )
    .await
    .expect("dial timed out")
    .expect("dial should reach the second resolved address");
    drop(io);

    timeout(Duration::from_secs(10), accept)
        .await
        .expect("listener never accepted: the fallback address was not dialled")
        .expect("accept task panicked")
        .expect("listener should have accepted the fallback connection");
}

/// Go's `net.ResolveUDPAddr` — what kcp-go's `Dial` uses — returns the IPv4
/// address of a dual-stack name (`measured: 127.0.0.1 for localhost`), not the
/// resolver's first entry. KCP gets no second attempt, so binding only that
/// address is what pins the choice.
///
/// On base (`main`) this test is red twice over: the hostname was rejected by
/// a bare `addr.parse::<SocketAddr>()`, and after that fix the resolver's first
/// entry (`[::1]`) was dialled into a black hole (`KCP session dead link`).
#[cfg(feature = "kcp")]
#[tokio::test(flavor = "multi_thread")]
async fn kcp_dial_uses_the_address_go_resolves() {
    use frp_core::kcp::{default_kcp_config, KcpListener};

    let peers = localhost_peers().await;
    // Go prefers IPv4; with no IPv4 address it returns the first entry.
    let go_peer = peers
        .iter()
        .find(|peer| peer.is_ipv4())
        .copied()
        .unwrap_or(peers[0]);
    if peers.len() == 1 {
        eprintln!("note: localhost resolves to a single address on this host: {peers:?}");
    }

    let mut listener = KcpListener::bind(
        &SocketAddr::new(go_peer.ip(), 0).to_string(),
        default_kcp_config(),
    )
    .await
    .expect("bind the address Go resolves to");
    let port = listener.local_addr().unwrap().port();
    let accept = tokio::spawn(async move { listener.accept().await.map(|_| ()) });

    let mut io = timeout(
        Duration::from_secs(10),
        dial_server(&dial_opts(port, TransportProtocol::Kcp)),
    )
    .await
    .expect("KCP dial timed out (the address dialled was not the one bound)")
    .expect("KCP dial should use the address Go's ResolveUDPAddr returns");
    // KCP's dial returns before the handshake completes: the first write is
    // what sends the session's probe, and the listener's `accept` resolves only
    // once that arrives (see `frp-core/tests/kcp.rs`).
    {
        use tokio::io::AsyncWriteExt;
        io.write_all(b"ping").await.expect("KCP first write");
        io.flush().await.expect("KCP flush");
    }
    drop(io);

    timeout(Duration::from_secs(10), accept)
        .await
        .expect("KCP listener never accepted: the wrong address was dialled")
        .expect("accept task panicked")
        .expect("KCP listener should have accepted the dial");
}
