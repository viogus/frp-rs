//! Integration tests for the `socks5` plugin's UDP ASSOCIATE relay
//! (RFC 1928 §7, frp-rs extension).
//!
//! These drive the plugin directly (like `plugin_socks5.rs`): a real SOCKS5
//! TCP control connection performs the handshake and UDP ASSOCIATE, then a
//! UDP socket exchanges SOCKS5-framed datagrams with the advertised relay.

use std::net::SocketAddr;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

use frp_core::config::PluginConfig;

const SOCKS5_VERSION: u8 = 5;
const AUTH_NO_AUTH: u8 = 0;
const AUTH_USER_PASS: u8 = 2;
const USERPASS_VERSION: u8 = 1;
const CMD_UDP_ASSOCIATE: u8 = 3;
const ATYP_IPV4: u8 = 1;
const ATYP_DOMAIN: u8 = 3;

const TIMEOUT: Duration = Duration::from_secs(2);

async fn start_udp_echo_backend() -> SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 2048];
        while let Ok((n, from)) = socket.recv_from(&mut buf).await {
            let _ = socket.send_to(&buf[..n], from).await;
        }
    });
    addr
}

fn plugin_cfg() -> PluginConfig {
    PluginConfig {
        plugin_type: "socks5".into(),
        udp_enable: true,
        udp_bind_addr: "127.0.0.1:0".into(),
        ..Default::default()
    }
}

async fn open_control(proxy: SocketAddr, credentials: Option<(&str, &str)>) -> TcpStream {
    let mut s = TcpStream::connect(proxy).await.unwrap();
    match credentials {
        None => {
            s.write_all(&[SOCKS5_VERSION, 1, AUTH_NO_AUTH])
                .await
                .unwrap();
            let mut reply = [0u8; 2];
            s.read_exact(&mut reply).await.unwrap();
            assert_eq!(reply, [SOCKS5_VERSION, AUTH_NO_AUTH]);
        }
        Some((u, p)) => {
            s.write_all(&[SOCKS5_VERSION, 1, AUTH_USER_PASS])
                .await
                .unwrap();
            let mut reply = [0u8; 2];
            s.read_exact(&mut reply).await.unwrap();
            assert_eq!(reply, [SOCKS5_VERSION, AUTH_USER_PASS]);
            let (u, p) = (u.as_bytes(), p.as_bytes());
            let mut sub = vec![USERPASS_VERSION, u.len() as u8];
            sub.extend_from_slice(u);
            sub.push(p.len() as u8);
            sub.extend_from_slice(p);
            s.write_all(&sub).await.unwrap();
            let mut status = [0u8; 2];
            s.read_exact(&mut status).await.unwrap();
            assert_eq!(status, [USERPASS_VERSION, 0]);
        }
    }
    s
}

/// Perform UDP ASSOCIATE and return (control connection, advertised relay).
/// The control connection must be kept alive for the association.
async fn udp_associate(
    proxy: SocketAddr,
    credentials: Option<(&str, &str)>,
) -> (TcpStream, SocketAddr) {
    let mut s = open_control(proxy, credentials).await;
    // DST.ADDR/DST.PORT is the client's expected UDP source; all-zero is the
    // common "not bound yet" form and is accepted.
    let req = [
        SOCKS5_VERSION,
        CMD_UDP_ASSOCIATE,
        0,
        ATYP_IPV4,
        0,
        0,
        0,
        0,
        0,
        0,
    ];
    s.write_all(&req).await.unwrap();

    let mut head = [0u8; 4];
    s.read_exact(&mut head).await.unwrap();
    assert_eq!(head[0], SOCKS5_VERSION, "reply version");
    assert_eq!(
        head[1], 0,
        "UDP ASSOCIATE must succeed, got REP {}",
        head[1]
    );
    let addr = match head[3] {
        ATYP_IPV4 => {
            let mut rest = [0u8; 6];
            s.read_exact(&mut rest).await.unwrap();
            let ip = std::net::Ipv4Addr::new(rest[0], rest[1], rest[2], rest[3]);
            let port = u16::from_be_bytes([rest[4], rest[5]]);
            SocketAddr::new(ip.into(), port)
        }
        ATYP_DOMAIN => {
            let mut len = [0u8; 1];
            s.read_exact(&mut len).await.unwrap();
            let mut name = vec![0u8; len[0] as usize + 2];
            s.read_exact(&mut name).await.unwrap();
            let host = std::str::from_utf8(&name[..len[0] as usize]).unwrap();
            let port = u16::from_be_bytes([name[len[0] as usize], name[len[0] as usize + 1]]);
            let ip: std::net::IpAddr = host.parse().expect("reply domain must be an IP literal");
            SocketAddr::new(ip, port)
        }
        other => panic!("unexpected BND.ATYP {other:#x}"),
    };
    (s, addr)
}

/// Build a SOCKS5 UDP request with an IPv4 destination.
fn framed_ipv4(target: SocketAddr, payload: &[u8]) -> Vec<u8> {
    let SocketAddr::V4(v4) = target else {
        panic!("expected IPv4 target");
    };
    let mut out = vec![0, 0, 0, ATYP_IPV4];
    out.extend_from_slice(&v4.ip().octets());
    out.extend_from_slice(&v4.port().to_be_bytes());
    out.extend_from_slice(payload);
    out
}

/// Build a SOCKS5 UDP request with an IPv6 destination.
fn framed_ipv6(target: SocketAddr, payload: &[u8]) -> Vec<u8> {
    let SocketAddr::V6(v6) = target else {
        panic!("expected IPv6 target");
    };
    let mut out = vec![0, 0, 0, 0x04];
    out.extend_from_slice(&v6.ip().octets());
    out.extend_from_slice(&v6.port().to_be_bytes());
    out.extend_from_slice(payload);
    out
}

/// Build a SOCKS5 UDP request with a domain destination.
fn framed_domain(host: &str, port: u16, payload: &[u8]) -> Vec<u8> {
    assert!(host.len() < 256);
    let mut out = vec![0, 0, 0, ATYP_DOMAIN, host.len() as u8];
    out.extend_from_slice(host.as_bytes());
    out.extend_from_slice(&port.to_be_bytes());
    out.extend_from_slice(payload);
    out
}

fn unframe(data: &[u8]) -> (&[u8], &[u8]) {
    assert!(data.len() >= 4, "short UDP reply");
    assert_eq!(&data[..3], &[0, 0, 0], "RSV/FRAG must be zero");
    let header_len = match data[3] {
        ATYP_IPV4 => 10,
        ATYP_DOMAIN => {
            assert!(data.len() >= 5);
            7 + data[4] as usize
        }
        0x04 => 22,
        other => panic!("unexpected reply ATYP {other:#x}"),
    };
    assert!(data.len() >= header_len, "truncated UDP reply header");
    (&data[3..header_len], &data[header_len..])
}

async fn recv_with_timeout(sock: &UdpSocket) -> Option<Vec<u8>> {
    let mut buf = vec![0u8; 4096];
    match tokio::time::timeout(TIMEOUT, sock.recv_from(&mut buf)).await {
        Ok(Ok((n, _))) => Some(buf[..n].to_vec()),
        _ => None,
    }
}

#[tokio::test]
async fn udp_associate_ipv4_round_trip() {
    let backend = start_udp_echo_backend().await;
    let handle = frp_client::plugin::start_socks5_proxy(&plugin_cfg())
        .await
        .expect("start socks5 plugin");

    let (_control, relay) = udp_associate(handle.local_addr, None).await;
    assert!(relay.ip().is_loopback(), "relay should advertise loopback");

    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let request = framed_ipv4(backend, b"hello-udp");
    client.send_to(&request, relay).await.unwrap();

    // The companion deployment's frpc bridge is `connect()`ed to BND.ADDR, so
    // the reply MUST come from the advertised relay socket. A mutant that
    // replies from the per-client outbound socket passes the payload checks
    // but is dropped by the kernel on that deployment.
    let mut buf = vec![0u8; 4096];
    let (n, src) = tokio::time::timeout(TIMEOUT, client.recv_from(&mut buf))
        .await
        .expect("UDP reply timed out")
        .expect("UDP recv");
    assert_eq!(src, relay, "reply source must be the advertised relay");
    let reply = buf[..n].to_vec();
    let (header, payload) = unframe(&reply);
    assert_eq!(payload, b"hello-udp", "echo through the UDP relay");
    let SocketAddr::V4(v4) = backend else {
        unreachable!()
    };
    let mut expected = vec![ATYP_IPV4];
    expected.extend_from_slice(&v4.ip().octets());
    expected.extend_from_slice(&v4.port().to_be_bytes());
    assert_eq!(header, &expected[..], "reply echoes the requested target");
}

#[tokio::test]
async fn udp_associate_ipv6_target_round_trip() {
    // The advertised relay is IPv4 (127.0.0.1); the target is IPv6. This
    // exercises the per-family outbound socket path.
    let Ok(backend) = UdpSocket::bind("[::1]:0").await else {
        eprintln!("Skipping test: IPv6 loopback unavailable");
        return;
    };
    let backend_addr = backend.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 2048];
        while let Ok((n, from)) = backend.recv_from(&mut buf).await {
            let _ = backend.send_to(&buf[..n], from).await;
        }
    });

    let handle = frp_client::plugin::start_socks5_proxy(&plugin_cfg())
        .await
        .expect("start socks5 plugin");
    let (_control, relay) = udp_associate(handle.local_addr, None).await;
    assert!(relay.is_ipv4(), "test expects the IPv4 relay");

    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    client
        .send_to(&framed_ipv6(backend_addr, b"ipv6-udp"), relay)
        .await
        .unwrap();
    let reply = recv_with_timeout(&client)
        .await
        .expect("UDP reply timed out");
    let (header, payload) = unframe(&reply);
    assert_eq!(payload, b"ipv6-udp");
    assert_eq!(header[0], 0x04, "reply header must be IPv6");
    assert_eq!(
        &header[1..17],
        &backend_addr
            .ip()
            .to_string()
            .parse::<std::net::Ipv6Addr>()
            .unwrap()
            .octets()
    );
    assert_eq!(
        u16::from_be_bytes([header[17], header[18]]),
        backend_addr.port()
    );
}

#[tokio::test]
async fn udp_associate_domain_target_round_trip() {
    let backend = start_udp_echo_backend().await;
    let handle = frp_client::plugin::start_socks5_proxy(&plugin_cfg())
        .await
        .expect("start socks5 plugin");

    let (_control, relay) = udp_associate(handle.local_addr, None).await;
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let request = framed_domain("127.0.0.1", backend.port(), b"domain-target");
    client.send_to(&request, relay).await.unwrap();

    let reply = recv_with_timeout(&client)
        .await
        .expect("UDP reply timed out");
    let (header, payload) = unframe(&reply);
    assert_eq!(payload, b"domain-target");
    // RFC 1928 §7: the reply header names the host that sent the datagram, so
    // a domain request is answered with the resolved IP (not the domain).
    assert_eq!(header[0], ATYP_IPV4);
    assert_eq!(&header[1..5], &[127, 0, 0, 1]);
    assert_eq!(u16::from_be_bytes([header[5], header[6]]), backend.port());
}

#[tokio::test]
async fn udp_associate_advertises_configured_public_address() {
    // The companion-UDP-proxy deployment: the relay binds loopback, but the
    // client must be told the frps public address:UDP port.
    let cfg = PluginConfig {
        udp_advertise_addr: "203.0.113.10:7001".into(),
        ..plugin_cfg()
    };
    let handle = frp_client::plugin::start_socks5_proxy(&cfg)
        .await
        .expect("start socks5 plugin");
    let (_control, relay) = udp_associate(handle.local_addr, None).await;
    assert_eq!(relay, "203.0.113.10:7001".parse().unwrap());
}

#[tokio::test]
async fn udp_associate_requires_tcp_auth() {
    let backend = start_udp_echo_backend().await;
    let cfg = PluginConfig {
        username: "alice".into(),
        password: "s3cret".into(),
        ..plugin_cfg()
    };
    let handle = frp_client::plugin::start_socks5_proxy(&cfg)
        .await
        .expect("start socks5 plugin");

    // A client offering only NO_AUTH must be rejected before UDP exists.
    let mut no_auth = TcpStream::connect(handle.local_addr).await.unwrap();
    no_auth
        .write_all(&[SOCKS5_VERSION, 1, AUTH_NO_AUTH])
        .await
        .unwrap();
    let mut method = [0u8; 2];
    no_auth.read_exact(&mut method).await.unwrap();
    assert_eq!(method, [SOCKS5_VERSION, 0xFF], "no acceptable method");

    // Correct credentials get an association and can relay.
    let (_control, relay) = udp_associate(handle.local_addr, Some(("alice", "s3cret"))).await;
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    client
        .send_to(&framed_ipv4(backend, b"authed"), relay)
        .await
        .unwrap();
    let reply = recv_with_timeout(&client)
        .await
        .expect("UDP reply timed out");
    assert_eq!(unframe(&reply).1, b"authed");
}

#[tokio::test]
async fn udp_associate_two_clients_same_target_keep_their_replies() {
    let backend = start_udp_echo_backend().await;
    let handle = frp_client::plugin::start_socks5_proxy(&plugin_cfg())
        .await
        .expect("start socks5 plugin");

    let (_control_a, relay_a) = udp_associate(handle.local_addr, None).await;
    let (_control_b, relay_b) = udp_associate(handle.local_addr, None).await;
    assert_eq!(relay_a, relay_b, "all associations share one relay address");

    let a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    a.send_to(&framed_ipv4(backend, b"from-a"), relay_a)
        .await
        .unwrap();
    b.send_to(&framed_ipv4(backend, b"from-b"), relay_b)
        .await
        .unwrap();

    assert_eq!(
        unframe(&recv_with_timeout(&a).await.expect("a timeout")).1,
        b"from-a"
    );
    assert_eq!(
        unframe(&recv_with_timeout(&b).await.expect("b timeout")).1,
        b"from-b"
    );
}

#[tokio::test]
async fn udp_relay_stops_when_control_connection_closes() {
    let backend = start_udp_echo_backend().await;
    let handle = frp_client::plugin::start_socks5_proxy(&plugin_cfg())
        .await
        .expect("start socks5 plugin");

    let (control, relay) = udp_associate(handle.local_addr, None).await;
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    client
        .send_to(&framed_ipv4(backend, b"before-close"), relay)
        .await
        .unwrap();
    assert_eq!(
        unframe(&recv_with_timeout(&client).await.expect("first timeout")).1,
        b"before-close"
    );

    drop(control);
    // Give the plugin handler a moment to observe EOF and drop the guard.
    tokio::time::sleep(Duration::from_millis(200)).await;
    client
        .send_to(&framed_ipv4(backend, b"after-close"), relay)
        .await
        .unwrap();
    assert!(
        recv_with_timeout(&client).await.is_none(),
        "the relay must not forward after the association's control connection closes"
    );
}

#[tokio::test]
async fn udp_gate_is_per_plugin_not_per_association() {
    // Documented limitation (docs/client-plugins.md § UDP ASSOCIATE): the RFC
    // framing carries no association identity, so the gate is "at least one
    // live association", not "this source's association is live". Pin it so a
    // future change either fixes it or changes the docs deliberately.
    let backend = start_udp_echo_backend().await;
    let handle = frp_client::plugin::start_socks5_proxy(&plugin_cfg())
        .await
        .expect("start socks5 plugin");

    let (control_a, relay) = udp_associate(handle.local_addr, None).await;
    let (_control_b, _) = udp_associate(handle.local_addr, None).await;
    let a = UdpSocket::bind("127.0.0.1:0").await.unwrap();

    a.send_to(&framed_ipv4(backend, b"a-before"), relay)
        .await
        .unwrap();
    assert_eq!(
        unframe(&recv_with_timeout(&a).await.expect("a-before timeout")).1,
        b"a-before"
    );

    drop(control_a);
    tokio::time::sleep(Duration::from_millis(200)).await;
    a.send_to(&framed_ipv4(backend, b"a-after"), relay)
        .await
        .unwrap();
    assert_eq!(
        unframe(&recv_with_timeout(&a).await.expect("a-after timeout")).1,
        b"a-after",
        "while another association is live, a closed association's source is still accepted"
    );
}

#[tokio::test]
async fn dropping_plugin_handle_releases_udp_relay_port() {
    // Lazy binding must not leak the socket when the plugin is dropped: the
    // cancellation token is what releases the port on reload/shutdown.
    let probe = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let port = probe.local_addr().unwrap().port();
    drop(probe);

    let cfg = PluginConfig {
        udp_bind_addr: format!("127.0.0.1:{port}"),
        ..plugin_cfg()
    };
    let handle = frp_client::plugin::start_socks5_proxy(&cfg)
        .await
        .expect("start socks5 plugin");
    let (control, relay) = udp_associate(handle.local_addr, None).await;
    assert_eq!(
        relay.port(),
        port,
        "relay must bind the configured fixed port"
    );

    drop(control);
    drop(handle);
    for _ in 0..100 {
        if UdpSocket::bind(("127.0.0.1", port)).await.is_ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("UDP relay port {port} was not released after the plugin handle was dropped");
}

#[tokio::test]
async fn udp_relay_drops_fragmented_datagrams() {
    let backend = start_udp_echo_backend().await;
    let handle = frp_client::plugin::start_socks5_proxy(&plugin_cfg())
        .await
        .expect("start socks5 plugin");

    let (_control, relay) = udp_associate(handle.local_addr, None).await;
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();

    let mut request = framed_ipv4(backend, b"fragmented");
    request[2] = 1; // FRAG
    client.send_to(&request, relay).await.unwrap();
    assert!(
        recv_with_timeout(&client).await.is_none(),
        "a fragmented request (FRAG != 0) must be dropped"
    );

    // The association is still usable for unfragmented datagrams.
    client
        .send_to(&framed_ipv4(backend, b"ok"), relay)
        .await
        .unwrap();
    assert_eq!(
        unframe(&recv_with_timeout(&client).await.expect("ok timeout")).1,
        b"ok"
    );
}

#[tokio::test]
async fn udp_disabled_keeps_connect_only_behaviour() {
    let handle = frp_client::plugin::start_socks5_proxy(&PluginConfig {
        plugin_type: "socks5".into(),
        ..Default::default()
    })
    .await
    .expect("start socks5 plugin");

    let mut s = open_control(handle.local_addr, None).await;
    let req = [
        SOCKS5_VERSION,
        CMD_UDP_ASSOCIATE,
        0,
        ATYP_IPV4,
        0,
        0,
        0,
        0,
        0,
        0,
    ];
    s.write_all(&req).await.unwrap();
    let mut reply = [0u8; 4];
    s.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[1], 0x07, "UDP disabled -> REP_CMD_NOT_SUPPORTED");
}
