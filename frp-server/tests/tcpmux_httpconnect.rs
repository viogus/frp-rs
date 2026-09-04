//! TCPMux HTTP-CONNECT listener e2e coverage (wave-3 round): oversized-header
//! silent close (T2), pipelined-payload byte-exact forwarding (R4),
//! Proxy-Authorization verbatim-payload parity (T12), and HTTP-group fan-out
//! semantics (R2). Helpers are file-local by integration-test convention.

mod common;

use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use common::{allocate_port, login_with_test_token, start_test_server, test_auth_cfg};
use frp_core::config::ServerConfig;
use frp_core::msg::{self, FrpMessage, NewProxy};
use frp_core::protocol::{read_msg_v1, write_msg_v1};

/// Construct a tcpmux NewProxy with minimal fields.
fn tcpmux_proxy(name: &str, domains: Vec<String>, local: &str) -> NewProxy {
    NewProxy {
        proxy_name: name.into(),
        proxy_type: "tcpmux".into(),
        sk: None,
        use_encryption: None,
        use_compression: None,
        group: None,
        group_key: None,
        local_str: Some(local.into()),
        remote_port: Some(0),
        custom_domains: Some(domains),
        subdomain: None,
        locations: None,
        http_user: None,
        http_pwd: None,
        host_header_rewrite: None,
        headers: None,
        response_headers: None,
        route_by_http_user: None,
        allow_users: None,
        bandwidth_limit: None,
        bandwidth_limit_mode: None,
        annotations: None,
        metas: None,
        multiplexer: Some("httpconnect".into()),
        virtual_net: None,
        proxy_protocol_version: None,
        advertise_subnet: None,
        vnet_ip: None,
        vnet_netmask: None,
        vnet_mtu: None,
    }
}

/// Read raw bytes until the header terminator (`\r\n\r\n`) is in the buffer
/// (or the peer closes). Loopback reads of small responses can arrive split.
async fn read_full_response(stream: &mut tokio::net::TcpStream) -> Vec<u8> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 128];
    loop {
        if buf.ends_with(b"\r\n\r\n") {
            return buf;
        }
        let n = tokio::time::timeout(std::time::Duration::from_secs(2), stream.read(&mut chunk))
            .await
            .expect("timeout waiting for the HTTP response")
            .expect("read HTTP response");
        assert!(
            n > 0,
            "EOF before the full response (got {:?})",
            String::from_utf8_lossy(&buf)
        );
        buf.extend_from_slice(&chunk[..n]);
    }
}

/// Register a proxy and return the NewProxyResp error (None = accepted).
async fn register_proxy(
    stream: &mut frp_core::transport::IoStream,
    np: NewProxy,
) -> Option<String> {
    write_msg_v1(stream, &FrpMessage::NewProxy(Box::new(np)))
        .await
        .expect("send NewProxy");
    match read_msg_v1(stream).await.expect("read NewProxyResp") {
        FrpMessage::NewProxyResp(ref r) => r.error.clone(),
        other => panic!("expected NewProxyResp, got {:?}", other.v1_type_byte()),
    }
}

/// Open a pooled work conn for a run_id (the server sends StartWorkConn on it
/// only once a CONNECT is dispatched).
async fn open_work_conn(addr: SocketAddr, run_id: &str) -> tokio::net::TcpStream {
    let mut work = tokio::net::TcpStream::connect(addr)
        .await
        .expect("work conn connect");
    write_msg_v1(
        &mut work,
        &FrpMessage::NewWorkConn(msg::NewWorkConn {
            run_id: Some(run_id.to_string()),
            timestamp: None,
            privilege_key: None,
        }),
    )
    .await
    .expect("send NewWorkConn");
    work
}

/// Assert the server closed a connection SILENTLY: the read yields EOF (0
/// bytes) or RST — the drop-with-unread-inbound-data case on loopback —
/// and never any HTTP response bytes.
async fn expect_silent_close(stream: &mut tokio::net::TcpStream, what: &str) {
    let mut buf = [0u8; 1024];
    let r = tokio::time::timeout(std::time::Duration::from_secs(3), stream.read(&mut buf))
        .await
        .unwrap_or_else(|_| {
            panic!("server must close the oversized connection within 3s ({what})")
        });
    match r {
        Ok(0) => {}
        Ok(n) => panic!(
            "{what} must be closed silently (got {} bytes: {:?})",
            n,
            String::from_utf8_lossy(&buf[..n])
        ),
        Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => {}
        Err(e) => panic!("{what}: read error: {e}"),
    }
}

/// Send one CONNECT to the tcpmux listener and read the full status response.
async fn send_connect(tcpmux_addr: SocketAddr, request: &[u8]) -> (tokio::net::TcpStream, String) {
    let mut client = tokio::net::TcpStream::connect(tcpmux_addr)
        .await
        .expect("connect to tcpmux port");
    client.write_all(request).await.expect("send CONNECT");
    let response = read_full_response(&mut client).await;
    let text = String::from_utf8_lossy(&response).into_owned();
    (client, text)
}

/// Read the StartWorkConn frame the server sends on a pooled work conn when a
/// CONNECT is dispatched to it (bounded — panic with context on timeout).
async fn read_start_work_conn(work: &mut tokio::net::TcpStream, what: &str) -> String {
    let msg = tokio::time::timeout(std::time::Duration::from_secs(3), read_msg_v1(work))
        .await
        .unwrap_or_else(|_| panic!("timeout waiting for StartWorkConn ({what})"))
        .unwrap_or_else(|_| panic!("read StartWorkConn failed ({what})"));
    match msg {
        FrpMessage::StartWorkConn(swc) => {
            assert!(
                swc.error.is_none(),
                "StartWorkConn error ({what}): {:?}",
                swc.error
            );
            swc.proxy_name
        }
        other => panic!(
            "expected StartWorkConn ({what}), got: {:?}",
            other.v1_type_byte()
        ),
    }
}

/// T2: a CONNECT whose header block exceeds the 4 KiB shared-listener buffer
/// must be closed SILENTLY — no 4xx/200 status bytes, no route dispatch —
/// whether or not the block contains a terminator (an oversized block is never
/// parsed, so the terminator position is irrelevant).
#[tokio::test]
async fn test_tcpmux_oversized_headers_silent_close() {
    let bind_port = allocate_port();
    let tcpmux_port = allocate_port();
    let cfg = ServerConfig {
        bind_addr: "127.0.0.1".into(),
        bind_port,
        tcpmux_httpconnect_port: tcpmux_port,
        auth: test_auth_cfg(),
        ..Default::default()
    };
    let (_handle, _) = start_test_server(cfg).await;
    let addr: SocketAddr = format!("127.0.0.1:{}", bind_port).parse().unwrap();
    let tcpmux_addr: SocketAddr = format!("127.0.0.1:{}", tcpmux_port).parse().unwrap();

    let (mut provider, resp) = login_with_test_token(addr).await.expect("provider login");
    let run_id = resp.run_id.expect("run_id");
    assert!(register_proxy(
        &mut provider,
        tcpmux_proxy(
            "tcpmux-oversize",
            vec!["oversize.example.com".into()],
            "127.0.0.1:22",
        ),
    )
    .await
    .is_none());

    // A pooled work conn proves the oversized CONNECT never reaches dispatch:
    // the server must not send StartWorkConn or any bytes on it.
    let mut work = open_work_conn(addr, &run_id).await;

    // Shape (a): 4608 bytes of headers, no terminator at all.
    let mut client = tokio::net::TcpStream::connect(tcpmux_addr)
        .await
        .expect("connect");
    let mut block = b"CONNECT oversize.example.com:22 HTTP/1.1\r\n".to_vec();
    block.extend(std::iter::repeat_n(b'X', 4096 + 512));
    client
        .write_all(&block)
        .await
        .expect("write oversized block");
    expect_silent_close(&mut client, "terminator-less oversized block").await;

    // Shape (b): a COMPLETE request whose header block (4100 bytes) exceeds
    // the 4 KiB buffer — terminator present but past the cap.
    let mut client2 = tokio::net::TcpStream::connect(tcpmux_addr)
        .await
        .expect("connect");
    let mut block = b"CONNECT oversize.example.com:22 HTTP/1.1\r\n".to_vec();
    block.extend(std::iter::repeat_n(b'X', 4096 + 4));
    block.extend_from_slice(b"\r\n\r\n");
    client2
        .write_all(&block)
        .await
        .expect("write oversized block");
    expect_silent_close(&mut client2, "terminated-but-oversized block").await;

    // Neither oversized CONNECT reached dispatch: the pooled work conn must
    // stay silent — no StartWorkConn, no forwarded bytes, conn still pooled.
    // The read timing out with NO bytes is the pass condition.
    let mut check = [0u8; 64];
    let r =
        tokio::time::timeout(std::time::Duration::from_millis(400), work.read(&mut check)).await;
    match r {
        Err(_elapsed) => {} // silent — exactly what an oversized block must produce
        Ok(Ok(0)) => panic!("pooled work conn hit EOF — it must stay pooled"),
        Ok(Ok(n)) => panic!(
            "oversized CONNECT was dispatched! work conn got {} bytes: {:?}",
            n,
            String::from_utf8_lossy(&check[..n])
        ),
        Ok(Err(e)) => panic!("pooled work conn read error: {e}"),
    }
}

/// R4: a CONNECT with payload bytes pipelined in the SAME write as the header
/// terminator must reach the backend byte-exact (the pre-read tail must not be
/// dropped, and no extra HTTP status bytes may leak into the stream).
#[tokio::test]
async fn test_tcpmux_connect_pipelined_payload_byte_exact() {
    let bind_port = allocate_port();
    let tcpmux_port = allocate_port();
    let cfg = ServerConfig {
        bind_addr: "127.0.0.1".into(),
        bind_port,
        tcpmux_httpconnect_port: tcpmux_port,
        auth: test_auth_cfg(),
        ..Default::default()
    };
    let (_handle, _) = start_test_server(cfg).await;
    let addr: SocketAddr = format!("127.0.0.1:{}", bind_port).parse().unwrap();
    let tcpmux_addr: SocketAddr = format!("127.0.0.1:{}", tcpmux_port).parse().unwrap();

    let (mut provider, resp) = login_with_test_token(addr).await.expect("provider login");
    let run_id = resp.run_id.expect("run_id");
    assert!(register_proxy(
        &mut provider,
        tcpmux_proxy(
            "tcpmux-pipelined",
            vec!["pipe.example.com".into()],
            "127.0.0.1:22",
        ),
    )
    .await
    .is_none());

    let mut work = open_work_conn(addr, &run_id).await;

    // One single write: CONNECT head + terminator + payload, no flush gap.
    let payload = b"PIPELINED-PAYLOAD-42!";
    let mut request =
        b"CONNECT pipe.example.com:22 HTTP/1.1\r\nHost: pipe.example.com:22\r\n\r\n".to_vec();
    request.extend_from_slice(payload);
    let (client, response) = send_connect(tcpmux_addr, &request).await;
    assert!(
        response.starts_with("HTTP/1.1 200"),
        "expected 200, got: {response:?}"
    );

    let proxy_name = read_start_work_conn(&mut work, "pipelined CONNECT").await;
    assert_eq!(proxy_name, "tcpmux-pipelined");

    // The pipelined payload arrives on the work conn byte-exact (either as
    // the pre-read tail or as subsequent tunnel data — both land here).
    let mut got = Vec::new();
    let mut buf = [0u8; 128];
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        while got.len() < payload.len() {
            let n = work.read(&mut buf).await.expect("read forwarded payload");
            assert!(n > 0, "EOF before the full pipelined payload ({got:?})");
            got.extend_from_slice(&buf[..n]);
        }
    })
    .await
    .expect("timeout waiting for the pipelined payload");
    assert_eq!(
        &got[..payload.len()],
        payload,
        "pipelined payload must arrive byte-exact"
    );
    assert!(
        !got.starts_with(b"HTTP/"),
        "no HTTP status bytes may leak into the tunnel: {got:?}"
    );

    drop(client);
    drop(work);
    drop(provider);
}

/// T12 e2e: Proxy-Authorization payload handling after "Basic " is verbatim
/// (Go pkg/util/http/http.go ParseBasicAuth parity) — interior whitespace
/// must fail auth. With no route_by_http_user configured the proxy registers
/// under the "" all-users bucket (Go getExactOrAllUsersLocked), so the parse
/// failure still MATCHES the route and then fails the per-proxy http_user
/// check. The response is Go successHook-before-checkAuth order (vhost.go
/// handle): the matched route's 200 OK lands first, THEN the fail-closed
/// 407 Proxy-Authenticate, then close — never a tunnel, never a bypass.
/// The 404 lookup-miss arm is covered by the route_by_http_user variant in
/// the route_user dashboard/control tests. Trailing OWS on the header line
/// is still stripped first (readMIMEHeader parity) → accepted.
#[tokio::test]
async fn test_tcpmux_proxy_auth_interior_space_rejected_407() {
    let bind_port = allocate_port();
    let tcpmux_port = allocate_port();
    let cfg = ServerConfig {
        bind_addr: "127.0.0.1".into(),
        bind_port,
        tcpmux_httpconnect_port: tcpmux_port,
        auth: test_auth_cfg(),
        ..Default::default()
    };
    let (_handle, _) = start_test_server(cfg).await;
    let addr: SocketAddr = format!("127.0.0.1:{}", bind_port).parse().unwrap();
    let tcpmux_addr: SocketAddr = format!("127.0.0.1:{}", tcpmux_port).parse().unwrap();

    let (mut provider, _resp) = login_with_test_token(addr).await.expect("provider login");
    let mut np = tcpmux_proxy(
        "auth-strict",
        vec!["auth-strict.example.com".into()],
        "127.0.0.1:8080",
    );
    np.http_user = Some("admin".into());
    np.http_pwd = Some("secret".into());
    assert!(register_proxy(&mut provider, np).await.is_none());

    // Single space: accepted (the canonical shape).
    let (_, response) = send_connect(
        tcpmux_addr,
        b"CONNECT auth-strict.example.com:443 HTTP/1.1\r\n\
          Host: auth-strict.example.com:443\r\n\
          Proxy-Authorization: Basic YWRtaW46c2VjcmV0\r\n\
          \r\n",
    )
    .await;
    assert!(response.starts_with("HTTP/1.1 200"), "got: {response:?}");

    // Double space after "Basic ": base64 decode must fail like Go
    // StdEncoding → the route's http_user check fails → 407 (fail-closed),
    // but AFTER the matched route's successHook 200 (Go write-order —
    // vhost.go handle: successHook runs before checkAuth). Assert both
    // statuses on the same conn, in Go order.
    let (_, response) = send_connect(
        tcpmux_addr,
        b"CONNECT auth-strict.example.com:443 HTTP/1.1\r\n\
          Host: auth-strict.example.com:443\r\n\
          Proxy-Authorization: Basic  YWRtaW46c2VjcmV0\r\n\
          \r\n",
    )
    .await;
    let ok_pos = response.find("HTTP/1.1 200 OK");
    let auth_pos = response.find("HTTP/1.1 407 Proxy Authentication Required");
    assert!(
        ok_pos.is_some_and(|p| auth_pos.is_some_and(|a| p < a)),
        "double-space credentials must be rejected: 200 (successHook) then 407, got: {response:?}"
    );

    // Trailing OWS on the header line: stripped before auth parsing
    // (readMIMEHeader parity) → single-space payload → accepted.
    let (_, response) = send_connect(
        tcpmux_addr,
        b"CONNECT auth-strict.example.com:443 HTTP/1.1\r\n\
          Host: auth-strict.example.com:443\r\n\
          Proxy-Authorization: Basic YWRtaW46c2VjcmV0 \t\r\n\
          \r\n",
    )
    .await;
    assert!(
        response.starts_with("HTTP/1.1 200"),
        "trailing OWS is stripped before auth (readMIMEHeader parity), got: {response:?}"
    );

    drop(provider);
}

/// R2: tcpmux HTTP-group fan-out (Go TCPMuxGroup HTTPConnectListen).
/// Arm mapping:
///  - round-robin fan-out across the two members (requests 1-3 → A, B, A);
///  - CloseProxy of member A (the route owner) while B remains → B serves
///    every subsequent request (member-close fallthrough);
///  - CloseProxy of the last member B → unregister_member returns the route
///    owner, the shared route is dropped → CONNECT gets 404 (empty-group →
///    owner arm).
/// The two race-window dispatch arms in tcpmux.rs (chosen member unregistered
/// between choose_endpoint and lookup → route-owner fallback; empty group →
/// route-owner dispatch) are not deterministically reachable over the wire —
/// they are pinned by review of the dispatch code only.
#[tokio::test]
async fn test_tcpmux_group_round_robin_and_member_close() {
    let bind_port = allocate_port();
    let tcpmux_port = allocate_port();
    let cfg = ServerConfig {
        bind_addr: "127.0.0.1".into(),
        bind_port,
        tcpmux_httpconnect_port: tcpmux_port,
        auth: test_auth_cfg(),
        ..Default::default()
    };
    let (_handle, _) = start_test_server(cfg).await;
    let addr: SocketAddr = format!("127.0.0.1:{}", bind_port).parse().unwrap();
    let tcpmux_addr: SocketAddr = format!("127.0.0.1:{}", tcpmux_port).parse().unwrap();

    let (mut ctl, resp) = login_with_test_token(addr).await.expect("provider login");
    let run_id = resp.run_id.expect("run_id");

    // Member A (first — registers the shared route), then member B joins.
    let mut np_a = tcpmux_proxy("grp-a", vec!["fan.example.com".into()], "127.0.0.1:22");
    np_a.group = Some("fan-grp".into());
    np_a.group_key = Some("fan-key".into());
    assert!(register_proxy(&mut ctl, np_a).await.is_none());
    let mut np_b = tcpmux_proxy("grp-b", vec!["fan.example.com".into()], "127.0.0.1:22");
    np_b.group = Some("fan-grp".into());
    np_b.group_key = Some("fan-key".into());
    assert!(register_proxy(&mut ctl, np_b).await.is_none());

    let request = b"CONNECT fan.example.com:22 HTTP/1.1\r\nHost: fan.example.com:22\r\n\r\n";

    // Phase 1 — round-robin fan-out: A, B, A (member list order = join order,
    // index starts at 0).
    for (round, expected) in ["grp-a", "grp-b", "grp-a"].iter().enumerate() {
        let mut work = open_work_conn(addr, &run_id).await;
        let (client, response) = send_connect(tcpmux_addr, request).await;
        assert!(
            response.starts_with("HTTP/1.1 200"),
            "round {round}: expected 200, got: {response:?}"
        );
        let got = read_start_work_conn(&mut work, &format!("round {round}")).await;
        assert_eq!(
            got, *expected,
            "round {round}: round-robin dispatch mismatch"
        );
        drop(client);
        drop(work);
    }

    // Phase 2 — member A (route owner) closes while B remains: B must serve.
    write_msg_v1(
        &mut ctl,
        &FrpMessage::CloseProxy(msg::CloseProxy {
            proxy_name: "grp-a".into(),
        }),
    )
    .await
    .expect("send CloseProxy A");

    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(8);
    loop {
        let mut work = open_work_conn(addr, &run_id).await;
        let (client, response) = send_connect(tcpmux_addr, request).await;
        assert!(
            response.starts_with("HTTP/1.1 200"),
            "route must survive member A leaving, got: {response:?}"
        );
        match tokio::time::timeout(
            std::time::Duration::from_millis(500),
            read_start_work_conn(&mut work, "after A left"),
        )
        .await
        {
            Ok(got) if got == "grp-b" => {
                drop(client);
                drop(work);
                break;
            }
            Ok(got) => {
                // A still serving → the CloseProxy was not yet processed;
                // retry until the member list converges on B.
                eprintln!("A still served ({got}); retrying after CloseProxy");
            }
            Err(_) => {
                // Dispatch raced the close and stalled; retry.
                eprintln!("no StartWorkConn in window; retrying");
            }
        }
        drop(client);
        drop(work);
        assert!(
            tokio::time::Instant::now() < deadline,
            "member B never served after A closed; last response: {response:?}"
        );
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }

    // Phase 3 — last member B closes: the group empties, unregister_member
    // returns the route owner (grp-a) and the shared route is dropped → 404.
    write_msg_v1(
        &mut ctl,
        &FrpMessage::CloseProxy(msg::CloseProxy {
            proxy_name: "grp-b".into(),
        }),
    )
    .await
    .expect("send CloseProxy B");

    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(8);
    let gone = loop {
        let (client, response) = send_connect(tcpmux_addr, request).await;
        drop(client);
        if response.starts_with("HTTP/1.1 404") {
            break response;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "route never dropped after the last member left; last response: {response:?}"
        );
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    };
    eprintln!("route dropped after last member close (404): {gone:?}");

    drop(ctl);
}
