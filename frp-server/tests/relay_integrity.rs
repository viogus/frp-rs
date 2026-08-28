//! Byte-exact relay integrity through the real server bridge (splice(2)
//! on Linux, copy_bidirectional otherwise). stcp_relay.rs only asserts
//! routing; this test pushes multi-MiB payloads in BOTH directions
//! through a real provider work conn and asserts every byte survives
//! in order: user → work (1.5 MiB + write-half shutdown) and work →
//! user (2 MiB, after the opposite direction already hit EOF).

mod common;

use std::net::SocketAddr;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use common::{allocate_port, login_with_test_token, start_test_server, test_auth_cfg};
use frp_core::config::ServerConfig;
use frp_core::msg::{self, FrpMessage};
use frp_core::protocol::{read_msg_v1, write_msg_v1};

/// Deterministic pseudo-random payload (LCG): distinct seeds, in-order
/// bytes — any swap, drop, or duplication changes the buffer.
fn payload(mut state: u64, len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    for _ in 0..len {
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        out.push((state >> 33) as u8);
    }
    out
}

/// Read exactly `n` bytes, bounded by a 15s timeout (a stalled relay
/// fails loudly instead of hanging the suite).
async fn read_exact_n(stream: &mut tokio::net::TcpStream, n: usize) -> Vec<u8> {
    let mut out = vec![0u8; n];
    tokio::time::timeout(
        std::time::Duration::from_secs(15),
        stream.read_exact(&mut out),
    )
    .await
    .expect("timeout reading bridged bytes (relay stalled?)")
    .expect("read bridged bytes");
    out
}

/// Register a tcp proxy on `proxy_port`, pool a real provider work conn,
/// then relay multi-MiB payloads both ways with byte-exact assertions.
#[tokio::test]
async fn test_relay_byte_exact_bidirectional() {
    let bind_port = allocate_port();
    let proxy_port = allocate_port();
    let cfg = ServerConfig {
        bind_addr: "127.0.0.1".into(),
        bind_port,
        auth: test_auth_cfg(),
        ..Default::default()
    };
    let (_handle, _) = start_test_server(cfg).await;
    let addr: SocketAddr = format!("127.0.0.1:{bind_port}").parse().unwrap();
    let proxy_addr: SocketAddr = format!("127.0.0.1:{proxy_port}").parse().unwrap();

    // Provider logs in and registers a tcp proxy listening on proxy_port.
    let (mut provider, resp) = login_with_test_token(addr).await.expect("provider login");
    let run_id = resp.run_id.expect("run_id");
    let np = FrpMessage::NewProxy(Box::new(msg::NewProxy {
        proxy_name: "relay-integrity".into(),
        proxy_type: "tcp".into(),
        local_str: Some("127.0.0.1:1".into()),
        remote_port: Some(proxy_port.into()),
        sk: None,
        use_encryption: None,
        use_compression: None,
        group: None,
        group_key: None,
        custom_domains: None,
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
        multiplexer: None,
        virtual_net: None,
        proxy_protocol_version: None,
        advertise_subnet: None,
        vnet_ip: None,
        vnet_netmask: None,
        vnet_mtu: None,
    }));
    write_msg_v1(&mut provider, &np)
        .await
        .expect("send NewProxy");
    match read_msg_v1(&mut provider).await.expect("NewProxyResp") {
        FrpMessage::NewProxyResp(r) => {
            assert!(r.error.is_none(), "registration failed: {:?}", r.error);
        }
        other => panic!("expected NewProxyResp, got {:?}", other.v1_type_byte()),
    }

    // Pool a real provider work conn (the bridge's server-side peer).
    let mut work_conn = tokio::net::TcpStream::connect(addr)
        .await
        .expect("work conn connect");
    write_msg_v1(
        &mut work_conn,
        &FrpMessage::NewWorkConn(msg::NewWorkConn {
            run_id: Some(run_id),
            timestamp: None,
            privilege_key: None,
        }),
    )
    .await
    .expect("send NewWorkConn");

    // External user connects to the proxy port → the server assigns the
    // pooled work conn and starts the bridge.
    let mut user = tokio::net::TcpStream::connect(proxy_addr)
        .await
        .expect("proxy port connect");
    match read_msg_v1(&mut work_conn).await.expect("StartWorkConn") {
        FrpMessage::StartWorkConn(swc) => {
            assert_eq!(swc.proxy_name, "relay-integrity");
            assert!(swc.error.is_none(), "StartWorkConn error: {:?}", swc.error);
        }
        other => panic!("expected StartWorkConn, got {:?}", other.v1_type_byte()),
    }

    // Direction 1: user → work. 1.5 MiB, then a write-half shutdown; the
    // relay must deliver every byte in order (clean EOF in one direction
    // must not tear down the opposite direction).
    let up_payload = payload(0x1234_5678_9abc_def0, 1_500_000);
    user.write_all(&up_payload).await.expect("user write");
    user.shutdown().await.expect("user write-half shutdown");
    let got = read_exact_n(&mut work_conn, up_payload.len()).await;
    assert_eq!(got, up_payload, "user→work relay corrupted bytes");

    // Direction 2: work → user. 2 MiB back over the same bridge.
    let down_payload = payload(0xfeed_face_cafe_beef, 2_000_000);
    work_conn
        .write_all(&down_payload)
        .await
        .expect("work write");
    let got = read_exact_n(&mut user, down_payload.len()).await;
    assert_eq!(got, down_payload, "work→user relay corrupted bytes");

    drop(user);
    drop(work_conn);
    drop(provider);
}
