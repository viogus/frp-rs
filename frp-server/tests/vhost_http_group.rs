//! HTTP/HTTPS group load balancing (Go frp v0.71.0 HTTPGroupController):
//! - two http proxies sharing one vhost route (same group + group_key +
//!   domain) dispatch requests round-robin across the members;
//! - a member with a wrong group_key is rejected;
//! - a member with mismatched routing params is rejected.

mod common;

use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use common::{allocate_port, login_with_test_token, start_test_server, test_auth_cfg};
use frp_core::config::ServerConfig;
use frp_core::msg::{self, FrpMessage, NewProxy};
use frp_core::protocol::{read_msg_v1, write_msg_v1};

fn http_group_proxy(name: &str, group: &str, group_key: &str, domain: &str) -> NewProxy {
    NewProxy {
        proxy_name: name.into(),
        proxy_type: "http".into(),
        sk: None,
        use_encryption: None,
        use_compression: None,
        group: Some(group.into()),
        group_key: Some(group_key.into()),
        local_str: Some("127.0.0.1:8080".into()),
        remote_port: Some(0),
        custom_domains: Some(vec![domain.into()]),
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
    }
}

/// Register a proxy and read the NewProxyResp error (if any).
async fn register_proxy<S>(stream: &mut S, np: NewProxy) -> Option<String>
where
    S: tokio::io::AsyncReadExt + tokio::io::AsyncWriteExt + Unpin,
{
    write_msg_v1(stream, &FrpMessage::NewProxy(Box::new(np)))
        .await
        .expect("send NewProxy");
    match read_msg_v1(stream).await.expect("NewProxyResp") {
        FrpMessage::NewProxyResp(ref r) => r.error.clone(),
        other => panic!("expected NewProxyResp, got {:?}", other.v1_type_byte()),
    }
}

/// Open a pooled work conn (NewWorkConn). The server keeps it pooled and
/// sends StartWorkConn only when a vhost request is dispatched to it.
async fn open_work_conn(addr: SocketAddr, run_id: &str) -> tokio::net::TcpStream {
    let mut work = tokio::net::TcpStream::connect(addr)
        .await
        .expect("work conn");
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

/// Blocking HTTP GET to the vhost port; returns the response body.
/// Reads the response head + Content-Length body (the bridge keeps the work
/// conn open, so EOF is never seen). Bounded internally: a request that
/// stalls server-side (e.g. dispatched to a member that never produces a
/// work conn) returns `<request-timeout>` instead of parking forever —
/// racing requests spawned by retry loops must self-terminate.
async fn http_request(vhost: SocketAddr, host: &str) -> String {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(6);
    let mut client = tokio::net::TcpStream::connect(vhost)
        .await
        .expect("vhost connect");
    client
        .write_all(
            format!("GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n").as_bytes(),
        )
        .await
        .expect("send request");
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    // Read the head up to the CRLFCRLF terminator.
    while buf.len() < 4096 {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return "<request-timeout>".to_string();
        }
        match tokio::time::timeout(remaining, client.read(&mut byte)).await {
            Ok(Ok(n)) if n > 0 => {
                buf.push(byte[0]);
                if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            _ => return "<request-timeout>".to_string(),
        }
    }
    // Parse Content-Length and read exactly that many body bytes.
    let text = String::from_utf8_lossy(&buf);
    let clen = text
        .lines()
        .find_map(|l| {
            l.split_once(':')
                .filter(|(k, _)| k.eq_ignore_ascii_case("content-length"))
                .and_then(|(_, v)| v.trim().parse::<usize>().ok())
        })
        .unwrap_or(0);
    let mut body = vec![0u8; clen];
    if clen > 0 {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero()
            || tokio::time::timeout(remaining, client.read_exact(&mut body))
                .await
                .is_err()
        {
            return "<request-timeout>".to_string();
        }
    }
    format!(
        "{}{}",
        String::from_utf8_lossy(&buf),
        String::from_utf8_lossy(&body)
    )
}

/// Read one HTTP request head (up to CRLFCRLF) from a work conn with a
/// bounded wait (the request may take a moment to be dispatched). Returns
/// the head bytes or None on overall timeout/EOF.
async fn read_work_head(work: &mut tokio::net::TcpStream) -> Option<Vec<u8>> {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(4);
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while head.len() < 4096 {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return None;
        }
        match tokio::time::timeout(remaining, work.read_exact(&mut byte)).await {
            Ok(Ok(_)) => {
                head.push(byte[0]);
                if head.windows(4).any(|w| w == b"\r\n\r\n") {
                    return Some(head);
                }
            }
            _ => return None,
        }
    }
    None
}

#[tokio::test]
async fn test_http_group_round_robin() {
    let bind_port = allocate_port();
    let vhost_port = allocate_port();

    let cfg = ServerConfig {
        bind_addr: "127.0.0.1".into(),
        bind_port,
        vhost_http_port: vhost_port,
        auth: test_auth_cfg(),
        ..Default::default()
    };
    let (_handle, _) = start_test_server(cfg).await;
    let addr: SocketAddr = format!("127.0.0.1:{bind_port}").parse().unwrap();
    let vhost: SocketAddr = format!("127.0.0.1:{vhost_port}").parse().unwrap();

    // Member A: first member — creates the shared route.
    let (mut ctl_a, resp_a) = login_with_test_token(addr).await.expect("login A");
    let run_id_a = resp_a.run_id.expect("run_id A");
    let err = register_proxy(
        &mut ctl_a,
        http_group_proxy("grp-a", "webgrp", "secret-key", "app.example.com"),
    )
    .await;
    assert!(err.is_none(), "first member rejected: {err:?}");

    // Member B: second member — joins the group.
    let (mut ctl_b, resp_b) = login_with_test_token(addr).await.expect("login B");
    let run_id_b = resp_b.run_id.expect("run_id B");
    let err = register_proxy(
        &mut ctl_b,
        http_group_proxy("grp-b", "webgrp", "secret-key", "app.example.com"),
    )
    .await;
    assert!(err.is_none(), "second member rejected: {err:?}");

    // Member C: wrong group_key must be rejected (Go ErrGroupAuthFailed).
    let (mut ctl_c, _) = login_with_test_token(addr).await.expect("login C");
    let err = register_proxy(
        &mut ctl_c,
        http_group_proxy("grp-c", "webgrp", "wrong-key", "app.example.com"),
    )
    .await;
    assert!(
        err.as_deref()
            .is_some_and(|e| e.contains("auth failed") || e.contains("group_key")),
        "wrong group_key should be rejected, got: {err:?}"
    );

    // Member D: mismatched domain must be rejected (Go ErrGroupParamsInvalid
    // — "group params invalid" verbatim; the invented "params mismatch"
    // phrasing died with the kind-keyed registry rework).
    let (mut ctl_d, _) = login_with_test_token(addr).await.expect("login D");
    let err = register_proxy(
        &mut ctl_d,
        http_group_proxy("grp-d", "webgrp", "secret-key", "other.example.com"),
    )
    .await;
    assert!(
        err.as_deref()
            .is_some_and(|e| e.contains("group params invalid")),
        "mismatched domain should be rejected, got: {err:?}"
    );

    // Round-robin: 6 requests, expect a fair A/B split (index starts at 0 →
    // first request → member A, second → B, ...). Each request consumes one
    // pooled work conn (the bridge moves it out of the pool), so we open a
    // fresh pooled conn for the expected member before each request — this
    // mirrors a real frpc answering the server's ReqWorkConn.
    let mut served_a = 0usize;
    let mut served_b = 0usize;
    for i in 0..6 {
        // Round-robin pick: index starts at 0 → member A on even rounds.
        let which = if i % 2 == 0 { "A" } else { "B" };
        let member_run_id = if which == "A" { &run_id_a } else { &run_id_b };
        // Fresh pooled work conn for the expected member (each request
        // consumes one).
        let mut work = open_work_conn(addr, member_run_id).await;
        // Send the request from a task so we can watch the member's work
        // conn for StartWorkConn + the forwarded head concurrently.
        let req = tokio::spawn(http_request(vhost, "app.example.com"));
        let head = read_work_head(&mut work).await;
        assert!(
            head.is_some(),
            "round {i}: member {which} did not receive the request"
        );
        let body = format!("member-{which}");
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {len}\r\nConnection: close\r\n\r\n{body}",
            len = body.len()
        );
        work.write_all(resp.as_bytes()).await.expect("serve");
        let resp_body = req.await.expect("request task");
        assert!(
            resp_body.contains(&format!("member-{which}")),
            "expected {which} body, got: {resp_body:?}"
        );
        if which == "A" {
            served_a += 1;
        } else {
            served_b += 1;
        }
    }
    assert!(served_a >= 2, "member A served too few: {served_a}");
    assert!(served_b >= 2, "member B served too few: {served_b}");
    assert!(
        (served_a as i32 - served_b as i32).abs() <= 1,
        "unbalanced round-robin: A={served_a} B={served_b}"
    );
}

/// Regression: when the FIRST member of an http group leaves while the group
/// still has members, and the LAST member leaves afterwards, the shared vhost
/// route must be dropped (keyed on the first member's name — not the last
/// member that emptied the group). Previously the route leaked and requests
/// kept failing with 502/404.
#[tokio::test]
async fn test_http_group_route_cleaned_when_last_member_leaves() {
    let bind_port = allocate_port();
    let vhost_port = allocate_port();

    let cfg = ServerConfig {
        bind_addr: "127.0.0.1".into(),
        bind_port,
        vhost_http_port: vhost_port,
        auth: test_auth_cfg(),
        ..Default::default()
    };
    let (_handle, _) = start_test_server(cfg).await;
    let addr: SocketAddr = format!("127.0.0.1:{bind_port}").parse().unwrap();
    let vhost: SocketAddr = format!("127.0.0.1:{vhost_port}").parse().unwrap();

    // Two members; A (first) registers the shared route.
    let (mut ctl_a, resp_a) = login_with_test_token(addr).await.expect("login A");
    let _run_id_a = resp_a.run_id.expect("run_id A");
    assert!(register_proxy(
        &mut ctl_a,
        http_group_proxy("grp-a", "webgrp", "secret-key", "app.example.com"),
    )
    .await
    .is_none());
    let (mut ctl_b, resp_b) = login_with_test_token(addr).await.expect("login B");
    let run_id_b = resp_b.run_id.expect("run_id B");
    assert!(register_proxy(
        &mut ctl_b,
        http_group_proxy("grp-b", "webgrp", "secret-key", "app.example.com"),
    )
    .await
    .is_none());

    // Member A (route owner) closes FIRST while B is still in the group —
    // the route must survive for B.
    // Go frp does not send CloseProxyResp — send and let the server process.
    write_msg_v1(
        &mut ctl_a,
        &FrpMessage::CloseProxy(msg::CloseProxy {
            proxy_name: "grp-a".into(),
        }),
    )
    .await
    .expect("send CloseProxy A");

    // Settle before serving: a request that races the unprocessed CloseProxy
    // is dispatched to A and only re-routed to the group once the delete
    // settles — by then the request's client socket is gone and the stale
    // dispatch steals the next fresh pooled conn from a live request (its
    // StartWorkConn arrives, its response never does). Requests must not
    // race the close, so wait for the drop to settle first.
    tokio::time::sleep(std::time::Duration::from_millis(1000)).await;

    // Serve one request through the surviving member B. Bounded retry loop:
    // the attempt succeeds only when the response actually comes back with a
    // member-B body (a stolen conn yields StartWorkConn but no response).
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(15);
    let mut served: Option<String> = None;
    while served.is_none() {
        let mut attempt = open_work_conn(addr, &run_id_b).await;
        let mut req = Some(tokio::spawn(http_request(vhost, "app.example.com")));
        if let Some(head) = read_work_head(&mut attempt).await {
            if !head.is_empty() {
                let body = "member-B";
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {len}\r\nConnection: close\r\n\r\n{body}",
                    len = body.len()
                );
                attempt.write_all(resp.as_bytes()).await.expect("serve");
                match tokio::time::timeout(
                    std::time::Duration::from_secs(4),
                    req.take().expect("request handle"),
                )
                .await
                {
                    Ok(Ok(r)) if r.contains("member-B") => served = Some(r),
                    Ok(Ok(r)) => {
                        assert!(
                            tokio::time::Instant::now() < deadline,
                            "member B never served after A (owner) left; got: {r:?}"
                        );
                    }
                    _ => {} // conn stolen by a stale dispatch — retry
                }
            }
        }
        if let Some(r) = req.take() {
            r.abort();
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "member B never served after A (owner) left"
        );
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert!(served.is_some());

    // Now B (the last member) closes -> the shared route must be dropped.
    write_msg_v1(
        &mut ctl_b,
        &FrpMessage::CloseProxy(msg::CloseProxy {
            proxy_name: "grp-b".into(),
        }),
    )
    .await
    .expect("send CloseProxy B");

    // Settle (same race discipline as above), then poll for the route to be
    // gone: the domain must answer 404 (not 502 from a zombie dispatch to a
    // dead member, not a stall on a dispatch that raced the close).
    tokio::time::sleep(std::time::Duration::from_millis(1000)).await;
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(15);
    let mut last_resp = String::new();
    loop {
        match tokio::time::timeout(
            std::time::Duration::from_secs(4),
            http_request(vhost, "app.example.com"),
        )
        .await
        {
            Ok(resp) if resp.contains("404") => break,
            Ok(resp) => last_resp = resp,
            Err(_) => {} // stalled on a dispatch that raced the close
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "route should be removed after the last member leaves; last response: {last_resp:?}"
        );
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
}
