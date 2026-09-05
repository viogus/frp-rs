//! e2e proofs that the per-kind `allow_users` visitor gate actually fires on
//! the wire (audit round 10 coverage gap A). Until this file, only a 4-row
//! pure-helper unit matrix existed (handlers/dispatch.rs `visitor_user_allowed`)
//! and every e2e fixture registered proxies with `allow_users: None`.
//!
//! Server sites exercised, each with its exact denial text asserted:
//!   STCP fresh-conn NewVisitorConn            handlers/dispatch.rs:208   -> "visitor not allowed"
//!   XTCP control-channel NewVisitorConn       control/nathole.rs:395     -> "auth failed"
//!   XTCP control-channel NatHoleVisitor       control/nathole.rs:495     -> "access denied" / "access denied: owner only"
//!   XTCP fresh-conn NatHoleVisitor (precheck) handlers/dispatch.rs:453   -> "access denied: restricted to authenticated users"
//!   XTCP fresh-conn NatHoleVisitor (full)     handlers/dispatch.rs:577   -> "access denied: use control channel for user-based auth"
//!
//! The gate semantics asserted e2e (Go frp visitor/visitor.go:83 + proxy.go:204):
//!   empty `allow_users`  -> owner only
//!   non-empty list       -> ONLY the listed users (no anonymous/other users)
//!   "*"                  -> any authenticated user
//!
//! Wire model mirrored from the real frpc: STCP visitors dial a FRESH conn per
//! user connection claiming their own control's run_id (visitor.rs
//! `create_visitor_conn_msg`); XTCP visitors send NatHoleVisitor over their
//! own control channel (service.rs "sent NatHoleVisitor on control"); the
//! server resolves the fresh-conn identity from the claimed run_id only when
//! it names an existing authenticated control from the same peer IP.

mod common;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use frp_core::auth::generate_token;
use frp_core::config::ServerConfig;
use frp_core::msg::{self, FrpMessage, NewProxy};
use frp_core::protocol::{read_msg_v1, write_msg_v1};
use frp_core::transport::IoStream;

use common::{allocate_port, login_with_identity, start_test_server, test_auth_cfg};

/// Exact denial texts from the enforcement sites (kept in sync with the
/// server sources above — a refactor of the strings must update these).
const STCP_FRESH_VISITOR_NOT_ALLOWED: &str = "visitor not allowed";
const XTCP_CTL_REG_AUTH_FAILED: &str = "auth failed";
const XTCP_CTL_LIST_DENIED: &str = "access denied";
const XTCP_CTL_OWNER_ONLY_DENIED: &str = "access denied: owner only";
const XTCP_FRESH_PRE_CHECK_DENIED: &str = "access denied: restricted to authenticated users";
const XTCP_FRESH_FULL_DENIED: &str = "access denied: use control channel for user-based auth";

fn test_addr(port: u16) -> SocketAddr {
    format!("127.0.0.1:{port}").parse().unwrap()
}

/// Seconds since the epoch (visitor messages use the same precision as the
/// other protocol tests).
fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

/// MD5(sk + ts) visitor sign_key and its timestamp — the message timestamp
/// MUST be the same value the key was generated from.
fn sign_key_at(sk: &str) -> (i64, String) {
    let ts = now_secs();
    (ts, generate_token(sk, ts))
}

/// Register an stcp/xtcp proxy on a logged-in control, asserting a clean
/// NewProxyResp. `allow_users` is the wire field under test (None = empty).
async fn register_visitor_proxy(
    ctl: &mut IoStream,
    name: &str,
    proxy_type: &str,
    sk: &str,
    allow_users: Option<Vec<String>>,
) {
    let np = FrpMessage::NewProxy(Box::new(NewProxy {
        proxy_name: name.into(),
        proxy_type: proxy_type.into(),
        sk: Some(sk.to_string()),
        use_encryption: None,
        use_compression: None,
        group: None,
        group_key: None,
        local_str: Some("127.0.0.1:9999".into()),
        remote_port: Some(0),
        custom_domains: None,
        subdomain: None,
        locations: None,
        http_user: None,
        http_pwd: None,
        host_header_rewrite: None,
        headers: None,
        response_headers: None,
        route_by_http_user: None,
        allow_users,
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
    write_msg_v1(ctl, &np)
        .await
        .unwrap_or_else(|e| panic!("send NewProxy for {name}: {e}"));
    match recv_msg(ctl, &format!("NewProxyResp for {name}")).await {
        FrpMessage::NewProxyResp(r) => assert!(
            r.error.is_none(),
            "register {name}: expected success, got {:?}",
            r.error
        ),
        other => panic!(
            "expected NewProxyResp for {name}, got type byte {:?}",
            other.v1_type_byte()
        ),
    }
}

/// Build the NewVisitorConn a real STCP visitor frpc sends on a fresh conn
/// (visitor.rs `create_visitor_conn_msg`): MD5(sk + ts) sign_key and the
/// visitor's own control run_id claim when it has one.
fn stcp_visitor_msg(proxy_name: &str, sk: &str, run_id: Option<&str>) -> FrpMessage {
    let (ts, sign_key) = sign_key_at(sk);
    FrpMessage::NewVisitorConn(msg::NewVisitorConn {
        proxy_name: proxy_name.into(),
        sign_key: Some(sign_key),
        timestamp: Some(ts),
        run_id: run_id.map(String::from),
        use_encryption: None,
        use_compression: None,
    })
}

/// The startup-registration NewVisitorConn an XTCP/STCP visitor frpc sends
/// over its own control channel at login (service.rs visitor registration
/// batch) — carries the valid sign_key for `sk`.
fn ctl_registration_msg(proxy_name: &str, sk: &str) -> FrpMessage {
    let (ts, sign_key) = sign_key_at(sk);
    FrpMessage::NewVisitorConn(msg::NewVisitorConn {
        proxy_name: proxy_name.into(),
        sign_key: Some(sign_key),
        timestamp: Some(ts),
        run_id: None,
        use_encryption: None,
        use_compression: None,
    })
}

/// Open a raw TCP conn to the server and send the FIRST frame `msg` (the
/// accept-loop dispatch path for fresh visitor connections).
async fn fresh_conn_with_first_frame(addr: SocketAddr, msg: FrpMessage) -> IoStream {
    let mut io = IoStream::Tcp(
        TcpStream::connect(addr)
            .await
            .expect("fresh visitor conn connect"),
    );
    write_msg_v1(&mut io, &msg)
        .await
        .expect("send first frame on fresh conn");
    io
}

/// Send a fresh-conn NewVisitorConn and assert the server answers
/// NewVisitorConnResp with exactly `want_error`.
async fn expect_fresh_stcp_verdict(
    addr: SocketAddr,
    proxy_name: &str,
    sk: &str,
    run_id: Option<&str>,
    want_error: Option<&str>,
    ctx: &str,
) {
    let mut io = fresh_conn_with_first_frame(addr, stcp_visitor_msg(proxy_name, sk, run_id)).await;
    let msg = recv_msg(&mut io, ctx).await;
    match msg {
        FrpMessage::NewVisitorConnResp(r) => assert_eq!(
            r.error.as_deref(),
            want_error,
            "{ctx}: NewVisitorConnResp error mismatch (proxy={proxy_name}, run_id={run_id:?})"
        ),
        other => panic!(
            "{ctx}: expected NewVisitorConnResp, got type byte {:?}",
            other.v1_type_byte()
        ),
    }
}

/// Send a fresh TCP conn, pool it as the provider's work conn (NewWorkConn
/// with the provider run_id), and return it. The server writes StartWorkConn
/// on it once a visitor/user conn is assigned.
async fn pool_work_conn(addr: SocketAddr, run_id: &str) -> IoStream {
    let mut wc = IoStream::Tcp(TcpStream::connect(addr).await.expect("work conn connect"));
    write_msg_v1(
        &mut wc,
        &FrpMessage::NewWorkConn(msg::NewWorkConn {
            run_id: Some(run_id.into()),
            timestamp: None,
            privilege_key: None,
        }),
    )
    .await
    .expect("send NewWorkConn");
    wc
}

async fn recv_msg(stream: &mut IoStream, what: &str) -> FrpMessage {
    tokio::time::timeout(Duration::from_secs(5), read_msg_v1(stream))
        .await
        .unwrap_or_else(|_| panic!("timed out waiting for {what}"))
        .unwrap_or_else(|e| panic!("read {what}: {e}"))
}

/// Read the StartWorkConn the server writes on the pooled work conn once the
/// visitor conn is assigned, asserting a clean assignment for `proxy_name`.
async fn expect_start_work_conn(work: &mut IoStream, proxy_name: &str, ctx: &str) {
    match recv_msg(work, &format!("{ctx}: StartWorkConn on pooled work conn")).await {
        FrpMessage::StartWorkConn(swc) => {
            assert_eq!(
                swc.proxy_name, proxy_name,
                "{ctx}: StartWorkConn for wrong proxy"
            );
            assert!(
                swc.error.is_none(),
                "{ctx}: StartWorkConn error: {:?}",
                swc.error
            );
        }
        other => panic!(
            "{ctx}: expected StartWorkConn, got type byte {:?}",
            other.v1_type_byte()
        ),
    }
}

/// Prove the visitor conn actually reaches the "local echo service": bytes
/// written by the visitor must arrive on the provider-side work conn and
/// echo back. `visitor` is the admitted STCP visitor conn (post-Resp).
async fn echo_round_trip(visitor: &mut IoStream, work: &mut IoStream, ctx: &str) {
    let payload = vec![0xA7u8; 4096];
    visitor
        .write_all(&payload)
        .await
        .expect("visitor writes payload");
    let mut received = vec![0u8; 4096];
    work.read_exact(&mut received)
        .await
        .expect("work conn reads payload");
    assert_eq!(received, payload, "{ctx}: payload must arrive byte-exact");

    let response = vec![0x3Cu8; 2048];
    work.write_all(&response)
        .await
        .expect("work conn writes response");
    let mut echoed = vec![0u8; 2048];
    visitor
        .read_exact(&mut echoed)
        .await
        .expect("visitor reads response");
    assert_eq!(echoed, response, "{ctx}: response must arrive byte-exact");
}

async fn start_two_user_server(port: u16) -> SocketAddr {
    let cfg = ServerConfig {
        bind_addr: "127.0.0.1".into(),
        bind_port: port,
        auth: test_auth_cfg(),
        ..Default::default()
    };
    let (_handle, _) = start_test_server(cfg).await;
    test_addr(port)
}

/// STCP allow-list ([alice]) on the fresh-conn site (dispatch.rs:208):
/// 1. bob (logged-in user, claiming his own control run_id) -> denied
///    with the exact "visitor not allowed" text — a logged-in foreign user
///    is refused even with a valid sk sign_key.
/// 2. an anonymous conn (no run_id claim, identity "") -> denied with the
///    same text.
/// 3. alice (in the list, claiming her own run_id) -> admitted, and the
///    visitor conn reaches the provider-side work conn (byte-exact echo).
#[tokio::test]
async fn stcp_allow_users_list_denies_foreign_users_and_admits_listed() {
    let addr = start_two_user_server(allocate_port()).await;

    // Provider logs in as "owner" and registers STCP proxy allowed for alice.
    let (mut owner_ctl, resp) = login_with_identity(addr, "owner", HashMap::new())
        .await
        .expect("owner login");
    let owner_run_id = resp.run_id.expect("owner run_id");
    register_visitor_proxy(
        &mut owner_ctl,
        "svc-a",
        "stcp",
        "sk-a",
        Some(vec!["alice".into()]),
    )
    .await;

    // Foreign user bob logs in (his own control, same frps, own run_id).
    // The control stream must stay ALIVE for the whole test so the run_id
    // claim on the fresh conn resolves to bob; only its run_id is used here.
    let (_bob_ctl, resp) = login_with_identity(addr, "bob", HashMap::new())
        .await
        .expect("bob login");
    let bob_run_id = resp.run_id.expect("bob run_id");

    // Arm 1: bob claims his OWN control run_id -> identity "bob" -> denied.
    expect_fresh_stcp_verdict(
        addr,
        "svc-a",
        "sk-a",
        Some(&bob_run_id),
        Some(STCP_FRESH_VISITOR_NOT_ALLOWED),
        "bob (in allow-list deny arm) claims own run_id",
    )
    .await;

    // Arm 2: no run_id claim -> identity "" -> denied (foreign/anonymous
    // clients cannot piggyback on an allow-list proxy).
    expect_fresh_stcp_verdict(
        addr,
        "svc-a",
        "sk-a",
        None,
        Some(STCP_FRESH_VISITOR_NOT_ALLOWED),
        "run_id-less visitor on allow-list proxy",
    )
    .await;

    // Listed user alice logs in and claims her own run_id. Her control
    // stream also stays alive for the claim (see bob above).
    let (_alice_ctl, resp) = login_with_identity(addr, "alice", HashMap::new())
        .await
        .expect("alice login");
    let alice_run_id = resp.run_id.expect("alice run_id");

    // Pre-pool one provider work conn so the assignment is immediate.
    let mut work = pool_work_conn(addr, &owner_run_id).await;
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Arm 3: alice -> admitted (error None), then StartWorkConn on the pool.
    let mut visitor =
        fresh_conn_with_first_frame(addr, stcp_visitor_msg("svc-a", "sk-a", Some(&alice_run_id)))
            .await;
    match recv_msg(&mut visitor, "alice NewVisitorConnResp").await {
        FrpMessage::NewVisitorConnResp(r) => {
            assert!(r.error.is_none(), "alice should be admitted: {:?}", r.error)
        }
        other => panic!(
            "expected NewVisitorConnResp for alice, got type byte {:?}",
            other.v1_type_byte()
        ),
    }
    expect_start_work_conn(&mut work, "svc-a", "alice admit arm").await;

    // The bridged relay is live: visitor <-> work conn byte-exact echo.
    echo_round_trip(&mut visitor, &mut work, "alice admit arm").await;

    drop(visitor);
    drop(work);
    drop(owner_ctl);
    // _bob_ctl / _alice_ctl drop here, closing their controls.
}

/// STCP wildcard ("*"): any authenticated user is admitted on the fresh-conn
/// site even though the proxy owner is a different user.
#[tokio::test]
async fn stcp_allow_users_wildcard_admits_any_user() {
    let addr = start_two_user_server(allocate_port()).await;

    let (mut owner_ctl, resp) = login_with_identity(addr, "owner", HashMap::new())
        .await
        .expect("owner login");
    let owner_run_id = resp.run_id.expect("owner run_id");
    register_visitor_proxy(
        &mut owner_ctl,
        "svc-w",
        "stcp",
        "sk-w",
        Some(vec!["*".into()]),
    )
    .await;

    let (_bob_ctl, resp) = login_with_identity(addr, "bob", HashMap::new())
        .await
        .expect("bob login");
    let bob_run_id = resp.run_id.expect("bob run_id");

    let mut work = pool_work_conn(addr, &owner_run_id).await;
    tokio::time::sleep(Duration::from_millis(200)).await;

    let mut visitor =
        fresh_conn_with_first_frame(addr, stcp_visitor_msg("svc-w", "sk-w", Some(&bob_run_id)))
            .await;
    match recv_msg(&mut visitor, "bob wildcard NewVisitorConnResp").await {
        FrpMessage::NewVisitorConnResp(r) => assert!(
            r.error.is_none(),
            "bob should be admitted by the wildcard: {:?}",
            r.error
        ),
        other => panic!(
            "expected NewVisitorConnResp for bob, got type byte {:?}",
            other.v1_type_byte()
        ),
    }
    expect_start_work_conn(&mut work, "svc-w", "bob wildcard admit arm").await;

    drop(visitor);
    drop(work);
    drop(owner_ctl);
    // _bob_ctl drops here, closing bob's control.
}

/// STCP empty allow_users -> owner-only normalization: on the fresh-conn site
/// a second user (not the owner) is denied; the owner himself is admitted.
/// a second user (not the owner) is denied; the owner himself is admitted.
#[tokio::test]
async fn stcp_empty_allow_users_is_owner_only() {
    let addr = start_two_user_server(allocate_port()).await;

    let (mut owner_ctl, resp) = login_with_identity(addr, "owner", HashMap::new())
        .await
        .expect("owner login");
    let owner_run_id = resp.run_id.expect("owner run_id");
    register_visitor_proxy(&mut owner_ctl, "svc-o", "stcp", "sk-o", None).await;

    let (_alice_ctl, resp) = login_with_identity(addr, "alice", HashMap::new())
        .await
        .expect("alice login");
    let alice_run_id = resp.run_id.expect("alice run_id");

    // Second user (not the owner) -> denied with the exact owner-only text of
    // the fresh-conn STCP site.
    expect_fresh_stcp_verdict(
        addr,
        "svc-o",
        "sk-o",
        Some(&alice_run_id),
        Some(STCP_FRESH_VISITOR_NOT_ALLOWED),
        "non-owner alice on owner-only stcp proxy",
    )
    .await;

    // The owner claiming his own run_id -> identity "owner" -> admitted.
    let mut work = pool_work_conn(addr, &owner_run_id).await;
    tokio::time::sleep(Duration::from_millis(200)).await;

    let mut visitor =
        fresh_conn_with_first_frame(addr, stcp_visitor_msg("svc-o", "sk-o", Some(&owner_run_id)))
            .await;
    match recv_msg(&mut visitor, "owner NewVisitorConnResp").await {
        FrpMessage::NewVisitorConnResp(r) => assert!(
            r.error.is_none(),
            "owner should be admitted on his own owner-only proxy: {:?}",
            r.error
        ),
        other => panic!(
            "expected NewVisitorConnResp for owner, got type byte {:?}",
            other.v1_type_byte()
        ),
    }
    expect_start_work_conn(&mut work, "svc-o", "owner admit arm").await;

    drop(visitor);
    drop(work);
    drop(owner_ctl);
    // _alice_ctl drops here, closing alice's control.
}

fn xtcp_visitor_msg(
    transaction_id: &str,
    proxy_name: &str,
    sk: &str,
    pre_check: bool,
) -> FrpMessage {
    let (ts, sign_key) = sign_key_at(sk);
    FrpMessage::NatHoleVisitor(msg::NatHoleVisitor {
        transaction_id: transaction_id.into(),
        proxy_name: proxy_name.into(),
        pre_check,
        protocol: Some("tcp".to_string()),
        sign_key: Some(sign_key),
        timestamp: Some(ts),
        mapped_addrs: None,
        assisted_addrs: None,
    })
}

/// Send a NatHoleVisitor over a control channel and assert the NatHoleResp
/// error exactly equals `want_error`.
async fn expect_ctl_nat_hole_verdict(
    ctl: &mut IoStream,
    transaction_id: &str,
    proxy_name: &str,
    sk: &str,
    pre_check: bool,
    want_error: Option<&str>,
    ctx: &str,
) {
    write_msg_v1(
        ctl,
        &xtcp_visitor_msg(transaction_id, proxy_name, sk, pre_check),
    )
    .await
    .unwrap_or_else(|e| panic!("{ctx}: send NatHoleVisitor: {e}"));
    match recv_msg(ctl, &format!("{ctx}: NatHoleResp")).await {
        FrpMessage::NatHoleResp(r) => {
            assert_eq!(
                r.error.as_deref(),
                want_error,
                "{ctx}: NatHoleResp error mismatch for {proxy_name} (pre_check={pre_check})"
            );
            assert_eq!(r.transaction_id, transaction_id, "{ctx}: wrong txn");
        }
        other => panic!(
            "{ctx}: expected NatHoleResp, got type byte {:?}",
            other.v1_type_byte()
        ),
    }
}

/// XTCP control-channel site (control/nathole.rs:495 — the path real XTCP
/// frpc visitors use: registration NewVisitorConn + NatHoleVisitor per user
/// connection are both sent over the visitor's own control channel):
///   allow-list proxy: registration "auth failed", NatHoleVisitor (pre_check
///   and full arms) "access denied"; listed user admitted through both.
///   owner-only proxy: "access denied: owner only"; owner admitted.
#[tokio::test]
async fn xtcp_allow_users_enforced_on_control_channel() {
    let addr = start_two_user_server(allocate_port()).await;

    // Provider "owner": one allow-list proxy and one owner-only proxy.
    let (mut owner_ctl, _) = login_with_identity(addr, "owner", HashMap::new())
        .await
        .expect("owner login");
    register_visitor_proxy(
        &mut owner_ctl,
        "xcp-l",
        "xtcp",
        "sk-xl",
        Some(vec!["alice".into()]),
    )
    .await;
    register_visitor_proxy(&mut owner_ctl, "xcp-o", "xtcp", "sk-xo", None).await;

    // bob: logged in but not listed anywhere.
    let (mut bob_ctl, _) = login_with_identity(addr, "bob", HashMap::new())
        .await
        .expect("bob login");

    // Startup registration NewVisitorConn on the control channel: denied
    // with the control-channel registration text "auth failed" (even though
    // bob's sign_key is correct — the user gate fires first).
    write_msg_v1(&mut bob_ctl, &ctl_registration_msg("xcp-l", "sk-xl"))
        .await
        .expect("bob registration NewVisitorConn");
    match recv_msg(&mut bob_ctl, "bob registration NewVisitorConnResp").await {
        FrpMessage::NewVisitorConnResp(r) => assert_eq!(
            r.error.as_deref(),
            Some(XTCP_CTL_REG_AUTH_FAILED),
            "bob registration on allow-list proxy must fail: {:?}",
            r.error
        ),
        other => panic!(
            "expected NewVisitorConnResp for bob registration, got type byte {:?}",
            other.v1_type_byte()
        ),
    }

    // Per-connection NatHoleVisitor, pre_check arm: "access denied".
    expect_ctl_nat_hole_verdict(
        &mut bob_ctl,
        "txn-bob-precheck",
        "xcp-l",
        "sk-xl",
        true,
        Some(XTCP_CTL_LIST_DENIED),
        "bob pre_check on allow-list xtcp proxy",
    )
    .await;
    // Full arm (real punch request): same gate, same text.
    expect_ctl_nat_hole_verdict(
        &mut bob_ctl,
        "txn-bob-full",
        "xcp-l",
        "sk-xl",
        false,
        Some(XTCP_CTL_LIST_DENIED),
        "bob full NatHoleVisitor on allow-list xtcp proxy",
    )
    .await;
    // Owner-only proxy (empty allow_users): the owner-only text.
    expect_ctl_nat_hole_verdict(
        &mut bob_ctl,
        "txn-bob-owneronly",
        "xcp-o",
        "sk-xo",
        true,
        Some(XTCP_CTL_OWNER_ONLY_DENIED),
        "bob pre_check on owner-only xtcp proxy",
    )
    .await;

    // alice: listed user. Registration succeeds (Go parity ack = ReqWorkConn)
    // and her pre_check passes the gate (error None).
    let (mut alice_ctl, _) = login_with_identity(addr, "alice", HashMap::new())
        .await
        .expect("alice login");
    write_msg_v1(&mut alice_ctl, &ctl_registration_msg("xcp-l", "sk-xl"))
        .await
        .expect("alice registration NewVisitorConn");
    match recv_msg(&mut alice_ctl, "alice registration ack").await {
        FrpMessage::ReqWorkConn(_) => {}
        other => panic!(
            "alice registration should be acked with ReqWorkConn, got type byte {:?}",
            other.v1_type_byte()
        ),
    }
    expect_ctl_nat_hole_verdict(
        &mut alice_ctl,
        "txn-alice-precheck",
        "xcp-l",
        "sk-xl",
        true,
        None,
        "alice pre_check on allow-list xtcp proxy",
    )
    .await;

    // owner: admitted on his own owner-only proxy.
    expect_ctl_nat_hole_verdict(
        &mut owner_ctl,
        "txn-owner-precheck",
        "xcp-o",
        "sk-xo",
        true,
        None,
        "owner pre_check on his owner-only xtcp proxy",
    )
    .await;

    drop(bob_ctl);
    drop(alice_ctl);
    drop(owner_ctl);
}

/// XTCP fresh-conn site (handlers/dispatch.rs:453 + :577): a fresh TCP
/// NatHoleVisitor carries no user identity (""), so a restricted proxy
/// refuses it with the fresh-path texts — restricted proxies must be reached
/// over the control channel instead.
#[tokio::test]
async fn xtcp_fresh_conn_restricted_proxy_refused() {
    let addr = start_two_user_server(allocate_port()).await;

    let (mut owner_ctl, _) = login_with_identity(addr, "owner", HashMap::new())
        .await
        .expect("owner login");
    register_visitor_proxy(
        &mut owner_ctl,
        "xcp-f",
        "xtcp",
        "sk-f",
        Some(vec!["alice".into()]),
    )
    .await;

    // pre_check arm: refused before any sk auth — the exact fresh-precheck text.
    let mut io = fresh_conn_with_first_frame(
        addr,
        xtcp_visitor_msg("txn-fresh-precheck", "xcp-f", "sk-f", true),
    )
    .await;
    match recv_msg(&mut io, "fresh pre_check NatHoleResp").await {
        FrpMessage::NatHoleResp(r) => assert_eq!(
            r.error.as_deref(),
            Some(XTCP_FRESH_PRE_CHECK_DENIED),
            "fresh pre_check on restricted xtcp proxy: {:?}",
            r.error
        ),
        other => panic!(
            "expected NatHoleResp, got type byte {:?}",
            other.v1_type_byte()
        ),
    }

    // Full arm with a VALID sign_key: sk auth passes, the user gate (identity
    // "" on a fresh conn) still refuses with the fresh-full text.
    let mut io = fresh_conn_with_first_frame(
        addr,
        xtcp_visitor_msg("txn-fresh-full", "xcp-f", "sk-f", false),
    )
    .await;
    match recv_msg(&mut io, "fresh full NatHoleResp").await {
        FrpMessage::NatHoleResp(r) => assert_eq!(
            r.error.as_deref(),
            Some(XTCP_FRESH_FULL_DENIED),
            "fresh full NatHoleVisitor on restricted xtcp proxy: {:?}",
            r.error
        ),
        other => panic!(
            "expected NatHoleResp, got type byte {:?}",
            other.v1_type_byte()
        ),
    }

    drop(owner_ctl);
}
