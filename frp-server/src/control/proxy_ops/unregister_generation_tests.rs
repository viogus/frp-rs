use super::*;
use std::time::{Duration, Instant};

pub(crate) fn test_state() -> Arc<AppState> {
    let cfg = frp_core::config::ServerConfig::default();
    Arc::new(AppState::new(
        frp_core::auth::AuthConfig::with_token("test-token"),
        "127.0.0.1".into(),
        frp_core::encryption::derive_key("test-token"),
        vec![frp_core::config::PortsRange {
            start: 1,
            end: u16::MAX,
            single: 0,
        }],
        String::new(),
        true,
        30,
        None,
        7200,
        0,
        0,
        90,
        1500,
        false,
        None,
        0,
        60,
        10,
        false,
        String::new(),
        Arc::new(crate::plugin::HttpPluginManager::new(Vec::new())),
        0,
        0,
        0,
        168,
        true,
        0,
        0,
        frp_core::config::ServerConfigSnapshot::from_config(&cfg),
    ))
}

async fn insert_control(state: &Arc<AppState>, run_id: &str, control_id: u64) {
    let _rx = insert_control_rx(state, run_id, control_id).await;
}

async fn insert_control_rx(
    state: &Arc<AppState>,
    run_id: &str,
    control_id: u64,
) -> mpsc::Receiver<InternalMsg> {
    let (tx, rx) = tokio::sync::mpsc::channel(8);
    state.run_id_to_ctl_tx.insert(
        run_id.to_string(),
        crate::state::ControlTx {
            tx,
            client_addr: None,
            login_time: std::time::Instant::now(),
            login_time_unix: 0,
            pool_stats: Arc::new(crate::state::PoolStats::default()),
            user: String::new(),
            control_id,
            udp_packet_codec: String::new(),
            wire_v2: false,
            superseded: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        },
    );
    rx
}

pub(crate) fn proxy_info(
    name: &str,
    proxy_type: &str,
    run_id: &str,
    remote_port: Option<u16>,
    control_id: u64,
) -> ProxyInfo {
    ProxyInfo {
        name: name.into(),
        proxy_type: proxy_type.into(),
        run_id: run_id.into(),
        control_id,
        remote_port,
        sk: None,
        group: None,
        group_key: None,
        local_addr: Some("127.0.0.1:8080".to_string()),
        use_encryption: false,
        use_compression: false,
        virtual_net: None,
        allow_users: Vec::new(),
        proxy_protocol_version: String::new(),
        response_headers: std::collections::HashMap::new(),
        custom_domains: Vec::new(),
        route_by_http_user: String::new(),
        multiplexer: String::new(),
        bandwidth_limit: String::new(),
        bandwidth_limit_mode: String::new(),
        bandwidth_limiter: None,
        udp_packet_codec: String::new(),
        user: String::new(),
        user_conn_sem: None,
    }
}

/// A minimal `msg::NewProxy` for registration tests. All optional fields
/// start None so each test only sets what its path needs.
fn new_proxy(proxy_name: &str, proxy_type: &str) -> msg::NewProxy {
    msg::NewProxy {
        proxy_name: proxy_name.to_string(),
        proxy_type: proxy_type.to_string(),
        use_encryption: None,
        use_compression: None,
        group: None,
        group_key: None,
        local_str: None,
        remote_port: None,
        sk: None,
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
    }
}

#[tokio::test]
async fn stale_failure_cannot_unregister_superseding_control() {
    let state = test_state();
    insert_control(&state, "run-1", 7).await;

    // An older failing control (generation 3) must not delete the
    // replacement's routing entry.
    unregister_control(&state, "run-1", 3, false, true).await;
    assert!(state.run_id_to_ctl_tx.contains_key("run-1"));

    // The replacement itself may still clean up its own generation.
    unregister_control(&state, "run-1", 7, false, true).await;
    assert!(!state.run_id_to_ctl_tx.contains_key("run-1"));
}

/// Round-4 audit finding: unregister_control's entry removal used to be
/// `get` then unconditional `remove` — a fresh re-login's insert landing
/// between them deleted the fresh ControlTx entry, and remove_user then
/// deleted its fresh user record. The removal is now a single atomic
/// remove_if keyed on control_id: a stale generation's cleanup is a
/// no-op for BOTH the routing entry and the user record, and a matching
/// cleanup drops both. The user record is additionally generation-exact
/// on its own: it is stored as (control_id, UserInfo) and remove_user
/// removes only when the stored control_id matches, so a stale remover is
/// a no-op regardless of interleaving. (This test exercises the atomic
/// remove_if gate; the generation-exact user record itself is covered by
/// `remove_user_is_generation_exact` in plugin/http.rs.)
///
/// Needs `http-proxy`: the test seeds `plugin_manager.record_login_user`
/// and asserts `plugin_manager.user_info` is `Some`, but the
/// `#[cfg(not(feature = "http-proxy"))]` stub at
/// frp-server/src/plugin/mod.rs:8-34 makes the first a no-op (:29) and
/// the second return `None` (:30-32), so the `assert_eq!` at :202 cannot
/// hold in that configuration. Measured: `cargo test -p frp-server
/// --no-default-features --lib unregister_generation_tests` ->
/// `48 passed; 1 failed` (`left: None`, `right: Some("fresh")`); with
/// `--features http-proxy` -> `49 passed; 0 failed`.
#[cfg(feature = "http-proxy")]
#[tokio::test]
async fn stale_unregister_keeps_fresh_user_record() {
    let state = test_state();
    state.plugin_manager.record_login_user(
        "run-1",
        7, // the fresh control's generation — remove_user is generation-exact
        &crate::plugin::UserInfo {
            user: "fresh".to_string(),
            metas: std::collections::HashMap::new(),
            run_id: "run-1".to_string(),
        },
    );
    insert_control(&state, "run-1", 7).await;

    // Stale generation 3's cleanup must not touch generation 7's routing
    // entry or its user record.
    unregister_control(&state, "run-1", 3, false, true).await;
    assert!(
        state.run_id_to_ctl_tx.contains_key("run-1"),
        "stale cleanup must not delete the fresh ControlTx entry"
    );
    assert_eq!(
        state.plugin_manager.user_info("run-1").map(|u| u.user),
        Some("fresh".to_string()),
        "stale cleanup must not delete the fresh control's user record"
    );

    // The fresh control's own cleanup removes both.
    unregister_control(&state, "run-1", 7, false, true).await;
    assert!(!state.run_id_to_ctl_tx.contains_key("run-1"));
    assert!(
        state.plugin_manager.user_info("run-1").is_none(),
        "matching cleanup must drop the user record"
    );
}

/// Regression test for the used_ports ↔ port_reservations lock-order
/// inversion (audit Task 1). `unregister_control` used to hold
/// `used_ports.write()` while acquiring `port_reservations.write()`,
/// while `allocate_proxy_port` held `port_reservations.write()` while
/// acquiring `used_ports.read()` — the reconnect-during-cleanup
/// interleaving below deadlocked both, wedging the whole service.
///
/// Deterministic staging (single-threaded test runtime): the test holds
/// `port_reservations.write()` and spawns the allocator first, then the
/// cleanup, so both queue on `port_reservations` in FIFO order. The
/// cleanup grabs `used_ports.write()` and parks on `port_reservations`
/// behind the allocator; releasing the test's guard grants the
/// allocator, which (old order) parks on `used_ports.read()` while still
/// holding `port_reservations` — a guaranteed ABBA deadlock. With the
/// fix the allocator drops `port_reservations` before touching
/// `used_ports`, so the cleanup proceeds and both complete.
#[tokio::test]
async fn concurrent_register_unregister_no_lock_order_deadlock() {
    let state = test_state();
    insert_control(&state, "run-1", 1).await;

    // A live TCP proxy for run-1 so the cleanup exercises the TCP port
    // release path.
    state
        .proxy_manager
        .register(
            "run-1".to_string(),
            proxy_info("p1", "tcp", "run-1", Some(49901), 0),
        )
        .await
        .expect("register p1");

    // Fresh (non-expired) 24h reservation for the allocating proxy.
    state
        .port_reservations
        .write()
        .await
        .insert("reg-test".to_string(), (49902, false, Instant::now()));

    // Stage the interleaving. Allocator first: it queues as a writer on
    // port_reservations (held by the test) and parks without acquiring
    // anything else.
    let held_reservations = state.port_reservations.write().await;
    let alloc = tokio::spawn({
        let state = state.clone();
        async move {
            let np = msg::NewProxy {
                proxy_name: "reg-test".to_string(),
                proxy_type: "tcp".to_string(),
                use_encryption: None,
                use_compression: None,
                group: None,
                group_key: None,
                local_str: None,
                remote_port: None,
                sk: None,
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
            };
            allocate_proxy_port(&state, &np, true, false, false, 0).await
        }
    });
    tokio::task::yield_now().await;
    // Cleanup second: it must acquire used_ports.write() (free) and park
    // on port_reservations behind the allocator. Staging check: the
    // cleanup removes the run_id entry before its first park, and every
    // await between that removal and the port_reservations park is
    // uncontended (cannot pend), so a removed entry means it is parked
    // on port_reservations. (Pre-fix it was parked there while still
    // holding used_ports.write().)
    let unreg = tokio::spawn({
        let state = state.clone();
        async move { unregister_control(&state, "run-1", 1, false, true).await }
    });
    tokio::task::yield_now().await;
    assert!(
        !state.run_id_to_ctl_tx.contains_key("run-1"),
        "cleanup should have run and parked on port_reservations"
    );

    // Release the reservations lock: the allocator is granted first
    // (FIFO). With the old lock order both tasks now wait on each other
    // forever; with the fix both complete.
    drop(held_reservations);
    tokio::time::timeout(Duration::from_secs(5), alloc)
        .await
        .expect("allocator hung: lock-order deadlock")
        .expect("allocator task panicked")
        .expect("allocator must succeed once the reservations lock is released");
    tokio::time::timeout(Duration::from_secs(5), unreg)
        .await
        .expect("cleanup hung: lock-order deadlock")
        .expect("cleanup task panicked");
    // End-state: the cleanup released the live proxy's port and recorded
    // the 24h reservation for it.
    assert!(!state.used_ports.read().await.contains(&49901));
    assert!(state
        .port_reservations
        .read()
        .await
        .get("p1")
        .is_some_and(|&(port, is_udp, _)| port == 49901 && !is_udp));
}

#[tokio::test]
async fn unregister_group_len_recheck_keeps_listener_on_concurrent_join() {
    let state = test_state();
    insert_control(&state, "run-1", 1).await;

    // A live TCP group proxy for run-1: only member of group "grp".
    let mut g1 = proxy_info("g1", "tcp", "run-1", Some(49911), 1);
    g1.group = Some("grp".to_string());
    g1.group_key = Some("grp-key".to_string());
    state
        .proxy_manager
        .register("run-1".to_string(), g1)
        .await
        .expect("register g1");
    assert_eq!(state.proxy_manager.group_len("grp").await, 1);

    // The shared group listener exists (normally created by the NewProxy
    // handler for the first member).
    let cancel_token = tokio_util::sync::CancellationToken::new();
    state
        .tcp_group_ctl
        .create_group(
            "grp",
            "grp-key",
            49911,
            49911, // declared_port: unit harness registers with no conflict
            "0.0.0.0",
            tokio::spawn(async {}),
            cancel_token.clone(),
        )
        .await
        .expect("create group");

    // Stage the interleaving: hold port_reservations so the cleanup parks
    // at its phase-3 reservation insert — AFTER the phase-1 group_len
    // decision but BEFORE the phase-3 remove_group re-check. Every await
    // before that park (list_client, group_len, used_ports) is
    // uncontended, so a removed run_id entry means the task is parked
    // there with the phase-1 group_len already observed.
    let held_reservations = state.port_reservations.write().await;
    let unreg = tokio::spawn({
        let state = state.clone();
        async move { unregister_control(&state, "run-1", 1, false, true).await }
    });
    tokio::task::yield_now().await;
    assert!(
        !state.run_id_to_ctl_tx.contains_key("run-1"),
        "cleanup should have passed phase 1 and parked on port_reservations"
    );

    // A concurrent group-member join lands between phase 1 and phase 3.
    let mut g2 = proxy_info("g2", "tcp", "run-2", Some(49911), 2);
    g2.group = Some("grp".to_string());
    g2.group_key = Some("grp-key".to_string());
    state
        .proxy_manager
        .register("run-2".to_string(), g2)
        .await
        .expect("register g2");
    assert_eq!(state.proxy_manager.group_len("grp").await, 2);

    // Let the cleanup proceed: its phase-3 re-check must notice the
    // joined member and skip remove_group, keeping the shared listener
    // alive for the remaining live member.
    drop(held_reservations);
    tokio::time::timeout(Duration::from_secs(5), unreg)
        .await
        .expect("cleanup hung")
        .expect("cleanup task panicked");

    // The group listener survives with its live member.
    assert!(
        state.tcp_group_ctl.group_exists("grp").await,
        "shared group listener must survive a concurrent member join"
    );
    assert!(!cancel_token.is_cancelled());
    assert_eq!(state.proxy_manager.group_len("grp").await, 2);
    assert!(state.proxy_manager.get("g2").await.is_some());
}

#[cfg(feature = "vnet")]
#[tokio::test]
async fn unregister_control_removes_run_id_vnet_routes_and_broadcasts_remove() {
    let state = test_state();
    let mut peer_rx = insert_control_rx(&state, "run-b", 2).await;
    insert_control(&state, "run-a", 1).await;
    // The sweep removes vnet routes per proxy (audit finding 3), so the
    // proxies owning the routes must be registered under the removing
    // control's generation.
    state
        .proxy_manager
        .register(
            "run-a".to_string(),
            proxy_info("proxy-a", "vnet", "run-a", Some(0), 1),
        )
        .await
        .expect("register proxy-a");
    state
        .proxy_manager
        .register(
            "run-a".to_string(),
            proxy_info("visitor-v6", "vnet", "run-a", Some(0), 1),
        )
        .await
        .expect("register visitor-v6");
    {
        let mut routes = state.vnet_routes.write().await;
        routes.insert(
            ("vnet-a".to_string(), "10.0.0.0/24".to_string()),
            ("run-a".to_string(), "proxy-a".to_string()),
        );
        routes.insert(
            ("vnet-a".to_string(), "2001:db8::/64".to_string()),
            ("run-a".to_string(), "visitor-v6".to_string()),
        );
        routes.insert(
            ("vnet-b".to_string(), "10.1.0.0/24".to_string()),
            ("run-b".to_string(), "proxy-b".to_string()),
        );
        // run-b also participates in vnet-a, so it is a peer of run-a's
        // vnet-a routes and must receive the broadcast removes below.
        routes.insert(
            ("vnet-a".to_string(), "10.99.0.0/24".to_string()),
            ("run-b".to_string(), "proxy-b-vnet-a".to_string()),
        );
    }

    unregister_control(&state, "run-a", 1, false, true).await;

    let routes = state.vnet_routes.read().await;
    assert!(routes.iter().all(|(_, (run_id, _))| run_id != "run-a"));
    assert!(routes.contains_key(&("vnet-b".to_string(), "10.1.0.0/24".to_string())));
    assert!(routes.contains_key(&("vnet-a".to_string(), "10.99.0.0/24".to_string())));
    drop(routes);

    let mut removes = Vec::new();
    for _ in 0..2 {
        match tokio::time::timeout(Duration::from_secs(5), peer_rx.recv()).await {
            Ok(Some(InternalMsg::VnetRouteRemoveForward { msg })) => removes.push(msg),
            other => panic!("expected forwarded remove, got {:?}", other),
        }
    }
    assert!(removes
        .iter()
        .any(|m| { m.proxy_name == "proxy-a" && m.virtual_net.as_deref() == Some("vnet-a") }));
    assert!(removes
        .iter()
        .any(|m| { m.proxy_name == "visitor-v6" && m.virtual_net.as_deref() == Some("vnet-a") }));
}

#[test]
fn prune_removes_expired_keeps_fresh() {
    let now = Instant::now();
    let mut map = crate::state::PortReservationMap::new();
    map.insert(
        "fresh".to_string(),
        (8080, true, now - Duration::from_secs(3600)),
    );
    map.insert(
        "expired".to_string(),
        (8081, false, now - Duration::from_secs(25 * 3600)),
    );

    assert_eq!(prune_expired_reservations_inner(&mut map, now), 1);
    assert!(map.contains_key("fresh"));
    assert!(!map.contains_key("expired"));
}

#[test]
fn prune_empty_map_is_noop() {
    let now = Instant::now();
    let mut map = crate::state::PortReservationMap::new();
    assert_eq!(prune_expired_reservations_inner(&mut map, now), 0);
    assert!(map.is_empty());
}

#[test]
fn prune_boundary_just_under_24h_is_kept() {
    // Strictly-less-than semantics: a reservation younger than 24h is
    // kept. (An exactly-24h boundary is not testable with Instant —
    // `now - 24h` then `now.duration_since(..)` includes nanosecond
    // overhead, so it would nondeterministically count as expired.)
    let now = Instant::now();
    let mut map = crate::state::PortReservationMap::new();
    map.insert(
        "boundary".to_string(),
        (8082, true, now - Duration::from_secs(24 * 3600 - 1)),
    );

    assert_eq!(prune_expired_reservations_inner(&mut map, now), 0);
    assert!(map.contains_key("boundary"));
}

/// Audit finding 1 regression: `client_ports_used` must only count
/// proxies that actually consume a port (tcp/udp/sudp with a real
/// remote port). stcp/xtcp/http/https/tcpmux register with remote port
/// 0 and previously inflated the count the `max_ports_per_client` gate
/// checks.
#[tokio::test]
async fn client_ports_used_counts_only_port_consuming_proxies() {
    let state = test_state();
    insert_control(&state, "run-1", 1).await;
    let (itx, _rx) = mpsc::channel(8);
    let mut handles: std::collections::HashMap<String, tokio::task::JoinHandle<()>> =
        std::collections::HashMap::new();
    let mut udp_sockets: std::collections::HashMap<String, std::sync::Arc<tokio::net::UdpSocket>> =
        std::collections::HashMap::new();

    // tcp proxy → counted.
    let mut np = new_proxy("p1", "tcp");
    np.remote_port = Some(24021);
    let mut writer = Vec::new();
    handle_new_proxy(
        np,
        "run-1",
        1,
        &state,
        &mut writer,
        &itx,
        &mut handles,
        &mut udp_sockets,
        false,
    )
    .await;
    assert_eq!(
        *state.client_ports_used.read().await.get("run-1").unwrap(),
        1,
        "tcp proxy must count against the client port budget"
    );

    // http proxy (remote port 0) → must NOT inflate the count.
    let mut np = new_proxy("p2", "http");
    np.custom_domains = Some(vec!["example.com".to_string()]);
    let mut writer = Vec::new();
    handle_new_proxy(
        np,
        "run-1",
        1,
        &state,
        &mut writer,
        &itx,
        &mut handles,
        &mut udp_sockets,
        false,
    )
    .await;
    assert_eq!(
        *state.client_ports_used.read().await.get("run-1").unwrap(),
        1,
        "http proxy (remote port 0) must not inflate the port count"
    );

    // stcp proxy (no remote port) → must NOT inflate the count.
    let mut np = new_proxy("p3", "stcp");
    np.sk = Some("secret".to_string());
    let mut writer = Vec::new();
    handle_new_proxy(
        np,
        "run-1",
        1,
        &state,
        &mut writer,
        &itx,
        &mut handles,
        &mut udp_sockets,
        false,
    )
    .await;
    assert_eq!(
        *state.client_ports_used.read().await.get("run-1").unwrap(),
        1,
        "stcp proxy (no remote port) must not inflate the port count"
    );

    // Second tcp proxy → 2.
    let mut np = new_proxy("p4", "tcp");
    np.remote_port = Some(24022);
    let mut writer = Vec::new();
    handle_new_proxy(
        np,
        "run-1",
        1,
        &state,
        &mut writer,
        &itx,
        &mut handles,
        &mut udp_sockets,
        false,
    )
    .await;
    assert_eq!(
        *state.client_ports_used.read().await.get("run-1").unwrap(),
        2,
        "two tcp proxies must count 2"
    );

    // Disconnect cleanup decrements by the count of port-consuming
    // proxies it actually removes (finding 3 symmetry): entry cleared.
    unregister_control(&state, "run-1", 1, false, true).await;
    assert!(
        state.client_ports_used.read().await.get("run-1").is_none(),
        "cleanup must remove the per-client port count"
    );
}

/// Audit finding 2 regression: closing one SUDP proxy must not release
/// the shared UDP port while another live SUDP proxy still holds it.
#[tokio::test]
async fn sudp_shared_port_released_only_when_last_owner() {
    let state = test_state();
    state.used_udp_ports.write().await.insert(24023);
    state
        .proxy_manager
        .register(
            "run-1".to_string(),
            proxy_info("s1", "sudp", "run-1", Some(24023), 1),
        )
        .await
        .expect("register s1");
    state
        .proxy_manager
        .register(
            "run-1".to_string(),
            proxy_info("s2", "sudp", "run-1", Some(24023), 1),
        )
        .await
        .expect("register s2");

    // Closing s1 while s2 still holds the port must NOT release it.
    // Mirrors handle_close_proxy: the owner check runs while the closing
    // proxy is still in the registry; the registry removal happens after.
    assert!(
        !release_udp_port_with_owner_check(&state, 24023, "s1").await,
        "shared port must stay allocated while s2 is live"
    );
    assert!(
        state.used_udp_ports.read().await.contains(&24023),
        "port must remain marked while a sibling SUDP proxy holds it"
    );
    state.proxy_manager.remove("s1").await;

    // Closing the last owner releases it.
    assert!(
        release_udp_port_with_owner_check(&state, 24023, "s2").await,
        "last SUDP owner must release the port"
    );
    assert!(
        !state.used_udp_ports.read().await.contains(&24023),
        "port must be released after the last owner closes"
    );
    state.proxy_manager.remove("s2").await;

    // Closing a proxy that never existed is a no-op release.
    assert!(
        release_udp_port_with_owner_check(&state, 24023, "ghost").await,
        "no live owner means the port is free to release"
    );
}

/// Audit finding 3 regression: when the 10s handoff barrier times out,
/// the old control's sweep must skip proxies registered by the
/// superseding control — it must only tear down its own generation.
#[tokio::test]
async fn unregister_control_generation_filter_skips_newer_proxies() {
    let state = test_state();
    // The superseding control (generation 2) owns the run_id entry.
    insert_control(&state, "run-1", 2).await;
    // Old control's proxy (generation 1) + new control's proxy (2).
    state
        .proxy_manager
        .register(
            "run-1".to_string(),
            proxy_info("old-proxy", "tcp", "run-1", Some(24024), 1),
        )
        .await
        .expect("register old-proxy");
    state
        .proxy_manager
        .register(
            "run-1".to_string(),
            proxy_info("new-proxy", "tcp", "run-1", Some(24025), 2),
        )
        .await
        .expect("register new-proxy");
    {
        let mut ports = state.used_ports.write().await;
        ports.insert(24024);
        ports.insert(24025);
    }
    state
        .client_ports_used
        .write()
        .await
        .insert("run-1".to_string(), 2);

    // Old control (generation 1) sweeps: only its own proxy's port is
    // released; the new control's proxy and counts survive.
    unregister_control(&state, "run-1", 1, false, true).await;
    assert!(
        !state.used_ports.read().await.contains(&24024),
        "old control's port must be released"
    );
    assert!(
        state.used_ports.read().await.contains(&24025),
        "superseding control's port must survive the old sweep"
    );
    assert_eq!(
        *state.client_ports_used.read().await.get("run-1").unwrap(),
        1,
        "only the old control's count may be decremented"
    );
    assert!(
        state.run_id_to_ctl_tx.contains_key("run-1"),
        "superseding control's routing entry must survive"
    );

    // The superseding control's own cleanup sweeps everything.
    unregister_control(&state, "run-1", 2, false, true).await;
    assert!(
        !state.used_ports.read().await.contains(&24025),
        "superseding control must release its own port on disconnect"
    );
    assert!(
        state.client_ports_used.read().await.get("run-1").is_none(),
        "per-client count must be cleared when the last control leaves"
    );
}

/// M2: tcpmux load-balancing group (Go frp v0.71.0 group.TCPMuxGroup).
/// A second client with the SAME group + group_key + routing params
/// joins the group instead of hitting the route conflict — the shared
/// route stays keyed on the first member, and accepted conns fan out
/// round-robin across members.
#[tokio::test]
async fn tcpmux_group_second_member_joins_shared_route() {
    let state = test_state();
    insert_control(&state, "run-1", 1).await;
    insert_control(&state, "run-2", 2).await;
    let (itx, _rx) = mpsc::channel(8);
    let mut handles: std::collections::HashMap<String, tokio::task::JoinHandle<()>> =
        std::collections::HashMap::new();
    let mut udp_sockets: std::collections::HashMap<String, std::sync::Arc<tokio::net::UdpSocket>> =
        std::collections::HashMap::new();

    // First member (client run-1) creates the group and registers the
    // shared route, tagged with the group name.
    let mut np1 = new_proxy("mux-a", "tcpmux");
    np1.custom_domains = Some(vec!["a.example.com".to_string()]);
    np1.group = Some("web".to_string());
    np1.group_key = Some("gk".to_string());
    np1.http_user = Some("alice".to_string());
    np1.http_pwd = Some("secret".to_string());
    let mut writer1 = Vec::new();
    let ok = handle_new_proxy(
        np1,
        "run-1",
        1,
        &state,
        &mut writer1,
        &itx,
        &mut handles,
        &mut udp_sockets,
        false,
    )
    .await;
    assert!(ok, "first group member must register");
    let route = state
        .tcpmux_manager
        .lookup("a.example.com", "alice")
        .await
        .expect("shared route must be registered");
    assert_eq!(route.proxy_name, "mux-a", "route keys on the first member");
    assert_eq!(route.group, "web", "shared route must carry the group");

    // Second member (client run-2), identical group/group_key/params:
    // joins the member list — no route conflict, no own route.
    let mut np2 = new_proxy("mux-b", "tcpmux");
    np2.custom_domains = Some(vec!["a.example.com".to_string()]);
    np2.group = Some("web".to_string());
    np2.group_key = Some("gk".to_string());
    np2.http_user = Some("alice".to_string());
    np2.http_pwd = Some("secret".to_string());
    let mut writer2 = Vec::new();
    let ok = handle_new_proxy(
        np2,
        "run-2",
        2,
        &state,
        &mut writer2,
        &itx,
        &mut handles,
        &mut udp_sockets,
        false,
    )
    .await;
    assert!(ok, "matching second member must join the group");
    assert!(
        state.proxy_manager.get("mux-b").await.is_some(),
        "joined member must be registered"
    );
    assert!(
        !String::from_utf8_lossy(&writer2).contains("conflict"),
        "second member must NOT be rejected as a route conflict: {}",
        String::from_utf8_lossy(&writer2)
    );

    // Round-robin fan-out: accepted conns alternate members.
    assert_eq!(
        state
            .tcpmux_group_ctl
            .choose_endpoint("web")
            .await
            .as_deref(),
        Some("mux-a")
    );
    assert_eq!(
        state
            .tcpmux_group_ctl
            .choose_endpoint("web")
            .await
            .as_deref(),
        Some("mux-b")
    );

    // Both members' routes auth against the SHARED route (validated
    // equal at join) — the first member's credentials gate the group.
    assert_eq!(route.http_user, "alice");
}

/// Register a tcpmux proxy through `handle_new_proxy`, returning
/// (accepted, response_text) for rejection-text assertions.
async fn register_proxy_via_handler(
    state: &Arc<AppState>,
    itx: &mpsc::Sender<InternalMsg>,
    handles: &mut std::collections::HashMap<String, tokio::task::JoinHandle<()>>,
    udp_sockets: &mut std::collections::HashMap<String, std::sync::Arc<tokio::net::UdpSocket>>,
    np: msg::NewProxy,
    run_id: &str,
    ctl_id: u64,
) -> (bool, String) {
    let mut writer = Vec::new();
    let ok = handle_new_proxy(
        np,
        run_id,
        ctl_id,
        state,
        &mut writer,
        itx,
        handles,
        udp_sockets,
        false,
    )
    .await;
    (ok, String::from_utf8_lossy(&writer).to_string())
}

/// M2: same group but mismatched routing params or group_key rejects
/// with the Go-verbatim errors ("group params invalid" /
/// "group auth failed"), rolled back without touching the group.
#[tokio::test]
async fn tcpmux_group_mismatch_rejected_with_go_errors() {
    let state = test_state();
    insert_control(&state, "run-1", 1).await;
    insert_control(&state, "run-2", 2).await;
    let (itx, _rx) = mpsc::channel(8);
    let mut handles: std::collections::HashMap<String, tokio::task::JoinHandle<()>> =
        std::collections::HashMap::new();
    let mut udp_sockets: std::collections::HashMap<String, std::sync::Arc<tokio::net::UdpSocket>> =
        std::collections::HashMap::new();
    // First member with http auth.
    let mut np1 = new_proxy("mux-a", "tcpmux");
    np1.custom_domains = Some(vec!["a.example.com".to_string()]);
    np1.group = Some("web".to_string());
    np1.group_key = Some("gk".to_string());
    np1.http_user = Some("alice".to_string());
    np1.http_pwd = Some("secret".to_string());
    let (ok, _) = register_proxy_via_handler(
        &state,
        &itx,
        &mut handles,
        &mut udp_sockets,
        np1,
        "run-1",
        1,
    )
    .await;
    assert!(ok, "first member must register");

    // Password mismatch → Go ErrGroupParamsInvalid text.
    let mut np2 = new_proxy("mux-b", "tcpmux");
    np2.custom_domains = Some(vec!["a.example.com".to_string()]);
    np2.group = Some("web".to_string());
    np2.group_key = Some("gk".to_string());
    np2.http_user = Some("alice".to_string());
    np2.http_pwd = Some("wrong".to_string());
    let (ok, text) = register_proxy_via_handler(
        &state,
        &itx,
        &mut handles,
        &mut udp_sockets,
        np2,
        "run-2",
        2,
    )
    .await;
    assert!(!ok, "params mismatch must reject");
    assert!(
        text.contains("group params invalid"),
        "rejection must carry the Go text: {text}"
    );
    assert!(
        state.proxy_manager.get("mux-b").await.is_none(),
        "rejected member must be rolled back"
    );

    // Group_key mismatch → Go ErrGroupAuthFailed text.
    let mut np3 = new_proxy("mux-c", "tcpmux");
    np3.custom_domains = Some(vec!["a.example.com".to_string()]);
    np3.group = Some("web".to_string());
    np3.group_key = Some("WRONG".to_string());
    np3.http_user = Some("alice".to_string());
    np3.http_pwd = Some("secret".to_string());
    let (ok, text) = register_proxy_via_handler(
        &state,
        &itx,
        &mut handles,
        &mut udp_sockets,
        np3,
        "run-2",
        2,
    )
    .await;
    assert!(!ok, "group_key mismatch must reject");
    assert!(
        text.contains("group auth failed"),
        "rejection must carry the Go text: {text}"
    );

    // The group survives both rejections — the original member keeps
    // serving.
    assert_eq!(
        state
            .tcpmux_group_ctl
            .choose_endpoint("web")
            .await
            .as_deref(),
        Some("mux-a")
    );
}

/// F5 (audit round 8): HTTPS group membership compares ONLY the group
/// name and domain — Go HTTPSGroup.Listen (server/group/https.go) never
/// looks at the routeConfig's route_by_http_user (an https proxy carries
/// no locations and listenForDomain builds an empty RouteConfig). Pre-fix
/// the https path routed through the HTTP-group register_member, which
/// compared rubu too, so a second https member with a different
/// route_by_http_user was wrongly rejected as a params mismatch.
#[tokio::test]
async fn https_group_member_with_different_rubu_joins() {
    let state = test_state();
    insert_control(&state, "run-1", 1).await;
    insert_control(&state, "run-2", 2).await;
    let (itx, _rx) = mpsc::channel(8);
    let mut handles: std::collections::HashMap<String, tokio::task::JoinHandle<()>> =
        std::collections::HashMap::new();
    let mut udp_sockets: std::collections::HashMap<String, std::sync::Arc<tokio::net::UdpSocket>> =
        std::collections::HashMap::new();

    let mut np1 = new_proxy("h-a", "https");
    np1.custom_domains = Some(vec!["a.example.com".to_string()]);
    np1.group = Some("web".to_string());
    np1.group_key = Some("gk".to_string());
    np1.route_by_http_user = Some("alice".to_string());
    let mut writer1 = Vec::new();
    let ok = handle_new_proxy(
        np1,
        "run-1",
        1,
        &state,
        &mut writer1,
        &itx,
        &mut handles,
        &mut udp_sockets,
        false,
    )
    .await;
    assert!(ok, "first https group member must register");

    // Same group + domain, DIFFERENT route_by_http_user — must join
    // (Go https.go compares only group + domain).
    let mut np2 = new_proxy("h-b", "https");
    np2.custom_domains = Some(vec!["a.example.com".to_string()]);
    np2.group = Some("web".to_string());
    np2.group_key = Some("gk".to_string());
    np2.route_by_http_user = Some("bob".to_string());
    let mut writer2 = Vec::new();
    let ok = handle_new_proxy(
        np2,
        "run-2",
        2,
        &state,
        &mut writer2,
        &itx,
        &mut handles,
        &mut udp_sockets,
        false,
    )
    .await;
    let text = String::from_utf8_lossy(&writer2).to_string();
    assert!(
        ok,
        "different rubu must not block an https group join: {text}"
    );

    // Round-robin over both members.
    assert_eq!(
        state
            .http_group_ctl
            .choose_endpoint("web", true)
            .await
            .as_deref(),
        Some("h-a")
    );
    assert_eq!(
        state
            .http_group_ctl
            .choose_endpoint("web", true)
            .await
            .as_deref(),
        Some("h-b")
    );
}

/// F5: a second, DIFFERENT domain under the same https group name
/// rejects with Go's ErrGroupParamsInvalid text on the default-config
/// (non-detailed) branch — whether it arrives as one proxy listing two
/// domains ([a,b]; Go HTTPSProxy.Run fails on the second Listen) or as a
/// second member with a different single domain. A wrong group_key
/// rejects with ErrGroupAuthFailed verbatim. test_state enables detailed
/// errors, so the wire here explains the constraint, and the generic
/// mapping (what a default server sends) is pinned to the Go constant.
/// The [a,b] rejection must also roll back the first domain's group
/// membership and shared SNI route — no half-registered state survives.
#[tokio::test]
async fn https_group_second_domain_rejected_with_go_text() {
    let state = test_state();
    insert_control(&state, "run-1", 1).await;
    insert_control(&state, "run-2", 2).await;
    let (itx, _rx) = mpsc::channel(8);
    let mut handles: std::collections::HashMap<String, tokio::task::JoinHandle<()>> =
        std::collections::HashMap::new();
    let mut udp_sockets: std::collections::HashMap<String, std::sync::Arc<tokio::net::UdpSocket>> =
        std::collections::HashMap::new();

    // One proxy listing [a, b]: the second (different) domain must fail
    // the whole registration with the Go text, rolling back the first.
    let mut np1 = new_proxy("h-ab", "https");
    np1.custom_domains = Some(vec![
        "a.example.com".to_string(),
        "b.example.com".to_string(),
    ]);
    np1.group = Some("web".to_string());
    np1.group_key = Some("gk".to_string());
    let mut writer1 = Vec::new();
    let ok = handle_new_proxy(
        np1,
        "run-1",
        1,
        &state,
        &mut writer1,
        &itx,
        &mut handles,
        &mut udp_sockets,
        false,
    )
    .await;
    let text1 = String::from_utf8_lossy(&writer1).to_string();
    assert!(!ok, "[a,b] group https proxy must be rejected");
    assert!(
        text1.contains("exactly one distinct custom_domain"),
        "rejection must explain the constraint: {text1}"
    );
    // Default-config (detailed_errors off) branch: the generic mapping
    // of this exact error must be Go's ErrGroupParamsInvalid text.
    assert_eq!(
        err_msg(false, text1.clone(), "group params invalid"),
        "group params invalid",
        "the default-config wire text must be Go-verbatim"
    );
    assert!(
        state.proxy_manager.get("h-ab").await.is_none(),
        "rejected proxy must be rolled back"
    );
    assert_eq!(
        state.http_group_ctl.choose_endpoint("web", true).await,
        None,
        "the group created by the rejected registration must be gone"
    );
    assert!(
        state
            .vhost_manager
            .lookup("a.example.com", "", "", "https")
            .await
            .is_none(),
        "the shared SNI route of the rejected registration must be rolled back"
    );

    // Second member with a DIFFERENT single domain: rejected verbatim,
    // the existing group survives.
    let mut np2 = new_proxy("h-b", "https");
    np2.custom_domains = Some(vec!["b.example.com".to_string()]);
    np2.group = Some("web".to_string());
    np2.group_key = Some("gk".to_string());
    let mut writer2 = Vec::new();
    let ok = handle_new_proxy(
        np2,
        "run-2",
        2,
        &state,
        &mut writer2,
        &itx,
        &mut handles,
        &mut udp_sockets,
        false,
    )
    .await;
    assert!(ok, "first member (domain b) must register");
    let mut np3 = new_proxy("h-a2", "https");
    np3.custom_domains = Some(vec!["a.example.com".to_string()]);
    np3.group = Some("web".to_string());
    np3.group_key = Some("gk".to_string());
    let mut writer3 = Vec::new();
    let ok = handle_new_proxy(
        np3,
        "run-2",
        2,
        &state,
        &mut writer3,
        &itx,
        &mut handles,
        &mut udp_sockets,
        false,
    )
    .await;
    let text3 = String::from_utf8_lossy(&writer3).to_string();
    assert!(!ok, "different-domain member must be rejected");
    assert!(
        text3.contains("group params invalid"),
        "rejection must carry the Go text: {text3}"
    );
    assert_eq!(
        state
            .http_group_ctl
            .choose_endpoint("web", true)
            .await
            .as_deref(),
        Some("h-b"),
        "the existing group must survive the rejected join"
    );

    // Matching domain, WRONG group_key → Go ErrGroupAuthFailed.
    let mut np4 = new_proxy("h-key", "https");
    np4.custom_domains = Some(vec!["b.example.com".to_string()]);
    np4.group = Some("web".to_string());
    np4.group_key = Some("WRONG".to_string());
    let mut writer4 = Vec::new();
    let ok = handle_new_proxy(
        np4,
        "run-2",
        2,
        &state,
        &mut writer4,
        &itx,
        &mut handles,
        &mut udp_sockets,
        false,
    )
    .await;
    let text4 = String::from_utf8_lossy(&writer4).to_string();
    assert!(!ok, "group_key mismatch must reject");
    assert!(
        text4.contains("group auth failed"),
        "rejection must carry the Go text: {text4}"
    );
}

/// F5: a proxy listing the SAME custom_domain twice under a group name
/// is accepted — Go HTTPSGroup.Listen adds a second shared listener for
/// the repeated identical domain (https.go has no ErrProxyRepeated;
/// only the HTTP-group path repeats-rejects). frp-rs dedups to a single
/// member registration (both Go handles share one muxer listener and
/// one route — the dedup is a weight approximation, documented
/// divergence). Pre-fix the https group branch rejected ANY proxy whose
/// domain list was not exactly one entry.
#[tokio::test]
async fn https_group_repeated_same_domain_accepted() {
    let state = test_state();
    insert_control(&state, "run-1", 1).await;
    insert_control(&state, "run-2", 2).await;
    let (itx, _rx) = mpsc::channel(8);
    let mut handles: std::collections::HashMap<String, tokio::task::JoinHandle<()>> =
        std::collections::HashMap::new();
    let mut udp_sockets: std::collections::HashMap<String, std::sync::Arc<tokio::net::UdpSocket>> =
        std::collections::HashMap::new();

    let mut np1 = new_proxy("h-aa", "https");
    np1.custom_domains = Some(vec![
        "a.example.com".to_string(),
        "a.example.com".to_string(),
    ]);
    np1.group = Some("web".to_string());
    np1.group_key = Some("gk".to_string());
    let mut writer1 = Vec::new();
    let ok = handle_new_proxy(
        np1,
        "run-1",
        1,
        &state,
        &mut writer1,
        &itx,
        &mut handles,
        &mut udp_sockets,
        false,
    )
    .await;
    let text1 = String::from_utf8_lossy(&writer1).to_string();
    assert!(ok, "[a,a] group https proxy must register: {text1}");
    assert_eq!(
        state
            .http_group_ctl
            .choose_endpoint("web", true)
            .await
            .as_deref(),
        Some("h-aa"),
        "the single deduped member must serve the group"
    );

    // A normal second member can still join the same group.
    let mut np2 = new_proxy("h-b", "https");
    np2.custom_domains = Some(vec!["a.example.com".to_string()]);
    np2.group = Some("web".to_string());
    np2.group_key = Some("gk".to_string());
    let mut writer2 = Vec::new();
    let ok = handle_new_proxy(
        np2,
        "run-2",
        2,
        &state,
        &mut writer2,
        &itx,
        &mut handles,
        &mut udp_sockets,
        false,
    )
    .await;
    let text2 = String::from_utf8_lossy(&writer2).to_string();
    assert!(ok, "second member must join: {text2}");
    assert_eq!(
        state
            .http_group_ctl
            .choose_endpoint("web", true)
            .await
            .as_deref(),
        Some("h-b"),
        "round-robin must reach the second member"
    );
}

/// Go parity (server/service.go wires HTTPGroupController on the
/// httpVhostRouter and HTTPSGroupController on the httpsMuxer): an HTTP
/// group "web" and an HTTPS group "web" coexist — same group NAME,
/// independent member lists and routes. The kind-keyed registry
/// ((group, is_https)) mirrors the split; pre-fix both kinds shared one
/// registry, so the second kind's first member hit a false "already
/// exists" / params collision.
#[tokio::test]
async fn http_and_https_group_same_name_coexist() {
    let state = test_state();
    insert_control(&state, "run-1", 1).await;
    let (itx, _rx) = mpsc::channel(8);
    let mut handles: std::collections::HashMap<String, tokio::task::JoinHandle<()>> =
        std::collections::HashMap::new();
    let mut udp_sockets: std::collections::HashMap<String, std::sync::Arc<tokio::net::UdpSocket>> =
        std::collections::HashMap::new();

    // HTTP-kind member of group "web".
    let mut np1 = new_proxy("h-web", "http");
    np1.custom_domains = Some(vec!["web.example.com".to_string()]);
    np1.group = Some("web".to_string());
    np1.group_key = Some("k".to_string());
    let (ok, text) = register_proxy_via_handler(
        &state,
        &itx,
        &mut handles,
        &mut udp_sockets,
        np1,
        "run-1",
        1,
    )
    .await;
    assert!(ok, "http member must register: {text}");

    // HTTPS-kind member of the SAME group name, same domain.
    let mut np2 = new_proxy("hs-web", "https");
    np2.custom_domains = Some(vec!["web.example.com".to_string()]);
    np2.group = Some("web".to_string());
    np2.group_key = Some("k".to_string());
    let (ok, text) = register_proxy_via_handler(
        &state,
        &itx,
        &mut handles,
        &mut udp_sockets,
        np2,
        "run-1",
        1,
    )
    .await;
    assert!(
        ok,
        "https member of the same group name must register: {text}"
    );

    // Each kind's registry serves its own member.
    assert_eq!(
        state
            .http_group_ctl
            .choose_endpoint("web", false)
            .await
            .as_deref(),
        Some("h-web")
    );
    assert_eq!(
        state
            .http_group_ctl
            .choose_endpoint("web", true)
            .await
            .as_deref(),
        Some("hs-web")
    );

    // Unregistering the http member empties ONLY the http-kind group —
    // the route owner of the http kind is returned, and the https-kind
    // group keeps serving (kind-keyed removal).
    assert_eq!(
        state
            .http_group_ctl
            .unregister_member("web", "h-web", false)
            .await
            .as_deref(),
        Some("h-web"),
        "the http-kind group emptied with its owner"
    );
    assert_eq!(
        state.http_group_ctl.choose_endpoint("web", false).await,
        None
    );
    assert_eq!(
        state
            .http_group_ctl
            .choose_endpoint("web", true)
            .await
            .as_deref(),
        Some("hs-web"),
        "the https-kind group is untouched"
    );
}

/// Go parity (server/group/tcp.go:111-113): the group port comparison
/// is DECLARED-vs-DECLARED with NO zero exemption. An auto-assign
/// member (declared 0) cannot join an explicit-port group, and an
/// explicit-port member cannot join an auto-assign group (declared 0
/// stays 0 — the real port is stored separately). Both directions must
/// mismatch with the Go text; only declared==declared joins.
#[tokio::test]
async fn tcp_group_declared_port_strict_both_directions() {
    let state = test_state();
    let cancel_token = tokio_util::sync::CancellationToken::new();

    // Explicit-port group (declared == real: the harness registers with
    // no port conflict).
    state
        .tcp_group_ctl
        .create_group(
            "g",
            "k",
            24061,
            24061, // declared_port
            "127.0.0.1",
            tokio::spawn(async {}),
            cancel_token.clone(),
        )
        .await
        .expect("create group");
    // Auto-assign member vs explicit group: mismatch, NOT a join on the
    // group's real port (pre-fix the zero exemption let it in).
    assert_eq!(
        state
            .tcp_group_ctl
            .get_group_port("g", "k", 0, "127.0.0.1")
            .await,
        GroupPortQuery::Mismatch("group should have same remote port")
    );

    // Auto-assign group: declared stays 0, the real port is 24062.
    state
        .tcp_group_ctl
        .create_group(
            "a",
            "k",
            24062,
            0, // declared_port: first member was auto-assigned
            "127.0.0.1",
            tokio::spawn(async {}),
            cancel_token.clone(),
        )
        .await
        .expect("create group");
    // A second auto-assign member joins on the group's real port…
    assert_eq!(
        state
            .tcp_group_ctl
            .get_group_port("a", "k", 0, "127.0.0.1")
            .await,
        GroupPortQuery::Matched(24062)
    );
    // …but an explicit-port member mismatches (its declared number can
    // never equal the group's declared 0).
    assert_eq!(
        state
            .tcp_group_ctl
            .get_group_port("a", "k", 24062, "127.0.0.1")
            .await,
        GroupPortQuery::Mismatch("group should have same remote port")
    );
}

/// R3 test-gap pin: a full handler-level auto-assign group walk. The
/// ctl-level declared-port pins create groups directly, so every handler
/// wiring site that passes `np.remote_port.unwrap_or(0)` as the DECLARED
/// port (proxy_ops.rs join probe, group create, member registration) is
/// only exercised where declared == bound (explicit ports) — a regression
/// swapping the resolved bound port in for the declared value is
/// invisible to every explicit-port pin because the numbers coincide.
/// Here the first member declares nothing (remote_port None → auto-assign
/// binds an OS port while the group stores declared 0), a second
/// None-declaring member must still JOIN it, and an explicit-port member
/// naming the group's REAL port must be REJECTED — Go compares declared
/// numbers with no zero exemption (tcp.go:111-113), so 0 never matches
/// the real number.
#[tokio::test]
async fn tcp_group_auto_assign_handler_walk_declared_zero_semantics() {
    let state = test_state();
    insert_control(&state, "run-1", 1).await;

    // First member: auto-assign. The group stores declared 0; the shared
    // listener binds the OS-probed port.
    let mut m1 = new_proxy("m1", "tcp");
    m1.group = Some("g".to_string());
    m1.group_key = Some("k".to_string());
    m1.remote_port = None;
    let _w1 = register_np(m1, &state).await;
    let m1_info = state
        .proxy_manager
        .get("m1")
        .await
        .expect("auto-assigned first member must register");
    let real = m1_info
        .remote_port
        .expect("first member carries the bound port");
    assert!(real > 0, "auto-assign resolved a real port, got {real}");
    assert!(
        state.used_ports.read().await.contains(&real),
        "the group's real port stays marked in used_ports"
    );
    // Declared 0 is the group's key: a 0 query matches, a query with the
    // REAL number mismatches (declared-vs-declared).
    assert_eq!(
        state
            .tcp_group_ctl
            .get_group_port("g", "k", 0, "127.0.0.1")
            .await,
        GroupPortQuery::Matched(real)
    );
    assert_eq!(
        state
            .tcp_group_ctl
            .get_group_port("g", "k", real, "127.0.0.1")
            .await,
        GroupPortQuery::Mismatch("group should have same remote port")
    );

    // Second member, also auto-assign-declaring: joins the group on its
    // real port (no second bind).
    let mut m2 = new_proxy("m2", "tcp");
    m2.group = Some("g".to_string());
    m2.group_key = Some("k".to_string());
    m2.remote_port = None;
    let _w2 = register_np(m2, &state).await;
    let m2_info = state
        .proxy_manager
        .get("m2")
        .await
        .expect("auto-assign second member must join the group");
    assert_eq!(
        m2_info.remote_port,
        Some(real),
        "joiner is registered on the group's shared port"
    );
    assert_eq!(
        *state.client_ports_used.read().await.get("run-1").unwrap(),
        2,
        "both members count exactly once"
    );

    // Explicit-port member naming the group's REAL port: rejected —
    // declared 0 vs declared real can never match, even though the
    // values coincide with the bound port.
    let mut m3 = new_proxy("m3", "tcp");
    m3.group = Some("g".to_string());
    m3.group_key = Some("k".to_string());
    m3.remote_port = Some(real as i32);
    let w3 = register_np(m3, &state).await;
    let resp_text = String::from_utf8_lossy(&w3);
    assert!(
        resp_text.contains("group should have same remote port"),
        "explicit member declaring the group's REAL port must mismatch its declared 0: {resp_text}"
    );
    assert!(
        state.proxy_manager.get("m3").await.is_none(),
        "rejected member must not register"
    );
}

/// M2: Go's TCPMuxGroup stores ONE (domain, rubu, user, pwd) per group
/// name — a grouped proxy with a second, different domain fails with
/// ErrGroupParamsInvalid. frp-rs mirrors the HTTP group path and
/// rejects up front (Go parity quirk: multi-domain group proxies are
/// not supported server-side).
#[tokio::test]
async fn tcpmux_group_multi_domain_rejected() {
    let state = test_state();
    insert_control(&state, "run-1", 1).await;
    let (itx, _rx) = mpsc::channel(8);
    let mut handles: std::collections::HashMap<String, tokio::task::JoinHandle<()>> =
        std::collections::HashMap::new();
    let mut udp_sockets: std::collections::HashMap<String, std::sync::Arc<tokio::net::UdpSocket>> =
        std::collections::HashMap::new();

    let mut np = new_proxy("mux-multi", "tcpmux");
    np.custom_domains = Some(vec![
        "a.example.com".to_string(),
        "b.example.com".to_string(),
    ]);
    np.group = Some("web".to_string());
    let mut writer = Vec::new();
    let ok = handle_new_proxy(
        np,
        "run-1",
        1,
        &state,
        &mut writer,
        &itx,
        &mut handles,
        &mut udp_sockets,
        false,
    )
    .await;
    assert!(!ok, "multi-domain group proxy must be rejected");
    let text = String::from_utf8_lossy(&writer);
    assert!(
        text.contains("exactly one custom_domain"),
        "rejection must explain the constraint: {text}"
    );
    assert!(
        state
            .tcpmux_manager
            .lookup("a.example.com", "")
            .await
            .is_none(),
        "rejected registration must leave no route"
    );
}

/// M2: group members and plain proxies cannot share a (domain, rubu)
/// route — Go routes grouped and plain proxies through the same muxer,
/// where the second registration is a Routers.Add conflict. The
/// existing conflict rejection must hold in both orderings.
#[tokio::test]
async fn tcpmux_group_vs_plain_route_conflict() {
    let state = test_state();
    insert_control(&state, "run-1", 1).await;
    insert_control(&state, "run-2", 2).await;
    let (itx, _rx) = mpsc::channel(8);
    let mut handles: std::collections::HashMap<String, tokio::task::JoinHandle<()>> =
        std::collections::HashMap::new();
    let mut udp_sockets: std::collections::HashMap<String, std::sync::Arc<tokio::net::UdpSocket>> =
        std::collections::HashMap::new();

    // Group member registers first (shared route under mux-a).
    let mut np1 = new_proxy("mux-a", "tcpmux");
    np1.custom_domains = Some(vec!["a.example.com".to_string()]);
    np1.group = Some("web".to_string());
    np1.group_key = Some("gk".to_string());
    let mut writer1 = Vec::new();
    assert!(
        handle_new_proxy(
            np1,
            "run-1",
            1,
            &state,
            &mut writer1,
            &itx,
            &mut handles,
            &mut udp_sockets,
            false,
        )
        .await
    );
    // Plain proxy claims the same domain → route conflict.
    let mut np2 = new_proxy("mux-b", "tcpmux");
    np2.custom_domains = Some(vec!["a.example.com".to_string()]);
    let mut writer2 = Vec::new();
    assert!(
        !handle_new_proxy(
            np2,
            "run-2",
            2,
            &state,
            &mut writer2,
            &itx,
            &mut handles,
            &mut udp_sockets,
            false,
        )
        .await,
        "plain proxy must not displace a group's shared route"
    );
    let text2 = String::from_utf8_lossy(&writer2);
    assert!(text2.contains("conflict"), "must surface conflict: {text2}");

    // Reverse: plain proxy first (run-3), then a group member on the
    // same domain with a DIFFERENT group name — the grouped register
    // is a route conflict too (its group differs from the owner's).
    insert_control(&state, "run-3", 3).await;
    insert_control(&state, "run-4", 4).await;
    let mut np3 = new_proxy("mux-c", "tcpmux");
    np3.custom_domains = Some(vec!["b.example.com".to_string()]);
    let mut writer3 = Vec::new();
    assert!(
        handle_new_proxy(
            np3,
            "run-3",
            3,
            &state,
            &mut writer3,
            &itx,
            &mut handles,
            &mut udp_sockets,
            false,
        )
        .await
    );
    let mut np4 = new_proxy("mux-d", "tcpmux");
    np4.custom_domains = Some(vec!["b.example.com".to_string()]);
    np4.group = Some("other".to_string());
    let mut writer4 = Vec::new();
    assert!(
        !handle_new_proxy(
            np4,
            "run-4",
            4,
            &state,
            &mut writer4,
            &itx,
            &mut handles,
            &mut udp_sockets,
            false,
        )
        .await,
        "different group cannot displace a plain route"
    );
    let text4 = String::from_utf8_lossy(&writer4);
    assert!(text4.contains("conflict"), "must surface conflict: {text4}");
}

/// Audit finding 5 regression: a tcpmux proxy claiming a domain already
/// routed by a live proxy is rejected — the sibling's route survives.
#[tokio::test]
async fn tcpmux_route_conflict_rejects_new_proxy() {
    let state = test_state();
    insert_control(&state, "run-1", 1).await;
    let (itx, _rx) = mpsc::channel(8);
    let mut handles: std::collections::HashMap<String, tokio::task::JoinHandle<()>> =
        std::collections::HashMap::new();
    let mut udp_sockets: std::collections::HashMap<String, std::sync::Arc<tokio::net::UdpSocket>> =
        std::collections::HashMap::new();

    let mut np1 = new_proxy("mux-a", "tcpmux");
    np1.custom_domains = Some(vec!["a.example.com".to_string()]);
    let mut writer1 = Vec::new();
    handle_new_proxy(
        np1,
        "run-1",
        1,
        &state,
        &mut writer1,
        &itx,
        &mut handles,
        &mut udp_sockets,
        false,
    )
    .await;
    assert!(
        state.proxy_manager.get("mux-a").await.is_some(),
        "first tcpmux proxy must register"
    );
    assert!(state
        .tcpmux_manager
        .lookup("a.example.com", "")
        .await
        .is_some_and(|r| r.proxy_name == "mux-a"));

    // Second proxy claims the same domain → must be rejected and rolled
    // back, with an error response naming the conflict.
    let mut np2 = new_proxy("mux-b", "tcpmux");
    np2.custom_domains = Some(vec!["a.example.com".to_string()]);
    let mut writer2 = Vec::new();
    handle_new_proxy(
        np2,
        "run-1",
        1,
        &state,
        &mut writer2,
        &itx,
        &mut handles,
        &mut udp_sockets,
        false,
    )
    .await;
    assert!(
        state.proxy_manager.get("mux-b").await.is_none(),
        "conflicting tcpmux proxy must be rolled back"
    );
    assert!(
        String::from_utf8_lossy(&writer2).contains("conflict"),
        "rejection response must surface the route conflict"
    );
    assert!(
        state
            .tcpmux_manager
            .lookup("a.example.com", "")
            .await
            .is_some_and(|r| r.proxy_name == "mux-a"),
        "live sibling's route must survive the rejected registration"
    );

    // tcpmux proxies never consume a port → no client port count.
    assert!(
        state.client_ports_used.read().await.get("run-1").is_none(),
        "tcpmux proxies must not count against the client port budget"
    );
}

/// Go frp v0.71.0 compat: TCPMuxProxy::httpConnectRun routes
/// buildDomains(CustomDomains, SubDomain), so a subdomain-only tcpmux
/// proxy must register with the expanded "{subdomain}.{sub_domain_host}"
/// route (frpc sends subdomain for tcpmux — previously hard-rejected
/// with "tcpmux proxy requires custom_domains").
#[tokio::test]
async fn tcpmux_subdomain_expands_to_route() {
    let mut state = test_state();
    // Fresh Arc from test_state: sole owner, safe to mutate in place.
    Arc::get_mut(&mut state).unwrap().sub_domain_host = "example.com".to_string();
    insert_control(&state, "run-1", 1).await;
    let (itx, _rx) = mpsc::channel(8);
    let mut handles: std::collections::HashMap<String, tokio::task::JoinHandle<()>> =
        std::collections::HashMap::new();
    let mut udp_sockets: std::collections::HashMap<String, std::sync::Arc<tokio::net::UdpSocket>> =
        std::collections::HashMap::new();

    let mut np = new_proxy("mux-sub", "tcpmux");
    np.subdomain = Some("app".to_string());
    let mut writer = Vec::new();
    let ok = handle_new_proxy(
        np,
        "run-1",
        1,
        &state,
        &mut writer,
        &itx,
        &mut handles,
        &mut udp_sockets,
        false,
    )
    .await;
    assert!(ok, "subdomain-only tcpmux proxy must register");
    assert!(
        state.proxy_manager.get("mux-sub").await.is_some(),
        "subdomain-only tcpmux proxy must be registered"
    );
    assert!(
        state
            .tcpmux_manager
            .lookup("app.example.com", "")
            .await
            .is_some_and(|r| r.proxy_name == "mux-sub"),
        "expanded subdomain route must be registered"
    );
}

/// Go frp v0.71.0 parity (round 8): buildDomains does no dedup, so a
/// duplicate custom_domains entry repeats the (domain, "", rubu) triple
/// and Go's second Muxer.Listen → Routers.Add rejects the whole
/// registration. The tcpmux manager's HashMap insert is idempotent for
/// same-proxy re-registration, so proxy_ops must reject the duplicate
/// itself.
#[tokio::test]
async fn tcpmux_duplicate_domain_rejected() {
    let state = test_state();
    insert_control(&state, "run-1", 1).await;
    let (itx, _rx) = mpsc::channel(8);
    let mut handles: std::collections::HashMap<String, tokio::task::JoinHandle<()>> =
        std::collections::HashMap::new();
    let mut udp_sockets: std::collections::HashMap<String, std::sync::Arc<tokio::net::UdpSocket>> =
        std::collections::HashMap::new();

    let mut np = new_proxy("mux-dup", "tcpmux");
    np.custom_domains = Some(vec![
        "a.example.com".to_string(),
        "a.example.com".to_string(),
    ]);
    let mut writer = Vec::new();
    let ok = handle_new_proxy(
        np,
        "run-1",
        1,
        &state,
        &mut writer,
        &itx,
        &mut handles,
        &mut udp_sockets,
        false,
    )
    .await;
    assert!(!ok, "tcpmux proxy with a duplicate domain must be rejected");
    assert!(
        state.proxy_manager.get("mux-dup").await.is_none(),
        "rejected tcpmux proxy must be rolled back"
    );
    assert!(
        String::from_utf8_lossy(&writer).contains("duplicate domain"),
        "rejection response must surface the duplicate domain"
    );
    assert!(
        state
            .tcpmux_manager
            .lookup("a.example.com", "")
            .await
            .is_none(),
        "no route may be left behind by the rejected registration"
    );
}

/// Round-18-review C-4: the per-client proxy-count cap and the
/// per-proxy route-claiming domain cap are enforced inside
/// `handle_new_proxy` but had no handler-level test (only the internal
/// helpers). Registering past `max_proxies_per_client` must reject with
/// a NewProxyResp error and register nothing.
#[tokio::test]
async fn client_proxy_cap_rejected_at_handler_level() {
    let mut state = test_state();
    Arc::get_mut(&mut state)
        .expect("sole state ref")
        .max_proxies_per_client = 2;
    insert_control(&state, "run-1", 1).await;
    let (itx, _rx) = mpsc::channel(8);
    let mut handles: std::collections::HashMap<String, tokio::task::JoinHandle<()>> =
        std::collections::HashMap::new();
    let mut udp_sockets: std::collections::HashMap<String, std::sync::Arc<tokio::net::UdpSocket>> =
        std::collections::HashMap::new();

    for (name, port) in [("cap-p1", 24031), ("cap-p2", 24032)] {
        let mut np = new_proxy(name, "tcp");
        np.remote_port = Some(port);
        let mut writer = Vec::new();
        let ok = handle_new_proxy(
            np,
            "run-1",
            1,
            &state,
            &mut writer,
            &itx,
            &mut handles,
            &mut udp_sockets,
            false,
        )
        .await;
        assert!(ok, "{name} must register within the cap");
        assert!(state.proxy_manager.get(name).await.is_some());
    }

    // Third proxy crosses the cap → rejected, not registered.
    let mut np = new_proxy("cap-p3", "tcp");
    np.remote_port = Some(24033);
    let mut writer = Vec::new();
    let ok = handle_new_proxy(
        np,
        "run-1",
        1,
        &state,
        &mut writer,
        &itx,
        &mut handles,
        &mut udp_sockets,
        false,
    )
    .await;
    assert!(!ok, "third proxy must be rejected at the client cap");
    assert!(
        state.proxy_manager.get("cap-p3").await.is_none(),
        "rejected proxy must not be registered"
    );
    assert!(
        String::from_utf8_lossy(&writer).contains("maximum number of proxies"),
        "rejection response must surface the cap error"
    );
}

/// Round-18-review C-4: the route-claiming domain cap
/// (`max_custom_domains_per_proxy`) rejects a single proxy whose
/// custom_domains/locations estimate exceeds the configured maximum —
/// one proxy is not bounded by the per-client proxy cap.
#[tokio::test]
async fn route_domain_cap_rejected_at_handler_level() {
    let mut state = test_state();
    Arc::get_mut(&mut state)
        .expect("sole state ref")
        .server_config_snapshot
        .max_custom_domains_per_proxy = 3;
    insert_control(&state, "run-1", 1).await;
    let (itx, _rx) = mpsc::channel(8);
    let mut handles: std::collections::HashMap<String, tokio::task::JoinHandle<()>> =
        std::collections::HashMap::new();
    let mut udp_sockets: std::collections::HashMap<String, std::sync::Arc<tokio::net::UdpSocket>> =
        std::collections::HashMap::new();

    // Exactly at the cap (3 domains) → accepted.
    let mut np = new_proxy("dom-ok", "http");
    np.custom_domains = Some(vec![
        "a.example.com".to_string(),
        "b.example.com".to_string(),
        "c.example.com".to_string(),
    ]);
    let mut writer = Vec::new();
    let ok = handle_new_proxy(
        np,
        "run-1",
        1,
        &state,
        &mut writer,
        &itx,
        &mut handles,
        &mut udp_sockets,
        false,
    )
    .await;
    assert!(ok, "3 domains must be accepted at a cap of 3");
    assert!(state.proxy_manager.get("dom-ok").await.is_some());

    // One domain past the cap → rejected.
    let mut np = new_proxy("dom-over", "http");
    np.custom_domains = Some(vec![
        "a.example.com".to_string(),
        "b.example.com".to_string(),
        "c.example.com".to_string(),
        "d.example.com".to_string(),
    ]);
    let mut writer = Vec::new();
    let ok = handle_new_proxy(
        np,
        "run-1",
        1,
        &state,
        &mut writer,
        &itx,
        &mut handles,
        &mut udp_sockets,
        false,
    )
    .await;
    assert!(!ok, "4 domains must be rejected at a cap of 3");
    assert!(
        state.proxy_manager.get("dom-over").await.is_none(),
        "rejected proxy must not be registered"
    );
    assert!(
        String::from_utf8_lossy(&writer).contains("exceeding the configured maximum"),
        "rejection response must surface the route-domain cap error"
    );
}

/// Round-18-review C-5 (M5 mirror): the per-proxy user-conn cap permit
/// is acquired at the LISTENER (accept) side before the message is
/// queued — an at-cap proxy must drop new conns instead of parking raw
/// sockets (fds) in the internal channel ahead of the handler-side
/// check. With max_conns_per_proxy = 1: the first user conn carries the
/// permit into the message; the second (concurrent) conn is dropped at
/// accept and never reaches the control channel.
#[tokio::test]
async fn user_conn_sem_acquired_at_listener_side() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let port = listener.local_addr().unwrap().port();
    let sem = Arc::new(tokio::sync::Semaphore::new(1));
    let (tx, mut rx) = mpsc::channel(8);
    let task = tokio::spawn(listen_and_proxy(
        listener,
        port,
        "sem-proxy".to_string(),
        tx,
        0,
        Some(sem.clone()),
    ));

    let _c1 = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("conn 1");
    let _c2 = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("conn 2");
    // Give the accept loop time to accept both and run the permit check.
    tokio::time::sleep(Duration::from_millis(50)).await;

    let first = rx.recv().await.expect("first conn must reach the control");
    match first {
        InternalMsg::ProxyUserConn {
            proxy_name,
            user_conn_permit,
            ..
        } => {
            assert_eq!(proxy_name, "sem-proxy");
            assert!(
                user_conn_permit.is_some(),
                "first conn must carry the user-conn permit"
            );
        }
        other => panic!("expected ProxyUserConn, got {other:?}"),
    }
    // The second conn must have been dropped at the listener — no
    // second message may arrive.
    let second = tokio::time::timeout(Duration::from_millis(100), rx.recv()).await;
    assert!(
        second.is_err(),
        "at-cap conn must be dropped at the listener, not queued"
    );

    task.abort();
}

/// Go parity: the same duplicate-domain rejection on the tcpmux path
/// for CASE-ONLY duplicates (Routers.Add lowercases before exist()).
/// (A subdomain-expansion collision with a custom_domains entry is
/// pre-empted by validateDomainConfigForServer — a custom domain under
/// subDomainHost is rejected before buildDomains runs — so the
/// reachable duplicate is a repeated custom_domains entry.)
#[tokio::test]
async fn tcpmux_case_variant_duplicate_domain_rejected() {
    let state = test_state();
    insert_control(&state, "run-1", 1).await;
    let (itx, _rx) = mpsc::channel(8);
    let mut handles: std::collections::HashMap<String, tokio::task::JoinHandle<()>> =
        std::collections::HashMap::new();
    let mut udp_sockets: std::collections::HashMap<String, std::sync::Arc<tokio::net::UdpSocket>> =
        std::collections::HashMap::new();

    let mut np = new_proxy("mux-case", "tcpmux");
    np.custom_domains = Some(vec![
        "a.example.net".to_string(),
        "A.EXAMPLE.NET".to_string(),
    ]);
    let mut writer = Vec::new();
    let ok = handle_new_proxy(
        np,
        "run-1",
        1,
        &state,
        &mut writer,
        &itx,
        &mut handles,
        &mut udp_sockets,
        false,
    )
    .await;
    assert!(!ok, "case-variant duplicate tcpmux domain must be rejected");
    assert!(state.proxy_manager.get("mux-case").await.is_none());
    assert!(
        String::from_utf8_lossy(&writer).contains("duplicate domain"),
        "rejection must name the duplicated domain: {}",
        String::from_utf8_lossy(&writer)
    );
}

/// Go parity (round 8): duplicate custom_domains entries flow through
/// to VhostManager::register, whose same-call duplicate detection
/// rejects the repeated (domain, location, routeByHTTPUser) triple —
/// previously the duplicate silently double-registered the vhost route.
/// (subdomain-expansion collisions are pre-empted by
/// validateDomainConfigForServer, Go validation/proxy.go:81-99.)
#[tokio::test]
async fn http_duplicate_custom_domains_rejected() {
    let state = test_state();
    insert_control(&state, "run-1", 1).await;
    let (itx, _rx) = mpsc::channel(8);
    let mut handles: std::collections::HashMap<String, tokio::task::JoinHandle<()>> =
        std::collections::HashMap::new();
    let mut udp_sockets: std::collections::HashMap<String, std::sync::Arc<tokio::net::UdpSocket>> =
        std::collections::HashMap::new();

    let mut np = new_proxy("http-dup", "http");
    np.custom_domains = Some(vec![
        "a.example.net".to_string(),
        "a.example.net".to_string(),
    ]);
    np.locations = Some(vec!["/".to_string()]);
    let mut writer = Vec::new();
    let ok = handle_new_proxy(
        np,
        "run-1",
        1,
        &state,
        &mut writer,
        &itx,
        &mut handles,
        &mut udp_sockets,
        false,
    )
    .await;
    assert!(
        !ok,
        "http proxy with duplicate custom_domains must be rejected"
    );
    assert!(state.proxy_manager.get("http-dup").await.is_none());
    assert!(
        String::from_utf8_lossy(&writer).contains("conflict"),
        "rejection response must surface the router config conflict"
    );
    assert!(
        state
            .vhost_manager
            .lookup("a.example.net", "/", "", "http")
            .await
            .is_none(),
        "no vhost route may be left behind by the rejected registration"
    );
}

/// Go parity: the same duplicate-custom_domains rejection on the HTTPS
/// (SNI, empty locations) path — VhostManager::register treats an empty
/// location list as the single location "" (Go https.go listenForDomain
/// → Add(domain, "")).
#[tokio::test]
async fn https_duplicate_custom_domains_rejected() {
    let state = test_state();
    insert_control(&state, "run-1", 1).await;
    let (itx, _rx) = mpsc::channel(8);
    let mut handles: std::collections::HashMap<String, tokio::task::JoinHandle<()>> =
        std::collections::HashMap::new();
    let mut udp_sockets: std::collections::HashMap<String, std::sync::Arc<tokio::net::UdpSocket>> =
        std::collections::HashMap::new();

    let mut np = new_proxy("https-dup", "https");
    np.custom_domains = Some(vec![
        "a.example.net".to_string(),
        "a.example.net".to_string(),
    ]);
    let mut writer = Vec::new();
    let ok = handle_new_proxy(
        np,
        "run-1",
        1,
        &state,
        &mut writer,
        &itx,
        &mut handles,
        &mut udp_sockets,
        false,
    )
    .await;
    assert!(
        !ok,
        "https proxy with duplicate custom_domains must be rejected"
    );
    assert!(state.proxy_manager.get("https-dup").await.is_none());
    assert!(
        String::from_utf8_lossy(&writer).contains("conflict"),
        "rejection response must surface the router config conflict"
    );
    assert!(
        state
            .vhost_manager
            .lookup("a.example.net", "", "", "https")
            .await
            .is_none(),
        "no SNI route may be left behind by the rejected registration"
    );
}

/// Regression (round-12 MEDIUM): Go's HTTPSProxyConfig is ProxyBaseConfig
/// + DomainConfig ONLY (pkg/config/v1/proxy.go) — HTTPS proxies never
/// carry route_by_http_user, so the SNI route must be registered under
/// the "" (empty httpUser) key, which is exactly what the SNI lookup
/// (http_user "") probes. Pre-fix the register call passed the proxy's
/// route_by_http_user through, storing the route under the rubu key and
/// making the proxy silently unreachable via SNI.
#[tokio::test]
async fn https_rubu_proxy_registered_under_empty_key() {
    let state = test_state();
    insert_control(&state, "run-1", 1).await;
    let (itx, _rx) = mpsc::channel(8);
    let mut handles: std::collections::HashMap<String, tokio::task::JoinHandle<()>> =
        std::collections::HashMap::new();
    let mut udp_sockets: std::collections::HashMap<String, std::sync::Arc<tokio::net::UdpSocket>> =
        std::collections::HashMap::new();

    let mut np = new_proxy("https-rubu", "https");
    np.custom_domains = Some(vec!["rubu.example.net".to_string()]);
    np.route_by_http_user = Some("app".to_string());
    let mut writer = Vec::new();
    let ok = handle_new_proxy(
        np,
        "run-1",
        1,
        &state,
        &mut writer,
        &itx,
        &mut handles,
        &mut udp_sockets,
        false,
    )
    .await;
    assert!(ok, "https proxy with route_by_http_user must register");
    // The SNI lookup (http_user "") must find the route — pre-fix it
    // was stored under "app" and this lookup missed.
    let route = state
        .vhost_manager
        .lookup("rubu.example.net", "", "", "https")
        .await
        .unwrap_or_else(|| panic!("SNI lookup must find the https proxy"));
    assert_eq!(route.proxy_name.as_ref(), "https-rubu");
}

/// Regression (round-12 MEDIUM): with route_by_http_user no longer
/// affecting HTTPS registration, two HTTPS proxies on the same domain
/// with DIFFERENT rubu values now collide on the shared (domain, "")
/// SNI triple and the second is rejected — matching Go, where
/// HTTPSProxyConfig has no RouteByHTTPUser and the HTTPS Muxer's
/// Routers.Add rejects the duplicate domain outright. Pre-fix the
/// different rubu keys let both through, with the first silently winning.
#[tokio::test]
async fn https_same_domain_different_rubu_second_rejected() {
    let state = test_state();
    insert_control(&state, "run-1", 1).await;
    let (itx, _rx) = mpsc::channel(8);
    let mut handles: std::collections::HashMap<String, tokio::task::JoinHandle<()>> =
        std::collections::HashMap::new();
    let mut udp_sockets: std::collections::HashMap<String, std::sync::Arc<tokio::net::UdpSocket>> =
        std::collections::HashMap::new();

    let mut np1 = new_proxy("https-a", "https");
    np1.custom_domains = Some(vec!["dup-rubu.example.net".to_string()]);
    np1.route_by_http_user = Some("a".to_string());
    let mut writer1 = Vec::new();
    let ok = handle_new_proxy(
        np1,
        "run-1",
        1,
        &state,
        &mut writer1,
        &itx,
        &mut handles,
        &mut udp_sockets,
        false,
    )
    .await;
    assert!(ok, "first https proxy must register");
    assert!(state.proxy_manager.get("https-a").await.is_some());

    let mut np2 = new_proxy("https-b", "https");
    np2.custom_domains = Some(vec!["dup-rubu.example.net".to_string()]);
    np2.route_by_http_user = Some("b".to_string());
    let mut writer2 = Vec::new();
    let ok = handle_new_proxy(
        np2,
        "run-1",
        1,
        &state,
        &mut writer2,
        &itx,
        &mut handles,
        &mut udp_sockets,
        false,
    )
    .await;
    assert!(
        !ok,
        "second https proxy on the same domain (different rubu) must be rejected"
    );
    assert!(state.proxy_manager.get("https-b").await.is_none());
    assert!(
        String::from_utf8_lossy(&writer2).contains("conflict"),
        "rejection response must surface the router config conflict"
    );
    // The first proxy's SNI route survives.
    let route = state
        .vhost_manager
        .lookup("dup-rubu.example.net", "", "", "https")
        .await
        .unwrap_or_else(|| panic!("first https proxy's SNI route must survive"));
    assert_eq!(route.proxy_name.as_ref(), "https-a");
}

/// Go validateDomainConfigForServer rejects a subdomain when
/// SubDomainHost is unset ("subdomain is not supported because this
/// feature is not enabled in server") — unlike the HTTP path (which
/// silently skips), the tcpmux path must mirror Go's rejection.
#[tokio::test]
async fn tcpmux_subdomain_without_subdomain_host_rejected() {
    let state = test_state(); // sub_domain_host = ""
    insert_control(&state, "run-1", 1).await;
    let (itx, _rx) = mpsc::channel(8);
    let mut handles: std::collections::HashMap<String, tokio::task::JoinHandle<()>> =
        std::collections::HashMap::new();
    let mut udp_sockets: std::collections::HashMap<String, std::sync::Arc<tokio::net::UdpSocket>> =
        std::collections::HashMap::new();

    let mut np = new_proxy("mux-sub", "tcpmux");
    np.subdomain = Some("app".to_string());
    let mut writer = Vec::new();
    let ok = handle_new_proxy(
        np,
        "run-1",
        1,
        &state,
        &mut writer,
        &itx,
        &mut handles,
        &mut udp_sockets,
        false,
    )
    .await;
    assert!(!ok, "subdomain without sub_domain_host must be rejected");
    assert!(
        state.proxy_manager.get("mux-sub").await.is_none(),
        "rejected tcpmux proxy must be rolled back"
    );
    assert!(
        String::from_utf8_lossy(&writer)
            .contains("not supported because this feature is not enabled in server"),
        "rejection must carry Go's subdomain-disabled message"
    );
}

/// The hard rejection stays for a tcpmux proxy whose MERGED domain list
/// is empty (no custom_domains, no subdomain) — Go registers a dead
/// proxy with zero routes; frp-rs rejects it instead.
#[tokio::test]
async fn tcpmux_no_domains_still_rejected() {
    let state = test_state();
    insert_control(&state, "run-1", 1).await;
    let (itx, _rx) = mpsc::channel(8);
    let mut handles: std::collections::HashMap<String, tokio::task::JoinHandle<()>> =
        std::collections::HashMap::new();
    let mut udp_sockets: std::collections::HashMap<String, std::sync::Arc<tokio::net::UdpSocket>> =
        std::collections::HashMap::new();

    let np = new_proxy("mux-none", "tcpmux");
    let mut writer = Vec::new();
    let ok = handle_new_proxy(
        np,
        "run-1",
        1,
        &state,
        &mut writer,
        &itx,
        &mut handles,
        &mut udp_sockets,
        false,
    )
    .await;
    assert!(!ok, "tcpmux with no domains must still be rejected");
    assert!(state.proxy_manager.get("mux-none").await.is_none());
    assert!(
        String::from_utf8_lossy(&writer).contains("requires custom_domains"),
        "rejection must name the missing custom_domains"
    );
}

/// F10: the UdpNeedsWorkConn handoff task must tolerate a closed
/// internal channel — the send fails (logged at debug) without
/// panicking the spawned task or failing the registration. The
/// registration success path still drains the oneshot signals before
/// the send, so a healthy channel never sees a spurious failure.
#[tokio::test]
async fn udp_proxy_registers_when_control_channel_closed() {
    let state = test_state();
    insert_control(&state, "run-1", 1).await;
    // Closed internal channel: the spawned UdpNeedsWorkConn send must
    // fail cleanly (debug log) — registration must still succeed.
    let (itx, rx) = mpsc::channel(8);
    drop(rx);
    let mut handles: std::collections::HashMap<String, tokio::task::JoinHandle<()>> =
        std::collections::HashMap::new();
    let mut udp_sockets: std::collections::HashMap<String, std::sync::Arc<tokio::net::UdpSocket>> =
        std::collections::HashMap::new();

    let mut np = new_proxy("udp-f10", "udp");
    np.remote_port = Some(24026);
    let mut writer = Vec::new();
    let ok = handle_new_proxy(
        np,
        "run-1",
        1,
        &state,
        &mut writer,
        &itx,
        &mut handles,
        &mut udp_sockets,
        false,
    )
    .await;
    assert!(
        ok,
        "UDP proxy must register even when the control channel is closed"
    );
    assert!(
        state.proxy_manager.get("udp-f10").await.is_some(),
        "closed control channel must not fail the registration"
    );
    assert!(
        state.used_udp_ports.read().await.contains(&24026),
        "UDP port must be marked"
    );
    // Yield so the spawned handoff task runs its send-failure path
    // (a panic there would surface as a test failure).
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
}

// ---------------------------------------------------------------
// Audit fixes (2026-08-13): supersession port-mark leak, group-create
// bind-race join, duplicate-login conflict sweep, sweep snapshot
// ownership re-checks.
// ---------------------------------------------------------------

#[tokio::test]
async fn supersession_replacement_frees_old_port_mark() {
    // Audit-fix regression (finding 1): when the superseding control
    // re-registers a name the old control still holds (barrier-timeout
    // supersession), the old control's original port mark must be freed
    // exactly once — nothing else prunes used_ports (the 24h pruner
    // only touches port_reservations), and the old control's own sweep
    // skips the name (newer control_id).
    let state = test_state();
    insert_control(&state, "run-1", 1).await;
    let (itx, _rx) = mpsc::channel(8);
    let mut handles: std::collections::HashMap<String, tokio::task::JoinHandle<()>> =
        std::collections::HashMap::new();
    let mut udp_sockets: std::collections::HashMap<String, std::sync::Arc<tokio::net::UdpSocket>> =
        std::collections::HashMap::new();

    // Old control (generation 1) registers "p" with an AUTO-ASSIGNED
    // port (remote_port 0 — the supersession leak scenario: an explicit
    // occupied port is rejected today, matching Go frp's
    // Manager.Acquire, so only auto-assigned re-registrations reach the
    // replacement path).
    let np = new_proxy("p", "tcp");
    let mut writer = Vec::new();
    handle_new_proxy(
        np,
        "run-1",
        1,
        &state,
        &mut writer,
        &itx,
        &mut handles,
        &mut udp_sockets,
        false,
    )
    .await;
    let old_port = state
        .proxy_manager
        .get("p")
        .await
        .expect("p registered")
        .remote_port
        .expect("auto-assigned port");
    assert!(state.used_ports.read().await.contains(&old_port));
    assert_eq!(
        *state.client_ports_used.read().await.get("run-1").unwrap(),
        1,
        "old control's proxy counts once"
    );
    assert_eq!(state.proxy_manager.get("p").await.unwrap().control_id, 1);

    // Superseding control (generation 2) re-registers the same name.
    // The old mark is still live, so allocation takes a different port;
    // the replacement must free the old mark exactly once.
    let np2 = new_proxy("p", "tcp");
    let mut writer2 = Vec::new();
    handle_new_proxy(
        np2,
        "run-1",
        2,
        &state,
        &mut writer2,
        &itx,
        &mut handles,
        &mut udp_sockets,
        false,
    )
    .await;

    let reg = state
        .proxy_manager
        .get("p")
        .await
        .expect("p still registered");
    assert_eq!(reg.control_id, 2, "superseding control owns the entry");
    let new_port = reg.remote_port.expect("tcp proxy has a port");
    assert_ne!(new_port, old_port, "allocation must take a different port");
    assert!(state.used_ports.read().await.contains(&new_port));
    assert!(
        !state.used_ports.read().await.contains(&old_port),
        "old port mark freed exactly once by the replacement"
    );
    assert_eq!(
        *state.client_ports_used.read().await.get("run-1").unwrap(),
        1,
        "one live proxy counts once (not twice)"
    );
    assert!(
        state.port_reservations.read().await.contains_key("p"),
        "freed port reserved under the proxy name (normal-cleanup parity)"
    );

    // The old control's own sweep skips the name — the new port and
    // entry must survive it.
    unregister_control(&state, "run-1", 1, false, true).await;
    assert!(state.proxy_manager.get("p").await.is_some());
    assert!(
        state.used_ports.read().await.contains(&new_port),
        "old sweep must not free the superseding control's port"
    );

    // The new control's own cleanup releases everything.
    unregister_control(&state, "run-1", 2, false, true).await;
    assert!(!state.used_ports.read().await.contains(&new_port));
    assert_eq!(
        state.client_ports_used.read().await.get("run-1"),
        None,
        "count entry removed when it reaches zero"
    );
}

#[tokio::test]
async fn supersession_replacement_respects_sudp_shared_port_ownership() {
    // Audit-fix regression (finding 1): SUDP shared-port ownership must
    // survive a supersession replacement — the old mark stays while a
    // sibling SUDP proxy still owns the port, and is freed once the
    // sibling is gone.
    let state = test_state();
    state.used_udp_ports.write().await.insert(24043);
    state
        .proxy_manager
        .register(
            "run-1".to_string(),
            proxy_info("s", "sudp", "run-1", Some(24043), 1),
        )
        .await
        .expect("register s");
    // A sibling SUDP proxy shares the port (frp-rs shared-port extension).
    state
        .proxy_manager
        .register(
            "run-2".to_string(),
            proxy_info("s2", "sudp", "run-2", Some(24043), 1),
        )
        .await
        .expect("register s2");

    let replaced = state
        .proxy_manager
        .register_or_replace(
            "run-1".to_string(),
            proxy_info("s", "sudp", "run-1", Some(24044), 2),
        )
        .await
        .expect("supersession replacement")
        .expect("replaced entry");
    // The new registration's allocation inserted its own mark.
    state.used_udp_ports.write().await.insert(24044);
    free_replaced_port(&state, &replaced, 24044).await;

    assert!(
        state.used_udp_ports.read().await.contains(&24043),
        "shared port mark stays while a sibling SUDP proxy holds it"
    );
    assert!(state.used_udp_ports.read().await.contains(&24044));
    assert!(
        !state.port_reservations.read().await.contains_key("s"),
        "no reservation while a sibling still owns the shared port"
    );

    // The replacement only frees the REPLACED ENTRY's own port. The
    // sibling's shared mark (24043) is released by the sibling's own
    // cleanup (unregister_control's udp_port_has_other_owner path) —
    // removing s2 without running its cleanup must leave the mark, or
    // a concurrent s2 cleanup would double-free it.
    state.proxy_manager.remove("s2").await;
    assert!(
        state.used_udp_ports.read().await.contains(&24043),
        "shared port mark stays for the sibling's own cleanup"
    );
}

#[tokio::test]
async fn supersession_replacement_same_port_keeps_mark() {
    // Audit-fix regression (finding 1): a replacement that SHARES the
    // old port (SUDP) must not free the mark — it now belongs to the
    // superseding control's proxy.
    let state = test_state();
    state.used_udp_ports.write().await.insert(24042);
    state
        .proxy_manager
        .register(
            "run-1".to_string(),
            proxy_info("s", "sudp", "run-1", Some(24042), 1),
        )
        .await
        .expect("register s");
    let replaced = state
        .proxy_manager
        .register_or_replace(
            "run-1".to_string(),
            proxy_info("s", "sudp", "run-1", Some(24042), 2),
        )
        .await
        .expect("supersession replacement")
        .expect("replaced entry");
    free_replaced_port(&state, &replaced, 24042).await;
    assert!(
        state.used_udp_ports.read().await.contains(&24042),
        "same-port replacement keeps the mark (now the new control's)"
    );
}

#[tokio::test]
async fn supersession_replacement_tcp_group_port_kept_while_members_remain() {
    // Audit-fix regression (finding 1): a replaced TCP group member
    // moving to a DIFFERENT group must not free the old group's shared
    // port while a sibling member still owns the shared listener.
    let state = test_state();
    state.used_ports.write().await.insert(24046);
    let mut g1 = proxy_info("g1", "tcp", "run-1", Some(24046), 1);
    g1.group = Some("grp".to_string());
    state
        .proxy_manager
        .register("run-1".to_string(), g1)
        .await
        .expect("register g1");
    let mut g2 = proxy_info("g2", "tcp", "run-2", Some(24046), 1);
    g2.group = Some("grp".to_string());
    state
        .proxy_manager
        .register("run-2".to_string(), g2)
        .await
        .expect("register g2");

    // Superseding control re-registers g1 into a different group.
    let mut g1b = proxy_info("g1", "tcp", "run-1", Some(24047), 2);
    g1b.group = Some("grp2".to_string());
    let replaced = state
        .proxy_manager
        .register_or_replace("run-1".to_string(), g1b)
        .await
        .expect("supersession replacement")
        .expect("replaced entry");
    // The new registration's allocation inserted its own mark.
    state.used_ports.write().await.insert(24047);
    free_replaced_port(&state, &replaced, 24047).await;

    assert!(
        state.used_ports.read().await.contains(&24046),
        "group port mark stays while a sibling member remains"
    );
    assert!(state.used_ports.read().await.contains(&24047));
    assert_eq!(
        state.proxy_manager.group_len("grp").await,
        1,
        "g1 left the old group index"
    );
    assert_eq!(state.proxy_manager.group_len("grp2").await, 1);
}

#[tokio::test]
async fn supersession_replacement_frees_group_port_when_group_emptied() {
    // Audit-fix regression (finding 1): a replaced TCP group member
    // whose old group emptied must free the shared port AND stop the
    // group's shared listener.
    let state = test_state();
    state.used_ports.write().await.insert(24048);
    let mut g1 = proxy_info("g1", "tcp", "run-1", Some(24048), 1);
    g1.group = Some("grp".to_string());
    state
        .proxy_manager
        .register("run-1".to_string(), g1)
        .await
        .expect("register g1");
    // The shared group listener (normally created by the first member's
    // NewProxy bind).
    let cancel_token = tokio_util::sync::CancellationToken::new();
    state
        .tcp_group_ctl
        .create_group(
            "grp",
            "k",
            24048,
            24048, // declared_port: unit harness registers with no conflict
            "127.0.0.1",
            tokio::spawn(async {}),
            cancel_token.clone(),
        )
        .await
        .expect("create group");

    let mut g1b = proxy_info("g1", "tcp", "run-1", Some(24049), 2);
    g1b.group = Some("grp2".to_string());
    let replaced = state
        .proxy_manager
        .register_or_replace("run-1".to_string(), g1b)
        .await
        .expect("supersession replacement")
        .expect("replaced entry");
    // The new registration's allocation inserted its own mark.
    state.used_ports.write().await.insert(24049);
    free_replaced_port(&state, &replaced, 24049).await;

    assert!(
        !state.used_ports.read().await.contains(&24048),
        "emptied old group's port mark is freed"
    );
    assert!(
        cancel_token.is_cancelled(),
        "emptied old group's shared listener is stopped"
    );
    assert!(
        state.port_reservations.read().await.contains_key("g1"),
        "freed group port reserved under the proxy name"
    );
}

#[tokio::test]
async fn supersession_replacement_group_recheck_keeps_listener_on_concurrent_join() {
    // Audit-fix regression: free_replaced_port's TCP-group branch
    // re-checks group_len immediately before remove_group (mirroring
    // the sweep's phase-3 re-check). A member joining between the first
    // observation and the teardown registers against the shared
    // listener without creating one of its own — remove_group would
    // cancel the listener out from under it, a dead group with a live
    // member.
    let state = test_state();
    state.used_ports.write().await.insert(24055);
    let mut g1 = proxy_info("g1", "tcp", "run-1", Some(24055), 1);
    g1.group = Some("grp".to_string());
    state
        .proxy_manager
        .register("run-1".to_string(), g1)
        .await
        .expect("register g1");
    // The shared group listener (normally created by the first member's
    // NewProxy bind).
    let cancel_token = tokio_util::sync::CancellationToken::new();
    state
        .tcp_group_ctl
        .create_group(
            "grp",
            "k",
            24055,
            24055, // declared_port: unit harness registers with no conflict
            "127.0.0.1",
            tokio::spawn(async {}),
            cancel_token.clone(),
        )
        .await
        .expect("create group");

    let mut g1b = proxy_info("g1", "tcp", "run-1", Some(24056), 2);
    g1b.group = Some("grp2".to_string());
    let replaced = state
        .proxy_manager
        .register_or_replace("run-1".to_string(), g1b)
        .await
        .expect("supersession replacement")
        .expect("replaced entry");
    // The new registration's allocation inserted its own mark.
    state.used_ports.write().await.insert(24056);

    // Park free_replaced_port between its first group_len observation
    // and the re-check: hold port_reservations (acquired after the mark
    // removal, before the re-check). Every await before that park
    // (group_len, used_ports) is uncontended, so a freed mark means the
    // task has passed the first "group empty" observation and parked.
    let held_reservations = state.port_reservations.write().await;
    let task = tokio::spawn({
        let state = state.clone();
        async move { free_replaced_port(&state, &replaced, 24056).await }
    });
    tokio::task::yield_now().await;
    assert!(
        !state.used_ports.read().await.contains(&24055),
        "the old group's mark should be freed before the task parks on port_reservations"
    );

    // A new member joins the old group between the first observation
    // and the re-check.
    let mut g2 = proxy_info("g2", "tcp", "run-2", Some(24055), 3);
    g2.group = Some("grp".to_string());
    state
        .proxy_manager
        .register("run-2".to_string(), g2)
        .await
        .expect("register g2");
    assert_eq!(state.proxy_manager.group_len("grp").await, 1);

    drop(held_reservations);
    tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .expect("free_replaced_port hung")
        .expect("task panicked");

    // The shared listener survives with its live member.
    assert!(
        state.tcp_group_ctl.group_exists("grp").await,
        "shared group listener must survive a concurrent member join"
    );
    assert!(!cancel_token.is_cancelled());
    assert_eq!(state.proxy_manager.group_len("grp").await, 1);
}

#[tokio::test]
async fn duplicate_login_conflict_does_not_sweep_live_control() {
    // Audit-fix regression (finding 3): the login paths must not sweep
    // the LIVE control's proxies. Note the duplicate-login CONFLICT
    // path itself could never have — register_with_control_id only
    // reports conflict when the existing entry's run_id DIFFERS
    // (registry.rs), and the sweep is run_id-scoped, so it would be
    // vacuous for another run_id's proxies. The REAL danger is the
    // login FAILURE paths after a 10s handoff-barrier timeout
    // (LoginResp write / flush failures in login.rs): there the new
    // login's control_id (monotonic counter) is HIGHER than the older
    // live control's, so a full sweep's generation filter would let
    // the older control's proxies through — tearing down ports,
    // sk_index, and routes while that control may still be running.
    // This test stages that state (same run_id, newer control_id,
    // sweep-free unregister) and asserts the live control's proxies
    // survive.
    let state = test_state();
    insert_control(&state, "run-1", 1).await;
    state
        .proxy_manager
        .register(
            "run-1".to_string(),
            proxy_info("p", "tcp", "run-1", Some(24053), 1),
        )
        .await
        .expect("register p");
    state.used_ports.write().await.insert(24053);
    let mut s = proxy_info("s", "stcp", "run-1", Some(0), 1);
    s.sk = Some("secret".to_string());
    state
        .proxy_manager
        .register("run-1".to_string(), s)
        .await
        .expect("register s");
    state
        .xtcp
        .sk_index
        .insert("s".to_string(), "secret".to_string());
    state
        .client_ports_used
        .write()
        .await
        .insert("run-1".to_string(), 1);

    // The rejected duplicate login's own ctl entry (control_id 2)
    // replaced the live control's entry before the conflict path ran —
    // mirror that here, then unregister with sweep=false.
    insert_control(&state, "run-1", 2).await;
    unregister_control(&state, "run-1", 2, false, false).await;

    assert!(
        state.proxy_manager.get("p").await.is_some(),
        "live control's proxy must survive the conflict path"
    );
    assert_eq!(state.proxy_manager.get("p").await.unwrap().control_id, 1);
    assert!(
        state.used_ports.read().await.contains(&24053),
        "live control's port mark must survive"
    );
    assert!(
        state.xtcp.sk_index.contains_key("s"),
        "live control's sk_index entry must survive"
    );
    assert_eq!(
        *state.client_ports_used.read().await.get("run-1").unwrap(),
        1,
        "live control's port count must survive"
    );
    assert!(
        !state.run_id_to_ctl_tx.contains_key("run-1"),
        "the rejected login's own ctl entry is removed"
    );
}

#[tokio::test]
async fn unregister_control_full_sweep_still_tears_down_older_generation() {
    // Contrast for the sweep-free mode: with sweep=true, a higher
    // control_id DOES tear down older proxies — that is the normal
    // cleanup behavior the conflict path must not trigger.
    let state = test_state();
    insert_control(&state, "run-1", 1).await;
    state
        .proxy_manager
        .register(
            "run-1".to_string(),
            proxy_info("p", "tcp", "run-1", Some(24054), 1),
        )
        .await
        .expect("register p");
    state.used_ports.write().await.insert(24054);

    unregister_control(&state, "run-1", 2, false, true).await;
    // unregister_control frees the ports; the registry-entry removal is
    // the caller's job (control::cleanup) — the port assertion is what
    // distinguishes the sweep from the sweep-free mode.
    assert!(!state.used_ports.read().await.contains(&24054));
}

#[tokio::test]
async fn unregister_control_sweep_skips_replaced_proxy_routes() {
    // Audit-fix regression (finding 6): the sweep's snapshot is taken
    // BEFORE its route cleanup runs. A superseding control that
    // re-registers the same name between snapshot and sweep must not
    // lose its sk_index entry / vhost routes.
    let state = test_state();
    insert_control(&state, "run-1", 1).await;
    let mut s = proxy_info("s", "stcp", "run-1", Some(0), 1);
    s.sk = Some("secret".to_string());
    state
        .proxy_manager
        .register("run-1".to_string(), s)
        .await
        .expect("register s");
    state
        .xtcp
        .sk_index
        .insert("s".to_string(), "secret".to_string());

    // Park the sweep after its snapshot, before the sk_index loop: hold
    // used_ports so phase 2 blocks. Every await before that park
    // (ctl removal, OIDC subjects, list_client, phase 1) is
    // uncontended, so a removed run_id entry means the task is parked
    // there with the snapshot already taken.
    let held_ports = state.used_ports.write().await;
    let unreg = tokio::spawn({
        let state = state.clone();
        async move { unregister_control(&state, "run-1", 1, false, true).await }
    });
    tokio::task::yield_now().await;
    assert!(
        !state.run_id_to_ctl_tx.contains_key("run-1"),
        "cleanup should have passed the ctl removal and parked on used_ports"
    );

    // A superseding control re-registers the same name between the
    // snapshot and the sweep's route cleanup, and re-inserts its
    // sk_index entry.
    let mut s2 = proxy_info("s", "stcp", "run-1", Some(0), 2);
    s2.sk = Some("secret".to_string());
    state
        .proxy_manager
        .register_or_replace("run-1".to_string(), s2)
        .await
        .expect("superseding replacement");
    state
        .xtcp
        .sk_index
        .insert("s".to_string(), "secret".to_string());

    drop(held_ports);
    tokio::time::timeout(Duration::from_secs(5), unreg)
        .await
        .expect("cleanup hung")
        .expect("cleanup panicked");

    assert!(
        state.xtcp.sk_index.contains_key("s"),
        "superseding control's sk_index must survive the old sweep"
    );
    assert_eq!(
        state
            .proxy_manager
            .get("s")
            .await
            .expect("registry entry")
            .control_id,
        2,
        "superseding control's registry entry survives"
    );
}

#[tokio::test]
async fn unregister_control_sweep_skips_replaced_proxy_ports_and_counts() {
    // Audit-fix regression (phase-1 port decisions + per-client count
    // decrement): the sweep's snapshot is taken BEFORE its phase-1 port
    // decisions. A superseding control that re-registers a name between
    // snapshot and phase 1 (barrier-timeout supersession) must not have
    // its old port decisions re-run by the sweep. Scenario: g1 (group
    // "grp") is replaced by a newer generation; the replacement's
    // free_replaced_port KEEPS the shared port mark while the sibling
    // g2 (another run_id) remains. Without the phase-1 ownership
    // re-check the sweep would observe group_len("grp") == 1 and free
    // the sibling's mark, then its phase-3 re-check (still 1, since g2
    // is untouched) would match and cancel the shared listener out from
    // under the live sibling — a dead group with a live member. The
    // per-client count must likewise not be double-decremented (the
    // replacement path already net-zeroed it).
    let state = test_state();
    insert_control(&state, "run-1", 1).await;
    let mut g1 = proxy_info("g1", "tcp", "run-1", Some(24060), 1);
    g1.group = Some("grp".to_string());
    state
        .proxy_manager
        .register("run-1".to_string(), g1)
        .await
        .expect("register g1");
    // A sibling in the same group under a different run_id: NOT part of
    // this sweep's snapshot, and its shared listener must survive.
    let mut g2 = proxy_info("g2", "tcp", "run-2", Some(24060), 5);
    g2.group = Some("grp".to_string());
    state
        .proxy_manager
        .register("run-2".to_string(), g2)
        .await
        .expect("register g2");
    state.used_ports.write().await.insert(24060);
    state
        .client_ports_used
        .write()
        .await
        .insert("run-1".to_string(), 1);
    // The shared group listener (normally created by the first member's
    // NewProxy bind).
    let cancel_token = tokio_util::sync::CancellationToken::new();
    state
        .tcp_group_ctl
        .create_group(
            "grp",
            "k",
            24060,
            24060, // declared_port: unit harness registers with no conflict
            "127.0.0.1",
            tokio::spawn(async {}),
            cancel_token.clone(),
        )
        .await
        .expect("create group");

    // Park the sweep after its snapshot, before phase 1: hold
    // oidc.subjects (acquired right after list_client). Every await
    // before that park (ctl removal, list_client, subjects) is
    // uncontended, so a removed run_id entry means the task is parked
    // there with the snapshot already taken.
    let held_subjects = state.oidc.subjects.write().await;
    let unreg = tokio::spawn({
        let state = state.clone();
        async move { unregister_control(&state, "run-1", 1, false, true).await }
    });
    tokio::task::yield_now().await;
    assert!(
        !state.run_id_to_ctl_tx.contains_key("run-1"),
        "cleanup should have passed the ctl removal and parked on oidc subjects"
    );

    // A superseding control re-registers g1 between the snapshot and
    // phase 1. Mirror the real replacement path (handle_new_proxy):
    // register_or_replace + per-client count net-zero + free_replaced_port
    // (which keeps the shared mark while g2 remains).
    let replaced = state
        .proxy_manager
        .register_or_replace(
            "run-1".to_string(),
            proxy_info("g1", "tcp", "run-1", Some(24061), 2),
        )
        .await
        .expect("superseding replacement")
        .expect("replaced entry");
    {
        let mut port_counts = state.client_ports_used.write().await;
        let count = port_counts.get_mut("run-1").unwrap();
        *count = count.saturating_sub(1);
        if *count == 0 {
            port_counts.remove("run-1");
        }
    }
    state.used_ports.write().await.insert(24061);
    free_replaced_port(&state, &replaced, 24061).await;
    state
        .client_ports_used
        .write()
        .await
        .entry("run-1".to_string())
        .and_modify(|c| *c += 1)
        .or_insert(1);
    assert!(
        state.used_ports.read().await.contains(&24060),
        "the shared port mark stays while the sibling remains"
    );

    drop(held_subjects);
    tokio::time::timeout(Duration::from_secs(5), unreg)
        .await
        .expect("cleanup hung")
        .expect("cleanup panicked");

    // The sibling's mark, its shared listener, and the count all
    // survive the old sweep.
    assert!(
        state.used_ports.read().await.contains(&24060),
        "sibling's shared port mark must survive the old sweep"
    );
    assert!(
        state.used_ports.read().await.contains(&24061),
        "superseding control's port mark must survive the old sweep"
    );
    assert!(
        state.tcp_group_ctl.group_exists("grp").await,
        "shared group listener must survive the old sweep"
    );
    assert!(!cancel_token.is_cancelled());
    assert_eq!(state.proxy_manager.group_len("grp").await, 1);
    assert_eq!(
        *state.client_ports_used.read().await.get("run-1").unwrap(),
        1,
        "the sweep must not double-decrement the replacement's count"
    );
    assert_eq!(
        state
            .proxy_manager
            .get("g1")
            .await
            .expect("registry entry")
            .control_id,
        2,
        "superseding control's registry entry survives"
    );
}

#[cfg(feature = "vnet")]
#[tokio::test]
async fn unregister_control_sweep_skips_replaced_vnet_routes() {
    // Audit-fix regression (finding 6, vnet variant): the sweep's vnet
    // route cleanup must skip a name re-registered by a superseding
    // control between the snapshot and the vnet loop — mirror of the
    // tested sk_index variant (vnet IS replaceable via
    // register_or_replace, unlike http/https/tcpmux).
    let state = test_state();
    insert_control(&state, "run-1", 1).await;
    state
        .proxy_manager
        .register(
            "run-1".to_string(),
            proxy_info("v1", "vnet", "run-1", Some(0), 1),
        )
        .await
        .expect("register v1");
    state.vnet_routes.write().await.insert(
        ("vnet-1".to_string(), "10.7.0.0/24".to_string()),
        ("run-1".to_string(), "v1".to_string()),
    );

    // Park the sweep after its snapshot, before the vnet loop: hold
    // used_ports so phase 2 blocks. The vnet loop runs last (after the
    // sk_index/UDP/vhost loops), and every await before that park is
    // uncontended, so a removed run_id entry means the task is parked
    // there with the snapshot already taken.
    let held_ports = state.used_ports.write().await;
    let unreg = tokio::spawn({
        let state = state.clone();
        async move { unregister_control(&state, "run-1", 1, false, true).await }
    });
    tokio::task::yield_now().await;
    assert!(
        !state.run_id_to_ctl_tx.contains_key("run-1"),
        "cleanup should have passed the ctl removal and parked on used_ports"
    );

    // A superseding control re-registers the same name between the
    // snapshot and the vnet loop, and re-inserts its routes (mirroring
    // the replacement path's vnet route registration).
    state
        .proxy_manager
        .register_or_replace(
            "run-1".to_string(),
            proxy_info("v1", "vnet", "run-1", Some(0), 2),
        )
        .await
        .expect("superseding replacement");
    state.vnet_routes.write().await.insert(
        ("vnet-1".to_string(), "10.7.0.0/24".to_string()),
        ("run-1".to_string(), "v1".to_string()),
    );

    drop(held_ports);
    tokio::time::timeout(Duration::from_secs(5), unreg)
        .await
        .expect("cleanup hung")
        .expect("cleanup panicked");

    assert!(
        state
            .vnet_routes
            .read()
            .await
            .contains_key(&("vnet-1".to_string(), "10.7.0.0/24".to_string())),
        "superseding control's vnet route must survive the old sweep"
    );
    assert_eq!(
        state
            .proxy_manager
            .get("v1")
            .await
            .expect("registry entry")
            .control_id,
        2,
        "superseding control's registry entry survives"
    );
}

#[tokio::test]
async fn group_create_bind_race_joins_existing_group() {
    // Audit-fix regression (finding 2): a group-create bind that hits
    // EADDRINUSE (a sibling member created the group and bound its
    // shared listener mid-registration) must JOIN the existing group
    // instead of rejecting the first member.
    let state = test_state();
    insert_control(&state, "run-1", 1).await;
    let (itx, _rx) = mpsc::channel(8);
    let mut handles: std::collections::HashMap<String, tokio::task::JoinHandle<()>> =
        std::collections::HashMap::new();
    let mut udp_sockets: std::collections::HashMap<String, std::sync::Arc<tokio::net::UdpSocket>> =
        std::collections::HashMap::new();

    // Stage the interleaving: hold client_ports_used so the registration
    // task parks right AFTER registering the proxy and BEFORE its
    // group-create bind (the increment is the last await before
    // setup_proxy_listeners). On this single-threaded test runtime the
    // task only advances when the test awaits, so the bind collision is
    // deterministic.
    let held_counts = state.client_ports_used.write().await;
    let mut np = new_proxy("m1", "tcp");
    np.group = Some("g".to_string());
    np.group_key = Some("k".to_string());
    np.remote_port = Some(24051);
    let task = tokio::spawn({
        let state = state.clone();
        let itx = itx.clone();
        async move {
            let mut writer = Vec::new();
            handle_new_proxy(
                np,
                "run-1",
                1,
                &state,
                &mut writer,
                &itx,
                &mut handles,
                &mut udp_sockets,
                false,
            )
            .await;
            writer
        }
    });

    // Wait until the task has registered the proxy (parked at the
    // client_ports_used increment, before its bind). The OS probe for
    // port 24051 runs on the spawn_blocking pool (r3/server#1), so
    // yield_now alone cannot observe its completion on slow CI
    // machines — warm the pool, then poll with real time.
    tokio::task::spawn_blocking(|| {}).await.unwrap();
    for _ in 0..100 {
        if state.proxy_manager.get("m1").await.is_some() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
    assert!(
        state.proxy_manager.get("m1").await.is_some(),
        "registration task should have parked after registering"
    );

    // Now bind the port and create the group behind the task's back:
    // its bind deterministically fails with EADDRINUSE (3×100ms
    // retries), and the audit-fix fallback joins the group.
    let listener = std::net::TcpListener::bind("127.0.0.1:24051").expect("hold the group port");
    let cancel_token = tokio_util::sync::CancellationToken::new();
    state
        .tcp_group_ctl
        .create_group(
            "g",
            "k",
            24051,
            24051, // declared_port: unit harness registers with no conflict
            "127.0.0.1",
            tokio::spawn(async {}),
            cancel_token.clone(),
        )
        .await
        .expect("create group");
    drop(held_counts);

    let writer = tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .expect("registration task hung")
        .expect("registration task panicked");
    drop(listener);

    // The member was NOT rejected: it joined the existing group.
    let reg = state
        .proxy_manager
        .get("m1")
        .await
        .expect("m1 must be registered (joined the group)");
    assert_eq!(reg.control_id, 1);
    assert_eq!(
        reg.remote_port,
        Some(24051),
        "member registered on the group's shared port"
    );
    assert!(
        state.used_ports.read().await.contains(&24051),
        "group port stays marked"
    );
    assert_eq!(
        state
            .tcp_group_ctl
            .get_group_port("g", "k", 24051, "127.0.0.1")
            .await,
        GroupPortQuery::Matched(24051),
        "group still exists"
    );
    assert_eq!(
        *state.client_ports_used.read().await.get("run-1").unwrap(),
        1,
        "member counts exactly once after the rollback+join"
    );
    let resp_text = String::from_utf8_lossy(&writer);
    assert!(
        resp_text.contains("24051"),
        "member's NewProxyResp must carry the group port: {resp_text}"
    );
}

/// Drive one full handle_new_proxy registration and return the response
/// bytes. No group/listener is pre-created.
async fn register_np(np: msg::NewProxy, state: &Arc<AppState>) -> Vec<u8> {
    insert_control(state, "run-1", 1).await;
    let (itx, _rx) = mpsc::channel(8);
    let mut handles: std::collections::HashMap<String, tokio::task::JoinHandle<()>> =
        std::collections::HashMap::new();
    let mut udp_sockets: std::collections::HashMap<String, std::sync::Arc<tokio::net::UdpSocket>> =
        std::collections::HashMap::new();
    let mut writer = Vec::new();
    handle_new_proxy(
        np,
        "run-1",
        1,
        state,
        &mut writer,
        &itx,
        &mut handles,
        &mut udp_sockets,
        false,
    )
    .await;
    writer
}

#[tokio::test]
async fn tcp_group_key_mismatch_rejects_with_go_auth_failed() {
    // F5 pin: Go server/group/tcp.go `TCPGroup.Listen` validates later
    // members — group_key mismatch → ErrGroupAuthFailed "group auth
    // failed". The old code conflated the mismatch with a missing group
    // and silently created a second listener (split group).
    let state = test_state();
    let cancel_token = tokio_util::sync::CancellationToken::new();
    state
        .tcp_group_ctl
        .create_group(
            "g",
            "k",
            24051,
            24051, // declared_port: unit harness registers with no conflict
            "127.0.0.1",
            tokio::spawn(async {}),
            cancel_token.clone(),
        )
        .await
        .expect("create group");
    let mut np = new_proxy("m1", "tcp");
    np.group = Some("g".to_string());
    np.group_key = Some("k2".to_string()); // wrong key
    np.remote_port = Some(24051);
    let writer = register_np(np, &state).await;
    let resp_text = String::from_utf8_lossy(&writer);
    assert!(
        resp_text.contains("group auth failed"),
        "must reject with Go text: {resp_text}"
    );
    assert!(
        state.proxy_manager.get("m1").await.is_none(),
        "mismatched member must not register"
    );
}

#[tokio::test]
async fn tcp_group_port_mismatch_rejects_with_go_different_port() {
    // F5 pin: port mismatch → ErrGroupDifferentPort "group should have
    // same remote port".
    let state = test_state();
    let cancel_token = tokio_util::sync::CancellationToken::new();
    state
        .tcp_group_ctl
        .create_group(
            "g",
            "k",
            24051,
            24051, // declared_port: unit harness registers with no conflict
            "127.0.0.1",
            tokio::spawn(async {}),
            cancel_token.clone(),
        )
        .await
        .expect("create group");
    let mut np = new_proxy("m1", "tcp");
    np.group = Some("g".to_string());
    np.group_key = Some("k".to_string());
    np.remote_port = Some(24052); // different port
    let writer = register_np(np, &state).await;
    let resp_text = String::from_utf8_lossy(&writer);
    assert!(
        resp_text.contains("group should have same remote port"),
        "must reject with Go text: {resp_text}"
    );
    assert!(state.proxy_manager.get("m1").await.is_none());
}

#[tokio::test]
async fn tcp_group_query_distinguishes_notfound_and_all_mismatch_kinds() {
    // F5 pin: the tri-state query drives the reject-vs-create decision
    // (Go check order: addr → port → group_key).
    let state = test_state();
    let cancel_token = tokio_util::sync::CancellationToken::new();
    state
        .tcp_group_ctl
        .create_group(
            "g",
            "k",
            24051,
            24051, // declared_port: unit harness registers with no conflict
            "127.0.0.1",
            tokio::spawn(async {}),
            cancel_token.clone(),
        )
        .await
        .expect("create group");
    let ctl = &state.tcp_group_ctl;
    // Exact match → the shared port.
    assert_eq!(
        ctl.get_group_port("g", "k", 24051, "127.0.0.1").await,
        GroupPortQuery::Matched(24051)
    );
    // Auto-assign (port 0) CANNOT join an explicit-port group: Go
    // compares DECLARED numbers with no zero exemption (tcp.go:111-113),
    // so a 0-declaring member versus a 24051-declaring group mismatches
    // and the caller must not take the group's port.
    assert_eq!(
        ctl.get_group_port("g", "k", 0, "127.0.0.1").await,
        GroupPortQuery::Mismatch("group should have same remote port")
    );
    // Unknown group → NotFound (caller creates).
    assert_eq!(
        ctl.get_group_port("nope", "k", 24051, "127.0.0.1").await,
        GroupPortQuery::NotFound
    );
    // Mismatch kinds carry the Go texts (server/group/group.go).
    assert_eq!(
        ctl.get_group_port("g", "k", 24052, "127.0.0.1").await,
        GroupPortQuery::Mismatch("group should have same remote port")
    );
    assert_eq!(
        ctl.get_group_port("g", "k2", 24051, "127.0.0.1").await,
        GroupPortQuery::Mismatch("group auth failed")
    );
    assert_eq!(
        ctl.get_group_port("g", "k", 24051, "10.0.0.1").await,
        GroupPortQuery::Mismatch("group params invalid")
    );
}

#[tokio::test]
async fn tcpmux_unknown_multiplexer_rejected_empty_accepted() {
    // F6 pin: Go server/proxy/tcpmux.go `Run()` — only httpconnect is
    // valid, anything else rejects with `unknown multiplexer [%s]`.
    // frp-rs accepts "" as a lenient default (documented divergence:
    // Go rejects "", existing frp-rs configs omit the field).
    let state = test_state();
    let mut np = new_proxy("m1", "tcpmux");
    np.multiplexer = Some("socks5".to_string());
    np.custom_domains = Some(vec!["a.example.com".to_string()]);
    let writer = register_np(np, &state).await;
    let resp_text = String::from_utf8_lossy(&writer);
    assert!(
        resp_text.contains("unknown multiplexer [socks5]"),
        "must reject with Go text: {resp_text}"
    );
    assert!(state.proxy_manager.get("m1").await.is_none());

    // "" default (multiplexer omitted) still registers.
    let state2 = test_state();
    let mut np2 = new_proxy("m2", "tcpmux");
    np2.custom_domains = Some(vec!["b.example.com".to_string()]);
    let writer2 = register_np(np2, &state2).await;
    let resp_text2 = String::from_utf8_lossy(&writer2);
    assert!(
        !resp_text2.contains("unknown multiplexer"),
        "default multiplexer must register: {resp_text2}"
    );
    assert!(
        state2.proxy_manager.get("m2").await.is_some(),
        "tcpmux with default multiplexer must register"
    );
}

/// Register a vnet proxy through the full handle_new_proxy path.
/// Returns (ok, NewProxyResp bytes as lossy string).
#[cfg(feature = "vnet")]
async fn register_vnet_proxy(
    state: &Arc<AppState>,
    itx: &mpsc::Sender<InternalMsg>,
    handles: &mut std::collections::HashMap<String, tokio::task::JoinHandle<()>>,
    udp_sockets: &mut std::collections::HashMap<String, std::sync::Arc<tokio::net::UdpSocket>>,
    np: msg::NewProxy,
    run_id: &str,
    ctl_id: u64,
) -> (bool, String) {
    let mut writer = Vec::new();
    let ok = handle_new_proxy(
        np,
        run_id,
        ctl_id,
        state,
        &mut writer,
        itx,
        handles,
        udp_sockets,
        false,
    )
    .await;
    (ok, String::from_utf8_lossy(&writer).to_string())
}

/// M2-adjacent audit finding 5: the NewProxy vnet_routes insert was
/// unconditional — a hijack advertise subnet (0.0.0.0/0) registered
/// instead of being refused like the VnetRouteAdvertise path refuses
/// it. The proxy registration must roll back and the client must get
/// an explicit rejection.
#[cfg(feature = "vnet")]
#[tokio::test]
async fn vnet_proxy_hijack_prefix_rejected_and_rolled_back() {
    let state = test_state();
    insert_control(&state, "run-1", 1).await;
    let (itx, _rx) = mpsc::channel(8);
    let mut handles: std::collections::HashMap<String, tokio::task::JoinHandle<()>> =
        std::collections::HashMap::new();
    let mut udp_sockets: std::collections::HashMap<String, std::sync::Arc<tokio::net::UdpSocket>> =
        std::collections::HashMap::new();

    // 0.0.0.0/0 would inject a default route into peers' kernels.
    let mut np = new_proxy("vp-hijack", "vnet");
    np.virtual_net = Some("vnet-1".to_string());
    np.advertise_subnet = Some("0.0.0.0/0".to_string());
    let (ok, resp) =
        register_vnet_proxy(&state, &itx, &mut handles, &mut udp_sockets, np, "run-1", 1).await;
    assert!(!ok, "hijack-prefix vnet proxy must be rejected: {resp}");
    assert!(
        resp.contains("hijack prefix"),
        "rejection must name the hijack prefix: {resp}"
    );
    assert!(
        state.proxy_manager.get("vp-hijack").await.is_none(),
        "rejected proxy must be rolled back out of the registry"
    );
    assert!(
        state.vnet_routes.read().await.is_empty(),
        "no route may be inserted for a rejected hijack proxy"
    );
}

/// Audit finding 5: the per-client route cap (64) must also gate the
/// NewProxy path, not just VnetRouteAdvertise. Re-registering an
/// already-owned key stays allowed (reload keeps the run_id).
#[cfg(feature = "vnet")]
#[tokio::test]
async fn vnet_proxy_route_cap_blocks_new_keys_allows_own_update() {
    let state = test_state();
    insert_control(&state, "run-1", 1).await;
    {
        let mut routes = state.vnet_routes.write().await;
        for i in 0..crate::control::nathole::MAX_VNET_ROUTES_PER_CLIENT {
            routes.insert(
                ("vnet-1".to_string(), format!("10.{i}.0.0/16")),
                ("run-1".to_string(), format!("filler-{i}")),
            );
        }
    }
    let (itx, _rx) = mpsc::channel(8);
    let mut handles: std::collections::HashMap<String, tokio::task::JoinHandle<()>> =
        std::collections::HashMap::new();
    let mut udp_sockets: std::collections::HashMap<String, std::sync::Arc<tokio::net::UdpSocket>> =
        std::collections::HashMap::new();

    // New key at the cap → rejected.
    let mut np = new_proxy("vp-over", "vnet");
    np.virtual_net = Some("vnet-1".to_string());
    np.advertise_subnet = Some("10.200.0.0/16".to_string());
    let (ok, resp) =
        register_vnet_proxy(&state, &itx, &mut handles, &mut udp_sockets, np, "run-1", 1).await;
    assert!(!ok, "over-cap vnet proxy must be rejected: {resp}");
    assert!(
        resp.contains("route cap"),
        "rejection must name the per-client cap: {resp}"
    );
    assert!(state.proxy_manager.get("vp-over").await.is_none());

    // Same run_id re-registering an already-owned key (reload) → allowed.
    let mut np = new_proxy("vp-update", "vnet");
    np.virtual_net = Some("vnet-1".to_string());
    np.advertise_subnet = Some("10.0.0.0/16".to_string());
    let (ok, resp) =
        register_vnet_proxy(&state, &itx, &mut handles, &mut udp_sockets, np, "run-1", 1).await;
    assert!(ok, "own-key re-registration must be allowed: {resp}");
    let routes = state.vnet_routes.read().await;
    assert_eq!(
        routes.get(&("vnet-1".to_string(), "10.0.0.0/16".to_string())),
        Some(&("run-1".to_string(), "vp-update".to_string())),
        "own-key update must replace the route value"
    );
    drop(routes);
}

/// Audit finding 5: a live owner's (virtual_net, subnet) route must not
/// be silently overwritten by another run_id's vnet proxy — the
/// displaced proxy's visitor packets would be redirected here. The
/// second registration is rejected and the original route survives.
#[cfg(feature = "vnet")]
#[tokio::test]
async fn vnet_proxy_live_owner_conflict_rejected() {
    let state = test_state();
    insert_control(&state, "run-1", 1).await;
    insert_control(&state, "run-2", 2).await;
    let (itx, _rx) = mpsc::channel(8);
    let mut handles: std::collections::HashMap<String, tokio::task::JoinHandle<()>> =
        std::collections::HashMap::new();
    let mut udp_sockets: std::collections::HashMap<String, std::sync::Arc<tokio::net::UdpSocket>> =
        std::collections::HashMap::new();

    // First owner registers its route.
    let mut np = new_proxy("vp-a", "vnet");
    np.virtual_net = Some("vnet-1".to_string());
    np.advertise_subnet = Some("10.7.0.0/24".to_string());
    let (ok, resp) =
        register_vnet_proxy(&state, &itx, &mut handles, &mut udp_sockets, np, "run-1", 1).await;
    assert!(ok, "first owner must register: {resp}");

    // Second run_id, same subnet → rejected, route untouched.
    let mut np = new_proxy("vp-b", "vnet");
    np.virtual_net = Some("vnet-1".to_string());
    np.advertise_subnet = Some("10.7.0.0/24".to_string());
    let (ok, resp) =
        register_vnet_proxy(&state, &itx, &mut handles, &mut udp_sockets, np, "run-2", 2).await;
    assert!(!ok, "live-owner conflict must be rejected: {resp}");
    assert!(
        resp.contains("already owned by live run_id"),
        "rejection must name the live owner: {resp}"
    );
    assert!(state.proxy_manager.get("vp-b").await.is_none());
    let routes = state.vnet_routes.read().await;
    assert_eq!(
        routes.get(&("vnet-1".to_string(), "10.7.0.0/24".to_string())),
        Some(&("run-1".to_string(), "vp-a".to_string())),
        "the original owner's route must survive the rejected takeover"
    );
    drop(routes);
}

/// Audit finding 5: a DEAD owner's route is reclaimable — a crashed
/// client that restarted with a fresh run_id must not be blocked from
/// re-advertising its subnet (mirror of the advertise-path liveness
/// check).
#[cfg(feature = "vnet")]
#[tokio::test]
async fn vnet_proxy_takes_over_dead_owner_route() {
    let state = test_state();
    // run-1 is NOT in run_id_to_ctl_tx — its control is dead.
    state.vnet_routes.write().await.insert(
        ("vnet-1".to_string(), "10.7.0.0/24".to_string()),
        ("run-1".to_string(), "ghost".to_string()),
    );
    insert_control(&state, "run-2", 2).await;
    let (itx, _rx) = mpsc::channel(8);
    let mut handles: std::collections::HashMap<String, tokio::task::JoinHandle<()>> =
        std::collections::HashMap::new();
    let mut udp_sockets: std::collections::HashMap<String, std::sync::Arc<tokio::net::UdpSocket>> =
        std::collections::HashMap::new();

    let mut np = new_proxy("vp-b", "vnet");
    np.virtual_net = Some("vnet-1".to_string());
    np.advertise_subnet = Some("10.7.0.0/24".to_string());
    let (ok, resp) =
        register_vnet_proxy(&state, &itx, &mut handles, &mut udp_sockets, np, "run-2", 2).await;
    assert!(ok, "dead-owner takeover must be allowed: {resp}");
    let routes = state.vnet_routes.read().await;
    assert_eq!(
        routes.get(&("vnet-1".to_string(), "10.7.0.0/24".to_string())),
        Some(&("run-2".to_string(), "vp-b".to_string())),
        "the fresh run_id must own the reclaimed route"
    );
    drop(routes);
}
