use super::*;

fn proxy_info(phase: ProxyPhase) -> ProxyRuntimeInfo {
    ProxyRuntimeInfo {
        local_addr: "127.0.0.1:8080".to_string(),
        proxy_type: "tcp".to_string(),
        use_encryption: false,
        use_compression: false,
        sk: String::new(),
        bandwidth_limit: 0,
        bandwidth_limit_mode: String::new(),
        bandwidth_limiter: None,
        proxy_protocol_version: String::new(),
        plugin: String::new(),
        remote_addr: String::new(),
        err: String::new(),
        config_snapshot: String::new(),
        phase,
    }
}

/// A `ControlWriter` whose receiver the caller keeps, so a test can assert
/// on what the handler under test enqueued on the control channel.
fn test_control_writer_rx() -> (
    Arc<ControlWriter>,
    tokio::sync::mpsc::Receiver<(FrpMessage, bool)>,
) {
    let (tx, rx) = tokio::sync::mpsc::channel::<(FrpMessage, bool)>(16);
    (
        Arc::new(ControlWriter {
            tx,
            failed: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            notify: Arc::new(tokio::sync::Notify::new()),
        }),
        rx,
    )
}

/// A minimal `SessionCtx` for tests that drive an extracted arm handler
/// directly. The extracted arms reach only a handful of `SessionCtx`
/// fields between them, but the struct has no `Default` and is private to
/// `service` (this module is its child, so it can name it), so the literal
/// is spelled out. `reader` stays `None`: no arm touches it.
fn test_session_ctx() -> SessionCtx {
    SessionCtx {
        control_stream: None,
        run_id: "test-run-id".to_string(),
        yamux: None,
        v2: false,
        #[cfg(feature = "quic")]
        quic_conn: None,
        ping_interval: None,
        ping_retry_backoff: None,
        last_pong: Instant::now(),
        hb_timeout: 30,
        hb_timeout_dur: Duration::from_secs(30),
        hb_watchdog_active: false,
        session_alive: Arc::new(AtomicBool::new(true)),
        wc_server_addr: "127.0.0.1".to_string(),
        wc_server_port: 7000,
        wc_tls_enable: false,
        wc_tls_server_name: String::new(),
        wc_tls_ca_file: None,
        wc_tls_use_system_ca: false,
        wc_tls_cert_file: None,
        wc_tls_key_file: None,
        wc_dns_server: None,
        wc_udp_packet_size: 1500,
        wc_udp_packet_codec: String::new(),
        wc_disable_custom_tls_first_byte: false,
        wc_keepalive_secs: 7200,
        wc_kcp_dead_link: frp_core::KCP_DEAD_LINK_DEFAULT,
        wc_kcp_liveness_probe: true,
        wc_bind_addr: None,
        wc_proxy_url: String::new(),
        wc_dial_timeout_secs: 10,
        protocol: TransportProtocol::Tcp,
        client_scopes: Vec::new(),
        server_scopes: Vec::new(),
        shutdown_flag: Arc::new(AtomicBool::new(false)),
        session_started_at: Instant::now(),
        pending_proxies: Vec::new(),
        pending_visitors: Vec::new(),
        write_failed: false,
        seen_registration_response: false,
        req_work_conns_seen: 0,
        writer: None,
        control_rx: None,
        control_failed: None,
        control_notify: None,
        reader: None,
        visitor_shutdown: None,
        visitor_handles: Vec::new(),
        work_conn_handles: Vec::new(),
        control_writer_handle: None,
        pending_xtcp: HashMap::new(),
        xtcp_sockets: Default::default(),
        visitor_pending: HashMap::new(),
        stun_result_tx: None,
        stun_result_rx: None,
        xtcp_cleanup_rx: None,
        proxy_retry_interval: None,
        waitstart_seen: HashMap::new(),
        cfg_user: String::new(),
    }
}

async fn test_service() -> Service {
    let cfg = ClientConfig {
        server_addr: "127.0.0.1".to_string(),
        server_port: 7000,
        token: "test-token".to_string(),
        ..Default::default()
    };
    Service::with_unsafe_features(cfg, None, UnsafeFeatures::default())
        .await
        .expect("service init must succeed")
}

/// The extracted `NewProxyResp` arm, driven directly. That arm has no
/// wire-level lane (no test puts a `NewProxyResp` on the wire to a client
/// `Service`), so this is the direct test for the phase and
/// `last_start_err` transitions it owns: an error moves
/// `WaitStart` -> `StartErr`, records the message and anchors the retry
/// clock; success accepts `WaitStart` and `StartErr` as `Running`
/// (clearing the error and copying `remote_addr`); a `Running` proxy and
/// an unknown proxy are left untouched by both branches.
#[tokio::test]
async fn new_proxy_resp_arm_moves_phase_and_anchors_retry() {
    let service = test_service().await;
    {
        let mut map = service.proxy_info_map.write().await;
        map.insert("user.p1".to_string(), proxy_info(ProxyPhase::WaitStart));
        map.insert("user.p2".to_string(), proxy_info(ProxyPhase::WaitStart));
        map.insert("user.p3".to_string(), proxy_info(ProxyPhase::Running));
    }
    let mut last_start_err: HashMap<String, Instant> = HashMap::new();

    // Non-empty error on a WaitStart proxy -> StartErr + retry anchor.
    service
        .handle_new_proxy_resp_arm(
            msg::NewProxyResp {
                proxy_name: "user.p1".to_string(),
                remote_addr: None,
                error: Some("port already used".to_string()),
            },
            &mut last_start_err,
        )
        .await;
    // Unknown proxy: neither branch may panic or anchor a clock.
    service
        .handle_new_proxy_resp_arm(
            msg::NewProxyResp {
                proxy_name: "user.unknown".to_string(),
                remote_addr: None,
                error: Some("boom".to_string()),
            },
            &mut last_start_err,
        )
        .await;

    {
        let map = service.proxy_info_map.read().await;
        let p1 = map.get("user.p1").expect("p1 present");
        match &p1.phase {
            ProxyPhase::StartErr(e) => assert_eq!(e, "port already used"),
            other => panic!("expected StartErr, got {}", other.as_str()),
        }
        assert_eq!(p1.err, "port already used");
        let p3 = map.get("user.p3").expect("p3 present");
        assert_eq!(
            p3.phase.as_str(),
            "running",
            "the error branch must not touch a Running proxy"
        );
    }
    assert!(
        last_start_err.contains_key("user.p1"),
        "the StartErr retry clock must be anchored on the error"
    );
    assert!(
        !last_start_err.contains_key("user.unknown"),
        "an unknown proxy must not anchor a retry clock"
    );

    // Success from WaitStart -> Running.
    service
        .handle_new_proxy_resp_arm(
            msg::NewProxyResp {
                proxy_name: "user.p2".to_string(),
                remote_addr: Some("1.2.3.4:7001".to_string()),
                error: None,
            },
            &mut last_start_err,
        )
        .await;
    // Empty (not absent) error is success, and StartErr may still recover.
    service
        .handle_new_proxy_resp_arm(
            msg::NewProxyResp {
                proxy_name: "user.p1".to_string(),
                remote_addr: Some("1.2.3.4:7002".to_string()),
                error: Some(String::new()),
            },
            &mut last_start_err,
        )
        .await;

    {
        let map = service.proxy_info_map.read().await;
        let p2 = map.get("user.p2").expect("p2 present");
        assert_eq!(p2.phase.as_str(), "running");
        assert_eq!(p2.remote_addr, "1.2.3.4:7001");
        assert!(p2.err.is_empty());
        let p1 = map.get("user.p1").expect("p1 present");
        assert_eq!(p1.phase.as_str(), "running");
        assert_eq!(p1.remote_addr, "1.2.3.4:7002");
        assert!(p1.err.is_empty());
        let p3 = map.get("user.p3").expect("p3 present");
        assert_eq!(p3.phase.as_str(), "running");
        assert!(
            p3.remote_addr.is_empty(),
            "the success branch must not touch a Running proxy"
        );
    }
}

/// A `Service` whose config participates in the `corp-net` virtual net: one
/// `virtual_net` proxy with a TUN address. That is the precondition
/// `local_vnet_set` applies before a vnet route frame is accepted, so it is
/// what the three vnet handlers below need to reach their accept branch.
#[cfg(feature = "vnet")]
async fn vnet_service() -> Service {
    let mut cfg = ClientConfig {
        server_addr: "127.0.0.1".to_string(),
        server_port: 7000,
        token: "test-token".to_string(),
        ..Default::default()
    };
    cfg.virtual_net.address = "10.0.0.1".to_string();
    cfg.proxies.push(frp_core::config::ProxyConfig {
        name: "vnet-a".to_string(),
        proxy_type: "vnet".to_string(),
        vnet_ip: "10.0.0.2".to_string(),
        vnet_netmask: "255.255.255.0".to_string(),
        virtual_net: "corp-net".to_string(),
        // `ProxyConfig`'s derived `Default` gives `enabled: false` (the
        // serde default is `true`, so only a hand-built config sees this),
        // and `with_unsafe_features` retains only enabled entries — without
        // this the vnet proxy is dropped and `local_vnet_set` is empty.
        enabled: true,
        ..Default::default()
    });
    Service::with_unsafe_features(cfg, None, UnsafeFeatures::default())
        .await
        .expect("service init must succeed")
}

/// The extracted `VnetPacket` arm, driven directly. No lane puts a
/// `VnetPacket` on the wire to a client `Service` (the `vnet` feature is in
/// no default build, and a server forwards one only to a peer that shares
/// the virtual net), so this is the direct test for the arm's three
/// behaviours: a decoded payload reaches the TUN channel registered for the
/// proxy, an undecodable payload is dropped, and a packet for a proxy with
/// neither a visitor nor a TUN channel is dropped.
#[cfg(feature = "vnet")]
#[tokio::test]
async fn vnet_packet_arm_delivers_to_tun_channel_and_drops_bad_input() {
    let service = vnet_service().await;
    let packet = vec![0x45u8, 0x00, 0x00, 0x14, 0xde, 0xad];
    let (tx, mut rx) = mpsc::channel::<Arc<[u8]>>(4);
    service
        .vnet_tun_tx
        .lock()
        .unwrap()
        .insert("vnet-a".to_string(), tx);

    service
        .handle_vnet_packet_arm(msg::VnetPacket {
            proxy_name: "vnet-a".to_string(),
            data: frp_core::base64::encode(&packet),
        })
        .await;
    let delivered = rx
        .try_recv()
        .expect("a decoded packet must reach the proxy's TUN channel");
    assert_eq!(&*delivered, &packet[..]);

    // Undecodable payload: warn, no delivery.
    service
        .handle_vnet_packet_arm(msg::VnetPacket {
            proxy_name: "vnet-a".to_string(),
            data: "!!!!".to_string(),
        })
        .await;
    assert!(rx.try_recv().is_err(), "a decode error must not deliver");

    // Neither a visitor route nor a TUN channel for the name: dropped.
    service
        .handle_vnet_packet_arm(msg::VnetPacket {
            proxy_name: "unknown".to_string(),
            data: frp_core::base64::encode(&packet),
        })
        .await;
    assert!(rx.try_recv().is_err(), "an unknown target must not deliver");
}

/// The extracted `VnetRouteAdvertise` arm, driven directly. A route for a
/// virtual net this client does not participate in is ignored; one for a
/// participating net lands in the shared route table, and (only when a
/// local TUN owns that net) is recorded as a peer route and injected at the
/// OS level.
#[cfg(feature = "vnet")]
#[tokio::test]
async fn vnet_route_advertise_arm_isolates_vnets_and_records_routes() {
    let service = vnet_service().await;

    // Foreign virtual net: ignored, route table and peer map untouched.
    service
        .handle_vnet_route_advertise_arm(msg::VnetRouteAdvertise {
            proxy_name: "peer-foreign".to_string(),
            subnet: "10.9.0.0/24".to_string(),
            virtual_net: Some("other-net".to_string()),
        })
        .await;
    assert_eq!(
        service
            .vnet_controller
            .route_table()
            .read()
            .await
            .lookup("other-net", &"10.9.0.5".parse().unwrap()),
        None
    );
    assert!(service.vnet_peer_routes.lock().await.is_empty());

    // Participating net, no local TUN: the TX route is inserted and no peer
    // route is recorded (there is no local interface to inject through).
    service
        .handle_vnet_route_advertise_arm(msg::VnetRouteAdvertise {
            proxy_name: "peer-a".to_string(),
            subnet: "10.1.0.0/24".to_string(),
            virtual_net: Some("corp-net".to_string()),
        })
        .await;
    assert_eq!(
        service
            .vnet_controller
            .route_table()
            .read()
            .await
            .lookup("corp-net", &"10.1.0.5".parse().unwrap()),
        Some("peer-a")
    );
    assert!(
        service.vnet_peer_routes.lock().await.is_empty(),
        "no local TUN for the net means no OS route to track"
    );

    // Participating net with a local TUN registered: the peer route is
    // recorded and the OS route injected (best-effort, so the injected
    // command's failure is ignored by `add_os_route`). Platform-gated
    // exactly like the block it exercises.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        service
            .vnet_tun_names
            .lock()
            .await
            .insert("vnet-a".to_string(), "tun-test0".to_string());
        service
            .handle_vnet_route_advertise_arm(msg::VnetRouteAdvertise {
                proxy_name: "peer-b".to_string(),
                subnet: "10.2.0.0/24".to_string(),
                virtual_net: Some("corp-net".to_string()),
            })
            .await;
        let peer_routes = service.vnet_peer_routes.lock().await;
        let (subnet, tun_name, vnet) = peer_routes
            .get("peer-b")
            .expect("a local TUN must record the peer route");
        assert_eq!(subnet, "10.2.0.0/24");
        assert_eq!(tun_name, "tun-test0");
        assert_eq!(vnet, "corp-net");
    }
}

/// The extracted `VnetRouteRemove` arm, driven directly. A removal for a
/// foreign virtual net is ignored; one for a participating net drops the
/// peer's OS route, its route-table entry and its visitor route.
#[cfg(feature = "vnet")]
#[tokio::test]
async fn vnet_route_remove_arm_isolates_vnets_and_cleans_state() {
    let service = vnet_service().await;
    let (visitor_tx, _visitor_rx) = mpsc::channel::<Vec<u8>>(4);
    service
        .vnet_controller
        .register_visitor_route("peer-a", "100.86.0.1/32", visitor_tx)
        .await
        .expect("visitor route registers");
    service
        .vnet_controller
        .route_table()
        .write()
        .await
        .insert("corp-net", "peer-a", "10.1.0.0/24")
        .expect("route inserts");
    service.vnet_peer_routes.lock().await.insert(
        "peer-a".to_string(),
        (
            "10.1.0.0/24".to_string(),
            "tun-test0".to_string(),
            "corp-net".to_string(),
        ),
    );

    // Foreign virtual net: ignored, every piece of state survives.
    service
        .handle_vnet_route_remove_arm(msg::VnetRouteRemove {
            proxy_name: "peer-a".to_string(),
            virtual_net: Some("other-net".to_string()),
        })
        .await;
    assert!(service.vnet_peer_routes.lock().await.contains_key("peer-a"));
    assert_eq!(
        service
            .vnet_controller
            .route_table()
            .read()
            .await
            .lookup("corp-net", &"10.1.0.5".parse().unwrap()),
        Some("peer-a")
    );
    assert!(service
        .vnet_controller
        .deliver_visitor_packet("peer-a", vec![0x45])
        .is_ok());

    // Participating net: peer route, route-table entry and visitor route go.
    service
        .handle_vnet_route_remove_arm(msg::VnetRouteRemove {
            proxy_name: "peer-a".to_string(),
            virtual_net: Some("corp-net".to_string()),
        })
        .await;
    assert!(service.vnet_peer_routes.lock().await.is_empty());
    assert_eq!(
        service
            .vnet_controller
            .route_table()
            .read()
            .await
            .lookup("corp-net", &"10.1.0.5".parse().unwrap()),
        None
    );
    assert!(service
        .vnet_controller
        .deliver_visitor_packet("peer-a", vec![0x45])
        .is_err());
}

/// The extracted ping-tick arm, driven directly. No test puts the arm's
/// timer on a live wire, so this is the direct lane for the two behaviours
/// the arm owns: an authenticated tick sends one `Ping` and clears the
/// failure streak, while a tick whose auth setup fails **skips** the send
/// (the session stays up) and re-arms `ping_interval` with the exponential
/// backoff, recording it in `ping_retry_backoff`.
///
/// `client_scopes` carries `HeartBeats` so `heartbeat_requires_auth` is
/// true, which is the precondition for the auth branch the skip path lives
/// in.
#[tokio::test]
async fn ping_tick_arm_sends_ping_and_skips_on_auth_failure() {
    // Normal path: token auth resolves, so a Ping is enqueued and the
    // streak is cleared.
    let service = test_service().await;
    let (writer, mut rx) = test_control_writer_rx();
    let mut ctx = test_session_ctx();
    // `HeartBeats` makes `heartbeat_requires_auth` true, which is the
    // precondition for the auth branch: the source's token resolves, a
    // login key is attached, and the streak is cleared.
    ctx.client_scopes = vec!["HeartBeats".to_string()];
    let period = Duration::from_millis(1);
    ctx.ping_interval = Some(tokio::time::interval(period));
    // Pretend a previous failure was in flight; a non-skipped attempt must
    // clear it.
    ctx.ping_retry_backoff = Some(Duration::from_secs(2));

    service.handle_ping_tick_arm(&mut ctx, &writer).await;

    let (msg, v2) = rx
        .try_recv()
        .expect("an authenticated tick must enqueue exactly one Ping");
    match msg {
        FrpMessage::Ping(p) => {
            assert!(
                p.privilege_key.is_some(),
                "token auth must attach a login key to the heartbeat"
            );
            assert!(p.timestamp.is_some());
        }
        other => panic!("expected Ping, got {other:?}"),
    }
    assert!(!v2, "the test ctx negotiates V1");
    assert!(
        ctx.ping_retry_backoff.is_none(),
        "a non-skipped attempt must end the failure streak"
    );
    assert!(
        rx.try_recv().is_err(),
        "one tick must enqueue exactly one message"
    );

    // Skip path: an auth config whose token cannot resolve makes
    // `try_generate_login_key` fail, so the tick is skipped rather than
    // tearing the session down.
    let mut service = test_service().await;
    {
        let mut auth = (*service.auth_cfg).clone();
        auth.token = String::new();
        service.auth_cfg = Arc::new(auth);
    }
    let (writer, mut rx) = test_control_writer_rx();
    let mut ctx = test_session_ctx();
    ctx.client_scopes = vec!["HeartBeats".to_string()];
    let period = Duration::from_millis(10);
    ctx.ping_interval = Some(tokio::time::interval(period));
    // `ping_retry_backoff` is already `None` from `test_session_ctx()`, so
    // the skip path below (which asserts it becomes `Some`) starts from a
    // clean streak without re-assigning the handler's own line.

    service.handle_ping_tick_arm(&mut ctx, &writer).await;

    assert!(
        rx.try_recv().is_err(),
        "a failed auth setup must skip the heartbeat, not send it"
    );
    assert_eq!(
        ctx.ping_retry_backoff,
        Some(period),
        "the skip path must record the (interval-capped) exponential backoff"
    );
    assert_eq!(
        ctx.ping_interval.as_ref().expect("interval armed").period(),
        period,
        "reset_after changes the next deadline, not the period"
    );
}

/// The extracted proxy-retry-tick arm, driven directly. No test drives the
/// retry timer's eligibility rules over a live `Service`, so this is the
/// direct lane for the three decisions the arm owns: a `StartErr` proxy
/// whose own anchor is older than `PROXY_RETRY_INTERVAL` is re-sent (and
/// moved to `WaitStart`, re-arming the WaitStart clock), a `StartErr` proxy
/// anchored just now is **not** re-sent, and a `WaitStart` proxy past
/// `WAIT_START_RETRY_TIMEOUT` is re-sent.
#[tokio::test]
async fn proxy_retry_tick_arm_retries_by_anchor_and_prunes_maps() {
    let service = test_service().await;
    // Two live proxies whose BARE names match the `user.`-prefixed runtime
    // map keys below: the retry candidate is looked up by stripped name,
    // so a config missing the bare name silently skips the re-send.
    let mk = |name: &str, local_port: u16| frp_core::config::ProxyConfig {
        name: name.to_string(),
        proxy_type: "tcp".to_string(),
        local_port,
        remote_port: 7001,
        enabled: true,
        ..Default::default()
    };
    let (p1, p2) = (mk("p1", 8080), mk("p2", 8081));
    *service.proxies.write().await = Arc::new(vec![p1.clone(), p2.clone()]);
    {
        let mut cfg = (*service.cfg.read().await).clone();
        cfg.proxies.push(p1);
        cfg.proxies.push(p2);
        *service.cfg.write().await = cfg;
    }
    {
        let mut map = service.proxy_info_map.write().await;
        map.insert("user.p1".to_string(), proxy_info(ProxyPhase::WaitStart));
        map.insert(
            "user.p2".to_string(),
            proxy_info(ProxyPhase::StartErr("port in use".to_string())),
        );
        map.insert(
            "user.p3".to_string(),
            proxy_info(ProxyPhase::StartErr("port in use".to_string())),
        );
    }

    let (writer, mut rx) = test_control_writer_rx();
    let mut ctx = test_session_ctx();
    ctx.cfg_user = "user".to_string();
    let mut interval = tokio::time::interval(Duration::from_millis(1));
    interval.tick().await; // skip the interval's immediate first tick
    ctx.proxy_retry_interval = Some(interval);
    // The WaitStart proxy's clock is old enough to be past
    // WAIT_START_RETRY_TIMEOUT + grace; p1 is not registered in
    // WaitStart, so p2/p3 carry the StartErr anchors.
    ctx.waitstart_seen.insert(
        "user.p1".to_string(),
        Instant::now() - Duration::from_secs(600),
    );
    let mut last_start_err: HashMap<String, Instant> = HashMap::new();
    let stale_anchor = Instant::now() - Duration::from_secs(600);
    let fresh_anchor = Instant::now();
    last_start_err.insert("user.p2".to_string(), stale_anchor);
    last_start_err.insert("user.p3".to_string(), fresh_anchor);

    service
        .handle_proxy_retry_tick_arm(&mut ctx, &writer, &mut last_start_err)
        .await;

    // Collect first: the valid `to_retry` list is filled from a `HashMap`
    // walk, so the two eligible proxies may be enqueued in either order.
    let mut sent: Vec<String> = Vec::new();
    while let Ok((msg, v2)) = rx.try_recv() {
        assert!(!v2, "the test ctx negotiates V1");
        match msg {
            FrpMessage::NewProxy(np) => {
                // `create_new_proxy_msg` strips `local_str` for Go frps
                // compatibility, so the local address travels through the
                // retry candidate, not through this field.
                assert!(np.local_str.is_none());
                sent.push(np.proxy_name);
            }
            other => panic!("expected NewProxy, got {other:?}"),
        }
    }
    sent.sort();
    assert_eq!(
        sent,
        vec!["user.p1".to_string(), "user.p2".to_string()],
        "the stuck WaitStart proxy and the StartErr proxy past its anchor \
         must be re-sent in one tick; the freshly-anchored StartErr proxy \
         must not"
    );

    {
        let map = service.proxy_info_map.read().await;
        assert_eq!(
            map.get("user.p1").expect("p1 present").phase,
            ProxyPhase::WaitStart
        );
        assert_eq!(
            map.get("user.p2").expect("p2 present").phase,
            ProxyPhase::WaitStart,
            "a retry send moves the proxy to WaitStart"
        );
        assert!(
            matches!(
                map.get("user.p3").expect("p3 present").phase,
                ProxyPhase::StartErr(_)
            ),
            "the freshly-anchored StartErr proxy keeps its phase"
        );
    }
    assert!(
        ctx.waitstart_seen.contains_key("user.p1"),
        "p1's WaitStart clock must be re-armed at the retry send"
    );
    // The prune pass runs before the sends, so p2 is still in StartErr
    // when it runs and its anchor survives it. That anchor is NOT re-armed
    // by the retry send: `waitstart_seen` is re-armed (the WaitStart clock
    // above), while a `last_start_err` entry is only ever written by the
    // `NewProxyResp` error path. The stale anchor is what made p2 eligible
    // and the entry is left exactly as it was.
    assert_eq!(
        last_start_err.get("user.p2").copied(),
        Some(stale_anchor),
        "the retry send must not rewrite the StartErr anchor"
    );
    assert_eq!(
        last_start_err.get("user.p3").copied(),
        Some(fresh_anchor),
        "the still-StartErr proxy keeps its original anchor"
    );
}
/// The extracted `xtcp_cleanup` arm, driven directly. No lane puts a
/// cleanup key on the channel to a client `Service`, so this is the direct
/// witness for the reclaim rule the arm owns: the key is removed from
/// **both** NAT-hole maps (the provider `sid` and the visitor txn_id
/// namespaces are independent, which is what makes the one lookup correct
/// for either), unrelated keys are untouched, and an absent key is a
/// silent no-op.
#[tokio::test]
async fn xtcp_cleanup_arm_reclaims_both_nat_hole_maps() {
    let service = test_service().await;
    let mut ctx = test_session_ctx();
    ctx.pending_xtcp
        .insert("sid-a".to_string(), "user.p1".to_string());
    let (visitor_tx, _visitor_rx) = oneshot::channel::<Result<msg::NatHoleResp, String>>();
    ctx.visitor_pending.insert("sid-a".to_string(), visitor_tx);
    ctx.pending_xtcp
        .insert("txn-b".to_string(), "user.p2".to_string());
    let (visitor_tx_b, _visitor_rx_b) = oneshot::channel::<Result<msg::NatHoleResp, String>>();
    ctx.visitor_pending
        .insert("txn-b".to_string(), visitor_tx_b);

    service
        .handle_xtcp_cleanup_arm("sid-a".to_string(), &mut ctx)
        .await;
    assert!(
        !ctx.pending_xtcp.contains_key("sid-a") && !ctx.visitor_pending.contains_key("sid-a"),
        "the reclaimed key must leave the provider and the visitor map"
    );
    assert!(
        ctx.pending_xtcp.contains_key("txn-b") && ctx.visitor_pending.contains_key("txn-b"),
        "an unrelated key must be left alone"
    );

    service
        .handle_xtcp_cleanup_arm("txn-b".to_string(), &mut ctx)
        .await;
    assert!(
        !ctx.pending_xtcp.contains_key("txn-b") && !ctx.visitor_pending.contains_key("txn-b"),
        "the visitor txn_id namespace is reclaimed by the same lookup"
    );

    service
        .handle_xtcp_cleanup_arm("absent".to_string(), &mut ctx)
        .await;
    assert!(
        ctx.pending_xtcp.is_empty() && ctx.visitor_pending.is_empty(),
        "an absent key must be a no-op"
    );
}

/// The extracted STUN-result arm, driven directly. This arm owns the
/// provider write, the `pending_xtcp` bookkeeping and the defensive 15s
/// cleanup spawn; its input's producer is the off-loop STUN task, which the
/// XTCP-notify test below drives for real.
#[tokio::test(start_paused = true)]
async fn stun_result_arm_writes_client_and_reclaims_socket_on_write_failure() {
    let service = test_service().await;
    let mut ctx = test_session_ctx();
    let (writer, mut written) = test_control_writer_rx();
    let (cleanup_tx, mut cleanup_rx) = mpsc::channel::<String>(4);

    // Success path: the `NatHoleClient` is enqueued on the control writer
    // and the sid is tracked for `NatHoleResp` routing.
    let probe = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind a STUN probe socket");
    ctx.xtcp_sockets
        .lock()
        .await
        .insert("s-ok".to_string(), Arc::new(probe));
    service
        .handle_stun_result_arm(
            StunResult {
                sid: "s-ok".to_string(),
                proxy_name: "user.p1".to_string(),
                msg: FrpMessage::NatHoleClient(Box::new(msg::NatHoleClient {
                    transaction_id: "txn-1".to_string(),
                    proxy_name: "user.p1".to_string(),
                    sid: Some("s-ok".to_string()),
                    protocol: Some("kcp".to_string()),
                    mapped_addrs: None,
                    assisted_addrs: None,
                    visitor_addr: None,
                })),
            },
            &mut ctx,
            &writer,
            &cleanup_tx,
        )
        .await;
    let (frame, v2) = written
        .try_recv()
        .expect("a successful write must enqueue the NatHoleClient");
    assert!(!v2, "the test ctx negotiates V1");
    assert!(matches!(frame, FrpMessage::NatHoleClient(_)));
    assert_eq!(
        ctx.pending_xtcp.get("s-ok").map(String::as_str),
        Some("user.p1"),
        "the success path tracks sid -> proxy_name for NatHoleResp routing"
    );
    assert!(
        ctx.xtcp_sockets.lock().await.contains_key("s-ok"),
        "the write itself must not reclaim the socket"
    );
    // The success branch spawned the arm's defensive cleanup task. With the
    // clock paused, waiting on the channel advances time to its 15s
    // deadline, so the assertion is on the task's real effect rather than
    // on a sleep: the socket is reclaimed and the sid is handed to the
    // cleanup arm.
    let cleaned = tokio::time::timeout(Duration::from_secs(60), cleanup_rx.recv())
        .await
        .expect("the success branch must spawn the defensive cleanup task")
        .expect("cleanup_tx is still held by this test");
    assert_eq!(
        cleaned, "s-ok",
        "the spawned cleanup task must hand the sid back after the NAT window"
    );
    assert!(
        !ctx.xtcp_sockets.lock().await.contains_key("s-ok"),
        "the cleanup task must reclaim the persisted socket"
    );

    // Failure path: nothing is enqueued, no pending entry is created, and
    // the socket the STUN task stored is reclaimed immediately — it would
    // otherwise sit until control-loop teardown.
    let probe2 = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind a second STUN probe socket");
    ctx.xtcp_sockets
        .lock()
        .await
        .insert("s-fail".to_string(), Arc::new(probe2));
    writer
        .failed
        .store(true, std::sync::atomic::Ordering::SeqCst);
    service
        .handle_stun_result_arm(
            StunResult {
                sid: "s-fail".to_string(),
                proxy_name: "user.p2".to_string(),
                msg: FrpMessage::NatHoleClient(Box::new(msg::NatHoleClient {
                    transaction_id: "txn-2".to_string(),
                    proxy_name: "user.p2".to_string(),
                    sid: Some("s-fail".to_string()),
                    protocol: Some("kcp".to_string()),
                    mapped_addrs: None,
                    assisted_addrs: None,
                    visitor_addr: None,
                })),
            },
            &mut ctx,
            &writer,
            &cleanup_tx,
        )
        .await;
    assert!(
        written.try_recv().is_err(),
        "a failed control write must enqueue nothing"
    );
    assert!(
        !ctx.xtcp_sockets.lock().await.contains_key("s-fail"),
        "the socket of a failed NatHoleClient send must not leak"
    );
    assert!(
        !ctx.pending_xtcp.contains_key("s-fail"),
        "the failure path must not create a pending_xtcp entry"
    );
}

/// The extracted XTCP-notify arm, driven directly against a loopback STUN
/// responder. This is the arm that **spawns**, so the test is built to
/// witness the split rather than the code text: the handler must return
/// with the result not yet produced (the message loop cannot stall for the
/// STUN round-trips), the spawned task must persist the STUN socket under
/// the sid, and the finished `NatHoleClient` must come back on
/// `stun_result_tx` for the loop to write — the write-before-`NatHoleResp`
/// ordering the arm's comment relies on.
///
/// The responder is the minimal RFC 5389 shape of the integration lane's
/// (`frp-client/tests/xtcp_pair_e2e.rs`, `run_mock_stun_server`): it echoes
/// the request txid and reports the OBSERVED SOURCE as MAPPED-ADDRESS, with
/// no OTHER-ADDRESS, so the arm's second probe re-queries this same server.
/// A unit test cannot import an integration test's module, so this copy is
/// the only way to drive the spawned STUN task directly.
#[tokio::test]
async fn xtcp_notify_arm_spawns_stun_and_hands_back_nat_hole_client() {
    // Written with `while let` + nested `if let` rather than the
    // integration lane's early-return-on-invalid shape, so this test adds
    // no loop-continue token: the file's executable-continue census stays
    // 0 (group C removed the last one) and its only textual hit stays the
    // ping handler's doc prose.
    async fn responder(socket: tokio::net::UdpSocket) {
        let mut buf = vec![0u8; 512];
        while let Ok((n, src)) = socket.recv_from(&mut buf).await {
            if n >= 20
                && u16::from_be_bytes([buf[0], buf[1]]) == 0x0001
                && buf[4..8] == 0x2112_A442u32.to_be_bytes()
            {
                if let std::net::IpAddr::V4(ip) = src.ip() {
                    let mut resp = Vec::with_capacity(32);
                    resp.extend_from_slice(&0x0101u16.to_be_bytes());
                    resp.extend_from_slice(&12u16.to_be_bytes());
                    resp.extend_from_slice(&0x2112_A442u32.to_be_bytes());
                    resp.extend_from_slice(&buf[8..20]);
                    resp.extend_from_slice(&0x0001u16.to_be_bytes());
                    resp.extend_from_slice(&8u16.to_be_bytes());
                    resp.push(0x00);
                    resp.push(0x01);
                    resp.extend_from_slice(&src.port().to_be_bytes());
                    resp.extend_from_slice(&ip.octets());
                    let _ = socket.send_to(&resp, src).await;
                }
            }
        }
    }

    let service = test_service().await;
    let mut ctx = test_session_ctx();
    let (stun_tx, mut stun_rx) = mpsc::channel::<StunResult>(4);
    ctx.stun_result_tx = Some(stun_tx);

    let stun_socket = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind the mock STUN responder");
    let stun_server = stun_socket
        .local_addr()
        .expect("responder addr")
        .to_string();
    let _responder = tokio::spawn(responder(stun_socket));

    // `SessionChannels` borrows its receivers, so the literal is built here
    // rather than returned from a helper.
    let (_health_tx, mut health_rx) = mpsc::channel::<HealthEvent>(1);
    let (_reload_tx, mut reload_rx) = mpsc::channel::<ReloadRequest>(1);
    let (_xtcp_tx, mut xtcp_rx) = mpsc::channel::<XtcpNotification>(1);
    let (_visitor_tx, mut visitor_rx) = mpsc::channel::<VisitorRequest>(1);
    let stop = CancellationToken::new();
    let health_cancels = Arc::new(Mutex::new(HashMap::new()));
    let channels = SessionChannels {
        health_rx: &mut health_rx,
        reload_rx: &mut reload_rx,
        xtcp_rx: &mut xtcp_rx,
        visitor_rx: &mut visitor_rx,
        stop: &stop,
        health_cancels: &health_cancels,
        nat_hole_stun_server: &stun_server,
    };

    service
        .handle_xtcp_notify_arm(
            XtcpNotification {
                sid: "sid-1".to_string(),
                proxy_name: "user.p1".to_string(),
            },
            &mut ctx,
            &channels,
        )
        .await;
    // The spawn/await split, witnessed: on a current-thread runtime the
    // spawned STUN task cannot have run yet (the handler body has no
    // yield point of its own), so a result already here would mean the arm
    // did the STUN inline and blocked the message loop.
    assert!(
        stun_rx.try_recv().is_err(),
        "the STUN work must be spawned off-loop, not awaited by the handler"
    );

    let stun = tokio::time::timeout(Duration::from_secs(10), stun_rx.recv())
        .await
        .expect("the spawned STUN task must hand a result back within 10s")
        .expect("stun_result_tx is still held by this test");
    assert_eq!(stun.sid, "sid-1");
    assert_eq!(stun.proxy_name, "user.p1");
    match stun.msg {
        FrpMessage::NatHoleClient(nhc) => {
            assert_eq!(nhc.proxy_name, "user.p1");
            assert_eq!(nhc.sid.as_deref(), Some("sid-1"));
            assert_eq!(
                nhc.protocol.as_deref(),
                Some("kcp"),
                "Go frp v0.70 compat: the provider announces protocol \"kcp\""
            );
            // frp-client forwards `frp-core/stun` from its `kcp` and
            // `vnet` features; in a shape with neither, `frp_core::stun`
            // is the stub that errors without touching the network, so
            // the arm stores no socket and builds the message with no
            // mapped address. Both shapes are asserted, and `cfg!` is the
            // compiled truth: if it ever disagrees with what the arm
            // actually did (a forwarding change in either direction),
            // this test reds instead of skipping.
            if cfg!(any(feature = "kcp", feature = "vnet")) {
                let mapped = nhc
                    .mapped_addrs
                    .expect("both STUN probes must report a mapped address");
                assert_eq!(
                    mapped.len(),
                    2,
                    "no OTHER-ADDRESS in the response -> the second probe re-queries the same server"
                );
                // The persisted socket is the one the probes ran on, so the
                // mapped port must equal its bound port.
                let sockets = ctx.xtcp_sockets.lock().await;
                let persisted = sockets
                    .get("sid-1")
                    .expect("the STUN socket must be persisted under the sid");
                let local_port = persisted.local_addr().expect("bound").port();
                assert_eq!(mapped[0], format!("127.0.0.1:{local_port}"));
                assert_eq!(mapped[1], format!("127.0.0.1:{local_port}"));
            } else {
                assert!(
                    nhc.mapped_addrs.is_none(),
                    "without frp-core/stun the probe fails, so no mapped address may be reported"
                );
                assert!(
                    ctx.xtcp_sockets.lock().await.is_empty(),
                    "a failed probe must not persist a socket"
                );
            }
        }
        other => panic!("expected NatHoleClient, got {other:?}"),
    }
    assert!(
        !ctx.pending_xtcp.contains_key("sid-1"),
        "pending_xtcp is the STUN-result arm's bookkeeping, not this arm's"
    );
}

/// The extracted health-event arm, driven directly for both events over a
/// real `Service` — the arm is channel-driven, and no test puts a
/// `HealthEvent` through a live session's `health_rx`. `Close` is witnessed
/// by the three effects the arm owns (P2P bridge token cancelled, phase
/// moved to `CheckFailed`, `CloseProxy` enqueued) and `Recover` by the
/// `NewProxy` it rebuilds from the stored config plus the `WaitStart` phase
/// the `NewProxyResp` handler completes; a `Recover` with no stored config
/// must send nothing.
#[tokio::test]
async fn health_event_arm_cancels_bridge_and_reregisters() {
    let service = test_service().await;
    let mut ctx = test_session_ctx();
    // The health-check tasks and `health_proxy_configs` are keyed by the
    // WIRE proxy name, so the prefix must be live for the re-registration
    // to rebuild the same name.
    ctx.cfg_user = "user".to_string();
    let (writer, mut written) = test_control_writer_rx();

    let token = CancellationToken::new();
    service
        .p2p_bridge_tokens
        .lock()
        .await
        .insert("user.p1".to_string(), token.clone());
    {
        let mut map = service.proxy_info_map.write().await;
        map.insert("user.p1".to_string(), proxy_info(ProxyPhase::Running));
        map.insert(
            "user.p2".to_string(),
            ProxyRuntimeInfo {
                local_addr: "127.0.0.1:9009".to_string(),
                ..proxy_info(ProxyPhase::Running)
            },
        );
    }
    // Only p2 has a stored config; p3 is the no-config branch.
    service.health_proxy_configs.lock().await.insert(
        "user.p2".to_string(),
        frp_core::config::ProxyConfig {
            name: "p2".to_string(),
            proxy_type: "tcp".to_string(),
            local_ip: "127.0.0.1".to_string(),
            local_port: 9001,
            ..Default::default()
        },
    );

    // Close: cancel the bridge token, mark CheckFailed, send CloseProxy.
    service
        .handle_health_event_arm(HealthEvent::Close("user.p1".to_string()), &mut ctx, &writer)
        .await;
    assert!(
        token.is_cancelled(),
        "health Close must cancel the proxy's P2P bridge token"
    );
    assert!(
        matches!(
            service
                .proxy_info_map
                .read()
                .await
                .get("user.p1")
                .map(|i| &i.phase),
            Some(ProxyPhase::CheckFailed)
        ),
        "health Close must mark the proxy CheckFailed before the send"
    );
    match written
        .try_recv()
        .expect("health Close must enqueue CloseProxy")
    {
        (FrpMessage::CloseProxy(cp), v2) => {
            assert_eq!(cp.proxy_name, "user.p1");
            assert!(!v2, "the test ctx negotiates V1");
        }
        other => panic!("expected CloseProxy, got {other:?}"),
    }
    assert!(written.try_recv().is_err(), "exactly one control message");

    // Recover: the stored config is re-registered from the map's local
    // address, and the phase waits for NewProxyResp.
    service
        .handle_health_event_arm(
            HealthEvent::Recover("user.p2".to_string()),
            &mut ctx,
            &writer,
        )
        .await;
    match written
        .try_recv()
        .expect("health Recover must re-send NewProxy")
    {
        (FrpMessage::NewProxy(np), v2) => {
            assert_eq!(np.proxy_name, "user.p2");
            // `local_str` is stripped by `create_new_proxy_msg` for Go frps
            // parity, so which local address the arm chose (the live
            // `proxy_info_map` entry above, not the config fallback) is not
            // observable from the message; the send, name, type and phase
            // are.
            assert!(
                np.local_str.is_none(),
                "create_new_proxy_msg strips local_str for Go frps parity"
            );
            assert_eq!(np.proxy_type, "tcp");
            assert!(!v2, "the test ctx negotiates V1");
        }
        other => panic!("expected NewProxy, got {other:?}"),
    }
    assert!(
        matches!(
            service
                .proxy_info_map
                .read()
                .await
                .get("user.p2")
                .map(|i| &i.phase),
            Some(ProxyPhase::WaitStart)
        ),
        "health Recover must move the proxy to WaitStart"
    );

    // Recover with no stored config: warn only, nothing on the wire.
    service
        .handle_health_event_arm(
            HealthEvent::Recover("user.p3".to_string()),
            &mut ctx,
            &writer,
        )
        .await;
    assert!(
        written.try_recv().is_err(),
        "a Recover without a stored config must send nothing"
    );
    assert!(
        !service.proxy_info_map.read().await.contains_key("user.p3"),
        "the no-config branch must not create a proxy entry"
    );
}

/// The extracted visitor-request arm, driven directly over a real
/// `Service`. This arm **spawns**, so the test witnesses the split rather
/// than the code text: the handler returns with the 20 s cleanup not yet
/// fired (the clock is paused), and advancing the clock fires the spawned
/// task, which hands the txn id back on the loop-owned `xtcp_cleanup_tx`.
/// The failure branch must complete the request's oneshot with the error
/// and record nothing.
#[tokio::test(start_paused = true)]
async fn visitor_request_arm_sends_and_arms_spawned_cleanup() {
    let service = test_service().await;
    let mut ctx = test_session_ctx();
    let (writer, mut written) = test_control_writer_rx();
    let (cleanup_tx, mut cleanup_rx) = mpsc::channel::<String>(4);

    let (reply_tx, mut reply_rx) = oneshot::channel::<Result<msg::NatHoleResp, String>>();
    service
        .handle_visitor_request_arm(
            VisitorRequest {
                nhv: msg::NatHoleVisitor {
                    transaction_id: "txn-1".to_string(),
                    proxy_name: "user.p1".to_string(),
                    ..Default::default()
                },
                reply: reply_tx,
            },
            &mut ctx,
            &writer,
            &cleanup_tx,
        )
        .await;
    let (frame, v2) = written
        .try_recv()
        .expect("a successful send must enqueue the NatHoleVisitor");
    assert!(!v2, "the test ctx negotiates V1");
    match frame {
        FrpMessage::NatHoleVisitor(nhv) => {
            assert_eq!(nhv.transaction_id, "txn-1");
            assert_eq!(nhv.proxy_name, "user.p1");
        }
        other => panic!("expected NatHoleVisitor, got {other:?}"),
    }
    assert!(written.try_recv().is_err(), "exactly one control message");
    assert!(
        ctx.visitor_pending.contains_key("txn-1"),
        "the success path records the txn for the NatHoleResp arm"
    );
    assert!(
        reply_rx.try_recv().is_err(),
        "the success path leaves the reply for the NatHoleResp arm"
    );
    // The 20 s cleanup must be off-loop: the handler body has no yield
    // point of its own, so on this current-thread runtime the spawned task
    // cannot have run yet, and with the clock paused its sleep has not
    // fired. If the arm awaited the sleep inline it would have
    // auto-advanced the paused clock and delivered the key before
    // returning, which this assertion catches.
    assert!(
        cleanup_rx.try_recv().is_err(),
        "the cleanup must be spawned off-loop, not awaited by the handler"
    );
    // Let the spawned task reach its sleep, then move the clock past the
    // 20 s deadline so the assertion is on the task's real effect.
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_secs(20)).await;
    let cleaned = tokio::time::timeout(Duration::from_secs(5), cleanup_rx.recv())
        .await
        .expect("the spawned 20s cleanup must hand the txn id back")
        .expect("cleanup_tx is still held by this test");
    assert_eq!(cleaned, "txn-1");

    // Failure path: a failed writer enqueues nothing, records nothing and
    // completes the request's oneshot with the error.
    let (writer2, mut written2) = test_control_writer_rx();
    writer2
        .failed
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let (reply_tx2, reply_rx2) = oneshot::channel::<Result<msg::NatHoleResp, String>>();
    service
        .handle_visitor_request_arm(
            VisitorRequest {
                nhv: msg::NatHoleVisitor {
                    transaction_id: "txn-2".to_string(),
                    proxy_name: "user.p2".to_string(),
                    ..Default::default()
                },
                reply: reply_tx2,
            },
            &mut ctx,
            &writer2,
            &cleanup_tx,
        )
        .await;
    assert!(
        written2.try_recv().is_err(),
        "a failed control send must enqueue nothing"
    );
    assert!(
        !ctx.visitor_pending.contains_key("txn-2"),
        "the failure path must not record the txn"
    );
    let err = reply_rx2
        .await
        .expect("the failure path must complete the reply")
        .expect_err("the reply must carry the send error");
    assert!(
        err.starts_with("send failed:"),
        "unexpected error text: {err}"
    );
}
