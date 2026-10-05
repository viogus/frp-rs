use super::*;
#[cfg(all(feature = "vnet", test))]
use tokio::sync::watch;
// register_vnet_tun and vnet_tun_cidr are used only by vnet tests, so their
// imports are test-cfg'd to keep plain builds warning-free.
#[cfg(all(feature = "vnet", test))]
use crate::vnet::{register_vnet_tun, vnet_tun_cidr};

/// A `ControlWriter` wired to a live (never-polled) channel, for tests
/// that only exercise map/lifecycle logic without delivering messages.
#[cfg(feature = "vnet")]
fn test_control_writer() -> Arc<ControlWriter> {
    let (writer, mut rx) = test_control_writer_rx();
    // Drain instead of dropping rx so `send` in the code under test
    // succeeds (drop would make it fail with Closed).
    tokio::spawn(async move { while rx.recv().await.is_some() {} });
    writer
}

/// Like [`test_control_writer`], but keeps the receiver so the test can
/// assert on the messages enqueued by the code under test. Not gated on
/// vnet: the XTCP punch-path tests use it to assert that a dead proxy
/// enqueues nothing on the control channel.
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

#[test]
fn heartbeat_auth_scope_unions_client_and_server_requirements() {
    let heartbeat = vec!["HeartBeats".to_string()];
    let unrelated = vec!["NewWorkConns".to_string()];

    assert!(crate::backoff::heartbeat_requires_auth(&heartbeat, &[]));
    assert!(crate::backoff::heartbeat_requires_auth(&[], &heartbeat));
    assert!(!crate::backoff::heartbeat_requires_auth(&unrelated, &[]));
    assert!(!crate::backoff::heartbeat_requires_auth(&[], &unrelated));
}

#[test]
fn heartbeat_ping_backoff_progression() {
    // Mirror of the Go v0.71.0 client heartbeat backoff
    // (client/control.go heartbeatWorker, wait.FastBackoffOptions
    // InitDurationIfFail=1s Factor=2 MaxDuration=heartbeat interval):
    // the FIRST consecutive failure re-arms at InitDurationIfFail ×
    // Factor = 2s (fastBackoffImpl doubles the init too), then the
    // delay doubles per consecutive failure, capped at the interval.
    //
    // This is the ONE place the literal 2s is allowed to appear. It pins
    // the value of `PING_FIRST_BACKOFF`, which is what the production call
    // site and the e2e re-arm oracle both read: without this comparison a
    // drift in the constant would be silently agreed to by all three
    // (TODO.md:9675).
    assert_eq!(
        PING_FIRST_BACKOFF,
        Duration::from_secs(2),
        "Go parity: InitDurationIfFail(1s) x Factor(2) is the first re-arm delay"
    );
    let interval = Duration::from_secs(10);
    assert_eq!(
        next_ping_backoff(None, interval),
        PING_FIRST_BACKOFF,
        "first failure of a streak re-arms at InitDurationIfFail(1s) x Factor(2)"
    );
    assert_eq!(
        next_ping_backoff(Some(PING_FIRST_BACKOFF), interval),
        Duration::from_secs(4)
    );
    assert_eq!(
        next_ping_backoff(Some(Duration::from_secs(4)), interval),
        Duration::from_secs(8)
    );
    // 16s would be the next doubling — capped at the interval so a long
    // outage still probes at most every heartbeat_interval.
    assert_eq!(
        next_ping_backoff(Some(Duration::from_secs(8)), interval),
        interval
    );
    assert_eq!(
        next_ping_backoff(Some(interval), interval),
        interval,
        "cap holds at the interval"
    );
    // An interval shorter than the 2s init caps the very first retry
    // (Go's MaxDuration clamp behaves identically).
    let small = Duration::from_millis(500);
    assert_eq!(next_ping_backoff(None, small), small);
    // A success ends the streak (the ping arm clears the state): the
    // next failure restarts at 2s again.
    assert_eq!(next_ping_backoff(None, interval), PING_FIRST_BACKOFF);
}

#[cfg(feature = "vnet")]
#[test]
fn virtual_net_visitor_route_advertisement() {
    use frp_core::config::VisitorPluginConfig;

    let visitor = frp_core::config::VisitorConfig {
        name: "vnet-visitor".into(),
        visitor_type: "stcp".into(),
        server_name: "vnet-server".into(),
        bind_port: -1,
        plugin: Some(VisitorPluginConfig {
            plugin_type: "virtual_net".into(),
            destination_ip: "100.86.0.1".into(),
            ..Default::default()
        }),
        ..Default::default()
    };
    let adv = virtual_net_visitor_route_adv(&visitor).expect("route advertisement");
    assert_eq!(adv.proxy_name, "vnet-visitor");
    assert_eq!(adv.subnet, "100.86.0.1/32");
    assert_eq!(adv.virtual_net, None);

    // Non-virtual-net plugins and invalid IPs produce no advertisement.
    let plain = frp_core::config::VisitorConfig {
        name: "plain".into(),
        plugin: Some(VisitorPluginConfig {
            plugin_type: "other".into(),
            destination_ip: "100.86.0.1".into(),
            ..Default::default()
        }),
        ..Default::default()
    };
    assert!(virtual_net_visitor_route_adv(&plain).is_none());

    let bad_ip = frp_core::config::VisitorConfig {
        name: "bad".into(),
        plugin: Some(VisitorPluginConfig {
            plugin_type: "virtual_net".into(),
            destination_ip: "not-an-ip".into(),
            ..Default::default()
        }),
        ..Default::default()
    };
    assert!(virtual_net_visitor_route_adv(&bad_ip).is_none());

    // IPv6 destinations advertise a /128 host route.
    let v6 = frp_core::config::VisitorConfig {
        name: "v6".into(),
        plugin: Some(VisitorPluginConfig {
            plugin_type: "virtual_net".into(),
            destination_ip: "2001:db8::1".into(),
            ..Default::default()
        }),
        ..Default::default()
    };
    let adv6 = virtual_net_visitor_route_adv(&v6).expect("IPv6 route advertisement");
    assert_eq!(adv6.proxy_name, "v6");
    assert_eq!(adv6.subnet, "2001:db8::1/128");
    // VnetRouteRemove is keyed only by proxy name, so the same advertisement
    // can be converted for both IPv4 and IPv6 destinations.
    let _remove = msg::VnetRouteRemove {
        proxy_name: adv6.proxy_name,
        virtual_net: adv6.virtual_net,
    };
}

#[test]
fn stable_sessions_do_not_reset_backoff_escalation() {
    // Go frp v0.70.1's fastBackoffImpl resets only when the retry callback
    // reports success; keepControllerWorking always reports an error after a
    // session closes, so escalation continues regardless of session length.
    // With full multiplicative jitter a single sample can land below the
    // previous level, so escalation is asserted on the mean over samples.
    let mut errors = 0;
    let mut retries = Vec::new();
    let fast_delays = (0..3)
        .map(|_| {
            crate::backoff::reconnect_delay_after_session(
                &mut errors,
                &mut retries,
                std::time::Duration::ZERO,
            )
        })
        .collect::<Vec<_>>();
    // Phase 1 stays sub-second (100-300ms).
    assert!(fast_delays
        .iter()
        .all(|delay| *delay < Duration::from_secs(1)));
    fn mean_level(consecutive: u32, window: u32, prev_secs: u64) -> f64 {
        (0..200)
            .map(|_| {
                crate::backoff::fast_backoff_delay(
                    consecutive,
                    window,
                    std::time::Duration::from_secs(prev_secs),
                )
                .as_millis() as f64
            })
            .sum::<f64>()
            / 200.0
    }
    let m4 = mean_level(4, 4, 8); // phase 2, 16s anchored from 8s
    let m5 = mean_level(5, 5, 16); // phase 2, 20s capped
    assert!(m5 > m4, "phase-2 mean should escalate: {m5} > {m4}");
    assert_eq!(errors, 3);
}

#[test]
fn fast_backoff_delay_phase1_fast_retry() {
    // First 3 retries (counts_in_fast_retry_window <= 3) use
    // 200ms × full jitter (0.5-1.5) → 100ms-300ms.
    for i in 1..=3u32 {
        for _ in 0..100 {
            let delay = crate::backoff::fast_backoff_delay(i, i, std::time::Duration::ZERO);
            let ms = delay.as_millis();
            assert!(ms >= 100, "delay {ms}ms too low for fast retry {i}");
            assert!(ms <= 300, "delay {ms}ms too high for fast retry {i}");
        }
    }
}

#[test]
fn fast_backoff_delay_phase2_base_first() {
    // After fast retries (counts_in_fast_retry_window > 3), consecutive_err_count=1
    // Go frp: InitDurationIfFail(1s) * Factor(2) = 2s × jitter (±10%)
    // -> 1800-2200ms
    for _ in 0..100 {
        let delay = crate::backoff::fast_backoff_delay(1, 4, std::time::Duration::ZERO);
        let ms = delay.as_millis();
        assert!(ms >= 1800, "delay {ms}ms below 1.8s for phase2 first");
        assert!(ms <= 2200, "delay {ms}ms above 2.2s for phase2 first");
    }
}

#[test]
fn fast_backoff_delay_phase2_exponential() {
    // Anchored to the PREVIOUS actual delay (Go fastBackoffImpl):
    // previous ≈ 8s × Factor(2) ± 10% → 14.4-17.6s (capped at 20s).
    for _ in 0..100 {
        let delay = crate::backoff::fast_backoff_delay(4, 5, std::time::Duration::from_secs(8));
        let ms = delay.as_millis();
        assert!(ms >= 14000, "delay {ms}ms below 14s for prev=8s");
        assert!(ms <= 20000, "delay {ms}ms above 20s cap");
    }
}

#[test]
fn fast_backoff_delay_phase2_caps_at_20s() {
    // A previous delay near the cap stays capped at 20s.
    for _ in 0..100 {
        let delay = crate::backoff::fast_backoff_delay(20, 20, std::time::Duration::from_secs(20));
        let ms = delay.as_millis();
        assert!(ms <= 20000, "delay {ms}ms above 20s cap");
    }
}

#[test]
fn fast_backoff_delay_monotonic_in_mean() {
    // Anchored mean grows with each retry.
    fn chained_delays(count: u32) -> f64 {
        let mut prev = std::time::Duration::ZERO;
        let mut sum = 0.0;
        for c in 1..=count {
            let d = crate::backoff::fast_backoff_delay(c, 10, prev);
            sum += d.as_millis() as f64;
            prev = d;
        }
        sum / count as f64
    }
    // Simulate one run per count: average of the first N chained delays
    // must grow as N grows (cap flattens the tail).
    let m1 = chained_delays(1); // ~2s
    let m2 = chained_delays(2); // ~(2s+4s)/2
    let m6 = chained_delays(6); // grows toward 20s cap
    assert!(m2 > m1, "mean delay should grow: {m2} > {m1}");
    assert!(m6 > m2, "mean delay should grow: {m6} > {m2}");
}

#[cfg(feature = "vnet")]
#[test]
fn vnet_tun_params_and_cidr_for_plugin_and_vnet_proxies() {
    let plugin = frp_core::config::ProxyConfig {
        name: "plugin".into(),
        proxy_type: "tcp".into(),
        plugin: Some(frp_core::config::PluginConfig {
            plugin_type: "virtual_net".into(),
            ..Default::default()
        }),
        ..Default::default()
    };
    let (ip, netmask, mtu) = vnet_tun_params(&plugin, "10.0.0.1").expect("plugin TUN params");
    assert_eq!(ip, "10.0.0.1".parse::<std::net::Ipv4Addr>().unwrap());
    assert_eq!(
        netmask,
        "255.255.255.0".parse::<std::net::Ipv4Addr>().unwrap()
    );
    assert_eq!(mtu, 1420);
    assert_eq!(
        vnet_tun_cidr(&plugin, "10.0.0.1").as_deref(),
        Some("10.0.0.0/24")
    );

    let vnet = frp_core::config::ProxyConfig {
        name: "vnet".into(),
        proxy_type: "vnet".into(),
        vnet_ip: "10.1.2.3".into(),
        vnet_netmask: "255.255.0.0".into(),
        vnet_mtu: 1400,
        ..Default::default()
    };
    let (ip, netmask, mtu) = vnet_tun_params(&vnet, "").expect("vnet TUN params");
    assert_eq!(ip, "10.1.2.3".parse::<std::net::Ipv4Addr>().unwrap());
    assert_eq!(
        netmask,
        "255.255.0.0".parse::<std::net::Ipv4Addr>().unwrap()
    );
    assert_eq!(mtu, 1400);
    assert_eq!(vnet_tun_cidr(&vnet, "").as_deref(), Some("10.1.0.0/16"));
    assert!(vnet_tun_params(&vnet, "").is_some());
}

#[cfg(feature = "vnet")]
#[test]
fn vnet_proxy_snapshot_detects_tun_only_changes() {
    let base = frp_core::config::ProxyConfig {
        name: "vnet".into(),
        proxy_type: "vnet".into(),
        vnet_ip: "10.0.0.1".into(),
        vnet_netmask: "255.255.255.0".into(),
        ..Default::default()
    };
    let changed_ip = frp_core::config::ProxyConfig {
        vnet_ip: "10.0.0.2".into(),
        ..base.clone()
    };
    assert_ne!(vnet_proxy_snapshot(&base), vnet_proxy_snapshot(&changed_ip));
}

#[test]
fn filter_active_visitors_honors_start_allowlist_and_enabled() {
    let cfg = frp_core::config::ClientConfig {
        start: vec!["v1".into()],
        ..Default::default()
    };
    let visitors = vec![
        frp_core::config::VisitorConfig {
            name: "v1".into(),
            visitor_type: "stcp".into(),
            ..Default::default()
        },
        frp_core::config::VisitorConfig {
            name: "v2".into(),
            visitor_type: "stcp".into(),
            ..Default::default()
        },
        frp_core::config::VisitorConfig {
            name: "v3".into(),
            visitor_type: "stcp".into(),
            enabled: false,
            ..Default::default()
        },
    ];

    let active = filter_active_visitors(&cfg, &visitors);
    let names: Vec<&str> = active.iter().map(|v| v.name.as_str()).collect();
    assert_eq!(names, vec!["v1"], "start allowlist must filter visitors");

    let all = filter_active_visitors(&frp_core::config::ClientConfig::default(), &visitors);
    let names: Vec<&str> = all.iter().map(|v| v.name.as_str()).collect();
    assert_eq!(names, vec!["v1", "v2"], "disabled visitors stay filtered");
}

#[cfg(feature = "vnet")]
struct FakeTun {
    inner: tokio::io::DuplexStream,
    configured: Arc<std::sync::atomic::AtomicBool>,
}

#[cfg(feature = "vnet")]
impl tokio::io::AsyncRead for FakeTun {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

#[cfg(feature = "vnet")]
impl tokio::io::AsyncWrite for FakeTun {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(feature = "vnet")]
impl frp_vnet::tun::TunDevice for FakeTun {
    fn configure(
        &self,
        _addr: std::net::Ipv4Addr,
        _netmask: std::net::Ipv4Addr,
        _mtu: u16,
    ) -> anyhow::Result<()> {
        self.configured
            .store(true, std::sync::atomic::Ordering::Relaxed);
        Ok(())
    }

    fn name(&self) -> &str {
        "fake"
    }

    fn mtu(&self) -> u16 {
        1420
    }
}

#[cfg(feature = "vnet")]
fn fake_tun() -> (Box<FakeTun>, Arc<std::sync::atomic::AtomicBool>) {
    let configured = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let tun = Box::new(FakeTun {
        inner: tokio::io::duplex(4096).0,
        configured: configured.clone(),
    });
    (tun, configured)
}

#[cfg(feature = "vnet")]
#[tokio::test]
async fn register_and_remove_vnet_tun_updates_all_maps() {
    let tuns: VnetTunMap = Arc::new(Mutex::new(HashMap::new()));
    let tx: VnetTunTxMap = Arc::new(std::sync::Mutex::new(HashMap::new()));
    let cancels: VnetTunCancelMap = Arc::new(Mutex::new(HashMap::new()));
    let names = Arc::new(Mutex::new(HashMap::new()));
    let subnets = Arc::new(Mutex::new(HashMap::new()));
    let peer_routes = Arc::new(Mutex::new(HashMap::new()));
    let route_table = Arc::new(tokio::sync::RwLock::new(frp_vnet::router::RouteTable::new()));
    let writer = test_control_writer();
    let (tun, configured) = fake_tun();

    register_vnet_tun(
        &tuns,
        &names,
        "vnet-a",
        (
            "10.0.0.1".parse().unwrap(),
            "255.255.255.0".parse().unwrap(),
            1420,
        ),
        tun,
    )
    .await
    .unwrap();
    assert!(configured.load(std::sync::atomic::Ordering::Relaxed));
    assert!(tuns.lock().await.contains_key("vnet-a"));
    assert_eq!(
        names.lock().await.get("vnet-a").map(String::as_str),
        Some("fake")
    );

    route_table
        .write()
        .await
        .insert("corp-net", "vnet-a", "10.0.0.0/24")
        .unwrap();
    remove_vnet_tun(
        &tuns,
        &tx,
        &cancels,
        &names,
        &subnets,
        &route_table,
        &peer_routes,
        &writer,
        false,
        "vnet-a",
        "corp-net",
    )
    .await;
    assert!(tuns.lock().await.is_empty());
    assert!(tx.lock().unwrap().is_empty());
    assert!(cancels.lock().await.is_empty());
    assert!(names.lock().await.is_empty());
    assert!(subnets.lock().await.is_empty());
    assert!(route_table.read().await.is_empty());
}

#[cfg(feature = "vnet")]
#[tokio::test]
async fn reload_tun_controller_rebuilds_delivery_channel() {
    let tuns: VnetTunMap = Arc::new(Mutex::new(HashMap::new()));
    let tx_map: VnetTunTxMap = Arc::new(std::sync::Mutex::new(HashMap::new()));
    let cancels: VnetTunCancelMap = Arc::new(Mutex::new(HashMap::new()));
    let names = Arc::new(Mutex::new(HashMap::new()));
    let subnets = Arc::new(Mutex::new(HashMap::new()));
    let peer_routes = Arc::new(Mutex::new(HashMap::new()));
    let route_table = Arc::new(tokio::sync::RwLock::new(frp_vnet::router::RouteTable::new()));
    let controller = Arc::new(frp_vnet::controller::ClientVnetController::new());
    let writer = test_control_writer();

    let (tun, _) = fake_tun();
    register_vnet_tun(
        &tuns,
        &names,
        "vnet-a",
        (
            "10.0.0.1".parse().unwrap(),
            "255.255.255.0".parse().unwrap(),
            1420,
        ),
        tun,
    )
    .await
    .unwrap();
    spawn_vnet_tun_controller(
        &tuns,
        &tx_map,
        &cancels,
        &controller,
        "vnet-a",
        "corp-net",
        &writer,
        false,
    )
    .await
    .expect("first controller should spawn");
    let old_tx = tx_map
        .lock()
        .unwrap()
        .get("vnet-a")
        .cloned()
        .expect("first delivery channel");

    remove_vnet_tun(
        &tuns,
        &tx_map,
        &cancels,
        &names,
        &subnets,
        &route_table,
        &peer_routes,
        &writer,
        false,
        "vnet-a",
        "corp-net",
    )
    .await;
    assert!(tx_map.lock().unwrap().is_empty());

    let (tun, _) = fake_tun();
    register_vnet_tun(
        &tuns,
        &names,
        "vnet-a",
        (
            "10.0.0.2".parse().unwrap(),
            "255.255.255.0".parse().unwrap(),
            1420,
        ),
        tun,
    )
    .await
    .unwrap();
    spawn_vnet_tun_controller(
        &tuns,
        &tx_map,
        &cancels,
        &controller,
        "vnet-a",
        "corp-net",
        &writer,
        false,
    )
    .await
    .expect("second controller should spawn");
    let new_tx = tx_map
        .lock()
        .unwrap()
        .get("vnet-a")
        .cloned()
        .expect("rebuilt delivery channel");
    assert!(
        !old_tx.same_channel(&new_tx),
        "reload must not reuse the old TUN delivery channel"
    );

    remove_vnet_tun(
        &tuns,
        &tx_map,
        &cancels,
        &names,
        &subnets,
        &route_table,
        &peer_routes,
        &writer,
        false,
        "vnet-a",
        "corp-net",
    )
    .await;
}

#[cfg(feature = "vnet")]
#[tokio::test]
async fn remove_vnet_tun_sends_vnet_route_remove_and_cleans_maps() {
    let tuns: VnetTunMap = Arc::new(Mutex::new(HashMap::new()));
    let tx: VnetTunTxMap = Arc::new(std::sync::Mutex::new(HashMap::new()));
    let cancels: VnetTunCancelMap = Arc::new(Mutex::new(HashMap::new()));
    let names = Arc::new(Mutex::new(HashMap::new()));
    let subnets = Arc::new(Mutex::new(HashMap::new()));
    let peer_routes = Arc::new(Mutex::new(HashMap::new()));
    let route_table = Arc::new(tokio::sync::RwLock::new(frp_vnet::router::RouteTable::new()));
    let (writer, mut control_rx) = test_control_writer_rx();

    // Pre-populate every map the removal path must clean up.
    names.lock().await.insert("vnet-a".into(), "tun0".into());
    subnets.lock().await.insert(
        "vnet-a".into(),
        frp_vnet::router::PrecompiledSubnet::new("10.0.0.0/24"),
    );
    route_table
        .write()
        .await
        .insert("corp-net", "vnet-a", "10.0.0.0/24")
        .unwrap();
    route_table
        .write()
        .await
        .insert("other-net", "other", "10.9.0.0/24")
        .unwrap();
    peer_routes.lock().await.insert(
        "vnet-a".into(),
        ("192.168.0.0/24".into(), "tun0".into(), "corp-net".into()),
    );
    tuns.lock().await.insert("vnet-a".into(), None);
    tx.lock()
        .unwrap()
        .insert("vnet-a".into(), mpsc::channel(4).0);
    cancels
        .lock()
        .await
        .insert("vnet-a".into(), watch::channel(false).0);

    remove_vnet_tun(
        &tuns,
        &tx,
        &cancels,
        &names,
        &subnets,
        &route_table,
        &peer_routes,
        &writer,
        false,
        "vnet-a",
        "corp-net",
    )
    .await;

    assert!(tuns.lock().await.is_empty());
    assert!(tx.lock().unwrap().is_empty());
    assert!(cancels.lock().await.is_empty());
    assert!(names.lock().await.is_empty());
    assert!(subnets.lock().await.is_empty());
    assert!(peer_routes.lock().await.is_empty());
    // The removed proxy's route is gone; unrelated vnets are untouched.
    assert_eq!(
        route_table
            .read()
            .await
            .lookup("corp-net", &"10.0.0.5".parse().unwrap()),
        None
    );
    assert_eq!(
        route_table
            .read()
            .await
            .lookup("other-net", &"10.9.0.5".parse().unwrap()),
        Some("other")
    );

    // A VnetRouteRemove for the proxy's virtual net is sent to the server.
    match control_rx
        .recv()
        .await
        .expect("no VnetRouteRemove enqueued")
    {
        (FrpMessage::VnetRouteRemove(rem), _v2) => {
            assert_eq!(rem.proxy_name, "vnet-a");
            assert_eq!(rem.virtual_net.as_deref(), Some("corp-net"));
        }
        (other, _v2) => panic!("expected VnetRouteRemove message, got {:?}", other),
    }
}

#[cfg(feature = "vnet")]
#[test]
fn local_vnet_set_collects_participating_vnets() {
    let mut cfg = frp_core::config::ClientConfig::default();
    cfg.virtual_net.address = "10.0.0.1".into();
    cfg.proxies.push(frp_core::config::ProxyConfig {
        name: "vnet-a".into(),
        proxy_type: "vnet".into(),
        vnet_ip: "10.0.0.2".into(),
        vnet_netmask: "255.255.255.0".into(),
        virtual_net: "corp-net".into(),
        ..Default::default()
    });
    cfg.proxies.push(frp_core::config::ProxyConfig {
        name: "vnet-default".into(),
        proxy_type: "vnet".into(),
        vnet_ip: "10.1.0.2".into(),
        vnet_netmask: "255.255.255.0".into(),
        ..Default::default()
    });
    cfg.visitors.push(frp_core::config::VisitorConfig {
        name: "vnet-visitor".into(),
        visitor_type: "stcp".into(),
        plugin: Some(frp_core::config::VisitorPluginConfig {
            plugin_type: "virtual_net".into(),
            destination_ip: "100.86.0.1".into(),
            ..Default::default()
        }),
        ..Default::default()
    });

    let vnets = local_vnet_set(&cfg);
    assert!(vnets.contains("corp-net"));
    assert!(
        vnets.contains(""),
        "default-net proxies and virtual_net visitors join the default vnet"
    );
    assert!(!vnets.contains("other-net"));
}

#[tokio::test]
async fn xtcp_reclaim_clears_both_maps_and_notifies_visitor() {
    // Provider-side namespace: sid -> proxy_name.
    let mut pending_xtcp: HashMap<String, String> = HashMap::new();
    // Visitor-side namespace: txn_id -> oneshot sender.
    let mut visitor_pending: HashMap<String, oneshot::Sender<Result<msg::NatHoleResp, String>>> =
        HashMap::new();

    pending_xtcp.insert("sid-1".into(), "pxy-a".into());
    let (tx, rx) = oneshot::channel::<Result<msg::NatHoleResp, String>>();
    visitor_pending.insert("txn-1".into(), tx);

    // The provider sid lives only in pending_xtcp: reclaiming it clears
    // that map and leaves the visitor map (different namespace) untouched.
    assert!(reclaim_stale_xtcp_entry(
        &mut pending_xtcp,
        &mut visitor_pending,
        "sid-1"
    ));
    assert!(pending_xtcp.is_empty());
    assert!(visitor_pending.contains_key("txn-1"));

    // The txn id lives only in visitor_pending: the residual sender is
    // notified with a timeout error and the entry is removed.
    assert!(reclaim_stale_xtcp_entry(
        &mut pending_xtcp,
        &mut visitor_pending,
        "txn-1"
    ));
    assert!(visitor_pending.is_empty());
    let notified = rx.await.expect("visitor sender must be notified");
    match notified {
        Err(e) => assert!(e.contains("timeout"), "error should mention timeout: {e}"),
        Ok(_) => panic!("visitor must receive an Err on timeout reclaim"),
    }

    // Unknown keys are a no-op in both maps.
    assert!(!reclaim_stale_xtcp_entry(
        &mut pending_xtcp,
        &mut visitor_pending,
        "nope"
    ));
}

/// Regression: a failing dynamic token source must fail Service init
/// (startup), not silently fall back to an empty token. Go frp v0.70.1
/// fails startup when token-source resolution errors.
#[tokio::test]
async fn service_init_fails_on_token_source_error() {
    let cfg = ClientConfig {
        server_addr: "127.0.0.1".to_string(),
        token: "file:///nonexistent/frp-token-startup.txt".to_string(),
        ..Default::default()
    };
    let result = Service::with_unsafe_features(cfg, None, UnsafeFeatures::default()).await;
    let err = match result {
        Ok(_) => panic!("token-source failure must fail startup"),
        Err(e) => e,
    };
    // The startup error must not leak the token-file path.
    let msg = err.to_string();
    assert!(
        !msg.contains("frp-token-startup.txt"),
        "error leaked the token-file path: {msg}"
    );
}

/// Regression (PR #242 review): when a NewProxy write on the control
/// stream fails, `register_proxies` must set `ctx.write_failed` and abort
/// the registration response phase immediately — the server never received
/// the request, so no NewProxyResp will ever arrive, and waiting for one
/// would hang the registration for a full `REGISTRATION_RESPONSE_TIMEOUT`
/// (30s at default) or until the heartbeat watchdog. The abort returns
/// false, which makes run() skip the session continuation (writer task,
/// visitor listeners, message loop) and go straight to teardown +
/// reconnect.
#[tokio::test]
async fn register_proxies_aborts_on_control_write_failure() {
    let proxy = frp_core::config::ProxyConfig {
        name: "abort-tcp".to_string(),
        proxy_type: "tcp".to_string(),
        local_ip: "127.0.0.1".to_string(),
        local_port: 1,
        remote_port: 12345,
        enabled: true,
        ..Default::default()
    };
    let cfg = ClientConfig {
        server_addr: "127.0.0.1".to_string(),
        server_port: 7000,
        token: "test-token".to_string(),
        proxies: vec![proxy.clone()],
        ..Default::default()
    };
    let service = Service::with_unsafe_features(cfg.clone(), None, UnsafeFeatures::default())
        .await
        .expect("service init must succeed");

    // Control stream with a dead write direction: connect a real TCP pair,
    // then SHUT_WR the client half — every subsequent write fails with
    // BrokenPipe (EPIPE) immediately, no peer RTT involved.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let mut client = tokio::net::TcpStream::connect(addr).await.unwrap();
    let _server = listener.accept().await.unwrap();
    tokio::io::AsyncWriteExt::shutdown(&mut client)
        .await
        .unwrap();

    let mut ctx = SessionCtx {
        control_stream: Some(IoStream::Tcp(client)),
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
        wc_tls_cert_file: None,
        wc_tls_key_file: None,
        wc_dns_server: None,
        wc_udp_packet_size: 1500,
        wc_udp_packet_codec: String::new(),
        wc_disable_custom_tls_first_byte: false,
        wc_keepalive_secs: 7200,
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
    };

    // The failed write must not leave the response-read loop spinning:
    // registration must return false promptly (without it, the loop would
    // wait out REGISTRATION_RESPONSE_TIMEOUT for a response to a request
    // the server never received — the 5s test timeout catches that).
    let completed = tokio::time::timeout(
        Duration::from_secs(5),
        service.register_proxies(&mut ctx, &cfg, std::slice::from_ref(&proxy), 1),
    )
    .await
    .expect("register_proxies must exit promptly on a control write failure");

    assert!(
        !completed,
        "a failed control write must abort registration, not complete it"
    );
    assert!(ctx.write_failed, "write_failed must be recorded on the ctx");
    assert!(
        ctx.pending_proxies.is_empty(),
        "the failed request must not be left pending"
    );
    let map = service.proxy_info_map.read().await;
    let info = map
        .get(&wire_proxy_name(&cfg.user, &proxy.name))
        .expect("proxy must have a runtime info entry");
    assert!(
        matches!(&info.phase, ProxyPhase::StartErr(e) if !e.is_empty()),
        "proxy must be marked StartErr after a failed write, got {:?}",
        info.phase
    );
}

/// Regression (SIGTERM crash, rc 101): `shutdown_visitor_tasks` must not
/// poll a `JoinHandle` whose task has already finished. With N >= 2
/// visitors sharing one `bind_port` the losers' `TcpListener::bind` fails
/// and their task returns at once, so `join_all` drives their handles to
/// `Ready` while the winner is still parked in `accept()` past the 500ms
/// grace — and the abort path then awaited those already-consumed handles,
/// hitting `JoinHandle polled after completion`
/// (tokio-1.53.1/src/runtime/task/core.rs:427). The binary-level half of
/// this pin is `frp-server/tests/visitor_multi_sigterm.rs`.
#[tokio::test]
async fn shutdown_visitor_tasks_tolerates_a_completed_handle() {
    let cfg = ClientConfig {
        server_addr: "127.0.0.1".to_string(),
        server_port: 7000,
        token: "test-token".to_string(),
        ..Default::default()
    };
    let service = Service::with_unsafe_features(cfg, None, UnsafeFeatures::default())
        .await
        .expect("service init must succeed");

    // The loser: a task that finishes immediately, exactly like a visitor
    // whose bind failed (`visitor.rs` returns straight away). `join_all`
    // inside `shutdown_visitor_tasks` polls it to `Ready` either way.
    let finished = tokio::spawn(async {});
    // The winner: parked in `accept()`, like an idle listener.
    let parked = tokio::spawn(async { std::future::pending::<()>().await });

    // Pre-fix this panics inside the 500ms abort branch; the timeout only
    // bounds the test if the panic is gone but the join hangs.
    tokio::time::timeout(
        Duration::from_secs(5),
        service.shutdown_visitor_tasks(vec![finished, parked]),
    )
    .await
    .expect("shutdown_visitor_tasks must return");
}

/// Measures the claim that makes skipping an already-finished handle safe
/// (the comment in `shutdown_visitor_tasks`): a task's future — and with it
/// any listener socket it holds — is dropped by the time
/// `JoinHandle::is_finished()` reports true, so the skip cannot leave a
/// bind port held; and the abort+await path still releases a listener that
/// was parked in `accept()`. Both halves are checked by re-binding the two
/// ports after the shutdown call returns (a held port would fail with
/// AddrInUse). Everything runs in-process, so no other process can release
/// the ports for us.
#[tokio::test]
async fn shutdown_visitor_tasks_releases_listeners() {
    let cfg = ClientConfig {
        server_addr: "127.0.0.1".to_string(),
        server_port: 7000,
        token: "test-token".to_string(),
        ..Default::default()
    };
    let service = Service::with_unsafe_features(cfg, None, UnsafeFeatures::default())
        .await
        .expect("service init must succeed");

    // Free ports, taken the same way the visitor listeners take theirs.
    // Both tasks report a successful bind on a oneshot before anything is
    // asserted, so a port stolen in the probe->bind window (the test
    // binaries run in parallel) fails this test loudly instead of quietly
    // turning a task into a finished-without-binding one — which would make
    // half 2 pass without ever exercising the abort+await path.
    let (bound_tx, bound_rx) = tokio::sync::oneshot::channel();
    let (finished_port, finished) = {
        let probe = std::net::TcpListener::bind("127.0.0.1:0").expect("probe port");
        let port = probe.local_addr().expect("probe addr").port();
        drop(probe);
        let handle = tokio::spawn(async move {
            let listener = tokio::net::TcpListener::bind(("127.0.0.1", port))
                .await
                .expect("loser-shaped listener bind");
            bound_tx.send(()).expect("report loser bind");
            drop(listener);
        });
        (port, handle)
    };
    let (parked_bound_tx, parked_bound_rx) = tokio::sync::oneshot::channel();
    let (parked_port, parked) = {
        let probe = std::net::TcpListener::bind("127.0.0.1:0").expect("probe port");
        let port = probe.local_addr().expect("probe addr").port();
        drop(probe);
        let handle = tokio::spawn(async move {
            let listener = tokio::net::TcpListener::bind(("127.0.0.1", port))
                .await
                .expect("winner-shaped listener bind");
            parked_bound_tx.send(()).expect("report parked bind");
            let _held = listener;
            std::future::pending::<()>().await
        });
        (port, handle)
    };

    // Both listeners exist before we observe anything, so neither half can
    // pass by accident.
    bound_rx
        .await
        .expect("loser-shaped task must bind its port");
    parked_bound_rx
        .await
        .expect("parked task must bind its port");
    // Let the first task drop its listener and finish.
    while !finished.is_finished() {
        tokio::task::yield_now().await;
    }
    assert!(
        !parked.is_finished(),
        "the parked task must still be holding its listener when shutdown starts"
    );
    // Half 1, measured BEFORE the shutdown call: a finished task has
    // already dropped its future, so its port is free while the handle is
    // still un-awaited. This does not discriminate the skip (dropping the
    // future is what releases the port); it establishes that nothing else
    // retains a port for a task the shutdown call is about to skip.
    let rebind = std::net::TcpListener::bind(("127.0.0.1", finished_port));
    assert!(
        rebind.is_ok(),
        "a finished visitor task must have released {finished_port} by the \
             time is_finished() is true, got {:?}",
        rebind.err()
    );
    drop(rebind);

    // Half 2, the discriminating half: the parked listener can only be
    // released by the abort+await inside shutdown_visitor_tasks.
    service.shutdown_visitor_tasks(vec![finished, parked]).await;

    let rebind = std::net::TcpListener::bind(("127.0.0.1", parked_port));
    assert!(
        rebind.is_ok(),
        "the parked listener's port {parked_port} must be released when \
             shutdown_visitor_tasks returns, got {:?}",
        rebind.err()
    );
    drop(rebind);
}

/// Sets its flag on drop — used to observe task cancellation (aborting
/// a task drops its future, running destructors).
struct DropFlag(Arc<AtomicBool>);

impl Drop for DropFlag {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}

/// Regression (HIGH leak): standalone work-conn tasks (tcp_mux off)
/// were spawned without tracking and never closed at teardown — on
/// reconnect each orphaned work-conn task + TCP conn lived until a
/// socket error (Go frp avoids this by closing work conns on control
/// close via workConnManager). `teardown_session` must abort them.
#[cfg(feature = "tcp-mux")]
#[tokio::test]
async fn teardown_session_aborts_work_conn_tasks() {
    let cfg = ClientConfig {
        server_addr: "127.0.0.1".to_string(),
        server_port: 7000,
        token: "test-token".to_string(),
        ..Default::default()
    };
    let service = Service::with_unsafe_features(cfg, None, UnsafeFeatures::default())
        .await
        .expect("service init must succeed");

    // A work-conn-shaped task that would otherwise bridge forever (an
    // idle connection with no traffic): block on a never-completing
    // future. A drop-guard flags when the task is cancelled, so the
    // test can observe the abort without owning the JoinHandle (which
    // is moved into the session and taken by teardown).
    let cancelled = Arc::new(AtomicBool::new(false));
    let flag = cancelled.clone();
    let stuck = tokio::spawn(async move {
        let _guard = DropFlag(flag);
        std::future::pending::<()>().await
    });
    // Let the task run once so its drop-guard exists before teardown
    // aborts it: a task aborted before its first poll never executes its
    // body, and the guard is created inside the body.
    tokio::task::yield_now().await;

    let mut ctx = SessionCtx {
        control_stream: None,
        run_id: "teardown-test-run-id".to_string(),
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
        wc_tls_cert_file: None,
        wc_tls_key_file: None,
        wc_dns_server: None,
        wc_udp_packet_size: 1500,
        wc_udp_packet_codec: String::new(),
        wc_disable_custom_tls_first_byte: false,
        wc_keepalive_secs: 7200,
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
        // The vnet teardown path sends VnetRouteRemove via the writer;
        // a drained channel satisfies the `.expect()` and the send
        // failures are logged, not fatal.
        #[cfg(feature = "vnet")]
        writer: Some(test_control_writer()),
        #[cfg(not(feature = "vnet"))]
        writer: None,
        control_rx: None,
        control_failed: None,
        control_notify: None,
        reader: None,
        visitor_shutdown: Some(Arc::new(AtomicBool::new(false))),
        visitor_handles: Vec::new(),
        work_conn_handles: vec![stuck],
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
    };

    let health_cancels: Arc<Mutex<HashMap<String, Arc<AtomicBool>>>> =
        Arc::new(Mutex::new(HashMap::new()));
    let mut admin_handle = None;
    service
        .teardown_session(&mut ctx, &mut None, &health_cancels, &mut admin_handle)
        .await;

    // The work-conn task must be cancelled: teardown aborts it. Without
    // the fix the task keeps running forever and the flag never fires —
    // this await times out (the test's failure mode).
    tokio::time::timeout(Duration::from_secs(2), async {
        while !cancelled.load(Ordering::Acquire) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("teardown_session must abort the session's work-conn tasks");
}

/// Regression (MEDIUM): the control writer task was spawned untracked
/// and never aborted at teardown. On tcp_mux=false the raw write half
/// lives only inside that task, so against a wedged-but-alive peer
/// (zero-window TCP that ACKs keepalive/window probes, or no-mux KCP
/// with no dead-conn detection) the task blocks forever in write_msg and
/// teardown cannot close the socket any other way — one task+fd leaked
/// per reconnect cycle. `teardown_session` must abort the writer (after
/// the vnet route-removal sends that ride its channel). The abort step
/// itself is feature-independent; the call-site signature differs under
/// tcp-mux, hence the two cfg-branched calls.
#[tokio::test]
async fn teardown_session_aborts_control_writer() {
    let cfg = ClientConfig {
        server_addr: "127.0.0.1".to_string(),
        server_port: 7000,
        token: "test-token".to_string(),
        ..Default::default()
    };
    let service = Service::with_unsafe_features(cfg, None, UnsafeFeatures::default())
        .await
        .expect("service init must succeed");

    // A writer-shaped task that would otherwise block forever (the
    // wedged-peer write_msg): block on a never-completing future. A
    // drop-guard flags when the task is cancelled, so the test can
    // observe the abort without owning the JoinHandle (which is moved
    // into the session and taken by teardown).
    let cancelled = Arc::new(AtomicBool::new(false));
    let flag = cancelled.clone();
    let stuck = tokio::spawn(async move {
        let _guard = DropFlag(flag);
        std::future::pending::<()>().await
    });
    // Let the task run once so its drop-guard exists before teardown
    // aborts it: a task aborted before its first poll never executes its
    // body, and the guard is created inside the body.
    tokio::task::yield_now().await;

    let mut ctx = SessionCtx {
        control_stream: None,
        run_id: "writer-teardown-test-run-id".to_string(),
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
        wc_tls_cert_file: None,
        wc_tls_key_file: None,
        wc_dns_server: None,
        wc_udp_packet_size: 1500,
        wc_udp_packet_codec: String::new(),
        wc_disable_custom_tls_first_byte: false,
        wc_keepalive_secs: 7200,
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
        // The vnet teardown path sends VnetRouteRemove via the writer;
        // a drained channel satisfies the `.expect()` and the send
        // failures are logged, not fatal.
        #[cfg(feature = "vnet")]
        writer: Some(test_control_writer()),
        #[cfg(not(feature = "vnet"))]
        writer: None,
        control_rx: None,
        control_failed: None,
        control_notify: None,
        reader: None,
        visitor_shutdown: Some(Arc::new(AtomicBool::new(false))),
        visitor_handles: Vec::new(),
        work_conn_handles: Vec::new(),
        control_writer_handle: Some(stuck),
        pending_xtcp: HashMap::new(),
        xtcp_sockets: Default::default(),
        visitor_pending: HashMap::new(),
        stun_result_tx: None,
        stun_result_rx: None,
        xtcp_cleanup_rx: None,
        proxy_retry_interval: None,
        waitstart_seen: HashMap::new(),
        cfg_user: String::new(),
    };

    let health_cancels: Arc<Mutex<HashMap<String, Arc<AtomicBool>>>> =
        Arc::new(Mutex::new(HashMap::new()));
    let mut admin_handle = None;
    #[cfg(feature = "tcp-mux")]
    service
        .teardown_session(&mut ctx, &mut None, &health_cancels, &mut admin_handle)
        .await;
    #[cfg(not(feature = "tcp-mux"))]
    service
        .teardown_session(&mut ctx, &health_cancels, &mut admin_handle)
        .await;

    // The writer task must be cancelled: teardown aborts it. Without the
    // fix the task keeps running forever and the flag never fires — this
    // await times out (the test's failure mode).
    tokio::time::timeout(Duration::from_secs(2), async {
        while !cancelled.load(Ordering::Acquire) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("teardown_session must abort the control writer task");
}

/// F2 guard semantics: the XTCP punch paths must refuse proxies that a
/// reload removed (absent from proxy_info_map) or a health Close marked
/// CheckFailed — punching for either would re-arm a fresh uncancelled
/// P2P token after the removal already cancelled one (the
/// cancel-before-reinsert race). A live (Running) or re-registering
/// (WaitStart) proxy must still pass.
#[tokio::test]
async fn punch_proxy_still_live_tracks_proxy_liveness() {
    let cfg = ClientConfig {
        server_addr: "127.0.0.1".to_string(),
        server_port: 7000,
        token: "test-token".to_string(),
        ..Default::default()
    };
    let service = Service::with_unsafe_features(cfg, None, UnsafeFeatures::default())
        .await
        .expect("service init must succeed");

    // Unknown proxy (reload removed it): dead.
    assert!(
        !service.punch_proxy_still_live("user.xtcp-a").await,
        "a proxy absent from proxy_info_map must not punch"
    );

    let proxy_info_map = &service.proxy_info_map;
    let insert = |phase: ProxyPhase| async move {
        let mut map = proxy_info_map.write().await;
        map.insert(
            "user.xtcp-a".to_string(),
            ProxyRuntimeInfo {
                local_addr: "127.0.0.1:8080".to_string(),
                proxy_type: "xtcp".to_string(),
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
            },
        );
    };

    insert(ProxyPhase::Running).await;
    assert!(
        service.punch_proxy_still_live("user.xtcp-a").await,
        "a Running proxy must still punch"
    );

    // Health Close marks the proxy CheckFailed (it stays in the map for
    // recovery monitoring): dead for punching.
    insert(ProxyPhase::CheckFailed).await;
    assert!(
        !service.punch_proxy_still_live("user.xtcp-a").await,
        "a health-closed (CheckFailed) proxy must not punch"
    );

    // Server CloseProxy marks the proxy Closed: the server's nathole
    // session outlives the close (NAT_HOLE_TIMEOUT = 10s), so a late
    // NatHoleClient/NatHoleResp must not re-arm a fresh token.
    insert(ProxyPhase::Closed).await;
    assert!(
        !service.punch_proxy_still_live("user.xtcp-a").await,
        "a server-closed (Closed) proxy must not punch"
    );

    // Recovery re-registration (WaitStart) may punch again.
    insert(ProxyPhase::WaitStart).await;
    assert!(
        service.punch_proxy_still_live("user.xtcp-a").await,
        "a re-registering (WaitStart) proxy must punch"
    );
}

/// F2: a NatHoleClient for a dead proxy must not punch — the handler
/// bails before binding a UDP socket or sending anything on the control
/// channel. Without the guard the handler reaches the visitor_addr
/// check and immediately enqueues a NatHoleReport failure; the test
/// asserts the control channel stays silent instead.
#[tokio::test]
async fn nat_hole_client_bails_for_dead_proxy_without_sending() {
    let cfg = ClientConfig {
        server_addr: "127.0.0.1".to_string(),
        server_port: 7000,
        token: "test-token".to_string(),
        ..Default::default()
    };
    let service = Service::with_unsafe_features(cfg, None, UnsafeFeatures::default())
        .await
        .expect("service init must succeed");
    let (writer, mut control_rx) = test_control_writer_rx();

    // proxy_info_map is empty: the proxy is dead (reload removed it).
    let nhc = msg::NatHoleClient {
        transaction_id: "txn-dead".to_string(),
        proxy_name: "user.xtcp-dead".to_string(),
        sid: Some("sid-dead".to_string()),
        protocol: Some("kcp".to_string()),
        mapped_addrs: None,
        assisted_addrs: None,
        visitor_addr: None,
    };
    service
        .handle_nat_hole_client(
            nhc,
            &writer,
            false,
            Arc::new(AtomicBool::new(true)),
            CancellationToken::new(),
        )
        .await;

    // Nothing may be enqueued: the guard returns before the handler can
    // send NatHoleSid / a NatHoleReport failure. Without the guard the
    // empty visitor_addr would produce an immediate NatHoleReport, and
    // this recv would resolve with Some instead of timing out.
    let silent = tokio::time::timeout(Duration::from_millis(300), control_rx.recv())
        .await
        .is_err();
    assert!(
        silent,
        "dead-proxy NatHoleClient must not punch; a control message was enqueued"
    );
}

/// F2: a NatHoleResp routed to a dead provider proxy must not spawn a
/// punch — the handler reclaims the sid's STUN socket and returns. The
/// socket refcount is the revert-proof observable: without the guard the
/// spawned punch task holds an Arc clone (and punches for up to 5s), so
/// `Arc::try_unwrap` would fail; with the guard the map was the only
/// other holder and the reclaim drops it.
#[tokio::test]
async fn nat_hole_resp_bails_for_dead_proxy_and_reclaims_socket() {
    let cfg = ClientConfig {
        server_addr: "127.0.0.1".to_string(),
        server_port: 7000,
        token: "test-token".to_string(),
        ..Default::default()
    };
    let service = Service::with_unsafe_features(cfg, None, UnsafeFeatures::default())
        .await
        .expect("service init must succeed");
    let (writer, _control_rx) = test_control_writer_rx();

    let socket = match tokio::net::UdpSocket::bind("127.0.0.1:0").await {
        Ok(s) => Some(Arc::new(s)),
        Err(e) => {
            eprintln!(
                "UDP bind denied ({e}); asserting map reclaim without the socket-refcount check"
            );
            None
        }
    };

    let sid = "sid-dead".to_string();
    let mut pending_xtcp = HashMap::new();
    pending_xtcp.insert(sid.clone(), "user.xtcp-dead".to_string());
    let xtcp_sockets: Arc<Mutex<HashMap<String, Arc<tokio::net::UdpSocket>>>> = Default::default();
    if let Some(ref s) = socket {
        xtcp_sockets.lock().await.insert(sid.clone(), s.clone());
    }
    let mut visitor_pending = HashMap::new();

    let resp = msg::NatHoleResp {
        transaction_id: String::new(),
        error: None,
        sid: Some(sid.clone()),
        protocol: None,
        candidate_addrs: Some(vec!["127.0.0.1:12345".to_string()]),
        assisted_addrs: Some(Vec::new()),
        detect_behavior: None,
    };
    service
        .handle_nat_hole_resp(
            resp,
            &mut pending_xtcp,
            &mut visitor_pending,
            &xtcp_sockets,
            &writer,
            Arc::new(AtomicBool::new(true)),
            CancellationToken::new(),
        )
        .await;

    // The guard reclaimed both sid entries synchronously.
    assert!(
        !pending_xtcp.contains_key(&sid),
        "dead-proxy NatHoleResp must reclaim the pending_xtcp entry"
    );
    assert!(
        !xtcp_sockets.lock().await.contains_key(&sid),
        "dead-proxy NatHoleResp must reclaim the STUN socket entry"
    );
    // The punch task must not exist: with the guard the map was the only
    // other Arc holder, so the reclaim leaves our clone alone; without
    // the guard the spawned task holds a clone for the punch duration.
    if let Some(socket) = socket {
        assert!(
            Arc::try_unwrap(socket).is_ok(),
            "dead-proxy NatHoleResp must not spawn a punch task holding the STUN socket"
        );
    }
}

/// The ≥5-minute-healthy-session error-count reset, extracted into a
/// pure function so the production window needs no wall-clock sleeps.
/// A session that lasted at least the healthy duration resets the
/// consecutive-error count (the next reconnect comes back at Phase 1
/// instead of the 20s exponential cap); a shorter session keeps the
/// count. The comparison is strict (`>`), matching the production
/// `elapsed() > 300s` semantics exactly.
#[test]
fn healthy_session_resets_consecutive_error_count() {
    let now = Instant::now();
    let healthy = Duration::from_secs(300);

    // Short session with prior errors: no reset — the backoff cap is
    // preserved across rapid reconnects.
    assert!(!healthy_resets_error_count(
        3,
        Some(now - Duration::from_secs(60)),
        now,
        healthy
    ));
    // Session started exactly `healthy` ago: NOT a reset (strict `>`).
    assert!(!healthy_resets_error_count(
        3,
        Some(now - healthy),
        now,
        healthy
    ));
    // Session longer than the healthy duration with prior errors: reset.
    assert!(healthy_resets_error_count(
        3,
        Some(now - healthy - Duration::from_millis(1)),
        now,
        healthy
    ));
    // No prior errors: the reset is a no-op — and must not report one.
    assert!(!healthy_resets_error_count(
        0,
        Some(now - healthy - Duration::from_secs(60)),
        now,
        healthy
    ));
    // No session start (never logged in): no reset.
    assert!(!healthy_resets_error_count(3, None, now, healthy));
}

/// The client half of S1: without the `oidc` feature, `auth.method = "oidc"`
/// used to fall through to `Token`, so an operator asking for OIDC got a
/// token-auth client. It must now be refused before any connection is made.
#[tokio::test]
#[cfg(not(feature = "oidc"))]
async fn oidc_method_with_client_oidc_off_is_rejected() {
    // One-expression initialisers (clippy::field_reassign_with_default):
    // neither config type implements `Drop`, so the struct-update form is
    // available here.
    let auth = frp_core::config::AuthClientConfig {
        method: "oidc".to_string(),
        ..Default::default()
    };
    let cfg = ClientConfig {
        auth: Some(auth),
        ..Default::default()
    };
    let err = match Service::with_unsafe_features(cfg, None, UnsafeFeatures::default()).await {
        Ok(_) => panic!("an oidc client config in an oidc-less build must be rejected"),
        Err(e) => e,
    };
    let msg = err.to_string();
    assert!(
        msg.contains("\"oidc\"") && msg.contains("feature"),
        "error must name the missing feature: {msg}"
    );
}

/// The helper `frpc verify` calls (via `run_verify`) — the only unit-testable
/// half of that path, because `run_verify` itself ends in `process::exit`
/// and would kill the test process. Pins both directions plus the `None`
/// case, so `verify` and `run` agree on what an oidc-less build refuses.
#[test]
#[cfg(not(feature = "oidc"))]
fn refuse_oidc_helper_rejects_oidc_and_accepts_token() {
    let oidc = frp_core::config::AuthClientConfig {
        method: "oidc".to_string(),
        ..Default::default()
    };
    let err = refuse_oidc_method_without_feature(Some(&oidc))
        .expect_err("an oidc config must be refused");
    assert_eq!(err, frp_core::auth::OIDC_FEATURE_REQUIRED);

    let token = frp_core::config::AuthClientConfig {
        method: "token".to_string(),
        ..Default::default()
    };
    assert!(refuse_oidc_method_without_feature(Some(&token)).is_ok());
    assert!(refuse_oidc_method_without_feature(None).is_ok());
}

/// The helper must apply the *one* policy, not a local `== "oidc"`. Before
/// this, every non-exact spelling returned `Ok` from it, so in an oidc-less
/// build `method = "OIDC"` started a token client.
///
/// Feature-independent on purpose (`refuse_oidc_method_without_feature`
/// always runs the parse): the "not exactly `token`/`oidc`" refusal is Go's
/// load error in every build, only the `"oidc"`-in-an-oidc-less-build
/// refusal is feature-specific. This is the unit half of the
/// `FRPC_TINY_CLI_TESTS` spawn pin; it covers the spellings the CLI test
/// cannot afford a subprocess each for.
#[test]
fn refuse_oidc_helper_applies_the_exact_method_policy() {
    for bad in [
        "OIDC",
        "Oidc",
        " oidc",
        "oidc ",
        "tokenn",
        "\u{043e}idc",
        "",
    ] {
        let ac = frp_core::config::AuthClientConfig {
            method: bad.to_string(),
            ..Default::default()
        };
        let err = refuse_oidc_method_without_feature(Some(&ac))
            .expect_err(&format!("{bad:?} must be refused (Go rejects it)"));
        assert_eq!(
            err,
            frp_core::auth::INVALID_AUTH_METHOD,
            "{bad:?} must carry Go's exact text"
        );
    }
    // Exactly `"oidc"` takes the feature arm instead: the shared parse
    // error must not shadow it. Both branches must compile in both
    // feature configurations, so this matches on the result rather than
    // binding it twice.
    let oidc = frp_core::config::AuthClientConfig {
        method: "oidc".to_string(),
        ..Default::default()
    };
    match refuse_oidc_method_without_feature(Some(&oidc)) {
        #[cfg(not(feature = "oidc"))]
        Err(e) => assert_eq!(e, frp_core::auth::OIDC_FEATURE_REQUIRED),
        #[cfg(not(feature = "oidc"))]
        Ok(()) => panic!("an oidc-less build must refuse \"oidc\""),
        #[cfg(feature = "oidc")]
        Ok(()) => {}
        #[cfg(feature = "oidc")]
        Err(e) => panic!("an oidc build serves \"oidc\", got {e:?}"),
    }
}

/// **Site 3 — the client's construction parse** (`Service::with_unsafe_features`).
/// Ungated on purpose: `"OIDC"` is refused by the *shared* parse in every
/// build, so this is one behavioural pin for both feature configurations
/// (the build matrix already runs this module with `oidc` on and off).
///
/// The config never went through the loader (its normal caller does that),
/// which is exactly why the construction site keeps its own `parse_auth_method`
/// call: without it the old code read `ac.method == "oidc"` → false and
/// silently built a **token** client, the downgrade the item describes.
#[tokio::test]
async fn construction_refuses_a_non_exact_auth_method() {
    for bad in ["OIDC", "Oidc", " oidc", "tokenn", ""] {
        let cfg = ClientConfig {
            auth: Some(frp_core::config::AuthClientConfig {
                method: bad.to_string(),
                token: "t".into(),
                ..Default::default()
            }),
            ..Default::default()
        };
        let err = match Service::with_unsafe_features(cfg, None, UnsafeFeatures::default()).await {
            Ok(_) => panic!("{bad:?} must be refused at construction (Go rejects it)"),
            Err(e) => e,
        };
        assert!(
            err.to_string()
                .ends_with(frp_core::auth::INVALID_AUTH_METHOD),
            "{bad:?} must carry Go's exact text, got {err:?}"
        );
        assert_eq!(
            err.kind(),
            frp_core::init_error::InitErrorKind::Auth,
            "{bad:?} must keep the auth tag (EXIT_AUTH/3)"
        );
    }
}
