use super::*;

fn test_state() -> Arc<AppState> {
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

/// Audit H1 regression: "0 = unlimited" must build NO connection
/// semaphore (`conn_semaphore = None`). The old service.rs mapping
/// `Some(0) => usize::MAX` passed the `> 0` gate and called
/// `Semaphore::new(usize::MAX)`, which panics (tokio MAX_PERMITS
/// assertion) — aborting frps at boot with panic=abort.
#[test]
fn max_connections_zero_creates_no_semaphore() {
    // test_state() constructs AppState::new with max_connections = 0.
    let state = test_state();
    assert!(
        state.conn_semaphore.is_none(),
        "max_connections = 0 must mean unlimited (no semaphore)"
    );
}

#[tokio::test]
async fn run_mu_entries_are_reclaimed_when_last_guard_drops() {
    let state = test_state();

    let (mu_a, guard_a) = state.get_run_mu("run-a");
    let (_mu_b, guard_b) = state.get_run_mu("run-b");
    assert_eq!(state.run_mu_map.lock().unwrap().len(), 2);

    // A second lifecycle participant inherits the same mutex.
    let (mu_a2, guard_a2) = state.get_run_mu("run-a");
    assert!(Arc::ptr_eq(&mu_a, &mu_a2));

    drop(guard_a);
    // run-a still has one live participant, so its entry must persist.
    assert_eq!(state.run_mu_map.lock().unwrap().len(), 2);
    drop(guard_a2);
    // run-b still holds its entry; run-a is fully reclaimed.
    assert_eq!(state.run_mu_map.lock().unwrap().len(), 1);

    drop(guard_b);
    assert!(state.run_mu_map.lock().unwrap().is_empty());
}

#[cfg(feature = "vnet")]
async fn insert_control(state: &Arc<AppState>, run_id: &str) -> mpsc::Receiver<InternalMsg> {
    let (tx, rx) = mpsc::channel(16);
    state.run_id_to_ctl_tx.insert(
        run_id.to_string(),
        ControlTx {
            tx,
            mux_shutdown: None,
            client_addr: None,
            login_time: Instant::now(),
            login_time_unix: 0,
            pool_stats: Arc::new(PoolStats::default()),
            user: String::new(),
            control_id: 1,
            udp_packet_codec: String::new(),
            wire_v2: false,
            superseded: Arc::new(AtomicBool::new(false)),
        },
    );
    rx
}

#[cfg(feature = "vnet")]
#[tokio::test]
async fn vnet_route_broadcast_only_reaches_same_vnet_peers() {
    let state = test_state();
    let mut sender_rx = insert_control(&state, "run-a").await;
    let mut peer_rx = insert_control(&state, "run-b").await;
    let mut other_vnet_rx = insert_control(&state, "run-c").await;
    // run-b participates in vnet-a; run-c only in vnet-b.
    {
        let mut routes = state.vnet_routes.write().await;
        routes.insert(
            ("vnet-a".to_string(), "10.0.0.0/24".to_string()),
            ("run-b".to_string(), "peer-b".to_string()),
        );
        routes.insert(
            ("vnet-b".to_string(), "10.1.0.0/24".to_string()),
            ("run-c".to_string(), "peer-c".to_string()),
        );
    }
    let adv = msg::VnetRouteAdvertise {
        proxy_name: "vnet-visitor".to_string(),
        subnet: "2001:db8::1/128".to_string(),
        virtual_net: Some("vnet-a".to_string()),
    };
    state.broadcast_vnet_route_advertise("run-a", &adv).await;

    match tokio::time::timeout(Duration::from_secs(5), peer_rx.recv()).await {
        Ok(Some(InternalMsg::VnetRouteAdvertiseForward { msg })) => {
            assert_eq!(msg.proxy_name, "vnet-visitor");
            assert_eq!(msg.virtual_net.as_deref(), Some("vnet-a"));
        }
        other => panic!("expected forwarded advertise, got {:?}", other),
    }
    assert!(
        sender_rx.try_recv().is_err(),
        "source run must not receive its own broadcast"
    );
    assert!(
        other_vnet_rx.try_recv().is_err(),
        "different-vnet peer must not receive the broadcast"
    );
}

#[cfg(feature = "vnet")]
#[tokio::test]
async fn remove_proxy_vnet_routes_broadcasts_to_same_vnet_peers() {
    let state = test_state();
    let mut peer_rx = insert_control(&state, "run-b").await;
    {
        let mut routes = state.vnet_routes.write().await;
        // run-a's proxy owns two vnet-a routes and one vnet-b route.
        routes.insert(
            ("vnet-a".to_string(), "10.0.0.0/24".to_string()),
            ("run-a".to_string(), "vnet-proxy".to_string()),
        );
        routes.insert(
            ("vnet-a".to_string(), "2001:db8::/64".to_string()),
            ("run-a".to_string(), "vnet-proxy".to_string()),
        );
        routes.insert(
            ("vnet-b".to_string(), "10.1.0.0/24".to_string()),
            ("run-a".to_string(), "vnet-proxy".to_string()),
        );
        // run-b participates in vnet-a, so it receives the vnet-a removal.
        routes.insert(
            ("vnet-a".to_string(), "172.16.0.0/16".to_string()),
            ("run-b".to_string(), "peer-b".to_string()),
        );
    }

    state
        .remove_proxy_vnet_routes_and_broadcast("run-a", "vnet-proxy")
        .await;

    assert!(
        state
            .vnet_routes
            .read()
            .await
            .iter()
            .all(|(_, (_, name))| name != "vnet-proxy"),
        "all routes for the closed proxy must be removed"
    );

    // Two removals are broadcast (vnet-a + vnet-b), but run-b only
    // receives the one for vnet-a.
    let mut received = Vec::new();
    while let Ok(InternalMsg::VnetRouteRemoveForward { msg }) = peer_rx.try_recv() {
        received.push(msg);
    }
    assert_eq!(received.len(), 1);
    assert_eq!(received[0].proxy_name, "vnet-proxy");
    assert_eq!(received[0].virtual_net.as_deref(), Some("vnet-a"));
}

#[cfg(feature = "vnet")]
#[tokio::test]
async fn vnet_packet_source_allowed_respects_isolation() {
    let state = test_state();
    {
        let mut routes = state.vnet_routes.write().await;
        routes.insert(
            ("vnet-a".to_string(), "10.0.0.0/24".to_string()),
            ("run-a".to_string(), "peer-a".to_string()),
        );
        routes.insert(
            ("vnet-a".to_string(), "10.0.1.0/24".to_string()),
            ("run-b".to_string(), "target-b".to_string()),
        );
        routes.insert(
            ("vnet-b".to_string(), "10.1.0.0/24".to_string()),
            ("run-c".to_string(), "target-c".to_string()),
        );
    }
    // run-a is in vnet-a and may reach target-b (also vnet-a).
    assert!(state.vnet_packet_source_allowed("run-a", "target-b").await);
    // run-c is only in vnet-b; reaching target-b (vnet-a) is denied.
    assert!(!state.vnet_packet_source_allowed("run-c", "target-b").await);
    // A source with no route in the target's vnet is denied.
    assert!(!state.vnet_packet_source_allowed("run-b", "target-c").await);
    // Unknown target routes are denied.
    assert!(!state.vnet_packet_source_allowed("run-a", "missing").await);
}

// --- VnetRoutes index tests (TOP-4: pre-grouped route table) ---

#[cfg(feature = "vnet")]
type FlatRoutes = HashMap<(String, String), (String, String)>;

/// Reference implementation of the visitor resolution, with the original
/// nested-scan semantics (the code the pre-grouped index replaced).
#[cfg(feature = "vnet")]
fn reference_visitor_route_target(
    routes: &FlatRoutes,
    source_run_id: &str,
    proxy_name: &str,
) -> Option<String> {
    routes
        .iter()
        .filter(|((vn, _), (_, name))| {
            name == proxy_name
                && routes
                    .iter()
                    .any(|((vn2, _), (rid2, _))| vn2 == vn && rid2 == source_run_id)
        })
        .map(|((vn, _), (run_id, _))| (vn.clone(), run_id.clone()))
        .min()
        .map(|(_, run_id)| run_id)
}

/// Reference implementation of the isolation gate (original two-pass
/// scan).
#[cfg(feature = "vnet")]
fn reference_source_allowed(routes: &FlatRoutes, run_id: &str, proxy_name: &str) -> bool {
    let source_vnets: HashSet<&String> = routes
        .iter()
        .filter(|(_, (rid, _))| rid == run_id)
        .map(|((vn, _), _)| vn)
        .collect();
    routes
        .iter()
        .any(|((vn, _), (_, name))| name == proxy_name && source_vnets.contains(vn))
}

/// Exhaustively compare every derived index against the reference
/// implementations over the current flat table: route counts, per-route
/// existence, vnet membership, the isolation gate and the visitor target
/// resolution — for every known run_id / vnet / proxy_name plus one
/// unknown of each.
#[cfg(feature = "vnet")]
fn assert_indexes_match_reference(routes: &VnetRoutes) {
    let flat: FlatRoutes = routes.iter().map(|(k, v)| (k.clone(), v.clone())).collect();

    let mut run_ids: Vec<String> = flat.values().map(|(r, _)| r.clone()).collect();
    run_ids.sort();
    run_ids.dedup();
    run_ids.push("run-absent".to_string());
    let mut names: Vec<String> = flat.values().map(|(_, n)| n.clone()).collect();
    names.sort();
    names.dedup();
    names.push("name-absent".to_string());
    let mut vnets: Vec<String> = flat.keys().map(|(v, _)| v.clone()).collect();
    vnets.sort();
    vnets.dedup();
    // A vnet key whose routes were all removed must behave as empty
    // against every index — the count maps drop their keys at zero and
    // absent = empty everywhere (audit review NIT).
    vnets.push("vnet-absent".to_string());

    for run_id in &run_ids {
        let expected_count = flat.values().filter(|(r, _)| r == run_id).count();
        assert_eq!(
            routes.run_route_count(run_id),
            expected_count,
            "route count for {run_id}"
        );

        for vnet in &vnets {
            let expected_members: Vec<String> = {
                let mut m: Vec<String> = flat
                    .iter()
                    .filter(|((v, _), _)| v == vnet)
                    .map(|(_, (r, _))| r.clone())
                    .collect();
                m.sort();
                m.dedup();
                m
            };
            let actual_members: Vec<String> = match routes.vnet_members_of(vnet) {
                Some(m) => {
                    let mut m: Vec<String> = m.iter().map(|r| r.to_string()).collect();
                    m.sort();
                    m
                }
                // An empty member set is dropped from the index
                // (absent = empty).
                None => Vec::new(),
            };
            assert_eq!(actual_members, expected_members, "members of {vnet:?}");

            for name in &names {
                let expected_has = flat
                    .iter()
                    .any(|((v, _), (r, n))| v == vnet && r == run_id && n == name);
                assert_eq!(
                    routes.has_route(run_id, vnet, name),
                    expected_has,
                    "has_route({run_id}, {vnet:?}, {name})"
                );
            }
        }

        for name in &names {
            assert_eq!(
                routes.source_allowed(run_id, name),
                reference_source_allowed(&flat, run_id, name),
                "source_allowed({run_id}, {name})"
            );
            assert_eq!(
                routes.visitor_route_target(run_id, name).as_deref(),
                reference_visitor_route_target(&flat, run_id, name).as_deref(),
                "visitor_route_target({run_id}, {name})"
            );
        }
    }
}

#[cfg(feature = "vnet")]
#[test]
fn vnet_routes_index_matches_reference_across_insert_and_remove() {
    let mut routes = VnetRoutes::new();
    // Two vnets, a multi-homed client, a same-named visitor in both vnets,
    // and a same-subnet key in two different vnets.
    routes.insert(
        ("vnet-a".to_string(), "10.0.0.0/24".to_string()),
        ("run-a".to_string(), "peer-a".to_string()),
    );
    routes.insert(
        ("vnet-a".to_string(), "10.99.0.0/24".to_string()),
        ("run-c".to_string(), "peer-a".to_string()), // same name, other run
    );
    routes.insert(
        ("vnet-b".to_string(), "10.0.0.0/24".to_string()),
        ("run-a".to_string(), "peer-b".to_string()),
    );
    routes.insert(
        ("vnet-b".to_string(), "10.1.0.0/24".to_string()),
        ("run-b".to_string(), "visitor".to_string()),
    );
    routes.insert(
        ("vnet-a".to_string(), "10.2.0.0/24".to_string()),
        ("run-b".to_string(), "visitor".to_string()),
    );
    // Default net (empty virtual_net) is a real key, not a wildcard.
    routes.insert(
        (String::new(), "10.3.0.0/24".to_string()),
        ("run-d".to_string(), "peer-d".to_string()),
    );
    assert_indexes_match_reference(&routes);
    // run-a advertises "peer-a" in vnet-a (run-c does too) and run-a is
    // itself the source here. The pre-index min() scan never excluded the
    // source's own route, so the smallest (vnet, run_id) candidate is
    // (vnet-a, run-a): self-target parity pinned.
    assert_eq!(
        routes.visitor_route_target("run-a", "peer-a").as_deref(),
        Some("run-a")
    );

    // Remove one route of a run_id that still owns others, then a whole
    // vnet's worth, then everything.
    routes.retain(|_, (run_id, _)| run_id != "run-c");
    assert_indexes_match_reference(&routes);
    assert_eq!(routes.run_route_count("run-c"), 0);
    assert!(!routes.has_route("run-c", "vnet-a", "peer-a"));
    assert!(!routes.source_allowed("run-c", "peer-a"));
    assert_eq!(routes.visitor_route_target("run-c", "peer-a"), None);

    routes.retain(|(vnet, _), _| vnet != "vnet-a");
    assert_indexes_match_reference(&routes);
    assert!(routes.vnet_members_of("vnet-a").is_none());
    assert!(!routes.has_route("run-a", "vnet-a", "peer-a"));
    // run-a survives in vnet-b.
    assert!(routes.has_route("run-a", "vnet-b", "peer-b"));
    assert_eq!(routes.run_route_count("run-a"), 1);

    routes.retain(|_, _| false);
    assert_indexes_match_reference(&routes);
    assert!(routes.is_empty());
    assert_eq!(routes.run_route_count("run-a"), 0);
    assert!(routes.visitor_route_target("run-a", "peer-a").is_none());
}

#[cfg(feature = "vnet")]
#[test]
fn vnet_routes_index_handles_takeover_and_name_change() {
    let mut routes = VnetRoutes::new();
    routes.insert(
        ("vnet-a".to_string(), "10.0.0.0/24".to_string()),
        ("run-old".to_string(), "proxy-old".to_string()),
    );
    routes.insert(
        ("vnet-a".to_string(), "10.0.1.0/24".to_string()),
        ("run-old".to_string(), "proxy-old".to_string()),
    );
    assert_eq!(routes.run_route_count("run-old"), 2);

    // Dead-owner takeover: the same (vnet, subnet) key re-registered by a
    // different run_id must move every index entry of THAT key to the new
    // owner — the stale owner must not keep counting the key. Its OTHER
    // routes (same vnet, same name) keep their shared index entries.
    let previous = routes.insert(
        ("vnet-a".to_string(), "10.0.0.0/24".to_string()),
        ("run-new".to_string(), "proxy-new".to_string()),
    );
    assert_eq!(
        previous,
        Some(("run-old".to_string(), "proxy-old".to_string())),
        "insert must return the displaced value (HashMap contract)"
    );
    assert_indexes_match_reference(&routes);
    assert_eq!(routes.run_route_count("run-old"), 1);
    assert_eq!(routes.run_route_count("run-new"), 1);
    // run-old still owns ("vnet-a", "10.0.1.0/24") under "proxy-old", so
    // its member and name entries survive the takeover.
    assert!(routes.has_route("run-old", "vnet-a", "proxy-old"));
    assert!(routes.has_route("run-new", "vnet-a", "proxy-new"));
    assert_eq!(
        routes
            .visitor_route_target("run-new", "proxy-new")
            .as_deref(),
        Some("run-new")
    );
    // "proxy-old" is still advertised (by run-old) in the vnet run-new
    // participates in.
    assert_eq!(
        routes
            .visitor_route_target("run-new", "proxy-old")
            .as_deref(),
        Some("run-old")
    );

    // Name change on the same key by the same run_id: the old proxy_name
    // must vanish from the name index.
    routes.insert(
        ("vnet-a".to_string(), "10.0.1.0/24".to_string()),
        ("run-old".to_string(), "renamed".to_string()),
    );
    assert_indexes_match_reference(&routes);
    assert_eq!(routes.run_route_count("run-old"), 1);
    assert!(!routes.has_route("run-old", "vnet-a", "proxy-old"));
    assert!(routes.has_route("run-old", "vnet-a", "renamed"));
    assert_eq!(
        routes.visitor_route_target("run-old", "renamed").as_deref(),
        Some("run-old")
    );
    assert_eq!(routes.visitor_route_target("run-old", "proxy-old"), None);

    // Removing the last route of a vnet drops the vnet's member set.
    routes.retain(|(vnet, subnet), _| !(vnet == "vnet-a" && subnet == "10.0.1.0/24"));
    assert_indexes_match_reference(&routes);
    assert_eq!(routes.run_route_count("run-old"), 0);
    assert!(routes.vnet_members_of("vnet-a").is_some()); // run-new still there
    routes.retain(|_, _| false);
    assert!(routes.vnet_members_of("vnet-a").is_none());
}

#[cfg(feature = "vnet")]
#[test]
fn vnet_routes_cap_count_survives_large_table() {
    // The per-client cap check is an O(1) counter now; pin that it tracks
    // a table far larger than the cap and stays correct after removals.
    let mut routes = VnetRoutes::new();
    for i in 0..300u32 {
        let run = format!("run-{}", i % 3);
        routes.insert(
            (
                "vnet-a".to_string(),
                format!("10.{}.{}.0/24", i / 256, i % 256),
            ),
            (run, format!("proxy-{i}")),
        );
    }
    assert_eq!(routes.run_route_count("run-0"), 100);
    assert_eq!(routes.run_route_count("run-1"), 100);
    assert_eq!(routes.run_route_count("run-2"), 100);
    assert_indexes_match_reference(&routes);
    routes.retain(|_, (run_id, _)| run_id != "run-1");
    assert_indexes_match_reference(&routes);
    assert_eq!(routes.run_route_count("run-1"), 0);
    assert_eq!(routes.len(), 200);
}

// --- ReplayTable tests (F3/F4) ---

/// ms-precision key, "now" for prune tests (>= MS_EPOCH).
const MS_NOW: i64 = 1_750_000_000_000;
const MS_TS: i64 = MS_NOW + 123;

#[test]
fn replay_table_dedup_rejects_ms_duplicate() {
    let mut t = ReplayTable::new();
    // ms-precision key (Rust frpc): an identical (run_id, ts) replay
    // is rejected.
    assert_eq!(t.record(MS_TS, "run-1"), ReplayCheck::Admitted);
    assert_eq!(t.total(), 1);
    assert_eq!(t.record(MS_TS, "run-1"), ReplayCheck::Replay);
    assert_eq!(t.total(), 1, "duplicates must not count as new entries");
    // Distinct run_ids at the same timestamp are fine.
    assert_eq!(t.record(MS_TS, "run-2"), ReplayCheck::Admitted);
    assert_eq!(t.total(), 2);
}

#[test]
fn replay_table_seconds_duplicate_is_admitted() {
    // Go frpc reuses its run_id and sends seconds keys: a reconnect
    // in the same wall-clock second is indistinguishable from a replay
    // and must be admitted (freshness window still bounds real replays).
    let mut t = ReplayTable::new();
    let ts = MS_NOW / 1000; // < MS_EPOCH
    assert_eq!(t.record(ts, "run-1"), ReplayCheck::Admitted);
    assert_eq!(
        t.record(ts, "run-1"),
        ReplayCheck::DuplicateSecondsPrecision
    );
}

#[test]
fn replay_table_duplicate_at_global_cap_does_not_evict() {
    // S5: the duplicate check runs BEFORE the global-cap eviction — a
    // replayed (ts, run_id) at (or over) the cap must return Replay
    // without evicting anything. Otherwise an attacker replaying one
    // captured pair could repeatedly evict fresh keys, shrinking the
    // replay window.
    let mut t = ReplayTable::new();
    let n_ts = MAX_TOTAL_REPLAY_ENTRIES / MAX_ENTRIES_PER_TIMESTAMP;
    for ts_i in 0..n_ts {
        let ts = MS_NOW + ts_i as i64;
        for i in 0..MAX_ENTRIES_PER_TIMESTAMP {
            assert_eq!(
                t.record(ts, &format!("run-{ts_i}-{i}")),
                ReplayCheck::Admitted
            );
        }
    }
    assert_eq!(t.total(), MAX_TOTAL_REPLAY_ENTRIES);
    let before = t.total();
    let oldest_ts = MS_NOW; // still present at the cap
    assert!(t.map.contains_key(&oldest_ts));

    // A duplicate of the OLDEST still-present key: rejected, and
    // neither the table nor any key is touched.
    assert_eq!(t.record(oldest_ts, "run-0-0"), ReplayCheck::Replay);
    assert_eq!(t.total(), before, "replay must not evict at the cap");
    assert!(t.map.contains_key(&oldest_ts));
    assert_eq!(t.map[&oldest_ts].len(), MAX_ENTRIES_PER_TIMESTAMP);
    // The victim's coverage is intact: a fresh run_id at that key is
    // still admitted — the whole oldest timestamp key is evicted
    // first (global cap), so the fresh entry lands in an empty bucket.
    assert_eq!(
        t.record(oldest_ts, "run-new"),
        ReplayCheck::Admitted,
        "non-duplicate logins still admitted at the cap"
    );
}

#[test]
fn replay_table_prunes_future_timestamps() {
    // Round 6 (LOW B7): timestamps ahead of now sort to the map tail
    // and must be pruned, not parked where they squeeze legitimate
    // entries in the global cap's eviction order. (Keys further ahead
    // than the freshness window never reach record — the login is
    // rejected first.)
    let mut t = ReplayTable::new();
    let now_ms = 2_000_000_000_000i64; // epoch-ms anchor
    let now_s = now_ms / 1000;
    // stale (age-pruned, beyond the 10s window), live (kept), future
    // (B7-pruned)
    t.record(now_ms - 15_000, "old");
    t.record(now_ms, "live");
    t.record(now_ms + 3000, "future");
    let pruned = t.prune_expired(now_ms, 10);
    assert_eq!(pruned, 2, "stale + future key pruned");
    assert_eq!(t.total(), 1);
    assert!(t.map.contains_key(&now_ms));
    // Seconds domain (Go frpc keys) gets the same tail treatment.
    let mut t2 = ReplayTable::new();
    t2.record(now_s, "live-s");
    t2.record(now_s + 5, "future-s");
    t2.prune_expired(now_ms, 10);
    assert_eq!(t2.total(), 1);
    assert!(t2.map.contains_key(&now_s));
}

#[test]
fn replay_table_per_timestamp_cap_evicts_oldest_and_admits() {
    // 101 distinct run_ids at the same timestamp: ALL admitted (F3 —
    // the old behavior rejected every login at a full key, locking
    // out a legitimate same-run_id reconnect), with the OLDEST run_id
    // evicted to keep the set bounded.
    let mut t = ReplayTable::new();
    for i in 0..MAX_ENTRIES_PER_TIMESTAMP {
        assert_eq!(
            t.record(MS_TS, &format!("run-{i:03}")),
            ReplayCheck::Admitted
        );
    }
    assert_eq!(t.total(), MAX_ENTRIES_PER_TIMESTAMP);
    assert_eq!(
        t.record(MS_TS, "run-100"),
        ReplayCheck::Admitted,
        "cap-hit must evict, not reject"
    );
    let entry = &t.map[&MS_TS];
    assert_eq!(entry.len(), MAX_ENTRIES_PER_TIMESTAMP);
    // The first-inserted run_id was evicted; the newest is kept.
    assert!(
        !entry.iter().any(|r| r == "run-000"),
        "oldest run_id must be evicted, got: {entry:?}"
    );
    assert!(entry.iter().any(|r| r == "run-100"));
    // The evicted run_id loses dedup coverage only; in-set run_ids
    // still replay, and the total stays consistent through the
    // evict+insert cycle.
    assert_eq!(t.record(MS_TS, "run-001"), ReplayCheck::Replay);
    assert_eq!(t.record(MS_TS, "run-000"), ReplayCheck::Admitted);
    assert_eq!(t.total(), MAX_ENTRIES_PER_TIMESTAMP);
}

#[test]
fn replay_table_global_cap_evicts_oldest_keys_and_keeps_recent_dedup() {
    // Fill the table to the global cap (100 run_ids per timestamp ×
    // 1000 timestamps), then record one more login at a NEW timestamp.
    // The OLDEST whole timestamp keys are evicted and the new login is
    // admitted (F4 — the old behavior degraded to freshness-only dedup
    // for ALL clients instead of evicting).
    let mut t = ReplayTable::new();
    let n_ts = MAX_TOTAL_REPLAY_ENTRIES / MAX_ENTRIES_PER_TIMESTAMP;
    for ts_i in 0..n_ts {
        let ts = MS_NOW + ts_i as i64;
        for i in 0..MAX_ENTRIES_PER_TIMESTAMP {
            assert_eq!(
                t.record(ts, &format!("run-{ts_i}-{i}")),
                ReplayCheck::Admitted
            );
        }
    }
    assert_eq!(t.total(), MAX_TOTAL_REPLAY_ENTRIES);

    let newest_ts = MS_NOW + n_ts as i64;
    assert_eq!(t.record(newest_ts, "run-new"), ReplayCheck::Admitted);
    assert!(
        t.total() <= MAX_TOTAL_REPLAY_ENTRIES,
        "total must stay bounded after cap eviction"
    );
    assert!(t.map.contains_key(&newest_ts));
    // The oldest timestamp key was evicted (the next-oldest stays —
    // eviction drains one key per record, just enough to admit the
    // new login)...
    assert!(!t.map.contains_key(&MS_NOW));
    assert!(
        t.map.contains_key(&(MS_NOW + 1)),
        "eviction must drain the oldest keys first"
    );
    // ...and dedup STILL works for a recent key — the security
    // property the old global-degrade path lost.
    assert_eq!(
        t.record(newest_ts, "run-new"),
        ReplayCheck::Replay,
        "in-window timestamps must keep duplicate detection after cap eviction"
    );
}

#[test]
fn replay_table_prune_drains_expired_keys_and_keeps_total_consistent() {
    let mut t = ReplayTable::new();
    // Expired seconds keys (Go frpc): 200s ago.
    t.record(MS_NOW / 1000 - 200, "old-sec-1");
    t.record(MS_NOW / 1000 - 200, "old-sec-2");
    // Live seconds key: 30s ago.
    t.record(MS_NOW / 1000 - 30, "live-sec");
    // Expired ms key (Rust frpc): 200s ago — sorts AFTER the live
    // seconds key, which is the two-precision-domain trap the prune
    // must handle (a single leading-key break on the first live key
    // would miss it).
    t.record(MS_NOW - 200_000, "old-ms");
    // Live ms key.
    t.record(MS_NOW - 30_000, "live-ms");
    assert_eq!(t.total(), 5);

    let pruned = t.prune_expired(MS_NOW, 90);
    assert_eq!(pruned, 3, "two old seconds keys + one old ms key");
    assert_eq!(t.total(), 2, "total counter must track the prune");
    assert!(!t.map.contains_key(&(MS_NOW / 1000 - 200)));
    assert!(!t.map.contains_key(&(MS_NOW - 200_000)));
    assert!(t.map.contains_key(&(MS_NOW / 1000 - 30)));
    assert!(t.map.contains_key(&(MS_NOW - 30_000)));
    // After the prune, dedup still works for the surviving keys.
    assert_eq!(t.record(MS_NOW - 30_000, "live-ms"), ReplayCheck::Replay);
    assert_eq!(t.total(), 2);
}

// --- Login throttle tests (check_login_throttle) ---
//
// check_login_throttle keys on `addr.ip()` and reads std::time::Instant,
// which tokio's test-util clock does NOT mock: `tokio::time::pause` /
// `advance` only affect tokio::time utilities, and clock.rs's mocked
// `now()` falls through to real std::time::Instant for everything else.
// The 60s-window and 90s-cleanup branches are therefore exercised by
// seeding stale `window_start` values directly into the (pub) throttle
// maps — deterministic, no 60s real sleeps, and it hits the exact
// `duration_since(window_start)` comparisons the production paths use.

#[tokio::test]
async fn check_login_throttle_five_allowed_then_sixth_rejected() {
    let state = test_state();
    let addr = |port: u16| std::net::SocketAddr::from(([127, 0, 0, 1], port));
    // 5 attempts per 60s window per IP; distinct ports still hit the
    // same per-IP bucket (keyed by addr.ip()).
    for port in 1..=5 {
        assert!(
            state.check_login_throttle(addr(port)).await,
            "attempt {port} must be allowed"
        );
    }
    assert!(
        !state.check_login_throttle(addr(6)).await,
        "6th attempt must be throttled"
    );
    // Same IP, different port: still throttled (per-IP, not per-addr).
    assert!(!state.check_login_throttle(addr(7)).await);
    // The pre-auth gate (is_login_throttled) mirrors the same table
    // state; a missing peer address is never throttled.
    assert!(state.is_login_throttled(Some(addr(8))).await);
    assert!(!state.is_login_throttled(None).await);
    // A different IP is unaffected by the throttled one.
    assert!(
        state
            .check_login_throttle(std::net::SocketAddr::from(([127, 0, 0, 2], 1)))
            .await
    );
}

#[tokio::test]
async fn check_login_throttle_window_expiry_resets_count() {
    let state = test_state();
    let ip = std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1));
    let addr = |port: u16| std::net::SocketAddr::from((ip, port));
    // Seed a stale entry: 5 failures whose 60s window started 61s ago.
    {
        let mut t = state.login_throttle.lock().await;
        t.insert(
            ip,
            (
                5,
                std::time::Instant::now() - std::time::Duration::from_secs(61),
            ),
        );
    }
    // Window expired → attempt allowed, count resets to 1.
    assert!(state.check_login_throttle(addr(1)).await);
    // Fresh window: 4 more allowed (counts 2..=5), then throttled.
    for port in 2..=5 {
        assert!(
            state.check_login_throttle(addr(port)).await,
            "post-reset attempt {port} must be allowed"
        );
    }
    assert!(!state.check_login_throttle(addr(6)).await);
    // A full count INSIDE its window stays throttled (no reset).
    let ip2 = std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 9));
    {
        let mut t = state.login_throttle.lock().await;
        t.insert(
            ip2,
            (
                5,
                std::time::Instant::now() - std::time::Duration::from_secs(1),
            ),
        );
    }
    assert!(
        !state
            .check_login_throttle(std::net::SocketAddr::from((ip2, 1)))
            .await
    );
}

#[tokio::test]
async fn check_login_throttle_cleanup_removes_entries_older_than_90s() {
    let state = test_state();
    let stale_ip = std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 77));
    let fresh_ip = std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 78));
    {
        let mut t = state.login_throttle.lock().await;
        t.insert(
            stale_ip,
            (
                5,
                std::time::Instant::now() - std::time::Duration::from_secs(91),
            ),
        );
        t.insert(fresh_ip, (1, std::time::Instant::now()));
    }
    // Any call runs the inline cleanup (90s grace) — the stale entry
    // must go, the fresh one must survive.
    assert!(
        state
            .check_login_throttle(std::net::SocketAddr::from(([127, 0, 0, 79], 1)))
            .await
    );
    let t = state.login_throttle.lock().await;
    assert!(!t.contains_key(&stale_ip), "91s-old entry must be cleaned");
    assert!(t.contains_key(&fresh_ip), "fresh entry must survive");
}

#[tokio::test]
async fn check_login_throttle_overflow_bucket_caps_untracked_ips() {
    let state = test_state();
    // Fill the main table to the 512-entry cap with distinct IPs.
    for i in 0u16..512 {
        let ip = std::net::IpAddr::V4(std::net::Ipv4Addr::new(
            127,
            (i >> 8) as u8,
            (i & 0xff) as u8,
            1,
        ));
        assert!(
            state
                .check_login_throttle(std::net::SocketAddr::from((ip, 1)))
                .await
        );
    }
    {
        let t = state.login_throttle.lock().await;
        assert_eq!(t.len(), 512, "main table must be full at the cap");
    }
    // A TRACKED IP still uses the main table (not the coarse overflow).
    let tracked = std::net::SocketAddr::from(([127, 0, 0, 1], 1));
    assert!(state.check_login_throttle(tracked).await);
    // An untracked IP hits the overflow bucket: 50 allowed, then false.
    let untracked = std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 99, 0, 1));
    for i in 1..=50 {
        assert!(
            state
                .check_login_throttle(std::net::SocketAddr::from((untracked, i)))
                .await,
            "overflow attempt {i} must be allowed"
        );
    }
    assert!(
        !state
            .check_login_throttle(std::net::SocketAddr::from((untracked, 51)))
            .await,
        "51st overflow attempt must be throttled"
    );
    // The pre-auth gate sees the coarse cap too.
    assert!(
        state
            .is_login_throttled(Some(std::net::SocketAddr::from((untracked, 52))))
            .await
    );
    // Overflow window expiry resets the coarse counter (count -> 1).
    {
        let mut o = state.login_throttle_overflow.lock().await;
        o.get_mut(&untracked).expect("overflow entry").1 =
            std::time::Instant::now() - std::time::Duration::from_secs(61);
    }
    assert!(
        state
            .check_login_throttle(std::net::SocketAddr::from((untracked, 53)))
            .await,
        "expired overflow window must reset the counter"
    );
    // 49 more allowed after the reset (counts 2..=50)...
    for i in 54..=102 {
        assert!(
            state
                .check_login_throttle(std::net::SocketAddr::from((untracked, i)))
                .await,
            "post-reset overflow attempt {i} must be allowed"
        );
    }
    // ...then capped again.
    assert!(
        !state
            .check_login_throttle(std::net::SocketAddr::from((untracked, 103)))
            .await
    );
}

// F11: the overflow bucket must be BOUNDED. The main table caps at 512
// and the 90s retain only removes TIME-expired rows, so the overflow
// bucket previously grew without limit under a sustained flood of fresh
// source IPs (~4096+ rows per 90s forever). A cap with oldest-eviction
// (ReplayTable precedent) bounds total per-IP state at
// MAX_THROTTLE_ENTRIES + OVERFLOW_CAP; per-IP 50/60s semantics are
// unchanged.
#[tokio::test]
async fn check_login_throttle_overflow_bucket_bounded_under_ip_burst() {
    let state = test_state();
    // Fill the main table to its 512-entry cap with distinct IPs.
    for i in 0u16..512 {
        let ip = std::net::IpAddr::V4(std::net::Ipv4Addr::new(
            10,
            (i >> 8) as u8,
            (i & 0xff) as u8,
            1,
        ));
        assert!(
            state
                .check_login_throttle(std::net::SocketAddr::from((ip, 1)))
                .await
        );
    }
    // Burst ~6200 more distinct IPs (all inside the 90s retain window —
    // the whole burst runs in milliseconds). Pre-fix the overflow
    // bucket kept every one of them.
    let mut newest = std::net::IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0));
    for i in 512u32..=6800 {
        let ip = std::net::IpAddr::V4(std::net::Ipv4Addr::new(
            172,
            (i >> 16) as u8,
            ((i >> 8) & 0xff) as u8,
            (i & 0xff) as u8,
        ));
        assert!(
            state
                .check_login_throttle(std::net::SocketAddr::from((ip, 1)))
                .await,
            "first attempt of burst IP {i} must be allowed"
        );
        newest = ip;
    }
    {
        let t = state.login_throttle.lock().await;
        assert_eq!(t.len(), 512, "main table must stay at its cap");
    }
    let o = state.login_throttle_overflow.lock().await;
    assert!(
        o.len() <= 4096,
        "overflow bucket must be capped at 4096 entries, got {}",
        o.len()
    );
    assert!(
        o.contains_key(&newest),
        "the newest burst IP must survive (just admitted)"
    );
}

// F11: eviction at the cap must remove the OLDEST entry (earliest
// window_start), never an arbitrary/newer one — the flood victim is
// always the entry whose throttle state is closest to expiry.
#[tokio::test]
async fn check_login_throttle_overflow_at_cap_evicts_oldest() {
    let state = test_state();
    // Fill the main table so untracked IPs fall into the overflow
    // bucket.
    for i in 0u16..512 {
        let ip = std::net::IpAddr::V4(std::net::Ipv4Addr::new(
            10,
            (i >> 8) as u8,
            (i & 0xff) as u8,
            1,
        ));
        state
            .check_login_throttle(std::net::SocketAddr::from((ip, 1)))
            .await;
    }
    // Seed the overflow bucket AT the cap (4096) with staggered
    // timestamps all inside the 90s retain window: entry i is
    // 2s + i*20ms old → entry 4095 (83.9s old) is the oldest and must
    // be the eviction victim.
    let now = std::time::Instant::now();
    {
        let mut o = state.login_throttle_overflow.lock().await;
        for i in 0..4096u32 {
            let ip = std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                172,
                16 + (i >> 8) as u8,
                (i & 0xff) as u8,
                1,
            ));
            o.insert(
                ip,
                (
                    1,
                    now - std::time::Duration::from_millis(2000 + 20 * i as u64),
                ),
            );
        }
    }
    let new_ip = std::net::IpAddr::V4(std::net::Ipv4Addr::new(172, 32, 0, 1));
    assert!(
        state
            .check_login_throttle(std::net::SocketAddr::from((new_ip, 1)))
            .await,
        "new IP must be admitted at the cap (evict-oldest)"
    );
    let o = state.login_throttle_overflow.lock().await;
    assert_eq!(o.len(), 4096, "cap must hold: one eviction per admission");
    assert!(o.contains_key(&new_ip), "new IP must be present");
    let oldest = std::net::IpAddr::V4(std::net::Ipv4Addr::new(172, 31, 255, 1));
    assert!(
        !o.contains_key(&oldest),
        "the oldest entry (i=4095) must be the eviction victim"
    );
    let newest_seed = std::net::IpAddr::V4(std::net::Ipv4Addr::new(172, 16, 0, 1));
    assert!(
        o.contains_key(&newest_seed),
        "the newest seeded entry (i=0) must survive"
    );
}

// F11: at-cap admission must FIRST sweep 90s-expired rows so live
// entries are only evicted when the bucket is genuinely full of fresh
// state.
#[tokio::test]
async fn check_login_throttle_overflow_at_cap_cleans_stale_before_evicting() {
    let state = test_state();
    for i in 0u16..512 {
        let ip = std::net::IpAddr::V4(std::net::Ipv4Addr::new(
            10,
            (i >> 8) as u8,
            (i & 0xff) as u8,
            1,
        ));
        state
            .check_login_throttle(std::net::SocketAddr::from((ip, 1)))
            .await;
    }
    let now = std::time::Instant::now();
    {
        let mut o = state.login_throttle_overflow.lock().await;
        // 100 stale rows (>90s old, would be retained forever pre-fix
        // without an at-cap sweep)...
        for i in 0..100u32 {
            let ip = std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                172,
                16 + (i >> 8) as u8,
                (i & 0xff) as u8,
                1,
            ));
            o.insert(
                ip,
                (
                    50,
                    now - std::time::Duration::from_millis(91_000 + 20 * i as u64),
                ),
            );
        }
        // ...and 3996 live rows fill the rest of the cap.
        for i in 100..4096u32 {
            let ip = std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                172,
                16 + (i >> 8) as u8,
                (i & 0xff) as u8,
                1,
            ));
            o.insert(ip, (1, now - std::time::Duration::from_secs(10)));
        }
    }
    let new_ip = std::net::IpAddr::V4(std::net::Ipv4Addr::new(172, 32, 0, 1));
    assert!(
        state
            .check_login_throttle(std::net::SocketAddr::from((new_ip, 1)))
            .await,
        "new IP must be admitted via the stale sweep (no live eviction needed)"
    );
    let o = state.login_throttle_overflow.lock().await;
    assert_eq!(
        o.len(),
        4096 - 100 + 1,
        "stale rows must be swept at cap pressure before any admission"
    );
    assert!(o.contains_key(&new_ip));
    // A live row must NOT have been evicted (the sweep made room).
    let live = std::net::IpAddr::V4(std::net::Ipv4Addr::new(172, 17, 0, 1));
    assert!(o.contains_key(&live), "live rows must survive the sweep");
    let stale = std::net::IpAddr::V4(std::net::Ipv4Addr::new(172, 16, 0, 1));
    assert!(!o.contains_key(&stale), "91s+ rows must be swept");
}
// M2: tcpmux group fan-out (Go frp v0.71.0 group.TCPMuxGroup). Second
// members join after Go-order validation (params → "group params
// invalid", key → "group auth failed", both verbatim); the route owner
// is the first member and surfaces only when the group empties;
// choose_endpoint round-robins.
#[tokio::test]
async fn tcpmux_group_controller_join_validation_and_round_robin() {
    let ctl = TcpMuxGroupController::new();

    // First member creates the group.
    let (g, first) = ctl
        .register_member(
            "web",
            "k1",
            "tunnel.example.com",
            "",
            "user",
            "pwd",
            "mux-a",
        )
        .await
        .expect("first member must create the group");
    assert!(first);
    assert_eq!(g.route_owner, "mux-a");

    // Second member, identical params + key → joins.
    let (_, first) = ctl
        .register_member(
            "web",
            "k1",
            "tunnel.example.com",
            "",
            "user",
            "pwd",
            "mux-b",
        )
        .await
        .expect("matching second member must join");
    assert!(!first);

    // Round-robin: 3 picks alternate mux-a, mux-b, mux-a.
    assert_eq!(ctl.choose_endpoint("web").await.as_deref(), Some("mux-a"));
    assert_eq!(ctl.choose_endpoint("web").await.as_deref(), Some("mux-b"));
    assert_eq!(ctl.choose_endpoint("web").await.as_deref(), Some("mux-a"));

    // Go ErrGroupParamsInvalid: params checked BEFORE the key — a
    // user/pwd mismatch rejects verbatim even with the right key.
    let err = ctl
        .register_member(
            "web",
            "k1",
            "tunnel.example.com",
            "",
            "user",
            "OTHER",
            "mux-c",
        )
        .await
        .expect_err("password mismatch must reject");
    assert_eq!(err, "group params invalid");
    let err = ctl
        .register_member("web", "k1", "other.example.com", "", "user", "pwd", "mux-c")
        .await
        .expect_err("domain mismatch must reject");
    assert_eq!(err, "group params invalid");
    // Go ErrGroupAuthFailed: same params, wrong key.
    let err = ctl
        .register_member(
            "web",
            "WRONG",
            "tunnel.example.com",
            "",
            "user",
            "pwd",
            "mux-c",
        )
        .await
        .expect_err("group_key mismatch must reject");
    assert_eq!(err, "group auth failed");
    // Duplicate member.
    let err = ctl
        .register_member(
            "web",
            "k1",
            "tunnel.example.com",
            "",
            "user",
            "pwd",
            "mux-b",
        )
        .await
        .expect_err("duplicate member must reject");
    assert!(err.contains("already a member"), "err: {err}");

    // Member close (non-owner): group survives, owner still registered.
    assert_eq!(
        ctl.unregister_member("web", "mux-b").await,
        None,
        "group with a remaining member must not return the owner"
    );
    assert_eq!(
        ctl.choose_endpoint("web").await.as_deref(),
        Some("mux-a"),
        "surviving owner keeps serving"
    );

    // Owner close empties the group → owner surfaces for route removal,
    // and the group is gone (choose_endpoint → None).
    assert_eq!(
        ctl.unregister_member("web", "mux-a").await.as_deref(),
        Some("mux-a"),
        "emptying the group must surface the route owner"
    );
    assert_eq!(ctl.choose_endpoint("web").await, None);
}
