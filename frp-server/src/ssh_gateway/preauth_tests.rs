use super::*;

/// Production-shape acquire (ssh_gateway.rs accept loop): look up or
/// create the IP's semaphore, then take one permit under the same lock.
fn acquire(map: &std::sync::Arc<PerIpPreauthMap>, ip: std::net::IpAddr) -> PreauthPermit {
    let mut map_guard = map.lock().unwrap_or_else(|e| e.into_inner());
    let sem = map_guard
        .entry(ip)
        .or_insert_with(|| std::sync::Arc::new(tokio::sync::Semaphore::new(SSH_PREAUTH_PER_IP_CAP)))
        .clone();
    PreauthPermit {
        ip,
        map: map.clone(),
        sem: sem.clone(),
        permit: Some(sem.try_acquire_owned().expect("cap 8, test acquires ≤ 8")),
    }
}

fn entry_count(map: &std::sync::Arc<PerIpPreauthMap>) -> usize {
    map.lock().unwrap_or_else(|e| e.into_inner()).len()
}

#[test]
fn preauth_map_entry_lives_until_last_permit_release() {
    let map: std::sync::Arc<PerIpPreauthMap> = std::sync::Arc::default();
    let ip: std::net::IpAddr = "127.0.0.1".parse().unwrap();

    // 8 permits pin the entry; a partial release keeps it (the IP may
    // still have pre-auth conns in flight).
    let mut permits: Vec<PreauthPermit> = (0..SSH_PREAUTH_PER_IP_CAP)
        .map(|_| acquire(&map, ip))
        .collect();
    assert_eq!(
        entry_count(&map),
        1,
        "IP with outstanding permits must hold its entry"
    );
    drop(permits.pop().unwrap());
    assert_eq!(
        entry_count(&map),
        1,
        "a non-final release must NOT remove the entry"
    );

    // The final release empties the semaphore -> entry removed.
    drop(permits);
    assert_eq!(entry_count(&map), 0, "final release must remove the entry");

    // Churn: acquire again after removal re-creates the entry, and a
    // drop-empty cycle leaves the map clean.
    let p = acquire(&map, ip);
    assert_eq!(entry_count(&map), 1);
    drop(p);
    assert_eq!(entry_count(&map), 0);
}

#[test]
fn preauth_stale_permit_cannot_remove_new_entry() {
    let map: std::sync::Arc<PerIpPreauthMap> = std::sync::Arc::default();
    let ip: std::net::IpAddr = "127.0.0.1".parse().unwrap();

    // A stale permit: its semaphore was replaced in the map (the map
    // entry emptied and a fresh acquire re-created it while the old
    // permit was still outstanding — possible across the release of
    // the LAST other permit, see the acquire-then-drop race the
    // ptr_eq guard closes).
    let stale = acquire(&map, ip);
    // Simulate the re-insertion: swap in a brand-new semaphore.
    let fresh_sem = {
        let mut guard = map.lock().unwrap_or_else(|e| e.into_inner());
        guard.insert(
            ip,
            std::sync::Arc::new(tokio::sync::Semaphore::new(SSH_PREAUTH_PER_IP_CAP)),
        )
    };
    // A fresh permit on the new entry.
    let fresh = {
        let guard = map.lock().unwrap_or_else(|e| e.into_inner());
        let sem = guard.get(&ip).unwrap().clone();
        PreauthPermit {
            ip,
            map: map.clone(),
            sem: sem.clone(),
            permit: Some(sem.try_acquire_owned().expect("fresh entry, cap 8")),
        }
    };
    drop(fresh_sem); // the replaced Arc (already in the map via `fresh`)

    // Dropping the STALE permit must not remove the fresh entry — its
    // semaphore is a different Arc (ptr_eq guard).
    drop(stale);
    assert_eq!(
        entry_count(&map),
        1,
        "a stale permit must not remove a re-inserted entry"
    );
    drop(fresh);
    assert_eq!(
        entry_count(&map),
        0,
        "the fresh permit's release removes it"
    );
}
