use super::*;
use std::time::Instant;

/// Minimal AsyncWrite capture for tests: every written byte lands in a
/// shared buffer for post-hoc assertions on the NewProxyResp payload.
#[derive(Default)]
struct CaptureWriter {
    buf: Arc<std::sync::Mutex<Vec<u8>>>,
}

impl tokio::io::AsyncWrite for CaptureWriter {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        self.buf.lock().unwrap().extend_from_slice(buf);
        std::task::Poll::Ready(Ok(buf.len()))
    }
    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }
    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }
}

fn auto_assign_tcp_np(proxy_name: &str) -> msg::NewProxy {
    msg::NewProxy {
        proxy_name: proxy_name.to_string(),
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
    }
}

/// The auto-assign bind race, proven end-to-end with real sockets:
///
/// 1. Hold `used_ports` READ — the allocator's OS probe runs OUTSIDE
///    any lock, so the registration task probes the first candidate
///    (port `stolen`, free at that moment) and then parks on the
///    commit WRITE lock.
/// 2. Bind `stolen` ourselves — the thief — exactly in the window
///    between probe and bind that a second frps instance would hit.
/// 3. Drop the READ guard: allocation commits the probed port,
///    registration runs, and the bind fails EADDRINUSE.
/// 4. The retry must roll the registration back, clear the 24h
///    reservation, re-allocate a FRESH port, re-register, and accept —
///    with the NewProxyResp carrying the fresh port.
#[tokio::test]
async fn auto_assign_bind_steal_retries_with_fresh_port() {
    let state = super::unregister_generation_tests::test_state();
    // A controlled range makes the first candidate deterministic.
    {
        let mut reloadable = state.reloadable.write().unwrap();
        reloadable.allow_ports = Arc::new(vec![frp_core::config::PortsRange {
            start: 61000,
            end: 61099,
            single: 0,
        }]);
    }
    // First candidate = first bindable port in the range.
    let stolen = (61000u16..61100)
        .find(|p| crate::proxy::is_tcp_port_bindable("127.0.0.1", *p))
        .expect("test range 61000-61099 must contain a free port");
    // Seed the 24h reservation: a re-registration within 24h of a close
    // would otherwise hand the SAME stolen port back on re-allocation.
    state
        .port_reservations
        .write()
        .await
        .insert("p1".to_string(), (stolen, false, Instant::now()));

    let np = auto_assign_tcp_np("p1");
    let buf = Arc::new(std::sync::Mutex::new(Vec::new()));
    let mut writer = CaptureWriter { buf: buf.clone() };
    let (itx, _irx) = tokio::sync::mpsc::channel(8);
    let mut listener_handles = std::collections::HashMap::new();
    let mut udp_sockets = std::collections::HashMap::new();

    // The seam: hold the used_ports READ lock. The allocator's commit
    // needs the WRITE lock, so the registration task parks there AFTER
    // probing `stolen` (free) — the thief then binds it in the
    // probe→bind window.
    let guard = state.used_ports.read().await;
    let st = state.clone();
    let np2 = np.clone();
    let task = tokio::spawn(async move {
        handle_new_proxy(
            np2,
            "run1",
            1,
            &st,
            &mut writer,
            &itx,
            &mut listener_handles,
            &mut udp_sockets,
            false,
        )
        .await
    });
    // Run the registration task to its first suspension (the commit
    // WRITE lock — it cannot proceed while the READ guard is held, and
    // nothing before the commit is contended). The OS probe itself now
    // runs on the spawn_blocking pool (r3/server#1), so plain yield_now
    // cannot observe its completion: warm the pool, then give the
    // blocking thread real time to finish the probe (a microsecond bind
    // after pool warm-up; 50ms is a wide margin) before the thief binds.
    tokio::task::spawn_blocking(|| {}).await.unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let thief = std::net::TcpListener::bind(("127.0.0.1", stolen)).expect("thief bind");
    drop(guard);

    let accepted = task.await.expect("registration task must not panic");
    assert!(
        accepted,
        "auto-assign TCP proxy must be accepted after the steal retry"
    );
    drop(thief);

    // NewProxyResp must carry the FRESH port, never the stolen one.
    let resp = String::from_utf8_lossy(&buf.lock().unwrap()).to_string();
    assert!(
        !resp.contains(&format!(":{stolen}")),
        "resp must not carry the stolen port {stolen}: {resp}"
    );
    // Registry entry holds the final port; every structure agrees.
    let info = state
        .proxy_manager
        .get("p1")
        .await
        .expect("proxy must be registered after the retry");
    let final_port = info
        .remote_port
        .expect("TCP proxy must hold a port after the retry");
    assert_ne!(
        final_port, stolen,
        "the fresh port must differ from the stolen one"
    );
    assert!(
        resp.contains(&format!(":{final_port}")),
        "resp must carry the re-allocated port {final_port}: {resp}"
    );
    let used = state.used_ports.read().await;
    assert!(
        used.contains(&final_port),
        "used_ports must hold the fresh port"
    );
    assert!(
        !used.contains(&stolen),
        "used_ports must release the stolen port"
    );
    drop(used);
    assert!(
        !state.port_reservations.read().await.contains_key("p1"),
        "the 24h reservation for 'p1' must be cleared by the retry"
    );
    assert_eq!(info.remote_port, Some(final_port));
}

/// The Go-parity guard: an EXPLICIT remote_port bind conflict must keep
/// the immediate reject — no re-allocation, no "silently different
/// port" response to a client that asked for a specific port. Uses the
/// same probe→bind seam as the auto-assign test so the conflict lands
/// on the bind itself (a thief binding BEFORE allocation is caught by
/// the OS probe, which is also a reject — the stronger case is the
/// bind-time steal, which must NOT trigger the retry for explicit
/// ports).
#[tokio::test]
async fn explicit_port_bind_steal_rejects_immediately() {
    let state = super::unregister_generation_tests::test_state();
    {
        let mut reloadable = state.reloadable.write().unwrap();
        reloadable.allow_ports = Arc::new(vec![frp_core::config::PortsRange {
            start: 61100,
            end: 61199,
            single: 0,
        }]);
    }
    let requested = (61100u16..61200)
        .find(|p| crate::proxy::is_tcp_port_bindable("127.0.0.1", *p))
        .expect("test range 61100-61199 must contain a free port");

    let mut np = auto_assign_tcp_np("p2");
    np.remote_port = Some(requested as i32);
    let buf = Arc::new(std::sync::Mutex::new(Vec::new()));
    let mut writer = CaptureWriter { buf: buf.clone() };
    let (itx, _irx) = tokio::sync::mpsc::channel(8);
    let mut listener_handles = std::collections::HashMap::new();
    let mut udp_sockets = std::collections::HashMap::new();

    let guard = state.used_ports.read().await;
    let st = state.clone();
    let np2 = np.clone();
    let task = tokio::spawn(async move {
        handle_new_proxy(
            np2,
            "run1",
            1,
            &st,
            &mut writer,
            &itx,
            &mut listener_handles,
            &mut udp_sockets,
            false,
        )
        .await
    });
    // Same probe→bind seam as the auto-assign test: warm the
    // spawn_blocking pool and let the probe finish before the thief
    // binds, so the steal lands on the bind itself.
    tokio::task::spawn_blocking(|| {}).await.unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let thief = std::net::TcpListener::bind(("127.0.0.1", requested)).expect("thief bind");
    drop(guard);

    let accepted = task.await.expect("registration task must not panic");
    drop(thief);

    assert!(
        !accepted,
        "explicit-port bind conflict must reject immediately (Go parity)"
    );
    let resp = String::from_utf8_lossy(&buf.lock().unwrap()).to_string();
    assert!(
        resp.contains("TCP bind failed"),
        "rejection must carry the TCP bind failure: {resp}"
    );
    assert!(
        state.proxy_manager.get("p2").await.is_none(),
        "a rejected explicit-port proxy must not be registered"
    );
    let used = state.used_ports.read().await;
    assert!(
        !used.contains(&requested),
        "the conflicted port must be released"
    );
}

/// P8 (audit round 2) regression tests: every port-allocation failure
/// must reach the client with the Go frp v0.71.0 branch-mapped text
/// (server/ports/ports.go:22-27) instead of collapsing into one
/// "no available port". Go's Acquire maps: an explicit port already
/// used → ErrPortAlreadyUsed; an explicit port outside every
/// allow_ports range → ErrPortNotAllowed; an in-range explicit port
/// whose OS bind probe fails → ErrPortUnAvailable; auto-assign
/// exhaustion → ErrNoAvailablePort.
mod port_error_text_tests {
    use super::super::*;
    use super::{auto_assign_tcp_np, CaptureWriter};

    /// Drive the real handler: rejection text lands in the captured
    /// NewProxyResp. Returns (accepted, response bytes as text).
    async fn register_and_reject(state: &Arc<AppState>, np: msg::NewProxy) -> (bool, String) {
        let buf = Arc::new(std::sync::Mutex::new(Vec::new()));
        let mut writer = CaptureWriter { buf: buf.clone() };
        let (itx, _irx) = tokio::sync::mpsc::channel(8);
        let mut listener_handles = std::collections::HashMap::new();
        let mut udp_sockets = std::collections::HashMap::new();
        let accepted = handle_new_proxy(
            np,
            "run1",
            1,
            state,
            &mut writer,
            &itx,
            &mut listener_handles,
            &mut udp_sockets,
            false,
        )
        .await;
        let resp = String::from_utf8_lossy(&buf.lock().unwrap()).to_string();
        (accepted, resp)
    }

    fn set_allow_ports(state: &Arc<AppState>, start: u16, end: u16) {
        let mut reloadable = state.reloadable.write().unwrap();
        reloadable.allow_ports = Arc::new(vec![frp_core::config::PortsRange {
            start,
            end,
            single: 0,
        }]);
    }

    /// Explicit TCP port already marked used by another live proxy →
    /// Go ErrPortAlreadyUsed ("port already used"). Deterministic: the
    /// used-mark is classified BEFORE the OS probe, so no real socket
    /// is involved.
    #[tokio::test]
    async fn tcp_explicit_used_port_rejects_port_already_used() {
        let state = super::super::unregister_generation_tests::test_state();
        state.used_ports.write().await.insert(61200);
        let mut np = auto_assign_tcp_np("p-used");
        np.remote_port = Some(61200);
        let (accepted, resp) = register_and_reject(&state, np).await;
        assert!(!accepted, "an in-use explicit port must be rejected");
        assert!(
            resp.contains("port already used"),
            "rejection must carry Go ErrPortAlreadyUsed text: {resp}"
        );
        assert!(
            state.proxy_manager.get("p-used").await.is_none(),
            "a rejected proxy must not be registered"
        );
    }

    /// Explicit TCP port outside every configured allow_ports range →
    /// Go ErrPortNotAllowed ("port not allowed").
    #[tokio::test]
    async fn tcp_explicit_outside_allow_rejects_port_not_allowed() {
        let state = super::super::unregister_generation_tests::test_state();
        set_allow_ports(&state, 61100, 61199);
        let mut np = auto_assign_tcp_np("p-range");
        np.remote_port = Some(62000); // above the 61100-61199 range
        let (accepted, resp) = register_and_reject(&state, np).await;
        assert!(!accepted, "an out-of-range explicit port must be rejected");
        assert!(
            resp.contains("port not allowed"),
            "rejection must carry Go ErrPortNotAllowed text: {resp}"
        );
    }

    /// Auto-assign (remote_port == 0) with zero candidates (the only
    /// allow-listed port is marked used) → Go ErrNoAvailablePort
    /// ("no available port"). Deterministic: an empty candidate list is
    /// exhausted before any OS probe runs.
    #[tokio::test]
    async fn tcp_auto_assign_exhaustion_rejects_no_available_port() {
        let state = super::super::unregister_generation_tests::test_state();
        set_allow_ports(&state, 61150, 61150);
        state.used_ports.write().await.insert(61150);
        let np = auto_assign_tcp_np("p-exhaust");
        let (accepted, resp) = register_and_reject(&state, np).await;
        assert!(!accepted, "auto-assign exhaustion must be rejected");
        assert!(
            resp.contains("no available port"),
            "exhaustion must carry Go ErrNoAvailablePort text: {resp}"
        );
    }

    /// Explicit UDP port already used by another UDP proxy →
    /// Go ErrPortAlreadyUsed (the usedPorts hit) — previously collapsed
    /// into "no available port" like every other allocation failure.
    #[tokio::test]
    async fn udp_explicit_conflict_rejects_port_already_used() {
        let state = super::super::unregister_generation_tests::test_state();
        state.used_udp_ports.write().await.insert(61300);
        let mut np = auto_assign_tcp_np("p-udp-used");
        np.proxy_type = "udp".to_string();
        np.remote_port = Some(61300);
        let (accepted, resp) = register_and_reject(&state, np).await;
        assert!(!accepted, "an in-use explicit UDP port must be rejected");
        assert!(
            resp.contains("port already used"),
            "UDP conflict must carry Go ErrPortAlreadyUsed text: {resp}"
        );
    }

    /// Explicit TCP port bound by another process (passes the allow
    /// range + used-mark checks, fails the OS probe) → Go
    /// ErrPortUnAvailable ("port unavailable").
    #[tokio::test]
    async fn tcp_explicit_os_bound_rejects_port_unavailable() {
        let state = super::super::unregister_generation_tests::test_state();
        // Real thief socket on 127.0.0.1 (test_state's proxy_bind_addr):
        // the allocator's probe fails with EADDRINUSE.
        let thief = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("thief bind");
        let port = thief.local_addr().expect("thief addr").port();
        let mut np = auto_assign_tcp_np("p-bound");
        np.remote_port = Some(port as i32);
        let (accepted, resp) = register_and_reject(&state, np).await;
        drop(thief);
        assert!(!accepted, "an OS-bound explicit port must be rejected");
        assert!(
            resp.contains("port unavailable"),
            "probe failure must carry Go ErrPortUnAvailable text: {resp}"
        );
    }

    /// Explicit UDP port bound by another process → Go
    /// ErrPortUnAvailable ("port unavailable").
    #[tokio::test]
    async fn udp_explicit_os_bound_rejects_port_unavailable() {
        let state = super::super::unregister_generation_tests::test_state();
        let thief = std::net::UdpSocket::bind(("127.0.0.1", 0)).expect("thief bind");
        let port = thief.local_addr().expect("thief addr").port();
        let mut np = auto_assign_tcp_np("p-udp-bound");
        np.proxy_type = "udp".to_string();
        np.remote_port = Some(port as i32);
        let (accepted, resp) = register_and_reject(&state, np).await;
        drop(thief);
        assert!(!accepted, "an OS-bound explicit UDP port must be rejected");
        assert!(
            resp.contains("port unavailable"),
            "UDP probe failure must carry Go ErrPortUnAvailable text: {resp}"
        );
    }
}
