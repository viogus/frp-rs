//! Graceful-shutdown listener release: cancellation — not `run()` returning —
//! must close the main frps listener, and cancellation must interrupt a
//! *blocked* SSH-gateway `accept()`.
//!
//! Go frp v0.71.1 (`55107d0`, "synchronize service startup and shutdown",
//! #5560) closes the main listener from `Close()`, which
//! `context.AfterFunc(ctx, …)` fires when the parent context is cancelled —
//! i.e. **at cancellation**, before the graceful drain. A reconnecting frpc
//! therefore gets `ECONNREFUSED` and backs off, instead of completing a TCP
//! handshake into an unserviced backlog and parking there for the whole drain
//! window (`graceful_shutdown_timeout`, default 30 s).
//!
//! frp-rs already stopped *accepting* at cancellation (the accept loop's
//! `select!` arm), and already closed the vhost/kcp/quic/ws/dashboard
//! listeners there, but kept the main `TcpListener` alive until `run()`
//! returned. `cancellation_releases_main_and_vhost_ports_before_run_returns`
//! pins that delta, ported from upstream's
//! `TestServiceParentCancellationAndCloseShareCleanup` / `TestServiceRunAfterEarlyShutdown`
//! assertions (`service_lifecycle_test.go` upstream: every configured port is
//! bindable again and the main listener closes on cancellation).
//!
//! These tests are **in-process**: no `frps` binary and no client login are
//! needed. The harness drives `Service::run` directly, and the drain is held
//! open by bumping the shared `active_connections` counter — the exact value
//! the drain loop polls — so `run()` cannot return while the "port is closed
//! but `run()` has not returned" assertions run.

mod common;

use common::{allocate_port, test_auth_cfg};
use frp_core::config::ServerConfig;
use frp_server::service::Service;
use frp_server::state::AppState;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

/// How long a port may keep accepting after cancellation. The fix is O(ms) —
/// the accept loop observes `cancelled()` on its next poll and drops the
/// listener — so a few hundred ms is generous, while a port released only at
/// `run()` return cannot slip through: the drain is held for
/// `DRAIN_HOLD` and `graceful_shutdown_timeout` is `DRAIN_HOLD + 1 s`, so
/// `run()` is still draining when this budget expires (the pre-fix run
/// accepts for the whole budget).
const RELEASE_BUDGET: Duration = Duration::from_millis(500);

/// How long the drain is deliberately held open, i.e. the window in which
/// "closed before `run()` returns" is asserted. Must stay well above
/// [`RELEASE_BUDGET`] and below the configured `graceful_shutdown_timeout`.
const DRAIN_HOLD: Duration = Duration::from_secs(2);

/// A running in-process server plus the handles the shutdown assertions need.
struct Booted {
    state: Arc<AppState>,
    handle: JoinHandle<Result<(), String>>,
}

/// Start `service.run()` on a task, returning the shutdown-visible state.
///
/// The `JoinHandle` yields `Result<(), String>` rather than the raw error box
/// so it stays `Send` (which `tokio::spawn` requires) without hiding a failure
/// mode from the assertions.
fn spawn_service(service: Service) -> Booted {
    let state = service.state();
    let handle = tokio::spawn(async move { service.run().await.map_err(|e| e.to_string()) });
    Booted { state, handle }
}

impl Booted {
    /// Hold the graceful drain open by bumping the counter the drain loop
    /// polls, so `run()` cannot return until [`release_drain_and_join`].
    fn hold_drain(&self) {
        let counter = &self.state.active_connections;
        counter.fetch_add(1, Ordering::Relaxed);
    }
}

/// Base config: loopback, the allocated main port, and a deliberately short
/// graceful drain so a broken test fails fast instead of sitting on the
/// default 30 s timeout.
fn test_config(bind_port: u16) -> ServerConfig {
    ServerConfig {
        bind_addr: "127.0.0.1".into(),
        bind_port,
        auth: test_auth_cfg(),
        // Long enough that the held drain cannot time out mid-assertion, short
        // enough that a regression that never releases the port fails in
        // seconds, not half a minute.
        graceful_shutdown_timeout: (DRAIN_HOLD + Duration::from_secs(1)).as_secs(),
        ..Default::default()
    }
}

fn loopback_addr(port: u16) -> SocketAddr {
    format!("127.0.0.1:{port}").parse().unwrap()
}

/// Poll until `addr` accepts a TCP connection (the listeners are bound and the
/// accept tasks are running), then drop the probe connection.
async fn wait_until_accepting(addr: SocketAddr) {
    for _ in 0..200 {
        if let Ok(stream) = TcpStream::connect(addr).await {
            drop(stream);
            return;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("server never started accepting on {addr}");
}

/// Assert that `addr` stops accepting within `budget`, because cancellation
/// closed the socket. Polls (rather than probing once) so the small window
/// between `cancel()` and the accept loop observing it cannot fail the test.
async fn expect_port_closed(addr: SocketAddr, budget: Duration, what: &str) {
    let deadline = tokio::time::Instant::now() + budget;
    loop {
        match TcpStream::connect(addr).await {
            Err(_) => return,
            Ok(stream) => {
                drop(stream);
                assert!(
                    tokio::time::Instant::now() < deadline,
                    "{what} at {addr} still completes TCP handshakes {budget:?} after \
                     shutdown_token.cancel(). The listening socket is only dropped when \
                     `run()` returns, so it stays bound and unserviced for the whole \
                     graceful drain — a reconnecting frpc hangs there instead of getting \
                     ECONNREFUSED. Go frp v0.71.1 closes the listener from Close(), which \
                     the cancelled context triggers immediately."
                );
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }
    }
}

/// Assert that `addr` can be bound within `budget` — i.e. nothing is listening
/// on it any more.
///
/// This is the right probe for the SSH gateway specifically: a `connect` would
/// itself wake a blocked `accept()`, letting the pre-fix poll-then-accept loop
/// observe the token on its *next* iteration and close the port — the probe
/// would hide the bug it is meant to catch. Binding does not touch the
/// gateway's accept path, so it observes the listener socket being gone only
/// because cancellation closed it. `TcpListener::bind` (through tokio) sets
/// only `SO_REUSEADDR`, not `SO_REUSEPORT`, so an already-listening socket on
/// the same address makes it fail with `EADDRINUSE`.
async fn expect_port_bindable(addr: SocketAddr, budget: Duration, what: &str) {
    let deadline = tokio::time::Instant::now() + budget;
    loop {
        match TcpListener::bind(addr).await {
            Ok(listener) => {
                drop(listener);
                return;
            }
            Err(e) => {
                assert!(
                    tokio::time::Instant::now() < deadline,
                    "{what} at {addr} is still bound {budget:?} after \
                     shutdown_token.cancel() (bind failed: {e}). The gateway only polls \
                     the token *before* awaiting accept(), so a blocked accept() never \
                     notices cancellation and the SSH port stays open — and silently \
                     accepts TCP handshakes it will never service — until some \
                     connection happens to arrive. Go frp v0.71.1 closes \
                     sshTunnelGateway from closeResources at cancellation."
                );
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }
    }
}

/// The drain counter is the only thing keeping `run()` alive in these tests:
/// drop it back to its pre-test value and let the server finish.
async fn release_drain_and_join(booted: Booted) {
    let counter = &booted.state.active_connections;
    counter.fetch_sub(1, Ordering::Relaxed);
    let result = tokio::time::timeout(Duration::from_secs(10), booted.handle)
        .await
        .expect("run() did not return after the drain counter was released");
    let result = result.expect("run() task panicked");
    assert_eq!(
        result,
        Ok(()),
        "a cancelled, drained server must return Ok from run()"
    );
}

/// D1 — ported from upstream `service_lifecycle_test.go`
/// (`TestServiceParentCancellationAndCloseShareCleanup`, line 131, and
/// `TestServiceRunAfterEarlyShutdown`, line 89).
///
/// Cancelling the token must close the **main** listener right away, while the
/// server is still draining; the vhost listener must be closed too; and once
/// `run()` returns every configured port must be bindable again.
#[tokio::test]
async fn cancellation_releases_main_and_vhost_ports_before_run_returns() {
    let main_port = allocate_port();
    let vhost_port = allocate_port();
    let main_addr = loopback_addr(main_port);
    let vhost_addr = loopback_addr(vhost_port);

    let mut cfg = test_config(main_port);
    cfg.vhost_http_port = vhost_port;

    let service = Service::new(cfg, None).await.expect("create service");
    let booted = spawn_service(service);

    wait_until_accepting(main_addr).await;
    wait_until_accepting(vhost_addr).await;

    // Hold the graceful drain open. `active_connections` is exactly what the
    // drain loop reads; with it non-zero, `run()` cannot return until we
    // release it below (or the timeout hits), so a successful port assertion
    // proves the port closed *before* `run()` returned.
    booted.hold_drain();
    booted.state.shutdown_token.cancel();

    expect_port_closed(main_addr, RELEASE_BUDGET, "main frps listener").await;
    assert!(
        !booted.handle.is_finished(),
        "run() returned before the main-listener assertion completed — the drain \
         counter is supposed to keep it alive; the test cannot distinguish \
         'closed at cancellation' from 'closed at return'"
    );

    expect_port_closed(vhost_addr, RELEASE_BUDGET, "HTTP vhost listener").await;
    assert!(
        !booted.handle.is_finished(),
        "run() returned before the vhost-listener assertion completed"
    );

    release_drain_and_join(booted).await;

    // Every configured port must be bindable again after a graceful stop.
    TcpListener::bind(main_addr)
        .await
        .expect("main frps port is still held after run() returned");
    TcpListener::bind(vhost_addr)
        .await
        .expect("HTTP vhost port is still held after run() returned");
}

/// D2 — the SSH gateway's blocked `accept()` must be interrupted by
/// cancellation, not merely re-checked before each accept.
///
/// The pre-fix loop polls `is_cancelled()` *before* awaiting, so cancellation
/// arriving while the gateway is parked in `accept()` is invisible: the SSH
/// port stays bound (and new dialers complete a TCP handshake against a
/// gateway that will never speak SSH) until a connection happens to arrive.
/// Go's `closeResources` closes `sshTunnelGateway` at cancellation.
#[cfg(feature = "ssh")]
#[tokio::test]
async fn cancellation_interrupts_blocked_ssh_accept_and_releases_port() {
    let main_port = allocate_port();
    let ssh_port = allocate_port();
    let main_addr = loopback_addr(main_port);
    let ssh_addr = loopback_addr(ssh_port);

    let mut cfg = test_config(main_port);
    cfg.ssh_tunnel_gateway.bind_addr = "127.0.0.1".into();
    cfg.ssh_tunnel_gateway.bind_port = ssh_port;

    let service = Service::new(cfg, None).await.expect("create service");
    let booted = spawn_service(service);

    wait_until_accepting(main_addr).await;
    // The gateway is spawned from `run()` as a detached task; wait until it is
    // actually listening so cancellation lands while it is blocked in accept.
    wait_until_accepting(ssh_addr).await;
    // Give the readiness probe's connection a moment to leave the accept path,
    // so the gateway is parked in `accept()` when the token fires.
    tokio::time::sleep(Duration::from_millis(50)).await;

    booted.hold_drain();
    booted.state.shutdown_token.cancel();

    // Bind probe, not a connect probe: see `expect_port_bindable`.
    expect_port_bindable(ssh_addr, RELEASE_BUDGET, "SSH tunnel gateway listener").await;
    assert!(
        !booted.handle.is_finished(),
        "run() returned before the SSH assertion completed — the drain counter is \
         supposed to keep the server alive while the detached gateway task reacts"
    );

    release_drain_and_join(booted).await;

    // ... and still bindable after the server is fully gone.
    TcpListener::bind(ssh_addr)
        .await
        .expect("SSH gateway port is still held after run() returned");
}
