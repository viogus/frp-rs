//! End-to-end regression test for the per-accept reap in `serve_plugin`
//! (`frp-client/src/plugin/mod.rs`), the fix for a listener that retained one
//! finished task cell per cumulative accepted connection.
//!
//! The existing unit test (`plugin::tests::reap_finished_handlers_releases_finished_tasks`)
//! builds its own `JoinSet` and calls the helper directly, so deleting the
//! `reap_finished_handlers(&mut handlers);` call in the accept loop leaves it
//! green. This test instead drives the REAL accept loop through
//! `frp_client::plugin::start_socks5_proxy` and measures live heap bytes with a
//! test-local `#[global_allocator]`, so it only passes while the accept arm
//! actually reaps.
//!
//! Each churned connection sends a complete SOCKS5 greeting and then closes:
//! the handler reads the greeting, hits EOF on the CONNECT request and returns
//! (an error — expected, no upstream server exists), i.e. the task *completes*,
//! which is the state `serve_plugin` must reap. With the reap deleted, every
//! completed task is retained by the listener's `JoinSet` for as long as the
//! `PluginHandle` is alive; the delta is measured before the handle is dropped
//! because teardown joins (and frees) everything.
//!
//! MEASURED (this machine, debug `cargo test` build, macOS aarch64), 20,000
//! churned connections and a 256 KiB bound:
//!   - with the reap (fixed): delta = 0 bytes → passes
//!   - with the reap line deleted (base): delta = 3,680,000 bytes → fails
//!
//! The retained cell is small because the debug-build socks5 handler future is
//! above tokio 1.53's 2048 B `BOX_FUTURE_THRESHOLD`, so the future is
//! `Box::pin`'d and freed at completion and only the task cell itself stays
//! behind.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

use frp_core::config::PluginConfig;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

/// Test-local allocator that counts LIVE bytes handed out by the system
/// allocator. Only this test binary links it, so the library under test is
/// unaffected.
struct LiveBytes;

static LIVE: AtomicUsize = AtomicUsize::new(0);

// SAFETY: `LiveBytes` is a zero-sized marker with no fields, no `Drop` and no
// interior state beyond the process-global `LIVE` counter. Every method
// delegates to `System` with the same `Layout`, so the `GlobalAlloc` contract
// is upheld exactly as it is for `System`: non-null, suitably-aligned returned
// pointers, `dealloc` receiving the same layout as `alloc`, and `realloc`
// preserving contents up to `min(old, new)`. The counter is an independent
// atomic and cannot be dereferenced as a pointer, so it is safe to touch from
// any thread. Charges are attributed only when the underlying call succeeds.
unsafe impl GlobalAlloc for LiveBytes {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = System.alloc(layout);
        if !ptr.is_null() {
            LIVE.fetch_add(layout.size(), Ordering::Relaxed);
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        System.dealloc(ptr, layout);
        LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let ptr = System.alloc_zeroed(layout);
        if !ptr.is_null() {
            LIVE.fetch_add(layout.size(), Ordering::Relaxed);
        }
        ptr
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let new_ptr = System.realloc(ptr, layout, new_size);
        if !new_ptr.is_null() {
            // The old block is gone; the live set now holds `new_size` bytes.
            LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
            LIVE.fetch_add(new_size, Ordering::Relaxed);
        }
        new_ptr
    }
}

#[global_allocator]
static ALLOC: LiveBytes = LiveBytes;

fn live_bytes() -> usize {
    LIVE.load(Ordering::Relaxed)
}

/// Connections churned to settle the runtime/allocator before the baseline.
const WARMUP: usize = 2_000;
/// Connections churned between baseline and measurement.
const CHURN: usize = 20_000;
/// Upper bound on retained growth, deliberately generous: with the reap the
/// listener holds only in-flight handlers, while the deleted-reap build retains
/// a cell per completed connection (multi-MB here).
const RETENTION_BOUND: usize = 256 * 1024;

/// Open `n` connections that each hand the handler a complete SOCKS5 greeting
/// and then close, so every spawned handler task completes and is dropped.
async fn churn(addr: std::net::SocketAddr, n: usize) {
    for _ in 0..n {
        let mut client = TcpStream::connect(addr).await.expect("connect to plugin");
        // Version 5, one offered method (no-auth). The handler reads the
        // greeting, replies with the method choice, then blocks on the CONNECT
        // request — which we never send — and sees EOF once this socket drops,
        // completing the task.
        client
            .write_all(&[0x05, 0x01, 0x00])
            .await
            .expect("send greeting");
        drop(client);
    }
}

/// Let every spawned handler reach completion and run the runtime's task
/// bookkeeping before the counter is read.
async fn settle() {
    for _ in 0..20 {
        tokio::task::yield_now().await;
    }
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
}

/// One test (its own binary) so the process-wide byte counter sees no
/// intra-process parallel churn from sibling tests.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn plugin_accept_reap_bounds_retained_bytes() {
    let cfg = PluginConfig {
        plugin_type: "socks5".into(),
        ..Default::default()
    };
    let handle = match frp_client::plugin::start_socks5_proxy(&cfg).await {
        Ok(h) => h,
        Err(e) => {
            eprintln!("Skipping test: cannot start plugin (sandboxed): {e}");
            return;
        }
    };
    let addr = handle.local_addr;

    // Warm up first: listener setup, runtime pools and first-connection
    // allocations must not read as growth.
    churn(addr, WARMUP).await;
    settle().await;
    let baseline = live_bytes();

    churn(addr, CHURN).await;
    settle().await;
    let after = live_bytes();
    let delta = after as i128 - baseline as i128;

    eprintln!(
        "plugin_accept_reap: churn={CHURN} warmup={WARMUP} baseline={baseline} \
         after={after} delta={delta} bound={RETENTION_BOUND}"
    );

    // Measured WHILE `handle` is alive: dropping it shuts the listener down and
    // joins every retained task, freeing the very cells this test looks for.
    assert!(
        delta < RETENTION_BOUND as i128,
        "accept loop retained {delta} live bytes across {CHURN} completed connections \
         (baseline {baseline}, after {after}); per-accept reaping must keep retention \
         bounded by in-flight handlers, under {RETENTION_BOUND} bytes"
    );

    drop(handle);
}
