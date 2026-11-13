//! Experimental bridge sharding: run a connection's copy pipeline on one of a
//! few dedicated single-threaded runtimes instead of the shared worker pool.
//!
//! ## Why (measured)
//!
//! On the 4-vCPU measurement VM, eight independent plain sessions through
//! frps+frpc move 645 MiB/s when both ends run one worker and 1201 MiB/s with
//! four workers, while a *single* session moves 612 MiB/s at either count.
//! Nothing in the bridge is CPU-bound — the splice path is two `splice(2)`
//! calls plus an epoll wakeup per chunk — so the 1.86x is the cost of every
//! session's readiness loop competing for the same worker thread, not of the
//! work itself.
//!
//! Sharding gives each bridge a stable thread of its own and keeps several of
//! them live, so concurrency no longer depends on `worker_threads`:
//!
//! * a single fat tunnel runs its copy loop on one thread, which is what the
//!   KCP measurements showed it wants (117 MiB/s at one worker, 66 at four);
//! * many sessions still get one shard thread each, so total throughput is
//!   bounded by cores rather than by the worker count.
//!
//! ## Cost
//!
//! One OS thread plus one reactor per shard, not per connection: shards are
//! shared round-robin (`FRP_BRIDGE_SHARD` = how many). A shard runs many
//! bridges concurrently on its single thread, exactly like a current-thread
//! runtime always does.
//!
//! Disabled by default (`FRP_BRIDGE_SHARD` unset or 0): every call site then
//! awaits the future inline, i.e. today's behaviour.

use std::future::Future;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::OnceLock;

/// Environment variable naming the number of shard threads (`0`/unset = the
/// bridge stays on the caller's worker pool).
const SHARD_ENV: &str = "FRP_BRIDGE_SHARD";

struct Shard {
    handle: tokio::runtime::Handle,
}

static SHARDS: OnceLock<Option<Vec<Shard>>> = OnceLock::new();
static NEXT: AtomicUsize = AtomicUsize::new(0);

fn shards() -> Option<&'static Vec<Shard>> {
    SHARDS
        .get_or_init(|| {
            let count: usize = std::env::var(SHARD_ENV).ok()?.trim().parse().ok()?;
            build_pool(count)
        })
        .as_ref()
}

/// Build `count` single-threaded runtimes, each parked on its own thread.
///
/// `None` when a thread or runtime cannot be created: the caller then falls
/// back to the inline path rather than failing the connection.
fn build_pool(count: usize) -> Option<Vec<Shard>> {
    if count == 0 {
        return None;
    }
    let mut shards = Vec::with_capacity(count);
    for index in 0..count {
        let name = format!("frp-bridge-{index}");
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::Builder::new()
            .name(name)
            .spawn(move || {
                let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                else {
                    return;
                };
                // Hand the handle back before parking: the parent
                // builds the pool synchronously, so a failed send can
                // only mean the parent is gone and the thread should
                // simply exit.
                if tx.send(runtime.handle().clone()).is_err() {
                    return;
                }
                runtime.block_on(std::future::pending::<()>());
            })
            .ok()?;
        shards.push(Shard { handle: rx.recv().ok()? });
    }
    Some(shards)
}

/// Run `fut` on the next shard thread, or inline when sharding is disabled.
///
/// The future is moved to the shard, so callers must hand over owned streams
/// (`'static`); both bridge entry points do — they consume the two halves.
pub async fn on_shard<F, T>(fut: F) -> T
where
    F: Future<Output = T> + Send + 'static,
    T: Send + 'static,
{
    match shards() {
        Some(shards) if !shards.is_empty() => {
            let index = NEXT.fetch_add(1, Ordering::Relaxed) % shards.len();
            shards[index]
                .handle
                .spawn(fut)
                .await
                .expect("bridge shard task panicked")
        }
        _ => fut.await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn on_shard_runs_inline_when_disabled() {
        // The test process does not set the variable: the future's own thread
        // must be the caller's, i.e. no shard thread takes part.
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        let caller = std::thread::current().id();
        let ran_on = runtime.block_on(async move {
            on_shard(async { std::thread::current().id() }).await
        });
        assert_eq!(ran_on, caller);
    }

    #[test]
    fn a_shard_runs_work_on_its_own_thread() {
        let pool = build_pool(2).expect("pool");
        let mut names = Vec::new();
        for shard in &pool {
            let (tx, rx) = std::sync::mpsc::channel();
            shard
                .handle
                .spawn(async move {
                    let _ = tx.send(std::thread::current().name().map(str::to_string));
                });
            names.push(rx.recv().expect("shard ran").unwrap_or_default());
        }
        assert_eq!(names.len(), 2);
        for (index, name) in names.iter().enumerate() {
            assert_eq!(name, &format!("frp-bridge-{index}"));
        }
    }
}
