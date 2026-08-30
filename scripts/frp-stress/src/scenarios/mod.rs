pub mod memory;
pub mod connections;
pub mod throughput;
pub mod longevity;
pub mod burst;
pub mod mixed;
pub mod echo;
pub mod latency;

use crate::Cli;
use anyhow::Result;
use std::pin::Pin;
use std::future::Future;

/// Run all scenarios sequentially. Each exits non-zero on failure.
pub async fn run_all(cli: &Cli) -> Result<()> {
    let scenarios: &[(&str, fn(&Cli) -> Pin<Box<dyn Future<Output = Result<()>> + '_>>)] = &[
        ("memory", |c| Box::pin(memory::run_with_mode(c, "idle_hold"))),
        ("connections", |c| Box::pin(connections::run(c))),
        ("throughput", |c| Box::pin(throughput::run(c))),
        ("longevity", |c| Box::pin(longevity::run(c))),
        ("burst", |c| Box::pin(burst::run(c))),
        ("mixed", |c| Box::pin(mixed::run(c))),
    ];

    let mut failed = 0;
    for (name, f) in scenarios {
        tracing::info!(name = %name, "=== Scenario: {} ===", name);
        match f(cli).await {
            Ok(()) => tracing::info!(name = %name, "PASS: {}", name),
            Err(e) => {
                tracing::error!(name = %name, error = %e, "FAIL: {}: {:#}", name, e);
                failed += 1;
            }
        }
    }

    if failed > 0 {
        anyhow::bail!("{}/{} scenarios failed", failed, scenarios.len());
    }
    Ok(())
}
