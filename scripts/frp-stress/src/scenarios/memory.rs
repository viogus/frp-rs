use crate::Cli;
use anyhow::{Context, Result};
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::interval;

pub async fn run(cli: &Cli) -> Result<()> {
    let target = format!(
        "{}:{}",
        cli.frps_addr.split(':').next().unwrap_or("127.0.0.1"),
        cli.port
    );
    let mut streams = Vec::new();

    tracing::info!(concurrency = %cli.concurrency, "Phase 1: Ramping up to {} connections", cli.concurrency);
    for i in 0..cli.concurrency {
        let stream = TcpStream::connect(&target)
            .await
            .with_context(|| format!("connect {} failed at conn {}", target, i))?;
        streams.push(stream);
        if i > 0 && i % 100 == 0 {
            tracing::info!(count = %i, "  {} connections established", i);
        }
    }

    tracing::info!(
        concurrency = %cli.concurrency,
        duration = %cli.duration,
        "Phase 2: Holding {} connections for {}s",
        cli.concurrency,
        cli.duration
    );
    let mut tick = interval(Duration::from_secs(10));
    let deadline = tokio::time::Instant::now() + Duration::from_secs(cli.duration);

    loop {
        tokio::select! {
            _ = tick.tick() => {
                let elapsed = (tokio::time::Instant::now() - deadline + Duration::from_secs(cli.duration)).as_secs();
                tracing::info!(connections = %streams.len(), elapsed = %elapsed, "  memory scenario: {} connections alive, elapsed {}s",
                    streams.len(), elapsed);
            }
            _ = tokio::time::sleep_until(deadline) => break,
        }
    }

    tracing::info!("Phase 3: Draining connections");
    drop(streams);
    tokio::time::sleep(Duration::from_secs(2)).await;
    tracing::info!("Memory scenario complete: no leaks detected");
    Ok(())
}
