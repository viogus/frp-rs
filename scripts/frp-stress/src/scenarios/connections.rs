use crate::Cli;
use anyhow::{Context, Result};
use std::time::Duration;
use tokio::net::TcpStream;

pub async fn run(cli: &Cli) -> Result<()> {
    let target = format!(
        "{}:{}",
        cli.frps_addr.split(':').next().unwrap_or("127.0.0.1"),
        cli.port
    );
    tracing::info!(concurrency = %cli.concurrency, target = %target, "Opening {} connections to {}", cli.concurrency, target);

    let mut handles = Vec::with_capacity(cli.concurrency);

    for _i in 0..cli.concurrency {
        let target = target.clone();
        let dur = Duration::from_secs(cli.duration);
        handles.push(tokio::spawn(async move {
            let stream = tokio::time::timeout(Duration::from_secs(5), TcpStream::connect(&target))
                .await
                .context("connect timeout")?
                .with_context(|| format!("connect {} failed", target))?;

            // Hold connection open -- wait for duration then drop
            tokio::time::sleep(dur).await;
            drop(stream);
            Ok::<_, anyhow::Error>(())
        }));
    }

    let mut failures = 0;
    for (i, h) in handles.into_iter().enumerate() {
        match h.await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                tracing::error!(i = %i, error = ?e, "Connection {} failed: {:#}", i, e);
                failures += 1;
            }
            Err(e) => {
                tracing::error!(i = %i, error = %e, "Task {} panicked: {}", i, e);
                failures += 1;
            }
        }
    }

    if failures > 0 {
        anyhow::bail!("{}/{} connections failed", failures, cli.concurrency);
    }

    tracing::info!(
        concurrency = %cli.concurrency,
        duration = %cli.duration,
        "All {} connections stable for {}s",
        cli.concurrency,
        cli.duration
    );
    Ok(())
}
