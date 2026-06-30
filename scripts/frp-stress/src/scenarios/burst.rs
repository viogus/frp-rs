use crate::Cli;
use anyhow::Result;
use std::time::Duration;
use tokio::net::TcpStream;

pub async fn run(cli: &Cli) -> Result<()> {
    let target = format!(
        "{}:{}",
        cli.frps_addr.split(':').next().unwrap_or("127.0.0.1"),
        cli.port
    );
    let deadline = tokio::time::Instant::now() + Duration::from_secs(cli.duration);
    let batch_size = cli.concurrency.min(50);

    tracing::info!(
        batch_size = %batch_size,
        duration = %cli.duration,
        "Burst test: batches of {} connect/disconnect for {}s",
        batch_size,
        cli.duration
    );

    let mut total_connects = 0u64;
    let mut total_failures = 0u64;

    while tokio::time::Instant::now() < deadline {
        let mut batch = Vec::with_capacity(batch_size);
        for _ in 0..batch_size {
            batch.push(TcpStream::connect(&target));
        }

        for result in futures_util::future::join_all(batch).await {
            match result {
                Ok(_) => total_connects += 1,
                Err(e) => {
                    tracing::warn!(error = %e, "Burst connect failed: {}", e);
                    total_failures += 1;
                }
            }
        }

        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    let fail_rate = if total_connects + total_failures > 0 {
        total_failures as f64 / (total_connects + total_failures) as f64
    } else {
        0.0
    };

    tracing::info!(
        total_connects = %total_connects,
        total_failures = %total_failures,
        fail_rate_pct = %(fail_rate * 100.0),
        "Burst: {} connects, {} failures ({:.1}% fail rate)",
        total_connects,
        total_failures,
        fail_rate * 100.0
    );

    if fail_rate > 0.05 {
        anyhow::bail!(
            "Burst failure rate too high: {:.1}% (max 5%)",
            fail_rate * 100.0
        );
    }
    Ok(())
}
