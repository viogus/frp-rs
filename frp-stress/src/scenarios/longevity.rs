use crate::Cli;
use anyhow::{Context, Result};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

pub async fn run(cli: &Cli) -> Result<()> {
    let target = format!(
        "{}:{}",
        cli.frps_addr.split(':').next().unwrap_or("127.0.0.1"),
        cli.port
    );
    let check_interval = Duration::from_secs(5);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(cli.duration);

    tracing::info!(
        "Longevity test: {}s with connect/transfer/close cycles",
        cli.duration
    );

    let mut cycles = 0u64;
    let mut failures = 0u64;

    while tokio::time::Instant::now() < deadline {
        match run_cycle(&target).await {
            Ok(()) => cycles += 1,
            Err(e) => {
                tracing::error!("Cycle {} failed: {:#}", cycles, e);
                failures += 1;
                if failures > 10 {
                    anyhow::bail!("Too many failures ({})", failures);
                }
            }
        }
        tokio::time::sleep(check_interval).await;
    }

    tracing::info!(
        "Longevity: {} cycles, {} failures over {}s",
        cycles,
        failures,
        cli.duration
    );
    Ok(())
}

async fn run_cycle(target: &str) -> Result<()> {
    let mut stream = TcpStream::connect(target).await.context("connect")?;
    stream.write_all(b"ping").await.context("write")?;
    let mut buf = [0u8; 4];
    stream.read_exact(&mut buf).await.context("read")?;
    Ok(())
}
