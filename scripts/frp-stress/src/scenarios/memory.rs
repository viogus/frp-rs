use crate::Cli;
use anyhow::{Context, Result};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

pub async fn run(cli: &Cli) -> Result<()> {
    run_with_mode(cli, &cli.mode).await
}

pub async fn run_with_mode(cli: &Cli, mode: &str) -> Result<()> {
    let target = format!(
        "{}:{}",
        cli.frps_addr.split(':').next().unwrap_or("127.0.0.1"),
        cli.port
    );
    match mode {
        "idle_hold" => idle_hold(cli, &target).await,
        "churn" => churn(cli, &target).await,
        other => anyhow::bail!("unknown memory mode: {other} (expected idle_hold|churn)"),
    }
}

/// Open N proxy connections, send one small message on each (forcing the
/// server + client bridge to allocate their per-connection buffers), then hold
/// them idle. Targets resident footprint (the pinned-buffer cost).
async fn idle_hold(cli: &Cli, target: &str) -> Result<()> {
    let msg = vec![0xABu8; cli.msg_bytes.max(1)];
    let mut buf = vec![0u8; msg.len()];
    let mut streams = Vec::with_capacity(cli.concurrency);
    tracing::info!(n = cli.concurrency, "idle_hold: opening {} conns, 1 msg each", cli.concurrency);
    for i in 0..cli.concurrency {
        let mut s = TcpStream::connect(target)
            .await
            .with_context(|| format!("idle_hold connect {i}"))?;
        s.write_all(&msg).await?;
        s.read_exact(&mut buf).await?; // forces both bridge buffers to allocate
        streams.push(s);
    }
    tracing::info!("idle_hold: MARK ramped ({} conns)", streams.len());
    tokio::time::sleep(Duration::from_secs(cli.duration)).await;
    tracing::info!("idle_hold: MARK hold-end, draining {} conns", streams.len());
    drop(streams);
    tokio::time::sleep(Duration::from_secs(2)).await;
    Ok(())
}

/// Repeatedly open -> send one message -> close, at fixed concurrency, for the
/// duration. Targets allocation rate (per-connection setup/teardown churn).
async fn churn(cli: &Cli, target: &str) -> Result<()> {
    let msg = vec![0xABu8; cli.msg_bytes.max(1)];
    let conc = cli.concurrency.max(1);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(cli.duration);
    tracing::info!(concurrency = conc, "churn: MARK start, open->1msg->close for {}s", cli.duration);
    let mut handles = Vec::with_capacity(conc);
    for _ in 0..conc {
        let target = target.to_string();
        let msg = msg.clone();
        handles.push(tokio::spawn(async move {
            let mut buf = vec![0u8; msg.len()];
            while tokio::time::Instant::now() < deadline {
                if let Ok(mut s) = TcpStream::connect(&target).await {
                    let _ = s.write_all(&msg).await;
                    let _ = s.read_exact(&mut buf).await;
                    drop(s);
                }
            }
        }));
    }
    for h in handles {
        let _ = h.await;
    }
    tracing::info!("churn: MARK end");
    tokio::time::sleep(Duration::from_secs(1)).await;
    Ok(())
}
