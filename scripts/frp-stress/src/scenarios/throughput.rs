use crate::Cli;
use anyhow::{Context, Result};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const PAYLOAD_SIZE: usize = 1024 * 64; // 64 KiB chunks

pub async fn run(cli: &Cli) -> Result<()> {
    let target = format!(
        "{}:{}",
        cli.frps_addr.split(':').next().unwrap_or("127.0.0.1"),
        cli.port
    );
    let payload = vec![0xABu8; PAYLOAD_SIZE];
    let deadline = tokio::time::Instant::now() + Duration::from_secs(cli.duration);
    let mut total_bytes: u64 = 0;

    tracing::info!(
        duration = %cli.duration,
        concurrency = %cli.concurrency,
        "Throughput test: {}s, {} streams",
        cli.duration,
        cli.concurrency
    );

    let mut handles = Vec::with_capacity(cli.concurrency);
    for i in 0..cli.concurrency {
        let target = target.clone();
        let payload = payload.clone();
        handles.push(tokio::spawn(async move {
            let mut stream = TcpStream::connect(&target)
                .await
                .with_context(|| format!("stream {} connect failed", i))?;

            let mut bytes = 0u64;
            let mut buf = vec![0u8; PAYLOAD_SIZE];
            while tokio::time::Instant::now() < deadline {
                stream.write_all(&payload).await?;
                stream.read_exact(&mut buf).await?;
                bytes += (PAYLOAD_SIZE * 2) as u64; // sent + received
            }
            Ok::<u64, anyhow::Error>(bytes)
        }));
    }

    for h in handles {
        match h.await {
            Ok(Ok(bytes)) => total_bytes += bytes,
            Ok(Err(e)) => tracing::error!(error = ?e, "Throughput stream failed: {:#}", e),
            Err(e) => tracing::error!(error = %e, "Throughput task panicked: {}", e),
        }
    }

    let mbps = (total_bytes as f64 / (1024.0 * 1024.0)) / cli.duration as f64;
    tracing::info!(
        total_bytes = %total_bytes,
        mbps = %mbps,
        "Throughput: {} total bytes, {:.2} MB/s",
        total_bytes,
        mbps
    );

    if mbps < 1.0 {
        anyhow::bail!(
            "Throughput too low: {:.2} MB/s (minimum 1.0 MB/s)",
            mbps
        );
    }
    Ok(())
}
