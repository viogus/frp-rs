use crate::Cli;
use anyhow::{Context, Result};
use std::io::Write;
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
    // streams == 0 means "use --concurrency" (back-compat); >0 overrides.
    let streams = if cli.streams > 0 { cli.streams } else { cli.concurrency };
    let payload = vec![0xABu8; PAYLOAD_SIZE];
    let deadline = tokio::time::Instant::now() + Duration::from_secs(cli.duration);
    let mut total_bytes: u64 = 0;

    tracing::info!(
        label = %cli.label,
        streams = %streams,
        "Throughput [{}]: {}s, {} streams",
        cli.label,
        cli.duration,
        streams
    );

    let mut handles = Vec::with_capacity(streams);
    for i in 0..streams {
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
        label = %cli.label,
        total_bytes = %total_bytes,
        mbps = %mbps,
        "Throughput [{}]: {} total bytes, {:.2} MB/s",
        cli.label,
        total_bytes,
        mbps
    );

    if let Some(path) = &cli.json_out {
        let record = serde_json::json!({
            "label": cli.label,
            "streams": streams,
            "duration_s": cli.duration,
            "total_bytes": total_bytes,
            "mbps": mbps,
        });
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .with_context(|| format!("open json_out {}", path))?;
        writeln!(f, "{}", record).context("write json_out")?;
    }

    if !cli.no_floor && mbps < 1.0 {
        anyhow::bail!("Throughput too low: {:.2} MB/s (minimum 1.0 MB/s)", mbps);
    }
    Ok(())
}
