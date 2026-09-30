use crate::Cli;
use anyhow::{Context, Result};
use std::io::Write;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
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
    let streams = if cli.streams > 0 {
        cli.streams
    } else {
        cli.concurrency
    };
    let payload = vec![0xABu8; PAYLOAD_SIZE];
    let deadline = tokio::time::Instant::now() + Duration::from_secs(cli.duration);
    // Bytes are accumulated through a shared counter rather than returned by
    // each task, so a stream that moves gigabytes and *then* fails still has
    // its progress recorded. Returning per-task totals discarded the partial
    // count on error, which made a killed mid-run bridge look like it had
    // transferred nothing at all.
    let total = Arc::new(AtomicU64::new(0));
    // Optional per-stream byte-rate ceiling. `--mbps 0` (the default) keeps the
    // historical unpaced behaviour that the throughput baseline depends on;
    // a soak sets it so hours of traffic do not saturate the host.
    let per_stream_bps = if cli.mbps > 0 {
        cli.mbps as f64 * 1024.0 * 1024.0
    } else {
        0.0
    };
    // Per-read/write/connect cap: keep it below the test window so a stalled
    // bridge cannot swallow the whole run, but never smaller than 2s.
    let io_timeout = Duration::from_secs(cli.duration.clamp(2, 5));

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
        let total = total.clone();
        handles.push(tokio::spawn(async move {
            let mut stream = tokio::time::timeout(io_timeout, TcpStream::connect(&target))
                .await
                .map_err(|_| anyhow::anyhow!("stream {} connect timed out", i))?
                .with_context(|| format!("stream {} connect failed", i))?;
            let mut bytes = 0u64;
            let stream_start = tokio::time::Instant::now();
            let mut buf = vec![0u8; PAYLOAD_SIZE];
            while tokio::time::Instant::now() < deadline {
                tokio::time::timeout(io_timeout, stream.write_all(&payload))
                    .await
                    .map_err(|_| {
                        anyhow::anyhow!("stream {} write timed out (stalled bridge?)", i)
                    })??;
                tokio::time::timeout(io_timeout, stream.read_exact(&mut buf))
                    .await
                    .map_err(|_| {
                        anyhow::anyhow!("stream {} read timed out (stalled bridge?)", i)
                    })??;
                bytes += (PAYLOAD_SIZE * 2) as u64; // sent + received
                total.fetch_add((PAYLOAD_SIZE * 2) as u64, Ordering::Relaxed);
                if per_stream_bps > 0.0 {
                    let target = Duration::from_secs_f64(bytes as f64 / per_stream_bps);
                    let spent = stream_start.elapsed();
                    if spent < target {
                        tokio::time::sleep(target - spent).await;
                    }
                }
            }
            Ok::<(), anyhow::Error>(())
        }));
    }

    let mut failed_streams = 0usize;
    for h in handles {
        match h.await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                failed_streams += 1;
                tracing::error!(error = ?e, "Throughput stream failed: {:#}", e)
            }
            Err(e) => {
                failed_streams += 1;
                tracing::error!(error = %e, "Throughput task panicked: {}", e)
            }
        }
    }
    let total_bytes = total.load(Ordering::Relaxed);

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

    // Record the row (including 0-byte failures) before any bail, so callers
    // can distinguish "measured 0" from "config never ran".
    if let Some(path) = &cli.json_out {
        let record = serde_json::json!({
            "label": cli.label,
            "streams": streams,
            "duration_s": cli.duration,
            "mbps_cap_per_stream": cli.mbps,
            "total_bytes": total_bytes,
            "failed_streams": failed_streams,
            "mbps": mbps,
        });
        let mut opts = std::fs::OpenOptions::new();
        opts.create(true);
        if cli.json_truncate {
            opts.write(true).truncate(true);
        } else {
            opts.append(true);
        }
        let mut f = opts
            .open(path)
            .with_context(|| format!("open json_out {}", path))?;
        writeln!(f, "{}", record).context("write json_out")?;
    }

    // A run that transferred nothing is invalid, not a measurement: the bridge was
    // never usable (connect refused before proxy registration, or a stalled peer).
    // Fail loudly even with --no-floor so callers never ingest 0-byte "results".
    if total_bytes == 0 && failed_streams > 0 {
        anyhow::bail!(
            "throughput invalid: {failed_streams}/{streams} streams failed, 0 bytes transferred"
        );
    }
    // A partial failure still yields a number, but it is not a measurement of
    // the bridge: refuse to publish it unless the caller explicitly opted out
    // (the soak does, because a torn-down stack is reported by its own abort
    // path and the partial byte count is wanted as evidence).
    if failed_streams > 0 && !cli.no_floor {
        anyhow::bail!(
            "throughput invalid: {failed_streams}/{streams} streams failed after {total_bytes} bytes"
        );
    }

    if !cli.no_floor && mbps < 1.0 {
        anyhow::bail!("Throughput too low: {:.2} MB/s (minimum 1.0 MB/s)", mbps);
    }
    Ok(())
}
