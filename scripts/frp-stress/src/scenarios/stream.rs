use crate::Cli;
use anyhow::{Context, Result};
use std::io::Write;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

const PAYLOAD_SIZE: usize = 1024 * 64; // 64 KiB chunks

/// One-way (streaming) throughput: N streams each connect, `write_all` a 64 KiB
/// payload in a loop until the deadline, and never read back. The `sink` peer
/// discards what arrives, so `total_bytes` is bytes SENT only — one direction,
/// not doubled like the ping-pong `throughput` scenario, which measures
/// frame-granularity round trips rather than the bridge's throughput.
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
    // its progress recorded (same reason as `throughput.rs`).
    let total = Arc::new(AtomicU64::new(0));
    // Per-write/connect cap: keep it below the test window so a stalled bridge
    // cannot swallow the whole run, but never smaller than 2s. A sender that
    // never reads blocks in `write_all` only once the socket buffers fill, so
    // this timeout is what turns a stall into a failed stream instead of a
    // hang.
    let io_timeout = Duration::from_secs(cli.duration.clamp(2, 5));

    tracing::info!(
        label = %cli.label,
        streams = %streams,
        "Stream [{}]: {}s, {} streams, one-way",
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
            // Same reason as the echo peer (see `echo.rs`): Nagle costs the
            // measured ~8 ms inside a chunked path, and on this shape the
            // sender's own writes are the thing being measured.
            if let Err(e) = stream.set_nodelay(true) {
                tracing::warn!("could not disable Nagle on the load socket: {e}");
            }
            while tokio::time::Instant::now() < deadline {
                tokio::time::timeout(io_timeout, stream.write_all(&payload))
                    .await
                    .map_err(|_| {
                        anyhow::anyhow!("stream {} write timed out (stalled bridge?)", i)
                    })??;
                total.fetch_add(PAYLOAD_SIZE as u64, Ordering::Relaxed);
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
                tracing::error!(error = ?e, "Stream failed: {:#}", e)
            }
            Err(e) => {
                failed_streams += 1;
                tracing::error!(error = %e, "Stream task panicked: {}", e)
            }
        }
    }
    let total_bytes = total.load(Ordering::Relaxed);

    // MiB/s, not MB/s (divisor 1024^2). The JSON key stays `mbps` so callers
    // that already read the ping-pong rows keep working — only the printed
    // unit is honest.
    let mibps = (total_bytes as f64 / (1024.0 * 1024.0)) / cli.duration as f64;
    tracing::info!(
        label = %cli.label,
        total_bytes = %total_bytes,
        mbps = %mibps,
        "Stream [{}]: {} total bytes, {:.2} MiB/s",
        cli.label,
        total_bytes,
        mibps
    );

    // Record the row (including 0-byte failures) before any bail, so callers
    // can distinguish "measured 0" from "config never ran".
    if let Some(path) = &cli.json_out {
        let record = serde_json::json!({
            "label": cli.label,
            "streams": streams,
            "duration_s": cli.duration,
            "total_bytes": total_bytes,
            "failed_streams": failed_streams,
            "mbps": mibps,
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

    // A run that transferred nothing is invalid, not a measurement: the bridge
    // was never usable (connect refused before proxy registration, or a stalled
    // peer). Fail loudly even with --no-floor so callers never ingest 0-byte
    // "results".
    if total_bytes == 0 && failed_streams > 0 {
        anyhow::bail!("stream invalid: {failed_streams}/{streams} streams failed, 0 bytes sent");
    }
    // A partial failure still yields a number, but it is not a measurement of
    // the bridge: refuse to publish it unless the caller explicitly opted out.
    if failed_streams > 0 && !cli.no_floor {
        anyhow::bail!(
            "stream invalid: {failed_streams}/{streams} streams failed after {total_bytes} bytes"
        );
    }

    if !cli.no_floor && mibps < 1.0 {
        anyhow::bail!("Stream too low: {:.2} MiB/s (minimum 1.0 MiB/s)", mibps);
    }
    Ok(())
}
