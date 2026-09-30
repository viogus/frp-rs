use crate::Cli;
use anyhow::{Context, Result};
use std::io::Write;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
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

/// Record the traffic this generator actually achieved.
///
/// Without it a caller cannot distinguish "the load ran for hours and RSS
/// stayed flat" from "every connect/echo failed and the flat line is an
/// artifact". A long-uptime soak must be able to reject the second reading, so
/// the counters are written as a machine-readable one-line JSON record
/// alongside the human log — the same `--json-out` contract the throughput and
/// latency scenarios already use.
fn write_result(
    cli: &Cli,
    mode: &str,
    connections: u64,
    round_trips: u64,
    bytes: u64,
) -> Result<()> {
    let Some(path) = &cli.json_out else {
        return Ok(());
    };
    let record = serde_json::json!({
        "scenario": "memory",
        "mode": mode,
        "label": cli.label,
        "duration_s": cli.duration,
        "concurrency": cli.concurrency,
        "rate_cap": cli.rate,
        "connections": connections,
        "round_trips": round_trips,
        "bytes": bytes,
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
        .with_context(|| format!("open json_out {path}"))?;
    writeln!(f, "{record}").context("write json_out")?;
    Ok(())
}

/// Open N proxy connections, send one small message on each (forcing the
/// server + client bridge to allocate their per-connection buffers), then hold
/// them idle. Targets resident footprint (the pinned-buffer cost).
async fn idle_hold(cli: &Cli, target: &str) -> Result<()> {
    let msg = vec![0xABu8; cli.msg_bytes.max(1)];
    let mut buf = vec![0u8; msg.len()];
    let mut streams = Vec::with_capacity(cli.concurrency);
    tracing::info!(
        n = cli.concurrency,
        "idle_hold: opening {} conns, 1 msg each",
        cli.concurrency
    );
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
    let n = streams.len() as u64;
    let bytes = n * (msg.len() as u64) * 2; // one send + one echo per conn
    drop(streams);
    write_result(cli, "idle_hold", n, n, bytes)?;
    tokio::time::sleep(Duration::from_secs(2)).await;
    Ok(())
}

/// Repeatedly open -> send one message -> close, at fixed concurrency, for the
/// duration. Targets allocation rate (per-connection setup/teardown churn).
///
/// `--rate` caps connection *starts* per second across all workers. It exists
/// instead of an unpaced spin for two reasons:
///
/// 1. **Method.** An unpaced generator is limited by each stack's own capacity,
///    so the faster implementation is handed more connections and the two sides
///    do not actually receive the same amount of work. A fixed rate offers both
///    the same number of connection starts per second.
/// 2. **Surviving hours.** Every client connection parks a socket in TIME_WAIT
///    (~30 s on macOS, ephemeral range 49152-65535 = 16 384 ports). An unpaced
///    spin exhausts that range in seconds, so a multi-hour run would die of
///    port exhaustion rather than measure memory.
async fn churn(cli: &Cli, target: &str) -> Result<()> {
    let msg = vec![0xABu8; cli.msg_bytes.max(1)];
    let conc = cli.concurrency.max(1);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(cli.duration);
    let period = if cli.rate > 0 {
        Some(Duration::from_secs_f64(conc as f64 / cli.rate as f64))
    } else {
        None
    };
    tracing::info!(
        concurrency = conc,
        rate_cap = cli.rate,
        "churn: MARK start, open->1msg->close for {}s",
        cli.duration
    );
    let connections = Arc::new(AtomicU64::new(0));
    let round_trips = Arc::new(AtomicU64::new(0));
    let bytes = Arc::new(AtomicU64::new(0));
    let mut handles = Vec::with_capacity(conc);
    for _ in 0..conc {
        let target = target.to_string();
        let msg = msg.clone();
        let connections = connections.clone();
        let round_trips = round_trips.clone();
        let bytes = bytes.clone();
        handles.push(tokio::spawn(async move {
            let mut buf = vec![0u8; msg.len()];
            while tokio::time::Instant::now() < deadline {
                let started = tokio::time::Instant::now();
                if let Ok(mut s) = TcpStream::connect(&target).await {
                    connections.fetch_add(1, Ordering::Relaxed);
                    // A round trip counts only when the echo came back: a
                    // half-open bridge that accepts and swallows bytes must not
                    // be recorded as "load delivered".
                    if s.write_all(&msg).await.is_ok() && s.read_exact(&mut buf).await.is_ok() {
                        round_trips.fetch_add(1, Ordering::Relaxed);
                        bytes.fetch_add((msg.len() * 2) as u64, Ordering::Relaxed);
                    }
                    drop(s);
                }
                if let Some(p) = period {
                    let spent = started.elapsed();
                    if spent < p {
                        tokio::time::sleep(p - spent).await;
                    }
                }
            }
        }));
    }
    for h in handles {
        let _ = h.await;
    }
    let connections = connections.load(Ordering::Relaxed);
    let round_trips = round_trips.load(Ordering::Relaxed);
    let bytes = bytes.load(Ordering::Relaxed);
    tracing::info!(
        connections = connections,
        round_trips = round_trips,
        bytes = bytes,
        "churn: MARK end"
    );
    write_result(cli, "churn", connections, round_trips, bytes)?;
    tokio::time::sleep(Duration::from_secs(1)).await;
    Ok(())
}
