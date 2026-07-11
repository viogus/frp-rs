use crate::Cli;
use anyhow::{Context, Result};
use std::io::Write;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Percentiles (p50/p95/p99/max/mean) in microseconds from nanosecond samples.
/// Returns (p50, p95, p99, max, mean).
fn percentiles_us(mut samples_ns: Vec<u128>) -> (f64, f64, f64, f64, f64) {
    assert!(!samples_ns.is_empty(), "no latency samples");
    samples_ns.sort_unstable();
    let n = samples_ns.len();
    let pick = |p: f64| -> f64 {
        // nearest-rank; clamp index to the last element
        let idx = ((p * n as f64).ceil() as usize).saturating_sub(1).min(n - 1);
        samples_ns[idx] as f64 / 1000.0
    };
    let mean = samples_ns.iter().sum::<u128>() as f64 / n as f64 / 1000.0;
    let max = *samples_ns.last().unwrap() as f64 / 1000.0;
    (pick(0.50), pick(0.95), pick(0.99), max, mean)
}

pub async fn run(cli: &Cli) -> Result<()> {
    let target = format!(
        "{}:{}",
        cli.frps_addr.split(':').next().unwrap_or("127.0.0.1"),
        cli.port
    );
    let msg = vec![0xABu8; cli.msg_bytes];
    let mut buf = vec![0u8; cli.msg_bytes];
    let mut samples_ns: Vec<u128> = Vec::with_capacity(cli.samples);

    tracing::info!(
        label = %cli.label, mode = %cli.mode, samples = cli.samples, msg_bytes = cli.msg_bytes,
        "Latency [{}] mode={}: {} samples, {}B", cli.label, cli.mode, cli.samples, cli.msg_bytes
    );

    match cli.mode.as_str() {
        "steady" => {
            // One persistent connection; serialized ping-pong RTTs.
            let mut stream = TcpStream::connect(&target)
                .await
                .with_context(|| format!("steady connect to {target} failed"))?;
            // Warm-up: one untimed round-trip to establish the work-conn bridge.
            stream.write_all(&msg).await?;
            stream.read_exact(&mut buf).await?;
            for _ in 0..cli.samples {
                let t0 = std::time::Instant::now();
                stream.write_all(&msg).await?;
                stream.read_exact(&mut buf).await?;
                samples_ns.push(t0.elapsed().as_nanos());
            }
        }
        "setup" => {
            // Fresh connection each sample; measure connect->first-byte-echoed.
            for _ in 0..cli.samples {
                let t0 = std::time::Instant::now();
                let mut stream = TcpStream::connect(&target)
                    .await
                    .with_context(|| format!("setup connect to {target} failed"))?;
                stream.write_all(&msg).await?;
                stream.read_exact(&mut buf).await?;
                samples_ns.push(t0.elapsed().as_nanos());
                drop(stream);
            }
        }
        other => anyhow::bail!("unknown latency mode: {other} (expected steady|setup)"),
    }

    let (p50, p95, p99, max, mean) = percentiles_us(samples_ns);
    tracing::info!(
        label = %cli.label, mode = %cli.mode,
        p50_us = p50, p95_us = p95, p99_us = p99, max_us = max, mean_us = mean,
        "Latency [{}] mode={}: p50={:.1}us p95={:.1}us p99={:.1}us max={:.1}us mean={:.1}us",
        cli.label, cli.mode, p50, p95, p99, max, mean
    );

    if let Some(path) = &cli.json_out {
        let record = serde_json::json!({
            "label": cli.label,
            "mode": cli.mode,
            "samples": cli.samples,
            "msg_bytes": cli.msg_bytes,
            "p50_us": p50, "p95_us": p95, "p99_us": p99, "max_us": max, "mean_us": mean,
        });
        let mut f = std::fs::OpenOptions::new()
            .create(true).append(true).open(path)
            .with_context(|| format!("open json_out {path}"))?;
        writeln!(f, "{record}").context("write json_out")?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::percentiles_us;

    #[test]
    fn percentiles_basic() {
        // 1..=100 microseconds (as ns). p50~50us, p99~99us, max=100us.
        let samples: Vec<u128> = (1..=100).map(|v| v as u128 * 1000).collect();
        let (p50, p95, p99, max, mean) = percentiles_us(samples);
        assert!((p50 - 50.0).abs() < 1.5, "p50={p50}");
        assert!((p95 - 95.0).abs() < 1.5, "p95={p95}");
        assert!((p99 - 99.0).abs() < 1.5, "p99={p99}");
        assert!((max - 100.0).abs() < 0.001, "max={max}");
        assert!((mean - 50.5).abs() < 0.001, "mean={mean}");
    }

    #[test]
    fn percentiles_single() {
        let (p50, p95, p99, max, mean) = percentiles_us(vec![7000]);
        assert_eq!((p50, p95, p99, max, mean), (7.0, 7.0, 7.0, 7.0, 7.0));
    }
}
