use crate::Cli;
use anyhow::{Context, Result};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;

/// UDP echo backend: binds 127.0.0.1:{port} and echoes every datagram to its
/// source. The UDP counterpart of `scenarios::echo`, so the bridge relays real
/// traffic instead of an accept-then-close socket.
pub async fn run_echo(cli: &Cli) -> Result<()> {
    let addr = format!("127.0.0.1:{}", cli.port);
    let sock = UdpSocket::bind(&addr)
        .await
        .with_context(|| format!("udp echo backend bind {} failed", addr))?;
    tracing::info!("udp echo backend listening on {}", addr);

    let mut buf = vec![0u8; 65_507];
    loop {
        let (n, peer) = sock.recv_from(&mut buf).await?;
        if let Err(e) = sock.send_to(&buf[..n], peer).await {
            tracing::debug!(error = %e, "udp echo send failed");
        }
    }
}

/// UDP request/response load against the proxied port.
///
/// Each flow is one socket doing strict ping-pong (send `--packet-size` bytes,
/// await the echo, send again), so the number is datagrams per second of a
/// round trip — the UDP analogue of the `throughput` scenario. A strict
/// ping-pong is deliberately per-flow serial: it measures per-datagram cost,
/// not a NIC's saturation point, and needs no pacing to stay stable.
pub async fn run(cli: &Cli) -> Result<()> {
    let flows = if cli.streams > 0 { cli.streams } else { 1 };
    let size = cli.udp_packet_size.clamp(1, 65_000);
    let target = format!("127.0.0.1:{}", cli.port);
    let sent = Arc::new(AtomicU64::new(0));
    let echoed = Arc::new(AtomicU64::new(0));
    let lost = Arc::new(AtomicU64::new(0));
    let deadline = Instant::now() + Duration::from_secs(cli.duration.max(1));

    let mut tasks = Vec::with_capacity(flows);
    for _ in 0..flows {
        let sent = Arc::clone(&sent);
        let echoed = Arc::clone(&echoed);
        let lost = Arc::clone(&lost);
        let target = target.clone();
        tasks.push(tokio::spawn(async move {
            let sock = match UdpSocket::bind("127.0.0.1:0").await {
                Ok(s) => s,
                Err(e) => {
                    tracing::error!(error = %e, "udp flow bind failed");
                    return;
                }
            };
            if let Err(e) = sock.connect(&target).await {
                tracing::error!(error = %e, "udp flow connect {} failed", target);
                return;
            }
            let payload = vec![0xA5u8; size];
            let mut back = vec![0u8; 65_507];
            while Instant::now() < deadline {
                if sock.send(&payload).await.is_err() {
                    lost.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
                sent.fetch_add(1, Ordering::Relaxed);
                match tokio::time::timeout(Duration::from_millis(500), sock.recv(&mut back)).await {
                    Ok(Ok(n)) if n > 0 => {
                        echoed.fetch_add(1, Ordering::Relaxed);
                    }
                    _ => {
                        lost.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        }));
    }
    for t in tasks {
        let _ = t.await;
    }

    let sent_n = sent.load(Ordering::Relaxed);
    let echoed_n = echoed.load(Ordering::Relaxed);
    let lost_n = lost.load(Ordering::Relaxed);
    let secs = cli.duration.max(1) as f64;
    let pps = echoed_n as f64 / secs;
    // Payload only, ONE direction: unlike the TCP harness (send + echoed read),
    // a UDP echo payload is not counted twice — this is the useful number.
    let mibps = (echoed_n as f64 * size as f64) / (1024.0 * 1024.0) / secs;

    tracing::info!(
        label = %cli.label,
        flows = %flows,
        packet_size = %size,
        sent = %sent_n,
        echoed = %echoed_n,
        lost = %lost_n,
        pps = %pps,
        "Udp [{}]: {} datagrams echoed of {} sent, {:.1} pps, {:.2} MiB/s one-way",
        cli.label,
        echoed_n,
        sent_n,
        pps,
        mibps
    );

    if let Some(path) = &cli.json_out {
        let record = serde_json::json!({
            "label": cli.label,
            "flows": flows,
            "packet_size": size,
            "duration_s": cli.duration,
            "packets_sent": sent_n,
            "packets_echoed": echoed_n,
            "timeouts": lost_n,
            "pps": pps,
            "mbps_one_way": mibps,
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
        use std::io::Write;
        writeln!(f, "{}", record).context("write json_out")?;
    }

    if echoed_n == 0 && !cli.no_floor {
        anyhow::bail!(
            "udp invalid: 0 of {sent_n} datagrams echoed — the proxy or backend is not relaying"
        );
    }
    if sent_n > 0 && echoed_n * 2 < sent_n && !cli.no_floor {
        anyhow::bail!(
            "udp invalid: only {echoed_n} of {sent_n} datagrams echoed ({lost_n} timeouts)"
        );
    }
    Ok(())
}
