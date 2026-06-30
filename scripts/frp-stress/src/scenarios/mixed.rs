use crate::Cli;
use anyhow::Result;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

pub async fn run(cli: &Cli) -> Result<()> {
    let target = format!(
        "{}:{}",
        cli.frps_addr.split(':').next().unwrap_or("127.0.0.1"),
        cli.port
    );
    tracing::info!(duration = %cli.duration, "Mixed load test: {}s", cli.duration);

    let target1 = target.clone();
    let target2 = target.clone();
    let target3 = target.clone();
    let dur = cli.duration;

    let (r1, r2, r3) = tokio::join!(
        tokio::spawn(steady_load(target1, dur)),
        tokio::spawn(burst_load(target2, dur)),
        tokio::spawn(pingpong_load(target3, dur)),
    );

    r1.map_err(|e| anyhow::anyhow!("steady_load panic: {}", e))??;
    r2.map_err(|e| anyhow::anyhow!("burst_load panic: {}", e))??;
    r3.map_err(|e| anyhow::anyhow!("pingpong_load panic: {}", e))??;

    tracing::info!("Mixed load: all workloads stable");
    Ok(())
}

async fn steady_load(target: String, dur: u64) -> Result<()> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(dur);
    let mut streams = Vec::new();
    while tokio::time::Instant::now() < deadline {
        match TcpStream::connect(&target).await {
            Ok(s) => streams.push(s),
            Err(e) => tracing::warn!(error = %e, "steady connect: {}", e),
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
        if streams.len() > 100 {
            streams.drain(0..50);
        }
    }
    Ok(())
}

async fn burst_load(target: String, dur: u64) -> Result<()> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(dur);
    while tokio::time::Instant::now() < deadline {
        let mut batch = Vec::with_capacity(10);
        for _ in 0..10 {
            batch.push(TcpStream::connect(&target));
        }
        futures_util::future::join_all(batch).await;
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
    Ok(())
}

async fn pingpong_load(target: String, dur: u64) -> Result<()> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(dur);
    while tokio::time::Instant::now() < deadline {
        if let Ok(mut s) = TcpStream::connect(&target).await {
            let _ = s.write_all(b"ping").await;
            let mut buf = [0u8; 4];
            let _ = s.read_exact(&mut buf).await;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    Ok(())
}
