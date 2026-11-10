use crate::Cli;
use anyhow::{Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// TCP echo backend: binds 127.0.0.1:{port}, echoes bytes until process killed.
/// Used as the throughput-baseline backend so the bridge relays real traffic.
pub async fn run(cli: &Cli) -> Result<()> {
    let addr = format!("127.0.0.1:{}", cli.port);
    let listener = TcpListener::bind(&addr)
        .await
        .with_context(|| format!("echo backend bind {} failed", addr))?;
    tracing::info!("echo backend listening on {}", addr);

    loop {
        let (mut sock, peer) = listener.accept().await?;
        // Nagle turns this peer into a timer: a relay that splits a message
        // into two chunks makes the echo's second write wait for an ACK, and
        // the measured round trip jumps from ~0.2 ms to ~7 ms (measured: 64 KiB
        // ping-pong through a plain tokio relay, 32 KiB chunks, 18 MiB/s with
        // Nagle vs 737 MiB/s without). Every matrix row and baseline goes
        // through this socket, so it must not add delay of its own.
        let _ = sock.set_nodelay(true);
        tokio::spawn(async move {
            let mut buf = vec![0u8; 64 * 1024];
            loop {
                match sock.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => {
                        if sock.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
            tracing::debug!("echo conn {} closed", peer);
        });
    }
}
