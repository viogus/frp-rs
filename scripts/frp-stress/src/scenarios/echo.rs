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
