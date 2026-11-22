use crate::Cli;
use anyhow::{Context, Result};
use tokio::io::AsyncReadExt;
use tokio::net::TcpListener;

/// TCP sink backend: binds 127.0.0.1:{port}, reads and DISCARDS bytes until EOF.
/// Used by the one-way `stream` scenario, where there is no reply to measure —
/// a sink never writes, so the reported rate is the send side alone.
pub async fn run(cli: &Cli) -> Result<()> {
    let addr = format!("127.0.0.1:{}", cli.port);
    let listener = TcpListener::bind(&addr)
        .await
        .with_context(|| format!("sink backend bind {} failed", addr))?;
    tracing::info!("sink backend listening on {}", addr);

    loop {
        let (mut sock, peer) = listener.accept().await?;
        // A sink never writes, so Nagle has nothing of its own to delay; the
        // flag is set anyway so this socket carries the same options as the
        // echo peer and the two backends differ only in what they do with the
        // bytes. (On the echo peer the same flag is what keeps its second write
        // from waiting on an ACK — see `echo.rs` — so a relay that splits a
        // message measures the relay, not a timer.)
        if let Err(e) = sock.set_nodelay(true) {
            tracing::warn!("could not disable Nagle on the sink socket: {e}");
        }
        tokio::spawn(async move {
            let mut buf = vec![0u8; 64 * 1024];
            loop {
                match sock.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(_) => {}
                    Err(_) => break,
                }
            }
            tracing::debug!("sink conn {} closed", peer);
        });
    }
}
