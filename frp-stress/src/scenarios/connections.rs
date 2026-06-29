use crate::Cli;
use anyhow::Result;

pub async fn run(cli: &Cli) -> Result<()> {
    tracing::info!("connections scenario: {}s, {} conns", cli.duration, cli.concurrency);
    Ok(())
}
