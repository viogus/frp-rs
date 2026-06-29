use crate::Cli;
use anyhow::Result;

pub async fn run(cli: &Cli) -> Result<()> {
    tracing::info!("memory scenario: {}s, {} conns", cli.duration, cli.concurrency);
    Ok(())
}
