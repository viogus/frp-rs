use crate::Cli;
use anyhow::Result;

pub async fn run(cli: &Cli) -> Result<()> {
    tracing::info!("mixed scenario: {}s, {} conns", cli.duration, cli.concurrency);
    Ok(())
}
