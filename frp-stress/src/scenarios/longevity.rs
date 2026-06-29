use crate::Cli;
use anyhow::Result;

pub async fn run(cli: &Cli) -> Result<()> {
    tracing::info!("longevity scenario: {}s, {} conns", cli.duration, cli.concurrency);
    Ok(())
}
