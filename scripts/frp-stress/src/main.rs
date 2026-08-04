//! frp-stress: CI stress testing for frp-rs.
//!
//! Three dimensions x 6 scenarios. CI-only via STRESS_TEST=1.
//! Launched by scripts/stress-test.sh.

use anyhow::Result;
use clap::Parser;

mod scenarios;

#[derive(Parser)]
#[command(name = "frp-stress", about = "frp-rs stress testing framework")]
struct Cli {
    /// Scenario to run (memory, connections, throughput, longevity, burst, mixed, all)
    #[arg(short, long, default_value = "all")]
    scenario: String,

    /// Duration in seconds (default: 60 for CI, longer for manual)
    #[arg(short, long, default_value = "60")]
    duration: u64,

    /// frps address (default: 127.0.0.1:7000)
    #[arg(long, default_value = "127.0.0.1:7000")]
    frps_addr: String,

    /// Auth token (default: test-token)
    #[arg(long, default_value = "test-token")]
    token: String,

    /// Concurrent connections for load scenarios
    #[arg(short, long, default_value = "100")]
    concurrency: usize,

    /// Proxy base port (server-side port allocation starts here)
    #[arg(short, long, default_value = "7000")]
    port: u16,

    /// Single-stream count override for throughput (defaults to --concurrency)
    #[arg(long, default_value = "0")]
    streams: usize,

    /// Write structured JSON result to this path (append mode unless --json-truncate)
    #[arg(long)]
    json_out: Option<String>,

    /// Truncate (overwrite) the --json-out file instead of appending, so repeated
    /// runs cannot stack stale rows from earlier invocations into one file.
    #[arg(long, default_value = "false")]
    json_truncate: bool,

    /// Configuration label recorded in JSON output (e.g. "plain", "tls")
    #[arg(long, default_value = "unlabeled")]
    label: String,

    /// Disable the throughput pass/fail floor (baseline measurement mode)
    #[arg(long, default_value = "false")]
    no_floor: bool,

    /// Latency mode: "steady" (persistent conn RTT) or "setup" (fresh-conn connect->first-byte)
    #[arg(long, default_value = "steady")]
    mode: String,

    /// Number of latency samples to collect
    #[arg(long, default_value = "2000")]
    samples: usize,

    /// Message size in bytes for latency probes
    #[arg(long, default_value = "64")]
    msg_bytes: usize,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt().with_env_filter("info").init();

    let cli = Cli::parse();
    tracing::info!(
        "frp-stress starting: scenario={}, duration={}s",
        cli.scenario,
        cli.duration
    );

    match cli.scenario.as_str() {
        "memory" => scenarios::memory::run(&cli).await?,
        "connections" => scenarios::connections::run(&cli).await?,
        "throughput" => scenarios::throughput::run(&cli).await?,
        "longevity" => scenarios::longevity::run(&cli).await?,
        "burst" => scenarios::burst::run(&cli).await?,
        "mixed" => scenarios::mixed::run(&cli).await?,
        "echo" => scenarios::echo::run(&cli).await?,
        "latency" => scenarios::latency::run(&cli).await?,
        "all" => scenarios::run_all(&cli).await?,
        _ => anyhow::bail!("unknown scenario: {}", cli.scenario),
    }

    tracing::info!("frp-stress complete: success");
    Ok(())
}
