use std::process;
use clap::Parser;
use tracing_subscriber::EnvFilter;

use frp_core::config::load_server_config;
use frp_server::service::Service;

#[derive(Parser)]
#[command(name = "frps", about = "frp server (Rust rewrite)")]
struct Cli {
    /// Path to the configuration file.
    #[arg(short, long, default_value = "frps.toml")]
    config: String,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();

    let cfg = match load_server_config(&cli.config) {
        Ok(cfg) => cfg,
        Err(e) => {
            tracing::error!("Failed to load config: {}", e);
            process::exit(1);
        }
    };

    tracing::info!("frps (Rust) v{} starting...", frp_core::VERSION);

    let service = Service::new(cfg);
    if let Err(e) = service.run().await {
        tracing::error!("frps error: {}", e);
        process::exit(1);
    }
}
