use std::process;
use clap::Parser;
use tracing_subscriber::EnvFilter;

use frp_core::config::load_client_config;
use frp_client::service::Service;

#[derive(Parser)]
#[command(name = "frpc", about = "frp client (Rust rewrite)")]
struct Cli {
    /// Path to the configuration file.
    #[arg(short, long, default_value = "frpc.toml")]
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

    let cfg = match load_client_config(&cli.config) {
        Ok(cfg) => cfg,
        Err(e) => {
            tracing::error!("Failed to load config: {}", e);
            process::exit(1);
        }
    };

    tracing::info!("frpc (Rust) v{} connecting...", frp_core::VERSION);

    let service = Service::new(cfg);
    if let Err(e) = service.run().await {
        tracing::error!("frpc error: {}", e);
        process::exit(1);
    }
}
