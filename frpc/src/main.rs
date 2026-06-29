use std::path::Path;
use std::process;
use std::sync::Arc;

#[cfg(unix)]
use tokio::signal;
use tracing_subscriber::EnvFilter;

use frp_core::cli::{
    parse_frpc_args, FrpcCmd, FrpcRunArgs,
    build_single_proxy_config,
};
use frp_core::config::{load_client_config, collect_config_files, ClientConfig, ProxyConfig};
use frp_client::service::Service;

#[tokio::main]
async fn main() {
    let cmd = parse_frpc_args();
    match cmd {
        FrpcCmd::Run(args) => run_normal(args).await,
        FrpcCmd::Tcp(args) => run_single_proxy(
            &args.server_addr, args.server_port, args.token.as_deref(),
            args.to_proxy_config(),
        ).await,
        FrpcCmd::Udp(args) => run_single_proxy(
            &args.server_addr, args.server_port, args.token.as_deref(),
            args.to_proxy_config(),
        ).await,
        FrpcCmd::Http(args) => run_single_proxy(
            &args.server_addr, args.server_port, args.token.as_deref(),
            args.to_proxy_config(),
        ).await,
        FrpcCmd::Https(args) => run_single_proxy(
            &args.server_addr, args.server_port, args.token.as_deref(),
            args.to_proxy_config(),
        ).await,
        FrpcCmd::Stcp(args) => run_single_proxy(
            &args.server_addr, args.server_port, args.token.as_deref(),
            args.to_proxy_config(),
        ).await,
        FrpcCmd::Xtcp(args) => run_single_proxy(
            &args.server_addr, args.server_port, args.token.as_deref(),
            args.to_proxy_config(),
        ).await,
        FrpcCmd::Sudp(args) => run_single_proxy(
            &args.server_addr, args.server_port, args.token.as_deref(),
            args.to_proxy_config(),
        ).await,
        FrpcCmd::Tcpmux(args) => run_single_proxy(
            &args.server_addr, args.server_port, args.token.as_deref(),
            args.to_proxy_config(),
        ).await,
        FrpcCmd::Verify(args) => run_verify(&args.config).await,
    }
}

fn init_logging(_cli: &FrpcRunArgs, cfg: Option<&ClientConfig>) {
    let level = cfg.map(|c| c.log.level.as_str()).unwrap_or(
        #[cfg(feature = "debug-logs")]
        "debug,yamux=trace",
        #[cfg(not(feature = "debug-logs"))]
        "info",
    );
    let file = cfg.and_then(|c| if c.log.file.is_empty() { None } else { Some(c.log.file.as_str()) });

    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(level));

    let builder = tracing_subscriber::fmt().with_env_filter(filter);

    if let Some(path) = file {
        let file_appender = tracing_appender::rolling::daily(
            Path::new(path).parent().unwrap_or(Path::new(".")),
            Path::new(path).file_name().unwrap_or(std::ffi::OsStr::new("frpc.log")),
        );
        builder.with_writer(file_appender).init();
    } else {
        builder.init();
    }
}

async fn run_normal(args: FrpcRunArgs) {
    if args.show_version {
        println!("frpc {}", frp_core::VERSION);
        process::exit(0);
    }

    // Config directory mode
    if let Some(ref dir) = args.config_dir {
        init_logging(&args, None);

        let files = match collect_config_files(Path::new(dir)) {
            Ok(files) => files,
            Err(e) => {
                tracing::error!("Failed to read config directory: {}", e);
                process::exit(1);
            }
        };
        if files.is_empty() {
            tracing::error!("No config files found in directory: {dir}");
            process::exit(1);
        }
        tracing::info!(
            "frpc (Rust) v{} starting {} services from config directory",
            frp_core::VERSION,
            files.len()
        );
        let mut handles = Vec::new();
        for path in &files {
            let path_str = path.display().to_string();
            match load_client_config(&path_str, args.strict_config) {
                Ok(cfg) => {
                    handles.push(tokio::spawn(async move {
                        let service = match Service::new(cfg, Some(path_str.clone())).await {
                            Ok(svc) => svc,
                            Err(e) => {
                                tracing::error!("frpc service init error for config file [{}]: {}", path_str, e);
                                return;
                            }
                        };
                        if let Err(e) = service.run().await {
                            tracing::error!("frpc service error for config file [{}]: {}", path_str, e);
                        }
                    }));
                }
                Err(e) => {
                    tracing::error!("Failed to load config from [{}]: {}", path_str, e);
                }
            }
        }
        if handles.is_empty() {
            tracing::error!("No services started — all config files failed to load");
            process::exit(1);
        }
        for handle in handles {
            if let Err(e) = handle.await {
                tracing::error!("frpc service task panicked: {}", e);
            }
        }
        return;
    }

    // Single config mode
    let cfg = match load_client_config(&args.config, args.strict_config) {
        Ok(cfg) => cfg,
        Err(e) => {
            init_logging(&args, None);
            tracing::error!("Failed to load config: {}", e);
            process::exit(1);
        }
    };

    init_logging(&args, Some(&cfg));

    tracing::info!("frpc (Rust) v{} connecting...", frp_core::VERSION);
    let service = Arc::new(match Service::new(cfg, Some(args.config.clone())).await {
        Ok(svc) => svc,
        Err(e) => {
            tracing::error!("frpc init error: {}", e);
            process::exit(1);
        }
    });

    // SIGUSR1 → config hot reload
    #[cfg(unix)]
    {
        let reload_svc = service.clone();
        tokio::spawn(async move {
            #[cfg(target_os = "macos")]
            const SIGUSR1: std::os::raw::c_int = 30;
            #[cfg(not(target_os = "macos"))]
            const SIGUSR1: std::os::raw::c_int = 10;

            let mut sig = match signal::unix::signal(signal::unix::SignalKind::from_raw(SIGUSR1)) {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!("SIGUSR1 handler init failed: {}", e);
                    return;
                }
            };
            loop {
                sig.recv().await;
                reload_svc.request_reload();
            }
        });
    }

    if let Err(e) = service.run().await {
        tracing::error!("frpc error: {}", e);
        process::exit(1);
    }
}

async fn run_single_proxy(server_addr: &str, server_port: u16, token: Option<&str>, proxy: ProxyConfig) {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .init();

    let cfg = build_single_proxy_config(server_addr, server_port, token, proxy);
    tracing::info!("frpc (Rust) v{} starting single proxy...", frp_core::VERSION);

    let service = match Service::new(cfg, None).await {
        Ok(svc) => svc,
        Err(e) => {
            tracing::error!("frpc init error: {}", e);
            process::exit(1);
        }
    };

    if let Err(e) = service.run().await {
        tracing::error!("frpc error: {}", e);
        process::exit(1);
    }
}

async fn run_verify(config_path: &str) {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .init();

    match load_client_config(config_path, true) {
        Ok(cfg) => {
            println!("Config file {} is valid", config_path);
            println!("  Server: {}:{}", cfg.server_addr, cfg.server_port);
            println!("  Proxies: {}", cfg.proxies.len());
            println!("  Visitors: {}", cfg.visitors.len());
        }
        Err(e) => {
            eprintln!("Config file {} is invalid: {}", config_path, e);
            process::exit(1);
        }
    }
}
