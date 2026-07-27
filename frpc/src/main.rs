use std::path::Path;
use std::process;
use std::sync::Arc;

#[cfg(unix)]
use tokio::signal;
use tracing_subscriber::EnvFilter;

use frp_client::service::Service;
use frp_core::cli::{
    build_single_proxy_config, parse_frpc_args, FrpcCmd, FrpcRunArgs, ReloadArgs, StatusArgs,
};
use frp_core::config::{collect_config_files, load_client_config, ClientConfig, ProxyConfig};
use frp_core::logging;
use frp_core::unsafe_features::UnsafeFeatures;
use frp_core::{EXIT_AUTH, EXIT_BIND, EXIT_CONFIG, EXIT_RUNTIME};

use data_encoding::BASE64;

// ── Admin HTTP client (raw TCP, zero deps) ─────────────────────────────────────

struct AdminConnection {
    addr: String,
    user: String,
    password: String,
}

/// Resolve admin server address, user, and password.
/// Priority: CLI flags > config file [web_server] > defaults (127.0.0.1:7400, no auth).
fn resolve_admin_connection(
    cli_addr: Option<&str>,
    cli_port: Option<u16>,
    cli_user: Option<&str>,
    cli_pwd: Option<&str>,
    config_path: Option<&str>,
) -> AdminConnection {
    // Priority 1: CLI flags (need both addr AND port)
    if let (Some(addr), Some(port)) = (cli_addr, cli_port) {
        return AdminConnection {
            addr: format!("{addr}:{port}"),
            user: cli_user.unwrap_or("").into(),
            password: cli_pwd.unwrap_or("").into(),
        };
    }
    // Priority 2: Config file [web_server] section
    if let Some(path) = config_path {
        if let Ok(cfg) = frp_core::config::load_client_config(path, true) {
            return AdminConnection {
                addr: format!("{}:{}", cfg.web_server.addr, cfg.web_server.port),
                user: cfg.web_server.user,
                password: cfg.web_server.password,
            };
        }
    }
    // Priority 3: Defaults
    AdminConnection {
        addr: "127.0.0.1:7400".into(),
        user: String::new(),
        password: String::new(),
    }
}

fn basic_auth_header(user: &str, password: &str) -> String {
    if user.is_empty() {
        return String::new();
    }
    let creds = format!("{user}:{password}");
    format!(
        "Authorization: Basic {}\r\n",
        BASE64.encode(creds.as_bytes())
    )
}

async fn admin_get(conn: &AdminConnection, path: &str) -> Result<String, String> {
    let mut stream = tokio::net::TcpStream::connect(&conn.addr)
        .await
        .map_err(|e| format!("connect {}: {e}", conn.addr))?;

    let auth = basic_auth_header(&conn.user, &conn.password);
    let req = format!(
        "GET {path} HTTP/1.1\r\nHost: {}\r\n{}{}\r\n",
        conn.addr, auth, "Connection: close\r\n",
    );
    tokio::io::AsyncWriteExt::write_all(&mut stream, req.as_bytes())
        .await
        .map_err(|e| format!("write: {e}"))?;

    let mut buf = Vec::new();
    tokio::io::AsyncReadExt::read_to_end(&mut stream, &mut buf)
        .await
        .map_err(|e| format!("read: {e}"))?;

    let response = String::from_utf8_lossy(&buf);
    let body = response.split("\r\n\r\n").nth(1).unwrap_or("");
    let status_line = response.lines().next().unwrap_or("");

    if status_line.contains("200") {
        Ok(body.to_string())
    } else {
        Err(status_line.to_string())
    }
}

async fn admin_post_json(
    conn: &AdminConnection,
    path: &str,
    json_body: &str,
) -> Result<String, String> {
    let mut stream = tokio::net::TcpStream::connect(&conn.addr)
        .await
        .map_err(|e| format!("connect {}: {e}", conn.addr))?;

    let auth = basic_auth_header(&conn.user, &conn.password);
    let req = format!(
        "POST {path} HTTP/1.1\r\nHost: {}\r\n{}Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{json_body}",
        conn.addr, auth, json_body.len(),
    );
    tokio::io::AsyncWriteExt::write_all(&mut stream, req.as_bytes())
        .await
        .map_err(|e| format!("write: {e}"))?;

    let mut buf = Vec::new();
    tokio::io::AsyncReadExt::read_to_end(&mut stream, &mut buf)
        .await
        .map_err(|e| format!("read: {e}"))?;

    let response = String::from_utf8_lossy(&buf);
    let body = response.split("\r\n\r\n").nth(1).unwrap_or("");
    let status_line = response.lines().next().unwrap_or("");

    if status_line.contains("200") {
        Ok(body.to_string())
    } else {
        Err(status_line.to_string())
    }
}

#[cfg(all(feature = "mimalloc", not(feature = "mem-profile")))]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

#[cfg(all(feature = "mem-profile", not(feature = "mimalloc")))]
#[global_allocator]
static GLOBAL: frp_core::mem_profile::CountingAlloc = frp_core::mem_profile::CountingAlloc;

#[tokio::main]
async fn main() {
    std::panic::set_hook(Box::new(|info| {
        eprintln!("fatal: {info}");
    }));
    let cmd = parse_frpc_args();
    #[cfg(feature = "mem-profile")]
    frp_core::mem_profile::spawn_emitter();
    match cmd {
        FrpcCmd::Run(args) => run_normal(args).await,
        FrpcCmd::Tcp(args) => {
            run_single_proxy(
                &args.server_addr,
                args.server_port,
                args.token.as_deref(),
                args.to_proxy_config(),
            )
            .await
        }
        FrpcCmd::Udp(args) => {
            run_single_proxy(
                &args.server_addr,
                args.server_port,
                args.token.as_deref(),
                args.to_proxy_config(),
            )
            .await
        }
        FrpcCmd::Http(args) => {
            run_single_proxy(
                &args.server_addr,
                args.server_port,
                args.token.as_deref(),
                args.to_proxy_config(),
            )
            .await
        }
        FrpcCmd::Https(args) => {
            run_single_proxy(
                &args.server_addr,
                args.server_port,
                args.token.as_deref(),
                args.to_proxy_config(),
            )
            .await
        }
        FrpcCmd::Stcp(args) => {
            run_single_proxy(
                &args.server_addr,
                args.server_port,
                args.token.as_deref(),
                args.to_proxy_config(),
            )
            .await
        }
        FrpcCmd::Xtcp(args) => {
            run_single_proxy(
                &args.server_addr,
                args.server_port,
                args.token.as_deref(),
                args.to_proxy_config(),
            )
            .await
        }
        FrpcCmd::Sudp(args) => {
            run_single_proxy(
                &args.server_addr,
                args.server_port,
                args.token.as_deref(),
                args.to_proxy_config(),
            )
            .await
        }
        FrpcCmd::Tcpmux(args) => {
            run_single_proxy(
                &args.server_addr,
                args.server_port,
                args.token.as_deref(),
                args.to_proxy_config(),
            )
            .await
        }
        FrpcCmd::Verify(args) => run_verify(&args.config).await,
        FrpcCmd::Reload(args) => run_reload(args).await,
        FrpcCmd::Status(args) => run_status(args).await,
    }
}

// ── Logging / tracing init ────────────────────────────────────────────────────

fn init_logging(cli: &FrpcRunArgs, cfg: Option<&ClientConfig>) {
    let level = logging::resolve_log_level(
        cli.log_level.clone(),
        cfg.map(|c| c.log.level.as_str()),
        "debug,yamux=trace",
    );
    let file = logging::resolve_log_file(
        cli.log_file.clone(),
        cfg.map(|c| c.log.file.as_str()).unwrap_or(""),
    );
    let ansi = logging::resolve_ansi(cli.disable_log_color);
    #[cfg(not(feature = "otel"))]
    logging::init_tracing(&level, file, ansi, "frpc.log");
    #[cfg(feature = "otel")]
    {
        let otlp_endpoint = std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT")
            .ok()
            .or_else(|| {
                cfg.and_then(|c| {
                    if c.observability.otlp_endpoint.is_empty() {
                        None
                    } else {
                        Some(c.observability.otlp_endpoint.clone())
                    }
                })
            });
        let svc_name = cfg
            .and_then(|c| {
                if c.observability.service_name.is_empty() {
                    None
                } else {
                    Some(c.observability.service_name.clone())
                }
            })
            .unwrap_or_else(|| "frpc".to_string());
        logging::init_tracing_otel(&level, file, ansi, &svc_name, otlp_endpoint, "frpc.log");
    }
}

async fn run_normal(mut args: FrpcRunArgs) {
    if args.show_version {
        println!("frpc {}", frp_core::VERSION);
        process::exit(0);
    }

    // Build UnsafeFeatures from CLI --allow-unsafe flag
    let allow_unsafe = std::mem::take(&mut args.allow_unsafe);
    let refs: Vec<&str> = allow_unsafe.iter().map(|s| s.as_str()).collect();
    let unsafe_features = UnsafeFeatures::new(&refs);

    // Config directory mode
    if let Some(ref dir) = args.config_dir {
        init_logging(&args, None);

        let files = match collect_config_files(Path::new(dir)) {
            Ok(files) => files,
            Err(e) => {
                tracing::error!(error = %e, "Failed to read config directory: {}", e);
                process::exit(frp_core::EXIT_CONFIG);
            }
        };
        if files.is_empty() {
            tracing::error!(dir = %dir, "No config files found in directory: {dir}");
            process::exit(frp_core::EXIT_CONFIG);
        }
        tracing::info!(
            version = %frp_core::VERSION,
            service_count = %files.len(),
            "frpc (Rust) v{} starting {} services from config directory",
            frp_core::VERSION,
            files.len()
        );
        let mut handles = Vec::new();
        for path in &files {
            let path_str = path.display().to_string();
            match load_client_config(&path_str, args.strict_config) {
                Ok(cfg) => {
                    let uf = unsafe_features.clone();
                    handles.push(tokio::spawn(async move {
                        let service = match Service::with_unsafe_features(cfg, Some(path_str.clone()), uf).await {
                            Ok(svc) => svc,
                            Err(e) => {
                                tracing::error!(config_file = %path_str, error = %e, "frpc service init error for config file [{}]: {}", path_str, e);
                                return;
                            }
                        };
                        if let Err(e) = service.run().await {
                            tracing::error!(config_file = %path_str, error = %e, "frpc service error for config file [{}]: {}", path_str, e);
                        }
                    }));
                }
                Err(e) => {
                    tracing::error!(path = %path_str, error = %e, "Failed to load config from [{}]: {}", path_str, e);
                }
            }
        }
        if handles.is_empty() {
            tracing::error!("No services started — all config files failed to load");
            process::exit(EXIT_CONFIG);
        }
        for handle in handles {
            if let Err(e) = handle.await {
                tracing::error!(error = %e, "frpc service task panicked: {}", e);
            }
        }
        return;
    }

    // Single config mode
    let cfg = match load_client_config(&args.config, args.strict_config) {
        Ok(cfg) => cfg,
        Err(e) => {
            init_logging(&args, None);
            tracing::error!(error = %e, "Failed to load config: {}", e);
            process::exit(EXIT_CONFIG);
        }
    };

    init_logging(&args, Some(&cfg));

    tracing::info!(version = %frp_core::VERSION, "frpc (Rust) v{} connecting...", frp_core::VERSION);
    let service = Arc::new(
        match Service::with_unsafe_features(cfg, Some(args.config.clone()), unsafe_features.clone())
            .await
        {
            Ok(svc) => svc,
            Err(e) => {
                let code = if logging::is_token_error(&e.to_string()) {
                    EXIT_AUTH
                } else {
                    EXIT_BIND
                };
                tracing::error!(error = %e, "frpc init error: {}", e);
                process::exit(code);
            }
        },
    );

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
                    tracing::warn!(error = %e, "SIGUSR1 handler init failed: {}", e);
                    return;
                }
            };
            loop {
                sig.recv().await;
                reload_svc.request_reload();
            }
        });
    }

    // SIGUSR2 → CPU profiling (Unix + profiling) — kill -USR2 <pid>
    // Runs a CPU profile for a configurable duration, writing a flamegraph SVG.
    // Environment variables:
    //   FRP_PROFILE_SECS — profiling duration in seconds (default 30)
    //   FRP_PROFILE_DIR  — output directory (default ".")
    #[cfg(all(unix, feature = "profiling"))]
    let profile_handle = {
        tokio::spawn(async move {
            #[cfg(target_os = "macos")]
            const SIGUSR2: std::os::raw::c_int = 31;
            #[cfg(not(target_os = "macos"))]
            const SIGUSR2: std::os::raw::c_int = 12;

            let mut sig = match signal::unix::signal(signal::unix::SignalKind::from_raw(SIGUSR2)) {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!(error = %e, "SIGUSR2 handler init failed: {}", e);
                    return;
                }
            };
            tracing::info!(pid = %std::process::id(), "SIGUSR2 profiling ready (pid={})", std::process::id());
            loop {
                sig.recv().await;
                let duration_secs = std::env::var("FRP_PROFILE_SECS")
                    .ok()
                    .and_then(|s| s.parse::<u64>().ok())
                    .unwrap_or(30);
                let output_dir =
                    std::env::var("FRP_PROFILE_DIR").unwrap_or_else(|_| ".".to_string());
                tokio::task::spawn_blocking(move || {
                    match frp_core::profiling::dump_cpu_profile(
                        std::time::Duration::from_secs(duration_secs),
                        std::path::Path::new(&output_dir),
                        "frpc",
                    ) {
                        Ok(path) => {
                            tracing::info!("SIGUSR2: CPU profile saved to {}", path.display())
                        }
                        Err(e) => tracing::error!(error = %e, "SIGUSR2: CPU profile failed: {}", e),
                    }
                });
            }
        })
    };

    if let Err(e) = service.run().await {
        tracing::error!(error = %e, "frpc error: {}", e);
        process::exit(EXIT_RUNTIME);
    }

    #[cfg(all(unix, feature = "profiling"))]
    profile_handle.abort();
}

async fn run_single_proxy(
    server_addr: &str,
    server_port: u16,
    token: Option<&str>,
    proxy: ProxyConfig,
) {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let cfg = build_single_proxy_config(server_addr, server_port, token, proxy);
    tracing::info!(version = %frp_core::VERSION, "frpc (Rust) v{} starting single proxy...", frp_core::VERSION);

    let service = match Service::new(cfg, None).await {
        Ok(svc) => svc,
        Err(e) => {
            let code = if logging::is_token_error(&e.to_string()) {
                EXIT_AUTH
            } else {
                EXIT_BIND
            };
            tracing::error!(error = %e, "frpc init error: {}", e);
            process::exit(code);
        }
    };

    if let Err(e) = service.run().await {
        tracing::error!(error = %e, "frpc error: {}", e);
        process::exit(EXIT_RUNTIME);
    }
}

async fn run_verify(config_path: &str) {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
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
            process::exit(EXIT_CONFIG);
        }
    }
}

async fn run_reload(args: ReloadArgs) {
    let conn = resolve_admin_connection(
        args.admin_addr.as_deref(),
        args.admin_port,
        args.admin_user.as_deref(),
        args.admin_pwd.as_deref(),
        args.config.as_deref(),
    );
    let body = format!(r#"{{"strictConfig":{}}}"#, args.strict_config);
    match admin_post_json(&conn, "/api/reload", &body).await {
        Ok(summary) => println!("reload success: {summary}"),
        Err(e) => {
            eprintln!("reload failed: {e}");
            std::process::exit(frp_core::EXIT_RUNTIME);
        }
    }
}

async fn run_status(args: StatusArgs) {
    let conn = resolve_admin_connection(
        args.admin_addr.as_deref(),
        args.admin_port,
        args.admin_user.as_deref(),
        args.admin_pwd.as_deref(),
        args.config.as_deref(),
    );
    let body = match admin_get(&conn, "/api/status").await {
        Ok(b) => b,
        Err(e) => {
            eprintln!("status query failed: {e}");
            std::process::exit(frp_core::EXIT_RUNTIME);
        }
    };

    if args.json {
        println!("{body}");
        return;
    }

    print_status_table(&body);
}

fn print_status_table(body: &str) {
    let parsed: serde_json::Value = match serde_json::from_str(body) {
        Ok(v) => v,
        Err(_) => {
            println!("Unable to parse status response:\n{body}");
            return;
        }
    };

    let mut rows: Vec<(String, String, String, String, String, String)> = Vec::new();
    // parsed is {"tcp": [...], "http": [...], ...}
    if let Some(obj) = parsed.as_object() {
        for (_, entries) in obj {
            if let Some(arr) = entries.as_array() {
                for entry in arr {
                    let name = entry["name"].as_str().unwrap_or("").to_string();
                    let ptype = entry["type"].as_str().unwrap_or("").to_string();
                    let status = entry["status"].as_str().unwrap_or("").to_string();
                    let local = entry["local_addr"].as_str().unwrap_or("").to_string();
                    let remote = entry["remote_addr"].as_str().unwrap_or("").to_string();
                    let err = entry["err"].as_str().unwrap_or("").to_string();
                    rows.push((name, ptype, status, local, remote, err));
                }
            }
        }
    }
    rows.sort_by(|a, b| a.0.cmp(&b.0));

    // Compute column widths (minimum header width)
    let mut name_w = 4;
    let mut type_w = 4;
    let mut status_w = 6;
    let mut local_w = 10;
    let mut remote_w = 11;
    for (name, ptype, status, local, remote, _err) in &rows {
        name_w = name_w.max(name.len());
        type_w = type_w.max(ptype.len());
        status_w = status_w.max(status.len());
        local_w = local_w.max(local.len());
        remote_w = remote_w.max(remote.len());
    }

    println!(
        "{:name_w$}  {:type_w$}  {:status_w$}  {:local_w$}  {:remote_w$}  ERR",
        "NAME", "TYPE", "STATUS", "LOCAL ADDR", "REMOTE ADDR",
    );

    for (name, ptype, status, local, remote, err) in &rows {
        let truncated_err = if err.len() > 40 {
            format!("{}...", err.chars().take(37).collect::<String>())
        } else {
            err.clone()
        };
        println!(
            "{:name_w$}  {:type_w$}  {:status_w$}  {:local_w$}  {:remote_w$}  {truncated_err}",
            name, ptype, status, local, remote,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_auth_header_empty_creds() {
        assert_eq!(basic_auth_header("", ""), "");
        assert_eq!(basic_auth_header("", "secret"), "");
    }

    #[test]
    fn test_basic_auth_header_encodes() {
        let header = basic_auth_header("admin", "admin");
        assert!(header.starts_with("Authorization: Basic "));
        assert!(header.ends_with("\r\n"));
        // "admin:admin" in base64 = "YWRtaW46YWRtaW4="
        assert!(header.contains("YWRtaW46YWRtaW4="));
    }

    #[test]
    fn test_resolve_admin_connection_cli_priority() {
        let conn = resolve_admin_connection(
            Some("10.0.0.1"),
            Some(1234),
            Some("u"),
            Some("p"),
            None, // no config file
        );
        assert_eq!(conn.addr, "10.0.0.1:1234");
        assert_eq!(conn.user, "u");
        assert_eq!(conn.password, "p");
    }

    #[test]
    fn test_resolve_admin_connection_defaults() {
        let conn = resolve_admin_connection(None, None, None, None, None);
        assert_eq!(conn.addr, "127.0.0.1:7400");
        assert_eq!(conn.user, "");
        assert_eq!(conn.password, "");
    }

    #[test]
    fn test_resolve_admin_connection_cli_addr_only_falls_through() {
        // addr without port is not enough — falls to defaults
        let conn = resolve_admin_connection(Some("10.0.0.1"), None, Some("u"), Some("p"), None);
        assert_eq!(conn.addr, "127.0.0.1:7400");
    }

    #[test]
    fn test_resolve_admin_connection_cli_port_only_falls_through() {
        let conn = resolve_admin_connection(None, Some(9999), None, None, None);
        assert_eq!(conn.addr, "127.0.0.1:7400");
    }
}
