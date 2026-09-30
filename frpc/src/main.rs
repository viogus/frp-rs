use std::path::Path;
use std::process;
use std::sync::Arc;
use std::time::Duration;

#[cfg(unix)]
use tokio::signal;

use frp_client::service::Service;
use frp_core::cli::{
    build_single_proxy_config, parse_frpc_args, FrpcCmd, FrpcRunArgs, ReloadArgs, StatusArgs,
    StopArgs,
};
use frp_core::config::{
    collect_config_files, load_client_config, load_client_config_with_presence,
    load_client_config_with_presence_checked, ClientConfig, ProxyConfig,
};
use frp_core::logging;
use frp_core::unsafe_features::UnsafeFeatures;
use frp_core::{EXIT_CONFIG, EXIT_RUNTIME};

use frp_core::base64::encode as base64_encode;

// ── Admin HTTP client (raw TCP, zero deps) ─────────────────────────────────────

#[derive(Debug)]
struct AdminConnection {
    addr: String,
    user: String,
    password: String,
}

/// Why the admin address could not be resolved for `reload`/`status`/`stop`.
///
/// Go frp v0.71.0 (`cmd/frpc/sub/admin.go:56-71`) loads the config first and, on
/// any error, prints it and exits 1 **without contacting anything**; it then
/// rejects `cfg.WebServer.Port <= 0` with a fixed message and exits 1. There is
/// no `127.0.0.1:7400` fallback anywhere in that path. Both refusals are
/// modelled here so a broken config can never be silently replaced by a default
/// address.
#[derive(Debug)]
enum AdminResolveError {
    /// `load_client_config` failed (missing file, parse error, unknown field in
    /// strict mode, …). The string is the load error, printed verbatim.
    Config(String),
    /// The effective admin port is 0 — from `[web_server] port`, or from the
    /// frp-rs-only `--admin-port` extension when it is explicitly `0`.
    NoPort,
}

impl std::fmt::Display for AdminResolveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            // Go: `fmt.Println(err); os.Exit(1)` (cmd/frpc/sub/admin.go:59-62).
            AdminResolveError::Config(e) => f.write_str(e),
            // Go: `fmt.Println("web server port should be set if you want to
            // use this feature"); os.Exit(1)` (cmd/frpc/sub/admin.go:63-66).
            AdminResolveError::NoPort => {
                f.write_str("web server port should be set if you want to use this feature")
            }
        }
    }
}

/// Resolve admin server address, user, and password.
///
/// A config path, when given, is **always** loaded and validated; a load error
/// is returned instead of falling back to a default address (Go always loads,
/// and a broken config is exactly what the user must be told). Priority after a
/// successful load: CLI flags (only when BOTH `--admin-addr` AND `--admin-port`
/// are given — the pre-existing rule, unchanged) > config file `[web_server]`.
/// With no config path at all the frp-rs default `127.0.0.1:7400` is used.
///
/// `--admin-addr`/`--admin-port`/`--admin-user`/`--admin-pwd` are an
/// undocumented frp-rs extension: Go v0.71.0's `reload`/`status`/`stop` register
/// no such flags (`cmd/frpc/sub/admin.go:34-50`), so they can never compensate
/// for a config that fails to load.
fn resolve_admin_connection(
    cli_addr: Option<&str>,
    cli_port: Option<u16>,
    cli_user: Option<&str>,
    cli_pwd: Option<&str>,
    config_path: Option<&str>,
    strict_config: bool,
) -> Result<AdminConnection, AdminResolveError> {
    if let Some(path) = config_path {
        let cfg = load_client_config(path, strict_config)
            .map_err(|e| AdminResolveError::Config(e.to_string()))?;
        let (addr, port, user, password) = match (cli_addr, cli_port) {
            // Priority 1: CLI flags (need both addr AND port).
            (Some(addr), Some(port)) => (
                addr.to_string(),
                port,
                cli_user.unwrap_or("").to_string(),
                cli_pwd.unwrap_or("").to_string(),
            ),
            // Priority 2: config file [web_server] section.
            _ => (
                cfg.web_server.addr.clone(),
                cfg.web_server.port,
                cfg.web_server.user.clone(),
                cfg.web_server.password.clone(),
            ),
        };
        // An explicit `--admin-port 0` is rejected with Go's message rather than
        // treated as "not supplied": falling back to the config port would
        // silently ignore an explicit flag, and `connect 127.0.0.1:0` is never
        // valid. Same rule Go applies to a port-0 `[web_server]`.
        if port == 0 {
            return Err(AdminResolveError::NoPort);
        }
        return Ok(AdminConnection {
            addr: format!("{addr}:{port}"),
            user,
            password,
        });
    }
    // No config path supplied. Go defaults `-c` to `./frpc.ini`; frp-rs keeps
    // `-c` optional for these two subcommands, so there is nothing to load —
    // a recorded divergence, unchanged here.
    if let (Some(addr), Some(port)) = (cli_addr, cli_port) {
        if port == 0 {
            return Err(AdminResolveError::NoPort);
        }
        return Ok(AdminConnection {
            addr: format!("{addr}:{port}"),
            user: cli_user.unwrap_or("").into(),
            password: cli_pwd.unwrap_or("").into(),
        });
    }
    Ok(AdminConnection {
        addr: "127.0.0.1:7400".into(),
        user: String::new(),
        password: String::new(),
    })
}

fn basic_auth_header(user: &str, password: &str) -> String {
    if user.is_empty() {
        return String::new();
    }
    let creds = format!("{user}:{password}");
    format!(
        "Authorization: Basic {}\r\n",
        base64_encode(creds.as_bytes())
    )
}

/// Error for an admin call that ran out of its `--api-timeout` deadline, or
/// whose deadline had already passed before it started.
///
/// frp-rs's wording is its own: Go wraps the same call in
/// `context.WithTimeout` (`cmd/frpc/sub/admin.go`) and reports
/// `context deadline exceeded`. Measured on v0.71.0 with `--api-timeout=0`,
/// `=0s` and `=-1s`: `Post "http://127.0.0.1:27411/api/stop": context deadline
/// exceeded` on **stdout**, exit 1.
fn admin_timeout_error(timeout: Duration) -> String {
    format!("admin request timed out after {timeout:?}")
}

/// Bounds one whole admin HTTP call — connect, write and read — with
/// `timeout`, exactly the span Go's `context.WithTimeout` covers.
///
/// A zero timeout is checked before dialing: Go treats `0`, `0s` and `-1s` as
/// an already-expired context and reports a timeout rather than whatever the
/// socket does, so a refused port must not win that race. (`-1s` reaches here
/// as [`Duration::ZERO`] — see `parse_go_duration`.)
async fn with_admin_timeout<F>(timeout: Duration, call: F) -> Result<String, String>
where
    F: std::future::Future<Output = Result<String, String>>,
{
    if timeout.is_zero() {
        return Err(admin_timeout_error(timeout));
    }
    match tokio::time::timeout(timeout, call).await {
        Ok(result) => result,
        Err(_elapsed) => Err(admin_timeout_error(timeout)),
    }
}

async fn admin_get(
    conn: &AdminConnection,
    path: &str,
    timeout: Duration,
) -> Result<String, String> {
    with_admin_timeout(timeout, admin_get_inner(conn, path)).await
}

async fn admin_get_inner(conn: &AdminConnection, path: &str) -> Result<String, String> {
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
    timeout: Duration,
) -> Result<String, String> {
    with_admin_timeout(timeout, admin_post_json_inner(conn, path, json_body)).await
}

async fn admin_post_json_inner(
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
    // mem-profile and mimalloc are mutually exclusive (the #[global_allocator]
    // guards are cfg-exclusive): with both enabled neither allocator is
    // installed, so the emitter must not run either.
    #[cfg(all(feature = "mem-profile", not(feature = "mimalloc")))]
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
        FrpcCmd::Verify(args) => {
            run_verify(&args.config, args.strict_config, &args.allow_unsafe).await
        }
        FrpcCmd::Reload(args) => run_reload(args).await,
        FrpcCmd::Status(args) => run_status(args).await,
        FrpcCmd::Stop(args) => run_stop(args).await,
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
    // Same zero-value rule as `frps`: Go completes `--log_max_days 0` to 3
    // (`pkg/config/v1/common.go:122`). The client's sibling shape is the config
    // file, which `LogConfig::complete` fills; this covers the flag.
    let max_days = logging::resolve_log_max_days(cli.log_max_days, cfg.map(|c| c.log.max_days));
    let format = logging::resolve_log_format(
        cli.log_format.clone(),
        cfg.map(|c| c.log.format.as_str()).unwrap_or("text"),
    );
    // Go frp v0.70.1 compat: log.disablePrintColor from the config file is
    // honored (audit task 9 finding 9); the CLI --disable-log-color flag
    // takes precedence when both are set.
    let ansi = logging::resolve_ansi(
        cli.disable_log_color || cfg.map(|c| c.log.disable_print_color).unwrap_or(false),
    );
    #[cfg(not(feature = "otel"))]
    logging::init_tracing(&level, file, max_days, &format, ansi, "frpc.log");
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
        logging::init_tracing_otel(
            &level,
            file,
            max_days,
            &format,
            ansi,
            &svc_name,
            otlp_endpoint,
            "frpc.log",
        );
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

        // SIGINT/SIGTERM → graceful shutdown of every directory service.
        // One process-wide handler sets SHUTDOWN_REQUESTED and iterates the
        // registered services on each signal; request_stop() is idempotent,
        // so repeat signals are harmless. Services register their Arc as
        // they come up. A signal delivered before a service finishes
        // initializing would otherwise be lost — docker stop sends exactly
        // one signal, so the handler cannot rely on re-firing — and the flag
        // is re-checked at registration time to stop a just-registered
        // service immediately.
        #[cfg(unix)]
        static SHUTDOWN_REQUESTED: std::sync::atomic::AtomicBool =
            std::sync::atomic::AtomicBool::new(false);
        #[cfg(unix)]
        let stop_services: Arc<std::sync::Mutex<Vec<Arc<Service>>>> =
            Arc::new(std::sync::Mutex::new(Vec::new()));
        #[cfg(unix)]
        {
            let stop_services = stop_services.clone();
            tokio::spawn(async move {
                let mut sigterm = match signal::unix::signal(signal::unix::SignalKind::terminate())
                {
                    Ok(s) => s,
                    Err(e) => {
                        tracing::warn!(error = %e, "SIGTERM handler init failed: {}", e);
                        return;
                    }
                };
                let mut sigint = match signal::unix::signal(signal::unix::SignalKind::interrupt()) {
                    Ok(s) => s,
                    Err(e) => {
                        tracing::warn!(error = %e, "SIGINT handler init failed: {}", e);
                        return;
                    }
                };
                loop {
                    tokio::select! {
                        _ = sigterm.recv() => {
                            tracing::info!(pid = %std::process::id(), "SIGTERM received, initiating graceful shutdown");
                        }
                        _ = sigint.recv() => {
                            tracing::info!(pid = %std::process::id(), "SIGINT received, initiating graceful shutdown");
                        }
                    }
                    SHUTDOWN_REQUESTED.store(true, std::sync::atomic::Ordering::Relaxed);
                    for svc in stop_services.lock().unwrap().iter() {
                        svc.request_stop();
                    }
                }
            });
        }

        // Config-directory mode is a deliberate, measured divergence: Go frp
        // v0.71.0 exits **0** here even when the directory does not exist, is
        // empty, or holds a config that fails to parse (`frpc --config-dir
        // <nonexistent|empty|bad>` → rc 0, the bad case printing only
        // `frpc service error for config file [...]`). frp-rs keeps its
        // pre-existing non-zero `EXIT_CONFIG` refusal rather than reporting a
        // silent success for a config that was never loaded. Stated in
        // `docs/developing.md` § CLI exit codes and pinned by
        // `frpc/tests/cli_exit_codes.rs`; do not "fix" it to 0.
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
        let mut handles: Vec<(usize, tokio::task::JoinHandle<Result<(), i32>>)> = Vec::new();
        let mut load_failures: Vec<(usize, i32)> = Vec::new();
        for (file_index, path) in files.iter().enumerate() {
            let path_str = path.display().to_string();
            match load_client_config_with_presence(&path_str, args.strict_config) {
                Ok((cfg, presence)) => {
                    // `init_logging` ran at the top of this branch, so the sink
                    // exists. The loader cannot warn (it would be silent on the
                    // `-c` path below), so the binary owns the diagnostic and
                    // this path emits it once, at its own load site.
                    presence.warn_inert_web_server_tls_enable(cfg!(feature = "admin"));
                    let uf = unsafe_features.clone();
                    #[cfg(unix)]
                    let stop_services = stop_services.clone();
                    handles.push((
                        file_index,
                        tokio::spawn(async move {
                            let service = match Service::with_unsafe_features(cfg, Some(path_str.clone()), uf).await {
                                Ok(svc) => svc,
                                Err(e) => {
                                    tracing::error!(config_file = %path_str, error = %e, "frpc service init error for config file [{}]: {}", path_str, e);
                                    // A file that never became a service served
                                    // nothing; carry its code out of the task so
                                    // an all-failed directory cannot report
                                    // success. Same code `-c <file>` exits with
                                    // (`e.kind().exit_code()`, above).
                                    return Err(e.kind().exit_code());
                                }
                            };
                            let service = Arc::new(service);
                            #[cfg(unix)]
                            stop_services.lock().unwrap().push(service.clone());
                            #[cfg(unix)]
                            if SHUTDOWN_REQUESTED.load(std::sync::atomic::Ordering::Relaxed) {
                                service.request_stop();
                            }
                            if let Err(e) = service.run().await {
                                tracing::error!(config_file = %path_str, error = %e, "frpc service error for config file [{}]: {}", path_str, e);
                                // Match `-c`: a service that failed to run did
                                // not serve, so the directory lane must be able
                                // to report the failure instead of exiting 0.
                                return Err(EXIT_RUNTIME);
                            }
                            Ok(())
                        }),
                    ));
                }
                Err(e) => {
                    tracing::error!(path = %path_str, error = %e, "Failed to load config from [{}]: {}", path_str, e);
                    // Keep the lane's pre-existing refusal code (see the
                    // `collect_config_files` comment above): a file that fails
                    // to load still counts toward the all-failed decision, and
                    // file order decides which code wins when several failed.
                    load_failures.push((file_index, EXIT_CONFIG));
                }
            }
        }
        if handles.is_empty() {
            tracing::error!("No services started — all config files failed to load");
            let code = load_failures
                .first()
                .map(|(_, code)| *code)
                .unwrap_or(EXIT_CONFIG);
            process::exit(code);
        }
        // A task that returned `Err(code)` — construction or `run()` — served
        // nothing. If **every** file failed (load or run), exit the file-order
        // first failure's code, exactly as `frps --config-dir` does, instead of
        // reporting success for a directory that serves nothing.
        let mut failures = load_failures;
        for (file_index, handle) in handles {
            match handle.await {
                Ok(Ok(())) => {}
                Ok(Err(code)) => failures.push((file_index, code)),
                Err(e) => {
                    tracing::error!(error = %e, "frpc service task panicked: {}", e);
                    failures.push((file_index, EXIT_RUNTIME));
                }
            }
        }
        if failures.len() == files.len() {
            failures.sort_by_key(|(file_index, _)| *file_index);
            if let Some((_, code)) = failures.first() {
                process::exit(*code);
            }
        }
        return;
    }

    // Single config mode
    let (cfg, presence) = match load_client_config_with_presence(&args.config, args.strict_config) {
        Ok(loaded) => loaded,
        Err(e) => {
            // Go frp v0.71.0: a `frpc -c <bad>` config failure is
            // `fmt.Println(err); os.Exit(1)` (`cmd/frpc/sub/root.go`) — one
            // bare line on **stdout**, no log prefix and no ANSI, then exit 1
            // (not a per-class code). Measured against the Go binary, stdout
            // and stderr captured separately; pinned by
            // `frpc/tests/cli_exit_codes.rs`. The `tracing` line this replaces
            // was the last path in `frpc` that wrapped the load error in a log
            // record — the admin subcommands already `println!` it
            // (`run_reload` / `run_status` / `run_stop` below).
            //
            // `init_logging` is deliberately **not** called here: Go installs
            // its logger only after a successful load
            // (`startServiceWithAggregator`, `cmd/frpc/sub/root.go:191`), and
            // this branch exits before any log record is emitted.
            println!("{e}");
            process::exit(EXIT_RUNTIME);
        }
    };

    init_logging(&args, Some(&cfg));

    // The sink exists from here on. `[web_server.tls] enable` is inert and the
    // loader cannot warn about it — on this path the load above deliberately
    // precedes `init_logging` (Go installs its logger only after a successful
    // load, `cmd/frpc/sub/root.go:191`), so a `tracing::warn` inside the loader
    // reaches no subscriber. The fact is carried out of the loader on
    // `ConfigPresence` and emitted here, once; the `--config-dir` branch above
    // warns at its own load site, so no path double-warns — pinned by the
    // `warn_delivery` lanes, which assert exactly one record on stdout and none
    // on stderr for both paths
    // (`frpc/tests/warn_delivery.rs::web_server_tls_enable_warning_reaches_a_dash_c_user`
    // and its `config_dir` sibling).
    presence.warn_inert_web_server_tls_enable(cfg!(feature = "admin"));

    tracing::info!(version = %frp_core::VERSION, "frpc (Rust) v{} connecting...", frp_core::VERSION);
    let service = Arc::new(
        match Service::with_unsafe_features(cfg, Some(args.config.clone()), unsafe_features.clone())
            .await
        {
            Ok(svc) => svc,
            Err(e) => {
                // The exit code comes from the constructor's typed tag, never
                // from the message: `e.to_string()` embeds the config path and
                // any URL in it, and a substring test over that text made two
                // identical failures exit differently (`…/authstore.json` → 3,
                // `…/plainstore.json` → 4). See `frp-core/src/init_error.rs`.
                let code = e.kind().exit_code();
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

    // SIGINT/SIGTERM → graceful shutdown (Ctrl+C; docker stop / systemctl stop
    // send SIGTERM). request_stop() wakes run()'s stop channel; the session
    // loop exits cleanly. Both signals take the same path and request_stop()
    // is idempotent, so repeat signals are harmless.
    #[cfg(unix)]
    {
        let stop_svc = service.clone();
        tokio::spawn(async move {
            let mut sigterm = match signal::unix::signal(signal::unix::SignalKind::terminate()) {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!(error = %e, "SIGTERM handler init failed: {}", e);
                    return;
                }
            };
            let mut sigint = match signal::unix::signal(signal::unix::SignalKind::interrupt()) {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!(error = %e, "SIGINT handler init failed: {}", e);
                    return;
                }
            };
            loop {
                tokio::select! {
                    _ = sigterm.recv() => {
                        tracing::info!(pid = %std::process::id(), "SIGTERM received, initiating graceful shutdown");
                    }
                    _ = sigint.recv() => {
                        tracing::info!(pid = %std::process::id(), "SIGINT received, initiating graceful shutdown");
                    }
                }
                stop_svc.request_stop();
            }
        });
    }

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
    logging::init_console_logger();

    let cfg = build_single_proxy_config(server_addr, server_port, token, proxy);
    tracing::info!(version = %frp_core::VERSION, "frpc (Rust) v{} starting single proxy...", frp_core::VERSION);

    let service = match Service::new(cfg, None).await {
        Ok(svc) => svc,
        Err(e) => {
            // Typed tag, not a text match — same reason as `run_normal` above.
            let code = e.kind().exit_code();
            tracing::error!(error = %e, "frpc init error: {}", e);
            process::exit(code);
        }
    };

    if let Err(e) = service.run().await {
        tracing::error!(error = %e, "frpc error: {}", e);
        process::exit(EXIT_RUNTIME);
    }
}

async fn run_verify(config_path: &str, strict_config: bool, allow_unsafe: &[String]) {
    logging::init_console_logger();

    // Go frp v0.70.1: `frpc verify` honors the persistent strictConfigMode
    // root flag (cmd/frpc/sub/verify.go) — with --strict-config=false, unknown
    // fields are accepted.
    //
    // The loader is the post-load-gated one: `auth.tokenSource`/
    // `auth.oidc.tokenSource` pointing at an `exec` command needs the
    // `--allow-unsafe TokenSourceExec` allow-list on **this** path too, because
    // Go's verify runs `ValidateClientConfig`'s unsafe-feature gate (measured on
    // Go v0.71.0: `frpc verify -c <exec cfg>` is rc 1 with the
    // `unsafe feature "TokenSourceExec" is not enabled. …` line and rc 0 with
    // `--allow-unsafe TokenSourceExec`). Without it this command certified a
    // config the daemon refuses at construction with rc 3.
    let refs: Vec<&str> = allow_unsafe.iter().map(|s| s.as_str()).collect();
    let unsafe_features = UnsafeFeatures::new(&refs);
    match load_client_config_with_presence_checked(config_path, strict_config, &unsafe_features) {
        Ok((cfg, presence)) => {
            // This path installs its console logger **before** the load, so the
            // sink exists: emit the `[web_server.tls] enable` diagnostic here to
            // keep the coverage this subcommand had while the loader warned (and
            // to keep it to one record).
            presence.warn_inert_web_server_tls_enable(cfg!(feature = "admin"));
            // `load_client_config` only parses, so without this `verify` printed
            // "is valid" (rc 0) for a config `frpc run` refuses during service
            // construction (an oidc config in a build without the `oidc`
            // feature). The helper is the same one the service construction
            // uses, and is a no-op in an oidc build, so nothing changes there.
            if let Err(e) =
                frp_client::service::refuse_oidc_method_without_feature(cfg.auth.as_ref())
            {
                // Same stream as the parse refusal below and as Go's
                // `fmt.Println(err)` (`cmd/frpc/sub/verify.go`).
                println!("Config file {} is invalid: {}", config_path, e);
                // Go v0.71.0 `frpc verify -c <bad>` exits 1 (`cmd/frpc/sub/verify.go`).
                process::exit(EXIT_RUNTIME);
            }
            // Go v0.71.0 `cmd/frpc/sub/verify.go:52` prints exactly
            // `frpc: the configuration file <path> syntax is ok` — the same
            // sentence shape `frps verify` already prints (`frps/src/main.rs`).
            // Measured against the Go v0.71.0 binary: stdout
            // `frpc: the configuration file good.toml syntax is ok`, stderr 0 B.
            // The three summary lines below are a frp-rs addition Go does not
            // print; they are kept deliberately because
            // `frpc/tests/legacy_ini_fixture.rs` observes the 43-proxy/2-visitor
            // legacy fixture through the `Proxies:`/`Visitors:` counts.
            println!("frpc: the configuration file {} syntax is ok", config_path);
            println!("  Server: {}:{}", cfg.server_addr, cfg.server_port);
            println!("  Proxies: {}", cfg.proxies.len());
            println!("  Visitors: {}", cfg.visitors.len());
        }
        Err(e) => {
            // Go frp v0.71.0 `frpc verify -c <bad>`: `fmt.Println(err);
            // os.Exit(1)` (`cmd/frpc/sub/verify.go`) — the refusal goes to
            // **stdout**, not stderr. Measured against the Go binary with the
            // two streams captured separately (Go: stdout 38 bytes, stderr 0);
            // pinned by `frpc/tests/cli_exit_codes.rs`. The `--allow-unsafe`
            // gate's refusal arrives on this same arm, through the loader.
            println!("Config file {} is invalid: {}", config_path, e);
            // Go v0.71.0 `frpc verify -c <bad>` exits 1; measured against the Go
            // binary and pinned by `frpc/tests/cli_exit_codes.rs`.
            process::exit(EXIT_RUNTIME);
        }
    }
}

async fn run_reload(args: ReloadArgs) {
    let conn = match resolve_admin_connection(
        args.admin_addr.as_deref(),
        args.admin_port,
        args.admin_user.as_deref(),
        args.admin_pwd.as_deref(),
        args.config.as_deref(),
        args.strict_config,
    ) {
        Ok(conn) => conn,
        Err(e) => {
            // Go prints both refusal messages with `fmt.Println` (stdout) and
            // exits 1 before contacting anything (cmd/frpc/sub/admin.go:56-71).
            // The connection-error path below stays on stderr — a pre-existing
            // stream divergence, deliberately not changed here.
            println!("{e}");
            process::exit(EXIT_RUNTIME);
        }
    };
    let body = format!(r#"{{"strictConfig":{}}}"#, args.strict_config);
    match admin_post_json(&conn, "/api/reload", &body, args.api_timeout).await {
        Ok(summary) => println!("reload success: {summary}"),
        Err(e) => {
            eprintln!("reload failed: {e}");
            std::process::exit(frp_core::EXIT_RUNTIME);
        }
    }
}

async fn run_status(args: StatusArgs) {
    let conn = match resolve_admin_connection(
        args.admin_addr.as_deref(),
        args.admin_port,
        args.admin_user.as_deref(),
        args.admin_pwd.as_deref(),
        args.config.as_deref(),
        args.strict_config,
    ) {
        Ok(conn) => conn,
        Err(e) => {
            // Same as run_reload: Go's refusal messages go to stdout, exit 1,
            // and no connection is attempted.
            println!("{e}");
            process::exit(EXIT_RUNTIME);
        }
    };
    let body = match admin_get(&conn, "/api/status", args.api_timeout).await {
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

async fn run_stop(args: StopArgs) {
    let conn = match resolve_admin_connection(
        args.admin_addr.as_deref(),
        args.admin_port,
        args.admin_user.as_deref(),
        args.admin_pwd.as_deref(),
        args.config.as_deref(),
        args.strict_config,
    ) {
        Ok(conn) => conn,
        Err(e) => {
            // Same as run_reload/run_status: Go's refusal messages go to
            // stdout, exit 1, and no connection is attempted.
            println!("{e}");
            process::exit(EXIT_RUNTIME);
        }
    };
    // Go's StopHandler sends no body and prints its own `stop success`,
    // discarding the response body (`cmd/frpc/sub/admin.go:115-125`, tag
    // v0.71.0). Method, path, `Content-Length: 0` and an empty body match the
    // measured Go request (`POST /api/stop HTTP/1.1`, `Content-Length: 0`);
    // the remaining headers differ: Go sends `User-Agent: Go-http-client/1.1`
    // and `Accept-Encoding: gzip`, frp-rs sends `Content-Type:
    // application/json` and `Connection: close`.
    match admin_post_json(&conn, "/api/stop", "", args.api_timeout).await {
        Ok(_) => println!("stop success"),
        Err(e) => {
            eprintln!("stop failed: {e}");
            std::process::exit(frp_core::EXIT_RUNTIME);
        }
    }
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
            true,
        )
        .unwrap();
        assert_eq!(conn.addr, "10.0.0.1:1234");
        assert_eq!(conn.user, "u");
        assert_eq!(conn.password, "p");
    }

    #[test]
    fn test_resolve_admin_connection_defaults() {
        let conn = resolve_admin_connection(None, None, None, None, None, true).unwrap();
        assert_eq!(conn.addr, "127.0.0.1:7400");
        assert_eq!(conn.user, "");
        assert_eq!(conn.password, "");
    }

    #[test]
    fn test_resolve_admin_connection_cli_addr_only_falls_through() {
        // addr without port is not enough — falls to defaults
        let conn =
            resolve_admin_connection(Some("10.0.0.1"), None, Some("u"), Some("p"), None, true)
                .unwrap();
        assert_eq!(conn.addr, "127.0.0.1:7400");
    }

    #[test]
    fn test_resolve_admin_connection_cli_port_only_falls_through() {
        let conn = resolve_admin_connection(None, Some(9999), None, None, None, true).unwrap();
        assert_eq!(conn.addr, "127.0.0.1:7400");
    }

    #[test]
    fn test_resolve_admin_connection_explicit_port_zero_is_rejected() {
        // `--admin-port 0` is not "not supplied": it is refused with Go's
        // web-server message instead of silently falling back to the default.
        let err = resolve_admin_connection(Some("127.0.0.1"), Some(0), None, None, None, true)
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "web server port should be set if you want to use this feature"
        );
    }

    #[test]
    fn test_resolve_admin_connection_missing_config_is_an_error() {
        // A config path that cannot be loaded must not fall back to a default
        // address; the error text is the load error, printed verbatim.
        let err = resolve_admin_connection(
            None,
            None,
            None,
            None,
            Some("/nonexistent/frpc-does-not-exist.toml"),
            true,
        )
        .unwrap_err();
        match err {
            AdminResolveError::Config(msg) => {
                assert!(
                    msg.contains("frpc-does-not-exist.toml"),
                    "load error should name the file, got: {msg}"
                );
            }
            other => panic!("expected a config error, got {other:?}"),
        }
    }
}
