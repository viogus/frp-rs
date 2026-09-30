use std::path::Path;
use std::process;

use frp_core::cli::{parse_frps_args, FrpsArgs, FrpsCmd};
use frp_core::config::{
    collect_config_files, load_server_config, load_server_config_uncompleted_with_presence,
    load_server_config_with_presence, ServerConfig,
};
use frp_core::logging;
use frp_core::unsafe_features::UnsafeFeatures;
use frp_server::service::Service;

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
    let cli = parse_frps_args();
    // mem-profile and mimalloc are mutually exclusive (the #[global_allocator]
    // guards are cfg-exclusive): with both enabled neither allocator is
    // installed, so the emitter must not run either.
    #[cfg(all(feature = "mem-profile", not(feature = "mimalloc")))]
    frp_core::mem_profile::spawn_emitter();
    match cli {
        // `verify` exits inside the call (`process::exit` on a bad config) and
        // returns to the runtime's exit 0 otherwise — the same shape as the root
        // command returning from `RunE` with a nil error.
        FrpsCmd::Verify(args) => run_verify(&args.config, args.strict_config),
        FrpsCmd::Run(args) => run(args).await,
    }
}

/// `frps verify`: load a server config and report Go's line, or fail like Go.
///
/// Mirrors Go's `verifyCmd` (`cmd/frps/verify.go`) and the shape the client's
/// `run_verify` (`frpc/src/main.rs`) already uses:
///
/// * an **empty** path is not an error in Go — `frps` registers `-c` with an
///   empty default (`cmd/frps/root.go:44`) and `verifyCmd` prints
///   `frps: the configuration file is not specified` and returns nil
///   (`cmd/frps/verify.go:36-39`), so the exit status is **0** (measured);
/// * a load failure is `fmt.Println(err); os.Exit(1)` (`:41-44`) — one bare
///   line on **stdout**, exit 1 (measured, stderr 0 bytes);
/// * success is `frps: the configuration file %s syntax is ok` on **stdout**,
///   exit 0 (`:56`).
///
/// The loader is [`load_server_config`] — the same parse-and-validate path the
/// run path uses: the run path's single-config branch calls
/// [`load_server_config_uncompleted`] (the same function minus
/// `ServerConfig::complete`) and completes the merged config itself, and both go
/// through `load_config_from_file` with `known_server_keys` and
/// `validate_server_config`. `verify` has no CLI overrides to merge, so it takes
/// the completing wrapper. The consequence is that `verify` accepts exactly the
/// configs `frps -c` accepts and refuses the ones it refuses at **load** time.
/// It does **not** run the later service-construction gates (the
/// `--allow-unsafe`/`TokenSourceExec` check, applied in
/// `frp-server/src/service.rs`), which is where Go differs: Go's verify *does*
/// run its post-load `ValidateServerConfig` gate (`cmd/frps/verify.go:46-48`), so
/// an `auth.tokenSource` with `type = "exec"` and no
/// `--allow-unsafe TokenSourceExec` is rc 1 on Go and rc 0 here — the same
/// pre-existing divergence `frpc verify` has, recorded in `docs/developing.md`
/// § CLI inputs and measured for the client in `frp-core/src/config/tests.rs`. It
/// is not closed here because both verify commands must report the same verdict
/// for the same config; a fix belongs in the shared load path, not in one
/// binary's verify.
///
/// Logging is deliberately **not** initialised: Go installs its logger only in
/// `runServer` (`cmd/frps/root.go:112`), never on the verify path, and the
/// measured Go stdout for a lenient (`--strict-config=false`) verify is exactly
/// the one success line with stderr empty. Leaving `tracing` uninitialised drops
/// the lenient-load warnings the run path would emit, which is what keeps that
/// one-line shape (`tracing` records are a no-op without a subscriber).
fn run_verify(config_path: &str, strict_config: bool) {
    if config_path.is_empty() {
        // Go: `fmt.Println("frps: the configuration file is not specified")`,
        // then `return nil` — rc 0, not an error.
        println!("frps: the configuration file is not specified");
        return;
    }
    match load_server_config(config_path, strict_config) {
        Ok(_) => {
            // Go: `fmt.Printf("frps: the configuration file %s syntax is ok\n",
            // cfgFile)` (`cmd/frps/verify.go:56`).
            println!("frps: the configuration file {} syntax is ok", config_path);
        }
        Err(e) => {
            // Go: `fmt.Println(err); os.Exit(1)` (`cmd/frps/verify.go:42-44`) —
            // the same bare stdout line and rc the run path's load failure
            // prints (`frps/src/main.rs`, single-config branch).
            println!("{e}");
            process::exit(frp_core::EXIT_RUNTIME);
        }
    }
}

// ── Logging / tracing init ────────────────────────────────────────────────────

fn init_logging(cli: &FrpsArgs, cfg: Option<&ServerConfig>) {
    let level = logging::resolve_log_level(
        cli.log_level.clone(),
        cfg.map(|c| c.log.level.as_str()),
        "debug",
    );
    let file = logging::resolve_log_file(
        cli.log_file.clone(),
        cfg.map(|c| c.log.file.as_str()).unwrap_or(""),
    );
    // `resolve_log_max_days` filters the CLI zero value (Go's `util.EmptyOr(0,
    // 3)`), so `--log-max-days 0` uses the completed config value — which this
    // lane has just set to 3 — instead of disabling startup cleanup. The
    // observable is synchronous: `init_tracing` calls `cleanup_expired_logs`
    // when `max_days > 0`.
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
    logging::init_tracing(&level, file, max_days, &format, ansi, "frps.log");
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
            .unwrap_or_else(|| "frps".to_string());
        logging::init_tracing_otel(
            &level,
            file,
            max_days,
            &format,
            ansi,
            &svc_name,
            otlp_endpoint,
            "frps.log",
        );
    }
}
async fn run(mut cli: FrpsArgs) {
    if cli.show_version {
        println!("frps {}", frp_core::VERSION);
        process::exit(0);
    }

    // Build UnsafeFeatures from CLI --allow-unsafe flag
    let allow_unsafe = std::mem::take(&mut cli.allow_unsafe);
    let refs: Vec<&str> = allow_unsafe.iter().map(|s| s.as_str()).collect();
    let unsafe_features = UnsafeFeatures::new(&refs);

    // Config directory mode: init logging from CLI only
    if let Some(ref dir) = cli.config_dir {
        init_logging(&cli, None);

        // `--config-dir` itself is an frp-rs extension — Go frps v0.71.0 rejects
        // it with `Error: unknown flag: --config-dir` and exit 1 — and the
        // non-zero refusals below are a deliberate, measured divergence from
        // Go's *client* directory mode, which exits 0 even for a missing or
        // invalid directory. See `frpc/src/main.rs` and `docs/developing.md`
        // § CLI exit codes; do not "fix" these to 0.
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
            count = %files.len(),
            "frps (Rust) v{} starting {} services from config directory",
            frp_core::VERSION,
            files.len()
        );
        let mut handles = Vec::new();
        // Each task publishes its `Arc<Service>` here once construction succeeds,
        // so the SIGUSR1 handler below reloads the *same* objects the runners are
        // using. A task still constructing has nothing to reload yet — and on
        // `-c` a signal sent before the handler is installed still takes the
        // default disposition, so that window is not new.
        #[cfg(unix)]
        let registry: std::sync::Arc<std::sync::Mutex<Vec<std::sync::Arc<Service>>>> =
            Default::default();
        for path in &files {
            let path_str = path.display().to_string();
            // Go frp v0.70.1 parity: with --config-dir each file is
            // authoritative — CLI config flags are not overlaid (audit task
            // 9 finding 5).
            match load_server_config_with_presence(&path_str, cli.strict_config) {
                Ok((cfg, presence)) => {
                    // `init_logging` ran at the top of this branch, so the sink
                    // exists; the loader cannot warn (it would be silent on `-c`),
                    // so the binary owns the diagnostic and this path emits it
                    // exactly once, here, like the `-c` branch below.
                    presence.warn_inert_web_server_tls_enable(cfg!(feature = "dashboard"));
                    // The flat server `tls_enable` is inert too; same sink, same
                    // one-record-per-load rule.
                    presence.warn_inert_server_tls_enable();
                    let uf = unsafe_features.clone();
                    #[cfg(unix)]
                    let registry = registry.clone();
                    handles.push(tokio::spawn(async move {
                        let service = match Service::with_unsafe_features(cfg, Some(path_str.clone()), uf).await {
                            Ok(s) => std::sync::Arc::new(s),
                            Err(e) => {
                                // Carry the **typed** code out of the task: the
                                // single-config path below exits on this same
                                // value, and a directory that started no service
                                // must not report success (measured at b8e1dd6d
                                // with one valid-but-rejected file: `-c` exited 3
                                // and `--config-dir` exited 0).
                                let code = e.kind().exit_code();
                                tracing::error!(path = %path_str, error = %e, "frps service init failed for [{}]: {}", path_str, e);
                                return Err(code);
                            }
                        };
                        // Registered before `run()`, so the soonest possible
                        // SIGUSR1 already finds this service.
                        #[cfg(unix)]
                        registry.lock().unwrap().push(service.clone());
                        if let Err(e) = service.run().await {
                            tracing::error!(path = %path_str, error = %e, "frps service error for config file [{}]: {}", path_str, e);
                        }
                        // `Ok(())` = this task constructed a service and ran it
                        // to completion; `Err(code)` = it never started.
                        Ok(())
                    }));
                }
                Err(e) => {
                    tracing::error!(path = %path_str, error = %e, "Failed to load config from [{}]: {}", path_str, e);
                }
            }
        }
        if handles.is_empty() {
            tracing::error!("No services started — all config files failed to load");
            process::exit(frp_core::EXIT_CONFIG);
        }

        // SIGUSR1 reload handler (Unix only) — kill -USR1 <pid>, the same
        // handler the single-config path installs below. One signal reloads
        // every service built from the directory, each from its **own** config
        // file (`Service::config_file` is that file's path), and each logs its
        // own summary. Without this task the flag kept its default disposition
        // and killed the process: measured on the base binary, `frps
        // --config-dir <dir>` + `kill -USR1` exited `unix_wait_status(158)`
        // (128+30, "User defined signal 1: 30") with no reload record.
        #[cfg(unix)]
        let reload_handle = {
            let registry = registry.clone();
            tokio::spawn(async move {
                match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::user_defined1())
                {
                    Ok(mut sig) => {
                        tracing::info!(pid = %std::process::id(), "SIGUSR1 reload ready (pid={})", std::process::id());
                        loop {
                            sig.recv().await;
                            // Copy the handles out and release the lock: the
                            // reload awaits, and holding a std mutex across an
                            // await would block registration (and duplicate the
                            // service list).
                            let svcs: Vec<std::sync::Arc<Service>> =
                                { registry.lock().unwrap().clone() };
                            for svc in &svcs {
                                match svc.reload().await {
                                    Ok(summary) => {
                                        tracing::info!(summary = %summary, "SIGUSR1: {}", summary)
                                    }
                                    Err(e) => tracing::error!(error = %e, "SIGUSR1 reload: {}", e),
                                }
                            }
                        }
                    }
                    Err(e) => tracing::warn!(error = %e, "SIGUSR1 unavailable: {}", e),
                }
            })
        };

        // A task that failed construction reports its typed exit code; one that
        // ran a service reports `Ok(())`. If **every** spawned task failed, the
        // directory started nothing at all, and the process must exit like the
        // single-config path does — with the first failure's typed code — rather
        // than 0. A mix (at least one service actually ran) keeps the historical
        // log-and-keep-serving behaviour.
        let spawned = handles.len();
        let mut init_failures: Vec<i32> = Vec::new();
        for handle in handles {
            match handle.await {
                Ok(Ok(())) => {}
                Ok(Err(code)) => init_failures.push(code),
                Err(e) => tracing::error!(error = %e, "frps service task panicked: {}", e),
            }
        }
        if init_failures.len() == spawned {
            if let Some(code) = init_failures.first() {
                process::exit(*code);
            }
        }

        #[cfg(unix)]
        reload_handle.abort();
        return;
    }

    // Single config mode: load config first, then init logging with [log] fallback.
    //
    // Go ordering: Go completes a **flag-populated** struct only on its
    // flags-only path — `cmd/frps/root.go:77-83`, no config file involved. Its
    // `-c` path loads a fresh struct from the file and completes that
    // (`pkg/config/load.go:313`, `:318-321`), discarding the pflag-bound one, so
    // Go ignores the flags there; frp-rs matches by ignoring them on `-c` too.
    // On the override lane frp-rs loads the file, overlays the CLI flags, and
    // completes the result — the same **order** as Go's flags-only path, though
    // not the same **values**: Go pre-seeds every pflag default into the struct
    // (`pkg/config/flags.go:230-255`), frp-rs keeps the file's values except
    // where a flag overrides them. See
    // `load_server_config_uncompleted` for the fields where writing the override
    // after `complete()` was observable (`bind_addr`, `bind_port`,
    // `web_server.addr`, and the derived `proxy_bind_addr`, which now follows
    // `--bind-addr`; measured end to end in `docs/developing.md` § CLI inputs
    // § 2b).
    let config_path = cli.config_path();
    let (mut cfg, presence) =
        match load_server_config_uncompleted_with_presence(&config_path, cli.strict_config) {
            Ok(loaded) => loaded,
            Err(e) => {
                // Go frp v0.71.0: `frps -c <bad>` is `fmt.Println(err); os.Exit(1)`
                // (`cmd/frps/root.go`) — one bare line on **stdout**, no log prefix
                // and no ANSI, same as the client, exit 1. Measured against the Go
                // binary with the two streams captured separately (Go: stdout 38
                // bytes, stderr 0); pinned by `frps/tests/cli_exit_codes.rs`.
                //
                // `init_logging` is deliberately **not** called here: Go installs
                // its logger only after a successful load
                // (`runServer`, `cmd/frps/root.go:112`), and this branch exits
                // before any log record is emitted.
                println!("{e}");
                process::exit(frp_core::EXIT_RUNTIME);
            }
        };

    // Go frp v0.70.1 parity: an explicit `-c` makes the config file
    // authoritative — CLI config flags are ignored (audit task 9 finding 5).
    // Without `-c`, CLI flags override the default frps.toml (frp-rs
    // extension; Go frps would use only flags in that mode).
    if cli.cli_overrides_enabled() {
        cli.override_server_config(&mut cfg);
    }
    // Completion runs on the merged config, never before it (Go order).
    cfg.complete();
    init_logging(&cli, Some(&cfg));

    // The sink exists from here on. `[web_server.tls] enable` is inert and the
    // loader cannot warn about it — on this path the load above deliberately
    // precedes `init_logging` (Go installs its logger only after a successful
    // load, `cmd/frps/root.go:112`), so a `tracing::warn` inside the loader
    // reaches no subscriber. The fact is carried out of the loader on
    // `ConfigPresence` and emitted here, once: the `--config-dir` branch above
    // warns at its own load site, so no path double-warns (measured, probe
    // `/tmp/enable-warn-probe/run-probe.sh`: 1 on stdout, 0 on stderr, both
    // paths, both binaries).
    presence.warn_inert_web_server_tls_enable(cfg!(feature = "dashboard"));
    // The flat server `tls_enable` is inert too — no code in `frp-server` or
    // `frps` reads `ServerConfig::tls_enable`, and a restart cannot make it take
    // effect. Same sink, same one-record-per-load rule.
    presence.warn_inert_server_tls_enable();

    tracing::info!(version = %frp_core::VERSION, "frps (Rust) v{} starting...", frp_core::VERSION);
    let config_path = Some(config_path);
    let service = std::sync::Arc::new(
        Service::with_unsafe_features(cfg, config_path, unsafe_features)
            .await
            .unwrap_or_else(|e| {
                tracing::error!(error = %e, "frps init error: {}", e);
                // Typed tag, not a text match: the message embeds the config
                // path and the OIDC issuer URL, so a substring over it let an
                // unrelated word choose the code. See
                // `frp-core/src/init_error.rs`.
                process::exit(e.kind().exit_code());
            }),
    );

    // SIGUSR1 reload handler (Unix only) — kill -USR1 <pid>
    #[cfg(unix)]
    let reload_handle = {
        let svc = service.clone();
        tokio::spawn(async move {
            match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::user_defined1()) {
                Ok(mut sig) => {
                    tracing::info!(pid = %std::process::id(), "SIGUSR1 reload ready (pid={})", std::process::id());
                    loop {
                        sig.recv().await;
                        match svc.reload().await {
                            Ok(summary) => {
                                tracing::info!(summary = %summary, "SIGUSR1: {}", summary)
                            }
                            Err(e) => tracing::error!(error = %e, "SIGUSR1 reload: {}", e),
                        }
                    }
                }
                Err(e) => tracing::warn!(error = %e, "SIGUSR1 unavailable: {}", e),
            }
        })
    };

    // SIGUSR2 profiling handler (Unix + profiling) — kill -USR2 <pid>
    // Runs a CPU profile for a configurable duration, writing a flamegraph SVG.
    // Environment variables:
    //   FRP_PROFILE_SECS — profiling duration in seconds (default 30)
    //   FRP_PROFILE_DIR  — output directory (default ".")
    #[cfg(all(unix, feature = "profiling"))]
    let profile_handle = {
        tokio::spawn(async move {
            match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::user_defined2()) {
                Ok(mut sig) => {
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
                                "frps",
                            ) {
                                Ok(path) => tracing::info!(
                                    "SIGUSR2: CPU profile saved to {}",
                                    path.display()
                                ),
                                Err(e) => {
                                    tracing::error!(error = %e, "SIGUSR2: CPU profile failed: {}", e)
                                }
                            }
                        });
                    }
                }
                Err(e) => tracing::warn!(error = %e, "SIGUSR2 unavailable: {}", e),
            }
        })
    };

    if let Err(e) = service.run().await {
        tracing::error!(error = %e, "frps error: {}", e);
        process::exit(frp_core::EXIT_RUNTIME);
    }

    #[cfg(unix)]
    reload_handle.abort();

    #[cfg(all(unix, feature = "profiling"))]
    profile_handle.abort();
}
