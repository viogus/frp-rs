use std::path::Path;
use std::process;

use frp_core::cli::{parse_frps_args, FrpsArgs, FrpsCmd};
use frp_core::config::{
    collect_config_files, load_server_config_checked, load_server_config_uncompleted_with_presence,
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

/// The `--config-dir` lane's live services, shared between the spawned service
/// tasks (writers) and the SIGUSR1 reload task (reader).
///
/// Local to the Unix lane on purpose: the signal itself and the handler both
/// live behind `#[cfg(unix)]`, and off unix a directory still runs but has no
/// reload path to share a registry with.
#[cfg(unix)]
type DirRegistry = std::sync::Arc<std::sync::Mutex<Vec<(std::sync::Arc<Service>, String)>>>;

/// Lock [`DirRegistry`], recovering a poisoned mutex instead of panicking.
///
/// The guarded value is a plain `Vec<(Arc<Service>, String)>`: a panic while the
/// lock was held cannot leave it structurally invalid, so taking the inner value
/// and continuing is safe. Panicking here instead is not safe — it would turn
/// every later registration and every later SIGUSR1 reload into a panic, i.e.
/// one service's panic would take the whole directory lane down with it.
#[cfg(unix)]
fn lock_dir_registry(
    registry: &DirRegistry,
) -> std::sync::MutexGuard<'_, Vec<(std::sync::Arc<Service>, String)>> {
    match registry.lock() {
        Ok(guard) => guard,
        Err(poisoned) => {
            tracing::error!(
                "SIGUSR1 directory registry mutex was poisoned; \
                 recovering the live service list"
            );
            // Debug-only sabotage hook for the `Run frps bin unit tests` CI step:
            // that step runs the poisoned-registry pin a second time with this
            // variable set and requires the run to **fail**, because a pin whose
            // body prints its completion marker and returns asserts nothing while
            // still reporting `1 passed`. Emptying the recovered list is exactly
            // the mutant the pin asserts against, so a vacuous pin cannot be made
            // to fail and the step reds. Never set outside that step.
            #[cfg(debug_assertions)]
            if std::env::var_os("FRPS_DIR_REGISTRY_TEST_DISCARD").is_some() {
                let mut guard = poisoned.into_inner();
                guard.clear();
                return guard;
            }
            poisoned.into_inner()
        }
    }
}

/// Removes one service from the [`DirRegistry`] when the task that registered it
/// stops — the graceful tail, a `run()` error, **or a panic**.
///
/// The last case is the whole reason this is a drop guard rather than the
/// explicit removal the error arm used to do: a panicking task unwinds, so it
/// never reaches that arm, and the dead service stayed registered — a later
/// SIGUSR1 fan-out then counted it (`reloaded N of N` with one of the N already
/// gone). Unwinding drops this guard, so the registration and the
/// unregistration are symmetric for every exit path the task has.
#[cfg(unix)]
struct DirRegistryEntry {
    registry: DirRegistry,
    service: std::sync::Arc<Service>,
}

#[cfg(unix)]
impl Drop for DirRegistryEntry {
    fn drop(&mut self) {
        let mut live = lock_dir_registry(&self.registry);
        if let Some(pos) = live
            .iter()
            .position(|(svc, _)| std::sync::Arc::ptr_eq(svc, &self.service))
        {
            live.remove(pos);
        }
    }
}

/// Main-task ownership of `SIGTERM`/`SIGINT` for the `--config-dir` lane.
///
/// The Unix `SIGTERM` handler lives inside `Service::run` — it is installed by a
/// task `run()` spawns at its top (`frp-server/src/service.rs:1854-1893`, the
/// same task that also takes `ctrl_c()`) — so a `SIGTERM` that lands between the
/// startup line and that registration takes the kernel's default disposition
/// and kills `frps` (`rc = -15`) instead of draining. The measured window is
/// ~0.16 ms median / 1.10 ms max.
///
/// Installing a main-task handler *without* recording would not fix that: tokio
/// keeps one `EventInfo` per signal kind, and its broadcast flips `pending` and
/// does a single `watch::Sender::send` (`tokio/…/signal/registry.rs`), so a
/// service whose own `Signal` is created later never sees a delivery that
/// happened before it existed. The race would become a **lost** `SIGTERM`,
/// which is worse than a signal death.
///
/// So this type records instead: [`Self::record`] is called by the main task's
/// listener the moment a signal is delivered, and it (a) sets `requested`,
/// (b) wakes the test-profile `recorded()` waiters, and (c) cancels the shutdown
/// token of every service that registered through [`Self::watch`]. `watch` and
/// `record` read `requested` and `states` in orders that cannot both miss a
/// service — see the call site in the per-file task.
///
/// A *second* request is a different matter: with nothing registered there is no
/// service to cancel and the caller may be stuck before its first one, so
/// [`Self::record`] forces an exit instead of leaving a process that no
/// `SIGTERM` can end (measured: pre-fix `frps` and Go `frpc` both die `rc 143`
/// in that lane).
#[cfg(unix)]
struct EarlyShutdown {
    /// Set by the recorder the moment a shutdown signal is delivered. Read by
    /// [`Self::watch`] (inline cancel) and by the test-profile `recorded()`.
    requested: std::sync::atomic::AtomicBool,
    /// Woken on the same edge so a task held open by the debug-only
    /// registration window (`FRPS_CFGDIR_TEST_REGISTRATION_DELAY_MS`) can
    /// register immediately instead of sleeping out a delay a spawn-level pin
    /// deliberately set longer than the pin itself.
    arrived: tokio::sync::watch::Sender<bool>,
    /// The `AppState` of every service that registered before the signal.
    /// `frps` depends on `tokio`, not `tokio-util`, so the cancellation token is
    /// reached through the service's own state (`Service::state`) rather than
    /// named here.
    states: std::sync::Mutex<Vec<std::sync::Arc<frp_server::state::AppState>>>,
}

#[cfg(unix)]
impl EarlyShutdown {
    /// Install the handler, before anything is spawned and before the startup
    /// line, and return the recorder.
    fn install() -> std::sync::Arc<Self> {
        use tokio::signal::unix::{signal, SignalKind};
        // The OS registration is what actually narrows the window, so it happens
        // first — a signal delivered while the directory is still being
        // constructed is queued by tokio and delivered to this listener.
        let sigterm = match signal(SignalKind::terminate()) {
            Ok(sig) => Some(sig),
            Err(e) => {
                tracing::warn!(error = %e, "SIGTERM unavailable: {}", e);
                None
            }
        };
        let sigint = match signal(SignalKind::interrupt()) {
            Ok(sig) => Some(sig),
            Err(e) => {
                tracing::warn!(error = %e, "SIGINT unavailable: {}", e);
                None
            }
        };
        let (arrived, _) = tokio::sync::watch::channel(false);
        let early = std::sync::Arc::new(Self {
            requested: std::sync::atomic::AtomicBool::new(false),
            arrived,
            states: std::sync::Mutex::new(Vec::new()),
        });
        if sigterm.is_none() && sigint.is_none() {
            return early;
        }
        let recorder = std::sync::Arc::clone(&early);
        tokio::spawn(async move {
            let mut sigterm = sigterm;
            let mut sigint = sigint;
            loop {
                tokio::select! {
                    _ = recv_shutdown_signal(&mut sigterm) => {
                        recorder.record(128 + 15, "SIGTERM");
                    }
                    _ = recv_shutdown_signal(&mut sigint) => {
                        recorder.record(128 + 2, "SIGINT");
                    }
                }
            }
        });
        early
    }

    /// Record a delivered shutdown signal and fan it out to every service that
    /// registered before it arrived.
    ///
    /// A *repeat* request while nothing has **ever** registered is the one case
    /// this cannot serve by cancelling: the config-directory lane is still
    /// blocked in `collect_config_files`/`read_to_string` (a pipe or FIFO named
    /// `*.toml` never returns), so no service exists to stop and there is
    /// nothing for the main task to observe. Left alone, the process would sit
    /// in that read forever, and the recorded request would have converted "dies
    /// on SIGTERM" into "deaf to SIGTERM" — on a FIFO-only directory the
    /// pre-fix and Go behaviour is signal death (`rc 143`). A second request
    /// therefore forces an exit; one signal is still always recorded and
    /// honoured, which is what the registration-window pin relies on.
    ///
    /// `states` is append-only, so "nothing has ever registered" above is exact:
    /// when the directory's *first* entry loads and the FIFO comes later, one
    /// service registers, this escalation cannot fire, and the lane stays deaf
    /// to `SIGTERM` exactly as the pre-fix binary is. Measured on that mixed
    /// shape (valid `a.toml` + FIFO `b.toml`): base `ea991757` and this tree
    /// both log `starting 2 services`, both survive four SIGTERMs, and only
    /// `SIGKILL` ends them (`wait rc 137`). Making that shape killable is a
    /// behaviour change, not claimed here or by the FIFO pin (FIFO-only
    /// fixture).
    fn record(&self, forced_exit: i32, name: &'static str) {
        // Store before taking `states`: `watch` reads `requested` **while
        // holding** the same lock, so a call that interleaves here either sees
        // `requested` already true (and cancels inline) or is already in
        // `states` below — never neither. The reverse order would open a gap in
        // which a service registers and the fan-out misses it.
        let already_requested = self
            .requested
            .swap(true, std::sync::atomic::Ordering::SeqCst);
        let states = self
            .states
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if already_requested && states.is_empty() {
            tracing::error!(
                "{name} requested again with no service registered to stop it; forcing exit \
                 {forced_exit}"
            );
            std::process::exit(forced_exit);
        }
        let _ = self.arrived.send(true);
        for state in states.iter() {
            state.shutdown_token.cancel();
        }
    }

    /// Register `state` for the recorded-shutdown fan-out. Returns `true`, after
    /// cancelling it, when the signal was recorded before this call — i.e. this
    /// service started inside the window this type exists to close.
    fn watch(&self, state: std::sync::Arc<frp_server::state::AppState>) -> bool {
        let mut states = self
            .states
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if self.requested.load(std::sync::atomic::Ordering::SeqCst) {
            state.shutdown_token.cancel();
            return true;
        }
        states.push(state);
        false
    }

    /// Resolves once a shutdown signal has been recorded — at once if one
    /// already was.
    ///
    /// Test-profile only. Both callers are spawn-level holds behind
    /// `debug_assertions` (`FRPS_CFGDIR_TEST_REGISTRATION_DELAY_MS` and
    /// `FRPS_CFGDIR_TEST_POST_REGISTRATION_DELAY_MS`), so a release build has no
    /// way to await this and the release CI jobs (`-D warnings`) would fail the
    /// build on the dead method. The gate sits on the method itself: an
    /// `allow(dead_code)` would hide the same warning for anything else that
    /// later becomes release-dead.
    #[cfg(debug_assertions)]
    async fn recorded(&self) {
        if self.requested.load(std::sync::atomic::Ordering::SeqCst) {
            return;
        }
        // `watch` (not `Notify`): every waiter must wake, and `subscribe` +
        // the re-check below makes the subscribe/send race impossible in either
        // direction — a send before `subscribe` is caught by the second check, a
        // send after it by `changed()`.
        let mut arrived = self.arrived.subscribe();
        if self.requested.load(std::sync::atomic::Ordering::SeqCst) {
            return;
        }
        let _ = arrived.changed().await;
    }
}

/// Await the next delivery on an optional signal, or never if its handler could
/// not be installed — `select!` needs a future on every branch even when one of
/// the two signals is unavailable.
#[cfg(unix)]
async fn recv_shutdown_signal(sig: &mut Option<tokio::signal::unix::Signal>) {
    match sig {
        Some(sig) => {
            sig.recv().await;
        }
        None => std::future::pending::<()>().await,
    }
}

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
        FrpsCmd::Verify(args) => run_verify(&args.config, args.strict_config, &args.allow_unsafe),
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
/// The loader is [`load_server_config_checked`] —
/// [`frp_core::config::load_server_config`] plus
/// [`frp_core::config::check_server_unsafe_features`]. The parse-and-validate
/// half is the same path the run path uses: the run path's single-config branch
/// calls [`frp_core::config::load_server_config_uncompleted`] (the same function
/// minus `ServerConfig::complete`) and completes the merged config itself, and
/// both go through `load_config_from_file` with `known_server_keys` and
/// `validate_server_config`. `verify` has no CLI overrides to merge, so it takes
/// the completing wrapper. The consequence is that `verify` accepts exactly the
/// configs `frps -c` accepts and refuses the ones it refuses: parse and
/// validation failures at **load** time, and an `auth.tokenSource` with
/// `type = "exec"` through the post-load `--allow-unsafe` gate, which is the
/// same predicate the daemon reaches at service construction
/// (`frp-server/src/service.rs`).
///
/// That gate is where Go and frp-rs once differed in *stage*: Go runs
/// `ValidateUnsafeFeature` from inside `ValidateServerConfig`
/// (`pkg/config/v1/validation/validator.go:22-27`, called for
/// `tokenSource.Type == "exec"` at `pkg/config/v1/validation/auth.go:34-35`), so
/// Go's verify (`cmd/frps/verify.go:46-48`) and its run path both refuse with
/// rc 1 and Go's own
/// `unsafe feature "TokenSourceExec" is not enabled. …` line. frp-rs now
/// refuses on this lane too (Go's rc **1**; the message is frp-rs's predicate
/// wording, the one the daemon already printed). The run path keeps its
/// construction-time refusal — `tracing::error!` + `EXIT_AUTH`/**3**, a
/// documented frp-rs extension, not Go's rc 1 — because moving the gate into
/// the loader would silently move that refusal onto this lane. Measured on the
/// branch head and pinned by `frps/tests/cli_exit_codes.rs`.
///
/// Logging is deliberately **not** initialised: Go installs its logger only in
/// `runServer` (`cmd/frps/root.go:112`), never on the verify path, and the
/// measured Go stdout for a lenient (`--strict-config=false`) verify is exactly
/// the one success line with stderr empty. Leaving `tracing` uninitialised drops
/// the lenient-load warnings the run path would emit, which is what keeps that
/// one-line shape (`tracing` records are a no-op without a subscriber).
fn run_verify(config_path: &str, strict_config: bool, allow_unsafe: &[String]) {
    if config_path.is_empty() {
        // Go: `fmt.Println("frps: the configuration file is not specified")`,
        // then `return nil` — rc 0, not an error.
        println!("frps: the configuration file is not specified");
        return;
    }
    let refs: Vec<&str> = allow_unsafe.iter().map(|s| s.as_str()).collect();
    let unsafe_features = UnsafeFeatures::new(&refs);
    match load_server_config_checked(config_path, strict_config, &unsafe_features) {
        Ok(_) => {
            // Go: `fmt.Printf("frps: the configuration file %s syntax is ok\n",
            // cfgFile)` (`cmd/frps/verify.go:56`).
            println!("frps: the configuration file {} syntax is ok", config_path);
        }
        Err(e) => {
            // Go: `fmt.Println(err); os.Exit(1)` (`cmd/frps/verify.go:42-44`) —
            // the same bare stdout line and rc the run path's load failure
            // prints (`frps/src/main.rs`, single-config branch). The
            // `--allow-unsafe` refusal arrives on this arm too, through the
            // loader's gate, which is why it needs no arm of its own.
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
        //
        // The file set is read **once**, here. SIGUSR1 only re-reads exactly
        // those files — one registry entry per file that constructed: a file
        // added to the directory after startup is never picked up, a file whose
        // construction failed is never retried, and a file removed on disk keeps
        // its service running (the reload then reports the read error and
        // changes nothing else). Documented and pinned by
        // `frps/tests/warn_delivery.rs::a_config_dir_reload_keeps_the_startup_file_set`.
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
        // Install the SIGUSR1 handler **before** anything is spawned and before
        // the startup line, so (a) a signal that arrives while the directory is
        // still being constructed is queued by tokio instead of taking the
        // default disposition and killing the process, and (b) the startup
        // marker is a hard lower bound for "the handler exists" — the spawn
        // tests send their signal the instant they see that line.
        //
        // Deliberately Unix-only. The whole SIGUSR1 lane (here, the registry
        // type above, the barrier below, and the reload task) has no non-unix
        // arm: off unix `--config-dir` still runs services but `SIGUSR1` is not
        // a signal that exists. `frps/tests/warn_delivery.rs` repeats the
        // `#[cfg(unix)]` gate on every test and helper that drives it, so the
        // omission is explicit rather than "compiles, then fails".
        #[cfg(unix)]
        let dir_reload_signal =
            match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::user_defined1()) {
                Ok(sig) => Some(sig),
                Err(e) => {
                    tracing::warn!(error = %e, "SIGUSR1 unavailable: {}", e);
                    None
                }
            };
        // The same "before anything is spawned and before the startup line"
        // ownership argument as SIGUSR1 above, for `SIGTERM`/`SIGINT`. These are
        // also installed per service inside `Service::run`, and tokio does *not*
        // replay a delivery to a listener created after it — so a second handler
        // alone would turn the pre-registration signal death into a lost
        // `SIGTERM` (see [`EarlyShutdown`]). The main task therefore owns the
        // handler first and **records** what it saw; each service hands its
        // `AppState` over after it registers, and either that handoff cancels the
        // token in time or the recorder's fan-out does.
        #[cfg(unix)]
        let early_shutdown = EarlyShutdown::install();
        tracing::info!(
            version = %frp_core::VERSION,
            count = %files.len(),
            "frps (Rust) v{} starting {} services from config directory",
            frp_core::VERSION,
            files.len()
        );
        // One permit per spawned task, released once that task has registered
        // its service — or once it has failed construction and therefore never
        // will. The reload task takes all `spawned` permits before it reports
        // ready, so the ready marker means "the registry is complete", not
        // merely "the handler exists". Without this, a signal in the
        // construction window silently reloaded only the subset that had
        // registered so far.
        #[cfg(unix)]
        let registration_barrier = std::sync::Arc::new(tokio::sync::Semaphore::new(0));
        let mut handles = Vec::new();
        // Files whose *load* failed never become tasks, so they are tracked
        // here — keyed by their position in `files` — to keep them inside the
        // all-failed decision below.
        let mut load_failures: Vec<(usize, i32)> = Vec::new();
        // Each task publishes its `Arc<Service>` **and its path** here once
        // construction succeeds, so the SIGUSR1 handler reloads the *same*
        // objects the runners are using and can name the file each summary came
        // from. A signal sent during construction now waits on the barrier above
        // and then sees the complete list; the lock is taken through
        // [`lock_dir_registry`], so a poisoned mutex is logged and skipped
        // rather than panicking every later reload.
        #[cfg(unix)]
        let registry: DirRegistry = Default::default();
        for (file_index, path) in files.iter().enumerate() {
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
                    presence.warn_inert_web_server_tls_enable(
                        frp_server::service::web_server_tls_enable_reader(),
                    );
                    // The flat server `tls_enable` is inert too; same sink, same
                    // one-record-per-load rule.
                    presence.warn_inert_server_tls_enable();
                    let uf = unsafe_features.clone();
                    #[cfg(unix)]
                    let registry = registry.clone();
                    #[cfg(unix)]
                    let registration_barrier = registration_barrier.clone();
                    #[cfg(unix)]
                    let early_shutdown = early_shutdown.clone();
                    handles.push((
                        file_index,
                        tokio::spawn(async move {
                            let service =
                                match Service::with_unsafe_features(cfg, Some(path_str.clone()), uf)
                                    .await
                                {
                                    Ok(s) => std::sync::Arc::new(s),
                                    Err(e) => {
                                        // Carry the **typed** code out of the
                                        // task: the single-config path below
                                        // exits on this same value, and a
                                        // directory that started no service must
                                        // not report success.
                                        let code = e.kind().exit_code();
                                        tracing::error!(path = %path_str, error = %e, "frps service init failed for [{}]: {}", path_str, e);
                                        // Construction failed, so this file
                                        // will never register: release its
                                        // barrier permit or the ready marker
                                        // would wait forever on a task that can
                                        // never satisfy it.
                                        #[cfg(unix)]
                                        registration_barrier.add_permits(1);
                                        return Err(code);
                                    }
                                };
                            // Debug-build-only hook (sibling of
                            // `FRPS_CFGDIR_TEST_PANIC` below): when
                            // `FRPS_CFGDIR_TEST_REGISTRATION_DELAY_MS` is set,
                            // the task sleeps here — **before** it registers —
                            // so a test can hold the pre-registration window
                            // open and deterministically observe what a SIGUSR1
                            // sent the instant the ready marker appeared would
                            // have seen without the barrier. `debug_assertions`
                            // is on for `cargo test` and off in every release
                            // build.
                            #[cfg(debug_assertions)]
                            if let Some(ms) = std::env::var("FRPS_CFGDIR_TEST_REGISTRATION_DELAY_MS")
                                .ok()
                                .and_then(|v| v.parse::<u64>().ok())
                            {
                                // Optional per-file filter
                                // (`FRPS_CFGDIR_TEST_REGISTRATION_DELAY_FILES`,
                                // comma-separated path fragments): hold only the
                                // matching files, so a pin can park one file
                                // across a delivered signal while the others
                                // register — the pre-registration half of the
                                // recorder's fan-out pin, whose
                                // post-registration half is the hold below.
                                let held = std::env::var("FRPS_CFGDIR_TEST_REGISTRATION_DELAY_FILES")
                                    .ok()
                                    .map(|files| {
                                        files.split(',').any(|f| path_str.contains(f.trim()))
                                    })
                                    .unwrap_or(true);
                                if held {
                                    // A recorded shutdown signal ends the hold early.
                                    // A spawn-level pin can then set a delay longer
                                    // than the test itself and send `SIGTERM` the
                                    // instant the startup line appears: the hold
                                    // ends because the main task *recorded* the
                                    // signal, so the pin proves the recorded path
                                    // instead of racing the registration.
                                    #[cfg(unix)]
                                    tokio::select! {
                                        _ = tokio::time::sleep(std::time::Duration::from_millis(ms)) => {}
                                        _ = early_shutdown.recorded() => {}
                                    }
                                    #[cfg(not(unix))]
                                    tokio::time::sleep(std::time::Duration::from_millis(ms)).await;
                                }
                            }
                            // Registered before `run()`, so the soonest possible
                            // SIGUSR1 already finds this service. Releasing the
                            // permit here (and only here, or on the
                            // construction-failure return above) is what makes
                            // the ready marker a registration barrier.
                            #[cfg(unix)]
                            {
                                lock_dir_registry(&registry)
                                    .push((service.clone(), path_str.clone()));
                                registration_barrier.add_permits(1);
                                // Hand the state to the main-task recorder
                                // **after** the push. `watch` and `record` read
                                // `requested`/`states` in orders that cannot both
                                // miss this service: `record` stores `requested`
                                // before it takes `states`, while `watch` holds
                                // `states` and reads `requested`. So either the
                                // signal was already recorded (this call cancels
                                // the token inline and returns true, meaning this
                                // service started inside the window the fix
                                // closes) or it arrives after the push and the
                                // recorder's fan-out cancels it. Never neither.
                                if early_shutdown.watch(service.state()) {
                                    tracing::info!(
                                        path = %path_str,
                                        "shutdown signal was recorded before this service \
                                         installed its own handler; stopping it through the \
                                         recorded request"
                                    );
                                }
                            }
                            // Debug-build-only hold (review round 2, F7), sibling
                            // of the pre-registration hook above: when it names
                            // *this* file, park the task **after** its state went
                            // into the recorder's fan-out list and **before**
                            // `Service::run` installs the service's own `SIGTERM`
                            // handler. In that interval only `record()`'s fan-out
                            // can cancel this token, so a pin can deliver one
                            // signal and observe whether the fan-out did its job.
                            // The `recorded()` arm keeps the hold from outliving
                            // the signal, so the pin measures the fan-out rather
                            // than a sleep.
                            #[cfg(all(unix, debug_assertions))]
                            if let Some(ms) =
                                std::env::var("FRPS_CFGDIR_TEST_POST_REGISTRATION_DELAY_MS")
                                    .ok()
                                    .and_then(|v| v.parse::<u64>().ok())
                            {
                                let held = std::env::var(
                                    "FRPS_CFGDIR_TEST_POST_REGISTRATION_DELAY_FILES",
                                )
                                .ok()
                                .map(|files| files.split(',').any(|f| path_str.contains(f.trim())))
                                .unwrap_or(true);
                                if held {
                                    tracing::info!(
                                        path = %path_str,
                                        "test hold: registered for the shutdown fan-out"
                                    );
                                    tokio::select! {
                                        _ = tokio::time::sleep(std::time::Duration::from_millis(ms)) => {}
                                        _ = early_shutdown.recorded() => {}
                                    }
                                }
                            }
                            // Armed immediately after the push above and dropped
                            // on **every** way out of this task — the graceful
                            // tail, the `run()` error arm below, and unwinding
                            // out of the panic hook in between. A panicking task
                            // never reaches the error arm, so an explicit removal
                            // there left the dead service in the registry and the
                            // next SIGUSR1 counted it.
                            #[cfg(unix)]
                            let _registry_entry = DirRegistryEntry {
                                registry: registry.clone(),
                                service: service.clone(),
                            };
                            // Debug-build-only hook for the spawn-level pin in
                            // `frps/tests/cli_exit_codes.rs`: when
                            // `FRPS_CFGDIR_TEST_PANIC` names *this* file, the
                            // task panics **after** it registered and released
                            // its permit — exactly the shape the exit guard
                            // must count. `debug_assertions` is on for
                            // `cargo test` and off in every release build, so
                            // this never ships and cannot be triggered in a
                            // production binary.
                            #[cfg(debug_assertions)]
                            if std::env::var_os("FRPS_CFGDIR_TEST_PANIC")
                                .is_some_and(|p| p == std::ffi::OsStr::new(path_str.as_str()))
                            {
                                panic!(
                                    "FRPS_CFGDIR_TEST_PANIC: deliberate test panic for {path_str}"
                                );
                            }
                            if let Err(e) = service.run().await {
                                // `Service::run` has exactly one `Ok(())`
                                // return — its graceful-shutdown tail
                                // (`frp-server/src/service.rs:2276`) — so this
                                // arm means the service stopped for good. The
                                // single-config path maps any `run()` error to
                                // `EXIT_RUNTIME` (`frps/src/main.rs:1079-1082`),
                                // and this lane carries the same code out,
                                // pinned on both lanes by
                                // `config_dir_where_every_service_fails_to_run_exits_like_dash_c`
                                // (`frps/tests/cli_exit_codes.rs`).
                                tracing::error!(path = %path_str, error = %e, "frps service error for config file [{}]: {}", path_str, e);
                                // Its listeners are gone, so a later SIGUSR1
                                // must not report a reload for a service that is
                                // no longer running: `_registry_entry` above owns
                                // that removal now, on this path and on the panic
                                // path alike.
                                return Err(frp_core::EXIT_RUNTIME);
                            }
                            // `Ok(())` = this task ran a service to a graceful
                            // shutdown; `Err(code)` = it never started, or its
                            // `run()` failed above.
                            Ok(())
                        }),
                    ));
                }
                Err(e) => {
                    tracing::error!(path = %path_str, error = %e, "Failed to load config from [{}]: {}", path_str, e);
                    // A load failure never becomes a task. Record it in file
                    // order with `EXIT_RUNTIME`, the code the `-c` lane maps
                    // every load error to, so the all-failed decision below can
                    // match `-c` instead of answering `EXIT_CONFIG` purely
                    // because `handles` came out empty.
                    load_failures.push((file_index, frp_core::EXIT_RUNTIME));
                }
            }
        }
        if handles.is_empty() {
            tracing::error!("No services started — all config files failed to load");
            // Match `-c`: the single-config lane maps a **load** error to
            // `EXIT_RUNTIME`/1 (`frps/src/main.rs` single-config branch), so a
            // directory where every file fails to load exits 1 too.
            // `load_failures` is in file order, so its first entry is the code
            // `-c <first failing file>` would exit on — the same file-order rule
            // the all-failed decision below uses. This used to be
            // `EXIT_CONFIG`/2 purely because `handles` was empty, which
            // disagreed with `-c` on the same file.
            let code = load_failures
                .first()
                .map(|(_, code)| *code)
                .unwrap_or(frp_core::EXIT_CONFIG);
            process::exit(code);
        }
        // Unix-only: the SIGUSR1 fan-out below is its only reader. Gated so the
        // non-unix cfg leaves no unused binding behind.
        #[cfg(unix)]
        let spawned = handles.len();

        // SIGUSR1 reload handler (Unix only) — kill -USR1 <pid>, the same
        // handler the single-config path installs below. One signal reloads
        // every service built from the directory, each from its **own** config
        // file (`Service::config_file` is that file's path), and each logs its
        // own summary. Without this task the flag kept its default disposition
        // and killed the process: measured on the base binary, `frps
        // --config-dir <dir>` + `kill -USR1` exited `unix_wait_status(158)`
        // (128+30, "User defined signal 1: 30") with no reload record.
        //
        // The OS registration happened above, before the startup line; this task
        // only owns the stream and the loop. It waits for every spawned task to
        // register — or to fail construction — before it reports ready, so the
        // ready marker cannot be observed while the registry is still filling.
        // The fan-out line then names both numbers, making a partial registry
        // visible in the record even if the gate ever regresses.
        #[cfg(unix)]
        let reload_handle = {
            let registry = registry.clone();
            let registration_barrier = registration_barrier.clone();
            tokio::spawn(async move {
                let mut sig = match dir_reload_signal {
                    Some(sig) => sig,
                    None => return,
                };
                // `spawned` permits, released one per task. Every task releases
                // exactly one — after registering, or on the
                // construction-failure return — and the panic hook sits *after*
                // its release, so a panicking task cannot hang this wait.
                if registration_barrier
                    .acquire_many(u32::try_from(spawned).unwrap_or(u32::MAX))
                    .await
                    .is_err()
                {
                    return;
                }
                tracing::info!(pid = %std::process::id(), "SIGUSR1 reload ready (pid={})", std::process::id());
                loop {
                    sig.recv().await;
                    // Copy the handles out and release the lock: the reload
                    // awaits, and holding a std mutex across an await would
                    // block registration (and duplicate the service list).
                    let svcs: Vec<(std::sync::Arc<Service>, String)> =
                        lock_dir_registry(&registry).clone();
                    let mut reloaded = 0usize;
                    for (svc, path) in &svcs {
                        // The `path` field attributes each summary when several
                        // services reload from one signal; the **message** stays
                        // byte-identical to the single-config lane's
                        // (`SIGUSR1: <summary>`), which the existing pins match
                        // on.
                        match svc.reload().await {
                            Ok(summary) => {
                                reloaded += 1;
                                tracing::info!(
                                    path = %path,
                                    summary = %summary,
                                    "SIGUSR1: {}",
                                    summary
                                );
                            }
                            Err(e) => tracing::error!(
                                path = %path,
                                error = %e,
                                "SIGUSR1 reload: {}",
                                e
                            ),
                        }
                    }
                    // `reloaded` counts services that actually reloaded;
                    // `registered` is the live registry size at signal time.
                    // Before the barrier above, a signal in the construction
                    // window produced a short `registered` (and a short fan-out)
                    // with no other trace of the files it silently missed;
                    // the line makes the shortfall visible either way.
                    let registered = svcs.len();
                    tracing::info!(
                        reloaded = reloaded,
                        registered = registered,
                        "SIGUSR1 fan-out: reloaded {} of {} services",
                        reloaded,
                        registered
                    );
                }
            })
        };

        // A task reports `Err(code)` when its service never started — the typed
        // code out of construction, or `EXIT_RUNTIME` when `run()` failed — and
        // `Ok(())` only when the service ran to a graceful shutdown, the sole
        // `Ok` return in `Service::run`
        // (`frp-server/src/service.rs:2276`). A **panicking** task reports
        // `Err(JoinError)`; it is counted as an `EXIT_RUNTIME` failure rather
        // than merely logged, because `Service::run` cannot have returned
        // `Ok(())` on a panic and dropping it let a directory where every task
        // panicked still exit 0. `load_failures` holds the files that never
        // became tasks, keyed by their position in `files`.
        //
        // The decision fires only when **every** file in the directory failed —
        // at load, construction, run, or by panic — and then exits on the
        // file-order first failure's code, i.e. exactly the code `-c` exits on
        // for that file. A mix (at least one file's service ran to a graceful
        // shutdown) keeps the historical log-and-keep-serving behaviour.
        //
        // Pinned by `frps/tests/cli_exit_codes.rs`:
        // `config_dir_where_every_file_fails_to_load_exits_like_dash_c` (all
        // load failures → 1, matching `-c`), the all-run-fail and mixed halves
        // of `config_dir_where_every_service_fails_to_run_exits_like_dash_c`
        // (`a.toml` no token → 3, `b.toml` held port → 1, so 3), and — through
        // the debug-only panic hook above —
        // `config_dir_where_every_task_panics_exits_nonzero`.
        //
        // The converse — a directory with a survivor — is pinned in **both**
        // file orders: `config_dir_where_one_service_fails_keeps_serving_and_exits_zero`
        // puts the failure second, and
        // `config_dir_where_the_first_service_fails_keeps_serving_and_exits_zero`
        // puts it first, so neither `if true` nor an "any file failed"
        // short-circuit (`failures.iter().any(|(file_index, _)| *file_index == 0)`)
        // can keep the process up on a code it must not exit.
        let mut failures: Vec<(usize, i32)> = load_failures;
        for (file_index, handle) in handles {
            match handle.await {
                Ok(Ok(())) => {}
                Ok(Err(code)) => failures.push((file_index, code)),
                Err(e) => {
                    tracing::error!(error = %e, "frps service task panicked: {}", e);
                    failures.push((file_index, frp_core::EXIT_RUNTIME));
                }
            }
        }
        if failures.len() == files.len() {
            failures.sort_by_key(|(file_index, _)| *file_index);
            if let Some((_, code)) = failures.first() {
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
    // warns at its own load site, so no path double-warns — pinned by the
    // `warn_delivery` lanes, which assert exactly one record on stdout and none
    // on stderr for both binaries and both paths
    // (`frps/tests/warn_delivery.rs::web_server_tls_enable_warning_reaches_a_dash_c_user`
    // and its `config_dir` sibling).
    presence.warn_inert_web_server_tls_enable(frp_server::service::web_server_tls_enable_reader());
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

/// `lock_dir_registry` must never turn a poisoned registry into a second panic.
///
/// The registry is locked on every registration and on every SIGUSR1 fan-out,
/// so a panic while the lock is held (a service task panicking mid-rotation
/// would do it) would otherwise make every *later* signal panic inside
/// `Mutex::lock().unwrap()` — a single failure silently escalating into "the
/// reload lane is dead". `lock_dir_registry` recovers the *live list* and logs;
/// this pin seeds the registry with **three** distinct real services under three
/// distinct names, in a deliberately non-sorted order, and captures the
/// recovery's log — so recovering an emptied list, truncating it to one entry,
/// reordering it, or dropping the log line is red rather than indistinguishable
/// from recovery.
#[cfg(all(test, unix))]
mod dir_registry_tests {
    use super::{lock_dir_registry, DirRegistry};
    use std::sync::{Arc, Mutex};

    /// An in-memory `tracing` writer: the recovery log has to be asserted, and
    /// `tracing_subscriber` is already a bin dependency (`init_logging`).
    #[derive(Clone, Default)]
    struct CapturedLog(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for CapturedLog {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().expect("capture lock").extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl CapturedLog {
        fn text(&self) -> String {
            String::from_utf8(self.0.lock().expect("capture lock").clone()).expect("utf-8 log")
        }
    }

    #[tokio::test]
    async fn lock_dir_registry_recovers_a_poisoned_registry() {
        // Three **distinct** services under three distinct file names, seeded in
        // a deliberately non-sorted order. One entry is not enough: a recovery
        // that truncates the list to its first element (`truncate(1)`, or
        // `drain(..).take(1)`) hands back `len() == 1` too, and a recovery that
        // sorts or dedups is only visible when the fixture is neither sorted nor
        // duplicate-free. Every entry is checked by `Arc::ptr_eq` and by name, so
        // "recovered the live list" cannot be satisfied by a fresh list of
        // lookalikes either.
        let mut live = Vec::new();
        for (token, name) in [
            ("registry-pin-c", "c.toml"),
            ("registry-pin-a", "a.toml"),
            ("registry-pin-b", "b.toml"),
        ] {
            let mut cfg = frp_core::config::ServerConfig::default();
            cfg.auth.token = token.to_string();
            live.push((
                Arc::new(
                    frp_server::service::Service::with_unsafe_features(
                        cfg,
                        None,
                        Default::default(),
                    )
                    .await
                    .expect("construct a service for the registry fixture"),
                ),
                name.to_string(),
            ));
        }
        let names: Vec<&str> = live.iter().map(|(_, name)| name.as_str()).collect();
        let registry: DirRegistry = Arc::new(Mutex::new(live.clone()));

        let poisoner = registry.clone();
        let _ = std::thread::spawn(move || {
            let _held = poisoner.lock().expect("fresh lock");
            panic!("deliberate test panic while the directory registry is locked");
        })
        .join();
        assert!(
            registry.is_poisoned(),
            "the mutex must actually be poisoned, or this pin proves nothing"
        );

        let captured = CapturedLog::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer({
                let captured = captured.clone();
                move || captured.clone()
            })
            .with_ansi(false)
            .finish();
        let guard = tracing::subscriber::with_default(subscriber, || lock_dir_registry(&registry));

        assert_eq!(
            guard.len(),
            live.len(),
            "recovery must hand back the whole live list, not a truncated one"
        );
        assert_eq!(
            guard
                .iter()
                .map(|(_, name)| name.as_str())
                .collect::<Vec<_>>(),
            names,
            "recovery must hand back every live entry, in registration order"
        );
        for (recovered, expected) in guard.iter().zip(live.iter()) {
            assert!(
                Arc::ptr_eq(&recovered.0, &expected.0),
                "the recovered entry for {} must still be that live service, not a \
                 lookalike",
                expected.1,
            );
        }
        let log = captured.text();
        assert!(
            log.contains("directory registry mutex was poisoned"),
            "recovery must log the poison it recovered from; log={log:?}"
        );
        // Reached only after **every** assertion above has run. The
        // `Run frps bin unit tests` CI step greps this line out of the
        // `--nocapture` output, so a test that returns early — and therefore
        // asserts nothing — reds that lane even though libtest still reports
        // `1 passed` for the name: a count/name check alone cannot see a gutted
        // body.
        println!("dir-registry-pin: ok, recovered {} entries", guard.len());
    }
}
