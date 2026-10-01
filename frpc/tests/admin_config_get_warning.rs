//! The admin config **GET**'s inert-`enable` delivery, pinned against the **real**
//! `frpc` binary — including the wiring the in-process test cannot reach.
//!
//! **What this pins that `frp-client/src/admin.rs` cannot.** The unit test there
//! (`admin_config_get_warns_once_per_state_change`) drives `config_from_file` and
//! `seed_web_server_tls_enable_seen` directly, so it pins the cell protocol and
//! the seed mapping — but not the one line in `spawn_admin_server`
//! (`frp-client/src/service.rs`) that puts the seed into the cell. Reverting that
//! line to round 2's `AtomicU8::new(0)` leaves all 11 of its tests green while the
//! shipped behaviour regresses (`seed` mutant M3b): the first GET then baselines
//! silently and a hand-edit that adds `[web_server.tls] enable` after startup is
//! **lost** (0 records). This target spawns the real binary, drives the real HTTP
//! route, and reds on that mutant.
//!
//! | case | startup | hand-edit | GETs | records |
//! |---|---|---|---|---|
//! | `hand_edit_after_startup_is_reported` | no `enable` | add `enable` | 1 | **1** |
//! | `startup_record_is_not_repeated_by_a_get` | has `enable` | — | 3 | **1** (startup only) |
//! | `seed_reads_the_file_non_strictly` | no `enable` + an unknown field, `--strict-config=false` | add `enable` | 1 | **1** |
//! | `seed_resolves_spellings_only_the_loader_does` (a/b) | `[common]` / `includes` spelling | — | 3 | **1** (startup only) |
//! | the same test's (c) | key in `admin-node.toml`, a key-less `frpc.toml` in the cwd | — | 3 | **1** (startup only) |
//! | the same test's (d) | key-less `admin-node.toml` (`-c`), a keyed `frpc.toml` in the cwd | add `enable` to the `-c` file | 1 | **1** |
//!
//! **The strict-flag row.** `seed_web_server_tls_enable_seen` loads with
//! `strict = false`, deliberately: the admin GET itself
//! (`config_from_file` → `load_client_config_with_presence(path, false)`) and the
//! service **reload** (`load_client_config(&path, false)`) both read the file
//! non-strictly, and the seed is standing in for the record that load already
//! emitted. Parsing strictly would make the seed fail on a file the runtime
//! accepts (any unknown field, under `--strict-config=false`), leaving
//! `NO_BASELINE` — and then the first GET baselines silently and a later add is
//! lost. The third row is that file: with the flag flipped to `true` the seed
//! fails, the GET adds **0**, and this test is red.
//!
//! **What this models.** A real `frpc` (built by `cargo test -p frpc --features
//! admin` for this target), a real config file, the real admin route
//! (`GET /api/proxy/main/config` — the handler loads the config *before* it
//! answers 404, so the 404 is not a problem), stdout and stderr captured
//! separately, a per-case free admin port, and a hand-edit made while the child
//! runs. No `frps` is needed: the admin server starts in `Service::run`
//! independently of the control connection, and `login_fail_exit = false` keeps
//! the child alive against a deliberately absent server.
//!
//! **What it does not cover.** The message text (pinned by
//! `frp-core/tests/web_server_tls_enable_warning.rs`), the PUT path's cell reset
//! (in-process, `admin_config_get_warns_once_per_state_change`), the admin API's
//! routing/auth/status codes (`frpc/tests/admin_cli.rs`), and the seed's
//! **failure-mode mapping** — that a missing path yields `NO_BASELINE` rather
//! than `ABSENT` is asserted in-process by that same test's two
//! `seed_web_server_tls_enable_seen(…) == WS_TLS_ENABLE_NO_BASELINE` cases
//! (`None`, then a path that does not exist). Under a `.unwrap_or(ABSENT)` mutant
//! **this** target stays green while the in-process one reds on the `None` case
//! (`frp-client/src/admin.rs:2044`), so the missing-path case is never reached;
//! either way the mapping is caught in-process, not here — this target only ever
//! exercises readable files. It also does not pin the *cadence* of any
//! particular poller beyond "three GETs add nothing".
//!
//! Bounded: every wait has a deadline, every child is killed and reaped by
//! [`ChildGuard::drop`] even on panic, and each test picks its own ports from the
//! ephemeral range. Record counts are polled to a deadline (stdout is a pipe;
//! a line can land a few milliseconds after the request that caused it).
//!
//! Gated on `full` (the `frpc` bin carries `required-features = ["full"]`) and
//! `admin` (the route only exists when the feature compiles it in).
#![cfg(all(feature = "full", feature = "admin"))]

use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// The binary under test: the one `cargo test -p frpc --features admin` built for
/// this target. `FRPC_BIN` overrides it, which is how the mutant runs are made.
const BIN: &str = env!("CARGO_BIN_EXE_frpc");
/// A substring of the first record `frpc` emits **after** `init_logging`, so
/// seeing it proves the load succeeded and a subscriber exists.
const STARTUP_MARKER: &str = "frpc (Rust) v";
/// Emitted once the admin listener is bound; the GETs must wait for it.
const ADMIN_MARKER: &str = "frpc admin server listening";
/// The inert-key record the tests count.
const KEY: &str = "web_server.tls.enable has no effect";
/// The marker unique to the **dashboard-build** clause
/// (`WEB_SERVER_TLS_ENABLE_INERT_WARNING`); this target only compiles when
/// `admin` is on, so this is the clause it must carry.
const DASHBOARD_CLAUSE: &str = "plaintext HTTP";
/// The marker unique to the **no-dashboard-build** clause
/// (`WEB_SERVER_TLS_ENABLE_INERT_WARNING_NO_DASHBOARD`) — the one an admin build
/// must never print. All three texts share `KEY` above, so `KEY` cannot tell them
/// apart on its own.
const NO_DASHBOARD_CLAUSE: &str = "no dashboard support";
/// How long a shape may take from spawn to a marker being visible.
const READY_TIMEOUT: Duration = Duration::from_secs(20);
/// How long a killed child may take to disappear before the guard gives up.
const REAP_TIMEOUT: Duration = Duration::from_secs(10);
/// Settle time after a marker or a GET, so the record it gates has been written.
const SETTLE: Duration = Duration::from_millis(500);
/// How long a record count may lag the request that caused it. Records appear in
/// milliseconds; this only stops a *failing* assertion from waiting out
/// [`READY_TIMEOUT`].
const COUNT_TIMEOUT: Duration = Duration::from_secs(5);
/// How long a spawn gets to *fail visibly* after its startup line: either the
/// child exited, or it logged [`ADMIN_PORT_HELD`]. Both happen microseconds after
/// `init_logging`, so this only bounds the observation — and it is what keeps a
/// port-contention retry from waiting out [`READY_TIMEOUT`].
const FAST_FAIL_WINDOW: Duration = Duration::from_millis(250);
/// The fatal record `frp-client`'s service logs when its admin listener cannot
/// bind. The child does **not** exit on it (it keeps retrying the control
/// connection), so the log is the only signal — the round-2 failure:
/// `frpc admin server failed: Address already in use (os error 48)`.
const ADMIN_PORT_HELD: &str = "admin server failed: Address already in use";
/// How many ports [`spawn_admin_ready`] may burn before it gives up. Startup
/// failures that survive three fresh ports are not port contention, so retrying
/// further would only hide a real breakage.
const MAX_ADMIN_PORT_ATTEMPTS: usize = 3;

fn bin() -> String {
    std::env::var("FRPC_BIN").unwrap_or_else(|_| BIN.to_string())
}

static DIR_COUNTER: AtomicU32 = AtomicU32::new(0);

/// Scratch directory that removes itself (same pattern as
/// `frpc/tests/warn_delivery.rs`: no `tempfile` dev-dependency in this crate).
struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        let n = DIR_COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("frpc-admin-get-{tag}-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        Self(dir)
    }

    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }

    fn write(&self, name: &str, contents: &str) -> PathBuf {
        let path = self.path(name);
        std::fs::write(&path, contents).expect("write config");
        path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// An ephemeral port that this process **keeps bound** until [`PortLease`] is
/// dropped or [`PortLease::release`] is called.
///
/// The old `free_port() -> u16` returned a number and immediately closed the
/// probe socket, so the kernel could hand the same port to any other process on
/// the host between that call and the child's bind — a window that is open for
/// as long as the test spends writing config files, which is exactly the window
/// the round-2 run lost: the child died with `frpc admin server failed: Address
/// already in use (os error 48)`. Holding the listener turns that race into a
/// *deterministic* failure here in the parent (our own bind, which we can see)
/// rather than an intermittent one in the child, and it is what lets
/// [`spawn_admin_ready`] and `admin_port_retry_recovers_from_a_held_port` force
/// the `AddrInUse` path on purpose instead of waiting for it to happen.
///
/// `release()` is the "hand the port over to the child" step and must be called
/// immediately before spawning; the lease stays useful for `.port()` either way.
struct PortLease {
    listener: std::net::TcpListener,
}

impl PortLease {
    fn port(&self) -> u16 {
        self.listener.local_addr().expect("lease local_addr").port()
    }

    /// Close the probe socket so the child can bind the port. Idempotent in
    /// effect (a later `release` re-binds and re-closes the same port, which
    /// keeps it withdrawn from the rest of the host for that instant).
    fn release(self) {
        drop(self.listener);
    }
}

/// A free port from the ephemeral range, deduplicated inside this process and
/// **held bound** — see [`PortLease`]. Release it right before spawning.
fn free_port() -> PortLease {
    loop {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("ephemeral bind");
        let port = listener.local_addr().expect("local_addr").port();
        if used_ports().lock().unwrap().insert(port) {
            return PortLease { listener };
        }
    }
}

/// One port handed to [`spawn_admin_ready`]: the lease **and** whether the helper
/// is allowed to release it.
///
/// Retrying requires releasing (the child must be able to bind), while the
/// `AddrInUse` demonstration requires the lease to stay bound. Leaving the choice
/// to the caller keeps one code path honest about both.
struct PortSource {
    lease: PortLease,
    released: bool,
}

impl PortSource {
    /// Hand the port to the child.
    fn releasable(lease: PortLease) -> Self {
        Self {
            lease,
            released: true,
        }
    }

    /// Keep the port for the duration — the child is not supposed to be able to
    /// bind it.
    fn held(lease: PortLease) -> Self {
        Self {
            lease,
            released: false,
        }
    }
}

fn used_ports() -> &'static Mutex<std::collections::HashSet<u16>> {
    static USED: std::sync::OnceLock<Mutex<std::collections::HashSet<u16>>> =
        std::sync::OnceLock::new();
    USED.get_or_init(|| Mutex::new(std::collections::HashSet::new()))
}

/// Kills and reaps the child on every exit path, including a panicking
/// assertion — a leaked `frpc` holds a port and keeps retrying its server.
struct ChildGuard {
    child: Child,
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let deadline = Instant::now() + REAP_TIMEOUT;
        loop {
            match self.child.try_wait() {
                Ok(Some(_)) => break,
                Ok(None) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(20))
                }
                _ => break,
            }
        }
        let _ = self.child.wait();
    }
}

/// A spawned `frpc` whose stdout and stderr are drained by reader threads (a full
/// pipe can never block the child).
struct Spawned {
    _guard: ChildGuard,
    stdout_buf: Arc<Mutex<String>>,
    stderr_buf: Arc<Mutex<String>>,
    /// The `web_server.port` the child was configured with, so a test can talk
    /// to it without threading the number through separately.
    admin_port: u16,
}

impl Spawned {
    fn from_child(mut child: Child, admin_port: u16) -> Self {
        let out = Arc::new(Mutex::new(String::new()));
        let err = Arc::new(Mutex::new(String::new()));
        drain(child.stdout.take().expect("child stdout"), out.clone());
        drain(child.stderr.take().expect("child stderr"), err.clone());
        Self {
            _guard: ChildGuard { child },
            stdout_buf: out,
            stderr_buf: err,
            admin_port,
        }
    }

    /// The admin port this child was configured with.
    fn admin_port(&self) -> u16 {
        self.admin_port
    }

    /// Wait until `marker` appears on either stream, or return why it did not, so
    /// a **retryable** startup failure ([`spawn_admin_ready`]) can report it and
    /// try another port instead of panicking out the whole readiness timeout. The
    /// first line of the message is stable ("exited"/"never"), so callers and
    /// logs can tell the two apart.
    fn wait_until(&mut self, marker: &str) -> Result<(), String> {
        let deadline = Instant::now() + READY_TIMEOUT;
        loop {
            let out = self.peek_stdout();
            let err = self.peek_stderr();
            if out.contains(marker) || err.contains(marker) {
                return Ok(());
            }
            if let Ok(Some(status)) = self._guard.child.try_wait() {
                return Err(format!(
                    "frpc exited ({status}) before {marker:?}\n--- stdout ({} B) ---\n{out}\n\
                     --- stderr ({} B) ---\n{err}",
                    out.len(),
                    err.len(),
                ));
            }
            if Instant::now() >= deadline {
                return Err(format!(
                    "frpc never logged {marker:?} within {READY_TIMEOUT:?}\n\
                     --- stdout ({} B) ---\n{out}\n--- stderr ({} B) ---\n{err}",
                    out.len(),
                    err.len(),
                ));
            }
            std::thread::sleep(Duration::from_millis(25));
        }
    }

    fn peek_stdout(&self) -> String {
        self.stdout_buf.lock().unwrap().clone()
    }

    /// Non-blocking: the child's exit status, if it has already died.
    fn peek_exit(&mut self) -> Option<std::process::ExitStatus> {
        self._guard.child.try_wait().ok().flatten()
    }

    fn peek_stderr(&self) -> String {
        self.stderr_buf.lock().unwrap().clone()
    }

    fn records(&self) -> usize {
        self.peek_stdout().matches(KEY).count()
    }

    /// Poll until at least `want` records are visible (a piped line can land a
    /// few milliseconds after the request that caused it), then assert exactly
    /// `want` on **both** streams' totals. `want` never changes under a mutant,
    /// so a wrong count can only fail — the poll just removes the timing flake.
    fn assert_records(&self, want: usize, tag: &str) {
        let deadline = Instant::now() + COUNT_TIMEOUT;
        while self.records() < want && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        let out = self.peek_stdout();
        let err = self.peek_stderr();
        assert_eq!(
            self.records(),
            want,
            "{tag}: expected {want} {KEY:?} record(s) on stdout\n--- stdout ---\n{out}\n\
             --- stderr ---\n{err}"
        );
        assert_eq!(
            err.matches(KEY).count(),
            0,
            "{tag}: the console sink is stdout; stderr must carry none\n--- stderr ---\n{err}"
        );
        assert_clause_is_the_dashboard_one(tag, &out);
    }
}

/// Fresh, **releasable** leases for [`spawn_ready`]: one per attempt, so a port
/// another process re-took during the handover costs one retry rather than the
/// whole readiness timeout.
struct FreePorts;

impl Iterator for FreePorts {
    type Item = PortSource;

    fn next(&mut self) -> Option<PortSource> {
        Some(PortSource::releasable(free_port()))
    }
}

/// The spawn every test in this file uses: pick a fresh leased port, hand it to
/// the child, and wait for the admin listener — **retrying on another leased
/// port** if the child cannot bind the one it was given.
///
/// There is no plain one-shot path any more. A number picked from the ephemeral
/// range and released just before the spawn can be taken by another process on
/// this host in the handover window, and the child does **not** exit on
/// `AddrInUse` (it keeps retrying its own server), so a one-shot "wait for the
/// admin marker" spends the whole [`READY_TIMEOUT`] and then fails a test that
/// had nothing wrong with it — the round-2 flake this closes. Going through
/// [`spawn_admin_ready`] makes a lost port recoverable; panics are reserved for
/// "every attempt failed on a distinct port", which is not contention.
fn spawn_ready(dir: &TempDir, argv: &[&str], write_config: impl Fn(&PortSource)) -> Spawned {
    let mut ports = FreePorts;
    // Nothing is deliberately held on this path, so the leases never escape the
    // loop; the forced-failure `admin_port_retry_recovers_from_a_held_port` owns
    // and asserts against its own held lease.
    let mut held_alive = Vec::new();
    // No test here asserts on the per-attempt reasons, but `spawn_admin_ready`
    // prints each one as it happens and includes them in its panic if the retry
    // budget runs out.
    let mut failures = Vec::new();
    spawn_admin_ready(
        dir,
        argv,
        write_config,
        &mut ports,
        &mut held_alive,
        &mut failures,
    )
}

/// Spawn the child and wait for its admin listener, **retrying with a fresh
/// leased port** when the child dies before it gets there.
///
/// `write_config` is called with each attempt's lease, so the file the child
/// reads always names the port that attempt actually uses — a retry that reused
/// the same port would just fail again and hide the point. A distinct port is
/// pulled from `port_source` per attempt, so a port another process on this host
/// grabbed is used at most once. `failures` collects the per-attempt reasons (and
/// is what `admin_port_retry_recovers_from_a_held_port` asserts on), and
/// `held_alive` keeps every [`PortSource::held`] lease bound for as long as the
/// caller needs it.
///
/// The child is only considered ready when both markers are visible **and** it is
/// still alive: a child that fails to bind the admin port logs
/// [`ADMIN_PORT_HELD`] immediately after `init_logging` (without exiting, because
/// it keeps retrying its server), so the startup marker alone is not readiness.
fn spawn_admin_ready(
    dir: &TempDir,
    argv: &[&str],
    write_config: impl Fn(&PortSource),
    port_source: &mut dyn Iterator<Item = PortSource>,
    held_alive: &mut Vec<PortLease>,
    failures: &mut Vec<String>,
) -> Spawned {
    for attempt in 1..=MAX_ADMIN_PORT_ATTEMPTS {
        let source = port_source
            .next()
            .unwrap_or_else(|| panic!("port source exhausted after {} attempt(s)", attempt - 1));
        write_config(&source);
        let port = source.lease.port();
        let PortSource { lease, released } = source;
        if released {
            lease.release();
        } else {
            // Keep it bound past this iteration — dropping it here would free
            // the port and make the "held" case indistinguishable from the
            // releasable one, which is what the caller is asserting against.
            held_alive.push(lease);
        }
        match admin_port_attempt(dir, argv, port) {
            Ok(mut spawned) => {
                spawned.admin_port = port;
                return spawned;
            }
            Err(reason) => {
                eprintln!(
                    "spawn attempt {attempt}/{MAX_ADMIN_PORT_ATTEMPTS} on port {port} failed: \
                     {reason}; retrying with a fresh leased port"
                );
                failures.push(reason);
            }
        }
    }
    panic!(
        "frpc never reached its admin listener in {MAX_ADMIN_PORT_ATTEMPTS} attempts, each on a \
         distinct leased port — this is not port contention\n--- attempts ---\n{}",
        failures.join("\n--- attempt ---\n")
    );
}

/// One [`spawn_admin_ready`] attempt: report **why** it failed rather than
/// panicking, so the caller can retry.
fn admin_port_attempt(dir: &TempDir, argv: &[&str], port: u16) -> Result<Spawned, String> {
    let child = Command::new(bin())
        .args(argv)
        .current_dir(&dir.0)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("spawn frpc: {e}"))?;
    let mut spawned = Spawned::from_child(child, port);
    // A startup failure is retryable by the caller, so propagate it instead of
    // panicking (`wait_for` is the panicking wrapper for the non-retrying path).
    spawned.wait_until(STARTUP_MARKER)?;
    // Fast-fail window: the held-port record (or a dead child) shows up here, so
    // the retry costs the window rather than the whole readiness timeout.
    std::thread::sleep(FAST_FAIL_WINDOW);
    if let Some(status) = spawned.peek_exit() {
        return Err(format!(
            "frpc exited ({status}) before its admin listener\n--- stdout ---\n{}\n\
             --- stderr ---\n{}",
            spawned.peek_stdout(),
            spawned.peek_stderr(),
        ));
    }
    if spawned.peek_stdout().contains(ADMIN_PORT_HELD) {
        return Err(format!(
            "frpc could not bind the admin port ({ADMIN_PORT_HELD:?}), and kept running\n\
             --- stdout ---\n{}",
            spawned.peek_stdout(),
        ));
    }
    if let Err(why) = spawned.wait_until(ADMIN_MARKER) {
        return Err(format!("frpc never reached its admin listener\n{why}"));
    }
    std::thread::sleep(SETTLE);
    Ok(spawned)
}

/// Provenance check used by the retry test: a second bind of `port` must fail
/// while the lease is alive, so the test can state that the port really was held.
fn rival_bind_fails(port: u16) -> bool {
    std::net::TcpListener::bind(("127.0.0.1", port)).is_err()
}

/// The clause the emitted record must carry in **this** target.
///
/// The file compiles only when `admin` is on (`#![cfg(all(feature = "full",
/// feature = "admin"))]`), so the build under test can serve HTTPS (`full`
/// forwards `frp-client/default`, which includes `tls`) and answers "a web server
/// with a TLS acceptor exists", and a record that says otherwise means a call
/// site answered wrongly. The call sites this file reaches are `frpc/src/main.rs:621`
/// (the `-c` startup load) and `frp-client/src/admin.rs:771` (the admin config-GET
/// handler runs `config_from_file`); it never drives the reload, so
/// `frp-client/src/service.rs:4458` is not visible here — that site is pinned by
/// `frp-client/tests/reload_warning_delivery.rs`. `KEY` is the shared prefix of
/// all three texts and cannot tell them apart; these markers are the whole
/// assertion. Every test in this file reaches it through [`assert_records`];
/// measured before the three-way reader landed, hardcoding a reached site's
/// answer to the no-dashboard one reds **2 of the 4** (`test result: FAILED. 2
/// passed; 2 failed`) — the startup rows witness `:604`, the hand-edit rows
/// witness `:771`.
fn assert_clause_is_the_dashboard_one(tag: &str, out: &str) {
    assert!(
        out.contains(DASHBOARD_CLAUSE),
        "{tag}: an admin build's record must keep the dashboard clause \
         ({DASHBOARD_CLAUSE:?})\n--- stdout ---\n{out}"
    );
    assert!(
        !out.contains(NO_DASHBOARD_CLAUSE),
        "{tag}: an admin build's record must not claim it has no dashboard support \
         ({NO_DASHBOARD_CLAUSE:?})\n--- stdout ---\n{out}"
    );
}

/// Read a child's pipe to EOF on its own thread, appending into `sink`.
fn drain<R: Read + Send + 'static>(mut pipe: R, sink: Arc<Mutex<String>>) {
    std::thread::spawn(move || {
        let mut buf = [0u8; 4096];
        loop {
            match pipe.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => sink
                    .lock()
                    .unwrap()
                    .push_str(&String::from_utf8_lossy(&buf[..n])),
            }
        }
    });
}

/// One admin config **GET**, hand-rolled so the test needs no HTTP client
/// dependency. The handler runs `config_from_file` before it can answer, so the
/// 404 for the absent `main` proxy still exercises the load; the response body is
/// read to EOF so the request is complete before the caller counts records.
fn admin_get(port: u16, tag: &str) -> String {
    let mut stream = std::net::TcpStream::connect(("127.0.0.1", port))
        .unwrap_or_else(|e| panic!("{tag}: connect to the admin port {port}: {e}"));
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .expect("set read timeout");
    stream
        .write_all(b"GET /api/proxy/main/config HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n")
        .unwrap_or_else(|e| panic!("{tag}: write the GET: {e}"));
    let mut response = String::new();
    stream
        .read_to_string(&mut response)
        .unwrap_or_else(|e| panic!("{tag}: read the response: {e}"));
    response
}

/// A `frpc` config that starts the admin server and stays up against an absent
/// server (`server_port = 1`, refused; `login_fail_exit = false`). `extra` is
/// appended verbatim after `[web_server]`.
fn frpc_config(admin_port: u16, extra: &str) -> String {
    format!(
        "server_addr = \"127.0.0.1\"\nserver_port = 1\ntoken = \"t\"\n\
         login_fail_exit = false\n[web_server]\naddr = \"127.0.0.1\"\nport = {admin_port}\n{extra}"
    )
}

/// The key's section, as a config fragment.
const ENABLE: &str = "[web_server.tls]\nenable = true\n";

/// A proxy whose `local_port` is distinctive, so a GET body proves **which**
/// file answered: only the `-c` file of sub-case (d) declares it, while the cwd
/// file there holds no proxies at all.
const MAIN_PROXY: &str =
    "\n[[proxies]]\nname = \"main\"\ntype = \"tcp\"\nlocalPort = 45999\nremotePort = 45999\n";

/// The headline behaviour change of the seeding round: a hand-edit that **adds**
/// `[web_server.tls] enable` after the admin server has started is reported by
/// the next admin config GET.
///
/// The file has no key at startup, so nothing is emitted at load and the seed
/// records `ABSENT`; the edit is therefore a real state change and the GET emits
/// **1**. With the seed wiring reverted to `AtomicU8::new(0)` the first GET
/// baselines silently and the total is **0** — the regression this target exists
/// to catch.
///
/// **What this does not cover.** A hand-edit made in the window **before** the
/// admin server starts: that one is still baselined, because the seed reads the
/// file at spawn; the window is named in the seed's and `AdminState`'s docs.
#[test]
fn hand_edit_after_startup_is_reported() {
    let dir = TempDir::new("hand-edit");
    let cfg = dir.path("frpc.toml");
    // Each attempt writes the port that attempt uses; `spawn_ready` releases the
    // lease and retries with a fresh one if the child cannot bind it.
    let child = spawn_ready(&dir, &["-c", cfg.to_str().unwrap()], |source| {
        dir.write("frpc.toml", &frpc_config(source.lease.port(), ""));
    });
    assert_eq!(
        child.records(),
        0,
        "no key at startup, so no startup record"
    );

    // The hand-edit: add the key while the child runs, then poll once.
    std::fs::write(&cfg, frpc_config(child.admin_port(), ENABLE)).expect("hand-edit the config");
    let response = admin_get(child.admin_port(), "hand-edit");
    assert!(
        response.contains("HTTP/1."),
        "the admin route must answer, got {response:?}"
    );

    child.assert_records(1, "one GET after a hand-edit");
    assert!(
        child.peek_stderr().is_empty() || !child.peek_stderr().contains(KEY),
        "stderr must stay clean"
    );
}

/// The no-duplicate control: a file that **had** the key at startup emits the
/// startup record, and three admin config GETs add **nothing**.
///
/// This is what the seed buys in the other direction — the cell already holds
/// `WRITTEN`, so the polls are not state changes. (It is a control rather than a
/// mutant-catcher: a `NO_BASELINE` cell also ends at one record, because its
/// first GET baselines silently. `hand_edit_after_startup_is_reported` is the row
/// that distinguishes the two.)
#[test]
fn startup_record_is_not_repeated_by_a_get() {
    let dir = TempDir::new("no-dup");
    let cfg = dir.path("frpc.toml");
    let child = spawn_ready(&dir, &["-c", cfg.to_str().unwrap()], |source| {
        dir.write("frpc.toml", &frpc_config(source.lease.port(), ENABLE));
    });
    child.assert_records(1, "the startup record");

    for i in 0..3 {
        let response = admin_get(child.admin_port(), "no-dup");
        assert!(response.contains("HTTP/1."), "GET {i} must answer");
    }
    child.assert_records(1, "three GETs over an unchanged file");
}

/// The seed reads the file **non-strictly**, like the admin GET and the service
/// reload it stands in for.
///
/// The config carries an unknown field, so the runtime is started with
/// `--strict-config=false`; the seed must still read it (strict parsing would
/// fail, leave `NO_BASELINE`, and silently baseline the hand-edit below). With
/// the flag flipped to `true` this test is red: 0 records instead of 1.
///
/// **What this does not cover.** The seed's `strict = true` failure mode itself
/// (asserted in-process by `admin_config_get_warns_once_per_state_change`'s
/// `NO_BASELINE` case), and the `-c` default (strict) — this row deliberately
/// measures the non-strict runtime.
#[test]
fn seed_reads_the_file_non_strictly() {
    let dir = TempDir::new("non-strict");
    let cfg = dir.path("frpc.toml");
    // An unknown top-level field: accepted by the runtime only because the run
    // is non-strict, and enough to make a strict seed fail.
    let child = spawn_ready(
        &dir,
        &["--strict-config=false", "-c", cfg.to_str().unwrap()],
        |source| {
            dir.write(
                "frpc.toml",
                &format!(
                    "unknown_top_level_field = 1\n{}",
                    frpc_config(source.lease.port(), "")
                ),
            );
        },
    );
    assert_eq!(child.records(), 0, "no key at startup");

    std::fs::write(
        &cfg,
        format!(
            "unknown_top_level_field = 1\n{}",
            frpc_config(child.admin_port(), ENABLE)
        ),
    )
    .expect("hand-edit the config");
    let response = admin_get(child.admin_port(), "non-strict");
    assert!(response.contains("HTTP/1."), "the route must answer");

    child.assert_records(1, "the seed must have read the non-strict file");
}

/// The seed reads the file with the **loader**, not with a raw top-level parse of
/// the TOML.
///
/// That distinction is invisible to the rows above: a seed that only looked at
/// `web_server.tls.enable` / `webServer.tls.enable` **at the top level** passes
/// them all, while the shipped seed resolves both shapes here — the key sits
/// under `[common]`, in either spelling, or in an `includes` file. Neither shape
/// reaches a raw top-level parse: `process_includes` deep-merges the include
/// (`frp-core/src/config/normalize.rs:600`) and the presence detector
/// (`ConfigPresence::web_server_tls_enable_set_in`) reads the value **before**
/// `normalize` (`frp-core/src/config/normalize.rs:621`), with its own "top level
/// first, `[common]` second" fallback per spelling
/// (`frp-core/src/config/loader.rs:427-429`). The per-key section merge
/// (`merge_section_into`) runs inside `normalize`, so it is not what the flag
/// consults — the merge has its own frp-core pin. Measured on the shipped binary
/// before this row existed: both shapes emit **1** record at 0 GETs and still
/// **1** after 3.
///
/// Each sub-case asserts the no-duplicate property: the file wrote the key (so
/// the startup load emits one record — asserted first, which is also what proves
/// the shape reached the loader), then three admin GETs add **nothing**. A
/// raw-parse seed records `ABSENT`, so the first GET sees a state change and
/// emits a second record, and the total is 2 — red.
///
/// **What this does not cover.** The presence detector's own spelling matrix
/// (pinned in `frp-core/tests/web_server_tls_enable_warning.rs`, which measures
/// each `[common]`/cross-spelling row directly, and by
/// `common_and_includes_spellings_set_the_flag`). Sub-cases (c) and (d) pin the
/// **path** the seed reads rather than a default filename, in both directions:
/// (c) starts the child with a non-default filename carrying the key while a
/// `frpc.toml` **without** the key sits in its working directory, and (d) starts
/// it with a key-less `-c` file while the working directory's `frpc.toml` **has**
/// the key, then adds the key to the `-c` file: the `-c` argument must win, so
/// that edit is a real state change and the GET emits **1**. (d) is the row a
/// "prefer `./frpc.toml` only when that file sets the key" seed reds (it would
/// have baselined `WRITTEN` and emitted **0**); (c) cannot see that seed, because
/// there the cwd file does not set the key.
#[test]
fn seed_resolves_spellings_only_the_loader_does() {
    // (a) `[common.webServer.tls] enable` beside a top-level `[web_server]`: the
    //     two spellings are different keys, so the flatten keeps `webServer` and
    //     the presence detector finds its `tls` through the `[common]` fallback —
    //     read before `normalize`, so the per-key merge is not what keeps it.
    let dir = TempDir::new("loader-common");
    let cfg = dir.path("frpc.toml");
    let child = spawn_ready(&dir, &["-c", cfg.to_str().unwrap()], |source| {
        dir.write(
            "frpc.toml",
            &frpc_config(
                source.lease.port(),
                "[common.webServer.tls]\nenable = true\n",
            ),
        );
    });
    child.assert_records(1, "(a) the startup record for the [common] spelling");
    for _ in 0..3 {
        let response = admin_get(child.admin_port(), "(a) common spelling");
        assert!(response.contains("HTTP/1."), "the route must answer");
    }
    child.assert_records(1, "(a) three GETs over the [common] spelling");

    // (b) The same key in an `includes` file, which `process_includes`
    //     deep-merges before the detector runs.
    let dir = TempDir::new("loader-includes");
    let cfg = dir.path("frpc.toml");
    let child = spawn_ready(&dir, &["-c", cfg.to_str().unwrap()], |source| {
        dir.write(
            "frpc.toml",
            &format!(
                "includes = [\"inc.toml\"]\n{}",
                frpc_config(source.lease.port(), "")
            ),
        );
        dir.write("inc.toml", "[common.webServer.tls]\nenable = true\n");
    });
    child.assert_records(1, "(b) the startup record for the includes spelling");
    for _ in 0..3 {
        let response = admin_get(child.admin_port(), "(b) includes spelling");
        assert!(response.contains("HTTP/1."), "the route must answer");
    }
    child.assert_records(1, "(b) three GETs over the includes spelling");

    // (c) The seed must read the path it was handed, not a default filename: the
    //     child is started with `-c admin-node.toml` (carrying the key) while its
    //     working directory holds a `frpc.toml` **without** the key. A seed that
    //     read `./frpc.toml` instead would record `ABSENT`, and the first GET would
    //     then report the key as a state change — a second record. (A default-name
    //     read of an *absent* `frpc.toml` is not caught here: `NO_BASELINE`
    //     baselines silently on the first GET, so the counts would match.)
    let dir = TempDir::new("loader-argument");
    let cfg = dir.path("admin-node.toml");
    let child = spawn_ready(&dir, &["-c", cfg.to_str().unwrap()], |source| {
        // Both files name the port this attempt actually uses, so a retry cannot
        // leave the cwd file pointing at a port another attempt owns.
        let port = source.lease.port();
        dir.write("frpc.toml", &frpc_config(port, ""));
        dir.write("admin-node.toml", &frpc_config(port, ENABLE));
    });
    child.assert_records(1, "(c) the startup record for a non-default filename");
    for _ in 0..3 {
        let response = admin_get(child.admin_port(), "(c) non-default filename");
        assert!(response.contains("HTTP/1."), "the route must answer");
    }
    child.assert_records(1, "(c) three GETs over a non-default filename");

    // (d) The same precedence in the other direction: the `-c` file
    //     (`admin-node.toml`) is **key-less**, while the working directory holds a
    //     `frpc.toml` **with** the key. The `-c` argument must still win, so the
    //     startup load emits nothing and the seed records `ABSENT` — which makes
    //     adding the key to the `-c` file a real state change, so the next GET
    //     emits **1** (a GET warns only when the file *becomes* written; see
    //     `config_from_file`). A seed that preferred an *existing* keyed
    //     `./frpc.toml` would record `WRITTEN`, and the same edit would then emit
    //     **0** — red. Sub-case (c) catches only the plain "always prefer
    //     `./frpc.toml`" seed (its keyed `-c` file makes that seed emit a second
    //     record, 2 vs 1); this row is what catches the narrower "prefer the cwd
    //     file only when it sets the key" fallback, which (c) cannot see because
    //     there the cwd file does *not* set the key.
    //
    //     The `-c` file also declares the only `main` proxy (distinctive
    //     `local_port = 45999`); the cwd file declares none. So the GET body, not
    //     just the record count, says which file answered: a load that preferred
    //     the proxy-less cwd file still emits the same single record, but answers
    //     `404 proxy "main" not found` instead of describing the proxy.
    let dir = TempDir::new("loader-precedence");
    let cfg = dir.path("admin-node.toml");
    let child = spawn_ready(&dir, &["-c", cfg.to_str().unwrap()], |source| {
        let port = source.lease.port();
        dir.write("frpc.toml", &frpc_config(port, ENABLE));
        dir.write("admin-node.toml", &frpc_config(port, MAIN_PROXY));
    });
    assert_eq!(
        child.records(),
        0,
        "(d) the `-c` file has no key at startup, so no record — a load that read \
         the keyed ./frpc.toml instead would have emitted one"
    );

    // The hand-edit lands in the `-c` file, not in the cwd one, so only a seed
    // that actually read the `-c` file sees the change. It keeps the proxy.
    std::fs::write(
        &cfg,
        frpc_config(child.admin_port(), &format!("{MAIN_PROXY}{ENABLE}")),
    )
    .expect("hand-edit the -c file");
    let response = admin_get(child.admin_port(), "(d) precedence");
    assert!(
        response.contains("HTTP/1."),
        "the admin route must answer, got {response:?}"
    );
    child.assert_records(1, "(d) one GET after the `-c` file gains the key");
    // Provenance, not just the count: `main` exists only in the `-c` file, so a
    // body describing it can only have come from there.
    assert!(
        response.contains("\"local_port\":45999"),
        "(d) the GET body must describe the `main` proxy declared in the `-c` file \
         — a load that read the proxy-less cwd ./frpc.toml answers 404 instead\n\
         --- response ---\n{response}"
    );
}

/// The retry path of [`spawn_admin_ready`], driven **on purpose**: the first port
/// handed to the retry loop is one this process deliberately keeps bound, so the
/// child cannot bind it and dies with the round-2 `Address already in use (os
/// error 48)`. The loop must recognize that early exit and try a second, fresh
/// port — under the old "pick a number, spawn once" flow the same situation
/// flakes instead of being reported, which is what this test keeps from coming
/// back.
///
/// The held port is bound **throughout** the call, so "the child bound it anyway"
/// is impossible; the rival-bind check at the end states that in the assertion.
#[test]
fn admin_port_retry_recovers_from_a_held_port() {
    let dir = TempDir::new("retry");
    // Attempt 1's lease is never released, so the child cannot bind it and dies.
    let held = free_port();
    let held_port = held.port();
    // Attempt 2 gets a releasable lease; this is the port the child survives on.
    let second = free_port();
    let second_port = second.port();
    let mut source = std::iter::once(PortSource::held(held))
        .chain(std::iter::once(PortSource::releasable(second)));
    // Keeps attempt 1's lease bound for the whole call (see `spawn_admin_ready`).
    let mut held_alive = Vec::new();
    let mut failures = Vec::new();
    // Each attempt gets a config naming the port that attempt actually uses.
    let child = spawn_admin_ready(
        &dir,
        &["-c", "frpc.toml"],
        |source| {
            dir.write("frpc.toml", &frpc_config(source.lease.port(), ENABLE));
        },
        &mut source,
        &mut held_alive,
        &mut failures,
    );
    assert_eq!(
        child.admin_port(),
        second_port,
        "the surviving child must be the retry, on the second leased port (held_port={held_port})"
    );

    // Provenance of the failure: attempt 1 must have died before its admin
    // listener, and the loop recorded it instead of panicking.
    assert_eq!(
        failures.len(),
        1,
        "exactly one attempt must be retried\n--- failures ---\n{}",
        failures.join("\n--- failure ---\n")
    );
    // The child logs the bind failure and keeps running, so the loop must have
    // recognized the *record*, not a process exit.
    assert!(
        failures[0].contains("could not bind the admin port")
            && failures[0].contains("Address already in use"),
        "the retried attempt must be the held port's bind failure, not a timeout: {}",
        failures[0]
    );

    // The child is alive and serving on its own second port; the held port is
    // still ours, so the failure this test forces cannot be blamed on the child.
    let response = admin_get(child.admin_port(), "(retry) recovered");
    assert!(
        response.contains("HTTP/1."),
        "the retried child must serve the admin route, got {response:?}"
    );
    assert!(
        rival_bind_fails(held_port),
        "the deliberately held port {held_port} must still be bound"
    );
    // Two-way control: once the caller lets the lease go, the same port binds —
    // so the assertion above is about the *held* lease, not about
    // `rival_bind_fails` being unable to succeed on this host.
    drop(held_alive);
    assert!(
        !rival_bind_fails(held_port),
        "the port must become bindable once the held lease is dropped, or the \
         check above proves nothing"
    );
}
