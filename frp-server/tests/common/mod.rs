use std::collections::HashSet;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{LazyLock, Mutex};
use std::time::Duration;
use tokio::net::TcpSocket;
use tokio::task::JoinHandle;

use frp_core::config::ServerConfig;
use frp_core::encryption;
use frp_core::msg::{self, FrpMessage, Login, LoginResp};
use frp_core::protocol::{read_msg_v1, write_msg_v1};
use frp_core::transport::IoStream;
use frp_server::service::Service;

/// Register a TCP proxy with an explicit remote port on a logged-in control
/// stream, asserting a successful NewProxyResp. The remote port must come
/// from `allocate_port` (an explicit port keeps frps from racing parallel
/// test servers on a full-range auto-assign scan).
#[allow(dead_code)]
pub async fn register_tcp_proxy(ctl: &mut IoStream, name: &str, remote_port: u16) {
    let np = FrpMessage::NewProxy(Box::new(msg::NewProxy {
        proxy_name: name.into(),
        proxy_type: "tcp".into(),
        sk: None,
        use_encryption: None,
        use_compression: None,
        group: None,
        group_key: None,
        local_str: Some("127.0.0.1:1".into()),
        remote_port: Some(remote_port as i32),
        custom_domains: None,
        subdomain: None,
        locations: None,
        http_user: None,
        http_pwd: None,
        host_header_rewrite: None,
        headers: None,
        response_headers: None,
        route_by_http_user: None,
        allow_users: None,
        bandwidth_limit: None,
        bandwidth_limit_mode: None,
        annotations: None,
        metas: None,
        multiplexer: None,
        virtual_net: None,
        proxy_protocol_version: None,
        advertise_subnet: None,
        vnet_ip: None,
        vnet_netmask: None,
        vnet_mtu: None,
    }));
    write_msg_v1(ctl, &np)
        .await
        .unwrap_or_else(|e| panic!("send NewProxy for {name}: {e}"));
    match read_msg_v1(ctl)
        .await
        .unwrap_or_else(|e| panic!("read NewProxyResp for {name}: {e}"))
    {
        FrpMessage::NewProxyResp(r) => {
            assert!(r.error.is_none(), "register {name}: {:?}", r.error);
        }
        other => panic!(
            "expected NewProxyResp for {name}, got type byte {:?}",
            other.v1_type_byte()
        ),
    }
}

/// Bridge one user connection through a live TCP proxy the way an frpc does.
/// The user connects to the proxy's remote port; because the test never
/// answers the post-login pre-warm ReqWorkConn, the work pool is empty and
/// the server asks for a work conn on the control; a fresh NewWorkConn TCP
/// connection answers and the server writes StartWorkConn on it.
///
/// Returns the `(user, work)` stream pair with the bridge live. `ctl` must
/// be the encrypted control stream from `raw_login`/`login_with_test_token`.
#[allow(dead_code)]
pub async fn open_tcp_proxy_bridge(
    server_addr: SocketAddr,
    remote_port: u16,
    ctl: &mut IoStream,
    run_id: &str,
) -> (tokio::net::TcpStream, tokio::net::TcpStream) {
    let user = tokio::net::TcpStream::connect(("127.0.0.1", remote_port))
        .await
        .expect("user conn to proxy remote port");
    match tokio::time::timeout(Duration::from_secs(5), read_msg_v1(ctl))
        .await
        .expect("ReqWorkConn after user connect within 5s")
        .expect("read ReqWorkConn")
    {
        FrpMessage::ReqWorkConn(_) => {}
        other => panic!(
            "expected ReqWorkConn, got type byte {:?}",
            other.v1_type_byte()
        ),
    }
    let mut work = tokio::net::TcpStream::connect(server_addr)
        .await
        .expect("work conn dial");
    write_msg_v1(
        &mut work,
        &FrpMessage::NewWorkConn(msg::NewWorkConn {
            run_id: Some(run_id.into()),
            timestamp: None,
            privilege_key: None,
        }),
    )
    .await
    .expect("send NewWorkConn");
    match tokio::time::timeout(Duration::from_secs(5), read_msg_v1(&mut work))
        .await
        .expect("StartWorkConn within 5s")
        .expect("read StartWorkConn")
    {
        FrpMessage::StartWorkConn(swc) => assert!(swc.error.is_none(), "{:?}", swc.error),
        other => panic!(
            "expected StartWorkConn, got type byte {:?}",
            other.v1_type_byte()
        ),
    }
    (user, work)
}

/// Pump `user_to_work` bytes user → work and `work_to_user` bytes work →
/// user through a live bridge, then half-close each side (write shutdown) in
/// an order that lets the server's relay terminate cleanly with exact byte
/// counts: FIN after the user→work data ends that arm, FIN after the
/// work→user data ends the other. The bridge task records the traffic on
/// completion, so callers poll the traffic endpoints afterwards.
#[allow(dead_code)]
pub async fn pump_tcp_bridge(
    mut user: tokio::net::TcpStream,
    mut work: tokio::net::TcpStream,
    user_to_work: usize,
    work_to_user: usize,
) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // user → work: write the payload, then half-close so the server's
    // user→work relay arm sees EOF (after all bytes) and finishes.
    let payload = vec![0xA5u8; user_to_work];
    user.write_all(&payload).await.expect("user writes payload");
    user.shutdown().await.expect("user half-close");
    // The frpc side (local service) receives exactly user_to_work bytes.
    let mut received = vec![0u8; user_to_work];
    work.read_exact(&mut received)
        .await
        .expect("work reads payload");
    assert_eq!(received, payload, "work conn payload must be byte-exact");

    // work → user: mirrored, closing the other direction.
    let response = vec![0x5Au8; work_to_user];
    work.write_all(&response)
        .await
        .expect("work writes response");
    work.shutdown().await.expect("work half-close");
    let mut echoed = vec![0u8; work_to_user];
    user.read_exact(&mut echoed)
        .await
        .expect("user reads response");
    assert_eq!(echoed, response, "user conn response must be byte-exact");
    // Both conns drop here, fully closed.
}

/// Go frp v0.71.0 `NotFoundResponse` (pkg/util/http/http.go) — the exact
/// 404 answer frps writes on a vhost/tcpmux route miss (and control-gone)
/// when no `custom_404_page` is configured. Probe-verified byte-exact vs
/// the Go v0.71.0 binary: 92-byte head + 489-byte body = 581 bytes total.
/// The response is written raw — Go's stdlib http.Server-layer headers
/// (Date, charset) are absent on frp's own responses.
#[allow(dead_code)] // used by the tcpmux and vhost_audit_fixes bins only
pub const GO_404_NOT_FOUND_RESPONSE: &str = concat!(
    "HTTP/1.1 404 Not Found\r\n",
    "Content-Length: 489\r\n",
    "Content-Type: text/html\r\n",
    "Server: frp/0.71.0\r\n",
    "\r\n",
    "<!DOCTYPE html>\n",
    "<html>\n",
    "<head>\n",
    "<title>Not Found</title>\n",
    "<style>\n",
    "    body {\n",
    "        width: 35em;\n",
    "        margin: 0 auto;\n",
    "        font-family: Tahoma, Verdana, Arial, sans-serif;\n",
    "    }\n",
    "</style>\n",
    "</head>\n",
    "<body>\n",
    "<h1>The page you requested was not found.</h1>\n",
    "<p>Sorry, the page you are looking for is currently unavailable.<br/>\n",
    "Please try again later.</p>\n",
    "<p>The server is powered by <a href=\"https://github.com/fatedier/frp\">frp</a>.</p>\n",
    "<p><em>Faithfully yours, frp.</em></p>\n",
    "</body>\n",
    "</html>\n",
);

/// Read from a client stream until EOF. frp-rs error responses (404/407/431)
/// are followed by the server dropping the conn, so EOF is the reliable
/// end-of-response marker for byte-exact assertions. Each read is bounded —
/// a peer that never closes fails the test fast instead of hanging it.
#[allow(dead_code)] // used by the tcpmux, tcpmux_httpconnect and vhost_audit_fixes bins
pub async fn read_until_eof(stream: &mut tokio::net::TcpStream) -> Vec<u8> {
    use tokio::io::AsyncReadExt;
    let mut out = Vec::new();
    let mut buf = [0u8; 512];
    loop {
        let n = tokio::time::timeout(Duration::from_secs(3), stream.read(&mut buf))
            .await
            .expect("timeout waiting for EOF after the response")
            .expect("read response bytes");
        if n == 0 {
            return out;
        }
        out.extend_from_slice(&buf[..n]);
    }
}

/// Ports already handed out by this process. Parallel tests must never
/// receive the same port twice — the probe-then-drop window in
/// allocate_port would otherwise let a second test grab the port before
/// the first test's server binds it (CI flake: a tcpmux CONNECT landing on
/// a foreign listener → connection reset).
#[allow(dead_code)]
static USED_PORTS: LazyLock<Mutex<HashSet<u16>>> = LazyLock::new(|| Mutex::new(HashSet::new()));

/// RAII guard holding an exclusive flock(2) on the shared port-allocation
/// lock file. Every integration-test **bin** is a separate process, so each
/// compiles its own copy of `common` with its own `USED_PORTS` set; the
/// kernel-level flock is the only thing that serializes the probe-then-drop
/// window **across** those processes. The lock is held for the duration of
/// one `allocate_port` call, so two bins can never both confirm the same
/// ephemeral port is free and hand it out at once.
#[cfg(unix)]
#[allow(dead_code)]
struct PortRequestGuard {
    file: std::os::fd::OwnedFd,
}

#[cfg(unix)]
impl Drop for PortRequestGuard {
    fn drop(&mut self) {
        use std::os::fd::AsRawFd;
        // SAFETY: `fd` is a live OwnedFd held by self until this Drop ends;
        // flock(LOCK_UN) is always safe on a valid fd. The OwnedFd's own Drop
        // then closes the descriptor after we release the lock.
        unsafe {
            libc::flock(self.file.as_raw_fd(), libc::LOCK_UN);
        }
    }
}

/// Acquire the cross-process port-allocation lock (blocking). The lock file
/// is kept in the OS temp dir so every test-bin process resolves the same
/// path; the file is never deleted (it is a persistent flock anchor).
#[cfg(unix)]
#[allow(dead_code)]
fn acquire_port_request_lock() -> PortRequestGuard {
    use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd};
    let path = std::env::temp_dir().join("frp-test-port-alloc.lock");
    let file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&path)
        .expect("open shared port-alloc lock file");
    // Transfer the raw fd ownership into an OwnedFd; it (not the File) is what
    // the guard holds, so the descriptor stays live for the whole lock.
    // SAFETY: `fd` is a valid, owned descriptor freshly produced by open(2)
    // above; transferring it into OwnedFd::from_raw_fd is the canonical idiom.
    let fd = unsafe { std::os::fd::OwnedFd::from_raw_fd(file.into_raw_fd()) };
    // Exclusive, blocking: concurrent bins queue here so only one probes-and-
    // confirms at a time. Failures from environmental fd exhaustion abort the
    // test loudly rather than silently racing for ports.
    let ret = unsafe { libc::flock(fd.as_raw_fd(), libc::LOCK_EX) };
    assert_eq!(ret, 0, "flock on shared port-alloc lock file failed: errno");
    PortRequestGuard { file: fd }
}

/// Non-unix fallback: a no-op guard so `allocate_port` compiles everywhere
/// (flock(2) is unix-only; the target platforms are macOS + Linux CI). Keeps
/// the `let _lock = acquire_port_request_lock();` call site cfg-free.
#[cfg(not(unix))]
#[allow(dead_code)]
struct PortRequestGuard;

#[cfg(not(unix))]
#[allow(dead_code)]
fn acquire_port_request_lock() -> PortRequestGuard {
    PortRequestGuard
}

/// Bind to a random port, return the port number, then drop the socket.
/// Never returns a port already handed out by this process, and re-verifies
/// the port is still bindable right before returning (narrows the
/// probe-then-drop window). Falls back to a random ephemeral port on
/// sandboxed environments where explicit binding is disallowed.
///
/// **Known residual window — not a fix, and not covered by the `flock`.** The
/// lock below serialises only the probe→confirm→hand-out step. The socket is
/// still *dropped* before the returned port is bound by the test (typically by
/// a child `frps`), and the port came from `127.0.0.1:0`, i.e. the ephemeral
/// range — so a concurrent outbound socket can take the number in between, and
/// the child then fails to bind with rc 1 `Address already in use (os error
/// 48)`, which `wait_tcp_port` cannot tell from a slow start (it waits out its
/// whole timeout). Four such collisions have been observed in `dashboard`-bin
/// runs on both sides of `fix/frps-empty-addr`; the evidence, the sampling
/// split and why they are not treated as established flakiness are recorded in
/// `TODO.md` (the `allocate_port` addendum). Closing it needs a holder that
/// survives until the child binds (or a retry on bind failure), not a wider
/// lock here.
#[allow(dead_code)]
pub fn allocate_port() -> u16 {
    // Serialize the whole probe→confirm→hand-out across processes so the
    // probe-then-drop window cannot be interleaved by another test bin. This
    // does *not* cover the window from the drop to the caller's bind — see the
    // doc comment above.
    let _lock = acquire_port_request_lock();
    for _ in 0..64 {
        let Some(port) = probe_ephemeral_port() else {
            return sandbox_fallback();
        };
        {
            let mut used = USED_PORTS.lock().unwrap();
            if !used.insert(port) {
                continue; // already handed out in this process — probe again
            }
            // Narrow the probe-then-drop window: confirm the port is still
            // free before handing it out.
            if !port_is_free(port) {
                used.remove(&port);
                continue;
            }
        }
        return port;
    }
    sandbox_fallback()
}

/// Bind to an ephemeral port and return the kernel-assigned number.
#[allow(dead_code)]
fn probe_ephemeral_port() -> Option<u16> {
    let socket = TcpSocket::new_v4().ok()?;
    socket.bind("127.0.0.1:0".parse().unwrap()).ok()?;
    socket.local_addr().ok().map(|a| a.port())
}

/// Re-bind `port` to confirm it is still available (the probe socket was
/// dropped, so a concurrent test could have taken it in between).
#[allow(dead_code)]
fn port_is_free(port: u16) -> bool {
    TcpSocket::new_v4()
        .and_then(|s| s.bind(format!("127.0.0.1:{port}").parse().unwrap()))
        .is_ok()
}

/// Sandbox fallback: return an ephemeral port (49152-65535 range).
/// Tests that need the port will bind to 0 and read the actual port.
/// Deterministic per process, so walk past ports already handed out to
/// avoid handing the same fallback port to two tests.
#[allow(dead_code)]
fn sandbox_fallback() -> u16 {
    use std::hash::{BuildHasher, Hasher};
    let mut h = std::collections::hash_map::RandomState::new().build_hasher();
    h.write_usize(std::process::id() as usize);
    let base = 49152 + (h.finish() % 16384) as u16;
    let mut used = USED_PORTS.lock().unwrap();
    for i in 0..16384u16 {
        let port = 49152 + ((base - 49152 + i) % 16384);
        if used.insert(port) {
            return port;
        }
    }
    base
}

/// Start the frp server on the given config, returning the join handle.
/// The server is ready to accept connections after a short sleep.
/// Note: tcp_mux is disabled by default for tests (raw V1 frames, no yamux).
#[allow(dead_code)]
pub async fn start_test_server(mut cfg: ServerConfig) -> (JoinHandle<()>, u16) {
    cfg.transport.tcp_mux = Some(false); // test clients use raw V1 frames
    let port = cfg.bind_port;
    let service = Service::new(cfg, None).await.expect("create service");
    let handle = tokio::spawn(async move {
        let _ = service.run().await;
    });
    // Wait until the server actually accepts connections (poll instead of a
    // fixed sleep: on slow CI the old 150ms sleep was not always enough).
    // The probe connection is accepted and closed by the server harmlessly.
    let addr: SocketAddr = format!("127.0.0.1:{}", port).parse().unwrap();
    let mut ready = false;
    for _ in 0..50 {
        if tokio::net::TcpStream::connect(addr).await.is_ok() {
            ready = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        ready,
        "test server did not start listening on {addr} in time"
    );
    (handle, port)
}

/// Start the frp server with tcp_mux (yamux) left ENABLED, returning the
/// join handle and bind port. Unlike `start_test_server`, this does NOT
/// force `cfg.transport.tcp_mux = false` — the caller must configure a
/// client that wraps its control connection in yamux to match (see
/// work_conn_auth.rs). Ready when the port accepts connections.
#[allow(dead_code)]
pub async fn start_test_server_tcpmux_on(cfg: ServerConfig) -> (JoinHandle<()>, u16) {
    let port = cfg.bind_port;
    let service = Service::new(cfg, None).await.expect("create service");
    let handle = tokio::spawn(async move {
        let _ = service.run().await;
    });
    let addr: SocketAddr = format!("127.0.0.1:{}", port).parse().unwrap();
    let mut ready = false;
    for _ in 0..50 {
        if tokio::net::TcpStream::connect(addr).await.is_ok() {
            ready = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        ready,
        "test server did not start listening on {addr} in time"
    );
    (handle, port)
}

/// Fully parametrized login: like `raw_login` plus the client identity
/// (`user`, `metas`) and `pool_count` Go frpc sends. Used by the plugin
/// tests to assert the `user` object and flat Login fields in payloads.
pub async fn raw_login_full(
    addr: SocketAddr,
    privilege_key: Option<String>,
    timestamp: Option<i64>,
    token: &str,
    user: Option<String>,
    metas: Option<std::collections::HashMap<String, String>>,
    pool_count: Option<i32>,
) -> Result<(IoStream, LoginResp), frp_core::Error> {
    let stream = tokio::net::TcpStream::connect(addr)
        .await
        .map_err(|e| frp_core::Error::Transport(format!("connect to {}: {}", addr, e).into()))?;

    let login = FrpMessage::Login(Box::new(Login {
        version: Some(frp_core::VERSION.into()),
        hostname: Some("test-host".into()),
        os: Some(std::env::consts::OS.into()),
        arch: Some(std::env::consts::ARCH.into()),
        user,
        run_id: None,
        client_id: None,
        pool_count,
        timestamp,
        privilege_key,
        metas,
        client_spec: None,
        multiplexer: None,
    }));

    let mut io = IoStream::Tcp(stream);
    write_msg_v1(&mut io, &login).await?;

    match read_msg_v1(&mut io).await? {
        FrpMessage::LoginResp(resp) => {
            // Wrap in AES-128-CFB encryption (matches server post-login)
            let enc_key = encryption::derive_key(token);
            let mut encrypted = io.into_encrypted(enc_key)?;

            // Drain initial ReqWorkConn messages sent by server after LoginResp.
            // Server sends pool_count ReqWorkConn immediately after wrapping
            // in CipherStream (matching Go frps ctl.Start()).
            let pool_count = if let FrpMessage::Login(ref l) = login {
                l.pool_count.unwrap_or(1).max(1) as usize
            } else {
                1
            };
            for _ in 0..pool_count {
                match read_msg_v1(&mut encrypted).await {
                    Ok(FrpMessage::ReqWorkConn(_)) => continue,
                    Ok(_) => break,
                    Err(_) => break,
                }
            }
            Ok((encrypted, resp))
        }
        other => Err(frp_core::Error::Protocol(
            format!(
                "expected LoginResp, got type byte {:?}",
                other.v1_type_byte()
            )
            .into(),
        )),
    }
}

/// Connect to the server and send a Login message.
/// Returns the encrypted IoStream (AES-128-CFB, matching server post-login)
/// and the LoginResp. Caller can continue sending/receiving messages.
/// `token` is the shared auth secret (empty = no auth); used for key derivation.
pub async fn raw_login(
    addr: SocketAddr,
    privilege_key: Option<String>,
    timestamp: Option<i64>,
    token: &str,
) -> Result<(IoStream, LoginResp), frp_core::Error> {
    raw_login_full(addr, privilege_key, timestamp, token, None, None, Some(1)).await
}

/// Log in with the default test token plus a client identity (user + metas),
/// generating a fresh timestamp and privilege_key (like login_with_test_token).
#[allow(dead_code)]
pub async fn login_with_identity(
    addr: SocketAddr,
    user: &str,
    metas: std::collections::HashMap<String, String>,
) -> Result<(IoStream, LoginResp), frp_core::Error> {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let key = frp_core::auth::generate_token(TEST_TOKEN, ts);
    raw_login_full(
        addr,
        Some(key),
        Some(ts),
        TEST_TOKEN,
        Some(user.into()),
        Some(metas),
        Some(1),
    )
    .await
}

/// Like raw_login but discards the stream, returning only the LoginResp.
#[allow(dead_code)]
pub async fn raw_login_resp(
    addr: SocketAddr,
    privilege_key: Option<String>,
    timestamp: Option<i64>,
    token: &str,
) -> Result<LoginResp, frp_core::Error> {
    let (_, resp) = raw_login(addr, privilege_key, timestamp, token).await?;
    Ok(resp)
}

/// Default test token used for authentication in integration tests.
#[allow(dead_code)]
pub const TEST_TOKEN: &str = "test-token";

/// Create a default `AuthServerConfig` with a test token for integration tests.
#[allow(dead_code)]
pub fn test_auth_cfg() -> frp_core::config::AuthServerConfig {
    frp_core::config::AuthServerConfig {
        method: "token".into(),
        token: TEST_TOKEN.into(),
        ..Default::default()
    }
}

/// Convenience: log in with the default test token.
/// Generates a fresh timestamp and privilege_key on every call.
#[allow(dead_code)]
pub async fn login_with_test_token(
    addr: SocketAddr,
) -> Result<(IoStream, LoginResp), frp_core::Error> {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let key = frp_core::auth::generate_token(TEST_TOKEN, ts);
    raw_login(addr, Some(key), Some(ts), TEST_TOKEN).await
}

/// Resolve the `frps` binary the way the CLI-driven tests need it (there is no
/// `CARGO_BIN_EXE_frps` for this package: `frps` is not a `frp-server`
/// dependency). Order of precedence:
///   1. `FRPS_BIN` env var (set by CI to a `--features dashboard` build)
///   2. `CARGO_BIN_EXE_frps` (set by cargo when frps *is* a dependency)
///   3. `../frps` in the workspace root (downloaded release)
///   4. `../target/{profile}/frps` (built from source)
///
/// **Build ordering.** In a `dashboard`-enabled run this resolution also
/// verifies that the resolved artifact carries the dashboard listener and
/// panics with a rebuild instruction when it does not (see
/// [`assert_frps_has_dashboard`]). The check exists because
/// `cargo test -p frps` — and any `cargo clippy` run that recompiles `frps` —
/// overwrites `target/debug/frps` with the **no-dashboard** artifact, after
/// which this lane reports `frps dashboard_port not ready` for every test with
/// nothing in the output naming the cause. Build the dashboard artifact
/// immediately before the lane, in this order:
///
/// ```text
/// cargo build -p frps --features dashboard
/// cargo test  -p frp-server --features dashboard -j 1
/// ```
///
/// The ordering, why it matters, and the failure it used to cause silently are
/// also recorded in `docs/developing.md` § Testing → “The `dashboard` lane:
/// build ordering”, which is where a local run reads them.
#[allow(dead_code)]
pub fn frps_binary() -> String {
    let bin = std::env::var("FRPS_BIN")
        .or_else(|_| std::env::var("CARGO_BIN_EXE_frps"))
        .or_else(|_| {
            let local = "../frps";
            if std::path::Path::new(local).is_file() {
                Ok(local.to_string())
            } else {
                Err(std::env::VarError::NotPresent)
            }
        })
        .unwrap_or_else(|_| {
            let profile = if cfg!(debug_assertions) {
                "debug"
            } else {
                "release"
            };
            format!("../target/{}/frps", profile)
        });
    // Only the dashboard lane requires the dashboard listener: a test target
    // compiled without the `dashboard` feature may legitimately point
    // `FRPS_BIN` at a no-dashboard build.
    #[cfg(feature = "dashboard")]
    assert_frps_has_dashboard(&bin);
    bin
}

/// The listener line `frp-server/src/dashboard.rs` emits **after** its
/// `TcpListener::bind` succeeds (`dashboard.rs:3772` plain, `:3759` TLS). It is
/// a plain byte string in a `--features dashboard` artifact and absent from a
/// no-dashboard one — measured at the head of `fix/harness-hazards` across
/// `cargo test -p frps`: `grep -ac` 1 → 0 and `strings | grep -c` 2 → 0 (the
/// two are the plain and the TLS format string, which is why this needle stops
/// before the `{}` / ` (TLS)` suffix and therefore matches both).
pub const DASHBOARD_LISTEN_MARKER: &str = "Dashboard listening on";

/// Whether the file at `path` carries [`DASHBOARD_LISTEN_MARKER`].
/// `None` when the file cannot be read at all (missing, a directory, no
/// permission): a binary that does not exist is a *different* failure whose
/// existing `Command::spawn` error (`Os { code: 2, kind: NotFound }`) is the
/// better message, so this guard stays silent there rather than blaming a
/// feature.
///
/// Cost: one `read` of the artifact plus a byte scan — no compile, no child
/// process, no network. The debug artifact is large (`target/debug/frps`
/// measured 71,033,304 bytes at this head) and a full read+scan of it measured
/// **61.45 ms** (`/tmp/scan-cost.rs`, `rustc -O`, 50 iterations, this host), so
/// the verdict is cached per process — see [`DASHBOARD_VERDICTS`].
#[allow(dead_code)]
pub fn dashboard_listener_present(path: &str) -> Option<bool> {
    let meta = std::fs::metadata(path).ok()?;
    if !meta.is_file() {
        return None;
    }
    let (len, mtime) = (meta.len(), meta.modified().ok());
    // The lock is scoped to this block on purpose: it must not be held across
    // the `std::fs::read` below (a guard held across a panic is a new failure
    // mode in a function whose whole job is to report one).
    let cached = {
        let verdicts = DASHBOARD_VERDICTS.lock().unwrap();
        verdicts.get(path).map(|c| (c.len, c.mtime, c.present))
    };
    if let Some((cached_len, cached_mtime, present)) = cached {
        if cached_len == len && cached_mtime == mtime {
            return Some(present);
        }
    }
    let bytes = std::fs::read(path).ok()?;
    let needle = DASHBOARD_LISTEN_MARKER.as_bytes();
    let present = bytes.windows(needle.len()).any(|w| w == needle);
    DASHBOARD_VERDICTS.lock().unwrap().insert(
        path.to_string(),
        CachedDashboardVerdict {
            len,
            mtime,
            present,
        },
    );
    Some(present)
}

/// Length + mtime witness for [`DASHBOARD_VERDICTS`]; a mismatch means the file
/// was replaced and the scan must run again.
struct CachedDashboardVerdict {
    len: u64,
    mtime: Option<std::time::SystemTime>,
    present: bool,
}

/// Per-process cache of [`dashboard_listener_present`] verdicts, keyed by the
/// **exact path string** the caller resolved (a relative and an absolute
/// spelling of the same file are two entries, never a collision). The dashboard
/// lane resolves one artifact once per test it spawns (~30 in `cargo test -p
/// frp-server --features dashboard -j 1`), and each uncached verdict costs a
/// 61 ms scan of the 71 MB debug artifact; caching takes that to one scan per
/// test binary instead of one per spawn.
///
/// **Residual, stated rather than hidden:** `(len, mtime)` cannot notice a swap
/// that preserves *both* — a `cp -p` or a cache restore that stamps the original
/// mtime onto an identically sized no-dashboard artifact would keep the stale
/// verdict. Cargo always writes a fresh mtime, so the swap this guard exists for
/// (`cargo test -p frps` / `cargo clippy -p frps`) does fire. Closing the
/// residual would need an inode or a content probe; an inode add is cheap but
/// does not cover a copy onto a fresh inode, and a content probe is either a
/// second full read (defeating the cache) or a hash of the same size — judged
/// over-engineering for a harness guard that already fails loudly and
/// self-explainingly in the case it is built for.
static DASHBOARD_VERDICTS: LazyLock<
    Mutex<std::collections::HashMap<String, CachedDashboardVerdict>>,
> = LazyLock::new(|| Mutex::new(std::collections::HashMap::new()));

/// Panic with a self-explaining message when `bin` is readable but does not
/// carry the dashboard listener.
///
/// This is hazard (a) of `TODO.md` (item “Two test-harness hazards”): the
/// dashboard lane resolves its `frps` through [`frps_binary`], and a
/// `cargo test -p frps` / `cargo clippy -p frps` run silently replaces that
/// artifact with the no-dashboard build. Without this check the lane then
/// fails 20/20 with `frps dashboard_port not ready: "port N not ready after
/// 15s"` and leaks the children that were waiting (hazard (b)), with nothing
/// in the output saying why. Pinned by
/// `frp-server/tests/frps_binary_guard.rs`.
#[allow(dead_code)]
pub fn assert_frps_has_dashboard(bin: &str) {
    if dashboard_listener_present(bin) == Some(false) {
        panic!(
            "resolved frps binary `{bin}` does not carry the dashboard listener \
             (`{DASHBOARD_LISTEN_MARKER}` is absent from the file), so every dashboard test \
             in this lane would fail with `frps dashboard_port not ready` after its 15s wait \
             and no hint of the cause. The usual cause is that `cargo test -p frps` or a \
             `cargo clippy` run that recompiles `frps` replaced this artifact with the \
             no-dashboard build. Fix: rebuild `frps --features dashboard`, then run this lane \
             in that order:\n  \
             cargo build -p frps --features dashboard\n  \
             cargo test -p frp-server --features dashboard -j 1\n\
             The path checked is the one this lane resolved (FRPS_BIN / CARGO_BIN_EXE_frps / \
             ../frps / ../target/<profile>/frps); see the doc comment on `frps_binary`."
        );
    }
}

/// A spawned real `frps` child whose stdout **and** stderr are redirected to a
/// file in its scratch config dir, so a test can read the listener lines it
/// emitted (which `FrpsHandle` deliberately discards). Kills the process and
/// removes the scratch dir on drop, so every spawn is bounded.
#[allow(dead_code)]
pub struct CapturedFrps {
    child: Child,
    log_path: PathBuf,
    _config_dir: tempfile::TempDir,
}

impl CapturedFrps {
    /// Spawn `frps -c <config>` with `config_content` and capture its output.
    /// Does **not** wait for the listeners: the caller polls `log()` (or the
    /// port) so the wait is bounded by the caller's own timeout.
    #[allow(dead_code)]
    pub fn start(config_content: &str) -> Self {
        let config_dir = tempfile::TempDir::new().unwrap();
        let config_path = config_dir.path().join("frps.toml");
        std::fs::write(&config_path, config_content).unwrap();
        let log_path = config_dir.path().join("frps.log");
        let log = std::fs::File::create(&log_path).unwrap();

        let child = Command::new(frps_binary())
            .arg("-c")
            .arg(&config_path)
            .env("RUST_LOG", "info")
            .stdout(Stdio::from(log.try_clone().unwrap()))
            .stderr(Stdio::from(log))
            .spawn()
            .expect("failed to start frps");

        Self {
            child,
            log_path,
            _config_dir: config_dir,
        }
    }

    /// Everything frps has written to stdout/stderr so far. `tracing` writes
    /// each line through a line-buffered writer, so a completed line is
    /// readable as soon as it is emitted.
    #[allow(dead_code)]
    pub fn log(&self) -> String {
        std::fs::read_to_string(&self.log_path).unwrap_or_default()
    }

    /// False once the child has exited, so a caller polling `log()` can fail
    /// fast on a startup error instead of waiting out its timeout.
    #[allow(dead_code)]
    pub fn running(&mut self) -> bool {
        matches!(self.child.try_wait(), Ok(None))
    }
}

impl Drop for CapturedFrps {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Handle to a running frps child process with dashboard.
/// Kills and reaps the process on drop — including on the panic path inside
/// [`FrpsHandle::start`], which is why the handle is constructed *before* the
/// first wait there.
#[allow(dead_code)]
pub struct FrpsHandle {
    child: Child,
    #[allow(dead_code)]
    pub bind_port: u16,
    pub dashboard_port: u16,
    _config_dir: tempfile::TempDir,
}

impl FrpsHandle {
    /// Start frps with the given TOML config content, waiting up to 15s per
    /// port. Returns the handle after both `bind_port` and `dashboard_port` are
    /// accepting connections and `/healthz` answers.
    #[allow(dead_code)]
    pub async fn start(config_content: &str) -> Self {
        Self::start_with_timeout(config_content, Duration::from_secs(15)).await
    }

    /// [`Self::start`] with an explicit per-wait budget. The budget is a
    /// parameter so the test that forces a wait failure (and pins that no child
    /// outlives it) does not have to sit out the production 15s first —
    /// `frp-server/tests/frps_handle_orphan.rs`. It is otherwise not used: every
    /// production call site goes through [`Self::start`].
    #[allow(dead_code)]
    pub async fn start_with_timeout(config_content: &str, wait: Duration) -> Self {
        let config_dir = tempfile::TempDir::new().unwrap();
        let config_path = config_dir.path().join("frps.toml");
        std::fs::write(&config_path, config_content).unwrap();

        // Extract ports from config
        let bind_port = config_content
            .lines()
            .find(|l| l.trim().starts_with("bind_port"))
            .and_then(|l| l.split('=').nth(1))
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(0);
        let dashboard_port = config_content
            .lines()
            .find(|l| l.trim().starts_with("port") && l.contains("web_server"))
            .or_else(|| {
                // port might be in [web_server] section, scan after web_server header
                let mut in_web = false;
                config_content.lines().find(|l| {
                    if l.trim() == "[web_server]" {
                        in_web = true;
                        return false;
                    }
                    if in_web && l.trim().starts_with("port") {
                        return true;
                    }
                    false
                })
            })
            .and_then(|l| l.split('=').nth(1))
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(0);

        // Resolve frps binary (see `frps_binary` for the precedence order).
        let frps_bin = frps_binary();

        let child = Command::new(&frps_bin)
            .arg("-c")
            .arg(&config_path)
            .env("RUST_LOG", "error")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("failed to start frps");

        // The kill-on-drop guard is constructed **before the first wait**, on
        // purpose. `Child`'s own `Drop` does not kill, and `Self::drop` is the
        // only thing that does, so an `.expect()` that panics on one of the
        // waits below while the child is still a bare local leaves a live
        // `frps` behind with `PPID 1` and its `TempDir` already removed — the
        // orphan wave measured when the dashboard lane runs against the
        // no-dashboard artifact (17 children at `PPID 1`, 20 listeners, in
        // `TODO.md`'s “Two test-harness hazards” item). Do not inline the
        // waits back above this binding.
        let handle = Self {
            child,
            bind_port,
            dashboard_port,
            _config_dir: config_dir,
        };

        // Wait for ports
        if bind_port > 0 {
            wait_tcp_port(bind_port, wait)
                .await
                .expect("frps bind_port not ready");
        }
        if dashboard_port > 0 {
            wait_tcp_port(dashboard_port, wait)
                .await
                .expect("frps dashboard_port not ready");
        }
        // Poll /healthz until the dashboard HTTP server is actually serving
        // requests (not just accepting TCP connections). Without this, CI
        // can hit IncompleteMessage when axum hasn't started processing yet.
        if dashboard_port > 0 {
            wait_http_ok(
                &format!("http://127.0.0.1:{}/healthz", dashboard_port),
                wait,
            )
            .await
            .expect("frps dashboard not healthy");
        }

        handle
    }

    #[allow(dead_code)]
    pub fn dashboard_url(&self, path: &str) -> String {
        format!("http://127.0.0.1:{}{}", self.dashboard_port, path)
    }
}

impl Drop for FrpsHandle {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Wait for a TCP port to accept connections.
pub async fn wait_tcp_port(port: u16, timeout: Duration) -> Result<(), String> {
    let start = std::time::Instant::now();
    while start.elapsed() < timeout {
        if tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .is_ok()
        {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    Err(format!("port {} not ready after {:?}", port, timeout))
}

/// Poll a URL until it returns HTTP 200 OK (or timeout).
/// Ensures the HTTP server is actually processing requests, not just
/// accepting TCP connections. Uses a throwaway client to avoid pool
/// interference with test clients.
#[allow(dead_code)]
pub async fn wait_http_ok(url: &str, timeout: Duration) -> Result<(), String> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(3))
        .build()
        .map_err(|e| format!("failed to build health-check client: {e}"))?;
    let start = std::time::Instant::now();
    while start.elapsed() < timeout {
        match client.get(url).send().await {
            Ok(resp) if resp.status().is_success() => return Ok(()),
            Ok(resp) => {
                // Server is up but returning an error status — wait for it
                // to become healthy (e.g. readiness probe during startup).
                let _ = resp.bytes().await;
            }
            Err(_) => {
                // Server not ready yet (connection refused, incomplete, etc.)
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    Err(format!("{url} not healthy after {timeout:?}"))
}
