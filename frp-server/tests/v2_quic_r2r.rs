#![cfg(feature = "quic")]
//! Rust↔Rust V2+QUIC compatibility test.
//!
//! Verifies: V2 handshake (ClientHello/ServerHello) + AEAD crypto +
//! TCP proxy tunnel over QUIC transport.
//!
//! Prerequisites:
//!   cargo build -p frps -p frpc --features quic
//!
//! Run:
//!   cargo test -p frp-server --test v2_quic_r2r -- --nocapture
//!
//! Skip if no QUIC support or no TLS certs:
//!   RUSTIC_SKIP_QUIC=1 cargo test ...

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

/// Monotonic counter so parallel test invocations never collide on the
/// shared temp directory (fixed `/tmp/frp-v2-quic-test` used to be reused
/// across runs, caching stale certs and logs).
static RUN_SEQ: AtomicU64 = AtomicU64::new(0);

/// Unique per-run temp directory under the system temp dir.
fn run_dir() -> PathBuf {
    let seq = RUN_SEQ.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!("frp-v2-quic-{}-{}", std::process::id(), seq))
}

/// Resolve binary path for a workspace member.
/// Prefers `<NAME>_BIN` env var (set by CI, e.g. `FRPS_BIN`), then
/// `CARGO_BIN_EXE_<name>` (set by Cargo when building the bin), then the
/// workspace `target/debug` dir.
fn workspace_bin(name: &str) -> PathBuf {
    let env_key = format!("{}_BIN", name.to_uppercase().replace('-', "_"));
    if let Ok(path) = std::env::var(&env_key) {
        return PathBuf::from(path);
    }
    if let Ok(path) = std::env::var(format!("CARGO_BIN_EXE_{name}")) {
        return PathBuf::from(path);
    }
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workspace_root = manifest_dir.parent().unwrap();
    workspace_root.join("target/debug").join(name)
}

/// Wait for a TCP port to be ready.
fn wait_for_port(port: u16, timeout: Duration) -> bool {
    let start = std::time::Instant::now();
    while start.elapsed() < timeout {
        if std::net::TcpStream::connect_timeout(
            &format!("127.0.0.1:{}", port).parse().unwrap(),
            Duration::from_millis(200),
        )
        .is_ok()
        {
            return true;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    false
}

/// Generate a CA → server cert chain with rcgen (no external `openssl`
/// binary, no stale on-disk cache).
///
/// Returns (server_cert_path, server_key_path, ca_cert_path). The CA cert is
/// used by frpc as `tls_ca_file`; the server cert (CN/SAN=localhost) is used
/// by frps. Certs are written as PEM under `dir`.
fn ensure_tls_certs(dir: &Path) -> (String, String, String) {
    use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair};

    // CA (self-signed, CA:TRUE)
    let mut ca_params = CertificateParams::new(Vec::<String>::default()).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params
        .key_usages
        .push(rcgen::KeyUsagePurpose::KeyCertSign);
    let ca_key = KeyPair::generate().unwrap();
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();

    // Server cert (signed by CA, CA:FALSE, SAN=localhost)
    let mut srv_params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    srv_params.is_ca = IsCa::NoCa;
    let srv_key = KeyPair::generate().unwrap();
    let srv_cert = srv_params.signed_by(&srv_key, &ca_cert, &ca_key).unwrap();

    let ca_path = dir.join("ca-cert.pem");
    let srv_cert_path = dir.join("server-cert.pem");
    let srv_key_path = dir.join("server-key.pem");
    std::fs::write(&ca_path, ca_cert.pem()).unwrap();
    std::fs::write(&srv_cert_path, srv_cert.pem()).unwrap();
    std::fs::write(&srv_key_path, srv_key.serialize_pem()).unwrap();

    (
        srv_cert_path.to_str().unwrap().to_string(),
        srv_key_path.to_str().unwrap().to_string(),
        ca_path.to_str().unwrap().to_string(),
    )
}

struct FrpsProcess {
    child: Child,
    dir: PathBuf,
}

impl FrpsProcess {
    fn start(port: u16, cert: &str, key: &str) -> Self {
        let dir = run_dir();
        std::fs::create_dir_all(&dir).ok();
        let config_path = dir.join("frps.toml");
        let log_path = dir.join("frps.log");
        let config = format!(
            r#"
bind_port = {bind_port}
quic_bind_port = {quic_port}
vhost_http_port = 0
vhost_https_port = 0
tcpmux_httpconnect_port = 0
tls_enable = true
tls_cert_file = "{cert}"
tls_key_file = "{key}"

[auth]
method = "token"
token = "test123"

[transport]
tcp_mux = false

[web_server]
port = 0
"#,
            bind_port = port,
            quic_port = port,
            cert = cert,
            key = key,
        );
        std::fs::write(&config_path, &config).unwrap();

        let log_file = std::fs::File::create(&log_path).unwrap();
        let child = Command::new(workspace_bin("frps"))
            .args(["-c", config_path.to_str().unwrap()])
            .stdout(std::process::Stdio::from(log_file.try_clone().unwrap()))
            .stderr(std::process::Stdio::from(log_file))
            .spawn()
            .expect("failed to start frps");

        if !wait_for_port(port, Duration::from_secs(10)) {
            eprintln!("--- frps log ({}) ---", log_path.display());
            if let Ok(log) = std::fs::read_to_string(&log_path) {
                eprintln!("{log}");
            }
            panic!("frps did not start");
        }

        FrpsProcess { child, dir }
    }
}

impl Drop for FrpsProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

struct FrpcProcess {
    child: Child,
    dir: PathBuf,
}

impl FrpcProcess {
    fn start(server_port: u16, ca_cert: &str, backend_port: u16, proxy_port: u16) -> Self {
        let dir = run_dir();
        std::fs::create_dir_all(&dir).ok();
        let config_path = dir.join("frpc.toml");
        let log_path = dir.join("frpc.log");
        let config = format!(
            r#"
server_addr = "127.0.0.1"
server_port = {server_port}
transport_protocol = "quic"
tls_enable = true
tls_server_name = "localhost"
tls_ca_file = "{ca_cert}"
tcp_mux = false
v2 = true
login_fail_exit = false

[auth]
method = "token"
token = "test123"

[[proxies]]
name = "tcp-test"
type = "tcp"
local_ip = "127.0.0.1"
local_port = {backend_port}
remote_port = {proxy_port}
"#,
            server_port = server_port,
            ca_cert = ca_cert,
            backend_port = backend_port,
            proxy_port = proxy_port,
        );
        std::fs::write(&config_path, &config).unwrap();

        let log_file = std::fs::File::create(&log_path).unwrap();
        let child = Command::new(workspace_bin("frpc"))
            .args(["-c", config_path.to_str().unwrap()])
            .stdout(std::process::Stdio::from(log_file.try_clone().unwrap()))
            .stderr(std::process::Stdio::from(log_file))
            .spawn()
            .expect("failed to start frpc");

        FrpcProcess { child, dir }
    }
}

impl Drop for FrpcProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

#[test]
fn v2_quic_r2r_tcp_proxy() {
    // Skip if RUSTIC_SKIP_QUIC is set.
    if std::env::var("RUSTIC_SKIP_QUIC").is_ok() {
        eprintln!("Skipping: RUSTIC_SKIP_QUIC set");
        return;
    }

    // Skip if frps/frpc binaries not built (CI test job runs cargo test without building them).
    let frps_bin = workspace_bin("frps");
    let frpc_bin = workspace_bin("frpc");
    if !frps_bin.exists() || !frpc_bin.exists() {
        eprintln!(
            "Skipping: binaries not found ({}, {}) — build with: cargo build -p frps -p frpc --features quic",
            frps_bin.display(),
            frpc_bin.display(),
        );
        return;
    }

    let dir = run_dir();
    std::fs::create_dir_all(&dir).ok();
    let (server_cert, server_key, ca_cert) = ensure_tls_certs(&dir);

    // Dynamic ports: bind an ephemeral port for the backend and probe two
    // more for frps/frpc (no hard-coded constants that collide under load).
    let backend_listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind backend");
    let backend_port = backend_listener.local_addr().unwrap().port();
    let server_port = probe_port();
    let proxy_port = probe_port();

    // Backend TCP echo server.
    std::thread::spawn(move || {
        for mut s in backend_listener.incoming().flatten() {
            let mut buf = [0u8; 1024];
            while let Ok(n) = s.read(&mut buf) {
                if n == 0 {
                    break;
                }
                s.write_all(&buf[..n]).ok();
            }
        }
    });

    // Start frps (server cert = end-entity cert signed by CA).
    let _frps = FrpsProcess::start(server_port, &server_cert, &server_key);

    // Start frpc (V2 + QUIC). Use CA cert as trust anchor.
    let _frpc = FrpcProcess::start(server_port, &ca_cert, backend_port, proxy_port);

    // Wait for proxy to be ready.
    if !wait_for_port(proxy_port, Duration::from_secs(10)) {
        eprintln!(
            "--- frpc log ({}) ---",
            _frpc.dir.join("frpc.log").display()
        );
        if let Ok(log) = std::fs::read_to_string(_frpc.dir.join("frpc.log")) {
            eprintln!("{log}");
        }
        eprintln!(
            "--- frps log ({}) ---",
            _frps.dir.join("frps.log").display()
        );
        if let Ok(log) = std::fs::read_to_string(_frps.dir.join("frps.log")) {
            eprintln!("{log}");
        }
        panic!("proxy port not ready");
    }

    // Test TCP tunnel through V2-QUIC proxy.
    let mut stream = TcpStream::connect_timeout(
        &format!("127.0.0.1:{proxy_port}").parse().unwrap(),
        Duration::from_secs(5),
    )
    .expect("connect to proxy");

    let msg = b"hello v2 quic!";
    stream.write_all(msg).expect("write");
    stream.flush().ok();

    let mut buf = [0u8; 64];
    let n = stream.read(&mut buf).expect("read");
    assert_eq!(&buf[..n], msg, "echo mismatch");

    eprintln!("\u{2713} V2+QUIC TCP proxy tunnel works");
    let _ = std::fs::remove_dir_all(&dir);
}

/// Probe a free TCP port (bind-to-0, read, drop). The caller binds shortly
/// after; the window is small and this test is single-threaded.
fn probe_port() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    l.local_addr().unwrap().port()
}
