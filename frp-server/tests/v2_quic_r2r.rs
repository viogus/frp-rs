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
use std::path::PathBuf;
use std::process::{Child, Command};
use std::time::Duration;

/// Resolve binary path relative to the workspace root.
/// `env!("CARGO_MANIFEST_DIR")` is `frp-server/`; the workspace root is one level up.
fn workspace_bin(name: &str) -> PathBuf {
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

/// Generate self-signed TLS cert/key for QUIC test.
/// Returns (server_cert_path, server_key_path, ca_cert_path).
///
/// Generates a proper CA → server cert chain:
/// - CA cert (self-signed, CA:TRUE) — used by frpc as tls_ca_file
/// - Server cert (signed by CA, CA:FALSE, CN=localhost) — used by frps
fn ensure_tls_certs() -> (String, String, String) {
    let dir = std::env::temp_dir().join("frp-v2-quic-test");
    std::fs::create_dir_all(&dir).ok();
    let ca_key = dir.join("ca-key.pem");
    let ca_cert = dir.join("ca-cert.pem");
    let srv_key = dir.join("server-key.pem");
    let srv_cert = dir.join("server-cert.pem");

    let ca_cert_str = ca_cert.to_str().unwrap().to_string();
    let srv_cert_str = srv_cert.to_str().unwrap().to_string();
    let srv_key_str = srv_key.to_str().unwrap().to_string();

    if ca_cert.exists() && srv_cert.exists() && srv_key.exists() {
        return (srv_cert_str, srv_key_str, ca_cert_str);
    }

    // Generate CA key + self-signed CA cert
    let output = Command::new("openssl")
        .args([
            "req", "-x509", "-newkey", "rsa:2048", "-keyout",
            ca_key.to_str().unwrap(), "-out", ca_cert.to_str().unwrap(),
            "-days", "1", "-nodes",
            "-subj", "/CN=frp-test-ca",
            "-addext", "basicConstraints=critical,CA:TRUE",
        ])
        .output()
        .expect("openssl not found — install openssl or set RUSTIC_SKIP_QUIC=1");
    assert!(output.status.success(), "openssl CA cert gen failed: {:?}", output);

    // Generate server key + CSR
    let output = Command::new("openssl")
        .args([
            "req", "-newkey", "rsa:2048", "-keyout",
            srv_key.to_str().unwrap(), "-out", dir.join("server.csr").to_str().unwrap(),
            "-days", "1", "-nodes",
            "-subj", "/CN=localhost",
        ])
        .output()
        .expect("openssl not found");
    assert!(output.status.success(), "openssl server key gen failed: {:?}", output);

    // Write extfile with SAN for the server cert
    let ext_path = dir.join("server.ext");
    std::fs::write(&ext_path, "subjectAltName=DNS:localhost\n").unwrap();

    // Sign server CSR with CA (including SAN extension)
    let output = Command::new("openssl")
        .args([
            "x509", "-req",
            "-in", dir.join("server.csr").to_str().unwrap(),
            "-CA", ca_cert.to_str().unwrap(),
            "-CAkey", ca_key.to_str().unwrap(),
            "-CAcreateserial",
            "-out", srv_cert.to_str().unwrap(),
            "-days", "1",
            "-extfile", ext_path.to_str().unwrap(),
        ])
        .output()
        .expect("openssl not found");
    assert!(output.status.success(), "openssl server cert sign failed: {:?}", output);

    (srv_cert_str, srv_key_str, ca_cert_str)
}

struct FrpsProcess {
    child: Child,
}

impl FrpsProcess {
    fn start(port: u16, cert: &str, key: &str) -> Self {
        let dir = std::env::temp_dir().join("frp-v2-quic-test");
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

        FrpsProcess { child }
    }
}

impl Drop for FrpsProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

struct FrpcProcess {
    child: Child,
}

impl FrpcProcess {
    fn start(server_port: u16, ca_cert: &str, backend_port: u16, proxy_port: u16) -> Self {
        let dir = std::env::temp_dir().join("frp-v2-quic-test");
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

        FrpcProcess { child }
    }
}

impl Drop for FrpcProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

const SERVER_PORT: u16 = 17890;
const PROXY_PORT: u16 = 17891;
const BACKEND_PORT: u16 = 17892;

#[test]
fn v2_quic_r2r_tcp_proxy() {
    // Skip if RUSTIC_SKIP_QUIC is set.
    if std::env::var("RUSTIC_SKIP_QUIC").is_ok() {
        eprintln!("Skipping: RUSTIC_SKIP_QUIC set");
        return;
    }

    let (server_cert, server_key, ca_cert) = ensure_tls_certs();

    // Start backend TCP echo server.
    let backend = std::net::TcpListener::bind(format!("127.0.0.1:{}", BACKEND_PORT))
        .expect("bind backend");
    std::thread::spawn(move || {
        for stream in backend.incoming() {
            if let Ok(mut s) = stream {
                let mut buf = [0u8; 1024];
                while let Ok(n) = s.read(&mut buf) {
                    if n == 0 { break; }
                    s.write_all(&buf[..n]).ok();
                }
            }
        }
    });

    // Start frps (server cert = end-entity cert signed by CA).
    let _frps = FrpsProcess::start(SERVER_PORT, &server_cert, &server_key);

    // Start frpc (V2 + QUIC). Use CA cert as trust anchor.
    let _frpc = FrpcProcess::start(SERVER_PORT, &ca_cert, BACKEND_PORT, PROXY_PORT);

    // Wait for proxy to be ready.
    if !wait_for_port(PROXY_PORT, Duration::from_secs(10)) {
        let dir = std::env::temp_dir().join("frp-v2-quic-test");
        let frps_log = dir.join("frps.log");
        let frpc_log = dir.join("frpc.log");
        eprintln!("--- frps log ({}) ---", frps_log.display());
        if let Ok(log) = std::fs::read_to_string(&frps_log) {
            eprintln!("{log}");
        }
        eprintln!("--- frpc log ({}) ---", frpc_log.display());
        if let Ok(log) = std::fs::read_to_string(&frpc_log) {
            eprintln!("{log}");
        }
        panic!("proxy port not ready");
    }

    // Test TCP tunnel through V2-QUIC proxy.
    let mut stream = TcpStream::connect_timeout(
        &format!("127.0.0.1:{}", PROXY_PORT).parse().unwrap(),
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
}
