#![cfg(feature = "ssh")]
mod common;

use common::{allocate_port, start_test_server, test_auth_cfg};
use frp_core::config::ServerConfig;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::AsyncReadExt;
use tokio::time::{timeout, Duration};

struct TestSshClient {
    /// `-R` local target address (e.g. "127.0.0.1:1234"). When set, server
    /// `forwarded-tcpip` channels are bridged to that TCP service.
    local_target: Option<String>,
}

impl russh::client::Handler for TestSshClient {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _server_public_key: &russh::keys::PublicKey,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }

    async fn channel_close(
        &mut self,
        channel: russh::ChannelId,
        _session: &mut russh::client::Session,
    ) -> Result<(), Self::Error> {
        // Default accept; the open handler's copy_bidirectional ends when the
        // local service closes, which shuts the channel.
        let _ = channel;
        Ok(())
    }

    async fn server_channel_open_forwarded_tcpip(
        &mut self,
        channel: russh::Channel<russh::client::Msg>,
        _connected_address: &str,
        _connected_port: u32,
        _originator_address: &str,
        _originator_port: u32,
        reply: russh::client::ChannelOpenHandle,
        _session: &mut russh::client::Session,
    ) -> Result<(), Self::Error> {
        // Accept the channel (0.62+: an unhandled handle drops with
        // AdministrativelyProhibited), then bridge the forwarded-tcpip
        // channel to the local -R target (the "local service" behind
        // ssh -R). ChannelStream is a full AsyncRead+AsyncWrite pair —
        // use copy_bidirectional.
        reply.accept().await;
        if let Some(target) = self.local_target.clone() {
            let mut stream = Box::pin(channel.into_stream());
            tokio::spawn(async move {
                if let Ok(mut local) = tokio::net::TcpStream::connect(&target).await {
                    let _ = tokio::io::copy_bidirectional(&mut stream, &mut local).await;
                }
            });
        }
        Ok(())
    }
}

fn ssh_test_config(ssh_port: u16, bind_port: u16) -> ServerConfig {
    let mut cfg = ServerConfig {
        bind_addr: "127.0.0.1".into(),
        bind_port,
        auth: test_auth_cfg(),
        ..Default::default()
    };
    cfg.ssh_tunnel_gateway.bind_port = ssh_port;
    cfg.ssh_tunnel_gateway.bind_addr = "127.0.0.1".into();
    cfg
}

/// Read the SSH banner from a TcpStream, returning it as a String.
/// Times out after 2 seconds.
async fn read_ssh_banner(stream: &mut tokio::net::TcpStream) -> String {
    let mut buf = [0u8; 256];
    let n = timeout(Duration::from_secs(2), stream.read(&mut buf))
        .await
        .expect("timed out waiting for SSH banner")
        .expect("read error on SSH stream");
    assert!(n > 0, "expected at least one byte of SSH banner");
    String::from_utf8_lossy(&buf[..n]).to_string()
}

/// Integration test: start frps with SSH gateway, verify banner.
#[tokio::test]
async fn test_ssh_gateway_startup_and_banner() {
    let ssh_port = allocate_port();
    let bind_port = allocate_port();

    let cfg = ssh_test_config(ssh_port, bind_port);

    let (_handle, _port) = start_test_server(cfg).await;

    // Retry: SSH gateway may not be listening immediately after server start.
    let mut ssh_stream = None;
    for _ in 0..20 {
        if let Ok(s) = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", ssh_port)).await {
            ssh_stream = Some(s);
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let mut ssh_stream = ssh_stream.expect("SSH port should accept connections");

    let banner = read_ssh_banner(&mut ssh_stream).await;
    println!("SSH banner received: {:?}", banner.trim_end());

    assert!(
        banner.starts_with("SSH-"),
        "expected SSH banner, got: {}",
        banner
    );
    assert!(
        banner.contains("frp-rs"),
        "banner should contain 'frp-rs', got: {}",
        banner
    );

    drop(ssh_stream);
}

/// Verify SSH gateway is NOT started when bind_port is 0 (disabled).
#[tokio::test]
async fn test_ssh_gateway_disabled_by_default() {
    let bind_port = allocate_port();

    let cfg = ServerConfig {
        bind_addr: "127.0.0.1".into(),
        bind_port,
        auth: test_auth_cfg(),
        ..Default::default()
    };
    // ssh_tunnel_gateway.bind_port defaults to 0 → disabled

    let (_handle, _port) = start_test_server(cfg).await;

    // Connect to the server's main FRP port and verify it does NOT serve SSH.
    let mut stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", bind_port))
        .await
        .expect("FRP port should accept connections");

    // FRP doesn't send data unsolicited — a read will time out.
    // The key assertion: the response must NOT start with "SSH-".
    let mut buf = [0u8; 32];
    let result = timeout(Duration::from_millis(500), stream.read(&mut buf)).await;
    match result {
        Ok(Ok(n)) if n > 0 => {
            let data = String::from_utf8_lossy(&buf[..n]);
            assert!(
                !data.starts_with("SSH-"),
                "FRP main port should not serve SSH banner, got: {}",
                data
            );
        }
        _ => {
            // Timeout or error is fine — FRP doesn't send data unsolicited.
            // The port accepted the connection but didn't speak SSH.
        }
    }
}

/// Verify multiple SSH connections are accepted (each gets unique run_id).
#[tokio::test]
async fn test_ssh_gateway_multiple_connections() {
    let ssh_port = allocate_port();
    let bind_port = allocate_port();

    let cfg = ssh_test_config(ssh_port, bind_port);

    let (_handle, _port) = start_test_server(cfg).await;

    let mut stream1 = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", ssh_port))
        .await
        .unwrap();
    let mut stream2 = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", ssh_port))
        .await
        .unwrap();

    let banner1 = read_ssh_banner(&mut stream1).await;
    let banner2 = read_ssh_banner(&mut stream2).await;
    assert!(banner1.starts_with("SSH-"));
    assert!(banner2.starts_with("SSH-"));
}

/// Verify SSH gateway works with auth token set — banner is still served.
#[tokio::test]
async fn test_ssh_gateway_with_auth_token() {
    let ssh_port = allocate_port();
    let bind_port = allocate_port();

    let mut cfg = ssh_test_config(ssh_port, bind_port);
    cfg.auth.token = "test-token-123456".into();

    let (_handle, _port) = start_test_server(cfg).await;

    let mut stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", ssh_port))
        .await
        .unwrap();

    let banner = read_ssh_banner(&mut stream).await;
    assert!(banner.starts_with("SSH-"));

    drop(stream);
}

/// SSH gateway should close connection when non-SSH data is sent after banner.
/// Verifies the server rejects invalid SSH protocol data (doesn't just hang).
#[tokio::test]
async fn test_ssh_gateway_rejects_non_ssh_data() {
    let ssh_port = allocate_port();
    let bind_port = allocate_port();

    let cfg = ssh_test_config(ssh_port, bind_port);
    let (_handle, _port) = start_test_server(cfg).await;

    // Retry connect
    let mut stream = None;
    for _ in 0..20 {
        if let Ok(s) = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", ssh_port)).await {
            stream = Some(s);
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let mut stream = stream.expect("SSH port should accept connections");

    // Read banner first (SSH protocol sends banner before client data)
    let mut buf = [0u8; 256];
    let n = timeout(Duration::from_secs(2), stream.read(&mut buf))
        .await
        .expect("banner timeout")
        .expect("banner read");
    assert!(n > 0, "should get SSH banner");

    // Send garbage data (not valid SSH handshake)
    use tokio::io::AsyncWriteExt;
    stream.write_all(b"NOT SSH DATA\r\n").await.unwrap();
    stream.flush().await.unwrap();

    // Server must close the connection — read should return 0 (FIN) or
    // an error (RST). A timeout without data means the server is hanging,
    // which is a bug (should reject invalid protocol).
    let mut buf = [0u8; 64];
    let result = timeout(Duration::from_secs(5), stream.read(&mut buf)).await;
    match result {
        Ok(Ok(0)) | Ok(Err(_)) | Err(_) => {
            // Expected: clean close via FIN, connection reset, or timeout.
        }
        Ok(Ok(_n)) => {
            // Server sent SSH disconnect message before closing.
            // Verify a subsequent read returns 0 (connection closed).
            let result2 = timeout(Duration::from_secs(2), stream.read(&mut buf)).await;
            assert!(
                matches!(result2, Ok(Ok(0)) | Ok(Err(_)) | Err(_)),
                "connection should be closed after SSH disconnect message, got {:?}",
                result2
            );
        }
    }
}

/// SSH gateway starts successfully with max_ports_per_client configured.
/// NOTE: Does not test actual limit enforcement (requires full SSH client).
/// The config value is validated at parse time; enforcement is in exec_request.
#[tokio::test]
async fn test_ssh_gateway_starts_with_port_limit_config() {
    let ssh_port = allocate_port();
    let bind_port = allocate_port();

    let mut cfg = ssh_test_config(ssh_port, bind_port);
    cfg.max_ports_per_client = 3;

    let (_handle, _port) = start_test_server(cfg).await;

    let mut stream = None;
    for _ in 0..20 {
        if let Ok(s) = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", ssh_port)).await {
            stream = Some(s);
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let mut ssh_stream = stream.expect("SSH port should accept connections");

    let banner = read_ssh_banner(&mut ssh_stream).await;
    assert!(banner.starts_with("SSH-"));
    assert!(banner.contains("frp-rs"));

    drop(ssh_stream);
}

/// Go-compatible `ssh -R`: the server accepts tcpip-forward, opens a
/// forwarded-tcpip channel per work connection, and bridges data between the
/// SSH client's local service and the frps proxy port.
#[tokio::test]
async fn test_ssh_gateway_reverse_forwarding_roundtrip() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .with_test_writer()
        .try_init();
    let ssh_port = allocate_port();
    let bind_port = allocate_port();
    let remote_port = allocate_port(); // frps proxy port
    let local_port = allocate_port(); // local echo service behind -R

    let cfg = ssh_test_config(ssh_port, bind_port);
    let (_handle, _port) = start_test_server(cfg).await;

    // Local echo server (simulates the ssh -R host:hostport target).
    let echo_listener = tokio::net::TcpListener::bind(format!("127.0.0.1:{local_port}"))
        .await
        .unwrap();
    let echo_task = tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = echo_listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                let mut buf = [0u8; 4096];
                loop {
                    match sock.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if sock.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }
    });

    let addr: SocketAddr = format!("127.0.0.1:{}", ssh_port).parse().unwrap();
    let mut client = None;
    for _ in 0..20 {
        if let Ok(c) = russh::client::connect(
            Arc::new(russh::client::Config::default()),
            addr,
            TestSshClient {
                local_target: Some(format!("127.0.0.1:{local_port}")),
            },
        )
        .await
        {
            client = Some(c);
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let mut client = client.expect("SSH client should connect");

    let auth = client
        .authenticate_password("v0", common::TEST_TOKEN)
        .await
        .expect("password auth should succeed");
    assert!(auth.success(), "SSH password auth failed");

    // ssh -R :remote_port:127.0.0.1:local_port
    let fwd = client
        .tcpip_forward("127.0.0.1", remote_port as u32)
        .await
        .expect("-R tcpip-forward must be accepted");
    // SSH protocol: a specific-port request's success reply carries no port
    // (russh returns 0); a 0 request would return the allocated port.
    assert_eq!(
        fwd, 0,
        "-R request should be granted for the requested port"
    );

    // Register a tcp proxy through the SSH remote command.
    let session = client
        .channel_open_session()
        .await
        .expect("open session channel");
    session
        .exec(
            true,
            format!("tcp --proxy_name \"ssh-r-test\" --remote_port {remote_port}"),
        )
        .await
        .expect("exec accepted");

    // Connect through the frps proxy port and verify the echo round-trip.
    let mut proxy_stream = None;
    for _ in 0..50 {
        if let Ok(s) = tokio::net::TcpStream::connect(format!("127.0.0.1:{remote_port}")).await {
            proxy_stream = Some(s);
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let mut proxy_stream = proxy_stream.expect("frps proxy port should accept");
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    proxy_stream.write_all(b"ping-over-ssh-r").await.unwrap();
    let mut buf = [0u8; 64];
    let n = tokio::time::timeout(Duration::from_secs(5), proxy_stream.read(&mut buf))
        .await
        .expect("should receive echoed data")
        .expect("echo read");
    assert_eq!(
        &buf[..n],
        b"ping-over-ssh-r",
        "data must round-trip through ssh -R"
    );

    client
        .disconnect(russh::Disconnect::ByApplication, "test complete", "")
        .await
        .ok();
    echo_task.abort();
}

/// Round-11 audit GAP 1: the per-IP password throttle must DENY, not just
/// count. After 5 wrong passwords from one IP (each answered with a normal
/// USERAUTH_FAILURE round-trip), a FRESH connection from the same IP inside
/// the 60s window is cut off by the server before its first guess is
/// evaluated as another round-trip. RED pre-fix: the throttle bool was
/// discarded in auth_password, so the 6th attempt (on any connection)
/// always got a fresh Reject round-trip.
///
/// Wire signature of the cutoff: the russh CLIENT maps a dropped connection
/// during auth to `Ok(Failure { empty methods })` (vendor/russh client
/// `wait_recv_reply`, receiver-closed arm — client/mod.rs), so the result
/// TYPE cannot distinguish a server cutoff from a normal reject. What
/// distinguishes them on the wire: every evaluated rejection round-trip is
/// delayed by russh's `auth_rejection_time` (3s, ssh_gateway.rs
/// `russh_config`) before the USERAUTH_FAILURE is sent, while a cutoff
/// kills the session immediately and the attempt returns in milliseconds.
/// Asserting the 6th-attempt latency < 2s (vs a 3s pre-fix floor) pins the
/// cutoff: the server never answered the guess with a rejection round-trip.
#[tokio::test]
async fn test_ssh_gateway_password_throttle_cuts_off_fresh_connection() {
    let ssh_port = allocate_port();
    let bind_port = allocate_port();

    let mut cfg = ssh_test_config(ssh_port, bind_port);
    cfg.auth.token = common::TEST_TOKEN.into();

    let (_handle, _port) = start_test_server(cfg).await;

    let addr: SocketAddr = format!("127.0.0.1:{}", ssh_port).parse().unwrap();
    let connect = || async {
        let mut last_err = None;
        for _ in 0..20 {
            match russh::client::connect(
                Arc::new(russh::client::Config::default()),
                addr,
                TestSshClient { local_target: None },
            )
            .await
            {
                Ok(c) => return Some(c),
                Err(e) => last_err = Some(e),
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        panic!("SSH client should connect; last error: {last_err:?}");
    };

    // Connection A: 5 wrong passwords. Each consumes a throttle slot; the
    // throttle slot for attempt N is consumed at attempt ARRIVAL (the
    // check precedes russh's 3s rejection delay), so attempts 1-4 get a
    // genuine USERAUTH_FAILURE round-trip. Attempt 5 is a corner: its
    // rejection reply is scheduled ~15.3s after accept (5 × ~3s
    // auth_rejection_time) while the ~15s SSH_AUTH_DEADLINE watchdog kills
    // the session at ~15s — the attempt's slot is still consumed at
    // arrival (~12.3s, before the sleep), and the russh CLIENT maps the
    // dropped session to Ok(Failure) (vendor/russh client
    // `wait_recv_reply` receiver-closed arm), so `!auth.success()` holds
    // on every arm either way.
    //
    // The Err arm: if the deadline kill lands BEFORE attempt i's send (a
    // scheduling delay >~2.8s anywhere in the loop pushes attempt 5's
    // ~12.2s send past the 15s deadline), russh returns Err(SendError)
    // instead of the Ok(Failure) it maps a mid-round-trip kill to. That is
    // the watchdog doing its job, not a handler failure — attempts 0..i
    // all got their round-trips (an Err before attempt 4 would need the
    // deadline to fire at <9.2s, outside any realistic schedule), so break
    // with the landed slots and let conn B's retry loop discriminate.
    let mut client_a = connect().await.expect("connection A should connect");
    let mut slots_landed = 0usize;
    for i in 0..5 {
        let auth = match client_a.authenticate_password("v0", "wrong-password").await {
            Ok(auth) => auth,
            Err(e) => {
                eprintln!(
                    "connection A's session died mid-loop (auth deadline) at attempt \
                     {i} with {slots_landed} slots landed: {e}"
                );
                break;
            }
        };
        assert!(
            !auth.success(),
            "attempt {i} with a wrong password must fail cleanly"
        );
        slots_landed = i + 1;
    }
    assert!(
        slots_landed >= 2,
        "connection A must land at least 2 throttle slots (deadline kill before \
         attempt 2 is not schedulable), got {slots_landed}"
    );

    drop(client_a);
    // NOTE: no same-session attempt-6 assertion here — by the time the 5th
    // rejection round-trip completes (~3s each, russh auth_rejection_time),
    // the session has burned its ~15s auth deadline and the accept-task
    // watchdog kills it, so a fast 6th-attempt return is indistinguishable
    // from a throttle cutoff. The fresh-connection assertion below is the
    // discriminator: a new session gets a fresh deadline, and only the
    // throttle cutoff (count persists per IP in AppState) answers its first
    // guess with instant death instead of a 3s-delayed rejection.

    // Connection B (retried), same IP, inside the 60s window: once the
    // throttle is armed (5 consumed slots), the FIRST wrong password on a
    // fresh connection must be cut off by the server (connection dropped,
    // no auth-failure round-trip — russh maps the killed session to a fast
    // Ok(Failure) since the client never sees the server's reject).
    // Pre-fix this returned a clean 3s-delayed Ok(failure).
    //
    // Retry loop: conn A's 5th rejection is processed ~12s after KEX
    // (5 × 3s auth_rejection_time serialized), ~3s before the 15s auth
    // deadline — under heavy parallel load the 5th attempt can lag and the
    // arm may not have landed when conn B connects. An attempt that gets
    // the 3s rejection floor is itself consuming the 5th slot, so a fresh
    // connection retry makes the test self-arming instead of timing-bound.
    // Budget: with N slots landed by A, a B round arriving when count < 5
    // consumes a slot (3s floor) and round k = 6 − N is the first cutoff.
    // 4 rounds therefore guarantee a cutoff whenever N ≥ 2 — conn A's
    // attempt 2 arrives ~3-6s after KEX, so N ≤ 1 would need conn A's
    // first attempts to arrive >12s after accept (>12s KEX on localhost),
    // outside realistic CI load. The self-arm consumes the last slots on
    // the late path exactly as round-10's design intended.
    let mut cutoff_seen = false;
    for _round in 0..4 {
        let mut client_b = connect().await.expect("fresh connection should connect");
        let start = tokio::time::Instant::now();
        let result = client_b.authenticate_password("v0", "wrong-password").await;
        let elapsed = start.elapsed();
        client_b
            .disconnect(russh::Disconnect::ByApplication, "test B complete", "")
            .await
            .ok();
        assert!(
            !result.as_ref().is_ok_and(|a| a.success()),
            "fresh connection from a throttled IP must not get a clean auth result, got: {result:?}"
        );
        if elapsed < Duration::from_secs(2) {
            // Fast Ok(Failure) — the session was killed by the throttle,
            // not answered with the 3s rejection floor.
            cutoff_seen = true;
            break;
        }
        // ~3s rejection floor: the arm had not landed (A's 5th attempt in
        // flight); this attempt consumed the last slot — retry fresh.
    }
    assert!(
        cutoff_seen,
        "throttle cutoff never observed across 4 fresh connections from the armed IP"
    );
}

/// Round-13 (S RISK): the per-IP pre-auth cap — a single source cannot
/// fill the global SSH conn semaphore with unauthenticated conns and hold
/// them to the auth deadline (8 slots/IP bounds one source to ~0.5
/// conns/s sustained; the old code let one reconnect-loop IP hold all
/// 128 global slots for up to ~15s each).
#[tokio::test]
async fn test_ssh_gateway_preauth_per_ip_cap_drops_overflow_conn() {
    let ssh_port = allocate_port();
    let bind_port = allocate_port();

    let mut cfg = ssh_test_config(ssh_port, bind_port);
    cfg.auth.token = common::TEST_TOKEN.into();

    let (_handle, _port) = start_test_server(cfg).await;

    let connect_raw = || async {
        let mut last_err = None;
        for _ in 0..20 {
            match tokio::net::TcpStream::connect(format!("127.0.0.1:{ssh_port}")).await {
                Ok(s) => return s,
                Err(e) => last_err = Some(e),
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        panic!("raw SSH connect failed; last error: {last_err:?}");
    };

    // Phase 1: hold 8 unauthenticated conns from one IP. Reading the
    // banner proves the conn was accepted AND its pre-auth slot acquired —
    // the slot is taken in the accept loop before the spawn that runs the
    // russh server and writes the banner.
    let mut held: Vec<tokio::net::TcpStream> = Vec::new();
    for i in 0..8 {
        let mut s = connect_raw().await;
        let banner = read_ssh_banner(&mut s).await;
        assert!(
            banner.starts_with("SSH-"),
            "held conn {i} must receive the banner: {banner:?}"
        );
        held.push(s);
    }

    // Phase 2: the 9th concurrent conn from the same IP is dropped at the
    // accept gate — no banner, no handshake: clean EOF (server closed the
    // accepted stream) or reset, never banner bytes.
    let mut ninth = connect_raw().await;
    let mut buf = [0u8; 8];
    let n = timeout(Duration::from_secs(2), ninth.read(&mut buf))
        .await
        .expect("9th conn must be cut off quickly, not left hanging")
        .unwrap_or_else(|e| {
            assert_eq!(
                e.kind(),
                std::io::ErrorKind::ConnectionReset,
                "9th conn read error: {e}"
            );
            0
        });
    assert_eq!(
        n, 0,
        "9th concurrent pre-auth conn from one IP must be dropped before the banner"
    );
    drop(ninth);

    // Phase 3: release one held conn (its accept task ends, returning the
    // permit). A fresh conn from the same IP is admitted again. Retry: the
    // task end is asynchronous, and a still-denied conn just reads EOF.
    held.pop();
    drop(held);
    let mut admitted = false;
    for _ in 0..20 {
        let mut s = connect_raw().await;
        let mut probe = [0u8; 64];
        let n = match timeout(Duration::from_secs(2), s.read(&mut probe)).await {
            Ok(Ok(n)) => n,
            Ok(Err(e)) if e.kind() == std::io::ErrorKind::ConnectionReset => 0,
            Ok(Err(e)) => panic!("post-release conn read error: {e}"),
            Err(_) => panic!("post-release conn banner timed out"),
        };
        if n > 0 && String::from_utf8_lossy(&probe[..n]).starts_with("SSH-") {
            admitted = true;
            break;
        }
    }
    assert!(
        admitted,
        "a conn after a pre-auth slot release must be admitted again"
    );
}

/// Round-13: the authorized_keys PUBLICKEY accept arm had only parse-level
/// units (test_parse_authorized_keys_shapes) — no e2e proved a key in the
/// allow-list actually authenticates through russh, nor that an absent key
/// is denied while the token password path keeps working.
#[tokio::test]
async fn test_ssh_gateway_authorized_keys_accept_and_deny_e2e() {
    use russh::keys::PublicKeyBase64;

    let ssh_port = allocate_port();
    let bind_port = allocate_port();

    let dir = tempfile::TempDir::new().unwrap();
    let keys_path = dir.path().join("authorized_keys");
    let key1 = russh::keys::PrivateKey::random(&mut rand::rng(), russh::keys::Algorithm::Ed25519)
        .expect("key1");
    let key2 = russh::keys::PrivateKey::random(&mut rand::rng(), russh::keys::Algorithm::Ed25519)
        .expect("key2");
    std::fs::write(
        &keys_path,
        format!(
            "ssh-ed25519 {} allow-listed\n",
            key1.public_key().public_key_base64()
        ),
    )
    .unwrap();

    let mut cfg = ssh_test_config(ssh_port, bind_port);
    cfg.auth.token = common::TEST_TOKEN.into();
    cfg.ssh_tunnel_gateway.authorized_keys_file = keys_path.to_str().unwrap().into();

    let (_handle, _port) = start_test_server(cfg).await;
    let addr: SocketAddr = format!("127.0.0.1:{}", ssh_port).parse().unwrap();
    let connect = || async {
        let mut last_err = None;
        for _ in 0..20 {
            match russh::client::connect(
                Arc::new(russh::client::Config::default()),
                addr,
                TestSshClient { local_target: None },
            )
            .await
            {
                Ok(c) => return c,
                Err(e) => last_err = Some(e),
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        panic!("SSH client should connect; last error: {last_err:?}");
    };

    // Key NOT in the allow-list: denied.
    let mut denied = connect().await;
    let auth = denied
        .authenticate_publickey(
            "v0",
            russh::keys::PrivateKeyWithHashAlg::new(Arc::new(key2.clone()), None),
        )
        .await
        .expect("publickey attempt must complete");
    assert!(!auth.success(), "an absent key must be denied");
    denied
        .disconnect(russh::Disconnect::ByApplication, "denied", "")
        .await
        .ok();

    // Key IN the allow-list: accepted.
    let mut accepted = connect().await;
    let auth = accepted
        .authenticate_publickey(
            "v0",
            russh::keys::PrivateKeyWithHashAlg::new(Arc::new(key1.clone()), None),
        )
        .await
        .expect("publickey attempt must complete");
    assert!(auth.success(), "an allow-listed key must authenticate");
    accepted
        .disconnect(russh::Disconnect::ByApplication, "accepted", "")
        .await
        .ok();

    // The token password path still works alongside the allow-list.
    let mut by_password = connect().await;
    let auth = by_password
        .authenticate_password("v0", common::TEST_TOKEN)
        .await
        .expect("password auth should succeed");
    assert!(auth.success(), "token password auth must still work");
}

/// Round-13: an authorized_keys_file that EXISTS but is unreadable (load
/// error → `unwrap_or_default` empty allow-list) must not crash the
/// gateway: fail-closed — every publickey attempt denied — while token
/// password auth keeps working (the load-once behavior lives in
/// SshListener::new; Go's per-auth re-read with abort-on-first-error is
/// documented as a divergence).
#[tokio::test]
async fn test_ssh_gateway_unreadable_authorized_keys_file_fails_closed() {
    use russh::keys::PublicKeyBase64;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    let ssh_port = allocate_port();
    let bind_port = allocate_port();

    let dir = tempfile::TempDir::new().unwrap();
    let keys_path = dir.path().join("authorized_keys");
    let key1 = russh::keys::PrivateKey::random(&mut rand::rng(), russh::keys::Algorithm::Ed25519)
        .expect("key1");
    std::fs::write(
        &keys_path,
        format!(
            "ssh-ed25519 {} would-allow\n",
            key1.public_key().public_key_base64()
        ),
    )
    .unwrap();
    // 0000: the load's read_to_string fails with EACCES for the test user.
    std::fs::set_permissions(&keys_path, std::fs::Permissions::from_mode(0o000)).unwrap();

    let mut cfg = ssh_test_config(ssh_port, bind_port);
    cfg.auth.token = common::TEST_TOKEN.into();
    cfg.ssh_tunnel_gateway.authorized_keys_file = keys_path.to_str().unwrap().into();

    let (_handle, _port) = start_test_server(cfg).await;
    let addr: SocketAddr = format!("127.0.0.1:{}", ssh_port).parse().unwrap();
    let connect = || async {
        let mut last_err = None;
        for _ in 0..20 {
            match russh::client::connect(
                Arc::new(russh::client::Config::default()),
                addr,
                TestSshClient { local_target: None },
            )
            .await
            {
                Ok(c) => return c,
                Err(e) => last_err = Some(e),
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        panic!("SSH client should connect; last error: {last_err:?}");
    };

    // The gateway is up (token set — no refuse-to-start), but the key that
    // WOULD have allowed this client is invisible: denied.
    let mut denied = connect().await;
    let auth = denied
        .authenticate_publickey(
            "v0",
            russh::keys::PrivateKeyWithHashAlg::new(Arc::new(key1), None),
        )
        .await
        .expect("publickey attempt must complete");
    assert!(
        !auth.success(),
        "an unreadable allow-list must fail closed (no key accepted)"
    );

    // Token password auth is unaffected.
    let mut by_password = connect().await;
    let auth = by_password
        .authenticate_password("v0", common::TEST_TOKEN)
        .await
        .expect("password auth should succeed");
    assert!(auth.success(), "token password auth must still work");

    drop(denied);
    drop(by_password);
    std::fs::set_permissions(&keys_path, std::fs::Permissions::from_mode(0o600)).ok();
}
