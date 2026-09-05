use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::debug;

use frp_core::config::PluginConfig;

use super::{serve_plugin, PluginHandle};

use crate::util::opt_if_empty;
use frp_core::auth::constant_time_eq;

// ---------------------------------------------------------------
// SOCKS5 plugin (RFC 1928)
// ---------------------------------------------------------------

const SOCKS5_VERSION: u8 = 0x05;
/// Bound the whole SOCKS5 handshake: a peer that connects but never completes
/// it (greeting, auth-method list, user/pass, CONNECT request) must not pin
/// the handler task + fd + bridge forever. One absolute deadline covers every
/// handshake read — total budget 60s from the first byte. The data-relay
/// phase after CONNECT is deliberately unbounded.
const SOCKS5_HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);
const AUTH_NO_AUTH: u8 = 0x00;
const AUTH_USER_PASS: u8 = 0x02;
const AUTH_NO_ACCEPTABLE: u8 = 0xFF;
const CMD_CONNECT: u8 = 0x01;
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;
const REP_SUCCEEDED: u8 = 0x00;
const REP_HOST_UNREACHABLE: u8 = 0x04;
const REP_CMD_NOT_SUPPORTED: u8 = 0x07;
const REP_ADDR_NOT_SUPPORTED: u8 = 0x08;
const USERPASS_VERSION: u8 = 0x01;
const USERPASS_OK: u8 = 0x00;
const USERPASS_FAIL: u8 = 0x01;

/// Start a SOCKS5 proxy plugin server.
///
/// Supports CONNECT command only (TCP tunnel).
/// Optional username/password auth via PluginConfig `username` / `password`.
pub async fn start_socks5_proxy(cfg: &PluginConfig) -> Result<PluginHandle, frp_core::Error> {
    let user = opt_if_empty!(cfg.username);
    let pass = opt_if_empty!(cfg.password);
    serve_plugin("socks5", (user, pass), |stream, peer, (u, p)| async move {
        if let Err(e) = handle_socks5_conn(stream, u, p).await {
            debug!(%peer, error = %e, "socks5: {peer} error: {e}");
        }
    })
    .await
}

async fn handle_socks5_conn(
    mut client: TcpStream,
    user: Option<String>,
    pass: Option<String>,
) -> Result<(), String> {
    let mut buf = [0u8; 512];

    // One absolute deadline anchors the whole handshake — greeting, auth
    // methods, user/pass, CONNECT request. A peer that connects but stalls
    // mid-handshake would otherwise pin the handler task + fd (and the
    // work-conn bridge) forever. The relay phase after CONNECT stays
    // unbounded: the bridge copies for as long as the tunnel lives.
    let deadline = tokio::time::Instant::now() + SOCKS5_HANDSHAKE_TIMEOUT;

    // Step 1: Auth method negotiation.
    match tokio::time::timeout_at(deadline, client.read_exact(&mut buf[..2])).await {
        Ok(Ok(_n)) => {}
        Ok(Err(e)) => return Err(format!("read greeting: {e}")),
        Err(_elapsed) => return Err("socks5 greeting timed out".into()),
    }
    let ver = buf[0];
    let nmethods = buf[1] as usize;
    if ver != SOCKS5_VERSION {
        return Err(format!("bad socks version: {ver}"));
    }
    if nmethods == 0 {
        return Err("no auth methods offered".into());
    }
    tokio::time::timeout_at(deadline, client.read_exact(&mut buf[..nmethods]))
        .await
        .map_err(|_| "socks5 handshake timed out".to_string())?
        .map_err(|e| format!("read methods: {e}"))?;
    let methods = &buf[..nmethods];

    // Go parity (pkg/plugin/client/socks5.go:44-46): auth is armed by
    // OR — `Username != "" || Password != ""` — so a PARTIAL config
    // (username without password, or vice versa) must still enforce
    // credentials instead of silently falling back to NO_AUTH (audit
    // finding M8: AND here made the tunnel fail open). The empty half is
    // enforced as the literal empty string, matching Go's
    // StaticCredentials(map[string]string{user: pass}).
    let use_auth = user.is_some() || pass.is_some();

    let chosen_method = if use_auth && methods.contains(&AUTH_USER_PASS) {
        AUTH_USER_PASS
    } else if !use_auth && methods.contains(&AUTH_NO_AUTH) {
        AUTH_NO_AUTH
    } else {
        client
            .write_all(&[SOCKS5_VERSION, AUTH_NO_ACCEPTABLE])
            .await
            .map_err(|e| format!("write auth reject: {e}"))?;
        return Err("no acceptable auth method".into());
    };

    client
        .write_all(&[SOCKS5_VERSION, chosen_method])
        .await
        .map_err(|e| format!("write auth reply: {e}"))?;

    // Step 2: Username/password auth (if selected)
    if chosen_method == AUTH_USER_PASS {
        // Partial config reaches here with one empty half (OR-arm, Go
        // parity) — compare against the literal empty string.
        let u = user.as_deref().unwrap_or("");
        let p = pass.as_deref().unwrap_or("");

        tokio::time::timeout_at(deadline, client.read_exact(&mut buf[..2]))
            .await
            .map_err(|_| "socks5 handshake timed out".to_string())?
            .map_err(|e| format!("read user/pass ver: {e}"))?;
        if buf[0] != USERPASS_VERSION {
            client
                .write_all(&[USERPASS_VERSION, USERPASS_FAIL])
                .await
                .map_err(|e| format!("write auth fail: {e}"))?;
            return Err(format!("bad user/pass version: {}", buf[0]));
        }
        let ulen = buf[1] as usize;
        if ulen > 255 {
            return Err("username too long".into());
        }
        tokio::time::timeout_at(deadline, client.read_exact(&mut buf[..ulen]))
            .await
            .map_err(|_| "socks5 handshake timed out".to_string())?
            .map_err(|e| format!("read username: {e}"))?;
        let client_user = std::str::from_utf8(&buf[..ulen])
            .map_err(|e| format!("username utf8: {e}"))?
            .to_string();

        tokio::time::timeout_at(deadline, client.read_exact(&mut buf[..1]))
            .await
            .map_err(|_| "socks5 handshake timed out".to_string())?
            .map_err(|e| format!("read plen: {e}"))?;
        let plen = buf[0] as usize;
        if plen > 255 {
            return Err("password too long".into());
        }
        tokio::time::timeout_at(deadline, client.read_exact(&mut buf[..plen]))
            .await
            .map_err(|_| "socks5 handshake timed out".to_string())?
            .map_err(|e| format!("read password: {e}"))?;
        let client_pass = std::str::from_utf8(&buf[..plen])
            .map_err(|e| format!("password utf8: {e}"))?
            .to_string();

        // Both comparisons must run — bitwise `&` (not `&&`) so a mismatched
        // username cannot skip the password comparison (timing oracle; parity
        // with http.rs Basic auth).
        if constant_time_eq(client_user.as_bytes(), u.as_bytes())
            & constant_time_eq(client_pass.as_bytes(), p.as_bytes())
        {
            client
                .write_all(&[USERPASS_VERSION, USERPASS_OK])
                .await
                .map_err(|e| format!("write auth ok: {e}"))?;
        } else {
            client
                .write_all(&[USERPASS_VERSION, USERPASS_FAIL])
                .await
                .map_err(|e| format!("write auth fail: {e}"))?;
            return Err("auth failed".into());
        }
    }

    // Step 3: Read request
    tokio::time::timeout_at(deadline, client.read_exact(&mut buf[..4]))
        .await
        .map_err(|_| "socks5 handshake timed out".to_string())?
        .map_err(|e| format!("read request hdr: {e}"))?;
    if buf[0] != SOCKS5_VERSION {
        return Err(format!("bad request version: {}", buf[0]));
    }
    let cmd = buf[1];
    let atyp = buf[3];

    if cmd != CMD_CONNECT {
        let reply = make_socks5_reply(REP_CMD_NOT_SUPPORTED, ATYP_IPV4, &[0, 0, 0, 0], 0);
        client
            .write_all(&reply)
            .await
            .map_err(|e| format!("write reply: {e}"))?;
        return Err(format!("unsupported cmd: {cmd}"));
    }

    // Parse target address
    let (host, port) = parse_socks5_target(deadline, &mut client, atyp, &mut buf).await?;

    // Step 4: Connect to target
    let target = format!("{host}:{port}");
    let remote = match TcpStream::connect(&target).await {
        Ok(remote) => remote,
        Err(_) => {
            let reply = make_socks5_reply(REP_HOST_UNREACHABLE, ATYP_IPV4, &[0, 0, 0, 0], 0);
            if let Err(e) = client.write_all(&reply).await {
                tracing::debug!(error = %e, "plugin relay error: {}", e);
            }
            return Err(format!("connect to {target}: failed"));
        }
    };
    frp_core::transport::set_nodelay(&remote);

    // Send success reply
    let reply = make_socks5_reply(REP_SUCCEEDED, ATYP_IPV4, &[0, 0, 0, 0], 0);
    client
        .write_all(&reply)
        .await
        .map_err(|e| format!("write reply: {e}"))?;

    // Step 5: Bidirectional relay through pooled buffers (audit round-8 P1:
    // relay_plain_pooled keeps copy_bidirectional semantics — FIN
    // propagation both ways — without the per-conn buffer pair).
    if let Err(e) = frp_core::bridge::relay_plain_pooled(client, remote).await {
        tracing::debug!(error = %e, "plugin relay error: {}", e);
    }
    Ok(())
}

/// Pure parser: decode a SOCKS5 address (ATYP + addr + port) from bytes.
/// Returns (host_string, port, bytes_consumed).
#[cfg(test)]
fn parse_socks5_addr(buf: &[u8]) -> Result<(String, u16, usize), String> {
    if buf.is_empty() {
        return Err("empty buffer".into());
    }
    let atyp = buf[0];
    match atyp {
        ATYP_IPV4 => {
            if buf.len() < 7 {
                return Err("buffer too short for IPv4".into());
            }
            let host = format!("{}.{}.{}.{}", buf[1], buf[2], buf[3], buf[4]);
            let port = u16::from_be_bytes([buf[5], buf[6]]);
            Ok((host, port, 7))
        }
        ATYP_DOMAIN => {
            if buf.len() < 2 {
                return Err("buffer too short for domain length".into());
            }
            let dlen = buf[1] as usize;
            if dlen > 255 {
                return Err("domain name too long".into());
            }
            if buf.len() < 2 + dlen + 2 {
                return Err("buffer too short for domain+port".into());
            }
            let domain = std::str::from_utf8(&buf[2..2 + dlen])
                .map_err(|e| format!("domain utf8: {e}"))?
                .to_string();
            let port = u16::from_be_bytes([buf[2 + dlen], buf[2 + dlen + 1]]);
            Ok((domain, port, 2 + dlen + 2))
        }
        ATYP_IPV6 => {
            if buf.len() < 19 {
                return Err("buffer too short for IPv6".into());
            }
            let host = format!(
                "{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}",
                u16::from_be_bytes([buf[1], buf[2]]),
                u16::from_be_bytes([buf[3], buf[4]]),
                u16::from_be_bytes([buf[5], buf[6]]),
                u16::from_be_bytes([buf[7], buf[8]]),
                u16::from_be_bytes([buf[9], buf[10]]),
                u16::from_be_bytes([buf[11], buf[12]]),
                u16::from_be_bytes([buf[13], buf[14]]),
                u16::from_be_bytes([buf[15], buf[16]]),
            );
            let port = u16::from_be_bytes([buf[17], buf[18]]);
            Ok((host, port, 19))
        }
        _ => Err(format!("unsupported atyp: {atyp}")),
    }
}

/// Parse target address from SOCKS5 request (ATYP + addr + port) over TCP.
/// Reads run under the shared handshake deadline.
async fn parse_socks5_target(
    deadline: tokio::time::Instant,
    client: &mut TcpStream,
    atyp: u8,
    buf: &mut [u8; 512],
) -> Result<(String, u16), String> {
    match atyp {
        ATYP_IPV4 => {
            tokio::time::timeout_at(deadline, client.read_exact(&mut buf[..6]))
                .await
                .map_err(|_| "socks5 handshake timed out".to_string())?
                .map_err(|e| format!("read ipv4: {e}"))?;
            let host = format!("{}.{}.{}.{}", buf[0], buf[1], buf[2], buf[3]);
            let port = u16::from_be_bytes([buf[4], buf[5]]);
            Ok((host, port))
        }
        ATYP_DOMAIN => {
            tokio::time::timeout_at(deadline, client.read_exact(&mut buf[..1]))
                .await
                .map_err(|_| "socks5 handshake timed out".to_string())?
                .map_err(|e| format!("read domain len: {e}"))?;
            let dlen = buf[0] as usize;
            if dlen > 255 {
                return Err("domain name too long".into());
            }
            tokio::time::timeout_at(deadline, client.read_exact(&mut buf[..dlen]))
                .await
                .map_err(|_| "socks5 handshake timed out".to_string())?
                .map_err(|e| format!("read domain: {e}"))?;
            let domain = std::str::from_utf8(&buf[..dlen])
                .map_err(|e| format!("domain utf8: {e}"))?
                .to_string();
            tokio::time::timeout_at(deadline, client.read_exact(&mut buf[..2]))
                .await
                .map_err(|_| "socks5 handshake timed out".to_string())?
                .map_err(|e| format!("read port: {e}"))?;
            let port = u16::from_be_bytes([buf[0], buf[1]]);
            Ok((domain, port))
        }
        ATYP_IPV6 => {
            tokio::time::timeout_at(deadline, client.read_exact(&mut buf[..18]))
                .await
                .map_err(|_| "socks5 handshake timed out".to_string())?
                .map_err(|e| format!("read ipv6: {e}"))?;
            let host = format!(
                "{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}",
                u16::from_be_bytes([buf[0], buf[1]]),
                u16::from_be_bytes([buf[2], buf[3]]),
                u16::from_be_bytes([buf[4], buf[5]]),
                u16::from_be_bytes([buf[6], buf[7]]),
                u16::from_be_bytes([buf[8], buf[9]]),
                u16::from_be_bytes([buf[10], buf[11]]),
                u16::from_be_bytes([buf[12], buf[13]]),
                u16::from_be_bytes([buf[14], buf[15]]),
            );
            let port = u16::from_be_bytes([buf[16], buf[17]]);
            Ok((host, port))
        }
        _ => {
            let reply = make_socks5_reply(REP_ADDR_NOT_SUPPORTED, ATYP_IPV4, &[0, 0, 0, 0], 0);
            client
                .write_all(&reply)
                .await
                .map_err(|e| format!("write reply: {e}"))?;
            Err(format!("unsupported atyp: {atyp}"))
        }
    }
}

/// Build a SOCKS5 reply packet.
fn make_socks5_reply(rep: u8, atyp: u8, addr: &[u8], port: u16) -> Vec<u8> {
    let mut reply = Vec::with_capacity(6 + addr.len());
    reply.push(SOCKS5_VERSION);
    reply.push(rep);
    reply.push(0x00); // RSV
    reply.push(atyp);
    reply.extend_from_slice(addr);
    reply.extend_from_slice(&port.to_be_bytes());
    reply
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_socks5_make_reply_success() {
        let reply = make_socks5_reply(REP_SUCCEEDED, ATYP_IPV4, &[127, 0, 0, 1], 8080);
        assert_eq!(reply[0], SOCKS5_VERSION);
        assert_eq!(reply[1], REP_SUCCEEDED);
        assert_eq!(reply[2], 0x00); // RSV
        assert_eq!(reply[3], ATYP_IPV4);
        assert_eq!(&reply[4..8], &[127, 0, 0, 1]);
        assert_eq!(u16::from_be_bytes([reply[8], reply[9]]), 8080);
    }

    #[test]
    fn test_socks5_make_reply_host_unreachable() {
        let reply = make_socks5_reply(REP_HOST_UNREACHABLE, ATYP_IPV4, &[0, 0, 0, 0], 0);
        assert_eq!(reply[1], REP_HOST_UNREACHABLE);
    }

    #[test]
    fn test_socks5_make_reply_ipv6() {
        let addr: [u8; 16] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let reply = make_socks5_reply(REP_SUCCEEDED, ATYP_IPV6, &addr, 443);
        assert_eq!(reply[3], ATYP_IPV6);
        assert_eq!(reply.len(), 22); // 4 + 16 + 2
        assert_eq!(&reply[4..20], &addr);
        assert_eq!(u16::from_be_bytes([reply[20], reply[21]]), 443);
    }

    #[test]
    fn test_socks5_parse_ipv4_addr() {
        // ATYP_IPV4 + 4 bytes + 2 bytes port
        let buf: [u8; 7] = [ATYP_IPV4, 192, 168, 1, 100, 0x1f, 0x90]; // 192.168.1.100:8080
        let (host, port, consumed) = parse_socks5_addr(&buf).unwrap();
        assert_eq!(host, "192.168.1.100");
        assert_eq!(port, 8080);
        assert_eq!(consumed, 7);
    }

    #[test]
    fn test_socks5_parse_domain_addr() {
        // ATYP_DOMAIN + len(11) + "example.com" + port(443)
        let domain = b"example.com";
        let mut buf = vec![ATYP_DOMAIN, domain.len() as u8];
        buf.extend_from_slice(domain);
        buf.extend_from_slice(&443u16.to_be_bytes());
        let (host, port, consumed) = parse_socks5_addr(&buf).unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, 443);
        assert_eq!(consumed, 1 + 1 + 11 + 2); // atyp + len + domain + port
    }

    #[tokio::test]
    async fn test_socks5_auth_negotiation_no_auth() {
        // Start a mini socks5 handler, connect as client, verify no-auth negotiation
        let listener = match tokio::net::TcpListener::bind("127.0.0.1:0").await {
            Ok(l) => l,
            Err(e) => {
                eprintln!("Skipping test: cannot bind (sandboxed): {e}");
                return;
            }
        };
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            // No username/password → no-auth only
            if let Err(e) = handle_socks5_conn(stream, None, None).await {
                tracing::debug!(error = %e, "plugin relay error: {}", e);
            }
        });

        let mut client = tokio::net::TcpStream::connect(addr).await.unwrap();

        // Send greeting: version=5, 1 method, method=NO_AUTH
        client
            .write_all(&[SOCKS5_VERSION, 1, AUTH_NO_AUTH])
            .await
            .unwrap();

        // Read auth reply
        let mut reply = [0u8; 2];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply[0], SOCKS5_VERSION);
        assert_eq!(reply[1], AUTH_NO_AUTH, "expected no-auth method");

        // Close to let server finish
        drop(client);
        server.await.unwrap();
    }

    /// M8 pins: PARTIAL auth config (username only) must NOT fall back to
    /// NO_AUTH (Go OR-arm) — a client offering only no-auth is rejected.
    #[tokio::test]
    async fn test_socks5_partial_username_rejects_no_auth_offer() {
        let listener = match tokio::net::TcpListener::bind("127.0.0.1:0").await {
            Ok(l) => l,
            Err(e) => {
                eprintln!("Skipping test: cannot bind (sandboxed): {e}");
                return;
            }
        };
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let _ = handle_socks5_conn(stream, Some("alice".to_string()), None).await;
        });

        let mut client = tokio::net::TcpStream::connect(addr).await.unwrap();
        // Greeting: only NO_AUTH offered. Config has a username (no
        // password) — server must not accept the anonymous method.
        client
            .write_all(&[SOCKS5_VERSION, 1, AUTH_NO_AUTH])
            .await
            .unwrap();
        let mut reply = [0u8; 2];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply[0], SOCKS5_VERSION);
        assert_eq!(
            reply[1], AUTH_NO_ACCEPTABLE,
            "partial auth config must not accept NO_AUTH"
        );
        drop(client);
        server.await.unwrap();
    }

    /// M8 pins: username-only config enforces USER_PASS with the empty
    /// password (Go StaticCredentials {user: ""}) — correct credentials
    /// pass and reach the request phase.
    #[tokio::test]
    async fn test_socks5_username_only_enforces_empty_password() {
        let listener = match tokio::net::TcpListener::bind("127.0.0.1:0").await {
            Ok(l) => l,
            Err(e) => {
                eprintln!("Skipping test: cannot bind (sandboxed): {e}");
                return;
            }
        };
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            // Username-only config: "alice" must authenticate with the
            // empty password. After auth the handler reads the CONNECT
            // request; client closes → handler exits, error expected.
            let _ = handle_socks5_conn(stream, Some("alice".to_string()), None).await;
        });

        let mut client = tokio::net::TcpStream::connect(addr).await.unwrap();
        client
            .write_all(&[SOCKS5_VERSION, 1, AUTH_USER_PASS])
            .await
            .unwrap();
        let mut reply = [0u8; 2];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply[1], AUTH_USER_PASS, "USER_PASS must be chosen");

        // USERPASS: version 1, user "alice" (5), empty password (0).
        let mut auth = vec![USERPASS_VERSION, 5];
        auth.extend_from_slice(b"alice");
        auth.push(0);
        client.write_all(&auth).await.unwrap();
        let mut auth_reply = [0u8; 2];
        client.read_exact(&mut auth_reply).await.unwrap();
        assert_eq!(
            auth_reply,
            [USERPASS_VERSION, USERPASS_OK],
            "alice + empty password must authenticate against username-only config"
        );

        drop(client);
        server.await.unwrap();
    }

    /// M8 pins: username-only config rejects a non-empty password.
    #[tokio::test]
    async fn test_socks5_username_only_rejects_nonempty_password() {
        let listener = match tokio::net::TcpListener::bind("127.0.0.1:0").await {
            Ok(l) => l,
            Err(e) => {
                eprintln!("Skipping test: cannot bind (sandboxed): {e}");
                return;
            }
        };
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let _ = handle_socks5_conn(stream, Some("alice".to_string()), None).await;
        });

        let mut client = tokio::net::TcpStream::connect(addr).await.unwrap();
        client
            .write_all(&[SOCKS5_VERSION, 1, AUTH_USER_PASS])
            .await
            .unwrap();
        let mut reply = [0u8; 2];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply[1], AUTH_USER_PASS);

        // Wrong password: "alice" + "x" → USERPASS_FAIL.
        let mut auth = vec![USERPASS_VERSION, 5];
        auth.extend_from_slice(b"alice");
        auth.extend_from_slice(&[1, b'x']);
        client.write_all(&auth).await.unwrap();
        let mut auth_reply = [0u8; 2];
        client.read_exact(&mut auth_reply).await.unwrap();
        assert_eq!(
            auth_reply,
            [USERPASS_VERSION, USERPASS_FAIL],
            "non-empty password must fail against username-only config"
        );
        drop(client);
        server.await.unwrap();
    }

    /// C-5: a peer that connects but stalls mid-handshake (here: greeting
    /// read_exact(2) stuck at 1/2) must be released by the single absolute
    /// SOCKS5_HANDSHAKE_TIMEOUT deadline — the handler task + fd cannot park
    /// forever. Pinned under paused time so the test is deterministic.
    #[tokio::test(start_paused = true)]
    async fn test_socks5_handshake_deadline_releases_handler() {
        let listener = match tokio::net::TcpListener::bind("127.0.0.1:0").await {
            Ok(l) => l,
            Err(e) => {
                eprintln!("Skipping test: cannot bind (sandboxed): {e}");
                return;
            }
        };
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            handle_socks5_conn(stream, None, None).await
        });

        let mut client = tokio::net::TcpStream::connect(addr).await.unwrap();
        // Version byte only — greeting read_exact(2) stays at 1/2 forever.
        client.write_all(&[SOCKS5_VERSION]).await.unwrap();
        tokio::task::yield_now().await;

        // The deadline is anchored at handler entry, so advancing past it
        // fires regardless of how far the task has progressed.
        tokio::time::advance(SOCKS5_HANDSHAKE_TIMEOUT + std::time::Duration::from_secs(1)).await;

        let res = server.await.unwrap();
        assert!(
            res.is_err(),
            "handshake deadline must release the handler task"
        );
    }

    #[tokio::test]
    async fn test_socks5_auth_negotiation_user_pass() {
        let listener = match tokio::net::TcpListener::bind("127.0.0.1:0").await {
            Ok(l) => l,
            Err(e) => {
                eprintln!("Skipping test: cannot bind (sandboxed): {e}");
                return;
            }
        };
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            if let Err(e) =
                handle_socks5_conn(stream, Some("alice".into()), Some("s3cret".into())).await
            {
                tracing::debug!(error = %e, "plugin relay error: {}", e);
            }
        });

        let mut client = tokio::net::TcpStream::connect(addr).await.unwrap();

        // Send greeting: version=5, 2 methods: USER_PASS, NO_AUTH
        client
            .write_all(&[SOCKS5_VERSION, 2, AUTH_USER_PASS, AUTH_NO_AUTH])
            .await
            .unwrap();

        // Server should pick USER_PASS
        let mut reply = [0u8; 2];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply[0], SOCKS5_VERSION);
        assert_eq!(reply[1], AUTH_USER_PASS);

        // Send user/pass auth: VER=1, ULEN=5, "alice", PLEN=6, "s3cret"
        client.write_all(&[USERPASS_VERSION, 5]).await.unwrap();
        client.write_all(b"alice").await.unwrap();
        client.write_all(&[6]).await.unwrap();
        client.write_all(b"s3cret").await.unwrap();

        // Read auth result
        let mut auth_result = [0u8; 2];
        client.read_exact(&mut auth_result).await.unwrap();
        assert_eq!(auth_result[0], USERPASS_VERSION);
        assert_eq!(auth_result[1], USERPASS_OK, "expected auth success");

        drop(client);
        server.await.unwrap();
    }

    /// R8 pin: PASSWORD-only config (user=None, pass=Some) is still an
    /// armed auth config (Go OR-arm) — a client offering only NO_AUTH must
    /// be rejected with [0x05, 0xFF], never accepted fail-open.
    #[tokio::test]
    async fn test_socks5_password_only_rejects_no_auth_offer() {
        let listener = match tokio::net::TcpListener::bind("127.0.0.1:0").await {
            Ok(l) => l,
            Err(e) => {
                eprintln!("Skipping test: cannot bind (sandboxed): {e}");
                return;
            }
        };
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            // Password-only config: user=None, pass=Some("s3cret").
            let _ = handle_socks5_conn(stream, None, Some("s3cret".to_string())).await;
        });

        let mut client = tokio::net::TcpStream::connect(addr).await.unwrap();
        client
            .write_all(&[SOCKS5_VERSION, 1, AUTH_NO_AUTH])
            .await
            .unwrap();
        let mut reply = [0u8; 2];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply[0], SOCKS5_VERSION);
        assert_eq!(
            reply[1], AUTH_NO_ACCEPTABLE,
            "password-only config must not accept NO_AUTH"
        );
        drop(client);
        server.await.unwrap();
    }

    /// R8 pin: password-only config authenticates the EMPTY username with
    /// the configured password (Go StaticCredentials {"": pass} — user=None
    /// normalizes to the literal empty string).
    #[tokio::test]
    async fn test_socks5_password_only_accepts_empty_username() {
        let listener = match tokio::net::TcpListener::bind("127.0.0.1:0").await {
            Ok(l) => l,
            Err(e) => {
                eprintln!("Skipping test: cannot bind (sandboxed): {e}");
                return;
            }
        };
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            // After USERPASS_OK the handler reads the CONNECT request;
            // client closes → handler exits, error expected.
            let _ = handle_socks5_conn(stream, None, Some("s3cret".to_string())).await;
        });

        let mut client = tokio::net::TcpStream::connect(addr).await.unwrap();
        client
            .write_all(&[SOCKS5_VERSION, 1, AUTH_USER_PASS])
            .await
            .unwrap();
        let mut reply = [0u8; 2];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply[1], AUTH_USER_PASS, "USER_PASS must be chosen");

        // USERPASS: version 1, empty username (0), password "s3cret" (6).
        let mut auth = vec![USERPASS_VERSION, 0];
        auth.extend_from_slice(&[6]);
        auth.extend_from_slice(b"s3cret");
        client.write_all(&auth).await.unwrap();
        let mut auth_reply = [0u8; 2];
        client.read_exact(&mut auth_reply).await.unwrap();
        assert_eq!(
            auth_reply,
            [USERPASS_VERSION, USERPASS_OK],
            "empty username + correct password must authenticate against password-only config"
        );

        drop(client);
        server.await.unwrap();
    }

    /// R8 pin: password-only config rejects a NON-EMPTY username even with
    /// the correct password (the username half is enforced as the literal
    /// empty string).
    #[tokio::test]
    async fn test_socks5_password_only_rejects_nonempty_username() {
        let listener = match tokio::net::TcpListener::bind("127.0.0.1:0").await {
            Ok(l) => l,
            Err(e) => {
                eprintln!("Skipping test: cannot bind (sandboxed): {e}");
                return;
            }
        };
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let _ = handle_socks5_conn(stream, None, Some("s3cret".to_string())).await;
        });

        let mut client = tokio::net::TcpStream::connect(addr).await.unwrap();
        client
            .write_all(&[SOCKS5_VERSION, 1, AUTH_USER_PASS])
            .await
            .unwrap();
        let mut reply = [0u8; 2];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply[1], AUTH_USER_PASS);

        // Wrong username: "eve" + correct password → USERPASS_FAIL.
        let mut auth = vec![USERPASS_VERSION, 3];
        auth.extend_from_slice(b"eve");
        auth.extend_from_slice(&[6]);
        auth.extend_from_slice(b"s3cret");
        client.write_all(&auth).await.unwrap();
        let mut auth_reply = [0u8; 2];
        client.read_exact(&mut auth_reply).await.unwrap();
        assert_eq!(
            auth_reply,
            [USERPASS_VERSION, USERPASS_FAIL],
            "non-empty username must fail against password-only config"
        );
        drop(client);
        server.await.unwrap();
    }
}
