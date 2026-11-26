use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::debug;

use frp_core::config::PluginConfig;

use super::socks5_udp::UdpAssociateHandle;
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
/// Absolute cap on one UDP association. RFC 1928 ties the association to its
/// TCP control connection, but a client that vanishes without FIN/RST leaves
/// that connection half-open (frps' keepalive is 2h by default and can be
/// disabled). The cap bounds how long such a leaked association can keep the
/// relay's gate open; clients re-associate after it expires.
const UDP_ASSOCIATION_MAX_LIFETIME: std::time::Duration = std::time::Duration::from_secs(3600);
const AUTH_NO_AUTH: u8 = 0x00;
const AUTH_USER_PASS: u8 = 0x02;
const AUTH_NO_ACCEPTABLE: u8 = 0xFF;
const CMD_CONNECT: u8 = 0x01;
const CMD_UDP_ASSOCIATE: u8 = 0x03;
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;
const REP_GENERAL_FAILURE: u8 = 0x01;
const REP_SUCCEEDED: u8 = 0x00;
const REP_HOST_UNREACHABLE: u8 = 0x04;
const REP_CMD_NOT_SUPPORTED: u8 = 0x07;
const REP_ADDR_NOT_SUPPORTED: u8 = 0x08;
const USERPASS_VERSION: u8 = 0x01;
const USERPASS_OK: u8 = 0x00;
const USERPASS_FAIL: u8 = 0x01;

const REPLY_SUCCEEDED_ZERO: [u8; 10] = [
    SOCKS5_VERSION,
    REP_SUCCEEDED,
    0x00,
    ATYP_IPV4,
    0,
    0,
    0,
    0,
    0,
    0,
];
const REPLY_GENERAL_FAILURE: [u8; 10] = [
    SOCKS5_VERSION,
    REP_GENERAL_FAILURE,
    0x00,
    ATYP_IPV4,
    0,
    0,
    0,
    0,
    0,
    0,
];
const REPLY_HOST_UNREACHABLE: [u8; 10] = [
    SOCKS5_VERSION,
    REP_HOST_UNREACHABLE,
    0x00,
    ATYP_IPV4,
    0,
    0,
    0,
    0,
    0,
    0,
];
const REPLY_CMD_NOT_SUPPORTED: [u8; 10] = [
    SOCKS5_VERSION,
    REP_CMD_NOT_SUPPORTED,
    0x00,
    ATYP_IPV4,
    0,
    0,
    0,
    0,
    0,
    0,
];
const REPLY_ADDR_NOT_SUPPORTED: [u8; 10] = [
    SOCKS5_VERSION,
    REP_ADDR_NOT_SUPPORTED,
    0x00,
    ATYP_IPV4,
    0,
    0,
    0,
    0,
    0,
    0,
];

/// Shared per-plugin state; cloned by `Arc` per accepted TCP connection
/// instead of cloning `String` credentials on every connect.
struct Socks5State {
    user: Option<String>,
    pass: Option<String>,
    udp: Option<UdpAssociateHandle>,
}

/// Stack-buffered reader for the SOCKS5 handshake. Large enough (520 B) to
/// hold the maximum RFC 1929 user/pass packet (`2 + 255 + 1 + 255 = 513 B`)
/// contiguously so auth slices need zero heap allocation and normal handshakes
/// drop from 7–10 `read()` syscalls to 2–3.
struct HandshakeBuf {
    buf: [u8; 520],
    pos: usize,
    len: usize,
}

impl HandshakeBuf {
    fn new() -> Self {
        Self {
            buf: [0u8; 520],
            pos: 0,
            len: 0,
        }
    }

    fn compact(&mut self) {
        if self.pos == self.len {
            self.pos = 0;
            self.len = 0;
        } else if self.pos > 0 {
            self.buf.copy_within(self.pos..self.len, 0);
            self.len -= self.pos;
            self.pos = 0;
        }
    }

    async fn ensure(&mut self, stream: &mut TcpStream, need: usize) -> std::io::Result<()> {
        if self.len - self.pos >= need {
            return Ok(());
        }
        if self.buf.len() - self.pos < need {
            self.compact();
        }
        while self.len - self.pos < need {
            let n = stream.read(&mut self.buf[self.len..]).await?;
            if n == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "early eof",
                ));
            }
            self.len += n;
        }
        Ok(())
    }

    async fn take_range(
        &mut self,
        stream: &mut TcpStream,
        n: usize,
    ) -> std::io::Result<std::ops::Range<usize>> {
        self.ensure(stream, n).await?;
        let start = self.pos;
        self.pos += n;
        Ok(start..start + n)
    }

    fn remaining(&self) -> &[u8] {
        &self.buf[self.pos..self.len]
    }
}

enum SocksTarget {
    Addr(SocketAddr),
    Domain(String, u16),
}

impl fmt::Display for SocksTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SocksTarget::Addr(addr) => write!(f, "{addr}"),
            SocksTarget::Domain(host, port) => write!(f, "{host}:{port}"),
        }
    }
}

enum HandshakeAction {
    Connect(SocksTarget),
    UdpAssociate,
}

/// Start a SOCKS5 proxy plugin server.
///
/// Supports CONNECT and, when `plugin.udp_enable` is set, UDP ASSOCIATE
/// (RFC 1928 §7). Optional username/password auth via PluginConfig
/// `username` / `password`.
pub async fn start_socks5_proxy(cfg: &PluginConfig) -> Result<PluginHandle, frp_core::Error> {
    let user = opt_if_empty!(cfg.username);
    let pass = opt_if_empty!(cfg.password);
    // Cancelled when the returned PluginHandle is dropped; the UDP relay binds
    // lazily on the first UDP ASSOCIATE and watches this token.
    let cancel = tokio_util::sync::CancellationToken::new();
    let udp = super::socks5_udp::UdpRelay::from_config(cfg, cancel.clone()).await?;
    let state = Arc::new(Socks5State { user, pass, udp });
    let mut handle = serve_plugin("socks5", state, |stream, peer, state| async move {
        if let Err(e) = handle_socks5_conn_state(stream, &state).await {
            debug!(%peer, error = %e, "socks5: {peer} error: {e}");
        }
    })
    .await?;
    handle.cancel = cancel;
    Ok(handle)
}

#[cfg(test)]
async fn handle_socks5_conn(
    client: TcpStream,
    user: Option<String>,
    pass: Option<String>,
    udp: Option<UdpAssociateHandle>,
) -> Result<(), String> {
    let state = Socks5State { user, pass, udp };
    handle_socks5_conn_state(client, &state).await
}

async fn handle_socks5_conn_state(
    mut client: TcpStream,
    state: &Socks5State,
) -> Result<(), String> {
    let mut hs = HandshakeBuf::new();

    // One single timeout anchors the whole handshake — greeting, auth methods,
    // user/pass, and request — replacing 7–10 per-read timer registrations with
    // one timer entry. The relay phase after CONNECT stays unbounded.
    let action = tokio::time::timeout(
        SOCKS5_HANDSHAKE_TIMEOUT,
        run_handshake(&mut client, &mut hs, state),
    )
    .await
    .map_err(|_| "socks5 handshake timed out".to_string())??;

    match action {
        HandshakeAction::UdpAssociate => {
            let Some(udp) = state.udp.as_ref() else {
                client
                    .write_all(&REPLY_CMD_NOT_SUPPORTED)
                    .await
                    .map_err(|e| format!("write reply: {e}"))?;
                return Err("UDP ASSOCIATE requested but plugin.udp_enable is false".into());
            };
            // The relay binds lazily here (so a reload of a fixed udp_bind_addr
            // does not collide with the previous plugin instance, which is still
            // serving until the reload commits). The association is counted before
            // the reply is written, so the first datagram cannot race the gate.
            let (_guard, advertise) = match udp.enter().await {
                Ok(v) => v,
                Err(e) => {
                    let _ = client.write_all(&REPLY_GENERAL_FAILURE).await;
                    return Err(e);
                }
            };
            let (reply, reply_len) = encode_reply_for_addr(REP_SUCCEEDED, advertise);
            client
                .write_all(&reply[..reply_len])
                .await
                .map_err(|e| format!("write udp associate reply: {e}"))?;

            // RFC 1928: the association lives as long as this TCP connection. It
            // carries no further protocol data; read until EOF (or an error) so a
            // half-closed control connection still terminates the association. The
            // absolute cap is a safety valve for a silently dead peer that never
            // produces EOF (see UDP_ASSOCIATION_MAX_LIFETIME).
            let mut sink = [0u8; 256];
            let deadline = tokio::time::Instant::now() + UDP_ASSOCIATION_MAX_LIFETIME;
            loop {
                match tokio::time::timeout_at(deadline, client.read(&mut sink)).await {
                    Err(_) => {
                        debug!("socks5 UDP association reached its maximum lifetime; closing");
                        break;
                    }
                    Ok(Ok(0)) | Ok(Err(_)) => break,
                    Ok(Ok(_)) => {}
                }
            }
            Ok(())
        }
        HandshakeAction::Connect(target) => {
            // Step 4: Connect to target without formatting/parsing IP literals.
            let connect_res = match &target {
                SocksTarget::Addr(addr) => TcpStream::connect(*addr).await,
                SocksTarget::Domain(host, port) => TcpStream::connect((host.as_str(), *port)).await,
            };
            let mut remote = match connect_res {
                Ok(remote) => remote,
                Err(_) => {
                    if let Err(e) = client.write_all(&REPLY_HOST_UNREACHABLE).await {
                        tracing::debug!(error = %e, "plugin relay error: {}", e);
                    }
                    return Err(format!("connect to {target}: failed"));
                }
            };
            frp_core::transport::set_nodelay(&remote);

            // Send success reply.
            client
                .write_all(&REPLY_SUCCEEDED_ZERO)
                .await
                .map_err(|e| format!("write reply: {e}"))?;

            // Flush any client application bytes that arrived pipelined in the
            // same TCP segment as the CONNECT request before handing the raw
            // TcpStreams to zero-copy splice / pooled relay.
            let pipelined = hs.remaining();
            if !pipelined.is_empty() {
                remote
                    .write_all(pipelined)
                    .await
                    .map_err(|e| format!("flush pipelined data: {e}"))?;
            }

            // Step 5: Bidirectional relay — Linux uses kernel-space zero-copy
            // `splice(2)` (`bridge_splice`); non-Linux uses lock-free
            // `TcpStream::into_split()` pooled buffers.
            if let Err(e) = frp_core::bridge::relay_tcp_fast(client, remote).await {
                tracing::debug!(error = %e, "plugin relay error: {}", e);
            }
            Ok(())
        }
    }
}

async fn run_handshake(
    client: &mut TcpStream,
    hs: &mut HandshakeBuf,
    state: &Socks5State,
) -> Result<HandshakeAction, String> {
    // Step 1: Auth method negotiation.
    let hdr = hs
        .take_range(client, 2)
        .await
        .map_err(|e| format!("read greeting: {e}"))?;
    let ver = hs.buf[hdr.start];
    let nmethods = hs.buf[hdr.start + 1] as usize;
    if ver != SOCKS5_VERSION {
        return Err(format!("bad socks version: {ver}"));
    }
    if nmethods == 0 {
        return Err("no auth methods offered".into());
    }
    let methods_range = hs
        .take_range(client, nmethods)
        .await
        .map_err(|e| format!("read methods: {e}"))?;
    let methods = &hs.buf[methods_range];

    // Go parity (pkg/plugin/client/socks5.go:44-46): auth is armed by
    // OR — `Username != "" || Password != ""` — so a PARTIAL config
    // (username without password, or vice versa) must still enforce
    // credentials instead of silently falling back to NO_AUTH (audit
    // finding M8: AND here made the tunnel fail open). The empty half is
    // enforced as the literal empty string, matching Go's
    // StaticCredentials(map[string]string{user: pass}).
    let use_auth = state.user.is_some() || state.pass.is_some();

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

    // Step 2: Username/password auth (if selected).
    if chosen_method == AUTH_USER_PASS {
        // Partial config reaches here with one empty half (OR-arm, Go
        // parity) — compare against the literal empty string.
        let u = state.user.as_deref().unwrap_or("");
        let p = state.pass.as_deref().unwrap_or("");

        // Compact so the entire RFC 1929 packet (<= 513 B) fits in `hs.buf`
        // without reallocating or copying credentials to the heap.
        hs.compact();
        let up_hdr = hs
            .take_range(client, 2)
            .await
            .map_err(|e| format!("read user/pass ver: {e}"))?;
        if hs.buf[up_hdr.start] != USERPASS_VERSION {
            client
                .write_all(&[USERPASS_VERSION, USERPASS_FAIL])
                .await
                .map_err(|e| format!("write auth fail: {e}"))?;
            return Err(format!("bad user/pass version: {}", hs.buf[up_hdr.start]));
        }
        let ulen = hs.buf[up_hdr.start + 1] as usize;
        let user_range = hs
            .take_range(client, ulen)
            .await
            .map_err(|e| format!("read username: {e}"))?;
        let plen_range = hs
            .take_range(client, 1)
            .await
            .map_err(|e| format!("read plen: {e}"))?;
        let plen = hs.buf[plen_range.start] as usize;
        let pass_range = hs
            .take_range(client, plen)
            .await
            .map_err(|e| format!("read password: {e}"))?;

        let client_user =
            std::str::from_utf8(&hs.buf[user_range]).map_err(|e| format!("username utf8: {e}"))?;
        let client_pass =
            std::str::from_utf8(&hs.buf[pass_range]).map_err(|e| format!("password utf8: {e}"))?;

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

    // Step 3: Read request.
    let req_hdr = hs
        .take_range(client, 4)
        .await
        .map_err(|e| format!("read request hdr: {e}"))?;
    if hs.buf[req_hdr.start] != SOCKS5_VERSION {
        return Err(format!("bad request version: {}", hs.buf[req_hdr.start]));
    }
    let cmd = hs.buf[req_hdr.start + 1];
    let atyp = hs.buf[req_hdr.start + 3];

    if cmd == CMD_UDP_ASSOCIATE {
        if state.udp.is_none() {
            return Ok(HandshakeAction::UdpAssociate);
        }
        // The client's declared UDP endpoint is advisory (RFC 1928 §7: it may
        // be all-zero when the source port is not known yet). Parse it to
        // consume the request, but bind no per-client state: the shared relay
        // learns datagram sources when they arrive.
        let _ = parse_socks5_target(client, hs, atyp).await?;
        return Ok(HandshakeAction::UdpAssociate);
    }

    if cmd != CMD_CONNECT {
        client
            .write_all(&REPLY_CMD_NOT_SUPPORTED)
            .await
            .map_err(|e| format!("write reply: {e}"))?;
        return Err(format!("unsupported cmd: {cmd}"));
    }

    let target = parse_socks5_target(client, hs, atyp).await?;
    Ok(HandshakeAction::Connect(target))
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

/// Parse target address from SOCKS5 request (ATYP + addr + port) via `hs`.
async fn parse_socks5_target(
    client: &mut TcpStream,
    hs: &mut HandshakeBuf,
    atyp: u8,
) -> Result<SocksTarget, String> {
    match atyp {
        ATYP_IPV4 => {
            let r = hs
                .take_range(client, 6)
                .await
                .map_err(|e| format!("read ipv4: {e}"))?;
            let b = &hs.buf[r];
            let ip = Ipv4Addr::new(b[0], b[1], b[2], b[3]);
            let port = u16::from_be_bytes([b[4], b[5]]);
            Ok(SocksTarget::Addr(SocketAddr::new(IpAddr::V4(ip), port)))
        }
        ATYP_DOMAIN => {
            let len_r = hs
                .take_range(client, 1)
                .await
                .map_err(|e| format!("read domain len: {e}"))?;
            let dlen = hs.buf[len_r.start] as usize;
            let body_r = hs
                .take_range(client, dlen + 2)
                .await
                .map_err(|e| format!("read domain: {e}"))?;
            let b = &hs.buf[body_r];
            let domain =
                std::str::from_utf8(&b[..dlen]).map_err(|e| format!("domain utf8: {e}"))?;
            let port = u16::from_be_bytes([b[dlen], b[dlen + 1]]);
            if let Ok(ip) = domain.parse::<IpAddr>() {
                Ok(SocksTarget::Addr(SocketAddr::new(ip, port)))
            } else {
                Ok(SocksTarget::Domain(domain.to_string(), port))
            }
        }
        ATYP_IPV6 => {
            let r = hs
                .take_range(client, 18)
                .await
                .map_err(|e| format!("read ipv6: {e}"))?;
            let b = &hs.buf[r];
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&b[..16]);
            let ip = Ipv6Addr::from(octets);
            let port = u16::from_be_bytes([b[16], b[17]]);
            Ok(SocksTarget::Addr(SocketAddr::new(IpAddr::V6(ip), port)))
        }
        _ => {
            client
                .write_all(&REPLY_ADDR_NOT_SUPPORTED)
                .await
                .map_err(|e| format!("write reply: {e}"))?;
            Err(format!("unsupported atyp: {atyp}"))
        }
    }
}

/// Encode a SOCKS5 reply for a concrete bound address (UDP ASSOCIATE BND.ADDR)
/// into a stack buffer with zero heap allocation.
fn encode_reply_for_addr(rep: u8, addr: SocketAddr) -> ([u8; 22], usize) {
    let mut out = [0u8; 22];
    out[0] = SOCKS5_VERSION;
    out[1] = rep;
    out[2] = 0x00; // RSV
    match addr.ip() {
        IpAddr::V4(ip) => {
            out[3] = ATYP_IPV4;
            out[4..8].copy_from_slice(&ip.octets());
            out[8..10].copy_from_slice(&addr.port().to_be_bytes());
            (out, 10)
        }
        IpAddr::V6(ip) => {
            out[3] = ATYP_IPV6;
            out[4..20].copy_from_slice(&ip.octets());
            out[20..22].copy_from_slice(&addr.port().to_be_bytes());
            (out, 22)
        }
    }
}

/// Build a SOCKS5 reply packet (kept for unit-test coverage).
#[cfg(test)]
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
            if let Err(e) = handle_socks5_conn(stream, None, None, None).await {
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
            let _ = handle_socks5_conn(stream, Some("alice".to_string()), None, None).await;
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
            let _ = handle_socks5_conn(stream, Some("alice".to_string()), None, None).await;
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
            let _ = handle_socks5_conn(stream, Some("alice".to_string()), None, None).await;
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
            handle_socks5_conn(stream, None, None, None).await
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
                handle_socks5_conn(stream, Some("alice".into()), Some("s3cret".into()), None).await
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
            let _ = handle_socks5_conn(stream, None, Some("s3cret".to_string()), None).await;
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
            let _ = handle_socks5_conn(stream, None, Some("s3cret".to_string()), None).await;
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
            let _ = handle_socks5_conn(stream, None, Some("s3cret".to_string()), None).await;
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
