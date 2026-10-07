//! HTTPS/SNI vhost listener (TLS pass-through, SNI routing) and the
//! ClientHello SNI parser.
//!
//! Split out of `vhost.rs` as a pure text move; the parent re-exports
//! `run_vhost_https_listener` (service listener call site) and
//! `extract_sni_from_client_hello` (`vhost/tests.rs` and the e2e test).

use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tracing::{debug, info, instrument, warn};

use crate::service::InternalMsg;

/// Run an HTTPS VHost listener on the given address.
///
/// Go frp compat (`pkg/util/vhost/https.go`): frps does NOT terminate TLS for
/// HTTPS vhosts. It reads only the ClientHello SNI, routes by SNI, and
/// forwards the original encrypted bytes (as pre_read) to the matching frpc
/// HTTPS proxy — the TLS session stays end-to-end between the user and the
/// backend.
#[cfg(feature = "tls")]
#[instrument(skip(state, shutdown_token), fields(addr = %addr))]
pub async fn run_vhost_https_listener(
    addr: String,
    state: std::sync::Arc<crate::service::AppState>,
    shutdown_token: tokio_util::sync::CancellationToken,
) -> Result<(), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind(&addr).await?;
    info!(addr = %addr, "HTTPS VHost listener started on {}", addr);

    loop {
        tokio::select! {
            result = listener.accept() => {
                let (mut stream, peer) = result?;
                frp_core::transport::set_nodelay(&stream);
                if state.tcp_keepalive > 0 {
                    frp_core::transport::set_keepalive(&stream, state.tcp_keepalive as u64);
                }
                let permit = state
                    .conn_semaphore
                    .as_ref()
                    .and_then(|s| s.clone().try_acquire_owned().ok());
                if permit.is_none() && state.conn_semaphore.is_some() {
                    warn!(addr = %peer, "Max connections reached, rejecting from {}", peer);
                    continue;
                }
                let rate_wait = if state.accept_rate_limiter.rate() > 0.0 {
                    state.accept_rate_limiter.try_acquire().err()
                } else {
                    None
                };
                if let Some(wait) = rate_wait {
                    warn!(addr = %peer, wait_ms = wait.as_millis(), "accept rate limit reached, delaying {}ms", wait.as_millis());
                    // Release the semaphore permit before sleeping — the
                    // connection is being delayed, not accepted, so it must
                    // not hold a connection slot while we wait.
                    drop(permit);
                    tokio::time::sleep(wait).await;
                    continue;
                }
                let state = state.clone();

                tokio::spawn(async move {
                    let _permit = permit;
                    // Read the TLS ClientHello (SNI lives in the first
                    // record; 4096 bytes comfortably covers it). Deadline is
                    // Go's FIXED vhostReadWriteTimeout (service.go:65/342 —
                    // the HTTPS Muxer is constructed with it), immune to the
                    // user's vhost_http_timeout: the old config-derived
                    // clamp made the SNI read window stretch to the 24h cap
                    // under a hostile timeout setting.
                    let mut buf = [0u8; 4096];
                    let n = match tokio::time::timeout(
                        std::time::Duration::from_secs(30),
                        read_client_hello_prefix(&mut stream, &mut buf),
                    )
                    .await
                    {
                        Ok(Ok(n)) if n > 0 => n,
                        _ => return,
                    };
                    let pre_read = buf[..n].to_vec();

                    let Some(sni) = extract_sni_from_client_hello(&buf[..n]) else {
                        warn!(peer = %peer, "HTTPS VHost: no SNI in ClientHello from {}", peer);
                        return;
                    };
                    debug!(sni = %sni, peer = %peer, "HTTPS VHost SNI '{}' from {}", sni, peer);

                    // Route by SNI (host), path "/" (Go https.go getByRoute).
                    // Go frp lowercases the host before lookup (router.go
                    // `Get` → strings.ToLower), so a mixed-case SNI must
                    // resolve case-insensitively. get_locked is the sole
                    // routing lowercaser, so pass the raw SNI here — the
                    // debug/warn lines below log it case-preserved.
                    // Scheme "https": the HTTPS Muxer's registryRouter only
                    // (Go parity) — SNI must never match an HTTP route.
                    if let Some(route) = state
                        .vhost_manager
                        .lookup_combined(&sni, "/", "", "https")
                        .await
                    {
                        // HTTPS group members share one SNI route, and Go
                        // dispatches each conn to whichever member accepts
                        // first (HTTPSGroup = baseGroup: every member's
                        // Listener reads the same acceptCh). frp-rs picks
                        // deterministically: round-robin over the https-kind
                        // members via the kind-keyed registry (the http and
                        // https groups may share the name). Owner-sticky
                        // routing would strand every conn on the first
                        // member while siblings stay idle.
                        let (proxy_name, run_id) = if route.group.is_empty() {
                            (route.proxy_name.to_string(), route.run_id.to_string())
                        } else {
                            match state
                                .http_group_ctl
                                .choose_endpoint(&route.group, true)
                                .await
                            {
                                Some(member) => {
                                    match state.proxy_manager.get(&member).await {
                                        Some(info) => {
                                            debug!(
                                                sni = %sni, group = %route.group,
                                                member = %member,
                                                "HTTPS VHost group '{}' -> member '{}'",
                                                route.group, member
                                            );
                                            (member, info.run_id.clone())
                                        }
                                        None => {
                                            // Member gone between choose and
                                            // lookup — fall back to the
                                            // route's recorded proxy.
                                            warn!(
                                                group = %route.group, member = %member,
                                                "HTTPS VHost: group member '{}' not registered, falling back to '{}'",
                                                member, route.proxy_name
                                            );
                                            (route.proxy_name.to_string(), route.run_id.to_string())
                                        }
                                    }
                                }
                                None => {
                                    // Group has no members — route to the
                                    // first member anyway; the control
                                    // dispatch will fail cleanly if it is
                                    // gone too.
                                    (route.proxy_name.to_string(), route.run_id.to_string())
                                }
                            }
                        };
                        let internal_tx = state
                            .run_id_to_ctl_tx
                            .get(run_id.as_str())
                            .map(|v| v.tx.clone());
                        if let Some(ctl_tx) = internal_tx {
                            // send().await: same backpressure rationale as the
                            // HTTP vhost path — runs in a per-connection
                            // spawned task, so the await is free. Bounded
                            // (audit H3, same as the HTTP path above): a
                            // control handler that stops draining must not
                            // pin this task + fd + permit forever; after
                            // CTL_SEND_TIMEOUT the connection drops.
                            match tokio::time::timeout(
                                crate::state::CTL_SEND_TIMEOUT,
                                ctl_tx.send(InternalMsg::ProxyUserConn {
                                    proxy_name,
                                    // Passthrough: raw encrypted bytes, no TLS wrap.
                                    user_conn: frp_core::transport::IoStream::Tcp(stream),
                                    pre_read,
                                    user_conn_permit: None,
                                    // Group selection was done here (choose_endpoint
                                    // above) — TCP-group re-selection must not
                                    // rerun. The receiving handler routes to the
                                    // named proxy as-is (group LB applies to TCP
                                    // groups only; http/https group members are
                                    // always pre-selected by the vhost router).
                                    group_selected: false,
                                    // Raw encrypted passthrough — never an HTTP
                                    // request the injector could splice (the
                                    // bridge sees TLS bytes, not a response
                                    // head). false matches every non-vhost
                                    // producer.
                                    request_is_connect: false,
                                }),
                            )
                            .await
                            {
                                Ok(Ok(())) => {}
                                Ok(Err(_)) => {
                                    warn!(sni = %sni, "HTTPS VHost route for '{}' found but control channel closed", sni);
                                }
                                Err(_elapsed) => {
                                    warn!(sni = %sni, "HTTPS VHost route for '{}' found but control channel send timed out; dropping conn", sni);
                                }
                            }
                        } else {
                            warn!(sni = %sni, "HTTPS VHost route for '{}' found but control handler gone", sni);
                        }
                    } else {
                        warn!(sni = %sni, peer = %peer, "No HTTPS VHost route for '{}' from {}", sni, peer);
                        // Best-effort TLS alert before the drop: fatal
                        // unrecognized_name — record type 0x15 (alert),
                        // TLS 1.2 record, 2-byte payload 0x02 0x70
                        // (fatal, alertUnrecognizedName=112) — so a TLS
                        // client fails fast instead of hanging on a
                        // handshake timeout. Write failure is ignored;
                        // the connection is dropped either way.
                        let _ = stream
                            .write_all(&[0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x70])
                            .await;
                    }
                });
            }
            _ = shutdown_token.cancelled() => {
                info!("HTTPS VHost listener shutting down");
                break;
            }
        }
    }
    Ok(())
}

/// Read up to `buf.len()` bytes for the TLS ClientHello. Reads until we have
/// the full ClientHello record (content type 0x16 + TLS record header), or
/// the buffer is full, or EOF.
#[allow(dead_code)] // TLS/HTTPS vhost paths only; absent in the micro build
async fn read_client_hello_prefix<S: tokio::io::AsyncRead + Unpin>(
    stream: &mut S,
    buf: &mut [u8],
) -> std::io::Result<usize> {
    use tokio::io::AsyncReadExt;
    let n = stream.read(buf).await?;
    if n == 0 {
        return Ok(0);
    }
    // A ClientHello handshake record is: 0x16 | version(2) | len(2) | handshake...
    // If the first record is a full ClientHello and we already have it all,
    // stop reading (avoids blocking on a keep-alive connection).
    let record_len = if n >= 5 && buf[0] == 0x16 {
        (u16::from_be_bytes([buf[3], buf[4]]) as usize) + 5
    } else {
        0
    };
    if record_len > 0 && n >= record_len {
        return Ok(n);
    }
    if record_len > 0 && record_len <= buf.len() {
        let mut total = n;
        while total < record_len {
            let m = stream.read(&mut buf[total..record_len]).await?;
            if m == 0 {
                break;
            }
            total += m;
        }
        Ok(total)
    } else {
        Ok(n)
    }
}

#[cfg(not(feature = "tls"))]
pub async fn run_vhost_https_listener(
    _addr: String,
    _state: std::sync::Arc<crate::service::AppState>,
    _shutdown_token: tokio_util::sync::CancellationToken,
) -> Result<(), Box<dyn std::error::Error>> {
    Err("TLS feature not enabled".into())
}

/// Extract the SNI hostname from a TLS ClientHello message (RFC 6066 §3).
///
/// `data` must start with the TLS record header (content_type = 0x16).
/// Returns the SNI hostname if found, or None.
pub fn extract_sni_from_client_hello(data: &[u8]) -> Option<String> {
    // Minimum: TLS record header (5) + handshake header (4) + client version (2)
    // + random (32) + session_id_len (1) = 44 bytes before any variable fields
    if data.len() < 44 {
        return None;
    }

    // TLS record: content_type (1) + version (2) + length (2)
    if data[0] != 0x16 {
        return None;
    }
    let record_len = u16::from_be_bytes([data[3], data[4]]) as usize;
    if data.len() < 5 + record_len {
        return None;
    }

    let handshake = &data[5..];
    // Handshake: type (1) + length (3)
    if handshake.is_empty() || handshake[0] != 0x01 {
        return None;
    }
    if handshake.len() < 4 {
        return None;
    }
    let hs_len =
        ((handshake[1] as usize) << 16) | ((handshake[2] as usize) << 8) | (handshake[3] as usize);
    if handshake.len() < 4 + hs_len {
        return None;
    }

    let ch = &handshake[4..4 + hs_len];
    if ch.len() < 38 {
        return None;
    }

    // Skip: version (2) + random (32) = 34 bytes to reach session_id_len
    let mut pos = 34;
    if pos >= ch.len() {
        return None;
    }
    let sid_len = ch[pos] as usize;
    pos += 1 + sid_len;
    if pos + 2 > ch.len() {
        return None;
    }

    // Cipher suites
    let cs_len = u16::from_be_bytes([ch[pos], ch[pos + 1]]) as usize;
    pos += 2 + cs_len;
    if pos + 1 > ch.len() {
        return None;
    }

    // Compression methods
    let cm_len = ch[pos] as usize;
    pos += 1 + cm_len;
    if pos + 2 > ch.len() {
        return None;
    }

    // Extensions
    let ext_len = u16::from_be_bytes([ch[pos], ch[pos + 1]]) as usize;
    pos += 2;
    let ext_end = pos + ext_len;
    if ext_end > ch.len() {
        return None;
    }

    // Search extensions for SNI (type 0x0000)
    while pos + 4 <= ext_end {
        let ext_type = u16::from_be_bytes([ch[pos], ch[pos + 1]]);
        let ext_data_len = u16::from_be_bytes([ch[pos + 2], ch[pos + 3]]) as usize;
        pos += 4;

        if ext_type == 0x0000 {
            // SNI extension: ServerNameList
            if pos + 2 > ch.len() {
                return None;
            }
            let list_len = u16::from_be_bytes([ch[pos], ch[pos + 1]]) as usize;
            pos += 2;
            let list_end = pos + list_len;
            if list_end > ext_end {
                return None;
            }

            while pos + 3 <= list_end {
                let name_type = ch[pos];
                let name_len = u16::from_be_bytes([ch[pos + 1], ch[pos + 2]]) as usize;
                pos += 3;

                if name_type == 0x00 && pos + name_len <= list_end {
                    return String::from_utf8(ch[pos..pos + name_len].to_vec()).ok();
                }
                pos += name_len;
            }
            break;
        }
        pos += ext_data_len;
    }

    None
}
