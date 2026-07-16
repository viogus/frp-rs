#[cfg(feature = "tls")]
use rustls::pki_types::ServerName;
#[cfg(feature = "tls")]
use tokio::io::{AsyncReadExt, AsyncWriteExt};
#[cfg(feature = "tls")]
use tokio::net::TcpStream;
#[cfg(feature = "tls")]
use tracing::{debug, warn};

use frp_core::config::PluginConfig;
#[cfg(feature = "tls")]
use frp_core::transport::build_tls_connector;

#[cfg(feature = "tls")]
use super::serve_plugin;
use super::PluginHandle;

/// Start a TLS-to-raw plugin.
///
/// frpc connects to the local service via TLS, then forwards through
/// the frp tunnel. frpc acts as TLS client to the local service.
///
/// Go frp compat: TLSToRawPlugin.
///
/// Config:
/// - plugin_local_addr: "127.0.0.1:8080" (the local TLS service)
/// - proxy_protocol_version: "v1" or "v2" (optional, read from tunnel
///   stream and written to raw TCP before TLS handshake)
#[cfg(feature = "tls")]
pub async fn start_tls2raw_plugin(cfg: &PluginConfig) -> Result<PluginHandle, frp_core::Error> {
    let target_addr = if !cfg.local_addr.is_empty() {
        cfg.local_addr.clone()
    } else {
        return Err(frp_core::Error::Transport(
            "tls2raw plugin: plugin_local_addr is required".into(),
        ));
    };
    // Build TLS connector once — fail fast if it can't be created.
    let tls_connector = build_tls_connector(None, None, None).map_err(|e| {
        frp_core::Error::Transport(format!("tls2raw plugin: TLS connector: {e}").into())
    })?;
    let proxy_protocol_version = cfg.proxy_protocol_version.clone();
    debug!(%target_addr, %proxy_protocol_version, "tls2raw plugin: target TLS service at {target_addr}");

    let state = (target_addr, tls_connector, proxy_protocol_version);
    serve_plugin("tls2raw", state, |mut tunnel_stream, _peer, (target, connector, proxy_proto_ver)| async move {
        // Extract hostname from target for TLS SNI.
        let host = target.rsplit_once(':').map(|(h, _)| h).unwrap_or(&target).to_string();
        let server_name = match ServerName::try_from(host) {
            Ok(n) => n,
            Err(e) => {
                warn!(%target, ?e, "tls2raw plugin: invalid hostname '{target}': {e:?}");
                return;
            }
        };

        // Read the proxy protocol header from the tunnel stream if configured.
        // work_conn.rs writes this header to the plugin's local socket before
        // bridging. The tls2raw plugin must strip it and write it to the raw
        // TCP connection BEFORE TLS handshake so the local TLS service sees
        // the real client IP/port at the TCP level (Go frp v0.70.0 compat).
        let (proxy_header, remaining_prefix) = match proxy_proto_ver.as_str() {
            "v1" => match read_proxy_header_v1(&mut tunnel_stream).await {
                Ok(h) => h,
                Err(e) => {
                    warn!(%target, ?e, "tls2raw: failed to read PROXY v1 header: {e}");
                    return;
                }
            },
            "v2" => match read_proxy_header_v2(&mut tunnel_stream).await {
                Ok(h) => h,
                Err(e) => {
                    warn!(%target, ?e, "tls2raw: failed to read PROXY v2 header: {e}");
                    return;
                }
            },
            _ => {
                // No proxy protocol configured — pass through unchanged.
                (Vec::new(), Vec::new())
            }
        };

        match TcpStream::connect(&target).await {
            Ok(mut tcp_stream) => {
                // Interactive forwarded data path — disable Nagle before writing header.
                frp_core::transport::set_nodelay(&tcp_stream);

                // Write proxy protocol header BEFORE TLS handshake (Go frp v0.70.0 compat).
                if !proxy_header.is_empty() {
                    if let Err(e) = tcp_stream.write_all(&proxy_header).await {
                        warn!(%target, ?e, "tls2raw: failed to write PROXY header: {e}");
                        return;
                    }
                }

                match connector.connect(server_name, tcp_stream).await {
                    Ok(mut tls_stream) => {
                        // Forward any pre-read bytes that were after the proxy
                        // protocol header in the tunnel stream.
                        if !remaining_prefix.is_empty() {
                            if let Err(e) = tls_stream.write_all(&remaining_prefix).await {
                                debug!(%target, ?e, "tls2raw: failed to write prefix bytes: {e}");
                                return;
                            }
                        }
                        let _ = tokio::io::copy_bidirectional(
                            &mut tunnel_stream,
                            &mut tls_stream,
                        )
                        .await;
                    }
                    Err(e) => warn!(%target, %e, "tls2raw: TLS connect to {target} failed: {e}"),
                }
            }
            Err(e) => warn!(%target, %e, "tls2raw: TCP connect to {target} failed: {e}"),
        }
    })
    .await
}

#[cfg(not(feature = "tls"))]
pub async fn start_tls2raw_plugin(_cfg: &PluginConfig) -> Result<PluginHandle, frp_core::Error> {
    Err(frp_core::Error::Transport(
        "tls2raw plugin: TLS support not compiled in".into(),
    ))
}

/// Read a PROXY protocol v1 header from the stream.
/// v1 format: "PROXY TCP4 src dst sport dport\r\n" (variable length).
/// Returns (header_bytes, remaining_bytes_after_header).
#[cfg(feature = "tls")]
async fn read_proxy_header_v1(stream: &mut TcpStream) -> std::io::Result<(Vec<u8>, Vec<u8>)> {
    let mut buf = Vec::with_capacity(128);
    let mut chunk = [0u8; 128];
    loop {
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "EOF while reading PROXY v1 header",
            ));
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(pos) = buf.windows(2).position(|w| w == b"\r\n") {
            // Validate PROXY v1 prefix before consuming the line.
            if !buf.starts_with(b"PROXY ") {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "PROXY v1 header must start with \"PROXY \"",
                ));
            }
            // Header ends at pos + 2 (inclusive of \r\n).
            let header_end = pos + 2;
            let header = buf[..header_end].to_vec();
            let remaining = buf[header_end..].to_vec();
            return Ok((header, remaining));
        }
        if buf.len() > 200 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "PROXY v1 header exceeds 200 bytes",
            ));
        }
    }
}

/// Read a PROXY protocol v2 header from the stream.
/// v2 format: 12-byte sig + 4-byte hdr + variable address block.
/// Returns (header_bytes, remaining_bytes_after_header).
#[cfg(feature = "tls")]
async fn read_proxy_header_v2(stream: &mut TcpStream) -> std::io::Result<(Vec<u8>, Vec<u8>)> {
    // Read fixed 16-byte prefix: 12 sig + 1 version|cmd + 1 transport + 2 addr_len.
    let mut fixed = [0u8; 16];
    stream.read_exact(&mut fixed).await?;

    // Validate PROXY v2 signature before parsing the address block.
    const V2_SIG: &[u8; 12] = b"\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A";
    if fixed[0..12] != V2_SIG[..] {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "invalid PROXY v2 signature",
        ));
    }

    let addr_len = u16::from_be_bytes([fixed[14], fixed[15]]) as usize;
    // Reasonable upper bound: 512 bytes covers IPv6 with TLVs.
    if addr_len > 512 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("PROXY v2 address length too large: {addr_len}"),
        ));
    }

    let total_len = 16 + addr_len;
    let mut header = Vec::with_capacity(total_len);
    header.extend_from_slice(&fixed);

    // Read address block.
    let mut addr = vec![0u8; addr_len];
    stream.read_exact(&mut addr).await?;
    header.extend_from_slice(&addr);

    // After the header, try to read any extra bytes that may have arrived
    // in the same TCP segment (tunnel data after the proxy header).
    let mut remaining = Vec::new();
    let mut probe = [0u8; 4096];
    match stream.try_read(&mut probe) {
        Ok(n) if n > 0 => {
            remaining.extend_from_slice(&probe[..n]);
        }
        Ok(_) | Err(_) => {
            // No extra data available (WouldBlock) or zero bytes — normal.
        }
    }

    Ok((header, remaining))
}
