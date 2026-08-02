#[cfg(feature = "tls")]
#[cfg(feature = "tls")]
use tokio::io::{AsyncReadExt, AsyncWriteExt};
#[cfg(feature = "tls")]
use tokio::net::TcpStream;
#[cfg(feature = "tls")]
#[cfg(feature = "tls")]
use tracing::{debug, warn};

use frp_core::config::PluginConfig;

#[cfg(feature = "tls")]
use super::serve_plugin;
use super::PluginHandle;

/// Start a TLS-to-raw plugin (Go frp compat: TLSToRawPlugin).
///
/// Tunnel side: frpc accepts TLS using the configured cert/key.
/// Local side: frpc connects to local service via raw TCP.
///
/// Config:
/// - plugin_local_addr: local raw TCP service address
/// - plugin_crt_path / plugin_key_path: TLS certificate and key for tunnel-side termination
/// - proxy_protocol_version: "v1" or "v2" (optional, written to raw TCP before bridging)
#[cfg(feature = "tls")]
pub async fn start_tls2raw_plugin(cfg: &PluginConfig) -> Result<PluginHandle, frp_core::Error> {
    let target_addr = if !cfg.local_addr.is_empty() {
        cfg.local_addr.clone()
    } else {
        return Err(frp_core::Error::Transport(
            "tls2raw plugin: plugin_local_addr is required".into(),
        ));
    };

    // Load TLS certificate and key — fail fast at startup (Go frp compat).
    let crt_file = if cfg.crt_file.is_empty() {
        return Err(frp_core::Error::Transport(
            "tls2raw plugin: plugin_crt_path is required".into(),
        ));
    } else {
        cfg.crt_file.clone()
    };
    let key_file = if cfg.key_file.is_empty() {
        return Err(frp_core::Error::Transport(
            "tls2raw plugin: plugin_key_path is required".into(),
        ));
    } else {
        cfg.key_file.clone()
    };

    let tls_acceptor = frp_core::transport::build_tls_acceptor(&crt_file, &key_file, None::<&str>)
        .map_err(|e| {
            frp_core::Error::Transport(format!("tls2raw plugin: TLS acceptor: {e}").into())
        })?;

    let proxy_protocol_version = cfg.proxy_protocol_version.clone();
    debug!(%target_addr, %crt_file, %key_file, %proxy_protocol_version,
        "tls2raw plugin: TLS termination → raw TCP at {target_addr}");

    let state = (target_addr, tls_acceptor, proxy_protocol_version);
    serve_plugin(
        "tls2raw",
        state,
        |mut tunnel_stream, _peer, (target, acceptor, proxy_proto_ver)| async move {
            // 1. Read PROXY protocol header from tunnel stream BEFORE TLS handshake
            //    (Go frp: connInfo.ProxyProtocolHeader is pre-read by work_conn).
            let proxy_header = match proxy_proto_ver.as_str() {
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
                _ => Vec::new(),
            };

            // 2. Perform TLS handshake on the tunnel side (Go: tls.Server).
            let mut tls_stream = match acceptor.accept(tunnel_stream).await {
                Ok(tls) => tls,
                Err(e) => {
                    warn!(%target, ?e, "tls2raw: TLS handshake failed: {e}");
                    return;
                }
            };

            // 3. Connect to local raw TCP service.
            let mut raw_conn = match TcpStream::connect(&target).await {
                Ok(c) => c,
                Err(e) => {
                    warn!(%target, ?e, "tls2raw: TCP connect to {target} failed: {e}");
                    return;
                }
            };
            frp_core::transport::set_nodelay(&raw_conn);

            // 4. Write PROXY protocol header to raw TCP before bridging
            //    (Go: connInfo.ProxyProtocolHeader.WriteTo(rawConn)).
            if !proxy_header.is_empty() {
                if let Err(e) = raw_conn.write_all(&proxy_header).await {
                    warn!(%target, ?e, "tls2raw: failed to write PROXY header: {e}");
                    return;
                }
            }

            // 5. Bridge TLS (tunnel) ↔ raw TCP (local).
            let _ = tokio::io::copy_bidirectional(&mut tls_stream, &mut raw_conn).await;
        },
    )
    .await
}

#[cfg(not(feature = "tls"))]
pub async fn start_tls2raw_plugin(_cfg: &PluginConfig) -> Result<PluginHandle, frp_core::Error> {
    Err(frp_core::Error::Transport(
        "tls2raw plugin: TLS support not compiled in".into(),
    ))
}

/// Read a PROXY protocol v1 header from the stream.
/// Returns the raw header bytes (including trailing \r\n).
#[cfg(feature = "tls")]
async fn read_proxy_header_v1(stream: &mut TcpStream) -> std::io::Result<Vec<u8>> {
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
            if !buf.starts_with(b"PROXY ") {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "PROXY v1 header must start with \"PROXY \"",
                ));
            }
            return Ok(buf[..pos + 2].to_vec());
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
/// Returns the raw header bytes.
#[cfg(feature = "tls")]
async fn read_proxy_header_v2(stream: &mut TcpStream) -> std::io::Result<Vec<u8>> {
    let mut fixed = [0u8; 16];
    stream.read_exact(&mut fixed).await?;

    const V2_SIG: &[u8; 12] = b"\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A";
    if fixed[0..12] != V2_SIG[..] {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "invalid PROXY v2 signature",
        ));
    }

    let addr_len = u16::from_be_bytes([fixed[14], fixed[15]]) as usize;
    if addr_len > 512 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("PROXY v2 address length too large: {addr_len}"),
        ));
    }

    let total_len = 16 + addr_len;
    let mut header = Vec::with_capacity(total_len);
    header.extend_from_slice(&fixed);
    let mut addr = vec![0u8; addr_len];
    stream.read_exact(&mut addr).await?;
    header.extend_from_slice(&addr);
    Ok(header)
}
