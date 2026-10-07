use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
#[cfg(feature = "vnet")]
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use tokio::net::UdpSocket;
#[cfg(feature = "vnet")]
use tokio::sync::Mutex;
use tokio::sync::{mpsc, RwLock};
use tracing::{debug, info, warn};

use frp_core::auth::{AuthConfig, OidcClient};
use frp_core::bandwidth::SharedBandwidthLimiter;
use frp_core::cipher_stream::{CipherReader, CipherWriter};
use frp_core::encryption;
use frp_core::metrics::ProxyMetricsRegistry;
use frp_core::msg::{self, FrpMessage};
use frp_core::mux::YamuxSession;
use frp_core::protocol::{
    read_msg_v1, read_msg_v2_udp_binary_socket, read_msg_v2_with_udp_codec, write_msg_v1,
    write_msg_v2, write_msg_v2_with_udp_codec, write_v1_frame_scratch, write_v2_frame_raw,
    UdpBinaryRead, V2_FRAME_TYPE_MESSAGE,
};
#[cfg(feature = "quic")]
use frp_core::quic::QuicConnection;
use frp_core::transport::{
    dial_server, split_work_conn_halves, BoxedReadHalf, BoxedWriteHalf, DialOptions, IoStream,
};

use crate::proxy;
use crate::proxy_runtime::{ProxyPhase, ProxyRuntimeInfo};

mod udp;
use udp::run_udp_work_conn;
#[cfg(test)]
use udp::{
    now_epoch_ms, resolve_udp_local_addr, udp_addr_of, UdpSession, UdpSessionTable,
    UDP_SESSION_CAP, UDP_SESSION_IDLE_TIMEOUT, UDP_SESSION_IDLE_TIMEOUT_MS,
    UDP_WORK_CONN_PING_INTERVAL,
};

#[cfg(feature = "vnet")]
type VnetTunMap = Arc<Mutex<HashMap<String, Option<Box<dyn frp_vnet::tun::TunDevice>>>>>;

/// Per-proxy TUN delivery channels (shared type — `Arc<[u8]>` elements so a
/// fanned-out packet is shared by refcount rather than copied per peer).
#[cfg(feature = "vnet")]
type VnetTunTxMap = crate::vnet::VnetTunTxMap;

/// Maximum framed vnet message size, matching Go frp `maxMessageSize`.
#[cfg(feature = "vnet")]
const MAX_VNET_MESSAGE: u32 = 1024 * 1024;

/// Reads length-prefixed IP packets from a `virtual_net` tunnel.
///
/// Go frp v0.70.1 frames every packet as `[u32 LE length][data]` before the
/// optional compression/encryption layers. The reader first decodes the
/// transport chunk stream (decompressing Snappy when enabled), buffers the
/// decoded bytes, and then parses complete length-prefixed messages so TCP or
/// yamux coalescing/splitting cannot corrupt packet boundaries.
#[cfg(feature = "vnet")]
pub(crate) struct TunnelPacketReader<R> {
    inner: R,
    decompressor: Option<frp_core::encryption::SnappyDecompressor>,
    stream_buf: Vec<u8>,
    /// Consumed-prefix cursor into `stream_buf`: bytes before it are already
    /// delivered packets; the next frame starts at `read_pos`. Replaces the
    /// per-packet `drain(..)` (a memmove of the whole remainder — O(buffered)
    /// per packet); compaction now happens once per ~4 KiB consumed.
    read_pos: usize,
    buf: Vec<u8>,
    eof: bool,
}

#[cfg(feature = "vnet")]
impl<R: tokio::io::AsyncRead + Unpin> TunnelPacketReader<R> {
    pub(crate) fn new(inner: R, use_compression: bool) -> Self {
        let decompressor = if use_compression {
            #[cfg(feature = "compression")]
            {
                Some(frp_core::encryption::SnappyDecompressor::new())
            }
            #[cfg(not(feature = "compression"))]
            {
                None
            }
        } else {
            None
        };
        Self {
            inner,
            decompressor,
            stream_buf: Vec::new(),
            read_pos: 0,
            buf: vec![0u8; 4096],
            eof: false,
        }
    }

    /// Return the next packet, or `None` at EOF.
    pub(crate) async fn next_packet(&mut self) -> std::io::Result<Option<Vec<u8>>> {
        loop {
            // Try to extract a complete framed message from buffered bytes.
            if let Some(packet) = self.take_complete_message()? {
                return Ok(Some(packet));
            }
            if self.eof {
                return Ok(None);
            }
            let n = self.inner.read(&mut self.buf).await?;
            if n == 0 {
                self.eof = true;
                // Only bytes past the read cursor are an incomplete frame;
                // consumed bytes are already-delivered packets.
                if self.stream_buf.len() > self.read_pos {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "vnet tunnel closed with an incomplete framed packet",
                    ));
                }
                return Ok(None);
            }
            if let Some(decompressor) = &mut self.decompressor {
                // Decompressed output may contain zero, one, or several framed
                // messages; drain complete frames without blocking.
                let mut input = &self.buf[..n];
                loop {
                    let mut out = Vec::new();
                    let status = decompressor
                        .feed_into_progress(input, &mut out)
                        .map_err(std::io::Error::other)?;
                    input = &[];
                    self.stream_buf.extend_from_slice(&out);
                    if !status.has_more_complete {
                        break;
                    }
                }
            } else {
                self.stream_buf.extend_from_slice(&self.buf[..n]);
            }
        }
    }

    /// Extract one `[u32 LE length][data]` message from `stream_buf`,
    /// starting at the read cursor.
    fn take_complete_message(&mut self) -> std::io::Result<Option<Vec<u8>>> {
        let start = self.read_pos;
        if self.stream_buf.len() < start + 4 {
            return Ok(None);
        }
        let len = u32::from_le_bytes(
            self.stream_buf[start..start + 4]
                .try_into()
                .expect("stream_buf.len() >= start + 4 checked above"),
        ) as usize;
        if len == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "vnet framed message length is 0",
            ));
        }
        if len as u32 > MAX_VNET_MESSAGE {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("vnet message too large: {len} > {MAX_VNET_MESSAGE}"),
            ));
        }
        if self.stream_buf.len() < start + 4 + len {
            return Ok(None);
        }
        let packet = self.stream_buf[start + 4..start + 4 + len].to_vec();
        self.read_pos = start + 4 + len;
        // Compact the consumed prefix once it grows large (amortized O(1)
        // per byte — the old per-packet `drain(..4 + len)` memmoved the
        // whole remainder on EVERY packet). Thresholds bound the buffer at
        // ~8 KiB of consumed + unconsumed bytes before compaction.
        if self.read_pos >= 4096 && self.stream_buf.len() - self.read_pos < 4096 {
            self.stream_buf.drain(..self.read_pos);
            self.read_pos = 0;
        }
        Ok(Some(packet))
    }
}

/// Writes length-prefixed IP packets to a `virtual_net` tunnel, applying
/// Snappy compression before AES-128-CFB encryption when enabled.
#[cfg(feature = "vnet")]
#[allow(clippy::large_enum_variant)]
pub(crate) enum TunnelPacketWriter<W: tokio::io::AsyncWrite + Unpin> {
    Plain(W),
    Encrypted(CipherWriter<W>),
}

#[cfg(feature = "vnet")]
impl<W: tokio::io::AsyncWrite + Unpin> TunnelPacketWriter<W> {
    pub(crate) async fn write_packet(
        &mut self,
        packet: &[u8],
        use_compression: bool,
    ) -> std::io::Result<()> {
        let len = packet.len() as u32;
        if len == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "vnet packet data length is 0",
            ));
        }
        if len > MAX_VNET_MESSAGE {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("vnet packet too large: {len} > {MAX_VNET_MESSAGE}"),
            ));
        }
        let mut frame = Vec::with_capacity(4 + len as usize);
        frame.extend_from_slice(&len.to_le_bytes());
        frame.extend_from_slice(packet);
        if use_compression {
            let mut compressed = Vec::new();
            frp_core::encryption::compress_into(&frame, &mut compressed)
                .map_err(std::io::Error::other)?;
            self.write_all(&compressed).await
        } else {
            self.write_all(&frame).await
        }
    }

    pub(crate) async fn write_all(&mut self, data: &[u8]) -> std::io::Result<()> {
        match self {
            Self::Plain(w) => w.write_all(data).await,
            Self::Encrypted(w) => w.write_all(data).await,
        }
    }

    pub(crate) async fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Self::Plain(w) => w.flush().await,
            Self::Encrypted(w) => w.flush().await,
        }
    }
}

/// Conditional type for the QUIC connection parameter.
/// When the `quic` feature is disabled, the parameter is `()` (ZST, no-op).
#[cfg(feature = "quic")]
type QuicConnOpt = Option<Arc<QuicConnection>>;
#[cfg(not(feature = "quic"))]
type QuicConnOpt = ();

/// Notification from a work connection that an XTCP NatHoleSid was received.
/// Sent to the control message loop so it can do STUN and send NatHoleClient.
#[derive(Debug)]
pub(crate) struct XtcpNotification {
    pub sid: String,
    pub proxy_name: String,
}

/// Check if an auth scope is enabled, considering both client and server config.
pub(crate) fn scope_requires_auth(
    client_scopes: &[String],
    server_scopes: &[String],
    scope: &str,
) -> bool {
    client_scopes.iter().any(|s| s == scope) || server_scopes.iter().any(|s| s == scope)
}

/// Configuration for spawning a work connection.
pub(crate) struct WorkConnConfig {
    pub server_addr: String,
    pub server_port: u16,
    pub protocol: frp_core::transport::TransportProtocol,
    pub run_id: String,
    pub proxy_info_map: Arc<RwLock<HashMap<String, ProxyRuntimeInfo>>>,
    pub enc_key: [u8; 16],
    pub pool_id: i32,
    pub auth_cfg: Arc<AuthConfig>,
    pub tls_enable: bool,
    pub tls_server_name: String,
    pub tls_ca_file: Option<String>,
    pub tls_cert_file: Option<String>,
    pub tls_key_file: Option<String>,
    /// Custom DNS server for resolving server_addr (and local backends).
    pub dns_server: Option<String>,
    pub yamux: Option<Arc<YamuxSession>>,
    pub quic_conn: QuicConnOpt,
    pub v2: bool,
    pub oidc_client: Option<Arc<OidcClient>>,
    /// UDP read buffer size. Go frp compat: clientCfg.UDPPacketSize.
    pub udp_packet_size: usize,
    pub proxy_metrics: Arc<ProxyMetricsRegistry>,
    pub client_auth_scopes: Vec<String>,
    pub server_auth_scopes: Vec<String>,
    pub disable_custom_tls_first_byte: bool,
    /// Dial-time TCP keepalive interval in seconds (socket-level, forwarded
    /// to `DialOptions.keepalive_secs` → socket2 SO_KEEPALIVE). This is the
    /// transport layer Go frp enables on control/work conns; it is NOT the
    /// UDP work-conn application-level pinger, whose interval is the fixed
    /// `UDP_WORK_CONN_PING_INTERVAL` (30s Go parity) and never reads this
    /// field (audit F1).
    pub keepalive_secs: u64,
    pub bind_addr: Option<String>,
    pub proxy_url: String,
    pub dial_timeout_secs: u64,
    pub xtcp_tx: mpsc::Sender<XtcpNotification>,
    pub session_alive: Arc<AtomicBool>,
    /// Negotiated UDPPacket codec for V2 data planes (`"binary-v1"` or
    /// empty; Go frp v0.71.0). Passed to UDP/SUDP work-conn bridges.
    pub udp_packet_codec: String,
    /// Test-only probe: each spawned work-conn task increments this counter when
    /// it starts. Always `None` in production configs.
    pub spawned_counter: Option<Arc<std::sync::atomic::AtomicUsize>>,
    #[cfg(feature = "vnet")]
    pub vnet_tuns: VnetTunMap,
    #[cfg(feature = "vnet")]
    pub vnet_controller: Arc<frp_vnet::controller::ClientVnetController>,
    #[cfg(feature = "vnet")]
    pub vnet_tun_tx: VnetTunTxMap,
}

/// Bundled parameters for work connection transport acquisition.
/// Extracted from `connect_yamux_or_dial` to keep the argument count manageable.
struct WorkConnDialConfig<'a> {
    yamux: &'a Option<Arc<YamuxSession>>,
    label: &'a str,
    server_addr: &'a str,
    server_port: u16,
    protocol: &'a frp_core::transport::TransportProtocol,
    tls_enable: bool,
    tls_server_name: &'a str,
    tls_ca_file: &'a Option<String>,
    tls_cert_file: &'a Option<String>,
    tls_key_file: &'a Option<String>,
    disable_custom_tls_first_byte: bool,
    keepalive_secs: u64,
    bind_addr: &'a Option<String>,
    proxy_url: &'a str,
    dial_timeout_secs: u64,
}

/// Bind a fresh UDP socket connected to the local service address (Go frp
/// compat: each wrapper binds its own socket). Used both at session start
/// and to rebuild the socket after a hot reload changes the target address.
/// Shared yamux-or-dial path for work connection transport acquisition.
/// Used by both QUIC and non-QUIC branches.
async fn connect_yamux_or_dial(cfg: &WorkConnDialConfig<'_>) -> Option<IoStream> {
    if let Some(ref yamux) = *cfg.yamux {
        match yamux.open_stream().await {
            Some(stream) => {
                debug!(label = %cfg.label, "Work conn {} opened yamux stream", cfg.label);
                Some(IoStream::Yamux(stream))
            }
            None => {
                warn!(label = %cfg.label, "Work conn {}: yamux open stream failed, session closed?", cfg.label);
                None
            }
        }
    } else {
        debug!(label = %cfg.label, "Work conn {} dialing server", cfg.label);
        let opts = DialOptions {
            server_addr: cfg.server_addr.to_string(),
            server_port: cfg.server_port,
            protocol: cfg.protocol.clone(),
            tls_enable: cfg.tls_enable,
            tls_server_name: cfg.tls_server_name.to_string(),
            tls_ca_file: cfg.tls_ca_file.clone(),
            tls_cert_file: cfg.tls_cert_file.clone(),
            tls_key_file: cfg.tls_key_file.clone(),
            disable_custom_tls_first_byte: cfg.disable_custom_tls_first_byte,
            keepalive_secs: cfg.keepalive_secs,
            bind_addr: cfg.bind_addr.clone(),
            proxy_url: if cfg.proxy_url.is_empty() {
                None
            } else {
                Some(cfg.proxy_url.to_string())
            },
            dial_timeout_secs: cfg.dial_timeout_secs,
            ..Default::default()
        };
        match dial_server(&opts).await {
            Ok(io) => Some(io),
            Err(e) => {
                debug!(label = %cfg.label, error = %e, "Work conn {} dial failed: {}", cfg.label, e);
                None
            }
        }
    }
}

fn start_work_conn_timeout(dial_timeout_secs: u64) -> Duration {
    Duration::from_secs(dial_timeout_secs.max(1))
}

async fn read_start_work_conn_with_timeout(
    work: &mut IoStream,
    v2: bool,
    timeout: Duration,
) -> std::io::Result<FrpMessage> {
    // Rust-only transport safety: Go frp v0.70.1 has no client-side timeout for
    // StartWorkConn. This bounds only the dial/handshake phase and is dropped as
    // soon as StartWorkConn arrives, so it never limits a long-lived bridge.
    tokio::time::timeout(timeout, async {
        if v2 {
            work.read_v2_frame().await
        } else {
            work.read_v1_frame().await
        }
    })
    .await
    .map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "timed out waiting for StartWorkConn",
        )
    })?
    .map_err(std::io::Error::other)
}

/// Bridge a `virtual_net` plugin work connection to the shared vnet controller.
///
/// Equivalent to Go frp's `VnetController.StartServerConnReadLoop`: bytes
/// arriving from the remote visitor tunnel are written into the local TUN,
/// and the remote source IP is registered so TUN return packets are written
/// back to this work connection.
#[cfg(feature = "vnet")]
async fn run_virtual_net_plugin_work_conn(
    work: IoStream,
    proxy_name: String,
    vnet_controller: Arc<frp_vnet::controller::ClientVnetController>,
    vnet_tun_tx: VnetTunTxMap,
    use_encryption: bool,
    use_compression: bool,
    enc_key: [u8; 16],
) {
    let tun_tx = {
        let txs = vnet_tun_tx.lock().unwrap_or_else(|e| e.into_inner());
        txs.get(&proxy_name).cloned()
    };
    let Some(tun_tx) = tun_tx else {
        warn!(proxy_name = %proxy_name, "virtual_net plugin: no TUN channel for '{}'", proxy_name);
        return;
    };

    let (work_r, work_w) = match work.into_split() {
        Ok(halves) => halves,
        Err(e) => {
            warn!(
                proxy_name = %proxy_name,
                error = %e,
                "virtual_net plugin work conn split failed: {}",
                e
            );
            return;
        }
    };
    // into_split already returns boxed halves — only the encrypted branch
    // re-boxes (the CipherReader wrapper).
    let work_r: Box<dyn tokio::io::AsyncRead + Unpin + Send> = if use_encryption {
        Box::new(CipherReader::new(work_r, enc_key))
    } else {
        work_r
    };
    let mut packet_reader = TunnelPacketReader::new(work_r, use_compression);
    let mut packet_writer = if use_encryption {
        // Audit B2: OS-RNG failure (IV generation) ends this tunnel setup
        // instead of aborting the process.
        match CipherWriter::new(work_w, enc_key) {
            Ok(w) => TunnelPacketWriter::Encrypted(w),
            Err(e) => {
                warn!(error = %e, "vnet tunnel: IV generation failed");
                return;
            }
        }
    } else {
        TunnelPacketWriter::Plain(work_w)
    };
    // Eagerly send the encrypted writer's IV so the peer's CipherReader can
    // proceed even before the first return packet arrives.
    if let Err(e) = packet_writer.flush().await {
        warn!(
            proxy_name = %proxy_name,
            error = %e,
            "virtual_net plugin work conn IV flush failed: {}",
            e
        );
        return;
    }

    let (return_tx, mut return_rx) = mpsc::channel::<Vec<u8>>(256);
    let (cancel_tx, cancel_rx) = tokio::sync::watch::channel(false);

    let reader_name = proxy_name.clone();
    let reader_ctrl = vnet_controller.clone();
    let reader_rtx = return_tx.clone();
    let reader_tun = tun_tx;
    let mut reader_cancel = cancel_rx.clone();
    let reader = async move {
        let mut registered_ips = Vec::<std::net::IpAddr>::new();
        loop {
            tokio::select! {
                biased;
                changed = reader_cancel.changed() => {
                    if changed.is_err() || *reader_cancel.borrow() { break; }
                }
                packet = packet_reader.next_packet() => {
                    match packet {
                        Ok(None) => break,
                        Ok(Some(packet)) => {
                            // Learn the remote host's source IP so return
                            // packets can be routed back on this connection.
                            // The mapping is effectively per-connection, so
                            // register only the first time an IP is seen.
                            if let Some(src_ip) = frp_vnet::router::packet_src_ip(&packet) {
                                if !registered_ips.contains(&src_ip) {
                                    reader_ctrl.register_server_conn(src_ip, reader_rtx.clone());
                                    registered_ips.push(src_ip);
                                }
                            }
                            // Single destination: the decoded Vec moves into
                            // the shared buffer type (no copy on an exact-fit
                            // allocation, one copy otherwise).
                            if let Err(e) = reader_tun.try_send(Arc::from(packet)) {
                                match e {
                                    mpsc::error::TrySendError::Full(_) => {
                                        warn!(
                                            proxy_name = %reader_name,
                                            "virtual_net plugin TUN queue full; dropping packet"
                                        );
                                    }
                                    mpsc::error::TrySendError::Closed(_) => break,
                                }
                            }
                        }
                        Err(e) => {
                            warn!(
                                proxy_name = %reader_name,
                                error = %e,
                                "virtual_net plugin work conn read error: {}",
                                e
                            );
                            break;
                        }
                    }
                }
            }
        }
        for src_ip in &registered_ips {
            reader_ctrl.unregister_server_conn_if_matches(src_ip, &reader_rtx);
        }
    };

    let writer_name = proxy_name;
    let mut writer_cancel = cancel_rx;
    let writer = async move {
        loop {
            tokio::select! {
                biased;
                changed = writer_cancel.changed() => {
                    if changed.is_err() || *writer_cancel.borrow() { break; }
                }
                pkt = return_rx.recv() => {
                    match pkt {
                        Some(pkt) => {
                            if let Err(e) = packet_writer.write_packet(&pkt, use_compression).await {
                                warn!(
                                    proxy_name = %writer_name,
                                    error = %e,
                                    "virtual_net plugin work conn write error: {}",
                                    e
                                );
                                break;
                            }
                        }
                        None => break,
                    }
                }
            }
        }
    };

    tokio::pin!(reader, writer);
    tokio::select! {
        _ = &mut reader => {
            let _ = cancel_tx.send(true);
            let _ = tokio::time::timeout(Duration::from_millis(100), &mut writer).await;
        }
        _ = &mut writer => {
            let _ = cancel_tx.send(true);
            let _ = tokio::time::timeout(Duration::from_millis(100), &mut reader).await;
        }
    }
}

/// Spawn a single work connection task.
///
/// The task:
/// 1. Under TcpMux: opens a yamux stream on the shared session
///    Without TcpMux: dials the server via TCP/TLS/WS
/// 2. Without TcpMux: sends NewWorkConn (with run_id + auth)
/// 3. Reads StartWorkConn from the server
/// 4. Connects to the local service
/// 5. Bridges data bidirectionally
///
/// `pool_id` is for logging only (< 0 means on-demand).
///
/// Returns the task's `JoinHandle`. The session (`handle_req_work_conn`)
/// tracks it and aborts it at teardown: a standalone work conn owns its
/// own connection to the server and must not outlive its session.
pub(crate) fn spawn_work_conn(cfg: WorkConnConfig) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        if let Some(counter) = &cfg.spawned_counter {
            counter.fetch_add(1, Ordering::SeqCst);
        }

        let WorkConnConfig {
            server_addr,
            server_port,
            protocol,
            run_id,
            proxy_info_map,
            enc_key,
            pool_id,
            auth_cfg,
            tls_enable,
            tls_server_name,
            tls_ca_file,
            tls_cert_file,
            tls_key_file,
            dns_server,
            yamux,
            quic_conn: _quic_conn,
            v2,
            oidc_client,
            udp_packet_size,
            proxy_metrics,
            client_auth_scopes: client_scopes,
            server_auth_scopes: server_scopes,
            disable_custom_tls_first_byte,
            keepalive_secs,
            bind_addr,
            proxy_url,
            dial_timeout_secs,
            xtcp_tx,
            session_alive,
            udp_packet_codec,
            spawned_counter: _spawned_counter,
            #[cfg(feature = "vnet")]
                vnet_tuns: _vnet_tuns,
            #[cfg(feature = "vnet")]
            vnet_controller,
            #[cfg(feature = "vnet")]
            vnet_tun_tx,
        } = cfg;

        let label = if pool_id >= 0 {
            format!("pool-{}", pool_id)
        } else {
            "on-demand".to_string()
        };

        // Acquire the underlying transport stream.
        // Priority: QUIC multi-stream > TcpMux yamux > direct dial.
        // Go frp compat: QUIC work connections open new streams on the
        // existing QUIC connection (multi-stream-per-connection).
        #[cfg(feature = "quic")]
        let mut work = if let Some(ref quic) = _quic_conn {
            match quic.open_bi().await {
                Ok(stream) => {
                    debug!(label = %label, "Work conn {} opened QUIC stream", label);
                    IoStream::Quic(stream)
                }
                Err(e) => {
                    warn!(label = %label, error = %e, "Work conn {}: QUIC open_bi failed: {}", label, e);
                    return;
                }
            }
        } else {
            let dial_cfg = WorkConnDialConfig {
                yamux: &yamux,
                label: &label,
                server_addr: &server_addr,
                server_port,
                protocol: &protocol,
                tls_enable,
                tls_server_name: &tls_server_name,
                tls_ca_file: &tls_ca_file,
                tls_cert_file: &tls_cert_file,
                tls_key_file: &tls_key_file,
                disable_custom_tls_first_byte,
                keepalive_secs,
                bind_addr: &bind_addr,
                proxy_url: &proxy_url,
                dial_timeout_secs,
            };
            match connect_yamux_or_dial(&dial_cfg).await {
                Some(io) => io,
                None => return,
            }
        };

        #[cfg(not(feature = "quic"))]
        let dial_cfg = WorkConnDialConfig {
            yamux: &yamux,
            label: &label,
            server_addr: &server_addr,
            server_port,
            protocol: &protocol,
            tls_enable,
            tls_server_name: &tls_server_name,
            tls_ca_file: &tls_ca_file,
            tls_cert_file: &tls_cert_file,
            tls_key_file: &tls_key_file,
            disable_custom_tls_first_byte,
            keepalive_secs,
            bind_addr: &bind_addr,
            proxy_url: &proxy_url,
            dial_timeout_secs,
        };
        #[cfg(not(feature = "quic"))]
        let mut work = match connect_yamux_or_dial(&dial_cfg).await {
            Some(io) => io,
            None => return,
        };

        // Send NewWorkConn — required for both yamux and raw transports.
        // Go frps needs the run_id and auth to associate the stream.
        {
            let mut nwc_msg = msg::NewWorkConn {
                run_id: Some(run_id.clone()),
                timestamp: None,
                privilege_key: None,
            };
            let requires_auth = scope_requires_auth(&client_scopes, &server_scopes, "NewWorkConns");
            if requires_auth {
                if let Some(ref oidc) = oidc_client {
                    if let Err(e) = oidc.set_new_work_conn(&mut nwc_msg).await {
                        warn!(label = %label, error = %e, "Work conn {} OIDC NewWorkConn auth failed: {}", label, e);
                        return;
                    }
                } else {
                    let timestamp = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_millis() as i64;
                    match auth_cfg.try_generate_login_key(timestamp) {
                        Ok(key) => {
                            nwc_msg.privilege_key = Some(key);
                            nwc_msg.timestamp = Some(timestamp);
                        }
                        Err(e) => {
                            warn!(label = %label, error = %e, "Work conn {} token source failed: {}", label, e);
                            return;
                        }
                    }
                }
            }
            // Write V2 magic before NewWorkConn on work connection streams.
            // Both Go frp and Rust frp write V2 magic on yamux work conn
            // streams, matching Go frp's messageConnector.Connect() which
            // calls WriteMagicIfV2 before returning the stream.
            if v2 {
                if let Err(e) = frp_core::protocol::write_v2_magic(&mut work).await {
                    warn!(label = %label, error = %e, "Work conn {} failed to write V2 magic: {}", label, e);
                    return;
                }
            }
            let nwc = FrpMessage::NewWorkConn(nwc_msg);
            let write_result = if v2 {
                work.write_v2_frame(&nwc).await
            } else {
                work.write_v1_frame(&nwc).await
            };
            if let Err(e) = write_result {
                warn!(label = %label, error = %e, "Work conn {} failed to send NewWorkConn: {}", label, e);
                return;
            }
            debug!(label = %label, "Work conn {} sent NewWorkConn, waiting for StartWorkConn", label);
        }

        // Read StartWorkConn
        let swc_result = read_start_work_conn_with_timeout(
            &mut work,
            v2,
            start_work_conn_timeout(dial_timeout_secs),
        )
        .await;
        match swc_result {
            Ok(FrpMessage::StartWorkConn(swc)) => {
                // Go parity (client/control.go InWorkConn): the server's
                // rejection of a work conn arrives as StartWorkConn with an
                // Error field set — log it and close instead of looking the
                // proxy up and bridging a rejected conn. Go gates on
                // `startMsg.Error != ""` (client/control.go:152), so an
                // EMPTY error string is a normal assignment — the filter
                // below mirrors that: `Some("")` must not be treated as a
                // rejection.
                if let Some(err) = swc.error.as_deref().filter(|e| !e.is_empty()) {
                    warn!(label = %label, error = %err, "Work conn {} StartWorkConn contains error: {}", label, err);
                    return;
                }
                let proxy_name = &swc.proxy_name;
                debug!(label = %label, proxy_name = %proxy_name, "Work conn {} assigned to proxy '{}'", label, proxy_name);
                // proxy_info_map uses wire names (with {user}. prefix) —
                // look up directly without stripping.
                let proxy_name = proxy_name.to_string();

                // Look up the proxy runtime info
                let info = {
                    let map = proxy_info_map.read().await;
                    map.get(&proxy_name).cloned()
                };
                let info = match info {
                    Some(info) => info,
                    None => {
                        warn!(label = %label, proxy_name = %proxy_name, "Work conn {}: unknown proxy '{}'", label, proxy_name);
                        return;
                    }
                };

                // Go frp v0.71.0 parity (client/proxy/proxy_wrapper.go
                // InWorkConn, lines 266-277): a work conn is bridged only
                // when the proxy phase is Running — otherwise the conn is
                // closed unbridged. A StartWorkConn racing a stop/reload
                // (phase WaitStart/StartErr/Closed/...) must not bridge to
                // the local service. Unknown proxies are handled above.
                if info.phase != ProxyPhase::Running {
                    warn!(label = %label, proxy_name = %proxy_name, phase = %info.phase.as_str(), "Work conn {}: proxy '{}' not running (phase {}), closing work conn", label, proxy_name, info.phase.as_str());
                    return;
                }

                if info.proxy_type == "xtcp" {
                    // XTCP proxy: after StartWorkConn, the next data on the work
                    // connection is either a NatHoleSid frame (XTCP notification)
                    // or raw bridge data (STCP fallback).
                    //
                    // Rust frps embeds nat_hole_sid in StartWorkConn JSON (new).
                    // Go frps sends a separate NatHoleSid V1 frame after (old).
                    // Check the embedded field first, then fall back to byte-peek.
                    if let Some(sid) = swc.nat_hole_sid.clone() {
                        if sid.is_empty() {
                            // STCP fallback marker from Rust frps.
                            // nat_hole_sid: Some("") (empty string) signals
                            // that this work conn is for STCP bridging, not
                            // XTCP notification. No dummy frame follows —
                            // the StartWorkConn payload is immediately
                            // followed by bridge data.
                            debug!(label = %label, proxy_name = %proxy_name, "XTCP work conn {}: STCP fallback for '{}'", label, proxy_name);
                            // Fall through to bridging
                        } else {
                            debug!(label = %label, proxy_name = %proxy_name, "XTCP work conn {}: NatHoleSid in StartWorkConn for '{}'", label, proxy_name);
                            // send().await: backpressure is correct here —
                            // if the control loop cannot drain XTCP notifications,
                            // the work connection should wait rather than silently
                            // drop the notification (which would hang the visitor).
                            let _ = xtcp_tx
                                .send(XtcpNotification {
                                    sid,
                                    proxy_name: proxy_name.clone(),
                                })
                                .await;
                            return; // XTCP notification: work conn consumed
                        }
                    }

                    // No embedded sid. Could be Go frps XTCP notification
                    // (separate NatHoleSid V1 frame with type byte 0x35 follows)
                    // or STCP fallback (bridge data follows).
                    // Byte-peek: read 1 byte, check if it's NatHoleSid type.
                    if !v2 {
                        use tokio::io::AsyncReadExt;
                        // Round 6 (LOW B3): the three probe reads below
                        // (1-byte peek, 8-byte header, length payload) were
                        // UNBOUNDED — a Go frps that sends StartWorkConn and
                        // then goes silent would park this task (and its fd)
                        // forever, since nothing else ever reads this conn.
                        // Each step gets the same dial-phase timeout as the
                        // StartWorkConn read; a timeout falls into the same
                        // recovery as a read failure (wrap consumed bytes as
                        // bridge data, or EOF-bridge for a timeout before any
                        // byte arrived).
                        let probe_timeout = start_work_conn_timeout(dial_timeout_secs);
                        let mut peek = [0u8; 1];
                        match tokio::time::timeout(probe_timeout, work.read_exact(&mut peek)).await
                        {
                            Ok(Ok(_)) if peek[0] == msg::TYPE_NAT_HOLE_SID => {
                                // Likely Go frps NatHoleSid V1 frame.
                                // Read remaining 8 header bytes + payload.
                                let mut header = [0u8; 8];
                                let mut consumed = vec![msg::TYPE_NAT_HOLE_SID];
                                match tokio::time::timeout(
                                    probe_timeout,
                                    work.read_exact(&mut header),
                                )
                                .await
                                {
                                    Ok(Ok(_)) => {
                                        consumed.extend_from_slice(&header);
                                        let length = i64::from_be_bytes(header);
                                        if (0..=frp_core::protocol::V1_MAX_MSG_LENGTH)
                                            .contains(&length)
                                        {
                                            let mut payload = vec![0u8; length as usize];
                                            // B3: payload read bounded like the
                                            // peek/header reads above.
                                            if tokio::time::timeout(
                                                probe_timeout,
                                                work.read_exact(&mut payload),
                                            )
                                            .await
                                            .is_ok_and(|r| r.is_ok())
                                            {
                                                consumed.extend_from_slice(&payload);
                                                match serde_json::from_slice::<msg::NatHoleSid>(
                                                    &payload,
                                                ) {
                                                    Ok(sid_msg) => {
                                                        if let Some(sid) = sid_msg.sid {
                                                            debug!(label = %label, proxy_name = %proxy_name, "XTCP work conn {}: NatHoleSid (Go frps) for '{}'", label, proxy_name);
                                                            let _ = xtcp_tx
                                                                .send(XtcpNotification {
                                                                    sid,
                                                                    proxy_name: proxy_name.clone(),
                                                                })
                                                                .await;
                                                            return;
                                                        }
                                                        // sid=None: STCP fallback (Go frps — unlikely)
                                                        debug!(label = %label, "XTCP work conn {}: NatHoleSid without sid (Go frps STCP fallback)", label);
                                                        // Fall through to bridging — no pre-read needed (NatHoleSid consumed).
                                                    }
                                                    _ => {
                                                        // Parsed as non-NatHoleSid — bridge data with a
                                                        // very unlikely 0x35 collision. Wrap consumed bytes.
                                                        work = IoStream::BufferedRead(
                                                            consumed,
                                                            0,
                                                            Box::new(work),
                                                        );
                                                    }
                                                }
                                            } else {
                                                // Payload read failed — wrap consumed header bytes.
                                                work = IoStream::BufferedRead(
                                                    consumed,
                                                    0,
                                                    Box::new(work),
                                                );
                                            }
                                        } else {
                                            // Invalid V1 length — wrap consumed header bytes.
                                            work =
                                                IoStream::BufferedRead(consumed, 0, Box::new(work));
                                        }
                                    }
                                    Ok(Err(_)) | Err(_) => {
                                        // Header read failed after 0x35 (EOF, or
                                        // B3 probe timeout) — wrap the 1 peeked byte.
                                        work = IoStream::BufferedRead(consumed, 0, Box::new(work));
                                    }
                                }
                            }
                            Ok(Ok(_)) => {
                                // Not 0x35 — STCP fallback. Wrap the peeked byte
                                // as pre-read bridge data.
                                work = IoStream::BufferedRead(vec![peek[0]], 0, Box::new(work));
                            }
                            Ok(Err(_)) => {
                                // EOF after StartWorkConn — bridge will get 0 bytes.
                            }
                            Err(_) => {
                                // B3 probe timeout before any byte arrived —
                                // nothing consumed, same recovery as EOF.
                            }
                        }
                    }
                    // V2: read one frame and check for NatHoleSid.
                    // Rust frps sends a V2 NatHoleSid frame after StartWorkConn
                    // for XTCP notification (separate frame for Go frp compat).
                    // Go frp v0.69.1 doesn't support V2 XTCP, so this is
                    // Rust↔Rust only.
                    if v2 {
                        use frp_core::protocol::{read_v2_frame_raw, V2_FRAME_TYPE_MESSAGE};
                        let mut peek_buf = Vec::new();
                        match read_v2_frame_raw(&mut work).await {
                            Ok((V2_FRAME_TYPE_MESSAGE, flags, payload)) => {
                                peek_buf.extend_from_slice(&V2_FRAME_TYPE_MESSAGE.to_be_bytes());
                                peek_buf.extend_from_slice(&flags.to_be_bytes());
                                peek_buf.extend_from_slice(&(payload.len() as u32).to_be_bytes());
                                peek_buf.extend_from_slice(&payload);
                                if payload.len() >= 2 {
                                    let type_id = u16::from_be_bytes([payload[0], payload[1]]);
                                    if type_id == msg::V2_TYPE_NAT_HOLE_SID {
                                        if let Ok(sid_msg) =
                                            serde_json::from_slice::<msg::NatHoleSid>(&payload[2..])
                                        {
                                            if let Some(sid) = sid_msg.sid {
                                                if !sid.is_empty() {
                                                    debug!(label = %label, proxy_name = %proxy_name, "XTCP work conn {}: NatHoleSid (V2) for '{}'", label, proxy_name);
                                                    let _ = xtcp_tx
                                                        .send(XtcpNotification {
                                                            sid,
                                                            proxy_name: proxy_name.clone(),
                                                        })
                                                        .await;
                                                    return;
                                                }
                                            }
                                            // sid=None or empty: STCP fallback — replay frame
                                        }
                                    }
                                }
                                // Not a NatHoleSid with non-empty sid — replay for STCP bridging
                                work = IoStream::BufferedRead(peek_buf, 0, Box::new(work));
                            }
                            Ok((frame_type, flags, payload)) => {
                                // Non-Message frame type — replay for STCP bridging
                                peek_buf.extend_from_slice(&frame_type.to_be_bytes());
                                peek_buf.extend_from_slice(&flags.to_be_bytes());
                                peek_buf.extend_from_slice(&(payload.len() as u32).to_be_bytes());
                                peek_buf.extend_from_slice(&payload);
                                work = IoStream::BufferedRead(peek_buf, 0, Box::new(work));
                            }
                            Err(_) => {
                                // Not a V2 frame — raw bridge data for STCP fallback.
                                // read_v2_frame_raw already consumed some bytes; the
                                // stream is in an indeterminate state. Fall through to
                                // bridging — the bridge will get an error or partial data.
                            }
                        }
                    }

                    // Fall through to normal bridging for STCP fallback
                }

                #[cfg(feature = "vnet")]
                if info.proxy_type == "vnet" {
                    // VnetController is spawned in the service layer after TUN
                    // creation. The work connection for vnet proxies carries
                    // StartWorkConn for connection lifecycle signaling;
                    // VnetPackets flow on the control connection.
                    info!(label = %label, proxy_name = %proxy_name, "vnet work conn established (controller in service layer)");
                    return;
                }

                #[cfg(feature = "vnet")]
                if info.plugin == "virtual_net" {
                    info!(label = %label, proxy_name = %proxy_name, "Work conn {} handed to virtual_net plugin controller", label);
                    let use_enc = swc.use_encryption.unwrap_or(info.use_encryption);
                    let use_comp = swc.use_compression.unwrap_or(info.use_compression);
                    run_virtual_net_plugin_work_conn(
                        work,
                        proxy_name.clone(),
                        vnet_controller,
                        vnet_tun_tx,
                        use_enc,
                        use_comp,
                        enc_key,
                    )
                    .await;
                    return;
                }

                if info.proxy_type == "udp" || info.proxy_type == "sudp" {
                    // UDP/SUDP proxy: bridge work conn ↔ local UDP service.
                    // Each distinct remote visitor gets its own ephemeral
                    // local socket inside run_udp_work_conn (Go frp
                    // per-remote semantics), so no session-scoped shared
                    // socket is needed here — reload changes to
                    // local_addr/encryption apply naturally on the next
                    // work conn.
                    let is_sudp = info.proxy_type == "sudp";
                    // Provider-segment encryption honors the proxy config for
                    // UDP and SUDP alike (Go frp three-stage model): the work
                    // conn stream is wrapped in CipherReader/CipherWriter with
                    // the token-derived key inside run_udp_work_conn. SUDP
                    // compression stays off (the per-packet compression model
                    // is not unified with Go's stream compression).
                    let use_enc = info.use_encryption;
                    let use_comp = info.use_compression && !is_sudp;

                    info!(label = %label, proxy_name = %proxy_name, use_enc = %use_enc, use_comp = %use_comp,
                        "Work conn {} bridging UDP for '{}' (enc={}, comp={})",
                        label, proxy_name, use_enc, use_comp);

                    run_udp_work_conn(
                        work,
                        proxy_name.clone(),
                        info.local_addr.clone(),
                        enc_key,
                        use_enc,
                        use_comp,
                        v2,
                        session_alive.clone(),
                        udp_packet_size,
                        info.proxy_protocol_version.clone(),
                        info.bandwidth_limiter.clone(),
                        udp_packet_codec.clone(),
                    )
                    .await;
                } else {
                    // Check if session is still alive before bridging
                    if !session_alive.load(Ordering::Acquire) {
                        debug!(label = %label, "Work conn {}: session dead, skipping bridge", label);
                        return;
                    }
                    // TCP/HTTP/STCP: connect to local TCP service and bridge
                    match proxy::connect_local_with_dns(&info.local_addr, dns_server.as_deref())
                        .await
                    {
                        Ok(mut local) => {
                            // M9 (Go http_common.go:116-117 parity): hand the
                            // https2http/https2https plugins the real tunnel
                            // peer — their listener is loopback, so without
                            // this X-Forwarded-For would carry 127.0.0.1. Go
                            // wraps the conn and calls
                            // SetRemoteAddr(connInfo.SrcAddr); here the plugin
                            // accept handler looks the real addr up by this
                            // dial's local ephemeral port. F5: the returned
                            // guard removes the registry entry when this task's
                            // scope ends — normal bridge end, early return, or
                            // abort (dropping the future drops the guard);
                            // the accept-handler take consumes the entry long
                            // before then (the plugin accept fires once the
                            // listener wakes, while the bridge below is still
                            // running). The guard MUST bind at this arm scope:
                            // audit R1 caught a nested binding whose Drop fired
                            // nanoseconds after insert — the entry was removed
                            // before the accept handler's 8×1ms plugin_peer_ip
                            // retry could take it, so every tunneled request
                            // fell back to X-Forwarded-For: 127.0.0.1.
                            let mut _plugin_peer_guard: Option<crate::plugin::PluginPeerGuard> =
                                None;
                            if matches!(info.plugin.as_str(), "https2http" | "https2https") {
                                if let (Some(src), Some(src_port)) =
                                    (swc.src_addr.as_deref(), swc.src_port)
                                {
                                    if let Ok(real_ip) = src.parse::<std::net::IpAddr>() {
                                        if let Ok(dialer_local) = local.local_addr() {
                                            _plugin_peer_guard =
                                                Some(crate::plugin::register_plugin_peer(
                                                    dialer_local.port(),
                                                    std::net::SocketAddr::new(real_ip, src_port),
                                                ));
                                        }
                                    }
                                }
                            }
                            // Write PROXY protocol header if configured. Go
                            // parity (client/proxy/proxy.go:183-197,210,
                            // f6688e2): the header is only emitted when the
                            // source address is non-empty AND the source
                            // port is non-zero; an empty destination address
                            // defaults to "127.0.0.1" (Go net.ResolveTCPAddr
                            // with the pre-set localhost default) and both
                            // addresses are resolved as IpAddr. A resolution
                            // failure logs and skips the header (Go closes
                            // the conn — the header is informational,
                            // dropping it keeps the data plane alive).
                            let src_port = swc.src_port.unwrap_or(0);
                            if !info.proxy_protocol_version.is_empty()
                                && swc.src_addr.is_some()
                                && src_port != 0
                            {
                                if let Some(ref src) = swc.src_addr {
                                    let dst = swc.dst_addr.as_deref().unwrap_or("127.0.0.1");
                                    if info.proxy_protocol_version == "v1" {
                                        match frp_core::proxy_protocol::build_proxy_protocol_v1(
                                            src,
                                            dst,
                                            src_port,
                                            swc.dst_port.unwrap_or(0),
                                        ) {
                                            Ok(header) => {
                                                if let Err(e) =
                                                    local.write_all(header.as_bytes()).await
                                                {
                                                    warn!(error = %e, "Failed to write PROXY v1 header: {}", e);
                                                }
                                            }
                                            Err(e) => {
                                                warn!(error = %e, "Failed to build PROXY v1 header (skipping): {}", e);
                                            }
                                        }
                                    } else if info.proxy_protocol_version == "v2" {
                                        match frp_core::proxy_protocol::build_proxy_protocol_v2(
                                            src,
                                            dst,
                                            src_port,
                                            swc.dst_port.unwrap_or(0),
                                        ) {
                                            Ok(header) => {
                                                if let Err(e) = local.write_all(&header).await {
                                                    warn!(error = %e, "Failed to write PROXY v2 header: {}", e);
                                                }
                                            }
                                            Err(e) => {
                                                warn!(error = %e, "Failed to build PROXY v2 header: {}", e);
                                            }
                                        }
                                    }
                                }
                            }
                            // Respect StartWorkConn's use_encryption/use_compression
                            // if explicitly set (Some), otherwise fall back to
                            // proxy info. This allows the server to disable
                            // encryption for XTCP STCP fallback work connections
                            // to avoid the dual-CipherWriter deadlock.
                            let use_enc = swc.use_encryption.unwrap_or(info.use_encryption);
                            let use_comp = swc.use_compression.unwrap_or(info.use_compression);
                            let enc = if use_enc { Some(&enc_key) } else { None };
                            proxy::bridge_streams(proxy::BridgeStreamsParams {
                                local,
                                work,
                                name: &proxy_name,
                                use_encryption: use_enc,
                                use_compression: use_comp,
                                enc_key: enc,
                                bw_limiter: info.bandwidth_limiter.as_ref(),
                                metrics: proxy_metrics,
                            })
                            .await;
                        }
                        Err(e) => {
                            warn!(label = %label, local_addr = %info.local_addr, error = %e, "Work conn {}: failed to connect to local {}: {}", label, info.local_addr, e);
                        }
                    }
                }
            }
            Ok(other) => {
                warn!(label = %label, v1_type = ?other.v1_type_byte(), "Work conn {}: unexpected message: {:?}", label, other.v1_type_byte());
            }
            Err(e) => {
                debug!(label = %label, error = %e, "Work conn {}: read error: {}", label, e);
            }
        }

        debug!(label = %label, "Work conn {} completed", label);

        // Pool replenishment is server-driven (ReqWorkConn), matching Go frp
        // v0.70. The client does NOT auto-spawn replacements — if it did,
        // concurrent completions could push the pool past server pool_cap
        // before the server can refuse, wasting TCP/TLS/yamux setup.
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// F4 pin: Go frp v0.71.0 evicts idle UDP remote sessions after 30s of no
    /// traffic in either direction (pkg/proto/udp/udp.go writerFn 30s
    /// SetReadDeadline); frp-rs was 60s (double the hold on ephemeral ports +
    /// session entries). The constant IS the parity contract — pin it so a
    /// future bump away from Go's 30s is a deliberate change.
    #[test]
    fn udp_session_idle_timeout_is_go_parity_30s() {
        assert_eq!(
            UDP_SESSION_IDLE_TIMEOUT,
            Duration::from_secs(30),
            "Go parity: 30s idle eviction (was 60s)"
        );
        assert_eq!(UDP_SESSION_IDLE_TIMEOUT_MS, 30_000);
    }

    /// F1 pin: the UDP work-conn keepalive pinger is FIXED at 30s — Go frp's
    /// UDP heartbeatFn hardcodes 30s with no config knob
    /// (client/proxy/udp.go:150-165), and the server's UDP work-conn read
    /// deadline is 60s (server/proxy/udp.go:116-119), so a longer interval
    /// lets the server kill an idle conn. The old wiring to
    /// dial_server_keepalive (default 7200s) is gone; the constant IS the
    /// parity contract — pin it so any change is deliberate.
    #[test]
    fn udp_work_conn_ping_interval_is_go_parity_fixed_30s() {
        assert_eq!(
            UDP_WORK_CONN_PING_INTERVAL,
            Duration::from_secs(30),
            "Go parity: fixed 30s heartbeat, no config knob"
        );
    }

    /// F6 pin: the per-work-conn session cap sits in the audit-specified
    /// 256..=1024 band and starts empty.
    #[test]
    fn udp_session_cap_bounds_table() {
        assert!(
            (256..=1024).contains(&UDP_SESSION_CAP),
            "cap {} outside the specified 256..=1024 band",
            UDP_SESSION_CAP
        );
        let table = UdpSessionTable::new();
        assert_eq!(table.total_len(), 0);
        assert!(!table.at_session_cap());
    }

    /// F6 pin: refuse-new semantics — at the cap, a table that frees one
    /// slot (30s idle reap) admits new remotes again.
    #[tokio::test]
    async fn udp_session_cap_refuses_new_remotes_at_cap() {
        let table = UdpSessionTable::new();
        // One real socket is shared by every fake entry (1024 real binds
        // would exhaust fds); the entries never send on it.
        let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let last_active = Arc::new(AtomicU64::new(now_epoch_ms()));
        for i in 0..UDP_SESSION_CAP {
            let remote = SocketAddr::from(([203, 0, 113, 1], 1000 + i as u16));
            table.shard(&remote).insert(
                remote,
                UdpSession {
                    socket: sock.clone(),
                    last_active: last_active.clone(),
                    first_packet: false,
                },
            );
        }
        assert!(table.at_session_cap());
        assert_eq!(table.total_len(), UDP_SESSION_CAP);
        // A session freed by the idle reap makes room again (the reader's
        // create path checks at_session_cap before binding).
        let victim = SocketAddr::from(([203, 0, 113, 1], 1000));
        table.shard(&victim).remove(&victim);
        assert_eq!(table.total_len(), UDP_SESSION_CAP - 1);
        assert!(!table.at_session_cap());
    }

    /// F2 pin: the UDP local-service target resolver accepts every local_ip
    /// shape — plain IP, bracketed IPv6, UNBRACKETED IPv6 (the old
    /// parse::<SocketAddr> rejected it and killed the work conn), and
    /// hostnames (Go net.ResolveUDPAddr parity). IP literals never hit DNS.
    #[tokio::test]
    async fn udp_resolve_local_addr_accepts_all_shapes() {
        // Canonical IPv4: pure parse.
        let sa = resolve_udp_local_addr("127.0.0.1:8080", "p").await.unwrap();
        assert_eq!(sa, SocketAddr::from(([127, 0, 0, 1], 8080)));
        // Bracketed IPv6: pure parse.
        let sa = resolve_udp_local_addr("[::1]:8080", "p").await.unwrap();
        assert_eq!(sa, SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 1], 8080)));
        // F2 headline: UNBRACKETED IPv6 — last-colon split keeps the v6
        // segments in the host; literal parse, no DNS.
        let sa = resolve_udp_local_addr("::1:8080", "p").await.unwrap();
        assert_eq!(sa, SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 1], 8080)));
        // Hostname: DNS resolution (localhost resolves without a resolver).
        let sa = resolve_udp_local_addr("localhost:9", "p").await.unwrap();
        assert_eq!(sa.port(), 9);
        assert!(sa.ip().is_loopback());
    }

    /// F2 pin: malformed local_addr shapes are rejected with a warn, not a
    /// panic or a bogus bind.
    #[tokio::test]
    async fn udp_resolve_local_addr_rejects_garbage() {
        assert!(resolve_udp_local_addr("", "p").await.is_none());
        assert!(resolve_udp_local_addr("127.0.0.1", "p").await.is_none()); // no port
        assert!(resolve_udp_local_addr("::1", "p").await.is_none()); // v6 without port
        assert!(resolve_udp_local_addr("host:notaport", "p").await.is_none());
        assert!(resolve_udp_local_addr(":8080", "p").await.is_none()); // empty host
                                                                       // The resolved value is what the wire carries (Go sends the real
                                                                       // bound address — never the raw config string).
        let sa = SocketAddr::from(([127, 0, 0, 1], 8080));
        let addr = udp_addr_of(&sa);
        assert_eq!(addr.ip, "127.0.0.1");
        assert_eq!(addr.port, 8080);
        assert_eq!(addr.zone, "");
    }

    async fn tcp_pair() -> (tokio::net::TcpStream, tokio::net::TcpStream) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (client, accepted) =
            tokio::join!(tokio::net::TcpStream::connect(addr), listener.accept(),);
        (client.unwrap(), accepted.unwrap().0)
    }

    fn test_work_conn_config(
        pool_id: i32,
        xtcp_tx: mpsc::Sender<XtcpNotification>,
        session_alive: Arc<AtomicBool>,
        spawned_counter: Option<Arc<std::sync::atomic::AtomicUsize>>,
    ) -> WorkConnConfig {
        #[cfg(feature = "quic")]
        let quic_conn = None;
        #[cfg(not(feature = "quic"))]
        let quic_conn = ();

        WorkConnConfig {
            server_addr: "127.0.0.1".to_string(),
            server_port: 1,
            protocol: frp_core::transport::TransportProtocol::Tcp,
            run_id: "burst-test-run-id".to_string(),
            proxy_info_map: Arc::new(RwLock::new(HashMap::new())),
            enc_key: [0; 16],
            pool_id,
            auth_cfg: Arc::new(AuthConfig::with_token("test-token")),
            tls_enable: false,
            tls_server_name: String::new(),
            tls_ca_file: None,
            tls_cert_file: None,
            tls_key_file: None,
            dns_server: None,
            yamux: None,
            quic_conn,
            v2: false,
            oidc_client: None,
            udp_packet_size: 65535,
            proxy_metrics: Arc::new(frp_core::metrics::ProxyMetricsRegistry::new()),
            client_auth_scopes: Vec::new(),
            server_auth_scopes: Vec::new(),
            disable_custom_tls_first_byte: true,
            keepalive_secs: 0,
            bind_addr: None,
            proxy_url: String::new(),
            dial_timeout_secs: 1,
            xtcp_tx,
            session_alive,
            udp_packet_codec: String::new(),
            spawned_counter,
            #[cfg(feature = "vnet")]
            vnet_tuns: Arc::new(Mutex::new(HashMap::new())),
            #[cfg(feature = "vnet")]
            vnet_controller: Arc::new(frp_vnet::controller::ClientVnetController::new()),
            #[cfg(feature = "vnet")]
            vnet_tun_tx: Arc::new(std::sync::Mutex::new(HashMap::new())),
        }
    }

    #[test]
    fn start_work_conn_timeout_has_one_second_floor() {
        assert_eq!(
            start_work_conn_timeout(0),
            Duration::from_secs(1),
            "disabled/zero dial timeout must not permit an unbounded handshake"
        );
        assert_eq!(start_work_conn_timeout(7), Duration::from_secs(7));
    }

    #[tokio::test]
    async fn silent_start_work_conn_handshake_times_out() {
        let (client, _silent_server) = tcp_pair().await;
        let mut work = IoStream::Tcp(client);

        let err = read_start_work_conn_with_timeout(&mut work, false, Duration::from_millis(20))
            .await
            .unwrap_err();

        assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);
    }

    #[tokio::test]
    async fn burst_of_req_work_conn_spawns_immediately_without_cap() {
        // Go frp v0.70.1 runs each ReqWorkConn handler asynchronously with no
        // client-side in-flight cap. The control loop spawns directly, so a
        // burst larger than the removed 64-inflight limit must all start. The
        // tasks dial 127.0.0.1:1, which fails immediately; the counter proves
        // every task began concurrently rather than waiting on a limiter.
        let started = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let (xtcp_tx, _xtcp_rx) = mpsc::channel(64);
        let session_alive = Arc::new(AtomicBool::new(true));
        let expected = 200;

        for pool_id in 0..expected {
            let cfg = test_work_conn_config(
                pool_id as i32,
                xtcp_tx.clone(),
                session_alive.clone(),
                Some(started.clone()),
            );
            // JoinHandle is must_use; the task's completion is irrelevant
            // to this test (it dials 127.0.0.1:1 and fails fast).
            std::mem::drop(spawn_work_conn(cfg));
        }

        tokio::time::timeout(Duration::from_secs(2), async {
            while started.load(Ordering::SeqCst) < expected {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("all spawned work conn tasks should start immediately");
    }

    /// TODO.md:10417 — the work-conn token path was uncovered: no test drove a
    /// work connection (`spawn_work_conn`, the `ReqWorkConn` handler's dial)
    /// that carries a token source, so `oidc.set_new_work_conn` /
    /// `auth_cfg.try_generate_login_key` on the NewWorkConn frame could be
    /// swapped for anything without a red test. This drives the real handshake
    /// end to end: a real 127.0.0.1 listener stands in for frps, the OIDC
    /// `tokenSource` exec supplies the key, and the plaintext V1 NewWorkConn on
    /// the wire must carry exactly what Go frp v0.71.0's `setNewWorkConn`
    /// produces — the RAW token as `privilege_key`, no `timestamp`
    /// (`pkg/auth/oidc.go` sets only `PrivilegeKey`), unlike the token path
    /// which also stamps a timestamp.
    ///
    /// Deletion/mutation proof: drop the `requires_auth` branch and the frame's
    /// `privilege_key` stays `None`; use `try_generate_login_key` instead of the
    /// OIDC setter and the key becomes an md5 token (not the raw token) and the
    /// timestamp appears — both redden here. The invocation log also proves the
    /// source ran exactly once, i.e. the frame's key can only have come from it.
    #[cfg(feature = "oidc")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn oidc_token_source_fills_new_work_conn_privilege_key() {
        use frp_core::config::{ExecSource, ValueSource};

        // Print the resolved token, and record one line per invocation.
        const SCRIPT: &str = "\
n=$(wc -l < \"$1\")\n\
printf 'invocation %s\\n' \"$((n + 1))\" >> \"$1\"\n\
printf '%s' \"$2\"\n";

        let dir = tempfile::tempdir().expect("tempdir");
        let script_path = dir.path().join("nwc-token-exec.sh");
        let log_path = dir.path().join("nwc-exec-invocations.txt");
        std::fs::write(&script_path, SCRIPT).expect("write exec script");
        std::fs::write(&log_path, "").expect("create exec invocation log");

        let token = "nwc-oidc-token";
        let source = ValueSource {
            source_type: "exec".to_string(),
            file: None,
            exec: Some(ExecSource {
                command: "sh".to_string(),
                args: vec![
                    script_path.to_str().unwrap().to_owned(),
                    log_path.to_str().unwrap().to_owned(),
                    token.to_string(),
                ],
                env: Vec::new(),
            }),
        };
        // A token source makes `new` skip endpoint discovery entirely (an empty
        // endpoint is the documented tokenSource mode), so this needs no IdP.
        let oidc = OidcClient::new(
            "nwc-oidc-client".to_string(),
            String::new(),
            String::new(),
            None,
            String::new(),
            None,
            &HashMap::new(),
            None,
            false,
            None,
            Some(source),
        )
        .await
        .expect("OidcClient::new with a token source needs no token endpoint");

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let (xtcp_tx, _xtcp_rx) = mpsc::channel(1);
        let session_alive = Arc::new(AtomicBool::new(true));
        let mut cfg = test_work_conn_config(-1, xtcp_tx, session_alive, None);
        cfg.server_port = port;
        cfg.run_id = "nwc-oidc-run-id".to_string();
        cfg.oidc_client = Some(Arc::new(oidc));
        // Only an advertised NewWorkConns scope makes the client authenticate
        // this frame at all (Go parity: scope_requires_auth).
        cfg.client_auth_scopes = vec!["NewWorkConns".to_string()];

        let handle = spawn_work_conn(cfg);

        let (conn, _) = tokio::time::timeout(Duration::from_secs(5), listener.accept())
            .await
            .expect("work conn dial")
            .expect("accept work conn");
        let mut stream = IoStream::Tcp(conn);
        let frame = tokio::time::timeout(Duration::from_secs(5), stream.read_v1_frame())
            .await
            .expect("NewWorkConn read timeout")
            .expect("read NewWorkConn");

        match frame {
            FrpMessage::NewWorkConn(nwc) => {
                assert_eq!(nwc.run_id.as_deref(), Some("nwc-oidc-run-id"));
                assert_eq!(
                    nwc.privilege_key.as_deref(),
                    Some(token),
                    "the OIDC NewWorkConn setter must put the RAW tokenSource \
                     output on the wire as privilege_key"
                );
                assert!(
                    nwc.timestamp.is_none(),
                    "Go frp's OIDC setNewWorkConn sets only PrivilegeKey \
                     (pkg/auth/oidc.go), so the timestamp stays unset"
                );
            }
            other => panic!("expected NewWorkConn, got {other:?}"),
        }
        assert_eq!(
            std::fs::read_to_string(&log_path)
                .map(|s| s.lines().count())
                .unwrap_or(0),
            1,
            "auth.oidc.tokenSource must have run exactly once, and the frame we \
             just read can only carry that run's output"
        );

        handle.abort();
    }

    #[tokio::test]
    async fn udp_work_reader_eof_cancels_blocked_writer() {
        let (work, peer) = tcp_pair().await;
        let session_alive = Arc::new(AtomicBool::new(true));

        let bridge = tokio::spawn(run_udp_work_conn(
            IoStream::Tcp(work),
            "udp-test".to_string(),
            "127.0.0.1:9".to_string(),
            [0; 16],
            false,
            false,
            false,
            session_alive,
            65535,
            String::new(),
            None,
            String::new(),
        ));
        drop(peer);

        tokio::time::timeout(Duration::from_millis(200), bridge)
            .await
            .expect("reader EOF must cancel the sibling blocked on the write channel")
            .unwrap();
    }

    #[tokio::test]
    async fn udp_work_writer_error_cancels_blocked_work_reader() {
        // Establish a per-remote session first, then sever the work conn so
        // the writer's next write fails — the writer must cancel the reader
        // blocked on the work read.
        let (work, peer) = tcp_pair().await;
        let mut peer = IoStream::Tcp(peer);
        let local = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let remote = msg::UdpAddr {
            ip: "203.0.113.7".to_string(),
            port: 4242,
            zone: String::new(),
        };
        let bridge = tokio::spawn(run_udp_work_conn(
            IoStream::Tcp(work),
            "udp-test".to_string(),
            local.local_addr().unwrap().to_string(),
            [0; 16],
            false,
            false,
            false,
            Arc::new(AtomicBool::new(true)),
            65535,
            String::new(),
            None,
            String::new(),
        ));

        // Establish the session: reader creates the per-remote socket and
        // forwards the first datagram to the local service.
        peer.write_v1_frame(&FrpMessage::UDPPacket(msg::UDPPacket {
            content: b"req".to_vec(),
            local_addr: None,
            remote_addr: Some(remote.clone()),
        }))
        .await
        .unwrap();
        let mut buf = [0u8; 32];
        let (_n, proxy_addr) = local.recv_from(&mut buf).await.unwrap();

        // Sever the work conn; the reply write must then fail.
        drop(peer);
        local.send_to(b"force-write", proxy_addr).await.unwrap();

        tokio::time::timeout(Duration::from_secs(1), bridge)
            .await
            .expect("writer error must cancel the sibling blocked on work read")
            .unwrap();
    }

    #[tokio::test]
    async fn udp_work_forwards_packets_and_preserves_remote_address() {
        let (work, peer) = tcp_pair().await;
        let mut peer = IoStream::Tcp(peer);
        let local = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let remote = msg::UdpAddr {
            ip: "203.0.113.7".to_string(),
            port: 4242,
            zone: String::new(),
        };
        let bridge = tokio::spawn(run_udp_work_conn(
            IoStream::Tcp(work),
            "udp-test".to_string(),
            local.local_addr().unwrap().to_string(),
            [0; 16],
            false,
            false,
            false,
            Arc::new(AtomicBool::new(true)),
            65535,
            String::new(),
            None,
            String::new(),
        ));

        peer.write_v1_frame(&FrpMessage::UDPPacket(msg::UDPPacket {
            content: b"request".to_vec(),
            local_addr: None,
            remote_addr: Some(remote.clone()),
        }))
        .await
        .unwrap();
        let mut buf = [0u8; 32];
        let (n, proxy_addr) = local.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"request");

        local.send_to(b"response", proxy_addr).await.unwrap();
        let response = peer.read_v1_frame().await.unwrap();
        match response {
            FrpMessage::UDPPacket(packet) => {
                assert_eq!(packet.content, b"response");
                assert_eq!(packet.remote_addr.unwrap().to_string(), remote.to_string());
            }
            other => panic!("expected UDPPacket, got type {}", other.v1_type_byte()),
        }

        drop(peer);
        tokio::time::timeout(Duration::from_secs(1), bridge)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn udp_work_two_remotes_route_replies_correctly() {
        // The headline fix: with two concurrent remotes, each gets its own
        // ephemeral local socket (distinct source ports), and replies are
        // routed back to the visitor they belong to — the old single
        // last_remote model sent both replies to whoever sent last.
        let (work, peer) = tcp_pair().await;
        let mut peer = IoStream::Tcp(peer);
        let local = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let remote_a = msg::UdpAddr {
            ip: "203.0.113.7".to_string(),
            port: 4242,
            zone: String::new(),
        };
        let remote_b = msg::UdpAddr {
            ip: "198.51.100.9".to_string(),
            port: 5353,
            zone: String::new(),
        };
        let bridge = tokio::spawn(run_udp_work_conn(
            IoStream::Tcp(work),
            "udp-test".to_string(),
            local.local_addr().unwrap().to_string(),
            [0; 16],
            false,
            false,
            false,
            Arc::new(AtomicBool::new(true)),
            65535,
            String::new(),
            None,
            String::new(),
        ));

        // Interleaved requests from two distinct remotes.
        peer.write_v1_frame(&FrpMessage::UDPPacket(msg::UDPPacket {
            content: b"req-a".to_vec(),
            local_addr: None,
            remote_addr: Some(remote_a.clone()),
        }))
        .await
        .unwrap();
        peer.write_v1_frame(&FrpMessage::UDPPacket(msg::UDPPacket {
            content: b"req-b".to_vec(),
            local_addr: None,
            remote_addr: Some(remote_b.clone()),
        }))
        .await
        .unwrap();

        // The local service must see them from DISTINCT source ports.
        let mut buf = [0u8; 32];
        let (n1, src_a) = local.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..n1], b"req-a");
        let (n2, src_b) = local.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..n2], b"req-b");
        assert_ne!(
            src_a.port(),
            src_b.port(),
            "per-remote sockets must use distinct source ports"
        );

        // Replies must be routed back to their own remotes.
        local.send_to(b"resp-a", src_a).await.unwrap();
        local.send_to(b"resp-b", src_b).await.unwrap();

        let r1 = peer.read_v1_frame().await.unwrap();
        let r2 = peer.read_v1_frame().await.unwrap();
        let mut got: Vec<(String, String)> = Vec::new();
        for r in [r1, r2] {
            match r {
                FrpMessage::UDPPacket(p) => got.push((
                    String::from_utf8_lossy(&p.content).to_string(),
                    p.remote_addr.unwrap().to_string(),
                )),
                other => panic!("expected UDPPacket, got type {}", other.v1_type_byte()),
            }
        }
        // Reply order is not guaranteed (concurrent session tasks); check
        // set membership and that the two remotes are distinct.
        assert!(
            got.iter()
                .any(|(c, r)| c == "resp-a" && *r == remote_a.to_string()),
            "resp-a must be routed to remote A, got {got:?}"
        );
        assert!(
            got.iter()
                .any(|(c, r)| c == "resp-b" && *r == remote_b.to_string()),
            "resp-b must be routed to remote B, got {got:?}"
        );
        assert_ne!(got[0].1, got[1].1);

        drop(peer);
        tokio::time::timeout(Duration::from_secs(1), bridge)
            .await
            .unwrap()
            .unwrap();
    }

    #[cfg(feature = "vnet")]
    #[tokio::test]
    async fn virtual_net_plugin_work_conn_round_trips_packets() {
        use std::net::Ipv4Addr;
        use tokio::io::AsyncWriteExt;

        let controller = Arc::new(frp_vnet::controller::ClientVnetController::new());
        let tun_txs = Arc::new(std::sync::Mutex::new(HashMap::new()));
        let (tun_tx, mut tun_rx) = mpsc::channel::<Arc<[u8]>>(16);
        tun_txs
            .lock()
            .unwrap()
            .insert("vnet-proxy".to_string(), tun_tx);

        let (work, mut peer) = tokio::io::duplex(4096);
        let task = tokio::spawn(run_virtual_net_plugin_work_conn(
            IoStream::SshChannel(Box::new(work)),
            "vnet-proxy".to_string(),
            controller.clone(),
            tun_txs,
            false,
            false,
            [0; 16],
        ));

        let inbound = vec![
            0x45, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x40, 0x06, 0x00, 0x00, 100, 86, 0, 1,
            100, 86, 0, 2,
        ];
        let mut framed = Vec::new();
        framed.extend_from_slice(&(inbound.len() as u32).to_le_bytes());
        framed.extend_from_slice(&inbound);
        peer.write_all(&framed).await.unwrap();
        assert_eq!(tun_rx.recv().await.as_deref(), Some(&inbound[..]));

        let src = std::net::IpAddr::V4(Ipv4Addr::new(100, 86, 0, 1));
        let return_tx = controller
            .server_conn_sender(&src)
            .expect("remote source IP must be registered for return traffic");
        return_tx.try_send(inbound.clone()).unwrap();
        let mut buf = vec![0u8; framed.len()];
        let n = peer.read(&mut buf).await.unwrap();
        assert_eq!(
            &buf[..n],
            &framed[..],
            "return traffic must be length-framed"
        );

        drop(peer);
        tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .unwrap()
            .unwrap();
        assert!(controller.server_conn_sender(&src).is_none());
    }

    #[cfg(feature = "vnet")]
    #[tokio::test]
    async fn virtual_net_plugin_work_conn_wraps_encrypted_compressed_wire_bytes() {
        use std::net::IpAddr;
        use tokio::io::AsyncWriteExt;

        let key = frp_core::encryption::derive_key("vnet-test-secret");
        let controller = Arc::new(frp_vnet::controller::ClientVnetController::new());
        let tun_txs = Arc::new(std::sync::Mutex::new(HashMap::new()));
        let (tun_tx, mut tun_rx) = mpsc::channel::<Arc<[u8]>>(16);
        tun_txs
            .lock()
            .unwrap()
            .insert("vnet-proxy".to_string(), tun_tx);

        let (work, mut peer) = tokio::io::duplex(8192);
        let task = tokio::spawn(run_virtual_net_plugin_work_conn(
            IoStream::SshChannel(Box::new(work)),
            "vnet-proxy".to_string(),
            controller.clone(),
            tun_txs,
            true,
            true,
            key,
        ));

        let inbound = vec![
            0x60, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x20, 0x01, 0x0d, 0xb8,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        ];
        let mut framed = Vec::new();
        framed.extend_from_slice(&(inbound.len() as u32).to_le_bytes());
        framed.extend_from_slice(&inbound);
        let mut compressed = Vec::new();
        frp_core::encryption::compress_into(&framed, &mut compressed).unwrap();
        let wire = frp_core::encryption::encrypt(&compressed, &key).unwrap();
        peer.write_all(&wire).await.unwrap();
        assert_eq!(tun_rx.recv().await.as_deref(), Some(&inbound[..]));

        let src: IpAddr = "2001:db8::2".parse().unwrap();
        let return_tx = controller
            .server_conn_sender(&src)
            .expect("IPv6 source must be registered for return traffic");
        return_tx.try_send(inbound.clone()).unwrap();

        let mut raw = vec![0u8; wire.len()];
        peer.read_exact(&mut raw).await.unwrap();
        assert_ne!(raw, wire, "return traffic must be re-wrapped, not replayed");
        let decrypted = frp_core::encryption::decrypt(&raw, &key).unwrap();
        let framed_restored = frp_core::encryption::decompress(&decrypted).unwrap();
        assert_eq!(framed_restored, framed, "wire must carry the framed packet");

        drop(peer);
        tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .unwrap()
            .unwrap();
        assert!(controller.server_conn_sender(&src).is_none());
    }

    #[cfg(all(feature = "vnet", feature = "compression"))]
    #[tokio::test]
    async fn tunnel_packet_reader_drains_multiple_frames_before_next_transport_read() {
        use tokio::io::AsyncWriteExt;

        let packet_a = vec![0x45, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x40, 0x06];
        let packet_b = vec![0x45, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x40, 0x11];
        let mut wire = Vec::new();
        for packet in [&packet_a, &packet_b] {
            let mut framed = Vec::new();
            framed.extend_from_slice(&(packet.len() as u32).to_le_bytes());
            framed.extend_from_slice(packet);
            let mut compressed = Vec::new();
            frp_core::encryption::compress_into(&framed, &mut compressed).unwrap();
            wire.extend_from_slice(&compressed);
        }
        let (mut writer, reader) = tokio::io::duplex(8192);
        writer.write_all(&wire).await.unwrap();
        drop(writer);

        let mut packet_reader = TunnelPacketReader::new(reader, true);
        assert_eq!(packet_reader.next_packet().await.unwrap(), Some(packet_a));
        assert_eq!(packet_reader.next_packet().await.unwrap(), Some(packet_b));
        assert_eq!(packet_reader.next_packet().await.unwrap(), None);
    }

    #[cfg(feature = "vnet")]
    #[tokio::test]
    async fn tunnel_packet_reader_handles_coalesced_and_split_frames_without_compression() {
        use tokio::io::AsyncWriteExt;

        let packet_a = vec![0x45, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x40, 0x06];
        let packet_b = vec![0x45, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x40, 0x11];
        let packet_c = vec![0x60, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x20, 0x01];
        let frame = |p: &[u8]| -> Vec<u8> {
            let mut f = Vec::new();
            f.extend_from_slice(&(p.len() as u32).to_le_bytes());
            f.extend_from_slice(p);
            f
        };

        let (mut writer, reader) = tokio::io::duplex(8192);
        let mut wire = frame(&packet_a);
        wire.extend_from_slice(&frame(&packet_b));
        writer.write_all(&wire).await.unwrap();

        let mut packet_reader = TunnelPacketReader::new(reader, false);
        assert_eq!(packet_reader.next_packet().await.unwrap(), Some(packet_a));
        assert_eq!(packet_reader.next_packet().await.unwrap(), Some(packet_b));

        // A frame split across transport reads must still reassemble.
        let split = frame(&packet_c);
        writer.write_all(&split[..2]).await.unwrap();
        writer.write_all(&split[2..]).await.unwrap();
        assert_eq!(packet_reader.next_packet().await.unwrap(), Some(packet_c));

        drop(writer);
        assert_eq!(packet_reader.next_packet().await.unwrap(), None);
    }
}
