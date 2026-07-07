//! KCP socket driver — UDP event loop shared across all sessions.

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::time::{interval, Duration};

use super::config::KcpConfig;
use super::session::KcpSession;
use super::stream::KcpStream;

pub(crate) struct WriteRequest {
    pub data: Vec<u8>,
}

pub(crate) struct KcpSocketHandle {
    pub write_tx: mpsc::UnboundedSender<(u32, WriteRequest)>,
    pub register_tx: mpsc::UnboundedSender<(u32, SocketAddr, KcpSession)>,
    /// Channel to send newly accepted streams back to KcpListener::accept().
    #[allow(dead_code)]
    pub accept_tx: mpsc::UnboundedSender<KcpStream>,
}

pub(crate) struct KcpSocket {
    socket: Arc<UdpSocket>,
    config: KcpConfig,
    sessions: HashMap<(u32, SocketAddr), KcpSession>,
    write_tx: mpsc::UnboundedSender<(u32, WriteRequest)>,
    write_rx: mpsc::UnboundedReceiver<(u32, WriteRequest)>,
    register_rx: mpsc::UnboundedReceiver<(u32, SocketAddr, KcpSession)>,
    accept_tx: mpsc::UnboundedSender<KcpStream>,
    start: Instant,
}

impl KcpSocket {
    pub fn new(
        socket: Arc<UdpSocket>,
        config: KcpConfig,
    ) -> (Self, KcpSocketHandle, mpsc::UnboundedReceiver<KcpStream>) {
        let (write_tx, write_rx) = mpsc::unbounded_channel();
        let (register_tx, register_rx) = mpsc::unbounded_channel();
        let (accept_tx, accept_rx) = mpsc::unbounded_channel();
        let this = Self {
            socket,
            config,
            sessions: HashMap::new(),
            write_tx: write_tx.clone(),
            write_rx,
            register_rx,
            accept_tx: accept_tx.clone(),
            start: Instant::now(),
        };
        let handle = KcpSocketHandle {
            write_tx,
            register_tx,
            accept_tx,
        };
        (this, handle, accept_rx)
    }

    pub async fn run(mut self) {
        // Drain any pending registrations sent before the driver was spawned.
        // This prevents a race where recv_from fires before register_tx is processed,
        // causing FEC fallback to create a duplicate session with wrong conv.
        while let Ok((conv, addr, session)) = self.register_rx.try_recv() {
            self.sessions.insert((conv, addr), session);
        }

        let mut tick = interval(Duration::from_millis(10));
        let mut buf = vec![0u8; 1500];

        loop {
            tokio::select! {
                _ = tick.tick() => {
                    let now_ms = self.start.elapsed().as_millis() as u32;
                    let mut to_remove = Vec::new();
                    for (key, session) in &mut self.sessions {
                        match session.update(now_ms) {
                            Ok(packets) => {
                                for pkt in packets {
                                    if let Err(e) = self.socket.send_to(&pkt, key.1).await {
                                        tracing::debug!(conv = key.0, peer = %key.1, error = %e, "KCP UDP send error");
                                    }
                                }
                            }
                            Err(e) => {
                                tracing::debug!(conv = key.0, peer = %key.1, error = %e, "KCP session error");
                                to_remove.push(*key);
                                continue;
                            }
                        }
                        if let Err(e) = session.recv_and_push() {
                            tracing::debug!(conv = key.0, peer = %key.1, error = %e, "KCP recv error");
                            to_remove.push(*key);
                        }
                    }
                    for key in to_remove {
                        self.sessions.remove(&key);
                    }
                }

                Some((conv, req)) = self.write_rx.recv() => {
                    // Route write to session matching conv (pick first match)
                    let _result = self.sessions.iter_mut()
                        .find(|((c, _), _)| *c == conv)
                        .map(|(_, s)| s.send(&req.data))
                        .unwrap_or_else(|| Err(io::Error::new(io::ErrorKind::NotConnected, "session not found")));
                }

                recv_result = self.socket.recv_from(&mut buf) => {
                    match recv_result {
                        Ok((n, src)) => {
                            let data = buf[..n].to_vec();
                            let key = Self::resolve_key(&data, src);
                            if let Some(session) = self.sessions.get_mut(&key) {
                                if let Err(e) = session.input(&data) {
                                    tracing::debug!(conv = key.0, peer = %src, error = %e, "KCP input error");
                                }
                            } else {
                                // FEC fallback: parity shards and data shards whose conv
                                // wasn't found in sessions are routed by peer_addr.
                                // With 6-byte FEC header (Go kcp-go format), conv is only
                                // available in data shards at offset 8.
                                let is_fec = data.len() >= 6
                                    && (u16::from_le_bytes([data[4], data[5]]) == 0xf1
                                        || u16::from_le_bytes([data[4], data[5]]) == 0xf2);
                                let fec_key = if is_fec {
                                    self.sessions.keys()
                                        .find(|(_, a)| *a == src)
                                        .copied()
                                } else {
                                    None
                                };
                                if let Some(fk) = fec_key {
                                    if let Some(session) = self.sessions.get_mut(&fk) {
                                        if let Err(e) = session.input(&data) {
                                            tracing::debug!(conv = fk.0, peer = %src, error = %e, "KCP FEC fallback input error");
                                        }
                                    }
                                } else if !is_fec {
                                    // New peer detected — create session + stream
                                    let (read_tx, read_rx) = mpsc::unbounded_channel();
                                    let mut session = KcpSession::new(
                                        key.0, src, self.config.clone(), read_tx,
                                    );
                                    if let Err(e) = session.input(&data) {
                                        tracing::debug!(conv = key.0, peer = %src, error = %e, "KCP new peer input error");
                                    }
                                    let stream = KcpStream::new(
                                        key.0, src,
                                        self.write_tx.clone(),
                                        read_rx,
                                    );
                                    let _ = self.accept_tx.send(stream);
                                    self.sessions.insert(key, session);
                                }
                            }
                        }
                        Err(e) => {
                            tracing::warn!(error = %e, "KCP UDP recv error");
                        }
                    }
                }

                Some((conv, addr, session)) = self.register_rx.recv() => {
                    let key = (conv, addr);
                    self.sessions.insert(key, session);
                }
            }
        }
    }

    /// Extract (conv, peer_addr) key from a raw UDP packet.
    /// Plain KCP: conv is first 4 bytes (little-endian u32).
    /// FEC data shard: 6-byte header [seqid: u32 LE][flag: u16 LE], then
    ///   SIZE(2B) + raw KCP data; conv at offset 8 (skip 6B header + 2B SIZE).
    /// FEC parity shard: 6-byte header, no conv available → return (0, src);
    ///   routing handled by FEC fallback below.
    fn resolve_key(data: &[u8], src: SocketAddr) -> (u32, SocketAddr) {
        if data.len() >= 6 {
            let flag = u16::from_le_bytes([data[4], data[5]]);
            if flag == 0xf1 || flag == 0xf2 {
                // FEC packet: 6-byte header, no conv field.
                if flag == 0xf1 && data.len() >= 12 {
                    // Data shard: KCP conv at offset 8 (6B header + 2B SIZE).
                    let conv = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
                    if conv != 0 {
                        return (conv, src);
                    }
                }
                // Parity shard or short data shard: can't extract conv.
                return (0, src);
            }
        }
        if data.len() >= 4 {
            let conv = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
            return (conv, src);
        }
        (0, src)
    }
}
