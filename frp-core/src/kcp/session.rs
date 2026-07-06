//! KCP session — per-conversation KCP state machine with optional FEC.

use std::collections::HashMap;
use std::io::{self, Write};
use std::net::SocketAddr;

use tokio::sync::mpsc;

use super::config::KcpConfig;
use crate::kcp_compat::Fec;

const FEC_HEADER_SIZE: usize = 6;
const TYPE_DATA: u16 = 0xf1;
const TYPE_PARITY: u16 = 0xf2;
const MAX_SHARD_SETS: usize = 3;

struct ShardGroup {
    shards: Vec<Option<Vec<u8>>>,
    received_count: usize,
}

/// Writer that collects each `write_all` call as a separate packet.
struct KcpWriter {
    packets: Vec<Vec<u8>>,
}

impl KcpWriter {
    fn new() -> Self {
        Self {
            packets: Vec::new(),
        }
    }

    fn drain(&mut self) -> Vec<Vec<u8>> {
        std::mem::take(&mut self.packets)
    }
}

impl Write for KcpWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.packets.push(buf.to_vec());
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub(crate) struct KcpSession {
    conv: u32,
    peer_addr: SocketAddr,
    kcp: kcp::Kcp<KcpWriter>,
    fec: Option<Fec>,
    config: KcpConfig,
    fec_seqid: u32,
    shard_groups: HashMap<u32, ShardGroup>,
    recv_buf: Vec<u8>,
    _read_tx: mpsc::UnboundedSender<Vec<u8>>,
    shutdown: bool,
}

impl KcpSession {
    pub fn new(
        conv: u32,
        peer_addr: SocketAddr,
        config: KcpConfig,
        read_tx: mpsc::UnboundedSender<Vec<u8>>,
    ) -> Self {
        let fec = if config.data_shards > 0 && config.parity_shards > 0 {
            Some(Fec::new(config.data_shards, config.parity_shards))
        } else {
            None
        };

        let writer = KcpWriter::new();
        let mut kcp = if config.stream {
            kcp::Kcp::new_stream(conv, writer)
        } else {
            kcp::Kcp::new(conv, writer)
        };
        kcp.set_mtu(config.mtu).ok();
        kcp.set_wndsize(config.wnd_size.0, config.wnd_size.1);
        kcp.set_nodelay(
            config.nodelay.nodelay,
            config.nodelay.interval,
            config.nodelay.resend,
            config.nodelay.nc,
        );

        Self {
            conv,
            peer_addr,
            kcp,
            fec,
            config,
            fec_seqid: 0,
            shard_groups: HashMap::new(),
            recv_buf: vec![0u8; 16384],
            _read_tx: read_tx,
            shutdown: false,
        }
    }

    pub fn conv(&self) -> u32 {
        self.conv
    }

    pub fn peer_addr(&self) -> SocketAddr {
        self.peer_addr
    }

    /// Called by driver on each tick. Updates KCP clock, returns output packets.
    /// `now_ms` is a monotonic millisecond timestamp.
    pub fn update(&mut self, now_ms: u32) -> io::Result<Vec<Vec<u8>>> {
        if self.shutdown {
            return Ok(Vec::new());
        }
        self.kcp.update(now_ms).map_err(io::Error::other)?;

        let output = self.kcp.output_mut().drain();
        if output.is_empty() {
            return Ok(Vec::new());
        }

        let mut packets = Vec::new();
        if let Some(ref fec) = self.fec {
            // Encode each raw KCP packet with FEC.
            // Fec::encode expects exactly data_shards slices. Split the raw
            // KCP output into data_shards equal-sized blocks (padding last block).
            for raw in &output {
                let block_size =
                    (raw.len() + self.config.data_shards - 1) / self.config.data_shards;
                let mut blocks: Vec<Vec<u8>> = (0..self.config.data_shards)
                    .map(|i| {
                        let start = i * block_size;
                        let end = ((i + 1) * block_size).min(raw.len());
                        let mut block = vec![0u8; block_size];
                        if start < raw.len() {
                            block[..(end - start)].copy_from_slice(&raw[start..end]);
                        }
                        block
                    })
                    .collect();

                let block_refs: Vec<&[u8]> = blocks.iter().map(|b| b.as_slice()).collect();
                let shards = fec.encode(&block_refs);
                for (i, shard) in shards.iter().enumerate() {
                    let flag = if i < self.config.data_shards {
                        TYPE_DATA
                    } else {
                        TYPE_PARITY
                    };
                    let mut packet = Vec::with_capacity(FEC_HEADER_SIZE + shard.len());
                    packet.extend_from_slice(&self.fec_seqid.to_le_bytes());
                    packet.extend_from_slice(&flag.to_le_bytes());
                    packet.extend_from_slice(shard);
                    packets.push(packet);
                }
                self.fec_seqid = self.fec_seqid.wrapping_add(1);
            }
        } else {
            packets = output;
        }
        Ok(packets)
    }

    /// Enqueue data to send via KCP.
    pub fn send(&mut self, data: &[u8]) -> io::Result<usize> {
        self.kcp.send(data).map_err(io::Error::other)
    }

    /// Feed received UDP data into KCP. Handles FEC decode if enabled.
    pub fn input(&mut self, data: &[u8]) -> io::Result<()> {
        if let Some(ref fec) = self.fec {
            if data.len() < FEC_HEADER_SIZE {
                return Ok(());
            }
            let seqid = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
            let flag = u16::from_le_bytes([data[4], data[5]]);

            if flag != TYPE_DATA && flag != TYPE_PARITY {
                // Not FEC — treat as raw KCP
                self.kcp.input(data).map_err(io::Error::other)?;
                return Ok(());
            }

            let shard_data = &data[FEC_HEADER_SIZE..];
            let shard_id = seqid / self.config.data_shards as u32;
            let shard_index = seqid as usize % self.config.data_shards;
            let total = self.config.data_shards + self.config.parity_shards;

            self.prune_old_groups();

            let group = self
                .shard_groups
                .entry(shard_id)
                .or_insert_with(|| ShardGroup {
                    shards: vec![None; total],
                    received_count: 0,
                });

            if group.shards[shard_index].is_none() {
                group.shards[shard_index] = Some(shard_data.to_vec());
                group.received_count += 1;
            }

            if group.received_count >= self.config.data_shards {
                if fec.decode(&mut group.shards) {
                    let mut reassembled = Vec::new();
                    for s in group.shards.iter().take(self.config.data_shards).flatten() {
                        reassembled.extend_from_slice(s);
                    }
                    while reassembled.last() == Some(&0) {
                        reassembled.pop();
                    }
                    if !reassembled.is_empty() {
                        self.kcp.input(&reassembled).map_err(io::Error::other)?;
                    }
                }
                self.shard_groups.remove(&shard_id);
            }
        } else {
            self.kcp.input(data).map_err(io::Error::other)?;
        }

        Ok(())
    }

    /// Push any received KCP data to the stream's read channel.
    /// Called by driver on each tick after update().
    pub fn recv_and_push(&mut self) -> io::Result<()> {
        loop {
            match self.kcp.peeksize() {
                Ok(size) => {
                    if size > self.recv_buf.len() {
                        self.recv_buf.resize(size, 0);
                    }
                    match self.kcp.recv(&mut self.recv_buf[..size]) {
                        Ok(n) => {
                            if self._read_tx.send(self.recv_buf[..n].to_vec()).is_err() {
                                self.shutdown = true;
                                return Ok(());
                            }
                        }
                        Err(e) => return Err(io::Error::other(e)),
                    }
                }
                Err(kcp::Error::RecvQueueEmpty) => return Ok(()),
                Err(e) => return Err(io::Error::other(e)),
            }
        }
    }

    /// Returns ms until next update is needed, or 0 if update now.
    pub fn check(&self, now_ms: u32) -> u32 {
        self.kcp.check(now_ms)
    }

    /// Check if the KCP connection is dead (too many retransmissions).
    pub fn is_dead_link(&self) -> bool {
        self.kcp.is_dead_link()
    }

    /// Mark session for shutdown. Driver will remove it on next tick.
    pub fn shutdown(&mut self) {
        self.shutdown = true;
    }

    fn prune_old_groups(&mut self) {
        while self.shard_groups.len() > MAX_SHARD_SETS {
            let oldest = self.shard_groups.keys().copied().min();
            if let Some(key) = oldest {
                self.shard_groups.remove(&key);
            } else {
                break;
            }
        }
    }
}
