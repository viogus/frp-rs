//! KCP session — per-conversation KCP state machine with optional FEC.

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::time::Instant;

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

pub(crate) struct KcpSession {
    conv: u32,
    peer_addr: SocketAddr,
    kcp: kcp::Kcp<Instant>,
    fec: Option<Fec>,
    config: KcpConfig,
    fec_seqid: u32,
    shard_groups: HashMap<u32, ShardGroup>,
    last_recv: Instant,
    read_tx: mpsc::UnboundedSender<Vec<u8>>,
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

        let mut kcp = kcp::Kcp::new(conv, Instant::now());
        kcp.set_mtu(config.mtu as i32).ok();
        kcp.set_wndsize(config.wnd_size.0 as i32, config.wnd_size.1 as i32);
        kcp.set_nodelay(
            config.nodelay.nodelay as i32,
            config.nodelay.interval,
            config.nodelay.resend,
            config.nodelay.nc as i32,
        );
        kcp.set_stream(config.stream as i32);

        Self {
            conv,
            peer_addr,
            kcp,
            fec,
            config,
            fec_seqid: 0,
            shard_groups: HashMap::new(),
            last_recv: Instant::now(),
            read_tx,
            shutdown: false,
        }
    }

    pub fn conv(&self) -> u32 {
        self.conv
    }
    pub fn peer_addr(&self) -> SocketAddr {
        self.peer_addr
    }

    /// Called by driver on each tick. Updates KCP clock, flushes output to UDP.
    /// Returns output packets to send via UDP.
    pub fn update(&mut self, now: Instant) -> io::Result<Vec<Vec<u8>>> {
        if self.shutdown {
            return Ok(Vec::new());
        }
        self.kcp.update(now).map_err(io::Error::other)?;

        let output = self.kcp.output().map_err(io::Error::other)?;
        if output.is_empty() {
            return Ok(Vec::new());
        }

        let mut packets = Vec::new();
        if let Some(ref fec) = self.fec {
            let shards = fec.encode(&[output.as_slice()]);
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
        } else {
            packets.push(output);
        }
        Ok(packets)
    }

    /// Enqueue data to send via KCP.
    pub fn send(&mut self, data: &[u8]) -> io::Result<()> {
        self.kcp.send(data).map_err(io::Error::other)?;
        if self.config.flush_write {
            self.kcp.flush().map_err(io::Error::other)?;
        }
        Ok(())
    }

    /// Feed received UDP data into KCP. Handles FEC decode if enabled.
    pub fn input(&mut self, data: &[u8]) -> io::Result<()> {
        self.last_recv = Instant::now();

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
            match self.kcp.recv() {
                Ok(buf) if buf.is_empty() => return Ok(()),
                Ok(buf) => {
                    if self.read_tx.send(buf).is_err() {
                        self.shutdown = true;
                        return Ok(());
                    }
                }
                Err(e) => return Err(io::Error::other(e)),
            }
        }
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
