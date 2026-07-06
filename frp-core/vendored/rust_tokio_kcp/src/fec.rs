//! Forward Error Correction (FEC) implementation using Reed-Solomon erasure coding
//!
//! FEC is placed between KCP layer and UDP layer:
//! - Outgoing: KCP output -> FEC encoding -> UDP send
//! - Incoming: UDP recv -> FEC decoding -> KCP input

use std::cmp::Ordering;
use std::collections::{BinaryHeap, HashMap, HashSet};
use std::time::{SystemTime, UNIX_EPOCH};
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use log;

use reed_solomon_erasure::{ReedSolomon, galois_8::Field};

pub const FEC_HEADER_SIZE: usize = 6;
pub const FEC_HEADER_SIZE_PLUS_2: usize = FEC_HEADER_SIZE + 2; // plus 2B data size
pub const TYPE_DATA: u16 = 0xf1;
pub const TYPE_PARITY: u16 = 0xf2;
const MAX_SHARD_SETS: u32 = 3;

/// FEC packet type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FecType {
    Data,
    Parity,
}

/// FEC packet header
#[derive(Debug, Clone, Copy)]
struct FecHeader {
    seqid: u32,
    flag: u16,
}

impl FecHeader {
    fn encode(&self, buf: &mut [u8]) {
        if buf.len() < FEC_HEADER_SIZE {
            return;
        }
        let mut writer = &mut buf[..FEC_HEADER_SIZE];
        writer.write_u32::<LittleEndian>(self.seqid).unwrap();
        writer.write_u16::<LittleEndian>(self.flag).unwrap();
    }

    fn decode(buf: &[u8]) -> Option<Self> {
        if buf.len() < FEC_HEADER_SIZE {
            return None;
        }
        let mut reader = &buf[..FEC_HEADER_SIZE];
        let seqid = reader.read_u32::<LittleEndian>().ok()?;
        let flag = reader.read_u16::<LittleEndian>().ok()?;
        Some(FecHeader { seqid, flag })
    }

    fn flag(&self) -> FecType {
        match self.flag {
            TYPE_DATA => FecType::Data,
            TYPE_PARITY => FecType::Parity,
            _ => FecType::Data,
        }
    }
}

/// FEC encoder for outgoing packets
#[derive(Debug)]
pub struct FecEncoder {
    data_shards: usize,
    parity_shards: usize,
    shard_size: usize,
    paws: u32, // Protect Against Wrapped Sequence numbers
    next: u32,
    shard_count: usize,
    max_size: usize,
    header_offset: usize,
    shard_cache: Vec<Vec<u8>>,
    encode_cache: Vec<Vec<u8>>,
    codec: ReedSolomon<Field>,
    ts_latest_packet: i64, // timestamp of latest packet in milliseconds
}

impl FecEncoder {
    pub fn new(data_shards: usize, parity_shards: usize, header_offset: usize) -> Option<Self> {
        if data_shards == 0 || parity_shards == 0 {
            return None;
        }
        if data_shards + parity_shards > 256 {
            return None;
        }

        let shard_size = data_shards + parity_shards;
        let paws = 0xffffffff / shard_size as u32 * shard_size as u32;

        let codec = ReedSolomon::new(data_shards, parity_shards).ok()?;

        let mut shard_cache = Vec::with_capacity(shard_size);
        for _ in 0..shard_size {
            shard_cache.push(vec![0u8; 1500]); // MTU limit
        }

        let mut encode_cache = Vec::with_capacity(shard_size);
        for _ in 0..shard_size {
            encode_cache.push(Vec::new());
        }

        Some(FecEncoder {
            data_shards,
            parity_shards,
            shard_size,
            paws,
            next: 0,
            shard_count: 0,
            max_size: 0,
            header_offset,
            shard_cache,
            encode_cache,
            codec,
            ts_latest_packet: 0,
        })
    }

    /// Encode a packet, returns parity shards if we have collected enough data shards
    /// rto: round trip time in milliseconds, used for continuity check
    pub fn encode(&mut self, buf: &mut [u8], rto: u32) -> Vec<Vec<u8>> {
        log::trace!("[FEC] encode called: shard_count={}, buf_len={}", self.shard_count, buf.len());
        let payload_offset = self.header_offset + FEC_HEADER_SIZE;
        
        // Seal data packet header
        // In kcp-go: sealData writes seqid and increments enc.next immediately
        let header = FecHeader {
            seqid: self.next,
            flag: TYPE_DATA,
        };
        header.encode(&mut buf[self.header_offset..]);
        // Increment next immediately after sealing data header (matching kcp-go sealData)
        self.next = (self.next + 1) % self.paws;
        
        // Write data size (2 bytes)
        // In kcp-go: binary.LittleEndian.PutUint16(b[enc.payloadOffset:], uint16(len(b[enc.payloadOffset:])))
        // This writes the length of [size(2B)][KCP packet] at the position of size field
        // buf format: [header_offset][FEC header(6B)][size(2B)][KCP packet]
        // payload_offset points to the size field position
        // So we write len(buf[payload_offset:]) which is len([size(2B)][KCP packet])
        // Note: buf[payload_offset:] is [size(2B)][KCP packet], so len(buf[payload_offset:]) = 2 + len(KCP packet)
        let data_size = if buf.len() > payload_offset {
            buf.len() - payload_offset
        } else {
            0
        };
        // Write size at payload_offset position
        // Debug: verify the calculation
        if data_size < 2 {
            eprintln!("[FEC ENCODE ERROR] data_size={} < 2, buf.len()={}, payload_offset={}, header_offset={}", 
                     data_size, buf.len(), payload_offset, self.header_offset);
        }
        let mut writer = &mut buf[payload_offset..payload_offset + 2];
        writer.write_u16::<LittleEndian>(data_size as u16).unwrap();

        // Get current timestamp in milliseconds
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64;

        // Copy data from payloadOffset to fec shard cache (matching kcp-go exactly)
        // In kcp-go: copy(enc.shardCache[enc.shardCount][enc.payloadOffset:], b[enc.payloadOffset:])
        // This means we only copy from payloadOffset onwards, NOT the header part
        // The header part (0..payloadOffset) will remain uninitialized (zeros) in shardCache
        // and will be filled later during encryption phase
        let sz = buf.len();
        if self.shard_count < self.shard_cache.len() {
            // Resize shard cache to match packet size
            self.shard_cache[self.shard_count].resize(sz, 0);
            // Only copy from payloadOffset onwards (matching kcp-go behavior)
            if sz > payload_offset {
                self.shard_cache[self.shard_count][payload_offset..sz]
                    .copy_from_slice(&buf[payload_offset..sz]);
            }
        }
        self.shard_count += 1;

        // Track max shard length
        if sz > self.max_size {
            self.max_size = sz;
        }

        // Generate parity shards when we have enough data shards
        let mut parity_shards = Vec::new();
        if self.shard_count == self.data_shards {
            // Check continuity: if interval is larger than rto, skip parity generation
            let should_generate_parity = if self.ts_latest_packet == 0 {
                log::trace!("[FEC] First packet group, generating parity shards");
                true // First packet, always generate
            } else {
                let interval = now - self.ts_latest_packet;
                let should_gen = interval < rto as i64;
                log::trace!("[FEC] Collected {} data shards, interval={}ms, rto={}ms, should_generate={}", 
                           self.data_shards, interval, rto, should_gen);
                should_gen
            };

            if should_generate_parity {
                log::trace!("[FEC] Generating {} parity shards", self.parity_shards);
                // Make all shards equal-sized
                for i in 0..self.data_shards {
                    if self.shard_cache[i].len() < self.max_size {
                        self.shard_cache[i].resize(self.max_size, 0);
                    }
                }

                // Prepare encode cache (strip header, only payload)
                // In kcp-go: cache[k] = enc.shardCache[k][enc.payloadOffset:enc.maxSize]
                // This sets encodeCache for ALL k (including k >= dataShards for parity shards)
                // For k >= dataShards, encodeCache[k] will be used as output buffer by Reed-Solomon encoder
                // payloadOffset = headerOffset + fecHeaderSize (not fecHeaderSizePlus2!)
                // This is the start of [size(2B)][KCP packet] part
                for k in 0..self.shard_size {
                    // Ensure shardCache[k] is at least max_size for k >= data_shards
                    if k >= self.data_shards && self.shard_cache[k].len() < self.max_size {
                        self.shard_cache[k].resize(self.max_size, 0);
                    }
                    // Extract payload part from shardCache (from payloadOffset to maxSize)
                    // For k < data_shards: this is input data
                    // For k >= data_shards: this is output buffer (will be filled by encoder)
                    self.encode_cache[k] = self.shard_cache[k][payload_offset..self.max_size].to_vec();
                }

                // Reed-Solomon encoding
                if self.codec.encode(&mut self.encode_cache).is_ok() {
                    // Create parity shard packets
                    // In kcp-go: ps = enc.shardCache[enc.dataShards:]
                    // The header part (0..headerOffset) remains uninitialized (zeros) in parity shards
                    // and will be filled later during encryption phase (nonce, CRC32, etc.)
                    for k in self.data_shards..self.shard_size {
                        // Resize shard cache to max_size if needed
                        if self.shard_cache[k].len() < self.max_size {
                            self.shard_cache[k].resize(self.max_size, 0);
                        }
                        
                        // Seal parity header (only FEC header, not the encryption header)
                        // In kcp-go: enc.sealParity(ps[k][enc.headerOffset:])
                        let header = FecHeader {
                            seqid: self.next,
                            flag: TYPE_PARITY,
                        };
                        header.encode(&mut self.shard_cache[k][self.header_offset..]);
                        
                        // Copy encoded parity data from encode_cache to shard_cache
                        // IMPORTANT: Do NOT write size field separately for parity shards!
                        // In kcp-go, parity shards do not have a separate size field.
                        // Reed-Solomon encoding generates parity data for the entire payload
                        // (including the "size field position"), and this parity data should
                        // be copied as-is without modification.
                        let copy_start = payload_offset;
                        let copy_len = self.encode_cache[k].len();
                        if copy_len > 0 && copy_start + copy_len <= self.shard_cache[k].len() {
                            self.shard_cache[k][copy_start..copy_start + copy_len]
                                .copy_from_slice(&self.encode_cache[k]);
                        }
                        
                        // Take the parity shard from shard_cache (matching kcp-go behavior)
                        // In kcp-go: ps[k] = ps[k][:enc.maxSize]
                        let mut parity = vec![0u8; self.max_size];
                        parity.copy_from_slice(&self.shard_cache[k][..self.max_size]);
                        parity_shards.push(parity);
                        self.next = (self.next + 1) % self.paws;
                    }
                } else {
                    // Encoding failed, skip parity but still advance seqid
                    log::warn!("[FEC] Reed-Solomon encoding failed, skipping parity shards");
                    self.skip_parity();
                }
            } else {
                // Non-continuous data detected, skip parity generation but advance seqid
                let interval = now - self.ts_latest_packet;
                log::trace!("[FEC] Non-continuous data detected (interval={}ms >= rto={}ms), skipping parity generation", 
                           interval, rto);
                self.skip_parity();
            }

            // Reset
            self.shard_count = 0;
            self.max_size = 0;
        }

        // Record the time of the latest data packet
        self.ts_latest_packet = now;
        
        if !parity_shards.is_empty() {
            log::trace!("[FEC] Returning {} parity shards", parity_shards.len());
        }

        parity_shards
    }

    fn skip_parity(&mut self) {
        self.next = (self.next + self.parity_shards as u32) % self.paws;
    }
}

/// Shard element for FEC decoder
#[derive(Debug, Clone)]
struct ShardElement {
    seqid: u32,
    data: Vec<u8>,
    flag: FecType,
}

impl PartialEq for ShardElement {
    fn eq(&self, other: &Self) -> bool {
        self.seqid == other.seqid
    }
}

impl Eq for ShardElement {}

impl PartialOrd for ShardElement {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        // Reverse order for max heap (newest first)
        other.seqid.partial_cmp(&self.seqid)
    }
}

impl Ord for ShardElement {
    fn cmp(&self, other: &Self) -> Ordering {
        other.seqid.cmp(&self.seqid)
    }
}

/// Shard heap for FEC decoder
#[derive(Debug)]
struct ShardHeap {
    elements: BinaryHeap<ShardElement>,
    marks: HashSet<u32>,
}

impl ShardHeap {
    fn new() -> Self {
        ShardHeap {
            elements: BinaryHeap::new(),
            marks: HashSet::new(),
        }
    }

    fn push(&mut self, elem: ShardElement) {
        if !self.marks.contains(&elem.seqid) {
            self.marks.insert(elem.seqid);
            self.elements.push(elem);
        }
    }

    fn pop(&mut self) -> Option<ShardElement> {
        self.elements.pop().map(|e| {
            self.marks.remove(&e.seqid);
            e
        })
    }

    fn len(&self) -> usize {
        self.elements.len()
    }

    fn has(&self, seqid: u32) -> bool {
        self.marks.contains(&seqid)
    }
}

/// FEC decoder for incoming packets
#[derive(Debug)]
pub struct FecDecoder {
    data_shards: usize,
    #[allow(dead_code)]
    parity_shards: usize,
    shard_size: usize,
    paws: u32,
    shard_set: HashMap<u32, ShardHeap>,
    newest_shard_id: u32,
    decode_cache: Vec<Option<Vec<u8>>>,
    flag_cache: Vec<bool>,
    codec: ReedSolomon<Field>,
}

impl FecDecoder {
    pub fn new(data_shards: usize, parity_shards: usize) -> Option<Self> {
        if data_shards == 0 || parity_shards == 0 {
            return None;
        }
        if data_shards + parity_shards > 256 {
            return None;
        }

        let shard_size = data_shards + parity_shards;
        let paws = 0xffffffff / shard_size as u32 * shard_size as u32;

        let codec = ReedSolomon::new(data_shards, parity_shards).ok()?;

        let mut decode_cache = Vec::with_capacity(shard_size);
        for _ in 0..shard_size {
            decode_cache.push(None);
        }

        let flag_cache = vec![false; shard_size];

        Some(FecDecoder {
            data_shards,
            parity_shards,
            shard_size,
            paws,
            shard_set: HashMap::new(),
            newest_shard_id: 0,
            decode_cache,
            flag_cache,
            codec,
        })
    }

    /// Decode a FEC packet, returns recovered packets if any
    pub fn decode(&mut self, buf: &[u8]) -> Vec<Vec<u8>> {
        if buf.len() < FEC_HEADER_SIZE_PLUS_2 {
            return Vec::new();
        }

        let header = match FecHeader::decode(buf) {
            Some(h) => h,
            None => return Vec::new(),
        };

        // Check seqid < paws to avoid invalid packets
        if header.seqid >= self.paws {
            return Vec::new();
        }

        let shard_id = header.seqid / self.shard_size as u32;
        let shard = self.shard_set.entry(shard_id).or_insert_with(ShardHeap::new);

        // Ignore duplicate packets
        if shard.has(header.seqid) {
            return Vec::new();
        }

        // Push packet into shard heap
        let elem = ShardElement {
            seqid: header.seqid,
            data: buf.to_vec(),
            flag: header.flag(),
        };
        shard.push(elem);
        
        // Log received packet type
        let packet_type = match header.flag() {
            FecType::Data => "DATA",
            FecType::Parity => "PARITY",
        };
        log::trace!("[FEC DECODER] Received {} packet: seqid={}, shard_id={}, shard_len={}/{}", 
                    packet_type, header.seqid, shard_id, shard.len(), self.shard_size);

        // Try to recover if we have enough shards
        let mut recovered = Vec::new();
        if shard.len() >= self.data_shards {
            // Prepare decode cache
            for k in 0..self.shard_size {
                self.decode_cache[k] = None;
                self.flag_cache[k] = false;
            }

            let mut num_data_shard = 0;
            let mut maxlen = 0;
            let mut pkts = Vec::new();

            // Pop all shards and fill decode cache
            // In kcp-go, pkt.data() returns bts[6:], which is [size(2B)][payload]
            while let Some(pkt) = shard.pop() {
                pkts.push(pkt.clone());
                let idx = (pkt.seqid % self.shard_size as u32) as usize;
                
                // Extract data part (from offset 6, which is [size(2B)][payload])
                if pkt.data.len() > FEC_HEADER_SIZE {
                    let data_part = &pkt.data[FEC_HEADER_SIZE..];
                    self.decode_cache[idx] = Some(data_part.to_vec());
                    self.flag_cache[idx] = true;
                    if pkt.flag == FecType::Data {
                        num_data_shard += 1;
                    }
                    if data_part.len() > maxlen {
                        maxlen = data_part.len();
                    }
                }
            }

            // Case 1: All data shards are present
            if num_data_shard == self.data_shards {
                log::trace!("[FEC DECODER] All {} data shards present, no recovery needed", self.data_shards);
            } else {
                // Case 2: Some data shards missing, try to recover
                let missing_count = self.data_shards - num_data_shard;
                log::info!("[FEC DECODER] Missing {} data shards (have {}/{}), attempting recovery...", 
                           missing_count, num_data_shard, self.data_shards);
                log::trace!("[FEC DECODER] Total shards collected: {}, data shards: {}, parity shards: {}", 
                           shard.len(), num_data_shard, shard.len() - num_data_shard);
                
                // Make all shards equal-sized and prepare for reconstruction
                for k in 0..self.shard_size {
                    if let Some(ref mut data) = self.decode_cache[k] {
                        if data.len() < maxlen {
                            data.resize(maxlen, 0);
                        }
                    } else if k < self.data_shards {
                        // Missing data shard, allocate buffer
                        self.decode_cache[k] = Some(vec![0u8; maxlen]);
                        log::trace!("[FEC DECODER] Allocated buffer for missing data shard at index {}", k);
                    }
                }

                // Reed-Solomon erasure decoding
                if self.codec.reconstruct_data(&mut self.decode_cache).is_ok() {
                    // Extract recovered data shards
                    // Return format: [size(2B)][payload] (matching kcp-go)
                    let mut recovered_indices = Vec::new();
                    for k in 0..self.data_shards {
                        if !self.flag_cache[k] {
                            if let Some(ref data) = self.decode_cache[k] {
                                // Return [size(2B)][payload] format, not full packet
                                recovered.push(data.clone());
                                recovered_indices.push(k);
                            }
                        }
                    }
                    
                    if !recovered.is_empty() {
                        log::info!("[FEC DECODER] ✓ Successfully recovered {} packets! (indices: {:?})", 
                                   recovered.len(), recovered_indices);
                    } else {
                        log::warn!("[FEC DECODER] Recovery succeeded but no packets recovered");
                    }
                } else {
                    log::warn!("[FEC DECODER] ✗ Recovery failed! Missing {} data shards, have {} total shards", 
                               missing_count, shard.len());
                }
            }
        }

        // Update newest shard id
        if shard_id > self.newest_shard_id {
            self.newest_shard_id = shard_id;
        }

        // Discard old shards
        self.discard_shards();

        recovered
    }

    fn discard_shards(&mut self) {
        // 只保留最近的 MAX_SHARD_SETS 个 shard sets
        // 与 kcp-go 的逻辑一致：discard if (newestShardId - shardId) > MAX_SHARD_SETS
        // kcp-go: _itimediff(dec.newestShardId*uint32(dec.shardSize), shardId*uint32(dec.shardSize)) > maxShardSets*int32(dec.shardSize)
        // 简化为：(newestShardId - shardId) * shardSize > maxShardSets * shardSize
        // 即：newestShardId - shardId > maxShardSets
        let threshold = self.newest_shard_id.saturating_sub(MAX_SHARD_SETS);
        self.shard_set.retain(|&shard_id, _| shard_id >= threshold);
    }
}
