use std::{
    io::{self, ErrorKind, Write},
    net::SocketAddr,
    sync::Arc,
    task::{Context, Poll, Waker},
    time::{Duration, Instant},
};

use futures_util::future;
use kcp::{Error as KcpError, Kcp, KcpResult};
use log::{error, trace};
use tokio::{net::UdpSocket, sync::mpsc};

use crate::{
    crypt::{BlockCrypt, CRYPT_HEADER_SIZE, NONCE_SIZE, CRC_SIZE},
    fec::{FecEncoder, FecDecoder, FEC_HEADER_SIZE, FEC_HEADER_SIZE_PLUS_2, TYPE_DATA, TYPE_PARITY}, 
    utils::now_millis, 
    KcpConfig
};
use std::sync::Mutex;
use rand::RngCore;

/// Writer for sending packets to the underlying UdpSocket
struct UdpOutput {
    socket: Arc<UdpSocket>,
    target_addr: SocketAddr,
    delay_tx: mpsc::UnboundedSender<Vec<u8>>,
    fec_encoder: Option<Arc<Mutex<FecEncoder>>>,
    crypt: Option<Arc<dyn BlockCrypt>>,
    header_size: usize,
    rto: u32, // Round trip time in milliseconds for FEC continuity check
    salt: Vec<u8>,
}

impl UdpOutput {
    /// Create a new Writer for writing packets to UdpSocket
    pub fn new(
        socket: Arc<UdpSocket>,
        target_addr: SocketAddr,
        fec_encoder: Option<Arc<Mutex<FecEncoder>>>,
        crypt: Option<Arc<dyn BlockCrypt>>,
        header_size: usize,
        rto: u32,
        salt: Vec<u8>,
    ) -> UdpOutput {
        let (delay_tx, mut delay_rx) = mpsc::unbounded_channel::<Vec<u8>>();

        {
            let socket = socket.clone();
            tokio::spawn(async move {
                while let Some(buf) = delay_rx.recv().await {
                    if let Err(err) = socket.send_to(&buf, target_addr).await {
                        error!("[SEND] UDP delayed send failed, error: {}", err);
                    }
                }
            });
        }

        UdpOutput {
            socket,
            target_addr,
            delay_tx,
            fec_encoder,
            crypt,
            header_size,
            rto,
            salt,
        }
    }
}

impl Write for UdpOutput {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        // Debug: log KCP packet before FEC encoding
        trace!("[UdpOutput::write] KCP packet len={}, first 16 bytes: {:02x?}", 
               buf.len(), &buf[..buf.len().min(16)]);
        
        // 参考 kcp-go: KCP output -> 预留头部空间 -> FEC encoding -> Encryption -> TxQueue
        // header_size 已经包含了加密头部大小（如果有）+ FEC 头部大小（如果有）
        // 数据包布局: [加密头部(20B)][FEC头部(8B)][KCP数据]
        let mut data_packet = vec![0u8; self.header_size + buf.len()];
        data_packet[self.header_size..].copy_from_slice(buf);
        
        let mut parity_packets = Vec::new();
        
        // 1. FEC encoding (在预留的头部空间中写入 FEC 头部)
        if let Some(ref fec_encoder) = self.fec_encoder {
            trace!("[UdpOutput] FEC encoder exists, calling encode()");
            parity_packets = fec_encoder.lock().unwrap().encode(&mut data_packet, self.rto);
            if !parity_packets.is_empty() {
                trace!("[UdpOutput] Generated {} parity packets", parity_packets.len());
            } else {
                trace!("[UdpOutput] No parity packets generated");
            }
        } else {
            trace!("[UdpOutput] No FEC encoder configured");
        }

        // 2. Encryption (在预留的加密头部空间中填充 nonce 和 CRC32，然后加密)
        // 参考 kcp-go: 
        //   - CFB 模式: fillRand(buf[:nonceSize]) -> CRC32 -> block.Encrypt(buf, buf)
        //   - AEAD 模式: fillRand(buf[:nonceSize]) -> block.Seal(dst, nonce, plaintext, nil)
        if let Some(ref crypt) = self.crypt {
            let mut rng = rand::thread_rng();
            
            if crypt.is_aead() {
                // AEAD 模式（如 AES-GCM）
                let nonce_size = crypt.nonce_size();
                let overhead = crypt.overhead();
                
                // 填充随机 nonce
                rng.fill_bytes(&mut data_packet[..nonce_size]);
                
                // 使用 Seal 方法加密（不计算 CRC32，因为 AEAD 自带认证）
                // plaintext 是 nonce 之后的所有数据
                let plaintext = data_packet[nonce_size..].to_vec();
                let nonce = data_packet[..nonce_size].to_vec();
                
                // 计算需要的空间：plaintext + overhead
                let required_size = plaintext.len() + overhead;
                let current_size = data_packet.len();
                if current_size < nonce_size + required_size {
                    data_packet.resize(nonce_size + required_size, 0);
                }
                
                match crypt.seal(&mut data_packet[nonce_size..], &nonce, &plaintext) {
                    Ok(sealed_len) => {
                        // Seal 成功，数据包现在是 [nonce][ciphertext][tag]
                        let new_len = nonce_size + sealed_len;
                        data_packet.truncate(new_len);
                    }
                    Err(e) => {
                        error!("[UdpOutput] AEAD Seal failed: {}", e);
                        return Err(io::Error::new(io::ErrorKind::Other, format!("AEAD Seal failed: {}", e)));
                    }
                }
                
                // 同样处理 parity packets
                for parity_packet in &mut parity_packets {
                    rng.fill_bytes(&mut parity_packet[..nonce_size]);
                    let plaintext = parity_packet[nonce_size..].to_vec();
                    let nonce = parity_packet[..nonce_size].to_vec();
                    
                    let required_size = plaintext.len() + overhead;
                    let current_size = parity_packet.len();
                    if current_size < nonce_size + required_size {
                        parity_packet.resize(nonce_size + required_size, 0);
                    }
                    
                    match crypt.seal(&mut parity_packet[nonce_size..], &nonce, &plaintext) {
                        Ok(sealed_len) => {
                            let new_len = nonce_size + sealed_len;
                            parity_packet.truncate(new_len);
                        }
                        Err(e) => {
                            error!("[UdpOutput] AEAD Seal failed for parity packet: {}", e);
                            return Err(io::Error::new(io::ErrorKind::Other, format!("AEAD Seal failed: {}", e)));
                        }
                    }
                }
            } else {
                // CFB 模式（传统加密方式）
                // 填充随机 nonce (在数据包的开头)
                rng.fill_bytes(&mut data_packet[..NONCE_SIZE]);
                
                trace!("[UdpOutput::write] salt: {:02x?}", &self.salt);
                // 计算 CRC32（从加密头部之后的数据开始计算）
                let checksum = if self.salt.len() == 0 {
                    crc32fast::hash(&data_packet[CRYPT_HEADER_SIZE..])
                }else{
                    let mut data2 = Vec::from(&data_packet[CRYPT_HEADER_SIZE..]);
                    data2.extend_from_slice(&self.salt);
                    crc32fast::hash(&data2[..])
                };
                data_packet[NONCE_SIZE..CRYPT_HEADER_SIZE].copy_from_slice(&checksum.to_le_bytes());
                
                // 加密整个包（包括加密头部、FEC头部和数据）
                // 需要临时副本，因为 encrypt 需要同时借用输入和输出
                let mut encrypted = data_packet.clone();
                crypt.encrypt(&mut encrypted, &data_packet);
                data_packet = encrypted;
                
                // 同样加密 parity packets
                for parity_packet in &mut parity_packets {
                    // 填充随机 nonce
                    rng.fill_bytes(&mut parity_packet[..NONCE_SIZE]);
                    
                    // 计算 CRC32
                    let checksum = if self.salt.len() == 0 {
                        crc32fast::hash(&parity_packet[CRYPT_HEADER_SIZE..])
                    }else{
                        let mut data2 = Vec::from(&parity_packet[CRYPT_HEADER_SIZE..]);
                        data2.extend_from_slice(&self.salt);
                        crc32fast::hash(&data2[..])
                    };
                    parity_packet[NONCE_SIZE..CRYPT_HEADER_SIZE].copy_from_slice(&checksum.to_le_bytes());
                    
                    // 加密（需要临时副本，因为 encrypt 需要同时借用输入和输出）
                    let mut encrypted = parity_packet.clone();
                    crypt.encrypt(&mut encrypted, parity_packet);
                    *parity_packet = encrypted;
                }
            }
        }

        // Send data packet
        let send_packet = |packet: &[u8], is_parity: bool| -> io::Result<()> {
            // Debug: log packet format
            // 数据包布局: [加密头部(20B)][FEC头部(8B)][KCP数据] 或 [FEC头部(8B)][KCP数据] 或 [KCP数据]
            // 只有当 FEC 被启用时，才解析和打印 FEC 头部信息
            if let Some(_) = self.fec_encoder {
            let crypt_offset = if self.crypt.is_some() { CRYPT_HEADER_SIZE } else { 0 };
            let fec_offset = crypt_offset;
            
            if packet.len() >= fec_offset + FEC_HEADER_SIZE {
                let seqid = u32::from_le_bytes([
                    packet[fec_offset], 
                    packet[fec_offset + 1], 
                    packet[fec_offset + 2], 
                    packet[fec_offset + 3]
                ]);
                let flag = u16::from_le_bytes([packet[fec_offset + 4], packet[fec_offset + 5]]);
                
                if is_parity {
                    let packet_type = if flag == TYPE_PARITY { "TYPE_PARITY" } else { "UNKNOWN" };
                    trace!("[SEND] FEC PARITY packet: seqid={}, flag={:04x} ({}), len={}", 
                           seqid, flag, packet_type, packet.len());
                } else {
                    if packet.len() >= fec_offset + FEC_HEADER_SIZE_PLUS_2 {
                        let size_field = u16::from_le_bytes([
                            packet[fec_offset + FEC_HEADER_SIZE], 
                            packet[fec_offset + FEC_HEADER_SIZE + 1]
                        ]) as usize;
                        let kcp_packet_len = packet.len() - fec_offset - FEC_HEADER_SIZE_PLUS_2;
                        trace!("[SEND] FEC DATA packet: seqid={}, flag={:04x} (TYPE_DATA), size_field={}, kcp_packet_len={}", 
                               seqid, flag, size_field, kcp_packet_len);
                    }
                }
                }
            } else {
                // FEC 被禁用，只打印简单的数据包信息
                let crypt_offset = if self.crypt.is_some() { CRYPT_HEADER_SIZE } else { 0 };
                let kcp_packet_len = packet.len() - crypt_offset;
                trace!("[SEND] KCP packet (no FEC): len={}, kcp_data_len={}", 
                       packet.len(), kcp_packet_len);
            }
            
            match self.socket.try_send_to(packet, self.target_addr) {
                Ok(_) => {
                    if is_parity {
                        trace!("[SEND] Parity packet sent successfully via UDP");
                    }
                    Ok(())
                },
                Err(ref err) if err.kind() == ErrorKind::WouldBlock => {
                    trace!("[SEND] UDP send EAGAIN, packet.size: {} bytes, delayed send", packet.len());
                    self.delay_tx.send(packet.to_owned()).expect("channel closed unexpectedly");
                    Ok(())
                }
                Err(err) => Err(err),
            }
        };

        send_packet(&data_packet, false)?;
        
        // Send parity packets
        if !parity_packets.is_empty() {
            trace!("[UdpOutput] ===== Sending {} FEC parity packets =====", parity_packets.len());
            for (idx, parity) in parity_packets.iter().enumerate() {
                trace!("[UdpOutput] Parity packet #{}/{}: len={} bytes", idx + 1, parity_packets.len(), parity.len());
                send_packet(parity, true)?;
            }
            trace!("[UdpOutput] ===== All {} parity packets sent successfully =====", parity_packets.len());
        }

        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[derive(Debug)]
pub struct KcpSocket {
    kcp: Kcp<UdpOutput>,
    last_update: Instant,
    socket: Arc<UdpSocket>,
    flush_write: bool,
    flush_ack_input: bool,
    sent_first: bool,
    pending_sender: Option<Waker>,
    pending_receiver: Option<Waker>,
    closed: bool,
    allow_recv_empty_packet: bool,
    #[allow(dead_code)]
    fec_encoder: Option<Arc<Mutex<FecEncoder>>>,
    fec_decoder: Option<Arc<Mutex<FecDecoder>>>,
    crypt: Option<Arc<dyn BlockCrypt>>,
    #[allow(dead_code)]
    header_size: usize,
    salt: Vec<u8>,
}

impl KcpSocket {
    pub fn new(
        c: &KcpConfig,
        conv: u32,
        socket: Arc<UdpSocket>,
        target_addr: SocketAddr,
        stream: bool,
        salt: Vec<u8>,
    ) -> KcpResult<KcpSocket> {
        // Initialize encryption and FEC encoder/decoder if enabled
        // In kcp-go: headerSize starts at 0, then adds cryptHeaderSize if encryption is enabled,
        // then adds fecHeaderSizePlus2 if FEC is enabled
        let mut header_size = 0;
        
        // Encryption header size (if enabled)
        let crypt = c.crypt.clone();
        if let Some(ref crypt) = crypt {
            header_size += crypt.header_size();
        }
        
        let fec_encoder = if c.fec_data_shards > 0 && c.fec_parity_shards > 0 {
            // headerOffset for FEC encoder is the current header_size (before adding FEC header)
            trace!("[KcpSocket] Creating FEC encoder: data_shards={}, parity_shards={}, header_offset={}", 
                   c.fec_data_shards, c.fec_parity_shards, header_size);
            let fec_encoder = FecEncoder::new(c.fec_data_shards, c.fec_parity_shards, header_size)
                .map(|e| Arc::new(Mutex::new(e)));
            if fec_encoder.is_some() {
                trace!("[KcpSocket] FEC encoder created successfully");
            } else {
                error!("[KcpSocket] Failed to create FEC encoder!");
            }
            // After creating FEC encoder, add FEC header size to header_size
            // In kcp-go: sess.headerSize += fecHeaderSizePlus2
            header_size += FEC_HEADER_SIZE_PLUS_2;
            fec_encoder
        } else {
            trace!("[KcpSocket] FEC disabled: data_shards={}, parity_shards={}", 
                   c.fec_data_shards, c.fec_parity_shards);
            None
        };
        
        let fec_decoder = if c.fec_data_shards > 0 && c.fec_parity_shards > 0 {
            FecDecoder::new(c.fec_data_shards, c.fec_parity_shards)
                .map(|d| Arc::new(Mutex::new(d)))
        } else {
            None
        };

        // Calculate header size (encryption header + FEC header if enabled)
        let actual_header_size = header_size;

        // Use maxFECEncodeLatency (500ms) for FEC continuity check, matching kcp-go
        // In kcp-go: maxFECEncodeLatency = 500ms is used for fecEncoder.encode()
        // This is NOT the KCP RTO, but a threshold for detecting non-continuous data
        let default_rto = 500u32;
        
        let output = UdpOutput::new(
            socket.clone(),
            target_addr,
            fec_encoder.clone(),
            crypt.clone(),
            actual_header_size,
            default_rto,
            salt.clone(),
        );
        let mut kcp = if stream {
            Kcp::new_stream(conv, output)
        } else {
            Kcp::new(conv, output)
        };
        c.apply_config(&mut kcp);

        // Only set input_conv when the server allocates a new conv for
        // a client that starts with conv=0. When the listener reads the
        // client's actual conv (non-zero), no input_conv needed.
        if conv == 0 {
            kcp.input_conv();
        }

        kcp.update(now_millis())?;

        Ok(KcpSocket {
            kcp,
            last_update: Instant::now(),
            socket,
            flush_write: c.flush_write,
            flush_ack_input: c.flush_acks_input,
            sent_first: false,
            pending_sender: None,
            pending_receiver: None,
            closed: false,
            allow_recv_empty_packet: c.allow_recv_empty_packet,
            fec_encoder,
            fec_decoder,
            crypt,
            header_size: actual_header_size,
            salt,
        })
    }

    /// Call every time you got data from transmission
    pub fn input(&mut self, buf: &[u8]) -> KcpResult<bool> {
        // Decryption (before FEC decoding)
        // 参考 kcp-go: network -> [decryption ->] [crc32 ->] [FEC ->] [KCP input ->] stream
        // kcp-go packetInput:
        //   - CFB 模式: block.Decrypt(data, data) -> data[nonceSize:] -> 验证CRC32 -> data[crcSize:]
        //   - AEAD 模式: block.Open(ciphertext[:0], nonce, ciphertext, nil) -> plaintext (不验证CRC32)
        let data: Vec<u8> = if let Some(ref crypt) = self.crypt {
            if crypt.is_aead() {
                // AEAD 模式（如 AES-GCM）
                let nonce_size = crypt.nonce_size();
                let overhead = crypt.overhead();
                
                if buf.len() < nonce_size + overhead {
                    trace!("[INPUT] AEAD packet too short: {} < {}", buf.len(), nonce_size + overhead);
                    return Ok(false);
                }
                
                trace!("[INPUT] AEAD encrypted packet received, len={}, first 32 bytes: {:02x?}", 
                       buf.len(), &buf[..buf.len().min(32)]);
                
                // 使用 Open 方法解密（不验证 CRC32，因为 AEAD 自带认证）
                let nonce = &buf[..nonce_size];
                let ciphertext = &buf[nonce_size..];
                
                let mut decrypted = vec![0u8; ciphertext.len()]; // 足够大的缓冲区
                match crypt.open(&mut decrypted, nonce, ciphertext) {
                    Ok(plaintext_len) => {
                        decrypted.truncate(plaintext_len);
                        trace!("[INPUT] AEAD decrypted packet, len={}, first 32 bytes: {:02x?}", 
                               decrypted.len(), &decrypted[..decrypted.len().min(32)]);
                        decrypted
                    }
                    Err(e) => {
                        trace!("[INPUT] AEAD Open failed: {}", e);
                        return Ok(false);
                    }
                }
            } else {
                // CFB 模式（传统加密方式）
                if buf.len() < CRYPT_HEADER_SIZE {
                    trace!("[INPUT] Packet too short for encryption header: {} < {}", buf.len(), CRYPT_HEADER_SIZE);
                    return Ok(false);
                }
                
                trace!("[INPUT] Encrypted packet received, len={}, first 32 bytes: {:02x?}", 
                       buf.len(), &buf[..buf.len().min(32)]);
                
                // 解密整个包（与 kcp-go 一致：block.Decrypt(data, data)）
                // 注意：由于 Rust 借用检查器的限制，我们先复制再解密
                // 但 decrypt 函数内部支持原地解密（如果 dst 和 src 指向同一内存）
                let mut decrypted = buf.to_vec();
                crypt.decrypt(&mut decrypted, buf);
                
                trace!("[INPUT] Decrypted packet, first 32 bytes: {:02x?}", 
                       &decrypted[..decrypted.len().min(32)]);
                
                // 跳过 nonce (16字节)，现在 decrypted 是 [CRC32(4B)][FEC头部][KCP数据]
                if decrypted.len() < NONCE_SIZE {
                    trace!("[INPUT] Decrypted packet too short for nonce: {} < {}", decrypted.len(), NONCE_SIZE);
                    return Ok(false);
                }
                let data_after_nonce = &decrypted[NONCE_SIZE..];
                
                // 验证 CRC32
                // kcp-go: checksum := crc32.ChecksumIEEE(data[crcSize:])
                //         if checksum != binary.LittleEndian.Uint32(data)
                if data_after_nonce.len() < CRC_SIZE {
                    trace!("[INPUT] Data after nonce too short for CRC32: {} < {}", data_after_nonce.len(), CRC_SIZE);
                    return Ok(false);
                }
                let stored_checksum = u32::from_le_bytes([
                    data_after_nonce[0],
                    data_after_nonce[1],
                    data_after_nonce[2],
                    data_after_nonce[3],
                ]);
                let calculated_checksum = if self.salt.len() == 0 {
                    crc32fast::hash(&data_after_nonce[CRC_SIZE..])
                } else {
                    let mut data2 = Vec::from(&data_after_nonce[CRC_SIZE..]);
                    data2.extend_from_slice(&self.salt);
                    crc32fast::hash(&data2[..])
                };
                
                if stored_checksum != calculated_checksum {
                    trace!("[INPUT] CRC32 checksum mismatch, stored={}, calculated={}, data_len={}", 
                           stored_checksum, calculated_checksum, data_after_nonce.len());
                    trace!("[INPUT] Data after nonce (first 32 bytes): {:02x?}", 
                           &data_after_nonce[..data_after_nonce.len().min(32)]);
                    return Ok(false); // CRC32 校验失败
                }
                
                trace!("[INPUT] CRC32 check passed, stored={}, calculated={}", 
                       stored_checksum, calculated_checksum);
                
                // 跳过 CRC32 (4字节)，返回 [FEC头部][KCP数据]
                let result = data_after_nonce[CRC_SIZE..].to_vec();
                trace!("[INPUT] After decryption, data len={}, first 16 bytes: {:02x?}", 
                       result.len(), &result[..result.len().min(16)]);
                result
            }
        } else {
            buf.to_vec()
        };
        
        // Check if this is a FEC packet (even if FEC decoder is not configured)
        // This handles the case where client sends FEC packets but server doesn't have FEC enabled
        if data.len() >= FEC_HEADER_SIZE_PLUS_2 {
            use byteorder::{LittleEndian, ReadBytesExt};
            // Check FEC flag (at offset 4)
            if data.len() >= 6 {
                let mut reader = &data[4..6];
                if let Ok(flag) = reader.read_u16::<LittleEndian>() {
                    if flag == TYPE_DATA || flag == TYPE_PARITY {
                        // This is a FEC packet
                        // Extract seqid for logging
                        let seqid = if data.len() >= 4 {
                            u32::from_le_bytes([data[0], data[1], data[2], data[3]])
                        } else {
                            0
                        };
                        
                        let fec_decoder_clone = self.fec_decoder.clone();
                        if let Some(ref fec_decoder) = fec_decoder_clone {
                            // FEC decoder is configured, use it for decoding and recovery
                            let recovered = {
                                let mut decoder = fec_decoder.lock().unwrap();
                                decoder.decode(&data)
                            };
                            
                            // Input data packet directly
                            // In kcp-go: data[fecHeaderSizePlus2:] is used directly, without checking size field
                            if flag == TYPE_DATA {
                                trace!("[INPUT] ===== Received FEC DATA packet: seqid={}, len={} =====", seqid, data.len());
                                if data.len() >= FEC_HEADER_SIZE_PLUS_2 {
                                    // Extract KCP packet directly from offset 8 (matching kcp-go)
                                    let kcp_packet = &data[FEC_HEADER_SIZE_PLUS_2..];
                                    trace!("[INPUT] FEC data packet: data_len={}, kcp_packet_len={}", 
                                           data.len(), kcp_packet.len());
                                    match self.kcp.input(kcp_packet) {
                                        Ok(..) => {
                                            trace!("[INPUT] KCP input success, kcp_packet_len={}", kcp_packet.len());
                                        }
                                        Err(KcpError::ConvInconsistent(..)) => {
                                            trace!("[INPUT] Conv inconsistent, ignored");
                                        }
                                        Err(err) => {
                                            trace!("[INPUT] KCP input error: {:?}", err);
                                        }
                                    }
                                }
                            }
                            
                            // Log parity packet received
                            if flag == TYPE_PARITY {
                                trace!("[INPUT] ===== Received FEC PARITY packet: seqid={}, len={} =====", seqid, data.len());
                            }
                            
                            // Input recovered packets
                            // Recovered format: [size(2B)][payload], matching kcp-go
                            if !recovered.is_empty() {
                                trace!("[INPUT] ===== FEC recovered {} packets =====", recovered.len());
                            }
                            for r in recovered {
                                if r.len() >= 2 {
                                    let sz = u16::from_le_bytes([r[0], r[1]]) as usize;
                                    if sz <= r.len() && sz >= 2 {
                                        let kcp_packet = &r[2..sz];
                                        match self.kcp.input(kcp_packet) {
                                            Ok(..) => {}
                                            Err(KcpError::ConvInconsistent(..)) => {
                                                trace!("[INPUT] Recovered packet conv inconsistent, ignored");
                                            }
                                            Err(err) => {
                                                trace!("[INPUT] Recovered packet KCP input error: {:?}", err);
                                            }
                                        }
                                    }
                                }
                            }
                            
                            self.last_update = Instant::now();
                            if self.flush_ack_input {
                                let _ = self.kcp.flush_ack();
                            }
                            return Ok(self.try_wake_pending_waker());
                        } else {
                            // FEC decoder is not configured, but we received a FEC packet
                            // Skip FEC header and input the KCP packet directly
                            // This handles the case where client has FEC enabled but server doesn't
                            if flag == TYPE_DATA {
                                if data.len() >= FEC_HEADER_SIZE_PLUS_2 {
                                    // Extract KCP packet directly from offset 8 (matching kcp-go)
                                    let kcp_packet = &data[FEC_HEADER_SIZE_PLUS_2..];
                                    trace!("[INPUT] FEC data packet (no decoder): data_len={}, kcp_packet_len={}", 
                                           data.len(), kcp_packet.len());
                                    match self.kcp.input(kcp_packet) {
                                        Ok(..) => {
                                            trace!("[INPUT] KCP input success (no decoder), kcp_packet_len={}", kcp_packet.len());
                                        }
                                        Err(KcpError::ConvInconsistent(..)) => {
                                            trace!("[INPUT] Conv inconsistent, ignored");
                                        }
                                        Err(err) => {
                                            trace!("[INPUT] KCP input error: {:?}", err);
                                        }
                                    }
                                    self.last_update = Instant::now();
                                    if self.flush_ack_input {
                                        let _ = self.kcp.flush_ack();
                                    }
                                    return Ok(self.try_wake_pending_waker());
                                }
                            } else {
                                // TYPE_PARITY packet without decoder, ignore it
                                trace!("[INPUT] FEC parity packet received but no decoder configured, ignoring");
                                return Ok(false);
                            }
                        }
                    }
                }
            }
        }
        
        // Not a FEC packet or FEC disabled, input directly
        match self.kcp.input(&data) {
            Ok(..) => {}
            Err(KcpError::ConvInconsistent(expected, actual)) => {
                trace!("[INPUT] Conv expected={} actual={} ignored", expected, actual);
                return Ok(false);
            }
            Err(err) => return Err(err),
        }
        self.last_update = Instant::now();

        if self.flush_ack_input {
            self.kcp.flush_ack()?;
        }

        Ok(self.try_wake_pending_waker())
    }

    /// Input a decrypted and CRC32-verified packet (similar to kcp-go's kcpInput)
    /// This method skips decryption and CRC32 verification, directly processing FEC and KCP input
    pub fn input_decrypted(&mut self, data: &[u8]) -> KcpResult<bool> {
        // 参考 kcp-go: kcpInput inputs a decrypted and crc32-checked packet
        // Skip decryption and CRC32 verification, directly process FEC and KCP
        
        // Check if this is a FEC packet (even if FEC decoder is not configured)
        if data.len() >= FEC_HEADER_SIZE_PLUS_2 {
            use byteorder::{LittleEndian, ReadBytesExt};
            // Check FEC flag (at offset 4)
            if data.len() >= 6 {
                let mut reader = &data[4..6];
                if let Ok(flag) = reader.read_u16::<LittleEndian>() {
                    if flag == TYPE_DATA || flag == TYPE_PARITY {
                        // This is a FEC packet
                        // Extract seqid for logging
                        let seqid = if data.len() >= 4 {
                            u32::from_le_bytes([data[0], data[1], data[2], data[3]])
                        } else {
                            0
                        };
                        
                        let fec_decoder_clone = self.fec_decoder.clone();
                        if let Some(ref fec_decoder) = fec_decoder_clone {
                            // FEC decoder is configured, use it for decoding and recovery
                            let recovered = {
                                let mut decoder = fec_decoder.lock().unwrap();
                                decoder.decode(data)
                            };
                            
                            // Log received packet type
                            if flag == TYPE_DATA {
                                trace!("[INPUT_DECRYPTED] ===== Received FEC DATA packet: seqid={}, len={} =====", seqid, data.len());
                            } else {
                                trace!("[INPUT_DECRYPTED] ===== Received FEC PARITY packet: seqid={}, len={} =====", seqid, data.len());
                            }
                            
                            // Input data packet directly
                            // In kcp-go: data[fecHeaderSizePlus2:] is used directly, without checking size field
                            if flag == TYPE_DATA {
                                if data.len() >= FEC_HEADER_SIZE_PLUS_2 {
                                    // Extract KCP packet directly from offset 8 (matching kcp-go)
                                    let kcp_packet = &data[FEC_HEADER_SIZE_PLUS_2..];
                                    trace!("[INPUT_DECRYPTED] FEC data packet: data_len={}, kcp_packet_len={}", 
                                           data.len(), kcp_packet.len());
                                    match self.kcp.input(kcp_packet) {
                                        Ok(..) => {
                                            trace!("[INPUT_DECRYPTED] KCP input success, kcp_packet_len={}", kcp_packet.len());
                                        }
                                        Err(KcpError::ConvInconsistent(..)) => {
                                            trace!("[INPUT_DECRYPTED] Conv inconsistent, ignored");
                                        }
                                        Err(err) => {
                                            trace!("[INPUT_DECRYPTED] KCP input error: {:?}", err);
                                        }
                                    }
                                }
                            }
                            
                            // Log recovered packets
                            if !recovered.is_empty() {
                                trace!("[INPUT_DECRYPTED] ===== FEC recovered {} packets =====", recovered.len());
                            }
                            
                            // Input recovered packets
                            // Recovered format: [size(2B)][payload], matching kcp-go
                            for r in recovered {
                                if r.len() >= 2 {
                                    let sz = u16::from_le_bytes([r[0], r[1]]) as usize;
                                    if sz <= r.len() && sz >= 2 {
                                        let kcp_packet = &r[2..sz];
                                        match self.kcp.input(kcp_packet) {
                                            Ok(..) => {}
                                            Err(KcpError::ConvInconsistent(..)) => {
                                                trace!("[INPUT_DECRYPTED] Recovered packet conv inconsistent, ignored");
                                            }
                                            Err(err) => {
                                                trace!("[INPUT_DECRYPTED] Recovered packet KCP input error: {:?}", err);
                                            }
                                        }
                                    }
                                }
                            }
                            
                            self.last_update = Instant::now();
                            if self.flush_ack_input {
                                let _ = self.kcp.flush_ack();
                            }
                            return Ok(self.try_wake_pending_waker());
                        } else {
                            // FEC decoder is not configured, but we received a FEC packet
                            // Skip FEC header and input the KCP packet directly
                            if flag == TYPE_DATA {
                                if data.len() >= FEC_HEADER_SIZE_PLUS_2 {
                                    // Extract KCP packet directly from offset 8 (matching kcp-go)
                                    let kcp_packet = &data[FEC_HEADER_SIZE_PLUS_2..];
                                    trace!("[INPUT_DECRYPTED] FEC data packet (no decoder): data_len={}, kcp_packet_len={}", 
                                           data.len(), kcp_packet.len());
                                    match self.kcp.input(kcp_packet) {
                                        Ok(..) => {
                                            trace!("[INPUT_DECRYPTED] KCP input success (no decoder), kcp_packet_len={}", kcp_packet.len());
                                        }
                                        Err(KcpError::ConvInconsistent(..)) => {
                                            trace!("[INPUT_DECRYPTED] Conv inconsistent, ignored");
                                        }
                                        Err(err) => {
                                            trace!("[INPUT_DECRYPTED] KCP input error: {:?}", err);
                                        }
                                    }
                                    self.last_update = Instant::now();
                                    if self.flush_ack_input {
                                        let _ = self.kcp.flush_ack();
                                    }
                                    return Ok(self.try_wake_pending_waker());
                                }
                            } else {
                                // TYPE_PARITY packet without decoder, ignore it
                                trace!("[INPUT_DECRYPTED] FEC parity packet received but no decoder configured, ignoring");
                                return Ok(false);
                            }
                        }
                    }
                }
            }
        }
        
        // Not a FEC packet or FEC disabled, input directly
        match self.kcp.input(data) {
            Ok(..) => {}
            Err(KcpError::ConvInconsistent(expected, actual)) => {
                trace!("[INPUT_DECRYPTED] Conv expected={} actual={} ignored", expected, actual);
                return Ok(false);
            }
            Err(err) => return Err(err),
        }
        self.last_update = Instant::now();

        if self.flush_ack_input {
            self.kcp.flush_ack()?;
        }

        Ok(self.try_wake_pending_waker())
    }

    /// Call if you want to send some data
    pub fn poll_send(&mut self, cx: &mut Context<'_>, mut buf: &[u8]) -> Poll<KcpResult<usize>> {
        if self.closed {
            return Err(io::Error::from(ErrorKind::BrokenPipe).into()).into();
        }

        // If:
        //     1. Have sent the first packet (asking for conv)
        //     2. Too many pending packets
        if self.sent_first
            && (self.kcp.wait_snd() >= self.kcp.snd_wnd() as usize
                || self.kcp.wait_snd() >= self.kcp.rmt_wnd() as usize
                || self.kcp.waiting_conv())
        {
            trace!(
                "[SEND] waitsnd={} sndwnd={} rmtwnd={} excceeded or waiting conv={}",
                self.kcp.wait_snd(),
                self.kcp.snd_wnd(),
                self.kcp.rmt_wnd(),
                self.kcp.waiting_conv()
            );

            if let Some(waker) = self.pending_sender.replace(cx.waker().clone()) {
                if !cx.waker().will_wake(&waker) {
                    waker.wake();
                }
            }
            return Poll::Pending;
        }

        if !self.sent_first && self.kcp.waiting_conv() && buf.len() > self.kcp.mss() {
            buf = &buf[..self.kcp.mss()];
        }

        let n = self.kcp.send(buf)?;
        self.sent_first = true;

        if self.kcp.wait_snd() >= self.kcp.snd_wnd() as usize || self.kcp.wait_snd() >= self.kcp.rmt_wnd() as usize {
            self.kcp.flush()?;
        }

        self.last_update = Instant::now();

        if self.flush_write {
            self.kcp.flush()?;
        }

        Ok(n).into()
    }

    /// Call if you want to send some data
    #[allow(dead_code)]
    pub async fn send(&mut self, buf: &[u8]) -> KcpResult<usize> {
        future::poll_fn(|cx| self.poll_send(cx, buf)).await
    }

    #[allow(dead_code)]
    pub fn try_recv(&mut self, buf: &mut [u8]) -> KcpResult<usize> {
        if self.closed {
            return Ok(0);
        }
        self.kcp.recv(buf)
    }

    pub fn poll_recv(&mut self, cx: &mut Context<'_>, buf: &mut [u8]) -> Poll<KcpResult<usize>> {
        if self.closed {
            return Ok(0).into();
        }

        match self.kcp.recv(buf) {
            e @ (Err(KcpError::RecvQueueEmpty) | Err(KcpError::ExpectingFragment)) => {
                trace!(
                    "[RECV] rcvwnd={} peeksize={} r={:?}",
                    self.kcp.rcv_wnd(),
                    self.kcp.peeksize().unwrap_or(0),
                    e
                );
            }
            Err(err) => return Err(err).into(),
            Ok(n) => {
                if n == 0 && !self.allow_recv_empty_packet {
                    trace!(
                        "[RECV] rcvwnd={} peeksize={} r=Ok(0)",
                        self.kcp.rcv_wnd(),
                        self.kcp.peeksize().unwrap_or(0),
                    );
                } else {
                    self.last_update = Instant::now();
                    return Ok(n).into();
                }
            }
        }

        if let Some(waker) = self.pending_receiver.replace(cx.waker().clone()) {
            if !cx.waker().will_wake(&waker) {
                waker.wake();
            }
        }

        Poll::Pending
    }

    #[allow(dead_code)]
    pub async fn recv(&mut self, buf: &mut [u8]) -> KcpResult<usize> {
        future::poll_fn(|cx| self.poll_recv(cx, buf)).await
    }

    pub fn flush(&mut self) -> KcpResult<()> {
        self.kcp.flush()?;
        self.last_update = Instant::now();
        Ok(())
    }

    fn try_wake_pending_waker(&mut self) -> bool {
        let mut waked = false;

        if self.pending_sender.is_some()
            && self.kcp.wait_snd() < self.kcp.snd_wnd() as usize
            && self.kcp.wait_snd() < self.kcp.rmt_wnd() as usize
            && !self.kcp.waiting_conv()
        {
            let waker = self.pending_sender.take().unwrap();
            waker.wake();

            waked = true;
        }

        if self.pending_receiver.is_some() {
            if let Ok(peek) = self.kcp.peeksize() {
                if self.allow_recv_empty_packet || peek > 0 {
                    let waker = self.pending_receiver.take().unwrap();
                    waker.wake();

                    waked = true;
                }
            }
        }

        waked
    }

    pub fn update(&mut self) -> KcpResult<Instant> {
        let now = now_millis();
        self.kcp.update(now)?;
        let next = self.kcp.check(now);

        self.try_wake_pending_waker();

        Ok(Instant::now() + Duration::from_millis(next as u64))
    }

    pub fn close(&mut self) {
        self.closed = true;
        if let Some(w) = self.pending_sender.take() {
            w.wake();
        }
        if let Some(w) = self.pending_receiver.take() {
            w.wake();
        }
    }

    pub fn udp_socket(&self) -> &Arc<UdpSocket> {
        &self.socket
    }

    pub fn can_close(&self) -> bool {
        self.kcp.wait_snd() == 0
    }

    pub fn conv(&self) -> u32 {
        self.kcp.conv()
    }

    pub fn set_conv(&mut self, conv: u32) {
        self.kcp.set_conv(conv);
    }

    pub fn waiting_conv(&self) -> bool {
        self.kcp.waiting_conv()
    }

    pub fn has_encryption(&self) -> bool {
        self.crypt.is_some()
    }

    pub fn peek_size(&self) -> KcpResult<usize> {
        self.kcp.peeksize()
    }

    pub fn last_update_time(&self) -> Instant {
        self.last_update
    }

    pub fn need_flush(&self) -> bool {
        (self.kcp.wait_snd() >= self.kcp.snd_wnd() as usize || self.kcp.wait_snd() >= self.kcp.rmt_wnd() as usize)
            && !self.kcp.waiting_conv()
    }
}

#[cfg(test)]
mod test {

    use kcp::Error as KcpError;
    use log::trace;
    use std::sync::Arc;
    use tokio::{
        net::UdpSocket,
        sync::Mutex,
        time::{self, Instant},
    };

    use super::KcpSocket;
    use crate::config::KcpConfig;

    #[tokio::test]
    async fn kcp_echo() {
        let _ = env_logger::try_init();

        static CONV: u32 = 0xdeadbeef;

        // s1 connects s2
        let s1 = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let s2 = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        let s1_addr = s1.local_addr().unwrap();
        let s2_addr = s2.local_addr().unwrap();

        let s1 = Arc::new(s1);
        let s2 = Arc::new(s2);

        let config = KcpConfig::default();
        let kcp1 = KcpSocket::new(&config, 0, s1.clone(), s2_addr, true, Vec::new()).unwrap();
        let kcp2 = KcpSocket::new(&config, CONV, s2.clone(), s1_addr, true, Vec::new()).unwrap();

        let kcp1 = Arc::new(Mutex::new(kcp1));
        let kcp2 = Arc::new(Mutex::new(kcp2));

        let kcp1_task = {
            let kcp1 = kcp1.clone();
            tokio::spawn(async move {
                loop {
                    let mut kcp = kcp1.lock().await;
                    let next = kcp.update().expect("update");
                    trace!("kcp1 next tick {:?}", next);
                    time::sleep_until(Instant::from_std(next)).await;
                }
            })
        };

        let kcp2_task = {
            let kcp2 = kcp2.clone();
            tokio::spawn(async move {
                loop {
                    let mut kcp = kcp2.lock().await;
                    let next = kcp.update().expect("update");
                    trace!("kcp2 next tick {:?}", next);
                    time::sleep_until(Instant::from_std(next)).await;
                }
            })
        };

        const SEND_BUFFER: &[u8] = b"HELLO WORLD";

        {
            let n = kcp1.lock().await.send(SEND_BUFFER).await.unwrap();
            assert_eq!(n, SEND_BUFFER.len());
        }

        let echo_task = tokio::spawn(async move {
            let mut buf = [0u8; 1024];

            loop {
                let n = s2.recv(&mut buf).await.unwrap();

                let packet = &mut buf[..n];

                let conv = kcp::get_conv(packet);
                if conv == 0 {
                    kcp::set_conv(packet, CONV);
                }

                let mut kcp2 = kcp2.lock().await;
                kcp2.input(packet).unwrap();

                match kcp2.try_recv(&mut buf) {
                    Ok(n) => {
                        let received = &buf[..n];
                        kcp2.send(received).await.unwrap();
                    }
                    Err(KcpError::RecvQueueEmpty) => {
                        continue;
                    }
                    Err(err) => {
                        panic!("kcp.recv error: {:?}", err);
                    }
                }
            }
        });

        {
            let mut buf = [0u8; 1024];

            loop {
                let n = s1.recv(&mut buf).await.unwrap();

                let packet = &buf[..n];

                let mut kcp1 = kcp1.lock().await;
                kcp1.input(packet).unwrap();

                match kcp1.try_recv(&mut buf) {
                    Ok(n) => {
                        let received = &buf[..n];
                        assert_eq!(received, SEND_BUFFER);
                        break;
                    }
                    Err(KcpError::RecvQueueEmpty) => {
                        continue;
                    }
                    Err(err) => {
                        panic!("kcp.recv error: {:?}", err);
                    }
                }
            }
        }

        echo_task.abort();
        kcp1_task.abort();
        kcp2_task.abort();
    }
}
