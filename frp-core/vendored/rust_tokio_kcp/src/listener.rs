use std::{
    io::{self, ErrorKind},
    net::SocketAddr,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
    collections::HashMap,
    sync::Mutex,
};

use byte_string::ByteStr;
use kcp::{Error as KcpError, KcpResult};
use log::{debug, error, trace};
use tokio::{
    net::{ToSocketAddrs, UdpSocket},
    sync::mpsc,
    task::JoinHandle,
    time,
};

use crate::{config::{KcpConfig, ListenerMode}, session::KcpSessionManager, stream::KcpStream};
use crate::fec::{FEC_HEADER_SIZE_PLUS_2, TYPE_DATA, TYPE_PARITY};
use crate::crypt::{CRYPT_HEADER_SIZE, NONCE_SIZE, CRC_SIZE};
use byteorder::{LittleEndian, ReadBytesExt};
use crc32fast;


pub enum CustomModeOperate{
    Add(u32, Vec<u8>,tokio::sync::oneshot::Sender<()>),//增加一个id
    Remove(u32,tokio::sync::oneshot::Sender<()>),//删除一个id的
}


#[derive(Debug)]
pub struct KcpListener {
    udp: Arc<UdpSocket>,
    accept_rx: mpsc::Receiver<(KcpStream, SocketAddr)>,
    task_watcher: JoinHandle<()>,
    mode:ListenerMode,
    custom_mode_tx:tokio::sync::mpsc::Sender<CustomModeOperate>,
    //conv_map: Arc<Mutex<HashMap<u32, Vec<u8>>>>,
}

pub struct CustomModeNotify{
    custom_mode_tx:tokio::sync::mpsc::Sender<CustomModeOperate>,
}

impl   CustomModeNotify{
    pub fn new(custom_mode_tx:tokio::sync::mpsc::Sender<CustomModeOperate>) -> Self {
        Self {
            custom_mode_tx,
        }
    }

    pub async  fn add(&self, id: u32, data: Vec<u8>) -> Result<(), ()> {
        let (sender, receiver) = tokio::sync::oneshot::channel();
        if self.custom_mode_tx.send(CustomModeOperate::Add(id, data, sender)).await.is_err() {
            return Err(()); // Channel closed
        }
        receiver.await.map_err(|_| ())
    }

    pub async fn remove(&self, id: u32) -> Result<(), ()> {
        let (sender, receiver) = tokio::sync::oneshot::channel();
        if self.custom_mode_tx.send(CustomModeOperate::Remove(id, sender)).await.is_err() {
            return Err(()); // Channel closed
        }
        receiver.await.map_err(|_| ())
    }
}

impl Drop for KcpListener {
    fn drop(&mut self) {
        self.task_watcher.abort();
    }
}

impl KcpListener {
    pub fn custom_mode_notify(&self) -> CustomModeNotify {
        CustomModeNotify::new(self.custom_mode_tx.clone())
    }

    /// Create an `KcpListener` bound to `addr`
    pub async fn bind<A: ToSocketAddrs>(config: KcpConfig, addr: A) -> KcpResult<KcpListener> {
        let udp = UdpSocket::bind(addr).await?;
        KcpListener::from_socket(config, udp).await
    }

    /// Create a `KcpListener` from an existed `UdpSocket`
    pub async fn from_socket(config: KcpConfig, udp: UdpSocket) -> KcpResult<KcpListener> {
        let udp = Arc::new(udp);
        let server_udp = udp.clone();


        let listener_mode = config.listener_mode.clone();
        let fec_data_shards = config.fec_data_shards;
        let fec_parity_shards = config.fec_parity_shards;
        let (accept_tx, accept_rx) = mpsc::channel(1024 /* backlogs */);
        let (custom_mode_tx, mut custom_mode_rx) = tokio::sync::mpsc::channel(1024);    
        let task_watcher = tokio::spawn(async move {
            let (close_tx, mut close_rx) = mpsc::channel(64);

            let mut sessions = KcpSessionManager::new();
            let mut packet_buffer = [0u8; 65536];

            let mut conv_map: HashMap<u32, Vec<u8>> = HashMap::new();
            loop {
                tokio::select! {
                    operate = custom_mode_rx.recv() => {
                        match operate {
                            Some(CustomModeOperate::Add(id, data, sender)) if listener_mode == ListenerMode::Custom => {
                                conv_map.insert(id, data.clone());
                                let _ = sender.send(());
                            }

                            Some(CustomModeOperate::Remove(id, sender)) if listener_mode == ListenerMode::Custom => {
                                conv_map.remove(&id);
                                let _ = sender.send(());
                            }

                            Some(CustomModeOperate::Add(_, _, sender)) | Some(CustomModeOperate::Remove(_, sender)) => {
                                // Not in Custom mode, but still need to respond to avoid receiver panic
                                let _ = sender.send(());
                            }

                            None => {
                                // Channel closed, exit loop
                                break;
                            }
                        }
                    }

                    peer_addr = close_rx.recv() => {
                        let peer_addr = peer_addr.expect("close_tx closed unexpectedly");
                        sessions.close_peer(peer_addr);
                        trace!("session peer_addr: {} removed", peer_addr);
                    }

                    recv_res = udp.recv_from(&mut packet_buffer) => {
                        match recv_res {
                            Err(err) => {
                                error!("udp.recv_from failed, error: {}", err);
                                time::sleep(Duration::from_secs(1)).await;
                            }
                            Ok((n, peer_addr)) => {
                                let packet = &mut packet_buffer[..n];

                                // 临时调试：打印所有数据包的前32字节
                                trace!("received peer: {}, packet_len: {}, first 32 bytes: {:02x?}", 
                                       peer_addr, n, &packet[..n.min(32)]);
                                trace!("received peer: {}, {:?}", peer_addr, ByteStr::new(packet));

                                // Decrypt and verify CRC32 (aligned with kcp-go's listener.packetInput)
                                // kcp-go:
                                //   - CFB 模式: block.Decrypt(data, data) -> data[nonceSize:] -> verify CRC32 -> data[crcSize:]
                                //   - AEAD 模式: block.Open(ciphertext[:0], nonce, ciphertext, nil) -> plaintext (不验证CRC32)
                                let (decrypted_packet, decrypted) = if let Some(ref crypt) = config.crypt {
                                    if crypt.is_aead() {
                                        // AEAD 模式（如 AES-GCM）
                                        let nonce_size = crypt.nonce_size();
                                        let overhead = crypt.overhead();
                                        
                                        if packet.len() < nonce_size + overhead {
                                            error!("AEAD packet too short: {} < {}", packet.len(), nonce_size + overhead);
                                            continue;
                                        }
                                        
                                        // 使用 Open 方法解密（不验证 CRC32，因为 AEAD 自带认证）
                                        let nonce = &packet[..nonce_size];
                                        let ciphertext = &packet[nonce_size..];
                                        
                                        let mut decrypted_buf = vec![0u8; ciphertext.len()];
                                        match crypt.open(&mut decrypted_buf, nonce, ciphertext) {
                                            Ok(plaintext_len) => {
                                                decrypted_buf.truncate(plaintext_len);
                                                // AEAD 模式解密后的数据直接是 [FEC头部][KCP数据] 或 [KCP数据]（没有 CRC32）
                                                (decrypted_buf.clone(), decrypted_buf)
                                            }
                                            Err(e) => {
                                                error!("AEAD Open failed: {}", e);
                                                continue;
                                            }
                                        }
                                    } else {
                                        // CFB 模式（传统加密方式）
                                        // All BlockCrypt implementations (including NoneBlockCrypt) use the same packet format:
                                        // [nonce(16B)][CRC32(4B)][FEC头部][KCP数据] or [nonce(16B)][CRC32(4B)][KCP数据]
                                        // NoneBlockCrypt's decrypt() just copies data, so it's safe to call it
                                        if packet.len() < CRYPT_HEADER_SIZE {
                                            error!("packet too short for encryption header: {} < {}", packet.len(), CRYPT_HEADER_SIZE);
                                            continue;
                                        }
                                        
                                        // Decrypt the packet (for NoneBlockCrypt, this just copies data)
                                        let mut decrypted = packet.to_vec();
                                        crypt.decrypt(&mut decrypted, packet);
                                        
                                        // Skip nonce, now we have [CRC32(4B)][FEC头部][KCP数据] or [CRC32(4B)][KCP数据]
                                        if decrypted.len() < NONCE_SIZE + CRC_SIZE {
                                            error!("decrypted packet too short: {} < {}", decrypted.len(), NONCE_SIZE + CRC_SIZE);
                                            continue;
                                        }
                                        
                                        let data_after_nonce = &decrypted[NONCE_SIZE..];
                                        
                                        // Verify CRC32 (aligned with kcp-go: checksum := crc32.ChecksumIEEE(data[crcSize:]))
                                        if data_after_nonce.len() < CRC_SIZE {
                                            error!("data after nonce too short for CRC32: {} < {}", data_after_nonce.len(), CRC_SIZE);
                                            continue;
                                        }
                                        
                                        // Skip CRC32, now we have [FEC头部][KCP数据] or [KCP数据]
                                        (data_after_nonce[CRC_SIZE..].to_vec(), decrypted)
                                    }
                                } else {
                                    // No encryption, use packet as-is
                                    (packet.to_vec(), packet.to_vec())
                                };

                                // Now check if this is a FEC packet (after decryption)
                                // If FEC is disabled (both shards are 0), skip FEC check
                                let (kcp_packet_offset, is_fec, fec_offset) = if fec_data_shards == 0 && fec_parity_shards == 0 {
                                    // FEC is disabled, packet format is [KCP数据] (no FEC header)
                                    (0, false, 0)
                                } else if decrypted_packet.len() >= FEC_HEADER_SIZE_PLUS_2 {
                                    // Check FEC flag (at offset 4 in decrypted packet)
                                    if decrypted_packet.len() >= 6 {
                                        let mut reader = &decrypted_packet[4..6];
                                        if let Ok(flag) = reader.read_u16::<LittleEndian>() {
                                            if flag == TYPE_DATA || flag == TYPE_PARITY {
                                                // This is a FEC packet, skip FEC header
                                                (FEC_HEADER_SIZE_PLUS_2, true, FEC_HEADER_SIZE_PLUS_2)
                                            } else {
                                                // Not a FEC packet, use as-is
                                                (0, false, 0)
                                            }
                                        } else {
                                            // Failed to read flag, use as-is
                                            (0, false, 0)
                                        }
                                    } else {
                                        // Too short to be FEC, use as-is
                                        (0, false, 0)
                                    }
                                } else {
                                    // Too short to be FEC, use as-is
                                    (0, false, 0)
                                };

                                // Check packet length first
                                if decrypted_packet.len() < kcp_packet_offset + kcp::KCP_OVERHEAD {
                                    error!("packet too short, received {} bytes, but at least {} bytes, kcp_packet_offset={}, packet content: {:02x?}",
                                           decrypted_packet.len(),
                                           kcp_packet_offset + kcp::KCP_OVERHEAD,
                                           kcp_packet_offset,
                                           decrypted_packet);
                                    continue;
                                }

                                // Read conv from the KCP packet position (in decrypted packet)
                                let conv_bytes = &decrypted_packet[kcp_packet_offset..kcp_packet_offset + 4];
                                let mut conv = u32::from_le_bytes([conv_bytes[0], conv_bytes[1], conv_bytes[2], conv_bytes[3]]);

                                if let Some(ref crypt) = config.crypt {
                                    if !crypt.is_aead() {
                                        // CFB 模式：验证 CRC32
                                        // All BlockCrypt implementations (including NoneBlockCrypt) use the same packet format:
                                        // [nonce(16B)][CRC32(4B)][FEC头部][KCP数据] or [nonce(16B)][CRC32(4B)][KCP数据]
                                        // NoneBlockCrypt's decrypt() just copies data, so the decrypted data is the same as the original
                                        let data_after_nonce = &decrypted[NONCE_SIZE..];
                                        if data_after_nonce.len() < CRC_SIZE {
                                            error!("data after nonce too short for CRC32: {} < {}", data_after_nonce.len(), CRC_SIZE);
                                            continue;
                                        }
                                        
                                        let stored_checksum = u32::from_le_bytes([
                                            data_after_nonce[0],
                                            data_after_nonce[1],
                                            data_after_nonce[2],
                                            data_after_nonce[3],
                                        ]);
                                        
                                        // Select CRC32 verification method based on listener mode
                                        let calculated_checksum = match config.listener_mode {
                                            ListenerMode::Normal => {
                                                // Normal mode: standard CRC32 verification (aligned with kcp-go)
                                                crc32fast::hash(&data_after_nonce[CRC_SIZE..])
                                            }
                                            ListenerMode::Custom => {
                                                if conv == 0 {
                                                    trace!("[LISTENER] Custom mode: conv is 0, dropping packet from {}", peer_addr);
                                                    continue;
                                                }
                                                // Custom mode: CRC32 verification with salt per conv_id
                                                match conv_map.get(&conv) {
                                                    Some(data) => {
                                                        let mut data2 = Vec::from(&data_after_nonce[CRC_SIZE..]);
                                                        data2.extend_from_slice(&data);
                                                        crc32fast::hash(&data2[..])
                                                    }
                                                    None => {
                                                        trace!("[LISTENER] Custom mode: conv not found in conv_map, dropping packet from {} conv: {}", peer_addr, conv);
                                                        continue;
                                                    }
                                                }
                                            }
                                        };
                                        
                                        if stored_checksum != calculated_checksum {
                                            trace!("[LISTENER] CRC32 checksum mismatch, stored={}, calculated={}, mode={:?}, dropping packet from {}",
                                                   stored_checksum, calculated_checksum, config.listener_mode, peer_addr);
                                            continue; // Drop packet, aligned with kcp-go behavior
                                        }
                                    }
                                    // AEAD 模式：不验证 CRC32（因为 AEAD 自带认证）
                                }
                                
                                // Read sn for Custom mode check (before conv allocation)
                                let kcp_packet = &decrypted_packet[kcp_packet_offset..];
                                let sn = kcp::get_sn(kcp_packet);
                                
                                // In Custom mode, reject packets with sn=0 and conv=0 (before conv allocation)
                                if config.listener_mode == ListenerMode::Custom && sn == 0 && conv == 0 {
                                    trace!("[LISTENER] Custom mode: rejecting packet with sn=0 and conv=0 from {}", peer_addr);
                                    continue;
                                }
                                
                                if conv == 0 {
                                    // Don't allocate a conv. Keep conv=0 — KcpSocket::new()
                                    // will call kcp.input_conv() which accepts the client's
                                    // real conv on the first kcp.input() call.
                                    // Allocating a random conv breaks things: the listener
                                    // reads seqid=0 from the FEC header as conv (when FEC
                                    // detection fails), but the real KCP conv is at offset 8.
                                    // The allocated conv never matches the real one.
                                    debug!("peer: {} with conv==0 (FEC seqid?), passing conv=0 to session for input_conv acceptance", peer_addr);
                                }

                                let salt = if config.listener_mode == ListenerMode::Custom {
                                    match conv_map.get(&conv) {
                                        Some(data) => {
                                            data.clone()
                                        }
                                        None => {
                                            continue;
                                        }
                                    } 
                                }else {
                                    Vec::new()
                                };

                                let session = match sessions.get_or_create(&config, conv, sn, &udp, peer_addr, &close_tx, salt).await {
                                    Ok((s, created)) => {
                                        if created {
                                            // Created a new session, constructed a new accepted client
                                            let stream = KcpStream::with_session(s.clone());
                                            if  accept_tx.try_send((stream, peer_addr)).is_err() {
                                                debug!("failed to create accepted stream due to channel failure");

                                                // remove it from session
                                                sessions.close_peer(peer_addr);
                                                continue;
                                            }
                                        } else {
                                            let session_conv = s.conv().await;
                                            if session_conv != conv {
                                                // Pass packet to session anyway — let KcpSocket's
                                                // own FEC detection + KCP conv validation handle it.
                                                // Listener-level conv reading can be wrong when FEC
                                                // detection fails (reads FEC seqid as conv).
                                                trace!("received peer: {} with conv: {} not match with session conv: {} (passing through)",
                                                       peer_addr,
                                                       conv,
                                                       session_conv);
                                                // Fall through to session.input_decrypted below
                                            }
                                        }

                                        s
                                    },
                                    Err(err) => {
                                        error!("failed to create session, error: {}, peer: {}, conv: {}", err, peer_addr, conv);
                                        continue;
                                    }
                                };

                                // Send the decrypted and CRC32-verified packet to session
                                // The session's input_decrypted method will handle FEC decoding and KCP input
                                // (aligned with kcp-go: listener.packetInput verifies CRC32, then calls s.kcpInput(decrypted_data))
                                if session.input_decrypted(&decrypted_packet).await.is_err() {
                                    trace!("[SESSION] KCP session is closing while listener tries to input");
                                }
                            }
                        }
                    }
                }
            }
        });

        Ok(KcpListener {
            udp: server_udp,
            accept_rx,
            task_watcher,
            mode: listener_mode,
            custom_mode_tx,
            //conv_map,
        })
    }

    /// Accept a new connected `KcpStream`
    pub async fn accept(&mut self) -> KcpResult<(KcpStream, SocketAddr)> {
        match self.accept_rx.recv().await {
            Some(s) => Ok(s),
            None => Err(KcpError::IoError(io::Error::new(
                ErrorKind::Other,
                "accept channel closed unexpectedly",
            ))),
        }
    }

    pub fn poll_accept(&mut self, cx: &mut Context<'_>) -> Poll<KcpResult<(KcpStream, SocketAddr)>> {
        self.accept_rx.poll_recv(cx).map(|op_res| {
            op_res
                .ok_or_else(|| KcpError::IoError(io::Error::new(ErrorKind::Other, "accept channel closed unexpectedly")))
        })
    }

    /// Get the local address of the underlying socket
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.udp.local_addr()
    }
}

#[cfg(unix)]
impl std::os::unix::io::AsRawFd for KcpListener {
    fn as_raw_fd(&self) -> std::os::unix::prelude::RawFd {
        self.udp.as_raw_fd()
    }
}

#[cfg(windows)]
impl std::os::windows::io::AsRawSocket for KcpListener {
    fn as_raw_socket(&self) -> std::os::windows::prelude::RawSocket {
        self.udp.as_raw_socket()
    }
}

#[cfg(test)]
mod test {
    use futures_util::future;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::KcpListener;
    use crate::{config::KcpConfig, stream::KcpStream};

    #[tokio::test]
    async fn multi_echo() {
        let _ = env_logger::try_init();

        let config = KcpConfig::default();
        let client_config = config.clone(); // 克隆用于客户端连接

        let mut listener = KcpListener::bind(config, "127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();

                tokio::spawn(async move {
                    let mut buffer = [0u8; 8192];
                    while let Ok(n) = stream.read(&mut buffer).await {
                        if n == 0 {
                            break;
                        }

                        let data = &buffer[..n];
                        stream.write_all(data).await.unwrap();
                        stream.flush().await.unwrap();
                    }
                });
            }
        });

        let mut vfut = Vec::new();

        for _ in 0..100 {
            let client_config = client_config.clone();
            vfut.push(async move {
                let mut stream = KcpStream::connect(&client_config, server_addr).await.unwrap();

                for _ in 0..20 {
                    const SEND_BUFFER: &[u8] = b"HELLO WORLD";
                    stream.write_all(SEND_BUFFER).await.unwrap();
                    stream.flush().await.unwrap();

                    let mut buffer = [0u8; 1024];
                    let n = stream.recv(&mut buffer).await.unwrap();
                    assert_eq!(SEND_BUFFER, &buffer[..n]);
                }
            });
        }

        future::join_all(vfut).await;
    }
}
