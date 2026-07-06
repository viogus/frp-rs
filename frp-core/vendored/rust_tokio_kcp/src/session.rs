use std::{
    collections::{hash_map::Entry, HashMap},
    fmt::{self, Debug},
    net::SocketAddr,
    ops::Deref,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};

use byte_string::ByteStr;
use kcp::KcpResult;
use log::{error, trace};
use spin::Mutex as SpinMutex;
use tokio::{
    net::UdpSocket,
    sync::{mpsc, Notify},
    time::{self, Instant},
};

use crate::{skcp::KcpSocket, KcpConfig};

enum InputData {
    Encrypted(Vec<u8>),
    Decrypted(Vec<u8>),
}

pub struct KcpSession {
    socket: SpinMutex<KcpSocket>,
    closed: AtomicBool,
    session_expire: Option<Duration>,
    session_close_notifier: Option<(mpsc::Sender<SocketAddr>, SocketAddr)>,
    input_tx: mpsc::Sender<InputData>,
    notifier: Notify,
}

impl Drop for KcpSession {
    fn drop(&mut self) {
        trace!(
            "[SESSION] KcpSession conv {} is dropping, closed? {}",
            self.socket.lock().conv(),
            self.closed.load(Ordering::Acquire),
        );
    }
}

impl Debug for KcpSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KcpSession")
            .field("socket", self.socket.lock().deref())
            .field("closed", &self.closed.load(Ordering::Relaxed))
            .field("session_expire", &self.session_expire)
            .field("session_close_notifier", &self.session_close_notifier)
            .field("input_tx", &self.input_tx)
            .field("notifier", &self.notifier)
            .finish()
    }
}

impl KcpSession {
    fn new(
        socket: KcpSocket,
        session_expire: Option<Duration>,
        session_close_notifier: Option<(mpsc::Sender<SocketAddr>, SocketAddr)>,
        input_tx: mpsc::Sender<InputData>,
    ) -> KcpSession {
        KcpSession {
            socket: SpinMutex::new(socket),
            closed: AtomicBool::new(false),
            session_expire,
            session_close_notifier,
            input_tx,
            notifier: Notify::new(),
        }
    }

    pub fn new_shared(
        socket: KcpSocket,
        session_expire: Option<Duration>,
        session_close_notifier: Option<(mpsc::Sender<SocketAddr>, SocketAddr)>,
    ) -> Arc<KcpSession> {
        let is_client = session_close_notifier.is_none();

        let (input_tx, mut input_rx) = mpsc::channel::<InputData>(64);

        let udp_socket = socket.udp_socket().clone();

        let session = Arc::new(KcpSession::new(
            socket,
            session_expire,
            session_close_notifier,
            input_tx,
        ));

        let io_task_handle = {
            let session = session.clone();
            tokio::spawn(async move {
                let mut input_buffer = [0u8; 65536];

                loop {
                    tokio::select! {
                        // recv() then input()
                        // Drives the KCP machine forward
                        recv_result = udp_socket.recv(&mut input_buffer), if is_client => {
                            match recv_result {
                                Err(err) => {
                                    error!("[SESSION] UDP recv failed, error: {}", err);
                                    session.closed.store(true, Ordering::Release);
                                    break;
                                }
                                Ok(n) => {
                                    let input_buffer = &input_buffer[..n];
                                    trace!("[SESSION] UDP recv {} bytes, first 16 bytes: {:?}", n, 
                                           if n >= 16 { &input_buffer[..16] } else { input_buffer });

                                    // 参考 kcp-go: readLoop 总是直接调用 packetInput，不做任何检查
                                    // packetInput 会处理解密、CRC32、FEC 和 KCP 输入
                                    let mut socket = session.socket.lock();
                                    match socket.input(input_buffer) {
                                        Ok(true) => {
                                            trace!("[SESSION] UDP input {} bytes and waked sender/receiver", n);
                                        }
                                        Ok(false) => {
                                            trace!("[SESSION] UDP input {} bytes but no waker", n);
                                        }
                                        Err(err) => {
                                            error!("[SESSION] UDP input {} bytes error: {}, input buffer {:?}",
                                                   n, err, ByteStr::new(input_buffer));
                                        }
                                    }
                                }
                            }
                        }

                        // bytes received from listener socket
                        input_opt = input_rx.recv() => {
                            if let Some(input_data) = input_opt {
                                let mut socket = session.socket.lock();
                                let (result, buf_len) = match &input_data {
                                    InputData::Encrypted(buf) => {
                                        (socket.input(buf), buf.len())
                                    }
                                    InputData::Decrypted(buf) => {
                                        (socket.input_decrypted(buf), buf.len())
                                    }
                                };
                                match result {
                                    Ok(waked) => {
                                        trace!("[SESSION] UDP input {} bytes from channel, waked? {} sender/receiver",
                                               buf_len, waked);
                                    }
                                    Err(err) => {
                                        error!("[SESSION] UDP input from channel failed, error: {}, input buffer len: {}",
                                               err, buf_len);
                                    }
                                }
                            }
                        }
                    }
                }
            })
        };

        // Per-session updater
        {
            let session = session.clone();
            tokio::spawn(async move {
                while !session.closed.load(Ordering::Relaxed) {
                    let next = {
                        let mut socket = session.socket.lock();

                        let is_closed = session.closed.load(Ordering::Acquire);
                        if is_closed {
                            // 立即关闭，不等待发送完成（与 kcp-go 对齐）
                            // 尝试 flush 所有数据
                            let _ = socket.flush();
                            trace!("[SESSION] KCP session closing immediately");
                            break;
                        }

                        // If window is full, flush it immediately
                        if socket.need_flush() {
                            let _ = socket.flush();
                        }

                        match socket.update() {
                            Ok(next_next) => Instant::from_std(next_next),
                            Err(err) => {
                                error!("[SESSION] KCP update failed, error: {}", err);
                                Instant::now() + Duration::from_millis(10)
                            }
                        }
                    };

                    tokio::select! {
                        _ = time::sleep_until(next) => {},
                        _ = session.notifier.notified() => {},
                    }
                }

                {
                    // Close the socket.
                    // Wake all pending tasks and let all send/recv return EOF
                    // 在关闭前尝试 flush 所有数据（类似 kcp-go）
                    let mut socket = session.socket.lock();
                    let _ = socket.flush(); // try best to send all queued messages
                    socket.close();
                }

                if let Some((ref notifier, peer_addr)) = session.session_close_notifier {
                    let _ = notifier.send(peer_addr).await;
                }

                session.closed.store(true, Ordering::Release);
                io_task_handle.abort();

                trace!("[SESSION] KCP session closed");
            });
        }

        session
    }

    pub fn kcp_socket(&self) -> &SpinMutex<KcpSocket> {
        &self.socket
    }

    pub fn close(&self) {
        // 尝试 flush 所有数据（类似 kcp-go 的 Close 方法）
        {
            let mut socket = self.socket.lock();
            let _ = socket.flush(); // try best to send all queued messages
        }
        
        self.closed.store(true, Ordering::Release);
        self.notify();
    }

    pub async fn input(&self, buf: &[u8]) -> Result<(), SessionClosedError> {
        self.input_tx.send(InputData::Encrypted(buf.to_owned())).await.map_err(|_| SessionClosedError)
    }

    pub async fn input_decrypted(&self, buf: &[u8]) -> Result<(), SessionClosedError> {
        self.input_tx.send(InputData::Decrypted(buf.to_owned())).await.map_err(|_| SessionClosedError)
    }

    pub async fn conv(&self) -> u32 {
        let socket = self.socket.lock();
        socket.conv()
    }

    pub fn notify(&self) {
        self.notifier.notify_one();
    }
}

pub struct SessionClosedError;

struct KcpSessionUniq(Arc<KcpSession>);

impl Drop for KcpSessionUniq {
    fn drop(&mut self) {
        self.0.close();
    }
}

impl Deref for KcpSessionUniq {
    type Target = KcpSession;

    fn deref(&self) -> &KcpSession {
        &self.0
    }
}

pub struct KcpSessionManager {
    sessions: HashMap<SocketAddr, KcpSessionUniq>,
}

impl KcpSessionManager {
    pub fn new() -> KcpSessionManager {
        KcpSessionManager {
            sessions: HashMap::new(),
        }
    }

    #[inline]
    #[allow(dead_code)]
    pub fn alloc_conv(&mut self) -> u32 {
        let mut conv = rand::random();
        while conv == 0 {
            conv = rand::random()
        }
        conv
    }

    pub fn close_peer(&mut self, peer_addr: SocketAddr) {
        self.sessions.remove(&peer_addr);
    }

    pub async fn get_or_create(
        &mut self,
        config: &KcpConfig,
        conv: u32,
        sn: u32,
        udp: &Arc<UdpSocket>,
        peer_addr: SocketAddr,
        session_close_notifier: &mpsc::Sender<SocketAddr>,
        salt: Vec<u8>,
    ) -> KcpResult<(Arc<KcpSession>, bool)> {
        match self.sessions.entry(peer_addr) {
            Entry::Occupied(mut occ) => {
                let session = occ.get();

                if sn == 0 && session.conv().await != conv {
                    // This is the first packet received from this peer.
                    // Recreate a new session for this specific client.

                    let socket = KcpSocket::new(config, conv, udp.clone(), peer_addr, config.stream, salt.clone())?;
                    let session = KcpSession::new_shared(
                        socket,
                        config.session_expire,
                        Some((session_close_notifier.clone(), peer_addr)),
                    );

                    let old_session = occ.insert(KcpSessionUniq(session.clone()));
                    let old_conv = old_session.conv().await;
                    trace!(
                        "replaced session with conv: {} (old: {}), peer: {}",
                        conv,
                        old_conv,
                        peer_addr
                    );

                    Ok((session, true))
                } else {
                    Ok((session.0.clone(), false))
                }
            }
            Entry::Vacant(vac) => {
                let socket = KcpSocket::new(config, conv, udp.clone(), peer_addr, config.stream, salt.clone())?;
                let session = KcpSession::new_shared(
                    socket,
                    config.session_expire,
                    Some((session_close_notifier.clone(), peer_addr)),
                );
                trace!("created session for conv: {}, peer: {}", conv, peer_addr);
                vac.insert(KcpSessionUniq(session.clone()));
                Ok((session, true))
            }
        }
    }
}
