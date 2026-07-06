# Replace rust_tokio_kcp Vendored Dep — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace ~5,900 lines vendored `rust_tokio_kcp` with ~1,000 lines direct `kcp` crate glue in `frp-core/src/kcp/`.

**Architecture:** Five-file module under `frp-core/src/kcp/`: `config.rs` (KcpConfig structs), `session.rs` (per-conv KCP + `kcp_compat::Fec` + read_tx), `socket.rs` (UDP driver loop with tokio::select!), `stream.rs` (AsyncRead/AsyncWrite via mpsc), `listener.rs` (bind + accept + dial). Keep vendored `kcp-0.6.0`. Reuse `kcp_compat::Fec` — zero new deps.

**Spec:** `docs/superpowers/specs/2026-07-06-replace-rust-tokio-kcp-design.md`

**Key design decision:** The session owns an `mpsc::UnboundedSender<Vec<u8>>` (`read_tx`) to push received KCP data to the stream. The driver calls `session.recv_and_push()` on each tick. This avoids the session needing to know about the stream's polling — it just pushes, stream pulls.

---

### Task 1: Config Structs

**Files:**
- Create: `frp-core/src/kcp/config.rs`

Move `KcpConfig` + `KcpNoDelayConfig` from old `kcp.rs` into standalone file. Remove unused fields (`crypt`, `listener_mode`, `session_expire`, `flush_acks_input`, `allow_recv_empty_packet`). Add `Default` impl matching Go frp v0.69.1 defaults.

- [ ] **Step 1: Write `frp-core/src/kcp/config.rs`**

```rust
//! KCP configuration — matches Go frp v0.69.1 wire parameters.

/// KCP no-delay configuration.
#[derive(Debug, Clone)]
pub struct KcpNoDelayConfig {
    /// Enable nodelay mode.
    pub nodelay: bool,
    /// Internal update interval in milliseconds.
    pub interval: i32,
    /// Fast retransmit threshold (0 = disabled).
    pub resend: i32,
    /// Disable congestion control (nc = "no congestion").
    pub nc: bool,
}

impl Default for KcpNoDelayConfig {
    fn default() -> Self {
        Self { nodelay: false, interval: 40, resend: 0, nc: false }
    }
}

/// KCP transport configuration.
#[derive(Debug, Clone)]
pub struct KcpConfig {
    /// Maximum transmission unit.
    pub mtu: usize,
    /// No-delay / retransmit / congestion parameters.
    pub nodelay: KcpNoDelayConfig,
    /// Send and receive window sizes.
    pub wnd_size: (u16, u16),
    /// Number of FEC data shards (0 = FEC disabled).
    pub data_shards: usize,
    /// Number of FEC parity shards (0 = FEC disabled).
    pub parity_shards: usize,
    /// Stream mode: each KCP output produces a single contiguous datagram.
    pub stream: bool,
    /// Flush after every write.
    pub flush_write: bool,
}

impl Default for KcpConfig {
    fn default() -> Self {
        Self {
            mtu: 1350,
            nodelay: KcpNoDelayConfig::default(),
            wnd_size: (1024, 1024),
            data_shards: 0,
            parity_shards: 0,
            stream: true,
            flush_write: true,
        }
    }
}
```

- [ ] **Step 2: Verify compiles (standalone)**

```bash
rustfmt --check frp-core/src/kcp/config.rs
```

- [ ] **Step 3: Commit**

```bash
git add frp-core/src/kcp/config.rs
git commit -m "feat(kcp): add KcpConfig and KcpNoDelayConfig structs

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 2: KcpSession — per-conv KCP + FEC

**Files:**
- Create: `frp-core/src/kcp/session.rs`

Each session owns a `kcp::Kcp` instance, an optional `Fec` codec, and a `read_tx` to push received data to the stream. Handles FEC header encode/decode (6-byte: `[seqid: u32 LE][flag: u16 LE]`), shard grouping with continuity detection.

- [ ] **Step 1: Write `frp-core/src/kcp/session.rs`**

```rust
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

    pub fn conv(&self) -> u32 { self.conv }
    pub fn peer_addr(&self) -> SocketAddr { self.peer_addr }

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
                let flag = if i < self.config.data_shards { TYPE_DATA } else { TYPE_PARITY };
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

            let group = self.shard_groups.entry(shard_id).or_insert_with(|| ShardGroup {
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
```

- [ ] **Step 2: Verify syntax**

```bash
rustfmt --check frp-core/src/kcp/session.rs
```

- [ ] **Step 3: Commit**

```bash
git add frp-core/src/kcp/session.rs
git commit -m "feat(kcp): add KcpSession with FEC encode/decode

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 3: KcpSocket Driver + KcpStream

**Files:**
- Create: `frp-core/src/kcp/socket.rs`
- Create: `frp-core/src/kcp/stream.rs`

`KcpSocket` owns the `Arc<UdpSocket>` and runs a `tokio::select!` loop: tick (update all sessions + flush output + push recv), write channel (enqueue data), UDP recv (route to session). Session registry keyed by `(conv, peer_addr)`.

`KcpStream` is the public handle: `AsyncRead`/`AsyncWrite` via mpsc channels to driver. Maintains same API surface as old wrapper (`conv()`, `global_read_bytes()`, etc.) plus diagnostic logging.

- [ ] **Step 1: Write `frp-core/src/kcp/socket.rs`**

```rust
//! KCP socket driver — UDP event loop shared across all sessions.

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot};
use tokio::time::{interval, Duration};

use super::config::KcpConfig;
use super::session::KcpSession;

pub(crate) struct WriteRequest {
    pub data: Vec<u8>,
    pub confirm: oneshot::Sender<io::Result<()>>,
}

pub(crate) struct KcpSocketHandle {
    pub write_tx: mpsc::UnboundedSender<(u32, WriteRequest)>,
    pub register_tx: mpsc::UnboundedSender<(u32, SocketAddr, KcpSession)>,
    /// Channel to send newly accepted streams back to KcpListener::accept().
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
}

impl KcpSocket {
    pub fn new(socket: Arc<UdpSocket>, config: KcpConfig) -> (Self, KcpSocketHandle, mpsc::UnboundedReceiver<KcpStream>) {
        let (write_tx, write_rx) = mpsc::unbounded_channel();
        let (register_tx, register_rx) = mpsc::unbounded_channel();
        let (accept_tx, accept_rx) = mpsc::unbounded_channel();
        let this = Self {
            socket, config, sessions: HashMap::new(),
            write_tx: write_tx.clone(), write_rx,
            register_rx, accept_tx: accept_tx.clone(),
        };
        let handle = KcpSocketHandle { write_tx, register_tx, accept_tx };
        (this, handle, accept_rx)
    }

    pub async fn run(mut self) {
        let mut tick = interval(Duration::from_millis(10));
        let mut buf = vec![0u8; 1500];

        loop {
            tokio::select! {
                _ = tick.tick() => {
                    let now = Instant::now();
                    let mut to_remove = Vec::new();
                    for (key, session) in &mut self.sessions {
                        match session.update(now) {
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
                    let result = self.sessions.iter_mut()
                        .find(|((c, _), _)| *c == conv)
                        .map(|(_, s)| s.send(&req.data))
                        .unwrap_or_else(|| Err(io::Error::new(io::ErrorKind::NotConnected, "session not found")));
                    let _ = req.confirm.send(result);
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
                            } else if key.0 != 0 {
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
    /// KCP header: conv is first 4 bytes (little-endian u32).
    fn resolve_key(data: &[u8], src: SocketAddr) -> (u32, SocketAddr) {
        if data.len() >= 4 {
            // Check if this is a FEC packet by looking at bytes [4..6] for flag
            if data.len() >= 10 {
                let flag = u16::from_le_bytes([data[4], data[5]]);
                if flag == 0xf1 || flag == 0xf2 {
                    // FEC packet: conv is at offset 6
                    let conv = u32::from_le_bytes([data[6], data[7], data[8], data[9]]);
                    if conv != 0 {
                        return (conv, src);
                    }
                }
            }
            // Plain KCP: conv at offset 0
            let conv = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
            return (conv, src);
        }
        (0, src)
    }
}
```

- [ ] **Step 2: Write `frp-core/src/kcp/stream.rs`**

```rust
//! KCP stream — AsyncRead + AsyncWrite over a KCP session.

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{mpsc, oneshot};

use super::socket::WriteRequest;

static KCP_READ_BYTES: AtomicU64 = AtomicU64::new(0);
static KCP_READ_CALLS: AtomicU64 = AtomicU64::new(0);
static KCP_WRITE_BYTES: AtomicU64 = AtomicU64::new(0);
static KCP_WRITE_CALLS: AtomicU64 = AtomicU64::new(0);

pub struct KcpStream {
    conv: u32,
    pub peer_addr: SocketAddr,
    write_tx: mpsc::UnboundedSender<(u32, WriteRequest)>,
    read_rx: mpsc::UnboundedReceiver<Vec<u8>>,
    read_buffer: Vec<u8>,
    read_pos: usize,
    read_count: u64,
    write_count: u64,
    shutdown: bool,
}

impl KcpStream {
    pub(crate) fn new(
        conv: u32,
        peer_addr: SocketAddr,
        write_tx: mpsc::UnboundedSender<(u32, WriteRequest)>,
        read_rx: mpsc::UnboundedReceiver<Vec<u8>>,
    ) -> Self {
        Self {
            conv, peer_addr, write_tx, read_rx,
            read_buffer: Vec::new(), read_pos: 0,
            read_count: 0, write_count: 0, shutdown: false,
        }
    }

    pub fn conv(&self) -> u32 { self.conv }
    pub fn global_read_bytes() -> u64 { KCP_READ_BYTES.load(Ordering::Relaxed) }
    pub fn global_write_bytes() -> u64 { KCP_WRITE_BYTES.load(Ordering::Relaxed) }
}

impl AsyncRead for KcpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // Drain buffered data first
        if self.read_pos < self.read_buffer.len() {
            let remaining = &self.read_buffer[self.read_pos..];
            let n = remaining.len().min(buf.remaining());
            buf.put_slice(&remaining[..n]);
            self.read_pos += n;
            self.read_count += n as u64;
            KCP_READ_BYTES.fetch_add(n as u64, Ordering::Relaxed);
            KCP_READ_CALLS.fetch_add(1, Ordering::Relaxed);
            tracing::debug!(
                conv = self.conv, n = n, total = self.read_count,
                "KCP read: {} bytes (total={})", n, self.read_count,
            );
            return Poll::Ready(Ok(()));
        }

        match self.read_rx.poll_recv(cx) {
            Poll::Ready(Some(data)) => {
                let n = data.len().min(buf.remaining());
                buf.put_slice(&data[..n]);
                if n < data.len() {
                    self.read_buffer = data;
                    self.read_pos = n;
                }
                self.read_count += n as u64;
                KCP_READ_BYTES.fetch_add(n as u64, Ordering::Relaxed);
                KCP_READ_CALLS.fetch_add(1, Ordering::Relaxed);
                tracing::debug!(
                    conv = self.conv, n = n, total = self.read_count,
                    first_hex = if n > 0 { hex::encode(&data[..n.min(16)]) } else { String::new() },
                    "KCP read: {} bytes (total={})", n, self.read_count,
                );
                Poll::Ready(Ok(()))
            }
            Poll::Ready(None) => Poll::Ready(Ok(())), // EOF
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for KcpStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.shutdown {
            return Poll::Ready(Err(io::Error::new(io::ErrorKind::NotConnected, "KCP stream shut down")));
        }

        tracing::trace!("KCP WRITE: {} bytes first_hex={}", buf.len(), hex::encode(&buf[..buf.len().min(32)]));

        let (confirm_tx, confirm_rx) = oneshot::channel();
        let req = WriteRequest { data: buf.to_vec(), confirm: confirm_tx };

        if self.write_tx.send((self.conv, req)).is_err() {
            return Poll::Ready(Err(io::Error::new(io::ErrorKind::NotConnected, "KCP driver closed")));
        }

        // Fire-and-forget: don't block on confirm — KCP's flow control via send window
        // handles backpressure. The oneshot confirm is for error reporting only.
        // Drop the receiver — we don't wait.
        drop(confirm_rx);

        let n = buf.len();
        self.write_count += n as u64;
        KCP_WRITE_BYTES.fetch_add(n as u64, Ordering::Relaxed);
        KCP_WRITE_CALLS.fetch_add(1, Ordering::Relaxed);
        if self.write_count <= 80 || self.write_count % 1024 == 0 {
            tracing::debug!(
                conv = self.conv, n = n, total = self.write_count,
                global_total = KCP_WRITE_BYTES.load(Ordering::Relaxed),
                first_hex = %hex::encode(&buf[..n.min(32)]),
                "KCP write: {} bytes (stream total={}, global total={})",
                n, self.write_count, KCP_WRITE_BYTES.load(Ordering::Relaxed),
            );
        }
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.shutdown = true;
        Poll::Ready(Ok(()))
    }
}
```

- [ ] **Step 3: Verify syntax**

```bash
rustfmt --check frp-core/src/kcp/socket.rs frp-core/src/kcp/stream.rs
```

- [ ] **Step 4: Commit**

```bash
git add frp-core/src/kcp/socket.rs frp-core/src/kcp/stream.rs
git commit -m "feat(kcp): add KcpSocket driver and KcpStream (AsyncRead/AsyncWrite)

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 4: KcpListener + dial_kcp

**Files:**
- Create: `frp-core/src/kcp/listener.rs`

Binds UDP socket, creates KcpSocket driver, spawns it. `accept()` returns `(KcpStream, SocketAddr)` for incoming connections. `dial_kcp()` creates outbound connection.

The accept mechanism: driver detects new peers → creates session + stream → sends via `accept_tx` channel back to `accept()`.

- [ ] **Step 1: Write `frp-core/src/kcp/listener.rs`**

```rust
//! KCP listener — bind UDP socket, accept incoming KCP connections, dial outbound.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use tokio::net::UdpSocket;
use tokio::sync::mpsc;

use super::config::KcpConfig;
use super::session::KcpSession;
use super::socket::{KcpSocket, KcpSocketHandle};
use super::stream::KcpStream;

pub struct KcpListener {
    local_addr: SocketAddr,
    handle: KcpSocketHandle,
    accept_rx: mpsc::UnboundedReceiver<KcpStream>,
}

impl KcpListener {
    /// Bind a KCP listener on the given address.
    pub async fn bind(addr: &str, config: KcpConfig) -> io::Result<Self> {
        let socket = UdpSocket::bind(addr).await?;
        let local_addr = socket.local_addr()?;
        let socket = Arc::new(socket);

        let (kcp_socket, handle, accept_rx) = KcpSocket::new(socket, config);

        tokio::spawn(async move { kcp_socket.run().await });

        Ok(Self { local_addr, handle, accept_rx })
    }

    /// Accept the next incoming KCP connection.
    /// Returns KcpStream with peer_addr already set (matching old API).
    pub async fn accept(&mut self) -> io::Result<KcpStream> {
        self.accept_rx
            .recv()
            .await
            .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "KCP listener closed"))
    }

    /// Local address of the underlying UDP socket.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local_addr)
    }
}

/// Create an outbound KCP connection (dial).
pub async fn dial_kcp(addr: &str, config: KcpConfig) -> io::Result<KcpStream> {
    let remote: SocketAddr = addr.parse().map_err(io::Error::other)?;
    let conv: u32 = rand::random();

    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    let socket = Arc::new(socket);

    let (kcp_socket, handle, _accept_rx) = KcpSocket::new(socket, config.clone());
    let (read_tx, read_rx) = mpsc::unbounded_channel();
    let session = KcpSession::new(conv, remote, config.clone(), read_tx);

    handle.register_tx.send((conv, remote, session))
        .map_err(|_| io::Error::new(io::ErrorKind::Other, "driver closed"))?;

    tokio::spawn(async move { kcp_socket.run().await });

    Ok(KcpStream::new(conv, remote, handle.write_tx, read_rx))
}
```

- [ ] **Step 2: Verify syntax**

```bash
rustfmt --check frp-core/src/kcp/listener.rs
```

- [ ] **Step 3: Commit**

```bash
git add frp-core/src/kcp/listener.rs
git commit -m "feat(kcp): add KcpListener and dial_kcp

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 5: mod.rs — Public API

**Files:**
- Create: `frp-core/src/kcp/mod.rs`

Re-exports everything. `default_kcp_config()` returns Go frp v0.69.1 defaults.

- [ ] **Step 1: Write `frp-core/src/kcp/mod.rs`**

```rust
//! KCP transport — reliable stream over UDP.
//!
//! Direct wrapper around the `kcp` crate (vendored 0.6.0 with Go compat patches)
//! and `kcp_compat::Fec` for forward error correction (GF(2^8) Vandermonde).

mod config;
mod listener;
mod session;
mod socket;
mod stream;

pub use config::{KcpConfig, KcpNoDelayConfig};
pub use listener::{dial_kcp, KcpListener};
pub use stream::KcpStream;

/// Build a KcpConfig matching Go frp v0.69.1 defaults.
pub fn default_kcp_config() -> KcpConfig {
    KcpConfig {
        nodelay: KcpNoDelayConfig {
            nodelay: true,
            interval: 20,
            resend: 2,
            nc: true,
        },
        wnd_size: (1024, 1024),
        mtu: 1350,
        data_shards: 10,
        parity_shards: 3,
        stream: true,
        flush_write: true,
    }
}
```

- [ ] **Step 2: Commit**

```bash
git add frp-core/src/kcp/mod.rs
git commit -m "feat(kcp): add kcp module public API with default_kcp_config

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 6: Wire Up — lib.rs, Cargo.toml, Delete Old Code

**Files:**
- Modify: `frp-core/src/lib.rs` (line 15-18)
- Modify: `frp-core/Cargo.toml` (line 36-37, feature definition)
- Modify: workspace `Cargo.toml` (line 48-49, 72-74)
- Delete: `frp-core/src/kcp.rs`
- Delete: `frp-core/vendored/rust_tokio_kcp/` (entire directory)

- [ ] **Step 1: Update `frp-core/src/lib.rs`**

Change:
```rust
#[cfg(feature = "kcp")]
pub mod kcp;
#[cfg(feature = "kcp")]
pub mod kcp_compat;
```

The `pub mod kcp;` now refers to `frp-core/src/kcp/mod.rs` (directory module) instead of `frp-core/src/kcp.rs` (file module). This works automatically once we delete `kcp.rs`.

No edit needed — the module declaration stays the same. Just delete `kcp.rs` and create `kcp/mod.rs`.

Actually, check: if both `kcp.rs` and `kcp/` exist, Rust prefers `kcp.rs`. So order matters: delete `kcp.rs` first.

- [ ] **Step 2: Delete old `kcp.rs`**

```bash
rm frp-core/src/kcp.rs
```

- [ ] **Step 3: Remove `rust_tokio_kcp` from `frp-core/Cargo.toml`**

Delete line 37:
```toml
rust_tokio_kcp = { workspace = true, optional = true }
```

Update `[features]` kcp line (line 54):
```toml
kcp = ["dep:kcp"]  # was: kcp = ["dep:kcp", "dep:rust_tokio_kcp"]
```

- [ ] **Step 4: Remove `rust_tokio_kcp` from workspace `Cargo.toml`**

Delete lines 48-49 (workspace dependency):
```toml
kcp = "0.6"
rust_tokio_kcp = { version = "0.2.1", default-features = false }
```
Keep only:
```toml
kcp = "0.6"
```

Delete line 74 (patch):
```toml
rust_tokio_kcp = { path = "frp-core/vendored/rust_tokio_kcp" }
```

Delete the vendored directory:
```bash
rm -rf frp-core/vendored/rust_tokio_kcp/
```

- [ ] **Step 5: Attempt build**

```bash
cargo build -p frp-core --no-default-features --features kcp 2>&1 | head -60
```

Expected: compilation errors (missing imports, type mismatches). These will be fixed in the next task.

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "chore(kcp): remove rust_tokio_kcp vendored dep, wire up new kcp/ module

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 7: Fix Compilation — transport.rs and service.rs Integration

**Files:**
- Modify: `frp-core/src/transport.rs` (line 1630 — `dial_kcp` call now takes `&str` not `&String`, check if signature matches)
- Modify: `frp-server/src/service.rs` (line 510 — `KcpListener::bind()` signature: `(addr: &str, config: KcpConfig)` matches)
- Maybe: `frp-core/src/kcp/mod.rs` (add re-exports if needed)

The new `KcpStream`, `KcpListener`, `dial_kcp()`, `default_kcp_config()` keep the **exact same public API** as the old ones. Verify and fix any mismatches.

- [ ] **Step 1: Try full workspace build**

```bash
cargo build --workspace 2>&1 | head -80
```

- [ ] **Step 2: Fix any type errors**

Common expected issues:
- `KcpStream::conv()` return type must be `u32` (matches old)
- `KcpListener::accept()` return type must be `io::Result<(KcpStream, SocketAddr)>` or `io::Result<KcpStream>` — check old signature at `frp-core/src/kcp.rs:145`: returns `io::Result<KcpStream>` (not tuple). The server at `service.rs:518` expects `(stream, _addr)`. Update if needed.
- `dial_kcp()` takes `&str` — transport.rs line 1630 passes `&addr` where `addr` is `format!("{}:{}", ...)`. That's `String` which coerces to `&str` via `as_str()`. Verify.

Check the old accept signature carefully:
```rust
// Old kcp.rs:145
pub async fn accept(&mut self) -> io::Result<KcpStream> {
    let (inner, peer_addr) = self.inner.accept().await...;
    Ok(KcpStream { inner, peer_addr, conv: 0, read_count: 0, write_count: 0 })
}
```
Returns `KcpStream` (not tuple). The server at service.rs:518 does:
```rust
let stream = listener.accept().await?;
let addr = stream.peer_addr;
```
So the new `KcpListener::accept()` should also return `io::Result<KcpStream>`, not a tuple. Fix the listener accordingly.

- [ ] **Step 3: Fix KcpListener::accept() return type**

In `frp-core/src/kcp/listener.rs`, change accept to return `KcpStream`:
```rust
pub async fn accept(&mut self) -> io::Result<KcpStream> {
    self.accept_rx
        .recv()
        .await
        .map(|(stream, _addr)| stream)
        .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "KCP listener closed"))
}
```

- [ ] **Step 4: Iterate until clean build**

```bash
cargo build --workspace 2>&1
```

Expected: builds clean.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "fix(kcp): wire up new kcp module — fix accept signature, transport integration

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 8: Run Tests

**Files:** None (verification only)

- [ ] **Step 1: Run unit tests**

```bash
cargo test -p frp-core --lib -- kcp 2>&1
```

Expected: `kcp_compat` tests pass (8 tests). If new kcp module has inline tests, those pass too.

- [ ] **Step 2: Run full test suite**

```bash
cargo test --workspace 2>&1
```

Expected: all tests pass. Pay attention to any test that uses KCP transport.

- [ ] **Step 3: Fix any test failures**

Common issues: old tests may reference `rust_tokio_kcp` types directly. Update to use new `frp_core::kcp::KcpConfig` etc.

- [ ] **Step 4: Commit** (if fixes needed)

```bash
git add -A
git commit -m "test(kcp): fix tests for new kcp module

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 8a: Unit Tests for New KCP Module

**Files:**
- Modify: `frp-core/src/kcp/session.rs` (add `#[cfg(test)] mod tests`)

- [ ] **Step 1: Add tests to `frp-core/src/kcp/session.rs`** (append at end of file)

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use super::super::config::KcpConfig;
    use tokio::sync::mpsc;

    #[test]
    fn test_session_create_no_fec() {
        let config = KcpConfig::default();
        let (read_tx, _read_rx) = mpsc::unbounded_channel();
        let session = KcpSession::new(
            12345, "127.0.0.1:9000".parse().unwrap(), config, read_tx,
        );
        assert_eq!(session.conv(), 12345);
    }

    #[test]
    fn test_session_send_recv_roundtrip() {
        let config = KcpConfig::default();
        let (read_tx, mut read_rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let mut s1 = KcpSession::new(
            1, "127.0.0.1:9001".parse().unwrap(), config.clone(), read_tx,
        );
        let (read_tx2, mut read_rx2) = mpsc::unbounded_channel();
        let mut s2 = KcpSession::new(
            1, "127.0.0.1:9000".parse().unwrap(), config, read_tx2,
        );

        s1.send(b"hello kcp").unwrap();
        let packets = s1.update(std::time::Instant::now()).unwrap();
        assert!(!packets.is_empty(), "KCP should produce output");

        for pkt in &packets {
            s2.input(pkt).unwrap();
        }
        s2.update(std::time::Instant::now()).unwrap();
        s2.recv_and_push().unwrap();

        let received = read_rx2.try_recv().unwrap();
        assert_eq!(received, b"hello kcp");
    }
}
```

- [ ] **Step 2: Run tests**

```bash
cargo test -p frp-core --lib kcp::session::tests 2>&1
```

Expected: 2 tests pass.

- [ ] **Step 3: Commit**

```bash
git add frp-core/src/kcp/session.rs
git commit -m "test(kcp): add KcpSession unit tests

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 8b: Integration Test

**Files:**
- Create: `frp-core/tests/kcp.rs`

- [ ] **Step 1: Write `frp-core/tests/kcp.rs`**

```rust
//! Integration test: KCP dial → send → recv round-trip.

use frp_core::kcp::{dial_kcp, default_kcp_config, KcpListener};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test]
async fn test_kcp_dial_send_recv() {
    let config = default_kcp_config();
    let mut listener = KcpListener::bind("127.0.0.1:0", config.clone())
        .await
        .unwrap();
    let addr = format!("127.0.0.1:{}", listener.local_addr().unwrap().port());

    let dial_handle = tokio::spawn(async move {
        let mut stream = dial_kcp(&addr, config).await.unwrap();
        stream.write_all(b"hello from dialer").await.unwrap();
        stream.shutdown().await.unwrap();
    });

    let mut stream = listener.accept().await.unwrap();
    let mut buf = vec![0u8; 1024];
    let n = stream.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"hello from dialer");

    dial_handle.await.unwrap();
}
```

- [ ] **Step 2: Run integration test**

```bash
cargo test -p frp-core --test kcp 2>&1
```

Expected: test passes (dial → send → accept → recv).

- [ ] **Step 3: Commit**

```bash
git add frp-core/tests/kcp.rs
git commit -m "test(kcp): add integration test for dial/accept round-trip

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 9: Run KCP Compat Tests

**Files:** None (verification only)

- [ ] **Step 1: Download Go frp if needed**

```bash
bash scripts/download-go-frp.sh
```

- [ ] **Step 2: Run KCP-specific compat tests**

```bash
bash scripts/compat-test.sh --verbose 2>&1 | grep -E "(kcp|KCP|PASS|FAIL|test_)"
```

Expected: KCP, KCP+TLS, KCP+TLS+tcpMux, KCP+TLS+tcpMux+CipherStream all pass.

- [ ] **Step 3: If failures, debug and fix**

Check wire format: is FEC header at correct offset? Is KCP conv being read from correct bytes? Is the Go frp sending FEC or plain KCP? Add hex dump logging if needed.

The key compat concern: Go frp's KCP listener expects raw KCP packets (FEC disabled by default). Our new `dial_kcp()` sends KCP output directly (no FEC header when `data_shards=0`). This should match Go frp's expected format.

- [ ] **Step 4: Commit** (if fixes needed)

```bash
git add -A
git commit -m "fix(kcp): Go frp KCP compat fixes

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 10: Clean Up Dead Dependencies

**Files:**
- Modify: workspace `Cargo.toml`
- Modify: `frp-core/Cargo.toml`

Verify and remove deps that were only pulled in by `rust_tokio_kcp`:
- `reed-solomon-erasure` — vendored dep only, not in workspace/frp-core Cargo.toml. No action needed (dies with vendored dir).
- `byteorder` — vendored dep only. No action needed.
- `crc32fast` — check if used elsewhere.
- `spin` — check if used elsewhere.

- [ ] **Step 1: Check for remaining uses of crc32fast and spin**

```bash
grep -r "crc32fast" --include="*.toml" . && echo "---" && grep -r "spin" --include="*.toml" .
```

If neither appears in any non-vendored Cargo.toml, no action needed.

- [ ] **Step 2: Run `cargo update` to clean lock file**

```bash
cargo update -p rust_tokio_kcp 2>&1 || true
# `cargo update` cleans up stale entries naturally
```

- [ ] **Step 3: Verify binary size**

```bash
cargo build --release -p frps -p frpc 2>&1
ls -lh target/release/frps target/release/frpc
```

Compare with baseline (from CLAUDE.md: frps ~4.8MB, frpc ~3.7MB). Expected: frps -50KB to -100KB, frpc similar reduction.

- [ ] **Step 4: Commit**

```bash
git add -A
git commit -m "chore(kcp): remove dead dependencies, verify binary size

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 11: Final Verification

- [ ] **Step 1: Full CI check**

```bash
cargo build --workspace && cargo test --workspace && cargo clippy --workspace 2>&1
```

Expected: all green. No new clippy warnings.

- [ ] **Step 2: Run full compat test suite**

```bash
bash scripts/compat-test.sh --verbose 2>&1
```

Expected: all 40+ tests pass, including KCP variants.

- [ ] **Step 3: Lint**

```bash
cargo clippy --workspace 2>&1
```

Expected: zero warnings.

- [ ] **Step 4: Final commit**

```bash
git add -A
git commit -m "chore(kcp): final verification — all tests pass, clippy clean

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```
