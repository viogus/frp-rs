#![cfg(feature = "tcp-mux")]

use std::{
    io,
    pin::Pin,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    task::{Context, Poll},
    time::Duration,
};

use frp_core::mux::{
    client_mux, server_mux, IncomingStreams, TcpMuxConfig, YamuxSession, YamuxStream,
};
use futures_util::task::AtomicWaker;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

fn mux_config(keepalive_interval: Duration) -> TcpMuxConfig {
    TcpMuxConfig {
        keepalive_interval,
        ..TcpMuxConfig::default()
    }
}

async fn connected_mux_pair(
    client_config: TcpMuxConfig,
    server_config: TcpMuxConfig,
) -> (YamuxStream, IncomingStreams, YamuxStream, YamuxSession) {
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    connected_mux_pair_over(client_io, server_io, client_config, server_config).await
}

async fn connected_mux_pair_over<C, S>(
    client_io: C,
    server_io: S,
    client_config: TcpMuxConfig,
    server_config: TcpMuxConfig,
) -> (YamuxStream, IncomingStreams, YamuxStream, YamuxSession)
where
    C: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let client = tokio::spawn(async move {
        let (mut control, session) = client_mux(client_io, &client_config)
            .await
            .expect("client mux should initialize");
        control
            .write_all(b"c")
            .await
            .expect("client should open the control stream");
        control
            .flush()
            .await
            .expect("client should flush the control stream");
        (control, session)
    });

    let (mut server_control, incoming) = tokio::time::timeout(
        Duration::from_secs(2),
        server_mux(
            server_io,
            &server_config,
            tokio::time::Instant::now() + Duration::from_secs(10),
        ),
    )
    .await
    .expect("server mux should receive the control stream")
    .expect("server mux should initialize");
    let mut byte = [0_u8; 1];
    server_control
        .read_exact(&mut byte)
        .await
        .expect("server should read the control stream");
    assert_eq!(byte, *b"c");

    let (client_control, session) = client.await.expect("client task should not panic");
    (server_control, incoming, client_control, session)
}

async fn advance_keepalive_ticks(interval: Duration, ticks: usize) {
    for _ in 0..ticks {
        tokio::time::advance(interval).await;
        tokio::task::yield_now().await;
    }
}

#[derive(Clone)]
struct FailureHandle(Arc<FailureState>);

struct FailureState {
    failed: AtomicBool,
    read_waker: AtomicWaker,
}

impl FailureHandle {
    fn fail_reads(&self) {
        self.0.failed.store(true, Ordering::Release);
        self.0.read_waker.wake();
    }
}

struct FailingIo<T> {
    inner: T,
    state: Arc<FailureState>,
}

impl<T> FailingIo<T> {
    fn new(inner: T) -> (Self, FailureHandle) {
        let state = Arc::new(FailureState {
            failed: AtomicBool::new(false),
            read_waker: AtomicWaker::new(),
        });
        (
            Self {
                inner,
                state: state.clone(),
            },
            FailureHandle(state),
        )
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for FailingIo<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.state.failed.load(Ordering::Acquire) {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::ConnectionReset,
                "injected transport failure",
            )));
        }

        this.state.read_waker.register(cx.waker());
        if this.state.failed.load(Ordering::Acquire) {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::ConnectionReset,
                "injected transport failure",
            )));
        }
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for FailingIo<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

#[tokio::test(start_paused = true)]
async fn client_can_open_stream_after_idle_keepalive_tick() {
    let interval = Duration::from_secs(1);
    let client_config = mux_config(interval);
    let server_config = mux_config(Duration::from_secs(5));

    let (_server_control, _incoming, _client_control, session) =
        connected_mux_pair(client_config, server_config).await;

    // Idle ticks must not kill a healthy client below the liveness bound
    // (a 1s interval yields a 30s wall-clock bound — MIN_IDLE_DEAD_TIME): a
    // buggy per-Pending-poll counter would close it within the first tick.
    // Paused time suppresses yamux's real-time PING/PONG, so no transport
    // activity resets the counter here.
    advance_keepalive_ticks(interval, 2).await;

    let stream = tokio::time::timeout(Duration::from_secs(1), session.open_stream())
        .await
        .expect("open_stream must not hang after an idle keepalive tick");
    assert!(
        stream.is_some(),
        "the healthy yamux session should stay open"
    );
}

#[tokio::test(start_paused = true)]
async fn server_keeps_healthy_connection_open_without_new_inbound_streams() {
    let interval = Duration::from_secs(1);
    let client_config = mux_config(Duration::from_secs(5));
    let server_config = mux_config(interval);

    let (_server_control, mut incoming, _client_control, session) =
        connected_mux_pair(client_config, server_config).await;

    // Idle ticks below the liveness bound (30s wall-clock for a 1s interval)
    // must not kill the server while the peer is healthy. Paused time
    // suppresses yamux's real-time PING/PONG, so no transport activity
    // resets the counter here.
    advance_keepalive_ticks(interval, 2).await;

    let mut client_stream = tokio::time::timeout(Duration::from_secs(1), session.open_stream())
        .await
        .expect("open_stream should complete")
        .expect("the healthy yamux session should stay open");
    client_stream
        .write_all(b"x")
        .await
        .expect("client should write to the new stream");
    client_stream
        .flush()
        .await
        .expect("client should flush the new stream");

    let mut server_stream = tokio::time::timeout(Duration::from_secs(1), incoming.recv())
        .await
        .expect("server should accept a stream after a healthy idle period")
        .expect("server acceptor must remain open while the peer is healthy");
    let mut byte = [0_u8; 1];
    server_stream
        .read_exact(&mut byte)
        .await
        .expect("server should read from the accepted stream");
    assert_eq!(byte, *b"x");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stream_opened_while_driver_busy_reaches_peer_promptly() {
    // The client driver task and this test run on different workers, so a
    // Notify wakeup fired while the driver is mid-iteration (processing
    // inbound I/O) would be lost, leaving the new stream's SYN/window
    // frames unflushed until the next keepalive tick (60s here, far beyond
    // the test window). The watch-based wakeup is stateful and must never
    // lose the signal: the stream must reach the server promptly, with no
    // keepalive-tick dependence.
    let interval = Duration::from_secs(60);
    let (_server_control, mut incoming, client_control, session) =
        connected_mux_pair(mux_config(interval), mux_config(interval)).await;

    // Keep the client driver busy: the server floods the control stream
    // while this task drains it client-side, so the driver spends the test
    // window routing inbound I/O rather than parked in select.
    let server_flood = tokio::spawn(async move {
        let mut server_control = _server_control;
        let payload = vec![0xabu8; 64 * 1024];
        for _ in 0..16 {
            server_control
                .write_all(&payload)
                .await
                .expect("flood write");
        }
    });
    let drain = tokio::spawn(async move {
        let mut sink = [0u8; 4096];
        let mut control = client_control;
        loop {
            if control.read(&mut sink).await.expect("drain read") == 0 {
                break;
            }
        }
    });

    for i in 0..8u8 {
        let mut stream = session
            .open_stream()
            .await
            .expect("open_stream must succeed while the driver is busy");
        stream.write_all(&[i]).await.expect("write on new stream");
        stream.flush().await.expect("flush new stream");

        let mut server_stream = tokio::time::timeout(Duration::from_secs(5), incoming.recv())
            .await
            .expect("accepted stream must arrive promptly (no keepalive-tick dependence)")
            .expect("server session must remain open");
        let mut byte = [0u8; 1];
        server_stream
            .read_exact(&mut byte)
            .await
            .expect("server should read from the accepted stream");
        assert_eq!(byte[0], i);
    }

    drain.abort();
    server_flood.abort();
}

#[tokio::test]
async fn zero_keepalive_interval_is_safe_for_both_roles() {
    let zero = mux_config(Duration::ZERO);
    let (_server_control, mut incoming, _client_control, session) =
        connected_mux_pair(zero.clone(), zero).await;

    let mut client_stream = tokio::time::timeout(Duration::from_secs(1), session.open_stream())
        .await
        .expect("zero keepalive must not spin or stall the client driver")
        .expect("zero keepalive must be normalized instead of closing the session");
    client_stream.write_all(b"z").await.unwrap();
    client_stream.flush().await.unwrap();

    let mut server_stream = tokio::time::timeout(Duration::from_secs(1), incoming.recv())
        .await
        .expect("zero keepalive must not spin or stall the server driver")
        .expect("server session must remain open after normalization");
    let mut byte = [0_u8; 1];
    server_stream.read_exact(&mut byte).await.unwrap();
    assert_eq!(byte, *b"z");
}

#[tokio::test]
async fn server_acceptor_exits_on_real_peer_eof() {
    let (server_control, mut incoming, client_control, session) =
        connected_mux_pair(TcpMuxConfig::default(), TcpMuxConfig::default()).await;

    drop(session);
    drop(client_control);
    drop(server_control);

    let next = tokio::time::timeout(Duration::from_secs(1), incoming.recv())
        .await
        .expect("server acceptor must observe peer EOF promptly");
    assert!(next.is_none(), "EOF must close the incoming stream channel");
}

#[tokio::test]
async fn server_acceptor_exits_on_transport_error() {
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let (server_io, failure) = FailingIo::new(server_io);
    let (_server_control, mut incoming, _client_control, _session) = connected_mux_pair_over(
        client_io,
        server_io,
        TcpMuxConfig::default(),
        TcpMuxConfig::default(),
    )
    .await;

    failure.fail_reads();

    let stream = tokio::time::timeout(Duration::from_secs(1), incoming.recv())
        .await
        .expect("server incoming channel must close after a transport error");
    assert!(
        stream.is_none(),
        "transport error must terminate the acceptor"
    );
}

#[tokio::test(start_paused = true)]
async fn dead_peer_session_closes_after_bounded_idle_keepalive_ticks() {
    let interval = Duration::from_secs(1);
    let config = mux_config(interval);
    let (_server_control, mut incoming, _client_control, session) =
        connected_mux_pair(config.clone(), config).await;

    // Paused time suppresses yamux's real-time PING/PONG, so neither driver
    // observes transport I/O. The bounded liveness counter must close both
    // sides after the wall-clock dead bound (30s floor for a 1s interval —
    // see MIN_IDLE_DEAD_TIME) rather than retaining the session
    // indefinitely. Advance 35 ticks for margin: the first server tick can
    // consume a straggling setup-phase pong (activity reset), and the final
    // advance's timer may not fire before the checks below.
    advance_keepalive_ticks(interval, 35).await;

    let server_next = tokio::time::timeout(Duration::from_secs(1), incoming.recv())
        .await
        .expect("server incoming channel must close after the liveness bound");
    assert!(
        server_next.is_none(),
        "server acceptor must close a peer with zero transport I/O"
    );

    let client_stream = tokio::time::timeout(Duration::from_secs(1), session.open_stream())
        .await
        .expect("open_stream must complete after the client liveness bound");
    assert!(
        client_stream.is_none(),
        "client session must close a peer with zero transport I/O"
    );
}

#[tokio::test]
async fn server_mux_first_stream_wait_is_bounded_by_accept_deadline() {
    // Slowloris guard: a peer that establishes the transport but never
    // sends a yamux frame must not park the server_mux caller forever.
    // The idle-kill driver only spawns AFTER the first stream arrives,
    // so the first-stream wait is bounded solely by the caller's accept
    // deadline (Go frp connReadTimeout=10s). A regression here would
    // hang the outer timeout below.
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    // client_io is kept alive (connected but silent) for the whole wait:
    // dropping it would EOF the read side and error out early instead of
    // exercising the deadline.
    let deadline = tokio::time::Instant::now() + Duration::from_millis(300);
    let started = tokio::time::Instant::now();
    let result = tokio::time::timeout(
        Duration::from_secs(5),
        server_mux(server_io, &TcpMuxConfig::default(), deadline),
    )
    .await;

    let err = match result {
        Ok(Ok((_control, _incoming))) => {
            panic!("a silent peer must not yield a control stream")
        }
        Ok(Err(e)) => e,
        Err(_) => {
            panic!("server_mux must resolve (with a timeout error) within the outer 5s bound")
        }
    };
    assert!(
        err.to_string().contains("timed out"),
        "expected a first-stream timeout error, got: {err}"
    );
    let elapsed = started.elapsed();
    assert!(
        elapsed >= Duration::from_millis(300),
        "server_mux returned before the accept deadline: {elapsed:?}"
    );
    drop(client_io);
}

/// Regression for the open_stream cancellation race (#7): cancelling an
/// in-flight `open_stream()` must leave the session fully usable. The old
/// request-channel design had the DRIVER open the stream and then fail the
/// reply send when the caller had gone — leaving a phantom outbound stream
/// (SYN already flushed) and, on cancellation floods, unbounded queued
/// requests. The caller-side design polls on the calling task, so dropping
/// the future simply cancels the poll with no side effect.
#[tokio::test]
async fn cancelling_open_stream_leaves_session_usable() {
    let interval = Duration::from_secs(60);
    let (_server_control, mut incoming, _client_control, session) =
        connected_mux_pair(mux_config(interval), mux_config(interval)).await;

    // Spawn and cancel several open_stream() calls. Aborting the task drops
    // the in-flight future mid-poll (it may be parked awaiting an ACK).
    for _ in 0..8 {
        let s = session.clone();
        let handle = tokio::spawn(async move { s.open_stream().await });
        // Give the spawned task a chance to actually enter the poll before
        // we cancel it, exercising the cancellation path with a real poll.
        tokio::task::yield_now().await;
        handle.abort();
    }

    // The session must still be alive and able to open a stream that the
    // server actually accepts — proving the cancelled opens left no wedge
    // and no phantom stream polluted the session.
    let mut stream = tokio::time::timeout(Duration::from_secs(2), session.open_stream())
        .await
        .expect("open_stream must complete after cancellations")
        .expect("session must stay usable after cancelled opens");
    stream.write_all(b"ok").await.expect("write on stream");
    stream.flush().await.expect("flush stream");

    let mut server_stream = tokio::time::timeout(Duration::from_secs(3), incoming.recv())
        .await
        .expect("server must accept the post-cancellation stream")
        .expect("server session must remain open");
    let mut byte = [0u8; 2];
    server_stream
        .read_exact(&mut byte)
        .await
        .expect("server should read from the accepted stream");
    assert_eq!(&byte, b"ok");
}

/// High-concurrency open_stream stress: a burst of simultaneous opens must
/// not wedge the session's driver task. In the old design the driver did the
/// poll_new_outbound, so once the outbound ACK backlog hit its cap the driver
/// parked and could never read the ACK that would unblock it — a PERMANENT
/// session wedge (#1). With the caller-side design the driver keeps reading
/// inbound (and thus ACKs) independently, so a burst of opens always drains.
///
/// N is capped at 64: beyond yamux's per-drain write batch (64 SYN frames per
/// Active::poll) and approaching MAX_ACK_BACKLOG (256), the vendored yamux
/// write path cannot flush a large burst of SYN frames in one pass, so the
/// SERVER sees fewer streams than the client opened regardless of the
/// open_stream design (verified identical on main and this branch) — that is
/// a pre-existing transport-throughput limit, not an open_stream wedge. This
/// test pins the driver-not-wedged property for a realistic burst; the deeper
/// >256 backpressure is out of scope here.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn concurrent_open_stream_burst_does_not_wedge_driver() {
    let interval = Duration::from_secs(60);
    // Use a large duplex so the concurrent yamux streams (SYN + ACK + each
    // stream's data frame) do not fill the shared buffer and stall the peers.
    let (client_io, server_io) = tokio::io::duplex(1024 * 1024);
    let (_server_control, mut incoming, _client_control, session) = connected_mux_pair_over(
        client_io,
        server_io,
        mux_config(interval),
        mux_config(interval),
    )
    .await;

    // The core of (#1): open all N streams concurrently while the server side
    // drains/ACKs them in parallel. With the caller-side design open_stream
    // parks on ITS OWN task when the ACK backlog is full; the driver is never
    // parked inside an open, so it keeps reading ACKs and the burst completes.
    //
    // The server side MUST drain `incoming` concurrently: its channel is
    // bounded (256) and the server driver stalls accept/ACK when it fills —
    // that is backpressure, not a wedge.
    const N: usize = 64;

    // Parallel server drain: accept each stream and read back its 16-bit index.
    let server_drain = tokio::spawn(async move {
        let mut seen2 = vec![false; N];
        let mut n = 0usize;
        while n < N {
            let mut server_stream = tokio::time::timeout(Duration::from_secs(15), incoming.recv())
                .await
                .expect("accepted stream must arrive promptly")
                .expect("server session must stay open");
            let mut idx_bytes = [0u8; 2];
            server_stream
                .read_exact(&mut idx_bytes)
                .await
                .expect("read");
            let v = u16::from_le_bytes(idx_bytes) as usize;
            assert!(v < N && !seen2[v], "server saw stream {v} twice or OOB");
            seen2[v] = true;
            n += 1;
        }
        seen2
    });

    // Parallel client opens: each opens a stream and writes its index. The
    // stream stays owned by the task until server_drain has read it (yield
    // once so the drain can run), avoiding an early-drop RST race.
    let mut open_handles = Vec::with_capacity(N);
    for i in 0..N {
        let s = session.clone();
        open_handles.push(tokio::spawn(async move {
            let mut stream = tokio::time::timeout(Duration::from_secs(30), s.open_stream())
                .await
                .expect("concurrent open must resolve (no driver wedge)")
                .expect("open_stream returned None (session must stay usable)");
            stream
                .write_all(&(i as u16).to_le_bytes())
                .await
                .expect("write");
            stream.flush().await.expect("flush");
            tokio::task::yield_now().await;
            (i, stream)
        }));
    }
    // Errors in any opening task surface the wedge: collect them all.
    let mut open_errors: Vec<String> = Vec::new();
    for h in open_handles {
        if let Err(e) = h.await {
            open_errors.push(format!("open task panicked: {e}"));
        }
    }

    let seen2 = tokio::time::timeout(Duration::from_secs(120), server_drain)
        .await
        .expect("server must drain all concurrent streams without wedging")
        .expect("server drain task");
    assert!(
        seen2.iter().all(|s| *s),
        "every stream must be received once"
    );
    assert!(
        open_errors.is_empty(),
        "client open tasks panicked: {}",
        open_errors.join("; ")
    );
}

/// 2 MiB of patterned data flowing in BOTH directions over one yamux
/// session at once. Each side writes and reads concurrently (a
/// write-then-read ordering would deadlock once both sides fill the
/// window), and every byte must arrive intact — a byte-reordering or
/// drop in the frame path would surface as an exact-length mismatch.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mux_2mib_bidirectional_byte_exact() {
    let interval = Duration::from_secs(60);
    // 1 MiB duplex (vs the 64 KiB default): yamux auto-tunes the per-stream
    // receive window past the 64 KiB duplex capacity on a 2 MiB transfer,
    // and full-window DATA frames over a smaller shared duplex deadlock
    // (real TCP has per-direction buffers; a shared duplex does not).
    let (client_io, server_io) = tokio::io::duplex(1024 * 1024);
    let (_server_control, mut incoming, _client_control, session) = connected_mux_pair_over(
        client_io,
        server_io,
        mux_config(interval),
        mux_config(interval),
    )
    .await;

    let mut client_stream = tokio::time::timeout(Duration::from_secs(5), session.open_stream())
        .await
        .expect("client open_stream must complete")
        .expect("client session must stay open");
    client_stream.write_all(b"p").await.expect("probe write");
    client_stream.flush().await.expect("probe flush");
    let mut server_stream = tokio::time::timeout(Duration::from_secs(5), incoming.recv())
        .await
        .expect("server must accept the stream")
        .expect("server session must stay open");
    let mut probe = [0u8; 1];
    server_stream
        .read_exact(&mut probe)
        .await
        .expect("server must read the probe byte");

    const N: usize = 2 * 1024 * 1024;
    let c2s: Vec<u8> = (0..N).map(|i| ((i * 31 + 7) % 251) as u8).collect();
    let s2c: Vec<u8> = (0..N).map(|i| ((i * 17 + 3) % 251) as u8).collect();

    let (mut c_r, mut c_w) = tokio::io::split(client_stream);
    let (mut s_r, mut s_w) = tokio::io::split(server_stream);

    // Writes and reads run concurrently per side — the 2 MiB each way far
    // exceeds the ~256 KiB yamux window, so a side that only writes would
    // park forever waiting for the peer's reads.
    let c2s_data = c2s.clone();
    let s2c_data = s2c.clone();
    let client_write = tokio::spawn(async move {
        c_w.write_all(&c2s_data).await.expect("c2s write");
        c_w.flush().await.expect("c2s flush");
    });
    let client_read = tokio::spawn(async move {
        let mut got = vec![0u8; N];
        c_r.read_exact(&mut got).await.expect("s2c read");
        got
    });
    let server_write = tokio::spawn(async move {
        s_w.write_all(&s2c_data).await.expect("s2c write");
        s_w.flush().await.expect("s2c flush");
    });
    let server_read = tokio::spawn(async move {
        let mut got = vec![0u8; N];
        s_r.read_exact(&mut got).await.expect("c2s read");
        got
    });

    let (cw, cr, sw, sr) = tokio::join!(client_write, client_read, server_write, server_read);
    cw.expect("client write task");
    sw.expect("server write task");
    let got_s2c = cr.expect("client read task");
    let got_c2s = sr.expect("server read task");
    assert_eq!(got_s2c, s2c, "server→client data must be byte-exact");
    assert_eq!(got_c2s, c2s, "client→server data must be byte-exact");
}

/// Flow-control backpressure: a 2 MiB write_all through a 64 KiB duplex
/// (plus the ~256 KiB yamux initial window) cannot complete until the peer
/// reads. The writer must stall — not spin, not finish early — and then
/// drain to completion once the peer drains, with every byte intact.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mux_writer_stalls_on_window_exhaustion_and_drains_on_peer_read() {
    let interval = Duration::from_secs(60);
    let (_server_control, mut incoming, _client_control, session) =
        connected_mux_pair(mux_config(interval), mux_config(interval)).await;

    let mut client_stream = tokio::time::timeout(Duration::from_secs(5), session.open_stream())
        .await
        .expect("client open_stream must complete")
        .expect("client session must stay open");
    client_stream.write_all(b"p").await.expect("probe write");
    client_stream.flush().await.expect("probe flush");
    let mut server_stream = tokio::time::timeout(Duration::from_secs(5), incoming.recv())
        .await
        .expect("server must accept the stream")
        .expect("server session must stay open");
    let mut probe = [0u8; 1];
    server_stream
        .read_exact(&mut probe)
        .await
        .expect("server must read the probe byte");

    const N: usize = 2 * 1024 * 1024;
    let payload: Vec<u8> = (0..N).map(|i| ((i * 7 + 11) % 251) as u8).collect();
    let write_data = payload.clone();
    let write_task = tokio::spawn(async move {
        client_stream
            .write_all(&write_data)
            .await
            .expect("write_all must complete once the peer drains");
        client_stream.flush().await.expect("flush");
    });

    // 2 MiB cannot fit in the 64 KiB duplex + ~256 KiB window: the writer
    // must be parked on credit within 100 ms.
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(
        !write_task.is_finished(),
        "writer must stall on window exhaustion until the peer reads"
    );

    // Draining the peer side releases window updates; the stalled writer
    // then completes and the payload arrives byte-exact.
    let mut got = vec![0u8; N];
    tokio::time::timeout(Duration::from_secs(30), server_stream.read_exact(&mut got))
        .await
        .expect("peer read must complete within 30s")
        .expect("read_exact");
    assert_eq!(got, payload, "payload must be byte-exact after the stall");
    tokio::time::timeout(Duration::from_secs(30), write_task)
        .await
        .expect("writer must finish after the peer drains")
        .expect("write task");
}

#[tokio::test]
async fn stream_graceful_shutdown_delivers_clean_eof_and_session_survives() {
    // Clean half-close: shutting down (FIN) one side of a stream must
    // surface Ok(0) EOF to the peer's reader while the session and its
    // other streams stay usable. The bridge/relay paths (plain and
    // encrypted) depend on this wire shape for half-close EOF. A driver
    // that dropped the stream instead of FINing it would hang the reader;
    // one that tore down the session would kill sibling streams.
    let (_server_control, mut incoming, _client_control, session) =
        connected_mux_pair(TcpMuxConfig::default(), TcpMuxConfig::default()).await;

    let mut client_stream = tokio::time::timeout(Duration::from_secs(2), session.open_stream())
        .await
        .expect("open_stream must resolve")
        .expect("session must stay open and yield a stream");
    client_stream.write_all(b"half").await.unwrap();
    client_stream
        .shutdown()
        .await
        .expect("clean shutdown must FIN");

    let mut server_stream = tokio::time::timeout(Duration::from_secs(2), incoming.recv())
        .await
        .expect("server must observe the stream")
        .expect("session must stay open");

    let mut data = [0u8; 4];
    server_stream
        .read_exact(&mut data)
        .await
        .expect("server reads the payload");
    assert_eq!(&data, b"half");
    let mut byte = [0u8; 1];
    let n = server_stream
        .read(&mut byte)
        .await
        .expect("EOF read must succeed, not error");
    assert_eq!(n, 0, "FIN must deliver clean EOF, not a hang");

    // The session survives the half-closed stream: a second stream still
    // opens and carries data in both directions.
    let mut second = tokio::time::timeout(Duration::from_secs(2), session.open_stream())
        .await
        .expect("second open_stream must resolve")
        .expect("session must stay open and yield the second stream");
    second.write_all(b"still alive").await.unwrap();
    second.shutdown().await.unwrap();

    let mut server_second = tokio::time::timeout(Duration::from_secs(2), incoming.recv())
        .await
        .expect("second stream must arrive")
        .expect("session must stay open");
    let mut buf = Vec::new();
    server_second
        .read_to_end(&mut buf)
        .await
        .expect("second payload plus its EOF");
    assert_eq!(&buf, b"still alive");
}
