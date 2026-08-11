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
