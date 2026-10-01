use super::*;
use tokio::io::AsyncReadExt;

/// Work stream whose reads block forever and whose writes fail
/// deterministically, independent of platform TCP shutdown/RST timing.
struct FailingWorkStream;

impl AsyncRead for FailingWorkStream {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Poll::Pending
    }
}

impl tokio::io::AsyncWrite for FailingWorkStream {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Poll::Ready(Err(std::io::Error::new(
            std::io::ErrorKind::BrokenPipe,
            "injected writer failure",
        )))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

async fn tcp_pair() -> (tokio::net::TcpStream, tokio::net::TcpStream) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (client, accepted) = tokio::join!(tokio::net::TcpStream::connect(addr), listener.accept(),);
    (client.unwrap(), accepted.unwrap().0)
}

#[tokio::test]
async fn udp_work_reader_eof_cancels_blocked_socket_writer() {
    let (work, peer) = tcp_pair().await;
    let socket = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let socket_addr = socket.local_addr().unwrap();
    let retained_socket = socket.clone();

    let bridge = tokio::spawn(run_udp_work_conn(
        IoStream::Tcp(work),
        socket,
        "udp-test".to_string(),
        None,
        false,
        [0u8; 16],
        false,
        1500,
        None,
        tokio_util::sync::CancellationToken::new(),
        String::new(),
        // M1: keep the 60s production read deadline; these tests end
        // the bridge via EOF/cancel, not frame silence.
        UDP_WORK_CONN_READ_TIMEOUT,
        None,
    ));
    drop(peer);

    tokio::time::timeout(std::time::Duration::from_millis(200), bridge)
        .await
        .expect("reader EOF must cancel the sibling blocked on UDP recv_from")
        .unwrap();

    let sender = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    sender.send_to(b"after-stop", socket_addr).await.unwrap();
    let mut buf = [0; 32];
    let (n, _) = tokio::time::timeout(
        std::time::Duration::from_millis(200),
        retained_socket.recv_from(&mut buf),
    )
    .await
    .expect("stopped writer must not consume a later datagram")
    .unwrap();
    assert_eq!(&buf[..n], b"after-stop");
}

#[tokio::test]
async fn udp_work_writer_error_cancels_blocked_work_reader() {
    let socket = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let sender = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let socket_addr = socket.local_addr().unwrap();

    let bridge = tokio::spawn(run_udp_work_conn(
        IoStream::SshChannel(Box::new(FailingWorkStream)),
        socket,
        "udp-test".to_string(),
        None,
        false,
        [0u8; 16],
        false,
        1500,
        None,
        tokio_util::sync::CancellationToken::new(),
        String::new(),
        // M1: keep the 60s production read deadline; these tests end
        // the bridge via EOF/cancel, not frame silence.
        UDP_WORK_CONN_READ_TIMEOUT,
        None,
    ));
    sender.send_to(b"force-write", socket_addr).await.unwrap();

    tokio::time::timeout(std::time::Duration::from_secs(1), bridge)
        .await
        .expect("writer error must cancel the sibling blocked on work read")
        .unwrap();
}

#[tokio::test]
async fn udp_work_forwards_packets_and_addresses_bidirectionally() {
    let (work, peer) = tcp_pair().await;
    let mut peer = IoStream::Tcp(peer);
    let socket = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let remote = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let remote_addr = remote.local_addr().unwrap();
    let local_addr = msg::UdpAddr {
        ip: "192.0.2.8".to_string(),
        port: 7000,
        zone: String::new(),
    };
    let bridge = tokio::spawn(run_udp_work_conn(
        IoStream::Tcp(work),
        socket.clone(),
        "udp-test".to_string(),
        Some(local_addr.clone()),
        false,
        [0u8; 16],
        false,
        1500,
        None,
        tokio_util::sync::CancellationToken::new(),
        String::new(),
        // M1: keep the 60s production read deadline; these tests end
        // the bridge via EOF/cancel, not frame silence.
        UDP_WORK_CONN_READ_TIMEOUT,
        None,
    ));

    peer.write_v1_frame(&FrpMessage::UDPPacket(msg::UDPPacket {
        content: b"request".to_vec(),
        local_addr: None,
        remote_addr: Some(msg::UdpAddr {
            ip: remote_addr.ip().to_string(),
            port: remote_addr.port(),
            zone: String::new(),
        }),
    }))
    .await
    .unwrap();
    let mut buf = [0u8; 32];
    let (n, _) = remote.recv_from(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"request");

    remote
        .send_to(b"response", socket.local_addr().unwrap())
        .await
        .unwrap();
    let response = peer.read_v1_frame().await.unwrap();
    match response {
        FrpMessage::UDPPacket(packet) => {
            assert_eq!(packet.content, b"response");
            assert_eq!(
                packet.local_addr.unwrap().to_string(),
                local_addr.to_string()
            );
            assert_eq!(
                packet.remote_addr.unwrap().to_string(),
                remote_addr.to_string()
            );
        }
        other => panic!("expected UDPPacket, got type {}", other.v1_type_byte()),
    }

    drop(peer);
    tokio::time::timeout(std::time::Duration::from_secs(1), bridge)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn udp_bridge_cancel_terminates_half_open_work_conn() {
    // Half-open work conn: keep the peer side open but never send, so the
    // reader blocks on read_msg_v1 (no EOF) and the writer blocks on
    // recv_from. Before the cancellation fix this bridge task hung
    // forever, leaking the work conn fd + socket + task memory after
    // control supersession/disconnect (Go frp v0.70.1 fix parity).
    let (work, _peer) = tcp_pair().await;
    let socket = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let cancel = tokio_util::sync::CancellationToken::new();
    let bridge_cancel = cancel.clone();

    let bridge = tokio::spawn(run_udp_work_conn(
        IoStream::Tcp(work),
        socket,
        "udp-test".to_string(),
        None,
        false,
        [0u8; 16],
        false,
        1500,
        None,
        bridge_cancel,
        String::new(),
        // M1: keep the 60s production read deadline; the cancel arm
        // below ends this bridge, not frame silence.
        UDP_WORK_CONN_READ_TIMEOUT,
        None,
    ));

    // Let both bridge tasks reach their blocking points.
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    cancel.cancel();

    tokio::time::timeout(std::time::Duration::from_secs(1), bridge)
        .await
        .expect("cancel must terminate the half-open UDP bridge task")
        .unwrap();
}

#[tokio::test]
async fn udp_work_reader_silence_reaps_half_open_conn() {
    // M1: Go server/proxy/udp.go read-deadline parity. A peer that
    // stays open but silent (no frames at all — a Ping included) must
    // be reaped after the read deadline; before the fix the reader was
    // parked on read_msg forever (dead UDP proxy until control
    // reconnect). Short deadline (150ms) pins the reap path without a
    // 60s test.
    let (work, peer) = tcp_pair().await;
    let socket = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let retained_socket = socket.clone();

    let bridge = tokio::spawn(run_udp_work_conn(
        IoStream::Tcp(work),
        socket,
        "udp-test".to_string(),
        None,
        false,
        [0u8; 16],
        false,
        1500,
        None,
        tokio_util::sync::CancellationToken::new(),
        String::new(),
        std::time::Duration::from_millis(150),
        None,
    ));
    // Keep `peer` alive and silent: no EOF, no frames.
    std::mem::forget(peer);

    tokio::time::timeout(std::time::Duration::from_secs(2), bridge)
        .await
        .expect("frame silence must end the UDP bridge after the read deadline")
        .unwrap();

    // The reaped bridge must not consume a later datagram (writer was
    // cancelled, not left draining).
    let sender = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    sender
        .send_to(b"after-stop", retained_socket.local_addr().unwrap())
        .await
        .unwrap();
    let mut buf = [0; 32];
    let (n, _) = tokio::time::timeout(
        std::time::Duration::from_millis(200),
        retained_socket.recv_from(&mut buf),
    )
    .await
    .expect("stopped writer must not consume a later datagram")
    .unwrap();
    assert_eq!(&buf[..n], b"after-stop");
}

#[tokio::test]
async fn udp_work_reader_frame_activity_slides_the_read_deadline() {
    // M1 (§4 示例 A): the read deadline is per completed FRAME (Go issues
    // SetReadDeadline after every read), so frames arriving inside the
    // window must slide the watchdog — and the re-armed timer must still
    // reap the conn once the frames stop.
    let (work, mut peer) = tcp_pair().await;
    let socket = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());

    let bridge = tokio::spawn(run_udp_work_conn(
        IoStream::Tcp(work),
        socket,
        "udp-test".to_string(),
        None,
        false,
        [0u8; 16],
        false,
        1500,
        None,
        tokio_util::sync::CancellationToken::new(),
        String::new(),
        std::time::Duration::from_millis(400),
        None,
    ));

    // 5 pings 100ms apart span 500ms — longer than ONE deadline, so a
    // watchdog that was not slid per frame would already have reaped the
    // conn by the assertion below.
    for _ in 0..5 {
        write_msg_v1(
            &mut peer,
            &FrpMessage::Ping(msg::Ping {
                privilege_key: None,
                timestamp: Some(1),
            }),
        )
        .await
        .unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert!(
        !bridge.is_finished(),
        "frames inside the window must slide the read deadline"
    );

    // Silence now reaps it on the re-armed timer.
    tokio::time::timeout(std::time::Duration::from_secs(2), bridge)
        .await
        .expect("silence after activity must still reap the bridge")
        .unwrap();
}

#[tokio::test]
async fn udp_work_reader_partial_frame_survives_competing_wakeup() {
    // M1 (§4 示例 A) against its nastiest wakeup shape: a competing
    // reader-cancel tick landing MID-FRAME (header consumed, payload
    // outstanding). The pre-M1 loop rebuilt the frame read per
    // iteration, so any wakeup dropped the read future WITH the header
    // already consumed — the next iteration read the payload bytes as a
    // fresh header (garbage length → protocol error → conn death). The
    // persisted `read_fut` survives the wakeup and finishes the SAME
    // frame. Two back-to-back watch sends with no await in between: the
    // current-thread runtime polls the reader only after both, so it
    // observes the final false and takes the benign `continue` arm.
    use tokio::io::AsyncWriteExt;
    let (work, mut peer) = tcp_pair().await;
    let socket = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let remote = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let remote_addr = remote.local_addr().unwrap();
    let (cancel_override, _cancel_rx) = tokio::sync::watch::channel(false);

    let bridge = tokio::spawn(run_udp_work_conn(
        IoStream::Tcp(work),
        socket,
        "udp-test".to_string(),
        None,
        false,
        [0u8; 16],
        false,
        1500,
        None,
        tokio_util::sync::CancellationToken::new(),
        String::new(),
        UDP_WORK_CONN_READ_TIMEOUT,
        Some(cancel_override.clone()),
    ));

    let packet = FrpMessage::UDPPacket(msg::UDPPacket {
        content: b"split-frame".to_vec(),
        local_addr: None,
        remote_addr: Some(msg::UdpAddr {
            ip: remote_addr.ip().to_string(),
            port: remote_addr.port(),
            zone: String::new(),
        }),
    });
    let payload = serde_json::to_vec(&packet).unwrap();
    // V1 header only (1 type byte + 8-byte BE length): the reader
    // consumes it and parks on the payload read — the mid-frame state.
    let mut header = Vec::with_capacity(9);
    header.push(packet.v1_type_byte());
    header.extend_from_slice(&(payload.len() as u64).to_be_bytes());
    peer.write_all(&header).await.unwrap();
    // Let the reader consume the header and block on the payload. Two
    // yields: the peer write wakes the bridge task, and on the
    // current-thread scheduler a yielded test task runs only after the
    // already-woken reader, so the header is consumed deterministically
    // (no wall-clock sleep, no vacuous-pass window).
    tokio::task::yield_now().await;
    tokio::task::yield_now().await;

    // Competing wakeup: true then false, no yield in between. The
    // reader must resume the SAME frame read, not restart it.
    cancel_override.send(true).unwrap();
    cancel_override.send(false).unwrap();

    peer.write_all(&payload).await.unwrap();

    let mut buf = [0u8; 64];
    let (n, _) = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        remote.recv_from(&mut buf),
    )
    .await
    .expect("the split frame must still be delivered after the competing wakeup")
    .unwrap();
    assert_eq!(&buf[..n], b"split-frame");

    drop(peer);
    tokio::time::timeout(std::time::Duration::from_secs(1), bridge)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn udp_work_conn_death_requests_replacement() {
    // M1: a UDP work-conn death (EOF here; read error / 60s silence
    // follow the same break path) must re-request a replacement
    // through the control loop — Go udpWorker replacement-loop parity.
    // Before the fix UdpNeedsWorkConn was sent exactly once at
    // registration and a dead work conn stranded the UDP proxy until
    // control reconnect.
    let (work, peer) = tcp_pair().await;
    let socket = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let mut udp_sockets = std::collections::HashMap::new();
    udp_sockets.insert("udp-test".to_string(), socket.clone());
    let (tx, mut rx) = tokio::sync::mpsc::channel::<crate::state::InternalMsg>(16);

    let assign = tokio::spawn(async move {
        assign_udp_work_conn(
            IoStream::Tcp(work),
            "udp-test",
            &udp_sockets,
            None,
            false,
            [0u8; 16],
            false,
            1500,
            None,
            tokio_util::sync::CancellationToken::new(),
            String::new(),
            tx,
        )
        .await
    });
    // Let assign write StartWorkConn and spawn the bridge, then kill the
    // peer so the bridge read sees EOF.
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    drop(peer);
    assign.await.unwrap();

    let msg = tokio::time::timeout(std::time::Duration::from_secs(5), rx.recv())
        .await
        .expect("work-conn death must re-request a replacement")
        .expect("channel closed");
    match msg {
        crate::state::InternalMsg::UdpNeedsWorkConn { proxy_name } => {
            assert_eq!(proxy_name, "udp-test");
        }
        other => panic!("expected UdpNeedsWorkConn, got {other:?}"),
    }
}

#[tokio::test]
async fn udp_work_conn_cancel_suppresses_replacement_request() {
    // M1: an exit caused by cancellation (proxy closed / control
    // teardown) must NOT re-request — the udp_sockets entry is gone and
    // a ReqWorkConn would dial a work conn into nothing. Half-open
    // bridge cancelled mid-flight; the channel must stay empty.
    let (work, peer) = tcp_pair().await;
    let socket = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let mut udp_sockets = std::collections::HashMap::new();
    udp_sockets.insert("udp-test".to_string(), socket.clone());
    let (tx, mut rx) = tokio::sync::mpsc::channel::<crate::state::InternalMsg>(16);
    let cancel = tokio_util::sync::CancellationToken::new();
    let cancel_in = cancel.clone();

    let assign = tokio::spawn(async move {
        assign_udp_work_conn(
            IoStream::Tcp(work),
            "udp-test",
            &udp_sockets,
            None,
            false,
            [0u8; 16],
            false,
            1500,
            None,
            cancel_in,
            String::new(),
            tx,
        )
        .await
    });
    // Let the bridge park on the half-open read, then cancel it (the
    // 60s production read deadline keeps the natural-death path out of
    // this test's window). Keep `peer` alive so no EOF races the cancel.
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    cancel.cancel();
    assign.await.unwrap();
    std::mem::forget(peer);

    match tokio::time::timeout(std::time::Duration::from_millis(300), rx.recv()).await {
        // Supervisors finished (tx dropped) without sending — correct.
        Ok(None) => {}
        Ok(Some(other)) => {
            panic!("cancel-based bridge exit must not re-request a replacement, got {other:?}")
        }
        Err(_elapsed) => panic!("supervisor still alive 300ms after cancel"),
    }
}

#[tokio::test]
async fn bridge_cancel_terminates_half_open_tcp_bridge() {
    // Half-open TCP bridge: work conn + user conn both open, neither
    // side sending, so the copy blocks forever. Before the fix the
    // bridge task selected only on the server-global shutdown token, so
    // control teardown (disconnect / supersession) left it copying — the
    // half-open work conn (client side gone) + user conn + task leaked
    // per reconnect with active tunnels (HIGH finding). The bridge must
    // exit when the per-control token is cancelled, which is exactly
    // what control cleanup does with `bridge_cancel`.
    let state = crate::control::proxy_ops::unregister_generation_tests::test_state();
    let (work, mut work_peer) = tcp_pair().await;
    let (user, _user_peer) = tcp_pair().await;
    let cancel = tokio_util::sync::CancellationToken::new();

    let req = PendingRequest {
        proxy_name: "t1".to_string(),
        user_conn: IoStream::Tcp(user),
        pre_read: Vec::new(),
        use_encryption: false,
        use_compression: false,
        visitor_use_encryption: false,
        visitor_use_compression: false,
        visitor_v2: false,
        visitor_udp_packet_codec: String::new(),
        created_at: tokio::time::Instant::now(),
        user_conn_permit: None,
        proxy_info: Some(Arc::new(
            crate::control::proxy_ops::unregister_generation_tests::proxy_info(
                "t1",
                "tcp",
                "run-1",
                Some(24000),
                1,
            ),
        )),
        request_is_connect: false,
    };
    let spawn_res = assign_work_to_proxy(
        IoStream::Tcp(work),
        req,
        [0u8; 16],
        state,
        false,
        cancel.clone(),
    )
    .await;
    assert!(spawn_res.is_ok(), "bridge spawn must succeed");

    // Let the bridge reach its blocking copy point on the half-open pair.
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // Control teardown: cancel the per-control bridge token.
    cancel.cancel();

    // The bridge task must exit, dropping the work conn (and user conn).
    // The work-conn peer observes EOF — but first drains the
    // StartWorkConn frame written on spawn. Without the fix the final
    // read hangs forever and the timeout fires.
    let mut out = Vec::new();
    let mut chunk = [0u8; 64];
    loop {
        let n = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            work_peer.read(&mut chunk),
        )
        .await
        .expect("cancel must terminate the half-open TCP bridge (work conn peer must see EOF)")
        .expect("read from work conn peer must succeed");
        if n == 0 {
            break;
        }
        out.extend_from_slice(&chunk[..n]);
    }
    assert!(
        !out.is_empty(),
        "StartWorkConn frame must have been delivered before EOF"
    );
}

// ---------------------------------------------------------------------
// ResponseHeaderInjector unit tests (regressions for #3a / #3b).
// ---------------------------------------------------------------------

async fn injector_read_all(
    injector: &mut ResponseHeaderInjector<tokio::io::DuplexStream>,
) -> Vec<u8> {
    use tokio::io::AsyncReadExt;
    let mut out = Vec::new();
    let mut chunk = [0u8; 7];
    loop {
        let n = injector.read(&mut chunk).await.expect("injector read");
        if n == 0 {
            break;
        }
        out.extend_from_slice(&chunk[..n]);
        // A deliberately small caller buffer exercises the "injected tail
        // must survive a partial serve" path (#3b).
    }
    out
}

/// Drive ONE `poll_read` into a fresh 1 KiB caller ReadBuf — the M1
/// tests need a caller buffer smaller than the injected emission and
/// per-poll control over which poll parks (a tokio `read` future
/// hides both: it drains as much as fits and re-polls transparently).
/// Each call uses a FRESH ReadBuf exactly like tokio's `Read` future
/// does — bytes filled by a poll that then returns Pending are lost,
/// which is the M1 bug under test. `Ok(n)` served n bytes, `Ok(0)`
/// clean EOF; `Err(TimedOut)` the poll PARKED (returned Pending and
/// registered the inner read's waker; the 1 s budget turns an
/// unexpected park into a test failure instead of a hang);
/// `Err(other)` the read failed.
async fn injector_poll_read_small(
    injector: &mut ResponseHeaderInjector<tokio::io::DuplexStream>,
    chunk: &mut [u8; 1024],
) -> std::io::Result<usize> {
    use std::future::poll_fn;
    use std::pin::Pin;
    use std::task::Poll;
    match tokio::time::timeout(
        std::time::Duration::from_secs(1),
        poll_fn(|cx| {
            let mut buf = ReadBuf::new(chunk);
            match Pin::new(&mut *injector).poll_read(cx, &mut buf) {
                Poll::Ready(Ok(())) => Poll::Ready(Ok(buf.filled().len())),
                Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                Poll::Pending => Poll::Pending,
            }
        }),
    )
    .await
    {
        Ok(r) => r,
        Err(_) => Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "injector poll parked",
        )),
    }
}

/// #3a: a response header longer than one internal 4 KiB buffer, whose
/// `\r\n\r\n` terminator spans two inner reads, must still be injected.
#[tokio::test]
async fn injector_headers_hspanning_reads_are_injected() {
    use tokio::io::AsyncWriteExt;
    let (mut inner_w, inner_r) = tokio::io::duplex(64 * 1024);
    let mut headers = std::collections::HashMap::new();
    headers.insert("X-Injected".to_string(), String::from("yes"));
    let mut injector = ResponseHeaderInjector::new(inner_r, headers, None);

    // Build a response whose header block is larger than the injector's
    // 4096-byte read buffer, so the boundary lands in the second read.
    let mut big_cookie = String::from("Set-Cookie: a=");
    for _ in 0..900 {
        big_cookie.push('x');
    }
    big_cookie.push_str(";\r\n");
    let response = format!("HTTP/1.1 200 OK\r\n{big_cookie}\r\nbody-data");
    inner_w.write_all(response.as_bytes()).await.expect("write");
    inner_w.shutdown().await.expect("shutdown");
    drop(inner_w);

    let out = injector_read_all(&mut injector).await;
    let s = String::from_utf8_lossy(&out);
    assert!(
        s.contains("X-Injected: yes"),
        "injected header must be present, got: {s:?}"
    );
    assert!(s.ends_with("body-data"), "body must survive, got: {s:?}");
    assert!(
        s.starts_with("HTTP/1.1 200 OK\r\n"),
        "leading status line must be preserved"
    );
}

/// #3b: the injected buffer is larger than the caller's `ReadBuf`, so the
/// injected header tail spans multiple polls — none of it may be dropped.
#[tokio::test]
async fn injector_injected_tail_not_dropped_across_small_reads() {
    use tokio::io::AsyncWriteExt;
    let (mut inner_w, inner_r) = tokio::io::duplex(64 * 1024);
    let mut headers = std::collections::HashMap::new();
    for i in 0..20 {
        headers.insert(format!("X-{i}"), String::from("value-value-value-value"));
    }
    let mut injector = ResponseHeaderInjector::new(inner_r, headers, None);

    let response = "HTTP/1.1 200 OK\r\n\r\nhello-body";
    inner_w.write_all(response.as_bytes()).await.expect("write");
    inner_w.shutdown().await.expect("shutdown");
    drop(inner_w);

    let out = injector_read_all(&mut injector).await;
    let s = String::from_utf8_lossy(&out);
    for i in 0..20 {
        assert!(
            s.contains(&format!("X-{i}: value-value-value-value\r\n")),
            "injected header {i} missing (tail dropped?): {s:?}"
        );
    }
    assert!(s.ends_with("hello-body"), "body must be intact");
}

/// Round-14 review: a backend that closes without any head terminator
/// (garbage, or a head cut short) must ERROR — nothing is relayed. Go
/// readResponse relays nothing until a head parses and errors on the
/// unterminated head; the vhost ErrorHandler answers 404 and frp-core
/// maps this UnexpectedEof to it. The old code relayed the partial
/// bytes raw and ended "clean" (half a head on the wire, no 404).
#[tokio::test]
async fn injector_unterminated_bytes_then_eof_errors_not_relayed() {
    use tokio::io::AsyncWriteExt;
    let (mut inner_w, inner_r) = tokio::io::duplex(64 * 1024);
    let mut headers = std::collections::HashMap::new();
    headers.insert("X-Injected".to_string(), String::from("yes"));
    let mut injector = ResponseHeaderInjector::new(inner_r, headers, None);

    inner_w
        .write_all(b"no-header-terminator-here")
        .await
        .expect("write");
    inner_w.shutdown().await.expect("shutdown");
    drop(inner_w);

    let mut buf = [0u8; 64];
    let err = injector
        .read(&mut buf)
        .await
        .expect_err("unterminated head + EOF must error, never relay partial bytes");
    assert_eq!(err.kind(), std::io::ErrorKind::UnexpectedEof);
}

/// Audit round 7 (S1 family): a backend response head with bare-LF line
/// endings is legal under Go textproto.ReadLine semantics (each line
/// ends at the next `\n`, ONE trailing `\r` is stripped, the head ends
/// at the first empty line) but contains no `\r\n\r\n` window. The old
/// strict-CRLF scan never found a boundary: injection was skipped and
/// the head read on until EOF. RED on the old scan — the fix must
/// terminate the gather at the LF blank line, emit the configured
/// header as a REAL header line BEFORE the head/body blank line (bytes
/// past it are the backend's body and pass verbatim), and keep the
/// body intact after it.
#[tokio::test]
async fn injector_lf_only_head_injects_at_blank_line() {
    use tokio::io::AsyncWriteExt;
    let (mut inner_w, inner_r) = tokio::io::duplex(64 * 1024);
    let mut headers = std::collections::HashMap::new();
    headers.insert("X-Injected".to_string(), String::from("yes"));
    let mut injector = ResponseHeaderInjector::new(inner_r, headers, None);

    let response = "HTTP/1.1 200 OK\nContent-Type: text/plain\n\nhello";
    inner_w.write_all(response.as_bytes()).await.expect("write");
    inner_w.shutdown().await.expect("shutdown");
    drop(inner_w);

    let out = injector_read_all(&mut injector).await;
    // Byte-exact pin: head lines verbatim (LF kept), the injected
    // header line CRLF-terminated BEFORE the backend's blank line, the
    // blank line itself and the body verbatim after it.
    let expected = b"HTTP/1.1 200 OK\nContent-Type: text/plain\nX-Injected: yes\r\n\nhello";
    assert_eq!(
        &out[..],
        expected,
        "LF-only head must terminate at the blank line with the header injected"
    );
}

#[tokio::test]
async fn injector_empty_first_line_is_rejected_not_prepended() {
    // Go http.ReadResponse rejects a head with no status line (the head
    // starting with its own blank line) — the old splice prepended the
    // configured headers to the garbage and forwarded it as a plausible
    // 200-ish response (round-3 review finding).
    use tokio::io::AsyncWriteExt;
    let mut headers = std::collections::HashMap::new();
    headers.insert("X-Injected".to_string(), String::from("yes"));

    for garbage in [
        "\r\nHTTP/1.1 200 OK\r\n\r\nbody",
        "\nHTTP/1.1 200 OK\n\nbody",
    ] {
        let (mut w, r) = tokio::io::duplex(64 * 1024);
        let mut injector = ResponseHeaderInjector::new(r, headers.clone(), None);
        w.write_all(garbage.as_bytes()).await.expect("write");
        w.shutdown().await.expect("shutdown");
        drop(w);
        let mut buf = Vec::new();
        let res = tokio::io::AsyncReadExt::read_to_end(&mut injector, &mut buf).await;
        assert!(
            res.is_err(),
            "an empty first line must error, not forward: {garbage:?}"
        );
    }
}

/// Round-13 (F1#2): a backend head of status 1xx (NOT 101) must be
/// served RAW, promptly, with no injection — Go's Transport consumes
/// interim responses and ModifyResponse never runs on them, and an
/// Expect:100-continue backend deadlocks if its 100 head is withheld
/// while the injector keeps gathering the (never-arriving) final head.
/// A final head pipelined in the SAME backend segment as the 100 must
/// still get the injection (the split-off tail is re-accumulated once
/// the raw emission drains).
#[tokio::test]
async fn injector_interim_1xx_served_raw_final_pipelined_injected() {
    use tokio::io::AsyncWriteExt;
    let (mut inner_w, inner_r) = tokio::io::duplex(64 * 1024);
    let mut headers = std::collections::HashMap::new();
    headers.insert("X-Injected".to_string(), String::from("yes"));
    let mut injector = ResponseHeaderInjector::new(inner_r, headers, None);

    // One backend segment: interim 100 head + final 200 head + body.
    let response =
        "HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nhello";
    inner_w.write_all(response.as_bytes()).await.expect("write");
    inner_w.shutdown().await.expect("shutdown");
    drop(inner_w);

    let out = injector_read_all(&mut injector).await;
    // Byte-exact: the 100 head verbatim, then the 200 head WITH the
    // configured header injected before its blank line, body intact.
    let expected = b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nX-Injected: yes\r\n\r\nhello";
    assert_eq!(
        &out[..],
        expected,
        "interim head must pass raw, final head must be injected"
    );
}

/// Round-13 (F1#2): interim head arriving on a SEPARATE write (the
/// Expect:100-continue shape — backend waits for the 100 to reach the
/// client before sending the final head) must be emitted before the
/// final head exists, not withheld while the injector waits for a
/// second head it cannot see.
#[tokio::test]
async fn injector_interim_1xx_emitted_before_final_arrives() {
    use tokio::io::AsyncWriteExt;
    let (mut inner_w, inner_r) = tokio::io::duplex(64 * 1024);
    let mut headers = std::collections::HashMap::new();
    headers.insert("X-Injected".to_string(), String::from("yes"));
    let mut injector = ResponseHeaderInjector::new(inner_r, headers, None);

    // Phase 1: only the 100 head. A single read must return it in full.
    inner_w
        .write_all(b"HTTP/1.1 100 Continue\r\n\r\n")
        .await
        .expect("write 100");
    let mut first = [0u8; 64];
    let n = tokio::io::AsyncReadExt::read(&mut injector, &mut first)
        .await
        .expect("read 100 head");
    assert_eq!(
        &first[..n],
        b"HTTP/1.1 100 Continue\r\n\r\n",
        "the interim head must be served raw before the final head exists"
    );

    // Phase 2: final head + body, then EOF.
    inner_w
        .write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nhello")
        .await
        .expect("write final");
    inner_w.shutdown().await.expect("shutdown");
    drop(inner_w);
    let mut rest = Vec::new();
    tokio::io::AsyncReadExt::read_to_end(&mut injector, &mut rest)
        .await
        .expect("read rest");
    assert_eq!(
        &rest[..],
        b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nX-Injected: yes\r\n\r\nhello",
        "the final head must still get the injection"
    );
}

/// Round-13 (F1#2): 101 is NOT interim — Go runs modifyResponse on a
/// 101, so the configured headers are injected into the 101 head, and
/// the raw upgrade bytes after it pass through verbatim.
#[tokio::test]
async fn injector_101_switching_protocols_gets_injection() {
    use tokio::io::AsyncWriteExt;
    let (mut inner_w, inner_r) = tokio::io::duplex(64 * 1024);
    let mut headers = std::collections::HashMap::new();
    headers.insert("X-Injected".to_string(), String::from("yes"));
    let mut injector = ResponseHeaderInjector::new(inner_r, headers, None);

    let response =
        b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n\x81\xfeRAW-UPGRADE-BYTES";
    inner_w.write_all(response).await.expect("write");
    inner_w.shutdown().await.expect("shutdown");
    drop(inner_w);

    let out = injector_read_all(&mut injector).await;
    let expected = b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nX-Injected: yes\r\n\r\n\x81\xfeRAW-UPGRADE-BYTES";
    assert_eq!(
        &out[..],
        expected,
        "101 must be injected, upgrade bytes must pass verbatim"
    );
}

/// Round-13 (F1#2) + round-14 review: 100 head then backend EOF with
/// no final head ever arriving — the raw 100 passes through, then the
/// stream errors. Go readResponse consumes the interim and errors on
/// the EOF-before-final-head; the vhost ErrorHandler answers 404, and
/// frp-core maps this UnexpectedEof to that 404 (a 100 already on the
/// wire is a legal interim prefix to a late final head).
#[tokio::test]
async fn injector_100_only_then_eof_errors_after_interim() {
    use tokio::io::AsyncWriteExt;
    let (mut inner_w, inner_r) = tokio::io::duplex(64 * 1024);
    let mut headers = std::collections::HashMap::new();
    headers.insert("X-Injected".to_string(), String::from("yes"));
    let mut injector = ResponseHeaderInjector::new(inner_r, headers, None);

    inner_w
        .write_all(b"HTTP/1.1 100 Continue\r\n\r\n")
        .await
        .expect("write 100");
    inner_w.shutdown().await.expect("shutdown");
    drop(inner_w);

    let mut buf = [0u8; 4096];
    let n = injector.read(&mut buf).await.expect("interim read");
    assert_eq!(&buf[..n], b"HTTP/1.1 100 Continue\r\n\r\n");
    let err = injector
        .read(&mut buf)
        .await
        .expect_err("EOF before the final head must error, not end cleanly");
    assert_eq!(err.kind(), std::io::ErrorKind::UnexpectedEof);
}

/// Round-13 review (3 independent reviewers): a head whose first line
/// does not parse as `HTTP/x.y <3-digit-code>` is malformed — Go errors
/// the whole response and the reverse proxy answers 502, ModifyResponse
/// never runs. The injector must serve such heads raw and NEVER
/// manufacture configured headers into them. Pins the strict status
/// line: tab separator, unparseable version token, and a 4-digit code
/// are all malformed (space-TrimLeft is spaces-only, "0200" rejected
/// before Atoi), while extra SPACES stay legal and DO inject.
#[tokio::test]
async fn injector_malformed_first_line_served_raw_never_injected() {
    use tokio::io::AsyncWriteExt;
    let headers = || {
        let mut h = std::collections::HashMap::new();
        h.insert("X-Injected".to_string(), String::from("yes"));
        h
    };
    for (name, head) in [
        ("tab separator", &b"HTTP/1.1\t100 Continue\r\n\r\n"[..]),
        ("bad version token", &b"HTTP/1.x 200 OK\r\n\r\n"[..]),
        ("4-digit code", &b"HTTP/1.1 0200 OK\r\n\r\n"[..]),
        ("no code", &b"HTTP/1.1 \r\n\r\n"[..]),
    ] {
        let (mut inner_w, inner_r) = tokio::io::duplex(64 * 1024);
        let mut injector = ResponseHeaderInjector::new(inner_r, headers(), None);
        inner_w.write_all(head).await.expect("write head");
        inner_w.shutdown().await.expect("shutdown");
        drop(inner_w);
        // The malformed head (blank line included) is served raw in one
        // read; the EOF after it ends the stream CLEANLY — the relayed
        // malformed unit IS the response (round-13: served uninjected
        // for the browser's own parser to reject), so a following EOF
        // must not signal a "missing final head" 404 on top of it.
        let out = injector_read_all(&mut injector).await;
        assert_eq!(
            &out[..],
            head,
            "[{name}] malformed first line must pass through byte-exact, uninjected"
        );
    }
    // Extra spaces between version and code are legal (Go TrimLeft): the
    // head IS final (200) and MUST be injected.
    let (mut inner_w, inner_r) = tokio::io::duplex(64 * 1024);
    let mut injector = ResponseHeaderInjector::new(inner_r, headers(), None);
    inner_w
        .write_all(b"HTTP/1.1   200 OK\r\nContent-Type: text/plain\r\n\r\nhello")
        .await
        .expect("write 200");
    inner_w.shutdown().await.expect("shutdown");
    drop(inner_w);
    let out = injector_read_all(&mut injector).await;
    let s = String::from_utf8_lossy(&out);
    assert!(
        s.contains("X-Injected: yes"),
        "multi-space first line is a valid final head and must inject, got: {s:?}"
    );
    assert!(s.ends_with("hello"), "body must survive, got: {s:?}");
}

/// Round-16 gap-fill pin: a MALFORMED head followed IN THE SAME
/// BACKEND SEGMENT by a valid-looking `HTTP/1.1 200 OK` head must
/// serve exactly ONE response — the garbage, raw and byte-exact — and
/// drop the pipelined valid head (never injected, never relayed), then
/// go permanent EOF. Round-15's terminal-drain fix (malformed_raw
/// drain: tail cleared, `complete` set, subsequent polls Ready(0))
/// already covers this shape; the sibling test above pins only the
/// malformed-head-then-EOF arm, so this pin closes the same-segment
/// coverage gap. Without the round-15 drain the gather loop resumed on
/// the split-off tail and the 200 head was INJECTED and served as a
/// second spliced response on one user connection (double-response,
/// smuggling-adjacent shape).
#[tokio::test]
async fn injector_malformed_then_pipelined_valid_head_same_segment_single_raw_serve() {
    use tokio::io::AsyncWriteExt;
    let (mut inner_w, inner_r) = tokio::io::duplex(64 * 1024);
    let mut headers = std::collections::HashMap::new();
    headers.insert("X-Injected".to_string(), String::from("yes"));
    let mut injector = ResponseHeaderInjector::new(inner_r, headers, None);

    // One write, one segment: malformed first line (bad version token →
    // status None → raw-served, malformed_raw) immediately followed by
    // a valid-looking final head + body.
    let segment = b"HTTP/1.x 200 OOPS\r\nServer: bogus\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
    inner_w.write_all(segment).await.expect("write");
    inner_w.shutdown().await.expect("shutdown");
    drop(inner_w);

    let out = injector_read_all(&mut injector).await;
    assert_eq!(
        &out[..],
        &b"HTTP/1.x 200 OOPS\r\nServer: bogus\r\n\r\n"[..],
        "only the malformed head may be served — the pipelined valid head must be \
             dropped with the tail (double-response regression)"
    );
    // Permanent EOF after the single raw serve: the drain discarded the
    // tail and the complete+malformed_raw arm never polls the backend
    // again (a follow-up read must not surface the 200 head).
    let mut probe = [0u8; 8];
    assert_eq!(
        injector.read(&mut probe).await.expect("read after drain"),
        0,
        "stream must be permanently at EOF after the malformed raw serve"
    );
}

/// Round-16/18: Go's net/http write layer suppresses Content-Length on
/// no-body statuses at user-facing serialization (chunkWriter.writeHeader
/// delHeader sweep, go1.25 server.go:1483-1497; suppressedHeadersNoBody =
/// {Content-Length, Transfer-Encoding} for 204, transfer.go:459-485) —
/// every response through Go frp's h1 http vhost loses its CL. The
/// injector owns every http non-CONNECT leg, EMPTY headers map included
/// (the deadline-only pass-through), so the strip must run there too: a
/// 204 with `Content-Length: 16` goes out without CL — AND (round-18
/// C3b) the declared body a lying backend wrote after the head is
/// withheld, never relayed: the backend DECLARED 16 bytes, exactly 16
/// junk bytes are consumed from the in-hand tail (Go's per-framing
/// abandon: chunked-on-204 and CL:0/absent → Body = NoBody, nothing
/// read and the pooled conn discarded with the junk buffered
/// (transfer.go:570-574); CL: N > 0 → LimitReader reads exactly N —
/// this test's shape). frp-rs's head is already out, so the discard
/// keeps the shared stream clean instead. Byte-exact pin: the
/// stripped head only — junk withheld.
/// `injector_read_all`'s 7-byte caller chunks push the emission-drain
/// discard handoff across many polls.
#[tokio::test]
async fn injector_204_strips_content_length_empty_map_deadline_only_leg() {
    use tokio::io::AsyncWriteExt;
    let (mut inner_w, inner_r) = tokio::io::duplex(64 * 1024);
    // NO configured response_headers: this is the pure deadline-only
    // pass-through leg — the 204/304 strip must still run.
    let mut injector =
        ResponseHeaderInjector::<tokio::io::DuplexStream>::new(inner_r, Default::default(), None);

    inner_w
        .write_all(
            b"HTTP/1.1 204 No Content\r\nContent-Length: 16\r\nX-Keep: yes\r\n\r\n0123456789abcdef",
        )
        .await
        .expect("write");
    inner_w.shutdown().await.expect("shutdown");
    drop(inner_w);

    let out = injector_read_all(&mut injector).await;
    assert_eq!(
        &out[..],
        &b"HTTP/1.1 204 No Content\r\nX-Keep: yes\r\n\r\n"[..],
        "204 head must lose its Content-Length line and the 16 DECLARED junk bytes \
             must be withheld (kept header and blank line verbatim)"
    );
}

/// Round-16/18: a 304 loses Content-Length AND Content-Type — Go's
/// suppressedHeaders304 = {Content-Type, Content-Length,
/// Transfer-Encoding} (transfer.go:480-486) suppresses the configured
/// X-Injected emission the same way it suppresses backend lines, since
/// ModifyResponse's Header.Set runs before the chunkWriter delHeader
/// sweep (server.go:1483-1497) — and (round-18 C3b) the 16 declared
/// junk bytes after the head are withheld like the 204's. Byte-exact
/// pin.
#[tokio::test]
async fn injector_304_strips_content_type_and_content_length_withholds_declared_body() {
    use tokio::io::AsyncWriteExt;
    let (mut inner_w, inner_r) = tokio::io::duplex(64 * 1024);
    let mut headers = std::collections::HashMap::new();
    headers.insert("X-Injected".to_string(), String::from("yes"));
    let mut injector = ResponseHeaderInjector::new(inner_r, headers, None);

    inner_w
        .write_all(
            b"HTTP/1.1 304 Not Modified\r\nContent-Length: 16\r\nContent-Type: text/plain\r\nETag: \"v1\"\r\n\r\n0123456789abcdef",
        )
        .await
        .expect("write");
    inner_w.shutdown().await.expect("shutdown");
    drop(inner_w);

    let out = injector_read_all(&mut injector).await;
    assert_eq!(
        &out[..],
        &b"HTTP/1.1 304 Not Modified\r\nETag: \"v1\"\r\nX-Injected: yes\r\n\r\n"[..],
        "304 head must lose Content-Length and Content-Type; the 16 declared junk \
             bytes must be withheld; kept headers and the configured emission survive"
    );
}

/// Round-18 C3b regression: a lying backend writes its declared
/// 204-body junk AND a pipelined next response in one segment. The
/// user must see exactly the stripped 204 head followed by the next
/// response — the 16 declared junk bytes land in no buffer the user
/// ever reads, and the shared stream resumes at the pipelined head.
#[tokio::test]
async fn injector_204_junk_withheld_next_response_parses_clean() {
    use tokio::io::AsyncWriteExt;
    let (mut inner_w, inner_r) = tokio::io::duplex(64 * 1024);
    let mut injector =
        ResponseHeaderInjector::<tokio::io::DuplexStream>::new(inner_r, Default::default(), None);

    inner_w
        .write_all(
            b"HTTP/1.1 204 No Content\r\nContent-Length: 16\r\n\r\n0123456789abcdef\
                  HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\ndone",
        )
        .await
        .expect("write");
    inner_w.shutdown().await.expect("shutdown");
    drop(inner_w);

    let out = injector_read_all(&mut injector).await;
    assert_eq!(
        &out[..],
        &b"HTTP/1.1 204 No Content\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\ndone"[..],
        "declared 204 junk must be consumed silently; the pipelined next response \
             must follow the stripped head byte-exact"
    );
}

/// Round-18 C3b: the chunked variant — a 204 head declaring
/// `Transfer-Encoding: chunked`, with the chunked junk (`10`-byte
/// chunk, footer, 0-chunk, blank trailer terminator) and a pipelined
/// next response written after it. The chunk grammar is consumed
/// (machine mirror of Go internal/chunked.go acceptance); the user
/// sees the stripped head and the next response raw.
#[tokio::test]
async fn injector_204_chunked_junk_withheld_next_response_raw() {
    use tokio::io::AsyncWriteExt;
    let (mut inner_w, inner_r) = tokio::io::duplex(64 * 1024);
    let mut injector =
        ResponseHeaderInjector::<tokio::io::DuplexStream>::new(inner_r, Default::default(), None);

    inner_w
        .write_all(
            b"HTTP/1.1 204 No Content\r\nTransfer-Encoding: chunked\r\n\r\n\
                  10\r\n0123456789abcdef\r\n0\r\n\r\n\
                  HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\ndone",
        )
        .await
        .expect("write");
    inner_w.shutdown().await.expect("shutdown");
    drop(inner_w);

    let out = injector_read_all(&mut injector).await;
    assert_eq!(
        &out[..],
        &b"HTTP/1.1 204 No Content\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\ndone"[..],
        "chunked 204 junk must be consumed silently (chunked framing stripped from the \
             head), the pipelined next response follows raw"
    );
}

/// Round-18 C3b: the backend declared `Content-Length: 16` but only 8
/// junk bytes were in hand before the stream ended — the discard eats
/// the 8 in-hand junk bytes, hits the spent-in-hand state, and ends
/// cleanly at the stripped head (no junk relayed, no second gateway
/// head, no deadline park, no WARN — nothing after the in-hand bytes
/// is ever read or classified; Go's Transport, reading exactly N on a
/// declared CL, would sit on the short read until the conn closes).
#[tokio::test]
async fn injector_204_truncated_declared_body_ends_stream() {
    use tokio::io::AsyncWriteExt;
    let (mut inner_w, inner_r) = tokio::io::duplex(64 * 1024);
    let mut injector =
        ResponseHeaderInjector::<tokio::io::DuplexStream>::new(inner_r, Default::default(), None);

    inner_w
        .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 16\r\n\r\n01234567")
        .await
        .expect("write");
    inner_w.shutdown().await.expect("shutdown");
    drop(inner_w);

    let out = injector_read_all(&mut injector).await;
    assert_eq!(
        &out[..],
        &b"HTTP/1.1 204 No Content\r\n\r\n"[..],
        "truncated declared junk must end the stream cleanly at the stripped head"
    );
}

/// R2 (independent PR review) pin: a LEGAL 304 whose Content-Length
/// declared the would-be-200 entity length (RFC 9110 §15.4.5 — the
/// backend never sends the body) must not arm a wire-reading discard.
/// Pre-fix the Length arm parked the bridge until the A2 deadline
/// fired (false WARN, a long stall on legal keep-alive traffic) and,
/// when a second response arrived on the keep-alive connection, ate
/// the first 16 bytes of ITS head as phantom "junk". The discard is
/// in-hand only: the stripped head is served, the stream completes
/// instantly, and a response written later arrives byte-exact. A
/// 200 ms response-head deadline is armed to prove no poll waits on
/// it — every read here completes immediately, so a stall would fail
/// the test outright.
#[tokio::test]
async fn injector_304_legal_content_length_junk_absent_no_eat_no_stall() {
    use tokio::io::AsyncReadExt;
    use tokio::io::AsyncWriteExt;
    let (mut inner_w, inner_r) = tokio::io::duplex(64 * 1024);
    let mut injector = ResponseHeaderInjector::<tokio::io::DuplexStream>::new(
        inner_r,
        Default::default(),
        Some(std::time::Duration::from_millis(200)),
    );

    inner_w
        .write_all(b"HTTP/1.1 304 Not Modified\r\nContent-Length: 16\r\nETag: \"v1\"\r\n\r\n")
        .await
        .expect("write 304 head");

    let mut head = [0u8; 256];
    let n = injector.read(&mut head).await.expect("read 304 head");
    assert_eq!(
        &head[..n],
        &b"HTTP/1.1 304 Not Modified\r\nETag: \"v1\"\r\n\r\n"[..],
        "the 304 head must be served promptly, stripped of Content-Length — never \
             parked on a phantom 16-byte junk body"
    );

    // The keep-alive backend later answers the connection's next
    // request. Its bytes must not be consumed as the 304's phantom
    // body: pre-fix the Length discard ate the first 16 bytes of this
    // very head (or stalled to the deadline first and aborted).
    let next = b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\ndone";
    inner_w.write_all(next).await.expect("write next response");
    inner_w.shutdown().await.expect("shutdown");
    drop(inner_w);

    let mut rest = Vec::new();
    tokio::io::AsyncReadExt::read_to_end(&mut injector, &mut rest)
        .await
        .expect("read next response");
    assert_eq!(
        &rest[..],
        &next[..],
        "the keep-alive next response must arrive byte-exact — the discard must not \
             eat its first bytes and must not stall on the response-head deadline"
    );
}

/// Round-18 M1 regression (RED on the pre-fix flag gate): the drain
/// of the FINAL chunk of an injected head must return
/// `Poll::Ready` even when the C3b discard handoff leaves the
/// discard armed. Pre-fix, that drain fell through into the discard
/// section on the SAME poll; a LEGAL 304 (declared Content-Length,
/// zero in-hand junk) instant-completed there and polled the inner
/// reader, which returned Pending for the keep-alive backend
/// (response 2 not yet staged). poll_read thus returned Pending with
/// the caller's ReadBuf already filled — tokio's `Read` future
/// builds a FRESH ReadBuf per poll, so the drain's final chunk was
/// silently dropped from the user-facing wire (any injected 204/304
/// head larger than the caller buffer loses its tail: > 32 KiB
/// emissions under frp-core's 32 KiB PoolGuard). Drive poll_read
/// with a 1 KiB caller buffer over a ~2.5 KiB injected 304 emission:
/// the full head must arrive byte-exact across the polls, then a
/// staged keep-alive response 2 byte-exact.
#[tokio::test]
async fn injector_flag_gate_final_drain_never_parks_with_a_filled_buf() {
    use tokio::io::AsyncWriteExt;
    let (mut inner_w, inner_r) = tokio::io::duplex(64 * 1024);
    let mut headers = std::collections::HashMap::new();
    for i in 0..8 {
        headers.insert(format!("X-Big-{i}"), "v".repeat(300));
    }
    let mut injector = ResponseHeaderInjector::new(inner_r, headers, None);

    // A LEGAL 304: `Content-Length: 16` declares the would-be-200
    // entity length (RFC 9110 §15.4.5) and the backend sends no body —
    // zero in-hand junk behind the head. The declaration still arms
    // the discard; with no in-hand junk it instant-completes once the
    // emission is out.
    inner_w
        .write_all(b"HTTP/1.1 304 Not Modified\r\nContent-Length: 16\r\n\r\n")
        .await
        .expect("write 304 head");

    // Expected emission: the status line (the backend Content-Length
    // is stripped), the configured headers in sorted order, the blank
    // line — over two 1 KiB caller buffers, so the drain spans polls.
    let value = "v".repeat(300);
    let mut expected: Vec<u8> = Vec::new();
    expected.extend_from_slice(b"HTTP/1.1 304 Not Modified\r\n");
    for i in 0..8 {
        expected.extend_from_slice(format!("X-Big-{i}: {value}\r\n").as_bytes());
    }
    expected.extend_from_slice(b"\r\n");
    assert!(
        expected.len() > 2 * 1024,
        "emission must exceed two 1 KiB caller buffers so the drain spans polls \
             (got {} bytes)",
        expected.len()
    );

    let mut got: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 1024];
    let mut parked = false;
    while got.len() < expected.len() {
        match injector_poll_read_small(&mut injector, &mut chunk).await {
            Ok(0) => panic!("clean EOF while the injected 304 head was still draining"),
            Ok(n) => got.extend_from_slice(&chunk[..n]),
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => {
                parked = true;
                break;
            }
            Err(e) => panic!("injector read failed: {e}"),
        }
    }
    if !parked {
        // The emission was fully served; the discard runs on the poll
        // AFTER the final drain (M1 — the drain's own poll must
        // return Ready). That poll instant-completes the legal 304
        // (nothing in-hand to serve) and parks on the inner reader
        // with a fresh 1 KiB caller buffer: the correct,
        // waker-registered park.
        match injector_poll_read_small(&mut injector, &mut chunk).await {
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => parked = true,
            Ok(0) => panic!("clean EOF where the discard's keep-alive park was expected"),
            Ok(n) => panic!(
                "expected the post-drain discard poll to park on the inner reader, \
                     it served {n} bytes (response 2 is not staged yet)"
            ),
            Err(e) => panic!("injector read failed: {e}"),
        }
    }
    assert!(
        parked,
        "the injector must end phase 1 parked on the keep-alive inner read"
    );
    assert_eq!(
        &got[..],
        &expected[..],
        "the full injected 304 head must cross the 1 KiB reads byte-exact — the \
             final-drain poll must never lose its bytes to a Pending return (M1)"
    );

    // The keep-alive backend answers the connection's next request.
    // Its bytes must pass through raw behind the stripped 304 head.
    let next = b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\ndone";
    inner_w.write_all(next).await.expect("write next response");
    inner_w.shutdown().await.expect("shutdown");
    drop(inner_w);

    let mut rest = Vec::new();
    loop {
        match injector_poll_read_small(&mut injector, &mut chunk).await {
            Ok(0) => break,
            Ok(n) => rest.extend_from_slice(&chunk[..n]),
            Err(e) => panic!("keep-alive response 2 read failed: {e}"),
        }
    }
    assert_eq!(
        &rest[..],
        &next[..],
        "response 2 must arrive byte-exact after the stripped 304 head"
    );
}

/// G1 pin (round-18 C3b abort arm, first coverage): a lying backend
/// declares `Transfer-Encoding: chunked` on a 204 and writes a
/// MALFORMED chunk line (`ZZ` is not hex — Go parseHexUint rejects,
/// internal/chunked.go:278-298) in the same in-hand segment as the
/// head. The chunked discard feed errors, so the stream ends with
/// PERMANENT clean EOF (`abort_after_discard_failure`): the user saw
/// exactly the stripped 204 head, no junk is relayed, no second
/// gateway head can follow, and the EOF comes from the injector's
/// terminal state — never from the inner reader — so bytes staged
/// later (inner writer kept alive) are never served. (The abort WARN
/// is rate-limited to one line per 5 s across all bridges.) RED on
/// any code that relays the garbage, parks on it, or answers a
/// second head.
#[tokio::test]
async fn injector_204_chunked_malformed_junk_ends_stream_permanently() {
    use tokio::io::AsyncWriteExt;
    let (mut inner_w, inner_r) = tokio::io::duplex(64 * 1024);
    let mut injector =
        ResponseHeaderInjector::<tokio::io::DuplexStream>::new(inner_r, Default::default(), None);

    // Head + malformed junk in ONE segment: the junk is the discard
    // input the moment the head boundary is found.
    inner_w
        .write_all(b"HTTP/1.1 204 No Content\r\nTransfer-Encoding: chunked\r\n\r\nZZ\r\n")
        .await
        .expect("write head + malformed junk");
    // Garbage staged AFTER the abort point; the writer stays alive so
    // a clean EOF can only come from the injector's terminal state,
    // not from duplex EOF.
    inner_w
        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nHELLO")
        .await
        .expect("write later garbage");

    // Poll-level oracle: the terminal state must be a CLEAN EOF
    // (`Ok(0)`) — no Err, and no park. `injector_read_all` would hide
    // both (it `expect`s on Err and would hang on a park until the
    // outer timeout). Each poll is internally 1 s-bounded and reports
    // a park as `Err(TimedOut)`.
    let mut out: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 1024];
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    let mut ended_clean = false;
    while std::time::Instant::now() < deadline {
        match injector_poll_read_small(&mut injector, &mut chunk).await {
            Ok(0) => {
                ended_clean = true;
                break;
            }
            Ok(n) => out.extend_from_slice(&chunk[..n]),
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => {
                panic!("abort must end the stream promptly, it parked instead")
            }
            Err(e) => panic!("the abort must end the stream with a clean EOF, got {e}"),
        }
    }
    assert!(
        ended_clean,
        "the injector's terminal state must serve a clean Ok(0) EOF"
    );
    assert_eq!(
        &out[..],
        &b"HTTP/1.1 204 No Content\r\n\r\n"[..],
        "the stripped 204 head is the whole response — malformed chunked junk must \
             never be relayed and no second head may follow"
    );
}

/// Round-18 4c pin: an EOF before the head terminator is ALWAYS
/// fail-closed. `malformed_raw` is normally unreachable at that arm
/// (both raise sites set `complete` first), so the guard's state is
/// driven directly here: a flag-set stream whose backend closes with
/// no head must surface `Err(UnexpectedEof)`, which frp-core answers
/// with Go's vhost ErrorHandler 404 page
/// (frp-core/src/bridge.rs:506-532) — never a clean end-of-stream.
/// The pre-fix guard returned `Ok(())` (fail-open), so this is RED on
/// that code.
#[tokio::test]
async fn injector_malformed_raw_eof_before_head_stays_fail_closed() {
    let (inner_w, inner_r) = tokio::io::duplex(64 * 1024);
    let mut injector =
        ResponseHeaderInjector::<tokio::io::DuplexStream>::new(inner_r, Default::default(), None);
    injector.malformed_raw = true;
    drop(inner_w);

    let mut chunk = [0u8; 1024];
    match injector_poll_read_small(&mut injector, &mut chunk).await {
        Err(e) => assert_eq!(
            e.kind(),
            std::io::ErrorKind::UnexpectedEof,
            "an unterminated head must surface UnexpectedEof (Go readResponse \
                 error -> vhost ErrorHandler 404), got {e}"
        ),
        Ok(n) => panic!(
            "an EOF before the head terminator must never read as a clean \
                 end-of-stream (served {n} bytes)"
        ),
    }
}

/// G2 pin (round-18): the 304 suppressed-headers table {Content-Type,
/// Content-Length, Transfer-Encoding} filters the CONFIGURED emission
/// too. The backend-side 304 strip is pinned by
/// `injector_304_strips_content_type_and_content_length_withholds_declared_body`;
/// this is the separate config-emission site — Go's ModifyResponse
/// `Header.Set` runs BEFORE chunkWriter.writeHeader's delHeader sweep
/// (server.go:1483-1497), so a configured suppressed name never
/// reaches the wire either.
#[tokio::test]
async fn injector_304_suppresses_configured_content_type_and_length() {
    use tokio::io::AsyncWriteExt;
    let (mut inner_w, inner_r) = tokio::io::duplex(64 * 1024);
    let mut headers = std::collections::HashMap::new();
    headers.insert(
        "Content-Type".to_string(),
        String::from("text/x-configured"),
    );
    headers.insert("Content-Length".to_string(), String::from("77"));
    headers.insert("X-Injected".to_string(), String::from("yes"));
    let mut injector = ResponseHeaderInjector::new(inner_r, headers, None);

    // No body framing on the wire, so no discard is armed — the strip
    // sites under test are purely the emission filters.
    inner_w
        .write_all(b"HTTP/1.1 304 Not Modified\r\nETag: \"v1\"\r\n\r\n")
        .await
        .expect("write");
    inner_w.shutdown().await.expect("shutdown");
    drop(inner_w);

    let out = injector_read_all(&mut injector).await;
    assert_eq!(
        &out[..],
        &b"HTTP/1.1 304 Not Modified\r\nETag: \"v1\"\r\nX-Injected: yes\r\n\r\n"[..],
        "configured Content-Type and Content-Length must be suppressed on a 304 like \
             backend lines; other configured headers still inject"
    );
}

/// G3 pin (round-18): a 204 with NO declared body framing (no
/// Content-Length, no Transfer-Encoding) followed in the SAME
/// in-hand segment by a pipelined next response. Go's Transport
/// answers Body = NoBody on a no-framing 204 — nothing is read
/// (transfer.go:565-578) and the pooled connection continues — so
/// the bytes behind the head are the next response, never junk, and
/// must reach the user raw behind the stripped head. The
/// DeclaredFraming::None arm attaches the in-hand tail to the
/// emission verbatim (no body parser runs on a no-body status in Go
/// either). Byte-exact pin — eating or withholding the pipelined
/// tail is RED.
#[tokio::test]
async fn injector_204_no_framing_pipelined_next_response_passes_raw() {
    use tokio::io::AsyncWriteExt;
    let (mut inner_w, inner_r) = tokio::io::duplex(64 * 1024);
    let mut injector =
        ResponseHeaderInjector::<tokio::io::DuplexStream>::new(inner_r, Default::default(), None);

    inner_w
        .write_all(
            b"HTTP/1.1 204 No Content\r\nX-Keep: yes\r\n\r\n\
                  HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\ndone",
        )
        .await
        .expect("write");
    inner_w.shutdown().await.expect("shutdown");
    drop(inner_w);

    let out = injector_read_all(&mut injector).await;
    assert_eq!(
        &out[..],
        &b"HTTP/1.1 204 No Content\r\nX-Keep: yes\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\ndone"[..],
        "a no-framing 204's in-hand tail is the pipelined next response — relayed \
             raw behind the stripped head, byte-exact"
    );
}

/// Round-18 C2c: a head delivered in a 1-byte drip — every inner read
/// appends one byte and the gather loop re-runs the boundary hunt —
/// must still be injected whole. Pre-fix the hunt rescanned the full
/// accumulated buffer per drip (O(n²)); the carried HeadEndScanner
/// resumes where the last feed stopped. Functional pin (the C1
/// textproto unit test pins the amortized cost).
#[tokio::test]
async fn injector_one_byte_drip_head_is_injected() {
    use tokio::io::AsyncWriteExt;
    let (mut inner_w, inner_r) = tokio::io::duplex(64 * 1024);
    let mut headers = std::collections::HashMap::new();
    headers.insert("X-Injected".to_string(), String::from("yes"));
    let mut injector = ResponseHeaderInjector::new(inner_r, headers, None);

    let head = b"HTTP/1.1 200 OK\r\nSet-Cookie: a=0123456789abcdef;\r\n\r\nbody";
    for &b in head {
        inner_w.write_all(&[b]).await.expect("drip write");
    }
    inner_w.shutdown().await.expect("shutdown");
    drop(inner_w);

    let out = injector_read_all(&mut injector).await;
    assert_eq!(
        &out[..],
        &b"HTTP/1.1 200 OK\r\nSet-Cookie: a=0123456789abcdef;\r\nX-Injected: yes\r\n\r\nbody"[..],
        "drip-fed head must be found at its blank line and injected (body verbatim)"
    );
}

/// Round-16: a body-bearing final status (200) is untouched — its
/// Content-Length survives byte-exact, statuses Go's write layer does
/// not suppress.
#[tokio::test]
async fn injector_200_keeps_content_length() {
    use tokio::io::AsyncWriteExt;
    let (mut inner_w, inner_r) = tokio::io::duplex(64 * 1024);
    let mut injector =
        ResponseHeaderInjector::<tokio::io::DuplexStream>::new(inner_r, Default::default(), None);

    inner_w
        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello")
        .await
        .expect("write");
    inner_w.shutdown().await.expect("shutdown");
    drop(inner_w);

    let out = injector_read_all(&mut injector).await;
    assert_eq!(
        &out[..],
        &b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"[..],
        "200 head must keep its Content-Length verbatim"
    );
}

/// Round-16: the suppression hits a CONFIGURED Content-Length too — Go's
/// ModifyResponse Header.Set runs BEFORE chunkWriter.writeHeader's
/// delHeader sweep, so a response_headers entry naming content-length is
/// suppressed on a 204 exactly like a backend line, while other
/// configured headers still inject.
#[tokio::test]
async fn injector_204_suppresses_configured_content_length_too() {
    use tokio::io::AsyncWriteExt;
    let (mut inner_w, inner_r) = tokio::io::duplex(64 * 1024);
    let mut headers = std::collections::HashMap::new();
    headers.insert("Content-Length".to_string(), String::from("99"));
    headers.insert("X-Injected".to_string(), String::from("yes"));
    let mut injector = ResponseHeaderInjector::new(inner_r, headers, None);

    inner_w
        .write_all(b"HTTP/1.1 204 No Content\r\nServer: b\r\n\r\n")
        .await
        .expect("write");
    inner_w.shutdown().await.expect("shutdown");
    drop(inner_w);

    let out = injector_read_all(&mut injector).await;
    assert_eq!(
        &out[..],
        &b"HTTP/1.1 204 No Content\r\nServer: b\r\nX-Injected: yes\r\n\r\n"[..],
        "configured Content-Length must be suppressed on a 204 like a backend line"
    );
}

// A4 (round-13 review): the version token must be exactly `HTTP/X.Y`
// single-digit — Go ParseHTTPVersion length-checks to 8 bytes and
// parses single bytes (request.go:819-838).
#[test]
fn head_status_go_version_token_matrix() {
    let v = ResponseHeaderInjector::<tokio::io::DuplexStream>::is_http_version;
    for ok in [
        "HTTP/1.1", "HTTP/1.0", "HTTP/0.9", "HTTP/1.9", "HTTP/2.0", "HTTP/9.9",
    ] {
        assert!(v(ok.as_bytes()), "{ok} must parse (Go ParseHTTPVersion)");
    }
    for bad in [
        "HTTP/1.10",
        "HTTP/01.1",
        "HTTP/10.0",
        "HTTP/1.x",
        "HTTP/x.1",
        "HTTP/1",
        "HTTP/1.",
        "HTTP//1.1",
        "HTTP/1.1 ",
        "1.1",
        "FOO",
    ] {
        assert!(!v(bad.as_bytes()), "{bad} must NOT parse");
    }
}

// A7 (round-13 review): the code token is 3 BYTES with Go strconv.Atoi
// semantics — a leading sign is legal ("+20" → 20, "-00" → 0) and only
// a parse error or negative VALUE rejects ("-01") — and there is no
// 100..=199 membership check here (response.go:173-186).
#[test]
fn head_status_go_code_atoi_matrix() {
    let code =
        |head: &[u8]| ResponseHeaderInjector::<tokio::io::DuplexStream>::head_status_code(head);
    let ok = [
        (&b"HTTP/1.1 200 OK\r\n\r\n"[..], 200u16),
        (&b"HTTP/1.1 +20 Weird\r\n\r\n"[..], 20u16),
        (&b"HTTP/1.1 -00 Weird\r\n\r\n"[..], 0u16),
        (&b"HTTP/1.1 000 Weird\r\n\r\n"[..], 0u16),
        (&b"HTTP/1.1 099 X\r\n\r\n"[..], 99u16),
        (&b"HTTP/1.1 599 X\r\n\r\n"[..], 599u16),
        (&b"HTTP/1.1 600 X\r\n\r\n"[..], 600u16),
        (&b"HTTP/1.1 999 X\r\n\r\n"[..], 999u16),
        (&b"HTTP/1.1 100 Continue\r\n\r\n"[..], 100u16),
        (&b"HTTP/1.0 101 Switching Protocols\r\n\r\n"[..], 101u16),
    ];
    for (head, want) in ok {
        assert_eq!(
            code(head),
            Some(want),
            "head: {}",
            String::from_utf8_lossy(head)
        );
    }
    let bad: &[&[u8]] = &[
        b"HTTP/1.1 -01 X\r\n\r\n",   // Atoi(-1) < 0 → malformed
        b"HTTP/1.1 +2a X\r\n\r\n",   // Atoi error
        b"HTTP/1.1 20a X\r\n\r\n",   // Atoi error
        b"HTTP/1.1 0200 X\r\n\r\n",  // 4-byte token
        b"HTTP/1.1 20 X\r\n\r\n",    // 2-byte token
        b"HTTP/1.1 + X\r\n\r\n",     // sign with no digits
        b"HTTP/1.10 200 OK\r\n\r\n", // A4: multi-digit minor
        b"HTTP/01.1 200 OK\r\n\r\n", // A4: multi-digit major
        b"FOO 200 OK\r\n\r\n",       // no HTTP/ prefix
    ];
    for head in bad {
        assert_eq!(code(head), None, "head: {}", String::from_utf8_lossy(head));
    }
}

/// Round-16 (false-Go-citation fix): the http-leg response-head
/// deadline takes the shared vhost clamp — a `<= 0` `vhost_http_timeout`
/// FLOORS to 60s, exactly like Go frp v0.71.0's NewHTTPReverseProxy
/// (pkg/util/vhost/http.go:50-51: `if option.ResponseHeaderTimeoutS <= 0
/// { option.ResponseHeaderTimeoutS = 60 }`), and everything caps at 24h
/// (Rust-only hardening; Go has no cap). The old `> 0` gate armed NO
/// deadline for a 0/unset config — a false "0 disables the timeout"
/// citation: in Go an unset VhostHTTPTimeout (config default 60) and an
/// explicit 0 both arm the same 60s deadline.
#[test]
fn http_leg_head_deadline_floors_zero_and_caps() {
    assert_eq!(http_leg_head_deadline(0), 60, "0 must floor to Go's 60s");
    assert_eq!(http_leg_head_deadline(1), 1);
    assert_eq!(http_leg_head_deadline(59), 59);
    assert_eq!(http_leg_head_deadline(60), 60);
    assert_eq!(http_leg_head_deadline(61), 61);
    let cap: i64 = 24 * 60 * 60;
    assert_eq!(http_leg_head_deadline(cap), cap as u64);
    assert_eq!(
        http_leg_head_deadline(cap + 1),
        cap as u64,
        "positive values cap at 24h"
    );
    assert_eq!(
        http_leg_head_deadline(-1),
        60,
        "a negative signed config value floors like Go"
    );
    assert_eq!(
        http_leg_head_deadline(i64::MAX),
        cap as u64,
        "hostile huge config must not overflow Instant arithmetic"
    );
}

// A7 end-to-end shape: a "+20"-coded head is FINAL (not interim) in Go
// — modifyResponse runs and the injector must inject.
#[tokio::test]
async fn injector_signed_code_heads_are_final_and_injected() {
    use tokio::io::AsyncWriteExt;
    let headers = || {
        let mut h = std::collections::HashMap::new();
        h.insert("X-Injected".to_string(), String::from("yes"));
        h
    };
    for head in [
        &b"HTTP/1.1 +20 Whimsy\r\n\r\nok"[..],
        &b"HTTP/1.1 -00 Whimsy\r\n\r\nok"[..],
    ] {
        let (mut inner_w, inner_r) = tokio::io::duplex(64 * 1024);
        let mut injector = ResponseHeaderInjector::new(inner_r, headers(), None);
        inner_w.write_all(head).await.expect("write head");
        inner_w.shutdown().await.expect("shutdown");
        drop(inner_w);
        let out = injector_read_all(&mut injector).await;
        let s = String::from_utf8_lossy(&out);
        assert!(
            s.contains("X-Injected: yes"),
            "signed code is a legal final head and must inject, got: {s:?}"
        );
        assert!(s.ends_with("ok"), "body must survive, got: {s:?}");
    }
    // The multi-digit version head, by contrast, is malformed in Go —
    // served raw, byte-exact, uninjected.
    let (mut inner_w, inner_r) = tokio::io::duplex(64 * 1024);
    let mut injector = ResponseHeaderInjector::new(inner_r, headers(), None);
    let raw = b"HTTP/1.10 200 OK\r\n\r\n";
    inner_w.write_all(raw).await.expect("write head");
    inner_w.shutdown().await.expect("shutdown");
    drop(inner_w);
    let out = injector_read_all(&mut injector).await;
    assert_eq!(&out[..], raw, "HTTP/1.10 must pass through raw, uninjected");
}

// A2 (round-13 review): the response-head deadline is ONE absolute
// deadline — an interim 1xx raw serve does NOT extend it. A backend
// that answers 100 then stalls errors TimedOut instead of parking the
// bridge forever.
#[tokio::test(start_paused = true)]
async fn injector_interim_1xx_does_not_extend_the_head_deadline() {
    use tokio::io::AsyncWriteExt;
    let headers = std::collections::HashMap::new();
    let (mut inner_w, inner_r) = tokio::io::duplex(64 * 1024);
    let mut injector =
        ResponseHeaderInjector::new(inner_r, headers, Some(std::time::Duration::from_secs(5)));
    inner_w
        .write_all(b"HTTP/1.1 100 Continue\r\n\r\n")
        .await
        .expect("write 100");
    let mut buf = [0u8; 4096];
    // The interim head is served raw...
    let n = injector.read(&mut buf).await.expect("interim read");
    assert_eq!(&buf[..n], b"HTTP/1.1 100 Continue\r\n\r\n");
    // ...then the final head never arrives: the absolute deadline fires
    // (the paused clock auto-advances while the read parks).
    let err = injector
        .read(&mut buf)
        .await
        .expect_err("deadline must fire");
    assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);
}

// A2 companion: a final head that ARRIVES within the deadline injects
// normally (the deadline must not cut healthy responses short).
#[tokio::test(start_paused = true)]
async fn injector_head_within_deadline_injects_normally() {
    use tokio::io::AsyncWriteExt;
    let headers = || {
        let mut h = std::collections::HashMap::new();
        h.insert("X-Injected".to_string(), String::from("yes"));
        h
    };
    let (mut inner_w, inner_r) = tokio::io::duplex(64 * 1024);
    let mut injector =
        ResponseHeaderInjector::new(inner_r, headers(), Some(std::time::Duration::from_secs(60)));
    inner_w
        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
        .await
        .expect("write 200");
    let mut buf = [0u8; 4096];
    let n = injector.read(&mut buf).await.expect("read");
    let out = String::from_utf8_lossy(&buf[..n]);
    assert!(out.contains("X-Injected: yes"), "injected, got: {out:?}");
    // Deadline NOT armed on the body path: the drain below is bounded by
    // the inner EOF, and nothing after `complete` consults the timer.
    assert!(out.ends_with("ok"), "body attached, got: {out:?}");
}

// A6 (round-13 review): case-insensitive duplicate config keys are ONE
// canonical header on the wire — keys sorted, the LAST same-name key
// wins (deterministic stand-in for Go's random map-iteration winner);
// never two lines. Backend-sent lines under either spelling are dropped
// with their folded continuations.
#[tokio::test]
async fn injector_config_case_duplicate_keys_emit_single_line() {
    use tokio::io::AsyncWriteExt;
    let mut headers = std::collections::HashMap::new();
    headers.insert("X-Custom".to_string(), "first".to_string());
    headers.insert("x-custom".to_string(), "second".to_string());
    let (mut inner_w, inner_r) = tokio::io::duplex(64 * 1024);
    let mut injector = ResponseHeaderInjector::new(inner_r, headers, None);
    inner_w
        .write_all(
            b"HTTP/1.1 200 OK\r\nX-Custom: backend\r\n  backend-fold\r\nContent-Length: 2\r\n\r\nok",
        )
        .await
        .expect("write");
    inner_w.shutdown().await.expect("shutdown");
    drop(inner_w);
    let out = injector_read_all(&mut injector).await;
    let s = String::from_utf8_lossy(&out);
    let custom_lines: Vec<&str> = s
        .lines()
        .filter(|l| l.to_ascii_lowercase().starts_with("x-custom:"))
        .collect();
    assert_eq!(
        custom_lines.len(),
        1,
        "exactly one X-Custom line on the wire, got: {s:?}"
    );
    // Sorted ascending, "X-Custom" < "x-custom" (uppercase first) — the
    // later key wins deterministically.
    assert_eq!(custom_lines[0], "x-custom: second", "got: {s:?}");
    assert!(
        !s.contains("backend"),
        "backend value must be dropped: {s:?}"
    );
    assert!(
        !s.contains("backend-fold"),
        "fold must go with its parent: {s:?}"
    );
    assert!(s.ends_with("ok"), "body must survive: {s:?}");
}

// B1 (round-13 review): a backend header whose lowercase spelling
// matches a configured key is dropped WITH its obs-fold tail; the
// configured value goes out alone.
#[tokio::test]
async fn injector_drops_lowercase_backend_header_under_config_key() {
    use tokio::io::AsyncWriteExt;
    let mut headers = std::collections::HashMap::new();
    headers.insert("X-Frame-Options".to_string(), "DENY".to_string());
    let (mut inner_w, inner_r) = tokio::io::duplex(64 * 1024);
    let mut injector = ResponseHeaderInjector::new(inner_r, headers, None);
    inner_w
        .write_all(
            b"HTTP/1.1 200 OK\r\nx-frame-options: SAMEORIGIN\r\n  folded-tail\r\nContent-Length: 2\r\n\r\nok",
        )
        .await
        .expect("write");
    inner_w.shutdown().await.expect("shutdown");
    drop(inner_w);
    let out = injector_read_all(&mut injector).await;
    let s = String::from_utf8_lossy(&out);
    assert!(
        s.contains("X-Frame-Options: DENY\r\n"),
        "configured value must be injected, got: {s:?}"
    );
    assert!(
        !s.contains("SAMEORIGIN"),
        "backend value must be dropped: {s:?}"
    );
    assert!(
        !s.contains("folded-tail"),
        "fold tail must go with its parent: {s:?}"
    );
    assert!(s.ends_with("ok"), "body must survive: {s:?}");
}

// B6 (round-13 review) + round-14 rework: a raw interim head, then a
// TRUNCATED second head ("HTTP/1.1 20" cut mid-code) followed by EOF.
// The interim goes out raw; nothing of the unterminated final head is
// ever relayed (Go readResponse errors on an unterminated head before
// the reverse proxy writes anything) — the partial is dropped and the
// next read reports Err(UnexpectedEof) so the bridge's 404 arm answers
// after the legal interim prefix.
#[tokio::test]
async fn injector_truncated_second_head_after_interim_not_relayed() {
    use tokio::io::AsyncWriteExt;
    let headers = || {
        let mut h = std::collections::HashMap::new();
        h.insert("X-Injected".to_string(), String::from("yes"));
        h
    };
    let (mut inner_w, inner_r) = tokio::io::duplex(64 * 1024);
    let mut injector = ResponseHeaderInjector::new(inner_r, headers(), None);
    inner_w
        .write_all(b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 20")
        .await
        .expect("write");
    inner_w.shutdown().await.expect("shutdown");
    drop(inner_w);
    let mut buf = [0u8; 4096];
    let n = injector.read(&mut buf).await.expect("interim read");
    assert_eq!(&buf[..n], b"HTTP/1.1 100 Continue\r\n\r\n");
    let err = injector
        .read(&mut buf)
        .await
        .expect_err("truncated final head must not be relayed");
    assert_eq!(err.kind(), std::io::ErrorKind::UnexpectedEof);
}

// B7 (round-13 review): a head whose FIRST line is blank (no status
// line) after an interim raw serve fails the read like Go's reverse
// proxy — it must not be spliced into a plausible response.
#[tokio::test]
async fn injector_blank_line_head_after_interim_is_invalid() {
    use tokio::io::AsyncWriteExt;
    let headers = || {
        let mut h = std::collections::HashMap::new();
        h.insert("X-Injected".to_string(), String::from("yes"));
        h
    };
    let (mut inner_w, inner_r) = tokio::io::duplex(64 * 1024);
    let mut injector = ResponseHeaderInjector::new(inner_r, headers(), None);
    inner_w
        .write_all(b"HTTP/1.1 100 Continue\r\n\r\n\r\n200 OK\r\n\r\n")
        .await
        .expect("write");
    let mut buf = [0u8; 4096];
    let n = injector.read(&mut buf).await.expect("interim read");
    assert_eq!(&buf[..n], b"HTTP/1.1 100 Continue\r\n\r\n");
    let err = injector
        .read(&mut buf)
        .await
        .expect_err("blank-first-line head must be rejected");
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
}

/// Audit round-15 gap pin: a mid-body decode failure AFTER a legal final
/// response head was already served must be swallowed as a CLEAN EOF —
/// the `complete` arm (:394-403) turns a post-head inner read error of
/// kind InvalidData into `Ok(())`, because frp-core would answer a
/// gateway head (404/502) for bytes the client already accepted as the
/// response (Go's ErrorHandler never runs once RoundTrip returned).
/// Producer shape pinned here is the real compressed-arm wiring
/// (`comp_key` → the work reader is wrapped in `SnappyStreamReader`
/// before the injector): a valid Snappy stream for the head + body,
/// then a garbage frame mid-body (a "compressed data" chunk header
/// declaring 0xFFFFFF bytes — far past the decoder's per-chunk cap, so
/// it errors the moment it is processed, never buffered as a partial
/// tail). Regression shape: without the swallow arm the read after the
/// body surfaces Err(InvalidData) instead of a clean EOF.
#[tokio::test]
async fn injector_mid_body_snappy_decode_failure_after_head_is_clean_eof() {
    use frp_core::encryption::SnappyCompressor;
    use tokio::io::AsyncWriteExt;

    let mut headers = std::collections::HashMap::new();
    headers.insert("X-Injected".to_string(), String::from("yes"));

    // Compress the whole backend response (head + body) into one
    // Snappy stream chunk, then append the corrupt frame.
    let mut comp = SnappyCompressor::new();
    let mut wire = Vec::new();
    comp.compress(
        b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello",
        &mut wire,
    )
    .expect("compress backend response");
    wire.extend_from_slice(&[0x00, 0xFF, 0xFF, 0xFF]);
    assert!(
        wire.len() < 32 * 1024,
        "payload must fit one SnappyStreamReader read chunk"
    );

    let (mut inner_w, inner_r) = tokio::io::duplex(64 * 1024);
    // The compressed-arm wiring (bridge.rs comp_key → injector inner is
    // a SnappyStreamReader over the work stream).
    let mut injector = ResponseHeaderInjector::new(
        frp_core::snappy_stream::SnappyStreamReader::new(inner_r),
        headers,
        None,
    );
    inner_w.write_all(&wire).await.expect("write wire");
    inner_w.shutdown().await.expect("shutdown");
    drop(inner_w);

    // Every read must succeed — the corruption may only shorten the
    // stream to a clean EOF, never surface as an error kind frp-core
    // would answer with a gateway head.
    let mut out = Vec::new();
    let mut chunk = [0u8; 7]; // small caller buffer (injector tail path)
    let saw_eof = loop {
        match injector.read(&mut chunk).await {
            Ok(0) => break true,
            Ok(n) => out.extend_from_slice(&chunk[..n]),
            Err(e) => panic!(
                "mid-body decode failure after head served must be swallowed as clean EOF, got Err({e})"
            ),
        }
    };
    assert!(
        saw_eof,
        "the corruption must end the stream with a clean EOF"
    );

    let s = String::from_utf8_lossy(&out);
    // The head was relayed/injected EXACTLY once, before the corruption.
    assert_eq!(
        s.matches("HTTP/1.1 200 OK").count(),
        1,
        "exactly one response head on the wire, got: {s:?}"
    );
    assert_eq!(
        s.matches("X-Injected: yes").count(),
        1,
        "injected header present exactly once, got: {s:?}"
    );
    assert!(
        s.starts_with("HTTP/1.1 200 OK\r\n"),
        "status line first, got: {s:?}"
    );
    // The legal body survived up to the corruption point...
    assert!(s.ends_with("hello"), "body must survive, got: {s:?}");
    // ...and the corrupt tail was never relayed (no second response /
    // garbage bytes after the body).
    assert!(
        !out.windows(4).any(|w| w == [0x00, 0xFF, 0xFF, 0xFF]),
        "corrupt frame bytes must never reach the wire: {out:?}"
    );
}
