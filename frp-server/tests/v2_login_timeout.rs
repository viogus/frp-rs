//! Regression tests for the V2 post-handshake Login-read timeout.
//!
//! Go frp v0.70.1 applies a single `connReadTimeout = 10s` read deadline
//! covering magic read + V2 ClientHello/ServerHello exchange + first message.
//! frp-rs mirrored the handshake timeout but left the read of the next frame
//! (Login) after a ClientHello unbounded. These tests verify that a peer which
//! completes ClientHello but never sends Login is disconnected within ~10s
//! (`V2_HANDSHAKE_TIMEOUT`), so it cannot pin a server task / file descriptor
//! forever.

mod common;

use std::time::{Duration, Instant};

use common::{allocate_port, test_auth_cfg};
use frp_core::config::{ServerConfig, ServerTransportConfig};
use frp_core::mux;
use frp_core::transport::{dial_server, DialOptions, IoStream};
use frp_core::v2_handshake;
use frp_server::service::Service;

/// Connect to a fresh in-process frps and complete the V2
/// ClientHello/ServerHello handshake, returning the connected stream.
/// The yamux session (when used) is returned too — dropping it closes the
/// connection, so callers must keep it alive until the assertion completes.
async fn handshake_v2(
    opts: DialOptions,
    wrap_in_yamux: bool,
) -> (IoStream, Option<mux::YamuxSession>) {
    let raw_stream = dial_server(&opts).await.expect("dial server");
    if !wrap_in_yamux {
        let mut io = raw_stream;
        frp_core::protocol::write_v2_magic(&mut io)
            .await
            .expect("write v2 magic");
        v2_handshake::v2_handshake_client(&mut io, "tcp", false, false, false)
            .await
            .expect("V2 handshake");
        return (io, None);
    }
    // V2 over yamux (default tcp_mux=true): yamux wraps the TCP stream BEFORE
    // the handshake, matching Go frp / frp-rs flow, then V2 magic is written
    // on the yamux control stream.
    let tcp_stream = raw_stream
        .into_tcp()
        .expect("expected IoStream::Tcp after V2 dial");
    let (control_yamux, yamux_session) = mux::client_mux(tcp_stream, &mux::TcpMuxConfig::default())
        .await
        .expect("yamux client init");
    let mut control = IoStream::Yamux(control_yamux);
    frp_core::protocol::write_v2_magic(&mut control)
        .await
        .expect("write v2 magic on yamux");
    v2_handshake::v2_handshake_client(&mut control, "tcp", false, true, false)
        .await
        .expect("V2 handshake");
    (control, Some(yamux_session))
}

/// Wait for the server to close the connection after a handshake with no
/// Login. Asserts the close happens after the V2 handshake timeout (~10s),
/// not immediately (i.e. the post-handshake Login read is bounded).
async fn expect_disconnect_after_timeout(io: &mut IoStream) {
    let start = Instant::now();
    match tokio::time::timeout(Duration::from_secs(15), io.read_raw_v2_frame()).await {
        Err(_) => panic!(
            "server did not close the connection within 15s (elapsed {:?})",
            start.elapsed()
        ),
        Ok(Err(e)) => {
            let elapsed = start.elapsed();
            assert!(
                elapsed >= Duration::from_secs(8),
                "connection closed too early after {elapsed:?}; server must wait the full V2 handshake timeout"
            );
            eprintln!("server closed idle V2 connection after {elapsed:?}: {e}");
        }
        Ok(Ok((ft, _, _))) => {
            panic!("unexpected V2 frame (type {ft}) after handshake with no Login sent")
        }
    }
}

/// V2 over yamux (default tcp_mux=true): ClientHello/ServerHello on the yamux
/// control stream, then stay silent. Server must close within ~10s.
#[tokio::test]
async fn test_v2_post_handshake_login_read_timeout_yamux() {
    let bind_port = allocate_port();
    let cfg = ServerConfig {
        bind_addr: "127.0.0.1".into(),
        bind_port,
        auth: test_auth_cfg(),
        ..Default::default()
    };
    let service = Service::new(cfg, None).await.expect("create service");
    let _server_handle = tokio::spawn(async move {
        let _ = service.run().await;
    });
    tokio::time::sleep(Duration::from_millis(200)).await;

    let opts = DialOptions {
        server_addr: "127.0.0.1".into(),
        server_port: bind_port,
        v2: true,
        ..Default::default()
    };
    let (mut control, _session) = handshake_v2(opts, true).await;

    // Handshake complete. Now stay silent — never send Login.
    expect_disconnect_after_timeout(&mut control).await;
}

/// V2 directly on raw TCP (tcp_mux=false): ClientHello/ServerHello, then stay
/// silent. Server must close within ~10s.
#[tokio::test]
async fn test_v2_post_handshake_login_read_timeout_raw_tcp() {
    let bind_port = allocate_port();
    let cfg = ServerConfig {
        bind_addr: "127.0.0.1".into(),
        bind_port,
        transport: ServerTransportConfig {
            tcp_mux: Some(false),
            ..Default::default()
        },
        auth: test_auth_cfg(),
        ..Default::default()
    };
    let service = Service::new(cfg, None).await.expect("create service");
    let _server_handle = tokio::spawn(async move {
        let _ = service.run().await;
    });
    tokio::time::sleep(Duration::from_millis(200)).await;

    let opts = DialOptions {
        server_addr: "127.0.0.1".into(),
        server_port: bind_port,
        v2: true,
        ..Default::default()
    };
    let (mut io, None) = handshake_v2(opts, false).await else {
        panic!("raw TCP path must not return a yamux session");
    };

    // Handshake complete. Now stay silent — never send Login.
    expect_disconnect_after_timeout(&mut io).await;
}
