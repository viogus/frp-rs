//! Round-14 V2 handshake coverage (test-completeness audit).
//!
//! The ClientHello/ServerHello negotiation (src/v2_handshake.rs) and the
//! AEAD stream layer (src/crypto.rs) are tested separately, but never
//! composed end-to-end: the exact path production runs — handshake over
//! one duplex, then AEAD-encrypted V2 messages over the wrapped stream —
//! has no test. These tests run that composition in memory.

use frp_core::crypto::{derive_aead_control_keys, AeadStream};
use frp_core::msg::{self, FrpMessage};
use frp_core::protocol::{read_msg_v2, write_msg_v2};
use frp_core::transport::IoStream;
use frp_core::v2_handshake::{
    v2_handshake_client_recv_hello, v2_handshake_client_send_hello, v2_handshake_server,
    CryptoContext,
};

/// Run a full client/server V2 handshake over a loopback TCP pair and
/// return each side's negotiated CryptoContext together with its stream.
/// (IoStream has no DuplexStream constructor — Transport is implemented
/// per transport type — so in-memory tests use real loopback sockets.)
async fn handshake_pair(
    with_crypto: bool,
) -> (
    Option<CryptoContext>,
    Option<CryptoContext>,
    IoStream,
    IoStream,
) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let client_half = tokio::net::TcpStream::connect(addr).await.unwrap();
    let (server_half, _) = listener.accept().await.unwrap();
    let mut client_io = IoStream::Tcp(client_half);
    let mut server_io = IoStream::Tcp(server_half);
    let (c, s) = tokio::join!(
        async move {
            let hello =
                v2_handshake_client_send_hello(&mut client_io, "tcp", false, false, with_crypto)
                    .await?;
            let ctx = v2_handshake_client_recv_hello(
                &mut client_io,
                &hello,
                "tcp",
                false,
                false,
                with_crypto,
            )
            .await?;
            Ok::<_, frp_core::Error>((ctx, client_io))
        },
        async move {
            let (_, ctx) = v2_handshake_server(&mut server_io).await?;
            Ok::<_, frp_core::Error>((ctx, server_io))
        },
    );
    let (cctx, client_io) = c.expect("client handshake must succeed");
    let (sctx, server_io) = s.expect("server handshake must succeed");
    (cctx, sctx, client_io, server_io)
}

#[tokio::test]
async fn test_v2_handshake_aead_aes256gcm_message_roundtrip() {
    let (cctx, sctx, client_io, server_io) = handshake_pair(true).await;
    let cctx = cctx.expect("client negotiated crypto");
    let sctx = sctx.expect("server negotiated crypto");
    assert_eq!(cctx.algorithm, sctx.algorithm, "algorithms must match");
    assert_eq!(
        cctx.transcript_hash, sctx.transcript_hash,
        "transcript hash must match"
    );

    // Client writes with client-to-server key, reads with server-to-client
    // key; server mirrors (login.rs:1066-1089 / client control.rs:478-486).
    let (c2s, s2c) =
        derive_aead_control_keys(b"round14-token", cctx.algorithm, &cctx.transcript_hash).unwrap();
    let mut client_aead = AeadStream::new(Box::new(client_io), cctx.algorithm, &s2c, &c2s).unwrap();
    let mut server_aead = AeadStream::new(Box::new(server_io), sctx.algorithm, &c2s, &s2c).unwrap();

    // Client → server: an AEAD-encrypted Login over V2 framing.
    let login = FrpMessage::Login(Box::new(msg::Login {
        version: Some("0.71.0".into()),
        hostname: Some("h1".into()),
        os: None,
        arch: None,
        user: None,
        run_id: Some("r1".into()),
        client_id: None,
        pool_count: Some(5),
        timestamp: Some(1_721_000_000),
        privilege_key: Some("pk".into()),
        metas: None,
        client_spec: None,
        multiplexer: Some("yamux".into()),
    }));
    write_msg_v2(&mut client_aead, &login).await.unwrap();
    let got = read_msg_v2(&mut server_aead).await.unwrap();
    assert_eq!(got, login);

    // Server → client: Pong with error.
    let pong = FrpMessage::Pong(msg::Pong {
        error: Some("ok".into()),
    });
    write_msg_v2(&mut server_aead, &pong).await.unwrap();
    let got = read_msg_v2(&mut client_aead).await.unwrap();
    assert_eq!(got, pong);
}

#[tokio::test]
async fn test_v2_handshake_wrong_token_breaks_decryption() {
    // The V2 handshake itself carries no authentication (Go frp design);
    // two peers with different tokens negotiate the same crypto context,
    // but derive different directional keys, so the first AEAD frame must
    // fail to decrypt — an Err from the read path, never a panic.
    let (cctx, sctx, client_io, server_io) = handshake_pair(true).await;
    let cctx = cctx.expect("client negotiated crypto");
    let sctx = sctx.expect("server negotiated crypto");

    // Client derives its keys with token A, server with token B.
    let (client_c2s, client_s2c) =
        derive_aead_control_keys(b"token-a", cctx.algorithm, &cctx.transcript_hash).unwrap();
    let (server_c2s, server_s2c) =
        derive_aead_control_keys(b"token-b", sctx.algorithm, &sctx.transcript_hash).unwrap();

    let mut client_aead = AeadStream::new(
        Box::new(client_io),
        cctx.algorithm,
        &client_s2c,
        &client_c2s,
    )
    .unwrap();
    let mut server_aead = AeadStream::new(
        Box::new(server_io),
        sctx.algorithm,
        &server_c2s,
        &server_s2c,
    )
    .unwrap();

    let login = FrpMessage::Login(Box::new(msg::Login {
        version: Some("0.71.0".into()),
        hostname: None,
        os: None,
        arch: None,
        user: None,
        run_id: None,
        client_id: None,
        pool_count: None,
        timestamp: None,
        privilege_key: None,
        metas: None,
        client_spec: None,
        multiplexer: None,
    }));
    // The write side is local encryption and succeeds...
    write_msg_v2(&mut client_aead, &login).await.unwrap();
    // ...but the server's read key differs, so the AEAD tag check fails.
    assert!(
        read_msg_v2(&mut server_aead).await.is_err(),
        "mismatched token must break AEAD decryption"
    );
}

#[tokio::test]
async fn test_v2_handshake_without_crypto_offer_is_rejected() {
    // Go parity (crypto.go NewServerHello: "no supported crypto algorithm"):
    // a client that offers no AEAD algorithm is rejected fail-closed — the
    // server writes a ServerHello carrying the error, then tears down. The
    // crypto-less handshake path does not exist in frp-rs (or Go v0.71.0);
    // `v2_handshake_server` must never proceed without crypto.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let client_half = tokio::net::TcpStream::connect(addr).await.unwrap();
    let (server_half, _) = listener.accept().await.unwrap();
    let mut client_io = IoStream::Tcp(client_half);
    let mut server_io = IoStream::Tcp(server_half);
    let (c, s) = tokio::join!(
        async move {
            let hello =
                v2_handshake_client_send_hello(&mut client_io, "tcp", false, false, false).await?;
            let res =
                v2_handshake_client_recv_hello(&mut client_io, &hello, "tcp", false, false, false)
                    .await;
            Ok::<_, frp_core::Error>((res.is_err(), client_io))
        },
        async move {
            let res = v2_handshake_server(&mut server_io).await;
            Ok::<_, frp_core::Error>((res.is_err(), server_io))
        },
    );
    let (client_rejected, _) = c.expect("client handshake attempt");
    let (server_rejected, _) = s.expect("server handshake attempt");
    assert!(
        server_rejected,
        "server must reject a no-crypto ClientHello"
    );
    assert!(client_rejected, "client must see the ServerHello error");
}
