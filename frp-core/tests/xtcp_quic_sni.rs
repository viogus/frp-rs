//! Regression test for the vendored rustls server-side SNI patch
//! (frp-rs `[patch.crates-io]` → `vendor/rustls`).
//!
//! Go frp v0.70.1 XTCP QUIC visitors send the peer address — `"ip:port"` —
//! as the TLS SNI hostname (client/visitor/xtcp.go →
//! `NewClientTLSConfig(..., raddr.String())`). Upstream rustls 0.23 parses
//! that as `ServerNamePayload::Invalid` and rejects the handshake with a
//! fatal `illegal_parameter` alert, so a Go QUIC visitor can never connect
//! to a Rust XTCP QUIC provider. The vendored patch treats an invalid SNI as
//! "no SNI" (the equivalent of upstream rustls 0.24 `invalid_sni_policy =
//! IgnoreAll`); this test drives a hand-crafted TLS 1.3 ClientHello carrying
//! that exact SNI through a `ServerConnection` and asserts the handshake
//! proceeds instead of failing.
//!
//! The client never completes the handshake — we only need the server's
//! first flight (ServerHello…) to prove it accepted the ClientHello.

#![cfg(feature = "tls")]

use std::io::Write;
use std::sync::Arc;

use rustls::ServerConnection;

fn client_hello_with_sni(sni: &str) -> Vec<u8> {
    // X25519 public key share — any 32 bytes; the client key is never used
    // because we stop after the server's first flight.
    let x25519_pub = [7u8; 32];

    // --- extensions ---
    let mut ext = Vec::new();

    // server_name (type 0): ServerNameList = len + { name_type(1)=host_name, len, sni }
    let mut host = Vec::new();
    host.push(0); // name_type = host_name
    host.extend_from_slice(&(sni.len() as u16).to_be_bytes());
    host.extend_from_slice(sni.as_bytes());
    let mut sni_ext = Vec::new();
    sni_ext.extend_from_slice(&(host.len() as u16).to_be_bytes()); // list len
    sni_ext.extend_from_slice(&host);
    ext.extend_from_slice(&0u16.to_be_bytes());
    ext.extend_from_slice(&(sni_ext.len() as u16).to_be_bytes());
    ext.extend_from_slice(&sni_ext);

    // supported_versions (43): list { 0x0304 } — body = list_len(1) + 0x0304
    let sv = vec![0x03, 0x04];
    ext.extend_from_slice(&43u16.to_be_bytes());
    ext.extend_from_slice(&3u16.to_be_bytes());
    ext.push(sv.len() as u8);
    ext.extend_from_slice(&sv);

    // signature_algorithms (13): rsa_pss_rsae_sha256(0x0804), ecdsa_secp256r1_sha256(0x0403)
    ext.extend_from_slice(&13u16.to_be_bytes());
    ext.extend_from_slice(&6u16.to_be_bytes());
    ext.extend_from_slice(&4u16.to_be_bytes());
    ext.extend_from_slice(&[0x08, 0x04, 0x04, 0x03]);

    // supported_groups (10): rustls selects the kx group from this extension.
    let groups = [0x001du16, 0x0017]; // X25519, P-256
    ext.extend_from_slice(&10u16.to_be_bytes());
    ext.extend_from_slice(&6u16.to_be_bytes());
    ext.extend_from_slice(&4u16.to_be_bytes());
    for g in groups {
        ext.extend_from_slice(&g.to_be_bytes());
    }

    // key_share (51): client_shares<1..2^16-1> = list_len + { group, key_len, key }
    let mut ks = Vec::new();
    ks.extend_from_slice(&0x001du16.to_be_bytes());
    ks.extend_from_slice(&32u16.to_be_bytes());
    ks.extend_from_slice(&x25519_pub);
    ext.extend_from_slice(&51u16.to_be_bytes());
    ext.extend_from_slice(&(ks.len() as u16 + 2).to_be_bytes());
    ext.extend_from_slice(&(ks.len() as u16).to_be_bytes());
    ext.extend_from_slice(&ks);

    // --- ClientHello body ---
    let mut body = Vec::new();
    body.extend_from_slice(&0x0303u16.to_be_bytes()); // legacy_version
    body.extend_from_slice(&[0x42; 32]); // random
    body.push(0); // legacy_session_id
                  // cipher_suites: TLS_AES_128_GCM_SHA256(0x1301) TLS_AES_256_GCM_SHA384(0x1302) TLS_CHACHA20_POLY1305_SHA256(0x1303)
    body.extend_from_slice(&6u16.to_be_bytes());
    body.extend_from_slice(&[0x13, 0x01, 0x13, 0x02, 0x13, 0x03]);
    body.push(1); // legacy_compression_methods len
    body.push(0);
    body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
    body.extend_from_slice(&ext);

    // --- wrap in handshake + record headers ---
    let mut hs = Vec::new();
    hs.push(1); // handshake_type = ClientHello
    hs.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
    hs.extend_from_slice(&body);

    let mut record = Vec::new();
    record.extend_from_slice(&[0x16, 0x03, 0x01]); // handshake, TLS 1.0 record
    record.extend_from_slice(&(hs.len() as u16).to_be_bytes());
    record.extend_from_slice(&hs);
    record
}

#[test]
fn invalid_sni_ip_port_is_accepted_as_no_sni() {
    // The exact SNI Go frp v0.70.1 XTCP QUIC visitors send: peer "ip:port".
    // (Upstream rustls 0.23 parses this as Invalid → fatal illegal_parameter;
    // the vendored patch treats it as "no SNI".)
    assert_server_accepts("1.2.3.4:7000");
}

#[test]
fn valid_sni_still_works() {
    // Sanity check on the test rig: a well-formed SNI must negotiate normally.
    assert_server_accepts("example.com");
}

fn assert_server_accepts(sni: &str) {
    let server_config =
        frp_core::transport::generate_self_signed_tls_config().expect("self-signed server config");
    let mut server = ServerConnection::new(Arc::new(server_config)).expect("server connection");

    let client_hello = client_hello_with_sni(sni);

    // Feed the ClientHello and process it. This is the step that rejected the
    // handshake before the patch (fatal alert); afterwards it succeeds and
    // the server produces its first flight (ServerHello…).
    let mut input = &client_hello[..];
    server
        .read_tls(&mut input)
        .expect("read_tls must accept the ClientHello");
    server
        .process_new_packets()
        .expect("process_new_packets must not fatal on invalid SNI (patch)");

    // The server's handshake flight lands in the send buffer; drain it.
    let mut out = Vec::new();
    while server.wants_write() {
        server
            .write_tls(&mut out)
            .expect("write_tls must produce the server flight");
    }

    assert!(
        !out.is_empty(),
        "server emitted no handshake flight; patch ineffective"
    );
    // A TLS 1.3 ServerHello record starts with 0x16 0x03 0x03 (handshake, TLS 1.3).
    assert!(
        out.starts_with(&[0x16, 0x03, 0x03]),
        "expected TLS 1.3 ServerHello flight, got: {:02x?}",
        &out[..out.len().min(8)]
    );
}
