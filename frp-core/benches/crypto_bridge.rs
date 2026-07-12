//! Micro-benchmarks for frp-core critical paths.
//!
//! Run all:
//!   cargo bench -p frp-core
//!
//! Filter by name:
//!   cargo bench -p frp-core -- key_derivation
//!   cargo bench -p frp-core -- stun

use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

// ── Bench helpers ──────────────────────────────────────────────────────────

fn bench_key() -> [u8; 16] {
    let mut key = [0u8; 16];
    for (i, b) in key.iter_mut().enumerate() {
        *b = i as u8;
    }
    key
}

fn bench_data(size: usize) -> Vec<u8> {
    let mut data = Vec::with_capacity(size);
    let mut x: u32 = 0xDEADBEEF;
    for _ in 0..size {
        x = x.wrapping_mul(1664525).wrapping_add(1013904223);
        data.push((x >> 24) as u8);
    }
    data
}

// ── Key derivation ─────────────────────────────────────────────────────────

fn bench_key_derivation(c: &mut Criterion) {
    let mut group = c.benchmark_group("key_derivation");
    group.bench_function("pbkdf2_sha1", |b| {
        let token = "my-test-token-42";
        b.iter(|| {
            frp_core::encryption::derive_key(black_box(token))
        });
    });
    group.finish();
}

// ── Snappy compression ─────────────────────────────────────────────────────

fn bench_compression(c: &mut Criterion) {
    let sizes = [64, 1024, 65536];

    let mut group = c.benchmark_group("compression");
    for size in sizes {
        let data = bench_data(size);
        group.throughput(Throughput::Bytes(size as u64));

        group.bench_function(format!("snappy_compress_{}_bytes", size), |b| {
            b.iter(|| {
                let _ = frp_core::encryption::compress(black_box(&data));
            });
        });

        let compressed = frp_core::encryption::compress(&data).unwrap();
        group.bench_function(format!("snappy_decompress_{}_bytes", size), |b| {
            b.iter(|| {
                let mut dec = frp_core::encryption::SnappyDecompressor::new();
                let _ = dec.feed(black_box(&compressed));
                let _ = dec.flush();
            });
        });
    }
    group.finish();
}

// ── AES-128-CFB streaming (tokio async — spawned in runtime) ───────────────

fn bench_cipher_stream(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let key = bench_key();
    let sizes = [64, 1024, 65536];

    let mut group = c.benchmark_group("cipher_stream");
    for size in sizes {
        let plaintext = bench_data(size);
        group.throughput(Throughput::Bytes(size as u64));

        group.bench_function(format!("aes128cfb_encrypt_{}_bytes", size), |b| {
            b.iter(|| {
                rt.block_on(async {
                    let (tx, mut rx) = tokio::io::duplex(size + 64);
                    let plain = plaintext.clone();
                    let h = tokio::spawn(async move {
                        use frp_core::cipher_stream::CipherWriter;
                        let mut w = CipherWriter::new(tx, key);
                        AsyncWriteExt::write_all(&mut w, &plain).await.unwrap();
                        AsyncWriteExt::flush(&mut w).await.unwrap();
                    });
                    let mut out = Vec::new();
                    AsyncReadExt::read_to_end(&mut rx, &mut out).await.unwrap();
                    h.await.unwrap();
                    out
                });
            });
        });

        // Pre-encrypt for decrypt bench
        let mut enc_buf = Vec::new();
        rt.block_on(async {
            let (tx, mut rx) = tokio::io::duplex(size + 64);
            let h = tokio::spawn(async move {
                use frp_core::cipher_stream::CipherWriter;
                let mut w = CipherWriter::new(tx, key);
                AsyncWriteExt::write_all(&mut w, &plaintext).await.unwrap();
                AsyncWriteExt::flush(&mut w).await.unwrap();
            });
            AsyncReadExt::read_to_end(&mut rx, &mut enc_buf).await.unwrap();
            h.await.unwrap();
        });

        group.bench_function(format!("aes128cfb_decrypt_{}_bytes", size), |b| {
            b.iter(|| {
                rt.block_on(async {
                    use frp_core::cipher_stream::CipherReader;
                    let mut r = CipherReader::new(black_box(enc_buf.as_slice()), key);
                    let mut out = vec![0u8; size + 32];
                    let _ = AsyncReadExt::read(&mut r, &mut out).await;
                });
            });
        });
    }
    group.finish();
}

// ── STUN response parsing ──────────────────────────────────────────────────

fn bench_stun_parse(c: &mut Criterion) {
    let mut group = c.benchmark_group("stun");

    let tx_id = [0x42u8; 12];
    let cookie: u32 = 0x2112A442;
    let cookie_hi = (cookie >> 16) as u16;
    let real_port: u16 = 12345;
    let real_ip: [u8; 4] = [203, 0, 113, 5];
    let xored_port = real_port ^ cookie_hi;
    let ip_u32 = u32::from_be_bytes(real_ip);
    let xored_ip = ip_u32 ^ cookie;

    let mut pkt = Vec::new();
    pkt.extend_from_slice(&0x0101u16.to_be_bytes());
    pkt.extend_from_slice(&12u16.to_be_bytes());
    pkt.extend_from_slice(&cookie.to_be_bytes());
    pkt.extend_from_slice(&tx_id);
    pkt.extend_from_slice(&0x0020u16.to_be_bytes());
    pkt.extend_from_slice(&8u16.to_be_bytes());
    pkt.push(0x00);
    pkt.push(0x01);
    pkt.extend_from_slice(&xored_port.to_be_bytes());
    pkt.extend_from_slice(&xored_ip.to_be_bytes());

    group.bench_function("parse_binding_response", |b| {
        b.iter(|| {
            let _ = frp_core::stun::parse_binding_response(
                black_box(&pkt),
                black_box(&tx_id),
            );
        });
    });
    group.finish();
}

// ── V1 protocol frame roundtrip ────────────────────────────────────────────

fn bench_protocol(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let msg = frp_core::msg::FrpMessage::Ping(frp_core::msg::Ping {
        timestamp: Some(1234567890),
        privilege_key: Some("test-key-data".into()),
    });

    let mut group = c.benchmark_group("protocol");

    group.bench_function("v1_frame_roundtrip", |b| {
        b.iter(|| {
            rt.block_on(async {
                let (mut a_tx, mut a_rx) = tokio::io::duplex(65536);

                frp_core::protocol::write_msg_v1(
                    black_box(&mut a_tx),
                    black_box(&msg),
                ).await.unwrap();

                let _ = frp_core::protocol::read_msg_v1(
                    black_box(&mut a_rx),
                ).await.unwrap();
            });
        });
    });

    group.finish();
}

// ── Protocol: V2 roundtrip + per-type V1/V2 serialize/deserialize ────────────

fn bench_protocol_all_types(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let all_types: &[(u8, u16, &str)] = &[
        (frp_core::msg::TYPE_LOGIN, frp_core::msg::V2_TYPE_LOGIN, "login"),
        (frp_core::msg::TYPE_LOGIN_RESP, frp_core::msg::V2_TYPE_LOGIN_RESP, "login_resp"),
        (frp_core::msg::TYPE_NEW_PROXY, frp_core::msg::V2_TYPE_NEW_PROXY, "new_proxy"),
        (frp_core::msg::TYPE_NEW_PROXY_RESP, frp_core::msg::V2_TYPE_NEW_PROXY_RESP, "new_proxy_resp"),
        (frp_core::msg::TYPE_CLOSE_PROXY, frp_core::msg::V2_TYPE_CLOSE_PROXY, "close_proxy"),
        (frp_core::msg::TYPE_NEW_WORK_CONN, frp_core::msg::V2_TYPE_NEW_WORK_CONN, "new_work_conn"),
        (frp_core::msg::TYPE_REQ_WORK_CONN, frp_core::msg::V2_TYPE_REQ_WORK_CONN, "req_work_conn"),
        (frp_core::msg::TYPE_START_WORK_CONN, frp_core::msg::V2_TYPE_START_WORK_CONN, "start_work_conn"),
        (frp_core::msg::TYPE_PING, frp_core::msg::V2_TYPE_PING, "ping"),
        (frp_core::msg::TYPE_PONG, frp_core::msg::V2_TYPE_PONG, "pong"),
        (frp_core::msg::TYPE_NEW_VISITOR_CONN, frp_core::msg::V2_TYPE_NEW_VISITOR_CONN, "new_visitor_conn"),
        (frp_core::msg::TYPE_NEW_VISITOR_CONN_RESP, frp_core::msg::V2_TYPE_NEW_VISITOR_CONN_RESP, "new_visitor_conn_resp"),
        (frp_core::msg::TYPE_UDP_PACKET, frp_core::msg::V2_TYPE_UDP_PACKET, "udp_packet"),
        (frp_core::msg::TYPE_NAT_HOLE_VISITOR, frp_core::msg::V2_TYPE_NAT_HOLE_VISITOR, "nat_hole_visitor"),
        (frp_core::msg::TYPE_NAT_HOLE_CLIENT, frp_core::msg::V2_TYPE_NAT_HOLE_CLIENT, "nat_hole_client"),
        (frp_core::msg::TYPE_NAT_HOLE_RESP, frp_core::msg::V2_TYPE_NAT_HOLE_RESP, "nat_hole_resp"),
        (frp_core::msg::TYPE_NAT_HOLE_SID, frp_core::msg::V2_TYPE_NAT_HOLE_SID, "nat_hole_sid"),
        (frp_core::msg::TYPE_NAT_HOLE_REPORT, frp_core::msg::V2_TYPE_NAT_HOLE_REPORT, "nat_hole_report"),
        (frp_core::msg::TYPE_CLOSE_PROXY_RESP, frp_core::msg::V2_TYPE_CLOSE_PROXY_RESP, "close_proxy_resp"),
        (frp_core::msg::TYPE_ERROR, frp_core::msg::V2_TYPE_ERROR, "error"),
    ];

    let mut group = c.benchmark_group("protocol_all_types");
    group.throughput(Throughput::Elements(1));

    for &(v1_byte, v2_id, name) in all_types {
        let msg = frp_core::msg::FrpMessage::from_v1_type_byte(v1_byte).unwrap();

        group.bench_function(format!("v1_serialize_{name}"), |b| {
            b.iter(|| {
                let _ = serde_json::to_vec(black_box(&msg)).unwrap();
            });
        });

        let json = serde_json::to_vec(&msg).unwrap();
        group.bench_function(format!("v1_deserialize_{name}"), |b| {
            b.iter(|| {
                let _ = frp_core::protocol::deserialize_v1(black_box(v1_byte), black_box(&json));
            });
        });

        group.bench_function(format!("v2_roundtrip_{name}"), |b| {
            b.iter(|| {
                rt.block_on(async {
                    let (mut a_tx, mut a_rx) = tokio::io::duplex(65536);
                    frp_core::protocol::write_msg_v2(black_box(&mut a_tx), black_box(&msg))
                        .await
                        .unwrap();
                    let _ = frp_core::protocol::read_msg_v2(black_box(&mut a_rx))
                        .await
                        .unwrap();
                });
            });
        });

        group.bench_function(format!("v2_serialize_{name}"), |b| {
            b.iter(|| {
                rt.block_on(async {
                    let mut sink: Vec<u8> = Vec::with_capacity(256);
                    frp_core::protocol::write_msg_v2(black_box(&mut sink), black_box(&msg))
                        .await
                        .unwrap();
                    black_box(&sink);
                });
            });
        });

        group.bench_function(format!("v2_deserialize_{name}"), |b| {
            b.iter(|| {
                let _ = frp_core::protocol::deserialize_v2(black_box(v2_id), black_box(&json));
            });
        });
    }

    group.finish();
}

// ── Encrypted bridge data pipeline ─────────────────────────────────────────

fn bench_bridge_pipeline(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let key = bench_key();
    let sizes = [1024, 65536, 262144, 1048576]; // 1KB, 64KB, 256KB, 1MB

    let mut group = c.benchmark_group("bridge");
    for size in sizes {
        let data = bench_data(size);
        group.throughput(Throughput::Bytes(size as u64));

        // Plain bridge: no encryption, no compression
        group.bench_function(format!("plain_bridge_{}_bytes", size), |b| {
            b.iter(|| {
                rt.block_on(async {
                    let (mut u_w_test, u_r_bridge) = tokio::io::duplex(size * 2);
                    let (w_w_bridge, _w_r_test) = tokio::io::duplex(size * 2);
                    let (w_w_test, w_r_bridge) = tokio::io::duplex(size * 2);
                    let (u_w_bridge, _u_r_test) = tokio::io::duplex(size * 2);

                    let h = tokio::spawn(async move {
                        frp_core::bridge::bridge_plain(
                            u_r_bridge, u_w_bridge, w_r_bridge, w_w_bridge,
                            false, vec![], None,
                        ).await;
                    });

                    AsyncWriteExt::write_all(&mut u_w_test, &data).await.unwrap();
                    drop(u_w_test);
                    drop(w_w_test);

                    h.await.unwrap();
                });
            });
        });

        // Encrypted only: no compression
        group.bench_function(format!("encrypted_bridge_{}_bytes", size), |b| {
            b.iter(|| {
                rt.block_on(async {
                    let (mut u_w_test, u_r_bridge) = tokio::io::duplex(size * 2);
                    let (w_w_bridge, _w_r_test) = tokio::io::duplex(size * 2);
                    let (w_w_test, w_r_bridge) = tokio::io::duplex(size * 2);
                    let (u_w_bridge, _u_r_test) = tokio::io::duplex(size * 2);

                    let h = tokio::spawn(async move {
                        frp_core::bridge::bridge_encrypted(
                            u_r_bridge, u_w_bridge, w_r_bridge, w_w_bridge,
                            &key, false, vec![], None, None, None,
                        ).await;
                    });

                    AsyncWriteExt::write_all(&mut u_w_test, &data).await.unwrap();
                    drop(u_w_test);
                    drop(w_w_test);

                    h.await.unwrap();
                });
            });
        });

        // Encrypted + compressed
        group.bench_function(format!("encrypted_compressed_bridge_{}_bytes", size), |b| {
            b.iter(|| {
                rt.block_on(async {
                    let (mut u_w_test, u_r_bridge) = tokio::io::duplex(size * 2);
                    let (w_w_bridge, _w_r_test) = tokio::io::duplex(size * 2);
                    let (w_w_test, w_r_bridge) = tokio::io::duplex(size * 2);
                    let (u_w_bridge, _u_r_test) = tokio::io::duplex(size * 2);

                    let h = tokio::spawn(async move {
                        frp_core::bridge::bridge_encrypted(
                            u_r_bridge, u_w_bridge, w_r_bridge, w_w_bridge,
                            &key, true, vec![], None, None, None,
                        ).await;
                    });

                    AsyncWriteExt::write_all(&mut u_w_test, &data).await.unwrap();
                    drop(u_w_test);
                    drop(w_w_test);

                    h.await.unwrap();
                });
            });
        });
    }
    group.finish();
}

// ── Bandwidth limiter accuracy ──────────────────────────────────────────────

fn bench_bandwidth_limiter(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();

    let mut group = c.benchmark_group("bandwidth");
    group.throughput(Throughput::Elements(1));

    group.bench_function("limiter_consume_within_burst", |b| {
        b.iter(|| {
            rt.block_on(async {
                let mut lim = frp_core::bandwidth::BandwidthLimiter::new(1_000_000_000); // 1 GB/s — huge burst
                lim.consume(black_box(1024)).await;
            });
        });
    });

    group.bench_function("limiter_consume_exceeds_burst", |b| {
        b.iter(|| {
            rt.block_on(async {
                // 1 KB/s rate, burst = 1KB. Consuming 2KB forces sleep.
                let mut lim = frp_core::bandwidth::BandwidthLimiter::new(1024);
                lim.consume(black_box(2048)).await;
            });
        });
    });

    group.bench_function("limiter_consume_zero", |b| {
        b.iter(|| {
            rt.block_on(async {
                let mut lim = frp_core::bandwidth::BandwidthLimiter::new(1024);
                lim.consume(black_box(0)).await;
            });
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_key_derivation,
    bench_compression,
    bench_cipher_stream,
    bench_stun_parse,
    bench_protocol,
    bench_protocol_all_types,
    bench_bridge_pipeline,
    bench_bandwidth_limiter,
);
criterion_main!(benches);
