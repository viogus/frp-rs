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

// ── Encrypted bridge data pipeline ─────────────────────────────────────────

fn bench_bridge_pipeline(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let key = bench_key();
    let sizes = [1024, 65536, 262144]; // 1KB, 64KB, 256KB

    let mut group = c.benchmark_group("bridge");
    for size in sizes {
        let data = bench_data(size);
        group.throughput(Throughput::Bytes(size as u64));

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
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_key_derivation,
    bench_compression,
    bench_cipher_stream,
    bench_stun_parse,
    bench_protocol,
    bench_bridge_pipeline,
);
criterion_main!(benches);
