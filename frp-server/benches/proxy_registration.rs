//! Micro-benchmarks for proxy registration throughput.
//!
//! Run all:
//!   cargo bench -p frp-server --bench proxy_registration
//!
//! Filter by name:
//!   cargo bench -p frp-server --bench proxy_registration -- register_1000

use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion, Throughput};
use frp_server::proxy::{ProxyInfo, ProxyManager};
use std::collections::HashMap;

/// Build a fresh `ProxyInfo` with all fields populated.
/// `ProxyInfo` does not implement `Default`, so every field is set explicitly.
fn make_info(name: &str, run_id: &str, group: Option<&str>) -> ProxyInfo {
    ProxyInfo {
        name: name.to_string(),
        proxy_type: "tcp".to_string(),
        run_id: run_id.to_string(),
        user: String::new(),
        remote_port: Some(6000),
        sk: None,
        group: group.map(|g| g.to_string()),
        group_key: group.map(|_| "gk".to_string()),
        local_addr: Some("127.0.0.1:8080".to_string()),
        use_encryption: false,
        use_compression: false,
        virtual_net: None,
        allow_users: Vec::new(),
        proxy_protocol_version: String::new(),
        response_headers: HashMap::new(),
        custom_domains: Vec::new(),
        route_by_http_user: String::new(),
        multiplexer: String::new(),
        bandwidth_limit: String::new(),
        bandwidth_limit_mode: String::new(),
    }
}

fn bench_proxy_registration(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let mut group = c.benchmark_group("proxy_registration");

    // 1. Register a single proxy into a fresh manager per iteration.
    group.bench_function("register_single", |b| {
        b.iter_batched(
            || (ProxyManager::new(), make_info("p0", "run0", None)),
            |(mgr, info)| {
                rt.block_on(async {
                    mgr.register(black_box("run0".to_string()), black_box(info))
                        .await
                        .unwrap();
                });
            },
            BatchSize::SmallInput,
        );
    });

    // 2. Register 1000 distinct proxies into a fresh manager per iteration.
    group.throughput(Throughput::Elements(1000));
    group.bench_function("register_1000", |b| {
        b.iter_batched(
            || {
                let infos: Vec<(String, ProxyInfo)> = (0..1000)
                    .map(|i| {
                        let run_id = format!("run{i}");
                        let info = make_info(&format!("p{i}"), &run_id, None);
                        (run_id, info)
                    })
                    .collect();
                (ProxyManager::new(), infos)
            },
            |(mgr, infos)| {
                rt.block_on(async {
                    for (run_id, info) in infos {
                        mgr.register(black_box(run_id), black_box(info))
                            .await
                            .unwrap();
                    }
                });
            },
            BatchSize::SmallInput,
        );
    });
    group.throughput(Throughput::Elements(1));

    // 3. Register a grouped proxy (exercises the extra `groups` write-lock branch).
    group.bench_function("register_with_group", |b| {
        b.iter_batched(
            || (ProxyManager::new(), make_info("pg", "rung", Some("g"))),
            |(mgr, info)| {
                rt.block_on(async {
                    mgr.register(black_box("rung".to_string()), black_box(info))
                        .await
                        .unwrap();
                });
            },
            BatchSize::SmallInput,
        );
    });

    // 4. Measure just constructing a `ProxyInfo` (no register).
    group.bench_function("proxy_info_construct", |b| {
        b.iter(|| {
            black_box(make_info(
                black_box("p0"),
                black_box("run0"),
                black_box(None),
            ));
        });
    });

    group.finish();
}

criterion_group!(benches, bench_proxy_registration);
criterion_main!(benches);
