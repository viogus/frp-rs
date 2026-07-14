//! Micro-benchmarks for NAT hole-punch pipeline.
//!
//! Run all:
//!   cargo bench -p frp-server
//!
//! Filter by name:
//!   cargo bench -p frp-server -- nat_classify
//!   cargo bench -p frp-server -- nat_analysis

use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use std::time::Duration;

// ── NAT classification ─────────────────────────────────────────────────────

fn bench_nat_classify(c: &mut Criterion) {
    let mut group = c.benchmark_group("nat_classify");
    group.throughput(Throughput::Elements(1));

    // Two EasyNAT addresses: same IP, different ports
    let easy_addrs: Vec<String> = vec!["203.0.113.1:1234".into(), "203.0.113.1:5678".into()];
    let local_ips: Vec<String> = vec!["10.0.0.1".into(), "192.168.1.1".into()];

    group.bench_function("classify_easy_nat", |b| {
        b.iter(|| {
            let _ = frp_server::nathole::classify::classify_nat_feature(
                black_box(&easy_addrs),
                black_box(&local_ips),
            );
        });
    });

    // Four addresses: simulate HardNAT (IP changes across addresses)
    let hard_addrs: Vec<String> = vec![
        "203.0.113.1:1234".into(),
        "203.0.113.2:1234".into(),
        "203.0.113.3:1234".into(),
        "203.0.113.4:1234".into(),
    ];

    group.bench_function("classify_hard_nat", |b| {
        b.iter(|| {
            let _ = frp_server::nathole::classify::classify_nat_feature(
                black_box(&hard_addrs),
                black_box(&local_ips),
            );
        });
    });

    // Batch feature count
    let features: Vec<frp_server::nathole::classify::NatFeature> = vec![
        frp_server::nathole::classify::classify_nat_feature(&easy_addrs, &local_ips).unwrap(),
        frp_server::nathole::classify::classify_nat_feature(&hard_addrs, &local_ips).unwrap(),
    ];

    group.bench_function("classify_feature_count", |b| {
        b.iter(|| {
            let _ = frp_server::nathole::classify::classify_feature_count(black_box(&features));
        });
    });

    group.finish();
}

// ── NAT analysis (behavior recommendation) ─────────────────────────────────

fn bench_nat_analysis(c: &mut Criterion) {
    let mut group = c.benchmark_group("nat_analysis");
    group.throughput(Throughput::Elements(1));

    // Both EasyNAT features for mode-0 testing
    let easy_feature = frp_server::nathole::classify::NatFeature {
        nat_type: "EasyNAT".into(),
        behavior: "BehaviorPortChanged".into(),
        ports_difference: 2,
        regular_ports_change: false,
        public_network: false,
    };

    // HardNAT features for mode-1/mode-2 testing
    let hard_regular = frp_server::nathole::classify::NatFeature {
        nat_type: "HardNAT".into(),
        behavior: "BehaviorIPChanged".into(),
        ports_difference: 0,
        regular_ports_change: true,
        public_network: false,
    };

    group.bench_function("get_recommend_easy_easy", |b| {
        let analyzer = frp_server::nathole::analysis::Analyzer::new(Duration::from_secs(3600));
        b.iter(|| {
            let _ = analyzer.get_recommend_behaviors(
                black_box("easy-key"),
                black_box(&easy_feature),
                black_box(&easy_feature),
            );
        });
    });

    group.bench_function("get_recommend_hard_hard", |b| {
        let analyzer = frp_server::nathole::analysis::Analyzer::new(Duration::from_secs(3600));
        b.iter(|| {
            let _ = analyzer.get_recommend_behaviors(
                black_box("hard-key"),
                black_box(&hard_regular),
                black_box(&hard_regular),
            );
        });
    });

    // Cycle through all mode-0 entries (exercises recommend + score rotation)
    group.bench_function("recommend_cycle_mode0", |b| {
        let analyzer = frp_server::nathole::analysis::Analyzer::new(Duration::from_secs(3600));
        // First warm-up to populate records
        analyzer.get_recommend_behaviors("cycle-key", &easy_feature, &easy_feature);

        let mut counter = 0u64;
        b.iter(|| {
            // Rotate key so each iteration gets a fresh entry to avoid score exhaustion
            let key = format!("cycle-{}", counter % 100);
            let _ = analyzer.get_recommend_behaviors(
                black_box(&key),
                black_box(&easy_feature),
                black_box(&easy_feature),
            );
            counter += 1;
        });
    });

    group.bench_function("report_success", |b| {
        let analyzer = frp_server::nathole::analysis::Analyzer::new(Duration::from_secs(3600));
        b.iter(|| {
            analyzer.report_success(black_box("success-key"), black_box(0), black_box(0));
        });
    });

    group.finish();
}

criterion_group!(benches, bench_nat_classify, bench_nat_analysis);
criterion_main!(benches);
