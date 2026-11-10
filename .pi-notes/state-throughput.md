# Throughput program — state

## Landed on main (throughput arc, user: "优化吞吐，差太多了")
- `a4cc86ca` docs(perf): tcpMux frame cost note; default stays 32 KiB (later superseded)
- `5a5dac91` docs(perf): real-host Go-vs-Rust measurement + README Performance section (#600)
- `a6bbea6f` perf(core): bridge buffer 64 KiB, 32 KiB on macOS (#601)
- `0a834028` + `f743255f` perf(core): 64 KiB on every platform (#602) — macOS carve-out removed as harness artifact
- `59b5d544` fix(stress): TCP_NODELAY in echo/throughput/latency mates (#603)
- `43dcb6ea` feat(ci): matrix floors calibrated + enforced, per-platform files (#604)

## Measurement facts (gc VM, 4 vCPU, 8192 MiB one-way, abbench with nodelay)
frp-rs vs Go v0.72.0: mux+TLS 562/399 (+41%), mux 970/647 (+50%), no-mux+TLS 1298/956 (+36%), no-mux 2168/1650 (+31%).
CPU µs/MiB: 3723 vs 5184 (mux+TLS), 2248 vs 3221. RSS 16/15 vs 35/50 MB. Binaries 8.5/7.2 vs 21.3/17.5 MB.
TLS costs ~40% on both stacks.
Buffer 64 KiB vs 32 KiB (same binary): +13.5% mux+TLS, +13.9% ws, +12.8% 1-flow.
macOS streaming: ws 1 flow 1479→2290 (+55%), 4 flows 1793→2380 (+33%), ws+mux 720→1013 (+41%).
Nagle bug: echo peer without TCP_NODELAY collapsed 64 KiB ping-pong 736.8 → 18.0 MiB/s.

## Harness
- gc VM: `/root/bench/` has abbench (sink/stream/pp), ab.sh, ab2.sh, res2.sh, mx.sh, base-bin/, def64-bin/, frp_0.72.0_linux_amd64/, rust clone /root/frp-rs (release + prof-target).
- local: /Users/cdf/kcpbench/ (protoab.sh, abbench-mac, echo-mac, base-bin, profout), scripts/frp-stress.
- matrix: `bash scripts/protocol-matrix.sh --floors scripts/protocol-matrix.floors.macos` on macOS (Linux file fires ws floors on a Mac).

## Open
- KCP Go-vs-Rust stream number (TODO P2 `The KCP Go-vs-Rust stream comparison has no publishable number`).
  Working shape from matrix: frps `kcp_bind_port`, frpc `server_port=<kcp port>` + `transport_protocol="kcp"`; Go: `kcpBindPort`, `transport.protocol="kcp"`, `tcpMux` must match.
  Earlier gc failure: proxy never came up — cause unknown; verified working on macOS via protocol-matrix rows.
- macOS 1-stream 64 KiB ping-pong ~2x slower than Linux: mechanism unexplained (not Nagle, not CPU).
