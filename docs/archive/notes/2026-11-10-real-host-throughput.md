# Throughput against Go frp on a real host — and the container numbers it retracts

Date: 2026-11-10. Base commit: `a4cc86ca` (Go frp v0.72.0 for the comparison).

This note replaces the Go-versus-Rust comparison published in
[`2026-11-09-kcp-fec-multiply-tables.md`](2026-11-09-kcp-fec-multiply-tables.md).
That comparison was measured inside a Docker container on a laptop, and its
stream rows came from a bench mode whose own outputs contradict each other.
Repeating the measurement on a Linux VM with a measured noise floor reverses the
conclusion: frp-rs is **ahead of Go frp on every row measured here**, by 14–31%
on row means.

## 1. Why the container numbers had to go

Two problems, both of which this note can show rather than assert:

1. **The numbers were bimodal.** Identical configuration, back-to-back rounds,
   4 flows through a bare relay: 4.0 GiB/s in one round and 8.5 GiB/s in the
   next. A noise floor larger than the effect being measured (15–17%) cannot
   support a comparison.
2. **The stream bench mode was broken.** A run of the old `bench-linux stream`
   printed three mutually inconsistent things: `121.2 MiB/s` for a 256 MiB
   transfer (which implies 2.11 s), an elapsed time of `in 0.00s`, and a process
   that exited in 12 ms. It cannot be said which field is wrong — only that the
   transfer those rows claim did not take place as reported, so the rows are not
   usable. Its ping-pong mode is unaffected: its duration agrees with wall clock,
   which is why the ping-pong rows survive in the KCP note.

**Scope of the retraction.** What does not survive: cross-implementation
*absolutes and ratios* measured in that container. What does survive, and is
still relied on below and elsewhere: same-binary A/B deltas measured within one
window, interleaved, that reproduced across three or more runs (the
frame-cost table, the 64 KiB buffer deltas, the UDP pps pairs). Those are comparisons of
two builds on the same host at the same moment, which is a different question
from "which implementation is faster".

## 2. Host

A Linux VM, chosen over a 5 GB-RAM alternative that showed 8.2% hypervisor steal
at both idle and full load:

- 4 vCPU AMD EPYC-Milan, 11.9 GB RAM (8 GB available), Debian 13, kernel
  6.12.111, 42 GB disk free.
- **Hypervisor steal stayed at 0** in `/proc/stat`'s steal ticks (1-centisecond
  resolution, so this means below that, not "proven zero") while a four-thread
  ALU loop held the box at 98% user.
- Fixed-iteration ALU loop: 799–891 ms across five runs. That is about 11%
  run-to-run, so this host supports comparing arms within one sitting, not
  quoting differences below ~5%.
- Direct loopback through no proxy, 4 flows: 6200 MiB/s — one sample, quoted as
  a ceiling, not as a measurement with an error bar.
- The vCPUs are a shared cloud shape; "quiet", not "exclusive", is the claim the
  steal number supports.
- Both **frp-rs** proxies built from the same tree at `a4cc86ca`; Go frp v0.72.0
  is the official linux/amd64 release.

Reader and writer in every row are my own client `abbench` (`stream` mode: N
threads, 64 KiB writes, `TCP_NODELAY`, total bytes split evenly across threads)
and its `sink` peer, which only reads. `abbench` is a different program from the
old `bench-linux` of §1(2): it times from the first write to the last completed
write and divides the byte count by *that* elapsed time. The two are
distinguishable per row — `8192 MiB ÷ printed elapsed` reproduces the printed
rate to within rounding on every row below.

## 3. The matrix

Four flows, 8192 MiB total per run (2048 MiB per flow), two interleaved repeats
per row. Cells are the two repeats, in MiB/s; the last column is computed from
the row means.

| configuration | frp-rs | Go frp v0.72.0 | frp-rs lead (means) |
|---|---|---|---|
| `tcpMux` + TLS | 499.7 / 521.4 | 412.6 / 416.6 | **+23%** |
| `tcpMux`, no TLS | 891.7 / 838.5 | 641.6 / 679.3 | **+31%** |
| no mux + TLS | 1209.1 / 1188.6 | 1080.1 / 1019.0 | **+14%** |
| no mux, no TLS | 2252.6 / 1860.6 | 1571.3 / 1737.3 | **+24%** |

Read the columns as: `tcpMux` is what frp ships by default and TLS is what both
ship by default, so the first row is the shipping configuration, and it is the
one that matters for "will this be slower than the Go build I replaced".

**Precision, from this table's own spread.** Repeat-to-repeat deviation is
1–6% of the row mean on rows 1–3 and 10–19% on row 4 (`no mux, no TLS`, where
the frp-rs pair is 2252.6 vs 1860.6). Pairing the worst frp-rs repeat against the
best Go repeat — the most hostile pairing the data allows — gives +19.9%, +23.4%,
+10.0% and +7.1%. So: the *direction* is robust (all eight rep-pair ratios are
positive, 7.1%–43.4%), the row means are the best estimate, and the no-mux rows
are not precise to better than ~10 points. The shipping row is the tightest of
the four.

## 4. What TLS costs — on both implementations

Same table, read vertically; each cell is the mean of that row's two repeats:

| stack | `tcpMux`, TLS off → on | no mux, TLS off → on |
|---|---|---|
| frp-rs | 865.1 → 510.6 (**−41%**) | 2056.6 → 1198.9 (**−42%**) |
| Go frp | 660.5 → 414.6 (**−37%**) | 1654.3 → 1049.6 (**−37%**) |

TLS removes ~40% of throughput for both proxies. That is the cost of TLS record
processing (per-record AEAD, per-record copies, 16 KiB record ceiling) and not a
property of either implementation, so it is not a gap to chase. It is, however,
where most of the measurable CPU goes — see §5.

## 5. Where the CPU goes

`perf record -F 499 -p <pid> -g -- sleep 20` on both processes of the shipping
configuration (`tcpMux` + TLS), debuginfo build. One record per process, roughly
10,000 samples each, so each percentage carries about ±0.3 points and rows below
about 4% are not separable from each other. Percentages are **self time**; with
`debug = 1` and inlining, a callee can be attributed to its caller, which is why
the absence in the last row of the table below is stated as "not in these rows"
rather than "does not run".

| | frps | frpc |
|---|---|---|
| 1 | `aes_gcm_enc_update_vaes_avx2` 9.17% | `aes_gcm_dec_update_vaes_avx2` 8.94% |
| 2 | `clear_page_erms` 3.59% | `alloc::vec::Vec<u8>::resize` (**rustls**) 5.33% |
| 3 | `_copy_to_iter` 3.49% | `_copy_to_iter` 4.02% |
| 4 | `native_queued_spin_lock_slowpath` 2.47% | `clear_page_erms` 2.97% |
| 5 | `_copy_from_iter` 2.11% | `do_user_addr_fault` 2.82% |

The five rows shown account for about 21% (frps) and 24% (frpc) of samples; the
rest is spread thin, which is the observation that matters and the one the
structural experiments in §7 confirm. In the full top 15, no yamux, bridge or
protocol-frame-writer frame appears for either process.

**The rustls deframer allocates per record.** The 5.33% `Vec::resize` frame is
instantiated in the `rustls` crate: the DWARF call graph shows it faulting fresh
pages inside `core::ptr::write`, called from `Vec::extend_with`. In
`vendor/rustls/src/msgs/deframer/buffers.rs`, `prepare_read` uses
`const READ_SIZE: usize = 4096` and shrinks the buffer back to 4 KiB whenever it
has been fully consumed, then grows it again in 4 KiB steps as records arrive —
so a 16 KiB TLS record arrives as four reads with a resize in between.

## 6. Claims this note retracts

- **KCP: "150 vs 121 MiB/s, +23%".** Withdrawn. The two numbers are `149.5 vs
  121.2` (single-flow) and `150.7 vs 128.9` (four-flow) — the quoted triple
  matched neither — and both came from the broken stream mode of §1(2). The KCP
  comparison needs re-measuring with a working one-way harness before any number
  is published again.
- **"frp-rs is 16% behind Go on TCP."** Withdrawn. Measured on this host, frp-rs
  leads on all four TCP rows (§3). The 15–17% figure this referred to was a
  container ratio.
- **"~17% behind on the plain bridge" / "23.9% behind at the shipped 32 KiB
  default" (`2026-11-10-mux-frame-cost.md` §1, §7) and "mux is ~15% behind Go"
  (`2026-11-08-mux-throughput-scaling.md` §3).** Withdrawn for the Linux
  comparison: all three were container or laptop ratios, not re-measured here.
  Both notes now carry a scope banner pointing at §3.
- **"The gap is a uniform per-byte cost in the shared data path."** Withdrawn: it
  was an artefact of the container.

## 7. What was tried and did not work (so nobody repeats it)

All measured before §3 settled the question; each was neutral or negative on the
shipping `tcpMux` path. The deltas here are same-binary A/B comparisons, which
§1 keeps in scope.

| change | result |
|---|---|
| yamux frame written with one `write_vectored` (header+body) | neutral (1 flow 1241 vs 1213; 4 flows 1337 vs 1340 MiB/s) |
| one-copy path: `Stream::poll_write_bufs` + `YamuxStream` newtype so the protocol layer takes its vectored branch | neutral (means 1388.6 → 1364.9 at 4 flows) |
| inline yamux write with a writer lock and mpsc fallback | **−9%** (1274.9 vs 1400 MiB/s at 4 flows) |
| bridge buffer default 32 KiB → 64 KiB | +12% under `tcpMux`, but −40 to −45% on macOS `ws`/`wss` without `tcpMux`; measured, not adopted (the default stays 32 KiB) |
| rustls `READ_SIZE` 4 KiB → 16 KiB | +2.3% on the laptop, inside a ±4% spread; not adopted |

The frame-coalescing change that *did* land (one `write_all` per protocol frame
when the writer is not vectored, PR #594) is a different fix: it removed a frame
per datagram on the UDP path, where pps is the metric, not MiB/s.

## 8. Limits

- **The win is measured in a CPU-bound regime.** Four vCPUs are shared by
  client, sink and both proxies, so the side that burns fewer CPU-cycles per byte
  wins. On an 8-core M2 the opposite ordering was measured once with the
  mechanism stated: frp-rs used ~36% less CPU (23 s vs 36 s) while Go pushed more
  bytes through the same single-session shape by spending more cores
  (`2026-11-08-mux-throughput-scaling.md` §3). That measurement is a different
  workload (strict ping-pong) and was never re-run on this host; on a wide host
  with idle cores the ordering could invert.
- One host, one network path, two repeats. The shipping row is the tightest; the
  no-mux rows are the loosest.
- TLS on both sides is the default but not a requirement; §4 quantifies what
  disabling it buys before it is worth considering.

## 9. Reproduce

Harness lives on the measuring host (`/root/bench`), not in this repository:
`abbench` (client and sink), `frp_0.72.0_linux_amd64/` (Go), `base-bin/` (frp-rs),
`ab2.sh` (`<bd> <label> <flows> <mux> <server-extra> <client-extra>`) and `mx.sh`
(the matrix above). `perf.sh` runs
`perf record -F 499 -p <pid> -g -- sleep 20` on both processes; the debuginfo
build is
`CARGO_PROFILE_RELEASE_STRIP=false CARGO_PROFILE_RELEASE_DEBUG=1 cargo build --release -p frps -p frpc`.

Config traps that cost time:

- A `frps` takes `transport.tls.force`, a `frpc` takes `transport.tls.enable`.
  Swapping them yields `unknown field "enable"`. (Both implementations accept the
  same roles: `frp-core/src/config/normalize.rs` maps the server's `force` to
  `tls_only` and the client's `enable` to `tls_enable`.)
- `transport.protocol` selects the transport (`tcp`, `kcp`, `quic`,
  `websocket`, `wss`), not the protocol version.
- `strip = true` in `[profile.release]` (`Cargo.toml`) blanks `perf`
  symbolization even with `debug = 1`; `CARGO_PROFILE_RELEASE_STRIP=false` is
  required.
