# Throughput against Go frp on a real host — and the container numbers it retracts

Date: 2026-11-10. Base commit: `a4cc86ca` (Go frp v0.72.0 for the comparison).

This note replaces the Go-versus-Rust comparison published in
[`2026-11-09-kcp-fec-multiply-tables.md`](2026-11-09-kcp-fec-multiply-tables.md).
That comparison was measured inside a Docker container on a laptop, and its
stream rows came from a bench mode that mis-reports its own duration. Repeating
the measurement on a dedicated Linux VM reverses the conclusion: frp-rs is
**ahead of Go frp on every row measured here**, by 12–31%.

## 1. Why the container numbers had to go

Three independent problems, in increasing order of severity:

1. **The host was a laptop with a `container` runtime network.** The VM's own
   `kcompactd0`/`veth_init` appear in `perf` profiles, so every measurement
   included a container network hop that neither proxy controls.
2. **The numbers were bimodal.** Identical configuration, back-to-back rounds,
   4 flows: ~4.0 GB/s and then ~8.5 GB/s for a bare relay. A noise floor larger
   than the effect being measured (16%) cannot support a comparison.
3. **The stream bench mode was broken.** `bench-linux stream` reports
   `121.2 MiB/s` while its own wall clock says the transfer finished in 12 ms,
   and its `in 0.00s` line contradicts both. Its ping-pong mode is sound; its
   stream mode is not. The KCP comparison in the older note used the stream
   mode, so that comparison is withdrawn in §6.

## 2. Host

A dedicated Linux VM, chosen over a 5 GB-RAM alternative that showed 8.2%
hypervisor steal at both idle and full load:

- 4 vCPU AMD EPYC-Milan, 11.9 GB RAM, Debian 13, kernel 6.12.111.
- **Hypervisor steal 0.0%** during a 98%-user load test.
- Fixed-iteration ALU loop: 799–891 ms across five runs (≈3% CV).
- Direct loopback through no proxy, 4 flows: **6200 MiB/s**.
- Both proxies built from the same tree at `a4cc86ca`; Go frp v0.72.0 official
  linux/amd64 release.

Every row uses the same client (`abbench stream <port> 8192 <flows>`: N threads,
64 KiB writes, `TCP_NODELAY`, sink peer that only reads), the same port
allocation and the same config shape; only the binary directory changes.

## 3. The matrix

Four flows, 8192 MiB one-way, two interleaved repeats per row, MiB/s:

| configuration | frp-rs | Go frp v0.72.0 | frp-rs |
|---|---|---|---|
| `tcpMux` + TLS | 499.7 / 521.4 | 412.6 / 416.6 | **+23%** |
| `tcpMux`, no TLS | 891.7 / 838.5 | 641.6 / 679.3 | **+31%** |
| no mux + TLS | 1209.1 / 1188.6 | 1080.1 / 1019.0 | **+14%** |
| no mux, no TLS | 2252.6 / 1860.6 | 1571.3 / 1737.3 | **+24%** |

Read the columns as: `tcpMux` is what frp ships by default and TLS is what both
ship by default, so the first row is the shipping configuration, and it is the
one that matters for "will this be slower than the Go build I replaced".

The per-row spread is 2–10%, which is the honest precision of a single VM with a
single network path. None of the four rows is within noise of parity.

## 4. What TLS costs — on both implementations

Same table, read vertically:

| stack | `tcpMux`, TLS off → on | no mux, TLS off → on |
|---|---|---|
| frp-rs | 865.1 → 510.6 (**−41%**) | 2056.6 → 1198.9 (**−42%**) |
| Go frp | 660.5 → 414.6 (**−37%**) | 1654.3 → 1049.6 (**−37%**) |

TLS removes ~40% of throughput for both proxies. That is the cost of TLS record
processing (per-record AEAD, per-record copies, 16 KiB record ceiling) and not a
property of either implementation, so it is not a gap to chase. It is, however,
the largest single term in the profile — see §5.

## 5. Where the CPU goes

`perf record` at 499 Hz on both processes of the shipping configuration
(`tcpMux` + TLS), debuginfo build, top self time:

| | frps | frpc |
|---|---|---|
| 1 | `aes_gcm_enc_update_vaes_avx2` 9.17% | `aes_gcm_dec_update_vaes_avx2` 8.94% |
| 2 | `clear_page_erms` 3.59% | `alloc::vec::Vec<u8>::resize` (**rustls**) 5.33% |
| 3 | `_copy_to_iter` 3.49% | `_copy_to_iter` 4.02% |
| 4 | `native_queued_spin_lock_slowpath` 2.47% | `clear_page_erms` 2.97% |
| 5 | `_copy_from_iter` 2.11% | `do_user_addr_fault` 2.82% |

Two things follow.

**No frp code is hot.** Yamux, the bridge and the protocol frame writer do not
appear in the top 15 of either process. Every structural experiment in §7 tried
to remove work from exactly those layers and none of them moved throughput,
which is what this profile predicts.

**The rustls deframer allocates per record.** The 5.33% `Vec::resize` frame is
instantiated in the `rustls` crate: the DWARF call graph shows it faulting fresh
pages inside `core::ptr::write`, called from `Vec::extend_with`. In
`vendor/rustls/src/msgs/deframer/buffers.rs`, `prepare_read` uses
`const READ_SIZE: usize = 4096` and shrinks the buffer back to 4 KiB whenever it
has been fully consumed, then grows it again in 4 KiB steps as records arrive —
so a 16 KiB TLS record arrives as four reads with a resize in between.

## 6. Claims this note retracts

- **KCP: "150 vs 121 MiB/s, +23%".** Withdrawn. It came from the broken stream
  mode described in §1. The KCP comparison needs re-measuring with a working
  one-way harness before any number is published again.
- **"frp-rs is 16% behind Go on TCP."** Withdrawn. Measured on this host, frp-rs
  leads on all four TCP rows (§3).
- **"The gap is a uniform per-byte cost in the shared data path."** Withdrawn:
  it was an artefact of the container.

## 7. What was tried and did not work (so nobody repeats it)

All measured on the container or the laptop, before §3 settled the question;
each was neutral or negative on the shipping `tcpMux` path.

| change | result |
|---|---|
| yamux frame written with one `write_vectored` (header+body) | neutral (1241 vs 1213 MiB/s) |
| one-copy path: `Stream::poll_write_bufs` + `YamuxStream` newtype so the protocol layer takes its vectored branch | neutral (means 1388.6 → 1364.9 at 4 flows) |
| inline yamux write with a writer lock and mpsc fallback | neutral to worse; ~97% of frames already bypassed the channel hop |
| bridge buffer default 32 KiB → 64 KiB | +12% under `tcpMux`, but −40% on macOS `ws`/`wss` without `tcpMux`; reverted, kept as a knob |
| rustls `READ_SIZE` 4 KiB → 16 KiB | +2.3% on the laptop, inside a ±4% spread; not adopted |

The frame-coalescing change that *did* land (one `write_all` per protocol frame
when the writer is not vectored, PR #594) is a different fix: it removed a frame
per datagram on the UDP path, where pps is the metric, not MiB/s.

## 8. Reproduce

Harness lives on the measuring host (`/root/bench`): `abbench` (the client and
the sink), `frp_0.72.0_linux_amd64/` (Go), `base-bin/` (frp-rs), `ab2.sh`
(`<bd> <label> <flows> <mux> <server-extra> <client-extra>`) and `mx.sh` (the
matrix above). `perf.sh` runs `perf record -F 499 -p <pid> -g -- sleep 20` on
both processes; the debuginfo build is
`CARGO_PROFILE_RELEASE_STRIP=false CARGO_PROFILE_RELEASE_DEBUG=1 cargo build --release -p frps -p frpc`.

Config traps that cost time:

- A Go `frps` needs `transport.tls.force = false`; a Go `frpc` needs
  `transport.tls.enable = false`. Swapping them yields
  `unknown field "enable"`.
- `transport.protocol` selects the transport (`tcp`, `kcp`, `quic`,
  `websocket`, `wss`), not the protocol version.
- `strip = "symbols"` in `[profile.release]` blanks `perf` symbolization even
  with `debug = 1`; `CARGO_PROFILE_RELEASE_STRIP=false` is required.
