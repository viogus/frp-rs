---
date: 2026-11-11
---

# One `sendmmsg` per KCP flush (+4.4% on a bulk stream)

A KCP flush does not produce one datagram — a 1326-byte MSS turns one 16 KiB
input burst into about thirteen data segments, and a completed 10-shard group
adds three parity shards on top (~16 datagrams), each sent with its own
`sendto(2)`. Batching them costs one syscall per flush instead.

## Result

Linux VM, both ends frp-rs at the previous commit, 2048 MiB one-way stream,
`tcpMux` on, TLS on, one flow (four interleaved pairs) and four flows (one pair):

| run | before | after | change |
|---|---|---|---|
| 1 flow, pair 1 | 59.3 | 60.6 | +2.2% |
| 1 flow, pair 2 | 58.1 | 61.9 | +6.5% |
| 1 flow, pair 3 | 59.1 | 60.9 | +3.0% |
| 1 flow, pair 4 | 58.5 | 61.9 | +5.8% |
| **1 flow, mean** | **58.8** | **61.3** | **+4.4%** |
| 4 flows | 59.4 | 61.6 | +3.7% |

CPU ticks from `/proc/<pid>/stat` (100 Hz) fell with throughput in the same
runs — pair 2: 4034+4122 → 3797+3893 ticks, i.e. ~81.6 s of CPU over 35 s wall
(2.33 of the guest's 4 vCPU) — so the win is not bought with work elsewhere. Every pair moved the
same direction, which is what separates this from the +2.3% on the rustls
read-buffer experiment that was discarded.

## What changed

`frp-core/src/kcp/socket.rs`: `send_udp_batch` builds one `mmsghdr` per datagram
(all targeting the same peer, which a flush guarantees), issues a single
`sendmmsg(2)` and returns how many the kernel took. `send_packets` — shared by `flush_session_output` and the 10 ms tick that
carries ACKs and retransmissions — recycles the sent buffers into the chunk pool
and hands the remainder to the existing one-at-a-time path, which already queues
on `EWOULDBLOCK` into `pending_udp`. Ordering is unchanged: the pending queue is drained before the
flush, and the remainder is pushed after it in flush order.

The helper declines (`returns 0`, ordinary path) when there is only one packet,
so the single-datagram case keeps its current syscall count.

Platform scope: `sendmmsg` is Linux-only here. macOS and Windows keep the loop;
`sendmmsg` exists on neither (`sendmsg_x`/`WSASendMsg` are different APIs) and
neither was measured.

## Limits

- One host, one transport shape, loopback inside a virtualised guest. The
  absolute numbers are not transferable; the paired deltas are.
- One run per pair, four interleaved pairs: the sign agrees four times out of
  four, but a per-pair delta of this size is not far from the ±3% the host shows
  between runs of the same binary.
- The batch path allocates two small vectors per flush (≈13 iovecs and 13
  `mmsghdr`s, ~1 KB for a 16 KiB burst) where the scalar loop allocated nothing.
  That cost is inside the measured +4.4%; it is not free, and for flushes of two
  or three packets it can exceed the syscall it saves.
- The gain is per syscall avoided, so it shrinks with larger MSS, smaller FEC
  overhead, or a host where a syscall is cheaper. It should be re-measured if
  either changes.
- `sendmmsg` with a partially filled `msg_vec` sends a prefix, not a subset —
  the code relies on that (it recycles `packets[..sent]`), and the test asserts
  the delivered datagrams are the same bytes in the same order.

## Verification

- `cargo test -p frp-core --all-features --lib send_udp_batch` — run on the
  Linux measurement host and in the `Tests (unit)` lane; the module is
  `#[cfg(target_os = "linux")]`, so on macOS it is not compiled at all. The full
  `frp-core` library suite passes too.
- Two Linux-only tests: `send_udp_batch_delivers_all_packets_in_order` (five
  datagrams of different lengths arrive intact and in order, over IPv4 and
  IPv6) and `send_udp_batch_declines_a_single_packet`. A *partial* `sendmmsg` is
  not deterministically inducible on loopback, so the sent-prefix accounting is
  covered by construction, not by a test.
- Cross-compat: the batch path changes no wire bytes — the datagrams are the
  same ones `sendto` carried — so `scripts/compat-test.sh` is unchanged.

## Reproduce

`/root/bench/kcp3.sh` on the measurement host: it writes both configs (frp-rs
`kcp_bind_port`, client `server_port` + `transport_protocol = "kcp"`, matching
`tcp_mux`), runs `abbench sink` behind one proxy and `abbench stream` through
it, and prints MiB/s plus CPU ticks from `/proc/<pid>/stat`.
