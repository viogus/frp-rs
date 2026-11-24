# Skipping the empty KCP `Flush` moves nothing measurable

**Status:** measured, not adopted (2026-11-24).

## The claim

`KcpSocket::handle_flush` (`frp-core/src/kcp/socket.rs:376`) runs
`flush_carry` + `flush_session_output` for every `WriteRequest::Flush`, and
`flush_session_output` calls `force_flush`, which runs KCP's `update()` and
`flush()` — a `snd_buf` walk and an `acklist` walk — whether or not the session
has anything to put on the wire.

That is a real pathology, not a hypothetical one. The `tcpMux` producer flushes
at the end of every write-burst pass, and on the shape where the pathology was
first noticed (a single small tunnel) the client issued **247,477 flush requests
to carry 339 KB** — ~18k wakeups/s, every batch at depth 1
(`docs/archive/notes/2026-11-23-kcp-write-batch-deeper.md` §6). A flush needs no
data to be expensive; it needs only to be frequent.

## The change

Three small pieces, enough to make the predicate cheap:

- `Kcp::would_emit(&self) -> bool` (`frp-core/src/kcp/protocol.rs`) —
  `!snd_buf.is_empty() || !snd_queue.is_empty() || !acklist.is_empty() ||
  probe & (KCP_ASK_SEND | KCP_ASK_TELL) != 0`.
- `KcpSession::flush_would_emit(&self)` — the above, plus a non-empty `carry`
  (a half-segment tail is exactly what `poll_flush` exists to push out).
- `KcpSocket::handle_flush` — when `pending_udp` is empty and the session has
  nothing to emit, skip `flush_session_output` and still resolve the oneshot.
  The ACK half of the flush is preserved by construction: a session with an
  `acklist` entry reports `would_emit() == true` and takes the normal path.

## What was measured

`gc` (4 vCPU, loopback), 8 streams, KCP + TLS + `tcpMux`, 8 s runs, 4
interleaved pairs per session, arm order flipped each pair. Throughput in MiB/s,
`cpuC`/`cpuS` = mean cores of frpc/frps during the run.

| session | arm | runs | mean | cpuC | cpuS |
|---|---|---|---|---|---|
| 1 | baseline | 133.3 / 142.9 / 147.1 / 143.0 | 141.6 | 1.42 | 1.77 |
| 1 | skip | 147.5 / 150.2 / 149.3 / 151.8 | **149.7 (+5.7%)** | 1.42 | 1.76 |
| 2 | baseline | 154.0 / 154.7 / 151.2 / 140.3 | 150.1 | 1.44 | 1.74 |
| 2 | skip | 147.7 / 145.1 / 144.0 / 151.1 | **147.0 (−2.0%)** | 1.42 | 1.76 |

Session 1 says +5.7% (4/4 positive), session 2 says −2.0% (1/4). Pooled means
are 145.9 vs 148.4, i.e. **+1.7%** — inside the ±6% resolution this host has
shown on every earlier round, and the two sessions disagree in sign. CPU is flat
within 0.7%.

The mechanism did fire, so a null result is not "the code never ran". A trace
run of the same shape (136.1 MiB/s) counted:

| side | flushes skipped | flushes sent | skip rate |
|---|---|---|---|
| frpc | 2,696 | 19,129 | **12.4%** |
| frps | 54 | 37,062 | 0.15% |

## Why it does not pay

The flush path is not where the time is. The 2026-11-23 profile of the same
shape put `force_flush` at **6.8% inclusive** of frps CPU, against 63.7% in
`send_packets` — and that was a *bulk* run, where most flushes carry data. On
the client the flush slice is smaller still. Twelve percent of a low-single-digit
share is a fraction of a percent: below anything this host can resolve without
a per-`Flush` cycle count, which would cost more to instrument than the answer is
worth.

What the kernel charges for is the datagram, and this change does not remove
one. That is the same wall the write-batching round hit
(`docs/archive/notes/2026-11-23-kcp-write-batch-deeper.md`): KCP sends ~54
datagrams per `sendmmsg`, MTU-sized, and 10+3 FEC adds a third more.

## What would move it instead

Nothing in the flush path. The live lever is the sender thread's **CPU per
MiB** — 0.0089 → 0.0123 cores per MiB/s, which is why a saturated host runs ~5%
behind even though a single tunnel gains 17% (`TODO.md` § "The KCP sender thread
buys throughput with CPU"). That item owns the next measurement.

One mechanism note worth keeping: the "18k flushes/s to move 30 KB/s" figure is
a *small-tunnel* shape. On this bulk shape the same client makes **2,728
flushes/s** — frequent, but not pathological, and only 12% of them empty.

## Reproduce

```bash
# on gc, with /root/bin-base (baseline) and /root/bin-flush (patched) built
/root/flush-ab.sh 4 8 8            # 4 interleaved pairs, 8 s, 8 streams

# skip rate
RUST_LOG=frp_core::kcp::socket=trace /root/bin-flush/frpc -c c.toml
grep -c "flush skipped" frpc.log    # vs "flush sent"
```

The patch is not on `main`; it lives in the stash
`kcp: skip the flush that carries nothing`.
