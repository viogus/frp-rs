# Reading a whole TLS record per syscall

Date: 2026-11-11. Status: landed (vendored `rustls` patch).

## 1. Where it came from

Profiling a bulk TCP transfer through frps and frpc on a 4-vCPU host
(`perf record -F 499`, `tcpMux` + TLS, 8192 MiB, one flow) put
`Vec::<u8>::resize` — instantiated from the vendored `rustls` crate — at
**16.9% of frpc's samples**, the largest single user-space entry, above
AES-GCM at 10.0%. `clear_page_erms` (the kernel zeroing freshly faulted pages)
was another 4.3%.

A smaller trial had already pointed this way and been filed as a negative
result: raising the same constant to 16 KiB on a laptop measured +2.3%, inside
a ±4% spread, so it was dropped (`2026-11-10-real-host-throughput.md` §7). That
value could not work: a full application record is 16 384 B of payload plus a
5-byte header and a 16-byte AEAD tag = **16 405 B** of wire, so a 16 KiB window
still needed two reads *and* still grew the buffer to 18 437 B and shrank it
back every record — the churn the patch is meant to remove. `MAX_WIRE_SIZE`
(18 437 B) is the size the deframer already grows to, so it removes the cycle
instead of shortening it.

The cause is in `DeframerVecBuffer::prepare_read`
(`vendor/rustls/src/msgs/deframer/buffers.rs`): upstream reads in 4 KiB steps
(`const READ_SIZE: usize = 4096`) and, whenever the buffer is empty,
`shrink_to`s it back to that size. A 16 KiB application write therefore arrives
as four reads, and the capacity grown for one record is freed and re-faulted for
the next.

## 2. Change

One constant: `READ_SIZE` becomes `MAX_WIRE_SIZE` (18 437 B), so the deframer
asks for a whole record per `read(2)` and its buffer stops oscillating. Nothing
about record sizes, the key schedule, certificate handling or the wire format
changes; the patch is 7 lines including the comment.

Cost: each TLS connection keeps an 18 437 B deframer buffer for its lifetime
(its first read allocates it), ~14 KiB more than the 4 KiB window, whatever the
record sizes on that connection — a 10 000-connection frps holds ~140 MiB more.
It is not a peak: upstream also grows to 18 437 B whenever a full record is
buffered. A second, transient effect: `received_plaintext`'s 16 KiB soft limit is
checked once per `read_tls`, so the worst-case plaintext overshoot grows by about
one record — bounded, and frp drains the plaintext buffer between reads.

## 3. Result

Separate `frps` and `frpc` processes, loopback on a 4-vCPU AMD EPYC-Milan VM,
`abbench` one-way stream, `tcpMux` + TLS on both sides, interleaved A/B with the
same client, CPU from `/proc/<pid>/stat` (100 Hz ticks, both processes summed).

One flow, 4096 MiB, eight pairs (two invocations of four):

| pair | before | after |
| --- | --- | --- |
| 1 | 551.4 | 580.2 |
| 2 | 567.8 | 611.9 |
| 3 | 536.4 | 589.2 |
| 4 | 591.4 | 572.5 |
| 5 | 546.2 | 587.0 |
| 6 | 541.2 | 550.8 |
| 7 | 543.1 | 553.2 |
| 8 | 555.2 | 576.2 |
| mean | 554.1 | 577.6 |
| CPU ticks | 1335 | 1271 |

**+4.2% throughput, −4.8% CPU**, seven of eight pairs positive.

Four flows, three pairs: 612.1 / 567.1 / 560.6 before (mean 579.9) against
613.0 / 596.0 / 591.8 after (mean 600.3) — **+3.5%**, CPU 1494 → 1418 (−5.1%).

## 4. Limits

- One host, loopback, one and four flows; no wide-area path was measured.
- The gain is a syscall and page-fault effect, so it scales with record size and
  connection count, not with bandwidth: a workload that sends 1 KiB records
  should see much less.
- The absolute numbers move ±3% between sessions on this VM; the paired ratios
  are the measurement.
- The memory axis is documented by arithmetic, not measured: the deframer buffer
  is one compile-time constant per connection, so the delta is exactly
  18 437 − 4 096 = 14 341 B × live TLS connections and cannot vary with load.
  `scripts/memory-baseline.sh` was not run for it (it needs a `mem-profile`
  build and measures steady-state traffic, where a fixed per-connection buffer
  is below its resolution); the connection count is the operator's input.
- `scripts/protocol-matrix.sh` on macOS after the change: 11/11 rows above their
  floors (`tcp-tls` 366.1, `tcp-tls-mux` 305.7 MiB/s), no regression in the
  WebSocket rows.

## 5. Reproduce

```bash
# /root/pr7 = the parent commit's release build, /root/tb = this one
for i in 1 2 3 4; do bash /root/bench/tcmp.sh /root/pr7 base 1; \
                     bash /root/bench/tcmp.sh /root/tb tlsbuf 1; done
```

`tcmp.sh` writes a TLS-forced server config and a TLS client config with one TCP
proxy, starts `abbench sink` on 19054, waits for the proxy port 19056, then runs
`abbench stream 19056 4096 <flows>` and prints MiB/s plus the summed CPU ticks.

## 6. What was tried next, and did not ship

With the deframer fixed, the largest remaining user-space entry on the sending
side was `Vec::<u8>::resize` from rustls again — 7.2% of frpc's samples — this
time in `ChunkVecBuffer::append_limited_copy`, which allocates one `Vec` per
record (`ChunkVecBuffer` drops it once written). A third patch that recycles the
drained chunk into a `spare` buffer (so the 16 KiB memset disappears) measured:

| shape | before | after | delta |
| --- | --- | --- | --- |
| one flow, both orders, 8 pairs | 529.0 | 556.8 | **+5.3%** (CPU −3.2%) |
| four flows, both orders, 7 pairs | 558.3 | 561.6 | +0.6% (noise) |

It was **not adopted**: the gain is single-connection only, while each TLS
connection would hold up to two spare record buffers (~32 KiB), i.e. ~320 MiB at
10 000 connections — a worse trade than the read-size patch above, which buys
+4.2% everywhere for ~14 KiB. The branch (`perf/tls-send-buffer-reuse`) keeps
the patch if the memory trade ever looks acceptable.

**Method note (applies to every A/B in these notes):** this harness has a
position bias. Measuring base-then-variant only, the four-flow change looked like
−2.7%; measuring variant-then-base gave +4.0% for the same pair of builds, and
the two orders cancel to +0.6%. Any A/B here must be run in **both orders** (or
at least interleaved with the order flipped), otherwise the second process in the
pair looks faster regardless of what changed.
