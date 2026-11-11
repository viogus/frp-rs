# Reading a whole TLS record per syscall

Date: 2026-11-11. Status: landed (vendored `rustls` patch).

## 1. Where it came from

Profiling a bulk TCP transfer through frps and frpc on a 4-vCPU host
(`perf record -F 499`, `tcpMux` + TLS, 8192 MiB, one flow) put
`Vec::<u8>::resize` — instantiated from the vendored `rustls` crate — at
**16.9% of frpc's samples**, the largest single user-space entry, above
AES-GCM at 10.0%. `clear_page_erms` (the kernel zeroing freshly faulted pages)
was another 4.3%.

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

Cost: the read buffer is allocated per TLS connection, so each connection
carries up to ~14 KiB more than before.

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
