# The inline-yamux-write experiment no longer has a target

2026-11-22. Measurement only — nothing ported, no production code changed.

## The experiment that was kept

`docs/archive/notes/2026-11-09-yamux-inline-write.md` measured the UDP-over-mux
data path at **118-119 µs per datagram at one flow** and **135-138 µs at four**
(6,781 pps), against 52-57 µs without mux, and located the cost in the
connection-driver round trip: a stream's `poll_write` queued its frame for the
driver task, which had to be woken, dequeue, encode and flush — a `P3→YF`
segment of **29 µs**. The fix (keep the experiment as
`keep/yamux-inline-write-v2`, 6 commits, ~1,000 lines) let a stream write its
own data frame through the connection's shared writer.

## What the path costs now

Rust↔Rust this time (frps and frpc both from `main` at `31143589`), not the
Rust-client-to-Go-server arrangement of the 2026-11-09 note — so the two tables
are comparable in *shape*, not in absolute terms. Otherwise the same shape: 512 B
datagrams, one saturating blaster per flow, per-flow echo backend, frpc
`workerThreads = 1`, 8 s per rep. µs/datagram is frpc's `ps -o time` delta over
the cell divided by `2 × datagrams` (echoed traffic counts twice); the factor is
a common multiple, so it changes the units and not the ratios.

| arm | flows | pps (reps) | µs/datagram |
|---|---|---|---|
| `tcpMux = true` | 1 | 19,032 / 19,009 / 18,860 | 23.4 / 23.5 / 23.4 |
| `tcpMux = true` | 4 | 14,737 / 11,192 | 31.9 / 30.7 |
| `tcpMux = false` | 1 | 24,067 / 24,330 | 18.0 / 17.8 |
| `tcpMux = false` | 4 | 4,480 / 6,062 | 87.0 / 52.8 |

Host: 8-core macOS, load 3.1-7.5 (the blasters count themselves in that load),
so treat ±30% as noise and read the ratios. Two of the four arms do not carry a
comparable tax: the four-flow no-mux arm collapses to 4.5-6 kpps (0.6-0.8 of
the client's single core, five short-lived proxied connections against one
thread, i.e. it is blocked on connection setup rather than bandwidth),
so "mux is cheaper at four flows" is a client-starvation artifact and is not
evidence against mux. Only the one-flow pair compares like with like: **1.31×**
(23.4 µs against 17.9). An RTT-bound ping-pong arm shows the same thing from
the other side: 1,974-2,008 pps with mux against 2,013-2,040 without, ~500 µs
RTT in both.

## Why the target is gone, and what is left

The experiment's own note already discounted part of its target: the writer-task
to connection-driver hand-off "was never the dominant term"
(`docs/archive/notes/2026-11-09-yamux-inline-write.md:202`), and the 29.1 µs it
quoted was the **flush** segment (`P3→YF`), not the hop. The hop itself measures
4.0 µs mean on `main` (5,000-datagram yamux ping-pong probe, `hop_mean_us=4.02`
at every sample point, max 510.7 µs) — an order of magnitude below the 29 µs
that motivated the work, and consistent with the old note's own reading. So the
total did not merely shrink around a constant cost; the platform moved the work.

The driver round trip this experiment removes has also lost its payload.
PR #594 (`b2655ccd`) split `frame::Io` into a `Reader<R>` and a `Writer<W>`
with a control-then-data queue and one frame in flight
(`vendor/yamux/src/frame/io.rs:40`, `:75`, `:139`); the control-then-data
queue is `vendor/yamux/src/connection.rs:346`, added `ConnWriter` — a
write mutex with an owner-wake handshake (`vendor/yamux/src/connection.rs:352-410`)
— and `Connection::new_split` (`:123`), consumed by frp's mux driver at
`frp-core/src/mux.rs:751` and `:976`. Its commit message ends
"…and *(next)* every stream share": the stream half was never taken, so
`Stream::poll_write` (`vendor/yamux/src/connection/stream.rs:388-444`) still
queues to the driver.

That half is therefore portable — and worth nothing measurable today, because
the cost it removes is no longer in the number it was found in. It is also
larger than "one function": the unported remainder of the kept branch is ~510
lines across `connection/stream.rs` and `connection.rs` — on that branch a
`try_lock` at `connection.rs:401`, `wait_for_flush` at `:415`, the rewritten
`WriteGuard::drop` at `:498-520` and `note_frame_taken` at `:868`, none of which
exist on `main` — on a crate
that has moved 523 insertions since. Porting that to chase a segment that no
longer dominates fails the same test the earlier experiment passed: measure the
cost, then fix it.

## Reopen trigger

Re-measure before reopening, with reps: this host's own spread is ±30%, so the
1.31× above is consistent with anything from 0.9× to 1.7× and a single cell
cannot resolve a threshold near it. Reopen if the one-flow tax exceeds 1.5×
across interleaved reps *and* the hop has grown back (the ping-pong probe's
`hop_mean_us`, several thousand samples, is the cheapest watch). Neither the UDP probe nor the hop probe is in the tree — both were run
from `/tmp`, which is the main weakness of this note; if either is needed again,
add it to `scripts/frp-stress` as a `udp` scenario rather than rebuilding it.

## What this does not establish

- Only loopback, one client thread, and a saturating sender per flow. A
  latency-shaped workload (small datagrams, few in flight, waiting for a reply)
  exercises the driver wake differently than a saturating one, and the
  ping-pong arm is a crude stand-in.
- The CPU column counts frpc only. A separation between protocol work and
  driver wake would need per-task accounting, not `ps`.
- Two of the four arms in the table (four flows without mux) are client-starved
  and are printed for completeness, not as evidence.
- The hop measurement is a 5,000-datagram ping-pong, which is RTT-shaped rather
  than saturating; it bounds the hand-off cost, it does not reproduce the
  datagram path's mix.
