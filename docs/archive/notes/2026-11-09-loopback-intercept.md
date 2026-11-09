# Loopback TCP interception: a ~1 s accepted-side hold that drops the payload

**Date:** 2026-11-09. **Host:** macOS 27.2 (build 26B123), arm64 (Apple M2),
rustc 1.96.0, Python 3.9.6. **Reported by:** `test_dashboard_proxy_traffic_live`
and `test_v2_proxy_traffic_live_go_shape` failing with
`user reads response: early eof` while the frps relay log showed both directions
copied and shut down correctly.

## 1. Symptom

On this host, data written by the **accepted** socket of a loopback TCP pair is
held back from the **connecting** socket. The hold grows with the payload: tens
of ms above ~512 B, roughly 1 s by 4 KiB. If the accepted side half-closes and
closes before the hold expires, the payload is **discarded** — the connecting
side reads EOF with less than the full write, or with nothing at all.

The direction is one-way. The opposite direction (connecting → accepted) is
unaffected, and Unix-domain sockets are unaffected. Nothing in frp is involved:
both reproductions below are plain sockets.

## 2. Pure `std::net` reproduction

`rustc -O repro.rs && ./repro.rs`:

```rust
use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::time::{Duration, Instant};

fn trial(n: usize, close_delay: Duration) -> (usize, u128) {
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let addr = listener.local_addr().unwrap();
    let w = std::thread::spawn(move || {
        let (mut s, _) = listener.accept().unwrap();
        s.set_nodelay(true).unwrap();
        s.write_all(&vec![0x5A; n]).unwrap();
        if !close_delay.is_zero() {
            std::thread::sleep(close_delay);
        }
        s.shutdown(Shutdown::Write).unwrap();
    });
    let mut c = TcpStream::connect(addr).unwrap();
    c.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    let t0 = Instant::now();
    let mut got = 0usize;
    let mut buf = [0u8; 4096];
    while let Ok(m) = c.read(&mut buf) {
        if m == 0 {
            break;
        }
        got += m;
    }
    let dt = t0.elapsed().as_millis();
    let _ = c.shutdown(Shutdown::Both);
    w.join().unwrap();
    (got, dt)
}

fn main() {
    for n in [512usize, 1024, 2048, 4096, 8192, 65536] {
        for d in [Duration::ZERO, Duration::from_millis(200)] {
            let (got, ms) = trial(n, d);
            println!("{n:>6} B, close after {:>3} ms -> {got:>6} B, EOF @ {ms} ms", d.as_millis());
        }
    }
}
```

Result (`got`, time to EOF):

| accepted-side write | close immediately | close 200 ms after the write |
| --- | --- | --- |
| 512 B (n=1) | 512 B @ 57 ms | 512 B @ 207 ms |
| 1024 B | 1024 B @ 121 ms | 1024 B @ 204 ms |
| 2048 B | 2048 B @ 300 ms | 2048 B @ 291 ms |
| 4096 B | **0 B** @ 1002 ms | 4096 B @ 1000 ms |
| 8192 B | 8192 B @ 998 ms* | 8192 B @ 1008 ms |
| 65536 B | 65536 B @ 997 ms | 65536 B @ 1032 ms |

\* lossy: see §4 — the same 8 KiB trial also returns `0 B` depending on how the
sender's close interleaves with the hold.

## 3. Pure Python reproduction

Same shape in Python 3.9.6 (`socket` + `threading`, `sendall` then
`shutdown(SHUT_WR)` + `close()`), single trial per row:

| accepted-side write | close immediately | close 200 ms after the write |
| --- | --- | --- |
| 512 B (n=1) | 512 B @ 63.5 ms | 512 B @ 210.5 ms |
| 1024 B | 1024 B @ 131.2 ms | 1024 B @ 209.1 ms |
| 2048 B | 2048 B @ 309.3 ms | 2048 B @ 288.8 ms |
| 4096 B | **0 B** @ 1002.6 ms | 4096 B @ 1016.8 ms |
| 8192 B | **0 B** @ 1002.6 ms | 8192 B @ 1007.4 ms |
| 65536 B | 65536 B @ 998.6 ms | 65536 B @ 1007.1 ms |

Both runtimes agree, so this is not a Rust runtime/scheduler effect.

## 4. Size sweep and determinism

Three trials per size, immediate close, Python (`got B @ ms`):

| write | trial 1 | trial 2 | trial 3 |
| --- | --- | --- | --- |
| 1024 B | 1024 @ 110 | 1024 @ 102 | 1024 @ 124 |
| 1536 B | 1536 @ 181 | 1536 @ 178 | 1536 @ 179 |
| 2048 B | 2048 @ 291 | 2048 @ 299 | 2048 @ 304 |
| 2560 B | 2560 @ 433 | 2560 @ 437 | 2560 @ 428 |
| 3072 B | 3072 @ 594 | 3072 @ 607 | 3072 @ 601 |
| 3584 B | 3584 @ 780 | 3584 @ 801 | 3584 @ 782 |
| 4096 B | **0 @ 1003** | 4096 @ 992 | **0 @ 1002** |
| 8192 B | **0 @ 1002** | **0 @ 1005** | **0 @ 1002** |

20 trials at 8 KiB, immediate close: **12/20 returned 0 bytes** at ~1 s; the 8
delivered runs arrived at 991-1000 ms. The hold is therefore not a byte-rate
limit: a 64 KiB write can arrive in the same ~1 s that a dropped 4 KiB write
takes. Loss depends on the close racing the hold.

What is deterministic is the **timing**: an 8 KiB accepted-side write never
reaches the connecting side in under ~990 ms here, whether it is later
delivered or dropped. On an unaffected host the same write completes in well
under 1 ms — orders of magnitude of separation, which is what the suite's probe
keys on (§7).

## 5. Controls

**Direction.** 8 KiB and 64 KiB written *connecting → accepted* (server reads):
complete in 0 ms, payload intact, every trial (3/3 each size). Only the
accepted → connecting direction is intercepted.

**Unix-domain sockets.** Same trial over `AF_UNIX`: 512 B @ 0.1 ms, 8192 B @
0.1 ms. The interception sits in the IP stack, not in socket buffering.

## 6. What is active on the host

`systemextensionsctl list`:

```text
4 extension(s)
--- com.apple.system_extension.network_extension
enabled	active	teamID	bundleID (version)	name	[state]
*	*	8K28G7K6W8	com.foamzou.bytetally.filterext (1.4.3/65)	Bytetally Network Filter	[activated enabled]
		8K28G7K6W8	com.foamzou.bytetally.filterext (1.0.1/24)	Bytetally Network Filter	[terminated waiting to uninstall on reboot]
*	*	YCKFLA6N72	com.nssurge.surge-mac.ne (5.0/40)	Surge Network Extension	[activated enabled]
--- com.apple.system_extension.driver_extension
enabled	active	teamID	bundleID (version)	name	[state]
*	*	G43BCU2T37	org.pqrs.Karabiner-DriverKit-VirtualHIDDevice (1.8.0/1.8.0)	...	[activated enabled]
```

Surge's network extension is active on this host and is the observed
interceptor: the stall-and-drop behaviour matches a transparent proxy holding a
loopback payload for its flush window. Another network filter (Bytetally) is
also enabled and was not A/B'd separately here, so the note records both — the
suite's probe classifies the host behaviourally, it does not attribute it to one
extension.

## 7. What the test suite does about it

Two live-traffic pins push real bytes through a live bridge and assert the
dashboard counters byte-exactly: `frp-server/tests/dashboard_integration.rs`
(`test_dashboard_proxy_traffic_live`) and
`frp-server/tests/dashboard_v2_integration.rs`
(`test_v2_proxy_traffic_live_go_shape`). They are the only live assertions for
`trafficIn`/`trafficOut`.

Skipping them on this host would leave that feature untested exactly where it is
flaky, and libtest swallows a skipped test's `eprintln!` so CI would read `ok`
with zero assertions. Instead `frp-server/tests/common/mod.rs` probes loopback
once per test binary and classifies the host:

- `LoopbackProbe::Ok` — the 8 KiB probe write arrived inside the budget; the
  pins pump their production sizes (`work -> user = 67_891` B).
- `LoopbackProbe::Intercepted` — the write was truncated, short, or held past
  the budget (500 ms: unaffected hosts are sub-millisecond, this host is
  ~1 s). The pins pump `512` B `work -> user` instead and assert exactly
  `512` on every counter; `user -> work` stays at `123_457` B because that
  direction is unaffected.
- `LoopbackProbe::Broken` — bind/connect/setup failed (no usable IPv4
  loopback, sandbox). The pins panic: no traffic assertion can run there, and
  a skip would be a false green.

The probe measures arrival time at the instant the last byte is read, not after
the writer thread joins, and it connects before spawning the writer and shuts
the client socket down before joining it, so neither a failed connect nor a
writer blocked in `write_all` can park a thread forever. The classification
table is unit-tested (`loopback_probe_classifies_every_read_outcome`); the probe
itself needs a real loopback, so a stub that always returned one verdict would
not be caught by that test.

Two limits of the 512 B shrink, recorded so a later reader does not assume full
coverage: 67,891 B crosses `copy_pooled` in three 32 KiB iterations while 512 B
is a single one, so on an intercepting host a `work -> user`-only bug in chunk
accounting or in the linger-armed branch would not show (the `user -> work` arm
still moves 123,457 B through the same `copy_pooled`, and every non-intercepting
host still runs the full 67,891 B). And a `Broken` verdict — a transient
`bind`/`connect` failure such as `EMFILE` — is cached for the whole test binary,
so it panics rather than retrying; that is loud, not a false green.
