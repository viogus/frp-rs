//! Test-only helpers shared by the `#[tokio::test(start_paused = true)]`
//! socket-deadline pins in this module tree (`plugin::http`,
//! `plugin::https2http`, `plugin::https2https`).
//!
//! Why this exists (TODO.md: "`frp-client`'s `start_paused` socket-deadline
//! tests are flaky on this host"). Those pins used to wrap the client-side
//! read in ONE `tokio::time::timeout(BOUND, ...)` and accept only `Ok(0)`.
//! That was wrong in two independent ways, and a naive "step the clock
//! yourself" rewrite is wrong in a third — all three are handled below.
//!
//! * **FIN vs RST.** A handler that releases a stalled peer by dropping the
//!   connection while the peer's bytes are still unread in its receive queue
//!   makes the OS send RST, not FIN, so the peer's read returns `ECONNRESET`.
//!   That is a *successful* release, and the old `Ok(Err(e))` arm reported it
//!   as a failure. Synthetic probe on macOS arm64: a server that closes with
//!   the peer's 5 bytes unread produced `ECONNRESET` 5/5 times; one that
//!   reads them first produced `Ok(0)` 5/5 times. That is the form the
//!   *trickler* pin's pre-fix failures originally took — 10 of 60 runs in the
//!   run that found it; a later 120-run old-shape sample saw none, so treat
//!   that count as a discovery sample rather than a rate. The head window can
//!   fire just after a byte the 59 s trickle delivered, and the drop then
//!   leaves that byte unread. The TLS pins' acceptor consumes the
//!   3-byte partial ClientHello on the accept future's first poll, so a FIN —
//!   clean EOF — is what they see. Measured post-fix, 60 runs per pin: EOF
//!   180/180, `ECONNRESET` 0/180.
//! * **Auto-advance ordering.** While the clock is paused, tokio's time
//!   driver parks the I/O driver with a zero timeout and, if that park did
//!   not unpark the runtime (`!handle.did_wake()`), advances the virtual
//!   clock by the *whole* distance to the next timer
//!   (`tokio/src/runtime/time/mod.rs`, `park_internal` +
//!   `park_thread_timeout`). With the old single far-away `BOUND` as the only
//!   timer the TLS pins owned, the clock could advance toward it in a single
//!   step rather than marching alongside the handler's own window. Two
//!   independent 12-run old-shape samples of the https2http pin agreed on the
//!   substance but not the split: the failing runs first polled the
//!   per-connection handler task at virtual t=69.63-69.95 s, so its 60 s
//!   window (armed on that first poll) fired at ~129.6 s — past the 70 s
//!   bound — while passing runs polled it at t=0 and instead armed the
//!   *bounded accept* at ~8 ms. One sample saw the listener accept on every
//!   run, the other in 11 of 12. What matters, and what the fix removes, is
//!   that the handler was sometimes not polled until ~69.6 s of virtual time
//!   had already passed, which is not the outer bound's own 70 s — so the
//!   advance was not literally "straight to the only timer". (The trickler
//!   owns the trickle task's repeating 59 s sleep as well, which caps the
//!   jump at 59 s; its observed failure form was the RST arm above.)
//! * **Real-time adequacy.** One slice of the wait below costs exactly one
//!   park, and a park that finds no I/O advances the clock by one slice — so
//!   a virtual budget of `b` buys `b / slice` polls, and each poll costs a
//!   few microseconds of real time. At a 250 ms slice the 10 s between the
//!   handler's 60 s deadline and the 70 s bound bought only ~40 polls
//!   (~0.2 ms of real time) for the kernel to deliver the close and wake the
//!   reactor — measured insufficient by review (6 failures in 10,394 runs at
//!   host load 10-37; the one of the six that was instrumented confirmed the
//!   product deadline had already fired, and the other five share its
//!   4360-poll signature). At a 1 ms slice the same 10 s buys ~10,000 polls,
//!   i.e. tens of milliseconds of real time, and virtual time stays
//!   proportional to polling effort: 3.7-4.2 µs of real time per virtual
//!   millisecond over 180 runs at load 10-40. (An earlier run claimed ~20 µs
//!   at load ~90; that regime was not reproduced in isolation, so it is not
//!   relied on here.)
//!
//! What the pin asserts: the close is observed **at or after `earliest`**
//! (the product's own deadline — a handler that drops the connection
//! immediately is a regression too, and the old shape only rejected that by
//! accident, and only when the early drop happened to be an RST) and
//! **within `bound`** of virtual time, checked after every slice so it may
//! land at most one slice (1 ms) past `bound`. `Ok(n)` with `n > 0` (payload)
//! and any error kind that is not a peer close still panic, and a peer that
//! never drops the connection still walks to `bound` and panics.

use std::io;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt};

/// Virtual-time slice. One slice ≈ one I/O-driver poll ≈ a few microseconds
/// of real time, so keeping it small is what makes `bound` a real-time
/// allowance as well as a virtual-time one (see the module docs).
const STEP: Duration = Duration::from_millis(1);

/// The window this helper waits on can be armed marginally before the helper's
/// clock starts: each caller starts its traffic first, and the paused clock
/// does not advance during that pre-helper window. Two independent instrumented
/// samples put the skew `helper_start − arm` in **[−69 ms, 0]** — never
/// positive — so 1 s is a ~14x margin over the largest |skew| observed. Treat
/// that bound as a sample: it is host- and load-dependent, which is why the
/// slack is a second rather than tens of milliseconds.
///
/// Known limitation, measured: because the guard is
/// `elapsed + EARLY_SLACK < earliest`, a product deadline shortened by up to
/// 1 s is still accepted as "at the deadline" — a 59 s mutant passes, a 58 s
/// one fails the TLS pins while the 300 s trickler bound still absorbs it.
/// That blind spot is 1.7 % of the 60 s window and is kept deliberately:
/// narrowing the slack would trade away the margin against a host whose skew
/// is larger than the one measured here.
const EARLY_SLACK: Duration = Duration::from_secs(1);

/// A read error kind that means the peer closed the connection rather than
/// that anything went wrong. `ConnectionReset` is the RST case in the module
/// docs; `ConnectionAborted` is the same event through another platform path.
/// `BrokenPipe` is accepted per the pin's contract but is **not verified on a
/// read path**: no probe on this host produced EPIPE from `read` (EPIPE is a
/// write-side error), and the crate's other read-path precedent
/// (`plugin/static_file.rs`, `is_conn_closed`) accepts only the two kinds
/// above.
fn is_peer_close(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::BrokenPipe
    )
}

/// Panic if a close observed now would be earlier than the product's
/// `earliest` deadline window allows.
fn assert_not_early(start: tokio::time::Instant, earliest: Duration, what: &str, form: &str) {
    let elapsed = start.elapsed();
    if elapsed + EARLY_SLACK < earliest {
        panic!(
            "{what} was released after only {elapsed:?} ({form}) — the {earliest:?} \
             deadline window is not being enforced"
        );
    }
}

/// Assert that a plugin handler drops `stream`'s connection between
/// `earliest` and `bound` of virtual time, accepting the close in whichever
/// form it arrives: clean EOF (`Ok(0)`) or a peer-close error (`ECONNRESET` /
/// `ECONNABORTED` / `BrokenPipe`).
///
/// `earliest` is the product deadline the pin is about
/// (`PLUGIN_HANDSHAKE_TIMEOUT` / `PLUGIN_HEADER_READ_TIMEOUT`); `bound` is the
/// generous outer bound the pin has always used (that deadline plus 10 s, or
/// 300 s for the trickler). `what` names the peer for the panic messages;
/// `red` states the regression being pinned, so a failure explains itself.
pub(crate) async fn assert_peer_closed_within<S>(
    stream: &mut S,
    earliest: Duration,
    bound: Duration,
    what: &str,
    red: &str,
) where
    S: AsyncRead + Unpin,
{
    let start = tokio::time::Instant::now();
    let mut polls: u64 = 0;
    let mut buf = [0u8; 1];
    loop {
        polls += 1;
        match tokio::time::timeout(STEP, stream.read(&mut buf)).await {
            Ok(Ok(0)) => {
                assert_not_early(start, earliest, what, "clean EOF");
                return;
            }
            Ok(Ok(n)) => panic!("unexpected {n} bytes from {what}"),
            Ok(Err(e)) if is_peer_close(&e) => {
                assert_not_early(start, earliest, what, &format!("peer close: {e}"));
                return;
            }
            Ok(Err(e)) => panic!("read error from {what}: {e}"),
            // No close within this slice: the clock advanced by at most one
            // STEP, so re-check the socket.
            Err(_) => {}
        }
        let elapsed = start.elapsed();
        if elapsed > bound {
            panic!(
                "{what} was not released: conn still open after {bound:?} \
                 ({elapsed:?} of virtual time elapsed, {polls} read polls) — RED: {red}"
            );
        }
    }
}
