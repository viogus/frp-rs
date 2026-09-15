use std::{cmp, sync::Arc};

use parking_lot::Mutex;
use web_time::{Duration, Instant};

use crate::{connection::rtt::Rtt, Config, ConnectionError, DEFAULT_CREDIT};

#[derive(Debug)]
pub(crate) struct FlowController {
    config: Arc<Config>,
    last_window_update: Instant,
    /// See [`Connection::rtt`].
    rtt: Rtt,
    /// See [`Connection::accumulated_max_stream_windows`].
    accumulated_max_stream_windows: Arc<Mutex<usize>>,
    receive_window: u32,
    max_receive_window: u32,
    send_window: u32,
}

impl FlowController {
    pub(crate) fn new(
        receive_window: u32,
        send_window: u32,
        accumulated_max_stream_windows: Arc<Mutex<usize>>,
        rtt: Rtt,
        config: Arc<Config>,
    ) -> Self {
        Self {
            receive_window,
            send_window,
            config,
            rtt,
            accumulated_max_stream_windows,
            max_receive_window: DEFAULT_CREDIT,
            last_window_update: Instant::now(),
        }
    }

    /// Calculate the number of additional window bytes the receiving side (local) should grant the
    /// sending side (remote) via a window update message.
    ///
    /// Returns `None` if too small to justify a window update message.
    pub(crate) fn next_window_update(&mut self, buffer_len: usize) -> Option<u32> {
        self.assert_invariants(buffer_len);

        let bytes_received = self.max_receive_window - self.receive_window;
        let mut next_window_update =
            bytes_received.saturating_sub(buffer_len.try_into().unwrap_or(u32::MAX));

        // Don't send an update in case half or more of the window is still available to the sender.
        if next_window_update < self.max_receive_window / 2 {
            return None;
        }

        log::trace!(
            "received {} mb in {} seconds ({} mbit/s)",
            next_window_update as f64 / crate::MIB as f64,
            self.last_window_update.elapsed().as_secs_f64(),
            next_window_update as f64 / crate::MIB as f64 * 8.0
                / self.last_window_update.elapsed().as_secs_f64()
        );

        // Auto-tuning `max_receive_window`
        //
        // The ideal `max_receive_window` is equal to the bandwidth-delay-product (BDP), thus
        // allowing the remote sender to exhaust the entire available bandwidth on a single stream.
        // Choosing `max_receive_window` too small prevents the remote sender from exhausting the
        // available bandwidth. Choosing `max_receive_window` to large is wasteful and delays
        // backpressure from the receiver to the sender on the stream.
        //
        // In case the remote sender has exhausted half or more of its credit in less than 2
        // round-trips, try to double `max_receive_window`.
        //
        // For simplicity `max_receive_window` is never decreased.
        //
        // This implementation is heavily influenced by QUIC. See document below for rational on the
        // above strategy.
        //
        // https://docs.google.com/document/d/1F2YfdDXKpy20WVKJueEf4abn_LVZHhMUMS5gX6Pgjl4/edit?usp=sharing
        //
        // frp-rs patch: warm-start the window growth. Uses the connection's
        // own RTT sample when it has one; otherwise falls back to
        // `Config::window_growth_seed_rtt` (100 ms in the frp-rs fork), so a
        // fresh stream is not pinned at `DEFAULT_CREDIT` for the connection's
        // first round-trip while the first PING/PONG is still in flight.
        // `None` restores upstream crates.io gating (no growth before the
        // first sample).
        let assumed_rtt = self.rtt.get().or(self.config.window_growth_seed_rtt);
        if window_growth_gate_open(assumed_rtt, self.last_window_update.elapsed()) {
            let mut accumulated_max_stream_windows = self.accumulated_max_stream_windows.lock();

            // Ideally one can just double it:
            let new_max = self.max_receive_window.saturating_mul(2);

            // But one has to consider the configured connection limit:
            let new_max = {
                let connection_limit: usize = self.max_receive_window as usize +
                    // the overall configured conneciton limit
                    (self.config.max_connection_receive_window.unwrap_or(usize::MAX)
                    // minus the minimum amount of window guaranteed to each stream
                    - self.config.max_num_streams * DEFAULT_CREDIT as usize
                    // minus the amount of bytes beyond the minimum amount (`DEFAULT_CREDIT`)
                    // already allocated by this and other streams on the connection.
                    - *accumulated_max_stream_windows);

                cmp::min(new_max, connection_limit.try_into().unwrap_or(u32::MAX))
            };

            // frp-rs patch: per-stream receive-window cap
            // (`Config::max_stream_receive_window`, Go frp `MaxStreamWindowSize=6MiB`
            // on the XTCP data plane). The cap only limits GROWTH: it is applied
            // when it is above the current max (a window that already exceeds the
            // cap — only possible if the cap is configured after traffic — is left
            // unchanged, which also keeps `new_max - self.max_receive_window`
            // non-negative for the accumulated-credit accounting below). The
            // connection-window invariants are preserved: the min only shrinks
            // `new_max`, and `connection_limit >= self.max_receive_window` (by the
            // accumulated invariant) so `new_max >= self.max_receive_window` holds.
            let new_max = match self.config.max_stream_receive_window {
                Some(cap) if cap > self.max_receive_window => cmp::min(new_max, cap),
                _ => new_max,
            };

            // Account for the additional credit on the accumulated connection counter.
            *accumulated_max_stream_windows += (new_max - self.max_receive_window) as usize;
            drop(accumulated_max_stream_windows);

            log::debug!(
                "old window_max: {} mb, new window_max: {} mb",
                self.max_receive_window as f64 / crate::MIB as f64,
                new_max as f64 / crate::MIB as f64
            );

            self.max_receive_window = new_max;

            // Recalculate `next_window_update` with the new `max_receive_window`.
            let bytes_received = self.max_receive_window - self.receive_window;
            next_window_update =
                bytes_received.saturating_sub(buffer_len.try_into().unwrap_or(u32::MAX));
        }

        self.last_window_update = Instant::now();
        self.receive_window += next_window_update;

        self.assert_invariants(buffer_len);

        Some(next_window_update)
    }

    fn assert_invariants(&self, buffer_len: usize) {
        if !cfg!(debug_assertions) {
            return;
        }

        let config = &self.config;
        let rtt = self.rtt.get();
        let accumulated_max_stream_windows = *self.accumulated_max_stream_windows.lock();

        assert!(
            buffer_len <= self.max_receive_window as usize,
            "The current buffer size never exceeds the maximum stream receive window."
        );
        assert!(
            self.receive_window <= self.max_receive_window,
            "The current window never exceeds the maximum."
        );
        assert!(
            (self.max_receive_window - DEFAULT_CREDIT) as usize
                <= config.max_connection_receive_window.unwrap_or(usize::MAX)
                    - config.max_num_streams * DEFAULT_CREDIT as usize,
            "The maximum never exceeds its maximum portion of the configured connection limit."
        );
        assert!(
            (self.max_receive_window - DEFAULT_CREDIT) as usize
                <= accumulated_max_stream_windows,
            "The amount by which the stream maximum exceeds DEFAULT_CREDIT is tracked in accumulated_max_stream_windows."
        );
        if rtt.is_none() && self.config.window_growth_seed_rtt.is_none() {
            // frp-rs patch note: with a seed configured (the fork default,
            // 100 ms) this precondition no longer holds — the maximum may
            // grow during the first round-trip, before any sample exists,
            // gated by the seed instead. The check below therefore applies
            // only to the upstream configuration (no sample, no seed).
            assert_eq!(
                self.max_receive_window, DEFAULT_CREDIT,
                "The maximum is only increased iff an rtt measurement is available."
            );
        }
    }

    pub(crate) fn send_window(&self) -> u32 {
        self.send_window
    }

    pub(crate) fn consume_send_window(&mut self, i: u32) -> Result<(), ConnectionError> {
        self.send_window = self
            .send_window
            .checked_sub(i)
            .ok_or(ConnectionError::InvalidWindowUpdate)?;
        Ok(())
    }

    pub(crate) fn increase_send_window_by(&mut self, i: u32) -> Result<(), ConnectionError> {
        self.send_window = self
            .send_window
            .checked_add(i)
            .ok_or(ConnectionError::InvalidWindowUpdate)?;
        Ok(())
    }

    pub(crate) fn consume_receive_window(&mut self, i: u32) -> Result<(), ConnectionError> {
        self.receive_window = self
            .receive_window
            .checked_sub(i)
            .ok_or(ConnectionError::InvalidWindowUpdate)?;
        Ok(())
    }
}

/// frp-rs patch: the auto-tuning growth gate — "the peer drained half of its
/// credit within two round-trips", i.e. its bandwidth-delay-product exceeds
/// the current window, so the window is worth doubling.
///
/// `assumed_rtt` is the connection's own RTT sample when it has one, else
/// `Config::window_growth_seed_rtt`; `None` (upstream crates.io
/// configuration) keeps the gate shut, which is what upstream expresses as
/// `.unwrap_or(false)`.
///
/// Takes the values rather than reading them so the policy is testable
/// without a live connection or a clock.
fn window_growth_gate_open(
    assumed_rtt: Option<Duration>,
    since_last_window_update: Duration,
) -> bool {
    assumed_rtt.is_some_and(|rtt| since_last_window_update < rtt.saturating_mul(2))
}

impl Drop for FlowController {
    fn drop(&mut self) {
        let mut accumulated_max_stream_windows = self.accumulated_max_stream_windows.lock();

        debug_assert!(
            *accumulated_max_stream_windows >= (self.max_receive_window - DEFAULT_CREDIT) as usize,
            "{accumulated_max_stream_windows} {}",
            self.max_receive_window
        );

        *accumulated_max_stream_windows -= (self.max_receive_window - DEFAULT_CREDIT) as usize;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quickcheck::{GenRange, QuickCheck};
    use web_time::Duration;

    #[derive(Debug)]
    struct Input {
        controller: FlowController,
        buffer_len: usize,
    }

    #[cfg(test)]
    impl Clone for Input {
        fn clone(&self) -> Self {
            Self {
                controller: FlowController {
                    config: self.controller.config.clone(),
                    accumulated_max_stream_windows: Arc::new(Mutex::new(
                        *self.controller.accumulated_max_stream_windows.lock(),
                    )),
                    rtt: self.controller.rtt.clone(),
                    last_window_update: self.controller.last_window_update,
                    receive_window: self.controller.receive_window,
                    max_receive_window: self.controller.max_receive_window,
                    send_window: self.controller.send_window,
                },
                buffer_len: self.buffer_len,
            }
        }
    }

    impl quickcheck::Arbitrary for Input {
        fn arbitrary(g: &mut quickcheck::Gen) -> Self {
            let config = Arc::new(Config::arbitrary(g));
            let rtt = Rtt::arbitrary(g);

            let max_connection_minus_default =
                config.max_connection_receive_window.unwrap_or(usize::MAX)
                    - (config.max_num_streams * (DEFAULT_CREDIT as usize));

            let max_receive_window = if rtt.get().is_none() {
                DEFAULT_CREDIT
            } else {
                g.gen_range(
                    DEFAULT_CREDIT
                        ..(DEFAULT_CREDIT as usize)
                            .saturating_add(max_connection_minus_default)
                            .try_into()
                            .unwrap_or(u32::MAX)
                            .saturating_add(1),
                )
            };
            let receive_window = g.gen_range(0..max_receive_window);
            let buffer_len = g.gen_range(0..max_receive_window as usize);
            let accumulated_max_stream_windows = Arc::new(Mutex::new(g.gen_range(
                (max_receive_window - DEFAULT_CREDIT) as usize
                    ..max_connection_minus_default.saturating_add(1),
            )));
            let last_window_update =
                Instant::now() - Duration::from_secs(g.gen_range(0..(60 * 60 * 24)));
            let send_window = g.gen_range(0..u32::MAX);

            Self {
                controller: FlowController {
                    accumulated_max_stream_windows,
                    rtt,
                    last_window_update,
                    config,
                    receive_window,
                    max_receive_window,
                    send_window,
                },
                buffer_len,
            }
        }
    }

    #[test]
    fn next_window_update() {
        fn property(
            Input {
                mut controller,
                buffer_len,
            }: Input,
        ) {
            controller.next_window_update(buffer_len);
        }

        QuickCheck::new().quickcheck(property as fn(_))
    }
}

/// frp-rs patch tests: the receive-window growth gate
/// (`window_growth_gate_open`, `Config::window_growth_seed_rtt`).
///
/// Kept in their own module so they only need `super::*`: the module above is
/// quickcheck-based and pulls in `quickcheck`, which is not a dev-dependency
/// of this vendored crate.
#[cfg(test)]
mod window_growth_tests {
    use super::*;

    /// A controller whose peer has consumed the entire window and left
    /// nothing buffered for the application, i.e. the state in which the
    /// "double the window" candidate update is worth considering.
    fn starved_controller(cfg: Config, rtt: Rtt, last_window_update: Instant) -> FlowController {
        FlowController {
            config: Arc::new(cfg),
            last_window_update,
            rtt,
            accumulated_max_stream_windows: Arc::new(Mutex::new(0)),
            receive_window: 0,
            max_receive_window: DEFAULT_CREDIT,
            send_window: DEFAULT_CREDIT,
        }
    }

    /// An `Instant` in the future makes `elapsed()` saturate to zero: the
    /// "peer just drained half the window" state, without depending on the
    /// test's own wall-clock race.
    fn just_now() -> Instant {
        let t = Instant::now() + Duration::from_secs(1);
        // The assumption this helper rests on: for a later instant,
        // `duration_since` saturates to zero rather than panicking.
        assert_eq!(t.elapsed(), Duration::ZERO);
        t
    }

    /// The fork default: a 100 ms seed is configured out of the box, so the
    /// gate is evaluated with it while no sample exists.
    #[test]
    fn fork_default_configures_the_seed() {
        let cfg = Config::default();
        assert_eq!(
            cfg.window_growth_seed_rtt(),
            Some(Duration::from_millis(100)),
            "the frp-rs fork default must carry the conservative 100 ms seed"
        );
    }

    /// The gate itself: seed used only when there is no sample; `None` (the
    /// upstream crates.io configuration) keeps it shut; with a sample the
    /// upstream `elapsed < 2 * rtt` condition applies verbatim.
    #[test]
    fn seed_gates_growth_without_a_sample_sample_wins_with_one() {
        let seed = Some(Duration::from_millis(100));
        let sample = Some(Duration::from_millis(20));

        // No sample: the seed's 2 x 100 ms window is what gates growth.
        // (Upstream, `None`, never opens the gate — last row.)
        assert!(window_growth_gate_open(seed, Duration::ZERO));
        assert!(window_growth_gate_open(seed, Duration::from_millis(199)));
        assert!(!window_growth_gate_open(seed, Duration::from_millis(200)));
        assert!(!window_growth_gate_open(seed, Duration::from_secs(1)));

        // A sample present: only `elapsed < 2 * sample` (40 ms), NOT the
        // seed's 200 ms — the seed must never widen a measured RTT.
        assert!(window_growth_gate_open(sample, Duration::from_millis(39)));
        assert!(!window_growth_gate_open(sample, Duration::from_millis(40)));
        assert!(!window_growth_gate_open(sample, Duration::from_millis(120)));

        // Upstream configuration (no sample, no seed): shut, as crates.io
        // yamux's `.unwrap_or(false)`.
        assert!(!window_growth_gate_open(None, Duration::ZERO));
        assert!(!window_growth_gate_open(None, Duration::from_millis(1)));
    }

    /// End to end through `next_window_update`: with no sample but the fork's
    /// seed, the first window update already doubles the window — a fresh
    /// stream is not pinned at `DEFAULT_CREDIT` for the connection's first
    /// round-trip. (Upstream this update is a no-op.)
    #[test]
    fn no_sample_seed_doubles_window_on_first_update() {
        let mut c = starved_controller(Config::default(), Rtt::new(), just_now());
        assert_eq!(c.rtt.get(), None, "no sample yet");

        let update = c.next_window_update(0).expect("window update");

        assert_eq!(
            c.max_receive_window,
            DEFAULT_CREDIT * 2,
            "the seed gate (elapsed 0 < 2 x 100 ms) must let the window double"
        );
        assert_eq!(update, DEFAULT_CREDIT * 2, "credit granted to the peer");
    }

    /// The seed is a gate, not a bypass: a peer that needed longer than
    /// `2 * seed` to drain half its credit has a BDP below the current
    /// window, so the window stays where it is.
    #[test]
    fn no_sample_slow_consumption_stays_at_default_credit() {
        let mut c = starved_controller(
            Config::default(),
            Rtt::new(),
            Instant::now() - Duration::from_secs(1),
        );

        let update = c.next_window_update(0).expect("window update");

        assert_eq!(
            c.max_receive_window, DEFAULT_CREDIT,
            ">= 2 x the 100 ms seed since the last update: no growth"
        );
        assert_eq!(update, DEFAULT_CREDIT);
    }

    /// With a sample the seeded path is not taken: growth follows the measured
    /// RTT (20 ms sample -> 40 ms window), and an elapsed time that the seed
    /// alone would have accepted (120 ms < 200 ms) does not grow it.
    #[test]
    fn sample_present_uses_measured_rtt_not_the_seed() {
        let mut rtt = Rtt::new();
        let ping = rtt.next_ping().expect("the first ping is due immediately");
        std::thread::sleep(Duration::from_millis(20));
        // Pong for the id `next_ping` just allocated; a mismatched id would
        // terminate the connection instead of setting the sample, and the
        // `expect` below would fail.
        let _ = rtt.handle_pong(ping.id());
        let sample = rtt.get().expect("rtt sample");
        assert!(
            sample >= Duration::from_millis(20),
            "sample must reflect the 20 ms sleep: {sample:?}"
        );

        // Within 2 x sample: grows, exactly as upstream.
        let mut fast = starved_controller(
            Config::default(),
            rtt.clone(),
            Instant::now() - Duration::from_millis(1),
        );
        fast.next_window_update(0).expect("window update");
        assert_eq!(fast.max_receive_window, DEFAULT_CREDIT * 2);

        // Beyond 2 x sample but well within 2 x seed: no growth — the seed
        // must not be consulted once a sample exists.
        let mut slow = starved_controller(
            Config::default(),
            rtt,
            Instant::now() - Duration::from_millis(120),
        );
        slow.next_window_update(0).expect("window update");
        assert_eq!(
            slow.max_receive_window, DEFAULT_CREDIT,
            "120 ms is inside the seed's 200 ms window but outside 2 x the 20 ms sample"
        );
    }

    /// Opting out (`None`) restores the crates.io behavior: no window growth
    /// before the first RTT sample, whatever the timing.
    #[test]
    fn upstream_configuration_never_grows_without_a_sample() {
        let mut cfg = Config::default();
        cfg.set_window_growth_seed_rtt(None);
        assert_eq!(cfg.window_growth_seed_rtt(), None);

        let mut c = starved_controller(cfg, Rtt::new(), just_now());
        let update = c.next_window_update(0).expect("window update");

        assert_eq!(
            c.max_receive_window, DEFAULT_CREDIT,
            "no sample and no seed: growth waits for the first ping/pong"
        );
        assert_eq!(update, DEFAULT_CREDIT);
    }
}
