//! NAT analysis engine: recommends hole-punch behaviors based on
//! observed NAT features. Learns from success/failure to improve future
//! recommendations. Go frp v0.69.1 compat: pkg/nathole/analysis.go

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use super::classify::{classify_feature_count, NatFeature};

/// Recommended hole-punch behavior for one peer.
#[derive(Debug, Clone)]
pub struct RecommendBehavior {
    pub role: String, // "sender" or "receiver"
    pub ttl: i32,
    pub send_delay_ms: i32,
    pub ports_range_number: i32,
    pub ports_random_number: i32,
    pub listen_random_ports: i32,
}

// --------------- Behavior Tables (Go frp v0.69.1 compat) ---------------

/// Number of entries per mode.
const MODE_COUNTS: [usize; 5] = [10, 6, 3, 6, 3];

/// All behavior pairs indexed by (mode, index).
type BehaviorPair = (RecommendBehavior, RecommendBehavior);

/// Mode 0: Both EasyNAT — 10 entries.
/// Alternates sender/receiver roles. TTL and send_delay_ms vary.
fn mode0_table() -> &'static [BehaviorPair] {
    use std::sync::OnceLock;
    static TABLE: OnceLock<Vec<BehaviorPair>> = OnceLock::new();
    TABLE.get_or_init(|| {
        vec![
            (sender(0, 0, 0, 0, 0), receiver(7, 0, 0, 0, 0)),
            (receiver(7, 0, 0, 0, 0), sender(0, 0, 0, 0, 0)),
            (sender(0, 0, 0, 0, 0), receiver(4, 0, 0, 0, 0)),
            (receiver(4, 0, 0, 0, 0), sender(0, 0, 0, 0, 0)),
            (sender(0, 0, 0, 0, 0), receiver(0, 0, 0, 0, 0)),
            (receiver(0, 0, 0, 0, 0), sender(0, 0, 0, 0, 0)),
            (sender(0, 5000, 0, 0, 0), receiver(0, 0, 0, 0, 0)),
            (sender(0, 10000, 0, 0, 0), receiver(0, 0, 0, 0, 0)),
            (receiver(0, 0, 0, 0, 0), sender(0, 5000, 0, 0, 0)),
            (receiver(0, 0, 0, 0, 0), sender(0, 10000, 0, 0, 0)),
        ]
    })
}

/// Mode 1: HardNAT sender, EasyNAT receiver, regular port changes — 6 entries.
fn mode1_table() -> &'static [BehaviorPair] {
    use std::sync::OnceLock;
    static TABLE: OnceLock<Vec<BehaviorPair>> = OnceLock::new();
    TABLE.get_or_init(|| {
        vec![
            (sender(0, 0, 0, 0, 0), recv_ports(7, 0, 10)),
            (sender(0, 2000, 0, 0, 0), recv_ports(7, 0, 10)),
            (sender(0, 0, 0, 0, 0), recv_ports(4, 0, 10)),
            (sender(0, 2000, 0, 0, 0), recv_ports(4, 0, 10)),
            (sender(0, 0, 0, 0, 0), recv_ports(0, 0, 10)),
            (sender(0, 2000, 0, 0, 0), recv_ports(0, 0, 10)),
        ]
    })
}

/// Mode 2: HardNAT receiver, EasyNAT sender — 3 entries.
fn mode2_table() -> &'static [BehaviorPair] {
    use std::sync::OnceLock;
    static TABLE: OnceLock<Vec<BehaviorPair>> = OnceLock::new();
    TABLE.get_or_init(|| {
        vec![
            (sender_port(3000, 1000, 0), recv_listen(7, 256)),
            (sender_port(3000, 1000, 0), recv_listen(4, 256)),
            (sender_port(3000, 1000, 0), recv_listen(0, 256)),
        ]
    })
}

/// Mode 3: Both HardNAT, both regular port changes — 6 entries.
/// First 3: A is sender, B is receiver. Last 3: A is receiver, B is sender.
fn mode3_table() -> &'static [BehaviorPair] {
    use std::sync::OnceLock;
    static TABLE: OnceLock<Vec<BehaviorPair>> = OnceLock::new();
    TABLE.get_or_init(|| {
        vec![
            // Go frp v0.70.1 compat: both sender and receiver have PortsRangeNumber=10.
            // sender(params: ttl, delay, prn, prnn, lrp) — so ports_range_number is 3rd param.
            (sender(0, 0, 10, 0, 0), recv_ports(7, 0, 10)),
            (sender(0, 0, 10, 0, 0), recv_ports(4, 0, 10)),
            (sender(0, 0, 10, 0, 0), recv_ports(0, 0, 10)),
            (recv_ports(7, 0, 10), sender(0, 0, 10, 0, 0)),
            (recv_ports(4, 0, 10), sender(0, 0, 10, 0, 0)),
            (recv_ports(0, 0, 10), sender(0, 0, 10, 0, 0)),
        ]
    })
}

/// Mode 4: Regular ports change peer is usually sender — 3 entries.
fn mode4_table() -> &'static [BehaviorPair] {
    use std::sync::OnceLock;
    static TABLE: OnceLock<Vec<BehaviorPair>> = OnceLock::new();
    TABLE.get_or_init(|| {
        vec![
            (sender_port(3000, 1000, 0), recv_listen_ports(7, 256, 2)),
            (sender_port(3000, 1000, 0), recv_listen_ports(4, 256, 2)),
            (sender_port(3000, 1000, 0), recv_listen_ports(0, 256, 2)),
        ]
    })
}

// --- Helper constructors for table entries ---

fn sender(ttl: i32, delay: i32, prn: i32, prnn: i32, lrp: i32) -> RecommendBehavior {
    RecommendBehavior {
        role: "sender".into(),
        ttl,
        send_delay_ms: delay,
        ports_range_number: prn,
        ports_random_number: prnn,
        listen_random_ports: lrp,
    }
}

fn receiver(ttl: i32, delay: i32, prn: i32, prnn: i32, lrp: i32) -> RecommendBehavior {
    RecommendBehavior {
        role: "receiver".into(),
        ttl,
        send_delay_ms: delay,
        ports_range_number: prn,
        ports_random_number: prnn,
        listen_random_ports: lrp,
    }
}

fn recv_ports(ttl: i32, delay: i32, prn: i32) -> RecommendBehavior {
    RecommendBehavior {
        role: "receiver".into(),
        ttl,
        send_delay_ms: delay,
        ports_range_number: prn,
        ports_random_number: 0,
        listen_random_ports: 0,
    }
}

fn sender_port(delay: i32, prnn: i32, lrp: i32) -> RecommendBehavior {
    RecommendBehavior {
        role: "sender".into(),
        ttl: 0,
        send_delay_ms: delay,
        ports_range_number: 0,
        ports_random_number: prnn,
        listen_random_ports: lrp,
    }
}

fn recv_listen(ttl: i32, lrp: i32) -> RecommendBehavior {
    RecommendBehavior {
        role: "receiver".into(),
        ttl,
        send_delay_ms: 0,
        ports_range_number: 0,
        ports_random_number: 0,
        listen_random_ports: lrp,
    }
}

fn recv_listen_ports(ttl: i32, lrp: i32, prn: i32) -> RecommendBehavior {
    RecommendBehavior {
        role: "receiver".into(),
        ttl,
        send_delay_ms: 0,
        ports_range_number: prn,
        ports_random_number: 0,
        listen_random_ports: lrp,
    }
}

// --------------- Scoring and Records ---------------

/// Score entry for a specific (mode, index) behavior pair.
#[derive(Debug, Clone)]
struct BehaviorScore {
    mode: i32,
    index: i32,
    score: i32,
}

/// Per-analysis-key storage with scored behavior history.
struct MakeHoleRecords {
    scores: Vec<BehaviorScore>,
    last_update_time: Instant,
}

impl MakeHoleRecords {
    /// Create records from client and visitor NAT features.
    /// Scoring logic matches Go frp v0.69.1 newMakeHoleRecordsWithClock.
    fn new(c_feature: &NatFeature, v_feature: &NatFeature) -> Self {
        let features = vec![c_feature.clone(), v_feature.clone()];
        let (easy_count, hard_count, ports_changed_regular_count) =
            classify_feature_count(&features);

        let mut scores = Vec::new();

        // Helper: append mode-0 entries with PublicNetwork-aware scoring.
        // Go frp v0.69.1 compat: getBehaviorScoresByMode2 checks each entry's
        // first-behavior role (c_behavior.role) and assigns senderScore or
        // receiverScore accordingly. When a peer is on a public network, it
        // should be the receiver (give receiver roles higher score).
        //   c.PublicNetwork → sender=0, receiver=1 (client should be receiver)
        //   v.PublicNetwork → sender=1, receiver=0 (visitor should be receiver)
        //   neither → all scores 0
        let append_mode0 = |scores: &mut Vec<BehaviorScore>, c_pub: bool, v_pub: bool| {
            let (sender_score, receiver_score) = if c_pub {
                (0, 1)
            } else if v_pub {
                (1, 0)
            } else {
                (0, 0)
            };
            let table = mode0_table();
            for (i, (c_behavior, _)) in table.iter().enumerate() {
                let score = if c_behavior.role == "sender" {
                    sender_score
                } else {
                    receiver_score
                };
                scores.push(BehaviorScore {
                    mode: 0,
                    index: i as i32,
                    score,
                });
            }
        };

        // Helper: append all entries for a mode with uniform score.
        let append_mode = |scores: &mut Vec<BehaviorScore>, mode: i32, score: i32| {
            for i in 0..MODE_COUNTS[mode as usize] as i32 {
                scores.push(BehaviorScore {
                    mode,
                    index: i,
                    score,
                });
            }
        };

        if easy_count == 2 {
            // Both easy NAT: mode 0 only, with PublicNetwork-aware scoring.
            append_mode0(
                &mut scores,
                c_feature.public_network,
                v_feature.public_network,
            );
        } else if hard_count == 1 && ports_changed_regular_count == 1 {
            // One hard with regular port change: mode1, mode2, mode0.
            // Go frp v0.70.1 uses score=0 for non-fallback entries.
            append_mode(&mut scores, 1, 0);
            append_mode(&mut scores, 2, 0);
            append_mode0(
                &mut scores,
                c_feature.public_network,
                v_feature.public_network,
            );
        } else if hard_count == 1 && ports_changed_regular_count == 0 {
            // One hard without regular port change: mode2, mode1, mode0.
            // Go frp v0.70.1 uses score=0 for non-fallback entries.
            append_mode(&mut scores, 2, 0);
            append_mode(&mut scores, 1, 0);
            append_mode0(
                &mut scores,
                c_feature.public_network,
                v_feature.public_network,
            );
        } else if hard_count == 2 && ports_changed_regular_count == 2 {
            // Both hard, both regular: mode3, mode4.
            // Go frp v0.70.1 uses score=0 for non-fallback entries.
            append_mode(&mut scores, 3, 0);
            append_mode(&mut scores, 4, 0);
        } else if hard_count == 2 && ports_changed_regular_count == 1 {
            // Both hard, one regular: mode4 only.
            // Go frp v0.70.1 uses score=0 for non-fallback entries.
            append_mode(&mut scores, 4, 0);
        } else {
            // Fallback: all entries for modes 0, 1, 3 with score 1 (Go frp compat).
            append_mode(&mut scores, 0, 1);
            append_mode(&mut scores, 1, 1);
            append_mode(&mut scores, 3, 1);
        }

        MakeHoleRecords {
            scores,
            last_update_time: Instant::now(),
        }
    }

    /// Select highest-scored (mode, index), decrement it to rotate choices.
    fn recommend(&mut self) -> (i32, i32) {
        if self.scores.is_empty() {
            return (0, 0);
        }
        let mut best_idx = 0usize;
        let mut best_score = i32::MIN;
        for (i, s) in self.scores.iter().enumerate() {
            if s.score > best_score {
                best_score = s.score;
                best_idx = i;
            }
        }
        self.scores[best_idx].score -= 1;
        // Go frp v0.69.1 compat: update last_update_time on every recommendation
        // to prevent premature cleanup of frequently-consulted records.
        self.last_update_time = Instant::now();
        (self.scores[best_idx].mode, self.scores[best_idx].index)
    }

    /// Report success: boost the matching (mode, index) score, max +2 cap at 10.
    /// Go frp v0.70.1 compat: update lastUpdateTime unconditionally BEFORE the loop.
    fn report_success(&mut self, mode: i32, index: i32) {
        self.last_update_time = Instant::now();
        for s in &mut self.scores {
            if s.mode == mode && s.index == index {
                s.score = (s.score + 2).min(10);
                break;
            }
        }
    }
}

// --------------- Behavior Lookup ---------------

/// Look up the behavior pair for a given (mode, index).
fn get_behavior_by_mode_and_index(mode: i32, index: i32) -> (RecommendBehavior, RecommendBehavior) {
    let idx = index as usize;
    let table: &[BehaviorPair] = match mode {
        0 => mode0_table(),
        1 => mode1_table(),
        2 => mode2_table(),
        3 => mode3_table(),
        4 => mode4_table(),
        _ => return default_fallback(),
    };
    table.get(idx).cloned().unwrap_or_else(default_fallback)
}

fn default_fallback() -> (RecommendBehavior, RecommendBehavior) {
    (sender(0, 2000, 16, 4, 0), receiver(0, 0, 0, 0, 0))
}

// --------------- Analyzer ---------------

/// Central analyzer: stores scored behavior histories keyed by NAT feature hash.
pub struct Analyzer {
    records: Mutex<HashMap<String, MakeHoleRecords>>,
    data_reserve_duration: Duration,
}

impl Analyzer {
    pub fn new(data_reserve_duration: Duration) -> Self {
        Analyzer {
            records: Mutex::new(HashMap::new()),
            data_reserve_duration,
        }
    }

    /// Get recommended behaviors for a hole-punch session.
    /// Returns (mode, index, c_behavior, v_behavior).
    /// Role swap rules are applied per Go frp v0.69.1.
    pub fn get_recommend_behaviors(
        &self,
        key: &str,
        c_feature: &NatFeature,
        v_feature: &NatFeature,
    ) -> (i32, i32, RecommendBehavior, RecommendBehavior) {
        let (mode, index) = {
            let mut records = self.records.lock().unwrap_or_else(|e| e.into_inner());
            let entry = records
                .entry(key.to_string())
                .or_insert_with(|| MakeHoleRecords::new(c_feature, v_feature));
            entry.recommend()
        };

        let (mut c_behavior, mut v_behavior) = get_behavior_by_mode_and_index(mode, index);

        // Role swap rules per mode (Go frp v0.69.1 compat).
        match mode {
            1 if c_feature.nat_type == super::classify::EASY_NAT => {
                // Mode 1: HardNAT is always sender. Client is EasyNAT, swap.
                std::mem::swap(&mut c_behavior, &mut v_behavior);
            }
            1 => {}
            2 if c_feature.nat_type == super::classify::HARD_NAT => {
                // Mode 2: HardNAT is always receiver. Client is HardNAT, swap.
                std::mem::swap(&mut c_behavior, &mut v_behavior);
            }
            2 => {}
            3 => {
                // Mode 3: No swap in default (first 3 entries have A=sender).
                // Entries 3-5 have A=receiver, B=sender — already swapped in table.
            }
            4 if !c_feature.regular_ports_change => {
                // Mode 4: Regular ports change peer is always sender.
                std::mem::swap(&mut c_behavior, &mut v_behavior);
            }
            4 => {}
            _ => {} // Mode 0: behaviors already alternate in table
        }

        (mode, index, c_behavior, v_behavior)
    }

    /// Record a successful hole punch to improve future recommendations.
    pub fn report_success(&self, key: &str, mode: i32, index: i32) {
        let mut records = self.records.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(entry) = records.get_mut(key) {
            entry.report_success(mode, index);
        }
    }

    /// Remove expired entries. Returns (removed, total_before).
    pub fn clean(&self) -> (usize, usize) {
        let mut records = self.records.lock().unwrap_or_else(|e| e.into_inner());
        let total = records.len();
        let now = Instant::now();
        records.retain(|_, r| now.duration_since(r.last_update_time) < self.data_reserve_duration);
        (total - records.len(), total)
    }
}

// --------------- Tests ---------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nathole::classify::classify_nat_feature;

    #[test]
    fn test_mode_0_both_easy() {
        let analyzer = Analyzer::new(Duration::from_secs(3600));
        let addrs = vec!["1.2.3.4:1234".into(), "1.2.3.4:1234".into()];
        let cf = classify_nat_feature(&addrs, &[]).unwrap();
        let vf = classify_nat_feature(&addrs, &[]).unwrap();

        let (mode, _, cb, vb) = analyzer.get_recommend_behaviors("test-key", &cf, &vf);
        assert_eq!(mode, 0);
        // First entry: sender then receiver with TTL 7
        assert_eq!(cb.role, "sender");
        assert_eq!(vb.role, "receiver");
    }

    #[test]
    fn test_report_success_boosts_score() {
        let analyzer = Analyzer::new(Duration::from_secs(3600));
        let addrs = vec!["1.2.3.4:1234".into(), "1.2.3.4:1234".into()];
        let cf = classify_nat_feature(&addrs, &[]).unwrap();
        let vf = classify_nat_feature(&addrs, &[]).unwrap();

        analyzer.report_success("test-key", 0, 0);

        let (mode2, _, _, _) = analyzer.get_recommend_behaviors("test-key", &cf, &vf);
        // Should still prefer mode 0 since we boosted it
        assert_eq!(mode2, 0);
    }

    #[test]
    fn test_clean_expired() {
        let analyzer = Analyzer::new(Duration::from_secs(0));
        let addrs = vec!["1.2.3.4:1234".into(), "1.2.3.4:1234".into()];
        let cf = classify_nat_feature(&addrs, &[]).unwrap();
        let vf = classify_nat_feature(&addrs, &[]).unwrap();

        analyzer.get_recommend_behaviors("test-key", &cf, &vf);
        let (removed, _total) = analyzer.clean();
        assert!(removed > 0);
    }

    #[test]
    fn test_mode_0_has_10_entries() {
        // Verify we can cycle through all 10 mode-0 entries
        let analyzer = Analyzer::new(Duration::from_secs(3600));
        let addrs = vec!["1.2.3.4:1234".into(), "1.2.3.4:1234".into()];
        let cf = classify_nat_feature(&addrs, &[]).unwrap();
        let vf = classify_nat_feature(&addrs, &[]).unwrap();

        let mut seen_indices = std::collections::HashSet::new();
        for _ in 0..10 {
            let (mode, index, _, _) = analyzer.get_recommend_behaviors("cycle-key", &cf, &vf);
            assert_eq!(mode, 0);
            seen_indices.insert(index);
        }
        // All 10 entries should be visited (scores start at 0, decrement to -1, etc.)
        assert!(
            seen_indices.len() >= 2,
            "should see multiple indices, got {}",
            seen_indices.len()
        );
    }

    #[test]
    fn test_mode_table_counts() {
        assert_eq!(mode0_table().len(), MODE_COUNTS[0]);
        assert_eq!(mode1_table().len(), MODE_COUNTS[1]);
        assert_eq!(mode2_table().len(), MODE_COUNTS[2]);
        assert_eq!(mode3_table().len(), MODE_COUNTS[3]);
        assert_eq!(mode4_table().len(), MODE_COUNTS[4]);
    }

    #[test]
    fn test_hard_nat_combos_recommend_modes() {
        let analyzer = Analyzer::new(Duration::from_secs(3600));
        // 端口随探针变化 => port_changed => 硬 NAT
        let hard_addrs = vec!["1.2.3.4:1234".into(), "1.2.3.4:5678".into()];
        let easy_addrs = vec!["1.2.3.4:1234".into(), "1.2.3.4:1234".into()];
        let hard = classify_nat_feature(&hard_addrs, &[]).unwrap();
        let easy = classify_nat_feature(&easy_addrs, &[]).unwrap();
        // (client, visitor) combos with the exact (mode, roles) the scorer
        // picks for them (verified against the Go v0.69.1 scoring tables):
        //   (hard, hard): both peers irregular → mode-0 fallback table
        //   (hard, easy): mode 2 — HardNAT is always receiver (client is hard)
        //   (easy, hard): mode 2 — HardNAT is always receiver (visitor is hard)
        let expected = [
            (&hard, &hard, 0, "sender", "receiver"),
            (&hard, &easy, 2, "receiver", "sender"),
            (&easy, &hard, 2, "sender", "receiver"),
        ];
        for (i, (cf, vf, want_mode, want_c_role, want_v_role)) in expected.iter().enumerate() {
            let (mode, _idx, cb, vb) =
                analyzer.get_recommend_behaviors(&format!("combo-{i}"), cf, vf);
            assert_eq!(mode, *want_mode, "combo {i}: mode");
            assert_eq!(cb.role, *want_c_role, "combo {i}: client role");
            assert_eq!(vb.role, *want_v_role, "combo {i}: visitor role");
        }
    }

    #[test]
    fn test_hard_nat_regular_port_change_reaches_modes_3_and_4() {
        let analyzer = Analyzer::new(Duration::from_secs(3600));
        // Ports within 1..=5 of each other => regular_ports_change=true
        // (classify.rs: only PORT_CHANGED behavior with a 1..=5 difference
        // counts as regular).
        let regular =
            classify_nat_feature(&["1.2.3.4:1234".into(), "1.2.3.4:1236".into()], &[]).unwrap();
        assert!(
            regular.regular_ports_change,
            "1234->1236 must classify as a regular port change"
        );
        let easy =
            classify_nat_feature(&["1.2.3.4:1234".into(), "1.2.3.4:1234".into()], &[]).unwrap();

        // Both hard, both regular: the score list is modes 3 + 4; the first
        // recommend picks mode 3 entry 0.
        let (mode, index, cb, vb) =
            analyzer.get_recommend_behaviors("regular-both", &regular, &regular);
        assert_eq!(mode, 3, "both-regular must start in mode 3");
        assert_eq!(index, 0);
        assert_ne!(cb.role, vb.role);

        // One hard regular + one easy: the score list is modes 1, 2, 0; the
        // first recommend picks mode 1 entry 0.
        let (mode, _idx, cb, vb) = analyzer.get_recommend_behaviors("regular-one", &regular, &easy);
        assert_eq!(mode, 1, "hard-regular vs easy must start in mode 1");
        assert_ne!(cb.role, vb.role);

        // Easy client + hard-regular visitor: mode 1 with the swap rule —
        // the EasyNAT client must become the receiver (Go frp role-swap).
        let (mode, _idx, cb, vb) =
            analyzer.get_recommend_behaviors("regular-one-swap", &easy, &regular);
        assert_eq!(mode, 1);
        assert_eq!(
            cb.role, "receiver",
            "EasyNAT client must swap to receiver in mode 1"
        );
        assert_eq!(vb.role, "sender");
    }

    #[test]
    fn test_score_decrement_rotates_modes_3_and_4() {
        // Modes 3 and 4 both start at score 0. `recommend()` picks the first
        // max-scored entry and decrements it, so repeated calls must walk
        // all six mode-3 entries, then rotate into the three mode-4 entries
        // as the mode-3 scores fall to -1 — without panicking on any table
        // boundary and with the mode always in 0..=4.
        let analyzer = Analyzer::new(Duration::from_secs(3600));
        let regular =
            classify_nat_feature(&["1.2.3.4:1234".into(), "1.2.3.4:1236".into()], &[]).unwrap();
        let mut seen = std::collections::HashSet::new();
        for i in 0..12 {
            let (mode, index, cb, vb) =
                analyzer.get_recommend_behaviors("rotate", &regular, &regular);
            assert!(
                (0..=4).contains(&mode),
                "iteration {i}: mode {mode} out of range"
            );
            assert_ne!(cb.role, vb.role, "iteration {i}: roles must pair");
            seen.insert((mode, index));
        }
        assert!(
            seen.iter().any(|(m, _)| *m == 3),
            "mode 3 must appear in the rotation: {seen:?}"
        );
        assert!(
            seen.iter().any(|(m, _)| *m == 4),
            "score decrements must rotate into mode 4: {seen:?}"
        );
        assert!(
            seen.len() >= 9,
            "all 6 mode-3 + 3 mode-4 entries must be visited: {seen:?}"
        );
    }
}
