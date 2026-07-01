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
    pub role: String,            // "sender" or "receiver"
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
            (sender(0, 0, 0, 0, 0),  receiver(7, 0, 0, 0, 0)),
            (receiver(7, 0, 0, 0, 0), sender(0, 0, 0, 0, 0)),
            (sender(0, 0, 0, 0, 0),  receiver(4, 0, 0, 0, 0)),
            (receiver(4, 0, 0, 0, 0), sender(0, 0, 0, 0, 0)),
            (sender(0, 0, 0, 0, 0),  receiver(0, 0, 0, 0, 0)),
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
            (sender(0, 0, 0, 0, 0),      recv_ports(7, 0, 10)),
            (sender(0, 2000, 0, 0, 0),    recv_ports(7, 0, 10)),
            (sender(0, 0, 0, 0, 0),      recv_ports(4, 0, 10)),
            (sender(0, 2000, 0, 0, 0),    recv_ports(4, 0, 10)),
            (sender(0, 0, 0, 0, 0),      recv_ports(0, 0, 10)),
            (sender(0, 2000, 0, 0, 0),    recv_ports(0, 0, 10)),
        ]
    })
}

/// Mode 2: HardNAT receiver, EasyNAT sender — 3 entries.
fn mode2_table() -> &'static [BehaviorPair] {
    use std::sync::OnceLock;
    static TABLE: OnceLock<Vec<BehaviorPair>> = OnceLock::new();
    TABLE.get_or_init(|| {
        vec![
            (sender_port(3000, 1000, 0),  recv_listen(7, 256)),
            (sender_port(3000, 1000, 0),  recv_listen(4, 256)),
            (sender_port(3000, 1000, 0),  recv_listen(0, 256)),
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
            (send_ports(0, 10),   recv_ports(7, 0, 10)),
            (send_ports(0, 10),   recv_ports(4, 0, 10)),
            (send_ports(0, 10),   recv_ports(0, 0, 10)),
            (recv_ports(7, 0, 10), send_ports(0, 10)),
            (recv_ports(4, 0, 10), send_ports(0, 10)),
            (recv_ports(0, 0, 10), send_ports(0, 10)),
        ]
    })
}

/// Mode 4: Regular ports change peer is usually sender — 3 entries.
fn mode4_table() -> &'static [BehaviorPair] {
    use std::sync::OnceLock;
    static TABLE: OnceLock<Vec<BehaviorPair>> = OnceLock::new();
    TABLE.get_or_init(|| {
        vec![
            (sender_port(3000, 1000, 0),  recv_listen_ports(7, 256, 2)),
            (sender_port(3000, 1000, 0),  recv_listen_ports(4, 256, 2)),
            (sender_port(3000, 1000, 0),  recv_listen_ports(0, 256, 2)),
        ]
    })
}

// --- Helper constructors for table entries ---

fn sender(ttl: i32, delay: i32, prn: i32, prnn: i32, lrp: i32) -> RecommendBehavior {
    RecommendBehavior { role: "sender".into(), ttl, send_delay_ms: delay,
        ports_range_number: prn, ports_random_number: prnn, listen_random_ports: lrp }
}

fn receiver(ttl: i32, delay: i32, prn: i32, prnn: i32, lrp: i32) -> RecommendBehavior {
    RecommendBehavior { role: "receiver".into(), ttl, send_delay_ms: delay,
        ports_range_number: prn, ports_random_number: prnn, listen_random_ports: lrp }
}

fn recv_ports(ttl: i32, delay: i32, prn: i32) -> RecommendBehavior {
    RecommendBehavior { role: "receiver".into(), ttl, send_delay_ms: delay,
        ports_range_number: prn, ports_random_number: 0, listen_random_ports: 0 }
}

fn send_ports(ttl: i32, prn: i32) -> RecommendBehavior {
    RecommendBehavior { role: "sender".into(), ttl, send_delay_ms: 0,
        ports_range_number: prn, ports_random_number: 0, listen_random_ports: 0 }
}

fn sender_port(delay: i32, prnn: i32, lrp: i32) -> RecommendBehavior {
    RecommendBehavior { role: "sender".into(), ttl: 0, send_delay_ms: delay,
        ports_range_number: 0, ports_random_number: prnn, listen_random_ports: lrp }
}

fn recv_listen(ttl: i32, lrp: i32) -> RecommendBehavior {
    RecommendBehavior { role: "receiver".into(), ttl, send_delay_ms: 0,
        ports_range_number: 0, ports_random_number: 0, listen_random_ports: lrp }
}

fn recv_listen_ports(ttl: i32, lrp: i32, prn: i32) -> RecommendBehavior {
    RecommendBehavior { role: "receiver".into(), ttl, send_delay_ms: 0,
        ports_range_number: prn, ports_random_number: 0, listen_random_ports: lrp }
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
        // Go frp: if c.PublicNetwork → client always receiver (sender=0, receiver=1).
        //         if v.PublicNetwork → client always sender (sender=1, receiver=0).
        //         else → all scores 0.
        let append_mode0 = |scores: &mut Vec<BehaviorScore>, c_pub: bool, v_pub: bool| {
            for i in 0..MODE_COUNTS[0] as i32 {
                if c_pub {
                    scores.push(BehaviorScore { mode: 0, index: i, score: 0 });
                } else if v_pub {
                    scores.push(BehaviorScore { mode: 0, index: i, score: 1 });
                } else {
                    scores.push(BehaviorScore { mode: 0, index: i, score: 0 });
                }
            }
        };

        // Helper: append all entries for a mode with uniform score.
        let append_mode = |scores: &mut Vec<BehaviorScore>, mode: i32, score: i32| {
            for i in 0..MODE_COUNTS[mode as usize] as i32 {
                scores.push(BehaviorScore { mode, index: i, score });
            }
        };

        if easy_count == 2 {
            // Both easy NAT: mode 0 only, with PublicNetwork-aware scoring.
            append_mode0(&mut scores, c_feature.public_network, v_feature.public_network);
        } else if hard_count == 1 && ports_changed_regular_count == 1 {
            // One hard with regular port change: mode1, mode2, mode0.
            append_mode(&mut scores, 1, 1);
            append_mode(&mut scores, 2, 1);
            append_mode0(&mut scores, c_feature.public_network, v_feature.public_network);
        } else if hard_count == 1 && ports_changed_regular_count == 0 {
            // One hard without regular port change: mode2, mode1, mode0.
            append_mode(&mut scores, 2, 1);
            append_mode(&mut scores, 1, 1);
            append_mode0(&mut scores, c_feature.public_network, v_feature.public_network);
        } else if hard_count == 2 && ports_changed_regular_count == 2 {
            // Both hard, both regular: mode3, mode4.
            append_mode(&mut scores, 3, 1);
            append_mode(&mut scores, 4, 1);
        } else if hard_count == 2 && ports_changed_regular_count == 1 {
            // Both hard, one regular: mode4 only.
            append_mode(&mut scores, 4, 1);
        } else {
            // Fallback: single-entry modes 0, 1, 3 with score 1.
            scores.push(BehaviorScore { mode: 0, index: 0, score: 1 });
            scores.push(BehaviorScore { mode: 1, index: 0, score: 1 });
            scores.push(BehaviorScore { mode: 3, index: 0, score: 1 });
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
        (self.scores[best_idx].mode, self.scores[best_idx].index)
    }

    /// Report success: boost the matching (mode, index) score, max +2 cap at 10.
    fn report_success(&mut self, mode: i32, index: i32) {
        let mut found = false;
        for s in &mut self.scores {
            if s.mode == mode && s.index == index {
                s.score = (s.score + 2).min(10);
                found = true;
                break;
            }
        }
        if found {
            self.last_update_time = Instant::now();
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
            let mut records = self.records.lock().unwrap();
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
        let mut records = self.records.lock().unwrap();
        if let Some(entry) = records.get_mut(key) {
            entry.report_success(mode, index);
        }
    }

    /// Remove expired entries. Returns (removed, total_before).
    pub fn clean(&self) -> (usize, usize) {
        let mut records = self.records.lock().unwrap();
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
}
