//! NAT analysis engine: recommends hole-punch behaviors based on
//! observed NAT features. Learns from success/failure to improve future
//! recommendations. Go frp v0.69.1 compat: pkg/nathole/analysis.go

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use super::classify::{classify_feature_count, NatFeature};

/// Recommended hole-punch behavior for one peer.
#[derive(Debug, Clone)]
pub struct RecommandBehavior {
    pub role: String,            // "sender" or "receiver"
    pub ttl: i32,
    pub send_delay_ms: i32,
    pub ports_range_number: i32,
    pub ports_random_number: i32,
    pub listen_random_ports: i32,
}

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
    fn new(c_feature: &NatFeature, v_feature: &NatFeature) -> Self {
        let features = vec![c_feature.clone(), v_feature.clone()];
        let (easy_count, hard_count, ports_changed_regular_count) =
            classify_feature_count(&features);

        let mut scores = Vec::new();

        if easy_count == 2 {
            // Both easy NAT: mode 0 only
            scores.push(BehaviorScore { mode: 0, index: 0, score: 1 });
        } else if hard_count == 1 && ports_changed_regular_count == 1 {
            // One hard with regular port change
            scores.push(BehaviorScore { mode: 1, index: 0, score: 1 });
            scores.push(BehaviorScore { mode: 2, index: 0, score: 1 });
            scores.push(BehaviorScore { mode: 0, index: 0, score: 0 });
        } else if hard_count == 1 && ports_changed_regular_count == 0 {
            // One hard without regular port change
            scores.push(BehaviorScore { mode: 2, index: 0, score: 1 });
            scores.push(BehaviorScore { mode: 1, index: 0, score: 1 });
            scores.push(BehaviorScore { mode: 0, index: 0, score: 0 });
        } else if hard_count == 2 && ports_changed_regular_count == 2 {
            // Both hard, both regular
            scores.push(BehaviorScore { mode: 3, index: 0, score: 1 });
            scores.push(BehaviorScore { mode: 4, index: 0, score: 1 });
        } else if hard_count == 2 && ports_changed_regular_count == 1 {
            // Both hard, one regular
            scores.push(BehaviorScore { mode: 4, index: 0, score: 1 });
        } else {
            // Fallback
            scores.push(BehaviorScore { mode: 0, index: 0, score: 1 });
            scores.push(BehaviorScore { mode: 1, index: 0, score: 1 });
            scores.push(BehaviorScore { mode: 3, index: 0, score: 1 });
        }

        // Public network overrides: if client has public network, swap sender/receiver
        if c_feature.public_network {
            for s in &mut scores {
                if s.mode == 0 || s.mode == 1 || s.mode == 3 {
                    s.score = 1;
                }
            }
        }

        MakeHoleRecords {
            scores,
            last_update_time: Instant::now(),
        }
    }

    /// Select highest-scored behavior, decrement it to rotate choices.
    fn recommand(&mut self) -> (i32, i32) {
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

    /// Report success: boost the matching (mode, index) score.
    fn report_success(&mut self, mode: i32, index: i32) {
        for s in &mut self.scores {
            if s.mode == mode && s.index == index {
                s.score = (s.score + 2).min(10);
                break;
            }
        }
        self.last_update_time = Instant::now();
    }
}

/// Predefined behavior tables for each mode.
/// Each mode has a list of (behavior_a, behavior_b) pairs.
/// Which peer gets which behavior is determined by role swap rules.
fn get_behavior_by_mode_and_index(mode: i32, index: i32) -> (RecommandBehavior, RecommandBehavior) {
    let idx = index as usize;
    match mode {
        0 => {
            let behaviors = vec![(
                RecommandBehavior {
                    role: "sender".into(), ttl: 0, send_delay_ms: 2000,
                    ports_range_number: 16, ports_random_number: 4, listen_random_ports: 0,
                },
                RecommandBehavior {
                    role: "receiver".into(), ttl: 0, send_delay_ms: 0,
                    ports_range_number: 0, ports_random_number: 0, listen_random_ports: 0,
                },
            )];
            behaviors.get(idx).cloned().unwrap_or_else(|| behaviors[0].clone())
        }
        1 => {
            // HardNAT is sender, EasyNAT is receiver
            let behaviors = vec![(
                RecommandBehavior {
                    role: "sender".into(), ttl: 4, send_delay_ms: 2000,
                    ports_range_number: 48, ports_random_number: 4, listen_random_ports: 0,
                },
                RecommandBehavior {
                    role: "receiver".into(), ttl: 0, send_delay_ms: 0,
                    ports_range_number: 0, ports_random_number: 0, listen_random_ports: 4,
                },
            )];
            behaviors.get(idx).cloned().unwrap_or_else(|| behaviors[0].clone())
        }
        2 => {
            // HardNAT is receiver, EasyNAT is sender
            let behaviors = vec![(
                RecommandBehavior {
                    role: "sender".into(), ttl: 4, send_delay_ms: 2000,
                    ports_range_number: 48, ports_random_number: 4, listen_random_ports: 4,
                },
                RecommandBehavior {
                    role: "receiver".into(), ttl: 0, send_delay_ms: 0,
                    ports_range_number: 0, ports_random_number: 0, listen_random_ports: 0,
                },
            )];
            behaviors.get(idx).cloned().unwrap_or_else(|| behaviors[0].clone())
        }
        3 => {
            let behaviors = vec![(
                RecommandBehavior {
                    role: "sender".into(), ttl: 4, send_delay_ms: 2000,
                    ports_range_number: 48, ports_random_number: 4, listen_random_ports: 4,
                },
                RecommandBehavior {
                    role: "receiver".into(), ttl: 0, send_delay_ms: 0,
                    ports_range_number: 0, ports_random_number: 0, listen_random_ports: 4,
                },
            )];
            behaviors.get(idx).cloned().unwrap_or_else(|| behaviors[0].clone())
        }
        4 => {
            // Regular ports change peer is sender
            let behaviors = vec![(
                RecommandBehavior {
                    role: "sender".into(), ttl: 4, send_delay_ms: 2000,
                    ports_range_number: 48, ports_random_number: 4, listen_random_ports: 4,
                },
                RecommandBehavior {
                    role: "receiver".into(), ttl: 0, send_delay_ms: 0,
                    ports_range_number: 0, ports_random_number: 0, listen_random_ports: 0,
                },
            )];
            behaviors.get(idx).cloned().unwrap_or_else(|| behaviors[0].clone())
        }
        _ => {
            // Default fallback: mode 0
            let b = RecommandBehavior {
                role: "sender".into(), ttl: 0, send_delay_ms: 2000,
                ports_range_number: 16, ports_random_number: 4, listen_random_ports: 0,
            };
            let b2 = RecommandBehavior {
                role: "receiver".into(), ttl: 0, send_delay_ms: 0,
                ports_range_number: 0, ports_random_number: 0, listen_random_ports: 0,
            };
            (b, b2)
        }
    }
}

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
    pub fn get_recommand_behaviors(
        &self,
        key: &str,
        c_feature: &NatFeature,
        v_feature: &NatFeature,
    ) -> (i32, i32, RecommandBehavior, RecommandBehavior) {
        let (mode, index) = {
            let mut records = self.records.lock().unwrap();
            let entry = records
                .entry(key.to_string())
                .or_insert_with(|| MakeHoleRecords::new(c_feature, v_feature));
            entry.recommand()
        };

        let (mut c_behavior, mut v_behavior) = get_behavior_by_mode_and_index(mode, index);

        // Role swap rules per mode
        match mode {
            1 => {
                // Mode 1: HardNAT is always sender. If client is EasyNAT, swap.
                if c_feature.nat_type == super::classify::EASY_NAT {
                    std::mem::swap(&mut c_behavior, &mut v_behavior);
                }
            }
            2 => {
                // Mode 2: HardNAT is always receiver. If client is HardNAT, swap.
                if c_feature.nat_type == super::classify::HARD_NAT {
                    std::mem::swap(&mut c_behavior, &mut v_behavior);
                }
            }
            4 => {
                // Mode 4: Regular ports change peer is always sender.
                // If client lacks regular ports change, swap.
                if !c_feature.regular_ports_change {
                    std::mem::swap(&mut c_behavior, &mut v_behavior);
                }
            }
            _ => {} // Modes 0, 3: no swap needed
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

        let (mode, _, cb, vb) = analyzer.get_recommand_behaviors("test-key", &cf, &vf);
        assert_eq!(mode, 0);
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

        let (mode2, _, _, _) = analyzer.get_recommand_behaviors("test-key", &cf, &vf);
        // Should still prefer mode 0 since we boosted it
        assert_eq!(mode2, 0);
    }

    #[test]
    fn test_clean_expired() {
        let analyzer = Analyzer::new(Duration::from_secs(0));
        let addrs = vec!["1.2.3.4:1234".into(), "1.2.3.4:1234".into()];
        let cf = classify_nat_feature(&addrs, &[]).unwrap();
        let vf = classify_nat_feature(&addrs, &[]).unwrap();

        analyzer.get_recommand_behaviors("test-key", &cf, &vf);
        let (removed, _total) = analyzer.clean();
        assert!(removed > 0);
    }
}
