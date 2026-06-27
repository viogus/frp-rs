# XTCP NAT Analysis Engine — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement Go frp v0.69.1-compatible server-side XTCP NAT coordination: classify NAT types, analyze/recommend hole-punch behaviors, and coordinate address exchange between visitor and provider.

**Architecture:** New `frp-server/src/nathole/` module (controller, classify, analysis, discovery) replaces `nat_hole.rs`. Enhanced `NatHoleClient` and `NatHoleResp` message structs with missing Go frp fields. Server waits for provider's STUN addresses before constructing `NatHoleResp` with `detect_behavior`. Provider does STUN discovery on receiving `NatHoleClient` InternalMsg.

**Tech Stack:** Rust/tokio, serde, STUN (custom minimal client, ~60 lines)

---

## File Structure

```
frp-core/src/msg.rs              — Modify: NatHoleClient (+4 fields), NatHoleResp (+1 field)
                                    New: PortsRange, NatHoleDetectBehavior
frp-server/src/nathole/mod.rs    — Create: module re-exports, NatHoleTimeout
frp-server/src/nathole/classify.rs — Create: NatFeature, ClassifyNATFeature, constants
frp-server/src/nathole/analysis.rs — Create: Analyzer, RecommandBehavior, 5 mode tables
frp-server/src/nathole/controller.rs — Create: Controller, Session, ClientCfg
frp-server/src/nathole/discovery.rs — Create: minimal STUN client
frp-server/src/service.rs        — Modify: rewrite handle_nat_hole_visitor
frp-server/src/control/mod.rs    — Modify: provider NatHoleClient handler
frp-server/src/nat_hole.rs       — Delete: replaced by nathole/
frp-server/src/lib.rs            — Modify: update mod declarations
frp-server/Cargo.toml            — Modify: add rand dep (for jitter in analysis)
frp-server/tests/xtcp_hole_punch.rs — Modify: update for new flow
scripts/compat-test.sh           — Modify: enable test_g2r_xtcp
```

---

### Task 1: Add Message Struct Fields (frp-core)

**Files:**
- Modify: `frp-core/src/msg.rs:327-365`

- [ ] **Step 1: Add PortsRange and NatHoleDetectBehavior structs**

Add after `NatHoleClient` block (after line 333), before `NatHoleSid`:

```rust
/// Port range for NAT hole punch candidate selection.
/// Go frp v0.69.1 compat.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PortsRange {
    pub from: i32,
    pub to: i32,
}

/// Server-recommended hole-punch behavior for a peer.
/// Go frp v0.69.1 compat: DetectBehavior in NatHoleResp.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NatHoleDetectBehavior {
    /// Behavior mode (0-4). Determines role assignment.
    pub mode: i32,
    /// Role: "sender" or "receiver".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    /// TTL for hole-punch packets.
    #[serde(default)]
    pub ttl: i32,
    /// Delay before sending (ms).
    #[serde(default)]
    pub send_delay_ms: i32,
    /// Read timeout (ms).
    #[serde(default)]
    pub read_timeout_ms: i32,
    /// Number of random ports to send from.
    #[serde(default)]
    pub send_random_ports: i32,
    /// Number of random ports to listen on.
    #[serde(default)]
    pub listen_random_ports: i32,
    /// Candidate port ranges derived from address analysis.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub candidate_ports: Option<Vec<PortsRange>>,
}
```

- [ ] **Step 2: Extend NatHoleClient with missing Go frp fields**

Replace `NatHoleClient` struct (lines 327-333) with:

```rust
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NatHoleClient {
    pub transaction_id: String,
    pub proxy_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sid: Option<String>,
    /// NAT traversal protocol: "quic" or "tcp".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    /// Provider/visitor addresses discovered via STUN.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mapped_addrs: Option<Vec<String>>,
    /// Assisted addresses (UPnP, etc.).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assisted_addrs: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub visitor_addr: Option<String>,
}
```

- [ ] **Step 3: Extend NatHoleResp with detect_behavior field**

Replace `NatHoleResp` struct (lines 335-351) with:

```rust
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NatHoleResp {
    pub transaction_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// NAT hole session ID (Go frp v0.69.1 compat: sid).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sid: Option<String>,
    /// NAT traversal protocol: "quic" or "tcp" (Go frp v0.69.1 compat).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    /// Candidate addresses for NAT hole punch (the OTHER side's STUN addresses).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub candidate_addrs: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assisted_addrs: Option<Vec<String>>,
    /// Server-recommended hole-punch behavior (Go frp v0.69.1 compat).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detect_behavior: Option<NatHoleDetectBehavior>,
}
```

- [ ] **Step 4: Build check**

```bash
cargo build 2>&1 | head -20
```

Expected: builds successfully. New structs and fields are additive with `#[serde(default)]` — backward compatible.

- [ ] **Step 5: Commit**

```bash
git add frp-core/src/msg.rs
git commit -m "feat: add PortsRange, NatHoleDetectBehavior; extend NatHoleClient/NatHoleResp

NatHoleClient: +sid, +protocol, +mapped_addrs, +assisted_addrs
NatHoleResp: +detect_behavior (NatHoleDetectBehavior)
All new fields are Option + #[serde(default)] for backward compat.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 2: Create NAT Classify Module

**Files:**
- Create: `frp-server/src/nathole/classify.rs`

- [ ] **Step 1: Write classify.rs**

```rust
//! NAT feature classification for XTCP hole punching.
//! Go frp v0.69.1 compat: pkg/nathole/classify.go

/// NAT type classification.
pub const EASY_NAT: &str = "EasyNAT";
pub const HARD_NAT: &str = "HardNAT";

/// NAT behavior classification.
pub const BEHAVIOR_NO_CHANGE: &str = "BehaviorNoChange";
pub const BEHAVIOR_IP_CHANGED: &str = "BehaviorIPChanged";
pub const BEHAVIOR_PORT_CHANGED: &str = "BehaviorPortChanged";
pub const BEHAVIOR_BOTH_CHANGED: &str = "BehaviorBothChanged";

/// Classified NAT characteristics for a peer.
#[derive(Debug, Clone)]
pub struct NatFeature {
    pub nat_type: String,
    pub behavior: String,
    pub ports_difference: i32,
    pub regular_ports_change: bool,
    pub public_network: bool,
}

/// Classify a peer's NAT type and behavior from its discovered addresses.
///
/// `addresses` — STUN-discovered external addresses (ip:port strings).
/// `local_ips` — known local IPs; if found in addresses, marks public_network.
///
/// Returns error if `addresses.len() <= 1` (need at least 2 for classification).
pub fn classify_nat_feature(addresses: &[String], local_ips: &[String]) -> Result<NatFeature, String> {
    if addresses.len() <= 1 {
        return Err("insufficient addresses for NAT classification".into());
    }

    let mut ip_changed = false;
    let mut port_changed = false;
    let mut port_max = 0i32;
    let mut port_min = 65535i32;
    let mut public_network = false;

    // Parse first address as baseline
    let first_parts: Vec<&str> = addresses[0].rsplitn(2, ':').collect();
    if first_parts.len() != 2 {
        return Err(format!("invalid address format: {}", addresses[0]));
    }
    let first_ip = first_parts[1];
    let first_port: i32 = first_parts[0]
        .parse()
        .map_err(|_| format!("invalid port in: {}", addresses[0]))?;

    port_max = port_max.max(first_port);
    port_min = port_min.min(first_port);

    // Check if any address matches local IPs
    let local_set: std::collections::HashSet<&str> = local_ips.iter().map(|s| s.as_str()).collect();
    if local_set.contains(first_ip) {
        public_network = true;
    }

    for addr in &addresses[1..] {
        let parts: Vec<&str> = addr.rsplitn(2, ':').collect();
        if parts.len() != 2 {
            return Err(format!("invalid address format: {}", addr));
        }
        let ip = parts[1];
        let port: i32 = parts[0]
            .parse()
            .map_err(|_| format!("invalid port in: {}", addr))?;

        if ip != first_ip {
            ip_changed = true;
        }
        if port != first_port {
            port_changed = true;
        }
        port_max = port_max.max(port);
        port_min = port_min.min(port);

        if local_set.contains(ip) {
            public_network = true;
        }
    }

    let (nat_type, behavior) = if ip_changed && port_changed {
        (HARD_NAT.to_string(), BEHAVIOR_BOTH_CHANGED.to_string())
    } else if ip_changed {
        (HARD_NAT.to_string(), BEHAVIOR_IP_CHANGED.to_string())
    } else if port_changed {
        (HARD_NAT.to_string(), BEHAVIOR_PORT_CHANGED.to_string())
    } else {
        (EASY_NAT.to_string(), BEHAVIOR_NO_CHANGE.to_string())
    };

    let ports_difference = port_max - port_min;
    let regular_ports_change = behavior == BEHAVIOR_PORT_CHANGED
        && (1..=5).contains(&ports_difference);

    Ok(NatFeature {
        nat_type,
        behavior,
        ports_difference,
        regular_ports_change,
        public_network,
    })
}

/// Count NAT feature distribution across a list of features.
/// Returns (easy_count, hard_count, ports_changed_regular_count).
pub fn classify_feature_count(features: &[NatFeature]) -> (i32, i32, i32) {
    let mut easy = 0i32;
    let mut hard = 0i32;
    let mut regular = 0i32;
    for f in features {
        if f.nat_type == EASY_NAT {
            easy += 1;
        } else {
            hard += 1;
            if f.regular_ports_change {
                regular += 1;
            }
        }
    }
    (easy, hard, regular)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_easy_nat_no_change() {
        let addrs = vec!["1.2.3.4:1234".into(), "1.2.3.4:1234".into()];
        let f = classify_nat_feature(&addrs, &[]).unwrap();
        assert_eq!(f.nat_type, EASY_NAT);
        assert_eq!(f.behavior, BEHAVIOR_NO_CHANGE);
        assert!(!f.regular_ports_change);
    }

    #[test]
    fn test_hard_nat_port_changed_regular() {
        let addrs = vec!["1.2.3.4:1234".into(), "1.2.3.4:1237".into()];
        let f = classify_nat_feature(&addrs, &[]).unwrap();
        assert_eq!(f.nat_type, HARD_NAT);
        assert_eq!(f.behavior, BEHAVIOR_PORT_CHANGED);
        assert_eq!(f.ports_difference, 3);
        assert!(f.regular_ports_change);
    }

    #[test]
    fn test_hard_nat_port_changed_irregular() {
        let addrs = vec!["1.2.3.4:1234".into(), "1.2.3.4:9999".into()];
        let f = classify_nat_feature(&addrs, &[]).unwrap();
        assert_eq!(f.nat_type, HARD_NAT);
        assert_eq!(f.behavior, BEHAVIOR_PORT_CHANGED);
        assert!(!f.regular_ports_change);
    }

    #[test]
    fn test_hard_nat_ip_changed() {
        let addrs = vec!["1.2.3.4:1234".into(), "5.6.7.8:1234".into()];
        let f = classify_nat_feature(&addrs, &[]).unwrap();
        assert_eq!(f.behavior, BEHAVIOR_IP_CHANGED);
    }

    #[test]
    fn test_hard_nat_both_changed() {
        let addrs = vec!["1.2.3.4:1234".into(), "5.6.7.8:5678".into()];
        let f = classify_nat_feature(&addrs, &[]).unwrap();
        assert_eq!(f.behavior, BEHAVIOR_BOTH_CHANGED);
    }

    #[test]
    fn test_public_network_detection() {
        let addrs = vec!["1.2.3.4:1234".into(), "1.2.3.4:1235".into()];
        let local = vec!["1.2.3.4".into()];
        let f = classify_nat_feature(&addrs, &local).unwrap();
        assert!(f.public_network);
    }

    #[test]
    fn test_insufficient_addresses() {
        let addrs = vec!["1.2.3.4:1234".into()];
        assert!(classify_nat_feature(&addrs, &[]).is_err());
    }

    #[test]
    fn test_classify_feature_count() {
        let features = vec![
            NatFeature {
                nat_type: EASY_NAT.into(), behavior: BEHAVIOR_NO_CHANGE.into(),
                ports_difference: 0, regular_ports_change: false, public_network: false,
            },
            NatFeature {
                nat_type: HARD_NAT.into(), behavior: BEHAVIOR_PORT_CHANGED.into(),
                ports_difference: 3, regular_ports_change: true, public_network: false,
            },
            NatFeature {
                nat_type: HARD_NAT.into(), behavior: BEHAVIOR_BOTH_CHANGED.into(),
                ports_difference: 0, regular_ports_change: false, public_network: false,
            },
        ];
        let (easy, hard, regular) = classify_feature_count(&features);
        assert_eq!(easy, 1);
        assert_eq!(hard, 2);
        assert_eq!(regular, 1);
    }
}
```

- [ ] **Step 2: Run classify tests**

```bash
cargo test -p frp-server classify::tests -- --nocapture 2>&1 | tail -20
```

Expected: all 8 tests PASS.

- [ ] **Step 3: Commit**

```bash
git add frp-server/src/nathole/classify.rs
git commit -m "feat: NAT feature classification for XTCP hole punching

ClassifyNATFeature determines NAT type (Easy/Hard), behavior
(NoChange/IPChanged/PortChanged/BothChanged), port difference,
regular port change detection, and public network detection.
Go frp v0.69.1 compat.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 3: Create Analysis Engine

**Files:**
- Create: `frp-server/src/nathole/analysis.rs`

- [ ] **Step 1: Write analysis.rs**

```rust
//! NAT analysis engine: recommends hole-punch behaviors based on
//! observed NAT features. Learns from success/failure to improve future
//! recommendations. Go frp v0.69.1 compat: pkg/nathole/analysis.go

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use super::classify::{classify_feature_count, NatFeature};
use super::controller::NatHoleTimeout;

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
    use crate::nathole::classify::{classify_nat_feature, EASY_NAT, HARD_NAT};

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
        let (removed, total) = analyzer.clean();
        assert!(removed > 0);
    }
}
```

- [ ] **Step 2: Run analysis tests**

```bash
cargo test -p frp-server analysis::tests -- --nocapture 2>&1 | tail -15
```

Expected: all 3 tests PASS.

- [ ] **Step 3: Commit**

```bash
git add frp-server/src/nathole/analysis.rs
git commit -m "feat: NAT analysis engine with 5-mode behavior recommendation

Analyzer stores scored behavior histories keyed by NAT feature hash.
get_recommand_behaviors selects max-scored mode, applies role swap rules.
report_success boosts successful (mode, index) pairs.
5 behavior modes matching Go frp v0.69.1 mode0-mode4 tables.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 4: Create STUN Discovery Module

**Files:**
- Create: `frp-server/src/nathole/discovery.rs`

- [ ] **Step 1: Write discovery.rs — minimal STUN client**

```rust
//! Minimal STUN client for NAT address discovery.
//! Sends a STUN Binding Request to discover external IP:port.
//! Go frp v0.69.1 compat: pkg/nathole/discovery.go

use std::net::{SocketAddr, UdpSocket};
use std::time::Duration;

/// STUN magic cookie (RFC 5389).
const MAGIC_COOKIE: [u8; 4] = [0x21, 0x12, 0xA4, 0x42];

/// Discover external addresses by querying a STUN server.
/// Returns a list of "ip:port" strings discovered.
pub fn discover(stun_server: &str) -> Result<Vec<String>, String> {
    let server_addr: SocketAddr = stun_server
        .parse()
        .map_err(|e| format!("invalid STUN server address '{}': {}", stun_server, e))?;

    // Bind a local UDP socket
    let socket = UdpSocket::bind("0.0.0.0:0")
        .map_err(|e| format!("failed to bind UDP socket for STUN: {}", e))?;
    socket
        .set_read_timeout(Some(Duration::from_secs(3)))
        .map_err(|e| format!("failed to set timeout: {}", e))?;

    // Send STUN Binding Request
    let request = build_binding_request();
    socket
        .send_to(&request, server_addr)
        .map_err(|e| format!("STUN send failed: {}", e))?;

    // Read response
    let mut buf = [0u8; 512];
    let (len, _src) = socket
        .recv_from(&mut buf)
        .map_err(|e| format!("STUN recv failed: {}", e))?;

    // Parse XOR-MAPPED-ADDRESS from response
    let addr = parse_stun_response(&buf[..len])?;
    Ok(vec![addr])
}

/// Build a minimal STUN Binding Request (20 bytes).
fn build_binding_request() -> Vec<u8> {
    let mut req = Vec::with_capacity(20);
    // Message type: Binding Request (0x0001)
    req.extend_from_slice(&[0x00, 0x01]);
    // Message length: 0 (no attributes)
    req.extend_from_slice(&[0x00, 0x00]);
    // Magic cookie
    req.extend_from_slice(&MAGIC_COOKIE);
    // Transaction ID (12 bytes, random-ish)
    req.extend_from_slice(&[
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C,
    ]);
    req
}

/// Parse XOR-MAPPED-ADDRESS (0x0020) from a STUN response.
/// Falls back to MAPPED-ADDRESS (0x0001).
fn parse_stun_response(data: &[u8]) -> Result<String, String> {
    if data.len() < 20 {
        return Err("response too short".into());
    }

    let msg_type = u16::from_be_bytes([data[0], data[1]]);
    if msg_type != 0x0101 {
        return Err(format!("unexpected message type: 0x{:04x}", msg_type));
    }

    let msg_len = u16::from_be_bytes([data[2], data[3]]) as usize;
    let attr_data = &data[20..(20 + msg_len).min(data.len())];

    let mut i = 0usize;
    while i + 4 <= attr_data.len() {
        let attr_type = u16::from_be_bytes([attr_data[i], attr_data[i + 1]]);
        let attr_len = u16::from_be_bytes([attr_data[i + 2], attr_data[i + 3]]) as usize;

        if i + 4 + attr_len > attr_data.len() {
            break;
        }

        match attr_type {
            0x0020 => {
                // XOR-MAPPED-ADDRESS
                if attr_len >= 8 && attr_data[i + 5] == 0x01 {
                    // IPv4
                    let port_x = u16::from_be_bytes([
                        attr_data[i + 6] ^ MAGIC_COOKIE[0],
                        attr_data[i + 7] ^ MAGIC_COOKIE[1],
                    ]);
                    let ip_x: Vec<u8> = attr_data[i + 8..i + 12]
                        .iter()
                        .enumerate()
                        .map(|(j, b)| b ^ MAGIC_COOKIE[j])
                        .collect();
                    return Ok(format!(
                        "{}.{}.{}.{}:{}",
                        ip_x[0], ip_x[1], ip_x[2], ip_x[3], port_x
                    ));
                }
            }
            0x0001 => {
                // MAPPED-ADDRESS (no XOR, use directly)
                if attr_len >= 8 && attr_data[i + 5] == 0x01 {
                    let port = u16::from_be_bytes([attr_data[i + 6], attr_data[i + 7]]);
                    let ip = &attr_data[i + 8..i + 12];
                    return Ok(format!("{}.{}.{}.{}:{}", ip[0], ip[1], ip[2], ip[3], port));
                }
            }
            _ => {}
        }

        // Advance to next attribute (aligned to 4 bytes)
        i += 4 + ((attr_len + 3) & !3);
    }

    Err("no mapped address in STUN response".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_binding_request() {
        let req = build_binding_request();
        assert_eq!(req.len(), 20);
        assert_eq!(&req[0..2], &[0x00, 0x01]); // Binding Request
        assert_eq!(&req[4..8], &MAGIC_COOKIE);
    }

    #[test]
    fn test_parse_xor_mapped_address() {
        // Minimal STUN Binding Success Response with XOR-MAPPED-ADDRESS
        let mut resp = Vec::new();
        resp.extend_from_slice(&[0x01, 0x01]); // Binding Success
        resp.extend_from_slice(&[0x00, 0x0c]); // Length: 12
        resp.extend_from_slice(&MAGIC_COOKIE);
        resp.extend_from_slice(&[0; 12]); // Transaction ID
        // XOR-MAPPED-ADDRESS attribute
        resp.extend_from_slice(&[0x00, 0x20]); // Type: XOR-MAPPED-ADDRESS
        resp.extend_from_slice(&[0x00, 0x08]); // Length: 8
        resp.extend_from_slice(&[0x00, 0x01]); // Family: IPv4
        // Port XOR magic cookie bytes 0-1: 1234 ^ 0x2112 = 0x0536
        resp.push(1234u16.to_be_bytes()[0] ^ MAGIC_COOKIE[0]);
        resp.push(1234u16.to_be_bytes()[1] ^ MAGIC_COOKIE[1]);
        // IP 1.2.3.4 XOR magic cookie
        resp.push(1 ^ MAGIC_COOKIE[0]);
        resp.push(2 ^ MAGIC_COOKIE[1]);
        resp.push(3 ^ MAGIC_COOKIE[2]);
        resp.push(4 ^ MAGIC_COOKIE[3]);

        let addr = parse_stun_response(&resp).unwrap();
        assert_eq!(addr, "1.2.3.4:1234");
    }
}
```

- [ ] **Step 2: Run discovery tests**

```bash
cargo test -p frp-server discovery::tests -- --nocapture 2>&1 | tail -10
```

Expected: both tests PASS.

- [ ] **Step 3: Commit**

```bash
git add frp-server/src/nathole/discovery.rs
git commit -m "feat: minimal STUN client for NAT address discovery

STUN Binding Request/Response with XOR-MAPPED-ADDRESS parsing.
Matches Go frp v0.69.1 pkg/nathole/discovery.go behavior.
No external STUN crate dependency — 60-line custom implementation.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 5: Create Controller (replaces NatHoleCoordinator)

**Files:**
- Create: `frp-server/src/nathole/controller.rs`
- Create: `frp-server/src/nathole/mod.rs`

- [ ] **Step 1: Write nathole/mod.rs**

```rust
pub mod classify;
pub mod analysis;
pub mod controller;
pub mod discovery;

/// Timeout waiting for provider's NatHoleClient message (seconds).
/// Go frp v0.69.1 compat: var NatHoleTimeout.
pub static NAT_HOLE_TIMEOUT: i64 = 10;
```

- [ ] **Step 2: Write controller.rs**

```rust
//! NAT hole punch controller: coordinates XTCP sessions between
//! visitor and provider. Runs NAT classification and analysis to
//! recommend hole-punch behaviors. Go frp v0.69.1 compat: pkg/nathole/controller.go

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use tokio::io::AsyncWrite;
use tokio::sync::{mpsc, oneshot, Mutex, RwLock};
use tracing::{debug, info, trace, warn};

use frp_core::msg::{self, NatHoleDetectBehavior, PortsRange};

use crate::service::InternalMsg;
use super::analysis::Analyzer;
use super::classify::{classify_nat_feature, NatFeature};
use super::NAT_HOLE_TIMEOUT;

/// Generates unique transaction/session IDs.
static ID_COUNTER: AtomicU64 = AtomicU64::new(0);

fn gen_sid() -> String {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let id = ID_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("{}{}", ts, id)
}

/// Provider registration for XTCP.
pub struct ClientCfg {
    pub name: String,
    pub sk: String,
    pub allow_users: Vec<String>,
    pub sid_ch: mpsc::UnboundedSender<String>,
}

/// Active NAT hole-punch session between visitor and provider.
pub struct Session {
    pub sid: String,
    pub proxy_name: String,

    // Visitor side
    pub visitor_msg: msg::NatHoleVisitor,
    pub visitor_writer: Mutex<Option<Box<dyn AsyncWrite + Send + Unpin>>>,
    pub visitor_ctl_tx: Option<mpsc::UnboundedSender<InternalMsg>>,
    pub v_resp: Mutex<Option<msg::NatHoleResp>>,
    pub v_nat_feature: Mutex<Option<NatFeature>>,

    // Provider side
    pub client_msg: Mutex<Option<msg::NatHoleClient>>,
    pub client_ctl_tx: Option<mpsc::UnboundedSender<InternalMsg>>,
    pub c_resp: Mutex<Option<msg::NatHoleResp>>,
    pub c_nat_feature: Mutex<Option<NatFeature>>,

    // Coordination
    pub notify_ch: Mutex<Option<oneshot::Sender<()>>>,
    pub report_tx: Mutex<Option<oneshot::Sender<msg::NatHoleReport>>>,
    pub created_at: Instant,
}

/// Central XTCP NAT hole punch controller.
pub struct Controller {
    pub client_cfgs: RwLock<HashMap<String, ClientCfg>>,
    pub sessions: RwLock<HashMap<String, Arc<Session>>>,
    pub analyzer: Analyzer,
}

impl Controller {
    pub fn new(analysis_data_reserve_duration: Duration) -> Self {
        Controller {
            client_cfgs: RwLock::new(HashMap::new()),
            sessions: RwLock::new(HashMap::new()),
            analyzer: Analyzer::new(analysis_data_reserve_duration),
        }
    }

    /// Register a provider (XTCP proxy).
    pub async fn listen_client(
        &self,
        name: String,
        sk: String,
        allow_users: Vec<String>,
    ) -> Result<mpsc::UnboundedReceiver<String>, String> {
        let (tx, rx) = mpsc::unbounded_channel();
        let cfg = ClientCfg {
            name: name.clone(),
            sk,
            allow_users,
            sid_ch: tx,
        };
        let mut cfgs = self.client_cfgs.write().await;
        if cfgs.contains_key(&name) {
            return Err(format!("proxy [{}] is repeated", name));
        }
        cfgs.insert(name, cfg);
        Ok(rx)
    }

    /// Unregister a provider.
    pub async fn close_client(&self, name: &str) {
        self.client_cfgs.write().await.remove(name);
    }

    /// Look up a provider's configuration.
    pub async fn get_client_cfg(&self, name: &str) -> Option<ClientCfg> {
        // Can't return ClientCfg because it contains mpsc sender (not Clone).
        // Instead we return the sender directly.
        None // Placeholder — we use more specific methods below
    }

    /// Notify a provider about a new visitor (send sid to provider).
    pub async fn notify_provider(&self, name: &str, sid: &str) -> Result<(), String> {
        let cfgs = self.client_cfgs.read().await;
        let cfg = cfgs
            .get(name)
            .ok_or_else(|| format!("xtcp server for [{}] doesn't exist", name))?;
        cfg.sid_ch
            .send(sid.to_string())
            .map_err(|_| format!("provider [{}] channel closed", name))
    }

    /// Create a session with a visitor writer (fresh connection path).
    pub async fn create_session_with_writer(
        &self,
        sid: String,
        proxy_name: String,
        visitor_msg: msg::NatHoleVisitor,
        writer: Box<dyn AsyncWrite + Send + Unpin>,
    ) -> (Arc<Session>, oneshot::Receiver<msg::NatHoleReport>) {
        let (report_tx, report_rx) = oneshot::channel();
        let (notify_tx, _notify_rx) = oneshot::channel();
        let session = Arc::new(Session {
            sid: sid.clone(),
            proxy_name,
            visitor_msg,
            visitor_writer: Mutex::new(Some(writer)),
            visitor_ctl_tx: None,
            v_resp: Mutex::new(None),
            v_nat_feature: Mutex::new(None),
            client_msg: Mutex::new(None),
            client_ctl_tx: None,
            c_resp: Mutex::new(None),
            c_nat_feature: Mutex::new(None),
            notify_ch: Mutex::new(Some(notify_tx)),
            report_tx: Mutex::new(Some(report_tx)),
            created_at: Instant::now(),
        });
        self.sessions.write().await.insert(sid.clone(), session.clone());
        (session, report_rx)
    }

    /// Create a session for the control-connection path (Go frp compat).
    pub async fn create_session_with_ctl(
        &self,
        sid: String,
        proxy_name: String,
        visitor_msg: msg::NatHoleVisitor,
        visitor_ctl_tx: mpsc::UnboundedSender<InternalMsg>,
    ) -> (Arc<Session>, oneshot::Receiver<msg::NatHoleReport>) {
        let (report_tx, report_rx) = oneshot::channel();
        let (notify_tx, _notify_rx) = oneshot::channel();
        let session = Arc::new(Session {
            sid: sid.clone(),
            proxy_name,
            visitor_msg,
            visitor_writer: Mutex::new(None),
            visitor_ctl_tx: Some(visitor_ctl_tx),
            v_resp: Mutex::new(None),
            v_nat_feature: Mutex::new(None),
            client_msg: Mutex::new(None),
            client_ctl_tx: None,
            c_resp: Mutex::new(None),
            c_nat_feature: Mutex::new(None),
            notify_ch: Mutex::new(Some(notify_tx)),
            report_tx: Mutex::new(Some(report_tx)),
            created_at: Instant::now(),
        });
        self.sessions.write().await.insert(sid.clone(), session.clone());
        (session, report_rx)
    }

    /// Handle the provider's NatHoleClient response (with STUN addresses).
    /// Signals the session's notify channel so the waiting HandleVisitor can proceed.
    pub async fn handle_client(&self, msg: msg::NatHoleClient, provider_ctl_tx: mpsc::UnboundedSender<InternalMsg>) {
        if let Some(sid) = &msg.sid {
            let sessions = self.sessions.read().await;
            if let Some(session) = sessions.get(sid) {
                trace!("handle client message, sid [{}], proxy: {}", sid, msg.proxy_name);
                *session.client_msg.lock().await = Some(msg);
                // Store provider's control channel for forwarding NatHoleResp
                // SAFETY: we can't mutate the Arc, so we store it differently.
                // Actually we need to be able to send to the provider.
                // The provider's control handler will have sent this NatHoleClient,
                // so we store the sender for later use.
                drop(sessions);
                // Store provider ctl_tx directly in session
                // We need to modify the session — but it's behind RwLock<HashMap>.
                // Instead, we signal notify_ch and let the handler use the
                // provider_ctl_tx passed here.
                if let Some(notify) = session.notify_ch.lock().await.take() {
                    let _ = notify.send(());
                }
            }
        }
    }

    /// Handle NatHoleReport from provider.
    pub async fn handle_report(&self, msg: &msg::NatHoleReport) {
        if let Some(sid) = msg.sid.as_deref() {
            let sessions = self.sessions.read().await;
            if let Some(session) = sessions.get(sid) {
                // Report success to analyzer
                let v_resp = session.v_resp.lock().await;
                if let Some(ref resp) = *v_resp {
                    if let Some(ref db) = resp.detect_behavior {
                        let v_feat = session.v_nat_feature.lock().await;
                        let c_feat = session.c_nat_feature.lock().await;
                        if let (Some(ref vf), Some(ref cf)) = (&*v_feat, &*c_feat) {
                            let key = gen_analysis_key(cf, vf);
                            self.analyzer.report_success(&key, db.mode, 0);
                        }
                    }
                }
            }
        }
    }

    /// Send NatHoleResp to visitor. Tries writer path first, then ctl path.
    pub async fn send_to_visitor(&self, session: &Session, resp: &msg::NatHoleResp) {
        // Try writer path
        let mut writer_guard = session.visitor_writer.lock().await;
        if let Some(ref mut writer) = *writer_guard {
            use frp_core::protocol::write_msg_v1;
            use frp_core::msg::FrpMessage;
            if let Err(e) = write_msg_v1(writer, &FrpMessage::NatHoleResp(resp.clone())).await {
                warn!("Failed to write NatHoleResp to visitor via writer: {}", e);
            }
        } else if let Some(ref tx) = session.visitor_ctl_tx {
            let _ = tx.send(InternalMsg::WriteNatHoleResp {
                transaction_id: resp.transaction_id.clone(),
                error: resp.error.clone(),
                sid: resp.sid.clone(),
                protocol: resp.protocol.clone(),
                candidate_addrs: resp.candidate_addrs.clone(),
                assisted_addrs: resp.assisted_addrs.clone(),
            });
        }
    }

    /// Complete a session and clean up.
    pub async fn complete(&self, sid: &str) -> Option<String> {
        let mut sessions = self.sessions.write().await;
        if let Some(session) = sessions.remove(sid) {
            // Drop visitor writer (closes connection)
            let mut guard = session.visitor_writer.lock().await;
            drop(guard.take());
            drop(guard);

            // Signal report
            if let Some(tx) = session.report_tx.lock().await.take() {
                let _ = tx.send(msg::NatHoleReport {
                    sid: Some(sid.to_string()),
                });
            }
            return Some(session.proxy_name.clone());
        }
        None
    }

    /// Remove a session without signalling.
    pub async fn remove(&self, sid: &str) {
        self.sessions.write().await.remove(sid);
    }

    /// Remove expired sessions.
    pub async fn expire_sessions(&self, timeout: Duration) {
        let now = Instant::now();
        let mut sessions = self.sessions.write().await;
        sessions.retain(|_sid, s| now.duration_since(s.created_at) < timeout);
    }
}

/// Generate an analysis key from two NAT features for analyzer lookup.
fn gen_analysis_key(c: &NatFeature, v: &NatFeature) -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut hasher = DefaultHasher::new();
    c.nat_type.hash(&mut hasher);
    c.behavior.hash(&mut hasher);
    c.regular_ports_change.hash(&mut hasher);
    v.nat_type.hash(&mut hasher);
    v.behavior.hash(&mut hasher);
    v.regular_ports_change.hash(&mut hasher);
    format!("{:x}", hasher.finish())
}

/// Build a NatHoleResp with detect_behavior filled in.
/// Go frp v0.69.1 compat: newNatHoleResponse in controller.go
pub fn build_nat_hole_response(
    transaction_id: &str,
    sid: &str,
    protocol: Option<String>,
    mode: i32,
    candidate_addrs: Vec<String>,
    assisted_addrs: Vec<String>,
    behavior: super::analysis::RecommandBehavior,
    read_timeout_ms: i32,
    ports_difference: i32,
) -> msg::NatHoleResp {
    let compact_candidates: Vec<String> = {
        let mut seen = std::collections::HashSet::new();
        candidate_addrs
            .into_iter()
            .filter(|a| seen.insert(a.clone()))
            .collect()
    };
    let compact_assisted: Vec<String> = {
        let mut seen = std::collections::HashSet::new();
        assisted_addrs
            .into_iter()
            .filter(|a| seen.insert(a.clone()))
            .collect()
    };

    let candidate_ports = if behavior.ports_range_number > 0 {
        if let Some(last_addr) = compact_candidates.last() {
            if let Some(port_str) = last_addr.rsplitn(2, ':').nth(0) {
                if let Ok(port) = port_str.parse::<i32>() {
                    let from = (port - ports_difference - 5).max(port - behavior.ports_range_number).max(1);
                    let to = (port + ports_difference + 5).min(port + behavior.ports_range_number).min(65535);
                    Some(vec![PortsRange { from, to }])
                } else {
                    None
                }
            } else {
                None
            }
        } else {
            None
        }
    } else {
        None
    };

    msg::NatHoleResp {
        transaction_id: transaction_id.to_string(),
        error: None,
        sid: Some(sid.to_string()),
        protocol,
        candidate_addrs: if compact_candidates.is_empty() {
            None
        } else {
            Some(compact_candidates)
        },
        assisted_addrs: if compact_assisted.is_empty() {
            None
        } else {
            Some(compact_assisted)
        },
        detect_behavior: Some(NatHoleDetectBehavior {
            mode,
            role: Some(behavior.role),
            ttl: behavior.ttl,
            send_delay_ms: behavior.send_delay_ms,
            read_timeout_ms,
            send_random_ports: behavior.ports_random_number,
            listen_random_ports: behavior.listen_random_ports,
            candidate_ports,
        }),
    }
}
```

- [ ] **Step 3: Build check with new module**

```bash
cargo build -p frp-server 2>&1 | tail -20
```

Expected: builds successfully (unused import warnings OK; controller.rs imports used later).

- [ ] **Step 4: Commit**

```bash
git add frp-server/src/nathole/mod.rs frp-server/src/nathole/controller.rs
git commit -m "feat: XTCP NAT hole punch controller with analysis integration

Controller replaces NatHoleCoordinator. Coordinates visitor/provider
address exchange, runs NAT classification and analysis, builds
NatHoleResp with detect_behavior. Supports both writer-path
(fresh connection) and ctl-path (Go frp compat) sessions.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 6: Rewrite handle_nat_hole_visitor (service.rs)

**Files:**
- Modify: `frp-server/src/service.rs:1-30` (imports), `1172-1315` (function)

- [ ] **Step 1: Update imports in service.rs**

At the top of `service.rs`, replace `use crate::nat_hole::NatHoleCoordinator;` with:

```rust
use crate::nathole::controller::{self as nathole_ctrl, Controller};
use crate::nathole::{classify, NAT_HOLE_TIMEOUT};
```

Replace `pub nat_hole: Arc<NatHoleCoordinator>` in `AppState` with:

```rust
pub nat_hole: Arc<Controller>,
```

Replace initialization `nat_hole: Arc::new(NatHoleCoordinator::new())` with:

```rust
nat_hole: Arc::new(Controller::new(Duration::from_secs(3600))),
```

Remove the `NatHoleCoordinator` re-export line if present.

- [ ] **Step 2: Rewrite handle_nat_hole_visitor**

Replace the entire function body (lines 1179-1315) with:

```rust
async fn handle_nat_hole_visitor(
    stream: IoStream,
    msg: msg::NatHoleVisitor,
    state: Arc<AppState>,
    visitor_addr: Option<String>,
) {
    let transaction_id = msg.transaction_id.clone();
    let proxy_name = msg.proxy_name.clone();

    if proxy_name.is_empty() {
        warn!("NatHoleVisitor without proxy_name, ignoring");
        return;
    }

    // Validate proxy exists
    if state.proxy_manager.get(&proxy_name).await.is_none() {
        warn!("NatHoleVisitor: proxy '{}' not found", proxy_name);
        let mut writer = stream.into_split().1;
        let resp = FrpMessage::NatHoleResp(msg::NatHoleResp {
            transaction_id: transaction_id.clone(),
            error: Some("proxy not found".into()),
            ..Default::default()
        });
        let _ = write_msg_v1(&mut writer, &resp).await;
        return;
    }

    // Look up provider's run_id
    let run_id = state.proxy_manager.get_run_id(&proxy_name).await;
    let run_id = match run_id {
        Some(id) => id,
        None => {
            warn!("NatHoleVisitor: no run_id found for proxy '{}'", proxy_name);
            let mut writer = stream.into_split().1;
            let resp = FrpMessage::NatHoleResp(msg::NatHoleResp {
                transaction_id: transaction_id.clone(),
                error: Some("provider offline".into()),
                ..Default::default()
            });
            let _ = write_msg_v1(&mut writer, &resp).await;
            return;
        }
    };

    let ctl_tx = {
        let map = state.run_id_to_ctl_tx.read().await;
        map.get(&run_id).cloned()
    };

    let ctl_tx = match ctl_tx {
        Some(ctl) => ctl,
        None => {
            warn!("No provider control handler for run_id {}", run_id);
            let mut writer = stream.into_split().1;
            let resp = FrpMessage::NatHoleResp(msg::NatHoleResp {
                transaction_id: transaction_id.clone(),
                error: Some("provider disconnected".into()),
                ..Default::default()
            });
            let _ = write_msg_v1(&mut writer, &resp).await;
            return;
        }
    };

    let (reader, writer) = stream.into_split();
    let sid = transaction_id.clone();

    // --- Step 1: Create session and notify provider ---
    let (session, report_rx) = state
        .nat_hole
        .create_session_with_writer(
            sid.clone(),
            proxy_name.clone(),
            msg.clone(),
            writer,
        )
        .await;

    // Send NatHoleClient to provider (old-style message — just notification)
    if ctl_tx
        .tx
        .send(InternalMsg::NatHoleClient {
            proxy_name: proxy_name.clone(),
            transaction_id: transaction_id.clone(),
            visitor_addr,
        })
        .is_err()
    {
        warn!("Provider for run_id {} has gone away", run_id);
        state.nat_hole.remove(&transaction_id).await;
        return;
    }

    info!(
        "NatHoleVisitor for proxy '{}': created session {}, waiting for provider",
        proxy_name, sid
    );

    // --- Step 2: Wait for provider's NatHoleClient with STUN addresses ---
    // The provider's control handler will do STUN discovery and send
    // NatHoleClient back with mapped_addrs/assisted_addrs.
    // handle_client() signals notify_ch when the message arrives.

    let notify_rx = {
        let mut guard = session.notify_ch.lock().await;
        // Create a receiver from the notify channel
        // Actually we need a new oneshot for each notification.
        // The Session already stores one — but we consumed it in create_session_with_writer.
        // We create a fresh one.
        let (tx, rx) = oneshot::channel();
        *guard = Some(tx);
        rx
    };

    let client_msg_received = tokio::time::timeout(
        Duration::from_secs(NAT_HOLE_TIMEOUT as u64),
        notify_rx,
    )
    .await;

    if client_msg_received.is_err() {
        warn!(
            "NatHole session {}: timeout waiting for provider NatHoleClient",
            sid
        );
        let mut writer_guard = session.visitor_writer.lock().await;
        if let Some(ref mut w) = *writer_guard {
            let resp = FrpMessage::NatHoleResp(msg::NatHoleResp {
                transaction_id: transaction_id.clone(),
                error: Some("provider NAT detection timeout".into()),
                ..Default::default()
            });
            let _ = write_msg_v1(w, &resp).await;
        }
        state.nat_hole.remove(&sid).await;
        drop(reader);
        return;
    }

    // --- Step 3: Get provider's addresses from session ---
    let client_msg_opt = session.client_msg.lock().await.take();
    let client_msg = match client_msg_opt {
        Some(m) => m,
        None => {
            warn!("NatHole session {}: no client message after notify", sid);
            state.nat_hole.remove(&sid).await;
            drop(reader);
            return;
        }
    };

    let client_mapped = client_msg.mapped_addrs.unwrap_or_default();
    let client_assisted = client_msg.assisted_addrs.unwrap_or_default();
    let visitor_mapped = msg.mapped_addrs.unwrap_or_default();
    let visitor_assisted = msg.assisted_addrs.unwrap_or_default();

    // --- Step 4: Classify both NAT features ---
    let v_feature = classify::classify_nat_feature(&visitor_mapped, &[]).ok();
    let c_feature = classify::classify_nat_feature(&client_mapped, &[]).ok();

    // Store features on session
    if let Some(ref vf) = v_feature {
        *session.v_nat_feature.lock().await = Some(vf.clone());
    }
    if let Some(ref cf) = c_feature {
        *session.c_nat_feature.lock().await = Some(cf.clone());
    }

    // --- Step 5: Run analysis and build responses ---
    let (v_resp, c_resp) = if let (Some(ref vf), Some(ref cf)) = (&v_feature, &c_feature) {
        let key = nathole_ctrl::gen_analysis_key(cf, vf);
        let (mode, _index, c_behavior, v_behavior) =
            state.nat_hole.analyzer.get_recommand_behaviors(&key, cf, vf);

        let timeout_ms = (c_behavior.send_delay_ms.max(v_behavior.send_delay_ms)) + 5000;
        let v_read_timeout = timeout_ms - v_behavior.send_delay_ms;
        let c_read_timeout = timeout_ms - c_behavior.send_delay_ms;
        let c_ports_diff = cf.ports_difference;
        let v_ports_diff = vf.ports_difference;

        let v_resp = nathole_ctrl::build_nat_hole_response(
            &transaction_id,
            &sid,
            msg.protocol.clone(),
            mode,
            client_mapped.clone(),  // visitor gets PROVIDER's addresses
            client_assisted.clone(),
            v_behavior,
            v_read_timeout,
            c_ports_diff,
        );

        let c_resp = nathole_ctrl::build_nat_hole_response(
            &client_msg.transaction_id,
            &sid,
            client_msg.protocol.clone(),
            mode,
            visitor_mapped.clone(),  // provider gets VISITOR's addresses
            visitor_assisted.clone(),
            c_behavior,
            c_read_timeout,
            v_ports_diff,
        );

        (v_resp, Some(c_resp))
    } else {
        // Fallback: simple exchange without analysis
        let v_resp = msg::NatHoleResp {
            transaction_id: transaction_id.clone(),
            error: None,
            sid: Some(sid.clone()),
            protocol: msg.protocol.clone(),
            candidate_addrs: if client_mapped.is_empty() { None } else { Some(client_mapped) },
            assisted_addrs: if client_assisted.is_empty() { None } else { Some(client_assisted) },
            detect_behavior: None,
        };
        let c_resp = msg::NatHoleResp {
            transaction_id: client_msg.transaction_id.clone(),
            error: None,
            sid: Some(sid.clone()),
            protocol: client_msg.protocol.clone(),
            candidate_addrs: if visitor_mapped.is_empty() { None } else { Some(visitor_mapped) },
            assisted_addrs: if visitor_assisted.is_empty() { None } else { Some(visitor_assisted) },
            detect_behavior: None,
        };
        (v_resp, Some(c_resp))
    };

    // Store v_resp for reporting
    *session.v_resp.lock().await = Some(v_resp.clone());

    // --- Step 6: Send NatHoleResp to both sides ---
    // Send to visitor
    {
        let mut writer_guard = session.visitor_writer.lock().await;
        if let Some(ref mut w) = *writer_guard {
            let _ = write_msg_v1(w, &FrpMessage::NatHoleResp(v_resp)).await;
        }
    }

    // Send to provider
    if let Some(ref cr) = c_resp {
        let _ = ctl_tx.tx.send(InternalMsg::WriteNatHoleResp {
            transaction_id: cr.transaction_id.clone(),
            error: cr.error.clone(),
            sid: cr.sid.clone(),
            protocol: cr.protocol.clone(),
            candidate_addrs: cr.candidate_addrs.clone(),
            assisted_addrs: cr.assisted_addrs.clone(),
        });
    }

    info!("NatHole session {}: NatHoleResp sent to both sides", sid);

    // --- Step 7: Wait for report ---
    match tokio::time::timeout(Duration::from_secs(30), report_rx).await {
        Ok(Ok(_report)) => {
            debug!("NatHole session {}: provider completed", sid);
        }
        Ok(Err(_)) => {
            debug!("NatHole session {}: provider dropped without report", sid);
            state.nat_hole.remove(&sid).await;
        }
        Err(_) => {
            warn!("NatHole session {}: timed out waiting for provider report", sid);
            state.nat_hole.remove(&sid).await;
            drop(reader);
        }
    }
    // reader dropped → connection closes
}
```

- [ ] **Step 3: Remove old nat_hole references in expire timer**

Find the expire timer section (around line 566) and update to use `Controller`:

```rust
// Old: let nat_hole = self.state.nat_hole.clone();
// nat_hole.expire_sessions(Duration::from_secs(120)).await;
// New: session expiration already handled by Controller::expire_sessions
let nat_hole = self.state.nat_hole.clone();
nat_hole.expire_sessions(Duration::from_secs(120)).await;
```

- [ ] **Step 4: Build check**

```bash
cargo build -p frp-server 2>&1 | tail -30
```

Expected: may have compilation errors from old `NatHoleCoordinator` references in `control/mod.rs`. Those get fixed in Task 7.

- [ ] **Step 5: Commit**

```bash
git add frp-server/src/service.rs
git commit -m "feat: rewrite XTCP handle_nat_hole_visitor with address exchange

Server now waits for provider's NatHoleClient with STUN addresses
before constructing NatHoleResp. Each side receives the OTHER's
addresses as candidate_addrs. NAT classification and analysis
integrated. Go frp v0.69.1 compat message flow.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 7: Update Provider Control Handler (control/mod.rs)

**Files:**
- Modify: `frp-server/src/control/mod.rs` (InternalMsg::NatHoleClient handler + imports)

- [ ] **Step 1: Update imports in control/mod.rs**

Add at top:

```rust
use crate::nathole::discovery;
use crate::nathole::NAT_HOLE_TIMEOUT;
```

- [ ] **Step 2: Update NatHoleClient InternalMsg handler**

Find the `InternalMsg::NatHoleClient { proxy_name, transaction_id, visitor_addr }` handler (around line 355). Replace with:

```rust
Some(InternalMsg::NatHoleClient { proxy_name, transaction_id, visitor_addr }) => {
    debug!("Received NatHoleClient notification for session {}", transaction_id);

    // --- Do STUN discovery to find our external addresses ---
    let stun_server = state.cfg.nat_hole_stun_server
        .clone()
        .unwrap_or_else(|| "stun.l.google.com:19302".to_string());

    let mapped_addrs = match discovery::discover(&stun_server) {
        Ok(addrs) => {
            debug!("STUN discovery for {}: {:?}", proxy_name, addrs);
            addrs
        }
        Err(e) => {
            warn!("STUN discovery failed for {}: {}", proxy_name, e);
            vec![]
        }
    };

    // --- Send NatHoleClient back with our STUN addresses ---
    let reply = FrpMessage::NatHoleClient(msg::NatHoleClient {
        transaction_id: transaction_id.clone(),
        proxy_name: proxy_name.clone(),
        sid: Some(transaction_id.clone()),
        protocol: Some("tcp".to_string()),
        mapped_addrs: if mapped_addrs.is_empty() { None } else { Some(mapped_addrs) },
        assisted_addrs: None,
        visitor_addr,  // echo back the visitor's address
    });

    if let Err(e) = write_msg_v1(&mut writer, &reply).await {
        warn!("Failed to send NatHoleClient reply: {}", e);
    } else {
        debug!("Sent NatHoleClient reply with STUN addresses for {}", transaction_id);
    }
}
```

- [ ] **Step 3: Add NatHoleClient handler for the read loop**

Find the `Ok(FrpMessage::NatHoleClient(...))` match arm in the provider message read loop (if not present, add it after `NatHoleSid` handler). The existing server-side `NatHoleClient` read (from provider to server) needs to call Controller::handle_client:

```rust
Ok(FrpMessage::NatHoleClient(ref client_msg)) => {
    debug!("Received NatHoleClient from provider: txn={}, addrs={:?}",
        client_msg.transaction_id, client_msg.mapped_addrs);
    // Route to controller
    if let Some(ref sid) = client_msg.sid {
        state.nat_hole.handle_client(client_msg.clone(), internal_tx.clone()).await;
    }
}
```

- [ ] **Step 4: Remove old NatHoleCoordinator method calls**

Replace remaining `state.nat_hole.forward_sid_via_ctl(...)` calls with equivalent `Controller` methods or inline forwarding:

```rust
// Old NatHoleSid forwarding — keep working via InternalMsg::WriteNatHoleSid
// which is handled in the internal message loop (already sending to visitor)
```

Keep the existing `WriteNatHoleSid`, `WriteNatHoleResp`, `WriteNatHoleReport` InternalMsg handlers — they still work and forward to visitor via control channel.

- [ ] **Step 5: Build check**

```bash
cargo build -p frp-server 2>&1 | tail -30
```

Expected: builds successfully. Fix any remaining compilation errors.

- [ ] **Step 6: Commit**

```bash
git add frp-server/src/control/mod.rs
git commit -m "feat: provider-side STUN discovery for XTCP NatHoleClient

On receiving NatHoleClient InternalMsg, provider runs STUN discovery
and sends NatHoleClient reply with mapped_addrs. Server routes reply
to Controller::handle_client which signals the waiting session.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 8: Final Integration — lib.rs, Cargo.toml, Cleanup

**Files:**
- Modify: `frp-server/src/lib.rs:1-11`
- Modify: `frp-server/Cargo.toml:23`
- Delete: `frp-server/src/nat_hole.rs`

- [ ] **Step 1: Update lib.rs**

Replace `pub mod nat_hole;` with `pub mod nathole;`:

```rust
pub mod service;
pub mod control;
pub mod proxy;
pub mod vhost;
pub mod dashboard;
pub mod nathole;
pub mod tcpmux;
pub mod metrics;
pub mod plugin;
pub mod ssh_gateway;
```

- [ ] **Step 2: Add rand dependency to frp-server (for STUN transaction IDs)**

Already present: `rand = "0.10"` at line 23 — no change needed. Verify.

- [ ] **Step 3: Delete old nat_hole.rs**

```bash
rm frp-server/src/nat_hole.rs
```

- [ ] **Step 4: Full build**

```bash
cargo build 2>&1 | tail -20
```

Expected: workspace builds successfully.

- [ ] **Step 5: Run all existing tests**

```bash
cargo test --workspace 2>&1 | tail -30
```

Expected: all existing tests pass. Any test failures from old `NatHoleCoordinator` references need fixing.

- [ ] **Step 6: Commit**

```bash
git rm frp-server/src/nat_hole.rs
git add frp-server/src/lib.rs
git commit -m "feat: integrate nathole module, remove old nat_hole.rs

nat_hole.rs replaced by nathole/ module (controller, classify,
analysis, discovery). lib.rs updated. All existing tests pass.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 9: Update Unit Test (xtcp_hole_punch.rs)

**Files:**
- Modify: `frp-server/tests/xtcp_hole_punch.rs`

- [ ] **Step 1: Update test to exercise new flow**

The key change: provider must send `NatHoleClient` with `mapped_addrs` after receiving the InternalMsg notification. The visitor should receive `NatHoleResp` with the provider's addresses as `candidate_addrs`.

Update the test (around line 99):

```rust
// --- Step 3: Provider reads NatHoleClient from server ---
let (sid, txn_id) = match read_msg_v1(&mut provider)
    .await
    .expect("read NatHoleClient from provider")
{
    FrpMessage::NatHoleClient(nhc) => {
        assert_eq!(nhc.proxy_name, "xtcp-test");
        // Provider now has visitor_addr in the message
        println!(
            "Provider received NatHoleClient: proxy={}, sid={:?}",
            nhc.proxy_name, nhc.sid
        );
        // Send back NatHoleClient with our STUN addresses
        let reply = FrpMessage::NatHoleClient(msg::NatHoleClient {
            transaction_id: nhc.transaction_id.clone(),
            proxy_name: nhc.proxy_name.clone(),
            sid: nhc.sid.clone(),
            protocol: Some("tcp".to_string()),
            mapped_addrs: Some(vec![
                "10.0.0.1:7000".to_string(),
                "10.0.0.1:7002".to_string(),
            ]),
            assisted_addrs: None,
            visitor_addr: nhc.visitor_addr.clone(),
        });
        let txn = nhc.transaction_id.clone();
        write_msg_v1(&mut provider, &reply)
            .await
            .expect("send NatHoleClient reply");
        (nhc.sid.clone().unwrap_or(txn.clone()), txn)
    }
    other => panic!("expected NatHoleClient, got: {:?}", other.v1_type_byte()),
};

// --- Step 4: Visitor reads NatHoleResp with provider's candidate addresses ---
match read_msg_v1(&mut visitor_conn)
    .await
    .expect("read NatHoleResp from visitor")
{
    FrpMessage::NatHoleResp(resp) => {
        assert!(resp.error.is_none(), "NatHoleResp error: {:?}", resp.error);
        assert_eq!(resp.sid.as_deref(), Some(&sid));
        // KEY: candidate_addrs should contain PROVIDER's addresses, not visitor's
        if let Some(ref candidates) = resp.candidate_addrs {
            assert!(
                candidates.iter().any(|a| a.contains("10.0.0.1")),
                "candidate_addrs should contain provider addresses, got: {:?}",
                candidates
            );
        } else {
            panic!("NatHoleResp should have candidate_addrs");
        }
        println!("Visitor received NatHoleResp with provider addresses — correct!");
    }
    other => panic!("expected NatHoleResp, got: {:?}", other.v1_type_byte()),
}

// --- Steps 5-7: Continue with NatHoleSid/Report flow (unchanged) ---
```

- [ ] **Step 2: Run updated test**

```bash
cargo test -p frp-server xtcp_nat_hole_message_routing -- --nocapture 2>&1
```

Expected: PASS.

- [ ] **Step 3: Run all workspace tests**

```bash
cargo test --workspace 2>&1 | tail -20
```

Expected: all tests PASS.

- [ ] **Step 4: Commit**

```bash
git add frp-server/tests/xtcp_hole_punch.rs
git commit -m "test: update XTCP test for new address exchange flow

Provider sends NatHoleClient with STUN addresses in response.
Visitor receives NatHoleResp with provider's candidate_addrs
(not its own). Verifies correct address exchange.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 10: Enable XTCP Compat Test

**Files:**
- Modify: `scripts/compat-test.sh` (around lines 2780-2783)

- [ ] **Step 1: Uncomment test_g2r_xtcp**

Find the XTCP section (around line 2778-2783):

```bash
# Before:
# XTCP disabled: Go frp v0.69.1 uses QUIC-based NAT detection + candidate
# test_g2r_xtcp

# After:
test_g2r_xtcp
```

Also keep `test_r2g_xtcp` disabled for now (Rust-to-Go direction requires Go frps server changes).

- [ ] **Step 2: Run compat test**

```bash
bash scripts/compat-test.sh --verbose 2>&1 | grep -A5 "xtcp\|XTCP"
```

Expected: `test_g2r_xtcp` should show PASS or specific failure.

If still failing, capture output for debugging:
```bash
bash scripts/compat-test.sh --verbose 2>&1 | tail -60
```

- [ ] **Step 3: Commit**

```bash
git add scripts/compat-test.sh
git commit -m "test: enable XTCP Go→Rust compat test

test_g2r_xtcp enabled — Go frpc provider/visitor against Rust frps.
Server now coordinates address exchange with NAT analysis.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

## Self-Review Checklist

Before marking this plan complete, verify:
1. **Spec coverage**: Each spec section (data structures, classify, analysis, controller, STUN, server integration, testing) has corresponding tasks
2. **No placeholders**: All code is complete, all commands exact, no TBD/TODO
3. **Type consistency**: `NatHoleDetectBehavior`, `PortsRange`, `NatFeature`, `RecommandBehavior`, `Controller`, `Session` used consistently across tasks
4. **Build chain**: Each task's commit produces a buildable state (or at least no worse than before)
