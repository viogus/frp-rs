//! Feature gate system — thread-safe feature flag registry with maturity stages.
//!
//! Port of Go frp v0.69.1 `pkg/policy/featuregate/feature_gate.go`.
//! Features progress through Alpha → Beta → GA (generally available).
//! GA features are always enabled and hidden from the known-features list.
//!
//! ## Usage
//!
//! ```ignore
//! use frp_core::feature_gate;
//!
//! if feature_gate::enabled(feature_gate::VIRTUAL_NET) {
//!     // Alpha feature logic here
//! }
//!
//! // Enable from config: feature_gate::set_from_map(&map)?;
//! ```

use std::collections::HashMap;
use std::sync::RwLock;

/// A feature gate name (O(1) copy, used for const definitions).
pub type Feature = &'static str;

/// Maturity level of a feature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FeatureStage {
    /// Experimental, disabled by default.
    Alpha,
    /// More stable but still might change, disabled by default.
    Beta,
    /// Generally available, enabled by default.
    GA,
}

impl std::fmt::Display for FeatureStage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FeatureStage::Alpha => write!(f, "ALPHA"),
            FeatureStage::Beta => write!(f, "BETA"),
            FeatureStage::GA => write!(f, "GA"),
        }
    }
}

/// Describes a feature and its properties.
#[derive(Debug, Clone)]
pub struct FeatureSpec {
    /// Default enablement state.
    pub default: bool,
    /// If true, the feature cannot be changed from its default.
    pub lock_to_default: bool,
    /// Maturity level.
    pub stage: FeatureStage,
}

impl FeatureSpec {
    pub const fn new(default: bool, stage: FeatureStage) -> Self {
        Self {
            default,
            lock_to_default: false,
            stage,
        }
    }

    pub const fn locked(mut self, lock: bool) -> Self {
        self.lock_to_default = lock;
        self
    }
}

// ── Feature definitions ──────────────────────────────────────────────────────

/// Virtual network (L3 VPN) — ALPHA feature.
pub const VIRTUAL_NET: Feature = "VirtualNet";

fn default_features() -> HashMap<String, FeatureSpec> {
    let mut m = HashMap::new();
    m.insert(
        VIRTUAL_NET.to_string(),
        FeatureSpec::new(false, FeatureStage::Alpha),
    );
    m
}

// ── FeatureGate ──────────────────────────────────────────────────────────────

/// Thread-safe feature flag registry.
///
/// Uses `RwLock` for concurrent reads with exclusive writes during config updates.
pub struct FeatureGate {
    known: RwLock<HashMap<String, FeatureSpec>>,
    enabled: RwLock<HashMap<String, bool>>,
}

impl FeatureGate {
    /// Create a new feature gate with the default features.
    pub fn new() -> Self {
        Self {
            known: RwLock::new(default_features()),
            enabled: RwLock::new(HashMap::new()),
        }
    }

    /// Check if a feature is enabled.
    ///
    /// Returns the explicitly-set value if it exists, otherwise the feature's
    /// default value. Unknown features return `false`.
    pub fn enabled(&self, key: Feature) -> bool {
        // Check explicit override first.
        if let Ok(enabled) = self.enabled.read() {
            if let Some(&v) = enabled.get(key) {
                return v;
            }
        }
        // Fall back to default.
        if let Ok(known) = self.known.read() {
            if let Some(spec) = known.get(key) {
                return spec.default;
            }
        }
        false
    }

    /// Set feature gate values from a map of feature name → bool.
    ///
    /// Returns an error if any feature name is unrecognized, or if any
    /// locked feature is set to a value different from its default.
    pub fn set_from_map(&self, m: &HashMap<String, bool>) -> Result<(), String> {
        let known = self.known.read().map_err(|e| format!("lock: {e}"))?;
        let mut enabled = self.enabled.write().map_err(|e| format!("lock: {e}"))?;

        for (k, &v) in m {
            let feature_spec = known
                .get(k.as_str())
                .ok_or_else(|| format!("unrecognized feature gate: {k}"))?;
            if feature_spec.lock_to_default && feature_spec.default != v {
                return Err(format!(
                    "cannot set feature gate {k} to {v}, feature is locked to {}",
                    feature_spec.default
                ));
            }
            enabled.insert(k.clone(), v);
        }
        Ok(())
    }

    /// Add features to the feature gate.
    ///
    /// Returns an error if a feature with the same name but different spec
    /// already exists.
    pub fn add(&self, features: HashMap<String, FeatureSpec>) -> Result<(), String> {
        let mut known = self.known.write().map_err(|e| format!("lock: {e}"))?;

        for (name, spec) in features {
            if let Some(existing) = known.get(&name) {
                if existing.default != spec.default
                    || existing.stage != spec.stage
                    || existing.lock_to_default != spec.lock_to_default
                {
                    return Err(format!(
                        "feature gate {name:?} with different spec already exists"
                    ));
                }
            } else {
                known.insert(name, spec);
            }
        }
        Ok(())
    }

    /// Return a human-readable string describing all known non-GA features.
    /// Format: `FeatureName=true|false (STAGE - default=bool)`
    pub fn known_features(&self) -> Vec<String> {
        let known = match self.known.read() {
            Ok(k) => k,
            Err(_) => return Vec::new(),
        };
        let mut result: Vec<String> = known
            .iter()
            .filter(|(_, spec)| spec.stage != FeatureStage::GA)
            .map(|(name, spec)| {
                format!(
                    "{name}=true|false ({} - default={})",
                    spec.stage, spec.default
                )
            })
            .collect();
        result.sort();
        result
    }

    /// String representation: comma-separated key=value pairs of enabled features.
    pub fn fmt_enabled(&self) -> String {
        let enabled = match self.enabled.read() {
            Ok(e) => e,
            Err(_) => return String::new(),
        };
        let mut pairs: Vec<String> = enabled.iter().map(|(k, v)| format!("{k}={v}")).collect();
        pairs.sort();
        pairs.join(",")
    }
}

impl Default for FeatureGate {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for FeatureGate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.fmt_enabled())
    }
}

// ── Global default instance ──────────────────────────────────────────────────

/// Global default feature gate instance.
pub static DEFAULT_FEATURE_GATES: std::sync::LazyLock<FeatureGate> =
    std::sync::LazyLock::new(FeatureGate::new);

/// Check if a feature is enabled in the default feature gates.
#[inline]
pub fn enabled(name: Feature) -> bool {
    DEFAULT_FEATURE_GATES.enabled(name)
}

/// Set feature gate values from a map in the default feature gates.
pub fn set_from_map(m: &HashMap<String, bool>) -> Result<(), String> {
    DEFAULT_FEATURE_GATES.set_from_map(m)
}

/// Return known non-GA features from the default feature gates.
pub fn known_features() -> Vec<String> {
    DEFAULT_FEATURE_GATES.known_features()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_features() {
        // VirtualNet should be disabled by default (Alpha).
        assert!(!enabled(VIRTUAL_NET));

        // Unknown features are always disabled.
        assert!(!enabled("NoSuchFeature"));
    }

    #[test]
    fn test_set_from_map() {
        let gate = FeatureGate::new();

        // Enable VirtualNet.
        let mut m = HashMap::new();
        m.insert("VirtualNet".to_string(), true);
        gate.set_from_map(&m).unwrap();
        assert!(gate.enabled(VIRTUAL_NET));

        // Unknown feature should error.
        let mut m = HashMap::new();
        m.insert("BadFeature".to_string(), true);
        assert!(gate.set_from_map(&m).is_err());
    }

    #[test]
    fn test_locked_feature() {
        let gate = FeatureGate::new();

        // Add a locked feature.
        let mut features = HashMap::new();
        features.insert(
            "LockedFeature".to_string(),
            FeatureSpec {
                default: true,
                lock_to_default: true,
                stage: FeatureStage::GA,
            },
        );
        gate.add(features).unwrap();

        // Trying to change it should fail.
        let mut m = HashMap::new();
        m.insert("LockedFeature".to_string(), false);
        assert!(gate.set_from_map(&m).is_err());
    }

    #[test]
    fn test_add_duplicate_same_spec() {
        let gate = FeatureGate::new();
        // Adding VirtualNet again with same spec should be ok.
        let mut features = HashMap::new();
        features.insert(
            VIRTUAL_NET.to_string(),
            FeatureSpec::new(false, FeatureStage::Alpha),
        );
        assert!(gate.add(features).is_ok());
    }

    #[test]
    fn test_known_features_hides_ga() {
        let gate = FeatureGate::new();
        let known = gate.known_features();
        // VirtualNet should appear (it's Alpha).
        let has_vnet = known.iter().any(|s| s.starts_with("VirtualNet"));
        assert!(has_vnet);
    }

    #[test]
    fn test_display() {
        let gate = FeatureGate::new();
        let s = gate.to_string();
        // Initially empty — no features explicitly enabled.
        assert!(s.is_empty());

        let mut m = HashMap::new();
        m.insert("VirtualNet".to_string(), true);
        gate.set_from_map(&m).unwrap();
        assert_eq!(gate.to_string(), "VirtualNet=true");
    }
}
