//! Unsafe features tracking — set-based allowlist for potentially dangerous features.
//!
//! Port of Go frp v0.69.1 `pkg/policy/security/unsafe.go`.
//! Both client and server have their own allowlists of features that require
//! explicit opt-in (e.g. exec-based token sources).

use std::collections::HashSet;

/// Constant for the exec-based token source feature.
pub const TOKEN_SOURCE_EXEC: &str = "TokenSourceExec";

/// Constant for the file-based token source feature.
pub const TOKEN_SOURCE_FILE: &str = "TokenSourceFile";

/// Client-side unsafe features that require explicit opt-in.
pub const CLIENT_UNSAFE_FEATURES: &[&str] = &[TOKEN_SOURCE_EXEC];

/// Server-side unsafe features that require explicit opt-in.
pub const SERVER_UNSAFE_FEATURES: &[&str] = &[TOKEN_SOURCE_EXEC];

/// Set of allowed unsafe features.
///
/// A feature not in this set is considered blocked.
#[derive(Debug, Clone, Default)]
pub struct UnsafeFeatures {
    features: HashSet<String>,
}

impl UnsafeFeatures {
    /// Create a new `UnsafeFeatures` with the given allowlist.
    ///
    /// Each element in `allowed` is a feature name that is permitted.
    pub fn new(allowed: &[&str]) -> Self {
        let features = allowed.iter().map(|&s| s.to_string()).collect();
        Self { features }
    }

    /// Check whether a feature is enabled (allowed).
    pub fn is_enabled(&self, feature: &str) -> bool {
        self.features.contains(feature)
    }

    /// Return the number of allowed features.
    pub fn len(&self) -> usize {
        self.features.len()
    }

    /// Return whether the allowlist is empty.
    pub fn is_empty(&self) -> bool {
        self.features.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_disallows_all() {
        let uf = UnsafeFeatures::default();
        assert!(!uf.is_enabled(TOKEN_SOURCE_EXEC));
        assert!(!uf.is_enabled("Other"));
    }

    #[test]
    fn test_client_allowlist() {
        let uf = UnsafeFeatures::new(CLIENT_UNSAFE_FEATURES);
        assert!(uf.is_enabled(TOKEN_SOURCE_EXEC));
        assert!(!uf.is_enabled("OtherFeature"));
    }

    #[test]
    fn test_server_allowlist() {
        let uf = UnsafeFeatures::new(SERVER_UNSAFE_FEATURES);
        assert!(uf.is_enabled(TOKEN_SOURCE_EXEC));
    }

    #[test]
    fn test_len() {
        let uf = UnsafeFeatures::new(&["a", "b"]);
        assert_eq!(uf.len(), 2);
        assert!(!uf.is_empty());

        let uf = UnsafeFeatures::default();
        assert!(uf.is_empty());
    }
}
