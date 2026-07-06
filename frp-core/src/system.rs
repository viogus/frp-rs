//! OS-specific system compatibility utilities.
//!
//! Port of Go frp v0.69.1 `pkg/util/system/system.go`.

/// Enable compatibility mode for non-standard platforms.
///
/// On Android, the inability to obtain the correct time zone results in
/// incorrect log time output. This provides a hook for such platforms.
/// Currently a no-op on all supported platforms.
pub fn enable_compatibility_mode() {
    // no-op on all currently supported platforms
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_enable_compatibility_mode_does_not_panic() {
        enable_compatibility_mode();
    }
}
