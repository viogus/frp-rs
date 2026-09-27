//! The typed error at the daemon service-construction boundary.
//!
//! `frpc` and `frps` construct their `Service` before they run it, and a
//! construction failure terminates the process with one of the two frp-rs
//! *extension* exit codes (see [`crate::EXIT_AUTH`] / [`crate::EXIT_BIND`]).
//! Which one is decided here, by [`InitErrorKind`], and **not** by the error
//! text.
//!
//! # Why the kind is a value and not a substring search
//!
//! The predecessor of this type was
//! `logging::is_token_error(&e.to_string())` — `msg.contains("token") ||
//! msg.contains("auth")` — evaluated in the daemons. The construction error's
//! text embeds the config path and any URL from the config, so an unrelated
//! substring chose the exit code: with **identical** malformed-`[store]`
//! configs, `…/authstore.json` exited 3 and `…/plainstore.json` exited 4. Both
//! are the same failure class (a client store that cannot be loaded), so the two
//! runs disagreed with each other.
//!
//! A message that is deliberately redacted, user-facing prose is not a machine
//! channel — the same rule this crate's `auth::TokenResolveError` documents for
//! errno, where control-flow information is carried structurally because it must
//! never be recovered by scanning text. This module applies that rule to the
//! exit code: the kind is attached where the failure is *raised*.
//!
//! # Scope of the guarantee
//!
//! The type system can force every construction error to *carry* a kind; it
//! cannot stop a future author from tagging an auth failure as
//! [`InitErrorKind::Other`]. What it does guarantee is that the displayed text
//! has no path to the code:
//!
//! * no daemon matches on `to_string()` to pick an exit code (the arms match on
//!   [`ConstructError::kind`]);
//! * `frp-core` contains no substring classifier for the daemons to call
//!   (`logging::is_token_error` was deleted with this change);
//! * `frpc/tests/cli_exit_codes.rs` runs one failure class under an
//!   `auth`-bearing and an auth-free name and asserts one code for both, and its
//!   inputs contain no `token` substring, so re-introducing a text match fails
//!   it.
//!
//! Coverage of the tests: the client store file and the client/server
//! `auth.tokenSource`, plus the server's empty-token and OIDC-construction
//! paths. The client's plugin-start failures are *not* covered — they are logged
//! and skipped inside the constructor and never reach this type.

use std::fmt;

/// Which kind of service-construction failure occurred.
///
/// The variant is chosen at the point the error is raised, so the process exit
/// code cannot depend on the formatted message. See the module docs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InitErrorKind {
    /// The auth material could not be resolved or validated, or an auth method
    /// was refused: `auth.tokenSource`, `auth.oidc.tokenSource`, a token that
    /// resolves empty (`AuthConfig::check_startup`), an `auth.method = "oidc"`
    /// that cannot be served, and the OIDC verifier/client construction.
    ///
    /// Daemons map this to [`crate::EXIT_AUTH`].
    Auth,
    /// Any other construction failure — currently the client's `[store]`
    /// source, which is the one non-auth failure reachable before `Service`
    /// construction returns.
    ///
    /// Daemons map this to [`crate::EXIT_BIND`]. Despite the constant's name
    /// this is *not* a bind error: the listener binds later, inside
    /// `Service::run`, and an occupied `bindPort` never reaches this type.
    Other,
}

impl InitErrorKind {
    /// The process exit code this kind terminates with.
    ///
    /// Both values are frp-rs extensions — Go frp v0.71.0 exits 1 on every
    /// construction failure in this list (and *starts* on an empty token rather
    /// than refusing). See `docs/developing.md` § CLI exit codes.
    pub fn exit_code(self) -> i32 {
        match self {
            InitErrorKind::Auth => crate::EXIT_AUTH,
            InitErrorKind::Other => crate::EXIT_BIND,
        }
    }
}

/// A service-construction failure carrying the [`InitErrorKind`] that the
/// daemons turn into an exit code.
pub struct ConstructError {
    kind: InitErrorKind,
    source: Box<dyn std::error::Error + Send + Sync>,
}

impl ConstructError {
    /// Tag any error as an auth-construction failure.
    pub fn auth(source: impl Into<Box<dyn std::error::Error + Send + Sync>>) -> Self {
        Self {
            kind: InitErrorKind::Auth,
            source: source.into(),
        }
    }

    /// Which kind of construction failure this is — the only input to the exit
    /// code.
    pub fn kind(&self) -> InitErrorKind {
        self.kind
    }
}

impl fmt::Display for ConstructError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.source)
    }
}

impl fmt::Debug for ConstructError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConstructError")
            .field("kind", &self.kind)
            .field("source", &self.source)
            .finish()
    }
}

impl std::error::Error for ConstructError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.source.as_ref())
    }
}

// Default tag for every construction error that is not explicitly an
// `InitErrorKind::Auth` one.
//
// These are explicit impls, not one blanket `impl<E: Into<Box<dyn Error + Send
// + Sync>>> From<E>`: that blanket impl overlaps std's reflexive
// `impl<T> From<T> for T` (with `E = ConstructError`), so it cannot be written.
// Every `?` on a non-auth failure in the `Service` constructors goes through
// one of these; the set is closed by the compiler, because adding a new error
// type to a constructor fails to build until it has a `From` (or an explicit
// `ConstructError::auth` at the site).
impl From<String> for ConstructError {
    fn from(source: String) -> Self {
        Self {
            kind: InitErrorKind::Other,
            source: source.into(),
        }
    }
}

impl From<std::io::Error> for ConstructError {
    fn from(source: std::io::Error) -> Self {
        Self {
            kind: InitErrorKind::Other,
            source: Box::new(source),
        }
    }
}

impl From<Box<dyn std::error::Error + Send + Sync>> for ConstructError {
    fn from(source: Box<dyn std::error::Error + Send + Sync>) -> Self {
        Self {
            kind: InitErrorKind::Other,
            source,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{EXIT_AUTH, EXIT_BIND};

    /// The kind → code mapping, asserted literally rather than through
    /// `exit_code()` on both sides.
    #[test]
    fn kind_maps_to_the_documented_exit_code() {
        assert_eq!(InitErrorKind::Auth.exit_code(), 3);
        assert_eq!(InitErrorKind::Auth.exit_code(), EXIT_AUTH);
        assert_eq!(InitErrorKind::Other.exit_code(), 4);
        assert_eq!(InitErrorKind::Other.exit_code(), EXIT_BIND);
    }

    /// The classification is a property of the value, not of its text: the
    /// same words under both kinds keep their kinds, and wrapping through
    /// `Box<dyn Error>`/`?` (the daemons' path) does not mutate it.
    #[test]
    fn classification_is_independent_of_the_displayed_text() {
        let text = "failed to load store from /tmp/authstore.json";
        let auth = ConstructError::auth(text.to_string());
        assert_eq!(auth.kind(), InitErrorKind::Auth);
        assert_eq!(auth.to_string(), text);

        let other: ConstructError = std::io::Error::other(text).into();
        assert_eq!(other.kind(), InitErrorKind::Other);
        assert_eq!(other.to_string(), text);

        // The daemons box the error before they read `.kind()` (via `?` into a
        // `Box<dyn Error + Send + Sync>`); assert the kind survives that.
        let boxed: Box<dyn std::error::Error + Send + Sync> = Box::new(auth);
        let downcast = boxed
            .downcast::<ConstructError>()
            .expect("ConstructError survives boxing");
        assert_eq!(downcast.kind(), InitErrorKind::Auth);
    }

    /// `From<String>` (the `frps` constructor's error type before this change)
    /// and `From<Box<dyn Error>>` (the `frpc` one) both land on `Other`.
    #[test]
    fn default_from_impls_are_other() {
        let from_string: ConstructError = "boom".to_string().into();
        assert_eq!(from_string.kind(), InitErrorKind::Other);
        assert_eq!(from_string.to_string(), "boom");

        let inner: Box<dyn std::error::Error + Send + Sync> = "inner".into();
        let from_box: ConstructError = inner.into();
        assert_eq!(from_box.kind(), InitErrorKind::Other);
        assert_eq!(from_box.to_string(), "inner");
    }
}
