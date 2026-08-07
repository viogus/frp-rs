//! Yamux transport: [`YamuxStream`] implements [`Transport`].
//!
//! The real type (tcp-mux feature on) and the compile-time stub (feature
//! off) both get the impl; only one compiles at a time.

use crate::mux::YamuxStream;

use super::Transport;

impl Transport for YamuxStream {
    fn debug_name(&self) -> &'static str {
        "IoStream::Yamux"
    }
    fn into_yamux(self: Box<Self>) -> Option<YamuxStream> {
        Some(*self)
    }
}
