//! Poison-tolerant std::sync::RwLock access.
//!
//! A poisoned lock means a thread panicked mid-write. The state under our locks
//! is always replaced wholesale (never partially mutated), so recovering the
//! guard via into_inner() is safe and keeps one panicked task from cascading.

use std::sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard};

pub trait RwLockExt<T: ?Sized> {
    /// Read lock, ignoring poison.
    fn read_ok(&self) -> RwLockReadGuard<'_, T>;
    /// Write lock, ignoring poison.
    fn write_ok(&self) -> RwLockWriteGuard<'_, T>;
}

impl<T: ?Sized> RwLockExt<T> for RwLock<T> {
    fn read_ok(&self) -> RwLockReadGuard<'_, T> {
        self.read().unwrap_or_else(|e| e.into_inner())
    }
    fn write_ok(&self) -> RwLockWriteGuard<'_, T> {
        self.write().unwrap_or_else(|e| e.into_inner())
    }
}

/// All locks in AppState are wrapped in Arc, so we also need an impl there.
/// (A blanket impl over `Deref<Target = RwLock<T>>` hits orphan-rule conflicts.)
impl<T: ?Sized> RwLockExt<T> for Arc<RwLock<T>> {
    fn read_ok(&self) -> RwLockReadGuard<'_, T> {
        self.read().unwrap_or_else(|e| e.into_inner())
    }
    fn write_ok(&self) -> RwLockWriteGuard<'_, T> {
        self.write().unwrap_or_else(|e| e.into_inner())
    }
}
