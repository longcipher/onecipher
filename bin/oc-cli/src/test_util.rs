//! Shared test utilities for the `oc-cli` crate.
//!
//! The CLI persists state under `~/.onecipher`, which `oc_core::paths::state_dir()`
//! resolves from the process-global `HOME` env var. Tests that touch the
//! filesystem redirect `HOME` to a fresh temp dir. Because `HOME` is
//! process-global and `cargo test` runs tests on multiple threads, **all** tests
//! that mutate `HOME` must serialize through the single shared [`HOME_LOCK`]
//! below — otherwise two tests from different modules (e.g. `tests.rs` and
//! `wallet_rpc`) would race on the same env var and intermittently fail.

use std::sync::MutexGuard;

/// The single process-wide lock serializing all `HOME`-mutating tests.
///
/// This MUST be the only `HOME_LOCK` in the crate. Do not declare a second
/// static with the same name in another module — two independent locks would
/// let tests from different modules race on the global `HOME` env var.
pub(crate) static HOME_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// RAII guard that redirects `HOME` to an isolated temp dir and restores the
/// original value on drop. Serializes against all other `HOME`-mutating tests
/// via the shared [`HOME_LOCK`].
pub(crate) struct HomeGuard {
    _lock: MutexGuard<'static, ()>,
    _dir: tempfile::TempDir,
    old_home: Option<String>,
}

impl HomeGuard {
    /// Create an isolated HOME. The `HOME` env var points at the returned
    /// temp dir for the guard's lifetime. Tests that create wallets, secrets,
    /// keys, etc. must hold this guard.
    pub(crate) fn new() -> Self {
        let lock = HOME_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let dir = tempfile::tempdir().expect("create temp HOME dir");
        let old_home = std::env::var("HOME").ok();
        set_env("HOME", &dir.path().to_string_lossy());
        Self { _lock: lock, _dir: dir, old_home }
    }

    /// The isolated home directory path.
    pub(crate) fn path(&self) -> &std::path::Path {
        self._dir.path()
    }
}

impl Drop for HomeGuard {
    fn drop(&mut self) {
        match &self.old_home {
            Some(old) => set_env("HOME", old),
            None => remove_env("HOME"),
        }
    }
}

/// Set an environment variable. Safe under the [`HOME_LOCK`] serialization and
/// because each command reads-then-clears these vars itself; wrapped in
/// `unsafe` purely to satisfy the toolchain's `set_var` unsafety contract.
#[allow(unused_unsafe)]
pub(crate) fn set_env(k: &str, v: &str) {
    // SAFETY: tests are serialized via HOME_LOCK; no other thread reads these
    // specific vars concurrently. set_var is unsound only under data races on
    // the var being set, which we avoid here.
    unsafe { std::env::set_var(k, v) };
}

/// Remove an environment variable (see [`set_env`] for the safety rationale).
#[allow(unused_unsafe)]
pub(crate) fn remove_env(k: &str) {
    unsafe { std::env::remove_var(k) };
}
