//! Test-only helpers shared across `oc-core`'s unit tests.

use std::sync::{Mutex, MutexGuard, OnceLock};

static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

/// Serialize tests that mutate process-global environment variables.
///
/// `cargo test` runs unit tests on multiple threads within one process, so
/// `set_var`/`remove_var` in one test are visible to all others. Any test that
/// touches the environment must hold this guard for its whole body.
///
/// The mutex is intentionally poison-tolerant: a panic in one env test should
/// fail that test only, not cascade into unrelated ones.
pub(crate) fn env_lock() -> MutexGuard<'static, ()> {
    ENV_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}
