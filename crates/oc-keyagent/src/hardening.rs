//! Process memory hardening for the Key-Agent (converged entry point).
//!
//! This module gathers the memory-hardening primitives that keep decrypted
//! key material out of core dumps, swap, and debugger reach, behind a single
//! idempotent entry point ([`apply_hardening`]):
//!
//! - `RLIMIT_CORE = 0` — no core files are written on crash.
//! - `mlockall(MCL_CURRENT | MCL_FUTURE)` — present and future mappings are pinned in RAM so key
//!   pages are never swapped to disk.
//! - Linux `prctl(PR_SET_DUMPABLE, 0)` — the process is not dumpable and, as a side effect, cannot
//!   be ptraced by non-root processes.
//! - macOS `ptrace(PT_DENY_ATTACH, ...)` — the macOS equivalent of dumpable denial (there is no
//!   `PR_SET_DUMPABLE` on macOS).
//!
//! The outcome is cached in a process-wide [`OnceLock<HardenStatus>`] so
//! repeated calls (daemon startup, per-connection threads, `doctor`) observe
//! one consistent snapshot. Use [`cached_status`] for read-only reporting and
//! [`HardenStatus`] as the machine-readable hardening state for `doctor`.
//!
//! ## Failure policy
//!
//! Hardening extras are fail-open by default: a step that cannot be applied
//! (low `RLIMIT_MEMLOCK`, missing `CAP_IPC_LOCK`, debugger already attached)
//! is logged via `tracing` and reflected as `false` in the status, while the
//! daemon keeps running. Setting `OC_STRICT_HARDEN=1` (also `true`/`yes`/`on`)
//! opts into fail-closed semantics through [`apply_hardening_strict`], which
//! returns [`KeyAgentError::Sandbox`] when the snapshot is incomplete.
//!
//! ## Relationship to `sandbox`
//!
//! [`crate::sandbox`] owns the composite confinement profile (seccomp BPF,
//! Seatbelt, capabilities, crash-dump policy switches) and keeps its own
//! copies of the dump/core primitives for its fail-closed network profile.
//! This module is the converged *memory*-hardening entry point: call
//! [`apply_hardening`] (or the strict variant) before [`crate::server::run`].
//!
//! ## macOS acknowledgment (written)
//!
//! On macOS this module fully applies `RLIMIT_CORE = 0`, `mlockall`, and
//! `PT_DENY_ATTACH`. Two limitations are explicitly acknowledged:
//!
//! 1. There is no `PR_SET_DUMPABLE` on macOS; `PT_DENY_ATTACH` is the documented equivalent for
//!    debugger denial, and `dumpable_denied` is therefore always `false` on macOS by design (see
//!    the field docs).
//! 2. Kernel *network* isolation on macOS is degraded when the Key-Agent runs embedded in the
//!    single-binary daemon: Seatbelt (`sandbox_init`) is process-wide, so the signing-thread
//!    sandbox deliberately skips it to avoid severing the daemon's own WSS relay (see
//!    [`crate::sandbox::apply_signing_thread_sandbox`]). Memory hardening is unaffected by that
//!    limitation; in-process network isolation on macOS rests on the R12a source scan over the
//!    isolated crates plus runtime `lsof -iTCP` checks, not on kernel enforcement. The per-request
//!    enclave ([`crate::enclave`]) closes the gap out-of-process: each signing child installs the
//!    full Seatbelt profile.
//!
//! Per R55/R56 this module is synchronous `std` only: no `tokio`, no network
//! I/O, and no new dependencies (only `std`, target-gated `libc`, `tracing`,
//! and `serde` for the doctor-facing snapshot — all already in scope).

// This module issues raw `setrlimit` / `mlockall` / `prctl` / `ptrace`
// syscalls. The crate root has `#![deny(unsafe_code)]` — it is relaxed for
// this module only via a module-level inner attribute, mirroring `sandbox.rs`.
#![allow(unsafe_code)]

use std::sync::OnceLock;

use serde::{Deserialize, Serialize};

use crate::error::KeyAgentError;

/// Machine-readable memory-hardening snapshot for `doctor` and startup logs.
///
/// A snapshot is [`HardenStatus::complete`] when core dumps are disabled,
/// memory is locked, and at least one debugger/dump denial is in force. The
/// two denial flags are platform-complementary by design: Linux sets both via
/// a single `prctl(PR_SET_DUMPABLE, 0)` (non-dumpable implies non-ptraceable
/// by non-root), while macOS sets only `debugger_denied` via
/// `ptrace(PT_DENY_ATTACH)` because `PR_SET_DUMPABLE` does not exist there.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct HardenStatus {
    /// `RLIMIT_CORE` was clamped to zero; no core files on crash.
    pub coredump_disabled: bool,
    /// `mlockall(MCL_CURRENT | MCL_FUTURE)` succeeded; mappings stay in RAM.
    pub memory_locked: bool,
    /// Linux `prctl(PR_SET_DUMPABLE, 0)` succeeded. Always `false` on macOS
    /// (no such primitive) and on unsupported platforms — see
    /// `debugger_denied` for the macOS equivalent.
    pub dumpable_denied: bool,
    /// Debugger attach is denied: macOS `ptrace(PT_DENY_ATTACH)`, or Linux
    /// `PR_SET_DUMPABLE = 0` (same call as `dumpable_denied`).
    pub debugger_denied: bool,
    /// `OC_STRICT_HARDEN` was set when this snapshot was taken.
    pub strict: bool,
}

impl HardenStatus {
    /// Whether every applicable hardening signal is in force.
    ///
    /// Requires core-dump disablement, locked memory, and at least one of the
    /// two platform-complementary denial flags.
    #[must_use]
    pub const fn complete(&self) -> bool {
        self.coredump_disabled &&
            self.memory_locked &&
            (self.dumpable_denied || self.debugger_denied)
    }

    /// Enforce fail-closed semantics on a snapshot.
    ///
    /// Returns `Ok(status)` when `strict` is false or the snapshot is
    /// complete; otherwise returns [`KeyAgentError::Sandbox`] describing which
    /// signals are missing. Pure (no I/O) so strictness is unit-testable
    /// without touching process-global state.
    pub fn check_strict(self, strict: bool) -> Result<Self, KeyAgentError> {
        if strict && !self.complete() {
            return Err(KeyAgentError::Sandbox(format!(
                "strict process hardening unmet (OC_STRICT_HARDEN=1): {self:?}"
            )));
        }
        Ok(self)
    }
}

/// Whether `OC_STRICT_HARDEN` opts into fail-closed hardening.
///
/// Accepts `1` / `true` / `yes` / `on` (case-insensitive, surrounding
/// whitespace ignored); unset or any other value means fail-open. Read on
/// every call so tests and late configuration changes observe the current
/// environment; the hardening *outcome* itself is still cached (see
/// [`apply_hardening`]).
#[must_use]
pub fn strict_mode_enabled() -> bool {
    std::env::var("OC_STRICT_HARDEN").map_or(false, |v| {
        matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on")
    })
}

/// Process-wide cached hardening outcome.
static HARDEN_STATUS: OnceLock<HardenStatus> = OnceLock::new();

/// Apply process memory hardening exactly once; return the cached snapshot.
///
/// Idempotent: the first call runs every step and caches the outcome in a
/// [`OnceLock`]; later calls (worker threads, `doctor`) return the same value
/// without reissuing syscalls. Individual step failures are logged and
/// reflected as `false` flags — use [`apply_hardening_strict`] for fail-closed
/// semantics under `OC_STRICT_HARDEN`.
pub fn apply_hardening() -> HardenStatus {
    *HARDEN_STATUS.get_or_init(run_hardening)
}

/// Apply process memory hardening, failing closed under `OC_STRICT_HARDEN`.
///
/// Behaves like [`apply_hardening`], then rejects an incomplete snapshot with
/// [`KeyAgentError::Sandbox`] when [`strict_mode_enabled`] holds. Daemon
/// startup should prefer this variant so a misconfigured host cannot
/// silently run the signer without memory hardening.
pub fn apply_hardening_strict() -> Result<HardenStatus, KeyAgentError> {
    apply_hardening().check_strict(strict_mode_enabled())
}

/// Read-only view of the cached hardening snapshot for `doctor`.
///
/// Returns `None` when [`apply_hardening`] has not run yet in this process;
/// never triggers hardening itself.
#[must_use]
pub fn cached_status() -> Option<HardenStatus> {
    HARDEN_STATUS.get().copied()
}

/// Run every hardening step once and assemble the snapshot.
fn run_hardening() -> HardenStatus {
    let mut status = HardenStatus { strict: strict_mode_enabled(), ..HardenStatus::default() };

    match disable_coredump() {
        Ok(()) => status.coredump_disabled = true,
        Err(e) => tracing::warn!(error = %e, "process hardening: could not disable core dumps"),
    }
    match lock_memory() {
        Ok(()) => status.memory_locked = true,
        Err(e) => {
            tracing::warn!(error = %e, "process hardening: could not mlockall; key pages may swap");
        }
    }

    #[cfg(target_os = "linux")]
    match deny_dumpable_linux() {
        Ok(()) => {
            // One prctl covers both: non-dumpable implies non-ptraceable.
            status.dumpable_denied = true;
            status.debugger_denied = true;
        }
        Err(e) => tracing::warn!(error = %e, "process hardening: prctl(PR_SET_DUMPABLE, 0) failed"),
    }

    // macOS has no PR_SET_DUMPABLE; PT_DENY_ATTACH is the equivalent denial.
    // `dumpable_denied` intentionally stays false here (see field docs).
    #[cfg(target_os = "macos")]
    match deny_debugger_macos() {
        Ok(()) => status.debugger_denied = true,
        Err(e) => tracing::warn!(error = %e, "process hardening: ptrace(PT_DENY_ATTACH) failed"),
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        tracing::warn!(
            "process hardening: no memory-hardening primitives on this platform; \
             snapshot stays incomplete"
        );
    }

    status
}

// ---------------------------------------------------------------------------
// Platform primitives
// ---------------------------------------------------------------------------

/// Clamp `RLIMIT_CORE` to zero so crashes never write core files.
///
/// Lowering the core limit never requires privilege, on Linux or macOS.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn disable_coredump() -> Result<(), String> {
    let limit = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
    // SAFETY: `setrlimit(RLIMIT_CORE, ...)` reads an `rlimit` struct we own;
    // the kernel copies it during the call and retains no pointer. Both
    // fields are zero, so no new resource grant is possible.
    let rc = unsafe { libc::setrlimit(libc::RLIMIT_CORE, &raw const limit) };
    if rc == 0 { Ok(()) } else { Err(std::io::Error::last_os_error().to_string()) }
}

/// Pin present and future mappings in RAM so key pages never reach swap.
///
/// Requires sufficient `RLIMIT_MEMLOCK` (Linux `CAP_IPC_LOCK` raises it);
/// containers with a tiny memlock limit will fail here — callers treat that
/// as fail-open `memory_locked = false`, or fail-closed under strict mode.
///
/// A low-but-nonzero limit is deliberately treated as failure: when the
/// process is still small, `mlockall(MCL_FUTURE)` *succeeds* and then turns
/// every later large allocation (age buffers, JSON frames — often megabytes)
/// into an `ENOMEM` abort once the lock budget is exhausted. Skipping the
/// call below [`MIN_MEMLOCK_FOR_MLOCKALL`] converts that delayed SIGABRT
/// into an honest `memory_locked = false` snapshot. Per-buffer locking
/// (`HardenedBytes` mlocks its own pages) is unaffected.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn lock_memory() -> Result<(), String> {
    let current = memlock_limit()?;
    if current != libc::RLIM_INFINITY && current < MIN_MEMLOCK_FOR_MLOCKALL {
        return Err(format!(
            "RLIMIT_MEMLOCK is {current} bytes (floor {MIN_MEMLOCK_FOR_MLOCKALL}): \
             skipping mlockall so later allocations cannot abort on ENOMEM"
        ));
    }
    // SAFETY: `mlockall` takes only integer flags and pins caller-owned
    // mappings; it dereferences no pointer and retains none.
    let rc = unsafe { libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE) };
    if rc == 0 { Ok(()) } else { Err(std::io::Error::last_os_error().to_string()) }
}

/// Minimum `RLIMIT_MEMLOCK` (bytes) for attempting process-wide `mlockall`.
///
/// Production hosts run with `CAP_IPC_LOCK` (effectively unlimited) and are
/// unaffected; small containers fail open instead of aborting later (see
/// [`lock_memory`]).
#[cfg(any(target_os = "linux", target_os = "macos"))]
const MIN_MEMLOCK_FOR_MLOCKALL: u64 = 64 * 1024 * 1024;

/// Read the current `RLIMIT_MEMLOCK` soft limit in bytes.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn memlock_limit() -> Result<u64, String> {
    let mut limit = libc::rlimit { rlim_cur: 0, rlim_max: 0 }; // SAFETY: `getrlimit(RLIMIT_MEMLOCK, ...)` writes a `rlimit` struct we
    // own; the kernel copies out during the call and retains no pointer.
    let rc = unsafe { libc::getrlimit(libc::RLIMIT_MEMLOCK, &raw mut limit) };
    if rc == 0 { Ok(limit.rlim_cur) } else { Err(std::io::Error::last_os_error().to_string()) }
}

/// Linux: mark the process non-dumpable (also blocks non-root ptrace).
#[cfg(target_os = "linux")]
fn deny_dumpable_linux() -> Result<(), String> {
    const PR_SET_DUMPABLE: libc::c_int = 4;
    // SAFETY: `prctl(PR_SET_DUMPABLE, 0, 0, 0, 0)` is a documented Linux
    // syscall with constant integer arguments and no memory-safety
    // implications; the return value is checked.
    let rc = unsafe { libc::prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) };
    if rc == 0 { Ok(()) } else { Err(std::io::Error::last_os_error().to_string()) }
}

/// macOS: refuse debugger attachment (the `PR_SET_DUMPABLE` equivalent).
#[cfg(target_os = "macos")]
fn deny_debugger_macos() -> Result<(), String> {
    const PT_DENY_ATTACH: libc::c_int = 31;
    // SAFETY: `ptrace(PT_DENY_ATTACH, 0, NULL, 0)` takes only integer and
    // NULL arguments; it dereferences no pointer. Failure (e.g. already
    // traced) is reported, never panicked.
    let rc = unsafe { libc::ptrace(PT_DENY_ATTACH, 0, std::ptr::null_mut(), 0) };
    if rc == 0 { Ok(()) } else { Err(std::io::Error::last_os_error().to_string()) }
}

/// Unsupported platforms have no core-dump primitive; the snapshot records
/// the gap instead of pretending otherwise.
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn disable_coredump() -> Result<(), String> {
    Err("RLIMIT_CORE is not available on this platform".to_string())
}

/// Unsupported platforms cannot pin memory process-wide.
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn lock_memory() -> Result<(), String> {
    Err("mlockall is not available on this platform".to_string())
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    /// Serializes the env-mutating tests: environment variables are
    /// process-global, so parallel tests must not race on `OC_STRICT_HARDEN`.
    static ENV_GUARD: Mutex<()> = Mutex::new(());

    #[test]
    fn default_status_is_incomplete() {
        assert!(!HardenStatus::default().complete());
    }

    #[test]
    fn complete_requires_every_signal() {
        let base = HardenStatus {
            coredump_disabled: true,
            memory_locked: true,
            dumpable_denied: true,
            debugger_denied: true,
            strict: false,
        };
        assert!(base.complete());
        // Each signal is load-bearing on its own.
        assert!(!HardenStatus { coredump_disabled: false, ..base }.complete());
        assert!(!HardenStatus { memory_locked: false, ..base }.complete());
        // Either denial flag suffices (platform complementarity).
        assert!(HardenStatus { dumpable_denied: false, ..base }.complete());
        assert!(HardenStatus { debugger_denied: false, ..base }.complete());
        assert!(
            !HardenStatus { dumpable_denied: false, debugger_denied: false, ..base }.complete()
        );
    }

    #[test]
    fn strict_check_is_fail_open_by_default() {
        let incomplete = HardenStatus::default();
        assert_eq!(incomplete.check_strict(false).unwrap(), incomplete);
    }

    #[test]
    fn strict_check_rejects_incomplete_snapshot() {
        let err = HardenStatus::default().check_strict(true).unwrap_err();
        assert!(matches!(err, KeyAgentError::Sandbox(_)));
        assert!(err.to_string().contains("OC_STRICT_HARDEN"));
    }

    #[test]
    fn strict_check_accepts_complete_snapshot() {
        let full = HardenStatus {
            coredump_disabled: true,
            memory_locked: true,
            dumpable_denied: true,
            debugger_denied: true,
            strict: true,
        };
        assert_eq!(full.check_strict(true).unwrap(), full);
    }

    #[test]
    fn strict_mode_parses_documented_values() {
        let _guard = ENV_GUARD.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let original = std::env::var("OC_STRICT_HARDEN").ok();
        for enabled in ["1", "true", "TRUE", " yes ", "on", "ON"] {
            // SAFETY: serialized by ENV_GUARD; the original value is restored
            // before the guard is released.
            unsafe { std::env::set_var("OC_STRICT_HARDEN", enabled) };
            assert!(strict_mode_enabled(), "{enabled:?} must enable strict mode");
        }
        for disabled in ["0", "false", "no", "", "strict"] {
            // SAFETY: see above.
            unsafe { std::env::set_var("OC_STRICT_HARDEN", disabled) };
            assert!(!strict_mode_enabled(), "{disabled:?} must not enable strict mode");
        }
        // SAFETY: see above.
        unsafe { std::env::remove_var("OC_STRICT_HARDEN") };
        assert!(!strict_mode_enabled(), "unset must mean fail-open");
        match original {
            // SAFETY: see above.
            Some(v) => unsafe { std::env::set_var("OC_STRICT_HARDEN", v) },
            // SAFETY: see above.
            None => unsafe { std::env::remove_var("OC_STRICT_HARDEN") },
        }
    }

    #[test]
    fn apply_is_idempotent_and_cached_for_doctor() {
        let first = apply_hardening();
        let second = apply_hardening();
        assert_eq!(first, second, "OnceLock must return one consistent snapshot");
        assert_eq!(cached_status(), Some(first), "doctor must observe the cached snapshot");
    }

    /// Lowering `RLIMIT_CORE` never requires privilege, so this signal must
    /// hold on every supported Unix in CI and on developer machines.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn coredump_signal_holds_on_supported_unix() {
        assert!(disable_coredump().is_ok(), "RLIMIT_CORE=0 must be settable");
        assert!(apply_hardening().coredump_disabled);
    }

    /// A small `RLIMIT_MEMLOCK` must fail `lock_memory` open instead of
    /// installing `MCL_FUTURE` and aborting a later multi-megabyte allocation
    /// (enclave children start small, so `mlockall` would succeed and the
    /// first age buffer would die with `ENOMEM` → SIGABRT).
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn memlock_floor_fails_open_on_small_limits() {
        let limit = memlock_limit().expect("getrlimit must succeed");
        if limit == libc::RLIM_INFINITY || limit >= MIN_MEMLOCK_FOR_MLOCKALL {
            assert!(
                lock_memory().is_ok(),
                "generous memlock limits must keep process-wide locking"
            );
        } else {
            assert!(
                lock_memory().is_err(),
                "a {limit}-byte memlock limit must skip mlockall (fail-open), not abort later"
            );
            assert!(
                !apply_hardening().memory_locked,
                "the snapshot must honestly report memory_locked=false"
            );
        }
    }

    #[test]
    fn snapshot_serializes_for_doctor_reports() {
        // `doctor --json` embeds hardening state; the snapshot must stay
        // JSON-compatible.
        let status = HardenStatus {
            coredump_disabled: true,
            memory_locked: false,
            dumpable_denied: true,
            debugger_denied: true,
            strict: false,
        };
        let json = serde_json::to_value(status).unwrap();
        assert_eq!(json["coredump_disabled"], true);
        assert_eq!(json["memory_locked"], false);
        let back: HardenStatus = serde_json::from_value(json).unwrap();
        assert_eq!(back, status);
    }
}
