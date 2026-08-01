//! Process-level security hardening for key material protection.
//!
//! Applies OS primitives to reduce the risk of key material leaking via
//! core dumps, debugger attachment, or memory swapping.
//!
//! Also provides signal-based cleanup hooks so that cached key material
//! is zeroized on SIGTERM, SIGINT, SIGHUP, or SIGQUIT before the process exits.
//! A panic hook ensures cleanup also runs on Rust panics (covering the SIGABRT path).

use std::sync::{Mutex, OnceLock};

/// Global registry of cleanup functions to run on termination signals.
type CleanupHooks = Mutex<Vec<Box<dyn Fn() + Send>>>;
static CLEANUP_HOOKS: OnceLock<CleanupHooks> = OnceLock::new();

fn hooks() -> &'static Mutex<Vec<Box<dyn Fn() + Send>>> {
    CLEANUP_HOOKS.get_or_init(|| Mutex::new(Vec::new()))
}

/// Register a cleanup function to run when a termination signal is received.
///
/// Typical usage: register a closure that clears a [`KeyCache`](crate::KeyCache):
///
/// ```rust,ignore
/// use std::sync::Arc;
/// use oc_signer::KeyCache;
/// use oc_signer::process_hardening::register_cleanup;
///
/// let cache = Arc::new(KeyCache::new(std::time::Duration::from_secs(300), 16));
/// register_cleanup({
///     let cache = Arc::clone(&cache);
///     move || cache.clear()
/// });
/// ```
pub fn register_cleanup(f: impl Fn() + Send + 'static) {
    hooks().lock().expect("process hardening hooks mutex poisoned").push(Box::new(f));
}

/// Run all registered cleanup hooks. Called by the signal handler thread.
fn run_cleanup_hooks() {
    if let Some(hooks) = CLEANUP_HOOKS.get() &&
        let Ok(hooks) = hooks.lock()
    {
        for hook in hooks.iter() {
            hook();
        }
    }
}

/// Install signal handlers for SIGTERM, SIGINT, SIGHUP, and SIGQUIT.
///
/// Spawns a background thread that waits for any of these signals,
/// runs all registered cleanup hooks (zeroizing cached keys), then exits.
///
/// Also installs a panic hook so that cleanup runs on Rust panics
/// (the primary path to SIGABRT, which cannot be safely intercepted
/// via signal handlers).
///
/// Must be called at most once; subsequent calls are no-ops.
#[cfg(unix)]
pub fn install_signal_handlers() {
    use std::sync::atomic::{AtomicBool, Ordering};

    use signal_hook::{
        consts::{SIGHUP, SIGINT, SIGQUIT, SIGTERM},
        iterator::Signals,
    };

    static INSTALLED: AtomicBool = AtomicBool::new(false);
    if INSTALLED.swap(true, Ordering::SeqCst) {
        return;
    }

    // Capture the default panic hook so we can chain after cleanup.
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        run_cleanup_hooks();
        default_hook(info);
    }));

    let mut signals = match Signals::new([SIGTERM, SIGINT, SIGHUP, SIGQUIT]) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("ows: failed to register signal handlers: {e}");
            return;
        }
    };

    if let Err(e) = std::thread::Builder::new().name("ows-signal-handler".into()).spawn(move || {
        if let Some(sig) = signals.forever().next() {
            eprintln!("ows: received signal {sig}, zeroizing key material and exiting");
            run_cleanup_hooks();
            std::process::exit(128 + sig);
        }
    }) {
        eprintln!("ows: failed to spawn signal handler thread: {e}");
    }
}

#[cfg(not(unix))]
pub fn install_signal_handlers() {
    // Signal handling is Unix-only; no-op on other platforms.
}

/// Report of which hardening measures succeeded.
#[derive(Debug)]
pub struct HardeningReport {
    pub core_dumps_disabled: bool,
    pub ptrace_disabled: bool,
}

/// Apply all available process hardening measures.
#[cfg(unix)]
pub fn harden_process() -> HardeningReport {
    let core_dumps_disabled = disable_core_dumps();
    let ptrace_disabled = disable_ptrace();

    if !core_dumps_disabled {
        eprintln!("warning: failed to disable core dumps");
    }
    if !ptrace_disabled {
        eprintln!("warning: failed to disable ptrace attachment");
    }

    HardeningReport { core_dumps_disabled, ptrace_disabled }
}

#[cfg(not(unix))]
pub fn harden_process() -> HardeningReport {
    HardeningReport { core_dumps_disabled: false, ptrace_disabled: false }
}

#[cfg(target_os = "linux")]
fn disable_core_dumps() -> bool {
    // SAFETY: prctl and setrlimit are safe to call with valid arguments.
    // PR_SET_DUMPABLE(0) disables core dumps for the current process.
    // RLIMIT_CORE(0,0) sets the core file size limit to zero.
    // Both are standard POSIX operations with no undefined behavior.
    unsafe {
        let prctl_ok = libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) == 0;

        let rlim = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
        let rlimit_ok = libc::setrlimit(libc::RLIMIT_CORE, &rlim) == 0;

        prctl_ok && rlimit_ok
    }
}

#[cfg(target_os = "macos")]
fn disable_core_dumps() -> bool {
    // SAFETY: setrlimit is safe to call with a valid rlimit struct pointer.
    // RLIMIT_CORE(0,0) sets the core file size limit to zero, disabling core dumps.
    // This is a standard POSIX operation with no undefined behavior.
    unsafe {
        let rlim = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
        libc::setrlimit(libc::RLIMIT_CORE, &raw const rlim) == 0
    }
}

#[cfg(all(unix, not(target_os = "linux"), not(target_os = "macos")))]
fn disable_core_dumps() -> bool {
    // SAFETY: setrlimit is safe to call with a valid rlimit struct pointer.
    // RLIMIT_CORE(0,0) sets the core file size limit to zero, disabling core dumps.
    // This is a standard POSIX operation with no undefined behavior.
    unsafe {
        let rlim = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
        libc::setrlimit(libc::RLIMIT_CORE, &rlim) == 0
    }
}

// On Linux, PR_SET_DUMPABLE already prevents ptrace.
#[cfg(target_os = "linux")]
fn disable_ptrace() -> bool {
    true
}

#[cfg(target_os = "macos")]
fn disable_ptrace() -> bool {
    #[cfg(not(debug_assertions))]
    {
        const PT_DENY_ATTACH: libc::c_int = 31;
        // SAFETY: ptrace(PT_DENY_ATTACH) is a macOS-specific request that denies
        // any future ptrace attach attempts. PID 0 and NULL data pointer are
        // required by the API. No undefined behavior.
        unsafe { libc::ptrace(PT_DENY_ATTACH, 0, std::ptr::null_mut(), 0) == 0 }
    }
    #[cfg(debug_assertions)]
    {
        true // Allow debuggers in dev builds
    }
}

#[cfg(all(unix, not(target_os = "linux"), not(target_os = "macos")))]
fn disable_ptrace() -> bool {
    false
}

/// Lock a memory region to prevent it from being swapped to disk.
/// Returns false on failure (e.g. ENOMEM from mlock budget).
#[cfg(unix)]
pub fn mlock_slice(ptr: *const u8, len: usize) -> bool {
    if len == 0 {
        return true;
    }
    // SAFETY: mlock() locks pages containing the given memory range.
    // The pointer and length are derived from a valid slice reference.
    // mlock does not write to the memory; it only prevents swapping.
    let ret = unsafe { libc::mlock(ptr.cast::<libc::c_void>(), len) };
    if ret != 0 {
        eprintln!(
            "warning: mlock failed ({}), key material may be swapped to disk",
            std::io::Error::last_os_error()
        );
        return false;
    }
    true
}

#[cfg(not(unix))]
pub fn mlock_slice(_ptr: *const u8, _len: usize) -> bool {
    false
}

/// Unlock a previously mlocked memory region.
#[cfg(unix)]
pub fn munlock_slice(ptr: *const u8, len: usize) {
    if len == 0 {
        return;
    }
    // SAFETY: munlock() unlocks previously mlock'd pages.
    // The pointer and length are from the same slice that was mlock'd.
    unsafe {
        libc::munlock(ptr.cast::<libc::c_void>(), len);
    }
}

#[cfg(not(unix))]
pub fn munlock_slice(_ptr: *const u8, _len: usize) {}

/// Read an environment variable and remove it from the process environment.
/// Returns the value if it was set. Note: this does not guarantee zeroing
/// of the C runtime's internal environment buffer.
pub fn clear_env_var(name: &str) -> Option<String> {
    let value = std::env::var(name).ok();
    // SAFETY: std::env::remove_var is unsafe since Rust 1.66 because
    // concurrent access to environment variables is undefined behavior.
    // This is called during process hardening (single-threaded startup phase)
    // before any threads are spawned.
    unsafe {
        std::env::remove_var(name);
    }
    value
}
