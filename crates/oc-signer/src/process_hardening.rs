//! Process-level security hardening for key material protection.
//!
//! Applies OS primitives to reduce the risk of key material leaking via
//! core dumps, debugger attachment, or memory swapping.
//!
//! # Termination-time cleanup
//!
//! Cached key material is zeroized via globally registered cleanup hooks
//! (see [`register_cleanup`]). Two integration styles are supported:
//!
//! 1. **One-shot CLI commands:** call [`install_signal_handlers()`]. A background thread waits for
//!    SIGTERM/SIGINT/SIGHUP/SIGQUIT, runs the cleanup hooks, and then **terminates the whole
//!    process** with exit status `128 + signal`. **WARNING:** this bypasses normal unwinding and
//!    any async runtime shutdown machinery. It is intended for short-lived commands only; do NOT
//!    use it in daemons or long-running services.
//! 2. **Daemons / long-running services:** call [`install_panic_cleanup_hook()`] and
//!    [`spawn_signal_notifier()`]. The notifier thread runs the cleanup hooks once per received
//!    signal and forwards the signal number over a channel; the daemon selects on that channel in
//!    its own shutdown loop and performs a graceful exit. The panic hook additionally runs cleanup
//!    whenever a Rust panic occurs (covering the SIGABRT path, which cannot be safely intercepted
//!    via signal handlers).

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
    // Poison recovery: the guarded data is a plain list of closures with no
    // cross-field invariant that a mid-panic unwind could corrupt (precedent:
    // oc-crypto/src/key_cache.rs), so continue with the recovered lock.
    let mut hooks = match hooks().lock() {
        Ok(hooks) => hooks,
        Err(poisoned) => poisoned.into_inner(),
    };
    hooks.push(Box::new(f));
}

/// Run all registered cleanup hooks. Called by the signal handler thread
/// and the panic hook.
fn run_cleanup_hooks() {
    if let Some(hooks) = CLEANUP_HOOKS.get() {
        // Poison recovery: see `register_cleanup` — the guarded list has no
        // cross-field invariant, and skipping cleanup because an earlier hook
        // panicked would leak key material.
        let hooks = match hooks.lock() {
            Ok(hooks) => hooks,
            Err(poisoned) => poisoned.into_inner(),
        };
        for hook in hooks.iter() {
            hook();
        }
    }
}

/// Install a panic hook that runs all cleanup hooks before the default hook.
///
/// Use this in daemons and long-running services so cached key material is
/// zeroized even when a panic aborts the process (the primary path to
/// SIGABRT, which cannot be safely intercepted via signal handlers).
///
/// Must be called at most once; subsequent calls are no-ops.
#[cfg(unix)]
pub fn install_panic_cleanup_hook() {
    use std::sync::atomic::{AtomicBool, Ordering};

    static PANIC_HOOK_INSTALLED: AtomicBool = AtomicBool::new(false);
    if PANIC_HOOK_INSTALLED.swap(true, Ordering::SeqCst) {
        return;
    }

    // Capture the default panic hook so we can chain after cleanup.
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        run_cleanup_hooks();
        default_hook(info);
    }));
}

#[cfg(not(unix))]
pub fn install_panic_cleanup_hook() {}

/// Install signal handlers for SIGTERM, SIGINT, SIGHUP, and SIGQUIT.
///
/// Spawns a background thread that waits for the FIRST of these signals,
/// runs all registered cleanup hooks (zeroizing cached keys), then
/// terminates the process with exit status `128 + signal`.
///
/// # WARNING
///
/// This function **terminates the process**; it is meant for one-shot CLI
/// commands only. It is NOT for daemons: exiting directly kills the process
/// before any graceful shutdown can run and races async shutdown handlers
/// such as `tokio::select!` on `tokio::signal::ctrl_c()`. Daemons should use
/// [`install_panic_cleanup_hook()`] plus [`spawn_signal_notifier()`] instead.
///
/// Must be called at most once; subsequent calls are no-ops.
#[cfg(unix)]
pub fn install_signal_handlers() {
    use std::sync::atomic::{AtomicBool, Ordering};

    use signal_hook::{
        consts::{SIGHUP, SIGINT, SIGQUIT, SIGTERM},
        iterator::Signals,
    };

    install_panic_cleanup_hook();

    static SIGNAL_THREAD_STARTED: AtomicBool = AtomicBool::new(false);
    if SIGNAL_THREAD_STARTED.swap(true, Ordering::SeqCst) {
        return;
    }

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

/// Spawn a daemon-style signal notifier thread for SIGTERM, SIGINT, SIGHUP,
/// and SIGQUIT.
///
/// Unlike [`install_signal_handlers()`], the notifier never exits the
/// process. For each received signal it runs the registered cleanup hooks
/// once and sends the signal number through the returned channel; the
/// daemon's own shutdown loop receives from that channel and performs a
/// graceful exit. Pair with [`install_panic_cleanup_hook()`] so panics also
/// trigger cleanup.
///
/// Must be called at most once per process. Returns immediately; if signal
/// registration fails, an empty channel is returned (no signals will ever be
/// delivered) and the error is logged.
#[cfg(unix)]
pub fn spawn_signal_notifier() -> std::sync::mpsc::Receiver<u32> {
    use signal_hook::{
        consts::{SIGHUP, SIGINT, SIGQUIT, SIGTERM},
        iterator::Signals,
    };

    let (sender, receiver) = std::sync::mpsc::channel();
    let mut signals = match Signals::new([SIGTERM, SIGINT, SIGHUP, SIGQUIT]) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("ows: failed to register signal handlers: {e}");
            return receiver;
        }
    };

    if let Err(e) =
        std::thread::Builder::new().name("ows-signal-notifier".into()).spawn(move || {
            signal_notifier_loop(signals.forever(), &sender);
        })
    {
        eprintln!("ows: failed to spawn signal notifier thread: {e}");
    }
    receiver
}

#[cfg(not(unix))]
pub fn spawn_signal_notifier() -> std::sync::mpsc::Receiver<u32> {
    // Signal handling is Unix-only; the returned channel never receives.
    std::sync::mpsc::channel().1
}

/// Body of the notifier thread, factored out so tests can drive it with a
/// synthetic signal iterator instead of raising real signals.
///
/// For each signal yielded by `signals`, runs the cleanup hooks once and
/// forwards the signal number to `sender`. Stops as soon as the receiver is
/// dropped (the daemon has shut down its notifier).
#[cfg(unix)]
fn signal_notifier_loop(signals: impl Iterator<Item = i32>, sender: &std::sync::mpsc::Sender<u32>) {
    for sig in signals {
        run_cleanup_hooks();
        // Invariant: signal_hook only yields OS signal numbers, which are
        // strictly positive, so this conversion cannot lose information.
        let sig_num = u32::try_from(sig).unwrap_or_default();
        if sender.send(sig_num).is_err() {
            break;
        }
    }
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
        let rlimit_ok = libc::setrlimit(libc::RLIMIT_CORE, &raw const rlim) == 0;

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
        libc::setrlimit(libc::RLIMIT_CORE, &raw const rlim) == 0
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

#[cfg(all(test, unix))]
mod tests {
    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    };

    use super::*;

    /// Serializes tests that touch the global cleanup-hook registry or the
    /// process-wide panic hook; cargo runs tests in parallel threads.
    static HOOK_TEST_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn notifier_loop_delivers_every_signal_and_runs_hooks_once_per_signal() {
        let _guard = HOOK_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());

        let hook_runs = Arc::new(AtomicUsize::new(0));
        register_cleanup({
            let hook_runs = Arc::clone(&hook_runs);
            move || {
                hook_runs.fetch_add(1, Ordering::SeqCst);
            }
        });

        let signals = [libc::SIGTERM, libc::SIGINT, libc::SIGHUP, libc::SIGQUIT, libc::SIGINT];
        let (tx, rx) = std::sync::mpsc::channel();
        signal_notifier_loop(signals.into_iter(), &tx);
        drop(tx);

        let delivered: Vec<u32> = rx.try_iter().collect();
        assert_eq!(
            delivered,
            signals.iter().map(|sig| u32::try_from(*sig).unwrap_or_default()).collect::<Vec<_>>(),
            "notifier must deliver every signal number, in order"
        );
        assert_eq!(
            hook_runs.load(Ordering::SeqCst),
            signals.len(),
            "cleanup hooks must run exactly once per signal"
        );
    }

    #[test]
    fn notifier_loop_stops_when_receiver_is_dropped() {
        let _guard = HOOK_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());

        let hook_runs = Arc::new(AtomicUsize::new(0));
        register_cleanup({
            let hook_runs = Arc::clone(&hook_runs);
            move || {
                hook_runs.fetch_add(1, Ordering::SeqCst);
            }
        });

        let signals = [libc::SIGTERM, libc::SIGINT];
        let (tx, rx) = std::sync::mpsc::channel();
        drop(rx);
        signal_notifier_loop(signals.into_iter(), &tx);

        assert_eq!(
            hook_runs.load(Ordering::SeqCst),
            1,
            "loop must stop after the first failed send"
        );
    }

    #[test]
    fn panic_hook_still_chains_cleanup() {
        let _guard = HOOK_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());

        // Silence the default hook output for the intentional panic below;
        // install_panic_cleanup_hook chains onto whatever hook is current.
        std::panic::set_hook(Box::new(|_| {}));
        install_panic_cleanup_hook();

        let cleaned = Arc::new(AtomicBool::new(false));
        register_cleanup({
            let cleaned = Arc::clone(&cleaned);
            move || cleaned.store(true, Ordering::SeqCst)
        });

        let result = std::panic::catch_unwind(|| panic!("intentional test panic"));
        assert!(result.is_err(), "the panic must still propagate as unwinding");
        assert!(
            cleaned.load(Ordering::SeqCst),
            "panic hook must run cleanup hooks before the default hook"
        );
    }
}
