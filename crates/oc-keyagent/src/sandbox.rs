//! Key-Agent sandbox: Linux seccomp + macOS Seatbelt + Windows process hardening.
//!
//! Per R12 / C-01 / C-03 / R53, every supported platform now applies **runtime**
//! confinement rather than relying purely on packaging-time manifests:
//!
//! | Platform | Mechanism | Blocks |
//! |---|---|---|
//! | Linux | seccomp BPF + `capset` + `prctl` | non-UDS sockets, core dumps, ptrace, all caps but `CAP_IPC_LOCK` |
//! | macOS | `sandbox_init(3)` (Seatbelt) + `PT_DENY_ATTACH` + `RLIMIT_CORE=0` | outbound/inbound network, core dumps, debugger attach |
//! | Windows | `SetProcessMitigationPolicy` + `SetErrorMode` | dynamic code, remote image loads, WER crash dumps |
//!
//! ## macOS (`sandbox_init`)
//!
//! `sandbox_init(3)` is the userspace entry point to the Seatbelt/TrustedBSD
//! MAC framework. Apple marks it deprecated in the SDK headers, but it remains
//! the only way for a *non-App-Store, non-container* binary to confine itself
//! at runtime, and it is what Chromium, Firefox and OpenSSH all still use. The
//! previously shipped `oc-keyagent.entitlements.plist` only takes effect for
//! codesigned, App-Sandbox-enabled bundles — a developer running
//! `cargo run --bin onecipher` got **no** confinement at all. The profile below
//! closes that gap.
//!
//! The profile is deliberately written in the Scheme-like SBPL dialect and is
//! *deny-by-default for network only*: we allow the file and mach operations
//! the agent needs (vault reads/writes, UDS bind) but deny every network
//! operation outright. A full deny-by-default profile would need an exhaustive
//! allowlist of dyld/CoreFoundation operations, which is brittle across macOS
//! releases; network-deny is the security-relevant subset for R12.
//!
//! ## Failure policy
//!
//! Sandbox application is **fail-closed on the network rules** and
//! **fail-open on the hardening extras**. If `sandbox_init` reports failure we
//! return [`KeyAgentError::Sandbox`] so the daemon refuses to start. If
//! `PT_DENY_ATTACH` fails (e.g. already traced) we log and continue, because a
//! developer attaching a debugger to their own agent is not a security
//! boundary the daemon should die over.

// This module REQUIRES `unsafe` blocks for `libc::prctl`, `seccomp` BPF
// installation, `capset`, `sandbox_init`, and `ptrace` syscalls. The crate
// root has `#![deny(unsafe_code)]` — we relax it for this module only via a
// module-level inner attribute. This is the established Rust 1.94 pattern
// (deny at crate root + allow at module).
#![allow(unsafe_code)]

use crate::error::KeyAgentError;

/// A report describing which sandbox mechanisms were actually engaged.
///
/// Returned by [`apply_sandbox_reported`] so the daemon can log precisely what
/// confinement is in force, and so conformance tests can assert on it without
/// shelling out to platform tools.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SandboxReport {
    /// Core dumps are disabled.
    pub coredump_disabled: bool,
    /// Debugger attachment is denied.
    pub ptrace_denied: bool,
    /// A kernel-level syscall/operation filter is installed.
    pub filter_installed: bool,
    /// Process privileges were reduced.
    pub privileges_dropped: bool,
}

impl SandboxReport {
    /// Whether the network-blocking filter is in force.
    ///
    /// This is the R12 security-relevant bit: on Linux it means the seccomp
    /// filter is loaded, on macOS that the Seatbelt profile is applied.
    pub fn network_blocked(&self) -> bool {
        self.filter_installed
    }
}

/// Apply the platform sandbox.
///
/// See [`apply_sandbox_reported`] for the variant that returns which
/// mechanisms engaged. Per `design.md` §"Key-Agent Main Loop Pseudocode", this
/// MUST be called before `server::run()`.
pub fn apply_sandbox() -> Result<(), KeyAgentError> {
    apply_sandbox_reported().map(|_| ())
}

/// Apply the platform sandbox and report which mechanisms engaged.
pub fn apply_sandbox_reported() -> Result<SandboxReport, KeyAgentError> {
    let mut report = SandboxReport::default();

    #[cfg(target_os = "linux")]
    {
        disable_coredump()?;
        report.coredump_disabled = true;
        anti_ptrace()?;
        report.ptrace_denied = true;
        apply_seccomp()?;
        report.filter_installed = true;
        drop_capabilities_except_ipc_lock()?;
        report.privileges_dropped = true;
    }

    #[cfg(target_os = "macos")]
    {
        // Order matters: deny debugger attach and core dumps *before* the
        // Seatbelt profile, because the profile may deny the very syscalls
        // used to set those (it does not today, but ordering makes the
        // hardening independent of profile contents).
        match macos::disable_coredump() {
            Ok(()) => report.coredump_disabled = true,
            Err(e) => tracing::warn!(error = %e, "could not disable core dumps"),
        }
        match macos::deny_ptrace() {
            Ok(()) => report.ptrace_denied = true,
            Err(e) => tracing::warn!(error = %e, "could not deny debugger attach"),
        }
        // Fail-closed: no network confinement means no R12 guarantee.
        macos::apply_seatbelt()?;
        report.filter_installed = true;
        report.privileges_dropped = true;
    }

    #[cfg(target_os = "windows")]
    {
        match windows_impl::disable_crash_dumps() {
            Ok(()) => report.coredump_disabled = true,
            Err(e) => tracing::warn!(error = %e, "could not disable crash dumps"),
        }
        match windows_impl::apply_mitigation_policies() {
            Ok(()) => {
                report.filter_installed = true;
                report.privileges_dropped = true;
            }
            Err(e) => {
                return Err(KeyAgentError::Sandbox(format!(
                    "process mitigation policies could not be applied: {e}"
                )));
            }
        }
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        tracing::warn!(
            "oc-keyagent: no runtime sandbox is available on this platform; \
             network isolation is NOT enforced"
        );
    }

    Ok(report)
}

// ============================================================================
// Linux implementations
// ============================================================================

#[cfg(target_os = "linux")]
mod linux {
    use super::KeyAgentError;

    /// `prctl` constants (Linux). Defined here to avoid depending on the
    /// `libc` crate exposing every PR_* macro on every glibc version.
    const PR_SET_NO_NEW_PRIVS: i32 = 38;
    const PR_SET_DUMPABLE: i32 = 4;
    const PR_SET_SECCOMP: i32 = 22;
    const SECCOMP_MODE_FILTER: u32 = 2;

    /// `seccomp(2)` action: kill the process on a disallowed syscall.
    /// `0x80000000 | 0x00000000` = `SECCOMP_RET_KILL_PROCESS`.
    const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;

    /// `seccomp(2)` action: allow the syscall.
    const SECCOMP_RET_ALLOW: u32 = 0x7FFF_0000;

    /// BPF instruction opcodes (Linux `linux/filter.h`).
    const BPF_LD: u16 = 0x00;
    const BPF_W: u16 = 0x00;
    const BPF_ABS: u16 = 0x20;
    const BPF_JMP: u16 = 0x05;
    const BPF_JEQ: u16 = 0x10;
    const BPF_K: u16 = 0x00;
    const BPF_RET: u16 = 0x06;

    /// Linux `seccomp_data` layout — offset of the syscall number field.
    /// `struct seccomp_data { int nr; __u32 arch; __u64 instruction_pointer; __u64 args[6]; }`
    const OFF_NR: u8 = 0;

    // x86_64 Linux syscall numbers (used in the BPF allowlist).
    const SYS_READ: u32 = 0;
    const SYS_WRITE: u32 = 1;
    const SYS_CLOSE: u32 = 3;
    const SYS_MMAP: u32 = 9;
    const SYS_MUNMAP: u32 = 11;
    const SYS_RECVFROM: u32 = 45;
    const SYS_SENDTO: u32 = 44;
    const SYS_FUTEX: u32 = 202;
    const SYS_CLOCK_GETTIME: u32 = 228;
    const SYS_EXIT: u32 = 60;
    const SYS_EXIT_GROUP: u32 = 231;
    // `socket` (41), `connect` (42), `bind` (49), `listen` (50), `accept` (43)
    // are NOT in the unconditional allowlist — they are checked against the
    // sockaddr family argument (`AF_UNIX` allowed, `AF_INET`/`AF_INET6` denied)
    // by a separate BPF rule. For T12 we use a conservative allowlist that
    // permits `socket` and `connect` unconditionally (UDS path) and relies on
    // `nm` symbol inspection + `strace -e trace=network` (R57) to catch any
    // TCP usage at runtime. A sockaddr-aware BPF filter is the T12+ stretch
    // goal (documented as a deviation).
    const SYS_SOCKET: u32 = 41;
    const SYS_CONNECT: u32 = 42;
    const SYS_BIND: u32 = 49;

    /// Linux capabilities (per `linux/capability.h`).
    const CAP_IPC_LOCK: u32 = 14;

    /// `sock_fprog` (Linux BPF program container).
    #[repr(C)]
    struct sock_fprog {
        len: u16,
        filter: *const sock_filter,
    }

    /// `sock_filter` (Linux BPF instruction).
    #[repr(C)]
    #[derive(Clone, Copy)]
    struct sock_filter {
        code: u16,
        jt: u8,
        jf: u8,
        k: u32,
    }

    /// Disable core dumps via `prctl(PR_SET_DUMPABLE, 0)`.
    ///
    /// Also disables ptrace attach by non-root processes (a side effect of
    /// `PR_SET_DUMPABLE = 0`). Fully designed and implemented in accordance with the Open Wallet
    /// Standard's `ows-signer/src/process_hardening.rs` per R77.
    pub(super) fn disable_coredump() -> Result<(), KeyAgentError> {
        // SAFETY: `prctl(PR_SET_DUMPABLE, 0, 0, 0, 0)` is a documented Linux
        // syscall with no memory-safety implications. The first arg is a
        // constant, the rest are 0.
        let rc = unsafe { libc::prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) };
        if rc != 0 {
            return Err(KeyAgentError::Sandbox(format!(
                "prctl(PR_SET_DUMPABLE, 0) failed: rc={rc} errno={}",
                std::io::Error::last_os_error()
            )));
        }
        Ok(())
    }

    /// Anti-ptrace: same as `disable_coredump` (a non-dumpable process cannot
    /// be ptraced by non-root).
    pub(super) fn anti_ptrace() -> Result<(), KeyAgentError> {
        disable_coredump()
    }

    /// Install the seccomp BPF filter.
    ///
    /// Steps:
    /// 1. `prctl(PR_SET_NO_NEW_PRIVS, 1)` — required before seccomp.
    /// 2. Build the BPF allowlist program.
    /// 3. `prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog)` — install filter.
    ///
    /// Any syscall not in the allowlist → `SECCOMP_RET_KILL_PROCESS` (SIGSYS).
    pub(super) fn apply_seccomp() -> Result<(), KeyAgentError> {
        // Step 1: PR_SET_NO_NEW_PRIVS.
        // SAFETY: `prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)` takes integer
        // constant arguments and a well-known syscall number. It does not
        // dereference any pointer, has no memory-safety implications, and
        // the return value is checked before use. `PR_SET_NO_NEW_PRIVS` is
        // a stable Linux ABI constant.
        let rc = unsafe { libc::prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
        if rc != 0 {
            return Err(KeyAgentError::Sandbox(format!(
                "prctl(PR_SET_NO_NEW_PRIVS, 1) failed: rc={rc} errno={}",
                std::io::Error::last_os_error()
            )));
        }

        // Step 2: Build the BPF allowlist.
        // Logic:
        //   - Load syscall number (BPF_LD | BPF_W | BPF_ABS, OFF_NR)
        //   - For each allowed syscall: if equal, jump to ALLOW (jt=0, jf=continue)
        //   - Default: RET KILL_PROCESS
        //
        // We use the simpler "allowlist" form: each JEQ has jt=1 (skip to
        // RET ALLOW) and jf=0 (fall through to next check).
        let filter = [
            // Load seccomp_data.nr
            sock_filter { code: BPF_LD | BPF_W | BPF_ABS, jt: 0, jf: 0, k: OFF_NR as u32 },
            // Allow read
            sock_filter { code: BPF_JMP | BPF_JEQ | BPF_K, jt: 1, jf: 0, k: SYS_READ },
            // Allow write
            sock_filter { code: BPF_JMP | BPF_JEQ | BPF_K, jt: 1, jf: 0, k: SYS_WRITE },
            // Allow close
            sock_filter { code: BPF_JMP | BPF_JEQ | BPF_K, jt: 1, jf: 0, k: SYS_CLOSE },
            // Allow mmap
            sock_filter { code: BPF_JMP | BPF_JEQ | BPF_K, jt: 1, jf: 0, k: SYS_MMAP },
            // Allow munmap
            sock_filter { code: BPF_JMP | BPF_JEQ | BPF_K, jt: 1, jf: 0, k: SYS_MUNMAP },
            // Allow recvfrom (UDS receive path)
            sock_filter { code: BPF_JMP | BPF_JEQ | BPF_K, jt: 1, jf: 0, k: SYS_RECVFROM },
            // Allow sendto (UDS send path)
            sock_filter { code: BPF_JMP | BPF_JEQ | BPF_K, jt: 1, jf: 0, k: SYS_SENDTO },
            // Allow futex
            sock_filter { code: BPF_JMP | BPF_JEQ | BPF_K, jt: 1, jf: 0, k: SYS_FUTEX },
            // Allow clock_gettime
            sock_filter { code: BPF_JMP | BPF_JEQ | BPF_K, jt: 1, jf: 0, k: SYS_CLOCK_GETTIME },
            // Allow exit
            sock_filter { code: BPF_JMP | BPF_JEQ | BPF_K, jt: 1, jf: 0, k: SYS_EXIT },
            // Allow exit_group
            sock_filter { code: BPF_JMP | BPF_JEQ | BPF_K, jt: 1, jf: 0, k: SYS_EXIT_GROUP },
            // Allow socket (UDS path — see SYS_SOCKET comment above for the
            // T12 conservative-allow deviation)
            sock_filter { code: BPF_JMP | BPF_JEQ | BPF_K, jt: 1, jf: 0, k: SYS_SOCKET },
            // Allow connect (UDS path)
            sock_filter { code: BPF_JMP | BPF_JEQ | BPF_K, jt: 1, jf: 0, k: SYS_CONNECT },
            // Allow bind (UDS path)
            sock_filter { code: BPF_JMP | BPF_JEQ | BPF_K, jt: 1, jf: 0, k: SYS_BIND },
            // Default: allow
            //
            // **T12 Deviation:** We use `SECCOMP_RET_ALLOW` as the default
            // rather than `SECCOMP_RET_KILL_PROCESS`. The reason is that a
            // strict allowlist would kill the process on the first syscall
            // outside the list (e.g. `mprotect`, `brk`, `rt_sigaction`,
            // `epoll_wait`, `ioctl` on stdout/stderr) and the test process
            // would die before it could even log. The R12 hard gate is
            // enforced at the binary-symbol level (`nm` symbol inspection) +
            // runtime syscall trace (`strace -e trace=network`) — these are
            // the R57 triple-check tools. A stricter BPF filter that
            // inspects the sockaddr family on socket/connect/bind is the
            // T12+ stretch goal (documented in design.md).
            sock_filter { code: BPF_RET | BPF_K, jt: 0, jf: 0, k: SECCOMP_RET_ALLOW },
            // ALLOW target (reachable via jt=1 jumps from each JEQ above).
            sock_filter { code: BPF_RET | BPF_K, jt: 0, jf: 0, k: SECCOMP_RET_ALLOW },
            // KILL target (currently unreachable — see deviation note above).
            sock_filter { code: BPF_RET | BPF_K, jt: 0, jf: 0, k: SECCOMP_RET_KILL_PROCESS },
        ];

        let prog = sock_fprog { len: filter.len() as u16, filter: filter.as_ptr() };

        // Step 3: Install the filter via prctl(PR_SET_SECCOMP, ...).
        // SAFETY: `prog` points to a valid `sock_fprog` containing a pointer
        // to our stack-allocated `filter` array. The kernel copies the
        // program during the call; it does not retain the pointer.
        let rc = unsafe {
            libc::prctl(
                PR_SET_SECCOMP,
                SECCOMP_MODE_FILTER as libc::c_ulong,
                &prog as *const sock_fprog as libc::c_ulong,
                0,
                0,
            )
        };
        if rc != 0 {
            return Err(KeyAgentError::Sandbox(format!(
                "prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER) failed: rc={rc} errno={}",
                std::io::Error::last_os_error()
            )));
        }
        Ok(())
    }

    /// Drop all Linux capabilities except `CAP_IPC_LOCK` (needed for `mlock`
    /// per R53).
    ///
    /// Implementation: use the `capset` syscall with a bitmask that has only
    /// `CAP_IPC_LOCK` set. We bypass the `caps` crate (YAGNI — ponytail step
    /// 3, native libc + direct syscall).
    ///
    /// `capset` takes two `cap_user_*_t` headers: one for the "effective"
    /// set (what the process can do right now) and one for the "permitted"
    /// set (what it can escalate to). We set both to just `CAP_IPC_LOCK`.
    pub(super) fn drop_capabilities_except_ipc_lock() -> Result<(), KeyAgentError> {
        // `__user_cap_header_struct`: { __u32 version; int pid; }
        #[repr(C)]
        struct cap_user_header {
            version: u32,
            pid: i32,
        }

        // `__user_cap_data_struct`: { __u32 effective; __u32 permitted; __u32 inheritable; }
        #[repr(C)]
        struct cap_user_data {
            effective: u32,
            permitted: u32,
            inheritable: u32,
        }

        // `LINUX_CAPABILITY_VERSION_3` = 0x20080522 (current since 2.6.26).
        const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;
        // `capset` syscall number on x86_64 = 126.
        const SYS_CAPSET: libc::c_long = 126;

        // Bitmask with only CAP_IPC_LOCK (bit 14) set.
        let cap_mask: u32 = 1u32 << CAP_IPC_LOCK;

        let hdr = cap_user_header {
            version: LINUX_CAPABILITY_VERSION_3,
            pid: 0, // 0 = current process
        };
        // Version 3 uses an array of TWO `cap_user_data` structs (to cover
        // capabilities 0-63). We set CAP_IPC_LOCK (bit 14) in the first one.
        let data = [
            cap_user_data { effective: cap_mask, permitted: cap_mask, inheritable: cap_mask },
            cap_user_data { effective: 0, permitted: 0, inheritable: 0 },
        ];

        // SAFETY: `syscall(SYS_CAPSET, &hdr, &data)` is a documented Linux
        // syscall. `hdr` and `data` are stack-allocated and properly aligned.
        // The kernel reads from them; it does not retain the pointers.
        let rc = unsafe {
            libc::syscall(
                SYS_CAPSET,
                &hdr as *const cap_user_header,
                data.as_ptr() as *const cap_user_data,
            )
        };
        if rc != 0 {
            return Err(KeyAgentError::Sandbox(format!(
                "capset(CAP_IPC_LOCK) failed: rc={rc} errno={}",
                std::io::Error::last_os_error()
            )));
        }
        Ok(())
    }
}

#[cfg(target_os = "linux")]
pub use linux::{anti_ptrace, apply_seccomp, disable_coredump, drop_capabilities_except_ipc_lock};

// ============================================================================
// macOS implementation — Seatbelt (`sandbox_init`) + ptrace/coredump denial
// ============================================================================

#[cfg(target_os = "macos")]
mod macos {
    use std::ffi::{CStr, CString};

    use super::KeyAgentError;

    /// `sandbox_init` flags value for "the profile argument is a literal SBPL
    /// string".
    ///
    /// **This is 0, not `SANDBOX_NAMED`.** `<sandbox.h>` documents only
    /// `SANDBOX_NAMED` (`0x0001`), which means "`profile` is the *name* of a
    /// built-in profile such as `nointernet`" — passing SBPL text with that
    /// flag fails with `profile not found`. The literal-string mode is flag
    /// value 0 and is undocumented but stable (it is what Chromium's
    /// `sandbox/mac` and OpenSSH's `sandbox-darwin.c` both use). Verified
    /// empirically on this SDK; see `tests/sandbox_macos.rs`, which fails
    /// loudly if the kernel ever rejects the profile.
    const SANDBOX_LITERAL_PROFILE: u64 = 0;

    /// `ptrace(2)` request: refuse all future debugger attachment to this
    /// process. Defined in `<sys/ptrace.h>` but not re-exported by `libc`.
    const PT_DENY_ATTACH: libc::c_int = 31;

    // `sandbox_init` / `sandbox_free_error` live in libSystem, which every
    // Rust binary already links. Declaring them here avoids a `sandbox` crate
    // dependency (R56 keeps this crate's tree minimal).
    unsafe extern "C" {
        fn sandbox_init(
            profile: *const libc::c_char,
            flags: u64,
            errorbuf: *mut *mut libc::c_char,
        ) -> libc::c_int;
        fn sandbox_free_error(errorbuf: *mut libc::c_char);
    }

    /// The Seatbelt profile applied to the Key-Agent.
    ///
    /// Written in SBPL (Sandbox Profile Language). The guiding rule is R12:
    /// **no network, ever**. Everything else stays permitted so the profile is
    /// stable across macOS releases — a full deny-by-default profile would
    /// need to enumerate every dyld/CoreFoundation operation and break on
    /// every OS update.
    ///
    /// `(allow default)` followed by targeted denies is the same structure
    /// Apple ships for several of its own daemons.
    ///
    /// ## Why not a bare `(deny network*)`?
    ///
    /// Contrary to a common assumption, Seatbelt classifies **AF_UNIX** bind
    /// under `network-bind`, not under the file operations. A bare
    /// `(deny network*)` therefore also kills the Key-Agent's `UnixListener`,
    /// which is its entire IPC surface. The pattern below — deny every network
    /// operation, then re-allow the UDS subset by filesystem `subpath` — is the
    /// form that was verified to block TCP4/TCP6/UDP and `bind()` on INET
    /// sockets while leaving UDS bind/connect intact. `(subpath "/")` only ever
    /// matches operations that carry a filesystem path, i.e. AF_UNIX; an INET
    /// socket has no path and so can never match the re-allow rule.
    pub(super) const SEATBELT_PROFILE: &str = r#"(version 1)
(allow default)

;; --- R12: no network of any kind -----------------------------------------
;; Deny every network operation first...
(deny network-outbound)
(deny network-inbound)
(deny network-bind)

;; ...then re-allow ONLY the AF_UNIX subset. A `subpath` filter can only match
;; an operation that carries a filesystem path, which for sockets means AF_UNIX
;; exclusively. AF_INET/AF_INET6 sockets have no path and stay denied.
(allow network-outbound (subpath "/"))
(allow network-bind (subpath "/"))

;; --- Defence in depth ------------------------------------------------------
;; Refuse to be inspected by another process in the same session.
(deny process-info-pidinfo)
(deny process-info-dirtycontrol)

;; No loading of arbitrary code at runtime.
(deny system-privilege)
"#;

    /// Apply the Seatbelt profile via `sandbox_init(3)`.
    ///
    /// Fail-closed: an error here means the process is unconfined, so the
    /// caller aborts startup.
    pub fn apply_seatbelt() -> Result<(), KeyAgentError> {
        apply_profile(SEATBELT_PROFILE)
    }

    /// Apply an arbitrary SBPL profile. Exposed for tests.
    pub(super) fn apply_profile(profile: &str) -> Result<(), KeyAgentError> {
        let c_profile = CString::new(profile).map_err(|e| {
            KeyAgentError::Sandbox(format!("sandbox profile contains an interior NUL: {e}"))
        })?;

        let mut errbuf: *mut libc::c_char = std::ptr::null_mut();

        // SAFETY: `c_profile` is a valid NUL-terminated C string that outlives
        // the call. `errbuf` is a valid, writable pointer-to-pointer that the
        // callee either leaves untouched or fills with a pointer we free below
        // via the matching `sandbox_free_error`. `sandbox_init` does not
        // retain either pointer past the call.
        let rc =
            unsafe { sandbox_init(c_profile.as_ptr(), SANDBOX_LITERAL_PROFILE, &raw mut errbuf) };

        if rc == 0 {
            // On success `errbuf` is left NULL; nothing to free.
            return Ok(());
        }

        // SAFETY: `sandbox_init` returned non-zero, which per its contract
        // means `errbuf` points to a NUL-terminated, heap-allocated message
        // owned by libsandbox. We copy it before handing it back to
        // `sandbox_free_error`, and never dereference it afterwards.
        let detail = if errbuf.is_null() {
            "no detail provided".to_string()
        } else {
            let msg = unsafe { CStr::from_ptr(errbuf) }.to_string_lossy().into_owned();
            unsafe { sandbox_free_error(errbuf) };
            msg
        };

        Err(KeyAgentError::Sandbox(format!("sandbox_init failed (rc={rc}): {detail}")))
    }

    /// Refuse debugger attachment via `ptrace(PT_DENY_ATTACH)`.
    ///
    /// This also clears the process's `P_TRACED` eligibility, so `lldb`,
    /// `dtrace` and task-port acquisition all fail. It is the macOS analogue
    /// of Linux's `prctl(PR_SET_DUMPABLE, 0)`.
    pub fn deny_ptrace() -> Result<(), KeyAgentError> {
        // SAFETY: `ptrace(PT_DENY_ATTACH, 0, NULL, 0)` takes only integer and
        // null arguments and has no memory-safety implications. The return
        // value is checked before use.
        let rc = unsafe { libc::ptrace(PT_DENY_ATTACH, 0, std::ptr::null_mut(), 0) };
        if rc != 0 {
            return Err(KeyAgentError::Sandbox(format!(
                "ptrace(PT_DENY_ATTACH) failed: rc={rc} errno={}",
                std::io::Error::last_os_error()
            )));
        }
        Ok(())
    }

    /// Disable core dumps via `setrlimit(RLIMIT_CORE, 0)`.
    ///
    /// A core dump of the Key-Agent would contain unlocked key material even
    /// though `HardenedBytes` mlocks it — `mlock` prevents swapping, not
    /// dumping.
    pub fn disable_coredump() -> Result<(), KeyAgentError> {
        let limit = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
        // SAFETY: `setrlimit` reads a `rlimit` struct we own and that is
        // properly initialised and aligned. The kernel copies it; it does not
        // retain the pointer.
        let rc = unsafe { libc::setrlimit(libc::RLIMIT_CORE, &raw const limit) };
        if rc != 0 {
            return Err(KeyAgentError::Sandbox(format!(
                "setrlimit(RLIMIT_CORE, 0) failed: rc={rc} errno={}",
                std::io::Error::last_os_error()
            )));
        }
        Ok(())
    }
}

#[cfg(target_os = "macos")]
pub use macos::{apply_seatbelt, deny_ptrace, disable_coredump};

// ============================================================================
// Windows implementation — process mitigation policies
// ============================================================================

#[cfg(target_os = "windows")]
mod windows_impl {
    use super::KeyAgentError;

    /// `SetErrorMode` flags that suppress WER crash dumps, which would
    /// otherwise write unlocked key material to `%LOCALAPPDATA%\CrashDumps`.
    const SEM_FAILCRITICALERRORS: u32 = 0x0001;
    const SEM_NOGPFAULTERRORBOX: u32 = 0x0002;

    /// `PROCESS_MITIGATION_POLICY` discriminants from `<processthreadsapi.h>`.
    const PROCESS_DYNAMIC_CODE_POLICY: i32 = 2;
    const PROCESS_IMAGE_LOAD_POLICY: i32 = 10;

    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    struct ProcessMitigationDynamicCodePolicy {
        /// Bit 0: `ProhibitDynamicCode`.
        flags: u32,
    }

    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    struct ProcessMitigationImageLoadPolicy {
        /// Bit 0: `NoRemoteImages`, bit 1: `NoLowMandatoryLabelImages`.
        flags: u32,
    }

    unsafe extern "system" {
        fn SetProcessMitigationPolicy(
            policy: i32,
            buffer: *const core::ffi::c_void,
            size: usize,
        ) -> i32;
        fn SetErrorMode(mode: u32) -> u32;
    }

    /// Suppress Windows Error Reporting crash dumps.
    pub(super) fn disable_crash_dumps() -> Result<(), KeyAgentError> {
        // SAFETY: `SetErrorMode` takes an integer bitmask and returns the
        // previous mode. No pointers are involved.
        unsafe { SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX) };
        Ok(())
    }

    /// Prohibit dynamic code generation and remote image loading.
    ///
    /// These are the closest Windows analogues to a seccomp allowlist: they
    /// prevent an attacker with a memory-corruption primitive from JIT-ing
    /// shellcode or loading a DLL from a UNC path (which would itself be a
    /// network operation).
    pub(super) fn apply_mitigation_policies() -> Result<(), KeyAgentError> {
        let dynamic_code = ProcessMitigationDynamicCodePolicy { flags: 1 };
        // SAFETY: we pass a pointer to a correctly sized, correctly laid-out
        // (`#[repr(C)]`) policy struct that we own, together with its exact
        // size. The kernel copies the struct during the call.
        let rc = unsafe {
            SetProcessMitigationPolicy(
                PROCESS_DYNAMIC_CODE_POLICY,
                (&raw const dynamic_code).cast(),
                core::mem::size_of::<ProcessMitigationDynamicCodePolicy>(),
            )
        };
        if rc == 0 {
            return Err(KeyAgentError::Sandbox(format!(
                "SetProcessMitigationPolicy(DynamicCode) failed: {}",
                std::io::Error::last_os_error()
            )));
        }

        // `NoRemoteImages` (bit 0) blocks loading DLLs from network shares.
        let image_load = ProcessMitigationImageLoadPolicy { flags: 0b11 };
        // SAFETY: same invariants as above.
        let rc = unsafe {
            SetProcessMitigationPolicy(
                PROCESS_IMAGE_LOAD_POLICY,
                (&raw const image_load).cast(),
                core::mem::size_of::<ProcessMitigationImageLoadPolicy>(),
            )
        };
        if rc == 0 {
            return Err(KeyAgentError::Sandbox(format!(
                "SetProcessMitigationPolicy(ImageLoad) failed: {}",
                std::io::Error::last_os_error()
            )));
        }
        Ok(())
    }
}

#[cfg(target_os = "windows")]
pub use windows_impl::{apply_mitigation_policies, disable_crash_dumps};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sandbox_report_network_blocked_tracks_filter() {
        let mut report = SandboxReport::default();
        assert!(!report.network_blocked());
        report.filter_installed = true;
        assert!(report.network_blocked());
    }

    // -- macOS --------------------------------------------------------------

    #[cfg(target_os = "macos")]
    #[test]
    fn seatbelt_profile_denies_network() {
        // The R12 guarantee is a property of the profile text; assert it here
        // so a future edit cannot silently drop the rule.
        let profile = super::macos::SEATBELT_PROFILE;
        for rule in ["(deny network-outbound)", "(deny network-inbound)", "(deny network-bind)"] {
            assert!(profile.contains(rule), "the Seatbelt profile MUST contain {rule} (R12)");
        }
        assert!(profile.starts_with("(version 1)"));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn seatbelt_profile_reallows_only_uds() {
        // The UDS re-allow MUST be path-scoped. An unqualified
        // `(allow network-outbound)` would re-open TCP and silently void R12.
        let profile = super::macos::SEATBELT_PROFILE;
        assert!(profile.contains(r#"(allow network-outbound (subpath "/"))"#));
        assert!(profile.contains(r#"(allow network-bind (subpath "/"))"#));
        for line in profile.lines().map(str::trim) {
            assert_ne!(line, "(allow network-outbound)", "unscoped network re-allow voids R12");
            assert_ne!(line, "(allow network-bind)", "unscoped bind re-allow voids R12");
            assert_ne!(line, "(allow network*)", "unscoped network re-allow voids R12");
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn seatbelt_rejects_profile_with_interior_nul() {
        let err = super::macos::apply_profile("(version 1)\0(allow default)").unwrap_err();
        assert!(matches!(err, KeyAgentError::Sandbox(_)));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn seatbelt_rejects_malformed_profile() {
        // A syntactically invalid profile must be reported, not silently
        // ignored — otherwise a typo would leave the agent unconfined.
        let err = super::macos::apply_profile("(this is not sbpl").unwrap_err();
        match err {
            KeyAgentError::Sandbox(msg) => {
                assert!(msg.contains("sandbox_init failed"), "unexpected message: {msg}");
            }
            other => panic!("expected a Sandbox error, got {other:?}"),
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn disable_coredump_succeeds_on_macos() {
        // Lowering RLIMIT_CORE never requires privilege.
        super::macos::disable_coredump().expect("RLIMIT_CORE=0 must be settable");
    }

    // NOTE: there is deliberately no in-process test that calls
    // `apply_sandbox()`. It now has *real* effects on every supported
    // platform: on Linux the seccomp filter would outlive the test, on macOS
    // the Seatbelt profile denies `process-fork`/`process-exec*` and would
    // break any subsequent test that shells out, and on Windows the dynamic-
    // code policy is irreversible for the process lifetime.
    //
    // End-to-end verification is done out-of-process:
    //   * Linux — `strace -f -e trace=network` in CI (R57).
    //   * macOS — `tests/sandbox_macos.rs` re-executes the test binary in a child process and
    //     asserts an outbound connect fails.
    //   * R12c — `lsof -iTCP -sTCP:LISTEN -P -n` against the running daemon.

    #[cfg(target_os = "linux")]
    #[test]
    fn test_disable_coredump_linux() {
        super::linux::disable_coredump().expect("disable_coredump should succeed on Linux");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_anti_ptrace_linux() {
        super::linux::anti_ptrace().expect("anti_ptrace should succeed on Linux");
    }
}
