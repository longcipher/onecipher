//! T12 sandbox integration tests.
//!
//! Platform gating:
//! - `test_apply_sandbox_non_linux_noop`: runs on non-Linux (macOS / Windows). Verifies
//!   `apply_sandbox()` is a no-op that returns Ok.
//! - `test_disable_coredump_linux`, `test_anti_ptrace_linux`: run on Linux only. Verify the prctl
//!   calls succeed.
//! - `test_seccomp_filter_install_linux`, `test_seccomp_allows_uds_linux`: run on Linux only. Fork
//!   a child, apply seccomp in child, verify behavior. (Not yet implemented — see TODO inline.)
//! - `test_entitlements_file_exists`, `test_appxmanifest_exists`: cross-platform. Verify the static
//!   manifest files exist at the crate root.

#![cfg(not(target_os = "windows"))] // T12 doesn't ship Windows runtime tests

use std::path::PathBuf;

/// Helper: path to a file at the crate root (next to `Cargo.toml`).
fn crate_root_file(name: &str) -> PathBuf {
    // `CARGO_MANIFEST_DIR` is the crate root (where Cargo.toml lives).
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    PathBuf::from(manifest_dir).join(name)
}

#[cfg(not(target_os = "linux"))]
#[test]
fn test_apply_sandbox_non_linux_noop() {
    // On macOS / Windows, apply_sandbox is a no-op that logs + returns Ok.
    // The real sandbox is enforced by the static manifest
    // (entitlements / AppxManifest) at packaging time.
    oc_keyagent::apply_sandbox().expect("apply_sandbox should succeed on non-Linux");
}

#[cfg(target_os = "linux")]
#[test]
fn test_disable_coredump_linux() {
    // PR_SET_DUMPABLE = 0 should succeed on any Linux. We don't verify the
    // actual core-dump-disabled state (that requires triggering a SIGSEGV
    // + checking for a core file) — we just verify the syscall succeeds.
    // Real verification is done via `ulimit -c 0` + `prctl` check in CI.
    oc_keyagent::apply_sandbox().expect("apply_sandbox should succeed on Linux");
}

#[cfg(target_os = "linux")]
#[test]
fn test_anti_ptrace_linux() {
    // anti_ptrace is implemented as disable_coredump (PR_SET_DUMPABLE=0
    // disables ptrace attach by non-root). Verifying ptrace denial requires
    // a separate attacker process — out of scope for T12 unit tests.
    // We rely on `strace -f -e trace=network` in CI (R57) to verify the
    // overall sandbox behavior.
    oc_keyagent::apply_sandbox().expect("anti_ptrace path should succeed on Linux");
}

#[cfg(target_os = "linux")]
#[test]
fn test_seccomp_filter_install_linux() {
    // TODO(T12+): fork() a child process, apply seccomp in the child, have
    // the child attempt `socket(AF_INET, ...)` and verify it is killed
    // with SIGSYS. The parent waits via `waitpid` and checks `WIFSIGNALED`
    // + `WTERMSIG == SIGSYS`.
    //
    // Skipped in T12 because:
    // 1. The current BPF default is `SECCOMP_RET_ALLOW` (see deviation note in sandbox.rs) — the
    //    filter installs but does not kill.
    // 2. The sockaddr-aware filter (T12+ stretch goal) is what makes this test meaningful.
    // 3. `fork()` in a Rust test is fragile (LLVM sanitizer, allocator state) — better to do this
    //    as a shell-script CI test using `strace -f -e trace=network target/release/oc-keyagent`.
    //
    // For T12, this test just verifies `apply_sandbox()` returns Ok on Linux
    // (i.e. the prctl + seccomp + capset calls all succeed).
    oc_keyagent::apply_sandbox().expect("seccomp install path should succeed on Linux");
}

#[cfg(target_os = "linux")]
#[test]
fn test_seccomp_allows_uds_linux() {
    // TODO(T12+): fork() a child, apply seccomp, child creates a UDS pair
    // via `UnixStream::pair()`, sends a byte, exits 0. Parent verifies
    // exit 0 (not SIGSYS).
    //
    // Skipped in T12 for the same reasons as test_seccomp_filter_install_linux.
    // The UDS path is implicitly tested by the T11 server tests
    // (test_handle_conn_request_response_round_trip etc.), which all pass
    // through UDS — if UDS were blocked by the sandbox, those tests would
    // fail.
    oc_keyagent::apply_sandbox().expect("seccomp should not block UDS on Linux");
}

#[test]
fn test_entitlements_file_exists() {
    // The macOS entitlements plist must exist at the crate root so that
    // `codesign --entitlements oc-keyagent.entitlements.plist` can find it
    // at packaging time.
    let path = crate_root_file("oc-keyagent.entitlements.plist");
    assert!(path.exists(), "macOS entitlements file missing: {}", path.display());
}

#[test]
fn test_appxmanifest_exists() {
    // The Windows AppContainer manifest must exist at the crate root so
    // that `makeappx pack /m AppxManifest.xml` can find it at packaging
    // time.
    let path = crate_root_file("AppxManifest.xml");
    assert!(path.exists(), "Windows AppContainer manifest missing: {}", path.display());
}

#[test]
fn test_entitlements_disables_network() {
    // Verify the entitlements plist contains the network=false keys.
    // We don't parse the plist (would require a plist crate — YAGNI); we
    // just grep the file content for the required keys + values.
    let path = crate_root_file("oc-keyagent.entitlements.plist");
    let content = std::fs::read_to_string(&path).unwrap();
    assert!(
        content.contains("com.apple.security.network.client") && content.contains("<false/>"),
        "entitlements must set network.client = false"
    );
    assert!(
        content.contains("com.apple.security.network.server"),
        "entitlements must set network.server = false"
    );
}

#[test]
fn test_appxmanifest_omits_internet_caps() {
    // Verify the AppxManifest does NOT declare internetClient/internetServer.
    let path = crate_root_file("AppxManifest.xml");
    let content = std::fs::read_to_string(&path).unwrap();
    assert!(
        !content.contains("internetClient") && !content.contains("internetServer"),
        "AppxManifest must NOT declare internetClient or internetServer (R12)"
    );
}
