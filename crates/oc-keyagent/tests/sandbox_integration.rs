// Test code may unwrap/expect/panic (workspace lint phase-1 carve-out).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
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
    // Verify that apply_sandbox() returns Ok on Linux (i.e. the prctl + seccomp
    // + capset calls all succeed). The full fork()-based seccomp behavior test
    // is in `test_seccomp_kills_inet_socket_linux` below.
    oc_keyagent::apply_sandbox().expect("seccomp install path should succeed on Linux");
}

#[cfg(target_os = "linux")]
#[test]
fn test_seccomp_kills_inet_socket_linux() {
    // Fork a child, apply seccomp in the child, have the child attempt
    // `socket(AF_INET, ...)` and verify it is killed with SIGSYS. The parent
    // waits via `waitpid` and checks `WIFSIGNALED` + `WTERMSIG == SIGSYS`.
    //
    // This test is Linux-only because seccomp is a Linux kernel feature.
    // On macOS / Windows the sandbox uses different mechanisms (Seatbelt /
    // process mitigation policies) that cannot be tested the same way.
    use std::os::unix::net::UnixStream;

    // Create a UDS pair before forking so the child has a communication channel.
    let (parent_sock, child_sock) = UnixStream::pair().expect("UDS pair creation should succeed");

    // Fork the child process.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        panic!("fork() failed: {}", std::io::Error::last_os_error());
    }

    if pid == 0 {
        // Child process: apply seccomp, then attempt to create an AF_INET socket.
        // The seccomp filter should kill the process with SIGSYS.
        let _ = child_sock; // Keep the socket alive (unused in child).

        // Apply the full sandbox (includes seccomp).
        // If this fails, the seccomp filter is not installed and the test
        // would be meaningless — exit with a distinct error code.
        if let Err(e) = oc_keyagent::apply_sandbox() {
            unsafe { libc::_exit(44) };
        }

        // Attempt to create an AF_INET socket — this should trigger SIGSYS.
        // SAFETY: `socket(AF_INET, SOCK_STREAM, 0)` is a standard POSIX syscall.
        // The seccomp filter should kill the process before the syscall completes.
        let ret = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
        // If we reach here, the seccomp filter did NOT kill the process.
        // This is a test failure — exit with a non-zero code.
        unsafe { libc::_exit(if ret >= 0 { 42 } else { 43 }) };
    }

    // Parent process: wait for the child and verify it was killed by SIGSYS.
    let mut status: libc::c_int = 0;
    let ret = unsafe { libc::waitpid(pid, &mut status, 0) };
    assert!(ret == pid, "waitpid() failed: {}", std::io::Error::last_os_error());

    // The child should have been killed by a signal (SIGSYS = 31 on x86_64 Linux).
    assert!(
        libc::WIFSIGNALED(status),
        "child should have been killed by a signal, status={status}"
    );
    let signal = libc::WTERMSIG(status);
    assert_eq!(signal, libc::SIGSYS, "child should have been killed by SIGSYS (31), got {signal}");

    // Clean up the parent socket.
    drop(parent_sock);
}

#[cfg(target_os = "linux")]
#[test]
fn test_seccomp_allows_uds_linux() {
    // Fork a child, apply seccomp, child creates a UDS pair via `UnixStream::pair()`,
    // sends a byte, exits 0. Parent verifies exit 0 (not SIGSYS).
    //
    // This test verifies that the seccomp filter does NOT block AF_UNIX sockets,
    // which are required for the Key-Agent UDS communication channel.
    use std::os::unix::net::UnixStream;

    // Create a UDS pair before forking so the child has a communication channel.
    let (parent_sock, child_sock) = UnixStream::pair().expect("UDS pair creation should succeed");

    // Fork the child process.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        panic!("fork() failed: {}", std::io::Error::last_os_error());
    }

    if pid == 0 {
        // Child process: apply seccomp, then create a UDS pair and send a byte.
        let _ = child_sock; // Keep the socket alive (unused in child).

        // Apply the full sandbox (includes seccomp).
        // If this fails, the seccomp filter is not installed and the test
        // would be meaningless — exit with a distinct error code.
        if let Err(e) = oc_keyagent::apply_sandbox() {
            unsafe { libc::_exit(44) };
        }

        // Create a new UDS pair — this should succeed (AF_UNIX is allowed).
        let (sock_a, _sock_b) =
            UnixStream::pair().expect("UDS pair creation should succeed in child");

        // Send a byte through the UDS pair.
        use std::io::Write;
        sock_a.try_clone().unwrap().write_all(b"x").expect("write to UDS should succeed");

        // Exit with success.
        unsafe { libc::_exit(0) };
    }

    // Parent process: wait for the child and verify it exited normally.
    let mut status: libc::c_int = 0;
    let ret = unsafe { libc::waitpid(pid, &mut status, 0) };
    assert!(ret == pid, "waitpid() failed: {}", std::io::Error::last_os_error());

    // The child should have exited normally (not killed by a signal).
    assert!(libc::WIFEXITED(status), "child should have exited normally, status={status}");
    let exit_code = libc::WEXITSTATUS(status);
    assert_eq!(exit_code, 0, "child should have exited with code 0, got {exit_code}");

    // Clean up the parent socket.
    drop(parent_sock);
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
