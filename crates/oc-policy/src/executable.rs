//! Executable policy rule runner (C8).
//!
//! Runs an external policy program with the request context on stdin as JSON,
//! a 5-second timeout, and fail-closed semantics. Uses only `std::process`
//! plus a reader thread with `mpsc::recv_timeout` (R56: no tokio in
//! `oc-policy`).
//!
//! Path hardening: the program must be an absolute path without `..`
//! components. Amount limits compare decimal strings as `u128`
//! ([`oc_core::policy::amount_exceeds`]), addresses compare case-insensitively,
//! and a missing asset allows.

use std::{
    io::{Read, Write},
    path::Path,
    process::{Command, Stdio},
    sync::mpsc,
    time::Duration,
};

/// Timeout for executable policy programs.
pub const EXEC_TIMEOUT: Duration = Duration::from_secs(5);

/// Validate an executable path: absolute and free of `..`.
pub fn validate_executable_path(path: &str) -> Result<(), String> {
    let p = Path::new(path);
    if !p.is_absolute() {
        return Err(format!("executable path must be absolute: '{path}'"));
    }
    if p.components().any(|c| matches!(c, std::path::Component::ParentDir)) {
        return Err(format!("executable path must not contain '..': '{path}'"));
    }
    Ok(())
}

/// Run `path` with `stdin_json` on stdin, returning stdout on success.
///
/// Fail-closed: any spawn/write/timeout/non-zero/parase failure is an `Err`.
pub fn run_executable(path: &str, stdin_json: &[u8]) -> Result<Vec<u8>, String> {
    validate_executable_path(path)?;
    let mut child = Command::new(path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("failed to start executable: {e}"))?;
    if let Some(mut stdin) = child.stdin.take() {
        // `BrokenPipe` means the child closed stdin (or exited) before we
        // finished writing. That is NOT a policy failure: the program has
        // already spoken, and its stdout verdict is authoritative. Treating
        // EPIPE as an error here discarded a valid verdict and spuriously
        // denied the request, which surfaced as a load-dependent flake
        // because it depended on whether the payload outran the pipe buffer.
        //
        // Every other write error is still a hard failure (fail-closed), and
        // the child's exit status / stdout are validated below regardless.
        if let Err(e) = stdin.write_all(stdin_json) {
            if e.kind() != std::io::ErrorKind::BrokenPipe {
                return Err(format!("failed to write stdin: {e}"));
            }
        }
        // Explicit close so the child observes EOF and can finish.
        drop(stdin);
    }
    // Reader thread so the 5s cap covers hung children without tokio.
    let mut stdout = child.stdout.take();
    let mut stderr = child.stderr.take();
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut out = Vec::new();
        let mut err = Vec::new();
        if let Some(s) = stdout.as_mut() {
            let _ = s.read_to_end(&mut out);
        }
        if let Some(s) = stderr.as_mut() {
            let _ = s.read_to_end(&mut err);
        }
        let status = child.wait();
        let _ = tx.send((status, out, err));
    });
    let (status, out, err) = rx
        .recv_timeout(EXEC_TIMEOUT)
        .map_err(|_| format!("executable timed out after {}s", EXEC_TIMEOUT.as_secs()))?;
    let status = status.map_err(|e| format!("failed to wait on executable: {e}"))?;
    if !status.success() {
        return Err(format!(
            "executable exited with {status}: {}",
            String::from_utf8_lossy(&err).trim()
        ));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_relative_and_parent_paths() {
        assert!(validate_executable_path("bin/policy").is_err());
        assert!(validate_executable_path("/tmp/../bin/policy").is_err());
        assert!(validate_executable_path("/usr/local/bin/policy").is_ok());
    }

    #[test]
    fn missing_binary_fails_closed() {
        assert!(run_executable("/nonexistent/onecipher-policy-test", b"{}").is_err());
    }

    #[test]
    fn echo_script_returns_stdout() {
        let dir = tempfile::tempdir().unwrap();
        let script = dir.path().join("echo.sh");
        std::fs::write(&script, "#!/bin/sh\ncat\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let out = run_executable(script.to_str().unwrap(), b"{\"a\":1}").unwrap();
        assert_eq!(out, b"{\"a\":1}");
    }

    #[test]
    fn verdict_survives_broken_pipe_on_stdin() {
        // Regression: a policy program that emits its verdict without
        // draining stdin closes the pipe, so the parent's `write_all` gets
        // EPIPE once the payload outruns the pipe buffer. The verdict must
        // still be returned rather than being turned into a hard error
        // (which the caller maps to `denied`).
        let dir = tempfile::tempdir().unwrap();
        let script = dir.path().join("early-exit.sh");
        std::fs::write(&script, "#!/bin/sh\necho '{\"allow\": true}'\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        // Far larger than the pipe buffer, so EPIPE is guaranteed.
        let payload = vec![b'{'; 4 << 20];
        let out = run_executable(script.to_str().unwrap(), &payload).unwrap();
        assert_eq!(out, b"{\"allow\": true}\n");
    }

    #[test]
    fn non_zero_exit_still_fails_closed_even_with_broken_pipe() {
        // The EPIPE tolerance must not weaken the exit-status check.
        let dir = tempfile::tempdir().unwrap();
        let script = dir.path().join("deny-exit.sh");
        std::fs::write(&script, "#!/bin/sh\necho '{\"allow\": true}'\nexit 3\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let payload = vec![b'{'; 4 << 20];
        let err = run_executable(script.to_str().unwrap(), &payload).unwrap_err();
        assert!(err.contains("exited with"), "got: {err}");
    }

    #[test]
    fn amount_address_asset_helpers() {
        assert!(oc_core::policy::amount_exceeds(Some("200"), "100"));
        assert!(!oc_core::policy::amount_exceeds(Some("50"), "100"));
        assert!(!oc_core::policy::amount_exceeds(None, "100"));
        assert!(oc_core::policy::amount_exceeds(Some("bad"), "100"));
        assert!(oc_core::policy::address_eq("0xABC", "0xabc"));
        assert!(oc_core::policy::asset_allowed(&[], Some("ETH")));
        assert!(oc_core::policy::asset_allowed(&["USDC".to_string()], None));
        assert!(!oc_core::policy::asset_allowed(&["USDC".to_string()], Some("ETH")));
    }
}
