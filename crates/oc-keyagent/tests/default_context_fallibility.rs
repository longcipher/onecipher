// Test code may unwrap/expect/panic (workspace lint phase-1 carve-out).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! M-07 regression test: [`default_context`] initialization failure must be
//! reported as `Err` with the cause attached — never as a panic inside the
//! signing thread.
//!
//! The default context lives in a process-wide `OnceLock`, so this scenario
//! cannot be exercised reliably in-process (other tests may have initialized
//! it first). Instead, the parent test re-executes this very test binary as a
//! child process with a marker env var set and `HOME` removed, guaranteeing a
//! cold `OnceLock` and a broken-HOME environment.
//!
//! Per R56 these tests are synchronous (no tokio / reqwest / hyper).

use std::process::Command;

/// Marker that switches the re-exec'd binary into child mode.
const CHILD_MARKER: &str = "OC_KEYAGENT_BROKEN_HOME_CHILD";

/// Name of the child-mode test (passed via `--exact`).
const CHILD_TEST: &str = "broken_home_child_reports_err";

#[test]
fn broken_home_parent_spawns_cold_child() {
    if std::env::var_os(CHILD_MARKER).is_some() {
        // Child mode reached through the normal test run (marker set by the
        // parent below) — nothing to do here; the child test drives itself.
        return;
    }

    let exe = std::env::current_exe().expect("locate current test binary");
    let output = Command::new(exe)
        .args(["--exact", CHILD_TEST, "--test-threads=1"])
        .env(CHILD_MARKER, "1")
        .env_remove("HOME")
        .output()
        .expect("spawn child test process");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!stderr.contains("panicked"), "child panicked instead of returning Err:\n{stderr}");
    assert!(
        output.status.success(),
        "child test should pass when dispatch returns Err cleanly\nstdout:\n{}\nstderr:\n{stderr}",
        String::from_utf8_lossy(&output.stdout)
    );
}

#[test]
fn broken_home_child_reports_err() {
    if std::env::var_os(CHILD_MARKER).is_none() {
        // Parent mode: skip silently — the parent drives this test via
        // re-exec with HOME removed and the marker set.
        return;
    }

    assert!(std::env::var_os("HOME").is_none(), "child must run with HOME removed");

    // Any request kind works: dispatch consults default_context() before
    // matching, so ListWallets is enough to trigger initialization.
    let req = oc_keyagent::KeyAgentRequest {
        kind: Some(oc_keyagent::KeyAgentRequestKind::ListWallets(oc_keyagent::proto::Empty {})),
    };
    match oc_keyagent::handler::dispatch(&req) {
        Err(oc_keyagent::KeyAgentError::Internal(msg)) => assert!(
            msg.contains("failed to initialize agent context"),
            "cause must be attached to the error, got: {msg}"
        ),
        other => panic!("expected Err(KeyAgentError::Internal), got: {other:?}"),
    }
}
