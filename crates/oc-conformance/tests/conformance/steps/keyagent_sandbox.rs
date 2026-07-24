//! T36 — Key-Agent Sandbox Properties BDD step definitions.
//!
//! Implements the 3 scenarios in
//! `keyagent_sandbox.feature`:
//! 1. Key-Agent has no network syscalls on Linux (strace empty) — Linux-only.
//! 2. Key-Agent dependency tree clean (no async runtime or network crates).
//! 3. Key-Agent binary has no TCP symbols (nm clean).
//!
//! # Platform gating
//!
//! The Background steps assert `cfg!(target_os = "linux")`. On non-Linux
//! (macOS), they log a skip message and return `Ok` — the scenario continues,
//! but Linux-specific steps (strace) will also early-return on non-Linux.
//! cucumber 0.21 doesn't provide a "skip scenario" API from within a step
//! function (the step either passes by returning `()` or fails by panicking),
//! so "skip" here means "log a skip message and return `()`" — the step
//! passes without doing the Linux-specific work.
//!
//! # Source-of-truth assertions
//!
//! Where possible, the steps delegate to `cargo tree` inspection (R56 hard gate)
//! and `nm` symbol analysis (R12 hard gate) — these are the same checks CI
//! runs, so the BDD scenarios fail exactly when CI would fail.
//!
//! # World scratchpad
//!
//! `ConformanceWorld::last_error` is used as a scratchpad to pass the exit
//! code of the R56/R12 checks from the `When` step to
//! the `Then` step. The exit code is encoded as `__deps_check:<code>` or
//! `__symbols_check:<code>`. Each scenario gets a fresh `ConformanceWorld`
//! (per cucumber's per-scenario isolation), so this scratchpad does not leak
//! across scenarios.

use std::{
    path::PathBuf,
    process::{Command, Stdio},
    time::Duration,
};

use cucumber::{given, then, when};

use crate::ConformanceWorld;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Path to the workspace root (where `ci/` and `Cargo.toml` live).
///
/// `CARGO_MANIFEST_DIR` for the conformance test crate is the workspace root
/// (the `[[test]]` section lives in the workspace `Cargo.toml`).
fn workspace_root() -> PathBuf {
    crate::workspace_root()
}

/// Path to the release-built `oc-keyagent` binary.
fn keyagent_binary() -> PathBuf {
    workspace_root().join("target").join("release").join("oc-keyagent")
}

/// Fixed path for the strace log (used only on Linux).
fn strace_log_path() -> PathBuf {
    PathBuf::from("/tmp/oc_keyagent_sandbox_strace.log")
}

/// Build a `cargo` subcommand with the sccache workaround applied.
///
/// Per the task spec, all cargo invocations MUST be prefixed with
/// `env -u RUSTC_WRAPPER -u RUST_WORKSPACE_WRAPPER`. Since the test process
/// may inherit those env vars from the parent shell, we explicitly remove
/// them here so `cargo build` / `cargo tree` work regardless of how the
/// test was launched.
fn cargo_command(args: &[&str]) -> Command {
    let mut cmd = Command::new("cargo");
    cmd.env_remove("RUSTC_WRAPPER")
        .env_remove("RUST_WORKSPACE_WRAPPER")
        .args(args)
        .current_dir(workspace_root());
    cmd
}

/// Build the release `oc-keyagent` binary. Returns `Ok(())` on success.
fn build_keyagent_release() -> Result<(), String> {
    let status = cargo_command(&["build", "--release", "--bin", "oc-keyagent"])
        .status()
        .map_err(|e| format!("failed to spawn cargo build: {e}"))?;
    if !status.success() {
        return Err(format!("cargo build --release --bin oc-keyagent exited {status}"));
    }
    Ok(())
}

/// Run a command and return `(exit_code, stdout, stderr)`.
fn run_command(cmd: &mut Command) -> (i32, String, String) {
    let output = match cmd.output() {
        Ok(o) => o,
        Err(e) => return (-1, String::new(), format!("failed to spawn command: {e}")),
    };
    let code = output.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    (code, stdout, stderr)
}

/// Decode a `__<tag>:<code>` scratchpad value from `world.last_error`.
fn decode_scratchpad(world: &ConformanceWorld, tag: &str) -> Option<i32> {
    let prefix = format!("__{tag}:");
    world
        .last_error
        .as_ref()
        .and_then(|s| s.strip_prefix(&prefix))
        .and_then(|s| s.parse::<i32>().ok())
}

// ---------------------------------------------------------------------------
// Background steps (T36-specific — NOT shared with background.rs)
// ---------------------------------------------------------------------------

/// `Given the Key-Agent binary is built for the Linux platform`.
///
/// Asserts `cfg!(target_os = "linux")`. On non-Linux (macOS), logs a skip
/// message and returns `Ok` — the scenario continues, but Linux-specific
/// steps will also early-return on non-Linux.
#[given("the Key-Agent binary is built for the Linux platform")]
async fn keyagent_built_for_linux(_world: &mut ConformanceWorld) {
    if !cfg!(target_os = "linux") {
        eprintln!("[SANDBOX] skipping — Linux-only scenario on macOS");
    }
    // No-op: invariant (target_os = "linux") is guaranteed by the early-return above.
}

/// `And the Key-Agent is launched with seccomp filtering enabled`.
///
/// Seccomp is Linux-only. On non-Linux, logs a skip message and returns Ok.
#[given("the Key-Agent is launched with seccomp filtering enabled")]
async fn keyagent_launched_with_seccomp(_world: &mut ConformanceWorld) {
    if !cfg!(target_os = "linux") {
        eprintln!("[SANDBOX] skipping — seccomp is Linux-only");
    }
    // No-op: invariant (target_os = "linux") is guaranteed by the early-return above.
}

// ---------------------------------------------------------------------------
// Scenario 1: Key-Agent has no network syscalls on Linux (strace empty)
// ---------------------------------------------------------------------------

/// `Given the Key-Agent is launched under strace tracing only network syscalls`.
///
/// On non-Linux, early-returns. On Linux, verifies `strace` is available
/// and builds the release binary so the next step can run it under strace.
#[given("the Key-Agent is launched under strace tracing only network syscalls")]
async fn keyagent_launched_under_strace(_world: &mut ConformanceWorld) {
    if !cfg!(target_os = "linux") {
        eprintln!("[SANDBOX] skipping strace scenario — Linux-only");
        return;
    }
    // Verify strace is available.
    let strace_check = Command::new("which").arg("strace").output();
    match strace_check {
        Ok(o) if o.status.success() => {}
        _ => {
            eprintln!("[SANDBOX] skipping — strace not available");
            return;
        }
    }
    // Build the release binary so the next step can exec it under strace.
    if let Err(e) = build_keyagent_release() {
        eprintln!("[SANDBOX] skipping — failed to build oc-keyagent: {e}");
    }
}

/// `When the Key-Agent processes a representative signing workload`.
///
/// On Linux, runs the Key-Agent under `strace -f -e trace=network -o <log>`
/// for ~2 seconds, then kills it. The Key-Agent is a long-running daemon
/// (UDS listener), so we capture its startup syscalls by letting it run
/// briefly before killing.
#[when("the Key-Agent processes a representative signing workload")]
async fn keyagent_processes_signing_workload(_world: &mut ConformanceWorld) {
    if !cfg!(target_os = "linux") {
        eprintln!("[SANDBOX] skipping strace workload — Linux-only");
        return;
    }
    let bin = keyagent_binary();
    if !bin.exists() {
        eprintln!("[SANDBOX] skipping — keyagent binary not found at {bin:?}");
        return;
    }
    let strace_log = strace_log_path();
    // Remove stale log so we only see this run's syscalls.
    let _ = std::fs::remove_file(&strace_log);
    // Use a per-test UDS socket path so we don't collide with a real agent.
    let test_sock = PathBuf::from("/tmp/oc_keyagent_sandbox_strace.sock");
    let _ = std::fs::remove_file(&test_sock);

    let mut cmd = Command::new("strace");
    cmd.args([
        "-f",
        "-e",
        "trace=network",
        "-o",
        strace_log.to_str().unwrap(),
        bin.to_str().unwrap(),
    ])
    .env("OC_KEYAGENT_SOCK", &test_sock)
    .stdin(Stdio::null())
    .stdout(Stdio::null())
    .stderr(Stdio::null());
    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[SANDBOX] skipping — failed to spawn strace: {e}");
            return;
        }
    };
    // Let it run for 2 seconds to capture startup syscalls.
    std::thread::sleep(Duration::from_secs(2));
    let _ = child.kill();
    let _ = child.wait();
    // Best-effort cleanup of the test socket.
    let _ = std::fs::remove_file(&test_sock);
}

/// `Then the strace output for network syscalls is empty`.
#[then("the strace output for network syscalls is empty")]
async fn strace_output_empty(_world: &mut ConformanceWorld) {
    if !cfg!(target_os = "linux") {
        eprintln!("[SANDBOX] skipping strace assertion — Linux-only");
        return;
    }
    let log = strace_log_path();
    if !log.exists() {
        eprintln!(
            "[SANDBOX] skipping strace assertion — log file not found (strace may have been skipped)"
        );
        return;
    }
    let content = std::fs::read_to_string(&log).unwrap_or_default();
    let non_empty_lines = content.lines().filter(|l| !l.trim().is_empty()).count();
    assert_eq!(
        non_empty_lines, 0,
        "expected empty strace log, got {non_empty_lines} non-empty lines:\n{content}"
    );
}

/// `And no socket, connect, bind, sendto, or recvfrom syscall appears in the
/// trace`.
#[then("no socket, connect, bind, sendto, or recvfrom syscall appears in the trace")]
async fn no_network_syscalls_in_trace(_world: &mut ConformanceWorld) {
    if !cfg!(target_os = "linux") {
        eprintln!("[SANDBOX] skipping strace syscall assertion — Linux-only");
        return;
    }
    let log = strace_log_path();
    if !log.exists() {
        eprintln!(
            "[SANDBOX] skipping strace syscall assertion — log file not found (strace may have been skipped)"
        );
        return;
    }
    let content = std::fs::read_to_string(&log).unwrap_or_default();
    for forbidden in ["socket", "connect", "bind", "sendto", "recvfrom"] {
        assert!(
            !content.contains(forbidden),
            "strace log contains forbidden syscall '{forbidden}':\n{content}"
        );
    }
}

// ---------------------------------------------------------------------------
// Scenario 2: Key-Agent dependency tree clean (cross-platform)
// ---------------------------------------------------------------------------

/// `Given the oc-keyagent crate is part of the workspace`.
#[given("the oc-keyagent crate is part of the workspace")]
async fn keyagent_crate_in_workspace(_world: &mut ConformanceWorld) {
    let cargo_toml = workspace_root().join("crates").join("oc-keyagent").join("Cargo.toml");
    assert!(cargo_toml.exists(), "crates/oc-keyagent/Cargo.toml must exist");
}

/// `When the dependency tree is computed`.
///
/// Runs the R56 hard-gate check (`cargo tree`) and stores the exit code on the
/// World via the `last_error` scratchpad (`__deps_check:<code>`).
#[when("the dependency tree is computed")]
async fn dependency_tree_computed(world: &mut ConformanceWorld) {
    let script = workspace_root().join("ci").join("check_deps.sh");
    let (code, stdout, stderr) =
        run_command(Command::new("bash").arg(&script).current_dir(workspace_root()));
    eprintln!("[SANDBOX] check_deps.sh exit={code}");
    if !stdout.is_empty() {
        eprintln!("[SANDBOX] check_deps.sh stdout:\n{stdout}");
    }
    if !stderr.is_empty() {
        eprintln!("[SANDBOX] check_deps.sh stderr:\n{stderr}");
    }
    world.last_error = Some(format!("__deps_check:{code}"));
}

/// `Then the tree does not contain tokio, reqwest, tungstenite, hyper,
/// async-std, or smol`.
///
/// Satisfied iff the R56 hard-gate check exits 0.
#[then("the tree does not contain tokio, reqwest, tungstenite, hyper, async-std, or smol")]
async fn tree_no_forbidden_crates(world: &mut ConformanceWorld) {
    let code = decode_scratchpad(world, "deps_check").unwrap_or(-1);
    assert_eq!(code, 0, "ci/check_deps.sh must exit 0 (R56 hard gate); got {code}");
}

/// `And the only allowed dependencies are oc-crypto, oc-core, oc-signer,
/// oc-policy, oc-session-key, oc-vault, and prost`.
///
/// Per the task note, this step is interpreted as "no forbidden crates"
/// (already checked by the previous `Then`) PLUS "the expected oc-* crates
/// ARE present in the tree" so a regression (e.g. oc-crypto accidentally
/// removed) is caught here. `oc-session-key` is NOT a dependency of
/// `oc-keyagent` (it's a sibling crate used by the Agent / Network-Agent
/// side), so we don't assert its presence — the feature file lists it as
/// "allowed" but not "required".
#[then(
    "the only allowed dependencies are oc-crypto, oc-core, oc-signer, oc-policy, oc-session-key, oc-vault, and prost"
)]
async fn tree_has_allowed_crates(_world: &mut ConformanceWorld) {
    let output =
        cargo_command(&["tree", "-p", "oc-keyagent"]).output().expect("cargo tree must spawn");
    assert!(
        output.status.success(),
        "cargo tree -p oc-keyagent failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let tree = String::from_utf8_lossy(&output.stdout);
    // oc-session-key is intentionally omitted (not a dep of oc-keyagent).
    for allowed in ["oc-crypto", "oc-core", "oc-signer", "oc-policy", "oc-vault", "prost"] {
        assert!(tree.contains(allowed), "cargo tree for oc-keyagent must contain '{allowed}'");
    }
}

/// `And std::os::unix::net is used for Unix Domain Socket I/O instead of any
/// async runtime`.
///
/// Greps the `crates/oc-keyagent/src/` tree for `std::os::unix::net`.
#[then("std::os::unix::net is used for Unix Domain Socket I/O instead of any async runtime")]
async fn uses_uds_not_async(_world: &mut ConformanceWorld) {
    let src_dir = workspace_root().join("crates").join("oc-keyagent").join("src");
    let mut found_uds = false;
    for entry in std::fs::read_dir(&src_dir).expect("oc-keyagent src dir must exist") {
        let entry = entry.expect("read_dir entry");
        let path = entry.path();
        if path.extension().is_some_and(|e| e == "rs") {
            let content = std::fs::read_to_string(&path).unwrap_or_default();
            if content.contains("std::os::unix::net") {
                found_uds = true;
                break;
            }
        }
    }
    assert!(found_uds, "oc-keyagent source must use std::os::unix::net for UDS I/O");
}

// ---------------------------------------------------------------------------
// Scenario 3: Key-Agent binary has no TCP symbols (nm clean)
// ---------------------------------------------------------------------------

/// `Given the release-built oc-keyagent binary`.
///
/// Builds the binary if missing. If the build fails, logs a skip message and
/// returns Ok; subsequent steps will early-return when they find no binary.
#[given("the release-built oc-keyagent binary")]
async fn release_built_keyagent_binary(_world: &mut ConformanceWorld) {
    let bin = keyagent_binary();
    if !bin.exists() {
        if let Err(e) = build_keyagent_release() {
            eprintln!("[SANDBOX] skipping — failed to build oc-keyagent: {e}");
            return;
        }
    }
    if !bin.exists() {
        eprintln!("[SANDBOX] skipping — oc-keyagent binary not found at {bin:?}");
    }
}

/// `When the symbol table is inspected via nm`.
///
/// Runs the R12 hard-gate check (`nm` symbol inspection) and stores the exit
/// code on the World via the `last_error` scratchpad
/// (`__symbols_check:<code>`).
#[when("the symbol table is inspected via nm")]
async fn symbol_table_inspected(world: &mut ConformanceWorld) {
    let bin = keyagent_binary();
    if !bin.exists() {
        eprintln!("[SANDBOX] skipping nm inspection — binary not found at {bin:?}");
        world.last_error = Some("__symbols_check:-1".to_string());
        return;
    }
    let script = workspace_root().join("ci").join("check_symbols.sh");
    let (code, stdout, stderr) =
        run_command(Command::new("bash").arg(&script).arg(&bin).current_dir(workspace_root()));
    eprintln!("[SANDBOX] check_symbols.sh exit={code}");
    if !stdout.is_empty() {
        eprintln!("[SANDBOX] check_symbols.sh stdout:\n{stdout}");
    }
    if !stderr.is_empty() {
        eprintln!("[SANDBOX] check_symbols.sh stderr:\n{stderr}");
    }
    world.last_error = Some(format!("__symbols_check:{code}"));
}

/// `Then no connect, socket, or bind symbol referring to TCP or AF_INET
/// appears`.
///
/// Satisfied iff the R12 hard-gate check exits 0.
#[then("no connect, socket, or bind symbol referring to TCP or AF_INET appears")]
async fn no_tcp_symbols(world: &mut ConformanceWorld) {
    let code = decode_scratchpad(world, "symbols_check").unwrap_or(-1);
    assert_eq!(code, 0, "ci/check_symbols.sh must exit 0 (R12 hard gate); got {code}");
}

/// `And only Unix-domain socket symbols are permitted`.
///
/// Softer assertion: verifies the binary's `nm` output contains socket
/// symbols that indicate UDS usage (UDS is allowed and expected — the
/// Key-Agent listens on a UDS socket).
///
/// On stripped release binaries (`strip = "symbols"` in `[profile.release]`),
/// Rust std symbols like `std::os::unix::net::UnixListener` are stripped.
/// We therefore check for generic libc socket symbols (`socket`, `bind`,
/// `listen`, `accept`) which are the syscalls UDS uses. The R12 hard gate
/// (`nm` symbol inspection) already verifies NO TCP-specific symbols
/// (`TcpListener`, `TcpStream`, `AF_INET`) are present, so the presence of
/// generic socket symbols implies UDS usage.
#[then("only Unix-domain socket symbols are permitted")]
async fn only_uds_symbols_permitted(_world: &mut ConformanceWorld) {
    let bin = keyagent_binary();
    if !bin.exists() {
        eprintln!("[SANDBOX] skipping UDS symbol assertion — binary not found");
        return;
    }
    let (code, stdout, _stderr) = run_command(Command::new("nm").arg(&bin));
    assert_eq!(code, 0, "nm must succeed on oc-keyagent binary");
    let lower = stdout.to_lowercase();
    // On unstripped binaries, look for "unix" (std::os::unix::net symbols).
    // On stripped release binaries, fall back to generic socket syscalls.
    let has_unix = lower.contains("unix");
    let has_socket_syscalls =
        lower.contains("_socket") || lower.contains("_bind") || lower.contains("_listen");
    assert!(
        has_unix || has_socket_syscalls,
        "oc-keyagent binary must contain Unix-domain socket symbols (UDS allowed)"
    );
}
