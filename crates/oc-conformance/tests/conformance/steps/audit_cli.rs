//! T39 — Audit Log CLI BDD step definitions.
//!
//! Implements the 2 scenarios in
//! `audit_cli.feature`:
//! 1. `onecipher audit list --since 24h --agent agent-01` prints only matching entries with all 7
//!    required fields.
//! 2. `onecipher audit list --since 7d --agent agent-02 --status DENIED` further filters by status
//!    and exposes `deny_reason`.
//!
//! # Approach
//! The BDD steps shell out to the `onecipher` debug binary (built on
//! demand via `cargo build --bin onecipher`). The CLI's `audit list`
//! subcommand reads a JSONL audit log file (path overridden via the
//! `OC_AUDIT_LOG` env var) and prints matching entries to stdout. The
//! test captures stdout via `Command::output()` and stashes it in
//! `world.last_error` for the `Then` steps to assert on.
//!
//! # Custom-timestamp entries
//! `AuditLog::append` uses `jiff::Timestamp::now()` for the timestamp, which
//! makes it impossible to test the `--since` filter against historical
//! entries. The `append_entry_with_timestamp` helper constructs an
//! `AuditEntry` with a custom timestamp, signs it with the device key,
//! chains it to the previous entry (correct `prev_hash`), and writes it
//! as one JSONL line. The resulting log passes `verify_chain` (signatures
//! and chain hashes are intact) — only the timestamp differs from what
//! `AuditLog::append` would have produced. This is the only way to test
//! the `--since` filter without sleeping for hours/days.

use std::{
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

use cucumber::{given, then, when};
use ed25519_dalek::{Signature, Signer, SigningKey};
use jiff::{Span, Timestamp};
use oc_keyagent::{AuditEntry, EventType};
use sha2::{Digest, Sha256};
use tempfile::tempdir;

use crate::ConformanceWorld;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Workspace root (resolved via `crate::workspace_root()` helper).
fn workspace_root() -> PathBuf {
    crate::workspace_root()
}

/// Path to the `onecipher` debug binary.
fn onecipher_bin() -> PathBuf {
    workspace_root().join("target").join("debug").join("onecipher")
}

/// Ensure the `onecipher` binary is built and return its path.
///
/// If the binary doesn't exist, invoke `cargo build -p oc-cli` (the
/// `onecipher` bin target lives in the `oc-cli` package). Strips
/// `RUSTC_WRAPPER` / `RUST_WORKSPACE_WRAPPER` from the child env to
/// avoid double-wrapping the compiler during the inner cargo build.
fn ensure_onecipher_built() -> PathBuf {
    let bin = onecipher_bin();
    if bin.exists() {
        return bin;
    }
    eprintln!("[AUDIT-CLI] building onecipher binary...");
    let status = Command::new("cargo")
        .args(["build", "-p", "oc-cli"])
        .env_remove("RUSTC_WRAPPER")
        .env_remove("RUST_WORKSPACE_WRAPPER")
        .status()
        .expect("cargo build -p oc-cli failed to start");
    assert!(status.success(), "cargo build -p oc-cli failed");
    bin
}

/// Compute the canonical bytes of an entry: the entry serialized with
/// `device_sig = ""` using `serde_json::to_vec` (compact, NOT pretty).
///
/// Mirrors the private `canonical_bytes` function in
/// `crates/oc-keyagent/src/audit.rs` — used for BOTH signing and chain
/// hashing. Replicated here because the original is module-private.
fn canonical_bytes(entry: &AuditEntry) -> Vec<u8> {
    let mut copy = entry.clone();
    copy.device_sig = String::new();
    serde_json::to_vec(&copy).expect("AuditEntry is always JSON-serializable")
}

/// Compute `SHA-256(canonical_bytes(entry))` as a lowercase hex string.
///
/// Mirrors the private `hash_entry` function in `audit.rs`.
fn hash_entry(entry: &AuditEntry) -> String {
    let mut hasher = Sha256::new();
    hasher.update(canonical_bytes(entry));
    hex::encode(hasher.finalize())
}

/// State carried across `append_entry_with_timestamp` calls so the chain
/// stays intact (each entry's `prev_hash` references the prior entry's
/// canonical-bytes hash, and `seq` is monotonically increasing).
struct ChainState {
    last_hash: String,
    last_seq: u64,
}

impl ChainState {
    const fn new() -> Self {
        Self { last_hash: String::new(), last_seq: 0 }
    }
}

/// Append a custom-timestamp audit entry to the JSONL log file.
///
/// Constructs an `AuditEntry` with the supplied `timestamp`, signs it
/// with `device_key`, chains it to the previous entry (via
/// `chain.last_hash` / `chain.last_seq`), and writes one JSONL line.
/// Updates `chain` in place so the next call chains correctly.
#[expect(clippy::too_many_arguments)]
fn append_entry_with_timestamp(
    path: &Path,
    device_id: &str,
    device_key: &SigningKey,
    chain: &mut ChainState,
    timestamp: Timestamp,
    event_type: EventType,
    session_key_id: Option<String>,
    payload: serde_json::Value,
) {
    chain.last_seq += 1;
    let entry = AuditEntry {
        device_id: device_id.to_string(),
        seq: chain.last_seq,
        timestamp: timestamp.to_string(),
        event_type,
        session_key_id,
        payload,
        prev_hash: chain.last_hash.clone(),
        device_sig: String::new(),
    };
    let canonical = canonical_bytes(&entry);
    let signature: Signature = device_key.sign(&canonical);
    let mut signed = entry;
    signed.device_sig = hex::encode(signature.to_bytes());
    let line = serde_json::to_string(&signed).expect("serialize AuditEntry");
    let mut file =
        std::fs::OpenOptions::new().append(true).open(path).expect("open audit log for append");
    file.write_all(line.as_bytes()).expect("write audit entry");
    file.write_all(b"\n").expect("write newline");
    chain.last_hash = hash_entry(&signed);
}

/// Run `onecipher audit list` with the given filters, capturing stdout.
///
/// Sets `OC_AUDIT_LOG` on the child process so the CLI reads from the
/// scenario's temp audit log file. Stashes the captured stdout in
/// `world.last_error` for the `Then` steps to assert on. Panics if the
/// CLI exits non-zero (the conformance scenarios require exit 0).
fn run_audit_list_and_capture(
    world: &mut ConformanceWorld,
    since: &str,
    agent: &str,
    status: Option<&str>,
) {
    let bin = ensure_onecipher_built();
    let audit_path =
        world.audit_path.as_ref().expect("audit_path must be set by Background").clone();

    let mut cmd = Command::new(&bin);
    cmd.arg("audit")
        .arg("list")
        .arg("--since")
        .arg(since)
        .arg("--agent")
        .arg(agent)
        .env("OC_AUDIT_LOG", &audit_path)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(s) = status {
        cmd.arg("--status").arg(s);
    }

    let output =
        cmd.output().unwrap_or_else(|e| panic!("onecipher audit list failed to start: {e}"));

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        panic!("onecipher audit list exited {:?} — stderr:\n{}", output.status.code(), stderr);
    }

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    world.last_error = Some(stdout);
}

/// Extract the value of a `key=value` field from a CLI output line.
fn field_value<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    let prefix = format!("{key}=");
    for token in line.split_whitespace() {
        if let Some(rest) = token.strip_prefix(&prefix) {
            return Some(rest);
        }
    }
    None
}

/// Parse the `timestamp=...` field of a CLI output line as RFC 3339.
fn parse_line_timestamp(line: &str) -> Option<Timestamp> {
    let ts = field_value(line, "timestamp")?;
    ts.parse::<Timestamp>().ok()
}

// ---------------------------------------------------------------------------
// Background steps (T39-specific — no conflict with other feature files)
// ---------------------------------------------------------------------------

/// `Given the onecipher CLI is installed and configured to talk to the
/// local daemon`.
///
/// - Ensures the `onecipher` debug binary is built.
/// - Creates a fresh (empty) audit log file in a leaked `TempDir`.
/// - Stashes the path in `world.audit_path` (the CLI reads it via the `OC_AUDIT_LOG` env var, which
///   is set on the child process in `run_audit_list_and_capture`).
/// - Generates a fresh Ed25519 device key for signing audit entries.
#[given("the onecipher CLI is installed and configured to talk to the local daemon")]
async fn cli_installed_configured(world: &mut ConformanceWorld) {
    // Ensure the binary is built (no-op if already built).
    let _ = ensure_onecipher_built();

    // Fresh device key for signing audit entries in this scenario.
    let device_key = SigningKey::generate(&mut rand_core::UnwrapErr(getrandom::SysRng));
    world.device_key = Some(device_key);

    // Fresh audit log file in a leaked TempDir (file survives the
    // scenario's lifetime — same pattern as T22 / T38 / T40).
    let tmp = tempdir().expect("tempdir for audit log");
    let audit_path = tmp.path().join("audit.jsonl");
    std::mem::forget(tmp);
    // Touch the file so the CLI can open it (the CLI treats a missing
    // file as an empty log; we create it explicitly so the
    // per-scenario Given steps can append via OpenOptions::append).
    std::fs::File::create(&audit_path).expect("create audit log file");
    world.audit_path = Some(audit_path);

    // Reset per-scenario state.
    world.last_error = None;
}

/// `And the audit log contains a representative history of Agent
/// operations`.
///
/// No-op: the file is created empty by the preceding Background step.
/// The per-scenario `Given` steps populate it with specific entries
/// (multiple agents, timestamps, statuses). This step exists in the
/// feature file's Background for narrative flow; it does not need to
/// add entries itself.
#[given("the audit log contains a representative history of Agent operations")]
async fn audit_log_representative_history(world: &mut ConformanceWorld) {
    assert!(world.audit_path.is_some(), "audit_path must be set by the preceding Background step");
}

// ---------------------------------------------------------------------------
// Scenario 1: --since 24h --agent agent-01
// ---------------------------------------------------------------------------

/// `Given the audit log contains entries from multiple Agents spanning
/// the last 48 hours`.
///
/// Writes 4 entries with custom timestamps (signed + chained):
/// - agent-01, now-12h, ALLOWED, amount 1.00 (within 24h)
/// - agent-01, now-36h, ALLOWED, amount 2.00 (outside 24h)
/// - agent-02, now-12h, ALLOWED, amount 3.00 (within 24h, wrong agent)
/// - agent-02, now-36h, ALLOWED, amount 4.00 (outside 24h, wrong agent)
///
/// When the CLI filters by `--since 24h --agent agent-01`, only the
/// first entry should be printed.
#[given("the audit log contains entries from multiple Agents spanning the last 48 hours")]
async fn given_entries_multiple_agents_48h(world: &mut ConformanceWorld) {
    let path = world.audit_path.as_ref().expect("audit_path must be set").clone();
    let device_key = world.device_key.as_ref().expect("device_key must be set").clone();
    let mut chain = ChainState::new();
    let now = Timestamp::now();

    // agent-01, now-12h (within 24h) — SHOULD be printed.
    append_entry_with_timestamp(
        &path,
        "agent-01",
        &device_key,
        &mut chain,
        now - Span::new().hours(12),
        EventType::PayX402,
        Some("sk-a1-1".to_string()),
        serde_json::json!({"status": "allowed", "amount_usd": 1.00}),
    );
    // agent-01, now-36h (outside 24h) — should NOT be printed.
    append_entry_with_timestamp(
        &path,
        "agent-01",
        &device_key,
        &mut chain,
        now - Span::new().hours(36),
        EventType::PayX402,
        Some("sk-a1-2".to_string()),
        serde_json::json!({"status": "allowed", "amount_usd": 2.00}),
    );
    // agent-02, now-12h (within 24h, wrong agent) — should NOT be printed.
    append_entry_with_timestamp(
        &path,
        "agent-02",
        &device_key,
        &mut chain,
        now - Span::new().hours(12),
        EventType::PayX402,
        Some("sk-a2-1".to_string()),
        serde_json::json!({"status": "allowed", "amount_usd": 3.00}),
    );
    // agent-02, now-36h (outside 24h, wrong agent) — should NOT be printed.
    append_entry_with_timestamp(
        &path,
        "agent-02",
        &device_key,
        &mut chain,
        now - Span::new().hours(36),
        EventType::PayX402,
        Some("sk-a2-2".to_string()),
        serde_json::json!({"status": "allowed", "amount_usd": 4.00}),
    );
}

/// `When the user runs `onecipher audit list --since 24h --agent
/// agent-01``.
#[when("the user runs `onecipher audit list --since 24h --agent agent-01`")]
async fn when_user_runs_audit_list_scenario1(world: &mut ConformanceWorld) {
    run_audit_list_and_capture(world, "24h", "agent-01", None);
}

/// `Then the CLI prints only entries authored by agent-01`.
#[then("the CLI prints only entries authored by agent-01")]
async fn then_only_agent_01(world: &mut ConformanceWorld) {
    let stdout = world.last_error.as_ref().expect("stdout must be captured by the When step");
    let lines: Vec<&str> = stdout.lines().filter(|l| !l.trim().is_empty()).collect();
    assert!(
        !lines.is_empty(),
        "expected at least one entry for agent-01 within 24h, got empty output"
    );
    for (i, line) in lines.iter().enumerate() {
        let device_id = field_value(line, "device_id").unwrap_or("");
        assert_eq!(
            device_id, "agent-01",
            "line {i} has device_id={device_id:?}, expected \"agent-01\": {line}"
        );
    }
}

/// `And every printed entry has a timestamp within the last 24 hours`.
#[then("every printed entry has a timestamp within the last 24 hours")]
async fn then_timestamps_within_24h(world: &mut ConformanceWorld) {
    let stdout = world.last_error.as_ref().expect("stdout must be captured by the When step");
    let cutoff = Timestamp::now() - Span::new().hours(24);
    for (i, line) in stdout.lines().filter(|l| !l.trim().is_empty()).enumerate() {
        let ts = parse_line_timestamp(line)
            .unwrap_or_else(|| panic!("line {i} has unparseable timestamp: {line}"));
        assert!(
            ts >= cutoff,
            "line {i} timestamp {ts} is older than 24h (cutoff {cutoff}): {line}"
        );
    }
}

/// `And each printed entry shows device_id, seq, timestamp, event_type,
/// session_key_id, status, and amount_usd`.
#[then(
    "each printed entry shows device_id, seq, timestamp, event_type, session_key_id, status, and amount_usd"
)]
async fn then_shows_all_seven_fields(world: &mut ConformanceWorld) {
    let stdout = world.last_error.as_ref().expect("stdout must be captured by the When step");
    let required = [
        "device_id=",
        "seq=",
        "timestamp=",
        "event_type=",
        "session_key_id=",
        "status=",
        "amount_usd=",
    ];
    for (i, line) in stdout.lines().filter(|l| !l.trim().is_empty()).enumerate() {
        for field in &required {
            assert!(line.contains(field), "line {i} missing field {field}: {line}");
        }
    }
}

// ---------------------------------------------------------------------------
// Scenario 2: --since 7d --agent agent-02 --status DENIED
// ---------------------------------------------------------------------------

/// `Given the audit log contains a mix of ALLOWED and DENIED entries from
/// multiple Agents over multiple days`.
///
/// Writes 6 entries with custom timestamps (signed + chained):
/// - agent-01, now-3d, ALLOWED (wrong agent)
/// - agent-01, now-3d, DENIED (wrong agent)
/// - agent-02, now-3d, ALLOWED (wrong status)
/// - agent-02, now-3d, DENIED, deny_reason "RATE_LIMIT_MINUTE" (MATCH)
/// - agent-02, now-10d, DENIED, deny_reason "POLICY_AMOUNT" (outside 7d)
/// - agent-03, now-3d, DENIED, deny_reason "POLICY_AMOUNT" (wrong agent)
///
/// When the CLI filters by `--since 7d --agent agent-02 --status DENIED`,
/// only the 4th entry should be printed.
#[given(
    "the audit log contains a mix of ALLOWED and DENIED entries from multiple Agents over multiple days"
)]
async fn given_mix_allowed_denied_multiple_days(world: &mut ConformanceWorld) {
    let path = world.audit_path.as_ref().expect("audit_path must be set").clone();
    let device_key = world.device_key.as_ref().expect("device_key must be set").clone();
    let mut chain = ChainState::new();
    let now = Timestamp::now();

    // agent-01, now-3d, ALLOWED — wrong agent.
    append_entry_with_timestamp(
        &path,
        "agent-01",
        &device_key,
        &mut chain,
        now - Span::new().days(3),
        EventType::PayX402,
        Some("sk-a1-3d-allowed".to_string()),
        serde_json::json!({"status": "allowed", "amount_usd": 5.00}),
    );
    // agent-01, now-3d, DENIED — wrong agent.
    append_entry_with_timestamp(
        &path,
        "agent-01",
        &device_key,
        &mut chain,
        now - Span::new().days(3),
        EventType::PayX402,
        Some("sk-a1-3d-denied".to_string()),
        serde_json::json!({"status": "denied", "amount_usd": 6.00, "deny_reason": "POLICY_AMOUNT"}),
    );
    // agent-02, now-3d, ALLOWED — wrong status.
    append_entry_with_timestamp(
        &path,
        "agent-02",
        &device_key,
        &mut chain,
        now - Span::new().days(3),
        EventType::PayX402,
        Some("sk-a2-3d-allowed".to_string()),
        serde_json::json!({"status": "allowed", "amount_usd": 7.00}),
    );
    // agent-02, now-3d, DENIED — MATCH (within 7d, right agent, right status).
    append_entry_with_timestamp(
        &path,
        "agent-02",
        &device_key,
        &mut chain,
        now - Span::new().days(3),
        EventType::PayX402,
        Some("sk-a2-3d-denied".to_string()),
        serde_json::json!({"status": "denied", "amount_usd": 8.00, "deny_reason": "RATE_LIMIT_MINUTE"}),
    );
    // agent-02, now-10d, DENIED — outside 7d window.
    append_entry_with_timestamp(
        &path,
        "agent-02",
        &device_key,
        &mut chain,
        now - Span::new().days(10),
        EventType::PayX402,
        Some("sk-a2-10d-denied".to_string()),
        serde_json::json!({"status": "denied", "amount_usd": 9.00, "deny_reason": "POLICY_AMOUNT"}),
    );
    // agent-03, now-3d, DENIED — wrong agent.
    append_entry_with_timestamp(
        &path,
        "agent-03",
        &device_key,
        &mut chain,
        now - Span::new().days(3),
        EventType::PayX402,
        Some("sk-a3-3d-denied".to_string()),
        serde_json::json!({"status": "denied", "amount_usd": 10.00, "deny_reason": "POLICY_AMOUNT"}),
    );
}

/// `When the user runs `onecipher audit list --since 7d --agent agent-02
/// --status DENIED``.
#[when("the user runs `onecipher audit list --since 7d --agent agent-02 --status DENIED`")]
async fn when_user_runs_audit_list_scenario2(world: &mut ConformanceWorld) {
    run_audit_list_and_capture(world, "7d", "agent-02", Some("DENIED"));
}

/// `Then the CLI prints only entries authored by agent-02 within the
/// last 7 days`.
#[then("the CLI prints only entries authored by agent-02 within the last 7 days")]
async fn then_only_agent_02_within_7d(world: &mut ConformanceWorld) {
    let stdout = world.last_error.as_ref().expect("stdout must be captured by the When step");
    let lines: Vec<&str> = stdout.lines().filter(|l| !l.trim().is_empty()).collect();
    assert!(
        !lines.is_empty(),
        "expected at least one DENIED entry for agent-02 within 7d, got empty output"
    );
    let cutoff = Timestamp::now() - Span::new().days(7);
    for (i, line) in lines.iter().enumerate() {
        let device_id = field_value(line, "device_id").unwrap_or("");
        assert_eq!(
            device_id, "agent-02",
            "line {i} has device_id={device_id:?}, expected \"agent-02\": {line}"
        );
        let ts = parse_line_timestamp(line)
            .unwrap_or_else(|| panic!("line {i} has unparseable timestamp: {line}"));
        assert!(ts >= cutoff, "line {i} timestamp {ts} is older than 7d (cutoff {cutoff}): {line}");
    }
}

/// `And every printed entry has status DENIED`.
#[then("every printed entry has status DENIED")]
async fn then_all_status_denied(world: &mut ConformanceWorld) {
    let stdout = world.last_error.as_ref().expect("stdout must be captured by the When step");
    for (i, line) in stdout.lines().filter(|l| !l.trim().is_empty()).enumerate() {
        let status = field_value(line, "status").unwrap_or("");
        assert_eq!(status, "DENIED", "line {i} has status={status:?}, expected \"DENIED\": {line}");
    }
}

/// `And every printed entry exposes its deny_reason`.
#[then("every printed entry exposes its deny_reason")]
async fn then_exposes_deny_reason(world: &mut ConformanceWorld) {
    let stdout = world.last_error.as_ref().expect("stdout must be captured by the When step");
    for (i, line) in stdout.lines().filter(|l| !l.trim().is_empty()).enumerate() {
        let deny_reason = field_value(line, "deny_reason");
        assert!(deny_reason.is_some(), "line {i} missing deny_reason field: {line}");
        let reason = deny_reason.unwrap();
        assert!(
            !reason.is_empty() && reason != "-",
            "line {i} has empty/placeholder deny_reason: {line}"
        );
    }
}

/// `And no entries from other Agents or other time windows appear in the
/// output`.
#[then("no entries from other Agents or other time windows appear in the output")]
async fn then_no_other_agents_or_time_windows(world: &mut ConformanceWorld) {
    let stdout = world.last_error.as_ref().expect("stdout must be captured by the When step");
    let cutoff = Timestamp::now() - Span::new().days(7);
    for (i, line) in stdout.lines().filter(|l| !l.trim().is_empty()).enumerate() {
        let device_id = field_value(line, "device_id").unwrap_or("");
        assert_eq!(device_id, "agent-02", "line {i} leaked entry from agent {device_id:?}: {line}");
        let ts = parse_line_timestamp(line)
            .unwrap_or_else(|| panic!("line {i} has unparseable timestamp: {line}"));
        assert!(
            ts >= cutoff,
            "line {i} leaked entry outside 7d window (ts={ts}, cutoff={cutoff}): {line}"
        );
        let status = field_value(line, "status").unwrap_or("");
        assert_eq!(
            status, "DENIED",
            "line {i} leaked non-DENIED entry (status={status:?}): {line}"
        );
    }
}
