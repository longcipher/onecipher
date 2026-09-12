//! True-binary end-to-end matrix (E1).
//!
//! Drives the real `onecipher` binary (`CARGO_BIN_EXE_onecipher`) through
//! levels L0..L9 in isolated temp `HOME`s. A `BTreeSet` records every level
//! that executed; a missing level fails the run. `STRESS_N` repeats the full
//! matrix (default 1) for soak coverage.
//!
//! English comments only. No network, no daemon: every level is local.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
    process::{Command, Output},
};

/// Expected coverage set: every level must execute.
const EXPECTED: [&str; 10] = ["L0", "L1", "L2", "L3", "L4", "L5", "L6", "L7", "L8", "L9"];

/// Repeat count for the full matrix (`STRESS_N`, default 1).
fn stress_n() -> usize {
    std::env::var("STRESS_N").ok().and_then(|s| s.parse().ok()).unwrap_or(1).max(1)
}

fn bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_onecipher"))
}

/// Run the binary with an isolated `HOME` plus non-interactive guards.
fn run(home: &Path, args: &[&str], stdin: Option<&str>) -> Output {
    let mut cmd = Command::new(bin());
    cmd.args(args).env("HOME", home).env("OC_NONINTERACTIVE", "1").env("ONECIPHER_PASSPHRASE", "");
    if stdin.is_some() {
        cmd.stdin(std::process::Stdio::piped());
    }
    cmd.stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped());
    let mut child = cmd.spawn().expect("spawn onecipher");
    if let Some(text) = stdin {
        use std::io::Write;
        child.stdin.as_mut().expect("piped stdin").write_all(text.as_bytes()).expect("write stdin");
    }
    child.wait_with_output().expect("wait onecipher")
}

fn assert_ok(home: &Path, args: &[&str], stdin: Option<&str>) -> String {
    let out = run(home, args, stdin);
    assert!(
        out.status.success(),
        "L-matrix command failed: onecipher {} (status={}, stderr={})",
        args.join(" "),
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn fresh_home() -> tempfile::TempDir {
    tempfile::tempdir().expect("temp HOME")
}

// --- levels ---------------------------------------------------------------

/// L0: binary meta surface (version/help/completion are always local).
fn l0(home: &Path) {
    assert_ok(home, &["--version"], None);
    assert_ok(home, &["--help"], None);
    assert_ok(home, &["completion", "bash"], None);
}

/// L1: age bootstrap (identity + recipients).
fn l1(home: &Path) {
    assert_ok(home, &["age", "init"], None);
    let out = assert_ok(home, &["age", "recipient", "list"], None);
    assert!(!out.trim().is_empty(), "recipient list must be non-empty after init");
}

/// L2: secret CRUD round-trip via stdin JSON.
fn l2(home: &Path) {
    let payload = r#"{"secret":"matrix-s3cr3t","notes":"e2e"}"#;
    assert_ok(
        home,
        &["secret", "add", "matrix/probe", "--type", "password", "--stdin"],
        Some(payload),
    );
    let got = assert_ok(home, &["secret", "get", "matrix/probe", "--json"], None);
    let v: serde_json::Value = serde_json::from_str(&got).expect("secret get --json");
    let text = v.to_string();
    assert!(text.contains("matrix-s3cr3t"), "stored value must round-trip");
    assert_ok(home, &["secret", "list"], None);
    assert_ok(home, &["secret", "rename", "matrix/probe", "matrix/probe2"], None);
    assert_ok(home, &["secret", "delete", "--force", "matrix/probe2"], None);
}

/// L3: password generation (pure, no store writes).
fn l3(home: &Path) {
    let out = assert_ok(home, &["password", "generate", "--length", "20"], None);
    assert!(out.trim().len() >= 20, "generated password must have requested length");
}

/// L4: TOTP add + code generation (RFC 6238 test vector).
fn l4(home: &Path) {
    assert_ok(
        home,
        &[
            "totp",
            "add",
            "matrix/totp",
            "--secret",
            "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
            "--issuer",
            "matrix",
            "--account",
            "probe",
        ],
        None,
    );
    let code = assert_ok(home, &["totp", "generate", "matrix/totp"], None);
    let digits: String = code.chars().filter(|c| c.is_ascii_digit()).collect();
    assert_eq!(digits.len(), 6, "TOTP code must be 6 digits");
    assert_ok(home, &["totp", "uris", "matrix/totp"], None);
}

/// L5: policy create/list/show/delete round-trip.
fn l5(home: &Path) {
    let policy = serde_json::json!({
        "id": "matrix-policy",
        "name": "Matrix",
        "version": 1,
        "created_at": "2026-01-01T00:00:00Z",
        "rules": [{"type": "allowed_chains", "chain_ids": ["eip155:8453"]}],
        "action": "deny"
    });
    let path = home.join("matrix-policy.json");
    std::fs::write(&path, serde_json::to_string_pretty(&policy).unwrap()).unwrap();
    assert_ok(home, &["policy", "create", "--file", path.to_str().unwrap()], None);
    assert_ok(home, &["policy", "list"], None);
    assert_ok(home, &["policy", "show", "--id", "matrix-policy"], None);
    assert_ok(home, &["policy", "delete", "--id", "matrix-policy", "--confirm"], None);
}

/// L6: doctor (human + JSON dual render).
fn l6(home: &Path) {
    assert_ok(home, &["doctor"], None);
    let out = assert_ok(home, &["doctor", "--json"], None);
    let v: serde_json::Value = serde_json::from_str(&out).expect("doctor --json");
    assert!(v.get("generation_census").is_some(), "doctor JSON must carry generation_census");
    // Repair rebuilds the generations floor from readable secrets.
    assert_ok(home, &["doctor", "--repair-generations"], None);
    let generations_path = home.join(".onecipher/store/generations");
    assert!(generations_path.exists(), "repair must write the generations file");
}

/// L7: audit surfaces (local only).
fn l7(home: &Path) {
    assert_ok(home, &["audit", "list"], None);
    assert_ok(home, &["audit", "secrets", "--skip-hibp", "--format", "json"], None);
}

/// L8: search + integrity surfaces.
fn l8(home: &Path) {
    let payload = r#"{"secret":"findme-123"}"#;
    assert_ok(
        home,
        &["secret", "add", "matrix/findme", "--type", "note", "--stdin"],
        Some(payload),
    );
    assert_ok(home, &["find", "findme", "--json"], None);
    assert_ok(home, &["grep", "findme"], None);
    assert_ok(home, &["fsck"], None);
}

/// L9: wallet + API key lifecycle (key requires at least one wallet).
fn l9(home: &Path) {
    assert_ok(home, &["wallet", "create", "--name", "matrix-w"], None);
    assert_ok(home, &["key", "create", "--name", "matrix-key", "--wallet", "matrix-w"], None);
    let out = assert_ok(home, &["key", "list"], None);
    assert!(out.contains("matrix-key"), "created key must be listed");
}

/// Run the full L0..L9 matrix once, recording coverage.
fn run_matrix_once(home: &Path, covered: &mut BTreeSet<&'static str>) {
    // Order matters: L1 bootstraps age for the secret levels.
    l0(home);
    covered.insert("L0");
    l1(home);
    covered.insert("L1");
    l2(home);
    covered.insert("L2");
    l3(home);
    covered.insert("L3");
    l4(home);
    covered.insert("L4");
    l5(home);
    covered.insert("L5");
    l6(home);
    covered.insert("L6");
    l7(home);
    covered.insert("L7");
    l8(home);
    covered.insert("L8");
    l9(home);
    covered.insert("L9");
}

#[test]
fn e2e_matrix_full_coverage() {
    let n = stress_n();
    for i in 0..n {
        let home = fresh_home();
        let mut covered = BTreeSet::new();
        run_matrix_once(home.path(), &mut covered);
        let expected: BTreeSet<&str> = EXPECTED.into_iter().collect();
        let missing: Vec<&&str> = expected.difference(&covered).collect();
        assert!(
            missing.is_empty(),
            "iteration {i}: matrix coverage missing levels: {missing:?} (covered={covered:?})"
        );
    }
}

// Per-level tests for failure attribution (each self-contained).
#[test]
fn e2e_l0_meta() {
    let home = fresh_home();
    l0(home.path());
}

#[test]
fn e2e_l1_age_bootstrap() {
    let home = fresh_home();
    l1(home.path());
}

#[test]
fn e2e_l2_secret_crud() {
    let home = fresh_home();
    l1(home.path());
    l2(home.path());
}

#[test]
fn e2e_l4_totp() {
    let home = fresh_home();
    l1(home.path());
    l4(home.path());
}

#[test]
fn e2e_l5_policy() {
    let home = fresh_home();
    l5(home.path());
}

#[test]
fn e2e_l6_doctor() {
    let home = fresh_home();
    l1(home.path());
    // Doctor is strict about store/index presence, so stage one secret first.
    let payload = r#"{"secret":"doctor-probe"}"#;
    assert_ok(
        home.path(),
        &["secret", "add", "matrix/probe", "--type", "note", "--stdin"],
        Some(payload),
    );
    l6(home.path());
}
