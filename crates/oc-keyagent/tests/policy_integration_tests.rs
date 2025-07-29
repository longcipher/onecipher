//! Integration tests for the oc-keyagent PolicyIntegration (T16).
//!
//! Per R29 / R76 / R78 / AD-04. Covers:
//!  - ALLOW resets consecutive deny counter
//!  - DENY increments consecutive deny counter
//!  - 3 consecutive DENYs fire `AlertSink` + write `HUMAN_ALERT` audit entry + reset counter (R78 /
//!    C-10)
//!  - `PolicyState` persists across "restart" (drop + reopen with same state_path) — counters do
//!    NOT reset (R29 CL1 / AD-04 / C-09)
//!  - Audit entry written on ALLOW (status=ALLOWED) (R76 / C-07)
//!  - Audit entry written on DENY (status=DENIED + reason) (R76 / C-07)
//!  - State file has mode 0600 after evaluate (R29 / AD-04)
//!
//! Per R56 / R77: synchronous std only, NO tokio / async.

#![cfg(unix)]

use std::{
    fs,
    os::unix::fs::PermissionsExt,
    sync::{Arc, Mutex},
};

use ed25519_dalek::SigningKey;
use oc_keyagent::{
    audit::{AuditEntry, AuditLog, EventType},
    policy_integration::PolicyIntegration,
};
use oc_policy::{
    AlertSink, BudgetAllocation, Decision, DenyReason, HumanAlert, PayRequest, PolicyRulesV2,
    PolicyV2,
};
/// Generate a fresh Ed25519 signing key (mirrors the helper
/// in `audit_integration.rs`).
fn fresh_key() -> SigningKey {
    SigningKey::generate(&mut rand::rng())
}

/// Mock alert sink that records all notified alerts. Returns the sink
/// paired with an `Arc<Mutex<Vec<HumanAlert>>>` so the test can read the
/// recorded alerts AFTER the sink is moved into `PolicyIntegration`.
struct MockAlertSink {
    fired: Arc<Mutex<Vec<HumanAlert>>>,
}

impl MockAlertSink {
    fn new() -> (Self, Arc<Mutex<Vec<HumanAlert>>>) {
        let fired = Arc::new(Mutex::new(Vec::new()));
        (Self { fired: fired.clone() }, fired)
    }
}

impl AlertSink for MockAlertSink {
    fn notify(&self, alert: &HumanAlert) {
        self.fired.lock().unwrap().push(alert.clone());
    }
}

/// Build a test `PolicyV2` that allows a small USDC payment on base.
fn test_policy() -> PolicyV2 {
    PolicyV2 {
        version: 2,
        session_key_id: "sk-test".into(),
        device_id: "dev-test".into(),
        rules: PolicyRulesV2 {
            max_single_amount_usd: 10.0,
            max_daily_amount_usd: 100.0,
            max_monthly_amount_usd: 1000.0,
            expiry_unix: 999_999_999,
            rate_limit_per_minute: 10,
            rate_limit_per_hour: 100,
            cooldown_after_denial_sec: 0,
            asset_whitelist: vec!["USDC".into()],
            chain_whitelist: vec!["eip155:8453".into()],
            contract_whitelist: vec![],
            payment_protocols: vec!["x402".into()],
        },
        budget_allocation: BudgetAllocation {
            allocated_usd: 50.0,
            allocated_at_unix: 0,
            parent_total_usd: 1000.0,
            parent_session_id: "parent".into(),
        },
    }
}

/// A `PayRequest` that the test policy ALLOWS (5 USDC < 10 max_single,
/// 0 + 5 < 50 allocated, on the asset/chain whitelist).
fn allow_request() -> PayRequest {
    PayRequest {
        session_key_id: "sk-test".into(),
        device_id: "dev-test".into(),
        amount_usd: 5.0,
        asset: "USDC".into(),
        chain_id: "eip155:8453".into(),
        recipient: None,
    }
}

/// A `PayRequest` that the test policy DENIES via single-amount
/// (15 > max_single 10). Per design.md step 9 the deny reason is
/// `DenyReason::Whitelist`.
fn deny_request() -> PayRequest {
    let mut r = allow_request();
    r.amount_usd = 15.0;
    r
}

/// Read all entries from a JSONL audit log file.
fn read_audit(path: &std::path::Path) -> Vec<AuditEntry> {
    let content = fs::read_to_string(path).unwrap();
    content
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str::<AuditEntry>(l).unwrap())
        .collect()
}

/// Open a `PolicyIntegration` with deterministic time
/// (`now_override = 1_000_000` seconds) so rate-limit / cooldown windows
/// behave predictably.
fn open_pi(
    state_path: &std::path::Path,
    audit_path: &std::path::Path,
    policy: Option<PolicyV2>,
    alert_sink: Box<dyn AlertSink>,
) -> PolicyIntegration {
    let audit_log = AuditLog::open(audit_path, "dev-test", fresh_key()).unwrap();
    let audit = Arc::new(Mutex::new(audit_log));
    let mut pi = PolicyIntegration::open(state_path, "sk-test", policy, audit, alert_sink).unwrap();
    pi.state_mut().now_override = Some(1_000_000);
    pi
}

#[test]
fn test_evaluate_allow_resets_deny_counter() {
    let tmp_state = tempfile::tempdir().unwrap();
    let tmp_audit = tempfile::tempdir().unwrap();
    let state_path = tmp_state.path().join("policy.json");
    let audit_path = tmp_audit.path().join("audit.jsonl");

    let (sink, _alerts) = MockAlertSink::new();
    let mut pi = open_pi(&state_path, &audit_path, Some(test_policy()), Box::new(sink));

    // Send 2 DENYs first to bring the counter to 2 (one short of the
    // alert threshold). Then send an ALLOW — the counter MUST reset to 0.
    pi.evaluate(&deny_request(), "sk-test");
    pi.evaluate(&deny_request(), "sk-test");
    assert_eq!(pi.consecutive_deny_counter(), 2);

    let decision = pi.evaluate(&allow_request(), "sk-test");
    assert_eq!(decision, Decision::Allow);
    assert_eq!(pi.consecutive_deny_counter(), 0, "ALLOW must reset the consecutive deny counter");
}

#[test]
fn test_evaluate_deny_increments_counter() {
    let tmp_state = tempfile::tempdir().unwrap();
    let tmp_audit = tempfile::tempdir().unwrap();
    let state_path = tmp_state.path().join("policy.json");
    let audit_path = tmp_audit.path().join("audit.jsonl");

    let (sink, _alerts) = MockAlertSink::new();
    let mut pi = open_pi(&state_path, &audit_path, Some(test_policy()), Box::new(sink));

    assert_eq!(pi.consecutive_deny_counter(), 0);
    let decision = pi.evaluate(&deny_request(), "sk-test");
    // T25 semantic fix: step_9 (single amount) returns BudgetExceeded (not
    // Whitelist — that was a T7 deviation corrected by T25). The deny_request
    // amount (15.0) exceeds max_single_amount_usd (10.0), so this is a single-
    // amount denial.
    assert_eq!(decision, Decision::Deny(DenyReason::BudgetExceeded));
    assert_eq!(
        pi.consecutive_deny_counter(),
        1,
        "DENY must increment the consecutive deny counter"
    );
}

#[test]
fn test_three_consecutive_denys_fire_alert() {
    let tmp_state = tempfile::tempdir().unwrap();
    let tmp_audit = tempfile::tempdir().unwrap();
    let state_path = tmp_state.path().join("policy.json");
    let audit_path = tmp_audit.path().join("audit.jsonl");

    let (sink, alerts) = MockAlertSink::new();
    let mut pi = open_pi(&state_path, &audit_path, Some(test_policy()), Box::new(sink));

    let d1 = pi.evaluate(&deny_request(), "sk-test");
    let d2 = pi.evaluate(&deny_request(), "sk-test");
    let d3 = pi.evaluate(&deny_request(), "sk-test");

    // T25 semantic fix: step_9 (single amount) returns BudgetExceeded (not
    // Whitelist — T7 deviation corrected by T25).
    assert_eq!(d1, Decision::Deny(DenyReason::BudgetExceeded));
    assert_eq!(d2, Decision::Deny(DenyReason::BudgetExceeded));
    assert_eq!(d3, Decision::Deny(DenyReason::BudgetExceeded));

    // Counter reset to 0 after the 3rd DENY (R78 / C-10).
    assert_eq!(
        pi.consecutive_deny_counter(),
        0,
        "counter must reset to 0 after the 3rd consecutive DENY"
    );

    // AlertSink fired exactly once with all 3 deny reasons.
    let alerts_guard = alerts.lock().unwrap();
    assert_eq!(alerts_guard.len(), 1, "AlertSink must fire exactly once");
    assert_eq!(alerts_guard[0].deny_reasons.len(), 3, "alert must carry all 3 deny reasons");
    assert_eq!(alerts_guard[0].session_key_id, "sk-test");
    drop(alerts_guard);

    // Audit log has 3 PayX402 DENY entries + 1 HumanAlert entry.
    let audit = read_audit(&audit_path);
    let human_alerts: Vec<&AuditEntry> =
        audit.iter().filter(|e| e.event_type == EventType::HumanAlert).collect();
    assert_eq!(
        human_alerts.len(),
        1,
        "exactly one HUMAN_ALERT audit entry after 3 consecutive DENYs"
    );
    let pay_x402: Vec<&AuditEntry> =
        audit.iter().filter(|e| e.event_type == EventType::PayX402).collect();
    assert_eq!(pay_x402.len(), 3, "exactly 3 PayX402 audit entries");
}

#[test]
fn test_state_persisted_across_restart() {
    let tmp_state = tempfile::tempdir().unwrap();
    let tmp_audit = tempfile::tempdir().unwrap();
    let state_path = tmp_state.path().join("policy.json");
    let audit_path = tmp_audit.path().join("audit.jsonl");

    // First instance: 2 ALLOWs (local_spent = 10) + 1 DENY (counter = 1).
    let (sink1, _alerts1) = MockAlertSink::new();
    let mut pi1 = open_pi(&state_path, &audit_path, Some(test_policy()), Box::new(sink1));
    pi1.evaluate(&allow_request(), "sk-test"); // local_spent = 5
    pi1.evaluate(&allow_request(), "sk-test"); // local_spent = 10
    pi1.evaluate(&deny_request(), "sk-test"); // counter = 1
    assert_eq!(pi1.consecutive_deny_counter(), 1);
    drop(pi1);

    // Second instance: reopen with the same state_path. Counters MUST
    // be preserved (R29 CL1 / AD-04 / C-09: "A process restart loads
    // PolicyState from disk — counters do NOT reset").
    let (sink2, _alerts2) = MockAlertSink::new();
    let mut pi2 = open_pi(&state_path, &audit_path, Some(test_policy()), Box::new(sink2));
    assert_eq!(pi2.state_mut().local_spent_usd, 10.0, "local_spent_usd must survive a restart");
    assert_eq!(
        pi2.consecutive_deny_counter(),
        1,
        "consecutive_deny_counter must survive a restart"
    );
}

#[test]
fn test_audit_entry_written_on_allow() {
    let tmp_state = tempfile::tempdir().unwrap();
    let tmp_audit = tempfile::tempdir().unwrap();
    let state_path = tmp_state.path().join("policy.json");
    let audit_path = tmp_audit.path().join("audit.jsonl");

    let (sink, _alerts) = MockAlertSink::new();
    let mut pi = open_pi(&state_path, &audit_path, Some(test_policy()), Box::new(sink));

    let decision = pi.evaluate(&allow_request(), "sk-test");
    assert_eq!(decision, Decision::Allow);

    let audit = read_audit(&audit_path);
    let pay_x402: Vec<&AuditEntry> =
        audit.iter().filter(|e| e.event_type == EventType::PayX402).collect();
    assert_eq!(pay_x402.len(), 1, "exactly one PayX402 audit entry on ALLOW");

    let payload = &pay_x402[0].payload;
    assert_eq!(payload["status"], "ALLOWED");
    assert_eq!(payload["session_key_id"], "sk-test");
    assert_eq!(payload["amount_usd"], 5.0);
    assert_eq!(payload["asset"], "USDC");
    assert_eq!(payload["chain_id"], "eip155:8453");
    assert_eq!(payload["deny_reason"], serde_json::Value::Null);
}

#[test]
fn test_audit_entry_written_on_deny() {
    let tmp_state = tempfile::tempdir().unwrap();
    let tmp_audit = tempfile::tempdir().unwrap();
    let state_path = tmp_state.path().join("policy.json");
    let audit_path = tmp_audit.path().join("audit.jsonl");

    let (sink, _alerts) = MockAlertSink::new();
    let mut pi = open_pi(&state_path, &audit_path, Some(test_policy()), Box::new(sink));

    let decision = pi.evaluate(&deny_request(), "sk-test");
    // T25 semantic fix: step_9 (single amount) returns BudgetExceeded (not
    // Whitelist — T7 deviation corrected by T25).
    assert_eq!(decision, Decision::Deny(DenyReason::BudgetExceeded));

    let audit = read_audit(&audit_path);
    let pay_x402: Vec<&AuditEntry> =
        audit.iter().filter(|e| e.event_type == EventType::PayX402).collect();
    assert_eq!(pay_x402.len(), 1, "exactly one PayX402 audit entry on DENY");

    let payload = &pay_x402[0].payload;
    assert_eq!(payload["status"], "DENIED");
    assert_eq!(payload["session_key_id"], "sk-test");
    assert_eq!(payload["amount_usd"], 15.0);
    // DenyReason serializes to snake_case ("budget_exceeded" — T25 fix).
    assert_eq!(
        payload["deny_reason"], "budget_exceeded",
        "deny_reason must be the snake_case DenyReason variant"
    );
}

#[test]
fn test_filesystem_mode_600_on_state_file() {
    let tmp_state = tempfile::tempdir().unwrap();
    let tmp_audit = tempfile::tempdir().unwrap();
    let state_path = tmp_state.path().join("policy.json");
    let audit_path = tmp_audit.path().join("audit.jsonl");

    let (sink, _alerts) = MockAlertSink::new();
    let mut pi = open_pi(&state_path, &audit_path, Some(test_policy()), Box::new(sink));

    // File may not exist yet (no evaluate has run). After one evaluate,
    // `PolicyState::persist` must have written it with 0600.
    pi.evaluate(&allow_request(), "sk-test");

    assert!(state_path.exists(), "state file must exist after evaluate");
    let mode = fs::metadata(&state_path).unwrap().permissions().mode();
    assert_eq!(
        mode & 0o777,
        0o600,
        "state file must have mode 0600 (R29 / AD-04), got {:o}",
        mode & 0o777
    );
}
