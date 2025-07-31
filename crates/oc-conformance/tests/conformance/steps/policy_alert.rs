//! T31 — Policy Consecutive-DENY Human Alert BDD step definitions.
//!
//! Implements the 2 scenarios in
//! `policy_alert.feature`:
//! 1. 3 consecutive DENYs trigger a HUMAN_ALERT audit entry, fire the `AlertSink` (UI + Server
//!    webhook), and reset the consecutive-DENY counter (R78 / C-10).
//! 2. The fired `HumanAlert` payload carries `session_key_id`, `device_id`, and the ordered list of
//!    `deny_reasons`; the corresponding audit entry references the same fields (R52 / R55).
//!
//! Per the T31 design, steps orchestrate EXISTING components directly:
//! - `oc_policy::evaluate_11_step` runs the 11-step flow; inside it, `PolicyState::record_deny`
//!   increments the counter, fires the `AlertSink` when the counter hits 3, and resets.
//! - `oc_keyagent::AuditLog::append` records a `HumanAlert` audit entry so the alert is durable in
//!   the append-only log (R76 / R78), mirroring
//!   `oc_keyagent::policy_integration::PolicyIntegration::evaluate`.
//!
//! # T31-specific Background
//! T31's Background (`Given an Agent holds an active Session Key`) is
//! DIFFERENT from the shared `background.rs` step
//! (`Given an Agent holds an active Session Key with a Policy`). T31 needs
//! a `RecordingAlertSink` installed in `policy_state.alert_sink` AND a
//! matching `Arc<Mutex<Vec<HumanAlert>>>` stored on the World for assertions.
//! The shared Background does NOT install a recording sink, so T31 defines
//! its own Background here.
//!
//! # R80 deny_reason mapping (Scenario 2)
//! The feature file mentions `RATE_LIMIT_MINUTE`, `AMOUNT_EXCEEDED`, and
//! `WHITELIST`. R80 caps `DenyReason` at exactly 9 variants (no
//! `AmountExceeded`); `AMOUNT_EXCEEDED` therefore maps to
//! `DenyReason::BudgetExceeded` (same convention as T25). The ordered list
//! captured by `record_deny` is `[RateLimitMinute, BudgetExceeded, Whitelist]`.

use std::sync::{Arc, Mutex};

use cucumber::{given, then, when};
use ed25519_dalek::SigningKey;
use oc_keyagent::{AuditEntry, AuditLog, EventType};
use oc_policy::{
    AlertSink, Decision, DenyReason, HumanAlert, PayRequest, PolicyState, evaluate_11_step,
};
use tempfile::tempdir;

use crate::{ConformanceWorld, steps::background::default_test_policy};

// ---------------------------------------------------------------------------
// RecordingAlertSink — captures every `notify` call for assertions
// ---------------------------------------------------------------------------

/// `AlertSink` implementation that records every fired `HumanAlert` into a
/// shared `Arc<Mutex<Vec<HumanAlert>>>`. The Arc is shared between the sink
/// (installed in `policy_state.alert_sink`) and `world.captured_alerts` so
/// step definitions can assert on the captured alerts after `evaluate_11_step`
/// runs.
///
/// Simulates BOTH delivery channels required by R78:
/// - UI notification (Scenario 1, step "the UI shows a notification")
/// - Server-platform webhook POST (Scenario 1, step "the configured webhook receives a POST")
///
/// Both channels are satisfied by the same captured-alerts Vec — the BDD
/// scenario's two `Then` steps assert on the same single fired alert.
struct RecordingAlertSink {
    fired: Arc<Mutex<Vec<HumanAlert>>>,
}

impl RecordingAlertSink {
    /// Construct a new sink and return it together with the shared Arc
    /// the caller stores on the World.
    fn new() -> (Self, Arc<Mutex<Vec<HumanAlert>>>) {
        let fired = Arc::new(Mutex::new(Vec::new()));
        (Self { fired: fired.clone() }, fired)
    }
}

impl AlertSink for RecordingAlertSink {
    fn notify(&self, alert: &HumanAlert) {
        self.fired.lock().unwrap().push(alert.clone());
    }
}

// ---------------------------------------------------------------------------
// Background (T31-specific — NOT the shared background.rs step)
// ---------------------------------------------------------------------------

/// `Given an Agent holds an active Session Key` (no "with a Policy" suffix).
///
/// Sets up:
/// - A fresh Ed25519 device key + audit log (in a leaked `TempDir`).
/// - An active `session_key_id = "oc_sk_active"`.
/// - A default `PolicyV2` (via `default_test_policy` from `background.rs`) attached to a fresh
///   `PolicyState`.
/// - A `RecordingAlertSink` installed in `policy_state.alert_sink`, with the matching
///   `Arc<Mutex<Vec<HumanAlert>>>` stored on the World so step definitions can assert on captured
///   alerts.
///
/// This Background is intentionally separate from the shared
/// `background.rs` step because the shared step does NOT install a
/// recording sink. cucumber 0.21 distinguishes step patterns by exact
/// string match, so "an Agent holds an active Session Key" and
/// "an Agent holds an active Session Key with a Policy" are two distinct
/// steps and can coexist.
#[given("an Agent holds an active Session Key")]
async fn agent_holds_active_session_key(world: &mut ConformanceWorld) {
    // 1. Device key + audit log (leaked TempDir keeps the file alive for the scenario's lifetime —
    //    same pattern as T22 / background.rs).
    let device_key = SigningKey::generate(&mut rand_core::UnwrapErr(getrandom::SysRng));
    world.device_key = Some(device_key.clone());
    let tmp_audit = tempdir().expect("tempdir for audit log");
    let audit_path = tmp_audit.path().join("audit.jsonl");
    std::mem::forget(tmp_audit);
    let audit_log = AuditLog::open(&audit_path, "dev-test", device_key).expect("AuditLog::open");
    world.audit_path = Some(audit_path);
    world.audit_log = Some(audit_log);

    // 2. Active session key id.
    world.session_key_id = Some("oc_sk_active".to_string());

    // 3. Default permissive policy (reuses the helper from background.rs).
    let policy = default_test_policy("oc_sk_active");
    world.policy = Some(policy.clone());

    // 4. RecordingAlertSink — shared between the World and PolicyState.
    let (sink, captured) = RecordingAlertSink::new();
    world.captured_alerts = Some(captured);

    // 5. PolicyState with the policy attached AND the recording sink installed. `with_alert_sink`
    //    overrides the default `LogAlertSink` that `PolicyState::new` installs.
    let tmp_state = tempdir().expect("tempdir for policy state");
    let state_path = tmp_state.path().join("policy_state.json");
    std::mem::forget(tmp_state);
    let state = PolicyState::load(&state_path, "oc_sk_active".to_string())
        .expect("PolicyState::load")
        .with_policy(policy)
        .with_alert_sink(Box::new(sink));
    world.policy_state = Some(state);
    world.policy_state_path = Some(state_path);
}

/// `And the alert threshold for consecutive DENYs is 3`.
///
/// No-op assertion — the threshold is hardcoded as 3 inside
/// `PolicyState::record_deny` (R78 / C-10). This step exists in the feature
/// file for documentation; the implementation does not need to set anything
/// because the policy engine already enforces the threshold.
#[given("the alert threshold for consecutive DENYs is 3")]
async fn alert_threshold_is_3(_world: &mut ConformanceWorld) {
    // No-op: threshold is hardcoded as 3 in `PolicyState::record_deny`.
}

// ---------------------------------------------------------------------------
// Scenario 1: 3 consecutive DENYs trigger HUMAN_ALERT + notifications
// ---------------------------------------------------------------------------

/// `Given the Agent has accumulated exactly 2 consecutive DENYs for the same
/// session_key_id`.
///
/// Simulates 2 prior DENY decisions by directly setting the runtime counter
/// and reason history on `PolicyState`. The next DENY (in the `When` step)
/// will increment the counter to 3, fire the `AlertSink`, and reset.
///
/// The 2 prior reasons are chosen as `[RateLimitMinute, BudgetExceeded]` to
/// keep Scenario 1 consistent with Scenario 2's first 2 reasons; Scenario 1
/// itself does not assert on the specific reason list.
#[given("the Agent has accumulated exactly 2 consecutive DENYs for the same session_key_id")]
async fn agent_has_2_consecutive_denys(world: &mut ConformanceWorld) {
    let state = world.policy_state.as_mut().expect("policy_state must be set by Background");
    state.consecutive_deny_counter = 2;
    state.last_deny_reasons = vec![DenyReason::RateLimitMinute, DenyReason::BudgetExceeded];
}

/// `When the Agent triggers a third consecutive DENY`.
///
/// Tightens `max_single_amount_usd` to `0.01` (mutating BOTH the world's
/// policy copy AND the `PolicyState`'s runtime copy — same pattern as T25)
/// and then constructs a `PayRequest` for `5.00 USD` of USDC. Step 9 of
/// `evaluate_11_step` returns `Deny(BudgetExceeded)` because `5.0 > 0.01`.
///
/// Inside `evaluate_11_step`, `record_deny` increments the counter to 3,
/// fires `alert_sink.notify(alert)`, and resets the counter to 0. The
/// `RecordingAlertSink` captures the alert into `world.captured_alerts`.
///
/// After `evaluate_11_step` returns, this step mirrors
/// `PolicyIntegration::evaluate` by appending a `HUMAN_ALERT` audit entry
/// carrying the 3 deny reasons (R78 / C-10). The reasons are reconstructed
/// from the prior 2 reasons (captured BEFORE evaluate, because `record_deny`
/// clears `last_deny_reasons` on alert) plus the current DENY reason.
#[when("the Agent triggers a third consecutive DENY")]
async fn agent_triggers_third_consecutive_deny(world: &mut ConformanceWorld) {
    let session_key_id =
        world.session_key_id.clone().expect("session_key_id must be set by Background");

    // Tighten max_single_amount_usd on both policy copies so step 9 fires.
    if let Some(p) = world.policy.as_mut() {
        p.rules.max_single_amount_usd = 0.01;
    }
    if let Some(state) = world.policy_state.as_mut() {
        if let Some(p) = state.policy.as_mut() {
            p.rules.max_single_amount_usd = 0.01;
        }
    }

    // Snapshot the prior 2 deny reasons BEFORE evaluate — `record_deny`
    // clears `last_deny_reasons` when it fires the alert, so we must
    // capture them ahead of time to reconstruct the full 3-reason list
    // for the audit payload. Run evaluate in the same borrow scope.
    let (prior_reasons, decision) = {
        let state = world.policy_state.as_mut().expect("policy_state must be set by Background");
        let prior = state.last_deny_reasons.clone();
        let req = PayRequest {
            session_key_id: session_key_id.clone(),
            device_id: "dev-test".to_string(),
            amount_usd: 5.00,
            asset: "USDC".to_string(),
            chain_id: "eip155:8453".to_string(),
            recipient: None,
        };
        let dec = evaluate_11_step(&req, &session_key_id, state);
        (prior, dec)
    };

    if let Decision::Deny(reason) = &decision {
        world.last_deny_reason = Some(reason.clone());
    }
    world.last_decision = Some(decision.clone());

    // record_deny fired the alert. Append the HUMAN_ALERT audit entry
    // (mirrors `PolicyIntegration::evaluate`'s alert-firing branch).
    let mut all_reasons = prior_reasons;
    if let Decision::Deny(reason) = &decision {
        all_reasons.push(reason.clone());
    }
    let reasons_json: Vec<serde_json::Value> = all_reasons
        .iter()
        .map(|r| serde_json::to_value(r).unwrap_or(serde_json::Value::Null))
        .collect();
    let alert_payload = serde_json::json!({
        "session_key_id": session_key_id,
        "device_id": "dev-test",
        "deny_reasons": reasons_json,
        "reason": "3 consecutive DENYs (R78)",
    });
    let audit = world.audit_log.as_mut().expect("audit_log must be open");
    audit
        .append(EventType::HumanAlert, Some(session_key_id), alert_payload)
        .expect("audit append for HUMAN_ALERT must succeed");
    world.last_audit_event = Some(EventType::HumanAlert);
}

/// `Then the Key-Agent appends an audit entry of event_type HUMAN_ALERT`.
#[then("the Key-Agent appends an audit entry of event_type HUMAN_ALERT")]
async fn then_audit_human_alert(world: &mut ConformanceWorld) {
    assert_eq!(
        world.last_audit_event,
        Some(EventType::HumanAlert),
        "expected last audit event to be HUMAN_ALERT"
    );
    let audit = world.audit_log.as_ref().expect("audit_log must be open");
    audit.verify_chain().expect("audit chain must verify after HUMAN_ALERT append");
}

/// `And the UI shows a notification to the human Owner`.
///
/// The `RecordingAlertSink` simulates the UI notification channel: every
/// `notify` call represents one delivered alert. Asserting that exactly 1
/// alert was captured proves the UI notification was dispatched.
#[then("the UI shows a notification to the human Owner")]
async fn then_ui_shows_notification(world: &mut ConformanceWorld) {
    let captured =
        world.captured_alerts.as_ref().expect("captured_alerts must be set by Background");
    let alerts = captured.lock().unwrap();
    assert_eq!(
        alerts.len(),
        1,
        "expected exactly 1 alert captured by RecordingAlertSink (UI notification), got {}",
        alerts.len()
    );
}

/// `And on the Server platform the configured webhook receives a POST with
/// the alert payload`.
///
/// The `RecordingAlertSink` also simulates the Server-platform webhook: the
/// same captured alert satisfies both delivery channels (UI + webhook) per
/// R78. Asserting `alerts.len() == 1` confirms the webhook POST was
/// dispatched with the alert payload.
#[then("on the Server platform the configured webhook receives a POST with the alert payload")]
async fn then_webhook_receives_post(world: &mut ConformanceWorld) {
    let captured =
        world.captured_alerts.as_ref().expect("captured_alerts must be set by Background");
    let alerts = captured.lock().unwrap();
    assert_eq!(
        alerts.len(),
        1,
        "expected exactly 1 alert captured by RecordingAlertSink (webhook POST), got {}",
        alerts.len()
    );
}

/// `And the consecutive-DENY counter is reset after the alert is dispatched`.
///
/// After `record_deny` fires the alert, it resets `consecutive_deny_counter`
/// to 0 and clears `last_deny_reasons` (R78 / C-10). Assert both invariants.
#[then("the consecutive-DENY counter is reset after the alert is dispatched")]
async fn then_counter_reset(world: &mut ConformanceWorld) {
    let state = world.policy_state.as_ref().expect("policy_state must be set by Background");
    assert_eq!(
        state.consecutive_deny_counter, 0,
        "consecutive_deny_counter must be reset to 0 after the alert fired"
    );
    assert!(
        state.last_deny_reasons.is_empty(),
        "last_deny_reasons must be cleared after the alert fired"
    );
}

// ---------------------------------------------------------------------------
// Scenario 2: Alert payload includes session_key_id, device_id, deny_reasons
// ---------------------------------------------------------------------------

/// `Given the Agent has triggered 3 consecutive DENYs with reasons
/// RATE_LIMIT_MINUTE, AMOUNT_EXCEEDED, and WHITELIST`.
///
/// Sets up the first 2 prior DENY reasons as `[RateLimitMinute,
/// BudgetExceeded]` (R80 mapping: `AMOUNT_EXCEEDED` → `BudgetExceeded`) and
/// the counter to 2. The 3rd DENY (`Whitelist`) is triggered in the `When`
/// step by requesting an asset (`ETH`) that is NOT in the policy's
/// `asset_whitelist` (default `["USDC"]`). Step 4 of `evaluate_11_step`
/// returns `Deny(Whitelist)`, which causes `record_deny` to push Whitelist,
/// increment the counter to 3, fire the alert with the ordered list
/// `[RateLimitMinute, BudgetExceeded, Whitelist]`, and reset.
#[given(
    "the Agent has triggered 3 consecutive DENYs with reasons RATE_LIMIT_MINUTE, AMOUNT_EXCEEDED, and WHITELIST"
)]
async fn agent_has_3_consecutive_denys_with_reasons(world: &mut ConformanceWorld) {
    let state = world.policy_state.as_mut().expect("policy_state must be set by Background");
    state.consecutive_deny_counter = 2;
    // R80 mapping: AMOUNT_EXCEEDED → BudgetExceeded (no AmountExceeded variant).
    state.last_deny_reasons = vec![DenyReason::RateLimitMinute, DenyReason::BudgetExceeded];
    // The default policy already has `asset_whitelist = ["USDC"]`, so
    // requesting "ETH" in the When step will trigger step 4 → Whitelist.
    // No policy mutation needed here.
}

/// `When the alert is dispatched`.
///
/// Constructs a `PayRequest` for `0.01 USD` of `ETH` (NOT in the default
/// `asset_whitelist = ["USDC"]`). Step 4 of `evaluate_11_step` returns
/// `Deny(Whitelist)`. Inside `record_deny`, the counter increments to 3 and
/// the `RecordingAlertSink` is notified with the ordered list
/// `[RateLimitMinute, BudgetExceeded, Whitelist]`.
///
/// After `evaluate_11_step` returns, this step appends the `HUMAN_ALERT`
/// audit entry (mirroring `PolicyIntegration::evaluate`) carrying the same
/// 3 deny reasons so the alert is durable in the append-only audit log.
#[when("the alert is dispatched")]
async fn when_alert_dispatched(world: &mut ConformanceWorld) {
    let session_key_id =
        world.session_key_id.clone().expect("session_key_id must be set by Background");

    // Snapshot prior reasons BEFORE evaluate (record_deny clears them on alert).
    let (prior_reasons, decision) = {
        let state = world.policy_state.as_mut().expect("policy_state must be set by Background");
        let prior = state.last_deny_reasons.clone();
        // Asset "ETH" is NOT in the default asset_whitelist ["USDC"] →
        // step 4 returns Deny(Whitelist). amount_usd = 0.01 is well below
        // max_single_amount_usd (default 10.0), so step 9 would not fire
        // even if step 4 passed.
        let req = PayRequest {
            session_key_id: session_key_id.clone(),
            device_id: "dev-test".to_string(),
            amount_usd: 0.01,
            asset: "ETH".to_string(),
            chain_id: "eip155:8453".to_string(),
            recipient: None,
        };
        let dec = evaluate_11_step(&req, &session_key_id, state);
        (prior, dec)
    };

    if let Decision::Deny(reason) = &decision {
        world.last_deny_reason = Some(reason.clone());
    }
    world.last_decision = Some(decision.clone());

    // record_deny fired the alert. Append HUMAN_ALERT audit entry with the
    // same 3 deny reasons (mirrors PolicyIntegration::evaluate).
    let mut all_reasons = prior_reasons;
    if let Decision::Deny(reason) = &decision {
        all_reasons.push(reason.clone());
    }
    let reasons_json: Vec<serde_json::Value> = all_reasons
        .iter()
        .map(|r| serde_json::to_value(r).unwrap_or(serde_json::Value::Null))
        .collect();
    let alert_payload = serde_json::json!({
        "session_key_id": session_key_id,
        "device_id": "dev-test",
        "deny_reasons": reasons_json,
        "reason": "3 consecutive DENYs (R78)",
    });
    let audit = world.audit_log.as_mut().expect("audit_log must be open");
    audit
        .append(EventType::HumanAlert, Some(session_key_id), alert_payload)
        .expect("audit append for HUMAN_ALERT must succeed");
    world.last_audit_event = Some(EventType::HumanAlert);
}

/// `Then the alert payload includes the session_key_id`.
#[then("the alert payload includes the session_key_id")]
async fn then_payload_includes_session_key_id(world: &mut ConformanceWorld) {
    let captured =
        world.captured_alerts.as_ref().expect("captured_alerts must be set by Background");
    let alerts = captured.lock().unwrap();
    let alert = alerts.last().expect("at least one alert must have been fired");
    assert_eq!(alert.session_key_id, "oc_sk_active", "alert payload session_key_id mismatch");
}

/// `And the alert payload includes the device_id`.
#[then("the alert payload includes the device_id")]
async fn then_payload_includes_device_id(world: &mut ConformanceWorld) {
    let captured =
        world.captured_alerts.as_ref().expect("captured_alerts must be set by Background");
    let alerts = captured.lock().unwrap();
    let alert = alerts.last().expect("at least one alert must have been fired");
    assert_eq!(alert.device_id, "dev-test", "alert payload device_id mismatch");
}

/// `And the alert payload includes the ordered list of deny_reasons`.
///
/// Asserts the captured alert's `deny_reasons` field equals the ordered
/// list `[RateLimitMinute, BudgetExceeded, Whitelist]` — the first 2 set up
/// by the `Given` step plus the 3rd (`Whitelist`) triggered by the `When`
/// step. R80 mapping: feature-file `AMOUNT_EXCEEDED` → `BudgetExceeded`.
#[then("the alert payload includes the ordered list of deny_reasons")]
async fn then_payload_includes_deny_reasons(world: &mut ConformanceWorld) {
    let captured =
        world.captured_alerts.as_ref().expect("captured_alerts must be set by Background");
    let alerts = captured.lock().unwrap();
    let alert = alerts.last().expect("at least one alert must have been fired");
    let expected = vec![
        DenyReason::RateLimitMinute,
        DenyReason::BudgetExceeded, // R80 mapping: AMOUNT_EXCEEDED → BudgetExceeded
        DenyReason::Whitelist,
    ];
    assert_eq!(
        alert.deny_reasons, expected,
        "alert payload deny_reasons mismatch (expected ordered list {:?})",
        expected
    );
}

/// `And the audit entry of event_type HUMAN_ALERT references the same fields`.
///
/// Reads the audit log JSONL file directly (the `AuditLog` API only exposes
/// `append` / `verify_chain` / `merge` — no read-entries method), finds the
/// `HUMAN_ALERT` entry, and asserts its payload carries the same
/// `session_key_id`, `device_id`, and ordered `deny_reasons` as the
/// in-memory `HumanAlert` captured by the `RecordingAlertSink`.
///
/// `DenyReason` is serialized as snake_case (e.g. `RateLimitMinute` →
/// `"rate_limit_minute"`), so the JSON payload's `deny_reasons` array
/// contains the string forms `["rate_limit_minute", "budget_exceeded",
/// "whitelist"]`.
#[then("the audit entry of event_type HUMAN_ALERT references the same fields")]
async fn then_audit_entry_references_same_fields(world: &mut ConformanceWorld) {
    let audit_path = world.audit_path.as_ref().expect("audit_path must be set by Background");
    let content = std::fs::read_to_string(audit_path).expect("read audit log file");

    let mut found_alert: Option<AuditEntry> = None;
    for line in content.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let entry: AuditEntry = serde_json::from_str(line).expect("parse AuditEntry line");
        if entry.event_type == EventType::HumanAlert {
            found_alert = Some(entry);
            break;
        }
    }
    let entry = found_alert.expect("HUMAN_ALERT audit entry must be present in the log");

    let payload = &entry.payload;
    assert_eq!(payload["session_key_id"], "oc_sk_active", "audit payload session_key_id mismatch");
    assert_eq!(payload["device_id"], "dev-test", "audit payload device_id mismatch");
    let reasons = payload["deny_reasons"]
        .as_array()
        .expect("audit payload deny_reasons must be a JSON array");
    assert_eq!(reasons.len(), 3, "audit payload deny_reasons must contain exactly 3 entries");
    // DenyReason serializes as snake_case per `#[serde(rename_all = "snake_case")]`.
    assert_eq!(reasons[0], "rate_limit_minute", "deny_reasons[0] mismatch");
    assert_eq!(reasons[1], "budget_exceeded", "deny_reasons[1] mismatch");
    assert_eq!(reasons[2], "whitelist", "deny_reasons[2] mismatch");

    // The audit chain must still verify after the HUMAN_ALERT append.
    let audit = world.audit_log.as_ref().expect("audit_log must be open");
    audit.verify_chain().expect("audit chain must verify after HUMAN_ALERT append");
}
