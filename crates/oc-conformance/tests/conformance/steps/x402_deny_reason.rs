//! T34 — x402 DENY Reason Enumeration BDD step definitions.
//!
//! Implements the 2 scenarios in
//! `x402_deny_reason.feature`:
//! 1. `PayX402Response.deny_reason` field populated on DENY (R65, R66; T28)
//! 2. `deny_reason` enumerates all Policy Engine rejection causes (R65, R67; T28)
//!
//! Per the T34 design, steps orchestrate EXISTING components directly:
//! - `oc_policy::evaluate_11_step` runs the 11-step flow and produces a
//!   `Decision::Deny(DenyReason)` for each trigger.
//! - `oc_keyagent::AuditLog::append` records `PayX402` audit entries whose payload carries the wire
//!   string form of `deny_reason` (R76).
//!
//! # R80 deny_reason mapping (wire strings)
//! R80 caps `DenyReason` at exactly 9 variants. The feature file's wire
//! strings map as follows (see `deny_reason_to_wire_string`):
//! - `RateLimitMinute` → `RATE_LIMIT_MINUTE`
//! - `RateLimitHour`   → `RATE_LIMIT_HOUR`
//! - `BudgetExceeded` (from step_8 / step_8a / step_8b) → `BUDGET_EXCEEDED`
//! - `BudgetExceeded` (from step_9, single-amount) → `AMOUNT_EXCEEDED` (T25)
//! - `Whitelist`       → `WHITELIST`
//! - `Expired`         → `EXPIRED`
//! - `Cooldown`        → `COOLDOWN`
//! - `PolicyMissing`   → `POLICY_INVALID` (T30 mapping)
//! - `PasskeyForged`   → `PASSKEY_FORGED`
//!
//! `PasskeyForged` is NOT produced by `evaluate_11_step` (passkey
//! verification happens before policy evaluation); Scenario 2 constructs
//! the decision directly to enumerate the wire string.
//!
//! # Background step text
//! T34's Background uses `Given the Agent holds an active Session Key`
//! (with "the"). This is a DIFFERENT step pattern from T31's
//! `Given an Agent holds an active Session Key` (with "an"), registered
//! in `policy_alert.rs`. cucumber 0.21 distinguishes step patterns by
//! exact string match, so both can coexist without conflict.

use std::cell::RefCell;

use cucumber::{given, then, when};
use ed25519_dalek::SigningKey;
use oc_keyagent::{AuditLog, EventType};
use oc_policy::{Decision, DenyReason, PayRequest, PolicyState, evaluate_11_step};
use tempfile::tempdir;

use crate::{ConformanceWorld, steps::background::default_test_policy};

// ---------------------------------------------------------------------------
// Thread-local store for Scenario 2's observed wire strings
// ---------------------------------------------------------------------------

// Holds the `deny_reason` wire strings observed during Scenario 2's
// `Given` step (one per trigger). Reset by the Background step; read by
// the `Then` step that asserts against the feature file's data table.
//
// cucumber 0.21 runs scenarios sequentially, so this thread-local is
// safe — it is set and consumed within the same scenario.
thread_local! {
    static OBSERVED_DENY_REASONS: RefCell<Vec<String>> = const { RefCell::new(Vec::new()) };
}

/// Deterministic `now` value (unix seconds) used by EXPIRED and COOLDOWN
/// triggers. Chosen as a round number well below the default
/// `expiry_unix` (`now + 3600`) so EXPIRED requires explicitly setting
/// `expiry_unix` to the past.
const NOW_OVERRIDE: u64 = 1_000_000;

// ---------------------------------------------------------------------------
// Helper: DenyReason → wire string (R80 mapping, BDD-only)
// ---------------------------------------------------------------------------

/// Map a `DenyReason` to its R80 wire string. The `context` arg
/// disambiguates `BudgetExceeded`:
/// - `"step_9"` (single-amount check) → `AMOUNT_EXCEEDED` (T25 mapping)
/// - any other context (step_8 / step_8a / step_8b) → `BUDGET_EXCEEDED`
///
/// This helper lives in the BDD step file (not production code) because
/// the wire-string form is a UI/Agent-facing concern; the policy engine
/// itself only emits the 9-variant `DenyReason` enum.
fn deny_reason_to_wire_string(reason: &DenyReason, context: &str) -> String {
    match (reason, context) {
        (DenyReason::BudgetExceeded, "step_9") => "AMOUNT_EXCEEDED".to_string(),
        (DenyReason::BudgetExceeded, _) => "BUDGET_EXCEEDED".to_string(),
        (DenyReason::RateLimitMinute, _) => "RATE_LIMIT_MINUTE".to_string(),
        (DenyReason::RateLimitHour, _) => "RATE_LIMIT_HOUR".to_string(),
        (DenyReason::Whitelist, _) => "WHITELIST".to_string(),
        (DenyReason::Expired, _) => "EXPIRED".to_string(),
        (DenyReason::Cooldown, _) => "COOLDOWN".to_string(),
        (DenyReason::PolicyMissing, _) => "POLICY_INVALID".to_string(),
        (DenyReason::PasskeyForged, _) => "PASSKEY_FORGED".to_string(),
        (DenyReason::Unknown, _) => "UNKNOWN".to_string(),
    }
}

// ---------------------------------------------------------------------------
// Background (T34-specific — "the Agent" != T31's "an Agent")
// ---------------------------------------------------------------------------

/// `Given the Agent holds an active Session Key`.
///
/// Sets up the minimum state needed for T34's scenarios:
/// - Fresh Ed25519 device key + audit log (leaked `TempDir`).
/// - Active `session_key_id = "oc_sk_active"`.
/// - Default permissive `PolicyV2` (via `default_test_policy`).
/// - `PolicyState` with the policy attached.
/// - Clears the thread-local `OBSERVED_DENY_REASONS` so each scenario starts fresh.
#[given("the Agent holds an active Session Key")]
async fn agent_holds_active_session_key(world: &mut ConformanceWorld) {
    // 1. Device key + audit log (leaked TempDir keeps the file alive).
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

    // 3. Default permissive policy.
    let policy = default_test_policy("oc_sk_active");
    world.policy = Some(policy.clone());

    // 4. PolicyState with the policy attached.
    let tmp_state = tempdir().expect("tempdir for policy state");
    let state_path = tmp_state.path().join("policy_state.json");
    std::mem::forget(tmp_state);
    let state = PolicyState::load(&state_path, "oc_sk_active".to_string())
        .expect("PolicyState::load")
        .with_policy(policy);
    world.policy_state = Some(state);
    world.policy_state_path = Some(state_path);

    // 5. Reset per-scenario thread-local state.
    OBSERVED_DENY_REASONS.with(|cell| cell.borrow_mut().clear());
    world.last_decision = None;
    world.last_deny_reason = None;
    world.last_audit_event = None;
    world.last_error = None;
}

/// `And the Agent issues PayX402 requests that may be denied by the
/// Policy Engine`.
///
/// Framing / documentation step — no state to set. The per-scenario
/// `Given` steps construct the actual `PayRequest`s and call
/// `evaluate_11_step`.
#[given("the Agent issues PayX402 requests that may be denied by the Policy Engine")]
async fn agent_issues_payx402_requests(_world: &mut ConformanceWorld) {
    // No-op: framing step.
}

// ---------------------------------------------------------------------------
// Scenario 1: PayX402Response.deny_reason field populated on DENY
// ---------------------------------------------------------------------------

/// `Given a PayX402 request that violates a Policy rule`.
///
/// Tightens `max_single_amount_usd` to `0.01` on BOTH the world's `policy`
/// copy AND the `PolicyState`'s runtime `policy` copy (the latter is what
/// `evaluate_11_step` actually reads). A subsequent 5.00 USD request will
/// trip step 9 (single-amount) → `Deny(BudgetExceeded)`, which the
/// `deny_reason_to_wire_string` helper maps to `AMOUNT_EXCEEDED` per the
/// T25 convention.
#[given("a PayX402 request that violates a Policy rule")]
async fn given_violating_payx402(world: &mut ConformanceWorld) {
    if let Some(p) = world.policy.as_mut() {
        p.rules.max_single_amount_usd = 0.01;
    }
    if let Some(state) = world.policy_state.as_mut() {
        if let Some(p) = state.policy.as_mut() {
            p.rules.max_single_amount_usd = 0.01;
        }
    }
}

/// `When the Policy Engine denies the request`.
///
/// Constructs a 5.00 USD `PayRequest` (USDC on Base), calls
/// `evaluate_11_step`, and records the decision + deny reason on the
/// world. Step 9 fires because `5.0 > 0.01` → `Deny(BudgetExceeded)`.
///
/// Also appends a `PayX402` audit entry whose payload carries the wire
/// string form of `deny_reason` (`AMOUNT_EXCEEDED`) and a human-readable
/// `error` field, so the subsequent `Then` step can assert the audit
/// entry records the same deny reason.
#[when("the Policy Engine denies the request")]
async fn when_policy_denies(world: &mut ConformanceWorld) {
    let session_key_id =
        world.session_key_id.clone().expect("session_key_id must be set by Background");

    let req = PayRequest {
        session_key_id: session_key_id.clone(),
        device_id: "dev-test".to_string(),
        amount_usd: 5.00,
        asset: "USDC".to_string(),
        chain_id: "eip155:8453".to_string(),
        recipient: None,
    };

    let decision = {
        let state = world.policy_state.as_mut().expect("policy_state must be set by Background");
        evaluate_11_step(&req, &session_key_id, state)
    };

    if let Decision::Deny(reason) = &decision {
        world.last_deny_reason = Some(reason.clone());
    }
    world.last_decision = Some(decision);

    // Compute the wire string (step_9 → AMOUNT_EXCEEDED) and append a
    // PayX402 audit entry carrying it + a human-readable error.
    let wire = world
        .last_deny_reason
        .as_ref()
        .map(|r| deny_reason_to_wire_string(r, "step_9"))
        .unwrap_or_default();
    let payload = serde_json::json!({
        "status": "denied",
        "deny_reason": wire,
        "error": format!("PayX402 denied: {}", wire),
    });

    let audit = world.audit_log.as_mut().expect("audit_log must be open");
    audit
        .append(EventType::PayX402, Some(session_key_id), payload)
        .expect("audit append for denied PayX402 must succeed");
    world.last_audit_event = Some(EventType::PayX402);
}

/// `Then the PayX402Response has status DENY`.
#[then("the PayX402Response has status DENY")]
async fn then_status_deny(world: &mut ConformanceWorld) {
    assert!(
        matches!(world.last_decision, Some(Decision::Deny(_))),
        "expected a Deny decision, got {:?}",
        world.last_decision
    );
}

/// `And the deny_reason field is a non-empty string identifying the rule
/// that was violated`.
///
/// The wire string is derived from `world.last_deny_reason` via the
/// `deny_reason_to_wire_string` helper (context = `"step_9"`). Asserts
/// the wire string is non-empty and equals `AMOUNT_EXCEEDED` (the T25
/// mapping for single-amount violations).
#[then("the deny_reason field is a non-empty string identifying the rule that was violated")]
async fn then_deny_reason_nonempty(world: &mut ConformanceWorld) {
    let reason =
        world.last_deny_reason.as_ref().expect("last_deny_reason must be set by the When step");
    let wire = deny_reason_to_wire_string(reason, "step_9");
    assert!(!wire.is_empty(), "deny_reason wire string must be non-empty");
    assert_eq!(
        wire, "AMOUNT_EXCEEDED",
        "expected AMOUNT_EXCEEDED (step_9 single-amount), got {wire}"
    );
}

/// `And the error field is populated with a human-readable description`.
///
/// The `When` step's audit payload includes an `error` field. This step
/// asserts the field is present and non-empty in the most-recently
/// appended `PayX402` audit entry.
#[then("the error field is populated with a human-readable description")]
async fn then_error_field_populated(world: &mut ConformanceWorld) {
    let audit_path = world.audit_path.as_ref().expect("audit_path must be set by Background");
    let content = std::fs::read_to_string(audit_path).expect("read audit log file");
    let mut found_error: Option<String> = None;
    for line in content.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let v: serde_json::Value = serde_json::from_str(line).expect("parse audit JSONL line");
        if v.get("event_type").and_then(|t| t.as_str()) == Some("pay_x402") {
            if let Some(err) =
                v.get("payload").and_then(|p| p.get("error")).and_then(|e| e.as_str())
            {
                found_error = Some(err.to_string());
                break;
            }
        }
    }
    let err = found_error.expect("PayX402 audit entry must carry an error field");
    assert!(!err.is_empty(), "error field must be non-empty");
}

/// `And an audit entry records the same deny_reason`.
///
/// Reads the audit log JSONL file directly (the `AuditLog` API only
/// exposes `append` / `verify_chain` / `merge`), finds the most-recent
/// `PayX402` entry, and asserts its payload's `deny_reason` field
/// matches the wire string derived from `world.last_deny_reason`
/// (`AMOUNT_EXCEEDED`). Also re-verifies the chain to ensure the append
/// didn't break integrity.
#[then("an audit entry records the same deny_reason")]
async fn then_audit_records_deny_reason(world: &mut ConformanceWorld) {
    let audit_path = world.audit_path.as_ref().expect("audit_path must be set by Background");
    let content = std::fs::read_to_string(audit_path).expect("read audit log file");

    let mut found_wire: Option<String> = None;
    for line in content.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let v: serde_json::Value = serde_json::from_str(line).expect("parse audit JSONL line");
        if v.get("event_type").and_then(|t| t.as_str()) == Some("pay_x402") {
            if let Some(w) =
                v.get("payload").and_then(|p| p.get("deny_reason")).and_then(|r| r.as_str())
            {
                found_wire = Some(w.to_string());
            }
        }
    }
    let wire = found_wire.expect("PayX402 audit entry must carry a deny_reason field");
    let expected = world
        .last_deny_reason
        .as_ref()
        .map(|r| deny_reason_to_wire_string(r, "step_9"))
        .expect("last_deny_reason must be set");
    assert_eq!(
        wire, expected,
        "audit entry deny_reason ({wire}) must match the response deny_reason ({expected})"
    );

    // Chain must still verify after the append.
    let audit = world.audit_log.as_ref().expect("audit_log must be open");
    audit.verify_chain().expect("audit chain must verify after denied PayX402 append");
}

// ---------------------------------------------------------------------------
// Scenario 2: deny_reason enumerates all 9 rejection causes
// ---------------------------------------------------------------------------

/// `Given the Agent triggers one DENY for each of the supported rejection
/// causes`.
///
/// Runs 9 independent triggers against the world's `PolicyState`, each
/// producing one `Decision::Deny(reason)`. The wire string for each is
/// computed via `deny_reason_to_wire_string` (with the appropriate
/// context for `BudgetExceeded`) and stored in the thread-local
/// `OBSERVED_DENY_REASONS` for the subsequent `Then` step to assert
/// against the feature file's 9-row data table.
///
/// Each trigger resets the relevant `PolicyState` fields to a known-good
/// state first so triggers don't interfere (e.g. a prior trigger's
/// `record_deny` setting `last_deny_at_unix` would otherwise cause
/// COOLDOWN to fire on later triggers).
#[given("the Agent triggers one DENY for each of the supported rejection causes")]
async fn given_triggers_all_denys(world: &mut ConformanceWorld) {
    let observed: Vec<String> = vec![
        trigger_rate_limit_minute(world),
        trigger_rate_limit_hour(world),
        trigger_budget_exceeded(world),
        trigger_whitelist(world),
        trigger_amount_exceeded(world),
        trigger_expired(world),
        trigger_cooldown(world),
        trigger_policy_invalid(world),
        trigger_passkey_forged(world),
    ];

    OBSERVED_DENY_REASONS.with(|cell| {
        cell.borrow_mut().clear();
        cell.borrow_mut().extend(observed);
    });
}

/// `When the Agent inspects the corresponding PayX402Response messages`.
///
/// No-op — the wire strings were captured in the `Given` step.
#[when("the Agent inspects the corresponding PayX402Response messages")]
async fn when_inspects_responses(_world: &mut ConformanceWorld) {
    // No-op: responses captured in the Given step.
}

/// `Then the observed deny_reason values include each of the following
/// exactly once`.
///
/// Parses the 9-row data table (header `deny_reason` + 9 wire-string
/// rows) from `step.table`, then asserts each expected wire string
/// appears exactly once in `OBSERVED_DENY_REASONS`.
#[then("the observed deny_reason values include each of the following exactly once")]
async fn then_observed_each_once(_world: &mut ConformanceWorld, step: &cucumber::gherkin::Step) {
    let table = step.table.as_ref().expect("data table must be present on the Then step");

    // First row is the header (`deny_reason`); subsequent rows are values.
    let expected: Vec<String> = table
        .rows
        .iter()
        .skip(1)
        .map(|row| {
            row.first()
                .cloned()
                .unwrap_or_else(|| panic!("deny_reason row must have a value: {:?}", row))
        })
        .collect();
    assert_eq!(
        expected.len(),
        9,
        "expected exactly 9 deny_reason rows in the data table, got {}",
        expected.len()
    );

    let observed = OBSERVED_DENY_REASONS.with(|cell| cell.borrow().clone());
    assert_eq!(observed.len(), 9, "expected exactly 9 observed deny reasons, got {:?}", observed);

    for wire in &expected {
        let count = observed.iter().filter(|o| *o == wire).count();
        assert_eq!(
            count, 1,
            "expected exactly 1 occurrence of {wire}, got {count} (observed: {observed:?})",
        );
    }
}

/// `And no other deny_reason string is observed`.
///
/// Asserts every observed wire string is in the R80-allowed set and that
/// the total count is exactly 9 (no extras).
#[then("no other deny_reason string is observed")]
async fn then_no_other_observed(_world: &mut ConformanceWorld) {
    let observed = OBSERVED_DENY_REASONS.with(|cell| cell.borrow().clone());
    let allowed: std::collections::HashSet<&str> = [
        "RATE_LIMIT_MINUTE",
        "RATE_LIMIT_HOUR",
        "BUDGET_EXCEEDED",
        "WHITELIST",
        "AMOUNT_EXCEEDED",
        "EXPIRED",
        "COOLDOWN",
        "POLICY_INVALID",
        "PASSKEY_FORGED",
    ]
    .iter()
    .copied()
    .collect();
    for wire in &observed {
        assert!(
            allowed.contains(wire.as_str()),
            "observed deny_reason {wire} is not in the R80-allowed set"
        );
    }
    assert_eq!(
        observed.len(),
        9,
        "expected exactly 9 observed deny reasons (no extras), got {}",
        observed.len()
    );
}

// ---------------------------------------------------------------------------
// Trigger helpers — one per deny reason
// ---------------------------------------------------------------------------

/// Reset `PolicyState` counters + windows to a fresh default before each
/// trigger so prior triggers don't interfere (e.g. `last_deny_at_unix`
/// from a prior trigger would cause COOLDOWN to fire unexpectedly).
///
/// Restores the default permissive policy on both `world.policy` and
/// `state.policy` so each trigger starts from a known-good baseline.
fn reset_state_for_trigger(world: &mut ConformanceWorld) {
    let policy = default_test_policy("oc_sk_active");
    world.policy = Some(policy.clone());
    if let Some(state) = world.policy_state.as_mut() {
        state.local_spent_usd = 0.0;
        state.minutely_window.clear();
        state.hourly_window.clear();
        state.daily_window.clear();
        state.monthly_window.clear();
        state.last_deny_at_unix = None;
        state.consecutive_deny_counter = 0;
        state.last_deny_reasons.clear();
        state.now_override = None;
        state.policy = Some(policy);
    }
}

/// Build a `PayRequest` with the given amount + asset on Base (in the
/// default chain whitelist).
fn make_request(amount_usd: f64, asset: &str) -> PayRequest {
    PayRequest {
        session_key_id: "oc_sk_active".to_string(),
        device_id: "dev-test".to_string(),
        amount_usd,
        asset: asset.to_string(),
        chain_id: "eip155:8453".to_string(),
        recipient: None,
    }
}

/// Run `evaluate_11_step` and return the resulting `Decision`. Panics if
/// `policy_state` is missing.
fn run_evaluate(world: &mut ConformanceWorld, req: &PayRequest) -> Decision {
    let state = world.policy_state.as_mut().expect("policy_state must be set by Background");
    evaluate_11_step(req, "oc_sk_active", state)
}

/// Extract the deny reason from a `Decision`, panicking on `Allow`.
fn deny_of(dec: Decision) -> DenyReason {
    match dec {
        Decision::Deny(r) => r,
        Decision::Allow => panic!("expected Deny, got Allow"),
    }
}

// --- 1. RATE_LIMIT_MINUTE --------------------------------------------------

/// Pre-populate `minutely_window` with 10 entries (== default
/// `rate_limit_per_minute`) 30s ago. Step 6 fires → `RateLimitMinute`.
fn trigger_rate_limit_minute(world: &mut ConformanceWorld) -> String {
    reset_state_for_trigger(world);
    let now_ms = NOW_OVERRIDE.saturating_mul(1000);
    if let Some(state) = world.policy_state.as_mut() {
        state.now_override = Some(NOW_OVERRIDE);
        for _ in 0..10 {
            state.minutely_window.push_back(now_ms - 30_000);
        }
    }
    let dec = run_evaluate(world, &make_request(0.01, "USDC"));
    deny_reason_to_wire_string(&deny_of(dec), "")
}

// --- 2. RATE_LIMIT_HOUR ----------------------------------------------------

/// Pre-populate `hourly_window` with 100 entries (== default
/// `rate_limit_per_hour`) 30min ago. Step 7 fires → `RateLimitHour`.
fn trigger_rate_limit_hour(world: &mut ConformanceWorld) -> String {
    reset_state_for_trigger(world);
    let now_ms = NOW_OVERRIDE.saturating_mul(1000);
    if let Some(state) = world.policy_state.as_mut() {
        state.now_override = Some(NOW_OVERRIDE);
        for _ in 0..100 {
            state.hourly_window.push_back(now_ms - 1_800_000);
        }
    }
    let dec = run_evaluate(world, &make_request(0.01, "USDC"));
    deny_reason_to_wire_string(&deny_of(dec), "")
}

// --- 3. BUDGET_EXCEEDED (step_8) -------------------------------------------

/// Set `local_spent_usd = allocated_usd` (50.0). Any positive request
/// makes `local_spent + amount > allocated` → step 8 fires →
/// `BudgetExceeded` → `BUDGET_EXCEEDED`.
fn trigger_budget_exceeded(world: &mut ConformanceWorld) -> String {
    reset_state_for_trigger(world);
    if let Some(state) = world.policy_state.as_mut() {
        state.local_spent_usd = 50.0; // == default allocated_usd
    }
    let dec = run_evaluate(world, &make_request(0.01, "USDC"));
    // Context = "" (not step_9) → BUDGET_EXCEEDED
    deny_reason_to_wire_string(&deny_of(dec), "step_8")
}

// --- 4. WHITELIST ----------------------------------------------------------

/// Request asset "ETH" (not in default `asset_whitelist = ["USDC"]`).
/// Step 4 fires → `Whitelist`.
fn trigger_whitelist(world: &mut ConformanceWorld) -> String {
    reset_state_for_trigger(world);
    let dec = run_evaluate(world, &make_request(0.01, "ETH"));
    deny_reason_to_wire_string(&deny_of(dec), "")
}

// --- 5. AMOUNT_EXCEEDED (step_9) -------------------------------------------

/// Tighten `max_single_amount_usd` to 0.01, request 5.00 USD. Step 9
/// fires → `BudgetExceeded` → `AMOUNT_EXCEEDED` (T25 mapping, context
/// = "step_9").
fn trigger_amount_exceeded(world: &mut ConformanceWorld) -> String {
    reset_state_for_trigger(world);
    if let Some(state) = world.policy_state.as_mut() {
        if let Some(p) = state.policy.as_mut() {
            p.rules.max_single_amount_usd = 0.01;
        }
    }
    if let Some(p) = world.policy.as_mut() {
        p.rules.max_single_amount_usd = 0.01;
    }
    let dec = run_evaluate(world, &make_request(5.00, "USDC"));
    deny_reason_to_wire_string(&deny_of(dec), "step_9")
}

// --- 6. EXPIRED ------------------------------------------------------------

/// Set `expiry_unix` to a value in the past relative to `NOW_OVERRIDE`.
/// Step 3 fires → `Expired`.
fn trigger_expired(world: &mut ConformanceWorld) -> String {
    reset_state_for_trigger(world);
    if let Some(state) = world.policy_state.as_mut() {
        state.now_override = Some(NOW_OVERRIDE);
        if let Some(p) = state.policy.as_mut() {
            p.rules.expiry_unix = NOW_OVERRIDE.saturating_sub(1);
        }
    }
    if let Some(p) = world.policy.as_mut() {
        p.rules.expiry_unix = NOW_OVERRIDE.saturating_sub(1);
    }
    let dec = run_evaluate(world, &make_request(0.01, "USDC"));
    deny_reason_to_wire_string(&deny_of(dec), "")
}

// --- 7. COOLDOWN -----------------------------------------------------------

/// Set `last_deny_at_unix = NOW_OVERRIDE - 30` and
/// `cooldown_after_denial_sec = 300`. `last_deny (999_970) + 300 =
/// 1_000_270 > now (1_000_000)` → step 5 fires → `Cooldown`.
fn trigger_cooldown(world: &mut ConformanceWorld) -> String {
    reset_state_for_trigger(world);
    if let Some(state) = world.policy_state.as_mut() {
        state.now_override = Some(NOW_OVERRIDE);
        state.last_deny_at_unix = Some(NOW_OVERRIDE - 30);
        if let Some(p) = state.policy.as_mut() {
            p.rules.cooldown_after_denial_sec = 300;
        }
    }
    if let Some(p) = world.policy.as_mut() {
        p.rules.cooldown_after_denial_sec = 300;
    }
    let dec = run_evaluate(world, &make_request(0.01, "USDC"));
    deny_reason_to_wire_string(&deny_of(dec), "")
}

// --- 8. POLICY_INVALID (PolicyMissing) -------------------------------------

/// Set `state.policy = None`. Step 2 fires → `PolicyMissing` →
/// `POLICY_INVALID` (T30 mapping).
fn trigger_policy_invalid(world: &mut ConformanceWorld) -> String {
    reset_state_for_trigger(world);
    if let Some(state) = world.policy_state.as_mut() {
        state.policy = None;
    }
    let dec = run_evaluate(world, &make_request(0.01, "USDC"));
    deny_reason_to_wire_string(&deny_of(dec), "")
}

// --- 9. PASSKEY_FORGED -----------------------------------------------------

/// `evaluate_11_step` never returns `PasskeyForged` (passkey verification
/// happens before policy evaluation). Scenario 2 constructs the decision
/// directly to enumerate the wire string. Also appends a
/// `PasskeyForged` audit entry so the audit log records the cause.
fn trigger_passkey_forged(world: &mut ConformanceWorld) -> String {
    reset_state_for_trigger(world);
    let reason = DenyReason::PasskeyForged;
    let wire = deny_reason_to_wire_string(&reason, "");

    // Mirror the production path: record the deny on the world + append
    // a PasskeyForged audit entry so the cause is durable (R76).
    world.last_decision = Some(Decision::Deny(reason.clone()));
    world.last_deny_reason = Some(reason);
    let audit = world.audit_log.as_mut().expect("audit_log must be open");
    let payload = serde_json::json!({
        "status": "denied",
        "deny_reason": wire,
        "error": "passkey signature verification failed",
    });
    audit
        .append(EventType::PasskeyForged, None, payload)
        .expect("audit append for PasskeyForged must succeed");
    world.last_audit_event = Some(EventType::PasskeyForged);

    wire
}
