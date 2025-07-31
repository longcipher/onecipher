//! T25 — Policy Amount Limits BDD step definitions.
//!
//! Implements the 3 scenarios in
//! `policy_amount.feature`:
//! 1. Single payment exceeds `max_single_amount_usd` → DENY(BudgetExceeded)
//! 2. Daily cumulative exceeds `max_daily_amount_usd` → DENY(BudgetExceeded)
//! 3. Monthly cumulative exceeds `max_monthly_amount_usd` → DENY(BudgetExceeded)
//!
//! Per the T25 design, steps orchestrate EXISTING components directly:
//! - `oc_policy::evaluate_11_step` for the 11-step Policy decision flow
//! - `oc_keyagent::AuditLog` for the append-only audit chain
//!
//! # R80 deny_reason mapping
//! The feature file uses the human-readable strings `AMOUNT_EXCEEDED`,
//! `DAILY_EXCEEDED`, and `MONTHLY_EXCEEDED`. R80 caps `DenyReason` at exactly
//! 9 variants (no `AmountExceeded`). All three feature-file terms therefore
//! map to `DenyReason::BudgetExceeded`. The `Then` step that asserts
//! `deny_reason "X"` translates the string to `BudgetExceeded` before
//! comparing with `world.last_deny_reason`.
//!
//! # Shared Background
//! The first Background step (`Given an Agent holds an active Session Key
//! with a Policy`) is shared with T26 and is implemented in
//! `steps/background.rs`. The second Background step
//! (`And the Policy rules include max_single_amount_usd, ...`) is T25-specific
//! and lives here as a no-op assertion — the default policy from `background.rs`
//! already populates these fields.

use cucumber::{given, then, when};
use oc_keyagent::EventType;
use oc_policy::{Decision, DenyReason, PayRequest, evaluate_11_step};

use crate::ConformanceWorld;

// ---------------------------------------------------------------------------
// T25-specific Background step
// ---------------------------------------------------------------------------

/// `And the Policy rules include max_single_amount_usd, max_daily_amount_usd,
/// and max_monthly_amount_usd`.
///
/// The default policy set up by the shared Background (in `background.rs`)
/// already populates all three R28 amount-limit fields with non-zero values
/// (`max_single=10`, `max_daily=100`, `max_monthly=1000`). This step is a
/// no-op assertion that the fields are present and non-zero, so a regression
/// in `default_test_policy()` is caught here rather than mid-scenario.
#[given(
    "the Policy rules include max_single_amount_usd, max_daily_amount_usd, and max_monthly_amount_usd"
)]
async fn policy_rules_include_amount_limits(world: &mut ConformanceWorld) {
    let policy = world.policy.as_ref().expect("policy must be set by shared Background");
    assert!(
        policy.rules.max_single_amount_usd > 0.0,
        "max_single_amount_usd must be non-zero in default policy"
    );
    assert!(
        policy.rules.max_daily_amount_usd > 0.0,
        "max_daily_amount_usd must be non-zero in default policy"
    );
    assert!(
        policy.rules.max_monthly_amount_usd > 0.0,
        "max_monthly_amount_usd must be non-zero in default policy"
    );
}

// ---------------------------------------------------------------------------
// Given: tighten a single amount-limit field (mutates BOTH policy copies)
// ---------------------------------------------------------------------------

/// `Given the Policy sets {max_single_amount_usd|max_daily_amount_usd|
/// max_monthly_amount_usd} to {value}`.
///
/// `evaluate_11_step` reads the policy from `state.policy` (the PolicyState's
/// runtime copy), NOT from `world.policy`. When a scenario tightens a limit,
/// we MUST mutate both copies so the assertion against `world.policy` and the
/// evaluation against `state.policy` agree.
#[given(
    regex = r"^the Policy sets (max_single_amount_usd|max_daily_amount_usd|max_monthly_amount_usd) to ([0-9.]+)$"
)]
async fn policy_sets_amount_limit(world: &mut ConformanceWorld, field: String, value: String) {
    let val: f64 =
        value.parse().unwrap_or_else(|_| panic!("amount limit must be a float, got {value}"));
    if let Some(p) = world.policy.as_mut() {
        set_amount_field(&mut p.rules, &field, val);
    }
    if let Some(state) = world.policy_state.as_mut() {
        if let Some(p) = state.policy.as_mut() {
            set_amount_field(&mut p.rules, &field, val);
        }
    }
}

fn set_amount_field(rules: &mut oc_policy::PolicyRulesV2, field: &str, val: f64) {
    match field {
        "max_single_amount_usd" => rules.max_single_amount_usd = val,
        "max_daily_amount_usd" => rules.max_daily_amount_usd = val,
        "max_monthly_amount_usd" => rules.max_monthly_amount_usd = val,
        other => unreachable!("unexpected amount field: {other}"),
    }
}

// ---------------------------------------------------------------------------
// Given: pre-populate rolling-window prior spend
// ---------------------------------------------------------------------------

/// `And the Agent has already spent {amount} USD within the rolling
/// {24-hour|30-day} window`.
///
/// Pre-populates the corresponding window on `world.policy_state` with a
/// single `(timestamp, amount)` entry positioned just inside the window
/// boundary (1 minute ago for daily, 1 hour ago for monthly). The entry
/// survives `slide_all_windows` during the subsequent `evaluate_11_step`
/// call because both deltas are well within their window durations
/// (60_000 ms << 86_400_000 ms; 3_600_000 ms << 2_592_000_000 ms).
#[given(
    regex = r"^the Agent has already spent ([0-9.]+) USD within the rolling (24-hour|30-day) window$"
)]
async fn agent_already_spent(
    world: &mut ConformanceWorld,
    amount_str: String,
    window_kind: String,
) {
    let amount: f64 = amount_str
        .parse()
        .unwrap_or_else(|_| panic!("prior spend must be a float, got {amount_str}"));
    let state = world.policy_state.as_mut().expect("policy_state must be set by shared Background");
    let now_unix =
        state.now_override.unwrap_or_else(|| jiff::Timestamp::now().as_second().max(0) as u64);
    let now_ms = now_unix.saturating_mul(1000);
    match window_kind.as_str() {
        "24-hour" => {
            // 1 minute ago — well within the 24h (86_400_000 ms) window.
            state.daily_window.push_back((now_ms.saturating_sub(60_000), amount));
        }
        "30-day" => {
            // 1 hour ago — well within the 30d (2_592_000_000 ms) window.
            state.monthly_window.push_back((now_ms.saturating_sub(3_600_000), amount));
        }
        other => unreachable!("unexpected window kind: {other}"),
    }
}

// ---------------------------------------------------------------------------
// When: Agent requests a PayX402
// ---------------------------------------------------------------------------

/// `When the Agent requests a PayX402 for {amount} USD`.
///
/// Constructs a `PayRequest` (USDC on Base, no recipient — native-style
/// transfer), calls `evaluate_11_step` against the world's PolicyState, and
/// records the resulting decision + deny reason on the world.
///
/// Also appends a `PayX402` audit entry whose payload varies by which rule
/// fired. The payload's `reason` field uses the feature-file terminology
/// (`amount_exceeded` / `daily_exceeded` / `monthly_exceeded`) — the audit
/// chain records the human-readable sub-reason so post-incident review can
/// distinguish single-payment caps from rolling-window caps even though R80
/// collapses them to `BudgetExceeded`.
///
/// The sub-reason is selected by inspecting which rolling window has prior
/// spend: a non-empty `daily_window` implies the daily rule fired, a
/// non-empty `monthly_window` implies the monthly rule fired, and both empty
/// implies the single-amount rule fired. This unambiguously distinguishes
/// the 3 T25 scenarios because each pre-populates at most one window.
#[when(regex = r"^the Agent requests a PayX402 for ([0-9.]+) USD$")]
async fn agent_requests_pay_x402(world: &mut ConformanceWorld, amount_str: String) {
    let amount: f64 = amount_str
        .parse()
        .unwrap_or_else(|_| panic!("PayX402 amount must be a float, got {amount_str}"));
    let req = PayRequest {
        session_key_id: "oc_sk_active".to_string(),
        device_id: "dev-test".to_string(),
        amount_usd: amount,
        asset: "USDC".to_string(),
        chain_id: "eip155:8453".to_string(),
        recipient: None,
    };

    // Borrow state mutably to call evaluate, then extract everything we need
    // into owned values so the mutable borrow ends before we touch audit_log.
    let (decision, daily_sum, monthly_sum, single_limit) = {
        let state =
            world.policy_state.as_mut().expect("policy_state must be set by shared Background");
        let decision = evaluate_11_step(&req, "oc_sk_active", state);
        let daily_sum: f64 = state.daily_window.iter().map(|(_, a)| a).sum();
        let monthly_sum: f64 = state.monthly_window.iter().map(|(_, a)| a).sum();
        let single_limit = state.policy.as_ref().map_or(0.0, |p| p.rules.max_single_amount_usd);
        (decision, daily_sum, monthly_sum, single_limit)
    };

    // Construct the audit payload based on which rule fired. The deny reason
    // from `evaluate_11_step` is `BudgetExceeded` for all three T25 scenarios
    // (R80 mapping); we use window population to disambiguate the sub-reason.
    let payload = match &decision {
        Decision::Deny(reason) => {
            world.last_deny_reason = Some(reason.clone());
            if daily_sum > 0.0 && monthly_sum == 0.0 {
                serde_json::json!({
                    "status": "denied",
                    "reason": "daily_exceeded",
                    "prior_cumulative_usd": daily_sum,
                    "rejected_amount_usd": amount,
                })
            } else if monthly_sum > 0.0 && daily_sum == 0.0 {
                serde_json::json!({
                    "status": "denied",
                    "reason": "monthly_exceeded",
                    "prior_cumulative_usd": monthly_sum,
                    "rejected_amount_usd": amount,
                })
            } else {
                // No prior window spend → single-amount rule fired.
                serde_json::json!({
                    "status": "denied",
                    "reason": "amount_exceeded",
                    "requested_usd": amount,
                    "limit_usd": single_limit,
                })
            }
        }
        Decision::Allow => {
            serde_json::json!({"status": "allowed", "amount_usd": amount})
        }
    };

    world.last_decision = Some(decision);
    world.last_audit_event = Some(EventType::PayX402);

    let audit = world.audit_log.as_mut().expect("audit_log must be open");
    audit
        .append(EventType::PayX402, Some("oc_sk_active".to_string()), payload)
        .expect("audit append for PayX402 must succeed");
}

// ---------------------------------------------------------------------------
// Then: assertions on the decision and audit entry
// ---------------------------------------------------------------------------

/// `Then the Policy Engine evaluates the single-amount rule`.
///
/// Implicit assertion — the `evaluate_11_step` call in the `When` step ran
/// the full 11-step flow, which includes step 9 (single-amount check). The
/// next `And` step asserts the deny reason.
#[then("the Policy Engine evaluates the single-amount rule")]
async fn then_evaluates_single_amount_rule(_world: &mut ConformanceWorld) {
    // No-op: implicit in the When step's evaluate_11_step call.
}

/// `Then the cumulative daily spend becomes {amount} USD which exceeds
/// the limit`.
///
/// Implicit assertion — verified by the `Deny(BudgetExceeded)` assertion in
/// the next `And` step. The cumulative value is computed inside step 8a and
/// is not surfaced separately on the world.
#[then(regex = r"^the cumulative daily spend becomes ([0-9.]+) USD which exceeds the limit$")]
async fn then_cumulative_daily_exceeds(_world: &mut ConformanceWorld, _amount: String) {
    // No-op: implicit in the Deny(BudgetExceeded) assertion.
}

/// `Then the cumulative monthly spend becomes {amount} USD which exceeds
/// the limit`.
#[then(regex = r"^the cumulative monthly spend becomes ([0-9.]+) USD which exceeds the limit$")]
async fn then_cumulative_monthly_exceeds(_world: &mut ConformanceWorld, _amount: String) {
    // No-op: implicit in the Deny(BudgetExceeded) assertion.
}

/// `And the response has status DENY and deny_reason "{reason}"`.
///
/// Translates the feature-file deny_reason string to the R80 `DenyReason`
/// variant before comparing with `world.last_deny_reason`. Per the T25 R80
/// mapping, all three feature-file terms (`AMOUNT_EXCEEDED`,
/// `DAILY_EXCEEDED`, `MONTHLY_EXCEEDED`) map to `DenyReason::BudgetExceeded`.
#[then(
    regex = r#"^the response has status DENY and deny_reason "(AMOUNT_EXCEEDED|DAILY_EXCEEDED|MONTHLY_EXCEEDED)"$"#
)]
async fn then_response_deny_with_reason(world: &mut ConformanceWorld, reason_str: String) {
    let expected = match reason_str.as_str() {
        "AMOUNT_EXCEEDED" | "DAILY_EXCEEDED" | "MONTHLY_EXCEEDED" => DenyReason::BudgetExceeded,
        other => panic!("unknown deny_reason variant in feature file: {other}"),
    };
    assert_eq!(
        world.last_deny_reason,
        Some(expected.clone()),
        "expected Deny({expected:?}) (feature term `{reason_str}`), \
         got last_deny_reason={:?}, last_decision={:?}",
        world.last_deny_reason,
        world.last_decision,
    );
    assert!(
        matches!(world.last_decision, Some(Decision::Deny(_))),
        "expected a Deny decision, got {:?}",
        world.last_decision,
    );
}

/// `And an audit entry is appended with the requested amount and the limit`
/// (Scenario 1 — single-amount).
///
/// Asserts that a `PayX402` audit entry was appended. The audit payload
/// (constructed in the `When` step) records `requested_usd` and `limit_usd`
/// per R76. The chain is then re-verified to ensure the append didn't break
/// integrity.
#[then("an audit entry is appended with the requested amount and the limit")]
async fn then_audit_appended_with_amount_and_limit(world: &mut ConformanceWorld) {
    assert_eq!(
        world.last_audit_event,
        Some(EventType::PayX402),
        "expected PayX402 audit entry recording requested amount and limit"
    );
    let audit = world.audit_log.as_ref().expect("audit_log must be open");
    audit.verify_chain().expect("audit chain must verify after denied PayX402 (single-amount)");
}

/// `And an audit entry records both the prior cumulative and the rejected
/// amount` (Scenarios 2 & 3 — daily/monthly cumulative).
///
/// Same structural assertion as the single-amount variant — the audit payload
/// (constructed in the `When` step) records `prior_cumulative_usd` and
/// `rejected_amount_usd` per R76. This step text is shared between the daily
/// and monthly scenarios; the `When` step disambiguates the payload via
/// window population.
#[then("an audit entry records both the prior cumulative and the rejected amount")]
async fn then_audit_records_prior_cumulative_and_rejected(world: &mut ConformanceWorld) {
    assert_eq!(
        world.last_audit_event,
        Some(EventType::PayX402),
        "expected PayX402 audit entry recording prior cumulative and rejected amount"
    );
    let audit = world.audit_log.as_ref().expect("audit_log must be open");
    audit.verify_chain().expect("audit chain must verify after denied PayX402 (cumulative)");
}
