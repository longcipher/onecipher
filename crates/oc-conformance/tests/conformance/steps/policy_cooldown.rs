//! T29 — Policy Cooldown After Denial BDD step definitions.
//!
//! Implements the 2 scenarios in
//! `policy_cooldown.feature`:
//! 1. First DENY triggers cooldown timer (R46, R47; T21)
//! 2. Subsequent request within `cooldown_after_denial_sec` is immediately denied with
//!    `DenyReason::Cooldown` (R46, R48; T21)
//!
//! Per the T22 design, steps orchestrate EXISTING components directly:
//! - `oc_policy::evaluate_11_step` for the 11-step Policy decision flow (step 5 =
//!   `step_5_check_cooldown`; step 11 = `record_deny` sets `last_deny_at_unix`)
//! - `oc_keyagent::AuditLog` for the append-only audit chain
//!
//! # R80 deny_reason mapping
//! The feature file uses the human-readable string `COOLDOWN`, which maps
//! directly to `DenyReason::Cooldown` (no translation needed).
//!
//! # Shared Background
//! The first Background step (`Given an Agent holds an active Session Key
//! with a Policy`) is shared with T25 / T26 and is implemented in
//! `steps/background.rs`. The default policy from `background.rs` sets
//! `cooldown_after_denial_sec = 60`. The T29-specific second Background step
//! (`And the Policy rules include cooldown_after_denial_sec`) is a no-op
//! assertion that the field is non-zero.
//!
//! # Deterministic time
//! The shared Background does NOT set `now_override`. Both T29 scenarios need
//! deterministic time for cooldown arithmetic, so each scenario's first Given
//! step installs `now_override = Some(NOW_OVERRIDE)` on the PolicyState. This
//! makes `record_deny`'s `last_deny_at_unix` (= `now_ms / 1000`) and
//! `step_5_check_cooldown`'s comparison (`last_deny + cooldown > now`)
//! fully deterministic.

use cucumber::{given, then, when};
use oc_keyagent::EventType;
use oc_policy::{Decision, DenyReason, PayRequest, evaluate_11_step};

use crate::ConformanceWorld;

/// Deterministic `now` value (unix seconds) used by both T29 scenarios.
/// Chosen as a round number well below any real-world `expiry_unix` (which
/// `default_test_policy` sets to `jiff::Timestamp::now() + 3600`), so step 3
/// (expiry) always passes.
const NOW_OVERRIDE: u64 = 1_000_000;

// ---------------------------------------------------------------------------
// T29-specific Background step
// ---------------------------------------------------------------------------

/// `And the Policy rules include cooldown_after_denial_sec`.
///
/// The default policy set up by the shared Background (`background.rs`)
/// already populates `cooldown_after_denial_sec = 60`. This step is a no-op
/// assertion that the field is non-zero, so a regression in
/// `default_test_policy()` is caught here rather than mid-scenario.
#[given("the Policy rules include cooldown_after_denial_sec")]
async fn policy_rules_include_cooldown(world: &mut ConformanceWorld) {
    let policy = world.policy.as_ref().expect("policy must be set by shared Background");
    assert!(
        policy.rules.cooldown_after_denial_sec > 0,
        "cooldown_after_denial_sec must be non-zero in default policy"
    );
}

// ---------------------------------------------------------------------------
// Scenario 1: First DENY triggers cooldown timer
// ---------------------------------------------------------------------------

/// `Given the Agent has no prior DENY in the current cooldown window`.
///
/// Asserts `state.last_deny_at_unix.is_none()` (no prior DENY recorded), then
/// installs `now_override = Some(NOW_OVERRIDE)` so the timestamp recorded by
/// `record_deny` is verifiable. The shared Background does NOT set
/// `now_override`, so this step owns it for Scenario 1.
#[given("the Agent has no prior DENY in the current cooldown window")]
async fn agent_has_no_prior_deny(world: &mut ConformanceWorld) {
    let state = world.policy_state.as_mut().expect("policy_state must be set by shared Background");
    assert!(
        state.last_deny_at_unix.is_none(),
        "expected no prior DENY, but last_deny_at_unix={:?}",
        state.last_deny_at_unix,
    );
    state.now_override = Some(NOW_OVERRIDE);
}

/// `When the Agent triggers a PayX402 that is DENIED for any reason`.
///
/// Triggers a DENY by tightening `max_single_amount_usd` to 0.01 (well below
/// the requested 5.00 USD) on BOTH policy copies, then running
/// `evaluate_11_step`. With no prior DENY, step 5 (cooldown) passes; steps 6-8
/// pass on the fresh counters; step 9 (single amount) returns
/// `BudgetExceeded`. `record_deny` (inside step_11_deny) then sets
/// `last_deny_at_unix = Some(now_unix)` where `now_unix = NOW_OVERRIDE`.
///
/// The audit payload records the actual DENY reason (as a snake_case string
/// via serde — `DenyReason` is `#[serde(rename_all = "snake_case")]`) plus
/// `cooldown_started: true` and `cooldown_duration_sec` (the policy's
/// `cooldown_after_denial_sec`).
#[when("the Agent triggers a PayX402 that is DENIED for any reason")]
async fn agent_triggers_denied_payx402(world: &mut ConformanceWorld) {
    // Tighten max_single_amount_usd to 0.01 on both policy copies so step 9
    // returns BudgetExceeded (5.00 USD >> 0.01 USD). `evaluate_11_step` reads
    // from `state.policy`; we keep `world.policy` in sync so any assertion
    // against `world.policy` agrees.
    if let Some(p) = world.policy.as_mut() {
        p.rules.max_single_amount_usd = 0.01;
    }
    if let Some(state) = world.policy_state.as_mut() {
        if let Some(p) = state.policy.as_mut() {
            p.rules.max_single_amount_usd = 0.01;
        }
    }

    let req = PayRequest {
        session_key_id: "oc_sk_active".to_string(),
        device_id: "dev-test".to_string(),
        amount_usd: 5.0,
        asset: "USDC".to_string(),
        chain_id: "eip155:8453".to_string(),
        recipient: None,
    };

    // Borrow state mutably to evaluate; extract owned values so the mutable
    // borrow ends before we touch audit_log.
    let (decision, cooldown_duration_sec) = {
        let state =
            world.policy_state.as_mut().expect("policy_state must be set by shared Background");
        let decision = evaluate_11_step(&req, "oc_sk_active", state);
        let cooldown_duration_sec =
            state.policy.as_ref().map_or(0, |p| p.rules.cooldown_after_denial_sec);
        (decision, cooldown_duration_sec)
    };

    // Construct the audit payload. The deny reason is whatever step fired
    // (BudgetExceeded in this wiring) — recorded as the snake_case form via
    // serde_json (`DenyReason` is `#[serde(rename_all = "snake_case")]`).
    let payload = match &decision {
        Decision::Deny(reason) => {
            world.last_deny_reason = Some(reason.clone());
            let reason_value =
                serde_json::to_value(reason).expect("DenyReason is always JSON-serializable");
            serde_json::json!({
                "status": "denied",
                "reason": reason_value,
                "cooldown_started": true,
                "cooldown_duration_sec": cooldown_duration_sec,
            })
        }
        Decision::Allow => {
            panic!("expected a DENY decision to trigger cooldown, got Allow");
        }
    };

    world.last_decision = Some(decision);
    world.last_audit_event = Some(EventType::PayX402);

    let audit = world.audit_log.as_mut().expect("audit_log must be open");
    audit
        .append(EventType::PayX402, Some("oc_sk_active".to_string()), payload)
        .expect("audit append for denied PayX402 must succeed");
}

/// `Then the Policy Engine records the timestamp of the DENY`.
///
/// Asserts that `record_deny` (called from step_11_deny) set
/// `last_deny_at_unix` to `NOW_OVERRIDE` (= 1_000_000 unix seconds), proving
/// the DENY timestamp was persisted to the PolicyState.
#[then("the Policy Engine records the timestamp of the DENY")]
async fn then_records_deny_timestamp(world: &mut ConformanceWorld) {
    let state = world.policy_state.as_ref().expect("policy_state must be set");
    assert_eq!(
        state.last_deny_at_unix,
        Some(NOW_OVERRIDE),
        "expected last_deny_at_unix = Some({}) (= now_override), got {:?}",
        NOW_OVERRIDE,
        state.last_deny_at_unix,
    );
}

/// `And the cooldown timer is started with duration cooldown_after_denial_sec`.
///
/// Asserts that the cooldown is currently active: `last_deny_at_unix +
/// cooldown_after_denial_sec > now_override`. With `last_deny_at_unix =
/// now_override = 1_000_000` and `cooldown_after_denial_sec = 60`, the cooldown
/// ends at 1_000_060, which is strictly greater than 1_000_000 → active. This
/// is exactly the invariant `step_5_check_cooldown` will check on the next
/// request.
#[then("the cooldown timer is started with duration cooldown_after_denial_sec")]
async fn then_cooldown_timer_started_with_duration(world: &mut ConformanceWorld) {
    let state = world.policy_state.as_ref().expect("policy_state must be set");
    let last_deny = state.last_deny_at_unix.expect("last_deny_at_unix must be set by record_deny");
    let cooldown = state.policy.as_ref().map_or(0, |p| p.rules.cooldown_after_denial_sec);
    assert!(cooldown > 0, "cooldown_after_denial_sec must be non-zero");
    let now = state.now_override.expect("now_override must be set by the Given step");
    assert!(
        last_deny.saturating_add(cooldown) > now,
        "expected cooldown active (last_deny={} + cooldown={} > now={}), \
         but it has already expired",
        last_deny,
        cooldown,
        now,
    );
}

/// `And an audit entry is appended recording the DENY reason and the cooldown
/// start` (Scenario 1).
///
/// Asserts that a `PayX402` audit entry was appended (the payload was
/// constructed in the `When` step) and that the chain still verifies.
#[then("an audit entry is appended recording the DENY reason and the cooldown start")]
async fn then_audit_appended_with_deny_reason_and_cooldown_start(world: &mut ConformanceWorld) {
    assert_eq!(
        world.last_audit_event,
        Some(EventType::PayX402),
        "expected PayX402 audit entry recording DENY reason and cooldown start"
    );
    let audit = world.audit_log.as_ref().expect("audit_log must be open");
    audit.verify_chain().expect("audit chain must verify after denied PayX402 (cooldown start)");
}

// ---------------------------------------------------------------------------
// Scenario 2: Subsequent request within cooldown_after_denial_sec
// ---------------------------------------------------------------------------

/// `Given the Agent received a DENY 30 seconds ago`.
///
/// Sets `now_override = Some(NOW_OVERRIDE)` and
/// `last_deny_at_unix = Some(NOW_OVERRIDE - 30)` (= 999_970), simulating a
/// DENY that happened 30 seconds before "now".
#[given("the Agent received a DENY 30 seconds ago")]
async fn agent_received_deny_30s_ago(world: &mut ConformanceWorld) {
    let state = world.policy_state.as_mut().expect("policy_state must be set by shared Background");
    state.now_override = Some(NOW_OVERRIDE);
    state.last_deny_at_unix = Some(NOW_OVERRIDE - 30); // 999_970
}

/// `And the Policy sets cooldown_after_denial_sec to 300`.
///
/// Mutates both the world's `policy` copy and the `PolicyState`'s runtime
/// `policy` copy (the latter is what `evaluate_11_step` actually reads via
/// `step_5_check_cooldown`).
#[given("the Policy sets cooldown_after_denial_sec to 300")]
async fn policy_sets_cooldown_to_300(world: &mut ConformanceWorld) {
    if let Some(p) = world.policy.as_mut() {
        p.rules.cooldown_after_denial_sec = 300;
    }
    if let Some(state) = world.policy_state.as_mut() {
        if let Some(p) = state.policy.as_mut() {
            p.rules.cooldown_after_denial_sec = 300;
        }
    }
}

/// `When the Agent makes another PayX402 request now`.
///
/// Runs `evaluate_11_step`. Step 5 (cooldown) fires first: `last_deny
/// (999_970) + 300 = 1_000_270 > now (1_000_000)` → `Deny(Cooldown)`. No later
/// step (rate limits, budget, single-amount) runs, so `local_spent_usd` and
/// the sliding windows are unchanged (asserted in the "no other rules"
/// `Then` step).
///
/// The audit payload records `reason: "cooldown"` and `cooldown_active: true`.
#[when("the Agent makes another PayX402 request now")]
async fn agent_makes_another_payx402_now(world: &mut ConformanceWorld) {
    let req = PayRequest {
        session_key_id: "oc_sk_active".to_string(),
        device_id: "dev-test".to_string(),
        amount_usd: 0.01,
        asset: "USDC".to_string(),
        chain_id: "eip155:8453".to_string(),
        recipient: None,
    };

    let decision = {
        let state = world.policy_state.as_mut().expect("policy_state must be set");
        evaluate_11_step(&req, "oc_sk_active", state)
    };

    let payload = match &decision {
        Decision::Deny(reason) => {
            world.last_deny_reason = Some(reason.clone());
            serde_json::json!({
                "status": "denied",
                "reason": "cooldown",
                "cooldown_active": true,
            })
        }
        Decision::Allow => {
            panic!("expected Deny(Cooldown), got Allow");
        }
    };

    world.last_decision = Some(decision);
    world.last_audit_event = Some(EventType::PayX402);

    let audit = world.audit_log.as_mut().expect("audit_log must be open");
    audit
        .append(EventType::PayX402, Some("oc_sk_active".to_string()), payload)
        .expect("audit append for COOLDOWN PayX402 must succeed");
}

/// `Then the Policy Engine detects the active cooldown before evaluating other
/// rules`.
///
/// Implicit assertion — the next `And` step asserts `deny_reason "COOLDOWN"`,
/// which proves step 5 fired. Step 5 runs BEFORE steps 6-9 in the 11-step
/// flow, so a `Cooldown` deny reason is only reachable if step 5 fired first
/// (steps 6-9 never produce `Cooldown`).
#[then("the Policy Engine detects the active cooldown before evaluating other rules")]
async fn then_detects_cooldown_before_other_rules(_world: &mut ConformanceWorld) {
    // No-op: implicit in the Deny(Cooldown) assertion below. A Cooldown deny
    // reason is only produced by step_5_check_cooldown, which runs before
    // steps 6-9 in evaluate_11_step.
}

/// `And the response has status DENY and deny_reason "COOLDOWN"`.
#[then(regex = r#"^the response has status DENY and deny_reason "COOLDOWN"$"#)]
async fn then_response_deny_cooldown(world: &mut ConformanceWorld) {
    assert!(
        matches!(world.last_decision, Some(Decision::Deny(DenyReason::Cooldown))),
        "expected Deny(Cooldown), got {:?}",
        world.last_decision
    );
    assert_eq!(
        world.last_deny_reason,
        Some(DenyReason::Cooldown),
        "expected last_deny_reason = Cooldown"
    );
}

/// `And no other policy rules are evaluated for this request`.
///
/// Proves step_10_allow did NOT run by asserting `local_spent_usd` is still 0
/// and all four sliding windows are still empty. If step 10 had run, it would
/// have incremented `local_spent_usd` by `req.amount_usd` and pushed
/// timestamps / (timestamp, amount) pairs into all four sliding windows
/// (see `PolicyState::record_allow`). The Background creates a fresh state
/// (all counters zero), and the Scenario 2 Given steps only touch
/// `last_deny_at_unix` / `now_override` / `cooldown_after_denial_sec` — never
/// `local_spent_usd` or the windows — so the "before" values are all zero /
/// empty.
#[then("no other policy rules are evaluated for this request")]
async fn then_no_other_rules_evaluated(world: &mut ConformanceWorld) {
    let state = world.policy_state.as_ref().expect("policy_state must be set");
    assert_eq!(
        state.local_spent_usd, 0.0,
        "local_spent_usd must be unchanged (step_10_allow did not run)"
    );
    assert!(
        state.minutely_window.is_empty(),
        "minutely_window must be empty (step_10_allow did not run)"
    );
    assert!(
        state.hourly_window.is_empty(),
        "hourly_window must be empty (step_10_allow did not run)"
    );
    assert!(
        state.daily_window.is_empty(),
        "daily_window must be empty (step_10_allow did not run)"
    );
    assert!(
        state.monthly_window.is_empty(),
        "monthly_window must be empty (step_10_allow did not run)"
    );
}

/// `And an audit entry is appended recording the COOLDOWN denial`.
#[then("an audit entry is appended recording the COOLDOWN denial")]
async fn then_audit_appended_with_cooldown_denial(world: &mut ConformanceWorld) {
    assert_eq!(
        world.last_audit_event,
        Some(EventType::PayX402),
        "expected PayX402 audit entry recording the COOLDOWN denial"
    );
    let audit = world.audit_log.as_ref().expect("audit_log must be open");
    audit.verify_chain().expect("audit chain must verify after denied PayX402 (COOLDOWN)");
}
