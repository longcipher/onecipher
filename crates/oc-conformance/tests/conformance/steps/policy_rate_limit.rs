//! T26 — Policy Rate Limits BDD step definitions.
//!
//! Implements the 2 scenarios in
//! `policy_rate_limit.feature`.
//!
//! The rate-limit logic itself lives in `oc_policy::v2` (steps 6 & 7 of the
//! 11-step flow — `step_6_check_rate_limit_minute` and
//! `step_7_check_rate_limit_hour`). These step definitions are pure BDD glue:
//! they orchestrate `PolicyState` and `evaluate_11_step` directly, in line
//! with the T22 component-level testing design.
//!
//! The shared Background step `Given an Agent holds an active Session Key with
//! a Policy` is implemented in `steps/background.rs` (shared with T25). This
//! module only adds the T26-specific Background step
//! (`And the Policy rules include rate_limit_per_minute and rate_limit_per_hour`)
//! plus the per-scenario Given/When/Then steps.

use cucumber::{given, then, when};
use oc_policy::{Decision, DenyReason, PayRequest, evaluate_11_step};

use crate::ConformanceWorld;

// ---------------------------------------------------------------------------
// Background (T26-specific second step)
// ---------------------------------------------------------------------------

/// `And the Policy rules include rate_limit_per_minute and rate_limit_per_hour`
///
/// The default policy set up by the shared Background (`background.rs`)
/// already populates both fields with non-zero values (10 and 100). This step
/// is therefore an assertion that the fields are present and non-zero.
#[given("the Policy rules include rate_limit_per_minute and rate_limit_per_hour")]
async fn policy_has_rate_limit_rules(world: &mut ConformanceWorld) {
    let policy = world.policy.as_ref().expect("policy must be set by shared Background");
    assert!(policy.rules.rate_limit_per_minute > 0, "rate_limit_per_minute must be non-zero");
    assert!(policy.rules.rate_limit_per_hour > 0, "rate_limit_per_hour must be non-zero");
}

// ---------------------------------------------------------------------------
// Scenario 1: Per-minute rate limit exceeded
// ---------------------------------------------------------------------------

/// `Given the Policy sets rate_limit_per_minute to 5`
///
/// Mutates both the world's `policy` copy and the `PolicyState`'s runtime
/// `policy` copy (the latter is what `evaluate_11_step` actually reads).
#[given("the Policy sets rate_limit_per_minute to 5")]
async fn policy_sets_rate_limit_per_minute_to_5(world: &mut ConformanceWorld) {
    if let Some(p) = world.policy.as_mut() {
        p.rules.rate_limit_per_minute = 5;
    }
    if let Some(state) = world.policy_state.as_mut() {
        if let Some(p) = state.policy.as_mut() {
            p.rules.rate_limit_per_minute = 5;
        }
    }
}

/// `And the Agent has already made 5 PayX402 requests within the last 60 seconds`
///
/// Pre-populates `state.minutely_window` with 5 timestamps 30s in the past.
/// Each entry represents a prior ALLOW decision (the rate-limit counter only
/// tracks ALLOWs). 30s ago is well within the 60s sliding window, so
/// `slide_all_windows` will not evict them when `evaluate_11_step` runs.
#[given("the Agent has already made 5 PayX402 requests within the last 60 seconds")]
async fn agent_made_5_requests_last_60s(world: &mut ConformanceWorld) {
    let now_unix = jiff::Timestamp::now().as_second().max(0) as u64;
    let now_ms = now_unix.saturating_mul(1000);
    let state = world.policy_state.as_mut().expect("policy_state must be set by Background");
    state.minutely_window.clear();
    for _ in 0..5 {
        state.minutely_window.push_back(now_ms - 30_000); // 30s ago, within 60s window
    }
}

/// `When the Agent makes a sixth PayX402 request within the same minute`
///
/// Constructs a `PayRequest` and runs `evaluate_11_step`. Stores the resulting
/// `Decision` in `world.last_decision` and extracts the `DenyReason` (if any)
/// into `world.last_deny_reason`.
#[when("the Agent makes a sixth PayX402 request within the same minute")]
async fn agent_makes_sixth_request_same_minute(world: &mut ConformanceWorld) {
    let session_key_id = world.session_key_id.clone().expect("session_key_id must be set");
    let req = PayRequest {
        session_key_id: session_key_id.clone(),
        device_id: "dev-test".to_string(),
        amount_usd: 0.01,
        asset: "USDC".to_string(),
        chain_id: "eip155:8453".to_string(),
        recipient: None,
    };
    let state = world.policy_state.as_mut().expect("policy_state must be set");
    let decision = evaluate_11_step(&req, &session_key_id, state);
    if let Decision::Deny(reason) = &decision {
        world.last_deny_reason = Some(reason.clone());
    }
    world.last_decision = Some(decision);
}

/// `Then the Policy Engine evaluates the sliding 60-second window counter`
///
/// Behavioural placeholder: `evaluate_11_step` already invoked
/// `slide_all_windows` before the per-minute rate check. The subsequent
/// `deny_reason` assertion proves the minute-window counter was consulted.
#[then("the Policy Engine evaluates the sliding 60-second window counter")]
async fn then_evaluates_sliding_60s_window(_world: &mut ConformanceWorld) {
    // No-op: the sliding window was evaluated inside `evaluate_11_step`.
}

/// `And the response has status DENY and deny_reason "RATE_LIMIT_MINUTE"`
#[then(regex = r#"^the response has status DENY and deny_reason "RATE_LIMIT_MINUTE"$"#)]
async fn then_response_deny_rate_limit_minute(world: &mut ConformanceWorld) {
    assert!(
        matches!(world.last_decision, Some(Decision::Deny(DenyReason::RateLimitMinute))),
        "expected Deny(RateLimitMinute), got {:?}",
        world.last_decision
    );
    assert_eq!(
        world.last_deny_reason,
        Some(DenyReason::RateLimitMinute),
        "expected last_deny_reason = RateLimitMinute"
    );
}

// ---------------------------------------------------------------------------
// Scenario 2: Per-hour rate limit exceeded
// ---------------------------------------------------------------------------

/// `Given the Policy sets rate_limit_per_hour to 50`
#[given("the Policy sets rate_limit_per_hour to 50")]
async fn policy_sets_rate_limit_per_hour_to_50(world: &mut ConformanceWorld) {
    if let Some(p) = world.policy.as_mut() {
        p.rules.rate_limit_per_hour = 50;
    }
    if let Some(state) = world.policy_state.as_mut() {
        if let Some(p) = state.policy.as_mut() {
            p.rules.rate_limit_per_hour = 50;
        }
    }
}

/// `And the Agent has already made 50 PayX402 requests within the last 3600 seconds`
///
/// Pre-populates `state.hourly_window` with 50 timestamps 30min in the past.
/// 30min ago is well within the 3600s sliding window, so `slide_all_windows`
/// will not evict them.
#[given("the Agent has already made 50 PayX402 requests within the last 3600 seconds")]
async fn agent_made_50_requests_last_3600s(world: &mut ConformanceWorld) {
    let now_unix = jiff::Timestamp::now().as_second().max(0) as u64;
    let now_ms = now_unix.saturating_mul(1000);
    let state = world.policy_state.as_mut().expect("policy_state must be set by Background");
    state.hourly_window.clear();
    for _ in 0..50 {
        state.hourly_window.push_back(now_ms - 1_800_000); // 30min ago, within 3600s window
    }
}

/// `And the per-minute counter is below its limit`
///
/// Ensures `state.minutely_window` is empty so the per-minute check (step 6)
/// passes and the per-hour check (step 7) is reached.
#[given("the per-minute counter is below its limit")]
async fn per_minute_counter_below_limit(world: &mut ConformanceWorld) {
    let state = world.policy_state.as_mut().expect("policy_state must be set by Background");
    state.minutely_window.clear();
    // After clearing, len() == 0 < rate_limit_per_minute (default 10) → step 6 passes.
}

/// `When the Agent makes a fifty-first PayX402 request within the same hour`
#[when("the Agent makes a fifty-first PayX402 request within the same hour")]
async fn agent_makes_51st_request_same_hour(world: &mut ConformanceWorld) {
    let session_key_id = world.session_key_id.clone().expect("session_key_id must be set");
    let req = PayRequest {
        session_key_id: session_key_id.clone(),
        device_id: "dev-test".to_string(),
        amount_usd: 0.01,
        asset: "USDC".to_string(),
        chain_id: "eip155:8453".to_string(),
        recipient: None,
    };
    let state = world.policy_state.as_mut().expect("policy_state must be set");
    let decision = evaluate_11_step(&req, &session_key_id, state);
    if let Decision::Deny(reason) = &decision {
        world.last_deny_reason = Some(reason.clone());
    }
    world.last_decision = Some(decision);
}

/// `Then the Policy Engine evaluates the sliding 3600-second window counter`
#[then("the Policy Engine evaluates the sliding 3600-second window counter")]
async fn then_evaluates_sliding_3600s_window(_world: &mut ConformanceWorld) {
    // No-op: the sliding window was evaluated inside `evaluate_11_step`.
}

/// `And the response has status DENY and deny_reason "RATE_LIMIT_HOUR"`
#[then(regex = r#"^the response has status DENY and deny_reason "RATE_LIMIT_HOUR"$"#)]
async fn then_response_deny_rate_limit_hour(world: &mut ConformanceWorld) {
    assert!(
        matches!(world.last_decision, Some(Decision::Deny(DenyReason::RateLimitHour))),
        "expected Deny(RateLimitHour), got {:?}",
        world.last_decision
    );
    assert_eq!(
        world.last_deny_reason,
        Some(DenyReason::RateLimitHour),
        "expected last_deny_reason = RateLimitHour"
    );
}

// ---------------------------------------------------------------------------
// Shared between both scenarios
// ---------------------------------------------------------------------------

/// `And the cooldown timer is started`
///
/// Asserts that `state.last_deny_at_unix` was set by `record_deny` inside
/// `evaluate_11_step` — this is the "cooldown timer started" behaviour.
#[then("the cooldown timer is started")]
async fn then_cooldown_timer_started(world: &mut ConformanceWorld) {
    let state = world.policy_state.as_ref().expect("policy_state must be set");
    assert!(
        state.last_deny_at_unix.is_some(),
        "expected last_deny_at_unix to be set (cooldown timer started), but it was None"
    );
}
