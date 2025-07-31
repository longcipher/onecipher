//! T27 — Policy Pessimistic Budget BDD step definitions.
//!
//! Implements the 4 scenarios in
//! `policy_budget.feature`:
//! 1. Pessimistic budget allocation per device (R36, R37; T19)
//! 2. Cumulative spend + current exceeds allocated_usd (R36, R38; T19)
//! 3. Two devices with hard sub-quotas cannot overspend parent total (R36, R39; T19)
//! 4. Budget reclaim on Session Key revocation (R40, R41; T5, T19)
//!
//! Per the T27 design, steps orchestrate EXISTING components directly:
//! - `oc_policy::evaluate_11_step` for the 11-step Policy decision flow
//! - `oc_policy::PolicyState` for runtime budget state (`local_spent_usd`)
//! - `oc_keyagent::AuditLog` for the append-only audit chain
//!
//! # R80 deny_reason mapping
//! The feature file uses `BUDGET_EXCEEDED`, which maps directly to
//! `DenyReason::BudgetExceeded`. No mapping needed.
//!
//! # Background
//! `policy_budget.feature`'s Background is T27-specific (it does NOT use the
//! shared `Given an Agent holds an active Session Key with a Policy` step
//! from `background.rs`). The first T27 Background step performs the same
//! setup work inline (device key + audit log + default policy + PolicyState),
//! then the next two Background steps are no-op assertions on the default
//! policy's budget fields.

use cucumber::{given, then, when};
use ed25519_dalek::SigningKey;
use oc_keyagent::{AuditEntry, AuditLog, EventType};
use oc_policy::{Decision, DenyReason, PayRequest, PolicyState, evaluate_11_step};
use tempfile::tempdir;

use crate::{ConformanceWorld, steps::background::default_test_policy};

// ---------------------------------------------------------------------------
// Background (T27-specific — sets up the world state)
// ---------------------------------------------------------------------------

/// `Given the main wallet has a parent_total_usd daily budget`.
///
/// Performs the same world setup as
/// `background.rs::agent_holds_active_session_key`: fresh Ed25519 device key
/// + audit log (in a leaked `TempDir`), an active `session_key_id =
/// "oc_sk_active"`, a default `PolicyV2` with non-zero `parent_total_usd`,
/// and a `PolicyState` with the policy attached backed by a temp JSON file.
/// Per-scenario `Given` steps then tighten specific fields (e.g.
/// `parent_total_usd = 10.00`, `allocated_usd = 3.00`) before the `When`
/// step runs.
#[given("the main wallet has a parent_total_usd daily budget")]
async fn main_wallet_has_parent_total_budget(world: &mut ConformanceWorld) {
    // 1. Device key + audit log (leaked TempDir keeps the file alive for the scenario's lifetime —
    //    same pattern as T22 / T25 / T26).
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

    // 3. Default permissive policy. Per-scenario `Given` steps will tighten
    //    budget_allocation.{parent_total_usd, allocated_usd} before the When.
    let policy = default_test_policy("oc_sk_active");
    world.policy = Some(policy.clone());

    // 4. Policy state with policy attached, backed by a temp file. The `PolicyState` carries the
    //    runtime `policy` field (`#[serde(skip)]`) so we attach it after `load`.
    let tmp_state = tempdir().expect("tempdir for policy state");
    let state_path = tmp_state.path().join("policy_state.json");
    std::mem::forget(tmp_state);
    let state = PolicyState::load(&state_path, "oc_sk_active".to_string())
        .expect("PolicyState::load")
        .with_policy(policy);
    world.policy_state = Some(state);
    world.policy_state_path = Some(state_path);

    // Reset per-scenario decision / audit / error state so a prior scenario's
    // leftovers cannot leak into this one (cucumber reuses the World).
    world.last_decision = None;
    world.last_deny_reason = None;
    world.last_audit_event = None;
    world.last_error = None;
}

/// `And the Owner has allocated pessimistic budget_allocation entries to
/// one or more device-Agent pairs`.
///
/// No-op assertion: verifies that the default policy from the prior
/// Background step has a non-zero `budget_allocation.allocated_usd`. The
/// "pessimistic" allocation model means each device-Agent pair receives a
/// hard sub-quota that it cannot exceed without consulting the parent
/// wallet (R36 / R37).
#[given(
    "the Owner has allocated pessimistic budget_allocation entries to one or more device-Agent pairs"
)]
async fn owner_allocated_pessimistic_budget(world: &mut ConformanceWorld) {
    let policy = world.policy.as_ref().expect("policy must be set by prior Background step");
    assert!(
        policy.budget_allocation.allocated_usd > 0.0,
        "allocated_usd must be non-zero in default policy"
    );
    assert!(
        policy.budget_allocation.parent_total_usd > 0.0,
        "parent_total_usd must be non-zero in default policy"
    );
}

/// `And each device evaluates its budget locally without cross-device
/// synchronization`.
///
/// No-op assertion: the pessimistic-budget model is enforced by step 8 of
/// `evaluate_11_step`, which only consults `state.local_spent_usd` and
/// `policy.budget_allocation.allocated_usd` (both device-local). There is
/// no cross-device synchronization primitive in the Phase 1 design.
#[given("each device evaluates its budget locally without cross-device synchronization")]
async fn each_device_evaluates_locally(_world: &mut ConformanceWorld) {
    // No-op: implicit in the design of `evaluate_11_step`'s step 8.
}

// ---------------------------------------------------------------------------
// Scenario 1: Pessimistic budget allocation per device
// ---------------------------------------------------------------------------

/// `Given the main wallet parent_total_usd is 10.00`.
///
/// Sets `parent_total_usd` on both the world's `policy` copy and the
/// `PolicyState`'s runtime `policy` copy (the latter is what
/// `evaluate_11_step` actually reads).
#[given(regex = r"^the main wallet parent_total_usd is ([0-9.]+)$")]
async fn main_wallet_parent_total_is(world: &mut ConformanceWorld, value: String) {
    let val: f64 =
        value.parse().unwrap_or_else(|_| panic!("parent_total_usd must be a float, got {value}"));
    if let Some(p) = world.policy.as_mut() {
        p.budget_allocation.parent_total_usd = val;
    }
    if let Some(state) = world.policy_state.as_mut() {
        if let Some(p) = state.policy.as_mut() {
            p.budget_allocation.parent_total_usd = val;
        }
    }
}

/// `When the Owner creates a Session Key on device "{device_id}" with
/// allocated_usd {amount}`.
///
/// Per the T27 design, this is a no-op simulation of the Session Key
/// creation flow: the policy's `budget_allocation.allocated_usd` is set
/// here (the parent wallet's "allocation" action), the policy's
/// `device_id` is recorded, and the world is left ready for the
/// subsequent `Then` assertions. No on-chain interaction occurs at the
/// conformance-test level (T22 covers the full Session Key lifecycle).
#[when(
    regex = r#"^the Owner creates a Session Key on device "([^"]+)" with allocated_usd ([0-9.]+)$"#
)]
async fn owner_creates_session_key_with_allocation(
    world: &mut ConformanceWorld,
    device_id: String,
    amount_str: String,
) {
    let allocated: f64 = amount_str
        .parse()
        .unwrap_or_else(|_| panic!("allocated_usd must be a float, got {amount_str}"));
    if let Some(p) = world.policy.as_mut() {
        p.device_id = device_id.clone();
        p.budget_allocation.allocated_usd = allocated;
    }
    if let Some(state) = world.policy_state.as_mut() {
        if let Some(p) = state.policy.as_mut() {
            p.device_id = device_id;
            p.budget_allocation.allocated_usd = allocated;
        }
    }
}

/// `Then the budget_allocation is stored locally on the device`.
///
/// Asserts that the world's `policy.budget_allocation.allocated_usd`
/// matches the value set in the `When` step, and that the runtime
/// `PolicyState`'s policy copy agrees (i.e. the allocation was persisted
/// to the device-local PolicyState, not just the world's standalone
/// `policy` snapshot).
#[then("the budget_allocation is stored locally on the device")]
async fn then_budget_allocation_stored_locally(world: &mut ConformanceWorld) {
    let world_alloc = world
        .policy
        .as_ref()
        .map(|p| p.budget_allocation.allocated_usd)
        .expect("policy must be set");
    let state_alloc = world
        .policy_state
        .as_ref()
        .and_then(|s| s.policy.as_ref())
        .map(|p| p.budget_allocation.allocated_usd)
        .expect("policy_state.policy must be set");
    assert_eq!(
        world_alloc, state_alloc,
        "world.policy and policy_state.policy must agree on allocated_usd"
    );
    assert!(world_alloc > 0.0, "allocated_usd must be positive after the When step");
}

/// `And the parent reserve pool becomes {amount}`.
///
/// Asserts that `parent_total_usd - allocated_usd == amount` on the
/// world's policy. The "parent reserve pool" is the unallocated portion
/// of the parent wallet's daily budget (R37).
#[then(regex = r"^the parent reserve pool becomes ([0-9.]+)$")]
async fn then_parent_reserve_pool_becomes(world: &mut ConformanceWorld, amount_str: String) {
    let expected: f64 = amount_str
        .parse()
        .unwrap_or_else(|_| panic!("reserve pool must be a float, got {amount_str}"));
    let policy = world.policy.as_ref().expect("policy must be set by prior steps");
    let reserve =
        policy.budget_allocation.parent_total_usd - policy.budget_allocation.allocated_usd;
    assert!(
        (reserve - expected).abs() < 1e-9,
        "parent reserve pool: expected {expected}, got {reserve} \
         (parent_total={}, allocated={})",
        policy.budget_allocation.parent_total_usd,
        policy.budget_allocation.allocated_usd,
    );
}

/// `And the device may approve payments up to {amount} USD cumulatively
/// without consulting other devices`.
///
/// Verifies the device-local budget cap by calling `evaluate_11_step`
/// twice on the world's `PolicyState`:
/// 1. A request exactly equal to the cap → must `Allow` (proving the device can approve up to the
///    cap on its own).
/// 2. Any further request (0.01 USD) → must `Deny(BudgetExceeded)` because the cumulative
///    `local_spent_usd` now equals the cap, so even a tiny additional payment exceeds it.
///
/// Both checks consult only `state.local_spent_usd` and
/// `policy.budget_allocation.allocated_usd` — both device-local — which
/// proves the device enforces its cap without cross-device
/// synchronization.
#[then(
    regex = r"^the device may approve payments up to ([0-9.]+) USD cumulatively without consulting other devices$"
)]
async fn then_device_may_approve_up_to(world: &mut ConformanceWorld, amount_str: String) {
    let cap: f64 = amount_str
        .parse()
        .unwrap_or_else(|_| panic!("device cap must be a float, got {amount_str}"));
    let session_key_id = world.session_key_id.clone().expect("session_key_id must be set");

    // 1. Request exactly equal to the cap → ALLOW. local_spent_usd is 0 before this call (the
    //    Background reset it), so 0 + cap == cap (not strictly greater) passes step 8.
    let req_at_cap = PayRequest {
        session_key_id: session_key_id.clone(),
        device_id: "dev-test".to_string(),
        amount_usd: cap,
        asset: "USDC".to_string(),
        chain_id: "eip155:8453".to_string(),
        recipient: None,
    };
    let decision_at_cap = {
        let state = world.policy_state.as_mut().expect("policy_state must be set");
        evaluate_11_step(&req_at_cap, &session_key_id, state)
    };
    assert!(
        matches!(decision_at_cap, Decision::Allow),
        "request at cap ({cap}) must ALLOW, got {decision_at_cap:?}"
    );

    // 2. Any further request → DENY(BudgetExceeded). local_spent_usd is now `cap` after the prior
    //    ALLOW, so cap + 0.01 > cap → step 8 fires BudgetExceeded.
    let req_over = PayRequest {
        session_key_id: session_key_id.clone(),
        device_id: "dev-test".to_string(),
        amount_usd: 0.01,
        asset: "USDC".to_string(),
        chain_id: "eip155:8453".to_string(),
        recipient: None,
    };
    let decision_over = {
        let state = world.policy_state.as_mut().expect("policy_state must be set");
        evaluate_11_step(&req_over, &session_key_id, state)
    };
    assert!(
        matches!(decision_over, Decision::Deny(DenyReason::BudgetExceeded)),
        "request over cap (0.01 after cumulative={cap}) must DENY(BudgetExceeded), \
         got {decision_over:?}"
    );
}

// ---------------------------------------------------------------------------
// Scenario 2: Cumulative spend + current exceeds allocated_usd
// ---------------------------------------------------------------------------

/// `Given a device has allocated_usd of {amount}`.
///
/// Sets `budget_allocation.allocated_usd` on both `world.policy` and
/// `world.policy_state.policy`. Also bumps `parent_total_usd` to at
/// least `2 * allocated` if it is smaller, so step 8 (budget) — not any
/// parent-total-style check — governs this scenario.
#[given(regex = r"^a device has allocated_usd of ([0-9.]+)$")]
async fn device_has_allocated_usd(world: &mut ConformanceWorld, amount_str: String) {
    let allocated: f64 = amount_str
        .parse()
        .unwrap_or_else(|_| panic!("allocated_usd must be a float, got {amount_str}"));
    if let Some(p) = world.policy.as_mut() {
        p.budget_allocation.allocated_usd = allocated;
        if p.budget_allocation.parent_total_usd < allocated * 2.0 {
            p.budget_allocation.parent_total_usd = allocated * 2.0;
        }
    }
    if let Some(state) = world.policy_state.as_mut() {
        if let Some(p) = state.policy.as_mut() {
            p.budget_allocation.allocated_usd = allocated;
            if p.budget_allocation.parent_total_usd < allocated * 2.0 {
                p.budget_allocation.parent_total_usd = allocated * 2.0;
            }
        }
    }
}

/// `And the device has already spent {amount} USD within the current
/// allocation period`.
///
/// Pre-populates `state.local_spent_usd` so step 8 of `evaluate_11_step`
/// sees the prior cumulative spend. The pessimistic budget check is
/// `local_spent + amount > allocated` (step 8 in v2.rs).
#[given(
    regex = r"^the device has already spent ([0-9.]+) USD within the current allocation period$"
)]
async fn device_already_spent(world: &mut ConformanceWorld, amount_str: String) {
    let amount: f64 = amount_str
        .parse()
        .unwrap_or_else(|_| panic!("prior spend must be a float, got {amount_str}"));
    let state = world.policy_state.as_mut().expect("policy_state must be set by Background");
    state.local_spent_usd = amount;
}

/// `When the Agent on that device requests a PayX402 for {amount} USD`.
///
/// Constructs a `PayRequest` and calls `evaluate_11_step`. Records the
/// resulting `Decision` and `DenyReason` (if any) on the world. Also
/// appends a `PayX402` audit entry whose payload records
/// `prior_cumulative_usd`, `requested_usd`, and `allocated_usd` per
/// R76 / R38.
#[when(regex = r"^the Agent on that device requests a PayX402 for ([0-9.]+) USD$")]
async fn agent_on_device_requests_pay_x402(world: &mut ConformanceWorld, amount_str: String) {
    let amount: f64 = amount_str
        .parse()
        .unwrap_or_else(|_| panic!("PayX402 amount must be a float, got {amount_str}"));
    let session_key_id = world.session_key_id.clone().expect("session_key_id must be set");

    // Borrow state mutably for evaluate, capture prior cumulative + allocation
    // into owned values so the mutable borrow ends before we touch audit_log.
    let (decision, prior_cumulative, allocated) = {
        let state = world.policy_state.as_mut().expect("policy_state must be set");
        let prior = state.local_spent_usd;
        let alloc = state.policy.as_ref().map_or(0.0, |p| p.budget_allocation.allocated_usd);
        let req = PayRequest {
            session_key_id: session_key_id.clone(),
            device_id: "dev-test".to_string(),
            amount_usd: amount,
            asset: "USDC".to_string(),
            chain_id: "eip155:8453".to_string(),
            recipient: None,
        };
        let dec = evaluate_11_step(&req, &session_key_id, state);
        (dec, prior, alloc)
    };

    // Construct audit payload per R76 / R38 — record prior cumulative,
    // requested amount, and allocation.
    let payload = match &decision {
        Decision::Deny(reason) => {
            world.last_deny_reason = Some(reason.clone());
            serde_json::json!({
                "status": "denied",
                "reason": "budget_exceeded",
                "prior_cumulative_usd": prior_cumulative,
                "requested_usd": amount,
                "allocated_usd": allocated,
            })
        }
        Decision::Allow => {
            serde_json::json!({"status": "allowed", "amount_usd": amount})
        }
    };

    world.last_decision = Some(decision);
    world.last_audit_event = Some(EventType::PayX402);

    let audit = world.audit_log.as_mut().expect("audit_log must be open");
    audit
        .append(EventType::PayX402, Some(session_key_id), payload)
        .expect("audit append for PayX402 must succeed");
}

/// `Then the local cumulative spend becomes {amount} USD which exceeds
/// the allocation`.
///
/// Asserts that the asserted cumulative (prior `local_spent_usd` + the
/// requested amount) exceeds the allocation. The next `And` step asserts
/// the DENY decision. Note: because the request was DENIED,
/// `state.local_spent_usd` was NOT incremented by `evaluate_11_step`;
/// the "cumulative" in the feature text refers to prior + requested, not
/// to the persisted counter.
#[then(regex = r"^the local cumulative spend becomes ([0-9.]+) USD which exceeds the allocation$")]
async fn then_local_cumulative_exceeds_allocation(
    world: &mut ConformanceWorld,
    amount_str: String,
) {
    let expected_total: f64 = amount_str
        .parse()
        .unwrap_or_else(|_| panic!("cumulative must be a float, got {amount_str}"));
    let state = world.policy_state.as_ref().expect("policy_state must be set");
    let allocated = state.policy.as_ref().map_or(0.0, |p| p.budget_allocation.allocated_usd);
    assert!(
        expected_total > allocated,
        "cumulative {expected_total} must exceed allocation {allocated}"
    );
}

/// `And the response has status DENY and deny_reason "BUDGET_EXCEEDED"`.
///
/// `BUDGET_EXCEEDED` maps directly to `DenyReason::BudgetExceeded` (R80).
#[then(regex = r#"^the response has status DENY and deny_reason "BUDGET_EXCEEDED"$"#)]
async fn then_response_deny_budget_exceeded(world: &mut ConformanceWorld) {
    assert!(
        matches!(world.last_decision, Some(Decision::Deny(DenyReason::BudgetExceeded))),
        "expected Deny(BudgetExceeded), got {:?}",
        world.last_decision
    );
    assert_eq!(
        world.last_deny_reason,
        Some(DenyReason::BudgetExceeded),
        "expected last_deny_reason = BudgetExceeded"
    );
}

/// `And an audit entry records the prior cumulative, the requested
/// amount, and the allocation`.
///
/// Asserts that a `PayX402` audit entry was appended (the payload,
/// constructed in the `When` step, records `prior_cumulative_usd`,
/// `requested_usd`, and `allocated_usd` per R76 / R38). The chain is
/// then re-verified to ensure the append didn't break integrity.
#[then("an audit entry records the prior cumulative, the requested amount, and the allocation")]
async fn then_audit_records_prior_requested_allocation(world: &mut ConformanceWorld) {
    assert_eq!(
        world.last_audit_event,
        Some(EventType::PayX402),
        "expected PayX402 audit entry recording prior cumulative / requested / allocation"
    );
    let audit = world.audit_log.as_ref().expect("audit_log must be open");
    audit.verify_chain().expect("audit chain must verify after denied PayX402 (budget)");
}

// ---------------------------------------------------------------------------
// Scenario 3: Two devices with hard sub-quotas cannot overspend parent total
// ---------------------------------------------------------------------------

/// `Given device "{device_id}" is allocated {alloc} USD out of parent_total
/// {parent} USD`.
///
/// Scenario 3 needs TWO independent device states (mac-A and mac-B). The
/// World only carries a single `PolicyState`, so we model the two devices
/// as follows:
/// - The FIRST invocation (mac-A) initialises both `world.policy` and `world.policy_state.policy`
///   with mac-A's allocation.
/// - The SECOND invocation (mac-B) overwrites only `world.policy` with mac-B's allocation;
///   `world.policy_state.policy` retains mac-A's values.
///
/// The `When` step then reads mac-A's allocation from
/// `world.policy_state.policy` and mac-B's allocation from `world.policy`,
/// constructs two LOCAL `PolicyState` instances (one per device),
/// evaluates each independently, and sums the resulting `local_spent_usd`
/// values.
#[given(
    regex = r#"^device "([^"]+)" is allocated ([0-9.]+) USD out of parent_total ([0-9.]+) USD$"#
)]
async fn device_allocated_out_of_parent(
    world: &mut ConformanceWorld,
    device_id: String,
    alloc_str: String,
    parent_str: String,
) {
    let allocated: f64 =
        alloc_str.parse().unwrap_or_else(|_| panic!("allocated must be a float, got {alloc_str}"));
    let parent: f64 = parent_str
        .parse()
        .unwrap_or_else(|_| panic!("parent_total must be a float, got {parent_str}"));

    // First invocation (mac-A): initialise world.policy AND
    // world.policy_state.policy with mac-A's allocation.
    //
    // Second invocation (mac-B): overwrite ONLY world.policy with mac-B's
    // allocation; world.policy_state.policy keeps mac-A's values so the
    // When step can read both.
    let is_first_device =
        world.policy_state.as_ref().and_then(|s| s.policy.as_ref()).map_or(true, |p| {
            // The Background sets device_id="dev-test". Once the first
            // Given (mac-A) runs, device_id becomes "mac-A". So if
            // device_id is still "dev-test", this is the first invocation.
            p.device_id == "dev-test"
        });

    if is_first_device {
        if let Some(p) = world.policy.as_mut() {
            p.device_id = device_id.clone();
            p.budget_allocation.allocated_usd = allocated;
            p.budget_allocation.parent_total_usd = parent;
        }
        if let Some(state) = world.policy_state.as_mut() {
            if let Some(p) = state.policy.as_mut() {
                p.device_id = device_id;
                p.budget_allocation.allocated_usd = allocated;
                p.budget_allocation.parent_total_usd = parent;
            }
        }
    } else {
        // Second device — overwrite only world.policy (mac-B). Leave
        // world.policy_state.policy as mac-A so the When step can read
        // both allocations.
        if let Some(p) = world.policy.as_mut() {
            p.device_id = device_id;
            p.budget_allocation.allocated_usd = allocated;
            p.budget_allocation.parent_total_usd = parent;
        }
    }
}

/// `And both devices operate offline from each other`.
///
/// No-op assertion: the pessimistic-budget model is enforced by step 8
/// of `evaluate_11_step`, which only consults device-local state. There
/// is no cross-device synchronization primitive in the Phase 1 design,
/// so "offline" is the default and only mode.
#[given("both devices operate offline from each other")]
async fn both_devices_operate_offline(_world: &mut ConformanceWorld) {
    // No-op: implicit in the design of `evaluate_11_step`'s step 8.
}

/// `When both Agents attempt to spend their full allocations
/// simultaneously`.
///
/// Simulates both devices independently spending their full allocations:
/// 1. Reads mac-A's allocation from `world.policy_state.policy` and builds a LOCAL `PolicyState`
///    for mac-A. Calls `evaluate_11_step` with a request equal to mac-A's full allocation. Asserts
///    ALLOW.
/// 2. Reads mac-B's allocation from `world.policy` and builds a second LOCAL `PolicyState` for
///    mac-B. Calls `evaluate_11_step` with a request equal to mac-B's full allocation. Asserts
///    ALLOW.
/// 3. Sums the two `local_spent_usd` values and stashes the combined spend on `world.last_error`
///    (the only `Option<String>` field available without adding new World fields — T31 owns World
///    edits this wave).
///
/// Both PolicyStates are LOCAL variables (not on the world), which
/// models the "two devices operate offline from each other" assumption:
/// neither device's spend counter is visible to the other.
#[when("both Agents attempt to spend their full allocations simultaneously")]
async fn when_both_agents_attempt_full_spend(world: &mut ConformanceWorld) {
    // Read mac-A's allocation + parent_total from world.policy_state.
    let (mac_a_alloc, mac_a_parent, mac_a_device_id) = {
        let state = world.policy_state.as_ref().expect("policy_state must be set by Background");
        let policy = state.policy.as_ref().expect("policy_state.policy must be set by first Given");
        (
            policy.budget_allocation.allocated_usd,
            policy.budget_allocation.parent_total_usd,
            policy.device_id.clone(),
        )
    };

    // Read mac-B's allocation + parent_total from world.policy.
    let (mac_b_alloc, mac_b_parent, mac_b_device_id) = {
        let policy = world.policy.as_ref().expect("policy must be set by second Given");
        (
            policy.budget_allocation.allocated_usd,
            policy.budget_allocation.parent_total_usd,
            policy.device_id.clone(),
        )
    };

    // Both devices share the same parent_total (set by the Background +
    // per-scenario Givens). Sanity-check this invariant.
    assert_eq!(mac_a_parent, mac_b_parent, "parent_total must match across mac-A and mac-B");

    let session_key_id = world.session_key_id.clone().expect("session_key_id must be set");

    // 1. Build a LOCAL PolicyState for mac-A and evaluate a full-allocation request. We use
    //    `default_test_policy` as the base (so all the non-budget rules are permissive) and then
    //    overwrite the budget fields + device_id.
    let mac_a_policy = {
        let mut p = default_test_policy(&session_key_id);
        p.device_id = mac_a_device_id;
        p.budget_allocation.allocated_usd = mac_a_alloc;
        p.budget_allocation.parent_total_usd = mac_a_parent;
        p
    };
    let mut mac_a_state = PolicyState::new(session_key_id.clone()).with_policy(mac_a_policy);
    let mac_a_req = PayRequest {
        session_key_id: session_key_id.clone(),
        device_id: "mac-A".to_string(),
        amount_usd: mac_a_alloc,
        asset: "USDC".to_string(),
        chain_id: "eip155:8453".to_string(),
        recipient: None,
    };
    let mac_a_decision = evaluate_11_step(&mac_a_req, &session_key_id, &mut mac_a_state);
    assert!(
        matches!(mac_a_decision, Decision::Allow),
        "mac-A full-allocation spend ({mac_a_alloc}) must ALLOW, got {mac_a_decision:?}"
    );

    // 2. Build a LOCAL PolicyState for mac-B and evaluate a full-allocation request.
    let mac_b_policy = {
        let mut p = default_test_policy(&session_key_id);
        p.device_id = mac_b_device_id;
        p.budget_allocation.allocated_usd = mac_b_alloc;
        p.budget_allocation.parent_total_usd = mac_b_parent;
        p
    };
    let mut mac_b_state = PolicyState::new(session_key_id.clone()).with_policy(mac_b_policy);
    let mac_b_req = PayRequest {
        session_key_id: session_key_id.clone(),
        device_id: "mac-B".to_string(),
        amount_usd: mac_b_alloc,
        asset: "USDC".to_string(),
        chain_id: "eip155:8453".to_string(),
        recipient: None,
    };
    let mac_b_decision = evaluate_11_step(&mac_b_req, &session_key_id, &mut mac_b_state);
    assert!(
        matches!(mac_b_decision, Decision::Allow),
        "mac-B full-allocation spend ({mac_b_alloc}) must ALLOW, got {mac_b_decision:?}"
    );

    // 3. Sum the local_spent_usd of both devices and stash the combined spend on world.last_error
    //    (the only Option<String> available without editing the World struct — T31 owns World edits
    //    this wave). The Then step parses this string back to f64.
    let combined = mac_a_state.local_spent_usd + mac_b_state.local_spent_usd;
    world.last_decision = Some(mac_b_decision);
    world.last_error = Some(format!("{combined:.2}"));
}

/// `Then the combined cumulative spend across both devices is at most
/// {amount} USD`.
///
/// Reads the combined spend stashed by the `When` step and asserts it
/// does not exceed the asserted upper bound.
#[then(regex = r"^the combined cumulative spend across both devices is at most ([0-9.]+) USD$")]
async fn then_combined_spend_at_most(world: &mut ConformanceWorld, max_str: String) {
    let max_spend: f64 =
        max_str.parse().unwrap_or_else(|_| panic!("max spend must be a float, got {max_str}"));
    let combined: f64 = world
        .last_error
        .as_ref()
        .expect("combined spend must be stashed in last_error by the When step")
        .parse()
        .expect("last_error must be a float stashed by the When step");
    assert!(combined <= max_spend + 1e-9, "combined spend {combined} must be ≤ {max_spend}");
}

/// `And the parent_total of {parent} USD is never exceeded because the
/// reserve pool of {reserve} USD is untouched`.
///
/// Asserts:
/// 1. Combined spend ≤ parent_total (the parent total is never exceeded).
/// 2. parent_total - combined_spend == reserve (the reserve pool of `reserve` USD is left
///    untouched, i.e. neither device dipped into the parent's reserve).
#[then(
    regex = r"^the parent_total of ([0-9.]+) USD is never exceeded because the reserve pool of ([0-9.]+) USD is untouched$"
)]
async fn then_parent_total_not_exceeded(
    world: &mut ConformanceWorld,
    parent_str: String,
    reserve_str: String,
) {
    let parent_total: f64 = parent_str
        .parse()
        .unwrap_or_else(|_| panic!("parent_total must be a float, got {parent_str}"));
    let reserve: f64 = reserve_str
        .parse()
        .unwrap_or_else(|_| panic!("reserve must be a float, got {reserve_str}"));
    let combined: f64 = world
        .last_error
        .as_ref()
        .expect("combined spend must be stashed in last_error by the When step")
        .parse()
        .expect("last_error must be a float stashed by the When step");
    assert!(
        combined <= parent_total + 1e-9,
        "combined spend {combined} must not exceed parent_total {parent_total}"
    );
    let actual_reserve = parent_total - combined;
    assert!(
        (actual_reserve - reserve).abs() < 1e-9,
        "reserve pool: expected {reserve}, got {actual_reserve} \
         (parent_total={parent_total}, combined={combined})"
    );
}

// ---------------------------------------------------------------------------
// Scenario 4: Budget reclaim on Session Key revocation
// ---------------------------------------------------------------------------

/// `Given a Session Key on device "{device_id}" has spent {spent} USD of
/// its {alloc} USD allocation`.
///
/// Sets `budget_allocation.allocated_usd = alloc` and
/// `state.local_spent_usd = spent` on both `world.policy` and
/// `world.policy_state`. Also records the `device_id` on the policy
/// (informational; the assertions key off `session_key_id`, not
/// `device_id`).
#[given(
    regex = r#"^a Session Key on device "([^"]+)" has spent ([0-9.]+) USD of its ([0-9.]+) USD allocation$"#
)]
async fn given_session_key_spent_of_allocation(
    world: &mut ConformanceWorld,
    device_id: String,
    spent_str: String,
    alloc_str: String,
) {
    let spent: f64 =
        spent_str.parse().unwrap_or_else(|_| panic!("spent must be a float, got {spent_str}"));
    let allocated: f64 =
        alloc_str.parse().unwrap_or_else(|_| panic!("allocated must be a float, got {alloc_str}"));
    assert!(spent <= allocated, "prior spent ({spent}) must not exceed allocation ({allocated})");
    if let Some(p) = world.policy.as_mut() {
        p.device_id = device_id.clone();
        p.budget_allocation.allocated_usd = allocated;
    }
    if let Some(state) = world.policy_state.as_mut() {
        if let Some(p) = state.policy.as_mut() {
            p.device_id = device_id;
            p.budget_allocation.allocated_usd = allocated;
        }
        state.local_spent_usd = spent;
    }
}

/// `When the Owner revokes the Session Key`.
///
/// Simulates revocation per the T27 design:
/// 1. Computes the remaining budget = `allocated - local_spent`.
/// 2. Sets `world.policy_state.policy = None` so subsequent `evaluate_11_step` calls return
///    `Deny(PolicyMissing)` from step 2.
/// 3. Appends a `BudgetReclaim` audit entry with `{reclaimed_usd, session_key_id, device_id}` per
///    R40 / R41.
/// 4. Stashes the reclaimed amount on `world.last_error` for the subsequent `Then the remaining ...
///    USD is returned to the parent reserve pool` step.
#[when("the Owner revokes the Session Key")]
async fn when_owner_revokes_session_key(world: &mut ConformanceWorld) {
    let (allocated, spent, device_id) = {
        let state = world.policy_state.as_ref().expect("policy_state must be set by Background");
        let policy = state.policy.as_ref().expect("policy must be set by Given step");
        (policy.budget_allocation.allocated_usd, state.local_spent_usd, policy.device_id.clone())
    };
    let reclaimed = allocated - spent;

    // 1. Revoke: set policy_state.policy = None so step_2 returns PolicyMissing on subsequent
    //    evaluate_11_step calls.
    if let Some(state) = world.policy_state.as_mut() {
        state.policy = None;
    }

    // 2. Append a BudgetReclaim audit entry with the reclaimed amount.
    let session_key_id = world.session_key_id.clone().expect("session_key_id must be set");
    let payload = serde_json::json!({
        "reclaimed_usd": reclaimed,
        "session_key_id": session_key_id,
        "device_id": device_id,
        "allocated_usd": allocated,
        "spent_usd": spent,
    });
    let audit = world.audit_log.as_mut().expect("audit_log must be open");
    audit
        .append(EventType::BudgetReclaim, Some(session_key_id), payload)
        .expect("audit append for BudgetReclaim must succeed");
    world.last_audit_event = Some(EventType::BudgetReclaim);

    // 3. Stash the reclaimed amount for the Then step.
    world.last_error = Some(format!("{reclaimed:.2}"));
}

/// `Then the remaining {amount} USD is returned to the parent reserve
/// pool`.
///
/// Asserts that the reclaimed amount (stashed by the `When` step) equals
/// the asserted remaining amount. The "parent reserve pool" is
/// conceptual: in the Phase 1 pessimistic-budget model, revocation
/// returns the unspent portion of the device's allocation to the parent
/// wallet's available pool (R40 / R41).
#[then(regex = r"^the remaining ([0-9.]+) USD is returned to the parent reserve pool$")]
async fn then_remaining_returned_to_reserve(world: &mut ConformanceWorld, amount_str: String) {
    let expected: f64 = amount_str
        .parse()
        .unwrap_or_else(|_| panic!("remaining must be a float, got {amount_str}"));
    let reclaimed: f64 = world
        .last_error
        .as_ref()
        .expect("reclaimed amount must be stashed in last_error by the When step")
        .parse()
        .expect("last_error must be a float stashed by the When step");
    assert!(
        (reclaimed - expected).abs() < 1e-9,
        "reclaimed amount: expected {expected}, got {reclaimed}"
    );
}

/// `And the local Policy Engine on device "{device_id}" denies all
/// subsequent requests for that session_key_id`.
///
/// Calls `evaluate_11_step` against the (now-revoked) `PolicyState` and
/// asserts `Deny(PolicyMissing)`. After revocation,
/// `state.policy = None`, so step 2 of the 11-step flow returns
/// `PolicyMissing` for any subsequent request.
#[then(
    regex = r#"^the local Policy Engine on device "([^"]+)" denies all subsequent requests for that session_key_id$"#
)]
async fn then_local_engine_denies_subsequent(world: &mut ConformanceWorld, _device_id: String) {
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
    assert!(
        matches!(decision, Decision::Deny(DenyReason::PolicyMissing)),
        "post-revocation request must DENY(PolicyMissing), got {decision:?}"
    );
    world.last_decision = Some(decision);
    world.last_deny_reason = Some(DenyReason::PolicyMissing);
}

/// `And an audit entry of event_type BUDGET_RECLAIM is appended with the
/// reclaimed amount`.
///
/// Asserts:
/// 1. `world.last_audit_event == Some(EventType::BudgetReclaim)`.
/// 2. The audit log file (read directly from `world.audit_path`) contains at least one entry with
///    `event_type == BudgetReclaim` and `payload.reclaimed_usd == 1.20` (the expected reclaim
///    amount for this scenario: 3.00 - 1.80 = 1.20).
/// 3. The audit chain still verifies after the append (integrity).
#[then("an audit entry of event_type BUDGET_RECLAIM is appended with the reclaimed amount")]
async fn then_audit_budget_reclaim_appended(world: &mut ConformanceWorld) {
    assert_eq!(
        world.last_audit_event,
        Some(EventType::BudgetReclaim),
        "expected last_audit_event = BudgetReclaim"
    );

    // Read the audit log file directly and find the BUDGET_RECLAIM entry.
    let audit_path = world.audit_path.as_ref().expect("audit_path must be set by Background");
    let content = std::fs::read_to_string(audit_path).expect("audit log must be readable");

    let mut found_reclaim = false;
    for line in content.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let entry: AuditEntry = match serde_json::from_str(line) {
            Ok(e) => e,
            Err(_) => continue,
        };
        if entry.event_type == EventType::BudgetReclaim {
            let reclaimed = entry
                .payload
                .get("reclaimed_usd")
                .and_then(|v| v.as_f64())
                .expect("BUDGET_RECLAIM payload must have reclaimed_usd");
            // Expected: 3.00 (allocated) - 1.80 (spent) = 1.20.
            assert!(
                (reclaimed - 1.20).abs() < 1e-9,
                "reclaimed_usd in audit payload: expected 1.20, got {reclaimed}"
            );
            found_reclaim = true;
            break;
        }
    }
    assert!(
        found_reclaim,
        "audit log must contain a BUDGET_RECLAIM entry with the reclaimed amount"
    );

    // Re-verify the audit chain to ensure the BudgetReclaim append didn't
    // break integrity.
    let audit = world.audit_log.as_ref().expect("audit_log must be open");
    audit.verify_chain().expect("audit chain must verify after BudgetReclaim append");
}
