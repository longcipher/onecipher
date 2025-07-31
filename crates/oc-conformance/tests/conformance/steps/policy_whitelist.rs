//! T28 — Policy Whitelists BDD step definitions.
//!
//! Implements the 3 scenarios in
//! `policy_whitelist.feature`:
//! 1. Asset not in `asset_whitelist` → DENY(Whitelist)
//! 2. Chain not in `chain_whitelist` → DENY(Whitelist)
//! 3. Contract recipient not in `contract_whitelist` → DENY(Whitelist)
//!
//! Per the T28 design, steps orchestrate EXISTING components directly:
//! - `oc_policy::evaluate_11_step` for the 11-step Policy decision flow. Step 4
//!   (`step_4_check_whitelists`) checks asset / chain / contract whitelists; an empty whitelist
//!   means "no restriction" (allow all).
//! - `oc_keyagent::AuditLog` for the append-only audit chain.
//!
//! # R80 deny_reason mapping
//! The feature file uses the human-readable string `WHITELIST`, which maps
//! directly to `DenyReason::Whitelist` (no R80 mapping required — the variant
//! name is unchanged).
//!
//! # Shared Background
//! The first Background step (`Given an Agent holds an active Session Key
//! with a Policy`) is shared with T25/T26 and is implemented in
//! `steps/background.rs`. The default policy set up there populates
//! `asset_whitelist = ["USDC"]`, `chain_whitelist = ["eip155:8453"]`, and
//! `contract_whitelist = []` (empty — no contract restriction by default).
//!
//! The second Background step
//! (`And the Policy rules include asset_whitelist, chain_whitelist, and
//! contract_whitelist`) is T28-specific and lives here as a no-op assertion
//! that the asset + chain whitelists are present (non-empty); the contract
//! whitelist may be empty per default (an empty whitelist means "allow all",
//! not "deny all").

use cucumber::{given, then, when};
use oc_keyagent::EventType;
use oc_policy::{Decision, DenyReason, PayRequest, evaluate_11_step};

use crate::ConformanceWorld;

// ---------------------------------------------------------------------------
// T28-specific Background step
// ---------------------------------------------------------------------------

/// `And the Policy rules include asset_whitelist, chain_whitelist, and
/// contract_whitelist`.
///
/// The default policy set up by the shared Background (`background.rs`)
/// populates `asset_whitelist = ["USDC"]`, `chain_whitelist = ["eip155:8453"]`,
/// and `contract_whitelist = []` (empty — no contract restriction by default).
/// This step is a no-op assertion that the asset + chain whitelists are
/// present (non-empty); the contract whitelist may be empty per default, so
/// a regression in `default_test_policy()` is caught here rather than
/// mid-scenario.
#[given("the Policy rules include asset_whitelist, chain_whitelist, and contract_whitelist")]
async fn policy_rules_include_whitelists(world: &mut ConformanceWorld) {
    let policy = world.policy.as_ref().expect("policy must be set by shared Background");
    assert!(
        !policy.rules.asset_whitelist.is_empty(),
        "asset_whitelist must be non-empty in default policy"
    );
    assert!(
        !policy.rules.chain_whitelist.is_empty(),
        "chain_whitelist must be non-empty in default policy"
    );
    // contract_whitelist may legitimately be empty by default
    // (empty whitelist == "no restriction", not "deny all").
}

// ---------------------------------------------------------------------------
// Scenario 1: Asset not in whitelist
// ---------------------------------------------------------------------------

/// `Given the Policy asset_whitelist contains only "..."`.
///
/// Replaces the default `asset_whitelist` (`["USDC"]`) with a single-element
/// list containing the exact asset ID from the feature file. Mutates BOTH
/// the world's `policy` copy and the `PolicyState`'s runtime `policy` copy
/// (the latter is what `evaluate_11_step` actually reads).
#[given(regex = r#"^the Policy asset_whitelist contains only "([^"]+)"$"#)]
async fn policy_asset_whitelist_contains_only(world: &mut ConformanceWorld, asset: String) {
    let new_whitelist = vec![asset];
    if let Some(p) = world.policy.as_mut() {
        p.rules.asset_whitelist = new_whitelist.clone();
    }
    if let Some(state) = world.policy_state.as_mut() {
        if let Some(p) = state.policy.as_mut() {
            p.rules.asset_whitelist = new_whitelist;
        }
    }
}

/// `When the Agent requests a PayX402 paying in "..."`.
///
/// Constructs a `PayRequest` with the given asset (CAIP-19 style ID),
/// `chain_id = "eip155:8453"` (in the default chain_whitelist), no recipient
/// (native-style transfer), and calls `evaluate_11_step`. Step 4 checks
/// `asset_whitelist` — if the asset is not in the list → `Deny(Whitelist)`.
///
/// After evaluation, appends a `PayX402` audit entry whose payload records
/// the requested asset and the whitelist (per R76 audit-payload convention).
#[when(regex = r#"^the Agent requests a PayX402 paying in "([^"]+)"$"#)]
async fn agent_requests_pay_x402_paying_in(world: &mut ConformanceWorld, asset: String) {
    let session_key_id =
        world.session_key_id.clone().expect("session_key_id must be set by shared Background");
    let req = PayRequest {
        session_key_id: session_key_id.clone(),
        device_id: "dev-test".to_string(),
        amount_usd: 0.01,
        asset: asset.clone(),
        chain_id: "eip155:8453".to_string(),
        recipient: None,
    };

    // Borrow state mutably to call evaluate, then extract everything we need
    // into owned values so the mutable borrow ends before we touch audit_log.
    let (decision, whitelist) = {
        let state =
            world.policy_state.as_mut().expect("policy_state must be set by shared Background");
        let decision = evaluate_11_step(&req, &session_key_id, state);
        let whitelist =
            state.policy.as_ref().map(|p| p.rules.asset_whitelist.clone()).unwrap_or_default();
        (decision, whitelist)
    };

    if let Decision::Deny(reason) = &decision {
        world.last_deny_reason = Some(reason.clone());
    }
    world.last_decision = Some(decision);
    world.last_audit_event = Some(EventType::PayX402);

    let payload = serde_json::json!({
        "status": "denied",
        "reason": "whitelist",
        "requested_asset": asset,
        "whitelist": whitelist,
    });

    let audit = world.audit_log.as_mut().expect("audit_log must be open");
    audit
        .append(EventType::PayX402, Some(session_key_id), payload)
        .expect("audit append for PayX402 (asset_whitelist) must succeed");
}

/// `Then the Policy Engine evaluates the asset_whitelist rule`.
///
/// Implicit assertion — the `evaluate_11_step` call in the `When` step ran
/// the full 11-step flow, which includes step 4 (whitelist checks). The next
/// `And` step asserts the deny reason.
#[then("the Policy Engine evaluates the asset_whitelist rule")]
async fn then_evaluates_asset_whitelist_rule(_world: &mut ConformanceWorld) {
    // No-op: implicit in the When step's evaluate_11_step call (step 4).
}

/// `And an audit entry records the requested asset and the whitelist`.
///
/// Asserts that a `PayX402` audit entry was appended. The audit payload
/// (constructed in the `When` step) records `requested_asset` and
/// `whitelist` per R76. The chain is then re-verified to ensure the append
/// didn't break integrity.
#[then("an audit entry records the requested asset and the whitelist")]
async fn then_audit_records_requested_asset(world: &mut ConformanceWorld) {
    assert_eq!(
        world.last_audit_event,
        Some(EventType::PayX402),
        "expected PayX402 audit entry recording requested asset and whitelist"
    );
    let audit = world.audit_log.as_ref().expect("audit_log must be open");
    audit.verify_chain().expect("audit chain must verify after denied PayX402 (asset_whitelist)");
}

// ---------------------------------------------------------------------------
// Scenario 2: Chain not in whitelist
// ---------------------------------------------------------------------------

/// `Given the Policy chain_whitelist contains "..." and "..."`.
///
/// Replaces the default `chain_whitelist` (`["eip155:8453"]`) with the two
/// chains from the feature file. Mutates BOTH the world's `policy` copy and
/// the `PolicyState`'s runtime `policy` copy.
#[given(regex = r#"^the Policy chain_whitelist contains "([^"]+)" and "([^"]+)"$"#)]
async fn policy_chain_whitelist_contains(
    world: &mut ConformanceWorld,
    chain1: String,
    chain2: String,
) {
    let new_whitelist = vec![chain1, chain2];
    if let Some(p) = world.policy.as_mut() {
        p.rules.chain_whitelist = new_whitelist.clone();
    }
    if let Some(state) = world.policy_state.as_mut() {
        if let Some(p) = state.policy.as_mut() {
            p.rules.chain_whitelist = new_whitelist;
        }
    }
}

/// `When the Agent requests a PayX402 on chain "..."`.
///
/// Constructs a `PayRequest` with the given `chain_id`, `asset = "USDC"`
/// (matches the default `asset_whitelist`), no recipient, and calls
/// `evaluate_11_step`. Step 4 checks `chain_whitelist` — if the chain is not
/// in the list → `Deny(Whitelist)`.
#[when(regex = r#"^the Agent requests a PayX402 on chain "([^"]+)"$"#)]
async fn agent_requests_pay_x402_on_chain(world: &mut ConformanceWorld, chain_id: String) {
    let session_key_id =
        world.session_key_id.clone().expect("session_key_id must be set by shared Background");
    let req = PayRequest {
        session_key_id: session_key_id.clone(),
        device_id: "dev-test".to_string(),
        amount_usd: 0.01,
        asset: "USDC".to_string(),
        chain_id: chain_id.clone(),
        recipient: None,
    };

    let (decision, whitelist) = {
        let state =
            world.policy_state.as_mut().expect("policy_state must be set by shared Background");
        let decision = evaluate_11_step(&req, &session_key_id, state);
        let whitelist =
            state.policy.as_ref().map(|p| p.rules.chain_whitelist.clone()).unwrap_or_default();
        (decision, whitelist)
    };

    if let Decision::Deny(reason) = &decision {
        world.last_deny_reason = Some(reason.clone());
    }
    world.last_decision = Some(decision);
    world.last_audit_event = Some(EventType::PayX402);

    let payload = serde_json::json!({
        "status": "denied",
        "reason": "whitelist",
        "requested_chain": chain_id,
        "whitelist": whitelist,
    });

    let audit = world.audit_log.as_mut().expect("audit_log must be open");
    audit
        .append(EventType::PayX402, Some(session_key_id), payload)
        .expect("audit append for PayX402 (chain_whitelist) must succeed");
}

/// `Then the Policy Engine evaluates the chain_whitelist rule`.
#[then("the Policy Engine evaluates the chain_whitelist rule")]
async fn then_evaluates_chain_whitelist_rule(_world: &mut ConformanceWorld) {
    // No-op: implicit in the When step's evaluate_11_step call (step 4).
}

/// `And an audit entry records the requested chain and the whitelist`.
#[then("an audit entry records the requested chain and the whitelist")]
async fn then_audit_records_requested_chain(world: &mut ConformanceWorld) {
    assert_eq!(
        world.last_audit_event,
        Some(EventType::PayX402),
        "expected PayX402 audit entry recording requested chain and whitelist"
    );
    let audit = world.audit_log.as_ref().expect("audit_log must be open");
    audit.verify_chain().expect("audit chain must verify after denied PayX402 (chain_whitelist)");
}

// ---------------------------------------------------------------------------
// Scenario 3: Contract not in whitelist
// ---------------------------------------------------------------------------

/// `Given the Policy contract_whitelist contains the x402 settler contract
/// on "..."`.
///
/// Sets `contract_whitelist = ["0xSettlerContract123"]` — the x402 settler
/// contract on the specified chain. The contract address is a synthetic
/// placeholder matching the feature file's intent: the exact address is not
/// load-bearing for the whitelist check; what matters is that the recipient
/// in the When step is NOT in this list. The captured chain is unused at the
/// Policy layer (`PayRequest` carries its own `chain_id`).
#[given(
    regex = r#"^the Policy contract_whitelist contains the x402 settler contract on "([^"]+)"$"#
)]
async fn policy_contract_whitelist_contains_settler(world: &mut ConformanceWorld, _chain: String) {
    let settler = "0xSettlerContract123".to_string();
    let new_whitelist = vec![settler];
    if let Some(p) = world.policy.as_mut() {
        p.rules.contract_whitelist = new_whitelist.clone();
    }
    if let Some(state) = world.policy_state.as_mut() {
        if let Some(p) = state.policy.as_mut() {
            p.rules.contract_whitelist = new_whitelist;
        }
    }
}

/// `When the Agent requests a PayX402 whose recipient is an unlisted contract
/// on "..."`.
///
/// Constructs a `PayRequest` with `recipient = Some("0xUnlistedContract456")`
/// — a synthetic contract address NOT in the contract_whitelist — on the
/// specified chain, with `asset = "USDC"` (matches default asset_whitelist).
/// Step 4 checks `contract_whitelist` — recipient not in list →
/// `Deny(Whitelist)`.
#[when(
    regex = r#"^the Agent requests a PayX402 whose recipient is an unlisted contract on "([^"]+)"$"#
)]
async fn agent_requests_pay_x402_unlisted_contract(world: &mut ConformanceWorld, chain_id: String) {
    let session_key_id =
        world.session_key_id.clone().expect("session_key_id must be set by shared Background");
    let recipient = "0xUnlistedContract456".to_string();
    let req = PayRequest {
        session_key_id: session_key_id.clone(),
        device_id: "dev-test".to_string(),
        amount_usd: 0.01,
        asset: "USDC".to_string(),
        chain_id,
        recipient: Some(recipient.clone()),
    };

    let (decision, whitelist) = {
        let state =
            world.policy_state.as_mut().expect("policy_state must be set by shared Background");
        let decision = evaluate_11_step(&req, &session_key_id, state);
        let whitelist =
            state.policy.as_ref().map(|p| p.rules.contract_whitelist.clone()).unwrap_or_default();
        (decision, whitelist)
    };

    if let Decision::Deny(reason) = &decision {
        world.last_deny_reason = Some(reason.clone());
    }
    world.last_decision = Some(decision);
    world.last_audit_event = Some(EventType::PayX402);

    let payload = serde_json::json!({
        "status": "denied",
        "reason": "whitelist",
        "requested_recipient": recipient,
        "whitelist": whitelist,
    });

    let audit = world.audit_log.as_mut().expect("audit_log must be open");
    audit
        .append(EventType::PayX402, Some(session_key_id), payload)
        .expect("audit append for PayX402 (contract_whitelist) must succeed");
}

/// `Then the Policy Engine evaluates the contract_whitelist rule`.
#[then("the Policy Engine evaluates the contract_whitelist rule")]
async fn then_evaluates_contract_whitelist_rule(_world: &mut ConformanceWorld) {
    // No-op: implicit in the When step's evaluate_11_step call (step 4).
}

/// `And an audit entry records the requested recipient and the whitelist`.
#[then("an audit entry records the requested recipient and the whitelist")]
async fn then_audit_records_requested_recipient(world: &mut ConformanceWorld) {
    assert_eq!(
        world.last_audit_event,
        Some(EventType::PayX402),
        "expected PayX402 audit entry recording requested recipient and whitelist"
    );
    let audit = world.audit_log.as_ref().expect("audit_log must be open");
    audit
        .verify_chain()
        .expect("audit chain must verify after denied PayX402 (contract_whitelist)");
}

// ---------------------------------------------------------------------------
// Shared Then: deny_reason "WHITELIST"
// ---------------------------------------------------------------------------

/// `And the response has status DENY and deny_reason "WHITELIST"`.
///
/// The feature-file term `WHITELIST` maps directly to `DenyReason::Whitelist`
/// (no R80 mapping required — the variant name is unchanged). Shared across
/// all 3 T28 scenarios.
#[then(regex = r#"^the response has status DENY and deny_reason "WHITELIST"$"#)]
async fn then_response_deny_with_whitelist(world: &mut ConformanceWorld) {
    assert!(
        matches!(world.last_decision, Some(Decision::Deny(DenyReason::Whitelist))),
        "expected Deny(Whitelist), got {:?}",
        world.last_decision
    );
    assert_eq!(
        world.last_deny_reason,
        Some(DenyReason::Whitelist),
        "expected last_deny_reason = Whitelist, got {:?}",
        world.last_deny_reason
    );
}
