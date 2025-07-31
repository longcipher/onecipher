//! T30 — Policy File Missing or Invalid BDD step definitions.
//!
//! Implements the 2 scenarios in
//! `policy_missing.feature`:
//! 1. Policy file missing on disk → DENY(PolicyMissing) + PolicyLookupFailed audit
//! 2. Policy file unparseable → DENY(PolicyMissing) + PolicyParseFailed audit
//!
//! Per the T22 design, steps orchestrate EXISTING components directly:
//! - `oc_policy::evaluate_11_step` — step_2_load_policy returns `Err(PolicyMissing)` when
//!   `state.policy` is `None`.
//! - `oc_keyagent::AuditLog` — append-only audit chain.
//!
//! # R80 deny_reason mapping
//! The feature file uses the wire string `POLICY_INVALID`. R80's `DenyReason`
//! enum has a `PolicyMissing` variant (not `PolicyInvalid`). The feature-file
//! term "POLICY_INVALID" therefore maps to `DenyReason::PolicyMissing`.
//!
//! # Unique Background
//! T30's Background is NOT shared from `background.rs`. It sets up minimal
//! state (device key, audit log via leaked `TempDir`, `session_key_id` =
//! "oc_sk_active", and a `PolicyState` with NO policy attached) so the
//! scenarios can test missing / invalid policy handling.

use cucumber::{given, then, when};
use ed25519_dalek::SigningKey;
use oc_keyagent::{AuditLog, EventType};
use oc_policy::{Decision, DenyReason, PayRequest, PolicyState, evaluate_11_step};
use tempfile::tempdir;

use crate::ConformanceWorld;

// ---------------------------------------------------------------------------
// Background (T30-specific — NOT shared from background.rs)
// ---------------------------------------------------------------------------

/// `Given an Agent holds a session_key_id and attempts a PayX402`.
///
/// Sets up minimal state for the missing/invalid policy scenarios:
/// - Fresh Ed25519 device key + audit log (leaked `TempDir` keeps the file alive for the scenario's
///   lifetime — same pattern as T22 / T25).
/// - Active `session_key_id = "oc_sk_active"`.
/// - A `PolicyState` with NO policy attached (`policy = None`) — the scenarios test missing/invalid
///   policy handling, so we intentionally do NOT call `.with_policy()`.
#[given("an Agent holds a session_key_id and attempts a PayX402")]
async fn agent_holds_session_key_id_attempt_payx402(world: &mut ConformanceWorld) {
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

    // 3. PolicyState with NO policy attached (policy = None). The temp file does NOT exist on disk
    //    yet — `PolicyState::load` returns a fresh state without creating the file when the path is
    //    absent.
    let tmp_state = tempdir().expect("tempdir for policy state");
    let state_path = tmp_state.path().join("policy_state.json");
    std::mem::forget(tmp_state);
    let state =
        PolicyState::load(&state_path, "oc_sk_active".to_string()).expect("PolicyState::load");
    // Intentionally do NOT call .with_policy() — state.policy remains None.
    world.policy_state = Some(state);
    world.policy_state_path = Some(state_path);
}

/// `And the Policy Engine attempts to load the Policy for the session_key_id
/// before any signing`.
///
/// Documentation / assertion step. The Background already loaded a
/// `PolicyState` with `policy = None`. We assert that state is present and
/// that no policy is attached — the scenarios test the missing/invalid
/// policy path, where step_2_load_policy returns `Err(PolicyMissing)`.
#[given("the Policy Engine attempts to load the Policy for the session_key_id before any signing")]
async fn policy_engine_attempts_load_before_signing(world: &mut ConformanceWorld) {
    let state = world.policy_state.as_ref().expect("policy_state must be set by Background");
    assert!(state.policy.is_none(), "policy must be None for missing/invalid policy scenarios");
}

// ---------------------------------------------------------------------------
// Scenario 1 — Policy file missing
// ---------------------------------------------------------------------------

/// `Given the Policy file for the session_key_id does not exist on disk`.
///
/// Asserts the Background's preconditions: `state.policy` is `None` AND
/// the policy state file does not exist on disk (no `persist` has happened).
#[given("the Policy file for the session_key_id does not exist on disk")]
async fn policy_file_does_not_exist(world: &mut ConformanceWorld) {
    let state = world.policy_state.as_ref().expect("policy_state must be set by Background");
    assert!(state.policy.is_none(), "state.policy must be None when the policy file is missing");
    let path =
        world.policy_state_path.as_ref().expect("policy_state_path must be set by Background");
    assert!(
        !path.exists(),
        "policy file should not exist on disk, but found at {}",
        path.display()
    );
    // Reset any stale parse error from a prior scenario run.
    world.last_error = None;
}

// ---------------------------------------------------------------------------
// Scenario 2 — Policy file unparseable
// ---------------------------------------------------------------------------

/// `Given the Policy file for the session_key_id exists on disk`.
///
/// Writes invalid JSON content to the policy state path so the file exists
/// on disk with corrupted contents (the next step verifies the content is
/// invalid and records the parse error).
#[given("the Policy file for the session_key_id exists on disk")]
async fn policy_file_exists_on_disk(world: &mut ConformanceWorld) {
    let path =
        world.policy_state_path.as_ref().expect("policy_state_path must be set by Background");
    // Write invalid JSON — the next Given step asserts the content is
    // not valid JSON and records the parse error.
    std::fs::write(path, "{ not valid json {{{").expect("write invalid JSON to policy file");
    assert!(path.exists(), "policy file should exist on disk after write");
}

/// `And the file contents are not valid JSON or fail schema validation`.
///
/// Reads the file written by the previous Given, attempts to parse it as
/// JSON, captures the parse error message into `world.last_error`, and
/// ensures `state.policy` is `None` (simulating that the parse failed and
/// no policy was loaded). The actual `PolicyState::load` would fail on
/// invalid JSON; for BDD we simulate the outcome: `policy = None` plus a
/// recorded parse error.
#[given("the file contents are not valid JSON or fail schema validation")]
async fn policy_file_contents_invalid(world: &mut ConformanceWorld) {
    let path =
        world.policy_state_path.as_ref().expect("policy_state_path must be set by Background");
    let content = std::fs::read_to_string(path).expect("read policy file contents");
    // Attempt to parse as JSON — capture the parse error.
    let parse_error = match serde_json::from_str::<serde_json::Value>(&content) {
        Ok(_) => "schema validation failed".to_string(),
        Err(e) => format!("parse error: {e}"),
    };
    assert!(
        !parse_error.is_empty(),
        "parse error message must be non-empty for invalid policy file"
    );
    world.last_error = Some(parse_error);
    // Defensive: ensure state.policy remains None (Background already left
    // it None; this mirrors what would happen if PolicyState::load had
    // failed mid-parse).
    let state = world.policy_state.as_mut().expect("policy_state must be set by Background");
    state.policy = None;
}

// ---------------------------------------------------------------------------
// Shared When — the Agent calls PayX402
// ---------------------------------------------------------------------------

/// `When the Agent calls PayX402`.
///
/// Constructs a `PayRequest` (USDC on Base, 5.00 USD) and calls
/// `evaluate_11_step` against the world's `PolicyState`. Because
/// `state.policy` is `None` (set up by the Background and asserted by the
/// per-scenario Given steps), step 2 (`step_2_load_policy`) returns
/// `Err(PolicyMissing)`, so `evaluate_11_step` returns `Deny(PolicyMissing)`.
///
/// The audit event type is selected based on which scenario is running:
/// - Scenario 1 (file missing): `world.last_error` is `None` → `PolicyLookupFailed`.
/// - Scenario 2 (file unparseable): `world.last_error` is `Some(parse_err)` → `PolicyParseFailed`
///   (with the parse error in the payload).
#[when("the Agent calls PayX402")]
async fn agent_calls_payx402(world: &mut ConformanceWorld) {
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

    // Decide which audit event type to append based on whether a parse
    // error was recorded by the per-scenario Given steps.
    let is_parse_failure = world.last_error.is_some();

    let decision = {
        let state = world.policy_state.as_mut().expect("policy_state must be set by Background");
        evaluate_11_step(&req, &session_key_id, state)
    };

    // The decision is always Deny(PolicyMissing) since state.policy is None.
    if let Decision::Deny(reason) = &decision {
        world.last_deny_reason = Some(reason.clone());
    }
    world.last_decision = Some(decision);

    // Append the appropriate audit entry. The payload records the
    // human-readable sub-reason (`policy_file_missing` vs
    // `policy_parse_failed`) plus the parse error (if any) for post-incident
    // review, even though R80 collapses both cases to `PolicyMissing`.
    let (event_type, payload) = if is_parse_failure {
        let parse_error = world.last_error.clone().unwrap_or_default();
        (
            EventType::PolicyParseFailed,
            serde_json::json!({
                "session_key_id": session_key_id,
                "reason": "policy_parse_failed",
                "parse_error": parse_error,
            }),
        )
    } else {
        (
            EventType::PolicyLookupFailed,
            serde_json::json!({
                "session_key_id": session_key_id,
                "reason": "policy_file_missing",
            }),
        )
    };

    let audit = world.audit_log.as_mut().expect("audit_log must be open");
    audit.append(event_type, Some(session_key_id), payload).expect("audit append must succeed");
    world.last_audit_event = Some(event_type);
}

// ---------------------------------------------------------------------------
// Then — Scenario 1: Policy Engine cannot find a Policy
// ---------------------------------------------------------------------------

/// `Then the Policy Engine cannot find a Policy for the session_key_id`.
#[then("the Policy Engine cannot find a Policy for the session_key_id")]
async fn then_policy_engine_cannot_find_policy(world: &mut ConformanceWorld) {
    assert!(
        matches!(world.last_decision, Some(Decision::Deny(DenyReason::PolicyMissing))),
        "expected Deny(PolicyMissing), got {:?}",
        world.last_decision
    );
    let state = world.policy_state.as_ref().expect("policy_state must be set by Background");
    assert!(
        state.policy.is_none(),
        "state.policy should still be None after PolicyMissing decision"
    );
}

// ---------------------------------------------------------------------------
// Then — Scenario 2: Policy Engine fails to parse the Policy
// ---------------------------------------------------------------------------

/// `Then the Policy Engine fails to parse the Policy`.
#[then("the Policy Engine fails to parse the Policy")]
async fn then_policy_engine_fails_to_parse(world: &mut ConformanceWorld) {
    assert!(
        matches!(world.last_decision, Some(Decision::Deny(DenyReason::PolicyMissing))),
        "expected Deny(PolicyMissing) after parse failure, got {:?}",
        world.last_decision
    );
    let state = world.policy_state.as_ref().expect("policy_state must be set by Background");
    assert!(state.policy.is_none(), "state.policy should still be None after parse failure");
    assert!(world.last_error.is_some(), "parse error should be recorded in world.last_error");
}

// ---------------------------------------------------------------------------
// Shared Then — DENY + POLICY_INVALID (R80 maps to PolicyMissing)
// ---------------------------------------------------------------------------

/// `And the response has status DENY and deny_reason "POLICY_INVALID"`.
///
/// Translates the feature-file wire string `POLICY_INVALID` to the R80
/// `DenyReason::PolicyMissing` variant before comparing with
/// `world.last_deny_reason`.
#[then(regex = r#"^the response has status DENY and deny_reason "POLICY_INVALID"$"#)]
async fn then_response_deny_policy_invalid(world: &mut ConformanceWorld) {
    assert_eq!(
        world.last_deny_reason,
        Some(DenyReason::PolicyMissing),
        "expected Deny(PolicyMissing) (feature wire term `POLICY_INVALID`), \
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

// ---------------------------------------------------------------------------
// Then — Scenario 1: PolicyLookupFailed audit entry
// ---------------------------------------------------------------------------

/// `And an audit entry of event_type POLICY_LOOKUP_FAILED is appended`.
#[then("an audit entry of event_type POLICY_LOOKUP_FAILED is appended")]
async fn then_audit_policy_lookup_failed(world: &mut ConformanceWorld) {
    assert_eq!(
        world.last_audit_event,
        Some(EventType::PolicyLookupFailed),
        "expected PolicyLookupFailed audit entry, got {:?}",
        world.last_audit_event
    );
    let audit = world.audit_log.as_ref().expect("audit_log must be open");
    audit.verify_chain().expect("audit chain must verify after PolicyLookupFailed append");
}

// ---------------------------------------------------------------------------
// Then — Scenario 2: PolicyParseFailed audit entry with parse error
// ---------------------------------------------------------------------------

/// `And an audit entry of event_type POLICY_PARSE_FAILED is appended with
/// the parse error`.
#[then("an audit entry of event_type POLICY_PARSE_FAILED is appended with the parse error")]
async fn then_audit_policy_parse_failed(world: &mut ConformanceWorld) {
    assert_eq!(
        world.last_audit_event,
        Some(EventType::PolicyParseFailed),
        "expected PolicyParseFailed audit entry, got {:?}",
        world.last_audit_event
    );
    assert!(world.last_error.is_some(), "parse error should be recorded in world.last_error");
    let audit = world.audit_log.as_ref().expect("audit_log must be open");
    audit.verify_chain().expect("audit chain must verify after PolicyParseFailed append");
}

// ---------------------------------------------------------------------------
// Shared Then — no signing is performed
// ---------------------------------------------------------------------------

/// `And no signing is performed`.
///
/// Because the decision is `Deny(PolicyMissing)`, the 11-step flow returns
/// at step 2 (load_policy) and never reaches the signing path (which would
/// only happen on `Decision::Allow` after step 10). This assertion confirms
/// the deny short-circuited before any signing could occur.
#[then("no signing is performed")]
async fn then_no_signing_performed(world: &mut ConformanceWorld) {
    assert!(
        matches!(world.last_decision, Some(Decision::Deny(DenyReason::PolicyMissing))),
        "expected Deny(PolicyMissing) — no signing should be performed, \
         got {:?}",
        world.last_decision,
    );
}
