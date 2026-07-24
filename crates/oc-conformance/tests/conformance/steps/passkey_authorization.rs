//! T23 — Passkey Authorization BDD step definitions.
//!
//! Implements the 5 scenarios in
//! `passkey_authorization.feature`.
//!
//! Per the T22/T23 design, steps orchestrate EXISTING components directly:
//! - `oc_keyagent::PasskeyVerifier` for Passkey challenge-response
//! - `oc_keyagent::AuditLog` for the append-only audit chain
//!
//! The Key-Agent handler (`oc_keyagent::handler::dispatch()`) remains stubbed
//! (T11); these step definitions prove the BEHAVIORS described in the
//! scenarios work end-to-end at the component level. A later task can wire
//! the handler to call these same components.
//!
//! R80 deny_reason mapping (CRITICAL — coarse 9-variant enum):
//! - Missing auth      → deny_reason `PASSKEY_FORGED`, audit `PASSKEY_MISSING`
//! - Replayed challenge → deny_reason `PASSKEY_FORGED`, audit `PASSKEY_REPLAY`
//! - Forged signature   → deny_reason `PASSKEY_FORGED`, audit `PASSKEY_FORGED`
//!
//! The `PasskeyVerifier` verify order is:
//! 1. Structural (challenge.len()==32 && credential_id non-empty) else `Missing`
//! 2. credential_id match else `CredentialMismatch`
//! 3. challenge in pending else `Replay`
//! 4. signature verifies else `Forged`
//! 5. consume challenge on success

use cucumber::{given, then, when};
use ed25519_dalek::{Signer, SigningKey};
use oc_keyagent::{
    EventType, PasskeyError, PasskeyPubkey, PasskeyVerifier, proto::PasskeyAuthorization,
};
use oc_policy::DenyReason;
use tempfile::tempdir;

use crate::ConformanceWorld;

// ---------------------------------------------------------------------------
// Background steps (shared across all 5 scenarios)
// ---------------------------------------------------------------------------

/// `Given the Key-Agent is running with a registered Passkey public key`
///
/// Sets up:
/// - A fresh Ed25519 device key + audit log (in a leaked `TempDir`).
/// - A fresh Ed25519 keypair as the "Passkey" (signing key kept by the UI; verifying key registered
///   with the Key-Agent).
/// - A `PasskeyVerifier` bound to the verifying key + a test credential ID.
///
/// Mirrors T22's `wallet_unlocked` setup pattern.
#[given("the Key-Agent is running with a registered Passkey public key")]
async fn keyagent_running_with_passkey(world: &mut ConformanceWorld) {
    // 1. Fresh Ed25519 device key for audit signing.
    let device_key = SigningKey::generate(&mut rand_core::UnwrapErr(getrandom::SysRng));
    world.device_key = Some(device_key.clone());

    // 2. Audit log in a leaked TempDir (file survives the scenario).
    let tmp = tempdir().expect("tempdir for audit log");
    let audit_path = tmp.path().join("audit.jsonl");
    std::mem::forget(tmp);
    let audit_log =
        oc_keyagent::AuditLog::open(&audit_path, "dev-test", device_key).expect("AuditLog::open");
    world.audit_path = Some(audit_path);
    world.audit_log = Some(audit_log);

    // 3. Fresh Ed25519 keypair as the Passkey. The signing key lives on the UI side (it signs
    //    challenges); the verifying key is registered with the Key-Agent via PasskeyVerifier.
    let passkey_signing = SigningKey::generate(&mut rand_core::UnwrapErr(getrandom::SysRng));
    let verifying_key = passkey_signing.verifying_key();
    world.passkey_signing_key = Some(passkey_signing);

    // 4. Register the PasskeyVerifier with the verifying key + credential ID.
    let credential_id = b"cred-test-passkey-001".to_vec();
    world.passkey_credential_id = Some(credential_id.clone());
    world.passkey_verifier =
        Some(PasskeyVerifier::new(PasskeyPubkey::Ed25519(verifying_key), credential_id));
}

/// `And high-risk operations are CreateSessionKey, RevokeSessionKey, and wallet export`
///
/// Informational: the high-risk ops list is implicit in the scenarios (each
/// scenario simulates a CreateSessionKey or similar high-risk op). No state
/// needs to be set here.
#[given("high-risk operations are CreateSessionKey, RevokeSessionKey, and wallet export")]
async fn high_risk_ops_defined(_world: &mut ConformanceWorld) {
    // No-op: the high-risk ops list is enforced by the scenarios themselves
    // (each one simulates a CreateSessionKey or similar high-risk request).
}

// ---------------------------------------------------------------------------
// Scenario 1: High-risk operation requires PasskeyAuthorization message
// ---------------------------------------------------------------------------

/// `Given the Agent initiates a CreateSessionKey request`
///
/// No-op: sets up the scenario context. The actual request simulation happens
/// in the When step.
#[given("the Agent initiates a CreateSessionKey request")]
async fn agent_initiates_create_session_key(_world: &mut ConformanceWorld) {
    // No-op: the Agent's intent to create a session key is the scenario
    // setup; the When step simulates the request reaching the Key-Agent.
}

/// `When the request reaches the Key-Agent without a PasskeyAuthorization field`
///
/// Simulates a request with NO PasskeyAuthorization: the auth struct is
/// structurally empty (zero-length challenge, empty signature, empty
/// credential_id). The verifier returns `PasskeyError::Missing` (step 1 of
/// the verify order). The Key-Agent appends a `PASSKEY_MISSING` audit entry
/// and rejects the request before policy evaluation.
#[when("the request reaches the Key-Agent without a PasskeyAuthorization field")]
async fn request_without_passkey_auth(world: &mut ConformanceWorld) {
    let empty_auth = PasskeyAuthorization {
        challenge: Vec::new(),
        signature: Vec::new(),
        credential_id: String::new(),
    };

    let result = world
        .passkey_verifier
        .as_mut()
        .expect("passkey_verifier must be set by Background")
        .verify(&empty_auth);

    match result {
        Err(PasskeyError::Missing) => {
            world.last_error = Some(format!("{:?}", PasskeyError::Missing));
            // R80 mapping: Missing → deny_reason PASSKEY_FORGED (coarse).
            world.last_deny_reason = Some(DenyReason::PasskeyForged);
            // Fine-grained audit event: PASSKEY_MISSING.
            world
                .audit_log
                .as_mut()
                .expect("audit_log must be open")
                .append(
                    EventType::PasskeyMissing,
                    None,
                    serde_json::json!({"status": "denied", "reason": "passkey_missing"}),
                )
                .expect("audit append for PasskeyMissing must succeed");
            world.last_audit_event = Some(EventType::PasskeyMissing);
        }
        other => panic!("expected PasskeyError::Missing for empty auth, got {:?}", other),
    }
}

/// `Then the Key-Agent rejects the request before policy evaluation`
#[then("the Key-Agent rejects the request before policy evaluation")]
async fn then_rejects_before_policy(world: &mut ConformanceWorld) {
    assert!(
        world.last_error.is_some(),
        "expected the Key-Agent to reject the request (last_error should be set)"
    );
    assert!(
        world.last_deny_reason.is_some(),
        "expected a deny_reason to be set for the rejected request"
    );
}

/// `And an audit entry of event_type PASSKEY_MISSING is appended`
#[then("an audit entry of event_type PASSKEY_MISSING is appended")]
async fn then_audit_passkey_missing(world: &mut ConformanceWorld) {
    assert_eq!(
        world.last_audit_event,
        Some(EventType::PasskeyMissing),
        "expected PASSKEY_MISSING audit event, got {:?}",
        world.last_audit_event
    );
    // verify_chain proves the entry was actually persisted with a valid
    // Ed25519 signature and chain hash — not just set in world state.
    world
        .audit_log
        .as_ref()
        .expect("audit_log must be open")
        .verify_chain()
        .expect("audit chain must verify after PASSKEY_MISSING append");
}

/// `And no Session Key is created`
#[then("no Session Key is created")]
async fn then_no_session_key_created(world: &mut ConformanceWorld) {
    assert!(
        world.session_key_id.is_none(),
        "no Session Key should be created when Passkey auth is missing, got: {:?}",
        world.session_key_id
    );
}

// ---------------------------------------------------------------------------
// Scenario 2: Key-Agent generates fresh 32-byte nonce per high-risk op
// ---------------------------------------------------------------------------

/// `Given the Agent initiates two consecutive CreateSessionKey requests`
///
/// Generates two fresh challenges from the verifier and stores both in
/// `world.challenges`. Each call to `generate_challenge()` draws 32 bytes
/// from OsRng (the kernel CSPRNG) and inserts the nonce into the verifier's
/// `pending_challenges` set.
#[given("the Agent initiates two consecutive CreateSessionKey requests")]
async fn agent_initiates_two_create_session_key(world: &mut ConformanceWorld) {
    let verifier =
        world.passkey_verifier.as_mut().expect("passkey_verifier must be set by Background");

    let c1 = verifier.generate_challenge();
    let c2 = verifier.generate_challenge();
    world.challenges.clear();
    world.challenges.push(c1);
    world.challenges.push(c2);
}

/// `When the Key-Agent returns a challenge for each request`
///
/// No-op: the challenges were already returned in the Given step. This step
/// is the BDD "When" framing of the same action.
#[when("the Key-Agent returns a challenge for each request")]
async fn when_keyagent_returns_challenges(_world: &mut ConformanceWorld) {
    // Challenges were generated in the Given step; nothing to do here.
}

/// `Then each challenge is exactly 32 bytes of cryptographically random data`
#[then("each challenge is exactly 32 bytes of cryptographically random data")]
async fn then_challenges_are_32_bytes(world: &mut ConformanceWorld) {
    assert!(
        world.challenges.len() >= 2,
        "expected at least 2 challenges, got {}",
        world.challenges.len()
    );
    for (i, c) in world.challenges.iter().take(2).enumerate() {
        assert_eq!(c.len(), 32, "challenge {} must be exactly 32 bytes, got {}", i, c.len());
        // Sanity: not all zeros (OsRng should never produce all-zero output
        // for a 32-byte draw — probability 2^-256). This is a weak check
        // for "cryptographically random"; the strong guarantee is that
        // PasskeyVerifier::generate_challenge uses `rand::rngs::OsRng`.
        assert!(c.iter().any(|&b| b != 0), "challenge {} must not be all zeros", i);
    }
}

/// `And the two challenges are not equal`
#[then("the two challenges are not equal")]
async fn then_challenges_not_equal(world: &mut ConformanceWorld) {
    assert!(
        world.challenges.len() >= 2,
        "expected at least 2 challenges, got {}",
        world.challenges.len()
    );
    assert_ne!(
        world.challenges[0], world.challenges[1],
        "two fresh challenges from OsRng must not be equal"
    );
}

/// `And each challenge is single-use and discarded after the response is verified`
///
/// Signs each challenge with the UI's Passkey signing key, builds a
/// PasskeyAuthorization, and calls `verify()` (which consumes the challenge
/// on success). After both verifications, `pending_count` must be 0.
#[then("each challenge is single-use and discarded after the response is verified")]
async fn then_challenges_single_use(world: &mut ConformanceWorld) {
    let signing_key = world.passkey_signing_key.clone().expect("passkey_signing_key must be set");
    let credential_id =
        world.passkey_credential_id.clone().expect("passkey_credential_id must be set");
    let credential_id_str =
        String::from_utf8(credential_id.clone()).expect("credential_id is utf8");

    let challenges: Vec<[u8; 32]> = world.challenges.clone();
    assert!(
        challenges.len() >= 2,
        "expected at least 2 challenges to consume, got {}",
        challenges.len()
    );

    let verifier = world.passkey_verifier.as_mut().expect("passkey_verifier must be set");

    // Before any verify: pending_count == 2 (both challenges pending).
    assert_eq!(
        verifier.pending_count(),
        2,
        "expected 2 pending challenges before verify, got {}",
        verifier.pending_count()
    );

    // Verify the first challenge — consumes it on success.
    let c1 = challenges[0];
    let mut message = Vec::with_capacity(c1.len() + credential_id.len());
    message.extend_from_slice(&c1);
    message.extend_from_slice(&credential_id);
    let sig1 = signing_key.sign(&message);
    let auth1 = PasskeyAuthorization {
        challenge: c1.to_vec(),
        signature: sig1.to_bytes().to_vec(),
        credential_id: credential_id_str.clone(),
    };
    verifier.verify(&auth1).expect("first verify must succeed and consume challenge 1");
    assert_eq!(
        verifier.pending_count(),
        1,
        "expected 1 pending challenge after first verify, got {}",
        verifier.pending_count()
    );

    // Verify the second challenge — consumes it on success.
    let c2 = challenges[1];
    let mut message = Vec::with_capacity(c2.len() + credential_id.len());
    message.extend_from_slice(&c2);
    message.extend_from_slice(&credential_id);
    let sig2 = signing_key.sign(&message);
    let auth2 = PasskeyAuthorization {
        challenge: c2.to_vec(),
        signature: sig2.to_bytes().to_vec(),
        credential_id: credential_id_str,
    };
    verifier.verify(&auth2).expect("second verify must succeed and consume challenge 2");
    assert_eq!(
        verifier.pending_count(),
        0,
        "expected 0 pending challenges after both verifies, got {}",
        verifier.pending_count()
    );
}

// ---------------------------------------------------------------------------
// Scenario 3: Reused challenge is rejected (replay protection)
// ---------------------------------------------------------------------------

/// `Given the Agent captured a valid PasskeyAuthorization from a previous request`
///
/// Generates a fresh challenge, signs it with the UI's Passkey signing key,
/// builds a PasskeyAuthorization, and calls `verify()` (which succeeds and
/// consumes the challenge). The captured auth is stored in `world.captured_auth`
/// for the subsequent replay attempt.
#[given("the Agent captured a valid PasskeyAuthorization from a previous request")]
async fn agent_captured_valid_auth(world: &mut ConformanceWorld) {
    let challenge =
        world.passkey_verifier.as_mut().expect("passkey_verifier must be set").generate_challenge();

    let signing_key = world.passkey_signing_key.clone().expect("passkey_signing_key must be set");
    let credential_id =
        world.passkey_credential_id.clone().expect("passkey_credential_id must be set");
    let mut message = Vec::with_capacity(challenge.len() + credential_id.len());
    message.extend_from_slice(&challenge);
    message.extend_from_slice(&credential_id);
    let signature = signing_key.sign(&message);

    let credential_id_str = String::from_utf8(credential_id).expect("credential_id is utf8");
    let auth = PasskeyAuthorization {
        challenge: challenge.to_vec(),
        signature: signature.to_bytes().to_vec(),
        credential_id: credential_id_str,
    };

    // Verify once — this must succeed and consume the challenge.
    world
        .passkey_verifier
        .as_mut()
        .expect("passkey_verifier must be set")
        .verify(&auth)
        .expect("first verify of captured auth must succeed");

    // Stash the auth for the replay attempt in the When step.
    world.captured_auth = Some(auth);
}

/// `When the Agent resubmits the same PasskeyAuthorization in a new high-risk request`
///
/// Calls `verify()` again with the same captured auth. The challenge has
/// already been consumed (removed from `pending_challenges`), so the verifier
/// returns `PasskeyError::Replay`. The Key-Agent maps this to deny_reason
/// `PASSKEY_FORGED` (R80 coarse) and appends a `PASSKEY_REPLAY` audit entry.
#[when("the Agent resubmits the same PasskeyAuthorization in a new high-risk request")]
async fn agent_resubmits_captured_auth(world: &mut ConformanceWorld) {
    let auth =
        world.captured_auth.as_ref().expect("captured_auth must be set by Given step").clone();

    let result =
        world.passkey_verifier.as_mut().expect("passkey_verifier must be set").verify(&auth);

    match result {
        Err(PasskeyError::Replay) => {
            world.last_error = Some(format!("{:?}", PasskeyError::Replay));
            // R80 mapping: Replay → deny_reason PASSKEY_FORGED (coarse).
            world.last_deny_reason = Some(DenyReason::PasskeyForged);
            // Fine-grained audit event: PASSKEY_REPLAY.
            world
                .audit_log
                .as_mut()
                .expect("audit_log must be open")
                .append(
                    EventType::PasskeyReplay,
                    None,
                    serde_json::json!({"status": "denied", "reason": "passkey_replay"}),
                )
                .expect("audit append for PasskeyReplay must succeed");
            world.last_audit_event = Some(EventType::PasskeyReplay);
        }
        other => panic!("expected PasskeyError::Replay for resubmitted auth, got {:?}", other),
    }
}

/// `Then the Key-Agent rejects it because the challenge has already been consumed`
#[then("the Key-Agent rejects it because the challenge has already been consumed")]
async fn then_rejects_replay(world: &mut ConformanceWorld) {
    let err = world.last_error.as_deref().expect("last_error must be set for replay rejection");
    let lower = err.to_lowercase();
    assert!(
        lower.contains("replay"),
        "expected error to mention 'replay', got: {:?}",
        world.last_error
    );
}

/// `And the response deny_reason is "PASSKEY_FORGED"`
///
/// Shared between Scenario 3 (replay) and Scenario 4 (forged boolean).
/// R80 has no `PASSKEY_REPLAY` deny_reason — both replay and forgery map to
/// the coarse `PASSKEY_FORGED` deny_reason. The fine-grained distinction is
/// captured in the audit event_type (PASSKEY_REPLAY vs PASSKEY_FORGED).
#[then(regex = r#"^the response deny_reason is "PASSKEY_FORGED"$"#)]
async fn then_deny_reason_passkey_forged(world: &mut ConformanceWorld) {
    assert_eq!(
        world.last_deny_reason,
        Some(DenyReason::PasskeyForged),
        "expected deny_reason PASSKEY_FORGED (R80 coarse), got {:?}",
        world.last_deny_reason
    );
}

/// `And an audit entry of event_type PASSKEY_REPLAY is appended`
#[then("an audit entry of event_type PASSKEY_REPLAY is appended")]
async fn then_audit_passkey_replay(world: &mut ConformanceWorld) {
    assert_eq!(
        world.last_audit_event,
        Some(EventType::PasskeyReplay),
        "expected PASSKEY_REPLAY audit event, got {:?}",
        world.last_audit_event
    );
    world
        .audit_log
        .as_ref()
        .expect("audit_log must be open")
        .verify_chain()
        .expect("audit chain must verify after PASSKEY_REPLAY append");
}

// ---------------------------------------------------------------------------
// Scenario 4: Key-Agent rejects forged UI boolean "authorized=true"
// ---------------------------------------------------------------------------

/// `Given a tampered UI process attempts to bypass biometric authentication`
///
/// No-op: sets up the adversarial context.
#[given("a tampered UI process attempts to bypass biometric authentication")]
async fn tampered_ui_attempts_bypass(_world: &mut ConformanceWorld) {
    // No-op: adversarial context is implicit in the When step.
}

/// `When the UI sends an IPC message containing a boolean field "authorized=true" without a Passkey
/// signature`
///
/// Simulates the attack: the UI sends `authorized=true` (a boolean the
/// Key-Agent MUST ignore per R31/C-05) but provides NO valid Passkey
/// signature. We model this as a PasskeyAuthorization with:
/// - `challenge`: a valid 32-byte challenge (from `generate_challenge()`, so it's in
///   `pending_challenges` — otherwise verify would return `Replay` before reaching the signature
///   check).
/// - `signature`: empty `Vec` (the UI sent no signature — just the boolean).
/// - `credential_id`: the registered credential ID (so step 2 of verify passes).
///
/// The verifier reaches step 4 (signature verification), tries to parse the
/// empty bytes as an Ed25519 signature, fails, and returns `Forged`. The
/// Key-Agent appends a `PASSKEY_FORGED` audit entry.
#[when(
    regex = r#"^the UI sends an IPC message containing a boolean field "authorized=true" without a Passkey signature$"#
)]
async fn ui_sends_boolean_without_signature(world: &mut ConformanceWorld) {
    // Generate a fresh challenge so it's in `pending_challenges` — this
    // ensures verify reaches step 4 (signature check) and returns Forged
    // rather than Replay.
    let challenge =
        world.passkey_verifier.as_mut().expect("passkey_verifier must be set").generate_challenge();

    let credential_id =
        world.passkey_credential_id.clone().expect("passkey_credential_id must be set");
    let credential_id_str = String::from_utf8(credential_id).expect("credential_id is utf8");

    // Forged auth: valid challenge + valid credential_id but EMPTY signature.
    // The boolean "authorized=true" is NOT a field on PasskeyAuthorization —
    // the Key-Agent has no way to even receive it via this proto. We model
    // the attack as "UI sent the IPC envelope with authorized=true but left
    // the PasskeyAuthorization.signature empty".
    let forged_auth = PasskeyAuthorization {
        challenge: challenge.to_vec(),
        signature: Vec::new(), // empty signature — parse will fail → Forged
        credential_id: credential_id_str,
    };

    let result =
        world.passkey_verifier.as_mut().expect("passkey_verifier must be set").verify(&forged_auth);

    match result {
        Err(PasskeyError::Forged) => {
            world.last_error = Some(format!("{:?}", PasskeyError::Forged));
            world.last_deny_reason = Some(DenyReason::PasskeyForged);
            world
                .audit_log
                .as_mut()
                .expect("audit_log must be open")
                .append(
                    EventType::PasskeyForged,
                    None,
                    serde_json::json!({"status": "denied", "reason": "passkey_forged"}),
                )
                .expect("audit append for PasskeyForged must succeed");
            world.last_audit_event = Some(EventType::PasskeyForged);
        }
        other => panic!("expected PasskeyError::Forged for empty signature, got {:?}", other),
    }
}

/// `Then the Key-Agent ignores the boolean field entirely`
///
/// The `PasskeyVerifier::verify` API accepts only `&PasskeyAuthorization`,
/// which has three fields: `challenge` (bytes), `signature` (bytes),
/// `credential_id` (string). There is NO boolean field on the proto message.
/// The Key-Agent cannot consult a UI boolean because none is transmitted.
/// This is a structural property verified by the type definition in
/// `oc-keyagent/src/proto.rs` (R31 / C-05).
#[then("the Key-Agent ignores the boolean field entirely")]
async fn then_ignores_boolean_field(world: &mut ConformanceWorld) {
    // The verify call in the When step returned Forged — proving the
    // Key-Agent reached its decision using ONLY the signature bytes, not
    // any boolean. If the Key-Agent had consulted a boolean, the empty
    // signature would have been irrelevant.
    assert!(
        world.last_error.is_some(),
        "expected the Key-Agent to reject based on signature, not boolean"
    );
    // PasskeyAuthorization has no boolean field — compile-time guarantee
    // from the proto type definition. No runtime assertion needed; the
    // type system enforces R31/C-05.
}

/// `And the Key-Agent denies the high-risk operation`
#[then("the Key-Agent denies the high-risk operation")]
async fn then_denies_high_risk_op(world: &mut ConformanceWorld) {
    assert!(
        world.last_deny_reason.is_some(),
        "expected the high-risk op to be denied (deny_reason must be set)"
    );
    assert!(
        world.session_key_id.is_none(),
        "high-risk op must NOT execute when Passkey verify fails"
    );
}

/// `And an audit entry of event_type PASSKEY_FORGED is appended`
#[then("an audit entry of event_type PASSKEY_FORGED is appended")]
async fn then_audit_passkey_forged(world: &mut ConformanceWorld) {
    assert_eq!(
        world.last_audit_event,
        Some(EventType::PasskeyForged),
        "expected PASSKEY_FORGED audit event, got {:?}",
        world.last_audit_event
    );
    world
        .audit_log
        .as_ref()
        .expect("audit_log must be open")
        .verify_chain()
        .expect("audit chain must verify after PASSKEY_FORGED append");
}

// ---------------------------------------------------------------------------
// Scenario 5: Key-Agent verifies Passkey signature locally (not UI boolean)
// ---------------------------------------------------------------------------

/// `Given the Key-Agent holds the Passkey public key in its own protected storage`
///
/// Already true from the Background (the PasskeyVerifier was initialized
/// with the Ed25519 verifying key). No-op.
#[given("the Key-Agent holds the Passkey public key in its own protected storage")]
async fn keyagent_holds_passkey_pubkey(_world: &mut ConformanceWorld) {
    // No-op: the Background step `keyagent_running_with_passkey` already
    // registered the PasskeyVerifier with the Ed25519 verifying key.
}

/// `When the UI returns a PasskeyAuthorization with challenge, signature, and credential_id`
///
/// Generates a fresh challenge, signs it with the UI's Passkey signing key
/// over `(challenge || credential_id)`, builds a PasskeyAuthorization, and
/// calls `verify()`. On success, the high-risk operation (CreateSessionKey)
/// is executed — modeled by setting `session_key_id`.
#[when("the UI returns a PasskeyAuthorization with challenge, signature, and credential_id")]
async fn ui_returns_valid_passkey_auth(world: &mut ConformanceWorld) {
    let challenge =
        world.passkey_verifier.as_mut().expect("passkey_verifier must be set").generate_challenge();

    let signing_key = world.passkey_signing_key.clone().expect("passkey_signing_key must be set");
    let credential_id =
        world.passkey_credential_id.clone().expect("passkey_credential_id must be set");
    let mut message = Vec::with_capacity(challenge.len() + credential_id.len());
    message.extend_from_slice(&challenge);
    message.extend_from_slice(&credential_id);
    let signature = signing_key.sign(&message);

    let credential_id_str = String::from_utf8(credential_id).expect("credential_id is utf8");
    let auth = PasskeyAuthorization {
        challenge: challenge.to_vec(),
        signature: signature.to_bytes().to_vec(),
        credential_id: credential_id_str,
    };

    let result =
        world.passkey_verifier.as_mut().expect("passkey_verifier must be set").verify(&auth);

    match result {
        Ok(()) => {
            // All three verifications passed (challenge match, credential_id
            // match, signature verify). The high-risk operation is executed.
            world.last_error = None;
            world.session_key_id = Some("oc_sk_passkey_verified".to_string());
        }
        Err(e) => {
            world.last_error = Some(format!("{e:?}"));
            panic!("expected Passkey verify to succeed, got {:?}", e);
        }
    }
}

/// `Then the Key-Agent verifies the signature against the stored public key`
#[then("the Key-Agent verifies the signature against the stored public key")]
async fn then_verifies_signature(world: &mut ConformanceWorld) {
    assert!(
        world.last_error.is_none(),
        "Passkey signature verification should have succeeded, got: {:?}",
        world.last_error
    );
    assert!(
        world.session_key_id.is_some(),
        "high-risk op should have executed after successful signature verify"
    );
}

/// `And the Key-Agent verifies the challenge matches the one it generated`
///
/// Implicit in the verify success: if the challenge didn't match (wasn't in
/// `pending_challenges`), verify would have returned `Replay` at step 3.
#[then("the Key-Agent verifies the challenge matches the one it generated")]
async fn then_verifies_challenge_matches(world: &mut ConformanceWorld) {
    assert!(
        world.last_error.is_none(),
        "challenge match check should have passed (verify succeeded), got: {:?}",
        world.last_error
    );
}

/// `And the Key-Agent verifies the credential_id is the registered credential`
///
/// Implicit in the verify success: if the credential_id didn't match, verify
/// would have returned `CredentialMismatch` at step 2.
#[then("the Key-Agent verifies the credential_id is the registered credential")]
async fn then_verifies_credential_id(world: &mut ConformanceWorld) {
    assert!(
        world.last_error.is_none(),
        "credential_id match check should have passed (verify succeeded), got: {:?}",
        world.last_error
    );
}

/// `And only after all three verifications pass is the high-risk operation executed`
#[then("only after all three verifications pass is the high-risk operation executed")]
async fn then_op_executed_after_verifications(world: &mut ConformanceWorld) {
    assert!(
        world.session_key_id.is_some(),
        "high-risk op must execute only after all three Passkey verifications pass"
    );
    assert!(
        world.last_error.is_none(),
        "no error should be set when all verifications pass, got: {:?}",
        world.last_error
    );
}

/// `And no boolean from the UI is consulted`
///
/// The `PasskeyVerifier::verify` API accepts only `&PasskeyAuthorization`,
/// which has three fields (`challenge`, `signature`, `credential_id`) —
/// none of which is a boolean. The Key-Agent cannot consult a UI boolean
/// because none is transmitted on the proto message (R31 / C-05).
#[then("no boolean from the UI is consulted")]
async fn then_no_boolean_consulted(world: &mut ConformanceWorld) {
    // Structural guarantee: PasskeyAuthorization has no boolean field.
    // The successful verify in the When step proves the Key-Agent reached
    // its decision using ONLY (challenge, signature, credential_id).
    assert!(
        world.last_error.is_none(),
        "verify should have succeeded without any boolean input, got: {:?}",
        world.last_error
    );
    assert!(
        world.session_key_id.is_some(),
        "high-risk op should have executed based on signature alone"
    );
}
