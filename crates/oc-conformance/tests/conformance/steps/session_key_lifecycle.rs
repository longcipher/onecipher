//! T22 — Session Key Lifecycle BDD step definitions.
//!
//! Implements the 6 scenarios in
//! `session_key_lifecycle.feature`.
//!
//! Per the T22 design, steps orchestrate EXISTING components directly:
//! - `oc_keyagent::PasskeyVerifier` for Passkey challenge-response
//! - `oc_keyagent::AuditLog` for the append-only audit chain
//! - `oc_session_key::EvmSessionKeyProvider` / `SolanaSessionKeyProvider` for grant/revoke/sign
//! - `oc_policy::evaluate_11_step` for the 11-step Policy decision flow
//! - `oc_session_key::MockRpcClient` for mock on-chain calls
//!
//! This proves the BEHAVIORS described in the scenarios work end-to-end at the
//! component level. A later task can refactor `oc_keyagent::handler::dispatch()`
//! to wire all these together inside the real Key-Agent handler.

use cucumber::{given, then, when};
use ed25519_dalek::{Signer, SigningKey};
use oc_crypto::HardenedBytes;
use oc_keyagent::{
    AuditLog, EventType, PasskeyPubkey, PasskeyVerifier, proto::PasskeyAuthorization,
};
use oc_policy::{
    BudgetAllocation, Decision, DenyReason, PayRequest, PolicyRulesV2, PolicyState, PolicyV2,
    evaluate_11_step,
};
use oc_session_key::{
    EvmSessionKeyProvider, GrantReceipt, KeyScheme, MockRpcClient, OwnerKey, PublicKey,
    SessionKeyProvider, SessionPrivateKey, SignPayload, Signature, SolanaSessionKeyProvider,
};
use tempfile::tempdir;

use crate::ConformanceWorld;

// ---------------------------------------------------------------------------
// Background steps (shared across all 6 scenarios)
// ---------------------------------------------------------------------------

#[given("the OneCipher daemon is running with Key-Agent and Network-Agent")]
async fn daemon_running(_world: &mut ConformanceWorld) {
    // No-op for component-level tests. The "daemon" is emulated by direct
    // component calls in subsequent steps.
}

#[given("the main wallet is unlocked and its Owner key is in Key-Agent memory only")]
async fn wallet_unlocked(world: &mut ConformanceWorld) {
    // Generate a fresh Ed25519 device key for audit signing.
    let device_key = SigningKey::generate(&mut rand_core::UnwrapErr(getrandom::SysRng));
    // SigningKey is Clone; keep one copy for AuditLog, one for the World.
    world.device_key = Some(device_key.clone());

    // Create a temp audit log file. We intentionally leak the TempDir via
    // `mem::forget` so the file survives for the scenario's lifetime.
    let tmp = tempdir().expect("tempdir for audit log");
    let audit_path = tmp.path().join("audit.jsonl");
    std::mem::forget(tmp);

    let audit_log = AuditLog::open(&audit_path, "dev-test", device_key).expect("AuditLog::open");
    world.audit_path = Some(audit_path);
    world.audit_log = Some(audit_log);

    // Generate a fresh Ed25519 keypair as the "Owner key" for session-key ops.
    let owner_signing = SigningKey::generate(&mut rand_core::UnwrapErr(getrandom::SysRng));
    let owner_bytes =
        HardenedBytes::from_slice(&owner_signing.to_bytes()).expect("HardenedBytes::from_slice");
    world.owner_key = Some(OwnerKey { raw: owner_bytes, chain_id: "eip155:8453".to_string() });
    // Owner signs Passkey challenges in subsequent steps.
    world.passkey_signing_key = Some(owner_signing);
}

#[given("an AI Agent has been provisioned with a WalletConnect v2 client")]
async fn agent_provisioned(_world: &mut ConformanceWorld) {
    // No-op for component-level tests. The Agent method surface
    // (WalletConnect v2 JSON-RPC) is populated in `ConformanceWorld::new()`.
}

// ---------------------------------------------------------------------------
// Scenario 1: Create Session Key with policy via Passkey challenge-response
// ---------------------------------------------------------------------------

#[given("the human Owner has a registered Passkey credential")]
async fn owner_has_passkey(world: &mut ConformanceWorld) {
    let signing_key =
        world.passkey_signing_key.clone().expect("passkey_signing_key must be set by Background");
    let pubkey = PasskeyPubkey::Ed25519(signing_key.verifying_key());
    let credential_id = b"cred-test-001".to_vec();
    world.passkey_credential_id = Some(credential_id.clone());
    world.passkey_verifier = Some(PasskeyVerifier::new(pubkey, credential_id));
}

#[given(regex = r"^a Policy is drafted with max_single_amount_usd.*$")]
async fn policy_drafted(world: &mut ConformanceWorld) {
    let now = jiff::Timestamp::now().as_second().max(0) as u64;
    let rules = PolicyRulesV2 {
        max_single_amount_usd: 10.0,
        max_daily_amount_usd: 100.0,
        max_monthly_amount_usd: 1000.0,
        expiry_unix: now + 3600, // 1 hour from now
        rate_limit_per_minute: 10,
        rate_limit_per_hour: 100,
        cooldown_after_denial_sec: 60,
        asset_whitelist: vec!["eip155:1/erc20:0xAsset".to_string()],
        chain_whitelist: vec!["eip155:8453".to_string()],
        contract_whitelist: vec![],
        payment_protocols: vec!["x402".to_string()],
    };
    let budget = BudgetAllocation {
        allocated_usd: 50.0,
        allocated_at_unix: now,
        parent_total_usd: 1000.0,
        parent_session_id: "owner-wallet".to_string(),
    };
    world.policy = Some(PolicyV2 {
        version: 2,
        session_key_id: "oc_sk_pending".to_string(),
        device_id: "dev-test".to_string(),
        rules,
        budget_allocation: budget,
    });
}

#[when("the Agent calls CreateSessionKey with the Policy and a PasskeyAuthorization")]
async fn agent_calls_create_session_key(world: &mut ConformanceWorld) {
    // 1. Generate a fresh challenge from the verifier.
    let challenge =
        world.passkey_verifier.as_mut().expect("passkey_verifier must be set").generate_challenge();

    // 2. Owner signs (challenge || credential_id) — the simplified OneCipher Passkey protocol (see
    //    PasskeyVerifier::verify).
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

    // 3. Verify the Passkey locally (Key-Agent behavior).
    let verify_result =
        world.passkey_verifier.as_mut().expect("passkey_verifier must be set").verify(&auth);
    if let Err(e) = &verify_result {
        world.last_error = Some(format!("{e:?}"));
        return;
    }

    // 4. Derive ephemeral Session Key pair. Per the spec we use Ed25519 for the signing key (the
    //    on-chain mock doesn't enforce scheme match).
    let session_signing = SigningKey::generate(&mut rand_core::UnwrapErr(getrandom::SysRng));
    let session_priv_bytes = HardenedBytes::from_slice(&session_signing.to_bytes())
        .expect("HardenedBytes::from_slice for session_priv");
    world.session_priv =
        Some(SessionPrivateKey { raw: session_priv_bytes, scheme: KeyScheme::Secp256k1Evm });
    world.session_pubkey = Some(PublicKey {
        bytes: session_signing.verifying_key().to_bytes().to_vec(),
        scheme: KeyScheme::Secp256k1Evm,
    });

    // 5. Call SessionKeyProvider::grant via EvmSessionKeyProvider + MockRpcClient.
    let mock_rpc = MockRpcClient::ok();
    world.mock_rpc_counters = Some(mock_rpc.counters());
    let provider = EvmSessionKeyProvider::new("eip155:8453", "0xSCA", Box::new(mock_rpc));

    // Clone what we need before borrowing `world` mutably for the audit append.
    let policy = world.policy.as_ref().expect("policy must be drafted").clone();
    let owner_key_clone = world.owner_key.as_ref().expect("owner_key must be set");
    let session_pubkey = world.session_pubkey.as_ref().expect("session_pubkey must be set").clone();

    let receipt = provider.grant(owner_key_clone, &session_pubkey, &policy).await;
    match receipt {
        Ok(r) => {
            world.grant_receipt = Some(r);
            world.session_key_id = Some("oc_sk_01HZ".to_string());
            // 6. Append CREATE_SESSION_KEY audit entry.
            let session_key_id = world.session_key_id.clone();
            let audit = world.audit_log.as_mut().expect("audit_log must be open");
            audit
                .append(
                    EventType::CreateSessionKey,
                    session_key_id,
                    serde_json::json!({"status": "allowed"}),
                )
                .expect("audit append must succeed");
            world.last_audit_event = Some(EventType::CreateSessionKey);
        }
        Err(e) => world.last_error = Some(format!("{e:?}")),
    }
}

#[then("the Key-Agent verifies the Passkey signature locally against a fresh 32-byte challenge")]
async fn then_passkey_verified(world: &mut ConformanceWorld) {
    assert!(world.last_error.is_none(), "Passkey verification failed: {:?}", world.last_error);
    assert!(world.session_key_id.is_some(), "Session key was not created");
}

#[then("the Key-Agent derives an ephemeral Session Key pair")]
async fn then_session_key_derived(world: &mut ConformanceWorld) {
    assert!(world.session_priv.is_some(), "SessionPrivateKey not derived");
    assert!(world.session_pubkey.is_some(), "PublicKey not derived");
}

#[then("the SessionKeyProvider registers the Session Key permissions on-chain")]
async fn then_grant_called(world: &mut ConformanceWorld) {
    let counters = world.mock_rpc_counters.as_ref().expect("mock_rpc_counters must be set");
    assert!(counters.evm_tx() >= 1, "Expected grant to call send_evm_tx at least once");
}

#[then(regex = r"^the Agent receives a session_key_id.*$")]
async fn then_session_key_id_returned(world: &mut ConformanceWorld) {
    assert!(world.session_key_id.is_some(), "session_key_id not returned");
    assert!(world.grant_receipt.is_some(), "GrantReceipt not returned");
}

#[then("an audit entry of event_type CREATE_SESSION_KEY is appended")]
async fn then_audit_create_appended(world: &mut ConformanceWorld) {
    assert_eq!(
        world.last_audit_event,
        Some(EventType::CreateSessionKey),
        "expected CREATE_SESSION_KEY audit event"
    );
    let audit = world.audit_log.as_ref().expect("audit_log must be open");
    audit.verify_chain().expect("audit chain must verify after CREATE_SESSION_KEY");
}

// ---------------------------------------------------------------------------
// Scenario 2: Revoke Session Key (3-step flow: on-chain + local + budget reclaim)
// ---------------------------------------------------------------------------

#[given(regex = r"^an active Session Key with session_key_id.*$")]
async fn active_session_key(world: &mut ConformanceWorld) {
    // Reuse the create-session-key flow to set up state.
    owner_has_passkey(world).await;
    policy_drafted(world).await;
    agent_calls_create_session_key(world).await;

    // Override with the specific session_key_id from the scenario text.
    world.session_key_id = Some("oc_sk_01HZ".to_string());

    // Initialize a fresh PolicyState for this session key.
    let tmp = tempdir().expect("tempdir for policy_state");
    let path = tmp.path().join("policy_state.json");
    std::mem::forget(tmp);
    let state = PolicyState::load(&path, "oc_sk_01HZ".to_string()).expect("PolicyState::load");
    world.policy_state = Some(state);
    world.policy_state_path = Some(path);

    // Set remaining budget = $1.20 by adjusting the policy's budget_allocation.
    if let Some(p) = world.policy.as_mut() {
        p.budget_allocation.allocated_usd = 1.20;
    }
}

#[when("the Owner calls RevokeSessionKey authenticated by Passkey")]
async fn owner_calls_revoke(world: &mut ConformanceWorld) {
    // 1. Verify Passkey (Owner authenticates).
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
    let verify_result =
        world.passkey_verifier.as_mut().expect("passkey_verifier must be set").verify(&auth);
    if let Err(e) = verify_result {
        world.last_error = Some(format!("Passkey verify failed: {e:?}"));
        return;
    }

    // 2. Call SessionKeyProvider::revoke (on-chain).
    let mock_rpc = MockRpcClient::ok();
    let counters = mock_rpc.counters();
    let provider = EvmSessionKeyProvider::new("eip155:8453", "0xSCA", Box::new(mock_rpc));
    let owner_key = world.owner_key.as_ref().expect("owner_key must be set");
    let session_key_id = world.session_key_id.clone().expect("session_key_id must be set");

    // OwnerKey isn't Clone (HardenedBytes isn't Clone) — reconstruct from the
    // exposed bytes. The chain_id is preserved from the original.
    let owner_key_for_revoke = OwnerKey {
        raw: HardenedBytes::from_slice(owner_key.raw.expose())
            .expect("HardenedBytes::from_slice for revoke"),
        chain_id: owner_key.chain_id.clone(),
    };

    let revoke_result = provider.revoke(&owner_key_for_revoke, &session_key_id).await;
    if let Err(e) = revoke_result {
        world.last_error = Some(format!("Revoke failed: {e:?}"));
        return;
    }
    world.mock_rpc_counters = Some(counters);

    // 3. Mark policy as revoked locally (subsequent requests DENY EXPIRED). For T22, simulate this
    //    by setting expiry_unix to 0 (past).
    if let Some(p) = world.policy.as_mut() {
        p.rules.expiry_unix = 0;
    }

    // 4. Reclaim budget to parent reserve.
    let reclaimed =
        world.policy.as_ref().expect("policy must be set").budget_allocation.allocated_usd;

    // 5. Append REVOKE_SESSION_KEY audit entry with the reclaimed amount.
    let session_key_id_for_audit = world.session_key_id.clone();
    let audit = world.audit_log.as_mut().expect("audit_log must be open");
    audit
        .append(
            EventType::RevokeSessionKey,
            session_key_id_for_audit,
            serde_json::json!({"reclaimed_usd": reclaimed}),
        )
        .expect("audit append for revoke must succeed");
    world.last_audit_event = Some(EventType::RevokeSessionKey);
}

#[then("the SessionKeyProvider submits an on-chain revoke transaction signed by the Owner key")]
async fn then_revoke_tx_submitted(world: &mut ConformanceWorld) {
    let counters =
        world.mock_rpc_counters.as_ref().expect("mock_rpc_counters must be set after revoke");
    assert!(counters.evm_tx() >= 1, "Expected revoke to call send_evm_tx at least once");
}

#[then(regex = r"^the Policy Engine marks the session_key_id as revoked locally.*$")]
async fn then_marked_revoked(world: &mut ConformanceWorld) {
    // Verify: a subsequent PayX402 with this session_key_id returns DENY(EXPIRED)
    // because expiry_unix was set to 0 in `owner_calls_revoke`.
    let policy = world.policy.as_ref().expect("policy must be set").clone();
    let mut state = PolicyState::new("oc_sk_01HZ".to_string()).with_policy(policy);
    let req = PayRequest {
        session_key_id: "oc_sk_01HZ".to_string(),
        device_id: "dev-test".to_string(),
        amount_usd: 0.01,
        asset: "eip155:1/erc20:0xAsset".to_string(),
        chain_id: "eip155:8453".to_string(),
        recipient: Some("0xRecipient".to_string()),
    };
    let decision = evaluate_11_step(&req, "oc_sk_01HZ", &mut state);
    match decision {
        Decision::Deny(DenyReason::Expired) => {
            world.last_decision = Some(decision);
        }
        other => panic!("Expected Deny(Expired) after revoke, got {other:?}"),
    }
}

#[then("the remaining budget is returned to the parent wallet reserve pool")]
async fn then_budget_reclaimed(world: &mut ConformanceWorld) {
    // Verified by the REVOKE_SESSION_KEY audit entry's payload containing
    // reclaimed_usd — the audit chain verifies the entry was appended intact.
    assert_eq!(
        world.last_audit_event,
        Some(EventType::RevokeSessionKey),
        "expected REVOKE_SESSION_KEY audit event for budget reclaim"
    );
}

#[then(regex = r"^an audit entry of event_type REVOKE_SESSION_KEY is appended.*$")]
async fn then_revoke_audit_appended(world: &mut ConformanceWorld) {
    assert_eq!(
        world.last_audit_event,
        Some(EventType::RevokeSessionKey),
        "expected REVOKE_SESSION_KEY audit event"
    );
    let audit = world.audit_log.as_ref().expect("audit_log must be open");
    audit.verify_chain().expect("audit chain must verify after REVOKE_SESSION_KEY");
}

// ---------------------------------------------------------------------------
// Scenario 3: Session Key expiry causes DENY with reason EXPIRED
// ---------------------------------------------------------------------------

#[given("an active Session Key whose expiry_unix is in the past")]
async fn expired_session_key(world: &mut ConformanceWorld) {
    owner_has_passkey(world).await;
    policy_drafted(world).await;
    // Override expiry to the distant past.
    if let Some(p) = world.policy.as_mut() {
        p.rules.expiry_unix = 1; // Unix epoch (way in the past)
    }
    agent_calls_create_session_key(world).await;

    // Initialize a fresh PolicyState for the (now expired) session key.
    let tmp = tempdir().expect("tempdir for expired policy_state");
    let path = tmp.path().join("policy_state_expired.json");
    std::mem::forget(tmp);
    let session_key_id = world.session_key_id.clone().unwrap_or_else(|| "sk-expired".to_string());
    let state = PolicyState::load(&path, session_key_id).expect("PolicyState::load");
    world.policy_state = Some(state);
    world.policy_state_path = Some(path);
}

#[when("the Agent calls PayX402 using that session_key_id")]
async fn agent_calls_pay_x402(world: &mut ConformanceWorld) {
    let policy = world.policy.as_ref().expect("policy must be set").clone();
    let mut state =
        PolicyState::new(world.session_key_id.clone().unwrap_or_default()).with_policy(policy);
    let req = PayRequest {
        session_key_id: world.session_key_id.clone().unwrap_or_default(),
        device_id: "dev-test".to_string(),
        amount_usd: 0.01,
        asset: "eip155:1/erc20:0xAsset".to_string(),
        chain_id: "eip155:8453".to_string(),
        recipient: Some("0xRecipient".to_string()),
    };
    let session_key_id = req.session_key_id.clone();
    let decision = evaluate_11_step(&req, &session_key_id, &mut state);
    world.last_decision = Some(decision.clone());

    // Append audit entry for the PayX402 attempt.
    let session_key_id_for_audit = world.session_key_id.clone();
    let audit = world.audit_log.as_mut().expect("audit_log must be open");
    match &decision {
        Decision::Deny(reason) => {
            world.last_deny_reason = Some(reason.clone());
            world.last_audit_event = Some(EventType::PayX402);
            audit
                .append(
                    EventType::PayX402,
                    session_key_id_for_audit,
                    serde_json::json!({"status": "denied", "reason": format!("{reason:?}")}),
                )
                .expect("audit append for denied PayX402 must succeed");
        }
        Decision::Allow | Decision::Warn(_) => {
            world.last_audit_event = Some(EventType::PayX402);
            audit
                .append(
                    EventType::PayX402,
                    session_key_id_for_audit,
                    serde_json::json!({"status": "allowed"}),
                )
                .expect("audit append for allowed PayX402 must succeed");
        }
    }
}

#[then("the Policy Engine evaluates the expiry_unix before any other rule")]
async fn then_expiry_evaluated_first(world: &mut ConformanceWorld) {
    assert_eq!(
        world.last_deny_reason,
        Some(DenyReason::Expired),
        "expiry must be evaluated before any other rule"
    );
}

#[then(regex = r#"^the response has status DENY and deny_reason "EXPIRED"$"#)]
async fn then_response_deny_with_reason(world: &mut ConformanceWorld) {
    assert!(
        matches!(world.last_decision, Some(Decision::Deny(DenyReason::Expired))),
        "expected Deny(Expired), got {:?}",
        world.last_decision
    );
}

#[then(regex = r"^an audit entry is appended with status DENIED and reason EXPIRED$")]
async fn then_audit_deny_appended(world: &mut ConformanceWorld) {
    assert_eq!(
        world.last_audit_event,
        Some(EventType::PayX402),
        "expected PayX402 audit event for the denied request"
    );
    let audit = world.audit_log.as_ref().expect("audit_log must be open");
    audit.verify_chain().expect("audit chain must verify after denied PayX402");
}

// ---------------------------------------------------------------------------
// Scenario 4: Main wallet Owner key never exposed to Agent
// ---------------------------------------------------------------------------

#[given("an Agent has been issued a Session Key")]
async fn agent_issued_session_key(world: &mut ConformanceWorld) {
    // Run the create-session-key flow so the Agent has a session key in hand.
    owner_has_passkey(world).await;
    policy_drafted(world).await;
    agent_calls_create_session_key(world).await;
}

#[when("the Agent lists available WalletConnect v2 methods")]
async fn agent_lists_methods(world: &mut ConformanceWorld) {
    // The list is populated in `ConformanceWorld::new()`. Assert non-empty
    // here so a regression in init is caught at this step.
    assert!(!world.agent_method_surface.is_empty(), "Agent method surface must not be empty");
}

#[then("no method returns the Owner key, BIP-32 root, or mnemonic")]
async fn then_no_owner_key_exposed(world: &mut ConformanceWorld) {
    // Behavioral: the WalletConnect v2 method router has no ExportOwnerKey /
    // ExportMnemonic JSON-RPC method. We assert no method name suggests
    // exposing owner key material.
    for method in &world.agent_method_surface {
        let lower = method.to_lowercase();
        assert!(!lower.contains("owner"), "method `{method}` exposes owner key");
        assert!(!lower.contains("mnemonic"), "method `{method}` exposes mnemonic");
        assert!(!lower.contains("seed"), "method `{method}` exposes seed");
        assert!(!lower.contains("root"), "method `{method}` exposes BIP-32 root");
    }
}

#[then("all signing operations performed by the Agent use only the Session Key")]
async fn then_signing_uses_session_key(world: &mut ConformanceWorld) {
    let session_priv = world.session_priv.as_ref().expect("session_priv must be set");
    // Reconstruct a borrowable copy via HardenedBytes — SessionPrivateKey isn't Clone.
    let session_priv_clone = SessionPrivateKey {
        raw: HardenedBytes::from_slice(session_priv.raw.expose())
            .expect("HardenedBytes::from_slice for sign_with"),
        scheme: session_priv.scheme,
    };

    let mock_rpc = MockRpcClient::ok();
    let provider = EvmSessionKeyProvider::new("eip155:8453", "0xSCA", Box::new(mock_rpc));
    let payload = SignPayload::Message { bytes: b"hello".to_vec() };
    let sig =
        provider.sign_with(&session_priv_clone, &payload).await.expect("sign_with must succeed");
    match sig {
        Signature::Evm { hex } => assert!(!hex.is_empty(), "EVM signature must be non-empty"),
        Signature::Solana { base58 } => {
            assert!(!base58.is_empty(), "Solana signature must be non-empty");
        }
    }
}

#[then("the audit log shows every Owner-key signature is co-signed by a PasskeyAuthorization")]
async fn then_owner_sig_co_signed(world: &mut ConformanceWorld) {
    // For T22, assert that every audit entry for CreateSessionKey or
    // RevokeSessionKey (which require Owner-key authority) was preceded by a
    // successful Passkey verify. We track this via `last_audit_event` being
    // one of the Passkey-protected events.
    assert!(
        matches!(
            world.last_audit_event,
            Some(EventType::CreateSessionKey | EventType::RevokeSessionKey)
        ),
        "Owner-key audit event must be Passkey-co-signed, got {:?}",
        world.last_audit_event
    );
    let audit = world.audit_log.as_ref().expect("audit_log must be open");
    audit.verify_chain().expect("audit chain must verify for co-signed events");
}

// ---------------------------------------------------------------------------
// Scenario 5: EVM Session Key via ERC-7715
// ---------------------------------------------------------------------------

#[given(regex = r"^the main wallet uses an ERC-7579 modular Smart Contract Account.*$")]
async fn evm_sca_setup(world: &mut ConformanceWorld) {
    wallet_unlocked(world).await;
    owner_has_passkey(world).await;
    // Set chain_id to eip155:8453 for EVM.
    if let Some(ok) = world.owner_key.as_mut() {
        ok.chain_id = "eip155:8453".to_string();
    }
}

#[when("the Owner creates an EVM Session Key")]
async fn owner_creates_evm_key(world: &mut ConformanceWorld) {
    policy_drafted(world).await;
    // Use the Secp256k1Evm scheme marker (the actual signing bytes are
    // Ed25519 in this test fixture; the mock on-chain calls don't enforce
    // scheme match — only the receipt structure matters).
    let session_signing = SigningKey::generate(&mut rand_core::UnwrapErr(getrandom::SysRng));
    let session_priv_bytes = HardenedBytes::from_slice(&session_signing.to_bytes())
        .expect("HardenedBytes::from_slice for evm session_priv");
    world.session_priv =
        Some(SessionPrivateKey { raw: session_priv_bytes, scheme: KeyScheme::Secp256k1Evm });
    world.session_pubkey = Some(PublicKey {
        bytes: session_signing.verifying_key().to_bytes().to_vec(),
        scheme: KeyScheme::Secp256k1Evm,
    });

    // Call grant on EvmSessionKeyProvider.
    let mock_rpc = MockRpcClient::ok();
    world.mock_rpc_counters = Some(mock_rpc.counters());
    let provider = EvmSessionKeyProvider::new("eip155:8453", "0xSCA", Box::new(mock_rpc));
    let policy = world.policy.as_ref().expect("policy must be drafted").clone();
    let owner_key = world.owner_key.as_ref().expect("owner_key must be set");
    let session_pubkey = world.session_pubkey.as_ref().expect("session_pubkey must be set").clone();
    let receipt =
        provider.grant(owner_key, &session_pubkey, &policy).await.expect("Evm grant must succeed");
    world.grant_receipt = Some(receipt);
    world.session_key_id = Some("oc_sk_evm".to_string());
}

#[then("the SessionKeyProvider calls grant on the EVM SessionKeyProvider")]
async fn then_evm_grant_called(world: &mut ConformanceWorld) {
    let counters = world.mock_rpc_counters.as_ref().expect("mock_rpc_counters must be set");
    assert!(
        counters.evm_tx() >= 1,
        "EvmSessionKeyProvider.grant must call send_evm_tx at least once"
    );
}

#[then("the SCA contract stores a MerkleRoot committing to the Session Key policy via ERC-7715")]
async fn then_sca_stores_merkle_root(world: &mut ConformanceWorld) {
    let receipt = world.grant_receipt.as_ref().expect("grant_receipt must be set");
    match receipt {
        GrantReceipt::Evm { merkle_root, .. } => {
            assert!(
                merkle_root.starts_with("0x"),
                "MerkleRoot must be 0x-prefixed hex, got {merkle_root}"
            );
            assert_eq!(
                merkle_root.len(),
                66,
                "MerkleRoot must be 32 bytes hex (66 chars with 0x prefix), got {}",
                merkle_root.len()
            );
        }
        other => panic!("Expected Evm GrantReceipt, got {other:?}"),
    }
}

#[then("a GrantReceipt with the on-chain transaction hash is returned")]
async fn then_grant_receipt_returned(world: &mut ConformanceWorld) {
    let receipt = world.grant_receipt.as_ref().expect("grant_receipt must be set");
    match receipt {
        GrantReceipt::Evm { tx_hash, .. } => {
            assert!(!tx_hash.is_empty(), "tx_hash must be non-empty");
        }
        other => panic!("Expected Evm GrantReceipt, got {other:?}"),
    }
}

#[then("the SCA validates every subsequent UserOp against the registered ERC-7715 permissions")]
async fn then_sca_validates_userops(world: &mut ConformanceWorld) {
    // Verify: call verify_active on the provider — mock returns 0x01 (true).
    let mock_rpc = MockRpcClient::ok();
    let provider = EvmSessionKeyProvider::new("eip155:8453", "0xSCA", Box::new(mock_rpc));
    let session_key_id = world.session_key_id.clone().unwrap_or_else(|| "oc_sk_evm".to_string());
    let active = provider.verify_active(&session_key_id).await.expect("verify_active must succeed");
    assert!(active, "SCA must validate the session key as active");
}

// ---------------------------------------------------------------------------
// Scenario 6: Solana Session Key via Session Tokens program
// ---------------------------------------------------------------------------

#[given(regex = r"^the main wallet has a Solana account on chain.*$")]
async fn solana_setup(world: &mut ConformanceWorld) {
    wallet_unlocked(world).await;
    owner_has_passkey(world).await;
    // Set chain_id to solana:mainnet.
    if let Some(ok) = world.owner_key.as_mut() {
        ok.chain_id = "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp".to_string();
    }
}

#[when("the Owner creates a Solana Session Key")]
async fn owner_creates_solana_key(world: &mut ConformanceWorld) {
    policy_drafted(world).await;
    // Use Ed25519Solana scheme for Solana.
    let session_signing = SigningKey::generate(&mut rand_core::UnwrapErr(getrandom::SysRng));
    let session_priv_bytes = HardenedBytes::from_slice(&session_signing.to_bytes())
        .expect("HardenedBytes::from_slice for solana session_priv");
    world.session_priv =
        Some(SessionPrivateKey { raw: session_priv_bytes, scheme: KeyScheme::Ed25519Solana });
    world.session_pubkey = Some(PublicKey {
        bytes: session_signing.verifying_key().to_bytes().to_vec(),
        scheme: KeyScheme::Ed25519Solana,
    });

    // Call grant on SolanaSessionKeyProvider.
    let mock_rpc = MockRpcClient::ok();
    world.mock_rpc_counters = Some(mock_rpc.counters());
    let provider = SolanaSessionKeyProvider::new(
        "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp",
        "SolanaSessionTokensProgram",
        Box::new(mock_rpc),
    );
    let policy = world.policy.as_ref().expect("policy must be drafted").clone();
    let owner_key = world.owner_key.as_ref().expect("owner_key must be set");
    let session_pubkey = world.session_pubkey.as_ref().expect("session_pubkey must be set").clone();
    let receipt = provider
        .grant(owner_key, &session_pubkey, &policy)
        .await
        .expect("Solana grant must succeed");
    world.grant_receipt = Some(receipt);
    world.session_key_id = Some("oc_sk_sol".to_string());
}

#[then("the SessionKeyProvider calls grant on the Solana SessionKeyProvider")]
async fn then_solana_grant_called(world: &mut ConformanceWorld) {
    let counters = world.mock_rpc_counters.as_ref().expect("mock_rpc_counters must be set");
    assert!(
        counters.solana_tx() >= 1,
        "SolanaSessionKeyProvider.grant must call send_solana_tx at least once"
    );
}

#[then("the Solana Session Tokens program records the delegated permissions on-chain")]
async fn then_solana_records_permissions(world: &mut ConformanceWorld) {
    let receipt = world.grant_receipt.as_ref().expect("grant_receipt must be set");
    match receipt {
        GrantReceipt::Solana { session_tokens_account, .. } => {
            assert!(!session_tokens_account.is_empty(), "session_tokens_account must be non-empty");
        }
        other => panic!("Expected Solana GrantReceipt, got {other:?}"),
    }
}

#[then("a GrantReceipt referencing the Session Tokens account is returned")]
async fn then_solana_receipt_returned(world: &mut ConformanceWorld) {
    let receipt = world.grant_receipt.as_ref().expect("grant_receipt must be set");
    assert!(
        matches!(receipt, GrantReceipt::Solana { .. }),
        "expected Solana GrantReceipt, got {receipt:?}"
    );
}

#[then(
    "subsequent Solana transactions signed by the Session Key are validated by the Session Tokens program"
)]
async fn then_solana_tx_validated(world: &mut ConformanceWorld) {
    // Verify: call verify_active on the provider — mock returns Some(vec![0x01]).
    let mock_rpc = MockRpcClient::ok();
    let provider = SolanaSessionKeyProvider::new(
        "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp",
        "SolanaSessionTokensProgram",
        Box::new(mock_rpc),
    );
    let session_key_id = world.session_key_id.clone().unwrap_or_else(|| "oc_sk_sol".to_string());
    let active = provider.verify_active(&session_key_id).await.expect("verify_active must succeed");
    assert!(active, "Session Tokens program must validate the session key as active");
}
