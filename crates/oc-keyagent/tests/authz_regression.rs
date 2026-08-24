// Test code may unwrap/expect/panic (workspace lint phase-1 carve-out).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Regression tests for the Key-Agent authorization fixes.
//!
//! Covers:
//! - **Wallet binding (H6)**: a passkey registered for wallet A must NOT authorize signing for
//!   wallet B (`verify_passkey_for`).
//! - **Wildcard refusal (M16)**: `RegisterPasskey` with an empty `wallet_id` is rejected — unbound
//!   credentials would act as signing wildcards.
//! - **Session-key lifecycle (H4)**: created keys are persisted and active; revoked keys cause
//!   signing requests carrying their id to be rejected before any key material is touched.
//!
//! The tests drive everything through `handler::dispatch` against an
//! isolated temp HOME so no global state leaks between runs.
//!
//! Per R56 these tests are synchronous (no tokio / reqwest / hyper).

use std::sync::MutexGuard;

use ed25519_dalek::Signer as _;
use oc_keyagent::{
    CreateSessionKeyRequest, CreateSessionKeyResponse, GenerateChallengeRequest,
    GenerateChallengeResponse, KeyAgentRequest, KeyAgentRequestKind, KeyAgentResponseKind,
    PasskeyAuthorization, RevokeSessionKeyRequest, SignTransactionRequest,
};
use prost::Message;

/// Serializes HOME-mutating tests (the passkey store lives under HOME).
static HOME_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// RAII guard that redirects `HOME` to a fresh temp dir and restores the
/// original value on drop.
struct HomeGuard {
    _lock: MutexGuard<'static, ()>,
    _dir: tempfile::TempDir,
}

impl HomeGuard {
    fn new() -> Self {
        let lock = HOME_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let dir = tempfile::tempdir().expect("create temp HOME dir");
        let home = dir.path().to_string_lossy().into_owned();
        // SAFETY: tests are serialized via HOME_LOCK; no other thread reads
        // HOME concurrently within this test binary.
        unsafe { std::env::set_var("HOME", &home) };
        Self { _lock: lock, _dir: dir }
    }
}

/// An in-test passkey holder: a fresh Ed25519 keypair bound to a credential id.
struct TestPasskey {
    credential_id: String,
    signing_key: ed25519_dalek::SigningKey,
}

impl TestPasskey {
    fn new(credential_id: &str) -> Self {
        let mut seed = [0u8; 32];
        rand::RngExt::fill(&mut rand::rng(), &mut seed);
        Self {
            credential_id: credential_id.to_string(),
            signing_key: ed25519_dalek::SigningKey::from_bytes(&seed),
        }
    }

    /// Register this passkey for `wallet_id` through the public dispatcher.
    fn register(&self, wallet_id: &str) {
        let reg = oc_keyagent::RegisterPasskeyRequest {
            wallet_id: wallet_id.to_string(),
            credential_id: self.credential_id.clone(),
            algorithm: "ed25519".to_string(),
            public_key: self.signing_key.verifying_key().to_bytes().to_vec(),
        };
        let resp = dispatch(KeyAgentRequestKind::RegisterPasskey(reg));
        assert!(!resp.is_error(), "register failed: {resp:?}");
    }

    /// Run the challenge round-trip and produce a valid authorization.
    fn authorize(&self) -> PasskeyAuthorization {
        let chal_req = GenerateChallengeRequest { credential_id: self.credential_id.clone() };
        let bytes = match dispatch(KeyAgentRequestKind::GenerateChallenge(chal_req)).kind {
            Some(KeyAgentResponseKind::Ok(b)) => b,
            other => panic!("generate_challenge failed: {other:?}"),
        };
        let challenge =
            GenerateChallengeResponse::decode(bytes.as_slice()).expect("decode challenge");
        let message = [&challenge.challenge[..], self.credential_id.as_bytes()].concat();
        let signature = self.signing_key.sign(&message);
        PasskeyAuthorization {
            challenge: challenge.challenge,
            signature: signature.to_bytes().to_vec(),
            credential_id: self.credential_id.clone(),
        }
    }
}

fn dispatch(kind: KeyAgentRequestKind) -> oc_keyagent::KeyAgentResponse {
    let req = KeyAgentRequest { kind: Some(kind) };
    oc_keyagent::dispatch(&req).expect("dispatch must not fail")
}

#[test]
fn passkey_bound_to_wallet_a_cannot_sign_for_wallet_b() {
    let _home = HomeGuard::new();
    let pk_a = TestPasskey::new("cred-a");
    pk_a.register("wallet-a");

    let auth = pk_a.authorize();
    let req = KeyAgentRequestKind::SignTransaction(SignTransactionRequest {
        session_key_id: String::new(),
        wallet_id: "wallet-b".to_string(),
        chain_id: "eip155:1".to_string(),
        raw_tx_hex: "deadbeef".to_string(),
        auth: Some(auth),
    });
    let resp = dispatch(req);
    assert!(resp.is_error(), "cross-wallet signing must be rejected");
    let msg = match resp.kind {
        Some(KeyAgentResponseKind::Error(m)) => m,
        other => panic!("expected Error, got {other:?}"),
    };
    assert!(
        msg.contains("not registered for this wallet"),
        "binding mismatch must be reported, got: {msg}"
    );
}

#[test]
fn unbounded_wildcard_passkey_registration_is_rejected() {
    let _home = HomeGuard::new();
    let pk = TestPasskey::new("cred-wildcard");
    let reg = oc_keyagent::RegisterPasskeyRequest {
        wallet_id: String::new(),
        credential_id: pk.credential_id.clone(),
        algorithm: "ed25519".to_string(),
        public_key: pk.signing_key.verifying_key().to_bytes().to_vec(),
    };
    let resp = dispatch(KeyAgentRequestKind::RegisterPasskey(reg));
    assert!(resp.is_error(), "empty wallet_id registration must be rejected");
}

#[test]
fn revoked_session_key_blocks_signing_requests_carrying_its_id() {
    let _home = HomeGuard::new();
    let pk = TestPasskey::new("cred-sk");
    pk.register("wallet-sk");

    // 1. Create a session key.
    let create = CreateSessionKeyRequest {
        label: "agent-key".to_string(),
        rules: None,
        budget: None,
        auth: Some(pk.authorize()),
    };
    let bytes = match dispatch(KeyAgentRequestKind::CreateSessionKey(create)).kind {
        Some(KeyAgentResponseKind::Ok(b)) => b,
        other => panic!("create_session_key failed: {other:?}"),
    };
    let created = CreateSessionKeyResponse::decode(bytes.as_slice()).expect("decode create");
    let sk_id = created.session_key_id;
    assert!(sk_id.starts_with("sk-"), "unexpected id format: {sk_id}");

    // 2. A signing request carrying the ACTIVE id passes the session gate (it later fails on vault
    //    decrypt because no such wallet exists — the important part is the error is NOT the
    //    session-key one).
    let tx_with_active = KeyAgentRequestKind::SignTransaction(SignTransactionRequest {
        session_key_id: sk_id.clone(),
        wallet_id: "wallet-sk".to_string(),
        chain_id: "eip155:1".to_string(),
        raw_tx_hex: "deadbeef".to_string(),
        auth: Some(pk.authorize()),
    });
    let msg_active = match dispatch(tx_with_active).kind {
        Some(KeyAgentResponseKind::Error(m)) => m,
        other => panic!("expected Error, got {other:?}"),
    };
    assert!(
        !msg_active.contains("E_SESSION_KEY"),
        "active session key must pass the gate, got: {msg_active}"
    );

    // 3. Revoke the session key.
    let revoke =
        RevokeSessionKeyRequest { session_key_id: sk_id.clone(), auth: Some(pk.authorize()) };
    let resp = dispatch(KeyAgentRequestKind::RevokeSessionKey(revoke));
    assert!(!resp.is_error(), "revoke failed: {resp:?}");

    // 4. The same signing request is now rejected by the session gate.
    let tx_after_revoke = KeyAgentRequestKind::SignTransaction(SignTransactionRequest {
        session_key_id: sk_id.clone(),
        wallet_id: "wallet-sk".to_string(),
        chain_id: "eip155:1".to_string(),
        raw_tx_hex: "deadbeef".to_string(),
        auth: Some(pk.authorize()),
    });
    let msg_revoked = match dispatch(tx_after_revoke).kind {
        Some(KeyAgentResponseKind::Error(m)) => m,
        other => panic!("expected Error, got {other:?}"),
    };
    assert!(
        msg_revoked.contains("E_SESSION_KEY") && msg_revoked.contains(&sk_id),
        "revoked session key must block signing, got: {msg_revoked}"
    );
}
