//! Integration tests for `oc_keyagent::passkey::PasskeyVerifier` (T15).
//!
//! Covers every scenario from `specs/.../features/passkey_authorization.feature`:
//! - missing auth → [`PasskeyError::Missing`]
//! - valid auth → `Ok(())` (P-256 + Ed25519)
//! - reused challenge → [`PasskeyError::Replay`]
//! - forged signature → [`PasskeyError::Forged`]
//! - boolean-only / empty signature → [`PasskeyError::Forged`] (R31: never trust a boolean)
//! - credential_id mismatch → [`PasskeyError::CredentialMismatch`]
//! - `generate_challenge` uniqueness (100 distinct nonces)
//!
//! Per R30/R31/C-05: the Key-Agent verifies the Passkey signature itself and
//! never consults a UI boolean. The `PasskeyAuthorization` proto has no
//! `authorized` / `user_verified` boolean field, so the "boolean-only attack"
//! is simulated by sending an empty / garbage signature with valid challenge
//! and credential_id — the verifier must still deny with `Forged`.

use oc_keyagent::{
    passkey::{PasskeyError, PasskeyPubkey, PasskeyVerifier},
    proto::PasskeyAuthorization,
};
// ----------------------------------------------------------------------------
// Test helpers
// ----------------------------------------------------------------------------
use p256::elliptic_curve::Generate;

/// Generate a P-256 keypair and sign `message`. Returns `(verifying_key, signature_bytes)`.
///
/// Used for cases where we want a *different* key than the verifier was bound
/// to (forged-signature and credential-mismatch tests).
fn sign_p256(message: &[u8]) -> (p256::ecdsa::VerifyingKey, Vec<u8>) {
    use p256::ecdsa::signature::Signer;
    let sk = p256::ecdsa::SigningKey::generate();
    let vk = p256::ecdsa::VerifyingKey::from(&sk);
    let sig: p256::ecdsa::Signature = sk.sign(message);
    (vk, sig.to_bytes().to_vec())
}

/// Build the OneCipher simplified signed message: `challenge || credential_id`.
fn message_for(challenge: &[u8], credential_id: &str) -> Vec<u8> {
    let mut m = Vec::with_capacity(challenge.len() + credential_id.len());
    m.extend_from_slice(challenge);
    m.extend_from_slice(credential_id.as_bytes());
    m
}

const CRED_ID: &str = "cred-test-12345";

// ----------------------------------------------------------------------------
// 1. Missing auth → Missing
// ----------------------------------------------------------------------------

#[test]
fn test_missing_auth_returns_missing() {
    let (vk, _) = sign_p256(b"init-only");
    let mut verifier = PasskeyVerifier::new(PasskeyPubkey::P256(vk), CRED_ID.as_bytes().to_vec());

    // All fields empty.
    let empty =
        PasskeyAuthorization { challenge: vec![], signature: vec![], credential_id: String::new() };
    assert_eq!(verifier.verify(&empty), Err(PasskeyError::Missing));

    // Wrong-length challenge (not 32 bytes).
    let bad_challenge = PasskeyAuthorization {
        challenge: vec![0xAB; 16],
        signature: vec![0xCD; 64],
        credential_id: CRED_ID.to_string(),
    };
    assert_eq!(verifier.verify(&bad_challenge), Err(PasskeyError::Missing));

    // Empty credential_id with valid-length challenge + non-empty signature.
    let no_cred = PasskeyAuthorization {
        challenge: vec![0x11; 32],
        signature: vec![0xCD; 64],
        credential_id: String::new(),
    };
    assert_eq!(verifier.verify(&no_cred), Err(PasskeyError::Missing));
}

// ----------------------------------------------------------------------------
// 2. Valid auth → Ok
// ----------------------------------------------------------------------------

#[test]
fn test_valid_auth_returns_ok() {
    use p256::ecdsa::signature::Signer;
    let sk = p256::ecdsa::SigningKey::generate();
    let vk = p256::ecdsa::VerifyingKey::from(&sk);
    let mut verifier = PasskeyVerifier::new(PasskeyPubkey::P256(vk), CRED_ID.as_bytes().to_vec());

    let challenge = verifier.generate_challenge();
    let message = message_for(&challenge, CRED_ID);
    let sig: p256::ecdsa::Signature = sk.sign(&message);

    let auth = PasskeyAuthorization {
        challenge: challenge.to_vec(),
        signature: sig.to_bytes().to_vec(),
        credential_id: CRED_ID.to_string(),
    };
    assert_eq!(verifier.verify(&auth), Ok(()));
    // Challenge was consumed (single-use).
    assert_eq!(verifier.pending_count(), 0);
}

// ----------------------------------------------------------------------------
// 3. Reused challenge → Replay
// ----------------------------------------------------------------------------

#[test]
fn test_reused_challenge_returns_replay() {
    use p256::ecdsa::signature::Signer;
    let sk = p256::ecdsa::SigningKey::generate();
    let vk = p256::ecdsa::VerifyingKey::from(&sk);
    let mut verifier = PasskeyVerifier::new(PasskeyPubkey::P256(vk), CRED_ID.as_bytes().to_vec());

    let challenge = verifier.generate_challenge();
    let message = message_for(&challenge, CRED_ID);
    let sig: p256::ecdsa::Signature = sk.sign(&message);
    let sig_bytes = sig.to_bytes().to_vec();

    let auth = PasskeyAuthorization {
        challenge: challenge.to_vec(),
        signature: sig_bytes,
        credential_id: CRED_ID.to_string(),
    };
    // First use: Ok.
    assert_eq!(verifier.verify(&auth), Ok(()));
    // Second use: same challenge (already consumed) → Replay.
    assert_eq!(verifier.verify(&auth), Err(PasskeyError::Replay));
    // Pending set stays empty after both attempts.
    assert_eq!(verifier.pending_count(), 0);
}

// ----------------------------------------------------------------------------
// 4. Forged signature → Forged
// ----------------------------------------------------------------------------

#[test]
fn test_forged_signature_returns_forged() {
    let (vk_real, _) = sign_p256(b"real-key");
    let mut verifier =
        PasskeyVerifier::new(PasskeyPubkey::P256(vk_real), CRED_ID.as_bytes().to_vec());

    let challenge = verifier.generate_challenge();
    let message = message_for(&challenge, CRED_ID);
    // Sign with a DIFFERENT private key — verify against `vk_real` must fail.
    let (_, wrong_sig) = sign_p256(&message);

    let auth = PasskeyAuthorization {
        challenge: challenge.to_vec(),
        signature: wrong_sig,
        credential_id: CRED_ID.to_string(),
    };
    assert_eq!(verifier.verify(&auth), Err(PasskeyError::Forged));
    // The challenge was NOT consumed on a failed verify — it remains in
    // pending so a legitimate retry with the correct signature could still
    // succeed. (Single-use is enforced only after a successful verify.)
    assert_eq!(verifier.pending_count(), 1);
}

// ----------------------------------------------------------------------------
// 5. Boolean-only attack → Forged (R31: never trust a boolean)
// ----------------------------------------------------------------------------

#[test]
fn test_boolean_only_returns_forged() {
    let (vk, _) = sign_p256(b"init-only");
    let mut verifier = PasskeyVerifier::new(PasskeyPubkey::P256(vk), CRED_ID.as_bytes().to_vec());

    // R31: a tampered UI sends "authorized=true" with no signature bytes.
    // The proto has no boolean field; we simulate the attack by sending an
    // empty signature with valid challenge + credential_id.
    let challenge = verifier.generate_challenge();
    let empty_sig = PasskeyAuthorization {
        challenge: challenge.to_vec(),
        signature: vec![],
        credential_id: CRED_ID.to_string(),
    };
    assert_eq!(verifier.verify(&empty_sig), Err(PasskeyError::Forged));

    // Garbage signature bytes (boolean-only attack where the UI fakes a
    // signature without holding the private key) — also Forged.
    let challenge2 = verifier.generate_challenge();
    let garbage_sig = PasskeyAuthorization {
        challenge: challenge2.to_vec(),
        signature: vec![0xAA; 64], // well-formed length but wrong content
        credential_id: CRED_ID.to_string(),
    };
    assert_eq!(verifier.verify(&garbage_sig), Err(PasskeyError::Forged));
}

// ----------------------------------------------------------------------------
// 6. credential_id mismatch → CredentialMismatch
// ----------------------------------------------------------------------------

#[test]
fn test_credential_id_mismatch() {
    let (vk, _) = sign_p256(b"init-only");
    let mut verifier = PasskeyVerifier::new(PasskeyPubkey::P256(vk), CRED_ID.as_bytes().to_vec());

    let challenge = verifier.generate_challenge();
    // Sign with WRONG credential_id (so the signature is well-formed over
    // the wrong message; the verifier should reject on credential_id first).
    let wrong_cred = "cred-WRONG-98765";
    let message = message_for(&challenge, wrong_cred);
    let (_, sig) = sign_p256(&message);

    let auth = PasskeyAuthorization {
        challenge: challenge.to_vec(),
        signature: sig,
        credential_id: wrong_cred.to_string(),
    };
    assert_eq!(verifier.verify(&auth), Err(PasskeyError::CredentialMismatch));
}

// ----------------------------------------------------------------------------
// 7. P-256 signature verify (dedicated)
// ----------------------------------------------------------------------------

#[test]
fn test_p256_signature_verify() {
    use p256::ecdsa::signature::Signer;
    let sk = p256::ecdsa::SigningKey::generate();
    let vk = p256::ecdsa::VerifyingKey::from(&sk);
    let mut verifier = PasskeyVerifier::new(PasskeyPubkey::P256(vk), CRED_ID.as_bytes().to_vec());

    let challenge = verifier.generate_challenge();
    let message = message_for(&challenge, CRED_ID);
    let sig: p256::ecdsa::Signature = sk.sign(&message);

    let auth = PasskeyAuthorization {
        challenge: challenge.to_vec(),
        signature: sig.to_bytes().to_vec(),
        credential_id: CRED_ID.to_string(),
    };
    assert_eq!(verifier.verify(&auth), Ok(()));
    assert_eq!(verifier.pending_count(), 0);
}

// ----------------------------------------------------------------------------
// 8. Ed25519 signature verify (dedicated)
// ----------------------------------------------------------------------------

#[test]
fn test_ed25519_signature_verify() {
    use ed25519_dalek::Signer;
    let sk = ed25519_dalek::SigningKey::generate(&mut rand::rng());
    let vk = sk.verifying_key();
    let mut verifier =
        PasskeyVerifier::new(PasskeyPubkey::Ed25519(vk), CRED_ID.as_bytes().to_vec());

    let challenge = verifier.generate_challenge();
    let message = message_for(&challenge, CRED_ID);
    let sig: ed25519_dalek::Signature = sk.sign(&message);

    let auth = PasskeyAuthorization {
        challenge: challenge.to_vec(),
        signature: sig.to_bytes().to_vec(),
        credential_id: CRED_ID.to_string(),
    };
    assert_eq!(verifier.verify(&auth), Ok(()));
    assert_eq!(verifier.pending_count(), 0);
}

// ----------------------------------------------------------------------------
// 9. generate_challenge uniqueness — 100 calls, all distinct
// ----------------------------------------------------------------------------

#[test]
fn test_generate_challenge_uniqueness() {
    let (vk, _) = sign_p256(b"init-only");
    let mut verifier = PasskeyVerifier::new(PasskeyPubkey::P256(vk), CRED_ID.as_bytes().to_vec());

    let mut seen = std::collections::HashSet::new();
    for i in 0..100 {
        let ch = verifier.generate_challenge();
        assert!(seen.insert(ch), "challenge collision within 100 calls (iteration {i})");
    }
    assert_eq!(seen.len(), 100, "exactly 100 distinct challenges expected");
    assert_eq!(verifier.pending_count(), 100);
}
