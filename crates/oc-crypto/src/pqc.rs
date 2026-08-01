//! Post-quantum cryptography primitives for OneCipher.
//!
//! Provides FIPS 204 (ML-DSA, formerly CRYSTALS-Dilithium) digital signatures
//! and a hybrid KEM framework for combining classical X25519 with a future
//! ML-KEM (FIPS 203, formerly CRYSTALS-Kyber) implementation.
//!
//! ML-KEM is deferred until the `age` crate's `ml-kem 0.2.x` dependency
//! conflict with `ml-kem 0.3.x` is resolved upstream. The `hybrid_kem_combine`
//! function is ready to accept ML-KEM shared secrets when available.
//!
//! Design goals:
//! - Hybrid mode: combine classical X25519 ECDH with ML-KEM-768 for defense-in-depth (neither
//!   algorithm alone is a single point of failure).
//! - Pure Rust implementations — zero C deps.
//! - Zero I/O, zero network deps (R51/R52 compliant).

use crate::{HardenedBytes, MemGuardError};

/// Errors from post-quantum operations.
#[derive(Debug, thiserror::Error)]
pub enum PqcError {
    #[error("ML-DSA signing failed: {0}")]
    SignFailed(String),
    #[error("ML-DSA verification failed: {0}")]
    VerifyFailed(String),
    #[error("ML-DSA key generation failed: {0}")]
    KeyGenFailed(String),
    #[error("memory hardening failed: {0}")]
    MemGuard(#[from] MemGuardError),
}

// ─────────────────────────────────────────────────────────────────────────────
// ML-DSA-65 (Digital Signature Algorithm, FIPS 204)
// ─────────────────────────────────────────────────────────────────────────────

/// ML-DSA-65 signing keypair (FIPS 204, security level 3 ≈ AES-192).
pub struct MlDsa65Keypair {
    /// The verifying key (public), encoded as bytes.
    pub verifying_key: Vec<u8>,
    /// The signing key (secret, zeroized on drop), encoded as seed bytes.
    pub signing_key: MlDsaSigningKey,
}

/// Wrapper around the ML-DSA signing key seed that is mlock'd and zeroized on drop.
pub struct MlDsaSigningKey {
    inner: HardenedBytes,
}

impl MlDsaSigningKey {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, PqcError> {
        let inner = HardenedBytes::from_slice(bytes)
            .map_err(|e| PqcError::KeyGenFailed(format!("mlock failed: {e}")))?;
        Ok(Self { inner })
    }

    pub fn expose(&self) -> &[u8] {
        self.inner.as_ref()
    }
}

/// Generate an ML-DSA-65 keypair using the OS random number generator.
pub fn ml_dsa_65_keygen() -> Result<MlDsa65Keypair, PqcError> {
    use ml_dsa::{Keypair, MlDsa65, SigningKey};
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).map_err(|e| PqcError::SignFailed(e.to_string()))?;
    let seed_arr = ml_dsa::B32::from(seed);
    let signing_key = SigningKey::<MlDsa65>::from_seed(&seed_arr);
    let verifying_key = signing_key.verifying_key();
    Ok(MlDsa65Keypair {
        verifying_key: verifying_key.encode().to_vec(),
        signing_key: MlDsaSigningKey::from_bytes(&seed)?,
    })
}

/// Sign a message with ML-DSA-65 (deterministic mode).
pub fn ml_dsa_65_sign(signing_key: &MlDsaSigningKey, message: &[u8]) -> Result<Vec<u8>, PqcError> {
    use ml_dsa::{MlDsa65, SigningKey};
    let seed_bytes: [u8; 32] = signing_key
        .expose()
        .try_into()
        .map_err(|_| PqcError::SignFailed("invalid seed length, expected 32 bytes".into()))?;
    let seed_arr = ml_dsa::B32::from(seed_bytes);
    let sk = SigningKey::<MlDsa65>::from_seed(&seed_arr);
    let expanded = sk.expanded_key();
    let sig = expanded
        .sign_deterministic(message, &[])
        .map_err(|e| PqcError::SignFailed(e.to_string()))?;
    Ok(sig.encode().to_vec())
}

/// Verify an ML-DSA-65 signature.
pub fn ml_dsa_65_verify(
    verifying_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), PqcError> {
    use ml_dsa::{MlDsa65, Signature, Verifier, VerifyingKey};
    let encoded_vk = ml_dsa::EncodedVerifyingKey::<MlDsa65>::try_from(verifying_key)
        .map_err(|e| PqcError::VerifyFailed(format!("invalid verifying key: {e}")))?;
    let vk = VerifyingKey::<MlDsa65>::decode(&encoded_vk);
    let encoded_sig = ml_dsa::EncodedSignature::<MlDsa65>::try_from(signature)
        .map_err(|e| PqcError::VerifyFailed(format!("invalid signature: {e}")))?;
    let sig = Signature::<MlDsa65>::decode(&encoded_sig)
        .ok_or_else(|| PqcError::VerifyFailed("signature decode failed".into()))?;
    vk.verify(message, &sig)
        .map_err(|_| PqcError::VerifyFailed("signature verification failed".into()))
}

// ─────────────────────────────────────────────────────────────────────────────
// Hybrid KEM framework (X25519 + ML-KEM-768)
// ─────────────────────────────────────────────────────────────────────────────

/// Derive a hybrid shared secret from X25519 and a post-quantum KEM.
///
/// The two shared secrets are concatenated and hashed with SHA-256 to produce
/// a single 32-byte key. This ensures that breaking *either* algorithm alone
/// does not compromise the key.
///
/// When ML-KEM-768 support is added (pending `age` crate dependency resolution),
/// pass the ML-KEM shared secret as `pq_shared`.
pub fn hybrid_kem_combine(
    x25519_shared: &[u8; 32],
    pq_shared: &HardenedBytes,
) -> Result<HardenedBytes, PqcError> {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(b"hybrid-kem-x25519-mlkem768-v1");
    hasher.update(x25519_shared);
    hasher.update(pq_shared.expose());
    let hash = hasher.finalize();
    Ok(HardenedBytes::from_slice(&hash)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ml_dsa_65_roundtrip() {
        let keypair = ml_dsa_65_keygen().unwrap();
        let message = b"test message for ML-DSA-65";
        let signature = ml_dsa_65_sign(&keypair.signing_key, message).unwrap();
        ml_dsa_65_verify(&keypair.verifying_key, message, &signature).unwrap();
    }

    #[test]
    fn test_ml_dsa_65_wrong_message_fails() {
        let keypair = ml_dsa_65_keygen().unwrap();
        let signature = ml_dsa_65_sign(&keypair.signing_key, b"correct").unwrap();
        let result = ml_dsa_65_verify(&keypair.verifying_key, b"tampered", &signature);
        assert!(result.is_err());
    }

    #[test]
    fn test_hybrid_kem_combine() {
        let x25519_secret = [0x42u8; 32];
        let pq_secret = HardenedBytes::from_slice(&[0x37u8; 32]).unwrap();
        let combined = hybrid_kem_combine(&x25519_secret, &pq_secret).unwrap();
        assert_eq!(combined.expose().len(), 32);

        let x25519_secret2 = [0x43u8; 32];
        let combined2 = hybrid_kem_combine(&x25519_secret2, &pq_secret).unwrap();
        assert_ne!(combined.expose(), combined2.expose());
    }
}
