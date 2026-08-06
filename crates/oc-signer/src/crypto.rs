//! Wallet encryption/decryption primitives.
//!
//! Cipher suite: **AES-256-GCM-SIV** (nonce-misuse-resistant AEAD) +
//! **Argon2id** (RFC 9106, password hashing competition winner) for
//! passphrase-based key derivation, or **HKDF-SHA256** for high-entropy
//! API tokens.
//!
//! Design rationale:
//! - AES-GCM-SIV: nonce reuse only reveals whether the same plaintext was encrypted twice, rather
//!   than catastrophically leaking the auth key as in AES-GCM.
//! - Argon2id: memory-hard KDF that resists GPU/ASIC attacks better than scrypt (2009). Tuned with
//!   m=64 MiB, t=3, p=4 for interactive use.
//! - HKDF: appropriate for high-entropy inputs (256-bit random API tokens) where expensive KDF is
//!   unnecessary.

use aes_gcm_siv::{Aes256GcmSiv, KeyInit, Nonce, aead::Aead};
use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::Zeroize;

use crate::SecretBytes as HardenedBytes;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptoEnvelope {
    pub cipher: String,
    pub cipherparams: CipherParams,
    pub ciphertext: String,
    pub auth_tag: String,
    pub kdf: String,
    pub kdfparams: KdfParamsVariant,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CipherParams {
    pub iv: String,
}

/// Argon2id KDF parameters (FIPS 203 / RFC 9106).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KdfParams {
    pub dklen: u32,
    pub m_cost: u32,
    pub t_cost: u32,
    pub p_cost: u32,
    pub salt: String,
}

/// HKDF-SHA256 KDF parameters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HkdfKdfParams {
    pub dklen: u32,
    pub salt: String,
    pub info: String,
}

/// Unified KDF parameters — deserializes to whichever variant matches the fields.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum KdfParamsVariant {
    Argon2id(KdfParams),
    Hkdf(HkdfKdfParams),
}

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("encryption failed: {0}")]
    EncryptionFailed(String),
    #[error("decryption failed: {0}")]
    DecryptionFailed(String),
    #[error("invalid parameters: {0}")]
    InvalidParams(String),
}

impl From<oc_crypto::MemGuardError> for CryptoError {
    fn from(e: oc_crypto::MemGuardError) -> Self {
        Self::DecryptionFailed(format!("memory hardening failed: {e}"))
    }
}

// Prevent fast-kdf from being used in release builds — weak KDF is test-only.
#[cfg(all(feature = "fast-kdf", not(debug_assertions)))]
compile_error!(
    "The `fast-kdf` feature reduces Argon2 parameters and must not be used in release builds. \
     Use dev-dependencies to enable it for tests only."
);

// Argon2id parameters: memory 64 MiB, 3 iterations, 4 parallelism.
// Production: ~200ms per call on modern hardware.
// Tests (fast-kdf): memory 8 MiB, 1 iteration, 1 parallelism (~5ms).
#[cfg(any(test, feature = "fast-kdf"))]
const ARGON2_M_COST: u32 = 8192; // 8 MiB
#[cfg(not(any(test, feature = "fast-kdf")))]
const ARGON2_M_COST: u32 = 65536; // 64 MiB

#[cfg(any(test, feature = "fast-kdf"))]
const ARGON2_T_COST: u32 = 1;
#[cfg(not(any(test, feature = "fast-kdf")))]
const ARGON2_T_COST: u32 = 3;

#[cfg(any(test, feature = "fast-kdf"))]
const ARGON2_P_COST: u32 = 1;
#[cfg(not(any(test, feature = "fast-kdf")))]
const ARGON2_P_COST: u32 = 4;

const KDF_DKLEN: u32 = 32;

/// Encrypt plaintext bytes using a passphrase (Argon2id KDF + AES-256-GCM-SIV).
///
/// Returns a `CryptoEnvelope` suitable for JSON serialization.
///
/// AES-GCM-SIV is nonce-misuse-resistant: if a nonce repeats, the only
/// information leaked is whether the same plaintext was encrypted twice.
pub fn encrypt(plaintext: &[u8], passphrase: &[u8]) -> Result<CryptoEnvelope, CryptoError> {
    let salt: [u8; 32] = rand::random();
    let nonce_bytes: [u8; 12] = rand::random();

    let mut derived_key = argon2id_derive(passphrase, &salt)?;
    let cipher = Aes256GcmSiv::new_from_slice(&derived_key)
        .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;
    derived_key.zeroize();

    let nonce = Nonce::from(nonce_bytes);
    let ciphertext_with_tag = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|_| CryptoError::EncryptionFailed("encryption failed".into()))?;

    // AES-GCM-SIV appends a 16-byte auth tag to the ciphertext
    let tag_offset = ciphertext_with_tag.len() - 16;
    let ciphertext = &ciphertext_with_tag[..tag_offset];
    let auth_tag = &ciphertext_with_tag[tag_offset..];

    Ok(CryptoEnvelope {
        cipher: "aes-256-gcm-siv".to_string(),
        cipherparams: CipherParams { iv: hex::encode(nonce_bytes) },
        ciphertext: hex::encode(ciphertext),
        auth_tag: hex::encode(auth_tag),
        kdf: "argon2id".to_string(),
        kdfparams: KdfParamsVariant::Argon2id(KdfParams {
            dklen: KDF_DKLEN,
            m_cost: ARGON2_M_COST,
            t_cost: ARGON2_T_COST,
            p_cost: ARGON2_P_COST,
            salt: hex::encode(salt),
        }),
    })
}

/// Decrypt a `CryptoEnvelope` using a passphrase (Argon2id) or token (HKDF).
///
/// Dispatches on the `kdf` field: `"argon2id"` or `"hkdf-sha256"`.
/// Returns the decrypted plaintext as `HardenedBytes` (page-locked + zeroized on drop).
pub fn decrypt(envelope: &CryptoEnvelope, passphrase: &[u8]) -> Result<HardenedBytes, CryptoError> {
    match envelope.kdf.as_str() {
        "argon2id" => decrypt_argon2id(envelope, passphrase),
        "hkdf-sha256" => decrypt_hkdf(envelope, passphrase),
        other => Err(CryptoError::InvalidParams(format!("unsupported KDF: {other}"))),
    }
}

/// Derive a 32-byte key from a passphrase using Argon2id.
fn argon2id_derive(passphrase: &[u8], salt: &[u8]) -> Result<[u8; 32], CryptoError> {
    let params = Params::new(ARGON2_M_COST, ARGON2_T_COST, ARGON2_P_COST, Some(32))
        .map_err(|e| CryptoError::InvalidParams(e.to_string()))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut derived_key = [0u8; 32];
    argon2
        .hash_password_into(passphrase, salt, &mut derived_key)
        .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;
    Ok(derived_key)
}

/// Decrypt using Argon2id KDF (passphrase path).
fn decrypt_argon2id(
    envelope: &CryptoEnvelope,
    passphrase: &[u8],
) -> Result<HardenedBytes, CryptoError> {
    let kdfparams = match &envelope.kdfparams {
        KdfParamsVariant::Argon2id(p) => p,
        _ => {
            return Err(CryptoError::InvalidParams(
                "expected argon2id kdfparams for kdf=argon2id".into(),
            ))
        }
    };

    let salt =
        hex::decode(&kdfparams.salt).map_err(|e| CryptoError::InvalidParams(e.to_string()))?;
    let iv = hex::decode(&envelope.cipherparams.iv)
        .map_err(|e| CryptoError::InvalidParams(e.to_string()))?;
    let ciphertext =
        hex::decode(&envelope.ciphertext).map_err(|e| CryptoError::InvalidParams(e.to_string()))?;
    let auth_tag =
        hex::decode(&envelope.auth_tag).map_err(|e| CryptoError::InvalidParams(e.to_string()))?;

    // Validate KDF parameters to prevent downgrade attacks.
    if kdfparams.m_cost < ARGON2_M_COST {
        return Err(CryptoError::InvalidParams(format!(
            "argon2id m_cost={} is below minimum {ARGON2_M_COST} — possible downgrade attack",
            kdfparams.m_cost
        )));
    }
    if kdfparams.t_cost < ARGON2_T_COST {
        return Err(CryptoError::InvalidParams(format!(
            "argon2id t_cost={} is below minimum {ARGON2_T_COST} — possible downgrade attack",
            kdfparams.t_cost
        )));
    }
    if kdfparams.p_cost < ARGON2_P_COST {
        return Err(CryptoError::InvalidParams(format!(
            "argon2id p_cost={} is below minimum {ARGON2_P_COST} — possible downgrade attack",
            kdfparams.p_cost
        )));
    }
    if kdfparams.dklen != KDF_DKLEN {
        return Err(CryptoError::InvalidParams(format!(
            "dklen={} is unsupported, expected exactly {KDF_DKLEN}",
            kdfparams.dklen
        )));
    }

    let params = Params::new(kdfparams.m_cost, kdfparams.t_cost, kdfparams.p_cost, Some(32))
        .map_err(|e| CryptoError::InvalidParams(e.to_string()))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut derived_key = [0u8; 32];
    argon2
        .hash_password_into(passphrase, &salt, &mut derived_key)
        .map_err(|_| CryptoError::DecryptionFailed("key derivation failed".into()))?;

    let cipher = Aes256GcmSiv::new_from_slice(&derived_key)
        .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))?;
    derived_key.zeroize();
    let nonce = Nonce::from(
        <[u8; 12]>::try_from(iv.as_slice())
            .map_err(|_| CryptoError::InvalidParams("iv is not 12 bytes".into()))?,
    );

    let mut combined = ciphertext;
    combined.extend_from_slice(&auth_tag);

    let plaintext = cipher
        .decrypt(&nonce, combined.as_ref())
        .map_err(|_| CryptoError::DecryptionFailed("decryption failed".into()))?;

    Ok(HardenedBytes::from_vec(plaintext)?)
}

const HKDF_INFO: &[u8] = b"ows-api-key-v1";
const HKDF_DKLEN: u32 = 32;

/// Encrypt plaintext using an API token as the key material (HKDF-SHA256 + AES-256-GCM-SIV).
///
/// The token is high-entropy (256-bit random), so HKDF is appropriate — no
/// expensive KDF needed.
pub fn encrypt_with_hkdf(plaintext: &[u8], token: &[u8]) -> Result<CryptoEnvelope, CryptoError> {
    let salt: [u8; 32] = rand::random();
    let nonce_bytes: [u8; 12] = rand::random();

    let hk = Hkdf::<Sha256>::new(Some(&salt), token);
    let mut derived_key = [0u8; 32];
    hk.expand(HKDF_INFO, &mut derived_key)
        .map_err(|_| CryptoError::EncryptionFailed("invalid key length".into()))?;

    let cipher = Aes256GcmSiv::new_from_slice(&derived_key)
        .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;
    derived_key.zeroize();
    let nonce = Nonce::from(nonce_bytes);
    let ciphertext_with_tag = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|_| CryptoError::EncryptionFailed("encryption failed".into()))?;

    let tag_offset = ciphertext_with_tag.len() - 16;
    let ciphertext = &ciphertext_with_tag[..tag_offset];
    let auth_tag = &ciphertext_with_tag[tag_offset..];

    Ok(CryptoEnvelope {
        cipher: "aes-256-gcm-siv".to_string(),
        cipherparams: CipherParams { iv: hex::encode(nonce_bytes) },
        ciphertext: hex::encode(ciphertext),
        auth_tag: hex::encode(auth_tag),
        kdf: "hkdf-sha256".to_string(),
        kdfparams: KdfParamsVariant::Hkdf(HkdfKdfParams {
            dklen: HKDF_DKLEN,
            salt: hex::encode(salt),
            info: String::from_utf8_lossy(HKDF_INFO).into_owned(),
        }),
    })
}

/// Decrypt a `CryptoEnvelope` that was encrypted with HKDF (API token path).
fn decrypt_hkdf(envelope: &CryptoEnvelope, token: &[u8]) -> Result<HardenedBytes, CryptoError> {
    let kdfparams = match &envelope.kdfparams {
        KdfParamsVariant::Hkdf(p) => p,
        _ => {
            return Err(CryptoError::InvalidParams(
                "expected HKDF kdfparams for kdf=hkdf-sha256".into(),
            ))
        }
    };

    if kdfparams.dklen != HKDF_DKLEN {
        return Err(CryptoError::InvalidParams(format!(
            "HKDF dklen={} is unsupported, expected exactly {HKDF_DKLEN}",
            kdfparams.dklen
        )));
    }

    let salt =
        hex::decode(&kdfparams.salt).map_err(|e| CryptoError::InvalidParams(e.to_string()))?;
    let iv = hex::decode(&envelope.cipherparams.iv)
        .map_err(|e| CryptoError::InvalidParams(e.to_string()))?;
    let ciphertext =
        hex::decode(&envelope.ciphertext).map_err(|e| CryptoError::InvalidParams(e.to_string()))?;
    let auth_tag =
        hex::decode(&envelope.auth_tag).map_err(|e| CryptoError::InvalidParams(e.to_string()))?;

    let hk = Hkdf::<Sha256>::new(Some(&salt), token);
    let mut derived_key = [0u8; 32];
    hk.expand(kdfparams.info.as_bytes(), &mut derived_key)
        .map_err(|_| CryptoError::DecryptionFailed("invalid key length".into()))?;

    let cipher = Aes256GcmSiv::new_from_slice(&derived_key)
        .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))?;
    derived_key.zeroize();
    let nonce = Nonce::from(
        <[u8; 12]>::try_from(iv.as_slice())
            .map_err(|_| CryptoError::InvalidParams("iv is not 12 bytes".into()))?,
    );

    let mut combined = ciphertext;
    combined.extend_from_slice(&auth_tag);

    let plaintext = cipher
        .decrypt(&nonce, combined.as_ref())
        .map_err(|_| CryptoError::DecryptionFailed("decryption failed".into()))?;

    Ok(HardenedBytes::from_vec(plaintext)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Extract mutable Argon2id params from an envelope (for test tampering).
    fn argon2id_params_mut(envelope: &mut CryptoEnvelope) -> &mut KdfParams {
        match &mut envelope.kdfparams {
            KdfParamsVariant::Argon2id(p) => p,
            _ => panic!("expected argon2id params"),
        }
    }

    /// Extract Argon2id params from an envelope (for assertions).
    fn argon2id_params(envelope: &CryptoEnvelope) -> &KdfParams {
        match &envelope.kdfparams {
            KdfParamsVariant::Argon2id(p) => p,
            _ => panic!("expected argon2id params"),
        }
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let plaintext = b"hello world";
        let passphrase = "my-secret-passphrase";

        let envelope = encrypt(plaintext, passphrase.as_bytes()).unwrap();
        let decrypted = decrypt(&envelope, passphrase.as_bytes()).unwrap();

        assert_eq!(decrypted.expose(), plaintext);
    }

    #[test]
    fn test_wrong_passphrase_fails() {
        let plaintext = b"hello world";
        let envelope = encrypt(plaintext, b"pass1").unwrap();
        let result = decrypt(&envelope, b"pass2");

        assert!(result.is_err());
    }

    #[test]
    fn test_different_encryptions_different_ciphertext() {
        let plaintext = b"same data";
        let passphrase = "same-pass";

        let env1 = encrypt(plaintext, passphrase.as_bytes()).unwrap();
        let env2 = encrypt(plaintext, passphrase.as_bytes()).unwrap();

        assert_ne!(env1.ciphertext, env2.ciphertext);
        assert_ne!(argon2id_params(&env1).salt, argon2id_params(&env2).salt);
        assert_ne!(env1.cipherparams.iv, env2.cipherparams.iv);
    }

    #[test]
    fn test_envelope_serde_roundtrip() {
        let plaintext = b"serde test";
        let envelope = encrypt(plaintext, b"pass").unwrap();

        let json = serde_json::to_string(&envelope).unwrap();
        let deserialized: CryptoEnvelope = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.cipher, envelope.cipher);
        assert_eq!(deserialized.ciphertext, envelope.ciphertext);
        assert_eq!(deserialized.auth_tag, envelope.auth_tag);
        assert_eq!(argon2id_params(&deserialized).salt, argon2id_params(&envelope).salt);
        assert_eq!(deserialized.cipherparams.iv, envelope.cipherparams.iv);

        let decrypted = decrypt(&deserialized, b"pass").unwrap();
        assert_eq!(decrypted.expose(), plaintext);
    }

    #[test]
    fn test_encrypt_decrypt_large_payload() {
        let plaintext = vec![0xAB; 1024];
        let passphrase = "test-passphrase-for-zeroize";

        let envelope = encrypt(&plaintext, passphrase.as_bytes()).unwrap();
        let decrypted = decrypt(&envelope, passphrase.as_bytes()).unwrap();

        assert_eq!(decrypted.expose(), &plaintext[..]);
    }

    #[test]
    fn test_decrypt_wrong_passphrase_still_fails() {
        let plaintext = b"sensitive data";
        let envelope = encrypt(plaintext, b"correct").unwrap();
        let result = decrypt(&envelope, b"wrong");
        assert!(result.is_err());
    }

    #[test]
    fn test_encrypt_decrypt_empty_passphrase() {
        let plaintext = b"data with empty passphrase";
        let envelope = encrypt(plaintext, b"").unwrap();
        let decrypted = decrypt(&envelope, b"").unwrap();
        assert_eq!(decrypted.expose(), plaintext);
    }

    #[test]
    fn test_decrypt_empty_passphrase_rejects_nonempty() {
        let plaintext = b"data with empty passphrase";
        let envelope = encrypt(plaintext, b"").unwrap();
        let result = decrypt(&envelope, b"wrong");
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_malformed_iv_bad_hex() {
        let mut envelope = encrypt(b"test", b"pass").unwrap();
        envelope.cipherparams.iv = "not-valid-hex!!!".to_string();
        let result = decrypt(&envelope, b"pass");
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), CryptoError::InvalidParams(_)));
    }

    #[test]
    fn test_decrypt_malformed_salt_bad_hex() {
        let mut envelope = encrypt(b"test", b"pass").unwrap();
        argon2id_params_mut(&mut envelope).salt = "zz".to_string();
        let result = decrypt(&envelope, b"pass");
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), CryptoError::InvalidParams(_)));
    }

    #[test]
    fn test_decrypt_malformed_ciphertext_bad_hex() {
        let mut envelope = encrypt(b"test", b"pass").unwrap();
        envelope.ciphertext = "not-hex".to_string();
        let result = decrypt(&envelope, b"pass");
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), CryptoError::InvalidParams(_)));
    }

    #[test]
    fn test_decrypt_malformed_auth_tag_bad_hex() {
        let mut envelope = encrypt(b"test", b"pass").unwrap();
        envelope.auth_tag = "not-hex".to_string();
        let result = decrypt(&envelope, b"pass");
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), CryptoError::InvalidParams(_)));
    }

    #[test]
    fn test_decrypt_truncated_auth_tag() {
        let mut envelope = encrypt(b"test", b"pass").unwrap();
        envelope.auth_tag = envelope.auth_tag[..8].to_string();
        let result = decrypt(&envelope, b"pass");
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_truncated_ciphertext() {
        let mut envelope = encrypt(b"test data here", b"pass").unwrap();
        envelope.ciphertext = envelope.ciphertext[..4].to_string();
        let result = decrypt(&envelope, b"pass");
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_m_cost_below_minimum() {
        let mut envelope = encrypt(b"test", b"pass").unwrap();
        argon2id_params_mut(&mut envelope).m_cost = 1024; // below test minimum
        let result = decrypt(&envelope, b"pass");
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), CryptoError::InvalidParams(_)));
    }

    #[test]
    fn test_decrypt_t_cost_zero() {
        let mut envelope = encrypt(b"test", b"pass").unwrap();
        argon2id_params_mut(&mut envelope).t_cost = 0;
        let result = decrypt(&envelope, b"pass");
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), CryptoError::InvalidParams(_)));
    }

    #[test]
    fn test_decrypt_dklen_mismatch() {
        let mut envelope = encrypt(b"test", b"pass").unwrap();
        argon2id_params_mut(&mut envelope).dklen = 48;
        let result = decrypt(&envelope, b"pass");
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), CryptoError::InvalidParams(_)));
    }

    #[test]
    fn test_envelope_fields_correct() {
        let envelope = encrypt(b"test", b"pass").unwrap();
        let kp = argon2id_params(&envelope);
        assert_eq!(envelope.cipher, "aes-256-gcm-siv");
        assert_eq!(envelope.kdf, "argon2id");
        assert_eq!(kp.dklen, 32);
        assert_eq!(kp.m_cost, ARGON2_M_COST);
        assert_eq!(kp.t_cost, ARGON2_T_COST);
        assert_eq!(kp.p_cost, ARGON2_P_COST);
        assert_eq!(envelope.cipherparams.iv.len(), 24);
        assert_eq!(kp.salt.len(), 64);
        assert_eq!(envelope.auth_tag.len(), 32);
    }

    // === HKDF tests ===

    #[test]
    fn test_hkdf_encrypt_decrypt_roundtrip() {
        let plaintext = b"hello from HKDF";
        let token = "oc_key_a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6";

        let envelope = encrypt_with_hkdf(plaintext, token.as_bytes()).unwrap();
        assert_eq!(envelope.kdf, "hkdf-sha256");

        let decrypted = decrypt(&envelope, token.as_bytes()).unwrap();
        assert_eq!(decrypted.expose(), plaintext);
    }

    #[test]
    fn test_hkdf_wrong_token_fails() {
        let plaintext = b"secret data";
        let envelope = encrypt_with_hkdf(plaintext, b"token1").unwrap();
        let result = decrypt(&envelope, b"token2");
        assert!(result.is_err());
    }

    #[test]
    fn test_hkdf_different_encryptions_different_ciphertext() {
        let plaintext = b"same data";
        let token = "same-token";

        let env1 = encrypt_with_hkdf(plaintext, token.as_bytes()).unwrap();
        let env2 = encrypt_with_hkdf(plaintext, token.as_bytes()).unwrap();

        assert_ne!(env1.ciphertext, env2.ciphertext);
        assert_ne!(env1.cipherparams.iv, env2.cipherparams.iv);
    }

    #[test]
    fn test_hkdf_envelope_fields_correct() {
        let envelope = encrypt_with_hkdf(b"test", b"token").unwrap();
        assert_eq!(envelope.cipher, "aes-256-gcm-siv");
        assert_eq!(envelope.kdf, "hkdf-sha256");
        assert_eq!(envelope.cipherparams.iv.len(), 24);
        assert_eq!(envelope.auth_tag.len(), 32);

        let kp = match &envelope.kdfparams {
            KdfParamsVariant::Hkdf(p) => p,
            _ => panic!("expected HKDF params"),
        };
        assert_eq!(kp.dklen, 32);
        assert_eq!(kp.salt.len(), 64);
        assert_eq!(kp.info, "ows-api-key-v1");
    }

    #[test]
    fn test_hkdf_serde_roundtrip() {
        let plaintext = b"serde hkdf test";
        let token = "oc_key_test_token";
        let envelope = encrypt_with_hkdf(plaintext, token.as_bytes()).unwrap();

        let json = serde_json::to_string(&envelope).unwrap();
        let deserialized: CryptoEnvelope = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.kdf, "hkdf-sha256");
        let decrypted = decrypt(&deserialized, token.as_bytes()).unwrap();
        assert_eq!(decrypted.expose(), plaintext);
    }

    #[test]
    fn test_hkdf_large_payload() {
        let plaintext = vec![0xCD; 2048];
        let token = "oc_key_large_payload_test";

        let envelope = encrypt_with_hkdf(&plaintext, token.as_bytes()).unwrap();
        let decrypted = decrypt(&envelope, token.as_bytes()).unwrap();
        assert_eq!(decrypted.expose(), &plaintext[..]);
    }

    #[test]
    fn test_decrypt_unsupported_kdf_rejected() {
        let mut envelope = encrypt(b"test", b"pass").unwrap();
        envelope.kdf = "bcrypt".to_string();
        let result = decrypt(&envelope, b"pass");
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), CryptoError::InvalidParams(_)));
    }

    #[test]
    fn test_argon2id_and_hkdf_envelopes_not_interchangeable() {
        let plaintext = b"test data";
        let credential = "shared-credential";

        let argon_env = encrypt(plaintext, credential.as_bytes()).unwrap();
        let hkdf_env = encrypt_with_hkdf(plaintext, credential.as_bytes()).unwrap();

        assert!(decrypt(&argon_env, credential.as_bytes()).is_ok());
        assert!(decrypt(&hkdf_env, credential.as_bytes()).is_ok());

        let mut tampered = argon_env;
        tampered.kdf = "hkdf-sha256".to_string();
        assert!(decrypt(&tampered, credential.as_bytes()).is_err());
    }

    #[test]
    fn test_hkdf_decrypt_tampered_dklen() {
        let plaintext = b"test";
        let token = "test-token";
        let mut envelope = encrypt_with_hkdf(plaintext, token.as_bytes()).unwrap();

        match &mut envelope.kdfparams {
            KdfParamsVariant::Hkdf(p) => p.dklen = 64,
            _ => panic!("expected HKDF params"),
        }

        let result = decrypt(&envelope, token.as_bytes());
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), CryptoError::InvalidParams(_)));
    }

    #[test]
    fn test_argon2id_json_deserialize() {
        let json = format!(
            r#"{{
                "cipher": "aes-256-gcm-siv",
                "cipherparams": {{ "iv": "aabbccddeeff00112233aabb" }},
                "ciphertext": "deadbeef",
                "auth_tag": "00112233445566778899aabbccddeeff",
                "kdf": "argon2id",
                "kdfparams": {{ "dklen": 32, "m_cost": {}, "t_cost": {}, "p_cost": {}, "salt": "0011223344556677889900112233445566778899001122334455667788990011" }}
            }}"#,
            ARGON2_M_COST, ARGON2_T_COST, ARGON2_P_COST
        );

        let envelope: CryptoEnvelope = serde_json::from_str(&json).unwrap();
        assert_eq!(envelope.kdf, "argon2id");
        let kp = argon2id_params(&envelope);
        assert_eq!(kp.m_cost, ARGON2_M_COST);
        assert_eq!(kp.t_cost, ARGON2_T_COST);
        assert_eq!(kp.p_cost, ARGON2_P_COST);
        assert_eq!(kp.dklen, 32);
    }

    #[test]
    fn test_hkdf_json_deserialize() {
        let json = r#"{
            "cipher": "aes-256-gcm-siv",
            "cipherparams": { "iv": "aabbccddeeff00112233aabb" },
            "ciphertext": "deadbeef",
            "auth_tag": "00112233445566778899aabbccddeeff",
            "kdf": "hkdf-sha256",
            "kdfparams": { "dklen": 32, "salt": "0011223344556677889900112233445566778899001122334455667788990011", "info": "ows-api-key-v1" }
        }"#;

        let envelope: CryptoEnvelope = serde_json::from_str(json).unwrap();
        assert_eq!(envelope.kdf, "hkdf-sha256");
        match &envelope.kdfparams {
            KdfParamsVariant::Hkdf(p) => {
                assert_eq!(p.dklen, 32);
                assert_eq!(p.info, "ows-api-key-v1");
            }
            _ => panic!("expected HKDF params"),
        }
    }
}
