//! Typed public-key helpers for `oc-signer`.
//!
//! Re-exports [`oc_core::DerivedPublicKey`], [`oc_core::PublicKeyKind`], and
//! [`oc_core::PubkeyError`] (the canonical types-only home per the
//! workspace storage boundary) and adds signer-side constructors from
//! private keys. Call sites that previously did `Vec<u8>` + `len()` guessing
//! must use [`DerivedPublicKey::from_bytes`] with an explicit
//! [`PublicKeyKind`] instead.

pub use oc_core::{DerivedPublicKey, PubkeyError, PublicKeyKind};

use crate::error::DeriveError;

/// Derive a compressed secp256k1 [`DerivedPublicKey`] from a 32-byte key.
///
/// # Errors
///
/// Returns [`DeriveError::Input`] when the key is not 32 bytes or cannot
/// be parsed, [`DeriveError::Crypto`] when point encoding fails.
pub fn secp256k1_compressed_from_private(
    private_key: &[u8],
) -> Result<DerivedPublicKey, DeriveError> {
    let sk = k256::ecdsa::SigningKey::from_slice(private_key)
        .map_err(|_| DeriveError::Input("key parsing failed".into()))?;
    let point = sk.verifying_key().to_sec1_point(true);
    let bytes = point.as_bytes();
    let mut arr = [0u8; 33];
    if bytes.len() != 33 {
        return Err(DeriveError::Crypto(format!(
            "compressed secp256k1 point must be 33 bytes, got {}",
            bytes.len()
        )));
    }
    arr.copy_from_slice(bytes);
    DerivedPublicKey::from_compressed(arr).map_err(|e| DeriveError::Crypto(e.to_string()))
}

/// Derive an uncompressed secp256k1 [`DerivedPublicKey`] from a 32-byte key.
///
/// # Errors
///
/// Returns [`DeriveError::Input`] when the key is not a valid scalar.
pub fn secp256k1_uncompressed_from_private(
    private_key: &[u8],
) -> Result<DerivedPublicKey, DeriveError> {
    let sk = k256::ecdsa::SigningKey::from_slice(private_key)
        .map_err(|_| DeriveError::Input("key parsing failed".into()))?;
    let point = sk.verifying_key().to_sec1_point(false);
    let bytes = point.as_bytes();
    let mut arr = [0u8; 65];
    if bytes.len() != 65 {
        return Err(DeriveError::Crypto(format!(
            "uncompressed secp256k1 point must be 65 bytes, got {}",
            bytes.len()
        )));
    }
    arr.copy_from_slice(bytes);
    DerivedPublicKey::from_uncompressed(arr).map_err(|e| DeriveError::Crypto(e.to_string()))
}

/// Derive an ed25519 [`DerivedPublicKey`] (SHA-512 domain) from a 32-byte key.
///
/// # Errors
///
/// Returns [`DeriveError::Input`] when `private_key.len() != 32`.
pub fn ed25519_from_private(private_key: &[u8]) -> Result<DerivedPublicKey, DeriveError> {
    let arr: [u8; 32] = private_key
        .try_into()
        .map_err(|_| DeriveError::Input(format!("expected 32 bytes, got {}", private_key.len())))?;
    let sk = ed25519_dalek::SigningKey::from_bytes(&arr);
    Ok(DerivedPublicKey::from_ed25519(*sk.verifying_key().as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compressed_from_generator_key() {
        // Private key = 1 is the generator point G.
        let mut privkey = [0u8; 32];
        privkey[31] = 1;
        let key = secp256k1_compressed_from_private(&privkey).unwrap();
        assert_eq!(key.kind(), PublicKeyKind::Secp256k1Compressed);
        assert_eq!(
            hex::encode(key.as_bytes()),
            "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        );
    }

    #[test]
    fn uncompressed_has_0x04_prefix() {
        let mut privkey = [0u8; 32];
        privkey[31] = 1;
        let key = secp256k1_uncompressed_from_private(&privkey).unwrap();
        assert_eq!(key.kind(), PublicKeyKind::Secp256k1Uncompressed);
        assert_eq!(key.as_bytes()[0], 0x04);
    }

    #[test]
    fn ed25519_from_rfc8032_seed() {
        let seed = hex::decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
            .unwrap();
        let key = ed25519_from_private(&seed).unwrap();
        assert_eq!(key.kind(), PublicKeyKind::Ed25519);
        assert_eq!(
            hex::encode(key.as_bytes()),
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
        );
    }

    #[test]
    fn rejects_short_key_without_guessing() {
        assert!(secp256k1_compressed_from_private(&[0u8; 16]).is_err());
        assert!(ed25519_from_private(&[0u8; 16]).is_err());
    }
}
