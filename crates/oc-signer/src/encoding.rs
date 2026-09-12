//! Shared address-encoding primitives.
//!
//! Deduplicates the Hash160 / double-SHA256 / Base58Check snippets that were
//! previously copy-pasted across the Bitcoin, Cosmos, and XRPL signers.
//!
//! # Boundary note (Tron)
//!
//! Tron addresses look like Base58Check but hash with **Keccak-256**, not
//! SHA-256 + RIPEMD-160. Tron therefore reuses only
//! [`base58check_encode`] from this module and keeps its own
//! `keccak256(pubkey)[12..]` derivation with an explicit comment at the
//! call site. Do not "simplify" Tron onto [`hash160`]; the hash functions
//! differ and the addresses would silently change.

use ripemd::Ripemd160;
use sha2::{Digest, Sha256};

use crate::error::DeriveError;

/// Hash160: `RIPEMD160(SHA256(data))`, returned as 20 bytes.
///
/// Used by Bitcoin (P2WPKH witness program), Cosmos (bech32 payload), and
/// XRPL (classic-address payload prior to Base58Check with version `0x00`).
#[must_use]
pub fn hash160(data: &[u8]) -> [u8; 20] {
    let sha = Sha256::digest(data);
    let ripe = Ripemd160::digest(sha);
    let mut out = [0u8; 20];
    out.copy_from_slice(&ripe);
    out
}

/// Double SHA-256: `SHA256(SHA256(data))`, returned as 32 bytes.
///
/// Used by Bitcoin (legacy sighash preimages, message signing) and Spark
/// (which shares the Bitcoin sighash convention as a Bitcoin L2).
#[must_use]
pub fn double_sha256(data: &[u8]) -> [u8; 32] {
    let first = Sha256::digest(data);
    let second = Sha256::digest(first);
    let mut out = [0u8; 32];
    out.copy_from_slice(&second);
    out
}

/// Base58Check-encode a version-prefixed payload (`version || data`).
///
/// Computes the 4-byte checksum as the first four bytes of
/// [`double_sha256`] over the payload, appends it, and Base58-encodes.
/// This matches Bitcoin (`bs58` with `check`), Tron (`0x41` prefix), and
/// XRPL (version `0x00`) conventions.
#[must_use]
pub fn base58check_encode(payload: &[u8]) -> String {
    bs58::encode(payload).with_check().into_string()
}

/// Decode a Base58Check string, verifying the 4-byte checksum.
///
/// Returns the version-prefixed payload (`version || data`) on success.
///
/// # Errors
///
/// Returns [`DeriveError::AddressEncoding`] when the input is not valid
/// Base58 or the checksum does not match.
pub fn base58check_decode(s: &str) -> Result<Vec<u8>, DeriveError> {
    bs58::decode(s)
        .with_check(None)
        .into_vec()
        .map_err(|e| DeriveError::AddressEncoding(format!("invalid base58check address: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash160_matches_known_vector() {
        // Hash160 of the compressed generator point G (privkey = 1).
        // Cross-checked against the Cosmos/Bitcoin `test_same_hash_*` vectors.
        let pubkey =
            hex::decode("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
                .unwrap();
        let hash = hash160(&pubkey);
        assert_eq!(hex::encode(hash), "751e76e8199196d454941c45d1b3a323f1433bd6");
    }

    #[test]
    fn double_sha256_matches_known_vector() {
        // Double-SHA256 of empty input is a well-known constant.
        let hash = double_sha256(b"");
        assert_eq!(
            hex::encode(hash),
            "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456"
        );
    }

    #[test]
    fn base58check_roundtrip_with_version() {
        let mut payload = vec![0x41u8];
        payload.extend_from_slice(&[0xAB; 20]);
        let encoded = base58check_encode(&payload);
        assert!(encoded.starts_with('T'));
        let decoded = base58check_decode(&encoded).unwrap();
        assert_eq!(decoded, payload);
    }

    #[test]
    fn base58check_rejects_bad_checksum() {
        let mut payload = vec![0x00u8];
        payload.extend_from_slice(&[0x11; 20]);
        let mut encoded = base58check_encode(&payload);
        // Flip the last character to corrupt the checksum.
        let last = encoded.pop().unwrap();
        encoded.push(if last == '1' { '2' } else { '1' });
        assert!(base58check_decode(&encoded).is_err());
    }
}
