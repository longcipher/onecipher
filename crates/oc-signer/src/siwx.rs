//! CAIP-122 chain verifiers (pure crypto, no I/O).
//!
//! [`EvmVerifier`] (EIP-191) and [`SolanaVerifier`] (Ed25519) implement
//! [`oc_siwx::SyncVerifier`] so `oc_siwx::authenticate` can verify Sign-In
//! with X messages. Both are synchronous and R56-safe (no tokio, no RPC).
//! Contract-account checks (EIP-1271 / ERC-6492) live in `oc-netagent`.

use oc_siwx::{ChainIdReason, SiwxError, SiwxMessage, SyncVerifier};
use sha3::{Digest, Keccak256};

use crate::chains::evm::EvmSigner;

// ---------------------------------------------------------------------------
// EVM
// ---------------------------------------------------------------------------

/// Ethereum CAIP-122 verifier (EIP-191 `personal_sign` only).
#[derive(Debug, Clone, Copy, Default)]
pub struct EvmVerifier;

impl EvmVerifier {
    /// Create a verifier that performs EIP-191 recovery.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

/// Parse an EVM chain id: `[0-9]+`, no leading zero unless `"0"`, fits `u64`.
pub fn parse_evm_chain_id(s: &str) -> Result<u64, SiwxError> {
    if s.is_empty() {
        return Err(SiwxError::InvalidChainId { reason: ChainIdReason::Empty });
    }
    if !s.as_bytes().iter().all(u8::is_ascii_digit) {
        return Err(SiwxError::InvalidChainId { reason: ChainIdReason::NotDecimal });
    }
    if s.len() > 1 && s.starts_with('0') {
        return Err(SiwxError::InvalidChainId { reason: ChainIdReason::LeadingZero });
    }
    s.parse().map_err(|_| SiwxError::InvalidChainId { reason: ChainIdReason::Overflow })
}

/// Validate an EIP-55 checksummed address (`0x` + 40 hex, checksum exact).
///
/// All-lowercase is accepted only when that string *is* the EIP-55 form.
pub fn validate_evm_address(address: &str) -> Result<(), SiwxError> {
    let hex_part = address
        .strip_prefix("0x")
        .or_else(|| address.strip_prefix("0X"))
        .ok_or_else(|| SiwxError::InvalidAddress { reason: "must start with 0x".to_owned() })?;
    if hex_part.len() != 40 || !hex_part.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(SiwxError::InvalidAddress { reason: "must be 0x + 40 hex chars".to_owned() });
    }
    let expected = EvmSigner::eip55_checksum(hex_part);
    // Compare the full `0x`-prefixed form exactly (checksum is case-sensitive).
    if expected != address.replace("0X", "0x") {
        return Err(SiwxError::InvalidAddress { reason: "bad EIP-55 checksum".to_owned() });
    }
    Ok(())
}

/// EIP-191 hash of the raw message bytes.
pub fn eip191_hash(raw_message: &[u8]) -> [u8; 32] {
    let prefix = format!("\x19Ethereum Signed Message:\n{}", raw_message.len());
    let mut prefixed = Vec::with_capacity(prefix.len() + raw_message.len());
    prefixed.extend_from_slice(prefix.as_bytes());
    prefixed.extend_from_slice(raw_message);
    Keccak256::digest(&prefixed).into()
}

impl SyncVerifier for EvmVerifier {
    const CHAIN_NAME: &'static str = oc_siwx::EVM_CHAIN_NAME;
    const NAMESPACE: &'static str = oc_siwx::EVM_NAMESPACE;

    fn validate_address(address: &str) -> Result<(), SiwxError> {
        validate_evm_address(address)
    }

    fn validate_chain_id(chain_id: &str) -> Result<(), SiwxError> {
        parse_evm_chain_id(chain_id).map(|_| ())
    }

    fn verify(
        &self,
        message: &SiwxMessage,
        raw_message: &str,
        signature: &[u8],
    ) -> Result<(), SiwxError> {
        if signature.len() != 65 {
            return Err(SiwxError::InvalidSignature {
                reason: format!("EIP-191 signature must be 65 bytes, got {}", signature.len()),
            });
        }
        let r_bytes: [u8; 32] = signature[..32]
            .try_into()
            .map_err(|_| SiwxError::InvalidSignature { reason: "bad r".to_owned() })?;
        let s_bytes: [u8; 32] = signature[32..64]
            .try_into()
            .map_err(|_| SiwxError::InvalidSignature { reason: "bad s".to_owned() })?;
        let v = signature[64];
        let sig = k256::ecdsa::Signature::from_scalars(r_bytes, s_bytes)
            .map_err(|e| SiwxError::InvalidSignature { reason: format!("bad encoding: {e}") })?;
        // EIP-2: reject malleable high-s signatures as malformed.
        if sig.normalize_s() != sig {
            return Err(SiwxError::InvalidSignature { reason: "high-s (EIP-2)".to_owned() });
        }
        let recovery_id = if v >= 27 { v - 27 } else { v };
        let recid = k256::ecdsa::RecoveryId::try_from(recovery_id)
            .map_err(|_| SiwxError::InvalidSignature { reason: format!("bad recovery id: {v}") })?;
        let hash = eip191_hash(raw_message.as_bytes());
        let recovered = k256::ecdsa::VerifyingKey::recover_from_prehash(&hash, &sig, recid)
            .map_err(|e| SiwxError::VerificationFailed {
                reason: format!("ECDSA recovery failed: {e}"),
            })?;
        let pubkey_bytes = recovered.to_sec1_point(false);
        let pubkey_hash = Keccak256::digest(&pubkey_bytes.as_bytes()[1..]);
        let recovered_addr = EvmSigner::eip55_checksum(&hex::encode(&pubkey_hash[12..]));
        // `validate_address` already enforced the checksum, so a
        // case-insensitive compare is sufficient here.
        if recovered_addr.to_lowercase() != message.address().to_lowercase() {
            return Err(SiwxError::VerificationFailed {
                reason: format!("recovered {} != expected {}", recovered_addr, message.address()),
            });
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Solana
// ---------------------------------------------------------------------------

/// Maximum Solana chain-id length (base58 of 32 bytes is at most 44 chars).
pub const MAX_SOLANA_CHAIN_ID_LEN: usize = 44;

/// Solana CAIP-122 verifier (Ed25519, `verify` — not `verify_strict`).
#[derive(Debug, Clone, Copy, Default)]
pub struct SolanaVerifier;

impl SolanaVerifier {
    /// Create a Solana Ed25519 verifier.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

/// Decode a base58 Solana address into its Ed25519 verifying key.
///
/// Rejects bad base58, wrong length, off-curve encodings (PDAs) and
/// weak/small-order keys (including the all-zero System Program identity).
pub(crate) fn verifying_key_from_address(
    address: &str,
) -> Result<ed25519_dalek::VerifyingKey, SiwxError> {
    let bytes = bs58::decode(address)
        .into_vec()
        .map_err(|e| SiwxError::InvalidAddress { reason: format!("invalid base58: {e}") })?;
    let arr: [u8; 32] = bytes.try_into().map_err(|v: Vec<u8>| SiwxError::InvalidAddress {
        reason: format!("expected 32 bytes, got {}", v.len()),
    })?;
    let vk = ed25519_dalek::VerifyingKey::from_bytes(&arr).map_err(|e| {
        SiwxError::InvalidAddress { reason: format!("invalid Ed25519 pubkey: {e}") }
    })?;
    if vk.is_weak() {
        return Err(SiwxError::InvalidAddress { reason: "weak/small-order pubkey".to_owned() });
    }
    Ok(vk)
}

/// Validate a Solana chain id: `[-_a-zA-Z0-9]{1,44}` (NOT CAIP-2 `{1,32}`).
pub fn validate_solana_chain_id(chain_id: &str) -> Result<(), SiwxError> {
    if chain_id.is_empty() {
        return Err(SiwxError::InvalidChainId { reason: ChainIdReason::Empty });
    }
    let valid = chain_id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
    if !valid || chain_id.len() > MAX_SOLANA_CHAIN_ID_LEN {
        return Err(SiwxError::InvalidChainId { reason: ChainIdReason::BadCharset });
    }
    Ok(())
}

impl SyncVerifier for SolanaVerifier {
    const CHAIN_NAME: &'static str = oc_siwx::SOLANA_CHAIN_NAME;
    const NAMESPACE: &'static str = oc_siwx::SOLANA_NAMESPACE;

    fn validate_address(address: &str) -> Result<(), SiwxError> {
        verifying_key_from_address(address).map(|_| ())
    }

    fn validate_chain_id(chain_id: &str) -> Result<(), SiwxError> {
        validate_solana_chain_id(chain_id)
    }

    fn verify(
        &self,
        message: &SiwxMessage,
        raw_message: &str,
        signature: &[u8],
    ) -> Result<(), SiwxError> {
        use ed25519_dalek::Verifier as _;

        let sig_arr: [u8; 64] = signature.try_into().map_err(|_| SiwxError::InvalidSignature {
            reason: format!("Ed25519 signature must be 64 bytes, got {}", signature.len()),
        })?;
        let sig = ed25519_dalek::Signature::from_bytes(&sig_arr);
        // Key identity always comes from the message address — never from a
        // caller-supplied pubkey.
        let vk = verifying_key_from_address(message.address())?;
        vk.verify(raw_message.as_bytes(), &sig).map_err(|e| SiwxError::VerificationFailed {
            reason: format!("Ed25519 verify failed: {e}"),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{chains::evm::EvmSigner, traits::ChainSigner};

    const PRIVKEY_HEX: &str = "4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318";

    fn evm_key() -> Vec<u8> {
        hex::decode(PRIVKEY_HEX).expect("privkey")
    }

    #[test]
    fn evm_verify_roundtrip() {
        let signer = EvmSigner;
        let key = evm_key();
        let address = signer.derive_address(&key).expect("address");
        let msg = SiwxMessage::new(
            "example.com",
            &address,
            "https://example.com/login",
            "1",
            "testnonce12345678",
        )
        .expect("message");
        let raw = EvmVerifier::format_message(&msg);
        let sig = signer.sign_message(&key, raw.as_bytes()).expect("sign");
        let verifier = EvmVerifier::new();
        let opts = oc_siwx::AuthOpts::new("example.com", "testnonce12345678");
        let auth = oc_siwx::authenticate(&verifier, &raw, &sig.signature, &opts).expect("auth");
        assert_eq!(auth.address(), address);
    }

    #[test]
    fn evm_verify_rejects_wrong_address() {
        let signer = EvmSigner;
        let key = evm_key();
        let address = signer.derive_address(&key).expect("address");
        let msg = SiwxMessage::new(
            "example.com",
            &address,
            "https://example.com/login",
            "1",
            "testnonce12345678",
        )
        .expect("message");
        let raw = EvmVerifier::format_message(&msg);
        let sig = signer.sign_message(&key, raw.as_bytes()).expect("sign");
        // Swap the message address for a different valid address; recovery
        // must fail with VerificationFailed (not InvalidSignature).
        let other = "0x0000000000000000000000000000000000000000";
        let raw2 = raw.replacen(&address, other, 1);
        let opts = oc_siwx::AuthOpts::new("example.com", "testnonce12345678");
        let err = oc_siwx::authenticate(&EvmVerifier::new(), &raw2, &sig.signature, &opts)
            .expect_err("wrong address");
        assert!(matches!(err, SiwxError::VerificationFailed { .. }), "got {err:?}");
    }

    #[test]
    fn evm_verify_rejects_short_signature() {
        let msg = SiwxMessage::new(
            "example.com",
            "0x2c7536E3605D9C16a7a3D7b1898e529396a65c23",
            "https://example.com/login",
            "1",
            "testnonce12345678",
        )
        .expect("message");
        let raw = EvmVerifier::format_message(&msg);
        let opts = oc_siwx::AuthOpts::new("example.com", "testnonce12345678");
        let err = oc_siwx::authenticate(&EvmVerifier::new(), &raw, &[0u8; 64], &opts)
            .expect_err("64 bytes");
        assert!(matches!(err, SiwxError::InvalidSignature { .. }), "got {err:?}");
    }

    #[test]
    fn evm_address_checksum_enforced() {
        // Lowercased form of a checksummed address must be rejected.
        assert!(validate_evm_address("0x2c7536e3605d9c16a7a3d7b1898e529396a65c23").is_err());
        assert!(validate_evm_address("0x2c7536E3605D9C16a7a3D7b1898e529396a65c23").is_ok());
        assert!(validate_evm_address("not-an-address").is_err());
    }

    #[test]
    fn evm_chain_id_rules() {
        assert_eq!(parse_evm_chain_id("1").expect("1"), 1);
        assert!(matches!(
            parse_evm_chain_id("").unwrap_err(),
            SiwxError::InvalidChainId { reason: ChainIdReason::Empty }
        ));
        assert!(matches!(
            parse_evm_chain_id("01").unwrap_err(),
            SiwxError::InvalidChainId { reason: ChainIdReason::LeadingZero }
        ));
        assert!(matches!(
            parse_evm_chain_id("abc").unwrap_err(),
            SiwxError::InvalidChainId { reason: ChainIdReason::NotDecimal }
        ));
        assert!(matches!(
            parse_evm_chain_id("18446744073709551616").unwrap_err(),
            SiwxError::InvalidChainId { reason: ChainIdReason::Overflow }
        ));
    }

    #[test]
    fn solana_verify_roundtrip() {
        use crate::chains::solana::SolanaSigner;

        let signer = SolanaSigner;
        let privkey =
            hex::decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
                .expect("privkey");
        let address = signer.derive_address(&privkey).expect("address");
        let msg = SiwxMessage::new(
            "example.com",
            &address,
            "https://example.com/login",
            "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d",
            "testnonce12345678",
        )
        .expect("message");
        let raw = SolanaVerifier::format_message(&msg);
        let sig = signer.sign_message(&privkey, raw.as_bytes()).expect("sign");
        let opts = oc_siwx::AuthOpts::new("example.com", "testnonce12345678");
        let auth = oc_siwx::authenticate(&SolanaVerifier::new(), &raw, &sig.signature, &opts)
            .expect("auth");
        assert_eq!(auth.address(), address);
    }

    #[test]
    fn solana_rejects_identity_and_off_curve() {
        let identity = bs58::encode([0u8; 32]).into_string();
        assert!(matches!(
            SolanaVerifier::validate_address(&identity).unwrap_err(),
            SiwxError::InvalidAddress { .. }
        ));
        let pda = bs58::encode([2u8; 32]).into_string();
        assert!(matches!(
            SolanaVerifier::validate_address(&pda).unwrap_err(),
            SiwxError::InvalidAddress { .. }
        ));
    }

    #[test]
    fn solana_chain_id_rules() {
        assert!(validate_solana_chain_id("5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d").is_ok());
        assert!(validate_solana_chain_id("mainnet").is_ok());
        assert!(matches!(
            validate_solana_chain_id("").unwrap_err(),
            SiwxError::InvalidChainId { reason: ChainIdReason::Empty }
        ));
        assert!(matches!(
            validate_solana_chain_id("solana:mainnet").unwrap_err(),
            SiwxError::InvalidChainId { reason: ChainIdReason::BadCharset }
        ));
    }
}
