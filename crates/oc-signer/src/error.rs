//! Unified derivation / signing error type.
//!
//! All chain signers return [`DeriveError`]. Callers match once instead of
//! per-chain error enums:
//!
//! ```rust
//! use oc_core::ChainType;
//! use oc_signer::{DeriveError, signer_for_chain};
//!
//! let signer = signer_for_chain(ChainType::Evm);
//! match signer.derive_address(&[0u8; 32]) {
//!     Ok(addr) => println!("{addr}"),
//!     Err(DeriveError::Input(msg)) => eprintln!("bad input: {msg}"),
//!     Err(DeriveError::Crypto(msg)) => eprintln!("crypto failure: {msg}"),
//!     Err(DeriveError::AddressEncoding(msg)) => eprintln!("address encoding: {msg}"),
//!     Err(DeriveError::Transaction(msg)) => eprintln!("bad transaction: {msg}"),
//!     Err(DeriveError::Unsupported(msg)) => eprintln!("unsupported: {msg}"),
//! }
//! ```
//!
//! Migration from the legacy `SignerError` names:
//!
//! | Legacy `SignerError`          | Unified `DeriveError`       |
//! |-------------------------------|-----------------------------|
//! | `InvalidPrivateKey(_)`        | `Input(_)`                  |
//! | `InvalidMessage(_)`           | `Input(_)`                  |
//! | `SigningFailed(_)`            | `Crypto(_)`                 |
//! | `AddressDerivationFailed(_)`  | `AddressEncoding(_)`        |
//! | `InvalidTransaction(_)`       | `Transaction(_)`            |
//!
//! `Unsupported(_)` is new: it covers fail-closed placeholders for chains
//! compiled out via cargo features and default trait methods that a chain
//! did not implement (`verify_message`, `encode_signed_transaction`).

/// Unified error for address derivation, signing, and transaction building.
///
/// Kept as a flat `String`-payload enum so every chain maps failures into
/// one of five buckets without leaking provider-specific error types.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DeriveError {
    /// Invalid caller input: bad private-key bytes, wrong message length,
    /// malformed path/index, bad hex, out-of-range quantity.
    #[error("invalid input: {0}")]
    Input(String),

    /// Cryptographic failure: key parsing inside k256/ed25519, prehash
    /// signing, HMAC init, hash digest, recovery.
    #[error("crypto failure: {0}")]
    Crypto(String),

    /// Address encoding failure: bech32, base58check, base32, EIP-55,
    /// or provider address formatting.
    #[error("address encoding failed: {0}")]
    AddressEncoding(String),

    /// Invalid transaction payload: empty bytes, bad PSBT, truncated RLP /
    /// Borsh / compact-u16, already-signed input, wrong signature length.
    #[error("invalid transaction: {0}")]
    Transaction(String),

    /// Operation unavailable: chain compiled out via cargo feature, or a
    /// default trait method the chain did not implement.
    #[error("unsupported: {0}")]
    Unsupported(String),
}

impl DeriveError {
    /// Wrap an invalid-private-key failure (legacy `InvalidPrivateKey`).
    #[must_use]
    pub fn invalid_key(msg: impl Into<String>) -> Self {
        Self::Input(msg.into())
    }

    /// Wrap an invalid-message failure (legacy `InvalidMessage`).
    #[must_use]
    pub fn invalid_message(msg: impl Into<String>) -> Self {
        Self::Input(msg.into())
    }

    /// Wrap a signing failure (legacy `SigningFailed`).
    #[must_use]
    pub fn signing(msg: impl Into<String>) -> Self {
        Self::Crypto(msg.into())
    }

    /// Wrap an address-derivation failure (legacy `AddressDerivationFailed`).
    #[must_use]
    pub fn address(msg: impl Into<String>) -> Self {
        Self::AddressEncoding(msg.into())
    }

    /// Wrap an invalid-transaction failure (legacy `InvalidTransaction`).
    #[must_use]
    pub fn transaction(msg: impl Into<String>) -> Self {
        Self::Transaction(msg.into())
    }

    /// Wrap an unsupported-operation failure.
    #[must_use]
    pub fn unsupported(msg: impl Into<String>) -> Self {
        Self::Unsupported(msg.into())
    }
}

/// Backward-compatible alias.
///
/// `SignerError` was the pre-Phase1 name. It is now an alias for
/// [`DeriveError`]; the variant names changed (see module docs for the
/// migration table), but existing `use oc_signer::SignerError` paths and
/// `#[from] SignerError` conversions keep compiling.
pub type SignerError = DeriveError;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_match_covers_all_chains() {
        // Every bucket must be displayable through one match.
        let errs = [
            DeriveError::Input("bad key".into()),
            DeriveError::Crypto("sign failed".into()),
            DeriveError::AddressEncoding("bech32".into()),
            DeriveError::Transaction("empty".into()),
            DeriveError::Unsupported("xrpl".into()),
        ];
        for err in errs {
            let msg = format!("{err}");
            assert_ne!(msg, "");
            // Alias must be the same type.
            let aliased: SignerError = err;
            assert_ne!(format!("{aliased}"), "");
        }
    }

    #[test]
    fn legacy_constructor_mapping() {
        assert!(matches!(DeriveError::invalid_key("x"), DeriveError::Input(_)));
        assert!(matches!(DeriveError::invalid_message("x"), DeriveError::Input(_)));
        assert!(matches!(DeriveError::signing("x"), DeriveError::Crypto(_)));
        assert!(matches!(DeriveError::address("x"), DeriveError::AddressEncoding(_)));
        assert!(matches!(DeriveError::transaction("x"), DeriveError::Transaction(_)));
        assert!(matches!(DeriveError::unsupported("x"), DeriveError::Unsupported(_)));
    }
}
