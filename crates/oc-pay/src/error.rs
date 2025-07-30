//! Error type for `oc-pay` operations.
//!
//! Per the T18 contract, [`PayError`] enumerates every failure mode the
//! settlers can surface — Bundler / Paymaster / Solana RPC / Tempo channel
//! failures plus the structural validation errors (`InvalidAmount`,
//! `InvalidRecipient`, `ChannelNotFound`, `ChannelClosed`) and signing
//! failures. Variants are stringly-typed where the underlying transport's own
//! error type is not portable (real Bundler / Paymaster / Solana / Tempo
//! clients live in `oc-netagent`).

use thiserror::Error;

/// Error type for all `oc-pay` operations.
///
/// `Clone` is derived so that mock clients can store and return
/// `Result<_, PayError>` responses without re-allocating the error path
/// (mirroring the pattern used by [`oc_session_key::SessionKeyError`]).
#[derive(Debug, Clone, Error)]
pub enum PayError {
    /// Bundler rejected the UserOp or returned an HTTP / transport error.
    #[error("bundler error: {0}")]
    BundlerError(String),
    /// Paymaster refused to sponsor the UserOp or returned an HTTP error.
    #[error("paymaster error: {0}")]
    PaymasterError(String),
    /// Solana RPC rejected the transaction or returned an HTTP error.
    #[error("solana rpc error: {0}")]
    SolanaRpcError(String),
    /// Tempo channel operation failed (open / stream / close / settle).
    #[error("tempo error: {0}")]
    TempoError(String),
    /// Amount was zero, negative, or exceeded the channel / policy cap.
    #[error("invalid amount")]
    InvalidAmount,
    /// Recipient failed CAIP-10 / base58 / 0x-address validation.
    #[error("invalid recipient: {0}")]
    InvalidRecipient(String),
    /// `close_channel` was called with an unknown [`crate::ChannelId`].
    #[error("channel not found: {0}")]
    ChannelNotFound(String),
    /// `close_channel` was called on a channel that is already closed.
    #[error("channel already closed: {0}")]
    ChannelClosed(String),
    /// The Key-Agent refused to sign or the signature failed verification.
    #[error("signing failed: {0}")]
    SigningFailed(String),
    /// The payer's session key is not valid for the requested chain / asset.
    #[error("chain mismatch: expected {expected}, got {actual}")]
    ChainMismatch {
        /// Expected CAIP-2 chain id (e.g. the settler's own `chain_id`).
        expected: String,
        /// Actual CAIP-2 chain id carried by the session key or asset.
        actual: String,
    },
}

impl PayError {
    /// Convenience constructor for [`PayError::BundlerError`].
    pub fn bundler(msg: impl Into<String>) -> Self {
        Self::BundlerError(msg.into())
    }

    /// Convenience constructor for [`PayError::PaymasterError`].
    pub fn paymaster(msg: impl Into<String>) -> Self {
        Self::PaymasterError(msg.into())
    }

    /// Convenience constructor for [`PayError::SolanaRpcError`].
    pub fn solana_rpc(msg: impl Into<String>) -> Self {
        Self::SolanaRpcError(msg.into())
    }

    /// Convenience constructor for [`PayError::TempoError`].
    pub fn tempo(msg: impl Into<String>) -> Self {
        Self::TempoError(msg.into())
    }

    /// Convenience constructor for [`PayError::SigningFailed`].
    pub fn signing_failed(msg: impl Into<String>) -> Self {
        Self::SigningFailed(msg.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pay_error_variants_display() {
        assert_eq!(PayError::BundlerError("boom".into()).to_string(), "bundler error: boom");
        assert_eq!(PayError::PaymasterError("nope".into()).to_string(), "paymaster error: nope");
        assert_eq!(PayError::SolanaRpcError("rpc".into()).to_string(), "solana rpc error: rpc");
        assert_eq!(PayError::TempoError("tmp".into()).to_string(), "tempo error: tmp");
        assert_eq!(PayError::InvalidAmount.to_string(), "invalid amount");
        assert_eq!(PayError::InvalidRecipient("0xz".into()).to_string(), "invalid recipient: 0xz");
        assert_eq!(PayError::ChannelNotFound("ch-1".into()).to_string(), "channel not found: ch-1");
        assert_eq!(
            PayError::ChannelClosed("ch-1".into()).to_string(),
            "channel already closed: ch-1"
        );
        assert_eq!(PayError::SigningFailed("kms".into()).to_string(), "signing failed: kms");
        assert_eq!(
            PayError::ChainMismatch {
                expected: "eip155:8453".into(),
                actual: "solana:mainnet".into(),
            }
            .to_string(),
            "chain mismatch: expected eip155:8453, got solana:mainnet"
        );
    }

    #[test]
    fn test_pay_error_clone() {
        // Mock clients store `Result<_, PayError>` and clone it on each call —
        // Clone must therefore be derivable for every variant.
        let errs = vec![
            PayError::BundlerError("x".into()),
            PayError::PaymasterError("x".into()),
            PayError::SolanaRpcError("x".into()),
            PayError::TempoError("x".into()),
            PayError::InvalidAmount,
            PayError::InvalidRecipient("x".into()),
            PayError::ChannelNotFound("x".into()),
            PayError::ChannelClosed("x".into()),
            PayError::SigningFailed("x".into()),
            PayError::ChainMismatch { expected: "a".into(), actual: "b".into() },
        ];
        for e in &errs {
            let _cloned = e.clone();
        }
    }

    #[test]
    fn test_required_variants_exist() {
        // T18 contract: assert each required variant is constructible.
        let _ = PayError::BundlerError(String::new());
        let _ = PayError::PaymasterError(String::new());
        let _ = PayError::SolanaRpcError(String::new());
        let _ = PayError::TempoError(String::new());
        let _ = PayError::InvalidAmount;
        let _ = PayError::InvalidRecipient(String::new());
        let _ = PayError::ChannelNotFound(String::new());
        let _ = PayError::ChannelClosed(String::new());
        let _ = PayError::SigningFailed(String::new());
    }
}
