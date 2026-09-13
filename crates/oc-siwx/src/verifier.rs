//! Chain-specific signature verifier (synchronous).
//!
//! Unlike the upstream siwx design (async `verify` for RPC), this trait is
//! synchronous so it stays usable from the sync Key-Agent loop (R55) and the
//! R56-isolated crates. Contract/counterfactual verification (EIP-1271 /
//! ERC-6492) lives in `oc-netagent` as `RpcVerifier`, which performs I/O and
//! then delegates the pure-crypto checks back to these sync primitives.
//!
//! # Contract
//!
//! * Hash / verify over **`raw_message` bytes** (the exact string the wallet signed), not a
//!   re-serialized form of `message`.
//! * Bind cryptographic identity to [`SiwxMessage::address`].
//! * `Ok(())` = valid; `VerificationFailed` = cryptographically invalid; `Backend` = transport
//!   (never include URLs); other variants = malformed.

use crate::{ChainIdReason, SiwxError, SiwxMessage};

/// Ecosystem label for EVM chains in the CAIP-122 preamble.
pub const EVM_CHAIN_NAME: &str = "Ethereum";
/// CAIP-2 namespace for EVM chains.
pub const EVM_NAMESPACE: &str = "eip155";
/// Ecosystem label for Solana in the CAIP-122 preamble.
pub const SOLANA_CHAIN_NAME: &str = "Solana";
/// CAIP-2 namespace for Solana.
pub const SOLANA_NAMESPACE: &str = "solana";

/// Chain-specific synchronous signature verifier.
pub trait SyncVerifier: Send + Sync {
    /// Ecosystem label in the preamble.
    const CHAIN_NAME: &'static str;

    /// CAIP-2 namespace, e.g. `"eip155"` / `"solana"`.
    const NAMESPACE: &'static str;

    /// Validate address shape. Default accepts any non-empty string.
    fn validate_address(address: &str) -> Result<(), SiwxError> {
        if address.is_empty() {
            return Err(SiwxError::InvalidAddress { reason: "empty".to_owned() });
        }
        Ok(())
    }

    /// Validate chain-id shape. Default rejects only empty.
    fn validate_chain_id(chain_id: &str) -> Result<(), SiwxError> {
        if chain_id.is_empty() {
            return Err(SiwxError::InvalidChainId { reason: ChainIdReason::Empty });
        }
        Ok(())
    }

    /// Verify `signature` over `raw_message`, binding identity to `message`.
    fn verify(
        &self,
        message: &SiwxMessage,
        raw_message: &str,
        signature: &[u8],
    ) -> Result<(), SiwxError>;

    /// Render `message` into the chain's canonical signing string.
    #[must_use]
    fn format_message(message: &SiwxMessage) -> String {
        message.to_sign_string(Self::CHAIN_NAME)
    }
}
