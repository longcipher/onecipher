use oc_core::ChainType;

use super::error::OcPayHttpError;

/// An account on any chain.
#[derive(Debug, Clone)]
pub struct Account {
    /// Address in the chain's native format (e.g. "0x..." for EVM, base58 for Solana).
    pub address: String,
}

/// Trait abstracting wallet access for payment operations.
///
/// Each method takes a CAIP-2 network identifier (e.g. `"eip155:8453"`,
/// `"solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp"`) to identify the chain.
///
/// The private key NEVER leaves the implementation — all signing happens
/// inside the wallet.
pub trait WalletAccess: Send + Sync {
    /// Chain families this wallet can operate on.
    fn supported_chains(&self) -> Vec<ChainType>;

    /// Get the account for a CAIP-2 network.
    fn account(&self, network: &str) -> Result<Account, OcPayHttpError>;

    /// Sign a payment payload for the given scheme and network.
    ///
    /// The payload format depends on the scheme:
    /// - `"exact"`: EIP-712 typed data JSON (EVM chains)
    ///
    /// Returns the signature as a hex string with `0x` prefix.
    fn sign_payload(
        &self,
        scheme: &str,
        network: &str,
        payload: &str,
    ) -> Result<String, OcPayHttpError>;
}
