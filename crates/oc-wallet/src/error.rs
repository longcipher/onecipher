use oc_signer::{CryptoError, SignerError, hd::HdError, mnemonic::MnemonicError};

/// Unified error type for oc-wallet operations.
#[derive(Debug, thiserror::Error)]
pub enum OcWalletError {
    #[error("wallet not found: '{0}'")]
    WalletNotFound(String),

    #[error("ambiguous wallet name '{name}' matches {count} wallets; use the wallet ID instead")]
    AmbiguousWallet { name: String, count: usize },

    #[error("wallet name already exists: '{0}'")]
    WalletNameExists(String),

    #[error("invalid input: {0}")]
    InvalidInput(String),

    #[error("broadcast failed: {0}")]
    BroadcastFailed(String),

    #[error("{0}")]
    Crypto(#[from] CryptoError),

    #[error("{0}")]
    Signer(#[from] SignerError),

    #[error("{0}")]
    Mnemonic(#[from] MnemonicError),

    #[error("{0}")]
    Hd(#[from] HdError),

    #[error("{0}")]
    Core(#[from] oc_core::OcError),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[cfg(feature = "rpc")]
    #[error("HTTP error: {0}")]
    Http(#[from] hpx::Error),
}

// Bridge vault errors into the wallet error type so callers can keep using `?`
// after the duplicate `vault` module was removed in favor of `oc_vault`.
// Variants are mapped to their semantic equivalents so existing match arms
// (e.g. `OcWalletError::WalletNotFound`) continue to behave identically.
impl From<oc_vault::OcVaultError> for OcWalletError {
    fn from(e: oc_vault::OcVaultError) -> Self {
        match e {
            oc_vault::OcVaultError::WalletNotFound(id) => Self::WalletNotFound(id),
            oc_vault::OcVaultError::AmbiguousWallet { name, count } => {
                Self::AmbiguousWallet { name, count }
            }
            oc_vault::OcVaultError::Io(io) => Self::Io(io),
            oc_vault::OcVaultError::Serde(s) => Self::Json(s),
            other => Self::InvalidInput(other.to_string()),
        }
    }
}
