//! Unified error type for oc-vault operations.
//!
//! Fully designed and implemented in accordance with the Open Wallet Standard's error types and
//! trimmed to the variants actually raised by the vault + backup-container code paths. `Crypto` and
//! `InvalidFormat` carry a String because the underlying crypto / format
//! errors come from several different crates (`chacha20poly1305`,
//! `argon2`, `serde_json`) and we don't want to leak their concrete error
//! types into the public API.

#[derive(Debug, thiserror::Error)]
pub enum OcVaultError {
    #[error("wallet not found: '{0}'")]
    WalletNotFound(String),

    #[error("ambiguous wallet name '{name}' matches {count} wallets; use the wallet ID instead")]
    AmbiguousWallet { name: String, count: usize },

    #[error("wallet name already exists: '{0}'")]
    WalletNameExists(String),

    #[error("invalid input: {0}")]
    InvalidInput(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    Serde(#[from] serde_json::Error),

    #[error("crypto error: {0}")]
    Crypto(String),

    #[error("vault is locked due to too many failed passphrase attempts")]
    Locked,

    #[error("wrong passphrase")]
    WrongPassphrase,

    #[error("invalid format: {0}")]
    InvalidFormat(String),
}
