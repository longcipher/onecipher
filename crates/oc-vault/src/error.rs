//! Unified error type for oc-vault operations.
//!
//! `Crypto` and `InvalidFormat` carry a String because the underlying crypto /
//! format errors come from several different crates (`age`, `serde_json`)
//! and we don't want to leak their concrete error types into the public API.

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

    #[error("insecure vault permissions: mode {0:04o}, expected 0700")]
    InsecurePermissions(u32),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    Serde(#[from] serde_json::Error),

    #[error("crypto error: {0}")]
    Crypto(String),

    #[error("invalid format: {0}")]
    InvalidFormat(String),

    #[error("unsupported backup container version: found {found}, expected {expected}")]
    UnsupportedVersion { found: u8, expected: u8 },
}
