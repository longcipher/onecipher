//! Wallet vault (filesystem 700/600, Keystore v3, .ocbk BackupContainer).
//!
//! Fully designed and implemented in accordance with the Open Wallet Standard (renamed `ows_core` →
//! `oc_core`, `OwsLibError` → `OcVaultError`) plus the new `BackupContainer`
//! implementing Argon2id + XChaCha20-Poly1305 AEAD (R42 / AD-05).

pub mod backup;
pub mod error;
pub mod vault;

pub use backup::{
    Argon2idParams, BackupContainer, MAGIC, MAX_FAILED_ATTEMPTS, VERSION, set_backoff_override,
};
pub use error::OcVaultError;
pub use vault::{
    SecretVault, Vault, check_vault_permissions, delete_wallet_file, list_encrypted_wallets,
    load_wallet_by_name_or_id, resolve_vault_path, save_encrypted_wallet, wallet_name_exists,
    wallets_dir,
};
