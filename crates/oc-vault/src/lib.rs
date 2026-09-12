// Test code may unwrap/expect/panic (workspace lint phase-1 carve-out).
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]
//! Wallet vault (filesystem 700/600, age-encrypted wallets, age backup bundles).
//!
//! Wallet files carry an [`AgeEnvelope`](crypto::AgeEnvelope) (age scrypt
//! passphrase); `.ocbk` backup bundles are age multi-recipient files (see
//! [`backup`]).

pub mod atomic;
pub mod backup;
pub mod crypto;
pub mod error;
pub mod vault;

pub use atomic::write_atomic_secret;
pub use backup::{BACKUP_PATH, BACKUP_TAG, export_backup, import_backup};
pub use crypto::{
    AGE_CIPHER, AgeEnvelope, AgeIdentity, CryptoError, decrypt_with_identity,
    decrypt_with_passphrase, encrypt_to_recipients, encrypt_with_passphrase, token_identity,
    token_recipient,
};
pub use error::OcVaultError;
pub use vault::{
    SecretVault, Vault, check_vault_permissions, delete_wallet_file, list_encrypted_wallets,
    load_wallet_by_name_or_id, resolve_vault_path, save_encrypted_wallet, wallet_name_exists,
    wallets_dir,
};
