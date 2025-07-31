//! Backup CLI (R42). Uses `oc-vault::BackupContainer` (Argon2id + XChaCha20-Poly1305 AEAD).
//!
//! `onecipher backup export --out <path>`
//! `onecipher backup import --in <path>`

use std::os::unix::fs::PermissionsExt;

use oc_vault::BackupContainer;

use crate::CliError;

/// Entry point for `onecipher backup export --out <path>`.
///
/// Lists all wallets from the default vault, serializes them to JSON, encrypts
/// the payload with a passphrase-derived key (Argon2id + XChaCha20-Poly1305),
/// and writes the resulting `BackupContainer` as pretty JSON to `out` with
/// mode 0600.
pub(crate) fn export(out: &str) -> Result<(), CliError> {
    let passphrase = super::read_passphrase();

    let wallets = oc_vault::list_encrypted_wallets(None)?;
    let payload = serde_json::to_vec(&wallets)?;
    let container = BackupContainer::export(&payload, &passphrase)?;
    let json = serde_json::to_string_pretty(&container)?;

    std::fs::write(out, json)?;
    // Enforce 0600 — the backup contains encrypted wallet material.
    std::fs::set_permissions(out, std::fs::Permissions::from_mode(0o600))?;

    eprintln!(
        "backup exported {} wallet(s) to {out} (Argon2id + XChaCha20-Poly1305)",
        wallets.len()
    );
    Ok(())
}

/// Entry point for `onecipher backup import --in <path>`.
///
/// Reads a `BackupContainer` JSON file, decrypts it with the provided
/// passphrase, deserializes the wallet list, and saves each wallet to the
/// default vault.
pub(crate) fn import(input: &str) -> Result<(), CliError> {
    let json = std::fs::read_to_string(input)?;
    let mut container: BackupContainer = serde_json::from_str(&json)?;

    let passphrase = super::read_passphrase();
    let payload = container.import(&passphrase)?;

    let wallets: Vec<oc_core::EncryptedWallet> = serde_json::from_slice(&payload)?;
    let count = wallets.len();
    for wallet in &wallets {
        oc_vault::save_encrypted_wallet(wallet, None)?;
    }

    eprintln!("backup imported {count} wallet(s) from {input}");
    Ok(())
}
