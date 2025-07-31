//! Migrate legacy wallet files into the unified secret store.
//!
//! Reads encrypted wallet JSON files (`<wallets_dir>/<id>.json`) created by
//! `oc-vault`, decrypts each with the user's passphrase, and stores the key
//! material as a [`SecretEntry`] in the [`SecretStore`].
//!
//! # Migration mapping
//!
//! | Legacy `KeyType` | New `ItemType` | Payload `secret` field         |
//! |------------------|---------------|--------------------------------|
//! | `Mnemonic`       | `Mnemonic`    | UTF-8 mnemonic phrase           |
//! | `PrivateKey`     | `PrivateKey`  | hex/raw key material (as-is)    |

use std::path::Path;

use oc_core::{KeyType, SecretMetadata, SecretPayload};
use oc_vault::{Vault, list_encrypted_wallets};

use crate::{
    entry::SecretEntry,
    store::{SecretStore, SecretStoreError},
};

/// Errors returned by wallet migration.
#[derive(Debug, thiserror::Error)]
pub enum MigrationError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("vault error: {0}")]
    Vault(#[from] oc_vault::OcVaultError),
    #[error("store error: {0}")]
    Store(#[from] SecretStoreError),
    #[error("entry error: {0}")]
    Entry(#[from] crate::entry::SecretEntryError),
    #[error("decrypted key material is not valid UTF-8")]
    InvalidUtf8,
    #[error("no recipients configured — cannot encrypt migrated secrets")]
    NoRecipients,
    #[error("memory hardening failed: {0}")]
    MemGuard(String),
}

impl From<oc_crypto::MemGuardError> for MigrationError {
    fn from(e: oc_crypto::MemGuardError) -> Self {
        Self::MemGuard(e.to_string())
    }
}

/// Result of migrating a single wallet.
#[derive(Clone, Debug)]
pub struct MigrationResult {
    /// The wallet ID from the legacy file.
    pub wallet_id: String,
    /// The name used for the new secret entry.
    pub entry_name: String,
    /// The original wallet name.
    pub wallet_name: String,
    /// The key type that was migrated.
    pub key_type: KeyType,
}

/// Migrate all legacy wallet files in `wallets_dir` into `store`.
///
/// Each wallet is decrypted with `passphrase`, then re-encrypted with the
/// provided `recipients` (age public key strings) and stored as a new
/// [`SecretEntry`]. The entry name is derived from the wallet name
/// (sanitized for filesystem safety).
///
/// When `dry_run` is `true`, the entry is still built (which validates that
/// the passphrase decrypts and the recipient list encrypts correctly) but it
/// is **not** written to the store. The legacy `<id>.json` file is never
/// deleted — migration only adds the new `.age` entry.
///
/// Returns the list of migration results. Wallets that fail to decrypt
/// (wrong passphrase, corrupted file) are skipped with a warning to stderr.
pub fn migrate_legacy_wallets(
    wallets_dir: &Path,
    store: &SecretStore,
    passphrase: &str,
    recipients: &[String],
    dry_run: bool,
) -> Result<Vec<MigrationResult>, MigrationError> {
    if recipients.is_empty() {
        return Err(MigrationError::NoRecipients);
    }

    let wallets = list_encrypted_wallets(Some(wallets_dir))?;
    let mut results = Vec::new();

    for wallet in &wallets {
        let wallet_path = wallets_dir.join("wallets").join(format!("{}.json", wallet.id));
        match migrate_one(&wallet_path, wallet, store, passphrase, recipients, dry_run) {
            Ok(result) => results.push(result),
            Err(e) => {
                eprintln!("warning: skipping wallet '{}' ({}): {e}", wallet.name, wallet.id);
            }
        }
    }

    Ok(results)
}

/// Rollback a migration by removing the `.age` entries created by
/// [`migrate_legacy_wallets`].
///
/// For each legacy wallet still present in `wallets_dir`, the sanitized entry
/// name is recomputed and the matching entry is deleted from `store`. Entries
/// that were never migrated (or already removed) are silently skipped. The
/// legacy `<id>.json` files are untouched (migration never deleted them), so
/// after rollback they become the primary source again.
///
/// Returns the number of entries actually removed.
pub fn rollback_migration(
    store: &SecretStore,
    wallets_dir: &Path,
) -> Result<usize, MigrationError> {
    let wallets = list_encrypted_wallets(Some(wallets_dir))?;
    let mut removed = 0usize;
    for wallet in &wallets {
        let entry_name = sanitize_name(&wallet.name);
        match store.delete(&entry_name) {
            Ok(()) => removed += 1,
            Err(crate::store::SecretStoreError::NotFound(_)) => { /* not migrated */ }
            Err(e) => return Err(e.into()),
        }
    }
    Ok(removed)
}

/// Migrate a single wallet file.
fn migrate_one(
    wallet_path: &Path,
    wallet: &oc_core::EncryptedWallet,
    store: &SecretStore,
    passphrase: &str,
    recipients: &[String],
    dry_run: bool,
) -> Result<MigrationResult, MigrationError> {
    // Load and decrypt the wallet.
    let vault = Vault::load(wallet_path)?;
    let key_bytes = vault.decrypt(&oc_crypto::HardenedBytes::from_slice(passphrase.as_bytes())?)?;

    // Interpret the decrypted bytes based on key_type.
    let (item_type, secret_str) = match wallet.key_type {
        KeyType::Mnemonic => {
            let phrase = std::str::from_utf8(key_bytes.expose())
                .map_err(|_| MigrationError::InvalidUtf8)?
                .to_owned();
            (oc_core::ItemType::Mnemonic, phrase)
        }
        KeyType::PrivateKey => {
            // Private key material may be raw bytes or JSON; store as
            // hex if not valid UTF-8, otherwise as-is.
            let secret = std::str::from_utf8(key_bytes.expose())
                .map_or_else(|_| hex::encode(key_bytes.expose()), |s| s.to_owned());
            (oc_core::ItemType::PrivateKey, secret)
        }
    };

    // Sanitize the wallet name for use as an entry name.
    let entry_name = sanitize_name(&wallet.name);

    // Build the payload and metadata.
    let payload = SecretPayload {
        secret: secret_str,
        notes: Some(format!("Migrated from wallet '{}'", wallet.name)),
        extra: Some(serde_json::json!({
            "wallet_id": wallet.id,
            "key_type": wallet.key_type,
        })),
    };

    let metadata = SecretMetadata {
        chain: wallet.accounts.first().map(|a| a.chain_id.clone()),
        ..Default::default()
    };

    // Create the encrypted entry. In dry-run mode the entry is still built
    // (validating decryption + re-encryption) but not persisted.
    let entry = SecretEntry::new(&entry_name, item_type, &payload, metadata, recipients)?;
    if !dry_run {
        store.put(&entry)?;
    }

    Ok(MigrationResult {
        wallet_id: wallet.id.clone(),
        entry_name,
        wallet_name: wallet.name.clone(),
        key_type: wallet.key_type.clone(),
    })
}

/// Sanitize a wallet name for use as a filesystem-safe entry name.
fn sanitize_name(name: &str) -> String {
    name.chars()
        .map(|c| if c.is_alphanumeric() || c == '-' || c == '_' { c } else { '-' })
        .collect::<String>()
        .trim_matches('-')
        .to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{age::AgeIdentity, store::StoreConfig};

    fn make_store() -> (tempfile::TempDir, SecretStore) {
        let dir = tempfile::tempdir().unwrap();
        let store = SecretStore::open(StoreConfig::new(dir.path().to_path_buf())).unwrap();
        (dir, store)
    }

    fn make_encrypted_wallet(
        name: &str,
        plaintext: &[u8],
        passphrase: &str,
    ) -> oc_core::EncryptedWallet {
        let envelope = oc_signer::encrypt(plaintext, passphrase.as_bytes()).unwrap();
        oc_core::EncryptedWallet::new(
            uuid::Uuid::new_v4().to_string(),
            name.to_string(),
            vec![],
            serde_json::to_value(&envelope).unwrap(),
            KeyType::Mnemonic,
        )
    }

    #[test]
    fn sanitize_replaces_special_chars() {
        // '!' is replaced with '-', then trim_matches removes the trailing dash.
        assert_eq!(sanitize_name("My Wallet!"), "My-Wallet");
        assert_eq!(sanitize_name("hello/world"), "hello-world");
        assert_eq!(sanitize_name("a b c"), "a-b-c");
    }

    #[test]
    fn sanitize_keeps_alphanumeric_and_dashes() {
        assert_eq!(sanitize_name("my-wallet_123"), "my-wallet_123");
    }

    #[test]
    fn migrate_mnemonic_wallet_round_trip() {
        let vault_dir = tempfile::tempdir().unwrap();
        let (_store_dir, store) = make_store();

        let passphrase = "correct horse battery staple";
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let wallet = make_encrypted_wallet("Test Wallet", mnemonic.as_bytes(), passphrase);
        oc_vault::save_encrypted_wallet(&wallet, Some(vault_dir.path())).unwrap();

        let identity = AgeIdentity::generate();
        let recipient = identity.to_recipient_string();

        let results =
            migrate_legacy_wallets(vault_dir.path(), &store, passphrase, &[recipient], false)
                .unwrap();

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].wallet_name, "Test Wallet");
        assert_eq!(results[0].key_type, KeyType::Mnemonic);

        // Verify the entry is in the store and decryptable.
        let entry = store.get(&results[0].entry_name).unwrap();
        let payload = entry.decrypt(&identity).unwrap();
        assert_eq!(payload.secret, mnemonic);
    }

    #[test]
    fn migrate_with_no_recipients_fails() {
        let vault_dir = tempfile::tempdir().unwrap();
        let (_store_dir, store) = make_store();

        let result = migrate_legacy_wallets(vault_dir.path(), &store, "pass", &[], false);
        assert!(matches!(result, Err(MigrationError::NoRecipients)));
    }

    #[test]
    fn migrate_wrong_passphrase_skips_wallet() {
        let vault_dir = tempfile::tempdir().unwrap();
        let (_store_dir, store) = make_store();

        let passphrase = "correct horse battery staple";
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let wallet = make_encrypted_wallet("Wallet", mnemonic.as_bytes(), passphrase);
        oc_vault::save_encrypted_wallet(&wallet, Some(vault_dir.path())).unwrap();

        let identity = AgeIdentity::generate();
        let recipient = identity.to_recipient_string();

        // Wrong passphrase — wallet should be skipped.
        let results = migrate_legacy_wallets(
            vault_dir.path(),
            &store,
            "wrong passphrase",
            &[recipient],
            false,
        )
        .unwrap();

        assert!(results.is_empty());
    }

    #[test]
    fn migrate_multiple_wallets() {
        let vault_dir = tempfile::tempdir().unwrap();
        let (_store_dir, store) = make_store();

        let passphrase = "pass";
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let w1 = make_encrypted_wallet("Wallet One", mnemonic.as_bytes(), passphrase);
        let w2 = make_encrypted_wallet("Wallet Two", mnemonic.as_bytes(), passphrase);
        oc_vault::save_encrypted_wallet(&w1, Some(vault_dir.path())).unwrap();
        oc_vault::save_encrypted_wallet(&w2, Some(vault_dir.path())).unwrap();

        let identity = AgeIdentity::generate();
        let recipient = identity.to_recipient_string();

        let results =
            migrate_legacy_wallets(vault_dir.path(), &store, passphrase, &[recipient], false)
                .unwrap();

        assert_eq!(results.len(), 2);
        let list = store.list().unwrap();
        assert_eq!(list.len(), 2);
    }

    #[test]
    fn dry_run_does_not_persist_entries() {
        let vault_dir = tempfile::tempdir().unwrap();
        let (_store_dir, store) = make_store();

        let passphrase = "correct horse battery staple";
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let wallet = make_encrypted_wallet("Dry Wallet", mnemonic.as_bytes(), passphrase);
        oc_vault::save_encrypted_wallet(&wallet, Some(vault_dir.path())).unwrap();

        let identity = AgeIdentity::generate();
        let recipient = identity.to_recipient_string();

        let results =
            migrate_legacy_wallets(vault_dir.path(), &store, passphrase, &[recipient], true)
                .unwrap();

        // Result is reported but nothing is written to the store.
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].wallet_name, "Dry Wallet");
        assert!(store.list().unwrap().is_empty());
        assert!(store.get(&results[0].entry_name).is_err());

        // The legacy .json file is untouched.
        assert!(vault_dir.path().join("wallets").join(format!("{}.json", wallet.id)).exists());
    }

    #[test]
    fn rollback_removes_migrated_entries() {
        let vault_dir = tempfile::tempdir().unwrap();
        let (_store_dir, store) = make_store();

        let passphrase = "pass";
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let w1 = make_encrypted_wallet("Roll One", mnemonic.as_bytes(), passphrase);
        let w2 = make_encrypted_wallet("Roll Two", mnemonic.as_bytes(), passphrase);
        oc_vault::save_encrypted_wallet(&w1, Some(vault_dir.path())).unwrap();
        oc_vault::save_encrypted_wallet(&w2, Some(vault_dir.path())).unwrap();

        let identity = AgeIdentity::generate();
        let recipient = identity.to_recipient_string();

        // Migrate both wallets.
        migrate_legacy_wallets(vault_dir.path(), &store, passphrase, &[recipient], false).unwrap();
        assert_eq!(store.list().unwrap().len(), 2);

        // Rollback removes both entries but leaves the .json files intact.
        let removed = rollback_migration(&store, vault_dir.path()).unwrap();
        assert_eq!(removed, 2);
        assert!(store.list().unwrap().is_empty());

        // Legacy files are still there.
        assert!(vault_dir.path().join("wallets").join(format!("{}.json", w1.id)).exists());
        assert!(vault_dir.path().join("wallets").join(format!("{}.json", w2.id)).exists());
    }

    #[test]
    fn rollback_without_migration_is_noop() {
        let vault_dir = tempfile::tempdir().unwrap();
        let (_store_dir, store) = make_store();

        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let wallet = make_encrypted_wallet("NoMig", mnemonic.as_bytes(), "pass");
        oc_vault::save_encrypted_wallet(&wallet, Some(vault_dir.path())).unwrap();

        // No migration performed — rollback removes nothing and does not error.
        let removed = rollback_migration(&store, vault_dir.path()).unwrap();
        assert_eq!(removed, 0);
    }
}
