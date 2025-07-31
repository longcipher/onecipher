//! Migrate legacy keystore v3 wallets to age-encrypted secrets.
//!
//! `onecipher migrate`           — migrate all legacy wallets into the secret store
//! `onecipher migrate --dry-run` — report what would be migrated without writing
//! `onecipher migrate --rollback` — remove `.age` entries created by migration
//!
//! The migration reads each `<vault>/wallets/<id>.json` file, decrypts it with
//! the user's passphrase, and re-encrypts the key material as an age
//! [`SecretEntry`] under `<vault>/secrets/<name>.age`. Legacy `.json` files are
//! never deleted — after verifying the migration the user removes them by hand.

use std::path::PathBuf;

use oc_core::Config;
use oc_secret::{RecipientsFile, SecretStore, StoreConfig, migrate};

use crate::CliError;

/// Recipients file name expected at the vault root.
const RECIPIENTS_FILE: &str = ".age-recipients";

/// Entry point for `onecipher migrate`.
pub(crate) fn run(dry_run: bool, rollback: bool) -> Result<(), CliError> {
    let vault_root: PathBuf = Config::default().vault_path;

    // Open the secret store rooted at the vault root (creates `secrets/` and
    // `index.jsonl` on first open). Rollback only needs the store, not the
    // recipients, so we open it unconditionally.
    let store = SecretStore::open(StoreConfig::new(vault_root.clone()))?;

    if rollback {
        let removed = migrate::rollback_migration(&store, &vault_root)?;
        eprintln!("rollback: removed {removed} migrated secret entry/entries");
        eprintln!("legacy wallet .json files are unchanged and remain the primary source");
        return Ok(());
    }

    // Load age recipients (public keys) from <vault_root>/.age-recipients.
    let recipients_path = vault_root.join(RECIPIENTS_FILE);
    let recipients = if recipients_path.is_file() {
        RecipientsFile::load(&recipients_path)?
    } else {
        return Err(CliError::InvalidArgs(format!(
            "no recipients file found at {}; create one first (e.g. with `age-keygen`)",
            recipients_path.display()
        )));
    };
    let recipient_strs: Vec<String> = recipients.iter().map(|r| r.to_string()).collect();

    let passphrase = super::read_passphrase();

    let results = migrate::migrate_legacy_wallets(
        &vault_root,
        &store,
        &passphrase,
        &recipient_strs,
        dry_run,
    )?;

    if results.is_empty() {
        eprintln!(
            "migrate: no wallets migrated (vault empty, already migrated, or wrong passphrase)"
        );
        return Ok(());
    }

    let label = if dry_run { "migrate (dry run)" } else { "migrate" };
    eprintln!(
        "{label}: {} wallet(s) {}:",
        results.len(),
        if dry_run { "would be migrated" } else { "migrated" }
    );
    for r in &results {
        eprintln!("  '{}' ({}) -> secret entry '{}'", r.wallet_name, r.wallet_id, r.entry_name);
    }
    if dry_run {
        eprintln!("no files were written (dry run)");
    } else {
        eprintln!("legacy .json files were NOT deleted; remove them manually after verifying");
    }
    Ok(())
}
