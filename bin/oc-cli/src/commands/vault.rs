//! Vault CLI (Phase 1 subcommand). `onecipher vault unlock` verifies the
//! passphrase against every wallet in the vault.
//!
//! NOTE: This is distinct from the top-level `crate::vault` module (which is
//! the legacy vault helpers, currently empty). This module hosts the
//! `onecipher vault unlock` subcommand.

use oc_core::ChainType;

use crate::CliError;

/// Entry point for `onecipher vault unlock`.
///
/// Prompts for a passphrase, then attempts to decrypt every wallet's signing
/// key to verify the passphrase is correct. If all wallets decrypt
/// successfully, prints a success message.
///
/// The passphrase is NOT cached — `oc-vault` has no "unlock session" concept.
/// Each subsequent signing command will prompt for the passphrase again (or
/// read it from `ONECIPHER_PASSPHRASE`).
pub(crate) fn unlock() -> Result<(), CliError> {
    let passphrase = super::read_passphrase();

    let wallets = oc_vault::list_encrypted_wallets(None)?;

    if wallets.is_empty() {
        eprintln!("vault unlock: no wallets in vault (passphrase not verified)");
        return Ok(());
    }

    let pp_bytes = passphrase.as_bytes();
    for wallet in &wallets {
        // Verify the passphrase by decrypting the signing key for the EVM
        // chain (every universal wallet derives an EVM account). Use the
        // wallet ID to avoid ambiguity from duplicate names.
        match oc_wallet::decrypt_signing_key(&wallet.id, ChainType::Evm, pp_bytes, Some(0), None) {
            Ok(_) => {}
            Err(oc_wallet::OcWalletError::Crypto(_)) => {
                eprintln!("vault unlock: wrong passphrase (failed on wallet '{}')", wallet.name);
                return Err(CliError::InvalidArgs("wrong passphrase".into()));
            }
            Err(e) => return Err(e.into()),
        }
    }

    eprintln!("Vault unlocked successfully (verified {} wallet(s)).", wallets.len());
    eprintln!("Note: passphrase verified but not cached; subsequent commands will prompt again.");
    Ok(())
}
