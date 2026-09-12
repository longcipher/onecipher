//! Backup CLI (R42). Uses `oc-vault` age-encrypted backup bundles.
//!
//! `onecipher backup export --out <path> --recipient <age1...> [--recipient ...]`
//! `onecipher backup import --in <path> [--identity <AGE-SECRET-KEY-1...>]`

use oc_vault::crypto::AgeIdentity;

use crate::CliError;

/// Entry point for `onecipher backup export`.
///
/// Lists all wallets from the default vault, serializes them to JSON,
/// age-encrypts the payload to the given X25519 recipients, and writes the
/// resulting bundle to `out` with mode 0600.
pub(crate) fn export(out: &str, recipients: &[String]) -> Result<(), CliError> {
    if recipients.is_empty() {
        return Err(CliError::InvalidArgs(
            "at least one --recipient <age1...> is required (the bundle decrypts only under a listed recipient identity)".into(),
        ));
    }

    let wallets = oc_vault::list_encrypted_wallets(None)?;
    let payload = serde_json::to_vec(&wallets)?;
    let bundle = oc_vault::export_backup(&payload, recipients)?;
    let count = wallets.len();

    // H-02: atomic private write — the file is created 0600 from the start
    // (no world-readable window) and cannot be observed torn. The backup
    // contains encrypted wallet material.
    oc_core::paths::write_atomic_private(std::path::Path::new(out), &bundle)?;

    eprintln!(
        "backup exported {count} wallet(s) to {out} (age, {} recipient(s))",
        recipients.len()
    );
    Ok(())
}

/// Read the backup identity from `--identity` or, when omitted, hidden from
/// the terminal.
fn read_identity(flag: Option<&str>) -> Result<AgeIdentity, CliError> {
    if let Some(s) = flag {
        return AgeIdentity::parse(s.trim())
            .map_err(|e| CliError::InvalidArgs(format!("invalid --identity: {e}")));
    }
    eprint!("Backup identity (AGE-SECRET-KEY-1...): ");
    std::io::Write::flush(&mut std::io::stderr()).ok();
    let line = rpassword::read_password().unwrap_or_default();
    AgeIdentity::parse(line.trim())
        .map_err(|e| CliError::InvalidArgs(format!("invalid backup identity: {e}")))
}

/// Entry point for `onecipher backup import`.
///
/// Reads an age-encrypted bundle, decrypts it with the recipient identity,
/// deserializes the wallet list, and saves each wallet to the default vault.
pub(crate) fn import(input: &str, identity: Option<&str>) -> Result<(), CliError> {
    let data = std::fs::read(input)?;
    let identity = read_identity(identity)?;
    let (generation, payload) = oc_vault::import_backup(&data, &identity)?;

    let wallets: Vec<oc_core::EncryptedWallet> = serde_json::from_slice(&payload)?;
    let count = wallets.len();
    for wallet in &wallets {
        oc_vault::save_encrypted_wallet(wallet, None)?;
    }

    eprintln!("backup imported {count} wallet(s) from {input} (exported at unix {generation})");
    Ok(())
}
