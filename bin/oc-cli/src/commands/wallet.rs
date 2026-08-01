use std::io::{BufRead, IsTerminal, Write};

use ed25519_dalek::SigningKey as Ed25519SigningKey;
use k256::ecdsa::SigningKey as K256SigningKey;
use zeroize::Zeroize;

use crate::{CliError, audit};

pub(crate) fn create(name: &str, words: u32, show_mnemonic: bool) -> Result<(), CliError> {
    // Generate mnemonic, then import it to create the wallet
    let mut mnemonic_phrase = oc_wallet::generate_mnemonic(words)?;
    let info = oc_wallet::import_wallet_mnemonic(name, &mnemonic_phrase, None, Some(0), None)?;

    audit::log_wallet_created(&info);

    println!("Wallet created: {}", info.id);
    println!("Name:           {name}");
    println!();
    for acct in &info.accounts {
        println!("  {} → {}", acct.chain_id, acct.address);
        if !acct.derivation_path.is_empty() {
            println!("    Path: {}", acct.derivation_path);
        }
    }

    if show_mnemonic {
        eprintln!();
        eprintln!("⚠️  WARNING: The mnemonic below provides FULL ACCESS to this wallet.");
        eprintln!("⚠️  Store it securely offline. It will NOT be shown again.");
        eprintln!();
        println!("{mnemonic_phrase}");
    } else {
        eprintln!();
        eprintln!("Mnemonic encrypted and saved to vault.");
        eprintln!("Use --show-mnemonic at creation time if you need a backup copy.");
    }

    mnemonic_phrase.zeroize();
    Ok(())
}

pub(crate) fn change_password(wallet_name: &str) -> Result<(), CliError> {
    if !std::io::stdin().is_terminal() {
        return Err(CliError::InvalidArgs(
            "wallet change-password requires an interactive terminal".into(),
        ));
    }

    // Load the wallet
    let wallet = oc_wallet::get_wallet(wallet_name, None)?;

    // Read current passphrase
    eprint!("Current passphrase (empty for none): ");
    std::io::stderr().flush().ok();
    let old_pass = rpassword::read_password().unwrap_or_default();

    // Verify by attempting to export
    let _ = oc_wallet::export_wallet(wallet_name, Some(&old_pass), None)
        .map_err(|_| CliError::InvalidArgs("incorrect current passphrase".into()))?;

    // Read new passphrase
    eprint!("New passphrase (empty for none): ");
    std::io::stderr().flush().ok();
    let new_pass = rpassword::read_password().unwrap_or_default();

    eprint!("Confirm new passphrase: ");
    std::io::stderr().flush().ok();
    let confirm_pass = rpassword::read_password().unwrap_or_default();

    if new_pass != confirm_pass {
        return Err(CliError::InvalidArgs("passphrases do not match".into()));
    }

    if old_pass == new_pass {
        return Err(CliError::InvalidArgs(
            "new passphrase must differ from current passphrase".into(),
        ));
    }

    // Decrypt with old passphrase, re-encrypt with new passphrase
    let decrypted = oc_wallet::export_wallet(wallet_name, Some(&old_pass), None)?;

    // Load the raw wallet file, update the crypto envelope
    let wallet_file = oc_vault::load_wallet_by_name_or_id(wallet_name, None)?;
    let new_envelope = oc_signer::encrypt(decrypted.expose(), new_pass.as_bytes())?;
    let new_crypto_json = serde_json::to_value(&new_envelope)?;

    // Build updated wallet
    let mut updated = wallet_file;
    updated.crypto = new_crypto_json;
    oc_vault::save_encrypted_wallet(&updated, None)?;

    println!("Password changed successfully for wallet '{}'", wallet.name);
    Ok(())
}

pub(crate) fn export_public_key(
    wallet_name: &str,
    chain: Option<&str>,
    compressed: bool,
) -> Result<(), CliError> {
    if !std::io::stdin().is_terminal() {
        return Err(CliError::InvalidArgs(
            "wallet export --public-key requires an interactive terminal".into(),
        ));
    }

    let passphrase = if let Ok(b) = oc_wallet::export_wallet(wallet_name, None, None) {
        let _ = b;
        String::new()
    } else {
        super::read_passphrase().to_string()
    };

    let passphrase_ref = if passphrase.is_empty() { None } else { Some(passphrase.as_str()) };

    // Export the private key to derive the public key
    let secret = oc_wallet::export_wallet(wallet_name, passphrase_ref, None)?;
    let secret_str = std::str::from_utf8(secret.expose())
        .map_err(|e| CliError::InvalidArgs(format!("exported wallet not valid UTF-8: {e}")))?;

    // Parse the exported material
    let is_key_pair = secret_str.starts_with('{');

    if is_key_pair {
        // Private key wallet — extract secp256k1 key and derive public key
        let obj: serde_json::Value = serde_json::from_str(secret_str)?;
        let secp_hex = obj["secp256k1"]
            .as_str()
            .ok_or_else(|| CliError::InvalidArgs("missing secp256k1 key".into()))?;
        let privkey_bytes = hex::decode(secp_hex.strip_prefix("0x").unwrap_or(secp_hex))
            .map_err(|e| CliError::InvalidArgs(format!("invalid hex: {e}")))?;

        let signing_key = K256SigningKey::from_slice(&privkey_bytes)
            .map_err(|e| CliError::InvalidArgs(format!("invalid private key: {e}")))?;
        let verifying_key = signing_key.verifying_key();
        let point = verifying_key.to_sec1_point(compressed);
        println!("{}", hex::encode(point.as_bytes()));
    } else {
        // Mnemonic wallet — derive key for specified chain, then get public key
        let chain_str = chain.unwrap_or("evm");
        let chain_parsed = oc_core::parse_chain(chain_str)
            .map_err(|e| CliError::InvalidArgs(format!("invalid chain: {e}")))?;
        let key = super::resolve_signing_key(wallet_name, chain_parsed.chain_type, 0)?;

        let signer = oc_signer::signer_for_chain(chain_parsed.chain_type);
        match signer.curve() {
            oc_signer::Curve::Secp256k1 => {
                let signing_key = K256SigningKey::from_slice(key.expose())
                    .map_err(|e| CliError::InvalidArgs(format!("invalid key: {e}")))?;
                let verifying_key = signing_key.verifying_key();
                let point = verifying_key.to_sec1_point(compressed);
                println!("{}", hex::encode(point.as_bytes()));
            }
            oc_signer::Curve::Ed25519 => {
                let key_bytes: [u8; 32] = key
                    .expose()
                    .try_into()
                    .map_err(|_| CliError::InvalidArgs("ed25519 key must be 32 bytes".into()))?;
                let signing_key = Ed25519SigningKey::from_bytes(&key_bytes);
                let verifying_key = signing_key.verifying_key();
                println!("{}", hex::encode(verifying_key.to_bytes()));
            }
        }
    }

    Ok(())
}

pub(crate) fn import_interactive(name: &str, chain: Option<&str>) -> Result<(), CliError> {
    if !std::io::stdin().is_terminal() {
        return Err(CliError::InvalidArgs(
            "interactive import requires an interactive terminal".into(),
        ));
    }

    eprintln!("Select import type:");
    eprintln!("  1) Mnemonic phrase");
    eprintln!("  2) Private key (hex)");
    eprint!("Choice [1]: ");
    std::io::stderr().flush().ok();

    let mut choice = String::new();
    std::io::stdin().lock().read_line(&mut choice)?;
    let choice = choice.trim();

    let info = match choice {
        "" | "1" => {
            eprint!("Enter mnemonic (hidden): ");
            std::io::stderr().flush().ok();
            let phrase = rpassword::read_password()
                .map_err(|e| CliError::InvalidArgs(format!("failed to read mnemonic: {e}")))?;
            if phrase.trim().is_empty() {
                return Err(CliError::InvalidArgs("mnemonic cannot be empty".into()));
            }
            oc_wallet::import_wallet_mnemonic(name, phrase.trim(), None, Some(0), None)?
        }
        "2" => {
            eprint!("Enter private key hex (hidden): ");
            std::io::stderr().flush().ok();
            let key = rpassword::read_password()
                .map_err(|e| CliError::InvalidArgs(format!("failed to read key: {e}")))?;
            if key.trim().is_empty() {
                return Err(CliError::InvalidArgs("private key cannot be empty".into()));
            }
            oc_wallet::import_wallet_private_key(name, key.trim(), chain, None, None, None, None)?
        }
        _ => return Err(CliError::InvalidArgs(format!("invalid choice: '{choice}'"))),
    };

    audit::log_wallet_imported(&info);

    println!("Wallet imported: {}", info.id);
    println!("Name:            {name}");
    println!();
    for acct in &info.accounts {
        println!("  {} → {}", acct.chain_id, acct.address);
        if !acct.derivation_path.is_empty() {
            println!("    Path: {}", acct.derivation_path);
        }
    }

    Ok(())
}

pub(crate) fn import(
    name: &str,
    use_mnemonic: bool,
    use_private_key: bool,
    chain: Option<&str>,
    index: u32,
) -> Result<(), CliError> {
    // Read curve-specific keys from environment variables (cleared immediately after reading)
    let secp256k1_key = oc_signer::process_hardening::clear_env_var("ONECIPHER_SECP256K1_KEY")
        .or_else(|| oc_signer::process_hardening::clear_env_var("OWS_SECP256K1_KEY"));
    let ed25519_key = oc_signer::process_hardening::clear_env_var("ONECIPHER_ED25519_KEY")
        .or_else(|| oc_signer::process_hardening::clear_env_var("OWS_ED25519_KEY"));
    let secp256k1_key = secp256k1_key.as_deref().filter(|s| !s.is_empty());
    let ed25519_key = ed25519_key.as_deref().filter(|s| !s.is_empty());

    let has_curve_keys = secp256k1_key.is_some() || ed25519_key.is_some();
    let both_curve_keys = secp256k1_key.is_some() && ed25519_key.is_some();

    // Must specify exactly one import mode: --mnemonic, --private-key, or both curve keys (via env)
    if use_mnemonic && (use_private_key || has_curve_keys) {
        return Err(CliError::InvalidArgs(
            "cannot combine --mnemonic with --private-key or curve-specific keys".into(),
        ));
    }
    if !use_mnemonic && !use_private_key && !both_curve_keys {
        return Err(CliError::InvalidArgs(
            "specify --mnemonic, --private-key, or set ONECIPHER_SECP256K1_KEY and ONECIPHER_ED25519_KEY"
                .into(),
        ));
    }

    let info = if use_mnemonic {
        let phrase = super::read_mnemonic()?;
        oc_wallet::import_wallet_mnemonic(name, &phrase, None, Some(index), None)?
    } else {
        // Read from env/stdin only when both curve keys are not already provided
        let private_key_hex = if both_curve_keys {
            zeroize::Zeroizing::new(String::new())
        } else {
            super::read_private_key()?
        };
        oc_wallet::import_wallet_private_key(
            name,
            &private_key_hex,
            chain,
            None,
            None,
            secp256k1_key,
            ed25519_key,
        )?
    };

    audit::log_wallet_imported(&info);

    println!("Wallet imported: {}", info.id);
    println!("Name:            {name}");
    println!();
    for acct in &info.accounts {
        println!("  {} → {}", acct.chain_id, acct.address);
        if !acct.derivation_path.is_empty() {
            println!("    Path: {}", acct.derivation_path);
        }
    }

    Ok(())
}

pub(crate) fn export(wallet_name: &str) -> Result<(), CliError> {
    if !std::io::stdin().is_terminal() {
        return Err(CliError::InvalidArgs(
            "wallet export requires an interactive terminal (do not pipe stdin)".into(),
        ));
    }

    // Try empty passphrase first, then prompt if it fails.
    // export_wallet returns SecretBytes (HardenedBytes) — memory-hardened,
    // zeroized on drop. We borrow via std::str::from_utf8 to avoid a plain
    // String copy.
    let exported = if let Ok(b) = oc_wallet::export_wallet(wallet_name, None, None) {
        b
    } else {
        let passphrase = super::read_passphrase();
        oc_wallet::export_wallet(wallet_name, Some(&passphrase), None)?
    };
    let exported_str = std::str::from_utf8(exported.expose())
        .map_err(|e| CliError::InvalidArgs(format!("exported wallet not valid UTF-8: {e}")))?;

    let is_key_pair = exported_str.starts_with('{');
    eprintln!();
    if is_key_pair {
        eprintln!("WARNING: The private key below provides FULL ACCESS to this wallet.");
    } else {
        eprintln!("WARNING: The mnemonic below provides FULL ACCESS to this wallet.");
    }
    eprintln!("Do not share it. Store it securely offline.");
    eprintln!();
    println!("{exported_str}");
    // exported (SecretBytes) is zeroized on drop automatically.

    let info = oc_wallet::get_wallet(wallet_name, None)?;
    audit::log_wallet_exported(&info.id);
    Ok(())
}

pub(crate) fn delete(wallet_name: &str, confirm: bool) -> Result<(), CliError> {
    if !confirm {
        eprintln!("To delete a wallet, pass --confirm.");
        eprintln!("Consider exporting it first: onecipher wallet export --wallet {wallet_name}");
        return Err(CliError::InvalidArgs("--confirm is required to delete a wallet".into()));
    }

    let info = oc_wallet::get_wallet(wallet_name, None)?;
    oc_wallet::delete_wallet(wallet_name, None)?;
    audit::log_wallet_deleted(&info.id, &info.name);

    println!("Wallet deleted: {} ({})", info.id, info.name);
    Ok(())
}

pub(crate) fn rename(wallet_name: &str, new_name: &str) -> Result<(), CliError> {
    let info = oc_wallet::get_wallet(wallet_name, None)?;
    oc_wallet::rename_wallet(wallet_name, new_name, None)?;
    audit::log_wallet_renamed(&info.id, &info.name, new_name);

    println!("Wallet renamed: '{}' -> '{}'", info.name, new_name);
    Ok(())
}

pub(crate) fn list() -> Result<(), CliError> {
    let wallets = oc_wallet::list_wallets(None)?;

    if wallets.is_empty() {
        println!("No wallets found.");
        return Ok(());
    }

    for w in &wallets {
        println!("ID:      {}", w.id);
        println!("Name:    {}", w.name);
        println!("Secured: ✓ (encrypted)");
        for acct in &w.accounts {
            let label = oc_core::parse_chain(&acct.chain_id)
                .map(|c| format!(" ({})", c.name))
                .unwrap_or_default();
            println!("  {}{} → {}", acct.chain_id, label, acct.address);
        }
        println!("Created: {}", w.created_at);
        println!();
    }

    Ok(())
}
