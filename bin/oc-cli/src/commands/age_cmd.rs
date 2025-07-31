//! age key management CLI commands (`onecipher age ...`).
//!
//! Manages the age X25519 identity and recipients list used to encrypt/decrypt
//! the secret store. The identity file lives at
//! `~/.onecipher/keys/age-identity.txt` (0600); the recipients list lives at
//! `~/.onecipher/.age-recipients`.

use std::path::Path;

use oc_secret::{AgeIdentity, Recipient, RecipientsFile};

use crate::CliError;

/// Entry point for `onecipher age init`.
///
/// Generates a new age X25519 identity, writes it to
/// `~/.onecipher/keys/age-identity.txt` (0600), writes the public recipient
/// string to `~/.onecipher/keys/age-recipient.txt`, and adds the recipient to
/// `~/.onecipher/.age-recipients`.
#[allow(dead_code)]
pub(crate) fn init() -> Result<(), CliError> {
    let identity = AgeIdentity::generate();
    let identity_str = identity.to_secret_string();
    let recipient_str = identity.to_recipient_string();

    let keys_dir = super::keys_dir();
    std::fs::create_dir_all(&keys_dir)?;
    set_dir_mode_0700(&keys_dir);

    // Write identity file (0600).
    let identity_path = super::age_identity_path();
    if identity_path.exists() {
        return Err(CliError::InvalidArgs(format!(
            "age identity already exists at {} (delete it first to reinitialize)",
            identity_path.display()
        )));
    }
    std::fs::write(&identity_path, &identity_str)?;
    set_file_mode_0600(&identity_path);

    // Write public recipient file (for display purposes).
    let recipient_pub_path = super::age_recipient_public_path();
    std::fs::write(&recipient_pub_path, &recipient_str)?;
    set_file_mode_0600(&recipient_pub_path);

    // Add to .age-recipients (dedup).
    recipient_add(&recipient_str)?;

    eprintln!("age identity generated: {}", identity_path.display());
    eprintln!("age recipient (public key): {recipient_str}");
    eprintln!("Recipient added to .age-recipients");
    Ok(())
}

/// Entry point for `onecipher age recipient add <bech32>`.
///
/// Adds an age recipient string to `~/.onecipher/.age-recipients`.
#[allow(dead_code)]
pub(crate) fn recipient_add(bech32: &str) -> Result<(), CliError> {
    // Validate by parsing.
    let new_recipient: Recipient =
        bech32.parse().map_err(|e| CliError::InvalidArgs(format!("invalid recipient: {e}")))?;

    let path = super::age_recipients_path();
    let mut recipients = if path.exists() {
        RecipientsFile::load(&path)
            .map_err(|e| CliError::InvalidArgs(format!("failed to load recipients: {e}")))?
    } else {
        Vec::new()
    };

    // Dedup: skip if already present.
    let already_present = recipients.iter().any(|r| r.to_string() == new_recipient.to_string());
    if !already_present {
        recipients.push(new_recipient);
        RecipientsFile::save(&path, &recipients)
            .map_err(|e| CliError::InvalidArgs(format!("failed to save recipients: {e}")))?;
        set_file_mode_0600(&path);
    }

    println!("Recipient added: {bech32}");
    Ok(())
}

/// Entry point for `onecipher age recipient list`.
///
/// Lists all recipients in `~/.onecipher/.age-recipients`.
#[allow(dead_code)]
pub(crate) fn recipient_list() -> Result<(), CliError> {
    let path = super::age_recipients_path();
    if !path.exists() {
        println!("No recipients found.");
        return Ok(());
    }

    let recipients = RecipientsFile::load(&path)
        .map_err(|e| CliError::InvalidArgs(format!("failed to load recipients: {e}")))?;

    if recipients.is_empty() {
        println!("No recipients found.");
        return Ok(());
    }

    for (i, r) in recipients.iter().enumerate() {
        println!("{}: {r}", i + 1);
    }
    Ok(())
}

/// Entry point for `onecipher age recipient remove <bech32>`.
///
/// Removes an age recipient string from `~/.onecipher/.age-recipients`.
#[allow(dead_code)]
pub(crate) fn recipient_remove(bech32: &str) -> Result<(), CliError> {
    let path = super::age_recipients_path();
    if !path.exists() {
        return Err(CliError::InvalidArgs(format!("recipients file not found: {}", path.display())));
    }

    let mut recipients = RecipientsFile::load(&path)
        .map_err(|e| CliError::InvalidArgs(format!("failed to load recipients: {e}")))?;

    let original_len = recipients.len();
    recipients.retain(|r| r.to_string() != bech32);

    if recipients.len() == original_len {
        return Err(CliError::InvalidArgs(format!("recipient not found: '{bech32}'")));
    }

    RecipientsFile::save(&path, &recipients)
        .map_err(|e| CliError::InvalidArgs(format!("failed to save recipients: {e}")))?;
    set_file_mode_0600(&path);

    println!("Recipient removed: {bech32}");
    Ok(())
}

/// Entry point for `onecipher age identity show`.
///
/// Prints the public recipient string (age1...). The private identity is
/// NEVER displayed.
#[allow(dead_code)]
pub(crate) fn identity_show() -> Result<(), CliError> {
    let identity = super::load_age_identity()?;
    let recipient = identity.to_recipient_string();
    println!("{recipient}");
    Ok(())
}

/// Entry point for `onecipher age reencrypt`.
///
/// Re-encrypts all secret entries in the store with the current recipients
/// list. This is used after adding/removing recipients to ensure all entries
/// are encrypted to the updated recipient set.
#[allow(dead_code)]
pub(crate) fn reencrypt() -> Result<(), CliError> {
    let identity = super::load_age_identity()?;
    let recipients = super::load_recipients()?;
    if recipients.is_empty() {
        return Err(CliError::InvalidArgs(
            "no recipients found — run `onecipher age init` first".into(),
        ));
    }

    let store = super::open_secret_store()?;
    let entries = store.list().map_err(super::secret::map_store_error)?;

    let mut count = 0usize;
    for index_entry in &entries {
        let mut entry = store.get(&index_entry.name).map_err(super::secret::map_store_error)?;
        entry
            .re_encrypt(&identity, &recipients)
            .map_err(|e| CliError::InvalidArgs(format!("re-encryption failed: {e}")))?;
        store.put(&entry).map_err(super::secret::map_store_error)?;
        count += 1;
    }

    println!("Re-encrypted {count} secret(s) with {} recipient(s).", recipients.len());
    Ok(())
}

#[cfg(unix)]
fn set_dir_mode_0700(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700));
}

#[cfg(not(unix))]
fn set_dir_mode_0700(_path: &Path) {}

#[cfg(unix)]
fn set_file_mode_0600(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
}

#[cfg(not(unix))]
fn set_file_mode_0600(_path: &Path) {}
