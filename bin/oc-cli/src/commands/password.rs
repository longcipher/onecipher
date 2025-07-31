//! Password-specific CLI commands (`onecipher password ...`).
//!
//! Convenience wrappers around [`super::secret`] that pre-fill `ItemType::Password`
//! and handle password generation + clipboard copy.

use oc_core::{ItemType, SecretMetadata, SecretPayload};

use crate::CliError;

/// Clipboard auto-clear delay (seconds).
const CLIPBOARD_CLEAR_DELAY_SECS: u64 = 40;

/// Default generated password length.
#[allow(dead_code)]
const DEFAULT_PASSWORD_LENGTH: usize = 32;

/// Entry point for `onecipher password add <name> --url <url> --username <user>
/// [--generate] [--length 32] [--symbols]`.
///
/// When `--generate` is set, a random password is generated and stored.
/// Otherwise, the password is read from `ONECIPHER_SECRET` env var or an
/// interactive prompt.
#[allow(dead_code)]
pub(crate) fn add(
    name: &str,
    url: &str,
    username: &str,
    generate: bool,
    length: usize,
    symbols: bool,
) -> Result<(), CliError> {
    let secret = if generate {
        generate_password(length, symbols)
    } else {
        super::read_secret_from_env_or_prompt()?
    };

    let metadata = SecretMetadata {
        url: Some(url.to_string()),
        username: Some(username.to_string()),
        ..Default::default()
    };

    let payload = SecretPayload { secret, notes: None, extra: None };
    let recipients = super::load_recipients()?;
    if recipients.is_empty() {
        return Err(CliError::InvalidArgs(
            "no recipients found — run `onecipher age init` first".into(),
        ));
    }

    let entry =
        oc_secret::SecretEntry::new(name, ItemType::Password, &payload, metadata, &recipients)
            .map_err(|e| CliError::InvalidArgs(format!("failed to create entry: {e}")))?;

    let store = super::open_secret_store()?;
    store.put(&entry).map_err(super::secret::map_store_error)?;
    println!("Password added: {name}");
    Ok(())
}

/// Entry point for `onecipher password get <name> [--copy]`.
///
/// Decrypts and prints the password. When `--copy` is set, the password is
/// copied to the system clipboard and auto-cleared after 40 seconds.
#[allow(dead_code)]
pub(crate) fn get(name: &str, copy: bool) -> Result<(), CliError> {
    let store = super::open_secret_store()?;
    let entry = store.get(name).map_err(super::secret::map_store_error)?;
    let identity = super::load_age_identity()?;
    let payload = entry
        .decrypt(&identity)
        .map_err(|e| CliError::InvalidArgs(format!("decryption failed: {e}")))?;

    if copy {
        let mut clipboard = arboard::Clipboard::new()
            .map_err(|e| CliError::InvalidArgs(format!("clipboard error: {e}")))?;
        clipboard
            .set_text(&payload.secret)
            .map_err(|e| CliError::InvalidArgs(format!("clipboard error: {e}")))?;
        eprintln!("Password copied to clipboard (will clear in {CLIPBOARD_CLEAR_DELAY_SECS}s)");
        eprintln!("Press Ctrl+C to exit without waiting.");
        std::thread::sleep(std::time::Duration::from_secs(CLIPBOARD_CLEAR_DELAY_SECS));
        let _ = clipboard.clear();
        eprintln!("Clipboard cleared.");
    } else {
        println!("{}", payload.secret);
    }

    Ok(())
}

/// Entry point for `onecipher password generate [--length 32] [--symbols]`.
///
/// Generates a random password and prints it to stdout.
#[allow(dead_code)]
pub(crate) fn generate(length: usize, symbols: bool) -> Result<(), CliError> {
    let password = generate_password(length, symbols);
    println!("{password}");
    Ok(())
}

/// Generate a random password.
///
/// When `symbols` is true, uses ASCII printable characters 33-126 (includes
/// letters, digits, and symbols). When false, uses only alphanumeric
/// characters (a-z, A-Z, 0-9).
fn generate_password(length: usize, symbols: bool) -> String {
    let charset: Vec<u8> = if symbols {
        (33u8..=126).collect()
    } else {
        let mut chars: Vec<u8> = (b'a'..=b'z').collect();
        chars.extend(b'A'..=b'Z');
        chars.extend(b'0'..=b'9');
        chars
    };

    (0..length)
        .map(|_| {
            let idx = rand::random_range(0..charset.len());
            charset[idx] as char
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_password_has_correct_length() {
        let pw = generate_password(20, false);
        assert_eq!(pw.len(), 20);
    }

    #[test]
    fn generated_password_alphanumeric_only() {
        let pw = generate_password(100, false);
        assert!(pw.chars().all(|c| c.is_ascii_alphanumeric()));
    }

    #[test]
    fn generated_password_with_symbols_has_printable_chars() {
        let pw = generate_password(100, true);
        assert!(pw.chars().all(|c| c.is_ascii_graphic()));
    }

    #[test]
    fn default_password_length_is_32() {
        assert_eq!(DEFAULT_PASSWORD_LENGTH, 32);
    }
}
