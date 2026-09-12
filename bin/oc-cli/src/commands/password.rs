//! Password-specific CLI commands (`onecipher password ...`).
//!
//! Thin shortcuts over the unified secret plane ([`super::secret`] +
//! [`oc_secret::crud`]) that pre-fill `ItemType::Password`. Generation and
//! strength policy live in [`oc_secret::password`] (the library is the single
//! source of truth); this module only passes arguments through.

use oc_core::{AuditOp, SecretMetadata};

use crate::{CliError, audit};

/// Entry point for `onecipher password add <name> --url <url> --username <user>
/// [--generate] [--length 32] [--symbols]`.
///
/// When `--generate` is set, a random password is generated via the shared
/// library generator and stored. Otherwise, the password is read from
/// `ONECIPHER_SECRET` env var or an interactive prompt.
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
        oc_secret::generate_password(length, symbols)
    } else {
        zeroize::Zeroizing::new(super::read_secret_from_env_or_prompt()?)
    };

    let metadata = SecretMetadata {
        url: Some(url.to_string()),
        username: Some(username.to_string()),
        ..Default::default()
    };

    // Funnel into page-locked memory at the single intake point; `crud`
    // performs the only String conversion at the serde boundary.
    let hardened = oc_signer::SecretBytes::from_slice(secret.as_bytes())
        .map_err(|e| CliError::InvalidArgs(format!("memory hardening failed: {e}")))?;
    let recipients = super::load_recipients()?;
    if recipients.is_empty() {
        return Err(CliError::InvalidArgs(
            "no recipients found — run `onecipher age init` first".into(),
        ));
    }

    let store = super::open_secret_store()?;
    oc_secret::create_entry(
        &store,
        oc_core::SecretKind::Password,
        name,
        &hardened,
        metadata,
        &recipients,
    )
    .map_err(super::secret::map_store_error)?;
    audit::log_secret_event(AuditOp::PasswordAdd, name, None);
    println!("Password added: {name}");
    Ok(())
}

/// Entry point for `onecipher password get <name> [--copy] [--timeout 45] [--json]`.
///
/// Decrypts and prints the password. When `--copy` is set, the password is
/// copied to the system clipboard and auto-cleared after `timeout` seconds.
/// A `timeout` of 0 disables auto-clear. When `--json` is set, the unified
/// [`oc_core::SecretEnvelope`] is printed instead.
#[allow(dead_code)]
pub(crate) fn get(name: &str, copy: bool, timeout: u64, json: bool) -> Result<(), CliError> {
    let store = super::open_secret_store()?;
    let entry = store.get(name).map_err(super::secret::map_store_error)?;
    let identity = super::load_age_identity()?;
    let payload = entry
        .decrypt(&identity)
        .map_err(|e| CliError::InvalidArgs(format!("decryption failed: {e}")))?;

    if json {
        let envelope = oc_secret::disclose_envelope(&entry, payload);
        super::secret::print_envelope_json(&envelope)?;
        audit::log_secret_event(AuditOp::PasswordRead, name, None);
        return Ok(());
    }

    if copy {
        super::clipboard::copy_and_clear(payload.reveal_for_json(), timeout)?;
    } else {
        // Explicit disclosure: shared labeled view with `secret get`.
        print!("{}", super::secret::render_disclosure(&entry.name, entry.item_type, &payload));
    }

    audit::log_secret_event(AuditOp::PasswordRead, name, None);
    Ok(())
}

/// Entry point for `onecipher password generate [--length 32] [--symbols] [--qr]`.
///
/// Generates a random password via the shared library generator and prints
/// it to stdout (bare emitter, suitable for `$(...)` capture).
/// When `--qr` is set, the password is displayed as a QR code in the terminal.
///
/// Supports three generator strategies (see [`oc_secret::password`]):
/// - `cryptic`: random characters (default)
/// - `memorable`: word+digit+word+symbol pattern
/// - `xkcd`: XKCD-style passphrase (correct-horse-battery-staple)
#[allow(dead_code)]
pub(crate) fn generate(
    length: usize,
    symbols: bool,
    generator: &str,
    xkcd_sep: &str,
    xkcd_words: usize,
    qr: bool,
) -> Result<(), CliError> {
    let strategy = oc_secret::PasswordGenerator::parse(generator).ok_or_else(|| {
        CliError::InvalidArgs(format!(
            "unknown generator '{generator}'; expected: cryptic, memorable, xkcd"
        ))
    })?;
    let opts = oc_secret::PasswordOptions {
        length,
        symbols,
        generator: strategy,
        xkcd_sep: xkcd_sep.to_string(),
        xkcd_words,
    };
    let password = oc_secret::generate(&opts).map_err(|e| CliError::InvalidArgs(e.to_string()))?;
    audit::log_secret_event(AuditOp::PasswordGenerate, "-", None);
    if qr {
        return super::print_qr(&password);
    }
    println!("{}", password.as_str());
    Ok(())
}
