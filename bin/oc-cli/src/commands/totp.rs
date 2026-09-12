//! TOTP-specific CLI commands (`onecipher totp ...`).
//!
//! Thin shortcuts over the unified secret plane ([`super::secret`] +
//! [`oc_secret::crud`]) that pre-fill `ItemType::Totp`. The `secret` field of
//! the `SecretPayload` holds the `otpauth://` URI. All OTP math — URI
//! building/parsing, TOTP/HOTP generation, short-seed handling (80/96-bit,
//! bare base32 defaults SHA-1 / 6 digits / 30s) and verification — lives in
//! [`oc_secret::totp`] (the library is the single source of truth); this
//! module only passes arguments through.

use oc_core::{AuditOp, SecretMetadata};

use crate::{CliError, audit};

/// Entry point for `onecipher totp add <name> --otpauth <uri>` or
/// `onecipher totp add <name> --secret <base32> --issuer <issuer> --account <account>`.
///
/// Stores the otpauth URI as an encrypted secret. When `--secret` is provided
/// (instead of `--otpauth`), the URI is built from the raw base32 secret,
/// issuer, and account. Bare base32 means SHA-1 / 6 digits / 30s period;
/// 80/96-bit short seeds are accepted by the library core.
#[allow(dead_code)]
pub(crate) fn add(
    name: &str,
    otpauth: Option<&str>,
    secret: Option<&str>,
    issuer: Option<&str>,
    account: Option<&str>,
) -> Result<(), CliError> {
    // Resolve the otpauth URI from either --otpauth or --secret + --issuer + --account.
    let (otpauth_uri, metadata_issuer, metadata_account) = if let Some(uri) = otpauth {
        // Extract issuer/account from the URI for the metadata index.
        let (issuer, account) = oc_secret::totp::extract_issuer_account(uri);
        (uri.to_string(), issuer, account)
    } else {
        let raw_secret = secret.ok_or_else(|| {
            CliError::InvalidArgs("either --otpauth or --secret is required".into())
        })?;
        let issuer_str = issuer.ok_or_else(|| {
            CliError::InvalidArgs("--issuer is required when using --secret".into())
        })?;
        let account_str = account.ok_or_else(|| {
            CliError::InvalidArgs("--account is required when using --secret".into())
        })?;
        let uri = oc_secret::totp::build_otpauth_uri(raw_secret, issuer_str, account_str)
            .map_err(|e| CliError::InvalidArgs(format!("failed to build otpauth URI: {e}")))?;
        (uri, Some(issuer_str.to_string()), Some(account_str.to_string()))
    };

    let metadata =
        SecretMetadata { issuer: metadata_issuer, account: metadata_account, ..Default::default() };

    // Funnel into page-locked memory at the single intake point.
    let hardened = oc_signer::SecretBytes::from_slice(otpauth_uri.as_bytes())
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
        oc_core::SecretKind::TotpSeed,
        name,
        &hardened,
        metadata,
        &recipients,
    )
    .map_err(super::secret::map_store_error)?;
    audit::log_secret_event(AuditOp::TotpAdd, name, None);
    println!("TOTP added: {name}");
    Ok(())
}

/// Entry point for `onecipher totp generate <name> [--qr] [--json]`.
///
/// Decrypts the stored otpauth URI and generates the current TOTP code
/// (bare emitter, suitable for `$(...)` capture).
/// When `--qr` is set, the code is displayed as a QR code.
/// When `--json` is set, the unified envelope `{"name","code"}` object is printed.
#[allow(dead_code)]
pub(crate) fn generate(name: &str, qr: bool, json: bool) -> Result<(), CliError> {
    let store = super::open_secret_store()?;
    let entry = store.get(name).map_err(super::secret::map_store_error)?;
    let identity = super::load_age_identity()?;
    let payload = entry
        .decrypt(&identity)
        .map_err(|e| CliError::InvalidArgs(format!("decryption failed: {e}")))?;

    let code = oc_secret::totp::generate_totp(payload.reveal_for_json())
        .map_err(|e| CliError::InvalidArgs(format!("TOTP generation failed: {e}")))?;

    audit::log_secret_event(AuditOp::TotpGenerate, name, None);
    if json {
        let json_str = serde_json::to_string_pretty(&serde_json::json!({
            "name": entry.name,
            "kind": oc_core::SecretKind::TotpSeed,
            "item_type": entry.item_type,
            "code": code,
        }))?;
        println!("{json_str}");
        return Ok(());
    }
    if qr {
        return super::print_qr(&code);
    }

    println!("{code}");
    Ok(())
}

/// Entry point for `onecipher totp uris <name> [--json]`.
///
/// Decrypts and prints the stored otpauth URI (bare emitter, suitable for
/// backup import into authenticator apps).
#[allow(dead_code)]
pub(crate) fn uris(name: &str, json: bool) -> Result<(), CliError> {
    let store = super::open_secret_store()?;
    let entry = store.get(name).map_err(super::secret::map_store_error)?;
    let identity = super::load_age_identity()?;
    let payload = entry
        .decrypt(&identity)
        .map_err(|e| CliError::InvalidArgs(format!("decryption failed: {e}")))?;

    audit::log_secret_event(AuditOp::TotpRevealUri, name, None);
    if json {
        let envelope = oc_secret::disclose_envelope(&entry, payload);
        super::secret::print_envelope_json(&envelope)?;
        return Ok(());
    }
    println!("{}", payload.reveal_for_json());
    Ok(())
}

/// Entry point for `onecipher totp hotp <name> --counter <n> [--increment] [--json]`.
///
/// Decrypts the stored otpauth URI and generates an HOTP code using the
/// given counter (bare emitter). When `--increment` is set, the counter
/// stored in the entry's `extra` field is bumped and re-encrypted.
#[allow(dead_code)]
pub(crate) fn hotp(name: &str, counter: u64, increment: bool, json: bool) -> Result<(), CliError> {
    let store = super::open_secret_store()?;
    let entry = store.get(name).map_err(super::secret::map_store_error)?;
    let identity = super::load_age_identity()?;
    let payload = entry
        .decrypt(&identity)
        .map_err(|e| CliError::InvalidArgs(format!("decryption failed: {e}")))?;

    let code = oc_secret::totp::generate_hotp(payload.reveal_for_json(), counter)
        .map_err(|e| CliError::InvalidArgs(format!("HOTP generation failed: {e}")))?;

    if increment {
        let mut extra =
            payload.extra.clone().unwrap_or_else(|| serde_json::Value::Object(Default::default()));
        extra["hotp_counter"] = serde_json::json!(counter + 1);

        let updated_payload = oc_core::SecretPayload {
            secret: payload.reveal_for_json().to_string(),
            notes: payload.notes.clone(),
            extra: Some(extra),
        };

        let recipients = super::load_recipients()?;
        if recipients.is_empty() {
            return Err(CliError::InvalidArgs(
                "no recipients found — run `onecipher age init` first".into(),
            ));
        }

        let next_gen = store.next_generation(name).map_err(super::secret::map_store_error)?;
        let updated_entry = oc_secret::SecretEntry::new(
            name,
            oc_core::ItemType::Totp,
            &updated_payload,
            entry.metadata,
            &recipients,
            next_gen,
        )
        .map_err(|e| CliError::InvalidArgs(format!("failed to re-encrypt entry: {e}")))?;

        store.put(&updated_entry).map_err(super::secret::map_store_error)?;
    }

    audit::log_secret_event(AuditOp::HotpGenerate, name, None);
    if json {
        let json_str = serde_json::to_string_pretty(&serde_json::json!({
            "name": entry.name,
            "kind": oc_core::SecretKind::TotpSeed,
            "item_type": entry.item_type,
            "counter": counter,
            "code": code,
        }))?;
        println!("{json_str}");
        return Ok(());
    }
    println!("{code}");
    Ok(())
}
