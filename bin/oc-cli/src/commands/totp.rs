//! TOTP-specific CLI commands (`onecipher totp ...`).
//!
//! Stores TOTP seeds as encrypted secrets with `ItemType::Totp`. The
//! `secret` field of the `SecretPayload` holds the `otpauth://` URI.

use oc_core::{ItemType, SecretMetadata, SecretPayload};

use crate::CliError;

/// Entry point for `onecipher totp add <name> --otpauth <uri>` or
/// `onecipher totp add <name> --secret <base32> --issuer <issuer> --account <account>`.
///
/// Stores the otpauth URI as an encrypted secret. When `--secret` is provided
/// (instead of `--otpauth`), the URI is built from the raw base32 secret,
/// issuer, and account.
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
        // Try to extract issuer/account from the URI for the metadata index.
        let extracted = extract_issuer_account(uri);
        (uri.to_string(), extracted.0, extracted.1)
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

    let payload = SecretPayload { secret: otpauth_uri, notes: None, extra: None };

    let recipients = super::load_recipients()?;
    if recipients.is_empty() {
        return Err(CliError::InvalidArgs(
            "no recipients found — run `onecipher age init` first".into(),
        ));
    }

    let entry = oc_secret::SecretEntry::new(name, ItemType::Totp, &payload, metadata, &recipients)
        .map_err(|e| CliError::InvalidArgs(format!("failed to create entry: {e}")))?;

    let store = super::open_secret_store()?;
    store.put(&entry).map_err(super::secret::map_store_error)?;
    println!("TOTP added: {name}");
    Ok(())
}

/// Entry point for `onecipher totp generate <name> [--qr]`.
///
/// Decrypts the stored otpauth URI and generates the current TOTP code.
/// When `--qr` is set, the otpauth URI is displayed as a QR code.
#[allow(dead_code)]
pub(crate) fn generate(name: &str, qr: bool) -> Result<(), CliError> {
    let store = super::open_secret_store()?;
    let entry = store.get(name).map_err(super::secret::map_store_error)?;
    let identity = super::load_age_identity()?;
    let payload = entry
        .decrypt(&identity)
        .map_err(|e| CliError::InvalidArgs(format!("decryption failed: {e}")))?;

    let code = oc_secret::totp::generate_totp(&payload.secret)
        .map_err(|e| CliError::InvalidArgs(format!("TOTP generation failed: {e}")))?;

    if qr {
        return super::print_qr(&code);
    }

    println!("{code}");
    Ok(())
}

/// Entry point for `onecipher totp uris <name>`.
///
/// Decrypts and prints the stored otpauth URI.
#[allow(dead_code)]
pub(crate) fn uris(name: &str) -> Result<(), CliError> {
    let store = super::open_secret_store()?;
    let entry = store.get(name).map_err(super::secret::map_store_error)?;
    let identity = super::load_age_identity()?;
    let payload = entry
        .decrypt(&identity)
        .map_err(|e| CliError::InvalidArgs(format!("decryption failed: {e}")))?;

    println!("{}", payload.secret);
    Ok(())
}

/// Entry point for `onecipher totp hotp <name> --counter <n> [--increment]`.
///
/// Decrypts the stored otpauth URI and generates an HOTP code using the
/// given counter. When `--increment` is set, the counter stored in the
/// entry's `extra` field is bumped and re-encrypted.
#[allow(dead_code)]
pub(crate) fn hotp(name: &str, counter: u64, increment: bool) -> Result<(), CliError> {
    let store = super::open_secret_store()?;
    let entry = store.get(name).map_err(super::secret::map_store_error)?;
    let identity = super::load_age_identity()?;
    let payload = entry
        .decrypt(&identity)
        .map_err(|e| CliError::InvalidArgs(format!("decryption failed: {e}")))?;

    let code = oc_secret::totp::generate_hotp(&payload.secret, counter)
        .map_err(|e| CliError::InvalidArgs(format!("HOTP generation failed: {e}")))?;

    if increment {
        let mut extra =
            payload.extra.unwrap_or_else(|| serde_json::Value::Object(Default::default()));
        extra["hotp_counter"] = serde_json::json!(counter + 1);

        let updated_payload =
            SecretPayload { secret: payload.secret, notes: payload.notes, extra: Some(extra) };

        let recipients = super::load_recipients()?;
        if recipients.is_empty() {
            return Err(CliError::InvalidArgs(
                "no recipients found — run `onecipher age init` first".into(),
            ));
        }

        let updated_entry = oc_secret::SecretEntry::new(
            name,
            ItemType::Totp,
            &updated_payload,
            entry.metadata,
            &recipients,
        )
        .map_err(|e| CliError::InvalidArgs(format!("failed to re-encrypt entry: {e}")))?;

        store.put(&updated_entry).map_err(super::secret::map_store_error)?;
    }

    println!("{code}");
    Ok(())
}

/// Best-effort extraction of issuer and account from an otpauth URI.
///
/// The standard format is:
/// `otpauth://totp/<issuer>:<account>?secret=<base32>&issuer=<issuer>&...`
///
/// Returns `(Some(issuer), Some(account))` if both can be extracted,
/// otherwise returns what's available.
fn extract_issuer_account(uri: &str) -> (Option<String>, Option<String>) {
    // Parse the label portion between "otpauth://totp/" and "?".
    let label = uri
        .strip_prefix("otpauth://totp/")
        .or_else(|| uri.strip_prefix("otpauth://totp"))
        .and_then(|s| s.split('?').next())
        .unwrap_or("");

    let (issuer, account) = if let Some((iss, acc)) = label.split_once(':') {
        (Some(iss.to_string()), Some(acc.to_string()))
    } else if !label.is_empty() {
        (None, Some(label.to_string()))
    } else {
        (None, None)
    };

    // Also check the `issuer=` query parameter as a fallback.
    let issuer = issuer.or_else(|| {
        uri.split('?').nth(1).and_then(|query| {
            query.split('&').find_map(|kv| kv.strip_prefix("issuer=").map(|s| s.to_string()))
        })
    });

    (issuer, account)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_from_full_uri() {
        let uri = "otpauth://totp/TestIssuer:test@example.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=TestIssuer&digits=6&period=30";
        let (issuer, account) = extract_issuer_account(uri);
        assert_eq!(issuer.as_deref(), Some("TestIssuer"));
        assert_eq!(account.as_deref(), Some("test@example.com"));
    }

    #[test]
    fn extract_from_uri_without_label_issuer() {
        let uri = "otpauth://totp/test@example.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=QueryIssuer";
        let (issuer, account) = extract_issuer_account(uri);
        assert_eq!(issuer.as_deref(), Some("QueryIssuer"));
        assert_eq!(account.as_deref(), Some("test@example.com"));
    }
}
