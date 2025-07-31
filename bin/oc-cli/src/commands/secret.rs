//! Generic secret management CLI commands (`onecipher secret ...`).
//!
//! Provides list / get / add / update / delete / rename operations over the
//! age-encrypted [`SecretStore`]. All sensitive material flows through the
//! shared helpers in [`super`], which read from stdin or env vars and never
//! echo secrets to stderr.

use oc_core::{ItemType, SecretPayload};
use oc_secret::SecretStoreError;

use crate::CliError;

/// Entry point for `onecipher secret list [--type <ItemType>] [--json]`.
///
/// Lists all entries in the secret store. When `--type` is provided, only
/// entries of that type are shown. When `--json` is set, a JSON array of
/// `SecretIndexEntry` objects is printed to stdout (no extra text).
#[allow(dead_code)]
pub(crate) fn list(item_type: Option<ItemType>, json: bool) -> Result<(), CliError> {
    let store = super::open_secret_store()?;
    let mut entries = store.list().map_err(map_store_error)?;

    if let Some(filter_type) = item_type {
        entries.retain(|e| e.item_type == filter_type);
    }

    if json {
        let json_str = serde_json::to_string_pretty(&entries)?;
        println!("{json_str}");
        return Ok(());
    }

    if entries.is_empty() {
        println!("No secrets found.");
        return Ok(());
    }

    for e in &entries {
        println!("Name:      {}", e.name);
        println!("Type:      {}", e.item_type);
        println!("ID:        {}", e.id);
        println!("Created:   {}", e.created_at);
        println!("Updated:   {}", e.updated_at);
        if let Some(url) = &e.metadata.url {
            println!("URL:       {url}");
        }
        if let Some(user) = &e.metadata.username {
            println!("Username:  {user}");
        }
        if let Some(issuer) = &e.metadata.issuer {
            println!("Issuer:    {issuer}");
        }
        if let Some(account) = &e.metadata.account {
            println!("Account:   {account}");
        }
        if !e.metadata.tags.is_empty() {
            println!("Tags:      {}", e.metadata.tags.join(", "));
        }
        println!();
    }

    Ok(())
}

/// Entry point for `onecipher secret get <name> [--field secret|notes|metadata] [--json]`.
///
/// Decrypts and prints the secret. When `--field` is specified, only that
/// field is printed. When `--json` is set, the full `SecretPayload` (plus
/// metadata) is printed as a JSON object.
#[allow(dead_code)]
pub(crate) fn get(name: &str, field: Option<&str>, json: bool) -> Result<(), CliError> {
    let store = super::open_secret_store()?;
    let entry = store.get(name).map_err(map_store_error)?;
    let identity = super::load_age_identity()?;
    let payload = entry
        .decrypt(&identity)
        .map_err(|e| CliError::InvalidArgs(format!("decryption failed: {e}")))?;

    if json {
        let json_obj = serde_json::json!({
            "name": entry.name,
            "id": entry.id,
            "item_type": entry.item_type,
            "metadata": entry.metadata,
            "payload": payload,
        });
        let json_str = serde_json::to_string_pretty(&json_obj)?;
        println!("{json_str}");
        return Ok(());
    }

    match field {
        Some("secret") => println!("{}", payload.secret),
        Some("notes") => match &payload.notes {
            Some(n) => println!("{n}"),
            None => println!(),
        },
        Some("metadata") => {
            let json_str = serde_json::to_string_pretty(&entry.metadata)?;
            println!("{json_str}");
        }
        Some(other) => {
            return Err(CliError::InvalidArgs(format!(
                "unknown field '{other}' (expected: secret, notes, metadata)"
            )));
        }
        None => {
            println!("Name:      {}", entry.name);
            println!("Type:      {}", entry.item_type);
            println!("Secret:    {}", payload.secret);
            if let Some(notes) = &payload.notes {
                println!("Notes:     {notes}");
            }
            if let Some(extra) = &payload.extra {
                let extra_str = serde_json::to_string_pretty(extra)?;
                println!("Extra:     {extra_str}");
            }
        }
    }

    Ok(())
}

/// Entry point for `onecipher secret add <name> --type <ItemType> [--meta key=val...] [--stdin]`.
///
/// Creates a new secret entry. When `--stdin` is set, the full
/// `SecretPayload` JSON is read from stdin. Otherwise, the secret value is
/// read from `ONECIPHER_SECRET` env var or an interactive prompt.
#[allow(dead_code)]
pub(crate) fn add(
    name: &str,
    item_type: ItemType,
    meta: &[String],
    stdin: bool,
) -> Result<(), CliError> {
    let store = super::open_secret_store()?;
    let metadata = super::parse_metadata(meta)?;

    let payload = if stdin {
        super::read_secret_payload_from_stdin()?
    } else {
        let secret = super::read_secret_from_env_or_prompt()?;
        SecretPayload { secret, notes: None, extra: None }
    };

    let recipients = super::load_recipients()?;
    if recipients.is_empty() {
        return Err(CliError::InvalidArgs(
            "no recipients found — run `onecipher age init` first".into(),
        ));
    }

    let entry = oc_secret::SecretEntry::new(name, item_type, &payload, metadata, &recipients)
        .map_err(|e| CliError::InvalidArgs(format!("failed to create entry: {e}")))?;

    store.put(&entry).map_err(map_store_error)?;
    println!("Secret added: {name}");
    Ok(())
}

/// Entry point for `onecipher secret update <name> [--field <...>] [--stdin]`.
///
/// Updates an existing secret entry. When `--stdin` is set, the full
/// `SecretPayload` JSON is read from stdin and replaces the existing payload.
/// When `--field secret` is set, only the secret field is updated (from env
/// or prompt). When `--field notes` is set, the notes field is updated.
#[allow(dead_code)]
#[allow(clippy::useless_let_if_seq)]
pub(crate) fn update(name: &str, field: Option<&str>, stdin: bool) -> Result<(), CliError> {
    let store = super::open_secret_store()?;
    let mut entry = store.get(name).map_err(map_store_error)?;
    let identity = super::load_age_identity()?;
    let mut payload = entry
        .decrypt(&identity)
        .map_err(|e| CliError::InvalidArgs(format!("decryption failed: {e}")))?;

    if stdin {
        let new_payload = super::read_secret_payload_from_stdin()?;
        payload = new_payload;
    } else {
        match field {
            Some("secret") | None => {
                let secret = super::read_secret_from_env_or_prompt()?;
                payload.secret = secret;
            }
            Some("notes") => {
                let notes = super::read_secret_from_env_or_prompt()?;
                if notes.is_empty() {
                    payload.notes = None;
                } else {
                    payload.notes = Some(notes);
                }
            }
            Some(other) => {
                return Err(CliError::InvalidArgs(format!(
                    "unknown field '{other}' (expected: secret, notes)"
                )));
            }
        }
    }

    let recipients = super::load_recipients()?;
    if recipients.is_empty() {
        return Err(CliError::InvalidArgs(
            "no recipients found — run `onecipher age init` first".into(),
        ));
    }

    // Re-encrypt the updated payload.
    let json = serde_json::to_vec(&payload)?;
    let ciphertext = oc_secret::encrypt_payload(&json, &recipients)
        .map_err(|e| CliError::InvalidArgs(format!("encryption failed: {e}")))?;
    entry.ciphertext = ciphertext;
    entry.updated_at = jiff::Timestamp::now().to_string();

    store.put(&entry).map_err(map_store_error)?;
    println!("Secret updated: {name}");
    Ok(())
}

/// Entry point for `onecipher secret delete <name>`.
#[allow(dead_code)]
pub(crate) fn delete(name: &str) -> Result<(), CliError> {
    let store = super::open_secret_store()?;
    store.delete(name).map_err(map_store_error)?;
    println!("Secret deleted: {name}");
    Ok(())
}

/// Entry point for `onecipher secret rename <old> <new>`.
#[allow(dead_code)]
pub(crate) fn rename(old: &str, new: &str) -> Result<(), CliError> {
    let store = super::open_secret_store()?;
    store.rename(old, new).map_err(map_store_error)?;
    println!("Secret renamed: '{old}' -> '{new}'");
    Ok(())
}

/// Convert a [`SecretStoreError`] into a [`CliError`].
pub(super) fn map_store_error(e: SecretStoreError) -> CliError {
    match e {
        SecretStoreError::NotFound(name) => {
            CliError::InvalidArgs(format!("secret not found: '{name}'"))
        }
        SecretStoreError::AlreadyExists(name) => {
            CliError::InvalidArgs(format!("secret already exists: '{name}'"))
        }
        SecretStoreError::InvalidName(msg) => CliError::InvalidArgs(msg),
        SecretStoreError::Io(e) => CliError::Io(e),
        SecretStoreError::Serde(e) => CliError::Json(e),
        SecretStoreError::Entry(e) => CliError::InvalidArgs(e.to_string()),
    }
}
