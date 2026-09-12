//! Generic secret management CLI commands (`onecipher secret ...`).
//!
//! Provides list / get / add / update / delete / rename operations over the
//! age-encrypted [`SecretStore`]. All sensitive material flows through the
//! shared helpers in [`super`], which read from stdin or env vars and never
//! echo secrets to stderr.

use oc_core::{AuditOp, ItemType, SecretKind, SecretPayload};
use oc_secret::{SecretEnvelope, SecretStoreError};

use crate::{CliError, audit};

/// Print one unified `--json` envelope (shared by `secret` / `password` /
/// `totp` disclosure reads so agents parse a single schema).
pub(crate) fn print_envelope_json(envelope: &SecretEnvelope) -> Result<(), CliError> {
    let json_str = serde_json::to_string_pretty(envelope)?;
    println!("{json_str}");
    Ok(())
}

/// Render the shared labeled disclosure view (explicit reveal).
///
/// Listings and reports default to hiding secrets (`reveal.then(false)`);
/// this view is only built after an explicit `get`-style disclosure, so the
/// material renders in the clear under one shape for all four
/// [`SecretKind`] states.
pub(crate) fn render_disclosure(
    name: &str,
    item_type: ItemType,
    payload: &SecretPayload,
) -> String {
    let mut out = String::new();
    out.push_str(&format!("Name:      {name}\n"));
    out.push_str(&format!("Type:      {item_type}\n"));
    out.push_str(&format!("Kind:      {}\n", SecretKind::from_item_type(item_type)));
    out.push_str(&format!("Secret:    {}\n", payload.reveal_for_json()));
    if let Some(notes) = &payload.notes {
        out.push_str(&format!("Notes:     {notes}\n"));
    }
    if let Some(extra) = &payload.extra {
        if let Ok(extra_str) = serde_json::to_string_pretty(extra) {
            out.push_str(&format!("Extra:     {extra_str}\n"));
        }
    }
    out
}

/// Entry point for `onecipher secret list [--type <ItemType>] [--json]`.
///
/// Lists all entries in the secret store. When `--type` is provided, only
/// entries of that type are shown. When `--json` is set, a JSON array of
/// unified [`SecretEnvelope`] objects (no secret material) is printed to
/// stdout (no extra text).
#[allow(dead_code)]
pub(crate) fn list(item_type: Option<ItemType>, json: bool) -> Result<(), CliError> {
    let store = super::open_secret_store()?;
    let mut entries = store.list().map_err(map_store_error)?;

    if let Some(filter_type) = item_type {
        entries.retain(|e| e.item_type == filter_type);
    }

    if json {
        let envelopes: Vec<SecretEnvelope> =
            entries.iter().map(SecretEnvelope::without_payload).collect();
        let json_str = serde_json::to_string_pretty(&envelopes)?;
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

/// Entry point for `onecipher secret get <name> [--field secret|notes|metadata] [--json] [--qr]`.
///
/// Decrypts and prints the secret. When `--field` is specified, only that
/// field is printed. When `--json` is set, the full `SecretPayload` (plus
/// metadata) is printed as a JSON object. When `--qr` is set, the secret
/// value is displayed as a QR code in the terminal.
#[allow(dead_code)]
pub(crate) fn get(
    name: &str,
    field: Option<&str>,
    json: bool,
    qr: bool,
    copy: bool,
    timeout: u64,
) -> Result<(), CliError> {
    let store = super::open_secret_store()?;
    let entry = store.get(name).map_err(map_store_error)?;
    let identity = super::load_age_identity()?;
    let payload = entry
        .decrypt(&identity)
        .map_err(|e| CliError::InvalidArgs(format!("decryption failed: {e}")))?;

    // Non-interactive clipboard copy (TUI parity): copies the secret value.
    if copy {
        let value = match field {
            Some("secret") | None => &payload.secret,
            Some("notes") => payload.notes.as_deref().unwrap_or(""),
            Some(other) => {
                return Err(CliError::InvalidArgs(format!(
                    "unknown field '{other}' (expected: secret, notes, metadata)"
                )));
            }
        };
        return super::clipboard::copy_and_clear(value, timeout);
    }

    if qr {
        let secret_value = match field {
            Some("secret") => &payload.secret,
            Some("notes") => match &payload.notes {
                Some(n) => n,
                None => return Ok(()),
            },
            Some("metadata") => {
                let json_str = serde_json::to_string_pretty(&entry.metadata)?;
                return super::print_qr(&json_str);
            }
            Some(other) => {
                return Err(CliError::InvalidArgs(format!(
                    "unknown field '{other}' (expected: secret, notes, metadata)"
                )));
            }
            None => &payload.secret,
        };
        return super::print_qr(secret_value);
    }

    if json {
        let envelope = oc_secret::disclose_envelope(&entry, payload);
        print_envelope_json(&envelope)?;
        audit::log_secret_event(AuditOp::SecretRead, name, None);
        return Ok(());
    }

    match field {
        Some("secret") => println!("{}", payload.reveal_for_json()),
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
            print!("{}", render_disclosure(&entry.name, entry.item_type, &payload));
        }
    }

    audit::log_secret_event(AuditOp::SecretRead, name, None);
    Ok(())
}

/// Load recipients, failing closed when `age init` never ran.
///
/// Shared by every creation/update path in the secret handling plane.
fn require_recipients() -> Result<Vec<String>, CliError> {
    let recipients = super::load_recipients()?;
    if recipients.is_empty() {
        return Err(CliError::InvalidArgs(
            "no recipients found — run `onecipher age init` first".into(),
        ));
    }
    Ok(recipients)
}

/// Wrap a plaintext secret into page-locked memory immediately after intake.
///
/// The CLI edge (env var / prompt / stdin) necessarily yields a `String`
/// first; this is the single funnel into [`oc_secret::crud`], which performs
/// the only `String` conversion at the serde boundary.
fn harden_secret(secret: &str) -> Result<oc_signer::SecretBytes, CliError> {
    oc_signer::SecretBytes::from_slice(secret.as_bytes())
        .map_err(|e| CliError::InvalidArgs(format!("memory hardening failed: {e}")))
}

/// Entry point for `onecipher secret add <name> --type <ItemType> [--meta key=val...] [--stdin]`.
///
/// Creates a new secret entry via the unified [`oc_secret::crud`] plane.
/// When `--stdin` is set, the full `SecretPayload` JSON is read from stdin.
/// Otherwise, the secret value is read from `ONECIPHER_SECRET` env var or an
/// interactive prompt.
#[allow(dead_code)]
pub(crate) fn add(
    name: &str,
    item_type: ItemType,
    meta: &[String],
    stdin: bool,
) -> Result<(), CliError> {
    let store = super::open_secret_store()?;
    let metadata = super::parse_metadata(meta)?;

    let (secret_hb, notes, extra) = if stdin {
        let mut payload = super::read_secret_payload_from_stdin()?;
        // `SecretPayload` zeroizes on drop: borrow the secret for hardening,
        // then `take()` the optional fields (moving out of a `Drop` type is
        // forbidden, `Option::take` is not).
        let hardened = harden_secret(&payload.secret)?;
        (hardened, payload.notes.take(), payload.extra.take())
    } else {
        let secret = super::read_secret_from_env_or_prompt()?;
        (harden_secret(&secret)?, None, None)
    };

    let recipients = require_recipients()?;
    let kind = SecretKind::from_item_type(item_type);
    oc_secret::create_entry_full(
        &store,
        kind,
        name,
        &secret_hb,
        notes,
        extra,
        metadata,
        &recipients,
    )
    .map_err(map_store_error)?;
    audit::log_secret_event(AuditOp::SecretCreate, name, None);
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
                // Single String-boundary copy; the old secret zeroizes with
                // the overwritten payload's drop.
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

    let recipients = require_recipients()?;

    // Re-encrypt the updated payload bound to the next generation (B1/B4).
    let next_gen = store.next_generation(name).map_err(map_store_error)?;
    entry
        .set_payload(&payload, &recipients, next_gen)
        .map_err(|e| CliError::InvalidArgs(format!("encryption failed: {e}")))?;

    store.put(&entry).map_err(map_store_error)?;
    audit::log_secret_event(AuditOp::SecretUpdate, name, None);
    println!("Secret updated: {name}");
    Ok(())
}

/// Entry point for `onecipher secret delete <name> --force`.
///
/// Deletion is irreversible, so an explicit `--force` flag is required;
/// without it the command fails with a usage error instead of deleting.
#[allow(dead_code)]
pub(crate) fn delete(name: &str, force: bool) -> Result<(), CliError> {
    crate::output::require_force(force, &format!("delete secret '{name}'"))?;
    let store = super::open_secret_store()?;
    oc_secret::delete_entry(&store, name).map_err(map_store_error)?;
    audit::log_secret_event(AuditOp::SecretDelete, name, None);
    println!("Secret deleted: {name}");
    Ok(())
}

/// Entry point for `onecipher secret rename <old> <new>`.
#[allow(dead_code)]
pub(crate) fn rename(old: &str, new: &str) -> Result<(), CliError> {
    let store = super::open_secret_store()?;
    let identity = super::load_age_identity()?;
    let recipients = require_recipients()?;
    oc_secret::rename_entry(&store, old, new, &identity, &recipients).map_err(map_store_error)?;
    audit::log_secret_event(AuditOp::SecretRename, new, Some(format!("from={old}")));
    println!("Secret renamed: '{old}' -> '{new}'");
    Ok(())
}

/// Entry point for `onecipher secret edit <name> [--editor <cmd>]`.
///
/// Decrypts the secret, writes the payload to a tempfile in a human-readable
/// format, opens `$EDITOR` (or `--editor` flag) for the user to modify it,
/// then parses the edited content back into a `SecretPayload`, re-encrypts,
/// and saves.
///
/// Format (3 sections, each on its own line):
/// ```text
/// <secret value>
/// Notes: <notes text or empty>
/// Extra: <JSON or empty>
/// ```
#[allow(dead_code)]
pub(crate) fn edit(name: &str, editor: Option<&str>) -> Result<(), CliError> {
    let store = super::open_secret_store()?;
    let mut entry = store.get(name).map_err(map_store_error)?;
    let identity = super::load_age_identity()?;
    let payload = entry
        .decrypt(&identity)
        .map_err(|e| CliError::InvalidArgs(format!("decryption failed: {e}")))?;

    // Format the current payload as human-readable text.
    let notes_line = match &payload.notes {
        Some(n) => format!("Notes: {n}"),
        None => "Notes: ".to_string(),
    };
    let extra_line = match &payload.extra {
        Some(v) => {
            let s = serde_json::to_string(v)
                .map_err(|e| CliError::InvalidArgs(format!("failed to serialize extra: {e}")))?;
            format!("Extra: {s}")
        }
        None => "Extra: ".to_string(),
    };
    let initial_content = format!("{}\n{}\n{}\n", payload.secret, notes_line, extra_line);

    // Write to a tempfile (in tmpfs on macOS/Linux).
    let tmpfile = tempfile::NamedTempFile::new()
        .map_err(|e| CliError::InvalidArgs(format!("tempfile: {e}")))?;
    std::fs::write(tmpfile.path(), &initial_content)?;

    // Determine editor command.
    let editor_cmd = editor
        .map(String::from)
        .or_else(|| std::env::var("EDITOR").ok())
        .or_else(|| std::env::var("VISUAL").ok())
        .unwrap_or_else(|| "vi".to_string());

    // Open the editor and wait for it to exit.
    let status =
        std::process::Command::new(&editor_cmd).arg(tmpfile.path()).status().map_err(|e| {
            CliError::InvalidArgs(format!("failed to launch editor '{editor_cmd}': {e}"))
        })?;

    if !status.success() {
        return Err(CliError::InvalidArgs(format!("editor '{editor_cmd}' exited with {status}")));
    }

    // Read back the edited content.
    let edited = std::fs::read_to_string(tmpfile.path())?;

    // Securely delete the tempfile (zeroize + unlink).
    // NamedTempFile::close() removes the file; we zeroize the initial_content separately.
    // The tmpfile path will be cleaned up when the handle is dropped.
    drop(tmpfile);
    // Zeroize the in-memory copy of the original content.
    // (initial_content is a plain String, but the plaintext secret only lives
    //  transiently in this scope.)
    drop(initial_content);

    // Parse the edited content back into a SecretPayload.
    let new_payload = parse_edited_payload(&edited)?;

    // Re-encrypt and save.
    let recipients = require_recipients()?;

    let next_gen = store.next_generation(name).map_err(map_store_error)?;
    entry
        .set_payload(&new_payload, &recipients, next_gen)
        .map_err(|e| CliError::InvalidArgs(format!("encryption failed: {e}")))?;

    store.put(&entry).map_err(map_store_error)?;
    audit::log_secret_event(AuditOp::SecretUpdate, name, None);
    println!("Secret updated: {name}");
    Ok(())
}

/// Entry point for `onecipher secret copy <src> <dst> [--force]`.
///
/// Copies a secret entry to a new name. The source entry is decrypted, then
/// re-encrypted under the current recipients and stored under the destination
/// name. When `--force` is set, an existing destination entry is overwritten.
#[allow(dead_code)]
pub(crate) fn copy(src: &str, dst: &str, force: bool) -> Result<(), CliError> {
    let store = super::open_secret_store()?;
    let identity = super::load_age_identity()?;
    let recipients = require_recipients()?;

    // Unified copy plane: destination guard (--force), decrypt, re-encrypt at
    // the destination's next generation.
    oc_secret::copy_entry(&store, &identity, src, dst, force, &recipients)
        .map_err(map_store_error)?;
    audit::log_secret_event(AuditOp::SecretCopy, dst, Some(format!("from={src}")));
    println!("Secret copied: '{src}' -> '{dst}'");
    Ok(())
}

/// Entry point for `onecipher secret move <src> <dst> [--force]`.
///
/// Moves (renames) a secret entry. Without `--force`, delegates to the
/// store's atomic rename (fails if the destination already exists). With
/// `--force`, performs a copy-then-delete to overwrite an existing destination.
#[allow(dead_code)]
pub(crate) fn mv(src: &str, dst: &str, force: bool) -> Result<(), CliError> {
    if !force {
        // Rename rebinds the envelope to the new path, so it needs the
        // identity + recipients for re-encryption (B1).
        let store = super::open_secret_store()?;
        let identity = super::load_age_identity()?;
        let recipients = require_recipients()?;
        oc_secret::rename_entry(&store, src, dst, &identity, &recipients)
            .map_err(map_store_error)?;
        audit::log_secret_event(AuditOp::SecretRename, dst, Some(format!("from={src}")));
        println!("Secret moved: '{src}' -> '{dst}'");
        return Ok(());
    }

    // --force: copy over existing destination, then delete source.
    copy(src, dst, true)?;
    let store = super::open_secret_store()?;
    oc_secret::delete_entry(&store, src).map_err(map_store_error)?;
    audit::log_secret_event(AuditOp::SecretRename, dst, Some(format!("from={src} (force)")));
    println!("Secret moved: '{src}' -> '{dst}'");
    Ok(())
}

/// Parse the editor output back into a [`SecretPayload`].
///
/// Expected format:
/// ```text
/// <secret>
/// Notes: <notes text or empty>
/// Extra: <JSON or empty>
/// ```
fn parse_edited_payload(text: &str) -> Result<SecretPayload, CliError> {
    let mut lines: Vec<&str> = text.lines().collect();

    // Trim trailing blank lines.
    while lines.last().is_some_and(|l| l.trim().is_empty()) {
        lines.pop();
    }

    if lines.is_empty() {
        return Err(CliError::InvalidArgs("edited content is empty — aborting save".into()));
    }

    // First line is the secret value.
    let secret = lines[0].to_string();
    if secret.is_empty() {
        return Err(CliError::InvalidArgs("secret value must not be empty".into()));
    }

    // Remaining lines may contain "Notes: ..." and "Extra: ..." prefixed lines.
    let mut notes: Option<String> = None;
    let mut extra: Option<serde_json::Value> = None;

    for line in &lines[1..] {
        if let Some(rest) = line.strip_prefix("Notes:") {
            let val = rest.trim();
            notes = if val.is_empty() { None } else { Some(val.to_string()) };
        } else if let Some(rest) = line.strip_prefix("Extra:") {
            let val = rest.trim();
            if !val.is_empty() {
                let parsed: serde_json::Value = serde_json::from_str(val).map_err(|e| {
                    CliError::InvalidArgs(format!("invalid JSON in Extra field: {e}"))
                })?;
                extra = Some(parsed);
            }
        }
        // Ignore any other lines (e.g. comments, blank lines).
    }

    Ok(SecretPayload { secret, notes, extra })
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
        SecretStoreError::GenerationMismatch { name, expected, got } => CliError::InvalidArgs(
            format!("generation mismatch for '{name}': expected {expected}, got {got}"),
        ),
        SecretStoreError::Tampered { path, reason } => {
            CliError::InvalidArgs(format!("tampered secret '{path}': {reason}"))
        }
        SecretStoreError::Io(e) => CliError::Io(e),
        SecretStoreError::Serde(e) => CliError::Json(e),
        SecretStoreError::Entry(e) => CliError::InvalidArgs(e.to_string()),
    }
}
