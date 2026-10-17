//! Generic secret management CLI commands (`onecipher secret ...`).
//!
//! Provides list / get / add / update / delete / rename operations over the
//! age-encrypted [`SecretStore`]. All sensitive material flows through the
//! shared helpers in [`super`], which read from stdin or env vars and never
//! echo secrets to stderr.

use oc_core::{AuditOp, ItemType, SecretKind, SecretPayload};
use oc_secret::{SecretEnvelope, SecretStoreError};
use zeroize::{Zeroize, Zeroizing};

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
            // seniorpw's `show -c -k otp`: copy the *code*, not the URI.
            Some("otp") => &totp_code(&payload)?,
            Some(other) => {
                return Err(CliError::InvalidArgs(format!(
                    "unknown field '{other}' (expected: secret, notes, otp, metadata)"
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
        // seniorpw's `show -k otp`: when the stored value is an otpauth URI,
        // print the current code instead of the secret.
        Some("otp") => println!("{}", totp_code(&payload)?),
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

/// Resolve the `otp` field of a payload: generate a code when the secret
/// value is an `otpauth://` URI (seniorpw's `show -k otp` behaviour).
fn totp_code(payload: &SecretPayload) -> Result<String, CliError> {
    let uri = payload.secret.trim();
    if !uri.starts_with("otpauth://") {
        return Err(CliError::InvalidArgs(
            "field 'otp' requires an otpauth:// URI in the secret value".into(),
        ));
    }
    super::totp_code_from_uri(uri)
}

/// Entry point for `onecipher secret cat [PREFIX] [--json]`.
///
/// Dumps the decrypted content of every secret (seniorpw's `senior cat`),
/// optionally restricted to a name prefix, in a pipe-friendly form:
///
/// ```text
/// github/personal
/// ---------------
/// hunter2
/// user: alice
/// ```
///
/// Pipe the output into `grep`, `fzf`, or `less` for ad-hoc searches; use
/// `--json` for machine consumption.
#[allow(dead_code)]
pub(crate) fn cat(prefix: &str, json: bool) -> Result<(), CliError> {
    let store = super::open_secret_store()?;
    let identity = super::load_age_identity()?;
    let entries = store.list().map_err(map_store_error)?;

    let prefix = prefix.trim().trim_end_matches('/');
    let mut dumped: Vec<serde_json::Value> = Vec::new();
    let mut first = true;

    for index_entry in &entries {
        if !prefix.is_empty() &&
            index_entry.name != prefix &&
            !index_entry.name.starts_with(&format!("{prefix}/"))
        {
            continue;
        }

        let entry = store.get(&index_entry.name).map_err(map_store_error)?;
        let mut payload = entry
            .decrypt(&identity)
            .map_err(|e| CliError::InvalidArgs(format!("decryption failed: {e}")))?;

        if json {
            dumped.push(serde_json::json!({
                "name": index_entry.name,
                "secret": payload.secret,
                "notes": payload.notes,
                "extra": payload.extra,
            }));
            payload.secret.zeroize();
            continue;
        }

        if !first {
            println!();
        }
        first = false;

        // Name, an underline, then the payload — the `senior cat` layout, so
        // the output reads well in a terminal and stays greppable.
        println!("{}", index_entry.name);
        println!("{}", "-".repeat(index_entry.name.chars().count()));
        println!("{}", payload.secret);
        if let Some(notes) = payload.notes.as_deref().filter(|n| !n.is_empty()) {
            println!("{notes}");
        }
        if let Some(extra) = &payload.extra {
            if let Ok(text) = serde_json::to_string(extra) {
                println!("extra: {text}");
            }
        }
        payload.secret.zeroize();
    }

    if json {
        println!("{}", serde_json::to_string_pretty(&dumped)?);
    }
    Ok(())
}

/// Entry point for `onecipher secret dir [--json]`.
///
/// Prints the directory of the active store (seniorpw's `senior print-dir`)
/// so scripts can locate it without hardcoding `~/.onecipher/store`.
pub(crate) fn dir(json: bool) -> Result<(), CliError> {
    let root = super::secret_store_root();
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "dir": root,
                "store": super::active_store_name(),
            }))?
        );
    } else {
        println!("{}", root.display());
    }
    Ok(())
}

/// Entry point for `onecipher secret stores [--json]`.
///
/// Lists the default store plus every named store under
/// `<onecipher_home>/stores/`, marking the active one with `*`.
pub(crate) fn stores(json: bool) -> Result<(), CliError> {
    let home = super::onecipher_home();
    let default = home.join("store");
    let named_dir = super::stores_dir();
    let active = super::active_store_name();

    let mut names: Vec<String> = Vec::new();
    if default.is_dir() {
        names.push(String::from("(default)"));
    }
    if named_dir.is_dir() {
        let mut named: Vec<String> = std::fs::read_dir(&named_dir)
            .map_err(CliError::Io)?
            .filter_map(Result::ok)
            .filter(|e| e.path().is_dir())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        named.sort();
        names.extend(named);
    }

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "active": active,
                "dir": super::secret_store_root(),
                "stores": names,
            }))?
        );
        return Ok(());
    }

    if names.is_empty() {
        println!("no stores yet; run `onecipher secret add` to create the default one");
        return Ok(());
    }

    for name in &names {
        let is_default = name == "(default)";
        let marker = if is_default {
            if active.is_none() { " *" } else { "  " }
        } else if active.as_deref() == Some(name.as_str()) {
            " *"
        } else {
            "  "
        };
        println!("{marker} {name}");
    }
    println!();
    println!("select with `onecipher -s <NAME> ...` (stores live in {})", named_dir.display());
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
/// Decrypts the secret into a human-readable form, opens it for editing,
/// then parses the edited content back into a `SecretPayload`, re-encrypts,
/// and saves.
///
/// Editor selection (in order):
/// 1. `--editor <cmd>` — an explicit external editor,
/// 2. `$VISUAL` / `$EDITOR` — an external editor,
/// 3. otherwise — the built-in in-memory TUI editor, which never writes the plaintext to disk (see
///    [`super::tui_edit`]). This is the default on a TTY and matches pago's approach.
///
/// The external path stages the plaintext inside the 0700 OneCipher state
/// directory and zero-fills + unlinks it afterwards (see
/// [`super::editor`]); it is never staged in the shared temp directory.
/// A discarded in-memory edit (`Ctrl+C`/`Esc`) leaves the entry untouched.
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
    // `Zeroizing` so the decrypted plaintext is wiped when this scope ends.
    let initial_content =
        Zeroizing::new(format!("{}\n{}\n{}\n", payload.secret, notes_line, extra_line));

    // Prefer the editor that never touches the filesystem: no `--editor`
    // flag and no `$VISUAL`/`$EDITOR` means the built-in TUI on a TTY.
    let configured_editor = editor
        .map(str::to_owned)
        .or_else(|| std::env::var("VISUAL").ok())
        .or_else(|| std::env::var("EDITOR").ok());

    let edited = if let Some(cmd) = configured_editor {
        super::editor::edit_text(&initial_content, Some(&cmd))?
    } else {
        if !super::is_interactive_stdin() {
            return Err(CliError::InvalidArgs(
                "secret edit needs a terminal: no $EDITOR/$VISUAL is set and stdin is not a TTY \
                 (set EDITOR or pass --editor <cmd>)"
                    .into(),
            ));
        }
        if let Some(text) = super::tui_edit::edit_in_memory(&initial_content)? {
            text
        } else {
            // Discarded by the user: leave the entry untouched.
            eprintln!("secret edit discarded: '{name}' unchanged");
            return Ok(());
        }
    };

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
///
/// Each variant maps to a distinct stable code (and therefore a distinct
/// BSD sysexits status) so scripts can branch on the failure mode:
/// `NotFound` -> 66, `AlreadyExists` -> 73, `InvalidName` /
/// `GenerationMismatch` / `Tampered` -> 65. See `crate::exit`.
pub(super) fn map_store_error(e: SecretStoreError) -> CliError {
    match e {
        SecretStoreError::NotFound(name) => CliError::Coded {
            code: "SECRET_NOT_FOUND",
            message: format!("secret not found: '{name}'"),
        },
        SecretStoreError::AlreadyExists(name) => CliError::Coded {
            code: "SECRET_EXISTS",
            message: format!("secret already exists: '{name}'"),
        },
        SecretStoreError::InvalidName(msg) => {
            CliError::Coded { code: "SECRET_NAME_INVALID", message: msg }
        }
        SecretStoreError::GenerationMismatch { name, expected, got } => CliError::Coded {
            code: "SECRET_GENERATION_MISMATCH",
            message: format!("generation mismatch for '{name}': expected {expected}, got {got}"),
        },
        SecretStoreError::Tampered { path, reason } => CliError::Coded {
            code: "SECRET_TAMPERED",
            message: format!("tampered secret '{path}': {reason}"),
        },
        SecretStoreError::Io(e) => CliError::Io(e),
        SecretStoreError::Serde(e) => CliError::Json(e),
        SecretStoreError::Entry(e) => CliError::InvalidArgs(e.to_string()),
    }
}
