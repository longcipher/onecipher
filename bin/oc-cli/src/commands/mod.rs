pub(crate) mod age_cmd;
pub(crate) mod agent_secret;
pub(crate) mod audit;
pub(crate) mod audit_secrets;
pub(crate) mod backup;
pub(crate) mod clipboard;
pub(crate) mod completion;
pub(crate) mod config;
pub(crate) mod derive;
pub(crate) mod doctor;
pub(crate) mod editor;
pub(crate) mod env_cmd;
pub(crate) mod find;
pub(crate) mod fsck;
pub(crate) mod generate;
#[cfg(feature = "git")]
pub(crate) mod git_cmd;
pub(crate) mod grep;
#[cfg(feature = "git")]
pub(crate) mod history;
pub(crate) mod info;
pub(crate) mod intent;
pub(crate) mod key;
pub(crate) mod migrate;
pub(crate) mod password;
pub(crate) mod policy;
pub(crate) mod render;
pub(crate) mod sbom;
pub(crate) mod secret;
pub(crate) mod send;
pub(crate) mod send_transaction;
pub(crate) mod service;
pub(crate) mod session_key;
pub(crate) mod sign_auth;
pub(crate) mod sign_message;
pub(crate) mod sign_transaction;
pub(crate) mod status;
pub(crate) mod totp;
pub(crate) mod uninstall;
pub(crate) mod update;
pub(crate) mod vanity;
pub(crate) mod vault;
pub(crate) mod verify;
pub(crate) mod wallet;
pub(crate) mod wallet_rpc;
pub(crate) mod wc;
pub(crate) mod webui;

use std::io::{self, BufRead, IsTerminal, Read, Write};

use oc_signer::SecretBytes;
use zeroize::Zeroizing;

use crate::CliError;

// ===========================================================================
// Burn-after-reading environment handling (Phase 1)
// ===========================================================================

/// Read `name` from the process environment and remove it immediately.
///
/// The value is wiped from the environment so a later `ps e` / `/proc`
/// scrape or child-process inheritance cannot recover it. Returns `None`
/// when unset. An explicitly empty value is preserved as `Some("")`
/// (empty passphrase is a valid "no passphrase" wallet key); use
/// [`take_first_env`] when several alias names feed one credential.
pub(crate) fn take_env(name: &str) -> Option<String> {
    let value = std::env::var(name).ok();
    // SAFETY: `std::env::remove_var` is `unsafe` because concurrent
    // environment access is undefined behavior. CLI takes happen on the
    // dispatch path before any secret-bearing child is spawned, and tests
    // serialize environment mutation via `HOME_LOCK`; no other thread
    // touches the same variable concurrently.
    unsafe {
        std::env::remove_var(name);
    }
    value
}

/// Drain every name in `names` (burn-after-reading) and return the first
/// hit, so stale aliases never linger for child processes to inherit.
///
/// Each probed name is removed even when an earlier alias already hit —
/// leaving a fallback passphrase behind would defeat the take.
pub(crate) fn take_first_env(names: &[&str]) -> Option<String> {
    let mut first = None;
    for name in names {
        if let Some(value) = take_env(name) {
            if first.is_none() {
                first = Some(value);
            }
        }
    }
    first
}

/// Ordered passphrase sources: canonical `ONECIPHER_PASSPHRASE` first, the
/// short `OC_PASSPHRASE` alias, then compat names (`OWS_PASSPHRASE`,
/// `OWX_PASSPHRASE`, `LWS_PASSPHRASE`). First hit wins; all probed names
/// are drained via [`take_first_env`].
pub(crate) fn take_passphrase() -> Option<String> {
    take_first_env(&[
        "ONECIPHER_PASSPHRASE",
        "OC_PASSPHRASE",
        "OWS_PASSPHRASE",
        "OWX_PASSPHRASE",
        "LWS_PASSPHRASE",
    ])
}

/// Returns `true` if stdin is a usable interactive terminal.
///
/// Always returns `false` under `#[cfg(test)]` (tests must provide input via
/// env vars or flags — blocking on `read_line()` would hang the harness).
/// Also returns `false` if the `OC_NONINTERACTIVE` env var is set, giving
/// scripts an explicit escape hatch, and when agent JSON mode is active
/// (`ONECIPHER_JSON_ERRORS=1`): JSON mode never prompts — missing input
/// fails closed with an explicit error instead (single stdout stream).
pub(crate) fn is_interactive_stdin() -> bool {
    if cfg!(test) {
        return false;
    }
    if std::env::var("OC_NONINTERACTIVE").is_ok() {
        return false;
    }
    if crate::output::is_json_mode() {
        return false;
    }
    io::stdin().is_terminal()
}

/// Read mnemonic from ONECIPHER_MNEMONIC env var (or OWS_MNEMONIC/LWS_MNEMONIC fallback) or stdin.
///
/// The env var is drained burn-after-reading via [`take_first_env`].
pub(crate) fn read_mnemonic() -> Result<Zeroizing<String>, CliError> {
    if let Some(value) = take_first_env(&["ONECIPHER_MNEMONIC", "OWS_MNEMONIC", "LWS_MNEMONIC"]) {
        let trimmed = value.trim().to_string();
        if !trimmed.is_empty() {
            return Ok(Zeroizing::new(trimmed));
        }
    }

    let stdin = io::stdin();
    if is_interactive_stdin() {
        eprint!("Enter mnemonic: ");
        io::stderr().flush().ok();
    } else {
        return Err(CliError::InvalidArgs(
            "no mnemonic provided (set ONECIPHER_MNEMONIC or pipe via stdin)".into(),
        ));
    }

    let mut line = String::new();
    stdin.lock().read_line(&mut line)?;
    let trimmed = line.trim().to_string();

    if trimmed.is_empty() {
        return Err(CliError::InvalidArgs(
            "no mnemonic provided (set ONECIPHER_MNEMONIC or pipe via stdin)".into(),
        ));
    }

    Ok(Zeroizing::new(trimmed))
}

/// Read a hex-encoded private key from ONECIPHER_PRIVATE_KEY env var (or
/// OWS_PRIVATE_KEY/LWS_PRIVATE_KEY fallback) or stdin.
///
/// The env var is drained burn-after-reading via [`take_first_env`].
pub(crate) fn read_private_key() -> Result<Zeroizing<String>, CliError> {
    if let Some(value) =
        take_first_env(&["ONECIPHER_PRIVATE_KEY", "OWS_PRIVATE_KEY", "LWS_PRIVATE_KEY"])
    {
        let trimmed = value.trim().to_string();
        if !trimmed.is_empty() {
            return Ok(Zeroizing::new(trimmed));
        }
    }

    let stdin = io::stdin();
    if is_interactive_stdin() {
        eprint!("Enter private key (hex): ");
        io::stderr().flush().ok();
    } else {
        return Err(CliError::InvalidArgs(
            "no private key provided (set ONECIPHER_PRIVATE_KEY or pipe via stdin)".into(),
        ));
    }

    let mut line = String::new();
    stdin.lock().read_line(&mut line)?;
    let trimmed = line.trim().to_string();

    if trimmed.is_empty() {
        return Err(CliError::InvalidArgs(
            "no private key provided (set ONECIPHER_PRIVATE_KEY or pipe via stdin)".into(),
        ));
    }

    Ok(Zeroizing::new(trimmed))
}

/// Read a passphrase from ONECIPHER_PASSPHRASE env var (or OC_PASSPHRASE /
/// OWS_PASSPHRASE / OWX_PASSPHRASE / LWS_PASSPHRASE fallback) or prompt
/// interactively.
///
/// The env var is drained burn-after-reading via [`take_passphrase`].
/// Under agent JSON mode ([`crate::output::is_json_mode`]) there is no
/// prompt: a missing env var yields an empty passphrase here, and every
/// caller that needs a real secret refuses explicitly through
/// [`is_interactive_stdin`] instead of blocking.
pub(crate) fn read_passphrase() -> Zeroizing<String> {
    if let Some(value) = take_passphrase() {
        return Zeroizing::new(value);
    }
    if is_interactive_stdin() {
        eprint!("Passphrase (empty for none): ");
        io::stderr().flush().ok();
        let mut line = String::new();
        io::stdin().lock().read_line(&mut line).unwrap_or(0);
        Zeroizing::new(line.trim().to_string())
    } else {
        Zeroizing::new(String::new())
    }
}

/// Peek at the passphrase value without consuming the env var.
/// Returns `Some(value)` if ONECIPHER_PASSPHRASE is set (even if empty), `None` otherwise.
/// Checks OC_PASSPHRASE, OWS_PASSPHRASE, OWX_PASSPHRASE and LWS_PASSPHRASE as fallbacks for
/// upgrade compatibility.
/// Used by sign commands to detect API tokens before deciding the code path.
pub(crate) fn peek_passphrase() -> Option<String> {
    std::env::var("ONECIPHER_PASSPHRASE")
        .ok()
        .or_else(|| std::env::var("OC_PASSPHRASE").ok())
        .or_else(|| std::env::var("OWS_PASSPHRASE").ok())
        .or_else(|| std::env::var("OWX_PASSPHRASE").ok())
        .or_else(|| std::env::var("LWS_PASSPHRASE").ok())
}

/// Resolve a wallet into the private key bytes for a specific chain.
///
/// Tries an empty passphrase first; if that fails, prompts the user.
/// Delegates to `oc_wallet::decrypt_signing_key` for the actual decryption
/// and key derivation so the signing path is never duplicated.
pub(crate) fn resolve_signing_key(
    wallet_name: &str,
    chain_type: oc_core::ChainType,
    index: u32,
) -> Result<SecretBytes, CliError> {
    // Try empty passphrase first.
    match oc_wallet::decrypt_signing_key(wallet_name, chain_type, b"", Some(index), None) {
        Ok(key) => return Ok(key),
        Err(oc_wallet::OcWalletError::Crypto(_)) => {
            // Empty passphrase didn't work — prompt the user.
        }
        Err(e) => return Err(e.into()),
    }

    let passphrase = read_passphrase();
    Ok(oc_wallet::decrypt_signing_key(
        wallet_name,
        chain_type,
        passphrase.as_bytes(),
        Some(index),
        None,
    )?)
}

// ===========================================================================
// Secret store helpers (Phase 2 — secret/password/totp/age commands)
// ===========================================================================

use std::path::PathBuf;

use oc_core::{ItemType, SecretMetadata, SecretPayload};
use oc_secret::{AgeIdentity, SecretStore, StoreConfig};

/// Resolve the OneCipher state directory (`~/.onecipher`).
///
/// Delegates to [`oc_core::paths::state_dir`], the single source of truth.
///
/// `main()` validates `HOME` before dispatching any subcommand, so the error
/// branch is unreachable in the CLI. It still refuses `/tmp`: the fallback is
/// a *relative* `.onecipher`, which stays inside the caller's own working
/// directory rather than a world-writable shared one.
pub(crate) fn onecipher_home() -> PathBuf {
    oc_core::paths::state_dir().unwrap_or_else(|_| PathBuf::from(oc_core::paths::STATE_DIR_NAME))
}

/// Secret store root directory: `<onecipher_home>/store/`.
///
/// The `SecretStore` creates `<root>/secrets/` (encrypted `.age` files) and
/// `<root>/index.jsonl` (plaintext index) internally.
pub(crate) fn secret_store_root() -> PathBuf {
    onecipher_home().join("store")
}

/// Open the secret store, creating it if necessary.
pub(crate) fn open_secret_store() -> Result<SecretStore, CliError> {
    let config = StoreConfig::new(secret_store_root());
    SecretStore::open(config).map_err(|e| CliError::InvalidArgs(e.to_string()))
}

/// Keys directory: `<onecipher_home>/keys/`.
pub(crate) fn keys_dir() -> PathBuf {
    onecipher_home().join("keys")
}

/// Age identity file path: `<onecipher_home>/keys/age-identity.txt`.
pub(crate) fn age_identity_path() -> PathBuf {
    keys_dir().join("age-identity.txt")
}

/// Age public recipient file path: `<onecipher_home>/keys/age-recipient.txt`.
pub(crate) fn age_recipient_public_path() -> PathBuf {
    keys_dir().join("age-recipient.txt")
}

/// Age recipients list file path: `<onecipher_home>/.age-recipients`.
pub(crate) fn age_recipients_path() -> PathBuf {
    onecipher_home().join(".age-recipients")
}

/// Load the age identity from disk (`~/.onecipher/keys/age-identity.txt`).
///
/// Returns an error directing the user to run `age init` if the identity file
/// does not exist.
pub(crate) fn load_age_identity() -> Result<AgeIdentity, CliError> {
    let path = age_identity_path();
    let content = std::fs::read_to_string(&path).map_err(|e| match e.kind() {
        std::io::ErrorKind::NotFound => CliError::InvalidArgs(format!(
            "age identity not found at {} — run `onecipher age init` first",
            path.display()
        )),
        _ => CliError::Io(e),
    })?;
    let identity_str = content.trim();
    AgeIdentity::parse(identity_str)
        .map_err(|e| CliError::InvalidArgs(format!("invalid age identity: {e}")))
}

/// Load the recipients list from `~/.onecipher/.age-recipients`.
///
/// Returns an empty vector if the file does not exist (e.g., before `age init`
/// has been run). Returns string representations of each recipient.
pub(crate) fn load_recipients() -> Result<Vec<String>, CliError> {
    let path = age_recipients_path();
    if !path.exists() {
        return Ok(Vec::new());
    }
    let recipients = oc_secret::RecipientsFile::load(&path)
        .map_err(|e| CliError::InvalidArgs(format!("failed to load recipients: {e}")))?;
    Ok(recipients.iter().map(|r| r.to_string()).collect())
}

// ===========================================================================
// Agent-mode helpers (Phase 6 — API token validation + daemon connection)
// ===========================================================================

/// Validate an API token and return the associated [`ApiKeyFile`].
///
/// Classification rides the shared dual-track model
/// ([`oc_core::Credential::parse`]): non-token credentials are rejected
/// before any hashing or lookup. Then:
/// 1. Hashes the token (SHA-256).
/// 2. Looks up the key file by token hash (constant-time compare).
/// 3. Checks expiry.
///
/// Returns the `ApiKeyFile` on success so callers can inspect
/// `secret_permissions` and `wallet_ids` for fine-grained authorization.
pub(crate) fn validate_api_token(token: &str) -> Result<oc_core::ApiKeyFile, CliError> {
    let oc_core::Credential::ApiToken(raw) = oc_core::Credential::parse(token) else {
        return Err(CliError::InvalidArgs(format!(
            "invalid API token — expected '{}' prefix",
            oc_core::TOKEN_PREFIX
        )));
    };

    let token_hash = oc_wallet::key_store::hash_token(raw.as_str());
    let key_file = oc_wallet::key_store::load_api_key_by_token_hash(&token_hash, None)?;

    // Check expiry.
    if let Some(ref expires) = key_file.expires_at {
        let now = jiff::Timestamp::now();
        let exp = expires.parse::<jiff::Timestamp>().map_err(|e| {
            CliError::InvalidArgs(format!("invalid expires_at timestamp '{expires}': {e}"))
        })?;
        if now > exp {
            return Err(CliError::Lws(oc_core::OcError::ApiKeyExpired { id: key_file.id }));
        }
    }

    Ok(key_file)
}

/// Connect to the Key-Agent daemon's UDS control socket.
///
/// Returns a `UnixStream` connected to `~/.onecipher/onecipher.ctrl`.
/// Used by agent-mode commands that need to send control messages to the
/// daemon (e.g., WC pairing injection). Secret operations do NOT use this
/// — they operate directly on the local SecretStore (R56: oc-keyagent
/// cannot depend on oc-secret).
#[cfg(unix)]
#[allow(dead_code)]
pub(crate) fn connect_daemon() -> Result<std::os::unix::net::UnixStream, CliError> {
    let path = onecipher_home().join("onecipher.ctrl");
    std::os::unix::net::UnixStream::connect(&path).map_err(|e| {
        CliError::InvalidArgs(format!(
            "cannot connect to daemon at {} — is `onecipher --daemon` running? ({e})",
            path.display()
        ))
    })
}

/// Read a `SecretPayload` JSON from stdin.
///
/// Expects a JSON object like `{"secret":"...","notes":"...","extra":{...}}`.
pub(crate) fn read_secret_payload_from_stdin() -> Result<SecretPayload, CliError> {
    let stdin = std::io::stdin();
    let mut buf = String::new();
    stdin.lock().read_to_string(&mut buf)?;
    let payload: SecretPayload = serde_json::from_str(&buf)?;
    Ok(payload)
}

/// Read a secret value from `ONECIPHER_SECRET` env var or an interactive prompt.
///
/// The env var is drained burn-after-reading via [`take_env`].
/// When stdin is a terminal, a prompt is printed to stderr before reading.
/// Under agent JSON mode there is no prompt: a missing env var fails
/// closed with an explicit error (single stdout stream downstream).
pub(crate) fn read_secret_from_env_or_prompt() -> Result<String, CliError> {
    if let Some(value) = take_env("ONECIPHER_SECRET") {
        let trimmed = value.trim().to_string();
        if !trimmed.is_empty() {
            return Ok(trimmed);
        }
    }

    let stdin = std::io::stdin();
    if is_interactive_stdin() {
        eprint!("Enter secret: ");
        io::stderr().flush().ok();
    } else {
        return Err(CliError::InvalidArgs(
            "no secret provided (set ONECIPHER_SECRET or enter via stdin)".into(),
        ));
    }

    let mut line = String::new();
    stdin.lock().read_line(&mut line)?;
    let trimmed = line.trim().to_string();

    if trimmed.is_empty() {
        return Err(CliError::InvalidArgs(
            "no secret provided (set ONECIPHER_SECRET or enter via stdin)".into(),
        ));
    }

    Ok(trimmed)
}

/// Parse an `ItemType` from a string (snake_case or display name).
///
/// Accepts: "mnemonic", "private_key", "password", "totp", "note", "file"
/// (case-insensitive). Also accepts display names like "Private Key".
#[allow(dead_code)]
pub(crate) fn parse_item_type(s: &str) -> Result<ItemType, CliError> {
    let lower = s.trim().to_ascii_lowercase();
    match lower.as_str() {
        "mnemonic" => Ok(ItemType::Mnemonic),
        "private_key" | "private key" => Ok(ItemType::PrivateKey),
        "password" => Ok(ItemType::Password),
        "totp" => Ok(ItemType::Totp),
        "note" => Ok(ItemType::Note),
        "file" => Ok(ItemType::File),
        _ => Err(CliError::InvalidArgs(format!(
            "unknown item type '{s}' (expected: mnemonic, private_key, password, totp, note, file)"
        ))),
    }
}

/// Parse `--meta key=val` pairs into a [`SecretMetadata`].
///
/// Supported keys: `url`, `username`, `chain`, `issuer`, `account`, `tags`.
/// The `tags` value is comma-separated.
pub(crate) fn parse_metadata(meta: &[String]) -> Result<SecretMetadata, CliError> {
    let mut metadata = SecretMetadata::default();
    for pair in meta {
        let (key, val) = pair.split_once('=').ok_or_else(|| {
            CliError::InvalidArgs(format!("invalid --meta (expected key=val): '{pair}'"))
        })?;
        let key = key.trim();
        let val = val.trim();
        match key {
            "url" => metadata.url = Some(val.to_string()),
            "username" => metadata.username = Some(val.to_string()),
            "chain" => metadata.chain = Some(val.to_string()),
            "issuer" => metadata.issuer = Some(val.to_string()),
            "account" => metadata.account = Some(val.to_string()),
            "tags" => {
                metadata.tags = val.split(',').map(|t| t.trim().to_string()).collect();
            }
            _ => {
                return Err(CliError::InvalidArgs(format!(
                    "unknown metadata key '{key}' (expected: url, username, chain, issuer, account, tags)"
                )));
            }
        }
    }
    Ok(metadata)
}

/// Print data as a QR code in the terminal (D11).
///
/// Rendering uses half-block characters (`▀`/`▄`/`█` + space) via `qr2term`,
/// which packs two QR rows per terminal row. This is an OPTIONAL display
/// feature behind the `qr` cargo feature (on by default).
///
/// Fail-safety: QR generation can fail (payload exceeds the QR capacity,
/// terminal too narrow, non-UTF8). A QR failure MUST NEVER fail the command —
/// the secret was already retrieved successfully. On any error (or when built
/// with `--no-default-features` without `qr`) we warn to stderr and fall back
/// to printing the plaintext payload, then return `Ok`.
pub(crate) fn print_qr(data: &str) -> Result<(), CliError> {
    #[cfg(feature = "qr")]
    {
        if let Err(e) = qr2term::print_qr(data) {
            eprintln!("warn: QR rendering failed ({e}); falling back to plaintext");
            println!("{data}");
        }
        return Ok(());
    }
    #[cfg(not(feature = "qr"))]
    {
        eprintln!("warn: QR support not compiled in; printing plaintext instead");
        println!("{data}");
        Ok(())
    }
}

#[cfg(test)]
mod qr_tests {
    use super::print_qr;

    #[test]
    fn print_qr_never_fails_on_oversize_payload() {
        // D11: silent-fail, never explode — even a payload far beyond QR
        // capacity must return Ok (plaintext fallback).
        let huge = "X".repeat(10_000);
        assert!(print_qr(&huge).is_ok());
        assert!(print_qr("").is_ok());
        assert!(print_qr("hello-qr").is_ok());
    }
}

#[cfg(test)]
mod take_env_tests {
    use super::{take_env, take_first_env, take_passphrase};
    use crate::test_util::{HOME_LOCK, remove_env, set_env};

    #[test]
    fn take_env_reads_then_removes() {
        let _lock = HOME_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        set_env("OC_TAKE_ENV_PROBE", "s3cr3t");
        assert_eq!(take_env("OC_TAKE_ENV_PROBE").as_deref(), Some("s3cr3t"));
        // Second take sees nothing: burn-after-reading.
        assert_eq!(take_env("OC_TAKE_ENV_PROBE"), None);
        assert!(std::env::var("OC_TAKE_ENV_PROBE").is_err());
    }

    #[test]
    fn take_env_missing_is_none() {
        let _lock = HOME_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        remove_env("OC_TAKE_ENV_ABSENT");
        assert_eq!(take_env("OC_TAKE_ENV_ABSENT"), None);
    }

    #[test]
    fn take_first_env_prefers_first_and_drains_all() {
        let _lock = HOME_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        set_env("OC_TAKE_FIRST_A", "first");
        set_env("OC_TAKE_FIRST_B", "second");
        assert_eq!(
            take_first_env(&["OC_TAKE_FIRST_A", "OC_TAKE_FIRST_B"]).as_deref(),
            Some("first")
        );
        // Both aliases are drained, not just the winner.
        assert!(std::env::var("OC_TAKE_FIRST_A").is_err());
        assert!(std::env::var("OC_TAKE_FIRST_B").is_err());
    }

    #[test]
    fn take_passphrase_supports_short_aliases() {
        let _lock = HOME_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        for name in [
            "ONECIPHER_PASSPHRASE",
            "OC_PASSPHRASE",
            "OWS_PASSPHRASE",
            "OWX_PASSPHRASE",
            "LWS_PASSPHRASE",
        ] {
            remove_env(name);
        }
        set_env("OWX_PASSPHRASE", "alias-pass");
        assert_eq!(take_passphrase().as_deref(), Some("alias-pass"));
        assert!(std::env::var("OWX_PASSPHRASE").is_err());
        set_env("OC_PASSPHRASE", "short-pass");
        assert_eq!(take_passphrase().as_deref(), Some("short-pass"));
        assert!(std::env::var("OC_PASSPHRASE").is_err());
        assert_eq!(take_passphrase(), None);
    }
}
