pub(crate) mod age_cmd;
pub(crate) mod agent_secret;
pub(crate) mod audit;
pub(crate) mod backup;
pub(crate) mod config;
pub(crate) mod derive;
pub(crate) mod fund;
pub(crate) mod generate;
#[cfg(feature = "git")]
pub(crate) mod git_cmd;
pub(crate) mod info;
pub(crate) mod intent;
pub(crate) mod key;
pub(crate) mod migrate;
pub(crate) mod password;
pub(crate) mod pay;
pub(crate) mod pay_x402;
pub(crate) mod policy;
pub(crate) mod sbom;
pub(crate) mod secret;
pub(crate) mod send_transaction;
pub(crate) mod session_key;
pub(crate) mod sign_message;
pub(crate) mod sign_transaction;
pub(crate) mod status;
pub(crate) mod totp;
pub(crate) mod uninstall;
pub(crate) mod update;
pub(crate) mod vault;
pub(crate) mod wallet;
pub(crate) mod wc;
pub(crate) mod webui;

use std::io::{self, BufRead, IsTerminal, Read, Write};

use oc_signer::{SecretBytes, process_hardening::clear_env_var};
use zeroize::Zeroizing;

use crate::CliError;

/// Read mnemonic from ONECIPHER_MNEMONIC env var (or OWS_MNEMONIC/LWS_MNEMONIC fallback) or stdin.
pub(crate) fn read_mnemonic() -> Result<Zeroizing<String>, CliError> {
    if let Some(value) = clear_env_var("ONECIPHER_MNEMONIC")
        .or_else(|| clear_env_var("OWS_MNEMONIC"))
        .or_else(|| clear_env_var("LWS_MNEMONIC"))
    {
        let trimmed = value.trim().to_string();
        if !trimmed.is_empty() {
            return Ok(Zeroizing::new(trimmed));
        }
    }

    let stdin = io::stdin();
    if stdin.is_terminal() {
        eprint!("Enter mnemonic: ");
        io::stderr().flush().ok();
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
pub(crate) fn read_private_key() -> Result<Zeroizing<String>, CliError> {
    if let Some(value) = clear_env_var("ONECIPHER_PRIVATE_KEY")
        .or_else(|| clear_env_var("OWS_PRIVATE_KEY"))
        .or_else(|| clear_env_var("LWS_PRIVATE_KEY"))
    {
        let trimmed = value.trim().to_string();
        if !trimmed.is_empty() {
            return Ok(Zeroizing::new(trimmed));
        }
    }

    let stdin = io::stdin();
    if stdin.is_terminal() {
        eprint!("Enter private key (hex): ");
        io::stderr().flush().ok();
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

/// Read a passphrase from ONECIPHER_PASSPHRASE env var (or OWS_PASSPHRASE/LWS_PASSPHRASE fallback)
/// or prompt interactively.
pub(crate) fn read_passphrase() -> Zeroizing<String> {
    if let Some(value) = clear_env_var("ONECIPHER_PASSPHRASE")
        .or_else(|| clear_env_var("OWS_PASSPHRASE"))
        .or_else(|| clear_env_var("LWS_PASSPHRASE"))
    {
        return Zeroizing::new(value);
    }
    let stdin = io::stdin();
    if stdin.is_terminal() {
        eprint!("Passphrase (empty for none): ");
        io::stderr().flush().ok();
        let mut line = String::new();
        stdin.lock().read_line(&mut line).unwrap_or(0);
        Zeroizing::new(line.trim().to_string())
    } else {
        Zeroizing::new(String::new())
    }
}

/// Peek at the passphrase value without consuming the env var.
/// Returns `Some(value)` if ONECIPHER_PASSPHRASE is set (even if empty), `None` otherwise.
/// Checks OWS_PASSPHRASE and LWS_PASSPHRASE as fallbacks for upgrade compatibility.
/// Used by sign commands to detect API tokens before deciding the code path.
pub(crate) fn peek_passphrase() -> Option<String> {
    std::env::var("ONECIPHER_PASSPHRASE")
        .ok()
        .or_else(|| std::env::var("OWS_PASSPHRASE").ok())
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

/// Resolve the OneCipher home directory (`~/.onecipher`).
///
/// Uses the `HOME` env var; falls back to `/tmp` if unset (matching
/// `oc_core::Config::default()` behavior).
pub(crate) fn onecipher_home() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
    PathBuf::from(home).join(".onecipher")
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
/// 1. Checks the `oc_key_` prefix.
/// 2. Hashes the token (SHA-256).
/// 3. Looks up the key file by token hash.
/// 4. Checks expiry.
///
/// Returns the `ApiKeyFile` on success so callers can inspect
/// `secret_permissions` and `wallet_ids` for fine-grained authorization.
pub(crate) fn validate_api_token(token: &str) -> Result<oc_core::ApiKeyFile, CliError> {
    if !token.starts_with(oc_wallet::key_store::TOKEN_PREFIX) {
        return Err(CliError::InvalidArgs(format!(
            "invalid API token — expected '{}' prefix",
            oc_wallet::key_store::TOKEN_PREFIX
        )));
    }

    let token_hash = oc_wallet::key_store::hash_token(token);
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
/// The env var is cleared immediately after reading (via `clear_env_var`).
/// When stdin is a terminal, a prompt is printed to stderr before reading.
pub(crate) fn read_secret_from_env_or_prompt() -> Result<String, CliError> {
    if let Some(value) = clear_env_var("ONECIPHER_SECRET") {
        let trimmed = value.trim().to_string();
        if !trimmed.is_empty() {
            return Ok(trimmed);
        }
    }

    let stdin = std::io::stdin();
    if stdin.is_terminal() {
        eprint!("Enter secret: ");
        io::stderr().flush().ok();
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
