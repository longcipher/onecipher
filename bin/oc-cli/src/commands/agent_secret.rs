//! Agent-mode secret operations (`onecipher agent-secret ...`).
//!
//! These commands run in API-token mode: the token is read from
//! `ONECIPHER_PASSPHRASE`, validated against the key file, and the
//! `SecretPermissions` on the key file are enforced before any secret
//! operation. All operations are logged to the audit log (best-effort).
//!
//! R56: the Key-Agent daemon cannot handle secret RPCs (oc-secret pulls in
//! the age dependency chain), so these commands operate directly on the
//! local SecretStore via oc-secret. The proto wire types (GetSecret /
//! ListSecrets / GenerateTotp) are defined for forward compatibility with
//! a future Net-Agent implementation.

use oc_keyagent::audit::{AuditError, AuditLog, DeviceKeyStore, EventType};

use crate::CliError;

/// Glob match with `*` wildcard support.
///
/// Matches the entire `name` against `pattern`. A `*` matches zero or more
/// characters. No other metacharacters are supported (keeps the matcher
/// dependency-free and predictable).
fn glob_match(pattern: &str, name: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let n: Vec<char> = name.chars().collect();
    glob_inner(&p, &n)
}

fn glob_inner(p: &[char], n: &[char]) -> bool {
    if p.is_empty() {
        return n.is_empty();
    }
    if p[0] == '*' {
        // Trailing `*` matches everything remaining.
        if p.len() == 1 {
            return true;
        }
        // Try consuming zero or more input chars.
        for i in 0..=n.len() {
            if glob_inner(&p[1..], &n[i..]) {
                return true;
            }
        }
        false
    } else if n.is_empty() {
        false
    } else if p[0] == n[0] {
        glob_inner(&p[1..], &n[1..])
    } else {
        false
    }
}

/// Read the API token from `ONECIPHER_PASSPHRASE`.
fn read_api_token() -> Result<String, CliError> {
    super::peek_passphrase().ok_or_else(|| {
        CliError::InvalidArgs(
            "no API token — set ONECIPHER_PASSPHRASE to an oc_key_... token".into(),
        )
    })
}

/// Best-effort audit log append for a secret read operation.
///
/// Opens the audit log fresh (reads the current tail from disk), appends a
/// signed entry, and drops. If the daemon is concurrently appending, there
/// is a small race window — the append itself is atomic (single write +
/// fsync), but the `prev_hash` chain may diverge. `verify_chain` will detect
/// any mismatch. Failures are logged to stderr and do not block the operation.
fn audit_secret_op(event: EventType, payload: serde_json::Value) {
    // L3 fix: never write the audit trail to world-writable /tmp.
    let Ok(path) = oc_core::paths::state_path("logs/audit.jsonl") else {
        eprintln!("warning: audit log skipped — cannot determine home directory");
        return;
    };
    let device_id = "cli-agent-secret".to_string();

    let device_key = match DeviceKeyStore::open_default().and_then(|s| s.load_or_generate()) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("[AUDIT-WARN] cannot load device key: {e}");
            return;
        }
    };

    let mut log = match AuditLog::open(&path, &device_id, device_key) {
        Ok(l) => l,
        Err(AuditError::Io(ref e)) if e.kind() == std::io::ErrorKind::NotFound => return,
        Err(e) => {
            eprintln!("[AUDIT-WARN] cannot open audit log: {e}");
            return;
        }
    };

    if let Err(e) = log.append(event, None, payload) {
        eprintln!("[AUDIT-WARN] append failed: {e}");
    }
}

/// Check that the secret name matches at least one read pattern.
fn check_read_permission(perms: &oc_core::SecretPermissions, name: &str) -> Result<(), CliError> {
    let allowed = perms.read_patterns.iter().any(|p| glob_match(p, name));
    if !allowed {
        return Err(CliError::InvalidArgs(format!(
            "access denied: secret '{name}' does not match any read pattern in the API key's secret_permissions"
        )));
    }
    Ok(())
}

/// Entry point for `onecipher agent-secret get <name>`.
///
/// Validates the API token, checks read permission, decrypts the secret,
/// and prints the secret value to stdout.
pub(crate) fn agent_secret_get(name: &str, json: bool) -> Result<(), CliError> {
    let token = read_api_token()?;
    let key_file = super::validate_api_token(&token)?;

    check_read_permission(&key_file.secret_permissions, name)?;

    let store = super::open_secret_store()?;
    let entry = store.get(name).map_err(|e| CliError::InvalidArgs(e.to_string()))?;
    let identity = super::load_age_identity()?;
    let payload =
        entry.decrypt(&identity).map_err(|e| CliError::InvalidArgs(format!("decrypt: {e}")))?;

    audit_secret_op(
        EventType::SecretRead,
        serde_json::json!({"name": name, "item_type": entry.item_type.to_string()}),
    );

    if json {
        let obj = serde_json::json!({
            "name": entry.name,
            "item_type": entry.item_type,
            "secret": payload.secret,
        });
        println!("{}", serde_json::to_string_pretty(&obj)?);
    } else {
        println!("{}", payload.secret);
    }

    Ok(())
}

/// Entry point for `onecipher agent-secret list`.
///
/// Validates the API token and lists all secret index entries. The
/// `read_patterns` are NOT applied to the list output (the index contains
/// only plaintext metadata — no secret values). The caller is expected to
/// `get` only the secrets they are permitted to read.
pub(crate) fn agent_secret_list(json: bool) -> Result<(), CliError> {
    let token = read_api_token()?;
    let key_file = super::validate_api_token(&token)?;

    // Require at least one read pattern to list — deny-all keys cannot list.
    if key_file.secret_permissions.read_patterns.is_empty() {
        return Err(CliError::InvalidArgs(
            "access denied: API key has no read patterns in secret_permissions".into(),
        ));
    }

    let store = super::open_secret_store()?;
    let entries = store.list().map_err(|e| CliError::InvalidArgs(e.to_string()))?;

    audit_secret_op(
        EventType::SecretRead,
        serde_json::json!({"action": "list", "count": entries.len()}),
    );

    if json {
        println!("{}", serde_json::to_string_pretty(&entries)?);
        return Ok(());
    }

    if entries.is_empty() {
        println!("No secrets found.");
        return Ok(());
    }

    for e in &entries {
        println!("{}\t{}\t{}", e.name, e.item_type, e.updated_at);
    }

    Ok(())
}

/// Entry point for `onecipher agent-secret totp <name>`.
///
/// Validates the API token, checks `allow_totp` + read permission, decrypts
/// the stored otpauth URI, and generates the current TOTP code.
pub(crate) fn agent_totp_generate(name: &str) -> Result<(), CliError> {
    let token = read_api_token()?;
    let key_file = super::validate_api_token(&token)?;

    if !key_file.secret_permissions.allow_totp {
        return Err(CliError::InvalidArgs(
            "access denied: TOTP generation is not allowed for this API key".into(),
        ));
    }

    check_read_permission(&key_file.secret_permissions, name)?;

    let store = super::open_secret_store()?;
    let entry = store.get(name).map_err(|e| CliError::InvalidArgs(e.to_string()))?;
    let identity = super::load_age_identity()?;
    let payload =
        entry.decrypt(&identity).map_err(|e| CliError::InvalidArgs(format!("decrypt: {e}")))?;

    let code = oc_secret::totp::generate_totp(&payload.secret)
        .map_err(|e| CliError::InvalidArgs(format!("TOTP generation: {e}")))?;

    audit_secret_op(
        EventType::SecretRead,
        serde_json::json!({"action": "totp_generate", "name": name}),
    );

    println!("{code}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_glob_exact_match() {
        assert!(glob_match("github", "github"));
        assert!(!glob_match("github", "gitlab"));
    }

    #[test]
    fn test_glob_trailing_star() {
        assert!(glob_match("github/*", "github/token"));
        assert!(glob_match("github/*", "github/"));
        assert!(!glob_match("github/*", "gitlab/token"));
    }

    #[test]
    fn test_glob_leading_star() {
        assert!(glob_match("*/token", "github/token"));
        assert!(glob_match("*/token", "gitlab/token"));
        assert!(!glob_match("*/token", "github/password"));
    }

    #[test]
    fn test_glob_star_only() {
        assert!(glob_match("*", "anything"));
        assert!(glob_match("*", ""));
    }

    #[test]
    fn test_glob_multiple_stars() {
        assert!(glob_match("*/*", "github/token"));
        assert!(glob_match("totp/*", "totp/github"));
        assert!(!glob_match("totp/*", "password/github"));
    }

    #[test]
    fn test_glob_no_match() {
        assert!(!glob_match("github", "github/token"));
        assert!(!glob_match("github", ""));
    }

    #[test]
    fn test_check_read_permission_allowed() {
        let perms = oc_core::SecretPermissions {
            read_patterns: vec!["github/*".into(), "totp/*".into()],
            ..Default::default()
        };
        assert!(check_read_permission(&perms, "github/token").is_ok());
        assert!(check_read_permission(&perms, "totp/aws").is_ok());
    }

    #[test]
    fn test_check_read_permission_denied() {
        let perms = oc_core::SecretPermissions {
            read_patterns: vec!["github/*".into()],
            ..Default::default()
        };
        assert!(check_read_permission(&perms, "aws/key").is_err());
    }

    #[test]
    fn test_check_read_permission_empty_patterns_denies_all() {
        let perms = oc_core::SecretPermissions::default();
        assert!(check_read_permission(&perms, "anything").is_err());
    }
}
