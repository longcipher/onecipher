use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// Permissions governing secret-vault operations for an API token.
///
/// Stored on [`ApiKeyFile`] so the Key-Agent can enforce glob-pattern
/// read/write scopes and TOTP generation without depending on `oc-secret`
/// (R56 — keeps the age dependency chain out of the isolated crates).
/// Default is deny-all: empty patterns + `allow_totp = false`.
#[derive(Clone, Debug, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct SecretPermissions {
    /// Glob patterns for readable secrets (e.g. `["github/*", "totp/*"]`).
    /// Empty list = no secrets readable.
    #[serde(default)]
    pub read_patterns: Vec<String>,
    /// Glob patterns for writable secrets. Empty list = no secrets writable.
    #[serde(default)]
    pub write_patterns: Vec<String>,
    /// Whether TOTP code generation is allowed for this token.
    #[serde(default)]
    pub allow_totp: bool,
    /// Rate limit: maximum secret reads per minute (0 = unlimited).
    #[serde(default)]
    pub max_reads_per_minute: u32,
}

/// An API key file stored at `~/.onecipher/keys/<id>.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKeyFile {
    pub id: String,
    pub name: String,
    /// SHA-256 hash of the raw token (hex-encoded).
    pub token_hash: String,
    pub created_at: String,
    /// Wallet IDs this key can access.
    pub wallet_ids: Vec<String>,
    /// Policy IDs attached to this key (AND semantics).
    pub policy_ids: Vec<String>,
    /// Optional expiry timestamp.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    /// Per-wallet encrypted secret copies, keyed by wallet ID.
    /// Each value is a CryptoEnvelope encrypted with HKDF(token).
    pub wallet_secrets: HashMap<String, serde_json::Value>,
    /// Secret-vault permissions (Phase 6). `#[serde(default)]` keeps old
    /// key files (pre-Phase-6) loadable as deny-all.
    #[serde(default)]
    pub secret_permissions: SecretPermissions,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_api_key_file_serde_roundtrip() {
        let key = ApiKeyFile {
            id: "7a2f1b3c-4d5e-6f7a-8b9c-0d1e2f3a4b5c".into(),
            name: "claude-agent".into(),
            token_hash: "e3b0c44298fc1c149afbf4c8996fb924".into(),
            created_at: "2026-03-22T10:30:00Z".into(),
            wallet_ids: vec!["3198bc9c-6672-5ab3-d995-4942343ae5b6".into()],
            policy_ids: vec!["base-agent-limits".into()],
            expires_at: None,
            wallet_secrets: HashMap::from([(
                "3198bc9c-6672-5ab3-d995-4942343ae5b6".into(),
                serde_json::json!({
                    "cipher": "aes-256-gcm",
                    "cipherparams": { "iv": "aabbccdd" },
                    "ciphertext": "deadbeef",
                    "auth_tag": "cafebabe",
                    "kdf": "hkdf-sha256",
                    "kdfparams": { "dklen": 32, "salt": "0011", "info": "ows-api-key-v1" }
                }),
            )]),
            secret_permissions: SecretPermissions::default(),
        };

        let json = serde_json::to_string_pretty(&key).unwrap();
        let deserialized: ApiKeyFile = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.id, key.id);
        assert_eq!(deserialized.name, "claude-agent");
        assert_eq!(deserialized.wallet_ids.len(), 1);
        assert_eq!(deserialized.policy_ids, vec!["base-agent-limits"]);
        assert!(deserialized.expires_at.is_none());
        assert!(deserialized.wallet_secrets.contains_key("3198bc9c-6672-5ab3-d995-4942343ae5b6"));
        assert_eq!(deserialized.secret_permissions, SecretPermissions::default());
    }

    #[test]
    fn test_api_key_file_with_expiry() {
        let key = ApiKeyFile {
            id: "test-id".into(),
            name: "expiring-key".into(),
            token_hash: "abc123".into(),
            created_at: "2026-03-22T10:30:00Z".into(),
            wallet_ids: vec![],
            policy_ids: vec![],
            expires_at: Some("2026-04-01T00:00:00Z".into()),
            wallet_secrets: HashMap::new(),
            secret_permissions: SecretPermissions::default(),
        };

        let json = serde_json::to_string(&key).unwrap();
        assert!(json.contains("expires_at"));
        let deserialized: ApiKeyFile = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.expires_at.as_deref(), Some("2026-04-01T00:00:00Z"));
    }

    #[test]
    fn test_api_key_file_no_expiry_omits_field() {
        let key = ApiKeyFile {
            id: "test-id".into(),
            name: "no-expiry".into(),
            token_hash: "abc123".into(),
            created_at: "2026-03-22T10:30:00Z".into(),
            wallet_ids: vec![],
            policy_ids: vec![],
            expires_at: None,
            wallet_secrets: HashMap::new(),
            secret_permissions: SecretPermissions::default(),
        };

        let json = serde_json::to_string(&key).unwrap();
        assert!(!json.contains("expires_at"));
    }

    #[test]
    fn test_secret_permissions_default_is_deny_all() {
        let perms = SecretPermissions::default();
        assert!(perms.read_patterns.is_empty());
        assert!(perms.write_patterns.is_empty());
        assert!(!perms.allow_totp);
        assert_eq!(perms.max_reads_per_minute, 0);
    }

    #[test]
    fn test_secret_permissions_serde_roundtrip() {
        let perms = SecretPermissions {
            read_patterns: vec!["github/*".into(), "totp/*".into()],
            write_patterns: vec!["notes/*".into()],
            allow_totp: true,
            max_reads_per_minute: 60,
        };
        let json = serde_json::to_string(&perms).unwrap();
        let restored: SecretPermissions = serde_json::from_str(&json).unwrap();
        assert_eq!(perms, restored);
    }

    #[test]
    fn test_old_api_key_file_without_secret_permissions_loads_as_default() {
        // Pre-Phase-6 key files do not have a `secret_permissions` field.
        // `#[serde(default)]` must allow them to load as deny-all.
        let old_json = serde_json::json!({
            "id": "legacy-key",
            "name": "legacy",
            "token_hash": "abc",
            "created_at": "2026-01-01T00:00:00Z",
            "wallet_ids": [],
            "policy_ids": [],
            "wallet_secrets": {}
        })
        .to_string();
        let key: ApiKeyFile = serde_json::from_str(&old_json).unwrap();
        assert_eq!(key.secret_permissions, SecretPermissions::default());
    }
}
