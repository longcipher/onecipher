//! Unified secret types for the OneCipher vault.
//!
//! `ItemType` is the top-level discriminator for vault entries. `KeyType`
//! (Mnemonic/PrivateKey) is a subset — wallets are just one kind of secret.

use serde::{Deserialize, Serialize};

/// Top-level entry type discriminator.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum ItemType {
    /// BIP-39 mnemonic seed phrase (12/24 words).
    Mnemonic,
    /// Single-chain private key (not derived from a mnemonic).
    PrivateKey,
    /// Password + metadata (URL, username, notes).
    Password,
    /// TOTP seed (otpauth URI or raw base32).
    Totp,
    /// Free-text encrypted note.
    Note,
    /// Binary file (certificate, SSH key, etc.).
    File,
}

impl ItemType {
    /// Returns all variants for iteration.
    pub fn all() -> &'static [Self] {
        &[Self::Mnemonic, Self::PrivateKey, Self::Password, Self::Totp, Self::Note, Self::File]
    }

    /// Human-readable label.
    pub fn label(&self) -> &'static str {
        match self {
            Self::Mnemonic => "Mnemonic",
            Self::PrivateKey => "Private Key",
            Self::Password => "Password",
            Self::Totp => "TOTP",
            Self::Note => "Note",
            Self::File => "File",
        }
    }
}

impl std::fmt::Display for ItemType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.label())
    }
}

/// Metadata for a secret entry (stored in plaintext index for searchability).
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct SecretMetadata {
    /// Associated URL (for passwords).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// Username or account name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    /// Chain type for wallet keys (e.g., "ethereum", "solana").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chain: Option<String>,
    /// TOTP issuer.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    /// TOTP account name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account: Option<String>,
    /// Free-form tags for categorization.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
}

/// Decrypted payload of a secret entry.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SecretPayload {
    /// The primary secret (password, mnemonic, TOTP seed, etc.).
    pub secret: String,
    /// Optional notes (can contain otpauth:// URI for TOTP).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
    /// Type-specific extra fields.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extra: Option<serde_json::Value>,
}

/// A secret entry index record (plaintext, stored in `index.jsonl`).
///
/// Contains no sensitive data — only metadata for listing and search.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SecretIndexEntry {
    pub id: String,
    pub name: String,
    pub item_type: ItemType,
    pub created_at: String,
    pub updated_at: String,
    pub metadata: SecretMetadata,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn item_type_serde_snake_case() {
        assert_eq!(serde_json::to_string(&ItemType::Mnemonic).unwrap(), "\"mnemonic\"");
        assert_eq!(serde_json::to_string(&ItemType::PrivateKey).unwrap(), "\"private_key\"");
        assert_eq!(serde_json::to_string(&ItemType::Totp).unwrap(), "\"totp\"");
    }

    #[test]
    fn item_type_round_trips() {
        for variant in ItemType::all() {
            let s = serde_json::to_string(variant).unwrap();
            let back: ItemType = serde_json::from_str(&s).unwrap();
            assert_eq!(variant, &back);
        }
    }

    #[test]
    fn item_type_all_has_six_variants() {
        assert_eq!(ItemType::all().len(), 6);
    }

    #[test]
    fn item_type_display_uses_label() {
        assert_eq!(ItemType::Mnemonic.to_string(), "Mnemonic");
        assert_eq!(ItemType::PrivateKey.to_string(), "Private Key");
        assert_eq!(ItemType::Totp.to_string(), "TOTP");
    }

    #[test]
    fn secret_metadata_default_is_empty() {
        let m = SecretMetadata::default();
        assert!(m.url.is_none());
        assert!(m.username.is_none());
        assert!(m.chain.is_none());
        assert!(m.issuer.is_none());
        assert!(m.account.is_none());
        assert!(m.tags.is_empty());
    }

    #[test]
    fn secret_metadata_skips_empty_fields_when_serialized() {
        let m = SecretMetadata::default();
        let json = serde_json::to_value(&m).unwrap();
        assert!(json.as_object().unwrap().is_empty());
    }

    #[test]
    fn secret_metadata_serializes_populated_fields() {
        let m = SecretMetadata {
            url: Some("https://example.com".into()),
            username: Some("alice".into()),
            chain: None,
            issuer: None,
            account: None,
            tags: vec!["work".into()],
        };
        let json = serde_json::to_value(&m).unwrap();
        assert_eq!(json["url"], "https://example.com");
        assert_eq!(json["username"], "alice");
        assert!(json.get("chain").is_none());
        assert_eq!(json["tags"][0], "work");
    }

    #[test]
    fn secret_payload_round_trips() {
        let p = SecretPayload {
            secret: "hunter2".into(),
            notes: Some("note text".into()),
            extra: Some(serde_json::json!({"k": "v"})),
        };
        let json = serde_json::to_string(&p).unwrap();
        let back: SecretPayload = serde_json::from_str(&json).unwrap();
        assert_eq!(back.secret, "hunter2");
        assert_eq!(back.notes.as_deref(), Some("note text"));
        assert_eq!(back.extra.unwrap()["k"], "v");
    }

    #[test]
    fn secret_index_entry_round_trips() {
        let e = SecretIndexEntry {
            id: "abc-123".into(),
            name: "GitHub".into(),
            item_type: ItemType::Password,
            created_at: "2024-01-01T00:00:00Z".into(),
            updated_at: "2024-01-02T00:00:00Z".into(),
            metadata: SecretMetadata::default(),
        };
        let json = serde_json::to_string(&e).unwrap();
        let back: SecretIndexEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(back.id, "abc-123");
        assert_eq!(back.name, "GitHub");
        assert_eq!(back.item_type, ItemType::Password);
    }
}
