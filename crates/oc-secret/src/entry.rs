//! A secret entry: encrypted payload + plaintext index metadata.

use oc_core::{ItemType, SecretIndexEntry, SecretMetadata, SecretPayload};
use oc_crypto::HardenedBytes;
use serde::{Deserialize, Serialize};

use crate::age::{self, AgeError, AgeIdentity};

/// Errors returned by [`SecretEntry`] operations.
#[derive(Debug, thiserror::Error)]
pub enum SecretEntryError {
    #[error("age error: {0}")]
    Age(#[from] AgeError),
    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("invalid name: {0}")]
    InvalidName(String),
    #[error("memory hardening failed: {0}")]
    MemGuard(String),
}

impl From<oc_crypto::MemGuardError> for SecretEntryError {
    fn from(e: oc_crypto::MemGuardError) -> Self {
        Self::MemGuard(e.to_string())
    }
}

/// A complete secret entry (encrypted payload + plaintext metadata).
///
/// The `ciphertext` field holds the age-encrypted [`SecretPayload`]. The
/// metadata fields (`name`, `item_type`, `created_at`, etc.) are stored in
/// plaintext so the index can be searched without decryption.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SecretEntry {
    pub id: String,
    pub name: String,
    pub item_type: ItemType,
    pub created_at: String,
    pub updated_at: String,
    pub metadata: SecretMetadata,
    /// age-encrypted `SecretPayload` (binary, base64-encoded in JSON).
    #[serde(with = "serde_bytes_base64")]
    pub ciphertext: Vec<u8>,
}

impl SecretEntry {
    /// Create a new secret entry by encrypting `payload` to `recipients`.
    pub fn new(
        name: &str,
        item_type: ItemType,
        payload: &SecretPayload,
        metadata: SecretMetadata,
        recipients: &[String],
    ) -> Result<Self, SecretEntryError> {
        if name.trim().is_empty() {
            return Err(SecretEntryError::InvalidName("name must not be empty".into()));
        }
        // Serialize payload to JSON, then encrypt with age.
        let json = serde_json::to_vec(payload)?;
        let ciphertext = age::encrypt_payload(&json, recipients)?;
        let now = jiff_now();
        Ok(Self {
            id: uuid::Uuid::new_v4().to_string(),
            name: name.to_string(),
            item_type,
            created_at: now.clone(),
            updated_at: now,
            metadata,
            ciphertext,
        })
    }

    /// Re-encrypt this entry's payload to a new recipient list.
    ///
    /// The existing payload is decrypted with `old_identity`, then
    /// re-encrypted to `new_recipients`. `updated_at` is bumped.
    pub fn re_encrypt(
        &mut self,
        old_identity: &AgeIdentity,
        new_recipients: &[String],
    ) -> Result<(), SecretEntryError> {
        let payload = self.decrypt(old_identity)?;
        let json = serde_json::to_vec(&payload)?;
        self.ciphertext = age::encrypt_payload(&json, new_recipients)?;
        self.updated_at = jiff_now();
        Ok(())
    }

    /// Decrypt this entry's payload using an age identity.
    ///
    /// The decrypted bytes are wrapped in [`HardenedBytes`] for the brief
    /// moment before JSON parsing, so the intermediate buffer is page-locked
    /// and zeroized on drop.
    pub fn decrypt(&self, identity: &AgeIdentity) -> Result<SecretPayload, SecretEntryError> {
        let plaintext = age::decrypt_payload(&self.ciphertext, identity)?;
        // Wrap the decrypted bytes in HardenedBytes for the brief moment
        // before JSON parsing.
        let hardened = HardenedBytes::from_vec(plaintext).map_err(SecretEntryError::from)?;
        let payload: SecretPayload = serde_json::from_slice(hardened.as_ref())?;
        Ok(payload)
    }

    /// Build a plaintext [`SecretIndexEntry`] from this entry.
    pub fn to_index_entry(&self) -> SecretIndexEntry {
        SecretIndexEntry {
            id: self.id.clone(),
            name: self.name.clone(),
            item_type: self.item_type,
            created_at: self.created_at.clone(),
            updated_at: self.updated_at.clone(),
            metadata: self.metadata.clone(),
        }
    }

    /// Update the entry's name (sets `updated_at`).
    pub fn rename(&mut self, new_name: &str) -> Result<(), SecretEntryError> {
        if new_name.trim().is_empty() {
            return Err(SecretEntryError::InvalidName("name must not be empty".into()));
        }
        self.name = new_name.to_string();
        self.updated_at = jiff_now();
        Ok(())
    }
}

fn jiff_now() -> String {
    jiff::Timestamp::now().to_string()
}

/// Serde adapter that base64-encodes `Vec<u8>` for compact JSON storage.
mod serde_bytes_base64 {
    use base64::{Engine, engine::general_purpose::STANDARD as BASE64_STANDARD};
    use serde::{Deserialize, Serialize};

    pub(super) fn serialize<S: serde::Serializer>(
        bytes: &Vec<u8>,
        s: S,
    ) -> Result<S::Ok, S::Error> {
        BASE64_STANDARD.encode(bytes).serialize(s)
    }

    pub(super) fn deserialize<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        BASE64_STANDARD.decode(s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use base64::{Engine, engine::general_purpose::STANDARD as BASE64_STANDARD};

    use super::*;

    fn recipient() -> (AgeIdentity, String) {
        let id = AgeIdentity::generate();
        let r = id.to_recipient_string();
        (id, r)
    }

    #[test]
    fn new_entry_encrypts_and_decrypts() {
        let (id, recipient_str) = recipient();
        let payload =
            SecretPayload { secret: "hunter2".into(), notes: Some("note".into()), extra: None };
        let entry = SecretEntry::new(
            "GitHub",
            ItemType::Password,
            &payload,
            SecretMetadata::default(),
            &[recipient_str],
        )
        .unwrap();

        assert_eq!(entry.name, "GitHub");
        assert_eq!(entry.item_type, ItemType::Password);
        assert!(!entry.ciphertext.is_empty());

        let decrypted = entry.decrypt(&id).unwrap();
        assert_eq!(decrypted.secret, "hunter2");
        assert_eq!(decrypted.notes.as_deref(), Some("note"));
    }

    #[test]
    fn empty_name_rejected() {
        let (_, recipient_str) = recipient();
        let payload = SecretPayload { secret: "x".into(), notes: None, extra: None };
        let result = SecretEntry::new(
            "  ",
            ItemType::Note,
            &payload,
            SecretMetadata::default(),
            &[recipient_str],
        );
        assert!(matches!(result, Err(SecretEntryError::InvalidName(_))));
    }

    #[test]
    fn to_index_entry_copies_metadata() {
        let (_, recipient_str) = recipient();
        let payload = SecretPayload { secret: "x".into(), notes: None, extra: None };
        let metadata =
            SecretMetadata { url: Some("https://example.com".into()), ..Default::default() };
        let entry =
            SecretEntry::new("name", ItemType::Password, &payload, metadata, &[recipient_str])
                .unwrap();
        let idx = entry.to_index_entry();
        assert_eq!(idx.name, "name");
        assert_eq!(idx.id, entry.id);
        assert_eq!(idx.metadata.url.as_deref(), Some("https://example.com"));
    }

    #[test]
    fn rename_updates_name_and_timestamp() {
        let (_id, recipient_str) = recipient();
        let payload = SecretPayload { secret: "x".into(), notes: None, extra: None };
        let mut entry = SecretEntry::new(
            "old",
            ItemType::Note,
            &payload,
            SecretMetadata::default(),
            &[recipient_str],
        )
        .unwrap();
        let original_updated = entry.updated_at.clone();
        // Sleep briefly to ensure timestamp changes.
        std::thread::sleep(std::time::Duration::from_millis(20));
        entry.rename("new").unwrap();
        assert_eq!(entry.name, "new");
        assert_ne!(entry.updated_at, original_updated);
    }

    #[test]
    fn serde_round_trip() {
        let (id, recipient_str) = recipient();
        let payload = SecretPayload {
            secret: "secret value".into(),
            notes: Some("a note".into()),
            extra: Some(serde_json::json!({"k": "v"})),
        };
        let entry = SecretEntry::new(
            "serde-test",
            ItemType::Mnemonic,
            &payload,
            SecretMetadata::default(),
            &[recipient_str],
        )
        .unwrap();

        let json = serde_json::to_string(&entry).unwrap();
        let restored: SecretEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.name, "serde-test");
        assert_eq!(restored.ciphertext, entry.ciphertext);

        let decrypted = restored.decrypt(&id).unwrap();
        assert_eq!(decrypted.secret, "secret value");
    }

    #[test]
    fn re_encrypt_to_new_recipient() {
        let (id1, recipient_str1) = recipient();
        let (id2, recipient_str2) = recipient();
        let payload = SecretPayload { secret: "re-encrypt me".into(), notes: None, extra: None };
        let mut entry = SecretEntry::new(
            "reenc",
            ItemType::PrivateKey,
            &payload,
            SecretMetadata::default(),
            &[recipient_str1],
        )
        .unwrap();

        entry.re_encrypt(&id1, &[recipient_str2]).unwrap();

        // Old identity can no longer decrypt.
        assert!(entry.decrypt(&id1).is_err());
        // New identity can.
        let decrypted = entry.decrypt(&id2).unwrap();
        assert_eq!(decrypted.secret, "re-encrypt me");
    }

    #[test]
    fn ciphertext_is_base64_in_json() {
        let (_id, recipient_str) = recipient();
        let payload = SecretPayload { secret: "x".into(), notes: None, extra: None };
        let entry = SecretEntry::new(
            "b64",
            ItemType::Note,
            &payload,
            SecretMetadata::default(),
            &[recipient_str],
        )
        .unwrap();
        let json = serde_json::to_value(&entry).unwrap();
        let ct = json["ciphertext"].as_str().unwrap();
        // Ciphertext is base64-encoded.
        assert!(BASE64_STANDARD.decode(ct).is_ok());
    }
}
