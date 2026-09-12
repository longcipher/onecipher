//! A secret entry: encrypted payload + plaintext index metadata.
//!
//! The age ciphertext wraps an `ocenv/1` envelope (see [`crate::envelope`])
//! binding the lookup path and the monotonic generation (B1/B4). Decryption
//! verifies the binding and fails closed with [`SecretEntryError::Tampered`].

use oc_core::{ItemType, SecretIndexEntry, SecretMetadata, SecretPayload};
use oc_crypto::HardenedBytes;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::{
    age::{self, AgeError, AgeIdentity},
    envelope::{self, ENVELOPE_MAGIC},
};

/// Errors returned by [`SecretEntry`] operations.
#[derive(Debug, thiserror::Error)]
pub enum SecretEntryError {
    #[error("age error: {0}")]
    Age(#[from] AgeError),
    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("invalid name: {0}")]
    InvalidName(String),
    #[error("tampered envelope for '{path}': {reason}")]
    Tampered { path: String, reason: String },
    #[error("memory hardening failed: {0}")]
    MemGuard(String),
}

impl From<oc_crypto::MemGuardError> for SecretEntryError {
    fn from(e: oc_crypto::MemGuardError) -> Self {
        Self::MemGuard(e.to_string())
    }
}

impl From<crate::envelope::EnvelopeError> for SecretEntryError {
    fn from(e: crate::envelope::EnvelopeError) -> Self {
        match e {
            crate::envelope::EnvelopeError::Tampered { path, reason } => {
                Self::Tampered { path, reason }
            }
            crate::envelope::EnvelopeError::InvalidPath(msg) => Self::InvalidName(msg),
        }
    }
}

/// A complete secret entry (encrypted payload + plaintext metadata).
///
/// The `ciphertext` field holds the age-encrypted `ocenv/1` envelope wrapping
/// the [`SecretPayload`] JSON. The metadata fields (`name`, `item_type`,
/// `generation`, timestamps, etc.) are stored in plaintext so the index can be
/// searched without decryption; the envelope binds the ciphertext to `name`
/// + `generation` so swaps and replays fail closed on [`decrypt`](Self::decrypt).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SecretEntry {
    pub id: String,
    pub name: String,
    pub item_type: ItemType,
    pub created_at: String,
    pub updated_at: String,
    pub metadata: SecretMetadata,
    /// Monotonic generation bound inside the envelope (B4, 0 = legacy).
    #[serde(default)]
    pub generation: u64,
    /// age-encrypted `ocenv/1` envelope (binary, base64-encoded in JSON).
    #[serde(with = "serde_bytes_base64")]
    pub ciphertext: Vec<u8>,
}

impl SecretEntry {
    /// Create a new secret entry by encrypting `payload` to `recipients`.
    ///
    /// `generation` MUST be the store-allocated `next_generation(name)`
    /// (`floor + 1` saturating, 1 for a fresh name). The envelope binds
    /// `name` + `generation`; [`SecretStore::put`](crate::store::SecretStore::put)
    /// rejects a stale `generation` fail-closed.
    pub fn new(
        name: &str,
        item_type: ItemType,
        payload: &SecretPayload,
        metadata: SecretMetadata,
        recipients: &[String],
        generation: u64,
    ) -> Result<Self, SecretEntryError> {
        crate::path::validate_path(name)
            .map_err(|e| SecretEntryError::InvalidName(e.to_string()))?;
        if generation == 0 {
            return Err(SecretEntryError::InvalidName("generation must be >= 1".into()));
        }
        // Serialize payload to JSON, wrap in the path-bound envelope, then
        // encrypt with age. Plaintext buffers are zeroized on drop.
        let json = Zeroizing::new(serde_json::to_vec(payload)?);
        let enveloped = envelope::wrap_envelope(name, generation, &json)?;
        let ciphertext = age::encrypt_payload(&enveloped, recipients)?;
        let now = jiff_now();
        Ok(Self {
            id: uuid::Uuid::new_v4().to_string(),
            name: name.to_string(),
            item_type,
            created_at: now.clone(),
            updated_at: now,
            metadata,
            generation,
            ciphertext,
        })
    }

    /// Replace the payload, rebinding to `generation` (caller-allocated next generation).
    ///
    /// Used by update/edit flows: the caller queries
    /// [`SecretStore::next_generation`](crate::store::SecretStore::next_generation)
    /// first, then persists via `put`.
    pub fn set_payload(
        &mut self,
        payload: &SecretPayload,
        recipients: &[String],
        generation: u64,
    ) -> Result<(), SecretEntryError> {
        if generation == 0 {
            return Err(SecretEntryError::InvalidName("generation must be >= 1".into()));
        }
        let json = Zeroizing::new(serde_json::to_vec(payload)?);
        let enveloped = envelope::wrap_envelope(&self.name, generation, &json)?;
        self.ciphertext = age::encrypt_payload(&enveloped, recipients)?;
        self.generation = generation;
        self.updated_at = jiff_now();
        Ok(())
    }

    /// Re-encrypt this entry's payload to a new recipient list.
    ///
    /// The existing payload is decrypted (verifying the envelope binding),
    /// then re-encrypted to `new_recipients` preserving `name` + `generation`.
    /// `updated_at` is bumped. For a store-level rotation that must also bump
    /// `generation`, decrypt + [`set_payload`](Self::set_payload) with the allocated
    /// next generation instead.
    pub fn re_encrypt(
        &mut self,
        old_identity: &AgeIdentity,
        new_recipients: &[String],
    ) -> Result<(), SecretEntryError> {
        let payload = self.decrypt(old_identity)?;
        let json = Zeroizing::new(serde_json::to_vec(&payload)?);
        let enveloped = envelope::wrap_envelope(&self.name, self.generation, &json)?;
        self.ciphertext = age::encrypt_payload(&enveloped, new_recipients)?;
        self.updated_at = jiff_now();
        Ok(())
    }

    /// Decrypt the age layer and verify the `ocenv/1` envelope binding.
    ///
    /// Returns the envelope `generation` and the inner payload JSON. Legacy
    /// ciphertexts (decrypted bytes not starting with `ocenv/1`) fall back to
    /// raw JSON with `generation == 0` so pre-B1 vaults still open; re-saving
    /// upgrades them to enveloped form.
    fn decrypt_envelope_json(
        &self,
        identity: &AgeIdentity,
    ) -> Result<(u64, Zeroizing<Vec<u8>>), SecretEntryError> {
        let mut plaintext = age::decrypt_payload(&self.ciphertext, identity)?;
        // Transfer ownership into a page-locked buffer for the brief moment
        // before parsing (`mem::take` leaves an empty buffer in the guard;
        // `HardenedBytes::from_vec` wipes the source).
        let hardened = HardenedBytes::from_vec(std::mem::take(&mut *plaintext))
            .map_err(SecretEntryError::from)?;
        let bytes: &[u8] = hardened.as_ref();
        if !starts_with_magic(bytes) {
            // Legacy (pre-envelope) payload: raw SecretPayload JSON.
            let mut legacy = Zeroizing::new(Vec::with_capacity(bytes.len()));
            legacy.extend_from_slice(bytes);
            return Ok((0, legacy));
        }
        let (generation, payload) = envelope::unwrap_envelope(&self.name, bytes)?;
        if self.generation != 0 && generation != self.generation {
            return Err(SecretEntryError::Tampered {
                path: self.name.clone(),
                reason: "generation mismatch".into(),
            });
        }
        Ok((generation, payload))
    }

    /// Decrypt this entry's payload using an age identity.
    ///
    /// Verifies the envelope path binding (`Tampered{path,reason}` on
    /// mismatch). The decrypted bytes are wrapped in [`HardenedBytes`] for
    /// the brief moment before JSON parsing, so the intermediate buffer is
    /// page-locked and zeroized on drop.
    pub fn decrypt(&self, identity: &AgeIdentity) -> Result<SecretPayload, SecretEntryError> {
        let (_gen, payload_json) = self.decrypt_envelope_json(identity)?;
        let hardened = HardenedBytes::from_slice(&payload_json).map_err(SecretEntryError::from)?;
        let payload: SecretPayload = serde_json::from_slice(hardened.as_ref())?;
        Ok(payload)
    }

    /// Decrypt and return only the primary secret field.
    ///
    /// Unlike [`decrypt`](Self::decrypt), this never materializes the
    /// optional `notes`/`extra` fields as plain owning values: the JSON is
    /// parsed into a minimal view capturing just the `secret` string,
    /// which is returned wrapped in [`Zeroizing`] (wiped on drop).
    pub fn decrypt_secret(
        &self,
        identity: &AgeIdentity,
    ) -> Result<Zeroizing<String>, SecretEntryError> {
        /// Serde view capturing only the primary secret field.
        #[derive(Deserialize)]
        struct SecretFieldOnly {
            secret: String,
        }

        let (_gen, payload_json) = self.decrypt_envelope_json(identity)?;
        let hardened = HardenedBytes::from_slice(&payload_json).map_err(SecretEntryError::from)?;
        let view: SecretFieldOnly = serde_json::from_slice(hardened.as_ref())?;
        Ok(Zeroizing::new(view.secret))
    }

    /// Decrypt and return the primary secret directly as page-locked [`HardenedBytes`].
    ///
    /// This is the hardened counterpart to [`decrypt_secret`](Self::decrypt_secret):
    /// the decrypted age plaintext is page-locked before JSON parsing, and the
    /// primary `secret` field is copied into a `HardenedBytes` buffer (mlock +
    /// `MADV_DONTDUMP` + zeroize-on-drop) before the intermediate `String` is
    /// dropped and zeroized via [`SecretPayload`]'s `Drop`. Callers that need
    /// `mlock` should prefer this over [`decrypt`](Self::decrypt) + `String`
    /// handling.
    pub fn decrypt_hardened(
        &self,
        identity: &AgeIdentity,
    ) -> Result<HardenedBytes, SecretEntryError> {
        let payload = self.decrypt(identity)?;
        let hb =
            HardenedBytes::from_slice(payload.secret.as_bytes()).map_err(SecretEntryError::from)?;
        Ok(hb)
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
            generation: self.generation,
            tombstone: false,
        }
    }
}

fn starts_with_magic(bytes: &[u8]) -> bool {
    let magic = ENVELOPE_MAGIC.as_bytes();
    bytes.len() >= magic.len() && &bytes[..magic.len()] == magic
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

    fn payload_of(secret: &str) -> SecretPayload {
        SecretPayload { secret: secret.into(), notes: None, extra: None }
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
            1,
        )
        .unwrap();

        assert_eq!(entry.name, "GitHub");
        assert_eq!(entry.item_type, ItemType::Password);
        assert_eq!(entry.generation, 1);
        assert_ne!(entry.ciphertext, [] as [u8; 0]);

        let decrypted = entry.decrypt(&id).unwrap();
        assert_eq!(decrypted.secret, "hunter2");
        assert_eq!(decrypted.notes.as_deref(), Some("note"));
    }

    #[test]
    fn envelope_binds_path_swapped_file_fails() {
        let (id, r) = recipient();
        let mut a = SecretEntry::new(
            "alpha",
            ItemType::Password,
            &payload_of("a"),
            SecretMetadata::default(),
            std::slice::from_ref(&r),
            1,
        )
        .unwrap();
        let b = SecretEntry::new(
            "beta",
            ItemType::Password,
            &payload_of("b"),
            SecretMetadata::default(),
            &[r],
            1,
        )
        .unwrap();
        // Swap ciphertexts: `a` now holds `b`'s envelope bound to "beta".
        a.ciphertext = b.ciphertext;
        let err = a.decrypt(&id).unwrap_err();
        assert!(matches!(err, SecretEntryError::Tampered { .. }), "swapped path must fail: {err}");
    }

    #[test]
    fn envelope_binds_gen_header_mismatch_fails() {
        let (id, r) = recipient();
        let mut entry = SecretEntry::new(
            "generation-check",
            ItemType::Password,
            &payload_of("x"),
            SecretMetadata::default(),
            &[r],
            3,
        )
        .unwrap();
        entry.generation = 4;
        let err = entry.decrypt(&id).unwrap_err();
        assert!(
            matches!(err, SecretEntryError::Tampered { .. }),
            "generation mismatch must fail: {err}"
        );
    }

    #[test]
    fn decrypt_secret_returns_only_primary_field() {
        let (id, recipient_str) = recipient();
        let payload = SecretPayload {
            secret: "primary-secret".into(),
            notes: Some("side note".into()),
            extra: Some(serde_json::json!({"k": "v"})),
        };
        let entry = SecretEntry::new(
            "hardened-getter",
            ItemType::Password,
            &payload,
            SecretMetadata::default(),
            &[recipient_str],
            1,
        )
        .unwrap();

        let secret = entry.decrypt_secret(&id).unwrap();
        assert_eq!(secret.as_str(), "primary-secret");
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
            1,
        );
        assert!(matches!(result, Err(SecretEntryError::InvalidName(_))));
    }

    #[test]
    fn zero_gen_rejected() {
        let (_, recipient_str) = recipient();
        let result = SecretEntry::new(
            "name",
            ItemType::Note,
            &payload_of("x"),
            SecretMetadata::default(),
            &[recipient_str],
            0,
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
            SecretEntry::new("name", ItemType::Password, &payload, metadata, &[recipient_str], 2)
                .unwrap();
        let idx = entry.to_index_entry();
        assert_eq!(idx.name, "name");
        assert_eq!(idx.id, entry.id);
        assert_eq!(idx.generation, 2);
        assert!(!idx.tombstone);
        assert_eq!(idx.metadata.url.as_deref(), Some("https://example.com"));
    }

    #[test]
    fn set_payload_rebinds_gen() {
        let (id, r) = recipient();
        let mut entry = SecretEntry::new(
            "rebind",
            ItemType::Password,
            &payload_of("v1"),
            SecretMetadata::default(),
            std::slice::from_ref(&r),
            1,
        )
        .unwrap();
        entry.set_payload(&payload_of("v2"), &[r], 2).unwrap();
        assert_eq!(entry.generation, 2);
        assert_eq!(entry.decrypt(&id).unwrap().secret, "v2");
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
            1,
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
            1,
        )
        .unwrap();

        entry.re_encrypt(&id1, &[recipient_str2]).unwrap();

        assert!(entry.decrypt(&id1).is_err());
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
            1,
        )
        .unwrap();
        let json = serde_json::to_value(&entry).unwrap();
        let ct = json["ciphertext"].as_str().unwrap();
        assert!(BASE64_STANDARD.decode(ct).is_ok());
    }
}
