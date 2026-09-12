//! Unified CRUD over the secret store for all four [`SecretKind`] states.
//!
//! Wallet keys, passwords, OTP seeds and notes share one handling plane:
//! one `create / read / update / delete / rename / copy` surface that maps
//! [`SecretKind`] to the on-disk [`ItemType`], allocates the monotonic
//! generation, and binds the path envelope. The `secret`, `password` and
//! `totp` CLI families all delegate here instead of re-implementing entry
//! construction.
//!
//! # Storage boundary (unchanged)
//!
//! This module only handles age-encrypted entries in [`SecretStore`]. Legacy
//! keystore wallet files (`oc-vault`) and API tokens (`oc-wallet::key_store`)
//! keep their own storage; they join the unified plane through the shared
//! [`SecretKind`], [`SecretEnvelope`](oc_core::SecretEnvelope) and
//! [`AuditOp`](oc_core::AuditOp) taxonomy, not through this CRUD.
//!
//! # Memory rule
//!
//! Secret values enter as [`HardenedBytes`] and are converted to the
//! JSON-compatible `String` payload at exactly one place
//! ([`payload_from_hardened`], the documented `--json`/serde boundary).

use std::collections::BTreeMap;

use oc_core::{
    ItemType, SecretEnvelope, SecretIndexEntry, SecretKind, SecretMetadata, SecretPayload,
};
use oc_crypto::HardenedBytes;

use crate::{
    age::AgeIdentity,
    entry::SecretEntry,
    store::{SecretStore, SecretStoreError},
};

/// Build a [`SecretPayload`] from hardened secret bytes.
///
/// Single conversion point from page-locked memory to the JSON-compatible
/// payload: the UTF-8 check happens here, and the resulting `String` is
/// owned by a payload whose [`Drop`](SecretPayload) zeroizes on drop.
pub fn payload_from_hardened(
    secret: &HardenedBytes,
    notes: Option<String>,
    extra: Option<serde_json::Value>,
) -> Result<SecretPayload, SecretStoreError> {
    let text = std::str::from_utf8(secret.expose()).map_err(|_| {
        SecretStoreError::InvalidName("secret material is not valid UTF-8".to_string())
    })?;
    Ok(SecretPayload { secret: text.to_string(), notes, extra })
}

/// Create a new entry of any [`SecretKind`] and persist it.
///
/// Allocates `next_generation(name)` internally so callers cannot bind a
/// stale generation. Fails with `AlreadyExists`-style semantics when a live
/// entry already holds `name`: callers that intend an overwrite must
/// [`update_secret`] instead.
pub fn create_entry(
    store: &SecretStore,
    kind: SecretKind,
    name: &str,
    secret: &HardenedBytes,
    metadata: SecretMetadata,
    recipients: &[String],
) -> Result<SecretEntry, SecretStoreError> {
    create_entry_full(store, kind, name, secret, None, None, metadata, recipients)
}

/// Create a new entry with optional notes/extra fields.
#[allow(clippy::too_many_arguments)]
pub fn create_entry_full(
    store: &SecretStore,
    kind: SecretKind,
    name: &str,
    secret: &HardenedBytes,
    notes: Option<String>,
    extra: Option<serde_json::Value>,
    metadata: SecretMetadata,
    recipients: &[String],
) -> Result<SecretEntry, SecretStoreError> {
    if recipients.is_empty() {
        return Err(SecretStoreError::InvalidName(
            "no recipients found — run `onecipher age init` first".to_string(),
        ));
    }
    if store.list()?.iter().any(|e| e.name == name) {
        return Err(SecretStoreError::AlreadyExists(name.to_string()));
    }
    let payload = payload_from_hardened(secret, notes, extra)?;
    let generation = store.next_generation(name)?;
    let entry = SecretEntry::new(
        name,
        kind_to_item_type(kind, &payload),
        &payload,
        metadata,
        recipients,
        generation,
    )?;
    store.put(&entry)?;
    Ok(entry)
}

/// Read an entry by name (index agreement + envelope binding verified).
pub fn read_entry(store: &SecretStore, name: &str) -> Result<SecretEntry, SecretStoreError> {
    store.get(name)
}

/// Replace the secret value of an existing entry, keeping metadata.
///
/// Binds the next generation and re-encrypts to `recipients`.
pub fn update_secret(
    store: &SecretStore,
    identity: &AgeIdentity,
    name: &str,
    secret: &HardenedBytes,
    recipients: &[String],
) -> Result<SecretEntry, SecretStoreError> {
    if recipients.is_empty() {
        return Err(SecretStoreError::InvalidName(
            "no recipients found — run `onecipher age init` first".to_string(),
        ));
    }
    let mut entry = store.get(name)?;
    let mut payload = entry.decrypt(identity).map_err(|e| {
        SecretStoreError::InvalidName(format!("decryption failed for '{name}': {e}"))
    })?;
    let text = std::str::from_utf8(secret.expose()).map_err(|_| {
        SecretStoreError::InvalidName("secret material is not valid UTF-8".to_string())
    })?;
    // Single String-boundary copy; the old secret zeroizes with the payload drop.
    payload.secret = text.to_string();
    let next_gen = store.next_generation(name)?;
    entry.set_payload(&payload, recipients, next_gen)?;
    store.put(&entry)?;
    Ok(entry)
}

/// Delete an entry (ciphertext removed, tombstone row kept).
pub fn delete_entry(store: &SecretStore, name: &str) -> Result<(), SecretStoreError> {
    store.delete(name)
}

/// Rename an entry, rebinding the envelope to the new path.
pub fn rename_entry(
    store: &SecretStore,
    old: &str,
    new: &str,
    identity: &AgeIdentity,
    recipients: &[String],
) -> Result<(), SecretStoreError> {
    store.rename(old, new, identity, recipients)
}

/// Copy an entry to a new name.
///
/// Without `force`, an existing destination is refused. With `force`, the
/// destination is overwritten at its own next generation.
pub fn copy_entry(
    store: &SecretStore,
    identity: &AgeIdentity,
    src: &str,
    dst: &str,
    force: bool,
    recipients: &[String],
) -> Result<SecretEntry, SecretStoreError> {
    if recipients.is_empty() {
        return Err(SecretStoreError::InvalidName(
            "no recipients found — run `onecipher age init` first".to_string(),
        ));
    }
    if !force && store.list()?.iter().any(|e| e.name == dst) {
        return Err(SecretStoreError::AlreadyExists(dst.to_string()));
    }
    let src_entry = store.get(src)?;
    let payload = src_entry.decrypt(identity).map_err(|e| {
        SecretStoreError::InvalidName(format!("decryption failed for '{src}': {e}"))
    })?;
    let dst_gen = store.next_generation(dst)?;
    let new_entry = SecretEntry::new(
        dst,
        src_entry.item_type,
        &payload,
        src_entry.metadata,
        recipients,
        dst_gen,
    )?;
    store.put(&new_entry)?;
    Ok(new_entry)
}

/// Build the unified `--json` envelope for a disclosure read.
pub fn disclose_envelope(entry: &SecretEntry, payload: SecretPayload) -> SecretEnvelope {
    SecretEnvelope::with_payload(
        entry.name.clone(),
        entry.id.clone(),
        entry.item_type,
        entry.metadata.clone(),
        entry.generation,
        payload,
    )
}

/// Live + tombstone counts per [`SecretKind`] over the whole index.
///
/// Covers all four handling states in one pass (tombstones keep their
/// deleted entry's kind). Used by `doctor` / `fsck`-style joint checks so
/// wallet keys, passwords, OTP seeds and notes are all visible.
pub fn census_by_kind(
    store: &SecretStore,
) -> Result<BTreeMap<SecretKind, (usize, usize)>, SecretStoreError> {
    let mut out: BTreeMap<SecretKind, (usize, usize)> = BTreeMap::new();
    for kind in SecretKind::all() {
        out.insert(*kind, (0, 0));
    }
    for row in store.list_all()? {
        let kind = SecretKind::from_item_type(row.item_type);
        if let Some(slot) = out.get_mut(&kind) {
            if row.tombstone {
                slot.1 += 1;
            } else {
                slot.0 += 1;
            }
        }
    }
    Ok(out)
}

/// Live index rows for a single [`SecretKind`].
pub fn list_by_kind(
    store: &SecretStore,
    kind: SecretKind,
) -> Result<Vec<SecretIndexEntry>, SecretStoreError> {
    Ok(store
        .list()?
        .into_iter()
        .filter(|e| SecretKind::from_item_type(e.item_type) == kind)
        .collect())
}

/// Resolve the on-disk [`ItemType`] for a creation request.
///
/// `WalletKey` is content-sniffed: payloads that parse as a JSON key pair
/// (`{"secp256k1":..,"ed25519":..}`) are stored as `PrivateKey`, everything
/// else as `Mnemonic`. All other kinds map 1:1.
fn kind_to_item_type(kind: SecretKind, payload: &SecretPayload) -> ItemType {
    match kind {
        SecretKind::WalletKey => {
            if is_key_pair_json(&payload.secret) {
                ItemType::PrivateKey
            } else {
                ItemType::Mnemonic
            }
        }
        SecretKind::Password => ItemType::Password,
        SecretKind::TotpSeed => ItemType::Totp,
        SecretKind::Note => ItemType::Note,
    }
}

/// Best-effort key-pair JSON sniff (never fails closed on weird input:
/// non-JSON simply means `Mnemonic`).
fn is_key_pair_json(secret: &str) -> bool {
    let trimmed = secret.trim_start();
    if !trimmed.starts_with('{') {
        return false;
    }
    serde_json::from_str::<serde_json::Value>(trimmed).is_ok_and(|v| {
        v.get("secp256k1").and_then(|k| k.as_str()).is_some() ||
            v.get("ed25519").and_then(|k| k.as_str()).is_some()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::StoreConfig;

    fn test_store() -> (tempfile::TempDir, SecretStore, AgeIdentity, String) {
        let dir = tempfile::tempdir().unwrap();
        let store = SecretStore::open(StoreConfig::new(dir.path().to_path_buf())).unwrap();
        let id = AgeIdentity::generate();
        let recipient = id.to_recipient_string();
        (dir, store, id, recipient)
    }

    fn hardened(secret: &str) -> HardenedBytes {
        HardenedBytes::from_slice(secret.as_bytes()).unwrap()
    }

    #[test]
    fn create_and_read_all_four_kinds() {
        let (_dir, store, id, recipient) = test_store();
        let recipients = vec![recipient];
        let cases = [
            (SecretKind::Password, "pw/1", "hunter2-hunter2"),
            (SecretKind::TotpSeed, "otp/1", "otpauth://totp/A:b?secret=JBSWY3DPEHPK3PXP&issuer=A"),
            (SecretKind::Note, "note/1", "remember the milk"),
            (
                SecretKind::WalletKey,
                "wallet/1",
                "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            ),
        ];
        for (kind, name, secret) in cases {
            let entry = create_entry(
                &store,
                kind,
                name,
                &hardened(secret),
                SecretMetadata::default(),
                &recipients,
            )
            .unwrap();
            assert_eq!(SecretKind::from_item_type(entry.item_type), kind);
            let loaded = read_entry(&store, name).unwrap();
            assert_eq!(loaded.decrypt(&id).unwrap().secret, secret);
        }
    }

    #[test]
    fn wallet_key_pair_json_maps_to_private_key() {
        let (_dir, store, _id, recipient) = test_store();
        let pair = r#"{"secp256k1":"4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318","ed25519":"9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"}"#;
        let entry = create_entry(
            &store,
            SecretKind::WalletKey,
            "wallets/pk",
            &hardened(pair),
            SecretMetadata::default(),
            &[recipient],
        )
        .unwrap();
        assert_eq!(entry.item_type, ItemType::PrivateKey);
    }

    #[test]
    fn create_duplicate_is_rejected() {
        let (_dir, store, _id, recipient) = test_store();
        let recipients = vec![recipient];
        create_entry(
            &store,
            SecretKind::Note,
            "dup",
            &hardened("a"),
            SecretMetadata::default(),
            &recipients,
        )
        .unwrap();
        let err = create_entry(
            &store,
            SecretKind::Note,
            "dup",
            &hardened("b"),
            SecretMetadata::default(),
            &recipients,
        )
        .unwrap_err();
        assert!(matches!(err, SecretStoreError::AlreadyExists(_)));
    }

    #[test]
    fn create_without_recipients_fails_closed() {
        let (_dir, store, _id, _r) = test_store();
        let err = create_entry(
            &store,
            SecretKind::Note,
            "x",
            &hardened("a"),
            SecretMetadata::default(),
            &[],
        )
        .unwrap_err();
        assert!(matches!(err, SecretStoreError::InvalidName(_)));
    }

    #[test]
    fn update_replace_secret_value() {
        let (_dir, store, id, recipient) = test_store();
        let recipients = vec![recipient];
        create_entry(
            &store,
            SecretKind::Password,
            "pw",
            &hardened("old-value-1"),
            SecretMetadata::default(),
            &recipients,
        )
        .unwrap();
        let updated =
            update_secret(&store, &id, "pw", &hardened("new-value-2"), &recipients).unwrap();
        assert_eq!(updated.generation, 2);
        assert_eq!(read_entry(&store, "pw").unwrap().decrypt(&id).unwrap().secret, "new-value-2");
    }

    #[test]
    fn copy_and_rename_round_trip() {
        let (_dir, store, id, recipient) = test_store();
        let recipients = std::slice::from_ref(&recipient);
        create_entry(
            &store,
            SecretKind::Note,
            "src",
            &hardened("body"),
            SecretMetadata::default(),
            recipients,
        )
        .unwrap();
        let copied = copy_entry(&store, &id, "src", "dst", false, recipients).unwrap();
        assert_eq!(copied.name, "dst");
        assert_eq!(copied.decrypt(&id).unwrap().secret, "body");
        // Second copy without force is refused.
        assert!(copy_entry(&store, &id, "src", "dst", false, recipients).is_err());
        // Force overwrites.
        assert!(copy_entry(&store, &id, "src", "dst", true, recipients).is_ok());
        rename_entry(&store, "src", "moved", &id, recipients).unwrap();
        assert!(read_entry(&store, "src").is_err());
        assert_eq!(read_entry(&store, "moved").unwrap().decrypt(&id).unwrap().secret, "body");
    }

    #[test]
    fn census_by_kind_covers_live_and_tombstones() {
        let (_dir, store, _id, recipient) = test_store();
        let recipients = vec![recipient];
        create_entry(
            &store,
            SecretKind::Password,
            "a",
            &hardened("x-1"),
            SecretMetadata::default(),
            &recipients,
        )
        .unwrap();
        create_entry(
            &store,
            SecretKind::TotpSeed,
            "b",
            &hardened("y-1"),
            SecretMetadata::default(),
            &recipients,
        )
        .unwrap();
        delete_entry(&store, "b").unwrap();
        let census = census_by_kind(&store).unwrap();
        assert_eq!(census[&SecretKind::Password], (1, 0));
        assert_eq!(census[&SecretKind::TotpSeed], (0, 1));
        assert_eq!(census[&SecretKind::Note], (0, 0));
        assert_eq!(census[&SecretKind::WalletKey], (0, 0));
    }

    #[test]
    fn disclose_envelope_carries_kind() {
        let (_dir, store, id, recipient) = test_store();
        let entry = create_entry(
            &store,
            SecretKind::TotpSeed,
            "otp",
            &hardened("seed-value"),
            SecretMetadata::default(),
            &[recipient],
        )
        .unwrap();
        let payload = entry.decrypt(&id).unwrap();
        let env = disclose_envelope(&entry, payload);
        assert_eq!(env.kind, SecretKind::TotpSeed);
        assert_eq!(env.item_type, ItemType::Totp);
        assert!(env.payload.is_some());
    }
}
