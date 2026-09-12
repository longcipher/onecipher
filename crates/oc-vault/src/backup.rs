//! Age-encrypted backup bundles (`.ocbk`).
//!
//! A bundle wraps a payload (the JSON-serialized wallet list) in an `ocenv/1`
//! envelope binding the `backup` domain tag and the export time, then
//! age-encrypts it to one or more X25519 recipients. The `.ocbk` file holds
//! the resulting [`AgeEnvelope`](crate::crypto::AgeEnvelope) as pretty JSON.
//!
//! ```text
//! ocenv/1
//! tag:backup
//! path:backup
//! generation:<export unix time>
//!
//! <payload bytes>
//! ```
//!
//! `tag:backup` domain-separates backup bundles from secret entries
//! (`tag:secret` in `oc-secret`) and wallet blobs so the three can never be
//! confused at import. `path` is the constant `backup`: binding the export
//! file name would break legitimate copies/renames between export and import.
//! `generation` records the export time for operator visibility; it is
//! returned (not enforced) on import because backups have no monotonic index
//! to compare against — see the N1 honest limitation in
//! `docs/security-model.md`, which applies here as well: a joint rollback of
//! a bundle together with every copy of it is indistinguishable from an
//! intentional restore.
//!
//! There is no passphrase path and therefore no brute-force lockout: a bundle
//! decrypts only under one of its recipient identities. A wrong identity
//! fails closed as [`OcVaultError::Crypto`].

use std::time::{SystemTime, UNIX_EPOCH};

use crate::{
    crypto::{AgeEnvelope, AgeIdentity, decrypt_with_identity, encrypt_to_recipients},
    error::OcVaultError,
};

/// Domain-separation tag for backup bundles inside the `ocenv/1` envelope.
pub const BACKUP_TAG: &str = "backup";

/// Fixed envelope path for backup bundles (see module docs).
pub const BACKUP_PATH: &str = "backup";

/// Envelope magic shared with `oc-secret` (`onecipher envelope v1`).
const ENVELOPE_MAGIC: &str = "ocenv/1";

/// Current export time as unix seconds (0 when the clock is before the epoch).
fn export_time_unix() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

/// Wrap `payload` in the `ocenv/1` backup envelope at `generation`.
fn wrap_backup_envelope(payload: &[u8], generation: u64) -> Vec<u8> {
    let header = format!(
        "{ENVELOPE_MAGIC}\ntag:{BACKUP_TAG}\npath:{BACKUP_PATH}\ngeneration:{generation}\n\n"
    );
    let mut out = Vec::with_capacity(header.len() + payload.len());
    out.extend_from_slice(header.as_bytes());
    out.extend_from_slice(payload);
    out
}

/// Unwrap and verify a backup envelope, returning `(generation, payload)`.
///
/// Every malformed input fails closed as [`OcVaultError::InvalidFormat`];
/// this function never panics on attacker-controlled bytes.
///
/// # Errors
///
/// Returns [`OcVaultError::InvalidFormat`] for a missing separator, bad
/// magic, wrong tag, path mismatch, or malformed generation.
fn unwrap_backup_envelope(data: &[u8]) -> Result<(u64, Vec<u8>), OcVaultError> {
    let invalid = |reason: &str| OcVaultError::InvalidFormat(format!("backup bundle: {reason}"));
    let sep = data
        .windows(2)
        .position(|w| w == b"\n\n")
        .ok_or_else(|| invalid("missing header/payload separator"))?;
    let (header_bytes, rest) = data.split_at(sep);
    let payload = rest.get(2..).ok_or_else(|| invalid("missing payload"))?;
    let header = std::str::from_utf8(header_bytes).map_err(|_| invalid("header is not UTF-8"))?;
    let mut lines = header.split('\n');
    if lines.next() != Some(ENVELOPE_MAGIC) {
        return Err(invalid("bad magic"));
    }
    if lines.next() != Some("tag:backup") {
        return Err(invalid("bad tag"));
    }
    if lines.next() != Some("path:backup") {
        return Err(invalid("path mismatch"));
    }
    let generation: u64 = lines
        .next()
        .and_then(|l| l.strip_prefix("generation:"))
        .filter(|t| !t.is_empty() && t.bytes().all(|b| b.is_ascii_digit()))
        .and_then(|t| t.parse().ok())
        .ok_or_else(|| invalid("bad generation"))?;
    if lines.next().is_some() {
        return Err(invalid("extra header line"));
    }
    Ok((generation, payload.to_vec()))
}

/// Export `payload` as an age-encrypted backup bundle for `recipients`.
///
/// Returns the `.ocbk` file bytes (pretty-printed [`AgeEnvelope`] JSON).
/// At least one recipient is required; an empty list fails closed without
/// touching the payload.
///
/// # Errors
///
/// Returns [`OcVaultError::Crypto`] when age encryption fails (including an
/// empty or unparseable recipient list) and [`OcVaultError::Serde`] when the
/// envelope cannot be serialized.
pub fn export_backup(payload: &[u8], recipients: &[String]) -> Result<Vec<u8>, OcVaultError> {
    let wrapped = wrap_backup_envelope(payload, export_time_unix());
    let envelope = encrypt_to_recipients(&wrapped, recipients)
        .map_err(|e| OcVaultError::Crypto(e.to_string()))?;
    serde_json::to_vec_pretty(&envelope).map_err(OcVaultError::Serde)
}

/// Import a backup bundle produced by [`export_backup`].
///
/// Returns `(generation, payload)` where `generation` is the export unix time
/// recorded at export. `identity` must be one of the export recipients.
///
/// # Errors
///
/// Returns [`OcVaultError::InvalidFormat`] for bytes that are not a backup
/// bundle, and [`OcVaultError::Crypto`] when `identity` matches no recipient
/// stanza or the ciphertext is tampered.
pub fn import_backup(data: &[u8], identity: &AgeIdentity) -> Result<(u64, Vec<u8>), OcVaultError> {
    let envelope: AgeEnvelope = serde_json::from_slice(data)
        .map_err(|e| OcVaultError::InvalidFormat(format!("not an age backup bundle: {e}")))?;
    let raw = decrypt_with_identity(&envelope, identity)
        .map_err(|e| OcVaultError::Crypto(e.to_string()))?;
    unwrap_backup_envelope(raw.expose())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn recipients(ids: &[AgeIdentity]) -> Vec<String> {
        ids.iter().map(AgeIdentity::to_recipient_string).collect()
    }

    #[test]
    fn round_trip_single_recipient() {
        let id = AgeIdentity::generate();
        let payload = b"wallet list json";
        let data = export_backup(payload, &[id.to_recipient_string()]).unwrap();
        let (generation, out) = import_backup(&data, &id).unwrap();
        assert_eq!(out, payload);
        assert!(generation > 0);
    }

    #[test]
    fn round_trip_multi_recipient() {
        let id1 = AgeIdentity::generate();
        let id2 = AgeIdentity::generate();
        let recips = recipients(&[id1.clone(), id2.clone()]);
        let payload = vec![0xABu8; 512];
        let data = export_backup(&payload, &recips).unwrap();
        let (_, out1) = import_backup(&data, &id1).unwrap();
        let (_, out2) = import_backup(&data, &id2).unwrap();
        assert_eq!(out1, payload);
        assert_eq!(out2, payload);
    }

    #[test]
    fn wrong_identity_fails() {
        let id1 = AgeIdentity::generate();
        let id2 = AgeIdentity::generate();
        let data = export_backup(b"secret", &[id1.to_recipient_string()]).unwrap();
        assert!(matches!(import_backup(&data, &id2), Err(OcVaultError::Crypto(_))));
    }

    #[test]
    fn empty_recipients_rejected() {
        assert!(matches!(export_backup(b"x", &[]), Err(OcVaultError::Crypto(_))));
    }

    #[test]
    fn invalid_recipient_rejected() {
        assert!(matches!(
            export_backup(b"x", &["not-a-recipient".to_string()]),
            Err(OcVaultError::Crypto(_))
        ));
    }

    #[test]
    fn non_bundle_bytes_rejected() {
        let id = AgeIdentity::generate();
        assert!(matches!(
            import_backup(b"definitely not a bundle", &id),
            Err(OcVaultError::InvalidFormat(_))
        ));
        assert!(matches!(
            import_backup(b"{\"cipher\":\"age\"}", &id),
            Err(OcVaultError::InvalidFormat(_))
        ));
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let id = AgeIdentity::generate();
        let data = export_backup(b"secret", &[id.to_recipient_string()]).unwrap();
        let mut envelope: AgeEnvelope = serde_json::from_slice(&data).unwrap();
        envelope.ciphertext.push_str("AA");
        let tampered = serde_json::to_vec(&envelope).unwrap();
        assert!(import_backup(&tampered, &id).is_err());
    }

    #[test]
    fn envelope_tampering_detected() {
        // Wrong domain tag fails closed at unwrap time.
        assert!(
            unwrap_backup_envelope(b"ocenv/1\ntag:secret\npath:backup\ngeneration:1\n\n{}")
                .is_err()
        );
        // Path mismatch fails closed.
        assert!(
            unwrap_backup_envelope(b"ocenv/1\ntag:backup\npath:other\ngeneration:1\n\n{}").is_err()
        );
        // Malformed generations fail closed, never panic.
        for data in [
            vec![],
            b"".to_vec(),
            b"garbage".to_vec(),
            b"ocenv/1\n".to_vec(),
            b"badmagic\ntag:backup\npath:backup\ngeneration:1\n\n{}".to_vec(),
            b"ocenv/1\ntag:backup\npath:backup\ngeneration:abc\n\n{}".to_vec(),
            b"ocenv/1\ntag:backup\npath:backup\ngeneration:\n\n{}".to_vec(),
            b"ocenv/1\ntag:backup\npath:backup\ngeneration:1\nextra:x\n\n{}".to_vec(),
            vec![0xff, 0xfe, 0x0a, 0x0a],
        ] {
            assert!(unwrap_backup_envelope(&data).is_err(), "should reject {data:?}");
        }
    }

    #[test]
    fn wrap_unwrap_roundtrip() {
        let (generation, out) = unwrap_backup_envelope(&wrap_backup_envelope(b"{}", 42)).unwrap();
        assert_eq!(generation, 42);
        assert_eq!(out, b"{}");
    }
}
