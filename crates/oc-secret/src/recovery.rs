//! Authenticated-recovery anti-planting checks (B6, Phase 2 groundwork).
//!
//! There is currently no staging/journal on disk (the future B5 two-phase
//! rotation will add one). This module provides the validation that the
//! commit path MUST call once staging exists, so Phase 2 only wires I/O:
//!
//! 1. The staged recipient set MUST contain our own recipient. Otherwise a planted staging file
//!    could rotate us out and lock us out.
//! 2. Every staged entry MUST decrypt with our own identity. Otherwise a planted staged ciphertext
//!    could smuggle in data we cannot read (or wedge recovery).
//!
//! Both violations fail closed with [`RecoveryError`].

use crate::{
    age::AgeIdentity,
    entry::SecretEntry,
    recipients::{canonicalize_strings, parse_recipient_strings},
};

/// Errors returned by staged-recovery validation.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum RecoveryError {
    #[error("staged recipients do not contain own recipient")]
    SelfMissing,
    #[error("invalid staged recipient '{0}': {1}")]
    InvalidRecipient(String, String),
    #[error("staged entry '{path}' is not decryptable with own identity")]
    Undecryptable { path: String },
}

/// Validate a staged recipient set contains `own_recipient`.
///
/// The staged list is parsed with comment + first-seen-dedup rules and every
/// entry is validated as an age recipient. Returns the canonical
/// (sorted + deduped) staged set for the commit path.
pub fn verify_staged_recipients(
    staged_content: &str,
    own_recipient: &str,
) -> Result<Vec<String>, RecoveryError> {
    let staged = parse_recipient_strings(staged_content).map_err(|e| match e {
        crate::recipients::RecipientError::InvalidRecipient(who, msg) => {
            RecoveryError::InvalidRecipient(who, msg)
        }
        other => RecoveryError::InvalidRecipient("staged".into(), other.to_string()),
    })?;
    let own = own_recipient.trim();
    if !staged.iter().any(|s| s == own) {
        return Err(RecoveryError::SelfMissing);
    }
    Ok(canonicalize_strings(&staged))
}

/// Validate staged entries are all decryptable with `own_identity`.
///
/// Call after [`verify_staged_recipients`]: even with self in the recipient
/// set, a planted staged file could hold ciphertext for another key.
pub fn verify_staged_entries(
    staged_entries: &[SecretEntry],
    own_identity: &AgeIdentity,
) -> Result<(), RecoveryError> {
    for entry in staged_entries {
        entry
            .decrypt(own_identity)
            .map_err(|_| RecoveryError::Undecryptable { path: entry.name.clone() })?;
    }
    Ok(())
}

/// Combined gate for the future two-phase commit path (B5).
pub fn validate_staged_recovery(
    staged_content: &str,
    own_recipient: &str,
    staged_entries: &[SecretEntry],
    own_identity: &AgeIdentity,
) -> Result<Vec<String>, RecoveryError> {
    let canonical = verify_staged_recipients(staged_content, own_recipient)?;
    verify_staged_entries(staged_entries, own_identity)?;
    Ok(canonical)
}

#[cfg(test)]
mod tests {
    use oc_core::{ItemType, SecretMetadata, SecretPayload};

    use super::*;

    fn identity_pair() -> (AgeIdentity, String) {
        let id = AgeIdentity::generate();
        let r = id.to_recipient_string();
        (id, r)
    }

    fn entry_for(name: &str, recipient: &str, generation: u64) -> SecretEntry {
        let payload = SecretPayload { secret: "s".into(), notes: None, extra: None };
        SecretEntry::new(
            name,
            ItemType::Password,
            &payload,
            SecretMetadata::default(),
            &[recipient.to_string()],
            generation,
        )
        .unwrap()
    }

    #[test]
    fn accepts_self_plus_decryptable_entries() {
        let (id, own) = identity_pair();
        let other = AgeIdentity::generate().to_recipient_string();
        let content = format!("# staged\n{other} # peer\n{own}\n");
        let entries = vec![entry_for("a", &own, 1)];
        let canonical = validate_staged_recovery(&content, &own, &entries, &id).unwrap();
        let mut expected = vec![own, other];
        expected.sort();
        assert_eq!(canonical, expected);
    }

    #[test]
    fn rejects_staging_without_self() {
        let (id, own) = identity_pair();
        let other = AgeIdentity::generate().to_recipient_string();
        let entries = vec![entry_for("a", &other, 1)];
        let err = validate_staged_recovery(&other, &own, &entries, &id).unwrap_err();
        assert_eq!(err, RecoveryError::SelfMissing);
    }

    #[test]
    fn rejects_undecryptable_staged_entry() {
        let (id, own) = identity_pair();
        let attacker = AgeIdentity::generate();
        let attacker_recipient = attacker.to_recipient_string();
        // Staged set contains self, but the staged entry is encrypted to the
        // attacker only: self cannot decrypt it.
        let content = format!("{own}\n{attacker_recipient}\n");
        let planted = entry_for("planted", &attacker_recipient, 1);
        let err = validate_staged_recovery(&content, &own, std::slice::from_ref(&planted), &id)
            .unwrap_err();
        assert_eq!(err, RecoveryError::Undecryptable { path: "planted".into() });
    }

    #[test]
    fn rejects_invalid_staged_recipient() {
        let (id, own) = identity_pair();
        let content = format!("{own}\nnot-a-recipient\n");
        let err = validate_staged_recovery(&content, &own, &[], &id).unwrap_err();
        assert!(matches!(err, RecoveryError::InvalidRecipient(_, _)));
    }
}
