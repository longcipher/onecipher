// Test code may unwrap/expect/panic (workspace lint phase-1 carve-out).
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]
//! Unified secret vault with age encryption.
//!
//! Provides a single interface for managing all sensitive data: wallet
//! mnemonics, private keys, passwords, TOTP seeds, and encrypted notes.
//! All secrets are encrypted with age (X25519 or scrypt passphrase),
//! stored as individual files in a directory tree.
//!
//! Each ciphertext wraps an `ocenv/1` envelope binding the lookup path and a
//! monotonic generation (`envelope::wrap_envelope`); `delete` keeps a
//! tombstone row so replays of old ciphertext fail closed. See N1 below.
//!
//! # N1 — what integrity does NOT cover (honest limitation)
//!
//! A joint rollback of a ciphertext file *together with* its index row (or a
//! whole-commit restore, e.g. `git revert` / filesystem snapshot restore) is
//! NOT detected and is indistinguishable from an intentional restore: the
//! envelope `generation` and the index floor agree again after the rollback. Only
//! single-sided replays (old file under a newer index, resurrected tombstone,
//! swapped paths) fail closed. Operators who need rollback evidence must rely
//! on external append-only audit/history outside the vault directory.
//!
//! # Hard-gate compliance
//!
//! - **R56:** No `tokio` / `reqwest` / `tungstenite` / `hyper` / `async-std` / `smol` dependencies
//!   — synchronous `std` only.
//! - **R51/R52:** The `age` dependency lives here, NOT in `oc-crypto` (which remains zero-I/O, zero
//!   network deps).
//! - All key material flows through [`oc_crypto::HardenedBytes`] (page-locked
//!   + zeroized on drop).

#![deny(unsafe_code)]

mod age;
pub mod crud;
mod entry;
pub mod envelope;
pub mod generations;
pub mod journal;
pub mod pass;
pub mod password;
pub mod path;
pub mod protection;
mod recipients;
pub mod recovery;
mod store;

#[cfg(feature = "git")]
pub mod git;
pub mod migrate;
pub mod totp;

pub use age::{AgeError, AgeIdentity, decrypt_payload, decrypt_with_passphrase, encrypt_payload};
pub use crud::{
    census_by_kind, copy_entry, create_entry, create_entry_full, delete_entry, disclose_envelope,
    list_by_kind, payload_from_hardened, read_entry, rename_entry, update_secret,
};
pub use entry::{SecretEntry, SecretEntryError};
pub use envelope::{ENVELOPE_MAGIC, ENVELOPE_TAG, EnvelopeError, unwrap_envelope, wrap_envelope};
pub use oc_core::{
    AuditOp, AuditTrack, ItemType, SecretEnvelope, SecretIndexEntry, SecretKind, SecretMetadata,
    SecretPayload,
};
pub use password::{
    MEMORABLE_SYMBOLS, PASSWORD_DEFAULT_LENGTH, PASSWORD_MIN_LENGTH, PasswordCharset,
    PasswordError, PasswordGenerator, PasswordOptions, WORDLIST, generate, generate_memorable,
    generate_password, generate_with_charset, generate_xkcd, password_strength,
};
pub use path::{
    ENTRY_EXTENSION, MAX_PATH_LEN, PathError, collect_entry_files, to_file, validate_path,
};
pub use recipients::{
    Recipient, RecipientError, RecipientsFile, canonicalize_strings, merge_strings,
    parse_recipient_strings,
};
pub use recovery::{
    RecoveryError, validate_staged_recovery, verify_staged_entries, verify_staged_recipients,
};
pub use store::{SecretStore, SecretStoreError, StoreConfig};
