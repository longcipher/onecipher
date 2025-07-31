//! Unified secret vault with age encryption.
//!
//! Provides a single interface for managing all sensitive data: wallet
//! mnemonics, private keys, passwords, TOTP seeds, and encrypted notes.
//! All secrets are encrypted with age (X25519 or scrypt passphrase),
//! stored as individual files in a directory tree.
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
mod entry;
mod recipients;
mod store;

#[cfg(feature = "git")]
pub mod git;
pub mod migrate;
pub mod totp;

pub use age::{AgeError, AgeIdentity, decrypt_payload, decrypt_with_passphrase, encrypt_payload};
pub use entry::{SecretEntry, SecretEntryError};
pub use oc_core::{ItemType, SecretIndexEntry, SecretMetadata, SecretPayload};
pub use recipients::{Recipient, RecipientError, RecipientsFile};
pub use store::{SecretStore, SecretStoreError, StoreConfig};
