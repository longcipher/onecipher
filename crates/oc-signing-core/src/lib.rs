#![deny(unsafe_code)]

//! OneCipher Signing Core — sync-only facade over the signing pipeline.
//!
//! This crate aggregates `oc-policy` + `oc-crypto` + `oc-signer` + `oc-vault`
//! + `oc-keyagent` into a single sync API surface. It is the R56-enforced leaf crate: CI verifies
//!   it has zero async/network dependencies.
//!
//! The main entry point is [`SigningEngine`], which is called from the async
//! layer via `tokio::task::spawn_blocking`.

pub mod engine;
pub mod error;

pub use engine::{SignRequest, SignResult, SigningEngine};
pub use error::SigningCoreError;
// Re-export key types for convenience.
pub use oc_core::{Passphrase, UnlockToken, WalletId};
pub use oc_keyagent::{
    audit::{AuditLog, DeviceKeyStore, EventType},
    frame, handler,
    passkey::{PasskeyPubkeyStore, PasskeyVerifier, StoredPasskeyPubkey},
    request, response,
};
