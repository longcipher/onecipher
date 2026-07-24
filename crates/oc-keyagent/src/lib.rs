//! oc-keyagent — Key-Agent main loop (sync, NO tokio).
//!
//! Per R55/R56/AD-01, the Key-Agent uses `std::os::unix::net::UnixListener`
//! and `std::thread` (NO async runtime). It listens on UDS, decodes `prost`
//! frames, and dispatches to handlers. Sandbox (T12), memory hardening (T13),
//! audit log (T14), Passkey verification (T15), and Policy integration (T16)
//! are all implemented in the modules below.

#![deny(unsafe_code)]

pub mod audit;
pub mod engine;
pub mod error;
pub mod frame;
pub mod handler;
pub mod key_ops;
pub mod passkey;
pub mod policy_integration;
pub mod proto;
pub mod request;
pub mod response;
pub mod sandbox;
pub mod server;
pub mod signing_core_error;

pub use audit::{AuditEntry, AuditError, AuditLog, EventType};
pub use engine::{SignRequest, SignResult, SigningEngine};
pub use error::KeyAgentError;
pub use frame::{FrameClient, FrameClientError, FrameError, read_frame, write_frame};
pub use key_ops::{decrypt_mnemonic, derive_chain_key};
// Re-export key types for convenience (formerly in oc-signing-core).
pub use oc_core::{Passphrase, UnlockToken, WalletId};
pub use passkey::{PasskeyError, PasskeyPubkey, PasskeyVerifier};
pub use policy_integration::PolicyIntegration;
// Re-export IPC wire types at the crate root so downstream crates can use
// `oc_keyagent::PayX402Request` etc. (replaces the former `oc-proto` crate).
pub use proto::*;
pub use request::{KeyAgentRequest, KeyAgentRequestKind};
pub use response::{KeyAgentResponse, KeyAgentResponseKind};
pub use sandbox::apply_sandbox;
pub use server::{handle_conn, run};
pub use signing_core_error::SigningCoreError;

/// Type alias for the process-wide key cache.
///
/// Delegates to [`oc_crypto::KeyCache`] parameterized over [`oc_crypto::HardenedBytes`]
/// so cached derived keys are page-locked + zeroized on eviction / drop.
/// Per R77: single process-wide cache, 5s TTL, 32 LRU entries.
pub type KeyCache = oc_crypto::KeyCache<oc_crypto::HardenedBytes>;

use std::sync::OnceLock;

static GLOBAL_KEY_CACHE: OnceLock<KeyCache> = OnceLock::new();

/// Returns the process-wide key cache (5s TTL, max 32 entries).
///
/// Per R77: a single process-wide cache is sufficient for the Key-Agent
/// (per-connection thread model, single wallet per process for T13 MVP). The
/// cache is initialized lazily on first access.
pub fn global_key_cache() -> &'static KeyCache {
    GLOBAL_KEY_CACHE.get_or_init(KeyCache::default)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_global_cache_returns_same_instance() {
        let a = global_key_cache();
        let b = global_key_cache();
        // Same static reference (OnceLock guarantees single init).
        assert!(std::ptr::eq(a, b));
    }
}
