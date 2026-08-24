// Test code may unwrap/expect/panic (workspace lint phase-1 carve-out).
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]
//! oc-crypto — minimal crypto + memory hardening + post-quantum primitives for OneCipher.
//!
//! Per R51/R52: zero I/O, zero network deps. Owns `HardenedBytes` (mlock + madvise DONTDUMP),
//! the `page_guard` module, the `pqc` module (FIPS 203/204 ML-KEM + ML-DSA), and re-exports
//! `secrecy::SecretBox` as `HardenedKey<T>`.
//!
//! Post-quantum cryptography:
//! - `ml_dsa_65_keygen/sign/verify` — FIPS 204 digital signatures (ML-DSA-65).
//! - `hybrid_kem_combine` — X25519 + post-quantum hybrid shared secret framework. ML-KEM-768 (FIPS
//!   203) encapsulation will be added when the `age` crate's dependency conflict with `ml-kem
//!   0.3.x` is resolved upstream.
//!
//! `unsafe` is confined to the `page_guard` module. We use `#![deny(unsafe_code)]`
//! (rather than `#![forbid(..)]`) at the crate root so that the per-module
//! `#[allow(unsafe_code)]` on `page_guard` can relax the lint there. `forbid`
//! would lock the lint level across the whole crate and prevent any relaxation.

#![deny(unsafe_code)]
#![cfg_attr(docsrs, feature(doc_cfg))]

pub mod hardened;
pub mod key_cache;
pub mod page_guard;
pub mod pqc;

pub use hardened::HardenedBytes;
pub use key_cache::{DEFAULT_MAX_ENTRIES, DEFAULT_TTL, KeyCache};
pub use pqc::{
    MlDsa65Keypair, MlDsaSigningKey, PqcError, hybrid_kem_combine, ml_dsa_65_keygen,
    ml_dsa_65_sign, ml_dsa_65_verify,
};
pub use secrecy::SecretBox as HardenedKey;

/// Constant-time byte-slice equality.
///
/// Use for comparing capability tokens, API tokens and other secrets where a
/// data-dependent early exit (`==` on slices) would leak prefix-match timing
/// to a local attacker. Length differences still short-circuit (length is not
/// treated as secret).
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    if a.len() != b.len() {
        return false;
    }
    bool::from(a.ct_eq(b))
}

#[derive(Debug, thiserror::Error)]
pub enum MemGuardError {
    #[error("mlock failed: {0}")]
    MlockFailed(#[from] std::io::Error),
    #[error("madvise(DONT_DUMP) failed: {0}")]
    MadviseFailed(std::io::Error),
    #[error("VirtualLock failed: {0}")]
    VirtualLockFailed(std::io::Error),
}
