//! R54 key-handling flow: decrypt mnemonic into `HardenedBytes`, derive chain
//! key, cache briefly (5s TTL, 32 LRU), zeroize on `Drop`.
//!
//! Full flow (per `tasks.md` T13 + design R54):
//! 1. `decrypt_mnemonic(vault, key)` — reads the encrypted wallet blob via
//!    `oc_vault::Vault::decrypt`, which returns `HardenedBytes` directly. The decrypted mnemonic
//!    bytes are page-locked + DONT_DUMP-marked + zeroized on `Drop`. No re-wrap needed —
//!    `HardenedBytes` IS the hardened wrapper.
//! 2. `derive_chain_key(mnemonic, chain)` — parses the mnemonic via `oc_signer::Mnemonic`, runs
//!    BIP-44 (EVM) or SLIP-10 (Solana) derivation via `oc_signer::HdDeriver`, returns the 32-byte
//!    private key wrapped in `HardenedBytes`. Caches by chain id (5s TTL, 32 LRU).
//! 3. Caller signs, then drops both `HardenedBytes` (mnemonic + chain key) → auto zeroize +
//!    munlock. The cache may retain a clone of the chain key for up to 5s; after TTL expiry it is
//!    reaped and zeroized.
//!
//! Per `#![deny(unsafe_code)]` at the crate root, this module uses ZERO
//! `unsafe` blocks. All mlock / munlock / zeroize happens inside
//! `HardenedBytes` (in `oc-crypto`).
//!
//! ## Deviation from spec signature (ponytail YAGNI step 1)
//!
//! The T13 task spec wrote the signature as
//! `decrypt_mnemonic(...) -> Result<HardenedKey<Mnemonic>, KeyAgentError>`.
//! `HardenedKey<T>` is `secrecy::SecretBox<T>` (re-exported from `oc-crypto`),
//! which requires `T: Zeroize`. `oc_signer::Mnemonic` does NOT implement
//! `Zeroize` (it wraps `coins_bip39::Mnemonic<English>` and provides its own
//! `phrase()` / `to_seed()` accessors returning `SecretBytes`), so it cannot
//! be placed inside `SecretBox<Mnemonic>` without modifying `oc-signer` —
//! which is out of scope for T13.
//!
//! We return `HardenedBytes` instead. The runtime guarantees (mlock +
//! DONT_DUMP + zeroize on Drop) are identical to `SecretBox<Vec<u8>>`. The
//! type-level tag (`Mnemonic`) is a static-safety hint, not a runtime
//! guarantee; per ponytail YAGNI step 1, we do not add an abstraction
//! (forking `Mnemonic` into `oc-keyagent` to add `Zeroize`) for a tag whose
//! runtime contract is already met by `HardenedBytes`.

use oc_crypto::HardenedBytes;
use oc_signer::{Curve, HdDeriver, Mnemonic};
use oc_vault::Vault;

use crate::{error::KeyAgentError, global_key_cache};

/// Decrypt the wallet mnemonic into a `HardenedBytes`.
///
/// Per R54: the decrypted mnemonic lives ONLY inside `HardenedBytes`
/// (page-locked, `MADV_DONTDUMP`-marked, zeroized on `Drop`). `Vault::decrypt`
/// returns `HardenedBytes` directly — we do not re-wrap; the bytes never
/// leave the hardened wrapper.
///
/// `key` is the user-supplied passphrase (UTF-8 bytes inside `HardenedBytes`).
/// `vault` is a loaded wallet file (`Vault::load(path)`).
///
/// Errors:
/// - `KeyAgentError::Internal` if the vault's crypto envelope fails to decrypt (wrong passphrase,
///   corrupt envelope, argon2id/AES-GCM-SIV failure, mlock failure on the output buffer).
pub fn decrypt_mnemonic(
    vault: &Vault,
    key: &HardenedBytes,
) -> Result<HardenedBytes, KeyAgentError> {
    let mnemonic_bytes = vault
        .decrypt(key)
        .map_err(|e| KeyAgentError::Internal(format!("vault decrypt failed: {e}")))?;
    Ok(mnemonic_bytes)
}

/// Derive a chain-specific signing key from the mnemonic.
///
/// Per R17: Layer 0 (mnemonic) → Layer 1 (master signing key) → Layer 2
/// (chain-derived key, hardened memory only). Returns `HardenedBytes` —
/// never raw bytes.
///
/// `chain` is a CAIP-2 chain id (e.g. `"eip155:1"`, `"solana:mainnet"`).
/// Phase 1 MVP supports `eip155:*` (BIP-44 `m/44'/60'/0'/0/0`, secp256k1)
/// and `solana:*` (SLIP-10 `m/44'/501'/0'/0'`, ed25519).
///
/// The result is cached by chain id in the process-wide `KeyCache` (5s TTL,
/// 32 LRU). On a cache hit, the mnemonic is NOT parsed — the cached
/// `HardenedBytes` is returned as a clone. On a miss, the mnemonic is
/// parsed, the key is derived, cached, and returned.
///
/// Errors:
/// - `KeyAgentError::InvalidRequest` if `mnemonic` is not valid UTF-8, is not a valid BIP-39
///   phrase, or `chain` is not a supported CAIP-2 id.
/// - `KeyAgentError::Internal` if HD derivation fails or mlock fails on the output buffer.
pub fn derive_chain_key(
    mnemonic: &HardenedBytes,
    chain: &str,
) -> Result<HardenedBytes, KeyAgentError> {
    // Cache hit: return a clone without touching the mnemonic.
    if let Some(cached) = global_key_cache().get(chain) {
        return Ok(cached);
    }

    // Cache miss: parse the mnemonic phrase (UTF-8 bytes inside HardenedBytes).
    // The &str borrows the HardenedBytes's underlying buffer — no copy.
    let phrase = std::str::from_utf8(mnemonic.expose())
        .map_err(|_| KeyAgentError::InvalidRequest("mnemonic is not valid UTF-8".into()))?;
    let mn = Mnemonic::from_phrase(phrase)
        .map_err(|e| KeyAgentError::InvalidRequest(format!("invalid mnemonic: {e}")))?;

    // Map CAIP-2 chain id → (derivation path, curve).
    let (path, curve) = chain_to_derivation(chain)?;

    // Derive the chain key. HdDeriver returns SecretBytes (= HardenedBytes
    // alias in oc-signer) — page-locked, zeroized on Drop.
    let key = HdDeriver::derive_from_mnemonic(&mn, "", path, curve)
        .map_err(|e| KeyAgentError::Internal(format!("HD derivation failed: {e}")))?;

    // Cache the derived key (clone — HardenedBytes::clone is best-effort mlock
    // per oc-crypto). On Drop (eviction / TTL / process exit), zeroize runs.
    global_key_cache().insert(chain, key.clone());

    Ok(key)
}

/// Map a CAIP-2 chain id to `(derivation_path, curve)`.
///
/// Phase 1 MVP supports EVM (`eip155:*`) and Solana (`solana:*`). Other
/// chains return `InvalidRequest`.
fn chain_to_derivation(chain: &str) -> Result<(&'static str, Curve), KeyAgentError> {
    if chain.starts_with("eip155:") {
        // BIP-44 m/44'/60'/0'/0/0 — matches EvmSigner::default_derivation_path(0).
        Ok(("m/44'/60'/0'/0/0", Curve::Secp256k1))
    } else if chain.starts_with("solana:") {
        // SLIP-10 m/44'/501'/0'/0' — matches SolanaSigner::default_derivation_path(0).
        Ok(("m/44'/501'/0'/0'", Curve::Ed25519))
    } else {
        Err(KeyAgentError::InvalidRequest(format!(
            "unsupported chain: {chain} (Phase 1 MVP supports eip155:* and solana:*)"
        )))
    }
}
