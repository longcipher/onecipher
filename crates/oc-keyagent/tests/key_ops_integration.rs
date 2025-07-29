//! Integration tests for `oc_keyagent::key_ops` + `oc_keyagent::global_key_cache`.
//!
//! These tests exercise the full R54 flow end-to-end:
//! - `decrypt_mnemonic` round-trip via a real `oc_vault::Vault` + `oc_signer::encrypt`
//! - `derive_chain_key` for EVM (BIP-44 / secp256k1) and Solana (SLIP-10 / ed25519) with known test
//!   vectors
//! - `KeyCache` TTL expiry, LRU eviction, and clear semantics
//!
//! Per R56 these tests are synchronous (no tokio / reqwest / hyper).
//!
//! Test 7 (`test_drop_zeroizes`) is omitted because `oc_crypto::HardenedBytes`
//! does not expose an `is_zeroized()` debug method — the R54 / R52 zeroize
//! contract is verified externally via `gcore <pid>` + `strings | grep -iE
//! "mnemonic|seed|private"` in the Linux CI harness (see `tasks.md` T13
//! steps 5 and 7).

use std::time::{Duration, Instant};

use oc_core::{ChainType, EncryptedWallet, KeyType};
use oc_crypto::HardenedBytes;
use oc_keyagent::{KeyCache, decrypt_mnemonic, derive_chain_key};
use oc_signer::signer_for_chain;

/// The canonical BIP-39 test vector mnemonic. Used by `coins-bip39`,
/// `bip32` reference tests, and `oc-signer` integration tests.
const ABANDON_PHRASE: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

// ---------------------------------------------------------------------------
// 1. decrypt_mnemonic round-trip
// ---------------------------------------------------------------------------

#[test]
fn test_decrypt_mnemonic_returns_hardened() {
    let dir = tempfile::tempdir().unwrap();
    let vault_dir = dir.path().to_path_buf();

    // Encrypt the known mnemonic phrase with a known passphrase, then wrap it
    // in an EncryptedWallet. decrypt_mnemonic should give us back the phrase
    // bytes inside a HardenedBytes (page-locked, zeroized on Drop).
    let passphrase = "correct horse battery staple";

    let envelope = oc_signer::encrypt(ABANDON_PHRASE.as_bytes(), passphrase.as_bytes()).unwrap();
    let wallet = EncryptedWallet::new(
        "t13-decrypt-id".to_string(),
        "t13-decrypt".to_string(),
        vec![],
        serde_json::to_value(&envelope).unwrap(),
        KeyType::Mnemonic,
    );

    let wallet_path = vault_dir.join("wallet.json");
    std::fs::write(&wallet_path, serde_json::to_string_pretty(&wallet).unwrap()).unwrap();

    let vault = oc_vault::Vault::load(&wallet_path).unwrap();
    let key = HardenedBytes::from_slice(passphrase.as_bytes()).unwrap();

    let decrypted = decrypt_mnemonic(&vault, &key).expect("decryption should succeed");

    // The decrypted bytes should be exactly the mnemonic phrase.
    let decrypted_str = std::str::from_utf8(decrypted.expose()).unwrap();
    assert_eq!(decrypted_str, ABANDON_PHRASE);

    // Sanity: the wrapper is non-trivial (mnemonic is ~69 bytes).
    assert!(decrypted.len() > 60);
}

#[test]
fn test_decrypt_mnemonic_wrong_passphrase_fails() {
    let dir = tempfile::tempdir().unwrap();
    let vault_dir = dir.path().to_path_buf();

    let envelope = oc_signer::encrypt(ABANDON_PHRASE.as_bytes(), b"correct").unwrap();
    let wallet = EncryptedWallet::new(
        "t13-wp-id".to_string(),
        "t13-wp".to_string(),
        vec![],
        serde_json::to_value(&envelope).unwrap(),
        KeyType::Mnemonic,
    );

    let wallet_path = vault_dir.join("wp.json");
    std::fs::write(&wallet_path, serde_json::to_string_pretty(&wallet).unwrap()).unwrap();

    let vault = oc_vault::Vault::load(&wallet_path).unwrap();
    let wrong_key = HardenedBytes::from_slice(b"wrong-passphrase").unwrap();

    let result = decrypt_mnemonic(&vault, &wrong_key);
    assert!(result.is_err(), "wrong passphrase must fail");
}

// ---------------------------------------------------------------------------
// 2. derive_chain_key — EVM (BIP-44 / secp256k1)
// ---------------------------------------------------------------------------

#[test]
fn test_derive_chain_key_evm() {
    let mnemonic = HardenedBytes::from_slice(ABANDON_PHRASE.as_bytes()).unwrap();
    let key = derive_chain_key(&mnemonic, "eip155:1").expect("EVM derivation should succeed");

    // BIP-32 / secp256k1 private keys are 32 bytes.
    assert_eq!(key.len(), 32, "EVM private key must be 32 bytes");

    // Known test vector: the "abandon ... about" mnemonic at m/44'/60'/0'/0/0
    // derives to EVM address 0x9858EfFD232B4033E47d90003D41EC34EcaEda94.
    // This vector is locked in by `oc-signer`'s
    // `test_abandon_mnemonic_evm_address` and is widely cited across the
    // Ethereum ecosystem.
    let signer = signer_for_chain(ChainType::Evm);
    let address = signer.derive_address(key.expose()).expect("address derive");
    assert_eq!(
        address, "0x9858EfFD232B4033E47d90003D41EC34EcaEda94",
        "EVM address must match known test vector for abandon-mnemonic / m/44'/60'/0'/0/0"
    );
}

// ---------------------------------------------------------------------------
// 3. derive_chain_key — Solana (SLIP-10 / ed25519)
// ---------------------------------------------------------------------------

#[test]
fn test_derive_chain_key_solana() {
    let mnemonic = HardenedBytes::from_slice(ABANDON_PHRASE.as_bytes()).unwrap();
    let key =
        derive_chain_key(&mnemonic, "solana:mainnet").expect("Solana derivation should succeed");

    // SLIP-10 ed25519 private keys are 32 bytes.
    assert_eq!(key.len(), 32, "Solana private key must be 32 bytes");

    // Derive the Solana address (base58 of the ed25519 verifying key).
    let signer = signer_for_chain(ChainType::Solana);
    let address = signer.derive_address(key.expose()).expect("solana address derive");

    // Solana pubkeys are base58-encoded 32-byte ed25519 verifying keys.
    // Base58 of 32 bytes is 32-44 ASCII characters; non-empty + ASCII is a
    // sufficient sanity check here (the precise vector for the abandon
    // mnemonic at m/44'/501'/0'/0' is not part of the SLIP-10 test vector
    // suite — SLIP-10 vectors cover raw seed derivations, not BIP-39 →
    // BIP-44/SLIP-10 combinations). Determinism is verified below.
    assert!(!address.is_empty(), "Solana address must be non-empty");
    assert!(
        address.len() >= 32 && address.len() <= 44,
        "Solana address length out of expected base58 range: {} (got '{}')",
        address.len(),
        address
    );

    // Determinism: re-derive from the same mnemonic + chain and verify the
    // address matches. The global cache may or may not be warm; either way
    // the result must be identical.
    let key2 = derive_chain_key(&mnemonic, "solana:mainnet").expect("re-derive should succeed");
    let address2 = signer.derive_address(key2.expose()).expect("solana address re-derive");
    assert_eq!(address, address2, "Solana address must be deterministic across derivations");

    // Cross-chain isolation: the Solana address must NOT equal the EVM
    // address (different curves + derivation paths → different keys).
    let evm_key = derive_chain_key(&mnemonic, "eip155:1").unwrap();
    let evm_address = signer_for_chain(ChainType::Evm).derive_address(evm_key.expose()).unwrap();
    assert_ne!(address, evm_address, "Solana and EVM addresses must differ for the same mnemonic");
}

#[test]
fn test_derive_chain_key_unsupported_chain_rejected() {
    let mnemonic = HardenedBytes::from_slice(ABANDON_PHRASE.as_bytes()).unwrap();
    let result = derive_chain_key(&mnemonic, "bitcoin:000000000019d6689c085ae165831e93");
    assert!(result.is_err(), "Phase 1 MVP must reject unsupported chain ids");
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("unsupported chain"),
        "error should mention unsupported chain, got: {err}"
    );
}

#[test]
fn test_derive_chain_key_invalid_mnemonic_rejected() {
    // Valid UTF-8 but NOT a valid BIP-39 phrase (wrong checksum).
    let bad = HardenedBytes::from_slice(
        b"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon",
    )
    .unwrap();
    let result = derive_chain_key(&bad, "eip155:1");
    assert!(result.is_err(), "invalid mnemonic must be rejected");
}

#[test]
fn test_derive_chain_key_non_utf8_mnemonic_rejected() {
    // 0xFF is not valid UTF-8 in isolation.
    let bad = HardenedBytes::from_slice(&[0xFF, 0xFE, 0xFD]).unwrap();
    let result = derive_chain_key(&bad, "eip155:1");
    assert!(result.is_err(), "non-UTF-8 mnemonic must be rejected");
}

// ---------------------------------------------------------------------------
// 4-6. KeyCache — TTL expiry, LRU eviction, clear
// ---------------------------------------------------------------------------

#[test]
fn test_key_cache_ttl_expiry() {
    // Use a short TTL (50ms) so the test doesn't sleep for 5 seconds.
    let cache = KeyCache::new(Duration::from_millis(50), 10);
    cache.insert("k", HardenedBytes::from_slice(&[1, 2, 3]).unwrap());
    assert!(cache.get("k").is_some(), "fresh entry should be retrievable");

    // Sleep past TTL+buffer. The task spec says "5s+100ms" — here the TTL is
    // 50ms so we sleep 100ms (TTL + 50ms buffer) to give Instant::elapsed()
    // headroom on slow CI runners.
    std::thread::sleep(Duration::from_millis(100));
    assert!(cache.get("k").is_none(), "expired entry must not be returned");
}

#[test]
fn test_key_cache_lru_eviction() {
    // Max 32 entries. Insert 33 keys with small sleeps so last_accessed is
    // strictly monotonic (no LRU ties). The first key (k0) should be evicted
    // when k32 is inserted.
    let cache = KeyCache::new(Duration::from_secs(5), 32);
    for i in 0..33u32 {
        let key = HardenedBytes::from_slice(&i.to_be_bytes()).unwrap();
        cache.insert(&format!("k{i}"), key);
        // 2ms sleep ensures Instant granularity distinguishes successive
        // inserts even on platforms with coarse monotonic clocks.
        std::thread::sleep(Duration::from_millis(2));
    }

    assert_eq!(cache.len(), 32, "cache should be exactly at capacity");
    assert!(cache.get("k0").is_none(), "k0 (LRU) should have been evicted when k32 was inserted");
    assert!(cache.get("k32").is_some(), "k32 (most recent) should still be present");
    // A middle key should also still be present.
    assert!(cache.get("k16").is_some(), "k16 (middle of LRU order) should still be present");
}

#[test]
fn test_key_cache_clear() {
    let cache = KeyCache::new(Duration::from_secs(5), 10);
    cache.insert("a", HardenedBytes::from_slice(&[1]).unwrap());
    cache.insert("b", HardenedBytes::from_slice(&[2]).unwrap());
    cache.insert("c", HardenedBytes::from_slice(&[3]).unwrap());
    assert_eq!(cache.len(), 3);

    cache.clear();
    assert_eq!(cache.len(), 0, "clear() must empty the cache");
    assert!(cache.get("a").is_none());
    assert!(cache.get("b").is_none());
    assert!(cache.get("c").is_none());
}

#[test]
fn test_key_cache_get_updates_lru_order() {
    // Verify that `get` updates last_accessed (LRU semantics): with max=2,
    // insert a, b, touch a, then insert c — b should be evicted (not a).
    let cache = KeyCache::new(Duration::from_secs(5), 2);
    cache.insert("a", HardenedBytes::from_slice(&[1]).unwrap());
    std::thread::sleep(Duration::from_millis(5));
    cache.insert("b", HardenedBytes::from_slice(&[2]).unwrap());
    std::thread::sleep(Duration::from_millis(5));

    // Touch "a" — it is now more recent than "b".
    assert!(cache.get("a").is_some());
    std::thread::sleep(Duration::from_millis(5));

    // Insert "c" — should evict "b" (least recently used).
    cache.insert("c", HardenedBytes::from_slice(&[3]).unwrap());
    assert_eq!(cache.len(), 2);
    assert!(cache.get("a").is_some(), "a was touched, should survive");
    assert!(cache.get("b").is_none(), "b was LRU, should be evicted");
    assert!(cache.get("c").is_some(), "c was just inserted");
}

// ---------------------------------------------------------------------------
// 7. drop_zeroizes — omitted (no debug method on HardenedBytes)
// ---------------------------------------------------------------------------

// TODO: verify via gcore + strings in CI.
// `oc_crypto::HardenedBytes` does not expose an `is_zeroized()` debug method,
// so we cannot assert zeroization from safe Rust. The R54 / R52 zeroize
// contract is verified externally in the Linux CI harness (T13 steps 5 and 7):
//   gcore $(pidof oc-keyagent) && strings core.* | grep -iE "mnemonic|seed|private"
// The expected result is empty (no plaintext keys in the core dump).

// ---------------------------------------------------------------------------
// Bonus: cache-hit behavior for derive_chain_key (regression guard)
// ---------------------------------------------------------------------------

#[test]
fn test_derive_chain_key_cache_hit_returns_same_key() {
    // Two successive calls for the same chain must return keys with identical
    // bytes (the second call hits the global cache, returning a clone).
    let mnemonic = HardenedBytes::from_slice(ABANDON_PHRASE.as_bytes()).unwrap();

    let start = Instant::now();
    let key1 = derive_chain_key(&mnemonic, "eip155:1").unwrap();
    let cold = start.elapsed();

    let start = Instant::now();
    let key2 = derive_chain_key(&mnemonic, "eip155:1").unwrap();
    let warm = start.elapsed();

    assert_eq!(key1.expose(), key2.expose(), "cached derivation must match cold derivation");
    // Cache hit should be at least as fast as the cold derivation. (We don't
    // assert `warm < cold` strictly — timing on shared CI runners is noisy —
    // but log the values for diagnostics if the test fails.)
    assert!(
        warm <= cold * 10,
        "warm call ({warm:?}) should not be orders of magnitude slower than cold ({cold:?})"
    );
}
