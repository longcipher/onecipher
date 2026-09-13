//! Multi-chain signing and HD key derivation for OneCipher.
//!
//! ## Seed-sealing policy (A2)
//!
//! The 64-byte BIP-39 seed is the most sensitive value in the wallet stack:
//! anyone holding it can derive *every* chain key. This crate seals it by
//! construction:
//!
//! ```text
//! oc-vault (encrypted mnemonic blob)
//!   → oc-keyagent::decrypt_mnemonic → HardenedBytes(mnemonic phrase)
//!   → HdDeriver::derive_from_mnemonic (seed derived AND consumed inside
//!     oc-signer; the 64-byte seed never crosses the crate boundary)
//!   → HardenedBytes (32-byte chain key)
//!   → ChainSigner::{derive_address, sign, sign_message, sign_transaction}
//! ```
//!
//! Chain signers only ever receive the derived 32-byte private key — never
//! the mnemonic, never the seed. The raw-seed escape hatch
//! (`Mnemonic::to_seed`, `HdDeriver::derive`) is compiled only with
//! `--features raw-seed` (off by default) for migration tooling and
//! external KAT vectors; production paths must use the sealed
//! `derive_from_mnemonic` / `derive_many` / `derive_range` APIs.
//!
//! ## Memory hardening
//!
//! Derived keys rest in [`HardenedBytes`] (mlock + `MADV_DONTDUMP` +
//! zeroize-on-drop, see `oc-crypto` R51/R52). Short-lived secret wrappers
//! ([`SealedPrivateKey`], [`WifString`], [`SealedKeypair`]) use
//! `zeroize::Zeroizing` and redact `Debug` output. See [`secret`] for the
//! full audit table.
// Test code may unwrap/expect/panic (workspace lint phase-1 carve-out).
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]
// A13 pilot: `no_std`+`alloc` layering. With default features (`std`) this is
// a normal `std` crate. With `--no-default-features` (optionally
// `--features alloc`) the crate is `no_std` and only the heap-light core
// (`curve`, `traits`, `rlp`) is compiled; every module that needs OS/threads,
// collections beyond `alloc`, or `std`-only dependencies is gated behind
// `#[cfg(feature = "std")]`. Full per-dependency `?/std` passthrough is a
// follow-up once each dependency's `std` gate is audited.
#![cfg_attr(not(feature = "std"), no_std)]
#[cfg(not(feature = "std"))]
extern crate alloc;

// `std`-gated: need OS, `std` collections, or `std`-only deps
// (`bitcoin`, `coins-*`, `signal-hook`, `serde_json` with std).
// Wallet-file encryption lives in `oc-vault::crypto` (unified age envelope),
// NOT here: this crate owns signing and key derivation only.
#[cfg(feature = "std")]
pub mod account;
#[cfg(feature = "std")]
pub mod chains;
pub mod curve;
#[cfg(feature = "std")]
pub mod eip712;
#[cfg(feature = "std")]
pub mod encoding;
pub mod error;
#[cfg(feature = "std")]
pub mod hd;
#[cfg(feature = "std")]
pub mod mnemonic;
pub mod prelude;
#[cfg(feature = "std")]
pub mod process_hardening;
#[cfg(feature = "std")]
pub mod pubkey;
pub mod rlp;
#[cfg(feature = "std")]
pub mod secret;
#[cfg(feature = "std")]
pub mod siwx;
#[cfg(feature = "std")]
pub mod style;
pub mod traits;

#[cfg(feature = "std")]
pub use chains::signer_for_chain;
pub use curve::Curve;
#[cfg(feature = "std")]
pub use encoding::{base58check_decode, base58check_encode, double_sha256, hash160};
pub use error::{DeriveError, SignerError};
#[cfg(feature = "std")]
pub use hd::HdDeriver;
#[cfg(feature = "std")]
pub use mnemonic::{Mnemonic, MnemonicStrength};
// Signer's private keys live in `oc_crypto::HardenedBytes` (page-locked,
// DONT_DUMP-marked, zeroized on drop) per R51/R52. `SecretBytes` is kept as a
// type alias so existing call sites and downstream crates continue to compile.
#[cfg(feature = "std")]
pub use oc_crypto::HardenedBytes;
#[cfg(feature = "std")]
pub use pubkey::{
    DerivedPublicKey, PubkeyError, PublicKeyKind, ed25519_from_private,
    secp256k1_compressed_from_private, secp256k1_uncompressed_from_private,
};
#[cfg(feature = "std")]
pub use secret::{SealedKeypair, SealedPrivateKey, WifString};
#[cfg(feature = "std")]
pub use siwx::{
    EvmVerifier, SolanaVerifier, eip191_hash, parse_evm_chain_id, validate_evm_address,
    validate_solana_chain_id,
};
pub use traits::{ChainSigner, SignOutput};
#[cfg(feature = "std")]
pub type SecretBytes = HardenedBytes;

/// Type alias for the process-wide key cache.
///
/// Delegates to [`oc_crypto::KeyCache`] parameterized over [`HardenedBytes`]
/// so cached derived keys are page-locked + zeroized on eviction / drop.
/// Requires `std` (uses `std::sync::OnceLock` + system clock).
#[cfg(feature = "std")]
pub type KeyCache = oc_crypto::KeyCache<HardenedBytes>;

#[cfg(feature = "std")]
use std::{sync::OnceLock, time::Duration};

#[cfg(feature = "std")]
static GLOBAL_KEY_CACHE: OnceLock<KeyCache> = OnceLock::new();

/// Returns the process-wide key cache (5s TTL, max 32 entries).
/// Requires the `std` feature (pilot `no_std` builds omit the cache).
#[cfg(feature = "std")]
pub fn global_key_cache() -> &'static KeyCache {
    GLOBAL_KEY_CACHE.get_or_init(|| KeyCache::new(Duration::from_secs(5), 32))
}

#[cfg(all(test, feature = "std"))]
mod integration_tests {
    use digest::Digest;
    use oc_core::ChainType;

    use super::*;

    const ABANDON_PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    fn derive_address_for_chain(mnemonic: &Mnemonic, chain: ChainType) -> String {
        let signer = signer_for_chain(chain);
        let curve = signer.curve();
        let path = signer.default_derivation_path(0);

        let key = HdDeriver::derive_from_mnemonic(mnemonic, "", &path, curve).unwrap();
        signer.derive_address(key.expose()).unwrap()
    }

    #[test]
    fn test_full_pipeline_evm() {
        let mnemonic = Mnemonic::from_phrase(ABANDON_PHRASE).unwrap();
        let address = derive_address_for_chain(&mnemonic, ChainType::Evm);
        assert!(address.starts_with("0x"));
        assert_eq!(address.len(), 42);
    }

    #[test]
    fn test_full_pipeline_solana() {
        let mnemonic = Mnemonic::from_phrase(ABANDON_PHRASE).unwrap();
        let address = derive_address_for_chain(&mnemonic, ChainType::Solana);
        // Base58 encoded ed25519 pubkey
        assert_ne!(address.len(), 0);
        let decoded = bs58::decode(&address).into_vec().unwrap();
        assert_eq!(decoded.len(), 32);
    }

    #[test]
    fn test_full_pipeline_bitcoin() {
        let mnemonic = Mnemonic::from_phrase(ABANDON_PHRASE).unwrap();
        let address = derive_address_for_chain(&mnemonic, ChainType::Bitcoin);
        assert!(address.starts_with("bc1"));
    }

    #[test]
    fn test_full_pipeline_cosmos() {
        let mnemonic = Mnemonic::from_phrase(ABANDON_PHRASE).unwrap();
        let address = derive_address_for_chain(&mnemonic, ChainType::Cosmos);
        assert!(address.starts_with("cosmos1"));
    }

    #[test]
    fn test_full_pipeline_tron() {
        let mnemonic = Mnemonic::from_phrase(ABANDON_PHRASE).unwrap();
        let address = derive_address_for_chain(&mnemonic, ChainType::Tron);
        assert!(address.starts_with('T'));
        assert_eq!(address.len(), 34);
    }

    #[test]
    fn test_full_pipeline_ton() {
        let mnemonic = Mnemonic::from_phrase(ABANDON_PHRASE).unwrap();
        let address = derive_address_for_chain(&mnemonic, ChainType::Ton);
        assert!(
            address.starts_with("UQ"),
            "TON non-bounceable address should start with UQ, got: {}",
            address
        );
        assert_eq!(address.len(), 48);
    }

    #[test]
    fn test_full_pipeline_spark() {
        let mnemonic = Mnemonic::from_phrase(ABANDON_PHRASE).unwrap();
        let address = derive_address_for_chain(&mnemonic, ChainType::Spark);
        assert!(
            address.starts_with("spark:"),
            "Spark address should start with spark:, got: {}",
            address
        );
    }

    #[cfg(feature = "xrpl")]
    #[test]
    fn test_full_pipeline_xrpl() {
        let mnemonic = Mnemonic::from_phrase(ABANDON_PHRASE).unwrap();
        let address = derive_address_for_chain(&mnemonic, ChainType::Xrpl);
        assert!(address.starts_with('r'), "XRPL address must start with 'r', got: {}", address);
        assert!(
            address.len() >= 25 && address.len() <= 34,
            "XRPL address length must be 25-34, got: {}",
            address.len()
        );
    }

    #[test]
    fn test_full_pipeline_filecoin() {
        let mnemonic = Mnemonic::from_phrase(ABANDON_PHRASE).unwrap();
        let address = derive_address_for_chain(&mnemonic, ChainType::Filecoin);
        assert!(
            address.starts_with("f1"),
            "Filecoin address should start with f1, got: {}",
            address
        );
    }

    #[test]
    fn test_spark_uses_bitcoin_derivation_path() {
        let mnemonic = Mnemonic::from_phrase(ABANDON_PHRASE).unwrap();
        let btc_signer = signer_for_chain(ChainType::Bitcoin);
        let spark_signer = signer_for_chain(ChainType::Spark);

        // Same derivation path
        assert_eq!(btc_signer.default_derivation_path(0), spark_signer.default_derivation_path(0),);

        // Same derived key
        let btc_key = HdDeriver::derive_from_mnemonic(
            &mnemonic,
            "",
            &btc_signer.default_derivation_path(0),
            Curve::Secp256k1,
        )
        .unwrap();
        let spark_key = HdDeriver::derive_from_mnemonic(
            &mnemonic,
            "",
            &spark_signer.default_derivation_path(0),
            Curve::Secp256k1,
        )
        .unwrap();
        assert_eq!(btc_key.expose(), spark_key.expose());
    }

    #[test]
    fn test_cross_chain_different_addresses() {
        let mnemonic = Mnemonic::from_phrase(ABANDON_PHRASE).unwrap();

        let evm_addr = derive_address_for_chain(&mnemonic, ChainType::Evm);
        let sol_addr = derive_address_for_chain(&mnemonic, ChainType::Solana);
        let btc_addr = derive_address_for_chain(&mnemonic, ChainType::Bitcoin);
        let cosmos_addr = derive_address_for_chain(&mnemonic, ChainType::Cosmos);
        let tron_addr = derive_address_for_chain(&mnemonic, ChainType::Tron);
        let ton_addr = derive_address_for_chain(&mnemonic, ChainType::Ton);
        let spark_addr = derive_address_for_chain(&mnemonic, ChainType::Spark);
        let fil_addr = derive_address_for_chain(&mnemonic, ChainType::Filecoin);
        #[cfg(feature = "xrpl")]
        let xrpl_addr = derive_address_for_chain(&mnemonic, ChainType::Xrpl);

        // All addresses should be different
        let addrs = [
            &evm_addr,
            &sol_addr,
            &btc_addr,
            &cosmos_addr,
            &tron_addr,
            &ton_addr,
            &spark_addr,
            &fil_addr,
            #[cfg(feature = "xrpl")]
            &xrpl_addr,
        ];
        for i in 0..addrs.len() {
            for j in (i + 1)..addrs.len() {
                assert_ne!(addrs[i], addrs[j], "addresses should differ");
            }
        }
    }

    #[test]
    fn test_deterministic_across_calls() {
        let mnemonic = Mnemonic::from_phrase(ABANDON_PHRASE).unwrap();
        let addr1 = derive_address_for_chain(&mnemonic, ChainType::Evm);
        let addr2 = derive_address_for_chain(&mnemonic, ChainType::Evm);
        assert_eq!(addr1, addr2);
    }

    #[test]
    fn test_sign_roundtrip_all_secp256k1_chains() {
        let mnemonic = Mnemonic::from_phrase(ABANDON_PHRASE).unwrap();

        for chain in [
            ChainType::Evm,
            ChainType::Bitcoin,
            ChainType::Cosmos,
            ChainType::Tron,
            ChainType::Spark,
            ChainType::Filecoin,
        ] {
            let signer = signer_for_chain(chain);
            let path = signer.default_derivation_path(0);
            let key =
                HdDeriver::derive_from_mnemonic(&mnemonic, "", &path, Curve::Secp256k1).unwrap();

            // Create a dummy 32-byte hash
            let hash = sha2::Sha256::digest(b"test transaction data");
            let result = signer.sign(key.expose(), &hash).unwrap();
            assert_ne!(result.signature.len(), 0);
            assert!(result.recovery_id.is_some());
        }
    }

    #[test]
    fn test_sign_roundtrip_ed25519_chains() {
        let mnemonic = Mnemonic::from_phrase(ABANDON_PHRASE).unwrap();

        for chain in [ChainType::Solana, ChainType::Ton] {
            let signer = signer_for_chain(chain);
            let path = signer.default_derivation_path(0);
            let key =
                HdDeriver::derive_from_mnemonic(&mnemonic, "", &path, Curve::Ed25519).unwrap();

            let result = signer.sign(key.expose(), b"test message").unwrap();
            assert_eq!(result.signature.len(), 64);
            assert!(result.recovery_id.is_none());
        }
    }

    #[test]
    fn test_signer_for_chain_registry() {
        // Verify all chain types are supported
        for chain in [
            ChainType::Evm,
            ChainType::Solana,
            ChainType::Bitcoin,
            ChainType::Cosmos,
            ChainType::Tron,
            ChainType::Ton,
            ChainType::Spark,
            ChainType::Filecoin,
            ChainType::Xrpl,
        ] {
            let signer = signer_for_chain(chain);
            assert_eq!(signer.chain_type(), chain);
        }
    }
}
