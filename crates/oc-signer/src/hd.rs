use digest::KeyInit;
use hmac::{Hmac, Mac};
use sha2::Sha512;

use crate::{
    SecretBytes,
    curve::Curve,
    mnemonic::{Mnemonic, MnemonicError},
};

/// Errors from HD key derivation.
#[derive(Debug, thiserror::Error)]
pub enum HdError {
    #[error("invalid derivation path: {0}")]
    InvalidPath(String),

    #[error("derivation failed: {0}")]
    DerivationFailed(String),

    #[error("ed25519 requires hardened-only derivation")]
    Ed25519NonHardened,

    #[error("invalid seed length: expected 16-64 bytes, got {0}")]
    InvalidSeedLength(usize),

    /// Batch derivation overflowed `u32` (`start + count` exceeds `u32::MAX`).
    #[error("index overflow: start {start} + count {count} exceeds u32 range")]
    IndexOverflow {
        /// Batch start index.
        start: u32,
        /// Requested element count.
        count: u32,
    },

    /// Batch range is empty or inverted (`start >= end`).
    #[error("invalid range: start {start} >= end {end}")]
    InvalidRange {
        /// Range start (inclusive).
        start: u32,
        /// Range end (exclusive).
        end: u32,
    },
}

impl From<oc_crypto::MemGuardError> for HdError {
    fn from(e: oc_crypto::MemGuardError) -> Self {
        Self::DerivationFailed(format!("memory hardening failed: {e}"))
    }
}

impl From<MnemonicError> for HdError {
    fn from(e: MnemonicError) -> Self {
        Self::DerivationFailed(e.to_string())
    }
}

/// HD key deriver supporting BIP-32 (secp256k1) and SLIP-10 (ed25519).
pub struct HdDeriver;

/// SLIP-10 hardened offset (`2^31`).
const HARDENED_OFFSET: u32 = 0x8000_0000;

impl HdDeriver {
    /// Derive a child private key from a raw seed and derivation path.
    ///
    /// Raw-seed escape hatch: compiled only with `--features raw-seed`
    /// (see crate docs for the sealing policy). Production code must use
    /// [`HdDeriver::derive_from_mnemonic`] so the 64-byte seed never leaves
    /// `oc-signer`. External KAT vectors and migration tooling enable the
    /// feature explicitly.
    ///
    /// Seed must be 16-64 bytes (BIP-32 §2).
    #[cfg(feature = "raw-seed")]
    pub fn derive(seed: &[u8], path: &str, curve: Curve) -> Result<SecretBytes, HdError> {
        Self::derive_inner(seed, path, curve)
    }

    /// Sealed derivation kernel: mnemonic → seed → child key without
    /// exposing the seed to the caller.
    ///
    /// Always compiled; backs [`HdDeriver::derive_from_mnemonic`] and the
    /// in-crate spec-vector tests. External crates reach raw seeds only
    /// through the `raw-seed`-gated [`HdDeriver::derive`].
    pub(crate) fn derive_inner(
        seed: &[u8],
        path: &str,
        curve: Curve,
    ) -> Result<SecretBytes, HdError> {
        if seed.len() < 16 || seed.len() > 64 {
            return Err(HdError::InvalidSeedLength(seed.len()));
        }
        Self::validate_path(path)?;

        match curve {
            Curve::Secp256k1 => Self::derive_secp256k1(seed, path),
            Curve::Ed25519 => Self::derive_ed25519(seed, path),
        }
    }

    /// Convenience: derive from a mnemonic + passphrase + path + curve.
    ///
    /// Sealed path — the BIP-39 seed is derived and consumed inside
    /// `oc-signer`; callers only ever handle the derived 32-byte key.
    pub fn derive_from_mnemonic(
        mnemonic: &Mnemonic,
        passphrase: &str,
        path: &str,
        curve: Curve,
    ) -> Result<SecretBytes, HdError> {
        let seed = mnemonic.to_seed_sealed(passphrase)?;
        Self::derive_inner(seed.expose(), path, curve)
    }

    /// Derive a batch of consecutive child keys.
    ///
    /// `make_path` maps each account index to its full derivation path
    /// (e.g. `|i| format!("m/44'/60'/0'/0/{i}")`). Indices are advanced
    /// with [`u32::checked_add`] so a batch crossing `u32::MAX` fails with
    /// [`HdError::IndexOverflow`] instead of wrapping.
    ///
    /// # Errors
    ///
    /// Returns [`HdError::IndexOverflow`] when `start + count` exceeds the
    /// `u32` range, or forwards the first per-index [`HdError`].
    pub fn derive_many(
        mnemonic: &Mnemonic,
        passphrase: &str,
        curve: Curve,
        make_path: impl Fn(u32) -> String,
        start: u32,
        count: u32,
    ) -> Result<Vec<SecretBytes>, HdError> {
        let mut out = Vec::new();
        if count > 0 {
            out.reserve(count.min(1024) as usize);
        }
        let mut index = start;
        for n in 0..count {
            let path = make_path(index);
            out.push(Self::derive_from_mnemonic(mnemonic, passphrase, &path, curve)?);
            // Advance only when another iteration follows, so a batch ending
            // exactly at `u32::MAX` still succeeds.
            if n + 1 < count {
                index = index.checked_add(1).ok_or(HdError::IndexOverflow { start, count })?;
            }
        }
        Ok(out)
    }

    /// Derive keys for `start..end_exclusive` via `make_path`.
    ///
    /// Range form of [`HdDeriver::derive_many`] with the same
    /// `checked_add` overflow discipline.
    ///
    /// # Errors
    ///
    /// Returns [`HdError::InvalidRange`] when `start >= end_exclusive`, or
    /// forwards per-index errors.
    pub fn derive_range(
        mnemonic: &Mnemonic,
        passphrase: &str,
        curve: Curve,
        make_path: impl Fn(u32) -> String,
        start: u32,
        end_exclusive: u32,
    ) -> Result<Vec<SecretBytes>, HdError> {
        if start >= end_exclusive {
            return Err(HdError::InvalidRange { start, end: end_exclusive });
        }
        let count = end_exclusive
            .checked_sub(start)
            .ok_or(HdError::InvalidRange { start, end: end_exclusive })?;
        Self::derive_many(mnemonic, passphrase, curve, make_path, start, count)
    }

    /// Like `derive_from_mnemonic`, but checks the global key cache first.
    /// On cache miss, derives the key and inserts it into the cache.
    pub fn derive_from_mnemonic_cached(
        mnemonic: &Mnemonic,
        passphrase: &str,
        path: &str,
        curve: Curve,
    ) -> Result<SecretBytes, HdError> {
        use digest::Digest;

        // Build a cache key by hashing all inputs (avoids storing sensitive material in the key).
        let phrase = mnemonic.phrase()?;
        let mut hasher = sha2::Sha256::new();
        hasher.update(phrase.expose());
        hasher.update(b":");
        hasher.update(passphrase.as_bytes());
        hasher.update(b":");
        hasher.update(path.as_bytes());
        hasher.update(b":");
        hasher.update(match curve {
            Curve::Secp256k1 => b"secp256k1" as &[u8],
            Curve::Ed25519 => b"ed25519",
        });
        let cache_key = hex::encode(hasher.finalize());

        let cache = crate::global_key_cache();
        if let Some(cached) = cache.get(&cache_key) {
            return Ok(cached);
        }

        let key = Self::derive_from_mnemonic(mnemonic, passphrase, path, curve)?;
        cache.insert(&cache_key, key.clone());
        Ok(key)
    }

    /// Validate a derivation path. Must start with "m/" and contain valid indices.
    ///
    /// Accepts both hardened suffixes (`'` and `h`/`H`, e.g. `44'` ≡ `44h`)
    /// so BIP-32 style paths validate regardless of notation. Whether a
    /// non-hardened component is *allowed* is curve-specific and enforced at
    /// derivation time ([`HdDeriver::derive_inner`] → SLIP-10 strict check
    /// for ed25519).
    pub fn validate_path(path: &str) -> Result<(), HdError> {
        if !path.starts_with("m/") && path != "m" {
            return Err(HdError::InvalidPath(format!("path must start with 'm/', got '{}'", path)));
        }
        if path == "m" {
            return Ok(());
        }
        let components = path[2..].split('/');
        for component in components {
            let index_str = component
                .strip_suffix('\'')
                .or_else(|| component.strip_suffix('h'))
                .or_else(|| component.strip_suffix('H'))
                .unwrap_or(component);
            if index_str.is_empty() {
                return Err(HdError::InvalidPath(format!("empty component in path '{}'", path)));
            }
            index_str.parse::<u32>().map_err(|_| {
                HdError::InvalidPath(format!("invalid index '{}' in path '{}'", component, path))
            })?;
        }
        Ok(())
    }

    /// Strict SLIP-10 hardened index parser for ed25519 paths.
    ///
    /// Accepts `'` and `h`/`H` suffixes (`0'` ≡ `0h`); both denote the same
    /// hardened child. Rejects bare indices and values `>= 2^31` with an
    /// error that tells the caller how to fix the path.
    ///
    /// # Errors
    ///
    /// Returns [`HdError::InvalidPath`] with a fix-up hint when the
    /// component is bare, malformed, or out of range.
    pub fn parse_slip10_index(component: &str, full_path: &str) -> Result<u32, HdError> {
        let hardened =
            component.ends_with('\'') || component.ends_with('h') || component.ends_with('H');
        if !hardened {
            return Err(HdError::InvalidPath(format!(
                "non-hardened index '{component}' in ed25519 path '{full_path}': \
                 ed25519 requires hardened derivation; add \"'\" suffix, e.g. \"{component}'\""
            )));
        }
        let index_str = &component[..component.len() - 1];
        if index_str.is_empty() {
            return Err(HdError::InvalidPath(format!("empty index in ed25519 path '{full_path}'")));
        }
        let index: u32 = index_str.parse().map_err(|_| {
            HdError::InvalidPath(format!("invalid index '{component}' in path '{full_path}'"))
        })?;
        if index >= HARDENED_OFFSET {
            return Err(HdError::InvalidPath(format!(
                "hardened index '{component}' in path '{full_path}' must be < 2^31; \
                 add \"'\" to an index below 2147483648 instead"
            )));
        }
        Ok(index)
    }

    /// Initialize an HMAC-SHA512 instance for SLIP-10 derivation.
    ///
    /// RFC 2104 allows keys of arbitrary length (oversized keys are hashed
    /// rather than rejected), so `new_from_slice` cannot fail for any input;
    /// the error arm maps that unreachable case into a typed error instead
    /// of panicking.
    fn hmac_sha512(key: &[u8]) -> Result<Hmac<Sha512>, HdError> {
        Hmac::<Sha512>::new_from_slice(key)
            .map_err(|e| HdError::DerivationFailed(format!("HMAC-SHA512 init failed: {e}")))
    }

    /// BIP-32 derivation for secp256k1 using coins-bip32.
    fn derive_secp256k1(seed: &[u8], path: &str) -> Result<SecretBytes, HdError> {
        use std::str::FromStr;

        use coins_bip32::{derived::DerivedXPriv, prelude::SigningKey, xkeys::Parent};
        use zeroize::Zeroize;

        let xpriv = DerivedXPriv::root_from_seed(seed, None)
            .map_err(|e| HdError::DerivationFailed(e.to_string()))?;

        let derivation_path = coins_bip32::path::DerivationPath::from_str(path)
            .map_err(|e| HdError::InvalidPath(e.to_string()))?;

        let derived = xpriv
            .derive_path(&derivation_path)
            .map_err(|e: coins_bip32::Bip32Error| HdError::DerivationFailed(e.to_string()))?;

        let signing_key: &SigningKey = derived.as_ref();
        let mut key_bytes = signing_key.to_bytes();
        let result = SecretBytes::from_vec(key_bytes.to_vec()).map_err(HdError::from);
        key_bytes.zeroize();
        result
    }

    /// SLIP-10 derivation for ed25519 (hardened-only, HMAC-SHA512 chain).
    fn derive_ed25519(seed: &[u8], path: &str) -> Result<SecretBytes, HdError> {
        use zeroize::Zeroize;

        // Parse path components with the strict SLIP-10 hardened check
        // (`'` and `h`/`H` accepted, bare indices rejected with a fix-up hint).
        let components = if path == "m" {
            vec![]
        } else {
            path[2..]
                .split('/')
                .map(|c| Self::parse_slip10_index(c, path))
                .collect::<Result<Vec<_>, _>>()?
        };

        // SLIP-10: Master key generation
        let mut mac = Self::hmac_sha512(b"ed25519 seed")?;
        mac.update(seed);
        let mut result = mac.finalize().into_bytes();

        let mut key = result[..32].to_vec();
        let mut chain_code = result[32..].to_vec();
        result.zeroize();

        // Derive each component (hardened only). `index` is validated
        // `< 2^31` by `parse_slip10_index`, so OR-ing the hardened bit
        // cannot overflow (checked_add equivalent without a failure arm).
        let mut data = Vec::new();
        for index in components {
            data.zeroize();
            data.clear();
            data.push(0u8); // 0x00 prefix for private key derivation
            data.extend_from_slice(&key);
            data.extend_from_slice(&(index | HARDENED_OFFSET).to_be_bytes());

            let mut mac = Self::hmac_sha512(&chain_code)?;
            mac.update(&data);
            let mut derived = mac.finalize().into_bytes();

            key.zeroize();
            chain_code.zeroize();
            key = derived[..32].to_vec();
            chain_code = derived[32..].to_vec();
            derived.zeroize();
        }

        data.zeroize();
        chain_code.zeroize();
        Ok(SecretBytes::from_vec(key)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ABANDON_PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    fn test_seed() -> SecretBytes {
        let mnemonic = Mnemonic::from_phrase(ABANDON_PHRASE).unwrap();
        mnemonic.to_seed_sealed("").unwrap()
    }

    #[test]
    fn test_derive_evm_account_0() {
        let seed = test_seed();
        let key =
            HdDeriver::derive_inner(seed.expose(), "m/44'/60'/0'/0/0", Curve::Secp256k1).unwrap();
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn test_derive_solana_account_0() {
        let seed = test_seed();
        let key =
            HdDeriver::derive_inner(seed.expose(), "m/44'/501'/0'/0'", Curve::Ed25519).unwrap();
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn test_derive_bitcoin_account_0() {
        let seed = test_seed();
        let key =
            HdDeriver::derive_inner(seed.expose(), "m/84'/0'/0'/0/0", Curve::Secp256k1).unwrap();
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn test_derive_cosmos_account_0() {
        let seed = test_seed();
        let key =
            HdDeriver::derive_inner(seed.expose(), "m/44'/118'/0'/0/0", Curve::Secp256k1).unwrap();
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn test_derive_tron_account_0() {
        let seed = test_seed();
        let key =
            HdDeriver::derive_inner(seed.expose(), "m/44'/195'/0'/0/0", Curve::Secp256k1).unwrap();
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn test_convenience_matches_two_step() {
        let mnemonic = Mnemonic::from_phrase(ABANDON_PHRASE).unwrap();
        let seed = mnemonic.to_seed_sealed("").unwrap();

        let key1 =
            HdDeriver::derive_inner(seed.expose(), "m/44'/60'/0'/0/0", Curve::Secp256k1).unwrap();
        let key2 =
            HdDeriver::derive_from_mnemonic(&mnemonic, "", "m/44'/60'/0'/0/0", Curve::Secp256k1)
                .unwrap();

        assert_eq!(key1.expose(), key2.expose());
    }

    #[test]
    fn test_path_validation_valid() {
        assert!(HdDeriver::validate_path("m/44'/60'/0'/0/0").is_ok());
        assert!(HdDeriver::validate_path("m/44'/501'/0'/0'").is_ok());
        assert!(HdDeriver::validate_path("m").is_ok());
    }

    #[test]
    fn test_path_validation_invalid() {
        assert!(HdDeriver::validate_path("44'/60'/0'/0/0").is_err());
        assert!(HdDeriver::validate_path("").is_err());
        assert!(HdDeriver::validate_path("x/44'/60'").is_err());
    }

    #[test]
    fn test_slip10_rejects_non_hardened_ed25519() {
        let seed = test_seed();
        let result = HdDeriver::derive_inner(seed.expose(), "m/44'/501'/0'/0", Curve::Ed25519);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("add \"'\""), "error must teach the user to add \"'\", got: {err}");
    }

    #[test]
    fn test_slip10_accepts_h_suffix() {
        // `h` is the long-standing BIP-32 hardened alias for `'`.
        let seed = test_seed();
        let via_tick =
            HdDeriver::derive_inner(seed.expose(), "m/44'/501'/0'/0'", Curve::Ed25519).unwrap();
        let via_h =
            HdDeriver::derive_inner(seed.expose(), "m/44h/501h/0h/0h", Curve::Ed25519).unwrap();
        assert_eq!(via_tick.expose(), via_h.expose());
    }

    #[test]
    fn test_slip10_rejects_index_above_2pow31() {
        let seed = test_seed();
        let result = HdDeriver::derive_inner(seed.expose(), "m/2147483648'", Curve::Ed25519);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("2^31"), "expected range hint, got: {err}");
    }

    #[test]
    fn test_slip10_bare_index_hint_names_component() {
        let err =
            HdDeriver::parse_slip10_index("0", "m/44'/501'/0'/0").expect_err("bare must fail");
        let msg = err.to_string();
        assert!(msg.contains("'0'") || msg.contains("\"'\""), "got: {msg}");
    }

    #[test]
    fn test_derive_many_matches_sequential() {
        let mnemonic = Mnemonic::from_phrase(ABANDON_PHRASE).unwrap();
        let make_path = |i: u32| format!("m/44'/60'/0'/0/{i}");
        let batch =
            HdDeriver::derive_many(&mnemonic, "", Curve::Secp256k1, make_path, 0, 3).unwrap();
        assert_eq!(batch.len(), 3);
        for (i, key) in batch.iter().enumerate() {
            let single = HdDeriver::derive_from_mnemonic(
                &mnemonic,
                "",
                &format!("m/44'/60'/0'/0/{i}"),
                Curve::Secp256k1,
            )
            .unwrap();
            assert_eq!(key.expose(), single.expose());
        }
    }

    #[test]
    fn test_derive_many_overflow_fails_closed() {
        let mnemonic = Mnemonic::from_phrase(ABANDON_PHRASE).unwrap();
        // Constant path: every index derives successfully, isolating the
        // `checked_add` overflow discipline from per-index path validity
        // (BIP-32 non-hardened indices are `< 2^31`, so a real path template
        // would fail derivation before the counter overflows).
        let result = HdDeriver::derive_many(
            &mnemonic,
            "",
            Curve::Secp256k1,
            |_| "m/44'/60'/0'/0/0".to_string(),
            u32::MAX,
            2,
        );
        assert!(matches!(result, Err(HdError::IndexOverflow { .. })));
    }

    #[test]
    fn test_derive_many_ending_at_max_succeeds() {
        // A batch ending exactly at `u32::MAX` must succeed: the counter is
        // only advanced when another iteration follows.
        let mnemonic = Mnemonic::from_phrase(ABANDON_PHRASE).unwrap();
        let batch = HdDeriver::derive_many(
            &mnemonic,
            "",
            Curve::Secp256k1,
            |_| "m/44'/60'/0'/0/0".to_string(),
            u32::MAX,
            1,
        )
        .unwrap();
        assert_eq!(batch.len(), 1);
    }

    #[test]
    fn test_derive_range_matches_many() {
        let mnemonic = Mnemonic::from_phrase(ABANDON_PHRASE).unwrap();
        let ranged = HdDeriver::derive_range(
            &mnemonic,
            "",
            Curve::Secp256k1,
            |i| format!("m/44'/60'/0'/0/{i}"),
            1,
            4,
        )
        .unwrap();
        assert_eq!(ranged.len(), 3);
        let many = HdDeriver::derive_many(
            &mnemonic,
            "",
            Curve::Secp256k1,
            |i| format!("m/44'/60'/0'/0/{i}"),
            1,
            3,
        )
        .unwrap();
        for (a, b) in ranged.iter().zip(many.iter()) {
            assert_eq!(a.expose(), b.expose());
        }
    }

    #[test]
    fn test_derive_range_rejects_inverted() {
        let mnemonic = Mnemonic::from_phrase(ABANDON_PHRASE).unwrap();
        let result = HdDeriver::derive_range(
            &mnemonic,
            "",
            Curve::Secp256k1,
            |i| format!("m/44'/60'/0'/0/{i}"),
            5,
            5,
        );
        assert!(matches!(result, Err(HdError::InvalidRange { .. })));
    }

    // === BIP-32 spec test vectors (secp256k1) ===
    // Source: https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#test-vectors

    #[test]
    fn test_bip32_vector1_chain() {
        let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();

        let cases = [
            ("m/0'", "edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea"),
            ("m/0'/1", "3c6cb8d0f6a264c91ea8b5030fadaa8e538b020f0a387421a12de9319dc93368"),
            ("m/0'/1/2'", "cbce0d719ecf7431d88e6a89fa1483e02e35092af60c042b1df2ff59fa424dca"),
            ("m/0'/1/2'/2", "0f479245fb19a38a1954c5c7c0ebab2f9bdfd96a17563ef28a6a4b1a2a764ef4"),
            (
                "m/0'/1/2'/2/1000000000",
                "471b76e389e528d6de6d816857e012c5455051cad6660850e58372a6c3e6e7c8",
            ),
        ];

        for (path, expected_hex) in cases {
            let key = HdDeriver::derive_inner(&seed, path, Curve::Secp256k1)
                .unwrap_or_else(|e| panic!("failed to derive {}: {}", path, e));
            assert_eq!(
                hex::encode(key.expose()),
                expected_hex,
                "BIP-32 vector 1 mismatch at {}",
                path
            );
        }
    }

    #[test]
    fn test_bip32_vector2_chain() {
        let seed = hex::decode(
            "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a2\
             9f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542",
        )
        .unwrap();

        let cases = [
            ("m/0", "abe74a98f6c7eabee0428f53798f0ab8aa1bd37873999041703c742f15ac7e1e"),
            ("m/0/2147483647'", "877c779ad9687164e9c2f4f0f4ff0340814392330693ce95a58fe18fd52e6e93"),
            (
                "m/0/2147483647'/1",
                "704addf544a06e5ee4bea37098463c23613da32020d604506da8c0518e1da4b7",
            ),
            (
                "m/0/2147483647'/1/2147483646'",
                "f1c7c871a54a804afe328b4c83a1c33b8e5ff48f5087273f04efa83b247d6a2d",
            ),
            (
                "m/0/2147483647'/1/2147483646'/2",
                "bb7d39bdb83ecf58f2fd82b6d918341cbef428661ef01ab97c28a4842125ac23",
            ),
        ];

        for (path, expected_hex) in cases {
            let key = HdDeriver::derive_inner(&seed, path, Curve::Secp256k1)
                .unwrap_or_else(|e| panic!("failed to derive {}: {}", path, e));
            assert_eq!(
                hex::encode(key.expose()),
                expected_hex,
                "BIP-32 vector 2 mismatch at {}",
                path
            );
        }
    }

    // === SLIP-10 spec test vectors (ed25519) ===
    // Source: https://github.com/satoshilabs/slips/blob/master/slip-0010.md#test-vectors

    #[test]
    fn test_slip10_vector1_chain() {
        let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();

        let cases = [
            ("m/0'", "68e0fe46dfb67e368c75379acec591dad19df3cde26e63b93a8e704f1dade7a3"),
            ("m/0'/1'", "b1d0bad404bf35da785a64ca1ac54b2617211d2777696fbffaf208f746ae84f2"),
            ("m/0'/1'/2'", "92a5b23c0b8a99e37d07df3fb9966917f5d06e02ddbd909c7e184371463e9fc9"),
            ("m/0'/1'/2'/2'", "30d1dc7e5fc04c31219ab25a27ae00b50f6fd66622f6e9c913253d6511d1e662"),
            (
                "m/0'/1'/2'/2'/1000000000'",
                "8f94d394a8e8fd6b1bc2f3f49f5c47e385281d5c17e65324b0f62483e37e8793",
            ),
        ];

        for (path, expected_hex) in cases {
            let key = HdDeriver::derive_inner(&seed, path, Curve::Ed25519)
                .unwrap_or_else(|e| panic!("failed to derive {}: {}", path, e));
            assert_eq!(
                hex::encode(key.expose()),
                expected_hex,
                "SLIP-10 vector 1 mismatch at {}",
                path
            );
        }
    }

    #[test]
    fn test_slip10_vector2_chain() {
        let seed = hex::decode(
            "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a2\
             9f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542",
        )
        .unwrap();

        let cases = [
            ("m/0'", "1559eb2bbec5790b0c65d8693e4d0875b1747f4970ae8b650486ed7470845635"),
            (
                "m/0'/2147483647'",
                "ea4f5bfe8694d8bb74b7b59404632fd5968b774ed545e810de9c32a4fb4192f4",
            ),
            (
                "m/0'/2147483647'/1'",
                "3757c7577170179c7868353ada796c839135b3d30554bbb74a4b1e4a5a58505c",
            ),
            (
                "m/0'/2147483647'/1'/2147483646'",
                "5837736c89570de861ebc173b1086da4f505d4adb387c6a1b1342d5e4ac9ec72",
            ),
            (
                "m/0'/2147483647'/1'/2147483646'/2'",
                "551d333177df541ad876a60ea71f00447931c0a9da16f227c11ea080d7391b8d",
            ),
        ];

        for (path, expected_hex) in cases {
            let key = HdDeriver::derive_inner(&seed, path, Curve::Ed25519)
                .unwrap_or_else(|e| panic!("failed to derive {}: {}", path, e));
            assert_eq!(
                hex::encode(key.expose()),
                expected_hex,
                "SLIP-10 vector 2 mismatch at {}",
                path
            );
        }
    }

    // === Seed length validation ===

    #[test]
    fn test_seed_length_too_short() {
        let seed = [0u8; 15];
        let result = HdDeriver::derive_inner(&seed, "m/0'", Curve::Secp256k1);
        assert!(matches!(result, Err(HdError::InvalidSeedLength(15))));
    }

    #[test]
    fn test_seed_length_too_long() {
        let seed = [0u8; 65];
        let result = HdDeriver::derive_inner(&seed, "m/0'", Curve::Secp256k1);
        assert!(matches!(result, Err(HdError::InvalidSeedLength(65))));
    }

    #[test]
    fn test_seed_length_minimum_accepted() {
        let seed = [0u8; 16];
        assert!(HdDeriver::derive_inner(&seed, "m/0'", Curve::Secp256k1).is_ok());
    }

    #[test]
    fn test_seed_length_maximum_accepted() {
        let seed = [0u8; 64];
        assert!(HdDeriver::derive_inner(&seed, "m/0'", Curve::Secp256k1).is_ok());
    }

    // === Characterization tests: lock down current behavior before refactoring ===

    #[test]
    fn test_abandon_mnemonic_evm_address() {
        // Known test vector: "abandon" mnemonic → known EVM address
        // This address is well-documented across the ecosystem
        let mnemonic = Mnemonic::from_phrase(ABANDON_PHRASE).unwrap();
        let key =
            HdDeriver::derive_from_mnemonic(&mnemonic, "", "m/44'/60'/0'/0/0", Curve::Secp256k1)
                .unwrap();

        // Derive the EVM address from the key
        let signer = crate::chains::EvmSigner;
        use crate::traits::ChainSigner;
        let address = signer.derive_address(key.expose()).unwrap();
        assert_eq!(
            address, "0x9858EfFD232B4033E47d90003D41EC34EcaEda94",
            "abandon mnemonic should derive to known EVM address"
        );
    }

    #[test]
    fn test_same_mnemonic_same_path_same_curve_same_key() {
        // Multiple independent derivations must produce identical results
        let mnemonic = Mnemonic::from_phrase(ABANDON_PHRASE).unwrap();
        let path = "m/44'/60'/0'/0/0";
        let curve = Curve::Secp256k1;

        let key1 = HdDeriver::derive_from_mnemonic(&mnemonic, "", path, curve).unwrap();
        let key2 = HdDeriver::derive_from_mnemonic(&mnemonic, "", path, curve).unwrap();
        let key3 = HdDeriver::derive_from_mnemonic(&mnemonic, "", path, curve).unwrap();

        assert_eq!(key1.expose(), key2.expose());
        assert_eq!(key2.expose(), key3.expose());
    }

    #[test]
    fn test_different_index_different_key_evm() {
        let mnemonic = Mnemonic::from_phrase(ABANDON_PHRASE).unwrap();
        let key0 =
            HdDeriver::derive_from_mnemonic(&mnemonic, "", "m/44'/60'/0'/0/0", Curve::Secp256k1)
                .unwrap();
        let key1 =
            HdDeriver::derive_from_mnemonic(&mnemonic, "", "m/44'/60'/0'/0/1", Curve::Secp256k1)
                .unwrap();
        let key2 =
            HdDeriver::derive_from_mnemonic(&mnemonic, "", "m/44'/60'/0'/0/2", Curve::Secp256k1)
                .unwrap();

        assert_ne!(key0.expose(), key1.expose());
        assert_ne!(key1.expose(), key2.expose());
        assert_ne!(key0.expose(), key2.expose());
    }

    #[test]
    fn test_different_index_different_key_ed25519() {
        let mnemonic = Mnemonic::from_phrase(ABANDON_PHRASE).unwrap();
        let key0 =
            HdDeriver::derive_from_mnemonic(&mnemonic, "", "m/44'/501'/0'/0'", Curve::Ed25519)
                .unwrap();
        let key1 =
            HdDeriver::derive_from_mnemonic(&mnemonic, "", "m/44'/501'/1'/0'", Curve::Ed25519)
                .unwrap();

        assert_ne!(key0.expose(), key1.expose());
    }

    #[test]
    fn test_cached_derivation_matches_uncached() {
        let mnemonic = Mnemonic::from_phrase(ABANDON_PHRASE).unwrap();
        let path = "m/44'/60'/0'/0/0";
        let curve = Curve::Secp256k1;

        let uncached = HdDeriver::derive_from_mnemonic(&mnemonic, "", path, curve).unwrap();
        let cached = HdDeriver::derive_from_mnemonic_cached(&mnemonic, "", path, curve).unwrap();

        assert_eq!(uncached.expose(), cached.expose());
    }

    #[test]
    fn test_key_length_32_bytes_all_curves() {
        let mnemonic = Mnemonic::from_phrase(ABANDON_PHRASE).unwrap();

        let secp_key =
            HdDeriver::derive_from_mnemonic(&mnemonic, "", "m/44'/60'/0'/0/0", Curve::Secp256k1)
                .unwrap();
        assert_eq!(secp_key.len(), 32);

        let ed_key =
            HdDeriver::derive_from_mnemonic(&mnemonic, "", "m/44'/501'/0'/0'", Curve::Ed25519)
                .unwrap();
        assert_eq!(ed_key.len(), 32);
    }

    #[test]
    fn test_deterministic() {
        let seed = test_seed();
        let key1 =
            HdDeriver::derive_inner(seed.expose(), "m/44'/60'/0'/0/0", Curve::Secp256k1).unwrap();
        let key2 =
            HdDeriver::derive_inner(seed.expose(), "m/44'/60'/0'/0/0", Curve::Secp256k1).unwrap();
        assert_eq!(key1.expose(), key2.expose());
    }

    #[test]
    fn test_different_indices_different_keys() {
        let seed = test_seed();
        let key0 =
            HdDeriver::derive_inner(seed.expose(), "m/44'/60'/0'/0/0", Curve::Secp256k1).unwrap();
        let key1 =
            HdDeriver::derive_inner(seed.expose(), "m/44'/60'/0'/0/1", Curve::Secp256k1).unwrap();
        assert_ne!(key0.expose(), key1.expose());
    }
}
