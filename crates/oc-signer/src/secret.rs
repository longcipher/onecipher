//! Zeroizing secret wrappers with redacted `Debug`.
//!
//! Audit scope (A5): every type that can hold mnemonic, seed, private-key,
//! WIF, or keypair material in `oc-signer`:
//!
//! | Type | Backing | `Debug` |
//! |------|---------|---------|
//! | [`oc_crypto::HardenedBytes`] (aka `SecretBytes`) | mlock + zeroize on drop | `[REDACTED; N bytes]` (upstream) |
//! | [`crate::mnemonic::Mnemonic`] | `coins-bip39` phrase, exposed only via `HardenedBytes` | `[REDACTED]` |
//! | [`SealedPrivateKey`] | `Zeroizing<[u8; 32]>` | `[REDACTED]` |
//! | [`WifString`] | `Zeroizing<String>` | `[REDACTED]` |
//! | [`SealedKeypair`] | `Zeroizing<[u8; 32]>` secret + 32-byte public | secret redacted |
//!
//! Rule: secrets never rest in plain `String` / `Vec<u8>`. Short-lived
//! conversions (hex, WIF) are wrapped immediately in the types below.

use zeroize::{Zeroize, Zeroizing};

/// A 32-byte private key sealed in zeroizing memory.
///
/// Prefer this over raw `[u8; 32]` / `Vec<u8>` at API boundaries that must
/// retain key material. The hot signing path still takes `&[u8]` slices
/// (borrowed from [`oc_crypto::HardenedBytes`] or this type) to avoid
/// extra copies; this wrapper is for storage and transport.
#[derive(Clone)]
pub struct SealedPrivateKey(Zeroizing<[u8; 32]>);

impl SealedPrivateKey {
    /// Wrap 32 raw bytes.
    #[must_use]
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// Borrow the raw bytes for signing / address derivation.
    #[must_use]
    pub fn expose(&self) -> &[u8] {
        &self.0[..]
    }

    /// Try to wrap a slice, checking length first.
    ///
    /// # Errors
    ///
    /// Returns [`crate::DeriveError::Input`] when `bytes.len() != 32`.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, crate::DeriveError> {
        if bytes.len() != 32 {
            return Err(crate::DeriveError::Input(format!(
                "expected 32-byte private key, got {} bytes",
                bytes.len()
            )));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(bytes);
        Ok(Self::new(arr))
    }
}

impl std::fmt::Debug for SealedPrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SealedPrivateKey([REDACTED])")
    }
}

/// A Bitcoin-style Wallet Import Format (WIF) string in zeroizing memory.
///
/// WIF is Base58Check(`0x80 || privkey || [0x01?]`) — inherently a `String`,
/// so the whole string is held in `Zeroizing<String>` and never logged.
#[derive(Clone)]
pub struct WifString(Zeroizing<String>);

impl WifString {
    /// Wrap an owned WIF string without an intermediate copy.
    #[must_use]
    pub fn new(wif: String) -> Self {
        Self(Zeroizing::new(wif))
    }

    /// Borrow the WIF string (e.g. for a single import/export call).
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }

    /// Encode a 32-byte key as compressed-mainnet WIF (`0x80 || key || 0x01`).
    #[must_use]
    pub fn encode_compressed_mainnet(key: &[u8; 32]) -> Self {
        let mut payload = Vec::with_capacity(34);
        payload.push(0x80);
        payload.extend_from_slice(key);
        payload.push(0x01);
        let encoded = bs58::encode(&payload).with_check().into_string();
        payload.zeroize();
        Self::new(encoded)
    }
}

impl std::fmt::Debug for WifString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("WifString([REDACTED])")
    }
}

/// A sealed keypair: zeroizing secret + copyable public half.
///
/// The public half is safe to clone; the secret half zeroizes on drop via
/// `Zeroizing`. `Debug` shows the public key but never the secret.
#[derive(Clone)]
pub struct SealedKeypair {
    /// Secret scalar (zeroized on drop).
    secret: Zeroizing<[u8; 32]>,
    /// Public key bytes (curve-specific encoding, safe to expose).
    public: [u8; 32],
}

impl SealedKeypair {
    /// Build from raw halves.
    #[must_use]
    pub fn new(secret: [u8; 32], public: [u8; 32]) -> Self {
        Self { secret: Zeroizing::new(secret), public }
    }

    /// Borrow the secret scalar.
    #[must_use]
    pub fn secret(&self) -> &[u8] {
        &self.secret[..]
    }

    /// Borrow the public half.
    #[must_use]
    pub fn public(&self) -> &[u8] {
        &self.public[..]
    }
}

impl std::fmt::Debug for SealedKeypair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SealedKeypair")
            .field("secret", &"[REDACTED]")
            .field("public", &hex::encode(self.public))
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_key_debug_does_not_leak() {
        let key = SealedPrivateKey::new([0xAB; 32]);
        let dbg = format!("{key:?}");
        assert!(dbg.contains("[REDACTED]"));
        assert!(!dbg.contains("abab"));
        assert_eq!(key.expose(), &[0xAB; 32]);
    }

    #[test]
    fn private_key_from_slice_checks_length() {
        assert!(SealedPrivateKey::from_slice(&[0u8; 16]).is_err());
        assert!(SealedPrivateKey::from_slice(&[0u8; 32]).is_ok());
    }

    #[test]
    fn wif_debug_does_not_leak() {
        let wif = WifString::encode_compressed_mainnet(&[0x11; 32]);
        let raw = wif.expose().to_owned();
        let dbg = format!("{wif:?}");
        assert!(dbg.contains("[REDACTED]"));
        assert!(!dbg.contains(&raw));
        // Compressed-mainnet WIF starts with K or L.
        assert!(raw.starts_with('K') || raw.starts_with('L'));
    }

    #[test]
    fn keypair_debug_redacts_secret_only() {
        let kp = SealedKeypair::new([0xCD; 32], [0xEF; 32]);
        let dbg = format!("{kp:?}");
        assert!(dbg.contains("[REDACTED]"));
        assert!(!dbg.contains(&"cd".repeat(32)));
        // Public half is intentionally visible for diagnostics.
        assert!(dbg.contains(&"ef".repeat(32)));
    }
}
