//! Typed derived public keys.
//!
//! Replaces ad-hoc `Vec<u8>` + length-guess logic at call sites (e.g. a
//! 33-byte buffer *assumed* to be a compressed secp256k1 key). Every
//! constructor validates length and encoding prefix, so a mismatched
//! buffer is a typed error instead of a downstream address mismatch.
//!
//! The four variants cover the curves used across the 12 supported chains:
//! secp256k1 (compressed / uncompressed) and ed25519. The ed25519 family is
//! split in two because Nano signs with Blake2b-512 (`raw_sign`) while all
//! other ed25519 chains use SHA-512: identical 32-byte encodings verify
//! under different hash functions, so conflating them risks cross-chain
//! signature confusion.

use zeroize::Zeroize;

/// Discriminant for [`DerivedPublicKey`] without the key material.
///
/// Used when only the kind (length / encoding rules) is needed, e.g. to
/// select a verification routine before the key bytes are available.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PublicKeyKind {
    /// 33-byte compressed secp256k1 (`0x02` / `0x03` prefix).
    Secp256k1Compressed,
    /// 65-byte uncompressed secp256k1 (`0x04` prefix).
    Secp256k1Uncompressed,
    /// 32-byte ed25519 (SHA-512 domain: Solana, Sui, TON, NEAR).
    Ed25519,
    /// 32-byte ed25519 in the Nano/Blake2b-512 domain.
    Ed25519Blake2b,
}

impl PublicKeyKind {
    /// Expected encoded length in bytes for this kind.
    ///
    /// No `is_empty` counterpart: a key *kind* has no emptiness concept, so
    /// `clippy::len_without_is_empty` is allowed here by design.
    #[allow(clippy::len_without_is_empty)]
    #[must_use]
    pub const fn len(self) -> usize {
        match self {
            Self::Secp256k1Compressed => 33,
            Self::Secp256k1Uncompressed => 65,
            Self::Ed25519 | Self::Ed25519Blake2b => 32,
        }
    }
}

/// A validated, typed derived public key.
///
/// The inner arrays are fixed-size so length confusion is unrepresentable.
/// The two ed25519 variants share the same encoding but live in different
/// signature domains (see module docs); converting between them requires an
/// explicit [`DerivedPublicKey::reinterpret_ed25519_domain`] call.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub enum DerivedPublicKey {
    /// 33-byte compressed secp256k1 public key.
    Secp256k1Compressed([u8; 33]),
    /// 65-byte uncompressed secp256k1 public key (`0x04 || x || y`).
    Secp256k1Uncompressed([u8; 65]),
    /// 32-byte ed25519 public key (SHA-512 domain).
    Ed25519([u8; 32]),
    /// 32-byte ed25519 public key (Nano Blake2b-512 domain).
    Ed25519Blake2b([u8; 32]),
}

impl DerivedPublicKey {
    /// Return the discriminant for this key.
    #[must_use]
    pub const fn kind(self) -> PublicKeyKind {
        match self {
            Self::Secp256k1Compressed(_) => PublicKeyKind::Secp256k1Compressed,
            Self::Secp256k1Uncompressed(_) => PublicKeyKind::Secp256k1Uncompressed,
            Self::Ed25519(_) => PublicKeyKind::Ed25519,
            Self::Ed25519Blake2b(_) => PublicKeyKind::Ed25519Blake2b,
        }
    }

    /// Borrow the raw encoded bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            Self::Secp256k1Compressed(b) => &b[..],
            Self::Secp256k1Uncompressed(b) => &b[..],
            Self::Ed25519(b) => &b[..],
            Self::Ed25519Blake2b(b) => &b[..],
        }
    }

    /// Copy the raw encoded bytes into a fresh `Vec`.
    ///
    /// Prefer [`DerivedPublicKey::as_bytes`] when a borrow suffices; this
    /// helper exists for wire formats that require ownership.
    #[must_use]
    pub fn to_vec(self) -> Vec<u8> {
        self.as_bytes().to_vec()
    }

    /// Validate and wrap a 33-byte compressed secp256k1 key.
    ///
    /// # Errors
    ///
    /// Returns [`PubkeyError::InvalidPrefix`] unless the first byte is
    /// `0x02` or `0x03`.
    pub fn from_compressed(bytes: [u8; 33]) -> Result<Self, PubkeyError> {
        if bytes[0] != 0x02 && bytes[0] != 0x03 {
            return Err(PubkeyError::InvalidPrefix {
                kind: PublicKeyKind::Secp256k1Compressed,
                prefix: bytes[0],
            });
        }
        Ok(Self::Secp256k1Compressed(bytes))
    }

    /// Validate and wrap a 65-byte uncompressed secp256k1 key.
    ///
    /// # Errors
    ///
    /// Returns [`PubkeyError::InvalidPrefix`] unless the first byte is `0x04`.
    pub fn from_uncompressed(bytes: [u8; 65]) -> Result<Self, PubkeyError> {
        if bytes[0] != 0x04 {
            return Err(PubkeyError::InvalidPrefix {
                kind: PublicKeyKind::Secp256k1Uncompressed,
                prefix: bytes[0],
            });
        }
        Ok(Self::Secp256k1Uncompressed(bytes))
    }

    /// Wrap a 32-byte ed25519 key in the SHA-512 domain (no prefix to check).
    #[must_use]
    pub const fn from_ed25519(bytes: [u8; 32]) -> Self {
        Self::Ed25519(bytes)
    }

    /// Wrap a 32-byte ed25519 key in the Nano Blake2b-512 domain.
    #[must_use]
    pub const fn from_ed25519_blake2b(bytes: [u8; 32]) -> Self {
        Self::Ed25519Blake2b(bytes)
    }

    /// Parse raw bytes with an explicit kind instead of guessing from length.
    ///
    /// This is the single replacement for `Vec<u8>` + `len()` dispatch:
    /// callers name the expected kind and get a typed error on mismatch.
    ///
    /// # Errors
    ///
    /// Returns [`PubkeyError::InvalidLength`] when `bytes.len()` does not
    /// match `kind.len()`, or [`PubkeyError::InvalidPrefix`] when the
    /// secp256k1 prefix byte is wrong.
    pub fn from_bytes(kind: PublicKeyKind, bytes: &[u8]) -> Result<Self, PubkeyError> {
        if bytes.len() != kind.len() {
            return Err(PubkeyError::invalid_length(kind, bytes.len()));
        }
        match kind {
            PublicKeyKind::Secp256k1Compressed => {
                let mut arr = [0u8; 33];
                arr.copy_from_slice(bytes);
                Self::from_compressed(arr)
            }
            PublicKeyKind::Secp256k1Uncompressed => {
                let mut arr = [0u8; 65];
                arr.copy_from_slice(bytes);
                Self::from_uncompressed(arr)
            }
            PublicKeyKind::Ed25519 => {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(bytes);
                Ok(Self::from_ed25519(arr))
            }
            PublicKeyKind::Ed25519Blake2b => {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(bytes);
                Ok(Self::from_ed25519_blake2b(arr))
            }
        }
    }

    /// Reinterpret an ed25519 key in the other hash domain.
    ///
    /// The encoding is identical; only the verification context changes.
    /// Returns `None` for secp256k1 variants.
    #[must_use]
    pub const fn reinterpret_ed25519_domain(self) -> Option<Self> {
        match self {
            Self::Ed25519(b) => Some(Self::Ed25519Blake2b(b)),
            Self::Ed25519Blake2b(b) => Some(Self::Ed25519(b)),
            Self::Secp256k1Compressed(_) | Self::Secp256k1Uncompressed(_) => None,
        }
    }

    /// Zeroize a mutable byte buffer holding key material.
    ///
    /// Convenience re-export of the `zeroize` contract so callers handling
    /// raw buffers next to this type do not need a direct `zeroize`
    /// dependency.
    pub fn zeroize_bytes(bytes: &mut [u8]) {
        bytes.zeroize();
    }
}

impl std::fmt::Debug for DerivedPublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Public keys are not secret, but Debug output is routinely captured
        // in logs; emit kind + length only to keep log shapes stable and to
        // avoid accidental pasting of key material into bug reports.
        write!(f, "{:?}([REDACTED; {} bytes])", self.kind(), self.kind().len())
    }
}

/// Errors from [`DerivedPublicKey`] constructors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PubkeyError {
    /// Buffer length does not match the declared [`PublicKeyKind`].
    #[error("invalid public key length for {kind:?}: expected {expected}, got {got}")]
    InvalidLength {
        /// Declared kind.
        kind: PublicKeyKind,
        /// Actual buffer length.
        got: usize,
        /// Expected length (equals `kind.len()`, repeated for message clarity).
        expected: usize,
    },
    /// secp256k1 prefix byte is wrong (`0x02`/`0x03` for compressed,
    /// `0x04` for uncompressed).
    #[error("invalid public key prefix for {kind:?}: got 0x{prefix:02x}")]
    InvalidPrefix {
        /// Declared kind.
        kind: PublicKeyKind,
        /// Offending first byte.
        prefix: u8,
    },
}

impl PubkeyError {
    /// Build an [`PubkeyError::InvalidLength`] with `expected` filled from `kind`.
    #[must_use]
    pub const fn invalid_length(kind: PublicKeyKind, got: usize) -> Self {
        Self::InvalidLength { kind, got, expected: kind.len() }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kind_lengths() {
        assert_eq!(PublicKeyKind::Secp256k1Compressed.len(), 33);
        assert_eq!(PublicKeyKind::Secp256k1Uncompressed.len(), 65);
        assert_eq!(PublicKeyKind::Ed25519.len(), 32);
        assert_eq!(PublicKeyKind::Ed25519Blake2b.len(), 32);
    }

    #[test]
    fn compressed_rejects_bad_prefix() {
        let mut bad = [0u8; 33];
        bad[0] = 0x04;
        assert!(DerivedPublicKey::from_compressed(bad).is_err());
        let mut good = [0u8; 33];
        good[0] = 0x02;
        assert!(DerivedPublicKey::from_compressed(good).is_ok());
        good[0] = 0x03;
        assert!(DerivedPublicKey::from_compressed(good).is_ok());
    }

    #[test]
    fn uncompressed_requires_0x04() {
        let mut bad = [0u8; 65];
        bad[0] = 0x02;
        assert!(DerivedPublicKey::from_uncompressed(bad).is_err());
        let mut good = [0u8; 65];
        good[0] = 0x04;
        assert!(DerivedPublicKey::from_uncompressed(good).is_ok());
    }

    #[test]
    fn from_bytes_replaces_len_guess() {
        // 32 bytes must not be accepted as compressed secp256k1.
        let buf = [7u8; 32];
        let err = DerivedPublicKey::from_bytes(PublicKeyKind::Secp256k1Compressed, &buf)
            .expect_err("length mismatch must fail");
        assert!(matches!(err, PubkeyError::InvalidLength { .. }));
        // Explicit kind selects the right variant.
        let key = DerivedPublicKey::from_bytes(PublicKeyKind::Ed25519, &buf).unwrap();
        assert_eq!(key.kind(), PublicKeyKind::Ed25519);
        assert_eq!(key.as_bytes(), &buf);
    }

    #[test]
    fn debug_does_not_leak() {
        let key = DerivedPublicKey::from_ed25519([0xAB; 32]);
        let dbg = format!("{key:?}");
        assert!(dbg.contains("[REDACTED"));
        assert!(!dbg.contains("abab"));
    }

    #[test]
    fn ed25519_domain_reinterpretation() {
        let a = DerivedPublicKey::from_ed25519([1u8; 32]);
        let b = a.reinterpret_ed25519_domain().unwrap();
        assert_eq!(b.kind(), PublicKeyKind::Ed25519Blake2b);
        let c = b.reinterpret_ed25519_domain().unwrap();
        assert_eq!(c, a);
        let mut arr = [0u8; 33];
        arr[0] = 0x02;
        let secp = DerivedPublicKey::from_compressed(arr);
        assert!(secp.unwrap().reinterpret_ed25519_domain().is_none());
    }
}
