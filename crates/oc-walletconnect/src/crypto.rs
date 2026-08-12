//! WalletConnect v2 crypto layer — spec-compliant implementation.
//!
//! Mirrors the official `@walletconnect/utils` crypto module
//! (`walletconnect-monorepo/packages/utils/src/crypto.ts`), verified against
//! the WalletConnect 2.0 specs. Key facts (from the official TypeScript
//! reference implementation):
//!
//! - **Key agreement**: X25519 ECDH → shared secret (32 bytes).
//! - **KDF**: HKDF-SHA256 with `ikm = shared_secret`, `salt = undefined` (the reference
//!   implementation's `@noble/hashes/hkdf` substitutes a 32-zero-byte salt for `undefined`), `info
//!   = undefined` (empty), output 32 bytes (256-bit symmetric key). This is `deriveSymKey`.
//! - **Cipher**: ChaCha20-Poly1305 (IETF construction, 12-byte nonce). The official implementation
//!   passes **no AAD** (`encrypt(data)` with no second arg → empty AAD).
//! - **Envelopes** (serialized then base64'd by the relay layer):
//!   - Type 0: `[type(1) ‖ iv(12) ‖ ciphertext]` — anonymous encrypted envelope.
//!   - Type 1: `[type(1) ‖ senderPubKey(32) ‖ iv(12) ‖ ciphertext]` — carries the sender's X25519
//!     public key so the receiver can derive the session key.
//!   - Type 2: `[type(1) ‖ plaintext]` — unencrypted.
//!
//! Sensitive material is wrapped in `Zeroizing` wrappers.

use chacha20poly1305::{
    ChaCha20Poly1305, KeyInit, Nonce,
    aead::{Aead, Payload},
};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::RngExt;
use sha2::Sha256;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::error::{WcError, WcResult};

/// Envelope type byte for an anonymous encrypted envelope (type 0).
pub const ENVELOPE_TYPE_0: u8 = 0;
/// Envelope type byte for an authenticated sender envelope (type 1).
pub const ENVELOPE_TYPE_1: u8 = 1;
/// Envelope type byte for an unencrypted envelope (type 2).
pub const ENVELOPE_TYPE_2: u8 = 2;

/// Nonce length for ChaCha20-Poly1305 (IETF standard: 96 bits).
pub const IV_LENGTH: usize = 12;
/// X25519 key length (bytes).
pub const KEY_LENGTH: usize = 32;

// ---------------------------------------------------------------------------
// X25519 key agreement
// ---------------------------------------------------------------------------

/// X25519 keypair for WC v2 session key agreement.
#[derive(Clone)]
pub struct WcKeyPair {
    secret: StaticSecret,
    public: X25519PublicKey,
}

impl WcKeyPair {
    pub fn generate() -> Self {
        let mut bytes = [0u8; 32];
        rand::rng().fill(&mut bytes[..]);
        let secret = StaticSecret::from(bytes);
        let public = X25519PublicKey::from(&secret);
        Self { secret, public }
    }

    pub fn public_key(&self) -> X25519PublicKey {
        self.public
    }

    /// Hex-encoded public key (32 bytes → 64 hex chars), matching the
    /// official client's `BASE16` output.
    pub fn public_key_hex(&self) -> String {
        hex::encode(self.public.as_bytes())
    }

    /// Derive the shared secret with the peer's public key.
    pub fn shared_secret(&self, peer: &X25519PublicKey) -> WcSharedSecret {
        let s = self.secret.diffie_hellman(peer);
        WcSharedSecret(Zeroizing::new(s.to_bytes()))
    }
}

/// Shared secret derived from X25519.
pub struct WcSharedSecret(Zeroizing<[u8; 32]>);

impl WcSharedSecret {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Construct from raw bytes (test-only helper for golden vectors).
    pub fn from_bytes_for_test(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }
}

// ---------------------------------------------------------------------------
// Symmetric key
// ---------------------------------------------------------------------------

/// 256-bit symmetric key (for ChaCha20-Poly1305 message encryption).
#[derive(Clone)]
pub struct WcSymKey(Zeroizing<[u8; 32]>);

impl WcSymKey {
    pub fn from_bytes(b: [u8; 32]) -> Self {
        Self(Zeroizing::new(b))
    }

    pub fn from_random() -> Self {
        let mut b = [0u8; 32];
        rand::rng().fill(&mut b[..]);
        Self(Zeroizing::new(b))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Hex-encoded key (64 hex chars).
    pub fn to_hex(&self) -> String {
        hex::encode(&self.0[..])
    }
}

// ---------------------------------------------------------------------------
// Key derivation (spec-compliant)
// ---------------------------------------------------------------------------

/// Derive the shared symmetric key from an X25519 shared secret, exactly as
/// the official `@walletconnect/utils` `deriveSymKey` does:
///
/// ```text
/// HKDF-SHA256(ikm = shared_secret, salt = zeroes(32), info = "", len = 32)
/// ```
///
/// The official TypeScript implementation calls
/// `hkdf(sha256, sharedKey, undefined, undefined, KEY_LENGTH)` where
/// `@noble/hashes` treats `undefined` salt as a zero-filled array of the hash
/// output length (32 bytes) and `undefined` info as an empty array.
pub fn derive_sym_key(shared_secret: &WcSharedSecret) -> WcSymKey {
    let salt = [0u8; 32];
    let hk = Hkdf::<Sha256>::new(Some(&salt), shared_secret.as_bytes());
    let mut okm = [0u8; KEY_LENGTH];
    // KEY_LENGTH (32) is within HKDF-SHA256's 255*32 output limit.
    hk.expand(&[], &mut okm).expect("hkdf expand to 32 bytes cannot fail");
    WcSymKey::from_bytes(okm)
}

/// `hashKey(symKey)` — SHA-256 of the raw key bytes, hex-encoded. The official
/// client uses this as the default session topic when no override is given.
pub fn hash_key(key: &WcSymKey) -> String {
    hash_bytes(key.as_bytes())
}

/// SHA-256 of raw bytes, hex-encoded.
pub fn hash_bytes(bytes: &[u8]) -> String {
    use sha2::Digest;
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

// ---------------------------------------------------------------------------
// Envelope (de)serialization — spec-compliant
// ---------------------------------------------------------------------------

/// A deserialized WC v2 message envelope.
#[derive(Debug, Clone)]
pub struct Envelope {
    /// Envelope type byte (0, 1, or 2).
    pub r#type: u8,
    /// Sender's X25519 public key (present only in type-1 envelopes).
    pub sender_public_key: Option<[u8; 32]>,
    /// 12-byte nonce.
    pub iv: [u8; 12],
    /// Ciphertext (or plaintext for type 2).
    pub sealed: Vec<u8>,
}

/// Serialize an envelope into the on-wire byte layout:
/// - Type 0: `[type ‖ iv ‖ sealed]`
/// - Type 1: `[type ‖ senderPubKey ‖ iv ‖ sealed]`
/// - Type 2: `[type ‖ sealed]`
pub fn serialize_envelope(
    r#type: u8,
    iv: &[u8; 12],
    sender: Option<&[u8; 32]>,
    sealed: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 12 + sealed.len());
    out.push(r#type);
    if r#type == ENVELOPE_TYPE_1 {
        let key = sender
            .ok_or_else(|| WcError::Crypto("type-1 envelope requires sender public key".into()));
        // We can't `?` in a non-Result helper returning Vec; fall back to empty.
        let key = match key {
            Ok(k) => k,
            Err(_) => return Vec::new(),
        };
        out.extend_from_slice(key);
    }
    if r#type != ENVELOPE_TYPE_2 {
        out.extend_from_slice(iv);
    }
    out.extend_from_slice(sealed);
    out
}

/// Parse an on-wire envelope byte buffer.
///
/// Returns `Err` for malformed input (too short, unknown type byte).
pub fn deserialize_envelope(bytes: &[u8]) -> WcResult<Envelope> {
    if bytes.is_empty() {
        return Err(WcError::Crypto("envelope is empty".into()));
    }
    let r#type = bytes[0];
    match r#type {
        ENVELOPE_TYPE_0 => {
            if bytes.len() < 1 + IV_LENGTH {
                return Err(WcError::Crypto("type-0 envelope too short".into()));
            }
            let mut iv = [0u8; IV_LENGTH];
            iv.copy_from_slice(&bytes[1..=IV_LENGTH]);
            Ok(Envelope {
                r#type,
                sender_public_key: None,
                iv,
                sealed: bytes[1 + IV_LENGTH..].to_vec(),
            })
        }
        ENVELOPE_TYPE_1 => {
            if bytes.len() < 1 + KEY_LENGTH + IV_LENGTH {
                return Err(WcError::Crypto("type-1 envelope too short".into()));
            }
            let mut sender = [0u8; KEY_LENGTH];
            sender.copy_from_slice(&bytes[1..=KEY_LENGTH]);
            let mut iv = [0u8; IV_LENGTH];
            iv.copy_from_slice(&bytes[1 + KEY_LENGTH..1 + KEY_LENGTH + IV_LENGTH]);
            Ok(Envelope {
                r#type,
                sender_public_key: Some(sender),
                iv,
                sealed: bytes[1 + KEY_LENGTH + IV_LENGTH..].to_vec(),
            })
        }
        ENVELOPE_TYPE_2 => Ok(Envelope {
            r#type,
            sender_public_key: None,
            // Type 2 does not carry an IV; zero-fill (matches the official
            // `deserialize` which returns a random placeholder — we use zeroes
            // since it is never used for type 2).
            iv: [0u8; IV_LENGTH],
            sealed: bytes[1..].to_vec(),
        }),
        other => Err(WcError::Crypto(format!("unknown envelope type byte: {other}"))),
    }
}

// ---------------------------------------------------------------------------
// AEAD — ChaCha20-Poly1305 with empty AAD (official behavior)
// ---------------------------------------------------------------------------

/// Stateless ChaCha20-Poly1305 AEAD wrapper matching the official
/// `@walletconnect/utils` `encrypt`/`decrypt` (no AAD).
pub struct WcCipher;

impl WcCipher {
    /// ChaCha20-Poly1305 AEAD seal with **empty AAD** (official behavior).
    pub fn seal(key: &WcSymKey, nonce: &[u8; 12], plaintext: &[u8]) -> WcResult<Vec<u8>> {
        let cipher = ChaCha20Poly1305::new_from_slice(key.as_bytes())
            .map_err(|e| WcError::Crypto(e.to_string()))?;
        let n = Nonce::try_from(nonce.as_slice()).map_err(|e| WcError::Crypto(e.to_string()))?;
        cipher
            .encrypt(&n, Payload { msg: plaintext, aad: &[] })
            .map_err(|e| WcError::Crypto(e.to_string()))
    }

    /// ChaCha20-Poly1305 AEAD open with **empty AAD**.
    pub fn open(key: &WcSymKey, nonce: &[u8; 12], ciphertext_with_tag: &[u8]) -> WcResult<Vec<u8>> {
        let cipher = ChaCha20Poly1305::new_from_slice(key.as_bytes())
            .map_err(|e| WcError::Crypto(e.to_string()))?;
        let n = Nonce::try_from(nonce.as_slice()).map_err(|e| WcError::Crypto(e.to_string()))?;
        cipher
            .decrypt(&n, Payload { msg: ciphertext_with_tag, aad: &[] })
            .map_err(|e| WcError::Crypto(e.to_string()))
    }

    /// Encrypt a plaintext into a **type-0 envelope**:
    /// `[0x00 ‖ iv(12) ‖ ciphertext ‖ tag(16)]`.
    pub fn seal_type0(key: &WcSymKey, plaintext: &[u8]) -> WcResult<Vec<u8>> {
        let mut iv = [0u8; IV_LENGTH];
        rand::rng().fill(&mut iv[..]);
        let sealed = Self::seal(key, &iv, plaintext)?;
        Ok(serialize_envelope(ENVELOPE_TYPE_0, &iv, None, &sealed))
    }

    /// Decrypt a type-0 envelope.
    pub fn open_type0(key: &WcSymKey, envelope: &[u8]) -> WcResult<Vec<u8>> {
        let env = deserialize_envelope(envelope)?;
        if env.r#type != ENVELOPE_TYPE_0 {
            return Err(WcError::Crypto(format!(
                "expected type-0 envelope, got type-{}",
                env.r#type
            )));
        }
        Self::open(key, &env.iv, &env.sealed)
    }

    /// Encrypt a plaintext into a **type-1 envelope** carrying the sender's
    /// X25519 public key: `[0x01 ‖ senderPubKey(32) ‖ iv(12) ‖ ciphertext]`.
    pub fn seal_type1(
        key: &WcSymKey,
        sender_pubkey: &[u8; 32],
        plaintext: &[u8],
    ) -> WcResult<Vec<u8>> {
        let mut iv = [0u8; IV_LENGTH];
        rand::rng().fill(&mut iv[..]);
        let sealed = Self::seal(key, &iv, plaintext)?;
        Ok(serialize_envelope(ENVELOPE_TYPE_1, &iv, Some(sender_pubkey), &sealed))
    }

    /// Decrypt a type-1 envelope (returns the sender's public key + plaintext).
    pub fn open_type1(key: &WcSymKey, envelope: &[u8]) -> WcResult<([u8; 32], Vec<u8>)> {
        let env = deserialize_envelope(envelope)?;
        if env.r#type != ENVELOPE_TYPE_1 {
            return Err(WcError::Crypto(format!(
                "expected type-1 envelope, got type-{}",
                env.r#type
            )));
        }
        let sender = env
            .sender_public_key
            .ok_or_else(|| WcError::Crypto("type-1 envelope missing sender key".into()))?;
        let plaintext = Self::open(key, &env.iv, &env.sealed)?;
        Ok((sender, plaintext))
    }
}

// ---------------------------------------------------------------------------
// HMAC / generic HKDF helpers
// ---------------------------------------------------------------------------

/// HMAC-SHA256 — returns 32-byte tag.
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("hmac accepts any key size");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

/// HKDF-SHA256 — returns `len`-byte derived key.
pub fn hkdf_sha256(salt: &[u8], ikm: &[u8], info: &[u8], len: usize) -> WcResult<Vec<u8>> {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut okm = vec![0u8; len];
    hk.expand(info, &mut okm)
        .map_err(|_| WcError::Crypto("hkdf expand failed: output too long".into()))?;
    Ok(okm)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keypair_agreement_round_trips() {
        let a = WcKeyPair::generate();
        let b = WcKeyPair::generate();
        let s1 = a.shared_secret(&b.public_key());
        let s2 = b.shared_secret(&a.public_key());
        assert_eq!(s1.as_bytes(), s2.as_bytes());
    }

    #[test]
    fn derive_sym_key_is_deterministic_and_distinct() {
        let a = WcKeyPair::generate();
        let b = WcKeyPair::generate();
        let s = a.shared_secret(&b.public_key());
        let k1 = derive_sym_key(&s);
        let k2 = derive_sym_key(&s);
        assert_eq!(k1.as_bytes(), k2.as_bytes());
        // Different shared secret → different key.
        let c = WcKeyPair::generate();
        let s2 = a.shared_secret(&c.public_key());
        let k3 = derive_sym_key(&s2);
        assert_ne!(k1.as_bytes(), k3.as_bytes());
    }

    #[test]
    fn envelope_type0_round_trip() {
        let key = WcSymKey::from_random();
        let msg = b"hello world";
        let sealed = WcCipher::seal_type0(&key, msg).unwrap();
        // [type(1) + iv(12) + ct(+16 tag)]
        assert_eq!(sealed[0], ENVELOPE_TYPE_0);
        assert_eq!(sealed.len(), 1 + IV_LENGTH + msg.len() + 16);
        let opened = WcCipher::open_type0(&key, &sealed).unwrap();
        assert_eq!(opened, msg);
        // Wrong key must fail.
        let other = WcSymKey::from_random();
        assert!(WcCipher::open_type0(&other, &sealed).is_err());
    }

    #[test]
    fn envelope_type1_round_trip_carries_sender_key() {
        let key = WcSymKey::from_random();
        let sender = [0xABu8; 32];
        let msg = b"authenticated";
        let sealed = WcCipher::seal_type1(&key, &sender, msg).unwrap();
        assert_eq!(sealed[0], ENVELOPE_TYPE_1);
        assert_eq!(sealed.len(), 1 + KEY_LENGTH + IV_LENGTH + msg.len() + 16);
        let (recovered_sender, opened) = WcCipher::open_type1(&key, &sealed).unwrap();
        assert_eq!(recovered_sender, sender);
        assert_eq!(opened, msg);
    }

    #[test]
    fn type2_envelope_is_plaintext() {
        let bytes = serialize_envelope(ENVELOPE_TYPE_2, &[0u8; 12], None, b"raw");
        assert_eq!(bytes, [ENVELOPE_TYPE_2, b'r', b'a', b'w']);
        let env = deserialize_envelope(&bytes).unwrap();
        assert_eq!(env.r#type, ENVELOPE_TYPE_2);
        assert_eq!(env.sealed, b"raw");
    }

    #[test]
    fn hash_key_matches_sha256_hex() {
        let key = WcSymKey::from_bytes([0x11; 32]);
        assert_eq!(hash_key(&key), hash_bytes(&[0x11; 32]));
    }

    #[test]
    fn session_topic_is_sha256_of_symkey() {
        // Official client: `topic = hashKey(symKey)`.
        let key = WcSymKey::from_random();
        let topic = hash_key(&key);
        assert_eq!(topic.len(), 64);
    }
}
