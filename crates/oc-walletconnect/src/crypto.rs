//! WalletConnect v2 crypto layer.
//!
//! - X25519 key agreement (keypairs + shared secret)
//! - ChaCha20-Poly1305 AEAD (seal/open)
//! - HKDF-SHA256 (key derivation per WC v2 spec)
//! - HMAC-SHA256 (message authentication)
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

/// X25519 keypair for WC v2 session key agreement.
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
}

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
}

/// Stateless ChaCha20-Poly1305 AEAD wrapper.
///
/// Exposed as a unit struct so callers invoke `WcCipher::seal(...)` /
/// `WcCipher::open(...)` — matching the WC v2 message-encryption API
/// consumed by `relay.rs`, `session.rs`, `wallet_server.rs`, and
/// `dapp_client.rs`.
pub struct WcCipher;

impl WcCipher {
    /// ChaCha20-Poly1305 AEAD seal.
    ///
    /// Returns ciphertext with appended 16-byte tag.
    pub fn seal(
        key: &WcSymKey,
        nonce: &[u8; 12],
        aad: &[u8],
        plaintext: &[u8],
    ) -> WcResult<Vec<u8>> {
        let cipher = ChaCha20Poly1305::new_from_slice(key.as_bytes())
            .map_err(|e| WcError::Crypto(e.to_string()))?;
        let n = Nonce::try_from(nonce.as_slice()).map_err(|e| WcError::Crypto(e.to_string()))?;
        cipher
            .encrypt(&n, Payload { msg: plaintext, aad })
            .map_err(|e| WcError::Crypto(e.to_string()))
    }

    /// ChaCha20-Poly1305 AEAD open.
    ///
    /// Expects ciphertext + appended 16-byte tag.
    pub fn open(
        key: &WcSymKey,
        nonce: &[u8; 12],
        aad: &[u8],
        ciphertext_with_tag: &[u8],
    ) -> WcResult<Vec<u8>> {
        let cipher = ChaCha20Poly1305::new_from_slice(key.as_bytes())
            .map_err(|e| WcError::Crypto(e.to_string()))?;
        let n = Nonce::try_from(nonce.as_slice()).map_err(|e| WcError::Crypto(e.to_string()))?;
        cipher
            .decrypt(&n, Payload { msg: ciphertext_with_tag, aad })
            .map_err(|e| WcError::Crypto(e.to_string()))
    }
}

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
}
