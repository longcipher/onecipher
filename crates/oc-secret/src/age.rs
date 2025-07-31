//! age encryption / decryption wrapper for OneCipher.
//!
//! Wraps the `age` crate's X25519 recipient-based encryption and scrypt
//! passphrase-based decryption. Key material flows through
//! [`oc_crypto::HardenedBytes`] (page-locked + zeroized on drop) when
//! serialized to/from disk. Per R51/R52, the `age` dependency lives here,
//! NOT in `oc-crypto` (which remains zero-I/O).

use std::{
    io::{Read, Write},
    str::FromStr,
};

use age::{
    Decryptor, Encryptor,
    secrecy::{ExposeSecret, SecretString},
    x25519::{Identity as AgeX25519Identity, Recipient as AgeX25519Recipient},
};
use oc_crypto::HardenedBytes;
use zeroize::Zeroize;

/// Errors returned by age encryption / decryption operations.
#[derive(Debug, thiserror::Error)]
pub enum AgeError {
    #[error("encryption failed: {0}")]
    Encryption(String),
    #[error("decryption failed: {0}")]
    Decryption(String),
    #[error("invalid recipient: {0}")]
    InvalidRecipient(String),
    #[error("invalid identity: {0}")]
    InvalidIdentity(String),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("memory hardening failed: {0}")]
    MemGuard(String),
}

impl From<oc_crypto::MemGuardError> for AgeError {
    fn from(e: oc_crypto::MemGuardError) -> Self {
        Self::MemGuard(e.to_string())
    }
}

/// An age X25519 identity (private key).
///
/// Wraps [`age::x25519::Identity`]. The underlying age identity manages its
/// own in-memory representation; when serializing to/from disk, the key
/// material flows through [`HardenedBytes`] (page-locked + zeroized on drop).
pub struct AgeIdentity {
    identity: AgeX25519Identity,
}

impl AgeIdentity {
    /// Generate a new random age X25519 identity.
    pub fn generate() -> Self {
        Self { identity: AgeX25519Identity::generate() }
    }

    /// Parse an identity from the standard age identity string
    /// (`AGE-SECRET-KEY-1...`).
    ///
    /// This delegates to the [`FromStr`] implementation.
    pub fn parse(s: &str) -> Result<Self, AgeError> {
        Self::from_str(s)
    }

    /// Serialize the identity to the standard age identity string
    /// (`AGE-SECRET-KEY-1...`).
    ///
    /// The returned `String` holds sensitive material — callers should
    /// [`Zeroize::zeroize`] it when done, or prefer
    /// [`to_hardened_bytes`](Self::to_hardened_bytes).
    pub fn to_secret_string(&self) -> String {
        // age 0.11.5's inherent `Identity::to_string()` returns a
        // `HardenedKey<str>` wrapper; `expose_secret()` yields the `&str`.
        self.identity.to_string().expose_secret().to_owned()
    }

    /// Return the public recipient string (`age1...`) for this identity.
    pub fn to_recipient_string(&self) -> String {
        format!("{}", self.identity.to_public())
    }

    /// Serialize the identity string into a [`HardenedBytes`] buffer.
    ///
    /// The returned buffer is page-locked and zeroized on drop. Use this
    /// when persisting the identity to disk.
    pub fn to_hardened_bytes(&self) -> Result<HardenedBytes, AgeError> {
        // Build the identity string and move it directly into a hardened
        // buffer without leaving a `String` around longer than necessary.
        let s = self.to_secret_string();
        let bytes = s.into_bytes();
        HardenedBytes::from_vec(bytes).map_err(AgeError::from)
    }

    /// Parse an identity from a [`HardenedBytes`] buffer previously produced
    /// by [`to_hardened_bytes`](Self::to_hardened_bytes).
    pub fn from_hardened_bytes(bytes: &HardenedBytes) -> Result<Self, AgeError> {
        // The age identity string is ASCII; from_utf8 is infallible in
        // practice, but we handle the error path defensively.
        let mut s = String::from_utf8(bytes.as_ref().to_vec())
            .map_err(|e| AgeError::InvalidIdentity(format!("invalid UTF-8: {e}")))?;
        let result = Self::from_str(&s);
        s.zeroize();
        result
    }

    /// Reference to the underlying age identity (for internal use by
    /// [`decrypt_payload`]).
    pub(crate) fn as_age_identity(&self) -> &AgeX25519Identity {
        &self.identity
    }
}

impl std::fmt::Debug for AgeIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AgeIdentity(***)")
    }
}

impl FromStr for AgeIdentity {
    type Err = AgeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let identity: AgeX25519Identity =
            s.parse().map_err(|e: &str| AgeError::InvalidIdentity(e.to_string()))?;
        Ok(Self { identity })
    }
}

/// Encrypt `plaintext` to one or more age recipients.
///
/// `recipients` is a list of age recipient strings (`age1...`). The
/// ciphertext is returned as a `Vec<u8>` suitable for writing to a file.
pub fn encrypt_payload(plaintext: &[u8], recipients: &[String]) -> Result<Vec<u8>, AgeError> {
    if recipients.is_empty() {
        return Err(AgeError::InvalidRecipient("no recipients provided".into()));
    }

    // Parse recipient strings into age::x25519::Recipient values.
    let parsed: Vec<AgeX25519Recipient> = recipients
        .iter()
        .map(|s| {
            s.parse::<AgeX25519Recipient>()
                .map_err(|e: &str| AgeError::InvalidRecipient(format!("{s}: {e}")))
        })
        .collect::<Result<_, _>>()?;

    // age 0.11.5's Encryptor::with_recipients takes `Iterator<Item = &dyn Recipient>`.
    let recipient_refs: Vec<&dyn age::Recipient> =
        parsed.iter().map(|r| r as &dyn age::Recipient).collect();

    let encryptor = Encryptor::with_recipients(recipient_refs.into_iter())
        .map_err(|e| AgeError::Encryption(e.to_string()))?;

    let mut encrypted = Vec::new();
    let mut writer =
        encryptor.wrap_output(&mut encrypted).map_err(|e| AgeError::Encryption(e.to_string()))?;
    writer.write_all(plaintext).map_err(|e| AgeError::Encryption(e.to_string()))?;
    writer.finish().map_err(|e| AgeError::Encryption(e.to_string()))?;
    Ok(encrypted)
}

/// Decrypt a ciphertext using an age X25519 identity.
pub fn decrypt_payload(ciphertext: &[u8], identity: &AgeIdentity) -> Result<Vec<u8>, AgeError> {
    let decryptor = Decryptor::new(ciphertext).map_err(|e| AgeError::Decryption(e.to_string()))?;
    let mut reader = decryptor
        .decrypt(std::iter::once(identity.as_age_identity() as &dyn age::Identity))
        .map_err(|e| AgeError::Decryption(e.to_string()))?;
    let mut decrypted = Vec::new();
    reader.read_to_end(&mut decrypted).map_err(|e| AgeError::Decryption(e.to_string()))?;
    Ok(decrypted)
}

/// Decrypt a passphrase-encrypted (scrypt) age ciphertext.
pub fn decrypt_with_passphrase(ciphertext: &[u8], passphrase: &str) -> Result<Vec<u8>, AgeError> {
    let secret = SecretString::from(passphrase.to_owned());
    let scrypt_identity = age::scrypt::Identity::new(secret);

    let decryptor = Decryptor::new(ciphertext).map_err(|e| AgeError::Decryption(e.to_string()))?;
    let mut reader = decryptor
        .decrypt(std::iter::once(&scrypt_identity as &dyn age::Identity))
        .map_err(|e| AgeError::Decryption(e.to_string()))?;
    let mut decrypted = Vec::new();
    reader.read_to_end(&mut decrypted).map_err(|e| AgeError::Decryption(e.to_string()))?;
    Ok(decrypted)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_and_round_trip() {
        let identity = AgeIdentity::generate();
        let recipient = identity.to_recipient_string();
        assert!(recipient.starts_with("age1"));

        let plaintext = b"hello age";
        let ciphertext = encrypt_payload(plaintext, &[recipient]).unwrap();
        assert_ne!(&ciphertext[..], &plaintext[..]);

        let decrypted = decrypt_payload(&ciphertext, &identity).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn identity_string_starts_with_age_secret_key() {
        let identity = AgeIdentity::generate();
        let s = identity.to_secret_string();
        assert!(s.starts_with("AGE-SECRET-KEY-1"), "got: {s}");
    }

    #[test]
    fn hardened_bytes_round_trip() {
        let identity = AgeIdentity::generate();
        let bytes = identity.to_hardened_bytes().unwrap();
        let restored = AgeIdentity::from_hardened_bytes(&bytes).unwrap();
        assert_eq!(identity.to_secret_string(), restored.to_secret_string());
    }

    #[test]
    fn encrypt_with_multiple_recipients() {
        let id1 = AgeIdentity::generate();
        let id2 = AgeIdentity::generate();
        let recipients = vec![id1.to_recipient_string(), id2.to_recipient_string()];

        let plaintext = b"multi-recipient test";
        let ciphertext = encrypt_payload(plaintext, &recipients).unwrap();

        // Both identities can decrypt.
        assert_eq!(decrypt_payload(&ciphertext, &id1).unwrap(), plaintext);
        assert_eq!(decrypt_payload(&ciphertext, &id2).unwrap(), plaintext);
    }

    #[test]
    fn encrypt_no_recipients_fails() {
        let result = encrypt_payload(b"data", &[]);
        assert!(matches!(result, Err(AgeError::InvalidRecipient(_))));
    }

    #[test]
    fn invalid_recipient_string_fails() {
        let result = encrypt_payload(b"data", &["not-a-valid-recipient".to_string()]);
        assert!(matches!(result, Err(AgeError::InvalidRecipient(_))));
    }

    #[test]
    fn passphrase_decrypt_round_trip() {
        let passphrase = "correct horse battery staple";
        let plaintext = b"passphrase secret";

        let secret = SecretString::from(passphrase.to_owned());
        let encryptor = Encryptor::with_user_passphrase(secret);

        let mut encrypted = Vec::new();
        let mut writer = encryptor.wrap_output(&mut encrypted).unwrap();
        writer.write_all(plaintext).unwrap();
        writer.finish().unwrap();

        let decrypted = decrypt_with_passphrase(&encrypted, passphrase).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn passphrase_wrong_passphrase_fails() {
        let passphrase = "correct horse battery staple";
        let plaintext = b"passphrase secret";

        let secret = SecretString::from(passphrase.to_owned());
        let encryptor = Encryptor::with_user_passphrase(secret);

        let mut encrypted = Vec::new();
        let mut writer = encryptor.wrap_output(&mut encrypted).unwrap();
        writer.write_all(plaintext).unwrap();
        writer.finish().unwrap();

        let result = decrypt_with_passphrase(&encrypted, "wrong passphrase");
        assert!(result.is_err());
    }

    #[test]
    fn debug_does_not_leak() {
        let identity = AgeIdentity::generate();
        let s = format!("{identity:?}");
        assert_eq!(s, "AgeIdentity(***)");
    }

    #[test]
    fn decrypt_wrong_identity_fails() {
        let id1 = AgeIdentity::generate();
        let id2 = AgeIdentity::generate();
        let ciphertext = encrypt_payload(b"secret", &[id1.to_recipient_string()]).unwrap();
        let result = decrypt_payload(&ciphertext, &id2);
        assert!(matches!(result, Err(AgeError::Decryption(_))));
    }
}
