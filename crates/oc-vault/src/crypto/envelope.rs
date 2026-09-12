// Unified age encryption envelope: the single ciphertext format for wallet
// files, API-token wallet copies and `.ocbk` backup bundles.
//
// Every payload is an `age` file (X25519 recipients and/or scrypt
// passphrase), following the design already proven by `oc-secret`:
// - Owner/device passphrases use the scrypt recipient (`encrypt_with_passphrase` /
//   `decrypt_with_passphrase`). The raw passphrase bytes are hex-encoded into the scrypt passphrase
//   string; hex is injective, so distinct byte strings (including empty and non-UTF8 inputs such as
//   UnlockToken-derived 32-byte secrets) always yield distinct scrypt inputs.
// - API-token copies and backups use X25519 recipients (`encrypt_to_recipients` /
//   `decrypt_with_identity`). Each API token's 32 random bytes ARE the X25519 static secret
//   (`token_identity`), so the key file stores only the public recipient plus the token hash — the
//   token plaintext is shown once at creation and never persisted.
// - The on-disk JSON wrapper ([`AgeEnvelope}]) carries `cipher: "age"` plus the base64 age binary.
//   Anything else in `cipher` (including the retired `aes-256-gcm-siv` envelopes) fails closed as
//   `InvalidParams`.
//
// R56: this module uses only `age` + `base64` + `bech32` + `hex` +
// `oc-crypto` + `oc-core` (no `tokio`, no networking). The `age` dependency
// lives here and in `oc-secret`, NEVER in `oc-crypto` (R51/R52).
// English comments only.

// Ban test-only weak scrypt cost in release builds (mirrors the old
// `fast-kdf` Argon2 guard: weak KDF parameters are test-only).
#[cfg(all(feature = "fast-kdf", not(debug_assertions)))]
compile_error!(
    "The `fast-kdf` feature reduces the age scrypt work factor and must not be used in release builds."
);

// Test scrypt work factor (`N = 2^10`): keeps unit tests in the millisecond
// range. Production uses age's auto-calibrated factor (~1 s of work).
#[cfg(any(test, feature = "fast-kdf"))]
const TEST_SCRYPT_WORK_FACTOR: u8 = 10;

/// Cipher tag carried by every envelope minted by this module.
pub const AGE_CIPHER: &str = "age";

use std::io::{Read, Write};

use age::{
    Decryptor, Encryptor,
    secrecy::{ExposeSecret, SecretString},
};
use base64::Engine as _;
use oc_crypto::HardenedBytes;

/// Errors returned by the unified age envelope operations.
#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("encryption failed: {0}")]
    EncryptionFailed(String),
    #[error("decryption failed: {0}")]
    DecryptionFailed(String),
    #[error("invalid parameters: {0}")]
    InvalidParams(String),
}

impl From<oc_crypto::MemGuardError> for CryptoError {
    fn from(e: oc_crypto::MemGuardError) -> Self {
        Self::DecryptionFailed(format!("memory hardening failed: {e}"))
    }
}

/// On-disk JSON wrapper around an age ciphertext.
///
/// `ciphertext` is the base64-encoded age binary (self-describing: its header
/// stanzas identify the scrypt vs X25519 recipient type). `cipher` is always
/// `"age"`; any other value fails closed in [`decode_envelope`].
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AgeEnvelope {
    pub cipher: String,
    pub ciphertext: String,
}

/// An age X25519 identity (private key), e.g. a backup identity or a
/// token-derived identity (see [`token_identity`]).
///
/// The inner age identity wipes its key material on drop; `Debug` is redacted
/// so identities never leak into logs.
#[derive(Clone)]
pub struct AgeIdentity {
    identity: age::x25519::Identity,
}

impl AgeIdentity {
    /// Generate a fresh random X25519 identity.
    pub fn generate() -> Self {
        Self { identity: age::x25519::Identity::generate() }
    }

    /// Parse an identity from its `AGE-SECRET-KEY-1...` string form.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::InvalidParams`] when the string is not a valid
    /// age identity.
    pub fn parse(s: &str) -> Result<Self, CryptoError> {
        s.parse::<age::x25519::Identity>()
            .map(|identity| Self { identity })
            .map_err(|e| CryptoError::InvalidParams(format!("invalid age identity: {e}")))
    }

    /// Return the public recipient string (`age1...`) for this identity.
    pub fn to_recipient_string(&self) -> String {
        self.identity.to_public().to_string()
    }

    /// Export the identity as its `AGE-SECRET-KEY-1...` string for backup.
    ///
    /// The returned buffer is [`zeroize::Zeroizing`] (wiped on drop); never
    /// log or Debug-print it. Persist it with 0600 permissions, separate
    /// from the bundles it decrypts.
    pub fn to_secret_string(&self) -> zeroize::Zeroizing<String> {
        zeroize::Zeroizing::new(self.identity.to_string().expose_secret().to_owned())
    }

    /// Borrow the underlying age identity for decryption.
    pub(crate) fn as_age(&self) -> &age::x25519::Identity {
        &self.identity
    }
}

impl std::fmt::Debug for AgeIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AgeIdentity(***)")
    }
}

/// Map arbitrary passphrase bytes to the age scrypt passphrase string.
///
/// Hex encoding is injective, so distinct inputs (including empty and
/// non-UTF8 byte strings) always produce distinct scrypt passphrases.
fn scrypt_secret(passphrase: &[u8]) -> SecretString {
    SecretString::from(hex::encode(passphrase))
}

/// Build the scrypt recipient for `passphrase`, pinning a low work factor in
/// test builds for speed.
fn scrypt_recipient(passphrase: &[u8]) -> age::scrypt::Recipient {
    #[allow(unused_mut)]
    let mut recipient = age::scrypt::Recipient::new(scrypt_secret(passphrase));
    #[cfg(any(test, feature = "fast-kdf"))]
    recipient.set_work_factor(TEST_SCRYPT_WORK_FACTOR);
    recipient
}

/// Encrypt `plaintext` to an age recipient set, returning the raw age binary.
fn encrypt_raw(
    plaintext: &[u8],
    recipients: &[&dyn age::Recipient],
) -> Result<Vec<u8>, CryptoError> {
    let encryptor = Encryptor::with_recipients(recipients.iter().copied())
        .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;
    let mut ciphertext = Vec::new();
    let mut writer = encryptor
        .wrap_output(&mut ciphertext)
        .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;
    writer.write_all(plaintext).map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;
    writer.finish().map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;
    Ok(ciphertext)
}

/// Decrypt a raw age binary with the given identities, returning the
/// plaintext as page-locked [`HardenedBytes`].
fn decrypt_raw(
    ciphertext: &[u8],
    identities: &[&dyn age::Identity],
) -> Result<HardenedBytes, CryptoError> {
    let decryptor =
        Decryptor::new(ciphertext).map_err(|e| CryptoError::DecryptionFailed(e.to_string()))?;
    let mut reader = decryptor
        .decrypt(identities.iter().copied())
        .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))?;
    let mut plaintext = Vec::new();
    reader.read_to_end(&mut plaintext).map_err(|e| CryptoError::DecryptionFailed(e.to_string()))?;
    HardenedBytes::from_vec(plaintext).map_err(CryptoError::from)
}

/// Wrap a raw age binary in the JSON envelope.
fn encode_envelope(ciphertext: Vec<u8>) -> AgeEnvelope {
    AgeEnvelope {
        cipher: AGE_CIPHER.to_string(),
        ciphertext: base64::prelude::BASE64_STANDARD.encode(&ciphertext),
    }
}

/// Validate the envelope tag and base64-decode the age binary.
///
/// # Errors
///
/// Returns [`CryptoError::InvalidParams`] for a non-`age` cipher tag
/// (including every retired legacy envelope) or malformed base64.
fn decode_envelope(envelope: &AgeEnvelope) -> Result<Vec<u8>, CryptoError> {
    if envelope.cipher != AGE_CIPHER {
        return Err(CryptoError::InvalidParams(format!(
            "unsupported cipher '{}': this build reads only age ('{AGE_CIPHER}') envelopes; \
             recreate the wallet, token or backup under the current format",
            envelope.cipher
        )));
    }
    base64::prelude::BASE64_STANDARD
        .decode(envelope.ciphertext.as_bytes())
        .map_err(|e| CryptoError::InvalidParams(format!("invalid age ciphertext base64: {e}")))
}

/// Encrypt `plaintext` under a passphrase (age scrypt recipient).
///
/// Works for owner passphrases (UTF-8) and device-derived secrets (arbitrary
/// bytes, e.g. `UnlockToken` output): both flow through the same injective
/// hex mapping (see [`scrypt_secret`]).
///
/// # Errors
///
/// Returns [`CryptoError::EncryptionFailed`] when age encryption fails, or
/// [`CryptoError::DecryptionFailed`] when the hardened output buffer cannot
/// be allocated.
pub fn encrypt_with_passphrase(
    plaintext: &[u8],
    passphrase: &[u8],
) -> Result<AgeEnvelope, CryptoError> {
    let recipient = scrypt_recipient(passphrase);
    let raw = encrypt_raw(plaintext, &[&recipient as &dyn age::Recipient])?;
    Ok(encode_envelope(raw))
}

/// Decrypt an envelope minted by [`encrypt_with_passphrase`].
///
/// # Errors
///
/// Returns [`CryptoError::InvalidParams`] for a non-`age` envelope or
/// malformed base64, and [`CryptoError::DecryptionFailed`] for a wrong
/// passphrase or tampered ciphertext.
pub fn decrypt_with_passphrase(
    envelope: &AgeEnvelope,
    passphrase: &[u8],
) -> Result<HardenedBytes, CryptoError> {
    let raw = decode_envelope(envelope)?;
    let identity = age::scrypt::Identity::new(scrypt_secret(passphrase));
    decrypt_raw(&raw, &[&identity as &dyn age::Identity])
}

/// Encrypt `plaintext` to one or more age X25519 recipients (`age1...`).
///
/// Used for API-token wallet copies (single recipient) and backup bundles
/// (multiple recipients). Fails closed on an empty recipient list.
///
/// # Errors
///
/// Returns [`CryptoError::InvalidParams`] for an empty list or an
/// unparseable recipient, and [`CryptoError::EncryptionFailed`] when age
/// encryption fails.
pub fn encrypt_to_recipients(
    plaintext: &[u8],
    recipients: &[String],
) -> Result<AgeEnvelope, CryptoError> {
    if recipients.is_empty() {
        return Err(CryptoError::InvalidParams("no age recipients provided".into()));
    }
    let parsed: Vec<age::x25519::Recipient> = recipients
        .iter()
        .map(|s| {
            s.parse::<age::x25519::Recipient>().map_err(|e: &str| {
                CryptoError::InvalidParams(format!("invalid age recipient '{s}': {e}"))
            })
        })
        .collect::<Result<_, _>>()?;
    let refs: Vec<&dyn age::Recipient> = parsed.iter().map(|r| r as &dyn age::Recipient).collect();
    let raw = encrypt_raw(plaintext, &refs)?;
    Ok(encode_envelope(raw))
}

/// Decrypt an envelope minted by [`encrypt_to_recipients`] with an X25519
/// identity.
///
/// # Errors
///
/// Returns [`CryptoError::InvalidParams`] for a non-`age` envelope or
/// malformed base64, and [`CryptoError::DecryptionFailed`] when the identity
/// matches no recipient stanza or the ciphertext is tampered.
pub fn decrypt_with_identity(
    envelope: &AgeEnvelope,
    identity: &AgeIdentity,
) -> Result<HardenedBytes, CryptoError> {
    let raw = decode_envelope(envelope)?;
    decrypt_raw(&raw, &[identity.as_age() as &dyn age::Identity])
}

/// Bech32 human-readable part for age secret keys (`AGE-SECRET-KEY-...`).
const AGE_SECRET_HRP: &str = "age-secret-key-";

/// Extract the 32 key bytes from an `oc_key_<64 hex>` API token.
///
/// # Errors
///
/// Returns [`CryptoError::InvalidParams`] for a missing prefix, malformed
/// hex, or a wrong byte length.
fn token_key_bytes(token: &str) -> Result<[u8; 32], CryptoError> {
    let invalid = |why: &str| CryptoError::InvalidParams(format!("invalid API token: {why}"));
    let hexpart = token
        .strip_prefix(oc_core::credential::TOKEN_PREFIX)
        .ok_or_else(|| invalid("missing prefix"))?;
    let bytes = hex::decode(hexpart).map_err(|_| invalid("malformed hex"))?;
    <[u8; 32]>::try_from(bytes).map_err(|_| invalid("wrong length"))
}

/// Rebuild the X25519 identity behind an API token.
///
/// The token's 32 random bytes ARE the age static secret: they are
/// bech32-encoded as an `AGE-SECRET-KEY-...` string and parsed back into an
/// age identity, so the holder of the token plaintext can always decrypt the
/// wallet copies encrypted to [`token_recipient`].
///
/// # Errors
///
/// Returns [`CryptoError::InvalidParams`] for a malformed token.
pub fn token_identity(token: &str) -> Result<AgeIdentity, CryptoError> {
    let bytes = token_key_bytes(token)?;
    let hrp = bech32::Hrp::parse(AGE_SECRET_HRP)
        .map_err(|e| CryptoError::InvalidParams(format!("bech32 HRP: {e}")))?;
    let encoded = bech32::encode::<bech32::Bech32>(hrp, &bytes)
        .map_err(|e| CryptoError::InvalidParams(format!("bech32 encode: {e}")))?;
    // Age renders secret keys uppercase; the parser accepts either case, but
    // match the canonical form exactly.
    AgeIdentity::parse(&encoded.to_uppercase())
}

/// Derive the age recipient (`age1...`) for an API token.
///
/// Called once at token creation; the recipient is stored in the key file
/// while the token plaintext is shown to the owner exactly once.
///
/// # Errors
///
/// Returns [`CryptoError::InvalidParams`] for a malformed token.
pub fn token_recipient(token: &str) -> Result<String, CryptoError> {
    token_identity(token).map(|id| id.to_recipient_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passphrase_roundtrip() {
        let env = encrypt_with_passphrase(b"hello vault", b"passphrase").unwrap();
        assert_eq!(env.cipher, AGE_CIPHER);
        let out = decrypt_with_passphrase(&env, b"passphrase").unwrap();
        assert_eq!(out.expose(), b"hello vault");
    }

    #[test]
    fn empty_passphrase_roundtrip() {
        // Unencrypted-by-default wallets (empty passphrase) keep working.
        let env = encrypt_with_passphrase(b"data", b"").unwrap();
        let out = decrypt_with_passphrase(&env, b"").unwrap();
        assert_eq!(out.expose(), b"data");
    }

    #[test]
    fn non_utf8_passphrase_roundtrip() {
        // Device-derived secrets (e.g. UnlockToken output) are arbitrary bytes.
        let passphrase = [0xFF, 0x00, 0xAB, 0x13, 0x7F, 0x80];
        let env = encrypt_with_passphrase(b"secret", &passphrase).unwrap();
        let out = decrypt_with_passphrase(&env, &passphrase).unwrap();
        assert_eq!(out.expose(), b"secret");
    }

    #[test]
    fn wrong_passphrase_fails() {
        let env = encrypt_with_passphrase(b"secret", b"right").unwrap();
        assert!(decrypt_with_passphrase(&env, b"wrong").is_err());
    }

    #[test]
    fn different_encryptions_differ() {
        let env1 = encrypt_with_passphrase(b"same", b"pass").unwrap();
        let env2 = encrypt_with_passphrase(b"same", b"pass").unwrap();
        assert_ne!(env1.ciphertext, env2.ciphertext);
    }

    #[test]
    fn legacy_cipher_rejected() {
        let mut env = encrypt_with_passphrase(b"x", b"p").unwrap();
        env.cipher = "aes-256-gcm-siv".to_string();
        let err = decrypt_with_passphrase(&env, b"p").unwrap_err();
        assert!(matches!(err, CryptoError::InvalidParams(_)));
        let err = decrypt_with_identity(&env, &AgeIdentity::generate()).unwrap_err();
        assert!(matches!(err, CryptoError::InvalidParams(_)));
    }

    #[test]
    fn malformed_base64_rejected() {
        let env = AgeEnvelope { cipher: AGE_CIPHER.to_string(), ciphertext: "!!!".to_string() };
        assert!(matches!(
            decrypt_with_passphrase(&env, b"p").unwrap_err(),
            CryptoError::InvalidParams(_)
        ));
    }

    #[test]
    fn recipient_roundtrip_single() {
        let id = AgeIdentity::generate();
        let recipient = id.to_recipient_string();
        assert!(recipient.starts_with("age1"));
        let env = encrypt_to_recipients(b"token copy", &[recipient]).unwrap();
        let out = decrypt_with_identity(&env, &id).unwrap();
        assert_eq!(out.expose(), b"token copy");
    }

    #[test]
    fn recipient_roundtrip_multi() {
        let id1 = AgeIdentity::generate();
        let id2 = AgeIdentity::generate();
        let recipients = vec![id1.to_recipient_string(), id2.to_recipient_string()];
        let env = encrypt_to_recipients(b"backup payload", &recipients).unwrap();
        assert_eq!(decrypt_with_identity(&env, &id1).unwrap().expose(), b"backup payload");
        assert_eq!(decrypt_with_identity(&env, &id2).unwrap().expose(), b"backup payload");
    }

    #[test]
    fn wrong_identity_fails() {
        let id1 = AgeIdentity::generate();
        let id2 = AgeIdentity::generate();
        let env = encrypt_to_recipients(b"secret", &[id1.to_recipient_string()]).unwrap();
        assert!(matches!(
            decrypt_with_identity(&env, &id2).unwrap_err(),
            CryptoError::DecryptionFailed(_)
        ));
    }

    #[test]
    fn empty_recipients_rejected() {
        assert!(matches!(
            encrypt_to_recipients(b"x", &[]).unwrap_err(),
            CryptoError::InvalidParams(_)
        ));
    }

    #[test]
    fn invalid_recipient_rejected() {
        assert!(matches!(
            encrypt_to_recipients(b"x", &["not-a-recipient".to_string()]).unwrap_err(),
            CryptoError::InvalidParams(_)
        ));
    }

    #[test]
    fn token_identity_roundtrip() {
        // A fixed 32-byte token maps deterministically to one recipient, and
        // the reconstructed identity decrypts copies encrypted to it.
        let token = format!(
            "{}a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
            oc_core::credential::TOKEN_PREFIX
        );
        let recipient = token_recipient(&token).unwrap();
        assert!(recipient.starts_with("age1"));
        assert_eq!(token_recipient(&token).unwrap(), recipient);
        let env = encrypt_to_recipients(b"wallet secret", &[recipient]).unwrap();
        let identity = token_identity(&token).unwrap();
        let out = decrypt_with_identity(&env, &identity).unwrap();
        assert_eq!(out.expose(), b"wallet secret");
    }

    #[test]
    fn token_identity_matches_generated_format() {
        // Random tokens from the key-store generator are valid identities.
        let bytes = [0x42u8; 32];
        let token = format!("{}{}", oc_core::credential::TOKEN_PREFIX, hex::encode(bytes));
        let recipient = token_recipient(&token).unwrap();
        let identity = token_identity(&token).unwrap();
        assert_eq!(identity.to_recipient_string(), recipient);
    }

    #[test]
    fn malformed_tokens_rejected() {
        assert!(token_identity("no-prefix").is_err());
        assert!(token_identity(&format!("{}zz", oc_core::credential::TOKEN_PREFIX)).is_err());
        assert!(token_identity(&format!("{}abcd", oc_core::credential::TOKEN_PREFIX)).is_err());
    }

    #[test]
    fn envelope_serde_roundtrip() {
        let env = encrypt_with_passphrase(b"serde", b"pass").unwrap();
        let json = serde_json::to_string(&env).unwrap();
        let back: AgeEnvelope = serde_json::from_str(&json).unwrap();
        assert_eq!(back.cipher, AGE_CIPHER);
        let out = decrypt_with_passphrase(&back, b"pass").unwrap();
        assert_eq!(out.expose(), b"serde");
    }

    #[test]
    fn identity_debug_redacted() {
        let id = AgeIdentity::generate();
        assert_eq!(format!("{id:?}"), "AgeIdentity(***)");
    }

    #[test]
    fn identity_secret_string_roundtrip() {
        let id = AgeIdentity::generate();
        let secret = id.to_secret_string();
        assert!(secret.starts_with("AGE-SECRET-KEY-1"));
        let back = AgeIdentity::parse(&secret).unwrap();
        assert_eq!(back.to_recipient_string(), id.to_recipient_string());
    }

    #[test]
    fn identity_string_roundtrip() {
        // The bech32 token-key encoding parses through age's own decoder:
        // recipient derived either way is identical.
        let token = format!(
            "{}ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            oc_core::credential::TOKEN_PREFIX
        );
        let direct = token_recipient(&token).unwrap();
        let identity = token_identity(&token).unwrap();
        assert_eq!(direct, identity.to_recipient_string());
    }
}
