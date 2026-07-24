//! `.ocbk` BackupContainer — Argon2id + XChaCha20-Poly1305 AEAD (R42 / AD-05).
//!
//! The container is a single JSON-serializable record:
//!
//! ```text
//! { magic, version, kdf_params, salt, nonce, ciphertext, failed_attempts, locked }
//! ```
//!
//! - `magic` = `b"OCBK"`, `version` = 1.
//! - KDF: Argon2id (m=64 MiB, t=3, p=4 by default per AD-05).
//! - Cipher: XChaCha20-Poly1305 (24-byte nonce, 16-byte Poly1305 tag appended to the ciphertext by
//!   the `chacha20poly1305` crate).
//! - `failed_attempts` and `locked` are persisted in the container header so a caller can serialize
//!   the container back to disk after a failed attempt and observe the lockout on next load.
//!
//! Wrong-passphrase backoff: production default is exponential
//! (1 s, 2 s, 4 s, ... = `2^(attempts-1)` seconds). For tests, call
//! [`set_backoff_override`] with `Some(Duration::ZERO)`; the override is
//! thread-local so it does not bleed between parallel test threads.

use std::{cell::RefCell, time::Duration};

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit},
};
use rand::RngExt;
use serde::{Deserialize, Serialize};

use crate::error::OcVaultError;

/// Magic bytes identifying a OneCipher backup container (`"OCBK"`).
pub const MAGIC: [u8; 4] = *b"OCBK";

/// Current on-disk format version.
pub const VERSION: u8 = 1;

/// Failed-passphrase attempts after which the container becomes permanently
/// locked (per R42 behavioral contract: 10).
pub const MAX_FAILED_ATTEMPTS: u32 = 10;

/// Argon2id output length (32 bytes — XChaCha20-Poly1305 key size).
const KEY_LEN: usize = 32;

/// Salt length (256 bits — Argon2id recommendation).
const SALT_LEN: usize = 32;

/// XChaCha20-Poly1305 nonce length (192 bits).
const NONCE_LEN: usize = 24;

thread_local! {
    static BACKOFF_OVERRIDE: RefCell<Option<Duration>> = const { RefCell::new(None) };
}

/// Override the wrong-passphrase backoff duration for the calling thread.
///
/// **Test-only utility.** Production code should never call this. Setting
/// `Some(Duration::ZERO)` disables the exponential backoff so unit tests
/// can exercise the lockout path without sleeping for 511 seconds.
/// Pass `None` to restore production behavior.
///
/// Gated behind `#[cfg(any(test, feature = "test-utils"))]` so it is only
/// compiled in unit tests (`cfg(test)`) or when the `test-utils` cargo
/// feature is enabled (used by the BDD conformance crate, which lives in a
/// separate crate and so does not have `cfg(test)` set for `oc-vault`).
#[cfg(any(test, feature = "test-utils"))]
pub fn set_backoff_override(d: Option<Duration>) {
    BACKOFF_OVERRIDE.with(|cell| *cell.borrow_mut() = d);
}

/// Argon2id KDF parameters.
///
/// Defaults per AD-05: m=64 MiB (65536 KiB), t=3, p=4. This costs ~300 ms
/// per derivation on commodity hardware — appropriate for a backup
/// container that is unlocked rarely.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Argon2idParams {
    /// Memory cost in KiB. Default = 64 * 1024 (64 MiB).
    pub m_cost: u32,
    /// Time cost (iterations). Default = 3.
    pub t_cost: u32,
    /// Parallelism (lanes). Default = 4.
    pub p_cost: u32,
}

impl Default for Argon2idParams {
    fn default() -> Self {
        Self { m_cost: 64 * 1024, t_cost: 3, p_cost: 4 }
    }
}

/// `.ocbk` backup container.
///
/// Round-trips a payload through Argon2id-derived XChaCha20-Poly1305 AEAD.
/// Tracks failed-passphrase attempts and locks after [`MAX_FAILED_ATTEMPTS`].
/// All fields are public and `Serialize`/`Deserialize` so callers can
/// persist the container (e.g. as JSON) between `import` calls.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupContainer {
    pub magic: [u8; 4],
    pub version: u8,
    pub kdf_params: Argon2idParams,
    pub salt: Vec<u8>,
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub failed_attempts: u32,
    pub locked: bool,
}

impl BackupContainer {
    /// Encrypt `payload` with `passphrase` using default Argon2id params.
    ///
    /// Convenience wrapper around [`export_with_params`](Self::export_with_params).
    pub fn export(payload: &[u8], passphrase: &str) -> Result<Self, OcVaultError> {
        Self::export_with_params(payload, passphrase, Argon2idParams::default())
    }

    /// Encrypt `payload` with `passphrase` using caller-supplied Argon2id params.
    ///
    /// `params` is stored in the resulting container so decryption can
    /// re-derive the key. Tests typically pass a weak `Argon2idParams {
    /// m_cost: 8, t_cost: 1, p_cost: 1 }` to keep iterations under 1 ms.
    pub fn export_with_params(
        payload: &[u8],
        passphrase: &str,
        params: Argon2idParams,
    ) -> Result<Self, OcVaultError> {
        let mut salt = vec![0u8; SALT_LEN];
        let mut nonce = vec![0u8; NONCE_LEN];
        rand::rng().fill(&mut salt[..]);
        rand::rng().fill(&mut nonce[..]);

        let key = derive_key(passphrase, &salt, &params)?;
        let cipher = XChaCha20Poly1305::new_from_slice(&key)
            .map_err(|e| OcVaultError::Crypto(e.to_string()))?;
        let ciphertext = cipher
            .encrypt(
                &XNonce::try_from(nonce.as_slice())
                    .map_err(|e| OcVaultError::Crypto(e.to_string()))?,
                payload,
            )
            .map_err(|e| OcVaultError::Crypto(e.to_string()))?;

        Ok(Self {
            magic: MAGIC,
            version: VERSION,
            kdf_params: params,
            salt,
            nonce,
            ciphertext,
            failed_attempts: 0,
            locked: false,
        })
    }

    /// Attempt to decrypt the container with `passphrase`.
    ///
    /// - On success: resets `failed_attempts` to 0 and returns the plaintext.
    /// - On wrong passphrase: increments `failed_attempts`, applies backoff (see module docs), and
    ///   returns [`OcVaultError::WrongPassphrase`]. After [`MAX_FAILED_ATTEMPTS`] failures, sets
    ///   `locked = true` and subsequent calls return [`OcVaultError::Locked`] without trying the
    ///   passphrase.
    /// - On a locked container: returns [`OcVaultError::Locked`] immediately.
    pub fn import(&mut self, passphrase: &str) -> Result<Vec<u8>, OcVaultError> {
        if self.locked {
            return Err(OcVaultError::Locked);
        }
        if self.magic != MAGIC {
            return Err(OcVaultError::InvalidFormat(format!(
                "bad magic: expected {:?}, got {:?}",
                MAGIC, self.magic
            )));
        }
        if self.salt.len() != SALT_LEN {
            return Err(OcVaultError::InvalidFormat(format!(
                "salt must be {} bytes, got {}",
                SALT_LEN,
                self.salt.len()
            )));
        }
        if self.nonce.len() != NONCE_LEN {
            return Err(OcVaultError::InvalidFormat(format!(
                "nonce must be {} bytes, got {}",
                NONCE_LEN,
                self.nonce.len()
            )));
        }

        let key = derive_key(passphrase, &self.salt, &self.kdf_params)?;
        let cipher = XChaCha20Poly1305::new_from_slice(&key)
            .map_err(|e| OcVaultError::Crypto(e.to_string()))?;
        if let Ok(plaintext) = cipher.decrypt(
            &XNonce::try_from(self.nonce.as_slice())
                .map_err(|_| OcVaultError::Crypto("invalid nonce length".into()))?,
            self.ciphertext.as_ref(),
        ) {
            self.failed_attempts = 0;
            Ok(plaintext)
        } else {
            self.failed_attempts = self.failed_attempts.saturating_add(1);
            if self.failed_attempts >= MAX_FAILED_ATTEMPTS {
                self.locked = true;
            } else {
                std::thread::sleep(backoff_duration(self.failed_attempts));
            }
            Err(OcVaultError::WrongPassphrase)
        }
    }
}

/// Derive a 32-byte XChaCha20-Poly1305 key from `passphrase` + `salt` via Argon2id.
fn derive_key(
    passphrase: &str,
    salt: &[u8],
    params: &Argon2idParams,
) -> Result<[u8; KEY_LEN], OcVaultError> {
    let argon2_params = Params::new(params.m_cost, params.t_cost, params.p_cost, Some(KEY_LEN))
        .map_err(|e| OcVaultError::Crypto(format!("argon2 params: {e}")))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon2_params);
    let mut key = [0u8; KEY_LEN];
    argon2
        .hash_password_into(passphrase.as_bytes(), salt, &mut key)
        .map_err(|e| OcVaultError::Crypto(format!("argon2 derive: {e}")))?;
    Ok(key)
}

/// Compute the wrong-passphrase backoff for the given attempt count.
///
/// Production: `2^(attempts-1)` seconds (1, 2, 4, ...). Capped at 2^30
/// to avoid shift overflow. Thread-local override (set via
/// [`set_backoff_override`]) takes precedence.
fn backoff_duration(failed_attempts: u32) -> Duration {
    if let Some(d) = BACKOFF_OVERRIDE.with(|cell| *cell.borrow()) {
        return d;
    }
    let shift = failed_attempts.saturating_sub(1).min(30);
    Duration::from_secs(1u64 << shift)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Weak KDF params for fast tests (<1 ms per derivation).
    fn fast_params() -> Argon2idParams {
        Argon2idParams { m_cost: 8, t_cost: 1, p_cost: 1 }
    }

    #[test]
    fn test_round_trip_basic() {
        set_backoff_override(Some(Duration::ZERO));
        let payload = b"hello world";
        let mut c = BackupContainer::export_with_params(payload, "pass", fast_params()).unwrap();
        let decrypted = c.import("pass").unwrap();
        assert_eq!(decrypted, payload);
        set_backoff_override(None);
    }

    #[test]
    fn test_round_trip_empty_payload() {
        set_backoff_override(Some(Duration::ZERO));
        let mut c = BackupContainer::export_with_params(b"", "pass", fast_params()).unwrap();
        let decrypted = c.import("pass").unwrap();
        assert_eq!(decrypted, b"");
        set_backoff_override(None);
    }

    #[test]
    fn test_round_trip_large_payload() {
        set_backoff_override(Some(Duration::ZERO));
        let payload = vec![0xAB; 4096];
        let mut c = BackupContainer::export_with_params(&payload, "pass", fast_params()).unwrap();
        let decrypted = c.import("pass").unwrap();
        assert_eq!(decrypted, payload);
        set_backoff_override(None);
    }

    #[test]
    fn test_wrong_passphrase_fails_and_increments_counter() {
        set_backoff_override(Some(Duration::ZERO));
        let mut c =
            BackupContainer::export_with_params(b"secret", "correct", fast_params()).unwrap();
        let result = c.import("wrong");
        assert!(matches!(result, Err(OcVaultError::WrongPassphrase)));
        assert_eq!(c.failed_attempts, 1);
        assert!(!c.locked);
        set_backoff_override(None);
    }

    #[test]
    fn test_correct_passphrase_resets_counter() {
        set_backoff_override(Some(Duration::ZERO));
        let mut c =
            BackupContainer::export_with_params(b"secret", "correct", fast_params()).unwrap();
        for _ in 0..3 {
            let _ = c.import("wrong");
        }
        assert_eq!(c.failed_attempts, 3);
        let decrypted = c.import("correct").unwrap();
        assert_eq!(decrypted, b"secret");
        assert_eq!(c.failed_attempts, 0);
        set_backoff_override(None);
    }

    #[test]
    fn test_10_wrong_passphrases_locks() {
        set_backoff_override(Some(Duration::ZERO));
        let mut c =
            BackupContainer::export_with_params(b"secret", "correct", fast_params()).unwrap();

        // First 9 wrong attempts: WrongPassphrase, not yet locked.
        for i in 1..MAX_FAILED_ATTEMPTS {
            let result = c.import("wrong");
            assert!(
                matches!(result, Err(OcVaultError::WrongPassphrase)),
                "attempt {} should be WrongPassphrase, got {:?}",
                i,
                result
            );
            assert!(!c.locked, "should not be locked after attempt {}", i);
            assert_eq!(c.failed_attempts, i);
        }

        // 10th wrong attempt: triggers lock. The call still returns
        // WrongPassphrase; `locked` flips to true as a side effect.
        let result = c.import("wrong");
        assert!(
            matches!(result, Err(OcVaultError::WrongPassphrase)),
            "10th attempt should still return WrongPassphrase (lock is set after)"
        );
        assert!(c.locked, "container should be locked after 10th failure");
        assert_eq!(c.failed_attempts, MAX_FAILED_ATTEMPTS);

        // 11th attempt — even with correct passphrase — is rejected with Locked.
        let result = c.import("correct");
        assert!(
            matches!(result, Err(OcVaultError::Locked)),
            "11th attempt on locked container should return Locked, got {:?}",
            result
        );
        set_backoff_override(None);
    }

    #[test]
    fn test_bad_magic_rejected() {
        set_backoff_override(Some(Duration::ZERO));
        let mut c = BackupContainer::export_with_params(b"secret", "pass", fast_params()).unwrap();
        c.magic = *b"XXXX";
        let result = c.import("pass");
        assert!(matches!(result, Err(OcVaultError::InvalidFormat(_))));
        set_backoff_override(None);
    }

    #[test]
    fn test_bad_salt_length_rejected() {
        set_backoff_override(Some(Duration::ZERO));
        let mut c = BackupContainer::export_with_params(b"secret", "pass", fast_params()).unwrap();
        c.salt.truncate(16);
        let result = c.import("pass");
        assert!(matches!(result, Err(OcVaultError::InvalidFormat(_))));
        set_backoff_override(None);
    }

    #[test]
    fn test_bad_nonce_length_rejected() {
        set_backoff_override(Some(Duration::ZERO));
        let mut c = BackupContainer::export_with_params(b"secret", "pass", fast_params()).unwrap();
        c.nonce.truncate(12);
        let result = c.import("pass");
        assert!(matches!(result, Err(OcVaultError::InvalidFormat(_))));
        set_backoff_override(None);
    }

    #[test]
    fn test_argon2_default_params_match_ad05() {
        let p = Argon2idParams::default();
        assert_eq!(p.m_cost, 64 * 1024);
        assert_eq!(p.t_cost, 3);
        assert_eq!(p.p_cost, 4);
    }

    #[test]
    fn test_container_serde_round_trip() {
        set_backoff_override(Some(Duration::ZERO));
        let payload = b"serde test payload";
        let c = BackupContainer::export_with_params(payload, "pass", fast_params()).unwrap();
        let json = serde_json::to_string(&c).unwrap();
        let mut c2: BackupContainer = serde_json::from_str(&json).unwrap();
        assert_eq!(c2.magic, MAGIC);
        assert_eq!(c2.version, VERSION);
        assert_eq!(c2.salt, c.salt);
        assert_eq!(c2.nonce, c.nonce);
        assert_eq!(c2.ciphertext, c.ciphertext);
        assert_eq!(c2.failed_attempts, 0);
        assert!(!c2.locked);
        let decrypted = c2.import("pass").unwrap();
        assert_eq!(decrypted, payload);
        set_backoff_override(None);
    }

    #[test]
    fn test_container_carries_lock_state_through_serde() {
        set_backoff_override(Some(Duration::ZERO));
        let mut c = BackupContainer::export_with_params(b"x", "p", fast_params()).unwrap();
        for _ in 0..MAX_FAILED_ATTEMPTS {
            let _ = c.import("wrong");
        }
        assert!(c.locked);
        assert_eq!(c.failed_attempts, MAX_FAILED_ATTEMPTS);

        // Persist & reload — locked state survives.
        let json = serde_json::to_string(&c).unwrap();
        let c2: BackupContainer = serde_json::from_str(&json).unwrap();
        assert!(c2.locked);
        assert_eq!(c2.failed_attempts, MAX_FAILED_ATTEMPTS);

        // Reloaded container still rejects the correct passphrase.
        let mut c2 = c2;
        let result = c2.import("p");
        assert!(matches!(result, Err(OcVaultError::Locked)));
        set_backoff_override(None);
    }

    #[test]
    fn test_different_passphrases_produce_different_ciphertext() {
        set_backoff_override(Some(Duration::ZERO));
        let c1 = BackupContainer::export_with_params(b"x", "pass1", fast_params()).unwrap();
        let c2 = BackupContainer::export_with_params(b"x", "pass2", fast_params()).unwrap();
        assert_ne!(c1.salt, c2.salt, "salts should differ");
        assert_ne!(c1.nonce, c2.nonce, "nonces should differ");
        assert_ne!(c1.ciphertext, c2.ciphertext, "ciphertexts should differ");
        set_backoff_override(None);
    }

    #[test]
    fn test_backoff_duration_production_default() {
        // Without override: 1s, 2s, 4s, ... = 2^(attempts-1) seconds.
        set_backoff_override(None);
        assert_eq!(backoff_duration(1), Duration::from_secs(1));
        assert_eq!(backoff_duration(2), Duration::from_secs(2));
        assert_eq!(backoff_duration(3), Duration::from_secs(4));
        assert_eq!(backoff_duration(4), Duration::from_secs(8));
        assert_eq!(backoff_duration(10), Duration::from_secs(512));
    }

    #[test]
    fn test_backoff_duration_override() {
        set_backoff_override(Some(Duration::from_millis(5)));
        assert_eq!(backoff_duration(1), Duration::from_millis(5));
        assert_eq!(backoff_duration(99), Duration::from_millis(5));
        set_backoff_override(None);
    }
}

#[cfg(test)]
mod proptests {
    use proptest::prelude::*;

    use super::*;

    proptest! {
        #[test]
        fn backup_round_trip(payload in prop::collection::vec(any::<u8>(), 0..256)) {
            set_backoff_override(Some(Duration::ZERO));
            let pw = "test-passphrase";
            let mut container = BackupContainer::export_with_params(
                &payload,
                pw,
                Argon2idParams { m_cost: 8, t_cost: 1, p_cost: 1 },
            ).unwrap();
            let decrypted = container.import(pw).unwrap();
            prop_assert_eq!(decrypted, payload);
            set_backoff_override(None);
        }
    }

    proptest! {
        #[test]
        fn backup_round_trip_random_passphrase(
            payload in prop::collection::vec(any::<u8>(), 0..128),
            passphrase in ".{1,40}",
        ) {
            set_backoff_override(Some(Duration::ZERO));
            let mut container = BackupContainer::export_with_params(
                &payload,
                &passphrase,
                Argon2idParams { m_cost: 8, t_cost: 1, p_cost: 1 },
            ).unwrap();
            let decrypted = container.import(&passphrase).unwrap();
            prop_assert_eq!(decrypted, payload);
            set_backoff_override(None);
        }
    }
}
