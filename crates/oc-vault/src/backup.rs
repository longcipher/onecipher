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
//! - `failed_attempts` and `locked` are mirrored in the container header for informational
//!   purposes, but the *authoritative* failed-attempt state lives in a sidecar file
//!   (`<state_dir>/backup_attempts.json`, mode 0600) keyed by a prefix of the container salt. This
//!   makes the lockout effective even when callers re-read a fresh copy of the container from disk
//!   on every attempt (H-03): the counter survives process restarts and fresh loads. After
//!   [`MAX_FAILED_ATTEMPTS`] failures, imports are refused until [`LOCKOUT_COOLDOWN_SECS`] seconds
//!   have elapsed since the last failure ([`OcVaultError::LockedOut`]); a successful import clears
//!   the recorded attempts.
//!
//! Wrong-passphrase backoff: production default is exponential
//! (1 s, 2 s, 4 s, ... = `2^(attempts-1)` seconds). For tests, call
//! [`set_backoff_override`] with `Some(Duration::ZERO)`; the override is
//! thread-local so it does not bleed between parallel test threads.

use std::{
    cell::RefCell,
    collections::HashMap,
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit},
};
use rand::RngExt;
use serde::{Deserialize, Serialize};
use tracing::warn;

use crate::error::OcVaultError;

/// Magic bytes identifying a OneCipher backup container (`"OCBK"`).
pub const MAGIC: [u8; 4] = *b"OCBK";

/// Current on-disk format version.
pub const VERSION: u8 = 1;

/// Failed-passphrase attempts after which the container becomes permanently
/// locked (per R42 behavioral contract: 10).
pub const MAX_FAILED_ATTEMPTS: u32 = 10;

/// Cooldown (in seconds) enforced once the persistent failed-attempt counter
/// reaches [`MAX_FAILED_ATTEMPTS`], counted from the most recent failure.
/// Further imports are rejected with [`OcVaultError::LockedOut`] until it
/// elapses; after expiry a fresh attempt window starts.
pub const LOCKOUT_COOLDOWN_SECS: u64 = 15 * 60;

/// Name of the sidecar file (inside the OneCipher state directory) that
/// persists failed-attempt counters across processes and fresh container
/// loads.
const ATTEMPTS_FILE_NAME: &str = "backup_attempts.json";

/// Number of leading salt bytes used to identify a container in the
/// attempts sidecar map.
const ATTEMPTS_KEY_BYTES: usize = 16;

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

thread_local! {
    static ATTEMPTS_STATE_OVERRIDE: RefCell<Option<PathBuf>> = const { RefCell::new(None) };
}

/// Override the location of the failed-attempts sidecar file for the calling
/// thread.
///
/// **Test-only utility.** See [`set_backoff_override`] for the gating rules.
/// Pass `Some(path)` to redirect the sidecar (unit tests point it at a
/// per-test tempdir so the real `~/.onecipher` state is never touched); pass
/// `None` to restore production behavior.
#[cfg(any(test, feature = "test-utils"))]
pub fn set_attempts_state_override(p: Option<PathBuf>) {
    ATTEMPTS_STATE_OVERRIDE.with(|cell| *cell.borrow_mut() = p);
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
    /// - On success: resets `failed_attempts` to 0, clears the persistent failed-attempt record for
    ///   this container, and returns the plaintext.
    /// - On wrong passphrase: increments `failed_attempts` (both in-memory and in the persistent
    ///   sidecar file), applies backoff (see module docs), and returns
    ///   [`OcVaultError::WrongPassphrase`]. After [`MAX_FAILED_ATTEMPTS`] failures, sets `locked =
    ///   true` and subsequent calls return [`OcVaultError::Locked`] without trying the passphrase.
    /// - On a locked container: returns [`OcVaultError::Locked`] immediately.
    /// - Once the persistent counter reaches [`MAX_FAILED_ATTEMPTS`], further attempts are refused
    ///   with [`OcVaultError::LockedOut`] until [`LOCKOUT_COOLDOWN_SECS`] have elapsed since the
    ///   last failure — even for freshly loaded copies of the container (H-03).
    ///
    /// The persistent state lives in `<state_dir>/backup_attempts.json`
    /// (mode 0600, atomic writes). Resolving that path requires a usable home
    /// directory; import fails closed when it cannot be resolved.
    ///
    /// # Errors
    ///
    /// See [`Self::import_with_state`] for the full error surface.
    pub fn import(&mut self, passphrase: &str) -> Result<Vec<u8>, OcVaultError> {
        // Structural validation runs before state-dir resolution so that an
        // invalid container reports its format error even without `HOME`.
        self.validate_header()?;
        let state_file = attempts_state_file()?;
        self.import_with_state(passphrase, &state_file, system_time_unix())
    }

    /// Validate the container header (magic, version, salt and nonce lengths)
    /// without touching KDF, AEAD or any persisted state.
    ///
    /// # Errors
    ///
    /// Returns [`OcVaultError::InvalidFormat`] for a bad magic, salt or nonce
    /// length, and [`OcVaultError::UnsupportedVersion`] for any format version
    /// other than [`VERSION`] (H-03a: a future v2 container must never be
    /// parsed as v1).
    fn validate_header(&self) -> Result<(), OcVaultError> {
        if self.magic != MAGIC {
            return Err(OcVaultError::InvalidFormat(format!(
                "bad magic: expected {:?}, got {:?}",
                MAGIC, self.magic
            )));
        }
        if self.version != VERSION {
            return Err(OcVaultError::UnsupportedVersion { found: self.version, expected: VERSION });
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
        Ok(())
    }

    /// [`Self::import`] with explicit sidecar path and clock — the
    /// testability seam for the persistent lockout (H-03b). Production
    /// callers use [`Self::import`], which supplies the default state file
    /// and the system clock.
    ///
    /// `now_unix` is the current UNIX time in seconds; tests pass fixed
    /// values to exercise cooldown expiry deterministically.
    pub(crate) fn import_with_state(
        &mut self,
        passphrase: &str,
        state_file: &Path,
        now_unix: u64,
    ) -> Result<Vec<u8>, OcVaultError> {
        if self.locked {
            return Err(OcVaultError::Locked);
        }
        self.validate_header()?;

        let key_id = attempts_key(&self.salt);
        let mut attempts = load_attempt_map(state_file);

        // Enforce the persistent lockout before any KDF work: once
        // MAX_FAILED_ATTEMPTS have been recorded for this container, refuse
        // every attempt until the cooldown since the last failure elapses.
        if attempts.get(&key_id).is_some_and(|rec| rec.count >= MAX_FAILED_ATTEMPTS) {
            let elapsed = now_unix
                .saturating_sub(attempts.get(&key_id).map_or(0, |rec| rec.last_failed_unix));
            if elapsed < LOCKOUT_COOLDOWN_SECS {
                return Err(OcVaultError::LockedOut {
                    retry_after_secs: LOCKOUT_COOLDOWN_SECS - elapsed,
                });
            }
            // Cooldown elapsed: start a fresh attempt window.
            attempts.remove(&key_id);
            persist_attempt_map(state_file, &attempts)?;
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
            if attempts.remove(&key_id).is_some() {
                persist_attempt_map(state_file, &attempts)?;
            }
            Ok(plaintext)
        } else {
            self.failed_attempts = self.failed_attempts.saturating_add(1);
            // Flip the in-memory lock before persisting so the per-process
            // guard holds even when the sidecar write fails.
            let now_locked = self.failed_attempts >= MAX_FAILED_ATTEMPTS;
            if now_locked {
                self.locked = true;
            }
            let count = attempts.get(&key_id).map_or(0, |rec| rec.count).saturating_add(1);
            warn!(count, "backup passphrase rejected; persistent attempt counter incremented");
            attempts.insert(key_id, AttemptRecord { count, last_failed_unix: now_unix });
            // Persist before sleeping so the failure survives a crash
            // mid-backoff.
            persist_attempt_map(state_file, &attempts)?;
            if !now_locked {
                std::thread::sleep(backoff_duration(self.failed_attempts));
            }
            Err(OcVaultError::WrongPassphrase)
        }
    }
}

/// Persistent failed-attempt record for one backup container.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct AttemptRecord {
    /// Cumulative failed-passphrase count across processes and reloads.
    count: u32,
    /// UNIX time (seconds) of the most recent failure.
    last_failed_unix: u64,
}

/// Sidecar map: container key → attempt record.
type AttemptMap = HashMap<String, AttemptRecord>;

/// Current UNIX time in seconds (0 if the clock is before the epoch).
fn system_time_unix() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

/// Resolve the failed-attempts sidecar path: the thread-local test override
/// when installed, otherwise `<state_dir>/backup_attempts.json`.
///
/// # Errors
///
/// Fails closed when no home directory can be determined and no override is
/// installed — silently skipping persistence would defeat the brute-force
/// protection.
fn attempts_state_file() -> Result<PathBuf, OcVaultError> {
    if let Some(p) = ATTEMPTS_STATE_OVERRIDE.with(|cell| cell.borrow().clone()) {
        return Ok(p);
    }
    oc_core::paths::state_path(ATTEMPTS_FILE_NAME).map_err(|e| {
        OcVaultError::InvalidInput(format!("cannot resolve backup attempts state path: {e}"))
    })
}

/// Hex-encode `bytes` (lowercase).
fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[usize::from(b >> 4)] as char);
        out.push(HEX[usize::from(b & 0x0f)] as char);
    }
    out
}

/// Stable identifier for a container within the sidecar map: the leading
/// bytes of its random salt. Salts are unique per export, so this pins the
/// counter to the exact container contents — stronger than a filesystem-path
/// key, because copying the `.ocbk` file elsewhere cannot reset the counter.
fn attempts_key(salt: &[u8]) -> String {
    let n = salt.len().min(ATTEMPTS_KEY_BYTES);
    hex_encode(&salt[..n])
}

/// Load the sidecar map. A missing, unreadable or corrupt file is treated as
/// empty (logged): the sidecar is defense-in-depth, and bricking legitimate
/// recovery because an auxiliary file is damaged would be worse than losing
/// the counter.
fn load_attempt_map(path: &Path) -> AttemptMap {
    let Ok(raw) = std::fs::read_to_string(path) else {
        return AttemptMap::new();
    };
    match serde_json::from_str(&raw) {
        Ok(map) => map,
        Err(e) => {
            warn!(path = %path.display(), error = %e, "corrupt backup attempts sidecar; ignoring");
            AttemptMap::new()
        }
    }
}

/// Durably persist the sidecar map (mode 0600, atomic replace). An empty map
/// removes the file entirely.
///
/// # Errors
///
/// Propagates I/O failures: silently dropping failed-attempt increments
/// would defeat the brute-force protection.
fn persist_attempt_map(path: &Path, map: &AttemptMap) -> Result<(), OcVaultError> {
    if map.is_empty() {
        if let Err(e) = std::fs::remove_file(path) {
            if e.kind() != std::io::ErrorKind::NotFound {
                return Err(e.into());
            }
        }
        return Ok(());
    }
    let json = serde_json::to_vec(map)?;
    oc_core::paths::write_atomic_private(path, &json).map_err(OcVaultError::Io)?;
    Ok(())
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
        let tmp = tempfile::tempdir().unwrap();
        set_attempts_state_override(Some(tmp.path().join(ATTEMPTS_FILE_NAME)));
        set_backoff_override(Some(Duration::ZERO));
        let mut c =
            BackupContainer::export_with_params(b"secret", "correct", fast_params()).unwrap();
        let result = c.import("wrong");
        assert!(matches!(result, Err(OcVaultError::WrongPassphrase)));
        assert_eq!(c.failed_attempts, 1);
        assert!(!c.locked);
        set_attempts_state_override(None);
        set_backoff_override(None);
    }

    #[test]
    fn test_correct_passphrase_resets_counter() {
        let tmp = tempfile::tempdir().unwrap();
        set_attempts_state_override(Some(tmp.path().join(ATTEMPTS_FILE_NAME)));
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
        set_attempts_state_override(None);
        set_backoff_override(None);
    }

    #[test]
    fn test_10_wrong_passphrases_locks() {
        let tmp = tempfile::tempdir().unwrap();
        set_attempts_state_override(Some(tmp.path().join(ATTEMPTS_FILE_NAME)));
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
        set_attempts_state_override(None);
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
    fn test_wrong_version_rejected_before_kdf() {
        let tmp = tempfile::tempdir().unwrap();
        let state = tmp.path().join("backup_attempts.json");
        let mut c = BackupContainer::export_with_params(b"secret", "pass", fast_params()).unwrap();
        c.version = VERSION + 1;
        // Make the KDF parameters impossible so that, were the version check
        // skipped, decryption would fail with a Crypto error instead of ever
        // succeeding — proving the version gate runs first.
        c.kdf_params.m_cost = u32::MAX;
        let result = c.import_with_state("pass", &state, 1_000);
        match result {
            Err(OcVaultError::UnsupportedVersion { found, expected }) => {
                assert_eq!(found, VERSION + 1);
                assert_eq!(expected, VERSION);
            }
            other => panic!("expected UnsupportedVersion, got {other:?}"),
        }
    }

    /// Drive a fresh container copy through `MAX_FAILED_ATTEMPTS` wrong
    /// passphrases against one sidecar file, returning the sidecar path and
    /// the serialized container for reloading fresh copies.
    fn locked_out_fixture(dir: &Path) -> (std::path::PathBuf, String, Vec<u8>) {
        // Disable the exponential backoff sleep so the 10 wrong attempts do
        // not take ~511 s of wall time.
        set_backoff_override(Some(Duration::ZERO));
        let state = dir.join("backup_attempts.json");
        let payload = b"secret".to_vec();
        let c = BackupContainer::export_with_params(&payload, "right", fast_params()).unwrap();
        let json = serde_json::to_string(&c).unwrap();
        let mut working: BackupContainer = serde_json::from_str(&json).unwrap();

        for i in 1..MAX_FAILED_ATTEMPTS {
            let result = working.import_with_state("wrong", &state, 1_000);
            assert!(
                matches!(result, Err(OcVaultError::WrongPassphrase)),
                "attempt {i} should be WrongPassphrase, got {result:?}"
            );
        }
        // 10th failure completes the persistent lockout window.
        let result = working.import_with_state("wrong", &state, 1_000);
        assert!(matches!(result, Err(OcVaultError::WrongPassphrase)));
        (state, json, payload)
    }

    #[test]
    fn test_persistent_lockout_blocks_fresh_container_copy() {
        let tmp = tempfile::tempdir().unwrap();
        let (state, json, _) = locked_out_fixture(tmp.path());

        // A brand-new copy of the container (as an offline attacker would
        // re-load it every attempt) is refused while cooling down — this is
        // the H-03 scenario the header-only counter could not stop.
        let mut fresh: BackupContainer = serde_json::from_str(&json).unwrap();
        match fresh.import_with_state("right", &state, 1_000) {
            Err(OcVaultError::LockedOut { retry_after_secs }) => {
                assert_eq!(retry_after_secs, LOCKOUT_COOLDOWN_SECS);
            }
            other => panic!("expected LockedOut, got {other:?}"),
        }
        // Retry-after shrinks as time passes.
        match fresh.import_with_state("right", &state, 1_000 + 60) {
            Err(OcVaultError::LockedOut { retry_after_secs }) => {
                assert_eq!(retry_after_secs, LOCKOUT_COOLDOWN_SECS - 60);
            }
            other => panic!("expected LockedOut after partial cooldown, got {other:?}"),
        }
    }

    #[test]
    fn test_cooldown_expiry_allows_retry() {
        let tmp = tempfile::tempdir().unwrap();
        let (state, json, payload) = locked_out_fixture(tmp.path());

        let mut fresh: BackupContainer = serde_json::from_str(&json).unwrap();
        let decrypted =
            fresh.import_with_state("right", &state, 1_000 + LOCKOUT_COOLDOWN_SECS).unwrap();
        assert_eq!(decrypted, payload);

        // The expired window was cleared, so another fresh copy imports
        // cleanly immediately afterwards and the sidecar is gone.
        let mut fresh2: BackupContainer = serde_json::from_str(&json).unwrap();
        let result = fresh2.import_with_state("right", &state, 1_000 + LOCKOUT_COOLDOWN_SECS + 1);
        assert!(result.is_ok());
        assert!(!state.exists(), "sidecar must be removed once attempts clear");
    }

    #[test]
    fn test_success_resets_persistent_counter() {
        let tmp = tempfile::tempdir().unwrap();
        let state = tmp.path().join("backup_attempts.json");
        let payload = b"secret";
        let c = BackupContainer::export_with_params(payload, "right", fast_params()).unwrap();
        let json = serde_json::to_string(&c).unwrap();
        let mut working: BackupContainer = serde_json::from_str(&json).unwrap();

        for _ in 0..3 {
            let _ = working.import_with_state("wrong", &state, 1_000);
        }
        assert!(state.exists(), "failures must be persisted");

        let mut recover: BackupContainer = serde_json::from_str(&json).unwrap();
        let decrypted = recover.import_with_state("right", &state, 1_001).unwrap();
        assert_eq!(decrypted, payload);
        assert!(!state.exists(), "success must clear the persistent counter");

        // No residual history: a fresh copy starts from a clean slate.
        let mut fresh: BackupContainer = serde_json::from_str(&json).unwrap();
        let decrypted = fresh.import_with_state("right", &state, 1_002).unwrap();
        assert_eq!(decrypted, payload);
    }

    #[test]
    fn test_sidecar_file_has_private_permissions() {
        let tmp = tempfile::tempdir().unwrap();
        let state = tmp.path().join("backup_attempts.json");
        let mut c = BackupContainer::export_with_params(b"x", "p", fast_params()).unwrap();
        let _ = c.import_with_state("wrong", &state, 1_000);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&state).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "sidecar holds brute-force state; must be 0600");
        }
    }

    #[test]
    fn test_corrupt_sidecar_treated_as_empty() {
        let tmp = tempfile::tempdir().unwrap();
        let state = tmp.path().join("backup_attempts.json");
        std::fs::write(&state, b"not json{").unwrap();
        let mut c = BackupContainer::export_with_params(b"x", "p", fast_params()).unwrap();
        let decrypted = c.import_with_state("p", &state, 1_000).unwrap();
        assert_eq!(decrypted, b"x");
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
        let tmp = tempfile::tempdir().unwrap();
        set_attempts_state_override(Some(tmp.path().join(ATTEMPTS_FILE_NAME)));
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
        set_attempts_state_override(None);
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
