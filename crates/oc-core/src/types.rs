use std::time::{Duration, Instant};

use oc_crypto::HardenedBytes;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::OcError;

/// Unique wallet identifier (UUID v4).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct WalletId(pub String);

impl Default for WalletId {
    fn default() -> Self {
        Self(uuid::Uuid::new_v4().to_string())
    }
}

impl WalletId {
    pub fn new() -> Self {
        Self::default()
    }
}

// ---------------------------------------------------------------------------
// Passphrase
// ---------------------------------------------------------------------------

/// A passphrase for vault decryption, backed by [`HardenedBytes`].
///
/// The raw passphrase bytes are page-locked (`mlock`), marked `MADV_DONTDUMP`
/// (Linux), and zeroized on drop. The passphrase is never held in a plain
/// `String` or `Vec<u8>` outside of the brief moment during construction.
///
/// Per the OneCipher memory-hardening rules (R51/R52), all sensitive key
/// material MUST flow through `HardenedBytes` — this type enforces that
/// invariant at the `oc-core` API boundary.
pub struct Passphrase(HardenedBytes);

impl Passphrase {
    /// Create a passphrase from owned raw bytes (e.g. Passkey-derived key
    /// material).
    ///
    /// The bytes are moved into a page-locked, `DONT_DUMP`-marked buffer
    /// without an intermediate copy (see `HardenedBytes::from_vec`).
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, OcError> {
        let hardened = HardenedBytes::from_vec(bytes).map_err(|e| OcError::InvalidInput {
            message: format!("failed to harden passphrase: {e}"),
        })?;
        Ok(Self(hardened))
    }

    /// Create a passphrase from a prompt string (CLI interactive mode).
    ///
    /// The string's bytes are copied into a hardened buffer. The original
    /// `&str` is not zeroized — callers should ensure the source is wiped
    /// if it lives in sensitive memory.
    pub fn from_prompt(s: &str) -> Result<Self, OcError> {
        Self::from_bytes(s.as_bytes().to_vec())
    }

    /// Access the raw passphrase bytes.
    ///
    /// The returned slice borrows from `self`; the bytes remain page-locked
    /// for the lifetime of the borrow.
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_ref()
    }
}

/// `Drop` is a no-op — `HardenedBytes` already zeroizes and unlocks on drop.
/// The explicit impl documents the intent that `Passphrase` must never leave
/// sensitive material in memory after it goes out of scope.
impl Drop for Passphrase {
    fn drop(&mut self) {
        // HardenedBytes handles zeroize-on-drop; nothing extra needed here.
    }
}

impl std::fmt::Debug for Passphrase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Passphrase(***)")
    }
}

// ---------------------------------------------------------------------------
// UnlockToken
// ---------------------------------------------------------------------------

/// A short-lived unlock token issued after successful Passkey verification.
///
/// The token carries key material derived from the Passkey output and has a
/// 30-second TTL ([`UnlockToken::DEFAULT_TTL`]). It is used to derive a
/// [`Passphrase`] for vault decryption via [`UnlockToken::to_passphrase`].
///
/// The token is bound to a specific wallet ID and must not be reused after
/// expiry ([`UnlockToken::is_valid`]).
pub struct UnlockToken {
    /// Derived key material (32 bytes, page-locked, zeroized on drop).
    key: HardenedBytes,
    /// When the token was issued.
    issued_at: Instant,
    /// Token TTL (default 30 seconds).
    ttl: Duration,
    /// Wallet ID this token is bound to.
    wallet_id: String,
}

impl Clone for UnlockToken {
    fn clone(&self) -> Self {
        Self {
            key: HardenedBytes::from_slice(self.key.as_ref()).expect("clone unlock token key"),
            issued_at: self.issued_at,
            ttl: self.ttl,
            wallet_id: self.wallet_id.clone(),
        }
    }
}

impl UnlockToken {
    /// TTL for unlock tokens (30 seconds).
    pub const DEFAULT_TTL: Duration = Duration::from_secs(30);

    /// Create a new unlock token from Passkey-derived key material.
    ///
    /// Derives a 32-byte key by hashing the key material together with a
    /// domain-separation tag and the wallet ID (SHA-256). This is a
    /// simplified HKDF-like construction; a full HKDF would require an
    /// additional `hkdf` crate dependency.
    pub fn new(wallet_id: String, key_material: &[u8]) -> Result<Self, OcError> {
        let mut hasher = Sha256::new();
        hasher.update(b"onecipher-unlock-token");
        hasher.update(key_material);
        hasher.update(wallet_id.as_bytes());
        let hash: [u8; 32] = hasher.finalize().into();
        let key = HardenedBytes::from_slice(&hash).map_err(|e| OcError::InvalidInput {
            message: format!("failed to harden unlock token: {e}"),
        })?;
        Ok(Self { key, issued_at: Instant::now(), ttl: Self::DEFAULT_TTL, wallet_id })
    }

    /// Check if the token is still valid (not expired).
    pub fn is_valid(&self) -> bool {
        self.issued_at.elapsed() < self.ttl
    }

    /// Get the wallet ID this token is bound to.
    pub fn wallet_id(&self) -> &str {
        &self.wallet_id
    }

    /// Derive a [`Passphrase`] from this token's key material.
    ///
    /// The passphrase bytes are copied into a new hardened buffer; the token
    /// retains its own key material.
    pub fn to_passphrase(&self) -> Result<Passphrase, OcError> {
        Passphrase::from_bytes(self.key.as_ref().to_vec())
    }

    /// Access the raw 32-byte key material.
    ///
    /// Used when transporting the token over IPC (e.g. returning it in an
    /// `UnlockVaultResponse`). The caller is responsible for not logging or
    /// persisting these bytes.
    pub fn key_bytes(&self) -> &[u8] {
        self.key.as_ref()
    }
}

impl std::fmt::Debug for UnlockToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UnlockToken")
            .field("wallet_id", &self.wallet_id)
            .field("issued_at", &self.issued_at)
            .field("ttl", &self.ttl)
            .field("key", &"[redacted]")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wallet_id_generates_uuid() {
        let id = WalletId::new();
        assert!(!id.0.is_empty());
        assert!(uuid::Uuid::parse_str(&id.0).is_ok());
    }

    #[test]
    fn test_wallet_id_serde() {
        let id = WalletId("test-id".to_string());
        let json = serde_json::to_string(&id).unwrap();
        assert_eq!(json, "\"test-id\"");
        let id2: WalletId = serde_json::from_str(&json).unwrap();
        assert_eq!(id, id2);
    }

    // --- Passphrase tests ---

    #[test]
    fn test_passphrase_from_prompt_preserves_bytes() {
        let pp = Passphrase::from_prompt("hunter2").expect("passphrase creation should succeed");
        assert_eq!(pp.as_bytes(), b"hunter2");
    }

    #[test]
    fn test_passphrase_from_bytes_preserves_data() {
        let data = vec![0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0xFF];
        let pp = Passphrase::from_bytes(data.clone()).expect("passphrase creation should succeed");
        assert_eq!(pp.as_bytes(), &data[..]);
    }

    #[test]
    fn test_passphrase_empty_bytes_is_ok() {
        let pp = Passphrase::from_bytes(Vec::new()).expect("empty passphrase should succeed");
        assert!(pp.as_bytes().is_empty());
    }

    #[test]
    fn test_passphrase_debug_does_not_leak() {
        let pp = Passphrase::from_prompt("secret-passphrase").unwrap();
        let s = format!("{pp:?}");
        assert_eq!(s, "Passphrase(***)");
        assert!(!s.contains("secret-passphrase"));
    }

    #[test]
    fn test_passphrase_drop_runs_without_panic() {
        {
            let _pp = Passphrase::from_prompt("ephemeral").unwrap();
        } // drop runs here; if we reach the next line, drop did not panic.
    }

    // --- UnlockToken tests ---

    #[test]
    fn test_unlock_token_is_valid_immediately() {
        let token = UnlockToken::new("wallet-1".to_string(), &[0x01; 32]).unwrap();
        assert!(token.is_valid(), "freshly minted token should be valid");
    }

    #[test]
    fn test_unlock_token_wallet_id() {
        let token = UnlockToken::new("wallet-abc".to_string(), &[0x02; 16]).unwrap();
        assert_eq!(token.wallet_id(), "wallet-abc");
    }

    #[test]
    fn test_unlock_token_to_passphrase_is_32_bytes() {
        let token = UnlockToken::new("wallet-2".to_string(), &[0x03; 64]).unwrap();
        let pp = token.to_passphrase().expect("passphrase derivation should succeed");
        assert_eq!(pp.as_bytes().len(), 32, "derived passphrase must be 32 bytes");
    }

    #[test]
    fn test_unlock_token_derivation_is_deterministic() {
        let wallet = "wallet-det".to_string();
        let km = [0x42u8; 32];
        let t1 = UnlockToken::new(wallet.clone(), &km).unwrap();
        let t2 = UnlockToken::new(wallet, &km).unwrap();
        let p1 = t1.to_passphrase().unwrap();
        let p2 = t2.to_passphrase().unwrap();
        assert_eq!(p1.as_bytes(), p2.as_bytes(), "same inputs must yield same passphrase");
    }

    #[test]
    fn test_unlock_token_different_wallets_yield_different_keys() {
        let km = [0x99u8; 32];
        let t1 = UnlockToken::new("wallet-A".to_string(), &km).unwrap();
        let t2 = UnlockToken::new("wallet-B".to_string(), &km).unwrap();
        let p1 = t1.to_passphrase().unwrap();
        let p2 = t2.to_passphrase().unwrap();
        assert_ne!(p1.as_bytes(), p2.as_bytes(), "different wallet IDs must yield different keys");
    }

    #[test]
    fn test_unlock_token_different_key_material_yields_different_keys() {
        let wallet = "wallet-same".to_string();
        let t1 = UnlockToken::new(wallet.clone(), &[0xAA; 32]).unwrap();
        let t2 = UnlockToken::new(wallet, &[0xBB; 32]).unwrap();
        let p1 = t1.to_passphrase().unwrap();
        let p2 = t2.to_passphrase().unwrap();
        assert_ne!(
            p1.as_bytes(),
            p2.as_bytes(),
            "different key material must yield different keys"
        );
    }

    #[test]
    fn test_unlock_token_default_ttl_is_30_seconds() {
        assert_eq!(UnlockToken::DEFAULT_TTL, Duration::from_secs(30));
    }

    #[test]
    fn test_unlock_token_debug_redacts_key() {
        let token = UnlockToken::new("wallet-debug".to_string(), &[0x77; 32]).unwrap();
        let s = format!("{token:?}");
        assert!(s.contains("wallet-debug"), "debug should show wallet_id");
        assert!(s.contains("[redacted]"), "debug should redact key");
    }

    #[test]
    fn test_unlock_token_clone_preserves_key() {
        let token = UnlockToken::new("wallet-clone".to_string(), &[0x55; 32]).unwrap();
        let cloned = token.clone();
        assert_eq!(token.key_bytes(), cloned.key_bytes(), "clone must preserve key material");
        assert_eq!(token.wallet_id(), cloned.wallet_id());
    }
}
