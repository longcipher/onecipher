//! Unified secret types for the OneCipher vault.
//!
//! `ItemType` is the top-level discriminator for vault entries. `KeyType`
//! (Mnemonic/PrivateKey) is a subset — wallets are just one kind of secret.

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// Top-level entry type discriminator.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum ItemType {
    /// BIP-39 mnemonic seed phrase (12/24 words).
    Mnemonic,
    /// Single-chain private key (not derived from a mnemonic).
    PrivateKey,
    /// Password + metadata (URL, username, notes).
    Password,
    /// TOTP seed (otpauth URI or raw base32).
    Totp,
    /// Free-text encrypted note.
    Note,
    /// Binary file (certificate, SSH key, etc.).
    File,
}

impl ItemType {
    /// Returns all variants for iteration.
    pub fn all() -> &'static [Self] {
        &[Self::Mnemonic, Self::PrivateKey, Self::Password, Self::Totp, Self::Note, Self::File]
    }

    /// Human-readable label.
    pub fn label(&self) -> &'static str {
        match self {
            Self::Mnemonic => "Mnemonic",
            Self::PrivateKey => "Private Key",
            Self::Password => "Password",
            Self::Totp => "TOTP",
            Self::Note => "Note",
            Self::File => "File",
        }
    }
}

impl std::fmt::Display for ItemType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.label())
    }
}

/// Unified four-state handling kind for secrets.
///
/// `ItemType` (six variants) remains the on-disk discriminator for backward
/// compatibility. `SecretKind` is the unified mental model for the handling
/// plane: wallet keys, passwords, OTP seeds and notes share one enum, one
/// CRUD surface (`oc_secret::crud`), one JSON envelope ([`SecretEnvelope`]),
/// one index/audit taxonomy, and one CLI render path.
///
/// Mapping: `Mnemonic`/`PrivateKey` collapse to [`SecretKind::WalletKey`],
/// `Password` to [`SecretKind::Password`], `Totp` to [`SecretKind::TotpSeed`],
/// and `Note`/`File` to [`SecretKind::Note`].
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum SecretKind {
    /// Wallet signing material (mnemonic phrase or private-key pair).
    WalletKey,
    /// Human password with optional URL/username metadata.
    Password,
    /// OTP seed (TOTP/HOTP `otpauth://` URI or raw base32).
    TotpSeed,
    /// Free-text note or opaque file blob.
    Note,
}

impl SecretKind {
    /// Returns all variants for iteration.
    pub fn all() -> &'static [Self] {
        &[Self::WalletKey, Self::Password, Self::TotpSeed, Self::Note]
    }

    /// Human-readable label.
    pub fn label(&self) -> &'static str {
        match self {
            Self::WalletKey => "Wallet Key",
            Self::Password => "Password",
            Self::TotpSeed => "TOTP Seed",
            Self::Note => "Note",
        }
    }

    /// Collapse an on-disk [`ItemType`] into its handling kind.
    pub const fn from_item_type(item_type: ItemType) -> Self {
        match item_type {
            ItemType::Mnemonic | ItemType::PrivateKey => Self::WalletKey,
            ItemType::Password => Self::Password,
            ItemType::Totp => Self::TotpSeed,
            ItemType::Note | ItemType::File => Self::Note,
        }
    }

    /// Default on-disk [`ItemType`] for this handling kind.
    ///
    /// The mapping is lossy by design (`WalletKey` defaults to `Mnemonic`,
    /// `Note` defaults to `Note`); callers that need the exact stored
    /// discriminator must read it from the index entry instead.
    pub const fn to_item_type(self) -> ItemType {
        match self {
            Self::WalletKey => ItemType::Mnemonic,
            Self::Password => ItemType::Password,
            Self::TotpSeed => ItemType::Totp,
            Self::Note => ItemType::Note,
        }
    }

    /// Parse a kind name (snake_case or display label, case-insensitive).
    pub fn parse(s: &str) -> Option<Self> {
        let lower = s.trim().to_ascii_lowercase();
        match lower.as_str() {
            "wallet_key" | "walletkey" | "wallet key" | "wallet" => Some(Self::WalletKey),
            "password" => Some(Self::Password),
            "totp_seed" | "totpseed" | "totp seed" | "totp" | "otp" => Some(Self::TotpSeed),
            "note" => Some(Self::Note),
            _ => None,
        }
    }
}

impl std::fmt::Display for SecretKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.label())
    }
}

/// Which append-only audit track an operation rides.
///
/// Two-track model: read-only/lifecycle operations ride the light channel
/// (`audit.jsonl`); signing/broadcast operations ride the strong channel
/// (`audit-strong.jsonl`) so a read-heavy workload cannot drown signing
/// evidence. Library code reports the track; the CLI maps it to files.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AuditTrack {
    /// Read-only and lifecycle operations.
    Light,
    /// Signing and broadcast operations.
    Strong,
}

/// Unified audit operation table for the wallet/password/OTP handling plane.
///
/// Every `secret.*`, `password.*`, `totp.*` and `wallet.*` CLI command logs
/// exactly one of these dotted names, so `audit list` consumers can filter
/// on a single taxonomy instead of per-command ad-hoc strings.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AuditOp {
    /// `secret add` — generic entry creation.
    SecretCreate,
    /// `secret get` / `secret list` — entry read.
    SecretRead,
    /// `secret update` / `secret edit` — entry modification.
    SecretUpdate,
    /// `secret delete` — entry deletion (tombstone kept).
    SecretDelete,
    /// `secret rename` / `secret move` — entry rename.
    SecretRename,
    /// `secret copy` — entry duplication.
    SecretCopy,
    /// `password add` — password entry creation.
    PasswordAdd,
    /// `password get` — password read.
    PasswordRead,
    /// `password generate` — standalone generation (no vault write).
    PasswordGenerate,
    /// `totp add` — OTP seed creation.
    TotpAdd,
    /// `totp generate` — TOTP code generation.
    TotpGenerate,
    /// `totp uris` — otpauth URI disclosure.
    TotpRevealUri,
    /// `totp hotp` — HOTP code generation.
    HotpGenerate,
    /// `wallet create` — wallet creation.
    WalletCreate,
    /// `wallet import` — wallet import.
    WalletImport,
    /// `wallet export` — secret disclosure (mnemonic or key pair).
    WalletExport,
    /// `wallet delete` — wallet deletion.
    WalletDelete,
    /// `wallet rename` — wallet rename.
    WalletRename,
    /// `wallet list` / `wallet info` — wallet read.
    WalletRead,
    /// `sign message` / `sign tx` / `sign auth` — signing.
    WalletSign,
    /// `send` / `sign send-tx` — broadcast.
    WalletBroadcast,
}

impl AuditOp {
    /// Dotted operation name written to the audit log.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SecretCreate => "secret.create",
            Self::SecretRead => "secret.read",
            Self::SecretUpdate => "secret.update",
            Self::SecretDelete => "secret.delete",
            Self::SecretRename => "secret.rename",
            Self::SecretCopy => "secret.copy",
            Self::PasswordAdd => "password.add",
            Self::PasswordRead => "password.read",
            Self::PasswordGenerate => "password.generate",
            Self::TotpAdd => "totp.add",
            Self::TotpGenerate => "totp.generate",
            Self::TotpRevealUri => "totp.reveal_uri",
            Self::HotpGenerate => "totp.hotp",
            Self::WalletCreate => "wallet.create",
            Self::WalletImport => "wallet.import",
            Self::WalletExport => "wallet.export",
            Self::WalletDelete => "wallet.delete",
            Self::WalletRename => "wallet.rename",
            Self::WalletRead => "wallet.read",
            Self::WalletSign => "wallet.sign",
            Self::WalletBroadcast => "wallet.broadcast",
        }
    }

    /// Which audit track this operation rides.
    pub const fn track(self) -> AuditTrack {
        match self {
            Self::WalletSign | Self::WalletBroadcast => AuditTrack::Strong,
            _ => AuditTrack::Light,
        }
    }

    /// Returns all operations for iteration.
    pub const fn all() -> &'static [Self] {
        &[
            Self::SecretCreate,
            Self::SecretRead,
            Self::SecretUpdate,
            Self::SecretDelete,
            Self::SecretRename,
            Self::SecretCopy,
            Self::PasswordAdd,
            Self::PasswordRead,
            Self::PasswordGenerate,
            Self::TotpAdd,
            Self::TotpGenerate,
            Self::TotpRevealUri,
            Self::HotpGenerate,
            Self::WalletCreate,
            Self::WalletImport,
            Self::WalletExport,
            Self::WalletDelete,
            Self::WalletRename,
            Self::WalletRead,
            Self::WalletSign,
            Self::WalletBroadcast,
        ]
    }
}

impl std::fmt::Display for AuditOp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Unified `--json` envelope for secret reads.
///
/// Every `secret get`, `password get`, `totp uris` (and `--json` wallet
/// reads) emit this single shape so agents parse one schema: identity
/// (`name`/`id`), taxonomy (`kind` + on-disk `item_type`), plaintext index
/// metadata, the monotonic `generation`, and — only for reads that disclose
/// material — the decrypted `payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SecretEnvelope {
    /// Lookup path (e.g. `github/personal`).
    pub name: String,
    /// Entry UUID.
    pub id: String,
    /// Unified handling kind.
    pub kind: SecretKind,
    /// On-disk discriminator (exact stored variant).
    pub item_type: ItemType,
    /// Plaintext index metadata.
    pub metadata: SecretMetadata,
    /// Monotonic generation bound inside the envelope.
    pub generation: u64,
    /// Decrypted payload (present on disclosure reads, absent on listings).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload: Option<SecretPayload>,
}

impl SecretEnvelope {
    /// Build an envelope for a disclosure read (payload included).
    pub fn with_payload(
        name: String,
        id: String,
        item_type: ItemType,
        metadata: SecretMetadata,
        generation: u64,
        payload: SecretPayload,
    ) -> Self {
        Self {
            name,
            id,
            kind: SecretKind::from_item_type(item_type),
            item_type,
            metadata,
            generation,
            payload: Some(payload),
        }
    }

    /// Build an envelope for a listing row (no secret material).
    pub fn without_payload(entry: &SecretIndexEntry) -> Self {
        Self {
            name: entry.name.clone(),
            id: entry.id.clone(),
            kind: SecretKind::from_item_type(entry.item_type),
            item_type: entry.item_type,
            metadata: entry.metadata.clone(),
            generation: entry.generation,
            payload: None,
        }
    }
}

/// Metadata for a secret entry (stored in plaintext index for searchability).
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct SecretMetadata {
    /// Associated URL (for passwords).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// Username or account name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    /// Chain type for wallet keys (e.g., "ethereum", "solana").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chain: Option<String>,
    /// TOTP issuer.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    /// TOTP account name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account: Option<String>,
    /// Free-form tags for categorization.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
}

/// Decrypted payload of a secret entry.
///
/// # Memory hardening (C3 fix, unified handling plane)
///
/// Handling-plane rule: secret material lives in page-locked
/// `oc_crypto::HardenedBytes` everywhere in memory; the `String` fields here
/// exist ONLY as the `--json` serialization boundary. The plaintext
/// `secret`/`notes` are held as `String` for serde/CLI compatibility (the
/// `--json` output must remain a plain string), but a custom [`Drop`]
/// zeroizes their backing buffers on drop. This is a best-effort mitigation:
/// it does not `mlock` the pages (that would require `HardenedBytes`), but it
/// prevents the plaintext from lingering in freed heap memory after the
/// payload is dropped. Callers that need page-locking should route the secret
/// through `oc_crypto::HardenedBytes` at the point of use via
/// [`SecretPayload::secret_hardened`] / [`SecretPayload::into_secret_hardened`]
/// (requires the `hardened` feature) or `oc_secret::SecretEntry::decrypt_hardened`.
///
/// ## Forensic window (documented, accepted)
///
/// Between `serde_json::to_vec` (encryption) and `serde_json::from_slice`
/// (decryption) the plaintext necessarily transits unhardened JSON buffers,
/// and [`reveal_for_json`](Self::reveal_for_json) — the single documented
/// conversion point for `--json` output — hands out the plain `&str`.
/// Treat its return value as live key material: never log it, never hold it
/// past the `println!`, and let the owning `SecretPayload` drop (zeroizing)
/// as soon as the envelope is emitted.
///
/// ## Why `String` and not `HardenedBytes`?
///
/// - `SecretPayload` covers passwords/TOTP/notes whose CLI `--json` contract requires plain string
///   serialization; `HardenedBytes` is not `Serialize`.
/// - It never holds wallet signing keys (those flow exclusively through `HardenedBytes` /
///   `SecretBytes`).
/// - Serde round-trips (`to_vec` → age encrypt, age decrypt → `from_slice`) would otherwise copy
///   plaintext through unhardened JSON buffers anyway. The hardened path is therefore applied *at
///   use-site* immediately after `decrypt`, not inside the payload type itself.
/// - Any future signing-key field on this type MUST use `HardenedBytes`.
///
/// Mitigation: `Drop` zeroizes, and `secret_hardened()` moves the bytes into
/// a page-locked `HardenedBytes` buffer so callers can upgrade hardening
/// without changing the JSON-compatible storage type.
// ponytail: String for JSON compat, HardenedBytes at use-site via secret_hardened()
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SecretPayload {
    /// The primary secret (password, mnemonic, TOTP seed, etc.).
    pub secret: String,
    /// Optional notes (can contain otpauth:// URI for TOTP).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
    /// Type-specific extra fields.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extra: Option<serde_json::Value>,
}

impl SecretPayload {
    /// Borrow the primary secret for `--json` serialization.
    ///
    /// This is the single documented conversion point where in-memory secret
    /// material becomes a plain JSON string (see the forensic-window note on
    /// [`SecretPayload`]). Callers MUST treat the return value as live key
    /// material: emit it and drop the owner immediately.
    #[must_use]
    pub fn reveal_for_json(&self) -> &str {
        &self.secret
    }

    /// Copy the primary secret into a page-locked [`oc_crypto::HardenedBytes`] buffer.
    ///
    /// Requires the `hardened` feature. Use when the decrypted secret must be
    /// handled with `mlock` + `MADV_DONTDUMP` + zeroize-on-drop beyond the
    /// best-effort `Drop` zeroize on `Self`.
    #[cfg(feature = "hardened")]
    pub fn secret_hardened(&self) -> Result<oc_crypto::HardenedBytes, oc_crypto::MemGuardError> {
        oc_crypto::HardenedBytes::from_slice(self.secret.as_bytes())
    }

    /// Move the primary secret into a page-locked [`oc_crypto::HardenedBytes`] buffer.
    ///
    /// Requires the `hardened` feature. Consumes `self` so the original
    /// `String` backing buffer is zeroized on drop; the returned buffer is
    /// page-locked and zeroized on its own drop.
    #[cfg(feature = "hardened")]
    pub fn into_secret_hardened(
        self,
    ) -> Result<oc_crypto::HardenedBytes, oc_crypto::MemGuardError> {
        let hb = oc_crypto::HardenedBytes::from_slice(self.secret.as_bytes())?;
        // `self` is dropped here and its Drop impl zeroizes secret/notes.
        Ok(hb)
    }
}

impl Drop for SecretPayload {
    fn drop(&mut self) {
        self.secret.zeroize();
        if let Some(notes) = self.notes.as_mut() {
            notes.zeroize();
        }
    }
}

/// A secret entry index record (plaintext, stored in `index.jsonl`).
///
/// Contains no sensitive data — only metadata for listing and search.
///
/// # Generation + tombstone (B4)
///
/// `generation` is a monotonically increasing generation counter (saturating `u64`)
/// that binds the index row to the path-bound envelope inside the ciphertext
/// (see `oc-secret` envelope `ocenv/1`). `tombstone` marks a deleted name:
/// `delete` removes the ciphertext file but keeps the index row as a
/// tombstone so a later insert uses `next = floor + 1` (saturating) and a
/// replayed old ciphertext (smaller `generation`) is detected as tampered.
/// A co-rollback of file + index together is NOT detected (see N1 in
/// `docs/security-model.md`).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SecretIndexEntry {
    pub id: String,
    pub name: String,
    pub item_type: ItemType,
    pub created_at: String,
    pub updated_at: String,
    pub metadata: SecretMetadata,
    /// Monotonic generation (0 = legacy row written before B4).
    #[serde(default)]
    pub r#generation: u64,
    /// True when the name was deleted but the floor is retained.
    #[serde(default)]
    pub tombstone: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn item_type_serde_snake_case() {
        assert_eq!(serde_json::to_string(&ItemType::Mnemonic).unwrap(), "\"mnemonic\"");
        assert_eq!(serde_json::to_string(&ItemType::PrivateKey).unwrap(), "\"private_key\"");
        assert_eq!(serde_json::to_string(&ItemType::Totp).unwrap(), "\"totp\"");
    }

    #[test]
    fn item_type_round_trips() {
        for variant in ItemType::all() {
            let s = serde_json::to_string(variant).unwrap();
            let back: ItemType = serde_json::from_str(&s).unwrap();
            assert_eq!(variant, &back);
        }
    }

    #[test]
    fn item_type_all_has_six_variants() {
        assert_eq!(ItemType::all().len(), 6);
    }

    #[test]
    fn item_type_display_uses_label() {
        assert_eq!(ItemType::Mnemonic.to_string(), "Mnemonic");
        assert_eq!(ItemType::PrivateKey.to_string(), "Private Key");
        assert_eq!(ItemType::Totp.to_string(), "TOTP");
    }

    #[test]
    fn secret_metadata_default_is_empty() {
        let m = SecretMetadata::default();
        assert!(m.url.is_none());
        assert!(m.username.is_none());
        assert!(m.chain.is_none());
        assert!(m.issuer.is_none());
        assert!(m.account.is_none());
        assert_eq!(m.tags.len(), 0);
    }

    #[test]
    fn secret_metadata_skips_empty_fields_when_serialized() {
        let m = SecretMetadata::default();
        let json = serde_json::to_value(&m).unwrap();
        assert_eq!(json.as_object().unwrap().len(), 0);
    }

    #[test]
    fn secret_metadata_serializes_populated_fields() {
        let m = SecretMetadata {
            url: Some("https://example.com".into()),
            username: Some("alice".into()),
            chain: None,
            issuer: None,
            account: None,
            tags: vec!["work".into()],
        };
        let json = serde_json::to_value(&m).unwrap();
        assert_eq!(json["url"], "https://example.com");
        assert_eq!(json["username"], "alice");
        assert!(json.get("chain").is_none());
        assert_eq!(json["tags"][0], "work");
    }

    #[test]
    fn secret_payload_round_trips() {
        let p = SecretPayload {
            secret: "hunter2".into(),
            notes: Some("note text".into()),
            extra: Some(serde_json::json!({"k": "v"})),
        };
        let json = serde_json::to_string(&p).unwrap();
        let back: SecretPayload = serde_json::from_str(&json).unwrap();
        assert_eq!(back.secret, "hunter2");
        assert_eq!(back.notes.as_deref(), Some("note text"));
        assert_eq!(back.extra.as_ref().unwrap()["k"], "v");
    }

    #[test]
    fn secret_kind_covers_all_item_types() {
        // Every on-disk discriminator maps into exactly one of four kinds.
        for variant in ItemType::all() {
            assert!(SecretKind::all().contains(&SecretKind::from_item_type(*variant)));
        }
        assert_eq!(SecretKind::from_item_type(ItemType::Mnemonic), SecretKind::WalletKey);
        assert_eq!(SecretKind::from_item_type(ItemType::PrivateKey), SecretKind::WalletKey);
        assert_eq!(SecretKind::from_item_type(ItemType::Password), SecretKind::Password);
        assert_eq!(SecretKind::from_item_type(ItemType::Totp), SecretKind::TotpSeed);
        assert_eq!(SecretKind::from_item_type(ItemType::Note), SecretKind::Note);
        assert_eq!(SecretKind::from_item_type(ItemType::File), SecretKind::Note);
    }

    #[test]
    fn secret_kind_round_trips_and_parses() {
        for kind in SecretKind::all() {
            let s = serde_json::to_string(kind).unwrap();
            let back: SecretKind = serde_json::from_str(&s).unwrap();
            assert_eq!(kind, &back);
        }
        assert_eq!(SecretKind::parse("wallet_key"), Some(SecretKind::WalletKey));
        assert_eq!(SecretKind::parse("TOTP"), Some(SecretKind::TotpSeed));
        assert_eq!(SecretKind::parse("note"), Some(SecretKind::Note));
        assert_eq!(SecretKind::parse("bogus"), None);
        assert_eq!(SecretKind::Password.to_string(), "Password");
        assert_eq!(SecretKind::WalletKey.to_item_type(), ItemType::Mnemonic);
        assert_eq!(SecretKind::TotpSeed.to_item_type(), ItemType::Totp);
    }

    #[test]
    fn audit_op_names_are_dotted_and_unique() {
        use std::collections::HashSet;
        let mut seen = HashSet::new();
        for op in AuditOp::all() {
            let name = op.as_str();
            assert!(name.contains('.'), "audit op must be dotted: {name}");
            assert!(seen.insert(name), "duplicate audit op name: {name}");
            assert_eq!(op.to_string(), name);
        }
        assert_eq!(AuditOp::SecretCreate.as_str(), "secret.create");
        assert_eq!(AuditOp::TotpGenerate.as_str(), "totp.generate");
        assert_eq!(AuditOp::WalletCreate.as_str(), "wallet.create");
        // Signing rides the strong track, everything else the light track.
        assert_eq!(AuditOp::WalletSign.track(), AuditTrack::Strong);
        assert_eq!(AuditOp::WalletBroadcast.track(), AuditTrack::Strong);
        assert_eq!(AuditOp::SecretCreate.track(), AuditTrack::Light);
        assert_eq!(AuditOp::TotpGenerate.track(), AuditTrack::Light);
    }

    #[test]
    fn secret_envelope_carries_kind_and_generation() {
        let entry = SecretIndexEntry {
            id: "id-1".into(),
            name: "github".into(),
            item_type: ItemType::Password,
            created_at: "2024-01-01T00:00:00Z".into(),
            updated_at: "2024-01-02T00:00:00Z".into(),
            metadata: SecretMetadata::default(),
            r#generation: 3,
            tombstone: false,
        };
        let listing = SecretEnvelope::without_payload(&entry);
        assert_eq!(listing.kind, SecretKind::Password);
        assert!(listing.payload.is_none());
        let payload = SecretPayload { secret: "hunter2".into(), notes: None, extra: None };
        let disclosed = SecretEnvelope::with_payload(
            entry.name.clone(),
            entry.id.clone(),
            entry.item_type,
            entry.metadata.clone(),
            entry.generation,
            payload,
        );
        assert_eq!(disclosed.kind, SecretKind::Password);
        assert_eq!(disclosed.payload.as_ref().unwrap().reveal_for_json(), "hunter2");
        // Envelope serializes with both kind and item_type for agents.
        let json = serde_json::to_value(&disclosed).unwrap();
        assert_eq!(json["kind"], "password");
        assert_eq!(json["item_type"], "password");
        assert_eq!(json["generation"], 3);
    }

    #[test]
    fn secret_index_entry_round_trips() {
        let e = SecretIndexEntry {
            id: "abc-123".into(),
            name: "GitHub".into(),
            item_type: ItemType::Password,
            created_at: "2024-01-01T00:00:00Z".into(),
            updated_at: "2024-01-02T00:00:00Z".into(),
            metadata: SecretMetadata::default(),
            r#generation: 3,
            tombstone: false,
        };
        let json = serde_json::to_string(&e).unwrap();
        let back: SecretIndexEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(back.id, "abc-123");
        assert_eq!(back.name, "GitHub");
        assert_eq!(back.item_type, ItemType::Password);
        assert_eq!(back.r#generation, 3);
        assert!(!back.tombstone);
    }
}
