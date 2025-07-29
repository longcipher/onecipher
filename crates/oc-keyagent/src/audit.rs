//! Append-only JSONL audit log with SHA-256 chain hash + Ed25519 device
//! signatures.
//!
//! Per R39 / R40 / R75 / AD-03. The log is a JSONL file at
//! `~/.onecipher/logs/audit.jsonl` (mode 0600, parent dir mode 0700). Each
//! line is one signed `AuditEntry`. The `prev_hash` field chains entries
//! together via SHA-256 over the entry's *canonical bytes* (the entry
//! serialized with `device_sig = ""` using `serde_json::to_vec` compact
//! form), and `device_sig` is an Ed25519 signature over those same canonical
//! bytes. Mutating any field of any historical entry breaks either the
//! chain hash check or the signature check (or both) — `verify_chain`
//! detects tampering.
//!
//! Append-only — no `delete` / `update` / `remove` / `edit` methods exist
//! on `AuditLog`. Corrections are appended as new entries per R40 / AD-03.
//!
//! Per R56 / R77 / YAGNI: synchronous std only, NO tokio / reqwest / async.
//! `#![deny(unsafe_code)]` is preserved at the crate root — this module
//! uses zero `unsafe` blocks. SHA-256 and Ed25519 have no stable stdlib
//! equivalent, so `sha2` + `ed25519-dalek` are justified per the ponytail
//! ladder (step 6: vetted crypto primitives).

use std::{
    collections::HashMap,
    fs::{File, OpenOptions},
    io::{BufRead, BufReader, Write},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::RngExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// One signed line in the JSONL audit log.
///
/// Per R39. Field order is significant for canonical bytes: when computing
/// `device_sig` and `prev_hash`, we serialize this struct with
/// `device_sig = ""` using `serde_json::to_vec` (compact, NOT pretty). The
/// `prev_hash` field IS included in the signed bytes (chain integrity).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditEntry {
    pub device_id: String,
    pub seq: u64,
    pub timestamp: String, // RFC 3339 UTC
    pub event_type: EventType,
    pub session_key_id: Option<String>,
    pub payload: serde_json::Value,
    /// Hex SHA-256 of the prior entry's canonical bytes (`""` for the
    /// first entry in a log).
    pub prev_hash: String,
    /// Hex Ed25519 signature over this entry's canonical bytes (i.e. the
    /// entry serialized with `device_sig = ""`).
    pub device_sig: String,
}

/// Audit event types per R39 (17 variants) + secret-vault events (6 variants).
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EventType {
    CreateSessionKey,
    RevokeSessionKey,
    PayX402,
    PayMpp,
    SignUserOp,
    PasskeyForged,
    PasskeyMissing,
    PasskeyReplay,
    PolicyLookupFailed,
    PolicyParseFailed,
    HumanAlert,
    BudgetReclaim,
    BackupAttemptFailed,
    BackupLocked,
    MppChannelOpen,
    MppChannelClose,
    AuthFailed,
    // Secret-vault events (Phase 1 unified secret vault).
    SecretRead,
    SecretWritten,
    SecretDeleted,
    SecretMigrated,
    AgeRecipientAdded,
    AgeReencrypted,
}

#[derive(Debug, thiserror::Error)]
pub enum AuditError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("signature verification failed at seq {0}")]
    Tampered(u64),
    #[error("chain hash mismatch at seq {0}")]
    ChainHashMismatch(u64),
    #[error("signature error: {0}")]
    Signature(String),
    #[error("duplicate (device_id, seq) detected during merge")]
    DuplicateInMerge,
    #[error("device key error: {0}")]
    DeviceKeyError(String),
}

/// Append-only JSONL audit log with SHA-256 chain hash + Ed25519 device
/// signatures.
///
/// Public API surface (intentionally minimal — NO `delete` / `update` /
/// `remove` / `edit` methods exist, per R40 / AD-03):
/// - [`AuditLog::open`] — open or create a log file
/// - [`AuditLog::append`] — append a signed entry; fsyncs
/// - [`AuditLog::verify_chain`] — recompute chain + verify all signatures
/// - [`AuditLog::merge`] — dedupe + sort fragments into a new log
pub struct AuditLog {
    path: PathBuf,
    device_id: String,
    device_key: SigningKey,
    last_hash: String, // hex; "" if log is empty
    last_seq: u64,     // highest seq seen
}

impl AuditLog {
    /// Open an existing log file or create a new one.
    ///
    /// - Loads `last_hash` + `last_seq` from disk if the file is non-empty.
    /// - Enforces mode 0600 on the log file and mode 0700 on the parent directory (best-effort:
    ///   failures to set permissions are ignored, which mirrors how `chmod` would behave if a
    ///   non-root user opened a file they don't own — we just continue).
    pub fn open(path: &Path, device_id: &str, device_key: SigningKey) -> Result<Self, AuditError> {
        // Ensure parent dir exists with mode 0700.
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
                let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
            }
        }

        let existed = path.exists();
        if !existed {
            // Touch the file so we can set its mode before any appends.
            File::create(path)?;
        }
        // Enforce 0600 on the log file (best-effort).
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));

        let (last_hash, last_seq) =
            if existed { Self::load_tail(path)? } else { (String::new(), 0) };

        Ok(Self {
            path: path.to_path_buf(),
            device_id: device_id.to_string(),
            device_key,
            last_hash,
            last_seq,
        })
    }

    /// Read every entry in the file and return `(last_hash, last_seq)`.
    ///
    /// `last_hash` is `""` if the file is empty. Otherwise it is the
    /// SHA-256 hex of the canonical bytes of the last non-empty entry.
    fn load_tail(path: &Path) -> Result<(String, u64), AuditError> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        let mut last_hash = String::new();
        let mut last_seq = 0u64;
        for line in reader.lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            // Tolerate legacy audit entries (missing device_id/seq fields) by
            // skipping lines that don't deserialize to the current schema.
            // This keeps the chain hash continuous after an upgrade.
            if let Ok(entry) = serde_json::from_str::<AuditEntry>(&line) {
                last_hash = hash_entry(&entry);
                last_seq = entry.seq;
            }
        }
        Ok((last_hash, last_seq))
    }

    /// Append a signed entry to the log. Computes `seq`, `timestamp`,
    /// `prev_hash`, and `device_sig` internally. fsyncs after writing
    /// (durability over throughput, per R75).
    ///
    /// Returns the assigned `seq`.
    pub fn append(
        &mut self,
        event_type: EventType,
        session_key_id: Option<String>,
        payload: serde_json::Value,
    ) -> Result<u64, AuditError> {
        let seq = self.last_seq + 1;
        let timestamp = jiff::Timestamp::now().to_string();
        let entry = AuditEntry {
            device_id: self.device_id.clone(),
            seq,
            timestamp,
            event_type,
            session_key_id,
            payload,
            prev_hash: self.last_hash.clone(),
            device_sig: String::new(),
        };

        // Canonical bytes (device_sig = "") used for BOTH signing and
        // chain hashing. The `prev_hash` field IS included in the signed
        // bytes so that chain integrity is itself signed.
        let canonical = canonical_bytes(&entry);
        let signature: Signature = self.device_key.sign(&canonical);
        let mut signed_entry = entry;
        signed_entry.device_sig = hex::encode(signature.to_bytes());

        // Serialize the signed entry to one JSONL line and append.
        let line = serde_json::to_string(&signed_entry)?;
        let mut file = OpenOptions::new().append(true).open(&self.path)?;
        file.write_all(line.as_bytes())?;
        file.write_all(b"\n")?;
        file.sync_all()?;

        // Update in-memory tail state.
        self.last_hash = hash_entry(&signed_entry);
        self.last_seq = seq;

        Ok(seq)
    }

    /// Verify the chain: recompute `prev_hash` for every entry and verify
    /// every `device_sig` against the public key derived from
    /// `self.device_key`.
    ///
    /// Returns `Err(Tampered(seq))` on signature mismatch,
    /// `Err(ChainHashMismatch(seq))` on chain break, or
    /// `Err(Signature(...))` on malformed signature bytes.
    pub fn verify_chain(&self) -> Result<(), AuditError> {
        let file = File::open(&self.path)?;
        let reader = BufReader::new(file);
        let verifying_key: VerifyingKey = self.device_key.verifying_key();
        let mut prev_hash = String::new();

        for line in reader.lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            let entry: AuditEntry = serde_json::from_str(&line)?;

            // 1) Chain hash check: entry.prev_hash must equal the hash of the previous entry's
            //    canonical bytes.
            if entry.prev_hash != prev_hash {
                return Err(AuditError::ChainHashMismatch(entry.seq));
            }

            // 2) Signature check: the stored device_sig must verify against the canonical bytes
            //    (entry with device_sig = ""). Any field mutation (timestamp, payload, prev_hash,
            //    event_type, etc.) changes the canonical bytes and breaks the signature.
            let canonical = canonical_bytes(&entry);
            let sig_bytes =
                hex::decode(&entry.device_sig).map_err(|e| AuditError::Signature(e.to_string()))?;
            if sig_bytes.len() != 64 {
                return Err(AuditError::Signature(format!(
                    "invalid signature length: {} (expected 64)",
                    sig_bytes.len()
                )));
            }
            let mut arr = [0u8; 64];
            arr.copy_from_slice(&sig_bytes);
            let signature = Signature::from_bytes(&arr);

            verifying_key
                .verify(&canonical, &signature)
                .map_err(|_| AuditError::Tampered(entry.seq))?;

            prev_hash = hash_entry(&entry);
        }

        Ok(())
    }

    /// Merge multiple fragment log files into one output log.
    ///
    /// - Dedupes by `(device_id, seq)` — first-seen wins (no overwrite).
    /// - Sorts output by `(timestamp, seq, device_id)`.
    /// - Does NOT re-sign entries (each entry keeps its original signature).
    /// - Enforces mode 0600 on the output file and mode 0700 on the parent.
    /// - The returned `AuditLog` carries the supplied `device_key` so the caller can continue
    ///   appending; `device_id` is set to the `device_id` of the last written entry (or empty if
    ///   the merge was a no-op). When `verify_chain` is later called on the merged log, it will
    ///   verify every entry against `device_key`'s public key — so for a multi-device merge, the
    ///   caller is responsible for ensuring all fragment entries were signed by `device_key` (or
    ///   for not calling `verify_chain` on the merged output).
    pub fn merge(
        fragments: Vec<PathBuf>,
        output: &Path,
        device_key: &SigningKey,
    ) -> Result<Self, AuditError> {
        let mut seen: HashMap<(String, u64), AuditEntry> = HashMap::new();

        for frag_path in &fragments {
            let file = File::open(frag_path)?;
            let reader = BufReader::new(file);
            for line in reader.lines() {
                let line = line?;
                if line.trim().is_empty() {
                    continue;
                }
                let entry: AuditEntry = serde_json::from_str(&line)?;
                let key = (entry.device_id.clone(), entry.seq);
                // First-seen wins: only insert if not already present.
                seen.entry(key).or_insert(entry);
            }
        }

        let mut all_entries: Vec<AuditEntry> = seen.into_values().collect();
        all_entries.sort_by(|a, b| {
            a.timestamp
                .cmp(&b.timestamp)
                .then(a.seq.cmp(&b.seq))
                .then(a.device_id.cmp(&b.device_id))
        });

        // Ensure output parent dir exists with mode 0700.
        if let Some(parent) = output.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
                let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
            }
        }

        // Write merged log.
        {
            let mut file = File::create(output)?;
            for entry in &all_entries {
                let line = serde_json::to_string(entry)?;
                file.write_all(line.as_bytes())?;
                file.write_all(b"\n")?;
            }
            file.sync_all()?;
        }
        let _ = std::fs::set_permissions(output, std::fs::Permissions::from_mode(0o600));

        let (last_hash, last_seq, device_id) = if let Some(last) = all_entries.last() {
            (hash_entry(last), last.seq, last.device_id.clone())
        } else {
            (String::new(), 0, String::new())
        };

        Ok(Self {
            path: output.to_path_buf(),
            device_id,
            device_key: device_key.clone(),
            last_hash,
            last_seq,
        })
    }

    // -----------------------------------------------------------------------
    // Secret-vault convenience methods (Phase 1 unified secret vault).
    //
    // Per R56: these methods log only the event name and non-sensitive
    // metadata (secret name, item type). The actual secret content is NEVER
    // written to the audit log.
    // -----------------------------------------------------------------------

    /// Log a `SecretRead` event. Records the secret name and item type only —
    /// never the secret content.
    pub fn log_secret_read(&mut self, name: &str, item_type: &str) -> Result<u64, AuditError> {
        self.append(
            EventType::SecretRead,
            None,
            serde_json::json!({ "name": name, "item_type": item_type }),
        )
    }

    /// Log a `SecretWritten` event. Records the secret name and item type.
    pub fn log_secret_written(&mut self, name: &str, item_type: &str) -> Result<u64, AuditError> {
        self.append(
            EventType::SecretWritten,
            None,
            serde_json::json!({ "name": name, "item_type": item_type }),
        )
    }

    /// Log a `SecretDeleted` event. Records the secret name.
    pub fn log_secret_deleted(&mut self, name: &str) -> Result<u64, AuditError> {
        self.append(EventType::SecretDeleted, None, serde_json::json!({ "name": name }))
    }

    /// Log a `SecretMigrated` event. Records the old and new names.
    pub fn log_secret_migrated(
        &mut self,
        old_name: &str,
        new_name: &str,
    ) -> Result<u64, AuditError> {
        self.append(
            EventType::SecretMigrated,
            None,
            serde_json::json!({ "old_name": old_name, "new_name": new_name }),
        )
    }

    /// Log an `AgeRecipientAdded` event. Records the recipient identifier.
    pub fn log_age_recipient_added(&mut self, recipient: &str) -> Result<u64, AuditError> {
        self.append(
            EventType::AgeRecipientAdded,
            None,
            serde_json::json!({ "recipient": recipient }),
        )
    }

    /// Log an `AgeReencrypted` event. Records the secret name.
    pub fn log_age_reencrypted(&mut self, name: &str) -> Result<u64, AuditError> {
        self.append(EventType::AgeReencrypted, None, serde_json::json!({ "name": name }))
    }
}

/// Persistent store for the audit log device signing key.
///
/// Stored as 32 raw bytes at `~/.onecipher/audit_device.key` (mode 0600).
/// Parent directory is mode 0700. The same key is reused across restarts so
/// that the audit chain hash and signatures remain verifiable — without this,
/// every process restart would generate a new random key and break the chain.
pub struct DeviceKeyStore {
    path: PathBuf,
}

impl DeviceKeyStore {
    /// Open the default store at `~/.onecipher/audit_device.key`.
    pub fn open_default() -> Result<Self, AuditError> {
        let path = default_device_key_path()?;
        Ok(Self { path })
    }

    /// Open a store at a specific path.
    pub fn open(path: &Path) -> Self {
        Self { path: path.to_path_buf() }
    }

    /// Load the device signing key, or generate and persist a new one if it
    /// doesn't exist.
    pub fn load_or_generate(&self) -> Result<SigningKey, AuditError> {
        if self.path.exists() { self.load() } else { self.generate_and_save() }
    }

    /// Load an existing device key from disk.
    fn load(&self) -> Result<SigningKey, AuditError> {
        let data = std::fs::read(&self.path)
            .map_err(|e| AuditError::DeviceKeyError(format!("read key: {e}")))?;

        if data.len() != 32 {
            return Err(AuditError::DeviceKeyError(format!(
                "expected 32 bytes, got {}",
                data.len()
            )));
        }

        let key_bytes: [u8; 32] = data
            .as_slice()
            .try_into()
            .map_err(|_| AuditError::DeviceKeyError("key conversion failed".to_string()))?;

        Ok(SigningKey::from_bytes(&key_bytes))
    }

    /// Generate a new random device key and save it to disk.
    fn generate_and_save(&self) -> Result<SigningKey, AuditError> {
        // Generate 32 random bytes via the kernel CSPRNG, then construct the
        // signing key from raw bytes. (We avoid `SigningKey::generate` because
        // ed25519-dalek 2.x depends on `rand_core` 0.6, while the workspace
        // uses `rand` 0.10 which exports `rand_core` 0.10 — the trait bounds
        // don't line up across the two versions.)
        let mut key_bytes = [0u8; 32];
        rand::rng().fill(&mut key_bytes);
        let signing_key = SigningKey::from_bytes(&key_bytes);

        // Ensure parent directory exists with 0700 permissions
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| AuditError::DeviceKeyError(format!("create dir: {e}")))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))
                    .map_err(|e| AuditError::DeviceKeyError(format!("set dir perms: {e}")))?;
            }
        }

        // Write key bytes (32 bytes raw)
        let key_bytes = signing_key.to_bytes();
        std::fs::write(&self.path, key_bytes)
            .map_err(|e| AuditError::DeviceKeyError(format!("write key: {e}")))?;

        // Set file permissions to 0600
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&self.path, std::fs::Permissions::from_mode(0o600))
                .map_err(|e| AuditError::DeviceKeyError(format!("set file perms: {e}")))?;
        }

        Ok(signing_key)
    }
}

/// Resolve the default device key path: `~/.onecipher/audit_device.key`
fn default_device_key_path() -> Result<PathBuf, AuditError> {
    let home = std::env::var("HOME")
        .map_err(|_| AuditError::DeviceKeyError("HOME not set".to_string()))?;
    Ok(PathBuf::from(home).join(".onecipher").join("audit_device.key"))
}

/// Compute the canonical bytes of an entry: the entry serialized with
/// `device_sig = ""` using `serde_json::to_vec` (compact, NOT pretty).
/// Used for BOTH signing and chain hashing — same bytes, same hash.
fn canonical_bytes(entry: &AuditEntry) -> Vec<u8> {
    let mut copy = entry.clone();
    copy.device_sig = String::new();
    // AuditEntry is always JSON-serializable (no custom Serialize impls,
    // no NaN/Infinity possible in serde_json::Value::Number).
    serde_json::to_vec(&copy).expect("AuditEntry is always JSON-serializable")
}

/// Compute `SHA-256(canonical_bytes(entry))` as a lowercase hex string.
fn hash_entry(entry: &AuditEntry) -> String {
    let mut hasher = Sha256::new();
    hasher.update(canonical_bytes(entry));
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_type_serde_snake_case() {
        // Spot-check a few variants to confirm `rename_all = "snake_case"`.
        assert_eq!(
            serde_json::to_string(&EventType::CreateSessionKey).unwrap(),
            "\"create_session_key\""
        );
        assert_eq!(serde_json::to_string(&EventType::PayX402).unwrap(), "\"pay_x402\"");
        assert_eq!(
            serde_json::to_string(&EventType::MppChannelOpen).unwrap(),
            "\"mpp_channel_open\""
        );
        assert_eq!(
            serde_json::to_string(&EventType::BackupAttemptFailed).unwrap(),
            "\"backup_attempt_failed\""
        );
        assert_eq!(serde_json::to_string(&EventType::AuthFailed).unwrap(), "\"auth_failed\"");
    }

    #[test]
    fn event_type_round_trips_through_json() {
        let all = [
            EventType::CreateSessionKey,
            EventType::RevokeSessionKey,
            EventType::PayX402,
            EventType::PayMpp,
            EventType::SignUserOp,
            EventType::PasskeyForged,
            EventType::PasskeyMissing,
            EventType::PasskeyReplay,
            EventType::PolicyLookupFailed,
            EventType::PolicyParseFailed,
            EventType::HumanAlert,
            EventType::BudgetReclaim,
            EventType::BackupAttemptFailed,
            EventType::BackupLocked,
            EventType::MppChannelOpen,
            EventType::MppChannelClose,
            EventType::AuthFailed,
            EventType::SecretRead,
            EventType::SecretWritten,
            EventType::SecretDeleted,
            EventType::SecretMigrated,
            EventType::AgeRecipientAdded,
            EventType::AgeReencrypted,
        ];
        assert_eq!(all.len(), 23, "17 base + 6 secret-vault variants");
        for e in all {
            let s = serde_json::to_string(&e).unwrap();
            let back: EventType = serde_json::from_str(&s).unwrap();
            assert_eq!(e, back, "round-trip failed for {:?}", e);
        }
    }

    #[test]
    fn canonical_bytes_excludes_device_sig() {
        let entry = AuditEntry {
            device_id: "dev1".into(),
            seq: 1,
            timestamp: "1970-01-01T00:00:00Z".into(),
            event_type: EventType::HumanAlert,
            session_key_id: None,
            payload: serde_json::json!({"k": "v"}),
            prev_hash: String::new(),
            device_sig: "deadbeef".into(),
        };
        let canonical = canonical_bytes(&entry);
        let s = String::from_utf8(canonical).unwrap();
        // device_sig in canonical form is empty string.
        assert!(
            s.contains("\"device_sig\":\"\""),
            "canonical bytes must have empty device_sig, got: {}",
            s
        );
        assert!(!s.contains("deadbeef"), "canonical bytes must not include the real device_sig");
    }

    #[test]
    fn hash_entry_is_64_hex_chars() {
        let entry = AuditEntry {
            device_id: "dev1".into(),
            seq: 1,
            timestamp: "1970-01-01T00:00:00Z".into(),
            event_type: EventType::HumanAlert,
            session_key_id: None,
            payload: serde_json::json!({"k": "v"}),
            prev_hash: String::new(),
            device_sig: String::new(),
        };
        let h = hash_entry(&entry);
        assert_eq!(h.len(), 64, "SHA-256 hex is 64 chars");
        assert!(h.chars().all(|c| c.is_ascii_hexdigit()));
    }

    // --- Secret-vault convenience methods ---

    fn make_test_log() -> (tempfile::TempDir, AuditLog) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let mut key_bytes = [0u8; 32];
        rand::rng().fill(&mut key_bytes);
        let device_key = SigningKey::from_bytes(&key_bytes);
        let log = AuditLog::open(&path, "test-device", device_key).unwrap();
        (dir, log)
    }

    #[test]
    fn log_secret_read_appends_event() {
        let (_dir, mut log) = make_test_log();
        let seq = log.log_secret_read("github-token", "password").unwrap();
        assert_eq!(seq, 1);
    }

    #[test]
    fn log_secret_written_appends_event() {
        let (_dir, mut log) = make_test_log();
        let seq = log.log_secret_written("new-secret", "totp").unwrap();
        assert_eq!(seq, 1);
    }

    #[test]
    fn log_secret_deleted_appends_event() {
        let (_dir, mut log) = make_test_log();
        let seq = log.log_secret_deleted("old-secret").unwrap();
        assert_eq!(seq, 1);
    }

    #[test]
    fn log_secret_migrated_appends_event() {
        let (_dir, mut log) = make_test_log();
        let seq = log.log_secret_migrated("old", "new").unwrap();
        assert_eq!(seq, 1);
    }

    #[test]
    fn log_age_recipient_added_appends_event() {
        let (_dir, mut log) = make_test_log();
        let seq = log.log_age_recipient_added("age1xyz").unwrap();
        assert_eq!(seq, 1);
    }

    #[test]
    fn log_age_reencrypted_appends_event() {
        let (_dir, mut log) = make_test_log();
        let seq = log.log_age_reencrypted("github-token").unwrap();
        assert_eq!(seq, 1);
    }

    #[test]
    fn secret_convenience_methods_increment_seq() {
        let (_dir, mut log) = make_test_log();
        assert_eq!(log.log_secret_read("a", "password").unwrap(), 1);
        assert_eq!(log.log_secret_written("b", "totp").unwrap(), 2);
        assert_eq!(log.log_secret_deleted("c").unwrap(), 3);
        assert_eq!(log.log_secret_migrated("d", "e").unwrap(), 4);
        assert_eq!(log.log_age_recipient_added("f").unwrap(), 5);
        assert_eq!(log.log_age_reencrypted("g").unwrap(), 6);
    }

    #[test]
    fn secret_convenience_chain_verifies() {
        let (dir, mut log) = make_test_log();
        log.log_secret_read("github", "password").unwrap();
        log.log_secret_written("gitlab", "password").unwrap();
        log.log_secret_deleted("temp").unwrap();
        // verify_chain must succeed — the chain hash + signatures must be intact.
        assert!(log.verify_chain().is_ok(), "audit chain must verify after secret events");
        // Drop log before dir to release the file handle.
        drop(log);
        let _ = dir;
    }
}

#[cfg(test)]
mod device_key_tests {
    use tempfile::tempdir;

    use super::*;

    #[test]
    fn test_generate_and_load() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("audit_device.key");
        let store = DeviceKeyStore::open(&path);

        // First call generates
        let key1 = store.load_or_generate().unwrap();

        // Second call loads the same key
        let key2 = store.load_or_generate().unwrap();

        assert_eq!(key1.to_bytes(), key2.to_bytes());
    }

    #[test]
    fn test_file_permissions() {
        // On Unix, verify the file has 0600 permissions
        let dir = tempdir().unwrap();
        let path = dir.path().join("audit_device.key");
        let store = DeviceKeyStore::open(&path);
        let _ = store.load_or_generate().unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(perms & 0o777, 0o600);
        }
    }
}
