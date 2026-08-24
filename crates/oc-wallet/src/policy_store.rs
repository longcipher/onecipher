//! Persistent storage for signed policy documents.
//!
//! # Signature scheme (sidecar)
//!
//! The policy JSON schema is unchanged. Each policy file `<id>.json` is
//! accompanied by a detached Ed25519 signature sidecar `<id>.json.sig`
//! containing the **lowercase hex encoding of the raw 64-byte Ed25519
//! signature** over the *exact* policy file bytes as written to disk.
//!
//! - `save_policy` writes the policy JSON atomically, then signs the exact byte sequence it wrote
//!   and stores the signature in the sidecar (mode 0600, atomic private write).
//! - `load_policy` verifies the sidecar against the file bytes read from disk and fails closed: any
//!   mismatch or corruption yields [`PolicyStoreError::SignatureInvalid`] and the policy is NOT
//!   returned.
//!
//! # Signing key choice
//!
//! The audit log's persistent device key lives in `oc-keyagent`
//! (`DeviceKeyStore`), which is deliberately NOT a dependency of `oc-wallet`
//! (crate isolation: the Key-Agent is consumed over UDS, and pulling it in
//! here would violate the workspace's dependency-boundary rules). This crate
//! therefore uses a **dedicated local signing keypair**, persisted at
//! `<vault>/policy_signing.key` — by default `~/.onecipher/policy_signing.key`,
//! i.e. the wallet config/state directory — as a raw 32-byte Ed25519 seed at
//! mode 0600 via [`oc_core::paths::write_atomic_private`] (same format as the
//! audit device key). The key is generated on first `save_policy` call and
//! reused so that previously written signatures remain verifiable.
//!
//! # Legacy migration path
//!
//! Policy files written before this scheme have no `.sig` sidecar.
//! `load_policy` accepts them but emits a `tracing::warn!` and reports them
//! via [`SignedPolicy::signature_verified`] == `false`, so callers can
//! distinguish verified from legacy-unsigned policies. Re-saving a legacy
//! policy with `save_policy` upgrades it to signed.
//!
//! `list_policies` is a non-verifying listing view (it never returns policy
//! data to the enforcement path); all enforcement lookups go through
//! `load_policy`, which fails closed.

use std::{
    fs,
    path::{Path, PathBuf},
};

use ed25519_dalek::{Signature, Signer as _, SigningKey, Verifier as _, VerifyingKey};
use oc_core::Policy;
use zeroize::Zeroize as _;

use crate::error::OcWalletError;

/// File name of the dedicated policy signing key inside the vault root.
const SIGNING_KEY_FILE: &str = "policy_signing.key";

/// Typed errors for the policy store.
#[derive(Debug, thiserror::Error)]
pub enum PolicyStoreError {
    /// Signature verification failed or the sidecar is corrupt/unverifiable.
    /// Loaders MUST treat this as fail-closed: the policy is not returned.
    #[error("policy signature invalid for '{path}': {reason}")]
    SignatureInvalid { path: String, reason: String },
}

/// A policy loaded from disk together with its signature-verification status.
#[derive(Debug, Clone)]
pub struct SignedPolicy {
    /// The deserialized policy document.
    pub policy: Policy,
    /// `true` iff a `.sig` sidecar existed AND verified against the exact
    /// file bytes. `false` means the policy was loaded via the legacy
    /// unsigned migration path (a warning is logged in that case).
    pub signature_verified: bool,
}

impl SignedPolicy {
    /// Whether the policy was loaded with a verified signature sidecar.
    pub fn is_signed(&self) -> bool {
        self.signature_verified
    }
}

/// Returns the policies directory, creating it if needed.
/// Policies are not secret — no restrictive permissions applied.
pub fn policies_dir(vault_path: Option<&Path>) -> Result<PathBuf, OcWalletError> {
    let base = oc_vault::resolve_vault_path(vault_path);
    let dir = base.join("policies");
    fs::create_dir_all(&dir)?;
    Ok(dir)
}

/// Path of the detached signature sidecar for a policy file.
fn sidecar_path(policy_path: &Path) -> PathBuf {
    let mut os = policy_path.as_os_str().to_os_string();
    os.push(".sig");
    PathBuf::from(os)
}

/// Path of the dedicated policy signing key:
/// `<vault_root>/policy_signing.key`. With no explicit vault path this
/// resolves to `~/.onecipher/policy_signing.key` (the wallet state/config
/// directory).
fn signing_key_path(vault_path: Option<&Path>) -> Result<PathBuf, OcWalletError> {
    let base = oc_vault::resolve_vault_path(vault_path);
    Ok(base.join(SIGNING_KEY_FILE))
}

/// Read an existing 32-byte Ed25519 seed from disk into a [`SigningKey`].
fn read_signing_key(path: &Path) -> Result<SigningKey, String> {
    let data = fs::read(path).map_err(|e| format!("read signing key: {e}"))?;
    let seed: [u8; 32] = data
        .as_slice()
        .try_into()
        .map_err(|_| format!("expected a 32-byte Ed25519 seed, got {} bytes", data.len()))?;
    Ok(SigningKey::from_bytes(&seed))
}

/// Load the dedicated policy signing key, generating and persisting a new
/// one (mode 0600) if it does not exist yet.
fn load_or_generate_signing_key(vault_path: Option<&Path>) -> Result<SigningKey, OcWalletError> {
    let path = signing_key_path(vault_path)?;
    if path.exists() {
        return read_signing_key(&path).map_err(OcWalletError::InvalidInput);
    }

    // Generate 32 random bytes via the kernel CSPRNG and construct the key
    // from raw bytes (avoids the ed25519-dalek/rand_core version-mismatch
    // documented in oc-keyagent's DeviceKeyStore).
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed)
        .map_err(|e| OcWalletError::InvalidInput(format!("generate signing key: {e}")))?;
    let key = SigningKey::from_bytes(&seed);
    // Best-effort wipe of the stack copy; the persisted form is `key.to_bytes()`.
    seed.zeroize();

    oc_core::paths::write_atomic_private(&path, &key.to_bytes())?;
    tracing::info!(path = %path.display(), "generated new policy signing key");
    Ok(key)
}

/// Save a policy to `<vault>/policies/<id>.json` together with a detached
/// Ed25519 signature sidecar `<id>.json.sig` (mode 0600) over the exact
/// file bytes.
pub fn save_policy(policy: &Policy, vault_path: Option<&Path>) -> Result<(), OcWalletError> {
    let dir = policies_dir(vault_path)?;
    let path = dir.join(format!("{}.json", policy.id));
    let json = serde_json::to_vec_pretty(policy)?;
    // Atomic: a torn write here would leave a corrupt or partially-populated
    // policy file. Because the engine is default-deny that is a lockout at
    // best, and at worst a truncation that still parses but has lost a rule.
    oc_core::paths::write_atomic(&path, &json, oc_core::paths::MODE_REGULAR_FILE)?;

    // Sign the EXACT bytes written to disk and store the detached signature.
    let signing_key = load_or_generate_signing_key(vault_path)?;
    let signature = signing_key.sign(&json);
    let sig_hex = hex::encode(signature.to_bytes());
    let sig_path = sidecar_path(&path);
    oc_core::paths::write_atomic_private(&sig_path, sig_hex.as_bytes())?;
    Ok(())
}

/// Load a single policy by ID, verifying its signature sidecar when present.
///
/// - Sidecar present + valid → [`SignedPolicy`] with `signature_verified`.
/// - Sidecar present + invalid/corrupt/unverifiable → typed [`PolicyStoreError::SignatureInvalid`]
///   (fail-closed; the policy is not returned).
/// - Sidecar absent → legacy migration path: loads with a `tracing::warn!` and `signature_verified
///   == false`.
pub fn load_policy(id: &str, vault_path: Option<&Path>) -> Result<SignedPolicy, OcWalletError> {
    let dir = policies_dir(vault_path)?;
    let path = dir.join(format!("{id}.json"));
    if !path.exists() {
        return Err(OcWalletError::InvalidInput(format!("policy not found: {id}")));
    }
    let contents = fs::read(&path)?;
    let sig_path = sidecar_path(&path);

    if !sig_path.exists() {
        tracing::warn!(
            path = %path.display(),
            "policy file has no signature sidecar; loading as legacy unsigned policy"
        );
        let policy: Policy = serde_json::from_slice(&contents)?;
        return Ok(SignedPolicy { policy, signature_verified: false });
    }

    verify_sidecar(&path, &sig_path, &contents, vault_path)?;
    let policy: Policy = serde_json::from_slice(&contents)?;
    Ok(SignedPolicy { policy, signature_verified: true })
}

/// Verify the detached sidecar signature against the exact policy bytes.
fn verify_sidecar(
    policy_path: &Path,
    sig_path: &Path,
    contents: &[u8],
    vault_path: Option<&Path>,
) -> Result<(), OcWalletError> {
    let invalid = |reason: String| {
        OcWalletError::PolicyStore(PolicyStoreError::SignatureInvalid {
            path: policy_path.display().to_string(),
            reason,
        })
    };

    let key_path = signing_key_path(vault_path)?;
    if !key_path.exists() {
        return Err(invalid("policy signing key not found; cannot verify".into()));
    }
    let signing_key = read_signing_key(&key_path).map_err(invalid)?;

    let sig_text =
        fs::read_to_string(sig_path).map_err(|e| invalid(format!("read sidecar: {e}")))?;
    let sig_bytes = hex::decode(sig_text.trim())
        .map_err(|e| invalid(format!("corrupt sidecar (bad hex): {e}")))?;
    let raw: [u8; 64] = sig_bytes
        .as_slice()
        .try_into()
        .map_err(|_| invalid(format!("corrupt sidecar (bad length {})", sig_bytes.len())))?;
    let signature = Signature::from_bytes(&raw);

    let verifying_key: VerifyingKey = signing_key.verifying_key();
    verifying_key
        .verify(contents, &signature)
        .map_err(|e| invalid(format!("signature mismatch: {e}")))
}

/// List all policies, sorted alphabetically by name.
///
/// Non-verifying listing view: see the module docs. Enforcement paths must
/// use [`load_policy`].
pub fn list_policies(vault_path: Option<&Path>) -> Result<Vec<Policy>, OcWalletError> {
    let dir = policies_dir(vault_path)?;
    let mut policies = Vec::new();

    let entries = match fs::read_dir(&dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(policies),
        Err(e) => return Err(e.into()),
    };

    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        match fs::read_to_string(&path) {
            Ok(contents) => match serde_json::from_str::<Policy>(&contents) {
                Ok(p) => policies.push(p),
                Err(e) => {
                    tracing::warn!(path = %path.display(), error = %e, "skipping policy file");
                }
            },
            Err(e) => tracing::warn!(path = %path.display(), error = %e, "skipping policy file"),
        }
    }

    policies.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(policies)
}

/// Delete a policy by ID, removing its signature sidecar as well.
pub fn delete_policy(id: &str, vault_path: Option<&Path>) -> Result<(), OcWalletError> {
    let dir = policies_dir(vault_path)?;
    let path = dir.join(format!("{id}.json"));
    if !path.exists() {
        return Err(OcWalletError::InvalidInput(format!("policy not found: {id}")));
    }
    fs::remove_file(&path)?;
    let sig_path = sidecar_path(&path);
    if sig_path.exists() {
        fs::remove_file(&sig_path)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use oc_core::{PolicyAction, PolicyRule};

    use super::*;

    fn test_policy(id: &str, name: &str) -> Policy {
        Policy {
            id: id.to_string(),
            name: name.to_string(),
            version: 1,
            created_at: "2026-03-22T10:00:00Z".to_string(),
            rules: vec![PolicyRule::AllowedChains { chain_ids: vec!["eip155:8453".to_string()] }],
            executable: None,
            config: None,
            action: PolicyAction::Deny,
        }
    }

    #[test]
    fn save_and_load_roundtrip_verifies_signature() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().to_path_buf();
        let policy = test_policy("base-only", "Base Only");

        save_policy(&policy, Some(&vault)).unwrap();
        let loaded = load_policy("base-only", Some(&vault)).unwrap();

        assert!(loaded.signature_verified, "roundtrip must verify the sidecar");
        assert!(loaded.is_signed());
        assert_eq!(loaded.policy.id, "base-only");
        assert_eq!(loaded.policy.name, "Base Only");
        assert_eq!(loaded.policy.rules.len(), 1);
    }

    #[test]
    fn tampered_policy_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().to_path_buf();
        let policy = test_policy("tamper-me", "Original Name");

        save_policy(&policy, Some(&vault)).unwrap();

        // Mutate one byte of the stored JSON after signing.
        let path = vault.join("policies").join("tamper-me.json");
        let contents = fs::read_to_string(&path).unwrap();
        let tampered = contents.replace("Original Name", "Tampered Name");
        assert_ne!(contents, tampered, "tamper must change the bytes");
        fs::write(&path, tampered).unwrap();

        let result = load_policy("tamper-me", Some(&vault));
        match result {
            Err(OcWalletError::PolicyStore(PolicyStoreError::SignatureInvalid {
                path, ..
            })) => {
                assert!(path.ends_with("tamper-me.json"));
            }
            other => panic!("expected SignatureInvalid, got: {other:?}"),
        }
    }

    #[test]
    fn missing_sig_loads_unsigned_with_warning_flag() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().to_path_buf();
        let policy = test_policy("legacy", "Legacy Policy");

        save_policy(&policy, Some(&vault)).unwrap();

        // Simulate a pre-signing-era file by removing the sidecar.
        let sig = vault.join("policies").join("legacy.json.sig");
        assert!(sig.exists(), "save_policy must create the sidecar");
        fs::remove_file(&sig).unwrap();

        let loaded = load_policy("legacy", Some(&vault)).unwrap();
        assert!(!loaded.signature_verified, "missing sidecar must be reported unsigned");
        assert!(!loaded.is_signed());
        assert_eq!(loaded.policy.name, "Legacy Policy");
    }

    #[test]
    fn corrupt_sig_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().to_path_buf();
        save_policy(&test_policy("corrupt", "Corrupt Sig"), Some(&vault)).unwrap();

        let sig = vault.join("policies").join("corrupt.json.sig");
        fs::write(&sig, "not-hex-signature-data").unwrap();

        let result = load_policy("corrupt", Some(&vault));
        assert!(
            matches!(
                result,
                Err(OcWalletError::PolicyStore(PolicyStoreError::SignatureInvalid { .. }))
            ),
            "corrupt sidecar must yield SignatureInvalid"
        );
    }

    #[test]
    fn wrong_signing_key_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().to_path_buf();
        save_policy(&test_policy("wrong-key", "Wrong Key"), Some(&vault)).unwrap();

        // Replace the signing key with a different one; existing signatures
        // must no longer verify.
        let key_path = vault.join(SIGNING_KEY_FILE);
        assert!(key_path.exists());
        let mut fresh = [7u8; 32];
        getrandom::fill(&mut fresh).unwrap();
        oc_core::paths::write_atomic_private(&key_path, &fresh).unwrap();

        let result = load_policy("wrong-key", Some(&vault));
        assert!(
            matches!(
                result,
                Err(OcWalletError::PolicyStore(PolicyStoreError::SignatureInvalid { .. }))
            ),
            "signature from another key must be rejected"
        );
    }

    #[cfg(unix)]
    #[test]
    fn sig_sidecar_has_0600_permissions() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().to_path_buf();
        save_policy(&test_policy("perm-check", "Perms"), Some(&vault)).unwrap();

        let sig = vault.join("policies").join("perm-check.json.sig");
        let mode = fs::metadata(&sig).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "sidecar must be mode 0600");

        // The signing key file must also be private.
        let key_mode =
            fs::metadata(vault.join(SIGNING_KEY_FILE)).unwrap().permissions().mode() & 0o777;
        assert_eq!(key_mode, 0o600, "signing key must be mode 0600");
    }

    #[test]
    fn delete_removes_sidecar() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().to_path_buf();

        save_policy(&test_policy("del-sig", "Delete Sig"), Some(&vault)).unwrap();
        assert!(vault.join("policies").join("del-sig.json.sig").exists());

        delete_policy("del-sig", Some(&vault)).unwrap();
        assert!(!vault.join("policies").join("del-sig.json").exists());
        assert!(!vault.join("policies").join("del-sig.json.sig").exists());
    }

    #[test]
    fn list_returns_sorted_by_name() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().to_path_buf();

        save_policy(&test_policy("z-policy", "Zebra"), Some(&vault)).unwrap();
        save_policy(&test_policy("a-policy", "Alpha"), Some(&vault)).unwrap();
        save_policy(&test_policy("m-policy", "Middle"), Some(&vault)).unwrap();

        let policies = list_policies(Some(&vault)).unwrap();
        assert_eq!(policies.len(), 3);
        assert_eq!(policies[0].name, "Alpha");
        assert_eq!(policies[1].name, "Middle");
        assert_eq!(policies[2].name, "Zebra");
    }

    #[test]
    fn delete_removes_file() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().to_path_buf();

        save_policy(&test_policy("del-me", "Delete Me"), Some(&vault)).unwrap();
        assert_eq!(list_policies(Some(&vault)).unwrap().len(), 1);

        delete_policy("del-me", Some(&vault)).unwrap();
        assert_eq!(list_policies(Some(&vault)).unwrap().len(), 0);
    }

    #[test]
    fn load_nonexistent_returns_error() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().to_path_buf();

        let result = load_policy("nope", Some(&vault));
        assert!(result.is_err());
    }

    #[test]
    fn delete_nonexistent_returns_error() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().to_path_buf();

        let result = delete_policy("nope", Some(&vault));
        assert!(result.is_err());
    }

    #[test]
    fn list_empty_vault_returns_empty() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().to_path_buf();

        let policies = list_policies(Some(&vault)).unwrap();
        assert!(policies.is_empty());
    }

    #[test]
    fn save_overwrites_existing_and_re_signs() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().to_path_buf();

        let mut policy = test_policy("overwrite-me", "Version 1");
        save_policy(&policy, Some(&vault)).unwrap();

        policy.name = "Version 2".to_string();
        policy.version = 2;
        save_policy(&policy, Some(&vault)).unwrap();

        let loaded = load_policy("overwrite-me", Some(&vault)).unwrap();
        assert!(loaded.signature_verified, "re-save must refresh the sidecar");
        assert_eq!(loaded.policy.name, "Version 2");
        assert_eq!(loaded.policy.version, 2);
        assert_eq!(list_policies(Some(&vault)).unwrap().len(), 1);
    }

    #[test]
    fn policy_with_executable_roundtrips() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().to_path_buf();

        let policy = Policy {
            id: "sim-policy".to_string(),
            name: "Simulation".to_string(),
            version: 1,
            created_at: "2026-03-22T10:00:00Z".to_string(),
            rules: vec![],
            executable: Some("/usr/local/bin/simulate-tx".to_string()),
            config: Some(serde_json::json!({"rpc": "https://mainnet.base.org"})),
            action: PolicyAction::Deny,
        };

        save_policy(&policy, Some(&vault)).unwrap();
        let loaded = load_policy("sim-policy", Some(&vault)).unwrap();
        assert_eq!(loaded.policy.executable.unwrap(), "/usr/local/bin/simulate-tx");
        assert!(loaded.policy.config.is_some());
    }
}
