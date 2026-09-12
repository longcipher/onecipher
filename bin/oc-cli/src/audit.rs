use std::{
    fs::{self, OpenOptions},
    io::Write,
};

use oc_core::{AuditOp, AuditTrack, Config};
use serde::Serialize;

#[derive(Debug, Serialize)]
pub(crate) struct AuditEntry {
    pub timestamp: String,
    pub wallet_id: String,
    pub operation: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chain_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,
    /// Secret entry name for `secret.*` / `password.*` / `totp.*` operations
    /// (`None` for wallet operations, where `wallet_id` is the wallet UUID).
    /// For secret-plane operations `wallet_id` carries the same name so
    /// legacy `wallet_id` filters keep working.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret_name: Option<String>,
}

/// Audit channel (D5 two-track): read-only operations ride the light
/// channel; signing operations ride the strong channel (separate file so a
/// read-heavy workload cannot drown signing evidence).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AuditChannel {
    /// Read-only / listing operations (`audit.jsonl`).
    Light,
    /// Signing / broadcast operations (`audit-strong.jsonl`).
    Strong,
}

impl AuditChannel {
    const fn file_name(self) -> &'static str {
        match self {
            Self::Light => "audit.jsonl",
            Self::Strong => "audit-strong.jsonl",
        }
    }
}

/// Append to a specific audit channel.
pub(crate) fn log_audit_chan(entry: &AuditEntry, channel: AuditChannel) {
    let config = Config::default();
    let log_dir = config.vault_path.join("logs");
    let log_path = log_dir.join(channel.file_name());
    let _ = fs::create_dir_all(&log_dir);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&log_dir, fs::Permissions::from_mode(0o700));
    }
    if let Ok(json) = serde_json::to_string(entry) {
        if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(&log_path) {
            let _ = writeln!(file, "{}", json);
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = fs::set_permissions(&log_path, fs::Permissions::from_mode(0o600));
            }
        }
    }
}

/// Strong-channel logger for signing operations.
pub(crate) fn log_audit_strong(entry: &AuditEntry) {
    log_audit_chan(entry, AuditChannel::Strong);
}

/// Append an audit entry to the audit log.
/// Creates the log directory and file if they don't exist.
/// Silently ignores write failures (audit should not break operations).
pub(crate) fn log_audit(entry: &AuditEntry) {
    log_audit_chan(entry, AuditChannel::Light);
}

/// Generic wallet event logger. All wallet audit helpers delegate here.
///
/// The operation comes from the unified [`AuditOp`] table and the channel
/// from [`AuditOp::track`], so wallet, secret, password and TOTP events share
/// one taxonomy over the two tracks.
pub(crate) fn log_wallet_event(
    wallet_id: &str,
    op: AuditOp,
    chain_id: Option<&str>,
    address: Option<&str>,
    details: Option<String>,
) {
    let entry = AuditEntry {
        timestamp: jiff::Timestamp::now().to_string(),
        wallet_id: wallet_id.to_string(),
        operation: op.as_str().to_string(),
        chain_id: chain_id.map(String::from),
        address: address.map(String::from),
        details,
        secret_name: None,
    };
    match op.track() {
        AuditTrack::Light => log_audit(&entry),
        AuditTrack::Strong => log_audit_strong(&entry),
    }
}

/// Generic secret-plane event logger (`secret.*` / `password.*` / `totp.*`).
///
/// `wallet_id` carries the secret name (legacy filters keep working) and
/// `secret_name` is set explicitly. Disclosure reads (`secret.read`,
/// `password.read`, `totp.generate`, …) never include secret material — only
/// the name and the dotted op.
pub(crate) fn log_secret_event(op: AuditOp, name: &str, details: Option<String>) {
    let entry = AuditEntry {
        timestamp: jiff::Timestamp::now().to_string(),
        wallet_id: name.to_string(),
        operation: op.as_str().to_string(),
        chain_id: None,
        address: None,
        details,
        secret_name: Some(name.to_string()),
    };
    match op.track() {
        AuditTrack::Light => log_audit(&entry),
        AuditTrack::Strong => log_audit_strong(&entry),
    }
}

/// Convenience: log a wallet creation event with all accounts.
pub(crate) fn log_wallet_created(info: &oc_wallet::WalletInfo) {
    let details = info
        .accounts
        .iter()
        .map(|a| format!("{}={}", a.chain_id, a.address))
        .collect::<Vec<_>>()
        .join(", ");
    log_wallet_event(&info.id, AuditOp::WalletCreate, None, None, Some(details));
}

/// Convenience: log a wallet import event with all accounts.
pub(crate) fn log_wallet_imported(info: &oc_wallet::WalletInfo) {
    let details = info
        .accounts
        .iter()
        .map(|a| format!("{}={}", a.chain_id, a.address))
        .collect::<Vec<_>>()
        .join(", ");
    log_wallet_event(&info.id, AuditOp::WalletImport, None, None, Some(details));
}

/// Convenience: log a wallet export event.
pub(crate) fn log_wallet_exported(wallet_id: &str) {
    log_wallet_event(wallet_id, AuditOp::WalletExport, None, None, None);
}

/// Convenience: log a wallet deletion event.
pub(crate) fn log_wallet_deleted(wallet_id: &str, name: &str) {
    log_wallet_event(wallet_id, AuditOp::WalletDelete, None, None, Some(format!("name={name}")));
}

/// Convenience: log a wallet rename event.
pub(crate) fn log_wallet_renamed(wallet_id: &str, old_name: &str, new_name: &str) {
    log_wallet_event(
        wallet_id,
        AuditOp::WalletRename,
        None,
        None,
        Some(format!("{old_name} -> {new_name}")),
    );
}

/// Convenience: log a broadcast event.
pub(crate) fn log_broadcast(wallet_id: &str, chain_id: &str, tx_hash: &str) {
    // Signing operations ride the strong channel (D5 two-track).
    log_audit_strong(&AuditEntry {
        timestamp: jiff::Timestamp::now().to_string(),
        wallet_id: wallet_id.to_string(),
        operation: AuditOp::WalletBroadcast.as_str().to_string(),
        chain_id: Some(chain_id.to_string()),
        address: None,
        details: Some(format!("tx_hash={tx_hash}")),
        secret_name: None,
    });
}

/// Append an audit entry to the audit log at a specific vault path.
/// Like `log_audit` but allows specifying the vault directory (for testing).
#[cfg(test)]
pub(crate) fn log_audit_at(entry: &AuditEntry, vault_path: &std::path::Path) {
    let log_dir = vault_path.join("logs");
    let log_path = log_dir.join("audit.jsonl");

    let _ = fs::create_dir_all(&log_dir);

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&log_dir, fs::Permissions::from_mode(0o700));
    }

    if let Ok(json) = serde_json::to_string(entry) {
        if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(&log_path) {
            let _ = writeln!(file, "{}", json);

            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = fs::set_permissions(&log_path, fs::Permissions::from_mode(0o600));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::BufRead;

    use super::*;

    #[test]
    fn char_audit_entry_written_to_file() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path();

        let entry = AuditEntry {
            timestamp: "2026-03-22T10:00:00Z".to_string(),
            wallet_id: "test-wallet-id".to_string(),
            operation: AuditOp::WalletCreate.as_str().to_string(),
            chain_id: None,
            address: None,
            details: Some("test details".to_string()),
            secret_name: None,
        };

        log_audit_at(&entry, vault);

        let log_path = vault.join("logs/audit.jsonl");
        assert!(log_path.exists(), "audit log file should exist");

        let contents = std::fs::read_to_string(&log_path).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(contents.trim()).unwrap();
        assert_eq!(parsed["wallet_id"], "test-wallet-id");
        assert_eq!(parsed["operation"], "wallet.create");
        assert_eq!(parsed["details"], "test details");
        assert_eq!(parsed["timestamp"], "2026-03-22T10:00:00Z");
    }

    #[test]
    fn char_audit_multiple_entries_appended() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path();

        for i in 0..3 {
            let entry = AuditEntry {
                timestamp: format!("2026-03-22T10:0{}:00Z", i),
                wallet_id: format!("wallet-{i}"),
                operation: AuditOp::WalletCreate.as_str().to_string(),
                chain_id: None,
                address: None,
                details: None,
                secret_name: None,
            };
            log_audit_at(&entry, vault);
        }

        let log_path = vault.join("logs/audit.jsonl");
        let file = std::fs::File::open(&log_path).unwrap();
        let lines: Vec<String> =
            std::io::BufReader::new(file).lines().collect::<Result<Vec<_>, _>>().unwrap();
        assert_eq!(lines.len(), 3, "should have 3 audit entries");

        // Verify each line is valid JSON
        for (i, line) in lines.iter().enumerate() {
            let parsed: serde_json::Value = serde_json::from_str(line).unwrap();
            assert_eq!(parsed["wallet_id"], format!("wallet-{i}"));
        }
    }

    #[test]
    fn char_audit_broadcast_entry() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path();

        let entry = AuditEntry {
            timestamp: jiff::Timestamp::now().to_string(),
            wallet_id: "bc-wallet".to_string(),
            operation: AuditOp::WalletBroadcast.as_str().to_string(),
            chain_id: Some("eip155:8453".to_string()),
            address: None,
            details: Some("tx_hash=0xabc123".to_string()),
            secret_name: None,
        };
        log_audit_at(&entry, vault);

        let log_path = vault.join("logs/audit.jsonl");
        let contents = std::fs::read_to_string(&log_path).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(contents.trim()).unwrap();
        assert_eq!(parsed["operation"], "wallet.broadcast");
        assert_eq!(parsed["chain_id"], "eip155:8453");
        assert!(parsed["details"].as_str().unwrap().contains("tx_hash=0xabc123"));
    }

    #[test]
    fn char_audit_entry_skips_none_fields() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path();

        let entry = AuditEntry {
            timestamp: "2026-03-22T10:00:00Z".to_string(),
            wallet_id: "w1".to_string(),
            operation: AuditOp::WalletCreate.as_str().to_string(),
            chain_id: None,
            address: None,
            details: None,
            secret_name: None,
        };
        log_audit_at(&entry, vault);

        let log_path = vault.join("logs/audit.jsonl");
        let contents = std::fs::read_to_string(&log_path).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(contents.trim()).unwrap();

        // Optional None fields should not be serialized
        assert!(parsed.get("chain_id").is_none());
        assert!(parsed.get("address").is_none());
        assert!(parsed.get("details").is_none());
        assert!(parsed.get("secret_name").is_none());
    }

    #[cfg(unix)]
    #[test]
    fn char_audit_read_only_dir_does_not_panic() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path();

        // Create logs dir as read-only
        let log_dir = vault.join("logs");
        std::fs::create_dir_all(&log_dir).unwrap();
        std::fs::set_permissions(&log_dir, std::fs::Permissions::from_mode(0o000)).unwrap();

        let entry = AuditEntry {
            timestamp: "2026-03-22T10:00:00Z".to_string(),
            wallet_id: "w1".to_string(),
            operation: AuditOp::WalletCreate.as_str().to_string(),
            chain_id: None,
            address: None,
            details: None,
            secret_name: None,
        };

        // This should not panic — audit failures are silently ignored
        log_audit_at(&entry, vault);

        // Restore permissions for cleanup
        std::fs::set_permissions(&log_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn char_audit_log_file_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path();

        let entry = AuditEntry {
            timestamp: "2026-03-22T10:00:00Z".to_string(),
            wallet_id: "w1".to_string(),
            operation: AuditOp::WalletCreate.as_str().to_string(),
            chain_id: None,
            address: None,
            details: None,
            secret_name: None,
        };
        log_audit_at(&entry, vault);

        let log_path = vault.join("logs/audit.jsonl");
        let meta = std::fs::metadata(&log_path).unwrap();
        let mode = meta.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "audit log file should have 0600 permissions, got {:04o}", mode);

        let log_dir = vault.join("logs");
        let dir_meta = std::fs::metadata(&log_dir).unwrap();
        let dir_mode = dir_meta.permissions().mode() & 0o777;
        assert_eq!(
            dir_mode, 0o700,
            "logs directory should have 0700 permissions, got {:04o}",
            dir_mode
        );
    }

    #[test]
    fn char_audit_two_tracks_split_light_and_strong() {
        // D5: read-only entries ride the light channel (`audit.jsonl`),
        // signing entries ride the strong channel (`audit-strong.jsonl`).
        let _home = crate::test_util::HomeGuard::new();
        let vault = oc_core::Config::default().vault_path;

        let read = AuditEntry {
            timestamp: "2026-03-22T10:00:00Z".to_string(),
            wallet_id: "w1".to_string(),
            operation: AuditOp::SecretRead.as_str().to_string(),
            chain_id: None,
            address: None,
            details: None,
            secret_name: None,
        };
        log_audit(&read);
        log_broadcast("w1", "eip155:8453", "0xabc");

        let light = std::fs::read_to_string(vault.join("logs/audit.jsonl")).unwrap();
        let strong = std::fs::read_to_string(vault.join("logs/audit-strong.jsonl")).unwrap();
        assert!(light.contains("secret.read"), "light channel must hold reads");
        assert!(!light.contains("wallet.broadcast"), "light must not hold signing");
        assert!(strong.contains("wallet.broadcast"), "strong channel must hold signing");
        assert!(!strong.contains("secret.read"), "strong must not hold reads");
    }

    #[test]
    fn unified_secret_event_uses_dotted_op_and_light_track() {
        // Secret-plane events share the AuditOp taxonomy and ride light.
        let _home = crate::test_util::HomeGuard::new();
        let vault = oc_core::Config::default().vault_path;

        log_secret_event(AuditOp::TotpGenerate, "github-2fa", None);
        log_secret_event(AuditOp::SecretCreate, "notes/todo", None);

        let light = std::fs::read_to_string(vault.join("logs/audit.jsonl")).unwrap();
        assert!(light.contains("totp.generate"), "got: {light}");
        assert!(light.contains("secret.create"), "got: {light}");
        assert!(light.contains("github-2fa"), "got: {light}");
    }
}
