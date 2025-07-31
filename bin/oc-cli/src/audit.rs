use std::{
    fs::{self, OpenOptions},
    io::Write,
};

use oc_core::Config;
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
}

/// Append an audit entry to the audit log.
/// Creates the log directory and file if they don't exist.
/// Silently ignores write failures (audit should not break operations).
pub(crate) fn log_audit(entry: &AuditEntry) {
    let config = Config::default();
    let log_dir = config.vault_path.join("logs");
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

/// Generic wallet event logger. All wallet audit helpers delegate here.
pub(crate) fn log_wallet_event(
    wallet_id: &str,
    operation: &str,
    chain_id: Option<&str>,
    address: Option<&str>,
    details: Option<String>,
) {
    log_audit(&AuditEntry {
        timestamp: jiff::Timestamp::now().to_string(),
        wallet_id: wallet_id.to_string(),
        operation: operation.to_string(),
        chain_id: chain_id.map(String::from),
        address: address.map(String::from),
        details,
    });
}

/// Convenience: log a wallet creation event with all accounts.
pub(crate) fn log_wallet_created(info: &oc_wallet::WalletInfo) {
    let details = info
        .accounts
        .iter()
        .map(|a| format!("{}={}", a.chain_id, a.address))
        .collect::<Vec<_>>()
        .join(", ");
    log_wallet_event(&info.id, "create_wallet", None, None, Some(details));
}

/// Convenience: log a wallet import event with all accounts.
pub(crate) fn log_wallet_imported(info: &oc_wallet::WalletInfo) {
    let details = info
        .accounts
        .iter()
        .map(|a| format!("{}={}", a.chain_id, a.address))
        .collect::<Vec<_>>()
        .join(", ");
    log_wallet_event(&info.id, "import_wallet", None, None, Some(details));
}

/// Convenience: log a wallet export event.
pub(crate) fn log_wallet_exported(wallet_id: &str) {
    log_wallet_event(wallet_id, "export_wallet", None, None, None);
}

/// Convenience: log a wallet deletion event.
pub(crate) fn log_wallet_deleted(wallet_id: &str, name: &str) {
    log_wallet_event(wallet_id, "delete_wallet", None, None, Some(format!("name={name}")));
}

/// Convenience: log a wallet rename event.
pub(crate) fn log_wallet_renamed(wallet_id: &str, old_name: &str, new_name: &str) {
    log_wallet_event(
        wallet_id,
        "rename_wallet",
        None,
        None,
        Some(format!("{old_name} -> {new_name}")),
    );
}

/// Convenience: log a broadcast event.
pub(crate) fn log_broadcast(wallet_id: &str, chain_id: &str, tx_hash: &str) {
    log_wallet_event(
        wallet_id,
        "broadcast_transaction",
        Some(chain_id),
        None,
        Some(format!("tx_hash={tx_hash}")),
    );
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
            operation: "create_wallet".to_string(),
            chain_id: None,
            address: None,
            details: Some("test details".to_string()),
        };

        log_audit_at(&entry, vault);

        let log_path = vault.join("logs/audit.jsonl");
        assert!(log_path.exists(), "audit log file should exist");

        let contents = std::fs::read_to_string(&log_path).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(contents.trim()).unwrap();
        assert_eq!(parsed["wallet_id"], "test-wallet-id");
        assert_eq!(parsed["operation"], "create_wallet");
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
                operation: "create_wallet".to_string(),
                chain_id: None,
                address: None,
                details: None,
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
            operation: "broadcast_transaction".to_string(),
            chain_id: Some("eip155:8453".to_string()),
            address: None,
            details: Some("tx_hash=0xabc123".to_string()),
        };
        log_audit_at(&entry, vault);

        let log_path = vault.join("logs/audit.jsonl");
        let contents = std::fs::read_to_string(&log_path).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(contents.trim()).unwrap();
        assert_eq!(parsed["operation"], "broadcast_transaction");
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
            operation: "create_wallet".to_string(),
            chain_id: None,
            address: None,
            details: None,
        };
        log_audit_at(&entry, vault);

        let log_path = vault.join("logs/audit.jsonl");
        let contents = std::fs::read_to_string(&log_path).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(contents.trim()).unwrap();

        // Optional None fields should not be serialized
        assert!(parsed.get("chain_id").is_none());
        assert!(parsed.get("address").is_none());
        assert!(parsed.get("details").is_none());
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
            operation: "create_wallet".to_string(),
            chain_id: None,
            address: None,
            details: None,
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
            operation: "create_wallet".to_string(),
            chain_id: None,
            address: None,
            details: None,
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
}
