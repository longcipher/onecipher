//! Append-only approval log for daemon-restart recovery.
//!
//! Events are stored as JSONL in `~/.onecipher/logs/approval_queue.jsonl`.
//! On startup, unresolved pending approvals are replayed back into the queue.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use tokio::io::AsyncWriteExt;
use uuid::Uuid;

use crate::approval::PendingApproval;

/// A single log event.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum ApprovalLogEvent {
    Pending { id: Uuid, at: u64, approval: Box<PendingApproval> },
    Resolved { id: Uuid, at: u64, decision: String, reason: String },
}

/// Append-only approval log handle.
pub struct ApprovalLog {
    path: PathBuf,
}

impl ApprovalLog {
    /// Open or create the approval log at the given directory.
    ///
    /// Creates `<dir>/logs/approval_queue.jsonl` with mode 0600 if it doesn't exist.
    pub async fn open(state_dir: &Path) -> std::io::Result<Self> {
        let logs_dir = state_dir.join("logs");
        tokio::fs::create_dir_all(&logs_dir).await?;
        let path = logs_dir.join("approval_queue.jsonl");
        // Touch the file with restrictive permissions. This log is append-only,
        // so we must NOT use write-temp-then-rename — replacing the inode would
        // discard prior entries. Instead create at 0600 directly.
        if !path.exists() {
            let mut opts = std::fs::OpenOptions::new();
            opts.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt as _;
                opts.mode(0o600);
            }
            opts.open(&path)?;
        }
        Ok(Self { path })
    }

    /// Append a `pending` event for a new approval.
    pub async fn append_pending(&self, approval: &PendingApproval) -> std::io::Result<()> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let event = ApprovalLogEvent::Pending {
            id: approval.id,
            at: now,
            approval: Box::new(approval.clone()),
        };
        self.append_event(&event).await
    }

    /// Append a `resolved` event.
    pub async fn append_resolved(
        &self,
        id: Uuid,
        decision: &str,
        reason: &str,
    ) -> std::io::Result<()> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let event = ApprovalLogEvent::Resolved {
            id,
            at: now,
            decision: decision.to_string(),
            reason: reason.to_string(),
        };
        self.append_event(&event).await
    }

    /// Replay all unresolved (pending without matching resolved) approvals.
    pub async fn replay_unresolved(&self) -> std::io::Result<Vec<PendingApproval>> {
        let content = tokio::fs::read_to_string(&self.path).await?;
        let mut pending_map: std::collections::HashMap<Uuid, PendingApproval> =
            std::collections::HashMap::new();

        for line in content.lines() {
            if line.trim().is_empty() {
                continue;
            }
            match serde_json::from_str::<ApprovalLogEvent>(line) {
                Ok(ApprovalLogEvent::Pending { id, approval, .. }) => {
                    pending_map.insert(id, *approval);
                }
                Ok(ApprovalLogEvent::Resolved { id, .. }) => {
                    pending_map.remove(&id);
                }
                Err(e) => {
                    tracing::warn!(line = line, error = %e, "skipping malformed log line");
                }
            }
        }

        Ok(pending_map.into_values().collect())
    }

    /// Remove resolved entries older than `days` from the log,
    /// along with their matching pending events.
    pub async fn gc_older_than(&self, days: u64) -> std::io::Result<usize> {
        let content = tokio::fs::read_to_string(&self.path).await?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let cutoff = now.saturating_sub(days * 86_400);

        // First pass: collect IDs of resolved events older than cutoff.
        let mut stale_ids = std::collections::HashSet::new();
        for line in content.lines() {
            if let Ok(ApprovalLogEvent::Resolved { id, at, .. }) =
                serde_json::from_str::<ApprovalLogEvent>(line)
            {
                if at < cutoff {
                    stale_ids.insert(id);
                }
            }
        }

        // Second pass: keep lines whose ID is not in stale set.
        let mut kept_lines = Vec::new();
        let mut removed = 0usize;
        for line in content.lines() {
            if line.trim().is_empty() {
                continue;
            }
            let keep = match serde_json::from_str::<ApprovalLogEvent>(line) {
                Ok(ApprovalLogEvent::Pending { id, .. }) => !stale_ids.contains(&id),
                Ok(ApprovalLogEvent::Resolved { id, .. }) => !stale_ids.contains(&id),
                Err(_) => true,
            };
            if keep {
                kept_lines.push(line);
            } else {
                removed += 1;
            }
        }

        if removed > 0 {
            let mut new_content = kept_lines.join("\n");
            if !new_content.is_empty() {
                new_content.push('\n');
            }
            // Rebuild the file atomically. A torn write during compaction
            // would lose approval records; the old code used `tokio::fs::write`
            // which truncates first.
            let p = self.path.clone();
            tokio::task::spawn_blocking(move || {
                oc_core::paths::write_atomic(
                    &p,
                    new_content.as_bytes(),
                    oc_core::paths::MODE_PRIVATE_FILE,
                )
            })
            .await
            .map_err(std::io::Error::other)??;
        }

        Ok(removed)
    }

    async fn append_event(&self, event: &ApprovalLogEvent) -> std::io::Result<()> {
        let mut line = serde_json::to_string(event).map_err(std::io::Error::other)?;
        line.push('\n');

        let mut file =
            tokio::fs::OpenOptions::new().create(true).append(true).open(&self.path).await?;
        file.write_all(line.as_bytes()).await?;
        file.flush().await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::approval::RiskLevel;

    fn make_approval(id: Uuid) -> PendingApproval {
        PendingApproval {
            id,
            method: "eth_sendTransaction".to_string(),
            params: serde_json::json!({}),
            dapp_name: "test".to_string(),
            dapp_origin: "https://example.com".to_string(),
            chain_id: "eip155:1".to_string(),
            risk: RiskLevel::Safe,
            risk_reasons: vec![],
            simulation: None,
            created_at_unix: 1000,
            expires_at_unix: 1300,
        }
    }

    #[tokio::test]
    async fn test_append_and_replay() {
        let dir = tempfile::tempdir().unwrap();
        let log = ApprovalLog::open(dir.path()).await.unwrap();

        let id1 = Uuid::new_v4();
        let id2 = Uuid::new_v4();

        log.append_pending(&make_approval(id1)).await.unwrap();
        log.append_pending(&make_approval(id2)).await.unwrap();
        log.append_resolved(id1, "approved", "").await.unwrap();

        let unresolved = log.replay_unresolved().await.unwrap();
        assert_eq!(unresolved.len(), 1);
        assert_eq!(unresolved[0].id, id2);
    }

    #[tokio::test]
    async fn test_gc_removes_old_resolved() {
        let dir = tempfile::tempdir().unwrap();
        let log = ApprovalLog::open(dir.path()).await.unwrap();

        let id1 = Uuid::new_v4();
        log.append_pending(&make_approval(id1)).await.unwrap();

        // Manually write an old resolved event
        let old_event = ApprovalLogEvent::Resolved {
            id: id1,
            at: 1, // very old
            decision: "approved".to_string(),
            reason: String::new(),
        };
        let mut line = serde_json::to_string(&old_event).unwrap();
        line.push('\n');
        tokio::fs::write(dir.path().join("logs/approval_queue.jsonl"), line.as_bytes())
            .await
            .unwrap();

        let removed = log.gc_older_than(7).await.unwrap();
        assert_eq!(removed, 1);

        let content =
            tokio::fs::read_to_string(dir.path().join("logs/approval_queue.jsonl")).await.unwrap();
        assert!(content.trim().is_empty());
    }

    #[tokio::test]
    async fn test_replay_with_no_resolved_returns_all_pending() {
        let dir = tempfile::tempdir().unwrap();
        let log = ApprovalLog::open(dir.path()).await.unwrap();

        let id1 = Uuid::new_v4();
        let id2 = Uuid::new_v4();
        log.append_pending(&make_approval(id1)).await.unwrap();
        log.append_pending(&make_approval(id2)).await.unwrap();

        let unresolved = log.replay_unresolved().await.unwrap();
        assert_eq!(unresolved.len(), 2);
    }
}
