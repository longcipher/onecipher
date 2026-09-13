//! Approval queue: receives pending approvals from the netagent via mpsc,
//! stores them in a DashMap, exposes REST endpoints, and broadcasts via WebSocket.

use std::sync::Arc;

use dashmap::DashMap;
use oc_core::{
    approval::{ApprovalDecision, PendingApproval},
    approval_log::ApprovalLog,
};
use tokio::sync::{broadcast, mpsc, oneshot};
use uuid::Uuid;

/// Error returned when submitting a decision fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolveError {
    /// The approval was already resolved (or never existed) — 409 Conflict.
    AlreadyResolved,
    /// The approval's TTL elapsed before a decision arrived — 410 Gone.
    ApprovalExpired,
}

impl std::fmt::Display for ResolveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::AlreadyResolved => "approval already resolved",
            Self::ApprovalExpired => "approval expired",
        })
    }
}

impl std::error::Error for ResolveError {}

/// Outcome of a successful decision submission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolveOutcome {
    /// The decision was forwarded to the original requester (which will sign).
    Delivered,
    /// The entry was a replayed orphan with no requester attached — the
    /// decision cleared the queue but nothing was signed.
    Stale,
}

/// WebSocket event broadcast to connected clients.
#[derive(Debug, Clone, serde::Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum WsEvent {
    PendingApproval { approval: Box<PendingApproval> },
    ApprovalResolved { id: Uuid, decision: ApprovalDecision },
}

/// Current unix time in seconds (0 if the clock is before the epoch).
fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default()
}

/// Entry in the pending approvals map.
struct QueueEntry {
    approval: PendingApproval,
    resp_tx: Option<oneshot::Sender<ApprovalDecision>>,
}

/// The approval queue that bridges incoming signing requests and the Web UI.
#[derive(Clone)]
pub struct ApprovalQueue {
    /// Pending approvals by ID.
    pending: Arc<DashMap<Uuid, QueueEntry>>,
    /// Broadcast channel for WebSocket events.
    ws_tx: broadcast::Sender<WsEvent>,
    /// Optional persistent log for crash recovery (JSONL WAL).
    log: Option<Arc<ApprovalLog>>,
}

impl ApprovalQueue {
    /// Create a new approval queue.
    ///
    /// `ws_capacity` sets the broadcast channel buffer size.
    pub fn new(ws_capacity: usize) -> Self {
        let (ws_tx, _) = broadcast::channel(ws_capacity);
        Self { pending: Arc::new(DashMap::new()), ws_tx, log: None }
    }

    /// Create a new approval queue with a persistent approval log.
    ///
    /// Pending approvals are appended to the log on insert and resolved
    /// events on resolve, enabling daemon-restart recovery.
    pub fn with_log(ws_capacity: usize, log: Arc<ApprovalLog>) -> Self {
        let (ws_tx, _) = broadcast::channel(ws_capacity);
        Self { pending: Arc::new(DashMap::new()), ws_tx, log: Some(log) }
    }

    /// Subscribe to WebSocket events (for new WS connections).
    pub fn subscribe(&self) -> broadcast::Receiver<WsEvent> {
        self.ws_tx.subscribe()
    }

    /// Get a list of all currently pending approvals.
    pub fn list_pending(&self) -> Vec<PendingApproval> {
        self.pending.iter().map(|entry| entry.value().approval.clone()).collect()
    }

    /// Get a single pending approval by ID.
    pub fn get_pending(&self, id: &Uuid) -> Option<PendingApproval> {
        self.pending.get(id).map(|entry| entry.value().approval.clone())
    }

    /// Submit a decision for a pending approval.
    ///
    /// Expiry is checked first: a decision arriving after
    /// `expires_at_unix` is rejected with [`ResolveError::ApprovalExpired`]
    /// and the entry is removed (the requester is told the request timed out).
    ///
    /// Returns the outcome on success, or [`ResolveError::AlreadyResolved`]
    /// if the approval was already resolved or never existed.
    pub fn resolve(
        &self,
        id: Uuid,
        decision: ApprovalDecision,
    ) -> Result<ResolveOutcome, ResolveError> {
        let Some((_, mut entry)) = self.pending.remove(&id) else {
            return Err(ResolveError::AlreadyResolved);
        };

        // Fail closed: a late decision on an expired approval must never
        // reach the signer. The requester learns nothing was signed.
        if unix_now() >= entry.approval.expires_at_unix {
            if let Some(tx) = entry.resp_tx.take() {
                let _ = tx.send(ApprovalDecision::Timeout);
            }
            self.record_resolution(id, &ApprovalDecision::Timeout);
            return Err(ResolveError::ApprovalExpired);
        }

        let outcome = match entry.resp_tx.take() {
            Some(tx) => {
                let _ = tx.send(decision.clone());
                ResolveOutcome::Delivered
            }
            // Replayed orphan: no response channel exists, so the decision
            // only cleared the queue — nothing was signed.
            None => ResolveOutcome::Stale,
        };
        self.record_resolution(id, &decision);
        Ok(outcome)
    }

    /// Broadcast the resolved event and persist it for crash recovery.
    fn record_resolution(&self, id: Uuid, decision: &ApprovalDecision) {
        let _ = self.ws_tx.send(WsEvent::ApprovalResolved { id, decision: decision.clone() });
        if let Some(log) = &self.log {
            let (decision_str, reason) = match decision {
                ApprovalDecision::Approve => ("approved", String::new()),
                ApprovalDecision::Reject { reason } => ("rejected", reason.clone()),
                ApprovalDecision::Timeout => ("timeout", String::new()),
            };
            if let Err(e) = log.append_resolved(id, decision_str, &reason) {
                tracing::warn!(error = %e, "failed to log resolved approval");
            }
        }
    }

    /// Insert a pending approval (called by the background receiver task;
    /// `pub(crate)` so route-level tests can seed the queue directly).
    pub(crate) fn insert(
        &self,
        approval: PendingApproval,
        resp_tx: oneshot::Sender<ApprovalDecision>,
    ) {
        let id = approval.id;
        // Broadcast pending event
        let _ = self.ws_tx.send(WsEvent::PendingApproval { approval: Box::new(approval.clone()) });
        // Persist the pending approval for crash recovery.
        if let Some(log) = &self.log {
            if let Err(e) = log.append_pending(&approval) {
                tracing::warn!(error = %e, "failed to log pending approval");
            }
        }
        self.pending.insert(id, QueueEntry { approval, resp_tx: Some(resp_tx) });
    }

    /// Spawn a background task that drains the approval receiver channel
    /// and inserts items into this queue.
    pub fn spawn_receiver(
        &self,
        mut rx: mpsc::Receiver<(PendingApproval, oneshot::Sender<ApprovalDecision>)>,
    ) -> tokio::task::JoinHandle<()> {
        let queue = self.clone();
        tokio::spawn(async move {
            while let Some((approval, resp_tx)) = rx.recv().await {
                tracing::info!(id = %approval.id, method = %approval.method, "queuing approval");
                queue.insert(approval, resp_tx);
            }
            tracing::info!("approval receiver channel closed");
        })
    }

    /// Re-queue approvals replayed from the approval log on startup.
    ///
    /// These are "orphaned" approvals that have no response channel — they'll
    /// be displayed to the user but cannot send a response back to a WC request
    /// (the WC connection is gone). The user can still "reject" them to clear the queue.
    pub fn replay_orphans(&self, approvals: Vec<PendingApproval>) {
        for approval in approvals {
            let id = approval.id;
            let _ =
                self.ws_tx.send(WsEvent::PendingApproval { approval: Box::new(approval.clone()) });
            self.pending.insert(
                id,
                QueueEntry {
                    approval,
                    resp_tx: None, // No response channel for replayed orphans
                },
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_approval(id: Uuid) -> PendingApproval {
        PendingApproval {
            id,
            method: "eth_sendTransaction".to_string(),
            params: serde_json::json!({}),
            dapp_name: "TestDApp".to_string(),
            dapp_origin: "https://example.com".to_string(),
            chain_id: "eip155:1".to_string(),
            risk: oc_core::RiskLevel::Safe,
            risk_reasons: vec![],
            simulation: None,
            siwx_summary: None,
            created_at_unix: unix_now(),
            expires_at_unix: unix_now() + 3600,
        }
    }

    /// An approval whose TTL has already elapsed.
    fn expired_approval(id: Uuid) -> PendingApproval {
        PendingApproval { expires_at_unix: 0, ..make_approval(id) }
    }

    #[tokio::test]
    async fn insert_and_list() {
        let queue = ApprovalQueue::new(16);
        let id = Uuid::new_v4();
        let (tx, _rx) = oneshot::channel();
        queue.insert(make_approval(id), tx);

        let list = queue.list_pending();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].id, id);
    }

    #[tokio::test]
    async fn resolve_removes_from_pending() {
        let queue = ApprovalQueue::new(16);
        let id = Uuid::new_v4();
        let (tx, rx) = oneshot::channel();
        queue.insert(make_approval(id), tx);

        let result = queue.resolve(id, ApprovalDecision::Approve);
        assert!(result.is_ok());
        assert!(queue.list_pending().is_empty());

        // The oneshot receiver should get the decision
        let decision = rx.await.unwrap();
        assert_eq!(decision, ApprovalDecision::Approve);
    }

    #[tokio::test]
    async fn double_resolve_returns_conflict() {
        let queue = ApprovalQueue::new(16);
        let id = Uuid::new_v4();
        let (tx, _rx) = oneshot::channel();
        queue.insert(make_approval(id), tx);

        let first = queue.resolve(id, ApprovalDecision::Approve);
        assert!(first.is_ok());

        let second = queue.resolve(id, ApprovalDecision::Reject { reason: "late".into() });
        assert_eq!(second, Err(ResolveError::AlreadyResolved));
    }

    #[tokio::test]
    async fn approve_after_expiry_is_rejected_and_removed() {
        let queue = ApprovalQueue::new(16);
        let id = Uuid::new_v4();
        let (tx, rx) = oneshot::channel();
        queue.insert(expired_approval(id), tx);

        let result = queue.resolve(id, ApprovalDecision::Approve);
        assert_eq!(result, Err(ResolveError::ApprovalExpired));
        // The expired entry is removed from the queue...
        assert!(queue.list_pending().is_empty());
        // ...and the requester learns that nothing was signed.
        assert_eq!(rx.await.unwrap(), ApprovalDecision::Timeout);
    }

    #[tokio::test]
    async fn orphan_approve_reports_stale() {
        let queue = ApprovalQueue::new(16);
        let id = Uuid::new_v4();
        queue.replay_orphans(vec![make_approval(id)]);

        // Approving an orphan clears the queue but signs nothing.
        let outcome = queue.resolve(id, ApprovalDecision::Approve).unwrap();
        assert_eq!(outcome, ResolveOutcome::Stale);
        assert!(queue.list_pending().is_empty());
    }

    #[tokio::test]
    async fn ws_broadcast_on_insert_and_resolve() {
        let queue = ApprovalQueue::new(16);
        let mut sub = queue.subscribe();

        let id = Uuid::new_v4();
        let (tx, _rx) = oneshot::channel();
        queue.insert(make_approval(id), tx);

        // Should receive pending event
        let event = sub.recv().await.unwrap();
        match event {
            WsEvent::PendingApproval { approval } => assert_eq!(approval.id, id),
            _ => panic!("expected PendingApproval event"),
        }

        queue.resolve(id, ApprovalDecision::Approve).unwrap();

        // Should receive resolved event
        let event = sub.recv().await.unwrap();
        match event {
            WsEvent::ApprovalResolved { id: resolved_id, .. } => assert_eq!(resolved_id, id),
            _ => panic!("expected ApprovalResolved event"),
        }
    }

    #[tokio::test]
    async fn spawn_receiver_drains_channel() {
        let queue = ApprovalQueue::new(16);
        let (tx, rx) = mpsc::channel(16);
        let _handle = queue.spawn_receiver(rx);

        let id = Uuid::new_v4();
        let (resp_tx, _resp_rx) = oneshot::channel();
        tx.send((make_approval(id), resp_tx)).await.unwrap();

        // Give the background task time to process
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let list = queue.list_pending();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].id, id);
    }

    #[test]
    fn replay_orphans_returns_listed_pending() {
        let queue = ApprovalQueue::new(16);
        let id = Uuid::new_v4();
        queue.replay_orphans(vec![make_approval(id)]);

        let list = queue.list_pending();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].id, id);

        // A replayed orphan (no response channel) can still be rejected to
        // clear the queue.
        let result = queue.resolve(id, ApprovalDecision::Reject { reason: "cleared".into() });
        assert!(result.is_ok());
        assert!(queue.list_pending().is_empty());
    }
}
