//! Approval channel types for the Web UI signing flow.
//!
//! The shared data types (`PendingApproval`, `ApprovalDecision`, `RiskLevel`, etc.)
//! live in `oc-core::approval` to avoid forcing `oc-webui` to depend on
//! `oc-netagent` (which pulls in `hpx`/`boring`).
//!
//! This module provides the `ApprovalChannel` async wrapper that bridges the
//! WC method router (sender side) and the Web UI approval queue (receiver side).

use std::time::Duration;

// Re-export core types for ergonomic use within oc-netagent.
pub use oc_core::approval::{
    ApprovalDecision, DecodedAction, PendingApproval, RiskLevel, RiskReason, RiskSource,
    TokenDelta, TokenDirection, TxSimulation,
};
use tokio::sync::{mpsc, oneshot};

// ---------------------------------------------------------------------------
// ApprovalChannel
// ---------------------------------------------------------------------------

/// Channel for routing pending approvals from `WcMethodRouter` to the Web UI.
///
/// The sender side lives in the router; the receiver side lives in the
/// `ApprovalQueue` (within `oc-webui`).
#[derive(Clone)]
pub struct ApprovalChannel {
    tx: mpsc::Sender<(PendingApproval, oneshot::Sender<ApprovalDecision>)>,
}

impl ApprovalChannel {
    /// Create a new approval channel with the given buffer capacity.
    pub fn new(
        capacity: usize,
    ) -> (Self, mpsc::Receiver<(PendingApproval, oneshot::Sender<ApprovalDecision>)>) {
        let (tx, rx) = mpsc::channel(capacity);
        (Self { tx }, rx)
    }

    /// Submit a pending approval and wait for the user's decision (or timeout).
    pub async fn request(&self, approval: PendingApproval, timeout: Duration) -> ApprovalDecision {
        let (resp_tx, resp_rx) = oneshot::channel();
        if self.tx.send((approval, resp_tx)).await.is_err() {
            // Receiver dropped — treat as timeout
            return ApprovalDecision::Timeout;
        }
        match tokio::time::timeout(timeout, resp_rx).await {
            Ok(Ok(decision)) => decision,
            Ok(Err(_)) => ApprovalDecision::Timeout, // oneshot sender dropped
            Err(_) => ApprovalDecision::Timeout,     // timeout elapsed
        }
    }
}

impl std::fmt::Debug for ApprovalChannel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApprovalChannel").finish_non_exhaustive()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use uuid::Uuid;

    use super::*;

    #[tokio::test]
    async fn test_approval_channel_approve() {
        let (channel, mut rx) = ApprovalChannel::new(16);
        let approval = PendingApproval {
            id: Uuid::new_v4(),
            method: "personal_sign".to_string(),
            params: serde_json::json!({}),
            dapp_name: "test".to_string(),
            dapp_origin: "https://example.com".to_string(),
            chain_id: "eip155:1".to_string(),
            risk: RiskLevel::Safe,
            risk_reasons: vec![],
            simulation: None,
            created_at_unix: 1000,
            expires_at_unix: 1300,
        };

        let handle =
            tokio::spawn(async move { channel.request(approval, Duration::from_secs(5)).await });

        let (pending, resp_tx) = rx.recv().await.unwrap();
        assert_eq!(pending.method, "personal_sign");
        resp_tx.send(ApprovalDecision::Approve).unwrap();

        let decision = handle.await.unwrap();
        assert_eq!(decision, ApprovalDecision::Approve);
    }

    #[tokio::test]
    async fn test_approval_channel_timeout() {
        let (channel, _rx) = ApprovalChannel::new(16);
        let approval = PendingApproval {
            id: Uuid::new_v4(),
            method: "eth_sendTransaction".to_string(),
            params: serde_json::json!({}),
            dapp_name: "test".to_string(),
            dapp_origin: "https://example.com".to_string(),
            chain_id: "eip155:1".to_string(),
            risk: RiskLevel::Safe,
            risk_reasons: vec![],
            simulation: None,
            created_at_unix: 1000,
            expires_at_unix: 1001,
        };

        // Timeout immediately (1ms)
        let decision = channel.request(approval, Duration::from_millis(1)).await;
        assert_eq!(decision, ApprovalDecision::Timeout);
    }

    #[test]
    fn test_pending_approval_serde_roundtrip() {
        let approval = PendingApproval {
            id: Uuid::new_v4(),
            method: "eth_sendTransaction".to_string(),
            params: serde_json::json!({"to": "0x123"}),
            dapp_name: "Uniswap".to_string(),
            dapp_origin: "https://app.uniswap.org".to_string(),
            chain_id: "eip155:1".to_string(),
            risk: RiskLevel::Warning,
            risk_reasons: vec![RiskReason {
                code: "policy_warn_large_approval".to_string(),
                level: RiskLevel::Warning,
                message: "Large amount".to_string(),
                source: RiskSource::Policy,
                detail: None,
            }],
            simulation: Some(TxSimulation {
                success: true,
                gas_used: 142500,
                balance_change: vec![TokenDelta {
                    token: "USDC".to_string(),
                    direction: TokenDirection::Send,
                    amount: "100".to_string(),
                }],
                decoded_action: None,
                error: None,
            }),
            created_at_unix: 1000,
            expires_at_unix: 1300,
        };
        let json = serde_json::to_string(&approval).unwrap();
        let parsed: PendingApproval = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.id, approval.id);
        assert_eq!(parsed.risk, RiskLevel::Warning);
        assert_eq!(parsed.risk_reasons.len(), 1);
    }
}
