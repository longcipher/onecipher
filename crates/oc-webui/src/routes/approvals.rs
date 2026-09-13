//! Approval REST endpoints.
//!
//! - `GET  /api/approvals`              — list pending
//! - `GET  /api/approvals/:id`          — get single pending
//! - `POST /api/approvals/:id/decision`  — submit approval decision
//! - `POST /api/approvals/:id/simulate` — simulate tx (W2 placeholder, always null)
//! - `GET  /api/approvals/history`       — placeholder for resolved log

use std::path::PathBuf;

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use oc_core::approval::ApprovalDecision;
use serde::Deserialize;
use uuid::Uuid;

use crate::{
    approval_queue::{ApprovalQueue, ResolveError, ResolveOutcome},
    auth::SessionStore,
};

/// Shared application state for all WebUI routes.
#[derive(Clone)]
pub struct AppState {
    pub queue: ApprovalQueue,
    /// Path to `~/.onecipher/` state directory.
    pub state_dir: PathBuf,
    /// In-memory session store for WebAuthn sessions.
    pub session_store: SessionStore,
    /// Sender for injecting WC pairing URIs into the daemon's wallet server.
    pub pairing_tx: tokio::sync::mpsc::Sender<oc_walletconnect::PairingUri>,
}

/// List all pending approvals.
pub async fn list_approvals(State(state): State<AppState>) -> impl IntoResponse {
    let approvals = state.queue.list_pending();
    Json(serde_json::json!({ "approvals": approvals }))
}

/// Get a single pending approval by ID.
pub async fn get_approval(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> impl IntoResponse {
    match state.queue.get_pending(&id) {
        Some(approval) => (StatusCode::OK, Json(serde_json::json!(approval))).into_response(),
        None => {
            (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "not found"}))).into_response()
        }
    }
}

/// Request body for submitting a decision.
#[derive(Debug, Deserialize)]
pub struct DecisionRequest {
    pub decision: DecisionType,
    #[serde(default)]
    pub reason: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DecisionType {
    Approve,
    Reject,
}

/// Submit a decision for a pending approval.
pub async fn submit_decision(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Json(body): Json<DecisionRequest>,
) -> impl IntoResponse {
    let decision = match body.decision {
        DecisionType::Approve => ApprovalDecision::Approve,
        DecisionType::Reject => ApprovalDecision::Reject { reason: body.reason },
    };

    match state.queue.resolve(id, decision) {
        Ok(ResolveOutcome::Delivered) => {
            (StatusCode::OK, Json(serde_json::json!({"ok": true}))).into_response()
        }
        // Replayed orphan: the queue entry was cleared but nothing was signed.
        Ok(ResolveOutcome::Stale) => {
            (StatusCode::OK, Json(serde_json::json!({"ok": false, "reason": "stale"})))
                .into_response()
        }
        // The approval's TTL elapsed before a decision arrived.
        Err(ResolveError::ApprovalExpired) => {
            (StatusCode::GONE, Json(serde_json::json!({"error": "approval expired"})))
                .into_response()
        }
        Err(ResolveError::AlreadyResolved) => (
            StatusCode::CONFLICT,
            Json(serde_json::json!({"error": "already resolved or not found"})),
        )
            .into_response(),
    }
}

/// Placeholder for approval history endpoint.
pub async fn approval_history() -> impl IntoResponse {
    Json(serde_json::json!({ "history": [] }))
}

/// Simulate a pending approval's transaction.
///
/// W2 placeholder — always returns `null` simulation. The real implementation
/// lands in W3.
pub async fn simulate_approval(
    State(_state): State<AppState>,
    Path(_id): Path<Uuid>,
) -> impl IntoResponse {
    Json(serde_json::json!({ "simulation": null }))
}

#[cfg(test)]
mod tests {
    use axum::{
        Router,
        body::Body,
        http::{Request, StatusCode},
    };
    use oc_core::approval::PendingApproval;
    use tower::ServiceExt;

    use super::*;

    fn test_state(queue: ApprovalQueue) -> AppState {
        let session_store = SessionStore::new(1800);
        let (pairing_tx, _pairing_rx) = tokio::sync::mpsc::channel(8);
        AppState { queue, state_dir: std::path::PathBuf::from("/tmp"), session_store, pairing_tx }
    }

    fn decision_app(state: AppState) -> Router {
        Router::new()
            .route("/api/approvals/{id}/decision", axum::routing::post(submit_decision))
            .with_state(state)
    }

    fn live_approval(id: Uuid) -> PendingApproval {
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
            created_at_unix: 0,
            expires_at_unix: u64::MAX,
        }
    }

    fn expired_approval(id: Uuid) -> PendingApproval {
        PendingApproval { expires_at_unix: 0, ..live_approval(id) }
    }

    async fn post_decision(app: Router, id: Uuid, body: &str) -> axum::response::Response {
        app.oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/approvals/{id}/decision"))
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn decision_on_expired_approval_returns_gone() {
        let queue = ApprovalQueue::new(16);
        let id = Uuid::new_v4();
        let (tx, _rx) = tokio::sync::oneshot::channel();
        queue.insert(expired_approval(id), tx);

        let resp =
            post_decision(decision_app(test_state(queue)), id, r#"{"decision":"approve"}"#).await;
        assert_eq!(resp.status(), StatusCode::GONE);
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json["error"], "approval expired");
    }

    #[tokio::test]
    async fn double_resolve_still_conflicts() {
        let queue = ApprovalQueue::new(16);
        let id = Uuid::new_v4();
        let (tx, _rx) = tokio::sync::oneshot::channel();
        queue.insert(live_approval(id), tx);
        let app = decision_app(test_state(queue));

        let first = post_decision(app.clone(), id, r#"{"decision":"approve"}"#).await;
        assert_eq!(first.status(), StatusCode::OK);

        let second = post_decision(app, id, r#"{"decision":"reject","reason":"late"}"#).await;
        assert_eq!(second.status(), StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn orphan_approve_returns_ok_false_stale() {
        let queue = ApprovalQueue::new(16);
        let id = Uuid::new_v4();
        // Replayed orphan: no response channel attached.
        queue.replay_orphans(vec![live_approval(id)]);

        let resp =
            post_decision(decision_app(test_state(queue)), id, r#"{"decision":"approve"}"#).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json["ok"], false);
        assert_eq!(json["reason"], "stale");
    }

    #[tokio::test]
    async fn test_simulate_returns_null() {
        let queue = ApprovalQueue::new(16);
        let session_store = SessionStore::new(1800);
        let (pairing_tx, _pairing_rx) = tokio::sync::mpsc::channel(8);
        let state = AppState {
            queue,
            state_dir: std::path::PathBuf::from("/tmp"),
            session_store,
            pairing_tx,
        };
        let app = axum::Router::new()
            .route("/api/approvals/{id}/simulate", axum::routing::post(simulate_approval))
            .with_state(state);

        let id = Uuid::new_v4();
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/api/approvals/{id}/simulate"))
                    .header("content-type", "application/json")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(json["simulation"].is_null());
    }
}
