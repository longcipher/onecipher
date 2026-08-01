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

use crate::{approval_queue::ApprovalQueue, auth::SessionStore};

/// Shared application state for all WebUI routes.
#[derive(Clone)]
pub struct AppState {
    pub queue: ApprovalQueue,
    /// Path to `~/.onecipher/` state directory.
    pub state_dir: PathBuf,
    /// In-memory session store for WebAuthn sessions.
    pub session_store: SessionStore,
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
        Ok(()) => (StatusCode::OK, Json(serde_json::json!({"ok": true}))).into_response(),
        Err(_) => (
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
        body::Body,
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;

    use super::*;

    #[tokio::test]
    async fn test_simulate_returns_null() {
        let queue = ApprovalQueue::new(16);
        let session_store = SessionStore::new(1800);
        let state = AppState { queue, state_dir: std::path::PathBuf::from("/tmp"), session_store };
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
