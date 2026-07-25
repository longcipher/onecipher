//! Audit log REST endpoint.
//!
//! - `GET /api/audit` — read audit.jsonl with pagination

use axum::{
    Json,
    extract::{Query, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde::Deserialize;

use crate::routes::approvals::AppState;

/// Query parameters for GET /api/audit.
#[derive(Debug, Deserialize)]
pub struct AuditQuery {
    #[serde(default)]
    pub offset: Option<usize>,
    #[serde(default = "default_limit")]
    pub limit: usize,
}

fn default_limit() -> usize {
    50
}

/// GET /api/audit — read audit log entries with pagination.
pub async fn get_audit(
    State(_state): State<AppState>,
    Query(params): Query<AuditQuery>,
) -> impl IntoResponse {
    tracing::debug!(offset = ?params.offset, limit = params.limit, "get_audit called");
    // ponytail: stub, read ~/.onecipher/logs/audit.jsonl later
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "entries": [],
            "total": 0,
            "offset": params.offset.unwrap_or(0),
            "limit": params.limit,
        })),
    )
}

#[cfg(test)]
mod tests {
    use axum::{body::Body, http::Request};
    use tower::ServiceExt;

    use super::*;
    use crate::approval_queue::ApprovalQueue;

    fn test_state() -> AppState {
        AppState { queue: ApprovalQueue::new(16) }
    }

    #[tokio::test]
    async fn test_get_audit_default() {
        let app = axum::Router::new()
            .route("/api/audit", axum::routing::get(get_audit))
            .with_state(test_state());
        let resp = app
            .oneshot(Request::builder().uri("/api/audit").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["limit"], 50);
    }

    #[tokio::test]
    async fn test_get_audit_with_pagination() {
        let app = axum::Router::new()
            .route("/api/audit", axum::routing::get(get_audit))
            .with_state(test_state());
        let resp = app
            .oneshot(
                Request::builder().uri("/api/audit?offset=10&limit=5").body(Body::empty()).unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["offset"], 10);
        assert_eq!(json["limit"], 5);
    }
}
