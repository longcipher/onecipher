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
    State(state): State<AppState>,
    Query(params): Query<AuditQuery>,
) -> impl IntoResponse {
    tracing::debug!(offset = ?params.offset, limit = params.limit, "get_audit called");

    let audit_path = state.state_dir.join("logs").join("audit.jsonl");
    let offset = params.offset.unwrap_or(0);

    // Read the audit log file. If it doesn't exist, return empty.
    let content = match tokio::fs::read_to_string(&audit_path).await {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return (
                StatusCode::OK,
                Json(serde_json::json!({
                    "entries": [],
                    "total": 0,
                    "offset": offset,
                    "limit": params.limit,
                })),
            );
        }
        Err(e) => {
            tracing::error!(error = %e, "failed to read audit log");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": format!("failed to read audit log: {e}")})),
            );
        }
    };

    // Parse JSONL entries.
    let all_entries: Vec<serde_json::Value> = content
        .lines()
        .filter(|line| !line.trim().is_empty())
        .filter_map(|line| serde_json::from_str(line).ok())
        .collect();

    let total = all_entries.len();
    let entries: Vec<&serde_json::Value> =
        all_entries.iter().skip(offset).take(params.limit).collect();

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "entries": entries,
            "total": total,
            "offset": offset,
            "limit": params.limit,
        })),
    )
}

#[cfg(test)]
mod tests {
    use axum::{body::Body, http::Request};
    use tower::ServiceExt;

    use super::*;
    use crate::{approval_queue::ApprovalQueue, auth::SessionStore};

    fn test_state() -> AppState {
        AppState {
            queue: ApprovalQueue::new(16),
            state_dir: std::path::PathBuf::from("/tmp"),
            session_store: SessionStore::new(1800),
        }
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
