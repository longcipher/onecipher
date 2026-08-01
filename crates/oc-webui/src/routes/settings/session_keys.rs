//! Session key CRUD endpoints.
//!
//! - `GET    /api/settings/session-keys`       — list session keys
//! - `GET    /api/settings/session-keys/{id}`  — get a session key
//! - `POST   /api/settings/session-keys`       — create a session key
//! - `PUT    /api/settings/session-keys/{id}`  — update a session key
//! - `DELETE /api/settings/session-keys/{id}`  — delete a session key

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde::Deserialize;

use crate::routes::approvals::AppState;

/// GET /api/settings/session-keys — list all session keys.
pub async fn list_session_keys(State(_state): State<AppState>) -> impl IntoResponse {
    tracing::debug!("list_session_keys called");
    // ponytail: stub, read from oc-session-key later
    Json(serde_json::json!({ "session_keys": [] }))
}

/// GET /api/settings/session-keys/{id} — get a single session key.
pub async fn get_session_key(
    State(_state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    tracing::debug!(id = %id, "get_session_key called");
    // ponytail: stub, read from oc-session-key later
    Json(serde_json::json!({
        "id": id,
        "name": "stub-session-key",
        "chain": "evm",
        "expires_at": null,
    }))
}

/// Request body for creating/updating a session key.
#[derive(Debug, Deserialize)]
pub struct SessionKeyRequest {
    pub name: String,
    pub chain: String,
    #[serde(default)]
    pub permissions: Vec<String>,
    #[serde(default)]
    pub expires_at: Option<String>,
}

/// POST /api/settings/session-keys — create a session key.
pub async fn create_session_key(
    State(_state): State<AppState>,
    Json(body): Json<SessionKeyRequest>,
) -> impl IntoResponse {
    tracing::info!(name = %body.name, chain = %body.chain, "create_session_key requested");
    // ponytail: stub, write to oc-session-key later
    (
        StatusCode::CREATED,
        Json(serde_json::json!({
            "id": "stub-session-key-id",
            "name": body.name,
            "chain": body.chain,
            "permissions": body.permissions,
            "expires_at": body.expires_at,
        })),
    )
}

/// PUT /api/settings/session-keys/{id} — update a session key.
pub async fn update_session_key(
    State(_state): State<AppState>,
    Path(id): Path<String>,
    Json(body): Json<SessionKeyRequest>,
) -> impl IntoResponse {
    tracing::info!(id = %id, name = %body.name, "update_session_key requested");
    // ponytail: stub, write to oc-session-key later
    Json(serde_json::json!({
        "id": id,
        "name": body.name,
        "chain": body.chain,
        "permissions": body.permissions,
        "expires_at": body.expires_at,
    }))
}

/// DELETE /api/settings/session-keys/{id} — delete a session key.
pub async fn delete_session_key(
    State(_state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    tracing::info!(id = %id, "delete_session_key requested");
    // ponytail: stub, delete from oc-session-key later
    Json(serde_json::json!({ "ok": true, "id": id }))
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

    fn json_body(value: serde_json::Value) -> Body {
        Body::from(serde_json::to_vec(&value).unwrap())
    }

    #[tokio::test]
    async fn test_list_session_keys() {
        let app = axum::Router::new()
            .route("/api/settings/session-keys", axum::routing::get(list_session_keys))
            .with_state(test_state());
        let resp = app
            .oneshot(
                Request::builder().uri("/api/settings/session-keys").body(Body::empty()).unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_get_session_key() {
        let app = axum::Router::new()
            .route("/api/settings/session-keys/{id}", axum::routing::get(get_session_key))
            .with_state(test_state());
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/settings/session-keys/key1")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_create_session_key() {
        let app = axum::Router::new()
            .route("/api/settings/session-keys", axum::routing::post(create_session_key))
            .with_state(test_state());
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/settings/session-keys")
                    .header("content-type", "application/json")
                    .body(json_body(serde_json::json!({"name": "test", "chain": "evm"})))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
    }

    #[tokio::test]
    async fn test_update_session_key() {
        let app = axum::Router::new()
            .route("/api/settings/session-keys/{id}", axum::routing::put(update_session_key))
            .with_state(test_state());
        let resp = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/api/settings/session-keys/key1")
                    .header("content-type", "application/json")
                    .body(json_body(serde_json::json!({"name": "updated", "chain": "solana"})))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_delete_session_key() {
        let app = axum::Router::new()
            .route("/api/settings/session-keys/{id}", axum::routing::delete(delete_session_key))
            .with_state(test_state());
        let resp = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/api/settings/session-keys/key1")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }
}
