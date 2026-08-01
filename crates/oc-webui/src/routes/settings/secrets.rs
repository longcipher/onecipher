//! Secrets CRUD endpoints.
//!
//! - `GET    /api/settings/secrets`       — list secrets (requires step-up WebAuthn)
//! - `GET    /api/settings/secrets/{id}`  — get a secret (requires step-up WebAuthn)
//! - `POST   /api/settings/secrets`       — create a secret
//! - `PUT    /api/settings/secrets/{id}`  — update a secret
//! - `DELETE /api/settings/secrets/{id}`  — delete a secret

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde::Deserialize;

use crate::routes::approvals::AppState;

/// GET /api/settings/secrets — list all secrets.
///
/// NOTE: Real implementation requires step-up WebAuthn authentication.
pub async fn list_secrets(State(_state): State<AppState>) -> impl IntoResponse {
    tracing::debug!("list_secrets called");
    // ponytail: stub, read from oc-secret later; needs step-up WebAuthn
    Json(serde_json::json!({ "secrets": [] }))
}

/// GET /api/settings/secrets/{id} — get a single secret.
///
/// NOTE: Real implementation requires step-up WebAuthn authentication.
pub async fn get_secret(
    State(_state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    tracing::debug!(id = %id, "get_secret called");
    // ponytail: stub, read from oc-secret later; needs step-up WebAuthn
    Json(serde_json::json!({
        "id": id,
        "name": "stub-secret",
        "has_totp": false,
    }))
}

/// Request body for creating/updating a secret.
#[derive(Debug, Deserialize)]
pub struct SecretRequest {
    pub name: String,
    pub value: String,
    #[serde(default)]
    pub kind: Option<String>,
}

/// POST /api/settings/secrets — create a secret.
pub async fn create_secret(
    State(_state): State<AppState>,
    Json(body): Json<SecretRequest>,
) -> impl IntoResponse {
    tracing::info!(name = %body.name, "create_secret requested");
    // ponytail: stub, write to oc-secret later
    (
        StatusCode::CREATED,
        Json(serde_json::json!({
            "id": "stub-secret-id",
            "name": body.name,
            "kind": body.kind.unwrap_or_else(|| "generic".to_string()),
        })),
    )
}

/// PUT /api/settings/secrets/{id} — update a secret.
pub async fn update_secret(
    State(_state): State<AppState>,
    Path(id): Path<String>,
    Json(body): Json<SecretRequest>,
) -> impl IntoResponse {
    tracing::info!(id = %id, name = %body.name, "update_secret requested");
    // ponytail: stub, write to oc-secret later
    Json(serde_json::json!({
        "id": id,
        "name": body.name,
        "kind": body.kind.unwrap_or_else(|| "generic".to_string()),
    }))
}

/// DELETE /api/settings/secrets/{id} — delete a secret.
pub async fn delete_secret(
    State(_state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    tracing::info!(id = %id, "delete_secret requested");
    // ponytail: stub, delete from oc-secret later
    Json(serde_json::json!({ "ok": true, "id": id }))
}

#[cfg(test)]
mod tests {
    use axum::{body::Body, http::Request};
    use tower::ServiceExt;

    use super::*;
    use crate::approval_queue::ApprovalQueue;

    fn test_state() -> AppState {
        AppState { queue: ApprovalQueue::new(16), state_dir: std::path::PathBuf::from("/tmp") }
    }

    fn json_body(value: serde_json::Value) -> Body {
        Body::from(serde_json::to_vec(&value).unwrap())
    }

    #[tokio::test]
    async fn test_list_secrets() {
        let app = axum::Router::new()
            .route("/api/settings/secrets", axum::routing::get(list_secrets))
            .with_state(test_state());
        let resp = app
            .oneshot(Request::builder().uri("/api/settings/secrets").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_get_secret() {
        let app = axum::Router::new()
            .route("/api/settings/secrets/{id}", axum::routing::get(get_secret))
            .with_state(test_state());
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/settings/secrets/secret1")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_create_secret() {
        let app = axum::Router::new()
            .route("/api/settings/secrets", axum::routing::post(create_secret))
            .with_state(test_state());
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/settings/secrets")
                    .header("content-type", "application/json")
                    .body(json_body(serde_json::json!({"name": "test", "value": "s3cret"})))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
    }

    #[tokio::test]
    async fn test_update_secret() {
        let app = axum::Router::new()
            .route("/api/settings/secrets/{id}", axum::routing::put(update_secret))
            .with_state(test_state());
        let resp = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/api/settings/secrets/secret1")
                    .header("content-type", "application/json")
                    .body(json_body(serde_json::json!({"name": "updated", "value": "new-val"})))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_delete_secret() {
        let app = axum::Router::new()
            .route("/api/settings/secrets/{id}", axum::routing::delete(delete_secret))
            .with_state(test_state());
        let resp = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/api/settings/secrets/secret1")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }
}
