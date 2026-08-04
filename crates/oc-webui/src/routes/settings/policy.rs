//! Policy rules CRUD endpoints.
//!
//! - `GET    /api/settings/policy`       — list policy rules
//! - `GET    /api/settings/policy/{id}`  — get a policy rule
//! - `POST   /api/settings/policy`       — create a policy rule
//! - `PUT    /api/settings/policy/{id}`  — update a policy rule
//! - `DELETE /api/settings/policy/{id}`  — delete a policy rule

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde::Deserialize;
use uuid::Uuid;

use crate::routes::approvals::AppState;

/// GET /api/settings/policy — list all policy rules.
pub async fn list_policy_rules(State(state): State<AppState>) -> impl IntoResponse {
    tracing::debug!("list_policy_rules called");
    let policies_dir = state.state_dir.join("policies");

    let mut rules = Vec::new();
    if policies_dir.exists() {
        let mut entries = match tokio::fs::read_dir(&policies_dir).await {
            Ok(e) => e,
            Err(e) => {
                tracing::error!(error = %e, "failed to read policies directory");
                return Json(serde_json::json!({ "rules": [] }));
            }
        };
        while let Ok(Some(entry)) = entries.next_entry().await {
            let path = entry.path();
            if path.extension().is_some_and(|ext| ext == "json") {
                if let Ok(content) = tokio::fs::read_to_string(&path).await {
                    if let Ok(rule) = serde_json::from_str::<serde_json::Value>(&content) {
                        rules.push(rule);
                    }
                }
            }
        }
    }

    Json(serde_json::json!({ "rules": rules }))
}

/// GET /api/settings/policy/{id} — get a single policy rule.
pub async fn get_policy_rule(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    tracing::debug!(id = %id, "get_policy_rule called");
    let path = state.state_dir.join("policies").join(format!("{id}.json"));

    match tokio::fs::read_to_string(&path).await {
        Ok(content) => match serde_json::from_str::<serde_json::Value>(&content) {
            Ok(rule) => (StatusCode::OK, Json(rule)).into_response(),
            Err(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": format!("invalid policy file: {e}")})),
            )
                .into_response(),
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": format!("policy not found: {id}")})),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("failed to read policy: {e}")})),
        )
            .into_response(),
    }
}

/// Request body for creating/updating a policy rule.
#[derive(Debug, Deserialize)]
pub struct PolicyRuleRequest {
    pub name: String,
    pub action: String,
    #[serde(default)]
    pub conditions: Vec<serde_json::Value>,
}

/// POST /api/settings/policy — create a policy rule.
pub async fn create_policy_rule(
    State(state): State<AppState>,
    Json(body): Json<PolicyRuleRequest>,
) -> impl IntoResponse {
    tracing::info!(name = %body.name, "create_policy_rule requested");
    let policies_dir = state.state_dir.join("policies");
    if let Err(e) = tokio::fs::create_dir_all(&policies_dir).await {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("failed to create policies dir: {e}")})),
        );
    }

    let id = Uuid::new_v4().to_string();
    let rule = serde_json::json!({
        "id": id,
        "name": body.name,
        "action": body.action,
        "conditions": body.conditions,
    });

    let path = policies_dir.join(format!("{id}.json"));
    let content = serde_json::to_string_pretty(&rule).unwrap_or_default();
    // Atomic: a torn write here would leave a policy file that doesn't parse,
    // which the engine treats as absent → silently drops the restriction.
    let p = path.clone();
    let io_result = tokio::task::spawn_blocking(move || {
        oc_core::paths::write_atomic(&p, content.as_bytes(), oc_core::paths::MODE_REGULAR_FILE)
    })
    .await
    .unwrap_or_else(|e| Err(std::io::Error::other(e)));
    if let Err(e) = io_result {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("failed to write policy: {e}")})),
        );
    }

    (StatusCode::CREATED, Json(rule))
}

/// PUT /api/settings/policy/{id} — update a policy rule.
pub async fn update_policy_rule(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(body): Json<PolicyRuleRequest>,
) -> impl IntoResponse {
    tracing::info!(id = %id, name = %body.name, "update_policy_rule requested");
    let path = state.state_dir.join("policies").join(format!("{id}.json"));

    if !path.exists() {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": format!("policy not found: {id}")})),
        );
    }

    let rule = serde_json::json!({
        "id": id,
        "name": body.name,
        "action": body.action,
        "conditions": body.conditions,
    });

    let content = serde_json::to_string_pretty(&rule).unwrap_or_default();
    let p = path.clone();
    let io_result = tokio::task::spawn_blocking(move || {
        oc_core::paths::write_atomic(&p, content.as_bytes(), oc_core::paths::MODE_REGULAR_FILE)
    })
    .await
    .unwrap_or_else(|e| Err(std::io::Error::other(e)));
    if let Err(e) = io_result {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("failed to write policy: {e}")})),
        );
    }

    (StatusCode::OK, Json(rule))
}

/// DELETE /api/settings/policy/{id} — delete a policy rule.
pub async fn delete_policy_rule(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    tracing::info!(id = %id, "delete_policy_rule requested");
    let path = state.state_dir.join("policies").join(format!("{id}.json"));

    if !path.exists() {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": format!("policy not found: {id}")})),
        );
    }

    if let Err(e) = tokio::fs::remove_file(&path).await {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("failed to delete policy: {e}")})),
        );
    }

    (StatusCode::OK, Json(serde_json::json!({ "ok": true, "id": id })))
}

#[cfg(test)]
mod tests {
    use axum::{body::Body, http::Request};
    use tower::ServiceExt;

    use super::*;
    use crate::{approval_queue::ApprovalQueue, auth::SessionStore};

    fn test_state_with_dir(dir: &std::path::Path) -> AppState {
        AppState {
            queue: ApprovalQueue::new(16),
            state_dir: dir.to_path_buf(),
            session_store: SessionStore::new(1800),
        }
    }

    fn json_body(value: serde_json::Value) -> Body {
        Body::from(serde_json::to_vec(&value).unwrap())
    }

    fn seed_policy_file(dir: &std::path::Path, id: &str) {
        let policies_dir = dir.join("policies");
        std::fs::create_dir_all(&policies_dir).unwrap();
        let rule = serde_json::json!({"id": id, "name": "test", "action": "allow"});
        std::fs::write(policies_dir.join(format!("{id}.json")), rule.to_string()).unwrap();
    }

    #[tokio::test]
    async fn test_list_policy_rules() {
        let dir = tempfile::tempdir().unwrap();
        let app = axum::Router::new()
            .route("/api/settings/policy", axum::routing::get(list_policy_rules))
            .with_state(test_state_with_dir(dir.path()));
        let resp = app
            .oneshot(Request::builder().uri("/api/settings/policy").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_get_policy_rule() {
        let dir = tempfile::tempdir().unwrap();
        seed_policy_file(dir.path(), "rule1");
        let app = axum::Router::new()
            .route("/api/settings/policy/{id}", axum::routing::get(get_policy_rule))
            .with_state(test_state_with_dir(dir.path()));
        let resp = app
            .oneshot(
                Request::builder().uri("/api/settings/policy/rule1").body(Body::empty()).unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_create_policy_rule() {
        let dir = tempfile::tempdir().unwrap();
        let app = axum::Router::new()
            .route("/api/settings/policy", axum::routing::post(create_policy_rule))
            .with_state(test_state_with_dir(dir.path()));
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/settings/policy")
                    .header("content-type", "application/json")
                    .body(json_body(serde_json::json!({"name": "test", "action": "allow"})))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
    }

    #[tokio::test]
    async fn test_update_policy_rule() {
        let dir = tempfile::tempdir().unwrap();
        seed_policy_file(dir.path(), "rule1");
        let app = axum::Router::new()
            .route("/api/settings/policy/{id}", axum::routing::put(update_policy_rule))
            .with_state(test_state_with_dir(dir.path()));
        let resp = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/api/settings/policy/rule1")
                    .header("content-type", "application/json")
                    .body(json_body(serde_json::json!({"name": "updated", "action": "deny"})))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_delete_policy_rule() {
        let dir = tempfile::tempdir().unwrap();
        seed_policy_file(dir.path(), "rule1");
        let app = axum::Router::new()
            .route("/api/settings/policy/{id}", axum::routing::delete(delete_policy_rule))
            .with_state(test_state_with_dir(dir.path()));
        let resp = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/api/settings/policy/rule1")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }
}
