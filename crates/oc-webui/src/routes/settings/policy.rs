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

use crate::routes::approvals::AppState;

/// GET /api/settings/policy — list all policy rules.
pub async fn list_policy_rules(State(_state): State<AppState>) -> impl IntoResponse {
    tracing::debug!("list_policy_rules called");
    // ponytail: stub, read from oc-policy later
    Json(serde_json::json!({ "rules": [] }))
}

/// GET /api/settings/policy/{id} — get a single policy rule.
pub async fn get_policy_rule(
    State(_state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    tracing::debug!(id = %id, "get_policy_rule called");
    // ponytail: stub, read from oc-policy later
    Json(serde_json::json!({
        "id": id,
        "name": "stub-rule",
        "action": "allow",
        "conditions": [],
    }))
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
    State(_state): State<AppState>,
    Json(body): Json<PolicyRuleRequest>,
) -> impl IntoResponse {
    tracing::info!(name = %body.name, "create_policy_rule requested");
    // ponytail: stub, write to oc-policy later
    (
        StatusCode::CREATED,
        Json(serde_json::json!({
            "id": "stub-rule-id",
            "name": body.name,
            "action": body.action,
            "conditions": body.conditions,
        })),
    )
}

/// PUT /api/settings/policy/{id} — update a policy rule.
pub async fn update_policy_rule(
    State(_state): State<AppState>,
    Path(id): Path<String>,
    Json(body): Json<PolicyRuleRequest>,
) -> impl IntoResponse {
    tracing::info!(id = %id, name = %body.name, "update_policy_rule requested");
    // ponytail: stub, write to oc-policy later
    Json(serde_json::json!({
        "id": id,
        "name": body.name,
        "action": body.action,
        "conditions": body.conditions,
    }))
}

/// DELETE /api/settings/policy/{id} — delete a policy rule.
pub async fn delete_policy_rule(
    State(_state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    tracing::info!(id = %id, "delete_policy_rule requested");
    // ponytail: stub, delete from oc-policy later
    Json(serde_json::json!({ "ok": true, "id": id }))
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

    fn json_body(value: serde_json::Value) -> Body {
        Body::from(serde_json::to_vec(&value).unwrap())
    }

    #[tokio::test]
    async fn test_list_policy_rules() {
        let app = axum::Router::new()
            .route("/api/settings/policy", axum::routing::get(list_policy_rules))
            .with_state(test_state());
        let resp = app
            .oneshot(Request::builder().uri("/api/settings/policy").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_get_policy_rule() {
        let app = axum::Router::new()
            .route("/api/settings/policy/{id}", axum::routing::get(get_policy_rule))
            .with_state(test_state());
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
        let app = axum::Router::new()
            .route("/api/settings/policy", axum::routing::post(create_policy_rule))
            .with_state(test_state());
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
        let app = axum::Router::new()
            .route("/api/settings/policy/{id}", axum::routing::put(update_policy_rule))
            .with_state(test_state());
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
        let app = axum::Router::new()
            .route("/api/settings/policy/{id}", axum::routing::delete(delete_policy_rule))
            .with_state(test_state());
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
