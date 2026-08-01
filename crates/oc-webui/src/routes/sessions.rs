//! WalletConnect session REST endpoints.
//!
//! - `GET    /api/sessions`           — list WC sessions
//! - `DELETE /api/sessions/{topic}`   — disconnect session
//! - `POST   /api/sessions/pair`      — pair with URI
//! - `POST   /api/sessions/generate`  — generate pairing URI

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde::Deserialize;

use crate::routes::approvals::AppState;

/// GET /api/sessions — list all active WalletConnect sessions.
pub async fn list_sessions(State(_state): State<AppState>) -> impl IntoResponse {
    tracing::debug!("list_sessions called");
    // ponytail: stub, forward to WcServerHandle later
    Json(serde_json::json!({ "sessions": [] }))
}

/// DELETE /api/sessions/{topic} — disconnect a WalletConnect session.
pub async fn disconnect_session(
    State(_state): State<AppState>,
    Path(topic): Path<String>,
) -> impl IntoResponse {
    tracing::info!(topic = %topic, "disconnect_session requested");
    // ponytail: stub, forward to WcServerHandle later
    Json(serde_json::json!({ "ok": true, "topic": topic }))
}

/// Request body for POST /api/sessions/pair.
#[derive(Debug, Deserialize)]
pub struct PairRequest {
    pub uri: String,
}

/// POST /api/sessions/pair — pair with a WalletConnect URI.
pub async fn pair_session(
    State(_state): State<AppState>,
    Json(body): Json<PairRequest>,
) -> impl IntoResponse {
    tracing::info!(uri = %body.uri, "pair_session requested");
    // ponytail: stub, forward to WcServerHandle later
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "ok": true,
            "topic": "stub-topic",
        })),
    )
}

/// Request body for POST /api/sessions/generate.
#[derive(Debug, Deserialize)]
pub struct GenerateRequest {
    #[serde(default)]
    pub chains: Option<Vec<String>>,
}

/// POST /api/sessions/generate — generate a WalletConnect pairing URI.
pub async fn generate_session(
    State(_state): State<AppState>,
    Json(body): Json<GenerateRequest>,
) -> impl IntoResponse {
    tracing::info!(chains = ?body.chains, "generate_session requested");
    // ponytail: stub, forward to WcServerHandle later
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "uri": "wc:stub-pairing-uri@2?relay-protocol=irn",
            "topic": "stub-topic",
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

    fn json_body(value: serde_json::Value) -> Body {
        Body::from(serde_json::to_vec(&value).unwrap())
    }

    #[tokio::test]
    async fn test_list_sessions() {
        let app = axum::Router::new()
            .route("/api/sessions", axum::routing::get(list_sessions))
            .with_state(test_state());
        let resp = app
            .oneshot(Request::builder().uri("/api/sessions").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_disconnect_session() {
        let app = axum::Router::new()
            .route("/api/sessions/{topic}", axum::routing::delete(disconnect_session))
            .with_state(test_state());
        let resp = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/api/sessions/abc123")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_pair_session() {
        let app = axum::Router::new()
            .route("/api/sessions/pair", axum::routing::post(pair_session))
            .with_state(test_state());
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/sessions/pair")
                    .header("content-type", "application/json")
                    .body(json_body(serde_json::json!({"uri": "wc:test@2"})))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_generate_session() {
        let app = axum::Router::new()
            .route("/api/sessions/generate", axum::routing::post(generate_session))
            .with_state(test_state());
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/sessions/generate")
                    .header("content-type", "application/json")
                    .body(json_body(serde_json::json!({})))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }
}
