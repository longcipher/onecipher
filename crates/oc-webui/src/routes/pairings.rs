//! WC pairing-URI injection endpoint.
//!
//! - `POST /api/pairings` — inject a dApp pairing URI (`wc:...`) into the daemon's WC v2 wallet
//!   server via the shared pairing channel. This is the WebUI equivalent of `onecipher wc connect
//!   <uri>`.

use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};
use serde::Deserialize;

use crate::routes::approvals::AppState;

/// Request body for POST /api/pairings.
#[derive(Debug, Deserialize)]
pub struct PairingRequest {
    /// WC v2 pairing URI (`wc:<topic>@2?relay-protocol=...&symKey=...`).
    pub uri: String,
}

/// POST /api/pairings — parse the URI and forward it into the pairing channel
/// so the wallet server injects it as a `Propose`-state session.
pub async fn inject_pairing(
    State(state): State<AppState>,
    Json(body): Json<PairingRequest>,
) -> impl IntoResponse {
    let uri = match oc_walletconnect::PairingUri::parse(&body.uri) {
        Ok(u) => u,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "ok": false, "error": format!("invalid pairing URI: {e}") })),
            )
                .into_response();
        }
    };

    match state.pairing_tx.send(uri.clone()).await {
        Ok(()) => (StatusCode::OK, Json(serde_json::json!({ "ok": true, "topic": uri.topic })))
            .into_response(),
        Err(_) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({ "ok": false, "error": "daemon wallet server not running" })),
        )
            .into_response(),
    }
}

#[cfg(test)]
mod tests {
    use axum::{body::Body, http::Request};
    use tower::ServiceExt;

    use super::*;
    use crate::{approval_queue::ApprovalQueue, auth::SessionStore};

    fn json_body(value: serde_json::Value) -> Body {
        Body::from(serde_json::to_vec(&value).unwrap())
    }

    #[tokio::test]
    async fn inject_pairing_forwards_valid_uri_into_channel() {
        let (pairing_tx, mut pairing_rx) = tokio::sync::mpsc::channel(8);
        let state = AppState {
            queue: ApprovalQueue::new(16),
            state_dir: std::path::PathBuf::from("/tmp"),
            session_store: SessionStore::new(1800),
            pairing_tx,
        };
        let app = axum::Router::new()
            .route("/api/pairings", axum::routing::post(inject_pairing))
            .with_state(state);

        let uri = format!("wc:{}@2?relay-protocol=irn&symKey={}", "ab".repeat(32), "cd".repeat(32));
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/pairings")
                    .header("content-type", "application/json")
                    .body(json_body(serde_json::json!({ "uri": uri })))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap(),
        )
        .unwrap();
        assert_eq!(body["ok"], true);
        assert_eq!(body["topic"], "ab".repeat(32));

        // The parsed URI must reach the pairing channel (the daemon consumes
        // this same channel).
        let injected = pairing_rx.try_recv().expect("pairing channel must receive the URI");
        assert_eq!(injected.topic, "ab".repeat(32));
        assert_eq!(injected.sym_key.as_deref(), Some("cd".repeat(32).as_str()));
    }

    #[tokio::test]
    async fn inject_pairing_rejects_malformed_uri() {
        let (pairing_tx, _pairing_rx) = tokio::sync::mpsc::channel(8);
        let state = AppState {
            queue: ApprovalQueue::new(16),
            state_dir: std::path::PathBuf::from("/tmp"),
            session_store: SessionStore::new(1800),
            pairing_tx,
        };
        let app = axum::Router::new()
            .route("/api/pairings", axum::routing::post(inject_pairing))
            .with_state(state);

        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/pairings")
                    .header("content-type", "application/json")
                    .body(json_body(serde_json::json!({ "uri": "not-a-wc-uri" })))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }
}
